//! Block import and chain sync.
//!
//! Live peer sync uses the buffered H/H+1 verification coordinator in the
//! node binary. The eager import helper in this module exists only for tests.
//! It:
//!   1. Validates the block's structural invariants
//!   2. Projects the block once, verifies the projected header roots
//!   3. Commits the verified projection to chain state
//!   4. Writes the block to the block store
//!   5. Evicts spent/invalid transactions from the mempool
//!   6. Optionally takes a state snapshot

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    time::{Duration, Instant},
};

use indra_consensus::mempool::Mempool;
use indra_core::codec::Decode;
use indra_core::types::block::{BlockProposalVNext, BlockVNext};
use indra_core::types::primitives::Bytes32;
use indra_core::EpochRecord;
use indra_state::{
    apply_block_with_effects, compute_state_roots, CanonicalStateEffects, ChainState,
};
use indra_storage::state_store::SNAPSHOT_INTERVAL;
use indra_storage::{BlockStore, StateStore};

use crate::error::{NodeError, NodeResult};

/// Maximum blocks to request in one sync batch.
pub const SYNC_BATCH_SIZE: u64 = 50;

/// Status claims expire after five ordinary six-second status intervals.
pub const SYNC_HEIGHT_CLAIM_TTL: Duration = Duration::from_secs(30);
/// Three distinct failing sources at one height pause expensive validation.
pub const MAX_EXPENSIVE_SYNC_FAILURE_SOURCES: usize = 3;
/// Duration of the aggregate expensive-validation circuit breaker.
pub const SYNC_FAILURE_CIRCUIT_BREAKER: Duration = Duration::from_secs(60);
/// Bound one outstanding block request without penalizing ordinary slow disks.
pub const SYNC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
struct HeightClaim {
    addr: SocketAddr,
    height: u64,
    tip_hash: Bytes32,
    stake: u64,
    expires_at: Instant,
}

/// Authenticated status data received from a peer.
pub struct PeerStatusObservation {
    /// Validator identity.
    pub validator_id: Bytes32,
    /// Peer socket address.
    pub peer: SocketAddr,
    /// Peer chain height.
    pub peer_height: u64,
    /// Peer tip hash.
    pub tip_hash: Bytes32,
    /// Peer active stake.
    pub peer_stake: u64,
    /// Total active stake at the peer.
    pub total_active_stake: u64,
    /// Local chain height.
    pub local_height: u64,
}

impl From<(Bytes32, SocketAddr, u64, Bytes32, u64, u64, u64)> for PeerStatusObservation {
    fn from(value: (Bytes32, SocketAddr, u64, Bytes32, u64, u64, u64)) -> Self {
        let (
            validator_id,
            peer,
            peer_height,
            tip_hash,
            peer_stake,
            total_active_stake,
            local_height,
        ) = value;
        Self {
            validator_id,
            peer,
            peer_height,
            tip_hash,
            peer_stake,
            total_active_stake,
            local_height,
        }
    }
}

/// One authenticated, locally-issued block-range request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutstandingSyncRequest {
    /// Authenticated validator expected to answer.
    pub validator_id: Bytes32,
    /// Transport endpoint selected for this request.
    pub peer: SocketAddr,
    /// Inclusive first requested height.
    pub from_height: u64,
    /// Inclusive last requested height, including one certification look-ahead.
    pub to_height: u64,
    /// Monotonic issue time used for timeout and source rotation.
    pub issued_at: Instant,
}

/// A fully validated block which is not canonical until its own QC arrives.
#[derive(Debug, Clone)]
pub struct ProvisionalSyncBlock {
    /// Fully validated but not yet finalized block.
    pub block: BlockProposalVNext,
    /// Authenticated identity which supplied the block.
    pub source_validator_id: Bytes32,
    /// Transport endpoint which supplied the block.
    pub source: SocketAddr,
    /// Time at which validation completed.
    pub staged_at: Instant,
    /// Detached authoritative projection computed exactly once at admission.
    pub prepared: PreparedSyncBlock,
}

/// Cryptographic attribution for a failed H/H+1 certification pair.
#[derive(Debug)]
pub enum PairVerificationError {
    /// The provisional proposal envelope itself is unauthorized or ineligible.
    ProvisionalProposalWrong(NodeError),
    /// H+1 carries a valid quorum certificate for a different height-H hash,
    /// proving that the provisional H supplied earlier is not canonical.
    ProvisionalBlockWrong {
        /// Hash which the independently valid quorum actually certified.
        certified_hash: Bytes32,
    },
    /// H+1's claimed certificate is malformed, unauthorized, or invalid.
    CertificateCarrierWrong(NodeError),
}

/// Current synchronization phase for a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncPhase {
    /// Have not yet heard from any peer.
    AwaitingPeers,
    /// Downloading missing blocks from a peer.
    Downloading {
        /// The peer currently serving us blocks.
        peer: SocketAddr,
        /// Highest height we know we must reach.
        target_height: u64,
        /// Next block height expected from the response stream.
        next_expected: u64,
    },
    /// Local height matches the best known peer height.
    CaughtUp,
}

/// Driver-owned synchronization state machine.
#[derive(Debug, Clone)]
pub struct SyncState {
    phase: SyncPhase,
    best_peer_height: u64,
    received_peer_status: bool,
    is_bootstrap_node: bool,
    connected_peers: HashSet<Bytes32>,
    height_claims: HashMap<Bytes32, HeightClaim>,
    total_active_stake: u64,
    outstanding: Option<OutstandingSyncRequest>,
    provisional: Option<ProvisionalSyncBlock>,
    expensive_failure_sources: HashMap<u64, HashMap<Bytes32, Instant>>,
    circuit_open_until: HashMap<u64, Instant>,
    session_finalized_blocks: u64,
}

/// Read-only operational synchronization diagnostics exposed only to admin RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncDiagnostics {
    /// Stable phase name.
    pub phase: &'static str,
    /// Local canonical height.
    pub local_height: u64,
    /// Corroborated target height, when downloading.
    pub target_height: Option<u64>,
    /// In-memory provisional height awaiting its own QC.
    pub provisional_height: Option<u64>,
    /// Number of unexpired authenticated height claims.
    pub corroboration_claim_count: usize,
    /// Whether any expensive-validation circuit breaker is currently open.
    pub circuit_breaker_open: bool,
    /// Whether operator recovery has been requested after multi-source failure.
    pub recovery_required: bool,
}

impl SyncState {
    /// Return a non-mutating operational diagnostic snapshot.
    pub fn diagnostics(&self, local_height: u64, now: Instant) -> SyncDiagnostics {
        let phase = match self.phase {
            SyncPhase::AwaitingPeers => "awaiting_peers",
            SyncPhase::Downloading { .. } => "downloading",
            SyncPhase::CaughtUp => "caught_up",
        };
        let circuit_breaker_open = self.circuit_open_until.values().any(|until| *until > now);
        SyncDiagnostics {
            phase,
            local_height,
            target_height: self.target_height(),
            provisional_height: self
                .provisional
                .as_ref()
                .map(|pending| pending.block.block.header.height),
            corroboration_claim_count: self
                .height_claims
                .values()
                .filter(|claim| claim.expires_at > now)
                .count(),
            circuit_breaker_open,
            // The durable recovery marker lives in the node data directory;
            // the RPC integration fills this field while it owns the driver.
            recovery_required: false,
        }
    }
    /// Create the bootstrap node sync state.
    pub fn bootstrap(local_height: u64) -> Self {
        Self {
            phase: if local_height == 0 {
                SyncPhase::CaughtUp
            } else {
                SyncPhase::AwaitingPeers
            },
            best_peer_height: local_height,
            received_peer_status: local_height == 0,
            is_bootstrap_node: true,
            connected_peers: HashSet::new(),
            height_claims: HashMap::new(),
            total_active_stake: 0,
            outstanding: None,
            provisional: None,
            expensive_failure_sources: HashMap::new(),
            circuit_open_until: HashMap::new(),
            session_finalized_blocks: 0,
        }
    }

    /// Create the follower node sync state.
    pub fn follower(local_height: u64) -> Self {
        Self {
            phase: SyncPhase::AwaitingPeers,
            best_peer_height: local_height,
            received_peer_status: false,
            is_bootstrap_node: false,
            connected_peers: HashSet::new(),
            height_claims: HashMap::new(),
            total_active_stake: 0,
            outstanding: None,
            provisional: None,
            expensive_failure_sources: HashMap::new(),
            circuit_open_until: HashMap::new(),
            session_finalized_blocks: 0,
        }
    }

    /// Return the current phase.
    pub fn phase(&self) -> &SyncPhase {
        &self.phase
    }

    /// True when the node may participate in consensus.
    pub fn is_caught_up(&self) -> bool {
        if !self.received_peer_status && !self.is_bootstrap_node {
            return false;
        }
        matches!(self.phase, SyncPhase::CaughtUp)
    }

    /// Current sync target height, if any.
    pub fn target_height(&self) -> Option<u64> {
        match self.phase {
            SyncPhase::Downloading { target_height, .. } => Some(target_height),
            SyncPhase::CaughtUp | SyncPhase::AwaitingPeers => None,
        }
    }

    /// Record an authenticated validator connection for corroboration policy.
    pub fn peer_connected(&mut self, validator_id: Bytes32) {
        self.connected_peers.insert(validator_id);
    }

    /// Remove all transient authority associated with a disconnected peer.
    pub fn peer_disconnected(&mut self, validator_id: Bytes32, addr: SocketAddr) {
        self.connected_peers.remove(&validator_id);
        self.height_claims.remove(&validator_id);
        if self
            .outstanding
            .is_some_and(|request| request.validator_id == validator_id || request.peer == addr)
        {
            self.outstanding = None;
        }
        if matches!(self.phase, SyncPhase::CaughtUp) {
            self.outstanding = None;
            self.provisional = None;
        }
        if matches!(self.phase, SyncPhase::Downloading { peer, .. } if peer == addr) {
            self.phase = SyncPhase::AwaitingPeers;
        }
    }

    /// Remove a failed source's claim without treating its transport as disconnected.
    pub fn source_failed(&mut self, validator_id: Bytes32, addr: SocketAddr) {
        // A cooled source is not currently eligible for graceful-degradation
        // counting even if its transport socket remains open.
        self.connected_peers.remove(&validator_id);
        self.height_claims.remove(&validator_id);
        if self
            .outstanding
            .is_some_and(|request| request.validator_id == validator_id || request.peer == addr)
        {
            self.outstanding = None;
        }
        if matches!(self.phase, SyncPhase::Downloading { peer, .. } if peer == addr) {
            self.phase = SyncPhase::AwaitingPeers;
        }
    }

    /// Observe an authenticated validator's expiring, stake-weighted status.
    pub fn observe_status(
        &mut self,
        observation: PeerStatusObservation,
        now: Instant,
    ) -> Option<(SocketAddr, u64, u64)> {
        let PeerStatusObservation {
            validator_id,
            peer,
            peer_height,
            tip_hash,
            peer_stake,
            total_active_stake,
            local_height,
        } = observation;
        self.received_peer_status = true;
        self.total_active_stake = total_active_stake;
        self.connected_peers.insert(validator_id);
        self.height_claims.retain(|_, claim| claim.expires_at > now);
        self.height_claims.insert(
            validator_id,
            HeightClaim {
                addr: peer,
                height: peer_height,
                tip_hash,
                stake: peer_stake,
                expires_at: now + SYNC_HEIGHT_CLAIM_TTL,
            },
        );

        let Some((target_height, selected_id, selected_peer)) =
            self.corroborated_target(local_height, now)
        else {
            if local_height >= self.best_peer_height {
                self.phase = SyncPhase::CaughtUp;
            }
            return None;
        };
        self.best_peer_height = target_height;

        if self.outstanding.is_some() {
            return None;
        }

        if local_height >= self.best_peer_height {
            if matches!(self.phase, SyncPhase::AwaitingPeers) {
                self.phase = SyncPhase::CaughtUp;
            }
            if matches!(self.phase, SyncPhase::Downloading { .. }) {
                self.phase = SyncPhase::CaughtUp;
            }
            return None;
        }

        let from_height = self
            .provisional
            .as_ref()
            .map(|pending| pending.block.block.header.height.saturating_add(1))
            .unwrap_or_else(|| local_height.saturating_add(1));
        let target_height = self.best_peer_height;
        // Fetch one look-ahead block because H+1 carries the QC finalising H.
        let to_height = target_height
            .saturating_add(1)
            .min(from_height.saturating_add(SYNC_BATCH_SIZE));

        self.phase = SyncPhase::Downloading {
            peer: selected_peer,
            target_height,
            next_expected: from_height,
        };
        self.outstanding = Some(OutstandingSyncRequest {
            validator_id: selected_id,
            peer: selected_peer,
            from_height,
            to_height,
            issued_at: now,
        });

        Some((selected_peer, from_height, to_height))
    }

    fn corroborated_target(
        &self,
        local_height: u64,
        now: Instant,
    ) -> Option<(u64, Bytes32, SocketAddr)> {
        let mut heights: Vec<u64> = self
            .height_claims
            .values()
            .filter(|claim| claim.expires_at > now && claim.height > local_height)
            .map(|claim| claim.height)
            .collect();
        heights.sort_unstable();
        heights.dedup();

        for height in heights.into_iter().rev() {
            let mut supporters: Vec<_> = self
                .height_claims
                .iter()
                .filter(|(_, claim)| claim.expires_at > now && claim.height >= height)
                .collect();
            supporters.sort_by_key(|(id, _)| id.0);
            let supporting_stake = supporters
                .iter()
                .fold(0u64, |sum, (_, claim)| sum.saturating_add(claim.stake));
            let stake_corroborated = self.total_active_stake > 0
                && u128::from(supporting_stake) * 3 > u128::from(self.total_active_stake);
            let identity_corroborated = supporters.len() >= 2 || self.connected_peers.len() < 2;
            if stake_corroborated && identity_corroborated {
                let (id, claim) = supporters.first().copied()?;
                // Retain the selected tip commitment for same-height
                // contradiction diagnostics and source rotation.
                let _selected_tip_hash = claim.tip_hash;
                return Some((height, *id, claim.addr));
            }
        }
        None
    }

    /// Rotate immediately to another still-corroborated source after failure.
    pub fn rotate_after_failure(
        &mut self,
        local_height: u64,
        now: Instant,
    ) -> Option<(SocketAddr, u64, u64)> {
        let (target_height, validator_id, peer) = self.corroborated_target(local_height, now)?;
        let from_height = self
            .provisional
            .as_ref()
            .map(|pending| pending.block.block.header.height.saturating_add(1))
            .unwrap_or_else(|| local_height.saturating_add(1));
        let to_height = target_height
            .saturating_add(1)
            .min(from_height.saturating_add(SYNC_BATCH_SIZE));
        self.best_peer_height = target_height;
        self.phase = SyncPhase::Downloading {
            peer,
            target_height,
            next_expected: from_height,
        };
        self.outstanding = Some(OutstandingSyncRequest {
            validator_id,
            peer,
            from_height,
            to_height,
            issued_at: now,
        });
        Some((peer, from_height, to_height))
    }

    /// Validate and consume the binding for one inbound response.
    pub fn accept_response(
        &mut self,
        validator_id: Bytes32,
        peer: SocketAddr,
        blocks: &[BlockProposalVNext],
    ) -> Result<OutstandingSyncRequest, &'static str> {
        let request = self.outstanding.ok_or("no sync request is outstanding")?;
        if !matches!(self.phase, SyncPhase::Downloading { .. }) {
            return Err("sync is not downloading");
        }
        if request.validator_id != validator_id || request.peer != peer {
            return Err("response source does not match selected sync peer");
        }
        if blocks.iter().any(|block| {
            block.block.header.height < request.from_height
                || block.block.header.height > request.to_height
        }) {
            return Err("response contains a block outside the requested range");
        }
        if blocks.windows(2).any(|pair| {
            let [first, second] = pair else {
                return true;
            };
            second.block.header.height != first.block.header.height.saturating_add(1)
        }) {
            return Err("response block heights are not contiguous");
        }
        self.outstanding = None;
        Ok(request)
    }

    /// Expire one stalled request so another corroborated source can be tried.
    pub fn expire_outstanding(&mut self, now: Instant) -> Option<OutstandingSyncRequest> {
        let request = self.outstanding?;
        if now.duration_since(request.issued_at) < SYNC_REQUEST_TIMEOUT {
            return None;
        }
        self.source_failed(request.validator_id, request.peer);
        Some(request)
    }

    /// Replace the single bounded provisional slot after full validation.
    pub fn stage_provisional(
        &mut self,
        block: BlockProposalVNext,
        prepared: PreparedSyncBlock,
        source_validator_id: Bytes32,
        source: SocketAddr,
        now: Instant,
    ) {
        let staged_height = block.block.header.height;
        self.provisional = Some(ProvisionalSyncBlock {
            block,
            source_validator_id,
            source,
            staged_at: now,
            prepared,
        });
        if let SyncPhase::Downloading { next_expected, .. } = &mut self.phase {
            *next_expected = staged_height.saturating_add(1);
        }
    }

    /// Return the currently staged, not-yet-final block.
    pub fn provisional(&self) -> Option<&ProvisionalSyncBlock> {
        self.provisional.as_ref()
    }

    /// Validate the authenticated source binding for the outstanding
    /// provisional-QC request before any QC decoding or cryptographic work.
    pub fn accept_provisional_qc_response(
        &self,
        validator_id: Bytes32,
        peer: SocketAddr,
        height: u64,
    ) -> Result<(), &'static str> {
        let provisional = self
            .provisional
            .as_ref()
            .ok_or("no provisional QC request")?;
        if provisional.source_validator_id != validator_id || provisional.source != peer {
            return Err("response source does not match provisional QC requester");
        }
        if provisional.block.block.header.height != height {
            return Err("response height does not match provisional QC request");
        }
        Ok(())
    }

    /// Consume the staged block once its own QC has been verified.
    pub fn take_provisional(&mut self) -> Option<ProvisionalSyncBlock> {
        self.provisional.take()
    }

    /// Discard an uncertified candidate before rotating sources.
    pub fn clear_provisional(&mut self) {
        self.provisional = None;
    }

    /// Record one distinct expensive-failure source and open the breaker at three.
    pub fn note_expensive_failure(
        &mut self,
        height: u64,
        validator_id: Bytes32,
        now: Instant,
    ) -> bool {
        let sources = self.expensive_failure_sources.entry(height).or_default();
        sources.retain(|_, observed| now.duration_since(*observed) < SYNC_FAILURE_CIRCUIT_BREAKER);
        sources.insert(validator_id, now);
        if sources.len() >= MAX_EXPENSIVE_SYNC_FAILURE_SOURCES {
            self.circuit_open_until
                .insert(height, now + SYNC_FAILURE_CIRCUIT_BREAKER);
            return true;
        }
        false
    }

    /// Return whether expensive validation is paused for this height.
    pub fn circuit_open(&mut self, height: u64, now: Instant) -> bool {
        self.circuit_open_until.retain(|_, until| *until > now);
        self.circuit_open_until
            .get(&height)
            .is_some_and(|until| *until > now)
    }

    /// Record one imported block while downloading.
    pub fn on_block_imported(&mut self, imported_height: u64) {
        self.session_finalized_blocks = self.session_finalized_blocks.saturating_add(1);
        if let SyncPhase::Downloading {
            target_height,
            next_expected,
            ..
        } = &mut self.phase
        {
            if imported_height >= *next_expected {
                *next_expected = imported_height.saturating_add(1);
            }
            *target_height = (*target_height).max(self.best_peer_height);
            if imported_height >= self.best_peer_height {
                self.phase = SyncPhase::CaughtUp;
            }
        }
        if self
            .session_finalized_blocks
            .is_multiple_of(SYNC_BATCH_SIZE)
            && !matches!(self.phase, SyncPhase::CaughtUp)
        {
            // Bound one uninterrupted catch-up session. Fresh, unexpired
            // status claims must schedule the next 50-block segment.
            self.phase = SyncPhase::AwaitingPeers;
            self.outstanding = None;
        }
    }

    /// After handling a block response, decide whether we need another batch.
    pub fn next_request_after_response(
        &mut self,
        local_height: u64,
    ) -> Option<(SocketAddr, u64, u64)> {
        match self.phase {
            SyncPhase::Downloading {
                peer,
                target_height,
                next_expected,
            } => {
                let target_height = target_height.max(self.best_peer_height);
                if local_height >= self.best_peer_height {
                    self.phase = SyncPhase::CaughtUp;
                    None
                } else {
                    let from_height = next_expected.max(local_height.saturating_add(1));
                    let to_height = target_height
                        .saturating_add(1)
                        .min(from_height.saturating_add(SYNC_BATCH_SIZE));
                    let validator_id = self
                        .height_claims
                        .iter()
                        .find_map(|(id, claim)| (claim.addr == peer).then_some(*id))?;
                    self.outstanding = Some(OutstandingSyncRequest {
                        validator_id,
                        peer,
                        from_height,
                        to_height,
                        issued_at: Instant::now(),
                    });
                    Some((peer, from_height, to_height))
                }
            }
            SyncPhase::AwaitingPeers | SyncPhase::CaughtUp => None,
        }
    }

    /// Empty responses never prove that the target has been reached.
    pub fn on_empty_response(&mut self) {
        self.outstanding = None;
        if matches!(self.phase, SyncPhase::Downloading { .. }) {
            self.phase = SyncPhase::AwaitingPeers;
        }
    }

    /// Reset round state after catching up to a new height.
    pub fn mark_caught_up(&mut self, local_height: u64) {
        self.best_peer_height = self.best_peer_height.max(local_height);
        self.phase = SyncPhase::CaughtUp;
        // If we successfully committed/imported a block, we are caught up
        // enough to participate without waiting for the periodic peer Status
        // heartbeat. The block itself proves network communication happened.
        self.received_peer_status = true;
    }
}

/// Eagerly import one block for isolated test harnesses.
///
/// # Security warning
///
/// This helper does **not** perform the forward-looking verification of the
/// block's own QC that the live H/H+1 buffered sync path requires. It must
/// never be called for a block received from an untrusted peer. It remains
/// public solely because `indra-node/tests/node.rs` is a separate integration
/// test crate; production sync must use the provisional coordinator.
#[doc(hidden)]
pub fn import_unfinalized_block_for_test(
    proposal: &BlockProposalVNext,
    state: &mut ChainState,
    mempool: &mut Mempool,
    block_store: &mut BlockStore,
    state_store: &StateStore,
    timestamp_secs: u64,
) -> NodeResult<Option<EpochRecord>> {
    import_unfinalized_block_with_effects_for_test(
        proposal,
        state,
        mempool,
        block_store,
        state_store,
        timestamp_secs,
    )
    .map(|outcome| outcome.epoch_record)
}

/// Test-only eager import returning the effects published after projection.
///
/// This omits forward-looking own-QC verification and must never be wired to
/// untrusted network input. See [`import_unfinalized_block_for_test`].
fn import_unfinalized_block_with_effects_for_test(
    proposal: &BlockProposalVNext,
    state: &mut ChainState,
    mempool: &mut Mempool,
    block_store: &mut BlockStore,
    state_store: &StateStore,
    timestamp_secs: u64,
) -> NodeResult<indra_state::AppliedBlockOutcome> {
    import_unfinalized_block_with_durable_hook_for_test(
        proposal,
        state,
        mempool,
        block_store,
        state_store,
        timestamp_secs,
        |_, _, _| Ok(()),
    )
}

/// Test-only eager import with a caller-supplied durable commit hook.
///
/// This omits forward-looking own-QC verification and must never be wired to
/// untrusted network input. The hook runs after the block and interval
/// snapshot are durable but before canonical memory or pending pools change.
fn import_unfinalized_block_with_durable_hook_for_test<F>(
    proposal: &BlockProposalVNext,
    state: &mut ChainState,
    mempool: &mut Mempool,
    block_store: &mut BlockStore,
    state_store: &StateStore,
    timestamp_secs: u64,
    durable_hook: F,
) -> NodeResult<indra_state::AppliedBlockOutcome>
where
    F: FnOnce(&ChainState, &Option<EpochRecord>, u64) -> NodeResult<()>,
{
    let projection = validate_imported_block(proposal, state, timestamp_secs)?;
    commit_prepared_with_durable_hook(
        proposal,
        projection,
        state,
        mempool,
        block_store,
        state_store,
        durable_hook,
    )
}

/// Durably publish an already-verified provisional projection without
/// repeating cryptographic or state validation.
pub(crate) fn commit_prepared_with_durable_hook<F>(
    proposal: &BlockProposalVNext,
    projection: PreparedSyncBlock,
    state: &mut ChainState,
    mempool: &mut Mempool,
    block_store: &mut BlockStore,
    state_store: &StateStore,
    durable_hook: F,
) -> NodeResult<indra_state::AppliedBlockOutcome>
where
    F: FnOnce(&ChainState, &Option<EpochRecord>, u64) -> NodeResult<()>,
{
    let block = &proposal.block;
    let height = block.header.height;
    if projection.block_hash != block.header.block_hash()
        || projection.pre_height != state.height
        || projection.pre_tip_hash != state.tip_hash
    {
        return Err(NodeError::BlockInvalid {
            height,
            reason: "prepared sync projection is stale or belongs to a different block".to_string(),
        });
    }

    // Store genesis placeholder if block_store is empty and this is height 1
    if block_store.is_empty() && height == 1 {
        let genesis = crate::genesis::build_genesis_proposal(state)
            .map_err(|detail| NodeError::InvalidConfiguration { detail })?;
        block_store.append(&genesis)?;
    }
    block_store.append(proposal)?;

    // Snapshot the verified detached state before it becomes canonical. An I/O
    // failure therefore cannot leave memory ahead of the durable snapshot.
    if height > 0 && height.is_multiple_of(SNAPSHOT_INTERVAL) {
        state_store.save(&projection.state)?;
    }
    durable_hook(
        &projection.state,
        &projection.epoch_record,
        block_store.next_height(),
    )?;

    // No fallible operation may occur between publishing the verified state
    // and publishing its pool effects. A failed append/fsync above therefore
    // leaves both canonical memory and all pending pools unchanged.
    let epoch_record = projection.epoch_record;
    let effects = projection.effects;
    *state = projection.state;
    publish_committed_effects(state, mempool, &effects)?;

    Ok(indra_state::AppliedBlockOutcome {
        epoch_record,
        effects,
    })
}

/// Validate and apply the canonical sync/import block pipeline up to, but not
/// including, durable block/snapshot writes.
///
/// The eager test import calls this helper before storage append. Tests that need to
/// exercise activation-boundary behavior at synthetic heights use this same
/// path because `BlockStore` itself intentionally requires contiguous heights
/// from genesis and cannot be jumped to `u64::MAX - 1`.
fn validate_imported_block(
    proposal: &BlockProposalVNext,
    state: &ChainState,
    timestamp_secs: u64,
) -> NodeResult<PreparedSyncBlock> {
    let block = &proposal.block;
    let height = block.header.height;
    let verified = verify_imported_proposal(proposal, state)?;

    if height > 1 {
        verify_block_qc(block, state)?;
    }

    project_and_verify_block_state_root(&verified, state, timestamp_secs)
}

fn publish_committed_effects(
    state: &ChainState,
    mempool: &mut Mempool,
    effects: &CanonicalStateEffects,
) -> NodeResult<()> {
    for event in &effects.slash_events {
        eprintln!(
            "[slash] validator {} slashed {}bps — burned={} self_bond_slashed={} reporter_reward={}",
            hex::encode(&event.validator_id.0[..4]),
            event.slash_bps,
            event.burned,
            event.self_principal_slashed,
            event.reporter_reward,
        );
    }
    // Evict spent transactions from mempool after the verified projection has
    // become the real state.
    mempool.apply_canonical_effects(state, effects)?;
    Ok(())
}

/// Verify proposer authorization and eligibility against the governing snapshot.
/// Snapshot lookup and both independent cryptographic checks fail closed at every
/// imported height; there is no live-registry bypass.
fn verify_imported_proposal<'a>(
    proposal: &'a indra_core::types::block::BlockProposalVNext,
    state: &ChainState,
) -> NodeResult<indra_core::types::proposal::VerifiedProposal<'a>> {
    let snapshot = state.snapshot_for_consensus_height(proposal.block.header.height)?;
    indra_core::types::proposal::verify_proposal(
        proposal,
        state.chain_id.as_bytes(),
        &state.election_seed,
        snapshot,
    )
    .map_err(|error| NodeError::BlockInvalid {
        height: proposal.block.header.height,
        reason: format!("proposal authorization or eligibility failed: {error}"),
    })
}

pub(crate) fn verify_block_qc(block: &BlockVNext, state: &ChainState) -> NodeResult<()> {
    verify_block_qc_with(block, state, None)
}

/// Verify a peer-sourced embedded QC through the node's bounded worker.
pub(crate) fn verify_network_block_qc(
    block: &BlockVNext,
    state: &ChainState,
    verifier: &crate::qc_verification::NetworkQcVerifier,
) -> NodeResult<()> {
    verify_block_qc_with(block, state, Some(verifier))
}

fn verify_block_qc_with(
    block: &BlockVNext,
    state: &ChainState,
    verifier: Option<&crate::qc_verification::NetworkQcVerifier>,
) -> NodeResult<()> {
    if block.header.height <= 1 {
        return Ok(());
    }

    let qc_bytes = block.header.quorum_certificate.as_slice();
    if qc_bytes.is_empty() {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "missing quorum certificate at height {} — only block 1 may omit a QC",
                block.header.height,
            ),
        });
    }

    let qc = indra_core::types::qc::QuorumCertificateV1::decode_exact(qc_bytes).map_err(|e| {
        NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!("invalid QC encoding: {e}"),
        }
    })?;

    let expected_qc_height = block.header.height.saturating_sub(1);
    if qc.height != expected_qc_height {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "embedded QC height {} does not match expected {}",
                qc.height, expected_qc_height,
            ),
        });
    }
    if qc.block_hash != block.header.prev_hash {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "embedded QC certifies block {} but parent is {} — QC must certify the exact parent block",
                hex::encode(&qc.block_hash.0[..8]),
                hex::encode(&block.header.prev_hash.0[..8]),
            ),
        });
    }

    verify_sync_qc_with(&qc, state, block.header.height, verifier)
}

/// Fully validate a next-height candidate without publishing any state.
pub fn verify_sync_candidate(
    proposal: &BlockProposalVNext,
    state: &ChainState,
    timestamp_secs: u64,
) -> NodeResult<PreparedSyncBlock> {
    let block = &proposal.block;
    let verified = verify_imported_proposal(proposal, state)?;
    if block.header.height > 1 {
        verify_block_qc(block, state)?;
    }
    project_and_verify_block_state_root(&verified, state, timestamp_secs)
}

/// Fully validate a peer-sourced candidate using bounded QC verification.
pub fn verify_network_sync_candidate(
    proposal: &BlockProposalVNext,
    state: &ChainState,
    timestamp_secs: u64,
    verifier: &crate::qc_verification::NetworkQcVerifier,
) -> NodeResult<PreparedSyncBlock> {
    let block = &proposal.block;
    let verified = verify_imported_proposal(proposal, state)?;
    if block.header.height > 1 {
        verify_network_block_qc(block, state, verifier)?;
    }
    project_and_verify_block_state_root(&verified, state, timestamp_secs)
}

/// Verify the certificate carried by H+1 against a provisional H and
/// attribute a mismatch cryptographically rather than blaming H blindly.
pub fn verify_provisional_certificate(
    provisional: &BlockProposalVNext,
    carrier: &BlockProposalVNext,
    canonical_state: &ChainState,
) -> Result<(), PairVerificationError> {
    verify_provisional_certificate_with(provisional, carrier, canonical_state, None)
}

/// Verify a peer-sourced provisional carrier through bounded QC verification.
pub fn verify_network_provisional_certificate(
    provisional: &BlockProposalVNext,
    carrier: &BlockProposalVNext,
    canonical_state: &ChainState,
    verifier: &crate::qc_verification::NetworkQcVerifier,
) -> Result<(), PairVerificationError> {
    verify_provisional_certificate_with(provisional, carrier, canonical_state, Some(verifier))
}

fn verify_provisional_certificate_with(
    provisional: &BlockProposalVNext,
    carrier: &BlockProposalVNext,
    canonical_state: &ChainState,
    verifier: Option<&crate::qc_verification::NetworkQcVerifier>,
) -> Result<(), PairVerificationError> {
    let projected = match verifier {
        Some(network) => verify_network_sync_candidate(provisional, canonical_state, 0, network),
        None => verify_sync_candidate(provisional, canonical_state, 0),
    }
    .map_err(PairVerificationError::ProvisionalProposalWrong)?;
    let provisional = &provisional.block;
    let carrier_proposal = carrier;
    let carrier = &carrier_proposal.block;
    let qc = indra_core::types::qc::QuorumCertificateV1::decode_exact(
        carrier.header.quorum_certificate.as_slice(),
    )
    .map_err(|error| {
        PairVerificationError::CertificateCarrierWrong(NodeError::BlockInvalid {
            height: carrier.header.height,
            reason: format!("invalid QC encoding: {error}"),
        })
    })?;
    if qc.height != provisional.header.height {
        return Err(PairVerificationError::CertificateCarrierWrong(
            NodeError::BlockInvalid {
                height: carrier.header.height,
                reason: format!(
                    "certificate carrier claims height {}, expected {}",
                    qc.height, provisional.header.height
                ),
            },
        ));
    }
    // Verify the certificate before comparing its hash. A valid quorum for a
    // different hash proves H was the wrong provisional branch; an invalid
    // quorum proves only that the later carrier is bad.
    verify_sync_qc_with(&qc, canonical_state, carrier.header.height, verifier)
        .map_err(PairVerificationError::CertificateCarrierWrong)?;
    let provisional_hash = provisional.header.block_hash();
    if qc.block_hash != provisional_hash {
        return Err(PairVerificationError::ProvisionalBlockWrong {
            certified_hash: qc.block_hash,
        });
    }
    // Only after the valid QC confirms that H is the branch being evaluated
    // can H+1's height-specific seed be derived from the projected H state.
    // If the QC certifies a different H, that quorum already proves the
    // provisional branch wrong; attempting proposer verification against the
    // wrong branch's derived seed would invert fault attribution.
    verify_imported_proposal(carrier_proposal, &projected.state)
        .map_err(PairVerificationError::CertificateCarrierWrong)?;
    if carrier.header.prev_hash != provisional_hash {
        return Err(PairVerificationError::CertificateCarrierWrong(
            NodeError::BlockInvalid {
                height: carrier.header.height,
                reason: "carrier parent hash does not match its valid QC".to_string(),
            },
        ));
    }
    Ok(())
}

/// Verify a directly requested QC for the bounded provisional block.
pub fn verify_direct_provisional_qc(
    provisional: &BlockProposalVNext,
    qc_bytes: &[u8],
    canonical_state: &ChainState,
) -> NodeResult<()> {
    verify_direct_provisional_qc_with(provisional, qc_bytes, canonical_state, None)
}

/// Verify a directly requested peer QC through bounded QC verification.
pub fn verify_network_direct_provisional_qc(
    provisional: &BlockProposalVNext,
    qc_bytes: &[u8],
    canonical_state: &ChainState,
    verifier: &crate::qc_verification::NetworkQcVerifier,
) -> NodeResult<()> {
    verify_direct_provisional_qc_with(provisional, qc_bytes, canonical_state, Some(verifier))
}

fn verify_direct_provisional_qc_with(
    provisional: &BlockProposalVNext,
    qc_bytes: &[u8],
    canonical_state: &ChainState,
    verifier: Option<&crate::qc_verification::NetworkQcVerifier>,
) -> NodeResult<()> {
    verify_imported_proposal(provisional, canonical_state)?;
    let provisional = &provisional.block;
    let qc =
        indra_core::types::qc::QuorumCertificateV1::decode_exact(qc_bytes).map_err(|error| {
            NodeError::BlockInvalid {
                height: provisional.header.height,
                reason: format!("invalid requested QC encoding: {error}"),
            }
        })?;
    if qc.height != provisional.header.height || qc.block_hash != provisional.header.block_hash() {
        return Err(NodeError::BlockInvalid {
            height: provisional.header.height,
            reason: "requested QC does not certify the provisional block".to_string(),
        });
    }
    verify_sync_qc_with(
        &qc,
        canonical_state,
        provisional.header.height.saturating_add(1),
        verifier,
    )
}

fn verify_sync_qc_with(
    qc: &indra_core::types::qc::QuorumCertificateV1,
    state: &ChainState,
    _importing_height: u64,
    verifier: Option<&crate::qc_verification::NetworkQcVerifier>,
) -> NodeResult<()> {
    let snapshot = state.snapshot_for_consensus_height(qc.height)?;
    if let Some(verifier) = verifier {
        verifier
            .verify(qc, snapshot, &state.chain_id)
            .map_err(|err| NodeError::BlockInvalid {
                height: qc.height,
                reason: format!("network QC verification failed: {err}"),
            })
    } else {
        crate::engine::NodeEngine::verify_qc_with_snapshot(qc, snapshot, &state.chain_id)
    }
}

#[cfg(test)]
fn verify_sync_qc(
    qc: &indra_core::types::qc::QuorumCertificateV1,
    state: &ChainState,
    importing_height: u64,
) -> NodeResult<()> {
    verify_sync_qc_with(qc, state, importing_height, None)
}

/// Opaque detached result of authoritative sync-candidate validation.
#[derive(Debug, Clone)]
pub struct PreparedSyncBlock {
    pub(crate) block_hash: Bytes32,
    pub(crate) pre_height: u64,
    pub(crate) pre_tip_hash: Bytes32,
    pub(crate) state: ChainState,
    pub(crate) epoch_record: Option<EpochRecord>,
    pub(crate) effects: CanonicalStateEffects,
}

pub(crate) fn project_and_verify_block_state_root(
    verified: &indra_core::types::proposal::VerifiedProposal<'_>,
    pre_state: &ChainState,
    timestamp_secs: u64,
) -> NodeResult<PreparedSyncBlock> {
    let block = verified.block();
    let expected_state_root = block.header.state_root;
    let expected_validator_root = block.header.validator_set_root;

    // Verify against a detached projected state first. The caller commits this
    // same projection only after all header commitments match, so import/replay
    // never applies the same block a second time.
    let mut projected = pre_state.clone();
    let outcome =
        apply_block_with_effects(&mut projected, verified, timestamp_secs).map_err(|e| {
            NodeError::BlockInvalid {
                height: block.header.height,
                reason: format!("block failed during pre-apply root verification: {e}"),
            }
        })?;
    let epoch_record = outcome.epoch_record;

    let actual_roots = compute_state_roots(&projected).map_err(|error| NodeError::BlockInvalid {
        height: block.header.height,
        reason: format!("state commitment rebuild failed: {error}"),
    })?;
    if actual_roots.state_root != expected_state_root {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "state_root mismatch: expected {}, got {}",
                hex::encode(expected_state_root.0),
                hex::encode(actual_roots.state_root.0),
            ),
        });
    }

    if actual_roots.validator_set_root != expected_validator_root {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "validator_set_root mismatch: expected {}, got {}",
                hex::encode(expected_validator_root.0),
                hex::encode(actual_roots.validator_set_root.0),
            ),
        });
    }

    let actual_value_hash = block.compute_value_hash(projected.total_supply);
    if actual_value_hash != block.header.value_hash {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "value_hash mismatch: expected {}, got {}",
                hex::encode(block.header.value_hash.0),
                hex::encode(actual_value_hash.0),
            ),
        });
    }

    Ok(PreparedSyncBlock {
        block_hash: block.header.block_hash(),
        pre_height: pre_state.height,
        pre_tip_hash: pre_state.tip_hash,
        state: projected,
        epoch_record,
        effects: outcome.effects,
    })
}

#[cfg(test)]
pub(crate) fn verify_block_state_root(
    proposal: &BlockProposalVNext,
    state: &ChainState,
) -> NodeResult<()> {
    let verified = verify_imported_proposal(proposal, state)?;
    project_and_verify_block_state_root(&verified, state, 0).map(|_| ())
}

#[cfg(test)]
mod tests {
    use indra_core::types::primitives::TEST_CHAIN_ID;
    use super::*;
    use indra_consensus::qc::{verify_qc_strict, QcValidator};
    use indra_consensus::{
        producer::{produce_block, BlockTemplate},
        proposer::{compute_proposer_vrf, ProposerCandidate, ProposerElection},
        qc::build_qc,
        vote::produce_vote,
    };
    use indra_core::{
        codec::Encode,
        types::{
            block::BlockVNext,
            primitives::EPOCH_DURATION_BLOCKS,
            vote::VoteStep,
        },
        Bytes32, QuorumCertificateV1, VariableBytes,
    };
    use indra_crypto::{
        hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
        VrfKeypair,
    };
    use indra_state::{
        apply_block, compute_state_root, compute_validator_set_root, ValidatorEntry,
        ValidatorStatus,
    };
    use indra_storage::StateStore;
    use std::path::PathBuf;

    fn temp_dir(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_sync_test_{}_{}", suffix, std::process::id()));
        p
    }

    fn observe_for_test(
        sync: &mut SyncState,
        identity_byte: u8,
        peer: SocketAddr,
        peer_height: u64,
        local_height: u64,
    ) -> Option<(SocketAddr, u64, u64)> {
        let identity = Bytes32::from([identity_byte; 32]);
        sync.peer_connected(identity);
        sync.observe_status(
            (
                identity,
                peer,
                peer_height,
                Bytes32::from([identity_byte; 32]),
                100,
                100,
                local_height,
            )
                .into(),
            Instant::now(),
        )
    }

    fn install_active_validator(
        state: &mut ChainState,
        seed: u8,
        stake: u64,
        with_vrf_key: bool,
        with_pq_key: bool,
    ) -> (Bytes32, HybridKeypair) {
        let classical = ClassicalKeypair::from_seed(&[seed; 32]);
        let pq = PqKeypair::from_seed(&[seed; 32]).unwrap();
        let hybrid = HybridKeypair::new(classical, pq);
        let public = hybrid.public_key();
        let vrf = VrfKeypair::from_seed(&[seed; 32]);
        let cold = indra_crypto::ColdHybridKeypair::from_independent_seeds(
            [seed.wrapping_add(1); 32],
            [seed.wrapping_add(2); 32],
        )
        .unwrap();
        let cold_public = cold.public_key();
        let cold_public = cold_public.as_complete_hybrid();
        let validator_id =
            indra_core::types::crypto::hybrid_identity_id(&public.classical.0, &public.pq.0);

        state
            .validators
            .upsert(ValidatorEntry {
                validator_id,
                name: format!("validator-{seed}"),
                hybrid_classical_pk: Some(public.classical.0),
                hybrid_pq_pk: with_pq_key.then(|| public.pq.0.to_vec()),
                vrf_pk: with_vrf_key.then(|| vrf.public_key()),
                vrf_key_activation_epoch: 0,
                pending_vrf_pk: None,
                pending_vrf_activation_epoch: None,
                stake_spark: stake,
                status: ValidatorStatus::Active,
                registered_epoch: 0,
                last_active_epoch: 0,
                slashed_offense_id: None,
                commission_bps: indra_core::types::primitives::DEFAULT_COMMISSION_BPS,
                pending_commission_bps: None,
                pending_commission_effective_epoch: None,
                min_delegation_spark: indra_core::types::primitives::DUST_LIMIT_SPARK,
                auto_delegate_to: None,
                network_addr: None,
                network_addr_last_updated_epoch: None,
                cold_hybrid_classical_pk: Some(cold_public.classical.0),
                cold_hybrid_pq_pk: Some(cold_public.pq.0),
                cold_key_version: 1,
                cold_nonce: 0,
            })
            .unwrap();

        if state.height == 0 && with_vrf_key && with_pq_key {
            // Tests assemble genesis incrementally; refresh all genesis-native
            // authority structures after each complete validator insertion.
            crate::genesis::finalize_test_genesis(state);
        }

        (validator_id, hybrid)
    }

    fn advance_fixture_height_with_issuance(state: &mut ChainState, height: u64) {
        let target = indra_state::monetary::cumulative_reward_target_at_height(
            state.monetary_ledger.reward_budget_spark,
            height,
        )
        .unwrap();
        if target != 0 {
            let mut position = state.stake_positions.values().next().unwrap().clone();
            position.pending_rewards_spark =
                position.pending_rewards_spark.checked_add(target).unwrap();
            state.stake_positions.insert(position.position_id, position);
        }
        state.monetary_ledger.cumulative_reward_minted_spark = target;
        state.monetary_ledger.epoch_reward_minted_spark = target;
        state.total_supply = state.total_supply.checked_add(target).unwrap();
        state.monetary_aggregates = state.recompute_monetary_aggregates().unwrap();
        state.height = height;
    }

    fn build_election(state: &ChainState, height: u64, round: u32) -> ProposerElection {
        let snapshot = state
            .snapshot_for_consensus_height(height)
            .expect("test state must carry the governing consensus snapshot");
        ProposerElection {
            chain_id: state.chain_id.as_bytes().to_vec(),
            election_seed: state.election_seed,
            snapshot_root: snapshot.snapshot_root,
            active_slot_coefficient_numerator: state.active_slot_coefficient_numerator,
            sortition_log: snapshot.sortition_log_interval().unwrap(),
            height,
            round,
            candidates: snapshot
                .entries()
                .iter()
                .map(|entry| ProposerCandidate {
                    validator_id: entry.validator_id,
                    vrf_pubkey: entry.vrf_pk,
                    stake: entry.consensus_weight_spark,
                })
                .collect(),
        }
    }

    fn install_test_snapshot_at_inert_gate(state: &mut ChainState) {
        let snapshot = state
            .build_consensus_snapshot(u64::MAX, u64::MAX - 1)
            .unwrap();
        state.consensus_snapshots.push(snapshot);
    }

    fn make_strict_block(
        state: &ChainState,
        proposer_seed: u8,
        round: u32,
        prev_qc_bytes: Vec<u8>,
    ) -> indra_core::types::block::BlockProposalVNext {
        let proposer = VrfKeypair::from_seed(&[proposer_seed; 32]);
        let election = (round..indra_core::types::primitives::MAX_ROUNDS_PER_HEIGHT)
            .find_map(|candidate_round| {
                let election = build_election(state, state.height + 1, candidate_round);
                let candidate = election
                    .candidates
                    .iter()
                    .find(|candidate| candidate.vrf_pubkey == proposer.public_key())?;
                compute_proposer_vrf(candidate.validator_id, &proposer, &election)
                    .ok()?
                    .eligible
                    .then_some(election)
            })
            .expect("requested test proposer must become eligible within the bounded round search");
        let template = BlockTemplate {
            proposer_vrf_keypair: proposer,
            prev_qc_bytes,
            timestamp: 1_700_000_000u64.saturating_add(state.height.saturating_add(1)),
            polc_round: None,
            transactions: vec![],
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        };
        let mut projection_state = state.clone();
        let block = produce_block(&template, &mut projection_state, &election).unwrap();
        let signer = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[proposer_seed; 32]),
            PqKeypair::from_seed(&[proposer_seed; 32]).unwrap(),
        );
        let mut proposal = indra_core::types::block::BlockProposalVNext {
            block,
            proposer_authorization: indra_core::types::crypto::HybridSignature {
                classical_sig: VariableBytes::from_slice(&[]).unwrap(),
                pq_sig: VariableBytes::from_slice(&[]).unwrap(),
            },
        };
        let transcript = proposal.signing_bytes(state.chain_id.as_bytes()).unwrap();
        let signature = signer.sign(&transcript).unwrap();
        proposal.proposer_authorization = indra_core::types::crypto::HybridSignature {
            classical_sig: VariableBytes::from_slice(&signature.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&signature.pq.0).unwrap(),
        };
        proposal
    }

    struct QcFixture<'a> {
        height: u64,
        round: u32,
        value_hash: Bytes32,
        validator_id: Bytes32,
        hybrid: &'a HybridKeypair,
        pq_pk: Vec<u8>,
        stake: u64,
        snapshot_root: Bytes32,
    }

    fn build_qc_bytes(fixture: QcFixture<'_>) -> Vec<u8> {
        let QcFixture {
            height,
            round,
            value_hash,
            validator_id,
            hybrid,
            pq_pk,
            stake,
            snapshot_root,
        } = fixture;
        let vote = produce_vote(indra_consensus::vote::VoteRequest { height, round, step: VoteStep::Precommit, block_hash: value_hash, validator_id, snapshot_root, chain_id: TEST_CHAIN_ID }, hybrid)
        .unwrap();
        let qc = build_qc(
            height,
            round,
            value_hash,
            TEST_CHAIN_ID,
            snapshot_root,
            &[QcValidator {
                validator_id,
                position: 0,
                pq_pk,
                classical_pk: hybrid.public_key().classical.0,
                stake,
            }],
            vec![&vote],
        )
        .unwrap();
        qc.encode_to_vec()
    }

    fn qc_from_test_signers(
        height: u64,
        block_hash: Bytes32,
        snapshot: &indra_core::types::consensus_snapshot::ConsensusSnapshot,
        signers: &[&HybridKeypair],
    ) -> QuorumCertificateV1 {
        let validators = crate::engine::NodeEngine::qc_validators_for_height(height, snapshot);
        let votes: Vec<_> = signers
            .iter()
            .map(|signer| {
                let validator_id = indra_core::types::crypto::hybrid_identity_id(
                    &signer.public_key().classical.0,
                    &signer.public_key().pq.0,
                );
                produce_vote(indra_consensus::vote::VoteRequest { height, round: 0, step: VoteStep::Precommit, block_hash, validator_id, snapshot_root: snapshot.snapshot_root, chain_id: TEST_CHAIN_ID }, signer)
                .unwrap()
            })
            .collect();
        build_qc(
            height,
            0,
            block_hash,
            TEST_CHAIN_ID,
            snapshot.snapshot_root,
            &validators,
            votes.iter().collect(),
        )
        .unwrap()
    }

    fn make_block(state: &ChainState) -> indra_core::types::block::BlockProposalVNext {
        let candidate = build_election(state, state.height + 1, 0)
            .candidates
            .into_iter()
            .next()
            .expect("canonical test genesis must have proposer authority");
        let proposer_seed = (0u8..=u8::MAX)
            .find(|seed| VrfKeypair::from_seed(&[*seed; 32]).public_key() == candidate.vrf_pubkey)
            .expect("test proposer VRF seed must be recoverable");
        let mut proposal = make_strict_block(state, proposer_seed, 0, vec![]);
        // The test genesis deliberately uses independent hot and VRF
        // seeds. Re-authorize the proposal with that fixture's registered hot
        // hybrid key; eligibility and authorization are independent proofs.
        authorize_canonical_test_proposal(&mut proposal, state.chain_id.as_bytes());
        proposal
    }

    fn authorize_canonical_test_proposal(
        proposal: &mut indra_core::types::block::BlockProposalVNext,
        chain_id: &[u8],
    ) {
        let proposer_id = proposal.block.header.proposer_id;
        let (classical_seed, pq_seed) = [
            ([0xD1; 32], [0xD2; 32]),
            ([0xB1; 32], [0xB2; 32]),
            ([0xC1; 32], [0xC2; 32]),
            ([0xE1; 32], [0xE2; 32]),
        ]
        .into_iter()
        .find(|(classical, pq)| {
            indra_core::types::crypto::hybrid_identity_id(
                &ClassicalKeypair::from_seed(classical).public_key().0,
                &PqKeypair::from_seed(pq).unwrap().public_key().0,
            ) == proposer_id
        })
        .expect("test proposer identity must be recoverable");
        authorize_test_proposal(proposal, chain_id, classical_seed, pq_seed);
    }

    fn authorize_test_proposal(
        proposal: &mut indra_core::types::block::BlockProposalVNext,
        chain_id: &[u8],
        classical_seed: [u8; 32],
        pq_seed: [u8; 32],
    ) {
        let signer = HybridKeypair::new(
            ClassicalKeypair::from_seed(&classical_seed),
            PqKeypair::from_seed(&pq_seed).unwrap(),
        );
        let signature = signer
            .sign(&proposal.signing_bytes(chain_id).unwrap())
            .unwrap();
        proposal.proposer_authorization = indra_core::types::crypto::HybridSignature {
            classical_sig: VariableBytes::from_slice(&signature.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&signature.pq.0).unwrap(),
        };
    }

    fn replace_qc_and_reauthorize(
        proposal: &mut indra_core::types::block::BlockProposalVNext,
        qc_bytes: Vec<u8>,
        signer_seed: u8,
        chain_id: &[u8],
    ) {
        proposal.block.header.quorum_certificate =
            VariableBytes::from_slice(&qc_bytes).expect("adversarial QC fits protocol cap");
        let signer = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[signer_seed; 32]),
            PqKeypair::from_seed(&[signer_seed; 32]).unwrap(),
        );
        let signature = signer
            .sign(&proposal.signing_bytes(chain_id).unwrap())
            .unwrap();
        proposal.proposer_authorization = indra_core::types::crypto::HybridSignature {
            classical_sig: VariableBytes::from_slice(&signature.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&signature.pq.0).unwrap(),
        };
    }

    fn apply_verified_test(
        state: &mut ChainState,
        proposal: &indra_core::types::block::BlockProposalVNext,
        timestamp_secs: u64,
    ) -> Result<Option<EpochRecord>, String> {
        let snapshot = state
            .snapshot_for_consensus_height(proposal.header.height)
            .map_err(|error| error.to_string())?;
        let verified = indra_core::types::proposal::verify_proposal(
            proposal,
            state.chain_id.as_bytes(),
            &state.election_seed,
            snapshot,
        )
        .map_err(|error| error.to_string())?;
        apply_block(state, &verified, timestamp_secs).map_err(|error| error.to_string())
    }

    fn verify_test<'a>(
        state: &ChainState,
        proposal: &'a indra_core::types::block::BlockProposalVNext,
    ) -> indra_core::types::proposal::VerifiedProposal<'a> {
        let snapshot = state
            .snapshot_for_consensus_height(proposal.header.height)
            .unwrap();
        indra_core::types::proposal::verify_proposal(
            proposal,
            state.chain_id.as_bytes(),
            &state.election_seed,
            snapshot,
        )
        .unwrap()
    }

    fn reference_two_step_validate_and_apply(
        block: &indra_core::types::block::BlockProposalVNext,
        state: &mut ChainState,
        mempool: &mut Mempool,
        timestamp_secs: u64,
    ) -> NodeResult<Option<EpochRecord>> {
        verify_block_state_root(block, state)?;
        let snapshot = state.snapshot_for_consensus_height(block.header.height)?;
        let verified = indra_core::types::proposal::verify_proposal(
            block,
            state.chain_id.as_bytes(),
            &state.election_seed,
            snapshot,
        )
        .map_err(|e| NodeError::BlockInvalid {
            height: block.header.height,
            reason: e.to_string(),
        })?;
        let outcome = apply_block_with_effects(state, &verified, timestamp_secs).map_err(|e| {
            NodeError::BlockInvalid {
                height: block.header.height,
                reason: e.to_string(),
            }
        })?;
        let _state_root = compute_state_root(state);
        mempool.apply_canonical_effects(state, &outcome.effects)?;
        Ok(outcome.epoch_record)
    }

    fn assert_import_state_equivalent(
        reference_state: &ChainState,
        actual_state: &ChainState,
        block: &BlockVNext,
    ) {
        assert_eq!(reference_state, actual_state);
        assert_eq!(
            reference_state.encode_to_vec(),
            actual_state.encode_to_vec(),
            "canonical encoded state must remain byte-identical"
        );
        assert_eq!(
            compute_state_root(reference_state),
            compute_state_root(actual_state)
        );
        assert_eq!(
            compute_validator_set_root(reference_state),
            compute_validator_set_root(actual_state)
        );
        assert_eq!(
            block.compute_value_hash(reference_state.total_supply),
            block.compute_value_hash(actual_state.total_supply)
        );
    }

    #[test]
    fn import_single_block() {
        let dir = temp_dir("a");
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = crate::genesis::test_genesis_state();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(
            dir.join("blocks.log"),
            indra_storage::PruneConfig::archive(),
        )
        .unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        let block = make_block(&state);
        import_unfinalized_block_for_test(
            &block,
            &mut state,
            &mut mempool,
            &mut block_store,
            &state_store,
            0,
        )
        .unwrap();

        assert_eq!(state.height, 1);
        assert_eq!(block_store.len(), 2); // genesis (0) + block 1

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn imported_projection_commit_matches_reference_two_step_sequence() {
        let mut reference_state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, hybrid) =
            install_active_validator(&mut reference_state, 0x61, 10_000, true, true);
        let mut actual_state = reference_state.clone();
        let mut reference_mempool = Mempool::default_config();
        let mut actual_mempool = Mempool::default_config();
        let mut prev_qc = Vec::new();

        for _ in 0..5 {
            let block = make_strict_block(&actual_state, 0x61, 0, prev_qc.clone());
            let reference_record = reference_two_step_validate_and_apply(
                &block,
                &mut reference_state,
                &mut reference_mempool,
                1_900_000_000,
            )
            .unwrap();
            let actual = validate_imported_block(&block, &actual_state, 1_900_000_000).unwrap();
            let actual_record = actual.epoch_record.clone();
            actual_state = actual.state;
            publish_committed_effects(&actual_state, &mut actual_mempool, &actual.effects)
                .unwrap();

            assert_eq!(reference_record, actual_record);
            assert_import_state_equivalent(&reference_state, &actual_state, &block);
            assert_eq!(reference_mempool.len(), actual_mempool.len());
            assert_eq!(reference_mempool.is_empty(), actual_mempool.is_empty());

            prev_qc = build_qc_bytes(QcFixture {
                height: block.header.height,
                round: block.header.proposer_round,
                value_hash: block.header.block_hash(),
                validator_id,
                hybrid: &hybrid,
                pq_pk: hybrid.public_key().pq.0.to_vec(),
                stake: 10_000,
                snapshot_root: actual_state
                    .snapshot_for_consensus_height(block.header.height)
                    .unwrap()
                    .snapshot_root,
            });
        }
    }

    #[test]
    fn sync_import_reproduces_signer_scoped_rewards() {
        let mut live_state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, hybrid) =
            install_active_validator(&mut live_state, 0x6A, 10_000, true, true);
        let mut imported_state = live_state.clone();
        let mut previous_qc = Vec::new();

        for _ in 0..6 {
            let block = make_strict_block(&live_state, 0x6A, 0, previous_qc.clone());
            let live_record = apply_verified_test(&mut live_state, &block, 0).unwrap();
            let imported = validate_imported_block(&block, &imported_state, 0).unwrap();
            assert_eq!(live_record, imported.epoch_record);
            assert_eq!(compute_state_root(&live_state), compute_state_root(&imported.state));
            assert_eq!(live_state.encode_to_vec(), imported.state.encode_to_vec());

            let position_id = indra_core::types::stake_position::derive_position_id(
                validator_id,
                validator_id,
                indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
                    validator_id,
                },
            );
            assert_eq!(
                live_state
                    .stake_positions
                    .get(&position_id)
                    .unwrap()
                    .pending_rewards_spark,
                imported
                    .state
                    .stake_positions
                    .get(&position_id)
                    .unwrap()
                    .pending_rewards_spark
            );
            imported_state = imported.state;
            previous_qc = build_qc_bytes(QcFixture {
                height: block.header.height,
                round: block.header.proposer_round,
                value_hash: block.header.block_hash(),
                validator_id,
                hybrid: &hybrid,
                pq_pk: hybrid.public_key().pq.0.to_vec(),
                stake: 10_000,
                snapshot_root: imported_state
                    .snapshot_for_consensus_height(block.header.height)
                    .unwrap()
                    .snapshot_root,
            });
        }
    }

    #[test]
    fn optimized_import_projection_roots_match_old_two_call_reference() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, hybrid) = install_active_validator(&mut state, 0x71, 10_000, true, true);
        let mut prev_qc = Vec::new();

        for _ in 0..4 {
            let block = make_strict_block(&state, 0x71, 0, prev_qc.clone());
            let mut old_reference = state.clone();
            let old_epoch_record =
                apply_verified_test(&mut old_reference, &block, 1_900_000_000).unwrap();
            let old_state_root = compute_state_root(&old_reference);
            let old_validator_set_root = compute_validator_set_root(&old_reference);
            let old_value_hash = block.compute_value_hash(old_reference.total_supply);

            let verified = verify_test(&state, &block);
            let optimized =
                project_and_verify_block_state_root(&verified, &state, 1_900_000_000).unwrap();
            assert_eq!(optimized.epoch_record, old_epoch_record);
            assert_eq!(optimized.state, old_reference);
            assert_eq!(compute_state_root(&optimized.state), old_state_root);
            assert_eq!(
                compute_validator_set_root(&optimized.state),
                old_validator_set_root
            );
            assert_eq!(
                block.compute_value_hash(optimized.state.total_supply),
                old_value_hash
            );

            state = optimized.state;
            prev_qc = build_qc_bytes(QcFixture {
                height: block.header.height,
                round: block.header.proposer_round,
                value_hash: block.header.block_hash(),
                validator_id,
                hybrid: &hybrid,
                pq_pk: hybrid.public_key().pq.0.to_vec(),
                stake: 10_000,
                snapshot_root: state
                    .snapshot_for_consensus_height(block.header.height)
                    .unwrap()
                    .snapshot_root,
            });
        }
    }

    #[test]
    fn live_import_projection_commit_preserves_epoch_record_timestamp() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, hybrid) = install_active_validator(&mut state, 0x62, 10_000, true, true);
        advance_fixture_height_with_issuance(&mut state, EPOCH_DURATION_BLOCKS - 1);
        state.tip_hash = Bytes32::from([0xA5; 32]);

        let parent_qc = build_qc_bytes(QcFixture {
            height: state.height,
            round: 0,
            value_hash: state.tip_hash,
            validator_id,
            hybrid: &hybrid,
            pq_pk: hybrid.public_key().pq.0.to_vec(),
            stake: 10_000,
            snapshot_root: state
                .snapshot_for_consensus_height(state.height)
                .unwrap()
                .snapshot_root,
        });
        let mut mempool = Mempool::default_config();
        let timestamp_secs = 1_999_999_999;
        let block = make_strict_block(&state, 0x62, 0, parent_qc);

        let projection = validate_imported_block(&block, &state, timestamp_secs).unwrap();
        let record = projection
            .epoch_record
            .clone()
            .expect("height 300 must produce an epoch record");
        state = projection.state;
        publish_committed_effects(&state, &mut mempool, &projection.effects).unwrap();

        assert_eq!(block.header.height, EPOCH_DURATION_BLOCKS);
        assert_eq!(record.epoch, 0);
        assert_eq!(record.start_height, 1);
        assert_eq!(record.end_height, EPOCH_DURATION_BLOCKS);
        assert_eq!(record.timestamp_secs, timestamp_secs);
        assert_eq!(state.height, EPOCH_DURATION_BLOCKS);
        assert_eq!(compute_state_root(&state).unwrap(), block.header.state_root);
    }

    #[test]
    fn failed_projection_root_mismatch_rolls_back_state_mempool_and_storage() {
        let dir = temp_dir("projection_root_rollback");
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = crate::genesis::test_genesis_state();
        let original_state = state.clone();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(
            dir.join("blocks.log"),
            indra_storage::PruneConfig::archive(),
        )
        .unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();
        let mut block = make_block(&state);
        block.header.state_root = Bytes32::from([0xEE; 32]);
        authorize_canonical_test_proposal(&mut block, state.chain_id.as_bytes());

        let err = import_unfinalized_block_for_test(
            &block,
            &mut state,
            &mut mempool,
            &mut block_store,
            &state_store,
            0,
        )
        .unwrap_err();

        match err {
            NodeError::BlockInvalid { reason, .. } => {
                assert!(
                    reason.contains("state_root mismatch"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(state, original_state);
        assert_eq!(mempool.len(), 0);
        assert!(block_store.is_empty());
        assert_eq!(state_store.latest_snapshot_height().unwrap(), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_projection_apply_error_rolls_back_state_mempool_and_storage() {
        let dir = temp_dir("projection_apply_rollback");
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = crate::genesis::test_genesis_state();
        let original_state = state.clone();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(
            dir.join("blocks.log"),
            indra_storage::PruneConfig::archive(),
        )
        .unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();
        let mut block = make_block(&state);
        block.header.base_fee = block.header.base_fee.saturating_add(1);
        authorize_canonical_test_proposal(&mut block, state.chain_id.as_bytes());

        let err = import_unfinalized_block_for_test(
            &block,
            &mut state,
            &mut mempool,
            &mut block_store,
            &state_store,
            0,
        )
        .unwrap_err();

        match err {
            NodeError::BlockInvalid { reason, .. } => {
                assert!(
                    reason.contains("block failed during pre-apply root verification"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(state, original_state);
        assert_eq!(mempool.len(), 0);
        assert!(block_store.is_empty());
        assert_eq!(state_store.latest_snapshot_height().unwrap(), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn durable_append_rejection_cannot_publish_projected_state_or_pool_effects() {
        let dir = temp_dir("durable_append_before_publish");
        std::fs::create_dir_all(&dir).unwrap();
        let mut state = crate::genesis::test_genesis_state();
        let original_state = state.clone();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(
            dir.join("blocks.log"),
            indra_storage::PruneConfig::archive(),
        )
        .unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();
        let block = make_block(&state);

        block_store
            .append(&crate::genesis::build_genesis_proposal(&state).unwrap())
            .unwrap();
        block_store.append(&block).unwrap();
        let error = import_unfinalized_block_for_test(
            &block,
            &mut state,
            &mut mempool,
            &mut block_store,
            &state_store,
            0,
        )
        .unwrap_err();
        assert!(error.to_string().contains("non-sequential write"));
        assert_eq!(state, original_state);
        assert!(mempool.is_empty());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn projected_verifier_preserves_root_error_strings() {
        let state = crate::genesis::test_genesis_state();

        let mut bad_state_root = make_block(&state);
        bad_state_root.header.state_root = Bytes32::from([0xE1; 32]);
        authorize_canonical_test_proposal(&mut bad_state_root, state.chain_id.as_bytes());
        let err = verify_block_state_root(&bad_state_root, &state).unwrap_err();
        assert!(err.to_string().contains("state_root mismatch"));

        let mut bad_validator_root = make_block(&state);
        bad_validator_root.header.validator_set_root = Bytes32::from([0xE2; 32]);
        authorize_canonical_test_proposal(&mut bad_validator_root, state.chain_id.as_bytes());
        let err = verify_block_state_root(&bad_validator_root, &state).unwrap_err();
        assert!(err.to_string().contains("validator_set_root mismatch"));

        let mut bad_value_hash = make_block(&state);
        bad_value_hash.header.value_hash = Bytes32::from([0xE3; 32]);
        authorize_canonical_test_proposal(&mut bad_value_hash, state.chain_id.as_bytes());
        let err = verify_block_state_root(&bad_value_hash, &state).unwrap_err();
        assert!(err.to_string().contains("value_hash mismatch"));

        let mut apply_failure = make_block(&state);
        apply_failure.header.prev_hash = Bytes32::from([0xE4; 32]);
        authorize_canonical_test_proposal(&mut apply_failure, state.chain_id.as_bytes());
        let err = verify_block_state_root(&apply_failure, &state).unwrap_err();
        assert!(err
            .to_string()
            .contains("block failed during pre-apply root verification"));
    }

    #[test]
    fn governed_sync_verification_fails_closed_without_snapshot() {
        let mut state = crate::genesis::test_genesis_state();
        let proposal = make_block(&state);
        state.consensus_snapshots.clear();
        let error = verify_block_state_root(&proposal, &state).unwrap_err();
        assert!(error.to_string().contains("consensus snapshot"));
    }

    #[test]
    fn sync_import_guard_uses_snapshot_when_live_active_set_is_empty() {
        let mut state = crate::genesis::test_genesis_state();
        let proposal = make_block(&state);
        for validator_id in state
            .validators
            .active_validators()
            .map(|validator| validator.validator_id)
            .collect::<Vec<_>>()
        {
            state.validators.get_mut(&validator_id).unwrap().status =
                indra_state::ValidatorStatus::Registered;
        }
        assert_eq!(state.validators.active_count(), 0);
        verify_block_state_root(&proposal, &state).unwrap();
    }

    #[test]
    fn import_chain_of_blocks() {
        let dir = temp_dir("b");
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let _ = install_active_validator(&mut state, 0x41, 10_000, true, true);
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(
            dir.join("blocks.log"),
            indra_storage::PruneConfig::archive(),
        )
        .unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        let classical = indra_crypto::hybrid::ClassicalKeypair::from_seed(&[0x41; 32]);
        let pq = indra_crypto::hybrid::PqKeypair::from_seed(&[0x41; 32]).unwrap();
        let hybrid = indra_crypto::hybrid::HybridKeypair::new(classical, pq);
        let validator_id = indra_core::types::crypto::hybrid_identity_id(
            &hybrid.public_key().classical.0,
            &hybrid.public_key().pq.0,
        );
        let pq_pk = hybrid.public_key().pq.0.to_vec();
        let mut prev_qc = Vec::new();
        for i in 1..=10u64 {
            let block = make_strict_block(&state, 0x41, 0, prev_qc.clone());
            import_unfinalized_block_for_test(
                &block,
                &mut state,
                &mut mempool,
                &mut block_store,
                &state_store,
                0,
            )
            .unwrap();
            prev_qc = build_qc_bytes(QcFixture {
                height: block.header.height,
                round: block.header.proposer_round,
                value_hash: block.header.block_hash(),
                validator_id,
                hybrid: &hybrid,
                pq_pk: pq_pk.clone(),
                stake: 10_000,
                snapshot_root: state
                    .snapshot_for_consensus_height(block.header.height)
                    .unwrap()
                    .snapshot_root,
            });
            assert_eq!(state.height, i);
        }

        assert_eq!(state.height, 10);
        assert_eq!(block_store.len(), 11); // genesis (0) + blocks 1-10

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_height_rejected() {
        let dir = temp_dir("c");
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = crate::genesis::test_genesis_state();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(
            dir.join("blocks.log"),
            indra_storage::PruneConfig::archive(),
        )
        .unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        // Try to import height 5 when we're at genesis (height 0)
        let mut block = make_block(&state);
        block.header.height = 5;
        authorize_canonical_test_proposal(&mut block, state.chain_id.as_bytes());
        assert!(import_unfinalized_block_for_test(
            &block,
            &mut state,
            &mut mempool,
            &mut block_store,
            &state_store,
            0
        )
        .is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn single_peer_cannot_raise_target_past_corroborated_height() {
        let peer_a: SocketAddr = "127.0.0.1:30001".parse().unwrap();
        let peer_b: SocketAddr = "127.0.0.1:30002".parse().unwrap();
        let mut sync = SyncState::follower(0);

        assert_eq!(
            observe_for_test(&mut sync, 1, peer_a, 550, 0),
            Some((peer_a, 1, 51))
        );
        assert_eq!(
            observe_for_test(&mut sync, 2, peer_b, 8_314, 0),
            None,
            "an outstanding bound request is not replaced by a later height claim"
        );

        for height in 1..=550 {
            sync.on_block_imported(height);
        }

        assert_eq!(sync.next_request_after_response(550), None);
        assert!(matches!(sync.phase(), SyncPhase::AwaitingPeers));
        assert!(
            !sync.is_caught_up(),
            "50-block checkpoints require a fresh status"
        );
    }

    #[test]
    fn false_height_requires_two_identities_and_one_third_stake() {
        let now = Instant::now();
        let peer_a: SocketAddr = "127.0.0.1:30101".parse().unwrap();
        let peer_b: SocketAddr = "127.0.0.1:30102".parse().unwrap();
        let id_a = Bytes32::from([0xA1; 32]);
        let id_b = Bytes32::from([0xA2; 32]);
        let mut sync = SyncState::follower(0);
        sync.peer_connected(id_a);
        sync.peer_connected(id_b);

        assert_eq!(
            sync.observe_status((id_a, peer_a, 10_000, Bytes32::ZERO, 33, 100, 0).into(), now),
            None,
            "one sub-one-third identity must not set a target"
        );
        assert_eq!(
            sync.observe_status((id_b, peer_b, 10_000, Bytes32::ZERO, 1, 100, 0).into(), now),
            Some((peer_a, 1, 51)),
            "two identities with combined stake strictly above one third corroborate"
        );
    }

    #[test]
    fn single_peer_graceful_degradation_never_relaxes_stake_threshold() {
        let now = Instant::now();
        let peer: SocketAddr = "127.0.0.1:30103".parse().unwrap();
        let id = Bytes32::from([0xA3; 32]);
        let mut sync = SyncState::follower(0);
        sync.peer_connected(id);
        assert_eq!(
            sync.observe_status((id, peer, 9_000, Bytes32::ZERO, 33, 100, 0).into(), now),
            None
        );
        assert_eq!(
            sync.observe_status((id, peer, 9_000, Bytes32::ZERO, 34, 100, 0).into(), now),
            Some((peer, 1, 51))
        );
    }

    #[test]
    fn height_claims_expire_after_thirty_seconds() {
        let now = Instant::now();
        let peer: SocketAddr = "127.0.0.1:30104".parse().unwrap();
        let id = Bytes32::from([0xA4; 32]);
        let mut sync = SyncState::follower(0);
        sync.peer_connected(id);
        assert!(sync
            .observe_status((id, peer, 42, Bytes32::ZERO, 100, 100, 0).into(), now)
            .is_some());
        assert!(sync
            .corroborated_target(0, now + SYNC_HEIGHT_CLAIM_TTL + Duration::from_millis(1))
            .is_none());
    }

    #[test]
    fn diagnostics_reports_exact_phase_claim_provisional_and_circuit_state() {
        let now = Instant::now();
        let peer: SocketAddr = "127.0.0.1:30140".parse().unwrap();
        let mut sync = SyncState::follower(40);

        assert_eq!(
            sync.diagnostics(40, now),
            SyncDiagnostics {
                phase: "awaiting_peers",
                local_height: 40,
                target_height: None,
                provisional_height: None,
                corroboration_claim_count: 0,
                circuit_breaker_open: false,
                recovery_required: false,
            }
        );
        sync.phase = SyncPhase::CaughtUp;
        assert_eq!(sync.diagnostics(40, now).phase, "caught_up");

        sync.phase = SyncPhase::Downloading {
            peer,
            target_height: 52,
            next_expected: 41,
        };
        sync.height_claims.insert(
            Bytes32::from([1; 32]),
            HeightClaim {
                addr: peer,
                height: 52,
                tip_hash: Bytes32::from([11; 32]),
                stake: 10,
                expires_at: now - Duration::from_millis(1),
            },
        );
        sync.height_claims.insert(
            Bytes32::from([2; 32]),
            HeightClaim {
                addr: peer,
                height: 52,
                tip_hash: Bytes32::from([12; 32]),
                stake: 20,
                expires_at: now,
            },
        );
        sync.height_claims.insert(
            Bytes32::from([3; 32]),
            HeightClaim {
                addr: peer,
                height: 52,
                tip_hash: Bytes32::from([13; 32]),
                stake: 30,
                expires_at: now + Duration::from_secs(1),
            },
        );

        let state = crate::genesis::test_genesis_state();
        let block = make_block(&state);
        let provisional_height = block.header.height;
        let prepared = PreparedSyncBlock {
            block_hash: block.header.block_hash(),
            pre_height: state.height,
            pre_tip_hash: state.tip_hash,
            state,
            epoch_record: None,
            effects: CanonicalStateEffects::default(),
        };
        sync.stage_provisional(block, prepared, Bytes32::from([3; 32]), peer, now);

        sync.circuit_open_until
            .insert(50, now - Duration::from_millis(1));
        sync.circuit_open_until.insert(51, now);
        sync.circuit_open_until
            .insert(52, now + Duration::from_secs(1));

        assert_eq!(
            sync.diagnostics(40, now),
            SyncDiagnostics {
                phase: "downloading",
                local_height: 40,
                target_height: Some(52),
                provisional_height: Some(provisional_height),
                // Both an already-expired claim and one expiring exactly at
                // `now` are excluded; only expires_at > now remains live.
                corroboration_claim_count: 1,
                circuit_breaker_open: true,
                recovery_required: false,
            }
        );

        sync.circuit_open_until
            .insert(52, now - Duration::from_millis(1));
        assert!(
            !sync.diagnostics(40, now).circuit_breaker_open,
            "past and exactly-now breaker deadlines must both be closed"
        );
    }

    #[test]
    fn response_binding_rejects_unsolicited_wrong_peer_and_out_of_range() {
        let peer: SocketAddr = "127.0.0.1:30105".parse().unwrap();
        let wrong_peer: SocketAddr = "127.0.0.1:30106".parse().unwrap();
        let id = Bytes32::from([0xA5; 32]);
        let wrong_id = Bytes32::from([0xA6; 32]);
        let mut sync = SyncState::follower(0);
        assert!(sync.accept_response(id, peer, &[]).is_err());
        sync.peer_connected(id);
        sync.observe_status((id, peer, 2, Bytes32::ZERO, 100, 100, 0).into(), Instant::now());
        assert!(sync.accept_response(wrong_id, wrong_peer, &[]).is_err());
        let mut out_of_range = make_block(&crate::genesis::test_genesis_state());
        out_of_range.header.height = 99;
        assert!(sync.accept_response(id, peer, &[out_of_range]).is_err());
    }

    #[test]
    fn provisional_qc_response_requires_selected_peer_and_height() {
        let peer: SocketAddr = "127.0.0.1:30109".parse().unwrap();
        let wrong_peer: SocketAddr = "127.0.0.1:30110".parse().unwrap();
        let id = Bytes32::from([0xA9; 32]);
        let wrong_id = Bytes32::from([0xAA; 32]);
        let now = Instant::now();
        let state = crate::genesis::test_genesis_state();
        let block = make_block(&state);
        let height = block.header.height;
        let prepared = PreparedSyncBlock {
            block_hash: block.header.block_hash(),
            pre_height: state.height,
            pre_tip_hash: state.tip_hash,
            state,
            epoch_record: None,
            effects: CanonicalStateEffects::default(),
        };
        let mut sync = SyncState::follower(0);
        sync.stage_provisional(block, prepared, id, peer, now);
        assert!(sync
            .accept_provisional_qc_response(wrong_id, wrong_peer, height)
            .is_err());
        assert!(sync
            .accept_provisional_qc_response(id, peer, height + 1)
            .is_err());
        assert!(sync
            .accept_provisional_qc_response(id, peer, height)
            .is_ok());
        sync.clear_provisional();
        assert!(sync
            .accept_provisional_qc_response(id, peer, height)
            .is_err());
    }

    #[test]
    fn disconnect_clears_selected_peer_and_outstanding_request() {
        let peer: SocketAddr = "127.0.0.1:30107".parse().unwrap();
        let id = Bytes32::from([0xA7; 32]);
        let mut sync = SyncState::follower(0);
        sync.peer_connected(id);
        sync.observe_status((id, peer, 2, Bytes32::ZERO, 100, 100, 0).into(), Instant::now());
        sync.peer_disconnected(id, peer);
        assert!(matches!(sync.phase(), SyncPhase::AwaitingPeers));
        assert!(sync.accept_response(id, peer, &[]).is_err());
    }

    #[test]
    fn stalled_request_expires_and_releases_selected_source() {
        let now = Instant::now();
        let peer: SocketAddr = "127.0.0.1:30108".parse().unwrap();
        let id = Bytes32::from([0xA8; 32]);
        let mut sync = SyncState::follower(0);
        sync.peer_connected(id);
        sync.observe_status((id, peer, 2, Bytes32::ZERO, 100, 100, 0).into(), now);
        assert!(sync.expire_outstanding(now).is_none());
        let expired = sync
            .expire_outstanding(now + SYNC_REQUEST_TIMEOUT + Duration::from_millis(1))
            .unwrap();
        assert_eq!(expired.validator_id, id);
        assert!(matches!(sync.phase(), SyncPhase::AwaitingPeers));
    }

    #[test]
    fn three_distinct_expensive_failures_open_circuit_for_sixty_seconds() {
        let now = Instant::now();
        let mut sync = SyncState::follower(0);
        assert!(!sync.note_expensive_failure(7, Bytes32::from([1; 32]), now));
        assert!(!sync.note_expensive_failure(7, Bytes32::from([2; 32]), now));
        assert!(sync.note_expensive_failure(7, Bytes32::from([3; 32]), now));
        assert!(sync.circuit_open(7, now));
        assert!(!sync.circuit_open(
            7,
            now + SYNC_FAILURE_CIRCUIT_BREAKER + Duration::from_millis(1)
        ));
    }

    #[test]
    fn valid_qc_for_other_hash_proves_provisional_block_is_wrong() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, hybrid) = install_active_validator(&mut state, 0xB1, 10_000, true, true);
        let real = make_strict_block(&state, 0xB1, 0, vec![]);
        let mut unfinalized_fork = real.clone();
        unfinalized_fork.header.timestamp = unfinalized_fork.header.timestamp.saturating_add(1);
        let mut fork_projection_state = state.clone();
        let roots = indra_state::project_block_for_roots(
            &mut fork_projection_state,
            &unfinalized_fork.block,
            0,
        )
        .unwrap();
        unfinalized_fork.header.state_root = roots.state_root;
        unfinalized_fork.header.validator_set_root = roots.validator_set_root;
        unfinalized_fork.header.value_hash = roots.value_hash;
        authorize_test_proposal(
            &mut unfinalized_fork,
            state.chain_id.as_bytes(),
            [0xB1; 32],
            [0xB1; 32],
        );
        verify_sync_candidate(&unfinalized_fork, &state, 0).unwrap();

        let qc = build_qc_bytes(QcFixture {
            height: real.header.height,
            round: real.header.proposer_round,
            value_hash: real.header.block_hash(),
            validator_id,
            hybrid: &hybrid,
            pq_pk: hybrid.public_key().pq.0.to_vec(),
            stake: 10_000,
            snapshot_root: state
                .snapshot_for_consensus_height(real.header.height)
                .unwrap()
                .snapshot_root,
        });
        let mut after_real = state.clone();
        apply_verified_test(&mut after_real, &real, 0).unwrap();
        let carrier = make_strict_block(&after_real, 0xB1, 0, qc);

        match verify_provisional_certificate(&unfinalized_fork, &carrier, &state) {
            Err(PairVerificationError::ProvisionalBlockWrong { certified_hash }) => {
                assert_eq!(certified_hash, real.header.block_hash());
            }
            other => panic!("wrong fault attribution: {other:?}"),
        }
        assert_eq!(
            state.height, 0,
            "provisional fork must remain non-canonical"
        );
    }

    #[test]
    fn invalid_later_certificate_is_attributed_to_carrier() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, hybrid) = install_active_validator(&mut state, 0xB2, 10_000, true, true);
        let block = make_strict_block(&state, 0xB2, 0, vec![]);
        let mut qc = build_qc_bytes(QcFixture {
            height: block.header.height,
            round: block.header.proposer_round,
            value_hash: block.header.block_hash(),
            validator_id,
            hybrid: &hybrid,
            pq_pk: hybrid.public_key().pq.0.to_vec(),
            stake: 10_000,
            snapshot_root: state
                .snapshot_for_consensus_height(block.header.height)
                .unwrap()
                .snapshot_root,
        });
        *qc.last_mut().unwrap() ^= 0x01;
        let mut after_block = state.clone();
        apply_verified_test(&mut after_block, &block, 0).unwrap();
        let valid_qc = build_qc_bytes(QcFixture {
            height: block.header.height,
            round: block.header.proposer_round,
            value_hash: block.header.block_hash(),
            validator_id,
            hybrid: &hybrid,
            pq_pk: hybrid.public_key().pq.0.to_vec(),
            stake: 10_000,
            snapshot_root: state
                .snapshot_for_consensus_height(block.header.height)
                .unwrap()
                .snapshot_root,
        });
        let mut carrier = make_strict_block(&after_block, 0xB2, 0, valid_qc);
        replace_qc_and_reauthorize(&mut carrier, qc, 0xB2, after_block.chain_id.as_bytes());

        assert!(matches!(
            verify_provisional_certificate(&block, &carrier, &state),
            Err(PairVerificationError::CertificateCarrierWrong(_))
        ));
        assert_eq!(state.height, 0);
    }

    #[test]
    fn offline_recovery_writes_new_directory_and_copies_only_certified_prefix() {
        let source_dir = temp_dir("offline_recovery_source");
        let destination_dir = temp_dir("offline_recovery_destination");
        let mut source =
            crate::NodeEngine::init(crate::NodeConfig::local_test(source_dir.clone())).unwrap();
        let classical = ClassicalKeypair::from_seed(&[0x42; 32]);
        let pq = PqKeypair::from_seed(&[0x42; 32]).unwrap();
        let hybrid = HybridKeypair::new(classical, pq);
        let validator_id = indra_core::types::crypto::hybrid_identity_id(
            &hybrid.public_key().classical.0,
            &hybrid.public_key().pq.0,
        );
        let stake = source.state.validators.total_active_stake();

        let mut block1 = make_strict_block(&source.state, 0x42, 0, vec![]);
        authorize_test_proposal(
            &mut block1,
            source.state.chain_id.as_bytes(),
            [0x42; 32],
            [0x42; 32],
        );
        source.commit_proposal(&block1).unwrap();
        let qc1 = build_qc_bytes(QcFixture {
            height: 1,
            round: block1.header.proposer_round,
            value_hash: block1.header.block_hash(),
            validator_id,
            hybrid: &hybrid,
            pq_pk: hybrid.public_key().pq.0.to_vec(),
            stake,
            snapshot_root: source
                .state
                .snapshot_for_consensus_height(1)
                .unwrap()
                .snapshot_root,
        });
        let mut block2 = make_strict_block(&source.state, 0x42, 0, qc1);
        authorize_test_proposal(
            &mut block2,
            source.state.chain_id.as_bytes(),
            [0x42; 32],
            [0x42; 32],
        );
        source.commit_proposal(&block2).unwrap();
        let qc2 = build_qc_bytes(QcFixture {
            height: 2,
            round: block2.header.proposer_round,
            value_hash: block2.header.block_hash(),
            validator_id,
            hybrid: &hybrid,
            pq_pk: hybrid.public_key().pq.0.to_vec(),
            stake,
            snapshot_root: source
                .state
                .snapshot_for_consensus_height(2)
                .unwrap()
                .snapshot_root,
        });
        indra_storage::save_last_qc(&source.config.state_dir(), &qc2).unwrap();
        let genesis_path = source_dir.join("genesis.toml");
        drop(source);

        let mut destination_config = crate::NodeConfig::full_node(destination_dir.clone());
        destination_config.genesis_path = Some(genesis_path.to_string_lossy().into_owned());
        let report =
            crate::recovery::recover_finalized_prefix(&source_dir, destination_config).unwrap();
        assert_eq!(report.recovered_height, 2);
        assert_eq!(report.first_unfinalized_height, None);

        let recovered = crate::NodeEngine::init({
            let mut config = crate::NodeConfig::full_node(destination_dir.clone());
            config.genesis_path = Some(genesis_path.to_string_lossy().into_owned());
            config
        })
        .unwrap();
        assert_eq!(recovered.height(), 2);
        assert_eq!(recovered.state.tip_hash, block2.header.block_hash());

        let _ = std::fs::remove_dir_all(source_dir);
        let _ = std::fs::remove_dir_all(destination_dir);
    }

    #[test]
    #[ignore = "real-hardware release benchmark; run explicitly with --release --ignored --nocapture"]
    fn buffered_sync_real_hardware_benchmark() {
        const FINALIZED_BLOCKS: usize = 50;
        let mut builder = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, hybrid) =
            install_active_validator(&mut builder, 0xC1, 10_000, true, true);
        let initial = builder.clone();
        let mut blocks = Vec::with_capacity(FINALIZED_BLOCKS + 1);
        let mut previous_qc = Vec::new();
        for _ in 0..=FINALIZED_BLOCKS {
            let block = make_strict_block(&builder, 0xC1, 0, previous_qc);
            previous_qc = build_qc_bytes(QcFixture {
                height: block.header.height,
                round: block.header.proposer_round,
                value_hash: block.header.block_hash(),
                validator_id,
                hybrid: &hybrid,
                pq_pk: hybrid.public_key().pq.0.to_vec(),
                stake: 10_000,
                snapshot_root: builder
                    .snapshot_for_consensus_height(block.header.height)
                    .unwrap()
                    .snapshot_root,
            });
            apply_verified_test(&mut builder, &block, 0).unwrap();
            blocks.push(block);
        }

        let dir = temp_dir("buffered_sync_benchmark");
        std::fs::create_dir_all(&dir).unwrap();
        let mut state = initial;
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(
            dir.join("blocks.log"),
            indra_storage::PruneConfig::archive(),
        )
        .unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();
        let started = Instant::now();
        for pair in blocks.windows(2) {
            let prepared = verify_sync_candidate(&pair[0], &state, 0).unwrap();
            verify_provisional_certificate(&pair[0], &pair[1], &state).unwrap();
            commit_prepared_with_durable_hook(
                &pair[0],
                prepared,
                &mut state,
                &mut mempool,
                &mut block_store,
                &state_store,
                |_, _, _| Ok(()),
            )
            .unwrap();
        }
        let elapsed = started.elapsed();
        eprintln!(
            "BUFFERED_SYNC_BENCH blocks={} total_ms={:.3} per_block_ms={:.3} blocks_per_sec={:.3}",
            FINALIZED_BLOCKS,
            elapsed.as_secs_f64() * 1_000.0,
            elapsed.as_secs_f64() * 1_000.0 / FINALIZED_BLOCKS as f64,
            FINALIZED_BLOCKS as f64 / elapsed.as_secs_f64(),
        );
        assert_eq!(state.height, FINALIZED_BLOCKS as u64);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[ignore = "real-hardware 200-validator aggregate invalid-QC benchmark"]
    fn aggregate_network_qc_budget_real_hardware_benchmark() {
        const VALIDATORS: usize = 200;
        const SIGNERS: usize = 134;
        const BYZANTINE_SOURCES: usize = 67;

        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let mut keypairs = Vec::with_capacity(VALIDATORS);
        for seed in 1..=VALIDATORS {
            let (_, keypair) =
                install_active_validator(&mut state, u8::try_from(seed).unwrap(), 1, true, true);
            keypairs.push(keypair);
        }
        install_test_snapshot_at_inert_gate(&mut state);
        let snapshot = state.snapshot_for_consensus_height(u64::MAX).unwrap();
        let signers: Vec<_> = keypairs.iter().take(SIGNERS).collect();
        let valid = qc_from_test_signers(u64::MAX, Bytes32::from([0xD4; 32]), snapshot, &signers);
        let invalid: Vec<_> = (0..BYZANTINE_SOURCES)
            .map(|mutation| {
                let mut qc = valid.clone();
                qc.classical_signatures.last_mut().unwrap().classical_sig =
                    VariableBytes::from_slice(&[u8::try_from(mutation + 1).unwrap(); 64]).unwrap();
                qc
            })
            .collect();

        let direct_started = Instant::now();
        for qc in &invalid {
            assert!(crate::engine::NodeEngine::verify_qc_with_snapshot(
                qc,
                snapshot,
                &state.chain_id,
            )
            .is_err());
        }
        let direct_elapsed = direct_started.elapsed();

        let verifier = crate::qc_verification::NetworkQcVerifier::new();
        let governed_started = Instant::now();
        for qc in &invalid {
            assert!(verifier.verify(qc, snapshot, &state.chain_id).is_err());
        }
        let governed_elapsed = governed_started.elapsed();
        let minimum_budgeted = crate::qc_verification::NETWORK_QC_MIN_START_INTERVAL
            * u32::try_from(BYZANTINE_SOURCES - 1).unwrap();
        assert!(governed_elapsed >= minimum_budgeted);
        eprintln!(
            "NETWORK_QC_AGGREGATE_BENCH validators={VALIDATORS} signers={SIGNERS} sources={BYZANTINE_SOURCES} direct_ms={:.3} governed_ms={:.3} direct_qc_per_sec={:.3} governed_qc_per_sec={:.3}",
            direct_elapsed.as_secs_f64() * 1_000.0,
            governed_elapsed.as_secs_f64() * 1_000.0,
            BYZANTINE_SOURCES as f64 / direct_elapsed.as_secs_f64(),
            BYZANTINE_SOURCES as f64 / governed_elapsed.as_secs_f64(),
        );
    }

    #[test]
    fn follower_waits_for_first_peer_status() {
        let peer: SocketAddr = "127.0.0.1:30004".parse().unwrap();
        let mut sync = SyncState::follower(10);

        assert!(!sync.is_caught_up());
        assert_eq!(observe_for_test(&mut sync, 3, peer, 10, 10), None);
        assert!(sync.is_caught_up());
    }

    #[test]
    fn mark_caught_up_sets_received_peer_status() {
        let mut sync = SyncState::follower(0);

        assert!(
            !sync.is_caught_up(),
            "follower must not be caught up before receiving Status"
        );

        sync.mark_caught_up(1);

        assert!(
            sync.is_caught_up(),
            "follower must be caught up after mark_caught_up (block committed)"
        );
    }

    #[test]
    fn follower_not_caught_up_before_any_communication() {
        let sync = SyncState::follower(0);
        assert!(!sync.is_caught_up());
    }

    #[test]
    fn follower_caught_up_after_status_then_commit() {
        let mut sync = SyncState::follower(0);
        let peer: SocketAddr = "1.2.3.4:30303".parse().unwrap();

        observe_for_test(&mut sync, 4, peer, 0, 0);
        assert!(sync.is_caught_up());

        sync.mark_caught_up(1);
        assert!(sync.is_caught_up());
    }

    #[test]
    fn bootstrap_node_at_nonzero_height_waits_for_peer_status() {
        let peer: SocketAddr = "127.0.0.1:30005".parse().unwrap();
        let mut sync = SyncState::bootstrap(10);

        assert!(!sync.is_caught_up());
        assert_eq!(observe_for_test(&mut sync, 5, peer, 10, 10), None);
        assert!(sync.is_caught_up());
    }

    #[test]
    fn empty_block_response_does_not_stall_sync() {
        let peer: SocketAddr = "127.0.0.1:30006".parse().unwrap();
        let mut sync = SyncState::follower(10);

        assert_eq!(
            observe_for_test(&mut sync, 6, peer, 11, 10),
            Some((peer, 11, 12))
        );
        assert!(!sync.is_caught_up());

        sync.on_empty_response();
        assert!(!sync.is_caught_up());
        assert!(sync.next_request_after_response(10).is_none());
    }

    #[test]
    fn one_block_behind_recovers_automatically() {
        let peer: SocketAddr = "127.0.0.1:30003".parse().unwrap();
        let mut sync = SyncState::follower(530);

        assert_eq!(
            observe_for_test(&mut sync, 7, peer, 531, 530),
            Some((peer, 531, 532))
        );
        assert!(!sync.is_caught_up());

        sync.on_block_imported(531);
        assert!(sync.is_caught_up());
        assert!(sync.next_request_after_response(531).is_none());
    }

    #[test]
    fn strict_block_one_accepts_empty_qc() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (_validator_id, _hybrid) =
            install_active_validator(&mut state, 0x11, 10_000, true, true);
        let block = make_strict_block(&state, 0x11, 0, vec![]);

        let _ = verify_test(&state, &block);
        assert!(verify_block_qc(&block, &state).is_ok());
        assert!(verify_block_state_root(&block, &state).is_ok());
    }

    #[test]
    fn strict_block_two_rejects_empty_qc() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, hybrid) = install_active_validator(&mut state, 0x12, 10_000, true, true);
        let block1 = make_strict_block(&state, 0x12, 0, vec![]);
        apply_verified_test(&mut state, &block1, 0).unwrap();

        let valid_qc = build_qc_bytes(QcFixture {
            height: block1.header.height,
            round: block1.header.proposer_round,
            value_hash: block1.header.block_hash(),
            validator_id,
            hybrid: &hybrid,
            pq_pk: hybrid.public_key().pq.0.to_vec(),
            stake: 10_000,
            snapshot_root: state
                .snapshot_for_consensus_height(block1.header.height)
                .unwrap()
                .snapshot_root,
        });
        let mut block2 = make_strict_block(&state, 0x12, 0, valid_qc);
        replace_qc_and_reauthorize(&mut block2, vec![], 0x12, state.chain_id.as_bytes());
        let err = verify_block_qc(&block2, &state).unwrap_err();
        match err {
            NodeError::BlockInvalid { reason, .. } => {
                assert!(reason.contains("missing quorum certificate"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_block_qc_rejects_wrong_height_qc() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, hybrid) = install_active_validator(&mut state, 0x14, 10_000, true, true);

        let block1 = make_strict_block(&state, 0x14, 0, vec![]);
        apply_verified_test(&mut state, &block1, 0).unwrap();

        let wrong_qc_bytes = build_qc_bytes(QcFixture {
            height: 3,
            round: block1.header.proposer_round,
            value_hash: block1.header.block_hash(),
            validator_id,
            hybrid: &hybrid,
            pq_pk: hybrid.public_key().pq.0.to_vec(),
            stake: 10_000,
            snapshot_root: state
                .snapshot_for_consensus_height(block1.header.height)
                .unwrap()
                .snapshot_root,
        });
        let valid_qc = build_qc_bytes(QcFixture {
            height: block1.header.height,
            round: block1.header.proposer_round,
            value_hash: block1.header.block_hash(),
            validator_id,
            hybrid: &hybrid,
            pq_pk: hybrid.public_key().pq.0.to_vec(),
            stake: 10_000,
            snapshot_root: state
                .snapshot_for_consensus_height(block1.header.height)
                .unwrap()
                .snapshot_root,
        });
        let mut block2 = make_strict_block(&state, 0x14, 0, valid_qc);
        replace_qc_and_reauthorize(&mut block2, wrong_qc_bytes, 0x14, state.chain_id.as_bytes());

        let err = verify_block_qc(&block2, &state).unwrap_err();
        match err {
            NodeError::BlockInvalid { reason, .. } => {
                assert!(
                    reason.contains("embedded QC height 3 does not match expected 1"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_block_qc_rejects_qc_certifying_wrong_parent_hash() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, hybrid) = install_active_validator(&mut state, 0x15, 10_000, true, true);

        let block1 = make_strict_block(&state, 0x15, 0, vec![]);
        let wrong_parent_hash = Bytes32::from([0xB0; 32]);
        assert_ne!(wrong_parent_hash, block1.header.block_hash());
        apply_verified_test(&mut state, &block1, 0).unwrap();

        let wrong_parent_qc_bytes = build_qc_bytes(QcFixture {
            height: block1.header.height,
            round: block1.header.proposer_round,
            value_hash: wrong_parent_hash,
            validator_id,
            hybrid: &hybrid,
            pq_pk: hybrid.public_key().pq.0.to_vec(),
            stake: 10_000,
            snapshot_root: state
                .snapshot_for_consensus_height(block1.header.height)
                .unwrap()
                .snapshot_root,
        });
        let valid_qc = build_qc_bytes(QcFixture {
            height: block1.header.height,
            round: block1.header.proposer_round,
            value_hash: block1.header.block_hash(),
            validator_id,
            hybrid: &hybrid,
            pq_pk: hybrid.public_key().pq.0.to_vec(),
            stake: 10_000,
            snapshot_root: state
                .snapshot_for_consensus_height(block1.header.height)
                .unwrap()
                .snapshot_root,
        });
        let mut block2 = make_strict_block(&state, 0x15, 0, valid_qc);
        replace_qc_and_reauthorize(
            &mut block2,
            wrong_parent_qc_bytes,
            0x15,
            state.chain_id.as_bytes(),
        );

        let err = verify_block_qc(&block2, &state).unwrap_err();
        match err {
            NodeError::BlockInvalid { reason, .. } => {
                assert!(
                    reason.contains("QC must certify the exact parent block"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_block_qc_accepts_qc_certifying_correct_parent_hash() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, hybrid) = install_active_validator(&mut state, 0x16, 10_000, true, true);

        let block1 = make_strict_block(&state, 0x16, 0, vec![]);
        apply_verified_test(&mut state, &block1, 0).unwrap();

        let qc_bytes = build_qc_bytes(QcFixture {
            height: block1.header.height,
            round: block1.header.proposer_round,
            value_hash: block1.header.block_hash(),
            validator_id,
            hybrid: &hybrid,
            pq_pk: hybrid.public_key().pq.0.to_vec(),
            stake: 10_000,
            snapshot_root: state
                .snapshot_for_consensus_height(block1.header.height)
                .unwrap()
                .snapshot_root,
        });
        let block2 = make_strict_block(&state, 0x16, 0, qc_bytes);

        assert!(verify_block_qc(&block2, &state).is_ok());
    }

    #[test]
    fn all_sync_qc_surfaces_reject_trailing_bytes() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, hybrid) = install_active_validator(&mut state, 0x17, 10_000, true, true);
        let block1 = make_strict_block(&state, 0x17, 0, vec![]);
        let valid_qc = build_qc_bytes(QcFixture {
            height: block1.header.height,
            round: block1.header.proposer_round,
            value_hash: block1.header.block_hash(),
            validator_id,
            hybrid: &hybrid,
            pq_pk: hybrid.public_key().pq.0.to_vec(),
            stake: 10_000,
            snapshot_root: state
                .snapshot_for_consensus_height(block1.header.height)
                .unwrap()
                .snapshot_root,
        });
        let mut qc_bytes = valid_qc.clone();
        qc_bytes.push(0xA5);

        let mut after_block = state.clone();
        apply_verified_test(&mut after_block, &block1, 0).unwrap();
        let mut carrier = make_strict_block(&after_block, 0x17, 0, valid_qc);
        replace_qc_and_reauthorize(
            &mut carrier,
            qc_bytes.clone(),
            0x17,
            after_block.chain_id.as_bytes(),
        );

        assert!(verify_block_qc(&carrier, &after_block).is_err());
        assert!(matches!(
            verify_provisional_certificate(&block1, &carrier, &state),
            Err(PairVerificationError::CertificateCarrierWrong(_))
        ));
        assert!(verify_direct_provisional_qc(&block1, &qc_bytes, &state).is_err());
        assert!(verify_sync_candidate(&carrier, &after_block, 0).is_err());
    }

    #[test]
    fn bounded_network_qc_queue_returns_every_admitted_outcome() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, hybrid) = install_active_validator(&mut state, 0x18, 10_000, true, true);
        install_test_snapshot_at_inert_gate(&mut state);
        let snapshot = state
            .snapshot_for_consensus_height(u64::MAX)
            .unwrap()
            .clone();
        let mut qc = QuorumCertificateV1::decode_exact(&build_qc_bytes(QcFixture {
            height: u64::MAX,
            round: 0,
            value_hash: Bytes32::from([0x18; 32]),
            validator_id,
            hybrid: &hybrid,
            pq_pk: hybrid.public_key().pq.0.to_vec(),
            stake: 10_000,
            snapshot_root: snapshot.snapshot_root,
        }))
        .unwrap();
        qc.classical_signatures[0].classical_sig = VariableBytes::from_slice(&[0xEE; 64]).unwrap();
        let verifier = crate::qc_verification::NetworkQcVerifier::new();
        let mut threads = Vec::new();
        for _ in 0..(crate::qc_verification::NETWORK_QC_QUEUE_CAPACITY + 4) {
            let verifier = verifier.clone();
            let snapshot = snapshot.clone();
            let qc = qc.clone();
            let chain_id = state.chain_id.clone();
            threads.push(std::thread::spawn(move || {
                verifier.verify(&qc, &snapshot, &chain_id)
            }));
        }
        let outcomes: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(
            outcomes.len(),
            crate::qc_verification::NETWORK_QC_QUEUE_CAPACITY + 4
        );
        assert!(outcomes.iter().all(Result::is_err));
        assert_eq!(
            verifier.expensive_verification_count(),
            1,
            "the first rejection must be cached for every exact replay"
        );
    }

    #[test]
    fn syncing_node_rejects_post_block_weight_inflation_qc_attack() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (a_id, a) = install_active_validator(&mut state, 0xB1, 20, true, true);
        install_active_validator(&mut state, 0xB2, 40, true, true);
        install_active_validator(&mut state, 0xB3, 40, true, true);
        install_test_snapshot_at_inert_gate(&mut state);
        let snapshot = state.snapshot_for_consensus_height(u64::MAX).unwrap();
        let qc = qc_from_test_signers(u64::MAX, Bytes32::from([0xB4; 32]), snapshot, &[&a]);

        state.validators.get_mut(&a_id).unwrap().stake_spark = 200;
        assert!(verify_qc_strict(
            &qc,
            &{
                let mut validators: Vec<_> = state.validators.active_validators().collect();
                validators.sort_by_key(|validator| validator.validator_id.0);
                validators
                    .into_iter()
                    .enumerate()
                    .map(|(position, validator)| QcValidator {
                        validator_id: validator.validator_id,
                        position,
                        pq_pk: validator.hybrid_pq_pk.clone().unwrap(),
                        classical_pk: validator.hybrid_classical_pk.unwrap(),
                        stake: validator.stake_spark,
                    })
                    .collect::<Vec<_>>()
            },
            state.validators.total_active_stake(),
            TEST_CHAIN_ID,
        )
        .is_ok());
        assert!(verify_sync_qc(&qc, &state, u64::MAX).is_err());
    }

    #[test]
    fn consensus_snapshot_capstone_blocks_both_original_qc_attacks_end_to_end() {
        use indra_consensus::vote::{VoteCollector, VoteDecision};

        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (a_id, a) = install_active_validator(&mut state, 0xC1, 40, true, true);
        let (_, b) = install_active_validator(&mut state, 0xC2, 30, true, true);
        let (c_id, _) = install_active_validator(&mut state, 0xC3, 30, true, true);
        install_test_snapshot_at_inert_gate(&mut state);
        let snapshot = state
            .snapshot_for_consensus_height(u64::MAX)
            .unwrap()
            .clone();

        // One governed-height authority feeds the real vote collector, QC
        // construction adapter, live verifier, and sync verifier.
        let block_h_hash = Bytes32::from([0xD1; 32]);
        let voters = crate::engine::NodeEngine::registered_voters_for_height(u64::MAX, &snapshot);
        let mut collector = VoteCollector::new(
            u64::MAX,
            0,
            VoteStep::Precommit,
            TEST_CHAIN_ID.to_string(),
            snapshot.snapshot_root,
            voters,
        );
        let a_vote = produce_vote(indra_consensus::vote::VoteRequest { height: u64::MAX, round: 0, step: VoteStep::Precommit, block_hash: block_h_hash, validator_id: a_id, snapshot_root: snapshot.snapshot_root, chain_id: TEST_CHAIN_ID }, &a)
        .unwrap();
        let b_id = indra_core::types::crypto::hybrid_identity_id(
            &b.public_key().classical.0,
            &b.public_key().pq.0,
        );
        let b_vote = produce_vote(indra_consensus::vote::VoteRequest { height: u64::MAX, round: 0, step: VoteStep::Precommit, block_hash: block_h_hash, validator_id: b_id, snapshot_root: snapshot.snapshot_root, chain_id: TEST_CHAIN_ID }, &b)
        .unwrap();
        assert!(matches!(
            collector.add_vote(a_vote.clone()).unwrap(),
            VoteDecision::Waiting
        ));
        assert!(matches!(
            collector.add_vote(b_vote.clone()).unwrap(),
            VoteDecision::QuorumReached { .. }
        ));
        let qc_h = build_qc(
            u64::MAX,
            0,
            block_h_hash,
            TEST_CHAIN_ID,
            snapshot.snapshot_root,
            &crate::engine::NodeEngine::qc_validators_for_height(u64::MAX, &snapshot),
            vec![&a_vote, &b_vote],
        )
        .unwrap();

        // Original liveness attack: H commits C's stake increase. The earlier
        // post-H interpretation rejects the genuine A+B QC, while both final
        // governed verification paths continue to accept it under S(H).
        state.validators.get_mut(&c_id).unwrap().stake_spark = 140;
        let mut live_validators: Vec<_> = state.validators.active_validators().collect();
        live_validators.sort_by_key(|validator| validator.validator_id.0);
        let live_qc_validators = live_validators
            .iter()
            .enumerate()
            .map(|(position, validator)| QcValidator {
                validator_id: validator.validator_id,
                position,
                pq_pk: validator.hybrid_pq_pk.clone().unwrap(),
                classical_pk: validator.hybrid_classical_pk.unwrap(),
                stake: validator.stake_spark,
            })
            .collect::<Vec<_>>();
        assert!(verify_qc_strict(
            &qc_h,
            &live_qc_validators,
            state.validators.total_active_stake(),
            TEST_CHAIN_ID,
        )
        .is_err());
        assert!(crate::engine::NodeEngine::verify_qc_with_snapshot(
            &qc_h,
            &snapshot,
            TEST_CHAIN_ID,
        )
        .is_ok());
        assert!(verify_sync_qc(&qc_h, &state, u64::MAX).is_ok());

        // Original safety attack: A's increase appears committed after the
        // certified block, and A presents a single-signer QC. The earlier
        // post-block interpretation accepts it, but the real live and sync
        // governed paths both reject it under the unchanged S(H).
        state.validators.get_mut(&a_id).unwrap().stake_spark = 500;
        let forged = qc_from_test_signers(u64::MAX, Bytes32::from([0xD2; 32]), &snapshot, &[&a]);
        let mut inflated_validators: Vec<_> = state.validators.active_validators().collect();
        inflated_validators.sort_by_key(|validator| validator.validator_id.0);
        let inflated_qc_validators = inflated_validators
            .iter()
            .enumerate()
            .map(|(position, validator)| QcValidator {
                validator_id: validator.validator_id,
                position,
                pq_pk: validator.hybrid_pq_pk.clone().unwrap(),
                classical_pk: validator.hybrid_classical_pk.unwrap(),
                stake: validator.stake_spark,
            })
            .collect::<Vec<_>>();
        assert!(verify_qc_strict(
            &forged,
            &inflated_qc_validators,
            state.validators.total_active_stake(),
            TEST_CHAIN_ID,
        )
        .is_ok());
        assert!(crate::engine::NodeEngine::verify_qc_with_snapshot(
            &forged,
            &snapshot,
            TEST_CHAIN_ID,
        )
        .is_err());
        assert!(verify_sync_qc(&forged, &state, u64::MAX).is_err());

        // Neither committed mutation may rewrite the retained authority.
        assert_eq!(
            state
                .snapshot_for_consensus_height(u64::MAX)
                .unwrap()
                .snapshot_root,
            snapshot.snapshot_root
        );
    }

    #[test]
    fn strict_valid_block_with_vrf_qc_and_state_root_passes() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, hybrid) = install_active_validator(&mut state, 0x31, 10_000, true, true);

        let block1 = make_strict_block(&state, 0x31, 0, vec![]);
        let dir = temp_dir("strict_ok");
        std::fs::create_dir_all(&dir).unwrap();
        let mut block_store = BlockStore::open(
            dir.join("blocks.log"),
            indra_storage::PruneConfig::archive(),
        )
        .unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();
        let mut mempool = Mempool::default_config();
        import_unfinalized_block_for_test(
            &block1,
            &mut state,
            &mut mempool,
            &mut block_store,
            &state_store,
            0,
        )
        .unwrap();

        let pq_pk = hybrid.public_key().pq.0.to_vec();
        let qc_bytes = build_qc_bytes(QcFixture {
            height: block1.header.height,
            round: block1.header.proposer_round,
            value_hash: block1.header.block_hash(),
            validator_id,
            hybrid: &hybrid,
            pq_pk,
            stake: 10_000,
            snapshot_root: state
                .snapshot_for_consensus_height(block1.header.height)
                .unwrap()
                .snapshot_root,
        });
        let block2 = make_strict_block(&state, 0x31, 0, qc_bytes);

        let _ = verify_test(&state, &block2);
        assert!(verify_block_qc(&block2, &state).is_ok());
        assert!(verify_block_state_root(&block2, &state).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
