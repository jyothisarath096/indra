//! Consensus driver — ties NodeEngine to the network layer.
//!
//! This file implements a compact Tendermint-style state machine for a single
//! node while preserving the existing INDRA driver interface used by
//! `node.rs`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::time::Instant;

use indra_consensus::{
    build_qc,
    error::ConsensusError,
    proposer::ProposerElection,
    verify_qc,
    vote::{verify_vote_authority, RegisteredVoter, VoteCollector, VoteDecision},
};
use indra_core::codec::{Decode, Encode};
use indra_core::types::{
    block::{BlockProposalVNext, BlockVNext},
    primitives::{
        has_strict_two_thirds_quorum, validate_consensus_round, Bytes32, MAX_ROUNDS_PER_HEIGHT,
    },
    proposal::verify_proposal,
    qc::QuorumCertificateV1,
    vote::{VoteStep, VoteV1},
};
use indra_storage::{PersistedConsensusLock, VoteSafetyLoadResult, VoteSafetyStore};

use crate::{
    consensus_authority::vrf_authority_from_snapshot,
    engine::NodeEngine,
    error::{NodeError, NodeResult},
    slash::{SlashDetector, SlashEvidence},
    sync::SyncState,
};

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// Maximum round jump accepted from one quorum-backed round certificate.
///
/// This is defense in depth only. The primary authorization boundary is a
/// strict >2/3 stake union of hybrid-signed votes at the target height/round.
const MAX_ACCEPTED_ROUND_JUMP: u32 = 8;

/// Maximum entries retained per stalled-height consensus collection.
///
/// These collections are normally pruned on height advancement. This cap keeps
/// them bounded when the node is stuck at one height and peers send many
/// distinct round/hash combinations.
const MAX_STALLED_HEIGHT_ENTRIES: usize = 256;

/// Minimum interval before re-emitting the same recovery request.
///
/// Several driver paths are tick-driven: the node loop or VRF timeout
/// machinery can revisit the same condition many times before a peer has
/// had a chance to answer. Remembering recent request keys prevents those
/// paths from turning one missing artifact into a tight request/log loop
/// while still allowing retry after a normal round-scale delay.
/// Current Tendermint phase of the local round state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundPhase {
    /// Waiting for the proposal of the current height/round.
    Propose,
    /// Collecting prevotes for the current height/round.
    Prevote,
    /// Collecting precommits for the current height/round.
    Precommit,
}

/// An inbound event for the driver to process.
#[derive(Debug)]
pub enum DriverEvent {
    /// A block arrived from a peer or was proposed locally.
    InboundBlock {
        /// The sender, or `None` when proposed locally.
        from: Option<SocketAddr>,
        /// The complete proposed envelope.
        proposal: Box<BlockProposalVNext>,
    },
    /// A consensus vote arrived from a peer.
    InboundVote {
        /// The sender.
        from: SocketAddr,
        /// The vote payload.
        vote: VoteV1,
    },
    /// A peer announced its chain status.
    PeerStatus {
        /// The peer.
        from: SocketAddr,
        /// Authenticated validator identity bound by the transport handshake.
        validator_id: Bytes32,
        /// The peer's committed height.
        height: u64,
        /// The peer's tip hash.
        tip_hash: Bytes32,
        /// The peer's current consensus round.
        round: u32,
    },
    /// A peer responded with raw QC bytes for the current committed tip.
    QcResponse {
        /// The sender.
        from: SocketAddr,
        /// The committed height the QC should certify.
        height: u64,
        /// Raw encoded QC bytes.
        qc_bytes: Vec<u8>,
    },
    /// A peer is requesting our last QC for the given height.
    QcRequest {
        /// The requesting peer.
        from: SocketAddr,
        /// The committed height the peer wants certified.
        height: u64,
    },
}

/// An action the driver wants to perform in response to an event.
#[derive(Debug)]
pub enum DriverAction {
    /// Broadcast this block to peers.
    BroadcastBlock(Box<BlockProposalVNext>),
    /// Broadcast this vote to peers.
    BroadcastVote(VoteV1),
    /// Request a block range from a peer.
    RequestBlocks {
        /// The peer to ask.
        from: SocketAddr,
        /// The first height needed.
        from_height: u64,
        /// The last height needed.
        to_height: u64,
    },
    /// Request a specific proposal referenced by votes.
    RequestProposal {
        /// The peer to ask.
        from: SocketAddr,
        /// Proposal height.
        height: u64,
        /// Proposal round.
        round: u32,
        /// Proposal block hash.
        hash: Bytes32,
    },
    /// Ask peers for the QC that certifies the current committed tip.
    RequestQC {
        /// The committed height whose QC is needed.
        height: u64,
    },
    /// Send a QC response directly to one peer.
    SendQCResponse {
        /// The peer to answer.
        to: SocketAddr,
        /// The committed height certified by the QC.
        height: u64,
        /// Raw encoded QC bytes.
        qc_bytes: Vec<u8>,
    },
    /// Slash evidence was detected.
    SlashDetected(Box<SlashEvidence>),
    /// A connected peer sent a consensus message that passed cheap routing
    /// checks but failed cryptographic/protocol validation.
    DisconnectInvalidConsensusPeer {
        /// Socket address that sent the invalid message.
        from: SocketAddr,
        /// Claimed validator identity inside the invalid message.
        validator_id: Bytes32,
        /// Human-readable reason for logs/scoring.
        reason: String,
    },
    /// An inbound message passed authoritative consensus validation.
    ScorePeer {
        /// Authenticated transport endpoint that supplied the message.
        from: SocketAddr,
        /// Reputation event to apply after authoritative acceptance.
        event: indra_network::peer::ScoreEvent,
    },
    /// No action needed.
    None,
    /// A fatal local invariant failure that must terminate the node.
    Fatal(NodeError),
}

#[cfg(test)]
/// Test-only counters proving proposal replay admission cost.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ProposalAdmissionMetrics {
    proposal_verifications: usize,
    qc_verifications: usize,
    detached_projections: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AcceptedVoteIdentity {
    block_hash: Bytes32,
    snapshot_root: Bytes32,
}

#[cfg(test)]
/// Test-only counters proving vote replay admission cost and state effects.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct VoteAdmissionMetrics {
    snapshot_lookups: usize,
    hybrid_authority_calls: usize,
    successful_ed25519_verifications: usize,
    successful_mldsa_verifications: usize,
    collector_insertions: usize,
    qc_formations: usize,
}

/// The consensus driver.
pub struct ConsensusDriver {
    /// The underlying node engine.
    pub engine: NodeEngine,
    slash_detector: SlashDetector,
    /// Vote collectors keyed by (height, round, step).
    vote_collectors: HashMap<(u64, u32, VoteStep), VoteCollector>,
    /// Independently verified signed votes proving validators reached a round.
    /// One entry per validator is counted across both vote steps.
    round_advance_evidence: HashMap<(u64, u32), BTreeMap<Bytes32, VoteV1>>,
    /// Pending blocks by block hash.
    pending_blocks: HashMap<Bytes32, BlockProposalVNext>,
    /// Votes received before the matching proposal was staged locally.
    buffered_votes: HashMap<(u64, u32, Bytes32), Vec<(SocketAddr, VoteV1)>>,
    /// Missing proposals already requested from peers.
    requested_proposals: HashSet<(u64, u32, Bytes32)>,
    /// First accepted vote identity per (validator, height, round, step).
    seen_round_votes: HashMap<(Bytes32, u64, u32, VoteStep), AcceptedVoteIdentity>,
    /// Blocks whose precommit quorum arrived before the proposal was staged.
    pending_precommit_quorum: HashSet<(u64, u32, Bytes32)>,
    /// Tendermint lock state for the current height.
    locked_round: Option<u32>,
    /// Full block hash this validator is locked on.
    locked_value: Option<Bytes32>,
    /// Stable value hash corresponding to `locked_value`, used only for POLC
    /// same-value checks across reproposals with different full hashes.
    locked_value_hash: Option<Bytes32>,
    /// Verified prevote PoLC proving the current durable lock.
    locked_polc_votes: Vec<VoteV1>,
    /// Tendermint valid value / valid round for reproposal.
    valid_round: Option<u32>,
    /// Full block hash that reached prevote quorum.
    valid_value: Option<Bytes32>,
    valid_proposal: Option<BlockProposalVNext>,
    /// Serialised QC for the most recently finalised height.
    last_qc_bytes: Vec<u8>,
    /// Registered voters for the current epoch.
    registered_voters: Vec<RegisteredVoter>,
    /// Current consensus round for the next block height.
    current_round: u32,
    /// Current Tendermint phase within the round.
    current_phase: RoundPhase,
    /// Synchronization phase for this node.
    sync: SyncState,
    /// Persisted local vote safety guard.
    pub vote_safety: VoteSafetyStore,
    /// If set, local voting is disabled until operator recovery.
    vote_safety_unavailable: Option<String>,
    #[cfg(test)]
    proposal_admission_metrics: ProposalAdmissionMetrics,
    #[cfg(test)]
    vote_admission_metrics: VoteAdmissionMetrics,
}

impl ConsensusDriver {
    /// Create a new driver from a node engine, failing if durable vote safety cannot be restored.
    pub fn try_new(engine: NodeEngine, vote_safety: VoteSafetyStore) -> NodeResult<Self> {
        let mut driver = Self {
            engine,
            slash_detector: SlashDetector::new(),
            vote_collectors: HashMap::new(),
            round_advance_evidence: HashMap::new(),
            pending_blocks: HashMap::new(),
            buffered_votes: HashMap::new(),
            requested_proposals: HashSet::new(),
            seen_round_votes: HashMap::new(),
            pending_precommit_quorum: HashSet::new(),
            locked_round: None,
            locked_value: None,
            locked_value_hash: None,
            locked_polc_votes: Vec::new(),
            valid_round: None,
            valid_value: None,
            valid_proposal: None,
            last_qc_bytes: Vec::new(),
            registered_voters: Vec::new(),
            current_round: 0,
            current_phase: RoundPhase::Propose,
            sync: SyncState::follower(0),
            vote_safety,
            vote_safety_unavailable: None,
            #[cfg(test)]
            proposal_admission_metrics: ProposalAdmissionMetrics::default(),
            #[cfg(test)]
            vote_admission_metrics: VoteAdmissionMetrics::default(),
        };
        driver.sync = if driver.engine.state.height == 0 {
            // At genesis every validator already has genesis state — no sync needed.
            // Start in consensus mode immediately regardless of bootstrap config.
            SyncState::bootstrap(0)
        } else if driver.engine.config.bootstrap_peers.is_empty() {
            SyncState::bootstrap(driver.engine.state.height)
        } else {
            SyncState::follower(driver.engine.state.height)
        };
        if driver.engine.state.height > 0 {
            driver.restore_last_qc_for_startup();
        }
        driver.refresh_registered_voters();
        driver.apply_vote_safety()?;
        Ok(driver)
    }

    /// Create a driver in unit tests, where construction errors fail the test immediately.
    #[cfg(test)]
    pub fn new(engine: NodeEngine, vote_safety: VoteSafetyStore) -> Self {
        Self::try_new(engine, vote_safety).expect("test driver construction")
    }

    /// Replace the registered voter set for the current epoch.
    pub fn set_voters(&mut self, voters: Vec<RegisteredVoter>) {
        self.vote_collectors.clear();
        self.round_advance_evidence.clear();
        self.registered_voters = voters;
    }

    /// Refresh the registered voter set from the engine state.
    pub fn refresh_registered_voters(&mut self) {
        let height = self.next_height();
        match self.engine.voters_for_consensus_height(height) {
            Ok(voters) => self.set_voters(voters),
            Err(error) => {
                eprintln!(
                    "[vote] CRITICAL: failed to resolve voter authority for height {height}: {error}"
                );
                // Fail closed: an empty voter set cannot authorize or form
                // quorum, and no live-registry fallback is attempted.
                self.set_voters(Vec::new());
            }
        }
    }

    /// Return the serialised QC to place in the next proposal header.
    pub fn last_qc_bytes(&self) -> Vec<u8> {
        self.last_qc_bytes.clone()
    }

    /// Return the height certified by the cached QC, if it is present and decodable.
    pub fn last_qc_height(&self) -> Option<u64> {
        Self::decode_qc_height(&self.last_qc_bytes)
    }

    fn restore_last_qc_for_startup(&mut self) {
        let state_height = self.engine.state.height;
        let state_dir = self.engine.config.state_dir();
        match self.engine.load_persisted_qc() {
            Ok(Some(qc_bytes)) if !qc_bytes.is_empty() => {
                match self.verify_persisted_tip_qc(&qc_bytes) {
                    Ok(qc) => {
                        eprintln!(
                            "[driver] restored last_qc_bytes ({} bytes) for height {}",
                            qc_bytes.len(),
                            qc.height,
                        );
                        self.last_qc_bytes = qc_bytes;
                        let _ = indra_storage::clear_pending_last_qc(&state_dir);
                        return;
                    }
                    Err(err) => {
                        eprintln!(
                            "[driver] WARNING: persisted QC at height {} is not trusted: {} — discarding and checking pending current-tip QC",
                            state_height, err,
                        );
                        let _ = indra_storage::clear_last_qc(&state_dir);
                    }
                }
            }
            Ok(Some(_)) | Ok(None) => {
                eprintln!(
                    "[driver] no persisted QC found at height {} — checking pending current-tip QC",
                    state_height,
                );
            }
            Err(e) => {
                eprintln!(
                    "[driver] WARNING: failed to load persisted QC: {e} — checking pending current-tip QC"
                );
            }
        }

        match indra_storage::load_pending_last_qc(&state_dir) {
            Ok(Some(qc_bytes)) if !qc_bytes.is_empty() => {
                match self.verify_persisted_tip_qc(&qc_bytes) {
                    Ok(qc) => {
                        eprintln!(
                            "[driver] restored pending last_qc_bytes ({} bytes) for height {} after commit-boundary recovery",
                            qc_bytes.len(),
                            qc.height,
                        );
                        self.last_qc_bytes = qc_bytes.clone();
                        if let Err(err) = indra_storage::save_last_qc(&state_dir, &qc_bytes) {
                            eprintln!(
                                "[driver] WARNING: failed to promote pending current-tip QC at height {}: {}",
                                state_height, err,
                            );
                        } else {
                            let _ = indra_storage::clear_pending_last_qc(&state_dir);
                            let _ = self.engine.write_chain_manifest();
                        }
                        return;
                    }
                    Err(err) => {
                        eprintln!(
                            "[driver] WARNING: pending QC at height {} is not trusted: {} — discarding and requesting from peers",
                            state_height, err,
                        );
                        let _ = indra_storage::clear_pending_last_qc(&state_dir);
                    }
                }
            }
            Ok(Some(_)) => {
                let _ = indra_storage::clear_pending_last_qc(&state_dir);
                eprintln!(
                    "[driver] WARNING: empty pending QC found at height {} — requesting from peers",
                    state_height,
                );
            }
            Ok(None) => {}
            Err(err) => {
                eprintln!(
                    "[driver] WARNING: failed to load pending current-tip QC: {} — requesting from peers",
                    err,
                );
            }
        }

        eprintln!(
            "[driver] WARNING: no current-tip QC available at height {} — node will not propose until another validator proposes first",
            state_height,
        );
    }

    fn verify_persisted_tip_qc(&self, qc_bytes: &[u8]) -> Result<QuorumCertificateV1, String> {
        let qc = QuorumCertificateV1::decode_exact(qc_bytes)
            .map_err(|err| format!("invalid encoding: {err}"))?;
        if qc.height != self.engine.state.height {
            return Err(format!(
                "certifies height {}, canonical tip is height {}",
                qc.height, self.engine.state.height,
            ));
        }
        if qc.block_hash != self.engine.state.tip_hash {
            return Err("does not certify the canonical tip hash".to_string());
        }
        let snapshot = self
            .engine
            .state
            .snapshot_for_consensus_height(qc.height)
            .map_err(|err| format!("governing snapshot unavailable: {err}"))?;
        indra_core::types::qc::verify_qc_against_snapshot(
            &qc,
            snapshot,
            &self.engine.state.chain_id,
        )
        .map_err(|err| format!("hybrid quorum verification failed: {err}"))?;
        Ok(qc)
    }

    fn decode_qc_height(qc_bytes: &[u8]) -> Option<u64> {
        if qc_bytes.is_empty() {
            return None;
        }
        QuorumCertificateV1::decode_exact(qc_bytes)
            .ok()
            .map(|qc| qc.height)
    }

    fn qc_bytes_digest(qc_bytes: &[u8]) -> String {
        hex::encode(&indra_crypto::sha256(qc_bytes)[..8])
    }

    /// Promotes `qc_bytes` as the driver's cached and persisted last QC when
    /// it is newer than the currently cached QC.
    ///
    /// The QC's own encoded height is authoritative. The caller-supplied
    /// `height` is an assertion that helps catch call-site mistakes.
    pub fn set_last_qc_bytes_if_newer(&mut self, height: u64, qc_bytes: Vec<u8>) -> NodeResult<()> {
        self.set_last_qc_bytes_if_newer_from_source(height, qc_bytes, "manual")
    }

    fn set_last_qc_bytes_if_newer_from_source(
        &mut self,
        height: u64,
        qc_bytes: Vec<u8>,
        source: &str,
    ) -> NodeResult<()> {
        let qc = QuorumCertificateV1::decode_exact(&qc_bytes).map_err(|err| {
            NodeError::BlockInvalid {
                height,
                reason: format!("last_qc_bytes from {source} are not decodable: {err}"),
            }
        })?;
        if qc.height != height {
            eprintln!(
                "[driver] WARNING: rejected last_qc_bytes from {} for claimed height {}: QC certifies height {}",
                source, height, qc.height,
            );
            return Err(NodeError::BlockInvalid {
                height,
                reason: format!(
                    "last_qc_bytes height mismatch: caller claimed {height}, QC certifies {}",
                    qc.height
                ),
            });
        }

        let current_height = self.last_qc_height();
        match current_height {
            Some(current) if height < current => {
                eprintln!(
                    "[driver] last_qc_bytes no-op from {}: stale QC height {} ignored; current cached height {}",
                    source, height, current,
                );
                return Ok(());
            }
            Some(current) if height == current && self.last_qc_bytes == qc_bytes => {
                eprintln!(
                    "[driver] last_qc_bytes no-op from {}: height {} already cached ({} bytes)",
                    source,
                    height,
                    qc_bytes.len(),
                );
                return Ok(());
            }
            Some(current) if height == current => {
                let current_qc =
                    QuorumCertificateV1::decode_exact(&self.last_qc_bytes).map_err(|err| {
                        NodeError::BlockInvalid {
                            height,
                            reason: format!("cached last_qc_bytes are not decodable: {err}"),
                        }
                    })?;
                self.engine
                    .verify_qc_for_height(&qc)
                    .map_err(|err| NodeError::BlockInvalid {
                        height,
                        reason: format!(
                            "last_qc_bytes from {source} failed QC verification: {err}"
                        ),
                    })?;

                let current_digest = Self::qc_bytes_digest(&self.last_qc_bytes);
                let incoming_digest = Self::qc_bytes_digest(&qc_bytes);
                if current_qc.round == qc.round && current_qc.block_hash == qc.block_hash {
                    eprintln!(
                        "[driver] equivalent last_qc_bytes from {} at height {}: keeping cached QC (current len={} sha256={}, incoming len={} sha256={})",
                        source,
                        height,
                        self.last_qc_bytes.len(),
                        current_digest,
                        qc_bytes.len(),
                        incoming_digest,
                    );
                    return Ok(());
                }

                eprintln!(
                    "[driver] WARNING: conflicting last_qc_bytes from {} at height {}: current len={} sha256={} incoming len={} sha256={}",
                    source,
                    height,
                    self.last_qc_bytes.len(),
                    current_digest,
                    qc_bytes.len(),
                    incoming_digest,
                );
                return Err(NodeError::BlockInvalid {
                    height,
                    reason: format!(
                        "conflicting last_qc_bytes at same height {height}: current sha256={current_digest}, incoming sha256={incoming_digest}"
                    ),
                });
            }
            Some(current) => {
                eprintln!(
                    "[driver] promoting last_qc_bytes from {}: height {} supersedes cached height {} ({} bytes)",
                    source,
                    height,
                    current,
                    qc_bytes.len(),
                );
            }
            None if self.last_qc_bytes.is_empty() => {
                eprintln!(
                    "[driver] promoting last_qc_bytes from {}: height {} ({} bytes)",
                    source,
                    height,
                    qc_bytes.len(),
                );
            }
            None => {
                eprintln!(
                    "[driver] WARNING: replacing undecodable cached last_qc_bytes with QC from {} at height {} ({} bytes)",
                    source,
                    height,
                    qc_bytes.len(),
                );
            }
        }

        self.last_qc_bytes = qc_bytes;
        indra_storage::save_last_qc(&self.engine.config.state_dir(), &self.last_qc_bytes)?;
        self.engine.write_chain_manifest()?;
        Ok(())
    }

    /// Promote the QC embedded in an imported block header.
    ///
    /// A block at height H carries the QC certifying height H-1. Height-1
    /// blocks usually carry no prior QC, so empty QC bytes are an explicit
    /// no-op.
    pub fn promote_block_header_qc(&mut self, block: &BlockVNext, source: &str) -> NodeResult<()> {
        let qc_bytes = block.header.quorum_certificate.as_slice().to_vec();
        if qc_bytes.is_empty() {
            eprintln!(
                "[driver] last_qc_bytes no-op from {}: block height {} carries empty embedded QC",
                source, block.header.height,
            );
            return Ok(());
        }
        let certified_height = block.header.height.saturating_sub(1);
        self.set_last_qc_bytes_if_newer_from_source(certified_height, qc_bytes, source)
    }

    /// Persist QC bytes that the sync coordinator has already verified as
    /// certifying the current canonical tip.
    pub fn promote_verified_sync_qc(&mut self, height: u64, qc_bytes: Vec<u8>) -> NodeResult<()> {
        if height != self.engine.state.height {
            return Err(NodeError::BlockInvalid {
                height,
                reason: format!(
                    "verified sync QC height does not match canonical height {}",
                    self.engine.state.height
                ),
            });
        }
        self.set_last_qc_bytes_if_newer_from_source(height, qc_bytes, "sync-qc-response")
    }

    /// True when the cached QC does not certify the current committed tip.
    pub fn last_qc_is_stale(&self) -> bool {
        if self.engine.state.height == 0 {
            return false;
        }
        if self.last_qc_bytes.is_empty() {
            return true;
        }
        match QuorumCertificateV1::decode_exact(&self.last_qc_bytes) {
            Ok(qc) => qc.height != self.engine.state.height,
            Err(_) => true,
        }
    }

    /// Drop the cached QC so recovery must fetch one for the current tip.
    pub fn clear_last_qc_bytes(&mut self) {
        self.last_qc_bytes.clear();
    }

    /// Proposal eligibility is enforced inside block construction, where the
    /// node can see the exact height and QC bytes being embedded.
    pub fn can_propose(&self) -> bool {
        true
    }

    /// Request the QC for the currently committed tip if restart recovery left
    /// us without persisted `last_qc_bytes`.
    pub fn request_qc_if_needed(&self) -> Vec<DriverAction> {
        if self.engine.state.height > 0 && self.last_qc_is_stale() {
            vec![DriverAction::RequestQC {
                height: self.engine.state.height,
            }]
        } else {
            vec![]
        }
    }

    /// Current round for the next block height.
    pub fn current_round(&self) -> u32 {
        self.current_round
    }

    /// Current local Tendermint step.
    pub fn current_phase(&self) -> RoundPhase {
        self.current_phase
    }

    /// Current synchronization state.
    pub fn sync(&self) -> &SyncState {
        &self.sync
    }

    /// Mutable synchronization state.
    pub fn sync_mut(&mut self) -> &mut SyncState {
        &mut self.sync
    }

    /// `node.rs` still asks this method to decide whether a local proposal
    /// should be suppressed. We derive that from staged proposals for the
    /// current slot rather than from a separate latch.
    pub fn has_accepted_proposal_for_height(&self, height: u64) -> bool {
        self.pending_block_for_slot(height, self.current_round)
            .is_some()
    }

    /// External round-reset hook used after height advancement.
    pub fn reset_round(&mut self) -> NodeResult<()> {
        self.valid_proposal = None;
        self.start_round(0)?;
        self.apply_vote_safety()?;
        Ok(())
    }

    /// Re-enter consensus cleanly after block download catchup.
    pub fn on_sync_caught_up(&mut self) -> NodeResult<()> {
        self.sync.mark_caught_up(self.engine.state.height);
        self.refresh_registered_voters();
        self.pending_blocks.clear();
        self.buffered_votes.clear();
        self.requested_proposals.clear();
        self.pending_precommit_quorum.clear();
        self.vote_collectors.clear();
        self.round_advance_evidence.clear();
        self.seen_round_votes.clear();
        self.start_round(0)?;
        self.apply_vote_safety()?;
        Ok(())
    }

    /// Process one inbound event and return the resulting driver actions.
    pub fn process(&mut self, event: DriverEvent) -> Vec<DriverAction> {
        match event {
            DriverEvent::InboundBlock { from, proposal } => self.process_proposal(from, *proposal),
            DriverEvent::InboundVote { from, vote } => self.process_vote(from, vote),
            DriverEvent::PeerStatus {
                from,
                validator_id,
                height,
                tip_hash,
                round,
            } => self.process_status(from, validator_id, height, tip_hash, round),
            DriverEvent::QcResponse {
                from,
                height,
                qc_bytes,
            } => self.handle_qc_response(from, height, qc_bytes),
            DriverEvent::QcRequest { from, height } => self.handle_qc_request(from, height),
        }
    }

    fn collector_key(height: u64, round: u32, step: VoteStep) -> (u64, u32, VoteStep) {
        (height, round, step)
    }

    fn start_round(&mut self, round: u32) -> NodeResult<()> {
        validate_consensus_round(round).map_err(|error| NodeError::BlockInvalid {
            height: self.next_height(),
            reason: error.to_string(),
        })?;
        self.current_round = round;
        self.current_phase = RoundPhase::Propose;
        Ok(())
    }

    fn enter_precommit_phase(&mut self) {
        self.current_phase = RoundPhase::Precommit;
    }

    /// Build the immutable proposer election authority for one height and round.
    pub fn proposer_election_for_height(
        &self,
        height: u64,
        round: u32,
    ) -> NodeResult<ProposerElection> {
        let snapshot = self.engine.state.snapshot_for_consensus_height(height)?;
        Ok(vrf_authority_from_snapshot(
            self.engine.state.chain_id.as_bytes(),
            height,
            round,
            self.engine.state.election_seed,
            snapshot,
        )?
        .election)
    }

    fn maybe_precommit_current_round_proposal(&mut self) -> Vec<DriverAction> {
        if !self.sync.is_caught_up() || self.current_phase != RoundPhase::Precommit {
            return vec![];
        }
        let height = self.next_height();
        let round = self.current_round;
        let Some(local_validator_id) = self.engine.validator_id() else {
            return vec![];
        };
        if self.collector_has_vote_from(height, round, VoteStep::Precommit, local_validator_id) {
            return vec![];
        }
        let block_hash = self.locked_value.unwrap_or(Bytes32::ZERO);
        self.sign_and_record_local_vote(height, round, VoteStep::Precommit, block_hash)
    }

    /// Retry a delayed precommit attempt.
    pub fn retry_precommit_if_waiting(&mut self) -> Vec<DriverAction> {
        self.maybe_precommit_current_round_proposal()
    }

    fn persisted_consensus_lock(&self) -> Result<Option<PersistedConsensusLock>, String> {
        let Some(round) = self.locked_round else {
            return Ok(None);
        };
        let block_hash = self
            .locked_value
            .ok_or("lock is missing full block identity")?;
        let value_hash = self
            .locked_value_hash
            .ok_or("lock is missing stable value identity")?;
        let proposal = self
            .valid_proposal
            .as_ref()
            .filter(|proposal| proposal.block.header.block_hash() == block_hash)
            .ok_or("lock is missing its canonical proposal envelope")?
            .clone();
        if self.locked_polc_votes.is_empty() {
            return Err("lock is missing its verified prevote PoLC".into());
        }
        Ok(Some(PersistedConsensusLock {
            height: self.next_height(),
            round,
            block_hash,
            value_hash,
            proposal,
            polc_votes: self.locked_polc_votes.clone(),
        }))
    }

    fn verify_and_restore_consensus_lock(
        &mut self,
        lock: PersistedConsensusLock,
    ) -> Result<(), String> {
        validate_consensus_round(lock.round).map_err(|error| error.to_string())?;
        if lock.height != self.next_height()
            || lock.proposal.block.header.height != lock.height
            || lock.proposal.block.header.block_hash() != lock.block_hash
            || lock.proposal.block.header.value_hash != lock.value_hash
        {
            return Err("persisted lock block identities do not match current height".into());
        }
        let snapshot = self
            .engine
            .state
            .snapshot_for_consensus_height(lock.height)
            .map_err(|error| format!("persisted lock snapshot unavailable: {error}"))?;
        verify_proposal(
            &lock.proposal,
            self.engine.state.chain_id.as_bytes(),
            &self.engine.state.election_seed,
            snapshot,
        )
        .map_err(|error| format!("persisted lock proposal failed verification: {error}"))?;
        let mut collector = VoteCollector::new(
            lock.height,
            lock.round,
            VoteStep::Prevote,
            self.engine.state.chain_id.clone(),
            snapshot.snapshot_root,
            self.registered_voters.clone(),
        );
        for vote in &lock.polc_votes {
            if vote.block_hash != lock.block_hash {
                return Err("persisted PoLC contains a vote for a different value".into());
            }
            collector
                .add_vote(vote.clone())
                .map_err(|error| format!("persisted PoLC vote failed verification: {error}"))?;
        }
        if !matches!(
            collector.current_decision(),
            VoteDecision::QuorumReached { block_hash, .. } if block_hash == lock.block_hash
        ) {
            return Err("persisted PoLC does not contain strict two-thirds prevote stake".into());
        }
        self.locked_round = Some(lock.round);
        self.locked_value = Some(lock.block_hash);
        self.locked_value_hash = Some(lock.value_hash);
        self.locked_polc_votes = lock.polc_votes;
        self.valid_round = Some(lock.round);
        self.valid_value = Some(lock.block_hash);
        self.valid_proposal = Some(lock.proposal);
        Ok(())
    }

    /// Restore durable vote and lock safety state before participating.
    fn apply_vote_safety(&mut self) -> NodeResult<()> {
        let next_height = self.engine.state.height.saturating_add(1);
        match self.vote_safety.load() {
            VoteSafetyLoadResult::NoRecord => {
                self.vote_safety_unavailable = None;
            }
            VoteSafetyLoadResult::Record(record) => {
                if let Some(lock) = record.consensus_lock {
                    if lock.height == next_height {
                        if let Err(reason) = self.verify_and_restore_consensus_lock(lock) {
                            let message = format!("persisted consensus lock is invalid: {reason}");
                            eprintln!("[vote_safety] CRITICAL: {message}");
                            return Err(NodeError::VoteSafetyUnavailable { detail: message });
                        }
                    } else if lock.height > next_height {
                        let message = format!(
                            "persisted consensus lock height {} is ahead of next height {next_height}",
                            lock.height
                        );
                        eprintln!("[vote_safety] CRITICAL: {message}");
                        return Err(NodeError::VoteSafetyUnavailable { detail: message });
                    }
                }
                self.vote_safety_unavailable = None;
                if record.height == next_height && record.round >= self.current_round {
                    let safe_round = match record
                        .round
                        .checked_add(1)
                        .filter(|round| *round < MAX_ROUNDS_PER_HEIGHT)
                    {
                        Some(round) => round,
                        None => {
                            let message = format!(
                                "persisted vote at final legal round {} leaves no safe round at height {}",
                                record.round, record.height
                            );
                            eprintln!("[vote_safety] CRITICAL: {message}");
                            self.vote_safety_unavailable = Some(message);
                            return Ok(())
                        }
                    };
                    eprintln!(
                        "[vote_safety] restarted: skipping to round {} (already voted at height={} round={} step={})",
                        safe_round, record.height, record.round, record.step
                    );
                    self.start_round(safe_round)?;
                }
            }
            VoteSafetyLoadResult::Corrupt(reason) => {
                let msg = format!(
                    "vote_safety.dat is corrupt or unreadable: {reason}; refusing to vote until operator recovery"
                );
                eprintln!("[vote_safety] CRITICAL: {msg}");
                return Err(NodeError::VoteSafetyUnavailable { detail: msg });
            }
        }
        Ok(())
    }

    /// Whether the validator is currently unable to vote without violating its
    /// durable final-round safety boundary.
    pub fn vote_safety_unavailable(&self) -> bool {
        self.vote_safety_unavailable.is_some()
    }

    #[cfg(test)]
    pub(crate) fn mark_vote_safety_unavailable_for_test(&mut self) {
        self.vote_safety_unavailable = Some("test final-round safety boundary".to_string());
    }

    fn next_height(&self) -> u64 {
        self.engine.state.height + 1
    }

    fn prune_stalled_collections(&mut self) {
        self.prune_vote_collectors();
        self.prune_round_advance_evidence();
        self.prune_pending_blocks();
        self.prune_buffered_votes();
        self.prune_requested_proposals();
        self.prune_seen_round_votes();
        self.prune_pending_precommit_quorum();
    }

    fn prune_round_advance_evidence(&mut self) {
        let height = self.next_height();
        let min_round = self.current_round.saturating_sub(MAX_ACCEPTED_ROUND_JUMP);
        let max_round = self
            .current_round.saturating_add(MAX_ACCEPTED_ROUND_JUMP)
            .min(MAX_ROUNDS_PER_HEIGHT - 1);
        self.round_advance_evidence
            .retain(|(h, round), _| *h == height && *round >= min_round && *round <= max_round);
        if self.round_advance_evidence.len() > MAX_STALLED_HEIGHT_ENTRIES {
            let mut keys: Vec<_> = self.round_advance_evidence.keys().copied().collect();
            keys.sort_by_key(|(_, round)| round.abs_diff(self.current_round));
            let keep: HashSet<_> = keys.into_iter().take(MAX_STALLED_HEIGHT_ENTRIES).collect();
            self.round_advance_evidence
                .retain(|key, _| keep.contains(key));
        }
    }

    fn prune_vote_collectors(&mut self) {
        if self.vote_collectors.len() <= MAX_STALLED_HEIGHT_ENTRIES {
            return;
        }
        let next_height = self.next_height();
        let current_round = self.current_round;
        let mut keys: Vec<_> = self.vote_collectors.keys().copied().collect();
        keys.sort_by_key(|(height, round, step)| {
            (
                height.abs_diff(next_height),
                round.abs_diff(current_round),
                match step {
                    VoteStep::Prevote => 0u8,
                    VoteStep::Precommit => 1u8,
                },
            )
        });
        let keep: HashSet<_> = keys.into_iter().take(MAX_STALLED_HEIGHT_ENTRIES).collect();
        self.vote_collectors.retain(|key, _| keep.contains(key));
    }

    fn prune_pending_blocks(&mut self) {
        if self.pending_blocks.len() <= MAX_STALLED_HEIGHT_ENTRIES {
            return;
        }
        let next_height = self.next_height();
        let current_round = self.current_round;
        let mut keys: Vec<_> = self
            .pending_blocks
            .iter()
            .map(|(hash, proposal)| {
                (
                    *hash,
                    proposal.block.header.height.abs_diff(next_height),
                    proposal.block.header.proposer_round.abs_diff(current_round),
                )
            })
            .collect();
        keys.sort_by_key(|(hash, height_distance, round_distance)| {
            (*height_distance, *round_distance, hash.0)
        });
        let keep: HashSet<_> = keys
            .into_iter()
            .take(MAX_STALLED_HEIGHT_ENTRIES)
            .map(|(hash, _, _)| hash)
            .collect();
        self.pending_blocks.retain(|hash, _| keep.contains(hash));
    }

    fn prune_buffered_votes(&mut self) {
        if self.buffered_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES {
            return;
        }
        let next_height = self.next_height();
        let current_round = self.current_round;
        let mut keys: Vec<_> = self.buffered_votes.keys().copied().collect();
        keys.sort_by_key(|(height, round, hash)| {
            (
                height.abs_diff(next_height),
                round.abs_diff(current_round),
                hash.0,
            )
        });
        let keep: HashSet<_> = keys.into_iter().take(MAX_STALLED_HEIGHT_ENTRIES).collect();
        self.buffered_votes.retain(|key, _| keep.contains(key));
    }

    fn prune_requested_proposals(&mut self) {
        if self.requested_proposals.len() <= MAX_STALLED_HEIGHT_ENTRIES {
            return;
        }
        let next_height = self.next_height();
        let current_round = self.current_round;
        let mut keys: Vec<_> = self.requested_proposals.iter().copied().collect();
        keys.sort_by_key(|(height, round, hash)| {
            (
                height.abs_diff(next_height),
                round.abs_diff(current_round),
                hash.0,
            )
        });
        let keep: HashSet<_> = keys.into_iter().take(MAX_STALLED_HEIGHT_ENTRIES).collect();
        self.requested_proposals.retain(|key| keep.contains(key));
    }

    fn prune_seen_round_votes(&mut self) {
        if self.seen_round_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES {
            return;
        }
        let next_height = self.next_height();
        let current_round = self.current_round;
        let mut keys: Vec<_> = self.seen_round_votes.keys().copied().collect();
        keys.sort_by_key(|(validator_id, height, round, step)| {
            (
                height.abs_diff(next_height),
                round.abs_diff(current_round),
                match step {
                    VoteStep::Prevote => 0u8,
                    VoteStep::Precommit => 1u8,
                },
                validator_id.0,
            )
        });
        let keep: HashSet<_> = keys.into_iter().take(MAX_STALLED_HEIGHT_ENTRIES).collect();
        self.seen_round_votes.retain(|key, _| keep.contains(key));
    }

    fn prune_pending_precommit_quorum(&mut self) {
        if self.pending_precommit_quorum.len() <= MAX_STALLED_HEIGHT_ENTRIES {
            return;
        }
        let next_height = self.next_height();
        let current_round = self.current_round;
        let mut keys: Vec<_> = self.pending_precommit_quorum.iter().copied().collect();
        keys.sort_by_key(|(height, round, hash)| {
            (
                height.abs_diff(next_height),
                round.abs_diff(current_round),
                hash.0,
            )
        });
        let keep: HashSet<_> = keys.into_iter().take(MAX_STALLED_HEIGHT_ENTRIES).collect();
        self.pending_precommit_quorum
            .retain(|key| keep.contains(key));
    }

    fn pending_block_for_slot(&self, height: u64, round: u32) -> Option<BlockVNext> {
        self.pending_blocks
            .values()
            .filter(|proposal| {
                proposal.block.header.height == height
                    && proposal.block.header.proposer_round == round
            })
            // Multiple validators may legitimately be eligible in one slot.
            // Selection is deterministic over the complete 512-bit priority;
            // the header hash is a total-order tie breaker only.
            .min_by_key(|proposal| {
                (
                    proposal.block.header.proposer_priority.0,
                    proposal.block.header.block_hash().0,
                )
            })
            .map(|proposal| proposal.block.clone())
    }

    /// Return a locally staged, fully authorized proposal envelope.
    pub fn pending_proposal(&self, hash: &Bytes32) -> Option<BlockProposalVNext> {
        self.pending_blocks.get(hash).cloned()
    }

    /// Return a locally staged proposal by hash, if present.
    pub fn pending_block(&self, hash: &Bytes32) -> Option<BlockVNext> {
        self.pending_blocks
            .get(hash)
            .map(|proposal| proposal.block.clone())
    }

    /// The proposer includes the latest valid-round in its header.
    pub fn proposal_polc_round(&self, height: u64) -> Option<u32> {
        if self.next_height() != height || self.valid_value.is_none() {
            return None;
        }
        self.valid_round
    }

    /// Return the current valid block and round, if available for reproposal.
    pub fn take_valid_block_for_reproposal(&self) -> Option<(BlockVNext, u32)> {
        match (&self.valid_proposal, self.valid_round) {
            (Some(proposal), Some(round)) => Some((proposal.block.clone(), round)),
            _ => None,
        }
    }

    fn collector_has_vote_from(
        &self,
        height: u64,
        round: u32,
        step: VoteStep,
        validator_id: Bytes32,
    ) -> bool {
        self.vote_collectors
            .get(&Self::collector_key(height, round, step))
            .map(|collector| collector.has_vote_from(&validator_id))
            .unwrap_or(false)
    }

    fn vote_decision(&self, height: u64, round: u32, step: VoteStep) -> Option<VoteDecision> {
        self.vote_collectors
            .get(&Self::collector_key(height, round, step))
            .map(|collector| collector.current_decision())
    }

    fn has_quorum_for_value_hash(
        &self,
        height: u64,
        round: u32,
        step: VoteStep,
        value_hash: Bytes32,
    ) -> bool {
        match self.vote_decision(height, round, step) {
            Some(VoteDecision::QuorumReached { block_hash, .. }) if block_hash != Bytes32::ZERO => {
                self.pending_block(&block_hash)
                    .is_some_and(|block| block.header.value_hash == value_hash)
            }
            _ => false,
        }
    }

    /// Rules 2 and 3 — decide whether the current-round proposal should be
    /// prevoted or nil-prevoted.
    fn maybe_prevote_current_round_proposal(&mut self) -> Vec<DriverAction> {
        if !self.sync.is_caught_up() {
            if self.current_phase == RoundPhase::Propose {
                eprintln!(
                    "[vote] DIAG: skipping prevote at height={} round={} — awaiting peer status",
                    self.next_height(),
                    self.current_round,
                );
            }
            return vec![];
        }
        if self.current_phase != RoundPhase::Propose {
            return vec![];
        }

        let height = self.next_height();
        let Some(block) = self.pending_block_for_slot(height, self.current_round) else {
            return vec![];
        };
        let hash = block.header.block_hash();
        let value_hash = block.header.value_hash;
        let vote_hash = if block.header.polc_round.is_none() {
            // Rule 2
            if self.locked_round.is_none() || self.locked_value == Some(hash) {
                hash
            } else {
                Bytes32::ZERO
            }
        } else {
            // Rule 3
            let valid_round = match block.header.polc_round {
                Some(round) => round,
                None => return vec![],
            };
            if valid_round < self.current_round
                && self.has_quorum_for_value_hash(
                    height,
                    valid_round,
                    VoteStep::Prevote,
                    value_hash,
                )
                && (self.locked_round.is_none()
                    || self.locked_value_hash == Some(value_hash)
                    || self
                        .locked_round
                        .is_some_and(|locked_round| locked_round <= valid_round))
            {
                hash
            } else {
                Bytes32::ZERO
            }
        };

        self.current_phase = RoundPhase::Prevote;
        self.sign_and_record_local_vote(height, self.current_round, VoteStep::Prevote, vote_hash)
    }

    fn sign_and_record_local_vote(
        &mut self,
        height: u64,
        round: u32,
        step: VoteStep,
        block_hash: Bytes32,
    ) -> Vec<DriverAction> {
        let canonical_height = self.next_height();
        if height != canonical_height || round != self.current_round {
            eprintln!(
                "[vote] refusing non-canonical signing coordinates: requested height={} round={}, canonical height={} round={}",
                height, round, canonical_height, self.current_round
            );
            return vec![DriverAction::None];
        }
        let Some(local_validator_id) = self.engine.validator_id() else {
            return vec![];
        };
        {
            match self
                .engine
                .voter_authorized_for_height(height, local_validator_id)
            {
                Ok(true) => {}
                Ok(false) => {
                    eprintln!(
                        "[vote] refusing local vote at height={height}: validator is not a member of the governing consensus authority"
                    );
                    return vec![];
                }
                Err(error) => {
                    eprintln!(
                        "[vote] CRITICAL: refusing local vote at height={height}: failed to resolve consensus authority: {error}"
                    );
                    return vec![DriverAction::None];
                }
            }
        }
        if self.collector_has_vote_from(height, round, step, local_validator_id) {
            return vec![];
        }
        if let Some(reason) = &self.vote_safety_unavailable {
            eprintln!("[vote_safety] refusing to sign local vote: {reason}");
            return vec![DriverAction::None];
        }

        let vote_block_hash = block_hash;

        let step_byte = match step {
            VoteStep::Prevote => 0u8,
            VoteStep::Precommit => 1u8,
        };
        let persisted_lock = match self.persisted_consensus_lock() {
            Ok(lock) => lock,
            Err(reason) => {
                eprintln!("[vote_safety] CRITICAL: refusing to vote: {reason}");
                self.vote_safety_unavailable = Some(reason);
                return vec![DriverAction::None];
            }
        };
        if let Err(err) = self
            .vote_safety
            .record(height, round, step_byte, persisted_lock.as_ref())
        {
            eprintln!(
                "[vote_safety] CRITICAL: failed to persist vote safety record before signing: {err}; refusing to vote"
            );
            return vec![DriverAction::None];
        }

        match self.engine.sign_vote(height, round, step, vote_block_hash) {
            Ok(local_vote) => {
                eprintln!(
                    "[vote] produced {:?} for height={} round={} hash={}",
                    step,
                    height,
                    round,
                    hex::encode(&vote_block_hash.0[..4]),
                );
                self.record_vote_and_actions(
                    SocketAddr::from(([127, 0, 0, 1], 0)),
                    local_vote,
                    false,
                )
            }
            Err(err) => {
                eprintln!(
                    "[vote] failed to sign local {:?} for {} at height={} round={}: {}",
                    step,
                    hex::encode(&vote_block_hash.0[..4]),
                    height,
                    round,
                    err,
                );
                vec![]
            }
        }
    }

    #[cfg(feature = "audit-harness")]
    pub(crate) fn audit_create_local_vote(
        &mut self,
        height: u64,
        round: u32,
        step: VoteStep,
        block_hash: Bytes32,
    ) -> Vec<DriverAction> {
        self.sign_and_record_local_vote(height, round, step, block_hash)
    }

    fn process_proposal(
        &mut self,
        from: Option<SocketAddr>,
        proposal: BlockProposalVNext,
    ) -> Vec<DriverAction> {
        if validate_consensus_round(proposal.block.header.proposer_round).is_err()
            || validate_consensus_round(proposal.block.header.value_entropy.origin_round).is_err()
            || proposal
                .block
                .header
                .polc_round
                .is_some_and(|round| validate_consensus_round(round).is_err())
        {
            return vec![DriverAction::None];
        }
        if !self.sync.is_caught_up() {
            return vec![DriverAction::None];
        }

        let block = &proposal.block;
        let next_height = self.next_height();
        if block.header.height < next_height {
            return vec![DriverAction::None];
        }
        // A proposal is consensus state only when its parent is the current
        // canonical tip and its full transition can be projected now. Future
        // or wrong-parent proposals are dropped; proposal request/response
        // recovery can fetch them after the parent commits. Keeping decoded
        // objects here would give unverified data trusted-container status.
        if block.header.height != next_height
            || block.header.prev_hash != self.engine.state.tip_hash
        {
            return vec![DriverAction::None];
        }

        // `pending_blocks` is authoritative: entries are inserted only after
        // proposer/VRF, embedded-QC, detached projection, and root validation
        // all succeed. An exact block hash already present here therefore
        // identifies an accepted proposal replay without letting unverified
        // input create trusted replay state. Different-round reproposals and
        // conflicting proposals have different consensus block hashes and
        // continue through full admission.
        let block_hash = block.header.block_hash();
        if self.pending_blocks.contains_key(&block_hash) {
            return vec![DriverAction::None];
        }

        self.process_proposal_internal(from, proposal)
    }

    fn process_proposal_internal(
        &mut self,
        from: Option<SocketAddr>,
        proposal: BlockProposalVNext,
    ) -> Vec<DriverAction> {
        let block = &proposal.block;
        let height = block.header.height;
        let snapshot = match self.engine.state.snapshot_for_consensus_height(height) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                eprintln!("[vote] rejecting proposal: governing snapshot unavailable: {error}");
                return vec![DriverAction::None];
            }
        };
        #[cfg(test)]
        {
            self.proposal_admission_metrics.proposal_verifications += 1;
        }
        let verified = match verify_proposal(
            &proposal,
            self.engine.state.chain_id.as_bytes(),
            &self.engine.state.election_seed,
            snapshot,
        ) {
            Ok(verified) => verified,
            Err(error) => {
                eprintln!(
                "[vote] rejecting proposal {} at height={} round={} because proposer verification failed: {}",
                hex::encode(&block.header.block_hash().0[..4]),
                height,
                block.header.proposer_round,
                error,
            );
                return vec![DriverAction::None];
            }
        };

        if block.header.height > 1 {
            #[cfg(test)]
            {
                self.proposal_admission_metrics.qc_verifications += 1;
            }
            if let Err(err) = crate::sync::verify_network_block_qc(
                block,
                &self.engine.state,
                &self.engine.network_qc_verifier,
            ) {
                eprintln!(
                    "[vote] rejecting proposal at height={} round={}: embedded QC invalid: {}",
                    block.header.height, block.header.proposer_round, err,
                );
                return vec![DriverAction::None];
            }
        }

        // Admission must validate the commitments before staging the proposal:
        // Rule 3 reasons about `value_hash`, so accepting a peer-supplied hash
        // without recomputing it would let a PoLC authorize different immutable
        // value entropy under the same claimed identity.
        #[cfg(test)]
        {
            self.proposal_admission_metrics.detached_projections += 1;
        }
        let projected =
            match indra_state::project_block_for_roots(&mut self.engine.state, verified.block(), 0)
            {
                Ok(projected) => projected,
                Err(_) => return vec![DriverAction::None],
            };
        if projected.state_root != block.header.state_root
            || projected.validator_set_root != block.header.validator_set_root
            || projected.value_hash != block.header.value_hash
        {
            return vec![DriverAction::None];
        }

        let block_hash = block.header.block_hash();
        if self.pending_blocks.contains_key(&block_hash) {
            return vec![DriverAction::None];
        }

        self.requested_proposals.remove(&(
            block.header.height,
            block.header.proposer_round,
            block_hash,
        ));
        self.pending_blocks.insert(block_hash, proposal.clone());
        self.prune_pending_blocks();

        // A valid proposal proves only that its proposer signed one candidate;
        // it does not prove sufficient stake reached that round. Higher-round
        // proposals remain staged until independently verified vote evidence
        // crosses strict >2/3 stake.

        let mut actions = vec![DriverAction::BroadcastBlock(Box::new(proposal.clone()))];
        if let Some(from) = from {
            actions.push(DriverAction::ScorePeer {
                from,
                event: indra_network::peer::ScoreEvent::ValidBlock,
            });
        }

        if let Some(buffered_votes) = self.buffered_votes.remove(&(
            block.header.height,
            block.header.proposer_round,
            block_hash,
        )) {
            for (vote_from, vote) in buffered_votes {
                actions.extend(self.record_vote_and_actions(vote_from, vote, true));
            }
        }

        if self.pending_precommit_quorum.remove(&(
            block.header.height,
            block.header.proposer_round,
            block_hash,
        )) {
            actions.extend(self.finalize_block_on_quorum(
                block.header.height,
                block.header.proposer_round,
                block_hash,
            ));
            return actions;
        }

        // Do not prevote on arrival.  The existing propose-phase timeout is the
        // deterministic collection boundary: a better eligible priority may
        // replace this candidate until the local prevote is durably cast.
        actions
    }

    fn process_vote(&mut self, from: SocketAddr, vote: VoteV1) -> Vec<DriverAction> {
        let mut actions = Vec::new();

        if validate_consensus_round(vote.round).is_err() {
            return actions;
        }

        let maximum_jump_round = self
            .current_round.saturating_add(MAX_ACCEPTED_ROUND_JUMP)
            .min(MAX_ROUNDS_PER_HEIGHT - 1);
        if vote.height != self.next_height() || vote.round > maximum_jump_round {
            return actions;
        }

        if self
            .engine
            .validator_id()
            .is_some_and(|local_id| local_id == vote.validator_id)
            && self.collector_has_vote_from(vote.height, vote.round, vote.step, vote.validator_id)
        {
            return actions;
        }

        let slot_key = (vote.validator_id, vote.height, vote.round, vote.step);
        let replay_identity = AcceptedVoteIdentity {
            block_hash: vote.block_hash,
            snapshot_root: vote.snapshot_root,
        };
        // This map is populated only after authoritative snapshot and hybrid
        // verification. Matching the complete signed semantic identity is
        // therefore safe before repeated snapshot/crypto work. A conflicting
        // block hash or snapshot root deliberately continues to verification
        // and slash/evidence handling.
        if self
            .seen_round_votes
            .get(&slot_key)
            .is_some_and(|accepted| *accepted == replay_identity)
        {
            return actions;
        }

        #[cfg(test)]
        {
            self.vote_admission_metrics.snapshot_lookups += 1;
        }
        let governing_snapshot_root =
            match self.engine.state.snapshot_for_consensus_height(vote.height) {
                Ok(snapshot) => snapshot.snapshot_root,
                Err(error) => {
                    actions.push(DriverAction::DisconnectInvalidConsensusPeer {
                        from,
                        validator_id: vote.validator_id,
                        reason: format!("Vote snapshot unavailable: {error}"),
                    });
                    return actions;
                }
            };
        #[cfg(test)]
        {
            self.vote_admission_metrics.hybrid_authority_calls += 1;
        }
        if let Err(err) = verify_vote_authority(
            &vote,
            &self.engine.state.chain_id,
            &governing_snapshot_root,
            &self.registered_voters,
        )
        .map_err(|error| error.to_string())
        {
            actions.push(DriverAction::DisconnectInvalidConsensusPeer {
                from,
                validator_id: vote.validator_id,
                reason: format!("Vote validation failed: {err}"),
            });
            return actions;
        }
        #[cfg(test)]
        {
            // Successful `verify_vote_authority` means both sequential hybrid
            // components completed successfully.
            self.vote_admission_metrics.successful_ed25519_verifications += 1;
            self.vote_admission_metrics.successful_mldsa_verifications += 1;
        }

        if let Some(evidence) = self.slash_detector.observe_vote(vote.clone()) {
            actions.push(DriverAction::SlashDetected(Box::new(evidence)));
        }

        if let Some(existing) = self.seen_round_votes.get(&slot_key).copied() {
            if existing == replay_identity {
            } else {
                eprintln!(
                    "[vote] rejected equivocating vote from {} for {} at height={} round={} (already saw {})",
                    from,
                    hex::encode(&vote.block_hash.0[..4]),
                    vote.height,
                    vote.round,
                    hex::encode(&existing.block_hash.0[..4]),
                );
            }
            return actions;
        }
        self.seen_round_votes.insert(slot_key, replay_identity);
        self.prune_seen_round_votes();

        // VoteV1 signatures bind chain ID, height, round, full validator ID,
        // step and value. A one-per-validator union across the two steps is a
        // compact round-change certificate proving strict >2/3 stake reached
        // the target round; no Status or proposal assertion contributes.
        self.round_advance_evidence
            .entry((vote.height, vote.round))
            .or_default()
            .entry(vote.validator_id)
            .or_insert_with(|| vote.clone());
        self.prune_round_advance_evidence();
        let mut round_advance_actions =
            self.maybe_advance_to_certified_round(vote.height, vote.round);

        if !self.sync.is_caught_up() {
            actions.extend(self.record_vote_passive(from, vote, true));
            actions.append(&mut round_advance_actions);
            return actions;
        }

        if !vote.is_nil()
            && vote.height == self.next_height()
            && self.pending_block(&vote.block_hash).is_none()
        {
            let request_key = (vote.height, vote.round, vote.block_hash);
            let should_request = self.requested_proposals.insert(request_key);
            self.prune_requested_proposals();
            if should_request {
                actions.push(DriverAction::RequestProposal {
                    from,
                    height: vote.height,
                    round: vote.round,
                    hash: vote.block_hash,
                });
            }
            self.buffered_votes
                .entry((vote.height, vote.round, vote.block_hash))
                .or_default()
                .push((from, vote));
            self.prune_buffered_votes();
            actions.append(&mut round_advance_actions);
            return actions;
        }

        actions.append(&mut round_advance_actions);
        actions.extend(self.record_vote_and_actions(from, vote, true));
        actions
    }

    fn maybe_advance_to_certified_round(
        &mut self,
        height: u64,
        target_round: u32,
    ) -> Vec<DriverAction> {
        if !self.sync.is_caught_up()
            || height != self.next_height()
            || target_round <= self.current_round
            || validate_consensus_round(target_round).is_err()
            || target_round
                > self
                    .current_round.saturating_add(MAX_ACCEPTED_ROUND_JUMP)
                    .min(MAX_ROUNDS_PER_HEIGHT - 1)
        {
            return Vec::new();
        }
        let Some(evidence) = self.round_advance_evidence.get(&(height, target_round)) else {
            return Vec::new();
        };
        let stake_by_id: BTreeMap<Bytes32, u64> = self
            .registered_voters
            .iter()
            .map(|voter| (voter.validator_id, voter.stake))
            .collect();
        let Some(signed_stake) = evidence.keys().try_fold(0u64, |total, validator_id| {
            total.checked_add(stake_by_id.get(validator_id).copied().unwrap_or(0))
        }) else {
            return Vec::new();
        };
        let Some(total_stake) = self
            .registered_voters
            .iter()
            .try_fold(0u64, |total, voter| total.checked_add(voter.stake))
        else {
            return Vec::new();
        };
        if !has_strict_two_thirds_quorum(signed_stake, total_stake) {
            return Vec::new();
        }

        eprintln!(
            "[consensus] quorum-certified round advance: {} → {} at height={} (stake={}/{})",
            self.current_round, target_round, height, signed_stake, total_stake
        );
        if let Err(error) = self.start_round(target_round) {
            eprintln!("[consensus] CRITICAL: certified round advance failed: {error}");
            return Vec::new();
        }
        if let Err(error) = self.apply_vote_safety() {
            eprintln!("[vote_safety] CRITICAL: failed after certified round advance: {error}");
            return Vec::new();
        }
        self.prune_stalled_collections();
        self.maybe_prevote_current_round_proposal()
    }

    fn precommit_votes_for_block(
        &self,
        collector: &VoteCollector,
        block_hash: Bytes32,
    ) -> Vec<VoteV1> {
        collector
            .accepted_votes()
            .into_iter()
            .filter(|vote| vote.block_hash == block_hash && vote.step == VoteStep::Precommit)
            .cloned()
            .collect()
    }

    fn record_vote_passive(
        &mut self,
        from: SocketAddr,
        vote: VoteV1,
        authority_verified: bool,
    ) -> Vec<DriverAction> {
        let mut actions = Vec::new();
        let key = Self::collector_key(vote.height, vote.round, vote.step);
        let decision = {
            let collector = self.vote_collectors.entry(key).or_insert_with(|| {
                VoteCollector::new(
                    vote.height,
                    vote.round,
                    vote.step,
                    self.engine.state.chain_id.clone(),
                    vote.snapshot_root,
                    self.registered_voters.clone(),
                )
            });
            if authority_verified {
                collector.add_verified_vote(vote.clone())
            } else {
                collector.add_vote(vote.clone())
            }
        };
        self.prune_vote_collectors();

        match decision {
            Ok(_decision) => {
                #[cfg(test)]
                {
                    self.vote_admission_metrics.collector_insertions += 1;
                }
                actions.push(DriverAction::ScorePeer {
                    from,
                    event: indra_network::peer::ScoreEvent::ValidVote,
                });
            }
            Err(err) => {
                eprintln!(
                    "[vote] rejected vote from {} for {} at height={} round={}: {}",
                    from,
                    hex::encode(&vote.block_hash.0[..4]),
                    vote.height,
                    vote.round,
                    err,
                );
                actions.push(DriverAction::DisconnectInvalidConsensusPeer {
                    from,
                    validator_id: vote.validator_id,
                    reason: format!("Vote validation failed: {err}"),
                });
            }
        }
        actions
    }

    fn record_vote_and_actions(
        &mut self,
        from: SocketAddr,
        vote: VoteV1,
        authority_verified: bool,
    ) -> Vec<DriverAction> {
        let mut actions = Vec::new();
        let key = Self::collector_key(vote.height, vote.round, vote.step);
        let decision = {
            let collector = self.vote_collectors.entry(key).or_insert_with(|| {
                VoteCollector::new(
                    vote.height,
                    vote.round,
                    vote.step,
                    self.engine.state.chain_id.clone(),
                    vote.snapshot_root,
                    self.registered_voters.clone(),
                )
            });
            if authority_verified {
                collector.add_verified_vote(vote.clone())
            } else {
                collector.add_vote(vote.clone())
            }
        };
        self.prune_vote_collectors();

        match decision {
            Ok(decision) => {
                #[cfg(test)]
                {
                    self.vote_admission_metrics.collector_insertions += 1;
                }
                actions.push(DriverAction::ScorePeer {
                    from,
                    event: indra_network::peer::ScoreEvent::ValidVote,
                });
                actions.push(DriverAction::BroadcastVote(vote.clone()));

                match decision {
                    VoteDecision::Waiting => {}
                    VoteDecision::QuorumReached { block_hash, .. } => {
                        match vote.step {
                            VoteStep::Prevote => {
                                // Rule 4: once 2f+1 prevotes of any value exist, the external
                                // timeout machinery continues from the Prevote step.
                                if block_hash != Bytes32::ZERO {
                                    // Rule 5 — a value got 2f+1 prevotes.
                                    self.valid_round = Some(vote.round);
                                    self.valid_value = Some(block_hash);
                                    self.valid_proposal = self.pending_proposal(&block_hash);
                                }

                                if vote.height == self.next_height()
                                    && vote.round == self.current_round
                                    && self.current_phase == RoundPhase::Prevote
                                {
                                    self.enter_precommit_phase();
                                    if block_hash != Bytes32::ZERO {
                                        self.locked_round = Some(vote.round);
                                        self.locked_value = Some(block_hash);
                                        self.locked_value_hash = self
                                            .pending_block(&block_hash)
                                            .map(|block| block.header.value_hash);
                                        self.locked_polc_votes = self
                                            .vote_collectors
                                            .get(&Self::collector_key(
                                                vote.height,
                                                vote.round,
                                                VoteStep::Prevote,
                                            ))
                                            .map(|collector| {
                                                collector
                                                    .accepted_votes()
                                                    .into_iter()
                                                    .filter(|accepted| {
                                                        accepted.block_hash == block_hash
                                                    })
                                                    .cloned()
                                                    .collect()
                                            })
                                            .unwrap_or_default();
                                        actions.extend(self.sign_and_record_local_vote(
                                            vote.height,
                                            vote.round,
                                            VoteStep::Precommit,
                                            block_hash,
                                        ));
                                    } else {
                                        // Rule 6 — nil prevote quorum.
                                        actions.extend(self.sign_and_record_local_vote(
                                            vote.height,
                                            vote.round,
                                            VoteStep::Precommit,
                                            Bytes32::ZERO,
                                        ));
                                    }
                                } else if block_hash != Bytes32::ZERO {
                                    // A PoLC for an older round may unblock Rule 3 for the
                                    // current proposal.
                                    actions.extend(self.maybe_prevote_current_round_proposal());
                                }
                            }
                            VoteStep::Precommit => {
                                // Rule 8: once 2f+1 precommits of any value exist, the external
                                // timeout machinery continues from the Precommit step.
                                if block_hash != Bytes32::ZERO {
                                    // Rule 9 — commit on 2f+1 precommits for a value.
                                    actions.extend(self.finalize_block_on_quorum(
                                        vote.height,
                                        vote.round,
                                        block_hash,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            Err(err) => {
                eprintln!(
                    "[vote] rejected vote from {} for {} at height={} round={}: {}",
                    from,
                    hex::encode(&vote.block_hash.0[..4]),
                    vote.height,
                    vote.round,
                    err,
                );
                actions.push(DriverAction::DisconnectInvalidConsensusPeer {
                    from,
                    validator_id: vote.validator_id,
                    reason: format!("Vote validation failed: {err}"),
                });
            }
        }

        actions
    }

    fn finalize_block_on_quorum(
        &mut self,
        height: u64,
        round: u32,
        block_hash: Bytes32,
    ) -> Vec<DriverAction> {
        let Some(block) = self.pending_blocks.get(&block_hash).cloned() else {
            eprintln!(
                "[commit] quorum reached for {} at height={} round={}, but block is not staged yet",
                hex::encode(&block_hash.0[..4]),
                height,
                round,
            );
            self.pending_precommit_quorum
                .insert((height, round, block_hash));
            self.prune_pending_precommit_quorum();
            return vec![DriverAction::None];
        };
        let key = Self::collector_key(height, round, VoteStep::Precommit);
        let Some(collector) = self.vote_collectors.get(&key) else {
            eprintln!(
                "[commit] quorum reached for {} at height={} round={}, but collector is missing",
                hex::encode(&block_hash.0[..4]),
                height,
                round,
            );
            return vec![DriverAction::None];
        };

        let (qc_validators, qc_total_weight) = match self.engine.qc_authority_for_height(height) {
            Ok(authority) => authority,
            Err(error) => {
                eprintln!(
                        "[commit] cannot finalize {} at height={} round={}: failed to resolve QC authority: {}",
                        hex::encode(&block_hash.0[..4]),
                        height,
                        round,
                        error,
                    );
                return vec![DriverAction::None];
            }
        };
        if qc_validators.len() != self.registered_voters.len() {
            eprintln!(
                "[commit] cannot finalize {} at height={} round={} because QC validator set is incomplete",
                hex::encode(&block_hash.0[..4]),
                height,
                round,
            );
            return vec![DriverAction::None];
        }
        {
            let adapters_match =
                self.registered_voters
                    .iter()
                    .zip(&qc_validators)
                    .all(|(voter, validator)| {
                        voter.validator_id == validator.validator_id
                            && voter.classical_pk == validator.classical_pk
                            && voter.pq_pk == validator.pq_pk
                            && voter.stake == validator.stake
                    });
            let voter_total = self
                .registered_voters
                .iter()
                .map(|voter| voter.stake)
                .fold(0u64, u64::saturating_add);
            if !adapters_match || voter_total != qc_total_weight {
                eprintln!(
                    "[commit] cannot finalize at height={height}: vote collector and QC authority do not describe the same snapshot"
                );
                return vec![DriverAction::None];
            }
        }

        let quorum_vote_values = self.precommit_votes_for_block(collector, block_hash);
        let quorum_votes: Vec<&VoteV1> = quorum_vote_values.iter().collect();
        #[cfg(test)]
        {
            self.vote_admission_metrics.qc_formations += 1;
        }
        let governing_snapshot = match self.engine.state.snapshot_for_consensus_height(height) {
            Ok(snapshot) => snapshot,
            Err(error) => return vec![DriverAction::Fatal(error.into())],
        };
        let qc = match build_qc(
            height,
            round,
            block_hash,
            &self.engine.state.chain_id,
            governing_snapshot.snapshot_root,
            &qc_validators,
            quorum_votes,
        ) {
            Ok(qc) => qc,
            Err(ConsensusError::CryptoError { detail }) => {
                eprintln!(
                    "[commit] failed to build QC for {} at height={} round={}: CryptoError: {}",
                    hex::encode(&block_hash.0[..4]),
                    height,
                    round,
                    detail,
                );
                return vec![DriverAction::None];
            }
            Err(err) => {
                eprintln!(
                    "[commit] failed to build QC for {} at height={} round={}: {}",
                    hex::encode(&block_hash.0[..4]),
                    height,
                    round,
                    err,
                );
                return vec![DriverAction::None];
            }
        };
        {
            if let Err(error) = verify_qc(
                &qc,
                &qc_validators,
                qc_total_weight,
                &self.engine.state.chain_id,
            ) {
                eprintln!(
                    "[commit] locally built QC failed verification under S({height}): {error}"
                );
                return vec![DriverAction::None];
            }
        }
        let old_height = self.engine.state.height;
        let qc_bytes = qc.encode_to_vec();
        if let Err(e) =
            indra_storage::save_pending_last_qc(&self.engine.config.state_dir(), &qc_bytes)
        {
            eprintln!(
                "[driver] WARNING: failed to durably stage consensus last_qc_bytes at height {} before commit: {}",
                height, e,
            );
            return vec![DriverAction::None];
        }

        match self.engine.commit_proposal(&block) {
            Ok(()) => {
                self.pending_blocks.remove(&block_hash);
                let mut actions = vec![DriverAction::BroadcastBlock(Box::new(block))];
                eprintln!(
                    "[commit] finalizing {} at height={} round={}",
                    hex::encode(&block_hash.0[..4]),
                    height,
                    round,
                );

                if let Err(e) =
                    self.set_last_qc_bytes_if_newer_from_source(height, qc_bytes, "consensus")
                {
                    eprintln!(
                        "[driver] WARNING: failed to promote consensus last_qc_bytes at height {}: {}",
                        height, e,
                    );
                } else if let Err(e) =
                    indra_storage::clear_pending_last_qc(&self.engine.config.state_dir())
                {
                    eprintln!(
                        "[driver] WARNING: failed to clear pending consensus last_qc_bytes at height {}: {}",
                        height, e,
                    );
                }
                self.slash_detector.prune_below(height.saturating_sub(100));
                self.refresh_registered_voters();
                self.sync.mark_caught_up(self.engine.state.height);

                // Rule 9 / height transition cleanup.
                self.locked_round = None;
                self.locked_value = None;
                self.locked_value_hash = None;
                self.locked_polc_votes.clear();
                self.valid_round = None;
                self.valid_value = None;
                self.valid_proposal = None;
                if let Err(error) = self.vote_safety.clear() {
                    eprintln!(
                        "[vote_safety] WARNING: failed to clear committed-height safety record: {error}"
                    );
                }
                if let Err(error) = self.start_round(0) {
                    eprintln!("[consensus] CRITICAL: post-commit round reset failed: {error}");
                    return vec![DriverAction::None];
                }

                self.vote_collectors
                    .retain(|(vote_height, _, _), _| *vote_height > height);
                self.round_advance_evidence
                    .retain(|(vote_height, _), _| *vote_height > height);
                self.pending_blocks
                    .retain(|_, pending| pending.block.header.height > height);
                self.buffered_votes
                    .retain(|(vote_height, _, _), _| *vote_height > height);
                self.seen_round_votes
                    .retain(|(_, vote_height, _, _), _| *vote_height > height);
                self.pending_precommit_quorum
                    .retain(|(vote_height, _, _)| *vote_height > height);

                if self.engine.state.height > old_height {
                    eprintln!(
                        "[timing] t={}ms HEIGHT ADVANCED to {} (was {})",
                        now_ms(),
                        self.engine.state.height,
                        old_height,
                    );
                }

                actions.extend(self.maybe_prevote_current_round_proposal());
                actions
            }
            Err(NodeError::BlockInvalid { height, reason }) => {
                eprintln!(
                    "[commit] failed to finalize {} at height={}: {}",
                    hex::encode(&block_hash.0[..4]),
                    height,
                    reason,
                );
                vec![DriverAction::None]
            }
            Err(err) => {
                eprintln!(
                    "[commit] failed to finalize {} at height={} round={}: {}",
                    hex::encode(&block_hash.0[..4]),
                    height,
                    round,
                    err,
                );
                vec![DriverAction::None]
            }
        }
    }

    fn process_status(
        &mut self,
        from: SocketAddr,
        validator_id: Bytes32,
        height: u64,
        tip_hash: Bytes32,
        _peer_round: u32,
    ) -> Vec<DriverAction> {
        let our_height = self.engine.height();
        // Status is intentionally informational only. Neither an authenticated
        // transport peer nor a validator identity proves quorum reached its
        // asserted round; only hybrid-signed vote evidence may advance rounds.
        let peer_stake = self
            .registered_voters
            .iter()
            .find(|voter| voter.validator_id == validator_id)
            .map(|voter| voter.stake)
            .unwrap_or(0);
        let total_active_stake = self
            .registered_voters
            .iter()
            .fold(0u64, |sum, voter| sum.saturating_add(voter.stake));
        match self.sync.observe_status(
            validator_id,
            from,
            height,
            tip_hash,
            peer_stake,
            total_active_stake,
            our_height,
            Instant::now(),
        ) {
            Some((peer, from_height, to_height)) => vec![DriverAction::RequestBlocks {
                from: peer,
                from_height,
                to_height,
            }],
            None => vec![DriverAction::None],
        }
    }

    fn handle_qc_request(&mut self, from: SocketAddr, height: u64) -> Vec<DriverAction> {
        let local_height = self.engine.state.height;

        if height == local_height {
            if self.last_qc_is_stale() {
                return vec![];
            }
            eprintln!("[driver] serving QC for height {} to {}", height, from);
            return vec![DriverAction::SendQCResponse {
                to: from,
                height,
                qc_bytes: self.last_qc_bytes.clone(),
            }];
        }

        if height == local_height.saturating_sub(1) && local_height > 0 {
            match self.engine.block_store.get(local_height) {
                Ok(block) => {
                    let qc_bytes = block.block.header.quorum_certificate.as_slice().to_vec();
                    if qc_bytes.is_empty() {
                        eprintln!(
                            "[driver] cannot serve QC for height {} — block {} has empty QC",
                            height, local_height
                        );
                        return vec![];
                    }
                    eprintln!(
                        "[driver] serving QC for height {} to {} (from block {} header)",
                        height, from, local_height
                    );
                    return vec![DriverAction::SendQCResponse {
                        to: from,
                        height,
                        qc_bytes,
                    }];
                }
                Err(e) => {
                    eprintln!(
                        "[driver] cannot serve QC for height {}: failed to read block {}: {}",
                        height, local_height, e
                    );
                    return vec![];
                }
            }
        }

        vec![]
    }

    fn handle_qc_response(
        &mut self,
        from: SocketAddr,
        height: u64,
        qc_bytes: Vec<u8>,
    ) -> Vec<DriverAction> {
        if height != self.engine.state.height || !self.last_qc_is_stale() {
            return vec![];
        }

        let qc = match QuorumCertificateV1::decode_exact(&qc_bytes) {
            Ok(qc) => qc,
            Err(err) => {
                eprintln!(
                    "[driver] WARNING: received invalid QC encoding from {} at height {}: {}",
                    from, height, err,
                );
                return vec![DriverAction::ScorePeer {
                    from,
                    event: indra_network::peer::ScoreEvent::InvalidMessage,
                }];
            }
        };

        if qc.height != height {
            return vec![DriverAction::ScorePeer {
                from,
                event: indra_network::peer::ScoreEvent::InvalidMessage,
            }];
        }

        if let Err(err) = self.engine.verify_network_qc_for_height(&qc) {
            eprintln!(
                "[driver] WARNING: received invalid QC from {} at height {}: {}",
                from, height, err,
            );
            return vec![DriverAction::ScorePeer {
                from,
                event: indra_network::peer::ScoreEvent::InvalidMessage,
            }];
        }

        if let Err(err) =
            self.set_last_qc_bytes_if_newer_from_source(height, qc_bytes, "qc-response")
        {
            eprintln!(
                "[driver] WARNING: failed to promote recovered last_qc_bytes at height {}: {}",
                height, err,
            );
            return vec![];
        }
        eprintln!(
            "[driver] recovered last_qc_bytes from peer at height {}",
            height
        );
        vec![]
    }

    /// At propose timeout, prevote the best verified staged proposal or nil.
    pub fn on_propose_timeout(&mut self) -> Vec<DriverAction> {
        if !self.sync.is_caught_up() || self.current_phase != RoundPhase::Propose {
            return vec![];
        }

        let staged_actions = self.maybe_prevote_current_round_proposal();
        if !staged_actions.is_empty() {
            return staged_actions;
        }

        self.current_phase = RoundPhase::Prevote;
        self.sign_and_record_local_vote(
            self.next_height(),
            self.current_round,
            VoteStep::Prevote,
            Bytes32::ZERO,
        )
    }

    /// Rule 7 — on prevote timeout, precommit nil.
    pub fn on_prevote_timeout(&mut self) -> Vec<DriverAction> {
        if !self.sync.is_caught_up() || self.current_phase != RoundPhase::Prevote {
            return vec![];
        }
        self.enter_precommit_phase();
        self.sign_and_record_local_vote(
            self.next_height(),
            self.current_round,
            VoteStep::Precommit,
            Bytes32::ZERO,
        )
    }

    /// Rule 10 — on precommit timeout, advance to the next round.
    pub fn on_precommit_timeout(&mut self) -> NodeResult<()> {
        if !self.sync.is_caught_up() || self.current_phase != RoundPhase::Precommit {
            return Ok(());
        }
        let next_round = self
            .current_round
            .checked_add(1)
            .filter(|round| *round < MAX_ROUNDS_PER_HEIGHT)
            .ok_or(NodeError::RoundLimitExceeded {
                height: self.next_height(),
                round: self.current_round,
            })?;
        self.start_round(next_round)
    }

    /// Current committed chain height.
    pub fn height(&self) -> u64 {
        self.engine.height()
    }
}

#[cfg(test)]
#[path = "driver_tests.rs"]
mod tests;
