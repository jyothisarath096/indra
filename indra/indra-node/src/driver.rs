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
    block::{BlockProposalVNext, BlockVNext, NO_POLC_ROUND},
    primitives::{has_strict_two_thirds_quorum, Bytes32},
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
        proposal: BlockProposalVNext,
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
    BroadcastBlock(BlockProposalVNext),
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
    /// Re-process a buffered future proposal after the local tip advances.
    ActivateBufferedProposal(BlockProposalVNext),
    /// Slash evidence was detected.
    SlashDetected(SlashEvidence),
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
    /// Proposals buffered because they arrived before their parent tip was committed locally.
    future_proposals: HashMap<(u64, Bytes32), Vec<BlockProposalVNext>>,
    /// Votes received before the matching proposal was staged locally.
    buffered_votes: HashMap<(u64, u32, Bytes32), Vec<(SocketAddr, VoteV1)>>,
    /// Missing proposals already requested from peers.
    requested_proposals: HashSet<(u64, u32, Bytes32)>,
    /// First accepted vote hash per (validator, height, round, step).
    seen_round_votes: HashMap<(Bytes32, u64, u32, VoteStep), Bytes32>,
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
}

impl ConsensusDriver {
    /// Create a new driver from a node engine.
    pub fn new(engine: NodeEngine, vote_safety: VoteSafetyStore) -> Self {
        let mut driver = Self {
            engine,
            slash_detector: SlashDetector::new(),
            vote_collectors: HashMap::new(),
            round_advance_evidence: HashMap::new(),
            pending_blocks: HashMap::new(),
            future_proposals: HashMap::new(),
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
        driver.apply_vote_safety();
        driver
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

    /// External compatibility hook used after height advancement.
    pub fn reset_round(&mut self) {
        self.prune_future_proposals();
        self.valid_proposal = None;
        self.start_round(0);
        self.apply_vote_safety();
    }

    /// Re-enter consensus cleanly after block download catchup.
    pub fn on_sync_caught_up(&mut self) {
        self.sync.mark_caught_up(self.engine.state.height);
        self.refresh_registered_voters();
        self.pending_blocks.clear();
        self.future_proposals.clear();
        self.buffered_votes.clear();
        self.requested_proposals.clear();
        self.pending_precommit_quorum.clear();
        self.vote_collectors.clear();
        self.round_advance_evidence.clear();
        self.seen_round_votes.clear();
        self.start_round(0);
        self.apply_vote_safety();
    }

    /// Process one inbound event and return the resulting driver actions.
    pub fn process(&mut self, event: DriverEvent) -> Vec<DriverAction> {
        match event {
            DriverEvent::InboundBlock { from, proposal } => self.process_proposal(from, proposal),
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

    fn start_round(&mut self, round: u32) {
        self.current_round = round;
        self.current_phase = RoundPhase::Propose;
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
        )
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
    fn apply_vote_safety(&mut self) {
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
                            self.vote_safety_unavailable = Some(message);
                            return;
                        }
                    } else if lock.height > next_height {
                        let message = format!(
                            "persisted consensus lock height {} is ahead of next height {next_height}",
                            lock.height
                        );
                        eprintln!("[vote_safety] CRITICAL: {message}");
                        self.vote_safety_unavailable = Some(message);
                        return;
                    }
                }
                self.vote_safety_unavailable = None;
                if record.height == next_height && record.round >= self.current_round {
                    let safe_round = record.round.saturating_add(1);
                    eprintln!(
                        "[vote_safety] restarted: skipping to round {} (already voted at height={} round={} step={})",
                        safe_round, record.height, record.round, record.step
                    );
                    self.start_round(safe_round);
                }
            }
            VoteSafetyLoadResult::Corrupt(reason) => {
                let msg = format!(
                    "vote_safety.dat is corrupt or unreadable: {reason}; refusing to vote until operator recovery"
                );
                eprintln!("[vote_safety] CRITICAL: {msg}");
                self.vote_safety_unavailable = Some(msg);
            }
        }
    }

    fn next_height(&self) -> u64 {
        self.engine.state.height + 1
    }

    fn prune_stalled_collections(&mut self) {
        self.prune_vote_collectors();
        self.prune_round_advance_evidence();
        self.prune_pending_blocks();
        self.prune_future_proposals_bounded();
        self.prune_buffered_votes();
        self.prune_requested_proposals();
        self.prune_seen_round_votes();
        self.prune_pending_precommit_quorum();
    }

    fn prune_round_advance_evidence(&mut self) {
        let height = self.next_height();
        let min_round = self.current_round.saturating_sub(MAX_ACCEPTED_ROUND_JUMP);
        let max_round = self.current_round.saturating_add(MAX_ACCEPTED_ROUND_JUMP);
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

    fn prune_future_proposals_bounded(&mut self) {
        for proposals in self.future_proposals.values_mut() {
            if proposals.len() > MAX_STALLED_HEIGHT_ENTRIES {
                let next_height = self.engine.state.height.saturating_add(1);
                let current_round = self.current_round;
                proposals.sort_by_key(|proposal| {
                    (
                        proposal.block.header.height.abs_diff(next_height),
                        proposal.block.header.proposer_round.abs_diff(current_round),
                        proposal.block.header.block_hash().0,
                    )
                });
                proposals.truncate(MAX_STALLED_HEIGHT_ENTRIES);
            }
        }
        self.future_proposals
            .retain(|_, proposals| !proposals.is_empty());

        let total: usize = self.future_proposals.values().map(Vec::len).sum();
        if total <= MAX_STALLED_HEIGHT_ENTRIES {
            return;
        }

        let next_height = self.next_height();
        let current_round = self.current_round;
        let mut ranked = Vec::new();
        for proposals in self.future_proposals.values() {
            for proposal in proposals {
                let hash = proposal.block.header.block_hash();
                ranked.push((
                    hash,
                    proposal.block.header.height.abs_diff(next_height),
                    proposal.block.header.proposer_round.abs_diff(current_round),
                ));
            }
        }
        ranked.sort_by_key(|(hash, height_distance, round_distance)| {
            (*height_distance, *round_distance, hash.0)
        });
        let keep: HashSet<_> = ranked
            .into_iter()
            .take(MAX_STALLED_HEIGHT_ENTRIES)
            .map(|(hash, _, _)| hash)
            .collect();
        self.future_proposals.retain(|_, proposals| {
            proposals.retain(|proposal| keep.contains(&proposal.block.header.block_hash()));
            !proposals.is_empty()
        });
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

    fn prune_future_proposals(&mut self) {
        let next_height = self.next_height();
        self.future_proposals.retain(|(height, _), _| {
            *height >= next_height && *height <= next_height.saturating_add(2)
        });
        self.prune_future_proposals_bounded();
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
        let vote_hash = if block.header.polc_round == NO_POLC_ROUND {
            // Rule 2
            if self.locked_round.is_none() || self.locked_value == Some(hash) {
                hash
            } else {
                Bytes32::ZERO
            }
        } else {
            // Rule 3
            let valid_round = block.header.polc_round;
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

    fn process_proposal(
        &mut self,
        from: Option<SocketAddr>,
        proposal: BlockProposalVNext,
    ) -> Vec<DriverAction> {
        if !self.sync.is_caught_up() {
            return vec![DriverAction::None];
        }

        let block = &proposal.block;
        let next_height = self.next_height();
        if block.header.height < next_height {
            return vec![DriverAction::None];
        }
        if block.header.height > next_height.saturating_add(2) {
            return vec![DriverAction::None];
        }
        if block.header.height > next_height || block.header.prev_hash != self.engine.state.tip_hash
        {
            let key = (block.header.height, block.header.prev_hash);
            let entry = self.future_proposals.entry(key).or_default();
            let block_hash = block.header.block_hash();
            if !entry
                .iter()
                .any(|existing| existing.block.header.block_hash() == block_hash)
            {
                entry.push(proposal);
            }
            self.prune_future_proposals();
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

        let mut projected_state = self.engine.state.clone();
        if indra_state::apply_block(&mut projected_state, &verified, 0).is_err() {
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

        let mut actions = vec![DriverAction::BroadcastBlock(proposal.clone())];
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

    fn activate_buffered_proposals_for_new_tip(&mut self) -> Vec<DriverAction> {
        let key = (self.next_height(), self.engine.state.tip_hash);
        let Some(buffered) = self.future_proposals.remove(&key) else {
            self.prune_future_proposals();
            return vec![];
        };

        let mut candidates = buffered;
        candidates.sort_by_key(|proposal| proposal.block.header.proposer_round);
        self.prune_future_proposals();
        candidates
            .into_iter()
            .map(DriverAction::ActivateBufferedProposal)
            .collect()
    }

    fn process_vote(&mut self, from: SocketAddr, vote: VoteV1) -> Vec<DriverAction> {
        let mut actions = Vec::new();

        if vote.height != self.next_height()
            || vote.round > self.current_round.saturating_add(MAX_ACCEPTED_ROUND_JUMP)
        {
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

        if let Err(err) =
            verify_vote_authority(&vote, &self.engine.state.chain_id, &self.registered_voters)
                .map_err(|error| error.to_string())
        {
            actions.push(DriverAction::DisconnectInvalidConsensusPeer {
                from,
                validator_id: vote.validator_id,
                reason: format!("Vote validation failed: {err}"),
            });
            return actions;
        }

        if let Some(evidence) = self.slash_detector.observe_vote(vote.clone()) {
            actions.push(DriverAction::SlashDetected(evidence));
        }

        let slot_key = (vote.validator_id, vote.height, vote.round, vote.step);
        if let Some(existing_hash) = self.seen_round_votes.get(&slot_key).copied() {
            if existing_hash == vote.block_hash {
            } else {
                eprintln!(
                    "[vote] rejected equivocating vote from {} for {} at height={} round={} (already saw {})",
                    from,
                    hex::encode(&vote.block_hash.0[..4]),
                    vote.height,
                    vote.round,
                    hex::encode(&existing_hash.0[..4]),
                );
            }
            return actions;
        }
        self.seen_round_votes.insert(slot_key, vote.block_hash);
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
            || target_round > self.current_round.saturating_add(MAX_ACCEPTED_ROUND_JUMP)
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
        self.start_round(target_round);
        self.apply_vote_safety();
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
            Ok(_decision) => actions.push(DriverAction::ScorePeer {
                from,
                event: indra_network::peer::ScoreEvent::ValidVote,
            }),
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
        let qc = match build_qc(
            height,
            round,
            block_hash,
            &self.engine.state.chain_id,
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
                let mut actions = vec![DriverAction::BroadcastBlock(block)];
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
                self.start_round(0);
                actions.extend(self.activate_buffered_proposals_for_new_tip());

                self.vote_collectors
                    .retain(|(vote_height, _, _), _| *vote_height > height);
                self.round_advance_evidence
                    .retain(|(vote_height, _), _| *vote_height > height);
                self.pending_blocks
                    .retain(|_, pending| pending.block.header.height > height);
                let next_height = self.next_height();
                self.future_proposals
                    .retain(|(proposal_height, _), _| *proposal_height >= next_height);
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
    pub fn on_precommit_timeout(&mut self) {
        if !self.sync.is_caught_up() || self.current_phase != RoundPhase::Precommit {
            return;
        }
        self.start_round(self.current_round.saturating_add(1));
    }

    /// Current committed chain height.
    pub fn height(&self) -> u64 {
        self.engine.height()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeConfig;
    use indra_consensus::{
        producer::{produce_block, BlockTemplate},
        vote::VoteCollector,
    };
    use indra_core::{
        types::block::{BlockHeaderVNext, BlockVNext},
        types::primitives::{DEFAULT_CHAIN_ID, DEFAULT_COMMISSION_BPS, DUST_LIMIT_SPARK},
        Bytes32, Bytes64, ProtocolVersion, VariableBytes,
    };
    use indra_crypto::{
        hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
        VrfKeypair,
    };

    use indra_state::{apply_block, ChainState, ValidatorEntry, ValidatorStatus};
    use std::{path::PathBuf, time::Instant};

    fn temp_dir(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "indra_driver_test_{}_{}",
            suffix,
            std::process::id()
        ));
        p
    }

    fn make_block(state: &ChainState) -> indra_core::types::block::BlockProposalVNext {
        let mut block = BlockVNext {
            header: BlockHeaderVNext {
                protocol_version: ProtocolVersion::CURRENT,
                height: state.height + 1,
                prev_hash: state.tip_hash,
                timestamp: 1_700_000_000 + state.height + 1,
                state_root: Bytes32::ZERO,
                validator_set_root: Bytes32::ZERO,
                mempool_set_root: Bytes32::ZERO,
                value_hash: Bytes32::ZERO,
                base_fee: state.base_fee,
                proposer_round: 0,
                polc_round: NO_POLC_ROUND,
                proposer_id: Bytes32::ZERO,
                vrf_suite: indra_core::types::block::VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
                election_seed: state.election_seed,
                proposer_vrf_output: VariableBytes::from_slice(&[0; 64]).unwrap(),
                proposer_vrf_proof: VariableBytes::from_slice(&[0; 80]).unwrap(),
                sortition_claim: indra_core::types::block::SortitionClaimV1::PraosThreshold,
                proposer_priority: indra_core::types::primitives::Bytes64::ZERO,
                quorum_certificate: indra_core::VariableBytes::from_slice(&[]).unwrap(),
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        };

        let mut projection_state = state.clone();
        let projected =
            indra_state::project_block_for_roots(&mut projection_state, &block, 0).unwrap();
        block.header.state_root = projected.state_root;
        block.header.validator_set_root = projected.validator_set_root;
        block.header.value_hash = projected.value_hash;
        indra_core::types::block::BlockProposalVNext {
            block,
            proposer_authorization: indra_core::types::crypto::HybridSignature {
                classical_sig: VariableBytes::from_slice(&[]).unwrap(),
                pq_sig: VariableBytes::from_slice(&[]).unwrap(),
            },
        }
    }

    fn test_hash(i: usize) -> Bytes32 {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&((i as u64).saturating_add(1)).to_le_bytes());
        Bytes32::from(bytes)
    }

    fn dummy_vote(height: u64, round: u32, step: VoteStep, block_hash: Bytes32) -> VoteV1 {
        VoteV1 {
            height,
            round,
            step,
            block_hash,
            validator_id: test_hash(round as usize),
            signature: indra_core::types::crypto::HybridSignature {
                classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                pq_sig: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            },
        }
    }

    fn single_validator_qc_bytes(
        driver: &ConsensusDriver,
        signer: &HybridKeypair,
        height: u64,
        block_hash: Bytes32,
    ) -> Vec<u8> {
        let validator_id = indra_core::types::crypto::hybrid_identity_id(
            &signer.public_key().classical.0,
            &signer.public_key().pq.0,
        );
        let vote = indra_consensus::vote::produce_vote(
            height,
            0,
            VoteStep::Precommit,
            block_hash,
            validator_id,
            DEFAULT_CHAIN_ID,
            signer,
        )
        .unwrap();
        build_qc(
            height,
            0,
            block_hash,
            DEFAULT_CHAIN_ID,
            &driver.engine.qc_validators(),
            vec![&vote],
        )
        .unwrap()
        .encode_to_vec()
    }

    fn qc_bytes_from_signers(
        driver: &ConsensusDriver,
        signers: &[&HybridKeypair],
        height: u64,
        round: u32,
        block_hash: Bytes32,
    ) -> Vec<u8> {
        let votes: Vec<_> = signers
            .iter()
            .map(|signer| {
                let validator_id = indra_core::types::crypto::hybrid_identity_id(
                    &signer.public_key().classical.0,
                    &signer.public_key().pq.0,
                );
                indra_consensus::vote::produce_vote(
                    height,
                    round,
                    VoteStep::Precommit,
                    block_hash,
                    validator_id,
                    DEFAULT_CHAIN_ID,
                    signer,
                )
                .unwrap()
            })
            .collect();
        let vote_refs: Vec<_> = votes.iter().collect();
        build_qc(
            height,
            round,
            block_hash,
            DEFAULT_CHAIN_ID,
            &driver.engine.qc_validators(),
            vote_refs,
        )
        .unwrap()
        .encode_to_vec()
    }

    fn install_active_validator(
        driver: &mut ConsensusDriver,
        seed: [u8; 32],
        name: &str,
    ) -> HybridKeypair {
        let classical = ClassicalKeypair::from_seed(&seed);
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let hybrid = HybridKeypair::new(classical, pq);
        let public = hybrid.public_key();
        let vrf_pk = VrfKeypair::from_seed(&seed).public_key();
        let cold = indra_crypto::ColdHybridKeypair::from_independent_seeds(
            [seed[0] ^ 0xA5; 32],
            [seed[0] ^ 0x5A; 32],
        )
        .unwrap();
        let cold_public = cold.public_key();
        let cold_public = cold_public.as_complete_hybrid();
        let validator_id =
            indra_core::types::crypto::hybrid_identity_id(&public.classical.0, &public.pq.0);

        driver
            .engine
            .state
            .validators
            .upsert(ValidatorEntry {
                validator_id,
                name: name.to_string(),
                hybrid_classical_pk: Some(public.classical.0),
                hybrid_pq_pk: Some(public.pq.0.to_vec()),
                vrf_pk: Some(vrf_pk),
                vrf_key_activation_epoch: 0,
                pending_vrf_pk: None,
                pending_vrf_activation_epoch: None,
                stake_spark: 1_000_000,
                status: ValidatorStatus::Active,
                registered_epoch: 0,
                last_active_epoch: 0,
                slashed_offense_id: None,
                commission_bps: DEFAULT_COMMISSION_BPS,
                pending_commission_bps: None,
                pending_commission_effective_epoch: None,
                min_delegation_spark: DUST_LIMIT_SPARK,
                auto_delegate_to: None,
                network_addr: None,
                network_addr_last_updated_epoch: None,
                cold_hybrid_classical_pk: Some(cold_public.classical.0),
                cold_hybrid_pq_pk: Some(cold_public.pq.0),
                cold_key_version: 1,
                cold_nonce: 0,
            })
            .unwrap();
        if driver.engine.state.height == 0 {
            crate::genesis::finalize_test_genesis(&mut driver.engine.state);
        }
        hybrid
    }

    fn validator_id_for(signer: &HybridKeypair) -> Bytes32 {
        indra_core::types::crypto::hybrid_identity_id(
            &signer.public_key().classical.0,
            &signer.public_key().pq.0,
        )
    }

    fn local_driver(seed: [u8; 32], suffix: &str) -> (ConsensusDriver, PathBuf) {
        let dir = temp_dir(suffix);
        let mut config = NodeConfig::local_test(dir.clone());
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let classical = ClassicalKeypair::from_seed(&seed);
        let vrf = VrfKeypair::from_seed(&seed);
        let cold = indra_crypto::ColdHybridKeypair::from_independent_seeds(
            [seed[0] ^ 0xA5; 32],
            [seed[0] ^ 0x5A; 32],
        )
        .unwrap();
        let cold_public = cold.public_key();
        let cold_public = cold_public.as_complete_hybrid();
        let validator_id = indra_core::types::crypto::hybrid_identity_id(
            &classical.public_key().0,
            &pq.public_key().0,
        )
        .0;
        let genesis_path = dir.join("genesis.toml");
        std::fs::create_dir_all(&dir).unwrap();
        let genesis = format!(
            "[genesis]\nchain_id = \"indra-testnet-1\"\nactive_slot_coefficient_numerator = \"9223372036854775808\"\nbitcoin_pow_entropy_header = \"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"\n\n[genesis.bitcoin_pow_entropy_source]\nscheme = 1\nnetwork_genesis_hash = \"0000000000000000000000000000000000000000000000000000000000000000\"\nannounced_height = 1\nheader_codec = 1\nextraction_algorithm = 1\nminimum_confirmations = 100\nreorg_policy = 1\n\n[[validators]]\nname = \"local\"\nvalidator_id = \"{}\"\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\ncold_hybrid_classical_pk = \"{}\"\ncold_hybrid_pq_pk = \"{}\"\ncold_key_version = 1\ncold_nonce = 0\nstake = 1000000\n",
            hex::encode(validator_id),
            hex::encode(classical.public_key().0),
            hex::encode(pq.public_key().0),
            hex::encode(vrf.public_key()),
            hex::encode(cold_public.classical.0),
            hex::encode(cold_public.pq.0),
        );
        std::fs::write(&genesis_path, &genesis).unwrap();
        config.genesis_path = Some(genesis_path.to_string_lossy().to_string());
        config.validator_seed = Some(seed);
        config.vrf_seed = Some(seed);
        config.pq_pk = Some(pq.public_key().0.to_vec());
        config.pq_seed = Some(pq.secret_key_bytes());
        let engine = NodeEngine::init(config).unwrap();
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let mut driver = ConsensusDriver::new(engine, vote_safety);
        for counter in 0u64..4_096 {
            let mut header = [0u8; 80];
            header[72..].copy_from_slice(&counter.to_le_bytes());
            let settings = crate::genesis::GenesisSettings {
                chain_id: "indra-testnet-1".into(),
                active_slot_coefficient_numerator: 1u64 << 63,
                bitcoin_pow_entropy_source: crate::genesis::BitcoinPowEntropySourceV1 {
                    scheme: 1,
                    network_genesis_hash: hex::encode([0u8; 32]),
                    announced_height: 1,
                    header_codec: 1,
                    extraction_algorithm: 1,
                    minimum_confirmations: 100,
                    reorg_policy: 1,
                },
                bitcoin_pow_entropy_header: hex::encode(header),
            };
            driver.engine.state.election_seed =
                crate::genesis::derive_genesis_election_seed(&settings).unwrap();
            let election = driver.proposer_election_for_height(1, 0).unwrap();
            let candidate = election
                .candidates
                .iter()
                .find(|candidate| candidate.vrf_pubkey == vrf.public_key())
                .unwrap();
            if indra_consensus::proposer::compute_proposer_vrf(
                candidate.validator_id,
                &vrf,
                &election,
            )
            .unwrap()
            .eligible
            {
                let persisted = genesis.replace(
                    &hex::encode([0u8; 80]),
                    &settings.bitcoin_pow_entropy_header,
                );
                std::fs::write(&genesis_path, persisted).unwrap();
                return (driver, dir);
            }
        }
        panic!("test genesis could not find an eligible deterministic election seed")
    }

    fn make_strict_block(
        driver: &ConsensusDriver,
        proposer_seed: [u8; 32],
        round: u32,
        prev_qc_bytes: Vec<u8>,
    ) -> indra_core::types::block::BlockProposalVNext {
        let vrf = VrfKeypair::from_seed(&proposer_seed);
        let election = (round..round.saturating_add(4_096))
            .find_map(|candidate_round| {
                let election = driver
                    .proposer_election_for_height(driver.height() + 1, candidate_round)
                    .ok()?;
                let candidate = election
                    .candidates
                    .iter()
                    .find(|candidate| candidate.vrf_pubkey == vrf.public_key())?;
                indra_consensus::proposer::compute_proposer_vrf(
                    candidate.validator_id,
                    &vrf,
                    &election,
                )
                .ok()?
                .eligible
                .then_some(election)
            })
            .expect("test proposer must become eligible within the bounded round search");
        let template = BlockTemplate {
            proposer_vrf_keypair: vrf,
            prev_qc_bytes,
            timestamp: 1_700_000_000 + driver.height() + 1,
            polc_round: None,
            transactions: vec![],
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        };
        let mut projected = driver.engine.state.clone();
        let block = produce_block(&template, &mut projected, &election).unwrap();
        let signer = HybridKeypair::new(
            ClassicalKeypair::from_seed(&proposer_seed),
            PqKeypair::from_seed(&proposer_seed).unwrap(),
        );
        let empty = indra_core::types::crypto::HybridSignature {
            classical_sig: VariableBytes::from_slice(&[]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[]).unwrap(),
        };
        let mut proposal = indra_core::types::block::BlockProposalVNext {
            block,
            proposer_authorization: empty,
        };
        let transcript = proposal.signing_bytes(DEFAULT_CHAIN_ID.as_bytes()).unwrap();
        let signature = signer.sign(&transcript).unwrap();
        proposal.proposer_authorization = indra_core::types::crypto::HybridSignature {
            classical_sig: VariableBytes::from_slice(&signature.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&signature.pq.0).unwrap(),
        };
        proposal
    }

    fn verify_live_proposal(
        driver: &ConsensusDriver,
        proposal: &indra_core::types::block::BlockProposalVNext,
    ) -> Result<(), String> {
        let snapshot = driver
            .engine
            .state
            .snapshot_for_consensus_height(proposal.header.height)
            .map_err(|error| error.to_string())?;
        indra_core::types::proposal::verify_proposal(
            proposal,
            driver.engine.state.chain_id.as_bytes(),
            &driver.engine.state.election_seed,
            snapshot,
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
    }

    fn process_single_validator_proposal(
        driver: &mut ConsensusDriver,
        proposal: indra_core::types::block::BlockProposalVNext,
    ) -> Vec<DriverAction> {
        // Deterministic test elections can require a later round. Model the
        // completed round-change that precedes delivery of that proposal; the
        // round-evidence protocol itself has dedicated adversarial tests.
        if proposal.header.proposer_round > driver.current_round() {
            driver.start_round(proposal.header.proposer_round);
        }
        let mut actions = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal,
        });
        actions.extend(driver.on_propose_timeout());
        actions
    }

    fn reauthorize_test_proposal(
        proposal: &mut indra_core::types::block::BlockProposalVNext,
        seed: [u8; 32],
        chain_id: &[u8],
    ) {
        let signer = HybridKeypair::new(
            ClassicalKeypair::from_seed(&seed),
            PqKeypair::from_seed(&seed).unwrap(),
        );
        let signature = signer
            .sign(&proposal.signing_bytes(chain_id).unwrap())
            .unwrap();
        proposal.proposer_authorization = indra_core::types::crypto::HybridSignature {
            classical_sig: VariableBytes::from_slice(&signature.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&signature.pq.0).unwrap(),
        };
    }

    fn election_for_round(driver: &ConsensusDriver, height: u64, round: u32) -> ProposerElection {
        driver.proposer_election_for_height(height, round).unwrap()
    }

    #[test]
    fn live_proposal_guard_uses_snapshot_when_live_active_set_is_empty() {
        let seed = [0xA3u8; 32];
        let (mut driver, dir) = local_driver(seed, "snapshot_live_proposer_guard");
        let valid = make_strict_block(&driver, seed, 0, vec![]);

        assert!(verify_live_proposal(&driver, &valid).is_ok());

        for validator_id in driver
            .engine
            .state
            .validators
            .active_validators()
            .map(|validator| validator.validator_id)
            .collect::<Vec<_>>()
        {
            driver
                .engine
                .state
                .validators
                .get_mut(&validator_id)
                .unwrap()
                .status = ValidatorStatus::Registered;
        }
        assert_eq!(driver.engine.state.validators.active_count(), 0);
        assert!(
            verify_live_proposal(&driver, &valid).is_ok(),
            "snapshot-authorized proposer must still verify after live demotion"
        );

        let mut invalid = valid;
        invalid.block.header.proposer_vrf_proof = VariableBytes::from_slice(&[0xA5; 32]).unwrap();
        assert!(
            verify_live_proposal(&driver, &invalid).is_err(),
            "invalid proposer proof must be checked, not skipped, when S(height) is nonempty"
        );

        driver.engine.state.consensus_snapshots.clear();
        assert!(verify_live_proposal(&driver, &invalid).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposal_requires_both_hybrid_components_and_independent_vrf_validity() {
        let seed = [0xA4u8; 32];
        let (driver, dir) = local_driver(seed, "proposal_hybrid_and_vrf_independence");
        let valid = make_strict_block(&driver, seed, 0, vec![]);
        assert!(verify_live_proposal(&driver, &valid).is_ok());

        let mut bad_classical = valid.clone();
        let mut classical_bytes = bad_classical
            .proposer_authorization
            .classical_sig
            .as_slice()
            .to_vec();
        classical_bytes[0] ^= 1;
        bad_classical.proposer_authorization.classical_sig =
            VariableBytes::from_slice(&classical_bytes).unwrap();
        assert!(verify_live_proposal(&driver, &bad_classical).is_err());

        let mut bad_pq = valid.clone();
        let mut pq_bytes = bad_pq.proposer_authorization.pq_sig.as_slice().to_vec();
        pq_bytes[0] ^= 1;
        bad_pq.proposer_authorization.pq_sig = VariableBytes::from_slice(&pq_bytes).unwrap();
        assert!(verify_live_proposal(&driver, &bad_pq).is_err());

        let attacker = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0xF1; 32]),
            PqKeypair::from_seed(&[0xF2; 32]).unwrap(),
        );
        let attacker_signature = attacker
            .sign(
                &valid
                    .signing_bytes(driver.engine.state.chain_id.as_bytes())
                    .unwrap(),
            )
            .unwrap();
        let mut mixed = valid.clone();
        mixed.proposer_authorization.pq_sig =
            VariableBytes::from_slice(&attacker_signature.pq.0).unwrap();
        assert!(verify_live_proposal(&driver, &mixed).is_err());

        let mut forged_eligibility = valid.clone();
        let mut output_bytes = forged_eligibility
            .block
            .header
            .proposer_vrf_output
            .as_slice()
            .to_vec();
        output_bytes[63] ^= 1;
        forged_eligibility.block.header.proposer_vrf_output =
            VariableBytes::from_slice(&output_bytes).unwrap();
        assert!(verify_live_proposal(&driver, &forged_eligibility).is_err());

        let mut tampered_content = valid.clone();
        tampered_content.block.header.timestamp ^= 1;
        assert!(verify_live_proposal(&driver, &tampered_content).is_err());

        let snapshot = driver
            .engine
            .state
            .snapshot_for_consensus_height(1)
            .unwrap();
        assert!(indra_core::types::proposal::verify_proposal(
            &valid,
            b"different-chain",
            &driver.engine.state.election_seed,
            snapshot,
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn local_vote_authorization_uses_snapshot_membership_after_registry_demotion() {
        let seed = [0xA5u8; 32];
        let (mut driver, dir) = local_driver(seed, "snapshot_local_vote_authority");
        let local_id = driver.engine.validator_id().unwrap();
        let snapshot = driver.engine.state.consensus_snapshots[0].clone();
        assert!(snapshot
            .entries()
            .iter()
            .any(|entry| entry.validator_id == local_id));
        driver
            .engine
            .state
            .validators
            .get_mut(&local_id)
            .unwrap()
            .status = ValidatorStatus::Registered;

        assert!(driver
            .engine
            .voter_authorized_for_height(u64::MAX, local_id)
            .unwrap());
        let actions =
            driver.sign_and_record_local_vote(u64::MAX, 0, VoteStep::Prevote, Bytes32::ZERO);
        assert!(actions
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastVote(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposer_authority_uses_snapshot_weights_not_live_registry() {
        let (mut driver, dir) = local_driver([0xB1; 32], "snapshot_proposer_weight");
        let local_id = driver.engine.validator_id().unwrap();
        let snapshot = driver.engine.state.consensus_snapshots[0].clone();
        let frozen = snapshot
            .entry_with_position(&local_id)
            .unwrap()
            .1
            .consensus_weight_spark;
        driver
            .engine
            .state
            .validators
            .get_mut(&local_id)
            .unwrap()
            .stake_spark = frozen + 999;

        let election = driver.proposer_election_for_height(u64::MAX, 0).unwrap();
        assert_eq!(election.candidates[0].stake, frozen);
        assert_ne!(
            election.candidates[0].stake,
            driver
                .engine
                .state
                .validators
                .get(&local_id)
                .unwrap()
                .stake_spark
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposer_vrf_vote_and_qc_authority_are_snapshot_identical() {
        let (driver, dir) = local_driver([0xB5; 32], "snapshot_cross_authority");
        let snapshot = driver
            .engine
            .state
            .build_genesis_consensus_snapshot()
            .unwrap();
        let vrf = vrf_authority_from_snapshot(
            DEFAULT_CHAIN_ID.as_bytes(),
            301,
            2,
            indra_core::types::primitives::Bytes64([0x55; 64]),
            &snapshot,
        );
        let voters = NodeEngine::registered_voters_for_height(301, &snapshot);
        let qc = NodeEngine::qc_validators_for_height(301, &snapshot);

        assert_eq!(vrf.election.candidates.len(), voters.len());
        assert_eq!(voters.len(), qc.len());
        for ((candidate, voter), validator) in vrf.election.candidates.iter().zip(&voters).zip(&qc)
        {
            assert_eq!(candidate.validator_id, voter.validator_id);
            assert_eq!(voter.validator_id, validator.validator_id);
            assert_eq!(candidate.stake, voter.stake);
            assert_eq!(voter.stake, validator.stake);
            assert_eq!(
                candidate.vrf_pubkey,
                snapshot.entries()[validator.position].vrf_pk
            );
        }
        assert_eq!(
            voters.iter().map(|voter| voter.stake).sum::<u64>(),
            snapshot.total_weight_spark
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn consensus_snapshot_capstone_multi_epoch_authority_lifecycle_is_consistent() {
        let local_seed = [0xC0; 32];
        let (mut driver, dir) = local_driver(local_seed, "snapshot_lifecycle_capstone");
        let local = install_active_validator(&mut driver, local_seed, "local");
        let b = install_active_validator(&mut driver, [0xC1; 32], "b");
        let c = install_active_validator(&mut driver, [0xC2; 32], "c");
        let local_id = validator_id_for(&local);
        let b_id = validator_id_for(&b);
        let c_id = validator_id_for(&c);
        for (id, stake) in [(local_id, 40), (b_id, 30), (c_id, 30)] {
            driver
                .engine
                .state
                .validators
                .get_mut(&id)
                .unwrap()
                .stake_spark = stake;
        }
        let genesis = driver
            .engine
            .state
            .build_genesis_consensus_snapshot()
            .unwrap();
        driver
            .engine
            .state
            .validators
            .get_mut(&c_id)
            .unwrap()
            .stake_spark = 60;
        let at_301 = driver
            .engine
            .state
            .build_consensus_snapshot(301, 300)
            .unwrap();
        driver
            .engine
            .state
            .validators
            .get_mut(&b_id)
            .unwrap()
            .status = ValidatorStatus::Registered;
        let d = install_active_validator(&mut driver, [0xC3; 32], "d");
        let d_id = validator_id_for(&d);
        driver
            .engine
            .state
            .validators
            .get_mut(&d_id)
            .unwrap()
            .stake_spark = 50;
        let at_601 = driver
            .engine
            .state
            .build_consensus_snapshot(601, 600)
            .unwrap();
        driver
            .engine
            .state
            .validators
            .get_mut(&local_id)
            .unwrap()
            .stake_spark = 80;
        driver
            .engine
            .state
            .validators
            .get_mut(&c_id)
            .unwrap()
            .status = ValidatorStatus::Registered;
        let at_901 = driver
            .engine
            .state
            .build_consensus_snapshot(901, 900)
            .unwrap();
        driver.engine.state.consensus_snapshots = vec![at_601.clone(), at_901.clone()];

        let signers = vec![
            (local_id, local_seed, local),
            (b_id, [0xC1; 32], b),
            (c_id, [0xC2; 32], c),
            (d_id, [0xC3; 32], d),
        ];
        let snapshots = [(1, genesis), (301, at_301), (601, at_601), (901, at_901)];
        let run = || {
            snapshots
                .iter()
                .map(|(height, snapshot)| {
                    let voters = NodeEngine::registered_voters_for_height(*height, snapshot);
                    let validators = NodeEngine::qc_validators_for_height(*height, snapshot);
                    let authority = vrf_authority_from_snapshot(
                        DEFAULT_CHAIN_ID.as_bytes(),
                        *height,
                        0,
                        Bytes64([(*height % 251) as u8; 64]),
                        snapshot,
                    );
                    assert_eq!(voters.len(), validators.len());
                    assert_eq!(validators.len(), authority.election.candidates.len());
                    for ((voter, validator), candidate) in voters
                        .iter()
                        .zip(&validators)
                        .zip(&authority.election.candidates)
                    {
                        assert_eq!(voter.validator_id, validator.validator_id);
                        assert_eq!(validator.validator_id, candidate.validator_id);
                        assert_eq!(voter.stake, validator.stake);
                        assert_eq!(validator.stake, candidate.stake);
                    }
                    let block_hash = Bytes32::from([(*height % 239) as u8; 32]);
                    let votes = signers
                        .iter()
                        .filter(|(id, _, _)| snapshot.entry_with_position(id).is_some())
                        .map(|(id, _, signer)| {
                            indra_consensus::vote::produce_vote(
                                *height,
                                0,
                                VoteStep::Precommit,
                                block_hash,
                                *id,
                                DEFAULT_CHAIN_ID,
                                signer,
                            )
                            .unwrap()
                        })
                        .collect::<Vec<_>>();
                    let qc = indra_consensus::qc::build_qc(
                        *height,
                        0,
                        block_hash,
                        DEFAULT_CHAIN_ID,
                        &validators,
                        votes.iter().collect(),
                    )
                    .unwrap();
                    NodeEngine::verify_qc_with_snapshot(&qc, snapshot, DEFAULT_CHAIN_ID).unwrap();
                    let sortition = signers
                        .iter()
                        .filter(|(id, _, _)| snapshot.entry_with_position(id).is_some())
                        .map(|(id, seed, _)| {
                            let result = indra_consensus::proposer::compute_proposer_vrf(
                                *id,
                                &VrfKeypair::from_seed(seed),
                                &authority.election,
                            )
                            .unwrap();
                            (result.vrf_output.0, result.eligible, result.priority)
                        })
                        .collect::<Vec<_>>();
                    (snapshot.snapshot_root, sortition, qc.encode_to_vec())
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            run(),
            run(),
            "live and replay transcripts must be identical"
        );
        assert_eq!(
            snapshots
                .iter()
                .map(|(_, snapshot)| snapshot.activation_height)
                .collect::<Vec<_>>(),
            vec![1, 301, 601, 901]
        );
        assert_eq!(
            driver
                .engine
                .state
                .consensus_snapshots
                .iter()
                .map(|snapshot| snapshot.activation_height)
                .collect::<Vec<_>>(),
            vec![601, 901]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn governed_proposer_and_vrf_quorum_fail_closed_without_snapshot() {
        let (mut driver, dir) = local_driver([0xB7; 32], "missing_vrf_snapshot");
        driver.engine.state.consensus_snapshots.clear();
        assert!(matches!(
            driver.proposer_election_for_height(u64::MAX, 0),
            Err(NodeError::ConsensusSnapshotLookup(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn competing_proposals_same_value_hash_cannot_both_reach_quorum() {
        let (mut driver, dir) = local_driver([0x8Bu8; 32], "competing_full_hash");
        let a = install_active_validator(&mut driver, [0x8Bu8; 32], "a");
        let b = install_active_validator(&mut driver, [0x8Cu8; 32], "b");
        let c = install_active_validator(&mut driver, [0x8Du8; 32], "c");
        let d = install_active_validator(&mut driver, [0x8Eu8; 32], "d");
        driver.refresh_registered_voters();

        let mut block_a = make_block(&driver.engine.state);
        block_a.header.proposer_round = 0;
        block_a.header.polc_round = NO_POLC_ROUND;
        let mut block_b = block_a.clone();
        block_b.header.proposer_round = 1;
        block_b.header.polc_round = 0;

        assert_eq!(block_a.header.value_hash, block_b.header.value_hash);
        let hash_a = block_a.header.block_hash();
        let hash_b = block_b.header.block_hash();
        assert_ne!(hash_a, hash_b);

        let voters = driver.registered_voters.clone();
        let mut collector = VoteCollector::new(
            1,
            0,
            VoteStep::Prevote,
            DEFAULT_CHAIN_ID.to_string(),
            voters,
        );
        let signer_ids = [
            indra_core::types::crypto::hybrid_identity_id(
                &a.public_key().classical.0,
                &a.public_key().pq.0,
            ),
            indra_core::types::crypto::hybrid_identity_id(
                &b.public_key().classical.0,
                &b.public_key().pq.0,
            ),
            indra_core::types::crypto::hybrid_identity_id(
                &c.public_key().classical.0,
                &c.public_key().pq.0,
            ),
            indra_core::types::crypto::hybrid_identity_id(
                &d.public_key().classical.0,
                &d.public_key().pq.0,
            ),
        ];
        let signers = [&a, &b, &c, &d];

        for idx in 0..2 {
            let vote = indra_consensus::vote::produce_vote(
                1,
                0,
                VoteStep::Prevote,
                hash_a,
                signer_ids[idx],
                DEFAULT_CHAIN_ID,
                signers[idx],
            )
            .unwrap();
            assert!(matches!(
                collector.add_vote(vote).unwrap(),
                indra_consensus::vote::VoteDecision::Waiting
            ));
        }
        for idx in 2..4 {
            let vote = indra_consensus::vote::produce_vote(
                1,
                0,
                VoteStep::Prevote,
                hash_b,
                signer_ids[idx],
                DEFAULT_CHAIN_ID,
                signers[idx],
            )
            .unwrap();
            assert!(matches!(
                collector.add_vote(vote).unwrap(),
                indra_consensus::vote::VoteDecision::Waiting
            ));
        }

        let equivocation = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Prevote,
            hash_a,
            signer_ids[2],
            DEFAULT_CHAIN_ID,
            signers[2],
        )
        .unwrap();
        assert!(
            collector.add_vote(equivocation).is_err(),
            "a validator cannot move from one full hash to another to make both quorums"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vote_before_block_requests_proposal_then_commits() {
        let (mut driver, dir) = local_driver([0x42u8; 32], "votes_before_block");
        let _local = install_active_validator(&mut driver, [0x42u8; 32], "local");
        let remote_a = install_active_validator(&mut driver, [0x43u8; 32], "remote-a");
        let remote_b = install_active_validator(&mut driver, [0x44u8; 32], "remote-b");
        driver.refresh_registered_voters();
        let block = make_strict_block(&driver, [0x42u8; 32], 0, vec![]);
        let round = block.header.proposer_round;
        driver.current_round = round;
        let block_hash = block.header.block_hash();

        let remote_a_id = indra_core::types::crypto::hybrid_identity_id(
            &remote_a.public_key().classical.0,
            &remote_a.public_key().pq.0,
        );
        let remote_b_id = indra_core::types::crypto::hybrid_identity_id(
            &remote_b.public_key().classical.0,
            &remote_b.public_key().pq.0,
        );

        let prevote_a = indra_consensus::vote::produce_vote(
            1,
            round,
            VoteStep::Prevote,
            block_hash,
            remote_a_id,
            DEFAULT_CHAIN_ID,
            &remote_a,
        )
        .unwrap();
        let prevote_b = indra_consensus::vote::produce_vote(
            1,
            round,
            VoteStep::Prevote,
            block_hash,
            remote_b_id,
            DEFAULT_CHAIN_ID,
            &remote_b,
        )
        .unwrap();
        let precommit_a = indra_consensus::vote::produce_vote(
            1,
            round,
            VoteStep::Precommit,
            block_hash,
            remote_a_id,
            DEFAULT_CHAIN_ID,
            &remote_a,
        )
        .unwrap();
        let precommit_b = indra_consensus::vote::produce_vote(
            1,
            round,
            VoteStep::Precommit,
            block_hash,
            remote_b_id,
            DEFAULT_CHAIN_ID,
            &remote_b,
        )
        .unwrap();

        let peer_a: SocketAddr = "127.0.0.1:9101".parse().unwrap();
        let peer_b: SocketAddr = "127.0.0.1:9102".parse().unwrap();
        let actions_a = driver.process(DriverEvent::InboundVote {
            from: peer_a,
            vote: prevote_a,
        });
        let actions_b = driver.process(DriverEvent::InboundVote {
            from: peer_b,
            vote: prevote_b,
        });
        assert!(actions_a
            .iter()
            .any(|a| matches!(a, DriverAction::RequestProposal { .. })));
        assert!(actions_b.is_empty());

        let mut actions = driver.process(DriverEvent::InboundBlock {
            from: Some(peer_a),
            proposal: block,
        });
        actions.extend(driver.on_propose_timeout());
        actions.extend(driver.process(DriverEvent::InboundVote {
            from: peer_a,
            vote: precommit_a,
        }));
        actions.extend(driver.process(DriverEvent::InboundVote {
            from: peer_b,
            vote: precommit_b,
        }));

        assert_eq!(driver.height(), 1);
        assert!(actions.iter().any(|a| matches!(
            a,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Precommit && vote.block_hash == block_hash
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn propose_timeout_prevotes_staged_block_instead_of_nil() {
        let (mut driver, dir) = local_driver([0x45u8; 32], "staged_timeout_prevote");
        let _local = install_active_validator(&mut driver, [0x45u8; 32], "local");
        driver.refresh_registered_voters();

        let block = make_strict_block(&driver, [0x45u8; 32], 0, vec![]);
        let block_hash = block.header.block_hash();
        let mut actions = driver.process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:9201".parse().unwrap()),
            proposal: block,
        });
        actions.extend(driver.on_propose_timeout());

        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == block_hash
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_round_timeouts_do_not_advance_election_seed() {
        let (mut driver, dir) = local_driver([0x48; 32], "empty_round_seed_stable");
        let _local = install_active_validator(&mut driver, [0x48; 32], "local");
        driver.refresh_registered_voters();
        let seed = driver.engine.state.election_seed;
        let height = driver.height();
        let _ = driver.on_propose_timeout();
        let _ = driver.on_precommit_timeout();
        assert_eq!(driver.height(), height);
        assert_eq!(driver.engine.state.election_seed, seed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposal_selection_switches_to_better_priority_only_before_prevote() {
        let (mut driver, dir) = local_driver([0x46; 32], "priority_selection_timeout");
        let a = install_active_validator(&mut driver, [0x46; 32], "a");
        let b = install_active_validator(&mut driver, [0x47; 32], "b");
        driver.refresh_registered_voters();
        let a_id = validator_id_for(&a);
        let b_id = validator_id_for(&b);
        let a_vrf = VrfKeypair::from_seed(&[0x46; 32]);
        let b_vrf = VrfKeypair::from_seed(&[0x47; 32]);
        let round = (0..4_096)
            .find(|round| {
                let election = election_for_round(&driver, 1, *round);
                indra_consensus::proposer::compute_proposer_vrf(a_id, &a_vrf, &election)
                    .is_ok_and(|r| r.eligible)
                    && indra_consensus::proposer::compute_proposer_vrf(b_id, &b_vrf, &election)
                        .is_ok_and(|r| r.eligible)
            })
            .expect("two deterministic candidates must share an eligible test round");
        driver.current_round = round;
        let a_proposal = make_strict_block(&driver, [0x46; 32], round, vec![]);
        let b_proposal = make_strict_block(&driver, [0x47; 32], round, vec![]);
        assert_eq!(a_proposal.header.proposer_round, round);
        assert_eq!(b_proposal.header.proposer_round, round);
        let (better, worse) =
            if a_proposal.header.proposer_priority < b_proposal.header.proposer_priority {
                (a_proposal, b_proposal)
            } else {
                (b_proposal, a_proposal)
            };
        let better_hash = better.header.block_hash();
        let worse_hash = worse.header.block_hash();

        let first = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: worse.clone(),
        });
        let switched = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: better,
        });
        assert!(!first.iter().chain(&switched).any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote) if vote.step == VoteStep::Prevote
        )));
        let timeout = driver.on_propose_timeout();
        assert!(timeout.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == better_hash
        )));

        let after_prevote = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: worse,
        });
        assert!(!after_prevote.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == worse_hash
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposal_requires_quorum_evidence_before_round_advancement() {
        let (mut driver, dir) = local_driver([0x4Fu8; 32], "proposal_round_advance");
        let signer = install_active_validator(&mut driver, [0x4Fu8; 32], "validator");
        driver.refresh_registered_voters();

        let block = make_strict_block(&driver, [0x4Fu8; 32], 5, vec![]);
        let block_hash = block.header.block_hash();
        let mut actions = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: block,
        });
        actions.extend(driver.on_propose_timeout());

        assert_eq!(driver.current_round(), 0);
        assert!(!actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.round == 5 && vote.step == VoteStep::Prevote && vote.block_hash == block_hash
        )));

        let vote = indra_consensus::vote::produce_vote(
            1,
            5,
            VoteStep::Prevote,
            Bytes32::ZERO,
            validator_id_for(&signer),
            DEFAULT_CHAIN_ID,
            &signer,
        )
        .unwrap();
        let actions = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9202".parse().unwrap(),
            vote,
        });
        // With the single-validator test snapshot, the certified advance also
        // lets the staged proposal immediately reach vote quorum and commit.
        assert_eq!(driver.height(), 1);
        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.round == 5 && vote.step == VoteStep::Prevote && vote.block_hash == block_hash
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposal_does_not_retreat_round() {
        let (mut driver, dir) = local_driver([0x50u8; 32], "proposal_round_no_retreat");
        let _local = install_active_validator(&mut driver, [0x50u8; 32], "local");
        driver.refresh_registered_voters();
        driver.current_round = 10;

        let block = make_strict_block(&driver, [0x50u8; 32], 3, vec![]);
        let _actions = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: block,
        });

        assert_eq!(driver.current_round(), 10);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposal_round_jump_cannot_bypass_vote_safety_without_evidence() {
        let (mut driver, dir) = local_driver([0x51u8; 32], "proposal_round_vote_safety");
        let _local = install_active_validator(&mut driver, [0x51u8; 32], "local");
        driver.refresh_registered_voters();
        driver.vote_safety.record(1, 5, 0, None).unwrap();

        let block = make_strict_block(&driver, [0x51u8; 32], 5, vec![]);
        let actions = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: block,
        });

        assert_eq!(driver.current_round(), 0);
        assert!(!actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote) if vote.round == 5
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prevote_timeout_sends_nil_precommit() {
        let (mut driver, dir) = local_driver([0x46u8; 32], "prevote_timeout_nil");
        let _local = install_active_validator(&mut driver, [0x46u8; 32], "local");
        driver.refresh_registered_voters();
        driver.current_phase = RoundPhase::Prevote;

        let actions = driver.on_prevote_timeout();
        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Precommit && vote.block_hash == Bytes32::ZERO
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn precommit_timeout_advances_round() {
        let (mut driver, dir) = local_driver([0x47u8; 32], "precommit_timeout_round");
        let _local = install_active_validator(&mut driver, [0x47u8; 32], "local");
        driver.refresh_registered_voters();
        driver.current_phase = RoundPhase::Precommit;
        driver.current_round = 3;

        driver.on_precommit_timeout();
        assert_eq!(driver.current_round(), 4);
        assert_eq!(driver.current_phase(), RoundPhase::Propose);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn process_status_cannot_advance_round_without_quorum_evidence() {
        let (mut driver, dir) = local_driver([0x4Au8; 32], "status_round_advance");
        let peer: SocketAddr = "127.0.0.1:9301".parse().unwrap();

        driver.process(DriverEvent::PeerStatus {
            from: peer,
            validator_id: Bytes32::ZERO,
            height: 1,
            tip_hash: driver.engine.state.tip_hash,
            round: 8,
        });

        assert_eq!(driver.current_round(), 0);
        assert_eq!(driver.current_phase(), RoundPhase::Propose);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legitimate_hybrid_signed_quorum_advances_round_and_preserves_liveness() {
        let (mut driver, dir) = local_driver([0x93u8; 32], "round_evidence_quorum");
        let signers: Vec<HybridKeypair> = (0u8..4)
            .map(|i| {
                let seed = [0xA0u8.saturating_add(i); 32];
                HybridKeypair::new(
                    ClassicalKeypair::from_seed(&seed),
                    PqKeypair::from_seed(&seed).unwrap(),
                )
            })
            .collect();
        driver.set_voters(
            signers
                .iter()
                .map(|signer| {
                    let public = signer.public_key();
                    RegisteredVoter {
                        validator_id: validator_id_for(signer),
                        classical_pk: public.classical.0,
                        pq_pk: public.pq.0.to_vec(),
                        stake: 1,
                    }
                })
                .collect(),
        );

        for (index, signer) in signers.iter().enumerate() {
            let vote = indra_consensus::vote::produce_vote(
                1,
                4,
                if index == 1 {
                    VoteStep::Precommit
                } else {
                    VoteStep::Prevote
                },
                Bytes32::ZERO,
                validator_id_for(signer),
                DEFAULT_CHAIN_ID,
                signer,
            )
            .unwrap();
            driver.process(DriverEvent::InboundVote {
                from: format!("127.0.0.1:{}", 9500 + index).parse().unwrap(),
                vote,
            });
            if index < 2 {
                assert_eq!(driver.current_round(), 0, "<=2/3 must not advance");
            } else {
                assert_eq!(driver.current_round(), 4, "strict >2/3 must advance");
                break;
            }
        }
        assert_eq!(driver.current_phase(), RoundPhase::Propose);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_status_large_round_claim_is_informational_only() {
        let (mut driver, dir) = local_driver([0x8Au8; 32], "status_round_cap");
        driver.current_round = 5;
        let peer: SocketAddr = "127.0.0.1:9401".parse().unwrap();

        driver.process(DriverEvent::PeerStatus {
            from: peer,
            validator_id: Bytes32::ZERO,
            height: 1,
            tip_hash: driver.engine.state.tip_hash,
            round: 1_358,
        });

        assert_eq!(driver.current_round(), 5);
        assert_eq!(driver.current_phase(), RoundPhase::Propose);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_status_normal_round_claim_is_informational_only() {
        let (mut driver, dir) = local_driver([0x8Bu8; 32], "status_round_normal");
        driver.current_round = 5;
        let peer: SocketAddr = "127.0.0.1:9402".parse().unwrap();

        driver.process(DriverEvent::PeerStatus {
            from: peer,
            validator_id: Bytes32::ZERO,
            height: 1,
            tip_hash: driver.engine.state.tip_hash,
            round: 6,
        });

        assert_eq!(driver.current_round(), 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_status_repeated_messages_cannot_force_round_advance() {
        let (mut driver, dir) = local_driver([0x8Cu8; 32], "status_round_repeated");
        driver.current_round = 5;
        let peer: SocketAddr = "127.0.0.1:9403".parse().unwrap();

        for _ in 0..100 {
            driver.sync.mark_caught_up(driver.height());
            driver.process(DriverEvent::PeerStatus {
                from: peer,
                validator_id: Bytes32::ZERO,
                height: 1,
                tip_hash: driver.engine.state.tip_hash,
                round: 29,
            });
        }

        assert_eq!(driver.current_round(), 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn process_status_does_not_retreat_round() {
        let (mut driver, dir) = local_driver([0x4Bu8; 32], "status_round_no_retreat");
        driver.current_round = 10;
        let peer: SocketAddr = "127.0.0.1:9302".parse().unwrap();

        driver.process(DriverEvent::PeerStatus {
            from: peer,
            validator_id: Bytes32::ZERO,
            height: 1,
            tip_hash: driver.engine.state.tip_hash,
            round: 3,
        });

        assert_eq!(driver.current_round(), 10);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn process_status_ignores_round_if_not_caught_up() {
        let (mut driver, dir) = local_driver([0x4Cu8; 32], "status_round_syncing");
        driver.sync = SyncState::follower(driver.engine.height());
        let peer: SocketAddr = "127.0.0.1:9303".parse().unwrap();

        driver.process(DriverEvent::PeerStatus {
            from: peer,
            validator_id: Bytes32::ZERO,
            height: 1,
            tip_hash: driver.engine.state.tip_hash,
            round: 8,
        });

        assert_eq!(driver.current_round(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn buffered_votes_does_not_grow_unbounded_while_stalled() {
        let (mut driver, dir) = local_driver([0x90u8; 32], "bounded_buffered_votes");
        driver.current_round = 128;
        let peer: SocketAddr = "127.0.0.1:9501".parse().unwrap();

        for i in 0..(MAX_STALLED_HEIGHT_ENTRIES + 100) {
            let hash = test_hash(i);
            driver
                .buffered_votes
                .entry((1, i as u32, hash))
                .or_default()
                .push((peer, dummy_vote(1, i as u32, VoteStep::Prevote, hash)));
        }
        driver.prune_buffered_votes();

        assert!(driver.buffered_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vote_collectors_evicts_oldest_when_at_capacity() {
        let (mut driver, dir) = local_driver([0x91u8; 32], "bounded_vote_collectors");
        driver.current_round = 128;

        for i in 0..(MAX_STALLED_HEIGHT_ENTRIES + 100) {
            driver.vote_collectors.insert(
                (1, i as u32, VoteStep::Prevote),
                VoteCollector::new(
                    1,
                    i as u32,
                    VoteStep::Prevote,
                    DEFAULT_CHAIN_ID.to_string(),
                    driver.registered_voters.clone(),
                ),
            );
        }
        driver.prune_vote_collectors();

        assert!(driver.vote_collectors.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn requested_proposals_does_not_grow_unbounded() {
        let (mut driver, dir) = local_driver([0x92u8; 32], "bounded_requested");
        driver.current_round = 128;

        for i in 0..(MAX_STALLED_HEIGHT_ENTRIES + 100) {
            driver
                .requested_proposals
                .insert((1, i as u32, test_hash(i)));
        }
        driver.prune_requested_proposals();

        assert!(driver.requested_proposals.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seen_round_votes_does_not_grow_unbounded() {
        let (mut driver, dir) = local_driver([0x93u8; 32], "bounded_seen_votes");
        driver.current_round = 128;

        for i in 0..(MAX_STALLED_HEIGHT_ENTRIES + 100) {
            driver.seen_round_votes.insert(
                (test_hash(i), 1, i as u32, VoteStep::Prevote),
                test_hash(i + 1_000),
            );
        }
        driver.prune_seen_round_votes();

        assert!(driver.seen_round_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pending_blocks_does_not_grow_unbounded() {
        let (mut driver, dir) = local_driver([0x94u8; 32], "bounded_pending_blocks");
        driver.current_round = 128;

        for i in 0..(MAX_STALLED_HEIGHT_ENTRIES + 100) {
            let mut block = make_block(&driver.engine.state);
            block.header.proposer_round = i as u32;
            block.header.timestamp = block.header.timestamp.saturating_add(i as u64);
            driver
                .pending_blocks
                .insert(block.header.block_hash(), block);
        }
        driver.prune_pending_blocks();

        assert!(driver.pending_blocks.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn future_proposals_does_not_grow_unbounded() {
        let (mut driver, dir) = local_driver([0x95u8; 32], "bounded_future_proposals");
        driver.current_round = 128;
        let key = (driver.next_height(), driver.engine.state.tip_hash);

        for i in 0..(MAX_STALLED_HEIGHT_ENTRIES + 100) {
            let mut block = make_block(&driver.engine.state);
            block.header.proposer_round = i as u32;
            block.header.timestamp = block.header.timestamp.saturating_add(i as u64);
            driver.future_proposals.entry(key).or_default().push(block);
        }
        driver.prune_future_proposals_bounded();

        let total: usize = driver.future_proposals.values().map(Vec::len).sum();
        assert!(total <= MAX_STALLED_HEIGHT_ENTRIES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pending_precommit_quorum_does_not_grow_unbounded() {
        let (mut driver, dir) = local_driver([0x96u8; 32], "bounded_pending_quorum");
        driver.current_round = 128;

        for i in 0..(MAX_STALLED_HEIGHT_ENTRIES + 100) {
            driver
                .pending_precommit_quorum
                .insert((1, i as u32, test_hash(i)));
        }
        driver.prune_pending_precommit_quorum();

        assert!(driver.pending_precommit_quorum.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bounded_collections_do_not_break_normal_consensus_operation() {
        let (mut driver, dir) = local_driver([0x97u8; 32], "bounded_normal_consensus");
        let _local = install_active_validator(&mut driver, [0x97u8; 32], "local");
        driver.refresh_registered_voters();

        let block = make_strict_block(&driver, [0x97u8; 32], 0, vec![]);
        let mut actions = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: block,
        });
        actions.extend(driver.on_propose_timeout());

        assert_eq!(driver.height(), 1);
        assert!(actions
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastBlock(_))));
        assert!(driver.vote_collectors.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        assert!(driver.pending_blocks.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        assert!(
            driver
                .future_proposals
                .values()
                .map(Vec::len)
                .sum::<usize>()
                <= MAX_STALLED_HEIGHT_ENTRIES
        );
        assert!(driver.buffered_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        assert!(driver.requested_proposals.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        assert!(driver.seen_round_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        assert!(driver.pending_precommit_quorum.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_vote_safety_skips_past_voted_rounds() {
        let (mut driver, dir) = local_driver([0x4Du8; 32], "vote_safety_skip");
        driver.engine.state.height = 4;
        driver.vote_safety.record(5, 7, 0, None).unwrap();

        driver.apply_vote_safety();

        assert_eq!(driver.current_round(), 8);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_vote_safety_ignores_old_height() {
        let (mut driver, dir) = local_driver([0x4Eu8; 32], "vote_safety_old_height");
        driver.engine.state.height = 5;
        driver.vote_safety.record(3, 10, 0, None).unwrap();

        driver.apply_vote_safety();

        assert_eq!(driver.current_round(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_vote_safety_record_prevents_voting() {
        let (mut driver, dir) = local_driver([0x71u8; 32], "vote_safety_corrupt_blocks");
        std::fs::write(driver.engine.config.vote_safety_path(), [0xAA, 0xBB]).unwrap();
        driver.apply_vote_safety();
        let actions = driver.sign_and_record_local_vote(1, 0, VoteStep::Prevote, Bytes32::ZERO);
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, DriverAction::BroadcastVote(_))),
            "corrupt vote_safety.dat must fail closed and block vote broadcast"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_vote_safety_record_allows_voting_on_fresh_start() {
        let (mut driver, dir) = local_driver([0x72u8; 32], "vote_safety_missing_allows");
        let _ = std::fs::remove_file(driver.engine.config.vote_safety_path());
        driver.apply_vote_safety();
        let actions = driver.sign_and_record_local_vote(1, 0, VoteStep::Prevote, Bytes32::ZERO);
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, DriverAction::BroadcastVote(_))),
            "missing vote_safety.dat on a fresh start should allow voting"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vote_safety_write_failure_prevents_vote_broadcast() {
        let (mut driver, dir) = local_driver([0x73u8; 32], "vote_safety_write_fail");
        let safety_path = driver.engine.config.vote_safety_path();
        let _ = std::fs::remove_file(&safety_path);
        std::fs::create_dir_all(&safety_path).unwrap();
        let actions = driver.sign_and_record_local_vote(1, 0, VoteStep::Prevote, Bytes32::ZERO);
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, DriverAction::BroadcastVote(_))),
            "vote safety persistence failure must block vote broadcast"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn valid_vote_safety_record_constrains_future_rounds() {
        let (mut driver, dir) = local_driver([0x74u8; 32], "vote_safety_valid_constrains");
        driver.vote_safety.record(1, 2, 0, None).unwrap();
        driver.apply_vote_safety();
        assert_eq!(driver.current_round(), 3);
        let actions = driver.sign_and_record_local_vote(1, 3, VoteStep::Prevote, Bytes32::ZERO);
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, DriverAction::BroadcastVote(_))),
            "higher round after persisted vote-safety record should remain allowed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn crash_restart_restores_lock_and_rejects_conflicting_no_polc_prevote() {
        let seed = [0x79u8; 32];
        let (mut driver, dir) = local_driver(seed, "restart_restores_lock");
        let local = install_active_validator(&mut driver, seed, "local");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());

        // Step 1-2: A received a genuine strict-two-thirds prevote PoLC and the
        // validator persisted its resulting lock before its non-nil precommit.
        let block_a = make_strict_block(&driver, seed, 0, vec![]);
        let hash_a = block_a.header.block_hash();
        let value_a = block_a.header.value_hash;
        let prevote_a = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Prevote,
            hash_a,
            validator_id_for(&local),
            DEFAULT_CHAIN_ID,
            &local,
        )
        .unwrap();
        let durable_lock = PersistedConsensusLock {
            height: 1,
            round: 0,
            block_hash: hash_a,
            value_hash: value_a,
            proposal: block_a,
            polc_votes: vec![prevote_a],
        };
        driver
            .vote_safety
            .record(1, 0, 1, Some(&durable_lock))
            .unwrap();

        // Step 3-4: crash and reconstruct from durable state. The lock and its
        // independently verified PoLC must be restored, not merely round-skip.
        let config = driver.engine.config.clone();
        drop(driver);
        let engine = NodeEngine::init(config).unwrap();
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let mut restarted = ConsensusDriver::new(engine, vote_safety);
        restarted.sync.mark_caught_up(restarted.height());
        assert_eq!(restarted.locked_round, Some(0));
        assert_eq!(restarted.locked_value, Some(hash_a));
        assert_eq!(restarted.current_round(), 1);

        // Step 5: a conflicting round-1 proposal without a later PoLC must get
        // a nil prevote. Before T7-01 the restarted driver was unlocked and
        // legitimately prevoted this conflicting full block hash.
        let mut block_b = make_block(&restarted.engine.state);
        block_b.header.proposer_round = 1;
        block_b.header.polc_round = NO_POLC_ROUND;
        block_b.header.timestamp = block_b.header.timestamp.saturating_add(1);
        block_b.header.value_hash = block_b.compute_value_hash(restarted.engine.state.total_supply);
        let hash_b = block_b.header.block_hash();
        assert_ne!(hash_b, hash_a);
        restarted.pending_blocks.insert(hash_b, block_b);
        restarted.current_phase = RoundPhase::Propose;
        let actions = restarted.maybe_prevote_current_round_proposal();
        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == Bytes32::ZERO
        )));
        assert!(!actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote) if vote.block_hash == hash_b
        )));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn restart_rejects_persisted_lock_with_invalid_proposer_authorization() {
        let seed = [0x7Eu8; 32];
        let (mut driver, dir) = local_driver(seed, "restart_rejects_bad_lock_envelope");
        let local = install_active_validator(&mut driver, seed, "local");
        driver.refresh_registered_voters();

        let mut proposal = make_strict_block(&driver, seed, 0, vec![]);
        let block_hash = proposal.header.block_hash();
        let value_hash = proposal.header.value_hash;
        let prevote = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Prevote,
            block_hash,
            validator_id_for(&local),
            DEFAULT_CHAIN_ID,
            &local,
        )
        .unwrap();
        let mut bad_pq = proposal.proposer_authorization.pq_sig.as_slice().to_vec();
        bad_pq[0] ^= 0x01;
        proposal.proposer_authorization.pq_sig = VariableBytes::from_slice(&bad_pq).unwrap();
        let durable_lock = PersistedConsensusLock {
            height: 1,
            round: 0,
            block_hash,
            value_hash,
            proposal,
            polc_votes: vec![prevote],
        };
        driver
            .vote_safety
            .record(1, 0, 1, Some(&durable_lock))
            .unwrap();

        let config = driver.engine.config.clone();
        drop(driver);
        let engine = NodeEngine::init(config).unwrap();
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let restarted = ConsensusDriver::new(engine, vote_safety);
        assert!(restarted.locked_round.is_none());
        assert!(restarted.locked_value.is_none());
        assert!(restarted
            .vote_safety_unavailable
            .as_deref()
            .is_some_and(|reason| reason.contains("persisted lock proposal failed verification")));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn lock_polc_is_durable_before_precommit_broadcast_is_returned() {
        let (mut driver, dir) = local_driver([0x7Au8; 32], "lock_before_precommit");
        let _local = install_active_validator(&mut driver, [0x7Au8; 32], "local");
        let remote_a = install_active_validator(&mut driver, [0x7Bu8; 32], "remote-a");
        let remote_b = install_active_validator(&mut driver, [0x7Cu8; 32], "remote-b");
        let _remote_c = install_active_validator(&mut driver, [0x7Du8; 32], "remote-c");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());

        let block = make_strict_block(&driver, [0x7Au8; 32], 0, vec![]);
        let round = block.header.proposer_round;
        driver.current_round = round;
        let hash = block.header.block_hash();
        let _ = process_single_validator_proposal(&mut driver, block);
        for (port, signer) in [(9711, &remote_a), (9712, &remote_b)] {
            let vote = indra_consensus::vote::produce_vote(
                1,
                round,
                VoteStep::Prevote,
                hash,
                validator_id_for(signer),
                DEFAULT_CHAIN_ID,
                signer,
            )
            .unwrap();
            let actions = driver.process(DriverEvent::InboundVote {
                from: SocketAddr::from(([127, 0, 0, 1], port)),
                vote,
            });
            if actions.iter().any(|action| {
                matches!(
                    action,
                    DriverAction::BroadcastVote(vote)
                        if vote.step == VoteStep::Precommit && vote.block_hash == hash
                )
            }) {
                let VoteSafetyLoadResult::Record(record) = driver.vote_safety.load() else {
                    panic!("precommit broadcast requires a durable safety record")
                };
                let lock = record
                    .consensus_lock
                    .expect("precommit broadcast requires a durable lock");
                assert_eq!(lock.block_hash, hash);
                assert!(lock.polc_votes.len() >= 3);
                let _ = std::fs::remove_dir_all(dir);
                return;
            }
        }
        panic!("prevote quorum did not produce the expected precommit");
    }

    #[test]
    fn driver_detects_double_precommit() {
        let (mut driver, dir) = local_driver([0x48u8; 32], "double_precommit");
        let remote = install_active_validator(&mut driver, [0x49u8; 32], "remote");
        driver.refresh_registered_voters();

        let remote_id = indra_core::types::crypto::hybrid_identity_id(
            &remote.public_key().classical.0,
            &remote.public_key().pq.0,
        );
        let vote_a = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Precommit,
            Bytes32::from([0xAAu8; 32]),
            remote_id,
            DEFAULT_CHAIN_ID,
            &remote,
        )
        .unwrap();
        let vote_b = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Precommit,
            Bytes32::from([0xBBu8; 32]),
            remote_id,
            DEFAULT_CHAIN_ID,
            &remote,
        )
        .unwrap();

        let peer: SocketAddr = "127.0.0.1:9301".parse().unwrap();
        let _ = driver.process(DriverEvent::InboundVote {
            from: peer,
            vote: vote_a,
        });
        let actions = driver.process(DriverEvent::InboundVote {
            from: peer,
            vote: vote_b,
        });

        assert!(actions
            .iter()
            .any(|a| matches!(a, DriverAction::SlashDetected(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn forged_vote_cannot_poison_real_validators_round_slot() {
        let (mut driver, dir) = local_driver([0x4Bu8; 32], "forged_vote_slot");
        let real = install_active_validator(&mut driver, [0x4Cu8; 32], "real");
        let attacker = install_active_validator(&mut driver, [0x4Du8; 32], "attacker");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());
        let real_id = indra_core::types::crypto::hybrid_identity_id(
            &real.public_key().classical.0,
            &real.public_key().pq.0,
        );
        let slot = (real_id, driver.next_height(), 0, VoteStep::Prevote);
        let forged = indra_consensus::vote::produce_vote(
            driver.next_height(),
            0,
            VoteStep::Prevote,
            Bytes32::ZERO,
            real_id,
            DEFAULT_CHAIN_ID,
            &attacker,
        )
        .unwrap();
        let forged_actions = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9302".parse().unwrap(),
            vote: forged,
        });
        assert!(forged_actions
            .iter()
            .any(|action| matches!(action, DriverAction::DisconnectInvalidConsensusPeer { .. })));
        assert!(!driver.seen_round_votes.contains_key(&slot));

        let legitimate = indra_consensus::vote::produce_vote(
            driver.next_height(),
            0,
            VoteStep::Prevote,
            Bytes32::ZERO,
            real_id,
            DEFAULT_CHAIN_ID,
            &real,
        )
        .unwrap();
        let legitimate_actions = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9303".parse().unwrap(),
            vote: legitimate,
        });
        assert!(!legitimate_actions
            .iter()
            .any(|action| matches!(action, DriverAction::DisconnectInvalidConsensusPeer { .. })));
        assert_eq!(driver.seen_round_votes.get(&slot), Some(&Bytes32::ZERO));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn implausible_future_vote_is_rejected_before_slot_reservation() {
        let (mut driver, dir) = local_driver([0x4Eu8; 32], "future_vote_bound");
        let remote = install_active_validator(&mut driver, [0x4Fu8; 32], "remote");
        driver.refresh_registered_voters();
        let remote_id = indra_core::types::crypto::hybrid_identity_id(
            &remote.public_key().classical.0,
            &remote.public_key().pq.0,
        );
        let vote = indra_consensus::vote::produce_vote(
            driver.next_height().saturating_add(100),
            driver
                .current_round
                .saturating_add(MAX_ACCEPTED_ROUND_JUMP + 1),
            VoteStep::Prevote,
            Bytes32::ZERO,
            remote_id,
            DEFAULT_CHAIN_ID,
            &remote,
        )
        .unwrap();
        let _ = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9304".parse().unwrap(),
            vote,
        });
        assert!(driver.seen_round_votes.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn forged_conflicting_votes_do_not_reach_slash_detector() {
        let (mut driver, dir) = local_driver([0x50u8; 32], "forged_vote_slash");
        let real = install_active_validator(&mut driver, [0x51u8; 32], "real");
        let attacker = install_active_validator(&mut driver, [0x52u8; 32], "attacker");
        driver.refresh_registered_voters();
        let real_id = indra_core::types::crypto::hybrid_identity_id(
            &real.public_key().classical.0,
            &real.public_key().pq.0,
        );
        for hash in [Bytes32::from([0xAA; 32]), Bytes32::from([0xBB; 32])] {
            let forged = indra_consensus::vote::produce_vote(
                driver.next_height(),
                0,
                VoteStep::Precommit,
                hash,
                real_id,
                DEFAULT_CHAIN_ID,
                &attacker,
            )
            .unwrap();
            let actions = driver.process(DriverEvent::InboundVote {
                from: "127.0.0.1:9305".parse().unwrap(),
                vote: forged,
            });
            assert!(!actions
                .iter()
                .any(|action| matches!(action, DriverAction::SlashDetected(_))));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn polc_round_exposes_valid_round_for_reproposal() {
        let (mut driver, dir) = local_driver([0x4Au8; 32], "valid_round");
        let _local = install_active_validator(&mut driver, [0x4Au8; 32], "local");
        driver.refresh_registered_voters();

        driver.valid_round = Some(2);
        driver.valid_value = Some(Bytes32::from([0x11u8; 32]));

        assert_eq!(driver.proposal_polc_round(1), Some(2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn last_qc_persisted_after_commit() {
        let (mut driver, dir) = local_driver([0x61u8; 32], "persist_qc");
        let _local = install_active_validator(&mut driver, [0x61u8; 32], "local");
        driver.refresh_registered_voters();

        let block = make_strict_block(&driver, [0x61u8; 32], 0, vec![]);
        let _ = process_single_validator_proposal(&mut driver, block);

        let qc_path = driver.engine.config.state_dir().join("last_qc.bin");
        assert!(qc_path.exists(), "expected last_qc.bin to be created");
        let bytes = std::fs::read(qc_path).unwrap();
        assert!(!bytes.is_empty(), "persisted QC must be non-empty");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn last_qc_is_stale_detects_height_mismatch() {
        let (mut driver, dir) = local_driver([0xA1u8; 32], "last_qc_stale");
        let local = install_active_validator(&mut driver, [0xA1u8; 32], "local");
        driver.refresh_registered_voters();
        driver.engine.state.height = 5;
        driver.last_qc_bytes =
            single_validator_qc_bytes(&driver, &local, 3, Bytes32::from([0x33u8; 32]));

        assert!(driver.last_qc_is_stale());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn last_qc_is_stale_false_when_height_matches() {
        let (mut driver, dir) = local_driver([0xA2u8; 32], "last_qc_fresh");
        let local = install_active_validator(&mut driver, [0xA2u8; 32], "local");
        driver.refresh_registered_voters();
        driver.engine.state.height = 5;
        driver.last_qc_bytes =
            single_validator_qc_bytes(&driver, &local, 5, Bytes32::from([0x55u8; 32]));

        assert!(!driver.last_qc_is_stale());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sync_path_promotes_last_qc_bytes() {
        let (mut source, source_dir) = local_driver([0xA3u8; 32], "sync_promote_source");
        let _source_local = install_active_validator(&mut source, [0xA3u8; 32], "local");
        source.refresh_registered_voters();

        let block1 = make_strict_block(&source, [0xA3u8; 32], 0, vec![]);
        let _ = process_single_validator_proposal(&mut source, block1.clone());
        let qc_for_height_1 = source.last_qc_bytes();
        assert!(!qc_for_height_1.is_empty());
        let block2 = make_strict_block(&source, [0xA3u8; 32], 0, qc_for_height_1.clone());

        let (mut driver, dir) = local_driver([0xA3u8; 32], "sync_promote_importer");
        let local = install_active_validator(&mut driver, [0xA3u8; 32], "local");
        driver.refresh_registered_voters();

        driver.engine.commit_proposal(&block1).unwrap();
        driver.promote_block_header_qc(&block1, "sync").unwrap();
        driver.engine.commit_proposal(&block2).unwrap();
        driver.promote_block_header_qc(&block2, "sync").unwrap();
        driver.refresh_registered_voters();
        driver.sync_mut().on_block_imported(block2.header.height);
        driver.reset_round();

        assert_eq!(driver.height(), 2);
        assert_eq!(driver.last_qc_bytes(), qc_for_height_1);
        assert_eq!(driver.last_qc_height(), Some(1));
        assert!(driver.last_qc_is_stale());
        assert!(matches!(
            driver.request_qc_if_needed().as_slice(),
            [DriverAction::RequestQC { height }] if *height == 2
        ));

        drop(local);
        let _ = std::fs::remove_dir_all(&source_dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sync_then_consensus_transition_recovers_after_qc_response() {
        let (mut source, source_dir) = local_driver([0xB5u8; 32], "sync_transition_source");
        let source_local = install_active_validator(&mut source, [0xB5u8; 32], "local");
        source.refresh_registered_voters();

        let block1 = make_strict_block(&source, [0xB5u8; 32], 0, vec![]);
        let _ = process_single_validator_proposal(&mut source, block1.clone());
        let qc_for_height_1 = source.last_qc_bytes();
        let block2 = make_strict_block(&source, [0xB5u8; 32], 0, qc_for_height_1.clone());

        let (mut driver, dir) = local_driver([0xB5u8; 32], "sync_transition_importer");
        let local = install_active_validator(&mut driver, [0xB5u8; 32], "local");
        driver.refresh_registered_voters();

        for block in [&block1, &block2] {
            driver.engine.commit_proposal(block).unwrap();
            driver.promote_block_header_qc(block, "sync").unwrap();
            driver.sync_mut().on_block_imported(block.header.height);
            driver.reset_round();
        }
        driver.on_sync_caught_up();

        assert_eq!(driver.height(), 2);
        assert_eq!(driver.last_qc_height(), Some(1));
        assert!(driver.last_qc_is_stale());
        assert!(matches!(
            driver.request_qc_if_needed().as_slice(),
            [DriverAction::RequestQC { height }] if *height == 2
        ));

        let source_validator_id = validator_id_for(&source_local);
        let qc_vote = indra_consensus::vote::produce_vote(
            2,
            block2.header.proposer_round,
            VoteStep::Precommit,
            block2.header.block_hash(),
            source_validator_id,
            DEFAULT_CHAIN_ID,
            &source_local,
        )
        .unwrap();
        let qc = indra_consensus::build_qc(
            2,
            block2.header.proposer_round,
            block2.header.block_hash(),
            DEFAULT_CHAIN_ID,
            &driver.engine.qc_validators(),
            vec![&qc_vote],
        )
        .unwrap();
        let qc_bytes = qc.encode_to_vec();

        let _ = driver.process(DriverEvent::QcResponse {
            from: "127.0.0.1:9510".parse().unwrap(),
            height: 2,
            qc_bytes: qc_bytes.clone(),
        });

        assert_eq!(driver.last_qc_height(), Some(2));
        assert_eq!(driver.last_qc_bytes(), qc_bytes);
        assert!(
            !driver.last_qc_is_stale(),
            "current-tip QC response must clear sync-recovery staleness"
        );
        assert!(
            driver.request_qc_if_needed().is_empty(),
            "driver must stop requesting QC after current-tip QC recovery"
        );
        let local_vrf = VrfKeypair::from_seed(&[0xB5; 32]);
        let election = (0..4_096)
            .map(|round| driver.proposer_election_for_height(3, round).unwrap())
            .find(|election| {
                indra_consensus::proposer::compute_proposer_vrf(
                    validator_id_for(&source_local),
                    &local_vrf,
                    election,
                )
                .is_ok_and(|result| result.eligible)
            })
            .expect("local validator must become eligible within the bounded round search");
        let proposal_result =
            driver
                .engine
                .propose(&election, 1_700_000_003, driver.last_qc_bytes(), None);
        assert!(
            proposal_result.is_ok(),
            "recovered current-tip QC should allow height-3 proposal construction: {proposal_result:?}"
        );

        drop(local);
        let _ = std::fs::remove_dir_all(&source_dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_recovers_pending_current_tip_qc_after_commit_boundary() {
        let (mut source, source_dir) = local_driver([0xC1u8; 32], "pending_qc_source");
        let _source_local = install_active_validator(&mut source, [0xC1u8; 32], "local");
        source.refresh_registered_voters();

        let block1 = make_strict_block(&source, [0xC1u8; 32], 0, vec![]);
        let _ = process_single_validator_proposal(&mut source, block1.clone());
        let qc_for_height_1 = source.last_qc_bytes();
        assert!(!qc_for_height_1.is_empty());

        let (mut driver, dir) = local_driver([0xC1u8; 32], "pending_qc_restart");
        let local = install_active_validator(&mut driver, [0xC1u8; 32], "local");
        driver.refresh_registered_voters();

        driver.engine.commit_proposal(&block1).unwrap();
        driver
            .set_last_qc_bytes_if_newer(1, qc_for_height_1.clone())
            .unwrap();
        assert_eq!(driver.height(), 1);
        assert_eq!(driver.last_qc_height(), Some(1));

        let block2 = make_strict_block(&driver, [0xC1u8; 32], 0, driver.last_qc_bytes());
        let validator_id = validator_id_for(&local);
        let qc_vote = indra_consensus::vote::produce_vote(
            2,
            block2.header.proposer_round,
            VoteStep::Precommit,
            block2.header.block_hash(),
            validator_id,
            DEFAULT_CHAIN_ID,
            &local,
        )
        .unwrap();
        let qc_for_height_2 = indra_consensus::build_qc(
            2,
            block2.header.proposer_round,
            block2.header.block_hash(),
            DEFAULT_CHAIN_ID,
            &driver.engine.qc_validators(),
            vec![&qc_vote],
        )
        .unwrap()
        .encode_to_vec();

        // Simulate the old crash boundary exactly: the current-tip QC has been
        // durably staged, the block/state commit reaches height 2, but the
        // process stops before `last_qc.bin` is promoted from height 1 to 2.
        indra_storage::save_pending_last_qc(&driver.engine.config.state_dir(), &qc_for_height_2)
            .unwrap();
        driver.engine.commit_proposal(&block2).unwrap();
        assert_eq!(driver.height(), 2);
        assert_eq!(driver.last_qc_height(), Some(1));
        assert_eq!(
            ConsensusDriver::decode_qc_height(
                &indra_storage::load_last_qc(&driver.engine.config.state_dir())
                    .unwrap()
                    .unwrap()
            ),
            Some(1)
        );
        assert_eq!(
            ConsensusDriver::decode_qc_height(
                &indra_storage::load_pending_last_qc(&driver.engine.config.state_dir())
                    .unwrap()
                    .unwrap()
            ),
            Some(2)
        );

        let config = driver.engine.config.clone();
        drop(local);
        drop(driver);

        let engine = NodeEngine::init(config).unwrap();
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let restarted = ConsensusDriver::new(engine, vote_safety);
        assert_eq!(restarted.height(), 2);
        assert_eq!(restarted.last_qc_height(), Some(2));
        assert_eq!(restarted.last_qc_bytes(), qc_for_height_2);
        assert!(!restarted.last_qc_is_stale());
        assert!(restarted.request_qc_if_needed().is_empty());
        assert_eq!(
            ConsensusDriver::decode_qc_height(
                &indra_storage::load_last_qc(&restarted.engine.config.state_dir())
                    .unwrap()
                    .unwrap()
            ),
            Some(2)
        );
        assert!(
            indra_storage::load_pending_last_qc(&restarted.engine.config.state_dir())
                .unwrap()
                .is_none()
        );

        let _ = std::fs::remove_dir_all(&source_dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sync_batch_partial_failure_does_not_promote_orphaned_qc() {
        let (mut source, source_dir) = local_driver([0xB6u8; 32], "sync_partial_source");
        let _source_local = install_active_validator(&mut source, [0xB6u8; 32], "local");
        source.refresh_registered_voters();

        let block1 = make_strict_block(&source, [0xB6u8; 32], 0, vec![]);
        let _ = process_single_validator_proposal(&mut source, block1.clone());
        let qc_for_height_1 = source.last_qc_bytes();
        let block2 = make_strict_block(&source, [0xB6u8; 32], 0, qc_for_height_1.clone());
        let _ = process_single_validator_proposal(&mut source, block2.clone());
        let qc_for_height_2 = source.last_qc_bytes();
        let mut bad_block3 = make_strict_block(&source, [0xB6u8; 32], 0, qc_for_height_2);
        bad_block3.header.prev_hash = Bytes32::from([0xEEu8; 32]);
        reauthorize_test_proposal(&mut bad_block3, [0xB6u8; 32], DEFAULT_CHAIN_ID.as_bytes());

        let (mut driver, dir) = local_driver([0xB6u8; 32], "sync_partial_importer");
        install_active_validator(&mut driver, [0xB6u8; 32], "local");
        driver.refresh_registered_voters();

        for block in [&block1, &block2] {
            driver.engine.commit_proposal(block).unwrap();
            driver.promote_block_header_qc(block, "sync").unwrap();
        }
        assert!(driver.engine.commit_proposal(&bad_block3).is_err());

        assert_eq!(driver.height(), 2);
        assert_eq!(driver.last_qc_height(), Some(1));
        assert_eq!(driver.last_qc_bytes(), qc_for_height_1);

        let _ = std::fs::remove_dir_all(&source_dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_last_qc_bytes_if_newer_height_ordering() {
        let (mut driver, dir) = local_driver([0xB7u8; 32], "last_qc_ordering");
        let local = install_active_validator(&mut driver, [0xB7u8; 32], "local");
        driver.refresh_registered_voters();

        let qc_height_3 =
            single_validator_qc_bytes(&driver, &local, 3, Bytes32::from([0x33u8; 32]));
        let qc_height_5_a =
            single_validator_qc_bytes(&driver, &local, 5, Bytes32::from([0x55u8; 32]));
        let qc_height_5_b =
            single_validator_qc_bytes(&driver, &local, 5, Bytes32::from([0x56u8; 32]));

        driver
            .set_last_qc_bytes_if_newer(5, qc_height_5_a.clone())
            .unwrap();
        assert_eq!(driver.last_qc_height(), Some(5));
        assert_eq!(driver.last_qc_bytes(), qc_height_5_a);

        driver.set_last_qc_bytes_if_newer(3, qc_height_3).unwrap();
        assert_eq!(driver.last_qc_height(), Some(5));
        assert_eq!(driver.last_qc_bytes(), qc_height_5_a);

        driver
            .set_last_qc_bytes_if_newer(5, qc_height_5_a.clone())
            .unwrap();
        assert_eq!(driver.last_qc_bytes(), qc_height_5_a);

        assert!(driver.set_last_qc_bytes_if_newer(5, qc_height_5_b).is_err());
        assert_eq!(driver.last_qc_height(), Some(5));
        assert_eq!(driver.last_qc_bytes(), qc_height_5_a);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn equivalent_qc_different_signer_subset_no_conflict() {
        let (mut driver, dir) = local_driver([0xB8u8; 32], "equivalent_qc_subset");
        let a = install_active_validator(&mut driver, [0xB8u8; 32], "a");
        let b = install_active_validator(&mut driver, [0xB9u8; 32], "b");
        let c = install_active_validator(&mut driver, [0xBAu8; 32], "c");
        let d = install_active_validator(&mut driver, [0xBBu8; 32], "d");
        driver.refresh_registered_voters();

        let block_hash = Bytes32::from([0x88u8; 32]);
        let qc_abc = qc_bytes_from_signers(&driver, &[&a, &b, &c], 5, 0, block_hash);
        let qc_abd = qc_bytes_from_signers(&driver, &[&a, &b, &d], 5, 0, block_hash);
        assert_ne!(
            qc_abc, qc_abd,
            "test setup must produce distinct QC bytes from different valid signer subsets"
        );

        driver
            .set_last_qc_bytes_if_newer(5, qc_abc.clone())
            .unwrap();
        driver.set_last_qc_bytes_if_newer(5, qc_abd).unwrap();

        assert_eq!(
            driver.last_qc_bytes(),
            qc_abc,
            "benign equivalent QCs should not replace the cached bytes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_qc_matching_metadata_still_rejected() {
        let (mut driver, dir) = local_driver([0xBCu8; 32], "invalid_equivalent_qc");
        let a = install_active_validator(&mut driver, [0xBCu8; 32], "a");
        let b = install_active_validator(&mut driver, [0xBDu8; 32], "b");
        let c = install_active_validator(&mut driver, [0xBEu8; 32], "c");
        let d = install_active_validator(&mut driver, [0xBFu8; 32], "d");
        driver.refresh_registered_voters();

        let block_hash = Bytes32::from([0x8Au8; 32]);
        let qc_abc = qc_bytes_from_signers(&driver, &[&a, &b, &c], 6, 0, block_hash);
        let mut invalid_qc = qc_bytes_from_signers(&driver, &[&a, &b, &d], 6, 0, block_hash);
        let last = invalid_qc.len() - 1;
        invalid_qc[last] ^= 0x01;

        driver
            .set_last_qc_bytes_if_newer(6, qc_abc.clone())
            .unwrap();
        let err = driver
            .set_last_qc_bytes_if_newer(6, invalid_qc)
            .unwrap_err();

        assert!(
            matches!(err, NodeError::BlockInvalid { .. }),
            "invalid same-content QC must be rejected, not treated as benign equivalent"
        );
        assert_eq!(driver.last_qc_bytes(), qc_abc);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn genuinely_conflicting_content_still_hard_errors() {
        let (mut driver, dir) = local_driver([0xC0u8; 32], "genuine_qc_conflict");
        let a = install_active_validator(&mut driver, [0xC0u8; 32], "a");
        let b = install_active_validator(&mut driver, [0xC1u8; 32], "b");
        let c = install_active_validator(&mut driver, [0xC2u8; 32], "c");
        let d = install_active_validator(&mut driver, [0xC3u8; 32], "d");
        driver.refresh_registered_voters();

        let qc_a = qc_bytes_from_signers(&driver, &[&a, &b, &c], 7, 0, Bytes32::from([0x8Du8; 32]));
        let qc_b = qc_bytes_from_signers(&driver, &[&a, &b, &d], 7, 0, Bytes32::from([0x8Eu8; 32]));

        driver.set_last_qc_bytes_if_newer(7, qc_a.clone()).unwrap();
        assert!(driver.set_last_qc_bytes_if_newer(7, qc_b).is_err());
        assert_eq!(driver.last_qc_bytes(), qc_a);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposal_with_wrong_qc_height_rejected_at_intake_not_just_finalization() {
        let (mut driver, dir) = local_driver([0xA4u8; 32], "proposal_wrong_qc_intake");
        let _local = install_active_validator(&mut driver, [0xA4u8; 32], "local");
        driver.refresh_registered_voters();

        let block1 = make_strict_block(&driver, [0xA4u8; 32], 0, vec![]);
        let _ = process_single_validator_proposal(&mut driver, block1);
        let qc_for_height_1 = driver.last_qc_bytes();

        let block2 = make_strict_block(&driver, [0xA4u8; 32], 0, qc_for_height_1.clone());
        let _ = process_single_validator_proposal(&mut driver, block2);
        assert_eq!(driver.height(), 2);

        let mut malformed_block3 =
            make_strict_block(&driver, [0xA4u8; 32], 0, driver.last_qc_bytes());
        malformed_block3.header.quorum_certificate =
            VariableBytes::from_slice(&qc_for_height_1).unwrap();
        reauthorize_test_proposal(
            &mut malformed_block3,
            [0xA4; 32],
            driver.engine.state.chain_id.as_bytes(),
        );
        let malformed_hash = malformed_block3.header.block_hash();
        let actions = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: malformed_block3,
        });

        assert!(actions
            .iter()
            .all(|action| matches!(action, DriverAction::None)));
        assert!(driver.pending_block(&malformed_hash).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn driver_restart_with_stale_persisted_qc_does_not_restore_it() {
        let dir = temp_dir("restart_stale_qc");
        let seed = [0xA5u8; 32];
        let stale_qc_bytes = {
            let (mut source_driver, source_dir) = local_driver(seed, "restart_stale_qc_source");
            let local = install_active_validator(&mut source_driver, seed, "local");
            source_driver.refresh_registered_voters();
            source_driver.engine.state.height = 3;
            let bytes =
                single_validator_qc_bytes(&source_driver, &local, 3, Bytes32::from([0xA5u8; 32]));
            let _ = std::fs::remove_dir_all(&source_dir);
            bytes
        };

        let mut config = NodeConfig::local_test(dir.clone());
        let pq = PqKeypair::from_seed(&seed).unwrap();
        config.genesis_path = Some(dir.join("genesis.toml").to_string_lossy().to_string());
        config.validator_seed = Some(seed);
        config.vrf_seed = Some(seed);
        config.pq_pk = Some(pq.public_key().0.to_vec());
        config.pq_seed = Some(pq.secret_key_bytes());
        {
            let mut pristine = NodeEngine::init(config.clone()).unwrap();
            pristine.write_chain_manifest().unwrap();
        }
        indra_storage::save_last_qc(&config.state_dir(), &stale_qc_bytes).unwrap();

        let mut engine = NodeEngine::init(config).unwrap();
        engine.state.height = 5;
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let restarted = ConsensusDriver::new(engine, vote_safety);

        assert!(restarted.last_qc_bytes().is_empty());
        assert!(restarted.last_qc_is_stale());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn normal_consensus_unaffected_by_staleness_checks() {
        let (mut driver, dir) = local_driver([0xA6u8; 32], "normal_qc_fresh");
        let _local = install_active_validator(&mut driver, [0xA6u8; 32], "local");
        driver.refresh_registered_voters();

        let seed_at_height_one = driver.engine.state.election_seed;
        let block1 = make_strict_block(&driver, [0xA6u8; 32], 0, vec![]);
        let _ = process_single_validator_proposal(&mut driver, block1.clone());
        assert_eq!(driver.height(), 1);
        assert_ne!(driver.engine.state.election_seed, seed_at_height_one);
        let seed_at_height_two = driver.engine.state.election_seed;
        let _ = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: block1,
        });
        assert_eq!(driver.engine.state.election_seed, seed_at_height_two);
        assert!(!driver.last_qc_is_stale());

        let block2 = make_strict_block(&driver, [0xA6u8; 32], 0, driver.last_qc_bytes());
        let _ = process_single_validator_proposal(&mut driver, block2);
        assert_eq!(driver.height(), 2);
        assert!(!driver.last_qc_is_stale());
        assert!(driver.request_qc_if_needed().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn last_qc_restored_on_restart() {
        let dir = temp_dir("restore_qc");
        let seed = [0x62u8; 32];
        {
            let (mut driver, _) = local_driver(seed, "restore_qc");
            let _local = install_active_validator(&mut driver, seed, "local");
            driver.refresh_registered_voters();
            let block = make_strict_block(&driver, seed, 0, vec![]);
            let _ = process_single_validator_proposal(&mut driver, block);
            assert!(!driver.last_qc_bytes().is_empty());
        }

        let mut config = NodeConfig::local_test(dir.clone());
        let pq = PqKeypair::from_seed(&seed).unwrap();
        config.genesis_path = Some(dir.join("genesis.toml").to_string_lossy().to_string());
        config.validator_seed = Some(seed);
        config.vrf_seed = Some(seed);
        config.pq_pk = Some(pq.public_key().0.to_vec());
        config.pq_seed = Some(pq.secret_key_bytes());
        let engine = NodeEngine::init(config).unwrap();
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let restarted = ConsensusDriver::new(engine, vote_safety);
        assert!(
            !restarted.last_qc_bytes().is_empty(),
            "restarted driver should restore persisted QC"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_discards_structurally_valid_qc_with_forged_signatures() {
        let seed = [0x68u8; 32];
        let (mut driver, dir) = local_driver(seed, "restore_forged_qc");
        let _local = install_active_validator(&mut driver, seed, "local");
        driver.refresh_registered_voters();
        let block = make_strict_block(&driver, seed, 0, vec![]);
        let _ = process_single_validator_proposal(&mut driver, block);
        let mut qc = QuorumCertificateV1::decode_exact(&driver.last_qc_bytes()).unwrap();
        let mut forged_signature = qc.pq_signatures[0].pq_sig.as_slice().to_vec();
        forged_signature[0] ^= 0x80;
        qc.pq_signatures[0].pq_sig = VariableBytes::from_slice(&forged_signature).unwrap();
        let forged = qc.encode_to_vec();
        indra_storage::save_last_qc(&driver.engine.config.state_dir(), &forged).unwrap();
        indra_storage::save_pending_last_qc(&driver.engine.config.state_dir(), &forged).unwrap();
        let config = driver.engine.config.clone();
        drop(driver);

        let engine = NodeEngine::init(config).unwrap();
        let state_dir = engine.config.state_dir();
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let restarted = ConsensusDriver::new(engine, vote_safety);
        assert!(restarted.last_qc_bytes().is_empty());
        assert!(indra_storage::load_last_qc(&state_dir).unwrap().is_none());
        assert!(indra_storage::load_pending_last_qc(&state_dir)
            .unwrap()
            .is_none());
        assert!(!restarted.request_qc_if_needed().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_can_enter_proposer_path_without_qc() {
        let (mut driver, dir) = local_driver([0x63u8; 32], "no_qc_no_propose");
        driver.engine.state.height = 2;
        driver.engine.state.tip_hash = Bytes32::from([0x11; 32]);
        assert!(
            driver.can_propose(),
            "proposal gating should be enforced during block construction, not before proposer selection"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_qc_file_does_not_panic() {
        let (mut driver, dir) = local_driver([0x64u8; 32], "missing_qc");
        driver.engine.state.height = 2;
        driver.engine.state.tip_hash = Bytes32::from([0x22; 32]);
        let engine = driver.engine;

        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let restarted = ConsensusDriver::new(engine, vote_safety);
        assert!(restarted.last_qc_bytes().is_empty());
        assert!(restarted.can_propose());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn handle_qc_response_accepts_valid_qc() {
        let (mut driver, dir) = local_driver([0x65u8; 32], "qc_response_valid");
        let local = install_active_validator(&mut driver, [0x65u8; 32], "local");
        driver.engine.state.height = 7;
        driver.engine.state.tip_hash = Bytes32::from([0x31; 32]);
        driver.refresh_registered_voters();

        let validator_id = indra_core::types::crypto::hybrid_identity_id(
            &local.public_key().classical.0,
            &local.public_key().pq.0,
        );
        let value_hash = Bytes32::from([0x44u8; 32]);
        let vote = indra_consensus::vote::produce_vote(
            7,
            0,
            VoteStep::Precommit,
            value_hash,
            validator_id,
            DEFAULT_CHAIN_ID,
            &local,
        )
        .unwrap();
        let validators = driver.engine.qc_validators();
        let qc =
            indra_consensus::build_qc(7, 0, value_hash, DEFAULT_CHAIN_ID, &validators, vec![&vote])
                .unwrap();
        let qc_bytes = qc.encode_to_vec();

        let _ = driver.process(DriverEvent::QcResponse {
            from: "127.0.0.1:9501".parse().unwrap(),
            height: 7,
            qc_bytes: qc_bytes.clone(),
        });

        assert_eq!(driver.last_qc_bytes(), qc_bytes);
        assert!(driver
            .engine
            .config
            .state_dir()
            .join("last_qc.bin")
            .exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn handle_qc_response_rejects_invalid_qc() {
        let (mut driver, dir) = local_driver([0x66u8; 32], "qc_response_invalid");
        let local = install_active_validator(&mut driver, [0x66u8; 32], "local");
        driver.engine.state.height = 7;
        driver.refresh_registered_voters();

        let validator_id = indra_core::types::crypto::hybrid_identity_id(
            &local.public_key().classical.0,
            &local.public_key().pq.0,
        );
        let value_hash = Bytes32::from([0x45u8; 32]);
        let vote = indra_consensus::vote::produce_vote(
            7,
            0,
            VoteStep::Precommit,
            value_hash,
            validator_id,
            DEFAULT_CHAIN_ID,
            &local,
        )
        .unwrap();
        let validators = driver.engine.qc_validators();
        let qc =
            indra_consensus::build_qc(7, 0, value_hash, DEFAULT_CHAIN_ID, &validators, vec![&vote])
                .unwrap();
        let mut qc_bytes = qc.encode_to_vec();
        let last = qc_bytes.len() - 1;
        qc_bytes[last] ^= 0x01;

        let actions = driver.process(DriverEvent::QcResponse {
            from: "127.0.0.1:9502".parse().unwrap(),
            height: 7,
            qc_bytes,
        });

        assert!(driver.last_qc_bytes().is_empty());
        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::ScorePeer {
                event: indra_network::peer::ScoreEvent::InvalidMessage,
                ..
            }
        )));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn handle_qc_response_rejects_trailing_bytes_before_verification() {
        let (mut driver, dir) = local_driver([0x68u8; 32], "qc_response_trailing");
        let local = install_active_validator(&mut driver, [0x68u8; 32], "local");
        driver.engine.state.height = 7;
        driver.refresh_registered_voters();
        let validator_id = indra_core::types::crypto::hybrid_identity_id(
            &local.public_key().classical.0,
            &local.public_key().pq.0,
        );
        let value_hash = Bytes32::from([0x46u8; 32]);
        let vote = indra_consensus::vote::produce_vote(
            7,
            0,
            VoteStep::Precommit,
            value_hash,
            validator_id,
            DEFAULT_CHAIN_ID,
            &local,
        )
        .unwrap();
        let validators = driver.engine.qc_validators();
        let mut qc_bytes =
            indra_consensus::build_qc(7, 0, value_hash, DEFAULT_CHAIN_ID, &validators, vec![&vote])
                .unwrap()
                .encode_to_vec();
        qc_bytes.push(0xA5);

        let actions = driver.process(DriverEvent::QcResponse {
            from: "127.0.0.1:9503".parse().unwrap(),
            height: 7,
            qc_bytes,
        });
        assert!(driver.last_qc_bytes().is_empty());
        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::ScorePeer {
                event: indra_network::peer::ScoreEvent::InvalidMessage,
                ..
            }
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn handle_qc_response_ignores_wrong_height() {
        let (mut driver, dir) = local_driver([0x67u8; 32], "qc_response_height");
        driver.engine.state.height = 100;
        let _ = driver.process(DriverEvent::QcResponse {
            from: "127.0.0.1:9503".parse().unwrap(),
            height: 50,
            qc_bytes: vec![1, 2, 3],
        });
        assert!(driver.last_qc_bytes().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn qc_request_not_sent_when_qc_present() {
        let (mut driver, dir) = local_driver([0x68u8; 32], "qc_request_present");
        let local = install_active_validator(&mut driver, [0x68u8; 32], "local");
        driver.refresh_registered_voters();
        driver.engine.state.height = 9;
        driver.last_qc_bytes =
            single_validator_qc_bytes(&driver, &local, 9, Bytes32::from([0x68u8; 32]));
        assert!(driver.request_qc_if_needed().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn qc_request_served_when_height_matches() {
        let (mut driver, dir) = local_driver([0x69u8; 32], "qc_request_served");
        let local = install_active_validator(&mut driver, [0x69u8; 32], "local");
        driver.refresh_registered_voters();
        let from: SocketAddr = "127.0.0.1:9504".parse().unwrap();
        driver.engine.state.height = 12;
        let expected_qc_bytes =
            single_validator_qc_bytes(&driver, &local, 12, Bytes32::from([0x69u8; 32]));
        driver.last_qc_bytes = expected_qc_bytes.clone();

        let actions = driver.process(DriverEvent::QcRequest { from, height: 12 });

        assert!(matches!(
            actions.as_slice(),
            [DriverAction::SendQCResponse { to, height, qc_bytes }]
                if *to == from && *height == 12 && qc_bytes == &expected_qc_bytes
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn qc_request_served_from_block_header_when_one_ahead() {
        let (mut driver, dir) = local_driver([0x6Au8; 32], "qc_request_one_ahead");
        let _local = install_active_validator(&mut driver, [0x6Au8; 32], "local");
        driver.refresh_registered_voters();

        let block1 = make_strict_block(&driver, [0x6Au8; 32], 0, vec![]);
        let _ = process_single_validator_proposal(&mut driver, block1);
        let qc_for_height_1 = driver.last_qc_bytes();
        assert!(!qc_for_height_1.is_empty());

        let mut block2 = make_strict_block(&driver, [0x6Au8; 32], 0, qc_for_height_1.clone());
        block2.header.quorum_certificate =
            indra_core::VariableBytes::from_slice(&qc_for_height_1).unwrap();
        let _ = process_single_validator_proposal(&mut driver, block2);

        let from: SocketAddr = "127.0.0.1:9505".parse().unwrap();
        let actions = driver.process(DriverEvent::QcRequest { from, height: 1 });

        assert!(matches!(
            actions.as_slice(),
            [DriverAction::SendQCResponse { to, height, qc_bytes }]
                if *to == from && *height == 1 && *qc_bytes == qc_for_height_1
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reproposal_is_voted_with_its_own_block_hash() {
        let (mut driver, dir) = local_driver([0x73u8; 32], "valid_reproposal");
        let local = install_active_validator(&mut driver, [0x73u8; 32], "local");
        let remote_a = install_active_validator(&mut driver, [0x74u8; 32], "remote-a");
        let remote_b = install_active_validator(&mut driver, [0x75u8; 32], "remote-b");
        let _remote_c = install_active_validator(&mut driver, [0x76u8; 32], "remote-c");
        driver.refresh_registered_voters();

        let block = make_strict_block(&driver, [0x73u8; 32], 0, vec![]);
        let value_hash = block.header.value_hash;
        let original_hash = block.header.block_hash();
        let height = block.header.height;
        let original_round = block.header.proposer_round;
        driver.current_round = original_round;
        let mut actions = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: block,
        });
        actions.extend(driver.on_propose_timeout());
        assert!(actions.iter().any(
            |a| matches!(a, DriverAction::BroadcastVote(vote) if vote.step == VoteStep::Prevote)
        ));

        let remote_a_id = indra_core::types::crypto::hybrid_identity_id(
            &remote_a.public_key().classical.0,
            &remote_a.public_key().pq.0,
        );
        let remote_b_id = indra_core::types::crypto::hybrid_identity_id(
            &remote_b.public_key().classical.0,
            &remote_b.public_key().pq.0,
        );
        let prevote_a = indra_consensus::vote::produce_vote(
            height,
            original_round,
            VoteStep::Prevote,
            original_hash,
            remote_a_id,
            DEFAULT_CHAIN_ID,
            &remote_a,
        )
        .unwrap();
        let prevote_b = indra_consensus::vote::produce_vote(
            height,
            original_round,
            VoteStep::Prevote,
            original_hash,
            remote_b_id,
            DEFAULT_CHAIN_ID,
            &remote_b,
        )
        .unwrap();

        let _ = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9701".parse().unwrap(),
            vote: prevote_a,
        });
        let _ = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9702".parse().unwrap(),
            vote: prevote_b,
        });

        assert_eq!(driver.valid_round, Some(original_round));
        assert_eq!(driver.valid_value, Some(original_hash));
        let (valid_block, valid_round) = driver
            .take_valid_block_for_reproposal()
            .expect("valid block should be stored for reproposal");
        assert_eq!(valid_round, original_round);
        assert_eq!(valid_block.header.value_hash, value_hash);

        let local_vrf = VrfKeypair::from_seed(&[0x73; 32]);
        let election = (original_round.saturating_add(1)..original_round.saturating_add(4_096))
            .map(|round| election_for_round(&driver, height, round))
            .find(|election| {
                indra_consensus::proposer::compute_proposer_vrf(
                    validator_id_for(&local),
                    &local_vrf,
                    election,
                )
                .is_ok_and(|result| result.eligible)
            })
            .expect("local proposer must become eligible for a later test round");
        let reproposal_round = election.round;

        let reproposed = driver
            .engine
            .repropose(
                &valid_block,
                reproposal_round,
                Some(valid_round),
                &election,
                valid_block.header.timestamp,
                driver.last_qc_bytes(),
            )
            .expect("reproposal should succeed");

        assert_eq!(reproposed.header.value_hash, value_hash);
        assert_eq!(reproposed.header.proposer_round, reproposal_round);
        assert_eq!(reproposed.header.polc_round, original_round);

        driver.current_round = reproposal_round;
        driver.current_phase = RoundPhase::Propose;
        let reproposed_hash = reproposed.header.block_hash();
        driver.pending_blocks.insert(reproposed_hash, reproposed);
        let reproposal_actions = driver.maybe_prevote_current_round_proposal();
        assert!(reproposal_actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == reproposed_hash
        )));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn repropose_preserves_value_hash() {
        let (mut driver, dir) = local_driver([0x77u8; 32], "repropose_value_hash");
        let local = install_active_validator(&mut driver, [0x77u8; 32], "local");
        driver.refresh_registered_voters();

        let height = driver.engine.state.height + 1;
        let election_round_zero = election_for_round(&driver, height, 0);
        let proposal = driver
            .engine
            .propose(
                &election_round_zero,
                1_700_000_001,
                driver.last_qc_bytes(),
                None,
            )
            .expect("initial proposal should succeed");

        let local_validator_id = indra_core::types::crypto::hybrid_identity_id(
            &local.public_key().classical.0,
            &local.public_key().pq.0,
        );
        assert!(
            indra_consensus::proposer::compute_proposer_vrf(
                local_validator_id,
                &VrfKeypair::from_seed(&[0x77; 32]),
                &election_round_zero,
            )
            .unwrap()
            .eligible
        );
        let local_vrf = VrfKeypair::from_seed(&[0x77; 32]);
        let election_round_one = (1..4_096)
            .map(|round| election_for_round(&driver, height, round))
            .find(|election| {
                indra_consensus::proposer::compute_proposer_vrf(
                    local_validator_id,
                    &local_vrf,
                    election,
                )
                .is_ok_and(|result| result.eligible)
            })
            .expect("local proposer must become eligible for a later test round");

        let reproposed = driver
            .engine
            .repropose(
                &proposal,
                election_round_one.round,
                Some(0),
                &election_round_one,
                proposal.header.timestamp,
                driver.last_qc_bytes(),
            )
            .expect("reproposal should succeed");

        assert_eq!(proposal.header.value_hash, reproposed.header.value_hash);
        assert_ne!(proposal.header.block_hash(), reproposed.header.block_hash());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn repropose_matches_clone_based_reference() {
        let (mut driver, dir) = local_driver([0x78u8; 32], "repropose_clone_reference");
        let _local = install_active_validator(&mut driver, [0x78u8; 32], "local");
        driver.refresh_registered_voters();

        let height = driver.engine.state.height + 1;
        let election_round_zero = election_for_round(&driver, height, 0);
        let proposal = driver
            .engine
            .propose(
                &election_round_zero,
                1_700_000_001,
                driver.last_qc_bytes(),
                None,
            )
            .expect("initial proposal should succeed");

        let election_round_one = election_for_round(&driver, height, 1);
        let pre_state = driver.engine.state.clone();
        let reproposed = driver
            .engine
            .repropose(
                &proposal,
                1,
                Some(0),
                &election_round_one,
                proposal.header.timestamp,
                driver.last_qc_bytes(),
            )
            .expect("reproposal should succeed");

        let mut clone_reference = pre_state.clone();
        let snapshot = clone_reference
            .snapshot_for_consensus_height(height)
            .unwrap();
        let verified = indra_core::types::proposal::verify_proposal(
            &reproposed,
            clone_reference.chain_id.as_bytes(),
            &clone_reference.election_seed,
            snapshot,
        )
        .unwrap();
        apply_block(&mut clone_reference, &verified, 0).unwrap();
        assert_eq!(
            reproposed.header.value_hash,
            reproposed.compute_value_hash(clone_reference.total_supply)
        );
        assert_eq!(proposal.header.value_hash, reproposed.header.value_hash);
        assert_eq!(reproposed.header.proposer_round, 1);
        assert_eq!(reproposed.header.polc_round, 0);
        assert_eq!(
            driver.engine.state, pre_state,
            "reproposal projection must roll back and leave real engine state untouched"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reproposal_converges_after_disruption() {
        let (mut driver_a, dir_a) = local_driver([0x81u8; 32], "reproposal_driver_a");
        let (mut driver_b, dir_b) = local_driver([0x82u8; 32], "reproposal_driver_b");

        let a = install_active_validator(&mut driver_a, [0x81u8; 32], "A");
        let b = install_active_validator(&mut driver_a, [0x82u8; 32], "B");
        let c = install_active_validator(&mut driver_a, [0x83u8; 32], "C");
        let d = install_active_validator(&mut driver_a, [0x84u8; 32], "D");
        for (seed, name) in [
            ([0x81u8; 32], "A"),
            ([0x82u8; 32], "B"),
            ([0x83u8; 32], "C"),
            ([0x84u8; 32], "D"),
        ] {
            install_active_validator(&mut driver_b, seed, name);
        }
        // Both simulated nodes must start from byte-identical genesis state;
        // local_driver seeds each node with its own genesis UTXO, so copy the
        // consensus state after installing the shared validator set.
        driver_b.engine.state = driver_a.engine.state.clone();
        driver_a.refresh_registered_voters();
        driver_b.refresh_registered_voters();

        let a_id = indra_core::types::crypto::hybrid_identity_id(
            &a.public_key().classical.0,
            &a.public_key().pq.0,
        );
        let b_id = indra_core::types::crypto::hybrid_identity_id(
            &b.public_key().classical.0,
            &b.public_key().pq.0,
        );
        let c_id = indra_core::types::crypto::hybrid_identity_id(
            &c.public_key().classical.0,
            &c.public_key().pq.0,
        );
        let d_id = indra_core::types::crypto::hybrid_identity_id(
            &d.public_key().classical.0,
            &d.public_key().pq.0,
        );

        let a_vrf = VrfKeypair::from_seed(&[0x81; 32]);
        let election_round_zero = (0..4_096)
            .map(|round| election_for_round(&driver_a, 1, round))
            .find(|election| {
                indra_consensus::proposer::compute_proposer_vrf(a_id, &a_vrf, election)
                    .is_ok_and(|result| result.eligible)
            })
            .expect("A must become eligible in the bounded test search");
        let original_round = election_round_zero.round;
        let block_x = driver_a
            .engine
            .propose(
                &election_round_zero,
                1_700_000_100,
                driver_a.last_qc_bytes(),
                None,
            )
            .expect("A should propose its eligible round");
        let value_hash = block_x.header.value_hash;
        let block_x_hash = block_x.header.block_hash();

        driver_b.current_round = original_round;
        let mut stage_actions = driver_b.process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:9801".parse().unwrap()),
            proposal: block_x.clone(),
        });
        stage_actions.extend(driver_b.on_propose_timeout());
        assert!(stage_actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == block_x_hash
        )));

        for (peer, validator_id, signer) in [
            ("127.0.0.1:9802", a_id, &a),
            ("127.0.0.1:9803", c_id, &c),
            ("127.0.0.1:9804", d_id, &d),
        ] {
            let vote = indra_consensus::vote::produce_vote(
                1,
                original_round,
                VoteStep::Prevote,
                block_x_hash,
                validator_id,
                DEFAULT_CHAIN_ID,
                signer,
            )
            .unwrap();
            let _ = driver_b.process(DriverEvent::InboundVote {
                from: peer.parse().unwrap(),
                vote,
            });
        }

        assert_eq!(driver_b.valid_round, Some(original_round));
        assert_eq!(driver_b.valid_value, Some(block_x_hash));
        assert_eq!(
            driver_b
                .take_valid_block_for_reproposal()
                .expect("valid block should be preserved")
                .0
                .header
                .value_hash,
            value_hash
        );

        driver_b.on_precommit_timeout();
        let b_vrf = VrfKeypair::from_seed(&[0x82; 32]);
        let election_round_one = (original_round.saturating_add(1)..4_096)
            .map(|round| election_for_round(&driver_b, 1, round))
            .find(|election| {
                indra_consensus::proposer::compute_proposer_vrf(b_id, &b_vrf, election)
                    .is_ok_and(|result| result.eligible)
            })
            .expect("B must become eligible in a later bounded test round");
        let reproposal_round = election_round_one.round;
        driver_b.current_round = reproposal_round;
        driver_b.current_phase = RoundPhase::Propose;
        let (valid_block, valid_round) = driver_b
            .take_valid_block_for_reproposal()
            .expect("round 1 proposer should still have valid block");
        let block_y = driver_b
            .engine
            .repropose(
                &valid_block,
                reproposal_round,
                Some(valid_round),
                &election_round_one,
                valid_block.header.timestamp,
                driver_b.last_qc_bytes(),
            )
            .expect("B should repropose valid value at round 1");
        assert_eq!(block_y.header.value_hash, value_hash);
        let block_y_hash = block_y.header.block_hash();
        assert_ne!(block_y_hash, block_x_hash);

        let mut reproposal_actions = driver_b.process(DriverEvent::InboundBlock {
            from: None,
            proposal: block_y.clone(),
        });
        reproposal_actions.extend(driver_b.on_propose_timeout());
        assert!(reproposal_actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == block_y_hash
        )));

        for (peer, validator_id, signer) in [
            ("127.0.0.1:9811", a_id, &a),
            ("127.0.0.1:9812", c_id, &c),
            ("127.0.0.1:9813", d_id, &d),
        ] {
            let vote = indra_consensus::vote::produce_vote(
                1,
                reproposal_round,
                VoteStep::Prevote,
                block_y_hash,
                validator_id,
                DEFAULT_CHAIN_ID,
                signer,
            )
            .unwrap();
            let _ = driver_b.process(DriverEvent::InboundVote {
                from: peer.parse().unwrap(),
                vote,
            });
        }

        for (peer, validator_id, signer) in [
            ("127.0.0.1:9821", a_id, &a),
            ("127.0.0.1:9822", c_id, &c),
            ("127.0.0.1:9823", d_id, &d),
        ] {
            let vote = indra_consensus::vote::produce_vote(
                1,
                reproposal_round,
                VoteStep::Precommit,
                block_y_hash,
                validator_id,
                DEFAULT_CHAIN_ID,
                signer,
            )
            .unwrap();
            let _ = driver_b.process(DriverEvent::InboundVote {
                from: peer.parse().unwrap(),
                vote,
            });
        }

        assert_eq!(driver_b.height(), 1, "reproposal should commit the block");

        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    #[test]
    fn node_syncs_before_joining_consensus() {
        let (mut driver, dir) = local_driver([0x6Bu8; 32], "sync_before_consensus");
        let _local = install_active_validator(&mut driver, [0x6Bu8; 32], "local");
        driver.refresh_registered_voters();

        let peer: SocketAddr = "127.0.0.1:9601".parse().unwrap();
        let voter = driver.registered_voters[0].clone();
        let local_height = driver.height();
        driver.sync.peer_connected(voter.validator_id);
        let _ = driver.sync.observe_status(
            voter.validator_id,
            peer,
            10,
            Bytes32::ZERO,
            voter.stake,
            voter.stake,
            local_height,
            Instant::now(),
        );
        assert!(!driver.sync.is_caught_up());

        let block = make_block(&driver.engine.state);
        let hash = block.header.block_hash();
        driver.pending_blocks.insert(hash, block);

        let actions = driver.maybe_prevote_current_round_proposal();
        assert!(actions.is_empty(), "syncing nodes must not join consensus");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn consensus_gate_blocks_votes_during_sync() {
        let (mut driver, dir) = local_driver([0x6Cu8; 32], "sync_vote_gate");
        let _local = install_active_validator(&mut driver, [0x6Cu8; 32], "local");
        let remote = install_active_validator(&mut driver, [0x6Du8; 32], "remote");
        driver.refresh_registered_voters();

        let peer: SocketAddr = "127.0.0.1:9602".parse().unwrap();
        let voter = driver.registered_voters[0].clone();
        let local_height = driver.height();
        driver.sync.peer_connected(voter.validator_id);
        let _ = driver.sync.observe_status(
            voter.validator_id,
            peer,
            10,
            Bytes32::ZERO,
            voter.stake,
            voter.stake,
            local_height,
            Instant::now(),
        );
        assert!(!driver.sync.is_caught_up());

        let remote_id = indra_core::types::crypto::hybrid_identity_id(
            &remote.public_key().classical.0,
            &remote.public_key().pq.0,
        );
        let vote = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Prevote,
            Bytes32::from([0xABu8; 32]),
            remote_id,
            DEFAULT_CHAIN_ID,
            &remote,
        )
        .unwrap();

        let actions = driver.process(DriverEvent::InboundVote { from: peer, vote });
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, DriverAction::BroadcastVote(_))),
            "syncing nodes must not emit votes"
        );
        let collector = driver
            .vote_collectors
            .get(&(1, 0, VoteStep::Prevote))
            .expect("vote should be recorded while syncing");
        assert_eq!(collector.vote_count(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
