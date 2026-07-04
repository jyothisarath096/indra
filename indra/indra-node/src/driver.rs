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
    proposer::{
        compute_fallback_election_result, compute_proposer_vrf, compute_vrf_input,
        elect_proposer_from_reveals, ProposerCandidate, ProposerElection,
    },
    verify_qc,
    vote::{RegisteredVoter, VoteCollector, VoteDecision},
};
use indra_core::codec::{ByteReader, Decode, Encode};
use indra_core::types::{
    block::{BlockV1, NO_POLC_ROUND},
    crypto::HybridSignature,
    primitives::{
        bps_of, reveal_set_commitment_active, vrf_commit_reveal_election_active, Bytes32,
        VariableBytes, CONSENSUS_QUORUM_BPS, MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES,
        MAX_VRF_EMPTY_REVEAL_ROUNDS, MAX_VRF_ROUND_ENTRIES, VRF_COMMIT_WINDOW_MS,
        VRF_ELECTION_SETTLE_MS, VRF_REVEAL_WINDOW_MS,
    },
    qc::QuorumCertificateV1,
    transaction::TransactionV1,
    vote::{VoteStep, VoteV1},
    vrf_election::{
        chain_id_hash, compute_reveal_set_commitment, compute_vrf_commit_hash,
        reveal_evidence_from_reveals, VrfCommit, VrfElectionResult, VrfReveal, VrfRevealEvidence,
    },
};
use indra_crypto::{
    hybrid::{verify_hybrid, ClassicalPublicKey, HybridPublicKey, PqPublicKey},
    vrf_verify, VrfOutput, VrfProof,
};
use indra_storage::{VoteSafetyLoadResult, VoteSafetyStore};

use crate::{
    engine::NodeEngine,
    error::{NodeError, NodeResult},
    slash::{SlashDetector, SlashEvidence},
    sync::{verify_block_qc, verify_proposer_vrf, verify_reveal_set_evidence, SyncState},
};

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// Maximum round jump accepted from a single peer Status message in one step.
///
/// A single faulty/runaway peer must not be able to teleport the whole
/// network's round counter to an arbitrary value. Larger legitimate gaps can
/// still be caught up gradually across repeated Status messages.
///
/// Multi-peer corroboration is intentionally deferred: on the 4-validator
/// testnet, requiring multiple matching statuses before any jump could stall
/// a partially connected but otherwise recoverable node.
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
const ACTION_RETRY_DEBOUNCE_MS: u64 = 1_000;

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

/// Commit-reveal VRF phase for one height/round election.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VrfRoundPhase {
    /// Collecting hidden VRF commitments.
    Commit,
    /// Collecting VRF reveals whose commitments were observed.
    Reveal,
    /// Election result computed.
    Complete,
    /// Public deterministic fallback result computed.
    Fallback,
}

/// Ephemeral commit-reveal state for one election round.
#[derive(Debug, Clone)]
pub struct VrfRoundState {
    /// Election height.
    pub height: u64,
    /// Election round.
    pub round: u32,
    /// Current VRF phase.
    pub phase: VrfRoundPhase,
    /// Commit window start time.
    pub commit_started_at: Instant,
    /// Reveal window start time.
    pub reveal_started_at: Option<Instant>,
    /// validator_id → signed commit.
    pub commits: BTreeMap<Bytes32, VrfCommit>,
    /// validator_id → signed reveal.
    pub reveals: BTreeMap<Bytes32, VrfReveal>,
    /// Reveals received before their matching commit.
    pub pending_reveals: BTreeMap<Bytes32, VrfReveal>,
    /// Deterministic result after reveal window closes.
    pub election_result: Option<VrfElectionResult>,
}

impl VrfRoundState {
    fn new(height: u64, round: u32) -> Self {
        Self {
            height,
            round,
            phase: VrfRoundPhase::Commit,
            commit_started_at: Instant::now(),
            reveal_started_at: None,
            commits: BTreeMap::new(),
            reveals: BTreeMap::new(),
            pending_reveals: BTreeMap::new(),
            election_result: None,
        }
    }
}

#[derive(Debug, Clone)]
struct LocalVrfRoundState {
    vrf_output: Bytes32,
    vrf_proof: Vec<u8>,
}

/// An inbound event for the driver to process.
#[derive(Debug)]
pub enum DriverEvent {
    /// A block arrived from a peer or was proposed locally.
    InboundBlock {
        /// The sender, or `None` when proposed locally.
        from: Option<SocketAddr>,
        /// The proposed block.
        block: BlockV1,
    },
    /// A consensus vote arrived from a peer.
    InboundVote {
        /// The sender.
        from: SocketAddr,
        /// The vote payload.
        vote: VoteV1,
    },
    /// A new transaction arrived from a peer.
    InboundTx {
        /// The sender.
        from: SocketAddr,
        /// The encoded transaction bytes.
        tx_bytes: Vec<u8>,
    },
    /// A peer announced its chain status.
    PeerStatus {
        /// The peer.
        from: SocketAddr,
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
    /// A peer is requesting signed VRF reveals for proposal verification.
    VrfRevealsRequest {
        /// The requesting peer.
        from: SocketAddr,
        /// Election height.
        height: u64,
        /// Election round.
        round: u32,
        /// Validator IDs whose reveals are requested.
        missing_validator_ids: Vec<Bytes32>,
    },
    /// A peer responded with signed VRF reveals.
    VrfRevealsResponse {
        /// The sender.
        from: SocketAddr,
        /// Election height.
        height: u64,
        /// Election round.
        round: u32,
        /// Signed reveals.
        reveals: Vec<VrfReveal>,
    },
    /// A validator sent a VRF commit.
    InboundVrfCommit {
        /// The sender.
        from: SocketAddr,
        /// Commit payload.
        commit: VrfCommit,
    },
    /// A validator sent a VRF reveal.
    InboundVrfReveal {
        /// The sender.
        from: SocketAddr,
        /// Reveal payload.
        reveal: VrfReveal,
    },
}

/// An action the driver wants to perform in response to an event.
#[derive(Debug)]
pub enum DriverAction {
    /// Broadcast this block to peers.
    BroadcastBlock(BlockV1),
    /// Broadcast this vote to peers.
    BroadcastVote(VoteV1),
    /// Broadcast this transaction to peers.
    BroadcastTx(TransactionV1),
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
    /// Ask peers for signed VRF reveals needed to verify a proposal.
    RequestVrfReveals {
        /// Election height.
        height: u64,
        /// Election round.
        round: u32,
        /// Validator IDs whose signed reveals are missing locally.
        missing_validator_ids: Vec<Bytes32>,
    },
    /// Send signed VRF reveals directly to one peer.
    SendVrfRevealsResponse {
        /// The peer to answer.
        to: SocketAddr,
        /// Election height.
        height: u64,
        /// Election round.
        round: u32,
        /// Signed reveals.
        reveals: Vec<VrfReveal>,
    },
    /// Broadcast a VRF commit.
    BroadcastVrfCommit(VrfCommit),
    /// Broadcast a VRF reveal.
    BroadcastVrfReveal(VrfReveal),
    /// Re-process a buffered future proposal after the local tip advances.
    ActivateBufferedProposal(BlockV1),
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
    /// Pending blocks by block hash.
    pending_blocks: HashMap<Bytes32, BlockV1>,
    /// Proposals buffered because they arrived before their parent tip was committed locally.
    future_proposals: HashMap<(u64, Bytes32), Vec<BlockV1>>,
    /// Votes received before the matching proposal was staged locally.
    buffered_votes: HashMap<(u64, u32, Bytes32), Vec<(SocketAddr, VoteV1)>>,
    /// Missing proposals already requested from peers.
    requested_proposals: HashSet<(u64, u32, Bytes32)>,
    /// First accepted vote hash per (validator, height, round, step).
    seen_round_votes: HashMap<(Bytes32, u64, u32, VoteStep), Bytes32>,
    /// Blocks whose precommit quorum arrived before the proposal was staged.
    pending_precommit_quorum: HashSet<(u64, u32, Bytes32)>,
    /// Proposals waiting on signed VRF reveal gossip before prevote.
    pending_reveal_blocks: HashMap<(u64, u32, Bytes32), BlockV1>,
    /// Recent VRF reveal recovery requests keyed by exact missing set.
    requested_vrf_reveals: HashMap<(u64, u32, Vec<Bytes32>), Instant>,
    /// Tendermint lock state for the current height.
    locked_round: Option<u32>,
    /// Full block hash this validator is locked on.
    locked_value: Option<Bytes32>,
    /// Stable value hash corresponding to `locked_value`, used only for POLC
    /// same-value checks across reproposals with different full hashes.
    locked_value_hash: Option<Bytes32>,
    /// Tendermint valid value / valid round for reproposal.
    valid_round: Option<u32>,
    /// Full block hash that reached prevote quorum.
    valid_value: Option<Bytes32>,
    valid_block: Option<BlockV1>,
    /// Serialised QC for the most recently finalised height.
    last_qc_bytes: Vec<u8>,
    /// Registered voters for the current epoch.
    registered_voters: Vec<RegisteredVoter>,
    /// Current consensus round for the next block height.
    current_round: u32,
    /// Current Tendermint phase within the round.
    current_phase: RoundPhase,
    /// When the current precommit phase started.
    ///
    /// Used to give the commit-reveal VRF election result a short settle
    /// window before falling back to nil precommit.
    precommit_phase_started_at: Option<Instant>,
    /// Synchronization phase for this node.
    sync: SyncState,
    /// Persisted local vote safety guard.
    pub vote_safety: VoteSafetyStore,
    /// If set, local voting is disabled until operator recovery.
    vote_safety_unavailable: Option<String>,
    /// Current and next-round commit-reveal VRF election states.
    vrf_states: [Option<VrfRoundState>; 2],
    /// Locally computed VRF outputs retained until reveal.
    local_vrf_rounds: BTreeMap<(u64, u32), LocalVrfRoundState>,
    /// Consecutive empty-reveal rounds at the current height.
    consecutive_empty_reveal_rounds: u32,
    /// Highest block height for which this driver has already pipelined its
    /// local round-0 VRF commit.
    highest_pipelined_vrf_commit_height: u64,
}

impl ConsensusDriver {
    /// Create a new driver from a node engine.
    pub fn new(engine: NodeEngine, vote_safety: VoteSafetyStore) -> Self {
        let mut driver = Self {
            engine,
            slash_detector: SlashDetector::new(),
            vote_collectors: HashMap::new(),
            pending_blocks: HashMap::new(),
            future_proposals: HashMap::new(),
            buffered_votes: HashMap::new(),
            requested_proposals: HashSet::new(),
            seen_round_votes: HashMap::new(),
            pending_precommit_quorum: HashSet::new(),
            pending_reveal_blocks: HashMap::new(),
            requested_vrf_reveals: HashMap::new(),
            locked_round: None,
            locked_value: None,
            locked_value_hash: None,
            valid_round: None,
            valid_value: None,
            valid_block: None,
            last_qc_bytes: Vec::new(),
            registered_voters: Vec::new(),
            current_round: 0,
            current_phase: RoundPhase::Propose,
            precommit_phase_started_at: None,
            sync: SyncState::follower(0),
            vote_safety,
            vote_safety_unavailable: None,
            vrf_states: [None, None],
            local_vrf_rounds: BTreeMap::new(),
            consecutive_empty_reveal_rounds: 0,
            highest_pipelined_vrf_commit_height: 0,
        };
        driver.highest_pipelined_vrf_commit_height = driver.engine.state.height;
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
            match driver.engine.load_persisted_qc() {
                Ok(Some(qc_bytes)) if !qc_bytes.is_empty() => {
                    match QuorumCertificateV1::decode_exact(&qc_bytes) {
                        Ok(qc) if qc.height == driver.engine.state.height => {
                            eprintln!(
                                "[driver] restored last_qc_bytes ({} bytes) for height {}",
                                qc_bytes.len(),
                                qc.height,
                            );
                            driver.last_qc_bytes = qc_bytes;
                        }
                        Ok(qc) => {
                            eprintln!(
                                "[driver] WARNING: persisted QC height {} does not match current state height {} — discarding and requesting from peers",
                                qc.height,
                                driver.engine.state.height,
                            );
                        }
                        Err(err) => {
                            eprintln!(
                                "[driver] WARNING: persisted QC at height {} is not decodable by this binary: {} — discarding and requesting from peers",
                                driver.engine.state.height,
                                err,
                            );
                        }
                    }
                }
                Ok(Some(_)) | Ok(None) => {
                    eprintln!(
                        "[driver] WARNING: no persisted QC found at height {} — node will not propose until another validator proposes first",
                        driver.engine.state.height,
                    );
                }
                Err(e) => {
                    eprintln!(
                        "[driver] WARNING: failed to load persisted QC: {e} — node will not propose until another validator proposes first"
                    );
                }
            }
        }
        driver.refresh_registered_voters();
        driver
    }

    /// Replace the registered voter set for the current epoch.
    pub fn set_voters(&mut self, voters: Vec<RegisteredVoter>) {
        self.vote_collectors.clear();
        self.registered_voters = voters;
    }

    /// Refresh the registered voter set from the engine state.
    pub fn refresh_registered_voters(&mut self) {
        self.set_voters(self.engine.registered_voters());
    }

    /// Return the serialised QC to place in the next proposal header.
    pub fn last_qc_bytes(&self) -> Vec<u8> {
        self.last_qc_bytes.clone()
    }

    /// Return the height certified by the cached QC, if it is present and decodable.
    pub fn last_qc_height(&self) -> Option<u64> {
        Self::decode_qc_height(&self.last_qc_bytes)
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
                let validators = self.engine.qc_validators();
                let total_stake = self.engine.state.validators.total_active_stake();
                verify_qc(&qc, &validators, total_stake, &self.engine.state.chain_id).map_err(
                    |err| NodeError::BlockInvalid {
                        height,
                        reason: format!(
                            "last_qc_bytes from {source} failed QC verification: {err}"
                        ),
                    },
                )?;

                let current_digest = Self::qc_bytes_digest(&self.last_qc_bytes);
                let incoming_digest = Self::qc_bytes_digest(&qc_bytes);
                if current_qc.round == qc.round
                    && current_qc.block_hash == qc.block_hash
                    && current_qc.election_result_hash == qc.election_result_hash
                {
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
    pub fn promote_block_header_qc(&mut self, block: &BlockV1, source: &str) -> NodeResult<()> {
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

    /// Clear cached QC bytes when they no longer certify the local tip.
    pub fn clear_last_qc_if_stale(&mut self) -> bool {
        if self.last_qc_is_stale() {
            self.clear_last_qc_bytes();
            true
        } else {
            false
        }
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

    /// External compatibility hook used by the node loop.
    pub fn advance_round(&mut self) {
        self.prune_future_proposals();
        self.start_round(self.current_round.saturating_add(1));
    }

    /// External compatibility hook used after height advancement.
    pub fn reset_round(&mut self) {
        self.prune_future_proposals();
        self.valid_block = None;
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
        self.requested_vrf_reveals.clear();
        self.vote_collectors.clear();
        self.seen_round_votes.clear();
        self.vrf_states = [None, None];
        self.local_vrf_rounds.clear();
        self.consecutive_empty_reveal_rounds = 0;
        self.highest_pipelined_vrf_commit_height = self.engine.state.height;
        self.locked_round = None;
        self.locked_value = None;
        self.locked_value_hash = None;
        self.valid_round = None;
        self.valid_value = None;
        self.valid_block = None;
        self.start_round(0);
        self.apply_vote_safety();
    }

    /// Process one inbound event and return the resulting driver actions.
    pub fn process(&mut self, event: DriverEvent) -> Vec<DriverAction> {
        match event {
            DriverEvent::InboundBlock { from, block } => self.process_block(from, block),
            DriverEvent::InboundVote { from, vote } => self.process_vote(from, vote),
            DriverEvent::InboundTx { from, tx_bytes } => self.process_tx(from, tx_bytes),
            DriverEvent::PeerStatus {
                from,
                height,
                tip_hash,
                round,
            } => self.process_status(from, height, tip_hash, round),
            DriverEvent::QcResponse {
                from,
                height,
                qc_bytes,
            } => self.handle_qc_response(from, height, qc_bytes),
            DriverEvent::QcRequest { from, height } => self.handle_qc_request(from, height),
            DriverEvent::VrfRevealsRequest {
                from,
                height,
                round,
                missing_validator_ids,
            } => self.handle_vrf_reveals_request(from, height, round, missing_validator_ids),
            DriverEvent::VrfRevealsResponse {
                from,
                height,
                round,
                reveals,
            } => self.handle_vrf_reveals_response(from, height, round, reveals),
            DriverEvent::InboundVrfCommit { from, commit } => self.process_vrf_commit(from, commit),
            DriverEvent::InboundVrfReveal { from, reveal } => self.process_vrf_reveal(from, reveal),
        }
    }

    fn collector_key(height: u64, round: u32, step: VoteStep) -> (u64, u32, VoteStep) {
        (height, round, step)
    }

    fn start_round(&mut self, round: u32) {
        self.current_round = round;
        self.current_phase = RoundPhase::Propose;
        self.precommit_phase_started_at = None;
        let height = self.next_height();
        self.requested_vrf_reveals
            .retain(|(h, r, _), _| *h == height && *r >= round);
        if vrf_commit_reveal_election_active(height) {
            let next = self
                .vrf_states
                .iter()
                .filter_map(|state| state.as_ref())
                .filter(|state| state.height == height && state.round == round)
                .next()
                .cloned();
            self.vrf_states[0] = next.or_else(|| Some(VrfRoundState::new(height, round)));
            self.vrf_states[1] = Some(VrfRoundState::new(height, round.saturating_add(1)));
            self.local_vrf_rounds
                .retain(|(h, r), _| *h == height && (*r == round || *r == round.saturating_add(1)));
        } else {
            self.vrf_states = [None, None];
            self.local_vrf_rounds.clear();
        }
    }

    fn enter_precommit_phase(&mut self) {
        if self.current_phase != RoundPhase::Precommit {
            self.precommit_phase_started_at = Some(Instant::now());
        }
        self.current_phase = RoundPhase::Precommit;
    }

    fn vrf_slot_index(&self, height: u64, round: u32) -> Option<usize> {
        self.vrf_states.iter().position(|state| {
            state
                .as_ref()
                .is_some_and(|s| s.height == height && s.round == round)
        })
    }

    fn active_vrf_candidates(&self, height: u64, round: u32) -> ProposerElection {
        let epoch_seed = Bytes32::from(indra_crypto::sha256(&self.engine.state.tip_hash.0));
        let candidates = self
            .engine
            .state
            .validators
            .active_validators()
            .filter_map(|validator| {
                validator.vrf_pk.map(|vrf_pubkey| ProposerCandidate {
                    validator_id: validator.validator_id,
                    vrf_pubkey,
                    verified_vrf_output: None,
                    stake: validator.stake_spark,
                })
            })
            .collect();
        ProposerElection {
            epoch_seed,
            height,
            round,
            candidates,
        }
    }

    fn vrf_input_for(&self, height: u64, round: u32) -> [u8; 32] {
        let epoch_seed = Bytes32::from(indra_crypto::sha256(&self.engine.state.tip_hash.0));
        compute_vrf_input(&epoch_seed.0, height, round)
    }

    fn total_active_stake(&self) -> u64 {
        self.engine
            .state
            .validators
            .active_validators()
            .map(|validator| validator.stake_spark)
            .fold(0u64, |a, b| a.saturating_add(b))
    }

    fn revealed_stake(&self, state: &VrfRoundState) -> u64 {
        state
            .reveals
            .keys()
            .filter_map(|id| self.engine.state.validators.get(id))
            .map(|validator| validator.stake_spark)
            .fold(0u64, |a, b| a.saturating_add(b))
    }

    fn quorum_stake_reached(&self, stake: u64) -> bool {
        let total = self.total_active_stake();
        total > 0 && stake >= bps_of(total, CONSENSUS_QUORUM_BPS)
    }

    fn missing_reveal_validator_ids(&self, state: &VrfRoundState) -> Vec<Bytes32> {
        self.engine
            .state
            .validators
            .active_validators()
            .filter(|validator| validator.vrf_pk.is_some())
            .filter_map(|validator| {
                (!state.reveals.contains_key(&validator.validator_id))
                    .then_some(validator.validator_id)
            })
            .collect()
    }

    fn should_emit_vrf_reveal_request(
        &mut self,
        height: u64,
        round: u32,
        missing_validator_ids: &[Bytes32],
    ) -> bool {
        let key = (height, round, missing_validator_ids.to_vec());
        let now = Instant::now();
        if self
            .requested_vrf_reveals
            .get(&key)
            .is_some_and(|last| last.elapsed().as_millis() < ACTION_RETRY_DEBOUNCE_MS as u128)
        {
            return false;
        }
        self.requested_vrf_reveals.insert(key, now);
        true
    }

    fn request_missing_reveals_for_slot(&mut self, slot: usize) -> Vec<DriverAction> {
        let Some(state) = self.vrf_states.get(slot).and_then(|state| state.as_ref()) else {
            return vec![];
        };
        if !reveal_set_commitment_active(state.height)
            || self.quorum_stake_reached(self.revealed_stake(state))
        {
            return vec![];
        }

        let height = state.height;
        let round = state.round;
        let mut missing_validator_ids = self.missing_reveal_validator_ids(state);
        missing_validator_ids.sort_by_key(|id| id.0);
        if missing_validator_ids.is_empty() {
            return vec![];
        }
        if !self.should_emit_vrf_reveal_request(height, round, &missing_validator_ids) {
            return vec![];
        }

        eprintln!(
            "[vrf] local reveal set below quorum for height={} round={} — requesting {} missing reveal(s)",
            height,
            round,
            missing_validator_ids.len(),
        );
        vec![DriverAction::RequestVrfReveals {
            height,
            round,
            missing_validator_ids,
        }]
    }

    fn empty_signature() -> Option<HybridSignature> {
        Some(HybridSignature {
            classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(&[]).ok()?,
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&[]).ok()?,
        })
    }

    fn convert_signature(sig: indra_crypto::HybridSignature) -> Option<HybridSignature> {
        Some(HybridSignature {
            classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(&sig.classical.0)
                .ok()?,
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&sig.pq.0).ok()?,
        })
    }

    fn validator_hybrid_public_key(&self, validator_id: &Bytes32) -> Option<HybridPublicKey> {
        let validator = self.engine.state.validators.get(validator_id)?;
        let classical = validator.hybrid_classical_pk?;
        let pq_vec = validator.hybrid_pq_pk.as_ref()?;
        let pq: [u8; indra_crypto::PQ_PK_BYTES] = pq_vec.as_slice().try_into().ok()?;
        Some(HybridPublicKey {
            classical: ClassicalPublicKey(classical),
            pq: PqPublicKey(pq),
        })
    }

    fn validator_vrf_pk_matches(&self, validator_id: &Bytes32, vrf_pubkey: &[u8; 32]) -> bool {
        self.engine
            .state
            .validators
            .get(validator_id)
            .and_then(|validator| validator.vrf_pk)
            .is_some_and(|registered| registered == *vrf_pubkey)
            && self
                .engine
                .state
                .validators
                .active_validators()
                .any(|validator| validator.validator_id == *validator_id)
    }

    fn verify_commit_signature(&self, commit: &VrfCommit) -> bool {
        let Some(pk) = self.validator_hybrid_public_key(&commit.validator_id) else {
            return false;
        };
        let Ok(sig) = commit.signature.to_crypto_sig() else {
            return false;
        };
        verify_hybrid(&commit.signing_bytes(), &sig, &pk).is_ok()
    }

    fn verify_reveal_signature(&self, reveal: &VrfReveal) -> bool {
        let Some(pk) = self.validator_hybrid_public_key(&reveal.validator_id) else {
            return false;
        };
        let Ok(sig) = reveal.signature.to_crypto_sig() else {
            return false;
        };
        verify_hybrid(&reveal.signing_bytes(), &sig, &pk).is_ok()
    }

    fn make_local_vrf_commit(&mut self, height: u64, round: u32) -> Option<VrfCommit> {
        if self.local_vrf_rounds.contains_key(&(height, round)) {
            return None;
        }
        let validator_id = self.engine.validator_id()?;
        let vrf_keypair = self.engine.local_vrf_keypair()?;
        let hybrid_keypair = self.engine.local_hybrid_keypair()?;
        let vrf_pubkey = vrf_keypair.public_key();
        let election = self.active_vrf_candidates(height, round);
        if !election.candidates.iter().any(|candidate| {
            candidate.validator_id == validator_id && candidate.vrf_pubkey == vrf_pubkey
        }) {
            return None;
        }
        let slot = compute_proposer_vrf(
            validator_id,
            vrf_keypair,
            &election.epoch_seed,
            height,
            round,
        );
        let vrf_output = Bytes32::from(slot.vrf_output.0);
        let vrf_proof = slot.vrf_proof.0.clone();
        let chain_id_hash = chain_id_hash(&self.engine.state.chain_id);
        let commit_hash = compute_vrf_commit_hash(
            &chain_id_hash,
            height,
            round,
            &validator_id,
            &vrf_pubkey,
            &slot.vrf_input,
            &vrf_output,
            &vrf_proof,
        );
        let mut commit = VrfCommit {
            chain_id_hash,
            height,
            round,
            validator_id,
            vrf_pubkey,
            commit_hash,
            signature: Self::empty_signature()?,
        };
        let sig = hybrid_keypair.sign(&commit.signing_bytes()).ok()?;
        commit.signature = Self::convert_signature(sig)?;
        self.local_vrf_rounds.insert(
            (height, round),
            LocalVrfRoundState {
                vrf_output,
                vrf_proof,
            },
        );
        Some(commit)
    }

    fn make_local_vrf_reveal(&self, height: u64, round: u32) -> Option<VrfReveal> {
        let validator_id = self.engine.validator_id()?;
        let hybrid_keypair = self.engine.local_hybrid_keypair()?;
        let local = self.local_vrf_rounds.get(&(height, round))?;
        let slot_index = self.vrf_slot_index(height, round)?;
        let state = self.vrf_states[slot_index].as_ref()?;
        let commit = state.commits.get(&validator_id)?;
        let mut reveal = VrfReveal {
            chain_id_hash: commit.chain_id_hash,
            height,
            round,
            validator_id,
            vrf_pubkey: commit.vrf_pubkey,
            vrf_output: local.vrf_output,
            vrf_proof: VariableBytes::from_slice(&local.vrf_proof).ok()?,
            commit_hash: commit.commit_hash,
            signature: Self::empty_signature()?,
        };
        let sig = hybrid_keypair.sign(&reveal.signing_bytes()).ok()?;
        reveal.signature = Self::convert_signature(sig)?;
        Some(reveal)
    }

    fn validate_vrf_reveal(&self, reveal: &VrfReveal) -> bool {
        if reveal.chain_id_hash != chain_id_hash(&self.engine.state.chain_id)
            || !self.validator_vrf_pk_matches(&reveal.validator_id, &reveal.vrf_pubkey)
            || !self.verify_reveal_signature(reveal)
        {
            return false;
        }
        let vrf_input = self.vrf_input_for(reveal.height, reveal.round);
        let proof = VrfProof(reveal.vrf_proof.as_slice().to_vec());
        if vrf_verify(
            &reveal.vrf_pubkey,
            &vrf_input,
            &VrfOutput(reveal.vrf_output.0),
            &proof,
        )
        .is_err()
        {
            return false;
        }
        let expected = compute_vrf_commit_hash(
            &reveal.chain_id_hash,
            reveal.height,
            reveal.round,
            &reveal.validator_id,
            &reveal.vrf_pubkey,
            &vrf_input,
            &reveal.vrf_output,
            reveal.vrf_proof.as_slice(),
        );
        expected == reveal.commit_hash
    }

    /// Ensure local commit/reveal state exists for a round and drive timeouts.
    pub fn ensure_vrf_election_for_round(
        &mut self,
        election: &ProposerElection,
    ) -> Vec<DriverAction> {
        if !vrf_commit_reveal_election_active(election.height) {
            return vec![];
        }
        if self
            .vrf_slot_index(election.height, election.round)
            .is_none()
        {
            self.vrf_states[0] = Some(VrfRoundState::new(election.height, election.round));
        }
        let mut actions = Vec::new();
        if let Some(commit) = self.make_local_vrf_commit(election.height, election.round) {
            let validator_id = commit.validator_id;
            if let Some(slot) = self.vrf_slot_index(election.height, election.round) {
                if let Some(state) = self.vrf_states[slot].as_mut() {
                    state.commits.insert(validator_id, commit.clone());
                }
            }
            actions.push(DriverAction::BroadcastVrfCommit(commit));
        }
        actions.extend(self.advance_vrf_round(election.height, election.round));
        actions
    }

    /// Start the next height's round-0 VRF commit immediately after the
    /// parent block has been finalized and applied.
    ///
    /// This is intentionally finalization-driven, not round-loop driven:
    /// once height N commits, `state.tip_hash` is the immutable seed source
    /// for height N+1, so there is no reason to wait for the next node-loop
    /// propose tick before broadcasting our round-0 commit.
    fn pipeline_next_height_vrf_commit_after_finalization(&mut self) -> Vec<DriverAction> {
        let height = self.next_height();
        let round = 0;
        if !vrf_commit_reveal_election_active(height)
            || height <= self.highest_pipelined_vrf_commit_height
        {
            return vec![];
        }

        if self.vrf_slot_index(height, round).is_none() {
            self.vrf_states[0] = Some(VrfRoundState::new(height, round));
        }

        let mut actions = Vec::new();
        if let Some(commit) = self.make_local_vrf_commit(height, round) {
            let validator_id = commit.validator_id;
            if let Some(slot) = self.vrf_slot_index(height, round) {
                if let Some(state) = self.vrf_states[slot].as_mut() {
                    state.commits.insert(validator_id, commit.clone());
                }
            }
            self.highest_pipelined_vrf_commit_height = height;
            actions.push(DriverAction::BroadcastVrfCommit(commit));
        }
        actions
    }

    fn advance_vrf_round(&mut self, height: u64, round: u32) -> Vec<DriverAction> {
        let mut actions = Vec::new();
        let Some(slot) = self.vrf_slot_index(height, round) else {
            return actions;
        };
        let open_reveal = self
            .vrf_states
            .get(slot)
            .and_then(|state| state.as_ref())
            .is_some_and(|state| {
                state.phase == VrfRoundPhase::Commit
                    && (self.quorum_stake_reached(
                        state
                            .commits
                            .keys()
                            .filter_map(|id| self.engine.state.validators.get(id))
                            .map(|validator| validator.stake_spark)
                            .fold(0u64, |a, b| a.saturating_add(b)),
                    ) || state.commit_started_at.elapsed().as_millis()
                        >= VRF_COMMIT_WINDOW_MS as u128)
            });
        if open_reveal {
            if let Some(state) = self.vrf_states[slot].as_mut() {
                state.phase = VrfRoundPhase::Reveal;
                state.reveal_started_at = Some(Instant::now());
            }
            if let Some(reveal) = self.make_local_vrf_reveal(height, round) {
                actions.extend(self.insert_valid_vrf_reveal(slot, reveal, true, None));
            }
        }

        let should_compute = self
            .vrf_states
            .get(slot)
            .and_then(|state| state.as_ref())
            .is_some_and(|state| {
                state.election_result.is_none()
                    && state.phase == VrfRoundPhase::Reveal
                    && (self.quorum_stake_reached(self.revealed_stake(state))
                        || state.reveal_started_at.is_some_and(|t| {
                            t.elapsed().as_millis() >= VRF_REVEAL_WINDOW_MS as u128
                        }))
            });
        if should_compute {
            if let Some(result) = self.compute_and_store_vrf_election(slot) {
                if result.height == self.next_height()
                    && result.round == self.current_round
                    && self.current_phase == RoundPhase::Precommit
                    && self.engine.validator_id().is_some_and(|local_id| {
                        !self.collector_has_vote_from(
                            result.height,
                            result.round,
                            VoteStep::Precommit,
                            local_id,
                        )
                    })
                {
                    actions.extend(self.maybe_precommit_current_round_proposal());
                }
            } else {
                actions.extend(self.request_missing_reveals_for_slot(slot));
            }
        }
        actions
    }

    fn compute_and_store_vrf_election(&mut self, slot: usize) -> Option<VrfElectionResult> {
        let Some(state) = self.vrf_states.get(slot).and_then(|state| state.as_ref()) else {
            return None;
        };
        let state_height = state.height;
        let state_round = state.round;
        let election = self.active_vrf_candidates(state.height, state.round);
        let revealed: BTreeMap<Bytes32, Bytes32> = state
            .reveals
            .iter()
            .map(|(id, reveal)| (*id, reveal.vrf_output))
            .collect();
        if reveal_set_commitment_active(state_height) {
            let revealed_stake = self.revealed_stake(state);
            if !self.quorum_stake_reached(revealed_stake) {
                eprintln!(
                    "[vrf] election pending for height={} round={}: reveal set below quorum (revealed_stake={} total_stake={} quorum_bps={})",
                    state_height,
                    state_round,
                    revealed_stake,
                    self.total_active_stake(),
                    CONSENSUS_QUORUM_BPS,
                );
                return None;
            }
        }
        if revealed.is_empty() {
            self.consecutive_empty_reveal_rounds =
                self.consecutive_empty_reveal_rounds.saturating_add(1);
            if self.consecutive_empty_reveal_rounds < MAX_VRF_EMPTY_REVEAL_ROUNDS {
                if let Some(state) = self.vrf_states[slot].as_mut() {
                    state.phase = VrfRoundPhase::Complete;
                }
                eprintln!(
                    "[vrf] no reveals for height={} round={} (empty rounds {}/{}) — no fallback yet",
                    state_height,
                    state_round,
                    self.consecutive_empty_reveal_rounds,
                    MAX_VRF_EMPTY_REVEAL_ROUNDS,
                );
                return None;
            }
            let result = compute_fallback_election_result(&election);
            let Ok(mut result) = result else {
                return None;
            };
            if reveal_set_commitment_active(state_height) {
                result.reveal_set_commitment = compute_reveal_set_commitment(&[]);
            }
            if let Some(state) = self.vrf_states[slot].as_mut() {
                state.phase = VrfRoundPhase::Fallback;
                state.election_result = Some(result);
            }
            eprintln!(
                "[vrf] election result computed for height={} round={}: elected={} fallback={}",
                result.height,
                result.round,
                hex::encode(&result.elected_validator_id.0[..4]),
                result.fallback_used,
            );
            return Some(result);
        }
        let result = elect_proposer_from_reveals(&election, &revealed);
        let Ok(mut result) = result else {
            return None;
        };
        if reveal_set_commitment_active(state_height) {
            let evidence = self
                .vrf_states
                .get(slot)
                .and_then(|state| state.as_ref())
                .map(|state| reveal_evidence_from_reveals(state.reveals.values().cloned()))
                .unwrap_or_default();
            result.reveal_set_commitment = compute_reveal_set_commitment(&evidence);
        }
        if let Some(state) = self.vrf_states[slot].as_mut() {
            self.consecutive_empty_reveal_rounds = 0;
            state.phase = VrfRoundPhase::Complete;
            state.election_result = Some(result);
        }
        eprintln!(
            "[vrf] election result computed for height={} round={}: elected={} fallback={}",
            result.height,
            result.round,
            hex::encode(&result.elected_validator_id.0[..4]),
            result.fallback_used,
        );
        Some(result)
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
    ///
    /// The commit-reveal election result may arrive shortly after a fast
    /// prevote quorum enters precommit. The node loop calls this during the
    /// precommit phase so the driver can either sign the block precommit as
    /// soon as the result is available, or nil-precommit after the settle
    /// window expires.
    pub fn retry_precommit_if_waiting(&mut self) -> Vec<DriverAction> {
        self.maybe_precommit_current_round_proposal()
    }

    fn insert_valid_vrf_reveal(
        &mut self,
        slot: usize,
        reveal: VrfReveal,
        gossip: bool,
        invalid_from: Option<SocketAddr>,
    ) -> Vec<DriverAction> {
        let mut actions = Vec::new();
        let (height, round) = {
            let Some(state) = self.vrf_states[slot].as_mut() else {
                return actions;
            };
            // Cheap duplicate/cap checks happen before signature/VRF proof
            // verification. Exact duplicates are normal gossip during stalls
            // and should cost neither crypto work nor peer penalties.
            if state.reveals.contains_key(&reveal.validator_id)
                || state.reveals.len() >= MAX_VRF_ROUND_ENTRIES
            {
                return actions;
            }
            let Some(commit) = state.commits.get(&reveal.validator_id) else {
                if !state.pending_reveals.contains_key(&reveal.validator_id)
                    && state.pending_reveals.len() < MAX_VRF_ROUND_ENTRIES
                {
                    state.pending_reveals.insert(reveal.validator_id, reveal);
                }
                return actions;
            };
            if commit.commit_hash != reveal.commit_hash {
                if let Some(from) = invalid_from {
                    actions.push(DriverAction::DisconnectInvalidConsensusPeer {
                        from,
                        validator_id: reveal.validator_id,
                        reason: "VrfReveal commit hash does not match prior commit".to_string(),
                    });
                }
                return actions;
            }
            (state.height, state.round)
        };
        if !self.validate_vrf_reveal(&reveal) {
            if let Some(from) = invalid_from {
                actions.push(DriverAction::DisconnectInvalidConsensusPeer {
                    from,
                    validator_id: reveal.validator_id,
                    reason: "VrfReveal signature or proof verification failed".to_string(),
                });
            }
            return actions;
        }
        let Some(state) = self.vrf_states[slot].as_mut() else {
            return actions;
        };
        if state.reveals.contains_key(&reveal.validator_id)
            || state.reveals.len() >= MAX_VRF_ROUND_ENTRIES
            || state
                .commits
                .get(&reveal.validator_id)
                .is_none_or(|commit| commit.commit_hash != reveal.commit_hash)
        {
            return actions;
        }
        state.reveals.insert(reveal.validator_id, reveal.clone());
        if gossip {
            actions.push(DriverAction::BroadcastVrfReveal(reveal));
        }
        actions.extend(self.advance_vrf_round(height, round));
        actions
    }

    /// Return the computed election result for a slot, when available.
    pub fn vrf_election_result(&self, height: u64, round: u32) -> Option<VrfElectionResult> {
        self.vrf_slot_index(height, round)
            .and_then(|slot| self.vrf_states[slot].as_ref())
            .and_then(|state| state.election_result)
    }

    /// Return canonical full reveal evidence for a VRF election slot.
    pub fn vrf_reveal_evidence(&self, height: u64, round: u32) -> Vec<VrfRevealEvidence> {
        self.vrf_slot_index(height, round)
            .and_then(|slot| self.vrf_states[slot].as_ref())
            .map(|state| reveal_evidence_from_reveals(state.reveals.values().cloned()))
            .unwrap_or_default()
    }

    fn missing_local_reveals_for_block(&self, block: &BlockV1) -> Vec<Bytes32> {
        let Some(slot) = self.vrf_slot_index(block.header.height, block.header.proposer_round)
        else {
            return block
                .vrf_reveals
                .iter()
                .map(|evidence| evidence.validator_id)
                .collect();
        };
        let Some(state) = self.vrf_states[slot].as_ref() else {
            return block
                .vrf_reveals
                .iter()
                .map(|evidence| evidence.validator_id)
                .collect();
        };
        block
            .vrf_reveals
            .iter()
            .filter_map(|evidence| match state.reveals.get(&evidence.validator_id) {
                Some(local)
                    if local.vrf_output == evidence.vrf_output
                        && local.vrf_proof.as_slice() == evidence.vrf_proof.as_slice() =>
                {
                    None
                }
                _ => Some(evidence.validator_id),
            })
            .collect()
    }

    /// Check persisted vote safety record and advance past already-voted rounds.
    fn apply_vote_safety(&mut self) {
        let next_height = self.engine.state.height.saturating_add(1);
        match self.vote_safety.load() {
            VoteSafetyLoadResult::NoRecord => {
                self.vote_safety_unavailable = None;
            }
            VoteSafetyLoadResult::Record(record) => {
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
        self.prune_pending_blocks();
        self.prune_future_proposals_bounded();
        self.prune_buffered_votes();
        self.prune_requested_proposals();
        self.prune_seen_round_votes();
        self.prune_pending_precommit_quorum();
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
            .map(|(hash, block)| {
                (
                    *hash,
                    block.header.height.abs_diff(next_height),
                    block.header.proposer_round.abs_diff(current_round),
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
                proposals.sort_by_key(|block| {
                    (
                        block.header.height.abs_diff(next_height),
                        block.header.proposer_round.abs_diff(current_round),
                        block.header.block_hash().0,
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
            for block in proposals {
                let hash = block.header.block_hash();
                ranked.push((
                    hash,
                    block.header.height.abs_diff(next_height),
                    block.header.proposer_round.abs_diff(current_round),
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
            proposals.retain(|block| keep.contains(&block.header.block_hash()));
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

    fn pending_block_for_slot(&self, height: u64, round: u32) -> Option<BlockV1> {
        self.pending_blocks
            .values()
            .find(|block| block.header.height == height && block.header.proposer_round == round)
            .cloned()
    }

    /// Return a locally staged proposal by hash, if present.
    pub fn pending_block(&self, hash: &Bytes32) -> Option<BlockV1> {
        self.pending_blocks.get(hash).cloned()
    }

    /// The proposer includes the latest valid-round in its header.
    pub fn proposal_polc_round(&self, height: u64) -> Option<u32> {
        if self.next_height() != height || self.valid_value.is_none() {
            return None;
        }
        self.valid_round
    }

    /// Return the current valid block and round, if available for reproposal.
    pub fn take_valid_block_for_reproposal(&self) -> Option<(BlockV1, u32)> {
        match (&self.valid_block, self.valid_round) {
            (Some(block), Some(round)) => Some((block.clone(), round)),
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
        let election_mismatch = vrf_commit_reveal_election_active(height)
            && block.header.election_result_hash
                != self
                    .vrf_election_result(height, self.current_round)
                    .map(|result| result.hash());

        if election_mismatch {
            if self
                .vrf_election_result(height, self.current_round)
                .is_none()
            {
                return vec![];
            }
            eprintln!(
                "[vote] nil-prevoting proposal {} at height={} round={} because election_result_hash does not match local commit-reveal result",
                hex::encode(&hash.0[..4]),
                height,
                self.current_round,
            );
            self.current_phase = RoundPhase::Prevote;
            return self.sign_and_record_local_vote(
                height,
                self.current_round,
                VoteStep::Prevote,
                Bytes32::ZERO,
            );
        }

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
        if self.collector_has_vote_from(height, round, step, local_validator_id) {
            return vec![];
        }
        if let Some(reason) = &self.vote_safety_unavailable {
            eprintln!("[vote_safety] refusing to sign local vote: {reason}");
            return vec![DriverAction::None];
        }

        let mut vote_block_hash = block_hash;
        let mut election_result_hash = None;
        if vrf_commit_reveal_election_active(height)
            && step == VoteStep::Precommit
            && block_hash != Bytes32::ZERO
        {
            match self
                .vrf_election_result(height, round)
                .map(|result| result.hash())
            {
                Some(hash) => {
                    if self
                        .pending_block(&block_hash)
                        .is_some_and(|block| block.header.election_result_hash != Some(hash))
                    {
                        eprintln!(
                            "[consensus] precommit for height={} round={}: local VRF election result does not match staged block — casting nil precommit",
                            height, round,
                        );
                        vote_block_hash = Bytes32::ZERO;
                    } else {
                        election_result_hash = Some(hash);
                    }
                }
                None => {
                    let waited_enough = self
                        .precommit_phase_started_at
                        .map(|started| {
                            started.elapsed().as_millis() >= VRF_ELECTION_SETTLE_MS as u128
                        })
                        .unwrap_or(false);
                    if !waited_enough {
                        eprintln!(
                            "[consensus] precommit height={} round={}: VRF election result not yet available — delaying nil precommit for {}ms settle window",
                            height, round, VRF_ELECTION_SETTLE_MS,
                        );
                        return vec![DriverAction::None];
                    }
                    eprintln!(
                        "[consensus] precommit height={} round={}: VRF election result still unavailable after {}ms — casting nil precommit",
                        height, round, VRF_ELECTION_SETTLE_MS,
                    );
                    vote_block_hash = Bytes32::ZERO;
                }
            }
        }

        let step_byte = match step {
            VoteStep::Prevote => 0u8,
            VoteStep::Precommit => 1u8,
        };
        if let Err(err) = self.vote_safety.record(height, round, step_byte) {
            eprintln!(
                "[vote_safety] CRITICAL: failed to persist vote safety record before signing: {err}; refusing to vote"
            );
            return vec![DriverAction::None];
        }

        match self.engine.sign_vote_with_election_result(
            height,
            round,
            step,
            vote_block_hash,
            election_result_hash,
        ) {
            Ok(local_vote) => {
                eprintln!(
                    "[vote] produced {:?} for height={} round={} hash={}",
                    step,
                    height,
                    round,
                    hex::encode(&vote_block_hash.0[..4]),
                );
                self.record_vote_and_actions(SocketAddr::from(([127, 0, 0, 1], 0)), local_vote)
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

    fn process_block(&mut self, from: Option<SocketAddr>, block: BlockV1) -> Vec<DriverAction> {
        if !self.sync.is_caught_up() {
            return vec![DriverAction::None];
        }

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
                .any(|existing| existing.header.block_hash() == block_hash)
            {
                entry.push(block);
            }
            self.prune_future_proposals();
            return vec![DriverAction::None];
        }

        self.process_block_internal(from, block)
    }

    fn process_block_internal(
        &mut self,
        _from: Option<SocketAddr>,
        block: BlockV1,
    ) -> Vec<DriverAction> {
        if self.engine.state.validators.active_count() > 0
            && (block.header.proposer_vrf_output != Bytes32::ZERO
                || !block.header.proposer_vrf_proof.as_slice().is_empty())
            && verify_proposer_vrf(&block, &self.engine.state).is_err()
        {
            eprintln!(
                "[vote] rejecting proposal {} at height={} round={} because it does not verify as the elected proposer block",
                hex::encode(&block.header.block_hash().0[..4]),
                block.header.height,
                block.header.proposer_round,
            );
            return vec![DriverAction::None];
        }
        if reveal_set_commitment_active(block.header.height) {
            match verify_reveal_set_evidence(&block, &self.engine.state) {
                Ok(_) => {
                    let missing = self.missing_local_reveals_for_block(&block);
                    if !missing.is_empty() {
                        let height = block.header.height;
                        let round = block.header.proposer_round;
                        let block_hash = block.header.block_hash();
                        self.pending_reveal_blocks
                            .insert((height, round, block_hash), block);
                        return vec![DriverAction::RequestVrfReveals {
                            height,
                            round,
                            missing_validator_ids: missing,
                        }];
                    }
                }
                Err(err) => {
                    eprintln!(
                        "[vote] rejecting proposal {} at height={} round={} because reveal-set evidence is invalid: {}",
                        hex::encode(&block.header.block_hash().0[..4]),
                        block.header.height,
                        block.header.proposer_round,
                        err,
                    );
                    return vec![DriverAction::None];
                }
            }
        } else if vrf_commit_reveal_election_active(block.header.height) {
            if let Some(local_result) =
                self.vrf_election_result(block.header.height, block.header.proposer_round)
            {
                if block.header.election_result_hash != Some(local_result.hash()) {
                    eprintln!(
                        "[vote] rejecting proposal {} at height={} round={} because election_result_hash does not match local commit-reveal result",
                        hex::encode(&block.header.block_hash().0[..4]),
                        block.header.height,
                        block.header.proposer_round,
                    );
                    return vec![DriverAction::None];
                }
            }
        }

        if block.header.height > 1 {
            if let Err(err) = verify_block_qc(&block, &self.engine.state) {
                eprintln!(
                    "[vote] rejecting proposal at height={} round={}: embedded QC invalid: {}",
                    block.header.height, block.header.proposer_round, err,
                );
                return vec![DriverAction::None];
            }
        }

        let mut projected_state = self.engine.state.clone();
        if indra_state::apply_block(&mut projected_state, &block, 0).is_err() {
            return vec![DriverAction::None];
        }

        let block_hash = block.header.block_hash();
        if let Some(existing_block) =
            self.pending_block_for_slot(block.header.height, block.header.proposer_round)
        {
            if existing_block.header.block_hash() != block_hash {
                return vec![DriverAction::None];
            }
        }
        if self.pending_blocks.contains_key(&block_hash) {
            return vec![DriverAction::None];
        }

        self.requested_proposals.remove(&(
            block.header.height,
            block.header.proposer_round,
            block_hash,
        ));
        self.pending_blocks.insert(block_hash, block.clone());
        self.prune_pending_blocks();

        let proposal_round = block.header.proposer_round;
        let proposal_height = block.header.height;
        if proposal_height == self.next_height()
            && proposal_round > self.current_round
            && self.sync.is_caught_up()
        {
            eprintln!(
                "[consensus] proposal-driven round jump: {} → {} at height={}",
                self.current_round, proposal_round, proposal_height
            );
            self.start_round(proposal_round);
            self.apply_vote_safety();
        }

        let mut actions = vec![DriverAction::BroadcastBlock(block.clone())];

        if let Some(buffered_votes) = self.buffered_votes.remove(&(
            block.header.height,
            block.header.proposer_round,
            block_hash,
        )) {
            for (vote_from, vote) in buffered_votes {
                actions.extend(self.record_vote_and_actions(vote_from, vote));
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

        // Rules 2 and 3 — if this is the proposal for our current slot, react
        // immediately instead of waiting for the propose timeout.
        if vrf_commit_reveal_election_active(proposal_height)
            && proposal_height == self.next_height()
            && proposal_round == self.current_round
        {
            let election = self.active_vrf_candidates(proposal_height, proposal_round);
            actions.extend(self.ensure_vrf_election_for_round(&election));
        }
        actions.extend(self.maybe_prevote_current_round_proposal());
        actions
    }

    fn activate_buffered_proposals_for_new_tip(&mut self) -> Vec<DriverAction> {
        let key = (self.next_height(), self.engine.state.tip_hash);
        let Some(buffered) = self.future_proposals.remove(&key) else {
            self.prune_future_proposals();
            return vec![];
        };

        let mut candidates = buffered;
        candidates.sort_by_key(|block| block.header.proposer_round);
        self.prune_future_proposals();
        candidates
            .into_iter()
            .map(DriverAction::ActivateBufferedProposal)
            .collect()
    }

    fn process_vote(&mut self, from: SocketAddr, vote: VoteV1) -> Vec<DriverAction> {
        let mut actions = Vec::new();

        if self
            .engine
            .validator_id()
            .is_some_and(|local_id| local_id == vote.validator_id)
            && self.collector_has_vote_from(vote.height, vote.round, vote.step, vote.validator_id)
        {
            return actions;
        }

        if vote.height <= self.engine.state.height {
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

        if !self.sync.is_caught_up() {
            actions.extend(self.record_vote_passive(from, vote));
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
            return actions;
        }

        actions.extend(self.record_vote_and_actions(from, vote));
        actions
    }

    fn validate_precommit_election_result_hash(&self, vote: &VoteV1) -> Result<(), String> {
        if !vrf_commit_reveal_election_active(vote.height)
            || vote.step != VoteStep::Precommit
            || vote.is_nil()
        {
            return Ok(());
        }
        let Some(vote_hash) = vote.election_result_hash else {
            return Err(
                "non-nil precommit is missing election_result_hash while commit-reveal election is active"
                    .to_string(),
            );
        };
        if let Some(block) = self.pending_block(&vote.block_hash) {
            if block.header.election_result_hash != Some(vote_hash) {
                return Err(format!(
                    "precommit election_result_hash {} does not match staged block {}",
                    hex::encode(&vote_hash.0[..4]),
                    block
                        .header
                        .election_result_hash
                        .map(|hash| hex::encode(&hash.0[..4]))
                        .unwrap_or_else(|| "None".to_string()),
                ));
            }
        }
        Ok(())
    }

    fn precommit_votes_with_election_quorum(
        &self,
        collector: &VoteCollector,
        block: &BlockV1,
        block_hash: Bytes32,
    ) -> Option<Vec<VoteV1>> {
        let votes: Vec<&VoteV1> = collector
            .accepted_votes()
            .into_iter()
            .filter(|vote| vote.block_hash == block_hash && vote.step == VoteStep::Precommit)
            .collect();

        if !vrf_commit_reveal_election_active(block.header.height) || block_hash == Bytes32::ZERO {
            return Some(votes.into_iter().cloned().collect());
        }

        let target_hash = block.header.election_result_hash?;
        let stake_by_validator: BTreeMap<Bytes32, u64> = self
            .registered_voters
            .iter()
            .map(|voter| (voter.validator_id, voter.stake))
            .collect();
        let total_stake = self
            .registered_voters
            .iter()
            .fold(0u64, |total, voter| total.saturating_add(voter.stake));
        let threshold = bps_of(total_stake, CONSENSUS_QUORUM_BPS);
        let matching: Vec<VoteV1> = votes
            .into_iter()
            .filter(|vote| vote.election_result_hash == Some(target_hash))
            .cloned()
            .collect();
        let matching_stake = matching.iter().fold(0u64, |total, vote| {
            total.saturating_add(
                stake_by_validator
                    .get(&vote.validator_id)
                    .copied()
                    .unwrap_or_default(),
            )
        });

        if matching_stake >= threshold {
            Some(matching)
        } else {
            eprintln!(
                "[consensus] quorum for {} at height={} round={} but election_result_hash does not independently reach quorum — waiting",
                hex::encode(&block_hash.0[..4]),
                block.header.height,
                block.header.proposer_round,
            );
            None
        }
    }

    fn record_vote_passive(&mut self, from: SocketAddr, vote: VoteV1) -> Vec<DriverAction> {
        let mut actions = Vec::new();
        if let Err(err) = self.validate_precommit_election_result_hash(&vote) {
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
            return actions;
        }
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
            collector.add_vote(vote.clone())
        };
        self.prune_vote_collectors();

        match decision {
            Ok(_decision) => {}
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

    fn record_vote_and_actions(&mut self, from: SocketAddr, vote: VoteV1) -> Vec<DriverAction> {
        let mut actions = Vec::new();
        if let Err(err) = self.validate_precommit_election_result_hash(&vote) {
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
            return actions;
        }
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
            collector.add_vote(vote.clone())
        };
        self.prune_vote_collectors();

        match decision {
            Ok(decision) => {
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
                                    self.valid_block = self.pending_block(&block_hash);
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

        let qc_validators = self.engine.qc_validators();
        if qc_validators.len() != self.registered_voters.len() {
            eprintln!(
                "[commit] cannot finalize {} at height={} round={} because QC validator set is incomplete",
                hex::encode(&block_hash.0[..4]),
                height,
                round,
            );
            return vec![DriverAction::None];
        }

        let Some(quorum_vote_values) =
            self.precommit_votes_with_election_quorum(collector, &block, block_hash)
        else {
            return vec![DriverAction::None];
        };
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
                    "[commit] failed to build QC for {} at height={} round={}: CryptoError: {} — this may indicate election_result_hash disagreement across precommit votes",
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
        if vrf_commit_reveal_election_active(height)
            && block.header.election_result_hash != qc.election_result_hash
        {
            eprintln!(
                "[commit] failed to finalize {} at height={} round={}: QC election_result_hash {:?} does not match block header {:?}",
                hex::encode(&block_hash.0[..4]),
                height,
                round,
                qc.election_result_hash.map(|hash| hex::encode(&hash.0[..4])),
                block.header.election_result_hash.map(|hash| hex::encode(&hash.0[..4])),
            );
            return vec![DriverAction::None];
        }

        let old_height = self.engine.state.height;
        match self.engine.commit_block(&block) {
            Ok(()) => {
                self.pending_blocks.remove(&block_hash);
                let mut actions = vec![DriverAction::BroadcastBlock(block)];
                eprintln!(
                    "[commit] finalizing {} at height={} round={}",
                    hex::encode(&block_hash.0[..4]),
                    height,
                    round,
                );

                if let Err(e) = self.set_last_qc_bytes_if_newer_from_source(
                    height,
                    qc.encode_to_vec(),
                    "consensus",
                ) {
                    eprintln!(
                        "[driver] WARNING: failed to promote consensus last_qc_bytes at height {}: {}",
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
                self.valid_round = None;
                self.valid_value = None;
                self.start_round(0);
                actions.extend(self.pipeline_next_height_vrf_commit_after_finalization());
                actions.extend(self.activate_buffered_proposals_for_new_tip());

                self.vote_collectors
                    .retain(|(vote_height, _, _), _| *vote_height > height);
                self.pending_blocks
                    .retain(|_, pending| pending.header.height > height);
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

    fn process_tx(&mut self, _from: SocketAddr, tx_bytes: Vec<u8>) -> Vec<DriverAction> {
        let mut reader = ByteReader::new(&tx_bytes);
        let tx = match TransactionV1::decode(&mut reader) {
            Ok(tx) => tx,
            Err(_) => return vec![DriverAction::None],
        };

        let state = self.engine.state.clone();
        match self.engine.mempool.submit_validated(tx.clone(), &state) {
            Ok(_) => vec![DriverAction::BroadcastTx(tx)],
            Err(_) => vec![DriverAction::None],
        }
    }

    fn process_vrf_commit(&mut self, from: SocketAddr, commit: VrfCommit) -> Vec<DriverAction> {
        if !vrf_commit_reveal_election_active(commit.height) {
            return vec![DriverAction::None];
        }
        if commit.chain_id_hash != chain_id_hash(&self.engine.state.chain_id) {
            return vec![DriverAction::DisconnectInvalidConsensusPeer {
                from,
                validator_id: commit.validator_id,
                reason: "VrfCommit chain_id_hash mismatch".to_string(),
            }];
        }
        // Cheap slot/range check before expensive hybrid signature
        // verification. Only current/next VRF rounds are retained.
        let Some(slot) = self.vrf_slot_index(commit.height, commit.round) else {
            return vec![DriverAction::None];
        };
        if !self.validator_vrf_pk_matches(&commit.validator_id, &commit.vrf_pubkey) {
            return vec![DriverAction::DisconnectInvalidConsensusPeer {
                from,
                validator_id: commit.validator_id,
                reason: "VrfCommit validator is inactive or VRF key does not match registry"
                    .to_string(),
            }];
        }
        {
            let Some(state) = self.vrf_states[slot].as_ref() else {
                return vec![DriverAction::None];
            };
            if state.commits.contains_key(&commit.validator_id)
                || state.commits.len() >= MAX_VRF_ROUND_ENTRIES
            {
                return vec![DriverAction::None];
            }
        }
        if !self.verify_commit_signature(&commit) {
            return vec![DriverAction::DisconnectInvalidConsensusPeer {
                from,
                validator_id: commit.validator_id,
                reason: "VrfCommit hybrid signature verification failed".to_string(),
            }];
        }
        let pending = {
            let Some(state) = self.vrf_states[slot].as_mut() else {
                return vec![DriverAction::None];
            };
            if state.commits.contains_key(&commit.validator_id)
                || state.commits.len() >= MAX_VRF_ROUND_ENTRIES
            {
                return vec![DriverAction::None];
            }
            state.commits.insert(commit.validator_id, commit.clone());
            state.pending_reveals.remove(&commit.validator_id)
        };
        let mut actions = vec![DriverAction::BroadcastVrfCommit(commit.clone())];
        if let Some(reveal) = pending {
            actions.extend(self.insert_valid_vrf_reveal(slot, reveal, true, None));
        }
        actions.extend(self.advance_vrf_round(commit.height, commit.round));
        actions
    }

    fn process_vrf_reveal(&mut self, from: SocketAddr, reveal: VrfReveal) -> Vec<DriverAction> {
        if !vrf_commit_reveal_election_active(reveal.height) {
            return vec![DriverAction::None];
        }
        if reveal.chain_id_hash != chain_id_hash(&self.engine.state.chain_id) {
            return vec![DriverAction::DisconnectInvalidConsensusPeer {
                from,
                validator_id: reveal.validator_id,
                reason: "VrfReveal chain_id_hash mismatch".to_string(),
            }];
        }
        let Some(slot) = self.vrf_slot_index(reveal.height, reveal.round) else {
            return vec![DriverAction::None];
        };
        let actions = self.insert_valid_vrf_reveal(slot, reveal, true, Some(from));
        if actions.is_empty() {
            vec![DriverAction::None]
        } else {
            actions
        }
    }

    fn process_status(
        &mut self,
        from: SocketAddr,
        height: u64,
        _tip_hash: Bytes32,
        peer_round: u32,
    ) -> Vec<DriverAction> {
        let our_height = self.engine.height();
        if height == our_height.saturating_add(1)
            && peer_round > self.current_round
            && self.sync.is_caught_up()
        {
            let current_round = self.current_round;
            let capped_round = current_round
                .saturating_add(MAX_ACCEPTED_ROUND_JUMP)
                .min(peer_round);
            if capped_round > current_round {
                if peer_round > capped_round {
                    eprintln!(
                        "[consensus] WARNING: peer {} claimed round {} (capping jump from {} to {})",
                        from, peer_round, current_round, capped_round
                    );
                } else {
                    eprintln!(
                        "[consensus] round sync: advancing from round {} to {} (peer at round {})",
                        current_round, capped_round, peer_round
                    );
                }
                self.start_round(capped_round);
                self.prune_stalled_collections();
            }
        }
        match self.sync.observe_status(from, height, our_height) {
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
                    let qc_bytes = block.header.quorum_certificate.as_slice().to_vec();
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

        let mut reader = ByteReader::new(&qc_bytes);
        let qc = match QuorumCertificateV1::decode(&mut reader) {
            Ok(qc) => qc,
            Err(err) => {
                eprintln!(
                    "[driver] WARNING: received invalid QC encoding from {} at height {}: {}",
                    from, height, err,
                );
                return vec![];
            }
        };

        if qc.height != height {
            return vec![];
        }

        let validators = self.engine.qc_validators();
        let total_stake = self.engine.state.validators.total_active_stake();
        if let Err(err) = verify_qc(&qc, &validators, total_stake, &self.engine.state.chain_id) {
            eprintln!(
                "[driver] WARNING: received invalid QC from {} at height {}: {}",
                from, height, err,
            );
            return vec![];
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

    fn handle_vrf_reveals_request(
        &mut self,
        from: SocketAddr,
        height: u64,
        round: u32,
        missing_validator_ids: Vec<Bytes32>,
    ) -> Vec<DriverAction> {
        let Some(slot) = self.vrf_slot_index(height, round) else {
            return vec![];
        };
        let Some(state) = self.vrf_states[slot].as_ref() else {
            return vec![];
        };
        let reveals: Vec<_> = missing_validator_ids
            .into_iter()
            .filter_map(|validator_id| state.reveals.get(&validator_id).cloned())
            .collect();
        if reveals.is_empty() {
            return vec![];
        }
        vec![DriverAction::SendVrfRevealsResponse {
            to: from,
            height,
            round,
            reveals,
        }]
    }

    fn handle_vrf_reveals_response(
        &mut self,
        from: SocketAddr,
        height: u64,
        round: u32,
        reveals: Vec<VrfReveal>,
    ) -> Vec<DriverAction> {
        let Some(slot) = self.vrf_slot_index(height, round) else {
            return vec![];
        };
        self.requested_vrf_reveals
            .retain(|(h, r, _), _| *h != height || *r != round);
        let mut actions = Vec::new();
        for reveal in reveals {
            if reveal.height == height && reveal.round == round {
                actions.extend(self.insert_valid_vrf_reveal(slot, reveal, false, Some(from)));
            }
        }

        let ready: Vec<_> = self
            .pending_reveal_blocks
            .iter()
            .filter_map(|(&(h, r, hash), block)| {
                (h == height
                    && r == round
                    && self.missing_local_reveals_for_block(block).is_empty())
                .then_some((h, r, hash))
            })
            .collect();

        for key in ready {
            if let Some(block) = self.pending_reveal_blocks.remove(&key) {
                actions.extend(self.process_block_internal(Some(from), block));
            }
        }

        actions
    }

    /// Rule 11 — on propose timeout, prevote nil unless the proposal for the
    /// current round is already staged locally.
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
        proposer::ProposerCandidate,
        vote::VoteCollector,
    };
    use indra_core::{
        types::block::{BlockHeaderV1, BlockV1},
        types::primitives::{
            DEFAULT_CHAIN_ID, DEFAULT_COMMISSION_BPS, DUST_LIMIT_SPARK, MAX_VRF_PROOF_BYTES,
        },
        Bytes32, ProtocolVersion, VariableBytes,
    };
    use indra_crypto::{
        hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
        VrfKeypair,
    };
    use indra_state::{
        apply_block, compute_state_root, compute_validator_set_root, ChainState, ValidatorEntry,
        ValidatorStatus,
    };
    use std::{path::PathBuf, time::Duration};

    fn temp_dir(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "indra_driver_test_{}_{}",
            suffix,
            std::process::id()
        ));
        p
    }

    fn make_block(state: &ChainState) -> BlockV1 {
        let mut block = BlockV1 {
            header: BlockHeaderV1 {
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
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof: VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
                quorum_certificate: indra_core::VariableBytes::from_slice(&[]).unwrap(),
                election_result_hash: None,
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            vrf_reveals: vec![],
        };

        let mut projected = state.clone();
        apply_block(&mut projected, &block, 0).unwrap();
        block.header.state_root = compute_state_root(&projected);
        block.header.validator_set_root = compute_validator_set_root(&projected);
        block.header.value_hash = block.compute_value_hash(projected.total_supply);
        block
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
            election_result_hash: None,
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
        let validator_id = Bytes32::from(indra_crypto::sha256(&signer.public_key().classical.0));
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
        election_result_hash: Option<Bytes32>,
    ) -> Vec<u8> {
        let votes: Vec<_> = signers
            .iter()
            .map(|signer| {
                let validator_id =
                    Bytes32::from(indra_crypto::sha256(&signer.public_key().classical.0));
                indra_consensus::vote::produce_vote_with_election_result(
                    height,
                    round,
                    VoteStep::Precommit,
                    block_hash,
                    validator_id,
                    election_result_hash,
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
        let validator_id = Bytes32::from(indra_crypto::sha256(&public.classical.0));

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
                stake_spark: 1_000_000,
                status: ValidatorStatus::Active,
                registered_epoch: 0,
                last_active_epoch: 0,
                pending_rewards: 0,
                rewards_last_epoch: 0,
                self_report_count: 0,
                commission_bps: DEFAULT_COMMISSION_BPS,
                pending_commission_bps: None,
                pending_commission_effective_epoch: None,
                min_delegation_spark: DUST_LIMIT_SPARK,
                auto_delegate_to: None,
            })
            .unwrap();
        hybrid
    }

    fn validator_id_for(signer: &HybridKeypair) -> Bytes32 {
        Bytes32::from(indra_crypto::sha256(&signer.public_key().classical.0))
    }

    fn local_driver(seed: [u8; 32], suffix: &str) -> (ConsensusDriver, PathBuf) {
        let dir = temp_dir(suffix);
        let mut config = NodeConfig::local_test(dir.clone());
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let classical = ClassicalKeypair::from_seed(&seed);
        let vrf = VrfKeypair::from_seed(&seed);
        let validator_id = indra_crypto::sha256(&classical.public_key().0);
        let genesis_path = dir.join("genesis.toml");
        std::fs::create_dir_all(&dir).unwrap();
        let genesis = format!(
            "[[validators]]\nname = \"local\"\nvalidator_id = \"{}\"\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\nstake = 1000000\n",
            hex::encode(validator_id),
            hex::encode(classical.public_key().0),
            hex::encode(pq.public_key().0),
            hex::encode(vrf.public_key()),
        );
        std::fs::write(&genesis_path, genesis).unwrap();
        config.genesis_path = Some(genesis_path.to_string_lossy().to_string());
        config.validator_seed = Some(seed);
        config.vrf_seed = Some(seed);
        config.pq_pk = Some(pq.public_key().0.to_vec());
        config.pq_sk = Some(pq.secret_key_bytes());
        let engine = NodeEngine::init(config).unwrap();
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        (ConsensusDriver::new(engine, vote_safety), dir)
    }

    fn signed_vrf_pair(
        driver: &ConsensusDriver,
        seed: [u8; 32],
        height: u64,
        round: u32,
        chain_id: &str,
    ) -> (VrfCommit, VrfReveal) {
        let classical = ClassicalKeypair::from_seed(&seed);
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let hybrid = HybridKeypair::new(classical, pq);
        let vrf = VrfKeypair::from_seed(&seed);
        let vrf_pubkey = vrf.public_key();
        let validator_id = driver
            .engine
            .state
            .validators
            .active_validators()
            .find(|validator| validator.vrf_pk == Some(vrf_pubkey))
            .expect("seed must be registered as active validator")
            .validator_id;
        let election = election_for_round(driver, height, round);
        let slot = compute_proposer_vrf(validator_id, &vrf, &election.epoch_seed, height, round);
        let vrf_output = Bytes32::from(slot.vrf_output.0);
        let chain_id_hash = chain_id_hash(chain_id);
        let commit_hash = compute_vrf_commit_hash(
            &chain_id_hash,
            height,
            round,
            &validator_id,
            &vrf_pubkey,
            &slot.vrf_input,
            &vrf_output,
            &slot.vrf_proof.0,
        );
        let mut commit = VrfCommit {
            chain_id_hash,
            height,
            round,
            validator_id,
            vrf_pubkey,
            commit_hash,
            signature: ConsensusDriver::empty_signature().unwrap(),
        };
        commit.signature =
            ConsensusDriver::convert_signature(hybrid.sign(&commit.signing_bytes()).unwrap())
                .unwrap();
        let mut reveal = VrfReveal {
            chain_id_hash,
            height,
            round,
            validator_id,
            vrf_pubkey,
            vrf_output,
            vrf_proof: VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&slot.vrf_proof.0).unwrap(),
            commit_hash,
            signature: ConsensusDriver::empty_signature().unwrap(),
        };
        reveal.signature =
            ConsensusDriver::convert_signature(hybrid.sign(&reveal.signing_bytes()).unwrap())
                .unwrap();
        (commit, reveal)
    }

    fn reveal_set_block_from_reveals(
        driver: &ConsensusDriver,
        active_seeds: &[[u8; 32]],
        reveals: &[VrfReveal],
    ) -> BlockV1 {
        let height = u64::MAX;
        let round = 0u32;
        let election = election_for_round(driver, height, round);
        let mut revealed_outputs = std::collections::BTreeMap::new();
        let mut evidence = reveal_evidence_from_reveals(reveals.iter().cloned());
        for evidence_item in &evidence {
            revealed_outputs.insert(evidence_item.validator_id, evidence_item.vrf_output);
        }

        let mut result = elect_proposer_from_reveals(&election, &revealed_outputs).unwrap();
        result.reveal_set_commitment = compute_reveal_set_commitment(&evidence);

        let proposer_seed = active_seeds
            .iter()
            .find(|seed| {
                let keypair = VrfKeypair::from_seed(seed);
                election.candidates.iter().any(|candidate| {
                    candidate.validator_id == result.elected_validator_id
                        && candidate.vrf_pubkey == keypair.public_key()
                })
            })
            .copied()
            .expect("elected proposer must map to one active test seed");
        let proposer_vrf = VrfKeypair::from_seed(&proposer_seed);
        let proposer_slot = compute_proposer_vrf(
            result.elected_validator_id,
            &proposer_vrf,
            &election.epoch_seed,
            height,
            round,
        );

        evidence.sort_by_key(|item| item.validator_id.0);
        let mut block = BlockV1 {
            header: BlockHeaderV1 {
                protocol_version: ProtocolVersion(
                    indra_core::types::primitives::BLOCK_PROTOCOL_VERSION_REVEAL_SET,
                ),
                height,
                prev_hash: driver.engine.state.tip_hash,
                timestamp: 1_900_000_000,
                state_root: Bytes32::ZERO,
                validator_set_root: Bytes32::ZERO,
                mempool_set_root: Bytes32::ZERO,
                value_hash: Bytes32::ZERO,
                base_fee: driver.engine.state.base_fee,
                proposer_round: round,
                polc_round: NO_POLC_ROUND,
                proposer_vrf_output: Bytes32::from(proposer_slot.vrf_output.0),
                proposer_vrf_proof: VariableBytes::from_slice(&proposer_slot.vrf_proof.0).unwrap(),
                quorum_certificate: VariableBytes::from_slice(&[]).unwrap(),
                election_result_hash: Some(result.hash()),
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            vrf_reveals: evidence,
        };

        let mut projected = driver.engine.state.clone();
        apply_block(&mut projected, &block, 0).unwrap();
        block.header.state_root = compute_state_root(&projected);
        block.header.validator_set_root = compute_validator_set_root(&projected);
        block.header.value_hash = block.compute_value_hash(projected.total_supply);
        block
    }

    fn seed_vrf_result_for_seed(
        driver: &mut ConsensusDriver,
        height: u64,
        round: u32,
        seed: [u8; 32],
    ) {
        let election = election_for_round(driver, height, round);
        let vrf = VrfKeypair::from_seed(&seed);
        let proposer_id = election
            .candidates
            .iter()
            .find(|candidate| candidate.vrf_pubkey == vrf.public_key())
            .expect("seed must be registered as active validator")
            .validator_id;
        let slot = compute_proposer_vrf(proposer_id, &vrf, &election.epoch_seed, height, round);
        let result = VrfElectionResult {
            height,
            round,
            elected_validator_id: proposer_id,
            elected_vrf_output: Bytes32::from(slot.vrf_output.0),
            fallback_used: false,
            reveal_set_commitment: Bytes32::ZERO,
        };
        let mut state = VrfRoundState::new(height, round);
        state.phase = VrfRoundPhase::Complete;
        state.election_result = Some(result);
        driver.vrf_states[0] = Some(state);
    }

    fn stage_block_with_precommit_quorum(
        driver: &mut ConsensusDriver,
        proposer_seed: [u8; 32],
        round: u32,
        signers: &[&HybridKeypair],
    ) -> (BlockV1, Bytes32) {
        let height = driver.next_height();
        seed_vrf_result_for_seed(driver, height, round, proposer_seed);
        let block = make_strict_block(driver, proposer_seed, round, driver.last_qc_bytes());
        let block_hash = block.header.block_hash();
        let election_result_hash = block.header.election_result_hash;
        driver.pending_blocks.insert(block_hash, block.clone());

        let mut collector = VoteCollector::new(
            height,
            round,
            VoteStep::Precommit,
            DEFAULT_CHAIN_ID.to_string(),
            driver.registered_voters.clone(),
        );
        for signer in signers {
            let vote = indra_consensus::vote::produce_vote_with_election_result(
                height,
                round,
                VoteStep::Precommit,
                block_hash,
                validator_id_for(signer),
                election_result_hash,
                DEFAULT_CHAIN_ID,
                signer,
            )
            .unwrap();
            let _ = collector.add_vote(vote).unwrap();
        }
        driver
            .vote_collectors
            .insert((height, round, VoteStep::Precommit), collector);
        (block, block_hash)
    }

    fn make_strict_block(
        driver: &ConsensusDriver,
        proposer_seed: [u8; 32],
        round: u32,
        prev_qc_bytes: Vec<u8>,
    ) -> BlockV1 {
        let epoch_seed = Bytes32::from(indra_crypto::sha256(&driver.engine.state.tip_hash.0));
        let mut candidates: Vec<_> = driver
            .engine
            .state
            .validators
            .active_validators()
            .filter_map(|v| {
                v.vrf_pk.map(|vrf_pk| ProposerCandidate {
                    validator_id: v.validator_id,
                    vrf_pubkey: vrf_pk,
                    verified_vrf_output: None,
                    stake: v.stake_spark,
                })
            })
            .collect();
        candidates.sort_by_key(|candidate| candidate.validator_id.0);
        let election = indra_consensus::proposer::ProposerElection {
            epoch_seed,
            height: driver.engine.state.height + 1,
            round,
            candidates,
        };
        let proposer_vrf = VrfKeypair::from_seed(&proposer_seed);
        let proposer_id = election
            .candidates
            .iter()
            .find(|candidate| candidate.vrf_pubkey == proposer_vrf.public_key())
            .expect("proposer must be in active validator set")
            .validator_id;
        let slot = compute_proposer_vrf(
            proposer_id,
            &proposer_vrf,
            &election.epoch_seed,
            election.height,
            election.round,
        );
        let election_result_hash = VrfElectionResult {
            height: election.height,
            round: election.round,
            elected_validator_id: proposer_id,
            elected_vrf_output: Bytes32::from(slot.vrf_output.0),
            fallback_used: false,
            reveal_set_commitment: Bytes32::ZERO,
        }
        .hash();
        let template = BlockTemplate {
            proposer_vrf_keypair: proposer_vrf,
            epoch_seed: election.epoch_seed,
            prev_qc_bytes,
            timestamp: 1_700_000_000 + driver.engine.state.height + 1,
            polc_round: None,
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            election_result_hash: Some(election_result_hash),
            vrf_reveals: vec![],
        };
        produce_block(
            &template,
            &driver.engine.state,
            &driver.engine.mempool,
            &election,
        )
        .unwrap()
    }

    fn election_for_round(
        driver: &ConsensusDriver,
        height: u64,
        round: u32,
    ) -> indra_consensus::proposer::ProposerElection {
        let epoch_seed = Bytes32::from(indra_crypto::sha256(&driver.engine.state.tip_hash.0));
        let candidates: Vec<indra_consensus::proposer::ProposerCandidate> = driver
            .engine
            .state
            .validators
            .active_validators()
            .filter_map(|v| {
                v.vrf_pk
                    .map(|vrf_pk| indra_consensus::proposer::ProposerCandidate {
                        validator_id: v.validator_id,
                        vrf_pubkey: vrf_pk,
                        verified_vrf_output: None,
                        stake: v.stake_spark,
                    })
            })
            .collect();
        indra_consensus::proposer::ProposerElection {
            epoch_seed,
            height,
            round,
            candidates,
        }
    }

    fn elect_with_verified_output_for_seed(
        election: &indra_consensus::proposer::ProposerElection,
        seed: [u8; 32],
    ) -> Option<Bytes32> {
        let keypair = VrfKeypair::from_seed(&seed);
        let validator_id = election
            .candidates
            .iter()
            .find(|candidate| candidate.vrf_pubkey == keypair.public_key())?
            .validator_id;
        let elected = indra_consensus::proposer::elect_proposer(election, election.height).ok()?;
        (elected == validator_id).then_some(elected)
    }

    #[test]
    fn vrf_commit_pipelines_immediately_on_finalization() {
        let (mut driver, dir) = local_driver([0xC1u8; 32], "vrf_pipeline_immediate");
        let local = install_active_validator(&mut driver, [0xC1u8; 32], "local");
        let a = install_active_validator(&mut driver, [0xC2u8; 32], "a");
        let b = install_active_validator(&mut driver, [0xC3u8; 32], "b");
        let _c = install_active_validator(&mut driver, [0xC4u8; 32], "c");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());

        let (_block, block_hash) =
            stage_block_with_precommit_quorum(&mut driver, [0xC1u8; 32], 0, &[&local, &a, &b]);

        let actions = driver.finalize_block_on_quorum(1, 0, block_hash);

        assert_eq!(driver.height(), 1);
        assert!(actions
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastBlock(_))));
        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVrfCommit(commit)
                if commit.height == 2 && commit.round == 0
        )));
        assert_eq!(driver.highest_pipelined_vrf_commit_height, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vrf_commit_not_duplicated_on_repeated_finalization_signal() {
        let (mut driver, dir) = local_driver([0xC5u8; 32], "vrf_pipeline_no_duplicate");
        let local = install_active_validator(&mut driver, [0xC5u8; 32], "local");
        let a = install_active_validator(&mut driver, [0xC6u8; 32], "a");
        let b = install_active_validator(&mut driver, [0xC7u8; 32], "b");
        let _c = install_active_validator(&mut driver, [0xC8u8; 32], "c");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());

        let (_block, block_hash) =
            stage_block_with_precommit_quorum(&mut driver, [0xC5u8; 32], 0, &[&local, &a, &b]);

        let first = driver.finalize_block_on_quorum(1, 0, block_hash);
        let guarded_retry = driver.pipeline_next_height_vrf_commit_after_finalization();
        let second = driver.finalize_block_on_quorum(1, 0, block_hash);
        let pipelined_count = first
            .iter()
            .chain(guarded_retry.iter())
            .chain(second.iter())
            .filter(|action| {
                matches!(
                    action,
                    DriverAction::BroadcastVrfCommit(commit)
                        if commit.height == 2 && commit.round == 0
                )
            })
            .count();

        assert_eq!(pipelined_count, 1);
        assert!(
            guarded_retry.is_empty(),
            "explicit height guard should make repeated pipelining no-op"
        );
        assert!(!second.iter().any(|action| {
            matches!(
                action,
                DriverAction::BroadcastVrfCommit(commit)
                    if commit.height == 2 && commit.round == 0
            )
        }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vrf_commit_pipelining_does_not_fire_on_round_timeout_without_finalization() {
        let (mut driver, dir) = local_driver([0xC9u8; 32], "vrf_pipeline_no_timeout");
        let _local = install_active_validator(&mut driver, [0xC9u8; 32], "local");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());
        driver.current_phase = RoundPhase::Prevote;
        driver.current_round = 0;

        let prevote_timeout_actions = driver.on_prevote_timeout();
        assert!(!prevote_timeout_actions
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastVrfCommit(_))));
        driver.on_precommit_timeout();

        assert_eq!(driver.height(), 0);
        assert_eq!(driver.current_round(), 1);
        assert_eq!(driver.highest_pipelined_vrf_commit_height, 0);
        assert!(!driver
            .local_vrf_rounds
            .keys()
            .any(|(height, _)| *height == 2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vrf_commit_pipelining_seed_matches_non_pipelined_seed() {
        let (mut pipelined, pipelined_dir) =
            local_driver([0xCAu8; 32], "vrf_pipeline_seed_pipelined");
        let local = install_active_validator(&mut pipelined, [0xCAu8; 32], "local");
        let a = install_active_validator(&mut pipelined, [0xCBu8; 32], "a");
        let b = install_active_validator(&mut pipelined, [0xCCu8; 32], "b");
        let _c = install_active_validator(&mut pipelined, [0xCDu8; 32], "c");
        pipelined.refresh_registered_voters();
        pipelined.sync.mark_caught_up(pipelined.height());
        let (block, block_hash) =
            stage_block_with_precommit_quorum(&mut pipelined, [0xCAu8; 32], 0, &[&local, &a, &b]);

        let pipelined_actions = pipelined.finalize_block_on_quorum(1, 0, block_hash);
        let pipelined_commit = pipelined_actions
            .iter()
            .find_map(|action| match action {
                DriverAction::BroadcastVrfCommit(commit)
                    if commit.height == 2 && commit.round == 0 =>
                {
                    Some(commit.clone())
                }
                _ => None,
            })
            .expect("finalization should pipeline the height-2 round-0 commit");
        let pipelined_local = pipelined
            .local_vrf_rounds
            .get(&(2, 0))
            .cloned()
            .expect("pipelined local VRF output should be retained for reveal");

        let (mut non_pipelined, non_pipelined_dir) =
            local_driver([0xCAu8; 32], "vrf_pipeline_seed_non_pipelined");
        let _local = install_active_validator(&mut non_pipelined, [0xCAu8; 32], "local");
        let _a = install_active_validator(&mut non_pipelined, [0xCBu8; 32], "a");
        let _b = install_active_validator(&mut non_pipelined, [0xCCu8; 32], "b");
        let _c = install_active_validator(&mut non_pipelined, [0xCDu8; 32], "c");
        non_pipelined.refresh_registered_voters();
        non_pipelined.sync.mark_caught_up(non_pipelined.height());
        non_pipelined.engine.commit_block(&block).unwrap();
        non_pipelined.refresh_registered_voters();
        non_pipelined
            .sync
            .mark_caught_up(non_pipelined.engine.state.height);
        non_pipelined.start_round(0);
        let election = election_for_round(&non_pipelined, 2, 0);
        let non_pipelined_actions = non_pipelined.ensure_vrf_election_for_round(&election);
        let non_pipelined_commit = non_pipelined_actions
            .iter()
            .find_map(|action| match action {
                DriverAction::BroadcastVrfCommit(commit)
                    if commit.height == 2 && commit.round == 0 =>
                {
                    Some(commit.clone())
                }
                _ => None,
            })
            .expect("old node-loop path should produce the same commit");
        let non_pipelined_local = non_pipelined
            .local_vrf_rounds
            .get(&(2, 0))
            .cloned()
            .expect("non-pipelined local VRF output should be retained for reveal");

        assert_eq!(pipelined_commit.height, non_pipelined_commit.height);
        assert_eq!(pipelined_commit.round, non_pipelined_commit.round);
        assert_eq!(
            pipelined_commit.validator_id,
            non_pipelined_commit.validator_id
        );
        assert_eq!(pipelined_commit.vrf_pubkey, non_pipelined_commit.vrf_pubkey);
        assert_eq!(
            pipelined_commit.commit_hash,
            non_pipelined_commit.commit_hash
        );
        assert_eq!(pipelined_local.vrf_output, non_pipelined_local.vrf_output);
        assert_eq!(pipelined_local.vrf_proof, non_pipelined_local.vrf_proof);

        let _ = std::fs::remove_dir_all(&pipelined_dir);
        let _ = std::fs::remove_dir_all(&non_pipelined_dir);
    }

    #[test]
    fn vrf_commit_pipelining_skipped_on_restart_replay() {
        let (mut source, dir) = local_driver([0xCEu8; 32], "vrf_pipeline_restart_replay");
        let local = install_active_validator(&mut source, [0xCEu8; 32], "local");
        source.refresh_registered_voters();
        source.sync.mark_caught_up(source.height());

        let block1 = make_strict_block(&source, [0xCEu8; 32], 0, vec![]);
        source.engine.commit_block(&block1).unwrap();
        source.promote_block_header_qc(&block1, "test").unwrap();
        let qc_for_height_1 =
            single_validator_qc_bytes(&source, &local, 1, block1.header.block_hash());
        source
            .set_last_qc_bytes_if_newer(1, qc_for_height_1.clone())
            .unwrap();
        let block2 = make_strict_block(&source, [0xCEu8; 32], 0, qc_for_height_1);
        source.engine.commit_block(&block2).unwrap();

        let config = source.engine.config.clone();
        drop(source);

        let engine = NodeEngine::init(config).unwrap();
        assert_eq!(engine.state.height, 2);
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let restarted = ConsensusDriver::new(engine, vote_safety);

        assert_eq!(restarted.height(), 2);
        assert_eq!(restarted.highest_pipelined_vrf_commit_height, 2);
        assert!(
            restarted.local_vrf_rounds.is_empty(),
            "startup replay must not emit or retain historical pipelined VRF commits"
        );
        assert!(
            !restarted
                .vrf_states
                .iter()
                .filter_map(|state| state.as_ref())
                .any(|state| state.height <= restarted.height()),
            "replay should not route through live finalization/pipelining state"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vrf_reveal_without_prior_commit_is_not_accepted() {
        let (mut driver, dir) = local_driver([0x11; 32], "vrf_reveal_without_commit");
        install_active_validator(&mut driver, [0x21; 32], "peer");
        let height = driver.next_height();
        let round = driver.current_round;
        let election = election_for_round(&driver, height, round);
        driver.ensure_vrf_election_for_round(&election);
        let (_commit, reveal) =
            signed_vrf_pair(&driver, [0x21; 32], height, round, DEFAULT_CHAIN_ID);
        let slot = driver.vrf_slot_index(height, round).unwrap();
        let external_validator_id = reveal.validator_id;

        let actions = driver.process(DriverEvent::InboundVrfReveal {
            from: "127.0.0.1:10001".parse().unwrap(),
            reveal,
        });

        assert!(!actions
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastVrfReveal(_))));
        assert!(!driver.vrf_states[slot]
            .as_ref()
            .unwrap()
            .reveals
            .contains_key(&external_validator_id));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn vrf_reveal_commitment_mismatch_is_rejected() {
        let (mut driver, dir) = local_driver([0x12; 32], "vrf_commitment_mismatch");
        install_active_validator(&mut driver, [0x22; 32], "peer");
        let height = driver.next_height();
        let round = driver.current_round;
        let election = election_for_round(&driver, height, round);
        driver.ensure_vrf_election_for_round(&election);
        let (commit, mut reveal) =
            signed_vrf_pair(&driver, [0x22; 32], height, round, DEFAULT_CHAIN_ID);
        let external_validator_id = reveal.validator_id;
        reveal.commit_hash = Bytes32::from([0xEE; 32]);

        driver.process(DriverEvent::InboundVrfCommit {
            from: "127.0.0.1:10001".parse().unwrap(),
            commit,
        });
        let actions = driver.process(DriverEvent::InboundVrfReveal {
            from: "127.0.0.1:10001".parse().unwrap(),
            reveal,
        });

        assert!(!actions
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastVrfReveal(_))));
        let slot = driver.vrf_slot_index(height, round).unwrap();
        assert!(!driver.vrf_states[slot]
            .as_ref()
            .unwrap()
            .reveals
            .contains_key(&external_validator_id));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn vrf_reveal_with_invalid_proof_is_rejected() {
        let (mut driver, dir) = local_driver([0x13; 32], "vrf_invalid_proof");
        install_active_validator(&mut driver, [0x23; 32], "peer");
        let height = driver.next_height();
        let round = driver.current_round;
        let from: SocketAddr = "127.0.0.1:10001".parse().unwrap();
        let election = election_for_round(&driver, height, round);
        driver.ensure_vrf_election_for_round(&election);
        let (commit, mut reveal) =
            signed_vrf_pair(&driver, [0x23; 32], height, round, DEFAULT_CHAIN_ID);
        let external_validator_id = reveal.validator_id;
        let bad_proof = vec![0xAB; reveal.vrf_proof.as_slice().len().max(1)];
        reveal.vrf_proof = VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&bad_proof).unwrap();

        driver.process(DriverEvent::InboundVrfCommit { from, commit });
        let actions = driver.process(DriverEvent::InboundVrfReveal { from, reveal });

        assert!(!actions
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastVrfReveal(_))));
        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::DisconnectInvalidConsensusPeer { from: got, .. } if *got == from
        )));
        let slot = driver.vrf_slot_index(height, round).unwrap();
        assert!(!driver.vrf_states[slot]
            .as_ref()
            .unwrap()
            .reveals
            .contains_key(&external_validator_id));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_reveal_triggers_request_and_recovers() {
        let local_seed = [0xD1u8; 32];
        let seed_b = [0xD2u8; 32];
        let seed_c = [0xD3u8; 32];
        let seed_d = [0xD4u8; 32];
        let (mut driver, dir) = local_driver(local_seed, "vrf_reveal_recovery");
        let local = install_active_validator(&mut driver, local_seed, "local");
        let b = install_active_validator(&mut driver, seed_b, "b");
        let c = install_active_validator(&mut driver, seed_c, "c");
        let _d = install_active_validator(&mut driver, seed_d, "d");
        driver.refresh_registered_voters();
        driver.engine.state.height = u64::MAX - 1;
        driver.engine.state.tip_hash = Bytes32::from([0xA5; 32]);
        driver.sync.mark_caught_up(driver.engine.state.height);
        driver.start_round(0);

        let height = u64::MAX;
        let round = 0;
        let (commit_a, reveal_a) =
            signed_vrf_pair(&driver, local_seed, height, round, DEFAULT_CHAIN_ID);
        let (commit_b, reveal_b) =
            signed_vrf_pair(&driver, seed_b, height, round, DEFAULT_CHAIN_ID);
        let (commit_c, reveal_c) =
            signed_vrf_pair(&driver, seed_c, height, round, DEFAULT_CHAIN_ID);
        let mut block = reveal_set_block_from_reveals(
            &driver,
            &[local_seed, seed_b, seed_c, seed_d],
            &[reveal_a.clone(), reveal_b.clone(), reveal_c.clone()],
        );
        let parent_votes: Vec<_> = [&local, &b, &c]
            .iter()
            .map(|signer| {
                indra_consensus::vote::produce_vote(
                    driver.engine.state.height,
                    0,
                    VoteStep::Precommit,
                    driver.engine.state.tip_hash,
                    validator_id_for(signer),
                    DEFAULT_CHAIN_ID,
                    signer,
                )
                .unwrap()
            })
            .collect();
        let parent_vote_refs: Vec<_> = parent_votes.iter().collect();
        let parent_qc = build_qc(
            driver.engine.state.height,
            0,
            driver.engine.state.tip_hash,
            DEFAULT_CHAIN_ID,
            &driver.engine.qc_validators(),
            parent_vote_refs,
        )
        .unwrap();
        block.header.quorum_certificate =
            VariableBytes::from_slice(&parent_qc.encode_to_vec()).unwrap();
        let block_hash = block.header.block_hash();

        let mut round_state = VrfRoundState::new(height, round);
        round_state.commits.insert(commit_a.validator_id, commit_a);
        round_state.commits.insert(commit_b.validator_id, commit_b);
        round_state.commits.insert(commit_c.validator_id, commit_c);
        round_state.reveals.insert(reveal_a.validator_id, reveal_a);
        round_state.reveals.insert(reveal_b.validator_id, reveal_b);
        driver.vrf_states[0] = Some(round_state);

        let actions = driver.process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:9911".parse().unwrap()),
            block,
        });
        assert!(matches!(
            actions.as_slice(),
            [DriverAction::RequestVrfReveals {
                height: requested_height,
                round: requested_round,
                missing_validator_ids
            }] if *requested_height == height
                && *requested_round == round
                && missing_validator_ids == &vec![reveal_c.validator_id]
        ));
        assert!(
            driver.pending_block(&block_hash).is_none(),
            "block should be parked until specified reveal evidence is locally available"
        );

        let actions = driver.process(DriverEvent::VrfRevealsResponse {
            from: "127.0.0.1:9912".parse().unwrap(),
            height,
            round,
            reveals: vec![reveal_c],
        });
        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.height == height
                    && vote.round == round
                    && vote.step == VoteStep::Prevote
                    && vote.block_hash == block_hash
        )));
        assert!(
            driver.pending_block(&block_hash).is_some(),
            "recovered block should enter normal pending-block processing after reveal response"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn local_election_requires_quorum_reveal_set() {
        let local_seed = [0xD5u8; 32];
        let seed_b = [0xD6u8; 32];
        let seed_c = [0xD7u8; 32];
        let seed_d = [0xD8u8; 32];
        let (mut driver, dir) = local_driver(local_seed, "local_election_quorum_required");
        install_active_validator(&mut driver, local_seed, "local");
        install_active_validator(&mut driver, seed_b, "b");
        install_active_validator(&mut driver, seed_c, "c");
        install_active_validator(&mut driver, seed_d, "d");
        driver.refresh_registered_voters();
        driver.engine.state.height = u64::MAX - 1;
        driver.engine.state.tip_hash = Bytes32::from([0xEE; 32]);

        let height = u64::MAX;
        let round = 0;
        let (commit_a, reveal_a) =
            signed_vrf_pair(&driver, local_seed, height, round, DEFAULT_CHAIN_ID);
        let mut state = VrfRoundState::new(height, round);
        state.phase = VrfRoundPhase::Reveal;
        state.reveal_started_at =
            Some(Instant::now() - Duration::from_millis(VRF_REVEAL_WINDOW_MS + 10));
        state.commits.insert(commit_a.validator_id, commit_a);
        state.reveals.insert(reveal_a.validator_id, reveal_a);
        driver.vrf_states[0] = Some(state);

        let result = driver.compute_and_store_vrf_election(0);

        assert!(
            result.is_none(),
            "sub-quorum reveal set must remain pending, not produce a local election result"
        );
        assert!(driver.vrf_election_result(height, round).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sparse_reveal_election_triggers_reveal_request() {
        let local_seed = [0xD9u8; 32];
        let seed_b = [0xDAu8; 32];
        let seed_c = [0xDBu8; 32];
        let seed_d = [0xDCu8; 32];
        let (mut driver, dir) = local_driver(local_seed, "sparse_reveal_request");
        install_active_validator(&mut driver, local_seed, "local");
        let b = install_active_validator(&mut driver, seed_b, "b");
        let c = install_active_validator(&mut driver, seed_c, "c");
        let d = install_active_validator(&mut driver, seed_d, "d");
        driver.refresh_registered_voters();

        let height = u64::MAX;
        let round = 0;
        let (commit_a, reveal_a) =
            signed_vrf_pair(&driver, local_seed, height, round, DEFAULT_CHAIN_ID);
        let mut state = VrfRoundState::new(height, round);
        state.phase = VrfRoundPhase::Reveal;
        state.reveal_started_at =
            Some(Instant::now() - Duration::from_millis(VRF_REVEAL_WINDOW_MS + 10));
        state.commits.insert(commit_a.validator_id, commit_a);
        state.reveals.insert(reveal_a.validator_id, reveal_a);
        driver.vrf_states[0] = Some(state);

        let actions = driver.advance_vrf_round(height, round);
        let mut expected_missing = vec![
            validator_id_for(&b),
            validator_id_for(&c),
            validator_id_for(&d),
        ];
        expected_missing.sort_by_key(|id| id.0);

        assert!(matches!(
            actions.as_slice(),
            [DriverAction::RequestVrfReveals {
                height: requested_height,
                round: requested_round,
                missing_validator_ids
            }] if *requested_height == height
                && *requested_round == round
                && *missing_validator_ids == expected_missing
        ));
        assert!(driver.vrf_election_result(height, round).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sparse_reveal_request_is_debounced_until_retry_window_or_response() {
        let local_seed = [0xC9u8; 32];
        let seed_b = [0xCAu8; 32];
        let seed_c = [0xCBu8; 32];
        let seed_d = [0xCCu8; 32];
        let (mut driver, dir) = local_driver(local_seed, "sparse_reveal_request_debounce");
        install_active_validator(&mut driver, local_seed, "local");
        install_active_validator(&mut driver, seed_b, "b");
        install_active_validator(&mut driver, seed_c, "c");
        install_active_validator(&mut driver, seed_d, "d");
        driver.refresh_registered_voters();

        let height = u64::MAX;
        let round = 0;
        let (commit_a, reveal_a) =
            signed_vrf_pair(&driver, local_seed, height, round, DEFAULT_CHAIN_ID);
        let mut state = VrfRoundState::new(height, round);
        state.phase = VrfRoundPhase::Reveal;
        state.reveal_started_at =
            Some(Instant::now() - Duration::from_millis(VRF_REVEAL_WINDOW_MS + 10));
        state.commits.insert(commit_a.validator_id, commit_a);
        state.reveals.insert(reveal_a.validator_id, reveal_a);
        driver.vrf_states[0] = Some(state);

        let first = driver.advance_vrf_round(height, round);
        assert!(matches!(
            first.as_slice(),
            [DriverAction::RequestVrfReveals { .. }]
        ));
        let second = driver.advance_vrf_round(height, round);
        assert!(
            second.is_empty(),
            "identical sparse-reveal condition must not re-emit immediately"
        );

        for at in driver.requested_vrf_reveals.values_mut() {
            *at = Instant::now() - Duration::from_millis(ACTION_RETRY_DEBOUNCE_MS + 1);
        }
        let retry = driver.advance_vrf_round(height, round);
        assert!(
            retry
                .iter()
                .any(|action| matches!(action, DriverAction::RequestVrfReveals { .. })),
            "same request should be allowed again after debounce window"
        );

        let _ = driver.process(DriverEvent::VrfRevealsResponse {
            from: "127.0.0.1:9914".parse().unwrap(),
            height,
            round,
            reveals: vec![],
        });
        assert!(
            driver.requested_vrf_reveals.is_empty(),
            "response path clears in-flight reveal request debounce state"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn election_completes_after_reveal_recovery() {
        let local_seed = [0xDDu8; 32];
        let seed_b = [0xDEu8; 32];
        let seed_c = [0xDFu8; 32];
        let seed_d = [0xE0u8; 32];
        let (mut driver, dir) = local_driver(local_seed, "sparse_reveal_recovers");
        install_active_validator(&mut driver, local_seed, "local");
        install_active_validator(&mut driver, seed_b, "b");
        install_active_validator(&mut driver, seed_c, "c");
        install_active_validator(&mut driver, seed_d, "d");
        driver.refresh_registered_voters();
        driver.engine.state.height = u64::MAX - 1;
        driver.engine.state.tip_hash = Bytes32::from([0xEF; 32]);

        let height = u64::MAX;
        let round = 0;
        let (commit_a, reveal_a) =
            signed_vrf_pair(&driver, local_seed, height, round, DEFAULT_CHAIN_ID);
        let (commit_b, reveal_b) =
            signed_vrf_pair(&driver, seed_b, height, round, DEFAULT_CHAIN_ID);
        let (commit_c, reveal_c) =
            signed_vrf_pair(&driver, seed_c, height, round, DEFAULT_CHAIN_ID);
        let mut state = VrfRoundState::new(height, round);
        state.phase = VrfRoundPhase::Reveal;
        state.reveal_started_at =
            Some(Instant::now() - Duration::from_millis(VRF_REVEAL_WINDOW_MS + 10));
        state.commits.insert(commit_a.validator_id, commit_a);
        state.commits.insert(commit_b.validator_id, commit_b);
        state.commits.insert(commit_c.validator_id, commit_c);
        state
            .reveals
            .insert(reveal_a.validator_id, reveal_a.clone());
        driver.vrf_states[0] = Some(state);

        let actions = driver.advance_vrf_round(height, round);
        assert!(actions
            .iter()
            .any(|action| matches!(action, DriverAction::RequestVrfReveals { .. })));

        let _actions = driver.process(DriverEvent::VrfRevealsResponse {
            from: "127.0.0.1:9913".parse().unwrap(),
            height,
            round,
            reveals: vec![reveal_b.clone(), reveal_c.clone()],
        });
        let result = driver
            .vrf_election_result(height, round)
            .expect("quorum reveal recovery should complete local election");
        assert!(!result.fallback_used);

        let block = reveal_set_block_from_reveals(
            &driver,
            &[local_seed, seed_b, seed_c, seed_d],
            &[reveal_a, reveal_b, reveal_c],
        );
        assert_eq!(block.header.election_result_hash, Some(result.hash()));
        assert!(
            crate::sync::verify_reveal_set_evidence(&block, &driver.engine.state).is_ok(),
            "quorum-backed reveal evidence should be independently verifiable"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn restart_sparse_reveal_cache_does_not_produce_self_rejecting_proposal() {
        let local_seed = [0xE1u8; 32];
        let seed_b = [0xE2u8; 32];
        let seed_c = [0xE3u8; 32];
        let seed_d = [0xE4u8; 32];
        let (mut driver, dir) = local_driver(local_seed, "restart_sparse_reveals");
        install_active_validator(&mut driver, local_seed, "local");
        let b = install_active_validator(&mut driver, seed_b, "b");
        let c = install_active_validator(&mut driver, seed_c, "c");
        let d = install_active_validator(&mut driver, seed_d, "d");
        driver.refresh_registered_voters();
        driver.engine.state.height = u64::MAX - 1;
        driver.engine.state.tip_hash = Bytes32::from([0xE5; 32]);
        driver.sync.mark_caught_up(driver.engine.state.height);
        driver.start_round(0);

        let height = u64::MAX;
        let round = 0;
        let (commit_a, reveal_a) =
            signed_vrf_pair(&driver, local_seed, height, round, DEFAULT_CHAIN_ID);
        let mut state = VrfRoundState::new(height, round);
        state.phase = VrfRoundPhase::Reveal;
        state.reveal_started_at =
            Some(Instant::now() - Duration::from_millis(VRF_REVEAL_WINDOW_MS + 10));
        state.commits.insert(commit_a.validator_id, commit_a);
        state.reveals.insert(reveal_a.validator_id, reveal_a);
        driver.vrf_states[0] = Some(state);

        let actions = driver.advance_vrf_round(height, round);
        let mut expected_missing = vec![
            validator_id_for(&b),
            validator_id_for(&c),
            validator_id_for(&d),
        ];
        expected_missing.sort_by_key(|id| id.0);

        assert!(driver.vrf_election_result(height, round).is_none());
        assert!(matches!(
            actions.as_slice(),
            [DriverAction::RequestVrfReveals {
                height: requested_height,
                round: requested_round,
                missing_validator_ids
            }] if *requested_height == height
                && *requested_round == round
                && *missing_validator_ids == expected_missing
        ));

        let election = election_for_round(&driver, height, round);
        let last_qc_bytes = driver.last_qc_bytes();
        let election_result_hash = driver
            .vrf_election_result(height, round)
            .map(|result| result.hash());
        let vrf_reveals = driver.vrf_reveal_evidence(height, round);
        let proposal = driver.engine.propose(
            &election,
            1_900_000_001,
            last_qc_bytes,
            None,
            election_result_hash,
            vrf_reveals,
        );
        assert!(
            proposal.is_err(),
            "post-activation proposal must not be produced without a quorum-backed election hash"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn invalid_vrf_commit_signature_triggers_disconnect_not_ban() {
        let (mut driver, dir) = local_driver([0x15; 32], "vrf_bad_commit_sig");
        install_active_validator(&mut driver, [0x25; 32], "peer");
        let height = driver.next_height();
        let round = driver.current_round;
        let from: SocketAddr = "127.0.0.1:10002".parse().unwrap();
        let election = election_for_round(&driver, height, round);
        driver.ensure_vrf_election_for_round(&election);
        let (mut commit, _reveal) =
            signed_vrf_pair(&driver, [0x25; 32], height, round, DEFAULT_CHAIN_ID);
        commit.signature = ConsensusDriver::empty_signature().unwrap();
        let validator_id = commit.validator_id;

        let actions = driver.process(DriverEvent::InboundVrfCommit { from, commit });

        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::DisconnectInvalidConsensusPeer {
                from: got,
                validator_id: claimed,
                reason
            } if *got == from
                && *claimed == validator_id
                && reason.contains("signature")
        )));
        assert!(!actions
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastVrfCommit(_))));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn far_future_vrf_commit_dropped_before_signature_verification() {
        let (mut driver, dir) = local_driver([0x16; 32], "vrf_future_commit");
        install_active_validator(&mut driver, [0x26; 32], "peer");
        let height = driver.next_height() + 99;
        let round = driver.current_round;
        let from: SocketAddr = "127.0.0.1:10003".parse().unwrap();
        let (mut commit, _reveal) =
            signed_vrf_pair(&driver, [0x26; 32], height, round, DEFAULT_CHAIN_ID);
        commit.signature = ConsensusDriver::empty_signature().unwrap();

        let actions = driver.process(DriverEvent::InboundVrfCommit { from, commit });

        assert!(
            actions.iter().all(|action| !matches!(
                action,
                DriverAction::DisconnectInvalidConsensusPeer { .. }
                    | DriverAction::BroadcastVrfCommit(_)
            )),
            "far-future commits must be cheap-dropped at the slot check before signature verification"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn vrf_commit_for_wrong_chain_is_rejected() {
        let (mut driver, dir) = local_driver([0x14; 32], "vrf_wrong_chain");
        let height = driver.next_height();
        let round = driver.current_round;
        let election = election_for_round(&driver, height, round);
        driver.ensure_vrf_election_for_round(&election);
        let (commit, _reveal) = signed_vrf_pair(&driver, [0x14; 32], height, round, "other-chain");

        let actions = driver.process(DriverEvent::InboundVrfCommit {
            from: "127.0.0.1:10001".parse().unwrap(),
            commit,
        });

        assert!(!actions
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastVrfCommit(_))));
        let _ = std::fs::remove_dir_all(dir);
    }

    fn pick_tip_hash_for_round_winners(
        driver: &ConsensusDriver,
        height: u64,
        round_zero_winner: Bytes32,
        round_one_winner: Bytes32,
    ) -> Bytes32 {
        for nonce in 0u16..=u16::MAX {
            let mut tip = [0u8; 32];
            tip[..2].copy_from_slice(&nonce.to_le_bytes());
            let tip_hash = Bytes32::from(tip);
            let epoch_seed = Bytes32::from(indra_crypto::sha256(&tip_hash.0));
            let candidates: Vec<indra_consensus::proposer::ProposerCandidate> = driver
                .engine
                .state
                .validators
                .active_validators()
                .filter_map(|v| {
                    v.vrf_pk
                        .map(|vrf_pk| indra_consensus::proposer::ProposerCandidate {
                            validator_id: v.validator_id,
                            vrf_pubkey: vrf_pk,
                            verified_vrf_output: None,
                            stake: v.stake_spark,
                        })
                })
                .collect();
            let election_round_zero = indra_consensus::proposer::ProposerElection {
                epoch_seed,
                height,
                round: 0,
                candidates: candidates.clone(),
            };
            let election_round_one = indra_consensus::proposer::ProposerElection {
                epoch_seed,
                height,
                round: 1,
                candidates,
            };
            if indra_consensus::proposer::elect_proposer(
                &election_round_zero,
                election_round_zero.height,
            )
            .ok()
                == Some(round_zero_winner)
                && indra_consensus::proposer::elect_proposer(
                    &election_round_one,
                    election_round_one.height,
                )
                .ok()
                    == Some(round_one_winner)
            {
                return tip_hash;
            }
        }
        panic!("failed to find deterministic tip hash for requested round winners");
    }

    fn validator_id_for_seed(seed: [u8; 32]) -> Bytes32 {
        let keypair = HybridKeypair::new(
            ClassicalKeypair::from_seed(&seed),
            PqKeypair::from_seed(&seed).unwrap(),
        );
        Bytes32::from(indra_crypto::sha256(&keypair.public_key().classical.0))
    }

    fn pick_tip_hash_for_verified_round_winners(
        driver: &ConsensusDriver,
        height: u64,
        round_zero_seed: [u8; 32],
        round_one_seed: [u8; 32],
    ) -> Bytes32 {
        let round_zero_winner = validator_id_for_seed(round_zero_seed);
        let round_one_winner = validator_id_for_seed(round_one_seed);
        for nonce in 0u16..=u16::MAX {
            let mut tip = [0u8; 32];
            tip[..2].copy_from_slice(&nonce.to_le_bytes());
            let tip_hash = Bytes32::from(tip);
            let epoch_seed = Bytes32::from(indra_crypto::sha256(&tip_hash.0));
            let candidates: Vec<indra_consensus::proposer::ProposerCandidate> = driver
                .engine
                .state
                .validators
                .active_validators()
                .filter_map(|v| {
                    v.vrf_pk
                        .map(|vrf_pk| indra_consensus::proposer::ProposerCandidate {
                            validator_id: v.validator_id,
                            vrf_pubkey: vrf_pk,
                            verified_vrf_output: None,
                            stake: v.stake_spark,
                        })
                })
                .collect();
            let election_round_zero = indra_consensus::proposer::ProposerElection {
                epoch_seed,
                height,
                round: 0,
                candidates: candidates.clone(),
            };
            let election_round_one = indra_consensus::proposer::ProposerElection {
                epoch_seed,
                height,
                round: 1,
                candidates,
            };

            if elect_with_verified_output_for_seed(&election_round_zero, round_zero_seed)
                == Some(round_zero_winner)
                && elect_with_verified_output_for_seed(&election_round_one, round_one_seed)
                    == Some(round_one_winner)
            {
                return tip_hash;
            }
        }
        panic!("failed to find deterministic tip hash for requested verified round winners");
    }

    fn pick_tip_hash_for_verified_winner(
        driver: &ConsensusDriver,
        height: u64,
        round: u32,
        proposer_seed: [u8; 32],
    ) -> Bytes32 {
        let proposer_id = validator_id_for_seed(proposer_seed);
        for nonce in 0u16..=u16::MAX {
            let mut tip = [0u8; 32];
            tip[..2].copy_from_slice(&nonce.to_le_bytes());
            let tip_hash = Bytes32::from(tip);
            let epoch_seed = Bytes32::from(indra_crypto::sha256(&tip_hash.0));
            let candidates: Vec<indra_consensus::proposer::ProposerCandidate> = driver
                .engine
                .state
                .validators
                .active_validators()
                .filter_map(|v| {
                    v.vrf_pk
                        .map(|vrf_pk| indra_consensus::proposer::ProposerCandidate {
                            validator_id: v.validator_id,
                            vrf_pubkey: vrf_pk,
                            verified_vrf_output: None,
                            stake: v.stake_spark,
                        })
                })
                .collect();
            let election = indra_consensus::proposer::ProposerElection {
                epoch_seed,
                height,
                round,
                candidates,
            };
            if elect_with_verified_output_for_seed(&election, proposer_seed) == Some(proposer_id) {
                return tip_hash;
            }
        }
        panic!("failed to find deterministic tip hash for requested verified winner");
    }

    #[test]
    fn single_validator_block_commits_immediately() {
        let (mut driver, dir) = local_driver([0x41u8; 32], "single_commit");
        let _local = install_active_validator(&mut driver, [0x41u8; 32], "local");
        driver.refresh_registered_voters();

        let block = make_strict_block(&driver, [0x41u8; 32], 0, vec![]);
        let actions = driver.process(DriverEvent::InboundBlock { from: None, block });

        assert!(actions
            .iter()
            .any(|a| matches!(a, DriverAction::BroadcastBlock(_))));
        assert_eq!(driver.height(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn votes_are_cast_for_full_block_hash_not_value_hash() {
        let (mut driver, dir) = local_driver([0x8Au8; 32], "vote_full_hash");
        let _local = install_active_validator(&mut driver, [0x8Au8; 32], "local");
        driver.refresh_registered_voters();

        let block = make_strict_block(&driver, [0x8Au8; 32], 0, vec![]);
        let full_hash = block.header.block_hash();
        let value_hash = block.header.value_hash;
        assert_ne!(
            full_hash, value_hash,
            "test requires full block hash to differ from value hash"
        );

        let actions = driver.process(DriverEvent::InboundBlock {
            from: None,
            block: block.clone(),
        });
        let vote = actions
            .iter()
            .find_map(|action| match action {
                DriverAction::BroadcastVote(vote) => Some(vote),
                _ => None,
            })
            .expect("proposal should trigger a prevote");

        assert_eq!(vote.block_hash, full_hash);
        assert_ne!(vote.block_hash, value_hash);

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
            Bytes32::from(indra_crypto::sha256(&a.public_key().classical.0)),
            Bytes32::from(indra_crypto::sha256(&b.public_key().classical.0)),
            Bytes32::from(indra_crypto::sha256(&c.public_key().classical.0)),
            Bytes32::from(indra_crypto::sha256(&d.public_key().classical.0)),
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
        driver.engine.state.tip_hash =
            pick_tip_hash_for_verified_winner(&driver, 1, 0, [0x42u8; 32]);
        let block = make_strict_block(&driver, [0x42u8; 32], 0, vec![]);
        let block_hash = block.header.block_hash();

        let remote_a_id = Bytes32::from(indra_crypto::sha256(&remote_a.public_key().classical.0));
        let remote_b_id = Bytes32::from(indra_crypto::sha256(&remote_b.public_key().classical.0));

        let prevote_a = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Prevote,
            block_hash,
            remote_a_id,
            DEFAULT_CHAIN_ID,
            &remote_a,
        )
        .unwrap();
        let prevote_b = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Prevote,
            block_hash,
            remote_b_id,
            DEFAULT_CHAIN_ID,
            &remote_b,
        )
        .unwrap();
        let precommit_a = indra_consensus::vote::produce_vote_with_election_result(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            remote_a_id,
            block.header.election_result_hash,
            DEFAULT_CHAIN_ID,
            &remote_a,
        )
        .unwrap();
        let precommit_b = indra_consensus::vote::produce_vote_with_election_result(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            remote_b_id,
            block.header.election_result_hash,
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

        seed_vrf_result_for_seed(&mut driver, 1, 0, [0x42u8; 32]);
        let mut actions = driver.process(DriverEvent::InboundBlock {
            from: Some(peer_a),
            block,
        });
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
        let actions = driver.process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:9201".parse().unwrap()),
            block,
        });

        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == block_hash
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposal_drives_round_advancement() {
        let (mut driver, dir) = local_driver([0x4Fu8; 32], "proposal_round_advance");
        install_active_validator(&mut driver, [0x4Fu8; 32], "validator");
        driver.refresh_registered_voters();

        let block = make_strict_block(&driver, [0x4Fu8; 32], 5, vec![]);
        let block_hash = block.header.block_hash();
        let actions = driver.process(DriverEvent::InboundBlock { from: None, block });

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
        let _actions = driver.process(DriverEvent::InboundBlock { from: None, block });

        assert_eq!(driver.current_round(), 10);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposal_round_jump_skips_past_voted_rounds() {
        let (mut driver, dir) = local_driver([0x51u8; 32], "proposal_round_vote_safety");
        let _local = install_active_validator(&mut driver, [0x51u8; 32], "local");
        driver.refresh_registered_voters();
        driver.vote_safety.record(1, 5, 0).unwrap();

        let block = make_strict_block(&driver, [0x51u8; 32], 5, vec![]);
        let actions = driver.process(DriverEvent::InboundBlock { from: None, block });

        assert_eq!(driver.current_round(), 6);
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
    fn process_status_advances_round_when_peer_is_ahead() {
        let (mut driver, dir) = local_driver([0x4Au8; 32], "status_round_advance");
        let peer: SocketAddr = "127.0.0.1:9301".parse().unwrap();

        driver.process(DriverEvent::PeerStatus {
            from: peer,
            height: 1,
            tip_hash: driver.engine.state.tip_hash,
            round: 8,
        });

        assert_eq!(driver.current_round(), 8);
        assert_eq!(driver.current_phase(), RoundPhase::Propose);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_status_round_jump_is_capped() {
        let (mut driver, dir) = local_driver([0x8Au8; 32], "status_round_cap");
        driver.current_round = 5;
        let peer: SocketAddr = "127.0.0.1:9401".parse().unwrap();

        driver.process(DriverEvent::PeerStatus {
            from: peer,
            height: 1,
            tip_hash: driver.engine.state.tip_hash,
            round: 1_358,
        });

        assert_eq!(driver.current_round(), 5 + MAX_ACCEPTED_ROUND_JUMP);
        assert_eq!(driver.current_phase(), RoundPhase::Propose);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_status_normal_round_advance_still_works() {
        let (mut driver, dir) = local_driver([0x8Bu8; 32], "status_round_normal");
        driver.current_round = 5;
        let peer: SocketAddr = "127.0.0.1:9402".parse().unwrap();

        driver.process(DriverEvent::PeerStatus {
            from: peer,
            height: 1,
            tip_hash: driver.engine.state.tip_hash,
            round: 6,
        });

        assert_eq!(driver.current_round(), 6);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_status_repeated_messages_can_eventually_catch_up() {
        let (mut driver, dir) = local_driver([0x8Cu8; 32], "status_round_repeated");
        driver.current_round = 5;
        let peer: SocketAddr = "127.0.0.1:9403".parse().unwrap();

        while driver.current_round() < 29 {
            driver.sync.mark_caught_up(driver.height());
            driver.process(DriverEvent::PeerStatus {
                from: peer,
                height: 1,
                tip_hash: driver.engine.state.tip_hash,
                round: 29,
            });
        }

        assert_eq!(driver.current_round(), 29);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn process_status_does_not_retreat_round() {
        let (mut driver, dir) = local_driver([0x4Bu8; 32], "status_round_no_retreat");
        driver.current_round = 10;
        let peer: SocketAddr = "127.0.0.1:9302".parse().unwrap();

        driver.process(DriverEvent::PeerStatus {
            from: peer,
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
        driver.engine.state.tip_hash = pick_tip_hash_for_round_winners(
            &driver,
            1,
            driver.engine.validator_id().unwrap(),
            driver.engine.validator_id().unwrap(),
        );

        let block = make_strict_block(&driver, [0x97u8; 32], 0, vec![]);
        let actions = driver.process(DriverEvent::InboundBlock { from: None, block });

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
        driver.vote_safety.record(5, 7, 0).unwrap();

        driver.apply_vote_safety();

        assert_eq!(driver.current_round(), 8);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_vote_safety_ignores_old_height() {
        let (mut driver, dir) = local_driver([0x4Eu8; 32], "vote_safety_old_height");
        driver.engine.state.height = 5;
        driver.vote_safety.record(3, 10, 0).unwrap();

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
        driver.vote_safety.record(1, 2, 0).unwrap();
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
    fn precommit_delayed_when_election_result_unavailable() {
        let (mut driver, dir) = local_driver([0x75u8; 32], "precommit_missing_erh_delay");
        let _local = install_active_validator(&mut driver, [0x75u8; 32], "local");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());
        driver.current_phase = RoundPhase::Precommit;
        driver.current_round = 0;
        driver.precommit_phase_started_at = Some(Instant::now());
        driver.vrf_states[0] = Some(VrfRoundState::new(1, 0));

        let block = make_strict_block(&driver, [0x75u8; 32], 0, vec![]);
        let block_hash = block.header.block_hash();
        driver.pending_blocks.insert(block_hash, block);

        let actions = driver.sign_and_record_local_vote(1, 0, VoteStep::Precommit, block_hash);
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, DriverAction::BroadcastVote(_))),
            "fresh precommit phase should delay rather than casting nil immediately"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nil_precommit_cast_after_settle_window() {
        let (mut driver, dir) = local_driver([0x75u8; 32], "precommit_missing_erh_nil");
        let _local = install_active_validator(&mut driver, [0x75u8; 32], "local");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());
        driver.current_phase = RoundPhase::Precommit;
        driver.current_round = 0;
        driver.precommit_phase_started_at = Some(
            Instant::now() - Duration::from_millis(VRF_ELECTION_SETTLE_MS.saturating_add(500)),
        );
        driver.vrf_states[0] = Some(VrfRoundState::new(1, 0));

        let block = make_strict_block(&driver, [0x75u8; 32], 0, vec![]);
        let block_hash = block.header.block_hash();
        driver.pending_blocks.insert(block_hash, block);

        let actions = driver.sign_and_record_local_vote(1, 0, VoteStep::Precommit, block_hash);
        let vote = actions
            .iter()
            .find_map(|action| match action {
                DriverAction::BroadcastVote(vote) => Some(vote),
                _ => None,
            })
            .expect("settle timeout should produce a safe nil precommit");

        assert_eq!(vote.block_hash, Bytes32::ZERO);
        assert_eq!(vote.election_result_hash, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn block_precommit_cast_when_election_result_arrives_during_wait() {
        let (mut driver, dir) = local_driver([0x76u8; 32], "precommit_erh_arrives");
        let _local = install_active_validator(&mut driver, [0x76u8; 32], "local");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());
        driver.current_phase = RoundPhase::Precommit;
        driver.current_round = 0;
        driver.precommit_phase_started_at = Some(Instant::now());
        driver.vrf_states[0] = Some(VrfRoundState::new(1, 0));
        let block = make_strict_block(&driver, [0x76u8; 32], 0, vec![]);
        let block_hash = block.header.block_hash();
        driver.pending_blocks.insert(block_hash, block);

        let delayed = driver.sign_and_record_local_vote(1, 0, VoteStep::Precommit, block_hash);
        assert!(
            !delayed
                .iter()
                .any(|action| matches!(action, DriverAction::BroadcastVote(_))),
            "precommit should wait while election result is missing"
        );

        seed_vrf_result_for_seed(&mut driver, 1, 0, [0x76u8; 32]);
        let expected_hash = driver.vrf_election_result(1, 0).unwrap().hash();
        let actions = driver.sign_and_record_local_vote(1, 0, VoteStep::Precommit, block_hash);
        let vote = actions
            .iter()
            .find_map(|action| match action {
                DriverAction::BroadcastVote(vote) => Some(vote),
                _ => None,
            })
            .expect("available VRF election result should produce a block precommit");

        assert_eq!(vote.block_hash, block_hash);
        assert_eq!(vote.election_result_hash, Some(expected_hash));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn precommit_quorum_not_declared_when_election_result_hash_disagrees() {
        let (mut driver, dir) = local_driver([0xA1u8; 32], "precommit_erh_disagree");
        let local = install_active_validator(&mut driver, [0xA1u8; 32], "local");
        let a = install_active_validator(&mut driver, [0xA2u8; 32], "a");
        let b = install_active_validator(&mut driver, [0xA3u8; 32], "b");
        let c = install_active_validator(&mut driver, [0xA4u8; 32], "c");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());

        seed_vrf_result_for_seed(&mut driver, 1, 0, [0xA1u8; 32]);
        let block = make_strict_block(&driver, [0xA1u8; 32], 0, vec![]);
        let block_hash = block.header.block_hash();
        let erh_a = block.header.election_result_hash;
        let erh_b = Some(Bytes32::from([0xBEu8; 32]));
        driver.pending_blocks.insert(block_hash, block);

        let signers = [
            (&local, validator_id_for(&local), erh_a),
            (&a, validator_id_for(&a), erh_a),
            (&b, validator_id_for(&b), erh_b),
            (&c, validator_id_for(&c), erh_b),
        ];
        let mut collector = VoteCollector::new(
            1,
            0,
            VoteStep::Precommit,
            DEFAULT_CHAIN_ID.to_string(),
            driver.registered_voters.clone(),
        );
        for (signer, validator_id, election_result_hash) in signers {
            let vote = indra_consensus::vote::produce_vote_with_election_result(
                1,
                0,
                VoteStep::Precommit,
                block_hash,
                validator_id,
                election_result_hash,
                DEFAULT_CHAIN_ID,
                signer,
            )
            .unwrap();
            let _ = collector.add_vote(vote).unwrap();
        }
        driver
            .vote_collectors
            .insert((1, 0, VoteStep::Precommit), collector);

        let actions = driver.finalize_block_on_quorum(1, 0, block_hash);
        assert_eq!(driver.height(), 0);
        assert!(driver.pending_block(&block_hash).is_some());
        assert!(!actions
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastBlock(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn precommit_quorum_declared_when_election_result_hash_agrees() {
        let (mut driver, dir) = local_driver([0xA5u8; 32], "precommit_erh_agree");
        let local = install_active_validator(&mut driver, [0xA5u8; 32], "local");
        let a = install_active_validator(&mut driver, [0xA6u8; 32], "a");
        let b = install_active_validator(&mut driver, [0xA7u8; 32], "b");
        let _c = install_active_validator(&mut driver, [0xA8u8; 32], "c");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());

        seed_vrf_result_for_seed(&mut driver, 1, 0, [0xA5u8; 32]);
        let block = make_strict_block(&driver, [0xA5u8; 32], 0, vec![]);
        let block_hash = block.header.block_hash();
        let erh = block.header.election_result_hash;
        driver.pending_blocks.insert(block_hash, block);

        let signers = [
            (&local, validator_id_for(&local)),
            (&a, validator_id_for(&a)),
            (&b, validator_id_for(&b)),
        ];
        let mut collector = VoteCollector::new(
            1,
            0,
            VoteStep::Precommit,
            DEFAULT_CHAIN_ID.to_string(),
            driver.registered_voters.clone(),
        );
        for (signer, validator_id) in signers {
            let vote = indra_consensus::vote::produce_vote_with_election_result(
                1,
                0,
                VoteStep::Precommit,
                block_hash,
                validator_id,
                erh,
                DEFAULT_CHAIN_ID,
                signer,
            )
            .unwrap();
            let _ = collector.add_vote(vote).unwrap();
        }
        driver
            .vote_collectors
            .insert((1, 0, VoteStep::Precommit), collector);

        let actions = driver.finalize_block_on_quorum(1, 0, block_hash);
        assert_eq!(driver.height(), 1);
        assert!(actions
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastBlock(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nil_precommit_quorum_not_affected_by_election_result_hash() {
        let (mut driver, dir) = local_driver([0xA9u8; 32], "nil_precommit_erh");
        let local = install_active_validator(&mut driver, [0xA9u8; 32], "local");
        let a = install_active_validator(&mut driver, [0xAAu8; 32], "a");
        let b = install_active_validator(&mut driver, [0xABu8; 32], "b");
        let _c = install_active_validator(&mut driver, [0xACu8; 32], "c");
        driver.refresh_registered_voters();

        let mut collector = VoteCollector::new(
            1,
            0,
            VoteStep::Precommit,
            DEFAULT_CHAIN_ID.to_string(),
            driver.registered_voters.clone(),
        );
        for signer in [&local, &a, &b] {
            let vote = indra_consensus::vote::produce_vote(
                1,
                0,
                VoteStep::Precommit,
                Bytes32::ZERO,
                validator_id_for(signer),
                DEFAULT_CHAIN_ID,
                signer,
            )
            .unwrap();
            match collector.add_vote(vote).unwrap() {
                VoteDecision::Waiting => {}
                VoteDecision::QuorumReached { block_hash, .. } => {
                    assert_eq!(block_hash, Bytes32::ZERO);
                }
            }
        }
        assert!(matches!(
            collector.current_decision(),
            VoteDecision::QuorumReached {
                block_hash,
                stake_bps: _
            } if block_hash == Bytes32::ZERO
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fallback_policy_matches_documented_behavior() {
        let (mut driver, dir) = local_driver([0xADu8; 32], "vrf_empty_fallback_threshold");
        install_active_validator(&mut driver, [0xADu8; 32], "local");
        install_active_validator(&mut driver, [0xAEu8; 32], "a");
        install_active_validator(&mut driver, [0xAFu8; 32], "b");
        install_active_validator(&mut driver, [0xB0u8; 32], "c");
        driver.refresh_registered_voters();

        for round in 0..MAX_VRF_EMPTY_REVEAL_ROUNDS {
            let mut state = VrfRoundState::new(1, round);
            state.phase = VrfRoundPhase::Reveal;
            state.reveal_started_at =
                Some(Instant::now() - Duration::from_millis(VRF_REVEAL_WINDOW_MS + 10));
            driver.vrf_states[0] = Some(state);

            let result = driver.compute_and_store_vrf_election(0);
            if round + 1 < MAX_VRF_EMPTY_REVEAL_ROUNDS {
                assert!(
                    result.is_none(),
                    "fallback must wait until the configured empty-round threshold"
                );
            } else {
                let result = result.expect("fallback should be produced at threshold");
                assert!(result.fallback_used);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn consecutive_empty_rounds_counter_resets_on_successful_reveal() {
        let (mut driver, dir) = local_driver([0xB1u8; 32], "vrf_empty_counter_reset");
        install_active_validator(&mut driver, [0xB1u8; 32], "local");
        install_active_validator(&mut driver, [0xB2u8; 32], "a");
        install_active_validator(&mut driver, [0xB3u8; 32], "b");
        install_active_validator(&mut driver, [0xB4u8; 32], "c");
        driver.refresh_registered_voters();
        driver.consecutive_empty_reveal_rounds = MAX_VRF_EMPTY_REVEAL_ROUNDS - 1;

        let (_commit, reveal) = signed_vrf_pair(&driver, [0xB1u8; 32], 1, 0, DEFAULT_CHAIN_ID);
        let mut state = VrfRoundState::new(1, 0);
        state.phase = VrfRoundPhase::Reveal;
        state.reveal_started_at =
            Some(Instant::now() - Duration::from_millis(VRF_REVEAL_WINDOW_MS + 10));
        state.reveals.insert(reveal.validator_id, reveal);
        driver.vrf_states[0] = Some(state);

        let result = driver
            .compute_and_store_vrf_election(0)
            .expect("successful reveal should compute an election result");
        assert!(!result.fallback_used);
        assert_eq!(driver.consecutive_empty_reveal_rounds, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_nil_precommit_without_election_result_hash_is_rejected_when_active() {
        let (mut driver, dir) = local_driver([0x77u8; 32], "reject_missing_erh_precommit");
        let _local = install_active_validator(&mut driver, [0x77u8; 32], "local");
        let remote = install_active_validator(&mut driver, [0x78u8; 32], "remote");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());
        let block = make_strict_block(&driver, [0x77u8; 32], 0, vec![]);
        let block_hash = block.header.block_hash();
        driver.pending_blocks.insert(block_hash, block);
        let remote_id = Bytes32::from(indra_crypto::sha256(&remote.public_key().classical.0));
        let vote = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            remote_id,
            DEFAULT_CHAIN_ID,
            &remote,
        )
        .unwrap();

        let actions = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9777".parse().unwrap(),
            vote,
        });

        assert!(actions.iter().any(|action| {
            matches!(
                action,
                DriverAction::DisconnectInvalidConsensusPeer { reason, .. }
                    if reason.contains("missing election_result_hash")
            )
        }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nil_precommit_without_election_result_hash_still_allowed() {
        let (mut driver, dir) = local_driver([0x79u8; 32], "nil_precommit_no_erh");
        let _local = install_active_validator(&mut driver, [0x79u8; 32], "local");
        let remote = install_active_validator(&mut driver, [0x7Au8; 32], "remote");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());
        let remote_id = Bytes32::from(indra_crypto::sha256(&remote.public_key().classical.0));
        let vote = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Precommit,
            Bytes32::ZERO,
            remote_id,
            DEFAULT_CHAIN_ID,
            &remote,
        )
        .unwrap();

        let actions = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9778".parse().unwrap(),
            vote,
        });

        assert!(!actions.iter().any(|action| {
            matches!(action, DriverAction::DisconnectInvalidConsensusPeer { .. })
        }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn driver_detects_double_precommit() {
        let (mut driver, dir) = local_driver([0x48u8; 32], "double_precommit");
        let remote = install_active_validator(&mut driver, [0x49u8; 32], "remote");
        driver.refresh_registered_voters();

        let remote_id = Bytes32::from(indra_crypto::sha256(&remote.public_key().classical.0));
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
        let _ = driver.process(DriverEvent::InboundBlock { from: None, block });

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
        let _ = source.process(DriverEvent::InboundBlock {
            from: None,
            block: block1.clone(),
        });
        let qc_for_height_1 = source.last_qc_bytes();
        assert!(!qc_for_height_1.is_empty());
        let block2 = make_strict_block(&source, [0xA3u8; 32], 0, qc_for_height_1.clone());

        let (mut driver, dir) = local_driver([0xA3u8; 32], "sync_promote_importer");
        let local = install_active_validator(&mut driver, [0xA3u8; 32], "local");
        driver.refresh_registered_voters();

        driver.engine.commit_block(&block1).unwrap();
        driver.promote_block_header_qc(&block1, "sync").unwrap();
        driver.engine.commit_block(&block2).unwrap();
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
        let _ = source.process(DriverEvent::InboundBlock {
            from: None,
            block: block1.clone(),
        });
        let qc_for_height_1 = source.last_qc_bytes();
        let block2 = make_strict_block(&source, [0xB5u8; 32], 0, qc_for_height_1.clone());

        let (mut driver, dir) = local_driver([0xB5u8; 32], "sync_transition_importer");
        let local = install_active_validator(&mut driver, [0xB5u8; 32], "local");
        driver.refresh_registered_voters();

        for block in [&block1, &block2] {
            driver.engine.commit_block(block).unwrap();
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
        assert!(
            driver
                .engine
                .propose(
                    &election_for_round(&driver, 3, 0),
                    1_700_000_003,
                    driver.last_qc_bytes(),
                    None,
                    None,
                    vec![],
                )
                .is_ok(),
            "recovered current-tip QC should allow height-3 proposal construction"
        );

        drop(local);
        let _ = std::fs::remove_dir_all(&source_dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sync_batch_partial_failure_does_not_promote_orphaned_qc() {
        let (mut source, source_dir) = local_driver([0xB6u8; 32], "sync_partial_source");
        let _source_local = install_active_validator(&mut source, [0xB6u8; 32], "local");
        source.refresh_registered_voters();

        let block1 = make_strict_block(&source, [0xB6u8; 32], 0, vec![]);
        let _ = source.process(DriverEvent::InboundBlock {
            from: None,
            block: block1.clone(),
        });
        let qc_for_height_1 = source.last_qc_bytes();
        let block2 = make_strict_block(&source, [0xB6u8; 32], 0, qc_for_height_1.clone());
        let _ = source.process(DriverEvent::InboundBlock {
            from: None,
            block: block2.clone(),
        });
        let qc_for_height_2 = source.last_qc_bytes();
        let mut bad_block3 = make_strict_block(&source, [0xB6u8; 32], 0, qc_for_height_2);
        bad_block3.header.prev_hash = Bytes32::from([0xEEu8; 32]);

        let (mut driver, dir) = local_driver([0xB6u8; 32], "sync_partial_importer");
        install_active_validator(&mut driver, [0xB6u8; 32], "local");
        driver.refresh_registered_voters();

        for block in [&block1, &block2] {
            driver.engine.commit_block(block).unwrap();
            driver.promote_block_header_qc(block, "sync").unwrap();
        }
        assert!(driver.engine.commit_block(&bad_block3).is_err());

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
        let election_result_hash = Some(Bytes32::from([0x89u8; 32]));
        let qc_abc = qc_bytes_from_signers(
            &driver,
            &[&a, &b, &c],
            5,
            0,
            block_hash,
            election_result_hash,
        );
        let qc_abd = qc_bytes_from_signers(
            &driver,
            &[&a, &b, &d],
            5,
            0,
            block_hash,
            election_result_hash,
        );
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
        let election_result_hash = Some(Bytes32::from([0x8Bu8; 32]));
        let qc_abc = qc_bytes_from_signers(
            &driver,
            &[&a, &b, &c],
            6,
            0,
            block_hash,
            election_result_hash,
        );
        let mut invalid_qc = qc_bytes_from_signers(
            &driver,
            &[&a, &b, &d],
            6,
            0,
            block_hash,
            election_result_hash,
        );
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

        let election_result_hash = Some(Bytes32::from([0x8Cu8; 32]));
        let qc_a = qc_bytes_from_signers(
            &driver,
            &[&a, &b, &c],
            7,
            0,
            Bytes32::from([0x8Du8; 32]),
            election_result_hash,
        );
        let qc_b = qc_bytes_from_signers(
            &driver,
            &[&a, &b, &d],
            7,
            0,
            Bytes32::from([0x8Eu8; 32]),
            election_result_hash,
        );

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
        let _ = driver.process(DriverEvent::InboundBlock {
            from: None,
            block: block1,
        });
        let qc_for_height_1 = driver.last_qc_bytes();

        let block2 = make_strict_block(&driver, [0xA4u8; 32], 0, qc_for_height_1.clone());
        let _ = driver.process(DriverEvent::InboundBlock {
            from: None,
            block: block2,
        });
        assert_eq!(driver.height(), 2);

        let malformed_block3 = make_strict_block(&driver, [0xA4u8; 32], 0, qc_for_height_1);
        let malformed_hash = malformed_block3.header.block_hash();
        let actions = driver.process(DriverEvent::InboundBlock {
            from: None,
            block: malformed_block3,
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
        config.pq_sk = Some(pq.secret_key_bytes());
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

        let block1 = make_strict_block(&driver, [0xA6u8; 32], 0, vec![]);
        let _ = driver.process(DriverEvent::InboundBlock {
            from: None,
            block: block1,
        });
        assert_eq!(driver.height(), 1);
        assert!(!driver.last_qc_is_stale());

        let block2 = make_strict_block(&driver, [0xA6u8; 32], 0, driver.last_qc_bytes());
        let _ = driver.process(DriverEvent::InboundBlock {
            from: None,
            block: block2,
        });
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
            let _ = driver.process(DriverEvent::InboundBlock { from: None, block });
            assert!(!driver.last_qc_bytes().is_empty());
        }

        let mut config = NodeConfig::local_test(dir.clone());
        let pq = PqKeypair::from_seed(&seed).unwrap();
        config.genesis_path = Some(dir.join("genesis.toml").to_string_lossy().to_string());
        config.validator_seed = Some(seed);
        config.vrf_seed = Some(seed);
        config.pq_pk = Some(pq.public_key().0.to_vec());
        config.pq_sk = Some(pq.secret_key_bytes());
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

        let validator_id = Bytes32::from(indra_crypto::sha256(&local.public_key().classical.0));
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

        let validator_id = Bytes32::from(indra_crypto::sha256(&local.public_key().classical.0));
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

        let _ = driver.process(DriverEvent::QcResponse {
            from: "127.0.0.1:9502".parse().unwrap(),
            height: 7,
            qc_bytes,
        });

        assert!(driver.last_qc_bytes().is_empty());

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
        let _ = driver.process(DriverEvent::InboundBlock {
            from: None,
            block: block1,
        });
        let qc_for_height_1 = driver.last_qc_bytes();
        assert!(!qc_for_height_1.is_empty());

        let mut block2 = make_strict_block(&driver, [0x6Au8; 32], 0, qc_for_height_1.clone());
        block2.header.quorum_certificate =
            indra_core::VariableBytes::from_slice(&qc_for_height_1).unwrap();
        let _ = driver.process(DriverEvent::InboundBlock {
            from: None,
            block: block2,
        });

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
        let _local = install_active_validator(&mut driver, [0x73u8; 32], "local");
        let remote_a = install_active_validator(&mut driver, [0x74u8; 32], "remote-a");
        let remote_b = install_active_validator(&mut driver, [0x75u8; 32], "remote-b");
        let _remote_c = install_active_validator(&mut driver, [0x76u8; 32], "remote-c");
        driver.refresh_registered_voters();

        let block = make_block(&driver.engine.state);
        let value_hash = block.header.value_hash;
        let original_hash = block.header.block_hash();
        let height = block.header.height;
        let actions = driver.process(DriverEvent::InboundBlock { from: None, block });
        assert!(actions.iter().any(
            |a| matches!(a, DriverAction::BroadcastVote(vote) if vote.step == VoteStep::Prevote)
        ));

        let remote_a_id = Bytes32::from(indra_crypto::sha256(&remote_a.public_key().classical.0));
        let remote_b_id = Bytes32::from(indra_crypto::sha256(&remote_b.public_key().classical.0));
        let prevote_a = indra_consensus::vote::produce_vote(
            height,
            0,
            VoteStep::Prevote,
            original_hash,
            remote_a_id,
            DEFAULT_CHAIN_ID,
            &remote_a,
        )
        .unwrap();
        let prevote_b = indra_consensus::vote::produce_vote(
            height,
            0,
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

        assert_eq!(driver.valid_round, Some(0));
        assert_eq!(driver.valid_value, Some(original_hash));
        let (valid_block, valid_round) = driver
            .take_valid_block_for_reproposal()
            .expect("valid block should be stored for reproposal");
        assert_eq!(valid_round, 0);
        assert_eq!(valid_block.header.value_hash, value_hash);

        let epoch_seed = Bytes32::from(indra_crypto::sha256(&driver.engine.state.tip_hash.0));
        let local_validator_id = driver.engine.validator_id().expect("local validator id");
        let candidates: Vec<indra_consensus::proposer::ProposerCandidate> = driver
            .engine
            .state
            .validators
            .active_validators()
            .filter(|v| v.validator_id == local_validator_id)
            .filter_map(|v| {
                v.vrf_pk
                    .map(|vrf_pk| indra_consensus::proposer::ProposerCandidate {
                        validator_id: v.validator_id,
                        vrf_pubkey: vrf_pk,
                        verified_vrf_output: None,
                        stake: v.stake_spark,
                    })
            })
            .collect();
        let election = indra_consensus::proposer::ProposerElection {
            epoch_seed,
            height,
            round: 1,
            candidates,
        };

        let reproposed = driver
            .engine
            .repropose(
                &valid_block,
                1,
                Some(valid_round),
                &election,
                valid_block.header.timestamp,
                driver.last_qc_bytes(),
                None,
                vec![],
            )
            .expect("reproposal should succeed");

        assert_eq!(reproposed.header.value_hash, value_hash);
        assert_eq!(reproposed.header.proposer_round, 1);
        assert_eq!(reproposed.header.polc_round, 0);

        driver.on_precommit_timeout();
        let reproposed_hash = reproposed.header.block_hash();
        driver.pending_blocks.insert(reproposed_hash, reproposed);
        seed_vrf_result_for_seed(&mut driver, height, 1, [0x73u8; 32]);
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
                None,
                vec![],
            )
            .expect("initial proposal should succeed");

        let election_round_one = indra_consensus::proposer::ProposerElection {
            epoch_seed: election_round_zero.epoch_seed,
            height,
            round: 1,
            candidates: election_round_zero.candidates.clone(),
        };
        let local_validator_id =
            Bytes32::from(indra_crypto::sha256(&local.public_key().classical.0));
        assert_eq!(
            indra_consensus::proposer::elect_proposer(
                &election_round_zero,
                election_round_zero.height,
            )
            .unwrap(),
            local_validator_id
        );

        let reproposed = driver
            .engine
            .repropose(
                &proposal,
                1,
                Some(0),
                &election_round_one,
                proposal.header.timestamp,
                driver.last_qc_bytes(),
                None,
                vec![],
            )
            .expect("reproposal should succeed");

        assert_eq!(proposal.header.value_hash, reproposed.header.value_hash);
        assert_ne!(proposal.header.block_hash(), reproposed.header.block_hash());

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

        let a_id = Bytes32::from(indra_crypto::sha256(&a.public_key().classical.0));
        let b_id = Bytes32::from(indra_crypto::sha256(&b.public_key().classical.0));
        let c_id = Bytes32::from(indra_crypto::sha256(&c.public_key().classical.0));
        let d_id = Bytes32::from(indra_crypto::sha256(&d.public_key().classical.0));

        let chosen_tip =
            pick_tip_hash_for_verified_round_winners(&driver_a, 1, [0x81u8; 32], [0x82u8; 32]);
        driver_a.engine.state.tip_hash = chosen_tip;
        driver_b.engine.state.tip_hash = chosen_tip;

        let election_round_zero = election_for_round(&driver_a, 1, 0);
        assert_eq!(
            elect_with_verified_output_for_seed(&election_round_zero, [0x81u8; 32]),
            Some(a_id)
        );
        let block_x = driver_a
            .engine
            .propose(
                &election_round_zero,
                1_700_000_100,
                driver_a.last_qc_bytes(),
                None,
                None,
                vec![],
            )
            .expect("A should propose round 0");
        let value_hash = block_x.header.value_hash;
        let block_x_hash = block_x.header.block_hash();

        seed_vrf_result_for_seed(&mut driver_b, 1, 0, [0x81u8; 32]);
        let stage_actions = driver_b.process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:9801".parse().unwrap()),
            block: block_x.clone(),
        });
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
                0,
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

        assert_eq!(driver_b.valid_round, Some(0));
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
        assert_eq!(driver_b.current_round(), 1);
        assert_eq!(driver_b.proposal_polc_round(1), Some(0));

        let election_round_one = election_for_round(&driver_b, 1, 1);
        assert_eq!(
            elect_with_verified_output_for_seed(&election_round_one, [0x82u8; 32]),
            Some(b_id)
        );
        let (valid_block, valid_round) = driver_b
            .take_valid_block_for_reproposal()
            .expect("round 1 proposer should still have valid block");
        let block_y = driver_b
            .engine
            .repropose(
                &valid_block,
                1,
                Some(valid_round),
                &election_round_one,
                valid_block.header.timestamp,
                driver_b.last_qc_bytes(),
                None,
                vec![],
            )
            .expect("B should repropose valid value at round 1");
        assert_eq!(block_y.header.value_hash, value_hash);
        let block_y_hash = block_y.header.block_hash();
        assert_ne!(block_y_hash, block_x_hash);

        seed_vrf_result_for_seed(&mut driver_b, 1, 1, [0x82u8; 32]);
        let reproposal_actions = driver_b.process(DriverEvent::InboundBlock {
            from: None,
            block: block_y.clone(),
        });
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
                1,
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
            let vote = indra_consensus::vote::produce_vote_with_election_result(
                1,
                1,
                VoteStep::Precommit,
                block_y_hash,
                validator_id,
                block_y.header.election_result_hash,
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
        let _ = driver.sync.observe_status(peer, 10, driver.height());
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
        let _ = driver.sync.observe_status(peer, 10, driver.height());
        assert!(!driver.sync.is_caught_up());

        let remote_id = Bytes32::from(indra_crypto::sha256(&remote.public_key().classical.0));
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
