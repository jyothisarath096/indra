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
        elect_proposer_from_reveals, ProposerElection,
    },
    verify_qc,
    vote::{verify_vote_authority, RegisteredVoter, VoteCollector, VoteDecision},
};
use indra_core::codec::{ByteReader, Decode, Encode};
use indra_core::types::{
    block::{BlockV1, NO_POLC_ROUND},
    crypto::HybridSignature,
    primitives::{
        bps_of, Bytes32, VariableBytes, CONSENSUS_QUORUM_BPS, MAX_CLASSICAL_SIG_BYTES,
        MAX_PQ_SIG_BYTES, MAX_VRF_EMPTY_REVEAL_ROUNDS, MAX_VRF_ROUND_ENTRIES, VRF_COMMIT_WINDOW_MS,
        VRF_REVEAL_WINDOW_MS,
    },
    qc::QuorumCertificateV1,
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
    consensus_authority::{vrf_authority_from_snapshot, VrfConsensusAuthority},
    engine::NodeEngine,
    error::{NodeError, NodeResult},
    slash::{SlashDetector, SlashEvidence},
    sync::{
        proposer_verification_required, verify_block_qc, verify_proposer_vrf,
        verify_reveal_set_evidence, SyncState,
    },
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
    /// Exact reveal evidence set used to compute `election_result`.
    ///
    /// Any field committed by `VrfElectionResult::hash()` must be captured
    /// atomically with the result and must not be re-derived later from live
    /// mutable gossip state. In particular, `reveal_set_commitment` commits to
    /// this exact evidence vector; valid reveals received after the result is
    /// computed remain useful for gossip/recovery, but they are not part of
    /// the already-committed election result.
    pub election_reveal_evidence: Option<Vec<VrfRevealEvidence>>,
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
            election_reveal_evidence: None,
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
    /// Consecutive rounds at the current height without a usable reveal set.
    ///
    /// Before reveal-set commitments activate, this means zero reveals. After
    /// activation, it means zero or non-zero reveals below the 2/3 stake quorum.
    /// Both cases must feed the same Option-D deterministic fallback counter so
    /// liveness is bounded by a fixed round count, not validator count or gossip
    /// timing.
    consecutive_empty_reveal_rounds: u32,
    /// Last insufficient reveal round already counted toward fallback.
    ///
    /// Reveal recovery can be retried within the same round after debounce, but
    /// the fixed fallback counter must advance at most once per round.
    last_insufficient_reveal_round_counted: Option<(u64, u32)>,
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
            last_insufficient_reveal_round_counted: None,
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
            driver.restore_last_qc_for_startup();
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
                match QuorumCertificateV1::decode_exact(&qc_bytes) {
                    Ok(qc) if qc.height == state_height => {
                        eprintln!(
                            "[driver] restored last_qc_bytes ({} bytes) for height {}",
                            qc_bytes.len(),
                            qc.height,
                        );
                        self.last_qc_bytes = qc_bytes;
                        let _ = indra_storage::clear_pending_last_qc(&state_dir);
                        return;
                    }
                    Ok(qc) => {
                        eprintln!(
                            "[driver] persisted QC height {} does not match current state height {} — checking pending current-tip QC",
                            qc.height, state_height,
                        );
                    }
                    Err(err) => {
                        eprintln!(
                            "[driver] WARNING: persisted QC at height {} is not decodable by this binary: {} — checking pending current-tip QC",
                            state_height, err,
                        );
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
                match QuorumCertificateV1::decode_exact(&qc_bytes) {
                    Ok(qc) if qc.height == state_height => {
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
                    Ok(qc) => {
                        eprintln!(
                            "[driver] pending QC height {} does not match current state height {} — discarding and requesting from peers",
                            qc.height, state_height,
                        );
                        let _ = indra_storage::clear_pending_last_qc(&state_dir);
                    }
                    Err(err) => {
                        eprintln!(
                            "[driver] WARNING: pending QC at height {} is not decodable by this binary: {} — discarding and requesting from peers",
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
        self.valid_block = None;
        self.consecutive_empty_reveal_rounds = 0;
        self.last_insufficient_reveal_round_counted = None;
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
        self.last_insufficient_reveal_round_counted = None;
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
        {
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

    #[cfg(test)]
    fn active_vrf_candidates(&self, height: u64, round: u32) -> ProposerElection {
        let epoch_seed = Bytes32::from(indra_crypto::sha256(&self.engine.state.tip_hash.0));
        let candidates = self
            .engine
            .state
            .validators
            .active_validators()
            .filter_map(|validator| {
                validator
                    .vrf_pk
                    .map(|vrf_pubkey| indra_consensus::proposer::ProposerCandidate {
                        validator_id: validator.validator_id,
                        vrf_pubkey,
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

    fn vrf_consensus_authority(
        &self,
        height: u64,
        round: u32,
    ) -> NodeResult<VrfConsensusAuthority> {
        let epoch_seed = Bytes32::from(indra_crypto::sha256(&self.engine.state.tip_hash.0));
        let snapshot = self.engine.state.snapshot_for_consensus_height(height)?;
        Ok(vrf_authority_from_snapshot(
            height, round, epoch_seed, snapshot,
        ))
    }

    /// Build the canonical proposer election authority for one height and round.
    ///
    /// Legacy heights use the live active validator set. Snapshot-governed
    /// heights use the consensus snapshot authoritative for `height`.
    pub fn proposer_election_for_height(
        &self,
        height: u64,
        round: u32,
    ) -> NodeResult<ProposerElection> {
        Ok(self.vrf_consensus_authority(height, round)?.election)
    }

    fn vrf_input_for(&self, height: u64, round: u32) -> [u8; 32] {
        let epoch_seed = Bytes32::from(indra_crypto::sha256(&self.engine.state.tip_hash.0));
        compute_vrf_input(&epoch_seed.0, height, round)
    }

    fn revealed_stake(&self, state: &VrfRoundState, authority: &VrfConsensusAuthority) -> u64 {
        state.reveals.keys().fold(0u64, |total, id| {
            total.saturating_add(authority.weights.get(id).copied().unwrap_or_default())
        })
    }

    fn quorum_stake_reached(authority: &VrfConsensusAuthority, stake: u64) -> bool {
        authority.total_weight > 0 && stake >= bps_of(authority.total_weight, CONSENSUS_QUORUM_BPS)
    }

    fn missing_reveal_validator_ids(
        &self,
        state: &VrfRoundState,
        authority: &VrfConsensusAuthority,
    ) -> Vec<Bytes32> {
        authority
            .election
            .candidates
            .iter()
            .filter_map(|candidate| {
                (!state.reveals.contains_key(&candidate.validator_id))
                    .then_some(candidate.validator_id)
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
        let Ok(authority) = self.vrf_consensus_authority(state.height, state.round) else {
            return vec![DriverAction::None];
        };
        if Self::quorum_stake_reached(&authority, self.revealed_stake(state, &authority)) {
            return vec![];
        }

        let height = state.height;
        let round = state.round;
        let mut missing_validator_ids = self.missing_reveal_validator_ids(state, &authority);
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

    fn validator_hybrid_public_key(
        &self,
        height: u64,
        validator_id: &Bytes32,
    ) -> Option<HybridPublicKey> {
        let snapshot = self
            .engine
            .state
            .snapshot_for_consensus_height(height)
            .ok()?;
        let (_, entry) = snapshot.entry_with_position(validator_id)?;
        Some(HybridPublicKey {
            classical: ClassicalPublicKey(entry.classical_vote_pk),
            pq: PqPublicKey(entry.pq_vote_pk.clone()),
        })
    }

    fn validator_vrf_pk_matches(
        &self,
        height: u64,
        validator_id: &Bytes32,
        vrf_pubkey: &[u8; 32],
    ) -> bool {
        self.engine
            .state
            .snapshot_for_consensus_height(height)
            .ok()
            .and_then(|snapshot| snapshot.entry_with_position(validator_id))
            .is_some_and(|(_, entry)| entry.vrf_pk == *vrf_pubkey)
    }

    fn verify_commit_signature(&self, commit: &VrfCommit) -> bool {
        let Some(pk) = self.validator_hybrid_public_key(commit.height, &commit.validator_id) else {
            return false;
        };
        let Ok(sig) = commit.signature.to_crypto_sig() else {
            return false;
        };
        verify_hybrid(&commit.signing_bytes(), &sig, &pk).is_ok()
    }

    fn verify_reveal_signature(&self, reveal: &VrfReveal) -> bool {
        let Some(pk) = self.validator_hybrid_public_key(reveal.height, &reveal.validator_id) else {
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
        let election = self.vrf_consensus_authority(height, round).ok()?.election;
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
            || !self.validator_vrf_pk_matches(
                reveal.height,
                &reveal.validator_id,
                &reveal.vrf_pubkey,
            )
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
            actions.extend(
                self.maybe_create_local_reveal_for_open_phase(election.height, election.round),
            );
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
        if height <= self.highest_pipelined_vrf_commit_height {
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
            actions.extend(self.maybe_create_local_reveal_for_open_phase(height, round));
        }
        actions
    }

    fn maybe_create_local_reveal_for_open_phase(
        &mut self,
        height: u64,
        round: u32,
    ) -> Vec<DriverAction> {
        let mut actions = Vec::new();
        let Some(slot) = self.vrf_slot_index(height, round) else {
            return actions;
        };
        let Some(local_validator_id) = self.engine.validator_id() else {
            return actions;
        };
        let should_create = self
            .vrf_states
            .get(slot)
            .and_then(|state| state.as_ref())
            .is_some_and(|state| {
                state.phase == VrfRoundPhase::Reveal
                    && state.commits.contains_key(&local_validator_id)
                    && !state.reveals.contains_key(&local_validator_id)
            });
        if !should_create {
            return actions;
        }
        if let Some(reveal) = self.make_local_vrf_reveal(height, round) {
            actions.extend(self.insert_valid_vrf_reveal(slot, reveal, true, None));
        }
        actions
    }

    fn advance_vrf_round(&mut self, height: u64, round: u32) -> Vec<DriverAction> {
        let mut actions = Vec::new();
        let Some(slot) = self.vrf_slot_index(height, round) else {
            return actions;
        };
        let authority = match self.vrf_consensus_authority(height, round) {
            Ok(authority) => authority,
            Err(error) => {
                eprintln!(
                    "[vrf] failed closed resolving consensus authority for height={height} round={round}: {error}"
                );
                return vec![DriverAction::None];
            }
        };
        let open_reveal = self
            .vrf_states
            .get(slot)
            .and_then(|state| state.as_ref())
            .is_some_and(|state| {
                state.phase == VrfRoundPhase::Commit
                    && (Self::quorum_stake_reached(
                        &authority,
                        state.commits.keys().fold(0u64, |total, id| {
                            total.saturating_add(
                                authority.weights.get(id).copied().unwrap_or_default(),
                            )
                        }),
                    ) || state.commit_started_at.elapsed().as_millis()
                        >= VRF_COMMIT_WINDOW_MS as u128)
            });
        if open_reveal {
            if let Some(state) = self.vrf_states[slot].as_mut() {
                state.phase = VrfRoundPhase::Reveal;
                state.reveal_started_at = Some(Instant::now());
            }
            actions.extend(self.maybe_create_local_reveal_for_open_phase(height, round));
        }

        let should_compute = self
            .vrf_states
            .get(slot)
            .and_then(|state| state.as_ref())
            .is_some_and(|state| {
                state.election_result.is_none()
                    && state.phase == VrfRoundPhase::Reveal
                    && (Self::quorum_stake_reached(
                        &authority,
                        self.revealed_stake(state, &authority),
                    ) || state
                        .reveal_started_at
                        .is_some_and(|t| t.elapsed().as_millis() >= VRF_REVEAL_WINDOW_MS as u128))
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
        let authority = self
            .vrf_consensus_authority(state.height, state.round)
            .ok()?;
        let election = &authority.election;
        let revealed: BTreeMap<Bytes32, Bytes32> = state
            .reveals
            .iter()
            .map(|(id, reveal)| (*id, reveal.vrf_output))
            .collect();
        {
            let revealed_stake = self.revealed_stake(state, &authority);
            if !Self::quorum_stake_reached(&authority, revealed_stake) {
                let counted_key = (state_height, state_round);
                if self.last_insufficient_reveal_round_counted != Some(counted_key) {
                    self.consecutive_empty_reveal_rounds =
                        self.consecutive_empty_reveal_rounds.saturating_add(1);
                    self.last_insufficient_reveal_round_counted = Some(counted_key);
                }
                eprintln!(
                    "[vrf] election pending for height={} round={}: reveal set below quorum (revealed_stake={} total_stake={} quorum_bps={} insufficient rounds {}/{})",
                    state_height,
                    state_round,
                    revealed_stake,
                    authority.total_weight,
                    CONSENSUS_QUORUM_BPS,
                    self.consecutive_empty_reveal_rounds,
                    MAX_VRF_EMPTY_REVEAL_ROUNDS,
                );
                if self.consecutive_empty_reveal_rounds < MAX_VRF_EMPTY_REVEAL_ROUNDS {
                    return None;
                }

                let result = compute_fallback_election_result(&election);
                let Ok(mut result) = result else {
                    return None;
                };
                result.reveal_set_commitment = compute_reveal_set_commitment(&[]);
                if let Some(state) = self.vrf_states[slot].as_mut() {
                    state.phase = VrfRoundPhase::Fallback;
                    state.election_result = Some(result);
                    state.election_reveal_evidence = Some(Vec::new());
                }
                eprintln!(
                    "[vrf] election result computed for height={} round={}: elected={} fallback={} after insufficient reveal threshold",
                    result.height,
                    result.round,
                    hex::encode(&result.elected_validator_id.0[..4]),
                    result.fallback_used,
                );
                return Some(result);
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
            result.reveal_set_commitment = compute_reveal_set_commitment(&[]);
            if let Some(state) = self.vrf_states[slot].as_mut() {
                state.phase = VrfRoundPhase::Fallback;
                state.election_result = Some(result);
                state.election_reveal_evidence = Some(Vec::new());
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
        let election_reveal_evidence = {
            let evidence = self
                .vrf_states
                .get(slot)
                .and_then(|state| state.as_ref())
                .map(|state| reveal_evidence_from_reveals(state.reveals.values().cloned()))
                .unwrap_or_default();
            result.reveal_set_commitment = compute_reveal_set_commitment(&evidence);
            Some(evidence)
        };
        if let Some(state) = self.vrf_states[slot].as_mut() {
            self.consecutive_empty_reveal_rounds = 0;
            self.last_insufficient_reveal_round_counted = None;
            state.phase = VrfRoundPhase::Complete;
            state.election_result = Some(result);
            state.election_reveal_evidence = election_reveal_evidence;
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
            .map(|state| {
                if state.election_result.is_some() {
                    // Once an election result exists, return the evidence that
                    // was frozen atomically with it. Rebuilding from
                    // `state.reveals` here would make proposal construction
                    // depend on later gossip and could diverge from the
                    // already-committed `reveal_set_commitment`.
                    state.election_reveal_evidence.clone().unwrap_or_default()
                } else {
                    reveal_evidence_from_reveals(state.reveals.values().cloned())
                }
            })
            .unwrap_or_default()
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

        let mut vote_block_hash = block_hash;
        let mut election_result_hash = None;
        if step == VoteStep::Precommit && block_hash != Bytes32::ZERO {
            match self
                .pending_block(&block_hash)
                .and_then(|block| block.header.election_result_hash)
            {
                Some(hash) => election_result_hash = Some(hash),
                None => {
                    eprintln!(
                        "[consensus] precommit for height={} round={}: staged block is missing verified reveal-set election_result_hash — casting nil precommit",
                        height, round,
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
        from: Option<SocketAddr>,
        block: BlockV1,
    ) -> Vec<DriverAction> {
        let height = block.header.height;
        if let Err(error) = self.verify_live_proposal_proposer(&block) {
            eprintln!(
                "[vote] rejecting proposal {} at height={} round={} because proposer verification failed: {}",
                hex::encode(&block.header.block_hash().0[..4]),
                height,
                block.header.proposer_round,
                error,
            );
            return vec![DriverAction::None];
        }
        {
            match verify_reveal_set_evidence(&block, &self.engine.state) {
                Ok(_) => {}
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

        // Rules 2 and 3 — if this is the proposal for our current slot, react
        // immediately instead of waiting for the propose timeout.
        if proposal_height == self.next_height() && proposal_round == self.current_round {
            match self.vrf_consensus_authority(proposal_height, proposal_round) {
                Ok(authority) => {
                    actions.extend(self.ensure_vrf_election_for_round(&authority.election))
                }
                Err(error) => {
                    eprintln!(
                        "[vrf] failed closed resolving proposer authority for height={proposal_height}: {error}"
                    );
                    actions.push(DriverAction::None);
                }
            }
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

        if let Err(err) = self
            .validate_precommit_election_result_hash(&vote)
            .and_then(|_| {
                verify_vote_authority(&vote, &self.engine.state.chain_id, &self.registered_voters)
                    .map_err(|error| error.to_string())
            })
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

        if !self.sync.is_caught_up() {
            actions.extend(self.record_vote_passive(from, vote, true));
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

        actions.extend(self.record_vote_and_actions(from, vote, true));
        actions
    }

    fn validate_precommit_election_result_hash(&self, vote: &VoteV1) -> Result<(), String> {
        if vote.step != VoteStep::Precommit || vote.is_nil() {
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

        if block_hash == Bytes32::ZERO {
            return Some(votes.into_iter().cloned().collect());
        }

        let target_hash = block.header.election_result_hash?;
        let (qc_validators, total_stake) = self
            .engine
            .qc_authority_for_height(block.header.height)
            .ok()?;
        let stake_by_validator: BTreeMap<Bytes32, u64> = qc_validators
            .iter()
            .map(|validator| (validator.validator_id, validator.stake))
            .collect();
        {
            let collector_matches_height_authority = self
                .registered_voters
                .iter()
                .zip(&qc_validators)
                .all(|(voter, validator)| {
                    voter.validator_id == validator.validator_id
                        && voter.stake == validator.stake
                        && voter.classical_pk == validator.classical_pk
                        && voter.pq_pk == validator.pq_pk
                })
                && self.registered_voters.len() == qc_validators.len();
            if !collector_matches_height_authority {
                return None;
            }
        }
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

    fn verify_live_proposal_proposer(&self, block: &BlockV1) -> NodeResult<()> {
        let height = block.header.height;
        let required = proposer_verification_required(&self.engine.state, height)?;
        if required {
            verify_proposer_vrf(block, &self.engine.state)?;
        }
        Ok(())
    }

    fn record_vote_passive(
        &mut self,
        from: SocketAddr,
        vote: VoteV1,
        authority_verified: bool,
    ) -> Vec<DriverAction> {
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
        if block.header.election_result_hash != qc.election_result_hash {
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

    fn process_vrf_commit(&mut self, from: SocketAddr, commit: VrfCommit) -> Vec<DriverAction> {
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
        if !self.validator_vrf_pk_matches(commit.height, &commit.validator_id, &commit.vrf_pubkey) {
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
        validator_id: Bytes32,
        height: u64,
        tip_hash: Bytes32,
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

        if let Err(err) = self.engine.verify_qc_for_height(&qc) {
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
            VRF_ELECTION_SETTLE_MS,
        },
        Bytes32, ProtocolVersion, VariableBytes,
    };
    use indra_crypto::{
        hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
        VrfKeypair,
    };

    const FINAL_REVEAL_SET_HEIGHT: u64 = 1;
    use indra_state::{
        apply_block, compute_state_roots, ChainState, ValidatorEntry, ValidatorStatus,
    };
    use std::{
        cmp::Ordering,
        collections::BinaryHeap,
        path::PathBuf,
        time::{Duration, Instant},
    };

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
        let roots = compute_state_roots(&projected);
        block.header.state_root = roots.state_root;
        block.header.validator_set_root = roots.validator_set_root;
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
        let cold = indra_crypto::ColdHybridKeypair::from_independent_seeds(
            [seed[0] ^ 0xA5; 32],
            [seed[0] ^ 0x5A; 32],
        )
        .unwrap();
        let cold_public = cold.public_key();
        let cold_public = cold_public.as_complete_hybrid();
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
        Bytes32::from(indra_crypto::sha256(&signer.public_key().classical.0))
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
        let validator_id = indra_crypto::sha256(&classical.public_key().0);
        let genesis_path = dir.join("genesis.toml");
        std::fs::create_dir_all(&dir).unwrap();
        let genesis = format!(
            "[genesis]\nchain_id = \"indra-testnet-1\"\n\n[[validators]]\nname = \"local\"\nvalidator_id = \"{}\"\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\ncold_hybrid_classical_pk = \"{}\"\ncold_hybrid_pq_pk = \"{}\"\ncold_key_version = 1\ncold_nonce = 0\nstake = 1000000\n",
            hex::encode(validator_id),
            hex::encode(classical.public_key().0),
            hex::encode(pq.public_key().0),
            hex::encode(vrf.public_key()),
            hex::encode(cold_public.classical.0),
            hex::encode(cold_public.pq.0),
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

    fn install_test_snapshot_at_inert_gate(driver: &mut ConsensusDriver) {
        let snapshot = driver
            .engine
            .state
            .build_consensus_snapshot(u64::MAX, u64::MAX - 1)
            .unwrap();
        driver.engine.state.consensus_snapshots.push(snapshot);
    }

    #[test]
    fn live_proposal_guard_uses_snapshot_when_live_active_set_is_empty() {
        let seed = [0xA3u8; 32];
        let (mut driver, dir) = local_driver(seed, "snapshot_live_proposer_guard");
        install_test_snapshot_at_inert_gate(&mut driver);
        driver.engine.state.height = u64::MAX - 1;
        driver.engine.state.tip_hash = Bytes32::from([0xA3; 32]);
        let (_, reveal) = signed_vrf_pair(&driver, seed, u64::MAX, 0, DEFAULT_CHAIN_ID);
        let valid = reveal_set_block_from_reveals(&driver, &[seed], std::slice::from_ref(&reveal));

        assert!(driver.verify_live_proposal_proposer(&valid).is_ok());

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
            driver.verify_live_proposal_proposer(&valid).is_ok(),
            "snapshot-authorized proposer must still verify after live demotion"
        );

        let mut invalid = valid;
        invalid.header.proposer_vrf_proof = VariableBytes::from_slice(&[0xA5; 32]).unwrap();
        assert!(
            driver.verify_live_proposal_proposer(&invalid).is_err(),
            "invalid proposer proof must be checked, not skipped, when S(height) is nonempty"
        );

        driver.engine.state.consensus_snapshots.clear();
        assert!(matches!(
            driver.verify_live_proposal_proposer(&invalid),
            Err(NodeError::ConsensusSnapshotLookup(_))
        ));
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

        let authority = driver.vrf_consensus_authority(u64::MAX, 0).unwrap();
        assert_eq!(authority.election.candidates[0].stake, frozen);
        assert_eq!(authority.total_weight, frozen);
        assert_ne!(
            authority.election.candidates[0].stake,
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
    fn vrf_quorum_uses_snapshot_weights_and_total() {
        let local_seed = [0xB2; 32];
        let (mut driver, dir) = local_driver(local_seed, "snapshot_vrf_quorum");
        let local = install_active_validator(&mut driver, local_seed, "local");
        let b = install_active_validator(&mut driver, [0xB3; 32], "b");
        let c = install_active_validator(&mut driver, [0xB4; 32], "c");
        let local_id = validator_id_for(&local);
        let b_id = validator_id_for(&b);
        let c_id = validator_id_for(&c);
        driver
            .engine
            .state
            .validators
            .get_mut(&local_id)
            .unwrap()
            .stake_spark = 40;
        driver
            .engine
            .state
            .validators
            .get_mut(&b_id)
            .unwrap()
            .stake_spark = 30;
        driver
            .engine
            .state
            .validators
            .get_mut(&c_id)
            .unwrap()
            .stake_spark = 30;
        crate::genesis::finalize_test_genesis(&mut driver.engine.state);
        driver
            .engine
            .state
            .validators
            .get_mut(&c_id)
            .unwrap()
            .stake_spark = 300;

        let authority = driver.vrf_consensus_authority(u64::MAX, 0).unwrap();
        let revealed = authority.weights[&local_id] + authority.weights[&b_id];
        assert_eq!(authority.total_weight, 100);
        assert!(ConsensusDriver::quorum_stake_reached(&authority, revealed));
        assert!(revealed < bps_of(370, CONSENSUS_QUORUM_BPS));
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
        let epoch_seed = Bytes32::from([0x55; 32]);
        let vrf = vrf_authority_from_snapshot(301, 2, epoch_seed, &snapshot);
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
        assert_eq!(vrf.total_weight, snapshot.total_weight_spark);
        assert_eq!(
            voters.iter().map(|voter| voter.stake).sum::<u64>(),
            snapshot.total_weight_spark
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pre_gate_proposer_and_vrf_authority_match_legacy_adapter() {
        let (driver, dir) = local_driver([0xB6; 32], "legacy_vrf_authority");
        let legacy = driver.active_vrf_candidates(1, 3);
        let authority = driver.vrf_consensus_authority(1, 3).unwrap();
        assert_eq!(legacy.candidates.len(), authority.election.candidates.len());
        for (legacy, actual) in legacy.candidates.iter().zip(&authority.election.candidates) {
            assert_eq!(legacy.validator_id, actual.validator_id);
            assert_eq!(legacy.vrf_pubkey, actual.vrf_pubkey);
            assert_eq!(legacy.stake, actual.stake);
        }
        assert_eq!(
            authority.total_weight,
            legacy
                .candidates
                .iter()
                .map(|candidate| candidate.stake)
                .sum::<u64>()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn governed_proposer_and_vrf_quorum_fail_closed_without_snapshot() {
        let (mut driver, dir) = local_driver([0xB7; 32], "missing_vrf_snapshot");
        driver.engine.state.consensus_snapshots.clear();
        assert!(matches!(
            driver.vrf_consensus_authority(u64::MAX, 0),
            Err(NodeError::ConsensusSnapshotLookup(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposer_and_vrf_quorum_replay_across_snapshot_boundary() {
        let (mut driver, dir) = local_driver([0xB8; 32], "vrf_boundary_replay");
        let old_snapshot = driver
            .engine
            .state
            .build_genesis_consensus_snapshot()
            .unwrap();
        let id = old_snapshot.entries()[0].validator_id;
        driver
            .engine
            .state
            .validators
            .get_mut(&id)
            .unwrap()
            .stake_spark += 500;
        let new_snapshot = driver
            .engine
            .state
            .build_consensus_snapshot(301, 300)
            .unwrap();
        let replay = || {
            let old = vrf_authority_from_snapshot(300, 0, Bytes32::from([0x80; 32]), &old_snapshot);
            let new = vrf_authority_from_snapshot(301, 0, Bytes32::from([0x81; 32]), &new_snapshot);
            (
                indra_consensus::proposer::elect_proposer(&old.election, 300).unwrap(),
                ConsensusDriver::quorum_stake_reached(&old, old.weights.values().copied().sum()),
                indra_consensus::proposer::elect_proposer(&new.election, 301).unwrap(),
                ConsensusDriver::quorum_stake_reached(&new, new.weights.values().copied().sum()),
            )
        };
        assert_eq!(replay(), replay());
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

        let signers = vec![(local_id, local), (b_id, b), (c_id, c), (d_id, d)];
        let snapshots = [(1, genesis), (301, at_301), (601, at_601), (901, at_901)];
        let run = || {
            snapshots
                .iter()
                .map(|(height, snapshot)| {
                    let voters = NodeEngine::registered_voters_for_height(*height, snapshot);
                    let validators = NodeEngine::qc_validators_for_height(*height, snapshot);
                    let authority = vrf_authority_from_snapshot(
                        *height,
                        0,
                        Bytes32::from([(*height % 251) as u8; 32]),
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
                    assert_eq!(authority.total_weight, snapshot.total_weight_spark);
                    assert!(ConsensusDriver::quorum_stake_reached(
                        &authority,
                        authority.weights.values().copied().sum()
                    ));

                    let block_hash = Bytes32::from([(*height % 239) as u8; 32]);
                    let votes = signers
                        .iter()
                        .filter(|(id, _)| snapshot.entry_with_position(id).is_some())
                        .map(|(id, signer)| {
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
                    let mut collector = VoteCollector::new(
                        *height,
                        0,
                        VoteStep::Precommit,
                        DEFAULT_CHAIN_ID.to_string(),
                        voters,
                    );
                    for vote in &votes {
                        collector.add_vote(vote.clone()).unwrap();
                    }
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
                    (
                        snapshot.snapshot_root,
                        indra_consensus::proposer::elect_proposer(&authority.election, *height)
                            .unwrap(),
                        qc.encode_to_vec(),
                    )
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
        reveal_set_block_from_reveals_at(driver, active_seeds, reveals, u64::MAX, 0)
    }

    fn reveal_set_block_from_reveals_at(
        driver: &ConsensusDriver,
        active_seeds: &[[u8; 32]],
        reveals: &[VrfReveal],
        height: u64,
        round: u32,
    ) -> BlockV1 {
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
                    indra_core::types::primitives::BLOCK_FORMAT_VERSION,
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
        let roots = compute_state_roots(&projected);
        block.header.state_root = roots.state_root;
        block.header.validator_set_root = roots.validator_set_root;
        block.header.value_hash = block.compute_value_hash(projected.total_supply);
        block
    }

    fn attach_parent_qc(driver: &ConsensusDriver, block: &mut BlockV1, signers: &[&HybridKeypair]) {
        let parent_qc = qc_bytes_from_signers(
            driver,
            signers,
            driver.engine.state.height,
            0,
            driver.engine.state.tip_hash,
            None,
        );
        block.header.quorum_certificate = VariableBytes::from_slice(&parent_qc).unwrap();
        let mut projected = driver.engine.state.clone();
        apply_block(&mut projected, block, 0).unwrap();
        let roots = compute_state_roots(&projected);
        block.header.state_root = roots.state_root;
        block.header.validator_set_root = roots.validator_set_root;
        block.header.value_hash = block.compute_value_hash(projected.total_supply);
    }

    fn set_complete_vrf_state_with_divergent_result(
        driver: &mut ConsensusDriver,
        height: u64,
        round: u32,
        commits: Vec<VrfCommit>,
        reveals: Vec<VrfReveal>,
        authoritative_hash: Bytes32,
    ) {
        let mut state = VrfRoundState::new(height, round);
        state.phase = VrfRoundPhase::Complete;
        for commit in commits {
            state.commits.insert(commit.validator_id, commit);
        }
        for reveal in &reveals {
            state.reveals.insert(reveal.validator_id, reveal.clone());
        }
        let mut evidence = reveal_evidence_from_reveals(reveals);
        evidence.sort_by_key(|item| item.validator_id.0);
        let mut divergent_result = VrfElectionResult {
            height,
            round,
            elected_validator_id: state
                .reveals
                .keys()
                .next()
                .copied()
                .expect("test must provide at least one reveal"),
            elected_vrf_output: Bytes32::from([0x7Bu8; 32]),
            fallback_used: false,
            reveal_set_commitment: compute_reveal_set_commitment(&evidence),
        };
        if divergent_result.hash() == authoritative_hash {
            divergent_result.elected_vrf_output = Bytes32::from([0x7Cu8; 32]);
        }
        assert_ne!(
            divergent_result.hash(),
            authoritative_hash,
            "test setup requires local election hash to differ from proposal hash"
        );
        state.election_result = Some(divergent_result);
        state.election_reveal_evidence = Some(evidence);
        driver.vrf_states[0] = Some(state);
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
        let preferred = VrfKeypair::from_seed(&proposer_seed);
        let mut keypairs = BTreeMap::new();
        let mut revealed = BTreeMap::new();
        let mut vrf_reveals = Vec::new();
        for candidate in &election.candidates {
            let keypair = if preferred.public_key() == candidate.vrf_pubkey {
                preferred.clone()
            } else {
                (0u8..=u8::MAX)
                    .map(|seed| VrfKeypair::from_seed(&[seed; 32]))
                    .find(|keypair| keypair.public_key() == candidate.vrf_pubkey)
                    .expect("test validator VRF seed must be recoverable")
            };
            let slot = compute_proposer_vrf(
                candidate.validator_id,
                &keypair,
                &election.epoch_seed,
                election.height,
                election.round,
            );
            let output = Bytes32::from(slot.vrf_output.0);
            revealed.insert(candidate.validator_id, output);
            vrf_reveals.push(VrfRevealEvidence {
                validator_id: candidate.validator_id,
                vrf_output: output,
                vrf_proof: VariableBytes::from_slice(&slot.vrf_proof.0).unwrap(),
            });
            keypairs.insert(candidate.validator_id, keypair);
        }
        let mut election_result = elect_proposer_from_reveals(&election, &revealed).unwrap();
        election_result.reveal_set_commitment = compute_reveal_set_commitment(&vrf_reveals);
        let proposer_vrf = keypairs
            .remove(&election_result.elected_validator_id)
            .unwrap();
        let election_result_hash = election_result.hash();
        let template = BlockTemplate {
            proposer_vrf_keypair: proposer_vrf,
            epoch_seed: election.epoch_seed,
            prev_qc_bytes,
            timestamp: 1_700_000_000 + driver.engine.state.height + 1,
            polc_round: None,
            transactions: vec![],
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            election_result_hash: Some(election_result_hash),
            election_result: Some(election_result),
            vrf_reveals,
        };
        let mut projection_state = driver.engine.state.clone();
        produce_block(&template, &mut projection_state, &election).unwrap()
    }

    fn authoritative_result_for_seed(
        election: &ProposerElection,
        seed: [u8; 32],
    ) -> (VrfElectionResult, Vec<VrfRevealEvidence>) {
        let keypair = VrfKeypair::from_seed(&seed);
        let mut evidence = Vec::new();
        let mut revealed = BTreeMap::new();
        for candidate in &election.candidates {
            let candidate_keypair = if candidate.vrf_pubkey == keypair.public_key() {
                keypair.clone()
            } else {
                (0u8..=u8::MAX)
                    .map(|byte| VrfKeypair::from_seed(&[byte; 32]))
                    .find(|candidate_keypair| {
                        candidate_keypair.public_key() == candidate.vrf_pubkey
                    })
                    .expect("test validator VRF seed must be recoverable")
            };
            let slot = compute_proposer_vrf(
                candidate.validator_id,
                &candidate_keypair,
                &election.epoch_seed,
                election.height,
                election.round,
            );
            let output = Bytes32::from(slot.vrf_output.0);
            revealed.insert(candidate.validator_id, output);
            evidence.push(VrfRevealEvidence {
                validator_id: candidate.validator_id,
                vrf_output: output,
                vrf_proof: VariableBytes::from_slice(&slot.vrf_proof.0).unwrap(),
            });
        }
        let mut result = elect_proposer_from_reveals(election, &revealed).unwrap();
        result.reveal_set_commitment = compute_reveal_set_commitment(&evidence);
        (result, evidence)
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

    fn real_driver_sim_n() -> usize {
        std::env::var("INDRA_REAL_DRIVER_SIM_N")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value >= 4)
            .unwrap_or(200)
    }

    fn real_driver_sim_quorum(validators: usize) -> usize {
        validators.saturating_mul(2) / 3 + 1
    }

    fn real_driver_sim_full_static_topology() -> bool {
        std::env::var("INDRA_REAL_DRIVER_SIM_TOPOLOGY")
            .ok()
            .is_some_and(|value| value == "full-static")
    }

    const REAL_DRIVER_SIM_TARGET_OUTBOUND: usize =
        indra_core::types::primitives::TARGET_OUTBOUND_PEERS;
    const REAL_DRIVER_SIM_MAX_INBOUND: usize = indra_core::types::primitives::MAX_INBOUND_PEERS;
    const REAL_DRIVER_SIM_MIN_RELAY_FANOUT: usize = 4;
    const REAL_DRIVER_SIM_MAX_RELAY_FANOUT: usize = 16;
    const REAL_DRIVER_SIM_BLOCK_FANOUT_MULTIPLIER: usize = 2;
    const REAL_DRIVER_SIM_MAX_BLOCK_FANOUT: usize = 24;
    const REAL_DRIVER_SIM_TICK_MS: u64 = 500;
    const REAL_DRIVER_SIM_DELIVERY_BASE_MS: u64 = 20;
    const REAL_DRIVER_SIM_MAX_MS: u64 = 180_000;
    const REAL_DRIVER_SIM_PROPOSE_TIMEOUT_MS: u64 = 8_000;
    const REAL_DRIVER_SIM_PREVOTE_TIMEOUT_MS: u64 = 3_000;
    const REAL_DRIVER_SIM_PRECOMMIT_TIMEOUT_MS: u64 = 3_000;

    #[derive(Clone)]
    enum RealSimMessage {
        Block(BlockV1),
        Vote(VoteV1),
        VrfCommit(VrfCommit),
        VrfReveal(VrfReveal),
        QcRequest {
            height: u64,
        },
        QcResponse {
            height: u64,
            qc_bytes: Vec<u8>,
        },
        VrfRevealsRequest {
            height: u64,
            round: u32,
            missing_validator_ids: Vec<Bytes32>,
        },
        VrfRevealsResponse {
            height: u64,
            round: u32,
            reveals: Vec<VrfReveal>,
        },
    }

    enum RealSimEventKind {
        Tick {
            node: usize,
        },
        Deliver {
            from: usize,
            to: usize,
            msg: RealSimMessage,
        },
        RestartStart {
            node: usize,
        },
    }

    fn real_sim_message_class(msg: &RealSimMessage) -> &'static str {
        match msg {
            RealSimMessage::Block(_) => "Block",
            RealSimMessage::Vote(_) => "Vote",
            RealSimMessage::VrfCommit(_) => "VrfCommit",
            RealSimMessage::VrfReveal(_) => "VrfReveal",
            RealSimMessage::QcRequest { .. } => "QcRequest",
            RealSimMessage::QcResponse { .. } => "QcResponse",
            RealSimMessage::VrfRevealsRequest { .. } => "VrfRevealsRequest",
            RealSimMessage::VrfRevealsResponse { .. } => "VrfRevealsResponse",
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct RealSimRelayKey {
        class: u8,
        digest: Bytes32,
    }

    fn real_sim_relay_key(msg: &RealSimMessage) -> Option<RealSimRelayKey> {
        let (class, mut bytes) = match msg {
            RealSimMessage::Block(block) => {
                let mut bytes = Vec::with_capacity(block.encoded_len());
                block.encode(&mut bytes);
                (0u8, bytes)
            }
            RealSimMessage::Vote(vote) => {
                let mut bytes = Vec::with_capacity(vote.encoded_len());
                vote.encode(&mut bytes);
                (1u8, bytes)
            }
            RealSimMessage::VrfCommit(commit) => {
                let mut bytes = Vec::with_capacity(commit.encoded_len());
                commit.encode(&mut bytes);
                (2u8, bytes)
            }
            RealSimMessage::VrfReveal(reveal) => {
                let mut bytes = Vec::with_capacity(reveal.encoded_len());
                reveal.encode(&mut bytes);
                (3u8, bytes)
            }
            // Point-to-point recovery traffic is not relay-deduped in
            // production's consensus relay path, so keep it outside the
            // simulated relay cache too.
            RealSimMessage::QcRequest { .. }
            | RealSimMessage::QcResponse { .. }
            | RealSimMessage::VrfRevealsRequest { .. }
            | RealSimMessage::VrfRevealsResponse { .. } => return None,
        };
        bytes.insert(0, class);
        Some(RealSimRelayKey {
            class,
            digest: Bytes32::from(indra_crypto::sha256(&bytes)),
        })
    }

    #[derive(Default)]
    struct RealDriverSimEventStats {
        processed_ticks: usize,
        processed_deliveries: usize,
        processed_restarts: usize,
        scheduled_deliveries: usize,
        broadcast_calls_from_tick: usize,
        broadcast_calls_from_deliver: usize,
        broadcast_calls_from_activate: usize,
        suppressed_rebroadcasts: usize,
        scheduled_by_class: HashMap<&'static str, usize>,
        processed_by_class: HashMap<&'static str, usize>,
        broadcast_by_class: HashMap<&'static str, usize>,
    }

    struct RealSimEvent {
        at_ms: u64,
        seq: u64,
        kind: RealSimEventKind,
    }

    impl PartialEq for RealSimEvent {
        fn eq(&self, other: &Self) -> bool {
            self.at_ms == other.at_ms && self.seq == other.seq
        }
    }

    impl Eq for RealSimEvent {}

    impl PartialOrd for RealSimEvent {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for RealSimEvent {
        fn cmp(&self, other: &Self) -> Ordering {
            other
                .at_ms
                .cmp(&self.at_ms)
                .then_with(|| other.seq.cmp(&self.seq))
        }
    }

    struct RealSimNode {
        addr: SocketAddr,
        config: NodeConfig,
        driver: Option<ConsensusDriver>,
        online: bool,
        stopped_once: bool,
        proposed_slots: HashSet<(u64, u32)>,
        phase_key: Option<(u64, u32, RoundPhase)>,
        phase_started_ms: u64,
        vrf_commit_started_ms: HashMap<(u64, u32), u64>,
        vrf_reveal_started_ms: HashMap<(u64, u32), u64>,
    }

    struct RealDriverRestartOutcome {
        name: &'static str,
        validators: usize,
        quorum: usize,
        restarted: usize,
        initial_online: usize,
        first_quorum_online_round: Option<u32>,
        finalized_round: Option<u32>,
        via_fallback: bool,
        finalized_nodes: usize,
        late_local_commit_cases: usize,
        duration_ms: u64,
        wall_ms: u128,
    }

    struct RealDriverSimHarness {
        root: PathBuf,
        validators: usize,
        quorum: usize,
        nodes: Vec<RealSimNode>,
        graph: Vec<HashSet<usize>>,
        relay_seen: Vec<HashSet<RealSimRelayKey>>,
        relay_forwarded: Vec<HashMap<RealSimRelayKey, HashSet<usize>>>,
        initial_qc_bytes: Vec<u8>,
        queue: BinaryHeap<RealSimEvent>,
        seq: u64,
        now_ms: u64,
        start_height: u64,
        late_local_commit_cases: usize,
        last_observed_round: u32,
        first_quorum_online_round: Option<u32>,
        via_fallback: bool,
        event_stats: RealDriverSimEventStats,
        signers: Vec<HybridKeypair>,
    }

    fn real_sim_seed(index: usize) -> [u8; 32] {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
        seed[8] = 0xA5;
        seed
    }

    fn real_sim_genesis(validators: usize) -> (String, Vec<HybridKeypair>) {
        let mut genesis = "[genesis]\nchain_id = \"indra-testnet-1\"\n".to_string();
        let mut signers = Vec::with_capacity(validators);
        for i in 0..validators {
            let seed = real_sim_seed(i);
            let classical = ClassicalKeypair::from_seed(&seed);
            let pq = PqKeypair::from_seed(&seed).unwrap();
            let vrf = VrfKeypair::from_seed(&seed);
            let cold = indra_crypto::ColdHybridKeypair::from_independent_seeds(
                [seed[0].wrapping_add(96); 32],
                [seed[0].wrapping_add(128); 32],
            )
            .unwrap();
            let cold_public = cold.public_key();
            let cold_public = cold_public.as_complete_hybrid();
            let validator_id = indra_crypto::sha256(&classical.public_key().0);
            genesis.push_str(&format!(
                "\n[[validators]]\nname = \"v{i}\"\nvalidator_id = \"{}\"\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\ncold_hybrid_classical_pk = \"{}\"\ncold_hybrid_pq_pk = \"{}\"\ncold_key_version = 1\ncold_nonce = 0\nstake = 1000000\n",
                hex::encode(validator_id),
                hex::encode(classical.public_key().0),
                hex::encode(pq.public_key().0),
                hex::encode(vrf.public_key()),
                hex::encode(cold_public.classical.0),
                hex::encode(cold_public.pq.0),
            ));
            signers.push(HybridKeypair::new(classical, pq));
        }
        (genesis, signers)
    }

    impl RealDriverSimHarness {
        fn new(suffix: &str) -> Self {
            Self::new_with_start_height(suffix, FINAL_REVEAL_SET_HEIGHT)
        }

        fn new_with_start_height(suffix: &str, start_height: u64) -> Self {
            let validators = real_driver_sim_n();
            let quorum = real_driver_sim_quorum(validators);
            let root = temp_dir(&format!("{suffix}_n{validators}"));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            let genesis_path = root.join("genesis.toml");
            let (genesis, signers) = real_sim_genesis(validators);
            std::fs::write(&genesis_path, genesis).unwrap();

            let mut nodes = Vec::with_capacity(validators);
            let template_dir = root.join("template_node");
            let template_seed = real_sim_seed(0);
            let template_pq = PqKeypair::from_seed(&template_seed).unwrap();
            let mut template_config = NodeConfig::local_test(template_dir.clone());
            template_config.genesis_path = Some(genesis_path.to_string_lossy().to_string());
            template_config.validator_seed = Some(template_seed);
            template_config.vrf_seed = Some(template_seed);
            template_config.pq_pk = Some(template_pq.public_key().0.to_vec());
            template_config.pq_sk = Some(template_pq.secret_key_bytes());
            template_config.p2p_addr = "127.0.0.1:30000".to_string();

            let engine = NodeEngine::init(template_config).unwrap();
            let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
            let mut template_driver = ConsensusDriver::new(engine, vote_safety);
            let tip_hash = if start_height == 0 {
                template_driver.engine.state.tip_hash
            } else {
                let tip_hash = Bytes32::from(indra_crypto::sha256(b"real-driver-sim-tip"));
                template_driver.engine.state.height = start_height;
                template_driver.engine.state.tip_hash = tip_hash;
                template_driver
                    .engine
                    .state_store
                    .save(&template_driver.engine.state)
                    .unwrap();
                tip_hash
            };
            template_driver.refresh_registered_voters();
            let quorum_signers: Vec<_> = signers.iter().take(quorum).collect();
            let qc = qc_bytes_from_signers(
                &template_driver,
                &quorum_signers,
                start_height,
                0,
                tip_hash,
                None,
            );
            drop(template_driver);

            for i in 0..validators {
                let seed = real_sim_seed(i);
                let pq = PqKeypair::from_seed(&seed).unwrap();
                let node_dir = root.join(format!("node_{i}"));
                let mut config = NodeConfig::local_test(node_dir);
                // Each simulated validator initializes its own canonical
                // store from the same validated manifest. Copying a live
                // template directory can omit atomically-managed manifest
                // files and is not a faithful restart setup.
                config.genesis_path = Some(genesis_path.to_string_lossy().to_string());
                config.validator_seed = Some(seed);
                config.vrf_seed = Some(seed);
                config.pq_pk = Some(pq.public_key().0.to_vec());
                config.pq_sk = Some(pq.secret_key_bytes());
                config.p2p_addr = format!("127.0.0.1:{}", 30_000 + i);
                if real_driver_sim_full_static_topology() {
                    config.bootstrap_peers = (0..validators)
                        .filter(|peer| *peer != i)
                        .map(|peer| format!("127.0.0.1:{}", 30_000 + peer))
                        .collect();
                } else {
                    config.bootstrap_peers = vec![format!("127.0.0.1:{}", 30_000)];
                    if i == 0 {
                        config.bootstrap_peers.clear();
                    }
                }

                let mut driver = Self::restart_driver_from_config(config.clone(), &qc);
                if start_height != 0 && driver.engine.state.height != start_height {
                    driver.engine.state.height = start_height;
                    driver.engine.state.tip_hash = tip_hash;
                    driver
                        .engine
                        .state_store
                        .save(&driver.engine.state)
                        .unwrap();
                }
                driver.sync.mark_caught_up(driver.height());
                driver.refresh_registered_voters();
                driver.start_round(0);
                nodes.push(RealSimNode {
                    addr: format!("127.0.0.1:{}", 30_000 + i).parse().unwrap(),
                    config,
                    driver: Some(driver),
                    online: true,
                    stopped_once: false,
                    proposed_slots: HashSet::new(),
                    phase_key: None,
                    phase_started_ms: 0,
                    vrf_commit_started_ms: HashMap::new(),
                    vrf_reveal_started_ms: HashMap::new(),
                });
            }

            let graph = if real_driver_sim_full_static_topology() {
                Self::build_full_static_graph(validators)
            } else {
                Self::build_bootstrap_first_graph(
                    validators,
                    REAL_DRIVER_SIM_TARGET_OUTBOUND,
                    REAL_DRIVER_SIM_MAX_INBOUND,
                )
            };

            Self {
                root,
                validators,
                quorum,
                nodes,
                graph,
                relay_seen: vec![HashSet::new(); validators],
                relay_forwarded: vec![HashMap::new(); validators],
                initial_qc_bytes: qc,
                queue: BinaryHeap::new(),
                seq: 0,
                now_ms: 0,
                start_height,
                late_local_commit_cases: 0,
                last_observed_round: 0,
                first_quorum_online_round: None,
                via_fallback: false,
                event_stats: RealDriverSimEventStats::default(),
                signers,
            }
        }

        /// Schedule the maximum steady-state traffic admitted for one
        /// authenticated Byzantine identity across all three consensus
        /// classes. Events are injected after the network rate gate, so this
        /// measures the aggregate work the driver is intentionally allowed to
        /// receive rather than traffic which would already have been dropped.
        fn schedule_combined_consensus_flood(&mut self, duration_secs: u64) -> usize {
            assert!(self.validators >= 4);
            let attacker = 0usize;
            let targets: Vec<usize> = (1..self.validators).collect();
            let height = self.start_height.saturating_add(1);
            let round = 0u32;
            let attacker_id = Bytes32::from(indra_crypto::sha256(
                &self.signers[attacker].public_key().classical.0,
            ));
            let mut scheduled = 0usize;

            for second in 0..duration_secs {
                for index in 0..20u64 {
                    let sequence = second * 20 + index;
                    let mut hash = [0u8; 32];
                    hash[..8].copy_from_slice(&sequence.to_le_bytes());
                    hash[8] = 0xF1;
                    let vote = indra_consensus::vote::produce_vote(
                        height,
                        round,
                        VoteStep::Prevote,
                        Bytes32::from(hash),
                        attacker_id,
                        DEFAULT_CHAIN_ID,
                        &self.signers[attacker],
                    )
                    .unwrap();
                    for &to in &targets {
                        self.schedule(
                            second * 1_000 + index * 50,
                            RealSimEventKind::Deliver {
                                from: attacker,
                                to,
                                msg: RealSimMessage::Vote(vote.clone()),
                            },
                        );
                        scheduled += 1;
                    }
                }

                for index in 0..8u64 {
                    let (mut commit, _) = signed_vrf_pair(
                        self.nodes[attacker].driver.as_ref().unwrap(),
                        real_sim_seed(attacker),
                        height,
                        round,
                        DEFAULT_CHAIN_ID,
                    );
                    let sequence = second * 8 + index;
                    let mut hash = [0u8; 32];
                    hash[..8].copy_from_slice(&sequence.to_le_bytes());
                    hash[8] = 0xF2;
                    // Distinct, well-shaped messages with signatures that no
                    // longer match model maximally expensive invalid commits.
                    commit.commit_hash = Bytes32::from(hash);
                    for &to in &targets {
                        self.schedule(
                            second * 1_000 + index * 125,
                            RealSimEventKind::Deliver {
                                from: attacker,
                                to,
                                msg: RealSimMessage::VrfCommit(commit.clone()),
                            },
                        );
                        scheduled += 1;
                    }
                }

                for index in 0..5u64 {
                    let mut qc_bytes = self.initial_qc_bytes.clone();
                    let sequence = second * 5 + index;
                    let offset = qc_bytes.len() - 1 - (sequence as usize % 16);
                    qc_bytes[offset] ^= 1u8 << (sequence % 8);
                    for &to in &targets {
                        self.schedule(
                            second * 1_000 + index * 200,
                            RealSimEventKind::Deliver {
                                from: attacker,
                                to,
                                msg: RealSimMessage::QcResponse {
                                    height: self.start_height,
                                    qc_bytes: qc_bytes.clone(),
                                },
                            },
                        );
                        scheduled += 1;
                    }
                }
            }
            scheduled
        }

        fn restart_driver_from_config(
            config: NodeConfig,
            initial_qc_bytes: &[u8],
        ) -> ConsensusDriver {
            let engine = NodeEngine::init(config).unwrap();
            let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
            let mut driver = ConsensusDriver::new(engine, vote_safety);
            driver.last_qc_bytes = initial_qc_bytes.to_vec();
            driver.sync.mark_caught_up(driver.height());
            driver.refresh_registered_voters();
            driver.start_round(0);
            driver
        }

        fn schedule(&mut self, at_ms: u64, kind: RealSimEventKind) {
            if let RealSimEventKind::Deliver { msg, .. } = &kind {
                self.event_stats.scheduled_deliveries =
                    self.event_stats.scheduled_deliveries.saturating_add(1);
                *self
                    .event_stats
                    .scheduled_by_class
                    .entry(real_sim_message_class(msg))
                    .or_default() += 1;
            }
            let event = RealSimEvent {
                at_ms,
                seq: self.seq,
                kind,
            };
            self.seq = self.seq.saturating_add(1);
            self.queue.push(event);
        }

        fn online_count(&self) -> usize {
            self.nodes.iter().filter(|node| node.online).count()
        }

        fn finalized_count(&self) -> usize {
            self.nodes
                .iter()
                .filter_map(|node| node.driver.as_ref())
                .filter(|driver| driver.height() > self.start_height)
                .count()
        }

        fn current_round_max(&self) -> u32 {
            self.nodes
                .iter()
                .filter_map(|node| node.driver.as_ref())
                .map(|driver| driver.current_round())
                .max()
                .unwrap_or(0)
        }

        fn observe_fallback_results(&mut self) {
            let proposal_height = self.start_height.saturating_add(1);
            for driver in self.nodes.iter().filter_map(|node| node.driver.as_ref()) {
                for state in driver.vrf_states.iter().filter_map(|state| state.as_ref()) {
                    if state.height == proposal_height
                        && state
                            .election_result
                            .is_some_and(|result| result.fallback_used)
                    {
                        self.via_fallback = true;
                    }
                }
            }
        }

        fn start_ticks(&mut self) {
            for node in 0..self.nodes.len() {
                if self.nodes[node].online {
                    self.schedule(0, RealSimEventKind::Tick { node });
                }
            }
        }

        fn restart_set(&self, restarted: usize) -> Vec<usize> {
            let mut ordered = (0..self.nodes.len())
                .map(|node| {
                    let digest = indra_crypto::sha256(&(node as u64).to_le_bytes());
                    (u64::from_le_bytes(digest[..8].try_into().unwrap()), node)
                })
                .collect::<Vec<_>>();
            ordered.sort();
            ordered
                .into_iter()
                .take(restarted)
                .map(|(_, node)| node)
                .collect()
        }

        fn schedule_correlated_restart(&mut self, restarted: usize, spread_ms: u64) {
            let mut nodes = self.restart_set(restarted);
            nodes.sort();
            for (idx, node) in nodes.into_iter().enumerate() {
                if self.nodes[node].online {
                    self.nodes[node].driver = None;
                    self.nodes[node].online = false;
                    self.nodes[node].stopped_once = true;
                    self.nodes[node].phase_key = None;
                    self.nodes[node].phase_started_ms = 0;
                    self.nodes[node].vrf_commit_started_ms.clear();
                    self.nodes[node].vrf_reveal_started_ms.clear();
                }
                let offset = if restarted <= 1 {
                    0
                } else {
                    (idx as u64).saturating_mul(spread_ms) / (restarted as u64 - 1)
                };
                self.schedule(5_000 + offset, RealSimEventKind::RestartStart { node });
            }
        }

        fn relay_fanout_for_message(&self, msg: &RealSimMessage) -> usize {
            let base = (((self.validators as f64).ln() * 2.0).ceil() as usize + 2).clamp(
                REAL_DRIVER_SIM_MIN_RELAY_FANOUT,
                REAL_DRIVER_SIM_MAX_RELAY_FANOUT,
            );
            match msg {
                RealSimMessage::Block(_) => base
                    .saturating_mul(REAL_DRIVER_SIM_BLOCK_FANOUT_MULTIPLIER)
                    .min(REAL_DRIVER_SIM_MAX_BLOCK_FANOUT),
                RealSimMessage::Vote(_)
                | RealSimMessage::VrfCommit(_)
                | RealSimMessage::VrfReveal(_)
                | RealSimMessage::QcRequest { .. }
                | RealSimMessage::VrfRevealsRequest { .. } => base,
                RealSimMessage::QcResponse { .. } | RealSimMessage::VrfRevealsResponse { .. } => 1,
            }
        }

        fn rendezvous_candidates(
            node: usize,
            candidates: impl Iterator<Item = usize>,
        ) -> Vec<usize> {
            let mut ordered = candidates
                .filter(|candidate| *candidate != node)
                .map(|candidate| {
                    let mut seed = Vec::with_capacity(4);
                    seed.extend_from_slice(&(node as u16).to_le_bytes());
                    seed.extend_from_slice(&(candidate as u16).to_le_bytes());
                    let digest = indra_crypto::sha256(&seed);
                    (
                        u64::from_le_bytes(digest[..8].try_into().unwrap_or([0xFF; 8])),
                        candidate,
                    )
                })
                .collect::<Vec<_>>();
            ordered.sort();
            ordered
                .into_iter()
                .map(|(_, candidate)| candidate)
                .collect()
        }

        fn connect_outbound(
            graph: &mut [HashSet<usize>],
            inbound_counts: &mut [usize],
            node: usize,
            ordered_candidates: Vec<usize>,
            target_outbound: usize,
            max_inbound: usize,
        ) {
            let mut outbound = graph[node].len();
            for candidate in ordered_candidates {
                if outbound >= target_outbound {
                    break;
                }
                if inbound_counts[candidate] >= max_inbound || graph[node].contains(&candidate) {
                    continue;
                }
                graph[node].insert(candidate);
                graph[candidate].insert(node);
                inbound_counts[candidate] += 1;
                outbound += 1;
            }
        }

        fn build_bootstrap_first_graph(
            n: usize,
            target_outbound: usize,
            max_inbound: usize,
        ) -> Vec<HashSet<usize>> {
            let bootstrap = 0usize;
            let mut graph = vec![HashSet::<usize>::new(); n];
            let mut inbound_counts = vec![0usize; n];

            for node in 1..n {
                Self::connect_outbound(
                    &mut graph,
                    &mut inbound_counts,
                    node,
                    vec![bootstrap],
                    1,
                    max_inbound,
                );
            }
            for node in 0..n {
                let mut candidates = Vec::new();
                if node != bootstrap {
                    candidates.push(bootstrap);
                }
                candidates.extend(Self::rendezvous_candidates(node, 0..n));
                Self::connect_outbound(
                    &mut graph,
                    &mut inbound_counts,
                    node,
                    candidates,
                    target_outbound,
                    max_inbound,
                );
            }

            graph
        }

        fn build_full_static_graph(n: usize) -> Vec<HashSet<usize>> {
            (0..n)
                .map(|node| (0..n).filter(|peer| *peer != node).collect())
                .collect()
        }

        fn relay_targets(
            &self,
            node: usize,
            origin: usize,
            fanout: usize,
            key: Option<&RealSimRelayKey>,
        ) -> Vec<usize> {
            let mut neighbors = self.graph[node]
                .iter()
                .copied()
                .filter(|peer| {
                    self.nodes[*peer].online
                        && key.is_none_or(|key| {
                            !self.relay_forwarded[node]
                                .get(key)
                                .is_some_and(|forwarded| forwarded.contains(peer))
                        })
                })
                .map(|peer| {
                    let mut seed = Vec::with_capacity(6);
                    seed.extend_from_slice(&(origin as u16).to_le_bytes());
                    seed.extend_from_slice(&(node as u16).to_le_bytes());
                    seed.extend_from_slice(&(peer as u16).to_le_bytes());
                    let digest = indra_crypto::sha256(&seed);
                    (
                        u64::from_le_bytes(digest[..8].try_into().unwrap_or([0xFF; 8])),
                        peer,
                    )
                })
                .collect::<Vec<_>>();
            neighbors.sort();
            neighbors
                .into_iter()
                .take(fanout)
                .map(|(_, peer)| peer)
                .collect()
        }

        fn missing_local_commit_in_open_reveal_phase(
            driver: &ConsensusDriver,
            height: u64,
            round: u32,
        ) -> bool {
            let Some(local_id) = driver.engine.validator_id() else {
                return false;
            };
            let Some(slot) = driver.vrf_slot_index(height, round) else {
                return false;
            };
            let Some(state) = driver.vrf_states[slot].as_ref() else {
                return false;
            };
            state.phase == VrfRoundPhase::Reveal && !state.commits.contains_key(&local_id)
        }

        fn local_commit_and_reveal_present(
            driver: &ConsensusDriver,
            height: u64,
            round: u32,
        ) -> bool {
            let Some(local_id) = driver.engine.validator_id() else {
                return false;
            };
            let Some(slot) = driver.vrf_slot_index(height, round) else {
                return false;
            };
            let Some(state) = driver.vrf_states[slot].as_ref() else {
                return false;
            };
            state.commits.contains_key(&local_id) && state.reveals.contains_key(&local_id)
        }

        fn sync_driver_timers(&mut self, node: usize) {
            let now = Instant::now();
            let now_ms = self.now_ms;
            let node_state = &mut self.nodes[node];
            let Some(driver) = node_state.driver.as_mut() else {
                return;
            };

            for state in driver
                .vrf_states
                .iter_mut()
                .filter_map(|state| state.as_mut())
            {
                let key = (state.height, state.round);
                let commit_started_ms = *node_state
                    .vrf_commit_started_ms
                    .entry(key)
                    .or_insert(now_ms);
                state.commit_started_at =
                    now - Duration::from_millis(now_ms.saturating_sub(commit_started_ms));

                if state.reveal_started_at.is_some() {
                    let reveal_started_ms = *node_state
                        .vrf_reveal_started_ms
                        .entry(key)
                        .or_insert(now_ms);
                    state.reveal_started_at =
                        Some(now - Duration::from_millis(now_ms.saturating_sub(reveal_started_ms)));
                }
            }

            if driver.current_phase == RoundPhase::Precommit {
                let phase_started_ms = node_state.phase_started_ms;
                driver.precommit_phase_started_at =
                    Some(now - Duration::from_millis(now_ms.saturating_sub(phase_started_ms)));
            }
        }

        fn sync_phase_clock(&mut self, node: usize) -> Option<(u64, u32, RoundPhase, u64)> {
            let driver = self.nodes[node].driver.as_ref()?;
            let key = (
                driver.next_height(),
                driver.current_round(),
                driver.current_phase(),
            );
            if self.nodes[node].phase_key != Some(key) {
                self.nodes[node].phase_key = Some(key);
                self.nodes[node].phase_started_ms = self.now_ms;
            }
            Some((
                key.0,
                key.1,
                key.2,
                self.now_ms
                    .saturating_sub(self.nodes[node].phase_started_ms),
            ))
        }

        fn tick_node(&mut self, node: usize) {
            if !self.nodes[node].online {
                return;
            }
            self.sync_phase_clock(node);
            self.sync_driver_timers(node);
            let (height, round, late_commit_before, actions) = {
                let Some(driver) = self.nodes[node].driver.as_mut() else {
                    return;
                };
                let height = driver.next_height();
                let round = driver.current_round();
                let late_commit_before =
                    Self::missing_local_commit_in_open_reveal_phase(driver, height, round);
                let election = driver.active_vrf_candidates(height, round);
                let actions = driver.ensure_vrf_election_for_round(&election);
                (height, round, late_commit_before, actions)
            };
            self.last_observed_round = self.last_observed_round.max(round);
            if late_commit_before
                && self.nodes[node].driver.as_ref().is_some_and(|driver| {
                    Self::local_commit_and_reveal_present(driver, height, round)
                })
            {
                self.late_local_commit_cases = self.late_local_commit_cases.saturating_add(1);
            }
            self.handle_actions(node, actions, "tick");
            self.sync_phase_clock(node);
            self.sync_driver_timers(node);
            self.try_propose(node);

            self.sync_phase_clock(node);
            self.sync_driver_timers(node);
            let Some(driver) = self.nodes[node].driver.as_mut() else {
                return;
            };
            let actions = driver.retry_precommit_if_waiting();
            self.handle_actions(node, actions, "tick");

            if self.nodes[node]
                .driver
                .as_ref()
                .is_some_and(|driver| driver.current_phase() == RoundPhase::Propose)
            {
                if self
                    .sync_phase_clock(node)
                    .is_some_and(|(_, _, _, elapsed)| elapsed >= REAL_DRIVER_SIM_PROPOSE_TIMEOUT_MS)
                {
                    let actions = self.nodes[node]
                        .driver
                        .as_mut()
                        .unwrap()
                        .on_propose_timeout();
                    self.nodes[node].phase_key = None;
                    self.handle_actions(node, actions, "tick");
                }
            }
            if self.nodes[node]
                .driver
                .as_ref()
                .is_some_and(|driver| driver.current_phase() == RoundPhase::Prevote)
            {
                if self
                    .sync_phase_clock(node)
                    .is_some_and(|(_, _, _, elapsed)| elapsed >= REAL_DRIVER_SIM_PREVOTE_TIMEOUT_MS)
                {
                    let actions = self.nodes[node]
                        .driver
                        .as_mut()
                        .unwrap()
                        .on_prevote_timeout();
                    self.nodes[node].phase_key = None;
                    self.handle_actions(node, actions, "tick");
                }
            }
            if self.nodes[node]
                .driver
                .as_ref()
                .is_some_and(|driver| driver.current_phase() == RoundPhase::Precommit)
            {
                if self
                    .sync_phase_clock(node)
                    .is_some_and(|(_, _, _, elapsed)| {
                        elapsed >= REAL_DRIVER_SIM_PRECOMMIT_TIMEOUT_MS
                    })
                {
                    self.nodes[node]
                        .driver
                        .as_mut()
                        .unwrap()
                        .on_precommit_timeout();
                    self.nodes[node].phase_key = None;
                }
            }

            if self.nodes[node].online
                && self
                    .nodes
                    .get(node)
                    .and_then(|node| node.driver.as_ref())
                    .is_some_and(|driver| driver.height() == self.start_height)
            {
                self.schedule(
                    self.now_ms + REAL_DRIVER_SIM_TICK_MS,
                    RealSimEventKind::Tick { node },
                );
            }
        }

        fn try_propose(&mut self, node: usize) {
            if !self.nodes[node].online {
                return;
            }
            let (height, round, already_accepted, is_elected) = {
                let Some(driver) = self.nodes[node].driver.as_ref() else {
                    return;
                };
                if driver.current_phase() != RoundPhase::Propose {
                    return;
                }
                let height = driver.next_height();
                let round = driver.current_round();
                let election_result = driver.vrf_election_result(height, round);
                let is_elected = election_result.is_some_and(|result| {
                    Some(result.elected_validator_id) == driver.engine.validator_id()
                });
                (
                    height,
                    round,
                    driver.has_accepted_proposal_for_height(height),
                    is_elected,
                )
            };
            if self.nodes[node].proposed_slots.contains(&(height, round)) || already_accepted {
                return;
            }
            if !is_elected {
                return;
            }
            let actions = {
                let Some(driver) = self.nodes[node].driver.as_mut() else {
                    return;
                };
                let election_result = driver.vrf_election_result(height, round);
                let election = driver.active_vrf_candidates(height, round);
                let vrf_reveals = driver.vrf_reveal_evidence(height, round);
                let timestamp = 2_000_000_000 + height + round as u64;
                let last_qc_bytes = driver.last_qc_bytes();
                let polc_round = driver.proposal_polc_round(height);
                let block = driver
                    .engine
                    .propose(
                        &election,
                        timestamp,
                        last_qc_bytes,
                        polc_round,
                        election_result,
                        vrf_reveals,
                    )
                    .unwrap();
                driver.process(DriverEvent::InboundBlock { from: None, block })
            };
            self.nodes[node].proposed_slots.insert((height, round));
            self.handle_actions(node, actions, "tick");
        }

        fn delivery_delay_ms(&self, from: usize, to: usize) -> u64 {
            REAL_DRIVER_SIM_DELIVERY_BASE_MS
                + ((from as u64 * 17 + to as u64 * 31 + self.now_ms / 10) % 80)
        }

        fn broadcast(&mut self, from: usize, msg: RealSimMessage, source: &'static str) {
            let relay_key = real_sim_relay_key(&msg);
            if relay_key
                .as_ref()
                .is_some_and(|key| self.relay_seen[from].contains(key))
            {
                self.event_stats.suppressed_rebroadcasts =
                    self.event_stats.suppressed_rebroadcasts.saturating_add(1);
                return;
            }
            if let Some(key) = relay_key.as_ref() {
                self.relay_seen[from].insert(key.clone());
            }
            match source {
                "tick" => {
                    self.event_stats.broadcast_calls_from_tick =
                        self.event_stats.broadcast_calls_from_tick.saturating_add(1)
                }
                "deliver" => {
                    self.event_stats.broadcast_calls_from_deliver = self
                        .event_stats
                        .broadcast_calls_from_deliver
                        .saturating_add(1)
                }
                "activate" => {
                    self.event_stats.broadcast_calls_from_activate = self
                        .event_stats
                        .broadcast_calls_from_activate
                        .saturating_add(1)
                }
                _ => {}
            }
            *self
                .event_stats
                .broadcast_by_class
                .entry(real_sim_message_class(&msg))
                .or_default() += 1;
            let fanout = self.relay_fanout_for_message(&msg);
            let mut seen = HashSet::from([from]);
            let mut frontier = vec![(from, self.now_ms)];
            while let Some((relay_node, send_at)) = frontier.pop() {
                if !self.nodes[relay_node].online {
                    continue;
                }
                if let Some(key) = relay_key.as_ref() {
                    self.relay_seen[relay_node].insert(key.clone());
                }
                for to in self.relay_targets(relay_node, from, fanout, relay_key.as_ref()) {
                    if !seen.insert(to) {
                        continue;
                    }
                    let arrival = send_at + self.delivery_delay_ms(relay_node, to);
                    self.schedule(
                        arrival,
                        RealSimEventKind::Deliver {
                            from: relay_node,
                            to,
                            msg: msg.clone(),
                        },
                    );
                    if let Some(key) = relay_key.as_ref() {
                        self.relay_forwarded[relay_node]
                            .entry(key.clone())
                            .or_default()
                            .insert(to);
                    }
                    frontier.push((to, arrival));
                }
            }
        }

        fn send_to(&mut self, from: usize, to_addr: SocketAddr, msg: RealSimMessage) {
            let Some(to) = self.nodes.iter().position(|node| node.addr == to_addr) else {
                return;
            };
            if !self.nodes[to].online {
                return;
            }
            self.schedule(
                self.now_ms + self.delivery_delay_ms(from, to),
                RealSimEventKind::Deliver { from, to, msg },
            );
        }

        fn handle_actions(
            &mut self,
            origin: usize,
            actions: Vec<DriverAction>,
            source: &'static str,
        ) {
            for action in actions {
                match action {
                    DriverAction::BroadcastBlock(block) => {
                        self.broadcast(origin, RealSimMessage::Block(block), source);
                    }
                    DriverAction::BroadcastVote(vote) => {
                        self.broadcast(origin, RealSimMessage::Vote(vote), source);
                    }
                    DriverAction::BroadcastVrfCommit(commit) => {
                        self.broadcast(origin, RealSimMessage::VrfCommit(commit), source);
                    }
                    DriverAction::BroadcastVrfReveal(reveal) => {
                        self.broadcast(origin, RealSimMessage::VrfReveal(reveal), source);
                    }
                    DriverAction::RequestQC { height } => {
                        self.broadcast(origin, RealSimMessage::QcRequest { height }, source);
                    }
                    DriverAction::SendQCResponse {
                        to,
                        height,
                        qc_bytes,
                    } => {
                        self.send_to(origin, to, RealSimMessage::QcResponse { height, qc_bytes });
                    }
                    DriverAction::RequestVrfReveals {
                        height,
                        round,
                        missing_validator_ids,
                    } => {
                        self.broadcast(
                            origin,
                            RealSimMessage::VrfRevealsRequest {
                                height,
                                round,
                                missing_validator_ids,
                            },
                            source,
                        );
                    }
                    DriverAction::SendVrfRevealsResponse {
                        to,
                        height,
                        round,
                        reveals,
                    } => {
                        self.send_to(
                            origin,
                            to,
                            RealSimMessage::VrfRevealsResponse {
                                height,
                                round,
                                reveals,
                            },
                        );
                    }
                    DriverAction::ActivateBufferedProposal(block) => {
                        if let Some(driver) = self.nodes[origin].driver.as_mut() {
                            let actions =
                                driver.process(DriverEvent::InboundBlock { from: None, block });
                            self.handle_actions(origin, actions, "activate");
                        }
                    }
                    DriverAction::None
                    | DriverAction::RequestBlocks { .. }
                    | DriverAction::RequestProposal { .. }
                    | DriverAction::SlashDetected(_)
                    | DriverAction::ScorePeer { .. }
                    | DriverAction::DisconnectInvalidConsensusPeer { .. } => {}
                }
            }
        }

        fn deliver(&mut self, from: usize, to: usize, msg: RealSimMessage) {
            if !self.nodes[to].online {
                return;
            }
            if let Some(key) = real_sim_relay_key(&msg) {
                self.relay_seen[to].insert(key);
            }
            let from_addr = self.nodes[from].addr;
            self.sync_phase_clock(to);
            self.sync_driver_timers(to);
            let Some(driver) = self.nodes[to].driver.as_mut() else {
                return;
            };
            let actions = match msg {
                RealSimMessage::Block(block) => driver.process(DriverEvent::InboundBlock {
                    from: Some(from_addr),
                    block,
                }),
                RealSimMessage::Vote(vote) => driver.process(DriverEvent::InboundVote {
                    from: from_addr,
                    vote,
                }),
                RealSimMessage::VrfCommit(commit) => {
                    driver.process(DriverEvent::InboundVrfCommit {
                        from: from_addr,
                        commit,
                    })
                }
                RealSimMessage::VrfReveal(reveal) => {
                    driver.process(DriverEvent::InboundVrfReveal {
                        from: from_addr,
                        reveal,
                    })
                }
                RealSimMessage::QcRequest { height } => driver.process(DriverEvent::QcRequest {
                    from: from_addr,
                    height,
                }),
                RealSimMessage::QcResponse { height, qc_bytes } => {
                    driver.process(DriverEvent::QcResponse {
                        from: from_addr,
                        height,
                        qc_bytes,
                    })
                }
                RealSimMessage::VrfRevealsRequest {
                    height,
                    round,
                    missing_validator_ids,
                } => driver.process(DriverEvent::VrfRevealsRequest {
                    from: from_addr,
                    height,
                    round,
                    missing_validator_ids,
                }),
                RealSimMessage::VrfRevealsResponse {
                    height,
                    round,
                    reveals,
                } => driver.process(DriverEvent::VrfRevealsResponse {
                    from: from_addr,
                    height,
                    round,
                    reveals,
                }),
            };
            self.handle_actions(to, actions, "deliver");
        }

        fn run(
            &mut self,
            name: &'static str,
            restarted: usize,
            restart_spread_ms: u64,
        ) -> RealDriverRestartOutcome {
            let wall_start = Instant::now();
            if restarted > 0 {
                self.schedule_correlated_restart(restarted, restart_spread_ms);
            }
            self.start_ticks();
            let initial_online = self.validators.saturating_sub(restarted);
            let mut processed_events = 0usize;
            while let Some(event) = self.queue.pop() {
                processed_events = processed_events.saturating_add(1);
                match &event.kind {
                    RealSimEventKind::Tick { .. } => {
                        self.event_stats.processed_ticks =
                            self.event_stats.processed_ticks.saturating_add(1)
                    }
                    RealSimEventKind::Deliver { msg, .. } => {
                        self.event_stats.processed_deliveries =
                            self.event_stats.processed_deliveries.saturating_add(1);
                        *self
                            .event_stats
                            .processed_by_class
                            .entry(real_sim_message_class(msg))
                            .or_default() += 1;
                    }
                    RealSimEventKind::RestartStart { .. } => {
                        self.event_stats.processed_restarts =
                            self.event_stats.processed_restarts.saturating_add(1)
                    }
                }
                if processed_events % 50_000 == 0 {
                    eprintln!(
                        "[real-driver-restart-sim:progress] scenario={} events={} now_ms={} queue={} online={} finalized={} round_max={}",
                        name,
                        processed_events,
                        self.now_ms,
                        self.queue.len(),
                        self.online_count(),
                        self.finalized_count(),
                        self.current_round_max(),
                    );
                    if std::env::var("INDRA_REAL_DRIVER_SIM_EVENT_STATS").is_ok() {
                        self.log_event_stats(name);
                    }
                }
                if event.at_ms > REAL_DRIVER_SIM_MAX_MS {
                    break;
                }
                self.now_ms = event.at_ms;
                if self.online_count() >= self.quorum && self.first_quorum_online_round.is_none() {
                    self.first_quorum_online_round = Some(self.current_round_max());
                }
                match event.kind {
                    RealSimEventKind::Tick { node } => self.tick_node(node),
                    RealSimEventKind::Deliver { from, to, msg } => self.deliver(from, to, msg),
                    RealSimEventKind::RestartStart { node } => {
                        if !self.nodes[node].online {
                            let driver = Self::restart_driver_from_config(
                                self.nodes[node].config.clone(),
                                &self.initial_qc_bytes,
                            );
                            self.nodes[node].driver = Some(driver);
                            self.nodes[node].online = true;
                            self.nodes[node].phase_key = None;
                            self.nodes[node].phase_started_ms = self.now_ms;
                            self.nodes[node].vrf_commit_started_ms.clear();
                            self.nodes[node].vrf_reveal_started_ms.clear();
                            self.schedule(self.now_ms, RealSimEventKind::Tick { node });
                        }
                    }
                }
                self.observe_fallback_results();
                if self.finalized_count() >= self.quorum {
                    break;
                }
            }
            let finalized = self.finalized_count() >= self.quorum;
            if std::env::var("INDRA_REAL_DRIVER_SIM_EVENT_STATS").is_ok() {
                self.log_event_stats(name);
            }
            RealDriverRestartOutcome {
                name,
                validators: self.validators,
                quorum: self.quorum,
                restarted,
                initial_online,
                first_quorum_online_round: self.first_quorum_online_round,
                finalized_round: finalized.then(|| self.current_round_max()),
                via_fallback: self.via_fallback,
                finalized_nodes: self.finalized_count(),
                late_local_commit_cases: self.late_local_commit_cases,
                duration_ms: self.now_ms,
                wall_ms: wall_start.elapsed().as_millis(),
            }
        }

        fn log_event_stats(&self, name: &str) {
            eprintln!(
                "[real-driver-restart-sim:event-stats] scenario={} ticks={} deliveries={} restarts={} scheduled_deliveries={} broadcasts(tick/deliver/activate)={}/{}/{} suppressed_rebroadcasts={} queue={} scheduled_by_class={:?} processed_by_class={:?} broadcast_by_class={:?}",
                name,
                self.event_stats.processed_ticks,
                self.event_stats.processed_deliveries,
                self.event_stats.processed_restarts,
                self.event_stats.scheduled_deliveries,
                self.event_stats.broadcast_calls_from_tick,
                self.event_stats.broadcast_calls_from_deliver,
                self.event_stats.broadcast_calls_from_activate,
                self.event_stats.suppressed_rebroadcasts,
                self.queue.len(),
                self.event_stats.scheduled_by_class,
                self.event_stats.processed_by_class,
                self.event_stats.broadcast_by_class,
            );
        }
    }

    impl Drop for RealDriverSimHarness {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    #[ignore = "scale-validation real-driver N=200 correlated restart harness; run explicitly with --ignored --nocapture"]
    fn real_driver_correlated_restart_n200_harness() {
        let scenarios = [
            ("baseline", 0usize, 0u64),
            ("restart_25pct", real_driver_sim_n() / 4, 15_000u64),
            ("restart_50pct", real_driver_sim_n() / 2, 15_000u64),
            ("restart_75pct", real_driver_sim_n() * 3 / 4, 15_000u64),
            (
                "restart_75pct_spread_15s",
                real_driver_sim_n() * 3 / 4,
                15_000u64,
            ),
            (
                "restart_75pct_spread_30s",
                real_driver_sim_n() * 3 / 4,
                30_000u64,
            ),
            (
                "restart_75pct_spread_60s",
                real_driver_sim_n() * 3 / 4,
                60_000u64,
            ),
            (
                "restart_75pct_spread_120s",
                real_driver_sim_n() * 3 / 4,
                120_000u64,
            ),
            (
                "restart_75pct_spread_180s",
                real_driver_sim_n() * 3 / 4,
                180_000u64,
            ),
        ];
        for (name, restarted, spread_ms) in scenarios {
            if std::env::var("INDRA_REAL_DRIVER_SIM_SCENARIO")
                .ok()
                .is_some_and(|selected| selected != name)
            {
                continue;
            }
            eprintln!("[real-driver-restart-sim:start] scenario={name}");
            let mut harness = RealDriverSimHarness::new(name);
            let outcome = harness.run(name, restarted, spread_ms);
            eprintln!(
                "[real-driver-restart-sim] scenario={} n={} quorum={} restarted={} initial_online={} first_quorum_online_round={:?} finalized_round={:?} via_fallback={} finalized_nodes={} duration_ms={} wall_ms={} late_local_commit_cases={}",
                outcome.name,
                outcome.validators,
                outcome.quorum,
                outcome.restarted,
                outcome.initial_online,
                outcome.first_quorum_online_round,
                outcome.finalized_round,
                outcome.via_fallback,
                outcome.finalized_nodes,
                outcome.duration_ms,
                outcome.wall_ms,
                outcome.late_local_commit_cases,
            );
            assert!(
                outcome.finalized_nodes >= outcome.quorum,
                "scenario {name} should finalize on at least quorum validators"
            );
        }
    }

    #[test]
    #[ignore = "real-hardware aggregate consensus-flood benchmark; run explicitly with --ignored --nocapture and INDRA_REAL_DRIVER_SIM_N=4"]
    fn real_driver_combined_consensus_flood_stays_within_round_budget() {
        let mut baseline = RealDriverSimHarness::new_with_start_height("consensus_baseline", 0);
        assert_eq!(baseline.validators, 4);
        let baseline_outcome = baseline.run("consensus_baseline", 0, 0);

        let mut harness =
            RealDriverSimHarness::new_with_start_height("combined_consensus_flood", 0);
        assert_eq!(
            harness.validators, 4,
            "set INDRA_REAL_DRIVER_SIM_N=4 for the below-BFT-threshold scenario"
        );
        let scheduled_flood_deliveries = harness.schedule_combined_consensus_flood(14);
        let outcome = harness.run("combined_consensus_flood", 0, 0);
        eprintln!(
            "[combined-consensus-flood] baseline_virtual_ms={} baseline_wall_ms={} scheduled_flood_deliveries={} processed_by_class={:?} flood_virtual_ms={} flood_wall_ms={} finalized_nodes={} quorum={} finalized_round={:?}",
            baseline_outcome.duration_ms,
            baseline_outcome.wall_ms,
            scheduled_flood_deliveries,
            harness.event_stats.processed_by_class,
            outcome.duration_ms,
            outcome.wall_ms,
            outcome.finalized_nodes,
            outcome.quorum,
            outcome.finalized_round,
        );
        assert!(outcome.finalized_nodes >= outcome.quorum);
        assert!(
            outcome.duration_ms
                <= REAL_DRIVER_SIM_PROPOSE_TIMEOUT_MS
                    + REAL_DRIVER_SIM_PREVOTE_TIMEOUT_MS
                    + REAL_DRIVER_SIM_PRECOMMIT_TIMEOUT_MS,
            "honest quorum must progress within one complete 8s/3s/3s round budget"
        );
        assert!(
            outcome.wall_ms
                <= (REAL_DRIVER_SIM_PROPOSE_TIMEOUT_MS
                    + REAL_DRIVER_SIM_PREVOTE_TIMEOUT_MS
                    + REAL_DRIVER_SIM_PRECOMMIT_TIMEOUT_MS) as u128,
            "serial processing on this hardware must not consume an entire round budget"
        );
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

    fn setup_four_validator_vrf_round(
        local_seed: [u8; 32],
        suffix: &str,
        height: u64,
        round: u32,
    ) -> (ConsensusDriver, PathBuf, [[u8; 32]; 3], Bytes32) {
        let remote_seeds = [[0xA2u8; 32], [0xA3u8; 32], [0xA4u8; 32]];
        let (mut driver, dir) = local_driver(local_seed, suffix);
        install_active_validator(&mut driver, local_seed, "local");
        install_active_validator(&mut driver, remote_seeds[0], "b");
        install_active_validator(&mut driver, remote_seeds[1], "c");
        install_active_validator(&mut driver, remote_seeds[2], "d");
        driver.refresh_registered_voters();
        driver.vrf_states[0] = Some(VrfRoundState::new(height, round));
        let local_id = driver.engine.validator_id().unwrap();
        (driver, dir, remote_seeds, local_id)
    }

    fn insert_remote_vrf_commits(
        driver: &mut ConsensusDriver,
        height: u64,
        round: u32,
        remote_seeds: &[[u8; 32]],
    ) {
        let slot = driver.vrf_slot_index(height, round).unwrap();
        for seed in remote_seeds {
            let (commit, _reveal) = signed_vrf_pair(driver, *seed, height, round, DEFAULT_CHAIN_ID);
            driver.vrf_states[slot]
                .as_mut()
                .unwrap()
                .commits
                .insert(commit.validator_id, commit);
        }
    }

    #[test]
    fn local_reveal_created_when_commit_arrives_after_reveal_phase_open() {
        let local_seed = [0xA1u8; 32];
        let height = 42;
        let round = 1;
        let (mut driver, dir, remote_seeds, local_id) = setup_four_validator_vrf_round(
            local_seed,
            "local_reveal_after_phase_open",
            height,
            round,
        );

        insert_remote_vrf_commits(&mut driver, height, round, &remote_seeds);
        let early_actions = driver.advance_vrf_round(height, round);
        let slot = driver.vrf_slot_index(height, round).unwrap();
        assert_eq!(
            driver.vrf_states[slot].as_ref().unwrap().phase,
            VrfRoundPhase::Reveal
        );
        assert!(!driver.vrf_states[slot]
            .as_ref()
            .unwrap()
            .commits
            .contains_key(&local_id));
        assert!(!driver.vrf_states[slot]
            .as_ref()
            .unwrap()
            .reveals
            .contains_key(&local_id));
        assert!(!early_actions
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastVrfReveal(_))));

        let election = election_for_round(&driver, height, round);
        let actions = driver.ensure_vrf_election_for_round(&election);

        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVrfCommit(commit)
                if commit.height == height && commit.round == round && commit.validator_id == local_id
        )));
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(
                    action,
                    DriverAction::BroadcastVrfReveal(reveal)
                        if reveal.height == height
                            && reveal.round == round
                            && reveal.validator_id == local_id
                ))
                .count(),
            1
        );
        assert!(driver.vrf_states[slot]
            .as_ref()
            .unwrap()
            .reveals
            .contains_key(&local_id));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn local_reveal_created_when_commit_arrives_before_reveal_phase_open() {
        let local_seed = [0xA5u8; 32];
        let height = 43;
        let round = 1;
        let (mut driver, dir, remote_seeds, local_id) = setup_four_validator_vrf_round(
            local_seed,
            "local_reveal_before_phase_open",
            height,
            round,
        );
        let election = election_for_round(&driver, height, round);

        let commit_actions = driver.ensure_vrf_election_for_round(&election);
        let slot = driver.vrf_slot_index(height, round).unwrap();
        assert!(commit_actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVrfCommit(commit)
                if commit.height == height && commit.round == round && commit.validator_id == local_id
        )));
        assert!(!commit_actions
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastVrfReveal(_))));
        assert_eq!(
            driver.vrf_states[slot].as_ref().unwrap().phase,
            VrfRoundPhase::Commit
        );

        insert_remote_vrf_commits(&mut driver, height, round, &remote_seeds[..2]);
        let reveal_actions = driver.advance_vrf_round(height, round);

        assert_eq!(
            reveal_actions
                .iter()
                .filter(|action| matches!(
                    action,
                    DriverAction::BroadcastVrfReveal(reveal)
                        if reveal.height == height
                            && reveal.round == round
                            && reveal.validator_id == local_id
                ))
                .count(),
            1
        );
        assert!(driver.vrf_states[slot]
            .as_ref()
            .unwrap()
            .reveals
            .contains_key(&local_id));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn local_reveal_not_duplicated_if_both_paths_could_fire() {
        let local_seed = [0xA6u8; 32];
        let height = 44;
        let round = 1;
        let (mut driver, dir, remote_seeds, local_id) =
            setup_four_validator_vrf_round(local_seed, "local_reveal_no_duplicate", height, round);
        let election = election_for_round(&driver, height, round);

        driver.ensure_vrf_election_for_round(&election);
        insert_remote_vrf_commits(&mut driver, height, round, &remote_seeds[..2]);
        let first = driver.advance_vrf_round(height, round);
        let second = driver.ensure_vrf_election_for_round(&election);
        let third = driver.advance_vrf_round(height, round);

        let local_reveal_broadcasts = first
            .iter()
            .chain(second.iter())
            .chain(third.iter())
            .filter(|action| {
                matches!(
                    action,
                    DriverAction::BroadcastVrfReveal(reveal)
                        if reveal.height == height
                            && reveal.round == round
                            && reveal.validator_id == local_id
                )
            })
            .count();
        assert_eq!(local_reveal_broadcasts, 1);
        let slot = driver.vrf_slot_index(height, round).unwrap();
        assert_eq!(
            driver.vrf_states[slot]
                .as_ref()
                .unwrap()
                .reveals
                .keys()
                .filter(|validator_id| **validator_id == local_id)
                .count(),
            1
        );
        let _ = std::fs::remove_dir_all(dir);
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
        driver.engine.state.consensus_snapshots.push(
            driver
                .engine
                .state
                .build_consensus_snapshot(u64::MAX, u64::MAX - 1)
                .unwrap(),
        );
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
            "self-contained reveal evidence should enter normal processing immediately"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn two_two_local_election_hash_split_still_finalizes_valid_proposal() {
        let local_seed = [0x31u8; 32];
        let seed_b = [0x32u8; 32];
        let seed_c = [0x33u8; 32];
        let seed_d = [0x34u8; 32];
        let (mut driver, dir) = local_driver(local_seed, "two_two_split_votes_block");
        let local = install_active_validator(&mut driver, local_seed, "local");
        let b = install_active_validator(&mut driver, seed_b, "b");
        let c = install_active_validator(&mut driver, seed_c, "c");
        let _d = install_active_validator(&mut driver, seed_d, "d");
        driver.refresh_registered_voters();
        let height = FINAL_REVEAL_SET_HEIGHT + 1;
        let round = 0;
        driver.engine.state.height = height - 1;
        driver
            .engine
            .block_store
            .append(&crate::genesis::build_genesis_block())
            .unwrap();
        let mut stored_parent = make_block(&driver.engine.state);
        stored_parent.header.height = height - 1;
        driver.engine.block_store.append(&stored_parent).unwrap();
        driver.engine.state.tip_hash = stored_parent.header.block_hash();
        driver.sync.mark_caught_up(driver.engine.state.height);
        driver.start_round(round);

        let (commit_a, reveal_a) =
            signed_vrf_pair(&driver, local_seed, height, round, DEFAULT_CHAIN_ID);
        let (commit_b, reveal_b) =
            signed_vrf_pair(&driver, seed_b, height, round, DEFAULT_CHAIN_ID);
        let (commit_c, reveal_c) =
            signed_vrf_pair(&driver, seed_c, height, round, DEFAULT_CHAIN_ID);
        let mut block = reveal_set_block_from_reveals_at(
            &driver,
            &[local_seed, seed_b, seed_c, seed_d],
            &[reveal_a.clone(), reveal_b.clone(), reveal_c.clone()],
            height,
            round,
        );
        attach_parent_qc(&driver, &mut block, &[&local, &b, &c]);
        let block_hash = block.header.block_hash();
        let proposal_election_hash = block
            .header
            .election_result_hash
            .expect("reveal-set block must commit to election result");
        set_complete_vrf_state_with_divergent_result(
            &mut driver,
            height,
            round,
            vec![commit_a, commit_b, commit_c],
            vec![reveal_a, reveal_b, reveal_c],
            proposal_election_hash,
        );

        let actions = driver.process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:9931".parse().unwrap()),
            block: block.clone(),
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
            !actions.iter().any(|action| matches!(
                action,
                DriverAction::BroadcastVote(vote)
                    if vote.height == height
                        && vote.round == round
                        && vote.step == VoteStep::Prevote
                        && vote.block_hash == Bytes32::ZERO
            )),
            "post-activation voting must not nil-prevote solely because the local reveal view hashes differently"
        );

        for (peer, signer) in [("127.0.0.1:9932", &b), ("127.0.0.1:9933", &c)] {
            let vote = indra_consensus::vote::produce_vote(
                height,
                round,
                VoteStep::Prevote,
                block_hash,
                validator_id_for(signer),
                DEFAULT_CHAIN_ID,
                signer,
            )
            .unwrap();
            let actions = driver.process(DriverEvent::InboundVote {
                from: peer.parse().unwrap(),
                vote,
            });
            if actions.iter().any(|action| {
                matches!(
                    action,
                    DriverAction::BroadcastVote(vote)
                        if vote.step == VoteStep::Precommit
                            && vote.height == height
                            && vote.round == round
                )
            }) {
                assert!(actions.iter().any(|action| matches!(
                    action,
                    DriverAction::BroadcastVote(vote)
                        if vote.step == VoteStep::Precommit
                            && vote.block_hash == block_hash
                            && vote.election_result_hash == Some(proposal_election_hash)
                )));
            }
        }

        for (peer, signer) in [("127.0.0.1:9934", &b), ("127.0.0.1:9935", &c)] {
            let vote = indra_consensus::vote::produce_vote_with_election_result(
                height,
                round,
                VoteStep::Precommit,
                block_hash,
                validator_id_for(signer),
                Some(proposal_election_hash),
                DEFAULT_CHAIN_ID,
                signer,
            )
            .unwrap();
            let _ = driver.process(DriverEvent::InboundVote {
                from: peer.parse().unwrap(),
                vote,
            });
        }
        assert_eq!(
            driver.height(),
            height,
            "valid proposer-specified reveal set should finalize even when local election hashes split 2-2"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn three_one_split_finalizes_without_minority_nil_vote() {
        let local_seed = [0x35u8; 32];
        let seed_b = [0x36u8; 32];
        let seed_c = [0x37u8; 32];
        let seed_d = [0x38u8; 32];
        let (mut driver, dir) = local_driver(local_seed, "three_one_split_votes_block");
        let local = install_active_validator(&mut driver, local_seed, "local");
        let b = install_active_validator(&mut driver, seed_b, "b");
        let c = install_active_validator(&mut driver, seed_c, "c");
        let _d = install_active_validator(&mut driver, seed_d, "d");
        driver.refresh_registered_voters();
        let height = FINAL_REVEAL_SET_HEIGHT + 1;
        let round = 0;
        driver.engine.state.height = height - 1;
        driver
            .engine
            .block_store
            .append(&crate::genesis::build_genesis_block())
            .unwrap();
        let mut stored_parent = make_block(&driver.engine.state);
        stored_parent.header.height = height - 1;
        driver.engine.block_store.append(&stored_parent).unwrap();
        driver.engine.state.tip_hash = stored_parent.header.block_hash();
        driver.sync.mark_caught_up(driver.engine.state.height);
        driver.start_round(round);

        let (commit_a, reveal_a) =
            signed_vrf_pair(&driver, local_seed, height, round, DEFAULT_CHAIN_ID);
        let (commit_b, reveal_b) =
            signed_vrf_pair(&driver, seed_b, height, round, DEFAULT_CHAIN_ID);
        let (commit_c, reveal_c) =
            signed_vrf_pair(&driver, seed_c, height, round, DEFAULT_CHAIN_ID);
        let mut block = reveal_set_block_from_reveals_at(
            &driver,
            &[local_seed, seed_b, seed_c, seed_d],
            &[reveal_a.clone(), reveal_b.clone(), reveal_c.clone()],
            height,
            round,
        );
        attach_parent_qc(&driver, &mut block, &[&local, &b, &c]);
        let block_hash = block.header.block_hash();
        let proposal_election_hash = block.header.election_result_hash.unwrap();
        set_complete_vrf_state_with_divergent_result(
            &mut driver,
            height,
            round,
            vec![commit_a, commit_b, commit_c],
            vec![reveal_a, reveal_b, reveal_c],
            proposal_election_hash,
        );

        let actions = driver.process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:9936".parse().unwrap()),
            block,
        });
        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == block_hash
        )));

        for (peer, signer) in [("127.0.0.1:9937", &b), ("127.0.0.1:9938", &c)] {
            let vote = indra_consensus::vote::produce_vote(
                height,
                round,
                VoteStep::Prevote,
                block_hash,
                validator_id_for(signer),
                DEFAULT_CHAIN_ID,
                signer,
            )
            .unwrap();
            let _ = driver.process(DriverEvent::InboundVote {
                from: peer.parse().unwrap(),
                vote,
            });
        }
        for (peer, signer) in [("127.0.0.1:9939", &b), ("127.0.0.1:9940", &c)] {
            let vote = indra_consensus::vote::produce_vote_with_election_result(
                height,
                round,
                VoteStep::Precommit,
                block_hash,
                validator_id_for(signer),
                Some(proposal_election_hash),
                DEFAULT_CHAIN_ID,
                signer,
            )
            .unwrap();
            let _ = driver.process(DriverEvent::InboundVote {
                from: peer.parse().unwrap(),
                vote,
            });
        }
        assert_eq!(driver.height(), height);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn invalid_reveal_set_evidence_still_rejected_before_voting() {
        let local_seed = [0x39u8; 32];
        let seed_b = [0x3Au8; 32];
        let seed_c = [0x3Bu8; 32];
        let seed_d = [0x3Cu8; 32];
        let (mut driver, dir) = local_driver(local_seed, "invalid_reveal_set_still_rejected");
        let local = install_active_validator(&mut driver, local_seed, "local");
        let b = install_active_validator(&mut driver, seed_b, "b");
        let c = install_active_validator(&mut driver, seed_c, "c");
        let _d = install_active_validator(&mut driver, seed_d, "d");
        driver.refresh_registered_voters();
        let height = FINAL_REVEAL_SET_HEIGHT + 1;
        let round = 0;
        driver.engine.state.height = height - 1;
        driver.engine.state.tip_hash = Bytes32::from([0x39; 32]);
        driver.sync.mark_caught_up(driver.engine.state.height);
        driver.start_round(round);

        let (_, reveal_a) = signed_vrf_pair(&driver, local_seed, height, round, DEFAULT_CHAIN_ID);
        let (_, reveal_b) = signed_vrf_pair(&driver, seed_b, height, round, DEFAULT_CHAIN_ID);
        let (_, reveal_c) = signed_vrf_pair(&driver, seed_c, height, round, DEFAULT_CHAIN_ID);
        let mut block = reveal_set_block_from_reveals_at(
            &driver,
            &[local_seed, seed_b, seed_c, seed_d],
            &[reveal_a.clone(), reveal_b.clone(), reveal_c.clone()],
            height,
            round,
        );
        attach_parent_qc(&driver, &mut block, &[&local, &b, &c]);
        block.vrf_reveals.pop();

        let actions = driver.process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:9941".parse().unwrap()),
            block,
        });
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, DriverAction::BroadcastVote(_))),
            "invalid reveal-set evidence must be rejected before the voting authority change can apply"
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
        install_test_snapshot_at_inert_gate(&mut driver);
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
        install_test_snapshot_at_inert_gate(&mut driver);
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
    fn reveal_evidence_frozen_at_election_result_computation() {
        let seeds = [[0x91u8; 32], [0x92u8; 32], [0x93u8; 32], [0x94u8; 32]];
        let (mut driver, dir) = local_driver(seeds[0], "reveal_evidence_frozen");
        for (idx, seed) in seeds.iter().enumerate() {
            install_active_validator(&mut driver, *seed, &format!("v{idx}"));
        }
        install_test_snapshot_at_inert_gate(&mut driver);
        driver.refresh_registered_voters();
        driver.engine.state.height = u64::MAX - 1;
        driver.engine.state.tip_hash = Bytes32::from([0x91; 32]);

        let height = u64::MAX;
        let round = 0;
        let signed: Vec<_> = seeds
            .iter()
            .map(|seed| signed_vrf_pair(&driver, *seed, height, round, DEFAULT_CHAIN_ID))
            .collect();
        let mut state = VrfRoundState::new(height, round);
        state.phase = VrfRoundPhase::Reveal;
        state.reveal_started_at =
            Some(Instant::now() - Duration::from_millis(VRF_REVEAL_WINDOW_MS + 10));
        for (commit, _) in &signed {
            state.commits.insert(commit.validator_id, commit.clone());
        }
        for (_, reveal) in signed.iter().take(3) {
            state.reveals.insert(reveal.validator_id, reveal.clone());
        }
        driver.vrf_states[0] = Some(state);

        let result = driver
            .compute_and_store_vrf_election(0)
            .expect("three of four reveals should satisfy quorum");
        let frozen = driver.vrf_reveal_evidence(height, round);
        assert_eq!(frozen.len(), 3);
        assert_eq!(
            result.reveal_set_commitment,
            compute_reveal_set_commitment(&frozen)
        );

        let late_reveal = signed[3].1.clone();
        let actions = driver.insert_valid_vrf_reveal(0, late_reveal, false, None);
        assert!(actions.is_empty());
        assert_eq!(
            driver.vrf_states[0]
                .as_ref()
                .expect("slot present")
                .reveals
                .len(),
            4,
            "late valid reveal should still be accepted into live gossip state"
        );
        assert_eq!(
            driver.vrf_reveal_evidence(height, round),
            frozen,
            "proposal evidence must remain the frozen set, not the expanded live set"
        );

        let proposer_seed = seeds
            .iter()
            .copied()
            .find(|seed| validator_id_for_seed(*seed) == result.elected_validator_id)
            .expect("elected validator maps to one test seed");
        let election = election_for_round(&driver, height, round);
        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&proposer_seed),
            epoch_seed: election.epoch_seed,
            prev_qc_bytes: vec![],
            timestamp: 1_700_000_001,
            polc_round: None,
            transactions: vec![],
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            election_result_hash: Some(result.hash()),
            election_result: Some(result),
            vrf_reveals: frozen.clone(),
        };
        let block = produce_block(&template, &mut driver.engine.state, &election)
            .expect("frozen evidence should satisfy the authoritative result commitment");

        assert_eq!(block.vrf_reveals, frozen);
        assert_eq!(block.header.election_result_hash, Some(result.hash()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn late_reveals_after_quorum_result_do_not_reproduce_proposer_mismatch() {
        let seeds = [[0x95u8; 32], [0x96u8; 32], [0x97u8; 32], [0x98u8; 32]];
        let (mut driver, dir) = local_driver(seeds[0], "late_reveals_no_mismatch");
        for (idx, seed) in seeds.iter().enumerate() {
            install_active_validator(&mut driver, *seed, &format!("v{idx}"));
        }
        install_test_snapshot_at_inert_gate(&mut driver);
        driver.refresh_registered_voters();
        driver.engine.state.height = u64::MAX - 1;
        driver.engine.state.tip_hash = Bytes32::from([0x95; 32]);

        let height = u64::MAX;
        let round = 0;
        let signed: Vec<_> = seeds
            .iter()
            .map(|seed| signed_vrf_pair(&driver, *seed, height, round, DEFAULT_CHAIN_ID))
            .collect();
        let mut state = VrfRoundState::new(height, round);
        state.phase = VrfRoundPhase::Reveal;
        state.reveal_started_at =
            Some(Instant::now() - Duration::from_millis(VRF_REVEAL_WINDOW_MS + 10));
        for (commit, _) in &signed {
            state.commits.insert(commit.validator_id, commit.clone());
        }
        for (_, reveal) in signed.iter().take(3) {
            state.reveals.insert(reveal.validator_id, reveal.clone());
        }
        driver.vrf_states[0] = Some(state);

        let result = driver
            .compute_and_store_vrf_election(0)
            .expect("quorum-backed election result should be computed");
        let frozen = driver.vrf_reveal_evidence(height, round);
        let live_before_late = compute_reveal_set_commitment(&frozen);
        assert_eq!(live_before_late, result.reveal_set_commitment);

        let late_reveal = signed[3].1.clone();
        let _ = driver.insert_valid_vrf_reveal(0, late_reveal, false, None);
        let expanded_live_evidence = reveal_evidence_from_reveals(
            driver.vrf_states[0]
                .as_ref()
                .expect("slot present")
                .reveals
                .values()
                .cloned(),
        );
        assert_ne!(
            compute_reveal_set_commitment(&expanded_live_evidence),
            result.reveal_set_commitment,
            "this is the live bug shape: rebuilding from mutable reveals would mismatch"
        );

        let proposer_seed = seeds
            .iter()
            .copied()
            .find(|seed| validator_id_for_seed(*seed) == result.elected_validator_id)
            .expect("elected validator maps to one test seed");
        let election = election_for_round(&driver, height, round);
        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&proposer_seed),
            epoch_seed: election.epoch_seed,
            prev_qc_bytes: vec![],
            timestamp: 1_700_000_001,
            polc_round: None,
            transactions: vec![],
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            election_result_hash: Some(result.hash()),
            election_result: Some(result),
            vrf_reveals: driver.vrf_reveal_evidence(height, round),
        };

        produce_block(&template, &mut driver.engine.state, &election)
            .expect("proposal must use frozen evidence and avoid proposer identity mismatch");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sub_quorum_reveals_count_toward_fallback_threshold() {
        let local_seed = [0xC1u8; 32];
        let seed_b = [0xC2u8; 32];
        let seed_c = [0xC3u8; 32];
        let seed_d = [0xC4u8; 32];
        let (mut driver, dir) = local_driver(local_seed, "sub_quorum_counts_to_fallback");
        install_active_validator(&mut driver, local_seed, "local");
        install_active_validator(&mut driver, seed_b, "b");
        install_active_validator(&mut driver, seed_c, "c");
        install_active_validator(&mut driver, seed_d, "d");
        install_test_snapshot_at_inert_gate(&mut driver);
        driver.refresh_registered_voters();
        driver.engine.state.height = u64::MAX - 1;
        driver.engine.state.tip_hash = Bytes32::from([0xC1; 32]);

        let height = u64::MAX;
        for round in 0..MAX_VRF_EMPTY_REVEAL_ROUNDS {
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
            assert_eq!(
                driver.consecutive_empty_reveal_rounds,
                round + 1,
                "sub-quorum non-zero reveal rounds must advance the same bounded fallback counter as zero-reveal rounds"
            );
            if round + 1 < MAX_VRF_EMPTY_REVEAL_ROUNDS {
                assert!(
                    result.is_none(),
                    "fallback must wait until the configured insufficient-reveal threshold"
                );
            } else {
                let result = result.expect("fallback should be produced at threshold");
                assert!(result.fallback_used);
                assert_eq!(
                    result.reveal_set_commitment,
                    compute_reveal_set_commitment(&[]),
                    "deterministic fallback commits to the canonical empty reveal evidence set"
                );
            }
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn permanent_reveal_deficit_still_guarantees_progress() {
        let local_seed = [0xC5u8; 32];
        let seed_b = [0xC6u8; 32];
        let seed_c = [0xC7u8; 32];
        let seed_d = [0xC8u8; 32];
        let (mut driver, dir) = local_driver(local_seed, "permanent_deficit_fallback");
        install_active_validator(&mut driver, local_seed, "local");
        install_active_validator(&mut driver, seed_b, "b");
        install_active_validator(&mut driver, seed_c, "c");
        install_active_validator(&mut driver, seed_d, "d");
        install_test_snapshot_at_inert_gate(&mut driver);
        driver.refresh_registered_voters();
        driver.engine.state.height = u64::MAX - 1;
        driver.engine.state.tip_hash = Bytes32::from([0xC5; 32]);

        let height = u64::MAX;
        let mut fallback = None;
        for round in 0..MAX_VRF_EMPTY_REVEAL_ROUNDS {
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
            if round + 1 < MAX_VRF_EMPTY_REVEAL_ROUNDS {
                assert!(
                    actions
                        .iter()
                        .any(|action| matches!(action, DriverAction::RequestVrfReveals { .. })),
                    "reveal recovery should still be attempted while the bounded fallback counter advances"
                );
            }
            fallback = driver.vrf_election_result(height, round);
        }

        let fallback = fallback.expect("permanent reveal deficit must produce bounded fallback");
        assert!(fallback.fallback_used);
        assert_eq!(
            fallback.reveal_set_commitment,
            compute_reveal_set_commitment(&[]),
            "fallback is independent of validator count and sparse local gossip state"
        );
        assert!(
            driver
                .vrf_reveal_evidence(height, MAX_VRF_EMPTY_REVEAL_ROUNDS - 1)
                .is_empty(),
            "fallback block bodies must carry the canonical empty reveal evidence set"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn request_and_fallback_counter_operate_concurrently() {
        let local_seed = [0xC9u8; 32];
        let seed_b = [0xCAu8; 32];
        let seed_c = [0xCBu8; 32];
        let seed_d = [0xCCu8; 32];
        let (mut driver, dir) = local_driver(local_seed, "request_and_counter_concurrent");
        install_active_validator(&mut driver, local_seed, "local");
        install_active_validator(&mut driver, seed_b, "b");
        install_active_validator(&mut driver, seed_c, "c");
        install_active_validator(&mut driver, seed_d, "d");
        install_test_snapshot_at_inert_gate(&mut driver);
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

        assert_eq!(
            driver.consecutive_empty_reveal_rounds, 1,
            "sub-quorum request path must not bypass fallback accounting"
        );
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, DriverAction::RequestVrfReveals { .. })),
            "reveal recovery request must still fire during fallback countdown"
        );
        assert!(driver.vrf_election_result(height, round).is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn quorum_reveal_after_sub_quorum_resets_fallback_counter() {
        let local_seed = [0xCDu8; 32];
        let seed_b = [0xCEu8; 32];
        let seed_c = [0xCFu8; 32];
        let seed_d = [0xD0u8; 32];
        let (mut driver, dir) = local_driver(local_seed, "sub_quorum_then_quorum_reset");
        install_active_validator(&mut driver, local_seed, "local");
        install_active_validator(&mut driver, seed_b, "b");
        install_active_validator(&mut driver, seed_c, "c");
        install_active_validator(&mut driver, seed_d, "d");
        install_test_snapshot_at_inert_gate(&mut driver);
        driver.refresh_registered_voters();
        driver.engine.state.height = u64::MAX - 1;
        driver.engine.state.tip_hash = Bytes32::from([0xCD; 32]);

        let height = u64::MAX;
        let (commit_a, reveal_a) =
            signed_vrf_pair(&driver, local_seed, height, 0, DEFAULT_CHAIN_ID);
        let mut sparse = VrfRoundState::new(height, 0);
        sparse.phase = VrfRoundPhase::Reveal;
        sparse.reveal_started_at =
            Some(Instant::now() - Duration::from_millis(VRF_REVEAL_WINDOW_MS + 10));
        sparse.commits.insert(commit_a.validator_id, commit_a);
        sparse.reveals.insert(reveal_a.validator_id, reveal_a);
        driver.vrf_states[0] = Some(sparse);
        assert!(driver.compute_and_store_vrf_election(0).is_none());
        assert_eq!(driver.consecutive_empty_reveal_rounds, 1);

        let (commit_a, reveal_a) =
            signed_vrf_pair(&driver, local_seed, height, 1, DEFAULT_CHAIN_ID);
        let (commit_b, reveal_b) = signed_vrf_pair(&driver, seed_b, height, 1, DEFAULT_CHAIN_ID);
        let (commit_c, reveal_c) = signed_vrf_pair(&driver, seed_c, height, 1, DEFAULT_CHAIN_ID);
        let mut quorum = VrfRoundState::new(height, 1);
        quorum.phase = VrfRoundPhase::Reveal;
        quorum.reveal_started_at =
            Some(Instant::now() - Duration::from_millis(VRF_REVEAL_WINDOW_MS + 10));
        for commit in [commit_a, commit_b, commit_c] {
            quorum.commits.insert(commit.validator_id, commit);
        }
        for reveal in [reveal_a, reveal_b, reveal_c] {
            quorum.reveals.insert(reveal.validator_id, reveal);
        }
        driver.vrf_states[0] = Some(quorum);

        let result = driver
            .compute_and_store_vrf_election(0)
            .expect("quorum reveal set should complete normal election");
        assert!(!result.fallback_used);
        assert_eq!(
            driver.consecutive_empty_reveal_rounds, 0,
            "quorum-backed recovery must reset the bounded fallback counter"
        );

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
        install_test_snapshot_at_inert_gate(&mut driver);
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
        install_test_snapshot_at_inert_gate(&mut driver);
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
        install_test_snapshot_at_inert_gate(&mut driver);
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
        let election_result = driver.vrf_election_result(height, round);
        let vrf_reveals = driver.vrf_reveal_evidence(height, round);
        let proposal = driver.engine.propose(
            &election,
            1_900_000_001,
            last_qc_bytes,
            None,
            election_result,
            vrf_reveals,
        );
        assert!(
            proposal.is_err(),
            "post-activation proposal must not be produced without a quorum-backed election hash"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn fallback_round_depth_check_ignores_desynced_local_counter() {
        let local_seed = [0xE5u8; 32];
        let seed_b = [0xE6u8; 32];
        let seed_c = [0xE7u8; 32];
        let seed_d = [0xE8u8; 32];
        let (mut driver, dir) = local_driver(local_seed, "fallback_depth_desync");
        install_active_validator(&mut driver, local_seed, "local");
        install_active_validator(&mut driver, seed_b, "b");
        install_active_validator(&mut driver, seed_c, "c");
        install_active_validator(&mut driver, seed_d, "d");
        install_test_snapshot_at_inert_gate(&mut driver);
        driver.refresh_registered_voters();
        driver.engine.state.height = u64::MAX - 1;
        driver.engine.state.tip_hash = Bytes32::from([0xE8; 32]);

        driver.consecutive_empty_reveal_rounds = MAX_VRF_EMPTY_REVEAL_ROUNDS;
        let premature_fallback =
            reveal_set_block_from_reveals(&driver, &[local_seed, seed_b, seed_c, seed_d], &[]);
        assert_eq!(premature_fallback.header.proposer_round, 0);

        let err =
            crate::sync::verify_reveal_set_evidence(&premature_fallback, &driver.engine.state)
                .unwrap_err();
        match err {
            NodeError::BlockInvalid { reason, .. } => {
                assert!(
                    reason.contains("before minimum fallback round"),
                    "fallback depth must be enforced from block round, not local counter: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }

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
    fn implausible_vrf_slots_are_dropped_before_crypto_for_commit_and_reveal() {
        let (mut driver, dir) = local_driver([0x17; 32], "vrf_implausible_slots");
        install_active_validator(&mut driver, [0x27; 32], "peer");
        let next_height = driver.next_height();
        let current_round = driver.current_round;
        let from: SocketAddr = "127.0.0.1:10004".parse().unwrap();

        let cases = [
            (next_height.saturating_sub(1), current_round),
            (next_height.saturating_add(99), current_round),
            (
                next_height,
                current_round.saturating_add(MAX_ACCEPTED_ROUND_JUMP + 1),
            ),
        ];
        for (height, round) in cases {
            let (mut commit, mut reveal) =
                signed_vrf_pair(&driver, [0x27; 32], height, round, DEFAULT_CHAIN_ID);
            // If either path reaches hybrid verification, these deliberately
            // empty signatures produce a disconnect action.
            commit.signature = ConsensusDriver::empty_signature().unwrap();
            reveal.signature = ConsensusDriver::empty_signature().unwrap();

            let commit_actions = driver.process(DriverEvent::InboundVrfCommit { from, commit });
            let reveal_actions = driver.process(DriverEvent::InboundVrfReveal { from, reveal });
            for actions in [commit_actions, reveal_actions] {
                assert!(
                    actions.iter().all(|action| !matches!(
                        action,
                        DriverAction::DisconnectInvalidConsensusPeer { .. }
                            | DriverAction::BroadcastVrfCommit(_)
                            | DriverAction::BroadcastVrfReveal(_)
                    )),
                    "an unallocated VRF slot must be cheap-dropped before cryptographic processing"
                );
            }
        }
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

            if authoritative_result_for_seed(&election_round_zero, round_zero_seed)
                .0
                .elected_validator_id
                == round_zero_winner
                && authoritative_result_for_seed(&election_round_one, round_one_seed)
                    .0
                    .elected_validator_id
                    == round_one_winner
            {
                return tip_hash;
            }
        }
        panic!("failed to find deterministic tip hash for requested reveal-set round winners");
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
            validator_id: Bytes32::ZERO,
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
            validator_id: Bytes32::ZERO,
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
            validator_id: Bytes32::ZERO,
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
                validator_id: Bytes32::ZERO,
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
        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote) if vote.block_hash == block_hash
        )));
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

        assert_eq!(vote.block_hash, block_hash);
        assert!(vote.election_result_hash.is_some());
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

        let actions = driver.sign_and_record_local_vote(1, 0, VoteStep::Precommit, block_hash);
        let vote = actions
            .iter()
            .find_map(|action| match action {
                DriverAction::BroadcastVote(vote) => Some(vote),
                _ => None,
            })
            .expect("the block's authoritative election result should produce a precommit");

        assert_eq!(vote.block_hash, block_hash);
        assert!(vote.election_result_hash.is_some());
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

        let reveals: Vec<_> = [[0xB1u8; 32], [0xB2u8; 32], [0xB3u8; 32]]
            .into_iter()
            .map(|seed| signed_vrf_pair(&driver, seed, 1, 0, DEFAULT_CHAIN_ID).1)
            .collect();
        let mut state = VrfRoundState::new(1, 0);
        state.phase = VrfRoundPhase::Reveal;
        state.reveal_started_at =
            Some(Instant::now() - Duration::from_millis(VRF_REVEAL_WINDOW_MS + 10));
        for reveal in reveals {
            state.reveals.insert(reveal.validator_id, reveal);
        }
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
        let vote_a = indra_consensus::vote::produce_vote_with_election_result(
            1,
            0,
            VoteStep::Precommit,
            Bytes32::from([0xAAu8; 32]),
            remote_id,
            Some(Bytes32::from([0xCC; 32])),
            DEFAULT_CHAIN_ID,
            &remote,
        )
        .unwrap();
        let vote_b = indra_consensus::vote::produce_vote_with_election_result(
            1,
            0,
            VoteStep::Precommit,
            Bytes32::from([0xBBu8; 32]),
            remote_id,
            Some(Bytes32::from([0xCC; 32])),
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
        let real_id = Bytes32::from(indra_crypto::sha256(&real.public_key().classical.0));
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
        let remote_id = Bytes32::from(indra_crypto::sha256(&remote.public_key().classical.0));
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
        let real_id = Bytes32::from(indra_crypto::sha256(&real.public_key().classical.0));
        for hash in [Bytes32::from([0xAA; 32]), Bytes32::from([0xBB; 32])] {
            let forged = indra_consensus::vote::produce_vote_with_election_result(
                driver.next_height(),
                0,
                VoteStep::Precommit,
                hash,
                real_id,
                Some(Bytes32::from([0xCC; 32])),
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
            {
                let election = election_for_round(&driver, 3, 0);
                let (result, evidence) = authoritative_result_for_seed(&election, [0xB5u8; 32]);
                driver
                    .engine
                    .propose(
                        &election,
                        1_700_000_003,
                        driver.last_qc_bytes(),
                        None,
                        Some(result),
                        evidence,
                    )
                    .is_ok()
            },
            "recovered current-tip QC should allow height-3 proposal construction"
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
        let _ = source.process(DriverEvent::InboundBlock {
            from: None,
            block: block1.clone(),
        });
        let qc_for_height_1 = source.last_qc_bytes();
        assert!(!qc_for_height_1.is_empty());

        let (mut driver, dir) = local_driver([0xC1u8; 32], "pending_qc_restart");
        let local = install_active_validator(&mut driver, [0xC1u8; 32], "local");
        driver.refresh_registered_voters();

        driver.engine.commit_block(&block1).unwrap();
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
        driver.engine.commit_block(&block2).unwrap();
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

        let block = make_strict_block(&driver, [0x73u8; 32], 0, vec![]);
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
        let (result, evidence) = authoritative_result_for_seed(&election, [0x73u8; 32]);

        let reproposed = driver
            .engine
            .repropose(
                &valid_block,
                1,
                Some(valid_round),
                &election,
                valid_block.header.timestamp,
                driver.last_qc_bytes(),
                Some(result),
                evidence,
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
        let (result_round_zero, evidence_round_zero) =
            authoritative_result_for_seed(&election_round_zero, [0x77u8; 32]);
        let proposal = driver
            .engine
            .propose(
                &election_round_zero,
                1_700_000_001,
                driver.last_qc_bytes(),
                None,
                Some(result_round_zero),
                evidence_round_zero,
            )
            .expect("initial proposal should succeed");

        let election_round_one = indra_consensus::proposer::ProposerElection {
            epoch_seed: election_round_zero.epoch_seed,
            height,
            round: 1,
            candidates: election_round_zero.candidates.clone(),
        };
        let (result_round_one, evidence_round_one) =
            authoritative_result_for_seed(&election_round_one, [0x77u8; 32]);
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
                Some(result_round_one),
                evidence_round_one,
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
        let (result_round_zero, evidence_round_zero) =
            authoritative_result_for_seed(&election_round_zero, [0x78u8; 32]);
        let proposal = driver
            .engine
            .propose(
                &election_round_zero,
                1_700_000_001,
                driver.last_qc_bytes(),
                None,
                Some(result_round_zero),
                evidence_round_zero,
            )
            .expect("initial proposal should succeed");

        let election_round_one = ProposerElection {
            epoch_seed: election_round_zero.epoch_seed,
            height,
            round: 1,
            candidates: election_round_zero.candidates.clone(),
        };
        let (result_round_one, evidence_round_one) =
            authoritative_result_for_seed(&election_round_one, [0x78u8; 32]);
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
                Some(result_round_one),
                evidence_round_one,
            )
            .expect("reproposal should succeed");

        let mut clone_reference = pre_state.clone();
        apply_block(&mut clone_reference, &reproposed, 0).unwrap();
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

        let a_id = Bytes32::from(indra_crypto::sha256(&a.public_key().classical.0));
        let b_id = Bytes32::from(indra_crypto::sha256(&b.public_key().classical.0));
        let c_id = Bytes32::from(indra_crypto::sha256(&c.public_key().classical.0));
        let d_id = Bytes32::from(indra_crypto::sha256(&d.public_key().classical.0));

        let chosen_tip =
            pick_tip_hash_for_verified_round_winners(&driver_a, 1, [0x81u8; 32], [0x82u8; 32]);
        driver_a.engine.state.tip_hash = chosen_tip;
        driver_b.engine.state.tip_hash = chosen_tip;

        let election_round_zero = election_for_round(&driver_a, 1, 0);
        let (result_round_zero, evidence_round_zero) =
            authoritative_result_for_seed(&election_round_zero, [0x81u8; 32]);
        assert_eq!(result_round_zero.elected_validator_id, a_id);
        let block_x = driver_a
            .engine
            .propose(
                &election_round_zero,
                1_700_000_100,
                driver_a.last_qc_bytes(),
                None,
                Some(result_round_zero),
                evidence_round_zero,
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
        let (valid_block, valid_round) = driver_b
            .take_valid_block_for_reproposal()
            .expect("round 1 proposer should still have valid block");
        let (result_round_one, evidence_round_one) =
            authoritative_result_for_seed(&election_round_one, [0x82u8; 32]);
        assert_eq!(result_round_one.elected_validator_id, b_id);
        let block_y = driver_b
            .engine
            .repropose(
                &valid_block,
                1,
                Some(valid_round),
                &election_round_one,
                valid_block.header.timestamp,
                driver_b.last_qc_bytes(),
                Some(result_round_one),
                evidence_round_one,
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
