//! Consensus driver — ties NodeEngine to the network layer.
//!
//! This file implements a compact Tendermint-style state machine for a single
//! node while preserving the existing INDRA driver interface used by
//! `node.rs`.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use indra_consensus::{
    build_qc, verify_qc,
    vote::{RegisteredVoter, VoteCollector, VoteDecision},
};
use indra_core::codec::{ByteReader, Decode, Encode};
use indra_core::types::{
    block::{BlockV1, NO_POLC_ROUND},
    primitives::Bytes32,
    qc::QuorumCertificateV1,
    transaction::TransactionV1,
    vote::{VoteStep, VoteV1},
};
use indra_storage::VoteSafetyStore;

use crate::{
    engine::NodeEngine,
    error::NodeError,
    slash::{SlashDetector, SlashEvidence},
    sync::{verify_block_qc, verify_proposer_vrf, SyncState},
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
    /// Re-process a buffered future proposal after the local tip advances.
    ActivateBufferedProposal(BlockV1),
    /// Slash evidence was detected.
    SlashDetected(SlashEvidence),
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
    /// Synchronization phase for this node.
    sync: SyncState,
    /// Persisted local vote safety guard.
    pub vote_safety: VoteSafetyStore,
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
            sync: SyncState::follower(0),
            vote_safety,
        };
        driver.sync = if driver.engine.config.bootstrap_peers.is_empty() {
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
        self.vote_collectors.clear();
        self.seen_round_votes.clear();
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
        }
    }

    fn collector_key(height: u64, round: u32, step: VoteStep) -> (u64, u32, VoteStep) {
        (height, round, step)
    }

    fn start_round(&mut self, round: u32) {
        self.current_round = round;
        self.current_phase = RoundPhase::Propose;
    }

    /// Check persisted vote safety record and advance past already-voted rounds.
    fn apply_vote_safety(&mut self) {
        let next_height = self.engine.state.height.saturating_add(1);
        if let Some(record) = self.vote_safety.load() {
            if record.height == next_height && record.round >= self.current_round {
                let safe_round = record.round.saturating_add(1);
                eprintln!(
                    "[vote_safety] restarted: skipping to round {} (already voted at height={} round={} step={})",
                    safe_round, record.height, record.round, record.step
                );
                self.start_round(safe_round);
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
        if self.collector_has_vote_from(height, round, step, local_validator_id) {
            return vec![];
        }

        let step_byte = match step {
            VoteStep::Prevote => 0u8,
            VoteStep::Precommit => 1u8,
        };
        if let Err(err) = self.vote_safety.record(height, round, step_byte) {
            eprintln!("[vote_safety] failed to persist vote safety record: {err}");
        }

        match self.engine.sign_vote(height, round, step, block_hash) {
            Ok(local_vote) => {
                self.record_vote_and_actions(SocketAddr::from(([127, 0, 0, 1], 0)), local_vote)
            }
            Err(err) => {
                eprintln!(
                    "[vote] failed to sign local {:?} for {} at height={} round={}: {}",
                    step,
                    hex::encode(&block_hash.0[..4]),
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
            self.record_vote_passive(from, vote);
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

    fn record_vote_passive(&mut self, from: SocketAddr, vote: VoteV1) {
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
            }
        }
    }

    fn record_vote_and_actions(&mut self, from: SocketAddr, vote: VoteV1) -> Vec<DriverAction> {
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
                                    self.current_phase = RoundPhase::Precommit;
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
        self.pending_blocks.remove(&block_hash);

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

        let quorum_votes: Vec<&VoteV1> = collector
            .accepted_votes()
            .into_iter()
            .filter(|vote| vote.block_hash == block_hash && vote.step == VoteStep::Precommit)
            .collect();
        let qc = match build_qc(
            height,
            round,
            block_hash,
            &self.engine.state.chain_id,
            &qc_validators,
            quorum_votes,
        ) {
            Ok(qc) => qc,
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

        let old_height = self.engine.state.height;
        match self.engine.commit_block(&block) {
            Ok(()) => {
                let mut actions = vec![DriverAction::BroadcastBlock(block)];
                eprintln!(
                    "[commit] finalizing {} at height={} round={}",
                    hex::encode(&block_hash.0[..4]),
                    height,
                    round,
                );

                self.last_qc_bytes = qc.encode_to_vec();
                if let Err(e) = indra_storage::save_last_qc(
                    &self.engine.config.state_dir(),
                    &self.last_qc_bytes,
                ) {
                    eprintln!("[driver] WARNING: failed to persist last_qc_bytes: {e}");
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

        let base_fee = self.engine.state.base_fee;
        let height = self.engine.state.height;
        match self.engine.mempool.submit(tx.clone(), base_fee, height) {
            Ok(_) => vec![DriverAction::BroadcastTx(tx)],
            Err(_) => vec![DriverAction::None],
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

        self.last_qc_bytes = qc_bytes;
        if let Err(err) =
            indra_storage::save_last_qc(&self.engine.config.state_dir(), &self.last_qc_bytes)
        {
            eprintln!("[driver] WARNING: failed to persist recovered last_qc_bytes: {err}");
        }
        eprintln!(
            "[driver] recovered last_qc_bytes from peer at height {}",
            height
        );
        vec![]
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
        self.current_phase = RoundPhase::Precommit;
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
    use std::path::PathBuf;

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
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
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
                min_delegation_spark: DUST_LIMIT_SPARK,
                auto_delegate_to: None,
            })
            .unwrap();
        hybrid
    }

    fn local_driver(seed: [u8; 32], suffix: &str) -> (ConsensusDriver, PathBuf) {
        let dir = temp_dir(suffix);
        let mut config = NodeConfig::local_test(dir.clone());
        let pq = PqKeypair::from_seed(&seed).unwrap();
        config.validator_seed = Some(seed);
        config.vrf_seed = Some(seed);
        config.pq_pk = Some(pq.public_key().0.to_vec());
        config.pq_sk = Some(pq.secret_key_bytes());
        let engine = NodeEngine::init(config).unwrap();
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        (ConsensusDriver::new(engine, vote_safety), dir)
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
        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&proposer_seed),
            epoch_seed: election.epoch_seed,
            prev_qc_bytes,
            timestamp: 1_700_000_000 + driver.engine.state.height + 1,
            polc_round: None,
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
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
        let slot = indra_consensus::proposer::compute_proposer_vrf(
            validator_id,
            &keypair,
            &election.epoch_seed,
            election.height,
            election.round,
        );
        let mut effective = indra_consensus::proposer::ProposerElection {
            epoch_seed: election.epoch_seed,
            height: election.height,
            round: election.round,
            candidates: election.candidates.clone(),
        };
        if let Some(candidate) = effective
            .candidates
            .iter_mut()
            .find(|candidate| candidate.validator_id == slot.proposer_id)
        {
            candidate.verified_vrf_output = Some(slot.vrf_output);
        }
        indra_consensus::proposer::elect_proposer(&effective, effective.height).ok()
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
        let precommit_a = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            remote_a_id,
            DEFAULT_CHAIN_ID,
            &remote_a,
        )
        .unwrap();
        let precommit_b = indra_consensus::vote::produce_vote(
            1,
            0,
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
        let validator_seeds = [[0x4Fu8; 32], [0x52u8; 32], [0x53u8; 32], [0x54u8; 32]];
        for seed in validator_seeds {
            install_active_validator(&mut driver, seed, "validator");
        }
        driver.refresh_registered_voters();

        let proposer_seed = validator_seeds
            .into_iter()
            .find_map(|seed| {
                driver.engine.state.tip_hash =
                    pick_tip_hash_for_verified_winner(&driver, 1, 5, seed);
                let proposer_election = election_for_round(&driver, 1, 5);
                let elected = elect_with_verified_output_for_seed(&proposer_election, seed)?;
                let validator_id = validator_id_for_seed(seed);
                (elected == validator_id).then_some(seed)
            })
            .expect("expected one validator to win with verified VRF output");
        let block = make_strict_block(&driver, proposer_seed, 5, vec![]);
        let block_hash = block.header.block_hash();
        let actions = driver.process(DriverEvent::InboundBlock { from: None, block });

        assert_eq!(driver.current_round(), 5);
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
    fn sync_import_clears_stale_last_qc_bytes() {
        let (mut driver, dir) = local_driver([0xA3u8; 32], "sync_import_stale_qc");
        let local = install_active_validator(&mut driver, [0xA3u8; 32], "local");
        driver.refresh_registered_voters();

        let block1 = make_strict_block(&driver, [0xA3u8; 32], 0, vec![]);
        let _ = driver.process(DriverEvent::InboundBlock {
            from: None,
            block: block1,
        });
        let qc_for_height_1 = driver.last_qc_bytes();
        assert!(!qc_for_height_1.is_empty());

        let block2 = make_strict_block(&driver, [0xA3u8; 32], 0, qc_for_height_1.clone());
        driver.engine.commit_block(&block2).unwrap();
        driver.refresh_registered_voters();
        driver.sync_mut().on_block_imported(block2.header.height);
        driver.reset_round();

        assert_eq!(driver.height(), 2);
        assert!(driver.last_qc_is_stale());
        assert!(driver.clear_last_qc_if_stale());
        assert!(driver.last_qc_bytes().is_empty());
        assert!(matches!(
            driver.request_qc_if_needed().as_slice(),
            [DriverAction::RequestQC { height }] if *height == 2
        ));

        drop(local);
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
            let mut config = NodeConfig::local_test(dir.clone());
            let pq = PqKeypair::from_seed(&seed).unwrap();
            config.validator_seed = Some(seed);
            config.vrf_seed = Some(seed);
            config.pq_pk = Some(pq.public_key().0.to_vec());
            config.pq_sk = Some(pq.secret_key_bytes());
            let engine = NodeEngine::init(config).unwrap();
            let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
            let mut driver = ConsensusDriver::new(engine, vote_safety);
            let _local = install_active_validator(&mut driver, seed, "local");
            driver.refresh_registered_voters();
            let block = make_strict_block(&driver, seed, 0, vec![]);
            let _ = driver.process(DriverEvent::InboundBlock { from: None, block });
            assert!(!driver.last_qc_bytes().is_empty());
        }

        let mut config = NodeConfig::local_test(dir.clone());
        let pq = PqKeypair::from_seed(&seed).unwrap();
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
            )
            .expect("reproposal should succeed");

        assert_eq!(reproposed.header.value_hash, value_hash);
        assert_eq!(reproposed.header.proposer_round, 1);
        assert_eq!(reproposed.header.polc_round, 0);

        driver.on_precommit_timeout();
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
            )
            .expect("A should propose round 0");
        let value_hash = block_x.header.value_hash;
        let block_x_hash = block_x.header.block_hash();

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
            )
            .expect("B should repropose valid value at round 1");
        assert_eq!(block_y.header.value_hash, value_hash);
        let block_y_hash = block_y.header.block_hash();
        assert_ne!(block_y_hash, block_x_hash);

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
            let vote = indra_consensus::vote::produce_vote(
                1,
                1,
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
