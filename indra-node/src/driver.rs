//! Consensus driver — ties NodeEngine to the network layer.
//!
//! This file implements a compact Tendermint-style state machine for a single
//! node while preserving the existing INDRA driver interface used by
//! `node.rs`.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use indra_consensus::{
    build_qc,
    vote::{RegisteredVoter, VoteCollector, VoteDecision},
};
use indra_core::codec::{ByteReader, Decode, Encode};
use indra_core::types::{
    block::{BlockV1, NO_POLC_ROUND},
    primitives::Bytes32,
    transaction::TransactionV1,
    vote::{VoteStep, VoteV1},
};

use crate::{
    engine::NodeEngine,
    error::NodeError,
    slash::{SlashDetector, SlashEvidence},
    sync::{verify_proposer_vrf, SyncState},
};

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// Current Tendermint phase of the local round state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    locked_value: Option<Bytes32>,
    /// Tendermint valid value / valid round for reproposal.
    valid_round: Option<u32>,
    valid_value: Option<Bytes32>,
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
}

impl ConsensusDriver {
    /// Create a new driver from a node engine.
    pub fn new(engine: NodeEngine) -> Self {
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
            valid_round: None,
            valid_value: None,
            last_qc_bytes: Vec::new(),
            registered_voters: Vec::new(),
            current_round: 0,
            current_phase: RoundPhase::Propose,
            sync: SyncState::follower(0),
        };
        driver.sync = if driver.engine.config.bootstrap_peers.is_empty() {
            SyncState::bootstrap(driver.engine.state.height)
        } else {
            SyncState::follower(driver.engine.state.height)
        };
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

    /// Current round for the next block height.
    pub fn current_round(&self) -> u32 {
        self.current_round
    }

    /// Current local Tendermint step.
    pub fn current_phase(&self) -> RoundPhase {
        self.current_phase
    }

    /// Current valid round for Rule 1 re-proposals.
    pub fn valid_round(&self) -> Option<u32> {
        self.valid_round
    }

    /// Current valid value hash for Rule 1 re-proposals.
    pub fn valid_value(&self) -> Option<Bytes32> {
        self.valid_value
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
        self.pending_block_for_slot(height, self.current_round).is_some()
    }

    /// External compatibility hook used by the node loop.
    pub fn advance_round(&mut self) {
        self.prune_future_proposals();
        self.start_round(self.current_round.saturating_add(1));
    }

    /// External compatibility hook used after height advancement.
    pub fn reset_round(&mut self) {
        self.prune_future_proposals();
        self.start_round(0);
    }

    /// Process one inbound event and return the resulting driver actions.
    pub fn process(&mut self, event: DriverEvent) -> Vec<DriverAction> {
        match event {
            DriverEvent::InboundBlock { from, block } => self.process_block(from, block),
            DriverEvent::InboundVote { from, vote } => self.process_vote(from, vote),
            DriverEvent::InboundTx { from, tx_bytes } => self.process_tx(from, tx_bytes),
            DriverEvent::PeerStatus { from, height, tip_hash } => {
                self.process_status(from, height, tip_hash)
            }
        }
    }

    fn collector_key(height: u64, round: u32, step: VoteStep) -> (u64, u32, VoteStep) {
        (height, round, step)
    }

    fn start_round(&mut self, round: u32) {
        self.current_round = round;
        self.current_phase = RoundPhase::Propose;
    }

    fn next_height(&self) -> u64 {
        self.engine.state.height + 1
    }

    fn prune_future_proposals(&mut self) {
        let next_height = self.next_height();
        self.future_proposals
            .retain(|(height, _), _| *height >= next_height && *height <= next_height.saturating_add(2));
    }

    fn pending_block_for_slot(&self, height: u64, round: u32) -> Option<BlockV1> {
        self.pending_blocks
            .values()
            .find(|block| block.header.height == height && block.header.proposer_round == round)
            .cloned()
    }

    fn has_pending_value_hash(&self, height: u64, round: u32, value_hash: Bytes32) -> bool {
        self.pending_blocks.values().any(|block| {
            block.header.height == height
                && block.header.proposer_round == round
                && block.header.value_hash == value_hash
        })
    }

    /// Return a locally staged proposal by hash, if present.
    pub fn pending_block(&self, hash: &Bytes32) -> Option<BlockV1> {
        self.pending_blocks
            .values()
            .find(|block| block.header.value_hash == *hash)
            .cloned()
    }

    /// Return a locally staged proposal by value hash, if present.
    pub fn get_pending_block(&self, hash: Bytes32) -> Option<BlockV1> {
        self.pending_block(&hash)
    }

    /// Return the PoLC round to advertise in a proposal header.
    ///
    /// INDRA's current proposer path always constructs a fresh block for the
    /// target round, so it cannot safely claim a prior PoLC unless it is able
    /// to re-propose the exact same value that reached prevote quorum. Until
    /// exact-value re-proposal exists, advertising `polc_round` causes later
    /// rounds to nil-prevote otherwise valid staged proposals under Rule 3.
    pub fn proposal_polc_round(&self, height: u64) -> Option<u32> {
        if self.next_height() != height {
            return None;
        }
        let valid_value = self.valid_value?;
        self.pending_block(&valid_value)?;
        self.valid_round
    }

    fn quorum_size(&self) -> usize {
        let n = self.registered_voters.len();
        if n == 0 { 0 } else { (2 * n) / 3 + 1 }
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

    fn has_quorum_for_hash(&self, height: u64, round: u32, step: VoteStep, hash: Bytes32) -> bool {
        matches!(
            self.vote_decision(height, round, step),
            Some(VoteDecision::QuorumReached { block_hash, .. }) if block_hash == hash
        )
    }

    /// Rules 2 and 3 — decide whether the current-round proposal should be
    /// prevoted or nil-prevoted.
    fn maybe_prevote_current_round_proposal(&mut self) -> Vec<DriverAction> {
        if !self.sync.is_caught_up() || self.current_phase != RoundPhase::Propose {
            return vec![];
        }

        let height = self.next_height();
        let Some(block) = self.pending_block_for_slot(height, self.current_round) else {
            return vec![];
        };
        let hash = block.header.value_hash;

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
                && self.has_quorum_for_hash(height, valid_round, VoteStep::Prevote, hash)
                && (self.locked_round.is_none()
                    || self.locked_value == Some(hash)
                    || self.locked_round.is_some_and(|locked_round| locked_round <= valid_round))
            {
                hash
            } else {
                Bytes32::ZERO
            }
        };

        self.current_phase = RoundPhase::Prevote;
        self.sign_and_record_local_vote(height, self.current_round, VoteStep::Prevote, vote_hash)
    }

    /// If a proposal is staged after the reactor already moved us into the
    /// Prevote step for this round, we may still cast the round's first
    /// prevote as long as we have not prevoted yet.
    fn maybe_prevote_staged_proposal_in_prevote_phase(&mut self) -> Vec<DriverAction> {
        if !self.sync.is_caught_up() || self.current_phase != RoundPhase::Prevote {
            return vec![];
        }

        let height = self.next_height();
        let round = self.current_round;
        let Some(local_validator_id) = self.engine.validator_id() else {
            return vec![];
        };
        if self.collector_has_vote_from(height, round, VoteStep::Prevote, local_validator_id) {
            return vec![];
        }

        let Some(block) = self.pending_block_for_slot(height, round) else {
            return vec![];
        };
        let hash = block.header.value_hash;
        let vote_hash = if self.locked_round.is_none() || self.locked_value == Some(hash) {
            hash
        } else {
            Bytes32::ZERO
        };

        self.sign_and_record_local_vote(height, round, VoteStep::Prevote, vote_hash)
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

        match self.engine.sign_vote(height, round, step, block_hash) {
            Ok(local_vote) => {
                match step {
                    VoteStep::Prevote => eprintln!(
                        "[vote] sending local prevote for {} at height={} round={}",
                        hex::encode(&block_hash.0[..4]),
                        height,
                        round,
                    ),
                    VoteStep::Precommit => eprintln!(
                        "[vote] sending local precommit for {} at height={} round={}",
                        hex::encode(&block_hash.0[..4]),
                        height,
                        round,
                    ),
                }
                eprintln!(
                    "[timing] t={}ms sent vote for {} at height={} round={}",
                    now_ms(),
                    hex::encode(block_hash.0),
                    height,
                    round,
                );
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

    fn get_local_vote_hash(&self, height: u64, round: u32, step: VoteStep) -> Option<Bytes32> {
        let local_validator_id = self.engine.validator_id()?;
        self.vote_collectors
            .get(&Self::collector_key(height, round, step))
            .and_then(|collector| {
                collector
                    .accepted_votes()
                    .into_iter()
                    .find(|vote| vote.validator_id == local_validator_id)
                    .map(|vote| vote.block_hash)
            })
    }

    fn remove_local_vote(&mut self, height: u64, round: u32, step: VoteStep) {
        let Some(local_validator_id) = self.engine.validator_id() else {
            return;
        };
        let Some(existing_hash) = self.get_local_vote_hash(height, round, step) else {
            return;
        };

        self.slash_detector
            .remove_vote(local_validator_id, height, round, step, existing_hash);

        let key = Self::collector_key(height, round, step);
        if let Some(old_collector) = self.vote_collectors.remove(&key) {
            let kept_votes: Vec<VoteV1> = old_collector
                .accepted_votes()
                .into_iter()
                .filter(|vote| vote.validator_id != local_validator_id)
                .cloned()
                .collect();

            let mut rebuilt = VoteCollector::new(height, round, step, self.registered_voters.clone());
            for vote in kept_votes {
                let _ = rebuilt.add_vote(vote);
            }
            self.vote_collectors.insert(key, rebuilt);
        }
    }

    fn sign_and_record_local_vote_upgrade(
        &mut self,
        height: u64,
        round: u32,
        step: VoteStep,
        block_hash: Bytes32,
    ) -> Vec<DriverAction> {
        let Some(existing_hash) = self.get_local_vote_hash(height, round, step) else {
            return self.sign_and_record_local_vote(height, round, step, block_hash);
        };

        if existing_hash == block_hash {
            return vec![];
        }
        if existing_hash != Bytes32::ZERO || block_hash == Bytes32::ZERO {
            return vec![];
        }

        self.remove_local_vote(height, round, step);
        self.sign_and_record_local_vote(height, round, step, block_hash)
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
        if block.header.height > next_height || block.header.prev_hash != self.engine.state.tip_hash {
            let key = (block.header.height, block.header.prev_hash);
            let entry = self.future_proposals.entry(key).or_default();
            let block_hash = block.header.block_hash();
            if !entry.iter().any(|existing| existing.header.block_hash() == block_hash) {
                entry.push(block);
            }
            self.prune_future_proposals();
            return vec![DriverAction::None];
        }

        self.process_block_internal(from, block)
    }

    fn process_block_internal(&mut self, from: Option<SocketAddr>, block: BlockV1) -> Vec<DriverAction> {
        if self.engine.state.validators.active_count() > 0
            && (block.header.proposer_vrf_output != Bytes32::ZERO
                || !block.header.proposer_vrf_proof.as_slice().is_empty())
            && verify_proposer_vrf(&block, &self.engine.state, false).is_err()
        {
            eprintln!(
                "[vote] rejecting proposal {} at height={} round={} because it does not verify as the elected proposer block",
                hex::encode(&block.header.block_hash().0[..4]),
                block.header.height,
                block.header.proposer_round,
            );
            return vec![DriverAction::None];
        }

        let mut projected_state = self.engine.state.clone();
        if indra_state::apply_block(&mut projected_state, &block).is_err() {
            return vec![DriverAction::None];
        }

        let block_hash = block.header.block_hash();
        let value_hash = block.header.value_hash;
        if let Some(existing_hash) =
            self.pending_block_for_slot(block.header.height, block.header.proposer_round)
                .map(|existing| existing.header.value_hash)
        {
            if existing_hash != value_hash {
                eprintln!(
                    "[vote] ignoring competing proposal {} for existing slot height={} round={} (accepted {})",
                    hex::encode(&block_hash.0[..4]),
                    block.header.height,
                    block.header.proposer_round,
                    hex::encode(&existing_hash.0[..4]),
                );
                return vec![DriverAction::None];
            }
        }
        if self.pending_blocks.contains_key(&block_hash) {
            return vec![DriverAction::None];
        }

        eprintln!(
            "[vote] received proposal {} from {} at height={} round={}, staging block",
            hex::encode(&block_hash.0[..4]),
            from.map(|addr| addr.to_string()).unwrap_or_else(|| "local".to_string()),
            block.header.height,
            block.header.proposer_round,
        );
        eprintln!(
            "[timing] t={}ms received+staged proposal {} at height={} round={} from={}",
            now_ms(),
            hex::encode(block_hash.0),
            block.header.height,
            block.header.proposer_round,
            from.map(|addr| addr.to_string()).unwrap_or_else(|| "local".to_string()),
        );

        self.requested_proposals
            .remove(&(block.header.height, block.header.proposer_round, value_hash));
        self.pending_blocks.insert(block_hash, block.clone());

        let mut actions = vec![DriverAction::BroadcastBlock(block.clone())];

        if let Some(buffered_votes) =
            self.buffered_votes.remove(&(block.header.height, block.header.proposer_round, value_hash))
        {
            for (vote_from, vote) in buffered_votes {
                actions.extend(self.record_vote_and_actions(vote_from, vote));
            }
        }

        if self.pending_precommit_quorum.remove(&(block.header.height, block.header.proposer_round, value_hash)) {
            actions.extend(self.finalize_block_on_quorum(
                block.header.height,
                block.header.proposer_round,
                value_hash,
            ));
            return actions;
        }

        // Rules 2 and 3 — if this is the proposal for our current slot, react
        // immediately instead of waiting for the propose timeout.
        actions.extend(self.maybe_prevote_current_round_proposal());
        if self.current_phase == RoundPhase::Prevote {
            actions.extend(self.maybe_prevote_staged_proposal_in_prevote_phase());
        }
        actions
    }

    /// Return buffered proposals that became valid after the local tip
    /// advanced to a new parent block.
    pub fn activate_buffered_proposals_for_new_tip(&mut self) -> Vec<DriverAction> {
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

        if !self.sync.is_caught_up() {
            return actions;
        }

        if self
            .engine
            .validator_id()
            .is_some_and(|local_id| local_id == vote.validator_id)
            && self.collector_has_vote_from(vote.height, vote.round, vote.step, vote.validator_id)
        {
            eprintln!(
                "[vote] ignoring echoed local vote from {} for {} at height={} round={}",
                from,
                hex::encode(&vote.block_hash.0[..4]),
                vote.height,
                vote.round,
            );
            return actions;
        }

        if vote.height <= self.engine.state.height {
            eprintln!(
                "[vote] ignoring stale vote from {} for {} at height={} round={} (local height={})",
                from,
                hex::encode(&vote.block_hash.0[..4]),
                vote.height,
                vote.round,
                self.engine.state.height,
            );
            return actions;
        }

        eprintln!(
            "[vote] received vote from {} for {} at height={} round={}",
            from,
            hex::encode(&vote.block_hash.0[..4]),
            vote.height,
            vote.round,
        );

        if let Some(evidence) = self.slash_detector.observe_vote(vote.clone()) {
            actions.push(DriverAction::SlashDetected(evidence));
        }

        let slot_key = (vote.validator_id, vote.height, vote.round, vote.step);
        if let Some(existing_hash) = self.seen_round_votes.get(&slot_key).copied() {
            if existing_hash == vote.block_hash {
                eprintln!(
                    "[vote] ignoring duplicate vote from {} for {} at height={} round={}",
                    from,
                    hex::encode(&vote.block_hash.0[..4]),
                    vote.height,
                    vote.round,
                );
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

        if !vote.is_nil()
            && vote.height == self.next_height()
            && !self.has_pending_value_hash(vote.height, vote.round, vote.block_hash)
        {
            let request_key = (vote.height, vote.round, vote.block_hash);
            let should_request = self.requested_proposals.insert(request_key);
            if should_request {
                eprintln!(
                    "[vote] buffering vote from {} for {} at height={} round={} until proposal is staged — requesting proposal from peer",
                    from,
                    hex::encode(&vote.block_hash.0[..4]),
                    vote.height,
                    vote.round,
                );
                actions.push(DriverAction::RequestProposal {
                    from,
                    height: vote.height,
                    round: vote.round,
                    hash: vote.block_hash,
                });
            } else {
                eprintln!(
                    "[vote] buffering vote from {} for {} at height={} round={} until proposal is staged",
                    from,
                    hex::encode(&vote.block_hash.0[..4]),
                    vote.height,
                    vote.round,
                );
            }
            self.buffered_votes
                .entry((vote.height, vote.round, vote.block_hash))
                .or_default()
                .push((from, vote));
            return actions;
        }

        actions.extend(self.record_vote_and_actions(from, vote));
        actions
    }

    fn record_vote_and_actions(&mut self, from: SocketAddr, vote: VoteV1) -> Vec<DriverAction> {
        let mut actions = Vec::new();
        let key = Self::collector_key(vote.height, vote.round, vote.step);
        let quorum = self.quorum_size();
        let (decision, current_count) = {
            let collector = self
                .vote_collectors
                .entry(key)
                .or_insert_with(|| VoteCollector::new(
                    vote.height,
                    vote.round,
                    vote.step,
                    self.registered_voters.clone(),
                ));
            let decision = collector.add_vote(vote.clone());
            let count = collector.vote_count();
            (decision, count)
        };

        match decision {
            Ok(decision) => {
                eprintln!(
                    "[timing] t={}ms received vote for {} at height={} round={} count={}/{}",
                    now_ms(),
                    hex::encode(vote.block_hash.0),
                    vote.height,
                    vote.round,
                    current_count,
                    self.registered_voters.len(),
                );
                actions.push(DriverAction::BroadcastVote(vote.clone()));

                match decision {
                    VoteDecision::Waiting => {
                        eprintln!(
                            "[vote] collected {}/{} votes for {} at height={} round={} — waiting",
                            current_count,
                            self.registered_voters.len(),
                            hex::encode(&vote.block_hash.0[..4]),
                            vote.height,
                            vote.round,
                        );
                    }
                    VoteDecision::QuorumReached { block_hash, .. } => {
                        eprintln!(
                            "[vote] collected {}/{} votes for {} at height={} round={} — quorum",
                            current_count,
                            self.registered_voters.len(),
                            hex::encode(&block_hash.0[..4]),
                            vote.height,
                            vote.round,
                        );

                        match vote.step {
                            VoteStep::Prevote => {
                                // Rule 4: once 2f+1 prevotes of any value exist, the external
                                // timeout machinery continues from the Prevote step.
                                if block_hash != Bytes32::ZERO {
                                    // Rule 5 — a value got 2f+1 prevotes.
                                    self.valid_round = Some(vote.round);
                                    self.valid_value = Some(block_hash);
                                }

                                if vote.height == self.next_height()
                                    && vote.round == self.current_round
                                    && self.current_phase == RoundPhase::Prevote
                                {
                                    self.current_phase = RoundPhase::Precommit;
                                    if block_hash != Bytes32::ZERO {
                                        self.locked_round = Some(vote.round);
                                        self.locked_value = Some(block_hash);
                                        eprintln!(
                                            "[timing] t={}ms QUORUM {} at height={} round={} — precommit",
                                            now_ms(),
                                            hex::encode(block_hash.0),
                                            vote.height,
                                            vote.round,
                                        );
                                        actions.extend(self.sign_and_record_local_vote(
                                            vote.height,
                                            vote.round,
                                            VoteStep::Precommit,
                                            block_hash,
                                        ));
                                    } else {
                                        // Rule 6 — nil prevote quorum.
                                        eprintln!(
                                            "[timing] t={}ms QUORUM {} at height={} round={} — precommit",
                                            now_ms(),
                                            hex::encode(block_hash.0),
                                            vote.height,
                                            vote.round,
                                        );
                                        actions.extend(self.sign_and_record_local_vote(
                                            vote.height,
                                            vote.round,
                                            VoteStep::Precommit,
                                            Bytes32::ZERO,
                                        ));
                                    }
                                } else if block_hash != Bytes32::ZERO
                                    && vote.height == self.next_height()
                                    && vote.round == self.current_round
                                    && self.current_phase == RoundPhase::Precommit
                                {
                                    self.locked_round = Some(vote.round);
                                    self.locked_value = Some(block_hash);
                                    eprintln!(
                                        "[timing] t={}ms QUORUM {} at height={} round={} — upgrade precommit",
                                        now_ms(),
                                        hex::encode(block_hash.0),
                                        vote.height,
                                        vote.round,
                                    );
                                    actions.extend(self.sign_and_record_local_vote_upgrade(
                                        vote.height,
                                        vote.round,
                                        VoteStep::Precommit,
                                        block_hash,
                                    ));
                                } else if block_hash != Bytes32::ZERO && current_count >= quorum {
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
                                    eprintln!(
                                        "[timing] t={}ms QUORUM {} at height={} round={} — commit",
                                        now_ms(),
                                        hex::encode(block_hash.0),
                                        vote.height,
                                        vote.round,
                                    );
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
        value_hash: Bytes32,
    ) -> Vec<DriverAction> {
        let Some((proposal_hash, block)) = self
            .pending_blocks
            .iter()
            .find(|(_, block)| {
                block.header.height == height
                    && block.header.proposer_round == round
                    && block.header.value_hash == value_hash
            })
            .map(|(proposal_hash, block)| (*proposal_hash, block.clone()))
        else {
            eprintln!(
                "[commit] quorum reached for {} at height={} round={}, but block is not staged yet",
                hex::encode(&value_hash.0[..4]),
                height,
                round,
            );
            self.pending_precommit_quorum.insert((height, round, value_hash));
            return vec![DriverAction::None];
        };
        self.pending_blocks.remove(&proposal_hash);

        let key = Self::collector_key(height, round, VoteStep::Precommit);
        let Some(collector) = self.vote_collectors.get(&key) else {
            eprintln!(
                "[commit] quorum reached for {} at height={} round={}, but collector is missing",
                hex::encode(&value_hash.0[..4]),
                height,
                round,
            );
            return vec![DriverAction::None];
        };

        let qc_validators = self.engine.qc_validators();
        if qc_validators.len() != self.registered_voters.len() {
            eprintln!(
                "[commit] cannot finalize {} at height={} round={} because QC validator set is incomplete",
                hex::encode(&value_hash.0[..4]),
                height,
                round,
            );
            return vec![DriverAction::None];
        }

        let quorum_votes: Vec<&VoteV1> = collector
            .accepted_votes()
            .into_iter()
            .filter(|vote| vote.block_hash == value_hash && vote.step == VoteStep::Precommit)
            .collect();
        let qc = match build_qc(height, round, value_hash, &qc_validators, quorum_votes) {
            Ok(qc) => qc,
            Err(err) => {
                eprintln!(
                    "[commit] failed to build QC for {} at height={} round={}: {}",
                    hex::encode(&value_hash.0[..4]),
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
                    "[commit] quorum reached for {} at height={} round={}, finalizing",
                    hex::encode(&value_hash.0[..4]),
                    height,
                    round,
                );

                self.last_qc_bytes = qc.encode_to_vec();
                self.slash_detector.prune_below(height.saturating_sub(100));
                self.refresh_registered_voters();
                self.sync.mark_caught_up(self.engine.state.height);

                // Rule 9 / height transition cleanup.
                self.locked_round = None;
                self.locked_value = None;
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
                    hex::encode(&value_hash.0[..4]),
                    height,
                    reason,
                );
                vec![DriverAction::None]
            }
            Err(err) => {
                eprintln!(
                    "[commit] failed to finalize {} at height={} round={}: {}",
                    hex::encode(&value_hash.0[..4]),
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
    ) -> Vec<DriverAction> {
        let our_height = self.engine.height();
        match self.sync.observe_status(from, height, our_height) {
            Some((peer, from_height, to_height)) => vec![DriverAction::RequestBlocks {
                from: peer,
                from_height,
                to_height,
            }],
            None => vec![DriverAction::None],
        }
    }

    /// Rule 11 — on propose timeout, prevote nil unless the proposal for the
    /// current round is already staged locally.
    pub fn on_propose_timeout(&mut self) -> Vec<DriverAction> {
        if !self.sync.is_caught_up() || self.current_phase != RoundPhase::Propose {
            return vec![];
        }

        let staged_actions = self.maybe_prevote_current_round_proposal();
        if !staged_actions.is_empty() {
            eprintln!("[consensus] propose timeout but proposal already staged — prevoting");
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
    use indra_core::{
        Bytes32, ProtocolVersion, VariableBytes,
        types::block::{BlockHeaderV1, BlockV1},
        types::primitives::{DEFAULT_COMMISSION_BPS, DUST_LIMIT_SPARK, MAX_VRF_PROOF_BYTES},
    };
    use indra_crypto::{
        VrfKeypair,
        hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    };
    use indra_state::{ChainState, ValidatorEntry, ValidatorStatus, apply_block, compute_state_root, compute_validator_set_root};
    use std::path::PathBuf;

    fn temp_dir(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_driver_test_{}_{}", suffix, std::process::id()));
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
        };

        let mut projected = state.clone();
        apply_block(&mut projected, &block).unwrap();
        block.header.state_root = compute_state_root(&projected);
        block.header.validator_set_root = compute_validator_set_root(&projected);
        block.header.value_hash = block.compute_value_hash(projected.total_supply);
        block
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
                hybrid_pq_pk: Some(public.pq.0.clone()),
                vrf_pk: Some(vrf_pk),
                stake_spark: 1_000_000,
                status: ValidatorStatus::Active,
                registered_epoch: 0,
                pending_rewards: 0,
                rewards_last_epoch: 0,
                self_report_count: 0,
                commission_bps: DEFAULT_COMMISSION_BPS,
                min_delegation_spark: DUST_LIMIT_SPARK,
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
        config.pq_pk = Some(pq.public_key().0.clone());
        config.pq_sk = Some(pq.secret_key_bytes());
        let engine = NodeEngine::init(config).unwrap();
        (ConsensusDriver::new(engine), dir)
    }

    #[test]
    fn single_validator_block_commits_immediately() {
        let (mut driver, dir) = local_driver([0x41u8; 32], "single_commit");
        let _local = install_active_validator(&mut driver, [0x41u8; 32], "local");
        driver.refresh_registered_voters();

        let block = make_block(&driver.engine.state);
        let actions = driver.process(DriverEvent::InboundBlock { from: None, block });

        assert!(actions.iter().any(|a| matches!(a, DriverAction::BroadcastBlock(_))));
        assert_eq!(driver.height(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vote_before_block_requests_proposal_then_commits() {
        let (mut driver, dir) = local_driver([0x42u8; 32], "votes_before_block");
        let _local = install_active_validator(&mut driver, [0x42u8; 32], "local");
        let remote_a = install_active_validator(&mut driver, [0x43u8; 32], "remote-a");
        let remote_b = install_active_validator(&mut driver, [0x44u8; 32], "remote-b");
        driver.refresh_registered_voters();

        let block = make_block(&driver.engine.state);
        let value_hash = block.header.value_hash;

        let remote_a_id = Bytes32::from(indra_crypto::sha256(&remote_a.public_key().classical.0));
        let remote_b_id = Bytes32::from(indra_crypto::sha256(&remote_b.public_key().classical.0));

        let prevote_a = indra_consensus::vote::produce_vote(
            1, 0, VoteStep::Prevote, value_hash, remote_a_id, &remote_a,
        ).unwrap();
        let prevote_b = indra_consensus::vote::produce_vote(
            1, 0, VoteStep::Prevote, value_hash, remote_b_id, &remote_b,
        ).unwrap();
        let precommit_a = indra_consensus::vote::produce_vote(
            1, 0, VoteStep::Precommit, value_hash, remote_a_id, &remote_a,
        ).unwrap();
        let precommit_b = indra_consensus::vote::produce_vote(
            1, 0, VoteStep::Precommit, value_hash, remote_b_id, &remote_b,
        ).unwrap();

        let peer_a: SocketAddr = "127.0.0.1:9101".parse().unwrap();
        let peer_b: SocketAddr = "127.0.0.1:9102".parse().unwrap();
        let actions_a = driver.process(DriverEvent::InboundVote { from: peer_a, vote: prevote_a });
        let actions_b = driver.process(DriverEvent::InboundVote { from: peer_b, vote: prevote_b });
        assert!(actions_a.iter().any(|a| matches!(a, DriverAction::RequestProposal { .. })));
        assert!(actions_b.is_empty());

        let mut actions = driver.process(DriverEvent::InboundBlock { from: Some(peer_a), block });
        actions.extend(driver.process(DriverEvent::InboundVote { from: peer_a, vote: precommit_a }));
        actions.extend(driver.process(DriverEvent::InboundVote { from: peer_b, vote: precommit_b }));

        assert_eq!(driver.height(), 1);
        assert!(actions.iter().any(|a| matches!(
            a,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Precommit && vote.block_hash == value_hash
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn propose_timeout_prevotes_staged_block_instead_of_nil() {
        let (mut driver, dir) = local_driver([0x45u8; 32], "staged_timeout_prevote");
        let _local = install_active_validator(&mut driver, [0x45u8; 32], "local");
        driver.refresh_registered_voters();

        let block = make_block(&driver.engine.state);
        let value_hash = block.header.value_hash;
        let actions = driver.process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:9201".parse().unwrap()),
            block,
        });

        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == value_hash
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
    fn late_prevote_quorum_upgrades_nil_precommit_to_real() {
        let (mut driver, dir) = local_driver([0x4Bu8; 32], "late_precommit_upgrade");
        let _local = install_active_validator(&mut driver, [0x4Bu8; 32], "local");
        let remote_a = install_active_validator(&mut driver, [0x4Cu8; 32], "remote-a");
        let remote_b = install_active_validator(&mut driver, [0x4Du8; 32], "remote-b");
        driver.refresh_registered_voters();

        let block = make_block(&driver.engine.state);
        let value_hash = block.header.value_hash;
        let height = block.header.height;
        let round = block.header.proposer_round;

        let peer_a: SocketAddr = "127.0.0.1:9401".parse().unwrap();
        let peer_b: SocketAddr = "127.0.0.1:9402".parse().unwrap();
        let remote_a_id = Bytes32::from(indra_crypto::sha256(&remote_a.public_key().classical.0));
        let remote_b_id = Bytes32::from(indra_crypto::sha256(&remote_b.public_key().classical.0));

        let stage_actions = driver.process(DriverEvent::InboundBlock {
            from: Some(peer_a),
            block,
        });
        assert!(stage_actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == value_hash
        )));

        let nil_precommit_actions = driver.on_prevote_timeout();
        assert!(nil_precommit_actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Precommit && vote.block_hash == Bytes32::ZERO
        )));
        assert_eq!(
            driver.get_local_vote_hash(height, round, VoteStep::Precommit),
            Some(Bytes32::ZERO)
        );

        let prevote_a = indra_consensus::vote::produce_vote(
            height, round, VoteStep::Prevote, value_hash, remote_a_id, &remote_a,
        ).unwrap();
        let prevote_b = indra_consensus::vote::produce_vote(
            height, round, VoteStep::Prevote, value_hash, remote_b_id, &remote_b,
        ).unwrap();

        let _ = driver.process(DriverEvent::InboundVote { from: peer_a, vote: prevote_a });
        let upgrade_actions = driver.process(DriverEvent::InboundVote { from: peer_b, vote: prevote_b });

        assert!(upgrade_actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Precommit && vote.block_hash == value_hash
        )));
        assert_eq!(
            driver.get_local_vote_hash(height, round, VoteStep::Precommit),
            Some(value_hash)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn driver_detects_double_precommit() {
        let (mut driver, dir) = local_driver([0x48u8; 32], "double_precommit");
        let remote = install_active_validator(&mut driver, [0x49u8; 32], "remote");
        driver.refresh_registered_voters();

        let remote_id = Bytes32::from(indra_crypto::sha256(&remote.public_key().classical.0));
        let vote_a = indra_consensus::vote::produce_vote(
            1, 0, VoteStep::Precommit, Bytes32::from([0xAAu8; 32]), remote_id, &remote,
        ).unwrap();
        let vote_b = indra_consensus::vote::produce_vote(
            1, 0, VoteStep::Precommit, Bytes32::from([0xBBu8; 32]), remote_id, &remote,
        ).unwrap();

        let peer: SocketAddr = "127.0.0.1:9301".parse().unwrap();
        let _ = driver.process(DriverEvent::InboundVote { from: peer, vote: vote_a });
        let actions = driver.process(DriverEvent::InboundVote { from: peer, vote: vote_b });

        assert!(actions.iter().any(|a| matches!(a, DriverAction::SlashDetected(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn polc_round_is_advertised_when_valid_value_is_staged() {
        let (mut driver, dir) = local_driver([0x4Au8; 32], "valid_round_enabled");
        let _local = install_active_validator(&mut driver, [0x4Au8; 32], "local");
        driver.refresh_registered_voters();

        let block = make_block(&driver.engine.state);
        let value_hash = block.header.value_hash;
        driver.pending_blocks.insert(block.header.block_hash(), block);
        driver.valid_round = Some(2);
        driver.valid_value = Some(value_hash);

        assert_eq!(driver.proposal_polc_round(1), Some(2));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
