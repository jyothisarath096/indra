//! Consensus reactor — single-owner event loop for the INDRA driver.
//!
//! The reactor owns `ConsensusDriver` directly and serializes all consensus
//! events, removing the shared-driver mutex from the hot path.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{
    mpsc::{self, Receiver, Sender, SyncSender},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

use indra_core::codec::Encode;
use indra_core::types::{
    block::BlockV1,
    primitives::Bytes32,
    transaction::TransactionV1,
    vote::VoteV1,
};
use indra_network::gossip::GossipEngine;
use indra_network::message::Message;
use indra_state::ChainState;

use crate::{
    driver::{ConsensusDriver, DriverAction, DriverEvent, RoundPhase},
    sync::SYNC_BATCH_SIZE,
};

/// Tendermint propose timeout used by the reactor.
pub const PROPOSE_TIMEOUT: Duration = Duration::from_secs(10);
/// Tendermint prevote timeout used by the reactor.
pub const PREVOTE_TIMEOUT: Duration = Duration::from_secs(8);
/// Tendermint precommit timeout used by the reactor.
pub const PRECOMMIT_TIMEOUT: Duration = Duration::from_secs(8);
/// Periodic status broadcast interval.
pub const STATUS_INTERVAL: Duration = Duration::from_secs(6);

/// A compact read-only chain snapshot shared with RPC and status threads.
#[derive(Debug, Clone)]
pub struct ChainSnapshot {
    /// Current committed chain state.
    pub state: ChainState,
    /// Current mempool size.
    pub mempool_size: usize,
    /// Whether the block store is archive mode.
    pub archive: bool,
    /// Lowest retained block height.
    pub lowest_block: u64,
    /// Number of retained blocks.
    pub retained_blocks: usize,
}

impl ChainSnapshot {
    /// Build a snapshot from the live consensus driver.
    pub fn from_driver(driver: &ConsensusDriver) -> Self {
        Self {
            state: driver.engine.state.clone(),
            mempool_size: driver.engine.mempool.len(),
            archive: driver.engine.block_store.is_archive(),
            lowest_block: driver.engine.block_store.lowest_height(),
            retained_blocks: driver.engine.block_store.len(),
        }
    }
}

/// Timeout category tracked by the reactor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimeoutKind {
    /// Waiting for a proposal in the current round.
    Propose,
    /// Waiting for enough prevotes in the current round.
    Prevote,
    /// Waiting for enough precommits in the current round.
    Precommit,
}

/// A scheduled timeout generation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TimeoutId {
    /// Timeout category.
    pub kind: TimeoutKind,
    /// Height the timeout was scheduled for.
    pub height: u64,
    /// Round the timeout was scheduled for.
    pub round: u32,
    /// Phase that scheduled this timeout.
    pub phase: RoundPhase,
}

/// An event delivered into the consensus reactor.
pub enum ConsensusEvent {
    /// A proposal block arrived from a peer or internal buffered activation.
    ProposalReceived {
        /// Sending peer, or `None` when activated internally.
        from: Option<SocketAddr>,
        /// The proposed block.
        block: BlockV1,
    },
    /// A vote arrived from a peer.
    VoteReceived {
        /// Sending peer.
        from: SocketAddr,
        /// The vote payload.
        vote: VoteV1,
    },
    /// A transaction arrived from a peer.
    TxReceived {
        /// Sending peer.
        from: SocketAddr,
        /// The decoded transaction.
        tx: TransactionV1,
    },
    /// A peer announced its chain status.
    PeerStatus {
        /// Sending peer.
        from: SocketAddr,
        /// Peer height.
        height: u64,
        /// Peer tip hash.
        tip_hash: Bytes32,
    },
    /// A peer requested a block range for sync.
    BlocksRequested {
        /// Requesting peer.
        from: SocketAddr,
        /// Start height.
        from_height: u64,
        /// End height.
        to_height: u64,
    },
    /// A peer responded with sync blocks.
    BlocksResponse {
        /// Returned blocks.
        blocks: Vec<BlockV1>,
    },
    /// A peer requested a specific proposal by hash.
    ProposalRequest {
        /// Requesting peer.
        from: SocketAddr,
        /// Proposal height.
        height: u64,
        /// Proposal round.
        round: u32,
        /// Proposal hash.
        hash: Bytes32,
    },
    /// Local RPC submitted a transaction.
    SubmitTx {
        /// The decoded transaction.
        tx: TransactionV1,
        /// One-shot reply with the tx id or rejection reason.
        reply: SyncSender<Result<Bytes32, String>>,
    },
    /// A scheduled timeout fired and was delivered through the same mailbox
    /// as proposals and votes.
    TimeoutFired {
        /// Timeout generation identifier.
        id: TimeoutId,
    },
    /// Periodic housekeeping tick.
    Tick,
}

/// An action emitted by the reactor.
#[derive(Debug)]
pub enum ConsensusAction {
    /// Broadcast a proposal block.
    BroadcastBlock(BlockV1),
    /// Broadcast a consensus vote.
    BroadcastVote(VoteV1),
    /// Broadcast a transaction.
    BroadcastTx(TransactionV1),
    /// Broadcast local chain status.
    BroadcastStatus {
        /// Current committed height.
        height: u64,
        /// Current committed tip hash.
        tip_hash: Bytes32,
    },
    /// Send a message to a specific peer.
    SendTo {
        /// Target peer.
        peer: SocketAddr,
        /// Encoded network message.
        msg: Message,
    },
    /// Inform observers that height advanced.
    HeightAdvanced {
        /// New committed height.
        new_height: u64,
    },
    /// Internal marker — no outward action.
    None,
}

/// Single-owner consensus reactor.
pub struct ConsensusReactor {
    driver: ConsensusDriver,
    event_rx: Receiver<ConsensusEvent>,
    action_tx: Sender<ConsensusAction>,
    gossip: Arc<Mutex<GossipEngine>>,
    snapshot: Arc<Mutex<ChainSnapshot>>,
    pending_timeouts: HashMap<TimeoutId, Instant>,
    timer_tx: Sender<(TimeoutId, Duration)>,
    internal_event_queue: VecDeque<ConsensusEvent>,
    proposed_at_slot: Option<(u64, u32)>,
    last_status_at: Instant,
}

impl ConsensusReactor {
    /// Create a reactor from its owned driver and channels.
    pub fn new(
        driver: ConsensusDriver,
        event_tx: Sender<ConsensusEvent>,
        event_rx: Receiver<ConsensusEvent>,
        action_tx: Sender<ConsensusAction>,
        gossip: Arc<Mutex<GossipEngine>>,
        snapshot: Arc<Mutex<ChainSnapshot>>,
    ) -> Self {
        let (timer_tx, timer_rx) = mpsc::channel::<(TimeoutId, Duration)>();
        run_timer_thread(timer_rx, event_tx.clone());
        run_tick_thread(event_tx.clone());
        if let Ok(mut guard) = snapshot.lock() {
            *guard = ChainSnapshot::from_driver(&driver);
        }
        Self {
            driver,
            event_rx,
            action_tx,
            gossip,
            snapshot,
            pending_timeouts: HashMap::new(),
            timer_tx,
            internal_event_queue: VecDeque::new(),
            proposed_at_slot: None,
            last_status_at: Instant::now() - STATUS_INTERVAL,
        }
    }

    /// Run the event loop forever.
    pub fn run(mut self) {
        self.maybe_propose_current_slot();
        self.maybe_schedule_timeout();

        loop {
            if self.drain_internal_events() {
                continue;
            }

            match self.event_rx.recv() {
                Ok(event) => {
                    self.process_event(event);
                    self.drain_internal_events();
                    while let Ok(queued) = self.event_rx.try_recv() {
                        self.process_event(queued);
                        self.drain_internal_events();
                    }
                }
                Err(_) => break,
            }
        }
    }

    fn process_event(&mut self, event: ConsensusEvent) {
        let before_height = self.driver.height();
        let before_tip = self.driver.engine.state.tip_hash;
        let before_mempool = self.driver.engine.mempool.len();
        let before_round = self.driver.current_round();
        let before_phase = self.driver.current_phase();

        let actions = match event {
            ConsensusEvent::ProposalReceived { from, block } => {
                self.driver.process(DriverEvent::InboundBlock { from, block })
            }
            ConsensusEvent::VoteReceived { from, vote } => {
                self.driver.process(DriverEvent::InboundVote { from, vote })
            }
            ConsensusEvent::TxReceived { from, tx } => {
                let mut tx_bytes = Vec::new();
                tx.encode(&mut tx_bytes);
                self.driver.process(DriverEvent::InboundTx { from, tx_bytes })
            }
            ConsensusEvent::PeerStatus {
                from,
                height,
                tip_hash,
            } => self
                .driver
                .process(DriverEvent::PeerStatus { from, height, tip_hash }),
            ConsensusEvent::BlocksRequested {
                from,
                from_height,
                to_height,
            } => {
                self.handle_blocks_requested(from, from_height, to_height);
                Vec::new()
            }
            ConsensusEvent::BlocksResponse { blocks } => self.handle_blocks_response(blocks),
            ConsensusEvent::ProposalRequest {
                from,
                height,
                round,
                hash,
            } => {
                self.handle_proposal_request(from, height, round, hash);
                Vec::new()
            }
            ConsensusEvent::SubmitTx { tx, reply } => {
                self.handle_submit_tx(tx, reply);
                Vec::new()
            }
            ConsensusEvent::TimeoutFired { id } => self.handle_timeout_fired(id, before_round),
            ConsensusEvent::Tick => {
                self.emit_action(ConsensusAction::BroadcastStatus {
                    height: self.driver.height(),
                    tip_hash: self.driver.engine.state.tip_hash,
                });
                self.last_status_at = Instant::now();
                Vec::new()
            }
        };

        self.handle_driver_actions(actions);
        self.maybe_propose_current_slot();
        self.cancel_superseded_timeout(before_height, before_round, before_phase);
        self.after_state_change(before_height, before_tip, before_mempool);
        self.maybe_schedule_timeout();
    }

    fn cancel_superseded_timeout(
        &mut self,
        before_height: u64,
        before_round: u32,
        before_phase: RoundPhase,
    ) {
        let after_height = self.driver.height();
        let after_round = self.driver.current_round();
        let after_phase = self.driver.current_phase();

        if before_phase == RoundPhase::Propose
            && after_height == before_height
            && after_round == before_round
            && after_phase == RoundPhase::Prevote
        {
            let cancel_id = TimeoutId {
                kind: TimeoutKind::Propose,
                height: before_height.saturating_add(1),
                round: before_round,
                phase: RoundPhase::Propose,
            };
            self.pending_timeouts.remove(&cancel_id);
        }
    }

    fn handle_timeout_fired(&mut self, id: TimeoutId, before_round: u32) -> Vec<DriverAction> {
        self.pending_timeouts.remove(&id);

        if !self.driver.sync().is_caught_up() {
            return Vec::new();
        }

        let current_height = self.driver.height() + 1;
        let current_round = self.driver.current_round();
        let current_phase = self.driver.current_phase();
        if id.height != current_height || id.round != current_round || id.phase != current_phase {
            return Vec::new();
        }

        match id.kind {
            TimeoutKind::Propose => self.driver.on_propose_timeout(),
            TimeoutKind::Prevote => self.driver.on_prevote_timeout(),
            TimeoutKind::Precommit => {
                self.driver.on_precommit_timeout();
                if self.driver.current_round() != before_round {
                    eprintln!(
                        "[timing] t={}ms ROUND ADVANCED to {} at height={}",
                        now_ms(),
                        self.driver.current_round(),
                        self.driver.height(),
                    );
                }
                Vec::new()
            }
        }
    }

    fn handle_driver_actions(&mut self, actions: Vec<DriverAction>) {
        for action in actions {
            match action {
                DriverAction::BroadcastBlock(block) => {
                    let mut gossip = self.gossip.lock().unwrap();
                    let peers = gossip.connection_count();
                    eprintln!(
                        "[gossip] broadcasting proposal {} to {} peers",
                        hex::encode(&block.header.block_hash().0[..4]),
                        peers,
                    );
                    let _ = gossip.broadcast_priority(&Message::Block(block));
                }
                DriverAction::BroadcastVote(vote) => {
                    let mut gossip = self.gossip.lock().unwrap();
                    let peers = gossip.connection_count();
                    eprintln!(
                        "[vote] sent vote for {} to {} peers",
                        hex::encode(&vote.block_hash.0[..4]),
                        peers,
                    );
                    let _ = gossip.broadcast(&Message::Vote(vote));
                }
                DriverAction::BroadcastTx(tx) => {
                    self.emit_action(ConsensusAction::BroadcastTx(tx));
                }
                DriverAction::RequestBlocks {
                    from,
                    from_height,
                    to_height,
                } => {
                    self.emit_action(ConsensusAction::SendTo {
                        peer: from,
                        msg: Message::RequestBlocks {
                            from_height,
                            to_height,
                        },
                    });
                }
                DriverAction::RequestProposal {
                    from,
                    height,
                    round,
                    hash,
                } => {
                    self.emit_action(ConsensusAction::SendTo {
                        peer: from,
                        msg: Message::RequestProposal {
                            height,
                            round,
                            hash,
                        },
                    });
                }
                DriverAction::ActivateBufferedProposal(block) => {
                    self.internal_event_queue
                        .push_back(ConsensusEvent::ProposalReceived {
                            from: None,
                            block,
                        });
                }
                DriverAction::SlashDetected(evidence) => {
                    eprintln!(
                        "[slash] detected {:?} at heights {} and {} rounds {} and {}",
                        evidence.offence,
                        evidence.vote_a.height,
                        evidence.vote_b.height,
                        evidence.vote_a.round,
                        evidence.vote_b.round,
                    );
                }
                DriverAction::None => {}
            }
        }
    }

    fn after_state_change(&mut self, before_height: u64, before_tip: Bytes32, before_mempool: usize) {
        let after_height = self.driver.height();
        let after_tip = self.driver.engine.state.tip_hash;
        let after_mempool = self.driver.engine.mempool.len();

        if after_height > before_height {
            self.pending_timeouts.clear();
            self.proposed_at_slot = None;
            self.emit_action(ConsensusAction::HeightAdvanced {
                new_height: after_height,
            });
            self.emit_action(ConsensusAction::BroadcastStatus {
                height: after_height,
                tip_hash: after_tip,
            });
            self.last_status_at = Instant::now();
        }

        if after_height != before_height
            || after_tip != before_tip
            || after_mempool != before_mempool
        {
            if let Ok(mut guard) = self.snapshot.lock() {
                *guard = ChainSnapshot::from_driver(&self.driver);
            }
        }
    }

    fn maybe_propose_current_slot(&mut self) {
        if !self.driver.sync().is_caught_up() || self.driver.current_phase() != RoundPhase::Propose {
            return;
        }

        let next_height = self.driver.height() + 1;
        let round = self.driver.current_round();
        if self.proposed_at_slot == Some((next_height, round))
            || self.driver.has_accepted_proposal_for_height(next_height)
        {
            return;
        }

        let should_propose = {
            let epoch_seed = Bytes32::from(indra_crypto::sha256(&self.driver.engine.state.tip_hash.0));
            let candidates: Vec<indra_consensus::proposer::ProposerCandidate> = self
                .driver
                .engine
                .state
                .validators
                .active_validators()
                .filter_map(|v| {
                    v.vrf_pk.map(|vrf_pk| indra_consensus::proposer::ProposerCandidate {
                        validator_id: v.validator_id,
                        vrf_pubkey: vrf_pk,
                        stake: v.stake_spark,
                    })
                })
                .collect();

            if candidates.is_empty() {
                self.driver.engine.config.bootstrap_peers.is_empty()
            } else {
                let election = indra_consensus::proposer::ProposerElection {
                    epoch_seed,
                    height: next_height,
                    round,
                    candidates,
                };
                self.driver.engine.is_proposer(&election)
            }
        };

        if !should_propose {
            return;
        }

        let epoch_seed = Bytes32::from(indra_crypto::sha256(&self.driver.engine.state.tip_hash.0));
        let candidates: Vec<indra_consensus::proposer::ProposerCandidate> = self
            .driver
            .engine
            .state
            .validators
            .active_validators()
            .filter_map(|v| {
                v.vrf_pk.map(|vrf_pk| indra_consensus::proposer::ProposerCandidate {
                    validator_id: v.validator_id,
                    vrf_pubkey: vrf_pk,
                    stake: v.stake_spark,
                })
            })
            .collect();

        let election = indra_consensus::proposer::ProposerElection {
            epoch_seed,
            height: next_height,
            round,
            candidates,
        };

        let reproposal = self
            .driver
            .valid_value()
            .zip(self.driver.valid_round())
            .and_then(|(valid_hash, valid_round)| {
                self.driver
                    .get_pending_block(valid_hash)
                    .map(|block| (block, valid_round))
            });

        match if let Some((block, valid_round)) = reproposal {
            self.driver.engine.repropose(
                &block,
                round,
                Some(valid_round),
                &election,
                block.header.timestamp,
                self.driver.last_qc_bytes(),
            )
        } else {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let polc_round = self.driver.proposal_polc_round(next_height);
            self.driver
                .engine
                .propose(&election, timestamp, self.driver.last_qc_bytes(), polc_round)
        } {
            Ok(block) => {
                if !block.transactions.is_empty() {
                    eprintln!(
                        "[mempool] including {} txs in block at height={}",
                        block.transactions.len(),
                        block.header.height,
                    );
                }
                let block_hash = block.header.block_hash();
                let actions = self.driver.process(DriverEvent::InboundBlock {
                    from: None,
                    block: block.clone(),
                });
                self.proposed_at_slot = Some((block.header.height, block.header.proposer_round));
                eprintln!(
                    "[timing] t={}ms proposed block {} at height={} round={}",
                    now_ms(),
                    hex::encode(block_hash.0),
                    block.header.height,
                    block.header.proposer_round,
                );
                self.handle_driver_actions(actions);
            }
            Err(e) => eprintln!("[consensus] proposal failed: {}", e),
        }
    }

    fn maybe_schedule_timeout(&mut self) {
        if !self.driver.sync().is_caught_up() {
            self.pending_timeouts.clear();
            return;
        }

        let height = self.driver.height() + 1;
        let round = self.driver.current_round();
        let phase = self.driver.current_phase();
        let id = TimeoutId {
            kind: phase_to_timeout_kind(phase),
            height,
            round,
            phase,
        };
        if self.pending_timeouts.contains_key(&id) {
            return;
        }

        let delay = phase_timeout(phase);
        self.pending_timeouts
            .insert(id.clone(), Instant::now() + delay);
        let _ = self.timer_tx.send((id, delay));
    }

    fn drain_internal_events(&mut self) -> bool {
        let mut drained = false;
        while let Some(event) = self.internal_event_queue.pop_front() {
            drained = true;
            self.process_event(event);
        }
        drained
    }

    fn handle_blocks_requested(&mut self, from: SocketAddr, from_height: u64, to_height: u64) {
        let upper = to_height.min(from_height.saturating_add(SYNC_BATCH_SIZE - 1));
        let mut blocks = Vec::new();
        for height in from_height..=upper {
            match self.driver.engine.block_store.get(height) {
                Ok(block) => blocks.push(block),
                Err(_) => break,
            }
        }
        eprintln!("[sync] serving blocks {}..{} to {}", from_height, upper, from);
        self.emit_action(ConsensusAction::SendTo {
            peer: from,
            msg: Message::BlockResponse { blocks },
        });
    }

    fn handle_proposal_request(&mut self, from: SocketAddr, height: u64, round: u32, hash: Bytes32) {
        let proposal = self
            .driver
            .pending_block(&hash)
            .or_else(|| self.driver.engine.block_store.get(height).ok())
            .filter(|block| {
                block.header.height == height
                    && block.header.proposer_round == round
                    && block.header.value_hash == hash
            });
        if let Some(block) = proposal {
            eprintln!(
                "[gossip] received proposal request for {} at height={} round={} — sending block",
                hex::encode(&hash.0[..4]),
                height,
                round,
            );
            self.emit_action(ConsensusAction::SendTo {
                peer: from,
                msg: Message::Block(block),
            });
        }
    }

    fn handle_blocks_response(&mut self, blocks: Vec<BlockV1>) -> Vec<DriverAction> {
        let mut imported_any = false;
        for block in blocks {
            if block.header.height != self.driver.height() + 1 {
                continue;
            }

            match self.driver.engine.commit_block(&block) {
                Ok(()) => {
                    imported_any = true;
                    self.driver.refresh_registered_voters();
                    self.driver.sync_mut().on_block_imported(block.header.height);
                    self.driver.reset_round();
                    eprintln!("[sync] imported block at height={}", block.header.height);
                }
                Err(e) => {
                    eprintln!("[sync] failed to import block {}: {}", block.header.height, e);
                    break;
                }
            }
        }

        let mut actions = Vec::new();
        if imported_any {
            actions.extend(self.driver.activate_buffered_proposals_for_new_tip());
        }

        let new_height = self.driver.height();
        if let Some((peer, from_height, to_height)) =
            self.driver.sync_mut().next_request_after_response(new_height)
        {
            self.emit_action(ConsensusAction::SendTo {
                peer,
                msg: Message::RequestBlocks {
                    from_height,
                    to_height,
                },
            });
        }
        if self.driver.sync().is_caught_up() && imported_any {
            eprintln!("[sync] caught up to height={}, joining consensus", new_height);
        }
        actions
    }

    fn handle_submit_tx(&mut self, tx: TransactionV1, reply: SyncSender<Result<Bytes32, String>>) {
        let base_fee = self.driver.engine.state.base_fee;
        let height = self.driver.engine.state.height;
        match self.driver.engine.mempool.submit(tx.clone(), base_fee, height) {
            Ok(tx_id) => {
                let _ = reply.send(Ok(tx_id));
                self.emit_action(ConsensusAction::BroadcastTx(tx));
                if let Ok(mut guard) = self.snapshot.lock() {
                    guard.mempool_size = self.driver.engine.mempool.len();
                }
            }
            Err(e) => {
                let _ = reply.send(Err(e.to_string()));
            }
        }
    }

    fn emit_action(&self, action: ConsensusAction) {
        let _ = self.action_tx.send(action);
    }
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn phase_to_timeout_kind(phase: RoundPhase) -> TimeoutKind {
    match phase {
        RoundPhase::Propose => TimeoutKind::Propose,
        RoundPhase::Prevote => TimeoutKind::Prevote,
        RoundPhase::Precommit => TimeoutKind::Precommit,
    }
}

fn phase_timeout(phase: RoundPhase) -> Duration {
    match phase {
        RoundPhase::Propose => PROPOSE_TIMEOUT,
        RoundPhase::Prevote => PREVOTE_TIMEOUT,
        RoundPhase::Precommit => PRECOMMIT_TIMEOUT,
    }
}

fn run_timer_thread(
    pending_rx: Receiver<(TimeoutId, Duration)>,
    event_tx: Sender<ConsensusEvent>,
) {
    thread::spawn(move || {
        while let Ok((id, delay)) = pending_rx.recv() {
            let event_tx = event_tx.clone();
            thread::spawn(move || {
                thread::sleep(delay);
                let _ = event_tx.send(ConsensusEvent::TimeoutFired { id });
            });
        }
    });
}

fn run_tick_thread(event_tx: Sender<ConsensusEvent>) {
    thread::spawn(move || loop {
        thread::sleep(STATUS_INTERVAL);
        if event_tx.send(ConsensusEvent::Tick).is_err() {
            break;
        }
    });
}
