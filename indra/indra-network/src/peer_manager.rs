//! Async peer-manager actor for the authenticated Tokio transport.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::{
    sync::{Mutex, mpsc},
    task::JoinHandle,
};

use indra_core::types::{
    primitives::{Bytes32, MAX_ACCEPTED_ROUND_JUMP, MAX_RELAY_HEIGHT_SKEW, MAX_ROUNDS_PER_HEIGHT},
    slash_detector::SlashDetector, slashing::SlashEvidenceV1,
    vote_signing::vote_signing_bytes,
};
use indra_core::{codec::Encode, ssz::sha256};
use indra_crypto::{ClassicalPublicKey, HybridPublicKey, PQ_PK_BYTES, PqPublicKey, verify_hybrid};

use crate::{
    dandelion::{
        Action as DandelionAction, FluffReason, RelayPeer, SWEEP_INTERVAL, State as DandelionState,
    },
    error::NetworkError,
    frame::{FrameReader, FrameWriter},
    handshake::HandshakeResult,
    message::Message,
    net_types::{NetworkCommand, NetworkEvent, PeerDisconnectReason, RelayValidatorKey},
    peer::{
        BAN_DURATION, BAN_DURATION_RATE_LIMIT, BAN_SCORE, INITIAL_SCORE, MAX_SCORE, PeerTable,
        ScoreEvent,
    },
    policy::{BanStore, BoundedTtlSet},
    rate_limit::{
        GlobalRateLimiter, MessageClass, PeerRateLimiter,
        RateLimitViolation as RateLimitViolationInfo,
    },
};

const SMALL_QUEUE_CAPACITY: usize = 256;
const LARGE_QUEUE_CAPACITY: usize = 4;
const TIE_BREAK_LOG_INTERVAL: Duration = Duration::from_secs(60);
const CONSENSUS_DUPLICATE_FILTER_CAPACITY: usize = 512;
const QC_RESPONSE_DEDUP_CAPACITY: usize = 2_048;
const CONSENSUS_RELAY_SEEN_CAPACITY: usize = 16_384;
const CONSENSUS_SEEN_TTL: Duration = Duration::from_secs(10 * 60);
const STATUS_COALESCE_WINDOW: Duration = Duration::from_millis(500);
const BAN_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const RELAY_FANOUT_SCALE_FACTOR: f64 = 2.0;
const RELAY_FANOUT_MARGIN: usize = 2;
const MIN_CONSENSUS_RELAY_FANOUT: usize = 4;
const MAX_CONSENSUS_RELAY_FANOUT: usize = 16;
const BLOCK_RELAY_FANOUT_MULTIPLIER: usize = 2;
const MAX_BLOCK_RELAY_FANOUT: usize = 24;
/// Maximum authenticated non-validator peers accepted from one IP address.
/// Active validators are identified by their authenticated validator ID and
/// are bounded by the active validator set plus the global peer-table cap.
const MAX_NON_VALIDATOR_PEERS_PER_IP: usize = 3;

#[derive(Clone)]
struct OutboundMessage {
    msg: Message,
    point_to_point: bool,
}

enum PeerManagerMessage {
    Connected {
        addr: SocketAddr,
        handshake: HandshakeResult,
    },
    Disconnected {
        validator_id: Bytes32,
        addr: SocketAddr,
        reason: PeerDisconnectReason,
    },
    InboundMessage {
        validator_id: Bytes32,
        addr: SocketAddr,
        msg: Box<Message>,
        msg_size: usize,
    },
}

struct ManagedPeer {
    addr: SocketAddr,
    is_outbound: bool,
    small_tx: mpsc::Sender<OutboundMessage>,
    large_tx: mpsc::Sender<OutboundMessage>,
    read_task: JoinHandle<()>,
    write_task: JoinHandle<()>,
}

struct PeerManagerActor {
    local_validator_id: Bytes32,
    event_tx: mpsc::Sender<NetworkEvent>,
    command_rx: mpsc::Receiver<NetworkCommand>,
    control_rx: mpsc::Receiver<PeerManagerMessage>,
    control_tx: mpsc::Sender<PeerManagerMessage>,
    peer_table: PeerTable,
    peers_by_validator: HashMap<Bytes32, ManagedPeer>,
    validator_by_addr: HashMap<SocketAddr, Bytes32>,
    connected_peers: Arc<AtomicUsize>,
    connected_outbound_peers: Arc<AtomicUsize>,
    ban_store: BanStore,
    scores_by_validator: HashMap<Bytes32, i32>,
    global_limiter: GlobalRateLimiter,
    limiters_by_validator: HashMap<Bytes32, PeerRateLimiter>,
    qc_response_seen: BoundedTtlSet<Bytes32>,
    transport_slash_detector: Arc<Mutex<SlashDetector>>,
    last_tie_break_log: HashMap<Bytes32, Instant>,
    relay_keys: HashMap<Bytes32, RelayValidatorKey>,
    relay_chain_id: String,
    relay_consensus_context: Option<(u64, u32)>,
    /// Highest same-height round relayed for each validator. This permits a
    /// paused node to receive distant-round evidence without relaying an
    /// unbounded stream of repeated high-round messages.
    relay_highest_rounds: HashMap<(u64, Bytes32), u32>,
    relay_fanout: usize,
    relay_seen: RelaySeenCache,
    block_relay_slots: HashMap<BlockRelaySlotKey, Bytes32>,
    relay_metrics: HashMap<RelayMessageClass, RelayMetrics>,
    dandelion: DandelionState,
}

#[derive(Debug, Clone, Copy)]
enum QueueType {
    Small,
    Large,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ConsensusMessageKey {
    Vote {
        validator_id: Bytes32,
        height: u64,
        round: u32,
        step: u8,
        block_hash: Bytes32,
        content_hash: Bytes32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RelayMessageClass {
    Block,
    Vote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RelayMessageKey {
    Consensus(ConsensusMessageKey),
    Block {
        height: u64,
        round: u32,
        block_hash: Bytes32,
        content_hash: Bytes32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct BlockRelaySlotKey {
    height: u64,
    round: u32,
    validator_id: Bytes32,
}

struct RelaySeenCache {
    order: VecDeque<(RelayMessageKey, Instant)>,
    forwarded: HashMap<RelayMessageKey, HashSet<Bytes32>>,
    capacity: usize,
    ttl: Duration,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RelayMetrics {
    relayed: u64,
    duplicate: u64,
    dropped: u64,
    verification_failed: u64,
    queue_full: u64,
}

struct ConsensusDuplicateFilter {
    seen: BoundedTtlSet<ConsensusMessageKey>,
}

impl ConsensusDuplicateFilter {
    fn new(capacity: usize) -> Self {
        Self {
            seen: BoundedTtlSet::new(capacity, CONSENSUS_SEEN_TTL),
        }
    }

    fn is_duplicate(&mut self, key: ConsensusMessageKey) -> bool {
        let now = Instant::now();
        if self.seen.contains_at(&key, now) {
            return true;
        }
        let _ = self.seen.insert_at(key, now);
        false
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.seen.len()
    }
}

impl RelaySeenCache {
    fn new(capacity: usize) -> Self {
        Self {
            order: VecDeque::with_capacity(capacity),
            forwarded: HashMap::with_capacity(capacity),
            capacity,
            ttl: CONSENSUS_SEEN_TTL,
        }
    }

    fn is_seen(&self, key: &RelayMessageKey) -> bool {
        self.forwarded.contains_key(key)
    }

    fn forwarded_to(&self, key: &RelayMessageKey, validator_id: &Bytes32) -> bool {
        self.forwarded
            .get(key)
            .is_some_and(|forwarded| forwarded.contains(validator_id))
    }

    fn record_forwarded(&mut self, key: RelayMessageKey, forwarded_to: &[Bytes32]) {
        if forwarded_to.is_empty() {
            return;
        }
        let forwarded = forwarded_to.iter().copied().collect::<HashSet<_>>();
        self.upsert_forwarded(key, &forwarded);
    }

    fn upsert_forwarded(&mut self, key: RelayMessageKey, forwarded: &HashSet<Bytes32>) {
        self.expire(Instant::now());
        if let Some(existing) = self.forwarded.get_mut(&key) {
            existing.extend(forwarded.iter().copied());
            return;
        }
        if self.capacity == 0 {
            return;
        }
        while self.order.len() >= self.capacity {
            if let Some((old, _)) = self.order.pop_front() {
                self.forwarded.remove(&old);
            }
        }
        self.order.push_back((key, Instant::now() + self.ttl));
        self.forwarded.insert(key, forwarded.clone());
    }

    fn expire(&mut self, now: Instant) {
        while self.order.front().is_some_and(|(_, expiry)| *expiry <= now) {
            if let Some((key, _)) = self.order.pop_front() {
                self.forwarded.remove(&key);
            }
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.forwarded.len()
    }
}

struct StatusCoalescer {
    last_forwarded: Option<Instant>,
    window: Duration,
}

impl StatusCoalescer {
    fn new(window: Duration) -> Self {
        Self {
            last_forwarded: None,
            window,
        }
    }

    /// Returns true when a Status message is inside the coalescing window and
    /// should be dropped before it takes driver-lock time. Non-Status messages
    /// are never coalesced.
    fn should_drop(&mut self, msg: &Message, now: Instant) -> bool {
        if !matches!(msg, Message::Status { .. }) {
            return false;
        }
        if self
            .last_forwarded
            .map(|last| now.duration_since(last) < self.window)
            .unwrap_or(false)
        {
            return true;
        }
        self.last_forwarded = Some(now);
        false
    }
}

fn consensus_message_key(msg: &Message) -> Option<ConsensusMessageKey> {
    let wire = msg.encode_wire().ok()?;
    let content_hash = Bytes32::from(sha256(&wire));
    match msg {
        Message::Vote(vote) => Some(ConsensusMessageKey::Vote {
            validator_id: vote.validator_id,
            height: vote.height,
            round: vote.round,
            step: vote.step as u8,
            block_hash: vote.block_hash,
            content_hash,
        }),
        _ => None,
    }
}

fn relay_message_class(msg: &Message) -> Option<RelayMessageClass> {
    match msg {
        Message::Block(_) => Some(RelayMessageClass::Block),
        Message::Vote(_) => Some(RelayMessageClass::Vote),
        _ => None,
    }
}

fn relay_message_key(msg: &Message) -> Option<RelayMessageKey> {
    if let Some(key) = consensus_message_key(msg) {
        return Some(RelayMessageKey::Consensus(key));
    }
    let Message::Block(block) = msg else {
        return None;
    };
    let wire = msg.encode_wire().ok()?;
    Some(RelayMessageKey::Block {
        height: block.block.header.height,
        round: block.block.header.proposer_round,
        block_hash: block.block.header.block_hash(),
        content_hash: Bytes32::from(sha256(&wire)),
    })
}

/// Derive relay fanout from active validator count using an epidemic broadcast
/// rule of thumb: O(ln N) peer choices per hop gives high coverage probability
/// after a small number of rounds in a bounded random-ish overlay. INDRA adds a
/// scale factor and margin because validator consensus messages are
/// latency-sensitive, then clamps the result to avoid degenerating back into
/// full-mesh fanout at N=200.
fn derive_consensus_relay_fanout(active_validators: usize) -> usize {
    if active_validators == 0 {
        return MIN_CONSENSUS_RELAY_FANOUT;
    }
    let derived = ((active_validators as f64).ln() * RELAY_FANOUT_SCALE_FACTOR).ceil() as usize
        + RELAY_FANOUT_MARGIN;
    derived.clamp(MIN_CONSENSUS_RELAY_FANOUT, MAX_CONSENSUS_RELAY_FANOUT)
}

fn relay_fanout_for_class(base_fanout: usize, class: RelayMessageClass) -> usize {
    match class {
        RelayMessageClass::Block => base_fanout
            .saturating_mul(BLOCK_RELAY_FANOUT_MULTIPLIER)
            .min(MAX_BLOCK_RELAY_FANOUT),
        RelayMessageClass::Vote => base_fanout,
    }
}

fn relay_key_map(keys: Vec<RelayValidatorKey>) -> HashMap<Bytes32, RelayValidatorKey> {
    keys.into_iter()
        .map(|key| (key.validator_id, key))
        .collect()
}

fn relay_hybrid_public_key(key: &RelayValidatorKey) -> Option<HybridPublicKey> {
    let pq: [u8; PQ_PK_BYTES] = key.hybrid_pq_pk.as_slice().try_into().ok()?;
    Some(HybridPublicKey {
        classical: ClassicalPublicKey(key.hybrid_classical_pk),
        pq: PqPublicKey(pq),
    })
}

fn verify_relay_hybrid_signature(
    signing_bytes: &[u8],
    signature: &indra_core::types::crypto::HybridSignature,
    key: &RelayValidatorKey,
) -> bool {
    let Some(pk) = relay_hybrid_public_key(key) else {
        return false;
    };
    let Ok(sig) = signature.to_crypto_sig() else {
        return false;
    };
    verify_hybrid(signing_bytes, &sig, &pk).is_ok()
}

fn block_relay_validator_id(
    block: &indra_core::types::block::BlockProposalVNext,
    relay_keys: &HashMap<Bytes32, RelayValidatorKey>,
) -> Option<Bytes32> {
    relay_keys
        .contains_key(&block.block.header.proposer_id)
        .then_some(block.block.header.proposer_id)
}

fn relay_message_key_bytes(key: &RelayMessageKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 8 + 4 + 32 + 32);
    match key {
        RelayMessageKey::Consensus(ConsensusMessageKey::Vote {
            validator_id,
            height,
            round,
            step,
            block_hash,
            content_hash,
        }) => {
            out.push(1);
            validator_id.encode(&mut out);
            height.encode(&mut out);
            round.encode(&mut out);
            step.encode(&mut out);
            block_hash.encode(&mut out);
            content_hash.encode(&mut out);
        }
        RelayMessageKey::Block {
            height,
            round,
            block_hash,
            content_hash,
        } => {
            out.push(4);
            height.encode(&mut out);
            round.encode(&mut out);
            block_hash.encode(&mut out);
            content_hash.encode(&mut out);
        }
    }
    out
}

fn short_validator_id(id: &Bytes32) -> String {
    id.0[..4]
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

fn is_self_connection(local_validator_id: Bytes32, peer_validator_id: Bytes32) -> bool {
    local_validator_id == peer_validator_id
}

fn should_log_tie_break(
    last_tie_break_log: &mut HashMap<Bytes32, Instant>,
    validator_id: Bytes32,
    now: Instant,
) -> bool {
    let should_log = last_tie_break_log
        .get(&validator_id)
        .map(|last| now.duration_since(*last) >= TIE_BREAK_LOG_INTERVAL)
        .unwrap_or(true);
    if should_log {
        last_tie_break_log.insert(validator_id, now);
    }
    should_log
}

fn tie_break_keep_new(
    local_validator_id: Bytes32,
    peer_validator_id: Bytes32,
    new_connection_is_initiator: bool,
) -> bool {
    let (initiator_id, responder_id) = if new_connection_is_initiator {
        (local_validator_id, peer_validator_id)
    } else {
        (peer_validator_id, local_validator_id)
    };
    initiator_id < responder_id
}

fn message_queue(msg: &Message) -> QueueType {
    match msg {
        Message::Block(_) | Message::BlockResponse { .. } | Message::QCResponse { .. } => {
            QueueType::Large
        }
        _ => QueueType::Small,
    }
}

fn format_rate_limit_log(
    addr: SocketAddr,
    validator_id: Bytes32,
    violation: RateLimitViolationInfo,
) -> String {
    format!(
        "[p2p] rate limit: dropped {:?} message from {} (validator {}), reason={:?}, penalty=-{}",
        violation.class,
        addr,
        short_validator_id(&validator_id),
        violation.reason,
        violation.penalty,
    )
}

async fn write_message(
    writer: &mut FrameWriter<tokio::net::tcp::OwnedWriteHalf>,
    outbound: OutboundMessage,
) -> Result<(), ()> {
    let Ok(wire) = outbound.msg.encode_wire() else {
        return Ok(());
    };
    writer.write_frame(&wire).await.map_err(|_| ())
}

impl PeerManagerActor {
    async fn handle_rate_limit_violation(
        &mut self,
        validator_id: Bytes32,
        addr: SocketAddr,
        violation: RateLimitViolationInfo,
    ) {
        if violation.class.is_protocol_necessary_for_validators() {
            eprintln!(
                "[p2p] dropping excess {:?} from authenticated validator {} ({}) — no score penalty",
                violation.class,
                short_validator_id(&validator_id),
                addr,
            );
            return;
        }
        self.adjust_validator_score(validator_id, -violation.penalty, BAN_DURATION_RATE_LIMIT)
            .await;
        if self
            .peer_table
            .get(&addr)
            .map(|peer| peer.is_banned())
            .unwrap_or(false)
        {
            if let Err(error) = self.ban_store.ban_until(
                validator_id,
                BanStore::unix_now().saturating_add(BAN_DURATION_RATE_LIMIT.as_secs()),
            ) {
                eprintln!("[p2p] failed to persist rate-limit ban: {error}");
            }
            eprintln!(
                "[p2p] peer {} ({}) banned 10min for sustained rate limit violations",
                short_validator_id(&validator_id),
                addr,
            );
            self.drop_peer(validator_id, addr, PeerDisconnectReason::Ban)
                .await;
        } else {
            eprintln!("{}", format_rate_limit_log(addr, validator_id, violation));
        }
    }

    fn increment_relay_metric(
        &mut self,
        class: RelayMessageClass,
        update: impl FnOnce(&mut RelayMetrics),
    ) {
        update(self.relay_metrics.entry(class).or_default());
    }

    fn relay_verification_passes(&self, msg: &Message) -> bool {
        match msg {
            Message::Vote(vote) => {
                let Some(key) = self.relay_keys.get(&vote.validator_id) else {
                    return false;
                };
                let Ok(signing_bytes) = vote_signing_bytes(
                    vote.height,
                    vote.round,
                    vote.step,
                    &vote.block_hash,
                    &vote.validator_id,
                    &vote.snapshot_root,
                    &self.relay_chain_id,
                ) else {
                    return false;
                };
                verify_relay_hybrid_signature(&signing_bytes, &vote.signature, key)
            }
            Message::Block(proposal) => {
                let Some(key) = self.relay_keys.get(&proposal.block.header.proposer_id) else {
                    return false;
                };
                proposal
                    .signing_bytes(self.relay_chain_id.as_bytes())
                    .is_ok_and(|bytes| {
                        verify_relay_hybrid_signature(&bytes, &proposal.proposer_authorization, key)
                    })
            }
            _ => false,
        }
    }

    fn block_relay_conflicts(
        &mut self,
        block: &indra_core::types::block::BlockProposalVNext,
        key: &RelayMessageKey,
    ) -> bool {
        let RelayMessageKey::Block { content_hash, .. } = key else {
            return false;
        };
        let Some(validator_id) = block_relay_validator_id(block, &self.relay_keys) else {
            return true;
        };
        let slot = BlockRelaySlotKey {
            height: block.block.header.height,
            round: block.block.header.proposer_round,
            validator_id,
        };
        match self.block_relay_slots.get(&slot) {
            Some(existing_hash) if existing_hash != content_hash => true,
            Some(_) => false,
            None => {
                self.block_relay_slots.insert(slot, *content_hash);
                false
            }
        }
    }

    fn relay_targets(
        &self,
        key: &RelayMessageKey,
        class: RelayMessageClass,
        sender: Bytes32,
    ) -> Vec<Bytes32> {
        let fanout = relay_fanout_for_class(self.relay_fanout, class);
        let mut candidates: Vec<(u64, i32, Bytes32)> = self
            .peers_by_validator
            .iter()
            .filter_map(|(validator_id, peer)| {
                if *validator_id == sender || self.relay_seen.forwarded_to(key, validator_id) {
                    return None;
                }
                let score = self
                    .peer_table
                    .get(&peer.addr)
                    .map(|peer| peer.score)
                    .unwrap_or_default();
                let mut seed = relay_message_key_bytes(key);
                validator_id.encode(&mut seed);
                let digest = sha256(&seed);
                let order = u64::from_le_bytes(digest[..8].try_into().unwrap_or([0xFF; 8]));
                Some((order, score, *validator_id))
            })
            .collect();
        candidates.sort_by(|(order_a, score_a, id_a), (order_b, score_b, id_b)| {
            score_b
                .cmp(score_a)
                .then_with(|| order_a.cmp(order_b))
                .then_with(|| id_a.0.cmp(&id_b.0))
        });
        candidates
            .into_iter()
            .take(fanout)
            .map(|(_, _, validator_id)| validator_id)
            .collect()
    }

    async fn relay_if_eligible(&mut self, sender: Bytes32, msg: &Message) {
        let Some(class) = relay_message_class(msg) else {
            return;
        };
        let mut verified_distant_round = false;
        if let Some((height, round)) = self.relay_consensus_context {
            let (message_height, message_round) = match msg {
                Message::Vote(vote) => (vote.height, vote.round),
                Message::Block(proposal) => (
                    proposal.block.header.height,
                    proposal.block.header.proposer_round,
                ),
                _ => return,
            };
            let message_validator_id = match msg {
                Message::Vote(vote) => vote.validator_id,
                Message::Block(proposal) => proposal.block.header.proposer_id,
                _ => return,
            };
            let min_height = height.saturating_sub(MAX_RELAY_HEIGHT_SKEW);
            let max_height = height.saturating_add(MAX_RELAY_HEIGHT_SKEW);
            let min_round = round.saturating_sub(MAX_ACCEPTED_ROUND_JUMP);
            let max_round = round
                .saturating_add(MAX_ACCEPTED_ROUND_JUMP)
                .min(MAX_ROUNDS_PER_HEIGHT - 1);
            let slot_matches = (min_height..=max_height).contains(&message_height)
                && (min_round..=max_round).contains(&message_round);
            if !slot_matches && message_height == height && message_round > max_round {
                let previous_round = self
                    .relay_highest_rounds
                    .get(&(message_height, message_validator_id))
                    .copied();
                if previous_round.is_some_and(|previous| message_round <= previous) {
                    self.increment_relay_metric(class, |metrics| metrics.dropped += 1);
                    return;
                }
                if !self.relay_verification_passes(msg) {
                    self.increment_relay_metric(class, |metrics| metrics.verification_failed += 1);
                    return;
                }
                self.relay_highest_rounds
                    .insert((message_height, message_validator_id), message_round);
                verified_distant_round = true;
            } else if !slot_matches {
                self.increment_relay_metric(class, |metrics| metrics.dropped += 1);
                // Slot distance is a relay admission decision, not proof that
                // the authenticated peer sent invalid consensus data. A
                // validator may be catching up after a restart, SIGSTOP, or a
                // partition. Keep this check before signature verification so
                // stale/flooded slots are cheap to discard, but leave scoring
                // of provably invalid consensus messages to the authoritative
                // validation path below the relay layer.
                return;
            }
        }
        let Some(key) = relay_message_key(msg) else {
            self.increment_relay_metric(class, |metrics| metrics.dropped += 1);
            return;
        };
        let already_seen = self.relay_seen.is_seen(&key);
        if !already_seen {
            if !verified_distant_round && !self.relay_verification_passes(msg) {
                self.increment_relay_metric(class, |metrics| metrics.verification_failed += 1);
                return;
            }
            if let Message::Vote(vote) = msg {
                if let Some(evidence) = self
                    .transport_slash_detector
                    .lock()
                    .await
                    .observe_vote(vote.clone())
                {
                    let wire_evidence = SlashEvidenceV1 {
                        validator_id: evidence.validator_id,
                        vote_1: evidence.vote_a,
                        vote_2: evidence.vote_b,
                    };
                    let _ = self
                        .event_tx
                        .send(NetworkEvent::SlashDetected(Box::new(wire_evidence)))
                        .await;
                }
            }
            if let Message::Block(block) = msg {
                if self.block_relay_conflicts(block, &key) {
                    self.increment_relay_metric(class, |metrics| metrics.dropped += 1);
                    return;
                }
            }
        }
        let targets = self.relay_targets(&key, class, sender);
        if targets.is_empty() {
            if already_seen {
                self.increment_relay_metric(class, |metrics| metrics.duplicate += 1);
            } else {
                self.increment_relay_metric(class, |metrics| metrics.dropped += 1);
            }
            return;
        }
        let mut enqueued = Vec::new();
        for validator_id in &targets {
            if self
                .try_send_to_validator(
                    *validator_id,
                    OutboundMessage {
                        msg: msg.clone(),
                        point_to_point: false,
                    },
                )
                .await
            {
                enqueued.push(*validator_id);
            }
        }
        self.relay_seen.record_forwarded(key, &enqueued);
        self.increment_relay_metric(class, |metrics| metrics.relayed += enqueued.len() as u64);
    }

    async fn broadcast_to_all_connected(&mut self, msg: Message) {
        let validators: Vec<Bytes32> = self.peers_by_validator.keys().copied().collect();
        self.broadcast_to_validators(msg, validators).await;
    }

    async fn broadcast_to_all_connected_except(&mut self, except: Bytes32, msg: Message) {
        let validators: Vec<Bytes32> = self
            .peers_by_validator
            .keys()
            .filter(|validator_id| **validator_id != except)
            .copied()
            .collect();
        self.broadcast_to_validators(msg, validators).await;
    }

    async fn broadcast_to_validators(&mut self, msg: Message, validators: Vec<Bytes32>) {
        let relay_key = relay_message_key(&msg);
        let mut enqueued = Vec::new();
        for validator_id in validators {
            if self
                .try_send_to_validator(
                    validator_id,
                    OutboundMessage {
                        msg: msg.clone(),
                        point_to_point: false,
                    },
                )
                .await
            {
                enqueued.push(validator_id);
            }
        }
        if let Some(key) = relay_key {
            self.relay_seen.record_forwarded(key, &enqueued);
        }
    }

    fn record_queue_full_drop(&mut self, validator_id: Bytes32, addr: SocketAddr, msg: &Message) {
        if let Some(class) = relay_message_class(msg) {
            self.increment_relay_metric(class, |metrics| metrics.queue_full += 1);
            eprintln!(
                "[relay] outbound queue full: dropped {:?} for validator {} ({})",
                class,
                short_validator_id(&validator_id),
                addr,
            );
        }
    }

    async fn try_send_to_validator(
        &mut self,
        validator_id: Bytes32,
        outbound: OutboundMessage,
    ) -> bool {
        let Some(peer) = self.peers_by_validator.get(&validator_id) else {
            return false;
        };
        let addr = peer.addr;
        let queue_type = message_queue(&outbound.msg);
        let result = match queue_type {
            QueueType::Small => peer.small_tx.try_send(outbound),
            QueueType::Large => peer.large_tx.try_send(outbound),
        };
        match result {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(message)) => {
                if message.point_to_point {
                    self.drop_peer(validator_id, addr, PeerDisconnectReason::Timeout)
                        .await;
                } else {
                    self.peer_table.score_event(&addr, ScoreEvent::Timeout);
                    self.record_queue_full_drop(validator_id, addr, &message.msg);
                }
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.drop_peer(validator_id, addr, PeerDisconnectReason::WriteError)
                    .await;
                false
            }
        }
    }

    async fn send_to_validator(&mut self, validator_id: Bytes32, msg: Message) {
        let _ = self
            .try_send_to_validator(
                validator_id,
                OutboundMessage {
                    msg,
                    point_to_point: true,
                },
            )
            .await;
    }

    async fn run(mut self) {
        let mut cleanup = tokio::time::interval(BAN_CLEANUP_INTERVAL);
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut dandelion_sweep = tokio::time::interval(SWEEP_INTERVAL);
        dandelion_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                maybe_command = self.command_rx.recv() => {
                    let Some(command) = maybe_command else {
                        break;
                    };
                    self.handle_command(command).await;
                }
                maybe_control = self.control_rx.recv() => {
                    let Some(control) = maybe_control else {
                        break;
                    };
                    self.handle_control(control).await;
                }
                _ = cleanup.tick() => {
                    self.peer_table.cleanup_expired_bans();
                    if let Err(error) = self.ban_store.cleanup_expired_at(BanStore::unix_now()) {
                        eprintln!("[p2p] failed to persist expired-ban cleanup: {error}");
                    }
                }
                _ = dandelion_sweep.tick() => {
                    let now = Instant::now();
                    let peers = self.dandelion_peers();
                    let actions = self.dandelion.tick(now, &peers, self.relay_keys.len());
                    self.execute_dandelion_actions(actions).await;
                }
            }
        }
    }

    async fn handle_command(&mut self, command: NetworkCommand) {
        match command {
            NetworkCommand::Broadcast(msg) => {
                self.broadcast_to_all_connected(msg).await;
            }
            NetworkCommand::BroadcastExcept { except, msg } => {
                self.broadcast_to_all_connected_except(except, msg).await;
            }
            NetworkCommand::SendTo { validator_id, msg } => {
                self.send_to_validator(validator_id, msg).await;
            }
            NetworkCommand::StartTxStem(tx) => {
                let peers = self.dandelion_peers();
                let actions =
                    self.dandelion
                        .start_local(tx, Instant::now(), &peers, self.relay_keys.len());
                self.execute_dandelion_actions(actions).await;
            }
            NetworkCommand::AcceptedTxStem { from, tx } => {
                let peers = self.dandelion_peers();
                let actions = self.dandelion.accept_stem(
                    from,
                    tx,
                    Instant::now(),
                    &peers,
                    self.relay_keys.len(),
                );
                self.execute_dandelion_actions(actions).await;
            }
            NetworkCommand::ObserveTxFluff { tx_id } => {
                let actions = self.dandelion.observe_fluff(tx_id, Instant::now());
                self.execute_dandelion_actions(actions).await;
            }
            NetworkCommand::Disconnect { validator_id } => {
                if let Some(peer) = self.peers_by_validator.get(&validator_id) {
                    self.drop_peer(validator_id, peer.addr, PeerDisconnectReason::Operator)
                        .await;
                }
            }
            NetworkCommand::DisconnectInvalidConsensusPeer {
                validator_id,
                reason,
            } => {
                if let Some(peer) = self.peers_by_validator.get(&validator_id) {
                    let addr = peer.addr;
                    self.score_validator(validator_id, ScoreEvent::InvalidMessage, BAN_DURATION)
                        .await;
                    eprintln!(
                        "[p2p] disconnecting validator {} ({}) for invalid consensus message: {}",
                        short_validator_id(&validator_id),
                        addr,
                        reason
                    );
                    if self.peers_by_validator.contains_key(&validator_id) {
                        self.drop_peer(validator_id, addr, PeerDisconnectReason::Ban)
                            .await;
                    }
                }
            }
            NetworkCommand::ScorePeer {
                validator_id,
                event,
            } => {
                self.score_validator(validator_id, event, BAN_DURATION)
                    .await;
            }
            NetworkCommand::UpdateRelayValidatorKeys {
                chain_id,
                validators,
            } => {
                self.relay_fanout = derive_consensus_relay_fanout(validators.len());
                self.relay_keys = relay_key_map(validators);
                self.relay_chain_id = chain_id;
            }
            NetworkCommand::UpdateRelayConsensusContext { height, round } => {
                self.relay_consensus_context = Some((height, round));
                self.relay_highest_rounds
                    .retain(|(message_height, _), _| *message_height == height);
            }
        }
    }

    fn dandelion_peers(&self) -> Vec<RelayPeer> {
        self.peers_by_validator
            .iter()
            .map(|(validator_id, peer)| RelayPeer {
                validator_id: *validator_id,
                is_outbound: peer.is_outbound,
            })
            .collect()
    }

    async fn execute_dandelion_actions(&mut self, actions: Vec<DandelionAction>) {
        for action in actions {
            match action {
                DandelionAction::Stem { tx_id, to, tx } => {
                    let sent = self
                        .try_send_to_validator(
                            to,
                            OutboundMessage {
                                msg: Message::TxStem(tx),
                                point_to_point: false,
                            },
                        )
                        .await;
                    if !sent {
                        self.dandelion.stem_send_failed(tx_id, Instant::now());
                    }
                }
                DandelionAction::Fluff { tx, except, reason } => {
                    if reason == FluffReason::NoRelay {
                        // Aggregate alert only: transaction IDs and peer addresses are
                        // deliberately excluded to avoid creating a correlation log.
                        eprintln!(
                            "[p2p][alert] no eligible Dandelion transaction relay after bounded reconnect window; fluffing"
                        );
                    }
                    let msg = Message::Tx(tx);
                    if let Some(except) = except {
                        self.broadcast_to_all_connected_except(except, msg).await;
                    } else {
                        self.broadcast_to_all_connected(msg).await;
                    }
                }
            }
        }
    }

    async fn handle_control(&mut self, control: PeerManagerMessage) {
        match control {
            PeerManagerMessage::Connected { addr, handshake } => {
                self.register_peer(addr, handshake).await;
            }
            PeerManagerMessage::Disconnected {
                validator_id,
                addr,
                reason,
            } => {
                self.drop_peer(validator_id, addr, reason).await;
            }
            PeerManagerMessage::InboundMessage {
                validator_id,
                addr,
                msg,
                msg_size,
            } => {
                // Exact QC repeats are harmlessly coalesced before consuming
                // the sender's finite identity budget. Distinct variants have
                // distinct hashes and remain governed by the rate limiter.
                let qc_response_key = if matches!(*msg, Message::QCResponse { .. }) {
                    let Ok(wire) = msg.encode_wire() else {
                        return;
                    };
                    let key = Bytes32::from(sha256(&wire));
                    let now = Instant::now();
                    if self.qc_response_seen.contains_at(&key, now) {
                        return;
                    }
                    Some(key)
                } else {
                    None
                };
                let violation = self
                    .limiters_by_validator
                    .entry(validator_id)
                    .or_insert_with(PeerRateLimiter::new_for_authenticated_validator)
                    .check(&msg, msg_size);
                if let Some(violation) = violation {
                    self.handle_rate_limit_violation(validator_id, addr, violation)
                        .await;
                    return;
                }
                if MessageClass::needs_global_byte_limit(&msg)
                    && !self.global_limiter.check_large_payload(msg_size)
                {
                    eprintln!(
                        "[p2p] global rate limit: dropped large payload from {}",
                        addr
                    );
                    self.peer_table
                        .adjust_score_with_duration(&addr, -1, BAN_DURATION_RATE_LIMIT);
                    return;
                }
                if let Some(key) = qc_response_key {
                    let _ = self.qc_response_seen.insert_at(key, Instant::now());
                }
                self.relay_if_eligible(validator_id, &msg).await;
                let _ = self
                    .event_tx
                    .send(NetworkEvent::Message {
                        from: addr,
                        validator_id,
                        msg,
                    })
                    .await;
            }
        }
    }

    async fn register_peer(&mut self, addr: SocketAddr, handshake: HandshakeResult) {
        let peer_validator_id = handshake.peer_validator_id;
        if is_self_connection(self.local_validator_id, peer_validator_id) {
            eprintln!(
                "[p2p] rejected self-connection from {} (validator {})",
                addr,
                short_validator_id(&peer_validator_id),
            );
            drop(handshake.stream);
            return;
        }
        if self
            .ban_store
            .is_banned_at(&peer_validator_id, BanStore::unix_now())
        {
            eprintln!(
                "[p2p] rejected actively banned validator {} from {}",
                short_validator_id(&peer_validator_id),
                addr
            );
            drop(handshake.stream);
            return;
        }

        let is_active_validator = self.relay_keys.contains_key(&peer_validator_id);
        if !is_active_validator
            && !self.peers_by_validator.contains_key(&peer_validator_id)
            && self
                .peers_by_validator
                .values()
                .filter(|peer| {
                    peer.addr.ip() == addr.ip()
                        && !self.relay_keys.contains_key(
                            &self
                                .validator_by_addr
                                .get(&peer.addr)
                                .copied()
                                .unwrap_or(Bytes32::ZERO),
                        )
                })
                .count()
                >= MAX_NON_VALIDATOR_PEERS_PER_IP
        {
            eprintln!(
                "[p2p] rejected non-validator peer {} from {}: per-IP authenticated cap reached",
                short_validator_id(&peer_validator_id),
                addr,
            );
            drop(handshake.stream);
            return;
        }

        if let Some(existing) = self.peers_by_validator.get(&peer_validator_id) {
            let keep_new = tie_break_keep_new(
                self.local_validator_id,
                peer_validator_id,
                handshake.is_initiator,
            );
            if keep_new {
                let existing_addr = existing.addr;
                if should_log_tie_break(
                    &mut self.last_tie_break_log,
                    peer_validator_id,
                    Instant::now(),
                ) {
                    eprintln!(
                        "[p2p] tie-break: replacing connection to {} with new {} (validator {})",
                        existing_addr,
                        addr,
                        short_validator_id(&peer_validator_id),
                    );
                }
                self.drop_peer(
                    peer_validator_id,
                    existing_addr,
                    PeerDisconnectReason::DuplicateConnection,
                )
                .await;
            } else {
                if should_log_tie_break(
                    &mut self.last_tie_break_log,
                    peer_validator_id,
                    Instant::now(),
                ) {
                    eprintln!(
                        "[p2p] tie-break: keeping existing connection to {} (validator {}), dropping new {}",
                        existing.addr,
                        short_validator_id(&peer_validator_id),
                        addr,
                    );
                }
                return;
            }
        }

        self.peer_table.cleanup_expired_bans();
        if self.peer_table.add(addr).is_err() {
            let _ = self.peer_table.evict_oldest_disconnected();
            if let Err(error) = self.peer_table.add(addr) {
                eprintln!("[p2p] rejecting {}: peer table remains full: {error}", addr);
                drop(handshake.stream);
                return;
            }
        }

        let is_outbound = handshake.is_initiator;
        let stream = handshake.stream;
        let send_key = handshake.send_key;
        let recv_key = handshake.recv_key;
        let (reader_half, writer_half) = stream.into_split();
        let (small_tx, small_rx) = mpsc::channel(SMALL_QUEUE_CAPACITY);
        let (large_tx, large_rx) = mpsc::channel(LARGE_QUEUE_CAPACITY);
        let control_tx = self.control_tx.clone();
        let read_task = tokio::spawn(async move {
            let mut reader = FrameReader::new(reader_half, recv_key);
            let mut duplicate_filter =
                ConsensusDuplicateFilter::new(CONSENSUS_DUPLICATE_FILTER_CAPACITY);
            let mut status_coalescer = StatusCoalescer::new(STATUS_COALESCE_WINDOW);
            let mut disconnect_reason = PeerDisconnectReason::RemoteClosed;
            loop {
                let plaintext = match reader.read_frame().await {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        disconnect_reason = PeerDisconnectReason::ReadError;
                        break;
                    }
                };
                let msg_size = plaintext.len();
                let msg = match Message::decode_framed_wire(&plaintext) {
                    Ok(msg) => msg,
                    Err(NetworkError::UnknownMessageType { .. }) => continue,
                    Err(_) => break,
                };
                if let Some(key) = consensus_message_key(&msg) {
                    if duplicate_filter.is_duplicate(key) {
                        continue;
                    }
                }
                if status_coalescer.should_drop(&msg, Instant::now()) {
                    continue;
                }
                if control_tx
                    .send(PeerManagerMessage::InboundMessage {
                        validator_id: peer_validator_id,
                        addr,
                        msg: Box::new(msg),
                        msg_size,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = control_tx
                .send(PeerManagerMessage::Disconnected {
                    validator_id: peer_validator_id,
                    addr,
                    reason: disconnect_reason,
                })
                .await;
        });

        let control_tx = self.control_tx.clone();
        let write_task = tokio::spawn(async move {
            run_write_loop(
                writer_half,
                send_key,
                small_rx,
                large_rx,
                control_tx,
                peer_validator_id,
                addr,
            )
            .await;
        });

        self.peer_table.set_validator_id(&addr, peer_validator_id);
        self.peer_table.mark_connected(&addr);
        if let Some(peer) = self.peer_table.get_mut(&addr) {
            peer.score = self
                .scores_by_validator
                .get(&peer_validator_id)
                .copied()
                .unwrap_or(INITIAL_SCORE);
        }
        self.validator_by_addr.insert(addr, peer_validator_id);
        self.peers_by_validator.insert(
            peer_validator_id,
            ManagedPeer {
                addr,
                is_outbound,
                small_tx,
                large_tx,
                read_task,
                write_task,
            },
        );
        self.connected_peers
            .store(self.peers_by_validator.len(), Ordering::Relaxed);
        let _ = self
            .event_tx
            .send(NetworkEvent::PeerConnected {
                validator_id: peer_validator_id,
                addr,
                is_outbound,
            })
            .await;
        self.refresh_connection_counts();
    }

    async fn drop_peer(
        &mut self,
        validator_id: Bytes32,
        addr: SocketAddr,
        reason: PeerDisconnectReason,
    ) {
        let mut is_outbound = false;
        if let Some(peer) = self.peers_by_validator.get(&validator_id) {
            if peer.addr == addr {
                let Some(peer) = self.peers_by_validator.remove(&validator_id) else {
                    return;
                };
                is_outbound = peer.is_outbound;
                peer.read_task.abort();
                peer.write_task.abort();
            } else {
                eprintln!(
                    "[p2p] ignoring stale disconnect for {} (validator {}, current addr is {})",
                    addr,
                    short_validator_id(&validator_id),
                    peer.addr,
                );
                return;
            }
        }
        self.validator_by_addr.remove(&addr);
        self.peer_table.mark_disconnected(&addr);
        self.connected_peers
            .store(self.peers_by_validator.len(), Ordering::Relaxed);
        self.refresh_connection_counts();
        let _ = self
            .event_tx
            .send(NetworkEvent::PeerDisconnected {
                validator_id,
                addr,
                is_outbound,
                reason,
            })
            .await;
    }

    fn refresh_connection_counts(&self) {
        self.connected_peers
            .store(self.peers_by_validator.len(), Ordering::Relaxed);
        self.connected_outbound_peers.store(
            self.peers_by_validator
                .values()
                .filter(|peer| peer.is_outbound)
                .count(),
            Ordering::Relaxed,
        );
    }

    async fn score_validator(
        &mut self,
        validator_id: Bytes32,
        event: ScoreEvent,
        ban_duration: Duration,
    ) {
        if !self.peers_by_validator.contains_key(&validator_id) {
            return;
        }
        self.adjust_validator_score(validator_id, event.delta(), ban_duration)
            .await;
    }

    async fn adjust_validator_score(
        &mut self,
        validator_id: Bytes32,
        delta: i32,
        ban_duration: Duration,
    ) {
        let score = self
            .scores_by_validator
            .entry(validator_id)
            .or_insert(INITIAL_SCORE);
        *score = (*score + delta).clamp(BAN_SCORE, MAX_SCORE);
        let addr = self
            .peers_by_validator
            .get(&validator_id)
            .map(|peer| peer.addr);
        if let Some(addr) = addr {
            if let Some(peer) = self.peer_table.get_mut(&addr) {
                peer.score = *score;
            }
        }
        if *score <= BAN_SCORE {
            if let Err(error) = self.ban_store.ban_until(
                validator_id,
                BanStore::unix_now().saturating_add(ban_duration.as_secs()),
            ) {
                eprintln!("[p2p] failed to persist identity ban: {error}");
            }
            if let Some(addr) = addr {
                self.drop_peer(validator_id, addr, PeerDisconnectReason::Ban)
                    .await;
            }
        }
    }
}

async fn run_write_loop(
    writer_half: tokio::net::tcp::OwnedWriteHalf,
    send_key: [u8; 32],
    mut small_rx: mpsc::Receiver<OutboundMessage>,
    mut large_rx: mpsc::Receiver<OutboundMessage>,
    control_tx: mpsc::Sender<PeerManagerMessage>,
    validator_id: Bytes32,
    addr: SocketAddr,
) {
    let mut writer = FrameWriter::new(writer_half, send_key);
    loop {
        tokio::select! {
            msg = small_rx.recv() => {
                match msg {
                    Some(m) => {
                        if write_message(&mut writer, m).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            msg = large_rx.recv() => {
                match msg {
                    Some(m) => {
                        if write_message(&mut writer, m).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
    let _ = control_tx
        .send(PeerManagerMessage::Disconnected {
            validator_id,
            addr,
            reason: PeerDisconnectReason::WriteError,
        })
        .await;
}

/// Static configuration for the peer-manager actor.
#[derive(Clone)]
pub struct PeerManagerConfig {
    /// Local validator identity for deterministic duplicate-connection resolution.
    pub local_validator_id: Bytes32,
    /// Current chain id used for vote relay signature verification.
    pub chain_id: String,
    /// Active validator public keys used for pre-relay cryptographic checks.
    pub relay_validator_keys: Vec<RelayValidatorKey>,
    /// Outbound event sink consumed by `indra-node`.
    pub event_tx: mpsc::Sender<NetworkEvent>,
    /// Maximum buffered commands from the node into the actor.
    pub command_buffer: usize,
    /// Node-local path for restart-persistent validator identity bans.
    pub ban_store_path: PathBuf,
}

/// Handle returned to callers that need to enqueue network commands or attach peers.
#[derive(Clone)]
pub struct PeerManagerHandle {
    command_tx: mpsc::Sender<NetworkCommand>,
    control_tx: mpsc::Sender<PeerManagerMessage>,
    connected_peers: Arc<AtomicUsize>,
    connected_outbound_peers: Arc<AtomicUsize>,
}

impl PeerManagerHandle {
    /// Queue a node-originated network command.
    pub async fn send(
        &self,
        command: NetworkCommand,
    ) -> Result<(), mpsc::error::SendError<NetworkCommand>> {
        self.command_tx.send(command).await
    }

    /// Queue a node-originated network command from synchronous code.
    pub fn send_blocking(
        &self,
        command: NetworkCommand,
    ) -> Result<(), Box<mpsc::error::SendError<NetworkCommand>>> {
        self.command_tx
            .blocking_send(command)
            .map_err(Box::new)
    }

    /// Register a fully handshaked peer with the actor.
    pub async fn register_peer(
        &self,
        addr: SocketAddr,
        handshake: HandshakeResult,
    ) -> Result<(), ()> {
        self.control_tx
            .send(PeerManagerMessage::Connected { addr, handshake })
            .await
            .map_err(|_| ())
    }

    /// Number of currently connected authenticated peers.
    pub fn connected_peer_count(&self) -> usize {
        self.connected_peers.load(Ordering::Relaxed)
    }

    /// Number of established connections initiated by this node.
    pub fn connected_outbound_peer_count(&self) -> usize {
        self.connected_outbound_peers.load(Ordering::Relaxed)
    }
}

/// Spawn the peer-manager actor and return its handle.
pub fn spawn_peer_manager(config: PeerManagerConfig) -> PeerManagerHandle {
    let (command_tx, command_rx) = mpsc::channel(config.command_buffer);
    let (control_tx, control_rx) = mpsc::channel(config.command_buffer);
    let connected_peers = Arc::new(AtomicUsize::new(0));
    let connected_outbound_peers = Arc::new(AtomicUsize::new(0));
    let ban_store = match BanStore::load(&config.ban_store_path) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("[p2p] failed to load ban store; authenticated networking disabled: {error}");
            drop(command_rx);
            drop(control_rx);
            return PeerManagerHandle {
                command_tx,
                control_tx,
                connected_peers,
                connected_outbound_peers,
            };
        }
    };
    let actor = PeerManagerActor {
        local_validator_id: config.local_validator_id,
        event_tx: config.event_tx,
        command_rx,
        control_rx,
        control_tx: control_tx.clone(),
        peer_table: PeerTable::new(),
        peers_by_validator: HashMap::new(),
        validator_by_addr: HashMap::new(),
        connected_peers: Arc::clone(&connected_peers),
        connected_outbound_peers: Arc::clone(&connected_outbound_peers),
        ban_store,
        scores_by_validator: HashMap::new(),
        global_limiter: GlobalRateLimiter::new(),
        limiters_by_validator: HashMap::new(),
        qc_response_seen: BoundedTtlSet::new(QC_RESPONSE_DEDUP_CAPACITY, CONSENSUS_SEEN_TTL),
        transport_slash_detector: Arc::new(Mutex::new(SlashDetector::new())),
        last_tie_break_log: HashMap::new(),
        relay_chain_id: config.chain_id,
        relay_consensus_context: None,
        relay_highest_rounds: HashMap::new(),
        relay_fanout: derive_consensus_relay_fanout(config.relay_validator_keys.len()),
        relay_keys: relay_key_map(config.relay_validator_keys),
        relay_seen: RelaySeenCache::new(CONSENSUS_RELAY_SEEN_CAPACITY),
        block_relay_slots: HashMap::new(),
        relay_metrics: HashMap::new(),
        dandelion: DandelionState::new(Instant::now()),
    };
    tokio::spawn(actor.run());
    PeerManagerHandle {
        command_tx,
        control_tx,
        connected_peers,
        connected_outbound_peers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerStatus;
    use crate::rate_limit::RateLimitReason;
    use indra_core::types::{
        block::{BlockHeaderVNext, BlockProposalVNext, BlockVNext, SortitionClaimV1, VrfSuiteV1},
        crypto::HybridSignature,
        primitives::{
            Bytes64, MAX_QC_SIZE_BYTES, MAX_STANDARD_VRF_OUTPUT_BYTES,
            MAX_STANDARD_VRF_PROOF_BYTES, ProtocolVersion, VariableBytes,
        },
        vote::{VoteStep, VoteV1},
    };
    use indra_crypto::{ClassicalKeypair, HybridKeypair, PqKeypair, VrfKeypair, vrf_prove};
    use tokio::net::{TcpListener, TcpStream};

    async fn stream_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = TcpStream::connect(addr).await.expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        (client, server)
    }

    fn test_actor(
        event_tx: mpsc::Sender<NetworkEvent>,
        local_validator_id: Bytes32,
    ) -> PeerManagerActor {
        static NEXT_TEST_STORE: AtomicUsize = AtomicUsize::new(0);
        let (_command_tx, command_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        PeerManagerActor {
            local_validator_id,
            event_tx,
            command_rx,
            control_rx,
            control_tx,
            peer_table: PeerTable::new(),
            peers_by_validator: HashMap::new(),
            validator_by_addr: HashMap::new(),
            connected_peers: Arc::new(AtomicUsize::new(0)),
            connected_outbound_peers: Arc::new(AtomicUsize::new(0)),
            ban_store: BanStore::empty(std::env::temp_dir().join(format!(
                "indra-peer-manager-test-bans-{}-{}",
                std::process::id(),
                NEXT_TEST_STORE.fetch_add(1, Ordering::Relaxed),
            ))),
            scores_by_validator: HashMap::new(),
            global_limiter: GlobalRateLimiter::new(),
            limiters_by_validator: HashMap::new(),
            qc_response_seen: BoundedTtlSet::new(QC_RESPONSE_DEDUP_CAPACITY, CONSENSUS_SEEN_TTL),
            transport_slash_detector: Arc::new(Mutex::new(SlashDetector::new())),
            last_tie_break_log: HashMap::new(),
            relay_keys: HashMap::new(),
            relay_chain_id: "indra-testnet-1".to_string(),
            relay_consensus_context: None,
            relay_highest_rounds: HashMap::new(),
            relay_fanout: derive_consensus_relay_fanout(0),
            relay_seen: RelaySeenCache::new(CONSENSUS_RELAY_SEEN_CAPACITY),
            block_relay_slots: HashMap::new(),
            relay_metrics: HashMap::new(),
            dandelion: DandelionState::new(Instant::now()),
        }
    }

    async fn handshake_result(
        peer_validator_id: Bytes32,
        is_initiator: bool,
    ) -> (HandshakeResult, TcpStream) {
        let (owned, keepalive) = stream_pair().await;
        (
            HandshakeResult {
                peer_validator_id,
                send_key: [0x11; 32],
                recv_key: [0x22; 32],
                stream: owned,
                is_initiator,
            },
            keepalive,
        )
    }

    #[tokio::test]
    async fn eight_inbound_connections_do_not_satisfy_outbound_target() {
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut actor = test_actor(event_tx, Bytes32::from([0xF0; 32]));
        let mut keepalive = Vec::new();
        for index in 0..8u8 {
            let (handshake, peer_stream) =
                handshake_result(Bytes32::from([index; 32]), false).await;
            actor
                .register_peer(
                    format!("127.0.0.{}:{}", index + 1, 20_000 + index as u16)
                        .parse()
                        .unwrap(),
                    handshake,
                )
                .await;
            keepalive.push(peer_stream);
            let _ = event_rx.recv().await;
        }
        assert_eq!(actor.peers_by_validator.len(), 8);
        assert_eq!(actor.connected_outbound_peers.load(Ordering::Relaxed), 0);

        let (handshake, peer_stream) = handshake_result(Bytes32::from([0xA0; 32]), true).await;
        actor
            .register_peer("127.0.1.1:21000".parse().unwrap(), handshake)
            .await;
        keepalive.push(peer_stream);
        assert_eq!(actor.connected_outbound_peers.load(Ordering::Relaxed), 1);
        assert_eq!(actor.peers_by_validator.len(), 9);
    }

    #[tokio::test]
    async fn active_identity_ban_rejects_reconnect_from_new_port() {
        let (event_tx, _event_rx) = mpsc::channel(4);
        let mut actor = test_actor(event_tx, Bytes32::from([0xF1; 32]));
        let validator = Bytes32::from([0x42; 32]);
        actor
            .ban_store
            .ban_until(validator, BanStore::unix_now() + 60)
            .unwrap();
        let (handshake, _keepalive) = handshake_result(validator, false).await;
        actor
            .register_peer("127.0.0.1:29999".parse().unwrap(), handshake)
            .await;
        assert!(!actor.peers_by_validator.contains_key(&validator));
    }

    #[tokio::test]
    async fn non_validator_authenticated_peers_are_capped_per_ip() {
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0xF3; 32]));
        let mut keepalive = Vec::new();
        for index in 0..MAX_NON_VALIDATOR_PEERS_PER_IP {
            let (handshake, peer_stream) =
                handshake_result(Bytes32::from([index as u8 + 1; 32]), false).await;
            actor
                .register_peer(
                    format!("127.0.0.1:{}", 30_100 + index)
                        .parse()
                        .unwrap(),
                    handshake,
                )
                .await;
            keepalive.push(peer_stream);
            assert!(matches!(event_rx.recv().await, Some(NetworkEvent::PeerConnected { .. })));
        }

        let (handshake, rejected_stream) =
            handshake_result(Bytes32::from([0xEE; 32]), false).await;
        actor
            .register_peer("127.0.0.1:30100".parse().unwrap(), handshake)
            .await;
        keepalive.push(rejected_stream);
        assert_eq!(actor.peers_by_validator.len(), MAX_NON_VALIDATOR_PEERS_PER_IP);
        assert!(!actor
            .peers_by_validator
            .contains_key(&Bytes32::from([0xEE; 32])));
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn active_validator_shared_ip_is_exempt_but_loses_exemption_when_removed() {
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0xF4; 32]));
        let active = Bytes32::from([0xAA; 32]);
        actor.relay_keys.insert(
            active,
            RelayValidatorKey {
                validator_id: active,
                hybrid_classical_pk: [0; 32],
                hybrid_pq_pk: vec![0; PQ_PK_BYTES],
                vrf_pk: None,
            },
        );
        let mut keepalive = Vec::new();
        for index in 0..MAX_NON_VALIDATOR_PEERS_PER_IP {
            let (handshake, peer_stream) =
                handshake_result(Bytes32::from([index as u8 + 1; 32]), false).await;
            actor
                .register_peer(
                    format!("127.0.0.1:{}", 30_200 + index)
                        .parse()
                        .unwrap(),
                    handshake,
                )
                .await;
            keepalive.push(peer_stream);
            let _ = event_rx.recv().await;
        }
        let (handshake, active_stream) = handshake_result(active, false).await;
        actor
            .register_peer("127.0.0.1:30200".parse().unwrap(), handshake)
            .await;
        keepalive.push(active_stream);
        let _ = event_rx.recv().await;
        assert_eq!(actor.peers_by_validator.len(), MAX_NON_VALIDATOR_PEERS_PER_IP + 1);

        actor.relay_keys.clear();
        let inactive = Bytes32::from([0xAB; 32]);
        let (handshake, inactive_stream) = handshake_result(inactive, false).await;
        actor
            .register_peer("127.0.0.1:30201".parse().unwrap(), handshake)
            .await;
        keepalive.push(inactive_stream);
        assert!(!actor.peers_by_validator.contains_key(&inactive));
    }

    #[tokio::test]
    async fn registration_at_peer_table_capacity_evicts_stale_and_remains_scored() {
        let (event_tx, _event_rx) = mpsc::channel(4);
        let mut actor = test_actor(event_tx, Bytes32::from([0xF2; 32]));
        for index in 0..crate::peer::MAX_PEERS {
            let addr: SocketAddr = format!("127.1.{}.{index}:30000", index / 250)
                .parse()
                .unwrap();
            actor.peer_table.add(addr).unwrap();
            actor.peer_table.mark_disconnected(&addr);
        }
        let validator = Bytes32::from([0x55; 32]);
        let (handshake, _keepalive) = handshake_result(validator, true).await;
        let addr = "127.2.0.1:30001".parse().unwrap();
        actor.register_peer(addr, handshake).await;
        assert_eq!(actor.peer_table.len(), crate::peer::MAX_PEERS);
        assert!(actor.peer_table.get(&addr).is_some());
        actor
            .score_validator(validator, ScoreEvent::ValidTx, BAN_DURATION)
            .await;
        assert_eq!(
            actor.peer_table.get(&addr).unwrap().score,
            crate::peer::INITIAL_SCORE + 1
        );
    }

    #[tokio::test]
    async fn test_duplicate_connection_tie_breaking() {
        let local = Bytes32::from([0x01; 32]);
        let peer = Bytes32::from([0x02; 32]);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, local);

        let addr_old: SocketAddr = "127.0.0.1:30001".parse().unwrap();
        let addr_new: SocketAddr = "127.0.0.1:30002".parse().unwrap();
        let ((old_hs, _old_keepalive), (new_hs, _new_keepalive)) =
            tokio::join!(handshake_result(peer, false), handshake_result(peer, true),);

        actor.register_peer(addr_old, old_hs).await;
        actor.register_peer(addr_new, new_hs).await;

        assert_eq!(actor.peers_by_validator.len(), 1);
        assert_eq!(actor.connected_peers.load(Ordering::Relaxed), 1);
        assert_eq!(actor.peers_by_validator.get(&peer).unwrap().addr, addr_new);
        assert!(!actor.validator_by_addr.contains_key(&addr_old));
        assert_eq!(actor.validator_by_addr.get(&addr_new), Some(&peer));

        let mut connected = 0;
        let mut disconnected = 0;
        while let Ok(event) = event_rx.try_recv() {
            match event {
                NetworkEvent::PeerConnected { .. } => connected += 1,
                NetworkEvent::PeerDisconnected { .. } => disconnected += 1,
                NetworkEvent::Message { .. } | NetworkEvent::SlashDetected(_) => {}
            }
        }
        assert_eq!(connected, 2);
        assert_eq!(disconnected, 1);
    }

    #[test]
    fn tie_break_with_same_validator_resolves_deterministically() {
        let local = Bytes32::from([0x01; 32]);
        let peer = Bytes32::from([0x02; 32]);

        assert!(tie_break_keep_new(local, peer, true));
        assert!(!tie_break_keep_new(local, peer, false));
        assert_eq!(
            tie_break_keep_new(local, peer, true),
            tie_break_keep_new(local, peer, true),
            "same validator pair and connection direction must resolve the same way"
        );
    }

    #[test]
    fn duplicate_connection_tie_breaking_is_symmetric_for_200_cases() {
        for seed in 0..200u16 {
            let mut local_bytes = [0u8; 32];
            let mut peer_bytes = [0u8; 32];
            local_bytes[..2].copy_from_slice(&seed.to_be_bytes());
            peer_bytes[..2].copy_from_slice(&(u16::MAX - seed).to_be_bytes());
            let local = Bytes32::from(local_bytes);
            let peer = Bytes32::from(peer_bytes);

            assert_eq!(
                tie_break_keep_new(local, peer, true),
                tie_break_keep_new(peer, local, false),
                "both endpoints must choose the same connection for case {seed}"
            );
        }
    }

    #[test]
    fn tie_break_log_is_rate_limited_per_validator() {
        let validator = Bytes32::from([0xAA; 32]);
        let now = Instant::now();
        let mut last = HashMap::new();

        assert!(should_log_tie_break(&mut last, validator, now));
        assert!(!should_log_tie_break(
            &mut last,
            validator,
            now + Duration::from_secs(1)
        ));
        assert!(should_log_tie_break(
            &mut last,
            validator,
            now + TIE_BREAK_LOG_INTERVAL + Duration::from_secs(1)
        ));
    }

    #[test]
    fn self_connection_is_rejected_before_peer_connected_event() {
        let local = Bytes32::from([0x01; 32]);
        let remote_self = Bytes32::from([0x01; 32]);
        let remote_peer = Bytes32::from([0x02; 32]);

        assert!(is_self_connection(local, remote_self));
        assert!(!is_self_connection(local, remote_peer));
    }

    fn dummy_signature() -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
        }
    }

    fn core_signature(sig: indra_crypto::HybridSignature) -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
        }
    }

    fn hybrid_key(seed: u8) -> HybridKeypair {
        HybridKeypair::new(
            ClassicalKeypair::from_seed(&[seed; 32]),
            PqKeypair::from_seed(&[seed.saturating_add(1); 32]).unwrap(),
        )
    }

    fn relay_key(validator_id: Bytes32, keypair: &HybridKeypair) -> RelayValidatorKey {
        let public = keypair.public_key();
        RelayValidatorKey {
            validator_id,
            hybrid_classical_pk: public.classical.0,
            hybrid_pq_pk: public.pq.0.to_vec(),
            vrf_pk: Some(VrfKeypair::from_seed(&validator_id.0).public_key()),
        }
    }

    fn signed_vote(validator_id: Bytes32, keypair: &HybridKeypair) -> VoteV1 {
        signed_vote_for_hash(
            validator_id,
            keypair,
            VoteStep::Prevote,
            Bytes32::from([0x44; 32]),
        )
    }

    fn signed_vote_for_hash(
        validator_id: Bytes32,
        keypair: &HybridKeypair,
        step: VoteStep,
        block_hash: Bytes32,
    ) -> VoteV1 {
        signed_vote_at(validator_id, keypair, 7, 2, step, block_hash)
    }

    fn signed_vote_at(
        validator_id: Bytes32,
        keypair: &HybridKeypair,
        height: u64,
        round: u32,
        step: VoteStep,
        block_hash: Bytes32,
    ) -> VoteV1 {
        let bytes = vote_signing_bytes(
            height,
            round,
            step,
            &block_hash,
            &validator_id,
            &Bytes32::ZERO,
            "indra-testnet-1",
        )
        .unwrap();
        VoteV1 {
            height,
            round,
            step,
            block_hash,
            validator_id,
            snapshot_root: Bytes32::ZERO,
            signature: core_signature(keypair.sign(&bytes).unwrap()),
        }
    }

    #[tokio::test]
    async fn transport_slash_detector_observes_only_verified_votes() {
        let victim = Bytes32::from([0xB3; 32]);
        let victim_key = hybrid_key(0xB3);
        let attacker_key = hybrid_key(0xB4);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        install_relay_keys(&mut actor, vec![relay_key(victim, &victim_key)]);

        for hash in [Bytes32::from([0xA1; 32]), Bytes32::from([0xA2; 32])] {
            let forged = Message::Vote(signed_vote_for_hash(
                victim,
                &attacker_key,
                VoteStep::Precommit,
                hash,
            ));
            actor
                .relay_if_eligible(Bytes32::from([0xB4; 32]), &forged)
                .await;
        }
        assert!(event_rx.try_recv().is_err());

        for hash in [Bytes32::from([0xC1; 32]), Bytes32::from([0xC2; 32])] {
            let valid = Message::Vote(signed_vote_for_hash(
                victim,
                &victim_key,
                VoteStep::Precommit,
                hash,
            ));
            actor
                .relay_if_eligible(Bytes32::from([0xB4; 32]), &valid)
                .await;
        }
        assert!(matches!(
            event_rx.try_recv(),
            Ok(NetworkEvent::SlashDetected(_))
        ));
    }

    fn relay_test_block(
        validator_id: Bytes32,
        vrf: &VrfKeypair,
        signer: &HybridKeypair,
        height: u64,
        round: u32,
        prev_hash: Bytes32,
        value_hash: Bytes32,
    ) -> BlockProposalVNext {
        let input = [
            height.to_le_bytes().as_slice(),
            round.to_le_bytes().as_slice(),
        ]
        .concat();
        let (output, proof) = vrf_prove(vrf, &input);
        let block = BlockVNext {
            header: BlockHeaderVNext {
                protocol_version: ProtocolVersion::CURRENT,
                height,
                prev_hash,
                timestamp: 0,
                state_root: Bytes32::ZERO,
                validator_set_root: Bytes32::ZERO,
                mempool_set_root: Bytes32::ZERO,
                value_hash,
                base_fee: 0,
                proposer_round: round,
                polc_round: None,
                proposer_id: validator_id,
                vrf_suite: VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
                election_seed: Bytes64([0x55; 64]),
                proposer_vrf_output: VariableBytes::<MAX_STANDARD_VRF_OUTPUT_BYTES>::from_slice(
                    &output.0,
                )
                .unwrap(),
                proposer_vrf_proof: VariableBytes::<MAX_STANDARD_VRF_PROOF_BYTES>::from_slice(
                    &proof.0,
                )
                .unwrap(),
                value_entropy: indra_core::types::block::ProposalEntropyV1 {
                    origin_proposer_id: validator_id,
                    origin_round: round,
                    vrf_output: VariableBytes::from_slice(&output.0).unwrap(),
                    vrf_proof: VariableBytes::from_slice(&proof.0).unwrap(),
                },
                sortition_claim: SortitionClaimV1::PraosThreshold,
                proposer_priority: Bytes64([0x56; 64]),
                quorum_certificate: VariableBytes::<MAX_QC_SIZE_BYTES>::from_slice(&[]).unwrap(),
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        };
        let mut proposal = BlockProposalVNext {
            block,
            proposer_authorization: dummy_signature(),
        };
        let signature = signer
            .sign(&proposal.signing_bytes(b"indra-testnet-1").unwrap())
            .unwrap();
        proposal.proposer_authorization = indra_core::types::crypto::HybridSignature {
            classical_sig: VariableBytes::from_slice(&signature.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&signature.pq.0).unwrap(),
        };
        proposal
    }

    fn install_relay_keys(actor: &mut PeerManagerActor, keys: Vec<RelayValidatorKey>) {
        actor.relay_fanout = derive_consensus_relay_fanout(keys.len());
        actor.relay_keys = relay_key_map(keys);
        actor.relay_chain_id = "indra-testnet-1".to_string();
    }

    fn add_test_peer(
        actor: &mut PeerManagerActor,
        validator_id: Bytes32,
        port: u16,
    ) -> mpsc::Receiver<OutboundMessage> {
        add_test_peer_receivers(actor, validator_id, port).0
    }

    fn add_test_peer_large(
        actor: &mut PeerManagerActor,
        validator_id: Bytes32,
        port: u16,
    ) -> mpsc::Receiver<OutboundMessage> {
        add_test_peer_receivers(actor, validator_id, port).1
    }

    fn add_test_peer_receivers(
        actor: &mut PeerManagerActor,
        validator_id: Bytes32,
        port: u16,
    ) -> (
        mpsc::Receiver<OutboundMessage>,
        mpsc::Receiver<OutboundMessage>,
    ) {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let (small_tx, small_rx) = mpsc::channel(16);
        let (large_tx, large_rx) = mpsc::channel(16);
        actor.peer_table.add(addr).unwrap();
        actor.peer_table.set_validator_id(&addr, validator_id);
        actor.peer_table.mark_connected(&addr);
        actor.validator_by_addr.insert(addr, validator_id);
        actor.peers_by_validator.insert(
            validator_id,
            ManagedPeer {
                addr,
                is_outbound: false,
                small_tx,
                large_tx,
                read_task: tokio::spawn(async {}),
                write_task: tokio::spawn(async {}),
            },
        );
        (small_rx, large_rx)
    }

    fn add_test_peer_receivers_with_capacity(
        actor: &mut PeerManagerActor,
        validator_id: Bytes32,
        port: u16,
        small_capacity: usize,
        large_capacity: usize,
    ) -> (
        mpsc::Receiver<OutboundMessage>,
        mpsc::Receiver<OutboundMessage>,
    ) {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let (small_tx, small_rx) = mpsc::channel(small_capacity);
        let (large_tx, large_rx) = mpsc::channel(large_capacity);
        actor.peer_table.add(addr).unwrap();
        actor.peer_table.set_validator_id(&addr, validator_id);
        actor.peer_table.mark_connected(&addr);
        actor.validator_by_addr.insert(addr, validator_id);
        actor.peers_by_validator.insert(
            validator_id,
            ManagedPeer {
                addr,
                is_outbound: false,
                small_tx,
                large_tx,
                read_task: tokio::spawn(async {}),
                write_task: tokio::spawn(async {}),
            },
        );
        (small_rx, large_rx)
    }

    #[test]
    fn consensus_duplicate_filter_is_bounded() {
        let mut filter = ConsensusDuplicateFilter::new(3);
        for i in 0..4u8 {
            assert!(!filter.is_duplicate(ConsensusMessageKey::Vote {
                validator_id: Bytes32::from([i; 32]),
                height: 1,
                round: 0,
                step: VoteStep::Prevote as u8,
                block_hash: Bytes32::from([i.saturating_add(10); 32]),
                content_hash: Bytes32::from([i.saturating_add(20); 32]),
            }));
        }
        assert_eq!(filter.len(), 3);
        assert!(
            !filter.is_duplicate(ConsensusMessageKey::Vote {
                validator_id: Bytes32::from([0; 32]),
                height: 1,
                round: 0,
                step: VoteStep::Prevote as u8,
                block_hash: Bytes32::from([10; 32]),
                content_hash: Bytes32::from([20; 32]),
            }),
            "oldest entry should be evicted when capacity is exceeded"
        );
    }

    #[test]
    fn consensus_duplicate_filter_detects_exact_vote_duplicates() {
        let vote = Message::Vote(VoteV1 {
            height: 7,
            round: 2,
            step: VoteStep::Prevote,
            block_hash: Bytes32::from([0xAA; 32]),
            validator_id: Bytes32::from([0xBB; 32]),
            snapshot_root: Bytes32::ZERO,
            signature: dummy_signature(),
        });
        let key = consensus_message_key(&vote).expect("vote key");
        let mut filter = ConsensusDuplicateFilter::new(CONSENSUS_DUPLICATE_FILTER_CAPACITY);
        assert!(!filter.is_duplicate(key));
        assert!(filter.is_duplicate(key));
    }

    #[tokio::test]
    async fn qc_response_dedup_is_node_wide_and_forwards_once() {
        let validator = Bytes32::from([0xB1; 32]);
        let addr: SocketAddr = "127.0.0.1:32101".parse().unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        let msg = Message::QCResponse {
            height: 9,
            qc_bytes: vec![0xAB; 128],
        };
        for _ in 0..2 {
            actor
                .handle_control(PeerManagerMessage::InboundMessage {
                    validator_id: validator,
                    addr,
                    msg: Box::new(msg.clone()),
                    msg_size: 128,
                })
                .await;
        }
        assert!(matches!(
            event_rx.try_recv(),
            Ok(NetworkEvent::Message {
                msg,
                ..
            }) if matches!(*msg, Message::QCResponse { .. })
        ));
        assert!(event_rx.try_recv().is_err());
        assert_eq!(actor.qc_response_seen.len(), 1);
    }

    #[tokio::test]
    async fn near_duplicate_votes_share_one_validator_identity_budget() {
        let validator = Bytes32::from([0xB2; 32]);
        let addr: SocketAddr = "127.0.0.1:32102".parse().unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(128);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        actor.limiters_by_validator.insert(
            validator,
            PeerRateLimiter::new_for_test_with_frozen_vote_bucket(),
        );
        for index in 0..81u8 {
            // All votes claim the exact same consensus slot, but differ in
            // signed content and encoded hash. They therefore evade the
            // connection-local exact-message filter and model a validator
            // spamming near-duplicates/equivocations with one identity.
            let msg = Message::Vote(VoteV1 {
                height: 1,
                round: 0,
                step: VoteStep::Prevote,
                block_hash: Bytes32::from([index; 32]),
                validator_id: validator,
                snapshot_root: Bytes32::ZERO,
                signature: dummy_signature(),
            });
            actor
                .handle_control(PeerManagerMessage::InboundMessage {
                    validator_id: validator,
                    addr,
                    msg: Box::new(msg),
                    msg_size: 5_000,
                })
                .await;
        }
        let mut delivered = 0;
        while event_rx.try_recv().is_ok() {
            delivered += 1;
        }
        assert_eq!(delivered, 80);
        assert_eq!(actor.limiters_by_validator.len(), 1);
    }

    #[tokio::test]
    async fn distinct_validators_have_independent_vote_budgets() {
        let validator_a = Bytes32::from([0xB3; 32]);
        let validator_b = Bytes32::from([0xB4; 32]);
        let addr: SocketAddr = "127.0.0.1:32103".parse().unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(256);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        for validator in [validator_a, validator_b] {
            actor.limiters_by_validator.insert(
                validator,
                PeerRateLimiter::new_for_test_with_frozen_vote_bucket(),
            );
            for index in 0..80u8 {
                actor
                    .handle_control(PeerManagerMessage::InboundMessage {
                        validator_id: validator,
                        addr,
                        msg: Box::new(Message::Vote(VoteV1 {
                            height: 1,
                            round: 0,
                            step: VoteStep::Prevote,
                            block_hash: Bytes32::from([index; 32]),
                            validator_id: validator,
                            snapshot_root: Bytes32::ZERO,
                            signature: dummy_signature(),
                        })),
                        msg_size: 5_000,
                    })
                    .await;
            }
        }
        let mut delivered = 0;
        while event_rx.try_recv().is_ok() {
            delivered += 1;
        }
        assert_eq!(delivered, 160);
        assert_eq!(actor.limiters_by_validator.len(), 2);
    }

    #[tokio::test]
    async fn disconnect_does_not_reset_validator_vote_budget() {
        let validator = Bytes32::from([0xB5; 32]);
        let addr: SocketAddr = "127.0.0.1:32104".parse().unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(128);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        actor.limiters_by_validator.insert(
            validator,
            PeerRateLimiter::new_for_test_with_frozen_vote_bucket(),
        );
        let vote = |index| {
            Message::Vote(VoteV1 {
                height: 1,
                round: 0,
                step: VoteStep::Prevote,
                block_hash: Bytes32::from([index; 32]),
                validator_id: validator,
                snapshot_root: Bytes32::ZERO,
                signature: dummy_signature(),
            })
        };
        for index in 0..80u8 {
            actor
                .handle_control(PeerManagerMessage::InboundMessage {
                    validator_id: validator,
                    addr,
                    msg: Box::new(vote(index)),
                    msg_size: 5_000,
                })
                .await;
        }
        actor
            .drop_peer(validator, addr, PeerDisconnectReason::Operator)
            .await;
        actor
            .handle_control(PeerManagerMessage::InboundMessage {
                validator_id: validator,
                addr,
                msg: Box::new(vote(80)),
                msg_size: 5_000,
            })
            .await;

        let mut delivered_votes = 0;
        while let Ok(event) = event_rx.try_recv() {
            if matches!(event, NetworkEvent::Message { .. }) {
                delivered_votes += 1;
            }
        }
        assert_eq!(delivered_votes, 80);
        assert!(actor.limiters_by_validator.contains_key(&validator));
    }

    #[test]
    fn fanout_derivation_matches_expected_values_at_each_phase_boundary() {
        assert_eq!(derive_consensus_relay_fanout(20), 8);
        assert_eq!(derive_consensus_relay_fanout(50), 10);
        assert_eq!(derive_consensus_relay_fanout(100), 12);
        assert_eq!(derive_consensus_relay_fanout(200), 13);
        assert_eq!(
            relay_fanout_for_class(13, RelayMessageClass::Block),
            24,
            "block relay fanout is a bounded multiplier, not full mesh"
        );
    }

    #[test]
    fn relay_cache_is_bounded_and_evicts_old_entries() {
        let mut cache = RelaySeenCache::new(2);
        let key = |byte| {
            RelayMessageKey::Consensus(ConsensusMessageKey::Vote {
                validator_id: Bytes32::from([byte; 32]),
                height: 1,
                round: 0,
                step: 0,
                block_hash: Bytes32::ZERO,
                content_hash: Bytes32::from([byte; 32]),
            })
        };
        let forwarded = Bytes32::from([0xFE; 32]);
        cache.record_forwarded(key(1), &[forwarded]);
        cache.record_forwarded(key(2), &[forwarded]);
        cache.record_forwarded(key(3), &[forwarded]);
        assert_eq!(cache.len(), 2);
        assert!(!cache.is_seen(&key(1)));
        assert!(cache.is_seen(&key(2)));
        assert!(cache.is_seen(&key(3)));
    }

    #[tokio::test]
    async fn relay_targets_skip_already_forwarded_peers() {
        let key = RelayMessageKey::Consensus(ConsensusMessageKey::Vote {
            validator_id: Bytes32::from([0x71; 32]),
            height: 1,
            round: 0,
            step: 1,
            block_hash: Bytes32::from([0x72; 32]),
            content_hash: Bytes32::from([0x73; 32]),
        });
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        let sender = Bytes32::from([0x70; 32]);
        let forwarded = Bytes32::from([0x74; 32]);
        let available = Bytes32::from([0x75; 32]);
        actor.relay_seen.record_forwarded(key, &[forwarded]);
        actor.relay_fanout = 4;
        let _forwarded_rx = add_test_peer(&mut actor, forwarded, 34074);
        let _available_rx = add_test_peer(&mut actor, available, 34075);

        let targets = actor.relay_targets(&key, RelayMessageClass::Vote, sender);
        assert!(!targets.contains(&forwarded));
        assert!(targets.contains(&available));
    }

    #[tokio::test]
    async fn relay_targets_prefer_higher_scored_peers() {
        let key = RelayMessageKey::Consensus(ConsensusMessageKey::Vote {
            validator_id: Bytes32::from([0x82; 32]),
            height: 1,
            round: 0,
            step: 1,
            block_hash: Bytes32::from([0x83; 32]),
            content_hash: Bytes32::from([0x84; 32]),
        });
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        actor.relay_fanout = 1;
        let sender = Bytes32::from([0x85; 32]);
        let high_score = Bytes32::from([0x86; 32]);
        let low_score = Bytes32::from([0x87; 32]);
        let _high_rx = add_test_peer(&mut actor, high_score, 34086);
        let _low_rx = add_test_peer(&mut actor, low_score, 34087);
        let high_addr: SocketAddr = "127.0.0.1:34086".parse().unwrap();
        let low_addr: SocketAddr = "127.0.0.1:34087".parse().unwrap();
        actor.peer_table.get_mut(&high_addr).unwrap().score = 150;
        actor.peer_table.get_mut(&low_addr).unwrap().score = 50;

        let targets = actor.relay_targets(&key, RelayMessageClass::Vote, sender);
        assert_eq!(targets, vec![high_score]);
    }

    #[tokio::test]
    async fn relay_metrics_track_relay_drop_duplicate_and_verification_failure() {
        let sender = Bytes32::from([0x90; 32]);
        let receiver = Bytes32::from([0x91; 32]);
        let keypair = hybrid_key(0x90);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        install_relay_keys(&mut actor, vec![relay_key(sender, &keypair)]);
        let mut receiver_rx = add_test_peer(&mut actor, receiver, 34091);
        let msg = Message::Vote(signed_vote(sender, &keypair));

        actor.relay_if_eligible(sender, &msg).await;
        assert!(receiver_rx.try_recv().is_ok());
        actor.relay_if_eligible(sender, &msg).await;
        assert_eq!(actor.relay_metrics[&RelayMessageClass::Vote].relayed, 1);
        assert_eq!(actor.relay_metrics[&RelayMessageClass::Vote].duplicate, 1);

        let invalid_sender = Bytes32::from([0x92; 32]);
        let invalid_keypair = hybrid_key(0x92);
        let invalid_msg = Message::Vote(signed_vote(invalid_sender, &invalid_keypair));
        actor.relay_if_eligible(invalid_sender, &invalid_msg).await;
        assert_eq!(
            actor.relay_metrics[&RelayMessageClass::Vote].verification_failed,
            1
        );

        let no_target_sender = Bytes32::from([0x93; 32]);
        let no_target_keypair = hybrid_key(0x93);
        install_relay_keys(
            &mut actor,
            vec![relay_key(no_target_sender, &no_target_keypair)],
        );
        actor.peers_by_validator.clear();
        let no_target_msg = Message::Vote(signed_vote(no_target_sender, &no_target_keypair));
        actor
            .relay_if_eligible(no_target_sender, &no_target_msg)
            .await;
        assert_eq!(actor.relay_metrics[&RelayMessageClass::Vote].dropped, 1);
    }

    #[tokio::test]
    async fn relay_forwarded_marked_only_after_successful_enqueue() {
        let sender = Bytes32::from([0xA0; 32]);
        let successful_peer = Bytes32::from([0xA1; 32]);
        let full_peer = Bytes32::from([0xA2; 32]);
        let keypair = hybrid_key(0xA0);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        let mut successful_rx = add_test_peer(&mut actor, successful_peer, 34101);
        let (mut full_rx, _large_rx) =
            add_test_peer_receivers_with_capacity(&mut actor, full_peer, 34102, 1, 1);
        let msg = Message::Vote(signed_vote(sender, &keypair));
        let key = relay_message_key(&msg).expect("vote should have relay key");

        actor
            .peers_by_validator
            .get(&full_peer)
            .unwrap()
            .small_tx
            .try_send(OutboundMessage {
                msg: Message::Ping(123),
                point_to_point: false,
            })
            .expect("test prefill should occupy the one-slot queue");

        actor
            .handle_command(NetworkCommand::Broadcast(msg.clone()))
            .await;

        assert!(successful_rx.try_recv().is_ok());
        assert!(
            actor.relay_seen.forwarded_to(&key, &successful_peer),
            "successful enqueue should be marked forwarded"
        );
        assert!(
            !actor.relay_seen.forwarded_to(&key, &full_peer),
            "queue-full peer must not be marked forwarded"
        );
        assert_eq!(actor.relay_metrics[&RelayMessageClass::Vote].queue_full, 1);
        assert!(matches!(
            full_rx
                .try_recv()
                .expect("prefill should remain queued")
                .msg,
            Message::Ping(123)
        ));
    }

    #[tokio::test]
    async fn relay_recovers_delivery_to_previously_failed_peer() {
        let origin = Bytes32::from([0xB0; 32]);
        let echoing_peer = Bytes32::from([0xB1; 32]);
        let missed_peer = Bytes32::from([0xB2; 32]);
        let keypair = hybrid_key(0xB0);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        let mut echoing_rx = add_test_peer(&mut actor, echoing_peer, 34111);
        let (mut missed_rx, _large_rx) =
            add_test_peer_receivers_with_capacity(&mut actor, missed_peer, 34112, 1, 1);
        let msg = Message::Vote(signed_vote(origin, &keypair));

        actor
            .peers_by_validator
            .get(&missed_peer)
            .unwrap()
            .small_tx
            .try_send(OutboundMessage {
                msg: Message::Ping(456),
                point_to_point: false,
            })
            .expect("test prefill should occupy the one-slot queue");

        actor
            .handle_command(NetworkCommand::Broadcast(msg.clone()))
            .await;
        assert!(echoing_rx.try_recv().is_ok());
        assert!(matches!(
            missed_rx.try_recv().expect("clear prefilled queue").msg,
            Message::Ping(456)
        ));

        actor.relay_if_eligible(echoing_peer, &msg).await;

        assert!(matches!(
            missed_rx
                .try_recv()
                .expect("relay should recover the missed peer")
                .msg,
            Message::Vote(_)
        ));
    }

    #[tokio::test]
    async fn queue_full_drop_is_counted_by_message_class() {
        let peer = Bytes32::from([0xA3; 32]);
        let sender = Bytes32::from([0xA4; 32]);
        let keypair = hybrid_key(0xA4);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        let (mut peer_rx, _large_rx) =
            add_test_peer_receivers_with_capacity(&mut actor, peer, 34103, 1, 1);
        let msg = Message::Vote(signed_vote(sender, &keypair));

        actor
            .peers_by_validator
            .get(&peer)
            .unwrap()
            .small_tx
            .try_send(OutboundMessage {
                msg: Message::Ping(789),
                point_to_point: false,
            })
            .expect("test prefill should occupy the one-slot queue");

        actor
            .handle_command(NetworkCommand::Broadcast(msg.clone()))
            .await;

        assert_eq!(actor.relay_metrics[&RelayMessageClass::Vote].queue_full, 1);
        let key = relay_message_key(&msg).expect("vote should have relay key");
        assert!(
            !actor.relay_seen.forwarded_to(&key, &peer),
            "queue-full vote delivery must not be marked forwarded"
        );
        assert!(matches!(
            peer_rx
                .try_recv()
                .expect("prefill should remain queued")
                .msg,
            Message::Ping(789)
        ));
    }

    #[tokio::test]
    async fn node_originated_broadcast_marks_seen_before_echo() {
        let sender = Bytes32::from([0x80; 32]);
        let peer = Bytes32::from([0x81; 32]);
        let keypair = hybrid_key(0x80);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        install_relay_keys(&mut actor, vec![relay_key(sender, &keypair)]);
        let mut peer_rx = add_test_peer(&mut actor, peer, 34081);
        let msg = Message::Vote(signed_vote(sender, &keypair));

        actor
            .handle_command(NetworkCommand::Broadcast(msg.clone()))
            .await;
        assert!(
            peer_rx.try_recv().is_ok(),
            "origin broadcast should send once"
        );
        actor.relay_if_eligible(peer, &msg).await;
        assert!(
            peer_rx.try_recv().is_err(),
            "echoed message must not be relay-forwarded after origin broadcast marked it seen"
        );
    }

    #[tokio::test]
    async fn fanout_recomputed_at_epoch_transition_not_per_message() {
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        let keys_20 = (0..20u8)
            .map(|i| {
                let id = Bytes32::from([i; 32]);
                relay_key(id, &hybrid_key(i.saturating_add(1)))
            })
            .collect::<Vec<_>>();
        let keys_200 = (0..200u16)
            .map(|i| {
                let mut id_bytes = [0u8; 32];
                id_bytes[..2].copy_from_slice(&i.to_le_bytes());
                let id = Bytes32::from(id_bytes);
                relay_key(id, &hybrid_key((i as u8).wrapping_add(1)))
            })
            .collect::<Vec<_>>();

        actor
            .handle_command(NetworkCommand::UpdateRelayValidatorKeys {
                chain_id: "indra-testnet-1".to_string(),
                validators: keys_20,
            })
            .await;
        assert_eq!(actor.relay_fanout, 8);
        let unchanged = relay_fanout_for_class(actor.relay_fanout, RelayMessageClass::Vote);
        assert_eq!(
            unchanged, 8,
            "message-class lookup must not recompute epoch fanout"
        );

        actor
            .handle_command(NetworkCommand::UpdateRelayValidatorKeys {
                chain_id: "indra-testnet-1".to_string(),
                validators: keys_200,
            })
            .await;
        assert_eq!(actor.relay_fanout, 13);
    }

    #[tokio::test]
    async fn relay_forwards_vote_to_fanout_excluding_sender() {
        let sender = Bytes32::from([0x10; 32]);
        let receiver = Bytes32::from([0x11; 32]);
        let keypair = hybrid_key(0x10);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        actor.relay_fanout = 4;
        install_relay_keys(&mut actor, vec![relay_key(sender, &keypair)]);
        let mut sender_rx = add_test_peer(&mut actor, sender, 34010);
        let mut receiver_rx = add_test_peer(&mut actor, receiver, 34011);
        let msg = Message::Vote(signed_vote(sender, &keypair));
        actor.relay_if_eligible(sender, &msg).await;
        assert!(
            sender_rx.try_recv().is_err(),
            "relay must exclude inbound sender"
        );
        assert!(matches!(
            receiver_rx.try_recv().unwrap().msg,
            Message::Vote(_)
        ));
    }

    #[tokio::test]
    async fn relay_verification_does_not_score_but_authoritative_outcomes_do() {
        let sender = Bytes32::from([0x12; 32]);
        let receiver = Bytes32::from([0x13; 32]);
        let keypair = hybrid_key(0x12);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        install_relay_keys(&mut actor, vec![relay_key(sender, &keypair)]);
        let _sender_rx = add_test_peer(&mut actor, sender, 34012);
        let _receiver_rx = add_test_peer(&mut actor, receiver, 34013);
        let addr = actor.peers_by_validator.get(&sender).unwrap().addr;
        let initial = actor.peer_table.get(&addr).unwrap().score;

        actor
            .relay_if_eligible(sender, &Message::Vote(signed_vote(sender, &keypair)))
            .await;
        assert_eq!(actor.peer_table.get(&addr).unwrap().score, initial);

        actor
            .score_validator(sender, ScoreEvent::ValidTx, BAN_DURATION)
            .await;
        actor
            .score_validator(sender, ScoreEvent::ValidVote, BAN_DURATION)
            .await;
        actor
            .score_validator(sender, ScoreEvent::ValidBlock, BAN_DURATION)
            .await;
        assert_eq!(actor.peer_table.get(&addr).unwrap().score, initial + 7);
        actor
            .score_validator(sender, ScoreEvent::InvalidMessage, BAN_DURATION)
            .await;
        assert_eq!(actor.peer_table.get(&addr).unwrap().score, initial - 3);
    }

    #[tokio::test]
    async fn relay_does_not_forward_duplicate_vote() {
        let sender = Bytes32::from([0x20; 32]);
        let receiver = Bytes32::from([0x21; 32]);
        let keypair = hybrid_key(0x20);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        install_relay_keys(&mut actor, vec![relay_key(sender, &keypair)]);
        let mut receiver_rx = add_test_peer(&mut actor, receiver, 34021);
        let msg = Message::Vote(signed_vote(sender, &keypair));
        actor.relay_if_eligible(sender, &msg).await;
        actor.relay_if_eligible(sender, &msg).await;
        assert!(receiver_rx.try_recv().is_ok());
        assert!(receiver_rx.try_recv().is_err());
        assert_eq!(actor.relay_metrics[&RelayMessageClass::Vote].duplicate, 1);
    }

    #[tokio::test]
    async fn pre_relay_signature_verification_rejects_invalid_signature() {
        let sender = Bytes32::from([0x30; 32]);
        let receiver = Bytes32::from([0x31; 32]);
        let keypair = hybrid_key(0x30);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        install_relay_keys(&mut actor, vec![relay_key(sender, &keypair)]);
        let mut receiver_rx = add_test_peer(&mut actor, receiver, 34031);
        let mut vote = signed_vote(sender, &keypair);
        vote.signature.classical_sig = VariableBytes::from_slice(&[0x42; 64]).unwrap();
        actor.relay_if_eligible(sender, &Message::Vote(vote)).await;
        assert!(receiver_rx.try_recv().is_err());
        assert_eq!(
            actor.relay_metrics[&RelayMessageClass::Vote].verification_failed,
            1
        );
    }

    #[tokio::test]
    async fn pre_relay_signature_verification_rejects_unregistered_validator() {
        let sender = Bytes32::from([0x40; 32]);
        let receiver = Bytes32::from([0x41; 32]);
        let keypair = hybrid_key(0x40);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        let mut receiver_rx = add_test_peer(&mut actor, receiver, 34041);
        actor
            .relay_if_eligible(sender, &Message::Vote(signed_vote(sender, &keypair)))
            .await;
        assert!(receiver_rx.try_recv().is_err());
        assert_eq!(
            actor.relay_metrics[&RelayMessageClass::Vote].verification_failed,
            1
        );
    }

    #[tokio::test]
    async fn pre_relay_slot_context_rejects_wrong_height_and_round() {
        let sender = Bytes32::from([0x50; 32]);
        let receiver = Bytes32::from([0x51; 32]);
        let keypair = hybrid_key(0x50);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        install_relay_keys(&mut actor, vec![relay_key(sender, &keypair)]);
        let mut receiver_rx = add_test_peer(&mut actor, receiver, 34051);
        actor
            .handle_command(NetworkCommand::UpdateRelayConsensusContext {
                height: 7,
                round: 2,
            })
            .await;

        for (height, round, hash) in [
            (7, 2, 0x52),
            (7, 0, 0x53),
            (7, 10, 0x54),
            (5, 2, 0x55),
            (8, 2, 0x56),
        ] {
            actor
                .relay_if_eligible(
                    sender,
                    &Message::Vote(signed_vote_at(
                        sender,
                        &keypair,
                        height,
                        round,
                        VoteStep::Prevote,
                        Bytes32::from([hash; 32]),
                    )),
                )
                .await;
        }
        for _ in 0..4 {
            assert!(receiver_rx.try_recv().is_ok());
        }
        assert!(receiver_rx.try_recv().is_err());
        assert_eq!(actor.relay_metrics[&RelayMessageClass::Vote].relayed, 4);
        assert_eq!(actor.relay_metrics[&RelayMessageClass::Vote].dropped, 1);
    }

    #[tokio::test]
    async fn distant_same_height_round_relay_is_verified_and_deduplicated() {
        let sender = Bytes32::from([0x57; 32]);
        let receiver = Bytes32::from([0x56; 32]);
        let keypair = hybrid_key(0x57);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        install_relay_keys(&mut actor, vec![relay_key(sender, &keypair)]);
        let mut receiver_rx = add_test_peer(&mut actor, receiver, 34057);
        actor
            .handle_command(NetworkCommand::UpdateRelayConsensusContext {
                height: 7,
                round: 0,
            })
            .await;
        let high_round = Message::Vote(signed_vote_at(
            sender,
            &keypair,
            7,
            20,
            VoteStep::Prevote,
            Bytes32::from([0x57; 32]),
        ));
        actor.relay_if_eligible(sender, &high_round).await;
        assert!(receiver_rx.try_recv().is_ok());

        let duplicate_high_round = Message::Vote(signed_vote_at(
            sender,
            &keypair,
            7,
            20,
            VoteStep::Precommit,
            Bytes32::from([0x58; 32]),
        ));
        actor
            .relay_if_eligible(sender, &duplicate_high_round)
            .await;
        assert!(receiver_rx.try_recv().is_err());
        assert_eq!(actor.relay_metrics[&RelayMessageClass::Vote].relayed, 1);
        assert_eq!(actor.relay_metrics[&RelayMessageClass::Vote].dropped, 1);
    }

    #[tokio::test]
    async fn out_of_window_honest_lag_is_relayed_without_scoring_or_blocking_catchup() {
        let sender = Bytes32::from([0x58; 32]);
        let receiver = Bytes32::from([0x59; 32]);
        let keypair = hybrid_key(0x58);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        install_relay_keys(&mut actor, vec![relay_key(sender, &keypair)]);
        let _sender_rx = add_test_peer(&mut actor, sender, 34058);
        let mut receiver_rx = add_test_peer(&mut actor, receiver, 34059);
        actor
            .handle_command(NetworkCommand::UpdateRelayConsensusContext {
                height: 100,
                round: 0,
            })
            .await;
        let addr = actor.peers_by_validator.get(&sender).unwrap().addr;

        // A restarted/syncing validator may still have votes from several old
        // heights in flight. They are validly signed, but not useful to this
        // relay slot.
        for (height, round, hash) in [
            (97, 0, 0x61), // three heights behind
            (80, 0, 0x62), // twenty heights behind
            (100, 9, 0x63), // distant same-height evidence after a stall
        ] {
            actor
                .relay_if_eligible(
                    sender,
                    &Message::Vote(signed_vote_at(
                        sender,
                        &keypair,
                        height,
                        round,
                        VoteStep::Prevote,
                        Bytes32::from([hash; 32]),
                    )),
                )
                .await;
        }

        assert_eq!(actor.relay_metrics[&RelayMessageClass::Vote].dropped, 2);
        assert_eq!(actor.relay_metrics[&RelayMessageClass::Vote].relayed, 1);
        assert_eq!(actor.relay_metrics[&RelayMessageClass::Vote].verification_failed, 0);
        assert_eq!(actor.peer_table.get(&addr).unwrap().score, INITIAL_SCORE);
        assert_eq!(actor.peer_table.get(&addr).unwrap().status, PeerStatus::Connected);
        assert!(receiver_rx.try_recv().is_ok());

        // The same authenticated peer can immediately deliver a current-slot
        // vote, which represents the relay/sync path remaining usable.
        actor
            .relay_if_eligible(
                sender,
                &Message::Vote(signed_vote_at(
                    sender,
                    &keypair,
                    100,
                    0,
                    VoteStep::Prevote,
                    Bytes32::from([0x64; 32]),
                )),
            )
            .await;
        assert!(receiver_rx.try_recv().is_ok());
        assert_eq!(actor.relay_metrics[&RelayMessageClass::Vote].relayed, 2);
    }

    #[tokio::test]
    async fn ten_thousand_out_of_window_votes_are_rejected_before_verification() {
        let sender = Bytes32::from([0x5A; 32]);
        let receiver = Bytes32::from([0x5B; 32]);
        let keypair = hybrid_key(0x5A);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        install_relay_keys(&mut actor, vec![relay_key(sender, &keypair)]);
        let _sender_rx = add_test_peer(&mut actor, sender, 34060);
        let _receiver_rx = add_test_peer(&mut actor, receiver, 34061);
        actor
            .handle_command(NetworkCommand::UpdateRelayConsensusContext {
                height: 100,
                round: 0,
            })
            .await;
        let addr = actor.peers_by_validator.get(&sender).unwrap().addr;

        let signed_template = signed_vote_at(
            sender,
            &keypair,
            80,
            0,
            VoteStep::Prevote,
            Bytes32::ZERO,
        );
        for index in 0u64..10_000 {
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&index.to_le_bytes());
            let mut vote = signed_template.clone();
            vote.block_hash = Bytes32::from(hash);
            actor
                .relay_if_eligible(
                    sender,
                    &Message::Vote(vote),
                )
                .await;
        }

        let metrics = actor.relay_metrics[&RelayMessageClass::Vote];
        assert_eq!(metrics.dropped, 10_000);
        assert_eq!(metrics.verification_failed, 0);
        assert_eq!(actor.peer_table.get(&addr).unwrap().score, INITIAL_SCORE);
        assert_eq!(actor.peer_table.get(&addr).unwrap().status, PeerStatus::Connected);
    }

    #[test]
    fn block_relay_verifies_embedded_proposer_vrf_not_election_authority() {
        let validator_id = Bytes32::from([0x60; 32]);
        let vrf = VrfKeypair::from_seed(&validator_id.0);
        let prev_hash = Bytes32::from([0x61; 32]);
        let keypair = hybrid_key(0x60);
        let block = relay_test_block(validator_id, &vrf, &keypair, 9, 3, prev_hash, Bytes32::ZERO);
        let mut key = relay_key(validator_id, &keypair);
        key.vrf_pk = Some(vrf.public_key());
        let mut keys = HashMap::new();
        keys.insert(validator_id, key);
        assert_eq!(block_relay_validator_id(&block, &keys), Some(validator_id));
    }

    #[tokio::test]
    async fn block_relay_blocks_second_conflicting_block_same_slot() {
        let validator_id = Bytes32::from([0xA0; 32]);
        let receiver = Bytes32::from([0xA1; 32]);
        let vrf = VrfKeypair::from_seed(&validator_id.0);
        let prev_hash = Bytes32::from([0xA2; 32]);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        let keypair = hybrid_key(0xA0);
        let mut key = relay_key(validator_id, &keypair);
        key.vrf_pk = Some(vrf.public_key());
        install_relay_keys(&mut actor, vec![key]);
        let mut receiver_rx = add_test_peer_large(&mut actor, receiver, 34101);

        let block_a = Message::Block(Box::new(relay_test_block(
            validator_id,
            &vrf,
            &keypair,
            11,
            2,
            prev_hash,
            Bytes32::from([0x01; 32]),
        )));
        let block_b = Message::Block(Box::new(relay_test_block(
            validator_id,
            &vrf,
            &keypair,
            11,
            2,
            prev_hash,
            Bytes32::from([0x02; 32]),
        )));
        actor.relay_if_eligible(validator_id, &block_a).await;
        actor.relay_if_eligible(validator_id, &block_b).await;

        assert!(matches!(
            receiver_rx.try_recv().unwrap().msg,
            Message::Block(_)
        ));
        assert!(
            receiver_rx.try_recv().is_err(),
            "conflicting second block for same proposer slot must not relay"
        );
        assert_eq!(actor.relay_metrics[&RelayMessageClass::Block].relayed, 1);
        assert_eq!(actor.relay_metrics[&RelayMessageClass::Block].dropped, 1);
    }

    #[tokio::test]
    async fn block_relay_allows_legitimate_reproposal_different_round() {
        let validator_id = Bytes32::from([0xB0; 32]);
        let receiver = Bytes32::from([0xB1; 32]);
        let vrf = VrfKeypair::from_seed(&validator_id.0);
        let prev_hash = Bytes32::from([0xB2; 32]);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        let keypair = hybrid_key(0xB0);
        let mut key = relay_key(validator_id, &keypair);
        key.vrf_pk = Some(vrf.public_key());
        install_relay_keys(&mut actor, vec![key]);
        let mut receiver_rx = add_test_peer_large(&mut actor, receiver, 34111);

        let block_round_2 = Message::Block(Box::new(relay_test_block(
            validator_id,
            &vrf,
            &keypair,
            11,
            2,
            prev_hash,
            Bytes32::from([0x03; 32]),
        )));
        let block_round_3 = Message::Block(Box::new(relay_test_block(
            validator_id,
            &vrf,
            &keypair,
            11,
            3,
            prev_hash,
            Bytes32::from([0x04; 32]),
        )));
        actor.relay_if_eligible(validator_id, &block_round_2).await;
        actor.relay_if_eligible(validator_id, &block_round_3).await;

        assert!(receiver_rx.try_recv().is_ok());
        assert!(receiver_rx.try_recv().is_ok());
        assert_eq!(actor.relay_metrics[&RelayMessageClass::Block].relayed, 2);
        assert_eq!(actor.relay_metrics[&RelayMessageClass::Block].dropped, 0);
    }

    #[tokio::test]
    async fn block_relay_single_non_conflicting_block_still_relays() {
        let validator_id = Bytes32::from([0xC0; 32]);
        let receiver = Bytes32::from([0xC1; 32]);
        let vrf = VrfKeypair::from_seed(&validator_id.0);
        let prev_hash = Bytes32::from([0xC2; 32]);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        let keypair = hybrid_key(0xC0);
        let mut key = relay_key(validator_id, &keypair);
        key.vrf_pk = Some(vrf.public_key());
        install_relay_keys(&mut actor, vec![key]);
        let mut receiver_rx = add_test_peer_large(&mut actor, receiver, 34121);

        let block = Message::Block(Box::new(relay_test_block(
            validator_id,
            &vrf,
            &keypair,
            12,
            0,
            prev_hash,
            Bytes32::from([0x05; 32]),
        )));
        actor.relay_if_eligible(validator_id, &block).await;

        assert!(matches!(
            receiver_rx.try_recv().unwrap().msg,
            Message::Block(_)
        ));
        assert_eq!(actor.relay_metrics[&RelayMessageClass::Block].relayed, 1);
    }

    #[test]
    fn relay_does_not_forward_request_or_response_messages() {
        assert!(relay_message_class(&Message::RequestQC { height: 7 }).is_none());
        assert!(
            relay_message_class(&Message::QCResponse {
                height: 7,
                qc_bytes: vec![]
            })
            .is_none()
        );
    }

    type RelayInbox = (
        mpsc::Receiver<OutboundMessage>,
        mpsc::Receiver<OutboundMessage>,
    );

    fn drain_relay_outbox(
        node: usize,
        inboxes: &mut [HashMap<usize, RelayInbox>],
        queue: &mut VecDeque<(usize, usize, Message)>,
    ) {
        for (peer, (small_receiver, large_receiver)) in &mut inboxes[node] {
            while let Ok(outbound) = small_receiver.try_recv() {
                queue.push_back((node, *peer, outbound.msg));
            }
            while let Ok(outbound) = large_receiver.try_recv() {
                queue.push_back((node, *peer, outbound.msg));
            }
        }
    }

    async fn relay_through_topology(
        graph: &[&[usize]],
        messages: Vec<(usize, Message)>,
    ) -> (HashSet<usize>, usize) {
        relay_through_topology_with_contexts(graph, messages, [None; 4]).await
    }

    async fn relay_through_topology_with_contexts(
        graph: &[&[usize]],
        messages: Vec<(usize, Message)>,
        contexts: [Option<(u64, u32)>; 4],
    ) -> (HashSet<usize>, usize) {
        let keys = (0..4u8)
            .map(|seed| {
                let id = Bytes32::from([seed.saturating_add(1); 32]);
                (id, hybrid_key(seed.saturating_add(1)))
            })
            .collect::<Vec<_>>();
        let relay_keys = keys
            .iter()
            .map(|(id, keypair)| relay_key(*id, keypair))
            .collect::<Vec<_>>();
        let (event_tx, _event_rx) = mpsc::channel(32);
        let mut actors = (0..4)
            .map(|index| test_actor(event_tx.clone(), Bytes32::from([index as u8 + 1; 32])))
            .collect::<Vec<_>>();
        let mut inboxes = (0..4)
            .map(|_| HashMap::<usize, RelayInbox>::new())
            .collect::<Vec<_>>();
        for (node, peers) in graph.iter().enumerate() {
            actors[node].relay_consensus_context = contexts[node];
            for peer in *peers {
                let receivers = add_test_peer_receivers(
                    &mut actors[node],
                    Bytes32::from([*peer as u8 + 1; 32]),
                    34200 + (node * 10 + *peer) as u16,
                );
                inboxes[node].insert(*peer, receivers);
            }
            install_relay_keys(&mut actors[node], relay_keys.clone());
        }

        let mut reached = HashSet::new();
        let mut queue = VecDeque::new();
        for (origin, message) in messages {
            reached.insert(origin);
            actors[origin]
                .handle_command(NetworkCommand::Broadcast(message))
                .await;
            drain_relay_outbox(origin, &mut inboxes, &mut queue);
            assert!(!queue.is_empty(), "origin broadcast must enqueue a neighbor delivery");
        }
        let mut deliveries = 0usize;
        while let Some((sender, receiver, message)) = queue.pop_front() {
            deliveries += 1;
            assert!(
                deliveries <= 64,
                "relay graph must terminate with bounded deliveries"
            );
            reached.insert(receiver);
            actors[receiver]
                .relay_if_eligible(Bytes32::from([sender as u8 + 1; 32]), &message)
                .await;
            drain_relay_outbox(receiver, &mut inboxes, &mut queue);
        }
        (reached, deliveries)
    }

    #[tokio::test]
    async fn relay_timing_skew_bridges_adjacent_slots_but_not_garbage() {
        let line = [&[1][..], &[0, 2][..], &[1, 3][..], &[2][..]];
        let sender = Bytes32::from([1; 32]);
        let keypair = hybrid_key(1);
        let round_ahead = Message::Vote(signed_vote_at(
            sender,
            &keypair,
            7,
            3,
            VoteStep::Prevote,
            Bytes32::from([0xA7; 32]),
        ));
        let next_height = Message::Vote(signed_vote_at(
            sender,
            &keypair,
            8,
            2,
            VoteStep::Prevote,
            Bytes32::from([0xA8; 32]),
        ));
        let far_round = Message::Vote(signed_vote_at(
            sender,
            &keypair,
            7,
            11,
            VoteStep::Prevote,
            Bytes32::from([0xAF; 32]),
        ));
        let (reached, deliveries) = relay_through_topology_with_contexts(
            &line,
            vec![(0, round_ahead), (0, next_height), (0, far_round)],
            [Some((7, 2)), Some((7, 2)), Some((7, 2)), Some((7, 2))],
        )
        .await;
        assert_eq!(reached.len(), 4, "bounded skew messages must reach endpoint");
        assert!(deliveries < 20, "far-slot flood must not amplify");
    }

    #[tokio::test]
    async fn relay_reaches_all_nodes_through_line_star_and_ring() {
        let line = [&[1][..], &[0, 2][..], &[1, 3][..], &[2][..]];
        let star = [&[1, 2, 3][..], &[0][..], &[0][..], &[0][..]];
        let ring = [&[1, 3][..], &[0, 2][..], &[1, 3][..], &[2, 0][..]];

        for (name, graph) in [("line", line), ("star", star), ("ring", ring)] {
            let messages = (0..5u64)
                .map(|height| {
                    let origin = 0usize;
                    let keypair = hybrid_key(origin as u8 + 1);
                    let validator_id = Bytes32::from([origin as u8 + 1; 32]);
                    let message = if height == 0 {
                        let vrf = VrfKeypair::from_seed(&validator_id.0);
                        Message::Block(Box::new(relay_test_block(
                            validator_id,
                            &vrf,
                            &keypair,
                            1,
                            0,
                            Bytes32::ZERO,
                            Bytes32::from([0xA1; 32]),
                        )))
                    } else {
                        Message::Vote(signed_vote_at(
                            validator_id,
                            &keypair,
                            height + 1,
                            height as u32,
                            VoteStep::Prevote,
                            Bytes32::from([(height + 1) as u8; 32]),
                        ))
                    };
                    (
                        origin,
                        message,
                    )
                })
                .collect();
            let (reached, deliveries) = relay_through_topology(&graph, messages).await;
            assert_eq!(reached.len(), 4, "{name} topology must reach every validator");
            assert!(deliveries <= 40, "{name} topology relay count must stay bounded");
        }
    }

    #[tokio::test]
    async fn relay_bounds_duplicate_and_conflicting_messages() {
        let graph = [&[1, 3][..], &[0, 2][..], &[1, 3][..], &[2, 0][..]];
        let sender = Bytes32::from([1; 32]);
        let keypair = hybrid_key(1);
        let message = Message::Vote(signed_vote_at(
            sender,
            &keypair,
            9,
            0,
            VoteStep::Prevote,
            Bytes32::from([0x91; 32]),
        ));
        let (reached, deliveries) = relay_through_topology(
            &graph,
            vec![(0, message.clone()), (0, message)],
        )
        .await;
        assert_eq!(reached.len(), 4);
        assert!(deliveries <= 16, "duplicate ring delivery must be deduplicated");
    }

    const SIM_VALIDATORS_N200: usize = 200;
    const SIM_TARGET_OUTBOUND: usize = 8;
    const SIM_MAX_INBOUND: usize = 64;
    fn sim_rendezvous_candidates(
        node: usize,
        candidates: impl Iterator<Item = usize>,
    ) -> Vec<usize> {
        let mut ordered = candidates
            .filter(|candidate| *candidate != node)
            .map(|candidate| {
                let mut seed = Vec::with_capacity(4);
                seed.extend_from_slice(&(node as u16).to_le_bytes());
                seed.extend_from_slice(&(candidate as u16).to_le_bytes());
                let digest = sha256(&seed);
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

    fn sim_connect_outbound(
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

    fn sim_build_random_bounded_graph(
        n: usize,
        target_outbound: usize,
        max_inbound: usize,
    ) -> (Vec<HashSet<usize>>, Vec<usize>) {
        let mut graph = vec![HashSet::<usize>::new(); n];
        let mut inbound_counts = vec![0usize; n];
        for node in 0..n {
            sim_connect_outbound(
                &mut graph,
                &mut inbound_counts,
                node,
                sim_rendezvous_candidates(node, 0..n),
                target_outbound,
                max_inbound,
            );
        }
        (graph, inbound_counts)
    }

    fn sim_build_bootstrap_first_graph(
        n: usize,
        target_outbound: usize,
        max_inbound: usize,
    ) -> (Vec<HashSet<usize>>, Vec<usize>) {
        let bootstrap = 0usize;
        let mut graph = vec![HashSet::<usize>::new(); n];
        let mut inbound_counts = vec![0usize; n];

        // Initial deployment shape: every non-bootstrap validator tries the
        // configured bootstrap peer first. The bootstrap is capped, then
        // peer-list gossip lets validators fill the remaining outbound set.
        for node in 1..n {
            sim_connect_outbound(
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
            candidates.extend(sim_rendezvous_candidates(node, 0..n));
            sim_connect_outbound(
                &mut graph,
                &mut inbound_counts,
                node,
                candidates,
                target_outbound,
                max_inbound,
            );
        }

        (graph, inbound_counts)
    }

    fn sim_relay_targets(
        graph: &[HashSet<usize>],
        node: usize,
        origin: usize,
        fanout: usize,
    ) -> Vec<usize> {
        let mut neighbors = graph[node]
            .iter()
            .copied()
            .map(|peer| {
                let mut seed = Vec::with_capacity(6);
                seed.extend_from_slice(&(origin as u16).to_le_bytes());
                seed.extend_from_slice(&(node as u16).to_le_bytes());
                seed.extend_from_slice(&(peer as u16).to_le_bytes());
                let digest = sha256(&seed);
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

    fn sim_build_relay_targets(graph: &[HashSet<usize>], fanout: usize) -> Vec<Vec<Vec<usize>>> {
        (0..graph.len())
            .map(|origin| {
                (0..graph.len())
                    .map(|node| sim_relay_targets(graph, node, origin, fanout))
                    .collect()
            })
            .collect()
    }

    fn sim_reached_after_hops(relay_targets: &[Vec<Vec<usize>>], max_hops: usize) -> usize {
        let mut reached = HashSet::new();
        let mut frontier = VecDeque::new();
        reached.insert(0usize);
        frontier.push_back(0usize);
        for _ in 0..max_hops {
            let level = frontier.len();
            for _ in 0..level {
                let node = frontier.pop_front().unwrap();
                for peer in relay_targets[0][node].iter().copied() {
                    if reached.insert(peer) {
                        frontier.push_back(peer);
                    }
                }
            }
        }
        reached.len()
    }

    #[test]
    fn partial_mesh_propagates_to_quorum_at_n200_realistic_topology() {
        let n = SIM_VALIDATORS_N200;
        let fanout = derive_consensus_relay_fanout(n);

        let (random_graph, random_inbound_counts) =
            sim_build_random_bounded_graph(n, SIM_TARGET_OUTBOUND, SIM_MAX_INBOUND);
        let (hub_graph, hub_inbound_counts) =
            sim_build_bootstrap_first_graph(n, SIM_TARGET_OUTBOUND, SIM_MAX_INBOUND);
        let random_relay_targets = sim_build_relay_targets(&random_graph, fanout);
        let hub_relay_targets = sim_build_relay_targets(&hub_graph, fanout);

        let random_base_two_hops = sim_reached_after_hops(&random_relay_targets, 2);
        let random_base_three_hops = sim_reached_after_hops(&random_relay_targets, 3);
        let hub_base_two_hops = sim_reached_after_hops(&hub_relay_targets, 2);
        let hub_base_three_hops = sim_reached_after_hops(&hub_relay_targets, 3);
        eprintln!(
            "[relay-sim] random bounded graph: base fanout reached {random_base_two_hops}/200 in 2 hops, {random_base_three_hops}/200 in 3 hops"
        );
        eprintln!(
            "[relay-sim] bootstrap-first graph: base fanout reached {hub_base_two_hops}/200 in 2 hops, {hub_base_three_hops}/200 in 3 hops"
        );
        assert!(
            random_base_three_hops >= 134,
            "random bounded graph base fanout {fanout} should reach quorum in <=3 hops, reached {random_base_three_hops}"
        );
        assert!(
            hub_base_three_hops >= 134,
            "bootstrap-first graph base fanout {fanout} should reach quorum in <=3 hops, reached {hub_base_three_hops}"
        );

        let block_fanout = relay_fanout_for_class(fanout, RelayMessageClass::Block);
        let random_block_relay_targets = sim_build_relay_targets(&random_graph, block_fanout);
        let hub_block_relay_targets = sim_build_relay_targets(&hub_graph, block_fanout);
        let random_block_two_hops = sim_reached_after_hops(&random_block_relay_targets, 2);
        let hub_block_two_hops = sim_reached_after_hops(&hub_block_relay_targets, 2);
        eprintln!(
            "[relay-sim] random bounded graph: block fanout reached {random_block_two_hops}/200 in 2 hops"
        );
        eprintln!(
            "[relay-sim] bootstrap-first graph: block fanout reached {hub_block_two_hops}/200 in 2 hops"
        );
        assert!(
            random_block_two_hops >= random_base_two_hops,
            "block fanout multiplier must not propagate worse than base fanout on random graph"
        );
        assert!(
            hub_block_two_hops >= hub_base_two_hops,
            "block fanout multiplier must not propagate worse than base fanout on bootstrap-first graph"
        );
        assert!(
            hub_block_two_hops >= 134,
            "bootstrap-first block relay fanout {block_fanout} should reach quorum in <=2 hops, reached {hub_block_two_hops}"
        );
        assert!(
            random_graph
                .iter()
                .chain(hub_graph.iter())
                .all(|neighbors| neighbors.len() < n / 2),
            "simulation must remain partial mesh, not accidentally full mesh"
        );
        assert!(
            random_inbound_counts
                .iter()
                .chain(hub_inbound_counts.iter())
                .all(|count| *count <= SIM_MAX_INBOUND),
            "simulation must honor inbound cap"
        );
    }

    #[test]
    #[ignore = "release-mode relay verification timing; run explicitly with --ignored --nocapture"]
    fn bench_pre_relay_verification_cost_n200() {
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        let mut keys = Vec::with_capacity(200);
        let mut messages = Vec::with_capacity(400);

        for i in 0..200u16 {
            let mut id_bytes = [0u8; 32];
            id_bytes[..2].copy_from_slice(&i.to_le_bytes());
            let validator_id = Bytes32::from(id_bytes);
            let keypair = hybrid_key((i as u8).wrapping_add(1));
            keys.push(relay_key(validator_id, &keypair));
            messages.push(Message::Vote(signed_vote(validator_id, &keypair)));
            messages.push(Message::Vote(signed_vote(validator_id, &keypair)));
        }

        install_relay_keys(&mut actor, keys);
        let start = Instant::now();
        for msg in &messages {
            assert!(actor.relay_verification_passes(msg));
        }
        let elapsed = start.elapsed();
        let per_us = elapsed.as_micros() as f64 / messages.len() as f64;
        eprintln!(
            "[bench] pre-relay hybrid verification: {} msgs in {}ms ({:.1}µs/msg)",
            messages.len(),
            elapsed.as_millis(),
            per_us
        );
        assert!(
            elapsed.as_millis() < indra_core::types::primitives::MIN_ROUND_TIME_MS as u128,
            "800 pre-relay verifications took {}ms, exceeding MIN_ROUND_TIME_MS",
            elapsed.as_millis()
        );
    }

    #[test]
    fn status_coalescer_drops_burst_within_window() {
        let mut coalescer = StatusCoalescer::new(Duration::from_millis(500));
        let now = Instant::now();
        let status_a = Message::Status {
            height: 1,
            tip_hash: Bytes32::from([0x01; 32]),
            round: 0,
        };
        let status_b = Message::Status {
            height: 2,
            tip_hash: Bytes32::from([0x02; 32]),
            round: 1,
        };
        assert!(!coalescer.should_drop(&status_a, now));
        assert!(coalescer.should_drop(&status_b, now + Duration::from_millis(100)));
        assert!(!coalescer.should_drop(&status_b, now + Duration::from_millis(600)));
    }

    #[tokio::test]
    async fn authenticated_validator_status_burst_does_not_trigger_penalty() {
        let validator = Bytes32::from([0xAA; 32]);
        let addr: SocketAddr = "127.0.0.1:32003".parse().unwrap();
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        let _receivers = add_test_peer_receivers(&mut actor, validator, 32003);
        let before = actor.peer_table.get(&addr).unwrap().score;

        actor
            .handle_rate_limit_violation(
                validator,
                addr,
                RateLimitViolationInfo {
                    class: MessageClass::Status,
                    penalty: 10,
                    reason: RateLimitReason::Count,
                },
            )
            .await;

        assert_eq!(actor.peer_table.get(&addr).unwrap().score, before);
        assert!(!actor.peer_table.get(&addr).unwrap().is_banned());
    }

    #[tokio::test]
    async fn authenticated_validator_block_request_burst_does_not_ban() {
        let validator = Bytes32::from([0xAB; 32]);
        let addr: SocketAddr = "127.0.0.1:32002".parse().unwrap();
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        actor.peer_table.add(addr).unwrap();
        actor.peer_table.set_validator_id(&addr, validator);
        actor.peer_table.mark_connected(&addr);
        let before = actor.peer_table.get(&addr).unwrap().score;

        for _ in 0..20 {
            actor
                .handle_rate_limit_violation(
                    validator,
                    addr,
                    RateLimitViolationInfo {
                        class: MessageClass::BlockRequest,
                        penalty: 10,
                        reason: RateLimitReason::Count,
                    },
                )
                .await;
        }

        assert_eq!(actor.peer_table.get(&addr).unwrap().score, before);
        assert!(!actor.peer_table.get(&addr).unwrap().is_banned());
    }

    #[tokio::test]
    async fn authenticated_validator_consensus_byte_overage_is_non_punitive() {
        let validator = Bytes32::from([0xAC; 32]);
        let addr: SocketAddr = "127.0.0.1:32003".parse().unwrap();
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        let _receivers = add_test_peer_receivers(&mut actor, validator, 32003);
        let before = actor.peer_table.get(&addr).unwrap().score;

        actor
            .handle_rate_limit_violation(
                validator,
                addr,
                RateLimitViolationInfo {
                    class: MessageClass::BlockResponse,
                    penalty: 10,
                    reason: RateLimitReason::Byte,
                },
            )
            .await;

        assert_eq!(actor.peer_table.get(&addr).unwrap().score, before);
    }

    #[test]
    fn rate_limit_log_includes_message_class() {
        let validator = Bytes32::from([0xAD; 32]);
        let addr: SocketAddr = "127.0.0.1:32004".parse().unwrap();
        let line = format_rate_limit_log(
            addr,
            validator,
            RateLimitViolationInfo {
                class: MessageClass::PingPong,
                penalty: 5,
                reason: RateLimitReason::Count,
            },
        );
        assert!(line.contains("PingPong"));
        assert!(line.contains("penalty=-5"));
    }

    #[tokio::test]
    async fn test_stale_disconnect_preserves_replacement() {
        let local = Bytes32::from([0x01; 32]);
        let peer = Bytes32::from([0x02; 32]);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, local);

        let addr_old: SocketAddr = "127.0.0.1:31001".parse().unwrap();
        let addr_new: SocketAddr = "127.0.0.1:31002".parse().unwrap();
        let ((old_hs, _old_keepalive), (new_hs, _new_keepalive)) =
            tokio::join!(handshake_result(peer, false), handshake_result(peer, true),);

        actor.register_peer(addr_old, old_hs).await;
        actor.register_peer(addr_new, new_hs).await;
        let before = actor.connected_peers.load(Ordering::Relaxed);
        actor
            .drop_peer(peer, addr_old, PeerDisconnectReason::DuplicateConnection)
            .await;

        assert_eq!(actor.connected_peers.load(Ordering::Relaxed), before);
        assert_eq!(actor.peers_by_validator.get(&peer).unwrap().addr, addr_new);
        assert!(!actor.validator_by_addr.contains_key(&addr_old));
        assert_eq!(actor.validator_by_addr.get(&addr_new), Some(&peer));

        let mut disconnected = 0;
        while let Ok(event) = event_rx.try_recv() {
            if matches!(event, NetworkEvent::PeerDisconnected { .. }) {
                disconnected += 1;
            }
        }
        assert_eq!(disconnected, 1);
    }

    #[tokio::test]
    async fn test_send_to_unknown_validator() {
        let local = Bytes32::from([0x01; 32]);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, local);
        actor
            .handle_command(NetworkCommand::SendTo {
                validator_id: Bytes32::from([0xFF; 32]),
                msg: Message::Ping(1),
            })
            .await;
        assert_eq!(actor.connected_peers.load(Ordering::Relaxed), 0);
        assert!(actor.peers_by_validator.is_empty());
    }
}
