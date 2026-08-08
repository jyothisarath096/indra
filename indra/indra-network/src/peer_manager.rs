//! Async peer-manager actor for the authenticated Tokio transport.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use tokio::{
    sync::{mpsc, Mutex},
    task::JoinHandle,
};

use indra_core::types::{
    block::BlockV1, primitives::Bytes32, slash_detector::SlashDetector, slashing::SlashEvidenceV1,
    vote_signing::vote_signing_bytes,
};
use indra_core::{codec::Encode, ssz::sha256};
use indra_crypto::{
    verify_hybrid, vrf_verify, ClassicalPublicKey, HybridPublicKey, PqPublicKey, VrfOutput,
    VrfProof, PQ_PK_BYTES,
};

use crate::{
    error::NetworkError,
    frame::{FrameReader, FrameWriter},
    handshake::HandshakeResult,
    message::Message,
    net_types::{NetworkCommand, NetworkEvent, RelayValidatorKey},
    peer::{
        PeerTable, ScoreEvent, BAN_DURATION, BAN_DURATION_RATE_LIMIT, BAN_SCORE, INITIAL_SCORE,
        MAX_SCORE,
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
    },
    InboundMessage {
        validator_id: Bytes32,
        addr: SocketAddr,
        msg: Message,
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
    relay_fanout: usize,
    relay_seen: RelaySeenCache,
    block_relay_slots: HashMap<BlockRelaySlotKey, Bytes32>,
    relay_metrics: HashMap<RelayMessageClass, RelayMetrics>,
}

#[derive(Debug, Clone, Copy)]
enum QueueType {
    Small,
    Large,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ConsensusMessageKey {
    VrfCommit {
        validator_id: Bytes32,
        height: u64,
        round: u32,
        commit_hash: Bytes32,
        content_hash: Bytes32,
    },
    VrfReveal {
        validator_id: Bytes32,
        height: u64,
        round: u32,
        commit_hash: Bytes32,
        vrf_output: Bytes32,
        content_hash: Bytes32,
    },
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
    VrfCommit,
    VrfReveal,
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
        Message::VrfCommit(commit) => Some(ConsensusMessageKey::VrfCommit {
            validator_id: commit.validator_id,
            height: commit.height,
            round: commit.round,
            commit_hash: commit.commit_hash,
            content_hash,
        }),
        Message::VrfReveal(reveal) => Some(ConsensusMessageKey::VrfReveal {
            validator_id: reveal.validator_id,
            height: reveal.height,
            round: reveal.round,
            commit_hash: reveal.commit_hash,
            vrf_output: reveal.vrf_output,
            content_hash,
        }),
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
        Message::VrfCommit(_) => Some(RelayMessageClass::VrfCommit),
        Message::VrfReveal(_) => Some(RelayMessageClass::VrfReveal),
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
        height: block.header.height,
        round: block.header.proposer_round,
        block_hash: block.header.block_hash(),
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
        RelayMessageClass::Vote | RelayMessageClass::VrfCommit | RelayMessageClass::VrfReveal => {
            base_fanout
        }
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

fn relay_vrf_input(prev_hash: &Bytes32, height: u64, round: u32) -> [u8; 32] {
    // Mirrors indra-consensus::proposer::compute_vrf_input without adding a
    // network -> consensus crate dependency. The epoch seed for block proposals
    // is SHA256(parent_hash), matching sync verification.
    let epoch_seed = sha256(&prev_hash.0);
    let mut election_input = Vec::with_capacity(8 + 4 + 8);
    election_input.extend_from_slice(&height.to_le_bytes());
    election_input.extend_from_slice(&round.to_le_bytes());
    election_input.extend_from_slice(&epoch_seed[..8]);
    let mut data = indra_crypto::hash::domains::VRF_INPUT.to_vec();
    data.extend_from_slice(&election_input);
    sha256(&data)
}

fn block_relay_validator_id(
    block: &BlockV1,
    relay_keys: &HashMap<Bytes32, RelayValidatorKey>,
) -> Option<Bytes32> {
    let vrf_input = relay_vrf_input(
        &block.header.prev_hash,
        block.header.height,
        block.header.proposer_round,
    );
    let output = VrfOutput(block.header.proposer_vrf_output.0);
    let proof = VrfProof(block.header.proposer_vrf_proof.as_slice().to_vec());
    let mut matches = relay_keys
        .values()
        .filter(|key| {
            key.vrf_pk
                .is_some_and(|vrf_pk| vrf_verify(&vrf_pk, &vrf_input, &output, &proof).is_ok())
        })
        .map(|key| key.validator_id);
    let first = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(first)
}

fn relay_message_key_bytes(key: &RelayMessageKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 8 + 4 + 32 + 32);
    match key {
        RelayMessageKey::Consensus(ConsensusMessageKey::VrfCommit {
            validator_id,
            height,
            round,
            commit_hash,
            content_hash,
        }) => {
            out.push(1);
            validator_id.encode(&mut out);
            height.encode(&mut out);
            round.encode(&mut out);
            commit_hash.encode(&mut out);
            content_hash.encode(&mut out);
        }
        RelayMessageKey::Consensus(ConsensusMessageKey::VrfReveal {
            validator_id,
            height,
            round,
            commit_hash,
            vrf_output,
            content_hash,
        }) => {
            out.push(2);
            validator_id.encode(&mut out);
            height.encode(&mut out);
            round.encode(&mut out);
            commit_hash.encode(&mut out);
            vrf_output.encode(&mut out);
            content_hash.encode(&mut out);
        }
        RelayMessageKey::Consensus(ConsensusMessageKey::Vote {
            validator_id,
            height,
            round,
            step,
            block_hash,
            content_hash,
        }) => {
            out.push(3);
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
        Message::Block(_)
        | Message::BlockResponse { .. }
        | Message::QCResponse { .. }
        | Message::VrfRevealsResponse { .. } => QueueType::Large,
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
            self.drop_peer(validator_id, addr).await;
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
                let signing_bytes = vote_signing_bytes(
                    vote.height,
                    vote.round,
                    vote.step,
                    &vote.block_hash,
                    &vote.validator_id,
                    vote.election_result_hash.as_ref(),
                    &self.relay_chain_id,
                );
                verify_relay_hybrid_signature(&signing_bytes, &vote.signature, key)
            }
            Message::VrfCommit(commit) => {
                let Some(key) = self.relay_keys.get(&commit.validator_id) else {
                    return false;
                };
                verify_relay_hybrid_signature(&commit.signing_bytes(), &commit.signature, key)
            }
            Message::VrfReveal(reveal) => {
                let Some(key) = self.relay_keys.get(&reveal.validator_id) else {
                    return false;
                };
                verify_relay_hybrid_signature(&reveal.signing_bytes(), &reveal.signature, key)
            }
            Message::Block(block) => block_relay_validator_id(block, &self.relay_keys).is_some(),
            _ => false,
        }
    }

    fn block_relay_conflicts(&mut self, block: &BlockV1, key: &RelayMessageKey) -> bool {
        let RelayMessageKey::Block { content_hash, .. } = key else {
            return false;
        };
        let Some(validator_id) = block_relay_validator_id(block, &self.relay_keys) else {
            return true;
        };
        let slot = BlockRelaySlotKey {
            height: block.header.height,
            round: block.header.proposer_round,
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
        let Some(key) = relay_message_key(msg) else {
            self.increment_relay_metric(class, |metrics| metrics.dropped += 1);
            return;
        };
        let already_seen = self.relay_seen.is_seen(&key);
        if !already_seen {
            if !self.relay_verification_passes(msg) {
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
                        .send(NetworkEvent::SlashDetected(wire_evidence))
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
                    self.drop_peer(validator_id, addr).await;
                } else {
                    self.peer_table.score_event(&addr, ScoreEvent::Timeout);
                    self.record_queue_full_drop(validator_id, addr, &message.msg);
                }
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.drop_peer(validator_id, addr).await;
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
            NetworkCommand::Disconnect { validator_id } => {
                if let Some(peer) = self.peers_by_validator.get(&validator_id) {
                    self.drop_peer(validator_id, peer.addr).await;
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
                        self.drop_peer(validator_id, addr).await;
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
        }
    }

    async fn handle_control(&mut self, control: PeerManagerMessage) {
        match control {
            PeerManagerMessage::Connected { addr, handshake } => {
                self.register_peer(addr, handshake).await;
            }
            PeerManagerMessage::Disconnected { validator_id, addr } => {
                self.drop_peer(validator_id, addr).await;
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
                let qc_response_key = if matches!(msg, Message::QCResponse { .. }) {
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
                self.drop_peer(peer_validator_id, existing_addr).await;
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
            loop {
                let plaintext = match reader.read_frame().await {
                    Ok(bytes) => bytes,
                    Err(_) => break,
                };
                let msg_size = plaintext.len();
                let payload = if plaintext.len() >= 4 {
                    &plaintext[4..]
                } else {
                    &plaintext[..]
                };
                let msg = match Message::decode_wire(payload) {
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
                        msg,
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

    async fn drop_peer(&mut self, validator_id: Bytes32, addr: SocketAddr) {
        let mut is_outbound = false;
        if let Some(peer) = self.peers_by_validator.get(&validator_id) {
            if peer.addr == addr {
                let peer = self.peers_by_validator.remove(&validator_id).unwrap();
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
                self.drop_peer(validator_id, addr).await;
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
        .send(PeerManagerMessage::Disconnected { validator_id, addr })
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
    ) -> Result<(), mpsc::error::SendError<NetworkCommand>> {
        self.command_tx.blocking_send(command)
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
        relay_fanout: derive_consensus_relay_fanout(config.relay_validator_keys.len()),
        relay_keys: relay_key_map(config.relay_validator_keys),
        relay_seen: RelaySeenCache::new(CONSENSUS_RELAY_SEEN_CAPACITY),
        block_relay_slots: HashMap::new(),
        relay_metrics: HashMap::new(),
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
    use crate::rate_limit::RateLimitReason;
    use indra_core::types::{
        block::{BlockHeaderV1, BlockV1, NO_POLC_ROUND},
        crypto::HybridSignature,
        primitives::{ProtocolVersion, VariableBytes, MAX_QC_SIZE_BYTES, MAX_VRF_PROOF_BYTES},
        vote::{VoteStep, VoteV1},
        vrf_election::{VrfCommit, VrfReveal},
    };
    use indra_crypto::{vrf_prove, ClassicalKeypair, HybridKeypair, PqKeypair, VrfKeypair};
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
            relay_fanout: derive_consensus_relay_fanout(0),
            relay_seen: RelaySeenCache::new(CONSENSUS_RELAY_SEEN_CAPACITY),
            block_relay_slots: HashMap::new(),
            relay_metrics: HashMap::new(),
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
        let bytes = vote_signing_bytes(
            7,
            2,
            step,
            &block_hash,
            &validator_id,
            None,
            "indra-testnet-1",
        );
        VoteV1 {
            height: 7,
            round: 2,
            step,
            block_hash,
            validator_id,
            election_result_hash: None,
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

    fn signed_commit(validator_id: Bytes32, keypair: &HybridKeypair) -> VrfCommit {
        let mut commit = VrfCommit {
            chain_id_hash: Bytes32::from([0x01; 32]),
            height: 7,
            round: 2,
            validator_id,
            vrf_pubkey: [0xCC; 32],
            commit_hash: Bytes32::from([0xDD; 32]),
            signature: dummy_signature(),
        };
        commit.signature = core_signature(keypair.sign(&commit.signing_bytes()).unwrap());
        commit
    }

    fn signed_reveal(validator_id: Bytes32, keypair: &HybridKeypair) -> VrfReveal {
        let mut reveal = VrfReveal {
            chain_id_hash: Bytes32::from([0x01; 32]),
            height: 7,
            round: 2,
            validator_id,
            vrf_pubkey: [0xCC; 32],
            vrf_output: Bytes32::from([0xEE; 32]),
            vrf_proof: VariableBytes::from_slice(&[0xAB; 80]).unwrap(),
            commit_hash: Bytes32::from([0xDD; 32]),
            signature: dummy_signature(),
        };
        reveal.signature = core_signature(keypair.sign(&reveal.signing_bytes()).unwrap());
        reveal
    }

    fn relay_test_block(
        _validator_id: Bytes32,
        vrf: &VrfKeypair,
        height: u64,
        round: u32,
        prev_hash: Bytes32,
        value_hash: Bytes32,
    ) -> BlockV1 {
        let input = relay_vrf_input(&prev_hash, height, round);
        let (output, proof) = vrf_prove(vrf, &input);
        BlockV1 {
            header: BlockHeaderV1 {
                protocol_version: ProtocolVersion(1),
                height,
                prev_hash,
                timestamp: 0,
                state_root: Bytes32::ZERO,
                validator_set_root: Bytes32::ZERO,
                mempool_set_root: Bytes32::ZERO,
                value_hash,
                base_fee: 0,
                proposer_round: round,
                polc_round: NO_POLC_ROUND,
                proposer_vrf_output: Bytes32::from(output.0),
                proposer_vrf_proof: VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&proof.0)
                    .unwrap(),
                quorum_certificate: VariableBytes::<MAX_QC_SIZE_BYTES>::from_slice(&[]).unwrap(),
                election_result_hash: None,
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            vrf_reveals: vec![],
        }
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
            assert!(!filter.is_duplicate(ConsensusMessageKey::VrfCommit {
                validator_id: Bytes32::from([i; 32]),
                height: 1,
                round: 0,
                commit_hash: Bytes32::from([i.saturating_add(10); 32]),
                content_hash: Bytes32::from([i.saturating_add(20); 32]),
            }));
        }
        assert_eq!(filter.len(), 3);
        assert!(
            !filter.is_duplicate(ConsensusMessageKey::VrfCommit {
                validator_id: Bytes32::from([0; 32]),
                height: 1,
                round: 0,
                commit_hash: Bytes32::from([10; 32]),
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
            election_result_hash: None,
            signature: dummy_signature(),
        });
        let key = consensus_message_key(&vote).expect("vote key");
        let mut filter = ConsensusDuplicateFilter::new(CONSENSUS_DUPLICATE_FILTER_CAPACITY);
        assert!(!filter.is_duplicate(key));
        assert!(filter.is_duplicate(key));
    }

    #[test]
    fn consensus_duplicate_filter_detects_exact_vrf_commit_duplicates() {
        let commit = Message::VrfCommit(VrfCommit {
            chain_id_hash: Bytes32::from([0x01; 32]),
            height: 7,
            round: 2,
            validator_id: Bytes32::from([0xBB; 32]),
            vrf_pubkey: [0xCC; 32],
            commit_hash: Bytes32::from([0xDD; 32]),
            signature: dummy_signature(),
        });
        let key = consensus_message_key(&commit).expect("vrf commit key");
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
                    msg: msg.clone(),
                    msg_size: 128,
                })
                .await;
        }
        assert!(matches!(
            event_rx.try_recv(),
            Ok(NetworkEvent::Message {
                msg: Message::QCResponse { .. },
                ..
            })
        ));
        assert!(event_rx.try_recv().is_err());
        assert_eq!(actor.qc_response_seen.len(), 1);
    }

    #[tokio::test]
    async fn authenticated_vote_limit_is_keyed_by_validator_identity() {
        let validator = Bytes32::from([0xB2; 32]);
        let addr: SocketAddr = "127.0.0.1:32102".parse().unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(128);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        for index in 0..81u8 {
            let msg = Message::Vote(VoteV1 {
                height: 1,
                round: index as u32,
                step: VoteStep::Prevote,
                block_hash: Bytes32::from([index; 32]),
                validator_id: validator,
                election_result_hash: None,
                signature: dummy_signature(),
            });
            actor
                .handle_control(PeerManagerMessage::InboundMessage {
                    validator_id: validator,
                    addr,
                    msg,
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
        let msg = Message::VrfReveal(signed_reveal(sender, &keypair));

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

        assert_eq!(
            actor.relay_metrics[&RelayMessageClass::VrfReveal].queue_full,
            1
        );
        let key = relay_message_key(&msg).expect("reveal should have relay key");
        assert!(
            !actor.relay_seen.forwarded_to(&key, &peer),
            "queue-full reveal delivery must not be marked forwarded"
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

    #[test]
    fn relay_verifies_vrf_commit_and_reveal_signatures() {
        let sender = Bytes32::from([0x50; 32]);
        let keypair = hybrid_key(0x50);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        install_relay_keys(&mut actor, vec![relay_key(sender, &keypair)]);
        assert!(
            actor.relay_verification_passes(&Message::VrfCommit(signed_commit(sender, &keypair)))
        );
        assert!(
            actor.relay_verification_passes(&Message::VrfReveal(signed_reveal(sender, &keypair)))
        );
    }

    #[test]
    fn block_relay_verifies_embedded_proposer_vrf_not_election_authority() {
        let validator_id = Bytes32::from([0x60; 32]);
        let vrf = VrfKeypair::from_seed(&validator_id.0);
        let prev_hash = Bytes32::from([0x61; 32]);
        let block = relay_test_block(validator_id, &vrf, 9, 3, prev_hash, Bytes32::ZERO);
        let keypair = hybrid_key(0x60);
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

        let block_a = Message::Block(relay_test_block(
            validator_id,
            &vrf,
            11,
            2,
            prev_hash,
            Bytes32::from([0x01; 32]),
        ));
        let block_b = Message::Block(relay_test_block(
            validator_id,
            &vrf,
            11,
            2,
            prev_hash,
            Bytes32::from([0x02; 32]),
        ));
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

        let block_round_2 = Message::Block(relay_test_block(
            validator_id,
            &vrf,
            11,
            2,
            prev_hash,
            Bytes32::from([0x03; 32]),
        ));
        let block_round_3 = Message::Block(relay_test_block(
            validator_id,
            &vrf,
            11,
            3,
            prev_hash,
            Bytes32::from([0x04; 32]),
        ));
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

        let block = Message::Block(relay_test_block(
            validator_id,
            &vrf,
            12,
            0,
            prev_hash,
            Bytes32::from([0x05; 32]),
        ));
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
        assert!(relay_message_class(&Message::QCResponse {
            height: 7,
            qc_bytes: vec![]
        })
        .is_none());
        assert!(relay_message_class(&Message::RequestVrfReveals {
            height: 7,
            round: 0,
            validator_ids: vec![]
        })
        .is_none());
        assert!(relay_message_class(&Message::VrfRevealsResponse {
            height: 7,
            round: 0,
            reveals: vec![]
        })
        .is_none());
    }

    const SIM_VALIDATORS_N200: usize = 200;
    const SIM_TARGET_OUTBOUND: usize = 8;
    const SIM_MAX_INBOUND: usize = 64;
    const SIM_QUORUM_BPS: u64 = 6_700;
    const SIM_RELAY_PROCESSING_MS: f64 = 2.0;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    enum SimRegion {
        NaEast,
        NaWest,
        EuWest,
        SouthAsia,
        EastAsia,
        SouthAmerica,
    }

    #[derive(Debug, Clone, Copy)]
    struct VrfTimingScenario {
        name: &'static str,
        message_loss_bps: u16,
        congested_region: Option<SimRegion>,
        bootstrap_saturated: bool,
        asymmetric_latency: bool,
        high_stake_slow_region: bool,
        congested_region_delay_ms: f64,
        bootstrap_delay_ms: f64,
        slow_region_delay_ms: f64,
        slow_region_stake: u64,
    }

    #[derive(Debug, Clone)]
    struct VrfTimingOutcome {
        quorum_validators: usize,
        commit_window_hits: usize,
        reveal_window_hits: usize,
        min_revealed_stake: u64,
        median_revealed_stake: u64,
        max_revealed_stake: u64,
        avg_compute_ms: f64,
        max_compute_ms: f64,
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    struct SimQueueState {
        node: usize,
        time_ms: f64,
    }

    impl Eq for SimQueueState {}

    impl Ord for SimQueueState {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            other
                .time_ms
                .total_cmp(&self.time_ms)
                .then_with(|| self.node.cmp(&other.node))
        }
    }

    impl PartialOrd for SimQueueState {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    fn sim_regions_n200() -> Vec<SimRegion> {
        let mut regions = Vec::with_capacity(SIM_VALIDATORS_N200);
        regions.extend(std::iter::repeat(SimRegion::NaEast).take(40));
        regions.extend(std::iter::repeat(SimRegion::NaWest).take(35));
        regions.extend(std::iter::repeat(SimRegion::EuWest).take(45));
        regions.extend(std::iter::repeat(SimRegion::SouthAsia).take(30));
        regions.extend(std::iter::repeat(SimRegion::EastAsia).take(30));
        regions.extend(std::iter::repeat(SimRegion::SouthAmerica).take(20));
        regions
    }

    fn sim_stakes_n200_with_slow_region_stake(
        high_stake_slow_region: bool,
        slow_region_stake: u64,
    ) -> Vec<u64> {
        let regions = sim_regions_n200();
        regions
            .into_iter()
            .map(|region| {
                if high_stake_slow_region && region == SimRegion::SouthAmerica {
                    slow_region_stake
                } else {
                    1
                }
            })
            .collect()
    }

    fn sim_scenario(name: &'static str) -> VrfTimingScenario {
        VrfTimingScenario {
            name,
            message_loss_bps: 0,
            congested_region: None,
            bootstrap_saturated: false,
            asymmetric_latency: false,
            high_stake_slow_region: false,
            congested_region_delay_ms: 360.0,
            bootstrap_delay_ms: 520.0,
            slow_region_delay_ms: 420.0,
            slow_region_stake: 50,
        }
    }

    fn sim_quorum_stake(stakes: &[u64]) -> u64 {
        stakes
            .iter()
            .copied()
            .sum::<u64>()
            .saturating_mul(SIM_QUORUM_BPS)
            .saturating_add(9_999)
            / 10_000
    }

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

    fn sim_relay_targets_masked(
        graph: &[HashSet<usize>],
        node: usize,
        origin: usize,
        fanout: usize,
        online: &[bool],
    ) -> Vec<usize> {
        let mut neighbors = graph[node]
            .iter()
            .copied()
            .filter(|peer| online[*peer])
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

    fn sim_build_relay_targets_masked(
        graph: &[HashSet<usize>],
        fanout: usize,
        online: &[bool],
    ) -> Vec<Vec<Vec<usize>>> {
        (0..graph.len())
            .map(|origin| {
                (0..graph.len())
                    .map(|node| {
                        if online[node] {
                            sim_relay_targets_masked(graph, node, origin, fanout, online)
                        } else {
                            Vec::new()
                        }
                    })
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

    fn sim_base_latency_ms(from: SimRegion, to: SimRegion) -> f64 {
        if from == to {
            return 8.0;
        }
        match (from.min(to), from.max(to)) {
            (SimRegion::NaEast, SimRegion::NaWest) => 35.0,
            (SimRegion::NaEast, SimRegion::EuWest) => 45.0,
            (SimRegion::NaEast, SimRegion::SouthAsia) => 105.0,
            (SimRegion::NaEast, SimRegion::EastAsia) => 110.0,
            (SimRegion::NaEast, SimRegion::SouthAmerica) => 75.0,
            (SimRegion::NaWest, SimRegion::EuWest) => 75.0,
            (SimRegion::NaWest, SimRegion::SouthAsia) => 115.0,
            (SimRegion::NaWest, SimRegion::EastAsia) => 75.0,
            (SimRegion::NaWest, SimRegion::SouthAmerica) => 80.0,
            (SimRegion::EuWest, SimRegion::SouthAsia) => 60.0,
            (SimRegion::EuWest, SimRegion::EastAsia) => 95.0,
            (SimRegion::EuWest, SimRegion::SouthAmerica) => 95.0,
            (SimRegion::SouthAsia, SimRegion::EastAsia) => 45.0,
            (SimRegion::SouthAsia, SimRegion::SouthAmerica) => 135.0,
            (SimRegion::EastAsia, SimRegion::SouthAmerica) => 145.0,
            _ => 150.0,
        }
    }

    fn sim_hash_unit(parts: &[usize]) -> f64 {
        let mut seed = Vec::with_capacity(parts.len() * 2);
        for part in parts {
            seed.extend_from_slice(&(*part as u16).to_le_bytes());
        }
        let digest = sha256(&seed);
        u64::from_le_bytes(digest[..8].try_into().unwrap_or([0xFF; 8])) as f64 / u64::MAX as f64
    }

    fn sim_edge_delay_ms(
        from: usize,
        to: usize,
        origin: usize,
        phase: usize,
        regions: &[SimRegion],
        scenario: VrfTimingScenario,
    ) -> f64 {
        let mut latency = sim_base_latency_ms(regions[from], regions[to]);
        latency *= 1.0 + 0.75 * sim_hash_unit(&[origin, from, to, phase, 11]);
        latency += 10.0;

        if scenario.asymmetric_latency && regions[from] > regions[to] {
            latency = latency.mul_add(0.8, 40.0);
        }
        if scenario
            .congested_region
            .is_some_and(|region| region == regions[from] || region == regions[to])
        {
            latency += scenario.congested_region_delay_ms;
        }
        if scenario.high_stake_slow_region
            && (regions[from] == SimRegion::SouthAmerica || regions[to] == SimRegion::SouthAmerica)
        {
            latency += scenario.slow_region_delay_ms;
        }
        if scenario.bootstrap_saturated && (from == 0 || to == 0) {
            latency += scenario.bootstrap_delay_ms;
        }

        latency + SIM_RELAY_PROCESSING_MS
    }

    fn sim_edge_dropped(
        from: usize,
        to: usize,
        origin: usize,
        phase: usize,
        scenario: VrfTimingScenario,
    ) -> bool {
        let loss_bps = if scenario.bootstrap_saturated && (from == 0 || to == 0) {
            scenario.message_loss_bps.max(3_000)
        } else {
            scenario.message_loss_bps
        };
        if loss_bps == 0 {
            return false;
        }
        let unit = sim_hash_unit(&[origin, from, to, phase, 97]);
        unit < f64::from(loss_bps) / 10_000.0
    }

    fn sim_propagation_arrivals(
        _graph: &[HashSet<usize>],
        relay_targets: &[Vec<Vec<usize>>],
        departures: &[f64],
        regions: &[SimRegion],
        scenario: VrfTimingScenario,
        phase: usize,
    ) -> Vec<Vec<f64>> {
        let n = relay_targets.len();
        let mut all = Vec::with_capacity(n);
        for origin in 0..n {
            let mut dist = vec![f64::INFINITY; n];
            let mut queue = std::collections::BinaryHeap::new();
            dist[origin] = departures[origin];
            queue.push(SimQueueState {
                node: origin,
                time_ms: departures[origin],
            });

            while let Some(SimQueueState { node, time_ms }) = queue.pop() {
                if time_ms > dist[node] {
                    continue;
                }
                for peer in relay_targets[origin][node].iter().copied() {
                    if sim_edge_dropped(node, peer, origin, phase, scenario) {
                        continue;
                    }
                    let candidate =
                        time_ms + sim_edge_delay_ms(node, peer, origin, phase, regions, scenario);
                    if candidate < dist[peer] {
                        dist[peer] = candidate;
                        queue.push(SimQueueState {
                            node: peer,
                            time_ms: candidate,
                        });
                    }
                }
            }
            all.push(dist);
        }
        all
    }

    fn sim_stake_received_by_deadline(
        arrivals: &[Vec<f64>],
        receiver: usize,
        deadline: f64,
        stakes: &[u64],
    ) -> u64 {
        arrivals
            .iter()
            .enumerate()
            .filter(|(origin, arrival)| arrival[receiver] <= deadline && stakes[*origin] > 0)
            .map(|(origin, _)| stakes[origin])
            .sum()
    }

    fn sim_vrf_timing_outcome(
        graph: &[HashSet<usize>],
        relay_targets: &[Vec<Vec<usize>>],
        window_ms: u64,
        scenario: VrfTimingScenario,
    ) -> VrfTimingOutcome {
        let regions = sim_regions_n200();
        let stakes = sim_stakes_n200_with_slow_region_stake(
            scenario.high_stake_slow_region,
            scenario.slow_region_stake,
        );
        let quorum_stake = sim_quorum_stake(&stakes);
        let departures = vec![0.0; graph.len()];
        let commit_arrivals =
            sim_propagation_arrivals(graph, relay_targets, &departures, &regions, scenario, 1);
        let mut reveal_departures = vec![0.0; graph.len()];
        let mut commit_window_hits = 0usize;
        for receiver in 0..graph.len() {
            let mut commit_times = commit_arrivals
                .iter()
                .enumerate()
                .filter_map(|(origin, arrivals)| {
                    arrivals[receiver]
                        .is_finite()
                        .then_some((arrivals[receiver], stakes[origin]))
                })
                .collect::<Vec<_>>();
            commit_times.sort_by(|a, b| a.0.total_cmp(&b.0));
            let mut stake = 0u64;
            let mut quorum_time = window_ms as f64;
            let mut reached_before_window = false;
            for (arrival, origin_stake) in commit_times {
                stake = stake.saturating_add(origin_stake);
                if stake >= quorum_stake {
                    quorum_time = arrival.min(window_ms as f64);
                    reached_before_window = arrival < window_ms as f64;
                    break;
                }
            }
            if !reached_before_window {
                commit_window_hits += 1;
            }
            reveal_departures[receiver] = quorum_time;
        }

        let reveal_arrivals = sim_propagation_arrivals(
            graph,
            relay_targets,
            &reveal_departures,
            &regions,
            scenario,
            2,
        );
        let mut revealed_stakes = Vec::with_capacity(graph.len());
        let mut compute_times = Vec::with_capacity(graph.len());
        let mut reveal_window_hits = 0usize;
        for receiver in 0..graph.len() {
            let deadline = reveal_departures[receiver] + window_ms as f64;
            let stake =
                sim_stake_received_by_deadline(&reveal_arrivals, receiver, deadline, &stakes);
            revealed_stakes.push(stake);

            let mut reveal_times = reveal_arrivals
                .iter()
                .enumerate()
                .filter_map(|(origin, arrivals)| {
                    arrivals[receiver]
                        .is_finite()
                        .then_some((arrivals[receiver], stakes[origin]))
                })
                .collect::<Vec<_>>();
            reveal_times.sort_by(|a, b| a.0.total_cmp(&b.0));
            let mut accumulated = 0u64;
            let mut compute_time = deadline;
            let mut reached_before_deadline = false;
            for (arrival, origin_stake) in reveal_times {
                accumulated = accumulated.saturating_add(origin_stake);
                if accumulated >= quorum_stake {
                    compute_time = arrival.min(deadline);
                    reached_before_deadline = arrival < deadline;
                    break;
                }
            }
            if !reached_before_deadline {
                reveal_window_hits += 1;
            }
            compute_times.push(compute_time);
        }
        revealed_stakes.sort_unstable();
        compute_times.sort_by(|a, b| a.total_cmp(b));
        let avg_compute_ms = compute_times.iter().sum::<f64>() / compute_times.len() as f64;
        VrfTimingOutcome {
            quorum_validators: revealed_stakes
                .iter()
                .filter(|stake| **stake >= quorum_stake)
                .count(),
            commit_window_hits,
            reveal_window_hits,
            min_revealed_stake: revealed_stakes[0],
            median_revealed_stake: revealed_stakes[revealed_stakes.len() / 2],
            max_revealed_stake: *revealed_stakes.last().unwrap(),
            avg_compute_ms,
            max_compute_ms: *compute_times.last().unwrap(),
        }
    }

    #[derive(Debug, Clone)]
    struct RestartSimOutcome {
        restarted: usize,
        initial_online: usize,
        first_quorum_online_round: Option<u32>,
        finalized_round: Option<u32>,
        finalized_via_fallback: bool,
        max_late_local_commit_cases_in_round: usize,
        min_block_reach_two_hops_after_quorum: usize,
        min_block_reach_three_hops_after_quorum: usize,
        min_block_reach_four_hops_after_quorum: usize,
        min_online_degree_after_quorum: usize,
        quorum_online_time_ms: Option<f64>,
    }

    #[derive(Debug, Clone)]
    struct RestartRoundOutcome {
        online: usize,
        quorum_backed_election_nodes: usize,
        late_local_commit_cases: usize,
        block_reach_two_hops: usize,
        block_reach_three_hops: usize,
        block_reach_four_hops: usize,
        min_online_degree: usize,
    }

    fn sim_restart_set(n: usize, restarted: usize) -> HashSet<usize> {
        let mut ordered = (0..n)
            .map(|node| {
                let digest = sha256(&[(node & 0xFF) as u8, ((node >> 8) & 0xFF) as u8, 0xC0, 0xDE]);
                (
                    u64::from_le_bytes(digest[..8].try_into().unwrap_or([0xFF; 8])),
                    node,
                )
            })
            .collect::<Vec<_>>();
        ordered.sort();
        ordered
            .into_iter()
            .take(restarted)
            .map(|(_, node)| node)
            .collect()
    }

    fn sim_restart_ready_times(n: usize, restarted: usize, restart_window_ms: f64) -> Vec<f64> {
        let restarted_set = sim_restart_set(n, restarted);
        let mut restarted_order = restarted_set.iter().copied().collect::<Vec<_>>();
        restarted_order.sort_by(|a, b| {
            sim_hash_unit(&[*a, 0xAA55])
                .total_cmp(&sim_hash_unit(&[*b, 0xAA55]))
                .then_with(|| a.cmp(b))
        });
        let mut ready = vec![0.0; n];
        for (idx, node) in restarted_order.into_iter().enumerate() {
            // Startup in the live node waits 500ms before loading discovery
            // sources, then dials with a 2s minimum backoff on failures. This
            // model adds a conservative 5s process/bootstrap base and spreads
            // the correlated restart cohort across the configured short window.
            let position = if restarted <= 1 {
                0.0
            } else {
                idx as f64 / (restarted - 1) as f64
            };
            ready[node] = 5_000.0 + position * restart_window_ms;
        }
        ready
    }

    fn sim_online_mask(ready_times: &[f64], at_ms: f64) -> Vec<bool> {
        ready_times.iter().map(|ready| *ready <= at_ms).collect()
    }

    fn sim_online_count(online: &[bool]) -> usize {
        online.iter().filter(|online| **online).count()
    }

    fn sim_online_quorum(online: &[bool]) -> bool {
        sim_online_count(online) >= sim_quorum_stake(&vec![1; online.len()]) as usize
    }

    fn sim_min_online_degree(graph: &[HashSet<usize>], online: &[bool]) -> usize {
        graph
            .iter()
            .enumerate()
            .filter(|(node, _)| online[*node])
            .map(|(_, neighbors)| neighbors.iter().filter(|peer| online[**peer]).count())
            .min()
            .unwrap_or(0)
    }

    fn sim_reached_after_hops_masked(
        relay_targets: &[Vec<Vec<usize>>],
        origin: usize,
        online: &[bool],
        max_hops: usize,
    ) -> usize {
        if !online[origin] {
            return 0;
        }
        let mut reached = HashSet::new();
        let mut frontier = VecDeque::new();
        reached.insert(origin);
        frontier.push_back(origin);
        for _ in 0..max_hops {
            let level = frontier.len();
            for _ in 0..level {
                let node = frontier.pop_front().unwrap();
                for peer in relay_targets[origin][node].iter().copied() {
                    if online[peer] && reached.insert(peer) {
                        frontier.push_back(peer);
                    }
                }
            }
        }
        reached.len()
    }

    fn sim_propagation_arrivals_masked(
        _graph: &[HashSet<usize>],
        relay_targets: &[Vec<Vec<usize>>],
        departures: &[f64],
        online: &[bool],
        regions: &[SimRegion],
        scenario: VrfTimingScenario,
        phase: usize,
    ) -> Vec<Vec<f64>> {
        let n = relay_targets.len();
        let mut all = Vec::with_capacity(n);
        for origin in 0..n {
            let mut dist = vec![f64::INFINITY; n];
            if !online[origin] || !departures[origin].is_finite() {
                all.push(dist);
                continue;
            }
            let mut queue = std::collections::BinaryHeap::new();
            dist[origin] = departures[origin];
            queue.push(SimQueueState {
                node: origin,
                time_ms: departures[origin],
            });

            while let Some(SimQueueState { node, time_ms }) = queue.pop() {
                if time_ms > dist[node] {
                    continue;
                }
                for peer in relay_targets[origin][node].iter().copied() {
                    if !online[peer] || sim_edge_dropped(node, peer, origin, phase, scenario) {
                        continue;
                    }
                    let candidate =
                        time_ms + sim_edge_delay_ms(node, peer, origin, phase, regions, scenario);
                    if candidate < dist[peer] {
                        dist[peer] = candidate;
                        queue.push(SimQueueState {
                            node: peer,
                            time_ms: candidate,
                        });
                    }
                }
            }
            all.push(dist);
        }
        all
    }

    fn sim_restart_round_outcome(
        graph: &[HashSet<usize>],
        relay_targets: &[Vec<Vec<usize>>],
        block_relay_targets: &[Vec<Vec<usize>>],
        ready_times: &[f64],
        round_start_ms: f64,
        scenario: VrfTimingScenario,
    ) -> RestartRoundOutcome {
        let regions = sim_regions_n200();
        let stakes = vec![1u64; graph.len()];
        let quorum_stake = sim_quorum_stake(&stakes);
        let online = sim_online_mask(ready_times, round_start_ms);
        let online_count = sim_online_count(&online);
        let mut commit_departures = vec![f64::INFINITY; graph.len()];
        for node in 0..graph.len() {
            if online[node] {
                // Simulate scheduler/load jitter after restart. Remote commit
                // quorum may open reveal phase before a node's own local commit
                // is inserted; the fixed driver path must still create that
                // node's reveal when the local commit arrives.
                let local_jitter_ms = 25.0 + 900.0 * sim_hash_unit(&[node, 0x5151]);
                commit_departures[node] = round_start_ms + local_jitter_ms;
            }
        }
        let commit_arrivals = sim_propagation_arrivals_masked(
            graph,
            relay_targets,
            &commit_departures,
            &online,
            &regions,
            scenario,
            11,
        );
        let mut reveal_departures = vec![f64::INFINITY; graph.len()];
        let mut late_local_commit_cases = 0usize;
        for receiver in 0..graph.len() {
            if !online[receiver] {
                continue;
            }
            let mut commit_times = commit_arrivals
                .iter()
                .enumerate()
                .filter_map(|(origin, arrivals)| {
                    arrivals[receiver]
                        .is_finite()
                        .then_some((arrivals[receiver], stakes[origin]))
                })
                .collect::<Vec<_>>();
            commit_times.sort_by(|a, b| a.0.total_cmp(&b.0));
            let mut stake = 0u64;
            let mut reveal_open_time =
                round_start_ms + indra_core::types::primitives::VRF_COMMIT_WINDOW_MS as f64;
            for (arrival, origin_stake) in commit_times {
                stake = stake.saturating_add(origin_stake);
                if stake >= quorum_stake {
                    reveal_open_time = arrival.min(reveal_open_time);
                    break;
                }
            }
            if commit_departures[receiver] > reveal_open_time {
                late_local_commit_cases += 1;
            }
            reveal_departures[receiver] = commit_departures[receiver].max(reveal_open_time);
        }

        let reveal_arrivals = sim_propagation_arrivals_masked(
            graph,
            relay_targets,
            &reveal_departures,
            &online,
            &regions,
            scenario,
            12,
        );
        let mut quorum_backed_election_nodes = 0usize;
        for receiver in 0..graph.len() {
            if !online[receiver] {
                continue;
            }
            let deadline = reveal_departures[receiver]
                + indra_core::types::primitives::VRF_REVEAL_WINDOW_MS as f64;
            let revealed_stake =
                sim_stake_received_by_deadline(&reveal_arrivals, receiver, deadline, &stakes);
            if revealed_stake >= quorum_stake {
                quorum_backed_election_nodes += 1;
            }
        }

        let block_reach_two_hops = (0..graph.len())
            .filter(|origin| online[*origin])
            .map(|origin| sim_reached_after_hops_masked(block_relay_targets, origin, &online, 2))
            .min()
            .unwrap_or(0);
        let block_reach_three_hops = (0..graph.len())
            .filter(|origin| online[*origin])
            .map(|origin| sim_reached_after_hops_masked(block_relay_targets, origin, &online, 3))
            .min()
            .unwrap_or(0);
        let block_reach_four_hops = (0..graph.len())
            .filter(|origin| online[*origin])
            .map(|origin| sim_reached_after_hops_masked(block_relay_targets, origin, &online, 4))
            .min()
            .unwrap_or(0);

        RestartRoundOutcome {
            online: online_count,
            quorum_backed_election_nodes,
            late_local_commit_cases,
            block_reach_two_hops,
            block_reach_three_hops,
            block_reach_four_hops,
            min_online_degree: sim_min_online_degree(graph, &online),
        }
    }

    fn sim_correlated_restart_outcome(
        restarted: usize,
        restart_window_ms: f64,
    ) -> RestartSimOutcome {
        let n = SIM_VALIDATORS_N200;
        let fanout = derive_consensus_relay_fanout(n);
        let block_fanout = relay_fanout_for_class(fanout, RelayMessageClass::Block);
        let (graph, _) = sim_build_bootstrap_first_graph(n, SIM_TARGET_OUTBOUND, SIM_MAX_INBOUND);
        let ready_times = sim_restart_ready_times(n, restarted, restart_window_ms);
        let initial_online = ready_times.iter().filter(|ready| **ready <= 0.0).count();
        let scenario = VrfTimingScenario {
            bootstrap_saturated: true,
            message_loss_bps: 100,
            ..sim_scenario("correlated_restart")
        };
        let failed_round_ms = indra_core::types::primitives::VRF_COMMIT_WINDOW_MS as f64
            + indra_core::types::primitives::VRF_REVEAL_WINDOW_MS as f64
            + 8_000.0;
        let mut insufficient_rounds = 0u32;
        let mut first_quorum_online_round = None;
        let mut quorum_online_time_ms = None;
        let mut max_late_local_commit_cases_in_round = 0usize;
        let mut min_block_reach_two_hops_after_quorum = usize::MAX;
        let mut min_block_reach_three_hops_after_quorum = usize::MAX;
        let mut min_block_reach_four_hops_after_quorum = usize::MAX;
        let mut min_online_degree_after_quorum = usize::MAX;
        let mut finalized_round = None;
        let mut finalized_via_fallback = false;

        for round in 0..64u32 {
            let round_start_ms = f64::from(round) * failed_round_ms;
            let online = sim_online_mask(&ready_times, round_start_ms);
            if sim_online_quorum(&online) && first_quorum_online_round.is_none() {
                first_quorum_online_round = Some(round);
                quorum_online_time_ms = Some(round_start_ms);
            }

            let outcome = sim_restart_round_outcome(
                &graph,
                &sim_build_relay_targets_masked(&graph, fanout, &online),
                &sim_build_relay_targets_masked(&graph, block_fanout, &online),
                &ready_times,
                round_start_ms,
                scenario,
            );
            max_late_local_commit_cases_in_round =
                max_late_local_commit_cases_in_round.max(outcome.late_local_commit_cases);
            if sim_online_quorum(&online) {
                min_block_reach_two_hops_after_quorum =
                    min_block_reach_two_hops_after_quorum.min(outcome.block_reach_two_hops);
                min_block_reach_three_hops_after_quorum =
                    min_block_reach_three_hops_after_quorum.min(outcome.block_reach_three_hops);
                min_block_reach_four_hops_after_quorum =
                    min_block_reach_four_hops_after_quorum.min(outcome.block_reach_four_hops);
                min_online_degree_after_quorum =
                    min_online_degree_after_quorum.min(outcome.min_online_degree);
            }

            if outcome.quorum_backed_election_nodes >= sim_quorum_stake(&vec![1; n]) as usize
                && outcome.online >= sim_quorum_stake(&vec![1; n]) as usize
            {
                finalized_round = Some(round);
                break;
            }

            insufficient_rounds = insufficient_rounds.saturating_add(1);
            if insufficient_rounds >= indra_core::types::primitives::MAX_VRF_EMPTY_REVEAL_ROUNDS
                && outcome.online >= sim_quorum_stake(&vec![1; n]) as usize
            {
                finalized_round = Some(round);
                finalized_via_fallback = true;
                break;
            }
        }

        RestartSimOutcome {
            restarted,
            initial_online,
            first_quorum_online_round,
            finalized_round,
            finalized_via_fallback,
            max_late_local_commit_cases_in_round,
            min_block_reach_two_hops_after_quorum: min_block_reach_two_hops_after_quorum.min(n),
            min_block_reach_three_hops_after_quorum: min_block_reach_three_hops_after_quorum.min(n),
            min_block_reach_four_hops_after_quorum: min_block_reach_four_hops_after_quorum.min(n),
            min_online_degree_after_quorum: min_online_degree_after_quorum.min(n),
            quorum_online_time_ms,
        }
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
    #[ignore = "scale-validation simulation; run explicitly with --ignored --nocapture"]
    fn vrf_timing_windows_under_n200_latency_stress() {
        let fanout = derive_consensus_relay_fanout(SIM_VALIDATORS_N200);
        let (hub_graph, _) = sim_build_bootstrap_first_graph(
            SIM_VALIDATORS_N200,
            SIM_TARGET_OUTBOUND,
            SIM_MAX_INBOUND,
        );
        let relay_targets = sim_build_relay_targets(&hub_graph, fanout);
        let windows = [500u64, 750, 1_000, 1_500];
        let scenarios = [
            VrfTimingScenario {
                message_loss_bps: 100,
                ..sim_scenario("one_percent_loss")
            },
            VrfTimingScenario {
                message_loss_bps: 500,
                ..sim_scenario("five_percent_loss")
            },
            VrfTimingScenario {
                congested_region: Some(SimRegion::EastAsia),
                message_loss_bps: 100,
                ..sim_scenario("east_asia_queue_spike")
            },
            VrfTimingScenario {
                bootstrap_saturated: true,
                message_loss_bps: 100,
                ..sim_scenario("bootstrap_saturation")
            },
            VrfTimingScenario {
                high_stake_slow_region: true,
                message_loss_bps: 100,
                ..sim_scenario("slow_region_high_stake")
            },
            VrfTimingScenario {
                asymmetric_latency: true,
                message_loss_bps: 100,
                ..sim_scenario("asymmetric_latency")
            },
            VrfTimingScenario {
                message_loss_bps: 500,
                congested_region: Some(SimRegion::EastAsia),
                bootstrap_saturated: true,
                asymmetric_latency: true,
                high_stake_slow_region: true,
                ..sim_scenario("combined_tail")
            },
        ];

        let mut window_choice_matters = false;
        for scenario in scenarios {
            let mut outcomes = Vec::new();
            for window in windows {
                let outcome = sim_vrf_timing_outcome(&hub_graph, &relay_targets, window, scenario);
                eprintln!(
                    "[vrf-window-sim] scenario={} window={}ms quorum_nodes={}/200 window_hits(commit/reveal)={}/{} stake_min/med/max={}/{}/{} avg/max_compute_ms={:.1}/{:.1}",
                    scenario.name,
                    window,
                    outcome.quorum_validators,
                    outcome.commit_window_hits,
                    outcome.reveal_window_hits,
                    outcome.min_revealed_stake,
                    outcome.median_revealed_stake,
                    outcome.max_revealed_stake,
                    outcome.avg_compute_ms,
                    outcome.max_compute_ms,
                );
                outcomes.push((window, outcome));
            }
            let baseline = outcomes[0].1.quorum_validators;
            let best = outcomes
                .iter()
                .map(|(_, outcome)| outcome.quorum_validators)
                .max()
                .unwrap();
            if best > baseline {
                window_choice_matters = true;
            }
            assert!(
                outcomes
                    .windows(2)
                    .all(|pair| pair[1].1.quorum_validators >= pair[0].1.quorum_validators),
                "larger VRF windows should not reduce quorum reachability in scenario {}",
                scenario.name
            );
        }

        assert!(
            window_choice_matters,
            "stress simulation must include at least one scenario where 500ms is binding"
        );
    }

    #[test]
    #[ignore = "scale-validation decision analysis; run explicitly with --ignored --nocapture"]
    fn vrf_timing_windows_finalization_cost_margin_and_settle() {
        let fanout = derive_consensus_relay_fanout(SIM_VALIDATORS_N200);
        let (hub_graph, _) = sim_build_bootstrap_first_graph(
            SIM_VALIDATORS_N200,
            SIM_TARGET_OUTBOUND,
            SIM_MAX_INBOUND,
        );
        let relay_targets = sim_build_relay_targets(&hub_graph, fanout);

        let normal = sim_scenario("normal_p50");
        let normal_500 = sim_vrf_timing_outcome(&hub_graph, &relay_targets, 500, normal);
        let normal_1500 = sim_vrf_timing_outcome(&hub_graph, &relay_targets, 1_500, normal);
        eprintln!(
            "[vrf-window-final] normal 500ms: quorum_nodes={}/200 window_hits(commit/reveal)={}/{} avg/max_compute_ms={:.1}/{:.1}",
            normal_500.quorum_validators,
            normal_500.commit_window_hits,
            normal_500.reveal_window_hits,
            normal_500.avg_compute_ms,
            normal_500.max_compute_ms,
        );
        eprintln!(
            "[vrf-window-final] normal 1500ms: quorum_nodes={}/200 window_hits(commit/reveal)={}/{} avg/max_compute_ms={:.1}/{:.1} avg_delta_ms={:.1} max_delta_ms={:.1}",
            normal_1500.quorum_validators,
            normal_1500.commit_window_hits,
            normal_1500.reveal_window_hits,
            normal_1500.avg_compute_ms,
            normal_1500.max_compute_ms,
            normal_1500.avg_compute_ms - normal_500.avg_compute_ms,
            normal_1500.max_compute_ms - normal_500.max_compute_ms,
        );
        assert_eq!(normal_500.commit_window_hits, 0);
        assert_eq!(normal_500.reveal_window_hits, 0);
        assert_eq!(normal_1500.commit_window_hits, 0);
        assert_eq!(normal_1500.reveal_window_hits, 0);
        assert!((normal_1500.avg_compute_ms - normal_500.avg_compute_ms).abs() < f64::EPSILON);

        let mut first_break = None;
        for extra_delay in [420.0, 500.0, 600.0, 700.0, 800.0, 900.0, 1_000.0] {
            let scenario = VrfTimingScenario {
                high_stake_slow_region: true,
                message_loss_bps: 100,
                slow_region_delay_ms: extra_delay,
                ..sim_scenario("slow_region_margin_sweep")
            };
            let outcome = sim_vrf_timing_outcome(&hub_graph, &relay_targets, 1_500, scenario);
            eprintln!(
                "[vrf-window-final] 1500ms slow-region delay+{:.0}ms: quorum_nodes={}/200 window_hits(commit/reveal)={}/{} stake_min/med/max={}/{}/{} avg/max_compute_ms={:.1}/{:.1}",
                extra_delay,
                outcome.quorum_validators,
                outcome.commit_window_hits,
                outcome.reveal_window_hits,
                outcome.min_revealed_stake,
                outcome.median_revealed_stake,
                outcome.max_revealed_stake,
                outcome.avg_compute_ms,
                outcome.max_compute_ms,
            );
            if outcome.quorum_validators < SIM_VALIDATORS_N200 && first_break.is_none() {
                first_break = Some(extra_delay);
            }
        }

        for slow_stake in [50, 75, 100] {
            let scenario = VrfTimingScenario {
                high_stake_slow_region: true,
                message_loss_bps: 100,
                slow_region_stake: slow_stake,
                ..sim_scenario("slow_region_stake_sweep")
            };
            let outcome = sim_vrf_timing_outcome(&hub_graph, &relay_targets, 1_500, scenario);
            eprintln!(
                "[vrf-window-final] 1500ms slow-region stake={}x: quorum_nodes={}/200 window_hits(commit/reveal)={}/{} stake_min/med/max={}/{}/{} avg/max_compute_ms={:.1}/{:.1}",
                slow_stake,
                outcome.quorum_validators,
                outcome.commit_window_hits,
                outcome.reveal_window_hits,
                outcome.min_revealed_stake,
                outcome.median_revealed_stake,
                outcome.max_revealed_stake,
                outcome.avg_compute_ms,
                outcome.max_compute_ms,
            );
        }

        let current_reveal_ms = indra_core::types::primitives::VRF_REVEAL_WINDOW_MS;
        let current_settle_ms = indra_core::types::primitives::VRF_ELECTION_SETTLE_MS;
        let current_margin_ms = current_settle_ms.saturating_sub(current_reveal_ms);
        let candidate_reveal_ms = 1_500u64;
        let recommended_settle_ms = candidate_reveal_ms.saturating_add(current_margin_ms);
        eprintln!(
            "[vrf-window-final] settle relation: current_reveal={}ms current_settle={}ms current_margin={}ms candidate_reveal={}ms recommended_settle={}ms first_1500_break_delay={:?}",
            current_reveal_ms,
            current_settle_ms,
            current_margin_ms,
            candidate_reveal_ms,
            recommended_settle_ms,
            first_break,
        );
        assert_eq!(current_margin_ms, 1_000);
        assert_eq!(recommended_settle_ms, 2_500);
    }

    #[test]
    #[ignore = "scale-validation correlated restart simulation; run explicitly with --ignored --nocapture"]
    fn correlated_multi_validator_restart_recovers_bounded_at_n200() {
        let severities = [(50usize, "25%"), (100usize, "50%"), (150usize, "75%")];
        let mut outcomes = Vec::new();
        for (restarted, label) in severities {
            let outcome = sim_correlated_restart_outcome(restarted, 15_000.0);
            eprintln!(
                "[restart-sim] severity={} restarted={}/200 initial_online={} quorum_online_round={:?} quorum_online_time_ms={:?} finalized_round={:?} finalized_via_fallback={} late_local_commit_cases_max={} min_block_reach_after_quorum(2/3/4hops)={}/{}/{} min_online_degree_after_quorum={}",
                label,
                outcome.restarted,
                outcome.initial_online,
                outcome.first_quorum_online_round,
                outcome.quorum_online_time_ms,
                outcome.finalized_round,
                outcome.finalized_via_fallback,
                outcome.max_late_local_commit_cases_in_round,
                outcome.min_block_reach_two_hops_after_quorum,
                outcome.min_block_reach_three_hops_after_quorum,
                outcome.min_block_reach_four_hops_after_quorum,
                outcome.min_online_degree_after_quorum,
            );

            let quorum_round = outcome
                .first_quorum_online_round
                .expect("restart cohort should eventually reconnect enough stake");
            let finalized_round = outcome
                .finalized_round
                .expect("network should recover after enough stake reconnects");
            assert!(
                finalized_round.saturating_sub(quorum_round)
                    <= indra_core::types::primitives::MAX_VRF_EMPTY_REVEAL_ROUNDS,
                "severity {label} should finalize within bounded fallback rounds after online quorum returns"
            );
            assert!(
                outcome.min_block_reach_four_hops_after_quorum >= 134,
                "severity {label} should preserve block relay quorum reach within four hops after reconnect"
            );
            outcomes.push((label, outcome));
        }

        let mut first_extended_unavailability = None;
        for restart_window_ms in [15_000.0, 30_000.0, 60_000.0, 120_000.0, 180_000.0] {
            let outcome = sim_correlated_restart_outcome(150, restart_window_ms);
            eprintln!(
                "[restart-sim:sweep] severity=75% restart_window_ms={:.0} quorum_online_round={:?} quorum_online_time_ms={:?} finalized_round={:?} finalized_via_fallback={}",
                restart_window_ms,
                outcome.first_quorum_online_round,
                outcome.quorum_online_time_ms,
                outcome.finalized_round,
                outcome.finalized_via_fallback,
            );
            if outcome.first_quorum_online_round.is_some_and(|round| {
                round > indra_core::types::primitives::MAX_VRF_EMPTY_REVEAL_ROUNDS
            }) && first_extended_unavailability.is_none()
            {
                first_extended_unavailability = Some(restart_window_ms);
            }
        }
        eprintln!(
            "[restart-sim] first 75% restart window where unavailable stake, not VRF/relay, dominates beyond fallback threshold: {:?}",
            first_extended_unavailability
        );
        assert_eq!(outcomes.len(), 3);
    }

    #[test]
    #[ignore = "release-mode relay verification timing; run explicitly with --ignored --nocapture"]
    fn bench_pre_relay_verification_cost_n200() {
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        let mut keys = Vec::with_capacity(200);
        let mut messages = Vec::with_capacity(800);

        for i in 0..200u16 {
            let mut id_bytes = [0u8; 32];
            id_bytes[..2].copy_from_slice(&i.to_le_bytes());
            let validator_id = Bytes32::from(id_bytes);
            let keypair = hybrid_key((i as u8).wrapping_add(1));
            keys.push(relay_key(validator_id, &keypair));
            messages.push(Message::Vote(signed_vote(validator_id, &keypair)));
            messages.push(Message::Vote(signed_vote(validator_id, &keypair)));
            messages.push(Message::VrfCommit(signed_commit(validator_id, &keypair)));
            messages.push(Message::VrfReveal(signed_reveal(validator_id, &keypair)));
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
        actor.drop_peer(peer, addr_old).await;

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
