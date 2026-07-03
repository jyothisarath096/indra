//! Async peer-manager actor for the authenticated Tokio transport.

use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
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

use indra_core::ssz::sha256;
use indra_core::types::{
    primitives::Bytes32, slash_detector::SlashDetector, slashing::SlashEvidenceV1,
};

use crate::{
    frame::{FrameReader, FrameWriter},
    handshake::HandshakeResult,
    message::Message,
    net_types::{NetworkCommand, NetworkEvent},
    peer::{PeerTable, ScoreEvent, BAN_DURATION_RATE_LIMIT},
    rate_limit::{
        GlobalRateLimiter, MessageClass, PeerRateLimiter, RateLimitReason,
        RateLimitViolation as RateLimitViolationInfo,
    },
};

const SMALL_QUEUE_CAPACITY: usize = 256;
const LARGE_QUEUE_CAPACITY: usize = 4;
const TIE_BREAK_LOG_INTERVAL: Duration = Duration::from_secs(60);
const CONSENSUS_DUPLICATE_FILTER_CAPACITY: usize = 512;
const STATUS_COALESCE_WINDOW: Duration = Duration::from_millis(500);

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
    RateLimitViolation {
        validator_id: Bytes32,
        addr: SocketAddr,
        violation: RateLimitViolationInfo,
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
    global_limiter: GlobalRateLimiter,
    transport_slash_detector: Arc<Mutex<SlashDetector>>,
    last_tie_break_log: HashMap<Bytes32, Instant>,
}

#[derive(Debug, Clone, Copy)]
enum QueueType {
    Small,
    Large,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

struct ConsensusDuplicateFilter {
    seen: VecDeque<ConsensusMessageKey>,
    capacity: usize,
}

impl ConsensusDuplicateFilter {
    fn new(capacity: usize) -> Self {
        Self {
            seen: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn is_duplicate(&mut self, key: ConsensusMessageKey) -> bool {
        if self.seen.contains(&key) {
            return true;
        }
        if self.capacity == 0 {
            return false;
        }
        if self.seen.len() >= self.capacity {
            self.seen.pop_front();
        }
        self.seen.push_back(key);
        false
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.seen.len()
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
    async fn run(mut self) {
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
            }
        }
    }

    async fn handle_command(&mut self, command: NetworkCommand) {
        match command {
            NetworkCommand::Broadcast(msg) => {
                let validators: Vec<Bytes32> = self.peers_by_validator.keys().copied().collect();
                for validator_id in validators {
                    self.try_send_to_validator(
                        validator_id,
                        OutboundMessage {
                            msg: msg.clone(),
                            point_to_point: false,
                        },
                    )
                    .await;
                }
            }
            NetworkCommand::SendTo { validator_id, msg } => {
                self.try_send_to_validator(
                    validator_id,
                    OutboundMessage {
                        msg,
                        point_to_point: true,
                    },
                )
                .await;
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
                    self.peer_table
                        .score_event(&addr, ScoreEvent::InvalidMessage);
                    eprintln!(
                        "[p2p] disconnecting validator {} ({}) for invalid consensus message: {}",
                        short_validator_id(&validator_id),
                        addr,
                        reason
                    );
                    self.drop_peer(validator_id, addr).await;
                }
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
            PeerManagerMessage::RateLimitViolation {
                validator_id,
                addr,
                violation,
            } => {
                if violation.reason == RateLimitReason::Count
                    && violation.class.is_protocol_necessary_for_validators()
                {
                    eprintln!(
                        "[p2p] dropping excess {:?} from authenticated validator {} ({}) — no score penalty",
                        violation.class,
                        short_validator_id(&validator_id),
                        addr,
                    );
                    return;
                }
                self.peer_table.adjust_score_with_duration(
                    &addr,
                    -violation.penalty,
                    BAN_DURATION_RATE_LIMIT,
                );
                if self
                    .peer_table
                    .get(&addr)
                    .map(|peer| peer.is_banned())
                    .unwrap_or(false)
                {
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
            PeerManagerMessage::InboundMessage {
                validator_id,
                addr,
                msg,
                msg_size,
            } => {
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

        let stream = handshake.stream;
        let send_key = handshake.send_key;
        let recv_key = handshake.recv_key;
        let (reader_half, writer_half) = stream.into_split();
        let (small_tx, small_rx) = mpsc::channel(SMALL_QUEUE_CAPACITY);
        let (large_tx, large_rx) = mpsc::channel(LARGE_QUEUE_CAPACITY);
        let control_tx = self.control_tx.clone();
        let event_tx = self.event_tx.clone();
        let transport_slash_detector = Arc::clone(&self.transport_slash_detector);

        let read_task = tokio::spawn(async move {
            let mut reader = FrameReader::new(reader_half, recv_key);
            let mut rate_limiter = PeerRateLimiter::new_for_authenticated_validator();
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
                    Err(_) => break,
                };
                if let Message::Vote(vote) = &msg {
                    if let Some(evidence) = transport_slash_detector
                        .lock()
                        .await
                        .observe_vote(vote.clone())
                    {
                        let wire_evidence = SlashEvidenceV1 {
                            validator_id: evidence.validator_id,
                            vote_1: evidence.vote_a,
                            vote_2: evidence.vote_b,
                        };
                        let _ = event_tx
                            .send(NetworkEvent::SlashDetected(wire_evidence))
                            .await;
                    }
                }
                if let Some(key) = consensus_message_key(&msg) {
                    if duplicate_filter.is_duplicate(key) {
                        continue;
                    }
                }
                if status_coalescer.should_drop(&msg, Instant::now()) {
                    continue;
                }
                if let Some(violation) = rate_limiter.check(&msg, msg_size) {
                    let _ = control_tx
                        .send(PeerManagerMessage::RateLimitViolation {
                            validator_id: peer_validator_id,
                            addr,
                            violation,
                        })
                        .await;
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

        let _ = self.peer_table.add(addr);
        self.peer_table.set_validator_id(&addr, peer_validator_id);
        self.peer_table.mark_connected(&addr);
        self.validator_by_addr.insert(addr, peer_validator_id);
        self.peers_by_validator.insert(
            peer_validator_id,
            ManagedPeer {
                addr,
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
            })
            .await;
    }

    async fn try_send_to_validator(&mut self, validator_id: Bytes32, outbound: OutboundMessage) {
        let Some(peer) = self.peers_by_validator.get(&validator_id) else {
            return;
        };
        let queue_type = message_queue(&outbound.msg);
        let result = match queue_type {
            QueueType::Small => peer.small_tx.try_send(outbound),
            QueueType::Large => peer.large_tx.try_send(outbound),
        };
        match result {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(message)) => {
                if message.point_to_point {
                    self.drop_peer(validator_id, peer.addr).await;
                } else {
                    self.peer_table.score_event(&peer.addr, ScoreEvent::Timeout);
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.drop_peer(validator_id, peer.addr).await;
            }
        }
    }

    async fn drop_peer(&mut self, validator_id: Bytes32, addr: SocketAddr) {
        if let Some(peer) = self.peers_by_validator.get(&validator_id) {
            if peer.addr == addr {
                let peer = self.peers_by_validator.remove(&validator_id).unwrap();
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
        let _ = self
            .event_tx
            .send(NetworkEvent::PeerDisconnected { validator_id, addr })
            .await;
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
    /// Outbound event sink consumed by `indra-node`.
    pub event_tx: mpsc::Sender<NetworkEvent>,
    /// Maximum buffered commands from the node into the actor.
    pub command_buffer: usize,
}

/// Handle returned to callers that need to enqueue network commands or attach peers.
#[derive(Clone)]
pub struct PeerManagerHandle {
    command_tx: mpsc::Sender<NetworkCommand>,
    control_tx: mpsc::Sender<PeerManagerMessage>,
    connected_peers: Arc<AtomicUsize>,
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
}

/// Spawn the peer-manager actor and return its handle.
pub fn spawn_peer_manager(config: PeerManagerConfig) -> PeerManagerHandle {
    let (command_tx, command_rx) = mpsc::channel(config.command_buffer);
    let (control_tx, control_rx) = mpsc::channel(config.command_buffer);
    let connected_peers = Arc::new(AtomicUsize::new(0));
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
        global_limiter: GlobalRateLimiter::new(),
        transport_slash_detector: Arc::new(Mutex::new(SlashDetector::new())),
        last_tie_break_log: HashMap::new(),
    };
    tokio::spawn(actor.run());
    PeerManagerHandle {
        command_tx,
        control_tx,
        connected_peers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::{
        crypto::HybridSignature,
        primitives::VariableBytes,
        vote::{VoteStep, VoteV1},
        vrf_election::VrfCommit,
    };
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
            global_limiter: GlobalRateLimiter::new(),
            transport_slash_detector: Arc::new(Mutex::new(SlashDetector::new())),
            last_tie_break_log: HashMap::new(),
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
        let addr: SocketAddr = "127.0.0.1:32001".parse().unwrap();
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        actor.peer_table.add(addr).unwrap();
        actor.peer_table.set_validator_id(&addr, validator);
        actor.peer_table.mark_connected(&addr);
        let before = actor.peer_table.get(&addr).unwrap().score;

        actor
            .handle_control(PeerManagerMessage::RateLimitViolation {
                validator_id: validator,
                addr,
                violation: RateLimitViolationInfo {
                    class: MessageClass::Status,
                    penalty: 10,
                    reason: RateLimitReason::Count,
                },
            })
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
                .handle_control(PeerManagerMessage::RateLimitViolation {
                    validator_id: validator,
                    addr,
                    violation: RateLimitViolationInfo {
                        class: MessageClass::BlockRequest,
                        penalty: 10,
                        reason: RateLimitReason::Count,
                    },
                })
                .await;
        }

        assert_eq!(actor.peer_table.get(&addr).unwrap().score, before);
        assert!(!actor.peer_table.get(&addr).unwrap().is_banned());
    }

    #[tokio::test]
    async fn authenticated_validator_byte_budget_violation_still_penalizes() {
        let validator = Bytes32::from([0xAC; 32]);
        let addr: SocketAddr = "127.0.0.1:32003".parse().unwrap();
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, Bytes32::from([0x01; 32]));
        actor.peer_table.add(addr).unwrap();
        actor.peer_table.set_validator_id(&addr, validator);
        actor.peer_table.mark_connected(&addr);
        let before = actor.peer_table.get(&addr).unwrap().score;

        actor
            .handle_control(PeerManagerMessage::RateLimitViolation {
                validator_id: validator,
                addr,
                violation: RateLimitViolationInfo {
                    class: MessageClass::BlockResponse,
                    penalty: 10,
                    reason: RateLimitReason::Byte,
                },
            })
            .await;

        assert_eq!(actor.peer_table.get(&addr).unwrap().score, before - 10);
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
