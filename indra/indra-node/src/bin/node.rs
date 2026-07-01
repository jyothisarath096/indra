//! INDRA v2 node binary.
//!
//! Networking runs on a Tokio runtime with authenticated encrypted transport.
//! Consensus and state transition logic remain synchronous on dedicated threads.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex, RwLock,
};
use std::time::{Duration, Instant};

use fs2::available_space;
use indra_core::types::primitives::{
    DEFAULT_PRUNE_KEEP_BLOCKS, DISK_CRITICAL_THRESHOLD_BYTES, DISK_WARN_THRESHOLD_BYTES,
    DNS_SEED_HOSTS, MAX_INBOUND_PEERS, MAX_OBSERVER_CONNECTIONS, MAX_PEER_LIST_SIZE,
    MIN_PRUNE_KEEP_BLOCKS, OBSERVER_PORT, PEER_LIST_INTERVAL_SECS, PEER_TABLE_SAVE_INTERVAL_SECS,
    TARGET_OUTBOUND_PEERS,
};
use indra_crypto::{PqKeypair, PqPublicKey};
use indra_network::{
    message::Message, observer::NODE_TYPE_FULL, perform_handshake_initiator,
    perform_handshake_responder, perform_observer_handshake_responder, read_frame_plain_limited,
    spawn_peer_manager, write_frame_plain, HandshakeConfig, NetworkCommand, NetworkEvent,
    ObserverFrameLimiter, PeerManagerConfig, PeerManagerHandle, TokenBucket,
};
use indra_node::{
    discovery::{
        default_dns_seed_hosts_config, load_peers, peer_list_payload, resolve_dns_seeds,
        resolve_peer_addr, save_peers,
    },
    driver::{ConsensusDriver, DriverAction, DriverEvent, RoundPhase},
    genesis::load_genesis_seed_peers,
    metrics::{record_block_commit, DEFAULT_METRICS_ADDR},
    net_driver::{action_to_message, message_to_event},
    sync::SYNC_BATCH_SIZE,
    KeysData, MetricsState, NodeConfig, NodeConfigFile, NodeEngine,
};
use tokio::runtime::Builder as TokioRuntimeBuilder;
use tokio::sync::mpsc as tokio_mpsc;

const PROPOSE_TIMEOUT: Duration = Duration::from_secs(8);
const PREVOTE_TIMEOUT: Duration = Duration::from_secs(3);
const PRECOMMIT_TIMEOUT: Duration = Duration::from_secs(3);
const MIN_BLOCK_INTERVAL_SECS: u64 = 6;
const DIAL_RETRY: Duration = Duration::from_secs(5);
const STATUS_INTERVAL: Duration = Duration::from_secs(6);
const MAX_DISCOVERED_PEERS: usize = 256;
const OBSERVER_REQUEST_BLOCKS_RATE: u64 = 2;
const OBSERVER_REQUEST_BLOCKS_BURST: u64 = 4;
const MAX_INBOUND_PER_IP: u8 = 3;
const MAX_DIAL_FAILURES_BEFORE_EVICTION: u32 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProposalMode {
    None,
    Fresh,
    Reproposal,
}

#[derive(Clone)]
struct NetworkBridge {
    handle: PeerManagerHandle,
    peer_addrs: Arc<Mutex<HashMap<indra_core::Bytes32, SocketAddr>>>,
    addr_validators: Arc<Mutex<HashMap<SocketAddr, indra_core::Bytes32>>>,
}

impl NetworkBridge {
    fn new(
        handle: PeerManagerHandle,
        peer_addrs: Arc<Mutex<HashMap<indra_core::Bytes32, SocketAddr>>>,
        addr_validators: Arc<Mutex<HashMap<SocketAddr, indra_core::Bytes32>>>,
    ) -> Self {
        Self {
            handle,
            peer_addrs,
            addr_validators,
        }
    }

    fn broadcast(&self, msg: &Message) {
        let _ = self
            .handle
            .send_blocking(NetworkCommand::Broadcast(msg.clone()));
    }

    fn send_to_validator(&self, validator_id: indra_core::Bytes32, msg: &Message) {
        let _ = self.handle.send_blocking(NetworkCommand::SendTo {
            validator_id,
            msg: msg.clone(),
        });
    }

    fn connection_count(&self) -> usize {
        self.handle.connected_peer_count()
    }

    fn connected_addrs(&self) -> Vec<SocketAddr> {
        self.peer_addrs.lock().unwrap().values().copied().collect()
    }

    fn validator_for_addr(&self, addr: &SocketAddr) -> Option<indra_core::Bytes32> {
        self.addr_validators.lock().unwrap().get(addr).copied()
    }
}

fn has_connected_ip(
    connected_addrs: &Arc<Mutex<HashMap<IpAddr, usize>>>,
    addr: &SocketAddr,
) -> bool {
    connected_addrs.lock().unwrap().contains_key(&addr.ip())
}

fn has_connected_ip_from_socket_addrs(connected_addrs: &[SocketAddr], addr: &SocketAddr) -> bool {
    connected_addrs
        .iter()
        .any(|connected| connected.ip() == addr.ip())
}

fn choose_discovery_eviction_candidate(
    discovered_peers: &HashSet<String>,
    authenticated_peer_addrs: &HashSet<String>,
    bootstrap_peers: &HashSet<String>,
    genesis_peer_addrs: &HashSet<String>,
) -> Option<String> {
    let mut unauthenticated_discovered: Vec<String> = discovered_peers
        .iter()
        .filter(|peer| {
            !authenticated_peer_addrs.contains(*peer)
                && !bootstrap_peers.contains(*peer)
                && !genesis_peer_addrs.contains(*peer)
        })
        .cloned()
        .collect();
    unauthenticated_discovered.sort();
    if let Some(peer) = unauthenticated_discovered.into_iter().next() {
        return Some(peer);
    }

    let mut genesis_candidates: Vec<String> = discovered_peers
        .iter()
        .filter(|peer| {
            !authenticated_peer_addrs.contains(*peer) && !bootstrap_peers.contains(*peer)
        })
        .cloned()
        .collect();
    genesis_candidates.sort();
    genesis_candidates.into_iter().next()
}

fn insert_discovered_peer_bounded(
    discovered_peers: &mut HashSet<String>,
    authenticated_peer_addrs: &HashSet<String>,
    bootstrap_peers: &HashSet<String>,
    genesis_peer_addrs: &HashSet<String>,
    peer: String,
) -> bool {
    if discovered_peers.contains(&peer) {
        return false;
    }

    if discovered_peers.len() < MAX_DISCOVERED_PEERS {
        return discovered_peers.insert(peer);
    }

    let Some(evict) = choose_discovery_eviction_candidate(
        discovered_peers,
        authenticated_peer_addrs,
        bootstrap_peers,
        genesis_peer_addrs,
    ) else {
        return false;
    };

    discovered_peers.remove(&evict);
    discovered_peers.insert(peer)
}

fn bounded_discovered_peer_addrs(discovered_peers: &HashSet<String>) -> Vec<SocketAddr> {
    let mut peers: Vec<SocketAddr> = discovered_peers
        .iter()
        .filter_map(|peer| resolve_peer_addr(peer))
        .collect();
    peers.sort();
    peers.dedup();
    peers.truncate(MAX_DISCOVERED_PEERS);
    peers
}

fn reserve_inbound_connection(
    inbound_count: &AtomicU64,
    inbound_by_ip: &Mutex<HashMap<IpAddr, u8>>,
    ip: IpAddr,
) -> bool {
    let mut total = inbound_count.load(Ordering::Relaxed);
    loop {
        if total >= MAX_INBOUND_PEERS as u64 {
            return false;
        }
        match inbound_count.compare_exchange_weak(
            total,
            total + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(next_total) => total = next_total,
        }
    }

    let mut by_ip = inbound_by_ip.lock().unwrap();
    let count = by_ip.entry(ip).or_insert(0);
    if *count >= MAX_INBOUND_PER_IP {
        inbound_count.fetch_sub(1, Ordering::Relaxed);
        return false;
    }
    *count += 1;
    true
}

fn release_inbound_connection(
    inbound_count: &AtomicU64,
    inbound_by_ip: &Mutex<HashMap<IpAddr, u8>>,
    ip: IpAddr,
) {
    inbound_count.fetch_sub(1, Ordering::Relaxed);
    let mut by_ip = inbound_by_ip.lock().unwrap();
    if let Some(count) = by_ip.get_mut(&ip) {
        if *count <= 1 {
            by_ip.remove(&ip);
        } else {
            *count -= 1;
        }
    }
}

fn should_skip_dial_for_connected_validator(
    peer_addr: &str,
    authenticated_addr_validators: &HashMap<String, indra_core::Bytes32>,
    connected_validator_ids: &HashSet<indra_core::Bytes32>,
) -> bool {
    authenticated_addr_validators
        .get(peer_addr)
        .is_some_and(|validator_id| connected_validator_ids.contains(validator_id))
}

fn record_dial_failure(
    peer_addr: &str,
    discovered_peers: &mut HashSet<String>,
    retry_after: &mut HashMap<String, Instant>,
    retry_delay: &mut HashMap<String, Duration>,
    failure_counts: &mut HashMap<String, u32>,
    bootstrap_peer_addrs: &HashSet<String>,
) -> bool {
    let count = failure_counts.entry(peer_addr.to_string()).or_insert(0);
    *count = count.saturating_add(1);
    if *count < MAX_DIAL_FAILURES_BEFORE_EVICTION || bootstrap_peer_addrs.contains(peer_addr) {
        return false;
    }

    discovered_peers.remove(peer_addr);
    retry_after.remove(peer_addr);
    retry_delay.remove(peer_addr);
    failure_counts.remove(peer_addr);
    true
}

fn clear_dial_failure(peer_addr: &str, failure_counts: &mut HashMap<String, u32>) {
    failure_counts.remove(peer_addr);
}

fn is_configured_self_addr(addr: &SocketAddr, local_p2p_addr: &str) -> bool {
    resolve_peer_addr(local_p2p_addr).is_some_and(|local| *addr == local)
}

fn is_address_acceptable_for_discovery(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => {
            !ip.is_loopback()
                && !ip.is_private()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_unicast_link_local()
                && !ip.is_unique_local()
        }
    }
}

fn proposal_matches_request(
    block: &indra_core::types::block::BlockV1,
    height: u64,
    round: u32,
    hash: &indra_core::Bytes32,
) -> bool {
    block.header.height == height
        && block.header.proposer_round == round
        && block.header.block_hash() == *hash
}

fn record_peer_connected_event(
    local_validator_id: indra_core::Bytes32,
    validator_id: indra_core::Bytes32,
    addr: SocketAddr,
    connected_addrs: &Arc<Mutex<HashMap<IpAddr, usize>>>,
    peer_addrs: &Arc<Mutex<HashMap<indra_core::Bytes32, SocketAddr>>>,
    addr_validators: &Arc<Mutex<HashMap<SocketAddr, indra_core::Bytes32>>>,
    discovered_peers: &Arc<Mutex<HashSet<String>>>,
    authenticated_peer_addrs: &Arc<Mutex<HashSet<String>>>,
    authenticated_addr_validators: &Arc<Mutex<HashMap<String, indra_core::Bytes32>>>,
    connected_validator_ids: &Arc<Mutex<HashSet<indra_core::Bytes32>>>,
    bootstrap_peer_addrs: &HashSet<String>,
    genesis_peer_addrs: &HashSet<String>,
    retry_after: &Arc<Mutex<HashMap<String, Instant>>>,
    retry_delay: &Arc<Mutex<HashMap<String, Duration>>>,
    failure_counts: &Arc<Mutex<HashMap<String, u32>>>,
) -> bool {
    if validator_id == local_validator_id {
        eprintln!(
            "[p2p] WARNING: rejected self-connection from {} (own validator_id), not adding to peer table",
            addr
        );
        discovered_peers.lock().unwrap().remove(&addr.to_string());
        authenticated_peer_addrs
            .lock()
            .unwrap()
            .remove(&addr.to_string());
        authenticated_addr_validators
            .lock()
            .unwrap()
            .remove(&addr.to_string());
        retry_after.lock().unwrap().remove(&addr.ip().to_string());
        retry_after.lock().unwrap().remove(&addr.to_string());
        retry_delay.lock().unwrap().remove(&addr.ip().to_string());
        retry_delay.lock().unwrap().remove(&addr.to_string());
        failure_counts.lock().unwrap().remove(&addr.to_string());
        return false;
    }

    *connected_addrs
        .lock()
        .unwrap()
        .entry(addr.ip())
        .or_insert(0) += 1;
    peer_addrs.lock().unwrap().insert(validator_id, addr);
    addr_validators.lock().unwrap().insert(addr, validator_id);
    connected_validator_ids.lock().unwrap().insert(validator_id);
    authenticated_peer_addrs
        .lock()
        .unwrap()
        .insert(addr.to_string());
    authenticated_addr_validators
        .lock()
        .unwrap()
        .insert(addr.to_string(), validator_id);
    let authenticated = authenticated_peer_addrs.lock().unwrap().clone();
    insert_discovered_peer_bounded(
        &mut discovered_peers.lock().unwrap(),
        &authenticated,
        bootstrap_peer_addrs,
        genesis_peer_addrs,
        addr.to_string(),
    );
    retry_after.lock().unwrap().remove(&addr.ip().to_string());
    retry_after.lock().unwrap().remove(&addr.to_string());
    retry_delay.lock().unwrap().remove(&addr.ip().to_string());
    retry_delay.lock().unwrap().remove(&addr.to_string());
    clear_dial_failure(&addr.to_string(), &mut failure_counts.lock().unwrap());
    true
}

fn choose_proposal_mode(
    should_propose: bool,
    valid_reproposal_available: bool,
    proposed_at_slot: Option<(u64, u32)>,
    next_height: u64,
    round: u32,
    already_have_proposal: bool,
) -> ProposalMode {
    if !should_propose {
        ProposalMode::None
    } else if valid_reproposal_available && proposed_at_slot != Some((next_height, round)) {
        ProposalMode::Reproposal
    } else if !already_have_proposal {
        ProposalMode::Fresh
    } else {
        ProposalMode::None
    }
}

fn build_handshake_config(engine: &NodeEngine) -> Option<HandshakeConfig> {
    let my_validator_id = engine.validator_id()?;
    let pq_keypair = match (
        engine.config.pq_pk.as_deref(),
        engine.config.pq_sk.as_deref(),
    ) {
        (Some(pk), Some(sk)) => PqKeypair::from_bytes(pk, sk).ok()?,
        _ => return None,
    };

    let known_validators = engine
        .state
        .validators
        .active_validators()
        .filter_map(|validator| {
            let pq_pk: [u8; indra_crypto::PQ_PK_BYTES] =
                validator.hybrid_pq_pk.as_deref()?.try_into().ok()?;
            Some((validator.validator_id, PqPublicKey(pq_pk)))
        })
        .collect::<Vec<_>>();

    Some(HandshakeConfig {
        my_validator_id,
        my_signing_key: pq_keypair,
        known_validators,
        timeout: Duration::from_secs(10),
    })
}

fn refresh_handshake_config(engine: &NodeEngine, config: &Arc<RwLock<HandshakeConfig>>) {
    if let Some(new_config) = build_handshake_config(engine) {
        *config.write().unwrap() = new_config;
    }
}

fn start_network_runtime(
    p2p_addr: String,
    bootstrap_peers: Vec<String>,
    initial_discovered_peers: Vec<String>,
    peers_file_path: String,
    dns_seed_host: String,
    handshake_config: Arc<RwLock<HandshakeConfig>>,
) -> (
    Arc<NetworkBridge>,
    Arc<Mutex<HashSet<String>>>,
    Arc<Mutex<HashSet<String>>>,
    std::sync::mpsc::Receiver<NetworkEvent>,
) {
    let connected_addrs = Arc::new(Mutex::new(HashMap::<std::net::IpAddr, usize>::new()));
    let peer_addrs = Arc::new(Mutex::new(HashMap::new()));
    let addr_validators = Arc::new(Mutex::new(HashMap::new()));
    let discovered_peers = Arc::new(Mutex::new(HashSet::<String>::new()));
    let authenticated_peer_addrs = Arc::new(Mutex::new(HashSet::<String>::new()));
    let authenticated_addr_validators =
        Arc::new(Mutex::new(HashMap::<String, indra_core::Bytes32>::new()));
    let connected_validator_ids = Arc::new(Mutex::new(HashSet::<indra_core::Bytes32>::new()));
    let bootstrap_peer_addrs =
        Arc::new(bootstrap_peers.iter().cloned().collect::<HashSet<String>>());
    let genesis_peer_addrs = Arc::new(
        initial_discovered_peers
            .iter()
            .cloned()
            .collect::<HashSet<String>>(),
    );
    let (event_tx, event_rx) = std::sync::mpsc::channel::<NetworkEvent>();
    let (handle_tx, handle_rx) = std::sync::mpsc::channel::<PeerManagerHandle>();
    let retry_after = Arc::new(Mutex::new(HashMap::<String, Instant>::new()));
    let retry_delay = Arc::new(Mutex::new(HashMap::<String, Duration>::new()));
    let failure_counts = Arc::new(Mutex::new(HashMap::<String, u32>::new()));
    let handshake_sem = Arc::new(tokio::sync::Semaphore::new(50));
    let inbound_count = Arc::new(AtomicU64::new(0));
    let inbound_by_ip = Arc::new(Mutex::new(HashMap::<IpAddr, u8>::new()));

    std::thread::spawn({
        let connected_addrs = Arc::clone(&connected_addrs);
        let peer_addrs = Arc::clone(&peer_addrs);
        let addr_validators = Arc::clone(&addr_validators);
        let retry_after = Arc::clone(&retry_after);
        let retry_delay = Arc::clone(&retry_delay);
        let handshake_sem = Arc::clone(&handshake_sem);
        let discovered_peers = Arc::clone(&discovered_peers);
        let authenticated_peer_addrs = Arc::clone(&authenticated_peer_addrs);
        let authenticated_addr_validators = Arc::clone(&authenticated_addr_validators);
        let connected_validator_ids = Arc::clone(&connected_validator_ids);
        let bootstrap_peer_addrs = Arc::clone(&bootstrap_peer_addrs);
        let genesis_peer_addrs = Arc::clone(&genesis_peer_addrs);
        let failure_counts = Arc::clone(&failure_counts);
        move || {
            let runtime = TokioRuntimeBuilder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");

            runtime.block_on(async move {
                let (async_event_tx, mut async_event_rx) = tokio_mpsc::channel::<NetworkEvent>(1024);
                let peer_manager = spawn_peer_manager(PeerManagerConfig {
                    local_validator_id: handshake_config.read().unwrap().my_validator_id,
                    event_tx: async_event_tx,
                    command_buffer: 1024,
                });
                let _ = handle_tx.send(peer_manager.clone());

                let network_bridge = PeerManagerHandle::clone(&peer_manager);

                tokio::spawn({
                    let connected_addrs = Arc::clone(&connected_addrs);
                    let peer_addrs = Arc::clone(&peer_addrs);
                    let addr_validators = Arc::clone(&addr_validators);
                    let retry_after = Arc::clone(&retry_after);
                    let retry_delay = Arc::clone(&retry_delay);
                    let discovered_peers = Arc::clone(&discovered_peers);
                    let authenticated_peer_addrs = Arc::clone(&authenticated_peer_addrs);
                    let authenticated_addr_validators = Arc::clone(&authenticated_addr_validators);
                    let connected_validator_ids = Arc::clone(&connected_validator_ids);
                    let bootstrap_peer_addrs = Arc::clone(&bootstrap_peer_addrs);
                    let genesis_peer_addrs = Arc::clone(&genesis_peer_addrs);
                    let failure_counts = Arc::clone(&failure_counts);
                    let handshake_config = Arc::clone(&handshake_config);
                    async move {
                        while let Some(event) = async_event_rx.recv().await {
                            match &event {
                                NetworkEvent::PeerConnected { validator_id, addr } => {
                                    let local_id =
                                        handshake_config.read().unwrap().my_validator_id;
                                    if !record_peer_connected_event(
                                        local_id,
                                        *validator_id,
                                        *addr,
                                        &connected_addrs,
                                        &peer_addrs,
                                        &addr_validators,
                                        &discovered_peers,
                                        &authenticated_peer_addrs,
                                        &authenticated_addr_validators,
                                        &connected_validator_ids,
                                        &bootstrap_peer_addrs,
                                        &genesis_peer_addrs,
                                        &retry_after,
                                        &retry_delay,
                                        &failure_counts,
                                    ) {
                                        continue;
                                    }
                                }
                                NetworkEvent::PeerDisconnected { validator_id, addr } => {
                                    {
                                        let mut ca = connected_addrs.lock().unwrap();
                                        let count = ca.entry(addr.ip()).or_insert(0);
                                        if *count <= 1 {
                                            ca.remove(&addr.ip());
                                            retry_after.lock().unwrap().insert(addr.ip().to_string(), Instant::now() + Duration::from_secs(2));
                                            retry_delay.lock().unwrap().insert(addr.ip().to_string(), Duration::from_secs(2));
                                        } else {
                                            *count -= 1;
                                        }
                                    }
                                    peer_addrs.lock().unwrap().remove(validator_id);
                                    addr_validators.lock().unwrap().remove(addr);
                                    connected_validator_ids.lock().unwrap().remove(validator_id);
                                }
                                NetworkEvent::Message { .. } | NetworkEvent::SlashDetected(_) => {}
                            }
                            let _ = event_tx.send(event);
                        }
                    }
                });

                tokio::spawn({
                    let handshake_config = Arc::clone(&handshake_config);
                    let peer_manager = PeerManagerHandle::clone(&network_bridge);
                    let handshake_sem = Arc::clone(&handshake_sem);
                    let inbound_count = Arc::clone(&inbound_count);
                    let inbound_by_ip = Arc::clone(&inbound_by_ip);
                    let listener_addr = p2p_addr.clone();
                    async move {
                        let listener = match tokio::net::TcpListener::bind(&listener_addr).await {
                            Ok(listener) => listener,
                            Err(e) => {
                                eprintln!("[listener] bind failed: {}", e);
                                return;
                            }
                        };
                        eprintln!("[p2p] listening on {}", listener_addr);

                        loop {
                            let Ok((stream, addr)) = listener.accept().await else {
                                continue;
                            };
                            if !reserve_inbound_connection(&inbound_count, &inbound_by_ip, addr.ip())
                            {
                                eprintln!(
                                    "[p2p] dropping inbound connection from {}: at capacity",
                                    addr
                                );
                                drop(stream);
                                continue;
                            }
                            let permit = match handshake_sem.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    eprintln!("[p2p] handshake limit reached, rejecting connection from {}", addr);
                                    release_inbound_connection(
                                        &inbound_count,
                                        &inbound_by_ip,
                                        addr.ip(),
                                    );
                                    drop(stream);
                                    continue;
                                }
                            };
                            let peer_manager = PeerManagerHandle::clone(&peer_manager);
                            let handshake_config = Arc::clone(&handshake_config);
                            let inbound_count = Arc::clone(&inbound_count);
                            let inbound_by_ip = Arc::clone(&inbound_by_ip);
                            tokio::spawn(async move {
                                let _permit = permit;
                                let config = handshake_config.read().unwrap().clone();
                                match perform_handshake_responder(stream, &config).await {
                                    Ok(handshake) => {
                                        let _ = peer_manager.register_peer(addr, handshake).await;
                                    }
                                    Err(e) => {
                                        eprintln!("[p2p] inbound handshake failed from {}: {}", addr, e);
                                    }
                                }
                                release_inbound_connection(
                                    &inbound_count,
                                    &inbound_by_ip,
                                    addr.ip(),
                                );
                            });
                        }
                    }
                });

                tokio::spawn({
                    let handshake_config = Arc::clone(&handshake_config);
                    let peer_manager = PeerManagerHandle::clone(&network_bridge);
                    let connected_addrs = Arc::clone(&connected_addrs);
                    let retry_after = Arc::clone(&retry_after);
                    let retry_delay = Arc::clone(&retry_delay);
                    let handshake_sem = Arc::clone(&handshake_sem);
                    let discovered_peers = Arc::clone(&discovered_peers);
                    let authenticated_peer_addrs = Arc::clone(&authenticated_peer_addrs);
                    let authenticated_addr_validators = Arc::clone(&authenticated_addr_validators);
                    let connected_validator_ids = Arc::clone(&connected_validator_ids);
                    let bootstrap_peer_addrs = Arc::clone(&bootstrap_peer_addrs);
                    let genesis_peer_addrs = Arc::clone(&genesis_peer_addrs);
                    let peer_addrs = Arc::clone(&peer_addrs);
                    let failure_counts = Arc::clone(&failure_counts);
                    let peers_file_path = peers_file_path.clone();
                    let dns_seed_host = dns_seed_host.clone();
                    let p2p_addr_for_port = p2p_addr.clone();
                    async move {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        let persisted = load_peers(&peers_file_path);
                        {
                            let mut dp = discovered_peers.lock().unwrap();
                            let authenticated = authenticated_peer_addrs.lock().unwrap().clone();
                            for addr in &persisted {
                                insert_discovered_peer_bounded(
                                    &mut dp,
                                    &authenticated,
                                    &bootstrap_peer_addrs,
                                    &genesis_peer_addrs,
                                    addr.to_string(),
                                );
                            }
                            for addr in &initial_discovered_peers {
                                insert_discovered_peer_bounded(
                                    &mut dp,
                                    &authenticated,
                                    &bootstrap_peer_addrs,
                                    &genesis_peer_addrs,
                                    addr.clone(),
                                );
                            }
                        }
                        eprintln!("[discovery] loaded {} persisted peers", persisted.len());
                        let p2p_port = p2p_addr_for_port
                            .rsplit(':')
                            .next()
                            .and_then(|port| port.parse::<u16>().ok())
                            .unwrap_or(30303);
                        let dns_peers = resolve_dns_seeds(&dns_seed_host, p2p_port);
                        {
                            let mut dp = discovered_peers.lock().unwrap();
                            let authenticated = authenticated_peer_addrs.lock().unwrap().clone();
                            for addr in &dns_peers {
                                insert_discovered_peer_bounded(
                                    &mut dp,
                                    &authenticated,
                                    &bootstrap_peer_addrs,
                                    &genesis_peer_addrs,
                                    addr.to_string(),
                                );
                            }
                        }
                        eprintln!("[discovery] {} DNS seed peers discovered", dns_peers.len());

                        const MIN_BACKOFF: Duration = Duration::from_secs(2);
                        const MAX_BACKOFF: Duration = Duration::from_secs(60);
                        let mut last_peer_save = Instant::now();
                        loop {
                            let mut all_peers = bootstrap_peers.clone();
                            {
                                let dp = discovered_peers.lock().unwrap();
                                for peer in dp.iter() {
                                    if !all_peers.contains(peer) {
                                        all_peers.push(peer.clone());
                                    }
                                }
                            }

                            for peer_addr_str in &all_peers {
                                if connected_addrs.lock().unwrap().len() >= TARGET_OUTBOUND_PEERS {
                                    break;
                                }
                                let Some(addr) = resolve_peer_addr(peer_addr_str) else {
                                    eprintln!("[dialer] invalid addr: {}", peer_addr_str);
                                    continue;
                                };
                                if is_configured_self_addr(&addr, &p2p_addr_for_port) {
                                    discovered_peers.lock().unwrap().remove(peer_addr_str);
                                    retry_after.lock().unwrap().remove(peer_addr_str);
                                    retry_delay.lock().unwrap().remove(peer_addr_str);
                                    continue;
                                }
                                if has_connected_ip(&connected_addrs, &addr) {
                                    retry_after.lock().unwrap().remove(peer_addr_str);
                                    retry_delay.lock().unwrap().remove(peer_addr_str);
                                    continue;
                                }
                                if should_skip_dial_for_connected_validator(
                                    peer_addr_str,
                                    &authenticated_addr_validators.lock().unwrap(),
                                    &connected_validator_ids.lock().unwrap(),
                                ) {
                                    retry_after.lock().unwrap().remove(peer_addr_str);
                                    retry_delay.lock().unwrap().remove(peer_addr_str);
                                    continue;
                                }
                                if let Some(next_attempt) = retry_after.lock().unwrap().get(peer_addr_str).copied() {
                                    if Instant::now() < next_attempt {
                                        continue;
                                    }
                                }
                                match tokio::net::TcpStream::connect(addr).await {
                                    Ok(stream) => {
                                        let permit = match handshake_sem.clone().try_acquire_owned() {
                                            Ok(permit) => permit,
                                            Err(_) => {
                                                eprintln!("[p2p] handshake limit reached, deferring outbound connection to {}", addr);
                                                retry_after.lock().unwrap().insert(peer_addr_str.clone(), Instant::now() + MIN_BACKOFF);
                                                continue;
                                            }
                                        };
                                        retry_after.lock().unwrap().remove(peer_addr_str);
                                        retry_delay.lock().unwrap().remove(peer_addr_str);
                                        let peer_manager = PeerManagerHandle::clone(&peer_manager);
                                        let handshake_config = Arc::clone(&handshake_config);
                                        let retry_after = Arc::clone(&retry_after);
                                        let retry_delay = Arc::clone(&retry_delay);
                                        let discovered_peers = Arc::clone(&discovered_peers);
                                        let failure_counts = Arc::clone(&failure_counts);
                                        let bootstrap_peer_addrs = Arc::clone(&bootstrap_peer_addrs);
                                        let peer_key = peer_addr_str.clone();
                                        tokio::spawn(async move {
                                            let _permit = permit;
                                            let config = handshake_config.read().unwrap().clone();
                                            match perform_handshake_initiator(stream, &config).await {
                                                Ok(handshake) => {
                                                    let _ = peer_manager.register_peer(addr, handshake).await;
                                                }
                                                Err(e) => {
                                                    eprintln!("[dialer] handshake failed with {}: {}", addr, e);
                                                    let mut delays = retry_delay.lock().unwrap();
                                                    let current = delays.get(&peer_key).copied().unwrap_or(MIN_BACKOFF);
                                                    let next = (current * 2).min(MAX_BACKOFF);
                                                    delays.insert(peer_key.clone(), next);
                                                    drop(delays);
                                                    retry_after
                                                        .lock()
                                                        .unwrap()
                                                        .insert(peer_key.clone(), Instant::now() + current);
                                                    if record_dial_failure(
                                                        &peer_key,
                                                        &mut discovered_peers.lock().unwrap(),
                                                        &mut retry_after.lock().unwrap(),
                                                        &mut retry_delay.lock().unwrap(),
                                                        &mut failure_counts.lock().unwrap(),
                                                        &bootstrap_peer_addrs,
                                                    ) {
                                                        eprintln!(
                                                            "[p2p] evicting permanently unreachable peer {} after {} failures",
                                                            peer_key,
                                                            MAX_DIAL_FAILURES_BEFORE_EVICTION
                                                        );
                                                    }
                                                }
                                            }
                                        });
                                    }
                                    Err(e) => {
                                        eprintln!("[dialer] failed to connect to {}: {}", addr, e);
                                        let mut delays = retry_delay.lock().unwrap();
                                        let current = delays.get(peer_addr_str).copied().unwrap_or(MIN_BACKOFF);
                                        let next = (current * 2).min(MAX_BACKOFF);
                                        delays.insert(peer_addr_str.clone(), next);
                                        drop(delays);
                                        retry_after
                                            .lock()
                                            .unwrap()
                                            .insert(peer_addr_str.clone(), Instant::now() + current);
                                        if record_dial_failure(
                                            peer_addr_str,
                                            &mut discovered_peers.lock().unwrap(),
                                            &mut retry_after.lock().unwrap(),
                                            &mut retry_delay.lock().unwrap(),
                                            &mut failure_counts.lock().unwrap(),
                                            &bootstrap_peer_addrs,
                                        ) {
                                            eprintln!(
                                                "[p2p] evicting permanently unreachable peer {} after {} failures",
                                                peer_addr_str,
                                                MAX_DIAL_FAILURES_BEFORE_EVICTION
                                            );
                                        }
                                    }
                                }
                            }
                            if last_peer_save.elapsed().as_secs() >= PEER_TABLE_SAVE_INTERVAL_SECS {
                                let mut peers_to_save: Vec<SocketAddr> =
                                    bounded_discovered_peer_addrs(&discovered_peers.lock().unwrap());
                                peers_to_save.extend(peer_addrs.lock().unwrap().values().copied());
                                peers_to_save.sort();
                                peers_to_save.dedup();
                                peers_to_save.truncate(MAX_DISCOVERED_PEERS);
                                save_peers(&peers_file_path, &peers_to_save);
                                last_peer_save = Instant::now();
                            }
                            tokio::time::sleep(DIAL_RETRY).await;
                        }
                    }
                });

                tokio::spawn({
                    let discovered_peers = Arc::clone(&discovered_peers);
                    let peer_addrs = Arc::clone(&peer_addrs);
                    let peers_file_path = peers_file_path.clone();
                    async move {
                        if tokio::signal::ctrl_c().await.is_ok() {
                            let mut peers_to_save: Vec<SocketAddr> =
                                bounded_discovered_peer_addrs(&discovered_peers.lock().unwrap());
                            peers_to_save.extend(peer_addrs.lock().unwrap().values().copied());
                            peers_to_save.sort();
                            peers_to_save.dedup();
                            peers_to_save.truncate(MAX_DISCOVERED_PEERS);
                            save_peers(&peers_file_path, &peers_to_save);
                            eprintln!(
                                "[discovery] saved {} peers before shutdown",
                                peers_to_save.len()
                            );
                            std::process::exit(0);
                        }
                    }
                });

                std::future::pending::<()>().await;
            });
        }
    });

    let peer_manager = handle_rx.recv().expect("peer manager handle");
    let bridge = Arc::new(NetworkBridge::new(
        peer_manager,
        peer_addrs,
        addr_validators,
    ));

    (bridge, discovered_peers, authenticated_peer_addrs, event_rx)
}

fn start_observer_runtime(
    observer_addr: String,
    driver: Arc<Mutex<ConsensusDriver>>,
    observer_count: Arc<AtomicUsize>,
) {
    std::thread::spawn(move || {
        let runtime = TokioRuntimeBuilder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        runtime.block_on(async move {
            let listener = match tokio::net::TcpListener::bind(&observer_addr).await {
                Ok(listener) => listener,
                Err(e) => {
                    eprintln!("[observer] bind failed on {}: {}", observer_addr, e);
                    return;
                }
            };
            eprintln!("[observer] listening on {}", observer_addr);

            let (block_tx, _) =
                tokio::sync::broadcast::channel::<indra_core::types::block::BlockV1>(64);
            tokio::spawn(observer_block_poller(Arc::clone(&driver), block_tx.clone()));

            loop {
                let (stream, addr) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        eprintln!("[observer] accept error: {}", e);
                        continue;
                    }
                };
                let driver = Arc::clone(&driver);
                let observer_count = Arc::clone(&observer_count);
                let mut block_rx = block_tx.subscribe();
                tokio::spawn(async move {
                    if let Err(e) = handle_observer_connection(
                        stream,
                        addr,
                        driver,
                        observer_count,
                        &mut block_rx,
                    )
                    .await
                    {
                        eprintln!("[observer] connection {} closed: {}", addr, e);
                    }
                });
            }
        });
    });
}

async fn observer_block_poller(
    driver: Arc<Mutex<ConsensusDriver>>,
    block_tx: tokio::sync::broadcast::Sender<indra_core::types::block::BlockV1>,
) {
    let mut last_height = driver.lock().unwrap().height();
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let (current_height, blocks) = {
            let mut d = driver.lock().unwrap();
            let current_height = d.height();
            let mut blocks = Vec::new();
            if current_height > last_height {
                for height in last_height.saturating_add(1)..=current_height {
                    if let Ok(block) = d.engine.block_store.get(height) {
                        blocks.push(block);
                    }
                }
            }
            (current_height, blocks)
        };
        for block in blocks {
            let _ = block_tx.send(block);
        }
        last_height = current_height;
    }
}

async fn handle_observer_connection(
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    driver: Arc<Mutex<ConsensusDriver>>,
    observer_count: Arc<AtomicUsize>,
    block_rx: &mut tokio::sync::broadcast::Receiver<indra_core::types::block::BlockV1>,
) -> indra_network::NetworkResult<()> {
    let result = perform_observer_handshake_responder(stream, NODE_TYPE_FULL).await?;
    let mut stream = result.stream;
    let status = current_status_message(&driver);
    write_message_plain(&mut stream, &status).await?;

    if observer_count.load(Ordering::Relaxed) >= MAX_OBSERVER_CONNECTIONS {
        eprintln!(
            "[observer] at capacity ({}), sending status and closing {}",
            MAX_OBSERVER_CONNECTIONS, addr
        );
        return Ok(());
    }

    let total = observer_count.fetch_add(1, Ordering::Relaxed) + 1;
    eprintln!("[observer] new connection from {} (total: {})", addr, total);
    let (mut reader, mut writer) = stream.into_split();
    let (write_tx, mut write_rx) = tokio::sync::mpsc::channel::<Message>(64);
    let mut frame_limiter = ObserverFrameLimiter::new();
    let mut request_blocks_limiter =
        TokenBucket::new(OBSERVER_REQUEST_BLOCKS_RATE, OBSERVER_REQUEST_BLOCKS_BURST);

    let writer_task = tokio::spawn(async move {
        while let Some(msg) = write_rx.recv().await {
            if write_message_plain(&mut writer, &msg).await.is_err() {
                break;
            }
        }
    });

    loop {
        tokio::select! {
            frame = read_frame_plain_limited(&mut reader, &mut frame_limiter) => {
                let frame = frame?;
                let msg = Message::decode_wire(&frame)?;
                match msg {
                    Message::RequestBlocks { from_height, to_height } => {
                        if !observer_request_blocks_allowed(&mut request_blocks_limiter) {
                            eprintln!(
                                "[observer] rate-limited RequestBlocks from {}",
                                addr
                            );
                            let _ = write_tx.send(Message::BlockResponse { blocks: Vec::new() }).await;
                            continue;
                        }
                        let blocks = observer_blocks_for_range(&driver, from_height, to_height);
                        let _ = write_tx.send(Message::BlockResponse { blocks }).await;
                    }
                    Message::Status { height, .. } => {
                        eprintln!("[observer] {} status height={}", addr, height);
                    }
                    Message::Ping(nonce) => {
                        let _ = write_tx.send(Message::Pong(nonce)).await;
                    }
                    Message::Pong(_) | Message::PeerList(_) => {}
                    Message::Vote(_)
                    | Message::RequestProposal { .. }
                    | Message::RequestQC { .. }
                    | Message::QCResponse { .. } => {
                        eprintln!("[observer] consensus message from {}, closing", addr);
                        break;
                    }
                    Message::Block(_) | Message::BlockResponse { .. } | Message::Tx(_) => {}
                }
            }
            block = block_rx.recv() => {
                match block {
                    Ok(block) => {
                        let _ = write_tx.send(Message::Block(block)).await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    drop(write_tx);
    let _ = writer_task.await;
    let remaining = observer_count
        .fetch_sub(1, Ordering::Relaxed)
        .saturating_sub(1);
    eprintln!(
        "[observer] peer disconnected {} (total: {})",
        addr, remaining
    );
    Ok(())
}

fn observer_request_blocks_allowed(limiter: &mut TokenBucket) -> bool {
    limiter.try_consume(1)
}

fn current_status_message(driver: &Arc<Mutex<ConsensusDriver>>) -> Message {
    let d = driver.lock().unwrap();
    Message::Status {
        height: d.height(),
        tip_hash: d.engine.state.tip_hash,
        round: d.current_round(),
    }
}

fn observer_blocks_for_range(
    driver: &Arc<Mutex<ConsensusDriver>>,
    from_height: u64,
    to_height: u64,
) -> Vec<indra_core::types::block::BlockV1> {
    let mut d = driver.lock().unwrap();
    let end = to_height.min(
        from_height
            .saturating_add(SYNC_BATCH_SIZE)
            .saturating_sub(1),
    );
    (from_height..=end)
        .filter_map(|height| d.engine.block_store.get(height).ok())
        .collect()
}

async fn write_message_plain<W>(writer: &mut W, msg: &Message) -> indra_network::NetworkResult<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let wire = msg.encode_wire()?;
    write_frame_plain(writer, &wire[4..]).await
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let get_arg = |flag: &str| -> Option<String> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    if args.iter().any(|arg| arg == "--init") {
        run_init();
        return;
    }
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return;
    }
    let config_path = get_arg("--config");
    let mut cfg_file = if let Some(ref path) = config_path {
        NodeConfigFile::load(Path::new(path)).unwrap_or_else(|e| {
            eprintln!("ERROR: {}", e);
            std::process::exit(1);
        })
    } else {
        NodeConfigFile::default()
    };

    if let Some(v) = get_arg("--data-dir") {
        cfg_file.data_dir = Some(v);
    }
    if let Some(v) = get_arg("--genesis") {
        cfg_file.genesis = Some(v);
    }
    if let Some(v) = get_arg("--keys") {
        cfg_file.keys_path = Some(v);
    }
    if let Some(v) = get_arg("--p2p-addr") {
        cfg_file.p2p_addr = Some(v);
    }
    if let Some(v) = get_arg("--observer-addr") {
        cfg_file.observer_addr = Some(v);
    }
    if let Some(v) = get_arg("--metrics-addr") {
        cfg_file.metrics_addr = Some(v);
        cfg_file.metrics_enabled = Some(true);
    }
    if let Some(v) = get_arg("--rpc-addr") {
        cfg_file.rpc_addr = Some(v);
    }
    if args.iter().any(|a| a == "--no-observer-port") {
        cfg_file.observer_addr = Some(String::new());
    }
    if args.iter().any(|a| a == "--no-metrics") {
        cfg_file.metrics_enabled = Some(false);
    }
    if args.iter().any(|a| a == "--archive") {
        cfg_file.prune_keep_blocks = Some(0);
    }
    if let Some(v) = get_arg("--prune-keep").and_then(|s| s.parse::<u64>().ok()) {
        cfg_file.prune_keep_blocks = Some(v);
    }
    if let Some(v) = get_arg("--bootstrap-peers") {
        cfg_file.bootstrap_peers = v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(v) = get_arg("--seeds") {
        cfg_file.dns_seed_host = Some(v);
    }
    if let Some(v) = get_arg("--peers-file") {
        cfg_file.peers_file = Some(v);
    }
    if config_path.is_some() {
        if let Err(errors) = cfg_file.validate() {
            eprintln!("ERROR: config.toml validation failed:");
            for err in &errors {
                eprintln!("  - {}", err);
            }
            std::process::exit(1);
        }
    } else {
        cfg_file.mode.get_or_insert_with(|| "validator".to_string());
        cfg_file
            .data_dir
            .get_or_insert_with(|| "./indra-data".to_string());
        cfg_file
            .genesis
            .get_or_insert_with(|| "genesis.toml".to_string());
        cfg_file
            .keys_path
            .get_or_insert_with(|| "keys.json".to_string());
    }

    let keys_path = cfg_file
        .keys_path
        .clone()
        .unwrap_or_else(|| "keys.json".to_string());
    let data_dir = cfg_file
        .data_dir
        .clone()
        .unwrap_or_else(|| "./indra-data".to_string());
    let p2p_addr = cfg_file
        .p2p_addr
        .clone()
        .unwrap_or_else(|| "0.0.0.0:30303".to_string());
    let observer_addr = match cfg_file.observer_addr.as_deref() {
        Some("") => None,
        Some(addr) => Some(addr.to_string()),
        None => Some(format!("0.0.0.0:{}", OBSERVER_PORT)),
    };
    let metrics_addr = if cfg_file.metrics_enabled == Some(false) {
        None
    } else {
        match cfg_file.metrics_addr.as_deref() {
            Some("") => None,
            Some(addr) => Some(addr.to_string()),
            None => Some(DEFAULT_METRICS_ADDR.to_string()),
        }
    };
    let dns_seed_host = cfg_file
        .dns_seed_host
        .clone()
        .unwrap_or_else(default_dns_seed_hosts_config);
    let prune_keep_cfg = cfg_file
        .prune_keep_blocks
        .unwrap_or(DEFAULT_PRUNE_KEEP_BLOCKS);
    let archive = prune_keep_cfg == 0;
    let prune_keep = if archive {
        0
    } else {
        prune_keep_cfg.max(MIN_PRUNE_KEEP_BLOCKS)
    };

    eprintln!("╔══════════════════════════════════════════╗");
    eprintln!("║      INDRA v2 — Phase 8 Node Starting     ║");
    eprintln!("╚══════════════════════════════════════════╝");
    eprintln!("Keys:      {}", keys_path);
    eprintln!("Data:      {}", data_dir);
    eprintln!("P2P:       {}", p2p_addr);
    eprintln!(
        "Observer:  {}",
        observer_addr.as_deref().unwrap_or("(disabled)")
    );
    eprintln!(
        "Metrics:   {}",
        metrics_addr.as_deref().unwrap_or("(disabled)")
    );
    eprintln!("Mode:      {}", if archive { "archive" } else { "pruned" });
    if !archive {
        eprintln!("Retain:    {} blocks", prune_keep);
    }

    check_disk_space(Path::new(&data_dir));

    // Load keys
    let keys_data = load_keys_data(&keys_path);

    let bootstrap_peers: Vec<String> = if cfg_file.bootstrap_peers.is_empty() {
        eprintln!("Bootstrap: (none; DNS/persisted/genesis discovery enabled)");
        vec![]
    } else {
        eprintln!("Bootstrap: {}", cfg_file.bootstrap_peers.join(","));
        cfg_file.bootstrap_peers.clone()
    };
    let genesis_path = cfg_file
        .genesis
        .clone()
        .unwrap_or_else(|| "genesis.toml".to_string());
    let peers_file = cfg_file.peers_file.clone().unwrap_or_else(|| {
        Path::new(&data_dir)
            .join("peers.json")
            .to_string_lossy()
            .to_string()
    });
    let genesis_seed_peers = load_genesis_seed_peers(&genesis_path);
    if !genesis_seed_peers.is_empty() {
        eprintln!(
            "[discovery] loaded {} peer hints from genesis",
            genesis_seed_peers.len()
        );
    }

    let config = NodeConfig {
        data_dir: std::path::PathBuf::from(&data_dir),
        genesis_path: Some(genesis_path),
        validator_seed: Some(keys_data.hybrid_seed),
        bls_seed: Some(keys_data.bls_seed),
        vrf_seed: Some(keys_data.vrf_seed),
        pq_sk: if keys_data.pq_sk.is_empty() {
            None
        } else {
            Some(keys_data.pq_sk)
        },
        pq_pk: if keys_data.pq_pk.is_empty() {
            None
        } else {
            Some(keys_data.pq_pk)
        },
        p2p_addr: p2p_addr.clone(),
        bootstrap_peers: bootstrap_peers.clone(),
        dns_seed_host: dns_seed_host.clone(),
        peers_file: peers_file.clone(),
        snapshot_interval: cfg_file.snapshot_interval.unwrap_or(300),
        mempool_capacity: cfg_file.mempool_capacity.unwrap_or(5_000),
        prune_keep_blocks: if archive { None } else { Some(prune_keep) },
        observer_addr: observer_addr.clone(),
        metrics_addr: metrics_addr.clone(),
    };

    // Init node engine + consensus driver
    let engine = NodeEngine::init(config).unwrap_or_else(|e| panic!("Node init failed: {}", e));

    eprintln!(
        "Validator set: {} active validators",
        engine.state.validators.active_count()
    );

    let validator_id = engine
        .validator_id()
        .map(|id| hex::encode(id.0))
        .unwrap_or_else(|| "full-node".to_string());

    eprintln!("\nChain:     {}", engine.state.chain_id);
    eprintln!("Validator: {}...", &validator_id[..16]);
    eprintln!("Height:    {}", engine.height());
    eprintln!("\nStarting P2P and consensus...\n");

    let vote_safety = indra_storage::VoteSafetyStore::open(engine.config.vote_safety_path());
    let mut driver_state = ConsensusDriver::new(engine, vote_safety);
    driver_state.refresh_registered_voters();
    let startup_qc_request = driver_state.request_qc_if_needed();
    let handshake_config = build_handshake_config(&driver_state.engine)
        .map(|config| Arc::new(RwLock::new(config)))
        .unwrap_or_else(|| panic!("authenticated transport requires validator networking keys"));
    let driver = driver_state;

    // Shared state between threads
    let driver = Arc::new(Mutex::new(driver));
    let (height_tx, height_rx) = std::sync::mpsc::channel::<()>();
    let observer_count = Arc::new(AtomicUsize::new(0));
    let connected_validator_peers = Arc::new(AtomicUsize::new(0));
    let metrics_state = Arc::new(MetricsState::new());
    let last_block_timestamp = Arc::new(AtomicU64::new(0));
    let (gossip, discovered_peers, authenticated_peer_addrs, network_events) =
        start_network_runtime(
            p2p_addr.clone(),
            bootstrap_peers.clone(),
            genesis_seed_peers.clone(),
            peers_file.clone(),
            dns_seed_host.clone(),
            Arc::clone(&handshake_config),
        );
    if let Some(addr) = observer_addr {
        start_observer_runtime(addr, Arc::clone(&driver), Arc::clone(&observer_count));
    }
    if let Some(addr) = metrics_addr {
        indra_node::start_metrics_server(
            addr,
            Arc::clone(&driver),
            Arc::clone(&observer_count),
            Arc::clone(&metrics_state),
            Arc::clone(&last_block_timestamp),
            Arc::clone(&connected_validator_peers),
            data_dir.clone(),
            env!("CARGO_PKG_VERSION").to_string(),
        );
    }

    // ── Thread 3: Authenticated network event loop ──────────────────────────
    {
        let gossip = Arc::clone(&gossip);
        let driver = Arc::clone(&driver);
        let height_tx = height_tx.clone();
        let handshake_config = Arc::clone(&handshake_config);
        let discovered_peers = Arc::clone(&discovered_peers);
        let authenticated_peer_addrs = Arc::clone(&authenticated_peer_addrs);
        let bootstrap_peer_addrs = bootstrap_peers.iter().cloned().collect::<HashSet<String>>();
        let genesis_peer_addrs = genesis_seed_peers
            .iter()
            .cloned()
            .collect::<HashSet<String>>();
        let local_p2p_addr = p2p_addr.clone();
        let connected_validator_peers = Arc::clone(&connected_validator_peers);
        let metrics_state = Arc::clone(&metrics_state);
        let last_block_timestamp = Arc::clone(&last_block_timestamp);

        std::thread::spawn(move || {
            while let Ok(event) = network_events.recv() {
                connected_validator_peers.store(gossip.connection_count(), Ordering::Relaxed);
                match event {
                    NetworkEvent::PeerConnected { validator_id, addr } => {
                        connected_validator_peers
                            .store(gossip.connection_count(), Ordering::Relaxed);
                        eprintln!("[p2p] authenticated peer connected: {}", addr);
                        let known_addrs = peer_list_payload(
                            gossip.connected_addrs(),
                            Some(addr),
                            &HashSet::new(),
                        );
                        if !known_addrs.is_empty() {
                            gossip.send_to_validator(validator_id, &Message::PeerList(known_addrs));
                        }
                        announce_status_and_recovery(
                            &driver,
                            &gossip,
                            &height_tx,
                            &handshake_config,
                            validator_id,
                            &metrics_state,
                            &last_block_timestamp,
                        );
                    }
                    NetworkEvent::PeerDisconnected { addr, .. } => {
                        connected_validator_peers
                            .store(gossip.connection_count(), Ordering::Relaxed);
                        eprintln!("[p2p] peer disconnected: {}", addr);
                    }
                    NetworkEvent::SlashDetected(evidence) => {
                        metrics_state
                            .slash_events_total
                            .fetch_add(1, Ordering::Relaxed);
                        let mut d = driver.lock().unwrap();
                        d.engine.add_slash_evidence(evidence);
                    }
                    NetworkEvent::Message {
                        from: addr,
                        validator_id,
                        msg,
                    } => {
                        match &msg {
                            Message::PeerList(addrs) => {
                                let mut new_peers = discovered_peers.lock().unwrap();
                                let authenticated =
                                    authenticated_peer_addrs.lock().unwrap().clone();
                                let mut accepted = 0usize;
                                for addr_str in addrs.iter().take(MAX_PEER_LIST_SIZE) {
                                    let Some(addr) = resolve_peer_addr(addr_str) else {
                                        continue;
                                    };
                                    if !is_configured_self_addr(&addr, &local_p2p_addr)
                                        && is_address_acceptable_for_discovery(&addr)
                                        && !has_connected_ip_from_socket_addrs(
                                            &gossip.connected_addrs(),
                                            &addr,
                                        )
                                    {
                                        if insert_discovered_peer_bounded(
                                            &mut new_peers,
                                            &authenticated,
                                            &bootstrap_peer_addrs,
                                            &genesis_peer_addrs,
                                            addr.to_string(),
                                        ) {
                                            accepted = accepted.saturating_add(1);
                                        }
                                    }
                                }
                                eprintln!(
                                    "[discovery] received {} peer addresses from {} (accepted {})",
                                    addrs.len(),
                                    addr,
                                    accepted
                                );
                                continue;
                            }
                            Message::RequestBlocks {
                                from_height,
                                to_height,
                            } => {
                                let upper = (*to_height)
                                    .min((*from_height).saturating_add(SYNC_BATCH_SIZE - 1));
                                let blocks_to_send = {
                                    let mut d = driver.lock().unwrap();
                                    let mut blocks = Vec::new();
                                    for height in *from_height..=upper {
                                        match d.engine.block_store.get(height) {
                                            Ok(block) => blocks.push(block),
                                            Err(_) => break,
                                        }
                                    }
                                    blocks
                                };
                                gossip.send_to_validator(
                                    validator_id,
                                    &Message::BlockResponse {
                                        blocks: blocks_to_send,
                                    },
                                );
                                continue;
                            }
                            Message::RequestProposal {
                                height,
                                round,
                                hash,
                            } => {
                                let proposal = {
                                    let mut d = driver.lock().unwrap();
                                    d.pending_block(hash)
                                        .or_else(|| d.engine.block_store.get(*height).ok())
                                        .filter(|block| {
                                            proposal_matches_request(block, *height, *round, hash)
                                        })
                                };
                                if let Some(block) = proposal {
                                    gossip.send_to_validator(validator_id, &Message::Block(block));
                                }
                                continue;
                            }
                            Message::BlockResponse { blocks } => {
                                let response_blocks = blocks.clone();
                                let request_more;
                                let mut caught_up_height = None;
                                let mut imported_any = false;
                                let mut qc_recovery_actions = Vec::new();
                                {
                                    let mut d = driver.lock().unwrap();
                                    for block in response_blocks {
                                        if block.header.height != d.height() + 1 {
                                            continue;
                                        }

                                        match d.engine.commit_block(&block) {
                                            Ok(()) => {
                                                imported_any = true;
                                                record_block_commit(
                                                    &metrics_state,
                                                    &last_block_timestamp,
                                                );
                                                refresh_handshake_config(
                                                    &d.engine,
                                                    &handshake_config,
                                                );
                                                d.refresh_registered_voters();
                                                d.sync_mut().on_block_imported(block.header.height);
                                                d.reset_round();
                                                if d.clear_last_qc_if_stale() {
                                                    eprintln!(
                                                        "[sync] imported height={} with stale last_qc_bytes — clearing and recovering QC for new tip",
                                                        block.header.height,
                                                    );
                                                }
                                                if should_log_sync_height(block.header.height) {
                                                    eprintln!(
                                                        "[sync] imported block at height={} from {}",
                                                        block.header.height,
                                                        addr
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!(
                                                    "[sync] failed to import block {} from {}: {}",
                                                    block.header.height, addr, e
                                                );
                                                break;
                                            }
                                        }
                                    }
                                    if !imported_any {
                                        let current_height = d.height();
                                        d.sync_mut().on_empty_response(current_height);
                                    }
                                    let new_height = d.height();
                                    request_more =
                                        d.sync_mut().next_request_after_response(new_height);
                                    if d.sync().is_caught_up() {
                                        d.on_sync_caught_up();
                                        qc_recovery_actions = d.request_qc_if_needed();
                                        caught_up_height = Some(new_height);
                                    }
                                }

                                if let Some((peer, from_height, to_height)) = request_more {
                                    let req = Message::RequestBlocks {
                                        from_height,
                                        to_height,
                                    };
                                    if let Some(peer_validator_id) =
                                        gossip.validator_for_addr(&peer)
                                    {
                                        gossip.send_to_validator(peer_validator_id, &req);
                                    }
                                }
                                if imported_any {
                                    let _ = height_tx.send(());
                                    broadcast_status(&driver, &gossip);
                                }
                                if !qc_recovery_actions.is_empty() {
                                    process_driver_actions(
                                        &driver,
                                        &gossip,
                                        &height_tx,
                                        &handshake_config,
                                        caught_up_height.unwrap_or_default(),
                                        qc_recovery_actions,
                                        &metrics_state,
                                        &last_block_timestamp,
                                    );
                                }
                                if let Some(height) = caught_up_height {
                                    eprintln!(
                                        "[sync] caught up to height={}, joining consensus",
                                        height
                                    );
                                }
                                continue;
                            }
                            Message::Ping(_) => {
                                let (height, tip_hash, round) = {
                                    let d = driver.lock().unwrap();
                                    (d.height(), d.engine.state.tip_hash, d.current_round())
                                };
                                gossip.send_to_validator(
                                    validator_id,
                                    &Message::Status {
                                        height,
                                        tip_hash,
                                        round,
                                    },
                                );
                                continue;
                            }
                            _ => {}
                        }

                        if let Some(event) = message_to_event(msg, addr) {
                            let previous_height = driver.lock().unwrap().height();
                            let actions = driver.lock().unwrap().process(event);
                            process_driver_actions(
                                &driver,
                                &gossip,
                                &height_tx,
                                &handshake_config,
                                previous_height,
                                actions,
                                &metrics_state,
                                &last_block_timestamp,
                            );
                            let new_height = driver.lock().unwrap().height();
                            if new_height > previous_height {
                                refresh_handshake_config(
                                    &driver.lock().unwrap().engine,
                                    &handshake_config,
                                );
                                let _ = height_tx.send(());
                                broadcast_status(&driver, &gossip);
                            }
                        }
                    }
                }
            }
        });
    }

    // ── Thread 4: Consensus loop ────────────────────────────────────────────
    {
        let driver = Arc::clone(&driver);
        let gossip = Arc::clone(&gossip);
        let height_tx = height_tx.clone();
        let handshake_config = Arc::clone(&handshake_config);
        let height_rx = height_rx;
        let metrics_state = Arc::clone(&metrics_state);
        let last_block_timestamp = Arc::clone(&last_block_timestamp);

        std::thread::spawn(move || {
            // Wait for peer connections to establish
            std::thread::sleep(Duration::from_secs(3));

            let mut proposed_at_slot: Option<(u64, u32)> = None;
            let mut last_commit_time: Option<std::time::SystemTime> = None;
            let mut last_observed_height = 0u64;
            let mut phase_started_at = Instant::now();
            let mut last_observed = None::<(u64, u32, RoundPhase)>;
            let mut last_status_at = Instant::now() - STATUS_INTERVAL;
            let mut last_peer_wait_log = None::<usize>;

            loop {
                let (height, round, phase, sync_target, sync_caught_up, connected, tip_hash) = {
                    let d = driver.lock().unwrap();
                    (
                        d.height(),
                        d.current_round(),
                        d.current_phase(),
                        d.sync().target_height(),
                        d.sync().is_caught_up(),
                        gossip.connection_count(),
                        d.engine.state.tip_hash,
                    )
                };
                let last_qc_bytes_empty = driver.lock().unwrap().last_qc_bytes().is_empty();
                if height > last_observed_height {
                    last_commit_time = Some(std::time::SystemTime::now());
                    last_observed_height = height;
                }

                if last_qc_bytes_empty && round % 10 == 0 {
                    let actions = driver.lock().unwrap().request_qc_if_needed();
                    if !actions.is_empty() {
                        process_driver_actions(
                            &driver,
                            &gossip,
                            &height_tx,
                            &handshake_config,
                            height,
                            actions,
                            &metrics_state,
                            &last_block_timestamp,
                        );
                    }
                }

                let observed = (height, round, phase);
                if last_observed != Some(observed) {
                    phase_started_at = Instant::now();
                    if last_observed.map(|(h, r, _)| (h, r)) != Some((height, round)) {
                        proposed_at_slot = None;
                    }
                    last_observed = Some(observed);
                }

                if connected < 2 {
                    if last_peer_wait_log != Some(connected) {
                        eprintln!("[consensus] waiting for peers (have {}, need 2)", connected);
                        last_peer_wait_log = Some(connected);
                    }
                    phase_started_at = Instant::now();
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
                last_peer_wait_log = None;

                if last_status_at.elapsed() >= STATUS_INTERVAL {
                    let status = Message::Status {
                        height,
                        tip_hash,
                        round,
                    };
                    gossip.broadcast(&status);
                    last_status_at = Instant::now();
                }

                if !sync_caught_up {
                    match height_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(()) => {
                            phase_started_at = Instant::now();
                            proposed_at_slot = None;
                        }
                        Err(_) => {}
                    }
                    continue;
                }

                if sync_target.is_none() {
                    match phase {
                        RoundPhase::Propose => {
                            let (should_propose, next_height) = {
                                let d = driver.lock().unwrap();
                                let epoch_seed = indra_core::types::primitives::Bytes32::from(
                                    indra_crypto::sha256(&d.engine.state.tip_hash.0),
                                );
                                let height = d.engine.state.height + 1;
                                let round = d.current_round();
                                let candidates: Vec<indra_consensus::proposer::ProposerCandidate> =
                                    d.engine
                                        .state
                                        .validators
                                        .active_validators()
                                        .filter_map(|v| {
                                            v.vrf_pk.map(|vrf_pk| {
                                                indra_consensus::proposer::ProposerCandidate {
                                                    validator_id: v.validator_id,
                                                    vrf_pubkey: vrf_pk,
                                                    verified_vrf_output: None,
                                                    stake: v.stake_spark,
                                                }
                                            })
                                        })
                                        .collect();

                                if candidates.is_empty() {
                                    (
                                        d.can_propose()
                                            && d.engine.config.bootstrap_peers.is_empty(),
                                        height,
                                    )
                                } else {
                                    let election = indra_consensus::proposer::ProposerElection {
                                        epoch_seed,
                                        height,
                                        round,
                                        candidates,
                                    };
                                    (d.can_propose() && d.engine.is_proposer(&election), height)
                                }
                            };

                            let already_have_proposal = proposed_at_slot
                                == Some((next_height, round))
                                || driver
                                    .lock()
                                    .unwrap()
                                    .has_accepted_proposal_for_height(next_height);
                            let valid_reproposal = if should_propose {
                                driver.lock().unwrap().take_valid_block_for_reproposal()
                            } else {
                                None
                            };
                            let proposal_mode = choose_proposal_mode(
                                should_propose,
                                valid_reproposal.is_some(),
                                proposed_at_slot,
                                next_height,
                                round,
                                already_have_proposal,
                            );

                            if matches!(
                                proposal_mode,
                                ProposalMode::Fresh | ProposalMode::Reproposal
                            ) {
                                let time_since_last_commit = last_commit_time
                                    .and_then(|t| t.elapsed().ok())
                                    .unwrap_or(Duration::from_secs(MIN_BLOCK_INTERVAL_SECS));

                                if time_since_last_commit
                                    < Duration::from_secs(MIN_BLOCK_INTERVAL_SECS)
                                    && time_since_last_commit
                                        < Duration::from_secs(MIN_BLOCK_INTERVAL_SECS * 2)
                                {
                                    match height_rx.recv_timeout(Duration::from_millis(100)) {
                                        Ok(()) => {
                                            phase_started_at = Instant::now();
                                            proposed_at_slot = None;
                                        }
                                        Err(_) => {}
                                    }
                                    continue;
                                }

                                let proposal = {
                                    let mut d = driver.lock().unwrap();
                                    let epoch_seed = indra_core::types::primitives::Bytes32::from(
                                        indra_crypto::sha256(&d.engine.state.tip_hash.0),
                                    );
                                    let height = d.engine.state.height + 1;
                                    let round = d.current_round();
                                    let candidates: Vec<
                                        indra_consensus::proposer::ProposerCandidate,
                                    > = d
                                        .engine
                                        .state
                                        .validators
                                        .active_validators()
                                        .filter_map(|v| {
                                            v.vrf_pk.map(|vrf_pk| {
                                                indra_consensus::proposer::ProposerCandidate {
                                                    validator_id: v.validator_id,
                                                    vrf_pubkey: vrf_pk,
                                                    verified_vrf_output: None,
                                                    stake: v.stake_spark,
                                                }
                                            })
                                        })
                                        .collect();
                                    let election = indra_consensus::proposer::ProposerElection {
                                        epoch_seed,
                                        height,
                                        round,
                                        candidates,
                                    };
                                    let timestamp = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    let polc_round = d.proposal_polc_round(height);
                                    let last_qc_bytes = d.last_qc_bytes();
                                    let proposal_result =
                                        if matches!(proposal_mode, ProposalMode::Reproposal) {
                                            let (valid_block, valid_round) = valid_reproposal
                                                .expect("reproposal mode requires a valid block");
                                            d.engine.repropose(
                                                &valid_block,
                                                round,
                                                Some(valid_round),
                                                &election,
                                                valid_block.header.timestamp,
                                                last_qc_bytes,
                                            )
                                        } else {
                                            d.engine.propose(
                                                &election,
                                                timestamp,
                                                last_qc_bytes,
                                                polc_round,
                                            )
                                        };
                                    match proposal_result {
                                        Ok(block) => {
                                            let actions = d.process(DriverEvent::InboundBlock {
                                                from: None,
                                                block: block.clone(),
                                            });
                                            Some((block, actions))
                                        }
                                        Err(indra_node::error::NodeError::MissingQc { height }) => {
                                            eprintln!(
                                                "[consensus] proposal skipped at height {}: no QC for previous block",
                                                height
                                            );
                                            None
                                        }
                                        Err(e) => {
                                            eprintln!("[consensus] proposal failed: {}", e);
                                            None
                                        }
                                    }
                                };

                                if let Some((block, actions)) = proposal {
                                    proposed_at_slot =
                                        Some((block.header.height, block.header.proposer_round));
                                    process_driver_actions(
                                        &driver,
                                        &gossip,
                                        &height_tx,
                                        &handshake_config,
                                        height,
                                        actions,
                                        &metrics_state,
                                        &last_block_timestamp,
                                    );
                                }
                            }

                            if phase_started_at.elapsed() >= PROPOSE_TIMEOUT {
                                let actions = driver.lock().unwrap().on_propose_timeout();
                                process_driver_actions(
                                    &driver,
                                    &gossip,
                                    &height_tx,
                                    &handshake_config,
                                    height,
                                    actions,
                                    &metrics_state,
                                    &last_block_timestamp,
                                );
                                phase_started_at = Instant::now();
                            }
                        }
                        RoundPhase::Prevote => {
                            if phase_started_at.elapsed() >= PREVOTE_TIMEOUT {
                                let actions = driver.lock().unwrap().on_prevote_timeout();
                                process_driver_actions(
                                    &driver,
                                    &gossip,
                                    &height_tx,
                                    &handshake_config,
                                    height,
                                    actions,
                                    &metrics_state,
                                    &last_block_timestamp,
                                );
                                phase_started_at = Instant::now();
                            }
                        }
                        RoundPhase::Precommit => {
                            if phase_started_at.elapsed() >= PRECOMMIT_TIMEOUT {
                                let (old_round, height_before) = {
                                    let d = driver.lock().unwrap();
                                    (d.current_round(), d.height())
                                };
                                {
                                    let mut d = driver.lock().unwrap();
                                    d.on_precommit_timeout();
                                    if d.current_round() != old_round && d.current_round() > 0 {
                                        eprintln!(
                                            "[timing] t={}ms ROUND ADVANCED to {} at height={}",
                                            now_ms(),
                                            d.current_round(),
                                            height_before,
                                        );
                                    }
                                }
                                phase_started_at = Instant::now();
                            }
                        }
                    }
                }

                match height_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(()) => {
                        phase_started_at = Instant::now();
                        proposed_at_slot = None;
                    }
                    Err(_) => {}
                }
            }
        });
    }

    if !startup_qc_request.is_empty() {
        let current_height = driver.lock().unwrap().height();
        process_driver_actions(
            &driver,
            &gossip,
            &height_tx,
            &handshake_config,
            current_height,
            startup_qc_request,
            &metrics_state,
            &last_block_timestamp,
        );
    }

    // ── Thread 5: RPC server ────────────────────────────────────────────────
    // Inline HTTP/JSON-RPC handler — avoids circular dependency with indra-rpc.
    // Reads chain state directly from the driver under a brief lock.
    {
        let driver_rpc = Arc::clone(&driver);
        let gossip_rpc = Arc::clone(&gossip);
        let discovered_peers_rpc = Arc::clone(&discovered_peers);
        let observer_count_rpc = Arc::clone(&observer_count);
        let rpc_addr = get_arg("--rpc-addr").unwrap_or_else(|| "127.0.0.1:8545".to_string());
        eprintln!("[rpc] listening on {}", rpc_addr);

        std::thread::spawn(move || {
            let listener = match std::net::TcpListener::bind(&rpc_addr) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[rpc] bind failed: {}", e);
                    return;
                }
            };
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let driver_rpc = Arc::clone(&driver_rpc);
                        let gossip_rpc = Arc::clone(&gossip_rpc);
                        let discovered_peers_rpc = Arc::clone(&discovered_peers_rpc);
                        let observer_count_rpc = Arc::clone(&observer_count_rpc);
                        std::thread::spawn(move || {
                            handle_rpc(
                                stream,
                                &driver_rpc,
                                &gossip_rpc,
                                &discovered_peers_rpc,
                                &observer_count_rpc,
                            );
                        });
                    }
                    Err(e) => eprintln!("[rpc] accept error: {}", e),
                }
            }
        });
    }

    // ── Main thread: status printer ─────────────────────────────────────────
    let mut last_height = 0u64;
    let mut tick = 0u64;

    loop {
        std::thread::sleep(STATUS_INTERVAL);
        tick += 1;

        let (height, base_fee, mempool, peers) = {
            let d = driver.lock().unwrap();
            (
                d.height(),
                d.engine.state.base_fee,
                d.engine.mempool.len(),
                gossip.connection_count(),
            )
        };

        let new_blocks = height.saturating_sub(last_height);
        let progress = if new_blocks > 0 {
            format!(" [+{} blocks]", new_blocks)
        } else {
            String::new()
        };

        println!(
            "[tick {}] height={}{} base_fee={} mempool={} txs peers={}",
            tick, height, progress, base_fee, mempool, peers
        );

        if tick.is_multiple_of(10) {
            check_disk_space(Path::new(&data_dir));
        }

        let peer_list_ticks = (PEER_LIST_INTERVAL_SECS / STATUS_INTERVAL.as_secs()).max(1);
        if tick.is_multiple_of(peer_list_ticks) {
            let known_addrs = peer_list_payload(gossip.connected_addrs(), None, &HashSet::new());
            if !known_addrs.is_empty() {
                gossip.broadcast(&Message::PeerList(known_addrs));
            }
        }

        last_height = height;
    }
}

fn broadcast_driver_message(gossip: &Arc<NetworkBridge>, _action: &DriverAction, msg: &Message) {
    gossip.broadcast(msg);
}

fn process_driver_actions(
    driver: &Arc<Mutex<ConsensusDriver>>,
    gossip: &Arc<NetworkBridge>,
    height_tx: &std::sync::mpsc::Sender<()>,
    handshake_config: &Arc<RwLock<HandshakeConfig>>,
    previous_height: u64,
    actions: Vec<DriverAction>,
    metrics_state: &Arc<MetricsState>,
    last_block_timestamp: &Arc<AtomicU64>,
) {
    let mut recorded_commit = false;
    for action in actions {
        if let DriverAction::ActivateBufferedProposal(block) = action {
            let actions2 = driver
                .lock()
                .unwrap()
                .process(DriverEvent::InboundBlock { from: None, block });
            process_driver_actions(
                driver,
                gossip,
                height_tx,
                handshake_config,
                previous_height,
                actions2,
                metrics_state,
                last_block_timestamp,
            );
            let new_height = driver.lock().unwrap().height();
            if new_height > previous_height {
                refresh_handshake_config(&driver.lock().unwrap().engine, handshake_config);
                if !recorded_commit {
                    record_block_commit(metrics_state, last_block_timestamp);
                    recorded_commit = true;
                }
                let _ = height_tx.send(());
                broadcast_status(driver, gossip);
            }
            continue;
        }

        if let DriverAction::RequestQC { height } = &action {
            let peers: Vec<SocketAddr> = gossip.connected_addrs();
            eprintln!(
                "[driver] requesting QC for height {} from {} peers",
                height,
                peers.len()
            );
            let msg = Message::RequestQC { height: *height };
            for peer in &peers {
                if let Some(peer_validator_id) = gossip.validator_for_addr(peer) {
                    gossip.send_to_validator(peer_validator_id, &msg);
                }
            }
            continue;
        }

        if let DriverAction::SlashDetected(slash_evidence) = &action {
            metrics_state
                .slash_events_total
                .fetch_add(1, Ordering::Relaxed);
            let wire_evidence = indra_core::types::slashing::SlashEvidenceV1 {
                validator_id: slash_evidence.validator_id,
                vote_1: slash_evidence.vote_a.clone(),
                vote_2: slash_evidence.vote_b.clone(),
            };
            let mut d = driver.lock().unwrap();
            d.engine.add_slash_evidence(wire_evidence);
            eprintln!(
                "[slash] equivocation detected from validator {} — evidence queued",
                hex::encode(&slash_evidence.validator_id.0[..4])
            );
            continue;
        }

        if let Some(out_msg) = action_to_message(&action) {
            if let DriverAction::BroadcastVote(vote) = &action {
                eprintln!(
                    "[vote] broadcasting {:?} for height={} round={}",
                    vote.step, vote.height, vote.round,
                );
            }
            broadcast_driver_message(gossip, &action, &out_msg);
        }

        if let DriverAction::RequestBlocks {
            from,
            from_height,
            to_height,
        } = &action
        {
            if should_log_sync_height(*from_height)
                || to_height.saturating_sub(*from_height) < SYNC_BATCH_SIZE
            {
                eprintln!(
                    "[sync] requesting blocks {}..{} from {}",
                    from_height, to_height, from
                );
            }
            let req = Message::RequestBlocks {
                from_height: *from_height,
                to_height: *to_height,
            };
            if let Some(peer_validator_id) = gossip.validator_for_addr(from) {
                gossip.send_to_validator(peer_validator_id, &req);
            }
        }

        if let DriverAction::RequestProposal {
            from,
            height,
            round,
            hash,
        } = &action
        {
            let req = Message::RequestProposal {
                height: *height,
                round: *round,
                hash: *hash,
            };
            if let Some(peer_validator_id) = gossip.validator_for_addr(from) {
                gossip.send_to_validator(peer_validator_id, &req);
            }
        }

        if let DriverAction::SendQCResponse {
            to,
            height,
            qc_bytes,
        } = &action
        {
            let msg = Message::QCResponse {
                height: *height,
                qc_bytes: qc_bytes.clone(),
            };
            if let Some(peer_validator_id) = gossip.validator_for_addr(to) {
                gossip.send_to_validator(peer_validator_id, &msg);
            }
        }

        let new_height = driver.lock().unwrap().height();
        if new_height > previous_height && !recorded_commit {
            record_block_commit(metrics_state, last_block_timestamp);
            recorded_commit = true;
        }
    }
}

fn announce_status_and_recovery(
    driver: &Arc<Mutex<ConsensusDriver>>,
    gossip: &Arc<NetworkBridge>,
    height_tx: &std::sync::mpsc::Sender<()>,
    handshake_config: &Arc<RwLock<HandshakeConfig>>,
    validator_id: indra_core::Bytes32,
    metrics_state: &Arc<MetricsState>,
    last_block_timestamp: &Arc<AtomicU64>,
) {
    let (height, tip_hash) = {
        let d = driver.lock().unwrap();
        (d.height(), d.engine.state.tip_hash)
    };
    let [status, ping] = startup_peer_messages(height, tip_hash);
    gossip.send_to_validator(validator_id, &status);
    gossip.send_to_validator(validator_id, &ping);
    broadcast_status(driver, gossip);

    let actions = driver.lock().unwrap().request_qc_if_needed();
    process_driver_actions(
        driver,
        gossip,
        height_tx,
        handshake_config,
        height,
        actions,
        metrics_state,
        last_block_timestamp,
    );
}

fn startup_peer_messages(height: u64, tip_hash: indra_core::Bytes32) -> [Message; 2] {
    [
        Message::Status {
            height,
            tip_hash,
            round: 0,
        },
        Message::Ping(now_ms() as u64),
    ]
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn should_log_sync_height(height: u64) -> bool {
    height <= 5 || height.is_multiple_of(100)
}

fn broadcast_status(driver: &Arc<Mutex<ConsensusDriver>>, gossip: &Arc<NetworkBridge>) {
    let (height, tip_hash, round) = {
        let d = driver.lock().unwrap();
        (d.height(), d.engine.state.tip_hash, d.current_round())
    };
    let status = Message::Status {
        height,
        tip_hash,
        round,
    };
    gossip.broadcast(&status);
}

fn check_disk_space(data_dir: &Path) -> u64 {
    let available = available_space(data_dir).unwrap_or(0);
    if available > 0 && available < DISK_CRITICAL_THRESHOLD_BYTES {
        eprintln!(
            "[disk] CRITICAL: only {} MB remaining",
            available / 1024 / 1024
        );
    } else if available > 0 && available < DISK_WARN_THRESHOLD_BYTES {
        eprintln!(
            "[disk] WARNING: only {} GB remaining",
            available / 1024 / 1024 / 1024
        );
    }
    available
}

fn print_help() {
    println!("Usage: indra-node [--config <path>] [flags]");
    println!();
    println!("  --config <path>         Load configuration from config.toml");
    println!("  --init                  Generate a config.toml interactively");
    println!("  --help                  Show this help");
    println!();
    println!("All flags below override the corresponding config.toml field:");
    println!("  --keys <path>");
    println!("  --data-dir <path>");
    println!("  --genesis <path>");
    println!("  --p2p-addr <host:port>");
    println!("  --observer-addr <host:port>");
    println!("  --no-observer-port");
    println!("  --rpc-addr <host:port>");
    println!("  --metrics-addr <addr>");
    println!("  --no-metrics");
    println!("  --bootstrap-peers <addr,addr,...>");
    println!("  --seeds <hostname>");
    println!("  --prune-keep <blocks>");
    println!("  --archive");
    println!("  --peers-file <path>");
}

fn run_init() {
    let name = prompt_default("Validator name (e.g. your name or city)", "validator");
    let data_dir = prompt_default("Data directory", "/root/.indra/data");
    let default_keys = Path::new(&data_dir)
        .join("keys.json")
        .to_string_lossy()
        .to_string();
    let keys_file = prompt_default("Keys file", &default_keys);
    let default_genesis = Path::new(&data_dir)
        .join("genesis.toml")
        .to_string_lossy()
        .to_string();
    let genesis_file = prompt_default("Genesis file", &default_genesis);
    let bootstrap_peers = prompt_default(
        "Bootstrap peers (comma-separated, leave blank for bootstrap node)",
        "",
    );
    let metrics_addr = prompt_default("Metrics address", "0.0.0.0:9615");
    let rpc_addr = prompt_default("RPC address", "127.0.0.1:8545");
    let prune_keep = prompt_default("Prune keep blocks [50000, 0=archive]", "50000");
    let config_path = Path::new(&data_dir).join("config.toml");
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        eprintln!("ERROR: cannot create data directory {}: {}", data_dir, e);
        std::process::exit(1);
    }
    let bootstrap_toml = bootstrap_peers_toml(&bootstrap_peers);
    let config = format!(
        r#"# INDRA Node Configuration
# Generated by: indra-node --init
# Version: {}

[node]
mode     = "validator"
chain_id = "indra-testnet-1"
data_dir = "{}"
genesis  = "{}"

[keys]
path = "{}"

[network]
p2p_addr        = "0.0.0.0:30303"
observer_addr   = "0.0.0.0:{}"
bootstrap_peers = {}
dns_seed_host   = "{}"
peers_file      = "{}/peers.json"

[rpc]
addr    = "{}"
enabled = true

[metrics]
addr    = "{}"
enabled = true

[storage]
prune_keep_blocks = {}
snapshot_interval = 300
mempool_capacity  = 5000
"#,
        env!("CARGO_PKG_VERSION"),
        toml_escape(&data_dir),
        toml_escape(&genesis_file),
        toml_escape(&keys_file),
        OBSERVER_PORT,
        bootstrap_toml,
        DNS_SEED_HOSTS.join(","),
        toml_escape(&data_dir),
        toml_escape(&rpc_addr),
        toml_escape(&metrics_addr),
        prune_keep
    );
    if let Err(e) = std::fs::write(&config_path, config) {
        eprintln!("ERROR: cannot write {}: {}", config_path.display(), e);
        std::process::exit(1);
    }
    println!("══════════════════════════════════════════");
    println!("  config.toml written to: {}", config_path.display());
    println!("  Validator name: {}", name);
    println!("══════════════════════════════════════════");
    println!();
    println!("  Systemd service file (copy to /etc/systemd/system/indra-node.service):");
    println!("  ─────────────────────────────────────────────────────────────────────");
    println!("  [Unit]");
    println!("  Description=INDRA Validator Node");
    println!("  After=network-online.target");
    println!("  Wants=network-online.target");
    println!();
    println!("  [Service]");
    println!("  Type=simple");
    println!("  User=root");
    println!(
        "  ExecStart=/root/.indra/bin/indra-node --config {}",
        config_path.display()
    );
    println!("  Restart=always");
    println!("  RestartSec=5");
    println!("  LimitNOFILE=65536");
    println!("  StandardOutput=journal");
    println!("  StandardError=journal");
    println!("  SyslogIdentifier=indra-node");
    println!();
    println!("  [Install]");
    println!("  WantedBy=multi-user.target");
    println!("  ─────────────────────────────────────────────────────────────────────");
    println!();
    println!("  Next steps:");
    println!("  1. sudo tee /etc/systemd/system/indra-node.service");
    println!("  2. sudo systemctl daemon-reload");
    println!("  3. sudo systemctl enable indra-node");
    println!("  4. sudo systemctl start indra-node");
    println!("══════════════════════════════════════════");
}

fn prompt_default(prompt: &str, default: &str) -> String {
    if default.is_empty() {
        print!("{}: ", prompt);
    } else {
        print!("{} [{}]: ", prompt, default);
    }
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return default.to_string();
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

fn bootstrap_peers_toml(raw: &str) -> String {
    let peers: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!("\"{}\"", toml_escape(s)))
        .collect();
    if peers.is_empty() {
        "[]".to_string()
    } else {
        format!("[{}]", peers.join(", "))
    }
}

fn toml_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn load_keys_data(keys_path: &str) -> KeysData {
    let keys_str = std::fs::read_to_string(keys_path)
        .unwrap_or_else(|e| panic!("Cannot read {}: {}", keys_path, e));
    KeysData {
        hybrid_seed: extract_hex32(&keys_str, "hybrid_seed"),
        bls_seed: extract_hex32(&keys_str, "bls_seed"),
        vrf_seed: extract_hex32(&keys_str, "vrf_seed"),
        pq_sk: extract_hex_field(&keys_str, "pq_sk"),
        pq_pk: extract_hex_field(&keys_str, "hybrid_pq_pk"),
    }
}

fn extract_hex_field(json: &str, field: &str) -> Vec<u8> {
    let key = format!("\"{}\":", field);
    let pos = match json.find(&key) {
        Some(p) => p,
        None => return vec![],
    };
    let after = &json[pos + key.len()..];
    let start = after.find('"').unwrap_or(0) + 1;
    let end = after[start..].find('"').unwrap_or(0) + start;
    hex::decode(&after[start..end]).unwrap_or_default()
}

fn extract_hex32(json: &str, field: &str) -> [u8; 32] {
    let key = format!("\"{}\":", field);
    let pos = json
        .find(&key)
        .unwrap_or_else(|| panic!("Field '{}' not found in keys.json", field));
    let after = &json[pos + key.len()..];
    let start = after.find('"').unwrap() + 1;
    let end = after[start..].find('"').unwrap() + start;
    let hex_str = &after[start..end];
    let bytes =
        hex::decode(hex_str).unwrap_or_else(|_| panic!("Invalid hex for field '{}'", field));
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    arr
}

/// Inline JSON-RPC handler for the node binary.
///
/// Reads one HTTP request, dispatches to the appropriate chain query,
/// and writes the JSON response. Locks the driver only for the duration
/// of the state read — not while writing the HTTP response.
fn handle_rpc(
    stream: std::net::TcpStream,
    driver: &Arc<Mutex<indra_node::driver::ConsensusDriver>>,
    gossip: &Arc<NetworkBridge>,
    discovered_peers: &Arc<Mutex<HashSet<String>>>,
    observer_count: &Arc<AtomicUsize>,
) {
    use indra_rpc::handlers::{dispatch, DispatchResult, NodeState};
    use indra_rpc::types::{parse_request, RpcResponse};
    use std::io::{BufRead, BufReader, Read};

    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));

    let mut reader = match stream.try_clone() {
        Ok(stream) => BufReader::new(stream),
        Err(_) => return,
    };

    let mut content_length = 0usize;
    let mut is_options = false;
    let mut line = String::new();
    let mut first_line = true;

    loop {
        line.clear();
        if reader.read_line(&mut line).is_err() {
            return;
        }
        let trimmed = line.trim();
        if first_line {
            is_options = trimmed.starts_with("OPTIONS");
            first_line = false;
        }
        if trimmed.is_empty() {
            break;
        }
        if trimmed.to_lowercase().starts_with("content-length:") {
            content_length = trimmed["content-length:".len()..]
                .trim()
                .parse()
                .unwrap_or(0);
        }
    }

    let cors = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n";

    if is_options {
        let resp = format!(
            "HTTP/1.1 204 No Content\r\n{}Connection: close\r\n\r\n",
            cors
        );
        let _ = stream
            .try_clone()
            .map(|mut writer| writer.write_all(resp.as_bytes()));
        return;
    }

    if content_length == 0 {
        let body = r#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"empty body"},"id":null}"#;
        send_http(&stream, cors, body);
        return;
    }

    let mut body_bytes = vec![0u8; content_length.min(1_048_576)];
    if reader.read_exact(&mut body_bytes).is_err() {
        return;
    }
    let body_str = String::from_utf8_lossy(&body_bytes);

    let req = match parse_request(&body_str) {
        Ok(request) => request,
        Err(_) => {
            let body =
                r#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"parse error"},"id":null}"#;
            send_http(&stream, cors, body);
            return;
        }
    };

    let response_body = {
        let mut guard = driver.lock().unwrap();
        let validator_peer_addrs: Vec<String> = gossip
            .connected_addrs()
            .iter()
            .map(|addr| addr.to_string())
            .collect();
        let discovered_count = discovered_peers.lock().unwrap().len();
        let observer_count_val = observer_count.load(Ordering::Relaxed);

        let state = NodeState::with_network(
            &guard.engine,
            validator_peer_addrs,
            discovered_count,
            observer_count_val,
        );

        match dispatch(&req.method, &req.params, &state) {
            DispatchResult::Ready(Ok(result)) => RpcResponse::ok(req.id.clone(), result).to_json(),
            DispatchResult::Ready(Err(error)) => {
                RpcResponse::err(req.id.clone(), error.code(), error.message().to_string())
                    .to_json()
            }
            DispatchResult::SubmitStakingOp(op_bytes) => {
                use indra_core::codec::Decode;
                use indra_core::types::staking::StakingOp;
                match StakingOp::decode_exact(&op_bytes) {
                    Ok(op) => match guard.engine.add_staking_op(op) {
                        Ok(()) => {
                            RpcResponse::ok(req.id.clone(), r#"{"status":"accepted"}"#.to_string())
                                .to_json()
                        }
                        Err(error) => {
                            RpcResponse::err(req.id.clone(), -32000, format!("rejected: {error}"))
                                .to_json()
                        }
                    },
                    Err(error) => RpcResponse::err(
                        req.id.clone(),
                        -32602,
                        format!("staking op decode failed: {error}"),
                    )
                    .to_json(),
                }
            }
            DispatchResult::SubmitGovernanceOp(op_bytes) => {
                use indra_core::codec::Decode;
                use indra_core::types::governance::GovernanceOpV2;
                match GovernanceOpV2::decode_exact(&op_bytes) {
                    Ok(op) => match guard.engine.add_governance_op(op) {
                        Ok(()) => {
                            RpcResponse::ok(req.id.clone(), r#"{"status":"accepted"}"#.to_string())
                                .to_json()
                        }
                        Err(error) => {
                            RpcResponse::err(req.id.clone(), -32000, format!("rejected: {error}"))
                                .to_json()
                        }
                    },
                    Err(error) => RpcResponse::err(
                        req.id.clone(),
                        -32602,
                        format!("governance op decode failed: {error}"),
                    )
                    .to_json(),
                }
            }
            DispatchResult::SubmitTransaction(tx_bytes) => {
                use indra_core::codec::{ByteReader, Decode};
                use indra_core::types::transaction::TransactionV1;
                let mut reader = ByteReader::new(&tx_bytes);
                match TransactionV1::decode(&mut reader) {
                    Ok(tx) => {
                        let state = guard.engine.state.clone();
                        match guard.engine.mempool.submit_validated(tx.clone(), &state) {
                            Ok(tx_id) => {
                                gossip.broadcast(&Message::Tx(tx));
                                RpcResponse::ok(
                                    req.id.clone(),
                                    format!(
                                        r#"{{"tx_id":"{}","status":"accepted"}}"#,
                                        hex::encode(tx_id.0)
                                    ),
                                )
                                .to_json()
                            }
                            Err(error) => RpcResponse::err(
                                req.id.clone(),
                                -32000,
                                format!("mempool rejected: {error}"),
                            )
                            .to_json(),
                        }
                    }
                    Err(error) => RpcResponse::err(
                        req.id.clone(),
                        -32602,
                        format!("tx decode failed: {error}"),
                    )
                    .to_json(),
                }
            }
        }
    };

    send_http(&stream, cors, &response_body);
}

fn send_http(stream: &std::net::TcpStream, cors: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        cors,
        body.len(),
        body
    );
    let _ = stream
        .try_clone()
        .map(|mut writer| writer.write_all(response.as_bytes()));
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_broadcast_on_first_peer_connection() {
        let tip_hash = indra_core::Bytes32::from([0x55u8; 32]);
        let [first, second] = startup_peer_messages(42, tip_hash);

        assert!(
            matches!(first, Message::Status { height: 42, tip_hash: got, .. } if got == tip_hash)
        );
        assert!(matches!(second, Message::Ping(_)));
    }

    #[test]
    fn stale_staged_proposal_does_not_block_valid_reproposal() {
        let mode = choose_proposal_mode(true, true, None, 10, 3, true);

        assert_eq!(mode, ProposalMode::Reproposal);
    }

    #[test]
    fn peer_connected_event_for_own_validator_id_is_rejected() {
        let local = indra_core::Bytes32::from([0x42; 32]);
        let addr: SocketAddr = "127.0.0.1:32782".parse().unwrap();
        let connected_addrs = Arc::new(Mutex::new(HashMap::<IpAddr, usize>::new()));
        let peer_addrs = Arc::new(Mutex::new(HashMap::<indra_core::Bytes32, SocketAddr>::new()));
        let addr_validators =
            Arc::new(Mutex::new(HashMap::<SocketAddr, indra_core::Bytes32>::new()));
        let discovered_peers = Arc::new(Mutex::new(HashSet::from([addr.to_string()])));
        let authenticated_peer_addrs = Arc::new(Mutex::new(HashSet::new()));
        let authenticated_addr_validators =
            Arc::new(Mutex::new(HashMap::<String, indra_core::Bytes32>::new()));
        let connected_validator_ids = Arc::new(Mutex::new(HashSet::<indra_core::Bytes32>::new()));
        let bootstrap_peer_addrs = HashSet::new();
        let genesis_peer_addrs = HashSet::new();
        let retry_after = Arc::new(Mutex::new(HashMap::<String, Instant>::new()));
        let retry_delay = Arc::new(Mutex::new(HashMap::<String, Duration>::new()));
        let failure_counts = Arc::new(Mutex::new(HashMap::<String, u32>::new()));

        let accepted = record_peer_connected_event(
            local,
            local,
            addr,
            &connected_addrs,
            &peer_addrs,
            &addr_validators,
            &discovered_peers,
            &authenticated_peer_addrs,
            &authenticated_addr_validators,
            &connected_validator_ids,
            &bootstrap_peer_addrs,
            &genesis_peer_addrs,
            &retry_after,
            &retry_delay,
            &failure_counts,
        );

        assert!(!accepted);
        assert!(connected_addrs.lock().unwrap().is_empty());
        assert!(peer_addrs.lock().unwrap().is_empty());
        assert!(addr_validators.lock().unwrap().is_empty());
        assert!(discovered_peers.lock().unwrap().is_empty());
        assert!(authenticated_peer_addrs.lock().unwrap().is_empty());
        assert!(authenticated_addr_validators.lock().unwrap().is_empty());
        assert!(connected_validator_ids.lock().unwrap().is_empty());
        assert!(failure_counts.lock().unwrap().is_empty());
    }

    #[test]
    fn discovered_peers_table_has_bounded_size() {
        let mut discovered_peers = HashSet::new();
        let authenticated = HashSet::new();
        let bootstrap = HashSet::new();
        let genesis = HashSet::new();

        for port in 30_000..(30_000 + MAX_DISCOVERED_PEERS as u16 + 100) {
            insert_discovered_peer_bounded(
                &mut discovered_peers,
                &authenticated,
                &bootstrap,
                &genesis,
                SocketAddr::from(([127, 0, 0, 1], port)).to_string(),
            );
        }

        assert_eq!(discovered_peers.len(), MAX_DISCOVERED_PEERS);
        assert_eq!(
            bounded_discovered_peer_addrs(&discovered_peers).len(),
            MAX_DISCOVERED_PEERS
        );
    }

    #[test]
    fn discovery_eviction_prefers_unauthenticated_entries() {
        let authenticated_peer = "203.0.113.1:30303".to_string();
        let mut discovered_peers = HashSet::from([authenticated_peer.clone()]);
        let authenticated = HashSet::from([authenticated_peer.clone()]);
        let bootstrap = HashSet::new();
        let genesis = HashSet::new();

        for idx in 2..=MAX_DISCOVERED_PEERS {
            discovered_peers.insert(format!("203.0.{}.{}:30303", idx / 250, (idx % 250) + 1));
        }
        assert_eq!(discovered_peers.len(), MAX_DISCOVERED_PEERS);

        let new_peer = "198.51.100.250:30303".to_string();
        assert!(insert_discovered_peer_bounded(
            &mut discovered_peers,
            &authenticated,
            &bootstrap,
            &genesis,
            new_peer.clone(),
        ));

        assert!(discovered_peers.contains(&authenticated_peer));
        assert!(discovered_peers.contains(&new_peer));
        assert_eq!(discovered_peers.len(), MAX_DISCOVERED_PEERS);
    }

    #[test]
    fn bootstrap_peers_are_never_evicted() {
        let bootstrap_peer = "203.0.113.10:30303".to_string();
        let mut discovered_peers = HashSet::from([bootstrap_peer.clone()]);
        let authenticated = HashSet::new();
        let bootstrap = HashSet::from([bootstrap_peer.clone()]);
        let genesis = HashSet::new();

        for idx in 11..=(MAX_DISCOVERED_PEERS + 9) {
            discovered_peers.insert(format!("203.0.{}.{}:30303", idx / 250, (idx % 250) + 1));
        }
        assert_eq!(discovered_peers.len(), MAX_DISCOVERED_PEERS);

        assert!(insert_discovered_peer_bounded(
            &mut discovered_peers,
            &authenticated,
            &bootstrap,
            &genesis,
            "198.51.100.99:30303".to_string(),
        ));

        assert!(discovered_peers.contains(&bootstrap_peer));
        assert_eq!(discovered_peers.len(), MAX_DISCOVERED_PEERS);
    }

    #[test]
    fn inbound_connection_limit_is_enforced() {
        let inbound_count = AtomicU64::new(0);
        let inbound_by_ip = Mutex::new(HashMap::<IpAddr, u8>::new());
        let mut reserved_ips = Vec::new();

        for idx in 0..MAX_INBOUND_PEERS {
            let ip = IpAddr::from([198, 51, (idx / 250) as u8, (idx % 250 + 1) as u8]);
            assert!(reserve_inbound_connection(
                &inbound_count,
                &inbound_by_ip,
                ip
            ));
            reserved_ips.push(ip);
        }

        assert!(!reserve_inbound_connection(
            &inbound_count,
            &inbound_by_ip,
            IpAddr::from([203, 0, 113, 250])
        ));

        for ip in reserved_ips {
            release_inbound_connection(&inbound_count, &inbound_by_ip, ip);
        }
        assert_eq!(inbound_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn inbound_per_ip_limit_is_enforced() {
        let inbound_count = AtomicU64::new(0);
        let inbound_by_ip = Mutex::new(HashMap::<IpAddr, u8>::new());
        let ip = IpAddr::from([203, 0, 113, 77]);

        for _ in 0..MAX_INBOUND_PER_IP {
            assert!(reserve_inbound_connection(
                &inbound_count,
                &inbound_by_ip,
                ip
            ));
        }
        assert!(!reserve_inbound_connection(
            &inbound_count,
            &inbound_by_ip,
            ip
        ));

        for _ in 0..MAX_INBOUND_PER_IP {
            release_inbound_connection(&inbound_count, &inbound_by_ip, ip);
        }
        assert_eq!(inbound_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn dial_loop_skips_already_connected_validator_identity() {
        let validator_id = indra_core::Bytes32::from([0x42; 32]);
        let peer_addr = "203.0.113.42:30303".to_string();
        let authenticated_addr_validators = HashMap::from([(peer_addr.clone(), validator_id)]);
        let connected_validator_ids = HashSet::from([validator_id]);

        assert!(should_skip_dial_for_connected_validator(
            &peer_addr,
            &authenticated_addr_validators,
            &connected_validator_ids,
        ));

        let unknown_addr = "203.0.113.43:30303".to_string();
        assert!(!should_skip_dial_for_connected_validator(
            &unknown_addr,
            &authenticated_addr_validators,
            &connected_validator_ids,
        ));
    }

    #[test]
    fn permanently_unreachable_peer_is_evicted_after_max_failures() {
        let peer = "203.0.113.55:30303".to_string();
        let mut discovered_peers = HashSet::from([peer.clone()]);
        let mut retry_after = HashMap::from([(peer.clone(), Instant::now())]);
        let mut retry_delay = HashMap::from([(peer.clone(), Duration::from_secs(60))]);
        let mut failure_counts = HashMap::new();
        let bootstrap = HashSet::new();

        for _ in 0..(MAX_DIAL_FAILURES_BEFORE_EVICTION - 1) {
            assert!(!record_dial_failure(
                &peer,
                &mut discovered_peers,
                &mut retry_after,
                &mut retry_delay,
                &mut failure_counts,
                &bootstrap,
            ));
            assert!(discovered_peers.contains(&peer));
        }

        assert!(record_dial_failure(
            &peer,
            &mut discovered_peers,
            &mut retry_after,
            &mut retry_delay,
            &mut failure_counts,
            &bootstrap,
        ));
        assert!(!discovered_peers.contains(&peer));
        assert!(!retry_after.contains_key(&peer));
        assert!(!retry_delay.contains_key(&peer));
        assert!(!failure_counts.contains_key(&peer));
    }

    #[test]
    fn successful_connection_resets_failure_count() {
        let local = indra_core::Bytes32::from([0x01; 32]);
        let validator = indra_core::Bytes32::from([0x02; 32]);
        let addr: SocketAddr = "203.0.113.80:30303".parse().unwrap();
        let connected_addrs = Arc::new(Mutex::new(HashMap::<IpAddr, usize>::new()));
        let peer_addrs = Arc::new(Mutex::new(HashMap::<indra_core::Bytes32, SocketAddr>::new()));
        let addr_validators =
            Arc::new(Mutex::new(HashMap::<SocketAddr, indra_core::Bytes32>::new()));
        let discovered_peers = Arc::new(Mutex::new(HashSet::from([addr.to_string()])));
        let authenticated_peer_addrs = Arc::new(Mutex::new(HashSet::new()));
        let authenticated_addr_validators =
            Arc::new(Mutex::new(HashMap::<String, indra_core::Bytes32>::new()));
        let connected_validator_ids = Arc::new(Mutex::new(HashSet::<indra_core::Bytes32>::new()));
        let bootstrap_peer_addrs = HashSet::new();
        let genesis_peer_addrs = HashSet::new();
        let retry_after = Arc::new(Mutex::new(HashMap::<String, Instant>::new()));
        let retry_delay = Arc::new(Mutex::new(HashMap::<String, Duration>::new()));
        let failure_counts = Arc::new(Mutex::new(HashMap::from([(addr.to_string(), 7)])));

        assert!(record_peer_connected_event(
            local,
            validator,
            addr,
            &connected_addrs,
            &peer_addrs,
            &addr_validators,
            &discovered_peers,
            &authenticated_peer_addrs,
            &authenticated_addr_validators,
            &connected_validator_ids,
            &bootstrap_peer_addrs,
            &genesis_peer_addrs,
            &retry_after,
            &retry_delay,
            &failure_counts,
        ));

        assert!(!failure_counts
            .lock()
            .unwrap()
            .contains_key(&addr.to_string()));
        assert!(discovered_peers.lock().unwrap().contains(&addr.to_string()));
        assert!(connected_validator_ids.lock().unwrap().contains(&validator));
    }

    #[test]
    fn bootstrap_peers_are_not_evicted_by_failure_count() {
        let peer = "198.51.100.1:30303".to_string();
        let mut discovered_peers = HashSet::from([peer.clone()]);
        let mut retry_after = HashMap::from([(peer.clone(), Instant::now())]);
        let mut retry_delay = HashMap::from([(peer.clone(), Duration::from_secs(60))]);
        let mut failure_counts = HashMap::new();
        let bootstrap = HashSet::from([peer.clone()]);

        for _ in 0..MAX_DIAL_FAILURES_BEFORE_EVICTION {
            assert!(!record_dial_failure(
                &peer,
                &mut discovered_peers,
                &mut retry_after,
                &mut retry_delay,
                &mut failure_counts,
                &bootstrap,
            ));
        }

        assert!(discovered_peers.contains(&peer));
        assert!(retry_after.contains_key(&peer));
        assert!(retry_delay.contains_key(&peer));
        assert_eq!(
            failure_counts.get(&peer).copied(),
            Some(MAX_DIAL_FAILURES_BEFORE_EVICTION)
        );
    }

    #[test]
    fn peerlist_rejects_loopback_addresses() {
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();
        assert!(!is_address_acceptable_for_discovery(&addr));

        let addr: SocketAddr = "[::1]:30303".parse().unwrap();
        assert!(!is_address_acceptable_for_discovery(&addr));
    }

    #[test]
    fn peerlist_rejects_private_addresses() {
        for raw in ["10.1.2.3:30303", "172.16.1.2:30303", "192.168.1.2:30303"] {
            let addr: SocketAddr = raw.parse().unwrap();
            assert!(!is_address_acceptable_for_discovery(&addr));
        }
    }

    #[test]
    fn peerlist_accepts_legitimate_public_addresses() {
        let addr: SocketAddr = "93.184.216.34:30303".parse().unwrap();
        assert!(is_address_acceptable_for_discovery(&addr));
    }

    fn request_proposal_test_block() -> indra_core::types::block::BlockV1 {
        use indra_core::types::block::{BlockHeaderV1, BlockV1, NO_POLC_ROUND};
        use indra_core::types::primitives::{Bytes32, ProtocolVersion, VariableBytes};

        BlockV1 {
            header: BlockHeaderV1 {
                protocol_version: ProtocolVersion::CURRENT,
                height: 7,
                prev_hash: Bytes32::from([0x01; 32]),
                timestamp: 1_700_000_007,
                state_root: Bytes32::from([0x02; 32]),
                validator_set_root: Bytes32::from([0x03; 32]),
                mempool_set_root: Bytes32::from([0x04; 32]),
                value_hash: Bytes32::from([0xAA; 32]),
                base_fee: 1,
                proposer_round: 3,
                polc_round: NO_POLC_ROUND,
                proposer_vrf_output: Bytes32::from([0x05; 32]),
                proposer_vrf_proof: VariableBytes::from_slice(&[]).unwrap(),
                quorum_certificate: VariableBytes::from_slice(&[]).unwrap(),
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        }
    }

    #[test]
    fn request_proposal_serves_by_full_block_hash() {
        let block = request_proposal_test_block();
        let full_hash = block.header.block_hash();

        assert!(proposal_matches_request(&block, 7, 3, &full_hash));
    }

    #[test]
    fn request_proposal_does_not_serve_by_value_hash_alone() {
        let block = request_proposal_test_block();
        let value_hash = block.header.value_hash;
        assert_ne!(block.header.block_hash(), value_hash);

        assert!(!proposal_matches_request(&block, 7, 3, &value_hash));
    }

    #[test]
    fn observer_request_blocks_is_rate_limited() {
        let mut limiter =
            TokenBucket::new(OBSERVER_REQUEST_BLOCKS_RATE, OBSERVER_REQUEST_BLOCKS_BURST);

        for _ in 0..OBSERVER_REQUEST_BLOCKS_BURST {
            assert!(observer_request_blocks_allowed(&mut limiter));
        }
        assert!(
            !observer_request_blocks_allowed(&mut limiter),
            "observer RequestBlocks bursts beyond the configured budget must be throttled"
        );
    }

    #[tokio::test]
    async fn handshake_semaphore_limits_concurrency() {
        let sem = Arc::new(tokio::sync::Semaphore::new(50));
        let mut permits = Vec::new();
        for _ in 0..50 {
            permits.push(sem.clone().try_acquire_owned().expect("permit"));
        }
        assert!(sem.clone().try_acquire_owned().is_err());
        drop(permits);
        assert!(sem.clone().try_acquire_owned().is_ok());
    }
}
