//! INDRA v2 node binary.
//!
//! Networking runs on a Tokio runtime with authenticated encrypted transport.
//! Consensus and state transition logic remain synchronous on dedicated threads.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use fs2::available_space;
use indra_core::types::primitives::{
    DEFAULT_PRUNE_KEEP_BLOCKS, DISK_CRITICAL_THRESHOLD_BYTES, DISK_WARN_THRESHOLD_BYTES,
    DNS_SEED_HOST, MAX_PEER_LIST_SIZE, MIN_PRUNE_KEEP_BLOCKS, PEER_LIST_INTERVAL_SECS,
    PEER_TABLE_SAVE_INTERVAL_SECS, TARGET_OUTBOUND_PEERS,
};
use indra_crypto::{PqKeypair, PqPublicKey};
use indra_network::{
    message::Message, perform_handshake_initiator, perform_handshake_responder, spawn_peer_manager,
    HandshakeConfig, NetworkCommand, NetworkEvent, PeerManagerConfig, PeerManagerHandle,
};
use indra_node::{
    discovery::{load_peers, peer_list_payload, resolve_dns_seeds, resolve_peer_addr, save_peers},
    driver::{ConsensusDriver, DriverAction, DriverEvent, RoundPhase},
    genesis::load_genesis_seed_peers,
    net_driver::{action_to_message, message_to_event},
    sync::SYNC_BATCH_SIZE,
    NodeConfig, NodeEngine,
};
use tokio::runtime::Builder as TokioRuntimeBuilder;
use tokio::sync::mpsc as tokio_mpsc;

const PROPOSE_TIMEOUT: Duration = Duration::from_secs(8);
const PREVOTE_TIMEOUT: Duration = Duration::from_secs(3);
const PRECOMMIT_TIMEOUT: Duration = Duration::from_secs(3);
const MIN_BLOCK_INTERVAL_SECS: u64 = 6;
const DIAL_RETRY: Duration = Duration::from_secs(5);
const STATUS_INTERVAL: Duration = Duration::from_secs(6);

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
    std::sync::mpsc::Receiver<NetworkEvent>,
) {
    let connected_addrs = Arc::new(Mutex::new(HashMap::<std::net::IpAddr, usize>::new()));
    let peer_addrs = Arc::new(Mutex::new(HashMap::new()));
    let addr_validators = Arc::new(Mutex::new(HashMap::new()));
    let discovered_peers = Arc::new(Mutex::new(HashSet::<String>::new()));
    let (event_tx, event_rx) = std::sync::mpsc::channel::<NetworkEvent>();
    let (handle_tx, handle_rx) = std::sync::mpsc::channel::<PeerManagerHandle>();
    let retry_after = Arc::new(Mutex::new(HashMap::<String, Instant>::new()));
    let retry_delay = Arc::new(Mutex::new(HashMap::<String, Duration>::new()));
    let handshake_sem = Arc::new(tokio::sync::Semaphore::new(50));

    std::thread::spawn({
        let connected_addrs = Arc::clone(&connected_addrs);
        let peer_addrs = Arc::clone(&peer_addrs);
        let addr_validators = Arc::clone(&addr_validators);
        let retry_after = Arc::clone(&retry_after);
        let retry_delay = Arc::clone(&retry_delay);
        let handshake_sem = Arc::clone(&handshake_sem);
        let discovered_peers = Arc::clone(&discovered_peers);
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
                    async move {
                        while let Some(event) = async_event_rx.recv().await {
                            match &event {
                                NetworkEvent::PeerConnected { validator_id, addr } => {
                                    *connected_addrs.lock().unwrap().entry(addr.ip()).or_insert(0) += 1;
                                    peer_addrs.lock().unwrap().insert(*validator_id, *addr);
                                    addr_validators.lock().unwrap().insert(*addr, *validator_id);
                                    discovered_peers.lock().unwrap().insert(addr.to_string());
                                    retry_after.lock().unwrap().remove(&addr.ip().to_string());
                                    retry_after.lock().unwrap().remove(&addr.to_string());
                                    retry_delay.lock().unwrap().remove(&addr.ip().to_string());
                                    retry_delay.lock().unwrap().remove(&addr.to_string());
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
                            let permit = match handshake_sem.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    eprintln!("[p2p] handshake limit reached, rejecting connection from {}", addr);
                                    drop(stream);
                                    continue;
                                }
                            };
                            let peer_manager = PeerManagerHandle::clone(&peer_manager);
                            let handshake_config = Arc::clone(&handshake_config);
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
                    let peer_addrs = Arc::clone(&peer_addrs);
                    let peers_file_path = peers_file_path.clone();
                    let dns_seed_host = dns_seed_host.clone();
                    let p2p_addr_for_port = p2p_addr.clone();
                    async move {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        let persisted = load_peers(&peers_file_path);
                        {
                            let mut dp = discovered_peers.lock().unwrap();
                            for addr in &persisted {
                                dp.insert(addr.to_string());
                            }
                            for addr in &initial_discovered_peers {
                                dp.insert(addr.clone());
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
                            for addr in &dns_peers {
                                dp.insert(addr.to_string());
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
                                if has_connected_ip(&connected_addrs, &addr) {
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
                                                    retry_after.lock().unwrap().insert(peer_key, Instant::now() + current);
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
                                    }
                                }
                            }
                            if last_peer_save.elapsed().as_secs() >= PEER_TABLE_SAVE_INTERVAL_SECS {
                                let mut peers_to_save: Vec<SocketAddr> = {
                                    let dp = discovered_peers.lock().unwrap();
                                    dp.iter().filter_map(|peer| resolve_peer_addr(peer)).collect()
                                };
                                peers_to_save.extend(peer_addrs.lock().unwrap().values().copied());
                                peers_to_save.sort();
                                peers_to_save.dedup();
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
                            let mut peers_to_save: Vec<SocketAddr> = {
                                let dp = discovered_peers.lock().unwrap();
                                dp.iter().filter_map(|peer| resolve_peer_addr(peer)).collect()
                            };
                            peers_to_save.extend(peer_addrs.lock().unwrap().values().copied());
                            peers_to_save.sort();
                            peers_to_save.dedup();
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

    (bridge, discovered_peers, event_rx)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("INDRA node");
        println!("  --keys <path>");
        println!("  --data-dir <path>");
        println!("  --p2p-addr <host:port>");
        println!("  --bootstrap-peers <addr,addr,...>");
        println!("  --seeds <hostname>   DNS seed hostname (default: seeds.indraprotocol.com)");
        println!("  --peers-file <path>");
        println!("  --genesis <path>");
        println!("  --archive");
        println!(
            "  --prune-keep <blocks>  (minimum {})",
            MIN_PRUNE_KEEP_BLOCKS
        );
        return;
    }
    let get_arg = |flag: &str| -> Option<String> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };

    let keys_path = get_arg("--keys").unwrap_or_else(|| "keys.json".to_string());
    let data_dir = get_arg("--data-dir").unwrap_or_else(|| "./indra-data".to_string());
    let p2p_addr = get_arg("--p2p-addr").unwrap_or_else(|| "0.0.0.0:30303".to_string());
    let bootstrap = get_arg("--bootstrap-peers");
    let dns_seed_host = get_arg("--seeds").unwrap_or_else(|| DNS_SEED_HOST.to_string());
    let archive = args.iter().any(|arg| arg == "--archive");
    let prune_keep = get_arg("--prune-keep")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_PRUNE_KEEP_BLOCKS)
        .max(MIN_PRUNE_KEEP_BLOCKS);

    eprintln!("╔══════════════════════════════════════════╗");
    eprintln!("║      INDRA v2 — Phase 8 Node Starting     ║");
    eprintln!("╚══════════════════════════════════════════╝");
    eprintln!("Keys:      {}", keys_path);
    eprintln!("Data:      {}", data_dir);
    eprintln!("P2P:       {}", p2p_addr);
    eprintln!("Mode:      {}", if archive { "archive" } else { "pruned" });
    if !archive {
        eprintln!("Retain:    {} blocks", prune_keep);
    }

    check_disk_space(Path::new(&data_dir));

    // Load keys
    let keys_str = std::fs::read_to_string(&keys_path)
        .unwrap_or_else(|e| panic!("Cannot read {}: {}", keys_path, e));
    let hybrid_seed = extract_hex32(&keys_str, "hybrid_seed");
    let bls_seed = extract_hex32(&keys_str, "bls_seed");
    let vrf_seed = extract_hex32(&keys_str, "vrf_seed");
    let pq_sk = extract_hex_field(&keys_str, "pq_sk");
    let pq_pk = extract_hex_field(&keys_str, "hybrid_pq_pk");

    let bootstrap_peers: Vec<String> = match bootstrap.as_deref() {
        Some(value) => value.split(',').map(|s| s.trim().to_string()).collect(),
        None => {
            eprintln!("Bootstrap: (none; DNS/persisted/genesis discovery enabled)");
            vec![]
        }
    };
    if bootstrap_peers.is_empty() && bootstrap.is_some() {
        eprintln!("Bootstrap: (bootstrap node)");
    } else if let Some(raw_bootstrap) = &bootstrap {
        eprintln!("Bootstrap: {}", raw_bootstrap);
    }
    let genesis_path = get_arg("--genesis").unwrap_or_else(|| "genesis.toml".to_string());
    let peers_file = get_arg("--peers-file").unwrap_or_else(|| {
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
        validator_seed: Some(hybrid_seed),
        bls_seed: Some(bls_seed),
        vrf_seed: Some(vrf_seed),
        pq_sk: if pq_sk.is_empty() { None } else { Some(pq_sk) },
        pq_pk: if pq_pk.is_empty() { None } else { Some(pq_pk) },
        p2p_addr: p2p_addr.clone(),
        bootstrap_peers: bootstrap_peers.clone(),
        dns_seed_host: dns_seed_host.clone(),
        peers_file: peers_file.clone(),
        snapshot_interval: 300,
        mempool_capacity: 5_000,
        prune_keep_blocks: if archive { None } else { Some(prune_keep) },
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

    let mut driver_state = ConsensusDriver::new(engine);
    driver_state.refresh_registered_voters();
    let startup_qc_request = driver_state.request_qc_if_needed();
    let handshake_config = build_handshake_config(&driver_state.engine)
        .map(|config| Arc::new(RwLock::new(config)))
        .unwrap_or_else(|| panic!("authenticated transport requires validator networking keys"));
    let driver = driver_state;

    // Shared state between threads
    let driver = Arc::new(Mutex::new(driver));
    let (height_tx, height_rx) = std::sync::mpsc::channel::<()>();
    let (gossip, discovered_peers, network_events) = start_network_runtime(
        p2p_addr.clone(),
        bootstrap_peers.clone(),
        genesis_seed_peers,
        peers_file.clone(),
        dns_seed_host.clone(),
        Arc::clone(&handshake_config),
    );

    // ── Thread 3: Authenticated network event loop ──────────────────────────
    {
        let gossip = Arc::clone(&gossip);
        let driver = Arc::clone(&driver);
        let height_tx = height_tx.clone();
        let handshake_config = Arc::clone(&handshake_config);
        let discovered_peers = Arc::clone(&discovered_peers);
        let local_p2p_addr = p2p_addr.clone();

        std::thread::spawn(move || {
            while let Ok(event) = network_events.recv() {
                match event {
                    NetworkEvent::PeerConnected { validator_id, addr } => {
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
                        );
                    }
                    NetworkEvent::PeerDisconnected { addr, .. } => {
                        eprintln!("[p2p] peer disconnected: {}", addr);
                    }
                    NetworkEvent::SlashDetected(evidence) => {
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
                                let mut accepted = 0usize;
                                for addr_str in addrs.iter().take(MAX_PEER_LIST_SIZE) {
                                    let Some(addr) = resolve_peer_addr(addr_str) else {
                                        continue;
                                    };
                                    if addr.to_string() != local_p2p_addr
                                        && !has_connected_ip_from_socket_addrs(
                                            &gossip.connected_addrs(),
                                            &addr,
                                        )
                                    {
                                        new_peers.insert(addr.to_string());
                                        accepted = accepted.saturating_add(1);
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
                                            block.header.height == *height
                                                && block.header.proposer_round == *round
                                                && (block.header.block_hash() == *hash
                                                    || block.header.value_hash == *hash)
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
                                {
                                    let mut d = driver.lock().unwrap();
                                    for block in response_blocks {
                                        if block.header.height != d.height() + 1 {
                                            continue;
                                        }

                                        match d.engine.commit_block(&block) {
                                            Ok(()) => {
                                                imported_any = true;
                                                refresh_handshake_config(
                                                    &d.engine,
                                                    &handshake_config,
                                                );
                                                d.refresh_registered_voters();
                                                d.sync_mut().on_block_imported(block.header.height);
                                                d.reset_round();
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
                                if let Some(height) = caught_up_height {
                                    eprintln!(
                                        "[sync] caught up to height={}, joining consensus",
                                        height
                                    );
                                }
                                continue;
                            }
                            Message::Ping(_) => {
                                let (height, tip_hash) = {
                                    let d = driver.lock().unwrap();
                                    (d.height(), d.engine.state.tip_hash)
                                };
                                gossip.send_to_validator(
                                    validator_id,
                                    &Message::Status { height, tip_hash },
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
                    let status = Message::Status { height, tip_hash };
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
                                                d.last_qc_bytes(),
                                            )
                                        } else {
                                            d.engine.propose(
                                                &election,
                                                timestamp,
                                                d.last_qc_bytes(),
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
        );
    }

    // ── Thread 5: RPC server ────────────────────────────────────────────────
    // Inline HTTP/JSON-RPC handler — avoids circular dependency with indra-rpc.
    // Reads chain state directly from the driver under a brief lock.
    {
        let driver_rpc = Arc::clone(&driver);
        let gossip_rpc = Arc::clone(&gossip);
        let discovered_peers_rpc = Arc::clone(&discovered_peers);
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
                        std::thread::spawn(move || {
                            handle_rpc(stream, &driver_rpc, &gossip_rpc, &discovered_peers_rpc);
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
) {
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
            );
            let new_height = driver.lock().unwrap().height();
            if new_height > previous_height {
                refresh_handshake_config(&driver.lock().unwrap().engine, handshake_config);
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
    }
}

fn announce_status_and_recovery(
    driver: &Arc<Mutex<ConsensusDriver>>,
    gossip: &Arc<NetworkBridge>,
    height_tx: &std::sync::mpsc::Sender<()>,
    handshake_config: &Arc<RwLock<HandshakeConfig>>,
    validator_id: indra_core::Bytes32,
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
    process_driver_actions(driver, gossip, height_tx, handshake_config, height, actions);
}

fn startup_peer_messages(height: u64, tip_hash: indra_core::Bytes32) -> [Message; 2] {
    [
        Message::Status { height, tip_hash },
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
    let (height, tip_hash) = {
        let d = driver.lock().unwrap();
        (d.height(), d.engine.state.tip_hash)
    };
    let status = Message::Status { height, tip_hash };
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
) {
    use std::io::{BufRead, BufReader, Read, Write};

    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));

    // ── Parse HTTP request ────────────────────────────────────────────────
    let mut reader = match stream.try_clone() {
        Ok(s) => BufReader::new(s),
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
            if trimmed.starts_with("OPTIONS") {
                is_options = true;
            }
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
        let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
        return;
    }

    if content_length == 0 {
        let body = r#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"empty body"},"id":null}"#;
        let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", cors, body.len(), body);
        let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
        return;
    }

    let mut body_bytes = vec![0u8; content_length.min(1_048_576)];
    if reader.read_exact(&mut body_bytes).is_err() {
        return;
    }
    let body_str = String::from_utf8_lossy(&body_bytes);

    // ── Parse JSON-RPC method ─────────────────────────────────────────────
    let method = extract_json_str(&body_str, "method").unwrap_or_default();
    let id_raw = extract_json_id(&body_str);
    let first_param = extract_json_first_param(&body_str);

    // ── Lock driver, read state, build response ───────────────────────────
    let result: String = {
        let mut guard = driver.lock().unwrap();
        let mempool_size = guard.engine.mempool.len();
        let s = &guard.engine.state;

        match method.as_str() {
            "indra_getHeight" => {
                format!(r#"{{"height":{}}}"#, s.height)
            }
            "indra_getTip" => {
                format!(
                    r#"{{"height":{},"tip_hash":"{}"}}"#,
                    s.height,
                    hex::encode(s.tip_hash.0)
                )
            }
            "indra_getChainInfo" => {
                let block_reward_spark = indra_state::epoch::block_reward_at_height(s.height);
                let total_staked_spark = s
                    .validators
                    .total_selectable_self_stake()
                    .saturating_add(s.delegations.total_staked());
                let max_active_validators =
                    indra_core::types::primitives::max_active_validators(total_staked_spark);
                let effective_min_stake_spark = s
                    .validators
                    .effective_min_active_stake(&s.delegations)
                    .unwrap_or(0);
                let validator_set_phase =
                    indra_core::types::primitives::validator_set_phase(total_staked_spark);
                let era = if s.height < indra_core::types::primitives::ERA_1_2_DURATION_BLOCKS {
                    1
                } else if s.height < indra_core::types::primitives::ERA_1_2_DURATION_BLOCKS * 2 {
                    2
                } else {
                    3 + ((s.height - (indra_core::types::primitives::ERA_1_2_DURATION_BLOCKS * 2))
                        / indra_core::types::primitives::ERA_3_PLUS_DURATION_BLOCKS)
                };
                format!(
                    r#"{{"height":{},"tip_hash":"{}","base_fee":{},"total_supply":{},"treasury_balance":{},"burn_buffer":{},"fee_reward_pool":{},"active_validators":{},"max_active_validators":{},"total_staked_spark":{},"effective_min_stake_spark":{},"validator_set_phase":{},"mempool_size":{},"epoch":{},"pruned_mode":{},"lowest_block":{},"blocks_retained":{},"block_reward_spark":{},"era":{},"peers":{},"chain_id":"{}"}}"#,
                    s.height,
                    hex::encode(s.tip_hash.0),
                    s.base_fee,
                    s.total_supply,
                    s.treasury_balance,
                    s.burn_buffer,
                    s.fee_reward_pool,
                    s.validators.active_count(),
                    max_active_validators,
                    total_staked_spark,
                    effective_min_stake_spark,
                    validator_set_phase,
                    mempool_size,
                    s.current_epoch(),
                    if guard.engine.block_store.is_archive() {
                        "false"
                    } else {
                        "true"
                    },
                    guard.engine.block_store.lowest_height(),
                    guard.engine.block_store.len(),
                    block_reward_spark,
                    era,
                    gossip.connection_count(),
                    s.chain_id,
                )
            }
            "indra_getMempoolSize" => {
                format!(r#"{{"size":{}}}"#, mempool_size)
            }
            "indra_getPeers" => {
                let connected: Vec<String> = gossip
                    .connected_addrs()
                    .iter()
                    .map(|addr| addr.to_string())
                    .collect();
                let discovered_count = discovered_peers.lock().unwrap().len();
                format!(
                    r#"{{"connected":{},"connected_count":{},"discovered_count":{}}}"#,
                    serde_json::to_string(&connected).unwrap_or_default(),
                    connected.len(),
                    discovered_count,
                )
            }
            "indra_submitStakingOp" => {
                let op_hex = first_param.clone().unwrap_or_default();
                if op_hex.is_empty() {
                    let err = format!(
                        r#"{{"jsonrpc":"2.0","error":{{"code":-32602,"message":"missing staking op hex param"}},"id":{}}}"#,
                        id_raw
                    );
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", cors, err.len(), err);
                    let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                    return;
                }
                let op_bytes = match hex::decode(&op_hex) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        let err = format!(
                            r#"{{"jsonrpc":"2.0","error":{{"code":-32602,"message":"invalid hex encoding"}},"id":{}}}"#,
                            id_raw
                        );
                        let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", cors, err.len(), err);
                        let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                        return;
                    }
                };
                use indra_core::codec::Decode;
                use indra_core::types::staking::StakingOp;
                match StakingOp::decode_exact(&op_bytes) {
                    Ok(op) => match guard.engine.add_staking_op(op) {
                        Ok(()) => format!(r#"{{"status":"accepted"}}"#),
                        Err(e) => {
                            let err = format!(
                                r#"{{"jsonrpc":"2.0","error":{{"code":-32000,"message":"rejected: {}"}},"id":{}}}"#,
                                e, id_raw
                            );
                            let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", cors, err.len(), err);
                            let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                            return;
                        }
                    },
                    Err(e) => {
                        let err = format!(
                            r#"{{"jsonrpc":"2.0","error":{{"code":-32602,"message":"staking op decode failed: {}"}},"id":{}}}"#,
                            e, id_raw
                        );
                        let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", cors, err.len(), err);
                        let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                        return;
                    }
                }
            }
            "indra_getStakingNonce" => {
                let signer_id_hex = first_param.clone().unwrap_or_default();
                if signer_id_hex.len() != 64 {
                    let err = format!(
                        r#"{{"jsonrpc":"2.0","error":{{"code":-32602,"message":"invalid signer_id hex"}},"id":{}}}"#,
                        id_raw
                    );
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", cors, err.len(), err);
                    let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                    return;
                }
                let mut raw = [0u8; 32];
                if hex::decode_to_slice(&signer_id_hex, &mut raw).is_err() {
                    let err = format!(
                        r#"{{"jsonrpc":"2.0","error":{{"code":-32602,"message":"invalid signer_id hex"}},"id":{}}}"#,
                        id_raw
                    );
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", cors, err.len(), err);
                    let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                    return;
                }
                let signer_id = indra_core::Bytes32::from(raw);
                let nonce = s.staking_nonces.get(&signer_id).copied().unwrap_or(0);
                format!(
                    r#"{{"signer_id":"{}","current_nonce":{},"next_nonce":{}}}"#,
                    signer_id_hex,
                    nonce,
                    nonce.saturating_add(1),
                )
            }
            "indra_getValidator" => {
                let validator_hex = first_param.clone().unwrap_or_default();
                let response = if validator_hex.len() == 64 {
                    let mut validator_bytes = [0u8; 32];
                    if let Ok(decoded) = hex::decode(&validator_hex) {
                        if decoded.len() == 32 {
                            validator_bytes.copy_from_slice(&decoded);
                        }
                    }
                    let validator_id = indra_core::Bytes32::from(validator_bytes);
                    match s.validators.get(&validator_id) {
                        Some(v) => format!(
                            r#"{{"validator_id":"{}","name":"{}","stake":{},"status":"{}","epoch_joined":{},"hybrid_classical_pk":"{}","hybrid_pq_pk":"{}"}}"#,
                            hex::encode(v.validator_id.0),
                            v.name,
                            v.stake_spark,
                            if v.is_active() { "active" } else { "inactive" },
                            v.registered_epoch,
                            v.hybrid_classical_pk.map(hex::encode).unwrap_or_default(),
                            v.hybrid_pq_pk.as_ref().map(hex::encode).unwrap_or_default(),
                        ),
                        None => "null".to_string(),
                    }
                } else {
                    "null".to_string()
                };
                response
            }
            "indra_getValidatorSet" => {
                let entries: Vec<String> = s.validators.active_validators().map(|v| {
                    format!(
                        r#"{{"validator_id":"{}","name":"{}","stake":{},"status":"active","commission_bps":{},"pending_rewards":{},"epoch_joined":{},"hybrid_classical_pk":"{}","hybrid_pq_pk":"{}"}}"#,
                        hex::encode(v.validator_id.0),
                        v.name,
                        v.stake_spark,
                        v.commission_bps,
                        v.pending_rewards,
                        v.registered_epoch,
                        v.hybrid_classical_pk.map(hex::encode).unwrap_or_default(),
                        v.hybrid_pq_pk.as_ref().map(hex::encode).unwrap_or_default(),
                    )
                }).collect();
                format!(r#"{{"validators":[{}]}}"#, entries.join(","))
            }
            "indra_getDelegations" => {
                let validator_hex = first_param.clone().unwrap_or_default();
                if validator_hex.len() != 64 {
                    let err = format!(
                        r#"{{"jsonrpc":"2.0","error":{{"code":-32602,"message":"invalid validator_id hex"}},"id":{}}}"#,
                        id_raw
                    );
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", cors, err.len(), err);
                    let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                    return;
                }
                let mut raw = [0u8; 32];
                if hex::decode_to_slice(&validator_hex, &mut raw).is_err() {
                    let err = format!(
                        r#"{{"jsonrpc":"2.0","error":{{"code":-32602,"message":"invalid validator_id hex"}},"id":{}}}"#,
                        id_raw
                    );
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", cors, err.len(), err);
                    let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                    return;
                }
                let validator_id = indra_core::Bytes32::from(raw);
                let entries: Vec<String> = s.delegations.get_delegators(&validator_id).iter().map(|de| {
                    format!(
                        r#"{{"delegator_id":"{}","staked_spark":{},"pending_rewards":{},"unbonding":{},"unbonding_end_epoch":{}}}"#,
                        hex::encode(de.delegator_id.0),
                        de.staked_spark,
                        de.pending_rewards,
                        if de.unbonding_end_epoch.is_some() { "true" } else { "false" },
                        de.unbonding_end_epoch.unwrap_or(0),
                    )
                }).collect();
                let bonds: Vec<String> = s
                    .staked_bonds
                    .values()
                    .filter(|bond| {
                        bond.validator_id == validator_id && bond.unbonding_end_epoch.is_none()
                    })
                    .map(|bond| {
                        format!(
                            r#"{{"bond_utxo_id":"{}","delegator_id":"{}","amount_spark":{},"bonded_epoch":{}}}"#,
                            hex::encode(bond.utxo_id.0),
                            hex::encode(bond.delegator_id.0),
                            bond.amount_spark,
                            bond.bonded_epoch,
                        )
                    })
                    .collect();
                format!(
                    r#"{{"validator_id":"{}","delegations":[{}],"bonds":[{}]}}"#,
                    validator_hex,
                    entries.join(","),
                    bonds.join(",")
                )
            }
            "indra_getStakeBonds" => {
                let delegator_hex = first_param.clone().unwrap_or_default();
                if delegator_hex.len() != 64 {
                    let err = format!(
                        r#"{{"jsonrpc":"2.0","error":{{"code":-32602,"message":"invalid delegator_id hex"}},"id":{}}}"#,
                        id_raw
                    );
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", cors, err.len(), err);
                    let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                    return;
                }
                let mut raw = [0u8; 32];
                if hex::decode_to_slice(&delegator_hex, &mut raw).is_err() {
                    let err = format!(
                        r#"{{"jsonrpc":"2.0","error":{{"code":-32602,"message":"invalid delegator_id hex"}},"id":{}}}"#,
                        id_raw
                    );
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", cors, err.len(), err);
                    let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                    return;
                }
                let delegator_id = indra_core::Bytes32::from(raw);
                let bonds: Vec<String> = s
                    .staked_bonds
                    .values()
                    .filter(|bond| {
                        bond.delegator_id == delegator_id && bond.unbonding_end_epoch.is_none()
                    })
                    .map(|bond| {
                        format!(
                            r#"{{"bond_utxo_id":"{}","validator_id":"{}","amount_spark":{},"bonded_epoch":{},"unbonding":false}}"#,
                            hex::encode(bond.utxo_id.0),
                            hex::encode(bond.validator_id.0),
                            bond.amount_spark,
                            bond.bonded_epoch,
                        )
                    })
                    .collect();
                format!(
                    r#"{{"delegator_id":"{}","bonds":[{}]}}"#,
                    delegator_hex,
                    bonds.join(",")
                )
            }
            "indra_getEpochInfo" => {
                let height = s.height;
                let current_epoch = indra_state::epoch::epoch_for_height(height);
                let epoch_duration = indra_core::types::primitives::EPOCH_DURATION_BLOCKS;
                let next_epoch_height = current_epoch
                    .saturating_add(1)
                    .saturating_mul(epoch_duration);
                let blocks_until_next = next_epoch_height.saturating_sub(height);
                let total_staked = s
                    .validators
                    .total_selectable_self_stake()
                    .saturating_add(s.delegations.total_staked());
                let phase = indra_core::types::primitives::validator_set_phase(total_staked);
                let max_validators =
                    indra_core::types::primitives::max_active_validators(total_staked);
                format!(
                    r#"{{"current_epoch":{},"next_epoch_height":{},"blocks_until_next_epoch":{},"epoch_duration_blocks":{},"validator_set_phase":{},"max_active_validators":{}}}"#,
                    current_epoch,
                    next_epoch_height,
                    blocks_until_next,
                    epoch_duration,
                    phase,
                    max_validators,
                )
            }
            "indra_getValidatorRewards" => {
                let validator_hex = first_param.clone().unwrap_or_default();
                if validator_hex.len() != 64 {
                    let err = format!(
                        r#"{{"jsonrpc":"2.0","error":{{"code":-32602,"message":"invalid validator_id hex"}},"id":{}}}"#,
                        id_raw
                    );
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", cors, err.len(), err);
                    let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                    return;
                }
                let mut raw = [0u8; 32];
                if hex::decode_to_slice(&validator_hex, &mut raw).is_err() {
                    let err = format!(
                        r#"{{"jsonrpc":"2.0","error":{{"code":-32602,"message":"invalid validator_id hex"}},"id":{}}}"#,
                        id_raw
                    );
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", cors, err.len(), err);
                    let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                    return;
                }
                let validator_id = indra_core::Bytes32::from(raw);
                let validator_rewards = s
                    .validators
                    .get(&validator_id)
                    .map(|v| v.pending_rewards)
                    .unwrap_or(0);
                let delegator_rewards: Vec<String> = s
                    .delegations
                    .get_delegators(&validator_id)
                    .iter()
                    .map(|de| {
                        format!(
                            r#"{{"delegator_id":"{}","pending_rewards":{}}}"#,
                            hex::encode(de.delegator_id.0),
                            de.pending_rewards,
                        )
                    })
                    .collect();
                format!(
                    r#"{{"validator_id":"{}","validator_pending_rewards":{},"delegator_rewards":[{}]}}"#,
                    validator_hex,
                    validator_rewards,
                    delegator_rewards.join(","),
                )
            }
            "indra_sendTransaction" => {
                // Params: ["<tx_hex>"]
                let tx_hex = first_param.clone().unwrap_or_default();
                if tx_hex.is_empty() {
                    let err = format!(
                        r#"{{"jsonrpc":"2.0","error":{{"code":-32602,"message":"missing tx_hex param"}},"id":{}}}"#,
                        id_raw
                    );
                    let resp = format!(
                        "HTTP/1.1 200 OK
Content-Type: application/json
{}Content-Length: {}
Connection: close

{}",
                        cors,
                        err.len(),
                        err
                    );
                    let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                    return;
                }
                let tx_bytes = match hex::decode(&tx_hex) {
                    Ok(b) => b,
                    Err(_) => {
                        let err = format!(
                            r#"{{"jsonrpc":"2.0","error":{{"code":-32602,"message":"invalid hex encoding"}},"id":{}}}"#,
                            id_raw
                        );
                        let resp = format!(
                            "HTTP/1.1 200 OK
Content-Type: application/json
{}Content-Length: {}
Connection: close

{}",
                            cors,
                            err.len(),
                            err
                        );
                        let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                        return;
                    }
                };
                use indra_core::codec::{ByteReader, Decode};
                use indra_core::types::transaction::TransactionV1;
                let mut reader = ByteReader::new(&tx_bytes);
                match TransactionV1::decode(&mut reader) {
                    Ok(tx) => {
                        let base_fee = guard.engine.state.base_fee;
                        let height = guard.engine.state.height;
                        match guard.engine.mempool.submit(tx.clone(), base_fee, height) {
                            Ok(tx_id) => {
                                gossip.broadcast(&Message::Tx(tx));
                                format!(
                                    r#"{{"tx_id":"{}","status":"accepted"}}"#,
                                    hex::encode(tx_id.0)
                                )
                            }
                            Err(e) => {
                                let err = format!(
                                    r#"{{"jsonrpc":"2.0","error":{{"code":-32000,"message":"mempool rejected: {}"}},"id":{}}}"#,
                                    e, id_raw
                                );
                                let resp = format!(
                                    "HTTP/1.1 200 OK
Content-Type: application/json
{}Content-Length: {}
Connection: close

{}",
                                    cors,
                                    err.len(),
                                    err
                                );
                                let _ =
                                    stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        let err = format!(
                            r#"{{"jsonrpc":"2.0","error":{{"code":-32602,"message":"tx decode failed: {}"}},"id":{}}}"#,
                            e, id_raw
                        );
                        let resp = format!(
                            "HTTP/1.1 200 OK
Content-Type: application/json
{}Content-Length: {}
Connection: close

{}",
                            cors,
                            err.len(),
                            err
                        );
                        let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                        return;
                    }
                }
            }
            "indra_getBalance" => {
                // Params: ["<address_hex>"] where address = SHA-256(classical_pk)
                let address_hex = first_param.clone().unwrap_or_default();
                let mut balance: u64 = 0;
                if address_hex.len() == 64 {
                    for entry in s.utxos.all_entries() {
                        let owner_address =
                            indra_crypto::sha256(&entry.output.owner_pubkey.classical_pk.0);
                        if hex::encode(owner_address) == address_hex {
                            balance = balance.saturating_add(entry.output.value_spark);
                        }
                    }
                }
                format!(r#"{{"address":"{}","balance":{}}}"#, address_hex, balance)
            }
            "indra_getUtxos" => {
                // Params: ["<address_hex>"] where address = SHA-256(classical_pk)
                let address_hex = first_param.clone().unwrap_or_default();
                let entries: Vec<String> = if address_hex.len() == 64 {
                    s.utxos.all_entries()
                        .filter(|e| hex::encode(indra_crypto::sha256(&e.output.owner_pubkey.classical_pk.0)) == address_hex)
                        .map(|e| {
                            format!(
                                r#"{{"utxo_id":"{}","amount":{},"created_height":{},"tx_index":{},"out_index":{},"lock_height":{}}}"#,
                                hex::encode(e.utxo_id.0),
                                e.output.value_spark,
                                e.created_height,
                                e.tx_index,
                                e.output_index,
                                e.output.lock_height,
                            )
                        })
                        .collect()
                } else {
                    vec![]
                };
                format!(
                    r#"{{"address":"{}","utxos":[{}]}}"#,
                    address_hex,
                    entries.join(",")
                )
            }
            "indra_getUtxoProof" => {
                // Params: ["<utxo_id_hex>"]
                let utxo_hex = first_param.clone().unwrap_or_default();
                if utxo_hex.len() != 64 {
                    "null".to_string()
                } else if let Ok(decoded) = hex::decode(&utxo_hex) {
                    if decoded.len() != 32 {
                        "null".to_string()
                    } else {
                        let mut raw = [0u8; 32];
                        raw.copy_from_slice(&decoded);
                        let utxo_id = indra_core::Bytes32::from(raw);
                        let proof = s.utxos.prove(&utxo_id);
                        let siblings = proof
                            .siblings
                            .iter()
                            .map(|sibling| format!(r#""{}""#, hex::encode(sibling)))
                            .collect::<Vec<_>>()
                            .join(",");
                        let value_hash = proof.value.map(hex::encode).unwrap_or_default();
                        let state_root = indra_state::compute_state_root(s);
                        format!(
                            r#"{{"utxo_id":"{}","present":{},"value_hash":"{}","siblings":[{}],"state_root":"{}"}}"#,
                            hex::encode(utxo_id.0),
                            if proof.value.is_some() {
                                "true"
                            } else {
                                "false"
                            },
                            value_hash,
                            siblings,
                            hex::encode(state_root.0),
                        )
                    }
                } else {
                    "null".to_string()
                }
            }
            _ => {
                let err = format!(
                    r#"{{"jsonrpc":"2.0","error":{{"code":-32601,"message":"method not found: {}"}},"id":{}}}"#,
                    method, id_raw
                );
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", cors, err.len(), err);
                let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                return;
            }
        }
    };

    let json_resp = format!(r#"{{"jsonrpc":"2.0","result":{},"id":{}}}"#, result, id_raw);
    let http_resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        cors, json_resp.len(), json_resp
    );
    let _ = stream
        .try_clone()
        .map(|mut w| w.write_all(http_resp.as_bytes()));
}

/// Extract the first element from the JSON-RPC params array.
fn extract_json_first_param(json: &str) -> Option<String> {
    let params_pos = json.find("\"params\"")?;
    let after = &json[params_pos + 8..];
    let arr_start = after.find('[')? + 1;
    let arr = after[arr_start..].trim_start();
    if let Some(inner) = arr.strip_prefix('"') {
        let end = inner.find('"')?;
        Some(inner[..end].to_string())
    } else if arr.starts_with(']') {
        None
    } else {
        // numeric param
        let end = arr.find(|c: char| !c.is_ascii_digit()).unwrap_or(arr.len());
        Some(arr[..end].to_string())
    }
}

/// Extract a string field value from a JSON string (simple, no full parser needed).
fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let pos = json.find(&needle)?;
    let after = &json[pos + needle.len()..];
    let colon = after.find(':')? + 1;
    let rest = after[colon..].trim_start();
    if let Some(inner) = rest.strip_prefix('"') {
        let end = inner.find('"')?;
        Some(inner[..end].to_string())
    } else {
        None
    }
}

/// Extract the id field from a JSON-RPC request as a raw JSON value.
fn extract_json_id(json: &str) -> String {
    let needle = "\"id\"";
    if let Some(pos) = json.find(needle) {
        let after = &json[pos + needle.len()..];
        if let Some(colon) = after.find(':') {
            let rest = after[colon + 1..].trim_start();
            // Take until comma or closing brace
            let end = rest.find([',', '}']).unwrap_or(rest.len());
            return rest[..end].trim().to_string();
        }
    }
    "null".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_broadcast_on_first_peer_connection() {
        let tip_hash = indra_core::Bytes32::from([0x55u8; 32]);
        let [first, second] = startup_peer_messages(42, tip_hash);

        assert!(matches!(first, Message::Status { height: 42, tip_hash: got } if got == tip_hash));
        assert!(matches!(second, Message::Ping(_)));
    }

    #[test]
    fn stale_staged_proposal_does_not_block_valid_reproposal() {
        let mode = choose_proposal_mode(true, true, None, 10, 3, true);

        assert_eq!(mode, ProposalMode::Reproposal);
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
