//! INDRA v2 node binary — Phase 8: live P2P consensus.
//!
//! Thread layout:
//!
//!   main          — status printer (every 6s)
//!   listener      — accepts inbound TCP connections from peers
//!   dialer        — connects to bootstrap peers, sends Status
//!   gossip_recv   — reads messages from all connected peers, routes to driver
//!   consensus     — every 6s: check if proposer, propose block, broadcast votes

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fs2::available_space;
use indra_core::types::primitives::{
    DEFAULT_PRUNE_KEEP_BLOCKS,
    DISK_CRITICAL_THRESHOLD_BYTES,
    DISK_WARN_THRESHOLD_BYTES,
    MIN_PRUNE_KEEP_BLOCKS,
};
use indra_network::{
    message::Message,
    peer::ScoreEvent,
    transport::{Transport, Connection},
    gossip::GossipEngine,
};
use indra_node::{
    NodeConfig, NodeEngine,
    driver::{ConsensusDriver, DriverAction, DriverEvent},
    net_driver::{message_to_event, action_to_message},
};

const BLOCK_TIME: Duration = Duration::from_secs(6);
const DIAL_RETRY: Duration = Duration::from_secs(5);
const STATUS_INTERVAL: Duration = Duration::from_secs(6);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("INDRA node");
        println!("  --keys <path>");
        println!("  --data-dir <path>");
        println!("  --p2p-addr <host:port>");
        println!("  --bootstrap-peers <addr,addr,...>");
        println!("  --genesis <path>");
        println!("  --archive");
        println!("  --prune-keep <blocks>  (minimum {})", MIN_PRUNE_KEEP_BLOCKS);
        return;
    }
    let get_arg = |flag: &str| -> Option<String> {
        args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
    };

    let keys_path  = get_arg("--keys").unwrap_or_else(|| "keys.json".to_string());
    let data_dir   = get_arg("--data-dir").unwrap_or_else(|| "./indra-data".to_string());
    let p2p_addr   = get_arg("--p2p-addr").unwrap_or_else(|| "0.0.0.0:30303".to_string());
    let bootstrap  = get_arg("--bootstrap-peers").unwrap_or_default();
    let archive    = args.iter().any(|arg| arg == "--archive");
    let prune_keep = get_arg("--prune-keep")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_PRUNE_KEEP_BLOCKS)
        .max(MIN_PRUNE_KEEP_BLOCKS);

    println!("╔══════════════════════════════════════════╗");
    println!("║      INDRA v2 — Phase 8 Node Starting     ║");
    println!("╚══════════════════════════════════════════╝");
    println!("Keys:      {}", keys_path);
    println!("Data:      {}", data_dir);
    println!("P2P:       {}", p2p_addr);
    println!("Bootstrap: {}", if bootstrap.is_empty() { "(bootstrap node)" } else { &bootstrap });
    println!("Mode:      {}", if archive { "archive" } else { "pruned" });
    if !archive {
        println!("Retain:    {} blocks", prune_keep);
    }

    check_disk_space(Path::new(&data_dir));

    // Load keys
    let keys_str = std::fs::read_to_string(&keys_path)
        .unwrap_or_else(|e| panic!("Cannot read {}: {}", keys_path, e));
    let hybrid_seed = extract_hex32(&keys_str, "hybrid_seed");
    let bls_seed    = extract_hex32(&keys_str, "bls_seed");
    let vrf_seed    = extract_hex32(&keys_str, "vrf_seed");
    let pq_sk       = extract_hex_field(&keys_str, "pq_sk");
    let pq_pk       = extract_hex_field(&keys_str, "hybrid_pq_pk");

    let bootstrap_peers: Vec<String> = if bootstrap.is_empty() {
        vec![]
    } else {
        bootstrap.split(',').map(|s| s.trim().to_string()).collect()
    };

    let config = NodeConfig {
        data_dir:          std::path::PathBuf::from(&data_dir),
        validator_seed:    Some(hybrid_seed),
        bls_seed:          Some(bls_seed),
        vrf_seed:          Some(vrf_seed),
        pq_sk:             if pq_sk.is_empty() { None } else { Some(pq_sk) },
        pq_pk:             if pq_pk.is_empty() { None } else { Some(pq_pk) },
        p2p_addr:          p2p_addr.clone(),
        bootstrap_peers:   bootstrap_peers.clone(),
        snapshot_interval: 300,
        mempool_capacity:  5_000,
        prune_keep_blocks: if archive { None } else { Some(prune_keep) },
        strict_header_verification: false,
    };

    // Init node engine + consensus driver
    let mut engine = NodeEngine::init(config)
        .unwrap_or_else(|e| panic!("Node init failed: {}", e));

    // Load validator set from genesis.toml
    let genesis_path = get_arg("--genesis").unwrap_or_else(|| "genesis.toml".to_string());
    if std::path::Path::new(&genesis_path).exists() {
        indra_node::load_genesis_validators(&genesis_path, &mut engine.state);
        engine.rebuild_state_from_block_log()
            .unwrap_or_else(|e| panic!("State replay failed after loading genesis validators: {}", e));
        println!("Validator set: {} active validators",
            engine.state.validators.active_count());
    } else {
        println!("[warning] genesis.toml not found at {} — validator set empty", genesis_path);
    }

    let validator_id = engine.validator_id()
        .map(|id| hex::encode(id.0))
        .unwrap_or_else(|| "full-node".to_string());

    println!("\nValidator: {}...", &validator_id[..16]);
    println!("Height:    {}", engine.height());
    println!("\nStarting P2P and consensus...\n");

    let driver = ConsensusDriver::new(engine);

    // Shared state between threads
    let driver    = Arc::new(Mutex::new(driver));
    let gossip    = Arc::new(Mutex::new(GossipEngine::new()));
    // connection map: addr → Connection (for gossip_recv thread)
    let conns: Arc<Mutex<HashMap<SocketAddr, Connection>>> = Arc::new(Mutex::new(HashMap::new()));

    // ── Thread 1: P2P listener ──────────────────────────────────────────────
    {
        let gossip  = Arc::clone(&gossip);
        let conns   = Arc::clone(&conns);
        let driver  = Arc::clone(&driver);
        let p2p     = p2p_addr.clone();

        std::thread::spawn(move || {
            let listener = match TcpListener::bind(&p2p) {
                Ok(l) => l,
                Err(e) => { eprintln!("[listener] bind failed: {}", e); return; }
            };
            println!("[P2P] Listening on {}", p2p);

            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let addr = match stream.peer_addr() {
                            Ok(a) => a,
                            Err(_) => continue,
                        };
                        println!("[P2P] Inbound connection from {}", addr);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

                        // Add to gossip engine
                        if let Ok(conn) = Connection::from_stream(stream.try_clone().unwrap_or_else(|_| panic!("clone failed"))) {
                            let _ = gossip.lock().unwrap().add_connection(addr, conn);
                        }
                        // Add raw stream to conns for recv loop
                        if let Ok(conn2) = Connection::from_stream(stream) {
                            conns.lock().unwrap().insert(addr, conn2);
                        }

                        // Send our status
                        let height = driver.lock().unwrap().height();
                        let tip = driver.lock().unwrap().engine.state.tip_hash;
                        let status = Message::Status { height, tip_hash: tip };
                        if let Ok(mut g) = gossip.lock() {
                            let _ = g.send_to(&addr, &status);
                        }
                    }
                    Err(e) => eprintln!("[listener] accept error: {}", e),
                }
            }
        });
    }

    // ── Thread 2: Peer dialer ───────────────────────────────────────────────
    {
        let gossip   = Arc::clone(&gossip);
        let conns    = Arc::clone(&conns);
        let driver   = Arc::clone(&driver);
        let peers    = bootstrap_peers.clone();
        std::thread::spawn(move || {
            // Wait a moment for the listener to start
            std::thread::sleep(Duration::from_millis(500));

            let transport = match Transport::bind("0.0.0.0:0") {
                Ok(t) => t,
                Err(e) => { eprintln!("[dialer] transport bind failed: {}", e); return; }
            };

            loop {
                for peer_addr_str in &peers {
                    let addr: SocketAddr = match peer_addr_str.parse() {
                        Ok(a) => a,
                        Err(_) => { eprintln!("[dialer] invalid addr: {}", peer_addr_str); continue; }
                    };

                    // Skip if already connected
                    if gossip.lock().unwrap().peers().connected().iter().any(|p| p.addr == addr) {
                        continue;
                    }

                    println!("[P2P] Dialing {}...", addr);
                    match transport.dial(addr) {
                        Ok(conn) => {
                            println!("[P2P] Connected to {}", addr);
                            // Add to gossip
                            let conn2 = match TcpStream::connect(addr) {
                                Ok(s) => {
                                    let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
                                    match Connection::from_stream(s) {
                                        Ok(c) => c,
                                        Err(_) => continue,
                                    }
                                }
                                Err(_) => continue,
                            };
                            let _ = gossip.lock().unwrap().add_connection(addr, conn);
                            conns.lock().unwrap().insert(addr, conn2);

                            // Send status
                            let height   = driver.lock().unwrap().height();
                            let tip_hash = driver.lock().unwrap().engine.state.tip_hash;
                            let status = Message::Status { height, tip_hash };
                            let _ = gossip.lock().unwrap().send_to(&addr, &status);
                        }
                        Err(e) => {
                            eprintln!("[dialer] failed to connect to {}: {}", addr, e);
                        }
                    }
                }
                std::thread::sleep(DIAL_RETRY);
            }
        });
    }

    // ── Thread 3: Gossip receive loop ───────────────────────────────────────
    {
        let conns   = Arc::clone(&conns);
        let gossip  = Arc::clone(&gossip);
        let driver  = Arc::clone(&driver);

        std::thread::spawn(move || {
            loop {
                // Collect addrs to avoid holding lock while reading
                let addrs: Vec<SocketAddr> = conns.lock().unwrap().keys().cloned().collect();

                for addr in addrs {
                    let msg = {
                        let mut c = conns.lock().unwrap();
                        if let Some(conn) = c.get_mut(&addr) {
                            match conn.recv() {
                                Ok(Some(m)) => Some(m),
                                Ok(None) => {
                                    // Connection closed
                                    eprintln!("[gossip] peer {} disconnected", addr);
                                    c.remove(&addr);
                                    gossip.lock().unwrap().remove_connection(&addr);
                                    None
                                }
                                Err(_) => None,
                            }
                        } else {
                            None
                        }
                    };

                    if let Some(msg) = msg {
                        // Score the peer
                        gossip.lock().unwrap().score_event(&addr, ScoreEvent::ValidBlock);

                        // Convert to driver event and process
                        if let Some(event) = message_to_event(msg, addr) {
                            let actions = driver.lock().unwrap().process(event);
                            for action in actions {
                                if let Some(out_msg) = action_to_message(&action) {
                                    let _ = gossip.lock().unwrap().broadcast(&out_msg);
                                }
                                // Handle sync request
                                if let DriverAction::RequestBlocks { from, from_height, to_height } = &action {
                                    let req = Message::GetBlocks {
                                        from_height: *from_height,
                                        to_height: *to_height,
                                    };
                                    let _ = gossip.lock().unwrap().send_to(from, &req);
                                }
                            }
                        }
                    }
                }

                std::thread::sleep(Duration::from_millis(50));
            }
        });
    }

    // ── Thread 4: Consensus loop ────────────────────────────────────────────
    {
        let driver  = Arc::clone(&driver);
        let gossip  = Arc::clone(&gossip);

        std::thread::spawn(move || {
            // Wait for peer connections to establish
            std::thread::sleep(Duration::from_secs(3));

            let mut last_block_time = Instant::now();

            loop {
                // Every BLOCK_TIME: attempt to propose a block
                if last_block_time.elapsed() >= BLOCK_TIME {
                    last_block_time = Instant::now();

                    let connected = gossip.lock().unwrap().connection_count();
                    let height    = driver.lock().unwrap().height();

                    if connected == 0 {
                        // No peers yet — print waiting message
                        println!("[consensus] height={} waiting for peers...", height);
                    } else {
                        println!("[consensus] height={} peers={} tick", height, connected);

                        // Broadcast our status to all peers
                        let tip_hash = driver.lock().unwrap().engine.state.tip_hash;
                        let status = Message::Status { height, tip_hash };
                        let _ = gossip.lock().unwrap().broadcast(&status);

                        // In a full implementation, the VRF election determines the proposer.
                        // For Phase 8, we use round-robin based on height to demonstrate
                        // block advancement. The validator whose position matches
                        // (height % validator_count) proposes.
                        //
                        // Full VRF-based election is already implemented in indra-consensus
                        // and will be wired in Phase 9 when we have the full validator set
                        // loaded from genesis.
                        //
                        // For now: the bootstrap node (no bootstrap-peers arg) always proposes
                        // to demonstrate block advancement.
                        // VRF-based proposer election
                        let should_propose = {
                            let d = driver.lock().unwrap();
                            let vrf_seed = d.engine.config.vrf_seed.unwrap_or([0u8; 32]);
                            let vrf_kp = indra_crypto::VrfKeypair::from_seed(&vrf_seed);
                            let epoch_seed = indra_core::types::primitives::Bytes32::from(
                                indra_crypto::sha256(&d.engine.state.tip_hash.0)
                            );
                            let height = d.engine.state.height + 1;

                            // Build candidate list from active validators
                            let candidates: Vec<indra_consensus::proposer::ProposerCandidate> =
                                d.engine.state.validators.active_validators()
                                    .filter_map(|v| v.vrf_pk.map(|vrf_pk| indra_consensus::proposer::ProposerCandidate {
                                        validator_id: v.validator_id,
                                        vrf_pubkey: vrf_pk,
                                        stake: v.stake_spark,
                                    }))
                                    .collect();

                            if candidates.is_empty() {
                                // No validators loaded — fall back to bootstrap behaviour
                                d.engine.config.bootstrap_peers.is_empty()
                            } else {
                                let election = indra_consensus::proposer::ProposerElection {
                                    epoch_seed,
                                    height,
                                    candidates,
                                };
                                let slot = indra_consensus::proposer::compute_proposer_vrf(
                                    &vrf_kp, &epoch_seed, height
                                );
                                let elected = indra_consensus::elect_proposer(&election)
                                    .unwrap_or(indra_core::types::primitives::Bytes32::ZERO);
                                elected == slot.proposer_id
                            }
                        };

                        if should_propose {
                            // Propose a block
                            use indra_core::{
                                Bytes32, ProtocolVersion, VariableBytes,
                                types::block::{BlockHeaderV1, BlockV1},
                                types::primitives::{MAX_VRF_PROOF_BYTES},
                            };

                            let (prev_hash, base_fee, new_height) = {
                                let d = driver.lock().unwrap();
                                (d.engine.state.tip_hash, d.engine.state.base_fee, d.engine.state.height + 1)
                            };

                            let block = BlockV1 {
                                header: BlockHeaderV1 {
                                    protocol_version:    ProtocolVersion::CURRENT,
                                    height:              new_height,
                                    prev_hash,
                                    timestamp:           std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs(),
                                    state_root:          Bytes32::ZERO,
                                    validator_set_root:  Bytes32::ZERO,
                                    mempool_set_root:    Bytes32::ZERO,
                                    base_fee,
                                    proposer_vrf_output: Bytes32::ZERO,
                                    proposer_vrf_proof:  VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
                                    quorum_certificate:  indra_core::VariableBytes::from_slice(&[]).unwrap(),
                                },
                                transactions:      vec![],
                                slashing_evidence: vec![],
                                governance_ops:    vec![],
                            };

                            // Process locally
                            let _actions = driver.lock().unwrap().process(
                                DriverEvent::InboundBlock { from: None, block: block.clone() }
                            );

                            // Broadcast to peers
                            let _ = gossip.lock().unwrap().broadcast(&Message::Block(block));

                            let new_h = driver.lock().unwrap().height();
                            println!("[consensus] ✓ proposed block → height={}", new_h);
                        }
                    }
                }

                std::thread::sleep(Duration::from_millis(100));
            }
        });
    }

    // ── Thread 5: RPC server ────────────────────────────────────────────────
    // Inline HTTP/JSON-RPC handler — avoids circular dependency with indra-rpc.
    // Reads chain state directly from the driver under a brief lock.
    {
        let driver_rpc = Arc::clone(&driver);
        let rpc_addr = get_arg("--rpc-addr").unwrap_or_else(|| "127.0.0.1:8545".to_string());
        println!("[RPC] Listening on {}", rpc_addr);

        std::thread::spawn(move || {
            let listener = match std::net::TcpListener::bind(&rpc_addr) {
                Ok(l) => l,
                Err(e) => { eprintln!("[rpc] bind failed: {}", e); return; }
            };
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let driver_rpc = Arc::clone(&driver_rpc);
                        std::thread::spawn(move || {
                            handle_rpc(stream, &driver_rpc);
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
            let g = gossip.lock().unwrap();
            (d.height(), d.engine.state.base_fee, d.engine.mempool.len(), g.connection_count())
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

        last_height = height;
    }
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
    let end   = after[start..].find('"').unwrap_or(0) + start;
    hex::decode(&after[start..end]).unwrap_or_default()
}

fn extract_hex32(json: &str, field: &str) -> [u8; 32] {
    let key = format!("\"{}\":", field);
    let pos = json.find(&key)
        .unwrap_or_else(|| panic!("Field '{}' not found in keys.json", field));
    let after = &json[pos + key.len()..];
    let start = after.find('"').unwrap() + 1;
    let end   = after[start..].find('"').unwrap() + start;
    let hex_str = &after[start..end];
    let bytes = hex::decode(hex_str)
        .unwrap_or_else(|_| panic!("Invalid hex for field '{}'", field));
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    arr
}

/// Inline JSON-RPC handler for the node binary.
///
/// Reads one HTTP request, dispatches to the appropriate chain query,
/// and writes the JSON response. Locks the driver only for the duration
/// of the state read — not while writing the HTTP response.
fn handle_rpc(stream: std::net::TcpStream, driver: &Arc<Mutex<indra_node::driver::ConsensusDriver>>) {
    use std::io::{BufRead, BufReader, Write, Read};

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
        if reader.read_line(&mut line).is_err() { return; }
        let trimmed = line.trim();
        if first_line {
            if trimmed.starts_with("OPTIONS") { is_options = true; }
            first_line = false;
        }
        if trimmed.is_empty() { break; }
        if trimmed.to_lowercase().starts_with("content-length:") {
            content_length = trimmed["content-length:".len()..].trim().parse().unwrap_or(0);
        }
    }

    let cors = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n";

    if is_options {
        let resp = format!("HTTP/1.1 204 No Content\r\n{}Connection: close\r\n\r\n", cors);
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
    if reader.read_exact(&mut body_bytes).is_err() { return; }
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
                format!(r#"{{"height":{},"tip_hash":"{}"}}"#,
                    s.height, hex::encode(s.tip_hash.0))
            }
            "indra_getChainInfo" => {
                let block_reward_spark = indra_state::epoch::block_reward_at_height(s.height);
                let era = if s.height < indra_core::types::primitives::ERA_1_2_DURATION_BLOCKS {
                    1
                } else if s.height < indra_core::types::primitives::ERA_1_2_DURATION_BLOCKS * 2 {
                    2
                } else {
                    3 + ((s.height - (indra_core::types::primitives::ERA_1_2_DURATION_BLOCKS * 2))
                        / indra_core::types::primitives::ERA_3_PLUS_DURATION_BLOCKS)
                };
                format!(
                    r#"{{"height":{},"tip_hash":"{}","base_fee":{},"total_supply":{},"treasury_balance":{},"burn_buffer":{},"fee_reward_pool":{},"active_validators":{},"mempool_size":{},"epoch":{},"pruned_mode":{},"lowest_block":{},"blocks_retained":{},"block_reward_spark":{},"era":{}}}"#,
                    s.height,
                    hex::encode(s.tip_hash.0),
                    s.base_fee,
                    s.total_supply,
                    s.treasury_balance,
                    s.burn_buffer,
                    s.fee_reward_pool,
                    s.validators.active_count(),
                    mempool_size,
                    s.current_epoch(),
                    if guard.engine.block_store.is_archive() { "false" } else { "true" },
                    guard.engine.block_store.lowest_height(),
                    guard.engine.block_store.len(),
                    block_reward_spark,
                    era,
                )
            }
            "indra_getMempoolSize" => {
                format!(r#"{{"size":{}}}"#, mempool_size)
            }
            "indra_getValidatorSet" => {
                let entries: Vec<String> = s.validators.active_validators().map(|v| {
                    format!(
                        r#"{{"validator_id":"{}","stake":{},"status":"active","commission_bps":{},"pending_rewards":{},"epoch_joined":{}}}"#,
                        hex::encode(v.validator_id.0),
                        v.stake_spark,
                        v.commission_bps,
                        v.pending_rewards,
                        v.registered_epoch,
                    )
                }).collect();
                format!(r#"{{"validators":[{}]}}"#, entries.join(","))
            }
            "indra_sendTransaction" => {
                // Params: ["<tx_hex>"]
                let tx_hex = first_param.clone().unwrap_or_default();
                if tx_hex.is_empty() {
                    let err = format!(r#"{{"jsonrpc":"2.0","error":{{"code":-32602,"message":"missing tx_hex param"}},"id":{}}}"#, id_raw);
                    let resp = format!("HTTP/1.1 200 OK
Content-Type: application/json
{}Content-Length: {}
Connection: close

{}", cors, err.len(), err);
                    let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                    return;
                }
                let tx_bytes = match hex::decode(&tx_hex) {
                    Ok(b) => b,
                    Err(_) => {
                        let err = format!(r#"{{"jsonrpc":"2.0","error":{{"code":-32602,"message":"invalid hex encoding"}},"id":{}}}"#, id_raw);
                        let resp = format!("HTTP/1.1 200 OK
Content-Type: application/json
{}Content-Length: {}
Connection: close

{}", cors, err.len(), err);
                        let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                        return;
                    }
                };
                use indra_core::codec::{Decode, ByteReader};
                use indra_core::types::transaction::TransactionV1;
                let mut reader = ByteReader::new(&tx_bytes);
                match TransactionV1::decode(&mut reader) {
                    Ok(tx) => {
                        let base_fee = guard.engine.state.base_fee;
                        let height = guard.engine.state.height;
                        match guard.engine.mempool.submit(tx, base_fee, height) {
                            Ok(tx_id) => {
                                format!(r#"{{"tx_id":"{}","status":"accepted"}}"#,
                                    hex::encode(tx_id.0))
                            }
                            Err(e) => {
                                let err = format!(r#"{{"jsonrpc":"2.0","error":{{"code":-32000,"message":"mempool rejected: {}"}},"id":{}}}"#, e, id_raw);
                                let resp = format!("HTTP/1.1 200 OK
Content-Type: application/json
{}Content-Length: {}
Connection: close

{}", cors, err.len(), err);
                                let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        let err = format!(r#"{{"jsonrpc":"2.0","error":{{"code":-32602,"message":"tx decode failed: {}"}},"id":{}}}"#, e, id_raw);
                        let resp = format!("HTTP/1.1 200 OK
Content-Type: application/json
{}Content-Length: {}
Connection: close

{}", cors, err.len(), err);
                        let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
                        return;
                    }
                }
            }
            "indra_getBalance" => {
                // Params: ["<classical_pubkey_hex>"]
                let pubkey_hex = first_param.clone().unwrap_or_default();
                let mut balance: u64 = 0;
                if pubkey_hex.len() == 64 {
                    if let Ok(pk_bytes) = hex::decode(&pubkey_hex) {
                        for entry in s.utxos.all_entries() {
                            let owner = hex::encode(entry.output.owner_pubkey.classical_pk.0);
                            if owner == pubkey_hex {
                                balance = balance.saturating_add(
                                    // value is hidden in commitment — return 0 for now
                                    // wallet tracks actual values locally
                                    0u64
                                );
                            }
                            let _ = pk_bytes.len(); // suppress unused warning
                        }
                    }
                }
                // Note: values are confidential — balance must be tracked by wallet
                // This endpoint returns UTXO count only
                let utxo_count = if pubkey_hex.len() == 64 {
                    s.utxos.all_entries()
                        .filter(|e| hex::encode(e.output.owner_pubkey.classical_pk.0) == pubkey_hex)
                        .count()
                } else { 0 };
                format!(r#"{{"pubkey":"{}","utxo_count":{},"note":"values are confidential — use wallet scan for balance"}}"#,
                    pubkey_hex, utxo_count)
            }
            "indra_getUtxos" => {
                // Params: ["<classical_pubkey_hex>"]
                let pubkey_hex = first_param.clone().unwrap_or_default();
                let entries: Vec<String> = if pubkey_hex.len() == 64 {
                    s.utxos.all_entries()
                        .filter(|e| hex::encode(e.output.owner_pubkey.classical_pk.0) == pubkey_hex)
                        .map(|e| {
                            format!(
                                r#"{{"utxo_id":"{}","created_height":{},"tx_index":{},"out_index":{},"lock_height":{}}}"#,
                                hex::encode(e.utxo_id.0),
                                e.created_height,
                                e.tx_index,
                                e.output_index,
                                e.output.lock_height,
                            )
                        })
                        .collect()
                } else { vec![] };
                format!(r#"{{"pubkey":"{}","utxos":[{}]}}"#,
                    pubkey_hex, entries.join(","))
            }
            _ => {
                let err = format!(r#"{{"jsonrpc":"2.0","error":{{"code":-32601,"message":"method not found: {}"}},"id":{}}}"#, method, id_raw);
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
    let _ = stream.try_clone().map(|mut w| w.write_all(http_resp.as_bytes()));
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
