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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use indra_core::{
    codec::Encode,
    types::primitives::Bytes32,
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
    let get_arg = |flag: &str| -> Option<String> {
        args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
    };

    let keys_path  = get_arg("--keys").unwrap_or_else(|| "keys.json".to_string());
    let data_dir   = get_arg("--data-dir").unwrap_or_else(|| "./indra-data".to_string());
    let p2p_addr   = get_arg("--p2p-addr").unwrap_or_else(|| "0.0.0.0:30303".to_string());
    let bootstrap  = get_arg("--bootstrap-peers").unwrap_or_default();

    println!("╔══════════════════════════════════════════╗");
    println!("║      INDRA v2 — Phase 8 Node Starting     ║");
    println!("╚══════════════════════════════════════════╝");
    println!("Keys:      {}", keys_path);
    println!("Data:      {}", data_dir);
    println!("P2P:       {}", p2p_addr);
    println!("Bootstrap: {}", if bootstrap.is_empty() { "(bootstrap node)" } else { &bootstrap });

    // Load keys
    let keys_str = std::fs::read_to_string(&keys_path)
        .unwrap_or_else(|e| panic!("Cannot read {}: {}", keys_path, e));
    let hybrid_seed = extract_hex32(&keys_str, "hybrid_seed");
    let bls_seed    = extract_hex32(&keys_str, "bls_seed");
    let vrf_seed    = extract_hex32(&keys_str, "vrf_seed");

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
        p2p_addr:          p2p_addr.clone(),
        bootstrap_peers:   bootstrap_peers.clone(),
        snapshot_interval: 300,
        mempool_capacity:  5_000,
    };

    // Init node engine + consensus driver
    let mut engine = NodeEngine::init(config)
        .unwrap_or_else(|e| panic!("Node init failed: {}", e));

    // Load validator set from genesis.toml
    let genesis_path = get_arg("--genesis").unwrap_or_else(|| "genesis.toml".to_string());
    if std::path::Path::new(&genesis_path).exists() {
        indra_node::load_genesis_validators(&genesis_path, &mut engine.state);
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
        let p2p      = p2p_addr.clone();

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
                            let total_stake = d.engine.state.validators.total_active_stake();
                            let candidates: Vec<indra_consensus::proposer::ProposerCandidate> =
                                d.engine.state.validators.active_validators()
                                    .map(|v| indra_consensus::proposer::ProposerCandidate {
                                        validator_id: v.validator_id,
                                        vrf_pubkey: indra_crypto::sha256(&v.validator_id.0),
                                        stake: v.stake_spark,
                                    })
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
                            let actions = driver.lock().unwrap().process(
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

        last_height = height;
    }
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
