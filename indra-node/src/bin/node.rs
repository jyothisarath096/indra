//! INDRA node binary.
//!
//! Thread layout:
//!
//!   main            — status printer (every 6s)
//!   listener        — accepts inbound TCP connections from peers
//!   dialer          — connects to bootstrap peers, sends Status
//!   gossip_recv     — reads messages from peers, forwards events to reactor
//!   consensus       — single-owner consensus reactor (owns ConsensusDriver)
//!   action_exec     — executes outbound network actions from reactor
//!   rpc             — serves HTTP/JSON-RPC from shared chain snapshots

use std::net::{SocketAddr, TcpListener, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::sync::{
    mpsc::{self, Sender},
    Arc, Mutex,
};
use std::time::Duration;

use fs2::available_space;
use indra_core::codec::{ByteReader, Decode};
use indra_core::types::{
    primitives::{
        DEFAULT_PRUNE_KEEP_BLOCKS,
        DISK_CRITICAL_THRESHOLD_BYTES,
        DISK_WARN_THRESHOLD_BYTES,
        MIN_PRUNE_KEEP_BLOCKS,
    },
    transaction::TransactionV1,
};
use indra_network::{
    gossip::GossipEngine,
    message::Message,
    peer::ScoreEvent,
    transport::{Connection, RecvStatus, Transport},
};
use indra_node::{
    driver::ConsensusDriver,
    reactor::{
        ChainSnapshot, ConsensusAction, ConsensusEvent, ConsensusReactor, STATUS_INTERVAL,
    },
    NodeConfig, NodeEngine,
};

const DIAL_RETRY: Duration = Duration::from_secs(5);
const DEFAULT_BOOTSTRAP_PEER: &str = "bootstrap.indraprotocol.com:30303";

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
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };

    let keys_path = get_arg("--keys").unwrap_or_else(|| "keys.json".to_string());
    let data_dir = get_arg("--data-dir").unwrap_or_else(|| "./indra-data".to_string());
    let p2p_addr = get_arg("--p2p-addr").unwrap_or_else(|| "0.0.0.0:30303".to_string());
    let bootstrap = get_arg("--bootstrap-peers");
    let archive = args.iter().any(|arg| arg == "--archive");
    let prune_keep = get_arg("--prune-keep")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_PRUNE_KEEP_BLOCKS)
        .max(MIN_PRUNE_KEEP_BLOCKS);

    println!("╔══════════════════════════════════════════╗");
    println!("║      INDRA v2 — Node Starting             ║");
    println!("╚══════════════════════════════════════════╝");
    println!("Keys:      {}", keys_path);
    println!("Data:      {}", data_dir);
    println!("P2P:       {}", p2p_addr);
    println!("Mode:      {}", if archive { "archive" } else { "pruned" });
    if !archive {
        println!("Retain:    {} blocks", prune_keep);
    }

    check_disk_space(Path::new(&data_dir));

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
            if should_skip_default_bootstrap(&p2p_addr, DEFAULT_BOOTSTRAP_PEER) {
                println!("Bootstrap: (bootstrap node)");
                vec![]
            } else {
                println!(
                    "[p2p] using default bootstrap peer: {}",
                    DEFAULT_BOOTSTRAP_PEER
                );
                println!("Bootstrap: {}", DEFAULT_BOOTSTRAP_PEER);
                vec![DEFAULT_BOOTSTRAP_PEER.to_string()]
            }
        }
    };
    if bootstrap_peers.is_empty() && bootstrap.is_some() {
        println!("Bootstrap: (bootstrap node)");
    } else if let Some(raw_bootstrap) = &bootstrap {
        println!("Bootstrap: {}", raw_bootstrap);
    }

    let config = NodeConfig {
        data_dir: std::path::PathBuf::from(&data_dir),
        validator_seed: Some(hybrid_seed),
        bls_seed: Some(bls_seed),
        vrf_seed: Some(vrf_seed),
        pq_sk: if pq_sk.is_empty() { None } else { Some(pq_sk) },
        pq_pk: if pq_pk.is_empty() { None } else { Some(pq_pk) },
        p2p_addr: p2p_addr.clone(),
        bootstrap_peers: bootstrap_peers.clone(),
        snapshot_interval: 300,
        mempool_capacity: 5_000,
        prune_keep_blocks: if archive { None } else { Some(prune_keep) },
        strict_header_verification: false,
    };

    let mut engine = NodeEngine::init(config).unwrap_or_else(|e| panic!("Node init failed: {}", e));

    let genesis_path = get_arg("--genesis").unwrap_or_else(|| "genesis.toml".to_string());
    if std::path::Path::new(&genesis_path).exists() {
        indra_node::load_genesis_validators(&genesis_path, &mut engine.state);
        engine
            .rebuild_state_from_block_log()
            .unwrap_or_else(|e| panic!("State replay failed after loading genesis validators: {}", e));
        println!(
            "Validator set: {} active validators",
            engine.state.validators.active_count()
        );
    } else {
        println!(
            "[warning] genesis.toml not found at {} — validator set empty",
            genesis_path
        );
    }

    let validator_id = engine
        .validator_id()
        .map(|id| hex::encode(id.0))
        .unwrap_or_else(|| "full-node".to_string());

    println!("\nValidator: {}...", &validator_id[..16]);
    println!("Height:    {}", engine.height());
    println!("\nStarting P2P and consensus...\n");

    let mut driver_state = ConsensusDriver::new(engine);
    driver_state.refresh_registered_voters();

    let snapshot = Arc::new(Mutex::new(ChainSnapshot::from_driver(&driver_state)));
    let gossip = Arc::new(Mutex::new(GossipEngine::new()));
    let (event_tx, event_rx) = mpsc::channel::<ConsensusEvent>();
    let (action_tx, action_rx) = mpsc::channel::<ConsensusAction>();

    {
        let gossip = Arc::clone(&gossip);
        let snapshot = Arc::clone(&snapshot);
        let p2p = p2p_addr.clone();

        std::thread::spawn(move || {
            let listener = match TcpListener::bind(&p2p) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[listener] bind failed: {}", e);
                    return;
                }
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
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

                        if let Ok(conn) = Connection::from_stream(stream) {
                            let _ = gossip.lock().unwrap().add_connection(addr, conn);
                        }

                        let status = {
                            let snap = snapshot.lock().unwrap().clone();
                            Message::Status {
                                height: snap.state.height,
                                tip_hash: snap.state.tip_hash,
                            }
                        };
                        let _ = gossip.lock().unwrap().send_to(&addr, &status);
                    }
                    Err(e) => eprintln!("[listener] accept error: {}", e),
                }
            }
        });
    }

    {
        let gossip = Arc::clone(&gossip);
        let snapshot = Arc::clone(&snapshot);
        let peers = bootstrap_peers.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));

            let transport = match Transport::bind("0.0.0.0:0") {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[dialer] transport bind failed: {}", e);
                    return;
                }
            };

            loop {
                for peer_addr_str in &peers {
                    let addr = match resolve_peer_addr(peer_addr_str) {
                        Some(addr) => addr,
                        None => {
                            eprintln!("[dialer] invalid addr: {}", peer_addr_str);
                            continue;
                        }
                    };

                    if gossip
                        .lock()
                        .unwrap()
                        .peers()
                        .connected()
                        .iter()
                        .any(|p| p.addr == addr)
                    {
                        continue;
                    }

                    println!("[P2P] Dialing {}...", addr);
                    match transport.dial(addr) {
                        Ok(conn) => {
                            println!("[P2P] Connected to {}", addr);
                            let _ = gossip.lock().unwrap().add_connection(addr, conn);

                            let status = {
                                let snap = snapshot.lock().unwrap().clone();
                                Message::Status {
                                    height: snap.state.height,
                                    tip_hash: snap.state.tip_hash,
                                }
                            };
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

    {
        let gossip = Arc::clone(&gossip);
        let event_tx = event_tx.clone();

        std::thread::spawn(move || loop {
            let addrs = gossip.lock().unwrap().connected_addrs();

            for addr in addrs {
                let msg = {
                    let mut g = gossip.lock().unwrap();
                    match g.recv_from(&addr) {
                        Ok(RecvStatus::Message(m)) => Some(m),
                        Ok(RecvStatus::NoData) => None,
                        Ok(RecvStatus::Disconnected) => {
                            eprintln!("[gossip] peer {} disconnected", addr);
                            g.remove_connection(&addr);
                            None
                        }
                        Err(e) => {
                            eprintln!("[gossip] peer {} disconnected: {}", addr, e);
                            g.remove_connection(&addr);
                            None
                        }
                    }
                };

                if let Some(msg) = msg {
                    gossip.lock().unwrap().score_event(&addr, ScoreEvent::ValidBlock);

                    let event = match msg {
                        Message::Block(block) => Some(ConsensusEvent::ProposalReceived {
                            from: Some(addr),
                            block,
                        }),
                        Message::Vote(vote) => Some(ConsensusEvent::VoteReceived { from: addr, vote }),
                        Message::Tx(tx) => Some(ConsensusEvent::TxReceived { from: addr, tx }),
                        Message::Status { height, tip_hash } => Some(ConsensusEvent::PeerStatus {
                            from: addr,
                            height,
                            tip_hash,
                        }),
                        Message::RequestBlocks {
                            from_height,
                            to_height,
                        } => Some(ConsensusEvent::BlocksRequested {
                            from: addr,
                            from_height,
                            to_height,
                        }),
                        Message::BlockResponse { blocks } => {
                            Some(ConsensusEvent::BlocksResponse { blocks })
                        }
                        Message::RequestProposal { height, round, hash } => {
                            Some(ConsensusEvent::ProposalRequest {
                                from: addr,
                                height,
                                round,
                                hash,
                            })
                        }
                        Message::PeerList(_) | Message::Ping(_) | Message::Pong(_) => None,
                    };

                    if let Some(event) = event {
                        let _ = event_tx.send(event);
                    }
                }
            }

            std::thread::sleep(Duration::from_millis(1));
        });
    }

    {
        let snapshot = Arc::clone(&snapshot);
        let event_tx_reactor = event_tx.clone();
        let gossip_reactor = Arc::clone(&gossip);
        std::thread::spawn(move || {
            let reactor = ConsensusReactor::new(
                driver_state,
                event_tx_reactor,
                event_rx,
                action_tx,
                gossip_reactor,
                snapshot,
            );
            reactor.run();
        });
    }

    {
        let gossip = Arc::clone(&gossip);
        std::thread::spawn(move || {
            while let Ok(action) = action_rx.recv() {
                execute_consensus_action(&gossip, action);
            }
        });
    }

    {
        let snapshot_rpc = Arc::clone(&snapshot);
        let gossip_rpc = Arc::clone(&gossip);
        let event_tx_rpc = event_tx.clone();
        let rpc_addr = get_arg("--rpc-addr").unwrap_or_else(|| "127.0.0.1:8545".to_string());
        println!("[RPC] Listening on {}", rpc_addr);

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
                        let snapshot_rpc = Arc::clone(&snapshot_rpc);
                        let gossip_rpc = Arc::clone(&gossip_rpc);
                        let event_tx_rpc = event_tx_rpc.clone();
                        std::thread::spawn(move || {
                            handle_rpc(stream, &snapshot_rpc, &gossip_rpc, &event_tx_rpc);
                        });
                    }
                    Err(e) => eprintln!("[rpc] accept error: {}", e),
                }
            }
        });
    }

    let mut last_height = 0u64;
    let mut tick = 0u64;

    loop {
        std::thread::sleep(STATUS_INTERVAL);
        tick += 1;

        let snap = snapshot.lock().unwrap().clone();
        let peers = gossip.lock().unwrap().connection_count();
        let height = snap.state.height;
        let base_fee = snap.state.base_fee;
        let mempool = snap.mempool_size;

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

fn execute_consensus_action(gossip: &Arc<Mutex<GossipEngine>>, action: ConsensusAction) {
    match action {
        ConsensusAction::BroadcastBlock(block) => {
            let peers = gossip.lock().unwrap().connection_count();
            eprintln!(
                "[gossip] broadcasting proposal {} to {} peers",
                hex::encode(&block.header.block_hash().0[..4]),
                peers,
            );
            let _ = gossip.lock().unwrap().broadcast_priority(&Message::Block(block));
        }
        ConsensusAction::BroadcastVote(vote) => {
            let peers = gossip.lock().unwrap().connection_count();
            eprintln!(
                "[vote] sent vote for {} to {} peers",
                hex::encode(&vote.block_hash.0[..4]),
                peers,
            );
            let _ = gossip.lock().unwrap().broadcast(&Message::Vote(vote));
        }
        ConsensusAction::BroadcastTx(tx) => {
            let peers = gossip.lock().unwrap().connection_count();
            eprintln!(
                "[mempool] broadcasting tx {} to {} peers",
                hex::encode(&tx.tx_hash().0[..4]),
                peers,
            );
            let _ = gossip.lock().unwrap().broadcast(&Message::Tx(tx));
        }
        ConsensusAction::BroadcastStatus { height, tip_hash } => {
            let _ = gossip
                .lock()
                .unwrap()
                .broadcast(&Message::Status { height, tip_hash });
        }
        ConsensusAction::SendTo { peer, msg } => {
            let _ = gossip.lock().unwrap().send_to(&peer, &msg);
        }
        ConsensusAction::HeightAdvanced { .. } | ConsensusAction::None => {}
    }
}

fn check_disk_space(data_dir: &Path) -> u64 {
    let available = available_space(data_dir).unwrap_or(0);
    if available > 0 && available < DISK_CRITICAL_THRESHOLD_BYTES {
        eprintln!("[disk] CRITICAL: only {} MB remaining", available / 1024 / 1024);
    } else if available > 0 && available < DISK_WARN_THRESHOLD_BYTES {
        eprintln!(
            "[disk] WARNING: only {} GB remaining",
            available / 1024 / 1024 / 1024
        );
    }
    available
}

fn should_skip_default_bootstrap(local_p2p_addr: &str, default_peer: &str) -> bool {
    if local_p2p_addr == default_peer {
        return true;
    }

    let Some(default_socket) = resolve_first_socket_addr(default_peer) else {
        return false;
    };

    if let Ok(local_addrs) = local_p2p_addr.to_socket_addrs() {
        for addr in local_addrs {
            if addr == default_socket {
                return true;
            }
        }
    }

    if let Some(local_port) = local_p2p_addr
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
    {
        if local_port == default_socket.port() {
            if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
                if sock.connect(default_socket).is_ok() {
                    if let Ok(local_outbound) = sock.local_addr() {
                        if local_outbound.ip() == default_socket.ip() {
                            return true;
                        }
                    }
                }
            }
        }
    }

    false
}

fn resolve_first_socket_addr(addr: &str) -> Option<SocketAddr> {
    addr.to_socket_addrs().ok()?.next()
}

fn resolve_peer_addr(addr: &str) -> Option<SocketAddr> {
    if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
        return Some(socket_addr);
    }

    let resolved = resolve_first_socket_addr(addr)?;
    println!("[p2p] resolved {} -> {}", addr, resolved);
    Some(resolved)
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
    let bytes = hex::decode(hex_str).unwrap_or_else(|_| panic!("Invalid hex for field '{}'", field));
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    arr
}

/// Inline JSON-RPC handler.
fn handle_rpc(
    stream: std::net::TcpStream,
    snapshot: &Arc<Mutex<ChainSnapshot>>,
    gossip: &Arc<Mutex<GossipEngine>>,
    event_tx: &Sender<ConsensusEvent>,
) {
    use std::io::{BufRead, BufReader, Read, Write};

    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));

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
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            cors,
            body.len(),
            body
        );
        let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
        return;
    }

    let mut body_bytes = vec![0u8; content_length.min(1_048_576)];
    if reader.read_exact(&mut body_bytes).is_err() {
        return;
    }
    let body_str = String::from_utf8_lossy(&body_bytes);

    let method = extract_json_str(&body_str, "method").unwrap_or_default();
    let id_raw = extract_json_id(&body_str);
    let first_param = extract_json_first_param(&body_str);

    let result: String = match method.as_str() {
        "indra_getHeight" => {
            let snap = snapshot.lock().unwrap().clone();
            format!(r#"{{"height":{}}}"#, snap.state.height)
        }
        "indra_getTip" => {
            let snap = snapshot.lock().unwrap().clone();
            format!(
                r#"{{"height":{},"tip_hash":"{}"}}"#,
                snap.state.height,
                hex::encode(snap.state.tip_hash.0)
            )
        }
        "indra_getChainInfo" => {
            let snap = snapshot.lock().unwrap().clone();
            let s = &snap.state;
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
                3 + ((s.height
                    - (indra_core::types::primitives::ERA_1_2_DURATION_BLOCKS * 2))
                    / indra_core::types::primitives::ERA_3_PLUS_DURATION_BLOCKS)
            };
            format!(
                r#"{{"height":{},"tip_hash":"{}","base_fee":{},"total_supply":{},"treasury_balance":{},"burn_buffer":{},"fee_reward_pool":{},"active_validators":{},"max_active_validators":{},"total_staked_spark":{},"effective_min_stake_spark":{},"validator_set_phase":{},"mempool_size":{},"epoch":{},"pruned_mode":{},"lowest_block":{},"blocks_retained":{},"block_reward_spark":{},"era":{},"peers":{}}}"#,
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
                snap.mempool_size,
                s.current_epoch(),
                if snap.archive { "false" } else { "true" },
                snap.lowest_block,
                snap.retained_blocks,
                block_reward_spark,
                era,
                gossip.lock().unwrap().connection_count(),
            )
        }
        "indra_getMempoolSize" => {
            let snap = snapshot.lock().unwrap().clone();
            format!(r#"{{"size":{}}}"#, snap.mempool_size)
        }
        "indra_getValidator" => {
            let snap = snapshot.lock().unwrap().clone();
            let validator_hex = first_param.clone().unwrap_or_default();
            if validator_hex.len() == 64 {
                let mut validator_bytes = [0u8; 32];
                if let Ok(decoded) = hex::decode(&validator_hex) {
                    if decoded.len() == 32 {
                        validator_bytes.copy_from_slice(&decoded);
                    }
                }
                let validator_id = indra_core::Bytes32::from(validator_bytes);
                match snap.state.validators.get(&validator_id) {
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
            }
        }
        "indra_getValidatorSet" => {
            let snap = snapshot.lock().unwrap().clone();
            let entries: Vec<String> = snap
                .state
                .validators
                .active_validators()
                .map(|v| {
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
                })
                .collect();
            format!(r#"{{"validators":[{}]}}"#, entries.join(","))
        }
        "indra_sendTransaction" => {
            let tx_hex = first_param.clone().unwrap_or_default();
            if tx_hex.is_empty() {
                write_json_rpc_error(
                    &stream,
                    cors,
                    id_raw.as_str(),
                    -32602,
                    "missing tx_hex param",
                );
                return;
            }
            let tx_bytes = match hex::decode(&tx_hex) {
                Ok(b) => b,
                Err(_) => {
                    write_json_rpc_error(
                        &stream,
                        cors,
                        id_raw.as_str(),
                        -32602,
                        "invalid hex encoding",
                    );
                    return;
                }
            };
            let mut reader = ByteReader::new(&tx_bytes);
            let tx = match TransactionV1::decode(&mut reader) {
                Ok(tx) => tx,
                Err(e) => {
                    write_json_rpc_error(
                        &stream,
                        cors,
                        id_raw.as_str(),
                        -32602,
                        format!("tx decode failed: {}", e).as_str(),
                    );
                    return;
                }
            };

            let (reply_tx, reply_rx) = mpsc::sync_channel(1);
            let _ = event_tx.send(ConsensusEvent::SubmitTx {
                tx,
                reply: reply_tx,
            });
            match reply_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(Ok(tx_id)) => {
                    format!(
                        r#"{{"tx_id":"{}","status":"accepted"}}"#,
                        hex::encode(tx_id.0)
                    )
                }
                Ok(Err(e)) => {
                    write_json_rpc_error(
                        &stream,
                        cors,
                        id_raw.as_str(),
                        -32000,
                        format!("mempool rejected: {}", e).as_str(),
                    );
                    return;
                }
                Err(_) => {
                    write_json_rpc_error(
                        &stream,
                        cors,
                        id_raw.as_str(),
                        -32001,
                        "consensus reactor unavailable",
                    );
                    return;
                }
            }
        }
        "indra_getBalance" => {
            let snap = snapshot.lock().unwrap().clone();
            let address_hex = first_param.clone().unwrap_or_default();
            let mut balance: u64 = 0;
            if address_hex.len() == 64 {
                for entry in snap.state.utxos.all_entries() {
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
            let snap = snapshot.lock().unwrap().clone();
            let address_hex = first_param.clone().unwrap_or_default();
            let entries: Vec<String> = if address_hex.len() == 64 {
                snap.state
                    .utxos
                    .all_entries()
                    .filter(|e| {
                        hex::encode(indra_crypto::sha256(&e.output.owner_pubkey.classical_pk.0))
                            == address_hex
                    })
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
            let snap = snapshot.lock().unwrap().clone();
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
                    let proof = snap.state.utxos.prove(&utxo_id);
                    let siblings = proof
                        .siblings
                        .iter()
                        .map(|sibling| format!(r#""{}""#, hex::encode(sibling)))
                        .collect::<Vec<_>>()
                        .join(",");
                    let value_hash = proof.value.map(hex::encode).unwrap_or_default();
                    let state_root = indra_state::compute_state_root(&snap.state);
                    format!(
                        r#"{{"utxo_id":"{}","present":{},"value_hash":"{}","siblings":[{}],"state_root":"{}"}}"#,
                        hex::encode(utxo_id.0),
                        if proof.value.is_some() { "true" } else { "false" },
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
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                cors,
                err.len(),
                err
            );
            let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
            return;
        }
    };

    let json_resp = format!(r#"{{"jsonrpc":"2.0","result":{},"id":{}}}"#, result, id_raw);
    let http_resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        cors,
        json_resp.len(),
        json_resp
    );
    let _ = stream
        .try_clone()
        .map(|mut w| w.write_all(http_resp.as_bytes()));
}

fn write_json_rpc_error(
    stream: &std::net::TcpStream,
    cors: &str,
    id_raw: &str,
    code: i64,
    message: &str,
) {
    use std::io::Write;

    let err = format!(
        r#"{{"jsonrpc":"2.0","error":{{"code":{},"message":"{}"}},"id":{}}}"#,
        code, message, id_raw
    );
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        cors,
        err.len(),
        err
    );
    let _ = stream.try_clone().map(|mut w| w.write_all(resp.as_bytes()));
}

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
        let end = arr.find(|c: char| !c.is_ascii_digit()).unwrap_or(arr.len());
        Some(arr[..end].to_string())
    }
}

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

fn extract_json_id(json: &str) -> String {
    let needle = "\"id\"";
    if let Some(pos) = json.find(needle) {
        let after = &json[pos + needle.len()..];
        if let Some(colon) = after.find(':') {
            let rest = after[colon + 1..].trim_start();
            let end = rest.find([',', '}']).unwrap_or(rest.len());
            return rest[..end].trim().to_string();
        }
    }
    "null".to_string()
}
