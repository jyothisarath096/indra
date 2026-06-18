//! INDRA v2 node binary — Phase 8: live P2P consensus.
//!
//! Thread layout:
//!
//!   main          — status printer (every 6s)
//!   listener      — accepts inbound TCP connections from peers
//!   dialer        — connects to bootstrap peers, sends Status
//!   gossip_recv   — reads messages from all connected peers, routes to driver
//!   consensus     — every 6s: check if proposer, propose block, broadcast votes

use std::net::{SocketAddr, TcpListener, ToSocketAddrs, UdpSocket};
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
    transport::{RecvStatus, Transport},
    gossip::GossipEngine,
};
use indra_node::{
    NodeConfig, NodeEngine,
    driver::{ConsensusDriver, DriverAction, DriverEvent, RoundPhase},
    net_driver::{message_to_event, action_to_message},
    sync::SYNC_BATCH_SIZE,
};

const PROPOSE_TIMEOUT: Duration = Duration::from_secs(8);
const PREVOTE_TIMEOUT: Duration = Duration::from_secs(3);
const PRECOMMIT_TIMEOUT: Duration = Duration::from_secs(3);
const MIN_BLOCK_INTERVAL_SECS: u64 = 6;
const DIAL_RETRY: Duration = Duration::from_secs(5);
const STATUS_INTERVAL: Duration = Duration::from_secs(6);
const DEFAULT_BOOTSTRAP_PEER: &str = "bootstrap.indraprotocol.com:30303";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProposalMode {
    None,
    Fresh,
    Reproposal,
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
    let bootstrap  = get_arg("--bootstrap-peers");
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

    let bootstrap_peers: Vec<String> = match bootstrap.as_deref() {
        Some(value) => value.split(',').map(|s| s.trim().to_string()).collect(),
        None => {
            if should_skip_default_bootstrap(&p2p_addr, DEFAULT_BOOTSTRAP_PEER) {
                println!("Bootstrap: (bootstrap node)");
                vec![]
            } else {
                println!("[p2p] using default bootstrap peer: {}", DEFAULT_BOOTSTRAP_PEER);
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
        strict_header_verification: true,
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

    let mut driver_state = ConsensusDriver::new(engine);
    driver_state.refresh_registered_voters();
    let startup_qc_request = driver_state.request_qc_if_needed();
    let driver = driver_state;

    // Shared state between threads
    let driver    = Arc::new(Mutex::new(driver));
    let gossip    = Arc::new(Mutex::new(GossipEngine::new()));
    let (height_tx, height_rx) = std::sync::mpsc::channel::<()>();

    // ── Thread 1: P2P listener ──────────────────────────────────────────────
    {
        let gossip  = Arc::clone(&gossip);
        let driver  = Arc::clone(&driver);
        let height_tx = height_tx.clone();
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

                        if let Ok(conn) = indra_network::transport::Connection::from_stream(stream) {
                            let _ = gossip.lock().unwrap().add_connection(addr, conn);
                        }
                        announce_status_and_recovery(&driver, &gossip, &height_tx, addr);
                    }
                    Err(e) => eprintln!("[listener] accept error: {}", e),
                }
            }
        });
    }

    // ── Thread 2: Peer dialer ───────────────────────────────────────────────
    {
        let gossip   = Arc::clone(&gossip);
        let driver   = Arc::clone(&driver);
        let height_tx = height_tx.clone();
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
                    let addr = match resolve_peer_addr(peer_addr_str) {
                        Some(addr) => addr,
                        None => {
                            eprintln!("[dialer] invalid addr: {}", peer_addr_str);
                            continue;
                        }
                    };

                    // Skip if already connected
                    if gossip.lock().unwrap().peers().connected().iter().any(|p| p.addr == addr) {
                        continue;
                    }

                    println!("[P2P] Dialing {}...", addr);
                    match transport.dial(addr) {
                        Ok(conn) => {
                            println!("[P2P] Connected to {}", addr);
                            let _ = gossip.lock().unwrap().add_connection(addr, conn);
                            announce_status_and_recovery(&driver, &gossip, &height_tx, addr);
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
        let gossip  = Arc::clone(&gossip);
        let driver  = Arc::clone(&driver);
        let height_tx = height_tx.clone();

        std::thread::spawn(move || {
            loop {
                let addrs = gossip.lock().unwrap().connected_addrs();

                for addr in addrs {
                    let msg = {
                        let mut g = gossip.lock().unwrap();
                        match g.recv_from(&addr) {
                            Ok(RecvStatus::Message(m)) => Some(m),
                            Ok(RecvStatus::NoData) => {
                                // No data yet — keep connection alive
                                None
                            }
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
                        // Score the peer
                        gossip.lock().unwrap().score_event(&addr, ScoreEvent::ValidBlock);

                        // QC recovery message ingress logging — remove after confirmed working
                        match &msg {
                            Message::RequestQC { height } => {
                                eprintln!(
                                    "[qc-ingress] received RequestQC for height {} from {}",
                                    height, addr
                                );
                            }
                            Message::QCResponse { height, qc_bytes } => {
                                eprintln!(
                                    "[qc-ingress] received QCResponse for height {} ({} bytes) from {}",
                                    height,
                                    qc_bytes.len(),
                                    addr
                                );
                            }
                            _ => {}
                        }

                        match &msg {
                            Message::RequestBlocks { from_height, to_height } => {
                                let upper = (*to_height).min((*from_height).saturating_add(SYNC_BATCH_SIZE - 1));
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
                                eprintln!("[sync] serving blocks {}..{} to {}", from_height, upper, addr);
                                let _ = gossip.lock().unwrap().send_to(
                                    &addr,
                                    &Message::BlockResponse { blocks: blocks_to_send },
                                );
                                continue;
                            }
                            Message::RequestProposal { height, round, hash } => {
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
                                    eprintln!(
                                        "[gossip] received proposal request for {} at height={} round={} — sending block",
                                        hex::encode(&hash.0[..4]),
                                        height,
                                        round,
                                    );
                                    let _ = gossip.lock().unwrap().send_to(&addr, &Message::Block(block));
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
                                                d.refresh_registered_voters();
                                                d.sync_mut().on_block_imported(block.header.height);
                                                d.reset_round();
                                                eprintln!(
                                                    "[sync] imported block at height={} from {}",
                                                    block.header.height,
                                                    addr
                                                );
                                            }
                                            Err(e) => {
                                                eprintln!(
                                                    "[sync] failed to import block {} from {}: {}",
                                                    block.header.height,
                                                    addr,
                                                    e
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
                                    request_more = d.sync_mut().next_request_after_response(new_height);
                                    if d.sync().is_caught_up() {
                                        d.on_sync_caught_up();
                                        caught_up_height = Some(new_height);
                                    }
                                }

                                if let Some((peer, from_height, to_height)) = request_more {
                                    let req = Message::RequestBlocks { from_height, to_height };
                                    let _ = gossip.lock().unwrap().send_to(&peer, &req);
                                }
                                if imported_any {
                                    let _ = height_tx.send(());
                                    broadcast_status(&driver, &gossip);
                                }
                                if let Some(height) = caught_up_height {
                                    eprintln!("[sync] caught up to height={}, joining consensus", height);
                                }
                                continue;
                            }
                            Message::Ping(_) => {
                                let (height, tip_hash) = {
                                    let d = driver.lock().unwrap();
                                    (d.height(), d.engine.state.tip_hash)
                                };
                                let _ = gossip.lock().unwrap().send_to(
                                    &addr,
                                    &Message::Status { height, tip_hash },
                                );
                                continue;
                            }
                            _ => {}
                        }

                        // Convert to driver event and process
                        if let Some(event) = message_to_event(msg, addr) {
                            let previous_height = driver.lock().unwrap().height();
                            let actions = driver.lock().unwrap().process(event);
                            process_driver_actions(&driver, &gossip, &height_tx, previous_height, actions);
                            let new_height = driver.lock().unwrap().height();
                            if new_height > previous_height {
                                let _ = height_tx.send(());
                                broadcast_status(&driver, &gossip);
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
        let height_tx = height_tx.clone();
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

            loop {
                let (height, round, phase, sync_target, sync_caught_up, connected, tip_hash) = {
                    let d = driver.lock().unwrap();
                    (
                        d.height(),
                        d.current_round(),
                        d.current_phase(),
                        d.sync().target_height(),
                        d.sync().is_caught_up(),
                        gossip.lock().unwrap().connection_count(),
                        d.engine.state.tip_hash,
                    )
                };
                let last_qc_bytes_empty = driver.lock().unwrap().last_qc_bytes().is_empty();
                if round == 0 || round % 10 == 0 {
                    eprintln!(
                        "[qc-debug] height={} round={} last_qc_bytes_empty={}",
                        height, round, last_qc_bytes_empty
                    );
                }

                if height > last_observed_height {
                    last_commit_time = Some(std::time::SystemTime::now());
                    last_observed_height = height;
                }

                if last_qc_bytes_empty && round % 10 == 0 {
                    let actions = driver.lock().unwrap().request_qc_if_needed();
                    if !actions.is_empty() {
                        process_driver_actions(&driver, &gossip, &height_tx, height, actions);
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
                    eprintln!("[consensus] waiting for peers (have {}, need 2)", connected);
                    phase_started_at = Instant::now();
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }

                if connected == 0 {
                    println!("[consensus] height={} waiting for peers...", height);
                } else if last_status_at.elapsed() >= STATUS_INTERVAL {
                    println!("[consensus] height={} peers={} round={} phase={:?}", height, connected, round, phase);
                    let status = Message::Status { height, tip_hash };
                    let _ = gossip.lock().unwrap().broadcast(&status);
                    last_status_at = Instant::now();
                }

                if !sync_caught_up {
                    if let Some(target) = sync_target {
                        println!("[consensus] syncing — height={} target={}", height, target);
                    }
                    match height_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(()) => {
                            phase_started_at = Instant::now();
                            proposed_at_slot = None;
                        }
                        Err(_) => {}
                    }
                    continue;
                }

                if let Some(target) = sync_target {
                    println!("[consensus] syncing — height={} target={}", height, target);
                } else {
                    match phase {
                        RoundPhase::Propose => {
                            let (should_propose, next_height) = {
                                let d = driver.lock().unwrap();
                                let epoch_seed = indra_core::types::primitives::Bytes32::from(
                                    indra_crypto::sha256(&d.engine.state.tip_hash.0)
                                );
                                let height = d.engine.state.height + 1;
                                let round = d.current_round();
                                let candidates: Vec<indra_consensus::proposer::ProposerCandidate> =
                                    d.engine.state.validators.active_validators()
                                        .filter_map(|v| v.vrf_pk.map(|vrf_pk| indra_consensus::proposer::ProposerCandidate {
                                            validator_id: v.validator_id,
                                            vrf_pubkey: vrf_pk,
                                            stake: v.stake_spark,
                                        }))
                                        .collect();

                                if candidates.is_empty() {
                                    (
                                        d.can_propose() && d.engine.config.bootstrap_peers.is_empty(),
                                        height,
                                    )
                                } else {
                                    let election = indra_consensus::proposer::ProposerElection {
                                        epoch_seed,
                                        height,
                                        round,
                                        candidates,
                                    };
                                    (
                                        d.can_propose() && d.engine.is_proposer(&election),
                                        height,
                                    )
                                }
                            };

                            let already_have_proposal = proposed_at_slot == Some((next_height, round))
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

                            if matches!(proposal_mode, ProposalMode::Fresh | ProposalMode::Reproposal) {
                                let time_since_last_commit = last_commit_time
                                    .and_then(|t| t.elapsed().ok())
                                    .unwrap_or(Duration::from_secs(MIN_BLOCK_INTERVAL_SECS));

                                if time_since_last_commit < Duration::from_secs(MIN_BLOCK_INTERVAL_SECS)
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
                                        indra_crypto::sha256(&d.engine.state.tip_hash.0)
                                    );
                                    let height = d.engine.state.height + 1;
                                    let round = d.current_round();
                                    let candidates: Vec<indra_consensus::proposer::ProposerCandidate> =
                                        d.engine.state.validators.active_validators()
                                            .filter_map(|v| v.vrf_pk.map(|vrf_pk| indra_consensus::proposer::ProposerCandidate {
                                                validator_id: v.validator_id,
                                                vrf_pubkey: vrf_pk,
                                                stake: v.stake_spark,
                                            }))
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
                                    let proposal_result = if matches!(proposal_mode, ProposalMode::Reproposal) {
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
                                        d.engine.propose(&election, timestamp, d.last_qc_bytes(), polc_round)
                                    };
                                    match proposal_result {
                                        Ok(block) => {
                                            if !block.transactions.is_empty() {
                                                eprintln!(
                                                    "[mempool] including {} txs in block at height={}",
                                                    block.transactions.len(),
                                                    block.header.height,
                                                );
                                            }
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
                                    proposed_at_slot = Some((block.header.height, block.header.proposer_round));
                                    eprintln!(
                                        "[timing] t={}ms proposed block {} at height={} round={}",
                                        now_ms(),
                                        hex::encode(block.header.block_hash().0),
                                        block.header.height,
                                        block.header.proposer_round,
                                    );
                                    process_driver_actions(&driver, &gossip, &height_tx, height, actions);

                                    println!(
                                        "[consensus] ✓ proposed block {} → height={}",
                                        hex::encode(block.header.block_hash().0),
                                        driver.lock().unwrap().height()
                                    );
                                }
                            }

                            if phase_started_at.elapsed() >= PROPOSE_TIMEOUT {
                                let actions = driver.lock().unwrap().on_propose_timeout();
                                process_driver_actions(&driver, &gossip, &height_tx, height, actions);
                                phase_started_at = Instant::now();
                            }
                        }
                        RoundPhase::Prevote => {
                            if phase_started_at.elapsed() >= PREVOTE_TIMEOUT {
                                let actions = driver.lock().unwrap().on_prevote_timeout();
                                process_driver_actions(&driver, &gossip, &height_tx, height, actions);
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
                                    if d.current_round() != old_round {
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
        process_driver_actions(&driver, &gossip, &height_tx, current_height, startup_qc_request);
    }

    // ── Thread 5: RPC server ────────────────────────────────────────────────
    // Inline HTTP/JSON-RPC handler — avoids circular dependency with indra-rpc.
    // Reads chain state directly from the driver under a brief lock.
    {
        let driver_rpc = Arc::clone(&driver);
        let gossip_rpc = Arc::clone(&gossip);
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
                        let gossip_rpc = Arc::clone(&gossip_rpc);
                        std::thread::spawn(move || {
                            handle_rpc(stream, &driver_rpc, &gossip_rpc);
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

fn log_broadcast_action(gossip: &Arc<Mutex<GossipEngine>>, action: &DriverAction) {
    let peers = gossip.lock().unwrap().connection_count();
    match action {
        DriverAction::BroadcastBlock(block) => {
            eprintln!(
                "[gossip] broadcasting proposal {} to {} peers",
                hex::encode(&block.header.block_hash().0[..4]),
                peers,
            );
        }
        DriverAction::BroadcastVote(vote) => {
            eprintln!(
                "[vote] sent vote for {} to {} peers",
                hex::encode(&vote.block_hash.0[..4]),
                peers,
            );
        }
        DriverAction::BroadcastTx(tx) => {
            eprintln!(
                "[mempool] broadcasting tx {} to {} peers",
                hex::encode(&tx.tx_hash().0[..4]),
                peers,
            );
        }
        _ => {}
    }
}

fn broadcast_driver_message(gossip: &Arc<Mutex<GossipEngine>>, action: &DriverAction, msg: &Message) {
    let mut g = gossip.lock().unwrap();
    let _ = match action {
        DriverAction::BroadcastBlock(_) => g.broadcast_priority(msg),
        _ => g.broadcast(msg),
    };
}

fn process_driver_actions(
    driver: &Arc<Mutex<ConsensusDriver>>,
    gossip: &Arc<Mutex<GossipEngine>>,
    height_tx: &std::sync::mpsc::Sender<()>,
    previous_height: u64,
    actions: Vec<DriverAction>,
) {
    for action in actions {
        if let DriverAction::ActivateBufferedProposal(block) = action {
            let actions2 = driver.lock().unwrap().process(DriverEvent::InboundBlock {
                from: None,
                block,
            });
            process_driver_actions(driver, gossip, height_tx, previous_height, actions2);
            let new_height = driver.lock().unwrap().height();
            if new_height > previous_height {
                let _ = height_tx.send(());
                broadcast_status(driver, gossip);
            }
            continue;
        }

        if let DriverAction::RequestQC { height } = &action {
            let peers: Vec<SocketAddr> = gossip.lock().unwrap().connected_addrs();
            eprintln!(
                "[driver] requesting QC for height {} from {} peers",
                height,
                peers.len()
            );
            let msg = Message::RequestQC { height: *height };
            for peer in &peers {
                let _ = gossip.lock().unwrap().send_to(peer, &msg);
            }
            continue;
        }

        if let Some(out_msg) = action_to_message(&action) {
            log_broadcast_action(gossip, &action);
            broadcast_driver_message(gossip, &action, &out_msg);
        }

        if let DriverAction::RequestBlocks { from, from_height, to_height } = &action {
            eprintln!(
                "[sync] peer at height={}, local behind, requesting blocks {}..{} from {}",
                to_height,
                from_height,
                to_height,
                from
            );
            let req = Message::RequestBlocks {
                from_height: *from_height,
                to_height: *to_height,
            };
            let _ = gossip.lock().unwrap().send_to(from, &req);
        }

        if let DriverAction::RequestProposal { from, height, round, hash } = &action {
            let req = Message::RequestProposal {
                height: *height,
                round: *round,
                hash: *hash,
            };
            let _ = gossip.lock().unwrap().send_to(from, &req);
        }

        if let DriverAction::SendQCResponse { to, height, qc_bytes } = &action {
            let msg = Message::QCResponse {
                height: *height,
                qc_bytes: qc_bytes.clone(),
            };
            if let Err(e) = gossip.lock().unwrap().send_to(to, &msg) {
                eprintln!("[driver] failed to send QCResponse to {}: {}", to, e);
            }
        }
    }
}

fn announce_status_and_recovery(
    driver: &Arc<Mutex<ConsensusDriver>>,
    gossip: &Arc<Mutex<GossipEngine>>,
    height_tx: &std::sync::mpsc::Sender<()>,
    addr: SocketAddr,
) {
    let (height, tip_hash) = {
        let d = driver.lock().unwrap();
        (d.height(), d.engine.state.tip_hash)
    };
    let [status, ping] = startup_peer_messages(height, tip_hash);
    if let Ok(mut g) = gossip.lock() {
        let _ = g.send_to(&addr, &status);
        let _ = g.send_to(&addr, &ping);
    }
    broadcast_status(driver, gossip);

    let actions = driver.lock().unwrap().request_qc_if_needed();
    process_driver_actions(driver, gossip, height_tx, height, actions);
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

fn broadcast_status(driver: &Arc<Mutex<ConsensusDriver>>, gossip: &Arc<Mutex<GossipEngine>>) {
    let (height, tip_hash) = {
        let d = driver.lock().unwrap();
        (d.height(), d.engine.state.tip_hash)
    };
    let status = Message::Status { height, tip_hash };
    let _ = gossip.lock().unwrap().broadcast(&status);
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

    if let Some(local_port) = local_p2p_addr.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()) {
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
fn handle_rpc(stream: std::net::TcpStream, driver: &Arc<Mutex<indra_node::driver::ConsensusDriver>>, gossip: &Arc<Mutex<indra_network::GossipEngine>>) {
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
                let total_staked_spark = s
                    .validators
                    .total_selectable_self_stake()
                    .saturating_add(s.delegations.total_staked());
                let max_active_validators =
                    indra_core::types::primitives::max_active_validators(total_staked_spark);
                let effective_min_stake_spark =
                    s.validators.effective_min_active_stake(&s.delegations).unwrap_or(0);
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
                    mempool_size,
                    s.current_epoch(),
                    if guard.engine.block_store.is_archive() { "false" } else { "true" },
                    guard.engine.block_store.lowest_height(),
                    guard.engine.block_store.len(),
                    block_reward_spark,
                    era,
                    gossip.lock().unwrap().connection_count(),
                )
            }
            "indra_getMempoolSize" => {
                format!(r#"{{"size":{}}}"#, mempool_size)
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
                        match guard.engine.mempool.submit(tx.clone(), base_fee, height) {
                            Ok(tx_id) => {
                                let _ = gossip.lock().unwrap().broadcast(&Message::Tx(tx));
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
                // Params: ["<address_hex>"] where address = SHA-256(classical_pk)
                let address_hex = first_param.clone().unwrap_or_default();
                let mut balance: u64 = 0;
                if address_hex.len() == 64 {
                    for entry in s.utxos.all_entries() {
                        let owner_address = indra_crypto::sha256(&entry.output.owner_pubkey.classical_pk.0);
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
                } else { vec![] };
                format!(r#"{{"address":"{}","utxos":[{}]}}"#,
                    address_hex, entries.join(","))
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
                        let siblings = proof.siblings
                            .iter()
                            .map(|sibling| format!(r#""{}""#, hex::encode(sibling)))
                            .collect::<Vec<_>>()
                            .join(",");
                        let value_hash = proof.value.map(hex::encode).unwrap_or_default();
                        let state_root = indra_state::compute_state_root(s);
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
        let mode = choose_proposal_mode(
            true,
            true,
            None,
            10,
            3,
            true,
        );

        assert_eq!(mode, ProposalMode::Reproposal);
    }
}
