//! INDRA observer/full-node binary.

use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use indra_core::types::primitives::{
    OBSERVER_PING_INTERVAL_SECS, OBSERVER_PONG_TIMEOUT_SECS, OBSERVER_PORT,
};
use indra_network::{
    observer::NODE_TYPE_OBSERVER, perform_observer_handshake_initiator, read_frame_plain,
    write_frame_plain, Message,
};
use indra_node::{
    metrics::{record_block_commit, DEFAULT_OBSERVER_METRICS_ADDR},
    sync::SYNC_BATCH_SIZE,
    MetricsState, NodeConfig, NodeConfigFile, NodeEngine,
};

const DEFAULT_BOOTSTRAP: &str = "116.203.185.28:30304";

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--init") {
        run_observer_init();
        return Ok(());
    }
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return Ok(());
    }

    let config_path = get_arg(&args, "--config");
    let mut cfg_file = if let Some(ref path) = config_path {
        NodeConfigFile::load(Path::new(path)).map_err(|e| format!("ERROR: {}", e))?
    } else {
        NodeConfigFile::default()
    };
    if let Some(v) = get_arg(&args, "--data-dir") {
        cfg_file.data_dir = Some(v);
    }
    if let Some(v) = get_arg(&args, "--genesis") {
        cfg_file.genesis = Some(v);
    }
    if let Some(v) = get_arg(&args, "--observer-addr") {
        cfg_file.observer_addr = Some(v);
    }
    if let Some(v) = get_arg(&args, "--metrics-addr") {
        cfg_file.metrics_addr = Some(v);
        cfg_file.metrics_enabled = Some(true);
    }
    if let Some(v) = get_arg(&args, "--rpc-addr") {
        cfg_file.rpc_addr = Some(v);
    }
    if args.iter().any(|arg| arg == "--no-metrics") {
        cfg_file.metrics_enabled = Some(false);
    }
    if let Some(v) = get_arg(&args, "--prune-keep").and_then(|v| v.parse::<u64>().ok()) {
        cfg_file.prune_keep_blocks = Some(v);
    }
    let cli_connect_peers = repeated_arg(&args, "--connect");
    if !cli_connect_peers.is_empty() {
        cfg_file.bootstrap_peers = cli_connect_peers;
    }
    if config_path.is_some() {
        cfg_file.mode.get_or_insert_with(|| "observer".to_string());
        if let Err(errors) = cfg_file.validate() {
            let mut msg = "ERROR: observer config validation failed:".to_string();
            for err in errors {
                msg.push_str("\n  - ");
                msg.push_str(&err);
            }
            return Err(msg);
        }
    } else {
        cfg_file.mode.get_or_insert_with(|| "observer".to_string());
        cfg_file
            .data_dir
            .get_or_insert_with(|| default_data_dir().to_string_lossy().to_string());
    }

    let data_dir = cfg_file
        .data_dir
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(default_data_dir);
    let genesis_path = cfg_file.genesis.clone();
    let rpc_addr = cfg_file
        .rpc_addr
        .clone()
        .unwrap_or_else(|| "127.0.0.1:8546".to_string());
    let observer_addr = match cfg_file.observer_addr.as_deref() {
        Some("") => None,
        Some(addr) => Some(addr.to_string()),
        None => None,
    };
    let metrics_addr = if cfg_file.metrics_enabled == Some(false) {
        None
    } else {
        match cfg_file.metrics_addr.as_deref() {
            Some("") => None,
            Some(addr) => Some(addr.to_string()),
            None => Some(DEFAULT_OBSERVER_METRICS_ADDR.to_string()),
        }
    };
    let prune_keep = cfg_file
        .prune_keep_blocks
        .and_then(|v| if v == 0 { None } else { Some(v) });
    let connect_peers = if cfg_file.bootstrap_peers.is_empty() {
        vec![DEFAULT_BOOTSTRAP.to_string()]
    } else {
        cfg_file.bootstrap_peers.clone()
    };

    let mut config = NodeConfig::observer_node(
        data_dir.clone(),
        cfg_file
            .p2p_addr
            .clone()
            .unwrap_or_else(|| "0.0.0.0:0".to_string()),
    );
    config.genesis_path = genesis_path;
    config.prune_keep_blocks = prune_keep;
    config.observer_addr = observer_addr.clone();
    config.metrics_addr = metrics_addr.clone();
    config.snapshot_interval = cfg_file.snapshot_interval.unwrap_or(300);
    config.mempool_capacity = cfg_file.mempool_capacity.unwrap_or(5_000);

    let engine = NodeEngine::init(config).map_err(|e| format!("observer init failed: {e}"))?;
    let engine = Arc::new(Mutex::new(engine));
    let metrics_state = Arc::new(MetricsState::new());
    let last_block_timestamp = Arc::new(AtomicU64::new(0));
    let observer_count = Arc::new(AtomicUsize::new(0));

    indra_node::hardened_read_rpc::start_hardened_observer_rpc(
        rpc_addr.clone(),
        cfg_file.rpc_trusted_tls_proxy == Some(true),
        Arc::clone(&engine),
        Arc::clone(&metrics_state),
    );
    eprintln!("[observer] rpc listening on {}", rpc_addr);
    if let Some(addr) = observer_addr {
        start_observer_reserve(&addr, Arc::clone(&engine), Arc::clone(&observer_count));
        eprintln!("[observer] re-serving observer port on {}", addr);
    }
    if let Some(addr) = metrics_addr {
        indra_node::start_observer_metrics_server(
            addr,
            Arc::clone(&engine),
            Arc::clone(&observer_count),
            Arc::clone(&metrics_state),
            Arc::clone(&last_block_timestamp),
            data_dir.to_string_lossy().to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        );
    }

    let mut backoff = Duration::from_secs(2);
    let mut peer_index = 0usize;
    loop {
        let peer = &connect_peers[peer_index % connect_peers.len()];
        peer_index = peer_index.saturating_add(1);
        match connect_and_sync(
            peer,
            Arc::clone(&engine),
            Arc::clone(&metrics_state),
            Arc::clone(&last_block_timestamp),
        )
        .await
        {
            Ok(()) => {
                backoff = Duration::from_secs(2);
            }
            Err(e) => {
                eprintln!(
                    "[observer] validator disconnected or failed: {}; reconnecting in {}s",
                    e,
                    backoff.as_secs()
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        }
    }
}

fn start_observer_reserve(
    addr: &str,
    engine: Arc<Mutex<NodeEngine>>,
    observer_count: Arc<AtomicUsize>,
) {
    let addr = addr.to_string();
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(e) => {
                eprintln!("[observer] reserve runtime failed: {}", e);
                return;
            }
        };
        runtime.block_on(async move {
            let listener = match tokio::net::TcpListener::bind(&addr).await {
                Ok(listener) => listener,
                Err(e) => {
                    eprintln!("[observer] reserve bind failed: {}", e);
                    return;
                }
            };
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        eprintln!("[observer] reserve accept error: {}", e);
                        continue;
                    }
                };
                let engine = Arc::clone(&engine);
                let observer_count = Arc::clone(&observer_count);
                tokio::spawn(async move {
                    observer_count.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = serve_observer_peer(stream, engine).await {
                        eprintln!("[observer] reserve peer {} closed: {}", peer, e);
                    }
                    observer_count.fetch_sub(1, Ordering::Relaxed);
                });
            }
        });
    });
}

async fn serve_observer_peer(
    stream: tokio::net::TcpStream,
    engine: Arc<Mutex<NodeEngine>>,
) -> Result<(), String> {
    let result = indra_network::perform_observer_handshake_responder(
        stream,
        indra_network::observer::NODE_TYPE_FULL,
    )
    .await
    .map_err(|e| e.to_string())?;
    let mut stream = result.stream;
    write_message(&mut stream, &local_status(&engine)).await?;
    loop {
        let frame = read_frame_plain(&mut stream)
            .await
            .map_err(|e| e.to_string())?;
        let msg = Message::decode_wire(&frame).map_err(|e| e.to_string())?;
        match msg {
            Message::RequestBlocks {
                from_height,
                to_height,
            } => {
                let blocks = {
                    let mut engine = engine.lock().map_err(|_| "engine lock poisoned")?;
                    let end = to_height.min(
                        from_height
                            .saturating_add(SYNC_BATCH_SIZE)
                            .saturating_sub(1),
                    );
                    (from_height..=end)
                        .filter_map(|height| engine.block_store.get(height).ok())
                        .collect()
                };
                write_message(
                    &mut stream,
                    &Message::BlockResponse {
                        blocks,
                        lowest_available: None,
                        highest_available: None,
                    },
                )
                .await?;
            }
            Message::Status { .. } => {}
            Message::Ping(nonce) => write_message(&mut stream, &Message::Pong(nonce)).await?,
            Message::Vote(_)
            | Message::RequestProposal { .. }
            | Message::RequestQC { .. }
            | Message::QCResponse { .. } => return Ok(()),
            _ => {}
        }
    }
}

async fn connect_and_sync(
    peer: &str,
    engine: Arc<Mutex<NodeEngine>>,
    metrics_state: Arc<MetricsState>,
    last_block_timestamp: Arc<AtomicU64>,
) -> Result<(), String> {
    let stream = tokio::net::TcpStream::connect(peer)
        .await
        .map_err(|e| format!("connect {peer}: {e}"))?;
    let result = perform_observer_handshake_initiator(stream, NODE_TYPE_OBSERVER)
        .await
        .map_err(|e| format!("observer handshake {peer}: {e}"))?;
    let mut stream = result.stream;
    eprintln!("[observer] connected to {}", peer);

    let status = local_status(&engine);
    write_message(&mut stream, &status).await?;
    let mut ping_interval = tokio::time::interval(Duration::from_secs(OBSERVER_PING_INTERVAL_SECS));
    let mut last_pong = std::time::Instant::now();

    loop {
        tokio::select! {
            _ = ping_interval.tick() => {
                write_message(&mut stream, &local_status(&engine)).await?;
                write_message(&mut stream, &Message::Ping(local_height(&engine))).await?;
                if last_pong.elapsed() > Duration::from_secs(OBSERVER_PING_INTERVAL_SECS + OBSERVER_PONG_TIMEOUT_SECS) {
                    return Err("pong timeout".to_string());
                }
            }
            frame = read_frame_plain(&mut stream) => {
                let frame = frame.map_err(|e| e.to_string())?;
                let msg = Message::decode_wire(&frame).map_err(|e| e.to_string())?;
                match msg {
                    Message::Status { height, .. } => {
                        let local = local_height(&engine);
                        if height > local {
                            eprintln!("[observer] syncing: height {} -> {}", local, height);
                            request_blocks(&mut stream, local.saturating_add(1), height).await?;
                        }
                    }
                    Message::Block(block) => {
                        import_observer_block(&engine, block, &metrics_state, &last_block_timestamp)?;
                    }
                    Message::BlockResponse { blocks, .. } => {
                        for block in blocks {
                            import_observer_block(
                                &engine,
                                block,
                                &metrics_state,
                                &last_block_timestamp,
                            )?;
                        }
                        let local = local_height(&engine);
                        request_blocks(&mut stream, local.saturating_add(1), local.saturating_add(SYNC_BATCH_SIZE)).await?;
                    }
                    Message::Pong(_) => {
                        last_pong = std::time::Instant::now();
                    }
                    Message::PeerList(peers) => {
                        eprintln!("[observer] received {} peer hints", peers.len());
                    }
                    Message::Ping(nonce) => {
                        write_message(&mut stream, &Message::Pong(nonce)).await?;
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn request_blocks(
    stream: &mut tokio::net::TcpStream,
    from_height: u64,
    target_height: u64,
) -> Result<(), String> {
    if from_height > target_height {
        return Ok(());
    }
    let to_height = target_height.min(
        from_height
            .saturating_add(SYNC_BATCH_SIZE)
            .saturating_sub(1),
    );
    write_message(
        stream,
        &Message::RequestBlocks {
            from_height,
            to_height,
        },
    )
    .await
}

fn import_observer_block(
    engine: &Arc<Mutex<NodeEngine>>,
    block: indra_core::types::block::BlockV1,
    metrics_state: &MetricsState,
    last_block_timestamp: &AtomicU64,
) -> Result<(), String> {
    let mut engine = engine
        .lock()
        .map_err(|_| "engine lock poisoned".to_string())?;
    if block.header.height <= engine.height() {
        return Ok(());
    }
    if block.header.height != engine.height().saturating_add(1) {
        return Ok(());
    }
    engine
        .commit_block(&block)
        .map_err(|e| format!("import block {}: {}", block.header.height, e))?;
    record_block_commit(metrics_state, last_block_timestamp);
    eprintln!(
        "[observer] imported block {} (epoch {})",
        block.header.height,
        engine.state.current_epoch()
    );
    Ok(())
}

fn local_status(engine: &Arc<Mutex<NodeEngine>>) -> Message {
    let engine = engine.lock().unwrap();
    Message::Status {
        height: engine.height(),
        tip_hash: engine.state.tip_hash,
        round: 0,
    }
}

fn local_height(engine: &Arc<Mutex<NodeEngine>>) -> u64 {
    engine.lock().map(|engine| engine.height()).unwrap_or(0)
}

async fn write_message(stream: &mut tokio::net::TcpStream, msg: &Message) -> Result<(), String> {
    let wire = msg.encode_wire().map_err(|e| e.to_string())?;
    write_frame_plain(stream, &wire[4..])
        .await
        .map_err(|e| e.to_string())
}

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|idx| args.get(idx + 1))
        .cloned()
}

fn repeated_arg(args: &[String], flag: &str) -> Vec<String> {
    args.iter()
        .enumerate()
        .filter_map(|(idx, arg)| {
            if arg == flag {
                args.get(idx + 1).cloned()
            } else {
                None
            }
        })
        .collect()
}

fn default_data_dir() -> PathBuf {
    std::env::var("HOME")
        .map(|home| PathBuf::from(home).join(".indra/observer"))
        .unwrap_or_else(|_| PathBuf::from("./indra-observer"))
}

fn run_observer_init() {
    let data_dir = prompt_default("Data directory", "/root/.indra/observer");
    let default_genesis = Path::new(&data_dir)
        .join("genesis.toml")
        .to_string_lossy()
        .to_string();
    let genesis_file = prompt_default("Genesis file", &default_genesis);
    let connect = prompt_default(
        "Observer peers (comma-separated)",
        "116.203.185.28:30304,5.161.221.10:30304,178.104.151.220:30304,5.161.98.155:30304",
    );
    let rpc_addr = prompt_default("RPC address", "127.0.0.1:8546");
    let metrics_addr = prompt_default("Metrics address", "127.0.0.1:9616");
    let prune_keep = prompt_default("Prune keep blocks [0=archive]", "0");
    let config_path = Path::new(&data_dir).join("observer-config.toml");
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        eprintln!("ERROR: cannot create data directory {}: {}", data_dir, e);
        std::process::exit(1);
    }
    let config = format!(
        r#"# INDRA Observer Configuration
# Generated by: indra-observer --init
# Version: {}

[node]
mode     = "observer"
chain_id = "indra-testnet-1"
data_dir = "{}"
genesis  = "{}"

[network]
p2p_addr        = "0.0.0.0:0"
observer_addr   = ""
bootstrap_peers = {}
dns_seed_host   = "seeds.indraprotocol.com"
# off = ordinary DNS, warn = log DNSSEC problems but use answers, require = secure answers only.
dns_seed_validation = "warn"
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
        bootstrap_peers_toml(&connect),
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
    println!(
        "  observer-config.toml written to: {}",
        config_path.display()
    );
    println!("══════════════════════════════════════════");
    println!();
    println!("  Start observer:");
    println!(
        "  /root/.indra/bin/indra-observer --config {}",
        config_path.display()
    );
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

fn print_help() {
    println!("INDRA Observer");
    println!("  --config <path>         Load observer configuration from TOML");
    println!("  --init                  Generate observer-config.toml interactively");
    println!("  --data-dir <path>       Data directory (default: ~/.indra/observer)");
    println!("  --genesis <path>        Path to genesis.toml");
    println!("  --connect <ip:port>     Validator observer port (repeatable)");
    println!("  --rpc-addr <addr>       JSON-RPC listen address (default: 127.0.0.1:8546)");
    println!("  --observer-addr <addr>  Re-serve observer port for other observers");
    println!("  --metrics-addr <addr>   Prometheus metrics address (default: 127.0.0.1:9616)");
    println!("  --no-metrics            Disable metrics endpoint");
    println!("  --prune-keep <n>        Keep last N blocks (default: archive)");
    println!("  default observer port: {}", OBSERVER_PORT);
}
