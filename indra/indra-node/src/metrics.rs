//! Prometheus metrics endpoint for the INDRA node.
//!
//! Exposes a `/metrics` HTTP endpoint in Prometheus text exposition format.
//! No external dependencies are used for metrics formatting; the format is
//! hand-written plain text.
//!
//! prometheus.yml example for INDRA validator monitoring:
//! ```yaml
//! scrape_configs:
//!   - job_name: 'indra-validators'
//!     static_configs:
//!       - targets:
//!           - '116.203.185.28:9615'
//!           - '5.161.221.10:9615'
//!           - '178.104.151.220:9615'
//!           - '5.161.98.155:9615'
//!     scrape_interval: 15s
//!     scrape_timeout: 10s
//! ```

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::{ConsensusDriver, NodeEngine};

/// Default Prometheus metrics endpoint for validator/full nodes.
pub const DEFAULT_METRICS_ADDR: &str = "127.0.0.1:9615";

/// Default Prometheus metrics endpoint for observer nodes.
pub const DEFAULT_OBSERVER_METRICS_ADDR: &str = "127.0.0.1:9616";

/// Shared metrics state for cumulative values.
pub struct MetricsState {
    /// Total slash events detected since node start.
    pub slash_events_total: Arc<AtomicU64>,
    /// Total blocks committed since node start.
    pub blocks_committed_total: Arc<AtomicU64>,
    /// Node process start time.
    pub started_at: Instant,
}

impl MetricsState {
    /// Create a fresh metrics state for this node process.
    pub fn new() -> Self {
        Self {
            slash_events_total: Arc::new(AtomicU64::new(0)),
            blocks_committed_total: Arc::new(AtomicU64::new(0)),
            started_at: Instant::now(),
        }
    }
}

impl Default for MetricsState {
    fn default() -> Self {
        Self::new()
    }
}

/// Add a Prometheus gauge to the buffer.
pub fn gauge(buf: &mut String, name: &str, help: &str, value: impl std::fmt::Display) {
    let _ = writeln!(buf, "# HELP {} {}", name, help);
    let _ = writeln!(buf, "# TYPE {} gauge", name);
    let _ = writeln!(buf, "{} {}", name, value);
}

/// Add a Prometheus counter to the buffer.
pub fn counter(buf: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(buf, "# HELP {} {}", name, help);
    let _ = writeln!(buf, "# TYPE {} counter", name);
    let _ = writeln!(buf, "{}_total {}", name, value);
}

/// Record that one block was committed by this process.
pub fn record_block_commit(metrics_state: &MetricsState, last_block_timestamp: &AtomicU64) {
    let now = now_unix_seconds();
    last_block_timestamp.store(now, Ordering::Relaxed);
    metrics_state
        .blocks_committed_total
        .fetch_add(1, Ordering::Relaxed);
}

/// Render validator/full-node metrics from a consensus driver.
pub fn render_metrics(
    driver: &Arc<Mutex<ConsensusDriver>>,
    observer_count: &Arc<AtomicUsize>,
    connected_validator_peers: usize,
    metrics_state: &MetricsState,
    last_block_timestamp: &AtomicU64,
    data_dir: &str,
    version: &str,
) -> String {
    let snapshot = {
        let Ok(d) = driver.lock() else {
            return "# HELP indra_metrics_lock_error Metrics lock failure\n# TYPE indra_metrics_lock_error gauge\nindra_metrics_lock_error 1\n".to_string();
        };
        MetricsSnapshot::from_driver(&d, connected_validator_peers, observer_count)
    };
    render_snapshot(
        snapshot,
        metrics_state,
        last_block_timestamp,
        data_dir,
        version,
    )
}

/// Render observer-node metrics from a standalone node engine.
pub fn render_observer_metrics(
    engine: &Arc<Mutex<NodeEngine>>,
    observer_count: &Arc<AtomicUsize>,
    metrics_state: &MetricsState,
    last_block_timestamp: &AtomicU64,
    data_dir: &str,
    version: &str,
) -> String {
    let snapshot = {
        let Ok(engine) = engine.lock() else {
            return "# HELP indra_metrics_lock_error Metrics lock failure\n# TYPE indra_metrics_lock_error gauge\nindra_metrics_lock_error 1\n".to_string();
        };
        MetricsSnapshot::from_engine(&engine, 0, observer_count, 0, true, 0)
    };
    render_snapshot(
        snapshot,
        metrics_state,
        last_block_timestamp,
        data_dir,
        version,
    )
}

/// Start a Prometheus metrics server for validator/full nodes.
pub fn start_metrics_server(
    addr: String,
    driver: Arc<Mutex<ConsensusDriver>>,
    observer_count: Arc<AtomicUsize>,
    metrics_state: Arc<MetricsState>,
    last_block_timestamp: Arc<AtomicU64>,
    connected_validator_peers: Arc<AtomicUsize>,
    data_dir: String,
    version: String,
) {
    std::thread::spawn(move || {
        let listener = match TcpListener::bind(&addr) {
            Ok(listener) => listener,
            Err(e) => {
                eprintln!("[metrics] bind failed on {}: {}", addr, e);
                return;
            }
        };
        eprintln!("[metrics] listening on {}", addr);
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let driver = Arc::clone(&driver);
                    let observer_count = Arc::clone(&observer_count);
                    let metrics_state = Arc::clone(&metrics_state);
                    let last_block_timestamp = Arc::clone(&last_block_timestamp);
                    let connected_validator_peers = Arc::clone(&connected_validator_peers);
                    let data_dir = data_dir.clone();
                    let version = version.clone();
                    std::thread::spawn(move || {
                        let peer_count = connected_validator_peers.load(Ordering::Relaxed);
                        let body = render_metrics(
                            &driver,
                            &observer_count,
                            peer_count,
                            &metrics_state,
                            &last_block_timestamp,
                            &data_dir,
                            &version,
                        );
                        if let Err(e) = write_http_metrics(stream, &body) {
                            eprintln!("[metrics] connection error: {}", e);
                        }
                    });
                }
                Err(e) => eprintln!("[metrics] accept error: {}", e),
            }
        }
    });
}

/// Start a Prometheus metrics server for observer nodes.
pub fn start_observer_metrics_server(
    addr: String,
    engine: Arc<Mutex<NodeEngine>>,
    observer_count: Arc<AtomicUsize>,
    metrics_state: Arc<MetricsState>,
    last_block_timestamp: Arc<AtomicU64>,
    data_dir: String,
    version: String,
) {
    std::thread::spawn(move || {
        let listener = match TcpListener::bind(&addr) {
            Ok(listener) => listener,
            Err(e) => {
                eprintln!("[metrics] bind failed on {}: {}", addr, e);
                return;
            }
        };
        eprintln!("[metrics] listening on {}", addr);
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let engine = Arc::clone(&engine);
                    let observer_count = Arc::clone(&observer_count);
                    let metrics_state = Arc::clone(&metrics_state);
                    let last_block_timestamp = Arc::clone(&last_block_timestamp);
                    let data_dir = data_dir.clone();
                    let version = version.clone();
                    std::thread::spawn(move || {
                        let body = render_observer_metrics(
                            &engine,
                            &observer_count,
                            &metrics_state,
                            &last_block_timestamp,
                            &data_dir,
                            &version,
                        );
                        if let Err(e) = write_http_metrics(stream, &body) {
                            eprintln!("[metrics] connection error: {}", e);
                        }
                    });
                }
                Err(e) => eprintln!("[metrics] accept error: {}", e),
            }
        }
    });
}

#[derive(Debug)]
struct MetricsSnapshot {
    height: u64,
    epoch: u64,
    era: u64,
    base_fee: u64,
    total_supply: u64,
    total_staked: u64,
    treasury: u64,
    burn_buffer: u64,
    block_reward: u64,
    round: u32,
    connected_validator_peers: usize,
    observer_connections: usize,
    mempool_size: usize,
    staking_mempool_size: usize,
    pending_slashes: usize,
    sync_caught_up: bool,
    sync_target: u64,
    active_validators: usize,
    blocks_retained: usize,
    lowest_block: u64,
    chain_id: String,
    validator_id_hex: String,
    is_validator: bool,
}

impl MetricsSnapshot {
    fn from_driver(
        driver: &ConsensusDriver,
        connected_validator_peers: usize,
        observer_count: &AtomicUsize,
    ) -> Self {
        Self::from_engine(
            &driver.engine,
            connected_validator_peers,
            observer_count,
            driver.current_round(),
            driver.sync().is_caught_up(),
            driver.sync().target_height().unwrap_or(0),
        )
    }

    fn from_engine(
        engine: &NodeEngine,
        connected_validator_peers: usize,
        observer_count: &AtomicUsize,
        round: u32,
        sync_caught_up: bool,
        sync_target: u64,
    ) -> Self {
        let s = &engine.state;
        let total_staked = s.validators.total_selectable_self_stake().saturating_add(
            if indra_core::types::primitives::delegator_bond_accounting_active(s.height) {
                s.total_active_delegated_bond_stake()
            } else {
                s.delegations.total_staked()
            },
        );
        let validator_id_hex = engine
            .validator_id()
            .map(|id| hex::encode(&id.0[..4]))
            .unwrap_or_else(|| "none".to_string());
        Self {
            height: s.height,
            epoch: s.current_epoch(),
            era: era_for_height(s.height),
            base_fee: s.base_fee,
            total_supply: s.total_supply,
            total_staked,
            treasury: s.treasury_balance,
            burn_buffer: s.burn_buffer,
            block_reward: indra_state::epoch::block_reward_at_height(s.height),
            round,
            connected_validator_peers,
            observer_connections: observer_count.load(Ordering::Relaxed),
            mempool_size: engine.mempool.len(),
            staking_mempool_size: engine.staking_mempool.len(),
            pending_slashes: engine.pending_slashes.len(),
            sync_caught_up,
            sync_target,
            active_validators: s.validators.active_count(),
            blocks_retained: engine.block_store.len(),
            lowest_block: engine.block_store.lowest_height(),
            chain_id: s.chain_id.clone(),
            validator_id_hex,
            is_validator: engine.config.is_validator(),
        }
    }
}

fn render_snapshot(
    snapshot: MetricsSnapshot,
    metrics_state: &MetricsState,
    last_block_timestamp: &AtomicU64,
    data_dir: &str,
    version: &str,
) -> String {
    let mut buf = String::new();
    gauge(
        &mut buf,
        "indra_block_height",
        "Current committed chain height",
        snapshot.height,
    );
    gauge(
        &mut buf,
        "indra_epoch",
        "Current epoch number",
        snapshot.epoch,
    );
    gauge(
        &mut buf,
        "indra_era",
        "Current era (1, 2, 3+)",
        snapshot.era,
    );
    gauge(
        &mut buf,
        "indra_base_fee_spark",
        "Current base fee in Spark per KB",
        snapshot.base_fee,
    );
    gauge(
        &mut buf,
        "indra_total_supply_spark",
        "Total supply in Spark",
        snapshot.total_supply,
    );
    gauge(
        &mut buf,
        "indra_total_staked_spark",
        "Total staked Spark (self-stake + delegated)",
        snapshot.total_staked,
    );
    gauge(
        &mut buf,
        "indra_treasury_balance_spark",
        "Treasury balance in Spark",
        snapshot.treasury,
    );
    gauge(
        &mut buf,
        "indra_burn_buffer_spark",
        "Accumulated burn buffer in Spark",
        snapshot.burn_buffer,
    );
    gauge(
        &mut buf,
        "indra_block_reward_spark",
        "Current era block reward in Spark",
        snapshot.block_reward,
    );
    gauge(
        &mut buf,
        "indra_consensus_round",
        "Current consensus round at current height",
        snapshot.round,
    );
    gauge(
        &mut buf,
        "indra_connected_validator_peers",
        "Number of authenticated validator peers",
        snapshot.connected_validator_peers,
    );
    gauge(
        &mut buf,
        "indra_observer_connections",
        "Number of connected observer peers",
        snapshot.observer_connections,
    );
    gauge(
        &mut buf,
        "indra_mempool_size",
        "Number of transactions in mempool",
        snapshot.mempool_size,
    );
    gauge(
        &mut buf,
        "indra_staking_mempool_size",
        "Number of pending staking ops",
        snapshot.staking_mempool_size,
    );
    gauge(
        &mut buf,
        "indra_pending_slash_evidence",
        "Number of queued slash evidence items",
        snapshot.pending_slashes,
    );
    gauge(
        &mut buf,
        "indra_sync_caught_up",
        "1 if caught up, 0 if syncing",
        if snapshot.sync_caught_up { 1 } else { 0 },
    );
    gauge(
        &mut buf,
        "indra_sync_target_height",
        "Sync target height (0 if not syncing)",
        snapshot.sync_target,
    );
    gauge(
        &mut buf,
        "indra_seconds_since_last_block",
        "Seconds elapsed since last committed block",
        seconds_since_last_block(last_block_timestamp),
    );
    gauge(
        &mut buf,
        "indra_node_uptime_seconds",
        "Seconds since node process started",
        metrics_state.started_at.elapsed().as_secs(),
    );
    counter(
        &mut buf,
        "indra_blocks_committed",
        "Total blocks committed since node start",
        metrics_state.blocks_committed_total.load(Ordering::Relaxed),
    );
    counter(
        &mut buf,
        "indra_slash_events",
        "Total slash events detected since node start",
        metrics_state.slash_events_total.load(Ordering::Relaxed),
    );
    gauge(
        &mut buf,
        "indra_validator_count",
        "Number of active validators in current set",
        snapshot.active_validators,
    );
    gauge(
        &mut buf,
        "indra_disk_available_bytes",
        "Available disk space in data directory",
        fs2::available_space(Path::new(data_dir)).unwrap_or(0),
    );
    gauge(
        &mut buf,
        "indra_blocks_retained",
        "Number of blocks currently retained",
        snapshot.blocks_retained,
    );
    gauge(
        &mut buf,
        "indra_lowest_block",
        "Lowest block height available (pruned mode)",
        snapshot.lowest_block,
    );
    let _ = writeln!(
        buf,
        "# HELP indra_node_info Node identity and version information"
    );
    let _ = writeln!(buf, "# TYPE indra_node_info gauge");
    let _ = writeln!(
        buf,
        "indra_node_info{{version=\"{}\",chain_id=\"{}\",validator_id=\"{}\",is_validator=\"{}\"}} 1",
        escape_label_value(version),
        escape_label_value(&snapshot.chain_id),
        escape_label_value(&snapshot.validator_id_hex),
        snapshot.is_validator
    );
    buf
}

fn write_http_metrics(mut stream: TcpStream, body: &str) -> std::io::Result<()> {
    drain_http_request(&mut stream)?;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())
}

fn drain_http_request(stream: &mut TcpStream) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let mut buf = [0u8; 512];
    let mut seen = Vec::new();
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        seen.extend_from_slice(&buf[..n]);
        if seen.windows(4).any(|window| window == b"\r\n\r\n") || seen.len() > 8192 {
            return Ok(());
        }
    }
}

fn seconds_since_last_block(last_block_timestamp: &AtomicU64) -> u64 {
    let ts = last_block_timestamp.load(Ordering::Relaxed);
    if ts == 0 {
        0
    } else {
        now_unix_seconds().saturating_sub(ts)
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn era_for_height(height: u64) -> u64 {
    use indra_core::types::primitives::{ERA_1_2_DURATION_BLOCKS, ERA_3_PLUS_DURATION_BLOCKS};
    if height < ERA_1_2_DURATION_BLOCKS {
        1
    } else if height < ERA_1_2_DURATION_BLOCKS.saturating_mul(2) {
        2
    } else {
        let era_3_start = ERA_1_2_DURATION_BLOCKS.saturating_mul(2);
        3 + height.saturating_sub(era_3_start) / ERA_3_PLUS_DURATION_BLOCKS
    }
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use std::sync::atomic::AtomicUsize;

    fn test_driver() -> (Arc<Mutex<ConsensusDriver>>, String) {
        let dir = std::env::temp_dir().join(format!(
            "indra-metrics-test-{}",
            now_unix_seconds().saturating_mul(1_000_000) + u64::from(std::process::id())
        ));
        let config = crate::NodeConfig::local_test(dir.clone());
        let engine = crate::NodeEngine::init(config).expect("engine init");
        let vote_safety = indra_storage::VoteSafetyStore::open(engine.config.vote_safety_path());
        (
            Arc::new(Mutex::new(crate::ConsensusDriver::new(engine, vote_safety))),
            dir.to_string_lossy().to_string(),
        )
    }

    #[test]
    fn test_gauge_helper_format() {
        let mut buf = String::new();
        gauge(&mut buf, "indra_example", "Example gauge", 7);
        assert_eq!(
            buf,
            "# HELP indra_example Example gauge\n# TYPE indra_example gauge\nindra_example 7\n"
        );
    }

    #[test]
    fn test_counter_helper_format() {
        let mut buf = String::new();
        counter(&mut buf, "indra_events", "Example counter", 9);
        assert_eq!(
            buf,
            "# HELP indra_events Example counter\n# TYPE indra_events counter\nindra_events_total 9\n"
        );
    }

    #[test]
    fn test_render_metrics_has_all_fields() {
        let (driver, data_dir) = test_driver();
        let observer_count = Arc::new(AtomicUsize::new(0));
        let metrics_state = MetricsState::new();
        let last_block_timestamp = AtomicU64::new(0);
        let output = render_metrics(
            &driver,
            &observer_count,
            0,
            &metrics_state,
            &last_block_timestamp,
            &data_dir,
            "0.1.0",
        );
        for name in [
            "indra_block_height",
            "indra_epoch",
            "indra_era",
            "indra_base_fee_spark",
            "indra_total_supply_spark",
            "indra_total_staked_spark",
            "indra_treasury_balance_spark",
            "indra_burn_buffer_spark",
            "indra_block_reward_spark",
            "indra_consensus_round",
            "indra_connected_validator_peers",
            "indra_observer_connections",
            "indra_mempool_size",
            "indra_staking_mempool_size",
            "indra_pending_slash_evidence",
            "indra_sync_caught_up",
            "indra_sync_target_height",
            "indra_seconds_since_last_block",
            "indra_node_uptime_seconds",
            "indra_blocks_committed_total",
            "indra_slash_events_total",
            "indra_validator_count",
            "indra_disk_available_bytes",
            "indra_blocks_retained",
            "indra_lowest_block",
            "indra_node_info",
        ] {
            assert!(output.contains(name), "missing metric {name}");
        }
    }

    #[test]
    fn test_render_metrics_prometheus_format() {
        let (driver, data_dir) = test_driver();
        let observer_count = Arc::new(AtomicUsize::new(0));
        let metrics_state = MetricsState::new();
        let last_block_timestamp = AtomicU64::new(0);
        let output = render_metrics(
            &driver,
            &observer_count,
            0,
            &metrics_state,
            &last_block_timestamp,
            &data_dir,
            "0.1.0",
        );
        let mut last_help = "";
        let mut last_type = "";
        for line in output.lines() {
            if line.starts_with("# HELP ") {
                last_help = line
                    .trim_start_matches("# HELP ")
                    .split(' ')
                    .next()
                    .unwrap_or("");
            } else if line.starts_with("# TYPE ") {
                last_type = line
                    .trim_start_matches("# TYPE ")
                    .split(' ')
                    .next()
                    .unwrap_or("");
            } else if !line.trim().is_empty() {
                let sample_name = line
                    .split(['{', ' '])
                    .next()
                    .unwrap_or("")
                    .trim_end_matches("_total");
                assert_eq!(last_help, sample_name, "missing HELP for {sample_name}");
                assert_eq!(last_type, sample_name, "missing TYPE for {sample_name}");
            }
        }
    }

    #[test]
    fn test_node_info_has_labels() {
        let (driver, data_dir) = test_driver();
        let observer_count = Arc::new(AtomicUsize::new(0));
        let metrics_state = MetricsState::new();
        let last_block_timestamp = AtomicU64::new(0);
        let output = render_metrics(
            &driver,
            &observer_count,
            0,
            &metrics_state,
            &last_block_timestamp,
            &data_dir,
            "0.1.0",
        );
        let node_info = output
            .lines()
            .find(|line| line.starts_with("indra_node_info{"))
            .unwrap_or("");
        assert!(node_info.contains("version=\""));
        assert!(node_info.contains("chain_id=\""));
        assert!(node_info.contains("validator_id=\""));
        assert!(node_info.contains("is_validator=\""));
    }

    #[test]
    fn test_metrics_server_starts_and_responds() {
        let (driver, data_dir) = test_driver();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind random port");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);

        start_metrics_server(
            addr.to_string(),
            driver,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(MetricsState::new()),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicUsize::new(0)),
            data_dir,
            "0.1.0".to_string(),
        );

        let deadline = Instant::now() + std::time::Duration::from_secs(3);
        let mut response = String::new();
        loop {
            match TcpStream::connect(addr) {
                Ok(mut stream) => {
                    let _ = stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n");
                    let _ = stream.read_to_string(&mut response);
                    break;
                }
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => panic!("metrics server did not start: {e}"),
            }
        }
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("indra_block_height"));
    }
}
