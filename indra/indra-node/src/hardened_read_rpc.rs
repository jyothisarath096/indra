//! Hardened published-snapshot RPC listener shared by standalone observers.

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use indra_core::{types::block::BlockVNext, Bytes32, EpochRecord};
use indra_rpc::{
    handlers::{dispatch_with_mode, DispatchResult, NodeState, RpcEngineView, RpcMode},
    server::{
        parse_http_json_rpc_body, rpc_method_cost, rpc_rate_limited_response, RpcGlobalRateLimiter,
        RpcGlobalWindowRateLimiter, RpcMethodCost, RpcRateLimiter, RpcWindowRateLimiter,
        RPC_PUBLIC_EXPENSIVE_GLOBAL_RATE_PER_MIN, RPC_PUBLIC_EXPENSIVE_RATE_PER_MIN,
        RPC_PUBLIC_GLOBAL_RATE_BURST, RPC_PUBLIC_GLOBAL_RATE_LIMIT_PER_SEC,
        RPC_PUBLIC_MAX_BODY_BYTES, RPC_PUBLIC_RATE_BURST, RPC_PUBLIC_RATE_LIMIT_PER_SEC,
    },
    types::RpcResponse,
};

use crate::{rpc_snapshot::RpcReadSnapshot, MetricsState, NodeEngine, RpcLimiterTelemetry};

const CONNECTION_CAP: u64 = 64;
const PER_IP_CONNECTION_CAP: u64 = 4;
const EXPENSIVE_CONCURRENCY: usize = 4;
const RESPONSE_CAP: usize = 32 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const PROGRESS_GRACE: Duration = Duration::from_secs(2);
const MIN_PROGRESS_PER_SEC: usize = 1024;

struct PublishedView {
    read: Arc<RpcReadSnapshot>,
    blocks: HashMap<u64, BlockVNext>,
    epochs: HashMap<u64, EpochRecord>,
    latest_epoch: Option<u64>,
}

impl RpcEngineView for PublishedView {
    fn chain_state(&self) -> &indra_state::ChainState {
        self.read.chain_state()
    }
    fn mempool_size(&self) -> usize {
        self.read.mempool_size()
    }
    fn pruned_mode(&self) -> bool {
        self.read.pruned_mode()
    }
    fn lowest_block(&self) -> u64 {
        self.read.lowest_block()
    }
    fn blocks_retained(&self) -> usize {
        self.read.blocks_retained()
    }
    fn state_root(&self) -> Result<Bytes32, String> {
        self.read.state_root()
    }
    fn get_block_by_height(&self, height: u64) -> Result<Option<BlockVNext>, String> {
        Ok(self.blocks.get(&height).cloned())
    }
    fn get_epoch_record(&self, epoch: u64) -> Result<Option<EpochRecord>, String> {
        Ok(self.epochs.get(&epoch).cloned())
    }
    fn latest_epoch(&self) -> Result<Option<u64>, String> {
        Ok(self.latest_epoch)
    }
    fn get_epoch_range(&self, to: u64, limit: usize) -> Result<Vec<EpochRecord>, String> {
        let mut records: Vec<_> = self
            .epochs
            .values()
            .filter(|record| record.epoch <= to)
            .cloned()
            .collect();
        records.sort_by_key(|record| std::cmp::Reverse(record.epoch));
        records.truncate(limit);
        Ok(records)
    }
    fn position_ids_by_owner(&self, id: &Bytes32) -> Option<&[Bytes32]> {
        self.read.position_ids_by_owner(id)
    }
    fn position_ids_by_validator(&self, id: &Bytes32) -> Option<&[Bytes32]> {
        self.read.position_ids_by_validator(id)
    }
    fn tranche_ids_by_position(&self, id: &Bytes32) -> Option<&[Bytes32]> {
        self.read.tranche_ids_by_position(id)
    }
    fn tranche_ids_by_owner(&self, id: &Bytes32) -> Option<&[Bytes32]> {
        self.read.tranche_ids_by_owner(id)
    }
    fn tranche_ids_by_validator(&self, id: &Bytes32) -> Option<&[Bytes32]> {
        self.read.tranche_ids_by_validator(id)
    }
    fn reward_ids_by_delegator(&self, id: &Bytes32) -> Option<&[Bytes32]> {
        self.read.reward_ids_by_delegator(id)
    }
    fn reward_ids_by_validator(&self, id: &Bytes32) -> Option<&[Bytes32]> {
        self.read.reward_ids_by_validator(id)
    }
}

struct Semaphore {
    available: Mutex<usize>,
    changed: Condvar,
}

impl Semaphore {
    fn acquire(&self, deadline: Instant) -> Option<Permit<'_>> {
        let mut available = self.available.lock().ok()?;
        while *available == 0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (next, timed) = self.changed.wait_timeout(available, remaining).ok()?;
            available = next;
            if timed.timed_out() {
                return None;
            }
        }
        *available -= 1;
        Some(Permit { semaphore: self })
    }
}

struct Permit<'a> {
    semaphore: &'a Semaphore,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if let Ok(mut available) = self.semaphore.available.lock() {
            *available = available.saturating_add(1);
            self.semaphore.changed.notify_one();
        }
    }
}

/// Start the standalone observer's hardened, unauthenticated read-only RPC.
///
/// Write/admin methods are rejected by the shared RPC allowlist before any
/// published snapshot or storage access occurs.
pub fn start_hardened_observer_rpc(
    addr: String,
    trusted_tls_proxy: bool,
    engine: Arc<Mutex<NodeEngine>>,
    metrics: Arc<MetricsState>,
) -> Option<JoinHandle<()>> {
    if !observer_bind_allowed(&addr, trusted_tls_proxy) {
        eprintln!(
            "[observer-rpc] refusing non-loopback bind without trusted TLS proxy acknowledgement"
        );
        return None;
    }
    let (publisher, storage) = match engine.lock() {
        Ok(engine) => (
            engine.rpc_snapshot.clone(),
            crate::rpc_snapshot::RpcStorageReadHandles {
                blocks: engine.block_store.read_handle(),
                epochs: engine.epoch_store.read_handle(),
            },
        ),
        Err(_) => {
            eprintln!("[observer-rpc] engine lock poisoned before startup");
            return None;
        }
    };
    let limiter_telemetry = Arc::new(RpcLimiterTelemetry::default());
    metrics.register_rpc_limiter_telemetry(Arc::clone(&limiter_telemetry));
    Some(std::thread::spawn(move || {
        let listener = match TcpListener::bind(&addr) {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("[observer-rpc] bind failed on {addr}: {error}");
                return;
            }
        };
        let total = Arc::new(AtomicU64::new(0));
        let per_ip_connections = Arc::new(Mutex::new(HashMap::<IpAddr, u64>::new()));
        let per_ip_rate = Arc::new(RpcRateLimiter::new());
        let global_rate = Arc::new(RpcGlobalRateLimiter::new(
            RPC_PUBLIC_GLOBAL_RATE_LIMIT_PER_SEC,
            RPC_PUBLIC_GLOBAL_RATE_BURST,
        ));
        let expensive_per_ip = Arc::new(RpcWindowRateLimiter::new());
        let expensive_global = Arc::new(RpcGlobalWindowRateLimiter::new());
        let expensive = Arc::new(Semaphore {
            available: Mutex::new(EXPENSIVE_CONCURRENCY),
            changed: Condvar::new(),
        });
        eprintln!("[observer-rpc] listening on {addr} (hardened read-only)");
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let Some(ip) = stream.peer_addr().ok().map(|peer| peer.ip()) else {
                continue;
            };
            if total.fetch_add(1, Ordering::AcqRel) >= CONNECTION_CAP {
                total.fetch_sub(1, Ordering::AcqRel);
                continue;
            }
            if !try_reserve_ip_connection(
                &per_ip_connections,
                &total,
                ip,
                PER_IP_CONNECTION_CAP,
            ) {
                continue;
            }
            metrics
                .rpc_active_connections
                .fetch_add(1, Ordering::Relaxed);
            let publisher = publisher.clone();
            let storage = storage.clone();
            let total = Arc::clone(&total);
            let per_ip_connections = Arc::clone(&per_ip_connections);
            let per_ip_rate = Arc::clone(&per_ip_rate);
            let global_rate = Arc::clone(&global_rate);
            let expensive_per_ip = Arc::clone(&expensive_per_ip);
            let expensive_global = Arc::clone(&expensive_global);
            let expensive = Arc::clone(&expensive);
            let metrics = Arc::clone(&metrics);
            let limiter_telemetry = Arc::clone(&limiter_telemetry);
            std::thread::spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    handle(
                        stream,
                        ip,
                        &publisher,
                        &storage,
                        &per_ip_rate,
                        &global_rate,
                        &expensive_per_ip,
                        &expensive_global,
                        &expensive,
                        &metrics,
                        &limiter_telemetry,
                    );
                }));
                if result.is_err() {
                    eprintln!("[observer-rpc] handler panicked for {ip}");
                    metrics.record_handler_panic("observer-rpc");
                }
                total.fetch_sub(1, Ordering::AcqRel);
                if let Ok(mut counts) = per_ip_connections.lock() {
                    if let Some(count) = counts.get_mut(&ip) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            counts.remove(&ip);
                        }
                    }
                }
                metrics
                    .rpc_active_connections
                    .fetch_sub(1, Ordering::Relaxed);
            });
        }
    }))
}

fn observer_bind_allowed(addr: &str, trusted_tls_proxy: bool) -> bool {
    addr.parse::<std::net::SocketAddr>()
        .is_ok_and(|socket| socket.ip().is_loopback())
        || trusted_tls_proxy
}

fn reserve_ip_connection(counts: &mut HashMap<IpAddr, u64>, ip: IpAddr, cap: u64) -> bool {
    let count = counts.entry(ip).or_default();
    if *count >= cap {
        return false;
    }
    *count += 1;
    true
}

fn try_reserve_ip_connection(
    counts: &Mutex<HashMap<IpAddr, u64>>,
    total: &AtomicU64,
    ip: IpAddr,
    cap: u64,
) -> bool {
    let mut counts = match counts.lock() {
        Ok(counts) => counts,
        Err(_) => {
            eprintln!("[observer-rpc] CRITICAL: per-IP connection mutex poisoned for {ip}; rejecting connection");
            total.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
    };
    let accepted = reserve_ip_connection(&mut counts, ip, cap);
    if !accepted {
        total.fetch_sub(1, Ordering::AcqRel);
    }
    accepted
}

#[allow(clippy::too_many_arguments)]
fn handle(
    stream: TcpStream,
    ip: IpAddr,
    publisher: &crate::rpc_snapshot::RpcSnapshotPublisher,
    storage: &crate::rpc_snapshot::RpcStorageReadHandles,
    per_ip_rate: &RpcRateLimiter,
    global_rate: &RpcGlobalRateLimiter,
    expensive_per_ip: &RpcWindowRateLimiter,
    expensive_global: &RpcGlobalWindowRateLimiter,
    expensive: &Semaphore,
    metrics: &MetricsState,
    limiter_telemetry: &RpcLimiterTelemetry,
) {
    let started = Instant::now();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
    struct LatencyGuard<'a> {
        started: Instant,
        metrics: &'a MetricsState,
    }
    impl Drop for LatencyGuard<'_> {
        fn drop(&mut self) {
            self.metrics.rpc_latency_micros_total.fetch_add(
                self.started.elapsed().as_micros().min(u64::MAX as u128) as u64,
                Ordering::Relaxed,
            );
        }
    }
    let _latency = LatencyGuard { started, metrics };
    metrics.rpc_requests_total.fetch_add(1, Ordering::Relaxed);
    if !per_ip_rate.allow_with_limits(ip, RPC_PUBLIC_RATE_LIMIT_PER_SEC, RPC_PUBLIC_RATE_BURST)
        || !global_rate.allow()
    {
        write_raw(&stream, &rpc_rate_limited_response(), metrics);
        return;
    }
    let (rate_entries, rate_evictions) = per_ip_rate.map_stats();
    let (expensive_entries, expensive_evictions) = expensive_per_ip.map_stats();
    limiter_telemetry.update(
        rate_entries.saturating_add(expensive_entries) as u64,
        rate_evictions.saturating_add(expensive_evictions),
    );
    let deadline = started + REQUEST_TIMEOUT;
    let request = match read_request(&stream, started, deadline) {
        Ok(request) => request,
        Err(error) => {
            write_json_error(&stream, -32600, &error, metrics);
            return;
        }
    };
    let req = match parse_http_json_rpc_body(&request) {
        Ok(req) => req,
        Err(response) => {
            write_json(&stream, &response.to_json(), metrics);
            return;
        }
    };
    if let Err(error) =
        indra_rpc::handlers::check_rpc_method_allowed(&req.method, RpcMode::ReadOnly)
    {
        write_json(
            &stream,
            &RpcResponse::err(req.id, error.code(), error.message().to_string()).to_json(),
            metrics,
        );
        return;
    }
    let _permit = if rpc_method_cost(&req.method) == RpcMethodCost::Expensive {
        if !expensive_per_ip.allow(ip, RPC_PUBLIC_EXPENSIVE_RATE_PER_MIN)
            || !expensive_global.allow(RPC_PUBLIC_EXPENSIVE_GLOBAL_RATE_PER_MIN)
        {
            write_raw(&stream, &rpc_rate_limited_response(), metrics);
            return;
        }
        let Some(permit) = expensive.acquire(deadline) else {
            write_json_error(
                &stream,
                -32029,
                "expensive RPC concurrency limit exceeded",
                metrics,
            );
            return;
        };
        Some(permit)
    } else {
        None
    };
    let view = match build_view(storage, publisher.load(), &req) {
        Ok(view) => view,
        Err(error) => {
            write_json_error(&stream, -32000, &error, metrics);
            return;
        }
    };
    let state = NodeState::read_only(&view).with_execution_deadline(deadline);
    let response = match dispatch_with_mode(&req.method, &req.params, &state, RpcMode::ReadOnly) {
        DispatchResult::Ready(Ok(result)) => RpcResponse::ok(req.id, result),
        DispatchResult::Ready(Err(error)) => {
            RpcResponse::err(req.id, error.code(), error.message().to_string())
        }
        DispatchResult::SubmitStakingOp(_)
        | DispatchResult::SubmitGovernanceOp(_)
        | DispatchResult::SubmitTransaction(_) => RpcResponse::err(
            req.id,
            -32003,
            "write method is unavailable on observer RPC".to_string(),
        ),
    };
    write_json(&stream, &response.to_json(), metrics);
}

fn build_view(
    storage: &crate::rpc_snapshot::RpcStorageReadHandles,
    read: Arc<RpcReadSnapshot>,
    req: &indra_rpc::types::RpcRequest,
) -> Result<PublishedView, String> {
    let mut heights = Vec::new();
    match req.method.as_str() {
        "indra_getBlock" | "indra_getTransaction" => {
            heights.extend(
                req.params
                    .first()
                    .and_then(|value| indra_rpc::types::unquote(value).parse::<u64>().ok()),
            );
        }
        "indra_getCanonicalBlocks" => {
            if let (Some(from), Some(limit)) = (
                req.params
                    .first()
                    .and_then(|value| indra_rpc::types::unquote(value).parse::<u64>().ok()),
                req.params
                    .get(1)
                    .and_then(|value| indra_rpc::types::unquote(value).parse::<u64>().ok()),
            ) {
                heights.extend(
                    from..=read
                        .height()
                        .min(from.saturating_add(limit.min(100)).saturating_sub(1)),
                );
            }
        }
        _ => {}
    }
    let needs_epochs = matches!(
        req.method.as_str(),
        "indra_getEpochRecord" | "indra_getEpochHistory" | "indra_getLatestEpoch"
    );
    let mut blocks = HashMap::new();
    let mut epochs = HashMap::new();
    let mut latest_epoch = None;
    if !heights.is_empty() || needs_epochs {
        for height in heights {
            if let Ok(proposal) = storage.blocks.get(height) {
                blocks.insert(height, proposal.block);
            }
        }
        latest_epoch = storage.epochs.latest_epoch();
        let to = req
            .params
            .first()
            .and_then(|value| indra_rpc::types::unquote(value).parse::<u64>().ok())
            .or(latest_epoch);
        let limit = req
            .params
            .get(1)
            .and_then(|value| indra_rpc::types::unquote(value).parse::<usize>().ok())
            .unwrap_or(100)
            .min(100);
        if let Some(to) = to {
            if req.method == "indra_getEpochRecord" {
                if let Ok(record) = storage.epochs.get(to) {
                    epochs.insert(record.epoch, record);
                }
            } else if req.method == "indra_getEpochHistory" {
                for record in storage
                    .epochs
                    .get_range(to, limit)
                    .map_err(|e| e.to_string())?
                {
                    epochs.insert(record.epoch, record);
                }
            }
        }
    }
    Ok(PublishedView {
        read,
        blocks,
        epochs,
        latest_epoch,
    })
}

fn read_request(stream: &TcpStream, started: Instant, deadline: Instant) -> Result<String, String> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut content_length = 0usize;
    let mut bytes = 0usize;
    let mut line = String::new();
    let mut first_line = true;
    loop {
        line.clear();
        timed_line(&mut reader, &mut line, started, deadline, &mut bytes)?;
        let trimmed = line.trim();
        if first_line {
            first_line = false;
            if !trimmed.starts_with("POST ") {
                return Err("only HTTP POST is supported".to_string());
            }
        }
        if trimmed.is_empty() {
            break;
        }
        if bytes > 16 * 1024 {
            return Err("request headers exceed 16 KiB".to_string());
        }
        if let Some(value) = trimmed.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = value.trim().parse().map_err(|_| "invalid content-length")?;
        }
    }
    if content_length == 0 || content_length > RPC_PUBLIC_MAX_BODY_BYTES {
        return Err("invalid or oversized request body".to_string());
    }
    let mut body = vec![0u8; content_length];
    let mut offset = 0usize;
    while offset < body.len() {
        ensure_progress(started, deadline, bytes)?;
        reader
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(|e| e.to_string())?;
        match reader.read(&mut body[offset..]) {
            Ok(0) => return Err("incomplete request body".to_string()),
            Ok(count) => {
                offset += count;
                bytes += count;
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    String::from_utf8(body).map_err(|_| "request body is not UTF-8".to_string())
}

fn timed_line(
    reader: &mut BufReader<TcpStream>,
    line: &mut String,
    started: Instant,
    deadline: Instant,
    bytes: &mut usize,
) -> Result<(), String> {
    loop {
        ensure_progress(started, deadline, *bytes)?;
        reader
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(|e| e.to_string())?;
        match reader.read_line(line) {
            Ok(0) => return Err("incomplete request headers".to_string()),
            Ok(count) => {
                *bytes += count;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn ensure_progress(started: Instant, deadline: Instant, bytes: usize) -> Result<(), String> {
    if Instant::now() >= deadline {
        return Err("absolute request deadline exceeded".to_string());
    }
    let elapsed = started.elapsed();
    if elapsed > PROGRESS_GRACE
        && bytes < MIN_PROGRESS_PER_SEC.saturating_mul(elapsed.as_secs() as usize)
    {
        return Err("minimum request read progress not met".to_string());
    }
    Ok(())
}

fn write_json(stream: &TcpStream, body: &str, metrics: &MetricsState) {
    let body = if body.len() <= RESPONSE_CAP {
        body.to_string()
    } else {
        RpcResponse::err(
            indra_rpc::types::JsonId::Null,
            -32030,
            "encoded RPC response exceeds 32 MiB limit".to_string(),
        )
        .to_json()
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    );
    write_raw(stream, &response, metrics);
}

fn write_json_error(stream: &TcpStream, code: i32, message: &str, metrics: &MetricsState) {
    write_json(
        stream,
        &RpcResponse::err(indra_rpc::types::JsonId::Null, code, message.to_string()).to_json(),
        metrics,
    );
}

fn write_raw(stream: &TcpStream, response: &str, metrics: &MetricsState) {
    metrics
        .rpc_response_bytes_total
        .fetch_add(response.len() as u64, Ordering::Relaxed);
    if let Err(error) = stream
        .try_clone()
        .and_then(|mut writer| writer.write_all(response.as_bytes()))
    {
        metrics
            .rpc_write_failures_total
            .fetch_add(1, Ordering::Relaxed);
        eprintln!("[observer-rpc] response write failed: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observer_rejects_fifth_connection_from_one_ip() {
        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        let mut counts = HashMap::new();
        for _ in 0..4 {
            assert!(reserve_ip_connection(&mut counts, ip, 4));
        }
        assert!(!reserve_ip_connection(&mut counts, ip, 4));
    }

    #[test]
    fn observer_rejects_poisoned_per_ip_mutex_and_restores_total() {
        let counts = Mutex::new(HashMap::new());
        let poison = std::sync::Arc::new(counts);
        let poisoned = std::sync::Arc::clone(&poison);
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.lock().unwrap();
            panic!("poison test");
        })
        .join();
        let total = AtomicU64::new(1);
        assert!(!try_reserve_ip_connection(
            &poison,
            &total,
            "192.0.2.10".parse().unwrap(),
            4
        ));
        assert_eq!(total.load(Ordering::Acquire), 0);
    }

    #[test]
    fn observer_policy_is_read_only_and_has_no_wildcard_cors() {
        assert!(indra_rpc::handlers::check_rpc_method_allowed(
            "indra_getHeight",
            RpcMode::ReadOnly
        )
        .is_ok());
        assert!(indra_rpc::handlers::check_rpc_method_allowed(
            "indra_sendTransaction",
            RpcMode::ReadOnly
        )
        .is_err());
        let source = include_str!("hardened_read_rpc.rs");
        let wildcard_header = ["Access-Control-Allow", "-Origin: *"].concat();
        assert!(!source.contains(&wildcard_header));
    }

    #[test]
    fn observer_response_ceiling_is_32_mib() {
        assert_eq!(RESPONSE_CAP, 32 * 1024 * 1024);
    }

    #[test]
    fn observer_non_loopback_requires_explicit_proxy_acknowledgement() {
        assert!(!observer_bind_allowed("0.0.0.0:8546", false));
        assert!(observer_bind_allowed("0.0.0.0:8546", true));
        assert!(observer_bind_allowed("127.0.0.1:8546", false));
        assert!(!observer_bind_allowed("invalid", false));
    }

    #[test]
    fn observer_progress_policy_rejects_slow_drip_after_grace() {
        let started = Instant::now() - Duration::from_secs(3);
        assert!(ensure_progress(started, Instant::now() + Duration::from_secs(1), 1024).is_err());
        assert!(ensure_progress(started, Instant::now() + Duration::from_secs(1), 4096).is_ok());
    }
}
