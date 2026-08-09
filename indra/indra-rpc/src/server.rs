//! HTTP server for the JSON-RPC API.
//!
//! Uses only the Rust standard library — no external HTTP crate.
//!
//! ## Protocol
//!
//! Listens on TCP. Accepts HTTP/1.1 POST requests to any path.
//! Reads the request body, parses it as JSON-RPC, dispatches to
//! the appropriate handler, and returns the JSON response.
//!
//! ## Thread model (Phase 7)
//!
//! Single-threaded for simplicity. Phase 8 adds a thread pool.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use indra_rpc::RpcServer;
//! use indra_state::ChainState;
//! use std::sync::{Arc, Mutex};
//!
//! let engine = ChainState::new_genesis();
//! let server = RpcServer::new("127.0.0.1:8545", Arc::new(Mutex::new(engine)));
//! // server.run(); // blocks forever
//! ```

use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use indra_network::policy::BoundedTtlMap;

use crate::{
    error::{ERR_INTERNAL_ERROR, ERR_INVALID_REQUEST, ERR_PARSE_ERROR},
    handlers::{
        check_rpc_method_allowed, dispatch_with_mode, DispatchResult, NodeState, RpcEngineMut,
        RpcEngineView, RpcMode,
    },
    types::{parse_request, JsonId, RpcResponse},
};

/// Read timeout for client connections.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of concurrent RPC connections accepted by the node.
pub const MAX_RPC_CONNECTIONS: u64 = 64;

/// Maximum RPC requests per second accepted from one IP address.
pub const RPC_RATE_LIMIT_PER_SEC: u64 = 20;

/// Maximum burst of RPC requests accepted from one IP address.
pub const RPC_RATE_BURST: u64 = 40;

/// Public read-only RPC requests per second accepted from one IP address.
pub const RPC_PUBLIC_RATE_LIMIT_PER_SEC: u64 = 5;

/// Public read-only RPC burst accepted from one IP address.
pub const RPC_PUBLIC_RATE_BURST: u64 = 20;

/// Public read-only RPC listener-wide requests per second.
pub const RPC_PUBLIC_GLOBAL_RATE_LIMIT_PER_SEC: u64 = 100;

/// Public read-only RPC listener-wide burst.
pub const RPC_PUBLIC_GLOBAL_RATE_BURST: u64 = 200;

/// Maximum number of attacker-controlled source identities retained by a limiter.
pub const RPC_LIMITER_MAP_CAPACITY: usize = 16_384;

/// Idle time after which limiter state for a source identity is discarded.
pub const RPC_LIMITER_MAP_IDLE_TTL: Duration = Duration::from_secs(15 * 60);

/// Maximum RPC request body size.
pub const MAX_RPC_BODY_BYTES: usize = 1_048_576;

/// Maximum public read-only RPC request body size.
pub const RPC_PUBLIC_MAX_BODY_BYTES: usize = 64 * 1024;

/// Per-request timeout for blocking stdlib RPC handlers.
pub const RPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-request timeout for public read-only RPC handlers.
pub const RPC_PUBLIC_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum public UTXO/balance scans per minute from one IP.

/// Maximum expensive public read-only calls per minute from one IP.
pub const RPC_PUBLIC_EXPENSIVE_RATE_PER_MIN: u64 = 30;

/// Maximum expensive public read-only calls per minute across a listener.
pub const RPC_PUBLIC_EXPENSIVE_GLOBAL_RATE_PER_MIN: u64 = 300;

fn body_exceeds_rpc_limit(content_length: usize) -> bool {
    content_length > MAX_RPC_BODY_BYTES
}

/// Shared per-IP fixed-window limiter for expensive UTXO scan endpoints.
#[derive(Debug)]
pub struct RpcWindowRateLimiter {
    windows: Mutex<BoundedTtlMap<IpAddr, (Instant, u64)>>,
}

impl RpcWindowRateLimiter {
    /// Create an empty window limiter.
    pub fn new() -> Self {
        Self {
            windows: Mutex::new(BoundedTtlMap::new(
                RPC_LIMITER_MAP_CAPACITY,
                RPC_LIMITER_MAP_IDLE_TTL,
            )),
        }
    }

    /// Return true if `ip` is still within the configured per-minute budget.
    pub fn allow(&self, ip: IpAddr, limit_per_min: u64) -> bool {
        let mut windows = match self.windows.lock() {
            Ok(windows) => windows,
            Err(_) => return false,
        };
        let now = Instant::now();
        let Some(entry) = windows.get_or_insert_with_at(ip, now, || (now, 0)) else {
            return false;
        };
        if entry.0.elapsed() >= Duration::from_secs(60) {
            *entry = (Instant::now(), 0);
        }
        if entry.1 >= limit_per_min {
            return false;
        }
        entry.1 = entry.1.saturating_add(1);
        true
    }

    /// Current live source count and cumulative capacity/TTL evictions.
    pub fn map_stats(&self) -> (usize, u64) {
        self.windows
            .lock()
            .map(|windows| (windows.len(), windows.evictions()))
            .unwrap_or_default()
    }
}

impl Default for RpcWindowRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared fixed-window limiter across the whole listener.
#[derive(Debug)]
pub struct RpcGlobalWindowRateLimiter {
    window: Mutex<(Instant, u64)>,
}

impl Default for RpcGlobalWindowRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RpcGlobalWindowRateLimiter {
    /// Create an empty global fixed-window limiter.
    pub fn new() -> Self {
        Self {
            window: Mutex::new((Instant::now(), 0)),
        }
    }

    /// Return true if the listener is still within the per-minute budget.
    pub fn allow(&self, limit_per_min: u64) -> bool {
        let mut entry = match self.window.lock() {
            Ok(entry) => entry,
            Err(_) => return false,
        };
        if entry.0.elapsed() >= Duration::from_secs(60) {
            *entry = (Instant::now(), 0);
        }
        if entry.1 >= limit_per_min {
            return false;
        }
        entry.1 = entry.1.saturating_add(1);
        true
    }
}

/// Minimal token bucket for RPC request admission.
#[derive(Debug, Clone)]
pub struct RpcTokenBucket {
    tokens: u64,
    capacity: u64,
    refill_per_sec: u64,
    last_refill: Instant,
}

impl RpcTokenBucket {
    /// Create a token bucket with the given refill rate and burst capacity.
    pub fn new(refill_per_sec: u64, capacity: u64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_per_sec,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one request token.
    pub fn allow(&mut self) -> bool {
        self.refill();
        if self.tokens == 0 {
            return false;
        }
        self.tokens = self.tokens.saturating_sub(1);
        true
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs();
        if elapsed == 0 {
            return;
        }
        let added = elapsed.saturating_mul(self.refill_per_sec);
        self.tokens = self.tokens.saturating_add(added).min(self.capacity);
        self.last_refill = Instant::now();
    }
}

/// Shared per-IP RPC limiter.
#[derive(Debug)]
pub struct RpcRateLimiter {
    buckets: Mutex<BoundedTtlMap<IpAddr, RpcTokenBucket>>,
}

impl RpcRateLimiter {
    /// Create an empty RPC rate limiter.
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(BoundedTtlMap::new(
                RPC_LIMITER_MAP_CAPACITY,
                RPC_LIMITER_MAP_IDLE_TTL,
            )),
        }
    }

    /// Return true if a request from `ip` is within the rate limit.
    pub fn allow(&self, ip: IpAddr) -> bool {
        self.allow_with_limits(ip, RPC_RATE_LIMIT_PER_SEC, RPC_RATE_BURST)
    }

    /// Return true if a request from `ip` is within the supplied rate limit.
    pub fn allow_with_limits(&self, ip: IpAddr, refill_per_sec: u64, burst: u64) -> bool {
        let mut buckets = match self.buckets.lock() {
            Ok(buckets) => buckets,
            Err(_) => return false,
        };
        buckets
            .get_or_insert_with_at(ip, Instant::now(), || {
                RpcTokenBucket::new(refill_per_sec, burst)
            })
            .is_some_and(RpcTokenBucket::allow)
    }

    /// Current live source count and cumulative capacity evictions.
    pub fn map_stats(&self) -> (usize, u64) {
        self.buckets
            .lock()
            .map(|buckets| (buckets.len(), buckets.evictions()))
            .unwrap_or_default()
    }
}

impl Default for RpcRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared listener-wide token bucket for aggregate public RPC admission.
#[derive(Debug)]
pub struct RpcGlobalRateLimiter {
    bucket: Mutex<RpcTokenBucket>,
}

impl RpcGlobalRateLimiter {
    /// Create a global limiter with the supplied refill rate and burst.
    pub fn new(refill_per_sec: u64, burst: u64) -> Self {
        Self {
            bucket: Mutex::new(RpcTokenBucket::new(refill_per_sec, burst)),
        }
    }

    /// Return true if the listener-wide request budget has capacity.
    pub fn allow(&self) -> bool {
        match self.bucket.lock() {
            Ok(mut bucket) => bucket.allow(),
            Err(_) => false,
        }
    }
}

/// Build an HTTP 429 response body.
pub fn rpc_rate_limited_response() -> String {
    let body = r#"{"jsonrpc":"2.0","error":{"code":-32029,"message":"RPC rate limit exceeded"},"id":null}"#;
    format!(
        "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

/// Public read-only method cost class used for pre-dispatch throttling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcMethodCost {
    /// Cheap metadata or point lookup.
    Cheap,
    /// Potentially scans sizeable state or reads historical ranges.
    Expensive,
}

/// Classify public read-only methods by expected resource cost.
pub fn rpc_method_cost(method: &str) -> RpcMethodCost {
    match method {
        "indra_getStakePositions"
        | "indra_getUnbondingTranches"
        | "indra_getValidatorStakePositions"
        | "indra_getOwnerStakePositions"
        | "indra_getDelegatorRewards"
        | "indra_getEpochHistory"
        | "indra_getUtxoProof"
        | "indra_getValidatorRewards"
        | "indra_getValidatorSet"
        | "indra_explainUtxoProvenanceAuthorized"
        | "indra_getCanonicalBlocks" => RpcMethodCost::Expensive,
        _ => RpcMethodCost::Cheap,
    }
}

/// Return true when the request body is a JSON-RPC batch request.
pub fn is_batch_request_body(body: &str) -> bool {
    body.trim_start().starts_with('[')
}

/// Parse a JSON-RPC request body or return the JSON-RPC error response that
/// should be sent for envelope-level failures.
pub fn parse_http_json_rpc_body(body: &str) -> Result<crate::types::RpcRequest, RpcResponse> {
    if is_batch_request_body(body) {
        return Err(RpcResponse::err(
            JsonId::Null,
            ERR_INVALID_REQUEST,
            "batch requests not supported".to_string(),
        ));
    }

    parse_request(body)
        .map_err(|error| RpcResponse::err(JsonId::Null, error.code(), error.response_message()))
}

/// Build CORS response headers. Empty allowlist means no browser cross-origin access.
pub fn cors_headers(origin: Option<&str>, allowlist: &[String]) -> String {
    let Some(origin) = origin else {
        return String::new();
    };
    if allowlist.iter().any(|allowed| allowed == origin) {
        format!(
            "Access-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, X-Admin-Token\r\n",
            origin
        )
    } else {
        String::new()
    }
}

/// Build a JSON HTTP error with a non-200 status.
pub fn http_json_error(status: &str, code: i32, message: &str, cors: &str) -> String {
    let body = format!(
        r#"{{"jsonrpc":"2.0","error":{{"code":{},"message":"{}"}},"id":null}}"#,
        code,
        message.replace('"', "\\\"")
    );
    format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        cors,
        body.len(),
        body
    )
}

/// The JSON-RPC HTTP server.
pub struct RpcServer<E> {
    addr: String,
    engine: Arc<Mutex<E>>,
}

impl<E> RpcServer<E>
where
    E: RpcEngineMut + Send + 'static,
{
    /// Create a new server bound to the given address.
    pub fn new(addr: &str, engine: Arc<Mutex<E>>) -> Self {
        Self {
            addr: addr.to_string(),
            engine,
        }
    }

    /// Start the server. Blocks forever, handling one connection at a time.
    ///
    /// Phase 8 replaces this with a thread-pool or Tokio async loop.
    pub fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.addr)?;
        loop {
            let (stream, _) = listener.accept()?;
            let engine = Arc::clone(&self.engine);
            Self::handle_connection(stream, engine);
        }
    }

    /// Handle one HTTP connection.
    /// Handle a single inbound TCP stream as a JSON-RPC request.
    pub fn handle_connection(stream: TcpStream, engine: Arc<Mutex<E>>) {
        let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
        let response = match Self::read_and_process(&stream, &engine) {
            Ok(resp) => resp,
            Err(e) => {
                let resp = RpcResponse::err(JsonId::Null, ERR_INTERNAL_ERROR, e.to_string());
                resp.to_json()
            }
        };

        let http_response = if response == "__OPTIONS__" {
            "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_string()
        } else if response == "__METHOD_NOT_ALLOWED__" {
            http_json_error("405 Method Not Allowed", -32600, "Method Not Allowed", "")
        } else if response == "__PAYLOAD_TOO_LARGE__" {
            http_json_error(
                "413 Payload Too Large",
                -32600,
                "request body too large",
                "",
            )
        } else {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
        };

        if let Ok(mut w) = stream.try_clone() {
            let _ = w.write_all(http_response.as_bytes());
        }
    }

    /// Read the HTTP request body and process the JSON-RPC call.
    fn read_and_process(
        stream: &TcpStream,
        engine: &Arc<Mutex<E>>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut reader = BufReader::new(stream.try_clone()?);

        // Read HTTP headers to find Content-Length and method
        let mut content_length = 0usize;
        let mut method = String::new();
        let mut line = String::new();
        let mut first_line = true;

        loop {
            line.clear();
            reader.read_line(&mut line)?;
            let trimmed = line.trim();
            if first_line {
                method = trimmed
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                first_line = false;
            }
            if trimmed.is_empty() {
                break;
            }
            if trimmed.to_lowercase().starts_with("content-length:") {
                let val = trimmed["content-length:".len()..].trim();
                content_length = val.parse().unwrap_or(0);
            }
        }

        if method == "OPTIONS" {
            return Ok("__OPTIONS__".to_string());
        }
        if method != "POST" {
            return Ok("__METHOD_NOT_ALLOWED__".to_string());
        }

        if content_length == 0 {
            return Ok(RpcResponse::err(
                JsonId::Null,
                ERR_PARSE_ERROR,
                "empty request body".to_string(),
            )
            .to_json());
        }

        // Read body
        if body_exceeds_rpc_limit(content_length) {
            return Ok("__PAYLOAD_TOO_LARGE__".to_string());
        }

        let mut body = vec![0u8; content_length];
        use std::io::Read;
        reader.read_exact(&mut body)?;
        let body_str = String::from_utf8_lossy(&body);
        // Parse JSON-RPC request
        let req = match parse_http_json_rpc_body(&body_str) {
            Ok(r) => r,
            Err(response) => {
                return Ok(response.to_json());
            }
        };

        let id = req.id.clone();

        let mut guard = engine.lock().map_err(|_| "engine lock poisoned")?;
        Ok(dispatch_to_response(
            &req.method,
            &req.params,
            id,
            &mut *guard,
            RpcMode::Full,
        ))
    }
}

/// Handle one HTTP/JSON-RPC request from a raw TCP stream with an engine reference.
///
/// This is the integration point for the node binary. It borrows the engine
/// for the duration of one request only — no Arc or cloning required.
pub fn handle_with_engine<E: RpcEngineView>(stream: TcpStream, engine: &E) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let response = match read_and_process_ref(&stream, engine) {
        Ok(resp) => resp,
        Err(e) => {
            let resp = RpcResponse::err(JsonId::Null, ERR_INTERNAL_ERROR, e.to_string());
            resp.to_json()
        }
    };

    let http_response = if response == "__OPTIONS__" {
        "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_string()
    } else if response == "__METHOD_NOT_ALLOWED__" {
        http_json_error("405 Method Not Allowed", -32600, "Method Not Allowed", "")
    } else if response == "__PAYLOAD_TOO_LARGE__" {
        http_json_error(
            "413 Payload Too Large",
            -32600,
            "request body too large",
            "",
        )
    } else {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response.len(),
            response
        )
    };

    if let Ok(mut w) = stream.try_clone() {
        let _ = w.write_all(http_response.as_bytes());
    }
}

/// Read and process one HTTP request using a plain engine reference.
fn read_and_process_ref<E: RpcEngineView>(
    stream: &TcpStream,
    engine: &E,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut content_length = 0usize;
    let mut method = String::new();
    let mut line = String::new();
    let mut first_line = true;

    loop {
        line.clear();
        reader.read_line(&mut line)?;
        let trimmed = line.trim();
        if first_line {
            method = trimmed
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();
            first_line = false;
        }
        if trimmed.is_empty() {
            break;
        }
        if trimmed.to_lowercase().starts_with("content-length:") {
            let val = trimmed["content-length:".len()..].trim();
            content_length = val.parse().unwrap_or(0);
        }
    }

    if method == "OPTIONS" {
        return Ok("__OPTIONS__".to_string());
    }
    if method != "POST" {
        return Ok("__METHOD_NOT_ALLOWED__".to_string());
    }

    if content_length == 0 {
        return Ok(RpcResponse::err(
            JsonId::Null,
            ERR_PARSE_ERROR,
            "empty request body".to_string(),
        )
        .to_json());
    }

    if body_exceeds_rpc_limit(content_length) {
        return Ok("__PAYLOAD_TOO_LARGE__".to_string());
    }

    let mut body = vec![0u8; content_length];
    use std::io::Read;
    reader.read_exact(&mut body)?;
    let body_str = String::from_utf8_lossy(&body);
    let req = match parse_http_json_rpc_body(&body_str) {
        Ok(r) => r,
        Err(response) => {
            return Ok(response.to_json());
        }
    };

    if let Err(error) = check_rpc_method_allowed(&req.method, RpcMode::ReadOnly) {
        return Ok(RpcResponse::err(req.id, error.code(), error.message().to_string()).to_json());
    }

    let state = NodeState::read_only(engine);
    let resp = match dispatch_with_mode(&req.method, &req.params, &state, RpcMode::ReadOnly) {
        DispatchResult::Ready(Ok(json)) => RpcResponse::ok(req.id, json),
        DispatchResult::Ready(Err(e)) => {
            RpcResponse::err(req.id, e.code(), e.message().to_string())
        }
        DispatchResult::SubmitStakingOp(_)
        | DispatchResult::SubmitGovernanceOp(_)
        | DispatchResult::SubmitTransaction(_) => RpcResponse::err(
            req.id,
            -32000,
            "mutation not available in read-only mode".to_string(),
        ),
    };

    Ok(resp.to_json())
}

/// Make a direct in-process RPC call (for testing without HTTP).
pub fn call_rpc<E: RpcEngineView>(method: &str, params: &[String], engine: &E) -> String {
    call_rpc_with_mode(method, params, engine, RpcMode::ReadOnly)
}

/// Make a direct in-process RPC call with an explicit listener mode.
pub fn call_rpc_with_mode<E: RpcEngineView>(
    method: &str,
    params: &[String],
    engine: &E,
    mode: RpcMode,
) -> String {
    let state = NodeState::read_only(engine);
    match dispatch_with_mode(method, params, &state, mode) {
        DispatchResult::Ready(Ok(result)) => RpcResponse::ok(JsonId::Number(1), result).to_json(),
        DispatchResult::Ready(Err(e)) => {
            RpcResponse::err(JsonId::Number(1), e.code(), e.message().to_string()).to_json()
        }
        DispatchResult::SubmitStakingOp(_)
        | DispatchResult::SubmitGovernanceOp(_)
        | DispatchResult::SubmitTransaction(_) => RpcResponse::err(
            JsonId::Number(1),
            -32000,
            "mutation not available in read-only mode".to_string(),
        )
        .to_json(),
    }
}

fn dispatch_to_response<E: RpcEngineMut>(
    method: &str,
    params: &[String],
    id: JsonId,
    engine: &mut E,
    mode: RpcMode,
) -> String {
    let state = NodeState::read_only(engine);
    let resp = match dispatch_with_mode(method, params, &state, mode) {
        DispatchResult::Ready(Ok(json)) => RpcResponse::ok(id, json),
        DispatchResult::Ready(Err(e)) => RpcResponse::err(id, e.code(), e.message().to_string()),
        DispatchResult::SubmitStakingOp(op_bytes) => {
            use indra_core::codec::Decode;
            use indra_core::types::staking::StakingOp;
            match StakingOp::decode_exact(&op_bytes) {
                Ok(op) => match engine.rpc_add_staking_op(op) {
                    Ok(()) => RpcResponse::ok(id, r#"{"status":"accepted"}"#.to_string()),
                    Err(e) => RpcResponse::err(id, -32000, format!("rejected: {e}")),
                },
                Err(e) => RpcResponse::err(id, -32602, format!("staking op decode failed: {e}")),
            }
        }
        DispatchResult::SubmitGovernanceOp(op_bytes) => {
            use indra_core::codec::Decode;
            use indra_core::types::governance::GovernanceOpV2;
            match GovernanceOpV2::decode_exact(&op_bytes) {
                Ok(op) => match engine.rpc_add_governance_op(op) {
                    Ok(()) => RpcResponse::ok(id, r#"{"status":"accepted"}"#.to_string()),
                    Err(e) => RpcResponse::err(id, -32000, format!("rejected: {e}")),
                },
                Err(e) => RpcResponse::err(id, -32602, format!("governance op decode failed: {e}")),
            }
        }
        DispatchResult::SubmitTransaction(tx_bytes) => {
            use indra_core::codec::{ByteReader, Decode};
            use indra_core::types::transaction::TransactionV1;
            let mut reader = ByteReader::new(&tx_bytes);
            match TransactionV1::decode(&mut reader) {
                Ok(tx) => match engine.rpc_submit_transaction(tx) {
                    Ok(tx_id) => RpcResponse::ok(
                        id,
                        format!(
                            r#"{{"tx_id":"{}","status":"accepted"}}"#,
                            hex::encode(tx_id.0)
                        ),
                    ),
                    Err(e) => RpcResponse::err(id, -32000, format!("mempool rejected: {e}")),
                },
                Err(e) => RpcResponse::err(id, -32602, format!("tx decode failed: {e}")),
            }
        }
    };
    resp.to_json()
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_state::ChainState;

    fn http_rpc_response_body(body: &str) -> String {
        let request = match parse_http_json_rpc_body(body) {
            Ok(request) => request,
            Err(response) => return response.to_json(),
        };
        let mut engine = ChainState::new_genesis();
        dispatch_to_response(
            &request.method,
            &request.params,
            request.id,
            &mut engine,
            RpcMode::Full,
        )
    }

    fn assert_rpc_error_code(body: &str, code: i32) -> String {
        let response = http_rpc_response_body(body);
        assert!(
            response.contains(&format!(r#""code":{}"#, code)),
            "expected code {code}, got {response}"
        );
        response
    }

    #[test]
    fn call_rpc_get_height() {
        let engine = ChainState::new_genesis();
        let resp = call_rpc("indra_getHeight", &[], &engine);
        assert!(resp.contains("\"height\":0"));
        assert!(resp.contains("\"result\""));
    }

    #[test]
    fn call_rpc_unknown_method() {
        let engine = ChainState::new_genesis();
        let resp = call_rpc("indra_fake", &[], &engine);
        assert!(resp.contains("\"error\""));
        assert!(resp.contains("-32601"));

        let full_resp = call_rpc_with_mode("indra_fake", &[], &engine, RpcMode::Full);
        assert!(full_resp.contains("\"error\""));
        assert!(full_resp.contains("-32601"));
    }

    #[test]
    fn call_rpc_chain_info() {
        let engine = ChainState::new_genesis();
        let resp = call_rpc("indra_getChainInfo", &[], &engine);
        assert!(resp.contains("\"result\""));
        assert!(resp.contains("\"height\""));
        assert!(resp.contains("\"base_fee\""));
    }

    #[test]
    fn call_rpc_validator_set() {
        let engine = ChainState::new_genesis();
        let resp = call_rpc("indra_getValidatorSet", &[], &engine);
        assert!(resp.contains("\"validators\""));
    }

    #[test]
    fn rpc_legacy_scan_challenge_returns_error_for_invalid_address() {
        let engine = ChainState::new_genesis();
        let resp = call_rpc(
            "indra_getLegacyScanChallenge",
            &["not-hex".to_string()],
            &engine,
        );
        assert!(resp.contains("\"error\""));
        assert!(resp.contains("invalid address"));
        assert!(!resp.contains("\"balance\":0"));
    }

    #[test]
    fn rpc_per_ip_rate_limit_returns_429() {
        let ip = "203.0.113.9".parse().unwrap();
        let limiter = RpcRateLimiter::new();
        for _ in 0..RPC_RATE_BURST {
            assert!(limiter.allow(ip));
        }
        assert!(!limiter.allow(ip));

        let response = rpc_rate_limited_response();
        assert!(response.starts_with("HTTP/1.1 429 Too Many Requests"));
        assert!(response.contains("RPC rate limit exceeded"));
    }

    #[test]
    fn rpc_public_global_rate_limit_catches_many_ip_aggregate() {
        let per_ip = RpcRateLimiter::new();
        let global = RpcGlobalRateLimiter::new(1, 3);

        for idx in 1..=3u8 {
            let ip = IpAddr::from([203, 0, 113, idx]);
            assert!(per_ip.allow_with_limits(
                ip,
                RPC_PUBLIC_RATE_LIMIT_PER_SEC,
                RPC_PUBLIC_RATE_BURST
            ));
            assert!(global.allow());
        }

        let fourth_ip = IpAddr::from([203, 0, 113, 99]);
        assert!(per_ip.allow_with_limits(
            fourth_ip,
            RPC_PUBLIC_RATE_LIMIT_PER_SEC,
            RPC_PUBLIC_RATE_BURST
        ));
        assert!(
            !global.allow(),
            "listener-wide public limit must reject distributed traffic even when each IP is below its own bucket"
        );
    }

    #[test]
    fn rpc_public_expensive_method_classification_is_explicit() {
        assert_eq!(
            rpc_method_cost("indra_getStakePositions"),
            RpcMethodCost::Expensive
        );
        assert_eq!(
            rpc_method_cost("indra_getEpochHistory"),
            RpcMethodCost::Expensive
        );
        for method in [
            "indra_getValidatorRewards",
            "indra_getValidatorSet",
            "indra_explainUtxoProvenanceAuthorized",
            "indra_getCanonicalBlocks",
        ] {
            assert_eq!(
                rpc_method_cost(method),
                RpcMethodCost::Expensive,
                "{method}"
            );
        }
        assert_eq!(rpc_method_cost("indra_getHeight"), RpcMethodCost::Cheap);
    }

    #[test]
    fn rpc_http_invalid_jsonrpc_version_returns_invalid_request() {
        let response = assert_rpc_error_code(
            r#"{"jsonrpc":"1.0","method":"indra_getChainInfo","params":[],"id":1}"#,
            -32600,
        );
        assert!(response.contains("Invalid Request"));
        assert!(response.contains("jsonrpc"));
    }

    #[test]
    fn rpc_http_missing_jsonrpc_returns_invalid_request() {
        assert_rpc_error_code(
            r#"{"method":"indra_getChainInfo","params":[],"id":1}"#,
            -32600,
        );
    }

    #[test]
    fn rpc_http_missing_or_invalid_method_returns_invalid_request() {
        assert_rpc_error_code(r#"{"jsonrpc":"2.0","params":[],"id":1}"#, -32600);
        assert_rpc_error_code(
            r#"{"jsonrpc":"2.0","method":42,"params":[],"id":1}"#,
            -32600,
        );
    }

    #[test]
    fn rpc_http_invalid_id_type_returns_invalid_request() {
        assert_rpc_error_code(
            r#"{"jsonrpc":"2.0","method":"indra_getChainInfo","params":[],"id":{}}"#,
            -32600,
        );
    }

    #[test]
    fn rpc_http_non_array_params_returns_invalid_request() {
        assert_rpc_error_code(
            r#"{"jsonrpc":"2.0","method":"indra_getChainInfo","params":{"x":1},"id":1}"#,
            -32600,
        );
    }

    #[test]
    fn rpc_http_non_object_top_level_json_returns_invalid_request() {
        assert_rpc_error_code(r#""hello""#, -32600);
        assert_rpc_error_code("42", -32600);
        assert_rpc_error_code("null", -32600);
    }

    #[test]
    fn rpc_http_malformed_json_returns_parse_error() {
        let response = assert_rpc_error_code(
            r#"{"jsonrpc":"2.0","method":"indra_getChainInfo","params":[],"id":1"#,
            -32700,
        );
        assert!(response.contains("parse error"));
    }

    #[test]
    fn rpc_http_missing_params_still_succeeds() {
        let response =
            http_rpc_response_body(r#"{"jsonrpc":"2.0","method":"indra_getChainInfo","id":1}"#);
        assert!(
            response.contains(r#""result":"#),
            "missing params should remain valid, got {response}"
        );
        assert!(!response.contains(r#""error":"#), "{response}");
    }

    #[test]
    fn rpc_http_top_level_array_still_returns_batch_rejection() {
        let response = assert_rpc_error_code(
            r#"[{"jsonrpc":"2.0","method":"indra_getChainInfo","params":[],"id":1}]"#,
            -32600,
        );
        assert!(response.contains("batch requests not supported"));
    }

    #[test]
    fn rpc_rejects_batch_requests() {
        assert!(is_batch_request_body(r#"[{"jsonrpc":"2.0"}]"#));
        assert!(!is_batch_request_body(r#"{"jsonrpc":"2.0"}"#));
    }

    #[test]
    fn rpc_rejects_oversized_body_before_allocation() {
        assert!(!body_exceeds_rpc_limit(MAX_RPC_BODY_BYTES));
        assert!(body_exceeds_rpc_limit(MAX_RPC_BODY_BYTES + 1));
        let response = http_json_error(
            "413 Payload Too Large",
            -32600,
            "request body too large",
            "",
        );
        assert!(response.starts_with("HTTP/1.1 413 Payload Too Large"));
        assert!(response.contains("request body too large"));
    }

    #[test]
    fn rpc_rejects_non_post_method() {
        let response = http_json_error("405 Method Not Allowed", -32600, "Method Not Allowed", "");
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed"));
    }

    #[test]
    fn rpc_cors_default_is_restrictive() {
        let headers = cors_headers(Some("http://localhost:3000"), &[]);
        assert!(!headers.contains("Access-Control-Allow-Origin: *"));
        assert!(headers.is_empty());
    }

    #[test]
    fn rpc_cors_reflects_allowlisted_origin() {
        let headers = cors_headers(
            Some("http://localhost:3000"),
            &["http://localhost:3000".to_string()],
        );
        assert!(headers.contains("Access-Control-Allow-Origin: http://localhost:3000"));
        assert!(!headers.contains("Access-Control-Allow-Origin: *"));
    }

    #[test]
    fn oversized_rpc_body_limit_is_documented() {
        assert_eq!(MAX_RPC_BODY_BYTES, 1_048_576);
    }
}
