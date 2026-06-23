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
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{
    error::{ERR_INTERNAL_ERROR, ERR_PARSE_ERROR},
    handlers::{dispatch, DispatchResult, NodeState, RpcEngineMut, RpcEngineView},
    types::{parse_request, JsonId, RpcResponse},
};

/// Read timeout for client connections.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

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
            "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n".to_string()
        } else {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
        let mut is_options = false;
        let mut line = String::new();
        let mut first_line = true;

        loop {
            line.clear();
            reader.read_line(&mut line)?;
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
                let val = trimmed["content-length:".len()..].trim();
                content_length = val.parse().unwrap_or(0);
            }
        }

        // Respond to CORS preflight immediately
        if is_options {
            return Ok("__OPTIONS__".to_string());
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
        let mut body = vec![0u8; content_length.min(1_048_576)]; // max 1 MB
        use std::io::Read;
        reader.read_exact(&mut body)?;
        let body_str = String::from_utf8_lossy(&body);

        // Parse JSON-RPC request
        let req = match parse_request(&body_str) {
            Ok(r) => r,
            Err(e) => {
                return Ok(RpcResponse::err(JsonId::Null, ERR_PARSE_ERROR, e).to_json());
            }
        };

        let id = req.id.clone();

        let mut guard = engine.lock().map_err(|_| "engine lock poisoned")?;
        Ok(dispatch_to_response(
            &req.method,
            &req.params,
            id,
            &mut *guard,
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
        "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n".to_string()
    } else {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
    let mut is_options = false;
    let mut line = String::new();
    let mut first_line = true;

    loop {
        line.clear();
        reader.read_line(&mut line)?;
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
            let val = trimmed["content-length:".len()..].trim();
            content_length = val.parse().unwrap_or(0);
        }
    }

    if is_options {
        return Ok("__OPTIONS__".to_string());
    }

    if content_length == 0 {
        return Ok(RpcResponse::err(
            JsonId::Null,
            ERR_PARSE_ERROR,
            "empty request body".to_string(),
        )
        .to_json());
    }

    let mut body = vec![0u8; content_length.min(1_048_576)];
    use std::io::Read;
    reader.read_exact(&mut body)?;
    let body_str = String::from_utf8_lossy(&body);

    let req = match parse_request(&body_str) {
        Ok(r) => r,
        Err(e) => {
            return Ok(RpcResponse::err(JsonId::Null, ERR_PARSE_ERROR, e).to_json());
        }
    };

    let state = NodeState::read_only(engine);
    let resp = match dispatch(&req.method, &req.params, &state) {
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
    let state = NodeState::read_only(engine);
    match dispatch(method, params, &state) {
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
) -> String {
    let state = NodeState::read_only(engine);
    let resp = match dispatch(method, params, &state) {
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
}
