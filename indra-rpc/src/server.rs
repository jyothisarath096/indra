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
//! use indra_node::{NodeConfig, NodeEngine};
//! use std::path::PathBuf;
//! use std::sync::{Arc, Mutex};
//!
//! let config = NodeConfig::local_test(PathBuf::from("/tmp/test"));
//! let engine = NodeEngine::init(config).unwrap();
//! let server = RpcServer::new("127.0.0.1:8545", Arc::new(Mutex::new(engine)));
//! // server.run(); // blocks forever
//! ```

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use indra_node::NodeEngine;

use crate::{
    error::{RpcError, ERR_INTERNAL_ERROR, ERR_PARSE_ERROR},
    handlers::{dispatch, NodeState},
    types::{parse_request, JsonId, RpcResponse},
};

/// Read timeout for client connections.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The JSON-RPC HTTP server.
pub struct RpcServer {
    addr:   String,
    engine: Arc<Mutex<NodeEngine>>,
}

impl RpcServer {
    /// Create a new server bound to the given address.
    pub fn new(addr: &str, engine: Arc<Mutex<NodeEngine>>) -> Self {
        Self {
            addr:   addr.to_string(),
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
    fn handle_connection(stream: TcpStream, engine: Arc<Mutex<NodeEngine>>) {
        let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
        let response = match Self::read_and_process(&stream, &engine) {
            Ok(resp) => resp,
            Err(e) => {
                let resp = RpcResponse::err(
                    JsonId::Null,
                    ERR_INTERNAL_ERROR,
                    e.to_string(),
                );
                resp.to_json()
            }
        };

        let http_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response.len(),
            response
        );

        if let Ok(mut w) = stream.try_clone() {
            let _ = w.write_all(http_response.as_bytes());
        }
    }

    /// Read the HTTP request body and process the JSON-RPC call.
    fn read_and_process(
        stream: &TcpStream,
        engine: &Arc<Mutex<NodeEngine>>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut reader = BufReader::new(stream.try_clone()?);

        // Read HTTP headers to find Content-Length
        let mut content_length = 0usize;
        let mut line = String::new();

        loop {
            line.clear();
            reader.read_line(&mut line)?;
            let trimmed = line.trim();
            if trimmed.is_empty() { break; }
            if trimmed.to_lowercase().starts_with("content-length:") {
                let val = trimmed["content-length:".len()..].trim();
                content_length = val.parse().unwrap_or(0);
            }
        }

        if content_length == 0 {
            return Ok(RpcResponse::err(
                JsonId::Null,
                ERR_PARSE_ERROR,
                "empty request body".to_string(),
            ).to_json());
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
                return Ok(RpcResponse::err(
                    JsonId::Null,
                    ERR_PARSE_ERROR,
                    e,
                ).to_json());
            }
        };

        let id = req.id.clone();

        // Dispatch to handler
        let guard = engine.lock().map_err(|_| "engine lock poisoned")?;
        let state = NodeState { engine: &guard };
        let result = dispatch(&req.method, &req.params, &state);
        drop(guard);

        let resp = match result {
            Ok(json)  => RpcResponse::ok(id, json),
            Err(e)    => RpcResponse::err(id, e.code(), e.to_string()),
        };

        Ok(resp.to_json())
    }
}

/// Make a direct in-process RPC call (for testing without HTTP).
pub fn call_rpc(
    method: &str,
    params: &[String],
    engine: &NodeEngine,
) -> String {
    let state = NodeState { engine };
    match dispatch(method, params, &state) {
        Ok(result) => RpcResponse::ok(JsonId::Number(1), result).to_json(),
        Err(e)     => RpcResponse::err(JsonId::Number(1), e.code(), e.to_string()).to_json(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_node::{NodeConfig, NodeEngine};
    use std::path::PathBuf;

    fn temp_dir(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_rpc_server_test_{}_{}", suffix, std::process::id()));
        p
    }

    #[test]
    fn call_rpc_get_height() {
        let dir = temp_dir("a");
        let engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let resp = call_rpc("indra_getHeight", &[], &engine);
        assert!(resp.contains("\"height\":0"));
        assert!(resp.contains("\"result\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn call_rpc_unknown_method() {
        let dir = temp_dir("b");
        let engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let resp = call_rpc("indra_fake", &[], &engine);
        assert!(resp.contains("\"error\""));
        assert!(resp.contains("-32601"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn call_rpc_chain_info() {
        let dir = temp_dir("c");
        let engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let resp = call_rpc("indra_getChainInfo", &[], &engine);
        assert!(resp.contains("\"result\""));
        assert!(resp.contains("\"height\""));
        assert!(resp.contains("\"base_fee\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn call_rpc_validator_set() {
        let dir = temp_dir("d");
        let engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let resp = call_rpc("indra_getValidatorSet", &[], &engine);
        assert!(resp.contains("\"validators\""));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
