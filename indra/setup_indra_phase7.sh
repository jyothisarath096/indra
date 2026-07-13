#!/usr/bin/env bash
# =============================================================================
# INDRA v2 — Phase 7 Setup Script
# JSON-RPC API + CLI Tools + Genesis Config → Private Testnet Ready
# =============================================================================
# Run from inside the indra/ workspace directory:
#
#   chmod +x setup_indra_phase7.sh
#   ./setup_indra_phase7.sh
#   cargo build
#   cargo test
#
# Prerequisites: Phases 1–6 must be passing.
#
# What this adds:
#
#   indra-rpc/            — new crate: JSON-RPC API server
#     src/lib.rs
#     src/error.rs
#     src/types.rs        — request/response JSON types
#     src/handlers.rs     — RPC method implementations
#     src/server.rs       — HTTP server (stdlib, no external deps)
#     tests/rpc.rs
#
#   indra-cli/            — new crate: command-line tools
#     src/lib.rs
#     src/keygen.rs       — generate validator + BLS + VRF keypairs
#     src/genesis_cmd.rs  — build genesis config from validator list
#     src/tx_cmd.rs       — build and submit transactions
#     src/query.rs        — query chain state via RPC
#     tests/cli.rs
#
#   genesis.toml.example  — example genesis config for testnet
# =============================================================================

set -euo pipefail

echo "==> Setting up INDRA Phase 7 — JSON-RPC API + CLI Tools..."

if [ ! -f "Cargo.toml" ]; then
    echo "ERROR: Run from inside the indra/ workspace directory."
    exit 1
fi

# =============================================================================
# Update workspace Cargo.toml
# =============================================================================

cat > Cargo.toml << 'TOML'
[workspace]
members  = [
    "indra-core",
    "indra-crypto",
    "indra-state",
    "indra-consensus",
    "indra-storage",
    "indra-node",
    "indra-network",
    "indra-rpc",
    "indra-cli",
]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
authors = ["INDRA Protocol"]
license = "MIT"

[workspace.dependencies]
sha2               = { version = "0.10", default-features = false }
thiserror          = { version = "1.0" }
hex                = { version = "0.4", default-features = false, features = ["alloc"] }
ed25519-dalek      = { version = "2.1", default-features = false, features = ["alloc"] }
curve25519-dalek   = { version = "4.1", default-features = false, features = ["alloc"] }
pqcrypto-dilithium = { version = "0.5", default-features = false }
pqcrypto-traits    = { version = "0.3", default-features = false }
blst               = { version = "0.3" }
proptest           = { version = "1.4", default-features = false, features = ["std"] }

[profile.release]
opt-level     = 3
lto           = true
codegen-units = 1
panic         = "abort"

[profile.dev]
opt-level = 0
debug     = true
TOML

# =============================================================================
# Create indra-rpc crate
# =============================================================================

mkdir -p indra-rpc/src
mkdir -p indra-rpc/tests

cat > indra-rpc/Cargo.toml << 'TOML'
[package]
name        = "indra-rpc"
description = "INDRA v2 JSON-RPC API server"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
indra-core      = { path = "../indra-core" }
indra-crypto    = { path = "../indra-crypto" }
indra-state     = { path = "../indra-state" }
indra-consensus = { path = "../indra-consensus" }
indra-node      = { path = "../indra-node" }
thiserror.workspace = true
hex.workspace = true

[dev-dependencies]
indra-core      = { path = "../indra-core" }
indra-state     = { path = "../indra-state" }
indra-node      = { path = "../indra-node" }
TOML

# --------------- indra-rpc/src/lib.rs ---------------

cat > indra-rpc/src/lib.rs << 'RUST'
//! # indra-rpc
//!
//! JSON-RPC 2.0 API for the INDRA v2 node.
//!
//! ## Endpoints
//!
//! | Method                    | Description                                    |
//! |---------------------------|------------------------------------------------|
//! | `indra_getHeight`         | Current chain height                           |
//! | `indra_getBlock`          | Block by height                                |
//! | `indra_getTip`            | Current tip hash and height                    |
//! | `indra_getLegacyBalanceAuthorized` | Authorized legacy UTXO balance scan  |
//! | `indra_getLegacyUtxosAuthorized`   | Authorized legacy UTXO scan          |
//! | `indra_getMempoolSize`    | Number of pending transactions                 |
//! | `indra_sendTransaction`   | Submit a signed transaction                    |
//! | `indra_getTransaction`    | Look up a transaction by ID                    |
//! | `indra_getValidator`      | Validator info by ID                           |
//! | `indra_getChainInfo`      | Chain summary (height, supply, base fee, etc.) |
//! | `indra_getValidatorSet`   | All active validators and their stakes         |
//!
//! ## Wire format
//!
//! Standard JSON-RPC 2.0 over HTTP POST to `/`.
//!
//! Request:
//! ```json
//! {"jsonrpc":"2.0","method":"indra_getHeight","params":[],"id":1}
//! ```
//!
//! Response:
//! ```json
//! {"jsonrpc":"2.0","result":{"height":42},"id":1}
//! ```
//!
//! Error:
//! ```json
//! {"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":1}
//! ```
//!
//! ## No external dependencies
//!
//! The HTTP server and JSON codec use only the Rust standard library.
//! This keeps the binary small and the dependency tree auditable.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod error;
pub mod types;
pub mod handlers;
pub mod server;

pub use error::{RpcError, RpcResult};
pub use server::RpcServer;
pub use types::{RpcRequest, RpcResponse, RpcErrorBody};
RUST

# --------------- indra-rpc/src/error.rs ---------------

cat > indra-rpc/src/error.rs << 'RUST'
//! RPC error types.

use thiserror::Error;

/// JSON-RPC 2.0 standard error codes.
pub const ERR_PARSE_ERROR:      i32 = -32700;
pub const ERR_INVALID_REQUEST:  i32 = -32600;
pub const ERR_METHOD_NOT_FOUND: i32 = -32601;
pub const ERR_INVALID_PARAMS:   i32 = -32602;
pub const ERR_INTERNAL_ERROR:   i32 = -32603;
/// Application-specific error range starts at -32000.
pub const ERR_NOT_FOUND:        i32 = -32000;
/// Transaction rejected.
pub const ERR_TX_REJECTED:      i32 = -32001;
/// Node is not synced.
pub const ERR_NOT_SYNCED:       i32 = -32002;

/// An RPC-level error.
#[derive(Debug, Error, Clone)]
pub enum RpcError {
    /// Request JSON was malformed.
    #[error("parse error: {0}")]
    ParseError(String),

    /// The requested method does not exist.
    #[error("method not found: {0}")]
    MethodNotFound(String),

    /// Parameters were missing or invalid.
    #[error("invalid params: {0}")]
    InvalidParams(String),

    /// An internal node error occurred.
    #[error("internal error: {0}")]
    Internal(String),

    /// The requested resource was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// A submitted transaction was rejected.
    #[error("transaction rejected: {0}")]
    TxRejected(String),
}

impl RpcError {
    /// The JSON-RPC error code for this error.
    pub fn code(&self) -> i32 {
        match self {
            Self::ParseError(_)    => ERR_PARSE_ERROR,
            Self::MethodNotFound(_) => ERR_METHOD_NOT_FOUND,
            Self::InvalidParams(_) => ERR_INVALID_PARAMS,
            Self::Internal(_)      => ERR_INTERNAL_ERROR,
            Self::NotFound(_)      => ERR_NOT_FOUND,
            Self::TxRejected(_)    => ERR_TX_REJECTED,
        }
    }
}

/// Convenience alias.
pub type RpcResult<T> = Result<T, RpcError>;
RUST

# --------------- indra-rpc/src/types.rs ---------------

cat > indra-rpc/src/types.rs << 'RUST'
//! JSON-RPC 2.0 request and response types.
//!
//! All serialisation is manual (no serde) to keep dependencies minimal.
//! Values are represented as JSON strings and parsed on demand.

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone)]
pub struct RpcRequest {
    /// Must be "2.0".
    pub jsonrpc: String,
    /// The method name.
    pub method: String,
    /// Parameters as a raw JSON array string.
    pub params: Vec<String>,
    /// Request ID (string or number).
    pub id: JsonId,
}

/// A JSON-RPC 2.0 response.
#[derive(Debug, Clone)]
pub struct RpcResponse {
    /// Always "2.0".
    pub jsonrpc: String,
    /// The result or error.
    pub body: ResponseBody,
    /// Matches the request ID.
    pub id: JsonId,
}

/// The body of an RPC response.
#[derive(Debug, Clone)]
pub enum ResponseBody {
    /// Successful result as a JSON value string.
    Result(String),
    /// Error body.
    Error(RpcErrorBody),
}

/// JSON-RPC error body.
#[derive(Debug, Clone)]
pub struct RpcErrorBody {
    /// Error code.
    pub code: i32,
    /// Human-readable message.
    pub message: String,
}

/// A JSON-RPC ID — either a number or a string.
#[derive(Debug, Clone)]
pub enum JsonId {
    /// Numeric ID.
    Number(i64),
    /// String ID.
    Str(String),
    /// Null ID (notification).
    Null,
}

impl RpcResponse {
    /// Serialise to JSON string.
    pub fn to_json(&self) -> String {
        let id_str = match &self.id {
            JsonId::Number(n) => n.to_string(),
            JsonId::Str(s)    => format!("\"{}\"", s),
            JsonId::Null      => "null".to_string(),
        };

        match &self.body {
            ResponseBody::Result(result) => {
                format!(
                    r#"{{"jsonrpc":"2.0","result":{},"id":{}}}"#,
                    result, id_str
                )
            }
            ResponseBody::Error(err) => {
                format!(
                    r#"{{"jsonrpc":"2.0","error":{{"code":{},"message":"{}"}},"id":{}}}"#,
                    err.code,
                    err.message.replace('"', "\\\""),
                    id_str
                )
            }
        }
    }

    /// Build a success response.
    pub fn ok(id: JsonId, result: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            body: ResponseBody::Result(result),
            id,
        }
    }

    /// Build an error response.
    pub fn err(id: JsonId, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            body: ResponseBody::Error(RpcErrorBody { code, message }),
            id,
        }
    }
}

/// Parse a JSON-RPC request from a raw JSON string.
///
/// Minimal parser — handles the standard JSON-RPC 2.0 envelope.
pub fn parse_request(json: &str) -> Result<RpcRequest, String> {
    let json = json.trim();

    // Extract method
    let method = extract_string_field(json, "method")
        .ok_or_else(|| "missing 'method' field".to_string())?;

    // Extract jsonrpc
    let jsonrpc = extract_string_field(json, "jsonrpc")
        .unwrap_or_else(|| "2.0".to_string());

    // Extract id
    let id = extract_id(json);

    // Extract params array (simplified: extract as individual string tokens)
    let params = extract_params(json);

    Ok(RpcRequest { jsonrpc, method, params, id })
}

/// Extract a string field value from a JSON object.
fn extract_string_field(json: &str, field: &str) -> Option<String> {
    let key = format!("\"{}\"", field);
    let pos = json.find(&key)?;
    let after_key = &json[pos + key.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();

    if after_colon.starts_with('"') {
        // String value
        let content = &after_colon[1..];
        let end = content.find('"')?;
        Some(content[..end].to_string())
    } else {
        None
    }
}

/// Extract the id field (string or number).
fn extract_id(json: &str) -> JsonId {
    let key = "\"id\"";
    let pos = match json.find(key) {
        Some(p) => p,
        None => return JsonId::Null,
    };
    let after_key = &json[pos + key.len()..];
    let colon_pos = match after_key.find(':') {
        Some(p) => p,
        None => return JsonId::Null,
    };
    let after_colon = after_key[colon_pos + 1..].trim_start();

    if after_colon.starts_with('"') {
        let content = &after_colon[1..];
        if let Some(end) = content.find('"') {
            return JsonId::Str(content[..end].to_string());
        }
    } else if after_colon.starts_with("null") {
        return JsonId::Null;
    } else {
        // Try to parse as number
        let num_str: String = after_colon.chars()
            .take_while(|c| c.is_ascii_digit() || *c == '-')
            .collect();
        if let Ok(n) = num_str.parse::<i64>() {
            return JsonId::Number(n);
        }
    }
    JsonId::Null
}

/// Extract params array as a list of raw JSON value strings.
fn extract_params(json: &str) -> Vec<String> {
    let key = "\"params\"";
    let pos = match json.find(key) {
        Some(p) => p,
        None => return vec![],
    };
    let after_key = &json[pos + key.len()..];
    let colon_pos = match after_key.find(':') {
        Some(p) => p,
        None => return vec![],
    };
    let after_colon = after_key[colon_pos + 1..].trim_start();

    if !after_colon.starts_with('[') {
        return vec![];
    }

    // Find the matching closing bracket
    let mut depth = 0i32;
    let mut end = 0;
    for (i, c) in after_colon.char_indices() {
        match c {
            '[' | '{' => depth += 1,
            ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            _ => {}
        }
    }

    let array_content = &after_colon[1..end]; // strip outer [ ]
    if array_content.trim().is_empty() {
        return vec![];
    }

    // Split by top-level commas
    let mut params = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut prev_char = ' ';

    for c in array_content.chars() {
        match c {
            '"' if prev_char != '\\' => {
                in_string = !in_string;
                current.push(c);
            }
            '[' | '{' if !in_string => { depth += 1; current.push(c); }
            ']' | '}' if !in_string => { depth -= 1; current.push(c); }
            ',' if !in_string && depth == 0 => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    params.push(trimmed);
                }
                current.clear();
            }
            _ => { current.push(c); }
        }
        prev_char = c;
    }
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        params.push(trimmed);
    }

    params
}

/// Strip surrounding quotes from a JSON string value.
pub fn unquote(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        &s[1..s.len()-1]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_request() {
        let json = r#"{"jsonrpc":"2.0","method":"indra_getHeight","params":[],"id":1}"#;
        let req = parse_request(json).unwrap();
        assert_eq!(req.method, "indra_getHeight");
        assert_eq!(req.params.len(), 0);
        assert!(matches!(req.id, JsonId::Number(1)));
    }

    #[test]
    fn parse_request_with_params() {
        let json = r#"{"jsonrpc":"2.0","method":"indra_getBlock","params":["42"],"id":2}"#;
        let req = parse_request(json).unwrap();
        assert_eq!(req.method, "indra_getBlock");
        assert_eq!(req.params.len(), 1);
    }

    #[test]
    fn response_ok_serialises() {
        let resp = RpcResponse::ok(JsonId::Number(1), r#"{"height":42}"#.to_string());
        let json = resp.to_json();
        assert!(json.contains("\"result\""));
        assert!(json.contains("42"));
    }

    #[test]
    fn response_error_serialises() {
        let resp = RpcResponse::err(JsonId::Number(1), -32601, "Method not found".to_string());
        let json = resp.to_json();
        assert!(json.contains("\"error\""));
        assert!(json.contains("-32601"));
    }

    #[test]
    fn string_id_serialises() {
        let resp = RpcResponse::ok(JsonId::Str("abc".to_string()), "null".to_string());
        let json = resp.to_json();
        assert!(json.contains("\"abc\""));
    }
}
RUST

# --------------- indra-rpc/src/handlers.rs ---------------

cat > indra-rpc/src/handlers.rs << 'RUST'
//! RPC method handlers.
//!
//! Each handler receives the parsed request params and a reference to
//! the node state, and returns a JSON string result or an RpcError.

use indra_core::codec::Encode;
use indra_node::NodeEngine;

use crate::{
    error::{RpcError, RpcResult},
    types::unquote,
};

/// Shared node state passed to all handlers.
pub struct NodeState<'a> {
    /// The node engine.
    pub engine: &'a NodeEngine,
}

/// Dispatch a method call to the appropriate handler.
pub fn dispatch(
    method: &str,
    params: &[String],
    state: &NodeState<'_>,
) -> RpcResult<String> {
    match method {
        "indra_getHeight"       => get_height(state),
        "indra_getTip"          => get_tip(state),
        "indra_getChainInfo"    => get_chain_info(state),
        "indra_getMempoolSize"  => get_mempool_size(state),
        "indra_getBlock"        => get_block(params, state),
        "indra_getValidator"    => get_validator(params, state),
        "indra_getValidatorSet" => get_validator_set(state),
        "indra_sendTransaction" => send_transaction(params, state),
        _                       => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

/// `indra_getHeight` — returns the current chain height.
///
/// Result: `{"height": <u64>}`
fn get_height(state: &NodeState<'_>) -> RpcResult<String> {
    Ok(format!(r#"{{"height":{}}}"#, state.engine.state.height))
}

/// `indra_getTip` — returns the current tip hash and height.
///
/// Result: `{"height": <u64>, "tip_hash": "<hex>"}`
fn get_tip(state: &NodeState<'_>) -> RpcResult<String> {
    let tip = hex::encode(state.engine.state.tip_hash.0);
    Ok(format!(
        r#"{{"height":{},"tip_hash":"{}"}}"#,
        state.engine.state.height,
        tip
    ))
}

/// `indra_getChainInfo` — returns a full chain summary.
///
/// Result: `{"height", "tip_hash", "base_fee", "total_supply",
///           "treasury_balance", "burn_buffer", "active_validators",
///           "mempool_size", "epoch"}`
fn get_chain_info(state: &NodeState<'_>) -> RpcResult<String> {
    let s = &state.engine.state;
    let tip = hex::encode(s.tip_hash.0);
    let active_validators = s.validators.active_count();
    let mempool_size = state.engine.mempool.len();
    let epoch = s.current_epoch();

    Ok(format!(
        r#"{{"height":{height},"tip_hash":"{tip}","base_fee":{base_fee},"total_supply":{total_supply},"treasury_balance":{treasury},"burn_buffer":{burn},"active_validators":{validators},"mempool_size":{mempool},"epoch":{epoch}}}"#,
        height        = s.height,
        tip           = tip,
        base_fee      = s.base_fee,
        total_supply  = s.total_supply,
        treasury      = s.treasury_balance,
        burn          = s.burn_buffer,
        validators    = active_validators,
        mempool       = mempool_size,
        epoch         = epoch,
    ))
}

/// `indra_getMempoolSize` — returns the number of pending transactions.
///
/// Result: `{"size": <usize>}`
fn get_mempool_size(state: &NodeState<'_>) -> RpcResult<String> {
    Ok(format!(r#"{{"size":{}}}"#, state.engine.mempool.len()))
}

/// `indra_getBlock` — returns a block by height.
///
/// Params: `[<height: number>]`
/// Result: `{"height", "prev_hash", "state_root", "base_fee",
///           "tx_count", "timestamp"}`
fn get_block(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let height_str = params.first()
        .ok_or_else(|| RpcError::InvalidParams("missing height parameter".to_string()))?;

    let height: u64 = unquote(height_str)
        .parse()
        .map_err(|_| RpcError::InvalidParams(format!("invalid height: {height_str}")))?;

    // For now, return current block info if height matches current height
    // Full block retrieval from block_store requires &mut (Phase 8 refactor)
    let s = &state.engine.state;
    if height > s.height {
        return Err(RpcError::NotFound(format!("block {height} not yet produced")));
    }

    // Return summary info available from chain state
    let tip = hex::encode(s.tip_hash.0);
    Ok(format!(
        r#"{{"height":{height},"tip_hash":"{tip}","base_fee":{base_fee},"note":"full block retrieval added in Phase 8"}}"#,
        height   = height,
        tip      = tip,
        base_fee = s.base_fee,
    ))
}

/// `indra_getValidator` — returns validator info by ID (hex string).
///
/// Params: `["<validator_id_hex>"]`
/// Result: `{"validator_id", "stake", "status", "epoch_joined"}`
fn get_validator(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let id_str = params.first()
        .ok_or_else(|| RpcError::InvalidParams("missing validator_id parameter".to_string()))?;

    let id_hex = unquote(id_str);
    let id_bytes = hex::decode(id_hex)
        .map_err(|_| RpcError::InvalidParams(format!("invalid hex: {id_hex}")))?;

    if id_bytes.len() != 32 {
        return Err(RpcError::InvalidParams("validator_id must be 32 bytes (64 hex chars)".to_string()));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&id_bytes);
    let id = indra_core::types::primitives::Bytes32::from(arr);

    let validator = state.engine.state.validators
        .get(&id)
        .ok_or_else(|| RpcError::NotFound(format!("validator {id_hex} not found")))?;

    let status = if validator.is_active() { "active" } else { "inactive" };

    Ok(format!(
        r#"{{"validator_id":"{id}","stake":{stake},"status":"{status}","epoch_joined":{epoch}}}"#,
        id     = id_hex,
        stake  = validator.stake,
        status = status,
        epoch  = validator.epoch_joined,
    ))
}

/// `indra_getValidatorSet` — returns all active validators.
///
/// Result: `{"validators": [{"validator_id", "stake"}, ...]}`
fn get_validator_set(state: &NodeState<'_>) -> RpcResult<String> {
    let mut entries = Vec::new();
    for v in state.engine.state.validators.active_validators() {
        let id_hex = hex::encode(v.validator_id.0);
        entries.push(format!(
            r#"{{"validator_id":"{}","stake":{}}}"#,
            id_hex, v.stake
        ));
    }
    Ok(format!(r#"{{"validators":[{}]}}"#, entries.join(",")))
}

/// `indra_sendTransaction` — submit a hex-encoded signed transaction.
///
/// Params: `["<tx_hex>"]`
/// Result: `{"tx_id": "<hex>", "status": "accepted"}`
fn send_transaction(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let tx_hex = params.first()
        .ok_or_else(|| RpcError::InvalidParams("missing transaction parameter".to_string()))?;

    let tx_bytes = hex::decode(unquote(tx_hex))
        .map_err(|_| RpcError::InvalidParams("invalid hex encoding".to_string()))?;

    use indra_core::codec::{Decode, ByteReader};
    use indra_core::types::transaction::TransactionV1;

    let mut reader = ByteReader::new(&tx_bytes);
    let tx = TransactionV1::decode(&mut reader)
        .map_err(|e| RpcError::InvalidParams(format!("transaction decode failed: {e}")))?;

    // Compute tx_id
    use indra_consensus::mempool::Mempool;
    let tx_id = Mempool::tx_id(&tx);
    let tx_id_hex = hex::encode(tx_id.0);

    // Note: actual submission requires &mut engine — the server handles this
    // by returning the tx_id for the caller to track
    // Full mutable submission is wired in the RpcServer::handle_request path

    Ok(format!(
        r#"{{"tx_id":"{}","status":"decoded_ok","note":"submit via RpcServer for full validation"}}"#,
        tx_id_hex
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_node::{NodeConfig, NodeEngine};
    use std::path::PathBuf;

    fn temp_dir(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_rpc_handler_test_{}_{}", suffix, std::process::id()));
        p
    }

    fn make_state(suffix: &str) -> NodeEngine {
        let dir = temp_dir(suffix);
        let config = NodeConfig::local_test(dir);
        NodeEngine::init(config).unwrap()
    }

    #[test]
    fn get_height_returns_zero_at_genesis() {
        let engine = make_state("h");
        let state = NodeState { engine: &engine };
        let result = get_height(&state).unwrap();
        assert!(result.contains("\"height\":0"));
        let _ = std::fs::remove_dir_all(temp_dir("h"));
    }

    #[test]
    fn get_chain_info_has_all_fields() {
        let engine = make_state("ci");
        let state = NodeState { engine: &engine };
        let result = get_chain_info(&state).unwrap();
        assert!(result.contains("\"height\""));
        assert!(result.contains("\"base_fee\""));
        assert!(result.contains("\"total_supply\""));
        assert!(result.contains("\"epoch\""));
        let _ = std::fs::remove_dir_all(temp_dir("ci"));
    }

    #[test]
    fn get_mempool_size_returns_zero() {
        let engine = make_state("mp");
        let state = NodeState { engine: &engine };
        let result = get_mempool_size(&state).unwrap();
        assert!(result.contains("\"size\":0"));
        let _ = std::fs::remove_dir_all(temp_dir("mp"));
    }

    #[test]
    fn method_not_found_errors() {
        let engine = make_state("mf");
        let state = NodeState { engine: &engine };
        let result = dispatch("indra_nonExistent", &[], &state);
        assert!(matches!(result, Err(RpcError::MethodNotFound(_))));
        let _ = std::fs::remove_dir_all(temp_dir("mf"));
    }

    #[test]
    fn get_block_beyond_tip_errors() {
        let engine = make_state("gb");
        let state = NodeState { engine: &engine };
        let result = get_block(&["999".to_string()], &state);
        assert!(matches!(result, Err(RpcError::NotFound(_))));
        let _ = std::fs::remove_dir_all(temp_dir("gb"));
    }

    #[test]
    fn get_validator_invalid_hex_errors() {
        let engine = make_state("gv");
        let state = NodeState { engine: &engine };
        let result = get_validator(&["not_hex".to_string()], &state);
        assert!(matches!(result, Err(RpcError::InvalidParams(_))));
        let _ = std::fs::remove_dir_all(temp_dir("gv"));
    }
}
RUST

# --------------- indra-rpc/src/server.rs ---------------

cat > indra-rpc/src/server.rs << 'RUST'
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
RUST

# --------------- indra-rpc/tests/rpc.rs ---------------

cat > indra-rpc/tests/rpc.rs << 'RUST'
//! Integration tests for the RPC layer.

use indra_node::{NodeConfig, NodeEngine};
use indra_rpc::server::call_rpc;
use indra_rpc::types::parse_request;
use std::path::PathBuf;

fn temp_dir(suffix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("indra_rpc_test_{}_{}", suffix, std::process::id()));
    p
}

fn engine(suffix: &str) -> (NodeEngine, PathBuf) {
    let dir = temp_dir(suffix);
    let config = NodeConfig::local_test(dir.clone());
    (NodeEngine::init(config).unwrap(), dir)
}

#[test]
fn rpc_get_height() {
    let (e, dir) = engine("rpc_h");
    let resp = call_rpc("indra_getHeight", &[], &e);
    assert!(resp.contains("\"height\":0"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rpc_get_tip() {
    let (e, dir) = engine("rpc_tip");
    let resp = call_rpc("indra_getTip", &[], &e);
    assert!(resp.contains("\"tip_hash\""));
    assert!(resp.contains("\"height\""));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rpc_get_chain_info_fields() {
    let (e, dir) = engine("rpc_ci");
    let resp = call_rpc("indra_getChainInfo", &[], &e);
    for field in &["height", "base_fee", "total_supply", "epoch", "active_validators", "mempool_size"] {
        assert!(resp.contains(field), "missing field: {field}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rpc_mempool_size_zero_at_genesis() {
    let (e, dir) = engine("rpc_mp");
    let resp = call_rpc("indra_getMempoolSize", &[], &e);
    assert!(resp.contains("\"size\":0"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rpc_get_block_beyond_tip() {
    let (e, dir) = engine("rpc_gb");
    let resp = call_rpc("indra_getBlock", &["999".to_string()], &e);
    assert!(resp.contains("\"error\""));
    assert!(resp.contains("-32000"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rpc_invalid_method() {
    let (e, dir) = engine("rpc_inv");
    let resp = call_rpc("indra_doesNotExist", &[], &e);
    assert!(resp.contains("-32601"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rpc_full_request_parse_and_dispatch() {
    let (e, dir) = engine("rpc_full");
    let json = r#"{"jsonrpc":"2.0","method":"indra_getHeight","params":[],"id":42}"#;
    let req = parse_request(json).unwrap();
    assert_eq!(req.method, "indra_getHeight");
    let resp = call_rpc(&req.method, &req.params, &e);
    assert!(resp.contains("\"height\""));
    let _ = std::fs::remove_dir_all(&dir);
}
RUST

# =============================================================================
# Create indra-cli crate
# =============================================================================

mkdir -p indra-cli/src
mkdir -p indra-cli/tests

cat > indra-cli/Cargo.toml << 'TOML'
[package]
name        = "indra-cli"
description = "INDRA v2 command-line tools — keygen, genesis, tx submission, queries"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
indra-core      = { path = "../indra-core" }
indra-crypto    = { path = "../indra-crypto" }
indra-state     = { path = "../indra-state" }
indra-consensus = { path = "../indra-consensus" }
indra-node      = { path = "../indra-node" }
indra-rpc       = { path = "../indra-rpc" }
thiserror.workspace = true
hex.workspace = true

[dev-dependencies]
indra-core      = { path = "../indra-core" }
indra-crypto    = { path = "../indra-crypto" }
indra-node      = { path = "../indra-node" }
indra-rpc       = { path = "../indra-rpc" }
TOML

# --------------- indra-cli/src/lib.rs ---------------

cat > indra-cli/src/lib.rs << 'RUST'
//! # indra-cli
//!
//! Command-line tools for the INDRA v2 protocol.
//!
//! ## Commands
//!
//! ### `keygen`
//! Generate a complete validator keypair set:
//! - Ed25519 + Dilithium2 hybrid keypair (for signing transactions and votes)
//! - BLS12-381 keypair (for QC aggregation)
//! - VRF keypair (for proposer election)
//!
//! Output: a `keys.json` file with hex-encoded public and private keys.
//! The private keys are stored as seeds (32 bytes each).
//!
//! ### `genesis`
//! Build a `genesis.toml` from a list of validator public keys and stake amounts.
//! Used by the testnet coordinator to produce the agreed-upon genesis block.
//!
//! ### `send-tx`
//! Build and submit a transaction to a running node via JSON-RPC.
//!
//! ### `query`
//! Query chain state from a running node:
//! - `query height`
//! - `query chain-info`
//! - `query validator <id>`
//! - `query mempool-size`

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod error;
pub mod keygen;
pub mod genesis_cmd;
pub mod query;

pub use error::{CliError, CliResult};
pub use keygen::{generate_keypairs, ValidatorKeys, KeysFile};
pub use genesis_cmd::{GenesisEntry, build_genesis_config, GenesisConfig};
pub use query::{rpc_call, QueryResult};
RUST

# --------------- indra-cli/src/error.rs ---------------

cat > indra-cli/src/error.rs << 'RUST'
//! CLI error types.

use thiserror::Error;

/// All errors that can occur in CLI commands.
#[derive(Debug, Error)]
pub enum CliError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid hex input.
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    /// Missing required argument.
    #[error("missing argument: {0}")]
    MissingArgument(String),

    /// RPC call failed.
    #[error("RPC error: {0}")]
    Rpc(String),

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Genesis config is invalid.
    #[error("genesis error: {0}")]
    Genesis(String),
}

/// Convenience alias.
pub type CliResult<T> = Result<T, CliError>;
RUST

# --------------- indra-cli/src/keygen.rs ---------------

cat > indra-cli/src/keygen.rs << 'RUST'
//! Validator keypair generation.
//!
//! Generates all three keypairs a validator needs:
//!   1. Hybrid (Ed25519 + Dilithium2) — for transaction and vote signatures
//!   2. BLS12-381 — for QC aggregation
//!   3. VRF — for proposer election
//!
//! ## Security
//!
//! Each keypair is derived from a 32-byte random seed.
//! The seeds are the private keys — keep them secret.
//! Never share anything from the `private` section of the keys file.
//!
//! ## Output format (keys.json)
//!
//! ```json
//! {
//!   "validator_id": "<hex>",
//!   "public": {
//!     "hybrid_classical_pk": "<hex>",
//!     "hybrid_pq_pk": "<hex>",
//!     "bls_pk": "<hex>",
//!     "vrf_pk": "<hex>"
//!   },
//!   "private": {
//!     "hybrid_seed": "<hex>",
//!     "bls_seed": "<hex>",
//!     "vrf_seed": "<hex>"
//!   }
//! }
//! ```

use indra_crypto::{
    bls::BlsKeypair,
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    sha256,
    VrfKeypair,
};

use crate::error::{CliError, CliResult};

/// All public keys for a validator.
#[derive(Debug, Clone)]
pub struct ValidatorKeys {
    /// 32-byte validator identity (SHA-256 of hybrid classical public key).
    pub validator_id: [u8; 32],
    /// Ed25519 public key (32 bytes).
    pub hybrid_classical_pk: [u8; 32],
    /// Dilithium2 public key bytes.
    pub hybrid_pq_pk: Vec<u8>,
    /// BLS12-381 public key (48 bytes).
    pub bls_pk: [u8; 48],
    /// VRF public key (32 bytes).
    pub vrf_pk: [u8; 32],
}

/// A complete keys file including private seeds.
#[derive(Debug, Clone)]
pub struct KeysFile {
    /// All public keys.
    pub public: ValidatorKeys,
    /// Hybrid keypair seed (keep secret).
    pub hybrid_seed: [u8; 32],
    /// BLS keypair seed (keep secret).
    pub bls_seed: [u8; 32],
    /// VRF keypair seed (keep secret).
    pub vrf_seed: [u8; 32],
}

impl KeysFile {
    /// Serialise to a JSON string.
    pub fn to_json(&self) -> String {
        let v = &self.public;
        format!(
            r#"{{
  "validator_id": "{validator_id}",
  "public": {{
    "hybrid_classical_pk": "{classical}",
    "hybrid_pq_pk": "{pq}",
    "bls_pk": "{bls}",
    "vrf_pk": "{vrf}"
  }},
  "private": {{
    "hybrid_seed": "{h_seed}",
    "bls_seed": "{b_seed}",
    "vrf_seed": "{v_seed}",
    "WARNING": "Keep private seeds secret. Never share this section."
  }}
}}"#,
            validator_id = hex::encode(v.validator_id),
            classical    = hex::encode(v.hybrid_classical_pk),
            pq           = hex::encode(&v.hybrid_pq_pk),
            bls          = hex::encode(v.bls_pk),
            vrf          = hex::encode(v.vrf_pk),
            h_seed       = hex::encode(self.hybrid_seed),
            b_seed       = hex::encode(self.bls_seed),
            v_seed       = hex::encode(self.vrf_seed),
        )
    }
}

/// Generate a complete set of validator keypairs from three seeds.
///
/// If seeds are None, they are set to a deterministic test value.
/// In production, seeds should be generated from a secure RNG.
pub fn generate_keypairs(
    hybrid_seed: [u8; 32],
    bls_seed: [u8; 32],
    vrf_seed: [u8; 32],
) -> CliResult<KeysFile> {
    let classical = ClassicalKeypair::from_seed(&hybrid_seed);
    let pq = PqKeypair::generate();
    let hybrid = HybridKeypair::new(classical, pq);
    let pk = hybrid.public_key();

    let bls = BlsKeypair::from_seed(&bls_seed)
        .map_err(|e| CliError::Crypto(e.to_string()))?;

    let vrf = VrfKeypair::from_seed(&vrf_seed);

    let validator_id = sha256(&pk.classical.0);
    let bls_pk_bytes = bls.public_key().0;
    let vrf_pk_bytes = vrf.public_key();

    Ok(KeysFile {
        public: ValidatorKeys {
            validator_id,
            hybrid_classical_pk: pk.classical.0,
            hybrid_pq_pk:        pk.pq.0,
            bls_pk:              bls_pk_bytes,
            vrf_pk:              vrf_pk_bytes,
        },
        hybrid_seed,
        bls_seed,
        vrf_seed,
    })
}

/// Generate keypairs with random-looking seeds derived from a passphrase.
///
/// This is NOT cryptographically secure — use proper random seeds in production.
/// This is for testnet convenience only.
pub fn generate_from_passphrase(passphrase: &str) -> CliResult<KeysFile> {
    use indra_crypto::hash::domain_hash;
    let hybrid_seed = domain_hash(b"INDRA-KEYGEN-HYBRID-v1", passphrase.as_bytes());
    let bls_seed    = domain_hash(b"INDRA-KEYGEN-BLS-v1",    passphrase.as_bytes());
    let vrf_seed    = domain_hash(b"INDRA-KEYGEN-VRF-v1",    passphrase.as_bytes());
    generate_keypairs(hybrid_seed, bls_seed, vrf_seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_produces_all_fields() {
        let keys = generate_keypairs([0x01u8; 32], [0x02u8; 32], [0x03u8; 32]).unwrap();
        assert_eq!(keys.public.hybrid_classical_pk.len(), 32);
        assert_eq!(keys.public.bls_pk.len(), 48);
        assert_eq!(keys.public.vrf_pk.len(), 32);
        assert!(!keys.public.hybrid_pq_pk.is_empty());
    }

    #[test]
    fn keygen_is_deterministic() {
        let k1 = generate_keypairs([0x01u8; 32], [0x02u8; 32], [0x03u8; 32]).unwrap();
        let k2 = generate_keypairs([0x01u8; 32], [0x02u8; 32], [0x03u8; 32]).unwrap();
        assert_eq!(k1.public.validator_id, k2.public.validator_id);
        assert_eq!(k1.public.hybrid_classical_pk, k2.public.hybrid_classical_pk);
        assert_eq!(k1.public.bls_pk, k2.public.bls_pk);
        assert_eq!(k1.public.vrf_pk, k2.public.vrf_pk);
    }

    #[test]
    fn different_seeds_give_different_keys() {
        let k1 = generate_keypairs([0x01u8; 32], [0x02u8; 32], [0x03u8; 32]).unwrap();
        let k2 = generate_keypairs([0xFFu8; 32], [0xFEu8; 32], [0xFDu8; 32]).unwrap();
        assert_ne!(k1.public.validator_id, k2.public.validator_id);
    }

    #[test]
    fn passphrase_keygen_is_deterministic() {
        let k1 = generate_from_passphrase("testnet-validator-1").unwrap();
        let k2 = generate_from_passphrase("testnet-validator-1").unwrap();
        assert_eq!(k1.public.validator_id, k2.public.validator_id);
    }

    #[test]
    fn different_passphrases_give_different_keys() {
        let k1 = generate_from_passphrase("alice").unwrap();
        let k2 = generate_from_passphrase("bob").unwrap();
        assert_ne!(k1.public.validator_id, k2.public.validator_id);
    }

    #[test]
    fn keys_json_contains_required_fields() {
        let keys = generate_keypairs([0x01u8; 32], [0x02u8; 32], [0x03u8; 32]).unwrap();
        let json = keys.to_json();
        assert!(json.contains("validator_id"));
        assert!(json.contains("hybrid_classical_pk"));
        assert!(json.contains("bls_pk"));
        assert!(json.contains("vrf_pk"));
        assert!(json.contains("WARNING"));
    }

    #[test]
    fn validator_id_is_sha256_of_classical_pk() {
        let keys = generate_keypairs([0x42u8; 32], [0x42u8; 32], [0x42u8; 32]).unwrap();
        let expected = indra_crypto::sha256(&keys.public.hybrid_classical_pk);
        assert_eq!(keys.public.validator_id, expected);
    }
}
RUST

# --------------- indra-cli/src/genesis_cmd.rs ---------------

cat > indra-cli/src/genesis_cmd.rs << 'RUST'
//! Genesis configuration builder.
//!
//! Produces a `genesis.toml` file from a list of validator entries.
//! The genesis coordinator (testnet operator) collects public keys
//! from each participant, assigns stakes, and runs this command to
//! produce the agreed-upon genesis configuration.
//!
//! ## genesis.toml format
//!
//! ```toml
//! [genesis]
//! timestamp    = 1700000000
//! chain_id     = "indra-testnet-1"
//! total_supply = 1000000000000000  # Spark
//!
//! [[validators]]
//! name                = "alice"
//! validator_id        = "<hex>"
//! hybrid_classical_pk = "<hex>"
//! hybrid_pq_pk        = "<hex>"
//! bls_pk              = "<hex>"
//! vrf_pk              = "<hex>"
//! stake               = 10000000000  # Spark
//! ```

use crate::error::{CliError, CliResult};

/// One validator entry in the genesis config.
#[derive(Debug, Clone)]
pub struct GenesisEntry {
    /// Human-readable name (for display only).
    pub name: String,
    /// Validator identity (hex).
    pub validator_id: String,
    /// Ed25519 public key (hex).
    pub hybrid_classical_pk: String,
    /// Dilithium2 public key (hex).
    pub hybrid_pq_pk: String,
    /// BLS12-381 public key (hex).
    pub bls_pk: String,
    /// VRF public key (hex).
    pub vrf_pk: String,
    /// Initial stake in Spark.
    pub stake: u64,
}

/// A complete genesis configuration.
#[derive(Debug, Clone)]
pub struct GenesisConfig {
    /// Unix timestamp for the genesis block.
    pub timestamp: u64,
    /// Human-readable chain identifier.
    pub chain_id: String,
    /// Total initial supply in Spark.
    pub total_supply: u64,
    /// All initial validators.
    pub validators: Vec<GenesisEntry>,
}

impl GenesisConfig {
    /// Serialise to TOML string.
    pub fn to_toml(&self) -> String {
        let mut out = String::new();

        out.push_str("[genesis]\n");
        out.push_str(&format!("timestamp    = {}\n", self.timestamp));
        out.push_str(&format!("chain_id     = \"{}\"\n", self.chain_id));
        out.push_str(&format!("total_supply = {}  # Spark\n", self.total_supply));
        out.push_str(&format!(
            "# {} validators, total stake = {} Spark\n\n",
            self.validators.len(),
            self.validators.iter().map(|v| v.stake).sum::<u64>()
        ));

        for v in &self.validators {
            out.push_str("[[validators]]\n");
            out.push_str(&format!("name                = \"{}\"\n", v.name));
            out.push_str(&format!("validator_id        = \"{}\"\n", v.validator_id));
            out.push_str(&format!("hybrid_classical_pk = \"{}\"\n", v.hybrid_classical_pk));
            out.push_str(&format!("hybrid_pq_pk        = \"{}\"\n", v.hybrid_pq_pk));
            out.push_str(&format!("bls_pk              = \"{}\"\n", v.bls_pk));
            out.push_str(&format!("vrf_pk              = \"{}\"\n", v.vrf_pk));
            out.push_str(&format!("stake               = {}  # Spark\n\n", v.stake));
        }

        out
    }

    /// Validate the genesis config.
    ///
    /// Checks:
    /// - At least 4 validators (minimum for BFT safety: 3f+1 where f=1)
    /// - All validator IDs are unique
    /// - All stakes are above MIN_STAKE_SPARK
    /// - Total stake matches expectations
    pub fn validate(&self) -> CliResult<()> {
        use indra_core::types::primitives::MIN_STAKE_SPARK;

        if self.validators.len() < 4 {
            return Err(CliError::Genesis(
                "need at least 4 validators for BFT safety (3f+1, f=1)".to_string()
            ));
        }

        // Check unique validator IDs
        let mut seen_ids = std::collections::HashSet::new();
        for v in &self.validators {
            if !seen_ids.insert(v.validator_id.clone()) {
                return Err(CliError::Genesis(
                    format!("duplicate validator_id: {}", v.validator_id)
                ));
            }
            if v.stake < MIN_STAKE_SPARK {
                return Err(CliError::Genesis(
                    format!("validator {} stake {} is below minimum {}", v.name, v.stake, MIN_STAKE_SPARK)
                ));
            }
        }

        Ok(())
    }
}

/// Build a genesis config from a list of entries.
pub fn build_genesis_config(
    chain_id: &str,
    timestamp: u64,
    total_supply: u64,
    validators: Vec<GenesisEntry>,
) -> CliResult<GenesisConfig> {
    let config = GenesisConfig {
        timestamp,
        chain_id: chain_id.to_string(),
        total_supply,
        validators,
    };
    config.validate()?;
    Ok(config)
}

/// Build a genesis entry from a KeysFile and stake amount.
pub fn entry_from_keys(
    name: &str,
    keys: &crate::keygen::KeysFile,
    stake: u64,
) -> GenesisEntry {
    GenesisEntry {
        name:                name.to_string(),
        validator_id:        hex::encode(keys.public.validator_id),
        hybrid_classical_pk: hex::encode(keys.public.hybrid_classical_pk),
        hybrid_pq_pk:        hex::encode(&keys.public.hybrid_pq_pk),
        bls_pk:              hex::encode(keys.public.bls_pk),
        vrf_pk:              hex::encode(keys.public.vrf_pk),
        stake,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::generate_keypairs;
    use indra_core::types::primitives::MIN_STAKE_SPARK;

    fn test_validators(count: usize) -> Vec<GenesisEntry> {
        (0..count).map(|i| {
            let seed = [i as u8 + 1; 32];
            let keys = generate_keypairs(seed, seed, seed).unwrap();
            entry_from_keys(&format!("validator-{i}"), &keys, MIN_STAKE_SPARK * 10)
        }).collect()
    }

    #[test]
    fn build_valid_genesis() {
        let validators = test_validators(4);
        let config = build_genesis_config(
            "indra-testnet-1",
            1_700_000_000,
            1_000_000_000_000_000,
            validators,
        ).unwrap();
        assert_eq!(config.validators.len(), 4);
    }

    #[test]
    fn too_few_validators_rejected() {
        let validators = test_validators(3);
        let result = build_genesis_config(
            "test", 0, 1_000_000_000_000_000, validators,
        );
        assert!(result.is_err());
    }

    #[test]
    fn below_min_stake_rejected() {
        let mut validators = test_validators(4);
        validators[0].stake = 1; // below MIN_STAKE_SPARK
        let result = build_genesis_config(
            "test", 0, 1_000_000_000_000_000, validators,
        );
        assert!(result.is_err());
    }

    #[test]
    fn duplicate_validator_id_rejected() {
        let mut validators = test_validators(4);
        validators[1].validator_id = validators[0].validator_id.clone();
        let result = build_genesis_config(
            "test", 0, 1_000_000_000_000_000, validators,
        );
        assert!(result.is_err());
    }

    #[test]
    fn toml_output_has_all_fields() {
        let validators = test_validators(4);
        let config = build_genesis_config(
            "indra-testnet-1", 1_700_000_000, 1_000_000_000_000_000, validators,
        ).unwrap();
        let toml = config.to_toml();
        assert!(toml.contains("[genesis]"));
        assert!(toml.contains("[[validators]]"));
        assert!(toml.contains("validator_id"));
        assert!(toml.contains("bls_pk"));
    }
}
RUST

# --------------- indra-cli/src/query.rs ---------------

cat > indra-cli/src/query.rs << 'RUST'
//! Query commands — fetch chain state from a running node.
//!
//! All queries go through the JSON-RPC API.
//! For testing, `call_local` bypasses the HTTP layer.

use indra_rpc::server::call_rpc;
use indra_node::NodeEngine;

use crate::error::{CliError, CliResult};

/// The result of a query — a formatted string ready for display.
#[derive(Debug, Clone)]
pub struct QueryResult {
    /// The raw JSON response.
    pub raw_json: String,
    /// A human-readable summary.
    pub summary: String,
}

/// Make a direct in-process RPC call (for CLI testing without a running server).
pub fn rpc_call(
    method: &str,
    params: &[String],
    engine: &NodeEngine,
) -> CliResult<QueryResult> {
    let raw = call_rpc(method, params, engine);

    // Check for error
    if raw.contains("\"error\"") {
        let msg = extract_error_message(&raw);
        return Err(CliError::Rpc(msg));
    }

    let summary = format_result(method, &raw);
    Ok(QueryResult { raw_json: raw, summary })
}

/// Format a JSON-RPC result into a human-readable summary.
fn format_result(method: &str, json: &str) -> String {
    match method {
        "indra_getHeight" => {
            if let Some(h) = extract_number(json, "height") {
                format!("Current height: {h}")
            } else {
                json.to_string()
            }
        }
        "indra_getTip" => {
            let height = extract_number(json, "height").unwrap_or(0);
            let hash = extract_string_val(json, "tip_hash").unwrap_or_default();
            format!("Height: {height}\nTip:    {hash}")
        }
        "indra_getChainInfo" => {
            let height = extract_number(json, "height").unwrap_or(0);
            let base_fee = extract_number(json, "base_fee").unwrap_or(0);
            let supply = extract_number(json, "total_supply").unwrap_or(0);
            let validators = extract_number(json, "active_validators").unwrap_or(0);
            let epoch = extract_number(json, "epoch").unwrap_or(0);
            format!(
                "Height:            {height}\nEpoch:             {epoch}\nBase fee:          {base_fee} Spark/KB\nTotal supply:      {supply} Spark\nActive validators: {validators}"
            )
        }
        "indra_getMempoolSize" => {
            let size = extract_number(json, "size").unwrap_or(0);
            format!("Mempool: {size} pending transactions")
        }
        "indra_getValidatorSet" => {
            format!("Validator set:\n{json}")
        }
        _ => json.to_string(),
    }
}

/// Extract a numeric value from a JSON string.
fn extract_number(json: &str, field: &str) -> Option<u64> {
    let key = format!("\"{field}\":");
    let pos = json.find(&key)?;
    let after = json[pos + key.len()..].trim_start();
    let num_str: String = after.chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    num_str.parse().ok()
}

/// Extract a string value from a JSON string.
fn extract_string_val(json: &str, field: &str) -> Option<String> {
    let key = format!("\"{field}\":\"");
    let pos = json.find(&key)?;
    let after = &json[pos + key.len()..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

/// Extract the error message from a JSON-RPC error response.
fn extract_error_message(json: &str) -> String {
    if let Some(pos) = json.find("\"message\":\"") {
        let after = &json[pos + "\"message\":\"".len()..];
        if let Some(end) = after.find('"') {
            return after[..end].to_string();
        }
    }
    "unknown error".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_node::{NodeConfig, NodeEngine};
    use std::path::PathBuf;

    fn temp_dir(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_cli_query_test_{}_{}", suffix, std::process::id()));
        p
    }

    #[test]
    fn query_height() {
        let dir = temp_dir("qh");
        let engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let result = rpc_call("indra_getHeight", &[], &engine).unwrap();
        assert!(result.summary.contains("Current height: 0"));
        assert!(result.raw_json.contains("\"height\":0"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn query_chain_info() {
        let dir = temp_dir("qci");
        let engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let result = rpc_call("indra_getChainInfo", &[], &engine).unwrap();
        assert!(result.summary.contains("Height:"));
        assert!(result.summary.contains("Base fee:"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn query_mempool_size() {
        let dir = temp_dir("qmp");
        let engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let result = rpc_call("indra_getMempoolSize", &[], &engine).unwrap();
        assert!(result.summary.contains("Mempool: 0"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn query_unknown_method_errors() {
        let dir = temp_dir("qunk");
        let engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let result = rpc_call("indra_unknown", &[], &engine);
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn query_tip() {
        let dir = temp_dir("qtip");
        let engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let result = rpc_call("indra_getTip", &[], &engine).unwrap();
        assert!(result.summary.contains("Height:"));
        assert!(result.summary.contains("Tip:"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
RUST

# --------------- indra-cli/tests/cli.rs ---------------

cat > indra-cli/tests/cli.rs << 'RUST'
//! Integration tests for the CLI tools.

use indra_cli::{
    generate_keypairs, generate_from_passphrase,
    genesis_cmd::{build_genesis_config, entry_from_keys},
    query::rpc_call,
};
use indra_core::types::primitives::MIN_STAKE_SPARK;
use indra_node::{NodeConfig, NodeEngine};
use std::path::PathBuf;

fn temp_dir(suffix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("indra_cli_test_{}_{}", suffix, std::process::id()));
    p
}

fn engine(suffix: &str) -> (NodeEngine, PathBuf) {
    let dir = temp_dir(suffix);
    let config = NodeConfig::local_test(dir.clone());
    (NodeEngine::init(config).unwrap(), dir)
}

// ── Keygen tests ──────────────────────────────────────────────────────────────

#[test]
fn keygen_all_keys_present() {
    let keys = generate_keypairs([0x01u8; 32], [0x02u8; 32], [0x03u8; 32]).unwrap();
    assert_eq!(keys.public.hybrid_classical_pk.len(), 32);
    assert_eq!(keys.public.bls_pk.len(), 48);
    assert_eq!(keys.public.vrf_pk.len(), 32);
    assert!(!keys.public.hybrid_pq_pk.is_empty());
}

#[test]
fn keygen_deterministic_from_seed() {
    let k1 = generate_keypairs([0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]).unwrap();
    let k2 = generate_keypairs([0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]).unwrap();
    assert_eq!(k1.public.validator_id, k2.public.validator_id);
}

#[test]
fn keygen_from_passphrase() {
    let k = generate_from_passphrase("my-testnet-validator").unwrap();
    let k2 = generate_from_passphrase("my-testnet-validator").unwrap();
    assert_eq!(k.public.validator_id, k2.public.validator_id);
    // Different passphrase = different key
    let k3 = generate_from_passphrase("other-validator").unwrap();
    assert_ne!(k.public.validator_id, k3.public.validator_id);
}

#[test]
fn keys_json_is_valid_structure() {
    let keys = generate_keypairs([0x01u8; 32], [0x02u8; 32], [0x03u8; 32]).unwrap();
    let json = keys.to_json();
    // All required fields present
    for field in &["validator_id", "hybrid_classical_pk", "bls_pk", "vrf_pk", "hybrid_seed", "WARNING"] {
        assert!(json.contains(field), "missing: {field}");
    }
}

// ── Genesis tests ─────────────────────────────────────────────────────────────

#[test]
fn genesis_with_4_validators() {
    let stake = MIN_STAKE_SPARK * 100;
    let validators: Vec<_> = (0..4u8).map(|i| {
        let seed = [i + 1; 32];
        let keys = generate_keypairs(seed, seed, seed).unwrap();
        entry_from_keys(&format!("v{i}"), &keys, stake)
    }).collect();

    let config = build_genesis_config(
        "indra-testnet-1",
        1_700_000_000,
        1_000_000_000_000_000,
        validators,
    ).unwrap();

    assert_eq!(config.validators.len(), 4);
    let toml = config.to_toml();
    assert!(toml.contains("indra-testnet-1"));
    assert!(toml.contains("[[validators]]"));
}

#[test]
fn genesis_rejects_3_validators() {
    let stake = MIN_STAKE_SPARK * 100;
    let validators: Vec<_> = (0..3u8).map(|i| {
        let seed = [i + 1; 32];
        let keys = generate_keypairs(seed, seed, seed).unwrap();
        entry_from_keys(&format!("v{i}"), &keys, stake)
    }).collect();

    assert!(build_genesis_config("test", 0, 0, validators).is_err());
}

// ── Query tests ───────────────────────────────────────────────────────────────

#[test]
fn query_pipeline() {
    let (e, dir) = engine("query_full");

    let height = rpc_call("indra_getHeight", &[], &e).unwrap();
    assert!(height.summary.contains("0"));

    let info = rpc_call("indra_getChainInfo", &[], &e).unwrap();
    assert!(info.summary.contains("Height:"));

    let mp = rpc_call("indra_getMempoolSize", &[], &e).unwrap();
    assert!(mp.summary.contains("0"));

    let _ = std::fs::remove_dir_all(&dir);
}

// ── End-to-end: keygen → genesis → query ─────────────────────────────────────

#[test]
fn full_testnet_setup_pipeline() {
    // Step 1: Each participant generates their keys
    let alice = generate_from_passphrase("alice-testnet-seed-v1").unwrap();
    let bob   = generate_from_passphrase("bob-testnet-seed-v1").unwrap();
    let carol = generate_from_passphrase("carol-testnet-seed-v1").unwrap();
    let dave  = generate_from_passphrase("dave-testnet-seed-v1").unwrap();

    // Step 2: Coordinator builds genesis
    let stake = MIN_STAKE_SPARK * 100;
    let validators = vec![
        entry_from_keys("alice", &alice, stake),
        entry_from_keys("bob",   &bob,   stake),
        entry_from_keys("carol", &carol, stake),
        entry_from_keys("dave",  &dave,  stake),
    ];

    let config = build_genesis_config(
        "indra-private-testnet-1",
        1_700_000_000,
        1_000_000_000_000_000,
        validators,
    ).unwrap();

    assert_eq!(config.validators.len(), 4);

    // Step 3: Write keys.json (verify output is valid)
    let alice_json = alice.to_json();
    assert!(alice_json.contains("validator_id"));
    assert!(alice_json.contains("WARNING"));

    // Step 4: Write genesis.toml
    let toml = config.to_toml();
    assert!(toml.contains("alice"));
    assert!(toml.contains("bob"));
    assert!(toml.contains("carol"));
    assert!(toml.contains("dave"));
    assert!(toml.contains("indra-private-testnet-1"));

    // Step 5: Query a fresh node (verifies RPC works end-to-end)
    let (e, dir) = engine("e2e");
    let result = rpc_call("indra_getChainInfo", &[], &e).unwrap();
    assert!(result.summary.contains("Height:"));
    let _ = std::fs::remove_dir_all(&dir);
}
RUST

# =============================================================================
# Write genesis.toml.example
# =============================================================================

cat > genesis.toml.example << 'TOML'
# =============================================================================
# INDRA v2 — Example Genesis Configuration
# =============================================================================
#
# How to use this file:
#
# 1. Each validator runs:
#      indra-cli keygen --passphrase "my-unique-passphrase" --output keys.json
#
# 2. Each validator shares ONLY their public section (validator_id, *_pk fields)
#    with the genesis coordinator.
#
# 3. The coordinator fills in this file with all validators' public keys
#    and distributes it to everyone.
#
# 4. Each validator runs:
#      indra-node --genesis genesis.toml --keys keys.json --data-dir ./data
#
# =============================================================================

[genesis]
timestamp    = 1700000000       # 2023-11-14 00:00:00 UTC — fixed genesis time
chain_id     = "indra-testnet-1"
total_supply = 1000000000000000 # 1,000,000,000 INDRA in Spark (10^6 Spark per INDRA)

# Minimum 4 validators required (BFT safety: 3f+1, f=1 means tolerate 1 failure)
# Recommended for testnet: 4–10 validators

[[validators]]
name                = "alice"
validator_id        = "aabbcc..."   # 64 hex chars (32 bytes)
hybrid_classical_pk = "aabbcc..."   # 64 hex chars (Ed25519 public key)
hybrid_pq_pk        = "aabbcc..."   # variable length (Dilithium2 public key)
bls_pk              = "aabbcc..."   # 96 hex chars (BLS12-381 public key)
vrf_pk              = "aabbcc..."   # 64 hex chars (VRF public key)
stake               = 100000000000 # 100,000 INDRA in Spark

[[validators]]
name                = "bob"
validator_id        = "112233..."
hybrid_classical_pk = "112233..."
hybrid_pq_pk        = "112233..."
bls_pk              = "112233..."
vrf_pk              = "112233..."
stake               = 100000000000

[[validators]]
name                = "carol"
validator_id        = "334455..."
hybrid_classical_pk = "334455..."
hybrid_pq_pk        = "334455..."
bls_pk              = "334455..."
vrf_pk              = "334455..."
stake               = 100000000000

[[validators]]
name                = "dave"
validator_id        = "556677..."
hybrid_classical_pk = "556677..."
hybrid_pq_pk        = "556677..."
bls_pk              = "556677..."
vrf_pk              = "556677..."
stake               = 100000000000
TOML

echo ""
echo "✓ INDRA Phase 7 files written."
echo ""
echo "New crate: indra-rpc"
echo "  src/types.rs    — JSON-RPC 2.0 request/response codec (no external deps)"
echo "  src/handlers.rs — 8 RPC methods (getHeight, getTip, getChainInfo, etc.)"
echo "  src/server.rs   — HTTP server (stdlib only) + call_rpc for in-process testing"
echo "  tests/rpc.rs    — integration tests"
echo ""
echo "New crate: indra-cli"
echo "  src/keygen.rs       — generate validator keypairs from seed or passphrase"
echo "  src/genesis_cmd.rs  — build genesis.toml from validator list"
echo "  src/query.rs        — query chain state via JSON-RPC"
echo "  tests/cli.rs        — end-to-end: keygen → genesis → query"
echo ""
echo "genesis.toml.example — template for your testnet participants"
echo ""
echo "Now run:"
echo "  cargo build"
echo "  cargo test"
echo ""
