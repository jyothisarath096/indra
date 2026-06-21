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
    for field in &[
        "height",
        "base_fee",
        "total_supply",
        "epoch",
        "active_validators",
        "mempool_size",
    ] {
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
