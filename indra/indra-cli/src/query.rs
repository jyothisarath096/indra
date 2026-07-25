//! Query commands — fetch chain state from a running node.
//!
//! All queries go through the JSON-RPC API.
//! For testing, `call_local` bypasses the HTTP layer.

use indra_node::NodeEngine;
use indra_rpc::server::call_rpc;

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
pub fn rpc_call(method: &str, params: &[String], engine: &NodeEngine) -> CliResult<QueryResult> {
    let raw = call_rpc(method, params, engine);

    // Check for error
    if raw.contains("\"error\"") {
        let msg = extract_error_message(&raw);
        return Err(CliError::Rpc(msg));
    }

    let summary = format_result(method, &raw)?;
    Ok(QueryResult {
        raw_json: raw,
        summary,
    })
}

/// Format a JSON-RPC result into a human-readable summary.
fn format_result(method: &str, json: &str) -> CliResult<String> {
    match method {
        "indra_getHeight" => {
            if let Some(h) = extract_number(json, "height") {
                Ok(format!("Current height: {h}"))
            } else {
                Err(CliError::Parse(
                    "indra_getHeight response missing required height field".into(),
                ))
            }
        }
        "indra_getTip" => {
            let height = required_number(json, "height", "indra_getTip")?;
            let hash = required_string(json, "tip_hash", "indra_getTip")?;
            Ok(format!("Height: {height}\nTip:    {hash}"))
        }
        "indra_getChainInfo" => {
            let height = required_number(json, "height", "indra_getChainInfo")?;
            let base_fee = required_number(json, "base_fee", "indra_getChainInfo")?;
            let supply = required_number(json, "total_supply", "indra_getChainInfo")?;
            let fee_reward_pool = required_number(json, "fee_reward_pool", "indra_getChainInfo")?;
            let validators = required_number(json, "active_validators", "indra_getChainInfo")?;
            let epoch = required_number(json, "epoch", "indra_getChainInfo")?;
            let era = required_number(json, "era", "indra_getChainInfo")?;
            Ok(format!(
                "Height:            {height}\nEpoch:             {epoch}\nEra:               {era}\nBase fee:          {base_fee} Spark/KB\nTotal supply:      {supply} Spark\nFee reward pool:   {fee_reward_pool} Spark\nActive validators: {validators}"
            ))
        }
        "indra_getMempoolSize" => {
            let size = required_number(json, "size", "indra_getMempoolSize")?;
            Ok(format!("Mempool: {size} pending transactions"))
        }
        "indra_getValidatorSet" => Ok(format!("Validator set:\n{json}")),
        _ => Ok(json.to_string()),
    }
}

/// Extract a numeric value from a JSON string.
fn extract_number(json: &str, field: &str) -> Option<u64> {
    let key = format!("\"{field}\":");
    let pos = json.find(&key)?;
    let after = json[pos + key.len()..].trim_start();
    let num_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    num_str.parse().ok()
}

fn required_number(json: &str, field: &str, method: &str) -> CliResult<u64> {
    extract_number(json, field)
        .ok_or_else(|| CliError::Parse(format!("{method} response missing required {field} field")))
}

/// Extract a string value from a JSON string.
fn extract_string_val(json: &str, field: &str) -> Option<String> {
    let key = format!("\"{field}\":\"");
    let pos = json.find(&key)?;
    let after = &json[pos + key.len()..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

fn required_string(json: &str, field: &str, method: &str) -> CliResult<String> {
    extract_string_val(json, field)
        .ok_or_else(|| CliError::Parse(format!("{method} response missing required {field} field")))
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
        p.push(format!(
            "indra_cli_query_test_{}_{}",
            suffix,
            std::process::id()
        ));
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

    #[test]
    fn query_formatter_preserves_real_zero_values() {
        let summary = format_result(
            "indra_getChainInfo",
            r#"{"height":0,"base_fee":0,"total_supply":0,"fee_reward_pool":0,"active_validators":0,"epoch":0,"era":0}"#,
        )
        .unwrap();
        assert!(summary.contains("Height:            0"));
        assert!(summary.contains("Active validators: 0"));

        let mempool = format_result("indra_getMempoolSize", r#"{"size":0}"#).unwrap();
        assert_eq!(mempool, "Mempool: 0 pending transactions");
    }

    #[test]
    fn query_formatter_rejects_missing_required_fields() {
        let err = format_result("indra_getTip", r#"{"height":12}"#).unwrap_err();
        assert!(err.to_string().contains("tip_hash"), "{err}");

        let err = format_result(
            "indra_getChainInfo",
            r#"{"height":0,"base_fee":0,"total_supply":0}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("fee_reward_pool"), "{err}");

        let err = format_result("indra_getMempoolSize", r#"{"count":0}"#).unwrap_err();
        assert!(err.to_string().contains("size"), "{err}");
    }
}
