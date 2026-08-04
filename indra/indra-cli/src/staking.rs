//! Staking CLI helpers: key reconstruction, HTTP RPC, nonce fetch, and submission.

use std::{
    io::{Read, Write},
    net::TcpStream,
};

use indra_crypto::hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair};

pub use crate::tx_builder::{
    build_claim_rewards_op, build_delegate_op, build_exit_stake_position_op,
    build_register_validator_op, build_register_validator_op_with_cold, build_set_auto_delegate_op,
    build_set_commission_op, build_update_network_address_op, StakePositionExitSigner,
};
use crate::{
    error::{CliError, CliResult},
    keygen::KeysFile,
};

/// Reconstruct the hybrid signing keypair from a keys file.
pub fn reconstruct_keypair(keys: &KeysFile) -> CliResult<HybridKeypair> {
    let classical = ClassicalKeypair::from_seed(&keys.hybrid_seed);
    let pq = PqKeypair::from_bytes(&keys.public.hybrid_pq_pk, &keys.pq_sk)
        .map_err(|e| CliError::Crypto(e.to_string()))?;
    Ok(HybridKeypair::new(classical, pq))
}

/// Make a simple HTTP/1.1 JSON-RPC POST request.
pub fn http_post(url: &str, body: &str) -> CliResult<String> {
    let url = url.trim_start_matches("http://");
    let (host, path) = if let Some(pos) = url.find('/') {
        (&url[..pos], &url[pos..])
    } else {
        (url, "/")
    };

    let mut stream = TcpStream::connect(host)
        .map_err(|e| CliError::Rpc(format!("cannot connect to node: {}", e)))?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        host,
        body.len(),
        body
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| CliError::Rpc(format!("write error: {}", e)))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| CliError::Rpc(format!("read error: {}", e)))?;

    if let Some(pos) = response.find("\r\n\r\n") {
        Ok(response[pos + 4..].to_string())
    } else {
        Ok(response)
    }
}

/// Fetch the current staking nonce for a signer. The caller adds one.
pub fn fetch_staking_nonce(node_url: &str, signer_id_hex: &str) -> CliResult<u64> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"indra_getStakingNonce","params":["{}"],"id":1}}"#,
        signer_id_hex
    );
    let response = http_post(node_url, &body)?;
    if let Some(message) = rpc_error_message(&response) {
        return Err(CliError::Rpc(message));
    }
    parse_u64_json_field(&response, "current_nonce")
        .or_else(|| parse_u64_json_field(&response, "nonce"))
        .ok_or_else(|| CliError::Rpc("cannot parse nonce from response".into()))
}

/// Fetch the node's chain ID.
pub fn fetch_chain_id(node_url: &str) -> CliResult<String> {
    let body = r#"{"jsonrpc":"2.0","method":"indra_getChainInfo","params":[],"id":1}"#;
    let response = http_post(node_url, body)?;
    if let Some(message) = rpc_error_message(&response) {
        return Err(CliError::Rpc(message));
    }
    parse_string_json_field(&response, "chain_id")
        .ok_or_else(|| CliError::Rpc("cannot parse chain_id from response".into()))
}

/// Fetch the registered cold-key version and next cold-role nonce.
pub fn fetch_validator_cold_replay(node_url: &str, validator_id: &str) -> CliResult<(u64, u64)> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"indra_getValidator","params":["{}"],"id":1}}"#,
        validator_id
    );
    let response = http_post(node_url, &body)?;
    if let Some(message) = rpc_error_message(&response) {
        return Err(CliError::Rpc(message));
    }
    let version = parse_u64_json_field(&response, "cold_key_version")
        .ok_or_else(|| CliError::Rpc("cannot parse cold_key_version".into()))?;
    let current_nonce = parse_u64_json_field(&response, "cold_nonce")
        .ok_or_else(|| CliError::Rpc("cannot parse cold_nonce".into()))?;
    let next_nonce = current_nonce
        .checked_add(1)
        .ok_or_else(|| CliError::Rpc("cold nonce overflow".into()))?;
    if version == 0 {
        return Err(CliError::Rpc(
            "validator has no active cold-key version".into(),
        ));
    }
    Ok((version, next_nonce))
}

/// Submit a hex-encoded staking op to a node.
pub fn submit_staking_op(node_url: &str, op_hex: &str) -> CliResult<String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"indra_submitStakingOp","params":["{}"],"id":1}}"#,
        op_hex
    );
    let response = http_post(node_url, &body)?;
    if let Some(message) = rpc_error_message(&response) {
        return Err(CliError::Rpc(message));
    }
    Ok(response)
}

fn rpc_error_message(response: &str) -> Option<String> {
    if !response.contains("\"error\"") {
        return None;
    }
    parse_string_json_field(response, "message").or_else(|| Some(response.to_string()))
}

fn parse_u64_json_field(json: &str, field: &str) -> Option<u64> {
    let key = format!("\"{}\":", field);
    let pos = json.find(&key)?;
    let after = json[pos + key.len()..].trim_start();
    let value: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    value.parse().ok()
}

fn parse_string_json_field(json: &str, field: &str) -> Option<String> {
    let key = format!("\"{}\":", field);
    let pos = json.find(&key)?;
    let after = json[pos + key.len()..].trim_start();
    let after = after.strip_prefix('"')?;
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_from_master_seed;

    #[test]
    fn test_reconstruct_keypair_is_deterministic() {
        let keys = generate_from_master_seed("validator".to_string(), [0x11; 32]).unwrap();
        let a = reconstruct_keypair(&keys).unwrap().public_key();
        let b = reconstruct_keypair(&keys).unwrap().public_key();
        assert_eq!(a.classical.0, b.classical.0);
        assert_eq!(a.pq.0, b.pq.0);
    }

    #[test]
    fn test_reconstruct_keypair_from_known_seed() {
        let keys = generate_from_master_seed("validator".to_string(), [0x44; 32]).unwrap();
        let keypair = reconstruct_keypair(&keys).unwrap();
        assert_eq!(
            keypair.public_key().classical.0,
            keys.public.hybrid_classical_pk
        );
    }
}
