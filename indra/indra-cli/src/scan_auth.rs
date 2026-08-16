//! Canonical payment-address ownership authorization for metadata-bearing RPCs.

use crate::{
    error::{CliError, CliResult},
    keygen::KeysFile,
    staking::{fetch_chain_id, http_post, reconstruct_keypair},
};

/// One fresh, single-use payment-address authorization proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanAuthorization {
    /// Canonical chain-bound `PaymentAddressV1` text.
    pub payment_address: String,
    /// JSON proof containing the challenge and full hybrid signature.
    pub proof: String,
}

/// Fetch, sign, and return one fresh scan authorization.
pub fn build_scan_authorization(node_url: &str, keys: &KeysFile) -> CliResult<ScanAuthorization> {
    let chain_id = fetch_chain_id(node_url)?;
    let address = keys
        .payment_address(chain_id.as_bytes())
        .map_err(|error| CliError::Crypto(error.to_string()))?;
    let payment_address = address.to_text();
    let challenge_hex = fetch_scan_challenge(node_url, &payment_address)?;
    let challenge = decode_hex32(&challenge_hex, "challenge")?;
    let message = indra_rpc::handlers::scan_auth_message(&address, challenge);
    let signature = reconstruct_keypair(keys)?
        .sign(&message)
        .map_err(|error| CliError::Crypto(error.to_string()))?;
    Ok(ScanAuthorization {
        payment_address,
        proof: format!(
            r#"{{"version":1,"challenge":"{}","classical_sig":"{}","pq_sig":"{}"}}"#,
            challenge_hex,
            hex::encode(signature.classical.0),
            hex::encode(signature.pq.0),
        ),
    })
}

/// Fetch a random, expiring, single-use challenge for a canonical payment address.
pub fn fetch_scan_challenge(node_url: &str, payment_address: &str) -> CliResult<String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"indra_getScanChallenge","params":["{}"],"id":1}}"#,
        json_escape(payment_address)
    );
    let response = http_post(node_url, &body)?;
    if let Some(message) = rpc_error_message(&response) {
        return Err(CliError::Rpc(message));
    }
    parse_string_json_field(&response, "challenge")
        .ok_or_else(|| CliError::Rpc("cannot parse scan challenge".into()))
}

/// Make a JSON-RPC call with already-rendered JSON parameter values.
pub fn rpc_call_raw_params(
    node_url: &str,
    method: &str,
    raw_params: &[String],
) -> CliResult<String> {
    let params = raw_params.join(",");
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"{}","params":[{}],"id":1}}"#,
        json_escape(method),
        params
    );
    let response = http_post(node_url, &body)?;
    if let Some(message) = rpc_error_message(&response) {
        return Err(CliError::Rpc(message));
    }
    Ok(response)
}

/// Quote a string as a JSON string value.
pub fn json_string(value: &str) -> String {
    format!(r#""{}""#, json_escape(value))
}

/// Escape a string for this crate's small JSON builders.
pub fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

fn rpc_error_message(response: &str) -> Option<String> {
    if !response.contains("\"error\"") {
        return None;
    }
    parse_string_json_field(response, "message").or_else(|| Some(response.to_string()))
}

fn parse_string_json_field(json: &str, field: &str) -> Option<String> {
    let key = format!("\"{}\":", field);
    let pos = json.find(&key)?;
    let after = json[pos + key.len()..].trim_start().strip_prefix('"')?;
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

fn decode_hex32(value: &str, name: &str) -> CliResult<[u8; 32]> {
    let bytes =
        hex::decode(value).map_err(|_| CliError::Parse(format!("{name} must be 32-byte hex")))?;
    let mut out = [0u8; 32];
    if bytes.len() != out.len() {
        return Err(CliError::Parse(format!("{name} must be 32-byte hex")));
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}
