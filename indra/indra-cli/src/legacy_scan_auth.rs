//! Temporary authorization helpers for legacy OutputV1 UTXO scans.
//!
//! This is deliberately not a view-key system. It builds a short-lived
//! ownership proof by signing a node-provided challenge with the address's
//! hybrid spend key.

use indra_crypto::sha256;

use crate::{
    error::{CliError, CliResult},
    keygen::KeysFile,
    staking::{http_post, reconstruct_keypair},
};

/// Versioned scan-authorization proof material for legacy OutputV1 scans.
///
/// Version 1 contains only the signed-challenge ownership proof needed by the
/// temporary RPC hardening. Future OutputV2 view-key material is intentionally
/// not populated here; that protocol remains deferred pending external review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanAuthFileV1 {
    /// File/proof version. Must be `1`.
    pub version: u8,
    /// Requested legacy address, hex-encoded.
    pub address: String,
    /// Node-provided challenge, hex-encoded.
    pub challenge: String,
    /// Reserved for future OutputV2 material; always empty in v1.
    pub reserved_output_v2: Option<String>,
}

impl ScanAuthFileV1 {
    /// Render the public metadata portion as JSON for diagnostics or storage.
    pub fn to_json(&self) -> String {
        let reserved = self
            .reserved_output_v2
            .as_ref()
            .map(|value| format!(r#""{}""#, json_escape(value)))
            .unwrap_or_else(|| "null".to_string());
        format!(
            r#"{{"version":{},"address":"{}","challenge":"{}","reserved_output_v2":{}}}"#,
            self.version,
            json_escape(&self.address),
            json_escape(&self.challenge),
            reserved
        )
    }
}

/// Build an authenticated legacy scan proof JSON object for `address_hex`.
pub fn build_legacy_scan_auth_proof(
    node_url: &str,
    keys: &KeysFile,
    address_hex: &str,
) -> CliResult<String> {
    let address = decode_hex32(address_hex, "address")?;
    if sha256(&keys.public.hybrid_classical_pk) != address {
        return Err(CliError::Transaction(
            "keys.json does not own the requested legacy scan address".into(),
        ));
    }
    let challenge_hex = fetch_legacy_scan_challenge(node_url, address_hex)?;
    let challenge = decode_hex32(&challenge_hex, "challenge")?;
    let msg = indra_rpc::handlers::legacy_scan_auth_message(address, challenge);
    let keypair = reconstruct_keypair(keys)?;
    let sig = keypair
        .sign(&msg)
        .map_err(|e| CliError::Crypto(e.to_string()))?;

    let _format = ScanAuthFileV1 {
        version: 1,
        address: address_hex.to_string(),
        challenge: challenge_hex.clone(),
        reserved_output_v2: None,
    };

    Ok(format!(
        r#"{{"version":1,"challenge":"{}","hybrid_classical_pk":"{}","hybrid_pq_pk":"{}","classical_sig":"{}","pq_sig":"{}","reserved_output_v2":null}}"#,
        challenge_hex,
        hex::encode(keys.public.hybrid_classical_pk),
        hex::encode(&keys.public.hybrid_pq_pk),
        hex::encode(sig.classical.0),
        hex::encode(sig.pq.0)
    ))
}

/// Fetch the node-provided legacy scan challenge for `address_hex`.
pub fn fetch_legacy_scan_challenge(node_url: &str, address_hex: &str) -> CliResult<String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"indra_getLegacyScanChallenge","params":["{}"],"id":1}}"#,
        json_escape(address_hex)
    );
    let response = http_post(node_url, &body)?;
    if let Some(message) = rpc_error_message(&response) {
        return Err(CliError::Rpc(message));
    }
    parse_string_json_field(&response, "challenge")
        .ok_or_else(|| CliError::Rpc("cannot parse legacy scan challenge".into()))
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
    let after = json[pos + key.len()..].trim_start();
    let after = after.strip_prefix('"')?;
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

fn decode_hex32(value: &str, name: &str) -> CliResult<[u8; 32]> {
    let bytes =
        hex::decode(value).map_err(|_| CliError::Parse(format!("{name} must be 32-byte hex")))?;
    if bytes.len() != 32 {
        return Err(CliError::Parse(format!("{name} must be 32-byte hex")));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_auth_file_v1_is_versioned_and_reserves_output_v2_slot() {
        let file = ScanAuthFileV1 {
            version: 1,
            address: "aa".repeat(32),
            challenge: "bb".repeat(32),
            reserved_output_v2: None,
        };
        let json = file.to_json();
        assert!(json.contains(r#""version":1"#));
        assert!(json.contains(r#""reserved_output_v2":null"#));
    }
}
