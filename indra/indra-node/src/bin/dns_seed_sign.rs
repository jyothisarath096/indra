#![deny(unused_must_use)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! Sign INDRA DNS discovery node lists with ML-DSA-87.
//!
//! This helper is intentionally separate from Cloudflare publishing. The DNS
//! API credential can live in the Python publisher process, while the signing
//! seed can live behind an operator-controlled wrapper or restricted file.

use std::{env, fs, net::SocketAddr, process};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use indra_crypto::PqKeypair;
use indra_node::discovery::build_signed_dns_seed_records;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let mut seq = None;
    let mut addrs = Vec::new();
    let mut seed_file = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seq" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--seq requires a value".to_string())?;
                seq = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| "--seq must be an integer".to_string())?,
                );
            }
            "--addr" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--addr requires a value".to_string())?;
                addrs.push(
                    value
                        .parse::<SocketAddr>()
                        .map_err(|_| format!("invalid socket address {value:?}"))?,
                );
            }
            "--pq-seed-file" => {
                seed_file = Some(
                    args.next()
                        .ok_or_else(|| "--pq-seed-file requires a path".to_string())?,
                );
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    let seq = seq.ok_or_else(|| "--seq is required".to_string())?;
    if addrs.is_empty() {
        return Err("at least one --addr is required".to_string());
    }
    let path = seed_file.ok_or_else(|| "--pq-seed-file is required".to_string())?;
    reject_permissive_secret_file(&path)?;
    let seed_hex =
        fs::read_to_string(&path).map_err(|error| format!("failed to read {path}: {error}"))?;
    let seed = parse_seed(seed_hex.trim())?;
    let keypair = PqKeypair::from_seed(&seed)
        .map_err(|error| format!("failed to derive ML-DSA keypair: {error}"))?;
    let records = build_signed_dns_seed_records(addrs, seq, &keypair)?;

    let node_chunks = records
        .node_chunks
        .iter()
        .map(|(name, content)| serde_json::json!({ "name": name, "content": content }))
        .collect::<Vec<_>>();
    let sig_chunks = records
        .sig_chunks
        .iter()
        .map(|(name, content)| serde_json::json!({ "name": name, "content": content }))
        .collect::<Vec<_>>();
    let payload = serde_json::json!({
        "root_txt": records.root_txt,
        "node_chunks": node_chunks,
        "sig_chunks": sig_chunks,
        "public_key_hex": hex::encode(keypair.public_key().0),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&payload)
            .map_err(|error| format!("failed to encode signer output: {error}"))?
    );
    Ok(())
}

fn parse_seed(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|_| "ML-DSA seed must be hex".to_string())?;
    if bytes.len() != 32 {
        return Err(format!("ML-DSA seed must be 32 bytes, got {}", bytes.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

#[cfg(unix)]
fn reject_permissive_secret_file(path: &str) -> Result<(), String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("failed to inspect {path}: {error}"))?;
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "refusing to read signing seed file {path}: permissions must be 0600 or stricter"
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_permissive_secret_file(_path: &str) -> Result<(), String> {
    Ok(())
}

fn print_help() {
    println!(
        "usage: dns_seed_sign --pq-seed-file PATH --seq N --addr IP:PORT [--addr IP:PORT ...]"
    );
}
