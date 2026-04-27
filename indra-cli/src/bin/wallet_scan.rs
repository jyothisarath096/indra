//! Wallet scan — discover UTXOs owned by this keypair from the chain.
//!
//! Calls indra_getUtxos RPC to find UTXOs, then the user provides
//! the blinding factors to reconstruct spendable wallet entries.
//!
//! ## Usage
//!
//! For genesis UTXOs (initial allocation), the blinding factor is
//! derived deterministically from the validator seed.
//!
//! indra-wallet-scan --keys keys.json --wallet wallet.json \
//!                   --node http://127.0.0.1:8545

use std::io::{Read, Write};
use std::net::TcpStream;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let get = |flag: &str| -> Option<String> {
        args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
    };

    let keys_path   = get("--keys").unwrap_or_else(|| "keys.json".to_string());
    let wallet_path = get("--wallet").unwrap_or_else(|| "wallet.json".to_string());
    let node_url    = get("--node").unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let add_utxo    = get("--add-utxo"); // manual: --add-utxo <utxo_id>:<value>:<blinding>

    println!("INDRA Wallet Scanner");
    println!("─────────────────────────────────────────");
    println!("Keys:   {}", keys_path);
    println!("Wallet: {}", wallet_path);
    println!("Node:   {}", node_url);
    println!("─────────────────────────────────────────");

    // Load keys
    let keys_str = std::fs::read_to_string(&keys_path).unwrap_or_else(|e| {
        eprintln!("Error reading keys: {}", e);
        std::process::exit(1);
    });
    let hybrid_seed = extract_hex32(&keys_str, "hybrid_seed");

    // Derive classical pubkey
    use indra_crypto::hybrid::ClassicalKeypair;
    let classical = ClassicalKeypair::from_seed(&hybrid_seed);
    let pubkey_hex = hex::encode(classical.public_key().0);

    println!("Scanning for UTXOs owned by: {}...", &pubkey_hex[..16]);

    // Load existing wallet
    let mut wallet = indra_cli::Wallet::load(&wallet_path).unwrap_or_else(|e| {
        eprintln!("Warning: could not load wallet ({}), starting fresh", e);
        indra_cli::Wallet::new()
    });

    println!("Existing wallet balance: {} Spark", wallet.balance());

    // Handle manual UTXO addition (for genesis or known UTXOs)
    if let Some(utxo_spec) = add_utxo {
        // Format: <utxo_id_hex>:<value_spark>:<blinding_hex>:<height>:<tx_idx>:<out_idx>
        let parts: Vec<&str> = utxo_spec.splitn(6, ':').collect();
        if parts.len() < 3 {
            eprintln!("Error: --add-utxo format: <utxo_id>:<value_spark>:<blinding_hex>[:<height>:<tx_idx>:<out_idx>]");
            std::process::exit(1);
        }

        let utxo_id_bytes = hex::decode(parts[0]).unwrap_or_else(|_| {
            eprintln!("Error: bad utxo_id hex");
            std::process::exit(1);
        });
        let value: u64 = parts[1].parse().unwrap_or_else(|_| {
            eprintln!("Error: bad value");
            std::process::exit(1);
        });
        let blinding_bytes = hex::decode(parts[2]).unwrap_or_else(|_| {
            eprintln!("Error: bad blinding hex");
            std::process::exit(1);
        });

        if utxo_id_bytes.len() != 32 || blinding_bytes.len() != 32 {
            eprintln!("Error: utxo_id and blinding must be 32 bytes each");
            std::process::exit(1);
        }

        let height: u64  = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
        let tx_idx: u32  = parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
        let out_idx: u32 = parts.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);

        let mut id_arr  = [0u8; 32];
        let mut bl_arr  = [0u8; 32];
        id_arr.copy_from_slice(&utxo_id_bytes);
        bl_arr.copy_from_slice(&blinding_bytes);

        use indra_core::types::primitives::Bytes32;
        let utxo_id = Bytes32::from(id_arr);

        wallet.add_utxo(utxo_id, value, bl_arr, height, tx_idx, out_idx);
        wallet.save(&wallet_path).unwrap_or_else(|e| {
            eprintln!("Error saving wallet: {}", e);
            std::process::exit(1);
        });

        println!("Added UTXO: {} ({} Spark)", parts[0], value);
        println!("New balance: {} Spark ({:.6} INDRA)",
            wallet.balance(), wallet.balance() as f64 / 1_000_000.0);
        return;
    }

    // Query node for UTXOs
    println!("\nQuerying node for UTXOs...");
    match query_utxos(&node_url, &pubkey_hex) {
        Ok(response) => {
            println!("Node response: {}", response);
            println!("\nNote: UTXO values are confidential (Pedersen commitments).");
            println!("To add a known UTXO to your wallet use:");
            println!("  indra-wallet-scan --keys keys.json --wallet wallet.json \\");
            println!("    --add-utxo <utxo_id>:<value_spark>:<blinding_hex>");
            println!("\nFor genesis validators, your initial UTXO blinding is:");
            let genesis_blinding = derive_genesis_blinding(&hybrid_seed);
            println!("  {}", hex::encode(genesis_blinding));
        }
        Err(e) => {
            eprintln!("Error querying node: {}", e);
        }
    }

    println!("\nCurrent wallet balance: {} Spark ({:.6} INDRA)",
        wallet.balance(), wallet.balance() as f64 / 1_000_000.0);
}

/// Query the node for UTXOs owned by a pubkey.
fn query_utxos(node_url: &str, pubkey_hex: &str) -> Result<String, String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"indra_getUtxos","params":["{}"],"id":1}}"#,
        pubkey_hex
    );
    http_post(node_url, &body)
}

/// Make a simple HTTP POST request.
fn http_post(url: &str, body: &str) -> Result<String, String> {
    let url = url.trim_start_matches("http://");
    let (host, path) = if let Some(pos) = url.find('/') {
        (&url[..pos], &url[pos..])
    } else {
        (url, "/")
    };

    let mut stream = TcpStream::connect(host)
        .map_err(|e| format!("cannot connect to {}: {}", host, e))?;

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host, body.len(), body
    );

    stream.write_all(request.as_bytes())
        .map_err(|e| format!("write error: {}", e))?;

    let mut response = String::new();
    stream.read_to_string(&mut response)
        .map_err(|e| format!("read error: {}", e))?;

    if let Some(pos) = response.find("\r\n\r\n") {
        Ok(response[pos + 4..].to_string())
    } else {
        Ok(response)
    }
}

/// Derive the genesis blinding factor for this validator's initial stake UTXO.
/// This is deterministic from the hybrid seed.
fn derive_genesis_blinding(hybrid_seed: &[u8; 32]) -> [u8; 32] {
    indra_crypto::sha256(&[hybrid_seed.as_slice(), b"genesis-utxo-blinding"].concat())
}

fn extract_hex32(json: &str, field: &str) -> [u8; 32] {
    let key = format!("\"{}\":", field);
    let pos = match json.find(&key) {
        Some(p) => p,
        None => { eprintln!("Field '{}' not found in keys.json", field); std::process::exit(1); }
    };
    let after = &json[pos + key.len()..];
    let start = after.find('"').unwrap_or(0) + 1;
    let end   = after[start..].find('"').unwrap_or(0) + start;
    let bytes = hex::decode(&after[start..end]).unwrap_or_else(|_| {
        eprintln!("Invalid hex for '{}'", field);
        std::process::exit(1);
    });
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    arr
}
