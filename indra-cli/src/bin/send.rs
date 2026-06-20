//! `indra send` — build and submit a transaction to a running node.
//!
//! Usage:
//!   indra-send --keys keys.json --wallet wallet.json \
//!              --to <classical_pubkey_hex> \
//!              --amount <INDRA> \
//!              --fee <INDRA> \
//!              --node http://127.0.0.1:8545

use std::io::Write;

const SPARK_PER_INDRA_F64: f64 = 100_000_000.0;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let get = |flag: &str| -> Option<String> {
        args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
    };

    let keys_path   = get("--keys").unwrap_or_else(|| "keys.json".to_string());
    let wallet_path = get("--wallet").unwrap_or_else(|| "wallet.json".to_string());
    let to          = get("--to").unwrap_or_else(|| { eprintln!("Error: --to required"); std::process::exit(1); });
    let amount_str  = get("--amount").unwrap_or_else(|| { eprintln!("Error: --amount required"); std::process::exit(1); });
    let fee_str     = get("--fee").unwrap_or_else(|| "0.0001".to_string());
    let node_url    = get("--node").unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let chain_id    = get("--chain-id").unwrap_or_else(|| {
        indra_core::types::primitives::DEFAULT_CHAIN_ID.to_string()
    });

    // Parse amounts (accept INDRA as decimal, convert to Spark)
    let amount_indra: f64 = amount_str.parse().unwrap_or_else(|_| {
        eprintln!("Error: invalid amount '{}'", amount_str);
        std::process::exit(1);
    });
    let fee_indra: f64 = fee_str.parse().unwrap_or_else(|_| {
        eprintln!("Error: invalid fee '{}'", fee_str);
        std::process::exit(1);
    });

    let amount_spark = (amount_indra * SPARK_PER_INDRA_F64) as u64;
    let fee_spark    = (fee_indra   * SPARK_PER_INDRA_F64) as u64;
    let fee_spark    = fee_spark.max(indra_cli::tx_builder::MIN_FEE_SPARK);

    println!("INDRA Send");
    println!("──────────────────────────────────────");
    println!("Keys:    {}", keys_path);
    println!("Wallet:  {}", wallet_path);
    println!("To:      {}...", &to[..to.len().min(16)]);
    println!("Amount:  {} INDRA ({} Spark)", amount_indra, amount_spark);
    println!("Fee:     {} INDRA ({} Spark)", fee_indra, fee_spark);
    println!("Node:    {}", node_url);
    println!("──────────────────────────────────────");

    // Load keys
    let keys_str = std::fs::read_to_string(&keys_path).unwrap_or_else(|e| {
        eprintln!("Error reading keys: {}", e);
        std::process::exit(1);
    });
    let hybrid_seed = extract_hex32(&keys_str, "hybrid_seed");
    let pq_sk_bytes = extract_hex_field(&keys_str, "pq_sk");
    let pq_pk_bytes = extract_hex_field(&keys_str, "hybrid_pq_pk");

    // Derive sender pubkey from seed
    use indra_core::types::{primitives::{Bytes32, VariableBytes}, crypto::HybridPubKey};
    use indra_crypto::hybrid::ClassicalKeypair;
    let classical = ClassicalKeypair::from_seed(&hybrid_seed);
    let sender_pubkey = HybridPubKey {
        classical_pk: Bytes32::from(classical.public_key().0),
        pq_pk: VariableBytes::from_slice(&pq_pk_bytes).unwrap_or_else(|_| {
            VariableBytes::from_slice(&[0u8; 1312]).unwrap()
        }),
    };

    // Load wallet
    let wallet = indra_cli::Wallet::load(&wallet_path).unwrap_or_else(|e| {
        eprintln!("Error loading wallet: {}", e);
        std::process::exit(1);
    });

    println!(
        "Wallet balance: {} Spark ({:.8} INDRA)",
        wallet.balance(),
        wallet.balance() as f64 / SPARK_PER_INDRA_F64
    );

    if wallet.balance() == 0 {
        eprintln!("Error: wallet is empty. Add UTXOs first with 'indra-wallet scan'.");
        std::process::exit(1);
    }

    // Build transaction
    let params = indra_cli::tx_builder::TxParams {
        chain_id: &chain_id,
        recipient_pubkey_hex: &to,
        amount_spark,
        fee_spark,
        wallet: &wallet,
        hybrid_seed,
        pq_sk_bytes,
        sender_pubkey,
    };

    let built = indra_cli::build_transaction(&params).unwrap_or_else(|e| {
        eprintln!("Error building transaction: {}", e);
        std::process::exit(1);
    });

    println!("\nTransaction built:");
    println!("  TX ID:    {}", built.tx_id);
    println!(
        "  Change:   {} Spark ({:.8} INDRA)",
        built.change_spark,
        built.change_spark as f64 / SPARK_PER_INDRA_F64
    );
    println!("  Inputs:   {}", built.spent_utxo_ids.len());

    // Submit to node
    print!("\nSubmitting to {}... ", node_url);
    std::io::stdout().flush().ok();

    match submit_transaction(&node_url, &built.tx_hex) {
        Ok(response) => {
            println!("OK");

            // Check if node accepted or rejected
            if response.contains("\"error\"") {
                // Extract error message
                let msg = if let Some(start) = response.find("\"message\":\"") {
                    let after = &response[start + 11..];
                    let end = after.find('"').unwrap_or(after.len());
                    after[..end].to_string()
                } else {
                    response.clone()
                };
                eprintln!("Node rejected transaction: {}", msg);
                eprintln!("Wallet NOT updated — UTXO is still spendable.");
                std::process::exit(1);
            }

            // Accepted — mark inputs as spent
            let mut wallet = wallet;
            for id in &built.spent_utxo_ids {
                wallet.mark_spent(id);
            }
            wallet.save(&wallet_path).unwrap_or_else(|e| {
                eprintln!("Warning: could not save wallet: {}", e);
            });

            println!("\nDone. TX ID: {}", built.tx_id);
            println!("Transaction is in mempool. Wait for next block (~6 seconds).");
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Submit a hex-encoded transaction to the node via JSON-RPC.
fn submit_transaction(node_url: &str, tx_hex: &str) -> Result<String, String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"indra_sendTransaction","params":["{}"],"id":1}}"#,
        tx_hex
    );

    // Use std::net for HTTP — no external HTTP crate needed
    let url = node_url.trim_start_matches("http://");
    let (host, path) = if let Some(pos) = url.find('/') {
        (&url[..pos], &url[pos..])
    } else {
        (url, "/")
    };

    use std::io::{Read, Write};
    use std::net::TcpStream;

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

    // Extract body (after \r\n\r\n)
    if let Some(pos) = response.find("\r\n\r\n") {
        Ok(response[pos + 4..].to_string())
    } else {
        Ok(response)
    }
}

fn extract_hex_field(json: &str, field: &str) -> Vec<u8> {
    let key = format!("\"{}\":", field);
    let pos = match json.find(&key) {
        Some(p) => p,
        None => return vec![0u8; 1312],
    };
    let after = &json[pos + key.len()..];
    let start = after.find('"').unwrap_or(0) + 1;
    let end   = after[start..].find('"').unwrap_or(0) + start;
    hex::decode(&after[start..end]).unwrap_or_else(|_| vec![0u8; 1312])
}

fn extract_hex32(json: &str, field: &str) -> [u8; 32] {
    let key = format!("\"{}\":", field);
    let pos = json.find(&key)
        .unwrap_or_else(|| { eprintln!("Field '{}' not found in keys.json", field); std::process::exit(1); });
    let after = &json[pos + key.len()..];
    let start = after.find('"').unwrap() + 1;
    let end   = after[start..].find('"').unwrap() + start;
    let hex_str = &after[start..end];
    let bytes = hex::decode(hex_str)
        .unwrap_or_else(|_| { eprintln!("Invalid hex for '{}'", field); std::process::exit(1); });
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    arr
}
