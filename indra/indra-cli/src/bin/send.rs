//! `indra send` — build and submit a transaction to a running node.
//!
//! Usage:
//!   indra-send --keys keys.json --wallet wallet.json \
//!              [--keys-password-file keys.pass] \
//!              --to <canonical_payment_address> \
//!              --amount <INDRA> \
//!              --fee <INDRA> \
//!              --node http://127.0.0.1:8545

use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let get = |flag: &str| -> Option<String> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };

    let keys_path = get("--keys").unwrap_or_else(|| "keys.json".to_string());
    let wallet_path = get("--wallet").unwrap_or_else(|| "wallet.json".to_string());
    let to = get("--to").unwrap_or_else(|| {
        eprintln!("Error: --to required");
        std::process::exit(1);
    });
    let amount_str = get("--amount").unwrap_or_else(|| {
        eprintln!("Error: --amount required");
        std::process::exit(1);
    });
    let fee_str = get("--fee").unwrap_or_else(|| "0.0001".to_string());
    let node_url = get("--node").unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let chain_id = get("--chain-id")
        .unwrap_or_else(|| indra_core::types::primitives::DEFAULT_CHAIN_ID.to_string());

    let amount_spark = parse_amount_or_exit(&amount_str, "--amount");
    let fee_spark =
        parse_amount_or_exit(&fee_str, "--fee").max(indra_cli::tx_builder::MIN_FEE_SPARK);

    println!("INDRA Send");
    println!("──────────────────────────────────────");
    println!("Keys:    {}", keys_path);
    println!("Wallet:  {}", wallet_path);
    println!("To:      {}...", &to[..to.len().min(16)]);
    println!("Amount:  {} INDRA ({} Spark)", amount_str, amount_spark);
    println!("Fee:     {} INDRA ({} Spark)", fee_str, fee_spark);
    println!("Node:    {}", node_url);
    println!("──────────────────────────────────────");

    // Load keys through the shared canonical encrypted-keystore loader.
    let keys = indra_cli::load_keys_for_cli(&keys_path, &args).unwrap_or_else(|e| {
        eprintln!("Error loading keys: {}", e);
        std::process::exit(1);
    });
    let hybrid_seed = keys.hybrid_seed;
    let pq_sk_bytes = keys.pq_sk.clone();
    let pq_pk_bytes = keys.public.hybrid_pq_pk.clone();

    // Derive sender pubkey from seed
    use indra_core::types::{
        crypto::HybridPubKey,
        primitives::{Bytes32, VariableBytes},
    };
    let sender_pubkey = HybridPubKey {
        classical_pk: Bytes32::from(keys.public.hybrid_classical_pk),
        pq_pk: VariableBytes::from_slice(&pq_pk_bytes)
            .unwrap_or_else(|_| VariableBytes::from_slice(&[0u8; 2592]).unwrap()),
    };

    // Load wallet
    let wallet = indra_cli::Wallet::load(&wallet_path).unwrap_or_else(|e| {
        eprintln!("Error loading wallet: {}", e);
        std::process::exit(1);
    });

    println!(
        "Wallet balance: {} Spark ({:.8} INDRA)",
        wallet.balance(),
        wallet.balance() as f64 / (indra_cli::SPARK_PER_INDRA as f64)
    );

    if wallet.balance() == 0 {
        eprintln!("Error: wallet is empty. Add UTXOs first with 'indra-wallet scan'.");
        std::process::exit(1);
    }

    let sender_payment_pubkey = keys
        .payment_keypair
        .as_ref()
        .map(indra_crypto::PaymentKeypairV1::public_key)
        .unwrap_or_else(|| {
            eprintln!("Error: canonical keystore is missing payment key material");
            std::process::exit(1);
        });

    // Build transaction
    let params = indra_cli::tx_builder::TxParams {
        chain_id: &chain_id,
        recipient_address: &to,
        amount_spark,
        fee_spark,
        wallet: &wallet,
        hybrid_seed,
        pq_sk_bytes,
        sender_pubkey,
        sender_payment_pubkey,
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
        built.change_spark as f64 / (indra_cli::SPARK_PER_INDRA as f64)
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
            let pending_change_value = built
                .pending_change
                .as_ref()
                .map(|change| change.output.value_spark);
            wallet.record_accepted_transaction(&built.spent_utxo_ids, built.pending_change);
            if let Some(value_spark) = pending_change_value {
                eprintln!(
                    "[wallet] saved pending change output: {} Spark",
                    value_spark
                );
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

fn parse_amount_or_exit(raw: &str, flag: &str) -> u64 {
    parse_cli_indra_amount(raw, flag).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    })
}

fn parse_cli_indra_amount(raw: &str, flag: &str) -> indra_cli::CliResult<u64> {
    indra_cli::parse_indra_amount_to_spark(raw, flag)
}

/// Submit a hex-encoded transaction to the node via JSON-RPC.
fn submit_transaction(node_url: &str, tx_hex: &str) -> Result<String, String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"indra_sendTransaction","params":["{}"],"id":1}}"#,
        tx_hex
    );
    submit_raw_rpc(node_url, &body)
}

fn submit_raw_rpc(node_url: &str, body: &str) -> Result<String, String> {
    // Use std::net for HTTP — no external HTTP crate needed
    let url = node_url.trim_start_matches("http://");
    let (host, path) = if let Some(pos) = url.find('/') {
        (&url[..pos], &url[pos..])
    } else {
        (url, "/")
    };

    use std::io::{Read, Write};
    use std::net::TcpStream;

    let mut stream =
        TcpStream::connect(host).map_err(|e| format!("cannot connect to {}: {}", host, e))?;

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host, body.len(), body
    );

    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write error: {}", e))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("read error: {}", e))?;

    // Extract body (after \r\n\r\n)
    if let Some(pos) = response.find("\r\n\r\n") {
        Ok(response[pos + 4..].to_string())
    } else {
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_uses_shared_exact_indra_amount_parser() {
        assert_eq!(parse_cli_indra_amount("0.00000003", "--amount").unwrap(), 3);
        assert_eq!(
            parse_cli_indra_amount("10.5", "--amount").unwrap(),
            indra_cli::parse_indra_amount_to_spark("10.5", "--amount").unwrap()
        );
    }
}
