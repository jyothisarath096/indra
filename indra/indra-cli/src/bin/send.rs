#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! `indra send` — build and submit a transaction to a running node.
//!
//! Usage:
//!   indra-send --keys keys.json --wallet wallet.json \
//!              --chain-id <id> \
//!              [--keys-password-file keys.pass] \
//!              --to <canonical_payment_address> \
//!              --amount <INDRA> \
//!              --fee <INDRA> \
//!              --node http://127.0.0.1:8545 \
//!              [--rpc-token-file token.path]
//!
//! Cold mode replaces `--keys` with `--cold-keys` and accepts
//! `--cold-keys-password-file` or `--cold-keys-password-env`; `--genesis`
//! may be supplied to discover cold-owned genesis UTXOs from the manifest.

use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Err(error) = indra_cli::rpc_client::configure_from_args(&args) {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }

    let get = |flag: &str| -> Option<String> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };

    let chain_id = indra_cli::required_chain_id(&args).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(1);
    });

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
    let requested_fee_spark = get("--fee").map(|raw| parse_amount_or_exit(&raw, "--fee"));
    let node_url = get("--node").unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let genesis_path = get("--genesis");

    let amount_spark = parse_amount_or_exit(&amount_str, "--amount");
    let base_fee = indra_cli::fetch_base_fee(&node_url).unwrap_or_else(|error| {
        eprintln!("Error fetching current base fee: {error}");
        std::process::exit(1);
    });

    println!("INDRA Send");
    println!("──────────────────────────────────────");
    println!("Keys:    {}", keys_path);
    println!("Wallet:  {}", wallet_path);
    println!("To:      {}...", &to[..to.len().min(16)]);
    println!("Amount:  {} INDRA ({} Spark)", amount_str, amount_spark);
    println!("Base fee: {} Spark/KiB", base_fee);
    println!("Node:    {}", node_url);
    println!("──────────────────────────────────────");

    let cold_keys_path = get("--cold-keys");
    let cold_keys = cold_keys_path.as_ref().map(|path| {
        let source = indra_cli::cold_password_source_from_args(&args);
        indra_cli::load_cold_keys(path, source).unwrap_or_else(|e| {
            eprintln!("Error loading cold keys: {}", e);
            std::process::exit(1);
        })
    });
    let hot_keys = if cold_keys.is_none() {
        Some(
            indra_cli::load_keys_for_cli(&keys_path, &args).unwrap_or_else(|e| {
                eprintln!("Error loading keys: {}", e);
                std::process::exit(1);
            }),
        )
    } else {
        None
    };

    // Load wallet
    let mut wallet = indra_cli::Wallet::load(&wallet_path).unwrap_or_else(|e| {
        eprintln!("Error loading wallet: {}", e);
        std::process::exit(1);
    });

    let cold_keypair = cold_keys.as_ref().map(|cold_keys| {
        cold_keys.reconstruct().unwrap_or_else(|e| {
            eprintln!("Error reconstructing cold keys: {}", e);
            std::process::exit(1);
        })
    });
    let signer_owner = if let Some(cold_keypair) = cold_keypair.as_ref() {
        indra_cli::cold_hybrid_pubkey(cold_keypair).unwrap_or_else(|e| {
            eprintln!("Error: {e}");
            std::process::exit(1);
        })
    } else {
        let Some(keys) = hot_keys.as_ref() else {
            eprintln!("Error: hot keys required when --cold-keys is absent");
            std::process::exit(1);
        };
        indra_core::types::crypto::HybridPubKey {
            classical_pk: indra_core::types::primitives::Bytes32::from(
                keys.public.hybrid_classical_pk,
            ),
            pq_pk: indra_core::types::primitives::VariableBytes::from_slice(
                &keys.public.hybrid_pq_pk,
            )
            .unwrap_or_else(|_| {
                eprintln!("Error: invalid hot public key");
                std::process::exit(1);
            }),
        }
    };

    // Build transaction. Cold mode requires owner-tagged wallet entries, which
    // are produced by `indra-wallet-scan --cold-owner`.
    let (built, required_fee) = if let Some(cold_keypair) = cold_keypair.as_ref() {
        if let Some(genesis_path) = genesis_path.as_deref() {
            indra_cli::seed_wallet_from_genesis(&mut wallet, genesis_path, &signer_owner)
                .unwrap_or_else(|error| {
                    eprintln!("Error loading genesis manifest: {error}");
                    std::process::exit(1);
                });
        }
        indra_cli::build_cold_transaction_with_fee_policy(&indra_cli::ColdTxParams {
            chain_id: &chain_id,
            recipient_address: &to,
            amount_spark,
            fee_spark: requested_fee_spark.unwrap_or(0),
            wallet: &wallet,
            keypair: cold_keypair,
            owner_pubkey: signer_owner.clone(),
        }, base_fee, requested_fee_spark)
    } else {
        let Some(keys) = hot_keys.as_ref() else {
            eprintln!("Error: hot keys required when --cold-keys is absent");
            std::process::exit(1);
        };
        let sender_pubkey = signer_owner.clone();
        indra_cli::build_transaction_with_fee_policy(&indra_cli::tx_builder::TxParams {
            chain_id: &chain_id,
            recipient_address: &to,
            amount_spark,
            fee_spark: requested_fee_spark.unwrap_or(0),
            wallet: &wallet,
            ed25519_seed: keys.ed25519_seed,
            ml_dsa_seed_bytes: keys.ml_dsa_seed.to_vec(),
            sender_pubkey,
        }, base_fee, requested_fee_spark)
    }
    .unwrap_or_else(|e| {
        eprintln!("Error building transaction: {}", e);
        std::process::exit(1);
    });

    println!("Required fee: {} Spark", required_fee);
    if let Some(given) = requested_fee_spark {
        let default_fee = indra_cli::default_fee_for_base_fee(base_fee).unwrap_or(u64::MAX);
        if given < default_fee {
            println!("Warning: requested fee may be rejected if the base fee rises before inclusion");
        }
    }

    println!(
        "Wallet balance: {} Spark ({:.8} INDRA)",
        wallet.balance_owned_by(&signer_owner),
        wallet.balance_owned_by(&signer_owner) as f64 / (indra_cli::SPARK_PER_INDRA as f64)
    );

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
    indra_cli::rpc_client::post_json(node_url, body).map_err(|error| error.to_string())
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
