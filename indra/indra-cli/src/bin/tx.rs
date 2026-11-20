#![deny(unused_must_use)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use indra_cli::{KeysFile, TxParams, Wallet};
use indra_core::types::{
    crypto::HybridPubKey,
    primitives::{Bytes32, VariableBytes},
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Err(error) = indra_cli::rpc_client::configure_from_args(&args) {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
    if args.len() < 2 {
        usage_and_exit();
    }

    let Some(command) = args.get(1).map(String::as_str) else {
        usage_and_exit();
    };
    let Some(command_args) = args.get(2..) else {
        eprintln!("Error: missing command arguments");
        std::process::exit(1);
    };
    match command {
        "address" => cmd_address(command_args),
        "balance" => cmd_balance(command_args),
        "send" => cmd_send(command_args),
        _ => usage_and_exit(),
    }
}

fn usage_and_exit() -> ! {
    eprintln!("Usage:");
    eprintln!(
        "  indra-tx address --chain-id <id> --keys <keys.json> [--keys-password-file <path>]"
    );
    eprintln!("  indra-tx balance --chain-id <id> --keys <keys.json> [--keys-password-file <path>] [--address <hex>] [--wallet <wallet.json>] --genesis-hash <64-hex> --rpc <url>");
    eprintln!("  indra-tx send --chain-id <id> --keys <keys.json> [--keys-password-file <path>] [--wallet <wallet.json>] --to <address-hex> --amount <INDRA> --genesis-hash <64-hex> --rpc <url>");
    eprintln!("{}", indra_cli::rpc_client::rpc_token_help());
    std::process::exit(1);
}

fn cmd_address(args: &[String]) {
    let chain_id = indra_cli::required_chain_id(args).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(1);
    });
    let keys_path = get_arg(args, "--keys").unwrap_or_else(|| "keys.json".to_string());
    let keys = indra_cli::load_keys_for_cli(&keys_path, args).unwrap_or_else(|e| {
        eprintln!("Error loading {}: {}", keys_path, e);
        std::process::exit(1);
    });
    let address = keys
        .payment_address(chain_id.as_bytes())
        .unwrap_or_else(|e| {
            eprintln!("Error constructing payment address: {e}");
            std::process::exit(1);
        });
    println!("{}", address.to_text());
}

fn cmd_balance(args: &[String]) {
    let chain_id = indra_cli::required_chain_id(args).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(1);
    });
    let keys_path = get_arg(args, "--keys").unwrap_or_else(|| {
        eprintln!(
            "Error: balance scans now require ownership authorization. \
             Re-run with --keys <keys.json> for the address owner."
        );
        std::process::exit(1);
    });
    let rpc = get_arg(args, "--rpc").unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let genesis_hash = required_genesis_hash(args);
    let wallet_path = get_arg(args, "--wallet").unwrap_or_else(|| "wallet.json".to_string());
    let keys = indra_cli::load_keys_for_cli(&keys_path, args).unwrap_or_else(|e| {
        eprintln!("Error loading {}: {}", keys_path, e);
        std::process::exit(1);
    });
    let derived_address = keys
        .payment_address(chain_id.as_bytes())
        .unwrap_or_else(|e| {
            eprintln!("Error constructing payment address: {e}");
            std::process::exit(1);
        })
        .to_text();
    let address = get_arg(args, "--address").unwrap_or_else(|| derived_address.clone());
    if address != derived_address {
        eprintln!(
            "Error: keys.json does not own requested address {}. \
             UTXO/balance scans require the owner's keys.",
            address
        );
        std::process::exit(1);
    }
    let wallet = scan_wallet_or_exit(&rpc, &wallet_path, &keys, genesis_hash);
    let sender_pubkey = HybridPubKey {
        classical_pk: Bytes32::from(keys.public.hybrid_classical_pk),
        pq_pk: VariableBytes::from_slice(&keys.public.hybrid_pq_pk).unwrap_or_else(|_| {
            eprintln!("Error: invalid sender pq key length");
            std::process::exit(1);
        }),
    };
    let balance = wallet.balance_owned_by(&sender_pubkey);
    println!(
        "Address: {}\nBalance: {} Spark ({:.8} INDRA)",
        address,
        balance,
        balance as f64 / (indra_cli::SPARK_PER_INDRA as f64)
    );
}

fn cmd_send(args: &[String]) {
    let chain_id = indra_cli::required_chain_id(args).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(1);
    });
    let keys_path = get_arg(args, "--keys").unwrap_or_else(|| "keys.json".to_string());
    let wallet_path = get_arg(args, "--wallet").unwrap_or_else(|| "wallet.json".to_string());
    let recipient_address = required_arg(args, "--to");
    let amount_spark =
        parse_send_amount_spark(&required_arg(args, "--amount")).unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        });
    let rpc = get_arg(args, "--rpc").unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let genesis_hash = required_genesis_hash(args);
    let keys = indra_cli::load_keys_for_cli(&keys_path, args).unwrap_or_else(|e| {
        eprintln!("Error loading {}: {}", keys_path, e);
        std::process::exit(1);
    });
    let ed25519_seed = keys.ed25519_seed;
    let ml_dsa_seed_bytes = keys.ml_dsa_seed.to_vec();
    let classical_pk = keys.public.hybrid_classical_pk;
    let pq_pk = keys.public.hybrid_pq_pk.clone();
    let wallet = scan_wallet_or_exit(&rpc, &wallet_path, &keys, genesis_hash);

    let sender_pubkey = HybridPubKey {
        classical_pk: Bytes32::from(classical_pk),
        pq_pk: VariableBytes::from_slice(&pq_pk).unwrap_or_else(|_| {
            eprintln!("Error: invalid sender pq key length");
            std::process::exit(1);
        }),
    };

    let requested_fee = get_arg(args, "--fee").map(|raw| {
        indra_cli::parse_indra_amount_to_spark(&raw, "--fee").unwrap_or_else(|error| {
            eprintln!("Error: {error}");
            std::process::exit(1);
        })
    });
    let base_fee = indra_cli::fetch_base_fee(&rpc).unwrap_or_else(|error| {
        eprintln!("Error fetching current base fee: {error}");
        std::process::exit(1);
    });
    let (built, _required_fee) = indra_cli::build_transaction_with_fee_policy(
        &TxParams {
            chain_id: &chain_id,
            recipient_address: &recipient_address,
            amount_spark,
            fee_spark: requested_fee.unwrap_or(0),
            wallet: &wallet,
            ed25519_seed,
            ml_dsa_seed_bytes,
            sender_pubkey,
        },
        base_fee,
        requested_fee,
    )
    .unwrap_or_else(|e| {
        eprintln!("Error building transaction: {}", e);
        std::process::exit(1);
    });

    if let Some(given) = requested_fee {
        let default_fee = indra_cli::default_fee_for_base_fee(base_fee).unwrap_or(u64::MAX);
        if given < default_fee {
            eprintln!(
                "Warning: requested fee may be rejected if the base fee rises before inclusion"
            );
        }
    }
    let response = rpc_call(
        &rpc,
        "indra_sendTransaction",
        std::slice::from_ref(&built.tx_hex),
    );
    if response.contains("\"error\"") {
        eprintln!("{}", response);
        std::process::exit(1);
    }
    if let Err(error) = update_wallet_after_accepted_transaction(&wallet_path, wallet, &built) {
        eprintln!(
            "Warning: could not update wallet {}: {}",
            wallet_path, error
        );
    }
    println!("{}", built.tx_id);
}

fn update_wallet_after_accepted_transaction(
    wallet_path: &str,
    mut wallet: Wallet,
    built: &indra_cli::BuiltTransaction,
) -> indra_cli::CliResult<()> {
    wallet.record_accepted_transaction(&built.spent_utxo_ids, built.pending_change.clone());
    wallet.save(wallet_path)
}

fn parse_send_amount_spark(raw: &str) -> indra_cli::CliResult<u64> {
    indra_cli::parse_indra_amount_to_spark(raw, "--amount")
}

fn scan_wallet_or_exit(
    rpc: &str,
    wallet_path: &str,
    keys: &KeysFile,
    expected_genesis_hash: indra_core::types::primitives::Bytes32,
) -> Wallet {
    let mut wallet = Wallet::load(wallet_path).unwrap_or_else(|error| {
        eprintln!("Error loading wallet {}: {}", wallet_path, error);
        std::process::exit(1);
    });
    let owner_pubkey = HybridPubKey {
        classical_pk: Bytes32::from(keys.public.hybrid_classical_pk),
        pq_pk: VariableBytes::from_slice(&keys.public.hybrid_pq_pk).unwrap_or_else(|_| {
            eprintln!("Error: invalid canonical hybrid public key");
            std::process::exit(1);
        }),
    };
    indra_cli::scan_canonical_blocks(rpc, &mut wallet, &[owner_pubkey], expected_genesis_hash)
        .unwrap_or_else(|error| {
            eprintln!("Error scanning canonical blocks: {}", error);
            std::process::exit(1);
        });
    wallet.save(wallet_path).unwrap_or_else(|error| {
        eprintln!("Error saving wallet {}: {}", wallet_path, error);
        std::process::exit(1);
    });
    wallet
}

fn required_genesis_hash(args: &[String]) -> indra_core::types::primitives::Bytes32 {
    let raw = get_arg(args, "--genesis-hash").unwrap_or_else(|| {
        eprintln!("Error: --genesis-hash required");
        std::process::exit(1);
    });
    let bytes = hex::decode(raw).unwrap_or_else(|_| {
        eprintln!("Error: --genesis-hash must be 32-byte hex");
        std::process::exit(1);
    });
    if bytes.len() != 32 {
        eprintln!("Error: --genesis-hash must be 32-byte hex");
        std::process::exit(1);
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    indra_core::types::primitives::Bytes32::from(hash)
}

fn rpc_call(url: &str, method: &str, params: &[String]) -> String {
    let params_json = params
        .iter()
        .map(|p| format!("\"{}\"", p))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"{}","params":[{}],"id":1}}"#,
        method, params_json
    );
    indra_cli::rpc_client::post_json(url, &body).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        std::process::exit(1);
    })
}

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn required_arg(args: &[String], flag: &str) -> String {
    get_arg(args, flag).unwrap_or_else(|| {
        eprintln!("Error: {} required", flag);
        std::process::exit(1);
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    const TEST_FEE_SPARK: u64 = 50_000;
    use indra_core::types::{primitives::VariableBytes, transaction::OutputV1};
    use indra_crypto::{hybrid::ClassicalKeypair, PqKeypair};

    fn test_owner() -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::from([0x11; 32]),
            pq_pk: VariableBytes::from_slice(&[0x22; 32]).unwrap(),
        }
    }

    #[test]
    fn indra_tx_send_uses_shared_exact_indra_amount_parser() {
        assert_eq!(parse_send_amount_spark("0.00000003").unwrap(), 3);
        assert_eq!(
            parse_send_amount_spark("10.5").unwrap(),
            indra_cli::parse_indra_amount_to_spark("10.5", "--amount").unwrap()
        );
    }

    #[test]
    fn accepted_indra_tx_send_updates_wallet_file_and_subsequent_balance() {
        let wallet_path = std::env::temp_dir().join(format!(
            "indra-tx-wallet-{}-{}.json",
            std::process::id(),
            rand::random::<u64>()
        ));
        let wallet_path_str = wallet_path.to_string_lossy().to_string();
        let spent_id = Bytes32::from([0xC1; 32]);
        let other_id = Bytes32::from([0xC2; 32]);
        let mut wallet = Wallet::new();
        wallet.add_utxo(spent_id, 1_000_000, 9, 0, 0, test_owner());
        wallet.add_utxo(other_id, 2_000_000, 9, 0, 1, test_owner());
        wallet.save(&wallet_path_str).unwrap();
        let built = indra_cli::BuiltTransaction {
            tx_hex: "00".to_string(),
            tx_id: hex::encode([0x44; 32]),
            change_spark: 750_000,
            spent_utxo_ids: vec![spent_id],
            pending_change: Some(indra_cli::PendingChange {
                output: sample_output(750_000),
            }),
        };

        update_wallet_after_accepted_transaction(&wallet_path_str, wallet, &built).unwrap();

        let updated = Wallet::load(&wallet_path_str).unwrap();
        assert!(updated.get(&spent_id).unwrap().spent);
        assert!(!updated.get(&other_id).unwrap().spent);
        assert_eq!(updated.pending_change_count(), 1);
        assert_eq!(updated.balance_owned_by(&test_owner()), 2_000_000);
        assert!(updated.select_utxos(&test_owner(), 2_000_000, 1).is_err());
        assert!(updated
            .select_utxos(&test_owner(), 1_900_000, TEST_FEE_SPARK)
            .is_ok());

        let _ = std::fs::remove_file(wallet_path);
    }

    fn key_material(seed_byte: u8) -> ([u8; 32], Vec<u8>, HybridPubKey) {
        let seed = [seed_byte; 32];
        let classical = ClassicalKeypair::from_seed(&seed);
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let pq_pk = pq.public_key();
        (
            seed,
            pq.secret_key_bytes(),
            HybridPubKey {
                classical_pk: Bytes32::from(classical.public_key().0),
                pq_pk: VariableBytes::from_slice(&pq_pk.0).unwrap(),
            },
        )
    }

    fn sample_output(value_spark: u64) -> OutputV1 {
        OutputV1 {
            value_spark,
            owner_pubkey: key_material(0x91).2,
            lock_height: 0,
        }
    }
}
