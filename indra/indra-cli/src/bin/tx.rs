use std::io::{Read, Write};
use std::net::TcpStream;

use indra_cli::{build_transaction, KeysFile, TxParams, Wallet};
use indra_core::types::{
    crypto::HybridPubKey,
    primitives::{Bytes32, VariableBytes},
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage_and_exit();
    }

    match args[1].as_str() {
        "address" => cmd_address(&args[2..]),
        "balance" => cmd_balance(&args[2..]),
        "send" => cmd_send(&args[2..]),
        _ => usage_and_exit(),
    }
}

fn usage_and_exit() -> ! {
    eprintln!("Usage:");
    eprintln!("  indra-tx address --keys <keys.json> [--keys-password-file <path>]");
    eprintln!("  indra-tx balance --keys <keys.json> [--keys-password-file <path>] [--address <hex>] [--wallet <wallet.json>] --rpc <url>");
    eprintln!("  indra-tx send --keys <keys.json> [--keys-password-file <path>] [--wallet <wallet.json>] --to <address-hex> --amount <INDRA> --rpc <url>");
    std::process::exit(1);
}

fn cmd_address(args: &[String]) {
    let keys_path = get_arg(args, "--keys").unwrap_or_else(|| "keys.json".to_string());
    let keys = indra_cli::load_keys_for_cli(&keys_path, args).unwrap_or_else(|e| {
        eprintln!("Error loading {}: {}", keys_path, e);
        std::process::exit(1);
    });
    let chain_id = get_arg(args, "--chain-id")
        .unwrap_or_else(|| indra_core::types::primitives::DEFAULT_CHAIN_ID.to_string());
    let address = keys
        .payment_address(chain_id.as_bytes())
        .unwrap_or_else(|e| {
            eprintln!("Error constructing payment address: {e}");
            std::process::exit(1);
        });
    println!("{}", address.to_text());
}

fn cmd_balance(args: &[String]) {
    let keys_path = get_arg(args, "--keys").unwrap_or_else(|| {
        eprintln!(
            "Error: balance scans now require ownership authorization. \
             Re-run with --keys <keys.json> for the address owner."
        );
        std::process::exit(1);
    });
    let rpc = get_arg(args, "--rpc").unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let wallet_path = get_arg(args, "--wallet").unwrap_or_else(|| "wallet.json".to_string());
    let keys = indra_cli::load_keys_for_cli(&keys_path, args).unwrap_or_else(|e| {
        eprintln!("Error loading {}: {}", keys_path, e);
        std::process::exit(1);
    });
    let chain_id = get_arg(args, "--chain-id")
        .unwrap_or_else(|| indra_core::types::primitives::DEFAULT_CHAIN_ID.to_string());
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
    let wallet = scan_wallet_or_exit(&rpc, &wallet_path, &keys);
    let balance = wallet.balance();
    println!(
        "Address: {}\nBalance: {} Spark ({:.8} INDRA)",
        address,
        balance,
        balance as f64 / (indra_cli::SPARK_PER_INDRA as f64)
    );
}

fn cmd_send(args: &[String]) {
    let keys_path = get_arg(args, "--keys").unwrap_or_else(|| "keys.json".to_string());
    let wallet_path = get_arg(args, "--wallet").unwrap_or_else(|| "wallet.json".to_string());
    let recipient_address = required_arg(args, "--to");
    let amount_spark =
        parse_send_amount_spark(&required_arg(args, "--amount")).unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        });
    let rpc = get_arg(args, "--rpc").unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let chain_id = get_arg(args, "--chain-id")
        .unwrap_or_else(|| indra_core::types::primitives::DEFAULT_CHAIN_ID.to_string());

    let keys = indra_cli::load_keys_for_cli(&keys_path, args).unwrap_or_else(|e| {
        eprintln!("Error loading {}: {}", keys_path, e);
        std::process::exit(1);
    });
    let ed25519_seed = keys.ed25519_seed;
    let ml_dsa_seed_bytes = keys.ml_dsa_seed.to_vec();
    let classical_pk = keys.public.hybrid_classical_pk;
    let pq_pk = keys.public.hybrid_pq_pk.clone();
    let wallet = scan_wallet_or_exit(&rpc, &wallet_path, &keys);

    let sender_pubkey = HybridPubKey {
        classical_pk: Bytes32::from(classical_pk),
        pq_pk: VariableBytes::from_slice(&pq_pk).unwrap_or_else(|_| {
            eprintln!("Error: invalid sender pq key length");
            std::process::exit(1);
        }),
    };

    let built = build_transaction(&TxParams {
        chain_id: &chain_id,
        recipient_address: &recipient_address,
        amount_spark,
        fee_spark: indra_cli::tx_builder::MIN_FEE_SPARK,
        wallet: &wallet,
        ed25519_seed,
        ml_dsa_seed_bytes,
        sender_pubkey,
    })
    .unwrap_or_else(|e| {
        eprintln!("Error building transaction: {}", e);
        std::process::exit(1);
    });

    let response = rpc_call(&rpc, "indra_sendTransaction", &[built.tx_hex.clone()]);
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

fn scan_wallet_or_exit(rpc: &str, wallet_path: &str, keys: &KeysFile) -> Wallet {
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
    indra_cli::scan_canonical_blocks(rpc, &mut wallet, keys, &[owner_pubkey]).unwrap_or_else(
        |error| {
            eprintln!("Error scanning canonical blocks: {}", error);
            std::process::exit(1);
        },
    );
    wallet.save(wallet_path).unwrap_or_else(|error| {
        eprintln!("Error saving wallet {}: {}", wallet_path, error);
        std::process::exit(1);
    });
    wallet
}

fn rpc_call(url: &str, method: &str, params: &[String]) -> String {
    let url = url.trim_start_matches("http://");
    let (host, path) = if let Some(pos) = url.find('/') {
        (&url[..pos], &url[pos..])
    } else {
        (url, "/")
    };
    let params_json = params
        .iter()
        .map(|p| format!("\"{}\"", p))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"{}","params":[{}],"id":1}}"#,
        method, params_json
    );
    let mut stream = TcpStream::connect(host).unwrap_or_else(|e| {
        eprintln!("Error connecting to {}: {}", host, e);
        std::process::exit(1);
    });
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host, body.len(), body
    );
    stream.write_all(request.as_bytes()).unwrap_or_else(|e| {
        eprintln!("Error writing request: {}", e);
        std::process::exit(1);
    });
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap_or_else(|e| {
        eprintln!("Error reading response: {}", e);
        std::process::exit(1);
    });
    response
        .find("\r\n\r\n")
        .map(|pos| response[pos + 4..].to_string())
        .unwrap_or(response)
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
    use indra_cli::tx_builder::MIN_FEE_SPARK;
    use indra_core::types::{primitives::VariableBytes, transaction::OutputV1};
    use indra_crypto::{hybrid::ClassicalKeypair, PqKeypair};

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
        wallet.add_utxo(spent_id, 1_000_000, 9, 0, 0);
        wallet.add_utxo(other_id, 2_000_000, 9, 0, 1);
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
        assert_eq!(updated.balance(), 2_000_000);
        assert!(updated.select_utxos(2_000_000, 1).is_err());
        assert!(updated.select_utxos(1_900_000, MIN_FEE_SPARK).is_ok());

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
