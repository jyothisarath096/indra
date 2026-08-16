//! Wallet scan — discover outputs owned by this keypair from canonical blocks.
//!
//! ## Usage
//!
//! indra-wallet-scan --keys keys.json --wallet wallet.json \
//!                   [--keys-password-file keys.pass] \
//!                   --node http://127.0.0.1:8545

use indra_core::types::{
    crypto::HybridPubKey,
    primitives::{Bytes32, VariableBytes},
};

const SPARK_PER_INDRA_F64: f64 = 100_000_000.0;

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
    let node_url = get("--node").unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let add_utxo = get("--add-utxo");

    println!("INDRA Wallet Scanner");
    println!("─────────────────────────────────────────");
    println!("Keys:   {}", keys_path);
    println!("Wallet: {}", wallet_path);
    println!("Node:   {}", node_url);
    println!("─────────────────────────────────────────");

    let keys = indra_cli::load_keys_for_cli(&keys_path, &args).unwrap_or_else(|e| {
        eprintln!("Error loading keys: {}", e);
        std::process::exit(1);
    });
    let classical_pk = keys.public.hybrid_classical_pk;
    let pubkey_hex = hex::encode(classical_pk);
    println!("Scanning for UTXOs owned by: {}...", &pubkey_hex[..16]);

    let mut wallet = indra_cli::Wallet::load(&wallet_path).unwrap_or_else(|e| {
        eprintln!("Warning: could not load wallet ({}), starting fresh", e);
        indra_cli::Wallet::new()
    });
    println!("Existing wallet balance: {} Spark", wallet.balance());

    if let Some(utxo_spec) = add_utxo {
        let parts: Vec<&str> = utxo_spec.splitn(5, ':').collect();
        if parts.len() < 2 {
            eprintln!(
                "Error: --add-utxo format: <utxo_id>:<value_spark>[:<height>:<tx_idx>:<out_idx>]"
            );
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
        if utxo_id_bytes.len() != 32 {
            eprintln!("Error: utxo_id must be 32 bytes");
            std::process::exit(1);
        }

        let height: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        let tx_idx: u32 = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
        let out_idx: u32 = parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
        let mut id_arr = [0u8; 32];
        id_arr.copy_from_slice(&utxo_id_bytes);
        let utxo_id = Bytes32::from(id_arr);

        wallet.add_utxo(utxo_id, value, height, tx_idx, out_idx);
        wallet.save(&wallet_path).unwrap_or_else(|e| {
            eprintln!("Error saving wallet: {}", e);
            std::process::exit(1);
        });
        println!("Added UTXO: {} ({} Spark)", parts[0], value);
        println!(
            "New balance: {} Spark ({:.8} INDRA)",
            wallet.balance(),
            wallet.balance() as f64 / SPARK_PER_INDRA_F64
        );
        return;
    }

    println!("\\nScanning canonical blocks locally...");
    let owner_pubkey = HybridPubKey {
        classical_pk: Bytes32::from(keys.public.hybrid_classical_pk),
        pq_pk: VariableBytes::from_slice(&keys.public.hybrid_pq_pk).unwrap_or_else(|_| {
            eprintln!("Error: invalid canonical hybrid public key");
            std::process::exit(1);
        }),
    };
    match scan_canonical_blocks(&node_url, &mut wallet, &keys, &[owner_pubkey]) {
        Ok(discovered) => {
            wallet.save(&wallet_path).unwrap_or_else(|error| {
                eprintln!("Error saving wallet: {error}");
                std::process::exit(1);
            });
            println!("Discovered {discovered} recoverable payment output(s).");
        }
        Err(error) => {
            eprintln!("Wallet scan failed: {error}");
            std::process::exit(1);
        }
    }

    println!(
        "\nCurrent wallet balance: {} Spark ({:.8} INDRA)",
        wallet.balance(),
        wallet.balance() as f64 / SPARK_PER_INDRA_F64
    );
}

fn scan_canonical_blocks(
    node_url: &str,
    wallet: &mut indra_cli::Wallet,
    keys: &indra_cli::KeysFile,
    owner_pubkeys: &[HybridPubKey],
) -> Result<usize, String> {
    indra_cli::scan_canonical_blocks(node_url, wallet, keys, owner_pubkeys)
}
