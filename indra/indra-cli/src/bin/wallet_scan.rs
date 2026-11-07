//! Wallet scan — discover outputs owned by this keypair from canonical blocks.
//!
//! ## Usage
//!
//! indra-wallet-scan --keys keys.json --wallet wallet.json \
//!                   [--keys-password-file keys.pass] \
//!                   [--cold-owner <encoded-hybrid-pubkey-hex>] \
//!                   --node http://127.0.0.1:8545

use indra_core::codec::Decode;
use indra_core::types::{crypto::HybridPubKey, primitives::{Bytes32, VariableBytes}};

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
    let cold_owner_hex = get("--cold-owner");

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

        let owner_hex = get("--owner").unwrap_or_else(|| {
            eprintln!("Error: --owner is required with --add-utxo");
            std::process::exit(1);
        });
        let owner_bytes = hex::decode(owner_hex).unwrap_or_else(|_| {
            eprintln!("Error: bad owner hex");
            std::process::exit(1);
        });
        let owner_pubkey = HybridPubKey::decode_exact(&owner_bytes).unwrap_or_else(|_| {
            eprintln!("Error: bad owner public key encoding");
            std::process::exit(1);
        });
        wallet.add_utxo(utxo_id, value, height, tx_idx, out_idx, owner_pubkey.clone());
        wallet.save(&wallet_path).unwrap_or_else(|e| {
            eprintln!("Error saving wallet: {}", e);
            std::process::exit(1);
        });
        println!("Added UTXO: {} ({} Spark)", parts[0], value);
        println!(
            "New balance: {} Spark ({:.8} INDRA)",
            wallet.balance_owned_by(&owner_pubkey),
            wallet.balance_owned_by(&owner_pubkey) as f64 / SPARK_PER_INDRA_F64
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
    let mut owner_pubkeys = vec![owner_pubkey.clone()];
    if let Some(raw_owner) = cold_owner_hex.as_deref() {
        owner_pubkeys.push(parse_cold_owner(raw_owner).unwrap_or_else(|error| {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }));
    }
    match scan_canonical_blocks(&node_url, &mut wallet, &keys, &owner_pubkeys) {
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

    let owned_balance: u64 = owner_pubkeys
        .iter()
        .map(|owner| wallet.balance_owned_by(owner))
        .sum();
    println!(
        "\nCurrent owned wallet balance: {} Spark ({:.8} INDRA)",
        owned_balance,
        owned_balance as f64 / SPARK_PER_INDRA_F64
    );
}

fn parse_cold_owner(raw: &str) -> Result<HybridPubKey, &'static str> {
    let bytes = hex::decode(raw).map_err(|_| "bad cold-owner hex")?;
    HybridPubKey::decode_exact(&bytes).map_err(|_| "bad cold-owner public key encoding")
}

fn scan_canonical_blocks(
    node_url: &str,
    wallet: &mut indra_cli::Wallet,
    keys: &indra_cli::KeysFile,
    owner_pubkeys: &[HybridPubKey],
) -> Result<usize, String> {
    indra_cli::scan_canonical_blocks(node_url, wallet, keys, owner_pubkeys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::codec::Encode;

    fn owner() -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::from([1; 32]),
            pq_pk: VariableBytes::from_slice(&[2; 32]).unwrap(),
        }
    }

    #[test]
    fn cold_owner_argument_accepts_encoded_public_key() {
        let encoded = hex::encode(owner().encode_to_vec());
        assert_eq!(parse_cold_owner(&encoded).unwrap(), owner());
    }

    #[test]
    fn cold_owner_argument_rejects_bad_hex() {
        assert_eq!(parse_cold_owner("not-hex").unwrap_err(), "bad cold-owner hex");
    }

    #[test]
    fn cold_owner_argument_rejects_bad_encoding() {
        assert_eq!(parse_cold_owner("00").unwrap_err(), "bad cold-owner public key encoding");
    }
}
