#![deny(unused_must_use)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unreachable, clippy::todo, clippy::unimplemented, clippy::indexing_slicing)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing))]

//! Wallet scan — discover outputs owned by this keypair from canonical blocks.
//!
//! ## Usage
//!
//! indra-wallet-scan --owner-pubkey <encoded-hybrid-pubkey-hex> --wallet wallet.json \
//!                   [--cold-owner <encoded-hybrid-pubkey-hex>] \
//!                   --genesis-hash <64-hex> --node http://127.0.0.1:8545
//!                   [--rpc-token-file token.path]

use indra_core::codec::Decode;
use indra_core::types::{
    crypto::HybridPubKey,
    primitives::Bytes32,
};

const SPARK_PER_INDRA_F64: f64 = 100_000_000.0;

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

    let wallet_path = get("--wallet").unwrap_or_else(|| "wallet.json".to_string());
    let node_url = get("--node").unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let genesis_hash = get("--genesis-hash").unwrap_or_else(|| {
        eprintln!("Error: --genesis-hash required");
        std::process::exit(1);
    });
    let add_utxo = get("--add-utxo");

    println!("INDRA Wallet Scanner");
    println!("─────────────────────────────────────────");
    println!("Owner:  {}", get("--owner-pubkey").or_else(|| get("--cold-owner")).unwrap_or_default());
    println!("Wallet: {}", wallet_path);
    println!("Node:   {}", node_url);
    println!("Genesis: {}", genesis_hash);
    println!("─────────────────────────────────────────");

    let owner_hex = get("--owner-pubkey").or_else(|| get("--cold-owner")).unwrap_or_else(|| {
        eprintln!("Error: --owner-pubkey or --cold-owner is required");
        std::process::exit(1);
    });

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

        let Some(utxo_id_text) = parts.first() else {
            eprintln!("Error: missing utxo_id");
            std::process::exit(1);
        };
        let Some(value_text) = parts.get(1) else {
            eprintln!("Error: missing value");
            std::process::exit(1);
        };
        let utxo_id_bytes = hex::decode(utxo_id_text).unwrap_or_else(|_| {
            eprintln!("Error: bad utxo_id hex");
            std::process::exit(1);
        });
        let value: u64 = value_text.parse().unwrap_or_else(|_| {
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
        wallet.add_utxo(
            utxo_id,
            value,
            height,
            tx_idx,
            out_idx,
            owner_pubkey.clone(),
        );
        wallet.save(&wallet_path).unwrap_or_else(|e| {
            eprintln!("Error saving wallet: {}", e);
            std::process::exit(1);
        });
        println!("Added UTXO: {} ({} Spark)", utxo_id_text, value);
        println!(
            "New balance: {} Spark ({:.8} INDRA)",
            wallet.balance_owned_by(&owner_pubkey),
            wallet.balance_owned_by(&owner_pubkey) as f64 / SPARK_PER_INDRA_F64
        );
        return;
    }

    println!("\nScanning canonical blocks locally...");
    let owner_pubkey = parse_cold_owner(&owner_hex).unwrap_or_else(|error| {
        eprintln!("Error: {error}");
        std::process::exit(1);
    });
    let owner_pubkeys = vec![owner_pubkey.clone()];
    let genesis_hash = hex::decode(&genesis_hash).unwrap_or_else(|_| {
        eprintln!("Error: --genesis-hash must be 32-byte hex");
        std::process::exit(1);
    });
    let mut expected_genesis_hash = [0u8; 32];
    if genesis_hash.len() != expected_genesis_hash.len() {
        eprintln!("Error: --genesis-hash must be 32-byte hex");
        std::process::exit(1);
    }
    expected_genesis_hash.copy_from_slice(&genesis_hash);
    match scan_canonical_blocks(
        &node_url,
        &mut wallet,
        &owner_pubkeys,
        indra_core::types::primitives::Bytes32::from(expected_genesis_hash),
    ) {
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
    owner_pubkeys: &[HybridPubKey],
    expected_genesis_hash: indra_core::types::primitives::Bytes32,
) -> Result<usize, String> {
    indra_cli::scan_canonical_blocks(
        node_url,
        wallet,
        owner_pubkeys,
        expected_genesis_hash,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::codec::Encode;
    use indra_core::types::primitives::VariableBytes;

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
        assert_eq!(
            parse_cold_owner("not-hex").unwrap_err(),
            "bad cold-owner hex"
        );
    }

    #[test]
    fn cold_owner_argument_rejects_bad_encoding() {
        assert_eq!(
            parse_cold_owner("00").unwrap_err(),
            "bad cold-owner public key encoding"
        );
    }
}
