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
    let add_utxo = get("--add-utxo"); // manual: --add-utxo <utxo_id>:<value>:<blinding>

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
    let classical_pk = classical.public_key().0;
    let address_hex = hex::encode(indra_crypto::sha256(&classical_pk));
    let pubkey_hex = hex::encode(classical_pk);

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

        let height: u64 = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
        let tx_idx: u32 = parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
        let out_idx: u32 = parts.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);

        let mut id_arr = [0u8; 32];
        let mut bl_arr = [0u8; 32];
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
        println!(
            "New balance: {} Spark ({:.8} INDRA)",
            wallet.balance(),
            wallet.balance() as f64 / SPARK_PER_INDRA_F64
        );
        return;
    }

    // Query node for UTXOs
    println!("\nQuerying node for UTXOs...");
    match query_utxos(&node_url, &address_hex) {
        Ok(response) => {
            println!("Node response: {}", response);
            let discovered = parse_utxos_json(&response);
            let genesis_blinding = derive_genesis_blinding(&hybrid_seed);
            let mut added = 0usize;
            let mut reconciled = 0usize;
            for utxo in discovered {
                if wallet.contains(&utxo.utxo_id) {
                    continue;
                }
                if utxo.created_height == 0 {
                    wallet.add_utxo(
                        utxo.utxo_id,
                        utxo.value,
                        genesis_blinding,
                        utxo.created_height,
                        utxo.tx_index,
                        utxo.out_index,
                    );
                    added += 1;
                    continue;
                }
                if wallet.reconcile_pending_change(
                    utxo.utxo_id,
                    utxo.created_height,
                    utxo.tx_index,
                    utxo.out_index,
                ) {
                    reconciled += 1;
                }
            }

            if added > 0 || reconciled > 0 {
                wallet.save(&wallet_path).unwrap_or_else(|e| {
                    eprintln!("Error saving wallet: {}", e);
                    std::process::exit(1);
                });
            }

            if added > 0 {
                println!("Added {} genesis UTXO(s) automatically.", added);
            }
            if reconciled > 0 {
                println!("Reconciled {} pending change UTXO(s).", reconciled);
            }

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

    println!(
        "\nCurrent wallet balance: {} Spark ({:.8} INDRA)",
        wallet.balance(),
        wallet.balance() as f64 / SPARK_PER_INDRA_F64
    );
}

/// Query the node for UTXOs owned by a pubkey.
fn query_utxos(node_url: &str, pubkey_hex: &str) -> Result<String, String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"indra_getUtxos","params":["{}"],"id":1}}"#,
        pubkey_hex
    );
    indra_cli::staking::http_post(node_url, &body).map_err(|e| e.to_string())
}

/// Derive the genesis blinding factor for this validator's initial stake UTXO.
/// This is deterministic from the hybrid seed.
fn derive_genesis_blinding(hybrid_seed: &[u8; 32]) -> [u8; 32] {
    use indra_crypto::hybrid::ClassicalKeypair;

    let classical = ClassicalKeypair::from_seed(hybrid_seed);
    let classical_pk = classical.public_key().0;
    let validator_id = indra_crypto::sha256(&classical_pk);
    indra_crypto::sha256(&[b"genesis-utxo-blinding".as_slice(), &validator_id].concat())
}

struct RpcUtxo {
    utxo_id: indra_core::Bytes32,
    value: u64,
    created_height: u64,
    tx_index: u32,
    out_index: u32,
}

fn parse_utxos_json(json: &str) -> Vec<RpcUtxo> {
    let Some(start) = json.find("\"utxos\":[") else {
        return vec![];
    };
    let after = &json[start + 9..];
    let Some(end) = after.find(']') else {
        return vec![];
    };
    let array = &after[..end];

    let mut utxos = Vec::new();
    let mut pos = 0usize;
    while let Some(obj_start_rel) = array[pos..].find('{') {
        let obj_start = pos + obj_start_rel;
        let Some(obj_end_rel) = array[obj_start..].find('}') else {
            break;
        };
        let obj_end = obj_start + obj_end_rel + 1;
        let obj = &array[obj_start..obj_end];
        pos = obj_end;

        let Some(utxo_hex) = extract_json_str(obj, "utxo_id") else {
            continue;
        };
        let Ok(decoded) = hex::decode(utxo_hex) else {
            continue;
        };
        if decoded.len() != 32 {
            continue;
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&decoded);
        utxos.push(RpcUtxo {
            utxo_id: indra_core::Bytes32::from(raw),
            value: extract_json_num(obj, "amount").unwrap_or(0),
            created_height: extract_json_num(obj, "created_height").unwrap_or(0),
            tx_index: extract_json_num(obj, "tx_index").unwrap_or(0) as u32,
            out_index: extract_json_num(obj, "out_index").unwrap_or(0) as u32,
        });
    }
    utxos
}

fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":\"", key);
    let pos = json.find(&needle)?;
    let after = &json[pos + needle.len()..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

fn extract_json_num(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{}\":", key);
    let pos = json.find(&needle)?;
    let after = json[pos + needle.len()..].trim_start();
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn extract_hex32(json: &str, field: &str) -> [u8; 32] {
    let key = format!("\"{}\":", field);
    let pos = match json.find(&key) {
        Some(p) => p,
        None => {
            eprintln!("Field '{}' not found in keys.json", field);
            std::process::exit(1);
        }
    };
    let after = &json[pos + key.len()..];
    let start = after.find('"').unwrap_or(0) + 1;
    let end = after[start..].find('"').unwrap_or(0) + start;
    let bytes = hex::decode(&after[start..end]).unwrap_or_else(|_| {
        eprintln!("Invalid hex for '{}'", field);
        std::process::exit(1);
    });
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    arr
}
