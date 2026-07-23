//! Wallet scan — discover UTXOs owned by this keypair from the chain.
//!
//! Calls the authorized legacy UTXO-scan RPC to find UTXOs, then the user provides
//! the blinding factors to reconstruct spendable wallet entries.
//!
//! ## Usage
//!
//! For genesis UTXOs (initial allocation), the blinding factor is
//! derived deterministically from the validator seed.
//!
//! indra-wallet-scan --keys keys.json --wallet wallet.json \
//!                   [--keys-password-file keys.pass] \
//!                   --node http://127.0.0.1:8545

use indra_core::{codec::Decode, types::transaction::TransactionV1};
use indra_crypto::{commit, recipient_derive_payment_blinding_v1, PaymentKeypairV1};
use indra_state::UtxoSet;

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
    let keys = indra_cli::load_keys_for_cli(&keys_path, &args).unwrap_or_else(|e| {
        eprintln!("Error loading keys: {}", e);
        std::process::exit(1);
    });
    let hybrid_seed = keys.hybrid_seed;

    // Derive classical pubkey
    let classical_pk = keys.public.hybrid_classical_pk;
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
    match query_utxos(&node_url, &keys, &address_hex) {
        Ok(response) => {
            println!("Node response: {}", response);
            let discovered = parse_utxos_json(&response);
            let genesis_blinding = derive_genesis_blinding(&hybrid_seed);
            let mut chain_id = None::<String>;
            let mut added = 0usize;
            let mut reconciled = 0usize;
            let mut recovered_payment_notes = 0usize;
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
                    continue;
                }
                if keys.payment_keypair.is_none() {
                    continue;
                }
                let chain_id_ref = match chain_id.as_deref() {
                    Some(chain_id) => chain_id,
                    None => {
                        let fetched = match indra_cli::fetch_chain_id(&node_url) {
                            Ok(chain_id) => chain_id,
                            Err(e) => {
                                eprintln!(
                                    "Error fetching chain ID for payment-note recovery: {}",
                                    e
                                );
                                std::process::exit(1);
                            }
                        };
                        chain_id.insert(fetched).as_str()
                    }
                };
                match recover_payment_note_from_node(&node_url, &utxo, &keys, chain_id_ref) {
                    Ok(Some(blinding)) => {
                        wallet.add_utxo(
                            utxo.utxo_id,
                            utxo.value,
                            blinding,
                            utxo.created_height,
                            utxo.tx_index,
                            utxo.out_index,
                        );
                        recovered_payment_notes += 1;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("Error recovering payment note: {}", e);
                        std::process::exit(1);
                    }
                }
            }

            if added > 0 || reconciled > 0 || recovered_payment_notes > 0 {
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
            if recovered_payment_notes > 0 {
                println!(
                    "Recovered {} payment-note UTXO(s) automatically.",
                    recovered_payment_notes
                );
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

/// Query the node for UTXOs owned by this keypair's legacy address.
fn query_utxos(
    node_url: &str,
    keys: &indra_cli::KeysFile,
    address_hex: &str,
) -> Result<String, String> {
    let proof = indra_cli::build_legacy_scan_auth_proof(node_url, keys, address_hex)
        .map_err(|e| e.to_string())?;
    indra_cli::rpc_call_raw_params(
        node_url,
        "indra_getLegacyUtxosAuthorized",
        &[indra_cli::json_string(address_hex), proof],
    )
    .map_err(|e| e.to_string())
}

/// Query the node for the full canonical transaction at a discovered UTXO's block position.
fn query_transaction(
    node_url: &str,
    height: u64,
    tx_index: u32,
) -> Result<Option<TransactionV1>, String> {
    let raw = indra_cli::rpc_call_raw_params(
        node_url,
        "indra_getTransaction",
        &[height.to_string(), tx_index.to_string()],
    )
    .map_err(|e| e.to_string())?;
    let Some(tx_hex) = extract_json_str(&raw, "tx_hex") else {
        return Ok(None);
    };
    let bytes = hex::decode(tx_hex).map_err(|_| "bad tx_hex from node".to_string())?;
    TransactionV1::decode_exact(&bytes)
        .map(Some)
        .map_err(|e| format!("failed to decode transaction: {e}"))
}

fn recover_payment_note_from_node(
    node_url: &str,
    utxo: &RpcUtxo,
    keys: &indra_cli::KeysFile,
    chain_id: &str,
) -> Result<Option<[u8; 32]>, String> {
    let Some(payment_keypair) = keys.payment_keypair.as_ref() else {
        return Ok(None);
    };
    let Some(tx) = query_transaction(node_url, utxo.created_height, utxo.tx_index)? else {
        return Ok(None);
    };
    recover_payment_note_blinding(&tx, utxo, payment_keypair, chain_id)
}

fn recover_payment_note_blinding(
    tx: &TransactionV1,
    utxo: &RpcUtxo,
    payment_keypair: &PaymentKeypairV1,
    chain_id: &str,
) -> Result<Option<[u8; 32]>, String> {
    let output_index = usize::try_from(utxo.out_index)
        .map_err(|_| "output index does not fit this platform".to_string())?;
    let Some(output) = tx.outputs.get(output_index) else {
        return Err("UTXO output index is outside the transaction outputs".to_string());
    };
    let computed_utxo_id =
        UtxoSet::compute_utxo_id(output, utxo.created_height, utxo.tx_index, utxo.out_index);
    if computed_utxo_id != utxo.utxo_id {
        return Err("UTXO metadata does not match the referenced transaction output".to_string());
    }
    let Some(Some(note)) = tx.payment_notes.get(output_index) else {
        return Ok(None);
    };
    let output_owner_id = indra_crypto::sha256(&output.owner_pubkey.classical_pk.0);
    if note.owner_id != output_owner_id {
        return Err("payment note owner_id does not match the output owner".to_string());
    }
    if output.value_spark != utxo.value {
        return Err("UTXO value does not match the referenced transaction output".to_string());
    }
    let recipient = recipient_derive_payment_blinding_v1(
        payment_keypair,
        note,
        chain_id.as_bytes(),
        utxo.out_index,
        output.value_spark,
        output.lock_height,
    )
    .map_err(|e| format!("payment note derivation failed: {e}"))?;
    let expected_commitment = commit(output.value_spark, &recipient.blinding);
    if expected_commitment.0 != output.commitment.compressed_point.0 {
        return Err("recovered payment blinding does not open the output commitment".to_string());
    }
    Ok(Some(recipient.blinding))
}

/// Derive the genesis blinding factor for this validator's initial stake UTXO.
/// This is deterministic from the hybrid seed.
fn derive_genesis_blinding(hybrid_seed: &[u8; 32]) -> [u8; 32] {
    use indra_crypto::hybrid::ClassicalKeypair;

    let classical = ClassicalKeypair::from_seed(hybrid_seed);
    let classical_pk = classical.public_key().0;
    indra_crypto::derive_genesis_utxo_blinding_from_classical_pk(&classical_pk)
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

#[cfg(test)]
mod tests {
    use super::*;
    use indra_cli::{build_transaction, tx_builder::DUST_LIMIT_SPARK, TxParams, Wallet};
    use indra_core::{
        codec::Decode,
        types::{crypto::HybridPubKey, primitives::DEFAULT_CHAIN_ID},
        Bytes32, VariableBytes,
    };
    use indra_crypto::{
        hybrid::{ClassicalKeypair, PqKeypair},
        PaymentKeypairV1,
    };

    fn hybrid_material(seed_byte: u8) -> ([u8; 32], Vec<u8>, HybridPubKey) {
        let seed = [seed_byte; 32];
        let classical = ClassicalKeypair::from_seed(&seed);
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let pubkey = HybridPubKey {
            classical_pk: Bytes32::from(classical.public_key().0),
            pq_pk: VariableBytes::from_slice(&pq.public_key().0).unwrap(),
        };
        (seed, pq.secret_key_bytes(), pubkey)
    }

    fn pubkey_hex(pubkey: &HybridPubKey) -> String {
        format!(
            "{}:{}",
            hex::encode(pubkey.classical_pk.0),
            hex::encode(pubkey.pq_pk.as_slice())
        )
    }

    fn source_wallet() -> Wallet {
        let mut wallet = Wallet::new();
        wallet.add_utxo(Bytes32::from([0xA0; 32]), 10_000_000, [0x01; 32], 1, 0, 0);
        wallet
    }

    fn build_received_payment() -> (
        indra_cli::BuiltTransaction,
        TransactionV1,
        PaymentKeypairV1,
        [u8; 32],
        Vec<u8>,
        HybridPubKey,
    ) {
        let wallet = source_wallet();
        let (sender_seed, sender_pq_sk, sender_pubkey) = hybrid_material(0x42);
        let (recipient_seed, recipient_pq_sk, recipient_pubkey) = hybrid_material(0x61);
        let payment_keypair = PaymentKeypairV1::generate();
        let params = TxParams {
            chain_id: DEFAULT_CHAIN_ID,
            recipient_pubkey_hex: &pubkey_hex(&recipient_pubkey),
            amount_spark: 2_000_000,
            fee_spark: indra_cli::tx_builder::MIN_FEE_SPARK,
            wallet: &wallet,
            hybrid_seed: sender_seed,
            pq_sk_bytes: sender_pq_sk,
            sender_pubkey,
            recipient_payment_pubkey: Some(payment_keypair.public_key()),
        };
        let built = build_transaction(&params).unwrap();
        let tx = TransactionV1::decode_exact(&hex::decode(&built.tx_hex).unwrap()).unwrap();
        (
            built,
            tx,
            payment_keypair,
            recipient_seed,
            recipient_pq_sk,
            recipient_pubkey,
        )
    }

    fn recipient_rpc_utxo(tx: &TransactionV1) -> RpcUtxo {
        let height = 7;
        let tx_index = 0;
        let out_index = 0;
        RpcUtxo {
            utxo_id: UtxoSet::compute_utxo_id(&tx.outputs[0], height, tx_index, out_index),
            value: tx.outputs[0].value_spark,
            created_height: height,
            tx_index,
            out_index,
        }
    }

    #[test]
    fn scanner_recovers_blinding_from_stage5_transaction_note() {
        let (built, tx, payment_keypair, _, _, _) = build_received_payment();
        let utxo = recipient_rpc_utxo(&tx);

        let recovered =
            recover_payment_note_blinding(&tx, &utxo, &payment_keypair, DEFAULT_CHAIN_ID)
                .unwrap()
                .unwrap();

        assert_eq!(recovered, built.recipient_blinding);
        assert_eq!(
            tx.outputs[0].commitment.compressed_point.0,
            commit(utxo.value, &recovered).0
        );
    }

    #[test]
    fn malformed_payment_note_fails_commitment_opening_check() {
        let (_, mut tx, payment_keypair, _, _, _) = build_received_payment();
        let utxo = recipient_rpc_utxo(&tx);
        tx.payment_notes[0].as_mut().unwrap().note_nonce = [0x99; 32];

        let err = recover_payment_note_blinding(&tx, &utxo, &payment_keypair, DEFAULT_CHAIN_ID)
            .unwrap_err();
        assert!(err.contains("does not open"));
    }

    #[test]
    fn scanner_ignores_legacy_utxo_with_no_payment_note() {
        let wallet = source_wallet();
        let (sender_seed, sender_pq_sk, sender_pubkey) = hybrid_material(0x42);
        let (_, _, recipient_pubkey) = hybrid_material(0x62);
        let params = TxParams {
            chain_id: DEFAULT_CHAIN_ID,
            recipient_pubkey_hex: &pubkey_hex(&recipient_pubkey),
            amount_spark: 2_000_000,
            fee_spark: indra_cli::tx_builder::MIN_FEE_SPARK,
            wallet: &wallet,
            hybrid_seed: sender_seed,
            pq_sk_bytes: sender_pq_sk,
            sender_pubkey,
            recipient_payment_pubkey: None,
        };
        let built = build_transaction(&params).unwrap();
        let tx = TransactionV1::decode_exact(&hex::decode(&built.tx_hex).unwrap()).unwrap();
        let utxo = recipient_rpc_utxo(&tx);

        assert_eq!(
            recover_payment_note_blinding(
                &tx,
                &utxo,
                &PaymentKeypairV1::generate(),
                DEFAULT_CHAIN_ID,
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn recovered_payment_utxo_is_spendable_by_recipient_wallet() {
        let (built, tx, payment_keypair, recipient_seed, recipient_pq_sk, recipient_pubkey) =
            build_received_payment();
        let utxo = recipient_rpc_utxo(&tx);
        let recovered =
            recover_payment_note_blinding(&tx, &utxo, &payment_keypair, DEFAULT_CHAIN_ID)
                .unwrap()
                .unwrap();

        let mut wallet = Wallet::new();
        wallet.add_utxo(
            utxo.utxo_id,
            utxo.value,
            recovered,
            utxo.created_height,
            utxo.tx_index,
            utxo.out_index,
        );
        assert_eq!(
            wallet.get(&utxo.utxo_id).unwrap().blinding,
            built.recipient_blinding
        );

        let (_, _, destination_pubkey) = hybrid_material(0x73);
        let wallet = Wallet::from_json(&wallet.to_json()).unwrap();
        let spend_params = TxParams {
            chain_id: DEFAULT_CHAIN_ID,
            recipient_pubkey_hex: &pubkey_hex(&destination_pubkey),
            amount_spark: 1_000_000,
            fee_spark: indra_cli::tx_builder::MIN_FEE_SPARK,
            wallet: &wallet,
            hybrid_seed: recipient_seed,
            pq_sk_bytes: recipient_pq_sk,
            sender_pubkey: recipient_pubkey,
            recipient_payment_pubkey: None,
        };

        let spend = build_transaction(&spend_params).unwrap();
        let spend_tx = TransactionV1::decode_exact(&hex::decode(&spend.tx_hex).unwrap()).unwrap();
        assert_eq!(spend_tx.inputs.len(), 1);
        assert_eq!(spend_tx.inputs[0].utxo_id, utxo.utxo_id);
        assert!(spend.change_spark > DUST_LIMIT_SPARK);
    }
}
