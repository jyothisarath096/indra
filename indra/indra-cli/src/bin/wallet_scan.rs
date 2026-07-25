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

use indra_core::{
    codec::Decode,
    types::{
        primitives::{
            Bytes32, COMPACT_STAKE_BOND_RELEASE_BLINDING_DOMAIN,
            NORMAL_STAKE_BOND_RELEASE_BLINDING_DOMAIN, STAKING_REWARD_BLINDING_DOMAIN,
        },
        transaction::{OutputV1, TransactionV1},
    },
};
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
    let scan_auth_proof =
        match indra_cli::build_legacy_scan_auth_proof(&node_url, &keys, &address_hex) {
            Ok(proof) => proof,
            Err(e) => {
                eprintln!("Error building scan authorization proof: {}", e);
                std::process::exit(1);
            }
        };
    match query_utxos(&node_url, &address_hex, &scan_auth_proof) {
        Ok(response) => {
            println!("Node response: {}", response);
            let discovered = parse_utxos_json(&response);
            let genesis_blinding = derive_genesis_blinding(&hybrid_seed);
            let mut chain_id = None::<String>;
            let mut added = 0usize;
            let mut reconciled = 0usize;
            let mut recovered_payment_notes = 0usize;
            let mut recovered_protocol = 0usize;
            let mut unrecoverable_protocol = 0usize;
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
                match recover_payment_note_if_available(&node_url, &utxo, &keys, &mut chain_id) {
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
                match recover_protocol_provenance_from_node(
                    &node_url,
                    &address_hex,
                    &scan_auth_proof,
                    &utxo,
                ) {
                    Ok(ProtocolRecovery::Recovered { category, blinding }) => {
                        wallet.add_utxo(
                            utxo.utxo_id,
                            utxo.value,
                            blinding,
                            utxo.created_height,
                            utxo.tx_index,
                            utxo.out_index,
                        );
                        recovered_protocol += 1;
                        println!(
                            "Recovered protocol UTXO {} via {}.",
                            hex::encode(utxo.utxo_id.0),
                            category
                        );
                    }
                    Ok(ProtocolRecovery::Unrecoverable { category, reason }) => {
                        unrecoverable_protocol += 1;
                        println!(
                            "Unrecoverable protocol UTXO {} ({category}): {reason}",
                            hex::encode(utxo.utxo_id.0)
                        );
                    }
                    Ok(ProtocolRecovery::NotProtocolGenerated) => {}
                    Err(e) => {
                        eprintln!("Error recovering protocol-generated UTXO: {}", e);
                        std::process::exit(1);
                    }
                }
            }

            if added > 0 || reconciled > 0 || recovered_payment_notes > 0 || recovered_protocol > 0
            {
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
            if recovered_protocol > 0 {
                println!(
                    "Recovered {} protocol-generated UTXO(s) automatically.",
                    recovered_protocol
                );
            }
            if unrecoverable_protocol > 0 {
                println!(
                    "Reported {} protocol-generated UTXO(s) as unrecoverable.",
                    unrecoverable_protocol
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
fn query_utxos(node_url: &str, address_hex: &str, scan_auth_proof: &str) -> Result<String, String> {
    indra_cli::rpc_call_raw_params(
        node_url,
        "indra_getLegacyUtxosAuthorized",
        &[
            indra_cli::json_string(address_hex),
            scan_auth_proof.to_string(),
        ],
    )
    .map_err(|e| e.to_string())
}

fn query_utxo_provenance(
    node_url: &str,
    address_hex: &str,
    scan_auth_proof: &str,
    utxo_id: Bytes32,
) -> Result<String, String> {
    indra_cli::rpc_call_raw_params(
        node_url,
        "indra_explainUtxoProvenanceAuthorized",
        &[
            indra_cli::json_string(address_hex),
            scan_auth_proof.to_string(),
            indra_cli::json_string(&hex::encode(utxo_id.0)),
        ],
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

fn recover_payment_note_if_available(
    node_url: &str,
    utxo: &RpcUtxo,
    keys: &indra_cli::KeysFile,
    chain_id: &mut Option<String>,
) -> Result<Option<[u8; 32]>, String> {
    if keys.payment_keypair.is_none() {
        return Ok(None);
    }
    let chain_id_ref = match chain_id.as_deref() {
        Some(chain_id) => chain_id,
        None => {
            let fetched = indra_cli::fetch_chain_id(node_url).map_err(|e| e.to_string())?;
            chain_id.insert(fetched).as_str()
        }
    };
    recover_payment_note_from_node(node_url, utxo, keys, chain_id_ref)
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

fn recover_protocol_provenance_from_node(
    node_url: &str,
    address_hex: &str,
    scan_auth_proof: &str,
    utxo: &RpcUtxo,
) -> Result<ProtocolRecovery, String> {
    let response = query_utxo_provenance(node_url, address_hex, scan_auth_proof, utxo.utxo_id)?;
    recover_protocol_provenance_from_response(utxo, &response)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProtocolRecovery {
    Recovered {
        category: String,
        blinding: [u8; 32],
    },
    Unrecoverable {
        category: String,
        reason: String,
    },
    NotProtocolGenerated,
}

fn recover_protocol_provenance_from_response(
    utxo: &RpcUtxo,
    response: &str,
) -> Result<ProtocolRecovery, String> {
    let root: serde_json::Value =
        serde_json::from_str(response).map_err(|e| format!("bad provenance JSON: {e}"))?;
    let provenance = provenance_result_object(&root)?;
    verify_provenance_utxo_fields(utxo, provenance)?;

    let category = json_str(provenance, "category")?.to_string();
    let recoverable = provenance
        .get("recoverable")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| "provenance response missing recoverable flag".to_string())?;

    if !recoverable {
        let reason = provenance
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("node reported this UTXO is not recoverable")
            .to_string();
        return Ok(match category.as_str() {
            "ordinary_transaction_output" | "genesis" => ProtocolRecovery::NotProtocolGenerated,
            _ => ProtocolRecovery::Unrecoverable { category, reason },
        });
    }

    let context = provenance
        .get("context")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "recoverable provenance response missing context object".to_string())?;
    let blinding = derive_protocol_blinding(&category, context)?;
    let output = provenance_output(provenance)?;
    let expected_commitment = commit(output.value_spark, &blinding);
    if expected_commitment.0 != output.commitment.compressed_point.0 {
        return Err(format!(
            "recovered protocol blinding for {category} does not open the output commitment"
        ));
    }
    Ok(ProtocolRecovery::Recovered { category, blinding })
}

fn provenance_result_object(root: &serde_json::Value) -> Result<&serde_json::Value, String> {
    if let Some(error) = root.get("error") {
        return Err(format!("provenance RPC error: {error}"));
    }
    if let Some(result) = root.get("result") {
        return Ok(result);
    }
    Ok(root)
}

fn verify_provenance_utxo_fields(utxo: &RpcUtxo, root: &serde_json::Value) -> Result<(), String> {
    let response_utxo_id = decode_hex32(json_str(root, "utxo_id")?, "utxo_id")?;
    if response_utxo_id != utxo.utxo_id.0 {
        return Err("provenance response UTXO ID does not match requested UTXO".to_string());
    }
    let amount = json_u64(root, "amount")?;
    if amount != utxo.value {
        return Err("provenance response amount does not match discovered UTXO".to_string());
    }
    if json_u64(root, "created_height")? != utxo.created_height {
        return Err("provenance response height does not match discovered UTXO".to_string());
    }
    if json_u64(root, "tx_index")? != u64::from(utxo.tx_index) {
        return Err("provenance response tx_index does not match discovered UTXO".to_string());
    }
    if json_u64(root, "out_index")? != u64::from(utxo.out_index) {
        return Err("provenance response out_index does not match discovered UTXO".to_string());
    }

    let output = provenance_output(root)?;
    let computed_utxo_id =
        UtxoSet::compute_utxo_id(&output, utxo.created_height, utxo.tx_index, utxo.out_index);
    if computed_utxo_id != utxo.utxo_id {
        return Err("provenance output_hex does not compute to the discovered UTXO ID".to_string());
    }
    if output.value_spark != utxo.value {
        return Err("provenance output value does not match discovered UTXO".to_string());
    }
    let commitment = decode_hex32(json_str(root, "commitment")?, "commitment")?;
    if commitment != output.commitment.compressed_point.0 {
        return Err("provenance commitment does not match output_hex".to_string());
    }

    Ok(())
}

fn provenance_output(root: &serde_json::Value) -> Result<OutputV1, String> {
    let output_hex = json_str(root, "output_hex")?;
    let bytes = hex::decode(output_hex).map_err(|_| "bad provenance output_hex".to_string())?;
    OutputV1::decode_exact(&bytes).map_err(|e| format!("bad provenance output encoding: {e}"))
}

fn derive_protocol_blinding(
    category: &str,
    context: &serde_json::Map<String, serde_json::Value>,
) -> Result<[u8; 32], String> {
    match category {
        "staking_reward_claim" => derive_staking_reward_from_context(context, "claim_height"),
        "validator_eviction_pending_reward" => {
            derive_staking_reward_from_context(context, "returned_height")
        }
        "validator_eviction_bond_refund" => {
            let validator_id = context_hex32(context, "validator_id")?;
            let delegator_id = context_hex32(context, "delegator_id")?;
            let bond_utxo_id = context_hex32(context, "bond_utxo_id")?;
            let release_height = context_u64(context, "returned_height")?;
            let amount_spark = context_u64(context, "amount_spark")?;
            Ok(derive_compact_bond_release_blinding(
                &validator_id,
                &delegator_id,
                &bond_utxo_id,
                release_height,
                amount_spark,
            ))
        }
        "normal_bond_release" => {
            let validator_id = context_hex32(context, "validator_id")?;
            let delegator_id = context_hex32(context, "delegator_id")?;
            let bond_utxo_id = context_hex32(context, "bond_utxo_id")?;
            let release_height = context_u64(context, "returned_height")?;
            let amount_spark = context_u64(context, "amount_spark")?;
            Ok(derive_normal_bond_release_blinding(
                &validator_id,
                &delegator_id,
                &bond_utxo_id,
                release_height,
                amount_spark,
            ))
        }
        "slash_reporter_reward" => {
            let evidence_hash = context_hex32(context, "evidence_hash")?;
            let block_height = context_u64(context, "block_height")?;
            Ok(derive_slash_reward_blinding(&evidence_hash, block_height))
        }
        "governance_deposit_change" => {
            let proposal_id = context_hex32(context, "proposal_id")?;
            Ok(derive_governance_change_blinding(&proposal_id))
        }
        "governance_deposit_refund" => {
            let proposal_id = context_hex32(context, "proposal_id")?;
            Ok(derive_governance_refund_blinding(&proposal_id))
        }
        _ => Err(format!(
            "node reported unsupported recoverable provenance category: {category}"
        )),
    }
}

fn derive_staking_reward_from_context(
    context: &serde_json::Map<String, serde_json::Value>,
    height_field: &str,
) -> Result<[u8; 32], String> {
    let validator_id = context_hex32(context, "validator_id")?;
    let delegator_id = context_hex32(context, "delegator_id")?;
    let height = context_u64(context, height_field)?;
    Ok(derive_staking_reward_blinding(
        &validator_id,
        &delegator_id,
        height,
    ))
}

fn derive_staking_reward_blinding(
    validator_id: &[u8; 32],
    delegator_id: &[u8; 32],
    height: u64,
) -> [u8; 32] {
    let mut data = Vec::with_capacity(STAKING_REWARD_BLINDING_DOMAIN.len() + 32 + 32 + 8);
    data.extend_from_slice(STAKING_REWARD_BLINDING_DOMAIN);
    data.extend_from_slice(validator_id);
    data.extend_from_slice(delegator_id);
    data.extend_from_slice(&height.to_le_bytes());
    indra_crypto::sha256(&data)
}

fn derive_compact_bond_release_blinding(
    validator_id: &[u8; 32],
    delegator_id: &[u8; 32],
    bond_utxo_id: &[u8; 32],
    release_height: u64,
    amount_spark: u64,
) -> [u8; 32] {
    let mut data =
        Vec::with_capacity(COMPACT_STAKE_BOND_RELEASE_BLINDING_DOMAIN.len() + 32 + 32 + 32 + 8 + 8);
    data.extend_from_slice(COMPACT_STAKE_BOND_RELEASE_BLINDING_DOMAIN);
    data.extend_from_slice(validator_id);
    data.extend_from_slice(delegator_id);
    data.extend_from_slice(bond_utxo_id);
    data.extend_from_slice(&release_height.to_le_bytes());
    data.extend_from_slice(&amount_spark.to_le_bytes());
    indra_crypto::sha256(&data)
}

fn derive_normal_bond_release_blinding(
    validator_id: &[u8; 32],
    delegator_id: &[u8; 32],
    bond_utxo_id: &[u8; 32],
    release_height: u64,
    amount_spark: u64,
) -> [u8; 32] {
    let mut data =
        Vec::with_capacity(NORMAL_STAKE_BOND_RELEASE_BLINDING_DOMAIN.len() + 32 + 32 + 32 + 8 + 8);
    data.extend_from_slice(NORMAL_STAKE_BOND_RELEASE_BLINDING_DOMAIN);
    data.extend_from_slice(validator_id);
    data.extend_from_slice(delegator_id);
    data.extend_from_slice(bond_utxo_id);
    data.extend_from_slice(&release_height.to_le_bytes());
    data.extend_from_slice(&amount_spark.to_le_bytes());
    indra_crypto::sha256(&data)
}

fn derive_slash_reward_blinding(evidence_hash: &[u8; 32], block_height: u64) -> [u8; 32] {
    let mut data = b"INDRA-SLASH-REWARD-BLINDING-v1".to_vec();
    data.extend_from_slice(evidence_hash);
    data.extend_from_slice(&block_height.to_le_bytes());
    indra_crypto::sha256(&data)
}

fn derive_governance_refund_blinding(proposal_id: &[u8; 32]) -> [u8; 32] {
    indra_crypto::sha256(
        &[
            b"governance-refund-blinding".as_slice(),
            proposal_id.as_slice(),
        ]
        .concat(),
    )
}

fn derive_governance_change_blinding(proposal_id: &[u8; 32]) -> [u8; 32] {
    indra_crypto::sha256(
        &[
            b"governance-deposit-change-blinding".as_slice(),
            proposal_id.as_slice(),
        ]
        .concat(),
    )
}

fn context_hex32(
    context: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<[u8; 32], String> {
    let value = context
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("provenance context missing {field}"))?;
    decode_hex32(value, field)
}

fn context_u64(
    context: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<u64, String> {
    context
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("provenance context missing numeric {field}"))
}

fn json_str<'a>(root: &'a serde_json::Value, field: &str) -> Result<&'a str, String> {
    root.get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("provenance response missing {field}"))
}

fn json_u64(root: &serde_json::Value, field: &str) -> Result<u64, String> {
    root.get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("provenance response missing numeric {field}"))
}

fn decode_hex32(value: &str, field: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|_| format!("{field} must be 32-byte hex"))?;
    if bytes.len() != 32 {
        return Err(format!("{field} must be 32-byte hex"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Derive the genesis blinding factor for this validator's initial stake UTXO.
/// This is deterministic from the hybrid seed.
fn derive_genesis_blinding(hybrid_seed: &[u8; 32]) -> [u8; 32] {
    use indra_crypto::hybrid::ClassicalKeypair;

    let classical = ClassicalKeypair::from_seed(hybrid_seed);
    let classical_pk = classical.public_key().0;
    indra_crypto::derive_genesis_utxo_blinding_from_classical_pk(&classical_pk)
}

#[derive(Debug, Clone)]
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
        codec::{Decode, Encode},
        types::{
            block::{BlockHeaderV1, BlockV1, NO_POLC_ROUND},
            crypto::{HybridPubKey, HybridSignature},
            primitives::{DEFAULT_CHAIN_ID, MAX_VRF_PROOF_BYTES, STAKING_TX_IDX},
            staking::{StakingOp, StakingOpBody},
        },
        Bytes32, CommitmentV1, ProtocolVersion, VariableBytes,
    };
    use indra_crypto::{
        hybrid::{ClassicalKeypair, PqKeypair},
        PaymentKeypairV1,
    };
    use indra_keystore::generate_keypairs;
    use indra_rpc::{handlers::RpcEngineView, server::call_rpc};
    use indra_state::ChainState;
    use std::collections::BTreeMap;

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

    struct BlockBackedEngine {
        chain: ChainState,
        blocks: BTreeMap<u64, BlockV1>,
    }

    impl RpcEngineView for BlockBackedEngine {
        fn chain_state(&self) -> &ChainState {
            &self.chain
        }

        fn mempool_size(&self) -> usize {
            0
        }

        fn pruned_mode(&self) -> bool {
            false
        }

        fn lowest_block(&self) -> u64 {
            0
        }

        fn blocks_retained(&self) -> usize {
            self.blocks.len()
        }

        fn get_block_by_height(&self, height: u64) -> Result<Option<BlockV1>, String> {
            Ok(self.blocks.get(&height).cloned())
        }
    }

    fn dummy_signature(byte: u8) -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[byte; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[byte; 32]).unwrap(),
        }
    }

    fn dummy_block(height: u64) -> BlockV1 {
        BlockV1 {
            header: BlockHeaderV1 {
                protocol_version: ProtocolVersion::CURRENT,
                height,
                prev_hash: Bytes32::from([0x01; 32]),
                timestamp: 1_700_000_000 + height,
                state_root: Bytes32::from([0x02; 32]),
                validator_set_root: Bytes32::from([0x03; 32]),
                mempool_set_root: Bytes32::from([0x04; 32]),
                value_hash: Bytes32::from([0x05; 32]),
                base_fee: 100,
                proposer_round: 0,
                polc_round: NO_POLC_ROUND,
                proposer_vrf_output: Bytes32::from([0x06; 32]),
                proposer_vrf_proof: VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[0x07; 64])
                    .unwrap(),
                quorum_certificate: VariableBytes::from_slice(&[]).unwrap(),
                election_result_hash: None,
            },
            transactions: Vec::new(),
            slashing_evidence: Vec::new(),
            governance_ops: Vec::new(),
            staking_ops: Vec::new(),
            vrf_reveals: Vec::new(),
        }
    }

    fn owned_protocol_output(amount: u64, blinding: [u8; 32]) -> OutputV1 {
        let (_, _, owner_pubkey) = hybrid_material(0xA8);
        OutputV1 {
            value_spark: amount,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from(commit(amount, &blinding).0),
            },
            owner_pubkey,
            range_proof: VariableBytes::from_slice(&[0x55; 32]).unwrap(),
            lock_height: 0,
        }
    }

    fn protocol_response(
        category: &str,
        context: &str,
        amount: u64,
        height: u64,
        tx_index: u32,
        out_index: u32,
        blinding: [u8; 32],
    ) -> (RpcUtxo, String) {
        let output = owned_protocol_output(amount, blinding);
        let utxo_id = UtxoSet::compute_utxo_id(&output, height, tx_index, out_index);
        let response = format!(
            r#"{{"address":"{}","utxo_id":"{}","amount":{},"created_height":{},"tx_index":{},"out_index":{},"lock_height":{},"commitment":"{}","output_hex":"{}","category":"{}","recoverable":true,"context":{},"reason":null}}"#,
            "aa".repeat(32),
            hex::encode(utxo_id.0),
            amount,
            height,
            tx_index,
            out_index,
            output.lock_height,
            hex::encode(output.commitment.compressed_point.0),
            hex::encode(output.encode_to_vec()),
            category,
            context,
        );
        (
            RpcUtxo {
                utxo_id,
                value: amount,
                created_height: height,
                tx_index,
                out_index,
            },
            response,
        )
    }

    fn unrecoverable_response(category: &str, reason: &str) -> (RpcUtxo, String) {
        let output = owned_protocol_output(4_000_000, [0xFE; 32]);
        let height = 12;
        let tx_index = indra_core::types::primitives::STAKING_TX_IDX;
        let out_index = 1;
        let utxo_id = UtxoSet::compute_utxo_id(&output, height, tx_index, out_index);
        let response = format!(
            r#"{{"address":"{}","utxo_id":"{}","amount":{},"created_height":{},"tx_index":{},"out_index":{},"lock_height":{},"commitment":"{}","output_hex":"{}","category":"{}","recoverable":false,"context":null,"reason":"{}"}}"#,
            "aa".repeat(32),
            hex::encode(utxo_id.0),
            output.value_spark,
            height,
            tx_index,
            out_index,
            output.lock_height,
            hex::encode(output.commitment.compressed_point.0),
            hex::encode(output.encode_to_vec()),
            category,
            reason,
        );
        (
            RpcUtxo {
                utxo_id,
                value: output.value_spark,
                created_height: height,
                tx_index,
                out_index,
            },
            response,
        )
    }

    fn assert_recovered_wallet_entry(
        category: &str,
        context: String,
        blinding: [u8; 32],
    ) -> (Wallet, RpcUtxo) {
        let (utxo, response) = protocol_response(
            category,
            &context,
            4_000_000,
            12,
            indra_core::types::primitives::STAKING_TX_IDX,
            0,
            blinding,
        );
        let recovered = recover_protocol_provenance_from_response(&utxo, &response).unwrap();
        let ProtocolRecovery::Recovered {
            category: recovered_category,
            blinding: recovered_blinding,
        } = recovered
        else {
            panic!("expected recovered provenance");
        };
        assert_eq!(recovered_category, category);
        assert_eq!(recovered_blinding, blinding);

        let mut wallet = Wallet::new();
        wallet.add_utxo(
            utxo.utxo_id,
            utxo.value,
            recovered_blinding,
            utxo.created_height,
            utxo.tx_index,
            utxo.out_index,
        );
        let restored = Wallet::from_json(&wallet.to_json()).unwrap();
        let entry = restored.get(&utxo.utxo_id).unwrap();
        assert_eq!(entry.blinding, blinding);
        assert_eq!(
            commit(entry.value_spark, &entry.blinding).0,
            commit(utxo.value, &blinding).0
        );
        (restored, utxo)
    }

    fn hex32(byte: u8) -> String {
        hex::encode([byte; 32])
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

    #[test]
    fn scanner_recovers_reward_claim_via_protocol_provenance() {
        let validator_id = [0x11; 32];
        let delegator_id = [0x12; 32];
        let height = 12;
        let blinding = derive_staking_reward_blinding(&validator_id, &delegator_id, height);
        let context = format!(
            r#"{{"validator_id":"{}","delegator_id":"{}","claim_height":{}}}"#,
            hex::encode(validator_id),
            hex::encode(delegator_id),
            height
        );

        assert_recovered_wallet_entry("staking_reward_claim", context, blinding);
    }

    #[test]
    fn scanner_recovers_validator_eviction_pending_reward_via_protocol_provenance() {
        let validator_id = [0x21; 32];
        let delegator_id = [0x22; 32];
        let height = 12;
        let blinding = derive_staking_reward_blinding(&validator_id, &delegator_id, height);
        let context = format!(
            r#"{{"validator_id":"{}","delegator_id":"{}","bond_utxo_id":"{}","returned_height":{},"returned_epoch":0,"amount_spark":4000000,"derivation":"pending_reward_payout"}}"#,
            hex::encode(validator_id),
            hex::encode(delegator_id),
            hex32(0x23),
            height
        );

        assert_recovered_wallet_entry("validator_eviction_pending_reward", context, blinding);
    }

    #[test]
    fn scanner_recovers_validator_eviction_compact_bond_refund_via_protocol_provenance() {
        let validator_id = [0x31; 32];
        let delegator_id = [0x32; 32];
        let bond_utxo_id = [0x33; 32];
        let height = 12;
        let amount = 4_000_000;
        let blinding = derive_compact_bond_release_blinding(
            &validator_id,
            &delegator_id,
            &bond_utxo_id,
            height,
            amount,
        );
        let context = format!(
            r#"{{"validator_id":"{}","delegator_id":"{}","bond_utxo_id":"{}","returned_height":{},"returned_epoch":0,"amount_spark":{},"derivation":"compact_bond_release"}}"#,
            hex::encode(validator_id),
            hex::encode(delegator_id),
            hex::encode(bond_utxo_id),
            height,
            amount
        );

        assert_recovered_wallet_entry("validator_eviction_bond_refund", context, blinding);
    }

    #[test]
    fn scanner_recovers_normal_bond_release_via_protocol_provenance() {
        let validator_id = [0x34; 32];
        let delegator_id = [0x35; 32];
        let bond_utxo_id = [0x36; 32];
        let height = 12;
        let amount = 4_000_000;
        let blinding = derive_normal_bond_release_blinding(
            &validator_id,
            &delegator_id,
            &bond_utxo_id,
            height,
            amount,
        );
        let context = format!(
            r#"{{"validator_id":"{}","delegator_id":"{}","bond_utxo_id":"{}","returned_height":{},"returned_epoch":0,"amount_spark":{},"derivation":"normal_bond_release"}}"#,
            hex::encode(validator_id),
            hex::encode(delegator_id),
            hex::encode(bond_utxo_id),
            height,
            amount
        );

        assert_recovered_wallet_entry("normal_bond_release", context, blinding);
    }

    #[test]
    fn scanner_recovers_slash_reporter_reward_via_protocol_provenance() {
        let evidence_hash = [0x41; 32];
        let height = 12;
        let blinding = derive_slash_reward_blinding(&evidence_hash, height);
        let context = format!(
            r#"{{"evidence_hash":"{}","block_height":{}}}"#,
            hex::encode(evidence_hash),
            height
        );

        assert_recovered_wallet_entry("slash_reporter_reward", context, blinding);
    }

    #[test]
    fn scanner_recovers_governance_deposit_change_via_protocol_provenance() {
        let proposal_id = [0x51; 32];
        let blinding = derive_governance_change_blinding(&proposal_id);
        let context = format!(
            r#"{{"proposal_id":"{}","proposer_id":"{}","proposed_epoch":0}}"#,
            hex::encode(proposal_id),
            hex32(0x52)
        );

        assert_recovered_wallet_entry("governance_deposit_change", context, blinding);
    }

    #[test]
    fn scanner_recovers_governance_deposit_refund_via_protocol_provenance() {
        let proposal_id = [0x61; 32];
        let blinding = derive_governance_refund_blinding(&proposal_id);
        let context = format!(
            r#"{{"proposal_id":"{}","proposer_id":"{}","proposed_epoch":0}}"#,
            hex::encode(proposal_id),
            hex32(0x62)
        );

        assert_recovered_wallet_entry("governance_deposit_refund", context, blinding);
    }

    #[test]
    fn scanner_rejects_malformed_protocol_provenance_response() {
        let validator_id = [0x71; 32];
        let delegator_id = [0x72; 32];
        let height = 12;
        let real_blinding = derive_staking_reward_blinding(&validator_id, &delegator_id, height);
        let wrong_delegator = [0x73; 32];
        let context = format!(
            r#"{{"validator_id":"{}","delegator_id":"{}","claim_height":{}}}"#,
            hex::encode(validator_id),
            hex::encode(wrong_delegator),
            height
        );
        let (utxo, response) = protocol_response(
            "staking_reward_claim",
            &context,
            4_000_000,
            height,
            indra_core::types::primitives::STAKING_TX_IDX,
            0,
            real_blinding,
        );

        let err = recover_protocol_provenance_from_response(&utxo, &response).unwrap_err();
        assert!(err.contains("does not open"), "{err}");
    }

    #[test]
    fn scanner_rejects_malformed_normal_bond_release_provenance_response() {
        let validator_id = [0x74; 32];
        let delegator_id = [0x75; 32];
        let bond_utxo_id = [0x76; 32];
        let wrong_bond_utxo_id = [0x77; 32];
        let height = 12;
        let amount = 4_000_000;
        let real_blinding = derive_normal_bond_release_blinding(
            &validator_id,
            &delegator_id,
            &bond_utxo_id,
            height,
            amount,
        );
        let context = format!(
            r#"{{"validator_id":"{}","delegator_id":"{}","bond_utxo_id":"{}","returned_height":{},"returned_epoch":0,"amount_spark":{},"derivation":"normal_bond_release"}}"#,
            hex::encode(validator_id),
            hex::encode(delegator_id),
            hex::encode(wrong_bond_utxo_id),
            height,
            amount
        );
        let (utxo, response) = protocol_response(
            "normal_bond_release",
            &context,
            amount,
            height,
            indra_core::types::primitives::STAKING_TX_IDX,
            0,
            real_blinding,
        );

        let err = recover_protocol_provenance_from_response(&utxo, &response).unwrap_err();
        assert!(err.contains("does not open"), "{err}");
    }

    #[test]
    fn scanner_parses_real_rpc_provenance_envelope() {
        let mut keys =
            generate_keypairs("claimant".to_string(), [0x80; 32], [0x81; 32], [0x82; 32]).unwrap();
        keys.payment_keypair = None;
        keys.public.payment_pubkey = None;

        let owner = HybridPubKey {
            classical_pk: Bytes32::from(keys.public.hybrid_classical_pk),
            pq_pk: VariableBytes::from_slice(&keys.public.hybrid_pq_pk).unwrap(),
        };
        let validator_id = Bytes32::from(indra_crypto::sha256(&owner.classical_pk.0));
        let delegator_id = validator_id;
        let height = 12;
        let amount = 4_000_000;
        let blinding = derive_staking_reward_blinding(&validator_id.0, &delegator_id.0, height);
        let output = OutputV1 {
            value_spark: amount,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from(commit(amount, &blinding).0),
            },
            owner_pubkey: owner.clone(),
            range_proof: VariableBytes::from_slice(&[0x83; 32]).unwrap(),
            lock_height: 0,
        };
        let mut chain = ChainState::new_genesis();
        chain.height = height;
        let utxo_id = chain
            .utxos
            .insert(output, height, STAKING_TX_IDX, 0)
            .unwrap();
        let mut block = dummy_block(height);
        block.staking_ops.push(StakingOp {
            body: StakingOpBody::ClaimRewards {
                validator_id,
                delegator_pubkey: owner,
            },
            nonce: 1,
            signature: dummy_signature(0x84),
        });
        let engine = BlockBackedEngine {
            chain,
            blocks: [(height, block)].into_iter().collect(),
        };

        let address_hex = hex::encode(indra_crypto::sha256(&keys.public.hybrid_classical_pk));
        let challenge_response = call_rpc(
            "indra_getLegacyScanChallenge",
            &[indra_cli::json_string(&address_hex)],
            &engine,
        );
        let challenge_json: serde_json::Value = serde_json::from_str(&challenge_response).unwrap();
        let challenge_hex = challenge_json["result"]["challenge"].as_str().unwrap();
        let challenge = decode_hex32(challenge_hex, "challenge").unwrap();
        let msg = indra_rpc::handlers::legacy_scan_auth_message(
            decode_hex32(&address_hex, "address").unwrap(),
            challenge,
        );
        let sig = indra_cli::reconstruct_keypair(&keys)
            .unwrap()
            .sign(&msg)
            .unwrap();
        let proof = format!(
            r#"{{"version":1,"challenge":"{}","hybrid_classical_pk":"{}","hybrid_pq_pk":"{}","classical_sig":"{}","pq_sig":"{}","reserved_output_v2":null}}"#,
            challenge_hex,
            hex::encode(keys.public.hybrid_classical_pk),
            hex::encode(&keys.public.hybrid_pq_pk),
            hex::encode(sig.classical.0),
            hex::encode(sig.pq.0)
        );
        let response = call_rpc(
            "indra_explainUtxoProvenanceAuthorized",
            &[
                indra_cli::json_string(&address_hex),
                proof,
                indra_cli::json_string(&hex::encode(utxo_id.0)),
            ],
            &engine,
        );
        assert!(response.contains(r#""result":"#), "{response}");

        let utxo = RpcUtxo {
            utxo_id,
            value: amount,
            created_height: height,
            tx_index: STAKING_TX_IDX,
            out_index: 0,
        };
        let recovered = recover_protocol_provenance_from_response(&utxo, &response).unwrap();
        assert_eq!(
            recovered,
            ProtocolRecovery::Recovered {
                category: "staking_reward_claim".to_string(),
                blinding,
            }
        );
    }

    #[test]
    fn scanner_attempts_protocol_provenance_without_payment_keypair() {
        let mut keys = generate_keypairs(
            "legacy-validator".to_string(),
            [0x7A; 32],
            [0x7B; 32],
            [0x7C; 32],
        )
        .unwrap();
        keys.payment_keypair = None;
        keys.public.payment_pubkey = None;
        assert!(keys.payment_keypair.is_none());

        let validator_id = [0x7D; 32];
        let delegator_id = [0x7E; 32];
        let height = 12;
        let blinding = derive_staking_reward_blinding(&validator_id, &delegator_id, height);
        let context = format!(
            r#"{{"validator_id":"{}","delegator_id":"{}","claim_height":{}}}"#,
            hex::encode(validator_id),
            hex::encode(delegator_id),
            height
        );
        let (utxo, response) = protocol_response(
            "staking_reward_claim",
            &context,
            4_000_000,
            height,
            indra_core::types::primitives::STAKING_TX_IDX,
            0,
            blinding,
        );

        let mut chain_id = None;
        assert_eq!(
            recover_payment_note_if_available("http://127.0.0.1:1", &utxo, &keys, &mut chain_id)
                .unwrap(),
            None
        );
        let recovered = recover_protocol_provenance_from_response(&utxo, &response).unwrap();
        assert_eq!(
            recovered,
            ProtocolRecovery::Recovered {
                category: "staking_reward_claim".to_string(),
                blinding,
            }
        );
    }

    #[test]
    fn scanner_reports_legacy_and_slashed_self_stake_as_unrecoverable() {
        for (category, reason) in [
            (
                "legacy_bond_release",
                "legacy bond release requires local wallet history",
            ),
            (
                "slashed_self_stake_release",
                "slashed self-stake release requires archive provenance",
            ),
        ] {
            let (utxo, response) = unrecoverable_response(category, reason);
            let result = recover_protocol_provenance_from_response(&utxo, &response).unwrap();
            assert_eq!(
                result,
                ProtocolRecovery::Unrecoverable {
                    category: category.to_string(),
                    reason: reason.to_string()
                }
            );
        }
    }

    #[test]
    fn genesis_and_pending_change_recovery_paths_still_work() {
        let (seed, _, _) = hybrid_material(0x81);
        let genesis_blinding = derive_genesis_blinding(&seed);
        let mut wallet = Wallet::new();
        let genesis_utxo = Bytes32::from([0x82; 32]);
        wallet.add_utxo(genesis_utxo, 1_000_000, genesis_blinding, 0, 0, 0);
        assert_eq!(
            wallet.get(&genesis_utxo).unwrap().blinding,
            genesis_blinding
        );

        let change_output = owned_protocol_output(2_000_000, [0x83; 32]);
        let change_id = UtxoSet::compute_utxo_id(&change_output, 20, 0, 1);
        wallet.add_pending_change(change_output, [0x83; 32]);
        assert!(wallet.reconcile_pending_change(change_id, 20, 0, 1));
        assert_eq!(wallet.get(&change_id).unwrap().blinding, [0x83; 32]);
    }

    #[test]
    fn recovered_protocol_utxo_is_spendable_after_wallet_scan() {
        let validator_id = [0x91; 32];
        let delegator_id = [0x92; 32];
        let height = 12;
        let blinding = derive_staking_reward_blinding(&validator_id, &delegator_id, height);
        let context = format!(
            r#"{{"validator_id":"{}","delegator_id":"{}","claim_height":{}}}"#,
            hex::encode(validator_id),
            hex::encode(delegator_id),
            height
        );
        let (wallet, utxo) =
            assert_recovered_wallet_entry("staking_reward_claim", context, blinding);

        let (sender_seed, sender_pq_sk, sender_pubkey) = hybrid_material(0xA8);
        let (_, _, destination_pubkey) = hybrid_material(0xA9);
        let params = TxParams {
            chain_id: DEFAULT_CHAIN_ID,
            recipient_pubkey_hex: &pubkey_hex(&destination_pubkey),
            amount_spark: 1_000_000,
            fee_spark: indra_cli::tx_builder::MIN_FEE_SPARK,
            wallet: &wallet,
            hybrid_seed: sender_seed,
            pq_sk_bytes: sender_pq_sk,
            sender_pubkey,
            recipient_payment_pubkey: None,
        };

        let spend = build_transaction(&params).unwrap();
        let spend_tx = TransactionV1::decode_exact(&hex::decode(&spend.tx_hex).unwrap()).unwrap();
        assert_eq!(spend_tx.inputs.len(), 1);
        assert_eq!(spend_tx.inputs[0].utxo_id, utxo.utxo_id);
    }

    #[test]
    fn recovered_normal_bond_release_utxo_is_spendable_after_wallet_scan() {
        let validator_id = [0xB1; 32];
        let delegator_id = [0xB2; 32];
        let bond_utxo_id = [0xB3; 32];
        let height = 12;
        let amount = 4_000_000;
        let blinding = derive_normal_bond_release_blinding(
            &validator_id,
            &delegator_id,
            &bond_utxo_id,
            height,
            amount,
        );
        let context = format!(
            r#"{{"validator_id":"{}","delegator_id":"{}","bond_utxo_id":"{}","returned_height":{},"returned_epoch":0,"amount_spark":{},"derivation":"normal_bond_release"}}"#,
            hex::encode(validator_id),
            hex::encode(delegator_id),
            hex::encode(bond_utxo_id),
            height,
            amount
        );
        let (wallet, utxo) =
            assert_recovered_wallet_entry("normal_bond_release", context, blinding);

        let (sender_seed, sender_pq_sk, sender_pubkey) = hybrid_material(0xB4);
        let (_, _, destination_pubkey) = hybrid_material(0xB5);
        let params = TxParams {
            chain_id: DEFAULT_CHAIN_ID,
            recipient_pubkey_hex: &pubkey_hex(&destination_pubkey),
            amount_spark: 1_000_000,
            fee_spark: indra_cli::tx_builder::MIN_FEE_SPARK,
            wallet: &wallet,
            hybrid_seed: sender_seed,
            pq_sk_bytes: sender_pq_sk,
            sender_pubkey,
            recipient_payment_pubkey: None,
        };

        let spend = build_transaction(&params).unwrap();
        let spend_tx = TransactionV1::decode_exact(&hex::decode(&spend.tx_hex).unwrap()).unwrap();
        assert_eq!(spend_tx.inputs.len(), 1);
        assert_eq!(spend_tx.inputs[0].utxo_id, utxo.utxo_id);
    }
}
