use std::io::{Read, Write};
use std::net::TcpStream;

use indra_cli::{build_transaction, KeysFile, TxParams, Wallet};
use indra_core::types::{
    crypto::HybridPubKey,
    primitives::{Bytes32, VariableBytes},
};
use indra_crypto::sha256;

const SPARK_PER_INDRA: f64 = 100_000_000.0;

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
    eprintln!("  indra-tx balance --keys <keys.json> [--keys-password-file <path>] [--address <hex>] --rpc <url>");
    eprintln!("  indra-tx send --keys <keys.json> [--keys-password-file <path>] [--wallet <wallet.json>] --to <address-hex> --amount <spark> --rpc <url>");
    std::process::exit(1);
}

fn cmd_address(args: &[String]) {
    let keys_path = get_arg(args, "--keys").unwrap_or_else(|| "keys.json".to_string());
    let keys = indra_cli::load_keys_for_cli(&keys_path, args).unwrap_or_else(|e| {
        eprintln!("Error loading {}: {}", keys_path, e);
        std::process::exit(1);
    });
    let address = sha256(&keys.public.hybrid_classical_pk);
    println!("{}", hex::encode(address));
}

fn cmd_balance(args: &[String]) {
    let keys_path = get_arg(args, "--keys").unwrap_or_else(|| {
        eprintln!(
            "Error: legacy balance scans now require ownership authorization. \
             Re-run with --keys <keys.json> for the address owner."
        );
        std::process::exit(1);
    });
    let rpc = get_arg(args, "--rpc").unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let keys = indra_cli::load_keys_for_cli(&keys_path, args).unwrap_or_else(|e| {
        eprintln!("Error loading {}: {}", keys_path, e);
        std::process::exit(1);
    });
    let derived_address = hex::encode(sha256(&keys.public.hybrid_classical_pk));
    let address = get_arg(args, "--address").unwrap_or_else(|| derived_address.clone());
    if address != derived_address {
        eprintln!(
            "Error: keys.json does not own requested address {}. \
             Legacy UTXO/balance scans require the owner's keys.",
            address
        );
        std::process::exit(1);
    }
    let proof = build_auth_or_exit(&rpc, &keys, &address);
    let raw = indra_cli::rpc_call_raw_params(
        &rpc,
        "indra_getLegacyBalanceAuthorized",
        &[indra_cli::json_string(&address), proof],
    )
    .unwrap_or_else(|e| {
        eprintln!("Error querying authorized legacy balance: {}", e);
        std::process::exit(1);
    });
    let balance = extract_number(&raw, "balance").unwrap_or(0);
    println!(
        "Address: {}\nBalance: {} Spark ({:.8} INDRA)",
        address,
        balance,
        balance as f64 / SPARK_PER_INDRA
    );
}

fn cmd_send(args: &[String]) {
    let keys_path = get_arg(args, "--keys").unwrap_or_else(|| "keys.json".to_string());
    let wallet_path = get_arg(args, "--wallet").unwrap_or_else(|| "wallet.json".to_string());
    let recipient_address = required_arg(args, "--to");
    let amount_spark = required_arg(args, "--amount")
        .parse::<u64>()
        .unwrap_or_else(|_| {
            eprintln!("Error: invalid --amount");
            std::process::exit(1);
        });
    let rpc = get_arg(args, "--rpc").unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let chain_id = get_arg(args, "--chain-id")
        .unwrap_or_else(|| indra_core::types::primitives::DEFAULT_CHAIN_ID.to_string());

    let keys = indra_cli::load_keys_for_cli(&keys_path, args).unwrap_or_else(|e| {
        eprintln!("Error loading {}: {}", keys_path, e);
        std::process::exit(1);
    });
    let hybrid_seed = keys.hybrid_seed;
    let pq_sk_bytes = keys.pq_sk.clone();
    let classical_pk = keys.public.hybrid_classical_pk;
    let pq_pk = keys.public.hybrid_pq_pk.clone();
    let sender_address = hex::encode(sha256(&classical_pk));

    let proof = build_auth_or_exit(&rpc, &keys, &sender_address);
    let utxos_raw = indra_cli::rpc_call_raw_params(
        &rpc,
        "indra_getLegacyUtxosAuthorized",
        &[indra_cli::json_string(&sender_address), proof],
    )
    .unwrap_or_else(|e| {
        eprintln!("Error querying authorized legacy UTXOs: {}", e);
        std::process::exit(1);
    });
    let local_wallet = Wallet::load(&wallet_path).unwrap_or_else(|e| {
        eprintln!(
            "Error loading wallet {}: {}. Run indra-wallet-scan to recover or add spendable UTXOs with their blinding factors.",
            wallet_path, e
        );
        std::process::exit(1);
    });
    let wallet =
        spendable_wallet_from_authorized_utxos(&utxos_raw, &local_wallet).unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        });

    let recipient_pubkey = resolve_recipient_pubkey(&rpc, &recipient_address);
    let recipient_payment_pubkey = lookup_payment_identity(&rpc, &recipient_address);
    let recipient_hex = format!(
        "{}:{}",
        hex::encode(recipient_pubkey.classical_pk.0),
        hex::encode(recipient_pubkey.pq_pk.as_slice())
    );

    let sender_pubkey = HybridPubKey {
        classical_pk: Bytes32::from(classical_pk),
        pq_pk: VariableBytes::from_slice(&pq_pk).unwrap_or_else(|_| {
            eprintln!("Error: invalid sender pq key length");
            std::process::exit(1);
        }),
    };

    let built = build_transaction(&TxParams {
        chain_id: &chain_id,
        recipient_pubkey_hex: &recipient_hex,
        amount_spark,
        fee_spark: indra_cli::tx_builder::MIN_FEE_SPARK,
        wallet: &wallet,
        hybrid_seed,
        pq_sk_bytes,
        sender_pubkey,
        recipient_payment_pubkey,
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
    if let Err(error) = update_wallet_after_accepted_transaction(&wallet_path, local_wallet, &built)
    {
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

fn build_auth_or_exit(rpc: &str, keys: &KeysFile, address: &str) -> String {
    indra_cli::build_legacy_scan_auth_proof(rpc, keys, address).unwrap_or_else(|e| {
        eprintln!(
            "Error building legacy scan authorization: {}. \
             Address-indexed UTXO scans are no longer public; use the owner's keys.json.",
            e
        );
        std::process::exit(1);
    })
}

fn resolve_recipient_pubkey(rpc: &str, address_hex: &str) -> HybridPubKey {
    let raw = rpc_call(rpc, "indra_getValidator", &[address_hex.to_string()]);
    let classical = extract_hex_string(&raw, "hybrid_classical_pk").unwrap_or_else(|| {
        eprintln!(
            "Error: recipient {} not found in validator set",
            address_hex
        );
        std::process::exit(1);
    });
    let pq = extract_hex_string(&raw, "hybrid_pq_pk").unwrap_or_else(|| {
        eprintln!("Error: recipient {} missing PQ key", address_hex);
        std::process::exit(1);
    });
    HybridPubKey {
        classical_pk: Bytes32::from(copy32(&classical)),
        pq_pk: VariableBytes::from_slice(&pq).unwrap_or_else(|_| {
            eprintln!("Error: recipient PQ key too large");
            std::process::exit(1);
        }),
    }
}

fn lookup_payment_identity(
    rpc: &str,
    recipient_address_hex: &str,
) -> Option<indra_crypto::PaymentPubKeyV1> {
    let raw = rpc_call(
        rpc,
        "indra_getPaymentIdentity",
        &[recipient_address_hex.to_string()],
    );
    payment_identity_from_rpc_json(&raw)
}

fn payment_identity_from_rpc_json(json: &str) -> Option<indra_crypto::PaymentPubKeyV1> {
    let version = extract_number(json, "version")?;
    let x25519_pk = hex::encode(extract_hex_string(json, "x25519_pk")?);
    let ml_kem_1024_ek = hex::encode(extract_hex_string(json, "ml_kem_1024_ek")?);
    let bytes = hex::decode(format!("{version:02x}{x25519_pk}{ml_kem_1024_ek}")).ok()?;
    indra_crypto::PaymentPubKeyV1::decode(&bytes).ok()
}

fn spendable_wallet_from_authorized_utxos(
    json: &str,
    local_wallet: &Wallet,
) -> Result<Wallet, String> {
    let mut spendable = Wallet::new();
    let Some(utxos_json) = extract_array(json, "utxos") else {
        return Ok(spendable);
    };

    let mut discovered = 0usize;
    let mut spendable_count = 0usize;
    let mut pos = 0usize;
    while let Some(start_rel) = utxos_json[pos..].find('{') {
        let start = pos + start_rel;
        let Some(end) = find_matching_brace(utxos_json, start) else {
            break;
        };
        let obj = &utxos_json[start..=end];
        let Some(utxo_id) = extract_hex_string(obj, "utxo_id") else {
            pos = end + 1;
            continue;
        };
        let amount = extract_number(obj, "amount").unwrap_or(0);
        let created_height = extract_number(obj, "created_height").unwrap_or(0);
        let tx_index = extract_number(obj, "tx_index").unwrap_or(0) as u32;
        let out_index = extract_number(obj, "out_index").unwrap_or(0) as u32;
        let mut utxo_id_arr = [0u8; 32];
        if utxo_id.len() == 32 {
            utxo_id_arr.copy_from_slice(&utxo_id);
            discovered += 1;
            let utxo_id = Bytes32::from(utxo_id_arr);
            if let Some(entry) = local_wallet.get(&utxo_id) {
                if entry.value_spark == amount && !entry.spent {
                    spendable_count += 1;
                    spendable.add_utxo(
                        utxo_id,
                        amount,
                        entry.blinding,
                        created_height,
                        tx_index,
                        out_index,
                    );
                }
            }
        }
        pos = end + 1;
    }
    if discovered > 0 && spendable_count == 0 {
        return Err(format!(
            "authorized RPC found {discovered} UTXO(s), but none match an unspent local wallet entry with a known blinding factor; run indra-wallet-scan or add the UTXO with --add-utxo before sending"
        ));
    }
    Ok(spendable)
}

fn extract_array<'a>(json: &'a str, field: &str) -> Option<&'a str> {
    let key = format!("\"{}\":", field);
    let pos = json.find(&key)?;
    let after = json[pos + key.len()..].trim_start();
    let after = after.strip_prefix('[')?;
    let mut depth = 1usize;
    for (idx, ch) in after.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&after[..idx]);
                }
            }
            _ => {}
        }
    }
    None
}

fn find_matching_brace(text: &str, start: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, ch) in text[start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(start + offset);
                }
            }
            _ => {}
        }
    }
    None
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

fn extract_number(json: &str, field: &str) -> Option<u64> {
    let key = format!("\"{}\":", field);
    let pos = json.find(&key)?;
    let after = json[pos + key.len()..].trim_start();
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn extract_hex_string(json: &str, field: &str) -> Option<Vec<u8>> {
    let key = format!("\"{}\":", field);
    let pos = json.find(&key)?;
    let after = json[pos + key.len()..].trim_start();
    let after = after.strip_prefix('"')?;
    let end = after.find('"')?;
    hex::decode(&after[..end]).ok()
}

fn copy32(bytes: &[u8]) -> [u8; 32] {
    if bytes.len() < 32 {
        eprintln!("Error: expected 32-byte field");
        std::process::exit(1);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_cli::tx_builder::MIN_FEE_SPARK;
    use indra_core::{
        codec::Decode,
        types::{
            primitives::VariableBytes,
            transaction::{OutputV1, TransactionV1},
        },
    };
    use indra_crypto::{
        commitment::verify_balance, hybrid::ClassicalKeypair, pedersen::commit, PedersenCommitment,
        PqKeypair,
    };

    #[test]
    fn spendable_wallet_from_nested_utxos_response_uses_local_blinding() {
        let json = r#"{"jsonrpc":"2.0","result":{"address":"28ce6ab9565c324950a4308ccd1187c473fa737d4e687e12121c04b0e4c8c1b6","utxos":[{"utxo_id":"e64a971111111111111111111111111111111111111111111111111111111111","amount":1000000000000,"created_height":0,"tx_index":0,"out_index":0,"lock_height":0}]},"id":1}"#;
        let mut local_wallet = Wallet::new();
        let utxo_id = Bytes32::from(copy32(
            &hex::decode("e64a971111111111111111111111111111111111111111111111111111111111")
                .unwrap(),
        ));
        local_wallet.add_utxo(utxo_id, 1_000_000_000_000, [0x42; 32], 0, 0, 0);

        let wallet = spendable_wallet_from_authorized_utxos(json, &local_wallet).unwrap();
        assert_eq!(wallet.balance(), 1_000_000_000_000);
        assert_eq!(wallet.get(&utxo_id).unwrap().blinding, [0x42; 32]);
    }

    #[test]
    fn rpc_discovered_utxo_without_local_blinding_fails_clearly() {
        let json = r#"{"jsonrpc":"2.0","result":{"utxos":[{"utxo_id":"e64a971111111111111111111111111111111111111111111111111111111111","amount":1000000000000,"created_height":0,"tx_index":0,"out_index":0}]}}"#;
        let err = spendable_wallet_from_authorized_utxos(json, &Wallet::new()).unwrap_err();

        assert!(err.contains("authorized RPC found 1 UTXO"));
        assert!(err.contains("known blinding factor"));
        assert!(err.contains("indra-wallet-scan"));
    }

    #[test]
    fn old_rpc_zero_blinding_path_builds_unbalanced_transaction() {
        let (hybrid_seed, pq_sk, sender_pubkey) = key_material(0x11);
        let (_, _, recipient_pubkey) = key_material(0x22);
        let recipient_hex = pubkey_hex(&recipient_pubkey);
        let utxo_id = Bytes32::from([0xA7; 32]);
        let input_value = 1_000_000;
        let real_input_blinding = [0x42; 32];

        let mut old_rpc_wallet = Wallet::new();
        old_rpc_wallet.add_utxo(utxo_id, input_value, [0u8; 32], 7, 0, 0);

        let built = build_transaction(&TxParams {
            chain_id: indra_core::types::primitives::DEFAULT_CHAIN_ID,
            recipient_pubkey_hex: &recipient_hex,
            amount_spark: 500_000,
            fee_spark: MIN_FEE_SPARK,
            wallet: &old_rpc_wallet,
            hybrid_seed,
            pq_sk_bytes: pq_sk,
            sender_pubkey,
            recipient_payment_pubkey: None,
        })
        .unwrap();
        let tx = decode_built_tx(&built);
        let real_input_commitment = commit(input_value, &real_input_blinding);

        assert!(verify_balance(
            &[PedersenCommitment(real_input_commitment.0)],
            &output_commitments(&tx.outputs),
            &PedersenCommitment(tx.fee_commitment.compressed_point.0),
        )
        .is_err());
    }

    #[test]
    fn known_local_blinding_builds_balanced_transaction() {
        let (hybrid_seed, pq_sk, sender_pubkey) = key_material(0x33);
        let (_, _, recipient_pubkey) = key_material(0x44);
        let recipient_hex = pubkey_hex(&recipient_pubkey);
        let utxo_id = Bytes32::from([0xB8; 32]);
        let input_value = 1_000_000;
        let real_input_blinding = [0x42; 32];
        let rpc_json = format!(
            r#"{{"result":{{"utxos":[{{"utxo_id":"{}","amount":{},"created_height":7,"tx_index":0,"out_index":0}}]}}}}"#,
            hex::encode(utxo_id.0),
            input_value
        );
        let mut local_wallet = Wallet::new();
        local_wallet.add_utxo(utxo_id, input_value, real_input_blinding, 7, 0, 0);
        let spendable_wallet =
            spendable_wallet_from_authorized_utxos(&rpc_json, &local_wallet).unwrap();

        let built = build_transaction(&TxParams {
            chain_id: indra_core::types::primitives::DEFAULT_CHAIN_ID,
            recipient_pubkey_hex: &recipient_hex,
            amount_spark: 500_000,
            fee_spark: MIN_FEE_SPARK,
            wallet: &spendable_wallet,
            hybrid_seed,
            pq_sk_bytes: pq_sk,
            sender_pubkey,
            recipient_payment_pubkey: None,
        })
        .unwrap();
        let tx = decode_built_tx(&built);
        let real_input_commitment = commit(input_value, &real_input_blinding);

        verify_balance(
            &[PedersenCommitment(real_input_commitment.0)],
            &output_commitments(&tx.outputs),
            &PedersenCommitment(tx.fee_commitment.compressed_point.0),
        )
        .unwrap();
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
        wallet.add_utxo(spent_id, 1_000_000, [0x31; 32], 9, 0, 0);
        wallet.add_utxo(other_id, 2_000_000, [0x32; 32], 9, 0, 1);
        wallet.save(&wallet_path_str).unwrap();
        let built = indra_cli::BuiltTransaction {
            tx_hex: "00".to_string(),
            tx_id: hex::encode([0x44; 32]),
            change_spark: 750_000,
            recipient_blinding: [0x55; 32],
            change_blinding: Some([0x56; 32]),
            spent_utxo_ids: vec![spent_id],
            pending_change: Some(indra_cli::PendingChange {
                output: sample_output(750_000),
                blinding: [0x56; 32],
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

    fn pubkey_hex(pubkey: &HybridPubKey) -> String {
        format!(
            "{}:{}",
            hex::encode(pubkey.classical_pk.0),
            hex::encode(pubkey.pq_pk.as_slice())
        )
    }

    fn decode_built_tx(built: &indra_cli::BuiltTransaction) -> TransactionV1 {
        TransactionV1::decode_exact(&hex::decode(&built.tx_hex).unwrap()).unwrap()
    }

    fn output_commitments(outputs: &[OutputV1]) -> Vec<PedersenCommitment> {
        outputs
            .iter()
            .map(|output| PedersenCommitment(output.commitment.compressed_point.0))
            .collect()
    }

    fn sample_output(value_spark: u64) -> OutputV1 {
        OutputV1 {
            value_spark,
            commitment: indra_core::types::crypto::CommitmentV1 {
                compressed_point: Bytes32::from([0x91; 32]),
            },
            owner_pubkey: key_material(0x91).2,
            range_proof: VariableBytes::from_slice(&[0x92; 32]).unwrap(),
            lock_height: 0,
        }
    }
}
