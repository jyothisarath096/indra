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
    eprintln!("  indra-tx address --keys <keys.json>");
    eprintln!("  indra-tx balance --address <hex> --rpc <url>");
    eprintln!("  indra-tx send --keys <keys.json> --to <address-hex> --amount <spark> --rpc <url>");
    std::process::exit(1);
}

fn cmd_address(args: &[String]) {
    let keys_path = get_arg(args, "--keys").unwrap_or_else(|| "keys.json".to_string());
    let keys = KeysFile::load(&keys_path).unwrap_or_else(|e| {
        eprintln!("Error loading {}: {}", keys_path, e);
        std::process::exit(1);
    });
    let address = sha256(&keys.public.hybrid_classical_pk);
    println!("{}", hex::encode(address));
}

fn cmd_balance(args: &[String]) {
    let address = required_arg(args, "--address");
    let rpc = get_arg(args, "--rpc").unwrap_or_else(|| "http://127.0.0.1:8545".to_string());
    let raw = rpc_call(&rpc, "indra_getBalance", &[address.clone()]);
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
    let recipient_address = required_arg(args, "--to");
    let amount_spark = required_arg(args, "--amount").parse::<u64>().unwrap_or_else(|_| {
        eprintln!("Error: invalid --amount");
        std::process::exit(1);
    });
    let rpc = get_arg(args, "--rpc").unwrap_or_else(|| "http://127.0.0.1:8545".to_string());

    let keys = KeysFile::load(&keys_path).unwrap_or_else(|e| {
        eprintln!("Error loading {}: {}", keys_path, e);
        std::process::exit(1);
    });
    let hybrid_seed = keys.hybrid_seed;
    let pq_sk_bytes = keys.pq_sk.clone();
    let classical_pk = keys.public.hybrid_classical_pk;
    let pq_pk = keys.public.hybrid_pq_pk.clone();
    let sender_address = hex::encode(sha256(&classical_pk));

    let utxos_raw = rpc_call(&rpc, "indra_getUtxos", &[sender_address.clone()]);
    let wallet = wallet_from_utxos_json(&utxos_raw);

    let recipient_pubkey = resolve_recipient_pubkey(&rpc, &recipient_address);
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
        recipient_pubkey_hex: &recipient_hex,
        amount_spark,
        fee_spark: indra_cli::tx_builder::MIN_FEE_SPARK,
        wallet: &wallet,
        hybrid_seed,
        pq_sk_bytes,
        sender_pubkey,
    }).unwrap_or_else(|e| {
        eprintln!("Error building transaction: {}", e);
        std::process::exit(1);
    });

    let response = rpc_call(&rpc, "indra_sendTransaction", &[built.tx_hex.clone()]);
    if response.contains("\"error\"") {
        eprintln!("{}", response);
        std::process::exit(1);
    }
    println!("{}", built.tx_id);
}

fn resolve_recipient_pubkey(rpc: &str, address_hex: &str) -> HybridPubKey {
    let raw = rpc_call(rpc, "indra_getValidator", &[address_hex.to_string()]);
    let classical = extract_hex_string(&raw, "hybrid_classical_pk").unwrap_or_else(|| {
        eprintln!("Error: recipient {} not found in validator set", address_hex);
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

fn wallet_from_utxos_json(json: &str) -> Wallet {
    let mut wallet = Wallet::new();
    let Some(utxos_json) = extract_array(json, "utxos") else {
        return wallet;
    };

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
            wallet.add_utxo(
                Bytes32::from(utxo_id_arr),
                amount,
                [0u8; 32],
                created_height,
                tx_index,
                out_index,
            );
        }
        pos = end + 1;
    }
    wallet
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
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
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

    #[test]
    fn wallet_from_nested_utxos_response_parses_balance() {
        let json = r#"{"jsonrpc":"2.0","result":{"address":"28ce6ab9565c324950a4308ccd1187c473fa737d4e687e12121c04b0e4c8c1b6","utxos":[{"utxo_id":"e64a971111111111111111111111111111111111111111111111111111111111","amount":1000000000000,"created_height":0,"tx_index":0,"out_index":0,"lock_height":0}]},"id":1}"#;
        let wallet = wallet_from_utxos_json(json);
        assert_eq!(wallet.balance(), 1_000_000_000_000);
    }
}
