#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::io::Write;

use indra_core::codec::Encode;
use indra_core::types::{
    crypto::HybridPubKey,
    primitives::{Bytes32, VariableBytes},
};
use indra_crypto::{ClassicalPublicKey, PaymentAddressV1, PqPublicKey};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args
        .iter()
        .any(|a| a == "--help" || a == "-h" || a == "help")
    {
        print_help();
        return;
    }
    if args.get(1).map(String::as_str) == Some("inspect") {
        cmd_inspect(&args[2..]);
        return;
    }
    if args.get(1).map(String::as_str) == Some("export-public") {
        cmd_export_public(&args[2..]);
        return;
    }
    if args.get(1).map(String::as_str) == Some("cold") {
        cmd_cold(&args[2..]);
        return;
    }

    let output = args
        .iter()
        .position(|a| a == "--output")
        .and_then(|i| args.get(i + 1))
        .map_or("keys.json", String::as_str);
    let chain_id = indra_cli::required_chain_id(&args).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(1);
    });
    if indra_cli::has_secret_value_in_argv(&args, "--recover") {
        eprintln!("Error: do not pass a mnemonic in argv. Use '--recover' and enter it at the secure prompt.");
        std::process::exit(1);
    }
    if indra_cli::has_secret_value_in_argv(&args, "--passphrase") {
        eprintln!("Error: do not pass a passphrase in argv. Use '--passphrase' and enter it at the secure prompt.");
        std::process::exit(1);
    }
    let recover_mode = args.iter().any(|a| a == "--recover");
    let passphrase_mode = args.iter().any(|a| a == "--passphrase");
    if recover_mode && passphrase_mode {
        eprintln!("Error: choose either --recover or --passphrase, not both");
        std::process::exit(1);
    }
    let password_source = keygen_password_source(&args);
    if matches!(password_source, indra_cli::PasswordSource::Prompt) && !stdin_is_tty() {
        eprintln!(
            "Error: encrypted key generation in noninteractive mode requires --keys-password-file/--password-file."
        );
        std::process::exit(1);
    }
    let name_arg = args
        .iter()
        .position(|a| a == "--name")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let name = name_arg.unwrap_or_else(|| {
        if recover_mode {
            String::new()
        } else {
            print!("  Enter your validator name: ");
            let _ = std::io::Write::flush(&mut std::io::stdout());
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);
            input.trim().to_string()
        }
    });

    let (mnemonic, keys) = if recover_mode {
        let phrase = read_secret_from_stdin("Enter recovery phrase: ");
        match indra_cli::recover_from_mnemonic(&phrase, name.clone()) {
            Ok(keys) => (None, keys),
            Err(err) => {
                eprintln!("Mnemonic recovery failed: {}", err);
                std::process::exit(1);
            }
        }
    } else if passphrase_mode {
        let phrase = read_secret_from_stdin("Enter passphrase: ");
        let confirm = read_secret_from_stdin("Confirm passphrase: ");
        if phrase != confirm {
            eprintln!("Passphrases do not match");
            std::process::exit(1);
        }
        match indra_cli::generate_from_passphrase(&phrase, name.clone()) {
            Ok(keys) => (None, keys),
            Err(err) => {
                eprintln!("Passphrase key generation failed: {}", err);
                std::process::exit(1);
            }
        }
    } else {
        match indra_cli::generate_from_new_mnemonic(name.clone()) {
            Ok((phrase, keys)) => (Some(phrase), keys),
            Err(err) => {
                eprintln!("Mnemonic generation failed: {}", err);
                std::process::exit(1);
            }
        }
    };

    let password = password_source.resolve(true).unwrap_or_else(|e| {
        eprintln!("Failed to read keystore password: {}", e);
        std::process::exit(1);
    });
    let json = indra_cli::encrypt_keys(&keys, password.as_bytes()).unwrap_or_else(|e| {
        eprintln!("Failed to encrypt keys: {}", e);
        std::process::exit(1);
    });
    if let Err(err) = indra_cli::write_keys_file_secure(output, &json) {
        eprintln!("Failed to write {}: {}", output, err);
        std::process::exit(1);
    }

    if let Some(phrase) = mnemonic {
        let words: Vec<&str> = phrase.split_whitespace().collect();
        println!("═══════════════════════════════════════════════════════════");
        println!("  INDRA VALIDATOR KEYS GENERATED");
        println!("═══════════════════════════════════════════════════════════");
        println!();
        println!("  YOUR 24-WORD RECOVERY PHRASE:");
        println!();
        for chunk in words.chunks(6) {
            println!("  {}", chunk.join(" "));
        }
        println!();
        println!("  WRITE THESE DOWN. STORE THEM SAFELY.");
        println!("  Anyone with these words can access your funds.");
        println!("  These words are NOT stored in keys.json.");
        println!("  If you lose keys.json, use these words to recover.");
        println!();
        println!("═══════════════════════════════════════════════════════════");
        println!();
    }

    println!("  Validator Name:   {}", keys.name);
    println!(
        "  Validator ID:     {}",
        hex::encode(keys.public.validator_id)
    );
    println!(
        "  Classical PK:     {}",
        hex::encode(keys.public.hybrid_classical_pk)
    );
    let payment_address = keys
        .payment_address(chain_id.as_bytes())
        .unwrap_or_else(|error| {
            eprintln!("Failed to construct canonical payment address: {error}");
            std::process::exit(1);
        });
    println!("  Payment Address:  {}", payment_address.to_text());
    println!("  Keys written to:  {}", output);
    println!("  Storage:          encrypted at rest");
    println!("  For unattended validator startup, store the password in a separate 0600 password file and set [keys].password_file.");
}

fn cmd_inspect(args: &[String]) {
    let keys_path = get(args, "--keys").unwrap_or_else(|| "keys.json".to_string());
    let chain_id = indra_cli::required_chain_id(args).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(1);
    });
    let json = std::fs::read_to_string(&keys_path).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", keys_path, e);
        std::process::exit(1);
    });
    let metadata = indra_cli::inspect_key_file_public_metadata(&json).unwrap_or_else(|e| {
        eprintln!("Failed to inspect keys: {}", e);
        std::process::exit(1);
    });
    match metadata {
        indra_cli::KeyFilePublicMetadata::Hot { name, public } => {
            println!("Validator Name: {}", name);
            println!("Validator ID:   {}", hex::encode(public.validator_id));
            println!(
                "Classical PK:   {}",
                hex::encode(public.hybrid_classical_pk)
            );
            println!("PQ PK bytes:    {}", public.hybrid_pq_pk.len());
            println!("VRF PK:         {}", hex::encode(public.vrf_pk));
            print_owner_details(
                public.hybrid_classical_pk,
                public.hybrid_pq_pk.clone(),
                &chain_id,
            );
        }
        indra_cli::KeyFilePublicMetadata::Cold {
            classical_pk,
            pq_pk,
        } => {
            println!("Key Role:       validator cold authority");
            println!("Classical PK:   {}", hex::encode(classical_pk));
            println!("PQ PK:          {}", hex::encode(&pq_pk));
            println!("PQ PK bytes:    {}", pq_pk.len());
            print_owner_details(classical_pk, pq_pk, &chain_id);
        }
    }
}

fn cmd_export_public(args: &[String]) {
    let keys_path = get(args, "--keys").unwrap_or_else(|| {
        eprintln!("Error: missing required --keys");
        std::process::exit(1);
    });
    let chain_id = indra_cli::required_chain_id(args).unwrap_or_else(|message| {
        eprintln!("Error: {message}");
        std::process::exit(1);
    });
    let output = get(args, "--output").unwrap_or_else(|| {
        eprintln!("Error: missing required --output");
        std::process::exit(1);
    });
    let json = std::fs::read_to_string(&keys_path).unwrap_or_else(|error| {
        eprintln!("Error: cannot read {keys_path}: {error}");
        std::process::exit(1);
    });
    let export = if let Some(hot_export_path) = get(args, "--hot-export") {
        let hot_json = std::fs::read_to_string(&hot_export_path).unwrap_or_else(|error| {
            eprintln!("Error: cannot read {hot_export_path}: {error}");
            std::process::exit(1);
        });
        indra_cli::public_export_from_cold_key_file(
            &keys_path,
            indra_cli::cold_password_source_from_args(args),
            &hot_json,
            &chain_id,
        )
        .unwrap_or_else(|error| {
            eprintln!("Error: {error}");
            std::process::exit(1);
        })
    } else {
        indra_cli::public_export_from_key_file(&json, &chain_id).unwrap_or_else(|error| {
            eprintln!("Error: {error}");
            std::process::exit(1);
        })
    };
    let contents = serde_json::to_vec_pretty(&export).unwrap_or_else(|error| {
        eprintln!("Error: cannot serialize public export: {error}");
        std::process::exit(1);
    });
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)
        .unwrap_or_else(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                eprintln!("Error: {output} already exists; refusing to overwrite");
            } else {
                eprintln!("Error: cannot create {output}: {error}");
            }
            std::process::exit(1);
        });
    if let Err(error) = file.write_all(&contents) {
        eprintln!("Error: cannot write {output}: {error}");
        std::process::exit(1);
    }
    #[cfg(unix)]
    if let Err(error) = std::fs::set_permissions(
        &output,
        std::os::unix::fs::PermissionsExt::from_mode(0o644),
    ) {
        eprintln!("Error: cannot set permissions on {output}: {error}");
        std::process::exit(1);
    }
    if let Err(error) = file.sync_all() {
        eprintln!("Error: cannot sync {output}: {error}");
        std::process::exit(1);
    }
    println!("Public {} key export written to {}", export.kind, output);
}

fn print_owner_details(classical_pk: [u8; 32], pq_pk: Vec<u8>, chain_id: &str) {
    let (owner_hex, address) =
        owner_details(classical_pk, pq_pk, chain_id).unwrap_or_else(|error| {
            eprintln!("Failed to construct public owner details: {error}");
            std::process::exit(1);
        });
    println!("chain_id={chain_id}");
    println!("owner_pubkey_hex={owner_hex}");
    println!("Payment Address:  {address}");
}

fn owner_details(
    classical_pk: [u8; 32],
    pq_pk: Vec<u8>,
    chain_id: &str,
) -> Result<(String, String), String> {
    let owner = HybridPubKey {
        classical_pk: Bytes32::from(classical_pk),
        pq_pk: VariableBytes::from_slice(&pq_pk)
            .map_err(|error| format!("invalid owner public key: {error}"))?,
    };
    let owner_hex = hex::encode(owner.encode_to_vec());
    let pq_array: [u8; indra_crypto::PQ_PK_BYTES] = pq_pk
        .try_into()
        .map_err(|_| "invalid owner public key: invalid PQ key length".to_string())?;
    let address = PaymentAddressV1::new(
        chain_id.as_bytes(),
        indra_crypto::HybridPublicKey {
            classical: ClassicalPublicKey(classical_pk),
            pq: PqPublicKey(pq_array),
        },
    )
    .map_err(|error| format!("invalid payment address: {error}"))?;
    Ok((owner_hex, address.to_text()))
}

#[cfg(test)]
mod inspect_tests {
    use super::*;
    use indra_core::codec::Decode;

    #[test]
    fn inspect_owner_hex_and_payment_address_round_trip_for_hot_and_cold_keys() {
        let chain_id = "inspect-test";
        let hot = indra_cli::generate_from_master_seed("hot".to_string(), [7; 32]).unwrap();
        let cold = indra_cli::ColdKeysFile::generate().unwrap();
        for (classical, pq) in [
            (
                hot.public.hybrid_classical_pk,
                hot.public.hybrid_pq_pk.clone(),
            ),
            (cold.classical_pk, cold.pq_pk.clone()),
        ] {
            let (owner_hex, address_text) = owner_details(classical, pq.clone(), chain_id).unwrap();
            let decoded = HybridPubKey::decode_exact(&hex::decode(owner_hex).unwrap()).unwrap();
            assert_eq!(decoded.classical_pk, Bytes32::from(classical));
            assert_eq!(decoded.pq_pk.as_slice(), pq.as_slice());
            let address = PaymentAddressV1::from_text(&address_text, chain_id.as_bytes()).unwrap();
            assert_eq!(address.owner_pubkey().classical.0, classical);
            assert_eq!(address.owner_pubkey().pq.0.as_slice(), pq.as_slice());
            if classical == hot.public.hybrid_classical_pk {
                assert_eq!(
                    hot.payment_address(chain_id.as_bytes()).unwrap().to_text(),
                    address_text
                );
            }
        }
    }
}

fn cmd_cold(args: &[String]) {
    match args.first().map(String::as_str) {
        Some("ceremony") => return cmd_cold_ceremony(&args[1..]),
        Some("split") => return cmd_cold_split(&args[1..]),
        Some("verify") => return cmd_cold_verify(&args[1..]),
        Some("recover") => return cmd_cold_recover(&args[1..]),
        Some("dealer-rekey") => return cmd_cold_dealer_rekey(&args[1..]),
        _ => {}
    }
    let output = get(args, "--output").unwrap_or_else(|| "validator-cold-keys.json".to_string());
    let force = args.iter().any(|arg| arg == "--force");
    let password = keygen_password_source_slice(args)
        .resolve(true)
        .unwrap_or_else(|e| {
            eprintln!("Failed to read cold-keystore password: {}", e);
            std::process::exit(1);
        });
    let keys = indra_cli::generate_cold_keys_file(
        std::path::Path::new(&output),
        password.as_bytes(),
        force,
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to generate cold keys: {}", e);
        std::process::exit(1);
    });
    println!("INDRA validator cold key generated");
    println!("Output:       {}", output);
    println!("Classical PK: {}", hex::encode(keys.classical_pk));
    println!("PQ PK:        {}", hex::encode(&keys.pq_pk));
    println!("Hot keys.json was not read or modified.");
}

fn cold_fail(message: impl std::fmt::Display) -> ! {
    eprintln!("Cold-key ceremony failed: {message}");
    std::process::exit(1)
}

fn required(args: &[String], flag: &str) -> String {
    get(args, flag).unwrap_or_else(|| cold_fail(format!("missing required flag {flag}")))
}

fn parse_u8_flag(args: &[String], flag: &str) -> u8 {
    required(args, flag)
        .parse::<u8>()
        .unwrap_or_else(|_| cold_fail(format!("{flag} must be an integer in 0..=255")))
}

fn share_paths(args: &[String]) -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--share" {
            let path = args
                .get(index + 1)
                .unwrap_or_else(|| cold_fail("--share requires a path"));
            paths.push(std::path::PathBuf::from(path));
            index += 2;
        } else {
            index += 1;
        }
    }
    if paths.is_empty() {
        cold_fail("provide repeated --share <path> arguments");
    }
    paths
}

fn load_share_set(args: &[String]) -> Vec<indra_cli::ColdShareFile> {
    share_paths(args)
        .iter()
        .map(|path| indra_cli::read_cold_share(path).unwrap_or_else(|e| cold_fail(e)))
        .collect()
}

fn load_public_metadata(path: &str) -> indra_cli::KeyFilePublicMetadata {
    let json = std::fs::read_to_string(path).unwrap_or_else(|error| cold_fail(error));
    indra_cli::inspect_key_file_public_metadata(&json).unwrap_or_else(|error| cold_fail(error))
}

fn expected_hot(args: &[String]) -> indra_cli::ValidatorKeys {
    match load_public_metadata(&required(args, "--hot-keys")) {
        indra_cli::KeyFilePublicMetadata::Hot { public, .. } => public,
        indra_cli::KeyFilePublicMetadata::Cold { .. } => {
            cold_fail("--hot-keys must name an encrypted hot validator keystore")
        }
    }
}

fn expected_cold(args: &[String]) -> indra_cli::ExpectedColdPublicKey {
    if let (Some(classical), Some(pq)) = (
        get(args, "--expected-cold-classical-pk"),
        get(args, "--expected-cold-pq-pk"),
    ) {
        let classical: [u8; 32] = hex::decode(classical)
            .unwrap_or_else(|_| cold_fail("expected cold classical key is invalid hex"))
            .try_into()
            .unwrap_or_else(|_| cold_fail("expected cold classical key must be 32 bytes"));
        let pq =
            hex::decode(pq).unwrap_or_else(|_| cold_fail("expected cold PQ key is invalid hex"));
        if pq.len() != indra_crypto::PQ_PK_BYTES {
            cold_fail("expected cold PQ key has the wrong length");
        }
        return indra_cli::ExpectedColdPublicKey { classical, pq };
    }
    match load_public_metadata(&required(args, "--expected-cold-file")) {
        indra_cli::KeyFilePublicMetadata::Cold {
            classical_pk,
            pq_pk,
        } => indra_cli::ExpectedColdPublicKey {
            classical: classical_pk,
            pq: pq_pk,
        },
        indra_cli::KeyFilePublicMetadata::Hot { .. } => {
            cold_fail("--expected-cold-file must name an encrypted cold keystore")
        }
    }
}

fn hot_password_source(args: &[String]) -> indra_cli::PasswordSource<'_> {
    if let Some(path) = get_ref(args, "--hot-keys-password-file") {
        indra_cli::PasswordSource::File {
            path: std::path::Path::new(path),
            reject_permissive: false,
        }
    } else if let Some(var) = get_ref(args, "--hot-keys-password-env") {
        indra_cli::PasswordSource::Env(var)
    } else {
        indra_cli::PasswordSource::Prompt
    }
}

fn load_hot_signer(args: &[String]) -> indra_cli::KeysFile {
    indra_cli::load_keys(&required(args, "--hot-keys"), hot_password_source(args))
        .unwrap_or_else(|error| cold_fail(error))
}

fn write_ceremony(ceremony: &indra_cli::ColdShareCeremony, out_dir: &std::path::Path, force: bool) {
    std::fs::create_dir_all(out_dir).unwrap_or_else(|e| cold_fail(e));
    let manifest_path = out_dir.join("ceremony.json");
    let share_paths: Vec<_> = ceremony
        .shares
        .iter()
        .map(|share| out_dir.join(format!("share-{:03}.json", share.share_index)))
        .collect();
    if !force {
        for path in std::iter::once(&manifest_path).chain(share_paths.iter()) {
            if path.exists() {
                cold_fail(format!("{} already exists", path.display()));
            }
        }
    }
    let manifest_json =
        serde_json::to_string_pretty(&ceremony.manifest).unwrap_or_else(|e| cold_fail(e));
    indra_cli::write_keys_file_secure(
        manifest_path
            .to_str()
            .unwrap_or_else(|| cold_fail("output path is not UTF-8")),
        &manifest_json,
    )
    .unwrap_or_else(|e| cold_fail(e));
    for (share, path) in ceremony.shares.iter().zip(share_paths) {
        indra_cli::write_cold_share_secure(&path, share, force).unwrap_or_else(|e| cold_fail(e));
    }
    println!(
        "Cold-key ceremony created: {}-of-{}",
        ceremony.manifest.threshold, ceremony.manifest.share_count
    );
    println!("Ceremony ID: {}", ceremony.manifest.ceremony_id);
    println!("Cold classical PK: {}", ceremony.manifest.cold_classical_pk);
    println!("Cold PQ PK: {}", ceremony.manifest.cold_pq_pk);
    println!("Distribute shares to separate custodians and physical locations.");
}

fn now_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn build_ceremony(
    keys: &indra_cli::ColdKeysFile,
    hot_keys: &indra_cli::KeysFile,
    args: &[String],
) -> indra_cli::ColdShareCeremony {
    indra_cli::generate_cold_share_ceremony(
        keys,
        hot_keys,
        parse_u8_flag(args, "--threshold"),
        parse_u8_flag(args, "--shares"),
        now_unix_seconds(),
        &mut rand::rngs::OsRng,
    )
    .unwrap_or_else(|e| cold_fail(e))
}

fn cmd_cold_ceremony(args: &[String]) {
    let keys = indra_cli::ColdKeysFile::generate().unwrap_or_else(|e| cold_fail(e));
    let hot_keys = load_hot_signer(args);
    let ceremony = build_ceremony(&keys, &hot_keys, args);
    write_ceremony(
        &ceremony,
        std::path::Path::new(&required(args, "--out-dir")),
        args.iter().any(|arg| arg == "--force"),
    );
    println!("No complete cold secret was written to disk.");
}

fn cmd_cold_split(args: &[String]) {
    let keys = indra_cli::load_cold_keys(
        &required(args, "--cold-keys"),
        keygen_password_source_slice(args),
    )
    .unwrap_or_else(|e| cold_fail(e));
    let hot_keys = load_hot_signer(args);
    let ceremony = build_ceremony(&keys, &hot_keys, args);
    write_ceremony(
        &ceremony,
        std::path::Path::new(&required(args, "--out-dir")),
        args.iter().any(|arg| arg == "--force"),
    );
    println!("The source keystore was not modified; retain or destroy it according to your ceremony policy.");
}

fn cmd_cold_verify(args: &[String]) {
    let shares = load_share_set(args);
    let hot = expected_hot(args);
    let cold = expected_cold(args);
    for share in &shares {
        indra_cli::verify_cold_share(share, &hot).unwrap_or_else(|error| cold_fail(error));
    }
    let keys =
        indra_cli::reconstruct_cold_shares(&shares, &hot, &cold).unwrap_or_else(|e| cold_fail(e));
    keys.reconstruct().unwrap_or_else(|e| cold_fail(e));
    if let Some(output) = get(args, "--verification-output") {
        let receipt = serde_json::json!({
            "format": "indra-cold-dealer-rekey-verification",
            "version": 1,
            "ceremony_id": shares[0].manifest.ceremony_id,
            "validator_id": shares[0].manifest.validator_id,
            "cold_classical_pk": hex::encode(cold.classical),
            "cold_pq_pk": hex::encode(&cold.pq),
            "verified_share_count": shares.len(),
        });
        let encoded = serde_json::to_string_pretty(&receipt).unwrap_or_else(|e| cold_fail(e));
        indra_cli::write_keys_file_secure(&output, &encoded).unwrap_or_else(|e| cold_fail(e));
        println!("Dealer rekey verification receipt written to {output}.");
    }
    println!("Shares reconstruct the expected complete hybrid cold public key.");
    println!("No reconstructed key file was written.");
}

fn cmd_cold_recover(args: &[String]) {
    if !args
        .iter()
        .any(|arg| arg == "--acknowledge-destroy-after-use")
    {
        cold_fail("recover requires --acknowledge-destroy-after-use");
    }
    let hot = expected_hot(args);
    let cold = expected_cold(args);
    let keys = indra_cli::reconstruct_cold_shares(&load_share_set(args), &hot, &cold)
        .unwrap_or_else(|e| cold_fail(e));
    let output = required(args, "--output");
    if std::path::Path::new(&output).exists() && !args.iter().any(|arg| arg == "--force") {
        cold_fail(format!(
            "{output} already exists; pass --force to overwrite"
        ));
    }
    let password = keygen_password_source_slice(args)
        .resolve(true)
        .unwrap_or_else(|e| cold_fail(e));
    let encrypted =
        indra_cli::encrypt_cold_keys(&keys, password.as_bytes()).unwrap_or_else(|e| cold_fail(e));
    indra_cli::write_keys_file_secure(&output, &encrypted).unwrap_or_else(|e| cold_fail(e));
    let verified = indra_keystore::decrypt_cold_keys(&encrypted, password.as_bytes())
        .unwrap_or_else(|e| cold_fail(e));
    if verified != keys {
        cold_fail("encrypted recovery output failed verification");
    }
    println!("Encrypted temporary cold keystore written to {output}.");
    println!("DESTROY THIS RECOVERED KEYSTORE IMMEDIATELY AFTER SIGNING OR RE-SHARING.");
}

fn cmd_cold_dealer_rekey(args: &[String]) {
    let shares = load_share_set(args);
    let hot_public = expected_hot(args);
    let cold = expected_cold(args);
    let keys = indra_cli::reconstruct_cold_shares(&shares, &hot_public, &cold)
        .unwrap_or_else(|e| cold_fail(e));
    let hot_signer = load_hot_signer(args);
    let ceremony = build_ceremony(&keys, &hot_signer, args);
    let out_dir = required(args, "--out-dir");
    write_ceremony(
        &ceremony,
        std::path::Path::new(&out_dir),
        args.iter().any(|arg| arg == "--force"),
    );
    let pending = serde_json::json!({
        "format": "indra-cold-dealer-rekey-pending-verification",
        "version": 1,
        "ceremony_id": ceremony.manifest.ceremony_id,
        "instruction": "Do not retire old shares until cold verify succeeds and writes a verification receipt."
    });
    let pending_path = std::path::Path::new(&out_dir).join("REKEY_PENDING.json");
    indra_cli::write_keys_file_secure(
        pending_path
            .to_str()
            .unwrap_or_else(|| cold_fail("pending marker path is not UTF-8")),
        &serde_json::to_string_pretty(&pending).unwrap_or_else(|e| cold_fail(e)),
    )
    .unwrap_or_else(|e| cold_fail(e));
    println!("Dealer-based reconstruct-and-rekey completed; this is not proactive resharing.");
    println!(
        "VERIFY THE NEW SHARE SET with `indra-keygen cold verify` before retiring any old share."
    );
}

fn get(args: &[String], flag: &str) -> Option<String> {
    get_ref(args, flag).map(ToString::to_string)
}

fn get_ref<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn keygen_password_source(args: &[String]) -> indra_cli::PasswordSource<'_> {
    keygen_password_source_slice(args)
}

fn keygen_password_source_slice(args: &[String]) -> indra_cli::PasswordSource<'_> {
    let path = get_ref(args, "--keys-password-file").or_else(|| get_ref(args, "--password-file"));
    if let Some(path) = path {
        indra_cli::PasswordSource::File {
            path: std::path::Path::new(path),
            reject_permissive: false,
        }
    } else if let Some(var) = get_ref(args, "--keys-password-env") {
        indra_cli::PasswordSource::Env(var)
    } else {
        indra_cli::PasswordSource::Prompt
    }
}

fn print_help() {
    println!("Usage:\n  indra-keygen [--output keys.json] [--name name] [--chain-id id] [--recover|--passphrase] [--keys-password-file path]\n  indra-keygen cold --output validator-cold-keys.json [--keys-password-file path] [--force]\n  indra-keygen cold ceremony --hot-keys <keys.json> --threshold <m> --shares <n> --out-dir <dir>\n  indra-keygen cold split --cold-keys <path> --hot-keys <keys.json> --threshold <m> --shares <n> --out-dir <dir>\n  indra-keygen cold verify --share <path> ... --hot-keys <keys.json> --expected-cold-file <cold.json> [--verification-output <receipt.json>]\n  indra-keygen cold recover --share <path> ... --hot-keys <keys.json> --expected-cold-file <cold.json> --output <encrypted.json> --acknowledge-destroy-after-use\n  indra-keygen cold dealer-rekey --share <path> ... --hot-keys <keys.json> --expected-cold-file <cold.json> --threshold <m> --shares <n> --out-dir <dir>\n  indra-keygen inspect --keys keys.json --chain-id id\n  indra-keygen export-public --keys keys.json --chain-id id --output public.json [--keys-password-file path] [--hot-export hot-public.json]");
}

fn stdin_is_tty() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: isatty only observes the stdin fd.
        unsafe { libc::isatty(0) == 1 }
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn read_secret_from_stdin(prompt: &str) -> String {
    eprint!("{}", prompt);
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let echo_guard = EchoGuard::disable();
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
    drop(echo_guard);
    eprintln!();
    input.trim().to_string()
}

#[cfg(unix)]
struct EchoGuard {
    original: libc::termios,
    active: bool,
}

#[cfg(unix)]
impl EchoGuard {
    fn disable() -> Self {
        let fd = 0;
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `original` points to valid writable memory for libc to fill.
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return Self {
                // SAFETY: zeroed termios is never used when active=false.
                original: unsafe { std::mem::zeroed() },
                active: false,
            };
        }
        // SAFETY: tcgetattr succeeded, so `original` has been initialized.
        let original = unsafe { original.assume_init() };
        let mut no_echo = original;
        no_echo.c_lflag &= !libc::ECHO;
        // SAFETY: `no_echo` is a valid termios copied from the current terminal settings.
        let active = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &no_echo) } == 0;
        Self { original, active }
    }
}

#[cfg(unix)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: `original` came from a successful tcgetattr call for stdin.
            let _ = unsafe { libc::tcsetattr(0, libc::TCSANOW, &self.original) };
        }
    }
}

#[cfg(not(unix))]
struct EchoGuard;

#[cfg(not(unix))]
impl EchoGuard {
    fn disable() -> Self {
        Self
    }
}
