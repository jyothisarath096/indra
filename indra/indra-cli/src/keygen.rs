//! Validator keypair generation and encrypted key-file helpers.
//!
//! The canonical `keys.json` parser/writer now lives in `indra-keystore` so
//! the CLI and node binary use one encrypted format.

use crate::{CliError, CliResult};

pub use indra_keystore::{
    check_password_file_permissions, encrypt_cold_keys, encrypt_keys, generate_cold_keys_file,
    generate_cold_share_ceremony, generate_from_master_seed, generate_from_new_mnemonic,
    generate_from_passphrase, has_secret_value_in_argv, inspect_key_file_public_metadata,
    inspect_public_metadata, load_cold_keys, load_keys, read_cold_share, reconstruct_cold_shares,
    recover_from_mnemonic, validate_cold_share_manifest, verify_cold_share,
    warn_if_key_file_permissive, write_cold_share_secure,
    write_keys_secure as write_keys_file_secure, ColdKeysFile, ColdShareCeremony, ColdShareFile,
    ColdShareManifest, ExpectedColdPublicKey, KeyFilePublicMetadata, KeysFile, KeystoreError,
    PasswordSource, ValidatorKeys,
};

/// Resolve the standard CLI key-password source.
pub fn password_source_from_args<'a>(args: &'a [String]) -> PasswordSource<'a> {
    if let Some(path) = arg_value(args, "--keys-password-file") {
        PasswordSource::File {
            path: std::path::Path::new(path),
            reject_permissive: false,
        }
    } else if let Some(var) = arg_value(args, "--keys-password-env") {
        PasswordSource::Env(var)
    } else {
        PasswordSource::Prompt
    }
}

/// Load keys for one-off CLI tools. Encrypted keys prompt by default; password
/// files with permissive permissions warn and continue.
pub fn load_keys_for_cli(path: &str, args: &[String]) -> CliResult<KeysFile> {
    KeysFile::load_with_password(path, password_source_from_args(args)).map_err(CliError::from)
}

fn arg_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|idx| args.get(idx + 1))
        .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> KeysFile {
        generate_from_master_seed("validator".to_string(), [1; 32]).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn keys_json_written_with_mode_0600() {
        let path =
            std::env::temp_dir().join(format!("indra-keygen-{}.json", rand::random::<u64>()));
        write_keys_file_secure(path.to_str().unwrap(), "{}").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn encrypted_keys_json_exposes_metadata_without_plaintext_secrets() {
        let keys = fixture();
        let json = encrypt_keys(&keys, b"pw").unwrap();
        assert!(json.contains("\"validator_id\""));
        assert!(!json.contains("\"ed25519_seed\""));
        assert!(!json.contains("bls_seed"));
        assert!(!json.contains("bls_pk"));
        assert!(!json.contains("\"vrf_seed\""));
        assert!(!json.contains("\"ml_dsa_seed\""));
    }

    #[test]
    fn cli_loader_reads_encrypted_keys_with_password_file() {
        let dir =
            std::env::temp_dir().join(format!("indra-cli-keystore-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let keys_path = dir.join("keys.json");
        let password_path = dir.join("keys.pass");
        let keys = fixture();
        let encrypted = encrypt_keys(&keys, b"pw").unwrap();
        write_keys_file_secure(keys_path.to_str().unwrap(), &encrypted).unwrap();
        write_keys_file_secure(password_path.to_str().unwrap(), "pw\n").unwrap();

        let args = vec![
            "tool".to_string(),
            "--keys-password-file".to_string(),
            password_path.to_string_lossy().to_string(),
        ];
        let loaded = load_keys_for_cli(keys_path.to_str().unwrap(), &args).unwrap();
        assert_eq!(loaded, keys);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_key_consumers_use_shared_keystore_loader() {
        let consumers = [
            include_str!("bin/stake.rs"),
            include_str!("bin/governance.rs"),
            include_str!("bin/tx.rs"),
            include_str!("bin/wallet_scan.rs"),
            include_str!("bin/send.rs"),
        ];
        for source in consumers {
            assert!(
                source.contains("load_keys_for_cli"),
                "CLI key consumer bypasses shared encrypted loader"
            );
            assert!(
                !source.contains("extract_hex32") && !source.contains("extract_hex_field"),
                "CLI key consumer contains stale direct keys.json scraping helper"
            );
        }
    }
}
