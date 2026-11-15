//! Validator keypair generation and encrypted key-file helpers.
//!
//! The canonical `keys.json` parser/writer now lives in `indra-keystore` so
//! the CLI and node binary use one encrypted format.

use crate::{CliError, CliResult};
use indra_core::codec::{Decode, Encode};
use indra_core::types::{
    crypto::HybridPubKey,
    primitives::{Bytes32, VariableBytes},
};
use serde::{Deserialize, Serialize};

/// Domain used for public key export bindings.
pub const PUBLIC_EXPORT_V1_DOMAIN: &[u8] = b"INDRA_PUBLIC_EXPORT_V1";

/// Tooling-only domain for proving that one cold key is paired with one hot validator.
pub const INDRA_COLD_HOT_PAIRING_V1: &[u8] = b"INDRA-COLD-HOT-PAIRING-v1";

/// Public export schema. The binding is SHA-256 over:
/// `domain || u32_be(version) || len(kind)||kind || len(chain_id)||chain_id ||`
/// followed by the kind-specific fields, each as `u32_be(len)||bytes`.
/// Hot fields are validator_id, hybrid_classical_pk, hybrid_pq_pk, vrf_pk.
/// Cold version 2 fields are cold_hybrid_classical_pk, cold_hybrid_pq_pk,
/// hot_validator_id, and pairing_signature. Key fields are the decoded public
/// bytes, while the two textual fields are UTF-8.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyExport {
    /// Schema version.
    pub version: u32,
    /// Exactly `hot` or `cold`.
    pub kind: String,
    /// Chain identifier to which this export is bound.
    pub chain_id: String,
    /// Hot validator identity, present only for hot exports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_id: Option<String>,
    /// Hot classical public key, present only for hot exports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hybrid_classical_pk: Option<String>,
    /// Hot PQ public key, present only for hot exports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hybrid_pq_pk: Option<String>,
    /// Hot VRF public key, present only for hot exports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vrf_pk: Option<String>,
    /// Cold classical public key, present only for cold exports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cold_hybrid_classical_pk: Option<String>,
    /// Cold PQ public key, present only for cold exports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cold_hybrid_pq_pk: Option<String>,
    /// Hot validator ID bound by a cold pairing proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hot_validator_id: Option<String>,
    /// Encoded hybrid signature proving cold-key consent to the hot pairing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_signature: Option<String>,
    /// SHA-256 binding over the canonical export fields.
    pub binding: String,
}

fn export_field(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    let len = u32::try_from(bytes.len()).map_err(|_| "public export field is too large")?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn export_binding(export: &PublicKeyExport) -> Result<String, String> {
    let mut bytes = PUBLIC_EXPORT_V1_DOMAIN.to_vec();
    bytes.extend_from_slice(&export.version.to_be_bytes());
    export_field(&mut bytes, export.kind.as_bytes())?;
    export_field(&mut bytes, export.chain_id.as_bytes())?;
    match export.kind.as_str() {
        "hot" => {
            if export.cold_hybrid_classical_pk.is_some()
                || export.cold_hybrid_pq_pk.is_some()
                || export.hot_validator_id.is_some()
                || export.pairing_signature.is_some()
            {
                return Err("hot export has unexpected cold fields".into());
            }
            for value in [
                export.validator_id.as_deref(),
                export.hybrid_classical_pk.as_deref(),
                export.hybrid_pq_pk.as_deref(),
                export.vrf_pk.as_deref(),
            ] {
                let value = value.ok_or("hot export is missing a public field")?;
                let decoded = hex::decode(value).map_err(|_| "hot export contains invalid hex")?;
                export_field(&mut bytes, &decoded)?;
            }
        }
        "cold" => {
            if export.validator_id.is_some()
                || export.hybrid_classical_pk.is_some()
                || export.hybrid_pq_pk.is_some()
                || export.vrf_pk.is_some()
            {
                return Err("cold export has unexpected hot fields".into());
            }
            for value in [
                export.cold_hybrid_classical_pk.as_deref(),
                export.cold_hybrid_pq_pk.as_deref(),
            ] {
                let value = value.ok_or("cold export is missing a public field")?;
                let decoded = hex::decode(value).map_err(|_| "cold export contains invalid hex")?;
                export_field(&mut bytes, &decoded)?;
            }
            let hot_validator_id = export
                .hot_validator_id
                .as_deref()
                .ok_or("cold export is missing hot_validator_id")?;
            let pairing_signature = export
                .pairing_signature
                .as_deref()
                .ok_or("cold export is missing pairing_signature")?;
            export_field(
                &mut bytes,
                &hex::decode(hot_validator_id)
                    .map_err(|_| "cold export contains invalid hot_validator_id")?,
            )?;
            export_field(
                &mut bytes,
                &hex::decode(pairing_signature)
                    .map_err(|_| "cold export contains invalid pairing_signature")?,
            )?;
        }
        _ => return Err("public export kind must be exactly 'hot' or 'cold'".into()),
    }
    Ok(hex::encode(indra_crypto::sha256(&bytes)))
}

/// Validate a public export and its self-binding, returning the decoded metadata.
pub fn validate_public_export(json: &str, expected_chain_id: &str) -> CliResult<PublicKeyExport> {
    let export: PublicKeyExport = serde_json::from_str(json)
        .map_err(|error| CliError::Genesis(format!("invalid public export: {error}")))?;
    if export.version != 1 && export.version != 2 {
        return Err(CliError::Genesis("unsupported public export version".into()));
    }
    if (export.kind == "hot" && export.version != 1)
        || (export.kind == "cold" && export.version != 2)
    {
        return Err(CliError::Genesis("unsupported public export version".into()));
    }
    if export.chain_id != expected_chain_id {
        return Err(CliError::Genesis("public export chain_id does not match target chain".into()));
    }
    for value in [
        export.validator_id.as_deref(),
        export.hybrid_classical_pk.as_deref(),
        export.hybrid_pq_pk.as_deref(),
        export.vrf_pk.as_deref(),
        export.cold_hybrid_classical_pk.as_deref(),
        export.cold_hybrid_pq_pk.as_deref(),
        export.hot_validator_id.as_deref(),
        export.pairing_signature.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let decoded = hex::decode(value)
            .map_err(|_| CliError::Genesis("public export contains invalid hex".into()))?;
        if hex::encode(decoded) != value {
            return Err(CliError::Genesis(
                "public export contains non-canonical hex".into(),
            ));
        }
    }
    if export.kind == "cold"
        && (export.hot_validator_id.is_none() || export.pairing_signature.is_none())
    {
        return Err(CliError::Genesis("cold export is missing pairing proof".into()));
    }
    let expected = export_binding(&export).map_err(CliError::Genesis)?;
    if export.binding != expected {
        return Err(CliError::Genesis("public export binding mismatch".into()));
    }
    match export.kind.as_str() {
        "hot" => {
            let id = export.validator_id.as_deref().ok_or_else(|| CliError::Genesis("hot export is missing validator_id".into()))?;
            let classical = export.hybrid_classical_pk.as_deref().ok_or_else(|| CliError::Genesis("hot export is missing hybrid_classical_pk".into()))?;
            let pq = export.hybrid_pq_pk.as_deref().ok_or_else(|| CliError::Genesis("hot export is missing hybrid_pq_pk".into()))?;
            let vrf = export.vrf_pk.as_deref().ok_or_else(|| CliError::Genesis("hot export is missing vrf_pk".into()))?;
            let id = hex::decode(id).map_err(|_| CliError::Genesis("hot export validator_id has invalid hex".into()))?;
            let classical = hex::decode(classical).map_err(|_| CliError::Genesis("hot export hybrid_classical_pk has invalid hex".into()))?;
            let pq = hex::decode(pq).map_err(|_| CliError::Genesis("hot export hybrid_pq_pk has invalid hex".into()))?;
            let vrf = hex::decode(vrf).map_err(|_| CliError::Genesis("hot export vrf_pk has invalid hex".into()))?;
            if id.len() != 32 || classical.len() != 32 || pq.len() != indra_crypto::PQ_PK_BYTES || vrf.len() != 32 {
                return Err(CliError::Genesis("public export key has wrong length".into()));
            }
            let classical: [u8; 32] = classical.try_into().map_err(|_| CliError::Genesis("public export key has wrong length".into()))?;
            let pq_key = VariableBytes::from_slice(&pq).map_err(|_| CliError::Genesis("public export key has wrong length".into()))?;
            let derived = HybridPubKey { classical_pk: Bytes32::from(classical), pq_pk: pq_key }.identity_id();
            if id.as_slice() != derived.0 {
                return Err(CliError::Genesis("public export validator_id does not match hot key".into()));
            }
        }
        "cold" => {
            let classical = export.cold_hybrid_classical_pk.as_deref().ok_or_else(|| CliError::Genesis("cold export is missing cold_hybrid_classical_pk".into()))?;
            let pq = export.cold_hybrid_pq_pk.as_deref().ok_or_else(|| CliError::Genesis("cold export is missing cold_hybrid_pq_pk".into()))?;
            let classical = hex::decode(classical).map_err(|_| CliError::Genesis("cold export cold_hybrid_classical_pk has invalid hex".into()))?;
            let pq = hex::decode(pq).map_err(|_| CliError::Genesis("cold export cold_hybrid_pq_pk has invalid hex".into()))?;
            if classical.len() != 32 || pq.len() != indra_crypto::PQ_PK_BYTES {
                return Err(CliError::Genesis("public export key has wrong length".into()));
            }
            let hot_id = export
                .hot_validator_id
                .as_deref()
                .ok_or_else(|| CliError::Genesis("cold export is missing pairing proof".into()))?;
            let hot_id = hex::decode(hot_id)
                .map_err(|_| CliError::Genesis("cold export hot_validator_id has invalid hex".into()))?;
            if hot_id.len() != 32 {
                return Err(CliError::Genesis("cold export hot_validator_id has wrong length".into()));
            }
            let signature = export
                .pairing_signature
                .as_deref()
                .ok_or_else(|| CliError::Genesis("cold export is missing pairing proof".into()))?;
            let signature = hex::decode(signature)
                .map_err(|_| CliError::Genesis("cold export pairing_signature has invalid hex".into()))?;
            indra_core::types::crypto::HybridSignature::decode_exact(&signature)
                .map_err(|_| CliError::Genesis("cold export pairing_signature has invalid encoding".into()))?;
        }
        _ => return Err(CliError::Genesis("public export kind must be exactly 'hot' or 'cold'".into())),
    }
    Ok(export)
}

/// Build a bound public export from a canonical encrypted keystore's public metadata.
pub fn public_export_from_key_file(json: &str, chain_id: &str) -> CliResult<PublicKeyExport> {
    let metadata = inspect_key_file_public_metadata(json).map_err(CliError::from)?;
    let mut export = match metadata {
        KeyFilePublicMetadata::Hot { public, .. } => PublicKeyExport {
            version: 1,
            kind: "hot".into(),
            chain_id: chain_id.into(),
            validator_id: Some(hex::encode(public.validator_id)),
            hybrid_classical_pk: Some(hex::encode(public.hybrid_classical_pk)),
            hybrid_pq_pk: Some(hex::encode(public.hybrid_pq_pk.clone())),
            vrf_pk: Some(hex::encode(public.vrf_pk)),
            cold_hybrid_classical_pk: None,
            cold_hybrid_pq_pk: None,
            hot_validator_id: None,
            pairing_signature: None,
            binding: String::new(),
        },
        KeyFilePublicMetadata::Cold { .. } => {
            return Err(CliError::Genesis(
                "cold export requires --hot-export".into(),
            ));
        }
    };
    export.binding = export_binding(&export).map_err(CliError::Genesis)?;
    Ok(export)
}

fn pairing_field(out: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    export_field(out, value)
}

/// Canonical pairing message: domain followed by six u32-big-endian length-prefixed fields.
pub fn cold_hot_pairing_message(
    chain_id: &str,
    hot_validator_id: &[u8],
    hot_classical_pk: &[u8],
    hot_pq_pk: &[u8],
    cold_classical_pk: &[u8],
    cold_pq_pk: &[u8],
) -> CliResult<Vec<u8>> {
    let mut message = INDRA_COLD_HOT_PAIRING_V1.to_vec();
    for field in [
        chain_id.as_bytes(),
        hot_validator_id,
        hot_classical_pk,
        hot_pq_pk,
        cold_classical_pk,
        cold_pq_pk,
    ] {
        pairing_field(&mut message, field).map_err(CliError::Genesis)?;
    }
    Ok(message)
}

/// Verify the cold export's pairing proof against the supplied hot export.
pub fn validate_cold_hot_pairing(
    hot: &PublicKeyExport,
    cold: &PublicKeyExport,
) -> CliResult<()> {
    let hot_id = hot
        .validator_id
        .as_deref()
        .ok_or_else(|| CliError::Genesis("hot export is missing validator_id".into()))?;
    if cold.hot_validator_id.as_deref() != Some(hot_id) {
        return Err(CliError::Genesis(
            "cold pairing proof does not match hot validator".into(),
        ));
    }
    let hot_classical = hot
        .hybrid_classical_pk
        .as_deref()
        .ok_or_else(|| CliError::Genesis("hot export is missing hybrid_classical_pk".into()))?;
    let hot_pq = hot
        .hybrid_pq_pk
        .as_deref()
        .ok_or_else(|| CliError::Genesis("hot export is missing hybrid_pq_pk".into()))?;
    let cold_classical = cold
        .cold_hybrid_classical_pk
        .as_deref()
        .ok_or_else(|| CliError::Genesis("cold export is missing cold_hybrid_classical_pk".into()))?;
    let cold_pq = cold
        .cold_hybrid_pq_pk
        .as_deref()
        .ok_or_else(|| CliError::Genesis("cold export is missing cold_hybrid_pq_pk".into()))?;
    let message = cold_hot_pairing_message(
        &hot.chain_id,
        &hex::decode(hot_id).map_err(|_| CliError::Genesis("cold pairing proof does not match hot validator".into()))?,
        &hex::decode(hot_classical).map_err(|_| CliError::Genesis("cold pairing proof does not match hot validator".into()))?,
        &hex::decode(hot_pq).map_err(|_| CliError::Genesis("cold pairing proof does not match hot validator".into()))?,
        &hex::decode(cold_classical).map_err(|_| CliError::Genesis("cold pairing proof does not match hot validator".into()))?,
        &hex::decode(cold_pq).map_err(|_| CliError::Genesis("cold pairing proof does not match hot validator".into()))?,
    )?;
    let signature_hex = cold
        .pairing_signature
        .as_deref()
        .ok_or_else(|| CliError::Genesis("cold export is missing pairing proof".into()))?;
    let signature = indra_core::types::crypto::HybridSignature::decode_exact(
        &hex::decode(signature_hex)
            .map_err(|_| CliError::Genesis("cold pairing proof does not match hot validator".into()))?,
    )
    .map_err(|_| CliError::Genesis("cold pairing proof does not match hot validator".into()))?;
    let cold_classical_bytes: [u8; 32] = hex::decode(cold_classical)
        .map_err(|_| CliError::Genesis("cold pairing proof does not match hot validator".into()))?
        .try_into()
        .map_err(|_| CliError::Genesis("cold pairing proof does not match hot validator".into()))?;
    let cold_key = HybridPubKey {
        classical_pk: Bytes32::from(cold_classical_bytes),
        pq_pk: VariableBytes::from_slice(
            &hex::decode(cold_pq)
                .map_err(|_| CliError::Genesis("cold pairing proof does not match hot validator".into()))?,
        )
        .map_err(|_| CliError::Genesis("cold pairing proof does not match hot validator".into()))?,
    };
    indra_crypto::verify_hybrid(
        &message,
        &signature
            .to_crypto_sig()
            .map_err(|_| CliError::Genesis("cold pairing proof does not match hot validator".into()))?,
        &cold_key
            .to_crypto_pubkey()
            .map_err(|_| CliError::Genesis("cold pairing proof does not match hot validator".into()))?,
    )
    .map_err(|_| CliError::Genesis("cold pairing proof does not match hot validator".into()))
}

/// Create a version-2 cold export by decrypting the cold key and signing its pairing proof.
pub fn public_export_from_cold_key_file(
    path: &str,
    source: PasswordSource<'_>,
    hot_json: &str,
    chain_id: &str,
) -> CliResult<PublicKeyExport> {
    let hot = validate_public_export(hot_json, chain_id)?;
    if hot.kind != "hot" {
        return Err(CliError::Genesis("cold export requires a hot export".into()));
    }
    let cold = load_cold_keys(path, source).map_err(CliError::from)?;
    let hot_id = hex::decode(hot.validator_id.as_deref().ok_or_else(|| CliError::Genesis("hot export is missing validator_id".into()))?)
        .map_err(|_| CliError::Genesis("hot export validator_id has invalid hex".into()))?;
    let hot_classical = hex::decode(hot.hybrid_classical_pk.as_deref().ok_or_else(|| CliError::Genesis("hot export is missing hybrid_classical_pk".into()))?)
        .map_err(|_| CliError::Genesis("hot export hybrid_classical_pk has invalid hex".into()))?;
    let hot_pq = hex::decode(hot.hybrid_pq_pk.as_deref().ok_or_else(|| CliError::Genesis("hot export is missing hybrid_pq_pk".into()))?)
        .map_err(|_| CliError::Genesis("hot export hybrid_pq_pk has invalid hex".into()))?;
    let cold_public = cold.reconstruct().map_err(CliError::from)?.public_key().as_complete_hybrid().clone();
    let message = cold_hot_pairing_message(
        chain_id,
        &hot_id,
        &hot_classical,
        &hot_pq,
        &cold_public.classical.0,
        &cold_public.pq.0,
    )?;
    let signed = cold.reconstruct().map_err(CliError::from)?.sign(&message)
        .map_err(|error| CliError::Crypto(error.to_string()))?;
    let wire = indra_core::types::crypto::HybridSignature {
        classical_sig: VariableBytes::from_slice(&signed.classical.0)
            .map_err(|_| CliError::Crypto("invalid pairing signature".into()))?,
        pq_sig: VariableBytes::from_slice(&signed.pq.0)
            .map_err(|_| CliError::Crypto("invalid pairing signature".into()))?,
    };
    let mut export = PublicKeyExport {
        version: 2,
        kind: "cold".into(),
        chain_id: chain_id.into(),
        validator_id: None,
        hybrid_classical_pk: None,
        hybrid_pq_pk: None,
        vrf_pk: None,
        cold_hybrid_classical_pk: Some(hex::encode(cold_public.classical.0)),
        cold_hybrid_pq_pk: Some(hex::encode(cold_public.pq.0)),
        hot_validator_id: Some(hex::encode(hot_id)),
        pairing_signature: Some(hex::encode(wire.encode_to_vec())),
        binding: String::new(),
    };
    export.binding = export_binding(&export).map_err(CliError::Genesis)?;
    validate_cold_hot_pairing(&hot, &export)?;
    Ok(export)
}

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

/// Resolve the password source for the encrypted cold-key file.
///
/// Cold password files are required to have restrictive permissions even when
/// the ordinary hot-key path only warns about them.
pub fn cold_password_source_from_args<'a>(args: &'a [String]) -> PasswordSource<'a> {
    if let Some(path) = arg_value(args, "--keys-password-file")
        .or_else(|| arg_value(args, "--cold-keys-password-file"))
    {
        PasswordSource::File {
            path: std::path::Path::new(path),
            reject_permissive: true,
        }
    } else if let Some(var) = arg_value(args, "--cold-keys-password-env") {
        PasswordSource::Env(var)
    } else {
        PasswordSource::Prompt
    }
}

/// Convert a reconstructed cold keypair to the owner-key representation used
/// by ordinary transaction outputs and wallet entries.
pub fn cold_hybrid_pubkey(keypair: &indra_crypto::ColdHybridKeypair) -> CliResult<HybridPubKey> {
    let public_key = keypair.public_key();
    let public = public_key.as_complete_hybrid();
    Ok(HybridPubKey {
        classical_pk: Bytes32::from(public.classical.0),
        pq_pk: VariableBytes::from_slice(&public.pq.0)
            .map_err(|_| CliError::Crypto("invalid cold public key".into()))?,
    })
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
        for (index, source) in consumers.iter().enumerate() {
            if index == 3 {
                assert!(source.contains("--owner-pubkey"));
                continue;
            }
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

    #[test]
    fn cold_cli_loader_reports_exact_wrong_passphrase_error() {
        let keys = ColdKeysFile::generate().unwrap();
        let encrypted = encrypt_cold_keys(&keys, b"correct").unwrap();
        let dir =
            std::env::temp_dir().join(format!("indra-cold-wrong-pass-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let cold_path = dir.join("cold.json");
        let pass_path = dir.join("wrong.pass");
        write_keys_file_secure(cold_path.to_str().unwrap(), &encrypted).unwrap();
        write_keys_file_secure(pass_path.to_str().unwrap(), "wrong\n").unwrap();
        let args = vec![
            "tool".to_string(),
            "--cold-keys-password-file".to_string(),
            pass_path.to_string_lossy().to_string(),
        ];
        let error = load_cold_keys(
            cold_path.to_str().unwrap(),
            cold_password_source_from_args(&args),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "keystore crypto error: authentication failed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn cold_password_file_rejects_permissive_permissions() {
        let keys = ColdKeysFile::generate().unwrap();
        let dir = std::env::temp_dir().join(format!("indra-cold-perms-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let cold_path = dir.join("cold.json");
        let pass_path = dir.join("cold.pass");
        write_keys_file_secure(
            cold_path.to_str().unwrap(),
            &encrypt_cold_keys(&keys, b"pw").unwrap(),
        )
        .unwrap();
        write_keys_file_secure(pass_path.to_str().unwrap(), "pw\n").unwrap();
        std::fs::set_permissions(&pass_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let args = vec![
            "tool".to_string(),
            "--cold-keys-password-file".to_string(),
            pass_path.to_string_lossy().to_string(),
        ];
        let error = load_cold_keys(
            cold_path.to_str().unwrap(),
            cold_password_source_from_args(&args),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "password file {} has permissive permissions (644); expected 600",
                pass_path.display()
            )
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cold_cli_argument_selects_cold_password_source() {
        let args = vec![
            "tool".to_string(),
            "--cold-keys-password-file".to_string(),
            "/tmp/cold.pass".to_string(),
        ];
        match cold_password_source_from_args(&args) {
            PasswordSource::File {
                path,
                reject_permissive,
            } => {
                assert_eq!(path.to_str(), Some("/tmp/cold.pass"));
                assert!(reject_permissive);
            }
            _ => panic!("expected cold password file source"),
        }
    }

    #[test]
    fn public_export_round_trips_without_secret_bytes() {
        let hot = fixture();
        let cold = ColdKeysFile::generate().unwrap();
        let hot_json = encrypt_keys(&hot, b"pw").unwrap();
        let cold_json = encrypt_cold_keys(&cold, b"pw").unwrap();
        let dir = std::env::temp_dir().join(format!("indra-cold-export-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let cold_path = dir.join("cold.json");
        let password_path = dir.join("password");
        write_keys_file_secure(cold_path.to_str().unwrap(), &cold_json).unwrap();
        write_keys_file_secure(password_path.to_str().unwrap(), "pw\n").unwrap();
        let hot_export = public_export_from_key_file(&hot_json, "export-chain").unwrap();
        let cold_export = public_export_from_cold_key_file(
            cold_path.to_str().unwrap(),
            PasswordSource::File {
                path: password_path.as_path(),
                reject_permissive: true,
            },
            &serde_json::to_string(&hot_export).unwrap(),
            "export-chain",
        )
        .unwrap();
        assert_eq!(validate_public_export(&serde_json::to_string(&hot_export).unwrap(), "export-chain").unwrap(), hot_export);
        assert_eq!(validate_public_export(&serde_json::to_string(&cold_export).unwrap(), "export-chain").unwrap(), cold_export);
        validate_cold_hot_pairing(&hot_export, &cold_export).unwrap();
        let hot_export_json = serde_json::to_string(&hot_export).unwrap();
        assert!(!hot_export_json.contains(&hex::encode(hot.ed25519_seed)));
        assert!(!hot_export_json.contains(&hex::encode(hot.ml_dsa_seed)));
        assert!(!hot_export_json.contains(&hex::encode(hot.vrf_seed)));
        assert!(!hot_export_json.contains(&hex::encode(cold.classical_seed)));
        assert!(!hot_export_json.contains(&hex::encode(cold.pq_seed)));
        assert!(!serde_json::to_string(&cold_export).unwrap().contains(&hex::encode(cold.classical_seed)));
        assert!(!serde_json::to_string(&cold_export).unwrap().contains(&hex::encode(cold.pq_seed)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn public_export_binding_rejects_tampered_public_fields() {
        let hot = fixture();
        let export = public_export_from_key_file(&encrypt_keys(&hot, b"pw").unwrap(), "export-chain").unwrap();
        for mutate in [
            |value: &mut PublicKeyExport| value.validator_id = Some(hex::encode([1u8; 32])),
            |value: &mut PublicKeyExport| value.hybrid_classical_pk = Some(hex::encode([2u8; 32])),
            |value: &mut PublicKeyExport| value.hybrid_pq_pk = Some(hex::encode([3u8; indra_crypto::PQ_PK_BYTES])),
            |value: &mut PublicKeyExport| value.vrf_pk = Some(hex::encode([4u8; 32])),
        ] {
            let mut tampered = export.clone();
            mutate(&mut tampered);
            assert_eq!(validate_public_export(&serde_json::to_string(&tampered).unwrap(), "export-chain").unwrap_err().to_string(), "genesis error: public export binding mismatch");
        }
    }

    #[test]
    fn public_export_binding_has_golden_vector() {
        let hot = fixture();
        let export = public_export_from_key_file(&encrypt_keys(&hot, b"pw").unwrap(), "export-chain").unwrap();
        assert_eq!(export.binding, "7d703cbbfe6ee4162b315b3db657f45c0d460e1e70c94ea1752019c24957f2d9");
    }

    #[test]
    fn public_export_rejects_wrong_chain_kind_and_key_length_exactly() {
        let hot = fixture();
        let export = public_export_from_key_file(&encrypt_keys(&hot, b"pw").unwrap(), "export-chain").unwrap();
        assert_eq!(
            validate_public_export(&serde_json::to_string(&export).unwrap(), "other-chain")
                .unwrap_err()
                .to_string(),
            "genesis error: public export chain_id does not match target chain"
        );
        let mut swapped = export.clone();
        swapped.kind = "cold".into();
        swapped.version = 2;
        assert_eq!(
            validate_public_export(&serde_json::to_string(&swapped).unwrap(), "export-chain")
                .unwrap_err()
                .to_string(),
            "genesis error: cold export is missing pairing proof"
        );
        let mut wrong_length = export.clone();
        wrong_length.hybrid_classical_pk = Some("00".into());
        wrong_length.binding = export_binding(&wrong_length).unwrap();
        assert_eq!(
            validate_public_export(&serde_json::to_string(&wrong_length).unwrap(), "export-chain")
                .unwrap_err()
                .to_string(),
            "genesis error: public export key has wrong length"
        );
    }

    #[test]
    fn cold_pairing_rejects_swapped_and_cross_domain_signatures_exactly() {
        let hot = fixture();
        let hot_export = public_export_from_key_file(
            &encrypt_keys(&hot, b"pw").unwrap(),
            "pairing-chain",
        )
        .unwrap();
        let dir = std::env::temp_dir().join(format!("indra-pairing-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let password_path = dir.join("password");
        write_keys_file_secure(password_path.to_str().unwrap(), "pw\n").unwrap();
        let cold_a = ColdKeysFile::generate().unwrap();
        let cold_b = ColdKeysFile::generate().unwrap();
        let cold_a_path = dir.join("cold-a.json");
        let cold_b_path = dir.join("cold-b.json");
        write_keys_file_secure(
            cold_a_path.to_str().unwrap(),
            &encrypt_cold_keys(&cold_a, b"pw").unwrap(),
        )
        .unwrap();
        write_keys_file_secure(
            cold_b_path.to_str().unwrap(),
            &encrypt_cold_keys(&cold_b, b"pw").unwrap(),
        )
        .unwrap();
        let source = || PasswordSource::File {
            path: password_path.as_path(),
            reject_permissive: true,
        };
        let export_a = public_export_from_cold_key_file(
            cold_a_path.to_str().unwrap(),
            source(),
            &serde_json::to_string(&hot_export).unwrap(),
            "pairing-chain",
        )
        .unwrap();
        let export_b = public_export_from_cold_key_file(
            cold_b_path.to_str().unwrap(),
            source(),
            &serde_json::to_string(&hot_export).unwrap(),
            "pairing-chain",
        )
        .unwrap();
        let mut swapped = export_b.clone();
        swapped.cold_hybrid_classical_pk = export_a.cold_hybrid_classical_pk.clone();
        swapped.cold_hybrid_pq_pk = export_a.cold_hybrid_pq_pk.clone();
        swapped.binding = export_binding(&swapped).unwrap();
        assert_eq!(
            validate_cold_hot_pairing(&hot_export, &swapped).unwrap_err().to_string(),
            "genesis error: cold pairing proof does not match hot validator"
        );
        let cold_a_pair = cold_a.reconstruct().unwrap();
        let wrong_signature = cold_a_pair.sign(PUBLIC_EXPORT_V1_DOMAIN).unwrap();
        let wrong_wire = indra_core::types::crypto::HybridSignature {
            classical_sig: VariableBytes::from_slice(&wrong_signature.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&wrong_signature.pq.0).unwrap(),
        };
        let mut cross_domain = export_a.clone();
        cross_domain.pairing_signature = Some(hex::encode(wrong_wire.encode_to_vec()));
        cross_domain.binding = export_binding(&cross_domain).unwrap();
        assert_eq!(
            validate_cold_hot_pairing(&hot_export, &cross_domain)
                .unwrap_err()
                .to_string(),
            "genesis error: cold pairing proof does not match hot validator"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cold_pairing_missing_proof_and_tampering_fail_exactly() {
        let hot = fixture();
        let hot_export = public_export_from_key_file(
            &encrypt_keys(&hot, b"pw").unwrap(),
            "pairing-chain",
        )
        .unwrap();
        let dir = std::env::temp_dir().join(format!("indra-pairing-fields-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let password_path = dir.join("password");
        let cold_path = dir.join("cold.json");
        write_keys_file_secure(password_path.to_str().unwrap(), "pw\n").unwrap();
        let cold = ColdKeysFile::generate().unwrap();
        write_keys_file_secure(
            cold_path.to_str().unwrap(),
            &encrypt_cold_keys(&cold, b"pw").unwrap(),
        )
        .unwrap();
        let export = public_export_from_cold_key_file(
            cold_path.to_str().unwrap(),
            PasswordSource::File {
                path: password_path.as_path(),
                reject_permissive: true,
            },
            &serde_json::to_string(&hot_export).unwrap(),
            "pairing-chain",
        )
        .unwrap();
        let mut missing = export.clone();
        missing.pairing_signature = None;
        assert_eq!(
            validate_public_export(&serde_json::to_string(&missing).unwrap(), "pairing-chain")
                .unwrap_err()
                .to_string(),
            "genesis error: cold export is missing pairing proof"
        );
        for mutate in [
            |value: &mut PublicKeyExport| value.hot_validator_id = Some(hex::encode([0x01; 32])),
            |value: &mut PublicKeyExport| value.pairing_signature = Some(hex::encode([0x02; 64])),
            |value: &mut PublicKeyExport| value.cold_hybrid_classical_pk = Some(hex::encode([0x03; 32])),
            |value: &mut PublicKeyExport| value.cold_hybrid_pq_pk = Some(hex::encode([0x04; indra_crypto::PQ_PK_BYTES])),
        ] {
            let mut tampered = export.clone();
            mutate(&mut tampered);
            assert_eq!(
                validate_public_export(&serde_json::to_string(&tampered).unwrap(), "pairing-chain")
                    .unwrap_err()
                    .to_string(),
                "genesis error: public export binding mismatch"
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cold_pairing_message_has_golden_vector() {
        let message = cold_hot_pairing_message(
            "pairing-chain",
            &[0x01, 0x02, 0x03],
            &[0x04, 0x05],
            &[0x06],
            &[0x07, 0x08, 0x09, 0x0a],
            &[0x0b],
        )
        .unwrap();
        assert_eq!(
            hex::encode(&message),
            "494e4452412d434f4c442d484f542d50414952494e472d76310000000d70616972696e672d636861696e000000030102030000000204050000000106000000040708090a000000010b"
        );
    }
}
