//! Deterministic founder-controlled genesis configuration builder.

#![allow(missing_docs)]

use crate::error::{CliError, CliResult};
use serde::{Deserialize, Serialize};

/// One validator entry in the genesis config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisEntry {
    pub name: String,
    pub validator_id: String,
    pub hybrid_classical_pk: String,
    pub hybrid_pq_pk: String,
    pub vrf_pk: String,
    pub vrf_possession_output: String,
    pub vrf_possession_proof: String,
    pub cold_hybrid_classical_pk: String,
    pub cold_hybrid_pq_pk: String,
    pub cold_key_version: u64,
    pub cold_nonce: u64,
    pub stake: u64,
}

#[derive(Debug, Clone)]
pub struct GenesisConfig {
    pub chain_id: String,
    pub genesis_timestamp: u64,
    pub active_slot_coefficient_numerator: u64,
    pub validators: Vec<GenesisEntry>,
}

/// Calculate a validator's genesis-stake share in basis points.
pub fn stake_share_bps(stake: u64, total: u64) -> u64 {
    if total == 0 {
        0
    } else {
        ((stake as u128 * 10_000) / total as u128) as u64
    }
}

/// Return whether a validator reaches the one-third genesis-stake threshold.
pub fn holds_at_least_one_third(stake: u64, total: u64) -> bool {
    total != 0 && 3u128 * stake as u128 >= total as u128
}

impl GenesisConfig {
    pub fn to_toml(&self) -> String {
        let mut out = format!(
            "[genesis]\nchain_id = {}\ngenesis_timestamp = {}\nactive_slot_coefficient_numerator = \"{}\"\n\n",
            toml_string(&self.chain_id), self.genesis_timestamp, self.active_slot_coefficient_numerator
        );
        for validator in &self.validators {
            out.push_str("[[validators]]\n");
            out.push_str(&format!("name = {}\n", toml_string(&validator.name)));
            out.push_str(&format!("validator_id = \"{}\"\n", validator.validator_id));
            out.push_str(&format!("hybrid_classical_pk = \"{}\"\n", validator.hybrid_classical_pk));
            out.push_str(&format!("hybrid_pq_pk = \"{}\"\n", validator.hybrid_pq_pk));
            out.push_str(&format!("vrf_pk = \"{}\"\n", validator.vrf_pk));
            out.push_str(&format!("vrf_possession_output = \"{}\"\n", validator.vrf_possession_output));
            out.push_str(&format!("vrf_possession_proof = \"{}\"\n", validator.vrf_possession_proof));
            out.push_str(&format!("cold_hybrid_classical_pk = \"{}\"\n", validator.cold_hybrid_classical_pk));
            out.push_str(&format!("cold_hybrid_pq_pk = \"{}\"\n", validator.cold_hybrid_pq_pk));
            out.push_str(&format!("cold_key_version = {}\n", validator.cold_key_version));
            out.push_str(&format!("cold_nonce = {}\n", validator.cold_nonce));
            out.push_str(&format!("stake = {}\n\n", validator.stake));
        }
        out
    }

    pub fn validate(&self) -> CliResult<()> {
        use indra_core::types::primitives::MIN_ACTIVE_VALIDATORS;
        if self.validators.len() < MIN_ACTIVE_VALIDATORS {
            return Err(CliError::Genesis(format!(
                "need at least {MIN_ACTIVE_VALIDATORS} validators for BFT safety"
            )));
        }
        indra_node::genesis::parse_genesis_manifest_str(&self.to_toml())
            .map(|_| ())
            .map_err(CliError::Genesis)
    }
}

fn toml_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a Rust string cannot fail")
}

pub fn build_genesis_config(chain_id: &str, genesis_timestamp: u64, validators: Vec<GenesisEntry>) -> CliResult<GenesisConfig> {
    let config = GenesisConfig {
        chain_id: chain_id.to_string(),
        genesis_timestamp,
        active_slot_coefficient_numerator:
            indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
        validators,
    };
    config.validate()?;
    Ok(config)
}

pub fn entry_from_keys(name: &str, keys: &crate::keygen::KeysFile, stake: u64) -> GenesisEntry {
    let entry_name = if keys.name.is_empty() { name.to_string() } else { keys.name.clone() };
    GenesisEntry {
        name: entry_name,
        validator_id: hex::encode(keys.public.validator_id),
        hybrid_classical_pk: hex::encode(keys.public.hybrid_classical_pk),
        hybrid_pq_pk: hex::encode(&keys.public.hybrid_pq_pk),
        vrf_pk: hex::encode(keys.public.vrf_pk),
        vrf_possession_output: String::new(),
        vrf_possession_proof: String::new(),
        cold_hybrid_classical_pk: String::new(),
        cold_hybrid_pq_pk: String::new(),
        cold_key_version: 1,
        cold_nonce: 0,
        stake,
    }
}

pub fn entry_from_public_keys(
    name: &str,
    public: &crate::keygen::ValidatorKeys,
    stake: u64,
) -> GenesisEntry {
    GenesisEntry {
        name: name.to_string(),
        validator_id: hex::encode(public.validator_id),
        hybrid_classical_pk: hex::encode(public.hybrid_classical_pk),
        hybrid_pq_pk: hex::encode(&public.hybrid_pq_pk),
        vrf_pk: hex::encode(public.vrf_pk),
        vrf_possession_output: String::new(),
        vrf_possession_proof: String::new(),
        cold_hybrid_classical_pk: String::new(),
        cold_hybrid_pq_pk: String::new(),
        cold_key_version: 1,
        cold_nonce: 0,
        stake,
    }
}

pub fn with_cold_manifest(
    mut entry: GenesisEntry,
    manifest: &crate::keygen::ColdShareManifest,
) -> CliResult<GenesisEntry> {
    let classical: [u8; 32] = hex::decode(&entry.hybrid_classical_pk)
        .map_err(|_| CliError::Genesis("hot classical key is invalid hex".into()))?
        .try_into()
        .map_err(|_| CliError::Genesis("hot classical key has wrong length".into()))?;
    let validator_id: [u8; 32] = hex::decode(&entry.validator_id)
        .map_err(|_| CliError::Genesis("validator ID is invalid hex".into()))?
        .try_into()
        .map_err(|_| CliError::Genesis("validator ID has wrong length".into()))?;
    let vrf_pk: [u8; 32] = hex::decode(&entry.vrf_pk)
        .map_err(|_| CliError::Genesis("VRF key is invalid hex".into()))?
        .try_into()
        .map_err(|_| CliError::Genesis("VRF key has wrong length".into()))?;
    let expected_hot = crate::keygen::ValidatorKeys {
        validator_id,
        hybrid_classical_pk: classical,
        hybrid_pq_pk: hex::decode(&entry.hybrid_pq_pk)
            .map_err(|_| CliError::Genesis("hot PQ key is invalid hex".into()))?,
        vrf_pk,
    };
    crate::keygen::validate_cold_share_manifest(manifest, &expected_hot)?;
    entry.cold_hybrid_classical_pk = manifest.cold_classical_pk.clone();
    entry.cold_hybrid_pq_pk = manifest.cold_pq_pk.clone();
    Ok(entry)
}

pub fn with_cold_file(mut entry: GenesisEntry, json: &str) -> CliResult<GenesisEntry> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|error| CliError::Genesis(format!("invalid cold JSON: {error}")))?;
    match value.get("format").and_then(|format| format.as_str()) {
        Some("indra-cold-key-pedersen-share") => {
            let manifest: crate::keygen::ColdShareManifest = serde_json::from_value(value)
                .map_err(|error| CliError::Genesis(format!("invalid cold metadata: {error}")))?;
            with_cold_manifest(entry, &manifest)
        }
        Some(indra_keystore::COLD_KEYSTORE_FORMAT) => {
            let metadata = crate::keygen::inspect_key_file_public_metadata(json)?;
            let crate::keygen::KeyFilePublicMetadata::Cold { classical_pk, pq_pk } = metadata else {
                return Err(CliError::Genesis("cold metadata resolved to non-cold keys".into()));
            };
            entry.cold_hybrid_classical_pk = hex::encode(classical_pk);
            entry.cold_hybrid_pq_pk = hex::encode(pq_pk);
            Ok(entry)
        }
        Some(format) => Err(CliError::Genesis(format!("unsupported cold-file format '{format}'"))),
        None => Err(CliError::Genesis("cold file is missing its format discriminator".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    fn entry_and_hot() -> (GenesisEntry, crate::KeysFile) {
        let hot = crate::generate_from_master_seed("cold-file-test".into(), [0x41; 32]).unwrap();
        (entry_from_keys("cold-file-test", &hot, 1_000_000_000), hot)
    }

    #[test]
    fn with_cold_file_rejects_unsupported_and_missing_format() {
        let (entry, _) = entry_and_hot();
        assert_eq!(with_cold_file(entry.clone(), r#"{"format":"other"}"#).unwrap_err().to_string(), "genesis error: unsupported cold-file format 'other'");
        assert_eq!(with_cold_file(entry, "{}").unwrap_err().to_string(), "genesis error: cold file is missing its format discriminator");
    }

    #[test]
    fn with_cold_file_rejects_validator_id_mismatch() {
        let (mut entry, hot) = entry_and_hot();
        let cold = crate::ColdKeysFile::generate().unwrap();
        let mut rng = StdRng::from_seed([0x42; 32]);
        let ceremony = crate::generate_cold_share_ceremony(&cold, &hot, 2, 3, 0, &mut rng).unwrap();
        entry.validator_id = hex::encode([0xAA; 32]);
        let json = serde_json::to_string(&ceremony.manifest).unwrap();
        assert_eq!(with_cold_file(entry, &json).unwrap_err().to_string(), "keystore error: keystore crypto error: cold-share ceremony: manifest hot identity does not match expected validator");
    }

    #[test]
    fn with_cold_file_rejects_a_non_cold_keystore() {
        let (entry, hot) = entry_and_hot();
        let json = crate::encrypt_keys(&hot, b"password").unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["format"] = serde_json::Value::String(indra_keystore::COLD_KEYSTORE_FORMAT.into());
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(with_cold_file(entry, &json).unwrap_err().to_string(), "keystore error: keystore parse error: missing field 'classical_pk'");
    }
}
