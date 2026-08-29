//! Genesis configuration builder.
//!
//! Produces a `genesis.toml` file from a list of validator entries.
//! The genesis coordinator (testnet operator) collects public keys
//! from each participant, assigns stakes, and runs this command to
//! produce the agreed-upon genesis configuration.
//!
//! ## genesis.toml format
//!
//! ```toml
//! [genesis]
//! chain_id     = "indra-testnet-1"
//! active_slot_coefficient_numerator = "6917529027641081856"
//! bitcoin_pow_entropy_header = "<160 lowercase hex chars>"
//!
//! [genesis.bitcoin_pow_entropy_source]
//! scheme = 1
//! network_genesis_hash = "<64 lowercase hex chars>"
//! announced_height = 840000
//! header_codec = 1
//! extraction_algorithm = 1
//! minimum_confirmations = 100
//! reorg_policy = 1
//!
//! [[validators]]
//! name                = "alice"
//! validator_id        = "<hex>"
//! hybrid_classical_pk = "<hex>"
//! hybrid_pq_pk        = "<hex>"
//! vrf_pk              = "<hex>"
//! cold_hybrid_classical_pk = "<hex>"
//! cold_hybrid_pq_pk        = "<hex>"
//! cold_key_version         = 1
//! cold_nonce               = 0
//! stake               = 10000000000  # Spark
//! ```

use crate::error::{CliError, CliResult};
use serde::{Deserialize, Serialize};

/// One validator entry in the genesis config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisEntry {
    /// Human-readable name (for display only).
    pub name: String,
    /// Validator identity (hex).
    pub validator_id: String,
    /// Ed25519 public key (hex).
    pub hybrid_classical_pk: String,
    /// ML-DSA-87 public key (hex).
    pub hybrid_pq_pk: String,
    /// VRF public key (hex).
    pub vrf_pk: String,
    /// RFC 9381 output proving possession of the VRF secret key (hex).
    pub vrf_possession_output: String,
    /// RFC 9381 possession proof (hex).
    pub vrf_possession_proof: String,
    /// Ed25519 cold public key (hex).
    pub cold_hybrid_classical_pk: String,
    /// ML-DSA-87 cold public key (hex).
    pub cold_hybrid_pq_pk: String,
    /// Initial cold-key version.
    pub cold_key_version: u64,
    /// Initial cold-key replay nonce.
    pub cold_nonce: u64,
    /// Initial stake in Spark.
    pub stake: u64,
    /// Pre-target hiding nonce, revealed only during finalization.
    pub genesis_commitment_nonce: String,
}

/// A complete genesis configuration.
#[derive(Debug, Clone)]
pub struct GenesisConfig {
    /// Human-readable chain identifier.
    pub chain_id: String,
    /// Immutable numerator `F` in `f = F / 2^64`.
    pub active_slot_coefficient_numerator: u64,
    /// Canonical external-entropy source descriptor.
    pub bitcoin_pow_entropy_source: indra_node::genesis::BitcoinPowEntropySourceV1,
    /// Exact Bitcoin 80-byte header, lowercase hexadecimal.
    pub bitcoin_pow_entropy_header: String,
    /// Externally witnessed canonical pre-target ceremony hash.
    pub genesis_precommit_hash: String,
    /// All initial validators.
    pub validators: Vec<GenesisEntry>,
}

impl GenesisConfig {
    /// Serialise to TOML string.
    pub fn to_toml(&self) -> String {
        let mut out = String::new();

        out.push_str("[genesis]\n");
        out.push_str(&format!("chain_id     = {}\n", toml_string(&self.chain_id)));
        out.push_str(&format!(
            "active_slot_coefficient_numerator = \"{}\"\n",
            self.active_slot_coefficient_numerator
        ));
        out.push_str(&format!(
            "bitcoin_pow_entropy_header = \"{}\"\n",
            self.bitcoin_pow_entropy_header
        ));
        out.push_str(&format!(
            "genesis_precommit_hash = \"{}\"\n\n",
            self.genesis_precommit_hash
        ));
        let source = &self.bitcoin_pow_entropy_source;
        out.push_str("[genesis.bitcoin_pow_entropy_source]\n");
        out.push_str(&format!("scheme = {}\n", source.scheme));
        out.push_str(&format!(
            "network_genesis_hash = \"{}\"\n",
            source.network_genesis_hash
        ));
        out.push_str(&format!("announced_height = {}\n", source.announced_height));
        out.push_str(&format!("header_codec = {}\n", source.header_codec));
        out.push_str(&format!(
            "extraction_algorithm = {}\n",
            source.extraction_algorithm
        ));
        out.push_str(&format!(
            "minimum_confirmations = {}\n",
            source.minimum_confirmations
        ));
        out.push_str(&format!("reorg_policy = {}\n", source.reorg_policy));
        out.push_str(&format!(
            "# {} validators; total stake is checked during validation\n\n",
            self.validators.len()
        ));

        for v in &self.validators {
            out.push_str("[[validators]]\n");
            out.push_str(&format!("name                = {}\n", toml_string(&v.name)));
            out.push_str(&format!("validator_id        = \"{}\"\n", v.validator_id));
            out.push_str(&format!(
                "hybrid_classical_pk = \"{}\"\n",
                v.hybrid_classical_pk
            ));
            out.push_str(&format!("hybrid_pq_pk        = \"{}\"\n", v.hybrid_pq_pk));
            out.push_str(&format!("vrf_pk              = \"{}\"\n", v.vrf_pk));
            out.push_str(&format!(
                "vrf_possession_output = \"{}\"\n",
                v.vrf_possession_output
            ));
            out.push_str(&format!(
                "vrf_possession_proof = \"{}\"\n",
                v.vrf_possession_proof
            ));
            out.push_str(&format!(
                "cold_hybrid_classical_pk = \"{}\"\n",
                v.cold_hybrid_classical_pk
            ));
            out.push_str(&format!(
                "cold_hybrid_pq_pk        = \"{}\"\n",
                v.cold_hybrid_pq_pk
            ));
            out.push_str(&format!(
                "cold_key_version         = {}\n",
                v.cold_key_version
            ));
            out.push_str(&format!("cold_nonce               = {}\n", v.cold_nonce));
            out.push_str(&format!("stake               = {}  # Spark\n", v.stake));
            out.push_str(&format!(
                "genesis_commitment_nonce = \"{}\"\n\n",
                v.genesis_commitment_nonce
            ));
        }

        out
    }

    /// Validate the genesis config.
    ///
    /// Checks:
    /// - At least 4 validators (minimum for BFT safety: 3f+1 where f=1)
    /// - All validator IDs are unique
    /// - All stakes are above the protocol dust floor
    /// - Total stake matches expectations
    pub fn validate(&self) -> CliResult<()> {
        self.validators.iter().try_fold(0u64, |sum, validator| {
            sum.checked_add(validator.stake).ok_or_else(|| {
                CliError::Genesis("genesis validator stake sum overflows u64".into())
            })
        })?;
        use indra_core::types::primitives::DUST_LIMIT_SPARK;

        if self.validators.len() < 4 {
            return Err(CliError::Genesis(
                "need at least 4 validators for BFT safety (3f+1, f=1)".to_string(),
            ));
        }

        // Check unique validator IDs
        let mut seen_ids = std::collections::HashSet::new();
        for v in &self.validators {
            if !seen_ids.insert(v.validator_id.clone()) {
                return Err(CliError::Genesis(format!(
                    "duplicate validator_id: {}",
                    v.validator_id
                )));
            }
            if v.stake < DUST_LIMIT_SPARK {
                return Err(CliError::Genesis(format!(
                    "validator {} stake {} is below dust limit {}",
                    v.name, v.stake, DUST_LIMIT_SPARK
                )));
            }
        }
        indra_node::genesis::parse_genesis_manifest_str(&self.to_toml())
            .map(|_| ())
            .map_err(CliError::Genesis)
    }
}

// JSON string literals are valid TOML basic strings and give the renderer a
// single, well-tested escaping rule for operator-supplied text.
fn toml_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a Rust string cannot fail")
}

/// Build a genesis config from a list of entries.
pub fn build_genesis_config(
    chain_id: &str,
    bitcoin_pow_entropy_source: indra_node::genesis::BitcoinPowEntropySourceV1,
    bitcoin_pow_entropy_header: String,
    genesis_precommit_hash: String,
    validators: Vec<GenesisEntry>,
) -> CliResult<GenesisConfig> {
    let config = GenesisConfig {
        chain_id: chain_id.to_string(),
        active_slot_coefficient_numerator:
            indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
        bitcoin_pow_entropy_source,
        bitcoin_pow_entropy_header,
        genesis_precommit_hash,
        validators,
    };
    config.validate()?;
    Ok(config)
}

/// Build a genesis entry from a KeysFile and stake amount.
pub fn entry_from_keys(name: &str, keys: &crate::keygen::KeysFile, stake: u64) -> GenesisEntry {
    let entry_name = if keys.name.is_empty() {
        name.to_string()
    } else {
        keys.name.clone()
    };
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
        genesis_commitment_nonce: String::new(),
    }
}

/// Build a genesis entry from independently inspectable public hot metadata.
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
        genesis_commitment_nonce: String::new(),
    }
}

/// Attach the public output of a cold-key ceremony to a genesis entry.
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
    if manifest.validator_id != entry.validator_id {
        return Err(CliError::Genesis(
            "cold ceremony validator_id does not match hot identity".into(),
        ));
    }
    entry.cold_hybrid_classical_pk = manifest.cold_classical_pk.clone();
    entry.cold_hybrid_pq_pk = manifest.cold_pq_pk.clone();
    Ok(entry)
}

/// Attach cold public metadata from either a signed ceremony manifest or a
/// canonical encrypted cold keystore. The explicit format discriminator selects
/// the schema; field-presence guessing is prohibited.
pub fn with_cold_file(mut entry: GenesisEntry, json: &str) -> CliResult<GenesisEntry> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|error| CliError::Genesis(format!("invalid cold JSON: {error}")))?;
    match value.get("format").and_then(|format| format.as_str()) {
        Some("indra-cold-key-pedersen-share") => {
            let manifest: crate::keygen::ColdShareManifest = serde_json::from_value(value)
                .map_err(|error| CliError::Genesis(format!("invalid cold ceremony: {error}")))?;
            with_cold_manifest(entry, &manifest)
        }
        Some(indra_keystore::COLD_KEYSTORE_FORMAT) => {
            let metadata = crate::keygen::inspect_key_file_public_metadata(json)?;
            let crate::keygen::KeyFilePublicMetadata::Cold {
                classical_pk,
                pq_pk,
            } = metadata
            else {
                return Err(CliError::Genesis(
                    "cold-file format resolved to non-cold metadata".into(),
                ));
            };
            entry.cold_hybrid_classical_pk = hex::encode(classical_pk);
            entry.cold_hybrid_pq_pk = hex::encode(pq_pk);
            Ok(entry)
        }
        Some(format) => Err(CliError::Genesis(format!(
            "unsupported cold-file format '{format}'; expected indra-cold-key-pedersen-share or indra-cold-keystore"
        ))),
        None => Err(CliError::Genesis(
            "cold file is missing its required format discriminator".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::generate_from_master_seed;
    use indra_core::types::primitives::DUST_LIMIT_SPARK;

    fn entropy() -> (indra_node::genesis::BitcoinPowEntropySourceV1, String) {
        (
            indra_node::genesis::BitcoinPowEntropySourceV1 {
                scheme: 1,
                network_genesis_hash: hex::encode([0x11; 32]),
                announced_height: 1,
                header_codec: 1,
                extraction_algorithm: 1,
                minimum_confirmations: 100,
                reorg_policy: 1,
            },
            hex::encode([0x22; 80]),
        )
    }

    fn build(chain_id: &str, validators: Vec<GenesisEntry>) -> CliResult<GenesisConfig> {
        let (source, header) = entropy();
        let settings = indra_node::GenesisSettings {
            chain_id: chain_id.into(),
            active_slot_coefficient_numerator:
                indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
            bitcoin_pow_entropy_source: source.clone(),
            bitcoin_pow_entropy_header: header.clone(),
            genesis_precommit_hash: String::new(),
        };
        let opened = validators
            .iter()
            .map(|entry| indra_node::GenesisValidator {
                name: entry.name.clone(),
                validator_id: entry.validator_id.clone(),
                hybrid_classical_pk: entry.hybrid_classical_pk.clone(),
                hybrid_pq_pk: entry.hybrid_pq_pk.clone(),
                vrf_pk: entry.vrf_pk.clone(),
                vrf_possession_output: entry.vrf_possession_output.clone(),
                vrf_possession_proof: entry.vrf_possession_proof.clone(),
                cold_hybrid_classical_pk: entry.cold_hybrid_classical_pk.clone(),
                cold_hybrid_pq_pk: entry.cold_hybrid_pq_pk.clone(),
                cold_key_version: entry.cold_key_version,
                cold_nonce: entry.cold_nonce,
                stake: entry.stake,
                genesis_commitment_nonce: entry.genesis_commitment_nonce.clone(),
            })
            .collect::<Vec<_>>();
        let hash = hex::encode(
            indra_node::genesis::genesis_precommit_hash(&settings, &opened)
                .map_err(CliError::Genesis)?
                .0,
        );
        build_genesis_config(chain_id, source, header, hash, validators)
    }

    fn test_validators(chain_id: &str, count: usize) -> Vec<GenesisEntry> {
        (0..count)
            .map(|i| {
                let seed = [i as u8 + 1; 32];
                let keys = generate_from_master_seed(format!("validator-{i}"), seed).unwrap();
                let cold_public = indra_crypto::ColdHybridKeypair::from_independent_seeds(
                    [i as u8 + 41; 32],
                    [i as u8 + 81; 32],
                )
                .unwrap()
                .public_key();
                let cold = cold_public.as_complete_hybrid();
                let mut entry =
                    entry_from_keys(&format!("validator-{i}"), &keys, DUST_LIMIT_SPARK * 10);
                entry.cold_hybrid_classical_pk = hex::encode(cold.classical.0);
                entry.cold_hybrid_pq_pk = hex::encode(cold.pq.0);
                let validator_id = indra_core::Bytes32::from(keys.public.validator_id);
                let vrf = indra_crypto::VrfKeypair::from_seed(&keys.vrf_seed);
                let challenge = indra_core::types::staking::StakingOp::vrf_possession_challenge(
                    chain_id,
                    &validator_id,
                    &indra_core::Bytes32::from(vrf.public_key()),
                    0,
                )
                .unwrap();
                let (output, proof) = indra_crypto::vrf_prove(&vrf, &challenge);
                entry.vrf_possession_output = hex::encode(output.0);
                entry.vrf_possession_proof = hex::encode(proof.0);
                entry.genesis_commitment_nonce = hex::encode([i as u8 + 121; 32]);
                entry
            })
            .collect()
    }

    #[test]
    fn build_valid_genesis() {
        let validators = test_validators("indra-testnet-1", 4);
        let config = build("indra-testnet-1", validators).unwrap();
        assert_eq!(config.validators.len(), 4);
        let parsed = indra_node::parse_genesis_manifest_str(&config.to_toml()).unwrap();
        assert_eq!(parsed.genesis.chain_id, config.chain_id);
        assert_eq!(parsed.validators.len(), config.validators.len());
        for (parsed, expected) in parsed.validators.iter().zip(&config.validators) {
            assert_eq!(parsed.validator_id, expected.validator_id);
            assert_eq!(
                parsed.cold_hybrid_classical_pk,
                expected.cold_hybrid_classical_pk
            );
            assert_eq!(parsed.cold_hybrid_pq_pk, expected.cold_hybrid_pq_pk);
            assert_eq!(parsed.cold_key_version, expected.cold_key_version);
            assert_eq!(parsed.cold_nonce, expected.cold_nonce);
        }
    }

    #[test]
    fn toml_renderer_escapes_operator_text() {
        let validators = test_validators("indra-\"test\\chain", 4);
        let config = build("indra-\"test\\chain", validators).unwrap();
        let parsed = indra_node::parse_genesis_manifest_str(&config.to_toml()).unwrap();
        assert_eq!(parsed.genesis.chain_id, "indra-\"test\\chain");
    }

    #[test]
    fn too_few_validators_rejected() {
        let validators = test_validators("test", 3);
        let result = build("test", validators);
        assert!(result.is_err());
    }

    #[test]
    fn below_dust_stake_rejected() {
        let mut validators = test_validators("test", 4);
        validators[0].stake = 1; // below DUST_LIMIT_SPARK
        let result = build("test", validators);
        assert!(result.is_err());
    }

    #[test]
    fn duplicate_validator_id_rejected() {
        let mut validators = test_validators("test", 4);
        validators[1].validator_id = validators[0].validator_id.clone();
        let result = build("test", validators);
        assert!(result.is_err());
    }

    #[test]
    fn toml_output_has_all_fields() {
        let validators = test_validators("indra-testnet-1", 4);
        let config = build("indra-testnet-1", validators).unwrap();
        let toml = config.to_toml();
        assert!(toml.contains("[genesis]"));
        assert!(toml.contains("[[validators]]"));
        assert!(toml.contains("validator_id"));
        assert!(!toml.contains("bls_pk"));
    }
}
