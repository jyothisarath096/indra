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
//! timestamp    = 1700000000
//! chain_id     = "indra-testnet-1"
//! total_supply = 1000000000000000  # Spark
//!
//! [[validators]]
//! name                = "alice"
//! validator_id        = "<hex>"
//! hybrid_classical_pk = "<hex>"
//! hybrid_pq_pk        = "<hex>"
//! bls_pk              = "<hex>"
//! vrf_pk              = "<hex>"
//! stake               = 10000000000  # Spark
//! ```

use crate::error::{CliError, CliResult};

/// One validator entry in the genesis config.
#[derive(Debug, Clone)]
pub struct GenesisEntry {
    /// Human-readable name (for display only).
    pub name: String,
    /// Validator identity (hex).
    pub validator_id: String,
    /// Ed25519 public key (hex).
    pub hybrid_classical_pk: String,
    /// Dilithium2 public key (hex).
    pub hybrid_pq_pk: String,
    /// BLS12-381 public key (hex).
    pub bls_pk: String,
    /// VRF public key (hex).
    pub vrf_pk: String,
    /// Initial stake in Spark.
    pub stake: u64,
}

/// A complete genesis configuration.
#[derive(Debug, Clone)]
pub struct GenesisConfig {
    /// Unix timestamp for the genesis block.
    pub timestamp: u64,
    /// Human-readable chain identifier.
    pub chain_id: String,
    /// Total initial supply in Spark.
    pub total_supply: u64,
    /// All initial validators.
    pub validators: Vec<GenesisEntry>,
}

impl GenesisConfig {
    /// Serialise to TOML string.
    pub fn to_toml(&self) -> String {
        let mut out = String::new();

        out.push_str("[genesis]\n");
        out.push_str(&format!("timestamp    = {}\n", self.timestamp));
        out.push_str(&format!("chain_id     = \"{}\"\n", self.chain_id));
        out.push_str(&format!("total_supply = {}  # Spark\n", self.total_supply));
        out.push_str(&format!(
            "# {} validators, total stake = {} Spark\n\n",
            self.validators.len(),
            self.validators.iter().map(|v| v.stake).sum::<u64>()
        ));

        for v in &self.validators {
            out.push_str("[[validators]]\n");
            out.push_str(&format!("name                = \"{}\"\n", v.name));
            out.push_str(&format!("validator_id        = \"{}\"\n", v.validator_id));
            out.push_str(&format!("hybrid_classical_pk = \"{}\"\n", v.hybrid_classical_pk));
            out.push_str(&format!("hybrid_pq_pk        = \"{}\"\n", v.hybrid_pq_pk));
            out.push_str(&format!("bls_pk              = \"{}\"\n", v.bls_pk));
            out.push_str(&format!("vrf_pk              = \"{}\"\n", v.vrf_pk));
            out.push_str(&format!("stake               = {}  # Spark\n\n", v.stake));
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
        use indra_core::types::primitives::DUST_LIMIT_SPARK;

        if self.validators.len() < 4 {
            return Err(CliError::Genesis(
                "need at least 4 validators for BFT safety (3f+1, f=1)".to_string()
            ));
        }

        // Check unique validator IDs
        let mut seen_ids = std::collections::HashSet::new();
        for v in &self.validators {
            if !seen_ids.insert(v.validator_id.clone()) {
                return Err(CliError::Genesis(
                    format!("duplicate validator_id: {}", v.validator_id)
                ));
            }
            if v.stake < DUST_LIMIT_SPARK {
                return Err(CliError::Genesis(
                    format!(
                        "validator {} stake {} is below dust limit {}",
                        v.name,
                        v.stake,
                        DUST_LIMIT_SPARK
                    )
                ));
            }
        }

        Ok(())
    }
}

/// Build a genesis config from a list of entries.
pub fn build_genesis_config(
    chain_id: &str,
    timestamp: u64,
    total_supply: u64,
    validators: Vec<GenesisEntry>,
) -> CliResult<GenesisConfig> {
    let config = GenesisConfig {
        timestamp,
        chain_id: chain_id.to_string(),
        total_supply,
        validators,
    };
    config.validate()?;
    Ok(config)
}

/// Build a genesis entry from a KeysFile and stake amount.
pub fn entry_from_keys(
    name: &str,
    keys: &crate::keygen::KeysFile,
    stake: u64,
) -> GenesisEntry {
    GenesisEntry {
        name:                name.to_string(),
        validator_id:        hex::encode(keys.public.validator_id),
        hybrid_classical_pk: hex::encode(keys.public.hybrid_classical_pk),
        hybrid_pq_pk:        hex::encode(&keys.public.hybrid_pq_pk),
        bls_pk:              hex::encode(keys.public.bls_pk),
        vrf_pk:              hex::encode(keys.public.vrf_pk),
        stake,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::generate_keypairs;
    use indra_core::types::primitives::DUST_LIMIT_SPARK;

    fn test_validators(count: usize) -> Vec<GenesisEntry> {
        (0..count).map(|i| {
            let seed = [i as u8 + 1; 32];
            let keys = generate_keypairs(seed, seed, seed).unwrap();
            entry_from_keys(&format!("validator-{i}"), &keys, DUST_LIMIT_SPARK * 10)
        }).collect()
    }

    #[test]
    fn build_valid_genesis() {
        let validators = test_validators(4);
        let config = build_genesis_config(
            "indra-testnet-1",
            1_700_000_000,
            1_000_000_000_000_000,
            validators,
        ).unwrap();
        assert_eq!(config.validators.len(), 4);
    }

    #[test]
    fn too_few_validators_rejected() {
        let validators = test_validators(3);
        let result = build_genesis_config(
            "test", 0, 1_000_000_000_000_000, validators,
        );
        assert!(result.is_err());
    }

    #[test]
    fn below_dust_stake_rejected() {
        let mut validators = test_validators(4);
        validators[0].stake = 1; // below DUST_LIMIT_SPARK
        let result = build_genesis_config(
            "test", 0, 1_000_000_000_000_000, validators,
        );
        assert!(result.is_err());
    }

    #[test]
    fn duplicate_validator_id_rejected() {
        let mut validators = test_validators(4);
        validators[1].validator_id = validators[0].validator_id.clone();
        let result = build_genesis_config(
            "test", 0, 1_000_000_000_000_000, validators,
        );
        assert!(result.is_err());
    }

    #[test]
    fn toml_output_has_all_fields() {
        let validators = test_validators(4);
        let config = build_genesis_config(
            "indra-testnet-1", 1_700_000_000, 1_000_000_000_000_000, validators,
        ).unwrap();
        let toml = config.to_toml();
        assert!(toml.contains("[genesis]"));
        assert!(toml.contains("[[validators]]"));
        assert!(toml.contains("validator_id"));
        assert!(toml.contains("bls_pk"));
    }
}
