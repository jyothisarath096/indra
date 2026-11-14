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
            out.push_str(&format!(
                "hybrid_classical_pk = \"{}\"\n",
                validator.hybrid_classical_pk
            ));
            out.push_str(&format!("hybrid_pq_pk = \"{}\"\n", validator.hybrid_pq_pk));
            out.push_str(&format!("vrf_pk = \"{}\"\n", validator.vrf_pk));
            out.push_str(&format!(
                "vrf_possession_output = \"{}\"\n",
                validator.vrf_possession_output
            ));
            out.push_str(&format!(
                "vrf_possession_proof = \"{}\"\n",
                validator.vrf_possession_proof
            ));
            out.push_str(&format!(
                "cold_hybrid_classical_pk = \"{}\"\n",
                validator.cold_hybrid_classical_pk
            ));
            out.push_str(&format!(
                "cold_hybrid_pq_pk = \"{}\"\n",
                validator.cold_hybrid_pq_pk
            ));
            out.push_str(&format!(
                "cold_key_version = {}\n",
                validator.cold_key_version
            ));
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
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

pub fn build_genesis_config(
    chain_id: &str,
    genesis_timestamp: u64,
    validators: Vec<GenesisEntry>,
) -> CliResult<GenesisConfig> {
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
