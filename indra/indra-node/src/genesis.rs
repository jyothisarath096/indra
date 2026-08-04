//! Genesis block and initial chain state.
//!
//! The genesis block is height 0. It has:
//! - An all-zero prev_hash
//! - No transactions, slashing evidence, or governance ops
//! - A zeroed QC (no previous block to certify)
//! - The initial base fee
//!
//! Canonical genesis state is assembled and finalized by this module. Direct
//! `ChainState::new_genesis()` use is only an intermediate builder state.

use indra_core::types::{
    block::{BlockHeaderV1, BlockV1},
    crypto::{CommitmentV1, HybridPubKey},
    primitives::{
        Bytes32, ProtocolVersion, VariableBytes, GENESIS_SUPPLY_SPARK, HARD_CAP_SPARK,
        INITIAL_BASE_FEE_SPARK_PER_KB, MAX_QC_SIZE_BYTES, MAX_VRF_PROOF_BYTES,
    },
    transaction::OutputV1,
};
use indra_crypto::{commit, derive_genesis_utxo_blinding, prove_range, sha256};
use indra_state::ChainState;
use rand::{rngs::StdRng, SeedableRng};
use serde::Deserialize;

const GENESIS_VALIDATOR_UTXO_SPARK: u64 = 1_000_000_000_000;

/// Canonical structured genesis manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisManifest {
    /// Chain-wide settings.
    pub genesis: GenesisSettings,
    /// Initial active validators.
    pub validators: Vec<GenesisValidator>,
    /// Optional network bootstrap hints (not consensus state).
    #[serde(default)]
    pub seeds: Vec<GenesisSeed>,
}

/// Consensus-relevant genesis settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisSettings {
    /// Replay-protection domain for the new chain.
    pub chain_id: String,
}

/// One initial validator in the canonical genesis manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisValidator {
    /// Human-readable operator label.
    pub name: String,
    /// SHA-256 identity derived from the classical hot key.
    pub validator_id: String,
    /// Ed25519 hot public key.
    pub hybrid_classical_pk: String,
    /// ML-DSA-87 hot public key.
    pub hybrid_pq_pk: String,
    /// VRF public key.
    pub vrf_pk: String,
    /// Ed25519 cold public key.
    pub cold_hybrid_classical_pk: String,
    /// ML-DSA-87 cold public key.
    pub cold_hybrid_pq_pk: String,
    /// Initial cold-key generation number.
    pub cold_key_version: u64,
    /// Initial cold replay nonce.
    pub cold_nonce: u64,
    /// Initial self-stake in Spark.
    pub stake: u64,
}

/// Optional non-consensus bootstrap address.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisSeed {
    /// Public host and P2P port.
    pub addr: String,
}

/// Parse and fully validate the canonical genesis manifest.
pub fn parse_genesis_manifest(genesis_path: &str) -> Result<GenesisManifest, String> {
    let content = std::fs::read_to_string(genesis_path)
        .map_err(|error| format!("cannot read {genesis_path}: {error}"))?;
    parse_genesis_manifest_str(&content)
}

/// Parse and fully validate canonical genesis TOML bytes.
pub fn parse_genesis_manifest_str(content: &str) -> Result<GenesisManifest, String> {
    parse_genesis_manifest_str_with_minimum(content, 4)
}

fn parse_genesis_manifest_str_with_minimum(
    content: &str,
    minimum_validators: usize,
) -> Result<GenesisManifest, String> {
    let manifest: GenesisManifest =
        toml::from_str(content).map_err(|error| format!("invalid genesis TOML: {error}"))?;
    validate_genesis_manifest_with_minimum(&manifest, minimum_validators)?;
    Ok(manifest)
}

/// Validate all cross-field and uniqueness invariants for genesis.
pub fn validate_genesis_manifest(manifest: &GenesisManifest) -> Result<(), String> {
    validate_genesis_manifest_with_minimum(manifest, 4)
}

fn validate_genesis_manifest_with_minimum(
    manifest: &GenesisManifest,
    minimum_validators: usize,
) -> Result<(), String> {
    use std::collections::HashSet;
    let chain_id = manifest.genesis.chain_id.as_bytes();
    if chain_id.is_empty() {
        return Err("genesis chain_id must not be empty".into());
    }
    if chain_id.len() > indra_core::types::primitives::MAX_CHAIN_ID_BYTES {
        return Err(format!(
            "genesis chain_id exceeds {} bytes",
            indra_core::types::primitives::MAX_CHAIN_ID_BYTES
        ));
    }
    if manifest.validators.len() < minimum_validators {
        return Err(format!(
            "genesis requires at least {minimum_validators} validators for BFT safety"
        ));
    }
    let mut validator_ids = HashSet::new();
    let mut classical_keys = HashSet::new();
    let mut pq_keys = HashSet::new();
    let mut vrf = HashSet::new();
    for validator in &manifest.validators {
        let validator_id = decode_hex_exact::<32>(&validator.validator_id, "validator_id")?;
        let classical =
            decode_hex_exact::<32>(&validator.hybrid_classical_pk, "hybrid_classical_pk")?;
        let pq = decode_hex_len(
            &validator.hybrid_pq_pk,
            indra_crypto::PQ_PK_BYTES,
            "hybrid_pq_pk",
        )?;
        let vrf_pk = decode_hex_exact::<32>(&validator.vrf_pk, "vrf_pk")?;
        let cold_classical_pk = decode_hex_exact::<32>(
            &validator.cold_hybrid_classical_pk,
            "cold_hybrid_classical_pk",
        )?;
        let cold_pq_pk = decode_hex_len(
            &validator.cold_hybrid_pq_pk,
            indra_crypto::PQ_PK_BYTES,
            "cold_hybrid_pq_pk",
        )?;
        if validator_id != indra_crypto::sha256(&classical) {
            return Err(format!(
                "genesis validator {} validator_id does not match its classical hot key",
                validator.name
            ));
        }
        for (inserted, label) in [
            (validator_ids.insert(validator_id.to_vec()), "validator_id"),
            (
                classical_keys.insert(classical.to_vec()),
                "classical hot/cold key",
            ),
            (pq_keys.insert(pq), "PQ hot/cold key"),
            (vrf.insert(vrf_pk.to_vec()), "VRF key"),
            (
                classical_keys.insert(cold_classical_pk.to_vec()),
                "classical hot/cold key",
            ),
            (pq_keys.insert(cold_pq_pk), "PQ hot/cold key"),
        ] {
            if !inserted {
                return Err(format!("duplicate genesis {label}"));
            }
        }
        if validator.stake < indra_core::types::primitives::DUST_LIMIT_SPARK {
            return Err(format!(
                "genesis validator {} stake is below dust",
                validator.name
            ));
        }
        if validator.cold_key_version == 0 {
            return Err(format!(
                "genesis validator {} cold_key_version must be nonzero",
                validator.name
            ));
        }
    }
    Ok(())
}

fn decode_hex_exact<const N: usize>(value: &str, field: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(value).map_err(|_| format!("invalid hex in genesis {field}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("genesis {field} must be exactly {N} bytes"))
}

fn decode_hex_len(value: &str, expected: usize, field: &str) -> Result<Vec<u8>, String> {
    let bytes = hex::decode(value).map_err(|_| format!("invalid hex in genesis {field}"))?;
    if bytes.len() != expected {
        return Err(format!("genesis {field} must be exactly {expected} bytes"));
    }
    Ok(bytes)
}

/// Build the genesis block.
///
/// The genesis block hash is SHA-256(encode(genesis_header)).
pub fn build_genesis_block() -> BlockV1 {
    BlockV1 {
        header: BlockHeaderV1 {
            protocol_version: ProtocolVersion::CURRENT,
            height: 0,
            prev_hash: Bytes32::ZERO,
            timestamp: 1_700_000_000, // 2023-11-14 — fixed genesis timestamp
            state_root: Bytes32::ZERO,
            validator_set_root: Bytes32::ZERO,
            mempool_set_root: Bytes32::ZERO,
            value_hash: Bytes32::ZERO,
            base_fee: INITIAL_BASE_FEE_SPARK_PER_KB,
            proposer_round: 0,
            polc_round: indra_core::types::block::NO_POLC_ROUND,
            proposer_vrf_output: Bytes32::ZERO,
            proposer_vrf_proof: VariableBytes::<MAX_VRF_PROOF_BYTES>::default(),
            quorum_certificate: VariableBytes::<MAX_QC_SIZE_BYTES>::default(),
            election_result_hash: None,
        },
        transactions: vec![],
        slashing_evidence: vec![],
        governance_ops: vec![],
        staking_ops: vec![],
        vrf_reveals: vec![],
    }
}

/// Compute the genesis block hash.
pub fn genesis_block_hash() -> Bytes32 {
    use indra_core::codec::Encode;
    let block = build_genesis_block();
    Bytes32::from(sha256(&block.header.encode_to_vec()))
}

/// Build the canonical local genesis state.
///
/// The returned value is fully finalized: all genesis-native authority
/// snapshots and commitments are present.
pub fn build_genesis_state() -> ChainState {
    use indra_crypto::{ClassicalKeypair, ColdHybridKeypair, HybridKeypair, PqKeypair, VrfKeypair};
    use indra_state::{ValidatorEntry, ValidatorStatus};

    let mut state = ChainState::new_genesis();
    let hot = HybridKeypair::new(
        ClassicalKeypair::from_seed(&[0xD1; 32]),
        PqKeypair::from_seed(&[0xD2; 32]).unwrap(),
    );
    let hot_public = hot.public_key();
    let cold = ColdHybridKeypair::from_independent_seeds([0xD3; 32], [0xD4; 32]).unwrap();
    let cold_public = cold.public_key();
    let cold_public = cold_public.as_complete_hybrid();
    let vrf_pk = VrfKeypair::from_seed(&[0xD5; 32]).public_key();
    let validator_id = Bytes32::from(sha256(&hot_public.classical.0));
    state
        .validators
        .upsert(ValidatorEntry {
            validator_id,
            name: "canonical-local-genesis".into(),
            hybrid_classical_pk: Some(hot_public.classical.0),
            hybrid_pq_pk: Some(hot_public.pq.0.to_vec()),
            vrf_pk: Some(vrf_pk),
            stake_spark: 1_000_000,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            pending_rewards: 0,
            rewards_last_epoch: 0,
            self_report_count: 0,
            commission_bps: indra_core::types::primitives::DEFAULT_COMMISSION_BPS,
            pending_commission_bps: None,
            pending_commission_effective_epoch: None,
            min_delegation_spark: indra_core::types::primitives::DUST_LIMIT_SPARK,
            auto_delegate_to: None,
            network_addr: None,
            network_addr_last_updated_epoch: None,
            cold_hybrid_classical_pk: Some(cold_public.classical.0),
            cold_hybrid_pq_pk: Some(cold_public.pq.0),
            cold_key_version: 1,
            cold_nonce: 0,
        })
        .unwrap();
    state.finalize_genesis().unwrap();
    assert_eq!(state.total_supply, GENESIS_SUPPLY_SPARK);
    assert!(state.total_supply <= HARD_CAP_SPARK);
    assert_eq!(state.fee_reward_pool, 0);
    state
}

/// Rebuild all genesis-native authority structures after a test has assembled
/// or amended its height-zero validator set.
#[cfg(test)]
pub(crate) fn finalize_test_genesis(state: &mut ChainState) {
    assert_eq!(state.height, 0, "test genesis must remain at height zero");
    state.consensus_snapshots.clear();
    state.reward_economic_snapshot = None;
    state.slash_membership_roots.clear();
    state.finalize_genesis().unwrap();
}

/// Construct a complete one-validator genesis for tests that do not care about
/// a particular authority identity but still exercise canonical state logic.
#[cfg(test)]
pub(crate) fn canonical_test_genesis() -> ChainState {
    build_genesis_state()
}

/// Load validator entries from a genesis.toml file.
///
/// Reads each [[validators]] section and registers them in the
/// provided ChainState validator set with Active status.
pub fn load_genesis_validators(
    genesis_path: &str,
    state: &mut indra_state::ChainState,
) -> Result<(), String> {
    load_genesis_validators_with_minimum(genesis_path, state, 4)
}

fn load_genesis_validators_with_minimum(
    genesis_path: &str,
    state: &mut indra_state::ChainState,
    minimum_validators: usize,
) -> Result<(), String> {
    use indra_core::types::primitives::Bytes32;
    use indra_state::{ValidatorEntry, ValidatorStatus};

    let content = std::fs::read_to_string(genesis_path)
        .map_err(|error| format!("cannot read {genesis_path}: {error}"))?;
    let manifest = parse_genesis_manifest_str_with_minimum(&content, minimum_validators)?;
    state.chain_id = manifest.genesis.chain_id.clone();
    let validators = manifest.validators;

    // NOTE: startup logging for node bootstrap; replace with structured tracing later.
    println!(
        "[genesis] Loading {} validators from {}",
        validators.len(),
        genesis_path
    );

    for v in &validators {
        let id_hex = &v.validator_id;
        let stake = v.stake;
        let name = &v.name;
        let arr = decode_hex_exact::<32>(id_hex, "validator_id")?;
        let validator_id = Bytes32::from(arr);

        let entry = ValidatorEntry {
            validator_id,
            name: name.clone(),
            hybrid_classical_pk: Some(decode_hex_exact::<32>(
                &v.hybrid_classical_pk,
                "hybrid_classical_pk",
            )?),
            hybrid_pq_pk: Some(decode_hex_len(
                &v.hybrid_pq_pk,
                indra_crypto::PQ_PK_BYTES,
                "hybrid_pq_pk",
            )?),
            vrf_pk: Some(decode_hex_exact::<32>(&v.vrf_pk, "vrf_pk")?),
            stake_spark: stake,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            pending_rewards: 0,
            rewards_last_epoch: 0,
            self_report_count: 0,
            commission_bps: indra_core::types::primitives::DEFAULT_COMMISSION_BPS,
            pending_commission_bps: None,
            pending_commission_effective_epoch: None,
            min_delegation_spark: indra_core::types::primitives::DUST_LIMIT_SPARK,
            auto_delegate_to: None,
            network_addr: None,
            network_addr_last_updated_epoch: None,
            cold_hybrid_classical_pk: Some(decode_hex_exact::<32>(
                &v.cold_hybrid_classical_pk,
                "cold_hybrid_classical_pk",
            )?),
            cold_hybrid_pq_pk: Some(decode_hex_exact::<{ indra_crypto::PQ_PK_BYTES }>(
                &v.cold_hybrid_pq_pk,
                "cold_hybrid_pq_pk",
            )?),
            cold_key_version: v.cold_key_version,
            cold_nonce: v.cold_nonce,
        };

        state
            .validators
            .upsert(entry)
            .map_err(|error| error.to_string())?;
        if let (Some(classical_pk), Some(hybrid_pq_pk)) = (
            Some(decode_hex_exact::<32>(
                &v.hybrid_classical_pk,
                "hybrid_classical_pk",
            )?),
            Some(decode_hex_len(
                &v.hybrid_pq_pk,
                indra_crypto::PQ_PK_BYTES,
                "hybrid_pq_pk",
            )?),
        ) {
            let blinding = derive_genesis_utxo_blinding(&validator_id.0);
            let commitment = commit(GENESIS_VALIDATOR_UTXO_SPARK, &blinding);
            let mut rng = StdRng::from_seed(validator_id.0);
            if let Ok(proof) = prove_range(GENESIS_VALIDATOR_UTXO_SPARK, &blinding, &mut rng) {
                let output = OutputV1 {
                    value_spark: GENESIS_VALIDATOR_UTXO_SPARK,
                    commitment: CommitmentV1 {
                        compressed_point: Bytes32::from(commitment.0),
                    },
                    owner_pubkey: HybridPubKey {
                        classical_pk: Bytes32::from(classical_pk),
                        pq_pk: VariableBytes::from_slice(&hybrid_pq_pk).unwrap_or_default(),
                    },
                    range_proof: VariableBytes::from_slice(&proof).unwrap_or_default(),
                    lock_height: 0,
                };
                let _ = state.utxos.insert(output, 0, 0, state.utxos.len() as u32);
                eprintln!(
                    "[genesis] created UTXO {} Spark for {}",
                    GENESIS_VALIDATOR_UTXO_SPARK, name
                );
            }
        }
        // NOTE: startup logging for node bootstrap; replace with structured tracing later.
        println!(
            "[genesis]   + {} ({}...) stake={} Spark",
            name,
            &id_hex[..8],
            stake
        );
    }
    // NOTE: validator stake is bonded in ValidatorEntry only.
    // Liquid allocations are handled separately from validator bonding state.
    Ok(())
}

/// Construct and finalize genesis from the configured validator manifest.
/// Every production startup/replay path must use this constructor rather than
/// treating `ChainState::new_genesis()` as a valid canonical state.
pub fn build_finalized_genesis_state(genesis_path: Option<&str>) -> Result<ChainState, String> {
    build_finalized_genesis_state_with_minimum(genesis_path, 4)
}

pub(crate) fn build_finalized_genesis_state_with_minimum(
    genesis_path: Option<&str>,
    minimum_validators: usize,
) -> Result<ChainState, String> {
    let mut state = ChainState::new_genesis();
    let path = genesis_path.ok_or_else(|| {
        "canonical genesis construction requires a validated genesis manifest".to_string()
    })?;
    load_genesis_validators_with_minimum(path, &mut state, minimum_validators)?;
    state
        .finalize_genesis()
        .map_err(|error| error.to_string())?;
    Ok(state)
}

/// Load optional P2P seed peer hints from a genesis.toml file.
pub fn load_genesis_seed_peers(genesis_path: &str) -> Vec<String> {
    parse_genesis_manifest(genesis_path)
        .map(|manifest| manifest.seeds.into_iter().map(|seed| seed.addr).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_crypto::derive_genesis_utxo_blinding_from_classical_pk;

    fn valid_manifest() -> GenesisManifest {
        let validators = (0..4u8)
            .map(|index| {
                let hot = indra_crypto::HybridKeypair::new(
                    indra_crypto::ClassicalKeypair::from_seed(&[index + 1; 32]),
                    indra_crypto::PqKeypair::from_seed(&[index + 11; 32]).unwrap(),
                );
                let hot_public = hot.public_key();
                let cold = indra_crypto::ColdHybridKeypair::from_independent_seeds(
                    [index + 21; 32],
                    [index + 31; 32],
                )
                .unwrap();
                let cold_public = cold.public_key();
                let cold_public = cold_public.as_complete_hybrid();
                GenesisValidator {
                    name: format!("validator-{index}"),
                    validator_id: hex::encode(sha256(&hot_public.classical.0)),
                    hybrid_classical_pk: hex::encode(hot_public.classical.0),
                    hybrid_pq_pk: hex::encode(hot_public.pq.0),
                    vrf_pk: hex::encode(
                        indra_crypto::VrfKeypair::from_seed(&[index + 41; 32]).public_key(),
                    ),
                    cold_hybrid_classical_pk: hex::encode(cold_public.classical.0),
                    cold_hybrid_pq_pk: hex::encode(cold_public.pq.0),
                    cold_key_version: 1,
                    cold_nonce: 0,
                    stake: 100_000_000_000,
                }
            })
            .collect();
        GenesisManifest {
            genesis: GenesisSettings {
                chain_id: "indra-testnet-new".into(),
            },
            validators,
            seeds: vec![],
        }
    }

    fn render_manifest(manifest: &GenesisManifest, omit_cold: bool) -> String {
        let mut rendered = format!("[genesis]\nchain_id = \"{}\"\n", manifest.genesis.chain_id);
        for validator in &manifest.validators {
            rendered.push_str(&format!("\n[[validators]]\nname = \"{}\"\nvalidator_id = \"{}\"\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\n", validator.name, validator.validator_id, validator.hybrid_classical_pk, validator.hybrid_pq_pk, validator.vrf_pk));
            if !omit_cold {
                rendered.push_str(&format!(
                    "cold_hybrid_classical_pk = \"{}\"\ncold_hybrid_pq_pk = \"{}\"\n",
                    validator.cold_hybrid_classical_pk, validator.cold_hybrid_pq_pk
                ));
            }
            rendered.push_str(&format!(
                "cold_key_version = {}\ncold_nonce = {}\nstake = {}\n",
                validator.cold_key_version, validator.cold_nonce, validator.stake
            ));
        }
        rendered
    }

    #[test]
    fn canonical_genesis_rejects_missing_cold_fields_and_bad_chain_ids() {
        let manifest = valid_manifest();
        assert!(parse_genesis_manifest_str(&render_manifest(&manifest, true)).is_err());
        let mut empty = manifest.clone();
        empty.genesis.chain_id.clear();
        assert!(validate_genesis_manifest(&empty).is_err());
        let mut oversized = manifest;
        oversized.genesis.chain_id =
            "x".repeat(indra_core::types::primitives::MAX_CHAIN_ID_BYTES + 1);
        assert!(validate_genesis_manifest(&oversized).is_err());
    }

    #[test]
    fn canonical_genesis_rejects_too_few_mismatched_and_duplicate_identities() {
        let baseline = valid_manifest();
        let mut too_few = baseline.clone();
        too_few.validators.pop();
        assert!(validate_genesis_manifest(&too_few).is_err());

        let mut mismatch = baseline.clone();
        mismatch.validators[0].validator_id = hex::encode([0xFF; 32]);
        assert!(validate_genesis_manifest(&mismatch).is_err());

        for field in 0..6 {
            let mut duplicate = baseline.clone();
            match field {
                0 => {
                    duplicate.validators[1].validator_id =
                        duplicate.validators[0].validator_id.clone()
                }
                1 => {
                    duplicate.validators[1].hybrid_classical_pk =
                        duplicate.validators[0].hybrid_classical_pk.clone()
                }
                2 => {
                    duplicate.validators[1].hybrid_pq_pk =
                        duplicate.validators[0].hybrid_pq_pk.clone()
                }
                3 => duplicate.validators[1].vrf_pk = duplicate.validators[0].vrf_pk.clone(),
                4 => {
                    duplicate.validators[1].cold_hybrid_classical_pk =
                        duplicate.validators[0].cold_hybrid_classical_pk.clone()
                }
                _ => {
                    duplicate.validators[1].cold_hybrid_pq_pk =
                        duplicate.validators[0].cold_hybrid_pq_pk.clone()
                }
            }
            assert!(validate_genesis_manifest(&duplicate).is_err());
        }
    }

    #[test]
    fn genesis_block_is_deterministic() {
        let h1 = genesis_block_hash();
        let h2 = genesis_block_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn genesis_block_height_is_zero() {
        let b = build_genesis_block();
        assert_eq!(b.header.height, 0);
    }

    #[test]
    fn genesis_block_has_zero_prev_hash() {
        let b = build_genesis_block();
        assert_eq!(b.header.prev_hash, Bytes32::ZERO);
    }

    #[test]
    fn genesis_state_height_is_zero() {
        let s = build_genesis_state();
        assert_eq!(s.height, 0);
    }

    #[test]
    fn genesis_utxo_blinding_opens_loaded_genesis_commitment() {
        let classical_pk = [0x42u8; 32];
        let validator_id = Bytes32::from(sha256(&classical_pk));
        let pq_pk = vec![0x24u8; 2592];
        let cold = indra_crypto::ColdHybridKeypair::from_independent_seeds([0x51; 32], [0x52; 32])
            .unwrap();
        let cold_public = cold.public_key();
        let cold_public = cold_public.as_complete_hybrid();
        let mut state = ChainState::new_genesis();
        let path = std::env::temp_dir().join(format!(
            "indra-genesis-blinding-test-{}.toml",
            std::process::id()
        ));
        let mut contents = format!(
            "[genesis]\nchain_id = \"test\"\n\n[[validators]]\nname = \"test-validator\"\nvalidator_id = \"{}\"\nstake = 100000000000\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\ncold_hybrid_classical_pk = \"{}\"\ncold_hybrid_pq_pk = \"{}\"\ncold_key_version = 1\ncold_nonce = 0\n",
            hex::encode(validator_id.0),
            hex::encode(classical_pk),
            hex::encode(&pq_pk),
            hex::encode([0x11u8; 32]),
            hex::encode(cold_public.classical.0),
            hex::encode(cold_public.pq.0),
        );
        for i in 1..4u8 {
            let hot = indra_crypto::HybridKeypair::new(
                indra_crypto::ClassicalKeypair::from_seed(&[0x60 + i; 32]),
                indra_crypto::PqKeypair::from_seed(&[0x70 + i; 32]).unwrap(),
            );
            let hot_public = hot.public_key();
            let extra_cold = indra_crypto::ColdHybridKeypair::from_independent_seeds(
                [0x80 + i; 32],
                [0x90 + i; 32],
            )
            .unwrap();
            let extra_cold_public = extra_cold.public_key();
            let extra_cold_public = extra_cold_public.as_complete_hybrid();
            contents.push_str(&format!(
                "\n[[validators]]\nname = \"extra-{i}\"\nvalidator_id = \"{}\"\nstake = 100000000000\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\ncold_hybrid_classical_pk = \"{}\"\ncold_hybrid_pq_pk = \"{}\"\ncold_key_version = 1\ncold_nonce = 0\n",
                hex::encode(sha256(&hot_public.classical.0)),
                hex::encode(hot_public.classical.0),
                hex::encode(hot_public.pq.0),
                hex::encode([0xA0 + i; 32]),
                hex::encode(extra_cold_public.classical.0),
                hex::encode(extra_cold_public.pq.0),
            ));
        }
        std::fs::write(&path, contents).unwrap();

        load_genesis_validators(path.to_str().unwrap(), &mut state).unwrap();
        let _ = std::fs::remove_file(&path);

        let entry = state
            .utxos
            .all_entries()
            .find(|entry| entry.output.owner_pubkey.classical_pk.0 == classical_pk)
            .unwrap();
        let blinding = derive_genesis_utxo_blinding_from_classical_pk(&classical_pk);
        let commitment = commit(GENESIS_VALIDATOR_UTXO_SPARK, &blinding);
        assert_eq!(entry.output.commitment.compressed_point.0, commitment.0);
    }
}
