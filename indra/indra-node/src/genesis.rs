//! Deterministic founder-controlled genesis construction.

use indra_core::types::{
    block::{BlockHeaderVNext, BlockProposalVNext, BlockVNext, SortitionClaimV1, VrfSuiteV1},
    crypto::{HybridPubKey, HybridSignature},
    primitives::{
        Bytes32, Bytes64, ProtocolVersion, VariableBytes, INITIAL_BASE_FEE_SPARK_PER_KB,
        MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES, MAX_QC_SIZE_BYTES,
        MAX_STANDARD_VRF_OUTPUT_BYTES, MAX_STANDARD_VRF_PROOF_BYTES,
        MIN_ACTIVE_VALIDATORS, LIFETIME_SUPPLY_CAP_SPARK,
    },
    transaction::OutputV1,
};
use indra_crypto::sha256;
#[cfg(any(test, feature = "test-support"))]
use indra_core::types::{crypto::hybrid_identity_id, staking::StakingOp, primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR};
#[cfg(any(test, feature = "test-support"))]
use indra_crypto::{vrf_prove, ClassicalKeypair, ColdHybridKeypair, PqKeypair, VrfKeypair};
use indra_state::ChainState;
use serde::{de::Error as _, Deserialize, Deserializer};
use sha2::{Digest, Sha512};

const GENESIS_VALIDATOR_UTXO_SPARK: u64 = 1_000_000_000_000;

/// Maximum UTF-8 byte length of a genesis validator name.
pub const MAX_GENESIS_VALIDATOR_NAME_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
/// Parsed deterministic genesis manifest.
pub struct GenesisManifest {
    /// Chain-wide genesis settings.
    pub genesis: GenesisSettings,
    /// Initial validator entries.
    pub validators: Vec<GenesisValidator>,
    /// Optional bootstrap seed peers.
    #[serde(default)]
    pub seeds: Vec<GenesisSeed>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
/// Consensus settings for deterministic genesis.
pub struct GenesisSettings {
    /// Chain identifier.
    pub chain_id: String,
    /// Fixed genesis header timestamp in seconds.
    pub genesis_timestamp: u64,
    /// Canonical active-slot coefficient numerator.
    #[serde(deserialize_with = "deserialize_canonical_decimal_u64")]
    pub active_slot_coefficient_numerator: u64,
}

fn deserialize_canonical_decimal_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    if encoded.is_empty()
        || !encoded.bytes().all(|byte| byte.is_ascii_digit())
        || (encoded.len() > 1 && encoded.starts_with('0'))
    {
        return Err(D::Error::custom(
            "active_slot_coefficient_numerator must be canonical ASCII decimal",
        ));
    }
    encoded.parse::<u64>().map_err(D::Error::custom)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
/// Public material and initial stake for one genesis validator.
pub struct GenesisValidator {
    /// Human-readable validator name.
    pub name: String,
    /// Validator identity digest.
    pub validator_id: String,
    /// Hot classical public key.
    pub hybrid_classical_pk: String,
    /// Hot post-quantum public key.
    pub hybrid_pq_pk: String,
    /// VRF public key.
    pub vrf_pk: String,
    /// VRF proof-of-possession output.
    pub vrf_possession_output: String,
    /// VRF proof-of-possession proof.
    pub vrf_possession_proof: String,
    /// Cold classical public key.
    pub cold_hybrid_classical_pk: String,
    /// Cold post-quantum public key.
    pub cold_hybrid_pq_pk: String,
    /// Cold-key version.
    pub cold_key_version: u64,
    /// Cold-key replay nonce.
    pub cold_nonce: u64,
    /// Initial self stake in spark.
    pub stake: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
/// Non-consensus bootstrap peer hint.
pub struct GenesisSeed {
    /// Peer address.
    pub addr: String,
}

/// Derive the initial election seed from sorted validator material.
pub fn derive_genesis_election_seed(
    settings: &GenesisSettings,
    validators: &[GenesisValidator],
) -> Result<Bytes64, String> {
    indra_core::sortition::validate_mainnet_f(settings.active_slot_coefficient_numerator)
        .map_err(|error| error.to_string())?;
    let chain = settings.chain_id.as_bytes();
    if chain.is_empty() || chain.len() > indra_core::types::primitives::MAX_CHAIN_ID_BYTES {
        return Err("genesis chain_id is outside the canonical length range".into());
    }
    let mut ordered = validators.to_vec();
    ordered.sort_by_key(|validator| validator.validator_id.clone());
    let mut material = b"INDRA-GENESIS-ELECTION-SEED-v2".to_vec();
    append_len_prefixed(&mut material, chain)?;
    material.extend_from_slice(
        &u32::try_from(ordered.len())
            .map_err(|_| "too many genesis validators")?
            .to_be_bytes(),
    );
    for validator in ordered {
        material.extend_from_slice(&decode_hex_exact::<32>(&validator.validator_id, "validator_id")?);
        append_len_prefixed(&mut material, &decode_hex_exact::<32>(&validator.hybrid_classical_pk, "hybrid_classical_pk")?)?;
        append_len_prefixed(&mut material, &decode_hex_len(&validator.hybrid_pq_pk, indra_crypto::PQ_PK_BYTES, "hybrid_pq_pk")?)?;
        append_len_prefixed(&mut material, &decode_hex_exact::<32>(&validator.vrf_pk, "vrf_pk")?)?;
        append_len_prefixed(&mut material, &decode_hex_exact::<32>(&validator.cold_hybrid_classical_pk, "cold_hybrid_classical_pk")?)?;
        append_len_prefixed(&mut material, &decode_hex_len(&validator.cold_hybrid_pq_pk, indra_crypto::PQ_PK_BYTES, "cold_hybrid_pq_pk")?)?;
        material.extend_from_slice(&validator.cold_key_version.to_be_bytes());
        material.extend_from_slice(&validator.cold_nonce.to_be_bytes());
        material.extend_from_slice(&validator.stake.to_be_bytes());
    }
    let digest = Sha512::digest(material);
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&digest);
    Ok(Bytes64(seed))
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| "genesis field is too large")?
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}

/// Read and validate a genesis manifest from disk.
pub fn parse_genesis_manifest(genesis_path: &str) -> Result<GenesisManifest, String> {
    parse_genesis_manifest_str(
        &std::fs::read_to_string(genesis_path)
            .map_err(|error| format!("cannot read {genesis_path}: {error}"))?,
    )
}

/// Parse and validate a genesis manifest string.
pub fn parse_genesis_manifest_str(content: &str) -> Result<GenesisManifest, String> {
    let manifest: GenesisManifest =
        toml::from_str(content).map_err(|error| format!("invalid genesis TOML: {error}"))?;
    validate_genesis_manifest(&manifest)?;
    Ok(manifest)
}

/// Validate all deterministic genesis invariants.
pub fn validate_genesis_manifest(manifest: &GenesisManifest) -> Result<(), String> {
    use std::collections::HashSet;
    if manifest.validators.len() < MIN_ACTIVE_VALIDATORS {
        return Err(format!(
            "genesis requires at least {MIN_ACTIVE_VALIDATORS} validators for BFT safety"
        ));
    }
    let mut ids = HashSet::new();
    let mut classical = HashSet::new();
    let mut pq = HashSet::new();
    let mut vrfs = HashSet::new();
    let total_stake = manifest.validators.iter().try_fold(0u64, |total, validator| {
        total.checked_add(validator.stake).ok_or_else(|| {
            "genesis validator stake total overflows u64".to_string()
        })
    })?;
    let genesis_utxo_total = (manifest.validators.len() as u64)
        .checked_mul(GENESIS_VALIDATOR_UTXO_SPARK)
        .ok_or_else(|| "genesis validator UTXO total overflows u64".to_string())?;
    let total_genesis_supply = total_stake
        .checked_add(genesis_utxo_total)
        .ok_or_else(|| "genesis total supply overflows u64".to_string())?;
    if total_genesis_supply > LIFETIME_SUPPLY_CAP_SPARK {
        return Err(format!(
            "genesis total supply exceeds lifetime supply cap {LIFETIME_SUPPLY_CAP_SPARK}"
        ));
    }
    for validator in &manifest.validators {
        validate_genesis_validator_name(&validator.name)?;
        let id = decode_hex_exact::<32>(&validator.validator_id, "validator_id")?;
        let hot_classical = decode_hex_exact::<32>(&validator.hybrid_classical_pk, "hybrid_classical_pk")?;
        let hot_pq = decode_hex_len(&validator.hybrid_pq_pk, indra_crypto::PQ_PK_BYTES, "hybrid_pq_pk")?;
        let vrf_pk = decode_hex_exact::<32>(&validator.vrf_pk, "vrf_pk")?;
        let output = decode_hex_exact::<64>(&validator.vrf_possession_output, "vrf_possession_output")?;
        let proof = decode_hex_exact::<80>(&validator.vrf_possession_proof, "vrf_possession_proof")?;
        let cold_classical = decode_hex_exact::<32>(&validator.cold_hybrid_classical_pk, "cold_hybrid_classical_pk")?;
        let cold_pq = decode_hex_len(&validator.cold_hybrid_pq_pk, indra_crypto::PQ_PK_BYTES, "cold_hybrid_pq_pk")?;
        let hot_identity = HybridPubKey {
            classical_pk: Bytes32::from(hot_classical),
            pq_pk: VariableBytes::from_slice(&hot_pq).map_err(|_| "hot PQ key is too large")?,
        };
        if id != hot_identity.identity_id().0 {
            return Err(format!("genesis validator {} has an incorrect validator_id", validator.name));
        }
        let challenge = indra_core::types::staking::StakingOp::vrf_possession_challenge(
            &manifest.genesis.chain_id,
            &Bytes32::from(id),
            &Bytes32::from(vrf_pk),
            0,
        )
        .map_err(|error| error.to_string())?;
        indra_crypto::vrf_verify(
            &vrf_pk,
            &challenge,
            &indra_crypto::VrfOutput(output),
            &indra_crypto::VrfProof(proof.to_vec()),
        )
        .map_err(|_| format!("genesis validator {} has an invalid VRF PoP", validator.name))?;
        if !ids.insert(id) || !vrfs.insert(vrf_pk) || !classical.insert(hot_classical) || !classical.insert(cold_classical) || !pq.insert(hot_pq.clone()) || !pq.insert(cold_pq.clone()) {
            return Err(format!("duplicate genesis validator or key in {}", validator.name));
        }
        indra_crypto::validate_classical_public_key(&indra_crypto::ClassicalPublicKey(hot_classical))
            .map_err(|_| format!("genesis validator {} has an invalid hot classical key", validator.name))?;
        let hot_pq: [u8; indra_crypto::PQ_PK_BYTES] = hot_pq.try_into().map_err(|_| "invalid hot PQ key length")?;
        indra_crypto::validate_pq_public_key(&indra_crypto::PqPublicKey(hot_pq))
            .map_err(|_| format!("genesis validator {} has an invalid hot PQ key", validator.name))?;
        indra_crypto::validate_classical_public_key(&indra_crypto::ClassicalPublicKey(cold_classical))
            .map_err(|_| format!("genesis validator {} has an invalid cold classical key", validator.name))?;
        let cold_pq: [u8; indra_crypto::PQ_PK_BYTES] = cold_pq.try_into().map_err(|_| "invalid cold PQ key length")?;
        indra_crypto::validate_pq_public_key(&indra_crypto::PqPublicKey(cold_pq))
            .map_err(|_| format!("genesis validator {} has an invalid cold PQ key", validator.name))?;
        if validator.cold_key_version != 1 || validator.cold_nonce != 0 {
            return Err(format!("genesis validator {} has invalid cold-key version or nonce", validator.name));
        }
        if validator.stake < indra_core::types::primitives::DUST_LIMIT_SPARK {
            return Err(format!("genesis validator {} stake is below dust", validator.name));
        }
    }
    derive_genesis_election_seed(&manifest.genesis, &manifest.validators)?;
    Ok(())
}

fn validate_genesis_validator_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("genesis validator name must not be empty".to_string());
    }
    if name.len() > MAX_GENESIS_VALIDATOR_NAME_BYTES {
        return Err(format!(
            "genesis validator name exceeds {MAX_GENESIS_VALIDATOR_NAME_BYTES} bytes"
        ));
    }
    if !name.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'.' | b'_' | b'-')
    }) {
        return Err("genesis validator name contains unsupported characters".to_string());
    }
    Ok(())
}

fn decode_hex_exact<const N: usize>(value: &str, field: &str) -> Result<[u8; N], String> {
    let bytes = decode_hex_len_any(value, field)?;
    bytes.try_into().map_err(|_| format!("genesis {field} must be exactly {N} bytes"))
}

fn decode_hex_len(value: &str, expected: usize, field: &str) -> Result<Vec<u8>, String> {
    let bytes = decode_hex_len_any(value, field)?;
    if bytes.len() != expected {
        return Err(format!("genesis {field} must be exactly {expected} bytes"));
    }
    Ok(bytes)
}

fn decode_hex_len_any(value: &str, field: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(format!("genesis {field} must be canonical lowercase hexadecimal"));
    }
    hex::decode(value).map_err(|_| format!("invalid hex in genesis {field}"))
}

/// Compute the genesis fingerprint from state commitments and metadata.
pub fn genesis_fingerprint(state: &ChainState) -> Result<Bytes32, String> {
    use indra_core::codec::Encode;
    let roots = indra_state::compute_state_roots(state);
    let snapshot = state.snapshot_for_consensus_height(1).map_err(|error| error.to_string())?;
    let mut preimage = b"INDRA-GENESIS-FINGERPRINT-v1".to_vec();
    let chain = state.chain_id.as_bytes();
    let len = u16::try_from(chain.len()).map_err(|_| "genesis chain id too long")?;
    preimage.extend_from_slice(&len.to_be_bytes());
    preimage.extend_from_slice(chain);
    preimage.extend_from_slice(&roots.state_root.0);
    preimage.extend_from_slice(&snapshot.snapshot_root.0);
    state.monetary_ledger.encode(&mut preimage);
    preimage.extend_from_slice(&state.election_seed.0);
    preimage.extend_from_slice(b"GENESIS-TIMESTAMP-v1");
    preimage.extend_from_slice(&state.genesis_timestamp.to_be_bytes());
    Ok(Bytes32::from(sha256(&preimage)))
}

/// Build the deterministic genesis block.
pub fn build_genesis_block(state: &ChainState) -> Result<BlockVNext, String> {
    let roots = indra_state::compute_state_roots(state);
    let fingerprint = genesis_fingerprint(state)?;
    Ok(BlockVNext {
        header: BlockHeaderVNext {
            protocol_version: ProtocolVersion::CURRENT,
            height: 0,
            prev_hash: Bytes32::ZERO,
            timestamp: state.genesis_timestamp,
            state_root: roots.state_root,
            validator_set_root: roots.validator_set_root,
            mempool_set_root: Bytes32::ZERO,
            value_hash: fingerprint,
            base_fee: INITIAL_BASE_FEE_SPARK_PER_KB,
            proposer_round: 0,
            polc_round: None,
            proposer_id: Bytes32::ZERO,
            vrf_suite: VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
            election_seed: state.election_seed,
            proposer_vrf_output: VariableBytes::<MAX_STANDARD_VRF_OUTPUT_BYTES>::default(),
            proposer_vrf_proof: VariableBytes::<MAX_STANDARD_VRF_PROOF_BYTES>::default(),
            value_entropy: indra_core::types::block::ProposalEntropyV1::genesis(),
            sortition_claim: SortitionClaimV1::PraosThreshold,
            proposer_priority: Bytes64([0; 64]),
            quorum_certificate: VariableBytes::<MAX_QC_SIZE_BYTES>::default(),
        },
        transactions: vec![],
        slashing_evidence: vec![],
        governance_ops: vec![],
        staking_ops: vec![],
    })
}

/// Build the deterministic unsigned genesis proposal.
pub fn build_genesis_proposal(state: &ChainState) -> Result<BlockProposalVNext, String> {
    Ok(BlockProposalVNext {
        block: build_genesis_block(state)?,
        proposer_authorization: HybridSignature {
            classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::default(),
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::default(),
        },
    })
}

/// Compute the deterministic genesis block hash.
pub fn genesis_block_hash(state: &ChainState) -> Result<Bytes32, String> {
    use indra_core::codec::Encode;
    Ok(Bytes32::from(sha256(&build_genesis_block(state)?.header.encode_to_vec())))
}

#[cfg(test)]
pub(crate) fn finalize_test_genesis(state: &mut ChainState) {
    assert_eq!(state.height, 0);
    state.active_slot_coefficient_numerator = indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR;
    state.consensus_snapshots.clear();
    state.reward_economic_snapshot = None;
    state.slash_membership_roots.clear();
    state.finalize_genesis().unwrap();
}

#[cfg(test)]
pub(crate) fn test_genesis_state() -> ChainState {
    let manifest = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        manifest.path(),
        test_genesis_toml(
            "indra-node-test",
            &[
                ([0xD1; 32], [0xD2; 32], [0xD5; 32]),
                ([0xB1; 32], [0xB2; 32], [0xB5; 32]),
                ([0xC1; 32], [0xC2; 32], [0xC5; 32]),
                ([0xE1; 32], [0xE2; 32], [0xE5; 32]),
            ],
        ),
    )
    .unwrap();
    build_finalized_genesis_state(manifest.path().to_str()).unwrap()
}

/// Load validator entries from a manifest into chain state.
fn load_genesis_validators(manifest: &GenesisManifest, state: &mut ChainState) -> Result<(), String> {
    state.genesis_timestamp = manifest.genesis.genesis_timestamp;
    state.active_slot_coefficient_numerator = manifest.genesis.active_slot_coefficient_numerator;
    state.election_seed = derive_genesis_election_seed(&manifest.genesis, &manifest.validators)?;
    state.election_seed_height = 1;
    let mut validators = manifest.validators.clone();
    validators.sort_by_key(|validator| validator.validator_id.clone());
    for validator in validators {
        let id = decode_hex_exact::<32>(&validator.validator_id, "validator_id")?;
        let hot_classical = decode_hex_exact::<32>(&validator.hybrid_classical_pk, "hybrid_classical_pk")?;
        let hot_pq = decode_hex_len(&validator.hybrid_pq_pk, indra_crypto::PQ_PK_BYTES, "hybrid_pq_pk")?;
        let cold_classical = decode_hex_exact::<32>(&validator.cold_hybrid_classical_pk, "cold_hybrid_classical_pk")?;
        let cold_pq = decode_hex_exact::<{ indra_crypto::PQ_PK_BYTES }>(&validator.cold_hybrid_pq_pk, "cold_hybrid_pq_pk")?;
        state.validators.upsert(indra_state::ValidatorEntry {
            validator_id: Bytes32::from(id), name: validator.name, hybrid_classical_pk: Some(hot_classical),
            hybrid_pq_pk: Some(hot_pq.clone()), vrf_pk: Some(decode_hex_exact::<32>(&validator.vrf_pk, "vrf_pk")?),
            vrf_key_activation_epoch: 0, pending_vrf_pk: None, pending_vrf_activation_epoch: None,
            stake_spark: validator.stake, status: indra_state::ValidatorStatus::Active,
            registered_epoch: 0, last_active_epoch: 0, slashed_offense_id: None,
            commission_bps: indra_core::types::primitives::DEFAULT_COMMISSION_BPS,
            pending_commission_bps: None, pending_commission_effective_epoch: None,
            min_delegation_spark: indra_core::types::primitives::DUST_LIMIT_SPARK,
            auto_delegate_to: None, network_addr: None, network_addr_last_updated_epoch: None,
            cold_hybrid_classical_pk: Some(cold_classical), cold_hybrid_pq_pk: Some(cold_pq),
            cold_key_version: validator.cold_key_version, cold_nonce: validator.cold_nonce,
        }).map_err(|error| error.to_string())?;
        state.utxos.insert(OutputV1 {
            value_spark: GENESIS_VALIDATOR_UTXO_SPARK,
            owner_pubkey: HybridPubKey { classical_pk: Bytes32::from(cold_classical), pq_pk: VariableBytes::from_slice(&cold_pq).map_err(|error| error.to_string())? },
            lock_height: 0,
        }, 0, 0, state.utxos.len() as u32).map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Build and finalize state from a manifest path.
pub fn build_finalized_genesis_state(genesis_path: Option<&str>) -> Result<ChainState, String> {
    let path = genesis_path.ok_or("canonical genesis construction requires a manifest")?;
    let manifest = parse_genesis_manifest(path)?;
    let mut state = ChainState::new_genesis(&manifest.genesis.chain_id);
    load_genesis_validators(&manifest, &mut state)?;
    state.finalize_genesis().map_err(|error| error.to_string())?;
    state.genesis_fingerprint = genesis_fingerprint(&state)?;
    Ok(state)
}

/// Load optional bootstrap peer hints from a manifest.
pub fn load_genesis_seed_peers(genesis_path: &str) -> Result<Vec<String>, String> {
    Ok(parse_genesis_manifest(genesis_path)?.seeds.into_iter().map(|seed| seed.addr).collect())
}

#[cfg(any(test, feature = "test-support"))]
/// Build a deterministic four-validator manifest for in-process tests.
pub fn test_genesis_toml(
    chain_id: &str,
    entries: &[([u8; 32], [u8; 32], [u8; 32])],
) -> String {
    test_genesis_toml_with_stakes(chain_id, entries, &vec![GENESIS_VALIDATOR_UTXO_SPARK; entries.len()])
}

#[cfg(any(test, feature = "test-support"))]
/// Build a deterministic test manifest in which the first validator is the
/// dominant authority and the remaining validators carry the minimum stake.
pub fn test_genesis_toml_single_authority(
    chain_id: &str,
    entries: &[([u8; 32], [u8; 32], [u8; 32])],
) -> String {
    let mut stakes = vec![indra_core::types::primitives::DUST_LIMIT_SPARK; entries.len()];
    if let Some(first) = stakes.first_mut() {
        *first = GENESIS_VALIDATOR_UTXO_SPARK;
    }
    test_genesis_toml_with_stakes(chain_id, entries, &stakes)
}

#[cfg(any(test, feature = "test-support"))]
fn test_genesis_toml_with_stakes(
    chain_id: &str,
    entries: &[([u8; 32], [u8; 32], [u8; 32])],
    stakes: &[u64],
) -> String {
    let mut output = format!(
        "[genesis]\nchain_id = \"{chain_id}\"\ngenesis_timestamp = 1700000000\nactive_slot_coefficient_numerator = \"{}\"\n",
        MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
    );
    for (index, (classical_seed, pq_seed, vrf_seed)) in entries.iter().enumerate() {
        let validator_name = if index == 0 {
            "local-test-validator".to_string()
        } else {
            format!("test-validator-{index}")
        };
        let classical = ClassicalKeypair::from_seed(classical_seed);
        let pq = PqKeypair::from_seed(pq_seed).unwrap();
        let vrf = VrfKeypair::from_seed(vrf_seed);
        let mut cold_classical_seed = *classical_seed;
        cold_classical_seed[0] ^= 0xA5;
        let mut cold_pq_seed = *classical_seed;
        cold_pq_seed[0] ^= 0x5A;
        let cold = ColdHybridKeypair::from_independent_seeds(cold_classical_seed, cold_pq_seed)
            .unwrap();
        let validator_id = hybrid_identity_id(&classical.public_key().0, &pq.public_key().0).0;
        let challenge = StakingOp::vrf_possession_challenge(
            chain_id,
            &Bytes32::from(validator_id),
            &Bytes32::from(vrf.public_key()),
            0,
        )
        .unwrap();
        let (vrf_output, vrf_proof) = vrf_prove(&vrf, &challenge);
        let cold_public = cold.public_key();
        let cold = cold_public.as_complete_hybrid();
        output.push_str(&format!(
            "\n[[validators]]\nname = \"{}\"\nvalidator_id = \"{}\"\nstake = {}\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\nvrf_possession_output = \"{}\"\nvrf_possession_proof = \"{}\"\ncold_hybrid_classical_pk = \"{}\"\ncold_hybrid_pq_pk = \"{}\"\ncold_key_version = 1\ncold_nonce = 0\n",
            validator_name,
            hex::encode(validator_id),
            stakes[index],
            hex::encode(classical.public_key().0),
            hex::encode(pq.public_key().0),
            hex::encode(vrf.public_key()),
            hex::encode(vrf_output.0),
            hex::encode(vrf_proof.0),
            hex::encode(cold.classical.0),
            hex::encode(cold.pq.0),
        ));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::codec::Encode;
    use indra_core::types::primitives::{MAX_CHAIN_ID_BYTES, TRANSACTION_PROTOCOL_VERSION};
    use indra_core::types::transaction::{InputV1, TransactionV1};
    use indra_crypto::{ClassicalKeypair, ColdHybridKeypair, HybridKeypair, PqKeypair, VrfKeypair};

    fn four_validator_test_state(chain_id: &str) -> ChainState {
        let manifest = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            manifest.path(),
            test_genesis_toml(
                chain_id,
                &[
                    ([1; 32], [1; 32], [1; 32]),
                    ([2; 32], [2; 32], [2; 32]),
                    ([3; 32], [3; 32], [3; 32]),
                    ([4; 32], [4; 32], [4; 32]),
                ],
            ),
        )
        .unwrap();
        build_finalized_genesis_state(manifest.path().to_str()) .unwrap()
    }

    #[test]
    fn build_finalized_genesis_state_uses_manifest_chain_id() {
        let manifest = tempfile::NamedTempFile::new().unwrap();
        let chain_id = "chain-id-from-manifest";
        std::fs::write(
            manifest.path(),
            test_genesis_toml(
                chain_id,
                &[
                    ([1; 32], [1; 32], [1; 32]),
                    ([2; 32], [2; 32], [2; 32]),
                    ([3; 32], [3; 32], [3; 32]),
                    ([4; 32], [4; 32], [4; 32]),
                ],
            ),
        )
        .unwrap();

        let state = build_finalized_genesis_state(manifest.path().to_str()).unwrap();
        assert_eq!(state.chain_id, chain_id);
    }

    fn validators(chain: &str) -> Vec<GenesisValidator> {
        (0..4u8).map(|i| {
            let hot = HybridKeypair::new(ClassicalKeypair::from_seed(&[i + 1; 32]), PqKeypair::from_seed(&[i + 11; 32]).unwrap()).public_key();
            let cold_public = ColdHybridKeypair::from_independent_seeds([i + 21; 32], [i + 31; 32]).unwrap().public_key();
            let cold = cold_public.as_complete_hybrid();
            let id = HybridPubKey { classical_pk: Bytes32::from(hot.classical.0), pq_pk: VariableBytes::from_slice(&hot.pq.0).unwrap() }.identity_id();
            let vrf = VrfKeypair::from_seed(&[i + 41; 32]);
            let challenge = indra_core::types::staking::StakingOp::vrf_possession_challenge(chain, &id, &Bytes32::from(vrf.public_key()), 0).unwrap();
            let (output, proof) = indra_crypto::vrf_prove(&vrf, &challenge);
            GenesisValidator { name: format!("v{i}"), validator_id: hex::encode(id.0), hybrid_classical_pk: hex::encode(hot.classical.0), hybrid_pq_pk: hex::encode(hot.pq.0), vrf_pk: hex::encode(vrf.public_key()), vrf_possession_output: hex::encode(output.0), vrf_possession_proof: hex::encode(proof.0), cold_hybrid_classical_pk: hex::encode(cold.classical.0), cold_hybrid_pq_pk: hex::encode(cold.pq.0), cold_key_version: 1, cold_nonce: 0, stake: 1_000_000_000 }
        }).collect()
    }

    fn settings(chain: &str) -> GenesisSettings { GenesisSettings { chain_id: chain.into(), genesis_timestamp: 1_700_000_000, active_slot_coefficient_numerator: indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR } }

    fn assert_validation_error(manifest: &GenesisManifest, expected: &str) {
        assert_eq!(validate_genesis_manifest(manifest).unwrap_err(), expected);
    }

    fn refresh_vrf_pop(chain: &str, validator: &mut GenesisValidator, seed: [u8; 32]) {
        let id_bytes: [u8; 32] = hex::decode(&validator.validator_id).unwrap().try_into().unwrap();
        let id = Bytes32::from(id_bytes);
        let vrf = VrfKeypair::from_seed(&seed);
        let challenge = StakingOp::vrf_possession_challenge(
            chain,
            &id,
            &Bytes32::from(vrf.public_key()),
            0,
        )
        .unwrap();
        let (output, proof) = vrf_prove(&vrf, &challenge);
        validator.vrf_possession_output = hex::encode(output.0);
        validator.vrf_possession_proof = hex::encode(proof.0);
    }

    #[test]
    fn seed_is_order_independent_and_changes_for_each_material_field() {
        let mut vs = validators("seed-test");
        let base = derive_genesis_election_seed(&settings("seed-test"), &vs).unwrap();
        assert_ne!(base, derive_genesis_election_seed(&settings("seed-test-other"), &vs).unwrap());
        assert_ne!(base, derive_genesis_election_seed(&settings("seed-test"), &vs[..3]).unwrap());
        vs.reverse();
        assert_eq!(base, derive_genesis_election_seed(&settings("seed-test"), &vs).unwrap());
        let mut changed = validators("seed-test");
        changed[0].stake += 1;
        assert_ne!(base, derive_genesis_election_seed(&settings("seed-test"), &changed).unwrap());
        changed = validators("seed-test"); changed[0].cold_nonce = 1;
        assert_ne!(base, derive_genesis_election_seed(&settings("seed-test"), &changed).unwrap());
        changed = validators("seed-test"); changed[0].validator_id.replace_range(0..2, "ff");
        assert_ne!(base, derive_genesis_election_seed(&settings("seed-test"), &changed).unwrap());
        changed = validators("seed-test"); changed[0].hybrid_classical_pk.replace_range(0..2, "ff");
        assert_ne!(base, derive_genesis_election_seed(&settings("seed-test"), &changed).unwrap());
        changed = validators("seed-test"); changed[0].hybrid_pq_pk.replace_range(0..2, "ff");
        assert_ne!(base, derive_genesis_election_seed(&settings("seed-test"), &changed).unwrap());
        changed = validators("seed-test"); changed[0].vrf_pk.replace_range(0..2, "ff");
        assert_ne!(base, derive_genesis_election_seed(&settings("seed-test"), &changed).unwrap());
        changed = validators("seed-test"); changed[0].cold_hybrid_classical_pk.replace_range(0..2, "ff");
        assert_ne!(base, derive_genesis_election_seed(&settings("seed-test"), &changed).unwrap());
        changed = validators("seed-test"); changed[0].cold_hybrid_pq_pk.replace_range(0..2, "ff");
        assert_ne!(base, derive_genesis_election_seed(&settings("seed-test"), &changed).unwrap());
        changed = validators("seed-test"); changed[0].cold_key_version = 2;
        assert_ne!(base, derive_genesis_election_seed(&settings("seed-test"), &changed).unwrap());
    }

    #[test]
    fn genesis_block_is_deterministic() {
        let first = four_validator_test_state("deterministic");
        let second = four_validator_test_state("deterministic");
        assert_eq!(build_genesis_block(&first).unwrap().encode_to_vec(), build_genesis_block(&second).unwrap().encode_to_vec());
        assert_eq!(genesis_block_hash(&first).unwrap(), genesis_block_hash(&second).unwrap());
    }

    #[test]
    fn genesis_block_has_zero_prev_hash() {
        assert_eq!(build_genesis_block(&four_validator_test_state("prev-hash")).unwrap().header.prev_hash, Bytes32::ZERO);
    }

    #[test]
    fn genesis_block_height_is_zero() {
        assert_eq!(build_genesis_block(&four_validator_test_state("height")).unwrap().header.height, 0);
    }

    #[test]
    fn genesis_state_height_is_zero() {
        assert_eq!(four_validator_test_state("state-height").height, 0);
    }

    #[test]
    fn genesis_utxo_uses_authoritative_public_value() {
        let entries = [([1; 32], [1; 32], [1; 32]), ([2; 32], [2; 32], [2; 32]), ([3; 32], [3; 32], [3; 32]), ([4; 32], [4; 32], [4; 32])];
        let path = std::env::temp_dir().join(format!("indra-utxo-value-{}.toml", std::process::id()));
        let manifest_text = test_genesis_toml("utxo-value", &entries);
        let manifest = parse_genesis_manifest_str(&manifest_text).unwrap();
        std::fs::write(&path, manifest_text).unwrap();
        let state = build_finalized_genesis_state(path.to_str()).unwrap();
        let rebuilt = build_finalized_genesis_state(path.to_str()).unwrap();
        assert_eq!(build_genesis_block(&state).unwrap().encode_to_vec(), build_genesis_block(&rebuilt).unwrap().encode_to_vec());
        assert_eq!(genesis_block_hash(&state).unwrap(), genesis_block_hash(&rebuilt).unwrap());
        let mut cold_owners = Vec::new();
        let mut hot_owners = Vec::new();
        for validator in manifest.validators {
            cold_owners.push(HybridPubKey {
                classical_pk: Bytes32::from(decode_hex_exact::<32>(&validator.cold_hybrid_classical_pk, "cold").unwrap()),
                pq_pk: VariableBytes::from_slice(&decode_hex_len(&validator.cold_hybrid_pq_pk, indra_crypto::PQ_PK_BYTES, "cold").unwrap()).unwrap(),
            });
            hot_owners.push(HybridPubKey {
                classical_pk: Bytes32::from(decode_hex_exact::<32>(&validator.hybrid_classical_pk, "hot").unwrap()),
                pq_pk: VariableBytes::from_slice(&decode_hex_len(&validator.hybrid_pq_pk, indra_crypto::PQ_PK_BYTES, "hot").unwrap()).unwrap(),
            });
        }
        let genesis_entries: Vec<_> = state.utxos.all_entries().collect();
        assert_eq!(genesis_entries.len(), cold_owners.len());
        let mut actual_owners: Vec<Vec<u8>> = genesis_entries.iter().map(|entry| entry.output.owner_pubkey.encode_to_vec()).collect();
        let mut expected_owners: Vec<Vec<u8>> = cold_owners.iter().map(Encode::encode_to_vec).collect();
        actual_owners.sort();
        expected_owners.sort();
        assert_eq!(actual_owners, expected_owners);
        for entry in genesis_entries {
            assert_eq!(entry.output.value_spark, GENESIS_VALIDATOR_UTXO_SPARK);
            assert!(!hot_owners.contains(&entry.output.owner_pubkey));
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn genesis_utxo_spend_requires_the_cold_hybrid_key() {
        let state = four_validator_test_state("cold-utxo-spend");
        let hot = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[1; 32]),
            PqKeypair::from_seed(&[1; 32]).unwrap(),
        );
        let mut cold_classical_seed = [1u8; 32];
        cold_classical_seed[0] ^= 0xA5;
        let mut cold_pq_seed = [1u8; 32];
        cold_pq_seed[0] ^= 0x5A;
        let cold = ColdHybridKeypair::from_independent_seeds(cold_classical_seed, cold_pq_seed).unwrap();
        let cold_public = cold.public_key();
        let cold_owner = HybridPubKey {
            classical_pk: Bytes32::from(cold_public.as_complete_hybrid().classical.0),
            pq_pk: VariableBytes::from_slice(&cold_public.as_complete_hybrid().pq.0).unwrap(),
        };
        let genesis_entry = state
            .utxos
            .all_entries()
            .find(|entry| entry.output.owner_pubkey == cold_owner)
            .unwrap();
        let utxo_id = genesis_entry.utxo_id;
        let value = genesis_entry.output.value_spark;
        let fee = state.base_fee * 10;
        let original_utxo_count = state.utxos.len();
        let mut cold_tx = TransactionV1 {
            version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
            signature_module_id: 1,
            inputs: vec![InputV1 { utxo_id }],
            outputs: vec![OutputV1 { value_spark: value - fee, owner_pubkey: cold_owner.clone(), lock_height: 0 }],
            fee_amount: fee,
            signature: HybridSignature { classical_sig: VariableBytes::from_slice(&[0; MAX_CLASSICAL_SIG_BYTES]).unwrap(), pq_sig: VariableBytes::from_slice(&[0; MAX_PQ_SIG_BYTES]).unwrap() },
        };
        let cold_signature = cold.sign(&cold_tx.signing_bytes(&state.chain_id).unwrap()).unwrap();
        cold_tx.signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&cold_signature.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&cold_signature.pq.0).unwrap(),
        };
        let mut accepted = state.clone();
        assert_eq!(indra_state::try_apply_transaction_candidate_with_dust(
            &mut accepted, &cold_tx, 1, 0, indra_core::types::primitives::DUST_LIMIT_SPARK,
        ), Ok(()));
        assert!(!accepted.utxos.contains(&utxo_id));
        assert!(accepted.utxos.all_entries().any(|entry| {
            entry.output.owner_pubkey == cold_owner && entry.output.value_spark == value - fee
        }));

        let mut hot_tx = cold_tx;
        let hot_signature = hot.sign(&hot_tx.signing_bytes(&state.chain_id).unwrap()).unwrap();
        hot_tx.signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&hot_signature.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&hot_signature.pq.0).unwrap(),
        };
        let mut rejected = state;
        let error = indra_state::try_apply_transaction_candidate_with_dust(
            &mut rejected, &hot_tx, 1, 0, indra_core::types::primitives::DUST_LIMIT_SPARK,
        ).unwrap_err();
        assert_eq!(error.to_string(), "transaction signature invalid: Ed25519 signature verification failed");
        assert!(rejected.utxos.contains(&utxo_id));
        assert_eq!(rejected.utxos.len(), original_utxo_count);
    }

    #[test]
    fn genesis_liquid_issuance_is_independent_of_manifest_validator_order() {
        use indra_core::codec::Encode;
        let entries = [([1; 32], [1; 32], [1; 32]), ([2; 32], [2; 32], [2; 32]), ([3; 32], [3; 32], [3; 32]), ([4; 32], [4; 32], [4; 32])];
        let mut reversed = entries;
        reversed.reverse();
        let base = std::env::temp_dir().join(format!("indra-order-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let first_path = base.join("first.toml");
        let second_path = base.join("second.toml");
        std::fs::write(&first_path, test_genesis_toml("order-test", &entries)).unwrap();
        std::fs::write(&second_path, test_genesis_toml("order-test", &reversed)).unwrap();
        let first = build_finalized_genesis_state(first_path.to_str()).unwrap();
        let second = build_finalized_genesis_state(second_path.to_str()).unwrap();
        assert_eq!(first.utxos.encode_to_vec(), second.utxos.encode_to_vec());
        assert_eq!(indra_state::compute_state_root(&first), indra_state::compute_state_root(&second));
        assert_eq!(genesis_fingerprint(&first).unwrap(), genesis_fingerprint(&second).unwrap());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn active_slot_coefficient_uses_strict_canonical_decimal_string() {
        let entries = [([1; 32], [1; 32], [1; 32]), ([2; 32], [2; 32], [2; 32]), ([3; 32], [3; 32], [3; 32]), ([4; 32], [4; 32], [4; 32])];
        let canonical = test_genesis_toml("f-test", &entries);
        let field = format!("active_slot_coefficient_numerator = \"{}\"", MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR);
        assert!(parse_genesis_manifest_str(&canonical).is_ok());
        for value in ["0", "01", "+1", "-1", "1_0"] {
            let error = parse_genesis_manifest_str(&canonical.replace(&field, &format!("active_slot_coefficient_numerator = \"{value}\""))).unwrap_err();
            if value == "0" {
                assert_eq!(error, format!("invalid proposer sortition: mainnet active_slot_coefficient_numerator must equal {MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR}"));
            } else {
                assert!(error.contains("active_slot_coefficient_numerator must be canonical ASCII decimal"), "unexpected error: {error}");
            }
        }
        let error = parse_genesis_manifest_str(&canonical.replace(&field, &format!("active_slot_coefficient_numerator = {}", MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR))).unwrap_err();
        assert!(error.contains("invalid genesis TOML"), "unexpected error: {error}");
    }

    #[test]
    fn canonical_genesis_rejects_missing_cold_fields_and_bad_chain_ids() {
        let mut manifest = GenesisManifest { genesis: settings("canonical"), validators: validators("canonical"), seeds: vec![] };
        assert!(validate_genesis_manifest(&manifest).is_ok());
        manifest.genesis.chain_id.clear();
        for (index, validator) in manifest.validators.iter_mut().enumerate() {
            refresh_vrf_pop("", validator, [index as u8 + 41; 32]);
        }
        assert_validation_error(&manifest, "genesis chain_id is outside the canonical length range");
        manifest.genesis.chain_id = "x".repeat(MAX_CHAIN_ID_BYTES + 1);
        for (index, validator) in manifest.validators.iter_mut().enumerate() {
            refresh_vrf_pop(&manifest.genesis.chain_id, validator, [index as u8 + 41; 32]);
        }
        assert_validation_error(&manifest, "genesis chain_id is outside the canonical length range");
        let rendered = test_genesis_toml("canonical", &[([1; 32], [1; 32], [1; 32]), ([2; 32], [2; 32], [2; 32]), ([3; 32], [3; 32], [3; 32]), ([4; 32], [4; 32], [4; 32])]);
        let error = parse_genesis_manifest_str(&rendered.replace("cold_hybrid_classical_pk =", "missing_cold =" )).unwrap_err();
        assert!(error.contains("unknown field `missing_cold`"), "unexpected error: {error}");
    }

    #[test]
    fn canonical_genesis_rejects_too_few_mismatched_and_duplicate_identities() {
        let baseline = validators("identity-test");
        let mut too_few = GenesisManifest { genesis: settings("identity-test"), validators: baseline[..3].to_vec(), seeds: vec![] };
        assert_validation_error(&too_few, "genesis requires at least 4 validators for BFT safety");
        too_few.validators = baseline.clone();
        too_few.validators[0].validator_id = hex::encode([0xFF; 32]);
        assert_validation_error(&too_few, "genesis validator v0 has an incorrect validator_id");
        let mut duplicate = baseline.clone();
        duplicate[1] = baseline[0].clone();
        assert_validation_error(&GenesisManifest { genesis: settings("identity-test"), validators: duplicate, seeds: vec![] }, "duplicate genesis validator or key in v0");
    }

    #[test]
    fn genesis_rejects_cross_role_key_reuse_and_oversized_fields() {
        let baseline = validators("cross-role");
        let mut cross_role = baseline.clone();
        cross_role[1].cold_hybrid_classical_pk = cross_role[0].hybrid_classical_pk.clone();
        assert_validation_error(&GenesisManifest {
            genesis: settings("cross-role"),
            validators: cross_role,
            seeds: vec![],
        }, "duplicate genesis validator or key in v1");

        let mut cross_role = baseline.clone();
        cross_role[1].cold_hybrid_pq_pk = cross_role[0].hybrid_pq_pk.clone();
        assert_validation_error(&GenesisManifest {
            genesis: settings("cross-role"),
            validators: cross_role,
            seeds: vec![],
        }, "duplicate genesis validator or key in v1");

        let mut cross_role = baseline.clone();
        cross_role[0].cold_hybrid_classical_pk = cross_role[0].hybrid_classical_pk.clone();
        assert_validation_error(&GenesisManifest {
            genesis: settings("cross-role"),
            validators: cross_role,
            seeds: vec![],
        }, "duplicate genesis validator or key in v0");

        let mut cross_role = baseline.clone();
        cross_role[0].cold_hybrid_pq_pk = cross_role[0].hybrid_pq_pk.clone();
        assert_validation_error(&GenesisManifest {
            genesis: settings("cross-role"),
            validators: cross_role,
            seeds: vec![],
        }, "duplicate genesis validator or key in v0");

        let mut oversized = baseline;
        oversized[0].hybrid_pq_pk.push_str("00");
        assert_validation_error(&GenesisManifest {
            genesis: settings("oversized"),
            validators: oversized,
            seeds: vec![],
        }, "genesis hybrid_pq_pk must be exactly 2592 bytes");
    }

    #[test]
    fn genesis_rejects_stake_below_dust_with_exact_error() {
        let mut base = validators("dust");
        base[0].stake = indra_core::types::primitives::DUST_LIMIT_SPARK - 1;
        assert_validation_error(
            &GenesisManifest { genesis: settings("dust"), validators: base, seeds: vec![] },
            "genesis validator v0 stake is below dust",
        );
    }

    #[test]
    fn genesis_rejects_invalid_cold_classical_and_pq_keys_with_exact_errors() {
        let baseline = validators("invalid-cold");
        let mut invalid_classical = baseline.clone();
        invalid_classical[0].cold_hybrid_classical_pk = "00".repeat(32);
        assert_validation_error(
            &GenesisManifest { genesis: settings("invalid-cold"), validators: invalid_classical, seeds: vec![] },
            "genesis validator v0 has an invalid cold classical key",
        );

        let mut invalid_pq = baseline;
        invalid_pq[0].cold_hybrid_pq_pk = "00".repeat(indra_crypto::PQ_PK_BYTES);
        assert_validation_error(
            &GenesisManifest { genesis: settings("invalid-cold"), validators: invalid_pq, seeds: vec![] },
            "genesis validator v0 has an invalid cold PQ key",
        );
    }

    #[test]
    fn empty_genesis_manifest_is_rejected() {
        assert_validation_error(&GenesisManifest {
            genesis: settings("empty"),
            validators: vec![],
            seeds: vec![],
        }, "genesis requires at least 4 validators for BFT safety");
    }

    #[test]
    fn finalized_genesis_preserves_manifest_cold_authority_fields() {
        let entries = [([1; 32], [1; 32], [1; 32]), ([2; 32], [2; 32], [2; 32]), ([3; 32], [3; 32], [3; 32]), ([4; 32], [4; 32], [4; 32])];
        let manifest = parse_genesis_manifest_str(&test_genesis_toml("cold-fields", &entries)).unwrap();
        let state = four_validator_test_state("cold-fields");
        for manifest_validator in manifest.validators {
            let id_bytes: [u8; 32] = hex::decode(manifest_validator.validator_id).unwrap().try_into().unwrap();
            let id = Bytes32::from(id_bytes);
            let state_validator = state.validators.get(&id).unwrap();
            let cold_classical: [u8; 32] = hex::decode(manifest_validator.cold_hybrid_classical_pk).unwrap().try_into().unwrap();
            assert_eq!(state_validator.cold_hybrid_classical_pk.unwrap(), cold_classical);
            assert_eq!(state_validator.cold_hybrid_pq_pk.unwrap().as_slice(), hex::decode(manifest_validator.cold_hybrid_pq_pk).unwrap().as_slice());
            assert_eq!(state_validator.cold_key_version, 1);
            assert_eq!(state_validator.cold_nonce, 0);
        }
    }

    #[test]
    fn finalized_genesis_sets_height_and_seed_from_manifest() {
        let entries = [([1; 32], [1; 32], [1; 32]), ([2; 32], [2; 32], [2; 32]), ([3; 32], [3; 32], [3; 32]), ([4; 32], [4; 32], [4; 32])];
        let manifest = parse_genesis_manifest_str(&test_genesis_toml("seed-state", &entries)).unwrap();
        let state = four_validator_test_state("seed-state");
        let expected = derive_genesis_election_seed(&manifest.genesis, &manifest.validators).unwrap();
        assert_eq!(state.election_seed_height, 1);
        assert_eq!(state.election_seed, expected);
    }

    #[test]
    fn genesis_rejects_vrf_squatting_cold_history_and_noncanonical_hex() {
        let base = validators("validation-test");
        let mut squatted = base.clone();
        squatted[0].vrf_pk = squatted[1].vrf_pk.clone();
        assert_validation_error(&GenesisManifest { genesis: settings("validation-test"), validators: squatted, seeds: vec![] }, "genesis validator v0 has an invalid VRF PoP");
        for (version, nonce) in [(2, 0), (1, 1)] {
            let mut changed = base.clone();
            changed[0].cold_key_version = version;
            changed[0].cold_nonce = nonce;
            assert_validation_error(&GenesisManifest { genesis: settings("validation-test"), validators: changed, seeds: vec![] }, "genesis validator v0 has invalid cold-key version or nonce");
        }
        let mut uppercase = base;
        uppercase[0].validator_id = uppercase[0].validator_id.to_uppercase();
        assert_validation_error(&GenesisManifest { genesis: settings("validation-test"), validators: uppercase, seeds: vec![] }, "genesis validator_id must be canonical lowercase hexadecimal");
    }

    #[test]
    fn reject_noncanonical_hex() {
        assert_eq!(decode_hex_exact::<32>("AA", "test").unwrap_err(), "genesis test must be canonical lowercase hexadecimal");
        assert!(decode_hex_exact::<32>(&"aa".repeat(32), "test").is_ok());
    }

    #[test]
    fn fingerprint_changes_with_every_genesis_identity_domain() {
        let mut state = four_validator_test_state("fingerprint");
        let original = genesis_fingerprint(&state).unwrap();
        state.chain_id.push_str("-other");
        assert_ne!(original, genesis_fingerprint(&state).unwrap());
        let mut state = four_validator_test_state("fingerprint");
        state.election_seed.0[0] ^= 1;
        assert_ne!(original, genesis_fingerprint(&state).unwrap());
        let mut state = four_validator_test_state("fingerprint");
        state.monetary_ledger.genesis_issued_spark += 1;
        assert_ne!(original, genesis_fingerprint(&state).unwrap());
        let mut state = four_validator_test_state("fingerprint");
        let validator_id = state.validators.all_validators().next().unwrap().validator_id;
        state.validators.get_mut(&validator_id).unwrap().stake_spark += 1;
        state.rebuild_state_commitment_v2(state.height);
        assert_ne!(original, genesis_fingerprint(&state).unwrap());
        let mut state = four_validator_test_state("fingerprint");
        state.genesis_timestamp += 1;
        assert_ne!(original, genesis_fingerprint(&state).unwrap());
    }

    #[test]
    fn invalid_hot_classical_key_is_rejected() {
        let mut base = validators("hot-classical");
        base[0].hybrid_classical_pk = "00".repeat(32);
        let pq: [u8; indra_crypto::PQ_PK_BYTES] = hex::decode(&base[0].hybrid_pq_pk).unwrap().try_into().unwrap();
        base[0].validator_id = hex::encode(hybrid_identity_id(&[0; 32], &pq).0);
        refresh_vrf_pop("hot-classical", &mut base[0], [41; 32]);
        assert_validation_error(&GenesisManifest { genesis: settings("hot-classical"), validators: base, seeds: vec![] }, "genesis validator v0 has an invalid hot classical key");
    }

    #[test]
    fn invalid_hot_pq_key_is_rejected() {
        let mut base = validators("hot-pq");
        base[0].hybrid_pq_pk = "00".repeat(indra_crypto::PQ_PK_BYTES);
        let classical: [u8; 32] = hex::decode(&base[0].hybrid_classical_pk).unwrap().try_into().unwrap();
        base[0].validator_id = hex::encode(hybrid_identity_id(&classical, &[0; indra_crypto::PQ_PK_BYTES]).0);
        refresh_vrf_pop("hot-pq", &mut base[0], [41; 32]);
        assert_validation_error(&GenesisManifest { genesis: settings("hot-pq"), validators: base, seeds: vec![] }, "genesis validator v0 has an invalid hot PQ key");
    }

    #[test]
    fn genesis_timestamp_changes_fingerprint_and_block_hash_but_not_seed() {
        let entries = [([1; 32], [1; 32], [1; 32]), ([2; 32], [2; 32], [2; 32]), ([3; 32], [3; 32], [3; 32]), ([4; 32], [4; 32], [4; 32])];
        let root = std::env::temp_dir().join(format!("indra-timestamp-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let first_path = root.join("first.toml");
        let second_path = root.join("second.toml");
        let first_manifest = test_genesis_toml("timestamp-test", &entries);
        let second_manifest = first_manifest.replace("genesis_timestamp = 1700000000", "genesis_timestamp = 1700000001");
        std::fs::write(&first_path, first_manifest).unwrap();
        std::fs::write(&second_path, second_manifest).unwrap();
        let first = build_finalized_genesis_state(first_path.to_str()).unwrap();
        let second = build_finalized_genesis_state(second_path.to_str()).unwrap();
        assert_eq!(first.election_seed, second.election_seed);
        assert_ne!(first.genesis_fingerprint, second.genesis_fingerprint);
        assert_ne!(genesis_block_hash(&first).unwrap(), genesis_block_hash(&second).unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn four_validators_are_required_and_bad_f_is_rejected() {
        let mut vs = validators("validate-test");
        let manifest = GenesisManifest { genesis: settings("validate-test"), validators: vs[..3].to_vec(), seeds: vec![] };
        assert_validation_error(&manifest, "genesis requires at least 4 validators for BFT safety");
        vs[0].stake += 1;
        let mut bad = settings("validate-test"); bad.active_slot_coefficient_numerator = 1;
        assert_eq!(derive_genesis_election_seed(&bad, &vs).unwrap_err(), format!("invalid proposer sortition: mainnet active_slot_coefficient_numerator must equal {}", MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR));
    }

    #[test]
    fn genesis_rejects_total_supply_cap_plus_one() {
        let mut base = validators("stake-cap");
        let available_for_stake = LIFETIME_SUPPLY_CAP_SPARK - 4 * GENESIS_VALIDATOR_UTXO_SPARK;
        base[0].stake = available_for_stake - 3 * base[1].stake + 1;
        assert_validation_error(&GenesisManifest { genesis: settings("stake-cap"), validators: base, seeds: vec![] }, format!("genesis total supply exceeds lifetime supply cap {LIFETIME_SUPPLY_CAP_SPARK}").as_str());
    }

    #[test]
    fn genesis_rejects_stake_sum_above_lifetime_cap() {
        let mut base = validators("stake-sum");
        base[0].stake = LIFETIME_SUPPLY_CAP_SPARK / 2 + 1;
        base[1].stake = LIFETIME_SUPPLY_CAP_SPARK / 2 + 1;
        assert_validation_error(&GenesisManifest { genesis: settings("stake-sum"), validators: base, seeds: vec![] }, format!("genesis total supply exceeds lifetime supply cap {LIFETIME_SUPPLY_CAP_SPARK}").as_str());
    }

    #[test]
    fn genesis_rejects_stake_sum_overflow() {
        let mut base = validators("stake-overflow");
        base[0].stake = u64::MAX;
        base[1].stake = u64::MAX;
        assert_validation_error(&GenesisManifest { genesis: settings("stake-overflow"), validators: base, seeds: vec![] }, "genesis validator stake total overflows u64");
    }

    #[test]
    fn genesis_rejects_total_supply_overflow() {
        let mut base = validators("supply-overflow");
        base[0].stake = u64::MAX - 4 * GENESIS_VALIDATOR_UTXO_SPARK + 1;
        assert_validation_error(
            &GenesisManifest { genesis: settings("supply-overflow"), validators: base, seeds: vec![] },
            "genesis total supply overflows u64",
        );
    }

    #[test]
    fn genesis_accepts_total_supply_exactly_at_lifetime_cap() {
        let mut base = validators("stake-exact");
        let available_for_stake = LIFETIME_SUPPLY_CAP_SPARK - 4 * GENESIS_VALIDATOR_UTXO_SPARK;
        base[0].stake = available_for_stake - 3 * base[1].stake;
        assert!(validate_genesis_manifest(&GenesisManifest { genesis: settings("stake-exact"), validators: base, seeds: vec![] }).is_ok());
    }

    #[test]
    fn genesis_validator_name_rules_are_canonical() {
        let mut empty = validators("name-empty");
        empty[0].name.clear();
        assert_validation_error(&GenesisManifest { genesis: settings("name-empty"), validators: empty, seeds: vec![] }, "genesis validator name must not be empty");
        let mut max = validators("name-max");
        max[0].name = "a".repeat(MAX_GENESIS_VALIDATOR_NAME_BYTES);
        assert!(validate_genesis_manifest(&GenesisManifest { genesis: settings("name-max"), validators: max, seeds: vec![] }).is_ok());
        let mut too_long = validators("name-too-long");
        too_long[0].name = "a".repeat(MAX_GENESIS_VALIDATOR_NAME_BYTES + 1);
        assert_validation_error(&GenesisManifest { genesis: settings("name-too-long"), validators: too_long, seeds: vec![] }, "genesis validator name exceeds 64 bytes");
        let mut control = validators("name-control");
        control[0].name.push('\n');
        assert_validation_error(&GenesisManifest { genesis: settings("name-control"), validators: control, seeds: vec![] }, "genesis validator name contains unsupported characters");
        let mut non_ascii = validators("name-nonascii");
        non_ascii[0].name.push('é');
        assert_validation_error(&GenesisManifest { genesis: settings("name-nonascii"), validators: non_ascii, seeds: vec![] }, "genesis validator name contains unsupported characters");
    }

    #[test]
    fn golden_vector_values() {
        let entries = [([1; 32], [1; 32], [1; 32]), ([2; 32], [2; 32], [2; 32]), ([3; 32], [3; 32], [3; 32]), ([4; 32], [4; 32], [4; 32])];
        let manifest = test_genesis_toml("golden-chain", &entries);
        let path = std::env::temp_dir().join(format!("indra-golden-{}.toml", std::process::id()));
        std::fs::write(&path, manifest).unwrap();
        let state = build_finalized_genesis_state(path.to_str()).unwrap();
        assert_eq!(hex::encode(state.election_seed.0), "f449538f3ffe86ac8fe27a2bea99714c8823140efdceda5144ac3f0143d58db0b3649bb84ddef0f63e2ebd3de8ecb1f09b46fc2d0b18fcf1feb3242ba477c039");
        let fingerprint: [u8; 32] = hex::decode("dc14cfe8a7d4b789554e442ad1bcd3cd4c26e782b6c5506b5e3e96b34e3f42dc").unwrap().try_into().unwrap();
        let block_hash: [u8; 32] = hex::decode("13cf73518f8185c762b72e125043259e8c52465a9acc933be69049ade9ab5223").unwrap().try_into().unwrap();
        assert_eq!(state.genesis_fingerprint, Bytes32::from(fingerprint));
        assert_eq!(genesis_block_hash(&state).unwrap(), Bytes32::from(block_hash));
        std::fs::remove_file(path).unwrap();
    }
}
