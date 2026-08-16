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
    block::{BlockHeaderVNext, BlockProposalVNext, BlockVNext, SortitionClaimV1, VrfSuiteV1},
    crypto::{HybridPubKey, HybridSignature},
    primitives::{
        Bytes32, Bytes64, ProtocolVersion, VariableBytes, INITIAL_BASE_FEE_SPARK_PER_KB,
        LIFETIME_SUPPLY_CAP_SPARK, MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES, MAX_QC_SIZE_BYTES,
        MAX_STANDARD_VRF_OUTPUT_BYTES, MAX_STANDARD_VRF_PROOF_BYTES,
    },
    transaction::OutputV1,
};
use indra_crypto::sha256;
use indra_state::ChainState;
use serde::{de::Error as _, Deserialize, Deserializer};
use sha2::{Digest, Sha512};

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
    /// Immutable numerator `F` in `f = F / 2^64`.
    #[serde(deserialize_with = "deserialize_canonical_decimal_u64")]
    pub active_slot_coefficient_numerator: u64,
    /// Precommitted Bitcoin proof-of-work entropy source.
    pub bitcoin_pow_entropy_source: BitcoinPowEntropySourceV1,
    /// Exact consensus-serialized 80-byte source header, lowercase hex.
    pub bitcoin_pow_entropy_header: String,
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
            "active_slot_coefficient_numerator must be canonical ASCII decimal without sign, whitespace, or leading zeroes",
        ));
    }
    encoded.parse::<u64>().map_err(D::Error::custom)
}

/// Canonical protocol-v2 external entropy descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinPowEntropySourceV1 {
    /// Descriptor scheme; protocol v2 requires 1.
    pub scheme: u8,
    /// Raw, non-display-reversed source-network genesis digest.
    pub network_genesis_hash: String,
    /// Precommitted future source-chain height.
    pub announced_height: u64,
    /// Header codec; 1 means the Bitcoin 80-byte header.
    pub header_codec: u8,
    /// Extraction algorithm; 1 means double SHA-256.
    pub extraction_algorithm: u8,
    /// Required canonical-chain confirmations, at least 100.
    pub minimum_confirmations: u32,
    /// Reorganization policy; 1 restarts at the same height.
    pub reorg_policy: u8,
}

impl BitcoinPowEntropySourceV1 {
    fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        if self.scheme != 1
            || self.header_codec != 1
            || self.extraction_algorithm != 1
            || self.reorg_policy != 1
        {
            return Err("unsupported Bitcoin entropy descriptor enum value".into());
        }
        if self.minimum_confirmations < 100 {
            return Err("Bitcoin entropy source requires at least 100 confirmations".into());
        }
        let genesis = decode_hex_exact::<32>(&self.network_genesis_hash, "network_genesis_hash")?;
        let mut out = Vec::with_capacity(48);
        out.push(self.scheme);
        out.extend_from_slice(&genesis);
        out.extend_from_slice(&self.announced_height.to_le_bytes());
        out.push(self.header_codec);
        out.push(self.extraction_algorithm);
        out.extend_from_slice(&self.minimum_confirmations.to_le_bytes());
        out.push(self.reorg_policy);
        Ok(out)
    }
}

/// Commit to the complete canonical public entropy record used at genesis.
pub fn genesis_entropy_record_hash(settings: &GenesisSettings) -> Result<Bytes32, String> {
    let descriptor = settings.bitcoin_pow_entropy_source.canonical_bytes()?;
    let header = decode_hex_exact::<80>(
        &settings.bitcoin_pow_entropy_header,
        "bitcoin_pow_entropy_header",
    )?;
    let mut preimage = b"INDRA-GENESIS-ENTROPY-RECORD-v1".to_vec();
    preimage.extend_from_slice(&descriptor);
    preimage.extend_from_slice(&header);
    Ok(Bytes32::from(sha256(&preimage)))
}

/// Deterministically derive the signed genesis election seed.
pub fn derive_genesis_election_seed(settings: &GenesisSettings) -> Result<Bytes64, String> {
    indra_core::sortition::validate_f(settings.active_slot_coefficient_numerator)
        .map_err(|e| e.to_string())?;
    let descriptor = settings.bitcoin_pow_entropy_source.canonical_bytes()?;
    let header = decode_hex_exact::<80>(
        &settings.bitcoin_pow_entropy_header,
        "bitcoin_pow_entropy_header",
    )?;
    let mut source_material = b"INDRA-EXTERNAL-ENTROPY-SOURCE-ID-v1".to_vec();
    source_material.extend_from_slice(&descriptor);
    let source_id = sha256(&source_material);
    let external = sha256(&sha256(&header));
    let mut seed_material = b"INDRA-GENESIS-ELECTION-SEED-v1".to_vec();
    seed_material.extend_from_slice(settings.chain_id.as_bytes());
    seed_material.extend_from_slice(&source_id);
    seed_material.extend_from_slice(&external);
    let digest = Sha512::digest(&seed_material);
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    Ok(Bytes64(out))
}

/// One initial validator in the canonical genesis manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisValidator {
    /// Human-readable operator label.
    pub name: String,
    /// Domain-separated SHA-256 identity derived from the complete hybrid hot key.
    pub validator_id: String,
    /// Ed25519 hot public key.
    pub hybrid_classical_pk: String,
    /// ML-DSA-87 hot public key.
    pub hybrid_pq_pk: String,
    /// VRF public key.
    pub vrf_pk: String,
    /// RFC 9381 output proving possession of the genesis VRF secret key.
    pub vrf_possession_output: String,
    /// RFC 9381 proof over the genesis registration transcript.
    pub vrf_possession_proof: String,
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
    derive_genesis_election_seed(&manifest.genesis)?;
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
        let vrf_output =
            decode_hex_exact::<64>(&validator.vrf_possession_output, "vrf_possession_output")?;
        let vrf_proof =
            decode_hex_exact::<80>(&validator.vrf_possession_proof, "vrf_possession_proof")?;
        let cold_classical_pk = decode_hex_exact::<32>(
            &validator.cold_hybrid_classical_pk,
            "cold_hybrid_classical_pk",
        )?;
        let cold_pq_pk = decode_hex_len(
            &validator.cold_hybrid_pq_pk,
            indra_crypto::PQ_PK_BYTES,
            "cold_hybrid_pq_pk",
        )?;
        let identity_key = HybridPubKey {
            classical_pk: Bytes32::from(classical),
            pq_pk: VariableBytes::from_slice(&pq)
                .map_err(|_| format!("genesis validator {} PQ key too large", validator.name))?,
        };
        if validator_id != identity_key.identity_id().0 {
            return Err(format!(
                "genesis validator {} validator_id does not match its complete hybrid hot key",
                validator.name
            ));
        }
        let challenge = indra_core::types::staking::StakingOp::vrf_possession_challenge(
            &manifest.genesis.chain_id,
            &Bytes32::from(validator_id),
            &Bytes32::from(vrf_pk),
            0,
        )
        .map_err(|error| error.to_string())?;
        indra_crypto::vrf_verify(
            &vrf_pk,
            &challenge,
            &indra_crypto::VrfOutput(vrf_output),
            &indra_crypto::VrfProof(vrf_proof.to_vec()),
        )
        .map_err(|_| {
            format!(
                "genesis validator {} VRF possession proof is invalid",
                validator.name
            )
        })?;
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
            (pq_keys.insert(cold_pq_pk.clone()), "PQ hot/cold key"),
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
        indra_crypto::validate_classical_public_key(&indra_crypto::ClassicalPublicKey(
            cold_classical_pk,
        ))
        .map_err(|_| {
            format!(
                "genesis validator {} has invalid cold classical key",
                validator.name
            )
        })?;
        let cold_pq_array: [u8; indra_crypto::PQ_PK_BYTES] =
            cold_pq_pk.as_slice().try_into().map_err(|_| {
                format!(
                    "genesis validator {} has invalid cold PQ key length",
                    validator.name
                )
            })?;
        indra_crypto::validate_pq_public_key(&indra_crypto::PqPublicKey(cold_pq_array)).map_err(
            |_| {
                format!(
                    "genesis validator {} has invalid cold PQ key",
                    validator.name
                )
            },
        )?;
        if validator.cold_key_version != 1 {
            return Err(format!(
                "genesis validator {} cold_key_version must equal 1",
                validator.name
            ));
        }
        if validator.cold_nonce != 0 {
            return Err(format!(
                "genesis validator {} cold_nonce must equal 0",
                validator.name
            ));
        }
    }
    Ok(())
}

fn decode_hex_exact<const N: usize>(value: &str, field: &str) -> Result<[u8; N], String> {
    reject_noncanonical_hex(value, field)?;
    let bytes = hex::decode(value).map_err(|_| format!("invalid hex in genesis {field}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("genesis {field} must be exactly {N} bytes"))
}

fn decode_hex_len(value: &str, expected: usize, field: &str) -> Result<Vec<u8>, String> {
    reject_noncanonical_hex(value, field)?;
    let bytes = hex::decode(value).map_err(|_| format!("invalid hex in genesis {field}"))?;
    if bytes.len() != expected {
        return Err(format!("genesis {field} must be exactly {expected} bytes"));
    }
    Ok(bytes)
}

fn reject_noncanonical_hex(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "genesis {field} must be canonical lowercase hexadecimal"
        ));
    }
    Ok(())
}

/// Build the genesis block.
///
/// The genesis block hash is SHA-256(encode(genesis_header)).
pub fn genesis_fingerprint(state: &ChainState) -> Result<Bytes32, String> {
    use indra_core::codec::Encode;
    let roots = indra_state::compute_state_roots(state);
    let snapshot = state
        .snapshot_for_consensus_height(1)
        .map_err(|error| error.to_string())?;
    let mut preimage = b"INDRA-GENESIS-FINGERPRINT-v1".to_vec();
    let chain_id = state.chain_id.as_bytes();
    let chain_len = u16::try_from(chain_id.len()).map_err(|_| "genesis chain id too long")?;
    preimage.extend_from_slice(&chain_len.to_be_bytes());
    preimage.extend_from_slice(chain_id);
    preimage.extend_from_slice(&roots.state_root.0);
    preimage.extend_from_slice(&snapshot.snapshot_root.0);
    state.monetary_ledger.encode(&mut preimage);
    preimage.extend_from_slice(&state.election_seed.0);
    preimage.extend_from_slice(&state.genesis_entropy_record_hash.0);
    Ok(Bytes32::from(sha256(&preimage)))
}

/// Build the unique height-zero block bound to finalized canonical genesis state.
pub fn build_genesis_block(state: &ChainState) -> Result<BlockVNext, String> {
    let roots = indra_state::compute_state_roots(state);
    let fingerprint = genesis_fingerprint(state)?;
    Ok(BlockVNext {
        header: BlockHeaderVNext {
            protocol_version: ProtocolVersion::CURRENT,
            height: 0,
            prev_hash: Bytes32::ZERO,
            timestamp: 1_700_000_000, // 2023-11-14 — fixed genesis timestamp
            state_root: roots.state_root,
            validator_set_root: roots.validator_set_root,
            mempool_set_root: Bytes32::ZERO,
            value_hash: fingerprint,
            base_fee: INITIAL_BASE_FEE_SPARK_PER_KB,
            proposer_round: 0,
            polc_round: indra_core::types::block::NO_POLC_ROUND,
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

/// Canonical storage envelope for the unsigned genesis exception.
pub fn build_genesis_proposal(state: &ChainState) -> Result<BlockProposalVNext, String> {
    Ok(BlockProposalVNext {
        block: build_genesis_block(state)?,
        proposer_authorization: HybridSignature {
            classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::default(),
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::default(),
        },
    })
}

/// Compute the genesis block hash.
pub fn genesis_block_hash(state: &ChainState) -> Result<Bytes32, String> {
    use indra_core::codec::Encode;
    let block = build_genesis_block(state)?;
    Ok(Bytes32::from(sha256(&block.header.encode_to_vec())))
}

/// Build the canonical local genesis state.
///
/// The returned value is fully finalized: all genesis-native authority
/// snapshots and commitments are present.
pub fn build_genesis_state() -> ChainState {
    use indra_crypto::{ClassicalKeypair, ColdHybridKeypair, HybridKeypair, PqKeypair, VrfKeypair};
    use indra_state::{ValidatorEntry, ValidatorStatus};

    let mut state = ChainState::new_genesis();
    state.active_slot_coefficient_numerator = 1;
    state.election_seed = Bytes64([0xA5; 64]);
    let hot = HybridKeypair::new(
        ClassicalKeypair::from_seed(&[0xD1; 32]),
        PqKeypair::from_seed(&[0xD2; 32]).unwrap(),
    );
    let hot_public = hot.public_key();
    let cold = ColdHybridKeypair::from_independent_seeds([0xD3; 32], [0xD4; 32]).unwrap();
    let cold_public = cold.public_key();
    let cold_public = cold_public.as_complete_hybrid();
    let vrf_pk = VrfKeypair::from_seed(&[0xD5; 32]).public_key();
    let validator_id = HybridPubKey {
        classical_pk: Bytes32::from(hot_public.classical.0),
        pq_pk: VariableBytes::from_slice(&hot_public.pq.0)
            .expect("fixed-size ML-DSA-87 public key fits protocol maximum"),
    }
    .identity_id();
    state
        .validators
        .upsert(ValidatorEntry {
            validator_id,
            name: "canonical-local-genesis".into(),
            hybrid_classical_pk: Some(hot_public.classical.0),
            hybrid_pq_pk: Some(hot_public.pq.0.to_vec()),
            vrf_pk: Some(vrf_pk),
            vrf_key_activation_epoch: 0,
            pending_vrf_pk: None,
            pending_vrf_activation_epoch: None,
            stake_spark: 1_000_000,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            slashed_offense_id: None,
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
    assert_eq!(
        state.total_supply,
        state.monetary_aggregates.total_claims_spark().unwrap()
    );
    assert!(state.total_supply <= LIFETIME_SUPPLY_CAP_SPARK);
    assert_eq!(state.fee_reward_pool, 0);
    state
}

/// Rebuild all genesis-native authority structures after a test has assembled
/// or amended its height-zero validator set.
#[cfg(test)]
pub(crate) fn finalize_test_genesis(state: &mut ChainState) {
    assert_eq!(state.height, 0, "test genesis must remain at height zero");
    state.active_slot_coefficient_numerator = 1u64 << 63;
    state.consensus_snapshots.clear();
    state.reward_economic_snapshot = None;
    state.slash_membership_roots.clear();
    state.finalize_genesis().unwrap();
}

/// Construct a complete one-validator genesis for tests that do not care about
/// a particular authority identity but still exercise canonical state logic.
#[cfg(test)]
pub(crate) fn canonical_test_genesis() -> ChainState {
    let mut state = build_genesis_state();
    // Consensus tests need a practical chance of electing their sole
    // validator. The release manifest deliberately leaves F uncalibrated at
    // its conservative minimum; test fixtures exercise both protocol
    // endpoints explicitly and use the admitted maximum for liveness tests.
    state.active_slot_coefficient_numerator = 1u64 << 63;
    state.consensus_snapshots.clear();
    state.reward_economic_snapshot = None;
    state.slash_membership_roots.clear();
    state.finalize_genesis().unwrap();
    state
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
    state.active_slot_coefficient_numerator = manifest.genesis.active_slot_coefficient_numerator;
    state.election_seed = derive_genesis_election_seed(&manifest.genesis)?;
    state.genesis_entropy_record_hash = genesis_entropy_record_hash(&manifest.genesis)?;
    state.election_seed_height = 1;
    let mut validators = manifest.validators;
    validators.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));

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
            vrf_key_activation_epoch: 0,
            pending_vrf_pk: None,
            pending_vrf_activation_epoch: None,
            stake_spark: stake,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            slashed_offense_id: None,
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
            let output = OutputV1 {
                value_spark: GENESIS_VALIDATOR_UTXO_SPARK,
                owner_pubkey: HybridPubKey {
                    classical_pk: Bytes32::from(classical_pk),
                    pq_pk: VariableBytes::from_slice(&hybrid_pq_pk)
                        .map_err(|error| format!("invalid genesis PQ public key: {error}"))?,
                },
                lock_height: 0,
            };
            let output_index = u32::try_from(state.utxos.len())
                .map_err(|_| "too many genesis UTXOs for canonical output index".to_string())?;
            state
                .utxos
                .insert(output, 0, 0, output_index)
                .map_err(|error| format!("cannot create genesis validator UTXO: {error}"))?;
            eprintln!(
                "[genesis] created UTXO {} Spark for {}",
                GENESIS_VALIDATOR_UTXO_SPARK, name
            );
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
    state.genesis_fingerprint = genesis_fingerprint(&state)?;
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
                let validator_id = indra_core::types::crypto::hybrid_identity_id(
                    &hot_public.classical.0,
                    &hot_public.pq.0,
                );
                let vrf_keypair = indra_crypto::VrfKeypair::from_seed(&[index + 41; 32]);
                let vrf_pk = Bytes32::from(vrf_keypair.public_key());
                let challenge = indra_core::types::staking::StakingOp::vrf_possession_challenge(
                    "indra-testnet-new",
                    &validator_id,
                    &vrf_pk,
                    0,
                )
                .unwrap();
                let (vrf_output, vrf_proof) = indra_crypto::vrf_prove(&vrf_keypair, &challenge);
                GenesisValidator {
                    name: format!("validator-{index}"),
                    validator_id: hex::encode(validator_id.0),
                    hybrid_classical_pk: hex::encode(hot_public.classical.0),
                    hybrid_pq_pk: hex::encode(hot_public.pq.0),
                    vrf_pk: hex::encode(vrf_pk.0),
                    vrf_possession_output: hex::encode(vrf_output.0),
                    vrf_possession_proof: hex::encode(vrf_proof.0),
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
                active_slot_coefficient_numerator: 1,
                bitcoin_pow_entropy_source: BitcoinPowEntropySourceV1 {
                    scheme: 1,
                    network_genesis_hash: hex::encode([0x11; 32]),
                    announced_height: 1,
                    header_codec: 1,
                    extraction_algorithm: 1,
                    minimum_confirmations: 100,
                    reorg_policy: 1,
                },
                bitcoin_pow_entropy_header: hex::encode([0x22; 80]),
            },
            validators,
            seeds: vec![],
        }
    }

    fn render_manifest(manifest: &GenesisManifest, omit_cold: bool) -> String {
        let s = &manifest.genesis.bitcoin_pow_entropy_source;
        let mut rendered = format!("[genesis]\nchain_id = \"{}\"\nactive_slot_coefficient_numerator = \"{}\"\nbitcoin_pow_entropy_header = \"{}\"\n\n[genesis.bitcoin_pow_entropy_source]\nscheme = {}\nnetwork_genesis_hash = \"{}\"\nannounced_height = {}\nheader_codec = {}\nextraction_algorithm = {}\nminimum_confirmations = {}\nreorg_policy = {}\n", manifest.genesis.chain_id,manifest.genesis.active_slot_coefficient_numerator,manifest.genesis.bitcoin_pow_entropy_header,s.scheme,s.network_genesis_hash,s.announced_height,s.header_codec,s.extraction_algorithm,s.minimum_confirmations,s.reorg_policy);
        for validator in &manifest.validators {
            rendered.push_str(&format!("\n[[validators]]\nname = \"{}\"\nvalidator_id = \"{}\"\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\nvrf_possession_output = \"{}\"\nvrf_possession_proof = \"{}\"\n", validator.name, validator.validator_id, validator.hybrid_classical_pk, validator.hybrid_pq_pk, validator.vrf_pk, validator.vrf_possession_output, validator.vrf_possession_proof));
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
    fn active_slot_coefficient_uses_strict_canonical_decimal_string() {
        let manifest = valid_manifest();
        let canonical = render_manifest(&manifest, false);
        for invalid in ["0", "01", "+1", "-1", " 1", "1 ", "1_0", "١"] {
            let malformed = canonical.replace(
                "active_slot_coefficient_numerator = \"1\"",
                &format!("active_slot_coefficient_numerator = \"{invalid}\""),
            );
            assert!(
                parse_genesis_manifest_str(&malformed).is_err(),
                "accepted {invalid:?}"
            );
        }
        let numeric = canonical.replace(
            "active_slot_coefficient_numerator = \"1\"",
            "active_slot_coefficient_numerator = 1",
        );
        assert!(parse_genesis_manifest_str(&numeric).is_err());

        let upper = canonical.replace(
            "active_slot_coefficient_numerator = \"1\"",
            "active_slot_coefficient_numerator = \"9223372036854775808\"",
        );
        assert_eq!(
            parse_genesis_manifest_str(&upper)
                .unwrap()
                .genesis
                .active_slot_coefficient_numerator,
            1u64 << 63
        );
    }

    #[test]
    fn genesis_entropy_is_reproducible_context_bound_and_is_height_one_seed() {
        let manifest = valid_manifest();
        let seed = derive_genesis_election_seed(&manifest.genesis).unwrap();
        assert_eq!(
            seed,
            derive_genesis_election_seed(&manifest.genesis).unwrap()
        );

        let mut other_chain = manifest.genesis.clone();
        other_chain.chain_id.push_str("-other");
        assert_ne!(seed, derive_genesis_election_seed(&other_chain).unwrap());

        let mut other_source = manifest.genesis.clone();
        other_source.bitcoin_pow_entropy_source.announced_height += 1;
        assert_ne!(seed, derive_genesis_election_seed(&other_source).unwrap());

        let mut other_header = manifest.genesis.clone();
        other_header.bitcoin_pow_entropy_header = hex::encode([0x23; 80]);
        assert_ne!(seed, derive_genesis_election_seed(&other_header).unwrap());

        let mut state = ChainState::new_genesis();
        let path = std::env::temp_dir().join(format!(
            "indra-genesis-entropy-test-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, render_manifest(&manifest, false)).unwrap();
        load_genesis_validators(path.to_str().unwrap(), &mut state).unwrap();
        let _ = std::fs::remove_file(path);
        assert_eq!(state.election_seed, seed);
        assert_eq!(state.election_seed_height, 1);
        state.finalize_genesis().unwrap();
        let snapshot = state.snapshot_for_consensus_height(1).unwrap();
        assert!(snapshot
            .entries()
            .iter()
            .all(|entry| entry.vrf_key_activation_epoch == 0));
        assert!(state.validators.active_validators().all(|validator| {
            validator.vrf_pk.is_some()
                && validator.pending_vrf_pk.is_none()
                && validator.pending_vrf_activation_epoch.is_none()
        }));
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
    fn genesis_rejects_vrf_squatting_cold_history_and_noncanonical_hex() {
        let manifest = valid_manifest();
        let mut squatted = manifest.clone();
        squatted.validators[0].vrf_pk = squatted.validators[1].vrf_pk.clone();
        assert!(validate_genesis_manifest(&squatted).is_err());

        let mut wrong_version = manifest.clone();
        wrong_version.validators[0].cold_key_version = 2;
        assert!(validate_genesis_manifest(&wrong_version).is_err());
        let mut used_nonce = manifest.clone();
        used_nonce.validators[0].cold_nonce = 1;
        assert!(validate_genesis_manifest(&used_nonce).is_err());
        let mut uppercase = manifest;
        uppercase.validators[0].validator_id = uppercase.validators[0].validator_id.to_uppercase();
        assert!(validate_genesis_manifest(&uppercase).is_err());
    }

    #[test]
    fn fingerprint_changes_with_every_genesis_identity_domain() {
        let manifest = valid_manifest();
        let path = std::env::temp_dir().join(format!(
            "indra-genesis-fingerprint-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, render_manifest(&manifest, false)).unwrap();
        let state = build_finalized_genesis_state_with_minimum(path.to_str(), 1).unwrap();
        let original = genesis_fingerprint(&state).unwrap();

        let mut changed = state.clone();
        changed.chain_id.push_str("-other");
        assert_ne!(original, genesis_fingerprint(&changed).unwrap());
        let mut changed = state.clone();
        changed.election_seed.0[0] ^= 1;
        assert_ne!(original, genesis_fingerprint(&changed).unwrap());
        let mut changed = state.clone();
        changed.genesis_entropy_record_hash.0[0] ^= 1;
        assert_ne!(original, genesis_fingerprint(&changed).unwrap());
        let mut changed = state.clone();
        changed.monetary_ledger.genesis_issued_spark = changed
            .monetary_ledger
            .genesis_issued_spark
            .checked_add(1)
            .unwrap();
        assert_ne!(original, genesis_fingerprint(&changed).unwrap());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn genesis_liquid_issuance_is_independent_of_manifest_validator_order() {
        use indra_core::codec::Encode;
        let manifest = valid_manifest();
        let mut reversed = manifest.clone();
        reversed.validators.reverse();
        let base = std::env::temp_dir().join(format!("indra-genesis-order-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let first_path = base.join("first.toml");
        let second_path = base.join("second.toml");
        std::fs::write(&first_path, render_manifest(&manifest, false)).unwrap();
        std::fs::write(&second_path, render_manifest(&reversed, false)).unwrap();
        let first = build_finalized_genesis_state_with_minimum(first_path.to_str(), 1).unwrap();
        let second = build_finalized_genesis_state_with_minimum(second_path.to_str(), 1).unwrap();
        assert_eq!(first.utxos.encode_to_vec(), second.utxos.encode_to_vec());
        assert_eq!(
            indra_state::compute_state_root(&first),
            indra_state::compute_state_root(&second)
        );
        assert_eq!(
            genesis_fingerprint(&first).unwrap(),
            genesis_fingerprint(&second).unwrap()
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn genesis_block_is_deterministic() {
        let state = build_genesis_state();
        let h1 = genesis_block_hash(&state).unwrap();
        let h2 = genesis_block_hash(&state).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn genesis_block_height_is_zero() {
        let b = build_genesis_block(&build_genesis_state()).unwrap();
        assert_eq!(b.header.height, 0);
    }

    #[test]
    fn genesis_block_has_zero_prev_hash() {
        let b = build_genesis_block(&build_genesis_state()).unwrap();
        assert_eq!(b.header.prev_hash, Bytes32::ZERO);
    }

    #[test]
    fn genesis_state_height_is_zero() {
        let s = build_genesis_state();
        assert_eq!(s.height, 0);
    }

    #[test]
    fn genesis_utxo_uses_authoritative_public_value() {
        let classical_pk = [0x42u8; 32];
        let pq_pk = vec![0x24u8; 2592];
        let identity_key = HybridPubKey {
            classical_pk: Bytes32::from(classical_pk),
            pq_pk: VariableBytes::from_slice(&pq_pk).unwrap(),
        };
        let validator_id = identity_key.identity_id();
        let cold = indra_crypto::ColdHybridKeypair::from_independent_seeds([0x51; 32], [0x52; 32])
            .unwrap();
        let cold_public = cold.public_key();
        let cold_public = cold_public.as_complete_hybrid();
        let mut state = ChainState::new_genesis();
        let path = std::env::temp_dir().join(format!(
            "indra-genesis-transparent-output-test-{}.toml",
            std::process::id()
        ));
        let vrf = indra_crypto::VrfKeypair::from_seed(&[0x11; 32]);
        let challenge = indra_core::types::staking::StakingOp::vrf_possession_challenge(
            "test",
            &validator_id,
            &Bytes32::from(vrf.public_key()),
            0,
        )
        .unwrap();
        let (vrf_output, vrf_proof) = indra_crypto::vrf_prove(&vrf, &challenge);
        let mut contents = format!(
            "[genesis]\nchain_id = \"test\"\nactive_slot_coefficient_numerator = \"1\"\nbitcoin_pow_entropy_header = \"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"\n\n[genesis.bitcoin_pow_entropy_source]\nscheme = 1\nnetwork_genesis_hash = \"0000000000000000000000000000000000000000000000000000000000000000\"\nannounced_height = 1\nheader_codec = 1\nextraction_algorithm = 1\nminimum_confirmations = 100\nreorg_policy = 1\n\n[[validators]]\nname = \"test-validator\"\nvalidator_id = \"{}\"\nstake = 100000000000\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\nvrf_possession_output = \"{}\"\nvrf_possession_proof = \"{}\"\ncold_hybrid_classical_pk = \"{}\"\ncold_hybrid_pq_pk = \"{}\"\ncold_key_version = 1\ncold_nonce = 0\n",
            hex::encode(validator_id.0),
            hex::encode(classical_pk),
            hex::encode(&pq_pk),
            hex::encode(vrf.public_key()),
            hex::encode(vrf_output.0),
            hex::encode(vrf_proof.0),
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
            let extra_id = indra_core::types::crypto::hybrid_identity_id(
                &hot_public.classical.0,
                &hot_public.pq.0,
            );
            let extra_vrf = indra_crypto::VrfKeypair::from_seed(&[0xA0 + i; 32]);
            let challenge = indra_core::types::staking::StakingOp::vrf_possession_challenge(
                "test",
                &extra_id,
                &Bytes32::from(extra_vrf.public_key()),
                0,
            )
            .unwrap();
            let (extra_output, extra_proof) = indra_crypto::vrf_prove(&extra_vrf, &challenge);
            contents.push_str(&format!(
                "\n[[validators]]\nname = \"extra-{i}\"\nvalidator_id = \"{}\"\nstake = 100000000000\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\nvrf_possession_output = \"{}\"\nvrf_possession_proof = \"{}\"\ncold_hybrid_classical_pk = \"{}\"\ncold_hybrid_pq_pk = \"{}\"\ncold_key_version = 1\ncold_nonce = 0\n",
                hex::encode(extra_id.0),
                hex::encode(hot_public.classical.0),
                hex::encode(hot_public.pq.0),
                hex::encode(extra_vrf.public_key()),
                hex::encode(extra_output.0),
                hex::encode(extra_proof.0),
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
        assert_eq!(entry.output.value_spark, GENESIS_VALIDATOR_UTXO_SPARK);
    }
}
