//! Genesis block and initial chain state.
//!
//! The genesis block is height 0. It has:
//! - An all-zero prev_hash
//! - No transactions, slashing evidence, or governance ops
//! - A zeroed QC (no previous block to certify)
//! - The initial base fee
//!
//! The genesis state is produced by `ChainState::new_genesis()`.

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
use indra_state::{ChainState, ColdKeyStatus};
use rand::{rngs::StdRng, SeedableRng};

const GENESIS_VALIDATOR_UTXO_SPARK: u64 = 1_000_000_000_000;

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
        slashing_evidence_v2: vec![],
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

/// Build the initial chain state (genesis state).
pub fn build_genesis_state() -> ChainState {
    let state = ChainState::new_genesis();
    assert_eq!(state.total_supply, GENESIS_SUPPLY_SPARK);
    assert!(state.total_supply <= HARD_CAP_SPARK);
    assert_eq!(state.fee_reward_pool, 0);
    state
}

/// Load validator entries from a genesis.toml file.
///
/// Reads each [[validators]] section and registers them in the
/// provided ChainState validator set with Active status.
pub fn load_genesis_validators(genesis_path: &str, state: &mut indra_state::ChainState) {
    use indra_core::types::primitives::Bytes32;
    use indra_state::{ValidatorEntry, ValidatorStatus};

    fn parse_fixed_hex<const N: usize>(value: Option<&String>) -> Option<[u8; N]> {
        let hex = value?;
        let bytes = hex::decode(hex).ok()?;
        let array: [u8; N] = bytes.try_into().ok()?;
        Some(array)
    }

    fn parse_vec_hex(value: Option<&String>) -> Option<Vec<u8>> {
        let hex = value?;
        hex::decode(hex).ok()
    }

    let content = match std::fs::read_to_string(genesis_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("[genesis] cannot read {}: {}", genesis_path, e);
            return;
        }
    };

    for line in content.lines() {
        let line = line.trim();
        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == "chain_id" {
                state.chain_id = value
                    .trim()
                    .trim_matches('"')
                    .trim_end_matches(',')
                    .trim_matches('"')
                    .to_string();
                break;
            }
        }
    }

    // Parse each [[validators]] block
    let mut in_validator = false;
    let mut current: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut validators = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line == "[[validators]]" {
            if !current.is_empty() {
                validators.push(current.clone());
                current.clear();
            }
            in_validator = true;
            continue;
        }
        if line.starts_with('[') && line != "[[validators]]" {
            if in_validator && !current.is_empty() {
                validators.push(current.clone());
                current.clear();
            }
            in_validator = false;
            continue;
        }
        if in_validator {
            if let Some(eq) = line.find('=') {
                let key = line[..eq].trim().to_string();
                let val = line[eq + 1..]
                    .trim()
                    .trim_matches('"')
                    .trim_end_matches(',')
                    .trim_matches('"')
                    .to_string();
                current.insert(key, val);
            }
        }
    }
    if !current.is_empty() {
        validators.push(current);
    }

    // NOTE: startup logging for node bootstrap; replace with structured tracing later.
    println!(
        "[genesis] Loading {} validators from {}",
        validators.len(),
        genesis_path
    );

    for v in &validators {
        let id_hex = match v.get("validator_id") {
            Some(s) => s.clone(),
            None => continue,
        };
        let stake_str = v.get("stake").cloned().unwrap_or_else(|| "0".to_string());
        let stake: u64 = stake_str.trim().parse().unwrap_or(0);
        let name = v.get("name").cloned().unwrap_or_default();

        let id_bytes = match hex::decode(&id_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => {
                eprintln!("[genesis] Invalid validator_id for {}: {}", name, id_hex);
                continue;
            }
        };

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&id_bytes);
        let validator_id = Bytes32::from(arr);

        let entry = ValidatorEntry {
            validator_id,
            name: name.clone(),
            hybrid_classical_pk: parse_fixed_hex::<32>(v.get("hybrid_classical_pk")),
            hybrid_pq_pk: parse_vec_hex(v.get("hybrid_pq_pk")),
            vrf_pk: parse_fixed_hex::<32>(v.get("vrf_pk")),
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
            cold_hybrid_classical_pk: parse_fixed_hex::<32>(v.get("cold_hybrid_classical_pk")),
            cold_hybrid_pq_pk: parse_fixed_hex::<{ indra_crypto::PQ_PK_BYTES }>(
                v.get("cold_hybrid_pq_pk"),
            ),
            cold_key_version: v
                .get("cold_key_version")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            cold_key_status: match v.get("cold_key_status").map(String::as_str) {
                Some("active") => ColdKeyStatus::Active,
                _ => ColdKeyStatus::Unenrolled,
            },
            cold_nonce: v
                .get("cold_nonce")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
        };

        let _ = state.validators.upsert(entry);
        if let (Some(classical_pk), Some(hybrid_pq_pk)) = (
            parse_fixed_hex::<32>(v.get("hybrid_classical_pk")),
            parse_vec_hex(v.get("hybrid_pq_pk")),
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
}

/// Load optional P2P seed peer hints from a genesis.toml file.
pub fn load_genesis_seed_peers(genesis_path: &str) -> Vec<String> {
    let content = match std::fs::read_to_string(genesis_path) {
        Ok(content) => content,
        Err(_) => return vec![],
    };

    let mut in_seed = false;
    let mut peers = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line == "[[seeds]]" {
            in_seed = true;
            continue;
        }
        if line.starts_with('[') && line != "[[seeds]]" {
            in_seed = false;
            continue;
        }
        if in_seed {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim() == "addr" {
                let addr = value
                    .trim()
                    .trim_matches('"')
                    .trim_end_matches(',')
                    .trim_matches('"')
                    .to_string();
                if !addr.is_empty() {
                    peers.push(addr);
                }
            }
        }
    }
    peers
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_crypto::derive_genesis_utxo_blinding_from_classical_pk;

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
        let mut state = ChainState::new_genesis();
        let path = std::env::temp_dir().join(format!(
            "indra-genesis-blinding-test-{}.toml",
            std::process::id()
        ));
        let contents = format!(
            "chain_id = \"test\"\n\n[[validators]]\nname = \"test-validator\"\nvalidator_id = \"{}\"\nstake = \"100000000000\"\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\n",
            hex::encode(validator_id.0),
            hex::encode(classical_pk),
            hex::encode(&pq_pk),
            hex::encode([0x11u8; 32])
        );
        std::fs::write(&path, contents).unwrap();

        load_genesis_validators(path.to_str().unwrap(), &mut state);
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
