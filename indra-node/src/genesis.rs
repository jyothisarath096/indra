//! Genesis block and initial chain state.
//!
//! The genesis block is height 0. It has:
//! - An all-zero prev_hash
//! - No transactions, slashing evidence, or governance ops
//! - A zeroed QC (no previous block to certify)
//! - The initial base fee
//!
//! The genesis state is produced by `ChainState::new_genesis()`.

use indra_core::{
    types::{
        block::{BlockHeaderV1, BlockV1},
        primitives::{
            Bytes32, ProtocolVersion, VariableBytes,
            INITIAL_BASE_FEE_SPARK_PER_KB, MAX_VRF_PROOF_BYTES, MAX_QC_SIZE_BYTES,
            MAX_RANGE_PROOF_BYTES,
        },
        crypto::{CommitmentV1, HybridPubKey},
        transaction::OutputV1,
    },
};
use indra_state::ChainState;
use indra_crypto::{sha256, pedersen::commit};

/// Build the genesis block.
///
/// The genesis block hash is SHA-256(encode(genesis_header)).
pub fn build_genesis_block() -> BlockV1 {
    BlockV1 {
        header: BlockHeaderV1 {
            protocol_version:    ProtocolVersion::CURRENT,
            height:              0,
            prev_hash:           Bytes32::ZERO,
            timestamp:           1_700_000_000, // 2023-11-14 — fixed genesis timestamp
            state_root:          Bytes32::ZERO,
            validator_set_root:  Bytes32::ZERO,
            mempool_set_root:    Bytes32::ZERO,
            base_fee:            INITIAL_BASE_FEE_SPARK_PER_KB,
            proposer_vrf_output: Bytes32::ZERO,
            proposer_vrf_proof:  VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap_or_else(|_| {
                // Safety: empty slice always fits
                panic!("empty VRF proof should always fit")
            }),
            quorum_certificate:  VariableBytes::<MAX_QC_SIZE_BYTES>::from_slice(&[]).unwrap_or_else(|_| {
                panic!("empty QC should always fit")
            }),
        },
        transactions:      vec![],
        slashing_evidence: vec![],
        governance_ops:    vec![],
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
    ChainState::new_genesis()
}


/// Load validator entries from a genesis.toml file.
///
/// Reads each [[validators]] section and registers them in the
/// provided ChainState validator set with Active status.
pub fn load_genesis_validators(genesis_path: &str, state: &mut indra_state::ChainState) {
    use indra_core::types::primitives::Bytes32;
    use indra_state::{ValidatorEntry, ValidatorStatus};

    let content = std::fs::read_to_string(genesis_path)
        .unwrap_or_else(|e| panic!("Cannot read genesis file {}: {}", genesis_path, e));

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
                let val = line[eq+1..].trim()
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

    println!("[genesis] Loading {} validators from {}", validators.len(), genesis_path);

    for (validator_index, v) in validators.iter().enumerate() {
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
            stake_spark: stake,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            pending_rewards: 0,
            rewards_last_epoch: 0,
            self_report_count: 0,
            commission_bps: indra_core::types::primitives::DEFAULT_COMMISSION_BPS,
        };

        let _ = state.validators.upsert(entry);
        println!("[genesis]   + {} ({}...)", name, &id_hex[..8]);

        // Create spendable genesis UTXO for this validator
        // Blinding = SHA-256(classical_pk || "genesis-utxo-blinding")
        let classical_pk_hex = match v.get("hybrid_classical_pk") {
            Some(s) => s.clone(),
            None => continue,
        };
        let classical_pk_bytes = match hex::decode(&classical_pk_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => {
                eprintln!("[genesis] Invalid hybrid_classical_pk for {}", name);
                continue;
            }
        };
        let pq_pk_hex = v.get("hybrid_pq_pk").cloned().unwrap_or_default();
        let pq_pk_bytes = hex::decode(&pq_pk_hex).unwrap_or_else(|_| vec![0u8; 1312]);

        // Derive blinding deterministically
        let mut blinding_input = classical_pk_bytes.clone();
        blinding_input.extend_from_slice(b"genesis-utxo-blinding");
        let blinding: [u8; 32] = sha256(&blinding_input);

        // Build Pedersen commitment: C = stake*G + blinding*H
        let commitment = commit(stake, &blinding);

        // Generate range proof
        let mut rng = rand::rngs::OsRng;
        let range_proof_bytes = match indra_crypto::prove_range(stake, &blinding, &mut rng) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[genesis] Range proof failed for {}: {}", name, e);
                continue;
            }
        };

        // Build owner pubkey
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&classical_pk_bytes);

        let pq_pk_var = match indra_core::types::primitives::VariableBytes::<{indra_core::types::primitives::MAX_PQ_PK_BYTES}>::from_slice(&pq_pk_bytes) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("[genesis] PQ pubkey too large for {}", name);
                continue;
            }
        };

        let owner_pubkey = HybridPubKey {
            classical_pk: Bytes32::from(pk_arr),
            pq_pk: pq_pk_var,
        };

        let proof_var = match VariableBytes::<MAX_RANGE_PROOF_BYTES>::from_slice(&range_proof_bytes) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("[genesis] Range proof too large for {}", name);
                continue;
            }
        };

        let output = OutputV1 {
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from(commitment.0),
            },
            owner_pubkey,
            range_proof: proof_var,
            lock_height: 0,
        };

        match state.utxos.insert(output, 0, 0, validator_index as u32) {
            Ok(utxo_id) => {
                println!("[genesis]   UTXO {} = {} Spark (blinding: {}...)",
                    hex::encode(&utxo_id.0[..8]),
                    stake,
                    hex::encode(&blinding[..8]),
                );
            }
            Err(e) => eprintln!("[genesis] Failed to insert UTXO for {}: {}", name, e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
