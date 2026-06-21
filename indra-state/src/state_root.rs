//! State-root computation over sparse Merkle commitments.
//!
//! The final state root commits to:
//! - the full UTXO sparse Merkle tree
//! - the full nullifier sparse Merkle tree
//! - chain metadata required for deterministic replay
//!
//! `tip_hash` is intentionally excluded from the metadata hash to avoid a
//! circular dependency: block hashes include `state_root`, and post-state
//! `tip_hash` becomes that same block hash after commit.

use indra_core::{
    codec::Encode,
    types::primitives::{Bytes32, VariableBytes, MAX_CHAIN_ID_BYTES},
};
use indra_crypto::sha256;

use crate::ChainState;

/// Compute the full state root for the given chain state.
pub fn compute_state_root(state: &ChainState) -> Bytes32 {
    let utxo_root = state.utxos.root();
    let nullifier_root = state.nullifiers.root();
    let validator_root = compute_validator_set_root(state);

    let chain_id = VariableBytes::<MAX_CHAIN_ID_BYTES>::from_slice(state.chain_id.as_bytes())
        .unwrap_or_default();
    let mut metadata = Vec::with_capacity(48 + chain_id.encoded_len());
    chain_id.encode(&mut metadata);
    metadata.extend_from_slice(&state.height.to_le_bytes());
    metadata.extend_from_slice(&state.total_supply.to_le_bytes());
    metadata.extend_from_slice(&state.base_fee.to_le_bytes());
    metadata.extend_from_slice(&state.treasury_balance.to_le_bytes());
    metadata.extend_from_slice(&state.burn_buffer.to_le_bytes());
    metadata.extend_from_slice(&state.fee_reward_pool.to_le_bytes());
    let metadata_hash = sha256(&metadata);

    let mut combined = Vec::with_capacity(128);
    combined.extend_from_slice(&utxo_root);
    combined.extend_from_slice(&nullifier_root);
    combined.extend_from_slice(&validator_root.0);
    combined.extend_from_slice(&metadata_hash);
    Bytes32::from(sha256(&combined))
}

/// Compute the validator/delegation commitment.
pub fn compute_validator_set_root(state: &ChainState) -> Bytes32 {
    let mut leaves: Vec<(Vec<u8>, [u8; 32])> = state
        .validators
        .all_validators()
        .map(|validator| {
            let mut key = Vec::with_capacity(33);
            key.push(0x01);
            key.extend_from_slice(&validator.validator_id.0);

            let mut value = Vec::new();
            value.extend_from_slice(&validator.validator_id.0);
            value.extend_from_slice(&validator.stake_spark.to_le_bytes());
            value.extend_from_slice(&validator.pending_rewards.to_le_bytes());
            value.extend_from_slice(&validator.registered_epoch.to_le_bytes());
            value.extend_from_slice(&validator.rewards_last_epoch.to_le_bytes());
            value.extend_from_slice(&validator.self_report_count.to_le_bytes());
            value.extend_from_slice(&validator.commission_bps.to_le_bytes());
            value.extend_from_slice(&validator.min_delegation_spark.to_le_bytes());
            match validator.status {
                crate::validator::ValidatorStatus::Registered => value.push(0),
                crate::validator::ValidatorStatus::Active => value.push(1),
                crate::validator::ValidatorStatus::Unbonding {
                    unbonding_end_epoch,
                } => {
                    value.push(2);
                    value.extend_from_slice(&unbonding_end_epoch.to_le_bytes());
                }
                crate::validator::ValidatorStatus::Slashed => value.push(3),
                crate::validator::ValidatorStatus::Exited => value.push(4),
            }
            if let Some(pk) = validator.hybrid_classical_pk {
                value.extend_from_slice(&pk);
            }
            if let Some(pk) = &validator.hybrid_pq_pk {
                value.extend_from_slice(pk);
            }
            if let Some(vrf_pk) = validator.vrf_pk {
                value.extend_from_slice(&vrf_pk);
            }
            (key, sha256(&value))
        })
        .collect();

    for validator in state.validators.all_validators() {
        for delegator in state.delegations.get_delegators(&validator.validator_id) {
            let mut key = Vec::with_capacity(65);
            key.push(0x02);
            key.extend_from_slice(&validator.validator_id.0);
            key.extend_from_slice(&delegator.delegator_id.0);

            let mut value = Vec::new();
            value.extend_from_slice(&delegator.delegator_id.0);
            value.extend_from_slice(&delegator.staked_spark.to_le_bytes());
            value.extend_from_slice(&delegator.pending_rewards.to_le_bytes());
            value.extend_from_slice(&delegator.rewards_last_epoch.to_le_bytes());
            value.extend_from_slice(&delegator.unbonding_end_epoch.unwrap_or(0).to_le_bytes());
            value.push(u8::from(delegator.unbonding_end_epoch.is_some()));
            leaves.push((key, sha256(&value)));
        }
    }

    for (signer_id, nonce) in &state.staking_nonces {
        let mut key = Vec::with_capacity(33);
        key.push(0x03);
        key.extend_from_slice(&signer_id.0);

        let mut value = Vec::with_capacity(40);
        value.extend_from_slice(&signer_id.0);
        value.extend_from_slice(&nonce.to_le_bytes());
        leaves.push((key, sha256(&value)));
    }

    for (utxo_id, bond) in &state.staked_bonds {
        let mut key = Vec::with_capacity(33);
        key.push(0x04);
        key.extend_from_slice(&utxo_id.0);

        let mut value = Vec::new();
        bond.encode(&mut value);
        leaves.push((key, sha256(&value)));
    }

    for hash in &state.applied_slash_hashes {
        let mut key = Vec::with_capacity(33);
        key.push(0x05);
        key.extend_from_slice(&hash.0);
        leaves.push((key, sha256(&hash.0)));
    }

    if leaves.is_empty() {
        return Bytes32::ZERO;
    }

    leaves.sort_by(|(a, _), (b, _)| a.cmp(b));
    let mut level: Vec<[u8; 32]> = leaves
        .into_iter()
        .map(|(key, value_hash)| {
            let key_hash = sha256(&key);
            let mut data = Vec::with_capacity(65);
            data.push(0u8);
            data.extend_from_slice(&key_hash);
            data.extend_from_slice(&value_hash);
            sha256(&data)
        })
        .collect();

    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = level.last().copied().unwrap_or([0u8; 32]);
            level.push(last);
        }

        let mut next = Vec::with_capacity(level.len() / 2);
        let mut index = 0usize;
        while index + 1 < level.len() {
            let mut data = Vec::with_capacity(65);
            data.push(1u8);
            data.extend_from_slice(&level[index]);
            data.extend_from_slice(&level[index + 1]);
            next.push(sha256(&data));
            index = index.saturating_add(2);
        }
        level = next;
    }

    Bytes32::from(level.first().copied().unwrap_or([0u8; 32]))
}

#[cfg(test)]
mod tests {
    use indra_core::{
        types::transaction::OutputV1, Bytes32, CommitmentV1, HybridPubKey, VariableBytes,
    };

    use super::*;

    fn dummy_output(byte: u8) -> OutputV1 {
        OutputV1 {
            value_spark: 1_000 + byte as u64,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from([byte; 32]),
            },
            owner_pubkey: HybridPubKey {
                classical_pk: Bytes32::from([byte; 32]),
                pq_pk: VariableBytes::from_slice(&[byte; 32]).unwrap_or_else(|_| unreachable!()),
            },
            range_proof: VariableBytes::from_slice(&[0u8; 32]).unwrap_or_else(|_| unreachable!()),
            lock_height: 0,
        }
    }

    #[test]
    fn state_root_is_deterministic() {
        let mut a = ChainState::new_genesis();
        let mut b = ChainState::new_genesis();
        let _ = a.utxos.insert(dummy_output(0x10), 1, 0, 0);
        let _ = b.utxos.insert(dummy_output(0x10), 1, 0, 0);
        assert_eq!(compute_state_root(&a), compute_state_root(&b));
    }

    #[test]
    fn state_root_changes_with_state() {
        let mut state = ChainState::new_genesis();
        let root0 = compute_state_root(&state);
        let _ = state.utxos.insert(dummy_output(0x20), 1, 0, 0);
        let root1 = compute_state_root(&state);
        assert_ne!(root0, root1);
    }

    #[test]
    fn validator_root_empty_is_zero() {
        let state = ChainState::new_genesis();
        assert_eq!(compute_validator_set_root(&state), Bytes32::ZERO);
    }

    #[test]
    fn chain_id_changes_state_root() {
        let mut a = ChainState::new_genesis();
        let mut b = ChainState::new_genesis();
        b.chain_id = "indra-mainnet-1".to_string();
        assert_ne!(compute_state_root(&a), compute_state_root(&b));
        a.chain_id = "indra-mainnet-1".to_string();
        assert_eq!(compute_state_root(&a), compute_state_root(&b));
    }
}
