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
    types::primitives::{
        registered_validator_cap_active, validator_network_address_active, Bytes32, VariableBytes,
        MAX_CHAIN_ID_BYTES,
    },
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
    state.governance.encode(&mut metadata);
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
    compute_validator_set_root_at_height(state, state.height)
}

/// Compute the validator/delegation commitment using the consensus root rule
/// active at `height`.
///
/// Validator network-address fields are consensus-visible only at/after
/// `VALIDATOR_NETWORK_ADDRESS_HEIGHT`. Historical pre-activation state roots
/// must reproduce the exact pre-v4 validator preimage; emitting `false`
/// presence bits for the new fields would still change old committed roots.
pub fn compute_validator_set_root_at_height(state: &ChainState, height: u64) -> Bytes32 {
    let include_network_addr = validator_network_address_active(height);
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
            value.extend_from_slice(&validator.last_active_epoch.to_le_bytes());
            value.extend_from_slice(&validator.rewards_last_epoch.to_le_bytes());
            value.extend_from_slice(&validator.self_report_count.to_le_bytes());
            value.extend_from_slice(&validator.commission_bps.to_le_bytes());
            value.extend_from_slice(&validator.min_delegation_spark.to_le_bytes());
            value.push(u8::from(validator.auto_delegate_to.is_some()));
            if let Some(target_id) = validator.auto_delegate_to {
                value.extend_from_slice(&target_id.0);
            }
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
            if include_network_addr {
                value.push(u8::from(validator.network_addr.is_some()));
                if let Some(addr) = &validator.network_addr {
                    value.extend_from_slice(&(addr.len() as u16).to_le_bytes());
                    value.extend_from_slice(addr.as_bytes());
                }
                value.push(u8::from(
                    validator.network_addr_last_updated_epoch.is_some(),
                ));
                if let Some(epoch) = validator.network_addr_last_updated_epoch {
                    value.extend_from_slice(&epoch.to_le_bytes());
                }
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

    if registered_validator_cap_active(height) {
        for event in &state.delegation_return_events {
            let mut key = Vec::with_capacity(1 + 32 + 32 + 8);
            key.push(0x06);
            key.extend_from_slice(&event.delegator_id.0);
            key.extend_from_slice(&event.bond_utxo_id.0);
            key.extend_from_slice(&event.returned_height.to_le_bytes());

            let mut value = Vec::new();
            event.encode(&mut value);
            leaves.push((key, sha256(&value)));
        }
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
        types::{
            primitives::{
                hard_forks::{REGISTERED_VALIDATOR_CAP_HEIGHT, VALIDATOR_NETWORK_ADDRESS_HEIGHT},
                DUST_LIMIT_SPARK,
            },
            transaction::OutputV1,
        },
        Bytes32, CommitmentV1, HybridPubKey, VariableBytes,
    };
    use indra_crypto::sha256;

    use crate::validator::{
        DelegationReturnEvent, DelegationReturnReason, ValidatorEntry, ValidatorStatus,
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

    fn validator_fixture() -> ValidatorEntry {
        ValidatorEntry {
            validator_id: Bytes32::from([0xA1; 32]),
            name: "validator-a".to_string(),
            hybrid_classical_pk: Some([0xA2; 32]),
            hybrid_pq_pk: Some(vec![0xA3; 80]),
            vrf_pk: Some([0xA4; 32]),
            stake_spark: 10_000,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            pending_rewards: 0,
            rewards_last_epoch: 0,
            self_report_count: 0,
            commission_bps: 1_000,
            pending_commission_bps: None,
            pending_commission_effective_epoch: None,
            min_delegation_spark: DUST_LIMIT_SPARK,
            auto_delegate_to: None,
            network_addr: None,
            network_addr_last_updated_epoch: None,
        }
    }

    fn pre_v4_validator_root_single_validator(validator: &ValidatorEntry) -> Bytes32 {
        let mut key = Vec::with_capacity(33);
        key.push(0x01);
        key.extend_from_slice(&validator.validator_id.0);

        let mut value = Vec::new();
        value.extend_from_slice(&validator.validator_id.0);
        value.extend_from_slice(&validator.stake_spark.to_le_bytes());
        value.extend_from_slice(&validator.pending_rewards.to_le_bytes());
        value.extend_from_slice(&validator.registered_epoch.to_le_bytes());
        value.extend_from_slice(&validator.last_active_epoch.to_le_bytes());
        value.extend_from_slice(&validator.rewards_last_epoch.to_le_bytes());
        value.extend_from_slice(&validator.self_report_count.to_le_bytes());
        value.extend_from_slice(&validator.commission_bps.to_le_bytes());
        value.extend_from_slice(&validator.min_delegation_spark.to_le_bytes());
        value.push(u8::from(validator.auto_delegate_to.is_some()));
        if let Some(target_id) = validator.auto_delegate_to {
            value.extend_from_slice(&target_id.0);
        }
        match validator.status {
            ValidatorStatus::Registered => value.push(0),
            ValidatorStatus::Active => value.push(1),
            ValidatorStatus::Unbonding {
                unbonding_end_epoch,
            } => {
                value.push(2);
                value.extend_from_slice(&unbonding_end_epoch.to_le_bytes());
            }
            ValidatorStatus::Slashed => value.push(3),
            ValidatorStatus::Exited => value.push(4),
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

        let key_hash = sha256(&key);
        let value_hash = sha256(&value);
        let mut leaf = Vec::with_capacity(65);
        leaf.push(0u8);
        leaf.extend_from_slice(&key_hash);
        leaf.extend_from_slice(&value_hash);
        Bytes32::from(sha256(&leaf))
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
    fn validator_set_root_includes_network_address() {
        let mut base = ChainState::new_genesis();
        base.height = VALIDATOR_NETWORK_ADDRESS_HEIGHT;
        let validator = validator_fixture();
        base.validators.upsert(validator.clone()).unwrap();

        let mut with_addr = base.clone();
        {
            let v = with_addr
                .validators
                .get_mut(&validator.validator_id)
                .unwrap();
            v.network_addr = Some("203.0.113.20:30303".to_string());
            v.network_addr_last_updated_epoch = Some(1);
        }
        assert_ne!(
            compute_validator_set_root(&base),
            compute_validator_set_root(&with_addr)
        );

        let mut default_again = ChainState::new_genesis();
        default_again.height = VALIDATOR_NETWORK_ADDRESS_HEIGHT;
        default_again.validators.upsert(validator).unwrap();
        assert_eq!(
            compute_validator_set_root(&base),
            compute_validator_set_root(&default_again)
        );
    }

    #[test]
    fn height_gated_root_matches_original_pre_activation_computation() {
        let mut state = ChainState::new_genesis();
        state.height = VALIDATOR_NETWORK_ADDRESS_HEIGHT.saturating_sub(1);
        let mut validator = validator_fixture();
        validator.network_addr = Some("203.0.113.20:30303".to_string());
        validator.network_addr_last_updated_epoch = Some(7);
        let old_preimage_root = pre_v4_validator_root_single_validator(&validator);
        state.validators.upsert(validator).unwrap();

        assert_eq!(compute_validator_set_root(&state), old_preimage_root);
    }

    #[test]
    fn height_gated_root_uses_new_encoding_at_and_after_activation() {
        let mut before = ChainState::new_genesis();
        before.height = VALIDATOR_NETWORK_ADDRESS_HEIGHT.saturating_sub(1);
        let mut base_validator = validator_fixture();
        base_validator.network_addr = Some("203.0.113.20:30303".to_string());
        base_validator.network_addr_last_updated_epoch = Some(7);
        before.validators.upsert(base_validator.clone()).unwrap();

        let mut at_activation_without_addr = ChainState::new_genesis();
        at_activation_without_addr.height = VALIDATOR_NETWORK_ADDRESS_HEIGHT;
        let mut without_addr = base_validator.clone();
        without_addr.network_addr = None;
        without_addr.network_addr_last_updated_epoch = None;
        at_activation_without_addr
            .validators
            .upsert(without_addr)
            .unwrap();

        let mut at_activation_with_addr = ChainState::new_genesis();
        at_activation_with_addr.height = VALIDATOR_NETWORK_ADDRESS_HEIGHT;
        at_activation_with_addr
            .validators
            .upsert(base_validator.clone())
            .unwrap();

        assert_eq!(
            compute_validator_set_root(&before),
            pre_v4_validator_root_single_validator(&base_validator)
        );
        assert_ne!(
            compute_validator_set_root(&at_activation_without_addr),
            compute_validator_set_root(&at_activation_with_addr)
        );
    }

    #[test]
    fn validator_set_root_includes_delegation_return_events_only_after_cap_activation() {
        let mut before = ChainState::new_genesis();
        before.height = REGISTERED_VALIDATOR_CAP_HEIGHT.saturating_sub(1);
        let mut before_with_event = before.clone();
        before_with_event.push_delegation_return_event(DelegationReturnEvent {
            delegator_id: Bytes32::from([0x51; 32]),
            validator_id: Bytes32::from([0x52; 32]),
            bond_utxo_id: Bytes32::from([0x53; 32]),
            amount_spark: 10,
            reason: DelegationReturnReason::ValidatorEvicted,
            returned_epoch: 1,
            returned_height: before_with_event.height,
            refund_utxo_id: Bytes32::from([0x54; 32]),
        });
        assert_eq!(
            compute_validator_set_root(&before),
            compute_validator_set_root(&before_with_event)
        );

        let mut at_activation = before_with_event;
        at_activation.height = REGISTERED_VALIDATOR_CAP_HEIGHT;
        let mut at_activation_empty = ChainState::new_genesis();
        at_activation_empty.height = REGISTERED_VALIDATOR_CAP_HEIGHT;
        assert_ne!(
            compute_validator_set_root(&at_activation_empty),
            compute_validator_set_root(&at_activation)
        );
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
