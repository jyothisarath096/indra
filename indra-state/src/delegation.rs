//! Delegation state transitions.
//!
//! Handles apply_delegate, apply_undelegate, apply_claim_rewards,
//! and apply_set_commission. Called from apply_block when a block
//! contains StakingOp entries.

use indra_core::types::{
    primitives::{
        Bytes32, UNBONDING_PERIOD_EPOCHS,
        MIN_COMMISSION_BPS, MAX_COMMISSION_BPS,
    },
    staking::StakingOp,
};

use crate::{
    chain::ChainState,
    error::{StateError, StateResult},
    validator::ValidatorStatus,
    epoch::epoch_for_height,
};

/// Apply a single staking operation to chain state.
///
/// Called after all transaction validation has passed.
/// Staking ops are applied in block order after UTXO transactions.
pub fn apply_staking_op(state: &mut ChainState, op: &StakingOp) -> StateResult<()> {
    match op {
        StakingOp::Delegate { validator_id, amount_spark, delegator_pubkey } => {
            apply_delegate(state, validator_id, *amount_spark, delegator_pubkey)
        }
        StakingOp::Undelegate { validator_id, amount_spark, delegator_pubkey } => {
            apply_undelegate(state, validator_id, *amount_spark, delegator_pubkey)
        }
        StakingOp::ClaimRewards { validator_id, delegator_pubkey } => {
            apply_claim_rewards(state, validator_id, delegator_pubkey)
        }
        StakingOp::RegisterValidator { commission_bps, validator_pubkey: _ } => {
            // Registration is handled at genesis or via separate onboarding flow.
            // Here we just validate the commission range.
            if *commission_bps < MIN_COMMISSION_BPS || *commission_bps > MAX_COMMISSION_BPS {
                return Err(StateError::InvalidStakingOp(
                    "commission out of range".into()
                ));
            }
            Ok(())
        }
        StakingOp::SetCommission { validator_id, new_commission_bps } => {
            apply_set_commission(state, validator_id, *new_commission_bps)
        }
    }
}

/// Delegate stake to a validator.
///
/// The delegator's stake is added to the validator's delegation pool.
/// Rewards accrue from the next epoch boundary.
fn apply_delegate(
    state: &mut ChainState,
    validator_id: &Bytes32,
    amount_spark: u64,
    delegator_pubkey: &indra_core::types::crypto::HybridPubKey,
) -> StateResult<()> {
    // Validator must exist and be active
    let validator = state.validators.get(validator_id)
        .ok_or(StateError::ValidatorNotFound)?;
    if !validator.is_active() {
        return Err(StateError::ValidatorNotActive);
    }

    // Derive delegator_id from pubkey bytes
    let delegator_id = pubkey_to_id(delegator_pubkey);
    let current_epoch = epoch_for_height(state.height);

    state.delegations.add_delegation(
        *validator_id,
        delegator_id,
        amount_spark,
        current_epoch,
    );

    Ok(())
}

/// Begin undelegating from a validator.
///
/// Stake enters unbonding for UNBONDING_PERIOD_EPOCHS epochs.
/// During unbonding, stake earns no rewards and cannot be redelegated.
fn apply_undelegate(
    state: &mut ChainState,
    validator_id: &Bytes32,
    amount_spark: u64,
    delegator_pubkey: &indra_core::types::crypto::HybridPubKey,
) -> StateResult<()> {
    let delegator_id = pubkey_to_id(delegator_pubkey);
    let current_epoch = epoch_for_height(state.height);
    let unbonding_end = current_epoch + UNBONDING_PERIOD_EPOCHS;

    state.delegations
        .begin_undelegate(validator_id, &delegator_id, amount_spark, unbonding_end)
        .map_err(|e| StateError::InvalidStakingOp(e.into()))
}

/// Claim pending rewards for a delegator.
///
/// Transfers pending_rewards to the delegator's UTXO set entry.
/// In Phase 3 this will create an actual UTXO output.
/// For now, rewards are zeroed and added to total supply as distributed.
fn apply_claim_rewards(
    state: &mut ChainState,
    validator_id: &Bytes32,
    delegator_pubkey: &indra_core::types::crypto::HybridPubKey,
) -> StateResult<()> {
    let delegator_id = pubkey_to_id(delegator_pubkey);

    let entry = state.delegations
        .get_delegator_mut(validator_id, &delegator_id)
        .ok_or(StateError::DelegatorNotFound)?;

    // Zero out pending rewards — in Phase 3 this creates a UTXO
    let _claimed = entry.pending_rewards;
    entry.pending_rewards = 0;

    Ok(())
}

/// Update a validator's commission rate.
///
/// Takes effect immediately for future epoch reward distributions.
/// Does not affect already-accrued pending rewards.
fn apply_set_commission(
    state: &mut ChainState,
    validator_id: &Bytes32,
    new_commission_bps: u32,
) -> StateResult<()> {
    if new_commission_bps < MIN_COMMISSION_BPS || new_commission_bps > MAX_COMMISSION_BPS {
        return Err(StateError::InvalidStakingOp(
            "commission out of governance-set range".into()
        ));
    }

    let validator = state.validators.get_mut(validator_id)
        .ok_or(StateError::ValidatorNotFound)?;

    if !matches!(validator.status, ValidatorStatus::Active) {
        return Err(StateError::ValidatorNotActive);
    }

    validator.commission_bps = new_commission_bps;
    Ok(())
}

/// Derive a stable delegator ID from their hybrid public key.
///
/// Uses SHA-256 of the encoded public key bytes, matching how
/// validator_id is derived from validator public keys.
fn pubkey_to_id(pubkey: &indra_core::types::crypto::HybridPubKey) -> Bytes32 {
    use indra_core::codec::Encode;
    let bytes = pubkey.encode_to_vec();
    // Simple SHA-256 via standard library — matches validator_id derivation
    let hash = indra_crypto::sha256(&bytes);
    Bytes32::from(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::{
        primitives::VariableBytes,
        crypto::HybridPubKey,
    };
    use crate::{
        chain::ChainState,
        validator::{ValidatorEntry, ValidatorStatus},
    };

    fn dummy_pubkey(seed: u8) -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::from([seed; 32]),
            pq_pk: VariableBytes::from_slice(&[seed; 1312]).unwrap(),
        }
    }

    fn make_active_validator(state: &mut ChainState, id_byte: u8) -> Bytes32 {
        let validator_id = Bytes32::from([id_byte; 32]);
        let entry = ValidatorEntry {
            validator_id,
            hybrid_classical_pk: None,
            hybrid_pq_pk: None,
            bls_pk: None,
            vrf_pk: None,
            stake_spark: 10_000_000_000,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            pending_rewards: 0,
            rewards_last_epoch: 0,
            self_report_count: 0,
            commission_bps: 1_000,
        };
        state.validators.upsert(entry).unwrap();
        validator_id
    }

    #[test]
    fn delegate_to_active_validator_succeeds() {
        let mut state = ChainState::new_genesis();
        let validator_id = make_active_validator(&mut state, 0x01);
        let pubkey = dummy_pubkey(0x02);

        let op = StakingOp::Delegate {
            validator_id,
            amount_spark: 1_000_000,
            delegator_pubkey: pubkey,
        };
        assert!(apply_staking_op(&mut state, &op).is_ok());
        assert_eq!(state.delegations.total_delegated(&validator_id), 1_000_000);
    }

    #[test]
    fn delegate_to_unknown_validator_fails() {
        let mut state = ChainState::new_genesis();
        let pubkey = dummy_pubkey(0x01);

        let op = StakingOp::Delegate {
            validator_id: Bytes32::from([0xFFu8; 32]),
            amount_spark: 1_000_000,
            delegator_pubkey: pubkey,
        };
        assert!(apply_staking_op(&mut state, &op).is_err());
    }

    #[test]
    fn set_commission_valid_range_succeeds() {
        let mut state = ChainState::new_genesis();
        let validator_id = make_active_validator(&mut state, 0x01);

        let op = StakingOp::SetCommission {
            validator_id,
            new_commission_bps: 1_500,
        };
        assert!(apply_staking_op(&mut state, &op).is_ok());
        assert_eq!(state.validators.get(&validator_id).unwrap().commission_bps, 1_500);
    }

    #[test]
    fn set_commission_out_of_range_fails() {
        let mut state = ChainState::new_genesis();
        let validator_id = make_active_validator(&mut state, 0x01);

        let op = StakingOp::SetCommission {
            validator_id,
            new_commission_bps: 9_999,
        };
        assert!(apply_staking_op(&mut state, &op).is_err());
    }

    #[test]
    fn undelegate_then_no_active_stake() {
        let mut state = ChainState::new_genesis();
        let validator_id = make_active_validator(&mut state, 0x01);
        let pubkey = dummy_pubkey(0x02);

        // First delegate
        let delegate_op = StakingOp::Delegate {
            validator_id,
            amount_spark: 1_000_000,
            delegator_pubkey: pubkey.clone(),
        };
        apply_staking_op(&mut state, &delegate_op).unwrap();

        // Then undelegate
        let undelegate_op = StakingOp::Undelegate {
            validator_id,
            amount_spark: 1_000_000,
            delegator_pubkey: pubkey,
        };
        assert!(apply_staking_op(&mut state, &undelegate_op).is_ok());
        // Active delegation should now be 0
        assert_eq!(state.delegations.total_delegated(&validator_id), 0);
    }
}
