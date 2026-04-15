//! Epoch transition logic.
//!
//! Triggered when `height % EPOCH_DURATION_BLOCKS == 0`.
//!
//! ## What happens at an epoch boundary (Spec Section F)
//!
//! 1. Compute epoch_reward = total_supply × INFLATION_RATE_BPS / 10000 / epochs_per_year
//! 2. Distribute: 60% to validator pool, 30% to treasury, 10% to burn buffer
//! 3. Distribute validator pool proportionally by stake weight
//! 4. Expire unclaimed rewards older than CLAIM_WINDOW_EPOCHS
//! 5. Advance unbonding validators (release stake if unbonding_end_epoch reached)
//!
//! ## Integer arithmetic
//!
//! All reward calculations use u64 integer arithmetic.
//! Rounding: floor division throughout.
//! Dust (remainder after distribution) stays in treasury.

use indra_core::types::primitives::{
    INFLATION_RATE_BPS,
    VALIDATOR_POOL_SHARE_BPS,
    TREASURY_SHARE_BPS,
    BURN_BUFFER_SHARE_BPS,
    EPOCH_DURATION_BLOCKS,
};

use crate::{
    chain::ChainState,
    error::StateResult,
    validator::ValidatorStatus,
};

/// Number of epochs per year (approximate).
/// 365.25 days × 24h × 60min × 60s / BLOCK_TIME / EPOCH_DURATION_BLOCKS
/// = 31_557_600 / 6 / 300 = 17_532 epochs/year
pub const EPOCHS_PER_YEAR: u64 = 17_532;

/// Apply the epoch transition to the chain state.
///
/// Called at the end of the last block of each epoch
/// (i.e., when `height % EPOCH_DURATION_BLOCKS == 0`).
///
/// Mutates `state` in place. Returns Ok(()) on success.
pub fn apply_epoch_transition(
    state: &mut ChainState,
    current_epoch: u64,
) -> StateResult<()> {
    // 1. Compute this epoch's reward pool
    let EpochRewards { validator_pool, treasury_amount, burn_amount } =
        compute_epoch_rewards(state.total_supply);

    // 2. Add to treasury
    state.treasury_balance = state.treasury_balance.saturating_add(treasury_amount);

    // 3. Add to burn buffer (tracked separately, actual burn handled by governance)
    state.burn_buffer = state.burn_buffer.saturating_add(burn_amount);

    // 4. Distribute validator pool proportionally by stake
    distribute_validator_rewards(state, validator_pool, current_epoch);

    // 5. Expire stale rewards
    state.validators.expire_stale_rewards(current_epoch);

    // 6. Release unbonded validators
    release_unbonded_validators(state, current_epoch);

    // 7. Update total supply (minted = validator_pool + treasury + burn_buffer)
    let minted = validator_pool.saturating_add(treasury_amount).saturating_add(burn_amount);
    state.total_supply = state.total_supply.saturating_add(minted);

    Ok(())
}

/// Reward amounts for one epoch.
#[derive(Debug, Clone, Copy)]
pub struct EpochRewards {
    /// Spark allocated to the validator reward pool.
    pub validator_pool: u64,
    /// Spark added to treasury.
    pub treasury_amount: u64,
    /// Spark added to burn buffer.
    pub burn_amount: u64,
}

/// Compute how many Spark to mint this epoch.
///
/// epoch_reward = total_supply × INFLATION_RATE_BPS / 10_000 / EPOCHS_PER_YEAR
///
/// Rounding: floor. Remainder dust stays in supply (not distributed).
pub fn compute_epoch_rewards(total_supply: u64) -> EpochRewards {
    // Total to mint this epoch
    let epoch_total = total_supply
        .saturating_mul(INFLATION_RATE_BPS as u64)
        / 10_000
        / EPOCHS_PER_YEAR;

    // Split by allocation shares
    let validator_pool  = epoch_total.saturating_mul(VALIDATOR_POOL_SHARE_BPS as u64) / 10_000;
    let treasury_amount = epoch_total.saturating_mul(TREASURY_SHARE_BPS as u64) / 10_000;
    let burn_amount     = epoch_total.saturating_mul(BURN_BUFFER_SHARE_BPS as u64) / 10_000;

    EpochRewards { validator_pool, treasury_amount, burn_amount }
}

/// Distribute the validator pool proportionally to active validators by stake.
///
/// Each validator receives: pool × their_stake / total_active_stake
/// Rounding: floor. Remainder stays in treasury.
fn distribute_validator_rewards(
    state: &mut ChainState,
    validator_pool: u64,
    current_epoch: u64,
) {
    let total_stake = state.validators.total_active_stake();
    if total_stake == 0 || validator_pool == 0 {
        // No active validators or no rewards: add pool to treasury
        state.treasury_balance = state.treasury_balance.saturating_add(validator_pool);
        return;
    }

    // Collect IDs and stakes first to avoid borrow issues
    let active: Vec<(indra_core::types::primitives::Bytes32, u64)> = state
        .validators
        .active_validators()
        .map(|v| (v.validator_id, v.stake_spark))
        .collect();

    let mut distributed: u64 = 0;

    for (id, stake) in &active {
        let reward = validator_pool
            .saturating_mul(*stake)
            / total_stake;

        // Split reward: commission to validator, rest to delegators
        let commission_bps = state.validators.get(id)
            .map(|v| v.commission_bps)
            .unwrap_or(1_000);

        let delegated = state.delegations.total_delegated(id);
        let validator_self_reward;
        let delegator_pool;

        if delegated == 0 {
            // No delegators — validator keeps all
            validator_self_reward = reward;
            delegator_pool = 0;
        } else {
            // Commission fraction goes to validator
            let commission = reward.saturating_mul(commission_bps as u64) / 10_000;
            validator_self_reward = commission;
            delegator_pool = reward.saturating_sub(commission);
        }

        if let Some(entry) = state.validators.get_mut(id) {
            entry.pending_rewards = entry.pending_rewards.saturating_add(validator_self_reward);
            entry.rewards_last_epoch = current_epoch;
            distributed = distributed.saturating_add(validator_self_reward);
        }

        // Distribute delegator pool proportionally
        let remainder_delegators = state.delegations.distribute_rewards(id, delegator_pool, current_epoch);
        distributed = distributed.saturating_add(delegator_pool.saturating_sub(remainder_delegators));
        // Delegator remainder back to treasury
        state.treasury_balance = state.treasury_balance.saturating_add(remainder_delegators);
    }

    // Remainder (due to floor division) goes to treasury
    let remainder = validator_pool.saturating_sub(distributed);
    state.treasury_balance = state.treasury_balance.saturating_add(remainder);
}

/// Release validators whose unbonding period has ended.
fn release_unbonded_validators(state: &mut ChainState, current_epoch: u64) {
    let ids: Vec<indra_core::types::primitives::Bytes32> = state
        .validators
        .all_validators()
        .filter(|v| matches!(
            v.status,
            ValidatorStatus::Unbonding { unbonding_end_epoch }
            if unbonding_end_epoch <= current_epoch
        ))
        .map(|v| v.validator_id)
        .collect();

    for id in ids {
        if let Some(entry) = state.validators.get_mut(&id) {
            // Stake is returned to the validator's UTXO set entry
            // (in Phase 3 this triggers a UTXO creation)
            // For now, mark as fully exited by setting stake to 0
            entry.stake_spark = 0;
            entry.status = ValidatorStatus::Slashed; // reuse Slashed as "exited"
        }
    }
}

/// True if the given height is the last block of an epoch.
pub fn is_epoch_boundary(height: u64) -> bool {
    height > 0 && height % EPOCH_DURATION_BLOCKS == 0
}

/// Epoch number for a given height (0-indexed).
pub fn epoch_for_height(height: u64) -> u64 {
    height / EPOCH_DURATION_BLOCKS
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::primitives::{GENESIS_SUPPLY_SPARK, EPOCH_DURATION_BLOCKS};

    #[test]
    fn epoch_boundary_detection() {
        assert!(!is_epoch_boundary(0));
        assert!(!is_epoch_boundary(1));
        assert!(!is_epoch_boundary(299));
        assert!(is_epoch_boundary(300));
        assert!(!is_epoch_boundary(301));
        assert!(is_epoch_boundary(600));
    }

    #[test]
    fn epoch_for_height_correct() {
        assert_eq!(epoch_for_height(0), 0);
        assert_eq!(epoch_for_height(299), 0);
        assert_eq!(epoch_for_height(300), 1);
        assert_eq!(epoch_for_height(599), 1);
        assert_eq!(epoch_for_height(600), 2);
    }

    #[test]
    fn epoch_rewards_nonzero_for_genesis_supply() {
        let r = compute_epoch_rewards(GENESIS_SUPPLY_SPARK);
        assert!(r.validator_pool > 0);
        assert!(r.treasury_amount > 0);
        assert!(r.burn_amount > 0);
    }

    #[test]
    fn epoch_rewards_allocation_consistent() {
        let r = compute_epoch_rewards(GENESIS_SUPPLY_SPARK);
        let total = r.validator_pool + r.treasury_amount + r.burn_amount;
        // Total distributed must be ≤ the computed epoch_total (floor rounding)
        let epoch_total = GENESIS_SUPPLY_SPARK
            .saturating_mul(INFLATION_RATE_BPS as u64)
            / 10_000
            / EPOCHS_PER_YEAR;
        assert!(total <= epoch_total);
        // And must be close (within 3 Spark of rounding losses)
        assert!(epoch_total - total <= 3);
    }

    #[test]
    fn rewards_zero_for_zero_supply() {
        let r = compute_epoch_rewards(0);
        assert_eq!(r.validator_pool, 0);
        assert_eq!(r.treasury_amount, 0);
        assert_eq!(r.burn_amount, 0);
    }

    #[test]
    fn epoch_transition_increases_treasury() {
        let mut state = crate::chain::ChainState::new_genesis();
        let initial_treasury = state.treasury_balance;
        apply_epoch_transition(&mut state, 1).unwrap();
        assert!(state.treasury_balance >= initial_treasury);
    }

    #[test]
    fn epoch_transition_increases_supply() {
        let mut state = crate::chain::ChainState::new_genesis();
        let initial_supply = state.total_supply;
        apply_epoch_transition(&mut state, 1).unwrap();
        assert!(state.total_supply > initial_supply);
    }

    #[test]
    fn epoch_transition_is_deterministic() {
        let mut s1 = crate::chain::ChainState::new_genesis();
        let mut s2 = crate::chain::ChainState::new_genesis();
        apply_epoch_transition(&mut s1, 1).unwrap();
        apply_epoch_transition(&mut s2, 1).unwrap();
        assert_eq!(s1.total_supply, s2.total_supply);
        assert_eq!(s1.treasury_balance, s2.treasury_balance);
    }
}
