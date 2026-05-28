//! Epoch transition logic — INDRA v7.1
//!
//! ## What happens at an epoch boundary
//!
//! 1. Compute block reward for current era (pre-minted supply, not inflation)
//! 2. Distribute block reward to active validators proportionally by stake
//!    with saturation-based anti-concentration adjustment
//! 3. Distribute accumulated fee rewards to validators
//! 4. Expire stale rewards
//! 5. Release unbonded validators
//!
//! ## Zero inflation guarantee
//!
//! `state.total_supply` never increases during an epoch transition.
//! Supply only decreases via the fee burn path in `apply.rs`.

use indra_core::types::primitives::{
    BLOCKS_PER_YEAR,
    EPOCH_DURATION_BLOCKS,
    ERA_1_2_DURATION_BLOCKS,
    ERA_3_BLOCK_REWARD_SPARK,
    ERA_3_PLUS_DURATION_BLOCKS,
    ERA_1_BLOCK_REWARD_SPARK,
    ERA_2_BLOCK_REWARD_SPARK,
    HARD_CAP_SPARK,
    TARGET_VALIDATOR_COUNT,
};

use crate::{
    chain::ChainState,
    error::StateResult,
    validator::ValidatorStatus,
};

/// Number of epochs per year (5,256,000 blocks/year / 300 blocks/epoch).
pub const EPOCHS_PER_YEAR: u64 = BLOCKS_PER_YEAR / EPOCH_DURATION_BLOCKS;

/// Apply the epoch transition to the chain state.
pub fn apply_epoch_transition(
    state: &mut ChainState,
    current_epoch: u64,
) -> StateResult<()> {
    let current_height = current_epoch.saturating_mul(EPOCH_DURATION_BLOCKS);
    let reward_per_block = block_reward_at_height(current_height);
    let epoch_block_reward = reward_per_block.saturating_mul(EPOCH_DURATION_BLOCKS);

    let supply_before = state.total_supply;
    distribute_block_rewards(state, epoch_block_reward, current_epoch);

    assert!(
        state.total_supply <= HARD_CAP_SPARK,
        "CRITICAL: Hard cap violated. supply={} cap={}",
        state.total_supply,
        HARD_CAP_SPARK
    );
    debug_assert_eq!(
        state.total_supply,
        supply_before,
        "supply changed during epoch transition"
    );

    distribute_fee_rewards(state, current_epoch);
    state.validators.expire_stale_rewards(current_epoch);
    release_unbonded_validators(state, current_epoch);

    Ok(())
}

/// Compute the block reward in Spark for a given block height.
pub fn block_reward_at_height(height: u64) -> u64 {
    if height < ERA_1_2_DURATION_BLOCKS {
        ERA_1_BLOCK_REWARD_SPARK
    } else if height < ERA_1_2_DURATION_BLOCKS.saturating_mul(2) {
        ERA_2_BLOCK_REWARD_SPARK
    } else {
        let era_3_start = ERA_1_2_DURATION_BLOCKS.saturating_mul(2);
        let blocks_since_era_3 = height.saturating_sub(era_3_start);
        let era_index = blocks_since_era_3 / ERA_3_PLUS_DURATION_BLOCKS;
        ERA_3_BLOCK_REWARD_SPARK >> era_index.min(63)
    }
}

fn saturation_adjusted_reward(
    raw_reward: u64,
    validator_stake: u64,
    total_active_stake: u64,
) -> u64 {
    if total_active_stake == 0 || TARGET_VALIDATOR_COUNT == 0 {
        return raw_reward;
    }

    let saturation_point = total_active_stake / TARGET_VALIDATOR_COUNT;
    if saturation_point == 0 || validator_stake <= saturation_point {
        return raw_reward;
    }

    raw_reward
        .saturating_mul(saturation_point)
        / validator_stake
}

fn distribute_block_rewards(
    state: &mut ChainState,
    epoch_block_reward: u64,
    current_epoch: u64,
) {
    let total_stake = state.validators.total_active_stake();
    if total_stake == 0 || epoch_block_reward == 0 {
        return;
    }

    let active: Vec<(indra_core::types::primitives::Bytes32, u64)> = state
        .validators
        .active_validators()
        .map(|v| (v.validator_id, v.stake_spark))
        .collect();

    for (id, stake) in &active {
        let raw_reward = epoch_block_reward.saturating_mul(*stake) / total_stake;
        let adjusted_reward = saturation_adjusted_reward(raw_reward, *stake, total_stake);

        let commission_bps = state
            .validators
            .get(id)
            .map(|v| v.commission_bps)
            .unwrap_or(1_000);
        let delegated = state.delegations.total_delegated(id);

        let (validator_share, delegator_pool) = if delegated == 0 {
            (adjusted_reward, 0)
        } else {
            let commission = adjusted_reward.saturating_mul(commission_bps as u64) / 10_000;
            (commission, adjusted_reward.saturating_sub(commission))
        };

        if let Some(entry) = state.validators.get_mut(id) {
            entry.pending_rewards = entry.pending_rewards.saturating_add(validator_share);
            entry.rewards_last_epoch = current_epoch;
        }

        let _remainder = state
            .delegations
            .distribute_rewards(id, delegator_pool, current_epoch);
    }
}

fn distribute_fee_rewards(
    state: &mut ChainState,
    current_epoch: u64,
) {
    let fee_pool = state.fee_reward_pool;
    if fee_pool == 0 {
        return;
    }

    let total_stake = state.validators.total_active_stake();
    if total_stake == 0 {
        return;
    }

    state.fee_reward_pool = 0;

    let active: Vec<(indra_core::types::primitives::Bytes32, u64)> = state
        .validators
        .active_validators()
        .map(|v| (v.validator_id, v.stake_spark))
        .collect();

    let mut distributed = 0u64;

    for (id, stake) in &active {
        let reward = fee_pool.saturating_mul(*stake) / total_stake;
        let commission_bps = state
            .validators
            .get(id)
            .map(|v| v.commission_bps)
            .unwrap_or(1_000);
        let delegated = state.delegations.total_delegated(id);

        let (validator_share, delegator_pool) = if delegated == 0 {
            (reward, 0)
        } else {
            let commission = reward.saturating_mul(commission_bps as u64) / 10_000;
            (commission, reward.saturating_sub(commission))
        };

        if let Some(entry) = state.validators.get_mut(id) {
            entry.pending_rewards = entry.pending_rewards.saturating_add(validator_share);
            entry.rewards_last_epoch = current_epoch;
            distributed = distributed.saturating_add(validator_share);
        }

        let remainder = state
            .delegations
            .distribute_rewards(id, delegator_pool, current_epoch);
        distributed = distributed
            .saturating_add(delegator_pool.saturating_sub(remainder));
    }

    let remainder = fee_pool.saturating_sub(distributed);
    state.fee_reward_pool = state.fee_reward_pool.saturating_add(remainder);
}

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
            entry.stake_spark = 0;
            entry.status = ValidatorStatus::Exited;
        }
    }
}

/// True if the given height is the last block of an epoch.
pub fn is_epoch_boundary(height: u64) -> bool {
    height > 0 && height.is_multiple_of(EPOCH_DURATION_BLOCKS)
}

/// Epoch number for a given height (0-indexed).
pub fn epoch_for_height(height: u64) -> u64 {
    height / EPOCH_DURATION_BLOCKS
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::primitives::{
        ERA_1_2_DURATION_BLOCKS,
        ERA_1_BLOCK_REWARD_SPARK,
        ERA_2_BLOCK_REWARD_SPARK,
        ERA_3_BLOCK_REWARD_SPARK,
        ERA_3_PLUS_DURATION_BLOCKS,
    };

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
        assert_eq!(epoch_for_height(600), 2);
    }

    #[test]
    fn block_reward_era_1() {
        assert_eq!(block_reward_at_height(0), ERA_1_BLOCK_REWARD_SPARK);
        assert_eq!(block_reward_at_height(1_000_000), ERA_1_BLOCK_REWARD_SPARK);
        assert_eq!(
            block_reward_at_height(ERA_1_2_DURATION_BLOCKS - 1),
            ERA_1_BLOCK_REWARD_SPARK
        );
    }

    #[test]
    fn block_reward_era_2() {
        assert_eq!(
            block_reward_at_height(ERA_1_2_DURATION_BLOCKS),
            ERA_2_BLOCK_REWARD_SPARK
        );
        assert_eq!(ERA_2_BLOCK_REWARD_SPARK, ERA_1_BLOCK_REWARD_SPARK / 2);
    }

    #[test]
    fn block_reward_era_3() {
        let era_3_start = ERA_1_2_DURATION_BLOCKS * 2;
        assert_eq!(block_reward_at_height(era_3_start), ERA_3_BLOCK_REWARD_SPARK);
        assert_eq!(ERA_3_BLOCK_REWARD_SPARK, ERA_2_BLOCK_REWARD_SPARK / 2);
    }

    #[test]
    fn block_reward_halves_each_era() {
        let r1 = block_reward_at_height(0);
        let r2 = block_reward_at_height(ERA_1_2_DURATION_BLOCKS);
        let era_3_start = ERA_1_2_DURATION_BLOCKS * 2;
        let r3 = block_reward_at_height(era_3_start);
        let r4 = block_reward_at_height(era_3_start + ERA_3_PLUS_DURATION_BLOCKS);
        assert_eq!(r2, r1 / 2);
        assert_eq!(r3, r2 / 2);
        assert_eq!(r4, r3 / 2);
    }

    #[test]
    fn saturation_below_point_full_reward() {
        let reward = saturation_adjusted_reward(1_000_000, 100, 200_000);
        assert_eq!(reward, 1_000_000);
    }

    #[test]
    fn saturation_above_point_reduced_reward() {
        let reward = saturation_adjusted_reward(1_000_000, 2_000, 200_000);
        assert_eq!(reward, 500_000);
    }

    #[test]
    fn saturation_at_point_full_reward() {
        let reward = saturation_adjusted_reward(1_000_000, 1_000, 200_000);
        assert_eq!(reward, 1_000_000);
    }

    #[test]
    fn epoch_transition_does_not_increase_supply() {
        let mut state = crate::chain::ChainState::new_genesis();
        let supply_before = state.total_supply;
        apply_epoch_transition(&mut state, 1).unwrap();
        assert_eq!(state.total_supply, supply_before);
    }

    #[test]
    fn epoch_transition_does_not_increase_treasury() {
        let mut state = crate::chain::ChainState::new_genesis();
        let treasury_before = state.treasury_balance;
        apply_epoch_transition(&mut state, 1).unwrap();
        assert_eq!(state.treasury_balance, treasury_before);
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
