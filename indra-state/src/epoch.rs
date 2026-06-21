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
    Bytes32, BLOCKS_PER_YEAR, EPOCH_DURATION_BLOCKS, ERA_1_2_DURATION_BLOCKS,
    ERA_1_BLOCK_REWARD_SPARK, ERA_2_BLOCK_REWARD_SPARK, ERA_3_BLOCK_REWARD_SPARK,
    ERA_3_PLUS_DURATION_BLOCKS, HARD_CAP_SPARK, SATURATION_MIN_VALIDATORS, STAKING_TX_IDX,
};

use crate::{chain::ChainState, error::StateResult, validator::ValidatorStatus};

/// Number of epochs per year (5,256,000 blocks/year / 300 blocks/epoch).
pub const EPOCHS_PER_YEAR: u64 = BLOCKS_PER_YEAR / EPOCH_DURATION_BLOCKS;

/// Apply the epoch transition to the chain state.
pub fn apply_epoch_transition(state: &mut ChainState, current_epoch: u64) -> StateResult<()> {
    eprintln!(
        "[epoch] transition at height={} epoch={} validators={} total_stake={} fee_pool={}",
        state.height,
        current_epoch,
        state.validators.active_count(),
        state.validators.total_active_stake(),
        state.fee_reward_pool,
    );
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
        state.total_supply, supply_before,
        "supply changed during epoch transition"
    );

    distribute_fee_rewards(state, current_epoch);
    state.validators.expire_stale_rewards(current_epoch);
    release_unbonded_validators(state, current_epoch);
    release_unbonded_bonds(state, current_epoch)?;
    apply_liveness_penalties(state, current_epoch);
    let total_staked = state
        .validators
        .total_selectable_self_stake()
        .saturating_add(state.delegations.total_staked());
    state
        .validators
        .select_active_set(&state.delegations, total_staked);

    eprintln!(
        "[epoch] complete epoch={} total_supply={} treasury={}",
        current_epoch, state.total_supply, state.treasury_balance,
    );
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
    active_validator_count: u64,
) -> u64 {
    if total_active_stake == 0 || active_validator_count == 0 {
        return raw_reward;
    }

    if active_validator_count <= SATURATION_MIN_VALIDATORS {
        return raw_reward;
    }

    let saturation_point = total_active_stake / active_validator_count;
    if saturation_point == 0 || validator_stake <= saturation_point {
        return raw_reward;
    }

    raw_reward.saturating_mul(saturation_point) / validator_stake
}

fn distribute_block_rewards(state: &mut ChainState, epoch_block_reward: u64, current_epoch: u64) {
    let total_stake = state.validators.total_active_stake();
    if total_stake == 0 || epoch_block_reward == 0 {
        return;
    }

    let mut active: Vec<(indra_core::types::primitives::Bytes32, u64)> = state
        .validators
        .active_validators()
        .map(|v| (v.validator_id, v.stake_spark))
        .collect();
    active.sort_by_key(|(id, _)| id.0);
    let active_validator_count = active.len() as u64;

    for (id, stake) in &active {
        let raw_reward = epoch_block_reward.saturating_mul(*stake) / total_stake;
        let adjusted_reward =
            saturation_adjusted_reward(raw_reward, *stake, total_stake, active_validator_count);

        let commission_bps = state
            .validators
            .get(id)
            .map(|v| v.commission_bps)
            .unwrap_or(1_000);
        eprintln!(
            "[epoch] validator {} reward={} Spark commission={}bps",
            hex::encode(&id.0[..4]),
            adjusted_reward,
            commission_bps,
        );
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

fn distribute_fee_rewards(state: &mut ChainState, current_epoch: u64) {
    let fee_pool = state.fee_reward_pool;
    if fee_pool == 0 {
        return;
    }

    let total_stake = state.validators.total_active_stake();
    if total_stake == 0 {
        return;
    }

    state.fee_reward_pool = 0;

    let mut active: Vec<(indra_core::types::primitives::Bytes32, u64)> = state
        .validators
        .active_validators()
        .map(|v| (v.validator_id, v.stake_spark))
        .collect();
    active.sort_by_key(|(id, _)| id.0);

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
        distributed = distributed.saturating_add(delegator_pool.saturating_sub(remainder));
    }

    let remainder = fee_pool.saturating_sub(distributed);
    state.fee_reward_pool = state.fee_reward_pool.saturating_add(remainder);
}

fn release_unbonded_validators(state: &mut ChainState, current_epoch: u64) {
    let mut ids: Vec<indra_core::types::primitives::Bytes32> = state
        .validators
        .all_validators()
        .filter(|v| {
            matches!(
                v.status,
                ValidatorStatus::Unbonding { unbonding_end_epoch }
                if unbonding_end_epoch <= current_epoch
            )
        })
        .map(|v| v.validator_id)
        .collect();
    ids.sort_by_key(|id| id.0);

    for id in ids {
        if let Some(entry) = state.validators.get_mut(&id) {
            entry.stake_spark = 0;
            entry.status = ValidatorStatus::Exited;
        }
    }
}

fn release_unbonded_bonds(state: &mut ChainState, current_epoch: u64) -> StateResult<()> {
    let mut to_release: Vec<Bytes32> = state
        .staked_bonds
        .values()
        .filter(|bond| {
            bond.unbonding_end_epoch
                .map(|end| end <= current_epoch)
                .unwrap_or(false)
        })
        .map(|bond| bond.utxo_id)
        .collect();
    to_release.sort_by_key(|id| id.0);

    let release_height = current_epoch.saturating_mul(EPOCH_DURATION_BLOCKS);
    for (idx, utxo_id) in to_release.into_iter().enumerate() {
        if let Some(bond) = state.staked_bonds.remove(&utxo_id) {
            let output_index = u32::try_from(idx).unwrap_or(u32::MAX - 1).saturating_add(1);
            state
                .utxos
                .insert(
                    bond.original_output,
                    release_height,
                    STAKING_TX_IDX,
                    output_index,
                )
                .map_err(|_| crate::error::StateError::InvariantViolation {
                    message: "UTXO ID collision in staking bond release",
                })?;
        }
    }
    Ok(())
}

fn apply_liveness_penalties(state: &mut ChainState, current_epoch: u64) {
    use indra_core::types::primitives::{SLASH_LIVENESS_BPS, SLASH_LIVENESS_THRESHOLD_EPOCHS};

    let validator_ids: Vec<Bytes32> = state
        .validators
        .active_validators()
        .map(|v| v.validator_id)
        .collect();

    for validator_id in validator_ids {
        let (missed, stake) = {
            let v = match state.validators.get(&validator_id) {
                Some(v) => v,
                None => continue,
            };
            let missed = current_epoch.saturating_sub(v.last_active_epoch);
            (missed, v.stake_spark)
        };

        if missed >= SLASH_LIVENESS_THRESHOLD_EPOCHS && stake > 0 {
            let penalty = stake
                .saturating_mul(SLASH_LIVENESS_BPS as u64)
                .saturating_div(10_000);
            if let Some(v) = state.validators.get_mut(&validator_id) {
                v.stake_spark = v.stake_spark.saturating_sub(penalty);
            }
            state.total_supply = state.total_supply.saturating_sub(penalty);
            eprintln!(
                "[liveness] validator {} missed {} epochs, penalty={} Spark burned",
                hex::encode(&validator_id.0[..4]),
                missed,
                penalty,
            );
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
    use crate::{
        compute_state_root,
        validator::{StakeBondEntry, ValidatorEntry, ValidatorStatus},
    };
    use indra_core::{
        types::{
            crypto::HybridPubKey,
            primitives::{
                Bytes32, VariableBytes, DEFAULT_COMMISSION_BPS, DUST_LIMIT_SPARK,
                ERA_1_2_DURATION_BLOCKS, ERA_1_BLOCK_REWARD_SPARK, ERA_2_BLOCK_REWARD_SPARK,
                ERA_3_BLOCK_REWARD_SPARK, ERA_3_PLUS_DURATION_BLOCKS,
            },
            transaction::OutputV1,
        },
        CommitmentV1,
    };

    fn make_validator(id_byte: u8, stake: u64) -> ValidatorEntry {
        ValidatorEntry {
            validator_id: Bytes32::from([id_byte; 32]),
            name: format!("validator-{id_byte}"),
            hybrid_classical_pk: None,
            hybrid_pq_pk: None,
            vrf_pk: None,
            stake_spark: stake,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            pending_rewards: 0,
            rewards_last_epoch: 0,
            self_report_count: 0,
            commission_bps: DEFAULT_COMMISSION_BPS,
            min_delegation_spark: DUST_LIMIT_SPARK,
        }
    }

    fn dummy_output(byte: u8) -> OutputV1 {
        OutputV1 {
            value_spark: 1_000_000,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from([byte; 32]),
            },
            owner_pubkey: HybridPubKey {
                classical_pk: Bytes32::from([byte; 32]),
                pq_pk: VariableBytes::from_slice(&[byte; 32]).unwrap(),
            },
            range_proof: VariableBytes::from_slice(&[byte; 32]).unwrap(),
            lock_height: 0,
        }
    }

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
        assert_eq!(
            block_reward_at_height(era_3_start),
            ERA_3_BLOCK_REWARD_SPARK
        );
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
        let reward = saturation_adjusted_reward(1_000_000, 100, 200_000, 200);
        assert_eq!(reward, 1_000_000);
    }

    #[test]
    fn saturation_above_point_reduced_reward() {
        let reward = saturation_adjusted_reward(1_000_000, 2_000, 200_000, 200);
        assert_eq!(reward, 500_000);
    }

    #[test]
    fn saturation_at_point_full_reward() {
        let reward = saturation_adjusted_reward(1_000_000, 1_000, 200_000, 200);
        assert_eq!(reward, 1_000_000);
    }

    #[test]
    fn saturation_disabled_for_small_validator_sets() {
        let reward = saturation_adjusted_reward(1_000_000, 50_000, 200_000, 20);
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
    fn liveness_penalty_applied_after_threshold() {
        let mut state = crate::chain::ChainState::new_genesis();
        let validator = make_validator(0x91, 1_000_000);
        let validator_id = validator.validator_id;
        state.validators.upsert(validator).unwrap();
        apply_epoch_transition(&mut state, 3).unwrap();
        assert_eq!(
            state.validators.get(&validator_id).unwrap().stake_spark,
            999_000
        );
    }

    #[test]
    fn liveness_no_penalty_within_threshold() {
        let mut state = crate::chain::ChainState::new_genesis();
        let validator = make_validator(0x92, 1_000_000);
        let validator_id = validator.validator_id;
        state.validators.upsert(validator).unwrap();
        apply_epoch_transition(&mut state, 2).unwrap();
        assert_eq!(
            state.validators.get(&validator_id).unwrap().stake_spark,
            1_000_000
        );
    }

    #[test]
    fn liveness_penalty_burns_supply() {
        let mut state = crate::chain::ChainState::new_genesis();
        state
            .validators
            .upsert(make_validator(0x93, 1_000_000))
            .unwrap();
        let supply_before = state.total_supply;
        apply_epoch_transition(&mut state, 3).unwrap();
        assert_eq!(state.total_supply, supply_before - 1_000);
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

    #[test]
    fn epoch_transition_is_order_independent() {
        let validators = [
            make_validator(0x01, 1_000_000),
            make_validator(0x02, 2_000_000),
            make_validator(0x03, 3_000_000),
            make_validator(0x04, 4_000_000),
        ];

        let mut s1 = crate::chain::ChainState::new_genesis();
        let mut s2 = crate::chain::ChainState::new_genesis();
        s1.fee_reward_pool = 123_456;
        s2.fee_reward_pool = 123_456;

        for validator in validators.iter().cloned() {
            s1.validators.upsert(validator).unwrap();
        }
        for validator in validators.iter().cloned().rev() {
            s2.validators.upsert(validator).unwrap();
        }

        apply_epoch_transition(&mut s1, 1).unwrap();
        apply_epoch_transition(&mut s2, 1).unwrap();

        for validator in validators {
            let id = validator.validator_id;
            assert_eq!(
                s1.validators.get(&id).unwrap().pending_rewards,
                s2.validators.get(&id).unwrap().pending_rewards
            );
            assert_eq!(
                s1.validators.get(&id).unwrap().status,
                s2.validators.get(&id).unwrap().status
            );
        }

        assert_eq!(compute_state_root(&s1), compute_state_root(&s2));
    }

    #[test]
    fn unbonded_bonds_released_to_utxo_set() {
        let mut state = crate::chain::ChainState::new_genesis();
        let utxo_id = Bytes32::from([0xAB; 32]);
        state.staked_bonds.insert(
            utxo_id,
            StakeBondEntry {
                utxo_id,
                validator_id: Bytes32::from([0x01; 32]),
                delegator_id: Bytes32::from([0x02; 32]),
                amount_spark: 1_000_000,
                bonded_epoch: 0,
                unbonding_end_epoch: Some(1),
                original_output: dummy_output(0x44),
            },
        );

        apply_epoch_transition(&mut state, 1).unwrap();

        assert!(state.staked_bonds.is_empty());
        assert_eq!(state.utxos.len(), 1);
    }

    #[test]
    fn active_bonds_not_released_early() {
        let mut state = crate::chain::ChainState::new_genesis();
        let utxo_id = Bytes32::from([0xAC; 32]);
        state.staked_bonds.insert(
            utxo_id,
            StakeBondEntry {
                utxo_id,
                validator_id: Bytes32::from([0x01; 32]),
                delegator_id: Bytes32::from([0x02; 32]),
                amount_spark: 1_000_000,
                bonded_epoch: 0,
                unbonding_end_epoch: None,
                original_output: dummy_output(0x45),
            },
        );

        apply_epoch_transition(&mut state, 1).unwrap();

        assert!(state.staked_bonds.contains_key(&utxo_id));
        assert!(state.utxos.is_empty());
    }
}
