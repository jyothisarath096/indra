//! Issuance schedule and canonical monetary accounting types.

use crypto_bigint::{CheckedAdd, CheckedSub, NonZero, U256};
use indra_core::{
    codec::{ByteReader, Decode, Encode},
    error::IndraResult,
    types::primitives::{
        ERA_1_2_DURATION_BLOCKS, ERA_3_PLUS_DURATION_BLOCKS, LIFETIME_SUPPLY_CAP_SPARK,
    },
};

use crate::error::{StateError, StateResult};

/// Closed classification of all supply-destroying transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BurnSourceV1 {
    /// Burned transaction-fee share.
    TransactionFee = 1,
    /// Burned validator principal, including unpaid reporter dust.
    ValidatorSlash = 2,
    /// Burned governance proposal escrow.
    GovernanceDeposit = 3,
}

/// Immutable and cumulative monetary audit ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonetaryLedgerV1 {
    /// Permanent protocol cap.
    pub lifetime_cap_spark: u64,
    /// Claims created at genesis.
    pub genesis_issued_spark: u64,
    /// Cap remaining for scheduled rewards after genesis.
    pub reward_budget_spark: u64,
    /// Cumulative scheduled rewards minted.
    pub cumulative_reward_minted_spark: u64,
    /// Cumulative fee burn.
    pub cumulative_fee_burned_spark: u64,
    /// Cumulative validator slash burn.
    pub cumulative_slash_burned_spark: u64,
    /// Cumulative governance escrow burn.
    pub cumulative_governance_burned_spark: u64,
    /// Rewards minted in the open epoch.
    pub epoch_reward_minted_spark: u64,
    /// Fees burned in the open epoch.
    pub epoch_fee_burned_spark: u64,
    /// Validator principal burned in the open epoch.
    pub epoch_slash_burned_spark: u64,
    /// Governance escrow burned in the open epoch.
    pub epoch_governance_burned_spark: u64,
}

impl MonetaryLedgerV1 {
    /// Construct the pristine pre-finalization genesis ledger.
    pub const fn empty_genesis() -> Self {
        Self {
            lifetime_cap_spark: LIFETIME_SUPPLY_CAP_SPARK,
            genesis_issued_spark: 0,
            reward_budget_spark: LIFETIME_SUPPLY_CAP_SPARK,
            cumulative_reward_minted_spark: 0,
            cumulative_fee_burned_spark: 0,
            cumulative_slash_burned_spark: 0,
            cumulative_governance_burned_spark: 0,
            epoch_reward_minted_spark: 0,
            epoch_fee_burned_spark: 0,
            epoch_slash_burned_spark: 0,
            epoch_governance_burned_spark: 0,
        }
    }

    /// Construct the genesis ledger from real genesis claims.
    pub fn genesis(genesis_issued_spark: u64) -> StateResult<Self> {
        let reward_budget_spark = LIFETIME_SUPPLY_CAP_SPARK
            .checked_sub(genesis_issued_spark)
            .ok_or(StateError::ValueOverflow)?;
        Ok(Self {
            reward_budget_spark,
            ..Self::empty_genesis()
        }
        .with_genesis_issued(genesis_issued_spark))
    }

    const fn with_genesis_issued(mut self, genesis_issued_spark: u64) -> Self {
        self.genesis_issued_spark = genesis_issued_spark;
        self
    }

    /// Checked total of all cumulative burn sources.
    pub fn cumulative_burned_spark(&self) -> StateResult<u64> {
        self.cumulative_fee_burned_spark
            .checked_add(self.cumulative_slash_burned_spark)
            .and_then(|v| v.checked_add(self.cumulative_governance_burned_spark))
            .ok_or(StateError::ValueOverflow)
    }

    /// Supply independently implied by issuance and burns.
    pub fn audited_supply(&self) -> StateResult<u64> {
        self.genesis_issued_spark
            .checked_add(self.cumulative_reward_minted_spark)
            .and_then(|v| v.checked_sub(self.cumulative_burned_spark().ok()?))
            .ok_or(StateError::ValueOverflow)
    }

    /// Validate immutable, cap, budget, and supply identities.
    pub fn validate(&self, total_supply: u64) -> StateResult<()> {
        if self.lifetime_cap_spark != LIFETIME_SUPPLY_CAP_SPARK
            || self.reward_budget_spark
                != self
                    .lifetime_cap_spark
                    .checked_sub(self.genesis_issued_spark)
                    .ok_or(StateError::ValueOverflow)?
            || self.cumulative_reward_minted_spark > self.reward_budget_spark
            || total_supply > self.lifetime_cap_spark
            || self.audited_supply()? != total_supply
        {
            return Err(StateError::InvariantViolation {
                message: "monetary ledger identity mismatch",
            });
        }
        Ok(())
    }
}

impl Encode for MonetaryLedgerV1 {
    fn encode(&self, out: &mut Vec<u8>) {
        for value in [
            self.lifetime_cap_spark,
            self.genesis_issued_spark,
            self.reward_budget_spark,
            self.cumulative_reward_minted_spark,
            self.cumulative_fee_burned_spark,
            self.cumulative_slash_burned_spark,
            self.cumulative_governance_burned_spark,
            self.epoch_reward_minted_spark,
            self.epoch_fee_burned_spark,
            self.epoch_slash_burned_spark,
            self.epoch_governance_burned_spark,
        ] {
            value.encode(out);
        }
    }

    fn encoded_len(&self) -> usize {
        11 * 8
    }
}

impl Decode for MonetaryLedgerV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            lifetime_cap_spark: u64::decode(r)?,
            genesis_issued_spark: u64::decode(r)?,
            reward_budget_spark: u64::decode(r)?,
            cumulative_reward_minted_spark: u64::decode(r)?,
            cumulative_fee_burned_spark: u64::decode(r)?,
            cumulative_slash_burned_spark: u64::decode(r)?,
            cumulative_governance_burned_spark: u64::decode(r)?,
            epoch_reward_minted_spark: u64::decode(r)?,
            epoch_fee_burned_spark: u64::decode(r)?,
            epoch_slash_burned_spark: u64::decode(r)?,
            epoch_governance_burned_spark: u64::decode(r)?,
        })
    }
}

/// State-root-committed totals for all authoritative value-bearing stores.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MonetaryAggregatesV1 {
    /// Unspent outputs.
    pub utxo_value_spark: u64,
    /// Active stake principal.
    pub active_principal_spark: u64,
    /// Unbonding tranche principal.
    pub unbonding_principal_spark: u64,
    /// Pending staking rewards.
    pub pending_rewards_spark: u64,
    /// Governance deposit escrow.
    pub governance_escrow_spark: u64,
    /// Fee rewards awaiting distribution.
    pub fee_reward_pool_spark: u64,
}

impl MonetaryAggregatesV1 {
    /// Checked total of all real claims.
    pub fn total_claims_spark(&self) -> StateResult<u64> {
        [
            self.utxo_value_spark,
            self.active_principal_spark,
            self.unbonding_principal_spark,
            self.pending_rewards_spark,
            self.governance_escrow_spark,
            self.fee_reward_pool_spark,
        ]
        .into_iter()
        .try_fold(0u64, |sum, v| {
            sum.checked_add(v).ok_or(StateError::ValueOverflow)
        })
    }
}

impl Encode for MonetaryAggregatesV1 {
    fn encode(&self, out: &mut Vec<u8>) {
        for value in [
            self.utxo_value_spark,
            self.active_principal_spark,
            self.unbonding_principal_spark,
            self.pending_rewards_spark,
            self.governance_escrow_spark,
            self.fee_reward_pool_spark,
        ] {
            value.encode(out);
        }
    }

    fn encoded_len(&self) -> usize {
        6 * 8
    }
}

impl Decode for MonetaryAggregatesV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            utxo_value_spark: u64::decode(r)?,
            active_principal_spark: u64::decode(r)?,
            unbonding_principal_spark: u64::decode(r)?,
            pending_rewards_spark: u64::decode(r)?,
            governance_escrow_spark: u64::decode(r)?,
            fee_reward_pool_spark: u64::decode(r)?,
        })
    }
}

/// Internal proof that one transition balances claims against mint/burn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MonetaryDeltaV1 {
    claims_created_spark: u64,
    claims_destroyed_spark: u64,
    minted_spark: u64,
    burned_spark: u64,
    burn_source: Option<BurnSourceV1>,
}

impl MonetaryDeltaV1 {
    pub(crate) fn reward_mint(amount: u64) -> StateResult<Self> {
        Self {
            claims_created_spark: amount,
            claims_destroyed_spark: 0,
            minted_spark: amount,
            burned_spark: 0,
            burn_source: None,
        }
        .checked()
    }

    pub(crate) fn burn(amount: u64, source: BurnSourceV1) -> StateResult<Self> {
        Self {
            claims_created_spark: 0,
            claims_destroyed_spark: amount,
            minted_spark: 0,
            burned_spark: amount,
            burn_source: (amount != 0).then_some(source),
        }
        .checked()
    }

    pub(crate) fn split_burn(
        gross_destroyed: u64,
        transferred: u64,
        burned: u64,
        source: BurnSourceV1,
    ) -> StateResult<Self> {
        Self {
            claims_created_spark: transferred,
            claims_destroyed_spark: gross_destroyed,
            minted_spark: 0,
            burned_spark: burned,
            burn_source: (burned != 0).then_some(source),
        }
        .checked()
    }

    fn checked(self) -> StateResult<Self> {
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn validate(self) -> StateResult<()> {
        let left = self
            .claims_created_spark
            .checked_add(self.burned_spark)
            .ok_or(StateError::ValueOverflow)?;
        let right = self
            .claims_destroyed_spark
            .checked_add(self.minted_spark)
            .ok_or(StateError::ValueOverflow)?;
        if left != right || (self.burned_spark != 0) != self.burn_source.is_some() {
            return Err(StateError::InvariantViolation {
                message: "unbalanced monetary transition",
            });
        }
        Ok(())
    }
}

fn add(a: U256, b: U256) -> StateResult<U256> {
    Option::from(a.checked_add(&b)).ok_or(StateError::ValueOverflow)
}

fn mul(a: U256, b: U256) -> StateResult<U256> {
    Option::from(a.checked_mul(&b)).ok_or(StateError::ValueOverflow)
}

fn as_u64(value: U256) -> StateResult<u64> {
    if value > U256::from(u64::MAX) {
        return Err(StateError::ValueOverflow);
    }
    value
        .as_words()
        .first()
        .copied()
        .ok_or(StateError::ValueOverflow)
}

fn div(numerator: U256, denominator: U256) -> StateResult<U256> {
    let denominator = Option::<NonZero<U256>>::from(NonZero::new(denominator)).ok_or(
        StateError::InvariantViolation {
            message: "zero monetary schedule denominator",
        },
    )?;
    Ok(numerator / denominator)
}

fn round_half_up(numerator: U256, denominator: U256) -> StateResult<U256> {
    div(
        add(mul(numerator, U256::from(2u8))?, denominator)?,
        mul(denominator, U256::from(2u8))?,
    )
}

/// Exact cumulative target after the named era.
pub fn cumulative_reward_target_after_era(budget: u64, era: u64) -> StateResult<u64> {
    if budget > LIFETIME_SUPPLY_CAP_SPARK {
        return Err(StateError::InvariantViolation {
            message: "reward budget exceeds lifetime cap",
        });
    }
    if era == 0 || budget == 0 {
        return Ok(0);
    }
    let budget = U256::from(budget);
    let (factor, denominator) = match era {
        1 => (U256::from(2u8), U256::from(5u8)),
        2 => (U256::from(3u8), U256::from(5u8)),
        _ => {
            let shift = era.checked_sub(3).ok_or(StateError::ValueOverflow)?;
            if shift >= 256 {
                return as_u64(budget);
            }
            let power =
                U256::ONE << usize::try_from(shift).map_err(|_| StateError::ValueOverflow)?;
            let denominator = mul(U256::from(5u8), power)?;
            let factor = Option::from(denominator.checked_sub(&U256::ONE))
                .ok_or(StateError::ValueOverflow)?;
            (factor, denominator)
        }
    };
    as_u64(round_half_up(mul(budget, factor)?, denominator)?)
}

/// Return `(era, one_based_offset, duration)` for a rewarded height.
pub fn issuance_era_and_offset(height: u64) -> StateResult<(u64, u64, u64)> {
    if height == 0 {
        return Err(StateError::InvariantViolation {
            message: "genesis has no scheduled reward",
        });
    }
    if height <= ERA_1_2_DURATION_BLOCKS {
        return Ok((1, height, ERA_1_2_DURATION_BLOCKS));
    }
    let era_two_end = ERA_1_2_DURATION_BLOCKS
        .checked_mul(2)
        .ok_or(StateError::ValueOverflow)?;
    if height <= era_two_end {
        return Ok((
            2,
            height
                .checked_sub(ERA_1_2_DURATION_BLOCKS)
                .ok_or(StateError::ValueOverflow)?,
            ERA_1_2_DURATION_BLOCKS,
        ));
    }
    let after = height
        .checked_sub(era_two_end)
        .and_then(|v| v.checked_sub(1))
        .ok_or(StateError::ValueOverflow)?;
    let era = 3u64
        .checked_add(after / ERA_3_PLUS_DURATION_BLOCKS)
        .ok_or(StateError::ValueOverflow)?;
    let offset = (after % ERA_3_PLUS_DURATION_BLOCKS)
        .checked_add(1)
        .ok_or(StateError::ValueOverflow)?;
    Ok((era, offset, ERA_3_PLUS_DURATION_BLOCKS))
}

/// Exact cumulative scheduled rewards after a height.
pub fn cumulative_reward_target_at_height(budget: u64, height: u64) -> StateResult<u64> {
    if height == 0 {
        return Ok(0);
    }
    let (era, offset, duration) = issuance_era_and_offset(height)?;
    let prior = cumulative_reward_target_after_era(
        budget,
        era.checked_sub(1).ok_or(StateError::ValueOverflow)?,
    )?;
    let end = cumulative_reward_target_after_era(budget, era)?;
    let allocation = end.checked_sub(prior).ok_or(StateError::ValueOverflow)?;
    let within = as_u64(div(
        mul(U256::from(offset), U256::from(allocation))?,
        U256::from(duration),
    )?)?;
    prior.checked_add(within).ok_or(StateError::ValueOverflow)
}

/// Exact reward earned by one finalized block.
pub fn block_reward_for_budget(budget: u64, height: u64) -> StateResult<u64> {
    if height == 0 {
        return Ok(0);
    }
    cumulative_reward_target_at_height(budget, height)?
        .checked_sub(cumulative_reward_target_at_height(budget, height - 1)?)
        .ok_or(StateError::ValueOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use num_traits::{One, ToPrimitive};

    fn oracle_after_era(budget: u64, era: u64) -> u64 {
        if era == 0 || budget == 0 {
            return 0;
        }
        let budget = BigUint::from(budget);
        let (factor, denominator) = match era {
            1 => (BigUint::from(2u8), BigUint::from(5u8)),
            2 => (BigUint::from(3u8), BigUint::from(5u8)),
            _ => {
                let denominator = BigUint::from(5u8) << usize::try_from(era - 3).unwrap();
                (denominator.clone() - BigUint::one(), denominator)
            }
        };
        let numerator = budget * factor;
        ((&numerator * 2u8 + &denominator) / (&denominator * 2u8))
            .to_u64()
            .unwrap()
    }

    #[test]
    fn exhaustive_small_budgets_are_exact() {
        for budget in 0..=9_999 {
            let mut prior = 0;
            for era in 1..=59 {
                let target = cumulative_reward_target_after_era(budget, era).unwrap();
                assert!(target >= prior && target <= budget);
                prior = target;
            }
            assert_eq!(prior, budget);
        }
    }

    #[test]
    fn maximum_budget_first_finishes_in_era_59() {
        assert!(
            cumulative_reward_target_after_era(LIFETIME_SUPPLY_CAP_SPARK, 58).unwrap()
                < LIFETIME_SUPPLY_CAP_SPARK
        );
        assert_eq!(
            cumulative_reward_target_after_era(LIFETIME_SUPPLY_CAP_SPARK, 59).unwrap(),
            LIFETIME_SUPPLY_CAP_SPARK
        );
    }

    #[test]
    fn eras_and_blocks_telescope_exactly() {
        for budget in [0, 1, 2, 9_999, LIFETIME_SUPPLY_CAP_SPARK] {
            let mut era_sum = 0u64;
            for era in 1..=59 {
                let prior = cumulative_reward_target_after_era(budget, era - 1).unwrap();
                let end = cumulative_reward_target_after_era(budget, era).unwrap();
                let allocation = end - prior;
                era_sum = era_sum.checked_add(allocation).unwrap();
                let duration = if era <= 2 {
                    ERA_1_2_DURATION_BLOCKS
                } else {
                    ERA_3_PLUS_DURATION_BLOCKS
                };
                let era_start = if era == 1 {
                    1
                } else if era == 2 {
                    ERA_1_2_DURATION_BLOCKS + 1
                } else {
                    ERA_1_2_DURATION_BLOCKS * 2 + (era - 3) * ERA_3_PLUS_DURATION_BLOCKS + 1
                };
                let era_end = era_start + duration - 1;
                assert_eq!(
                    cumulative_reward_target_at_height(budget, era_end).unwrap(),
                    end
                );
                assert_eq!(
                    cumulative_reward_target_at_height(budget, era_start - 1).unwrap(),
                    prior
                );
            }
            assert_eq!(era_sum, budget);
        }
    }

    #[test]
    fn adjacent_rewards_differ_by_at_most_one_and_boundaries_are_exact() {
        let budget = LIFETIME_SUPPLY_CAP_SPARK;
        for era in 1..=59 {
            let duration = if era <= 2 {
                ERA_1_2_DURATION_BLOCKS
            } else {
                ERA_3_PLUS_DURATION_BLOCKS
            };
            let start = if era == 1 {
                1
            } else if era == 2 {
                ERA_1_2_DURATION_BLOCKS + 1
            } else {
                ERA_1_2_DURATION_BLOCKS * 2 + (era - 3) * ERA_3_PLUS_DURATION_BLOCKS + 1
            };
            let samples = [start, start + 1, start + duration / 2, start + duration - 1];
            let rewards = samples.map(|height| block_reward_for_budget(budget, height).unwrap());
            let min = *rewards.iter().min().unwrap();
            let max = *rewards.iter().max().unwrap();
            assert!(max - min <= 1, "era {era}: {rewards:?}");
        }
        let first_zero_height = ERA_1_2_DURATION_BLOCKS * 2 + 57 * ERA_3_PLUS_DURATION_BLOCKS + 1;
        assert_eq!(
            block_reward_for_budget(budget, first_zero_height).unwrap(),
            0
        );
        assert_eq!(
            block_reward_for_budget(budget, first_zero_height + 1).unwrap(),
            0
        );
    }

    #[test]
    fn fixed_width_schedule_matches_independent_big_integer_oracle() {
        for budget in 0..=4_096 {
            for era in 0..=59 {
                assert_eq!(
                    cumulative_reward_target_after_era(budget, era).unwrap(),
                    oracle_after_era(budget, era),
                    "budget={budget}, era={era}"
                );
            }
        }
        let mut seed = 0xD1CE_BA5E_1234_5678u64;
        for _ in 0..10_000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let budget = seed % (LIFETIME_SUPPLY_CAP_SPARK + 1);
            let era = (seed >> 32) % 60;
            assert_eq!(
                cumulative_reward_target_after_era(budget, era).unwrap(),
                oracle_after_era(budget, era)
            );
        }
    }

    #[test]
    fn zero_budget_mints_zero_forever_and_over_cap_is_rejected() {
        for height in [0, 1, ERA_1_2_DURATION_BLOCKS, u64::MAX] {
            assert_eq!(cumulative_reward_target_at_height(0, height).unwrap(), 0);
            assert_eq!(block_reward_for_budget(0, height).unwrap(), 0);
        }
        assert!(cumulative_reward_target_after_era(LIFETIME_SUPPLY_CAP_SPARK + 1, 1).is_err());
    }
}
