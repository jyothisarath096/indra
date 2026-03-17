//! EIP-1559 style base fee update formula.
//!
//! Applied at the end of every block to set the base fee for the next block.
//!
//! ## Formula (Spec Section F3)
//!
//!   utilisation = block_tx_count / MAX_TX_PER_BLOCK
//!   delta       = utilisation - TARGET (50%)
//!
//!   if utilisation > TARGET:
//!     new_fee = old_fee + old_fee × κ × delta / TARGET
//!   else:
//!     new_fee = old_fee - old_fee × κ × |delta| / TARGET
//!
//! Where κ = 125/1000 (0.125), TARGET = 50/100 (50%).
//!
//! ## Integer arithmetic
//!
//! All calculations use u64 integer arithmetic with explicit rounding.
//! Division always rounds down (floor). No floating point.
//! The fee is clamped to [MIN_BASE_FEE, u64::MAX] after each update.

use indra_core::types::primitives::{
    MAX_TX_PER_BLOCK,
    MIN_BASE_FEE_SPARK_PER_KB,
    FEE_ADJUST_NUMERATOR,
    FEE_ADJUST_DENOMINATOR,
    TARGET_UTILISATION_NUMERATOR,
    TARGET_UTILISATION_DENOMINATOR,
};

/// Compute the base fee for the next block given the current block's state.
///
/// Arguments:
/// - `current_base_fee`: the base fee that was in effect for this block (Spark/KB)
/// - `tx_count`: number of transactions included in this block
///
/// Returns the base fee to be recorded in the next block's header.
///
/// This function is pure: same inputs always produce the same output.
/// It never fails — the result is always clamped to a valid range.
pub fn compute_next_base_fee(current_base_fee: u64, tx_count: usize) -> u64 {
    let max_txs = MAX_TX_PER_BLOCK as u64;
    let count   = tx_count as u64;

    // target_count = MAX_TX_PER_BLOCK × TARGET_NUMERATOR / TARGET_DENOMINATOR
    // = 200 × 50 / 100 = 100 transactions
    let target_count = max_txs
        .saturating_mul(TARGET_UTILISATION_NUMERATOR)
        / TARGET_UTILISATION_DENOMINATOR;

    let new_fee = if count > target_count {
        // Above target: increase fee
        // delta = count - target_count
        // adjustment = current_fee × κ × delta / target_count
        let delta = count - target_count;
        let adjustment = current_base_fee
            .saturating_mul(FEE_ADJUST_NUMERATOR)
            .saturating_mul(delta)
            / FEE_ADJUST_DENOMINATOR
            / target_count.max(1);
        current_base_fee.saturating_add(adjustment)
    } else {
        // At or below target: decrease fee
        let delta = target_count - count;
        let adjustment = current_base_fee
            .saturating_mul(FEE_ADJUST_NUMERATOR)
            .saturating_mul(delta)
            / FEE_ADJUST_DENOMINATOR
            / target_count.max(1);
        current_base_fee.saturating_sub(adjustment)
    };

    // Clamp to minimum — fee can never go below MIN_BASE_FEE
    new_fee.max(MIN_BASE_FEE_SPARK_PER_KB)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::primitives::{
        INITIAL_BASE_FEE_SPARK_PER_KB, MIN_BASE_FEE_SPARK_PER_KB, MAX_TX_PER_BLOCK,
    };

    #[test]
    fn empty_block_decreases_fee() {
        let fee = compute_next_base_fee(INITIAL_BASE_FEE_SPARK_PER_KB, 0);
        assert!(fee < INITIAL_BASE_FEE_SPARK_PER_KB);
    }

    #[test]
    fn full_block_increases_fee() {
        let fee = compute_next_base_fee(INITIAL_BASE_FEE_SPARK_PER_KB, MAX_TX_PER_BLOCK);
        assert!(fee > INITIAL_BASE_FEE_SPARK_PER_KB);
    }

    #[test]
    fn target_block_keeps_fee_stable() {
        // Exactly at 50% utilisation (100 txs out of 200)
        let target = MAX_TX_PER_BLOCK / 2;
        let fee = compute_next_base_fee(INITIAL_BASE_FEE_SPARK_PER_KB, target);
        // At exact target, delta = 0, adjustment = 0, fee unchanged
        assert_eq!(fee, INITIAL_BASE_FEE_SPARK_PER_KB);
    }

    #[test]
    fn fee_never_below_minimum() {
        // Even with zero transactions and a very low starting fee
        let fee = compute_next_base_fee(MIN_BASE_FEE_SPARK_PER_KB, 0);
        assert!(fee >= MIN_BASE_FEE_SPARK_PER_KB);
    }

    #[test]
    fn fee_is_deterministic() {
        let f1 = compute_next_base_fee(100, 150);
        let f2 = compute_next_base_fee(100, 150);
        assert_eq!(f1, f2);
    }

    #[test]
    fn fee_increases_monotonically_with_load() {
        let low  = compute_next_base_fee(100, 110);
        let mid  = compute_next_base_fee(100, 150);
        let high = compute_next_base_fee(100, 200);
        assert!(low < mid);
        assert!(mid < high);
    }

    #[test]
    fn fee_decreases_monotonically_with_less_load() {
        let a = compute_next_base_fee(100, 90);
        let b = compute_next_base_fee(100, 50);
        let c = compute_next_base_fee(100, 0);
        assert!(a > b);
        assert!(b > c);
    }

    #[test]
    fn no_overflow_at_max_values() {
        // Should not panic
        let fee = compute_next_base_fee(u64::MAX / 2, MAX_TX_PER_BLOCK);
        assert!(fee >= MIN_BASE_FEE_SPARK_PER_KB);
    }
}
