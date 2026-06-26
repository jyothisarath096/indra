//! Mempool benchmarks.

use std::time::Duration;

use indra_consensus::mempool::{Mempool, MempoolConfig};
use indra_core::types::primitives::INITIAL_BASE_FEE_SPARK_PER_KB;

use crate::{fixtures::dummy_tx, timer::bench};

/// Benchmark submitting a single transaction to the mempool.
pub fn bench_mempool_submit(iterations: u64) {
    let r = bench("mempool_submit", iterations, || {
        let mut mp = Mempool::default_config();
        let tx = dummy_tx(0x01, INITIAL_BASE_FEE_SPARK_PER_KB * 100);
        let _ = mp.submit(tx, INITIAL_BASE_FEE_SPARK_PER_KB, 1);
    });
    r.print();
    r.assert_faster_than(Duration::from_micros(500));
}

/// Benchmark submitting N transactions to a mempool.
pub fn bench_mempool_fill(n: usize, iterations: u64) {
    let txs: Vec<_> = (0..n as u8)
        .map(|i| dummy_tx(i, INITIAL_BASE_FEE_SPARK_PER_KB * 100))
        .collect();

    let r = bench(&format!("mempool_fill_{n}"), iterations, || {
        let mut mp = Mempool::new(MempoolConfig {
            capacity: n + 100,
            min_fee_ratio_bps: 10_000,
        });
        for tx in &txs {
            let _ = mp.submit(tx.clone(), INITIAL_BASE_FEE_SPARK_PER_KB, 1);
        }
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(n as u64 / 10 + 5));
}

/// Benchmark selecting 200 transactions from a 5000-tx mempool.
pub fn bench_mempool_select(iterations: u64) {
    // Pre-fill a mempool with 200 unique txs (u8 nonce limit)
    let pool_size = 200usize;
    let mut mp = Mempool::new(MempoolConfig {
        capacity: pool_size + 100,
        min_fee_ratio_bps: 10_000,
    });
    for i in 0..pool_size as u8 {
        let tx = dummy_tx(i, INITIAL_BASE_FEE_SPARK_PER_KB * 100);
        let _ = mp.submit(tx, INITIAL_BASE_FEE_SPARK_PER_KB, 1);
    }

    let r = bench("mempool_select_200", iterations, || {
        let _ = mp.select_for_block(200, 1);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(10));
}

/// Benchmark age-eligible selection (priority path).
pub fn bench_mempool_age_eligible(iterations: u64) {
    use indra_consensus::mempool::AGE_INCLUSION_BLOCKS;
    let mut mp = Mempool::default_config();
    // Half old (age-eligible), half new
    for i in 0..50u8 {
        let tx = dummy_tx(i, INITIAL_BASE_FEE_SPARK_PER_KB * 100);
        let _ = mp.submit(tx, INITIAL_BASE_FEE_SPARK_PER_KB, 1);
    }
    for i in 50..100u8 {
        let tx = dummy_tx(i, INITIAL_BASE_FEE_SPARK_PER_KB * 100);
        let _ = mp.submit(tx, INITIAL_BASE_FEE_SPARK_PER_KB, 100);
    }
    let current_height = 1 + AGE_INCLUSION_BLOCKS;

    let r = bench("mempool_age_eligible_50", iterations, || {
        let _ = mp.age_eligible(current_height);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(5));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_mempool_submit_runs() {
        bench_mempool_submit(100);
    }

    #[test]
    fn bench_mempool_fill_runs() {
        bench_mempool_fill(100, 10);
    }

    #[test]
    fn bench_mempool_select_runs() {
        bench_mempool_select(100);
    }

    #[test]
    fn bench_mempool_age_eligible_runs() {
        bench_mempool_age_eligible(200);
    }
}
