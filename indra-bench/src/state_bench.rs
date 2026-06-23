//! State machine benchmarks.

use std::time::Duration;

use indra_node::state_root::compute_state_root;
use indra_state::{apply_block, ChainState};

use crate::{fixtures::dummy_block, timer::bench};

/// Benchmark applying an empty block.
pub fn bench_block_apply_empty(iterations: u64) {
    let r = bench("block_apply_empty", iterations, || {
        let mut state = ChainState::new_genesis();
        let block = dummy_block(1, state.tip_hash, 0);
        let _ = apply_block(&mut state, &block, 0);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(5));
}

/// Benchmark applying a full block (200 transactions).
/// Note: transactions have dummy (unsigned) signatures so signature
/// verification is not included here — see crypto benchmarks for that.
pub fn bench_block_apply_full(iterations: u64) {
    let r = bench("block_apply_200tx", iterations, || {
        let mut state = ChainState::new_genesis();
        let block = dummy_block(1, state.tip_hash, 200);
        let _ = apply_block(&mut state, &block, 0);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(100));
}

/// Benchmark a chain of N sequential block applications.
pub fn bench_chain_of_blocks(n: u64, iterations: u64) {
    let r = bench(&format!("chain_{n}_blocks"), iterations, || {
        let mut state = ChainState::new_genesis();
        for i in 1..=n {
            let block = dummy_block(i, state.tip_hash, 10);
            let _ = apply_block(&mut state, &block, 0);
        }
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(n * 5));
}

/// Benchmark state root computation.
pub fn bench_state_root(iterations: u64) {
    let state = ChainState::new_genesis();

    let r = bench("state_root_genesis", iterations, || {
        let _ = compute_state_root(&state);
    });
    r.print();
    r.assert_faster_than(Duration::from_micros(100));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_block_apply_empty_runs() {
        bench_block_apply_empty(50);
    }

    #[test]
    fn bench_block_apply_full_runs() {
        bench_block_apply_full(20);
    }

    #[test]
    fn bench_chain_of_blocks_runs() {
        bench_chain_of_blocks(10, 10);
    }

    #[test]
    fn bench_state_root_runs() {
        bench_state_root(500);
    }
}
