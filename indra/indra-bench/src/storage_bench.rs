//! Storage benchmarks.

use std::time::Duration;

use indra_core::Bytes32;
use indra_storage::{BlockStore, PruneConfig};

use crate::{fixtures::dummy_proposal, timer::bench};

/// Benchmark appending blocks to the block store.
pub fn bench_block_store_append(n: u64, iterations: u64) {
    let Ok(root) = tempfile::tempdir() else {
        return;
    };

    let r = bench(&format!("block_store_append_{n}"), iterations, || {
        let Ok(iteration) = tempfile::tempdir_in(root.path()) else {
            return;
        };
        let path = iteration.path().join("blocks.log");
        let Ok(mut store) = BlockStore::open(&path, PruneConfig::archive()) else {
            return;
        };
        // Store the genesis block first (height 0)
        let genesis = dummy_proposal(0, Bytes32::ZERO, 0);
        let _ = store.append(&genesis);
        for i in 1..n {
            let block = dummy_proposal(i, Bytes32::ZERO, 10);
            let _ = store.append(&block);
        }
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(n * 2 + 10));
}

/// Benchmark reading a block by height.
pub fn bench_block_store_read(iterations: u64) {
    let Ok(root) = tempfile::tempdir() else {
        return;
    };
    let path = root.path().join("blocks.log");
    {
        let Ok(mut store) = BlockStore::open(&path, PruneConfig::archive()) else {
            return;
        };
        for i in 0..10u64 {
            let block = dummy_proposal(i, Bytes32::ZERO, 10);
            if store.append(&block).is_err() {
                return;
            }
        }
    }

    let r = bench("block_store_read", iterations, || {
        let Ok(mut store) = BlockStore::open(&path, PruneConfig::archive()) else {
            return;
        };
        let _ = store.get(5);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(5));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_block_store_append_runs() {
        bench_block_store_append(5, 3);
    }

    #[test]
    fn bench_block_store_read_runs() {
        bench_block_store_read(20);
    }
}
