//! Storage benchmarks.

use std::time::Duration;

use indra_core::Bytes32;
use indra_storage::{BlockStore, PruneConfig};

use crate::{fixtures::dummy_block, timer::bench};

/// Benchmark appending blocks to the block store.
pub fn bench_block_store_append(n: u64, iterations: u64) {
    let root = tempfile::tempdir().expect("unique benchmark directory");

    let r = bench(&format!("block_store_append_{n}"), iterations, || {
        let iteration = tempfile::tempdir_in(root.path()).expect("unique iteration directory");
        let path = iteration.path().join("blocks.log");
        let mut store = BlockStore::open(&path, PruneConfig::archive()).unwrap();
        // Store the genesis block first (height 0)
        let genesis = dummy_block(0, Bytes32::ZERO, 0);
        let _ = store.append(&genesis);
        for i in 1..n {
            let block = dummy_block(i, Bytes32::ZERO, 10);
            let _ = store.append(&block);
        }
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(n * 2 + 10));
}

/// Benchmark reading a block by height.
pub fn bench_block_store_read(iterations: u64) {
    let root = tempfile::tempdir().expect("unique benchmark directory");
    let path = root.path().join("blocks.log");
    {
        let mut store = BlockStore::open(&path, PruneConfig::archive()).unwrap();
        for i in 0..10u64 {
            let block = dummy_block(i, Bytes32::ZERO, 10);
            store.append(&block).unwrap();
        }
    }

    let r = bench("block_store_read", iterations, || {
        let mut store = BlockStore::open(&path, PruneConfig::archive()).unwrap();
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
