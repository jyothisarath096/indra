//! Storage benchmarks.

use std::path::PathBuf;
use std::time::Duration;

use indra_core::Bytes32;
use indra_storage::{BlockStore, PruneConfig};

use crate::{fixtures::dummy_block, timer::bench};

fn temp_path(suffix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "indra_bench_storage_{}_{}.bin",
        suffix,
        std::process::id()
    ));
    p
}

/// Benchmark appending blocks to the block store.
pub fn bench_block_store_append(n: u64, iterations: u64) {
    let path = temp_path(&format!("append_{n}"));

    let r = bench(&format!("block_store_append_{n}"), iterations, || {
        let mut store = BlockStore::open(&path, PruneConfig::archive()).unwrap();
        // Store the genesis block first (height 0)
        let genesis = dummy_block(0, Bytes32::ZERO, 0);
        let _ = store.append(&genesis);
        for i in 1..n {
            let block = dummy_block(i, Bytes32::ZERO, 10);
            let _ = store.append(&block);
        }
        // Clean up for next iteration
        drop(store);
        let _ = std::fs::remove_file(&path);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(n * 2 + 10));
    let _ = std::fs::remove_file(&path);
}

/// Benchmark reading a block by height.
pub fn bench_block_store_read(iterations: u64) {
    let path = temp_path("read");
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
    let _ = std::fs::remove_file(&path);
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
