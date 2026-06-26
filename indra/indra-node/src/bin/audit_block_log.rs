use std::path::PathBuf;

use indra_core::{
    codec::{ByteReader, Decode, Encode},
    types::block::BlockV1,
};
use indra_storage::{BlockStore, PruneConfig};

fn main() {
    let path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("indra-data/blocks.log"));

    let mut store = BlockStore::open(&path, PruneConfig::archive())
        .unwrap_or_else(|e| panic!("failed to open {}: {e}", path.display()));

    let block_count = store.next_height();
    println!("block_log={}", path.display());
    println!("next_height={}", block_count);

    if block_count <= 2 {
        println!("not enough blocks to compare block 1 against block 2 prev_hash");
        return;
    }

    let block1 = store.get(1).expect("failed to read block 1");
    let block2 = store.get(2).expect("failed to read block 2");
    let block1_hash = block1.header.block_hash();
    let block2_prev = block2.header.prev_hash;

    println!("block1.hash={}", hex::encode(block1_hash.0));
    println!("block2.prev_hash={}", hex::encode(block2_prev.0));
    println!("block1_matches_block2_prev={}", block1_hash == block2_prev);

    let mut roundtrip_failures = 0usize;
    let mut linkage_failures = 0usize;
    let mut previous: Option<BlockV1> = None;

    for height in 0..block_count {
        let block = store
            .get(height)
            .unwrap_or_else(|e| panic!("failed to read block {height}: {e}"));
        let encoded = block.encode_to_vec();
        let mut reader = ByteReader::new(&encoded);
        let decoded = BlockV1::decode(&mut reader)
            .unwrap_or_else(|e| panic!("failed to decode re-encoded block {height}: {e}"));
        if decoded != block {
            roundtrip_failures += 1;
            println!("roundtrip_mismatch_at_height={}", height);
        }

        if let Some(prev) = &previous {
            let expected_prev_hash = prev.header.block_hash();
            if block.header.prev_hash != expected_prev_hash {
                linkage_failures += 1;
                println!(
                    "hash_link_mismatch_at_height={} expected_prev={} got_prev={}",
                    height,
                    hex::encode(expected_prev_hash.0),
                    hex::encode(block.header.prev_hash.0),
                );
            }
        }

        previous = Some(block);
    }

    println!("roundtrip_failures={}", roundtrip_failures);
    println!("linkage_failures={}", linkage_failures);
}
