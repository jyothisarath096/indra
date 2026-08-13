use std::path::PathBuf;

use indra_core::{
    codec::{Decode, Encode},
    types::block::BlockV1,
};
use indra_storage::{BlockStore, PruneConfig};

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("indra-data/blocks.log"));
    let inspect_height_arg = args.next();

    let mut store = BlockStore::open(&path, PruneConfig::archive())
        .unwrap_or_else(|e| panic!("failed to open {}: {e}", path.display()));

    let block_count = store.next_height();
    println!("block_log={}", path.display());
    println!("next_height={}", block_count);

    let inspect_height = inspect_height_arg
        .as_deref()
        .map(|s| {
            s.parse::<u64>()
                .unwrap_or_else(|e| panic!("invalid block height '{s}': {e}"))
        })
        .unwrap_or_else(|| {
            block_count
                .checked_sub(1)
                .expect("block log is empty; no tip height to inspect")
        });
    let inspect_block = store
        .get(inspect_height)
        .unwrap_or_else(|e| panic!("failed to read inspect block {inspect_height}: {e}"));
    println!("inspect.height={}", inspect_block.header.height);
    println!(
        "inspect.protocol_version={}",
        inspect_block.header.protocol_version.0
    );
    println!(
        "inspect.election_result_hash={}",
        inspect_block
            .header
            .election_result_hash
            .map(|h| hex::encode(h.0))
            .unwrap_or_else(|| "None".to_string())
    );
    println!(
        "inspect.vrf_reveals_len={}",
        inspect_block.vrf_reveals.len()
    );

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
        let decoded = BlockV1::decode_exact(&encoded)
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
