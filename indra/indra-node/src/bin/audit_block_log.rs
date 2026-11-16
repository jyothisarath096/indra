#![deny(unused_must_use)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::path::PathBuf;
use std::error::Error;

use indra_core::{
    codec::{Decode, Encode},
    types::block::BlockProposalVNext,
};
use indra_storage::{BlockStore, PruneConfig};

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("indra-data/blocks.log"));
    let inspect_height_arg = args.next();

    let mut store = BlockStore::open(&path, PruneConfig::archive())
        .map_err(|e| format!("failed to open {}: {e}", path.display()))?;

    let block_count = store.next_height();
    println!("block_log={}", path.display());
    println!("next_height={}", block_count);

    let inspect_height = if let Some(s) = inspect_height_arg.as_deref() {
        s.parse::<u64>()
            .map_err(|e| format!("invalid block height '{s}': {e}"))?
    } else {
        block_count
            .checked_sub(1)
            .ok_or("block log is empty; no tip height to inspect")?
    };
    let inspect_block = store
        .get(inspect_height)
        .map_err(|e| format!("failed to read inspect block {inspect_height}: {e}"))?;
    println!("inspect.height={}", inspect_block.block.header.height);
    println!(
        "inspect.protocol_version={}",
        inspect_block.block.header.protocol_version.0
    );
    println!(
        "inspect.proposer_authorization_bytes={}",
        inspect_block.proposer_authorization.encoded_len()
    );

    if block_count <= 2 {
        println!("not enough blocks to compare block 1 against block 2 prev_hash");
        return Ok(());
    }

    let block1 = store
        .get(1)
        .map_err(|e| format!("failed to read block 1: {e}"))?;
    let block2 = store
        .get(2)
        .map_err(|e| format!("failed to read block 2: {e}"))?;
    let block1_hash = block1.block.header.block_hash();
    let block2_prev = block2.block.header.prev_hash;

    println!("block1.hash={}", hex::encode(block1_hash.0));
    println!("block2.prev_hash={}", hex::encode(block2_prev.0));
    println!("block1_matches_block2_prev={}", block1_hash == block2_prev);

    let mut roundtrip_failures = 0usize;
    let mut linkage_failures = 0usize;
    let mut previous: Option<BlockProposalVNext> = None;

    for height in 0..block_count {
        let block = store
            .get(height)
            .map_err(|e| format!("failed to read block {height}: {e}"))?;
        let encoded = block.encode_to_vec();
        let decoded = BlockProposalVNext::decode_exact(&encoded)
            .map_err(|e| format!("failed to decode re-encoded block {height}: {e}"))?;
        if decoded != block {
            roundtrip_failures += 1;
            println!("roundtrip_mismatch_at_height={}", height);
        }

        if let Some(prev) = &previous {
            let expected_prev_hash = prev.block.header.block_hash();
            if block.block.header.prev_hash != expected_prev_hash {
                linkage_failures += 1;
                println!(
                    "hash_link_mismatch_at_height={} expected_prev={} got_prev={}",
                    height,
                    hex::encode(expected_prev_hash.0),
                    hex::encode(block.block.header.prev_hash.0),
                );
            }
        }

        previous = Some(block);
    }

    println!("roundtrip_failures={}", roundtrip_failures);
    println!("linkage_failures={}", linkage_failures);
    Ok(())
}
