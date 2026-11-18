//! Full benchmark suite — run with:
//!   cargo test -p indra-bench --test full_bench -- --nocapture

#![deny(unused_must_use)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::unreachable, clippy::todo, clippy::unimplemented)]
#![deny(clippy::indexing_slicing)]

use indra_bench::{
    codec_bench::*, crypto_bench::*, mempool_bench::*, state_bench::*, storage_bench::*,
};

fn main() {
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║         INDRA v2 Performance Benchmark Suite          ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    println!("── Cryptography ─────────────────────────────────────────");
    bench_sha256(5_000);
    bench_ed25519(500);
    bench_dilithium2(100);
    bench_hybrid(100);
    bench_vrf(200);

    println!("\n── Serialisation ────────────────────────────────────────");
    bench_tx_encode(2_000);
    bench_tx_decode(2_000);
    bench_block_encode(100);
    bench_block_decode(100);

    println!("\n── State Machine ────────────────────────────────────────");
    bench_state_root(2_000);
    bench_block_apply_empty(200);
    bench_block_apply_full(50);
    bench_chain_of_blocks(10, 20);

    println!("\n── Mempool ──────────────────────────────────────────────");
    bench_mempool_submit(500);
    bench_mempool_fill(100, 20);
    bench_mempool_select(200);
    bench_mempool_age_eligible(500);

    println!("\n── Storage ──────────────────────────────────────────────");
    bench_block_store_append(5, 10);
    bench_block_store_read(50);

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║                  Benchmark complete                   ║");
    println!("╚══════════════════════════════════════════════════════╝\n");
}
