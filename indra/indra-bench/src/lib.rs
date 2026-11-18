//! # indra-bench
//!
//! Performance benchmarks for the INDRA v2 protocol.
//!
//! ## What is measured
//!
//! | Benchmark              | What it measures                                  |
//! |------------------------|---------------------------------------------------|
//! | `bench_ed25519`        | Ed25519 sign + verify throughput                  |
//! | `bench_dilithium2`     | Dilithium2 sign + verify throughput               |
//! | `bench_hybrid`         | Full hybrid sign + verify (Ed25519 + Dilithium2)  |
//! | `bench_sha256`         | SHA-256 throughput                                |
//! | `bench_vrf`            | VRF prove + verify                                |
//! | `bench_tx_encode`      | Transaction serialisation                         |
//! | `bench_tx_decode`      | Transaction deserialisation                       |
//! | `bench_block_apply`    | Apply a full block (200 txs) to chain state       |
//! | `bench_mempool_submit` | Mempool submission throughput                     |
//! | `bench_mempool_select` | Select 200 txs from 5000-tx mempool               |
//! | `bench_state_root`     | State root computation                            |
//! | `bench_block_store`    | Block log append + read                           |
//!
//! ## How to run
//!
//! ```bash
//! # Run all benchmarks with timing output
//! cargo test -p indra-bench -- --nocapture
//!
//! # Run a specific benchmark
//! cargo test -p indra-bench bench_hybrid -- --nocapture
//! ```

//! ## Reading results
//!
//! Each benchmark prints:
//! ```text
//! [bench_hybrid] 1000 iterations in 1234ms → 1.234ms/op (811 ops/sec)
//! ```
//!
//! ## Target numbers (Apple M2, single core)
//!
//! | Operation            | Target      |
//! |----------------------|-------------|
//! | Ed25519 sign         | < 0.1 ms    |
//! | Ed25519 verify       | < 0.2 ms    |
//! | Dilithium2 sign      | < 1.0 ms    |
//! | Dilithium2 verify    | < 0.5 ms    |
//! | Hybrid sign          | < 1.5 ms    |
//! | Hybrid verify        | < 0.8 ms    |
//! | Block apply (200 tx) | < 500 ms    |
//! | Mempool select (200) | < 10 ms     |

#![forbid(unsafe_code)]
#![deny(unused_must_use)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::unreachable, clippy::todo, clippy::unimplemented)]
#![deny(clippy::indexing_slicing)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]
pub mod codec_bench;
pub mod crypto_bench;
pub mod fixtures;
pub mod mempool_bench;
pub mod state_bench;
pub mod storage_bench;
pub mod timer;
