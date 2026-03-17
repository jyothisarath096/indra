#!/usr/bin/env bash
# =============================================================================
# INDRA v2 — Benchmark Module Setup Script
# Measures real performance: crypto, block processing, mempool, gossip
# =============================================================================
# Run from inside the indra/ workspace directory:
#
#   chmod +x setup_indra_bench.sh
#   ./setup_indra_bench.sh
#   cargo build
#   cargo test                        # run unit tests
#   cargo test -p indra-bench         # run benchmark as normal tests (fast)
#   cargo test -p indra-bench -- --nocapture   # see timing output
# =============================================================================

set -euo pipefail

echo "==> Setting up INDRA Benchmark Module..."

if [ ! -f "Cargo.toml" ]; then
    echo "ERROR: Run from inside the indra/ workspace directory."
    exit 1
fi

# =============================================================================
# Update workspace Cargo.toml
# =============================================================================

cat > Cargo.toml << 'TOML'
[workspace]
members  = [
    "indra-core",
    "indra-crypto",
    "indra-state",
    "indra-consensus",
    "indra-storage",
    "indra-node",
    "indra-network",
    "indra-rpc",
    "indra-cli",
    "indra-bench",
]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
authors = ["INDRA Protocol"]
license = "MIT"

[workspace.dependencies]
sha2               = { version = "0.10", default-features = false }
thiserror          = { version = "1.0" }
hex                = { version = "0.4", default-features = false, features = ["alloc"] }
ed25519-dalek      = { version = "2.1", default-features = false, features = ["alloc"] }
curve25519-dalek   = { version = "4.1", default-features = false, features = ["alloc"] }
pqcrypto-dilithium = { version = "0.5", default-features = false }
pqcrypto-traits    = { version = "0.3", default-features = false }
blst               = { version = "0.3" }
proptest           = { version = "1.4", default-features = false, features = ["std"] }

[profile.release]
opt-level     = 3
lto           = true
codegen-units = 1
panic         = "abort"

[profile.dev]
opt-level = 0
debug     = true

[profile.bench]
opt-level = 3
debug     = false
TOML

# =============================================================================
# Create indra-bench crate
# =============================================================================

mkdir -p indra-bench/src
mkdir -p indra-bench/benches

cat > indra-bench/Cargo.toml << 'TOML'
[package]
name        = "indra-bench"
description = "INDRA v2 performance benchmarks"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
indra-core      = { path = "../indra-core" }
indra-crypto    = { path = "../indra-crypto" }
indra-state     = { path = "../indra-state" }
indra-consensus = { path = "../indra-consensus" }
indra-storage   = { path = "../indra-storage" }
indra-node      = { path = "../indra-node" }

[dev-dependencies]
indra-core      = { path = "../indra-core" }
indra-crypto    = { path = "../indra-crypto" }
indra-state     = { path = "../indra-state" }
indra-consensus = { path = "../indra-consensus" }
indra-storage   = { path = "../indra-storage" }
indra-node      = { path = "../indra-node" }
TOML

# --------------- indra-bench/src/lib.rs ---------------

cat > indra-bench/src/lib.rs << 'RUST'
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
//! | `bench_bls_sign`       | BLS12-381 single signature                        |
//! | `bench_bls_aggregate`  | BLS aggregate over N signatures                   |
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
//!
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
//! | BLS sign             | < 0.5 ms    |
//! | BLS aggregate (100)  | < 5 ms      |
//! | Block apply (200 tx) | < 500 ms    |
//! | Mempool select (200) | < 10 ms     |

#![forbid(unsafe_code)]
#![allow(missing_docs)] // benchmarks don't need doc comments

pub mod timer;
pub mod fixtures;
pub mod crypto_bench;
pub mod codec_bench;
pub mod state_bench;
pub mod mempool_bench;
pub mod storage_bench;
RUST

# --------------- indra-bench/src/timer.rs ---------------

cat > indra-bench/src/timer.rs << 'RUST'
//! Simple wall-clock timer for benchmarks.

use std::time::{Duration, Instant};

/// Run a closure N times and report timing statistics.
pub struct BenchResult {
    /// Name of the benchmark.
    pub name: String,
    /// Number of iterations.
    pub iterations: u64,
    /// Total elapsed time.
    pub total: Duration,
}

impl BenchResult {
    /// Average time per iteration.
    pub fn per_op(&self) -> Duration {
        self.total / self.iterations as u32
    }

    /// Operations per second.
    pub fn ops_per_sec(&self) -> f64 {
        self.iterations as f64 / self.total.as_secs_f64()
    }

    /// Print a one-line summary.
    pub fn print(&self) {
        println!(
            "[{}] {} iters in {:.1}ms → {:.3}ms/op ({:.0} ops/sec)",
            self.name,
            self.iterations,
            self.total.as_secs_f64() * 1000.0,
            self.per_op().as_secs_f64() * 1000.0,
            self.ops_per_sec(),
        );
    }

    /// Assert that the average operation time is below a threshold.
    /// Prints a warning if exceeded but does not fail the test
    /// (hardware varies too much to hard-fail on timing).
    pub fn assert_faster_than(&self, threshold: Duration) {
        let per_op = self.per_op();
        if per_op > threshold {
            println!(
                "  ⚠ SLOW: {:.3}ms/op exceeds target {:.3}ms/op",
                per_op.as_secs_f64() * 1000.0,
                threshold.as_secs_f64() * 1000.0,
            );
        } else {
            println!(
                "  ✓ FAST: {:.3}ms/op within target {:.3}ms/op",
                per_op.as_secs_f64() * 1000.0,
                threshold.as_secs_f64() * 1000.0,
            );
        }
    }
}

/// Run a benchmark: execute `f` `iterations` times and return results.
pub fn bench<F: FnMut()>(name: &str, iterations: u64, mut f: F) -> BenchResult {
    // Warmup: 10% of iterations, minimum 3
    let warmup = (iterations / 10).max(3);
    for _ in 0..warmup {
        f();
    }

    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let total = start.elapsed();

    BenchResult {
        name: name.to_string(),
        iterations,
        total,
    }
}
RUST

# --------------- indra-bench/src/fixtures.rs ---------------

cat > indra-bench/src/fixtures.rs << 'RUST'
//! Reusable test fixtures for benchmarks.

use indra_core::{
    Bytes32, CommitmentV1, HybridPubKey, ProtocolVersion, VariableBytes,
    types::{
        block::{BlockHeaderV1, BlockV1},
        crypto::HybridSignature,
        primitives::{
            INITIAL_BASE_FEE_SPARK_PER_KB, MAX_VRF_PROOF_BYTES,
            MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES,
        },
        transaction::{InputV1, OutputV1, TransactionV1},
    },
};
use indra_crypto::{
    bls::BlsKeypair,
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    VrfKeypair,
};

/// A pre-built transaction for benchmarks.
pub fn dummy_tx(nonce: u8, fee: u64) -> TransactionV1 {
    TransactionV1 {
        version: ProtocolVersion::CURRENT,
        signature_module_id: 1,
        inputs: vec![InputV1 {
            utxo_id:   Bytes32::from([nonce; 32]),
            nullifier: Bytes32::from([nonce; 32]),
        }],
        outputs: vec![OutputV1 {
            commitment:   CommitmentV1 { compressed_point: Bytes32::ZERO },
            owner_pubkey: HybridPubKey {
                classical_pk: Bytes32::ZERO,
                pq_pk: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            },
            range_proof:  VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            lock_height:  0,
        }],
        fee_amount:     fee,
        fee_blinding:   Bytes32::ZERO,
        fee_commitment: CommitmentV1 { compressed_point: Bytes32::ZERO },
        signature: HybridSignature {
            classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(&[0u8; 64]).unwrap(),
            pq_sig:        VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&[0u8; 32]).unwrap(),
        },
    }
}

/// A block with N transactions.
pub fn dummy_block(height: u64, prev_hash: Bytes32, tx_count: usize) -> BlockV1 {
    let txs: Vec<TransactionV1> = (0..tx_count)
        .map(|i| dummy_tx(i as u8, INITIAL_BASE_FEE_SPARK_PER_KB * 10))
        .collect();

    BlockV1 {
        header: BlockHeaderV1 {
            protocol_version:    ProtocolVersion::CURRENT,
            height,
            prev_hash,
            timestamp:           1_700_000_000 + height,
            state_root:          Bytes32::ZERO,
            validator_set_root:  Bytes32::ZERO,
            mempool_set_root:    Bytes32::ZERO,
            base_fee:            INITIAL_BASE_FEE_SPARK_PER_KB,
            proposer_vrf_output: Bytes32::ZERO,
            proposer_vrf_proof:  VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
            quorum_certificate:  VariableBytes::from_slice(&[]).unwrap(),
        },
        transactions:      txs,
        slashing_evidence: vec![],
        governance_ops:    vec![],
    }
}

/// A hybrid keypair for benchmarks.
pub fn hybrid_keypair(seed: u8) -> HybridKeypair {
    let classical = ClassicalKeypair::from_seed(&[seed; 32]);
    let pq = PqKeypair::generate();
    HybridKeypair::new(classical, pq)
}

/// A BLS keypair for benchmarks.
pub fn bls_keypair(seed: u8) -> BlsKeypair {
    BlsKeypair::from_seed(&[seed; 32]).unwrap()
}

/// A VRF keypair for benchmarks.
pub fn vrf_keypair(seed: u8) -> VrfKeypair {
    VrfKeypair::from_seed(&[seed; 32])
}
RUST

# --------------- indra-bench/src/crypto_bench.rs ---------------

cat > indra-bench/src/crypto_bench.rs << 'RUST'
//! Cryptographic operation benchmarks.

use std::time::Duration;

use indra_crypto::{
    bls::{BlsKeypair, BlsSignature, aggregate_signatures},
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair, verify_hybrid},
    sha256,
    vrf::{vrf_prove, vrf_verify},
    VrfKeypair,
};

use crate::{
    fixtures::{bls_keypair, hybrid_keypair, vrf_keypair},
    timer::bench,
};

/// Benchmark Ed25519 sign + verify.
pub fn bench_ed25519(iterations: u64) {
    let kp = ClassicalKeypair::from_seed(&[0x01u8; 32]);
    let msg = b"INDRA benchmark message for Ed25519 signing";

    let r = bench("ed25519_sign", iterations, || {
        let _ = kp.sign(msg);
    });
    r.print();
    r.assert_faster_than(Duration::from_micros(200));

    let sig = kp.sign(msg);
    let pk = kp.public_key();

    let r = bench("ed25519_verify", iterations, || {
        let _ = indra_crypto::hybrid::verify_classical(msg, &sig, &pk);
    });
    r.print();
    r.assert_faster_than(Duration::from_micros(400));
}

/// Benchmark Dilithium2 sign + verify.
pub fn bench_dilithium2(iterations: u64) {
    let kp = PqKeypair::generate();
    let msg = b"INDRA benchmark message for Dilithium2 signing";

    let r = bench("dilithium2_sign", iterations, || {
        let _ = kp.sign(msg);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(2));

    let sig = kp.sign(msg).unwrap();
    let pk = kp.public_key();

    let r = bench("dilithium2_verify", iterations, || {
        let _ = indra_crypto::hybrid::verify_pq(msg, &sig, &pk);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(1));
}

/// Benchmark full hybrid sign + verify (Ed25519 + Dilithium2 together).
pub fn bench_hybrid(iterations: u64) {
    let kp = hybrid_keypair(0x01);
    let msg = b"INDRA benchmark message for hybrid signing";

    let r = bench("hybrid_sign", iterations, || {
        let _ = kp.sign(msg);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(3));

    let sig = kp.sign(msg).unwrap();
    let pk = kp.public_key();

    let r = bench("hybrid_verify", iterations, || {
        let _ = verify_hybrid(msg, &sig, &pk);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(2));
}

/// Benchmark BLS12-381 single sign.
pub fn bench_bls_sign(iterations: u64) {
    let kp = bls_keypair(0x01);
    let msg = b"INDRA benchmark message for BLS signing";

    let r = bench("bls_sign", iterations, || {
        let _ = kp.sign(msg);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(1));
}

/// Benchmark BLS aggregate over N signatures.
pub fn bench_bls_aggregate(n: usize, iterations: u64) {
    let keypairs: Vec<_> = (0..n as u8).map(bls_keypair).collect();
    let msg = b"INDRA benchmark message for BLS aggregation";
    let sigs: Vec<BlsSignature> = keypairs.iter().map(|kp| kp.sign(msg)).collect();

    let r = bench(&format!("bls_aggregate_{n}"), iterations, || {
        let _ = aggregate_signatures(&sigs);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(n as u64 / 10 + 5));
}

/// Benchmark SHA-256 on a 1 KB message.
pub fn bench_sha256(iterations: u64) {
    let data = vec![0xABu8; 1024];

    let r = bench("sha256_1kb", iterations, || {
        let _ = sha256(&data);
    });
    r.print();
    r.assert_faster_than(Duration::from_micros(50));
}

/// Benchmark VRF prove + verify.
pub fn bench_vrf(iterations: u64) {
    let kp = vrf_keypair(0x01);
    let input = sha256(b"INDRA VRF benchmark input");

    let r = bench("vrf_prove", iterations, || {
        let _ = vrf_prove(&kp, &input);
    });
    r.print();
    r.assert_faster_than(Duration::from_micros(500));

    let (output, proof) = vrf_prove(&kp, &input);
    let pk = kp.public_key();

    let r = bench("vrf_verify", iterations, || {
        let _ = vrf_verify(&pk, &input, &output, &proof);
    });
    r.print();
    r.assert_faster_than(Duration::from_micros(500));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_ed25519_runs() {
        bench_ed25519(50);
    }

    #[test]
    fn bench_dilithium2_runs() {
        bench_dilithium2(20);
    }

    #[test]
    fn bench_hybrid_runs() {
        bench_hybrid(20);
    }

    #[test]
    fn bench_bls_sign_runs() {
        bench_bls_sign(50);
    }

    #[test]
    fn bench_bls_aggregate_runs() {
        bench_bls_aggregate(10, 20);
        bench_bls_aggregate(100, 10);
    }

    #[test]
    fn bench_sha256_runs() {
        bench_sha256(1000);
    }

    #[test]
    fn bench_vrf_runs() {
        bench_vrf(100);
    }
}
RUST

# --------------- indra-bench/src/codec_bench.rs ---------------

cat > indra-bench/src/codec_bench.rs << 'RUST'
//! Serialisation/deserialisation benchmarks.

use std::time::Duration;

use indra_core::codec::{Decode, Encode, ByteReader};

use crate::{
    fixtures::dummy_tx,
    timer::bench,
};

/// Benchmark transaction encode.
pub fn bench_tx_encode(iterations: u64) {
    let tx = dummy_tx(0x01, 10_000);

    let r = bench("tx_encode", iterations, || {
        let _ = tx.encode_to_vec();
    });
    r.print();
    r.assert_faster_than(Duration::from_micros(50));
}

/// Benchmark transaction decode.
pub fn bench_tx_decode(iterations: u64) {
    let tx = dummy_tx(0x01, 10_000);
    let encoded = tx.encode_to_vec();

    let r = bench("tx_decode", iterations, || {
        let mut reader = ByteReader::new(&encoded);
        let _ = indra_core::types::transaction::TransactionV1::decode(&mut reader);
    });
    r.print();
    r.assert_faster_than(Duration::from_micros(50));
}

/// Benchmark block encode (200 transactions).
pub fn bench_block_encode(iterations: u64) {
    use crate::fixtures::dummy_block;
    use indra_core::Bytes32;
    let block = dummy_block(1, Bytes32::ZERO, 200);

    let r = bench("block_encode_200tx", iterations, || {
        let _ = block.encode_to_vec();
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(5));
}

/// Benchmark block decode (200 transactions).
pub fn bench_block_decode(iterations: u64) {
    use crate::fixtures::dummy_block;
    use indra_core::Bytes32;
    let block = dummy_block(1, Bytes32::ZERO, 200);
    let encoded = block.encode_to_vec();

    let r = bench("block_decode_200tx", iterations, || {
        let mut reader = ByteReader::new(&encoded);
        let _ = indra_core::types::block::BlockV1::decode(&mut reader);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(5));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_tx_encode_runs() {
        bench_tx_encode(500);
    }

    #[test]
    fn bench_tx_decode_runs() {
        bench_tx_decode(500);
    }

    #[test]
    fn bench_block_encode_runs() {
        bench_block_encode(100);
    }

    #[test]
    fn bench_block_decode_runs() {
        bench_block_decode(100);
    }
}
RUST

# --------------- indra-bench/src/state_bench.rs ---------------

cat > indra-bench/src/state_bench.rs << 'RUST'
//! State machine benchmarks.

use std::time::Duration;

use indra_core::Bytes32;
use indra_state::{apply_block, ChainState};
use indra_node::state_root::compute_state_root;

use crate::{
    fixtures::dummy_block,
    timer::bench,
};

/// Benchmark applying an empty block.
pub fn bench_block_apply_empty(iterations: u64) {
    let r = bench("block_apply_empty", iterations, || {
        let mut state = ChainState::new_genesis();
        let block = dummy_block(1, state.tip_hash, 0);
        let _ = apply_block(&mut state, &block);
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
        let _ = apply_block(&mut state, &block);
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
            let _ = apply_block(&mut state, &block);
        }
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(n as u64 * 5));
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
RUST

# --------------- indra-bench/src/mempool_bench.rs ---------------

cat > indra-bench/src/mempool_bench.rs << 'RUST'
//! Mempool benchmarks.

use std::time::Duration;

use indra_consensus::mempool::{Mempool, MempoolConfig};
use indra_core::types::primitives::INITIAL_BASE_FEE_SPARK_PER_KB;

use crate::{
    fixtures::dummy_tx,
    timer::bench,
};

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
RUST

# --------------- indra-bench/src/storage_bench.rs ---------------

cat > indra-bench/src/storage_bench.rs << 'RUST'
//! Storage benchmarks.

use std::path::PathBuf;
use std::time::Duration;

use indra_core::Bytes32;
use indra_storage::BlockStore;

use crate::{
    fixtures::dummy_block,
    timer::bench,
};

fn temp_path(suffix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("indra_bench_storage_{}_{}.bin", suffix, std::process::id()));
    p
}

/// Benchmark appending blocks to the block store.
pub fn bench_block_store_append(n: u64, iterations: u64) {
    let path = temp_path(&format!("append_{n}"));

    let r = bench(&format!("block_store_append_{n}"), iterations, || {
        let mut store = BlockStore::open(&path).unwrap();
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
    r.assert_faster_than(Duration::from_millis(n as u64 * 2 + 10));
    let _ = std::fs::remove_file(&path);
}

/// Benchmark reading a block by height.
pub fn bench_block_store_read(iterations: u64) {
    let path = temp_path("read");
    {
        let mut store = BlockStore::open(&path).unwrap();
        for i in 0..10u64 {
            let block = dummy_block(i, Bytes32::ZERO, 10);
            store.append(&block).unwrap();
        }
    }

    let r = bench("block_store_read", iterations, || {
        let mut store = BlockStore::open(&path).unwrap();
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
RUST

# --------------- indra-bench/benches/full_bench.rs ---------------
# This is the main benchmark runner — prints a full report

cat > indra-bench/benches/full_bench.rs << 'RUST'
//! Full benchmark suite — run with:
//!   cargo test -p indra-bench --test full_bench -- --nocapture

use indra_bench::{
    crypto_bench::*,
    codec_bench::*,
    state_bench::*,
    mempool_bench::*,
    storage_bench::*,
};

#[test]
fn full_benchmark_suite() {
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║         INDRA v2 Performance Benchmark Suite          ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    println!("── Cryptography ─────────────────────────────────────────");
    bench_sha256(5_000);
    bench_ed25519(500);
    bench_dilithium2(100);
    bench_hybrid(100);
    bench_bls_sign(500);
    bench_bls_aggregate(10,  100);
    bench_bls_aggregate(100, 20);
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
    bench_block_store_append(5,  10);
    bench_block_store_read(50);

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║                  Benchmark complete                   ║");
    println!("╚══════════════════════════════════════════════════════╝\n");
}
RUST

echo ""
echo "✓ INDRA Benchmark Module files written."
echo ""
echo "New crate: indra-bench"
echo "  src/timer.rs         — wall-clock timer with warmup and ops/sec output"
echo "  src/fixtures.rs      — pre-built transactions, blocks, keypairs"
echo "  src/crypto_bench.rs  — Ed25519, Dilithium2, hybrid, BLS, VRF"
echo "  src/codec_bench.rs   — tx/block encode + decode"
echo "  src/state_bench.rs   — block apply, chain replay, state root"
echo "  src/mempool_bench.rs — submit, fill, select, age-eligible"
echo "  src/storage_bench.rs — block store append + read"
echo "  benches/full_bench.rs — full suite runner"
echo ""
echo "Run benchmarks:"
echo "  cargo test -p indra-bench -- --nocapture          # full suite with output"
echo "  cargo test -p indra-bench bench_hybrid -- --nocapture  # single benchmark"
echo ""
echo "Now run:"
echo "  cargo build"
echo "  cargo test"
echo ""
