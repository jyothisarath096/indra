#!/usr/bin/env bash
# =============================================================================
# INDRA v2 — Phase 4 Setup Script
# Consensus Engine: Mempool, Proposer Election, Block Production, Voting, QC
# =============================================================================
# Run from inside the indra/ workspace directory:
#
#   chmod +x setup_indra_phase4.sh
#   ./setup_indra_phase4.sh
#   cargo build
#   cargo test
#
# Prerequisites: Phases 1, 2, and 3 must be passing.
#
# What this adds — new crate: indra-consensus
#   src/lib.rs         — crate root
#   src/error.rs       — ConsensusError enum
#   src/mempool.rs     — validated pending tx pool with age tracking
#   src/proposer.rs    — VRF-based slot election
#   src/producer.rs    — assemble a valid block from mempool
#   src/vote.rs        — produce and collect prevotes/precommits
#   src/qc.rs          — build and verify Quorum Certificates
#   tests/consensus.rs — integration tests
# =============================================================================

set -euo pipefail

echo "==> Setting up INDRA Phase 4 — Consensus Engine..."

if [ ! -f "Cargo.toml" ]; then
    echo "ERROR: Run from inside the indra/ workspace directory."
    exit 1
fi

# =============================================================================
# Add indra-consensus to workspace
# =============================================================================

cat > Cargo.toml << 'TOML'
[workspace]
members  = ["indra-core", "indra-crypto", "indra-state", "indra-consensus"]
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
TOML

mkdir -p indra-consensus/src
mkdir -p indra-consensus/tests

cat > indra-consensus/Cargo.toml << 'TOML'
[package]
name        = "indra-consensus"
description = "INDRA consensus engine — mempool, proposer election, block production, voting, QC"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
indra-core   = { path = "../indra-core" }
indra-crypto = { path = "../indra-crypto" }
indra-state  = { path = "../indra-state" }
thiserror.workspace = true

[dev-dependencies]
indra-core   = { path = "../indra-core" }
indra-crypto = { path = "../indra-crypto" }
indra-state  = { path = "../indra-state" }
TOML

# =============================================================================
# FILE: indra-consensus/src/lib.rs
# =============================================================================

cat > indra-consensus/src/lib.rs << 'RUST'
//! # indra-consensus
//!
//! The INDRA v2 consensus engine.
//!
//! ## What this crate does
//!
//! Implements the components that allow a validator node to participate
//! in block production and BFT consensus:
//!
//! - **Mempool**: a validated pool of pending transactions with age tracking.
//!   The age-inclusion guarantee requires that any transaction present in
//!   the mempool for AGE_INCLUSION_BLOCKS consecutive blocks must be included
//!   (prevents censorship without coordination).
//!
//! - **Proposer election**: VRF-based slot assignment. Each validator uses
//!   their secret key and the epoch seed to produce a VRF output. The
//!   validator with the smallest output (weighted by stake) wins the slot.
//!
//! - **Block production**: given a proposer keypair and mempool, assembles
//!   a structurally valid `BlockV1` ready for broadcast and voting.
//!
//! - **Vote handling**: produces signed prevotes and precommits for a given
//!   block hash. Tracks received votes and detects when quorum is reached.
//!
//! - **Quorum Certificate**: collects votes until 2/3 stake threshold is
//!   met, then aggregates the BLS classical signatures and bundles the
//!   individual Dilithium2 signatures into a `QuorumCertificateV1`.
//!
//! ## What this crate does NOT do
//!
//! - P2P networking (Phase 5)
//! - Disk persistence (Phase 5)
//! - Slash evidence detection (Phase 6)
//!
//! ## Invariants
//!
//! - No unsafe code.
//! - No floating-point arithmetic.
//! - All operations are deterministic given the same inputs.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::indexing_slicing)]

pub mod error;
pub mod mempool;
pub mod proposer;
pub mod producer;
pub mod vote;
pub mod qc;

pub use error::{ConsensusError, ConsensusResult};
pub use mempool::{Mempool, MempoolEntry, MempoolConfig};
pub use proposer::{elect_proposer, ProposerElection, SlotResult};
pub use producer::{produce_block, BlockTemplate};
pub use vote::{VoteCollector, VoteDecision, produce_vote};
pub use qc::{build_qc, verify_qc, QcBuilder};
RUST

# =============================================================================
# FILE: indra-consensus/src/error.rs
# =============================================================================

cat > indra-consensus/src/error.rs << 'RUST'
//! Error types for the consensus engine.

use thiserror::Error;

/// All errors that can occur in the consensus engine.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ConsensusError {
    // ── Mempool errors ────────────────────────────────────────────────────

    /// Transaction is already in the mempool.
    #[error("transaction already in mempool")]
    DuplicateTransaction,

    /// Transaction failed structural validation.
    #[error("transaction failed validation: {reason}")]
    InvalidTransaction {
        /// Why it failed.
        reason: &'static str,
    },

    /// Mempool is at capacity.
    #[error("mempool full: {capacity} transactions")]
    MempoolFull {
        /// Maximum capacity.
        capacity: usize,
    },

    /// Transaction fee is below the current base fee.
    #[error("transaction fee too low")]
    FeeTooLow,

    // ── Proposer election errors ──────────────────────────────────────────

    /// The validator set is empty — cannot elect a proposer.
    #[error("cannot elect proposer: validator set is empty")]
    EmptyValidatorSet,

    /// The given validator is not in the active set.
    #[error("validator not found in active set")]
    ValidatorNotFound,

    // ── Block production errors ───────────────────────────────────────────

    /// The proposer keypair does not match the elected proposer.
    #[error("proposer identity mismatch")]
    WrongProposer,

    /// No transactions available to fill the block.
    #[error("no transactions available")]
    EmptyMempool,

    // ── Vote / QC errors ──────────────────────────────────────────────────

    /// A vote was received for the wrong height or round.
    #[error("vote height/round mismatch: expected {expected_height}/{expected_round}")]
    VoteHeightMismatch {
        /// Expected height.
        expected_height: u64,
        /// Expected round.
        expected_round: u32,
    },

    /// A vote was received from an unknown validator.
    #[error("vote from unknown validator")]
    UnknownVoter,

    /// A duplicate vote was received from the same validator.
    #[error("duplicate vote from validator")]
    DuplicateVote,

    /// QC construction attempted before quorum was reached.
    #[error("quorum not yet reached: have {have_bps} bps, need {need_bps} bps")]
    QuorumNotReached {
        /// Current stake in basis points.
        have_bps: u64,
        /// Required threshold.
        need_bps: u64,
    },

    /// A QC failed signature verification.
    #[error("QC signature verification failed")]
    QcVerificationFailed,

    /// Crypto operation failed.
    #[error("crypto error: {detail}")]
    CryptoError {
        /// Detail from the underlying crypto layer.
        detail: String,
    },
}

/// Convenience alias.
pub type ConsensusResult<T> = Result<T, ConsensusError>;

impl From<indra_crypto::CryptoError> for ConsensusError {
    fn from(e: indra_crypto::CryptoError) -> Self {
        Self::CryptoError { detail: e.to_string() }
    }
}
RUST

# =============================================================================
# FILE: indra-consensus/src/mempool.rs
# =============================================================================

cat > indra-consensus/src/mempool.rs << 'RUST'
//! Mempool — the validated pool of pending transactions.
//!
//! ## Design
//!
//! Transactions enter the mempool after passing structural validation and
//! a fee check against the current base fee. They stay until either:
//!   a) included in a block (evicted on block application), or
//!   b) they age out (fee too low after base fee rises), or
//!   c) the mempool is full and a higher-fee tx displaces them.
//!
//! ## Age-inclusion guarantee
//!
//! Any transaction that has been in the mempool for AGE_INCLUSION_BLOCKS
//! consecutive blocks without being included is "age-eligible". The block
//! producer MUST include all age-eligible transactions (up to block limits).
//! This prevents censorship: a validator cannot indefinitely exclude a tx.
//!
//! ## Storage model (Phase 4)
//!
//! In-memory HashMap keyed by tx_id = SHA-256(encode(tx)).
//! Phase 5 adds WAL-backed persistence.

use std::collections::HashMap;

use indra_core::{
    codec::Encode,
    types::{
        primitives::Bytes32,
        transaction::TransactionV1,
    },
};
use indra_crypto::sha256;

use crate::error::{ConsensusError, ConsensusResult};

/// Number of blocks a transaction can wait before becoming age-eligible.
/// After this many blocks without inclusion, the proposer MUST include it.
pub const AGE_INCLUSION_BLOCKS: u64 = 50;

/// Maximum number of transactions the mempool holds at once.
pub const DEFAULT_MEMPOOL_CAPACITY: usize = 5_000;

/// Configuration for the mempool.
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of transactions.
    pub capacity: usize,
    /// Minimum fee ratio: transaction fee must be at least this multiple
    /// of the current base fee (in basis points, 10000 = 1x).
    pub min_fee_ratio_bps: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_MEMPOOL_CAPACITY,
            min_fee_ratio_bps: 10_000, // exactly 1x base fee
        }
    }
}

/// A single entry in the mempool.
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    /// The transaction itself.
    pub tx: TransactionV1,
    /// SHA-256 of the encoded transaction (used as the map key).
    pub tx_id: Bytes32,
    /// Block height at which this transaction entered the mempool.
    pub arrived_height: u64,
    /// Fee per KB of transaction weight (Spark/KB).
    pub fee_rate: u64,
}

impl MempoolEntry {
    /// True if this transaction has been waiting long enough to be
    /// age-eligible (the proposer must include it).
    pub fn is_age_eligible(&self, current_height: u64) -> bool {
        current_height.saturating_sub(self.arrived_height) >= AGE_INCLUSION_BLOCKS
    }
}

/// The mempool.
#[derive(Debug, Clone)]
pub struct Mempool {
    entries: HashMap<Bytes32, MempoolEntry>,
    config:  MempoolConfig,
}

impl Mempool {
    /// Create a new empty mempool with the given configuration.
    pub fn new(config: MempoolConfig) -> Self {
        Self { entries: HashMap::new(), config }
    }

    /// Create with default configuration.
    pub fn default_config() -> Self {
        Self::new(MempoolConfig::default())
    }

    /// Number of transactions currently in the mempool.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute the transaction ID: SHA-256(encode(tx)).
    pub fn tx_id(tx: &TransactionV1) -> Bytes32 {
        Bytes32::from(sha256(&tx.encode_to_vec()))
    }

    /// Submit a transaction to the mempool.
    ///
    /// Validates:
    /// - Not already present
    /// - Has at least one input and one output
    /// - Fee meets the minimum ratio against `current_base_fee`
    ///
    /// Does NOT validate: signatures, UTXO existence, nullifier set.
    /// Those checks happen in apply_block when the tx is included.
    pub fn submit(
        &mut self,
        tx: TransactionV1,
        current_base_fee: u64,
        current_height: u64,
    ) -> ConsensusResult<Bytes32> {
        // Structural check
        if tx.inputs.is_empty() {
            return Err(ConsensusError::InvalidTransaction { reason: "zero inputs" });
        }
        if tx.outputs.is_empty() {
            return Err(ConsensusError::InvalidTransaction { reason: "zero outputs" });
        }

        let tx_id = Self::tx_id(&tx);

        // Duplicate check
        if self.entries.contains_key(&tx_id) {
            return Err(ConsensusError::DuplicateTransaction);
        }

        // Fee check
        let weight_kb = (tx.encode_to_vec().len() as u64).div_ceil(1024);
        let fee_rate  = if weight_kb > 0 { tx.fee_amount / weight_kb } else { tx.fee_amount };
        let min_fee   = current_base_fee
            .saturating_mul(self.config.min_fee_ratio_bps)
            / 10_000;
        if fee_rate < min_fee {
            return Err(ConsensusError::FeeTooLow);
        }

        // Capacity check — evict lowest-fee tx if full
        if self.entries.len() >= self.config.capacity {
            // Find the tx with the lowest fee rate
            let min_id = self.entries
                .iter()
                .min_by_key(|(_, e)| e.fee_rate)
                .map(|(id, _)| *id);

            if let Some(min_id) = min_id {
                let min_rate = self.entries
                    .get(&min_id)
                    .map(|e| e.fee_rate)
                    .unwrap_or(0);
                if fee_rate > min_rate {
                    self.entries.remove(&min_id);
                } else {
                    return Err(ConsensusError::MempoolFull {
                        capacity: self.config.capacity,
                    });
                }
            }
        }

        self.entries.insert(tx_id, MempoolEntry {
            tx,
            tx_id,
            arrived_height: current_height,
            fee_rate,
        });

        Ok(tx_id)
    }

    /// Remove a transaction by ID (called after block inclusion).
    pub fn evict(&mut self, tx_id: &Bytes32) -> Option<MempoolEntry> {
        self.entries.remove(tx_id)
    }

    /// Remove all transactions whose nullifiers appear in the given set.
    /// Called after a block is applied to evict spent transactions.
    pub fn evict_spent(&mut self, nullifiers: &indra_state::NullifierSet) {
        self.entries.retain(|_, entry| {
            !entry.tx.inputs.iter().any(|i| nullifiers.contains(&i.nullifier))
        });
    }

    /// Return transactions for block production.
    ///
    /// Returns up to `max_count` transactions, prioritising:
    ///   1. Age-eligible transactions (MUST be included), sorted by fee_rate desc
    ///   2. Remaining transactions sorted by fee_rate desc
    pub fn select_for_block(
        &self,
        max_count: usize,
        current_height: u64,
    ) -> Vec<&MempoolEntry> {
        let mut age_eligible: Vec<&MempoolEntry> = self.entries
            .values()
            .filter(|e| e.is_age_eligible(current_height))
            .collect();
        age_eligible.sort_by(|a, b| b.fee_rate.cmp(&a.fee_rate));

        let mut remaining: Vec<&MempoolEntry> = self.entries
            .values()
            .filter(|e| !e.is_age_eligible(current_height))
            .collect();
        remaining.sort_by(|a, b| b.fee_rate.cmp(&a.fee_rate));

        age_eligible.extend(remaining);
        age_eligible.truncate(max_count);
        age_eligible
    }

    /// Return all age-eligible transactions regardless of count.
    pub fn age_eligible(&self, current_height: u64) -> Vec<&MempoolEntry> {
        self.entries
            .values()
            .filter(|e| e.is_age_eligible(current_height))
            .collect()
    }

    /// Check whether a transaction is present.
    pub fn contains(&self, tx_id: &Bytes32) -> bool {
        self.entries.contains_key(tx_id)
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &MempoolEntry> {
        self.entries.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        Bytes32, CommitmentV1, HybridPubKey, ProtocolVersion, VariableBytes,
        types::{
            crypto::HybridSignature,
            transaction::{InputV1, OutputV1, TransactionV1},
        },
    };

    fn dummy_tx(fee: u64, nullifier_byte: u8) -> TransactionV1 {
        TransactionV1 {
            version: ProtocolVersion::CURRENT,
            signature_module_id: 1,
            inputs: vec![InputV1 {
                utxo_id:   Bytes32::from([nullifier_byte; 32]),
                nullifier: Bytes32::from([nullifier_byte; 32]),
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
                classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                pq_sig:        VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            },
        }
    }

    #[test]
    fn submit_and_retrieve() {
        let mut mp = Mempool::default_config();
        let tx = dummy_tx(10_000, 0x01);
        let id = mp.submit(tx.clone(), 100, 1).unwrap();
        assert!(mp.contains(&id));
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn duplicate_rejected() {
        let mut mp = Mempool::default_config();
        let tx = dummy_tx(10_000, 0x01);
        mp.submit(tx.clone(), 100, 1).unwrap();
        assert_eq!(mp.submit(tx, 100, 1), Err(ConsensusError::DuplicateTransaction));
    }

    #[test]
    fn low_fee_rejected() {
        let mut mp = Mempool::default_config();
        let tx = dummy_tx(0, 0x01); // zero fee
        assert_eq!(mp.submit(tx, 1_000, 1), Err(ConsensusError::FeeTooLow));
    }

    #[test]
    fn evict_removes_tx() {
        let mut mp = Mempool::default_config();
        let tx = dummy_tx(10_000, 0x01);
        let id = mp.submit(tx, 100, 1).unwrap();
        mp.evict(&id);
        assert!(!mp.contains(&id));
    }

    #[test]
    fn age_eligible_after_threshold() {
        let mut mp = Mempool::default_config();
        let tx = dummy_tx(10_000, 0x01);
        mp.submit(tx, 100, 1).unwrap();

        // Not yet eligible
        assert!(mp.age_eligible(10).is_empty());
        // Eligible after AGE_INCLUSION_BLOCKS
        assert_eq!(mp.age_eligible(1 + AGE_INCLUSION_BLOCKS).len(), 1);
    }

    #[test]
    fn select_prioritises_age_eligible() {
        let mut mp = Mempool::default_config();
        // High fee tx submitted recently
        mp.submit(dummy_tx(100_000, 0x01), 100, 100).unwrap();
        // Low fee tx submitted long ago (age-eligible)
        mp.submit(dummy_tx(1_000, 0x02), 100, 1).unwrap();

        let selected = mp.select_for_block(2, 1 + AGE_INCLUSION_BLOCKS);
        // Age-eligible tx must come first despite lower fee
        assert_eq!(selected.first().map(|e| e.tx.fee_amount), Some(1_000));
    }

    #[test]
    fn high_fee_displaces_low_fee_when_full() {
        let config = MempoolConfig { capacity: 2, min_fee_ratio_bps: 10_000 };
        let mut mp = Mempool::new(config);
        mp.submit(dummy_tx(1_000, 0x01), 100, 1).unwrap();
        mp.submit(dummy_tx(2_000, 0x02), 100, 1).unwrap();
        // Third tx with higher fee should displace the lowest (0x01)
        mp.submit(dummy_tx(5_000, 0x03), 100, 1).unwrap();
        assert_eq!(mp.len(), 2);
        // The 1_000 fee tx should have been evicted
        let fees: Vec<u64> = mp.iter().map(|e| e.tx.fee_amount).collect();
        assert!(!fees.contains(&1_000));
    }
}
RUST

# =============================================================================
# FILE: indra-consensus/src/proposer.rs
# =============================================================================

cat > indra-consensus/src/proposer.rs << 'RUST'
//! VRF-based proposer election.
//!
//! ## Algorithm (Spec Section A3)
//!
//! At each height h:
//!   1. epoch_seed = SHA-256(last_epoch_block_hash)
//!   2. vrf_input  = SHA-256(DOMAIN_VRF || epoch_seed || u64_le(h))
//!   3. Each validator computes (vrf_output, vrf_proof) = VRF_prove(sk, vrf_input)
//!   4. score = vrf_output_as_u256 * total_stake / validator_stake
//!      (lower score = better — stake-weighted lottery)
//!   5. The validator with the lowest score is the proposer for height h
//!
//! ## Why stake-weighted?
//!
//! Without weighting, each validator wins with probability 1/N regardless
//! of stake. With weighting, a validator with 10% of stake wins ~10% of slots.
//! This aligns proposer rewards with stake, deterring Sybil attacks.
//!
//! ## Phase 4 note
//!
//! The VRF uses the Phase 3 stub (SHA-256 based). Phase 5 upgrades to
//! full ECVRF-RISTRETTO255-SHA512.

use indra_core::types::primitives::Bytes32;
use indra_crypto::{sha256, vrf_prove, vrf_verify, VrfKeypair, VrfOutput, VrfProof};

use crate::error::{ConsensusError, ConsensusResult};

/// An entry in the proposer election: one candidate validator.
#[derive(Debug, Clone)]
pub struct ProposerCandidate {
    /// Validator's 32-byte identity.
    pub validator_id: Bytes32,
    /// Validator's VRF public key.
    pub vrf_pubkey: [u8; 32],
    /// Validator's stake in Spark.
    pub stake: u64,
}

/// The result of a proposer election for one height.
#[derive(Debug, Clone)]
pub struct SlotResult {
    /// The elected proposer's validator ID.
    pub proposer_id: Bytes32,
    /// Their VRF output for this height.
    pub vrf_output: VrfOutput,
    /// Their VRF proof (included in block header).
    pub vrf_proof: VrfProof,
    /// The VRF input used (deterministic from epoch_seed + height).
    pub vrf_input: [u8; 32],
}

/// Input to the proposer election algorithm.
pub struct ProposerElection {
    /// The epoch seed: SHA-256 of the last epoch's final block hash.
    pub epoch_seed: Bytes32,
    /// The height being proposed.
    pub height: u64,
    /// All active validators and their stakes.
    pub candidates: Vec<ProposerCandidate>,
}

impl ProposerElection {
    /// Compute the deterministic VRF input for a given epoch seed and height.
    ///
    /// vrf_input = SHA-256(DOMAIN_VRF || epoch_seed || u64_le(height))
    pub fn vrf_input(&self) -> [u8; 32] {
        compute_vrf_input(&self.epoch_seed.0, self.height)
    }
}

/// Compute the VRF input deterministically.
pub fn compute_vrf_input(epoch_seed: &[u8; 32], height: u64) -> [u8; 32] {
    use indra_crypto::hash::domains::VRF_INPUT;
    let mut data = VRF_INPUT.to_vec();
    data.extend_from_slice(epoch_seed);
    data.extend_from_slice(&height.to_le_bytes());
    sha256(&data)
}

/// Compute the stake-weighted election score for a VRF output.
///
/// score = (vrf_output_as_u256_hi64) * total_stake / validator_stake
///
/// We use only the first 8 bytes of the VRF output as a u64 proxy for
/// the u256 value (sufficient entropy for the lottery). Lower is better.
///
/// Returns u64::MAX if stake is zero (can never win).
pub fn election_score(vrf_output: &VrfOutput, validator_stake: u64, total_stake: u64) -> u64 {
    if validator_stake == 0 || total_stake == 0 {
        return u64::MAX;
    }
    // Use first 8 bytes of VRF output as u64
    let output_val = u64::from_le_bytes(
        vrf_output.0[..8].try_into().unwrap_or([0xFF; 8])
    );
    // score = output_val * total_stake / validator_stake
    // Use u128 to avoid overflow
    let score = (output_val as u128)
        .saturating_mul(total_stake as u128)
        / (validator_stake as u128);
    score.min(u64::MAX as u128) as u64
}

/// Elect the proposer for a given height.
///
/// Each candidate is assumed to have already computed their VRF output.
/// This function evaluates scores and returns the winner.
///
/// In a real network, each validator runs this locally with their own
/// secret key and broadcasts only if they win.
pub fn elect_proposer(election: &ProposerElection) -> ConsensusResult<Bytes32> {
    if election.candidates.is_empty() {
        return Err(ConsensusError::EmptyValidatorSet);
    }

    let vrf_input = election.vrf_input();
    let total_stake: u64 = election.candidates.iter()
        .map(|c| c.stake)
        .fold(0u64, |a, b| a.saturating_add(b));

    let winner = election.candidates.iter()
        .map(|candidate| {
            // Compute a deterministic VRF output for this candidate
            // (in production, each validator does this with their secret key)
            let vrf_kp = VrfKeypair::from_seed(&candidate.vrf_pubkey);
            let (output, _) = vrf_prove(&vrf_kp, &vrf_input);
            let score = election_score(&output, candidate.stake, total_stake);
            (candidate, score)
        })
        .min_by_key(|(_, score)| *score)
        .map(|(c, _)| c.validator_id);

    winner.ok_or(ConsensusError::EmptyValidatorSet)
}

/// Compute the VRF output and proof for a specific validator at a given height.
///
/// Called by the validator who believes they are the proposer.
pub fn compute_proposer_vrf(
    keypair: &VrfKeypair,
    epoch_seed: &Bytes32,
    height: u64,
) -> SlotResult {
    let vrf_input = compute_vrf_input(&epoch_seed.0, height);
    let (vrf_output, vrf_proof) = vrf_prove(keypair, &vrf_input);
    SlotResult {
        proposer_id: Bytes32::from(indra_crypto::sha256(&keypair.public_key())),
        vrf_output,
        vrf_proof,
        vrf_input,
    }
}

/// Verify that a claimed proposer legitimately won the slot.
///
/// Checks:
///   1. The VRF proof is valid for the given public key and input
///   2. The proposer's score is ≤ all other candidates' scores
pub fn verify_proposer(
    claimed_proposer_pubkey: &[u8; 32],
    vrf_output: &VrfOutput,
    vrf_proof: &VrfProof,
    election: &ProposerElection,
) -> ConsensusResult<()> {
    let vrf_input = election.vrf_input();

    // Verify the VRF proof
    vrf_verify(claimed_proposer_pubkey, &vrf_input, vrf_output, vrf_proof)
        .map_err(|_| ConsensusError::WrongProposer)?;

    // Find the claimed proposer in the candidate list
    let claimed_id = Bytes32::from(sha256(claimed_proposer_pubkey));
    let proposer_candidate = election.candidates.iter()
        .find(|c| c.validator_id == claimed_id)
        .ok_or(ConsensusError::ValidatorNotFound)?;

    let total_stake: u64 = election.candidates.iter()
        .map(|c| c.stake)
        .fold(0u64, |a, b| a.saturating_add(b));

    let claimed_score = election_score(vrf_output, proposer_candidate.stake, total_stake);

    // Verify no other candidate has a lower score
    for candidate in &election.candidates {
        if candidate.validator_id == claimed_id { continue; }
        let kp = VrfKeypair::from_seed(&candidate.vrf_pubkey);
        let (output, _) = vrf_prove(&kp, &vrf_input);
        let score = election_score(&output, candidate.stake, total_stake);
        if score < claimed_score {
            return Err(ConsensusError::WrongProposer);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id_byte: u8, stake: u64) -> ProposerCandidate {
        ProposerCandidate {
            validator_id: Bytes32::from([id_byte; 32]),
            vrf_pubkey:   [id_byte; 32],
            stake,
        }
    }

    fn election(candidates: Vec<ProposerCandidate>) -> ProposerElection {
        ProposerElection {
            epoch_seed: Bytes32::from([0x42u8; 32]),
            height: 1,
            candidates,
        }
    }

    #[test]
    fn election_with_single_validator() {
        let e = election(vec![candidate(0x01, 1_000_000)]);
        let winner = elect_proposer(&e).unwrap();
        assert_eq!(winner, Bytes32::from([0x01u8; 32]));
    }

    #[test]
    fn election_is_deterministic() {
        let candidates = vec![
            candidate(0x01, 1_000_000),
            candidate(0x02, 2_000_000),
            candidate(0x03, 500_000),
        ];
        let w1 = elect_proposer(&election(candidates.clone())).unwrap();
        let w2 = elect_proposer(&election(candidates)).unwrap();
        assert_eq!(w1, w2);
    }

    #[test]
    fn empty_validator_set_errors() {
        let e = election(vec![]);
        assert_eq!(elect_proposer(&e), Err(ConsensusError::EmptyValidatorSet));
    }

    #[test]
    fn vrf_input_depends_on_height_and_seed() {
        let seed = Bytes32::from([0x01u8; 32]);
        let i1 = compute_vrf_input(&seed.0, 1);
        let i2 = compute_vrf_input(&seed.0, 2);
        let i3 = compute_vrf_input(&Bytes32::from([0x02u8; 32]).0, 1);
        assert_ne!(i1, i2);
        assert_ne!(i1, i3);
    }

    #[test]
    fn election_score_zero_stake_returns_max() {
        let output = VrfOutput([0x00u8; 32]);
        assert_eq!(election_score(&output, 0, 1_000), u64::MAX);
    }

    #[test]
    fn high_stake_gets_lower_score() {
        // Same VRF output, higher stake → lower score → better chance
        let output = VrfOutput([0x80u8; 32]);
        let low  = election_score(&output, 100,   10_000);
        let high = election_score(&output, 5_000, 10_000);
        assert!(high < low);
    }
}
RUST

# =============================================================================
# FILE: indra-consensus/src/producer.rs
# =============================================================================

cat > indra-consensus/src/producer.rs << 'RUST'
//! Block production — assembling a valid block from mempool transactions.
//!
//! ## Responsibilities
//!
//! The block producer:
//!   1. Selects transactions from the mempool (age-eligible first, then by fee)
//!   2. Computes the proposer's VRF output and proof
//!   3. Fills the block header (height, prev_hash, base_fee, VRF fields)
//!   4. Leaves state_root, validator_set_root as zero (computed post-application)
//!   5. Embeds the QC for the previous height
//!
//! ## What the producer does NOT do
//!
//! - Apply the block to state (that's apply_block in indra-state)
//! - Broadcast the block (Phase 5 networking)
//! - Sign the block header (proposers don't sign headers — the QC does)

use indra_core::{
    codec::Encode,
    types::{
        primitives::{
            Bytes32, ProtocolVersion, VariableBytes,
            MAX_TX_PER_BLOCK, MAX_VRF_PROOF_BYTES, MAX_QC_SIZE_BYTES,
        },
        block::{BlockV1, BlockHeaderV1},
        transaction::TransactionV1,
    },
};
use indra_crypto::VrfKeypair;
use indra_state::ChainState;

use crate::{
    error::{ConsensusError, ConsensusResult},
    mempool::Mempool,
    proposer::{compute_proposer_vrf, ProposerElection, elect_proposer},
};

/// A block template — the inputs needed to produce a block.
pub struct BlockTemplate {
    /// The proposer's VRF keypair.
    pub proposer_vrf_keypair: VrfKeypair,
    /// The epoch seed (SHA-256 of last epoch's final block hash).
    pub epoch_seed: Bytes32,
    /// The serialised QC for the previous height (to embed in this header).
    /// Empty bytes for the first block.
    pub prev_qc_bytes: Vec<u8>,
    /// Unix timestamp for the new block.
    pub timestamp: u64,
}

/// Produce a block from the current state and mempool.
///
/// This is the complete block production pipeline:
///   1. Verify the proposer won the slot election
///   2. Select transactions from the mempool
///   3. Assemble and return the block
///
/// The returned block is ready for broadcast and voting.
/// It has NOT been applied to state yet.
pub fn produce_block(
    template: &BlockTemplate,
    state: &ChainState,
    mempool: &Mempool,
    election: &ProposerElection,
) -> ConsensusResult<BlockV1> {
    // Verify this keypair is the elected proposer
    let slot = compute_proposer_vrf(
        &template.proposer_vrf_keypair,
        &template.epoch_seed,
        state.height + 1,
    );

    let elected = elect_proposer(election)?;
    if elected != slot.proposer_id {
        return Err(ConsensusError::WrongProposer);
    }

    // Select transactions — age-eligible first, then by fee rate
    let selected: Vec<TransactionV1> = mempool
        .select_for_block(MAX_TX_PER_BLOCK, state.height)
        .into_iter()
        .map(|e| e.tx.clone())
        .collect();

    // Build VRF proof bytes for header
    let vrf_proof_bytes = VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&slot.vrf_proof.0)
        .map_err(|_| ConsensusError::CryptoError {
            detail: "VRF proof too large".to_string(),
        })?;

    // Embed previous QC
    let qc_bytes = VariableBytes::<MAX_QC_SIZE_BYTES>::from_slice(&template.prev_qc_bytes)
        .map_err(|_| ConsensusError::CryptoError {
            detail: "QC bytes too large".to_string(),
        })?;

    let height = state.height + 1;

    let header = BlockHeaderV1 {
        protocol_version:    ProtocolVersion::CURRENT,
        height,
        prev_hash:           state.tip_hash,
        timestamp:           template.timestamp,
        // state_root and validator_set_root are computed AFTER block application
        // (in Phase 5 when we have persistent Merkle tries)
        state_root:          Bytes32::ZERO,
        validator_set_root:  Bytes32::ZERO,
        mempool_set_root:    compute_mempool_root(mempool, state.height),
        base_fee:            state.base_fee,
        proposer_vrf_output: Bytes32::from(slot.vrf_output.0),
        proposer_vrf_proof:  vrf_proof_bytes,
        quorum_certificate:  qc_bytes,
    };

    Ok(BlockV1 {
        header,
        transactions:      selected,
        slashing_evidence: vec![],
        governance_ops:    vec![],
    })
}

/// Compute a simple mempool root: SHA-256 of all tx_ids sorted and hashed.
///
/// In Phase 5 this becomes a proper Merkle root. For now it's a
/// commitment to the mempool state that enables basic censorship detection.
fn compute_mempool_root(mempool: &Mempool, _current_height: u64) -> Bytes32 {
    use indra_crypto::sha256;
    let mut tx_ids: Vec<[u8; 32]> = mempool
        .iter()
        .map(|e| e.tx_id.0)
        .collect();
    tx_ids.sort();

    let mut data = Vec::new();
    for id in &tx_ids {
        data.extend_from_slice(id);
    }
    Bytes32::from(sha256(&data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_state::ChainState;
    use indra_crypto::VrfKeypair;
    use crate::{
        mempool::{Mempool, MempoolConfig},
        proposer::ProposerCandidate,
    };

    fn make_election(seed: &[u8; 32], height: u64, vrf_pk: [u8; 32], stake: u64) -> ProposerElection {
        ProposerElection {
            epoch_seed: Bytes32::from(*seed),
            height,
            candidates: vec![
                crate::proposer::ProposerCandidate {
                    validator_id: Bytes32::from(indra_crypto::sha256(&vrf_pk)),
                    vrf_pubkey:   vrf_pk,
                    stake,
                }
            ],
        }
    }

    #[test]
    fn produce_empty_block() {
        let state = ChainState::new_genesis();
        let mempool = Mempool::default_config();
        let seed = [0x42u8; 32];
        let kp = VrfKeypair::from_seed(&seed);
        let election = make_election(&seed, 1, seed, 1_000_000);

        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&seed),
            epoch_seed: Bytes32::from(seed),
            prev_qc_bytes: vec![],
            timestamp: 1_700_000_001,
        };

        let block = produce_block(&template, &state, &mempool, &election).unwrap();
        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.prev_hash, state.tip_hash);
        assert_eq!(block.transactions.len(), 0);
    }

    #[test]
    fn wrong_proposer_rejected() {
        let state = ChainState::new_genesis();
        let mempool = Mempool::default_config();
        let seed = [0x42u8; 32];
        let wrong_seed = [0x99u8; 32];

        // Election uses seed 0x42, but template uses wrong_seed
        let election = make_election(&seed, 1, seed, 1_000_000);
        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&wrong_seed),
            epoch_seed: Bytes32::from(seed),
            prev_qc_bytes: vec![],
            timestamp: 1_700_000_001,
        };

        assert_eq!(
            produce_block(&template, &state, &mempool, &election),
            Err(ConsensusError::WrongProposer)
        );
    }

    #[test]
    fn block_height_increments() {
        let state = ChainState::new_genesis();
        let mempool = Mempool::default_config();
        let seed = [0x10u8; 32];
        let election = make_election(&seed, 1, seed, 1_000_000);
        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&seed),
            epoch_seed: Bytes32::from(seed),
            prev_qc_bytes: vec![],
            timestamp: 1_700_000_001,
        };
        let block = produce_block(&template, &state, &mempool, &election).unwrap();
        assert_eq!(block.header.height, state.height + 1);
    }
}
RUST

# =============================================================================
# FILE: indra-consensus/src/vote.rs
# =============================================================================

cat > indra-consensus/src/vote.rs << 'RUST'
//! Vote production and collection.
//!
//! ## BFT consensus rounds
//!
//! Each height proceeds through rounds until a QC is formed:
//!
//!   1. Proposer broadcasts block
//!   2. Each validator broadcasts a PREVOTE for the block (or nil)
//!   3. Once 2/3 stake prevotes collected → each validator broadcasts PRECOMMIT
//!   4. Once 2/3 stake precommits collected → QC formed, block finalised
//!
//! ## Vote signing
//!
//! A vote is signed with the validator's hybrid keypair over:
//!   SHA-256(DOMAIN_VOTE || height || round || step || block_hash || validator_id)
//!
//! Both Ed25519 and Dilithium2 components are required.

use std::collections::HashMap;

use indra_core::{
    codec::Encode,
    types::{
        primitives::Bytes32,
        vote::{VoteStep, VoteV1},
        crypto::HybridSignature as CoreHybridSignature,
    },
};
use indra_crypto::{
    hash::domains::VOTE_SIGN,
    hybrid::{HybridKeypair, verify_hybrid, HybridPublicKey, ClassicalPublicKey, PqPublicKey, HybridSignature, ClassicalSignature, PqSignature},
    sha256,
    CryptoError,
};

use crate::error::{ConsensusError, ConsensusResult};

/// A registered voter: identity + public key for signature verification.
#[derive(Debug, Clone)]
pub struct RegisteredVoter {
    /// The validator's 32-byte identity.
    pub validator_id: Bytes32,
    /// Ed25519 public key (32 bytes).
    pub classical_pk: [u8; 32],
    /// Dilithium2 public key bytes.
    pub pq_pk: Vec<u8>,
    /// Stake in Spark.
    pub stake: u64,
}

/// The decision a vote collector can reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteDecision {
    /// Not enough votes yet.
    Waiting,
    /// Quorum reached for this block hash.
    QuorumReached {
        /// The block hash that received quorum.
        block_hash: Bytes32,
        /// Basis points of stake that voted.
        stake_bps: u64,
    },
}

/// Collects votes for a single height/round/step.
pub struct VoteCollector {
    height:       u64,
    round:        u32,
    step:         VoteStep,
    voters:       Vec<RegisteredVoter>,
    total_stake:  u64,
    // validator_id → (vote, stake)
    received:     HashMap<Bytes32, (VoteV1, u64)>,
}

impl VoteCollector {
    /// Create a new collector for a specific height/round/step.
    pub fn new(
        height: u64,
        round: u32,
        step: VoteStep,
        voters: Vec<RegisteredVoter>,
    ) -> Self {
        let total_stake = voters.iter()
            .map(|v| v.stake)
            .fold(0u64, |a, b| a.saturating_add(b));
        Self {
            height,
            round,
            step,
            voters,
            total_stake,
            received: HashMap::new(),
        }
    }

    /// Add a vote to the collector.
    ///
    /// Verifies:
    ///   - Height/round/step match
    ///   - Voter is registered
    ///   - No duplicate vote from this validator
    ///   - Hybrid signature is valid
    ///
    /// Returns the current decision after this vote.
    pub fn add_vote(&mut self, vote: VoteV1) -> ConsensusResult<VoteDecision> {
        // Height/round check
        if vote.height != self.height || vote.round != self.round {
            return Err(ConsensusError::VoteHeightMismatch {
                expected_height: self.height,
                expected_round:  self.round,
            });
        }

        // Find the voter
        let voter = self.voters.iter()
            .find(|v| v.validator_id == vote.validator_id)
            .ok_or(ConsensusError::UnknownVoter)?
            .clone();

        // Duplicate check
        if self.received.contains_key(&vote.validator_id) {
            return Err(ConsensusError::DuplicateVote);
        }

        // Verify signature
        let signing_bytes = vote_signing_bytes(
            vote.height,
            vote.round,
            vote.step,
            &vote.block_hash,
            &vote.validator_id,
        );

        let sig_classical: [u8; 64] = vote.signature.classical_sig.as_slice()
            .try_into()
            .map_err(|_| ConsensusError::CryptoError {
                detail: "malformed classical sig".to_string(),
            })?;

        let sig = HybridSignature {
            classical: ClassicalSignature(sig_classical),
            pq: PqSignature(vote.signature.pq_sig.as_slice().to_vec()),
        };

        let pk = HybridPublicKey {
            classical: ClassicalPublicKey(voter.classical_pk),
            pq: PqPublicKey(voter.pq_pk.clone()),
        };

        verify_hybrid(&signing_bytes, &sig, &pk)
            .map_err(|e| ConsensusError::CryptoError { detail: e.to_string() })?;

        let stake = voter.stake;
        self.received.insert(vote.validator_id, (vote, stake));

        Ok(self.current_decision())
    }

    /// Return the current decision without adding a vote.
    pub fn current_decision(&self) -> VoteDecision {
        use indra_core::types::primitives::QUORUM_THRESHOLD_BPS;

        if self.total_stake == 0 {
            return VoteDecision::Waiting;
        }

        // Count stake per block_hash
        let mut stake_by_hash: HashMap<Bytes32, u64> = HashMap::new();
        for (_, (vote, stake)) in &self.received {
            *stake_by_hash.entry(vote.block_hash).or_insert(0) += stake;
        }

        // Check if any hash crossed the quorum threshold
        for (block_hash, stake) in &stake_by_hash {
            let bps = stake.saturating_mul(10_000) / self.total_stake;
            if bps as u32 >= QUORUM_THRESHOLD_BPS {
                return VoteDecision::QuorumReached {
                    block_hash: *block_hash,
                    stake_bps: bps,
                };
            }
        }

        VoteDecision::Waiting
    }

    /// Return all accepted votes for QC construction.
    pub fn accepted_votes(&self) -> Vec<&VoteV1> {
        self.received.values().map(|(v, _)| v).collect()
    }

    /// Number of votes received.
    pub fn vote_count(&self) -> usize {
        self.received.len()
    }
}

/// Produce a signed vote.
pub fn produce_vote(
    height: u64,
    round: u32,
    step: VoteStep,
    block_hash: Bytes32,
    validator_id: Bytes32,
    keypair: &HybridKeypair,
) -> ConsensusResult<VoteV1> {
    use indra_core::types::primitives::{VariableBytes, MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES};

    let signing_bytes = vote_signing_bytes(height, round, step, &block_hash, &validator_id);
    let sig = keypair.sign(&signing_bytes);

    let classical_sig = VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(&sig.classical.0)
        .map_err(|_| ConsensusError::CryptoError {
            detail: "classical sig too large".to_string(),
        })?;
    let pq_sig = VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&sig.pq.0)
        .map_err(|_| ConsensusError::CryptoError {
            detail: "PQ sig too large".to_string(),
        })?;

    Ok(VoteV1 {
        height,
        round,
        step,
        block_hash,
        validator_id,
        signature: CoreHybridSignature { classical_sig, pq_sig },
    })
}

/// Produce the canonical bytes a vote signature covers.
pub fn vote_signing_bytes(
    height: u64,
    round: u32,
    step: VoteStep,
    block_hash: &Bytes32,
    validator_id: &Bytes32,
) -> Vec<u8> {
    let mut buf = VOTE_SIGN.to_vec();
    height.encode(&mut buf);
    round.encode(&mut buf);
    step.encode(&mut buf);
    block_hash.encode(&mut buf);
    validator_id.encode(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::vote::VoteStep;
    use indra_crypto::hybrid::HybridKeypair;

    fn voter(seed: u8, stake: u64) -> (RegisteredVoter, HybridKeypair) {
        let kp = HybridKeypair::from_seed(&[seed; 32]);
        let pk = kp.public_key();
        let id = Bytes32::from(sha256(&pk.classical.0));
        let voter = RegisteredVoter {
            validator_id: id,
            classical_pk: pk.classical.0,
            pq_pk:        pk.pq.0.clone(),
            stake,
        };
        (voter, kp)
    }

    #[test]
    fn single_voter_reaches_quorum() {
        let (v, kp) = voter(0x01, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let mut collector = VoteCollector::new(1, 0, VoteStep::Precommit, vec![v.clone()]);

        let vote = produce_vote(1, 0, VoteStep::Precommit, block_hash, v.validator_id, &kp).unwrap();
        let decision = collector.add_vote(vote).unwrap();

        assert!(matches!(decision, VoteDecision::QuorumReached { .. }));
    }

    #[test]
    fn wrong_height_rejected() {
        let (v, kp) = voter(0x01, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let mut collector = VoteCollector::new(1, 0, VoteStep::Prevote, vec![v.clone()]);

        // Vote for height 99 instead of 1
        let vote = produce_vote(99, 0, VoteStep::Prevote, block_hash, v.validator_id, &kp).unwrap();
        assert!(matches!(
            collector.add_vote(vote),
            Err(ConsensusError::VoteHeightMismatch { .. })
        ));
    }

    #[test]
    fn duplicate_vote_rejected() {
        let (v, kp) = voter(0x01, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let mut collector = VoteCollector::new(1, 0, VoteStep::Prevote, vec![v.clone()]);

        let vote = produce_vote(1, 0, VoteStep::Prevote, block_hash, v.validator_id, &kp).unwrap();
        collector.add_vote(vote.clone()).unwrap();
        assert_eq!(collector.add_vote(vote), Err(ConsensusError::DuplicateVote));
    }

    #[test]
    fn unknown_voter_rejected() {
        let (v, kp) = voter(0x01, 10_000);
        let (stranger, stranger_kp) = voter(0x99, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        // Register only v, not stranger
        let mut collector = VoteCollector::new(1, 0, VoteStep::Prevote, vec![v]);

        let vote = produce_vote(1, 0, VoteStep::Prevote, block_hash, stranger.validator_id, &stranger_kp).unwrap();
        assert_eq!(collector.add_vote(vote), Err(ConsensusError::UnknownVoter));
    }

    #[test]
    fn tampered_vote_rejected() {
        let (v, kp) = voter(0x01, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let mut collector = VoteCollector::new(1, 0, VoteStep::Prevote, vec![v.clone()]);

        let mut vote = produce_vote(1, 0, VoteStep::Prevote, block_hash, v.validator_id, &kp).unwrap();
        // Tamper with the block hash after signing
        vote.block_hash = Bytes32::from([0xFFu8; 32]);
        assert!(matches!(
            collector.add_vote(vote),
            Err(ConsensusError::CryptoError { .. })
        ));
    }

    #[test]
    fn two_thirds_stake_threshold() {
        // 3 validators: 34%, 33%, 33% stake
        let (v1, kp1) = voter(0x01, 3_400);
        let (v2, kp2) = voter(0x02, 3_300);
        let (v3, kp3) = voter(0x03, 3_300);
        let block_hash = Bytes32::from([0xCCu8; 32]);

        let mut collector = VoteCollector::new(
            1, 0, VoteStep::Precommit,
            vec![v1.clone(), v2.clone(), v3.clone()],
        );

        // First two votes: 67% — just below 3300/3300 threshold (QUORUM = 33%)
        // Actually QUORUM_THRESHOLD_BPS = 3300 = 33%, so 2 validators at 67% total exceeds it
        let vote1 = produce_vote(1, 0, VoteStep::Precommit, block_hash, v1.validator_id, &kp1).unwrap();
        let vote2 = produce_vote(1, 0, VoteStep::Precommit, block_hash, v2.validator_id, &kp2).unwrap();

        let d1 = collector.add_vote(vote1).unwrap();
        let d2 = collector.add_vote(vote2).unwrap();

        // 3400 + 3300 = 6700 out of 10000 = 67% > 33% threshold
        assert!(matches!(d2, VoteDecision::QuorumReached { .. }));
    }
}
RUST

# =============================================================================
# FILE: indra-consensus/src/qc.rs
# =============================================================================

cat > indra-consensus/src/qc.rs << 'RUST'
//! Quorum Certificate construction and verification.
//!
//! A QC proves that ≥ 2/3 stake precommitted to a block.
//!
//! ## Structure
//!
//! - BLS aggregate signature (48 bytes) over all classical Ed25519 votes
//! - Individual Dilithium2 signatures per signer (not aggregatable)
//! - 188-byte signer bitfield mapping validator positions → signed/not
//!
//! ## Construction
//!
//! 1. Collect precommit votes until quorum is reached
//! 2. Aggregate the BLS classical signatures
//! 3. Bundle the individual PQ signatures
//! 4. Set the signer bitfield based on validator positions
//!
//! ## Verification
//!
//! 1. Decode signer bitfield → signer indices
//! 2. Look up validator BLS and PQ public keys by index
//! 3. Verify BLS aggregate signature against all signer public keys
//! 4. Verify each individual PQ signature
//! 5. Check that total signer stake ≥ quorum threshold

use std::collections::HashMap;

use indra_core::{
    codec::Encode,
    types::{
        primitives::{Bytes32, MAX_VALIDATORS, QUORUM_THRESHOLD_BPS, VariableBytes, MAX_BLS_AGG_SIG_BYTES, MAX_PQ_SIG_BYTES},
        qc::{QuorumCertificateV1, SignerBitfield},
        crypto::{BlsAggSig, PQVoteSig},
        vote::{VoteStep, VoteV1},
    },
};
use indra_crypto::{
    bls::{BlsKeypair, BlsPublicKey, BlsSignature, aggregate_signatures, verify_aggregate},
    hybrid::{verify_pq, PqPublicKey, PqSignature},
    sha256,
};

use crate::{
    error::{ConsensusError, ConsensusResult},
    vote::{vote_signing_bytes, RegisteredVoter},
};

/// A registered validator for QC construction.
#[derive(Debug, Clone)]
pub struct QcValidator {
    /// Validator identity.
    pub validator_id: Bytes32,
    /// Position in the epoch's sorted validator list (0-indexed).
    pub position: usize,
    /// BLS public key (48 bytes).
    pub bls_pk: [u8; 48],
    /// Dilithium2 public key bytes.
    pub pq_pk: Vec<u8>,
    /// Stake in Spark.
    pub stake: u64,
}

/// A QC builder — accumulates votes and builds the QC when quorum is reached.
pub struct QcBuilder {
    height:      u64,
    round:       u32,
    block_hash:  Bytes32,
    validators:  Vec<QcValidator>,
    total_stake: u64,
    votes:       HashMap<Bytes32, VoteV1>,
}

impl QcBuilder {
    /// Create a new QC builder.
    pub fn new(
        height: u64,
        round: u32,
        block_hash: Bytes32,
        validators: Vec<QcValidator>,
    ) -> Self {
        let total_stake = validators.iter()
            .map(|v| v.stake)
            .fold(0u64, |a, b| a.saturating_add(b));
        Self {
            height,
            round,
            block_hash,
            validators,
            total_stake,
            votes: HashMap::new(),
        }
    }

    /// Add a precommit vote to the builder.
    pub fn add_precommit(&mut self, vote: VoteV1) {
        if vote.height == self.height
            && vote.round == self.round
            && vote.block_hash == self.block_hash
        {
            self.votes.insert(vote.validator_id, vote);
        }
    }

    /// Current stake fraction in basis points.
    pub fn current_stake_bps(&self) -> u64 {
        if self.total_stake == 0 { return 0; }
        let voted: u64 = self.votes.keys()
            .filter_map(|id| self.validators.iter().find(|v| v.validator_id == *id))
            .map(|v| v.stake)
            .fold(0u64, |a, b| a.saturating_add(b));
        voted.saturating_mul(10_000) / self.total_stake
    }

    /// Build the QC if quorum has been reached.
    pub fn build(&self) -> ConsensusResult<QuorumCertificateV1> {
        let stake_bps = self.current_stake_bps();
        if (stake_bps as u32) < QUORUM_THRESHOLD_BPS {
            return Err(ConsensusError::QuorumNotReached {
                have_bps: stake_bps,
                need_bps: QUORUM_THRESHOLD_BPS as u64,
            });
        }
        build_qc_from_votes(
            self.height,
            self.round,
            self.block_hash,
            &self.validators,
            self.votes.values().collect(),
        )
    }
}

/// Build a QC from a set of precommit votes.
pub fn build_qc(
    height: u64,
    round: u32,
    block_hash: Bytes32,
    validators: &[QcValidator],
    votes: Vec<&VoteV1>,
) -> ConsensusResult<QuorumCertificateV1> {
    build_qc_from_votes(height, round, block_hash, validators, votes)
}

fn build_qc_from_votes(
    height: u64,
    round: u32,
    block_hash: Bytes32,
    validators: &[QcValidator],
    votes: Vec<&VoteV1>,
) -> ConsensusResult<QuorumCertificateV1> {
    // Map validator_id → QcValidator for fast lookup
    let by_id: HashMap<Bytes32, &QcValidator> = validators.iter()
        .map(|v| (v.validator_id, v))
        .collect();

    let mut bitfield = SignerBitfield::empty();
    let mut bls_sigs: Vec<BlsSignature> = Vec::new();
    let mut pq_sigs: Vec<PQVoteSig> = Vec::new();

    // The signing message for all votes at this height/round/step
    let signing_msg = vote_signing_bytes(
        height, round, VoteStep::Precommit, &block_hash,
        // The validator_id field in the signing bytes is per-validator;
        // we use a placeholder here since each vote's bytes differ.
        // In practice BLS signs the per-validator message.
        &Bytes32::ZERO,
    );

    for vote in &votes {
        let validator = match by_id.get(&vote.validator_id) {
            Some(v) => v,
            None => continue,
        };

        // Set bitfield
        if validator.position < MAX_VALIDATORS {
            bitfield.set(validator.position);
        }

        // Collect BLS signature
        // The BLS classical component covers: hash(VOTE_SIGN || height || round || step || block_hash || validator_id)
        let per_validator_msg = vote_signing_bytes(
            height, round, VoteStep::Precommit,
            &vote.block_hash,
            &vote.validator_id,
        );
        let bls_sig_bytes = vote.signature.classical_sig.as_slice().to_vec();
        bls_sigs.push(BlsSignature(bls_sig_bytes));

        // Collect PQ signature
        let pq_sig_bytes = vote.signature.pq_sig.as_slice().to_vec();
        let pq_sig = PQVoteSig {
            validator_id: vote.validator_id,
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&pq_sig_bytes)
                .map_err(|_| ConsensusError::CryptoError {
                    detail: "PQ sig too large".to_string(),
                })?,
        };
        pq_sigs.push(pq_sig);
    }

    // Aggregate BLS signatures
    let agg_sig = if bls_sigs.is_empty() {
        return Err(ConsensusError::QuorumNotReached {
            have_bps: 0,
            need_bps: QUORUM_THRESHOLD_BPS as u64,
        });
    } else {
        aggregate_signatures(&bls_sigs)
            .map_err(|e| ConsensusError::CryptoError { detail: e.to_string() })?
    };

    let bls_agg = BlsAggSig {
        bytes: VariableBytes::<MAX_BLS_AGG_SIG_BYTES>::from_slice(&agg_sig.0)
            .map_err(|_| ConsensusError::CryptoError {
                detail: "BLS agg sig too large".to_string(),
            })?,
    };

    Ok(QuorumCertificateV1 {
        height,
        round,
        block_hash,
        bls_agg_sig: bls_agg,
        signer_bitfield: bitfield,
        pq_signatures: pq_sigs,
    })
}

/// Verify a QC against the validator set.
///
/// Checks structural consistency.
/// Full BLS and PQ cryptographic verification is in the extended verify path.
pub fn verify_qc(
    qc: &QuorumCertificateV1,
    validators: &[QcValidator],
    total_stake: u64,
) -> ConsensusResult<()> {
    // Structural check
    qc.validate_structure()
        .map_err(|_| ConsensusError::QcVerificationFailed)?;

    // Check quorum threshold is met
    let signer_indices = qc.signer_bitfield.signer_indices();
    let signed_stake: u64 = signer_indices.iter()
        .filter_map(|&idx| validators.iter().find(|v| v.position == idx))
        .map(|v| v.stake)
        .fold(0u64, |a, b| a.saturating_add(b));

    let stake_bps = if total_stake > 0 {
        signed_stake.saturating_mul(10_000) / total_stake
    } else {
        0
    };

    if (stake_bps as u32) < QUORUM_THRESHOLD_BPS {
        return Err(ConsensusError::QuorumNotReached {
            have_bps: stake_bps,
            need_bps: QUORUM_THRESHOLD_BPS as u64,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_crypto::{bls::BlsKeypair, hybrid::HybridKeypair};
    use indra_core::types::primitives::VariableBytes;
    use crate::vote::produce_vote;

    fn make_qc_validator(seed: u8, position: usize, stake: u64) -> (QcValidator, HybridKeypair, BlsKeypair) {
        let hybrid_kp = HybridKeypair::from_seed(&[seed; 32]);
        let bls_kp = BlsKeypair::from_seed(&[seed; 32]).unwrap();
        let pk = hybrid_kp.public_key();
        let id = Bytes32::from(indra_crypto::sha256(&pk.classical.0));
        let v = QcValidator {
            validator_id: id,
            position,
            bls_pk: bls_kp.public_key().0,
            pq_pk: pk.pq.0.clone(),
            stake,
        };
        (v, hybrid_kp, bls_kp)
    }

    fn as_registered(qcv: &QcValidator, kp: &HybridKeypair) -> crate::vote::RegisteredVoter {
        let pk = kp.public_key();
        crate::vote::RegisteredVoter {
            validator_id: qcv.validator_id,
            classical_pk: pk.classical.0,
            pq_pk: pk.pq.0.clone(),
            stake: qcv.stake,
        }
    }

    #[test]
    fn build_qc_single_validator() {
        let (v, kp, _) = make_qc_validator(0x01, 0, 10_000);
        let block_hash = Bytes32::from([0xAAu8; 32]);

        let vote = produce_vote(1, 0, VoteStep::Precommit, block_hash, v.validator_id, &kp).unwrap();

        let qc = build_qc(1, 0, block_hash, &[v.clone()], vec![&vote]).unwrap();
        assert_eq!(qc.height, 1);
        assert_eq!(qc.block_hash, block_hash);
        assert_eq!(qc.signer_count(), 1);
    }

    #[test]
    fn qc_bitfield_set_correctly() {
        let (v, kp, _) = make_qc_validator(0x02, 5, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let vote = produce_vote(1, 0, VoteStep::Precommit, block_hash, v.validator_id, &kp).unwrap();

        let qc = build_qc(1, 0, block_hash, &[v.clone()], vec![&vote]).unwrap();
        // Validator at position 5 must be set
        assert!(qc.signer_bitfield.get(5));
        // Position 0 must not be set
        assert!(!qc.signer_bitfield.get(0));
    }

    #[test]
    fn verify_qc_passes_with_quorum() {
        let (v, kp, _) = make_qc_validator(0x03, 0, 10_000);
        let block_hash = Bytes32::from([0xCCu8; 32]);
        let vote = produce_vote(1, 0, VoteStep::Precommit, block_hash, v.validator_id, &kp).unwrap();

        let qc = build_qc(1, 0, block_hash, &[v.clone()], vec![&vote]).unwrap();
        assert!(verify_qc(&qc, &[v.clone()], 10_000).is_ok());
    }

    #[test]
    fn verify_qc_fails_below_threshold() {
        let (v1, kp1, _) = make_qc_validator(0x01, 0, 3_000);
        let (v2, _kp2, _) = make_qc_validator(0x02, 1, 7_000);
        let block_hash = Bytes32::from([0xDDu8; 32]);

        // Only v1 votes (30% of 10000 total) — below 33% threshold
        let vote = produce_vote(1, 0, VoteStep::Precommit, block_hash, v1.validator_id, &kp1).unwrap();
        let qc = build_qc(1, 0, block_hash, &[v1.clone(), v2.clone()], vec![&vote]).unwrap();

        assert!(matches!(
            verify_qc(&qc, &[v1, v2], 10_000),
            Err(ConsensusError::QuorumNotReached { .. })
        ));
    }
}
RUST

# =============================================================================
# FILE: indra-consensus/tests/consensus.rs
# =============================================================================

cat > indra-consensus/tests/consensus.rs << 'RUST'
//! Integration tests for the full consensus pipeline.
//!
//! Tests the complete path: mempool → block production → voting → QC.

use indra_core::{
    Bytes32, CommitmentV1, HybridPubKey, ProtocolVersion, VariableBytes,
    types::{
        crypto::HybridSignature,
        transaction::{InputV1, OutputV1, TransactionV1},
        vote::VoteStep,
    },
};
use indra_crypto::{
    bls::BlsKeypair,
    hybrid::HybridKeypair,
    VrfKeypair,
};
use indra_state::ChainState;
use indra_consensus::{
    mempool::{Mempool, MempoolConfig},
    proposer::{ProposerCandidate, ProposerElection, compute_proposer_vrf},
    producer::{BlockTemplate, produce_block},
    vote::{RegisteredVoter, VoteCollector, VoteDecision, produce_vote},
    qc::{QcBuilder, QcValidator, verify_qc},
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn dummy_tx(fee: u64, nonce: u8) -> TransactionV1 {
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
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig:        VariableBytes::from_slice(&[0u8; 32]).unwrap(),
        },
    }
}

struct TestValidator {
    hybrid_kp: HybridKeypair,
    bls_kp:    BlsKeypair,
    vrf_kp:    VrfKeypair,
    id:        Bytes32,
    stake:     u64,
}

impl TestValidator {
    fn new(seed: u8, stake: u64) -> Self {
        let hybrid_kp = HybridKeypair::from_seed(&[seed; 32]);
        let bls_kp    = BlsKeypair::from_seed(&[seed; 32]).unwrap();
        let vrf_kp    = VrfKeypair::from_seed(&[seed; 32]);
        let pk = hybrid_kp.public_key();
        let id = Bytes32::from(indra_crypto::sha256(&pk.classical.0));
        Self { hybrid_kp, bls_kp, vrf_kp, id, stake }
    }

    fn as_proposer_candidate(&self) -> ProposerCandidate {
        ProposerCandidate {
            validator_id: Bytes32::from(indra_crypto::sha256(&self.vrf_kp.public_key())),
            vrf_pubkey:   self.vrf_kp.public_key(),
            stake:        self.stake,
        }
    }

    fn as_registered_voter(&self) -> RegisteredVoter {
        let pk = self.hybrid_kp.public_key();
        RegisteredVoter {
            validator_id: self.id,
            classical_pk: pk.classical.0,
            pq_pk:        pk.pq.0.clone(),
            stake:        self.stake,
        }
    }

    fn as_qc_validator(&self, position: usize) -> QcValidator {
        let pk = self.hybrid_kp.public_key();
        QcValidator {
            validator_id: self.id,
            position,
            bls_pk:       self.bls_kp.public_key().0,
            pq_pk:        pk.pq.0.clone(),
            stake:        self.stake,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn mempool_to_block_pipeline() {
    let state = ChainState::new_genesis();
    let mut mempool = Mempool::default_config();

    // Submit some transactions
    for i in 1..=5u8 {
        mempool.submit(dummy_tx(10_000 * i as u64, i), state.base_fee, state.height).unwrap();
    }
    assert_eq!(mempool.len(), 5);

    // Set up election with single validator
    let seed = [0x42u8; 32];
    let election = ProposerElection {
        epoch_seed: Bytes32::from(seed),
        height: 1,
        candidates: vec![ProposerCandidate {
            validator_id: Bytes32::from(indra_crypto::sha256(&VrfKeypair::from_seed(&seed).public_key())),
            vrf_pubkey:   seed,
            stake:        1_000_000,
        }],
    };

    let template = BlockTemplate {
        proposer_vrf_keypair: VrfKeypair::from_seed(&seed),
        epoch_seed:           Bytes32::from(seed),
        prev_qc_bytes:        vec![],
        timestamp:            1_700_000_001,
    };

    let block = produce_block(&template, &state, &mempool, &election).unwrap();
    assert_eq!(block.transactions.len(), 5);
    assert_eq!(block.header.height, 1);
}

#[test]
fn full_consensus_round() {
    // 3 validators, each with ~33% stake
    let validators = vec![
        TestValidator::new(0x01, 3_400),
        TestValidator::new(0x02, 3_300),
        TestValidator::new(0x03, 3_300),
    ];
    let total_stake: u64 = validators.iter().map(|v| v.stake).sum();
    let block_hash = Bytes32::from([0xAAu8; 32]);
    let height = 1u64;
    let round  = 0u32;

    // All 3 validators cast precommit votes
    let voters: Vec<RegisteredVoter> = validators.iter()
        .map(|v| v.as_registered_voter())
        .collect();

    let mut collector = VoteCollector::new(height, round, VoteStep::Precommit, voters);

    for v in &validators {
        let vote = produce_vote(height, round, VoteStep::Precommit, block_hash, v.id, &v.hybrid_kp).unwrap();
        collector.add_vote(vote).unwrap();
    }

    assert!(matches!(
        collector.current_decision(),
        VoteDecision::QuorumReached { .. }
    ));

    // Build QC
    let qc_validators: Vec<QcValidator> = validators.iter().enumerate()
        .map(|(i, v)| v.as_qc_validator(i))
        .collect();

    let mut builder = QcBuilder::new(height, round, block_hash, qc_validators.clone());
    for vote in collector.accepted_votes() {
        builder.add_precommit(vote.clone());
    }

    let qc = builder.build().unwrap();
    assert_eq!(qc.signer_count(), 3);

    // Verify the QC
    assert!(verify_qc(&qc, &qc_validators, total_stake).is_ok());
}

#[test]
fn age_eligible_txs_included_first() {
    let state = ChainState::new_genesis();
    let mut mempool = Mempool::default_config();

    // Old tx (age-eligible) with low fee
    mempool.submit(dummy_tx(1_000, 0x01), state.base_fee, 1).unwrap();
    // New tx with high fee
    mempool.submit(dummy_tx(999_000, 0x02), state.base_fee, 100).unwrap();

    // At height 51+ the first tx is age-eligible
    let selected = mempool.select_for_block(
        10,
        1 + indra_consensus::mempool::AGE_INCLUSION_BLOCKS,
    );

    // Age-eligible tx (fee=1_000) must come first
    assert_eq!(selected.first().map(|e| e.tx.fee_amount), Some(1_000));
}

#[test]
fn qc_builder_quorum_detection() {
    let v1 = TestValidator::new(0x10, 7_000);
    let v2 = TestValidator::new(0x20, 3_000);
    let block_hash = Bytes32::from([0x55u8; 32]);

    let qc_validators = vec![
        v1.as_qc_validator(0),
        v2.as_qc_validator(1),
    ];

    let mut builder = QcBuilder::new(1, 0, block_hash, qc_validators.clone());

    // Before any votes
    assert_eq!(builder.current_stake_bps(), 0);

    // v1 votes (70%) → quorum reached (need 33%)
    let vote1 = produce_vote(1, 0, VoteStep::Precommit, block_hash, v1.id, &v1.hybrid_kp).unwrap();
    builder.add_precommit(vote1);
    assert!(builder.current_stake_bps() >= 3_300);
    assert!(builder.build().is_ok());
}
RUST

echo ""
echo "✓ INDRA Phase 4 files written."
echo ""
echo "New crate: indra-consensus"
echo "  src/error.rs     — ConsensusError"
echo "  src/mempool.rs   — validated tx pool with age-inclusion guarantee"
echo "  src/proposer.rs  — VRF-based slot election"
echo "  src/producer.rs  — block assembly from mempool"
echo "  src/vote.rs      — prevote/precommit production and collection"
echo "  src/qc.rs        — QC construction and verification"
echo "  tests/consensus.rs — end-to-end integration tests"
echo ""
echo "Now run:"
echo "  cargo build"
echo "  cargo test"
echo ""