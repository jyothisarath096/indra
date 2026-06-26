#!/usr/bin/env bash
# =============================================================================
# INDRA v2 — Phase 2 Setup Script
# State Machine: UTXO set, Nullifier set, Block application, Fee update,
#                Epoch transition
# =============================================================================
# Run from inside the indra/ workspace directory:
#
#   chmod +x setup_indra_phase2.sh
#   ./setup_indra_phase2.sh
#   cargo build
#   cargo test
#
# Prerequisites: Phase 1 must already be set up and passing.
# =============================================================================

set -euo pipefail

echo "==> Setting up INDRA Phase 2 — State Machine..."

# =============================================================================
# Add indra-state crate to workspace
# =============================================================================

# Update workspace Cargo.toml to include the new crate
cat > Cargo.toml << 'TOML'
[workspace]
members  = ["indra-core", "indra-crypto", "indra-state"]
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

# =============================================================================
# Create indra-state crate
# =============================================================================

mkdir -p indra-state/src

cat > indra-state/Cargo.toml << 'TOML'
[package]
name        = "indra-state"
description = "INDRA state machine — UTXO set, nullifier set, block application, epoch transitions"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
indra-core   = { path = "../indra-core" }
indra-crypto = { path = "../indra-crypto" }
thiserror.workspace = true

[dev-dependencies]
indra-core = { path = "../indra-core" }
TOML

# =============================================================================
# FILE: indra-state/src/lib.rs
# =============================================================================

cat > indra-state/src/lib.rs << 'RUST'
//! # indra-state
//!
//! The INDRA v2 state machine.
//!
//! ## What this crate does
//!
//! Takes a `BlockV1` and a `ChainState`, validates the block against the
//! current state, and produces a new `ChainState`. This is the core of the
//! protocol: everything else (networking, storage, consensus) exists to
//! feed blocks into this function.
//!
//! ## What this crate does NOT do (yet)
//!
//! - Cryptographic verification (signatures, range proofs, VRF) — Phase 3
//! - Disk persistence — Phase 5
//! - P2P networking — Phase 4
//!
//! All state lives in memory. This is intentional: get the logic correct
//! before adding storage complexity.
//!
//! ## Invariants
//!
//! - No unsafe code.
//! - No floating-point arithmetic. All fee/reward calculations use integer
//!   arithmetic with explicit rounding rules.
//! - Every state transition is deterministic: same (block, state) input
//!   always produces the same output state.
//! - A block is either applied completely or not at all. No partial state
//!   updates on error.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::indexing_slicing)]

pub mod error;
pub mod utxo;
pub mod nullifier;
pub mod validator;
pub mod chain;
pub mod apply;
pub mod fee;
pub mod epoch;

pub use error::{StateError, StateResult};
pub use utxo::{UtxoSet, UtxoEntry};
pub use nullifier::NullifierSet;
pub use validator::{ValidatorEntry, ValidatorSet, ValidatorStatus};
pub use chain::ChainState;
pub use apply::apply_block;
pub use fee::compute_next_base_fee;
pub use epoch::apply_epoch_transition;
RUST

# =============================================================================
# FILE: indra-state/src/error.rs
# =============================================================================

cat > indra-state/src/error.rs << 'RUST'
//! Error types for the state machine.

use thiserror::Error;

/// All errors that can occur during state transitions.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum StateError {
    // ── Block-level errors ─────────────────────────────────────────────────

    /// Block height is not exactly prev_height + 1.
    #[error("invalid block height: expected {expected}, got {actual}")]
    InvalidHeight {
        /// Expected height.
        expected: u64,
        /// Actual height in the block.
        actual: u64,
    },

    /// Block's prev_hash does not match the current tip hash.
    #[error("block prev_hash does not match current tip")]
    PrevHashMismatch,

    /// Block's protocol version is not supported.
    #[error("unsupported protocol version {version}")]
    UnsupportedVersion {
        /// The version found.
        version: u16,
    },

    /// Block exceeds the maximum permitted size.
    #[error("block {actual} bytes exceeds maximum {max} bytes")]
    BlockTooLarge {
        /// Actual encoded size.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Block contains more transactions than allowed.
    #[error("block contains {actual} transactions, maximum is {max}")]
    TooManyTransactions {
        /// Actual count.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Block's base_fee field does not match the computed value.
    #[error("block base_fee {block_fee} does not match computed {computed_fee}")]
    BaseFeeIncorrect {
        /// What the block claims.
        block_fee: u64,
        /// What we computed.
        computed_fee: u64,
    },

    // ── Transaction-level errors ───────────────────────────────────────────

    /// A transaction references a UTXO that does not exist.
    #[error("transaction references unknown UTXO")]
    UnknownUtxo,

    /// A transaction attempts to spend an already-spent nullifier.
    #[error("double-spend detected: nullifier already in nullifier set")]
    DoubleSpend,

    /// A transaction's fee is below the required base fee.
    #[error("transaction fee {actual} Spark/KB below required {required} Spark/KB")]
    FeeTooLow {
        /// Fee the transaction paid.
        actual: u64,
        /// Minimum required.
        required: u64,
    },

    /// A transaction has zero inputs.
    #[error("transaction has zero inputs")]
    ZeroInputs,

    /// A transaction has zero outputs.
    #[error("transaction has zero outputs")]
    ZeroOutputs,

    /// A transaction contains duplicate nullifiers.
    #[error("transaction contains duplicate nullifiers")]
    DuplicateNullifier,

    /// A block contains the same transaction twice.
    #[error("block contains duplicate transaction")]
    DuplicateTransaction,

    /// An output value is below the dust limit.
    #[error("output value below dust limit of {limit} Spark")]
    BelowDustLimit {
        /// The dust limit.
        limit: u64,
    },

    /// An output is locked and cannot be spent at the current height.
    #[error("output locked until height {lock_height}, current height {current_height}")]
    OutputLocked {
        /// When it unlocks.
        lock_height: u64,
        /// Current height.
        current_height: u64,
    },

    // ── State integrity errors ─────────────────────────────────────────────

    /// An invariant was violated. The node must halt.
    #[error("INVARIANT VIOLATION: {message}")]
    InvariantViolation {
        /// Description of the violated invariant.
        message: &'static str,
    },
}

/// Convenience alias.
pub type StateResult<T> = Result<T, StateError>;
RUST

# =============================================================================
# FILE: indra-state/src/utxo.rs
# =============================================================================

cat > indra-state/src/utxo.rs << 'RUST'
//! UTXO set — the set of all unspent transaction outputs.
//!
//! ## UTXO ID derivation
//!
//! Each output gets a deterministic ID:
//!
//!   utxo_id = SHA-256(
//!       encode(output)  ||
//!       u64_le(height)  ||
//!       u32_le(tx_idx)  ||
//!       u32_le(out_idx)
//!   )
//!
//! This is collision-resistant and position-dependent: the same output bytes
//! at different positions in the chain produce different IDs.
//!
//! ## Storage model (Phase 2)
//!
//! In-memory HashMap. Phase 5 replaces this with a persistent Merkle trie.
//! The interface is unchanged — only the backing store swaps out.

use std::collections::HashMap;

use indra_core::{
    codec::Encode,
    types::{
        primitives::Bytes32,
        transaction::OutputV1,
    },
};
use indra_crypto::sha256;

use crate::error::{StateError, StateResult};

/// A UTXO entry in the set: the output itself plus metadata.
#[derive(Debug, Clone)]
pub struct UtxoEntry {
    /// The output data.
    pub output: OutputV1,
    /// Block height at which this output was created.
    pub created_height: u64,
    /// Transaction index within that block.
    pub tx_index: u32,
    /// Output index within that transaction.
    pub output_index: u32,
}

/// The complete set of unspent transaction outputs.
///
/// Keyed by UTXO ID (32-byte hash). Supports insert, lookup, and spend.
/// All operations are O(1) average via HashMap.
#[derive(Debug, Clone, Default)]
pub struct UtxoSet {
    entries: HashMap<Bytes32, UtxoEntry>,
}

impl UtxoSet {
    /// Create an empty UTXO set.
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    /// Number of UTXOs currently in the set.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute the deterministic UTXO ID for an output at a given position.
    ///
    /// utxo_id = SHA-256(encode(output) || u64_le(height) || u32_le(tx_idx) || u32_le(out_idx))
    pub fn compute_utxo_id(
        output: &OutputV1,
        height: u64,
        tx_index: u32,
        output_index: u32,
    ) -> Bytes32 {
        let mut data = output.encode_to_vec();
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(&tx_index.to_le_bytes());
        data.extend_from_slice(&output_index.to_le_bytes());
        Bytes32::from(sha256(&data))
    }

    /// Insert a new output into the UTXO set.
    ///
    /// Returns the UTXO ID assigned to this output.
    /// Panics (via InvariantViolation) if the computed ID already exists —
    /// this would indicate a hash collision, which is computationally
    /// infeasible with SHA-256.
    pub fn insert(
        &mut self,
        output: OutputV1,
        height: u64,
        tx_index: u32,
        output_index: u32,
    ) -> StateResult<Bytes32> {
        let id = Self::compute_utxo_id(&output, height, tx_index, output_index);
        if self.entries.contains_key(&id) {
            return Err(StateError::InvariantViolation {
                message: "UTXO ID collision — SHA-256 collision or duplicate block application",
            });
        }
        self.entries.insert(id, UtxoEntry {
            output,
            created_height: height,
            tx_index,
            output_index,
        });
        Ok(id)
    }

    /// Look up a UTXO by ID without removing it.
    pub fn get(&self, id: &Bytes32) -> Option<&UtxoEntry> {
        self.entries.get(id)
    }

    /// Remove a UTXO from the set (mark as spent).
    ///
    /// Returns the entry if it existed, None if it was already absent.
    pub fn spend(&mut self, id: &Bytes32) -> Option<UtxoEntry> {
        self.entries.remove(id)
    }

    /// Check whether a UTXO exists (is unspent).
    pub fn contains(&self, id: &Bytes32) -> bool {
        self.entries.contains_key(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        Bytes32, CommitmentV1, HybridPubKey, VariableBytes,
        types::transaction::OutputV1,
    };

    fn dummy_output(byte: u8) -> OutputV1 {
        OutputV1 {
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from([byte; 32]),
            },
            owner_pubkey: HybridPubKey {
                classical_pk: Bytes32::from([byte; 32]),
                pq_pk: VariableBytes::from_slice(&[byte; 32]).unwrap(),
            },
            range_proof: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            lock_height: 0,
        }
    }

    #[test]
    fn insert_and_get() {
        let mut set = UtxoSet::new();
        let output = dummy_output(0x01);
        let id = set.insert(output.clone(), 1, 0, 0).unwrap();
        let entry = set.get(&id).unwrap();
        assert_eq!(entry.created_height, 1);
        assert_eq!(entry.tx_index, 0);
        assert_eq!(entry.output_index, 0);
    }

    #[test]
    fn spend_removes_utxo() {
        let mut set = UtxoSet::new();
        let id = set.insert(dummy_output(0x02), 1, 0, 0).unwrap();
        assert!(set.contains(&id));
        let entry = set.spend(&id);
        assert!(entry.is_some());
        assert!(!set.contains(&id));
    }

    #[test]
    fn spend_nonexistent_returns_none() {
        let mut set = UtxoSet::new();
        let fake_id = Bytes32::from([0xFFu8; 32]);
        assert!(set.spend(&fake_id).is_none());
    }

    #[test]
    fn utxo_id_is_position_dependent() {
        let output = dummy_output(0x42);
        let id1 = UtxoSet::compute_utxo_id(&output, 1, 0, 0);
        let id2 = UtxoSet::compute_utxo_id(&output, 1, 0, 1); // different output_index
        let id3 = UtxoSet::compute_utxo_id(&output, 2, 0, 0); // different height
        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
        assert_ne!(id2, id3);
    }

    #[test]
    fn utxo_id_is_deterministic() {
        let output = dummy_output(0x55);
        let id1 = UtxoSet::compute_utxo_id(&output, 100, 3, 7);
        let id2 = UtxoSet::compute_utxo_id(&output, 100, 3, 7);
        assert_eq!(id1, id2);
    }

    #[test]
    fn len_tracks_insertions_and_spends() {
        let mut set = UtxoSet::new();
        assert_eq!(set.len(), 0);
        let id1 = set.insert(dummy_output(0x01), 1, 0, 0).unwrap();
        let _id2 = set.insert(dummy_output(0x02), 1, 0, 1).unwrap();
        assert_eq!(set.len(), 2);
        set.spend(&id1);
        assert_eq!(set.len(), 1);
    }
}
RUST

# =============================================================================
# FILE: indra-state/src/nullifier.rs
# =============================================================================

cat > indra-state/src/nullifier.rs << 'RUST'
//! Nullifier set — the double-spend guard.
//!
//! Every spent input adds its nullifier to this set.
//! Every new input is checked against it before being accepted.
//!
//! A nullifier = SHA-256(owner_secret_key || utxo_id).
//! It reveals nothing about which UTXO was spent or who owns it,
//! but is deterministic: the same spend always produces the same nullifier.
//!
//! ## Storage model (Phase 2)
//!
//! In-memory HashSet. Phase 5 replaces this with a persistent Merkle trie.
//! The interface is unchanged.

use std::collections::HashSet;

use indra_core::types::primitives::Bytes32;

/// The complete set of spent nullifiers.
///
/// Membership check is O(1) average. Insertion is O(1) average.
/// There is no removal: nullifiers are permanent once added.
#[derive(Debug, Clone, Default)]
pub struct NullifierSet {
    spent: HashSet<Bytes32>,
}

impl NullifierSet {
    /// Create an empty nullifier set.
    pub fn new() -> Self {
        Self { spent: HashSet::new() }
    }

    /// Number of nullifiers in the set.
    pub fn len(&self) -> usize {
        self.spent.len()
    }

    /// True if no nullifiers have been recorded.
    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }

    /// Check whether a nullifier has already been spent.
    ///
    /// Returns true if the nullifier is in the set (already spent).
    /// Returns false if it is not (safe to spend).
    pub fn contains(&self, nullifier: &Bytes32) -> bool {
        self.spent.contains(nullifier)
    }

    /// Insert a nullifier, marking the associated UTXO as permanently spent.
    ///
    /// Returns true if the nullifier was newly inserted.
    /// Returns false if it was already present (double-spend attempt).
    pub fn insert(&mut self, nullifier: Bytes32) -> bool {
        self.spent.insert(nullifier)
    }

    /// Insert a nullifier, returning an error if it was already present.
    ///
    /// This is the preferred method in the block application path.
    pub fn insert_or_double_spend(
        &mut self,
        nullifier: Bytes32,
    ) -> Result<(), crate::error::StateError> {
        if !self.insert(nullifier) {
            return Err(crate::error::StateError::DoubleSpend);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_crypto::sha256;

    fn nullifier(seed: u8) -> Bytes32 {
        Bytes32::from(sha256(&[seed; 64]))
    }

    #[test]
    fn empty_set_contains_nothing() {
        let set = NullifierSet::new();
        assert!(!set.contains(&nullifier(0x01)));
    }

    #[test]
    fn insert_then_contains() {
        let mut set = NullifierSet::new();
        let n = nullifier(0x42);
        assert!(set.insert(n));
        assert!(set.contains(&n));
    }

    #[test]
    fn double_insert_returns_false() {
        let mut set = NullifierSet::new();
        let n = nullifier(0x99);
        assert!(set.insert(n));
        assert!(!set.insert(n)); // second insert: already present
    }

    #[test]
    fn insert_or_double_spend_ok_then_err() {
        let mut set = NullifierSet::new();
        let n = nullifier(0x10);
        assert!(set.insert_or_double_spend(n).is_ok());
        assert!(set.insert_or_double_spend(n).is_err());
    }

    #[test]
    fn distinct_nullifiers_all_accepted() {
        let mut set = NullifierSet::new();
        for i in 0..10u8 {
            assert!(set.insert_or_double_spend(nullifier(i)).is_ok());
        }
        assert_eq!(set.len(), 10);
    }

    #[test]
    fn nullifiers_are_permanent() {
        // There is no remove operation — once spent, always spent
        let mut set = NullifierSet::new();
        let n = nullifier(0x77);
        set.insert(n);
        // No remove method exists. Verify it's still there.
        assert!(set.contains(&n));
    }
}
RUST

# =============================================================================
# FILE: indra-state/src/validator.rs
# =============================================================================

cat > indra-state/src/validator.rs << 'RUST'
//! Validator set — the active set of staked validators.
//!
//! Tracks each validator's stake, status, and accumulated reward.
//! The validator set is snapshotted at each epoch boundary.

use std::collections::HashMap;

use indra_core::types::primitives::{Bytes32, MAX_VALIDATORS};

/// Lifecycle status of a validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorStatus {
    /// Active: eligible to propose and vote.
    Active,
    /// Unbonding: initiated exit, stake locked until unbonding_end_epoch.
    Unbonding {
        /// Epoch at which the stake is released.
        unbonding_end_epoch: u64,
    },
    /// Slashed: permanently removed, stake partially or fully burned.
    Slashed,
}

/// A single validator's entry in the validator set.
#[derive(Debug, Clone)]
pub struct ValidatorEntry {
    /// Validator identity: SHA-256(hybrid_public_key_bytes).
    pub validator_id: Bytes32,
    /// Staked amount in Spark.
    pub stake_spark: u64,
    /// Current lifecycle status.
    pub status: ValidatorStatus,
    /// Epoch in which this validator was registered.
    pub registered_epoch: u64,
    /// Accumulated unclaimed rewards in Spark.
    pub pending_rewards: u64,
    /// Epoch at which pending_rewards was last updated.
    pub rewards_last_epoch: u64,
    /// Number of self-reported bug slashes used (max 1 per lifetime).
    pub self_report_count: u32,
}

impl ValidatorEntry {
    /// True if this validator is currently active.
    pub fn is_active(&self) -> bool {
        matches!(self.status, ValidatorStatus::Active)
    }

    /// True if this validator's rewards have expired.
    ///
    /// Rewards expire if unclaimed after CLAIM_WINDOW_EPOCHS epochs.
    pub fn rewards_expired(&self, current_epoch: u64) -> bool {
        use indra_core::types::primitives::CLAIM_WINDOW_EPOCHS;
        current_epoch.saturating_sub(self.rewards_last_epoch) > CLAIM_WINDOW_EPOCHS
    }
}

/// The complete validator set.
///
/// Keyed by validator_id (Bytes32). Maximum MAX_VALIDATORS entries.
#[derive(Debug, Clone, Default)]
pub struct ValidatorSet {
    validators: HashMap<Bytes32, ValidatorEntry>,
}

impl ValidatorSet {
    /// Create an empty validator set.
    pub fn new() -> Self {
        Self { validators: HashMap::new() }
    }

    /// Number of registered validators (active + unbonding).
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// True if no validators are registered.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Number of currently active validators.
    pub fn active_count(&self) -> usize {
        self.validators.values()
            .filter(|v| v.is_active())
            .count()
    }

    /// Total stake of all active validators in Spark.
    pub fn total_active_stake(&self) -> u64 {
        self.validators.values()
            .filter(|v| v.is_active())
            .fold(0u64, |acc, v| acc.saturating_add(v.stake_spark))
    }

    /// Look up a validator by ID.
    pub fn get(&self, id: &Bytes32) -> Option<&ValidatorEntry> {
        self.validators.get(id)
    }

    /// Mutable lookup.
    pub fn get_mut(&mut self, id: &Bytes32) -> Option<&mut ValidatorEntry> {
        self.validators.get_mut(id)
    }

    /// Insert or update a validator entry.
    ///
    /// Returns an error if adding this validator would exceed MAX_VALIDATORS
    /// and the validator is not already registered.
    pub fn upsert(
        &mut self,
        entry: ValidatorEntry,
    ) -> crate::error::StateResult<()> {
        let id = entry.validator_id;
        if !self.validators.contains_key(&id)
            && self.validators.len() >= MAX_VALIDATORS
        {
            return Err(crate::error::StateError::InvariantViolation {
                message: "validator set at maximum capacity",
            });
        }
        self.validators.insert(id, entry);
        Ok(())
    }

    /// Iterate over all active validators.
    pub fn active_validators(&self) -> impl Iterator<Item = &ValidatorEntry> {
        self.validators.values().filter(|v| v.is_active())
    }

    /// Iterate over all validators regardless of status.
    pub fn all_validators(&self) -> impl Iterator<Item = &ValidatorEntry> {
        self.validators.values()
    }

    /// Expire rewards for validators who have not claimed within CLAIM_WINDOW.
    ///
    /// Called at epoch transition. Expired rewards are simply zeroed —
    /// they do not return to treasury (they are effectively burned).
    pub fn expire_stale_rewards(&mut self, current_epoch: u64) {
        for entry in self.validators.values_mut() {
            if entry.pending_rewards > 0 && entry.rewards_expired(current_epoch) {
                entry.pending_rewards = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::primitives::MAX_VALIDATORS;

    fn make_validator(id_byte: u8, stake: u64, epoch: u64) -> ValidatorEntry {
        ValidatorEntry {
            validator_id:     Bytes32::from([id_byte; 32]),
            stake_spark:      stake,
            status:           ValidatorStatus::Active,
            registered_epoch: epoch,
            pending_rewards:  0,
            rewards_last_epoch: epoch,
            self_report_count: 0,
        }
    }

    #[test]
    fn insert_and_retrieve() {
        let mut vs = ValidatorSet::new();
        let v = make_validator(0x01, 10_000_000_000, 0);
        let id = v.validator_id;
        vs.upsert(v).unwrap();
        assert!(vs.get(&id).is_some());
        assert_eq!(vs.active_count(), 1);
    }

    #[test]
    fn total_active_stake_sums_correctly() {
        let mut vs = ValidatorSet::new();
        vs.upsert(make_validator(0x01, 1_000, 0)).unwrap();
        vs.upsert(make_validator(0x02, 2_000, 0)).unwrap();
        vs.upsert(make_validator(0x03, 3_000, 0)).unwrap();
        assert_eq!(vs.total_active_stake(), 6_000);
    }

    #[test]
    fn unbonding_validator_not_counted_as_active() {
        let mut vs = ValidatorSet::new();
        let mut v = make_validator(0x01, 5_000, 0);
        v.status = ValidatorStatus::Unbonding { unbonding_end_epoch: 10 };
        vs.upsert(v).unwrap();
        assert_eq!(vs.active_count(), 0);
        assert_eq!(vs.total_active_stake(), 0);
    }

    #[test]
    fn reward_expiry_zeroes_stale_rewards() {
        let mut vs = ValidatorSet::new();
        let mut v = make_validator(0x01, 5_000, 0);
        v.pending_rewards = 999;
        v.rewards_last_epoch = 0;
        vs.upsert(v).unwrap();

        use indra_core::types::primitives::CLAIM_WINDOW_EPOCHS;
        // Expire at exactly CLAIM_WINDOW + 1 epochs later
        vs.expire_stale_rewards(CLAIM_WINDOW_EPOCHS + 1);

        let id = Bytes32::from([0x01u8; 32]);
        assert_eq!(vs.get(&id).unwrap().pending_rewards, 0);
    }

    #[test]
    fn rewards_not_expired_within_window() {
        let mut vs = ValidatorSet::new();
        let mut v = make_validator(0x01, 5_000, 0);
        v.pending_rewards = 500;
        v.rewards_last_epoch = 0;
        vs.upsert(v).unwrap();

        // Still within the window
        vs.expire_stale_rewards(100);

        let id = Bytes32::from([0x01u8; 32]);
        assert_eq!(vs.get(&id).unwrap().pending_rewards, 500);
    }
}
RUST

# =============================================================================
# FILE: indra-state/src/fee.rs
# =============================================================================

cat > indra-state/src/fee.rs << 'RUST'
//! EIP-1559 style base fee update formula.
//!
//! Applied at the end of every block to set the base fee for the next block.
//!
//! ## Formula (Spec Section F3)
//!
//!   utilisation = block_tx_count / MAX_TX_PER_BLOCK
//!   delta       = utilisation - TARGET (50%)
//!
//!   if utilisation > TARGET:
//!     new_fee = old_fee + old_fee × κ × delta / TARGET
//!   else:
//!     new_fee = old_fee - old_fee × κ × |delta| / TARGET
//!
//! Where κ = 125/1000 (0.125), TARGET = 50/100 (50%).
//!
//! ## Integer arithmetic
//!
//! All calculations use u64 integer arithmetic with explicit rounding.
//! Division always rounds down (floor). No floating point.
//! The fee is clamped to [MIN_BASE_FEE, u64::MAX] after each update.

use indra_core::types::primitives::{
    MAX_TX_PER_BLOCK,
    MIN_BASE_FEE_SPARK_PER_KB,
    FEE_ADJUST_NUMERATOR,
    FEE_ADJUST_DENOMINATOR,
    TARGET_UTILISATION_NUMERATOR,
    TARGET_UTILISATION_DENOMINATOR,
};

/// Compute the base fee for the next block given the current block's state.
///
/// Arguments:
/// - `current_base_fee`: the base fee that was in effect for this block (Spark/KB)
/// - `tx_count`: number of transactions included in this block
///
/// Returns the base fee to be recorded in the next block's header.
///
/// This function is pure: same inputs always produce the same output.
/// It never fails — the result is always clamped to a valid range.
pub fn compute_next_base_fee(current_base_fee: u64, tx_count: usize) -> u64 {
    let max_txs = MAX_TX_PER_BLOCK as u64;
    let count   = tx_count as u64;

    // target_count = MAX_TX_PER_BLOCK × TARGET_NUMERATOR / TARGET_DENOMINATOR
    // = 200 × 50 / 100 = 100 transactions
    let target_count = max_txs
        .saturating_mul(TARGET_UTILISATION_NUMERATOR)
        / TARGET_UTILISATION_DENOMINATOR;

    let new_fee = if count > target_count {
        // Above target: increase fee
        // delta = count - target_count
        // adjustment = current_fee × κ × delta / target_count
        let delta = count - target_count;
        let adjustment = current_base_fee
            .saturating_mul(FEE_ADJUST_NUMERATOR)
            .saturating_mul(delta)
            / FEE_ADJUST_DENOMINATOR
            / target_count.max(1);
        current_base_fee.saturating_add(adjustment)
    } else {
        // At or below target: decrease fee
        let delta = target_count - count;
        let adjustment = current_base_fee
            .saturating_mul(FEE_ADJUST_NUMERATOR)
            .saturating_mul(delta)
            / FEE_ADJUST_DENOMINATOR
            / target_count.max(1);
        current_base_fee.saturating_sub(adjustment)
    };

    // Clamp to minimum — fee can never go below MIN_BASE_FEE
    new_fee.max(MIN_BASE_FEE_SPARK_PER_KB)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::primitives::{
        INITIAL_BASE_FEE_SPARK_PER_KB, MIN_BASE_FEE_SPARK_PER_KB, MAX_TX_PER_BLOCK,
    };

    #[test]
    fn empty_block_decreases_fee() {
        let fee = compute_next_base_fee(INITIAL_BASE_FEE_SPARK_PER_KB, 0);
        assert!(fee < INITIAL_BASE_FEE_SPARK_PER_KB);
    }

    #[test]
    fn full_block_increases_fee() {
        let fee = compute_next_base_fee(INITIAL_BASE_FEE_SPARK_PER_KB, MAX_TX_PER_BLOCK);
        assert!(fee > INITIAL_BASE_FEE_SPARK_PER_KB);
    }

    #[test]
    fn target_block_keeps_fee_stable() {
        // Exactly at 50% utilisation (100 txs out of 200)
        let target = MAX_TX_PER_BLOCK / 2;
        let fee = compute_next_base_fee(INITIAL_BASE_FEE_SPARK_PER_KB, target);
        // At exact target, delta = 0, adjustment = 0, fee unchanged
        assert_eq!(fee, INITIAL_BASE_FEE_SPARK_PER_KB);
    }

    #[test]
    fn fee_never_below_minimum() {
        // Even with zero transactions and a very low starting fee
        let fee = compute_next_base_fee(MIN_BASE_FEE_SPARK_PER_KB, 0);
        assert!(fee >= MIN_BASE_FEE_SPARK_PER_KB);
    }

    #[test]
    fn fee_is_deterministic() {
        let f1 = compute_next_base_fee(100, 150);
        let f2 = compute_next_base_fee(100, 150);
        assert_eq!(f1, f2);
    }

    #[test]
    fn fee_increases_monotonically_with_load() {
        let low  = compute_next_base_fee(100, 110);
        let mid  = compute_next_base_fee(100, 150);
        let high = compute_next_base_fee(100, 200);
        assert!(low < mid);
        assert!(mid < high);
    }

    #[test]
    fn fee_decreases_monotonically_with_less_load() {
        let a = compute_next_base_fee(100, 90);
        let b = compute_next_base_fee(100, 50);
        let c = compute_next_base_fee(100, 0);
        assert!(a > b);
        assert!(b > c);
    }

    #[test]
    fn no_overflow_at_max_values() {
        // Should not panic
        let fee = compute_next_base_fee(u64::MAX / 2, MAX_TX_PER_BLOCK);
        assert!(fee >= MIN_BASE_FEE_SPARK_PER_KB);
    }
}
RUST

# =============================================================================
# FILE: indra-state/src/epoch.rs
# =============================================================================

cat > indra-state/src/epoch.rs << 'RUST'
//! Epoch transition logic.
//!
//! Triggered when `height % EPOCH_DURATION_BLOCKS == 0`.
//!
//! ## What happens at an epoch boundary (Spec Section F)
//!
//! 1. Compute epoch_reward = total_supply × INFLATION_RATE_BPS / 10000 / epochs_per_year
//! 2. Distribute: 60% to validator pool, 30% to treasury, 10% to burn buffer
//! 3. Distribute validator pool proportionally by stake weight
//! 4. Expire unclaimed rewards older than CLAIM_WINDOW_EPOCHS
//! 5. Advance unbonding validators (release stake if unbonding_end_epoch reached)
//!
//! ## Integer arithmetic
//!
//! All reward calculations use u64 integer arithmetic.
//! Rounding: floor division throughout.
//! Dust (remainder after distribution) stays in treasury.

use indra_core::types::primitives::{
    INFLATION_RATE_BPS,
    VALIDATOR_POOL_SHARE_BPS,
    TREASURY_SHARE_BPS,
    BURN_BUFFER_SHARE_BPS,
    EPOCH_DURATION_BLOCKS,
};

use crate::{
    chain::ChainState,
    error::StateResult,
    validator::ValidatorStatus,
};

/// Number of epochs per year (approximate).
/// 365.25 days × 24h × 60min × 60s / BLOCK_TIME / EPOCH_DURATION_BLOCKS
/// = 31_557_600 / 6 / 300 = 17_532 epochs/year
pub const EPOCHS_PER_YEAR: u64 = 17_532;

/// Apply the epoch transition to the chain state.
///
/// Called at the end of the last block of each epoch
/// (i.e., when `height % EPOCH_DURATION_BLOCKS == 0`).
///
/// Mutates `state` in place. Returns Ok(()) on success.
pub fn apply_epoch_transition(
    state: &mut ChainState,
    current_epoch: u64,
) -> StateResult<()> {
    // 1. Compute this epoch's reward pool
    let EpochRewards { validator_pool, treasury_amount, burn_amount } =
        compute_epoch_rewards(state.total_supply);

    // 2. Add to treasury
    state.treasury_balance = state.treasury_balance.saturating_add(treasury_amount);

    // 3. Add to burn buffer (tracked separately, actual burn handled by governance)
    state.burn_buffer = state.burn_buffer.saturating_add(burn_amount);

    // 4. Distribute validator pool proportionally by stake
    distribute_validator_rewards(state, validator_pool, current_epoch);

    // 5. Expire stale rewards
    state.validators.expire_stale_rewards(current_epoch);

    // 6. Release unbonded validators
    release_unbonded_validators(state, current_epoch);

    // 7. Update total supply (minted = validator_pool + treasury + burn_buffer)
    let minted = validator_pool.saturating_add(treasury_amount).saturating_add(burn_amount);
    state.total_supply = state.total_supply.saturating_add(minted);

    Ok(())
}

/// Reward amounts for one epoch.
#[derive(Debug, Clone, Copy)]
pub struct EpochRewards {
    /// Spark allocated to the validator reward pool.
    pub validator_pool: u64,
    /// Spark added to treasury.
    pub treasury_amount: u64,
    /// Spark added to burn buffer.
    pub burn_amount: u64,
}

/// Compute how many Spark to mint this epoch.
///
/// epoch_reward = total_supply × INFLATION_RATE_BPS / 10_000 / EPOCHS_PER_YEAR
///
/// Rounding: floor. Remainder dust stays in supply (not distributed).
pub fn compute_epoch_rewards(total_supply: u64) -> EpochRewards {
    // Total to mint this epoch
    let epoch_total = total_supply
        .saturating_mul(INFLATION_RATE_BPS as u64)
        / 10_000
        / EPOCHS_PER_YEAR;

    // Split by allocation shares
    let validator_pool  = epoch_total.saturating_mul(VALIDATOR_POOL_SHARE_BPS as u64) / 10_000;
    let treasury_amount = epoch_total.saturating_mul(TREASURY_SHARE_BPS as u64) / 10_000;
    let burn_amount     = epoch_total.saturating_mul(BURN_BUFFER_SHARE_BPS as u64) / 10_000;

    EpochRewards { validator_pool, treasury_amount, burn_amount }
}

/// Distribute the validator pool proportionally to active validators by stake.
///
/// Each validator receives: pool × their_stake / total_active_stake
/// Rounding: floor. Remainder stays in treasury.
fn distribute_validator_rewards(
    state: &mut ChainState,
    validator_pool: u64,
    current_epoch: u64,
) {
    let total_stake = state.validators.total_active_stake();
    if total_stake == 0 || validator_pool == 0 {
        // No active validators or no rewards: add pool to treasury
        state.treasury_balance = state.treasury_balance.saturating_add(validator_pool);
        return;
    }

    // Collect IDs and stakes first to avoid borrow issues
    let active: Vec<(indra_core::types::primitives::Bytes32, u64)> = state
        .validators
        .active_validators()
        .map(|v| (v.validator_id, v.stake_spark))
        .collect();

    let mut distributed: u64 = 0;

    for (id, stake) in &active {
        let reward = validator_pool
            .saturating_mul(*stake)
            / total_stake;

        if let Some(entry) = state.validators.get_mut(id) {
            entry.pending_rewards = entry.pending_rewards.saturating_add(reward);
            entry.rewards_last_epoch = current_epoch;
            distributed = distributed.saturating_add(reward);
        }
    }

    // Remainder (due to floor division) goes to treasury
    let remainder = validator_pool.saturating_sub(distributed);
    state.treasury_balance = state.treasury_balance.saturating_add(remainder);
}

/// Release validators whose unbonding period has ended.
fn release_unbonded_validators(state: &mut ChainState, current_epoch: u64) {
    let ids: Vec<indra_core::types::primitives::Bytes32> = state
        .validators
        .all_validators()
        .filter(|v| matches!(
            v.status,
            ValidatorStatus::Unbonding { unbonding_end_epoch }
            if unbonding_end_epoch <= current_epoch
        ))
        .map(|v| v.validator_id)
        .collect();

    for id in ids {
        if let Some(entry) = state.validators.get_mut(&id) {
            // Stake is returned to the validator's UTXO set entry
            // (in Phase 3 this triggers a UTXO creation)
            // For now, mark as fully exited by setting stake to 0
            entry.stake_spark = 0;
            entry.status = ValidatorStatus::Slashed; // reuse Slashed as "exited"
        }
    }
}

/// True if the given height is the last block of an epoch.
pub fn is_epoch_boundary(height: u64) -> bool {
    height > 0 && height % EPOCH_DURATION_BLOCKS == 0
}

/// Epoch number for a given height (0-indexed).
pub fn epoch_for_height(height: u64) -> u64 {
    height / EPOCH_DURATION_BLOCKS
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::primitives::{GENESIS_SUPPLY_SPARK, EPOCH_DURATION_BLOCKS};

    #[test]
    fn epoch_boundary_detection() {
        assert!(!is_epoch_boundary(0));
        assert!(!is_epoch_boundary(1));
        assert!(!is_epoch_boundary(299));
        assert!(is_epoch_boundary(300));
        assert!(!is_epoch_boundary(301));
        assert!(is_epoch_boundary(600));
    }

    #[test]
    fn epoch_for_height_correct() {
        assert_eq!(epoch_for_height(0), 0);
        assert_eq!(epoch_for_height(299), 0);
        assert_eq!(epoch_for_height(300), 1);
        assert_eq!(epoch_for_height(599), 1);
        assert_eq!(epoch_for_height(600), 2);
    }

    #[test]
    fn epoch_rewards_nonzero_for_genesis_supply() {
        let r = compute_epoch_rewards(GENESIS_SUPPLY_SPARK);
        assert!(r.validator_pool > 0);
        assert!(r.treasury_amount > 0);
        assert!(r.burn_amount > 0);
    }

    #[test]
    fn epoch_rewards_allocation_consistent() {
        let r = compute_epoch_rewards(GENESIS_SUPPLY_SPARK);
        let total = r.validator_pool + r.treasury_amount + r.burn_amount;
        // Total distributed must be ≤ the computed epoch_total (floor rounding)
        let epoch_total = GENESIS_SUPPLY_SPARK
            .saturating_mul(INFLATION_RATE_BPS as u64)
            / 10_000
            / EPOCHS_PER_YEAR;
        assert!(total <= epoch_total);
        // And must be close (within 3 Spark of rounding losses)
        assert!(epoch_total - total <= 3);
    }

    #[test]
    fn rewards_zero_for_zero_supply() {
        let r = compute_epoch_rewards(0);
        assert_eq!(r.validator_pool, 0);
        assert_eq!(r.treasury_amount, 0);
        assert_eq!(r.burn_amount, 0);
    }

    #[test]
    fn epoch_transition_increases_treasury() {
        let mut state = crate::chain::ChainState::new_genesis();
        let initial_treasury = state.treasury_balance;
        apply_epoch_transition(&mut state, 1).unwrap();
        assert!(state.treasury_balance >= initial_treasury);
    }

    #[test]
    fn epoch_transition_increases_supply() {
        let mut state = crate::chain::ChainState::new_genesis();
        let initial_supply = state.total_supply;
        apply_epoch_transition(&mut state, 1).unwrap();
        assert!(state.total_supply > initial_supply);
    }

    #[test]
    fn epoch_transition_is_deterministic() {
        let mut s1 = crate::chain::ChainState::new_genesis();
        let mut s2 = crate::chain::ChainState::new_genesis();
        apply_epoch_transition(&mut s1, 1).unwrap();
        apply_epoch_transition(&mut s2, 1).unwrap();
        assert_eq!(s1.total_supply, s2.total_supply);
        assert_eq!(s1.treasury_balance, s2.treasury_balance);
    }
}
RUST

# =============================================================================
# FILE: indra-state/src/chain.rs
# =============================================================================

cat > indra-state/src/chain.rs << 'RUST'
//! ChainState — the complete state of the INDRA chain at a point in time.
//!
//! This is everything a node needs to validate the next block.
//! It is the input and output of `apply_block`.

use indra_core::types::primitives::{
    Bytes32,
    GENESIS_SUPPLY_SPARK,
    INITIAL_BASE_FEE_SPARK_PER_KB,
};

use crate::{
    nullifier::NullifierSet,
    utxo::UtxoSet,
    validator::ValidatorSet,
};

/// The complete chain state at a given block height.
///
/// Two `ChainState` values are equivalent if and only if they represent
/// the same chain history. The `state_root` field (once implemented in
/// Phase 5) will be a cryptographic commitment to this entire structure.
#[derive(Debug, Clone)]
pub struct ChainState {
    /// Height of the most recently applied block (0 = genesis, before block 1).
    pub height: u64,

    /// Hash of the most recently applied block header.
    /// All-zero at genesis (no block has been applied yet).
    pub tip_hash: Bytes32,

    /// Current base fee in Spark/KB.
    /// Set to INITIAL_BASE_FEE at genesis, updated after each block.
    pub base_fee: u64,

    /// Total supply of Spark in existence (minted - burned).
    pub total_supply: u64,

    /// Treasury balance in Spark.
    pub treasury_balance: u64,

    /// Burn buffer balance in Spark (pending governance-directed burns).
    pub burn_buffer: u64,

    /// All unspent transaction outputs.
    pub utxos: UtxoSet,

    /// All spent nullifiers (double-spend guard).
    pub nullifiers: NullifierSet,

    /// Current validator set.
    pub validators: ValidatorSet,
}

impl ChainState {
    /// Create the genesis state (before any block has been applied).
    ///
    /// This is the canonical starting point for every INDRA node.
    pub fn new_genesis() -> Self {
        Self {
            height:           0,
            tip_hash:         Bytes32::ZERO,
            base_fee:         INITIAL_BASE_FEE_SPARK_PER_KB,
            total_supply:     GENESIS_SUPPLY_SPARK,
            treasury_balance: 0,
            burn_buffer:      0,
            utxos:            UtxoSet::new(),
            nullifiers:       NullifierSet::new(),
            validators:       ValidatorSet::new(),
        }
    }

    /// Current epoch number (0-indexed).
    pub fn current_epoch(&self) -> u64 {
        crate::epoch::epoch_for_height(self.height)
    }

    /// True if the chain has had at least one block applied.
    pub fn has_blocks(&self) -> bool {
        self.height > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::primitives::{
        GENESIS_SUPPLY_SPARK, INITIAL_BASE_FEE_SPARK_PER_KB,
    };

    #[test]
    fn genesis_state_is_correct() {
        let state = ChainState::new_genesis();
        assert_eq!(state.height, 0);
        assert_eq!(state.tip_hash, Bytes32::ZERO);
        assert_eq!(state.base_fee, INITIAL_BASE_FEE_SPARK_PER_KB);
        assert_eq!(state.total_supply, GENESIS_SUPPLY_SPARK);
        assert_eq!(state.treasury_balance, 0);
        assert!(state.utxos.is_empty());
        assert!(state.nullifiers.is_empty());
        assert!(state.validators.is_empty());
    }

    #[test]
    fn genesis_has_no_blocks() {
        assert!(!ChainState::new_genesis().has_blocks());
    }

    #[test]
    fn genesis_epoch_is_zero() {
        assert_eq!(ChainState::new_genesis().current_epoch(), 0);
    }
}
RUST

# =============================================================================
# FILE: indra-state/src/apply.rs
# =============================================================================

cat > indra-state/src/apply.rs << 'RUST'
//! Block application — the core state transition function.
//!
//! `apply_block(state, block)` is the heart of the protocol.
//!
//! ## Validation order (Spec Section C)
//!
//! Block-level checks (fail fast before touching any state):
//!   1. Protocol version == 1
//!   2. Height == state.height + 1
//!   3. prev_hash == state.tip_hash
//!   4. Encoded block size ≤ MAX_BLOCK_SIZE_BYTES
//!   5. Transaction count ≤ MAX_TX_PER_BLOCK
//!   6. base_fee field matches our computed value
//!
//! Per-transaction checks (in order, for each tx):
//!   7.  At least 1 input, at least 1 output
//!   8.  No duplicate nullifiers within the transaction
//!   9.  No duplicate nullifiers against the nullifier set
//!   10. All input UTXOs exist in the UTXO set
//!   11. All input UTXOs are past their lock_height
//!   12. fee_amount ≥ base_fee × tx_weight_kb
//!
//! State updates (only after ALL checks pass):
//!   - Spend inputs (remove from UTXO set, add nullifiers)
//!   - Create outputs (insert into UTXO set)
//!   - Update base_fee
//!   - If epoch boundary: apply epoch transition
//!   - Update height and tip_hash
//!
//! ## Atomicity
//!
//! State is only mutated after all validation passes.
//! On any error, the original state is unchanged.

use std::collections::HashSet;

use indra_core::{
    codec::Encode,
    types::{
        primitives::{
            Bytes32, PROTOCOL_VERSION, MAX_BLOCK_SIZE_BYTES, MAX_TX_PER_BLOCK,
        },
        block::BlockV1,
        transaction::TransactionV1,
    },
};

use crate::{
    chain::ChainState,
    epoch::{apply_epoch_transition, is_epoch_boundary, epoch_for_height},
    error::{StateError, StateResult},
    fee::compute_next_base_fee,
    utxo::UtxoSet,
    nullifier::NullifierSet,
};

/// Apply a block to the chain state, producing a new state.
///
/// This function is the single entry point for all state transitions.
/// It is deterministic: same (state, block) → same result, always.
///
/// On success: returns the updated state.
/// On failure: returns an error and the original state is unchanged.
pub fn apply_block(state: &mut ChainState, block: &BlockV1) -> StateResult<()> {
    // ── Phase 1: Block-level validation (read-only) ───────────────────────

    validate_block_header(state, block)?;

    // ── Phase 2: Transaction validation (read-only) ───────────────────────

    // Check for duplicate transactions within the block
    let mut seen_tx_hashes: HashSet<Vec<u8>> = HashSet::new();
    for tx in &block.transactions {
        let tx_bytes = tx.encode_to_vec();
        if !seen_tx_hashes.insert(tx_bytes) {
            return Err(StateError::DuplicateTransaction);
        }
    }

    // Validate each transaction against current state
    // We do a dry-run: check but don't mutate yet
    // Track nullifiers seen in THIS block to catch intra-block double spends
    let mut block_nullifiers: HashSet<Bytes32> = HashSet::new();

    for tx in &block.transactions {
        validate_transaction(state, tx, &mut block_nullifiers, block.header.height)?;
    }

    // ── Phase 3: State mutation (all validation passed) ───────────────────

    // Apply each transaction
    for (tx_idx, tx) in block.transactions.iter().enumerate() {
        apply_transaction(state, tx, block.header.height, tx_idx as u32)?;
    }

    // Update base fee for next block
    let next_fee = compute_next_base_fee(state.base_fee, block.transactions.len());
    state.base_fee = next_fee;

    // Advance height and tip hash
    state.height = block.header.height;
    state.tip_hash = block.header.block_hash();

    // Apply epoch transition if this is the last block of an epoch
    if is_epoch_boundary(state.height) {
        let epoch = epoch_for_height(state.height);
        apply_epoch_transition(state, epoch)?;
    }

    Ok(())
}

/// Validate block-level invariants (does not touch state).
fn validate_block_header(state: &ChainState, block: &BlockV1) -> StateResult<()> {
    // Protocol version
    if block.header.protocol_version.0 != PROTOCOL_VERSION {
        return Err(StateError::UnsupportedVersion {
            version: block.header.protocol_version.0,
        });
    }

    // Height must be exactly state.height + 1
    let expected_height = state.height + 1;
    if block.header.height != expected_height {
        return Err(StateError::InvalidHeight {
            expected: expected_height,
            actual: block.header.height,
        });
    }

    // prev_hash must match our current tip
    if block.header.prev_hash != state.tip_hash {
        return Err(StateError::PrevHashMismatch);
    }

    // Block size
    let block_size = block.encode_to_vec().len();
    if block_size > MAX_BLOCK_SIZE_BYTES {
        return Err(StateError::BlockTooLarge {
            actual: block_size,
            max: MAX_BLOCK_SIZE_BYTES,
        });
    }

    // Transaction count
    if block.transactions.len() > MAX_TX_PER_BLOCK {
        return Err(StateError::TooManyTransactions {
            actual: block.transactions.len(),
            max: MAX_TX_PER_BLOCK,
        });
    }

    // base_fee field must match what we computed for this height
    // (the block proposer must use the correct fee or be rejected)
    if block.header.base_fee != state.base_fee {
        return Err(StateError::BaseFeeIncorrect {
            block_fee: block.header.base_fee,
            computed_fee: state.base_fee,
        });
    }

    Ok(())
}

/// Validate one transaction against the current state.
///
/// `block_nullifiers` accumulates nullifiers seen so far in THIS block,
/// allowing detection of intra-block double spends.
fn validate_transaction(
    state: &ChainState,
    tx: &TransactionV1,
    block_nullifiers: &mut HashSet<Bytes32>,
    current_height: u64,
) -> StateResult<()> {
    if tx.inputs.is_empty()  { return Err(StateError::ZeroInputs);  }
    if tx.outputs.is_empty() { return Err(StateError::ZeroOutputs); }

    for input in &tx.inputs {
        // Duplicate nullifier within this transaction
        if block_nullifiers.contains(&input.nullifier) {
            return Err(StateError::DuplicateNullifier);
        }

        // Already spent in a previous block
        if state.nullifiers.contains(&input.nullifier) {
            return Err(StateError::DoubleSpend);
        }

        // Referenced UTXO must exist
        let entry = state.utxos.get(&input.utxo_id)
            .ok_or(StateError::UnknownUtxo)?;

        // UTXO must be past its lock height
        if entry.output.lock_height > current_height {
            return Err(StateError::OutputLocked {
                lock_height:    entry.output.lock_height,
                current_height,
            });
        }

        block_nullifiers.insert(input.nullifier);
    }

    // Fee check: fee_amount must cover base_fee × weight
    let weight_kb = {
        let bytes = tx.encode_to_vec().len() as u64;
        bytes.div_ceil(1024)
    };
    let required_fee = state.base_fee.saturating_mul(weight_kb);
    if tx.fee_amount < required_fee {
        return Err(StateError::FeeTooLow {
            actual:   tx.fee_amount,
            required: required_fee,
        });
    }

    Ok(())
}

/// Apply one transaction's state changes.
///
/// Called only after validate_transaction has passed for all transactions.
fn apply_transaction(
    state: &mut ChainState,
    tx: &TransactionV1,
    height: u64,
    tx_index: u32,
) -> StateResult<()> {
    // Spend inputs: remove UTXOs, record nullifiers
    for input in &tx.inputs {
        state.utxos.spend(&input.utxo_id);
        state.nullifiers.insert_or_double_spend(input.nullifier)?;
    }

    // Create outputs: insert new UTXOs
    for (out_idx, output) in tx.outputs.iter().enumerate() {
        state.utxos.insert(
            output.clone(),
            height,
            tx_index,
            out_idx as u32,
        )?;
    }

    // Fees are burned (100% burn — no validator fee payment in v1)
    // Total supply decreases by fee_amount
    state.total_supply = state.total_supply.saturating_sub(tx.fee_amount);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        Bytes32, CommitmentV1, HybridPubKey, HybridSignature, VariableBytes,
        ProtocolVersion,
        types::{
            transaction::{InputV1, OutputV1, TransactionV1},
            block::{BlockV1, BlockHeaderV1},
            governance::GovernanceOpV1,
            slashing::SlashEvidenceV1,
            primitives::{
                INITIAL_BASE_FEE_SPARK_PER_KB, MAX_VRF_PROOF_BYTES, MAX_QC_SIZE_BYTES,
            },
        },
    };
    use crate::{chain::ChainState, utxo::UtxoSet};

    // ── Test helpers ──────────────────────────────────────────────────────

    fn dummy_sig() -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig:        VariableBytes::from_slice(&[0u8; 2420]).unwrap(),
        }
    }

    fn dummy_pubkey() -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::ZERO,
            pq_pk: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
        }
    }

    fn dummy_output(byte: u8) -> OutputV1 {
        OutputV1 {
            commitment:   CommitmentV1 { compressed_point: Bytes32::from([byte; 32]) },
            owner_pubkey: dummy_pubkey(),
            range_proof:  VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            lock_height:  0,
        }
    }

    /// Build a state that has one pre-existing UTXO ready to be spent.
    fn state_with_utxo() -> (ChainState, Bytes32) {
        let mut state = ChainState::new_genesis();
        let output = dummy_output(0x01);
        let utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();
        (state, utxo_id)
    }

    fn make_tx(utxo_id: Bytes32, nullifier: Bytes32) -> TransactionV1 {
        TransactionV1 {
            version:             ProtocolVersion::CURRENT,
            signature_module_id: 1,
            inputs:  vec![InputV1 { utxo_id, nullifier }],
            outputs: vec![dummy_output(0x02)],
            fee_amount:     INITIAL_BASE_FEE_SPARK_PER_KB * 10, // covers 10 KB
            fee_blinding:   Bytes32::ZERO,
            fee_commitment: CommitmentV1 { compressed_point: Bytes32::ZERO },
            signature:      dummy_sig(),
        }
    }

    fn make_block(state: &ChainState, txs: Vec<TransactionV1>) -> BlockV1 {
        let height = state.height + 1;
        BlockV1 {
            header: BlockHeaderV1 {
                protocol_version:    ProtocolVersion::CURRENT,
                height,
                prev_hash:           state.tip_hash,
                timestamp:           1_700_000_000 + height,
                state_root:          Bytes32::ZERO,
                validator_set_root:  Bytes32::ZERO,
                mempool_set_root:    Bytes32::ZERO,
                base_fee:            state.base_fee,
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof:  VariableBytes::from_slice(&[0u8; 32]).unwrap(),
                quorum_certificate:  VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            },
            transactions:      txs,
            slashing_evidence: vec![],
            governance_ops:    vec![],
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────

    #[test]
    fn apply_empty_block_advances_height() {
        let mut state = ChainState::new_genesis();
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block).unwrap();
        assert_eq!(state.height, 1);
    }

    #[test]
    fn apply_block_updates_tip_hash() {
        let mut state = ChainState::new_genesis();
        let block = make_block(&state, vec![]);
        let expected_hash = block.header.block_hash();
        apply_block(&mut state, &block).unwrap();
        assert_eq!(state.tip_hash, expected_hash);
    }

    #[test]
    fn apply_block_with_tx_spends_utxo() {
        let (mut state, utxo_id) = state_with_utxo();
        let nullifier = Bytes32::from([0x99u8; 32]);
        let tx = make_tx(utxo_id, nullifier);
        let block = make_block(&state, vec![tx]);
        apply_block(&mut state, &block).unwrap();

        // Input UTXO must be gone
        assert!(!state.utxos.contains(&utxo_id));
        // Output UTXO must exist
        assert_eq!(state.utxos.len(), 1);
        // Nullifier must be recorded
        assert!(state.nullifiers.contains(&nullifier));
    }

    #[test]
    fn double_spend_rejected() {
        let (mut state, utxo_id) = state_with_utxo();
        let nullifier = Bytes32::from([0xAAu8; 32]);
        let tx = make_tx(utxo_id, nullifier);
        let block1 = make_block(&state, vec![tx.clone()]);
        apply_block(&mut state, &block1).unwrap();

        // Re-insert the output so the utxo_id exists again
        // but the nullifier is already spent
        let output = dummy_output(0x01);
        state.utxos.insert(output, 0, 0, 0).unwrap();

        let block2 = make_block(&state, vec![make_tx(utxo_id, nullifier)]);
        assert_eq!(apply_block(&mut state, &block2), Err(StateError::DoubleSpend));
    }

    #[test]
    fn wrong_height_rejected() {
        let mut state = ChainState::new_genesis();
        let mut block = make_block(&state, vec![]);
        block.header.height = 99; // wrong
        assert!(matches!(
            apply_block(&mut state, &block),
            Err(StateError::InvalidHeight { expected: 1, actual: 99 })
        ));
    }

    #[test]
    fn wrong_prev_hash_rejected() {
        let mut state = ChainState::new_genesis();
        let mut block = make_block(&state, vec![]);
        block.header.prev_hash = Bytes32::from([0xFFu8; 32]); // wrong
        assert_eq!(apply_block(&mut state, &block), Err(StateError::PrevHashMismatch));
    }

    #[test]
    fn wrong_base_fee_rejected() {
        let mut state = ChainState::new_genesis();
        let mut block = make_block(&state, vec![]);
        block.header.base_fee = 9999; // wrong
        assert!(matches!(
            apply_block(&mut state, &block),
            Err(StateError::BaseFeeIncorrect { .. })
        ));
    }

    #[test]
    fn unknown_utxo_rejected() {
        let mut state = ChainState::new_genesis();
        let fake_utxo = Bytes32::from([0xDEu8; 32]);
        let nullifier  = Bytes32::from([0xADu8; 32]);
        let tx = make_tx(fake_utxo, nullifier);
        let block = make_block(&state, vec![tx]);
        assert_eq!(apply_block(&mut state, &block), Err(StateError::UnknownUtxo));
    }

    #[test]
    fn fee_too_low_rejected() {
        let (mut state, utxo_id) = state_with_utxo();
        let mut tx = make_tx(utxo_id, Bytes32::from([0x01u8; 32]));
        tx.fee_amount = 0; // too low
        let block = make_block(&state, vec![tx]);
        assert!(matches!(
            apply_block(&mut state, &block),
            Err(StateError::FeeTooLow { .. })
        ));
    }

    #[test]
    fn fee_burns_supply() {
        let (mut state, utxo_id) = state_with_utxo();
        let initial_supply = state.total_supply;
        let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 10;
        let tx = make_tx(utxo_id, Bytes32::from([0x11u8; 32]));
        let block = make_block(&state, vec![tx]);
        apply_block(&mut state, &block).unwrap();
        // Supply decreases by the fee (100% burn)
        assert_eq!(state.total_supply, initial_supply - fee);
    }

    #[test]
    fn state_unchanged_on_error() {
        let mut state = ChainState::new_genesis();
        let height_before  = state.height;
        let supply_before  = state.total_supply;
        let utxos_before   = state.utxos.len();

        // Block with wrong height — will fail
        let mut block = make_block(&state, vec![]);
        block.header.height = 99;
        let _ = apply_block(&mut state, &block);

        assert_eq!(state.height, height_before);
        assert_eq!(state.total_supply, supply_before);
        assert_eq!(state.utxos.len(), utxos_before);
    }

    #[test]
    fn consecutive_blocks_chain_correctly() {
        let (mut state, utxo_id) = state_with_utxo();

        // Block 1: spend the UTXO
        let nullifier = Bytes32::from([0x55u8; 32]);
        let tx = make_tx(utxo_id, nullifier);
        let block1 = make_block(&state, vec![tx]);
        apply_block(&mut state, &block1).unwrap();
        assert_eq!(state.height, 1);

        // Block 2: empty, but chains correctly off block 1
        let block2 = make_block(&state, vec![]);
        apply_block(&mut state, &block2).unwrap();
        assert_eq!(state.height, 2);
    }

    #[test]
    fn locked_utxo_rejected_before_unlock() {
        let mut state = ChainState::new_genesis();
        let mut output = dummy_output(0x01);
        output.lock_height = 100; // locked until height 100
        let utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();

        let tx = make_tx(utxo_id, Bytes32::from([0x01u8; 32]));
        let block = make_block(&state, vec![tx]); // height will be 1 < 100
        assert!(matches!(
            apply_block(&mut state, &block),
            Err(StateError::OutputLocked { .. })
        ));
    }
}
RUST

# =============================================================================
# Integration tests
# =============================================================================

mkdir -p indra-state/tests

cat > indra-state/tests/state_machine.rs << 'RUST'
//! Integration tests for the complete state machine.
//!
//! These tests verify multi-block scenarios, epoch transitions,
//! and fee evolution over sequences of blocks.

use indra_core::{
    Bytes32, CommitmentV1, HybridPubKey, HybridSignature, VariableBytes,
    ProtocolVersion,
    types::{
        block::{BlockV1, BlockHeaderV1},
        transaction::{InputV1, OutputV1, TransactionV1},
        primitives::{
            EPOCH_DURATION_BLOCKS, INITIAL_BASE_FEE_SPARK_PER_KB,
            GENESIS_SUPPLY_SPARK,
        },
    },
};
use indra_state::{
    apply_block, ChainState,
    utxo::UtxoSet,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn dummy_sig() -> HybridSignature {
    HybridSignature {
        classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
        pq_sig:        VariableBytes::from_slice(&[0u8; 2420]).unwrap(),
    }
}

fn dummy_pubkey() -> HybridPubKey {
    HybridPubKey {
        classical_pk: Bytes32::ZERO,
        pq_pk: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
    }
}

fn make_output(byte: u8) -> OutputV1 {
    OutputV1 {
        commitment:   CommitmentV1 { compressed_point: Bytes32::from([byte; 32]) },
        owner_pubkey: dummy_pubkey(),
        range_proof:  VariableBytes::from_slice(&[0u8; 32]).unwrap(),
        lock_height:  0,
    }
}

fn make_tx(utxo_id: Bytes32, nullifier_byte: u8, out_byte: u8) -> TransactionV1 {
    TransactionV1 {
        version:             ProtocolVersion::CURRENT,
        signature_module_id: 1,
        inputs:  vec![InputV1 {
            utxo_id,
            nullifier: Bytes32::from([nullifier_byte; 32]),
        }],
        outputs: vec![make_output(out_byte)],
        fee_amount:     INITIAL_BASE_FEE_SPARK_PER_KB * 10,
        fee_blinding:   Bytes32::ZERO,
        fee_commitment: CommitmentV1 { compressed_point: Bytes32::ZERO },
        signature:      dummy_sig(),
    }
}

fn make_block(state: &ChainState, txs: Vec<TransactionV1>) -> BlockV1 {
    let height = state.height + 1;
    BlockV1 {
        header: BlockHeaderV1 {
            protocol_version:    ProtocolVersion::CURRENT,
            height,
            prev_hash:           state.tip_hash,
            timestamp:           1_700_000_000 + height,
            state_root:          Bytes32::ZERO,
            validator_set_root:  Bytes32::ZERO,
            mempool_set_root:    Bytes32::ZERO,
            base_fee:            state.base_fee,
            proposer_vrf_output: Bytes32::ZERO,
            proposer_vrf_proof:  VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            quorum_certificate:  VariableBytes::from_slice(&[0u8; 32]).unwrap(),
        },
        transactions:      txs,
        slashing_evidence: vec![],
        governance_ops:    vec![],
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn genesis_state_constants() {
    let state = ChainState::new_genesis();
    assert_eq!(state.total_supply, GENESIS_SUPPLY_SPARK);
    assert_eq!(state.height, 0);
    assert_eq!(state.base_fee, INITIAL_BASE_FEE_SPARK_PER_KB);
}

#[test]
fn one_hundred_empty_blocks() {
    let mut state = ChainState::new_genesis();
    for _ in 0..100 {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block).unwrap();
    }
    assert_eq!(state.height, 100);
}

#[test]
fn utxo_lifecycle_across_blocks() {
    let mut state = ChainState::new_genesis();

    // Create a UTXO by inserting it at genesis
    let output = make_output(0x01);
    let utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();

    // Block 1: spend that UTXO, create a new one
    let tx = make_tx(utxo_id, 0xAA, 0x02);
    let block1 = make_block(&state, vec![tx]);
    apply_block(&mut state, &block1).unwrap();

    assert!(!state.utxos.contains(&utxo_id), "old UTXO should be spent");
    assert_eq!(state.utxos.len(), 1, "one new UTXO created");
    assert!(state.nullifiers.contains(&Bytes32::from([0xAAu8; 32])));

    // Block 2: spend the new UTXO
    // Find the new UTXO id — it was inserted at height 1, tx 0, output 0
    let new_utxo_id = UtxoSet::compute_utxo_id(&make_output(0x02), 1, 0, 0);
    let tx2 = make_tx(new_utxo_id, 0xBB, 0x03);
    let block2 = make_block(&state, vec![tx2]);
    apply_block(&mut state, &block2).unwrap();

    assert_eq!(state.height, 2);
    assert_eq!(state.utxos.len(), 1);
    assert!(state.nullifiers.contains(&Bytes32::from([0xBBu8; 32])));
}

#[test]
fn fee_evolves_over_blocks() {
    let mut state = ChainState::new_genesis();
    let fee_at_genesis = state.base_fee;

    // Apply 10 empty blocks — fee should decrease (below target utilisation)
    for _ in 0..10 {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block).unwrap();
    }
    // Fee should have decreased from initial
    assert!(state.base_fee <= fee_at_genesis);
    // But never below minimum
    assert!(state.base_fee >= indra_core::types::primitives::MIN_BASE_FEE_SPARK_PER_KB);
}

#[test]
fn epoch_transition_fires_at_boundary() {
    let mut state = ChainState::new_genesis();
    let supply_before = state.total_supply;

    // Apply exactly one epoch worth of blocks
    for _ in 0..EPOCH_DURATION_BLOCKS {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block).unwrap();
    }

    assert_eq!(state.height, EPOCH_DURATION_BLOCKS);
    assert_eq!(state.current_epoch(), 1);
    // Supply should have increased (inflation minted)
    assert!(state.total_supply > supply_before);
    // Treasury should have received its share
    assert!(state.treasury_balance > 0);
}

#[test]
fn two_epochs_inflate_twice() {
    let mut state = ChainState::new_genesis();

    // First epoch
    for _ in 0..EPOCH_DURATION_BLOCKS {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block).unwrap();
    }
    let supply_after_epoch1 = state.total_supply;

    // Second epoch
    for _ in 0..EPOCH_DURATION_BLOCKS {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block).unwrap();
    }

    assert!(state.total_supply > supply_after_epoch1);
    assert_eq!(state.current_epoch(), 2);
}

#[test]
fn fees_are_burned() {
    let mut state = ChainState::new_genesis();

    // Insert a spendable UTXO
    let output = make_output(0x01);
    let utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();
    let supply_before = state.total_supply;

    let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 10;
    let tx = make_tx(utxo_id, 0xCC, 0x02);
    assert_eq!(tx.fee_amount, fee);

    let block = make_block(&state, vec![tx]);
    apply_block(&mut state, &block).unwrap();

    // Supply must have decreased by exactly the fee
    assert_eq!(state.total_supply, supply_before - fee);
}

#[test]
fn chain_is_deterministic() {
    // Two independent nodes starting from genesis and applying the same blocks
    // must arrive at identical state
    let mut state_a = ChainState::new_genesis();
    let mut state_b = ChainState::new_genesis();

    for i in 0..50u64 {
        let block_a = make_block(&state_a, vec![]);
        let block_b = make_block(&state_b, vec![]);
        // Blocks are identical because states are identical
        assert_eq!(
            block_a.header.block_hash(),
            block_b.header.block_hash(),
            "block hashes must match at height {}",
            i + 1
        );
        apply_block(&mut state_a, &block_a).unwrap();
        apply_block(&mut state_b, &block_b).unwrap();
        assert_eq!(state_a.height, state_b.height);
        assert_eq!(state_a.tip_hash, state_b.tip_hash);
        assert_eq!(state_a.total_supply, state_b.total_supply);
        assert_eq!(state_a.base_fee, state_b.base_fee);
    }
}
RUST

echo ""
echo "✓ INDRA Phase 2 files written."
echo ""
echo "Now run:"
echo "  cargo build"
echo "  cargo test"
echo ""