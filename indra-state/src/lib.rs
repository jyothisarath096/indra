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
pub mod smt;
pub mod utxo;
pub mod nullifier;
pub mod validator;
pub mod chain;
pub mod apply;
pub mod fee;
pub mod delegation;
pub mod epoch;
pub mod state_root;

pub use error::{StateError, StateResult};
pub use smt::{MerkleProof, SparseMerkleTree, SMT_DEPTH};
pub use utxo::{UtxoSet, UtxoEntry};
pub use nullifier::NullifierSet;
pub use validator::{ValidatorEntry, ValidatorSet, ValidatorStatus};
pub use chain::ChainState;
pub use apply::apply_block;
pub use fee::compute_next_base_fee;
pub use delegation::apply_staking_op;
pub use epoch::apply_epoch_transition;
pub use validator::DelegatorEntry;
pub use state_root::{compute_state_root, compute_validator_set_root};
