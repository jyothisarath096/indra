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
//! ## What this crate does NOT do
//!
//! - VRF / proposer-election verification (handled by block import and consensus layers)
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

pub mod apply;
pub mod chain;
pub mod delegation;
pub mod effects;
pub mod epoch;
pub mod error;
pub mod fee;
pub mod governance;
pub mod governance_apply;
pub mod identity;
pub mod nullifier;
pub mod pending;
pub mod persistent;
pub mod smt;
pub mod stake_positions;
pub mod state_commitment;
pub mod state_root;
pub mod tranche_tombstone;
pub(crate) mod txn;
pub mod utxo;
pub mod validator;

pub use apply::{
    apply_block, apply_block_with_effects, project_block_for_roots, try_apply_governance_candidate,
    try_apply_slash_candidate, try_apply_staking_candidate,
    try_apply_transaction_candidate_with_dust, try_apply_verified_governance_candidate,
    try_apply_verified_slash_candidate, try_apply_verified_staking_candidate, ProjectedBlockRoots,
};
pub use chain::ChainState;
pub use delegation::{apply_staking_op, apply_verified_staking_op};
pub use effects::{AppliedBlockOutcome, CanonicalStateEffects, CommittedSlashEvent};
pub use epoch::{apply_epoch_transition, EpochTransitionContext};
pub use error::{ConsensusSnapshotLookupError, StateError, StateResult};
pub use fee::compute_next_base_fee;
pub use governance::{GovernableParams, GovernanceState, ProposalPhase, ProposalRecord};
pub use governance_apply::{apply_governance_op, apply_verified_governance_op};
pub use identity::{
    resolve_and_check_identity, resolve_delegator_identity_for_redelegation, IdentityCheckOutcome,
    IdentityError,
};
pub use nullifier::NullifierSet;
pub use persistent::{
    PersistentAuthTree, PersistentOrdMap, PersistentOrdSet, PersistentSparseMerkleTree,
};
pub use smt::{
    AuthTreeProof, CompressedAuthTree, CompressedChildKind, CompressedProof, CompressedProofChild,
    CompressedProofStep, MerkleProof, ProofTerminal, SparseMerkleTree, SMT_DEPTH,
};
pub use stake_positions::{
    deposit_stake_position, exit_stake_position, release_matured_position_tranches,
};
pub use state_commitment::StateCommitmentV2;
pub use state_root::{compute_state_root, compute_state_roots, compute_validator_set_root};
pub use tranche_tombstone::{
    clear_matured_tranche_reference_v2, first_representable_tranche_eviction_v2,
    plan_tranche_native_eviction_v2, slashable_self_targets_v2, tombstone_is_prunable_v2,
    validate_all_tombstone_references_v2, validate_tombstone_references_v2, TombstoneAuthorityV2,
    TrancheEvictionPlanV2,
};
pub use utxo::{UtxoEntry, UtxoSet};
pub use validator::{
    validate_new_validator_cold_key, validate_validator_cold_key, EvictedColdCustodyV1,
    ValidatedColdKey, ValidatorEntry, ValidatorSet, ValidatorStatus,
};
