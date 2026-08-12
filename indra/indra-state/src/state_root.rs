//! State-root computation over sparse Merkle commitments.
//!
//! The final state root commits to:
//! - the full UTXO sparse Merkle tree
//! - chain metadata required for deterministic replay
//!
//! `tip_hash` is intentionally excluded from the metadata hash to avoid a
//! circular dependency: block hashes include `state_root`, and post-state
//! `tip_hash` becomes that same block hash after commit.

use indra_core::{
    codec::Encode,
    types::primitives::{Bytes32, VariableBytes, MAX_CHAIN_ID_BYTES},
};
use indra_crypto::sha256;

use crate::ChainState;

/// Root values computed from the same post-state snapshot.
///
/// `state_root` commits to the UTXO root, validator/staking root, and chain
/// metadata. `validator_set_root` is exposed alongside it so
/// block-header callers do not need to recompute the expensive validator/
/// delegation/staking commitment a second time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComputedStateRoots {
    /// Full combined state root.
    pub state_root: Bytes32,
    /// Validator/delegation/staking commitment included inside `state_root`.
    pub validator_set_root: Bytes32,
}

/// Compute the full state root for the given chain state.
pub fn compute_state_root(state: &ChainState) -> Bytes32 {
    compute_state_roots(state).state_root
}

/// Compute the full state root and the validator/delegation commitment in one
/// pass.
pub fn compute_state_roots(state: &ChainState) -> ComputedStateRoots {
    let utxo_root = state.utxos.root_at_height(state.height);
    let validator_set_root = compute_validator_set_root(state);

    let chain_id = VariableBytes::<MAX_CHAIN_ID_BYTES>::from_slice(state.chain_id.as_bytes())
        .unwrap_or_default();
    let mut metadata = Vec::with_capacity(48 + chain_id.encoded_len());
    chain_id.encode(&mut metadata);
    metadata.extend_from_slice(&state.height.to_le_bytes());
    metadata.extend_from_slice(&state.total_supply.to_le_bytes());
    metadata.extend_from_slice(&state.base_fee.to_le_bytes());
    metadata.extend_from_slice(&state.treasury_balance.to_le_bytes());
    metadata.extend_from_slice(&state.burn_buffer.to_le_bytes());
    metadata.extend_from_slice(&state.fee_reward_pool.to_le_bytes());
    state.governance.encode(&mut metadata);
    let metadata_hash = sha256(&metadata);

    let mut combined = Vec::with_capacity(96);
    combined.extend_from_slice(&utxo_root);
    combined.extend_from_slice(&validator_set_root.0);
    combined.extend_from_slice(&metadata_hash);
    ComputedStateRoots {
        state_root: Bytes32::from(sha256(&combined)),
        validator_set_root,
    }
}

/// Compute the validator/delegation commitment.
pub fn compute_validator_set_root(state: &ChainState) -> Bytes32 {
    compute_validator_set_root_at_height(state, state.height)
}

/// Compute the canonical validator/delegation commitment.
pub fn compute_validator_set_root_at_height(state: &ChainState, height: u64) -> Bytes32 {
    state.state_commitment_v2_root(height)
}
#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::{crypto::HybridPubKey, transaction::OutputV1};

    #[test]
    fn state_root_is_deterministic_and_changes_with_canonical_state() {
        let mut state = ChainState::new_genesis();
        assert_eq!(
            compute_state_root(&state),
            compute_state_root(&state.clone())
        );
        let before = compute_state_root(&state);
        state
            .utxos
            .insert(
                OutputV1 {
                    value_spark: 1_000,
                    owner_pubkey: HybridPubKey {
                        classical_pk: Bytes32::from([1; 32]),
                        pq_pk: indra_core::VariableBytes::from_slice(&[1; 32]).unwrap(),
                    },
                    lock_height: 0,
                },
                1,
                0,
                0,
            )
            .unwrap();
        state.height = 1;
        state.rebuild_state_commitment_v2(1);
        assert_ne!(before, compute_state_root(&state));
        assert_eq!(
            compute_validator_set_root_at_height(&state, 1),
            state.state_commitment_v2_root(1)
        );
    }

    #[test]
    fn chain_id_is_committed() {
        let first = ChainState::new_genesis();
        let mut second = first.clone();
        second.chain_id = "other-chain".to_string();
        second.rebuild_state_commitment_v2(second.height);
        assert_ne!(compute_state_root(&first), compute_state_root(&second));
    }
}
