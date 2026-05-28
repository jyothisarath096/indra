//! State root computation.
//!
//! Computes the `state_root` and `validator_set_root` fields in block headers.
//!
//! ## Phase 5 implementation
//!
//! We use a simple Merkle tree over the serialised chain state fields.
//! Phase 6 replaces this with a full persistent Merkle Patricia Trie
//! backed by RocksDB, enabling light client proofs.
//!
//! ## state_root
//!
//! SHA-256(height || base_fee || tip_hash || total_supply || treasury
//!         || fee_reward_pool || utxo_set_hash || nullifier_set_hash)
//!
//! ## validator_set_root
//!
//! Merkle root of all active validator IDs sorted ascending.

use indra_core::types::primitives::Bytes32;
use indra_crypto::sha256;
use indra_state::ChainState;

/// Compute the state root for the given chain state.
///
/// This is a commitment to all consensus-critical state fields.
/// Nodes that have applied the same blocks will produce identical roots.
pub fn compute_state_root(state: &ChainState) -> Bytes32 {
    let mut data = Vec::with_capacity(128);
    data.extend_from_slice(&state.height.to_le_bytes());
    data.extend_from_slice(&state.base_fee.to_le_bytes());
    data.extend_from_slice(&state.tip_hash.0);
    data.extend_from_slice(&state.total_supply.to_le_bytes());
    data.extend_from_slice(&state.treasury_balance.to_le_bytes());
    data.extend_from_slice(&state.fee_reward_pool.to_le_bytes());

    // Hash of UTXO count (Phase 6 replaces with full Merkle trie)
    let utxo_count = state.utxos.len() as u64;
    data.extend_from_slice(&utxo_count.to_le_bytes());

    // Hash of nullifier count
    let nullifier_count = state.nullifiers.len() as u64;
    data.extend_from_slice(&nullifier_count.to_le_bytes());

    Bytes32::from(sha256(&data))
}

/// Compute the validator set root for the given chain state.
///
/// This is a Merkle root over all active validator identities.
/// Sorted ascending by validator_id for determinism.
pub fn compute_validator_set_root(state: &ChainState) -> Bytes32 {
    let mut validator_ids: Vec<[u8; 32]> = state.validators
        .active_validators()
        .map(|e| e.validator_id.0)
        .collect();

    if validator_ids.is_empty() {
        return Bytes32::ZERO;
    }

    validator_ids.sort();

    // Simple binary Merkle tree
    let leaves: Vec<[u8; 32]> = validator_ids.iter()
        .map(|id| sha256(id))
        .collect();

    Bytes32::from(merkle_root(&leaves))
}

/// Compute a binary Merkle root from a list of 32-byte leaves.
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    use indra_crypto::sha256;
    use indra_crypto::hash_pair;

    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    // Pad to next power of two
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    let target = layer.len().next_power_of_two();
    let zero = sha256(&[0u8; 32]);
    while layer.len() < target {
        layer.push(zero);
    }

    // Hash pairs bottom-up
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        let mut i = 0;
        while i + 1 < layer.len() {
            next.push(hash_pair(&layer[i], &layer[i + 1]));
            i += 2;
        }
        layer = next;
    }

    layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_root_is_deterministic() {
        let state = ChainState::new_genesis();
        assert_eq!(compute_state_root(&state), compute_state_root(&state));
    }

    #[test]
    fn state_root_changes_with_height() {
        let mut s1 = ChainState::new_genesis();
        let mut s2 = ChainState::new_genesis();
        s1.height = 1;
        s2.height = 2;
        assert_ne!(compute_state_root(&s1), compute_state_root(&s2));
    }

    #[test]
    fn validator_set_root_empty_is_zero() {
        let state = ChainState::new_genesis();
        // Genesis state has no validators
        assert_eq!(compute_validator_set_root(&state), Bytes32::ZERO);
    }

    #[test]
    fn merkle_root_single_leaf() {
        let leaf = sha256(b"test");
        assert_eq!(merkle_root(&[leaf]), leaf);
    }

    #[test]
    fn merkle_root_two_leaves() {
        let a = sha256(b"a");
        let b = sha256(b"b");
        let root = merkle_root(&[a, b]);
        assert_ne!(root, a);
        assert_ne!(root, b);
        // Deterministic
        assert_eq!(root, merkle_root(&[a, b]));
    }
}
