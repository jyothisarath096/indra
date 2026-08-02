//! Nullifier set — the double-spend guard.
//!
//! Every spent input adds its nullifier to this set.
//! Every new input is checked against it before being accepted.
//!
//! A nullifier = SHA-256(owner_secret_key || utxo_id).
//! It reveals nothing about which UTXO was spent or who owns it,
//! but is deterministic: the same spend always produces the same nullifier.
//!
//! ## Storage model
//!
//! Canonical nullifiers are kept in a persistent ordered set, with a frozen
//! legacy sparse tree for pre-compressed-auth-tree compatibility and a
//! persistent compressed authenticated tree for active roots/proofs.

use indra_core::{
    codec::{encode_list, list_encoded_len, ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    types::primitives::Bytes32,
};
use indra_crypto::sha256;

use crate::{
    persistent::{PersistentAuthTree, PersistentOrdSet},
    smt::AuthTreeProof,
};

/// Defensive snapshot decode ceiling for spent nullifiers.
///
/// This mirrors the UTXO snapshot guard: large enough for normal operation, but
/// finite so corrupted snapshots cannot request unbounded allocation/work.
pub const MAX_NULLIFIERS_DECODE: usize = 1_000_000;

/// The complete set of spent nullifiers.
///
/// There is no public removal: nullifiers are permanent once added. Internal
/// rollback can remove a just-inserted nullifier through StateTxn.
#[derive(Debug, Clone, Default)]
pub struct NullifierSet {
    spent: PersistentOrdSet<Bytes32>,
    compressed: PersistentAuthTree,
}

impl PartialEq for NullifierSet {
    fn eq(&self, other: &Self) -> bool {
        // Equality covers canonical nullifiers and the derived compressed root.
        self.spent == other.spent && self.compressed.root() == other.compressed.root()
    }
}

impl Eq for NullifierSet {}

impl Encode for NullifierSet {
    fn encode(&self, buf: &mut Vec<u8>) {
        let mut spent: Vec<_> = self.spent.iter().copied().collect();
        spent.sort_by_key(|nullifier| nullifier.0);
        encode_list(&spent, buf);
    }

    fn encoded_len(&self) -> usize {
        let mut spent: Vec<_> = self.spent.iter().copied().collect();
        spent.sort_by_key(|nullifier| nullifier.0);
        list_encoded_len(&spent)
    }
}

impl Decode for NullifierSet {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Self::decode_at_height(r, 0)
    }
}

impl NullifierSet {
    /// Decode a nullifier set and rebuild its canonical compressed tree.
    pub fn decode_at_height(r: &mut ByteReader<'_>, _height: u64) -> IndraResult<Self> {
        let count = u32::decode(r)? as usize;
        if count > MAX_NULLIFIERS_DECODE {
            return Err(IndraError::LengthExceeded {
                field: "snapshot.nullifiers",
                max: MAX_NULLIFIERS_DECODE,
                actual: count,
            });
        }
        let mut set = Self::new();
        for _ in 0..count {
            let nullifier = Bytes32::decode(r)?;
            if !set.spent.insert(nullifier) {
                return Err(IndraError::DuplicateEntries {
                    field: "snapshot.nullifiers",
                });
            }
        }
        set.rebuild_compressed_cache();
        Ok(set)
    }

    /// Create an empty nullifier set.
    pub fn new() -> Self {
        Self {
            spent: PersistentOrdSet::new(),
            compressed: PersistentAuthTree::new(),
        }
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
        self.insert_at_height(nullifier, 0)
    }

    /// Insert a nullifier at a specific resulting block height.
    pub fn insert_at_height(&mut self, nullifier: Bytes32, height: u64) -> bool {
        let inserted = self.spent.insert(nullifier);
        if inserted {
            let _ = height;
            self.compressed.insert(nullifier.0, sha256(&nullifier.0));
        }
        inserted
    }

    /// Insert a nullifier, returning an error if it was already present.
    ///
    /// This is the preferred method in the block application path.
    pub fn insert_or_double_spend(
        &mut self,
        nullifier: Bytes32,
    ) -> Result<(), crate::error::StateError> {
        self.insert_or_double_spend_at_height(nullifier, 0)
    }

    /// Insert a nullifier at a specific resulting block height, returning an
    /// error if it was already present.
    pub fn insert_or_double_spend_at_height(
        &mut self,
        nullifier: Bytes32,
        height: u64,
    ) -> Result<(), crate::error::StateError> {
        if !self.insert_at_height(nullifier, height) {
            return Err(crate::error::StateError::DoubleSpend);
        }
        Ok(())
    }

    pub(crate) fn remove_for_rollback_at_height(
        &mut self,
        nullifier: &Bytes32,
        height: u64,
    ) -> bool {
        let removed = self.spent.remove(nullifier);
        if removed {
            let _ = height;
            self.compressed.delete(nullifier.0);
        }
        removed
    }

    /// Consensus root for all spent nullifiers under the root rule active at `height`.
    pub fn root_at_height(&self, _height: u64) -> [u8; 32] {
        self.compressed.root()
    }

    /// Versioned proof under the proof rule active at `height`.
    pub fn prove_at_height(&self, nullifier: &Bytes32, _height: u64) -> AuthTreeProof {
        self.compressed.prove(nullifier.0)
    }

    fn rebuild_compressed_cache(&mut self) {
        self.compressed = PersistentAuthTree::from_pairs(
            self.spent
                .iter()
                .copied()
                .map(|nullifier| (nullifier.0, sha256(&nullifier.0))),
        )
        .expect("nullifiers are unique in NullifierSet");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_tree_round_trip_and_membership() {
        let mut set = NullifierSet::new();
        let present = Bytes32::from([7; 32]);
        assert!(set.insert_at_height(present, 1));
        let root = set.root_at_height(1);
        let proof = set.prove_at_height(&present, 1);
        assert!(PersistentAuthTree::verify_proof(root, present.0, &proof));

        let encoded = set.encode_to_vec();
        let decoded = NullifierSet::decode(&mut ByteReader::new(&encoded)).unwrap();
        assert_eq!(decoded, set);
        assert_eq!(decoded.root_at_height(1), root);
    }

    #[test]
    fn canonical_tree_is_insertion_order_independent_and_rolls_back() {
        let a = Bytes32::from([1; 32]);
        let b = Bytes32::from([2; 32]);
        let mut first = NullifierSet::new();
        assert!(first.insert_at_height(a, 1));
        assert!(first.insert_at_height(b, 1));
        let mut second = NullifierSet::new();
        assert!(second.insert_at_height(b, 1));
        assert!(second.insert_at_height(a, 1));
        assert_eq!(first.root_at_height(1), second.root_at_height(1));
        first.remove_for_rollback_at_height(&a, 1);
        assert!(!first.contains(&a));
        assert!(first.insert_at_height(a, 1));
        assert_eq!(first.root_at_height(1), second.root_at_height(1));
    }
}
