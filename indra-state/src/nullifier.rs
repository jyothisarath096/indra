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

use indra_core::{
    codec::{ByteReader, Decode, Encode, decode_list, encode_list, list_encoded_len},
    error::{IndraError, IndraResult},
    types::primitives::Bytes32,
};
use indra_crypto::sha256;

use crate::smt::{MerkleProof, SparseMerkleTree};

/// The complete set of spent nullifiers.
///
/// Membership check is O(1) average. Insertion is O(1) average.
/// There is no removal: nullifiers are permanent once added.
#[derive(Debug, Clone, Default)]
pub struct NullifierSet {
    spent: HashSet<Bytes32>,
    smt: SparseMerkleTree,
}

impl PartialEq for NullifierSet {
    fn eq(&self, other: &Self) -> bool {
        self.spent == other.spent && self.smt.root() == other.smt.root()
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
        let spent: Vec<Bytes32> = decode_list(r, usize::MAX, "snapshot.nullifiers")?;
        let mut set = Self::new();
        for nullifier in spent {
            if !set.spent.insert(nullifier) {
                return Err(IndraError::DuplicateEntries {
                    field: "snapshot.nullifiers",
                });
            }
            set.smt.insert(nullifier.0, sha256(&nullifier.0));
        }
        Ok(set)
    }
}

impl NullifierSet {
    /// Create an empty nullifier set.
    pub fn new() -> Self {
        Self {
            spent: HashSet::new(),
            smt: SparseMerkleTree::new(),
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
        let inserted = self.spent.insert(nullifier);
        if inserted {
            self.smt.insert(nullifier.0, sha256(&nullifier.0));
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
        if !self.insert(nullifier) {
            return Err(crate::error::StateError::DoubleSpend);
        }
        Ok(())
    }

    /// Current SMT root for all spent nullifiers.
    pub fn root(&self) -> [u8; 32] {
        self.smt.root()
    }

    /// Inclusion or exclusion proof for a nullifier.
    pub fn prove(&self, nullifier: &Bytes32) -> MerkleProof {
        self.smt.prove(nullifier.0)
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

    #[test]
    fn proof_matches_membership() {
        let mut set = NullifierSet::new();
        let present = nullifier(0x33);
        let missing = nullifier(0x34);
        set.insert(present);

        let included = set.prove(&present);
        assert_eq!(included.value, Some(sha256(&present.0)));
        assert!(SparseMerkleTree::verify_proof(set.root(), present.0, &included));

        let excluded = set.prove(&missing);
        assert_eq!(excluded.value, None);
        assert!(SparseMerkleTree::verify_proof(set.root(), missing.0, &excluded));
    }
}
