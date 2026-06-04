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
    /// The UTXO ID (key in the set — stored here for convenience).
    pub utxo_id: Bytes32,
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
            utxo_id: id,
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
    /// Iterate over all UTXO entries (used for wallet scan and balance queries).
    pub fn all_entries(&self) -> impl Iterator<Item = &UtxoEntry> {
        self.entries.values()
    }

    /// True if a UTXO with the given ID exists in the set.
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
            value_spark: 1_000 + byte as u64,
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
