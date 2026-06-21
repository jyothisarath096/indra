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
    codec::{decode_list, encode_list, list_encoded_len, ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    types::{primitives::Bytes32, transaction::OutputV1},
};
use indra_crypto::sha256;

use crate::{
    error::{StateError, StateResult},
    smt::{MerkleProof, SparseMerkleTree},
};

/// A UTXO entry in the set: the output itself plus metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl Encode for UtxoEntry {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.utxo_id.encode(buf);
        self.output.encode(buf);
        self.created_height.encode(buf);
        self.tx_index.encode(buf);
        self.output_index.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        self.utxo_id.encoded_len()
            + self.output.encoded_len()
            + self.created_height.encoded_len()
            + self.tx_index.encoded_len()
            + self.output_index.encoded_len()
    }
}

impl Decode for UtxoEntry {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            utxo_id: Bytes32::decode(r)?,
            output: OutputV1::decode(r)?,
            created_height: u64::decode(r)?,
            tx_index: u32::decode(r)?,
            output_index: u32::decode(r)?,
        })
    }
}

/// The complete set of unspent transaction outputs.
///
/// Keyed by UTXO ID (32-byte hash). Supports insert, lookup, and spend.
/// All operations are O(1) average via HashMap.
#[derive(Debug, Clone, Default)]
pub struct UtxoSet {
    entries: HashMap<Bytes32, UtxoEntry>,
    smt: SparseMerkleTree,
}

impl PartialEq for UtxoSet {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries && self.smt.root() == other.smt.root()
    }
}

impl Eq for UtxoSet {}

impl Encode for UtxoSet {
    fn encode(&self, buf: &mut Vec<u8>) {
        let mut entries: Vec<_> = self.entries.values().cloned().collect();
        entries.sort_by_key(|entry| entry.utxo_id.0);
        encode_list(&entries, buf);
    }

    fn encoded_len(&self) -> usize {
        let mut entries: Vec<_> = self.entries.values().cloned().collect();
        entries.sort_by_key(|entry| entry.utxo_id.0);
        list_encoded_len(&entries)
    }
}

impl Decode for UtxoSet {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let entries: Vec<UtxoEntry> = decode_list(r, usize::MAX, "snapshot.utxos")?;
        let mut set = Self::new();
        for entry in entries {
            if set.entries.contains_key(&entry.utxo_id) {
                return Err(IndraError::DuplicateEntries {
                    field: "snapshot.utxos",
                });
            }
            let leaf_value = Self::leaf_value(&entry);
            set.smt.insert(entry.utxo_id.0, leaf_value);
            set.entries.insert(entry.utxo_id, entry);
        }
        Ok(set)
    }
}

impl UtxoSet {
    /// Create an empty UTXO set.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            smt: SparseMerkleTree::new(),
        }
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
        self.entries.insert(
            id,
            UtxoEntry {
                utxo_id: id,
                output,
                created_height: height,
                tx_index,
                output_index,
            },
        );
        let smt_value = self
            .entries
            .get(&id)
            .map(Self::leaf_value)
            .unwrap_or([0u8; 32]);
        self.smt.insert(id.0, smt_value);
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
        let removed = self.entries.remove(id);
        if removed.is_some() {
            self.smt.delete(id.0);
        }
        removed
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

    /// Current SMT root for all unspent outputs.
    pub fn root(&self) -> [u8; 32] {
        self.smt.root()
    }

    /// Inclusion or exclusion proof for a specific UTXO ID.
    pub fn prove(&self, id: &Bytes32) -> MerkleProof {
        self.smt.prove(id.0)
    }

    /// Deterministic 32-byte value committed at a UTXO leaf.
    pub fn value_hash(&self, id: &Bytes32) -> Option<[u8; 32]> {
        self.entries.get(id).map(Self::leaf_value)
    }

    fn leaf_value(entry: &UtxoEntry) -> [u8; 32] {
        let mut data = entry.output.encode_to_vec();
        data.extend_from_slice(&entry.created_height.to_le_bytes());
        data.extend_from_slice(&entry.tx_index.to_le_bytes());
        data.extend_from_slice(&entry.output_index.to_le_bytes());
        sha256(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        types::transaction::OutputV1, Bytes32, CommitmentV1, HybridPubKey, VariableBytes,
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

    #[test]
    fn root_and_proof_track_membership() {
        let mut set = UtxoSet::new();
        let id = set.insert(dummy_output(0x11), 2, 1, 0).unwrap();
        let proof = set.prove(&id);
        let value = set.value_hash(&id).unwrap();
        assert_eq!(proof.value, Some(value));
        assert!(SparseMerkleTree::verify_proof(set.root(), id.0, &proof));

        set.spend(&id);
        let missing = set.prove(&id);
        assert_eq!(missing.value, None);
        assert!(SparseMerkleTree::verify_proof(set.root(), id.0, &missing));
    }
}
