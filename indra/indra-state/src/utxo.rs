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
//! ## Storage model
//!
//! Canonical entries are kept in a persistent ordered map, with a frozen
//! legacy sparse tree for pre-compressed-auth-tree compatibility and a
//! persistent compressed authenticated tree for active roots/proofs.

use indra_core::{
    codec::{encode_list, list_encoded_len, ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    types::{
        primitives::{
            Bytes32, SCHEMA_VERSION, SCHEMA_VERSION_GENESIS,
            SCHEMA_VERSION_PRE_VALIDATOR_NETWORK_ADDRESS,
        },
        stake_position::TrancheRefundEventV1,
        transaction::OutputV1,
    },
};
use indra_crypto::sha256;

use crate::{
    error::{StateError, StateResult},
    persistent::{PersistentAuthTree, PersistentOrdMap},
    smt::AuthTreeProof,
};

/// Defensive snapshot decode ceiling for UTXO entries.
///
/// This is a corruption/DoS guard for in-memory snapshot loading, not a
/// consensus policy limit. It is high enough for current operation while
/// preventing `u32::MAX` allocation attempts from malformed snapshots.
pub const MAX_UTXOS_DECODE: usize = 1_000_000;

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
    /// Recovery context for a protocol-created tranche refund. It exists for
    /// exactly the lifetime of this unspent output and is deleted with it.
    pub tranche_refund: Option<TrancheRefundEventV1>,
}

impl Encode for UtxoEntry {
    fn encode(&self, buf: &mut Vec<u8>) {
        SCHEMA_VERSION.encode(buf);
        self.utxo_id.encode(buf);
        self.output.encode(buf);
        self.created_height.encode(buf);
        self.tx_index.encode(buf);
        self.output_index.encode(buf);
        self.tranche_refund.is_some().encode(buf);
        if let Some(event) = &self.tranche_refund {
            event.encode(buf);
        }
    }

    fn encoded_len(&self) -> usize {
        1 + self.utxo_id.encoded_len()
            + self.output.encoded_len()
            + self.created_height.encoded_len()
            + self.tx_index.encoded_len()
            + self.output_index.encoded_len()
            + 1
            + self
                .tranche_refund
                .as_ref()
                .map(Encode::encoded_len)
                .unwrap_or(0)
    }
}

impl Decode for UtxoEntry {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let marker = u8::decode(r)?;
        match marker {
            SCHEMA_VERSION_GENESIS
            | SCHEMA_VERSION_PRE_VALIDATOR_NETWORK_ADDRESS
            | SCHEMA_VERSION => decode_utxo_entry_fields(r, None),
            other if r.remaining() == 0 => Err(IndraError::UnsupportedSchemaVersion {
                struct_name: "UtxoEntry",
                version: other,
                max_supported: SCHEMA_VERSION,
            }),
            first_byte => decode_utxo_entry_fields(r, Some(first_byte)),
        }
    }
}

impl UtxoEntry {
    /// Decode the legacy unversioned UTXO layout.
    pub fn decode_legacy(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        decode_utxo_entry_fields(r, None)
    }
}

fn decode_utxo_entry_fields(
    r: &mut ByteReader<'_>,
    first_byte: Option<u8>,
) -> IndraResult<UtxoEntry> {
    let utxo_id = match first_byte {
        Some(first) => {
            let mut bytes = [0u8; 32];
            bytes[0] = first;
            bytes[1..].copy_from_slice(r.read_bytes(31)?);
            Bytes32::from(bytes)
        }
        None => Bytes32::decode(r)?,
    };
    Ok(UtxoEntry {
        utxo_id,
        output: OutputV1::decode(r)?,
        created_height: u64::decode(r)?,
        tx_index: u32::decode(r)?,
        output_index: u32::decode(r)?,
        tranche_refund: if bool::decode(r)? {
            Some(TrancheRefundEventV1::decode(r)?)
        } else {
            None
        },
    })
}

/// The complete set of unspent transaction outputs.
///
/// Keyed by UTXO ID (32-byte hash). Supports insert, lookup, and spend.
/// Cloning is structurally shared; mutations path-copy touched entries and
/// compressed-tree nodes.
#[derive(Debug, Clone)]
pub struct UtxoSet {
    entries: PersistentOrdMap<Bytes32, UtxoEntry>,
    compressed: PersistentAuthTree,
}

impl PartialEq for UtxoSet {
    fn eq(&self, other: &Self) -> bool {
        // Equality covers canonical entries and the derived compressed root.
        self.entries == other.entries && self.compressed.root() == other.compressed.root()
    }
}

impl Eq for UtxoSet {}

impl Default for UtxoSet {
    fn default() -> Self {
        Self::new()
    }
}

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
        Self::decode_at_height(r, 0)
    }
}

impl UtxoSet {
    /// Decode a UTXO set and rebuild its canonical compressed tree.
    pub fn decode_at_height(r: &mut ByteReader<'_>, _height: u64) -> IndraResult<Self> {
        let count = u32::decode(r)? as usize;
        if count > MAX_UTXOS_DECODE {
            return Err(IndraError::LengthExceeded {
                field: "snapshot.utxos",
                max: MAX_UTXOS_DECODE,
                actual: count,
            });
        }
        let mut set = Self::new();
        for _ in 0..count {
            let entry = UtxoEntry::decode(r)?;
            validate_tranche_refund_entry(&entry)?;
            if set.entries.contains_key(&entry.utxo_id) {
                return Err(IndraError::DuplicateEntries {
                    field: "snapshot.utxos",
                });
            }
            set.entries.insert(entry.utxo_id, entry);
        }
        set.rebuild_compressed_cache();
        Ok(set)
    }

    /// Create an empty UTXO set.
    pub fn new() -> Self {
        Self {
            entries: PersistentOrdMap::new(),
            compressed: PersistentAuthTree::new(),
        }
    }

    /// Decode a legacy unversioned UTXO set.
    pub fn decode_legacy(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Self::decode_legacy_at_height(r, 0)
    }

    /// Decode a legacy unversioned UTXO set for a state snapshot at `height`.
    pub fn decode_legacy_at_height(r: &mut ByteReader<'_>, height: u64) -> IndraResult<Self> {
        let count = u32::decode(r)? as usize;
        if count > MAX_UTXOS_DECODE {
            return Err(IndraError::LengthExceeded {
                field: "snapshot.utxos",
                max: MAX_UTXOS_DECODE,
                actual: count,
            });
        }
        let mut set = Self::new();
        let _ = height;
        for _ in 0..count {
            let entry = UtxoEntry::decode_legacy(r)?;
            validate_tranche_refund_entry(&entry)?;
            if set.entries.contains_key(&entry.utxo_id) {
                return Err(IndraError::DuplicateEntries {
                    field: "snapshot.utxos",
                });
            }
            set.entries.insert(entry.utxo_id, entry);
        }
        set.rebuild_compressed_cache();
        Ok(set)
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
        self.insert_with_tranche_refund(output, height, tx_index, output_index, None)
    }

    /// Insert an output and bind optional tranche-refund recovery context to
    /// the same canonical UTXO lifetime.
    pub fn insert_with_tranche_refund(
        &mut self,
        output: OutputV1,
        height: u64,
        tx_index: u32,
        output_index: u32,
        tranche_refund: Option<TrancheRefundEventV1>,
    ) -> StateResult<Bytes32> {
        if live_utxo_capacity_exceeded(self.entries.len()) {
            return Err(StateError::LiveStateCapacityExceeded {
                collection: "UTXO set",
                current: self.entries.len(),
                max: indra_core::types::primitives::MAX_LIVE_UTXOS,
            });
        }
        let id = Self::compute_utxo_id(&output, height, tx_index, output_index);
        if self.entries.contains_key(&id) {
            return Err(StateError::InvariantViolation {
                message: "UTXO ID collision — SHA-256 collision or duplicate block application",
            });
        }
        if let Some(event) = &tranche_refund {
            event
                .validate()
                .map_err(|_| StateError::InvariantViolation {
                    message: "invalid tranche refund provenance",
                })?;
            if event.refund_utxo_id != id
                || event.release_height != height
                || event.principal_spark != output.value_spark
            {
                return Err(StateError::InvariantViolation {
                    message: "tranche refund provenance does not match its UTXO",
                });
            }
        }
        self.entries.insert(
            id,
            UtxoEntry {
                utxo_id: id,
                output,
                created_height: height,
                tx_index,
                output_index,
                tranche_refund,
            },
        );
        let smt_value = self
            .entries
            .get(&id)
            .map(Self::leaf_value)
            .unwrap_or([0u8; 32]);
        let _ = height;
        self.compressed.insert(id.0, smt_value);
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
        self.spend_at_height(id, 0)
    }

    /// Remove a UTXO from the set at a specific resulting block height.
    pub fn spend_at_height(&mut self, id: &Bytes32, height: u64) -> Option<UtxoEntry> {
        let removed = self.entries.remove(id);
        if removed.is_some() {
            let _ = height;
            self.compressed.delete(id.0);
        }
        removed
    }

    pub(crate) fn remove_for_rollback_at_height(
        &mut self,
        id: &Bytes32,
        height: u64,
    ) -> Option<UtxoEntry> {
        self.spend_at_height(id, height)
    }

    pub(crate) fn restore_for_rollback_at_height(&mut self, entry: UtxoEntry, height: u64) {
        let id = entry.utxo_id;
        let value = Self::leaf_value(&entry);
        self.entries.insert(id, entry);
        let _ = height;
        self.compressed.insert(id.0, value);
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

    /// Consensus root for all unspent outputs under the root rule active at `height`.
    pub fn root_at_height(&self, _height: u64) -> [u8; 32] {
        self.compressed.root()
    }

    /// Versioned proof under the proof rule active at `height`.
    pub fn prove_at_height(&self, id: &Bytes32, _height: u64) -> AuthTreeProof {
        self.compressed.prove(id.0)
    }

    /// Deterministic 32-byte value committed at a UTXO leaf.
    pub fn value_hash(&self, id: &Bytes32) -> Option<[u8; 32]> {
        self.entries.get(id).map(Self::leaf_value)
    }

    fn rebuild_compressed_cache(&mut self) {
        self.compressed = PersistentAuthTree::from_pairs(
            self.entries
                .values()
                .map(|entry| (entry.utxo_id.0, Self::leaf_value(entry))),
        )
        .expect("UTXO IDs are unique in UtxoSet");
    }

    fn leaf_value(entry: &UtxoEntry) -> [u8; 32] {
        let mut data = entry.output.encode_to_vec();
        data.extend_from_slice(&entry.created_height.to_le_bytes());
        data.extend_from_slice(&entry.tx_index.to_le_bytes());
        data.extend_from_slice(&entry.output_index.to_le_bytes());
        data.push(u8::from(entry.tranche_refund.is_some()));
        if let Some(event) = &entry.tranche_refund {
            data.extend_from_slice(&event.encode_to_vec());
        }
        sha256(&data)
    }
}

fn live_utxo_capacity_exceeded(current: usize) -> bool {
    current >= indra_core::types::primitives::MAX_LIVE_UTXOS
}

fn validate_tranche_refund_entry(entry: &UtxoEntry) -> IndraResult<()> {
    if let Some(event) = &entry.tranche_refund {
        event.validate()?;
        if event.refund_utxo_id != entry.utxo_id
            || event.release_height != entry.created_height
            || event.principal_spark != entry.output.value_spark
        {
            return Err(IndraError::InvariantViolation {
                message: "tranche refund provenance does not match its UTXO",
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_utxo_cap_boundary_rejects_creation_at_exact_consensus_cap() {
        assert!(!live_utxo_capacity_exceeded(
            indra_core::types::primitives::MAX_LIVE_UTXOS - 1
        ));
        assert!(live_utxo_capacity_exceeded(
            indra_core::types::primitives::MAX_LIVE_UTXOS
        ));
    }
    use indra_core::types::{crypto::CommitmentV1, stake_position::PositionCustodyV1};

    fn dummy_output(byte: u8) -> OutputV1 {
        OutputV1 {
            value_spark: 1_000,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from([byte.wrapping_add(1); 32]),
            },
            owner_pubkey: indra_core::types::crypto::HybridPubKey {
                classical_pk: Bytes32::from([byte; 32]),
                pq_pk: indra_core::VariableBytes::from_slice(&[byte; 32]).unwrap(),
            },
            range_proof: indra_core::VariableBytes::from_slice(&[byte]).unwrap(),
            lock_height: 0,
        }
    }

    #[test]
    fn canonical_tree_round_trip_and_membership() {
        let mut set = UtxoSet::new();
        let id = set.insert(dummy_output(7), 1, 0, 1).unwrap();
        let root = set.root_at_height(1);
        let proof = set.prove_at_height(&id, 1);
        assert!(PersistentAuthTree::verify_proof(root, id.0, &proof));

        let encoded = set.encode_to_vec();
        let decoded = UtxoSet::decode(&mut ByteReader::new(&encoded)).unwrap();
        assert_eq!(decoded, set);
        assert_eq!(decoded.root_at_height(1), root);
    }

    #[test]
    fn canonical_tree_is_insertion_order_independent_and_rolls_back() {
        let a = UtxoEntry {
            utxo_id: Bytes32::from([1; 32]),
            output: dummy_output(1),
            created_height: 1,
            tx_index: 0,
            output_index: 0,
            tranche_refund: None,
        };
        let b = UtxoEntry {
            utxo_id: Bytes32::from([2; 32]),
            output: dummy_output(2),
            created_height: 1,
            tx_index: 0,
            output_index: 1,
            tranche_refund: None,
        };
        let mut first = UtxoSet::new();
        first.restore_for_rollback_at_height(a.clone(), 1);
        first.restore_for_rollback_at_height(b.clone(), 1);
        let mut second = UtxoSet::new();
        second.restore_for_rollback_at_height(b, 1);
        second.restore_for_rollback_at_height(a.clone(), 1);
        assert_eq!(first.root_at_height(1), second.root_at_height(1));
        assert_eq!(first.spend_at_height(&a.utxo_id, 1), Some(a.clone()));
        first.restore_for_rollback_at_height(a, 1);
        assert_eq!(first.root_at_height(1), second.root_at_height(1));
    }

    #[test]
    fn tranche_refund_provenance_has_exact_utxo_lifetime() {
        let output = dummy_output(9);
        let refund_utxo_id = UtxoSet::compute_utxo_id(&output, 300, 7, 1);
        let owner = Bytes32::from([4; 32]);
        let event = TrancheRefundEventV1 {
            refund_utxo_id,
            position_id: Bytes32::from([1; 32]),
            tranche_id: Bytes32::from([2; 32]),
            principal_owner_id: owner,
            custody: PositionCustodyV1::DelegatorIdentity {
                delegator_id: owner,
            },
            principal_spark: output.value_spark,
            release_height: 300,
            end_epoch: 1,
        };
        let mut set = UtxoSet::new();
        assert_eq!(
            set.insert_with_tranche_refund(output, 300, 7, 1, Some(event.clone()))
                .unwrap(),
            refund_utxo_id
        );
        let encoded = set.encode_to_vec();
        let decoded = UtxoSet::decode(&mut ByteReader::new(&encoded)).unwrap();
        assert_eq!(
            decoded.get(&refund_utxo_id).unwrap().tranche_refund,
            Some(event)
        );

        let removed = set.spend_at_height(&refund_utxo_id, 301).unwrap();
        assert!(set.get(&refund_utxo_id).is_none());
        set.restore_for_rollback_at_height(removed, 301);
        assert!(set.get(&refund_utxo_id).unwrap().tranche_refund.is_some());
    }
}
