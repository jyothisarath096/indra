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

use std::{collections::HashMap, sync::Arc};

use indra_core::{
    codec::{encode_list, list_encoded_len, ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    types::{
        primitives::{
            compressed_auth_tree_active, Bytes32, SCHEMA_VERSION, SCHEMA_VERSION_GENESIS,
            SCHEMA_VERSION_PRE_VALIDATOR_NETWORK_ADDRESS,
        },
        transaction::OutputV1,
    },
};
use indra_crypto::sha256;

use crate::{
    error::{StateError, StateResult},
    smt::{AuthTreeProof, CompressedAuthTree, MerkleProof, SparseMerkleTree},
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
}

impl Encode for UtxoEntry {
    fn encode(&self, buf: &mut Vec<u8>) {
        SCHEMA_VERSION.encode(buf);
        self.utxo_id.encode(buf);
        self.output.encode(buf);
        self.created_height.encode(buf);
        self.tx_index.encode(buf);
        self.output_index.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        1 + self.utxo_id.encoded_len()
            + self.output.encoded_len()
            + self.created_height.encoded_len()
            + self.tx_index.encoded_len()
            + self.output_index.encoded_len()
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
    })
}

/// The complete set of unspent transaction outputs.
///
/// Keyed by UTXO ID (32-byte hash). Supports insert, lookup, and spend.
/// All operations are O(1) average via HashMap.
#[derive(Debug, Clone, Default)]
pub struct UtxoSet {
    entries: HashMap<Bytes32, UtxoEntry>,
    smt: Arc<SparseMerkleTree>,
    compressed: CompressedAuthTree,
}

impl PartialEq for UtxoSet {
    fn eq(&self, other: &Self) -> bool {
        // The legacy SMT is a derived pre-activation cache. After
        // `COMPRESSED_AUTH_TREE_HEIGHT`, post-activation snapshots may omit or
        // freeze it because consensus roots/proofs use `compressed` instead.
        // Equality therefore compares canonical entries and the active derived
        // compressed cache, not the cold legacy cache.
        self.entries == other.entries && self.compressed.root() == other.compressed.root()
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
        Self::decode_at_height(r, 0)
    }
}

impl UtxoSet {
    /// Decode a UTXO set for a state snapshot at `height`.
    ///
    /// Pre-activation states rebuild the legacy SMT because their consensus root
    /// still depends on it. Post-activation states intentionally skip rebuilding
    /// that cold cache; UTXO roots/proofs use the compressed tree at and after
    /// `COMPRESSED_AUTH_TREE_HEIGHT`.
    pub fn decode_at_height(r: &mut ByteReader<'_>, height: u64) -> IndraResult<Self> {
        let count = u32::decode(r)? as usize;
        if count > MAX_UTXOS_DECODE {
            return Err(IndraError::LengthExceeded {
                field: "snapshot.utxos",
                max: MAX_UTXOS_DECODE,
                actual: count,
            });
        }
        let mut set = Self::new();
        let update_legacy = should_update_legacy_smt(height);
        for _ in 0..count {
            let entry = UtxoEntry::decode(r)?;
            if set.entries.contains_key(&entry.utxo_id) {
                return Err(IndraError::DuplicateEntries {
                    field: "snapshot.utxos",
                });
            }
            let leaf_value = Self::leaf_value(&entry);
            if update_legacy {
                Arc::make_mut(&mut set.smt).insert(entry.utxo_id.0, leaf_value);
            }
            set.entries.insert(entry.utxo_id, entry);
        }
        set.rebuild_compressed_cache();
        Ok(set)
    }

    /// Create an empty UTXO set.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            smt: Arc::new(SparseMerkleTree::new()),
            compressed: CompressedAuthTree::new(),
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
        let update_legacy = should_update_legacy_smt(height);
        for _ in 0..count {
            let entry = UtxoEntry::decode_legacy(r)?;
            if set.entries.contains_key(&entry.utxo_id) {
                return Err(IndraError::DuplicateEntries {
                    field: "snapshot.utxos",
                });
            }
            let leaf_value = Self::leaf_value(&entry);
            if update_legacy {
                Arc::make_mut(&mut set.smt).insert(entry.utxo_id.0, leaf_value);
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
        if should_update_legacy_smt(height) {
            Arc::make_mut(&mut self.smt).insert(id.0, smt_value);
        }
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
            if should_update_legacy_smt(height) {
                Arc::make_mut(&mut self.smt).delete(id.0);
            }
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
        if should_update_legacy_smt(height) {
            Arc::make_mut(&mut self.smt).insert(id.0, value);
        }
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

    /// Current SMT root for all unspent outputs.
    pub fn root(&self) -> [u8; 32] {
        self.smt.root()
    }

    /// Consensus root for all unspent outputs under the root rule active at `height`.
    pub fn root_at_height(&self, height: u64) -> [u8; 32] {
        if compressed_auth_tree_active(height) {
            self.compressed.root()
        } else {
            self.smt.root()
        }
    }

    /// Inclusion or exclusion proof for a specific UTXO ID.
    pub fn prove(&self, id: &Bytes32) -> MerkleProof {
        self.smt.prove(id.0)
    }

    /// Versioned proof under the proof rule active at `height`.
    pub fn prove_at_height(&self, id: &Bytes32, height: u64) -> AuthTreeProof {
        if compressed_auth_tree_active(height) {
            AuthTreeProof::V2Compressed(self.compressed.prove(id.0))
        } else {
            AuthTreeProof::V1LegacySparse(self.smt.prove(id.0))
        }
    }

    /// Deterministic 32-byte value committed at a UTXO leaf.
    pub fn value_hash(&self, id: &Bytes32) -> Option<[u8; 32]> {
        self.entries.get(id).map(Self::leaf_value)
    }

    fn rebuild_compressed_cache(&mut self) {
        self.compressed = CompressedAuthTree::from_pairs(
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
        sha256(&data)
    }

    #[cfg(test)]
    fn legacy_smt_ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.smt, &other.smt)
    }
}

fn should_update_legacy_smt(height: u64) -> bool {
    !compressed_auth_tree_active(height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        codec::ByteReader, types::primitives::hard_forks::COMPRESSED_AUTH_TREE_HEIGHT,
        types::transaction::OutputV1, Bytes32, CommitmentV1, HybridPubKey, VariableBytes,
    };
    use std::{env, time::Instant};

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
    fn utxo_set_decode_rejects_excessive_entry_count() {
        let mut bytes = Vec::new();
        ((MAX_UTXOS_DECODE + 1) as u32).encode(&mut bytes);

        let err = UtxoSet::decode_exact(&bytes).unwrap_err();
        assert!(matches!(
            err,
            IndraError::LengthExceeded {
                field: "snapshot.utxos",
                max: MAX_UTXOS_DECODE,
                actual
            } if actual == MAX_UTXOS_DECODE + 1
        ));
    }

    #[test]
    fn utxo_set_decode_accepts_realistic_entry_count() {
        let mut set = UtxoSet::new();
        set.insert(dummy_output(0x31), 1, 0, 0).unwrap();
        set.insert(dummy_output(0x32), 1, 0, 1).unwrap();

        let decoded = UtxoSet::decode_exact(&set.encode_to_vec()).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded.root(), set.root());
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

    #[test]
    fn compressed_auth_tree_roots_and_proofs_switch_only_at_activation_height() {
        let mut set = UtxoSet::new();
        let id = set.insert(dummy_output(0x12), 2, 1, 0).unwrap();

        assert!(
            COMPRESSED_AUTH_TREE_HEIGHT > 0,
            "this test needs a pre-activation height; update it if compressed auth trees activate at genesis"
        );
        let pre_activation_height = COMPRESSED_AUTH_TREE_HEIGHT - 1;

        assert_eq!(set.root_at_height(pre_activation_height), set.root());
        assert!(matches!(
            set.prove_at_height(&id, pre_activation_height),
            AuthTreeProof::V1LegacySparse(_)
        ));

        let compressed_root = set.root_at_height(COMPRESSED_AUTH_TREE_HEIGHT);
        assert_ne!(compressed_root, set.root());
        let AuthTreeProof::V2Compressed(proof) =
            set.prove_at_height(&id, COMPRESSED_AUTH_TREE_HEIGHT)
        else {
            panic!("expected compressed proof at activation");
        };
        assert!(CompressedAuthTree::verify_proof(
            compressed_root,
            id.0,
            &proof
        ));
    }

    #[test]
    fn legacy_smt_updates_until_activation_then_freezes() {
        let mut set = UtxoSet::new();
        assert!(
            COMPRESSED_AUTH_TREE_HEIGHT > 0,
            "this test needs a pre-activation height"
        );
        let last_legacy_height = COMPRESSED_AUTH_TREE_HEIGHT - 1;
        let activation_height = COMPRESSED_AUTH_TREE_HEIGHT;

        let legacy_root_before = set.root();
        let id1 = set
            .insert(dummy_output(0x81), last_legacy_height, 0, 0)
            .unwrap();
        assert_ne!(
            set.root(),
            legacy_root_before,
            "legacy SMT must still be updated by the last pre-activation block"
        );
        let frozen_legacy_root = set.root();
        let compressed_before_activation_mutation = set.root_at_height(activation_height);
        let before_activation_mutation = set.clone();

        let id2 = set
            .insert(dummy_output(0x82), activation_height, 0, 1)
            .unwrap();
        assert!(set.contains(&id1));
        assert!(set.contains(&id2));
        assert_eq!(
            set.root(),
            frozen_legacy_root,
            "legacy SMT must be untouched at the first compressed-tree block height"
        );
        assert!(
            set.legacy_smt_ptr_eq(&before_activation_mutation),
            "post-activation UTXO mutation must not copy or mutate the frozen legacy SMT"
        );
        assert_ne!(
            set.root_at_height(activation_height),
            compressed_before_activation_mutation,
            "compressed tree must still track post-activation canonical UTXO mutations"
        );

        let before_spend = set.clone();
        let _ = set.spend_at_height(&id1, activation_height);
        assert_eq!(
            set.root(),
            frozen_legacy_root,
            "post-activation UTXO spend must not mutate the frozen legacy SMT"
        );
        assert!(
            set.legacy_smt_ptr_eq(&before_spend),
            "post-activation UTXO spend must keep sharing the frozen legacy SMT"
        );
    }

    #[test]
    fn post_activation_decode_skips_legacy_smt_rebuild_but_preserves_compressed_root() {
        let mut set = UtxoSet::new();
        set.insert(dummy_output(0x91), 1, 0, 0).unwrap();
        set.insert(dummy_output(0x92), 2, 0, 1).unwrap();
        let encoded = set.encode_to_vec();
        let expected_compressed_root = set.root_at_height(COMPRESSED_AUTH_TREE_HEIGHT);

        let decoded =
            UtxoSet::decode_at_height(&mut ByteReader::new(&encoded), COMPRESSED_AUTH_TREE_HEIGHT)
                .unwrap();

        assert_eq!(decoded.len(), set.len());
        assert_eq!(
            decoded.root(),
            SparseMerkleTree::new().root(),
            "post-activation snapshots do not rebuild the unread legacy SMT"
        );
        assert_eq!(
            decoded.root_at_height(COMPRESSED_AUTH_TREE_HEIGHT),
            expected_compressed_root,
            "post-activation consensus root still comes from the rebuilt compressed tree"
        );
    }

    #[test]
    #[ignore = "release-mode legacy SMT freeze benchmark; run with --release --ignored --nocapture"]
    fn legacy_smt_freeze_decode_and_clone_benchmark() {
        let sizes = env::var("INDRA_LEGACY_SMT_FREEZE_BENCH_SIZES")
            .unwrap_or_else(|_| "100000".to_string());
        let skip_old_baseline = env::var("INDRA_LEGACY_SMT_FREEZE_BENCH_SKIP_OLD")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        for size in sizes
            .split(',')
            .map(|raw| raw.trim().parse::<usize>().expect("valid benchmark size"))
        {
            let mut entries = Vec::with_capacity(size);
            for i in 0..size {
                let output = dummy_output((i & 0xff) as u8);
                let utxo_id = UtxoSet::compute_utxo_id(&output, 1, 0, i as u32);
                entries.push(UtxoEntry {
                    utxo_id,
                    output,
                    created_height: 1,
                    tx_index: 0,
                    output_index: i as u32,
                });
            }
            entries.sort_by_key(|entry| entry.utxo_id.0);
            let mut encoded = Vec::new();
            encode_list(&entries, &mut encoded);

            let start = Instant::now();
            let post_activation = UtxoSet::decode_at_height(
                &mut ByteReader::new(&encoded),
                COMPRESSED_AUTH_TREE_HEIGHT,
            )
            .unwrap();
            let post_activation_decode = start.elapsed();

            let start = Instant::now();
            let legacy_arc_clone = post_activation.smt.clone();
            let arc_clone = start.elapsed();
            std::hint::black_box(legacy_arc_clone);

            let (old_deep_clone, pre_activation_decode) = if skip_old_baseline {
                (None, None)
            } else {
                let start = Instant::now();
                let pre_activation =
                    UtxoSet::decode_at_height(&mut ByteReader::new(&encoded), 0).unwrap();
                let pre_activation_decode = start.elapsed();

                let start = Instant::now();
                let legacy_deep_clone = (*pre_activation.smt).clone();
                let old_deep_clone = start.elapsed();
                std::hint::black_box(legacy_deep_clone);
                std::hint::black_box(pre_activation);
                (Some(old_deep_clone), Some(pre_activation_decode))
            };

            eprintln!(
                "[legacy-smt-freeze] utxos={size} post_activation_decode={:?} pre_activation_decode_old_rebuild={:?} legacy_arc_clone={:?} legacy_deep_clone_old={:?}",
                post_activation_decode, pre_activation_decode, arc_clone, old_deep_clone
            );
        }
    }
}
