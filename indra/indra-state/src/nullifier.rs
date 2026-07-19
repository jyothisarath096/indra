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

use std::sync::Arc;

use indra_core::{
    codec::{encode_list, list_encoded_len, ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    types::primitives::{compressed_auth_tree_active, Bytes32},
};
use indra_crypto::sha256;

use crate::{
    persistent::{PersistentAuthTree, PersistentOrdSet},
    smt::{AuthTreeProof, MerkleProof, SparseMerkleTree},
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
    smt: Arc<SparseMerkleTree>,
    compressed: PersistentAuthTree,
}

impl PartialEq for NullifierSet {
    fn eq(&self, other: &Self) -> bool {
        // The legacy SMT is a derived pre-activation cache. At/after
        // `COMPRESSED_AUTH_TREE_HEIGHT`, nullifier roots/proofs use the
        // compressed tree, so post-activation snapshots may omit or freeze the
        // legacy cache without changing consensus-visible state.
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
    /// Decode a nullifier set for a state snapshot at `height`.
    ///
    /// Pre-activation states rebuild the legacy SMT because their consensus root
    /// still depends on it. Post-activation states intentionally skip rebuilding
    /// that cold cache; roots/proofs use the compressed tree at and after
    /// `COMPRESSED_AUTH_TREE_HEIGHT`.
    pub fn decode_at_height(r: &mut ByteReader<'_>, height: u64) -> IndraResult<Self> {
        let count = u32::decode(r)? as usize;
        if count > MAX_NULLIFIERS_DECODE {
            return Err(IndraError::LengthExceeded {
                field: "snapshot.nullifiers",
                max: MAX_NULLIFIERS_DECODE,
                actual: count,
            });
        }
        let mut set = Self::new();
        let update_legacy = should_update_legacy_smt(height);
        for _ in 0..count {
            let nullifier = Bytes32::decode(r)?;
            if !set.spent.insert(nullifier) {
                return Err(IndraError::DuplicateEntries {
                    field: "snapshot.nullifiers",
                });
            }
            if update_legacy {
                Arc::make_mut(&mut set.smt).insert(nullifier.0, sha256(&nullifier.0));
            }
        }
        set.rebuild_compressed_cache();
        Ok(set)
    }

    /// Create an empty nullifier set.
    pub fn new() -> Self {
        Self {
            spent: PersistentOrdSet::new(),
            smt: Arc::new(SparseMerkleTree::new()),
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
            if should_update_legacy_smt(height) {
                Arc::make_mut(&mut self.smt).insert(nullifier.0, sha256(&nullifier.0));
            }
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
            if should_update_legacy_smt(height) {
                Arc::make_mut(&mut self.smt).delete(nullifier.0);
            }
            self.compressed.delete(nullifier.0);
        }
        removed
    }

    /// Current SMT root for all spent nullifiers.
    pub fn root(&self) -> [u8; 32] {
        self.smt.root()
    }

    /// Consensus root for all spent nullifiers under the root rule active at `height`.
    pub fn root_at_height(&self, height: u64) -> [u8; 32] {
        if compressed_auth_tree_active(height) {
            self.compressed.root()
        } else {
            self.smt.root()
        }
    }

    /// Inclusion or exclusion proof for a nullifier.
    pub fn prove(&self, nullifier: &Bytes32) -> MerkleProof {
        self.smt.prove(nullifier.0)
    }

    /// Versioned proof under the proof rule active at `height`.
    pub fn prove_at_height(&self, nullifier: &Bytes32, height: u64) -> AuthTreeProof {
        if compressed_auth_tree_active(height) {
            self.compressed.prove(nullifier.0)
        } else {
            AuthTreeProof::V1LegacySparse(self.smt.prove(nullifier.0))
        }
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
    use crate::smt::CompressedAuthTree;
    use indra_core::{
        codec::ByteReader, types::primitives::hard_forks::COMPRESSED_AUTH_TREE_HEIGHT,
    };
    use indra_crypto::sha256;
    use std::{
        collections::HashSet,
        env,
        time::{Duration, Instant},
    };

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
    fn nullifier_set_decode_rejects_excessive_entry_count() {
        let mut bytes = Vec::new();
        ((MAX_NULLIFIERS_DECODE + 1) as u32).encode(&mut bytes);

        let err = NullifierSet::decode_exact(&bytes).unwrap_err();
        assert!(matches!(
            err,
            IndraError::LengthExceeded {
                field: "snapshot.nullifiers",
                max: MAX_NULLIFIERS_DECODE,
                actual
            } if actual == MAX_NULLIFIERS_DECODE + 1
        ));
    }

    #[test]
    fn nullifier_set_decode_accepts_realistic_entry_count() {
        let mut set = NullifierSet::new();
        set.insert(nullifier(0x21));
        set.insert(nullifier(0x22));

        let decoded = NullifierSet::decode_exact(&set.encode_to_vec()).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded.root(), set.root());
    }

    #[test]
    fn proof_matches_membership() {
        let mut set = NullifierSet::new();
        let present = nullifier(0x33);
        let missing = nullifier(0x34);
        set.insert(present);

        let included = set.prove(&present);
        assert_eq!(included.value, Some(sha256(&present.0)));
        assert!(SparseMerkleTree::verify_proof(
            set.root(),
            present.0,
            &included
        ));

        let excluded = set.prove(&missing);
        assert_eq!(excluded.value, None);
        assert!(SparseMerkleTree::verify_proof(
            set.root(),
            missing.0,
            &excluded
        ));
    }

    #[test]
    fn compressed_auth_tree_roots_and_proofs_switch_only_at_activation_height() {
        let mut set = NullifierSet::new();
        let present = nullifier(0x35);
        set.insert(present);

        assert!(
            COMPRESSED_AUTH_TREE_HEIGHT > 0,
            "this test needs a pre-activation height; update it if compressed auth trees activate at genesis"
        );
        let pre_activation_height = COMPRESSED_AUTH_TREE_HEIGHT - 1;

        assert_eq!(set.root_at_height(pre_activation_height), set.root());
        assert!(matches!(
            set.prove_at_height(&present, pre_activation_height),
            AuthTreeProof::V1LegacySparse(_)
        ));

        let compressed_root = set.root_at_height(COMPRESSED_AUTH_TREE_HEIGHT);
        assert_ne!(compressed_root, set.root());
        let AuthTreeProof::V2Compressed(proof) =
            set.prove_at_height(&present, COMPRESSED_AUTH_TREE_HEIGHT)
        else {
            panic!("expected compressed proof at activation");
        };
        assert!(CompressedAuthTree::verify_proof(
            compressed_root,
            present.0,
            &proof
        ));
    }

    #[test]
    fn legacy_smt_updates_until_activation_then_freezes() {
        let mut set = NullifierSet::new();
        assert!(
            COMPRESSED_AUTH_TREE_HEIGHT > 0,
            "this test needs a pre-activation height"
        );
        let last_legacy_height = COMPRESSED_AUTH_TREE_HEIGHT - 1;
        let activation_height = COMPRESSED_AUTH_TREE_HEIGHT;

        let legacy_root_before = set.root();
        let first = nullifier(0x81);
        assert!(set.insert_at_height(first, last_legacy_height));
        assert_ne!(
            set.root(),
            legacy_root_before,
            "legacy SMT must still be updated by the last pre-activation block"
        );
        let frozen_legacy_root = set.root();
        let compressed_before_activation_mutation = set.root_at_height(activation_height);
        let before_activation_mutation = set.clone();

        let second = nullifier(0x82);
        assert!(set.insert_at_height(second, activation_height));
        assert!(set.contains(&first));
        assert!(set.contains(&second));
        assert_eq!(
            set.root(),
            frozen_legacy_root,
            "legacy SMT must be untouched at the first compressed-tree block height"
        );
        assert!(
            set.legacy_smt_ptr_eq(&before_activation_mutation),
            "post-activation nullifier mutation must not copy or mutate the frozen legacy SMT"
        );
        assert_ne!(
            set.root_at_height(activation_height),
            compressed_before_activation_mutation,
            "compressed tree must still track post-activation canonical nullifier mutations"
        );

        let before_rollback_remove = set.clone();
        assert!(set.remove_for_rollback_at_height(&first, activation_height));
        assert_eq!(
            set.root(),
            frozen_legacy_root,
            "post-activation nullifier rollback removal must not mutate the frozen legacy SMT"
        );
        assert!(
            set.legacy_smt_ptr_eq(&before_rollback_remove),
            "post-activation rollback removal must keep sharing the frozen legacy SMT"
        );
    }

    #[test]
    fn post_activation_decode_skips_legacy_smt_rebuild_but_preserves_compressed_root() {
        let mut set = NullifierSet::new();
        set.insert(nullifier(0x91));
        set.insert(nullifier(0x92));
        let encoded = set.encode_to_vec();
        let expected_compressed_root = set.root_at_height(COMPRESSED_AUTH_TREE_HEIGHT);

        let decoded = NullifierSet::decode_at_height(
            &mut ByteReader::new(&encoded),
            COMPRESSED_AUTH_TREE_HEIGHT,
        )
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
    fn persistent_spent_preserves_legacy_encoding_order_and_compressed_proofs() {
        let mut set = NullifierSet::new();
        let mut legacy_spent = HashSet::new();
        for tag in [0x44, 0x11, 0x77, 0x22] {
            let n = nullifier(tag);
            assert!(set.insert(n));
            assert!(legacy_spent.insert(n));
        }

        let mut legacy_encoded_nullifiers: Vec<_> = legacy_spent.iter().copied().collect();
        legacy_encoded_nullifiers.sort_by_key(|nullifier| nullifier.0);
        let mut legacy_encoded = Vec::new();
        encode_list(&legacy_encoded_nullifiers, &mut legacy_encoded);
        assert_eq!(
            set.encode_to_vec(),
            legacy_encoded,
            "PersistentOrdSet-backed NullifierSet encoding must remain byte-identical to sorted legacy HashSet encoding"
        );

        let legacy_compressed = CompressedAuthTree::from_pairs(
            legacy_spent
                .iter()
                .copied()
                .map(|nullifier| (nullifier.0, sha256(&nullifier.0))),
        )
        .unwrap();
        assert_eq!(
            set.root_at_height(COMPRESSED_AUTH_TREE_HEIGHT),
            legacy_compressed.root()
        );

        for n in legacy_spent {
            let AuthTreeProof::V2Compressed(proof) =
                set.prove_at_height(&n, COMPRESSED_AUTH_TREE_HEIGHT)
            else {
                panic!("expected compressed nullifier proof after activation");
            };
            assert_eq!(proof, legacy_compressed.prove(n.0));
        }
    }

    #[test]
    fn persistent_spent_is_insertion_order_independent() {
        let nullifiers: Vec<_> = (0..8u8).map(nullifier).collect();
        let mut forward = NullifierSet::new();
        let mut reverse = NullifierSet::new();

        for n in nullifiers.iter().copied() {
            assert!(forward.insert(n));
        }
        for n in nullifiers.into_iter().rev() {
            assert!(reverse.insert(n));
        }

        assert_eq!(forward.encode_to_vec(), reverse.encode_to_vec());
        assert_eq!(
            forward.root_at_height(COMPRESSED_AUTH_TREE_HEIGHT),
            reverse.root_at_height(COMPRESSED_AUTH_TREE_HEIGHT)
        );
    }

    #[test]
    #[ignore = "release-mode Stage 2b clone benchmark; run with --release --ignored --nocapture"]
    fn persistent_spent_and_compressed_tree_clone_benchmark() {
        // This is intentionally ignored and release-mode-only. The benchmark
        // isolates the Stage 2b payoff: cloning canonical nullifiers plus the
        // active compressed tree. Debug-mode timings are not meaningful.
        let sizes = env::var("INDRA_STAGE2B_NULLIFIER_CLONE_BENCH_SIZES")
            .unwrap_or_else(|_| "100000,1000000".to_string());
        for size in sizes
            .split(',')
            .map(|raw| raw.trim().parse::<usize>().expect("valid benchmark size"))
        {
            let mut nullifiers: Vec<_> = (0..size)
                .map(|i| {
                    let mut bytes = [0u8; 32];
                    bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    Bytes32::from(sha256(&bytes))
                })
                .collect();
            nullifiers.sort_by_key(|nullifier| nullifier.0);

            let mut migrated = NullifierSet::new();
            for n in nullifiers.iter().copied() {
                assert!(migrated.insert_at_height(n, COMPRESSED_AUTH_TREE_HEIGHT));
            }
            let legacy_spent: HashSet<_> = nullifiers.iter().copied().collect();
            let legacy_compressed = CompressedAuthTree::from_pairs(
                nullifiers
                    .iter()
                    .copied()
                    .map(|nullifier| (nullifier.0, sha256(&nullifier.0))),
            )
            .unwrap();
            let mut legacy_encoded = Vec::new();
            encode_list(&nullifiers, &mut legacy_encoded);
            assert_eq!(
                migrated.encode_to_vec(),
                legacy_encoded,
                "large-scale migrated nullifier encoding must stay byte-identical to the sorted legacy HashSet encoding"
            );

            let start = Instant::now();
            let migrated_clone = migrated.clone();
            let migrated_clone_time = start.elapsed();
            std::hint::black_box(migrated_clone);

            let start = Instant::now();
            let legacy_spent_clone = legacy_spent.clone();
            let legacy_compressed_clone = legacy_compressed.clone();
            let legacy_clone_time = start.elapsed();
            std::hint::black_box((legacy_spent_clone, legacy_compressed_clone));

            assert!(
                migrated_clone_time < Duration::from_millis(10),
                "persistent nullifier clone should be near-constant, got {:?}",
                migrated_clone_time
            );
            eprintln!(
                "[stage2b-clone] nullifiers={size} migrated_spent_plus_compressed_clone={:?} legacy_hashset_plus_compressed_clone={:?}",
                migrated_clone_time, legacy_clone_time
            );
        }
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
            let mut nullifiers: Vec<_> = (0..size)
                .map(|i| {
                    let mut bytes = [0u8; 32];
                    bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    Bytes32::from(sha256(&bytes))
                })
                .collect();
            nullifiers.sort_by_key(|nullifier| nullifier.0);
            let mut encoded = Vec::new();
            encode_list(&nullifiers, &mut encoded);

            let start = Instant::now();
            let post_activation = NullifierSet::decode_at_height(
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
                    NullifierSet::decode_at_height(&mut ByteReader::new(&encoded), 0).unwrap();
                let pre_activation_decode = start.elapsed();

                let start = Instant::now();
                let legacy_deep_clone = (*pre_activation.smt).clone();
                let old_deep_clone = start.elapsed();
                std::hint::black_box(legacy_deep_clone);
                std::hint::black_box(pre_activation);
                (Some(old_deep_clone), Some(pre_activation_decode))
            };

            eprintln!(
                "[legacy-smt-freeze] nullifiers={size} post_activation_decode={:?} pre_activation_decode_old_rebuild={:?} legacy_arc_clone={:?} legacy_deep_clone_old={:?}",
                post_activation_decode, pre_activation_decode, arc_clone, old_deep_clone
            );
        }
    }
}
