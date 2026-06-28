//! Sparse Merkle Tree over a 256-bit key space.
//!
//! This is a deterministic sparse tree suitable for state commitments and
//! inclusion/exclusion proofs. The implementation keeps a sparse map of
//! populated leaves and recomputes the affected internal nodes eagerly on
//! every update. That keeps the external API incremental while preserving
//! simple, auditable logic.
//!
//! ## Determinism guarantees
//!
//! The root hash is deterministic and independent of leaf insertion or
//! deletion order. This is a consensus-critical invariant: all validators
//! must compute identical roots from identical leaf sets.
//!
//! Internal `HashMap` usage is safe because nodes are keyed by
//! deterministic `NodeLoc` values and the root is retrieved by a fixed
//! root key, not by iteration. See `recompute()` for the safety comment.
//!
//! **Do not** add iteration-order-dependent logic to `recompute()` without
//! updating the determinism tests and this documentation.

use std::collections::HashMap;

use indra_core::types::primitives::Bytes32;
use indra_crypto::sha256;

/// Total depth of the sparse tree.
pub const SMT_DEPTH: usize = 256;

/// Inclusion or exclusion proof for a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    /// The queried key.
    pub key: [u8; 32],
    /// The proven value, or `None` for an exclusion proof.
    pub value: Option<[u8; 32]>,
    /// Sibling hashes from leaf level up to the root.
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NodeLoc {
    depth: u16,
    prefix: [u8; 32],
}

/// Sparse Merkle Tree with a 256-bit key space.
#[derive(Debug, Clone, Default)]
pub struct SparseMerkleTree {
    leaves: HashMap<[u8; 32], [u8; 32]>,
    nodes: HashMap<NodeLoc, [u8; 32]>,
    root: [u8; 32],
}

impl SparseMerkleTree {
    /// Create an empty tree.
    pub fn new() -> Self {
        let empty_hashes = empty_hashes();
        Self {
            leaves: HashMap::new(),
            nodes: HashMap::new(),
            root: *empty_hashes.first().unwrap_or(&[0u8; 32]),
        }
    }

    /// Insert or replace a leaf.
    pub fn insert(&mut self, key: [u8; 32], value: [u8; 32]) {
        self.leaves.insert(key, value);
        self.recompute();
    }

    /// Delete a leaf if it exists.
    pub fn delete(&mut self, key: [u8; 32]) {
        self.leaves.remove(&key);
        self.recompute();
    }

    /// Current root hash.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Build an inclusion or exclusion proof for a key.
    pub fn prove(&self, key: [u8; 32]) -> MerkleProof {
        let empty_hashes = empty_hashes();
        let mut siblings = Vec::with_capacity(SMT_DEPTH);

        for bit_index in (0..SMT_DEPTH).rev() {
            let depth = u16::try_from(bit_index.saturating_add(1)).unwrap_or(0);
            let sibling_prefix = sibling_prefix(key, bit_index);
            let sibling_loc = NodeLoc {
                depth,
                prefix: sibling_prefix,
            };
            let sibling_hash = self.nodes.get(&sibling_loc).copied().unwrap_or_else(|| {
                empty_hashes
                    .get(bit_index + 1)
                    .copied()
                    .unwrap_or([0u8; 32])
            });
            siblings.push(sibling_hash);
        }

        MerkleProof {
            key,
            value: self.leaves.get(&key).copied(),
            siblings,
        }
    }

    /// Verify an inclusion or exclusion proof against a root.
    pub fn verify_proof(root: [u8; 32], key: [u8; 32], proof: &MerkleProof) -> bool {
        if proof.key != key || proof.siblings.len() != SMT_DEPTH {
            return false;
        }

        let empty_hashes = empty_hashes();
        let mut acc = proof
            .value
            .map(|value| hash_leaf(&key, &value))
            .unwrap_or_else(|| empty_hashes.get(SMT_DEPTH).copied().unwrap_or([0u8; 32]));

        for (index, sibling) in proof.siblings.iter().enumerate() {
            let bit_index = SMT_DEPTH.saturating_sub(1 + index);
            if bit_at(&key, bit_index) {
                acc = hash_internal(sibling, &acc);
            } else {
                acc = hash_internal(&acc, sibling);
            }
        }

        acc == root
    }

    fn recompute(&mut self) {
        // DETERMINISM SAFETY: This function uses HashMap internally for
        // intermediate node storage. The computed root is order-insensitive
        // because every node is keyed by its deterministic NodeLoc (depth +
        // prefix), and parent hashes are pure functions of (left_child,
        // right_child) selected by bit_at(), not by iteration order.
        //
        // MAINTENANCE WARNING: Do NOT fold HashMap entries directly into a
        // running hash or accumulator. Always key by NodeLoc and fetch by
        // deterministic location. Violating this breaks consensus determinism.
        //
        // The test `deterministic_independent_of_insertion_order` guards this
        // invariant. Add new leaves to that test when adding new leaf types.
        let empty_hashes = empty_hashes();
        let mut levels: Vec<HashMap<NodeLoc, [u8; 32]>> =
            (0..=SMT_DEPTH).map(|_| HashMap::new()).collect();

        if let Some(leaf_level) = levels.get_mut(SMT_DEPTH) {
            for (key, value) in &self.leaves {
                leaf_level.insert(
                    NodeLoc {
                        depth: depth_from_bit(SMT_DEPTH),
                        prefix: *key,
                    },
                    hash_leaf(key, value),
                );
            }
        }

        for bit_index in (0..SMT_DEPTH).rev() {
            let child_depth = bit_index + 1;
            let Some(child_level) = levels.get(child_depth).cloned() else {
                continue;
            };
            let mut grouped: HashMap<NodeLoc, (Option<[u8; 32]>, Option<[u8; 32]>)> =
                HashMap::new();
            for (loc, hash) in child_level {
                let parent = NodeLoc {
                    depth: depth_from_bit(bit_index),
                    prefix: truncate_key(loc.prefix, bit_index),
                };
                let entry = grouped.entry(parent).or_insert((None, None));
                if bit_at(&loc.prefix, bit_index) {
                    entry.1 = Some(hash);
                } else {
                    entry.0 = Some(hash);
                }
            }

            let Some(level) = levels.get_mut(bit_index) else {
                continue;
            };
            for (parent, (left, right)) in grouped {
                let empty_child = empty_hashes.get(child_depth).copied().unwrap_or([0u8; 32]);
                let left_hash = left.unwrap_or(empty_child);
                let right_hash = right.unwrap_or(empty_child);
                level.insert(parent, hash_internal(&left_hash, &right_hash));
            }
        }

        self.nodes.clear();
        for level in levels {
            for (loc, hash) in level {
                self.nodes.insert(loc, hash);
            }
        }

        self.root = self
            .nodes
            .get(&NodeLoc {
                depth: 0,
                prefix: [0u8; 32],
            })
            .copied()
            .unwrap_or_else(|| empty_hashes.first().copied().unwrap_or([0u8; 32]));
    }
}

fn empty_hashes() -> Vec<[u8; 32]> {
    let mut hashes = vec![[0u8; 32]; SMT_DEPTH + 1];
    if let Some(last) = hashes.get_mut(SMT_DEPTH) {
        *last = sha256(b"EMPTY");
    }

    for bit_index in (0..SMT_DEPTH).rev() {
        let child = hashes.get(bit_index + 1).copied().unwrap_or([0u8; 32]);
        if let Some(slot) = hashes.get_mut(bit_index) {
            *slot = hash_internal(&child, &child);
        }
    }

    hashes
}

fn depth_from_bit(bit_index: usize) -> u16 {
    u16::try_from(bit_index).unwrap_or(0)
}

fn hash_leaf(key: &[u8; 32], value: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(65);
    data.push(0u8);
    data.extend_from_slice(key);
    data.extend_from_slice(value);
    sha256(&data)
}

fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(65);
    data.push(1u8);
    data.extend_from_slice(left);
    data.extend_from_slice(right);
    sha256(&data)
}

fn bit_at(key: &[u8; 32], bit_index: usize) -> bool {
    let byte_index = bit_index / 8;
    let bit_offset = 7u8.saturating_sub(u8::try_from(bit_index % 8).unwrap_or(0));
    match key.get(byte_index) {
        Some(byte) => (byte & (1u8 << bit_offset)) != 0,
        None => false,
    }
}

fn truncate_key(key: [u8; 32], depth: usize) -> [u8; 32] {
    let mut prefix = [0u8; 32];
    for bit_index in 0..depth {
        if bit_at(&key, bit_index) {
            set_bit(&mut prefix, bit_index, true);
        }
    }
    prefix
}

fn sibling_prefix(key: [u8; 32], bit_index: usize) -> [u8; 32] {
    let mut sibling = truncate_key(key, bit_index + 1);
    let current = bit_at(&key, bit_index);
    set_bit(&mut sibling, bit_index, !current);
    sibling
}

fn set_bit(bytes: &mut [u8; 32], bit_index: usize, value: bool) {
    let byte_index = bit_index / 8;
    let bit_offset = 7u8.saturating_sub(u8::try_from(bit_index % 8).unwrap_or(0));
    if let Some(byte) = bytes.get_mut(byte_index) {
        if value {
            *byte |= 1u8 << bit_offset;
        } else {
            *byte &= !(1u8 << bit_offset);
        }
    }
}

/// Convert a 32-byte root hash into `Bytes32`.
pub fn as_bytes32(hash: [u8; 32]) -> Bytes32 {
    Bytes32::from(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn value(byte: u8) -> [u8; 32] {
        sha256(&[byte; 8])
    }

    #[test]
    fn insert_and_inclusion_proof() {
        let mut smt = SparseMerkleTree::new();
        let k = key(0x11);
        let v = value(0x22);
        smt.insert(k, v);
        let proof = smt.prove(k);
        assert_eq!(proof.value, Some(v));
        assert!(SparseMerkleTree::verify_proof(smt.root(), k, &proof));
    }

    #[test]
    fn delete_and_exclusion_proof() {
        let mut smt = SparseMerkleTree::new();
        let k = key(0x33);
        smt.insert(k, value(0x44));
        smt.delete(k);
        let proof = smt.prove(k);
        assert_eq!(proof.value, None);
        assert!(SparseMerkleTree::verify_proof(smt.root(), k, &proof));
    }

    #[test]
    fn root_changes_on_updates() {
        let mut smt = SparseMerkleTree::new();
        let root0 = smt.root();
        smt.insert(key(0x01), value(0x02));
        let root1 = smt.root();
        smt.insert(key(0x03), value(0x04));
        let root2 = smt.root();
        smt.delete(key(0x01));
        let root3 = smt.root();
        assert_ne!(root0, root1);
        assert_ne!(root1, root2);
        assert_ne!(root2, root3);
    }

    #[test]
    fn deterministic_independent_of_insertion_order() {
        let pairs: Vec<([u8; 32], [u8; 32])> = (0u8..16)
            .map(|i| (key(i), value(i.wrapping_mul(3))))
            .collect();

        let mut a = SparseMerkleTree::new();
        for (k, v) in &pairs {
            a.insert(*k, *v);
        }

        let mut b = SparseMerkleTree::new();
        for (k, v) in pairs.iter().rev() {
            b.insert(*k, *v);
        }

        let mut c = SparseMerkleTree::new();
        let mut shuffled = pairs.clone();
        shuffled.rotate_left(7);
        for (k, v) in &shuffled {
            c.insert(*k, *v);
        }

        assert_eq!(
            a.root(),
            b.root(),
            "SMT root must be identical regardless of insertion order (forward vs reverse)"
        );
        assert_eq!(
            a.root(),
            c.root(),
            "SMT root must be identical regardless of insertion order (forward vs shuffled)"
        );

        let proof_a = a.prove(pairs[0].0);
        let proof_b = b.prove(pairs[0].0);
        assert_eq!(
            proof_a.siblings, proof_b.siblings,
            "SMT proof siblings must be identical regardless of insertion order"
        );
    }

    #[test]
    fn smt_root_is_independent_of_deletion_order() {
        let all_pairs: Vec<([u8; 32], [u8; 32])> = (0u8..8).map(|i| (key(i), value(i))).collect();
        let to_delete: Vec<[u8; 32]> = (0u8..4).map(key).collect();

        let mut a = SparseMerkleTree::new();
        for (k, v) in &all_pairs {
            a.insert(*k, *v);
        }
        for k in &to_delete {
            a.delete(*k);
        }

        let mut b = SparseMerkleTree::new();
        for (k, v) in &all_pairs {
            b.insert(*k, *v);
        }
        for k in to_delete.iter().rev() {
            b.delete(*k);
        }

        assert_eq!(
            a.root(),
            b.root(),
            "SMT root must be identical regardless of deletion order"
        );
    }
}
