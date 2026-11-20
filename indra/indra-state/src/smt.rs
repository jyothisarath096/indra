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

use std::collections::{BTreeMap, HashMap};

use indra_crypto::sha256;

use crate::error::{StateError, StateResult};

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

/// Versioned authenticated-tree proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthTreeProof {
    /// Compressed authenticated tree proof.
    V2Compressed(CompressedProof),
}

/// Compressed authenticated tree proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedProof {
    /// The queried key.
    pub key: [u8; 32],
    /// The proven value for inclusion proofs, or `None` for non-membership.
    pub value: Option<[u8; 32]>,
    /// Terminal proof case at the queried subtree.
    pub terminal: ProofTerminal,
    /// Branch reconstruction steps from the terminal subtree upward to root.
    pub steps: Vec<CompressedProofStep>,
}

/// Terminal case for a compressed authenticated proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofTerminal {
    /// The queried key is present.
    Included,
    /// The queried key's next child is absent from an otherwise matching branch.
    MissingChild,
    /// The queried path terminates at a different leaf.
    DivergentLeaf {
        /// Existing leaf key proving non-membership of the queried key.
        existing_key: [u8; 32],
        /// Existing leaf value hash.
        existing_value_hash: [u8; 32],
    },
    /// The queried key diverges before a compressed branch's prefix.
    PrefixMismatch {
        /// The branch prefix, as nibbles.
        branch_prefix: Vec<u8>,
        /// All committed children of the mismatched branch.
        children: Vec<CompressedProofChild>,
    },
}

/// One compressed branch reconstruction step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedProofStep {
    /// Branch prefix, as nibbles.
    pub branch_prefix: Vec<u8>,
    /// Nibble followed by the queried key at this branch.
    pub target_nibble: u8,
    /// Bitmap of non-empty children committed by this branch.
    pub child_bitmap: u16,
    /// Sibling children required to reconstruct this branch, sorted by nibble.
    pub siblings: Vec<CompressedProofChild>,
}

/// A revealed compressed-branch child hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedProofChild {
    /// Child nibble, 0..=15.
    pub nibble: u8,
    /// Child node kind.
    pub kind: CompressedChildKind,
    /// Child hash.
    pub hash: [u8; 32],
}

/// Hash-domain child kind committed in compressed branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressedChildKind {
    /// Leaf child.
    Leaf,
    /// Branch child.
    Branch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthTreeNode {
    Empty,
    Leaf {
        key: [u8; 32],
        value_hash: [u8; 32],
        hash: [u8; 32],
    },
    Branch {
        prefix: Vec<u8>,
        children: BTreeMap<u8, Box<AuthTreeNode>>,
        hash: [u8; 32],
    },
}

/// Compressed authenticated tree over a 256-bit key space.
///
/// This is a current-state, Jellyfish-style compressed sparse tree. It stores
/// full keys at leaves, compressed nibble prefixes at branches, and never
/// materializes empty subtrees or single-child branch chains. Internal node
/// hashes are domain-separated from the fixed-depth sparse tree so roots cannot be confused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedAuthTree {
    leaves: HashMap<[u8; 32], [u8; 32]>,
    root: AuthTreeNode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NodeLoc {
    depth: usize,
    prefix: [u8; 32],
}

#[cfg(test)]
type ChildHashes = (Option<[u8; 32]>, Option<[u8; 32]>);

/// Sparse Merkle Tree with a 256-bit key space.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SparseMerkleTree {
    leaves: HashMap<[u8; 32], [u8; 32]>,
    nodes: HashMap<NodeLoc, [u8; 32]>,
    root: [u8; 32],
}

impl Default for CompressedAuthTree {
    fn default() -> Self {
        Self::new()
    }
}

impl CompressedAuthTree {
    /// Create an empty compressed authenticated tree.
    pub fn new() -> Self {
        Self {
            leaves: HashMap::new(),
            root: AuthTreeNode::Empty,
        }
    }

    /// Build a compressed tree from a complete leaf set in one deterministic pass.
    pub fn from_pairs<I>(pairs: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = ([u8; 32], [u8; 32])>,
    {
        let mut sorted: Vec<_> = pairs.into_iter().collect();
        sorted.sort_by_key(|(key, _)| *key);
        for (first, second) in sorted.iter().zip(sorted.iter().skip(1)) {
            if first.0 == second.0 {
                return Err("duplicate compressed authenticated tree key".to_string());
            }
        }
        let leaves = sorted.iter().copied().collect::<HashMap<_, _>>();
        let root = build_compressed_subtree(&sorted, 0).map_err(|err| err.to_string())?;
        Ok(Self { leaves, root })
    }

    /// Number of real leaves in the tree.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// True if the tree has no leaves.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Number of materialized compressed nodes, including leaves.
    pub fn materialized_node_count(&self) -> usize {
        compressed_node_count(&self.root)
    }

    /// Insert or replace a leaf.
    pub fn insert(&mut self, key: [u8; 32], value_hash: [u8; 32]) -> StateResult<()> {
        self.leaves.insert(key, value_hash);
        let root = std::mem::replace(&mut self.root, AuthTreeNode::Empty);
        self.root = compressed_insert(root, key, value_hash)?;
        Ok(())
    }

    /// Delete a leaf if it exists.
    pub fn delete(&mut self, key: [u8; 32]) -> StateResult<()> {
        self.leaves.remove(&key);
        let root = std::mem::replace(&mut self.root, AuthTreeNode::Empty);
        self.root = compressed_delete(root, key)?;
        Ok(())
    }

    /// Current compressed root hash.
    pub fn root(&self) -> [u8; 32] {
        self.root.hash()
    }

    /// Build an inclusion or non-membership proof for a key.
    pub fn prove(&self, key: [u8; 32]) -> CompressedProof {
        let mut proof = compressed_prove(&self.root, key);
        proof.key = key;
        proof
    }

    /// Verify a compressed proof against a root.
    pub fn verify_proof(root: [u8; 32], key: [u8; 32], proof: &CompressedProof) -> bool {
        if proof.key != key {
            return false;
        }
        let key_nibbles = key_to_nibbles(&key);
        let (mut acc, mut child_kind, mut child_present) = match &proof.terminal {
            ProofTerminal::Included => {
                let Some(value_hash) = proof.value else {
                    return false;
                };
                (
                    hash_compressed_leaf(&key, &value_hash),
                    CompressedChildKind::Leaf,
                    true,
                )
            }
            ProofTerminal::MissingChild => {
                if proof.value.is_some() {
                    return false;
                }
                (compressed_empty_hash(), CompressedChildKind::Leaf, false)
            }
            ProofTerminal::DivergentLeaf {
                existing_key,
                existing_value_hash,
            } => {
                if proof.value.is_some() || existing_key == &key {
                    return false;
                }
                (
                    hash_compressed_leaf(existing_key, existing_value_hash),
                    CompressedChildKind::Leaf,
                    true,
                )
            }
            ProofTerminal::PrefixMismatch {
                branch_prefix,
                children,
            } => {
                if proof.value.is_some()
                    || starts_with_nibbles(&key_nibbles, branch_prefix)
                    || children.is_empty()
                {
                    return false;
                }
                let Ok(hash) = hash_branch_from_children(branch_prefix, children) else {
                    return false;
                };
                (hash, CompressedChildKind::Branch, true)
            }
        };

        for step in &proof.steps {
            if !valid_nibble_path(&step.branch_prefix)
                || step.target_nibble > 0x0F
                || !starts_with_nibbles(&key_nibbles, &step.branch_prefix)
                || step.branch_prefix.len() >= key_nibbles.len()
                || key_nibbles.get(step.branch_prefix.len()).copied() != Some(step.target_nibble)
            {
                return false;
            }
            let mut children = step.siblings.clone();
            if child_present {
                children.push(CompressedProofChild {
                    nibble: step.target_nibble,
                    kind: child_kind,
                    hash: acc,
                });
            }
            children.sort_by_key(|child| child.nibble);
            let bitmap = child_bitmap(&children);
            if bitmap != Some(step.child_bitmap) {
                return false;
            }
            if child_present {
                if (step.child_bitmap & (1u16 << step.target_nibble)) == 0 {
                    return false;
                }
            } else if (step.child_bitmap & (1u16 << step.target_nibble)) != 0 {
                return false;
            }
            let Ok(hash) = hash_branch_from_children(&step.branch_prefix, &children) else {
                return false;
            };
            acc = hash;
            child_kind = CompressedChildKind::Branch;
            child_present = true;
        }

        acc == root
    }
}

impl AuthTreeNode {
    fn hash(&self) -> [u8; 32] {
        match self {
            AuthTreeNode::Empty => compressed_empty_hash(),
            AuthTreeNode::Leaf { hash, .. } | AuthTreeNode::Branch { hash, .. } => *hash,
        }
    }

    fn kind(&self) -> CompressedChildKind {
        match self {
            AuthTreeNode::Leaf { .. } => CompressedChildKind::Leaf,
            AuthTreeNode::Branch { .. } | AuthTreeNode::Empty => CompressedChildKind::Branch,
        }
    }
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
        self.update_path(key);
    }

    /// Delete a leaf if it exists.
    pub fn delete(&mut self, key: [u8; 32]) {
        self.leaves.remove(&key);
        self.update_path(key);
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
            let depth = bit_index.saturating_add(1);
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

    #[cfg(test)]
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
            let mut grouped: HashMap<NodeLoc, ChildHashes> = HashMap::new();
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

    fn update_path(&mut self, key: [u8; 32]) {
        let empty_hashes = empty_hashes();
        let mut acc = self
            .leaves
            .get(&key)
            .map(|value| hash_leaf(&key, value))
            .unwrap_or_else(|| empty_hashes.get(SMT_DEPTH).copied().unwrap_or([0u8; 32]));

        let leaf_loc = NodeLoc {
            depth: depth_from_bit(SMT_DEPTH),
            prefix: key,
        };
        set_or_remove_node(
            &mut self.nodes,
            leaf_loc,
            acc,
            empty_hashes.get(SMT_DEPTH).copied().unwrap_or([0u8; 32]),
        );

        for bit_index in (0..SMT_DEPTH).rev() {
            let child_depth = bit_index + 1;
            let sibling_loc = NodeLoc {
                depth: depth_from_bit(child_depth),
                prefix: sibling_prefix(key, bit_index),
            };
            let sibling_hash = self
                .nodes
                .get(&sibling_loc)
                .copied()
                .unwrap_or_else(|| empty_hashes.get(child_depth).copied().unwrap_or([0u8; 32]));

            acc = if bit_at(&key, bit_index) {
                hash_internal(&sibling_hash, &acc)
            } else {
                hash_internal(&acc, &sibling_hash)
            };

            let parent_loc = NodeLoc {
                depth: depth_from_bit(bit_index),
                prefix: truncate_key(key, bit_index),
            };
            set_or_remove_node(
                &mut self.nodes,
                parent_loc,
                acc,
                empty_hashes.get(bit_index).copied().unwrap_or([0u8; 32]),
            );
        }

        self.root = acc;
    }
}

fn build_compressed_subtree(
    pairs: &[([u8; 32], [u8; 32])],
    start_nibble: usize,
) -> StateResult<AuthTreeNode> {
    match pairs.len() {
        0 => Ok(AuthTreeNode::Empty),
        1 => {
            let [(key, value_hash)] = pairs else {
                return Err(StateError::InternalInvariant {
                    site: "smt::build_compressed_subtree singleton",
                });
            };
            Ok(AuthTreeNode::Leaf {
                key: *key,
                value_hash: *value_hash,
                hash: hash_compressed_leaf(key, value_hash),
            })
        }
        _ => {
            let prefix = longest_common_prefix_for_pairs(pairs, start_nibble)?;
            let mut children = BTreeMap::new();
            let mut index = 0usize;
            while index < pairs.len() {
                let (key, _) = pairs.get(index).ok_or(StateError::InternalInvariant {
                    site: "smt::build_compressed_subtree index",
                })?;
                let nibbles = key_to_nibbles(key);
                let child_nibble = nibbles.iter().copied().nth(prefix.len()).ok_or(
                    StateError::InternalInvariant {
                        site: "smt::build_compressed_subtree child nibble",
                    },
                )?;
                let mut end = index + 1;
                while end < pairs.len() {
                    let (other_key, _) = pairs.get(end).ok_or(StateError::InternalInvariant {
                        site: "smt::build_compressed_subtree end",
                    })?;
                    let other = key_to_nibbles(other_key);
                    let other_nibble = other.iter().copied().nth(prefix.len()).ok_or(
                        StateError::InternalInvariant {
                            site: "smt::build_compressed_subtree other nibble",
                        },
                    )?;
                    if other_nibble != child_nibble {
                        break;
                    }
                    end += 1;
                }
                let group = pairs.get(index..end).ok_or(StateError::InternalInvariant {
                    site: "smt::build_compressed_subtree group",
                })?;
                let child = build_compressed_subtree(group, prefix.len() + 1)?;
                children.insert(child_nibble, Box::new(child));
                index = end;
            }
            make_branch(prefix, children)
        }
    }
}

fn compressed_insert(
    node: AuthTreeNode,
    key: [u8; 32],
    value_hash: [u8; 32],
) -> StateResult<AuthTreeNode> {
    match node {
        AuthTreeNode::Empty => Ok(AuthTreeNode::Leaf {
            key,
            value_hash,
            hash: hash_compressed_leaf(&key, &value_hash),
        }),
        AuthTreeNode::Leaf {
            key: existing_key,
            value_hash: existing_value,
            ..
        } => {
            if existing_key == key {
                Ok(AuthTreeNode::Leaf {
                    key,
                    value_hash,
                    hash: hash_compressed_leaf(&key, &value_hash),
                })
            } else {
                let existing_nibbles = key_to_nibbles(&existing_key);
                let key_nibbles = key_to_nibbles(&key);
                let prefix_len = common_nibble_prefix_len(&existing_nibbles, &key_nibbles, 0);
                let prefix = key_nibbles.iter().take(prefix_len).copied().collect();
                let mut children = BTreeMap::new();
                let existing_nibble = existing_nibbles.iter().copied().nth(prefix_len).ok_or(
                    StateError::InternalInvariant {
                        site: "smt::compressed_insert existing nibble",
                    },
                )?;
                let new_nibble = key_nibbles.iter().copied().nth(prefix_len).ok_or(
                    StateError::InternalInvariant {
                        site: "smt::compressed_insert new nibble",
                    },
                )?;
                children.insert(
                    existing_nibble,
                    Box::new(AuthTreeNode::Leaf {
                        key: existing_key,
                        value_hash: existing_value,
                        hash: hash_compressed_leaf(&existing_key, &existing_value),
                    }),
                );
                children.insert(
                    new_nibble,
                    Box::new(AuthTreeNode::Leaf {
                        key,
                        value_hash,
                        hash: hash_compressed_leaf(&key, &value_hash),
                    }),
                );
                make_branch(prefix, children)
            }
        }
        AuthTreeNode::Branch {
            prefix,
            mut children,
            ..
        } => {
            let key_nibbles = key_to_nibbles(&key);
            let shared = common_nibble_prefix_len(&prefix, &key_nibbles, 0);
            if shared < prefix.len() {
                let old_nibble =
                    prefix
                        .iter()
                        .copied()
                        .nth(shared)
                        .ok_or(StateError::InternalInvariant {
                            site: "smt::compressed_insert old nibble",
                        })?;
                let new_nibble = key_nibbles.iter().copied().nth(shared).ok_or(
                    StateError::InternalInvariant {
                        site: "smt::compressed_insert new split nibble",
                    },
                )?;
                let mut split_children = BTreeMap::new();
                split_children.insert(old_nibble, Box::new(make_branch(prefix, children)?));
                split_children.insert(
                    new_nibble,
                    Box::new(AuthTreeNode::Leaf {
                        key,
                        value_hash,
                        hash: hash_compressed_leaf(&key, &value_hash),
                    }),
                );
                return make_branch(
                    key_nibbles.iter().take(shared).copied().collect(),
                    split_children,
                );
            }

            let child_nibble = key_nibbles.iter().copied().nth(prefix.len()).ok_or(
                StateError::InternalInvariant {
                    site: "smt::compressed_insert child nibble",
                },
            )?;
            let child = children
                .remove(&child_nibble)
                .map(|boxed| *boxed)
                .unwrap_or(AuthTreeNode::Empty);
            children.insert(
                child_nibble,
                Box::new(compressed_insert(child, key, value_hash)?),
            );
            make_branch(prefix, children)
        }
    }
}

fn compressed_delete(node: AuthTreeNode, key: [u8; 32]) -> StateResult<AuthTreeNode> {
    match node {
        AuthTreeNode::Empty => Ok(AuthTreeNode::Empty),
        AuthTreeNode::Leaf {
            key: existing_key, ..
        } => {
            if existing_key == key {
                Ok(AuthTreeNode::Empty)
            } else {
                Ok(node)
            }
        }
        AuthTreeNode::Branch {
            prefix,
            mut children,
            ..
        } => {
            let key_nibbles = key_to_nibbles(&key);
            if !starts_with_nibbles(&key_nibbles, &prefix) || prefix.len() >= key_nibbles.len() {
                return make_branch(prefix, children);
            }
            let child_nibble = key_nibbles.iter().copied().nth(prefix.len()).ok_or(
                StateError::InternalInvariant {
                    site: "smt::compressed_delete child nibble",
                },
            )?;
            if let Some(child) = children.remove(&child_nibble) {
                match compressed_delete(*child, key)? {
                    AuthTreeNode::Empty => {}
                    updated => {
                        children.insert(child_nibble, Box::new(updated));
                    }
                }
            }
            collapse_or_branch(prefix, children)
        }
    }
}

fn collapse_or_branch(
    prefix: Vec<u8>,
    mut children: BTreeMap<u8, Box<AuthTreeNode>>,
) -> StateResult<AuthTreeNode> {
    match children.len() {
        0 => Ok(AuthTreeNode::Empty),
        1 => match children.pop_first() {
            Some((_, child)) => Ok(*child),
            None => Err(StateError::InternalInvariant {
                site: "smt::collapse_or_branch child",
            }),
        },
        _ => make_branch(prefix, children),
    }
}

fn make_branch(
    prefix: Vec<u8>,
    children: BTreeMap<u8, Box<AuthTreeNode>>,
) -> StateResult<AuthTreeNode> {
    let mut proof_children = Vec::with_capacity(children.len());
    for (nibble, child) in &children {
        if matches!(**child, AuthTreeNode::Empty) {
            continue;
        }
        proof_children.push(CompressedProofChild {
            nibble: *nibble,
            kind: child.kind(),
            hash: child.hash(),
        });
    }
    if proof_children.is_empty() {
        return Ok(AuthTreeNode::Empty);
    }
    let hash = hash_branch_from_children(&prefix, &proof_children).map_err(|_| {
        StateError::InternalInvariant {
            site: "smt::make_branch proof children",
        }
    })?;
    Ok(AuthTreeNode::Branch {
        prefix,
        children,
        hash,
    })
}

fn compressed_prove(node: &AuthTreeNode, key: [u8; 32]) -> CompressedProof {
    let key_nibbles = key_to_nibbles(&key);
    match node {
        AuthTreeNode::Empty => CompressedProof {
            key,
            value: None,
            terminal: ProofTerminal::MissingChild,
            steps: Vec::new(),
        },
        AuthTreeNode::Leaf {
            key: existing_key,
            value_hash,
            ..
        } => {
            if existing_key == &key {
                CompressedProof {
                    key,
                    value: Some(*value_hash),
                    terminal: ProofTerminal::Included,
                    steps: Vec::new(),
                }
            } else {
                CompressedProof {
                    key,
                    value: None,
                    terminal: ProofTerminal::DivergentLeaf {
                        existing_key: *existing_key,
                        existing_value_hash: *value_hash,
                    },
                    steps: Vec::new(),
                }
            }
        }
        AuthTreeNode::Branch {
            prefix, children, ..
        } => {
            if !starts_with_nibbles(&key_nibbles, prefix) || prefix.len() >= key_nibbles.len() {
                return CompressedProof {
                    key,
                    value: None,
                    terminal: ProofTerminal::PrefixMismatch {
                        branch_prefix: prefix.clone(),
                        children: proof_children_from_map(children, None),
                    },
                    steps: Vec::new(),
                };
            }
            let mut target_iter = key_nibbles.iter().copied().skip(prefix.len());
            let Some(target) = target_iter.next() else {
                return CompressedProof {
                    key,
                    value: None,
                    terminal: ProofTerminal::PrefixMismatch {
                        branch_prefix: prefix.clone(),
                        children: proof_children_from_map(children, None),
                    },
                    steps: Vec::new(),
                };
            };
            let step = CompressedProofStep {
                branch_prefix: prefix.clone(),
                target_nibble: target,
                child_bitmap: child_bitmap_from_map(&proof_children_from_map(children, None)),
                siblings: proof_children_from_map(children, Some(target)),
            };
            if let Some(child) = children.get(&target) {
                let mut proof = compressed_prove(child, key);
                proof.steps.push(step);
                proof
            } else {
                CompressedProof {
                    key,
                    value: None,
                    terminal: ProofTerminal::MissingChild,
                    steps: vec![step],
                }
            }
        }
    }
}

fn proof_children_from_map(
    children: &BTreeMap<u8, Box<AuthTreeNode>>,
    exclude: Option<u8>,
) -> Vec<CompressedProofChild> {
    children
        .iter()
        .filter(|(nibble, child)| {
            Some(**nibble) != exclude && !matches!(***child, AuthTreeNode::Empty)
        })
        .map(|(nibble, child)| CompressedProofChild {
            nibble: *nibble,
            kind: child.kind(),
            hash: child.hash(),
        })
        .collect()
}

fn compressed_node_count(node: &AuthTreeNode) -> usize {
    match node {
        AuthTreeNode::Empty => 0,
        AuthTreeNode::Leaf { .. } => 1,
        AuthTreeNode::Branch { children, .. } => {
            1 + children
                .values()
                .map(|child| compressed_node_count(child))
                .sum::<usize>()
        }
    }
}

fn longest_common_prefix_for_pairs(
    pairs: &[([u8; 32], [u8; 32])],
    start_nibble: usize,
) -> StateResult<Vec<u8>> {
    let Some((first_key, _)) = pairs.first() else {
        return Err(StateError::InternalInvariant {
            site: "smt::longest_common_prefix empty pairs",
        });
    };
    let first = key_to_nibbles(first_key);
    let mut len = start_nibble;
    while len < first.len() {
        let Some(nibble) = first.iter().copied().nth(len) else {
            return Err(StateError::InternalInvariant {
                site: "smt::longest_common_prefix index",
            });
        };
        if pairs
            .iter()
            .skip(1)
            .all(|(key, _)| key_to_nibbles(key).iter().copied().nth(len) == Some(nibble))
        {
            len += 1;
        } else {
            break;
        }
    }
    Ok(first.iter().take(len).copied().collect())
}

fn common_nibble_prefix_len(a: &[u8], b: &[u8], start: usize) -> usize {
    let mut index = start;
    while index < a.len() && index < b.len() && a.get(index) == b.get(index) {
        index += 1;
    }
    index
}

fn starts_with_nibbles(key: &[u8], prefix: &[u8]) -> bool {
    key.get(..prefix.len()) == Some(prefix)
}

fn valid_nibble_path(path: &[u8]) -> bool {
    path.iter().all(|nibble| *nibble <= 0x0F) && path.len() <= 64
}

fn key_to_nibbles(key: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (byte, slots) in key.iter().copied().zip(out.chunks_exact_mut(2)) {
        let mut slots = slots.iter_mut();
        if let (Some(high), Some(low)) = (slots.next(), slots.next()) {
            *high = byte >> 4;
            *low = byte & 0x0F;
        }
    }
    out
}

fn pack_nibbles(nibbles: &[u8]) -> Option<Vec<u8>> {
    if !valid_nibble_path(nibbles) {
        return None;
    }
    let mut out = Vec::with_capacity(nibbles.len().div_ceil(2));
    for chunk in nibbles.chunks_exact(2) {
        let mut values = chunk.iter().copied();
        match (values.next(), values.next()) {
            (Some(high), Some(low)) => out.push((high << 4) | low),
            _ => return None,
        }
    }
    if let Some(&last) = nibbles.chunks_exact(2).remainder().first() {
        out.push(last << 4);
    }
    Some(out)
}

fn child_bitmap(children: &[CompressedProofChild]) -> Option<u16> {
    let mut bitmap = 0u16;
    let mut previous = None;
    for child in children {
        if child.nibble > 0x0F || previous.is_some_and(|prev| child.nibble <= prev) {
            return None;
        }
        bitmap |= 1u16 << child.nibble;
        previous = Some(child.nibble);
    }
    Some(bitmap)
}

fn child_bitmap_from_map(children: &[CompressedProofChild]) -> u16 {
    children
        .iter()
        .fold(0u16, |bitmap, child| bitmap | (1u16 << child.nibble))
}

fn compressed_empty_hash() -> [u8; 32] {
    sha256(b"INDRA-auth-tree-v2-empty")
}

fn hash_compressed_leaf(key: &[u8; 32], value_hash: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity("INDRA-auth-tree-v2-leaf".len() + 64);
    data.extend_from_slice(b"INDRA-auth-tree-v2-leaf");
    data.extend_from_slice(key);
    data.extend_from_slice(value_hash);
    sha256(&data)
}

fn hash_branch_from_children(
    prefix: &[u8],
    children: &[CompressedProofChild],
) -> Result<[u8; 32], String> {
    if !valid_nibble_path(prefix) || children.is_empty() {
        return Err("invalid compressed branch".to_string());
    }
    let bitmap = child_bitmap(children).ok_or_else(|| "invalid compressed children".to_string())?;
    let packed_prefix = pack_nibbles(prefix).ok_or_else(|| "invalid branch prefix".to_string())?;
    let mut data = Vec::with_capacity(32 + 1 + packed_prefix.len() + 2 + children.len() * 34);
    data.extend_from_slice(b"INDRA-auth-tree-v2-branch");
    data.push(u8::try_from(prefix.len()).map_err(|_| "branch prefix too long".to_string())?);
    data.extend_from_slice(&packed_prefix);
    data.extend_from_slice(&bitmap.to_le_bytes());
    for child in children {
        data.push(child.nibble);
        data.push(match child.kind {
            CompressedChildKind::Leaf => 0,
            CompressedChildKind::Branch => 1,
        });
        data.extend_from_slice(&child.hash);
    }
    Ok(sha256(&data))
}

fn set_or_remove_node(
    nodes: &mut HashMap<NodeLoc, [u8; 32]>,
    loc: NodeLoc,
    hash: [u8; 32],
    empty_hash: [u8; 32],
) {
    if hash == empty_hash {
        nodes.remove(&loc);
    } else {
        nodes.insert(loc, hash);
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

fn depth_from_bit(bit_index: usize) -> usize {
    bit_index
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
    let bit_offset = 7usize - (bit_index % 8);
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
    let bit_offset = 7usize - (bit_index % 8);
    if let Some(byte) = bytes.get_mut(byte_index) {
        if value {
            *byte |= 1u8 << bit_offset;
        } else {
            *byte &= !(1u8 << bit_offset);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_compressed_prefix_input_returns_typed_invariant_error() {
        assert_eq!(
            longest_common_prefix_for_pairs(&[], 0),
            Err(StateError::InternalInvariant {
                site: "smt::longest_common_prefix empty pairs",
            })
        );
    }

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn value(byte: u8) -> [u8; 32] {
        sha256(&[byte; 8])
    }

    fn ckey(first: u8, second: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = (first << 4) | second;
        out
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

    #[test]
    fn incremental_insert_delete_matches_full_recompute_sequence() {
        let mut incremental = SparseMerkleTree::new();
        let mut full = SparseMerkleTree::new();

        for i in 0u8..64 {
            let k = key(i.wrapping_mul(17));
            let v = value(i.wrapping_mul(31));
            incremental.insert(k, v);
            full.leaves.insert(k, v);
            full.recompute();
            assert_eq!(
                incremental.root(),
                full.root(),
                "incremental insert must match full recompute at step {i}"
            );
        }

        for i in (0u8..64).step_by(3) {
            let k = key(i.wrapping_mul(17));
            incremental.delete(k);
            full.leaves.remove(&k);
            full.recompute();
            assert_eq!(
                incremental.root(),
                full.root(),
                "incremental delete must match full recompute at step {i}"
            );
        }
    }

    #[test]
    fn proofs_verify_after_incremental_update_sequence() {
        let mut smt = SparseMerkleTree::new();
        let mut present = Vec::new();
        for i in 0u8..32 {
            let k = key(i.wrapping_mul(9));
            smt.insert(k, value(i.wrapping_add(1)));
            present.push(k);
        }
        for k in present.iter().step_by(4) {
            smt.delete(*k);
        }

        for k in &present {
            let proof = smt.prove(*k);
            assert!(SparseMerkleTree::verify_proof(smt.root(), *k, &proof));
        }
        let absent = key(0xFE);
        let proof = smt.prove(absent);
        assert!(SparseMerkleTree::verify_proof(smt.root(), absent, &proof));
    }

    #[test]
    fn compressed_tree_known_small_vector_root() {
        let k1 = ckey(0x1, 0x0);
        let k2 = ckey(0x1, 0x1);
        let v1 = value(0xA1);
        let v2 = value(0xA2);
        let tree = CompressedAuthTree::from_pairs([(k1, v1), (k2, v2)]).unwrap();

        let children = vec![
            CompressedProofChild {
                nibble: 0,
                kind: CompressedChildKind::Leaf,
                hash: hash_compressed_leaf(&k1, &v1),
            },
            CompressedProofChild {
                nibble: 1,
                kind: CompressedChildKind::Leaf,
                hash: hash_compressed_leaf(&k2, &v2),
            },
        ];
        let expected = hash_branch_from_children(&[0x1], &children).unwrap();
        assert_eq!(tree.root(), expected);
        assert_eq!(tree.materialized_node_count(), 3);
    }

    #[test]
    fn compressed_batch_construction_matches_incremental_construction() {
        let pairs: Vec<_> = (0u8..96)
            .map(|i| {
                let mut k = sha256(&[i; 4]);
                k[0] ^= i.rotate_left(1);
                (k, value(i.wrapping_mul(11)))
            })
            .collect();
        let batch = CompressedAuthTree::from_pairs(pairs.clone()).unwrap();
        let mut incremental = CompressedAuthTree::new();
        for (k, v) in pairs.iter().rev() {
            incremental.insert(*k, *v).unwrap();
        }
        assert_eq!(batch.root(), incremental.root());
        assert!(
            batch.materialized_node_count() <= batch.len().saturating_mul(2),
            "compressed tree should stay close to real leaf count"
        );
    }

    #[test]
    fn compressed_insert_update_delete_matches_batch_reference() {
        let mut live = CompressedAuthTree::new();
        let mut reference = HashMap::new();
        for i in 0u8..64 {
            let k = sha256(&[i, i.wrapping_mul(7)]);
            let v = value(i);
            live.insert(k, v).unwrap();
            reference.insert(k, v);
            let rebuilt =
                CompressedAuthTree::from_pairs(reference.iter().map(|(k, v)| (*k, *v))).unwrap();
            assert_eq!(live.root(), rebuilt.root());
        }
        for i in (0u8..64).step_by(5) {
            let k = sha256(&[i, i.wrapping_mul(7)]);
            live.delete(k).unwrap();
            reference.remove(&k);
            let rebuilt =
                CompressedAuthTree::from_pairs(reference.iter().map(|(k, v)| (*k, *v))).unwrap();
            assert_eq!(live.root(), rebuilt.root());
        }
    }

    #[test]
    fn compressed_inclusion_proof_verifies() {
        let k1 = ckey(0x1, 0x0);
        let k2 = ckey(0x1, 0x1);
        let tree = CompressedAuthTree::from_pairs([(k1, value(1)), (k2, value(2))]).unwrap();
        let proof = tree.prove(k1);
        assert!(matches!(proof.terminal, ProofTerminal::Included));
        assert!(CompressedAuthTree::verify_proof(tree.root(), k1, &proof));
    }

    #[test]
    fn compressed_non_membership_missing_child_verifies() {
        let k1 = ckey(0x1, 0x0);
        let k2 = ckey(0x1, 0x1);
        let missing = ckey(0x1, 0x2);
        let tree = CompressedAuthTree::from_pairs([(k1, value(1)), (k2, value(2))]).unwrap();
        let proof = tree.prove(missing);
        assert!(matches!(proof.terminal, ProofTerminal::MissingChild));
        assert!(CompressedAuthTree::verify_proof(
            tree.root(),
            missing,
            &proof
        ));
    }

    #[test]
    fn compressed_non_membership_divergent_leaf_verifies() {
        let present = ckey(0x4, 0x4);
        let missing = ckey(0x4, 0x5);
        let tree = CompressedAuthTree::from_pairs([(present, value(1))]).unwrap();
        let proof = tree.prove(missing);
        assert!(matches!(
            proof.terminal,
            ProofTerminal::DivergentLeaf { .. }
        ));
        assert!(CompressedAuthTree::verify_proof(
            tree.root(),
            missing,
            &proof
        ));
    }

    #[test]
    fn compressed_non_membership_prefix_mismatch_verifies() {
        let k1 = ckey(0x1, 0x0);
        let k2 = ckey(0x1, 0x1);
        let missing = ckey(0x2, 0x0);
        let tree = CompressedAuthTree::from_pairs([(k1, value(1)), (k2, value(2))]).unwrap();
        let proof = tree.prove(missing);
        assert!(matches!(
            proof.terminal,
            ProofTerminal::PrefixMismatch { .. }
        ));
        assert!(CompressedAuthTree::verify_proof(
            tree.root(),
            missing,
            &proof
        ));
    }

    #[test]
    fn compressed_proof_tampering_fails() {
        let k1 = ckey(0x1, 0x0);
        let k2 = ckey(0x1, 0x1);
        let tree = CompressedAuthTree::from_pairs([(k1, value(1)), (k2, value(2))]).unwrap();
        let mut proof = tree.prove(k1);
        assert!(CompressedAuthTree::verify_proof(tree.root(), k1, &proof));
        proof.steps[0].siblings[0].hash[0] ^= 0x80;
        assert!(!CompressedAuthTree::verify_proof(tree.root(), k1, &proof));
    }

    #[test]
    fn adversarial_compressed_inclusion_forgery_attempts_fail() {
        let k1 = ckey(0x1, 0x0);
        let k2 = ckey(0x1, 0x1);
        let absent = ckey(0x1, 0x2);
        let tree = CompressedAuthTree::from_pairs([(k1, value(1)), (k2, value(2))]).unwrap();
        let proof = tree.prove(k1);
        assert!(CompressedAuthTree::verify_proof(tree.root(), k1, &proof));

        let mut forged_value = proof.clone();
        forged_value.value = Some(value(99));
        assert!(
            !CompressedAuthTree::verify_proof(tree.root(), k1, &forged_value),
            "changing only the claimed value must not forge inclusion"
        );

        let mut stolen_for_absent_key = proof.clone();
        stolen_for_absent_key.key = absent;
        assert!(
            !CompressedAuthTree::verify_proof(tree.root(), absent, &stolen_for_absent_key),
            "a valid proof for one key must not be reusable for another key"
        );

        let mut terminal_flip = proof.clone();
        terminal_flip.value = None;
        terminal_flip.terminal = ProofTerminal::MissingChild;
        assert!(
            !CompressedAuthTree::verify_proof(tree.root(), k1, &terminal_flip),
            "flipping an inclusion proof into a non-membership terminal must fail"
        );
    }

    #[test]
    fn adversarial_compressed_non_membership_cannot_hide_present_keys() {
        let k1 = ckey(0x1, 0x0);
        let k2 = ckey(0x1, 0x1);
        let missing_child_key = ckey(0x1, 0x2);
        let prefix_mismatch_key = ckey(0x2, 0x0);
        let two_leaf_tree =
            CompressedAuthTree::from_pairs([(k1, value(1)), (k2, value(2))]).unwrap();

        let mut missing_child_proof = two_leaf_tree.prove(missing_child_key);
        assert!(matches!(
            missing_child_proof.terminal,
            ProofTerminal::MissingChild
        ));
        missing_child_proof.key = k1;
        assert!(
            !CompressedAuthTree::verify_proof(two_leaf_tree.root(), k1, &missing_child_proof),
            "a missing-child proof for an absent nibble must not prove non-membership for a present key"
        );

        let mut prefix_mismatch_proof = two_leaf_tree.prove(prefix_mismatch_key);
        assert!(matches!(
            prefix_mismatch_proof.terminal,
            ProofTerminal::PrefixMismatch { .. }
        ));
        prefix_mismatch_proof.key = k1;
        assert!(
            !CompressedAuthTree::verify_proof(two_leaf_tree.root(), k1, &prefix_mismatch_proof),
            "a prefix-mismatch proof must not be reusable against a key under that prefix"
        );

        let single_leaf_tree = CompressedAuthTree::from_pairs([(k1, value(1))]).unwrap();
        let mut divergent_leaf_proof = single_leaf_tree.prove(k2);
        assert!(matches!(
            divergent_leaf_proof.terminal,
            ProofTerminal::DivergentLeaf { .. }
        ));
        divergent_leaf_proof.key = k1;
        assert!(
            !CompressedAuthTree::verify_proof(single_leaf_tree.root(), k1, &divergent_leaf_proof),
            "a divergent-leaf proof naming the present leaf must not hide that same present key"
        );
    }

    #[test]
    fn adversarial_compressed_domain_and_child_encoding_confusion_fails() {
        let k1 = ckey(0x1, 0x0);
        let k2 = ckey(0x1, 0x1);
        let v1 = value(1);
        let v2 = value(2);
        let leaf_hash = hash_compressed_leaf(&k1, &v1);
        let branch_hash = hash_branch_from_children(
            &[0x1],
            &[
                CompressedProofChild {
                    nibble: 0,
                    kind: CompressedChildKind::Leaf,
                    hash: leaf_hash,
                },
                CompressedProofChild {
                    nibble: 1,
                    kind: CompressedChildKind::Leaf,
                    hash: hash_compressed_leaf(&k2, &v2),
                },
            ],
        )
        .unwrap();

        assert_ne!(compressed_empty_hash(), leaf_hash);
        assert_ne!(compressed_empty_hash(), branch_hash);
        assert_ne!(
            leaf_hash, branch_hash,
            "leaf and branch hash domains must remain structurally non-interchangeable"
        );

        let tree = CompressedAuthTree::from_pairs([(k1, v1), (k2, v2)]).unwrap();
        let mut proof = tree.prove(k1);
        assert!(CompressedAuthTree::verify_proof(tree.root(), k1, &proof));
        let duplicated_sibling = proof.steps[0].siblings[0];
        proof.steps[0].siblings.push(CompressedProofChild {
            nibble: duplicated_sibling.nibble,
            kind: CompressedChildKind::Leaf,
            hash: duplicated_sibling.hash,
        });
        assert!(
            !CompressedAuthTree::verify_proof(tree.root(), k1, &proof),
            "duplicate child encodings must be rejected rather than hashed ambiguously"
        );
    }

    #[test]
    fn adversarial_compressed_pathological_keys_and_ordering_are_deterministic() {
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k2[31] = 1;
        let mut k3 = [0xFFu8; 32];
        k3[31] = 0xFE;
        let pairs = vec![(k1, value(1)), (k2, value(2)), (k3, value(3))];

        assert!(
            CompressedAuthTree::from_pairs([(k1, value(1)), (k1, value(2))]).is_err(),
            "batch construction must reject duplicate keys instead of silently choosing an ordering"
        );

        let batch = CompressedAuthTree::from_pairs(pairs.clone()).unwrap();
        let mut forward = CompressedAuthTree::new();
        for (key, value_hash) in &pairs {
            forward.insert(*key, *value_hash).unwrap();
        }
        let mut reverse = CompressedAuthTree::new();
        for (key, value_hash) in pairs.iter().rev() {
            reverse.insert(*key, *value_hash).unwrap();
        }

        assert_eq!(batch.root(), forward.root());
        assert_eq!(batch.root(), reverse.root());
        for (key, _) in &pairs {
            let proof = reverse.prove(*key);
            assert!(CompressedAuthTree::verify_proof(
                reverse.root(),
                *key,
                &proof
            ));
        }

        k1[31] = 2;
        let missing = batch.prove(k1);
        assert!(CompressedAuthTree::verify_proof(batch.root(), k1, &missing));
    }

    #[test]
    fn p3_golden_roots_and_proof_bytes_are_stable() {
        let mut empty = SparseMerkleTree::new();
        let one_key = key(0x11);
        empty.insert(one_key, value(0x22));
        let one_root = empty.root();

        let mut colliding = SparseMerkleTree::new();
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k1[0] = 0x10;
        k2[0] = 0x11;
        colliding.insert(k1, value(1));
        colliding.insert(k2, value(2));

        let mut random = SparseMerkleTree::new();
        let mut seed = 0x9E3779B97F4A7C15u64;
        for i in 0..1000u64 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&seed.to_be_bytes());
            k[8..16].copy_from_slice(&i.to_be_bytes());
            random.insert(k, value((i as u8).wrapping_add(3)));
        }

        let mut sequence = SparseMerkleTree::new();
        for i in 0u8..32 {
            sequence.insert(key(i), value(i.wrapping_add(1)));
        }
        for i in (0u8..32).step_by(3) {
            sequence.delete(key(i));
        }
        for i in (1u8..32).step_by(4) {
            sequence.insert(key(i), value(i.wrapping_add(77)));
        }

        let proof = random.prove({
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&seed.to_be_bytes());
            k[8..16].copy_from_slice(&999u64.to_be_bytes());
            k
        });
        let mut proof_bytes = Vec::new();
        proof_bytes.extend_from_slice(&proof.key);
        match proof.value {
            Some(value) => {
                proof_bytes.push(1);
                proof_bytes.extend_from_slice(&value);
            }
            None => proof_bytes.push(0),
        }
        proof_bytes.extend_from_slice(&(proof.siblings.len() as u32).to_be_bytes());
        for sibling in proof.siblings {
            proof_bytes.extend_from_slice(&sibling);
        }
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            hex(&SparseMerkleTree::new().root()),
            "aee65339a08b06fbd1665922de21c2d317f62b6cdccde6a3734a3e76adcbf85d"
        );
        assert_eq!(
            hex(&one_root),
            "4a3b7eeee9681c532ca0e5ca63b3585305fa01c0cbcd633756d86290fff99bbb"
        );
        assert_eq!(
            hex(&colliding.root()),
            "0ce4559c1b8d6d89df0c9dc1cf156a055ace5fa6559bed9394f2be50b9a8e2a4"
        );
        assert_eq!(
            hex(&random.root()),
            "695f52706fe2a51746f330f5e3d33201cb77d88cee2983352deee79b5d6010f1"
        );
        assert_eq!(
            hex(&sequence.root()),
            "d68a447318b2b7dbc8262a07dba08692a52dbb8dae6fcbf2d3bd87034009e9c8"
        );
        assert_eq!(
            hex(&sha256(&proof_bytes)),
            "b5a8b2f4a91b9e63a251b86239faa359844755b37797818bddedd0676c7acf4e"
        );
    }
}
