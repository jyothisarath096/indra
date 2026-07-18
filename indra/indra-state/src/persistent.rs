//! Persistent/path-copying data-structure primitives.
//!
//! These types are intentionally standalone Stage-1 foundations for the
//! eventual `ChainState` structural-sharing migration. They are not wired into
//! consensus state yet. The safety property they provide is simple: clones share
//! immutable nodes, and every mutation returns/replaces only the nodes on the
//! changed path. There is no interior mutability.

use std::{cmp::Ordering, collections::BTreeMap, sync::Arc};

use indra_crypto::sha256;

use crate::smt::{
    AuthTreeProof, CompressedAuthTree, CompressedChildKind, CompressedProof, CompressedProofChild,
    CompressedProofStep, ProofTerminal,
};

/// Immutable, path-copying ordered map.
#[derive(Debug, Clone, Default)]
pub struct PersistentOrdMap<K, V> {
    root: Option<Arc<MapNode<K, V>>>,
}

#[derive(Debug)]
struct MapNode<K, V> {
    key: K,
    value: V,
    height: i8,
    len: usize,
    left: Option<Arc<MapNode<K, V>>>,
    right: Option<Arc<MapNode<K, V>>>,
}

impl<K, V> PartialEq for PersistentOrdMap<K, V>
where
    K: Ord + Clone + PartialEq,
    V: Clone + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl<K, V> Eq for PersistentOrdMap<K, V>
where
    K: Ord + Clone + Eq,
    V: Clone + Eq,
{
}

impl<K, V> PersistentOrdMap<K, V>
where
    K: Ord + Clone,
    V: Clone,
{
    /// Create an empty map.
    pub fn new() -> Self {
        Self { root: None }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        node_len(&self.root)
    }

    /// True if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Get a value by key.
    pub fn get(&self, key: &K) -> Option<&V> {
        let mut cursor = self.root.as_deref();
        while let Some(node) = cursor {
            match key.cmp(&node.key) {
                Ordering::Less => cursor = node.left.as_deref(),
                Ordering::Greater => cursor = node.right.as_deref(),
                Ordering::Equal => return Some(&node.value),
            }
        }
        None
    }

    /// Insert or replace a key/value pair.
    ///
    /// Returns the previous value when replacing an existing key.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let (root, old) = insert_node(&self.root, key, value);
        self.root = root;
        old
    }

    /// Return a new map with the key/value pair inserted.
    pub fn inserted(&self, key: K, value: V) -> Self {
        let mut next = self.clone();
        next.insert(key, value);
        next
    }

    /// Remove a key.
    ///
    /// Returns the previous value when the key existed.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let (root, old) = remove_node(&self.root, key);
        self.root = root;
        old
    }

    /// Return a new map with the key removed.
    pub fn removed(&self, key: &K) -> Self {
        let mut next = self.clone();
        next.remove(key);
        next
    }

    /// Iterate entries in canonical key order.
    pub fn iter(&self) -> PersistentOrdMapIter<'_, K, V> {
        let mut iter = PersistentOrdMapIter { stack: Vec::new() };
        iter.push_left(self.root.as_deref());
        iter
    }

    #[cfg(test)]
    fn root_arc(&self) -> Option<Arc<MapNode<K, V>>> {
        self.root.clone()
    }
}

/// Ordered map iterator.
pub struct PersistentOrdMapIter<'a, K, V> {
    stack: Vec<&'a MapNode<K, V>>,
}

impl<'a, K, V> PersistentOrdMapIter<'a, K, V> {
    fn push_left(&mut self, mut cursor: Option<&'a MapNode<K, V>>) {
        while let Some(node) = cursor {
            self.stack.push(node);
            cursor = node.left.as_deref();
        }
    }
}

impl<'a, K, V> Iterator for PersistentOrdMapIter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.stack.pop()?;
        self.push_left(node.right.as_deref());
        Some((&node.key, &node.value))
    }
}

fn node_height<K, V>(node: &Option<Arc<MapNode<K, V>>>) -> i8 {
    node.as_ref().map(|node| node.height).unwrap_or(0)
}

fn node_len<K, V>(node: &Option<Arc<MapNode<K, V>>>) -> usize {
    node.as_ref().map(|node| node.len).unwrap_or(0)
}

fn make_map_node<K, V>(
    key: K,
    value: V,
    left: Option<Arc<MapNode<K, V>>>,
    right: Option<Arc<MapNode<K, V>>>,
) -> Arc<MapNode<K, V>> {
    Arc::new(MapNode {
        key,
        value,
        height: 1 + node_height(&left).max(node_height(&right)),
        len: 1 + node_len(&left) + node_len(&right),
        left,
        right,
    })
}

fn balance_factor<K, V>(node: &MapNode<K, V>) -> i8 {
    node_height(&node.left) - node_height(&node.right)
}

fn rotate_right<K, V>(node: Arc<MapNode<K, V>>) -> Arc<MapNode<K, V>>
where
    K: Clone,
    V: Clone,
{
    let Some(left) = &node.left else {
        return node;
    };
    let new_right = make_map_node(
        node.key.clone(),
        node.value.clone(),
        left.right.clone(),
        node.right.clone(),
    );
    make_map_node(
        left.key.clone(),
        left.value.clone(),
        left.left.clone(),
        Some(new_right),
    )
}

fn rotate_left<K, V>(node: Arc<MapNode<K, V>>) -> Arc<MapNode<K, V>>
where
    K: Clone,
    V: Clone,
{
    let Some(right) = &node.right else {
        return node;
    };
    let new_left = make_map_node(
        node.key.clone(),
        node.value.clone(),
        node.left.clone(),
        right.left.clone(),
    );
    make_map_node(
        right.key.clone(),
        right.value.clone(),
        Some(new_left),
        right.right.clone(),
    )
}

fn rebalance<K, V>(node: Arc<MapNode<K, V>>) -> Arc<MapNode<K, V>>
where
    K: Clone,
    V: Clone,
{
    let balance = balance_factor(&node);
    if balance > 1 {
        let Some(left) = &node.left else {
            return node;
        };
        let left = if balance_factor(left) < 0 {
            Some(rotate_left(left.clone()))
        } else {
            node.left.clone()
        };
        return rotate_right(make_map_node(
            node.key.clone(),
            node.value.clone(),
            left,
            node.right.clone(),
        ));
    }
    if balance < -1 {
        let Some(right) = &node.right else {
            return node;
        };
        let right = if balance_factor(right) > 0 {
            Some(rotate_right(right.clone()))
        } else {
            node.right.clone()
        };
        return rotate_left(make_map_node(
            node.key.clone(),
            node.value.clone(),
            node.left.clone(),
            right,
        ));
    }
    node
}

fn insert_node<K, V>(
    node: &Option<Arc<MapNode<K, V>>>,
    key: K,
    value: V,
) -> (Option<Arc<MapNode<K, V>>>, Option<V>)
where
    K: Ord + Clone,
    V: Clone,
{
    let Some(current) = node else {
        return (Some(make_map_node(key, value, None, None)), None);
    };
    match key.cmp(&current.key) {
        Ordering::Less => {
            let (left, old) = insert_node(&current.left, key, value);
            let next = make_map_node(
                current.key.clone(),
                current.value.clone(),
                left,
                current.right.clone(),
            );
            (Some(rebalance(next)), old)
        }
        Ordering::Greater => {
            let (right, old) = insert_node(&current.right, key, value);
            let next = make_map_node(
                current.key.clone(),
                current.value.clone(),
                current.left.clone(),
                right,
            );
            (Some(rebalance(next)), old)
        }
        Ordering::Equal => (
            Some(make_map_node(
                current.key.clone(),
                value,
                current.left.clone(),
                current.right.clone(),
            )),
            Some(current.value.clone()),
        ),
    }
}

fn remove_min<K, V>(node: &Arc<MapNode<K, V>>) -> (Option<Arc<MapNode<K, V>>>, Arc<MapNode<K, V>>)
where
    K: Clone,
    V: Clone,
{
    if node.left.is_none() {
        return (node.right.clone(), node.clone());
    }
    let (left, min) = remove_min(node.left.as_ref().expect("checked"));
    let next = make_map_node(
        node.key.clone(),
        node.value.clone(),
        left,
        node.right.clone(),
    );
    (Some(rebalance(next)), min)
}

fn remove_node<K, V>(
    node: &Option<Arc<MapNode<K, V>>>,
    key: &K,
) -> (Option<Arc<MapNode<K, V>>>, Option<V>)
where
    K: Ord + Clone,
    V: Clone,
{
    let Some(current) = node else {
        return (None, None);
    };
    match key.cmp(&current.key) {
        Ordering::Less => {
            let (left, old) = remove_node(&current.left, key);
            let next = make_map_node(
                current.key.clone(),
                current.value.clone(),
                left,
                current.right.clone(),
            );
            (Some(rebalance(next)), old)
        }
        Ordering::Greater => {
            let (right, old) = remove_node(&current.right, key);
            let next = make_map_node(
                current.key.clone(),
                current.value.clone(),
                current.left.clone(),
                right,
            );
            (Some(rebalance(next)), old)
        }
        Ordering::Equal => {
            let old = current.value.clone();
            match (&current.left, &current.right) {
                (None, None) => (None, Some(old)),
                (Some(left), None) => (Some(left.clone()), Some(old)),
                (None, Some(right)) => (Some(right.clone()), Some(old)),
                (Some(_), Some(right)) => {
                    let (new_right, successor) = remove_min(right);
                    let next = make_map_node(
                        successor.key.clone(),
                        successor.value.clone(),
                        current.left.clone(),
                        new_right,
                    );
                    (Some(rebalance(next)), Some(old))
                }
            }
        }
    }
}

/// Persistent, path-copying compressed authenticated tree.
///
/// Its hash domains and proof shape intentionally match the existing
/// [`CompressedAuthTree`] implementation in `smt.rs`; tests compare roots
/// directly against that implementation as an oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentAuthTree {
    leaves: PersistentOrdMap<[u8; 32], [u8; 32]>,
    root: Arc<PersistentAuthNode>,
}

#[derive(Debug, PartialEq, Eq)]
enum PersistentAuthNode {
    Empty,
    Leaf {
        key: [u8; 32],
        value_hash: [u8; 32],
        hash: [u8; 32],
    },
    Branch {
        prefix: Vec<u8>,
        children: BTreeMap<u8, Arc<PersistentAuthNode>>,
        hash: [u8; 32],
    },
}

impl Default for PersistentAuthTree {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistentAuthTree {
    /// Create an empty authenticated tree.
    pub fn new() -> Self {
        Self {
            leaves: PersistentOrdMap::new(),
            root: Arc::new(PersistentAuthNode::Empty),
        }
    }

    /// Build from a complete set of key/value-hash pairs.
    pub fn from_pairs<I>(pairs: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = ([u8; 32], [u8; 32])>,
    {
        let mut sorted: Vec<_> = pairs.into_iter().collect();
        sorted.sort_by_key(|(key, _)| *key);
        for window in sorted.windows(2) {
            if window[0].0 == window[1].0 {
                return Err("duplicate persistent authenticated tree key".to_string());
            }
        }
        let mut leaves = PersistentOrdMap::new();
        for (key, value_hash) in &sorted {
            leaves.insert(*key, *value_hash);
        }
        Ok(Self {
            leaves,
            root: build_persistent_subtree(&sorted, 0),
        })
    }

    /// Number of leaves.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// True if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Current root hash.
    pub fn root(&self) -> [u8; 32] {
        self.root.hash()
    }

    /// Get a leaf value hash.
    pub fn get(&self, key: &[u8; 32]) -> Option<&[u8; 32]> {
        self.leaves.get(key)
    }

    /// Insert or replace a leaf.
    pub fn insert(&mut self, key: [u8; 32], value_hash: [u8; 32]) -> Option<[u8; 32]> {
        let old = self.leaves.insert(key, value_hash);
        self.root = persistent_insert(&self.root, key, value_hash);
        old
    }

    /// Delete a leaf.
    pub fn delete(&mut self, key: [u8; 32]) -> Option<[u8; 32]> {
        let old = self.leaves.remove(&key);
        if old.is_some() {
            self.root = persistent_delete(&self.root, key);
        }
        old
    }

    /// Build an inclusion/non-membership proof.
    pub fn prove(&self, key: [u8; 32]) -> AuthTreeProof {
        AuthTreeProof::V2Compressed(persistent_prove(&self.root, key))
    }

    /// Verify a proof against this tree's root.
    pub fn verify_proof(root: [u8; 32], key: [u8; 32], proof: &AuthTreeProof) -> bool {
        match proof {
            AuthTreeProof::V2Compressed(proof) => {
                CompressedAuthTree::verify_proof(root, key, proof)
            }
            AuthTreeProof::V1LegacySparse(_) => false,
        }
    }

    #[cfg(test)]
    fn root_arc(&self) -> Arc<PersistentAuthNode> {
        self.root.clone()
    }
}

impl PersistentAuthNode {
    fn hash(&self) -> [u8; 32] {
        match self {
            PersistentAuthNode::Empty => compressed_empty_hash(),
            PersistentAuthNode::Leaf { hash, .. } | PersistentAuthNode::Branch { hash, .. } => {
                *hash
            }
        }
    }

    fn kind(&self) -> CompressedChildKind {
        match self {
            PersistentAuthNode::Leaf { .. } => CompressedChildKind::Leaf,
            PersistentAuthNode::Branch { .. } | PersistentAuthNode::Empty => {
                CompressedChildKind::Branch
            }
        }
    }
}

fn build_persistent_subtree(
    pairs: &[([u8; 32], [u8; 32])],
    start_nibble: usize,
) -> Arc<PersistentAuthNode> {
    match pairs.len() {
        0 => Arc::new(PersistentAuthNode::Empty),
        1 => {
            let (key, value_hash) = pairs[0];
            Arc::new(PersistentAuthNode::Leaf {
                key,
                value_hash,
                hash: hash_compressed_leaf(&key, &value_hash),
            })
        }
        _ => {
            let prefix = longest_common_prefix_for_pairs(pairs, start_nibble);
            let mut children = BTreeMap::new();
            let mut index = 0usize;
            while index < pairs.len() {
                let nibbles = key_to_nibbles(&pairs[index].0);
                let child_nibble = nibbles.get(prefix.len()).copied().unwrap_or(0);
                let mut end = index + 1;
                while end < pairs.len() {
                    let other = key_to_nibbles(&pairs[end].0);
                    if other.get(prefix.len()).copied().unwrap_or(0) != child_nibble {
                        break;
                    }
                    end += 1;
                }
                children.insert(
                    child_nibble,
                    build_persistent_subtree(&pairs[index..end], prefix.len() + 1),
                );
                index = end;
            }
            make_persistent_branch(prefix, children)
        }
    }
}

fn persistent_insert(
    node: &Arc<PersistentAuthNode>,
    key: [u8; 32],
    value_hash: [u8; 32],
) -> Arc<PersistentAuthNode> {
    match node.as_ref() {
        PersistentAuthNode::Empty => Arc::new(PersistentAuthNode::Leaf {
            key,
            value_hash,
            hash: hash_compressed_leaf(&key, &value_hash),
        }),
        PersistentAuthNode::Leaf {
            key: existing_key,
            value_hash: existing_value,
            ..
        } => {
            if existing_key == &key {
                Arc::new(PersistentAuthNode::Leaf {
                    key,
                    value_hash,
                    hash: hash_compressed_leaf(&key, &value_hash),
                })
            } else {
                let existing_nibbles = key_to_nibbles(existing_key);
                let key_nibbles = key_to_nibbles(&key);
                let prefix_len = common_nibble_prefix_len(&existing_nibbles, &key_nibbles, 0);
                let prefix = key_nibbles[..prefix_len].to_vec();
                let mut children = BTreeMap::new();
                children.insert(
                    existing_nibbles[prefix_len],
                    Arc::new(PersistentAuthNode::Leaf {
                        key: *existing_key,
                        value_hash: *existing_value,
                        hash: hash_compressed_leaf(existing_key, existing_value),
                    }),
                );
                children.insert(
                    key_nibbles[prefix_len],
                    Arc::new(PersistentAuthNode::Leaf {
                        key,
                        value_hash,
                        hash: hash_compressed_leaf(&key, &value_hash),
                    }),
                );
                make_persistent_branch(prefix, children)
            }
        }
        PersistentAuthNode::Branch {
            prefix, children, ..
        } => {
            let key_nibbles = key_to_nibbles(&key);
            let shared = common_nibble_prefix_len(prefix, &key_nibbles, 0);
            if shared < prefix.len() {
                let old_nibble = prefix[shared];
                let new_nibble = key_nibbles[shared];
                let mut split_children = BTreeMap::new();
                split_children.insert(
                    old_nibble,
                    make_persistent_branch(prefix.clone(), children.clone()),
                );
                split_children.insert(
                    new_nibble,
                    Arc::new(PersistentAuthNode::Leaf {
                        key,
                        value_hash,
                        hash: hash_compressed_leaf(&key, &value_hash),
                    }),
                );
                return make_persistent_branch(key_nibbles[..shared].to_vec(), split_children);
            }

            let Some(child_nibble) = key_nibbles.get(prefix.len()).copied() else {
                return make_persistent_branch(prefix.clone(), children.clone());
            };
            let mut updated_children = children.clone();
            let child = updated_children
                .get(&child_nibble)
                .cloned()
                .unwrap_or_else(|| Arc::new(PersistentAuthNode::Empty));
            updated_children.insert(child_nibble, persistent_insert(&child, key, value_hash));
            make_persistent_branch(prefix.clone(), updated_children)
        }
    }
}

fn persistent_delete(node: &Arc<PersistentAuthNode>, key: [u8; 32]) -> Arc<PersistentAuthNode> {
    match node.as_ref() {
        PersistentAuthNode::Empty => Arc::new(PersistentAuthNode::Empty),
        PersistentAuthNode::Leaf {
            key: existing_key, ..
        } => {
            if existing_key == &key {
                Arc::new(PersistentAuthNode::Empty)
            } else {
                node.clone()
            }
        }
        PersistentAuthNode::Branch {
            prefix, children, ..
        } => {
            let key_nibbles = key_to_nibbles(&key);
            if !starts_with_nibbles(&key_nibbles, prefix) || prefix.len() >= key_nibbles.len() {
                return make_persistent_branch(prefix.clone(), children.clone());
            }
            let child_nibble = key_nibbles[prefix.len()];
            let Some(child) = children.get(&child_nibble) else {
                return make_persistent_branch(prefix.clone(), children.clone());
            };
            let updated_child = persistent_delete(child, key);
            let mut updated_children = children.clone();
            if matches!(updated_child.as_ref(), PersistentAuthNode::Empty) {
                updated_children.remove(&child_nibble);
            } else {
                updated_children.insert(child_nibble, updated_child);
            }
            collapse_or_persistent_branch(prefix.clone(), updated_children)
        }
    }
}

fn collapse_or_persistent_branch(
    prefix: Vec<u8>,
    mut children: BTreeMap<u8, Arc<PersistentAuthNode>>,
) -> Arc<PersistentAuthNode> {
    match children.len() {
        0 => Arc::new(PersistentAuthNode::Empty),
        1 => children.pop_first().expect("len checked").1,
        _ => make_persistent_branch(prefix, children),
    }
}

fn make_persistent_branch(
    prefix: Vec<u8>,
    children: BTreeMap<u8, Arc<PersistentAuthNode>>,
) -> Arc<PersistentAuthNode> {
    let mut proof_children = Vec::with_capacity(children.len());
    for (nibble, child) in &children {
        if matches!(child.as_ref(), PersistentAuthNode::Empty) {
            continue;
        }
        proof_children.push(CompressedProofChild {
            nibble: *nibble,
            kind: child.kind(),
            hash: child.hash(),
        });
    }
    if proof_children.is_empty() {
        return Arc::new(PersistentAuthNode::Empty);
    }
    let hash = hash_branch_from_children(&prefix, &proof_children)
        .unwrap_or_else(|_| compressed_empty_hash());
    Arc::new(PersistentAuthNode::Branch {
        prefix,
        children,
        hash,
    })
}

fn persistent_prove(node: &Arc<PersistentAuthNode>, key: [u8; 32]) -> CompressedProof {
    let key_nibbles = key_to_nibbles(&key);
    match node.as_ref() {
        PersistentAuthNode::Empty => CompressedProof {
            key,
            value: None,
            terminal: ProofTerminal::MissingChild,
            steps: Vec::new(),
        },
        PersistentAuthNode::Leaf {
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
        PersistentAuthNode::Branch {
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
            let target = key_nibbles[prefix.len()];
            let step = CompressedProofStep {
                branch_prefix: prefix.clone(),
                target_nibble: target,
                child_bitmap: child_bitmap(&proof_children_from_map(children, None)).unwrap_or(0),
                siblings: proof_children_from_map(children, Some(target)),
            };
            if let Some(child) = children.get(&target) {
                let mut proof = persistent_prove(child, key);
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
    children: &BTreeMap<u8, Arc<PersistentAuthNode>>,
    exclude: Option<u8>,
) -> Vec<CompressedProofChild> {
    children
        .iter()
        .filter(|(nibble, child)| {
            Some(**nibble) != exclude && !matches!(child.as_ref(), PersistentAuthNode::Empty)
        })
        .map(|(nibble, child)| CompressedProofChild {
            nibble: *nibble,
            kind: child.kind(),
            hash: child.hash(),
        })
        .collect()
}

fn longest_common_prefix_for_pairs(pairs: &[([u8; 32], [u8; 32])], start_nibble: usize) -> Vec<u8> {
    let first = key_to_nibbles(&pairs[0].0);
    let mut len = start_nibble;
    while len < first.len() {
        let nibble = first[len];
        if pairs
            .iter()
            .skip(1)
            .all(|(key, _)| key_to_nibbles(key).get(len).copied() == Some(nibble))
        {
            len += 1;
        } else {
            break;
        }
    }
    first[..len].to_vec()
}

fn common_nibble_prefix_len(a: &[u8], b: &[u8], start: usize) -> usize {
    let mut index = start;
    while index < a.len() && index < b.len() && a[index] == b[index] {
        index += 1;
    }
    index
}

fn starts_with_nibbles(key: &[u8], prefix: &[u8]) -> bool {
    key.len() >= prefix.len() && key[..prefix.len()] == *prefix
}

fn valid_nibble_path(path: &[u8]) -> bool {
    path.iter().all(|nibble| *nibble <= 0x0F) && path.len() <= 64
}

fn key_to_nibbles(key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    for byte in key {
        out.push(byte >> 4);
        out.push(byte & 0x0F);
    }
    out
}

fn pack_nibbles(nibbles: &[u8]) -> Option<Vec<u8>> {
    if !valid_nibble_path(nibbles) {
        return None;
    }
    let mut out = Vec::with_capacity(nibbles.len().div_ceil(2));
    for chunk in nibbles.chunks(2) {
        let high = chunk[0] << 4;
        let low = chunk.get(1).copied().unwrap_or(0);
        out.push(high | low);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn keyed(prefix: &[u8], last: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (index, byte) in prefix.iter().copied().enumerate().take(31) {
            out[index] = byte;
        }
        out[31] = last;
        out
    }

    fn value(byte: u8) -> [u8; 32] {
        sha256(&[byte; 8])
    }

    fn pairs(count: usize) -> Vec<([u8; 32], [u8; 32])> {
        (0..count)
            .map(|index| {
                let mut key = sha256(&(index as u64).to_le_bytes());
                key[0] ^= (index as u8).rotate_left(3);
                (key, sha256(&key))
            })
            .collect()
    }

    #[test]
    fn persistent_ord_map_basic_correctness_and_order() {
        let mut map = PersistentOrdMap::new();
        assert!(map.is_empty());
        assert_eq!(map.insert(3, "c"), None);
        assert_eq!(map.insert(1, "a"), None);
        assert_eq!(map.insert(2, "b"), None);
        assert_eq!(map.insert(2, "bb"), Some("b"));
        assert_eq!(map.len(), 3);
        assert_eq!(map.get(&2), Some(&"bb"));
        assert_eq!(
            map.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>(),
            vec![(1, "a"), (2, "bb"), (3, "c")]
        );
        assert_eq!(map.remove(&2), Some("bb"));
        assert_eq!(map.get(&2), None);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn persistent_ord_map_clone_is_immutable_snapshot() {
        let mut original = PersistentOrdMap::new();
        for index in 0..128 {
            original.insert(index, index * 10);
        }
        let before = original.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>();
        let mut clone = original.clone();
        clone.insert(64, 999);
        clone.insert(256, 2560);
        clone.remove(&0);
        assert_eq!(
            original.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>(),
            before
        );
        assert_eq!(original.get(&64), Some(&640));
        assert_eq!(clone.get(&64), Some(&999));
        assert_eq!(original.get(&256), None);
    }

    #[test]
    fn persistent_ord_map_shares_unrelated_nodes() {
        let mut original = PersistentOrdMap::new();
        for index in 0..64 {
            original.insert(index, index);
        }
        let mut clone = original.clone();
        let original_root = original.root_arc().unwrap();
        clone.insert(1_000, 1_000);
        let clone_root = clone.root_arc().unwrap();
        assert!(!Arc::ptr_eq(&original_root, &clone_root));
        assert!(Arc::ptr_eq(
            original_root.left.as_ref().expect("left branch"),
            clone_root.left.as_ref().expect("left branch")
        ));
    }

    #[test]
    fn persistent_ord_map_insertion_order_independent_delete_reinsert_and_branches() {
        let mut a = PersistentOrdMap::new();
        let mut b = PersistentOrdMap::new();
        for index in 0..256 {
            a.insert(index, index * 2);
        }
        for index in (0..256).rev() {
            b.insert(index, index * 2);
        }
        assert_eq!(a, b);
        assert_eq!(a.remove(&100), Some(200));
        assert_eq!(a.insert(100, 777), None);
        assert_ne!(a, b);
        b.insert(100, 777);
        assert_eq!(a, b);
    }

    #[test]
    fn persistent_ord_map_deep_branch_sharing_between_derived_clones() {
        let mut base = PersistentOrdMap::new();
        for index in 0..128 {
            base.insert(index, index);
        }
        let mut left = base.clone();
        let mut right = base.clone();
        left.insert(-10, -10);
        right.insert(500, 500);
        assert_eq!(base.get(&-10), None);
        assert_eq!(base.get(&500), None);
        assert_eq!(left.get(&500), None);
        assert_eq!(right.get(&-10), None);
        assert_eq!(base.len(), 128);
    }

    #[test]
    fn persistent_auth_tree_basic_correctness_and_proofs() {
        let mut tree = PersistentAuthTree::new();
        assert!(tree.is_empty());
        let k1 = key(0x11);
        let k2 = key(0x22);
        assert_eq!(tree.insert(k1, value(0xAA)), None);
        assert_eq!(tree.insert(k2, value(0xBB)), None);
        assert_eq!(tree.insert(k1, value(0xCC)), Some(value(0xAA)));
        assert_eq!(tree.get(&k1), Some(&value(0xCC)));
        let proof = tree.prove(k1);
        assert!(PersistentAuthTree::verify_proof(tree.root(), k1, &proof));
        assert_eq!(tree.delete(k2), Some(value(0xBB)));
        assert_eq!(tree.get(&k2), None);
        let missing = tree.prove(k2);
        assert!(PersistentAuthTree::verify_proof(tree.root(), k2, &missing));
    }

    #[test]
    fn persistent_auth_tree_clone_is_immutable_snapshot() {
        let mut original = PersistentAuthTree::from_pairs(pairs(128)).unwrap();
        let original_root = original.root();
        let mut clone = original.clone();
        clone.insert(key(0xFE), value(0xFE));
        clone.delete(pairs(128)[0].0);
        assert_eq!(original.root(), original_root);
        assert_ne!(clone.root(), original.root());
        original.insert(key(0xFD), value(0xFD));
        assert_ne!(clone.root(), original.root());
    }

    #[test]
    fn persistent_auth_tree_shares_unrelated_subtrees() {
        let entries = vec![
            (keyed(&[0x10], 0x01), value(1)),
            (keyed(&[0x10], 0x02), value(2)),
            (keyed(&[0xF0], 0x01), value(3)),
            (keyed(&[0xF0], 0x02), value(4)),
        ];
        let original = PersistentAuthTree::from_pairs(entries).unwrap();
        let mut clone = original.clone();
        clone.insert(keyed(&[0xF0], 0x03), value(5));
        let original_root = original.root_arc();
        let clone_root = clone.root_arc();
        let PersistentAuthNode::Branch {
            children: original_children,
            ..
        } = original_root.as_ref()
        else {
            panic!("expected branch");
        };
        let PersistentAuthNode::Branch {
            children: clone_children,
            ..
        } = clone_root.as_ref()
        else {
            panic!("expected branch");
        };
        assert!(Arc::ptr_eq(
            original_children.get(&0x1).expect("left branch"),
            clone_children.get(&0x1).expect("left branch")
        ));
    }

    #[test]
    fn persistent_auth_tree_insertion_order_independent_and_oracle_matches() {
        let entries = pairs(512);
        let forward = PersistentAuthTree::from_pairs(entries.clone()).unwrap();
        let reverse = PersistentAuthTree::from_pairs(entries.iter().rev().copied()).unwrap();
        let mut incremental = PersistentAuthTree::new();
        let mut oracle = CompressedAuthTree::new();
        for (key, value) in entries
            .iter()
            .cycle()
            .skip(137)
            .take(entries.len())
            .copied()
        {
            incremental.insert(key, value);
            oracle.insert(key, value);
        }
        assert_eq!(forward.root(), reverse.root());
        assert_eq!(forward.root(), incremental.root());
        assert_eq!(oracle.root(), incremental.root());
    }

    #[test]
    fn persistent_auth_tree_delete_reinsert_duplicate_and_derived_clones() {
        let entries = pairs(64);
        let mut base = PersistentAuthTree::from_pairs(entries.clone()).unwrap();
        let root = base.root();
        assert_eq!(base.insert(entries[0].0, entries[0].1), Some(entries[0].1));
        assert_eq!(base.root(), root, "same key/value replacement is stable");
        assert_eq!(base.delete(entries[0].0), Some(entries[0].1));
        assert_ne!(base.root(), root);
        assert_eq!(base.insert(entries[0].0, entries[0].1), None);
        assert_eq!(base.root(), root);

        let mut a = base.clone();
        let mut b = base.clone();
        a.insert(key(0xA1), value(0xA1));
        b.insert(key(0xB1), value(0xB1));
        assert_eq!(base.get(&key(0xA1)), None);
        assert_eq!(base.get(&key(0xB1)), None);
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn persistent_auth_tree_long_common_prefix_and_final_bit_keys_match_oracle() {
        let mut entries = Vec::new();
        let prefix = [0xAB; 31];
        entries.push((keyed(&prefix, 0b0000_0000), value(1)));
        entries.push((keyed(&prefix, 0b0000_0001), value(2)));
        entries.push((keyed(&prefix, 0b0000_0010), value(3)));
        entries.push((keyed(&prefix, 0b0000_0011), value(4)));
        let persistent = PersistentAuthTree::from_pairs(entries.clone()).unwrap();
        let oracle = CompressedAuthTree::from_pairs(entries).unwrap();
        assert_eq!(persistent.root(), oracle.root());
        for suffix in 0..4 {
            let key = keyed(&prefix, suffix);
            let proof = persistent.prove(key);
            assert!(PersistentAuthTree::verify_proof(
                persistent.root(),
                key,
                &proof
            ));
        }
    }

    #[test]
    fn persistent_auth_tree_many_randomized_oracle_sets() {
        for size in [0usize, 1, 2, 3, 7, 16, 63, 257] {
            let entries = pairs(size);
            let persistent = PersistentAuthTree::from_pairs(entries.clone()).unwrap();
            let oracle = CompressedAuthTree::from_pairs(entries.clone()).unwrap();
            assert_eq!(persistent.root(), oracle.root(), "size={size}");
            let mut incremental = PersistentAuthTree::new();
            let mut oracle_incremental = CompressedAuthTree::new();
            for (key, value) in entries.iter().rev().copied() {
                incremental.insert(key, value);
                oracle_incremental.insert(key, value);
            }
            assert_eq!(
                incremental.root(),
                oracle_incremental.root(),
                "incremental size={size}"
            );
        }
    }

    #[test]
    #[ignore = "release-mode performance sanity benchmark; run explicitly with --release --ignored"]
    fn persistent_primitives_clone_cost_is_near_constant() {
        for size in [100_000usize, 1_000_000, 10_000_000] {
            let map_start = Instant::now();
            let mut map = PersistentOrdMap::new();
            for index in 0..size {
                map.insert(index as u64, index as u64);
            }
            let map_build = map_start.elapsed();
            let clone_start = Instant::now();
            let map_clone = map.clone();
            let map_clone_elapsed = clone_start.elapsed();
            assert_eq!(map_clone.len(), size);

            let entries = pairs(size);
            let tree_start = Instant::now();
            let tree = PersistentAuthTree::from_pairs(entries).unwrap();
            let tree_build = tree_start.elapsed();
            let tree_clone_start = Instant::now();
            let tree_clone = tree.clone();
            let tree_clone_elapsed = tree_clone_start.elapsed();
            assert_eq!(tree_clone.root(), tree.root());

            eprintln!(
                "persistent_primitives_clone_cost size={size} map_build={map_build:?} map_clone={map_clone_elapsed:?} tree_build={tree_build:?} tree_clone={tree_clone_elapsed:?}"
            );
            assert!(
                map_clone_elapsed.as_millis() < 5,
                "map clone should stay near-constant at size={size}: {map_clone_elapsed:?}"
            );
            assert!(
                tree_clone_elapsed.as_millis() < 5,
                "tree clone should stay near-constant at size={size}: {tree_clone_elapsed:?}"
            );
        }
    }
}
