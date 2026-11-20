//! Persistent/path-copying data-structure primitives.
//!
//! These types are intentionally standalone Stage-1 foundations for the
//! eventual `ChainState` structural-sharing migration. They are not wired into
//! consensus state yet. The safety property they provide is simple: clones share
//! immutable nodes, and every mutation returns/replaces only the nodes on the
//! changed path. There is no interior mutability.

use std::{cmp::Ordering, collections::BTreeMap, sync::Arc};

use indra_crypto::sha256;

use crate::error::{StateError, StateResult};
use crate::smt::{
    AuthTreeProof, CompressedAuthTree, CompressedChildKind, CompressedProof, CompressedProofChild,
    CompressedProofStep, MerkleProof, ProofTerminal, SMT_DEPTH,
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

    /// True if a key exists in the map.
    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
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

    /// Iterate values in canonical key order.
    pub fn values(&self) -> PersistentOrdMapValues<'_, K, V> {
        PersistentOrdMapValues { inner: self.iter() }
    }

    #[cfg(test)]
    fn root_arc(&self) -> Option<Arc<MapNode<K, V>>> {
        self.root.clone()
    }
}

impl<K, V> FromIterator<(K, V)> for PersistentOrdMap<K, V>
where
    K: Ord + Clone,
    V: Clone,
{
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        let mut map = Self::new();
        for (key, value) in iter {
            map.insert(key, value);
        }
        map
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

impl<'a, K, V> IntoIterator for &'a PersistentOrdMap<K, V>
where
    K: Ord + Clone,
    V: Clone,
{
    type Item = (&'a K, &'a V);
    type IntoIter = PersistentOrdMapIter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Ordered values iterator.
pub struct PersistentOrdMapValues<'a, K, V> {
    inner: PersistentOrdMapIter<'a, K, V>,
}

impl<'a, K, V> Iterator for PersistentOrdMapValues<'a, K, V> {
    type Item = &'a V;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(_, value)| value)
    }
}

/// Immutable, path-copying ordered set.
///
/// This is intentionally a thin set-shaped wrapper over [`PersistentOrdMap`].
/// Iteration is in canonical key order, matching the ordered-map primitive and
/// making it suitable for consensus-adjacent structures whose serialization
/// must not depend on hash-table iteration order.
#[derive(Debug, Clone, Default)]
pub struct PersistentOrdSet<K> {
    inner: PersistentOrdMap<K, ()>,
}

impl<K> PartialEq for PersistentOrdSet<K>
where
    K: Ord + Clone + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl<K> Eq for PersistentOrdSet<K> where K: Ord + Clone + Eq {}

impl<K> PersistentOrdSet<K>
where
    K: Ord + Clone,
{
    /// Create an empty set.
    pub fn new() -> Self {
        Self {
            inner: PersistentOrdMap::new(),
        }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// True if the key exists in the set.
    pub fn contains(&self, key: &K) -> bool {
        self.inner.contains_key(key)
    }

    /// Insert a key.
    ///
    /// Returns true when the key was newly inserted.
    pub fn insert(&mut self, key: K) -> bool {
        self.inner.insert(key, ()).is_none()
    }

    /// Remove a key.
    ///
    /// Returns true when the key existed.
    pub fn remove(&mut self, key: &K) -> bool {
        self.inner.remove(key).is_some()
    }

    /// Iterate entries in canonical key order.
    pub fn iter(&self) -> PersistentOrdSetIter<'_, K> {
        PersistentOrdSetIter {
            inner: self.inner.iter(),
        }
    }

    #[cfg(test)]
    fn root_arc(&self) -> Option<Arc<MapNode<K, ()>>> {
        self.inner.root_arc()
    }
}

impl<K> FromIterator<K> for PersistentOrdSet<K>
where
    K: Ord + Clone,
{
    fn from_iter<T: IntoIterator<Item = K>>(iter: T) -> Self {
        let mut set = Self::new();
        for key in iter {
            set.insert(key);
        }
        set
    }
}

impl<'a, K> IntoIterator for &'a PersistentOrdSet<K>
where
    K: Ord + Clone,
{
    type Item = &'a K;
    type IntoIter = PersistentOrdSetIter<'a, K>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Ordered set iterator.
pub struct PersistentOrdSetIter<'a, K> {
    inner: PersistentOrdMapIter<'a, K, ()>,
}

impl<'a, K> Iterator for PersistentOrdSetIter<'a, K> {
    type Item = &'a K;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(key, _)| key)
    }
}

fn node_height<K, V>(node: &Option<Arc<MapNode<K, V>>>) -> i8 {
    node.as_ref().map(|node| node.height).unwrap_or(0)
}

fn node_len<K, V>(node: &Option<Arc<MapNode<K, V>>>) -> usize {
    node.as_ref().map(|node| node.len).unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PersistentSparseNodeLoc {
    depth: usize,
    prefix: [u8; 32],
}

/// Persistent, path-copying version of the fixed-depth 256-bit sparse Merkle tree.
///
/// This mirrors [`crate::smt::SparseMerkleTree`]'s fixed-depth tree, hash
/// domains, empty-subtree defaults, and proof shape. It deliberately does not
/// reuse [`PersistentAuthTree`], because the compressed authenticated tree has
/// a different structure and proof encoding. Clones share immutable map nodes;
/// insert/delete operations replace only the changed leaf map path and the 256
/// cached node locations on that leaf's path to the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentSparseMerkleTree {
    leaves: PersistentOrdMap<[u8; 32], [u8; 32]>,
    nodes: PersistentOrdMap<PersistentSparseNodeLoc, [u8; 32]>,
    root: [u8; 32],
}

impl Default for PersistentSparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistentSparseMerkleTree {
    /// Create an empty fixed-depth sparse Merkle tree.
    pub fn new() -> Self {
        let empty_hashes = sparse_empty_hashes();
        Self {
            leaves: PersistentOrdMap::new(),
            nodes: PersistentOrdMap::new(),
            root: empty_hashes.first().copied().unwrap_or([0u8; 32]),
        }
    }

    /// Build from a complete set of key/value pairs.
    pub fn from_pairs<I>(pairs: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = ([u8; 32], [u8; 32])>,
    {
        let mut sorted: Vec<_> = pairs.into_iter().collect();
        sorted.sort_by_key(|(key, _)| *key);
        for (first, second) in sorted.iter().zip(sorted.iter().skip(1)) {
            if first.0 == second.0 {
                return Err("duplicate persistent sparse Merkle tree key".to_string());
            }
        }

        let mut tree = Self::new();
        for (key, value) in sorted {
            tree.insert(key, value);
        }
        Ok(tree)
    }

    /// Number of leaves.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// True if the tree has no leaves.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Current fixed-depth sparse Merkle root.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Get a leaf value.
    pub fn get(&self, key: &[u8; 32]) -> Option<&[u8; 32]> {
        self.leaves.get(key)
    }

    /// Insert or replace a leaf.
    ///
    /// Returns the previous value when replacing an existing key.
    pub fn insert(&mut self, key: [u8; 32], value: [u8; 32]) -> Option<[u8; 32]> {
        let old = self.leaves.insert(key, value);
        self.update_path(key);
        old
    }

    /// Delete a leaf.
    ///
    /// Returns the previous value when the key existed.
    pub fn delete(&mut self, key: [u8; 32]) -> Option<[u8; 32]> {
        let old = self.leaves.remove(&key);
        self.update_path(key);
        old
    }

    /// Build an inclusion or exclusion proof for a key.
    pub fn prove(&self, key: [u8; 32]) -> MerkleProof {
        let empty_hashes = sparse_empty_hashes();
        let mut siblings = Vec::with_capacity(SMT_DEPTH);

        for bit_index in (0..SMT_DEPTH).rev() {
            let sibling_loc = PersistentSparseNodeLoc {
                depth: sparse_depth_from_bit(bit_index.saturating_add(1)),
                prefix: sparse_sibling_prefix(key, bit_index),
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

        let empty_hashes = sparse_empty_hashes();
        let mut acc = proof
            .value
            .map(|value| sparse_hash_leaf(&key, &value))
            .unwrap_or_else(|| empty_hashes.get(SMT_DEPTH).copied().unwrap_or([0u8; 32]));

        for (index, sibling) in proof.siblings.iter().enumerate() {
            let bit_index = SMT_DEPTH.saturating_sub(1 + index);
            if sparse_bit_at(&key, bit_index) {
                acc = sparse_hash_internal(sibling, &acc);
            } else {
                acc = sparse_hash_internal(&acc, sibling);
            }
        }

        acc == root
    }

    #[cfg(test)]
    fn root_arc_pair(&self) -> RootArcPair {
        (self.leaves.root_arc(), self.nodes.root_arc())
    }

    fn update_path(&mut self, key: [u8; 32]) {
        let empty_hashes = sparse_empty_hashes();
        let mut acc = self
            .leaves
            .get(&key)
            .map(|value| sparse_hash_leaf(&key, value))
            .unwrap_or_else(|| empty_hashes.get(SMT_DEPTH).copied().unwrap_or([0u8; 32]));

        let leaf_loc = PersistentSparseNodeLoc {
            depth: sparse_depth_from_bit(SMT_DEPTH),
            prefix: key,
        };
        persistent_sparse_set_or_remove_node(
            &mut self.nodes,
            leaf_loc,
            acc,
            empty_hashes.get(SMT_DEPTH).copied().unwrap_or([0u8; 32]),
        );

        for bit_index in (0..SMT_DEPTH).rev() {
            let child_depth = bit_index + 1;
            let sibling_loc = PersistentSparseNodeLoc {
                depth: sparse_depth_from_bit(child_depth),
                prefix: sparse_sibling_prefix(key, bit_index),
            };
            let sibling_hash = self
                .nodes
                .get(&sibling_loc)
                .copied()
                .unwrap_or_else(|| empty_hashes.get(child_depth).copied().unwrap_or([0u8; 32]));

            acc = if sparse_bit_at(&key, bit_index) {
                sparse_hash_internal(&sibling_hash, &acc)
            } else {
                sparse_hash_internal(&acc, &sibling_hash)
            };

            let parent_loc = PersistentSparseNodeLoc {
                depth: sparse_depth_from_bit(bit_index),
                prefix: sparse_truncate_key(key, bit_index),
            };
            persistent_sparse_set_or_remove_node(
                &mut self.nodes,
                parent_loc,
                acc,
                empty_hashes.get(bit_index).copied().unwrap_or([0u8; 32]),
            );
        }

        self.root = acc;
    }
}

#[cfg(test)]
type RootArcPair = (
    Option<Arc<MapNode<[u8; 32], [u8; 32]>>>,
    Option<Arc<MapNode<PersistentSparseNodeLoc, [u8; 32]>>>,
);

fn persistent_sparse_set_or_remove_node(
    nodes: &mut PersistentOrdMap<PersistentSparseNodeLoc, [u8; 32]>,
    loc: PersistentSparseNodeLoc,
    value: [u8; 32],
    empty: [u8; 32],
) {
    if value == empty {
        nodes.remove(&loc);
    } else {
        nodes.insert(loc, value);
    }
}

fn sparse_empty_hashes() -> Vec<[u8; 32]> {
    let mut hashes = vec![[0u8; 32]; SMT_DEPTH + 1];
    if let Some(last) = hashes.get_mut(SMT_DEPTH) {
        *last = sha256(b"EMPTY");
    }

    for bit_index in (0..SMT_DEPTH).rev() {
        let child = hashes.get(bit_index + 1).copied().unwrap_or([0u8; 32]);
        if let Some(slot) = hashes.get_mut(bit_index) {
            *slot = sparse_hash_internal(&child, &child);
        }
    }

    hashes
}

fn sparse_depth_from_bit(bit_index: usize) -> usize {
    bit_index
}

fn sparse_hash_leaf(key: &[u8; 32], value: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(65);
    data.push(0u8);
    data.extend_from_slice(key);
    data.extend_from_slice(value);
    sha256(&data)
}

fn sparse_hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(65);
    data.push(1u8);
    data.extend_from_slice(left);
    data.extend_from_slice(right);
    sha256(&data)
}

fn sparse_bit_at(key: &[u8; 32], bit_index: usize) -> bool {
    let byte_index = bit_index / 8;
    let bit_offset = 7usize - (bit_index % 8);
    match key.get(byte_index) {
        Some(byte) => (byte & (1u8 << bit_offset)) != 0,
        None => false,
    }
}

fn sparse_truncate_key(key: [u8; 32], depth: usize) -> [u8; 32] {
    let mut prefix = [0u8; 32];
    for bit_index in 0..depth {
        if sparse_bit_at(&key, bit_index) {
            sparse_set_bit(&mut prefix, bit_index, true);
        }
    }
    prefix
}

fn sparse_sibling_prefix(key: [u8; 32], bit_index: usize) -> [u8; 32] {
    let mut sibling = sparse_truncate_key(key, bit_index + 1);
    let current = sparse_bit_at(&key, bit_index);
    sparse_set_bit(&mut sibling, bit_index, !current);
    sibling
}

fn sparse_set_bit(bytes: &mut [u8; 32], bit_index: usize, value: bool) {
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

type RemoveMinResult<K, V> = (Option<Arc<MapNode<K, V>>>, Arc<MapNode<K, V>>);

fn remove_min<K, V>(node: &Arc<MapNode<K, V>>) -> RemoveMinResult<K, V>
where
    K: Clone,
    V: Clone,
{
    match node.left.as_ref() {
        None => (node.right.clone(), node.clone()),
        Some(left_node) => {
            let (left, min) = remove_min(left_node);
            let next = make_map_node(
                node.key.clone(),
                node.value.clone(),
                left,
                node.right.clone(),
            );
            (Some(rebalance(next)), min)
        }
    }
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
        for (first, second) in sorted.iter().zip(sorted.iter().skip(1)) {
            if first.0 == second.0 {
                return Err("duplicate persistent authenticated tree key".to_string());
            }
        }
        let mut leaves = PersistentOrdMap::new();
        for (key, value_hash) in &sorted {
            leaves.insert(*key, *value_hash);
        }
        Ok(Self {
            leaves,
            root: build_persistent_subtree(&sorted, 0).map_err(|err| err.to_string())?,
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
    pub fn insert(&mut self, key: [u8; 32], value_hash: [u8; 32]) -> StateResult<Option<[u8; 32]>> {
        let old = self.leaves.insert(key, value_hash);
        self.root = persistent_insert(&self.root, key, value_hash)?;
        Ok(old)
    }

    /// Delete a leaf.
    pub fn delete(&mut self, key: [u8; 32]) -> StateResult<Option<[u8; 32]>> {
        let old = self.leaves.remove(&key);
        if old.is_some() {
            self.root = persistent_delete(&self.root, key)?;
        }
        Ok(old)
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
) -> StateResult<Arc<PersistentAuthNode>> {
    match pairs.len() {
        0 => Ok(Arc::new(PersistentAuthNode::Empty)),
        1 => {
            let [(key, value_hash)] = pairs else {
                return Err(StateError::InternalInvariant {
                    site: "persistent::build_persistent_subtree singleton",
                });
            };
            Ok(Arc::new(PersistentAuthNode::Leaf {
                key: *key,
                value_hash: *value_hash,
                hash: hash_compressed_leaf(key, value_hash),
            }))
        }
        _ => {
            let prefix = longest_common_prefix_for_pairs(pairs, start_nibble)?;
            let mut children = BTreeMap::new();
            let mut index = 0usize;
            while index < pairs.len() {
                let (key, _) = pairs.get(index).ok_or(StateError::InternalInvariant {
                    site: "persistent::build_persistent_subtree index",
                })?;
                let nibbles = key_to_nibbles(key);
                let child_nibble = nibbles.iter().copied().nth(prefix.len()).ok_or(
                    StateError::InternalInvariant {
                        site: "persistent::build_persistent_subtree child nibble",
                    },
                )?;
                let mut end = index + 1;
                while end < pairs.len() {
                    let (other_key, _) = pairs.get(end).ok_or(StateError::InternalInvariant {
                        site: "persistent::build_persistent_subtree end",
                    })?;
                    let other = key_to_nibbles(other_key);
                    let other_nibble = other.iter().copied().nth(prefix.len()).ok_or(
                        StateError::InternalInvariant {
                            site: "persistent::build_persistent_subtree other nibble",
                        },
                    )?;
                    if other_nibble != child_nibble {
                        break;
                    }
                    end += 1;
                }
                let group = pairs.get(index..end).ok_or(StateError::InternalInvariant {
                    site: "persistent::build_persistent_subtree group",
                })?;
                children.insert(
                    child_nibble,
                    build_persistent_subtree(group, prefix.len() + 1)?,
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
) -> StateResult<Arc<PersistentAuthNode>> {
    match node.as_ref() {
        PersistentAuthNode::Empty => Ok(Arc::new(PersistentAuthNode::Leaf {
            key,
            value_hash,
            hash: hash_compressed_leaf(&key, &value_hash),
        })),
        PersistentAuthNode::Leaf {
            key: existing_key,
            value_hash: existing_value,
            ..
        } => {
            if existing_key == &key {
                Ok(Arc::new(PersistentAuthNode::Leaf {
                    key,
                    value_hash,
                    hash: hash_compressed_leaf(&key, &value_hash),
                }))
            } else {
                let existing_nibbles = key_to_nibbles(existing_key);
                let key_nibbles = key_to_nibbles(&key);
                let prefix_len = common_nibble_prefix_len(&existing_nibbles, &key_nibbles, 0);
                let prefix = key_nibbles.iter().take(prefix_len).copied().collect();
                let mut children = BTreeMap::new();
                let existing_nibble = existing_nibbles.iter().copied().nth(prefix_len).ok_or(
                    StateError::InternalInvariant {
                        site: "persistent::persistent_insert existing nibble",
                    },
                )?;
                let new_nibble = key_nibbles.iter().copied().nth(prefix_len).ok_or(
                    StateError::InternalInvariant {
                        site: "persistent::persistent_insert new nibble",
                    },
                )?;
                children.insert(
                    existing_nibble,
                    Arc::new(PersistentAuthNode::Leaf {
                        key: *existing_key,
                        value_hash: *existing_value,
                        hash: hash_compressed_leaf(existing_key, existing_value),
                    }),
                );
                children.insert(
                    new_nibble,
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
                let old_nibble =
                    prefix
                        .iter()
                        .copied()
                        .nth(shared)
                        .ok_or(StateError::InternalInvariant {
                            site: "persistent::persistent_insert old nibble",
                        })?;
                let new_nibble = key_nibbles.iter().copied().nth(shared).ok_or(
                    StateError::InternalInvariant {
                        site: "persistent::persistent_insert new split nibble",
                    },
                )?;
                let mut split_children = BTreeMap::new();
                split_children.insert(
                    old_nibble,
                    make_persistent_branch(prefix.clone(), children.clone())?,
                );
                split_children.insert(
                    new_nibble,
                    Arc::new(PersistentAuthNode::Leaf {
                        key,
                        value_hash,
                        hash: hash_compressed_leaf(&key, &value_hash),
                    }),
                );
                return make_persistent_branch(
                    key_nibbles.iter().take(shared).copied().collect(),
                    split_children,
                );
            }

            let child_nibble = key_nibbles.iter().copied().nth(prefix.len()).ok_or(
                StateError::InternalInvariant {
                    site: "persistent::persistent_insert child nibble",
                },
            )?;
            let mut updated_children = children.clone();
            let child = updated_children
                .get(&child_nibble)
                .cloned()
                .unwrap_or_else(|| Arc::new(PersistentAuthNode::Empty));
            updated_children.insert(child_nibble, persistent_insert(&child, key, value_hash)?);
            make_persistent_branch(prefix.clone(), updated_children)
        }
    }
}

fn persistent_delete(
    node: &Arc<PersistentAuthNode>,
    key: [u8; 32],
) -> StateResult<Arc<PersistentAuthNode>> {
    match node.as_ref() {
        PersistentAuthNode::Empty => Ok(Arc::new(PersistentAuthNode::Empty)),
        PersistentAuthNode::Leaf {
            key: existing_key, ..
        } => {
            if existing_key == &key {
                Ok(Arc::new(PersistentAuthNode::Empty))
            } else {
                Ok(node.clone())
            }
        }
        PersistentAuthNode::Branch {
            prefix, children, ..
        } => {
            let key_nibbles = key_to_nibbles(&key);
            if !starts_with_nibbles(&key_nibbles, prefix) || prefix.len() >= key_nibbles.len() {
                return make_persistent_branch(prefix.clone(), children.clone());
            }
            let child_nibble = key_nibbles.iter().copied().nth(prefix.len()).ok_or(
                StateError::InternalInvariant {
                    site: "persistent::persistent_delete child nibble",
                },
            )?;
            let Some(child) = children.get(&child_nibble) else {
                return make_persistent_branch(prefix.clone(), children.clone());
            };
            let updated_child = persistent_delete(child, key)?;
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
) -> StateResult<Arc<PersistentAuthNode>> {
    match children.len() {
        0 => Ok(Arc::new(PersistentAuthNode::Empty)),
        1 => match children.pop_first() {
            Some((_, child)) => Ok(child),
            None => Err(StateError::InternalInvariant {
                site: "persistent::collapse_or_branch child",
            }),
        },
        _ => make_persistent_branch(prefix, children),
    }
}

fn make_persistent_branch(
    prefix: Vec<u8>,
    children: BTreeMap<u8, Arc<PersistentAuthNode>>,
) -> StateResult<Arc<PersistentAuthNode>> {
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
        return Ok(Arc::new(PersistentAuthNode::Empty));
    }
    let hash = hash_branch_from_children(&prefix, &proof_children).map_err(|_| {
        StateError::InternalInvariant {
            site: "persistent::make_persistent_branch proof children",
        }
    })?;
    Ok(Arc::new(PersistentAuthNode::Branch {
        prefix,
        children,
        hash,
    }))
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

fn longest_common_prefix_for_pairs(
    pairs: &[([u8; 32], [u8; 32])],
    start_nibble: usize,
) -> StateResult<Vec<u8>> {
    let Some((first_key, _)) = pairs.first() else {
        return Err(StateError::InternalInvariant {
            site: "persistent::longest_common_prefix empty pairs",
        });
    };
    let first = key_to_nibbles(first_key);
    let mut len = start_nibble;
    while len < first.len() {
        let Some(nibble) = first.iter().copied().nth(len) else {
            return Err(StateError::InternalInvariant {
                site: "persistent::longest_common_prefix index",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smt::SparseMerkleTree;
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
    fn persistent_ord_set_basic_correctness_and_order() {
        let mut set = PersistentOrdSet::new();
        assert!(set.is_empty());
        assert!(set.insert(3));
        assert!(set.insert(1));
        assert!(set.insert(2));
        assert!(!set.insert(2));
        assert_eq!(set.len(), 3);
        assert!(set.contains(&2));
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), vec![1, 2, 3]);
        assert!(set.remove(&2));
        assert!(!set.remove(&2));
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), vec![1, 3]);
    }

    #[test]
    fn persistent_ord_set_clone_is_immutable_snapshot_and_shares_nodes() {
        let mut original = PersistentOrdSet::new();
        for index in 0..128 {
            original.insert(index);
        }
        let original_root = original.root_arc().unwrap();
        let mut clone = original.clone();
        let clone_before_root = clone.root_arc().unwrap();
        assert!(Arc::ptr_eq(&original_root, &clone_before_root));

        clone.insert(256);
        clone.remove(&0);
        assert_eq!(original.iter().copied().collect::<Vec<_>>().len(), 128);
        assert!(!original.contains(&256));
        assert!(original.contains(&0));
        assert!(clone.contains(&256));
        assert!(!clone.contains(&0));
        assert!(Arc::ptr_eq(&original_root, &original.root_arc().unwrap()));
        assert!(!Arc::ptr_eq(&original_root, &clone.root_arc().unwrap()));
    }

    #[test]
    fn persistent_ord_set_insertion_order_independent_delete_reinsert() {
        let forward: PersistentOrdSet<_> = (0..256).collect();
        let reverse: PersistentOrdSet<_> = (0..256).rev().collect();
        assert_eq!(forward, reverse);

        let mut changed = forward.clone();
        assert!(changed.remove(&100));
        assert_ne!(changed, reverse);
        assert!(changed.insert(100));
        assert_eq!(changed, reverse);
    }

    #[test]
    fn persistent_sparse_merkle_tree_basic_correctness_and_proofs() {
        let mut tree = PersistentSparseMerkleTree::new();
        assert!(tree.is_empty());
        let k1 = key(0x11);
        let k2 = key(0x22);
        assert_eq!(tree.insert(k1, value(0xAA)), None);
        assert_eq!(tree.insert(k2, value(0xBB)), None);
        assert_eq!(tree.insert(k1, value(0xCC)), Some(value(0xAA)));
        assert_eq!(tree.get(&k1), Some(&value(0xCC)));
        let proof = tree.prove(k1);
        assert!(PersistentSparseMerkleTree::verify_proof(
            tree.root(),
            k1,
            &proof
        ));
        assert!(SparseMerkleTree::verify_proof(tree.root(), k1, &proof));
        assert_eq!(tree.delete(k2), Some(value(0xBB)));
        assert_eq!(tree.get(&k2), None);
        let missing = tree.prove(k2);
        assert!(PersistentSparseMerkleTree::verify_proof(
            tree.root(),
            k2,
            &missing
        ));
        assert!(SparseMerkleTree::verify_proof(tree.root(), k2, &missing));
    }

    #[test]
    fn persistent_sparse_merkle_tree_clone_is_immutable_snapshot_and_shares_handles() {
        let mut original = PersistentSparseMerkleTree::from_pairs(pairs(128)).unwrap();
        let original_root_hash = original.root();
        let (original_leaves_root, original_nodes_root) = original.root_arc_pair();
        let mut clone = original.clone();
        let (clone_leaves_before, clone_nodes_before) = clone.root_arc_pair();
        assert!(Arc::ptr_eq(
            original_leaves_root.as_ref().unwrap(),
            clone_leaves_before.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            original_nodes_root.as_ref().unwrap(),
            clone_nodes_before.as_ref().unwrap()
        ));

        clone.insert(key(0xFE), value(0xFE));
        clone.delete(pairs(128)[0].0);
        assert_eq!(original.root(), original_root_hash);
        assert_ne!(clone.root(), original.root());
        let (original_leaves_after, original_nodes_after) = original.root_arc_pair();
        assert!(Arc::ptr_eq(
            original_leaves_root.as_ref().unwrap(),
            original_leaves_after.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            original_nodes_root.as_ref().unwrap(),
            original_nodes_after.as_ref().unwrap()
        ));

        original.insert(key(0xFD), value(0xFD));
        assert_ne!(clone.root(), original.root());
    }

    #[test]
    fn persistent_sparse_merkle_tree_insertion_order_independent_and_oracle_matches() {
        let entries = pairs(512);
        let forward = PersistentSparseMerkleTree::from_pairs(entries.clone()).unwrap();
        let reverse =
            PersistentSparseMerkleTree::from_pairs(entries.iter().rev().copied()).unwrap();
        let mut incremental = PersistentSparseMerkleTree::new();
        let mut oracle = SparseMerkleTree::new();
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
    fn persistent_sparse_merkle_tree_delete_reinsert_duplicate_and_derived_clones() {
        let entries = pairs(64);
        assert!(PersistentSparseMerkleTree::from_pairs(vec![entries[0], entries[0]]).is_err());
        let mut base = PersistentSparseMerkleTree::from_pairs(entries.clone()).unwrap();
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
    fn persistent_sparse_merkle_tree_long_common_prefix_and_final_bit_keys_match_oracle() {
        let prefix = [0xAB; 31];
        let entries = vec![
            (keyed(&prefix, 0b0000_0000), value(1)),
            (keyed(&prefix, 0b0000_0001), value(2)),
            (keyed(&prefix, 0b0000_0010), value(3)),
            (keyed(&prefix, 0b0000_0011), value(4)),
        ];
        let persistent = PersistentSparseMerkleTree::from_pairs(entries.clone()).unwrap();
        let mut oracle = SparseMerkleTree::new();
        for (key, value) in entries {
            oracle.insert(key, value);
        }
        assert_eq!(persistent.root(), oracle.root());
        for suffix in 0..4 {
            let key = keyed(&prefix, suffix);
            let proof = persistent.prove(key);
            assert_eq!(proof, oracle.prove(key));
            assert!(SparseMerkleTree::verify_proof(
                persistent.root(),
                key,
                &proof
            ));
        }
    }

    #[test]
    fn persistent_sparse_merkle_tree_many_randomized_oracle_sets_roots_and_proofs_match() {
        for size in [0usize, 1, 2, 3, 7, 16, 63, 257] {
            let entries = pairs(size);
            let persistent = PersistentSparseMerkleTree::from_pairs(entries.clone()).unwrap();
            let mut oracle = SparseMerkleTree::new();
            for (key, value) in &entries {
                oracle.insert(*key, *value);
            }
            assert_eq!(persistent.root(), oracle.root(), "size={size}");

            let mut incremental = PersistentSparseMerkleTree::new();
            let mut oracle_incremental = SparseMerkleTree::new();
            for (key, value) in entries.iter().rev().copied() {
                incremental.insert(key, value);
                oracle_incremental.insert(key, value);
            }
            assert_eq!(
                incremental.root(),
                oracle_incremental.root(),
                "incremental size={size}"
            );

            let mut queries: Vec<_> = entries.iter().map(|(key, _)| *key).collect();
            queries.push(keyed(&[0x42; 31], 0x01));
            queries.push(keyed(&[0x42; 31], 0x02));
            for query in queries {
                let persistent_proof = persistent.prove(query);
                let oracle_proof = oracle.prove(query);
                assert_eq!(
                    persistent_proof, oracle_proof,
                    "proof differs for size={size}"
                );
                assert!(SparseMerkleTree::verify_proof(
                    persistent.root(),
                    query,
                    &persistent_proof
                ));
                assert!(PersistentSparseMerkleTree::verify_proof(
                    persistent.root(),
                    query,
                    &persistent_proof
                ));
            }
        }
    }

    #[test]
    fn persistent_auth_tree_basic_correctness_and_proofs() {
        let mut tree = PersistentAuthTree::new();
        assert!(tree.is_empty());
        let k1 = key(0x11);
        let k2 = key(0x22);
        assert_eq!(tree.insert(k1, value(0xAA)), Ok(None));
        assert_eq!(tree.insert(k2, value(0xBB)), Ok(None));
        assert_eq!(tree.insert(k1, value(0xCC)), Ok(Some(value(0xAA))));
        assert_eq!(tree.get(&k1), Some(&value(0xCC)));
        let proof = tree.prove(k1);
        assert!(PersistentAuthTree::verify_proof(tree.root(), k1, &proof));
        assert_eq!(tree.delete(k2), Ok(Some(value(0xBB))));
        assert_eq!(tree.get(&k2), None);
        let missing = tree.prove(k2);
        assert!(PersistentAuthTree::verify_proof(tree.root(), k2, &missing));
    }

    #[test]
    fn empty_persistent_prefix_input_returns_typed_invariant_error() {
        assert_eq!(
            longest_common_prefix_for_pairs(&[], 0),
            Err(StateError::InternalInvariant {
                site: "persistent::longest_common_prefix empty pairs",
            })
        );
    }

    #[test]
    fn persistent_auth_tree_clone_is_immutable_snapshot() {
        let mut original = PersistentAuthTree::from_pairs(pairs(128)).unwrap();
        let original_root = original.root();
        let mut clone = original.clone();
        clone.insert(key(0xFE), value(0xFE)).unwrap();
        clone.delete(pairs(128)[0].0).unwrap();
        assert_eq!(original.root(), original_root);
        assert_ne!(clone.root(), original.root());
        original.insert(key(0xFD), value(0xFD)).unwrap();
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
        clone.insert(keyed(&[0xF0], 0x03), value(5)).unwrap();
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
            incremental.insert(key, value).unwrap();
            oracle.insert(key, value).unwrap();
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
        assert_eq!(
            base.insert(entries[0].0, entries[0].1),
            Ok(Some(entries[0].1))
        );
        assert_eq!(base.root(), root, "same key/value replacement is stable");
        assert_eq!(base.delete(entries[0].0), Ok(Some(entries[0].1)));
        assert_ne!(base.root(), root);
        assert_eq!(base.insert(entries[0].0, entries[0].1), Ok(None));
        assert_eq!(base.root(), root);

        let mut a = base.clone();
        let mut b = base.clone();
        a.insert(key(0xA1), value(0xA1)).unwrap();
        b.insert(key(0xB1), value(0xB1)).unwrap();
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
                incremental.insert(key, value).unwrap();
                oracle_incremental.insert(key, value).unwrap();
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
        let sizes: Vec<usize> = std::env::var("INDRA_PERSISTENT_STAGE2B_BENCH_SIZES")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .filter_map(|part| part.trim().parse::<usize>().ok())
                    .collect()
            })
            .filter(|sizes: &Vec<usize>| !sizes.is_empty())
            .unwrap_or_else(|| vec![100_000usize, 1_000_000, 10_000_000]);
        for size in sizes {
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

            let set_start = Instant::now();
            let mut set = PersistentOrdSet::new();
            for index in 0..size {
                set.insert(index as u64);
            }
            let set_build = set_start.elapsed();
            let set_clone_start = Instant::now();
            let set_clone = set.clone();
            let set_clone_elapsed = set_clone_start.elapsed();
            assert_eq!(set_clone.len(), size);

            let sparse_entries = pairs(size);
            let sparse_start = Instant::now();
            let sparse = PersistentSparseMerkleTree::from_pairs(sparse_entries).unwrap();
            let sparse_build = sparse_start.elapsed();
            let sparse_clone_start = Instant::now();
            let sparse_clone = sparse.clone();
            let sparse_clone_elapsed = sparse_clone_start.elapsed();
            assert_eq!(sparse_clone.root(), sparse.root());

            eprintln!(
                "persistent_primitives_clone_cost size={size} map_build={map_build:?} map_clone={map_clone_elapsed:?} set_build={set_build:?} set_clone={set_clone_elapsed:?} auth_tree_build={tree_build:?} auth_tree_clone={tree_clone_elapsed:?} sparse_tree_build={sparse_build:?} sparse_tree_clone={sparse_clone_elapsed:?}"
            );
            assert!(
                map_clone_elapsed.as_millis() < 5,
                "map clone should stay near-constant at size={size}: {map_clone_elapsed:?}"
            );
            assert!(
                set_clone_elapsed.as_millis() < 5,
                "set clone should stay near-constant at size={size}: {set_clone_elapsed:?}"
            );
            assert!(
                tree_clone_elapsed.as_millis() < 5,
                "tree clone should stay near-constant at size={size}: {tree_clone_elapsed:?}"
            );
            assert!(
                sparse_clone_elapsed.as_millis() < 5,
                "sparse tree clone should stay near-constant at size={size}: {sparse_clone_elapsed:?}"
            );
        }
    }
}
