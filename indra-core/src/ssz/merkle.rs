//! Binary Merkle tree over 32-byte chunks (SSZ-style).

use super::hash_pair;

/// Merkleise a slice of 32-byte chunks into a single 32-byte root.
///
/// Algorithm:
/// 1. Empty → return zero hash.
/// 2. Pad to next power of two using the zero chunk.
/// 3. Build the tree bottom-up, hashing adjacent pairs.
/// 4. The last remaining node is the root.
///
/// This matches the SSZ merkleise function from the Ethereum consensus spec
/// and produces identical output given the same chunks.
pub fn merkleise(chunks: &[[u8; 32]]) -> [u8; 32] {
    if chunks.is_empty() {
        return [0u8; 32];
    }
    let n = chunks.len().next_power_of_two();
    let mut layer: Vec<[u8; 32]> = chunks.to_vec();
    layer.resize(n, [0u8; 32]); // zero-pad to power of two

    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        let mut i = 0;
        while i + 1 < layer.len() {
            next.push(hash_pair(&layer[i], &layer[i + 1]));
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

/// Chunk a byte sequence into 32-byte pieces (zero-padding the last),
/// then merkleise.
pub fn hash_tree_root_chunks(data: &[u8]) -> [u8; 32] {
    if data.is_empty() {
        return merkleise(&[]);
    }
    let mut chunks = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut chunk = [0u8; 32];
        let end = (i + 32).min(data.len());
        chunk[..end - i].copy_from_slice(&data[i..end]);
        chunks.push(chunk);
        i += 32;
    }
    merkleise(&chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_returns_zero_hash() {
        assert_eq!(merkleise(&[]), [0u8; 32]);
    }

    #[test]
    fn single_chunk_is_identity() {
        let c = [0xABu8; 32];
        assert_eq!(merkleise(&[c]), c);
    }

    #[test]
    fn two_chunks() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let root = merkleise(&[a, b]);
        assert_eq!(root, hash_pair(&a, &b));
    }

    #[test]
    fn four_chunks_matches_manual() {
        let chunks: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        let root = merkleise(&chunks);
        let l = hash_pair(&chunks[0], &chunks[1]);
        let r = hash_pair(&chunks[2], &chunks[3]);
        assert_eq!(root, hash_pair(&l, &r));
    }

    #[test]
    fn merkleise_is_deterministic() {
        let chunks: Vec<[u8; 32]> = (0..8u8).map(|i| [i; 32]).collect();
        assert_eq!(merkleise(&chunks), merkleise(&chunks));
    }

    #[test]
    fn hash_tree_root_empty() {
        assert_eq!(hash_tree_root_chunks(b""), [0u8; 32]);
    }

    #[test]
    fn hash_tree_root_deterministic() {
        let data = b"INDRA Phase 1 serialisation layer test vector";
        assert_eq!(hash_tree_root_chunks(data), hash_tree_root_chunks(data));
    }

    #[test]
    fn different_data_different_roots() {
        let a = hash_tree_root_chunks(b"data A");
        let b = hash_tree_root_chunks(b"data B");
        assert_ne!(a, b);
    }
}
