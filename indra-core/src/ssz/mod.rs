//! SSZ-style Merkleisation — `hash_tree_root`.
//!
//! Produces a deterministic 32-byte root for any protocol object.
//! Guaranteed identical output on all platforms (Linux/macOS/Windows, x86/ARM).

pub mod merkle;

pub use merkle::{merkleise, hash_tree_root_chunks};

use sha2::{Digest, Sha256};

/// SHA-256 of raw bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Hash two 32-byte nodes as a Merkle parent.
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Types that can produce an SSZ-style hash tree root.
pub trait Ssz {
    /// Produce the 32-byte hash tree root for this value.
    fn hash_tree_root(&self) -> [u8; 32];
}

// ── Primitive Ssz implementations ────────────────────────────────────────────

impl Ssz for u8 {
    fn hash_tree_root(&self) -> [u8; 32] {
        let mut c = [0u8; 32]; c[0] = *self; c
    }
}
impl Ssz for u16 {
    fn hash_tree_root(&self) -> [u8; 32] {
        let mut c = [0u8; 32]; c[..2].copy_from_slice(&self.to_le_bytes()); c
    }
}
impl Ssz for u32 {
    fn hash_tree_root(&self) -> [u8; 32] {
        let mut c = [0u8; 32]; c[..4].copy_from_slice(&self.to_le_bytes()); c
    }
}
impl Ssz for u64 {
    fn hash_tree_root(&self) -> [u8; 32] {
        let mut c = [0u8; 32]; c[..8].copy_from_slice(&self.to_le_bytes()); c
    }
}
impl Ssz for bool {
    fn hash_tree_root(&self) -> [u8; 32] {
        let mut c = [0u8; 32]; c[0] = *self as u8; c
    }
}
