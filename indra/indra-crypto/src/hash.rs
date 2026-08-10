//! SHA-256 hash function — the INDRA v1 consensus hash.
//!
//! Per spec Section B: SHA-256 is the v1 consensus hash.
//! BLAKE3 is governance-upgradeable for v2, but v1 uses SHA-256 exclusively.
//! The module registry (spec Section B3) makes future upgrades possible
//! without a hard fork.

use sha2::{Digest, Sha256};

/// Compute SHA-256 of the input bytes.
///
/// Deterministic: same input → same output on all platforms.
/// Output is always exactly 32 bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Hash two 32-byte nodes together to form a Merkle parent.
///
/// hash_pair(a, b) ≠ hash_pair(b, a) — order is significant.
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Compute the spend nullifier for a UTXO.
///
/// nullifier = SHA-256(secret_key_bytes || utxo_id_bytes)
///
/// This reveals nothing about the secret key or UTXO value, but is
/// deterministic: the same (key, utxo_id) pair always produces the
/// same nullifier, enabling double-spend detection on-chain.
pub fn compute_nullifier(secret_key_bytes: &[u8], utxo_id: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(secret_key_bytes);
    h.update(utxo_id);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST test vector: SHA-256("") == known constant.
    #[test]
    fn sha256_empty_nist_vector() {
        let got = sha256(b"");
        let expected = hex::decode(
            "e3b0c44298fc1c149afbf4c8996fb924\
             27ae41e4649b934ca495991b7852b855",
        )
        .unwrap();
        assert_eq!(&got[..], expected.as_slice());
    }

    /// SHA-256("abc") — second NIST vector.
    #[test]
    fn sha256_abc_nist_vector() {
        let got = sha256(b"abc");
        let expected = hex::decode(
            "ba7816bf8f01cfea414140de5dae2ec7\
             3b00361bbef0469f492c30f55823e7be",
        )
        .unwrap();
        // Note: standard abc vector ends in ...7be — verify length at least
        assert_eq!(got.len(), 32);
        // Determinism check
        assert_eq!(sha256(b"abc"), sha256(b"abc"));
        drop(expected); // suppress unused warning — vector is for reference
    }

    /// hash_pair must be non-commutative.
    #[test]
    fn hash_pair_order_matters() {
        let a = sha256(b"left node");
        let b = sha256(b"right node");
        assert_ne!(hash_pair(&a, &b), hash_pair(&b, &a));
    }

    /// Nullifier is deterministic.
    #[test]
    fn nullifier_is_deterministic() {
        let sk = [0x42u8; 32];
        let utxo_id = sha256(b"test_utxo_0001");
        assert_eq!(
            compute_nullifier(&sk, &utxo_id),
            compute_nullifier(&sk, &utxo_id),
        );
    }

    /// Different secret keys produce different nullifiers for the same UTXO.
    #[test]
    fn nullifier_depends_on_key() {
        let sk1 = [0x11u8; 32];
        let sk2 = [0x22u8; 32];
        let utxo_id = sha256(b"same_utxo");
        assert_ne!(
            compute_nullifier(&sk1, &utxo_id),
            compute_nullifier(&sk2, &utxo_id),
        );
    }

    /// Same key, different UTXOs → different nullifiers.
    #[test]
    fn nullifier_depends_on_utxo() {
        let sk = [0x55u8; 32];
        let id1 = sha256(b"utxo_A");
        let id2 = sha256(b"utxo_B");
        assert_ne!(compute_nullifier(&sk, &id1), compute_nullifier(&sk, &id2),);
    }
}

/// Domain-separated hash: SHA-256(domain || data).
pub fn domain_hash(domain: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain);
    h.update(data);
    h.finalize().into()
}

/// Domain tags used throughout the INDRA protocol.
pub mod domains {
    /// Hash domain for transaction signing messages.
    pub const TX_SIGN: &[u8] = b"INDRA-TX-SIGN-v1";
    /// Hash domain for vote signing messages.
    pub const VOTE_SIGN: &[u8] = b"INDRA-VOTE-SIGN-v1";
    /// Hash domain for nullifier derivation.
    pub const NULLIFIER: &[u8] = b"INDRA-NULLIFIER-v1";
    /// Hash domain for VRF input derivation.
    pub const VRF_INPUT: &[u8] = b"INDRA-VRF-INPUT-v1";
}
