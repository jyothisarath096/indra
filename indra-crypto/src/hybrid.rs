//! Hybrid signature system: Ed25519 (classical) + Dilithium2 (post-quantum).
//!
//! Both schemes must verify independently for any signature to be accepted.
//! This is the core cryptographic invariant of the INDRA protocol:
//! security requires an attacker to break BOTH schemes simultaneously.

use ed25519_dalek::{
    Signature as Ed25519Sig,
    SigningKey,
    VerifyingKey,
    Signer,
    Verifier,
};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{
    PublicKey as PqPubKeyTrait,
    SignedMessage as PqSignedMsg,

};

use crate::{
    constants::{CLASSICAL_SIG_BYTES, CLASSICAL_PK_BYTES},
    error::{CryptoError, CryptoResult},
};

// ── Classical (Ed25519) ───────────────────────────────────────────────────────

/// An Ed25519 public key (32 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassicalPublicKey(pub [u8; CLASSICAL_PK_BYTES]);

/// An Ed25519 signature (64 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassicalSignature(pub [u8; CLASSICAL_SIG_BYTES]);

/// An Ed25519 signing keypair.
pub struct ClassicalKeypair(SigningKey);

impl ClassicalKeypair {
    /// Create from a 32-byte seed (must be cryptographically random).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// Return the corresponding public key.
    pub fn public_key(&self) -> ClassicalPublicKey {
        ClassicalPublicKey(self.0.verifying_key().to_bytes())
    }

    /// Sign a message. Ed25519 signing is deterministic (RFC 8032).
    /// Same (key, message) always produces the same signature.
    pub fn sign(&self, message: &[u8]) -> ClassicalSignature {
        let sig = self.0.sign(message);
        ClassicalSignature(sig.to_bytes())
    }
}

/// Verify an Ed25519 signature.
///
/// Returns `Ok(())` if valid.
/// Returns `Err(CryptoError::ClassicalVerifyFailed)` if invalid.
pub fn verify_classical(
    message: &[u8],
    sig: &ClassicalSignature,
    pk: &ClassicalPublicKey,
) -> CryptoResult<()> {
    let vk = VerifyingKey::from_bytes(&pk.0)
        .map_err(|_| CryptoError::MalformedPublicKey {
            scheme: "Ed25519",
            actual: CLASSICAL_PK_BYTES,
        })?;
    let ed_sig = Ed25519Sig::from_bytes(&sig.0);
    vk.verify(message, &ed_sig)
        .map_err(|_| CryptoError::ClassicalVerifyFailed)
}

// ── Post-Quantum (Dilithium2) ─────────────────────────────────────────────────

/// A Dilithium2 public key (~1312 bytes, stored in a Vec for flexibility).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqPublicKey(pub Vec<u8>);

/// A Dilithium2 signature (~2420 bytes, stored in a Vec).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqSignature(pub Vec<u8>);

/// A Dilithium2 signing keypair.
pub struct PqKeypair {
    pk: dilithium2::PublicKey,
    sk: dilithium2::SecretKey,
}

impl PqKeypair {
    /// Generate a new Dilithium2 keypair using the library's secure RNG.
    pub fn generate() -> Self {
        let (pk, sk) = dilithium2::keypair();
        Self { pk, sk }
    }

    /// Load a Dilithium2 keypair from raw byte slices.
    ///
    /// Use this to restore a previously generated keypair from stored bytes.
    /// The bytes must have been produced by a prior call to `generate()`.
    pub fn from_bytes(pk_bytes: &[u8], sk_bytes: &[u8]) -> CryptoResult<Self> {
        use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
        let pk = dilithium2::PublicKey::from_bytes(pk_bytes)
            .map_err(|_| CryptoError::MalformedPublicKey {
                scheme: "dilithium2",
                actual: pk_bytes.len(),
            })?;
        let sk = dilithium2::SecretKey::from_bytes(sk_bytes)
            .map_err(|_| CryptoError::MalformedPublicKey {
                scheme: "dilithium2-sk",
                actual: sk_bytes.len(),
            })?;
        Ok(Self { pk, sk })
    }

    /// Return the raw secret key bytes (for storage in keys.json).
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        use pqcrypto_traits::sign::SecretKey as _;
        self.sk.as_bytes().to_vec()
    }

    /// Return the public key.
    pub fn public_key(&self) -> PqPublicKey {
        PqPublicKey(self.pk.as_bytes().to_vec())
    }

    /// Sign a message with Dilithium2.
    pub fn sign(&self, message: &[u8]) -> CryptoResult<PqSignature> {
        let sm = dilithium2::sign(message, &self.sk);
        let sig_len = dilithium2::signature_bytes();
        let raw = sm.as_bytes();
        if raw.len() < sig_len {
            return Err(CryptoError::MalformedSignature {
                scheme: "Dilithium2",
                actual: raw.len(),
            });
        }
        // pqcrypto prepends the detached signature to the message
        Ok(PqSignature(raw[..sig_len].to_vec()))
    }
}

/// Verify a Dilithium2 signature.
pub fn verify_pq(
    message: &[u8],
    sig: &PqSignature,
    pk: &PqPublicKey,
) -> CryptoResult<()> {
    let pk_obj = dilithium2::PublicKey::from_bytes(&pk.0)
        .map_err(|_| CryptoError::MalformedPublicKey {
            scheme: "Dilithium2",
            actual: pk.0.len(),
        })?;
    // Reconstruct the signed message format pqcrypto expects: sig || message
    let sig_len = dilithium2::signature_bytes();
    let mut combined = sig.0.clone();
    combined.extend_from_slice(message);
    if combined.len() < sig_len {
        return Err(CryptoError::MalformedSignature {
            scheme: "Dilithium2",
            actual: sig.0.len(),
        });
    }
    let sm = dilithium2::SignedMessage::from_bytes(&combined)
        .map_err(|_| CryptoError::MalformedSignature {
            scheme: "Dilithium2",
            actual: sig.0.len(),
        })?;
    dilithium2::open(&sm, &pk_obj)
        .map(|_| ())
        .map_err(|_| CryptoError::PqVerifyFailed)
}

// ── Hybrid ────────────────────────────────────────────────────────────────────

/// A hybrid public key: Ed25519 + Dilithium2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridPublicKey {
    /// Ed25519 component (32 bytes).
    pub classical: ClassicalPublicKey,
    /// Dilithium2 component (~1312 bytes).
    pub pq: PqPublicKey,
}

/// A hybrid signature: Ed25519 + Dilithium2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridSignature {
    /// Ed25519 component (64 bytes).
    pub classical: ClassicalSignature,
    /// Dilithium2 component (~2420 bytes).
    pub pq: PqSignature,
}

/// A hybrid signing keypair.
pub struct HybridKeypair {
    classical: ClassicalKeypair,
    pq: PqKeypair,
}

impl HybridKeypair {
    /// Create from separate classical and PQ keypairs.
    pub fn new(classical: ClassicalKeypair, pq: PqKeypair) -> Self {
        Self { classical, pq }
    }

    /// Return the hybrid public key.
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            classical: self.classical.public_key(),
            pq: self.pq.public_key(),
        }
    }

    /// Sign a message with both schemes.
    pub fn sign(&self, message: &[u8]) -> CryptoResult<HybridSignature> {
        Ok(HybridSignature {
            classical: self.classical.sign(message),
            pq: self.pq.sign(message)?,
        })
    }
}

/// Verify a hybrid signature.
///
/// BOTH schemes must verify for `Ok(())` to be returned.
/// This is the core security invariant: breaking one scheme is not enough.
pub fn verify_hybrid(
    message: &[u8],
    sig: &HybridSignature,
    pk: &HybridPublicKey,
) -> CryptoResult<()> {
    verify_classical(message, &sig.classical, &pk.classical)?;
    verify_pq(message, &sig.pq, &pk.pq)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classical_kp() -> ClassicalKeypair {
        ClassicalKeypair::from_seed(&[0x42u8; 32])
    }

    #[test]
    fn classical_sign_verify_roundtrip() {
        let kp = classical_kp();
        let msg = b"INDRA test message";
        let sig = kp.sign(msg);
        assert!(verify_classical(msg, &sig, &kp.public_key()).is_ok());
    }

    #[test]
    fn classical_wrong_message_fails() {
        let kp = classical_kp();
        let sig = kp.sign(b"correct");
        assert!(verify_classical(b"wrong", &sig, &kp.public_key()).is_err());
    }

    #[test]
    fn classical_wrong_key_fails() {
        let kp1 = ClassicalKeypair::from_seed(&[0x01u8; 32]);
        let kp2 = ClassicalKeypair::from_seed(&[0x02u8; 32]);
        let msg = b"test";
        let sig = kp1.sign(msg);
        assert!(verify_classical(msg, &sig, &kp2.public_key()).is_err());
    }

    #[test]
    fn classical_sig_is_deterministic() {
        let kp = classical_kp();
        let msg = b"determinism";
        assert_eq!(kp.sign(msg), kp.sign(msg));
    }

    #[test]
    fn pq_sign_verify_roundtrip() {
        let kp = PqKeypair::generate();
        let msg = b"INDRA PQ test";
        let sig = kp.sign(msg).unwrap();
        assert!(verify_pq(msg, &sig, &kp.public_key()).is_ok());
    }

    #[test]
    fn pq_wrong_message_fails() {
        let kp = PqKeypair::generate();
        let sig = kp.sign(b"correct").unwrap();
        assert!(verify_pq(b"wrong", &sig, &kp.public_key()).is_err());
    }

    #[test]
    fn hybrid_both_schemes_must_pass() {
        let kp = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0xABu8; 32]),
            PqKeypair::generate(),
        );
        let msg = b"hybrid test message";
        let sig = kp.sign(msg).unwrap();
        assert!(verify_hybrid(msg, &sig, &kp.public_key()).is_ok());
    }

    #[test]
    fn hybrid_wrong_message_fails() {
        let kp = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0xCDu8; 32]),
            PqKeypair::generate(),
        );
        let sig = kp.sign(b"signed").unwrap();
        assert!(verify_hybrid(b"different", &sig, &kp.public_key()).is_err());
    }
}
