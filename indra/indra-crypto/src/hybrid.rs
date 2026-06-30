//! Hybrid signature system: Ed25519 (classical) + ML-DSA-87 (post-quantum).
//!
//! Both schemes must verify independently for any signature to be accepted.
//! This is the core cryptographic invariant of the INDRA protocol:
//! security requires an attacker to break BOTH schemes simultaneously.

use ed25519_dalek::{Signature as Ed25519Sig, Signer, SigningKey, Verifier, VerifyingKey};
use ml_dsa::{
    EncodedVerifyingKey, Generate, KeyExport, Keypair, MlDsa87, Signature as MlDsaSignature,
    SignatureEncoding, Signer as MlDsaSigner, SigningKey as MlDsaSigningKey,
    Verifier as MlDsaVerifier, VerifyingKey as MlDsaVerifyingKey,
};

use crate::{
    constants::{CLASSICAL_PK_BYTES, CLASSICAL_SIG_BYTES, PQ_PK_BYTES, PQ_SIG_BYTES, PQ_SK_BYTES},
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
    let vk = VerifyingKey::from_bytes(&pk.0).map_err(|_| CryptoError::MalformedPublicKey {
        scheme: "Ed25519",
        actual: CLASSICAL_PK_BYTES,
    })?;
    let ed_sig = Ed25519Sig::from_bytes(&sig.0);
    vk.verify(message, &ed_sig)
        .map_err(|_| CryptoError::ClassicalVerifyFailed)
}

// ── Post-Quantum (ML-DSA-87) ─────────────────────────────────────────────────

/// An ML-DSA-87 verifying key (2592 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqPublicKey(pub [u8; PQ_PK_BYTES]);

/// An ML-DSA-87 signature (4627 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqSignature(pub [u8; PQ_SIG_BYTES]);

/// An ML-DSA-87 signing keypair represented canonically by its 32-byte seed.
#[derive(Clone)]
pub struct PqKeypair {
    seed: [u8; PQ_SK_BYTES],
}

impl PqKeypair {
    /// Generate a deterministic ML-DSA-87 keypair from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> CryptoResult<Self> {
        Ok(Self { seed: *seed })
    }

    /// Generate a fresh ML-DSA-87 keypair using the library RNG.
    pub fn generate() -> Self {
        let sk = MlDsaSigningKey::<MlDsa87>::generate();
        Self {
            seed: sk.to_seed().into(),
        }
    }

    /// Load an ML-DSA-87 keypair from raw public key and seed bytes.
    pub fn from_bytes(pk_bytes: &[u8], sk_bytes: &[u8]) -> CryptoResult<Self> {
        if sk_bytes.len() != PQ_SK_BYTES {
            return Err(CryptoError::MalformedPublicKey {
                scheme: "ML-DSA-87-seed",
                actual: sk_bytes.len(),
            });
        }

        let mut seed = [0u8; PQ_SK_BYTES];
        seed.copy_from_slice(sk_bytes);
        let keypair = Self { seed };

        if !pk_bytes.is_empty() {
            if pk_bytes.len() != PQ_PK_BYTES {
                return Err(CryptoError::MalformedPublicKey {
                    scheme: "ML-DSA-87",
                    actual: pk_bytes.len(),
                });
            }

            if keypair.public_key().0 != pk_bytes {
                return Err(CryptoError::MalformedPublicKey {
                    scheme: "ML-DSA-87-public-mismatch",
                    actual: pk_bytes.len(),
                });
            }
        }

        Ok(keypair)
    }

    /// Return the raw seed bytes (for storage in keys.json).
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.seed.to_vec()
    }

    /// Return the public key.
    pub fn public_key(&self) -> PqPublicKey {
        let sk = MlDsaSigningKey::<MlDsa87>::from_seed(&self.seed.into());
        let vk = sk.verifying_key();
        PqPublicKey(vk.to_bytes().into())
    }

    /// Sign a message with ML-DSA-87.
    pub fn sign(&self, message: &[u8]) -> CryptoResult<PqSignature> {
        let sk = MlDsaSigningKey::<MlDsa87>::from_seed(&self.seed.into());
        let sig = MlDsaSigner::sign(&sk, message);
        Ok(PqSignature(sig.to_bytes().into()))
    }
}

/// Verify an ML-DSA-87 signature.
pub fn verify_pq(message: &[u8], sig: &PqSignature, pk: &PqPublicKey) -> CryptoResult<()> {
    let enc_vk = EncodedVerifyingKey::<MlDsa87>::try_from(pk.0.as_slice()).map_err(|_| {
        CryptoError::MalformedPublicKey {
            scheme: "ML-DSA-87",
            actual: pk.0.len(),
        }
    })?;
    let vk = MlDsaVerifyingKey::<MlDsa87>::decode(&enc_vk);
    let sig_obj = MlDsaSignature::<MlDsa87>::try_from(sig.0.as_slice()).map_err(|_| {
        CryptoError::MalformedSignature {
            scheme: "ML-DSA-87",
            actual: sig.0.len(),
        }
    })?;
    MlDsaVerifier::verify(&vk, message, &sig_obj).map_err(|_| CryptoError::PqVerifyFailed)
}

// ── Hybrid ────────────────────────────────────────────────────────────────────

/// A hybrid public key: Ed25519 + ML-DSA-87.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridPublicKey {
    /// Ed25519 component (32 bytes).
    pub classical: ClassicalPublicKey,
    /// ML-DSA-87 component (2592 bytes).
    pub pq: PqPublicKey,
}

/// A hybrid signature: Ed25519 + ML-DSA-87.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridSignature {
    /// Ed25519 component (64 bytes).
    pub classical: ClassicalSignature,
    /// ML-DSA-87 component (4627 bytes).
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
    fn ed25519_rejects_non_canonical_signature() {
        let kp = ClassicalKeypair::from_seed(&[0x42u8; 32]);
        let msg = b"test message";
        let mut sig_bytes = kp.sign(msg).0;
        sig_bytes[63] |= 0x80;
        let bad_sig = ClassicalSignature(sig_bytes);
        assert!(
            verify_classical(msg, &bad_sig, &kp.public_key()).is_err(),
            "ed25519-dalek must reject non-canonical S values"
        );
    }

    #[test]
    fn classical_sig_is_deterministic() {
        let kp = classical_kp();
        let msg = b"determinism";
        assert_eq!(kp.sign(msg), kp.sign(msg));
    }

    #[test]
    fn pq_sign_verify_roundtrip() {
        let kp = PqKeypair::from_seed(&[0x11u8; 32]).unwrap();
        let msg = b"INDRA PQ test";
        let sig = kp.sign(msg).unwrap();
        assert!(verify_pq(msg, &sig, &kp.public_key()).is_ok());
    }

    #[test]
    fn pq_wrong_message_fails() {
        let kp = PqKeypair::from_seed(&[0x22u8; 32]).unwrap();
        let sig = kp.sign(b"correct").unwrap();
        assert!(verify_pq(b"wrong", &sig, &kp.public_key()).is_err());
    }

    #[test]
    fn hybrid_both_schemes_must_pass() {
        let kp = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0xABu8; 32]),
            PqKeypair::from_seed(&[0x33u8; 32]).unwrap(),
        );
        let msg = b"hybrid test message";
        let sig = kp.sign(msg).unwrap();
        assert!(verify_hybrid(msg, &sig, &kp.public_key()).is_ok());
    }

    #[test]
    fn hybrid_wrong_message_fails() {
        let kp = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0xCDu8; 32]),
            PqKeypair::from_seed(&[0x44u8; 32]).unwrap(),
        );
        let sig = kp.sign(b"signed").unwrap();
        assert!(verify_hybrid(b"different", &sig, &kp.public_key()).is_err());
    }

    #[test]
    fn pq_seeded_keygen_is_deterministic() {
        let a = PqKeypair::from_seed(&[0x55u8; 32]).unwrap();
        let b = PqKeypair::from_seed(&[0x55u8; 32]).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.secret_key_bytes(), b.secret_key_bytes());
    }
}
