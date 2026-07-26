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
use rand_core::{CryptoRng, OsRng, RngCore};
use zeroize::Zeroize;

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

/// A validator cold-storage public key.
///
/// This role-specific wrapper always contains one complete hybrid public key.
/// Verification APIs consume it as a unit and never accept separate classical
/// and post-quantum public-key components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColdHybridPublicKey(HybridPublicKey);

impl ColdHybridPublicKey {
    /// Wrap one complete hybrid public key as a cold-role public key.
    pub fn from_complete_hybrid(public_key: HybridPublicKey) -> Self {
        Self(public_key)
    }

    /// Return the complete underlying hybrid public key.
    pub fn as_complete_hybrid(&self) -> &HybridPublicKey {
        &self.0
    }
}

/// A validator cold-storage keypair backed by independent Ed25519 and
/// ML-DSA-87 entropy.
///
/// This type intentionally exposes no one-seed constructor. Callers must
/// provide two independent seeds or two independent cryptographic RNG inputs.
pub struct ColdHybridKeypair {
    keypair: HybridKeypair,
}

impl ColdHybridKeypair {
    /// Construct from independently sourced Ed25519 and ML-DSA-87 seeds.
    pub fn from_independent_seeds(
        mut classical_seed: [u8; 32],
        mut pq_seed: [u8; 32],
    ) -> CryptoResult<Self> {
        let classical = ClassicalKeypair::from_seed(&classical_seed);
        let pq = PqKeypair::from_seed(&pq_seed);
        classical_seed.zeroize();
        pq_seed.zeroize();
        Ok(Self {
            keypair: HybridKeypair::new(classical, pq?),
        })
    }

    /// Generate using two independently supplied cryptographic RNGs.
    ///
    /// Requiring two RNG parameters prevents this API from deriving both
    /// component seeds from one shared 32-byte value.
    pub fn generate_with_rngs<RClassical, RPq>(
        classical_rng: &mut RClassical,
        pq_rng: &mut RPq,
    ) -> CryptoResult<Self>
    where
        RClassical: CryptoRng + RngCore,
        RPq: CryptoRng + RngCore,
    {
        let mut classical_seed = [0u8; 32];
        let mut pq_seed = [0u8; 32];
        classical_rng.fill_bytes(&mut classical_seed);
        pq_rng.fill_bytes(&mut pq_seed);
        Self::from_independent_seeds(classical_seed, pq_seed)
    }

    /// Generate using two independent operating-system CSPRNG reads.
    pub fn generate() -> CryptoResult<Self> {
        let mut classical_rng = OsRng;
        let mut pq_rng = OsRng;
        Self::generate_with_rngs(&mut classical_rng, &mut pq_rng)
    }

    /// Return the complete cold-role public key.
    pub fn public_key(&self) -> ColdHybridPublicKey {
        ColdHybridPublicKey::from_complete_hybrid(self.keypair.public_key())
    }

    /// Sign a message with both cold-key components.
    pub fn sign(&self, message: &[u8]) -> CryptoResult<HybridSignature> {
        self.keypair.sign(message)
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

/// Verify a dual-required authorization.
///
/// The hot and cold signatures must each be complete hybrid signatures over
/// the same message. The helper accepts complete public-key objects only; it
/// has no API for receiving or recombining individual public-key components.
pub fn verify_dual_hybrid(
    message: &[u8],
    hot_signature: Option<&HybridSignature>,
    registered_hot_pair: &HybridPublicKey,
    cold_signature: Option<&HybridSignature>,
    registered_or_proposed_cold_pair: &ColdHybridPublicKey,
) -> CryptoResult<()> {
    let hot_signature = hot_signature.ok_or(CryptoError::MissingHybridSignature { role: "hot" })?;
    let cold_signature =
        cold_signature.ok_or(CryptoError::MissingHybridSignature { role: "cold" })?;

    verify_hybrid(message, hot_signature, registered_hot_pair)?;
    verify_hybrid(
        message,
        cold_signature,
        registered_or_proposed_cold_pair.as_complete_hybrid(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{CryptoRng, Error as RandError, RngCore};

    struct CountingRng {
        byte: u8,
        fill_calls: usize,
    }

    impl RngCore for CountingRng {
        fn next_u32(&mut self) -> u32 {
            u32::from(self.byte)
        }

        fn next_u64(&mut self) -> u64 {
            u64::from(self.byte)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.fill_calls += 1;
            dest.fill(self.byte);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for CountingRng {}

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
    fn cold_key_generation_requires_two_independent_entropy_inputs() {
        let mut classical_rng = CountingRng {
            byte: 0x31,
            fill_calls: 0,
        };
        let mut pq_rng = CountingRng {
            byte: 0xA7,
            fill_calls: 0,
        };

        let generated =
            ColdHybridKeypair::generate_with_rngs(&mut classical_rng, &mut pq_rng).unwrap();
        let expected = ColdHybridKeypair::from_independent_seeds([0x31; 32], [0xA7; 32]).unwrap();

        assert_eq!(classical_rng.fill_calls, 1);
        assert_eq!(pq_rng.fill_calls, 1);
        assert_eq!(generated.public_key(), expected.public_key());
    }

    #[test]
    fn dual_verification_requires_both_complete_pairs_and_rejects_mixing() {
        let hot = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0x11; 32]),
            PqKeypair::from_seed(&[0x12; 32]).unwrap(),
        );
        let cold = ColdHybridKeypair::from_independent_seeds([0x21; 32], [0x22; 32]).unwrap();
        let message = b"INDRA dual-required authorization test";
        let hot_signature = hot.sign(message).unwrap();
        let cold_signature = cold.sign(message).unwrap();
        let hot_public = hot.public_key();
        let cold_public = cold.public_key();

        assert!(verify_dual_hybrid(
            message,
            Some(&hot_signature),
            &hot_public,
            Some(&cold_signature),
            &cold_public,
        )
        .is_ok());

        assert_eq!(
            verify_dual_hybrid(
                message,
                Some(&hot_signature),
                &hot_public,
                None,
                &cold_public,
            ),
            Err(CryptoError::MissingHybridSignature { role: "cold" })
        );
        assert_eq!(
            verify_dual_hybrid(
                message,
                None,
                &hot_public,
                Some(&cold_signature),
                &cold_public,
            ),
            Err(CryptoError::MissingHybridSignature { role: "hot" })
        );

        let mixed_hot_classical_cold_pq = HybridSignature {
            classical: hot_signature.classical.clone(),
            pq: cold_signature.pq.clone(),
        };
        assert_eq!(
            verify_dual_hybrid(
                message,
                Some(&mixed_hot_classical_cold_pq),
                &hot_public,
                Some(&cold_signature),
                &cold_public,
            ),
            Err(CryptoError::PqVerifyFailed)
        );

        let mixed_cold_classical_hot_pq = HybridSignature {
            classical: cold_signature.classical.clone(),
            pq: hot_signature.pq.clone(),
        };
        assert_eq!(
            verify_dual_hybrid(
                message,
                Some(&hot_signature),
                &hot_public,
                Some(&mixed_cold_classical_hot_pq),
                &cold_public,
            ),
            Err(CryptoError::PqVerifyFailed)
        );
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
