#!/usr/bin/env bash
# =============================================================================
# INDRA v2 — Phase 3 Setup Script
# Cryptographic Verification Layer
# =============================================================================
# Run from inside the indra/ workspace directory:
#
#   chmod +x setup_indra_phase3.sh
#   ./setup_indra_phase3.sh
#   cargo build
#   cargo test
#
# Prerequisites: Phase 1 and Phase 2 must already be set up and passing.
#
# What this adds:
#   indra-crypto/src/
#     lib.rs         — crate root, public API
#     error.rs       — CryptoError enum
#     hash.rs        — SHA-256 primitives, domain-separated hashing
#     hybrid.rs      — Ed25519 + Dilithium2 hybrid sign/verify
#     bls.rs         — BLS12-381 aggregation and QC verification
#     pedersen.rs    — Pedersen commitments on Ristretto255
#     commitment.rs  — Commitment balance equation verification
#     vrf.rs         — VRF stub (ECVRF interface, full impl in Phase 4)
#
#   indra-state/src/verify.rs  — plugs crypto into the block application loop
# =============================================================================

set -euo pipefail

echo "==> Setting up INDRA Phase 3 — Cryptographic Verification..."

# Confirm we're in the right place
if [ ! -f "Cargo.toml" ]; then
    echo "ERROR: Run this script from inside the indra/ workspace directory."
    echo "  cd ~/Desktop/project_indra/indra"
    echo "  ./setup_indra_phase3.sh"
    exit 1
fi

# =============================================================================
# Update workspace Cargo.toml — add curve25519-dalek for Pedersen commitments
# =============================================================================

cat > Cargo.toml << 'TOML'
[workspace]
members  = ["indra-core", "indra-crypto", "indra-state"]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
authors = ["INDRA Protocol"]
license = "MIT"

[workspace.dependencies]
sha2                = { version = "0.10", default-features = false }
thiserror           = { version = "1.0" }
hex                 = { version = "0.4", default-features = false, features = ["alloc"] }
ed25519-dalek       = { version = "2.1", default-features = false, features = ["alloc"] }
curve25519-dalek    = { version = "4.1", default-features = false, features = ["alloc"] }
pqcrypto-dilithium  = { version = "0.5", default-features = false }
pqcrypto-traits     = { version = "0.3", default-features = false }
blst                = { version = "0.3" }
proptest            = { version = "1.4", default-features = false, features = ["std"] }

[profile.release]
opt-level     = 3
lto           = true
codegen-units = 1
panic         = "abort"

[profile.dev]
opt-level = 0
debug     = true
TOML

# =============================================================================
# Update indra-crypto/Cargo.toml
# =============================================================================

cat > indra-crypto/Cargo.toml << 'TOML'
[package]
name        = "indra-crypto"
description = "INDRA cryptographic primitives — Ed25519+Dilithium2 hybrid, BLS12-381, Pedersen commitments"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
sha2.workspace               = true
thiserror.workspace          = true
hex.workspace                = true
ed25519-dalek.workspace      = true
curve25519-dalek.workspace   = true
pqcrypto-dilithium.workspace = true
pqcrypto-traits.workspace    = true
blst.workspace               = true

[dev-dependencies]
proptest.workspace = true
TOML

# =============================================================================
# Update indra-state/Cargo.toml — add indra-crypto dependency
# =============================================================================

cat > indra-state/Cargo.toml << 'TOML'
[package]
name        = "indra-state"
description = "INDRA state machine — UTXO set, nullifier set, block application, epoch transitions, crypto verification"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
indra-core   = { path = "../indra-core" }
indra-crypto = { path = "../indra-crypto" }
thiserror.workspace = true

[dev-dependencies]
indra-core   = { path = "../indra-core" }
indra-crypto = { path = "../indra-crypto" }
TOML

# =============================================================================
# FILE: indra-crypto/src/lib.rs
# =============================================================================

cat > indra-crypto/src/lib.rs << 'RUST'
//! # indra-crypto
//!
//! Cryptographic primitives for the INDRA v2 protocol.
//!
//! ## Hybrid Signature Security Model
//!
//! Every signed message requires BOTH of these to pass:
//!
//!   verify_ed25519(message, sig_classical, pk_classical) == true
//!   AND
//!   verify_dilithium2(message, sig_pq, pk_pq)           == true
//!
//! No OR logic. No fallback. Either failure rejects the message.
//! An attacker must break both Ed25519 AND Dilithium2 simultaneously.
//!
//! ## Pedersen Commitment Model
//!
//! Commitments use Ristretto255 (a prime-order group over Curve25519).
//!
//!   C = value * G + blinding * H
//!
//! G and H are independent generators (H derived by hashing to the curve).
//! Commitments are additively homomorphic:
//!   C(v1,r1) + C(v2,r2) = C(v1+v2, r1+r2)
//!
//! ## Invariants
//!
//! - No unsafe code.
//! - No floating-point arithmetic.
//! - All operations deterministic given the same inputs.
//! - No runtime algorithm negotiation.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod error;
pub mod hash;
pub mod hybrid;
pub mod bls;
pub mod pedersen;
pub mod commitment;
pub mod vrf;

pub use error::{CryptoError, CryptoResult};
pub use hash::{sha256, hash_pair, domain_hash};
pub use hybrid::{
    ClassicalKeypair, ClassicalPublicKey, ClassicalSignature,
    PqKeypair, PqPublicKey, PqSignature,
    HybridKeypair, HybridPublicKey, HybridSignature,
    verify_classical, verify_pq, verify_hybrid,
};
pub use bls::{
    BlsKeypair, BlsPublicKey, BlsSignature, BlsAggregateSignature,
    aggregate_signatures, verify_aggregate,
};
pub use pedersen::{
    PedersenCommitment, PedersenOpening,
    commit, verify_opening,
};
pub use commitment::verify_balance;
pub use vrf::{VrfKeypair, VrfOutput, VrfProof, vrf_prove, vrf_verify};
RUST

# =============================================================================
# FILE: indra-crypto/src/error.rs
# =============================================================================

cat > indra-crypto/src/error.rs << 'RUST'
//! Error types for the INDRA cryptographic layer.

use thiserror::Error;

/// All errors that can occur in the INDRA cryptographic layer.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum CryptoError {
    /// Ed25519 signature verification failed.
    #[error("Ed25519 signature verification failed")]
    ClassicalVerifyFailed,

    /// Dilithium2 signature verification failed.
    #[error("Dilithium2 signature verification failed")]
    PqVerifyFailed,

    /// BLS operation failed.
    #[error("BLS operation failed: {detail}")]
    BlsFailed {
        /// Detail of the failure.
        detail: &'static str,
    },

    /// A public key had the wrong length or was otherwise malformed.
    #[error("malformed public key for {scheme}: got {actual} bytes")]
    MalformedPublicKey {
        /// Which scheme.
        scheme: &'static str,
        /// Actual size received.
        actual: usize,
    },

    /// A signature had the wrong length or was otherwise malformed.
    #[error("malformed signature for {scheme}: got {actual} bytes")]
    MalformedSignature {
        /// Which scheme.
        scheme: &'static str,
        /// Actual size received.
        actual: usize,
    },

    /// A Ristretto255 point was not a valid compressed encoding.
    #[error("invalid Ristretto255 point encoding")]
    InvalidPoint,

    /// Pedersen commitment opening verification failed.
    #[error("Pedersen commitment opening failed")]
    CommitmentOpeningFailed,

    /// Commitment balance check failed.
    #[error("commitment balance failed: inputs do not equal outputs plus fee")]
    CommitmentBalanceFailed,

    /// VRF proof verification failed.
    #[error("VRF proof verification failed")]
    VrfProofFailed,

    /// VRF output does not match the proof.
    #[error("VRF output does not match proof")]
    VrfOutputMismatch,

    /// BLS aggregation requires at least one signer.
    #[error("BLS aggregation requires at least one signer")]
    EmptySignerSet,
}

/// Convenience alias.
pub type CryptoResult<T> = Result<T, CryptoError>;
RUST

# =============================================================================
# FILE: indra-crypto/src/hash.rs
# =============================================================================

cat > indra-crypto/src/hash.rs << 'RUST'
//! SHA-256 and domain-separated hashing.
//!
//! Domain separation prevents cross-context hash collisions.
//! Every distinct hashing context uses a unique domain tag prefix.

use sha2::{Digest, Sha256};

/// SHA-256 of the input bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Hash two 32-byte nodes to form a Merkle parent.
/// Non-commutative: hash_pair(a,b) != hash_pair(b,a).
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Domain-separated hash: SHA-256(domain_tag || data).
pub fn domain_hash(domain: &[u8], data: &[u8]) -> [u8; 32] {
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
    /// Hash domain for validator ID derivation.
    pub const VALIDATOR_ID: &[u8] = b"INDRA-VALIDATOR-ID-v1";
    /// Hash domain for VRF input derivation.
    pub const VRF_INPUT: &[u8] = b"INDRA-VRF-INPUT-v1";
}

/// Compute the validator ID from a hybrid public key encoding.
pub fn compute_validator_id(hybrid_pk_bytes: &[u8]) -> [u8; 32] {
    domain_hash(domains::VALIDATOR_ID, hybrid_pk_bytes)
}

/// Compute a spend nullifier.
///
/// nullifier = SHA-256(DOMAIN_NULLIFIER || secret_key_bytes || utxo_id)
pub fn compute_nullifier(secret_key_bytes: &[u8], utxo_id: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domains::NULLIFIER);
    h.update(secret_key_bytes);
    h.update(utxo_id);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty_nist_vector() {
        let got = sha256(b"");
        assert_eq!(got[0], 0xe3);
        assert_eq!(got[1], 0xb0);
        assert_eq!(got.len(), 32);
    }

    #[test]
    fn hash_pair_is_noncommutative() {
        let a = sha256(b"left");
        let b = sha256(b"right");
        assert_ne!(hash_pair(&a, &b), hash_pair(&b, &a));
    }

    #[test]
    fn domain_hash_differs_from_plain() {
        assert_ne!(sha256(b"data"), domain_hash(b"DOMAIN", b"data"));
    }

    #[test]
    fn domain_hash_different_domains_differ() {
        assert_ne!(
            domain_hash(b"DOMAIN-A", b"data"),
            domain_hash(b"DOMAIN-B", b"data")
        );
    }

    #[test]
    fn nullifier_is_deterministic() {
        let sk = [0x42u8; 32];
        let id = sha256(b"utxo");
        assert_eq!(compute_nullifier(&sk, &id), compute_nullifier(&sk, &id));
    }

    #[test]
    fn nullifier_depends_on_inputs() {
        let sk1 = [0x01u8; 32];
        let sk2 = [0x02u8; 32];
        let id  = sha256(b"utxo");
        assert_ne!(compute_nullifier(&sk1, &id), compute_nullifier(&sk2, &id));
    }
}
RUST

# =============================================================================
# FILE: indra-crypto/src/hybrid.rs
# =============================================================================

cat > indra-crypto/src/hybrid.rs << 'RUST'
//! Hybrid signature scheme: Ed25519 (classical) + Dilithium2 (post-quantum).
//!
//! Both schemes must verify for any signature to be accepted.

use ed25519_dalek::{
    Signature as Ed25519Sig, SigningKey, VerifyingKey, Signer, Verifier,
};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{PublicKey as PqPubKeyTrait, SignedMessage};

use crate::error::{CryptoError, CryptoResult};

// ── Ed25519 ───────────────────────────────────────────────────────────────────

/// An Ed25519 public key (32 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassicalPublicKey(pub [u8; 32]);

/// An Ed25519 signature (64 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassicalSignature(pub [u8; 64]);

/// An Ed25519 signing keypair.
pub struct ClassicalKeypair(SigningKey);

impl ClassicalKeypair {
    /// Create from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// Return the corresponding public key.
    pub fn public_key(&self) -> ClassicalPublicKey {
        ClassicalPublicKey(self.0.verifying_key().to_bytes())
    }

    /// Sign a message (deterministic per RFC 8032).
    pub fn sign(&self, message: &[u8]) -> ClassicalSignature {
        ClassicalSignature(self.0.sign(message).to_bytes())
    }
}

/// Verify an Ed25519 signature.
pub fn verify_classical(
    message: &[u8],
    sig: &ClassicalSignature,
    pk: &ClassicalPublicKey,
) -> CryptoResult<()> {
    let vk = VerifyingKey::from_bytes(&pk.0)
        .map_err(|_| CryptoError::MalformedPublicKey { scheme: "Ed25519", actual: 32 })?;
    let ed_sig = Ed25519Sig::from_bytes(&sig.0);
    vk.verify(message, &ed_sig)
        .map_err(|_| CryptoError::ClassicalVerifyFailed)
}

// ── Dilithium2 ────────────────────────────────────────────────────────────────

/// A Dilithium2 public key (~1312 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqPublicKey(pub Vec<u8>);

/// A Dilithium2 detached signature (~2420 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqSignature(pub Vec<u8>);

/// A Dilithium2 signing keypair.
pub struct PqKeypair {
    pk: dilithium2::PublicKey,
    sk: dilithium2::SecretKey,
}

impl PqKeypair {
    /// Generate a new Dilithium2 keypair.
    pub fn generate() -> Self {
        let (pk, sk) = dilithium2::keypair();
        Self { pk, sk }
    }

    /// Return the public key bytes.
    pub fn public_key(&self) -> PqPublicKey {
        PqPublicKey(self.pk.as_bytes().to_vec())
    }

    /// Sign a message, returning the detached signature.
    pub fn sign(&self, message: &[u8]) -> PqSignature {
        let sm = dilithium2::sign(message, &self.sk);
        let sig_len = dilithium2::signature_bytes();
        PqSignature(sm.as_bytes()[..sig_len].to_vec())
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

    let sig_len = dilithium2::signature_bytes();
    if sig.0.len() != sig_len {
        return Err(CryptoError::MalformedSignature {
            scheme: "Dilithium2",
            actual: sig.0.len(),
        });
    }
    // Reconstruct signed-message format: sig || message
    let mut combined = sig.0.clone();
    combined.extend_from_slice(message);

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
    /// Ed25519 component.
    pub classical: ClassicalPublicKey,
    /// Dilithium2 component.
    pub pq: PqPublicKey,
}

/// A hybrid signature: Ed25519 + Dilithium2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridSignature {
    /// Ed25519 component.
    pub classical: ClassicalSignature,
    /// Dilithium2 component.
    pub pq: PqSignature,
}

/// A hybrid signing keypair.
pub struct HybridKeypair {
    /// Classical (Ed25519) component.
    pub classical: ClassicalKeypair,
    /// Post-quantum (Dilithium2) component.
    pub pq: PqKeypair,
}

impl HybridKeypair {
    /// Create from a 32-byte Ed25519 seed with a fresh Dilithium2 keypair.
    pub fn from_seed(classical_seed: &[u8; 32]) -> Self {
        Self {
            classical: ClassicalKeypair::from_seed(classical_seed),
            pq: PqKeypair::generate(),
        }
    }

    /// Return the hybrid public key.
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            classical: self.classical.public_key(),
            pq: self.pq.public_key(),
        }
    }

    /// Sign a message with both schemes.
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        HybridSignature {
            classical: self.classical.sign(message),
            pq: self.pq.sign(message),
        }
    }
}

/// Verify a hybrid signature. Both components must pass.
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

    fn kp() -> HybridKeypair { HybridKeypair::from_seed(&[0x42u8; 32]) }

    #[test]
    fn classical_roundtrip() {
        let kp = ClassicalKeypair::from_seed(&[0x01u8; 32]);
        let sig = kp.sign(b"INDRA test");
        assert!(verify_classical(b"INDRA test", &sig, &kp.public_key()).is_ok());
    }

    #[test]
    fn classical_wrong_message_fails() {
        let kp = ClassicalKeypair::from_seed(&[0x02u8; 32]);
        let sig = kp.sign(b"correct");
        assert!(verify_classical(b"wrong", &sig, &kp.public_key()).is_err());
    }

    #[test]
    fn classical_wrong_key_fails() {
        let kp1 = ClassicalKeypair::from_seed(&[0x03u8; 32]);
        let kp2 = ClassicalKeypair::from_seed(&[0x04u8; 32]);
        let sig = kp1.sign(b"test");
        assert!(verify_classical(b"test", &sig, &kp2.public_key()).is_err());
    }

    #[test]
    fn pq_roundtrip() {
        let kp = PqKeypair::generate();
        let sig = kp.sign(b"INDRA PQ test");
        assert!(verify_pq(b"INDRA PQ test", &sig, &kp.public_key()).is_ok());
    }

    #[test]
    fn pq_wrong_message_fails() {
        let kp = PqKeypair::generate();
        let sig = kp.sign(b"correct");
        assert!(verify_pq(b"wrong", &sig, &kp.public_key()).is_err());
    }

    #[test]
    fn hybrid_roundtrip() {
        let kp = kp();
        let sig = kp.sign(b"hybrid test");
        assert!(verify_hybrid(b"hybrid test", &sig, &kp.public_key()).is_ok());
    }

    #[test]
    fn hybrid_wrong_message_fails() {
        let kp = kp();
        let sig = kp.sign(b"signed");
        assert!(verify_hybrid(b"different", &sig, &kp.public_key()).is_err());
    }

    #[test]
    fn hybrid_tampered_classical_fails() {
        let kp = kp();
        let mut sig = kp.sign(b"tamper");
        sig.classical.0[0] ^= 0xFF;
        assert!(verify_hybrid(b"tamper", &sig, &kp.public_key()).is_err());
    }

    #[test]
    fn hybrid_tampered_pq_fails() {
        let kp = kp();
        let mut sig = kp.sign(b"tamper pq");
        if let Some(b) = sig.pq.0.first_mut() { *b ^= 0xFF; }
        assert!(verify_hybrid(b"tamper pq", &sig, &kp.public_key()).is_err());
    }
}
RUST

# =============================================================================
# FILE: indra-crypto/src/bls.rs
# =============================================================================

cat > indra-crypto/src/bls.rs << 'RUST'
//! BLS12-381 aggregate signatures for Quorum Certificates.
//!
//! N validator signatures collapse to 96 bytes total.

use blst::min_pk::{PublicKey, SecretKey, Signature, AggregateSignature};
use blst::BLST_ERROR;

use crate::error::{CryptoError, CryptoResult};

/// Domain Separation Tag.
const DST: &[u8] = b"INDRA-BLS12381-G2-SHA256-v1";

/// A BLS12-381 public key (48 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlsPublicKey(pub [u8; 48]);

/// A single BLS12-381 signature (96 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlsSignature(pub Vec<u8>);

/// An aggregated BLS12-381 signature (96 bytes, covers N signers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlsAggregateSignature(pub Vec<u8>);

/// A BLS12-381 signing keypair.
pub struct BlsKeypair {
    sk: SecretKey,
    pk: PublicKey,
}

impl BlsKeypair {
    /// Create from a 32-byte IKM seed.
    pub fn from_seed(seed: &[u8; 32]) -> CryptoResult<Self> {
        let sk = SecretKey::key_gen(seed, &[])
            .map_err(|_| CryptoError::BlsFailed { detail: "key_gen failed" })?;
        let pk = sk.sk_to_pk();
        Ok(Self { sk, pk })
    }

    /// Return the public key.
    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey(self.pk.to_bytes())
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        BlsSignature(self.sk.sign(message, DST, &[]).to_bytes().to_vec())
    }
}

/// Aggregate multiple BLS signatures into one.
pub fn aggregate_signatures(sigs: &[BlsSignature]) -> CryptoResult<BlsAggregateSignature> {
    if sigs.is_empty() {
        return Err(CryptoError::EmptySignerSet);
    }
    let parsed: Vec<Signature> = sigs.iter()
        .map(|s| Signature::from_bytes(&s.0)
            .map_err(|_| CryptoError::MalformedSignature {
                scheme: "BLS12-381",
                actual: s.0.len(),
            }))
        .collect::<CryptoResult<_>>()?;

    let refs: Vec<&Signature> = parsed.iter().collect();
    let agg = AggregateSignature::aggregate(&refs, true)
        .map_err(|_| CryptoError::BlsFailed { detail: "aggregation failed" })?;

    Ok(BlsAggregateSignature(agg.to_signature().to_bytes().to_vec()))
}

/// Verify an aggregated BLS signature against multiple public keys.
pub fn verify_aggregate(
    message: &[u8],
    agg_sig: &BlsAggregateSignature,
    public_keys: &[BlsPublicKey],
) -> CryptoResult<()> {
    if public_keys.is_empty() {
        return Err(CryptoError::EmptySignerSet);
    }
    let sig = Signature::from_bytes(&agg_sig.0)
        .map_err(|_| CryptoError::MalformedSignature {
            scheme: "BLS12-381 aggregate",
            actual: agg_sig.0.len(),
        })?;

    let parsed_pks: Vec<PublicKey> = public_keys.iter()
        .map(|pk| PublicKey::from_bytes(&pk.0)
            .map_err(|_| CryptoError::MalformedPublicKey {
                scheme: "BLS12-381",
                actual: pk.0.len(),
            }))
        .collect::<CryptoResult<_>>()?;

    let pk_refs: Vec<&PublicKey> = parsed_pks.iter().collect();
    let msgs: Vec<&[u8]> = vec![message; pk_refs.len()];

    match sig.aggregate_verify(true, &msgs, DST, &pk_refs, true) {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err(CryptoError::BlsFailed { detail: "aggregate_verify failed" }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(b: u8) -> BlsKeypair { BlsKeypair::from_seed(&[b; 32]).unwrap() }

    #[test]
    fn single_sign_verify() {
        let k = kp(1);
        let msg = b"INDRA QC test";
        let agg = aggregate_signatures(&[k.sign(msg)]).unwrap();
        assert!(verify_aggregate(msg, &agg, &[k.public_key()]).is_ok());
    }

    #[test]
    fn multi_signer_aggregate() {
        let (k1, k2, k3) = (kp(1), kp(2), kp(3));
        let msg = b"consensus message";
        let agg = aggregate_signatures(&[k1.sign(msg), k2.sign(msg), k3.sign(msg)]).unwrap();
        assert!(verify_aggregate(msg, &agg, &[k1.public_key(), k2.public_key(), k3.public_key()]).is_ok());
    }

    #[test]
    fn wrong_message_fails() {
        let k = kp(10);
        let agg = aggregate_signatures(&[k.sign(b"signed")]).unwrap();
        assert!(verify_aggregate(b"not signed", &agg, &[k.public_key()]).is_err());
    }

    #[test]
    fn empty_signers_errors() {
        assert!(aggregate_signatures(&[]).is_err());
    }

    #[test]
    fn aggregate_is_96_bytes() {
        let k = kp(0xFF);
        let agg = aggregate_signatures(&[k.sign(b"size")]).unwrap();
        assert_eq!(agg.0.len(), 96);
    }
}
RUST

# =============================================================================
# FILE: indra-crypto/src/pedersen.rs
# =============================================================================

cat > indra-crypto/src/pedersen.rs << 'RUST'
//! Pedersen commitments on Ristretto255.
//!
//! C = value * G + blinding * H
//!
//! Properties: hiding, binding, additively homomorphic.
//! G = standard Ristretto255 basepoint.
//! H = hash_to_ristretto255("INDRA-PEDERSEN-H-v1") — no known DL rel to G.

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    constants::RISTRETTO_BASEPOINT_POINT,
};
use sha2::Sha512;

use crate::error::{CryptoError, CryptoResult};

/// The standard Ristretto255 basepoint G (value generator).
pub static GENERATOR_G: std::sync::LazyLock<RistrettoPoint> =
    std::sync::LazyLock::new(|| RISTRETTO_BASEPOINT_POINT);

/// The second generator H (blinding generator).
pub static GENERATOR_H: std::sync::LazyLock<RistrettoPoint> =
    std::sync::LazyLock::new(|| {
        RistrettoPoint::hash_from_bytes::<Sha512>(b"INDRA-PEDERSEN-H-v1")
    });

/// A Pedersen commitment: a compressed Ristretto255 point (32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PedersenCommitment(pub [u8; 32]);

impl PedersenCommitment {
    /// The identity (zero) commitment.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Decompress to a RistrettoPoint for arithmetic.
    pub fn decompress(&self) -> CryptoResult<RistrettoPoint> {
        CompressedRistretto(self.0)
            .decompress()
            .ok_or(CryptoError::InvalidPoint)
    }

    /// Add two commitments homomorphically.
    pub fn add(&self, other: &Self) -> CryptoResult<Self> {
        let a = self.decompress()?;
        let b = other.decompress()?;
        Ok(Self::from_point(&(a + b)))
    }

    /// Subtract two commitments homomorphically.
    pub fn sub(&self, other: &Self) -> CryptoResult<Self> {
        let a = self.decompress()?;
        let b = other.decompress()?;
        Ok(Self::from_point(&(a - b)))
    }

    /// Compress a RistrettoPoint to a PedersenCommitment.
    pub fn from_point(p: &RistrettoPoint) -> Self {
        Self(p.compress().to_bytes())
    }
}

/// The opening of a Pedersen commitment: (value, blinding).
#[derive(Debug, Clone)]
pub struct PedersenOpening {
    /// The committed value.
    pub value: u64,
    /// The blinding factor.
    pub blinding: [u8; 32],
}

/// Compute C = value*G + blinding*H.
pub fn commit(value: u64, blinding: &[u8; 32]) -> PedersenCommitment {
    let v = Scalar::from(value);
    let r = Scalar::from_bytes_mod_order(*blinding);
    let point = v * *GENERATOR_G + r * *GENERATOR_H;
    PedersenCommitment::from_point(&point)
}

/// Verify that a commitment opens correctly.
pub fn verify_opening(
    commitment: &PedersenCommitment,
    opening: &PedersenOpening,
) -> CryptoResult<()> {
    if commit(opening.value, &opening.blinding) == *commitment {
        Ok(())
    } else {
        Err(CryptoError::CommitmentOpeningFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(byte: u8) -> [u8; 32] { [byte; 32] }

    #[test]
    fn commit_and_verify() {
        let c = commit(1000, &b(0x01));
        assert!(verify_opening(&c, &PedersenOpening { value: 1000, blinding: b(0x01) }).is_ok());
    }

    #[test]
    fn wrong_value_fails() {
        let c = commit(1000, &b(0x01));
        assert!(verify_opening(&c, &PedersenOpening { value: 999, blinding: b(0x01) }).is_err());
    }

    #[test]
    fn wrong_blinding_fails() {
        let c = commit(1000, &b(0x01));
        assert!(verify_opening(&c, &PedersenOpening { value: 1000, blinding: b(0x02) }).is_err());
    }

    #[test]
    fn deterministic() {
        assert_eq!(commit(500, &b(0xAA)), commit(500, &b(0xAA)));
    }

    #[test]
    fn different_values_differ() {
        assert_ne!(commit(100, &b(0x01)), commit(101, &b(0x01)));
    }

    #[test]
    fn homomorphic_addition() {
        let r1 = Scalar::from_bytes_mod_order(b(0x01));
        let r2 = Scalar::from_bytes_mod_order(b(0x02));
        let c1 = commit(100, &r1.to_bytes());
        let c2 = commit(200, &r2.to_bytes());
        let c_sum = c1.add(&c2).unwrap();
        let r_sum = (r1 + r2).to_bytes();
        assert_eq!(c_sum, commit(300, &r_sum));
    }

    #[test]
    fn homomorphic_subtraction() {
        let r1 = Scalar::from_bytes_mod_order(b(0x05));
        let r2 = Scalar::from_bytes_mod_order(b(0x02));
        let c1 = commit(500, &r1.to_bytes());
        let c2 = commit(200, &r2.to_bytes());
        let c_diff = c1.sub(&c2).unwrap();
        let r_diff = (r1 - r2).to_bytes();
        assert_eq!(c_diff, commit(300, &r_diff));
    }
}
RUST

# =============================================================================
# FILE: indra-crypto/src/commitment.rs
# =============================================================================

cat > indra-crypto/src/commitment.rs << 'RUST'
//! Commitment balance verification.
//!
//! Verifies: sum(input_commitments) == sum(output_commitments) + fee_commitment
//!
//! This is the core privacy invariant: value is conserved without
//! revealing any individual amounts.

use crate::{
    error::{CryptoError, CryptoResult},
    pedersen::PedersenCommitment,
};

/// Verify the commitment balance equation.
///
/// Returns Ok(()) if sum(inputs) == sum(outputs) + fee.
pub fn verify_balance(
    input_commitments: &[PedersenCommitment],
    output_commitments: &[PedersenCommitment],
    fee_commitment: &PedersenCommitment,
) -> CryptoResult<()> {
    let mut input_sum = PedersenCommitment::ZERO;
    for c in input_commitments {
        input_sum = input_sum.add(c)?;
    }

    let mut output_sum = PedersenCommitment::ZERO;
    for c in output_commitments {
        output_sum = output_sum.add(c)?;
    }
    output_sum = output_sum.add(fee_commitment)?;

    if input_sum == output_sum {
        Ok(())
    } else {
        Err(CryptoError::CommitmentBalanceFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pedersen::commit;
    use curve25519_dalek::scalar::Scalar;

    #[test]
    fn balanced_transaction_passes() {
        let r_out = Scalar::from_bytes_mod_order([0x01u8; 32]);
        let r_fee = Scalar::from_bytes_mod_order([0x02u8; 32]);
        let r_in  = r_out + r_fee;
        assert!(verify_balance(
            &[commit(1000, &r_in.to_bytes())],
            &[commit(900,  &r_out.to_bytes())],
            &commit(100,   &r_fee.to_bytes()),
        ).is_ok());
    }

    #[test]
    fn unbalanced_fails() {
        assert!(verify_balance(
            &[commit(1000, &[0x01u8; 32])],
            &[commit(800,  &[0x02u8; 32])],
            &commit(100,   &[0x03u8; 32]),
        ).is_err());
    }

    #[test]
    fn multi_input_multi_output() {
        let r_in1  = Scalar::from_bytes_mod_order([0x01u8; 32]);
        let r_in2  = Scalar::from_bytes_mod_order([0x02u8; 32]);
        let r_out1 = Scalar::from_bytes_mod_order([0x03u8; 32]);
        let r_out2 = Scalar::from_bytes_mod_order([0x04u8; 32]);
        let r_fee  = r_in1 + r_in2 - r_out1 - r_out2;
        assert!(verify_balance(
            &[commit(600, &r_in1.to_bytes()), commit(400, &r_in2.to_bytes())],
            &[commit(700, &r_out1.to_bytes()), commit(250, &r_out2.to_bytes())],
            &commit(50, &r_fee.to_bytes()),
        ).is_ok());
    }

    #[test]
    fn zero_fee_balanced() {
        let r = Scalar::from_bytes_mod_order([0x10u8; 32]);
        assert!(verify_balance(
            &[commit(500, &r.to_bytes())],
            &[commit(500, &r.to_bytes())],
            &commit(0, &Scalar::ZERO.to_bytes()),
        ).is_ok());
    }
}
RUST

# =============================================================================
# FILE: indra-crypto/src/vrf.rs
# =============================================================================

cat > indra-crypto/src/vrf.rs << 'RUST'
//! VRF (Verifiable Random Function) — proposer election.
//!
//! Phase 3: deterministic stub with correct interface.
//! Phase 4: full ECVRF-RISTRETTO255-SHA512 per RFC 9381.

use crate::error::{CryptoError, CryptoResult};
use crate::hash::sha256;

/// VRF output: 32 bytes of pseudorandom data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfOutput(pub [u8; 32]);

/// VRF proof: allows others to verify the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfProof(pub Vec<u8>);

/// A VRF keypair.
pub struct VrfKeypair {
    secret_key: [u8; 32],
    public_key: [u8; 32],
}

impl VrfKeypair {
    /// Create from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self { secret_key: *seed, public_key: sha256(seed) }
    }

    /// Return the public key bytes.
    pub fn public_key(&self) -> [u8; 32] { self.public_key }
}

/// Compute a VRF output and proof.
/// STUB: output = SHA-256(sk || input). Full impl uses ECVRF.
pub fn vrf_prove(keypair: &VrfKeypair, input: &[u8]) -> (VrfOutput, VrfProof) {
    let mut data = keypair.secret_key.to_vec();
    data.extend_from_slice(input);
    let output = sha256(&data);

    let mut proof = sha256(&[&output[..], input].concat()).to_vec();
    proof.extend_from_slice(&sha256(&[&output[..], b"proof"].concat()));

    (VrfOutput(output), VrfProof(proof))
}

/// Verify a VRF output and proof.
/// STUB: checks structural consistency. Full impl verifies EC proof.
pub fn vrf_verify(
    _public_key: &[u8; 32],
    input: &[u8],
    output: &VrfOutput,
    proof: &VrfProof,
) -> CryptoResult<()> {
    if proof.0.len() != 64 {
        return Err(CryptoError::VrfProofFailed);
    }
    let expected = sha256(&[&output.0[..], input].concat());
    if proof.0[..32] != expected {
        return Err(CryptoError::VrfProofFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_verify_roundtrip() {
        let kp = VrfKeypair::from_seed(&[0x42u8; 32]);
        let (out, proof) = vrf_prove(&kp, b"epoch seed");
        assert!(vrf_verify(&kp.public_key(), b"epoch seed", &out, &proof).is_ok());
    }

    #[test]
    fn deterministic() {
        let kp = VrfKeypair::from_seed(&[0x55u8; 32]);
        let (o1, _) = vrf_prove(&kp, b"input");
        let (o2, _) = vrf_prove(&kp, b"input");
        assert_eq!(o1, o2);
    }

    #[test]
    fn different_inputs_different_outputs() {
        let kp = VrfKeypair::from_seed(&[0x77u8; 32]);
        let (o1, _) = vrf_prove(&kp, b"A");
        let (o2, _) = vrf_prove(&kp, b"B");
        assert_ne!(o1, o2);
    }

    #[test]
    fn wrong_output_fails() {
        let kp = VrfKeypair::from_seed(&[0xABu8; 32]);
        let (_, proof) = vrf_prove(&kp, b"input");
        assert!(vrf_verify(&kp.public_key(), b"input", &VrfOutput([0xFF; 32]), &proof).is_err());
    }

    #[test]
    fn wrong_proof_fails() {
        let kp = VrfKeypair::from_seed(&[0xCDu8; 32]);
        let (output, _) = vrf_prove(&kp, b"input");
        assert!(vrf_verify(&kp.public_key(), b"input", &output, &VrfProof(vec![0xFF; 64])).is_err());
    }
}
RUST

# =============================================================================
# FILE: indra-state/src/verify.rs
# =============================================================================

cat > indra-state/src/verify.rs << 'RUST'
//! Cryptographic verification hooks for the state machine.
//!
//! Bridges indra-crypto into the block application loop.
//!
//! ## Verified in Phase 3
//! - Hybrid signature on each transaction
//! - Commitment balance: sum(inputs) == sum(outputs) + fee
//!
//! ## Stubbed for Phase 4
//! - Range proofs (Bulletproofs)
//! - VRF proof on block header
//! - BLS QC aggregate signature

use indra_core::{
    codec::Encode,
    types::{
        crypto::CommitmentV1,
        transaction::TransactionV1,
    },
};
use indra_crypto::{
    commitment::verify_balance,
    error::{CryptoError, CryptoResult},
    hybrid::{
        verify_hybrid,
        ClassicalPublicKey, ClassicalSignature,
        HybridPublicKey, HybridSignature,
        PqPublicKey, PqSignature,
    },
    pedersen::PedersenCommitment,
};

fn to_pedersen(c: &CommitmentV1) -> PedersenCommitment {
    PedersenCommitment(c.compressed_point.0)
}

/// Produce the canonical bytes a transaction signature covers.
///
/// Domain-separated to prevent cross-context reuse.
pub fn transaction_signing_bytes(tx: &TransactionV1) -> Vec<u8> {
    use indra_crypto::hash::domains::TX_SIGN;
    let mut buf = TX_SIGN.to_vec();
    tx.version.encode(&mut buf);
    tx.signature_module_id.encode(&mut buf);
    indra_core::codec::encode_list(&tx.inputs, &mut buf);
    indra_core::codec::encode_list(&tx.outputs, &mut buf);
    tx.fee_amount.encode(&mut buf);
    tx.fee_blinding.encode(&mut buf);
    tx.fee_commitment.encode(&mut buf);
    buf
}

/// Verify the hybrid signature on a transaction.
pub fn verify_transaction_signature(
    tx: &TransactionV1,
    signer_pubkey_classical: &[u8; 32],
    signer_pubkey_pq: &[u8],
) -> CryptoResult<()> {
    let signing_bytes = transaction_signing_bytes(tx);
    let pk = HybridPublicKey {
        classical: ClassicalPublicKey(*signer_pubkey_classical),
        pq: PqPublicKey(signer_pubkey_pq.to_vec()),
    };
    let sig_classical: [u8; 64] = tx.signature.classical_sig.as_slice()
        .try_into()
        .map_err(|_| CryptoError::MalformedSignature {
            scheme: "Ed25519",
            actual: tx.signature.classical_sig.len(),
        })?;
    let sig = HybridSignature {
        classical: ClassicalSignature(sig_classical),
        pq: PqSignature(tx.signature.pq_sig.as_slice().to_vec()),
    };
    verify_hybrid(&signing_bytes, &sig, &pk)
}

/// Verify the commitment balance equation for a transaction.
pub fn verify_transaction_balance(
    input_commitments: &[CommitmentV1],
    output_commitments: &[CommitmentV1],
    fee_commitment: &CommitmentV1,
) -> CryptoResult<()> {
    let inputs:  Vec<PedersenCommitment> = input_commitments.iter().map(to_pedersen).collect();
    let outputs: Vec<PedersenCommitment> = output_commitments.iter().map(to_pedersen).collect();
    verify_balance(&inputs, &outputs, &to_pedersen(fee_commitment))
}

/// Verify a VRF proof on a block header.
/// TODO Phase 4: full ECVRF-RISTRETTO255-SHA512.
pub fn verify_block_vrf(
    _proposer_pubkey: &[u8; 32],
    _epoch_seed: &[u8; 32],
    _vrf_output: &[u8; 32],
    vrf_proof: &[u8],
) -> CryptoResult<()> {
    if vrf_proof.is_empty() {
        return Err(CryptoError::VrfProofFailed);
    }
    Ok(())
}

/// Verify the BLS aggregate signature in a Quorum Certificate.
/// TODO Phase 4: full BLS QC verification.
pub fn verify_qc_bls(
    _block_hash: &[u8; 32],
    _agg_sig: &[u8],
    _validator_public_keys: &[[u8; 48]],
) -> CryptoResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        Bytes32, CommitmentV1, HybridPubKey, ProtocolVersion, VariableBytes,
        types::transaction::{InputV1, OutputV1, TransactionV1},
        types::crypto::HybridSignature as CoreHybridSignature,
    };
    use indra_crypto::{
        hybrid::HybridKeypair,
        pedersen::commit,
    };
    use curve25519_dalek::scalar::Scalar;

    fn make_signed_tx(kp: &HybridKeypair) -> TransactionV1 {
        let classical_pk = kp.public_key().classical.0;
        let pq_pk_bytes  = kp.public_key().pq.0.clone();

        let mut tx = TransactionV1 {
            version: ProtocolVersion::CURRENT,
            signature_module_id: 1,
            inputs: vec![InputV1 {
                utxo_id:   Bytes32::from([0x01u8; 32]),
                nullifier: Bytes32::from([0x02u8; 32]),
            }],
            outputs: vec![OutputV1 {
                commitment:   CommitmentV1 { compressed_point: Bytes32::from([0x03u8; 32]) },
                owner_pubkey: HybridPubKey {
                    classical_pk: Bytes32::from(classical_pk),
                    pq_pk: VariableBytes::from_slice(&pq_pk_bytes).unwrap(),
                },
                range_proof:  VariableBytes::from_slice(&[0u8; 32]).unwrap(),
                lock_height:  0,
            }],
            fee_amount:     1_000,
            fee_blinding:   Bytes32::ZERO,
            fee_commitment: CommitmentV1 { compressed_point: Bytes32::ZERO },
            signature: CoreHybridSignature {
                classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                pq_sig:        VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            },
        };

        let signing_bytes = transaction_signing_bytes(&tx);
        let sig = kp.sign(&signing_bytes);

        tx.signature = CoreHybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig:        VariableBytes::from_slice(&sig.pq.0).unwrap(),
        };
        tx
    }

    #[test]
    fn valid_signature_passes() {
        let kp = HybridKeypair::from_seed(&[0x42u8; 32]);
        let tx = make_signed_tx(&kp);
        let pk = kp.public_key();
        assert!(verify_transaction_signature(&tx, &pk.classical.0, &pk.pq.0).is_ok());
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = HybridKeypair::from_seed(&[0x42u8; 32]);
        let kp2 = HybridKeypair::from_seed(&[0x99u8; 32]);
        let tx  = make_signed_tx(&kp1);
        let pk2 = kp2.public_key();
        assert!(verify_transaction_signature(&tx, &pk2.classical.0, &pk2.pq.0).is_err());
    }

    #[test]
    fn tampered_fee_fails() {
        let kp = HybridKeypair::from_seed(&[0x33u8; 32]);
        let mut tx = make_signed_tx(&kp);
        tx.fee_amount += 1;
        let pk = kp.public_key();
        assert!(verify_transaction_signature(&tx, &pk.classical.0, &pk.pq.0).is_err());
    }

    #[test]
    fn balanced_commitments_pass() {
        let r_out = Scalar::from_bytes_mod_order([0x01u8; 32]);
        let r_fee = Scalar::from_bytes_mod_order([0x02u8; 32]);
        let r_in  = r_out + r_fee;
        let c_in  = CommitmentV1 { compressed_point: Bytes32::from(commit(1000, &r_in.to_bytes()).0)  };
        let c_out = CommitmentV1 { compressed_point: Bytes32::from(commit(900,  &r_out.to_bytes()).0) };
        let c_fee = CommitmentV1 { compressed_point: Bytes32::from(commit(100,  &r_fee.to_bytes()).0) };
        assert!(verify_transaction_balance(&[c_in], &[c_out], &c_fee).is_ok());
    }

    #[test]
    fn unbalanced_commitments_fail() {
        let c_in  = CommitmentV1 { compressed_point: Bytes32::from(commit(1000, &[0x01u8; 32]).0) };
        let c_out = CommitmentV1 { compressed_point: Bytes32::from(commit(800,  &[0x02u8; 32]).0) };
        let c_fee = CommitmentV1 { compressed_point: Bytes32::from(commit(100,  &[0x03u8; 32]).0) };
        assert!(verify_transaction_balance(&[c_in], &[c_out], &c_fee).is_err());
    }
}
RUST

# =============================================================================
# Update indra-state/src/lib.rs to expose verify module
# =============================================================================

cat > indra-state/src/lib.rs << 'RUST'
//! # indra-state — INDRA v2 State Machine
//!
//! Phase 3 adds cryptographic verification: hybrid signatures,
//! Pedersen commitment balance, VRF and QC stubs.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::indexing_slicing)]

pub mod error;
pub mod utxo;
pub mod nullifier;
pub mod validator;
pub mod chain;
pub mod apply;
pub mod fee;
pub mod epoch;
pub mod verify;

pub use error::{StateError, StateResult};
pub use utxo::{UtxoSet, UtxoEntry};
pub use nullifier::NullifierSet;
pub use validator::{ValidatorEntry, ValidatorSet, ValidatorStatus};
pub use chain::ChainState;
pub use apply::apply_block;
pub use fee::compute_next_base_fee;
pub use epoch::apply_epoch_transition;
RUST

echo ""
echo "✓ INDRA Phase 3 files written."
echo ""
echo "New crate: indra-crypto (fully populated)"
echo "  src/lib.rs, error.rs, hash.rs, hybrid.rs, bls.rs"
echo "  src/pedersen.rs, commitment.rs, vrf.rs"
echo ""
echo "Updated: indra-state"
echo "  src/verify.rs — crypto hooks for block application"
echo ""
echo "Now run:"
echo "  cargo build"
echo "  cargo test"
echo ""