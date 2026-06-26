//! SPHINCS+-SHA2-128s — optional post-quantum signature scheme.
//!
//! ## When to use SPHINCS+ vs Dilithium2
//!
//! | Use case                    | Scheme     | Reason                          |
//! |-----------------------------|------------|---------------------------------|
//! | Vote signatures             | Dilithium2 | Fast, compact                   |
//! | Transaction signatures      | Dilithium2 | Fast, compact                   |
//! | Land record certificates    | SPHINCS+   | Hash-based, 30yr track record   |
//! | Legal document signatures   | SPHINCS+   | Quantum-safe for 50+ years      |
//! | Validator registration      | SPHINCS+   | Done once, stored once          |
//!
//! ## Signature sizes
//!
//! | Scheme     | Sig size  | Sign time | Verify time |
//! |------------|-----------|-----------|-------------|
//! | Dilithium2 | 2,420 B   | ~0.5ms    | ~0.3ms      |
//! | SPHINCS+   | 7,856 B   | ~50ms     | ~2ms        |
//!
//! ## Usage
//!
//! SPHINCS+ is activated by setting `signature_module_id = 2` in a
//! TransactionV1. The node validates using the appropriate scheme
//! based on this field.
//!
//! ## Feature flag
//!
//! This module is gated behind the `sphincs` feature flag:
//!   cargo build -p indra-crypto --features sphincs

#[cfg(feature = "sphincs")]
use pqcrypto_sphincsplus::sphincssha2128ssimple as sphincs;
#[cfg(feature = "sphincs")]
use pqcrypto_traits::sign::{PublicKey, SecretKey, DetachedSignature};

use crate::error::{CryptoError, CryptoResult};

/// SPHINCS+-SHA2-128s public key size in bytes.
pub const SPHINCS_PK_BYTES: usize = 32;
/// SPHINCS+-SHA2-128s secret key size in bytes.
pub const SPHINCS_SK_BYTES: usize = 64;
/// SPHINCS+-SHA2-128s signature size in bytes.
pub const SPHINCS_SIG_BYTES: usize = 7_856;

/// A SPHINCS+ keypair for long-lived document signatures.
pub struct SphincsKeypair {
    /// Public key bytes (32 bytes).
    pub public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl SphincsKeypair {
    /// Generate a new random SPHINCS+ keypair.
    #[cfg(feature = "sphincs")]
    pub fn generate() -> Self {
        let (pk, sk) = sphincs::keypair();
        Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        }
    }

    /// Generate a stub keypair when sphincs feature is not enabled.
    #[cfg(not(feature = "sphincs"))]
    pub fn generate() -> Self {
        Self {
            public_key: vec![0u8; SPHINCS_PK_BYTES],
            secret_key: vec![0u8; SPHINCS_SK_BYTES],
        }
    }

    /// Sign a message with SPHINCS+.
    #[cfg(feature = "sphincs")]
    pub fn sign(&self, message: &[u8]) -> CryptoResult<Vec<u8>> {
        let sk = sphincs::SecretKey::from_bytes(&self.secret_key)
            .map_err(|_| CryptoError::MalformedSignature {
                scheme: "SPHINCS+",
                actual: self.secret_key.len(),
            })?;
        let sig = sphincs::detached_sign(message, &sk);
        Ok(sig.as_bytes().to_vec())
    }

    /// Sign stub when sphincs feature not enabled.
    #[cfg(not(feature = "sphincs"))]
    pub fn sign(&self, _message: &[u8]) -> CryptoResult<Vec<u8>> {
        Err(CryptoError::MalformedSignature {
            scheme: "SPHINCS+ (feature not enabled — rebuild with --features sphincs)",
            actual: 0,
        })
    }
}

/// Verify a SPHINCS+ signature.
#[cfg(feature = "sphincs")]
pub fn verify_sphincs(message: &[u8], signature: &[u8], public_key: &[u8]) -> CryptoResult<()> {
    let pk = sphincs::PublicKey::from_bytes(public_key)
        .map_err(|_| CryptoError::MalformedPublicKey {
            scheme: "SPHINCS+",
            actual: public_key.len(),
        })?;
    let sig = sphincs::DetachedSignature::from_bytes(signature)
        .map_err(|_| CryptoError::MalformedSignature {
            scheme: "SPHINCS+",
            actual: signature.len(),
        })?;
    sphincs::verify_detached_signature(&sig, message, &pk)
        .map_err(|_| CryptoError::PqVerifyFailed)
}

/// Verify stub when sphincs feature not enabled.
#[cfg(not(feature = "sphincs"))]
pub fn verify_sphincs(_message: &[u8], _signature: &[u8], _public_key: &[u8]) -> CryptoResult<()> {
    Err(CryptoError::PqVerifyFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "sphincs")]
    fn sphincs_roundtrip() {
        let kp = SphincsKeypair::generate();
        let msg = b"Land record certificate - Plot 42, Survey 123";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), SPHINCS_SIG_BYTES);
        assert!(verify_sphincs(msg, &sig, &kp.public_key).is_ok());
    }

    #[test]
    #[cfg(feature = "sphincs")]
    fn sphincs_wrong_message_fails() {
        let kp = SphincsKeypair::generate();
        let sig = kp.sign(b"original message").unwrap();
        assert!(verify_sphincs(b"tampered message", &sig, &kp.public_key).is_err());
    }

    #[test]
    fn sphincs_constants_correct() {
        assert_eq!(SPHINCS_PK_BYTES, 32);
        assert_eq!(SPHINCS_SIG_BYTES, 7_856);
    }

    #[test]
    #[cfg(not(feature = "sphincs"))]
    fn sphincs_stub_returns_error() {
        let kp = SphincsKeypair::generate();
        assert!(kp.sign(b"test").is_err());
    }
}
