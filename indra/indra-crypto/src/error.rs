//! Error types for the INDRA cryptographic layer.

use thiserror::Error;

/// All errors that can occur in the INDRA cryptographic layer.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum CryptoError {
    /// Ed25519 signature verification failed.
    #[error("Ed25519 signature verification failed")]
    ClassicalVerifyFailed,

    /// ML-DSA-87 signature verification failed.
    #[error("ML-DSA-87 signature verification failed")]
    PqVerifyFailed,

    /// A complete hot or cold hybrid signature was absent.
    #[error("missing complete {role} hybrid signature")]
    MissingHybridSignature {
        /// The missing authorization role.
        role: &'static str,
    },

    /// A public key had the wrong length or was malformed.
    #[error("malformed public key for {scheme}: got {actual} bytes")]
    MalformedPublicKey {
        /// Which scheme.
        scheme: &'static str,
        /// Actual size received.
        actual: usize,
    },

    /// A signature had the wrong length or was malformed.
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

    /// VRF proof verification failed.
    #[error("VRF proof verification failed")]
    VrfProofFailed,

    /// Invalid or malformed BIP-39 mnemonic phrase.
    #[error("invalid BIP-39 mnemonic phrase")]
    InvalidMnemonic,

    /// A decoded crypto object had an unsupported version byte.
    #[error("unsupported crypto object version {version} for {scheme}")]
    UnsupportedVersion {
        /// Which scheme.
        scheme: &'static str,
        /// Version found.
        version: u8,
    },

    /// A crypto object had the wrong encoded length.
    #[error("malformed encoded {scheme}: got {actual} bytes")]
    MalformedEncoding {
        /// Which scheme.
        scheme: &'static str,
        /// Actual size received.
        actual: usize,
    },

    /// An encoded input exceeded its protocol limit.
    #[error("KDF input '{field}' length {actual} exceeds maximum {max}")]
    LengthExceeded {
        /// Field name.
        field: &'static str,
        /// Maximum allowed length.
        max: usize,
        /// Actual length supplied.
        actual: usize,
    },

    /// A payment address failed canonical decoding or validation.
    #[error("invalid payment address: {reason}")]
    InvalidPaymentAddress {
        /// Static validation failure reason.
        reason: &'static str,
    },
}

/// Convenience alias.
pub type CryptoResult<T> = Result<T, CryptoError>;
