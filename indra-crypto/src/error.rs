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

    /// Pedersen commitment opening verification failed.
    #[error("Pedersen commitment opening failed")]
    CommitmentOpeningFailed,

    /// Commitment balance check failed.
    #[error("commitment balance failed: inputs do not equal outputs plus fee")]
    CommitmentBalanceFailed,

    /// VRF proof verification failed.
    #[error("VRF proof verification failed")]
    VrfProofFailed,

    /// BLS aggregation requires at least one signer.
    #[error("BLS aggregation requires at least one signer")]
    EmptySignerSet,

    /// Invalid or malformed BIP-39 mnemonic phrase.
    #[error("invalid BIP-39 mnemonic phrase")]
    InvalidMnemonic,
}

/// Convenience alias.
pub type CryptoResult<T> = Result<T, CryptoError>;
