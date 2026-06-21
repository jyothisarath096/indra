//! Error types for indra-bulletproofs.

use alloc::string::String;
use core::fmt;

/// Errors returned by range-proof proving and verification.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BulletproofError {
    /// The range proof failed a verification equation.
    VerificationFailed,

    /// A proof component could not be decoded canonically.
    InvalidEncoding(String),

    /// The proof byte length did not match the expected encoding size.
    InvalidLength {
        /// The actual number of bytes provided.
        actual: usize,
        /// The required number of bytes for this proof type.
        expected: usize,
    },

    /// A caller supplied a value outside the supported range.
    ValueOutOfRange(u128),

    /// The inner-product argument failed verification.
    InnerProductFailed,
}

impl fmt::Display for BulletproofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VerificationFailed => write!(f, "range proof verification failed"),
            Self::InvalidEncoding(message) => write!(f, "invalid proof encoding: {message}"),
            Self::InvalidLength { actual, expected } => {
                write!(
                    f,
                    "proof length {actual} does not match expected {expected}"
                )
            }
            Self::ValueOutOfRange(value) => write!(f, "value {value} is out of range [0, 2^64)"),
            Self::InnerProductFailed => write!(f, "inner product argument verification failed"),
        }
    }
}

impl core::error::Error for BulletproofError {}

/// Convenience result alias for Bulletproof operations.
pub type BulletproofResult<T> = Result<T, BulletproofError>;
