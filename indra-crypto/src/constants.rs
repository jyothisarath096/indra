//! Size constants for all cryptographic types.
//!
//! These are the authoritative sizes. All other code must reference
//! these constants — no magic numbers elsewhere.

/// Ed25519 signature size in bytes.
pub const CLASSICAL_SIG_BYTES: usize = 64;

/// Ed25519 public key size in bytes.
pub const CLASSICAL_PK_BYTES: usize = 32;

/// Dilithium2 signature size in bytes.
/// Actual NIST Dilithium2 signature = 2420 bytes. We keep a small margin.
pub const PQ_SIG_BYTES: usize = 2_500;

/// Dilithium2 public key size in bytes.
/// Actual NIST Dilithium2 public key = 1312 bytes.
pub const PQ_PK_BYTES: usize = 1_400;

/// BLS12-381 aggregate signature size in bytes (G1-compressed point).
pub const BLS_SIG_BYTES: usize = 48;

/// BLS12-381 public key size in bytes (G1-compressed point).
pub const BLS_PK_BYTES: usize = 48;

/// Maximum ECVRF proof size in bytes.
pub const VRF_PROOF_BYTES: usize = 1_024;
