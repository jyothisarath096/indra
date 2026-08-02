//! Size constants for all cryptographic types.
//!
//! These are the authoritative sizes. All other code must reference
//! these constants — no magic numbers elsewhere.

/// Ed25519 signature size in bytes.
pub const CLASSICAL_SIG_BYTES: usize = 64;

/// Ed25519 public key size in bytes.
pub const CLASSICAL_PK_BYTES: usize = 32;

/// ML-DSA-87 signature size in bytes.
pub const PQ_SIG_BYTES: usize = 4_627;

/// ML-DSA-87 verifying key size in bytes.
pub const PQ_PK_BYTES: usize = 2_592;

/// ML-DSA-87 secret key storage size in bytes.
///
/// INDRA stores the canonical 32-byte seed, not the expanded signing key.
pub const PQ_SK_BYTES: usize = 32;

/// Maximum ECVRF proof size in bytes.
pub const VRF_PROOF_BYTES: usize = 1_024;

/// X25519 public key size in bytes.
pub const X25519_PK_BYTES: usize = 32;

/// X25519 static secret key storage size in bytes.
pub const X25519_SK_BYTES: usize = 32;

/// ML-KEM-1024 encapsulation key size in bytes.
pub const ML_KEM_1024_EK_BYTES: usize = 1_568;

/// ML-KEM-1024 ciphertext size in bytes.
pub const ML_KEM_1024_CT_BYTES: usize = 1_568;

/// ML-KEM seed storage size in bytes.
pub const ML_KEM_SEED_BYTES: usize = 64;
