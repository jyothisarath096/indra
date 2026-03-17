//! INDRA cryptographic primitives.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod constants;
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
pub use bls::{BlsKeypair, BlsPublicKey, BlsSignature, BlsAggregateSignature, aggregate_signatures, verify_aggregate};
pub use pedersen::{PedersenCommitment, PedersenOpening, commit, verify_opening};
pub use commitment::verify_balance;
pub use vrf::{VrfKeypair, VrfOutput, VrfProof, vrf_prove, vrf_verify};
