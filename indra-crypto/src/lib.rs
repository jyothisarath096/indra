//! INDRA cryptographic primitives.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod constants;
pub mod error;
pub mod hash;
pub mod mnemonic;
pub mod hybrid;
pub mod bls;
pub mod pedersen;
pub mod commitment;
pub mod vrf;

pub use error::{CryptoError, CryptoResult};
pub use indra_bulletproofs::{prove_range, verify_range, BulletproofError, RANGE_PROOF_BYTES};
pub use hash::{sha256, hash_pair, domain_hash};
pub use mnemonic::{
    DerivedSeeds,
    MNEMONIC_WORD_COUNT,
    derive_all_seeds,
    generate_mnemonic,
    mnemonic_to_seed,
    mnemonic_words,
    validate_mnemonic,
};
pub use hybrid::{
    ClassicalKeypair, ClassicalPublicKey, ClassicalSignature,
    PqKeypair, PqPublicKey, PqSignature,
    HybridKeypair, HybridPublicKey, HybridSignature,
    verify_classical, verify_pq, verify_hybrid,
};
pub use bls::{BlsKeypair, BlsPublicKey, BlsSignature, BlsAggregateSignature, aggregate_signatures, verify_aggregate};
pub use pedersen::{PedersenCommitment, PedersenOpening, commit, verify_opening};
pub use commitment::verify_balance;
pub use constants::{CLASSICAL_SIG_BYTES, PQ_PK_BYTES, PQ_SIG_BYTES};
pub use vrf::{VrfKeypair, VrfOutput, VrfProof, vrf_prove, vrf_verify};
