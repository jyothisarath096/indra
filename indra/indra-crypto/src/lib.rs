//! INDRA cryptographic primitives.

#![deny(missing_docs)]
#![deny(unused_must_use)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable, clippy::todo, clippy::unimplemented)]
#![deny(clippy::indexing_slicing)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod constants;
pub mod error;
pub mod hash;
pub mod hybrid;
pub mod mnemonic;
pub mod payment_address;
pub mod vrf;

pub use constants::{CLASSICAL_SIG_BYTES, PQ_PK_BYTES, PQ_SIG_BYTES, PQ_SK_BYTES};
pub use error::{CryptoError, CryptoResult};
pub use hash::{domain_hash, hash_pair, sha256};
pub use hybrid::{
    validate_classical_public_key, validate_pq_public_key, verify_classical, verify_dual_hybrid,
    verify_hybrid, verify_pq, ClassicalKeypair, ClassicalPublicKey, ClassicalSignature,
    ColdHybridKeypair, ColdHybridPublicKey, HybridKeypair, HybridPublicKey, HybridSignature,
    PqKeypair, PqPublicKey, PqSignature,
};
pub use mnemonic::{
    derive_all_seeds, generate_mnemonic, mnemonic_to_seed, mnemonic_words, validate_mnemonic,
    DerivedSeeds, MNEMONIC_WORD_COUNT,
};
pub use payment_address::{
    PaymentAddressV1, MAX_PAYMENT_CHAIN_ID_BYTES, PAYMENT_ADDRESS_TEXT_PREFIX,
    PAYMENT_ADDRESS_VERSION,
};
pub use vrf::{validate_vrf_public_key, vrf_prove, vrf_verify, VrfKeypair, VrfOutput, VrfProof};
