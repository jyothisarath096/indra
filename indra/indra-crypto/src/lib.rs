//! INDRA cryptographic primitives.

#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod bls;
pub mod commitment;
pub mod constants;
pub mod error;
pub mod hash;
pub mod hybrid;
pub mod mnemonic;
pub mod pedersen;
pub mod vrf;

pub use bls::{
    aggregate_signatures, verify_aggregate, BlsAggregateSignature, BlsKeypair, BlsPublicKey,
    BlsSignature,
};
pub use commitment::verify_balance;
pub use constants::{CLASSICAL_SIG_BYTES, PQ_PK_BYTES, PQ_SIG_BYTES, PQ_SK_BYTES};
pub use error::{CryptoError, CryptoResult};
pub use hash::{domain_hash, hash_pair, sha256};
pub use hybrid::{
    verify_classical, verify_hybrid, verify_pq, ClassicalKeypair, ClassicalPublicKey,
    ClassicalSignature, HybridKeypair, HybridPublicKey, HybridSignature, PqKeypair, PqPublicKey,
    PqSignature,
};
pub use indra_bulletproofs::{prove_range, verify_range, BulletproofError, RANGE_PROOF_BYTES};
pub use mnemonic::{
    derive_all_seeds, generate_mnemonic, mnemonic_to_seed, mnemonic_words, validate_mnemonic,
    DerivedSeeds, MNEMONIC_WORD_COUNT,
};
pub use pedersen::{commit, verify_opening, PedersenCommitment, PedersenOpening};
pub use vrf::{vrf_prove, vrf_verify, VrfKeypair, VrfOutput, VrfProof};

/// Derive the deterministic blinding factor for a genesis validator UTXO.
///
/// The genesis state commits each validator's initial spendable UTXO with:
///
/// `SHA256("genesis-utxo-blinding" || validator_id)`
///
/// where `validator_id = SHA256(hybrid_classical_pk)`.
pub fn derive_genesis_utxo_blinding(validator_id: &[u8; 32]) -> [u8; 32] {
    sha256(&[b"genesis-utxo-blinding".as_slice(), validator_id.as_slice()].concat())
}

/// Derive the deterministic genesis UTXO blinding from a hybrid classical
/// public key.
pub fn derive_genesis_utxo_blinding_from_classical_pk(classical_pk: &[u8; 32]) -> [u8; 32] {
    let validator_id = sha256(classical_pk);
    derive_genesis_utxo_blinding(&validator_id)
}
