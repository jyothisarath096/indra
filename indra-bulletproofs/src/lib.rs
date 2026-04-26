//! INDRA Bulletproofs — Range proofs compatible with curve25519-dalek 4.x.
//!
//! Implements the Bulletproof range proof scheme from:
//! "Bulletproofs: Short Proofs for Confidential Transactions and More"
//! Bünz, Bootle, Boneh, Poelstra, Wuille, Maxwell (2018)
//! https://eprint.iacr.org/2017/1066.pdf

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![no_std]

extern crate alloc;

pub mod errors;
pub mod generators;
pub mod inner_product;
pub mod range_proof;
pub mod transcript;

pub use errors::{BulletproofError, BulletproofResult};
pub use range_proof::{
    RANGE_PROOF_BYTES, RangeProof, prove as prove_range_full, verify as verify_range,
};

/// Prove that `value` is in `[0, 2^64)` and return serialized proof bytes.
pub fn prove_range<R: rand_core::RngCore + rand_core::CryptoRng>(
    value: u64,
    blinding: &[u8; 32],
    rng: &mut R,
) -> BulletproofResult<alloc::vec::Vec<u8>> {
    let proof = range_proof::prove(value, blinding, rng)?;
    Ok(proof.to_bytes())
}
