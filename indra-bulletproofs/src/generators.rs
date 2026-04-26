//! Pedersen generators for Bulletproofs.

use alloc::vec::Vec;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::RistrettoPoint,
};
use sha2::Sha512;

/// Bit length for range proofs. 64 = prove values in [0, 2^64).
pub const RANGE_BITS: usize = 64;

/// The value generator G.
pub fn generator_g() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

/// The blinding generator H.
pub fn generator_h() -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(b"INDRA-PEDERSEN-H-v1")
}

/// Generate the `i`-th `G` vector generator.
pub fn generator_g_vec(i: usize) -> RistrettoPoint {
    let mut input = b"INDRA-BP-G-v1".to_vec();
    input.extend_from_slice(&(i as u32).to_le_bytes());
    RistrettoPoint::hash_from_bytes::<Sha512>(&input)
}

/// Generate the `i`-th `H` vector generator.
pub fn generator_h_vec(i: usize) -> RistrettoPoint {
    let mut input = b"INDRA-BP-H-v1".to_vec();
    input.extend_from_slice(&(i as u32).to_le_bytes());
    RistrettoPoint::hash_from_bytes::<Sha512>(&input)
}

/// Pre-generate all `G_vec` generators for `RANGE_BITS`.
pub fn g_vec() -> Vec<RistrettoPoint> {
    (0..RANGE_BITS).map(generator_g_vec).collect()
}

/// Pre-generate all `H_vec` generators for `RANGE_BITS`.
pub fn h_vec() -> Vec<RistrettoPoint> {
    (0..RANGE_BITS).map(generator_h_vec).collect()
}
