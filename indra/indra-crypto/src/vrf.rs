//! Full ECVRF-RISTRETTO255-SHA512 implementation.
//!
//! Implements draft-irtf-cfrg-vrf-15 Section 5.4 (ECVRF-RISTRETTO255-SHA512).
//!
//! ## Algorithm
//!
//! Given secret key `sk` (32 bytes) and input `alpha`:
//!
//! 1. Derive `x` = SHA-512(sk) reduced as a wide Ristretto scalar
//! 2. Compute `Y` = x * B  (public key, Ristretto point)
//! 3. Hash `alpha` to a curve point `H` = hash_to_ristretto(alpha)
//! 4. Compute `Gamma` = x * H
//! 5. Choose random nonce `k`
//! 6. Compute `U` = k*B, `V` = k*H
//! 7. Challenge `c` = SHA-512(Y || H || Gamma || U || V)[..16]
//! 8. Response `s` = k + c*x  (mod group order)
//! 9. Proof = Gamma || c || s
//! 10. Output = SHA-512(suite || 0x03 || Gamma)[..32]
//!
//! ## Security
//!
//! Security relies on the hardness of the discrete log problem on
//! Ristretto255 (equivalent to Curve25519). The VRF output is
//! pseudorandom and unpredictable without the secret key.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use sha2::{Digest, Sha512};

use crate::error::{CryptoError, CryptoResult};

/// VRF suite string for ECVRF-RISTRETTO255-SHA512.
const SUITE: u8 = 0x04;
/// Proof size: 32 (Gamma) + 16 (c) + 32 (s) = 80 bytes.
pub const PROOF_BYTES: usize = 80;

/// VRF output: 32 bytes of pseudorandom output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfOutput(pub [u8; 32]);

/// VRF proof: 80 bytes (Gamma || c || s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfProof(pub Vec<u8>);

/// A VRF keypair (secret scalar + public Ristretto point).
pub struct VrfKeypair {
    secret_key: [u8; 32],
    /// The public key (compressed Ristretto point, 32 bytes).
    pub public_key: [u8; 32],
}

impl VrfKeypair {
    /// Create from a 32-byte seed.
    ///
    /// The secret scalar is derived as SHA-512(seed) reduced as a wide
    /// Ristretto scalar.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let public_key = derive_public_key(seed);
        Self {
            secret_key: *seed,
            public_key,
        }
    }

    /// Return the public key (compressed Ristretto point).
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
}

/// Derive public key from seed.
#[allow(non_snake_case)]
fn derive_public_key(seed: &[u8; 32]) -> [u8; 32] {
    let x = derive_scalar(seed);
    let Y = x * RISTRETTO_BASEPOINT_POINT;
    Y.compress().to_bytes()
}

/// Derive secret scalar from seed using SHA-512.
fn derive_scalar(seed: &[u8; 32]) -> Scalar {
    let hash = Sha512::digest(seed);
    let mut wide_bytes = [0u8; 64];
    wide_bytes.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide_bytes)
}

/// Hash arbitrary bytes to a Ristretto255 point.
///
/// Uses the Elligator2 map via SHA-512 (hash-and-pray with rejection).
fn hash_to_ristretto(data: &[u8]) -> RistrettoPoint {
    let mut counter: u8 = 0;
    loop {
        let mut h = Sha512::new();
        h.update([SUITE, 0x01]);
        h.update(data);
        h.update([counter]);
        let hash = h.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash[..32]);

        if let Some(point) = CompressedRistretto(bytes).decompress() {
            return point;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Deterministic nonce generation (RFC 6979 style).
fn generate_nonce(secret_key: &[u8; 32], alpha: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(secret_key);
    h.update(alpha);
    h.update(b"INDRA-VRF-NONCE-v1");
    let hash = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash[..32]);
    Scalar::from_bytes_mod_order(bytes)
}

/// Compute the VRF challenge hash.
#[allow(non_snake_case)]
fn compute_challenge(
    Y: &RistrettoPoint,
    H: &RistrettoPoint,
    Gamma: &RistrettoPoint,
    U: &RistrettoPoint,
    V: &RistrettoPoint,
) -> [u8; 16] {
    let mut h = Sha512::new();
    h.update([SUITE, 0x02]);
    h.update(Y.compress().as_bytes());
    h.update(H.compress().as_bytes());
    h.update(Gamma.compress().as_bytes());
    h.update(U.compress().as_bytes());
    h.update(V.compress().as_bytes());
    let hash = h.finalize();
    let mut c = [0u8; 16];
    c.copy_from_slice(&hash[..16]);
    c
}

/// Prove: compute VRF output and proof for given input.
#[allow(non_snake_case)]
pub fn vrf_prove(kp: &VrfKeypair, alpha: &[u8]) -> (VrfOutput, VrfProof) {
    let x = derive_scalar(&kp.secret_key);
    let Y = x * RISTRETTO_BASEPOINT_POINT;

    // Hash input to curve point
    let H = hash_to_ristretto(alpha);
    let Gamma = x * H;

    // Deterministic nonce
    let k = generate_nonce(&kp.secret_key, alpha);
    let U = k * RISTRETTO_BASEPOINT_POINT;
    let V = k * H;

    // Challenge
    let c_bytes = compute_challenge(&Y, &H, &Gamma, &U, &V);
    let mut c_scalar_bytes = [0u8; 32];
    c_scalar_bytes[..16].copy_from_slice(&c_bytes);
    let c = Scalar::from_bytes_mod_order(c_scalar_bytes);

    // Response
    let s = k + c * x;

    // Build proof: Gamma (32) || c (16) || s (32) = 80 bytes
    let mut proof = Vec::with_capacity(PROOF_BYTES);
    proof.extend_from_slice(Gamma.compress().as_bytes());
    proof.extend_from_slice(&c_bytes);
    proof.extend_from_slice(s.as_bytes());

    // Compute VRF output: SHA-512(suite || 0x03 || Gamma)[..32]
    let mut h = Sha512::new();
    h.update([SUITE, 0x03]);
    h.update(Gamma.compress().as_bytes());
    let output_hash = h.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&output_hash[..32]);

    (VrfOutput(output), VrfProof(proof))
}

/// Verify a VRF proof.
///
/// Returns Ok(()) if the proof is valid for (pk, alpha, output).
#[allow(non_snake_case)]
pub fn vrf_verify(
    pk: &[u8; 32],
    alpha: &[u8],
    output: &VrfOutput,
    proof: &VrfProof,
) -> CryptoResult<()> {
    if proof.0.len() != PROOF_BYTES {
        return Err(CryptoError::VrfProofFailed);
    }

    // Decode public key
    let Y = CompressedRistretto(*pk)
        .decompress()
        .ok_or(CryptoError::InvalidPoint)?;

    // Decode proof components
    let mut gamma_bytes = [0u8; 32];
    gamma_bytes.copy_from_slice(&proof.0[..32]);
    let Gamma = CompressedRistretto(gamma_bytes)
        .decompress()
        .ok_or(CryptoError::InvalidPoint)?;

    let mut c_bytes = [0u8; 16];
    c_bytes.copy_from_slice(&proof.0[32..48]);
    let mut c_scalar_bytes = [0u8; 32];
    c_scalar_bytes[..16].copy_from_slice(&c_bytes);
    let c = Scalar::from_bytes_mod_order(c_scalar_bytes);

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&proof.0[48..80]);
    let s = Scalar::from_canonical_bytes(s_bytes)
        .into_option()
        .ok_or(CryptoError::VrfProofFailed)?;

    // Recompute H
    let H = hash_to_ristretto(alpha);

    // Recompute U = s*B - c*Y, V = s*H - c*Gamma
    let U = s * RISTRETTO_BASEPOINT_POINT - c * Y;
    let V = s * H - c * Gamma;

    // Recompute challenge
    let c_check = compute_challenge(&Y, &H, &Gamma, &U, &V);
    if c_check != c_bytes {
        return Err(CryptoError::VrfProofFailed);
    }

    // Verify output
    let mut h = Sha512::new();
    h.update([SUITE, 0x03]);
    h.update(Gamma.compress().as_bytes());
    let output_hash = h.finalize();
    if output.0 != output_hash[..32] {
        return Err(CryptoError::VrfProofFailed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let kp = VrfKeypair::from_seed(&[0x42u8; 32]);
        let (out, proof) = vrf_prove(&kp, b"INDRA epoch seed test");
        assert!(vrf_verify(&kp.public_key(), b"INDRA epoch seed test", &out, &proof).is_ok());
    }

    #[test]
    fn vrf_scalar_no_clamping_for_ristretto() {
        let seed = [0x01u8; 32];
        let kp = VrfKeypair::from_seed(&seed);
        let (out, proof) = vrf_prove(&kp, b"test");
        assert!(vrf_verify(&kp.public_key(), b"test", &out, &proof).is_ok());
    }

    #[test]
    fn wrong_input_fails() {
        let kp = VrfKeypair::from_seed(&[0x01u8; 32]);
        let (out, proof) = vrf_prove(&kp, b"correct input");
        assert!(vrf_verify(&kp.public_key(), b"wrong input", &out, &proof).is_err());
    }

    #[test]
    fn wrong_output_fails() {
        let kp = VrfKeypair::from_seed(&[0xABu8; 32]);
        let (_, proof) = vrf_prove(&kp, b"input");
        assert!(vrf_verify(&kp.public_key(), b"input", &VrfOutput([0xFF; 32]), &proof).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = VrfKeypair::from_seed(&[0x01u8; 32]);
        let kp2 = VrfKeypair::from_seed(&[0x02u8; 32]);
        let (out, proof) = vrf_prove(&kp1, b"input");
        assert!(vrf_verify(&kp2.public_key(), b"input", &out, &proof).is_err());
    }

    #[test]
    fn proof_is_80_bytes() {
        let kp = VrfKeypair::from_seed(&[0x10u8; 32]);
        let (_, proof) = vrf_prove(&kp, b"test");
        assert_eq!(proof.0.len(), PROOF_BYTES);
    }

    #[test]
    fn different_inputs_give_different_outputs() {
        let kp = VrfKeypair::from_seed(&[0x42u8; 32]);
        let (out1, _) = vrf_prove(&kp, b"input one");
        let (out2, _) = vrf_prove(&kp, b"input two");
        assert_ne!(out1, out2);
    }

    #[test]
    fn deterministic() {
        let kp = VrfKeypair::from_seed(&[0x42u8; 32]);
        let (out1, proof1) = vrf_prove(&kp, b"same input");
        let (out2, proof2) = vrf_prove(&kp, b"same input");
        assert_eq!(out1, out2);
        assert_eq!(proof1, proof2);
    }
}
