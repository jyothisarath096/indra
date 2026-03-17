//! VRF stub — full ECVRF-RISTRETTO255-SHA512 in Phase 4.

use crate::{error::{CryptoError, CryptoResult}, hash::sha256};

/// VRF output: 32 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfOutput(pub [u8; 32]);

/// VRF proof bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfProof(pub Vec<u8>);

/// A VRF keypair.
pub struct VrfKeypair { secret_key: [u8; 32], public_key: [u8; 32] }

impl VrfKeypair {
    /// Create from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self { secret_key: *seed, public_key: sha256(seed) }
    }
    /// Return the public key.
    pub fn public_key(&self) -> [u8; 32] { self.public_key }
}

/// Compute a VRF output and proof (stub).
pub fn vrf_prove(kp: &VrfKeypair, input: &[u8]) -> (VrfOutput, VrfProof) {
    let output = sha256(&[&kp.secret_key[..], input].concat());
    let mut proof = sha256(&[&output[..], input].concat()).to_vec();
    proof.extend_from_slice(&sha256(&[&output[..], b"proof"].concat()));
    (VrfOutput(output), VrfProof(proof))
}

/// Verify a VRF output and proof (stub).
pub fn vrf_verify(_pk: &[u8; 32], input: &[u8], output: &VrfOutput, proof: &VrfProof) -> CryptoResult<()> {
    if proof.0.len() != 64 { return Err(CryptoError::VrfProofFailed); }
    if proof.0[..32] != sha256(&[&output.0[..], input].concat()) { return Err(CryptoError::VrfProofFailed); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let kp = VrfKeypair::from_seed(&[0x42u8; 32]);
        let (out, proof) = vrf_prove(&kp, b"epoch seed");
        assert!(vrf_verify(&kp.public_key(), b"epoch seed", &out, &proof).is_ok());
    }

    #[test]
    fn wrong_output_fails() {
        let kp = VrfKeypair::from_seed(&[0xABu8; 32]);
        let (_, proof) = vrf_prove(&kp, b"input");
        assert!(vrf_verify(&kp.public_key(), b"input", &VrfOutput([0xFF; 32]), &proof).is_err());
    }
}
