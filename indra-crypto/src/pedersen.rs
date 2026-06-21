//! Pedersen commitments on Ristretto255.
//!
//! C = value * G + blinding * H

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use sha2::Sha512;

use crate::error::{CryptoError, CryptoResult};

/// The standard Ristretto255 basepoint G (value generator).
pub static GENERATOR_G: std::sync::LazyLock<RistrettoPoint> =
    std::sync::LazyLock::new(|| RISTRETTO_BASEPOINT_POINT);

/// The second independent generator H (blinding generator).
pub static GENERATOR_H: std::sync::LazyLock<RistrettoPoint> =
    std::sync::LazyLock::new(|| RistrettoPoint::hash_from_bytes::<Sha512>(b"INDRA-PEDERSEN-H-v1"));

/// A Pedersen commitment: a compressed Ristretto255 point (32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PedersenCommitment(pub [u8; 32]);

impl PedersenCommitment {
    /// The identity (zero) commitment.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Decompress to a RistrettoPoint for arithmetic.
    pub fn decompress(&self) -> CryptoResult<RistrettoPoint> {
        CompressedRistretto(self.0)
            .decompress()
            .ok_or(CryptoError::InvalidPoint)
    }

    /// Add two commitments homomorphically.
    pub fn add(&self, other: &Self) -> CryptoResult<Self> {
        Ok(Self::from_point(
            &(self.decompress()? + other.decompress()?),
        ))
    }

    /// Subtract two commitments homomorphically.
    pub fn sub(&self, other: &Self) -> CryptoResult<Self> {
        Ok(Self::from_point(
            &(self.decompress()? - other.decompress()?),
        ))
    }

    /// Compress a RistrettoPoint to a PedersenCommitment.
    pub fn from_point(p: &RistrettoPoint) -> Self {
        Self(p.compress().to_bytes())
    }
}

/// The opening of a Pedersen commitment: (value, blinding).
#[derive(Debug, Clone)]
pub struct PedersenOpening {
    /// The committed value.
    pub value: u64,
    /// The blinding factor.
    pub blinding: [u8; 32],
}

/// Compute C = value*G + blinding*H.
pub fn commit(value: u64, blinding: &[u8; 32]) -> PedersenCommitment {
    let v = Scalar::from(value);
    let r = Scalar::from_bytes_mod_order(*blinding);
    PedersenCommitment::from_point(&(v * *GENERATOR_G + r * *GENERATOR_H))
}

/// Verify that a commitment opens correctly.
pub fn verify_opening(
    commitment: &PedersenCommitment,
    opening: &PedersenOpening,
) -> CryptoResult<()> {
    if commit(opening.value, &opening.blinding) == *commitment {
        Ok(())
    } else {
        Err(CryptoError::CommitmentOpeningFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn b(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn commit_and_verify() {
        let c = commit(1000, &b(0x01));
        assert!(verify_opening(
            &c,
            &PedersenOpening {
                value: 1000,
                blinding: b(0x01)
            }
        )
        .is_ok());
    }

    #[test]
    fn wrong_value_fails() {
        let c = commit(1000, &b(0x01));
        assert!(verify_opening(
            &c,
            &PedersenOpening {
                value: 999,
                blinding: b(0x01)
            }
        )
        .is_err());
    }

    #[test]
    fn deterministic() {
        assert_eq!(commit(500, &b(0xAA)), commit(500, &b(0xAA)));
    }

    #[test]
    fn homomorphic_addition() {
        let r1 = Scalar::from_bytes_mod_order(b(0x01));
        let r2 = Scalar::from_bytes_mod_order(b(0x02));
        let c_sum = commit(100, &r1.to_bytes())
            .add(&commit(200, &r2.to_bytes()))
            .unwrap();
        assert_eq!(c_sum, commit(300, &(r1 + r2).to_bytes()));
    }
}
