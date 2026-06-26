//! Bulletproof range proofs.

use alloc::{vec, vec::Vec};

use crate::{
    errors::{BulletproofError, BulletproofResult},
    generators::{g_vec, generator_g, generator_h, h_vec, RANGE_BITS},
    inner_product::{self, InnerProductProof},
    transcript::Transcript,
};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::MultiscalarMul,
};

/// The serialized byte length of one range proof.
pub const RANGE_PROOF_BYTES: usize = 674;

/// A Bulletproof range proof.
#[derive(Debug, Clone)]
pub struct RangeProof {
    /// Commitment to the bit vector.
    pub a: CompressedRistretto,
    /// Blinding commitment.
    pub s: CompressedRistretto,
    /// First polynomial commitment.
    pub t1: CompressedRistretto,
    /// Second polynomial commitment.
    pub t2: CompressedRistretto,
    /// Blinding factor for the combined polynomial evaluation.
    pub tau_x: Scalar,
    /// Combined blinding factor.
    pub mu: Scalar,
    /// Inner product result.
    pub tx: Scalar,
    /// The inner product argument.
    pub ipa: InnerProductProof,
}

impl RangeProof {
    /// Serialize to exactly `RANGE_PROOF_BYTES`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RANGE_PROOF_BYTES);
        bytes.extend_from_slice(self.a.as_bytes());
        bytes.extend_from_slice(self.s.as_bytes());
        bytes.extend_from_slice(self.t1.as_bytes());
        bytes.extend_from_slice(self.t2.as_bytes());
        bytes.extend_from_slice(self.tau_x.as_bytes());
        bytes.extend_from_slice(self.mu.as_bytes());
        bytes.extend_from_slice(self.tx.as_bytes());
        bytes.extend_from_slice(&self.ipa.to_bytes());
        bytes.extend_from_slice(&[0u8; 2]);
        debug_assert_eq!(bytes.len(), RANGE_PROOF_BYTES);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> BulletproofResult<Self> {
        if bytes.len() != RANGE_PROOF_BYTES {
            return Err(BulletproofError::InvalidLength {
                actual: bytes.len(),
                expected: RANGE_PROOF_BYTES,
            });
        }

        let mut offset = 0usize;
        let read_point = |offset: &mut usize| -> BulletproofResult<CompressedRistretto> {
            let point = CompressedRistretto::from_slice(&bytes[*offset..*offset + 32])
                .map_err(|_| BulletproofError::InvalidEncoding("bad point".into()))?;
            *offset += 32;
            Ok(point)
        };
        let read_scalar = |offset: &mut usize| -> BulletproofResult<Scalar> {
            let scalar_bytes: [u8; 32] = bytes[*offset..*offset + 32]
                .try_into()
                .map_err(|_| BulletproofError::InvalidEncoding("bad scalar".into()))?;
            let scalar = Scalar::from_canonical_bytes(scalar_bytes)
                .into_option()
                .ok_or_else(|| BulletproofError::InvalidEncoding("bad scalar".into()))?;
            *offset += 32;
            Ok(scalar)
        };

        let a = read_point(&mut offset)?;
        let s = read_point(&mut offset)?;
        let t1 = read_point(&mut offset)?;
        let t2 = read_point(&mut offset)?;
        let tau_x = read_scalar(&mut offset)?;
        let mu = read_scalar(&mut offset)?;
        let tx = read_scalar(&mut offset)?;
        let ipa = InnerProductProof::from_bytes(
            &bytes[offset..offset + InnerProductProof::serialized_len(RANGE_BITS)],
            RANGE_BITS,
        )?;
        offset += InnerProductProof::serialized_len(RANGE_BITS);
        if bytes[offset..offset + 2] != [0u8; 2] {
            return Err(BulletproofError::InvalidEncoding(
                "bad proof trailer".into(),
            ));
        }

        Ok(Self {
            a,
            s,
            t1,
            t2,
            tau_x,
            mu,
            tx,
            ipa,
        })
    }
}

fn commitment_bytes(value: u64, blinding: &[u8; 32]) -> [u8; 32] {
    let point = RistrettoPoint::multiscalar_mul(
        [Scalar::from(value), Scalar::from_bytes_mod_order(*blinding)],
        [generator_g(), generator_h()],
    );
    point.compress().to_bytes()
}

/// Prove that `value` is in `[0, 2^64)` given a Pedersen commitment opening.
pub fn prove<R: rand_core::RngCore + rand_core::CryptoRng>(
    value: u64,
    blinding: &[u8; 32],
    rng: &mut R,
) -> BulletproofResult<RangeProof> {
    let n = RANGE_BITS;
    let g = generator_g();
    let h = generator_h();
    let g_vec = g_vec();
    let h_vec = h_vec();
    let gamma = Scalar::from_bytes_mod_order(*blinding);
    let commitment_bytes = commitment_bytes(value, blinding);

    let bits: Vec<u64> = (0..n).map(|i| (value >> i) & 1).collect();
    let mut a_l: Vec<Scalar> = bits.iter().map(|&bit| Scalar::from(bit)).collect();
    let mut a_r: Vec<Scalar> = bits
        .iter()
        .map(|&bit| Scalar::from(bit) - Scalar::ONE)
        .collect();
    let mut s_l: Vec<Scalar> = (0..n).map(|_| Scalar::random(rng)).collect();
    let mut s_r: Vec<Scalar> = (0..n).map(|_| Scalar::random(rng)).collect();
    let alpha = Scalar::random(rng);
    let rho = Scalar::random(rng);

    let a_point = {
        let scalars: Vec<Scalar> = a_l
            .iter()
            .copied()
            .chain(a_r.iter().copied())
            .chain(core::iter::once(alpha))
            .collect();
        let points: Vec<RistrettoPoint> = g_vec
            .iter()
            .cloned()
            .chain(h_vec.iter().cloned())
            .chain(core::iter::once(h))
            .collect();
        RistrettoPoint::multiscalar_mul(scalars, points)
    };
    let s_point = {
        let scalars: Vec<Scalar> = s_l
            .iter()
            .copied()
            .chain(s_r.iter().copied())
            .chain(core::iter::once(rho))
            .collect();
        let points: Vec<RistrettoPoint> = g_vec
            .iter()
            .cloned()
            .chain(h_vec.iter().cloned())
            .chain(core::iter::once(h))
            .collect();
        RistrettoPoint::multiscalar_mul(scalars, points)
    };

    let a_compressed = a_point.compress();
    let s_compressed = s_point.compress();

    let mut transcript = Transcript::new(b"INDRA-range-proof-v1");
    transcript.append_u64(b"n", n as u64);
    transcript.append_message(b"V", &commitment_bytes);
    transcript.append_point(b"A", &a_compressed);
    transcript.append_point(b"S", &s_compressed);

    let y = transcript.challenge_scalar(b"y");
    let z = transcript.challenge_scalar(b"z");
    let z_sq = z * z;

    let y_powers: Vec<Scalar> = {
        let mut powers = vec![Scalar::ONE; n];
        for i in 1..n {
            powers[i] = powers[i - 1] * y;
        }
        powers
    };
    let two_powers: Vec<Scalar> = {
        let mut powers = vec![Scalar::ONE; n];
        for i in 1..n {
            powers[i] = powers[i - 1] + powers[i - 1];
        }
        powers
    };

    let l_0: Vec<Scalar> = a_l.iter().map(|ai| *ai - z).collect();
    let l_1: Vec<Scalar> = s_l.clone();
    let r_0: Vec<Scalar> = (0..n)
        .map(|i| y_powers[i] * (a_r[i] + z) + z_sq * two_powers[i])
        .collect();
    let r_1: Vec<Scalar> = (0..n).map(|i| y_powers[i] * s_r[i]).collect();

    let t1_val: Scalar = l_0
        .iter()
        .zip(r_1.iter())
        .map(|(li, ri)| *li * *ri)
        .sum::<Scalar>()
        + l_1
            .iter()
            .zip(r_0.iter())
            .map(|(li, ri)| *li * *ri)
            .sum::<Scalar>();
    let t2_val: Scalar = l_1.iter().zip(r_1.iter()).map(|(li, ri)| *li * *ri).sum();

    let tau1 = Scalar::random(rng);
    let tau2 = Scalar::random(rng);
    let t1 = RistrettoPoint::multiscalar_mul([t1_val, tau1], [g, h]).compress();
    let t2 = RistrettoPoint::multiscalar_mul([t2_val, tau2], [g, h]).compress();

    transcript.append_point(b"T1", &t1);
    transcript.append_point(b"T2", &t2);

    let x = transcript.challenge_scalar(b"x");
    let l_x: Vec<Scalar> = l_0
        .iter()
        .zip(l_1.iter())
        .map(|(l0, l1)| *l0 + *l1 * x)
        .collect();
    let r_x: Vec<Scalar> = r_0
        .iter()
        .zip(r_1.iter())
        .map(|(r0, r1)| *r0 + *r1 * x)
        .collect();
    let tx_val: Scalar = l_x.iter().zip(r_x.iter()).map(|(li, ri)| *li * *ri).sum();

    let tau_x = tau2 * x * x + tau1 * x + z_sq * gamma;
    let mu = alpha + rho * x;

    transcript.append_scalar(b"tx", &tx_val);
    transcript.append_scalar(b"tau_x", &tau_x);
    transcript.append_scalar(b"mu", &mu);

    let w = transcript.challenge_scalar(b"w");
    let y_inv = y.invert();
    let y_inv_powers: Vec<Scalar> = {
        let mut powers = vec![Scalar::ONE; n];
        for i in 1..n {
            powers[i] = powers[i - 1] * y_inv;
        }
        powers
    };
    let h_prime: Vec<RistrettoPoint> = h_vec
        .iter()
        .zip(y_inv_powers.iter())
        .map(|(point, scalar)| *point * *scalar)
        .collect();
    let q = g * w;

    let mut p = a_point + s_point * x - h * mu;
    for i in 0..n {
        p += h_prime[i] * (z * y_powers[i] + z_sq * two_powers[i]);
        p -= g_vec[i] * z;
    }
    p += q * tx_val;

    let mut ipa_transcript = transcript;
    let ipa = inner_product::prove(&mut ipa_transcript, &q, g_vec, h_prime, l_x, r_x);

    a_l.fill(Scalar::ZERO);
    a_r.fill(Scalar::ZERO);
    s_l.fill(Scalar::ZERO);
    s_r.fill(Scalar::ZERO);

    Ok(RangeProof {
        a: a_compressed,
        s: s_compressed,
        t1,
        t2,
        tau_x,
        mu,
        tx: tx_val,
        ipa,
    })
}

/// Verify a range proof against a Pedersen commitment.
pub fn verify(commitment_bytes: &[u8; 32], proof_bytes: &[u8]) -> BulletproofResult<()> {
    let proof = RangeProof::from_bytes(proof_bytes)?;
    let n = RANGE_BITS;
    let g = generator_g();
    let h = generator_h();
    let g_vec = g_vec();
    let h_vec = h_vec();

    let commitment = CompressedRistretto::from_slice(commitment_bytes)
        .map_err(|_| BulletproofError::InvalidEncoding("bad commitment".into()))?
        .decompress()
        .ok_or_else(|| BulletproofError::InvalidEncoding("bad commitment point".into()))?;

    let mut transcript = Transcript::new(b"INDRA-range-proof-v1");
    transcript.append_u64(b"n", n as u64);
    transcript.append_message(b"V", commitment_bytes);
    transcript.append_point(b"A", &proof.a);
    transcript.append_point(b"S", &proof.s);

    let y = transcript.challenge_scalar(b"y");
    let z = transcript.challenge_scalar(b"z");
    transcript.append_point(b"T1", &proof.t1);
    transcript.append_point(b"T2", &proof.t2);
    let x = transcript.challenge_scalar(b"x");
    transcript.append_scalar(b"tx", &proof.tx);
    transcript.append_scalar(b"tau_x", &proof.tau_x);
    transcript.append_scalar(b"mu", &proof.mu);
    let w = transcript.challenge_scalar(b"w");

    let z_sq = z * z;
    let z_cu = z_sq * z;
    let y_powers: Vec<Scalar> = {
        let mut powers = vec![Scalar::ONE; n];
        for i in 1..n {
            powers[i] = powers[i - 1] * y;
        }
        powers
    };
    let two_powers: Vec<Scalar> = {
        let mut powers = vec![Scalar::ONE; n];
        for i in 1..n {
            powers[i] = powers[i - 1] + powers[i - 1];
        }
        powers
    };
    let sum_y: Scalar = y_powers.iter().copied().sum();
    let sum_2: Scalar = two_powers.iter().copied().sum();
    let delta = (z - z_sq) * sum_y - z_cu * sum_2;

    let t1_point = proof
        .t1
        .decompress()
        .ok_or_else(|| BulletproofError::InvalidEncoding("bad T1".into()))?;
    let t2_point = proof
        .t2
        .decompress()
        .ok_or_else(|| BulletproofError::InvalidEncoding("bad T2".into()))?;

    let lhs = RistrettoPoint::multiscalar_mul([proof.tx, proof.tau_x], [g, h]);
    let rhs = RistrettoPoint::multiscalar_mul(
        [z_sq, delta, x, x * x],
        [commitment, g, t1_point, t2_point],
    );
    if lhs != rhs {
        return Err(BulletproofError::VerificationFailed);
    }

    let y_inv = y.invert();
    let y_inv_powers: Vec<Scalar> = {
        let mut powers = vec![Scalar::ONE; n];
        for i in 1..n {
            powers[i] = powers[i - 1] * y_inv;
        }
        powers
    };
    let h_prime: Vec<RistrettoPoint> = h_vec
        .iter()
        .zip(y_inv_powers.iter())
        .map(|(point, scalar)| *point * *scalar)
        .collect();
    let a_point = proof
        .a
        .decompress()
        .ok_or_else(|| BulletproofError::InvalidEncoding("bad A".into()))?;
    let s_point = proof
        .s
        .decompress()
        .ok_or_else(|| BulletproofError::InvalidEncoding("bad S".into()))?;
    let q = g * w;

    let mut p = a_point + s_point * x - h * proof.mu;
    for i in 0..n {
        p += h_prime[i] * (z * y_powers[i] + z_sq * two_powers[i]);
        p -= g_vec[i] * z;
    }
    p += q * proof.tx;

    inner_product::verify(&mut transcript, &q, &g_vec, &h_prime, &p, &proof.ipa)
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;
    use crate::generators::{generator_g, generator_h};

    fn compute_commitment(value: u64, blinding: &[u8; 32]) -> [u8; 32] {
        RistrettoPoint::multiscalar_mul(
            [Scalar::from(value), Scalar::from_bytes_mod_order(*blinding)],
            [generator_g(), generator_h()],
        )
        .compress()
        .to_bytes()
    }

    #[test]
    fn range_proof_zero() {
        let blinding = [0x01u8; 32];
        let proof = prove(0, &blinding, &mut OsRng).unwrap();
        let commitment = compute_commitment(0, &blinding);
        assert!(verify(&commitment, &proof.to_bytes()).is_ok());
    }

    #[test]
    fn range_proof_max_u64() {
        let blinding = [0x02u8; 32];
        let proof = prove(u64::MAX, &blinding, &mut OsRng).unwrap();
        let commitment = compute_commitment(u64::MAX, &blinding);
        assert!(verify(&commitment, &proof.to_bytes()).is_ok());
    }

    #[test]
    fn range_proof_1_indra() {
        let blinding = [0x03u8; 32];
        let proof = prove(1_000_000, &blinding, &mut OsRng).unwrap();
        let commitment = compute_commitment(1_000_000, &blinding);
        assert!(verify(&commitment, &proof.to_bytes()).is_ok());
    }

    #[test]
    fn proof_size_is_674_bytes() {
        let proof = prove(42, &[0x04u8; 32], &mut OsRng).unwrap();
        assert_eq!(proof.to_bytes().len(), 674);
    }

    #[test]
    fn wrong_commitment_fails() {
        let blinding = [0x05u8; 32];
        let proof = prove(100, &blinding, &mut OsRng).unwrap();
        let wrong_commitment = compute_commitment(101, &blinding);
        assert!(verify(&wrong_commitment, &proof.to_bytes()).is_err());
    }

    #[test]
    fn tampered_proof_fails() {
        let blinding = [0x06u8; 32];
        let proof = prove(100, &blinding, &mut OsRng).unwrap();
        let commitment = compute_commitment(100, &blinding);
        let mut proof_bytes = proof.to_bytes();
        proof_bytes[10] ^= 0xFF;
        assert!(verify(&commitment, &proof_bytes).is_err());
    }

    #[test]
    fn prove_verify_multiple_values() {
        let test_cases: &[(u64, [u8; 32])] = &[
            (0, [0x10u8; 32]),
            (1, [0x11u8; 32]),
            (100_000_000, [0x12u8; 32]),
            (u64::MAX / 2, [0x13u8; 32]),
            (u64::MAX, [0x14u8; 32]),
        ];

        for (value, blinding) in test_cases {
            let proof = prove(*value, blinding, &mut OsRng).unwrap();
            let commitment = compute_commitment(*value, blinding);
            assert!(
                verify(&commitment, &proof.to_bytes()).is_ok(),
                "failed for value={value}"
            );
        }
    }
}
