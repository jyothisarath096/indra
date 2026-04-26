//! Inner product argument (IPA).

use alloc::{vec, vec::Vec};

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::MultiscalarMul,
};

use crate::{
    errors::{BulletproofError, BulletproofResult},
    transcript::Transcript,
};

fn log2_pow2(n: usize) -> usize {
    debug_assert!(n.is_power_of_two());
    n.trailing_zeros() as usize
}

/// An inner product argument proof.
#[derive(Debug, Clone)]
pub struct InnerProductProof {
    /// Left fold commitments, one per round.
    pub l_vec: Vec<CompressedRistretto>,
    /// Right fold commitments, one per round.
    pub r_vec: Vec<CompressedRistretto>,
    /// Final scalar a.
    pub a: Scalar,
    /// Final scalar b.
    pub b: Scalar,
}

impl InnerProductProof {
    /// Expected byte length for `n`-element vectors.
    pub fn serialized_len(n: usize) -> usize {
        let lg_n = log2_pow2(n);
        (lg_n * 2 + 2) * 32
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity((self.l_vec.len() * 2 + 2) * 32);
        for (l, r) in self.l_vec.iter().zip(self.r_vec.iter()) {
            bytes.extend_from_slice(l.as_bytes());
            bytes.extend_from_slice(r.as_bytes());
        }
        bytes.extend_from_slice(self.a.as_bytes());
        bytes.extend_from_slice(self.b.as_bytes());
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8], n: usize) -> BulletproofResult<Self> {
        if !n.is_power_of_two() {
            return Err(BulletproofError::InnerProductFailed);
        }

        let lg_n = log2_pow2(n);
        let expected = Self::serialized_len(n);
        if bytes.len() != expected {
            return Err(BulletproofError::InvalidLength {
                actual: bytes.len(),
                expected,
            });
        }

        let mut l_vec = Vec::with_capacity(lg_n);
        let mut r_vec = Vec::with_capacity(lg_n);
        let mut offset = 0usize;

        for _ in 0..lg_n {
            let l = CompressedRistretto::from_slice(&bytes[offset..offset + 32])
                .map_err(|_| BulletproofError::InvalidEncoding("bad L point".into()))?;
            offset += 32;
            let r = CompressedRistretto::from_slice(&bytes[offset..offset + 32])
                .map_err(|_| BulletproofError::InvalidEncoding("bad R point".into()))?;
            offset += 32;
            l_vec.push(l);
            r_vec.push(r);
        }

        let a_bytes: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| BulletproofError::InvalidEncoding("bad scalar a".into()))?;
        let a = Scalar::from_canonical_bytes(a_bytes)
            .into_option()
            .ok_or_else(|| BulletproofError::InvalidEncoding("bad scalar a".into()))?;
        offset += 32;

        let b_bytes: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| BulletproofError::InvalidEncoding("bad scalar b".into()))?;
        let b = Scalar::from_canonical_bytes(b_bytes)
            .into_option()
            .ok_or_else(|| BulletproofError::InvalidEncoding("bad scalar b".into()))?;

        Ok(Self { l_vec, r_vec, a, b })
    }
}

/// Prove an inner product relationship.
pub fn prove(
    transcript: &mut Transcript,
    q: &RistrettoPoint,
    g_vec: Vec<RistrettoPoint>,
    h_vec: Vec<RistrettoPoint>,
    a_vec: Vec<Scalar>,
    b_vec: Vec<Scalar>,
) -> InnerProductProof {
    let mut n = g_vec.len();
    assert!(n.is_power_of_two(), "n must be a power of 2");
    assert_eq!(n, h_vec.len(), "generator vectors must be equal length");
    assert_eq!(n, a_vec.len(), "secret vectors must be equal length");
    assert_eq!(n, b_vec.len(), "secret vectors must be equal length");

    let mut g = g_vec;
    let mut h = h_vec;
    let mut a = a_vec;
    let mut b = b_vec;
    let mut l_vec = Vec::new();
    let mut r_vec = Vec::new();

    while n > 1 {
        n /= 2;

        let c_l: Scalar = a[..n]
            .iter()
            .zip(b[n..].iter())
            .map(|(ai, bi)| *ai * *bi)
            .sum();
        let c_r: Scalar = a[n..]
            .iter()
            .zip(b[..n].iter())
            .map(|(ai, bi)| *ai * *bi)
            .sum();

        let l_scalars: Vec<Scalar> = a[..n]
            .iter()
            .copied()
            .chain(b[n..].iter().copied())
            .chain(core::iter::once(c_l))
            .collect();
        let l_points: Vec<RistrettoPoint> = g[n..]
            .iter()
            .cloned()
            .chain(h[..n].iter().cloned())
            .chain(core::iter::once(*q))
            .collect();
        let l_point = RistrettoPoint::multiscalar_mul(l_scalars, l_points);
        let l_compressed = l_point.compress();
        transcript.append_point(b"L", &l_compressed);
        l_vec.push(l_compressed);

        let r_scalars: Vec<Scalar> = a[n..]
            .iter()
            .copied()
            .chain(b[..n].iter().copied())
            .chain(core::iter::once(c_r))
            .collect();
        let r_points: Vec<RistrettoPoint> = g[..n]
            .iter()
            .cloned()
            .chain(h[n..].iter().cloned())
            .chain(core::iter::once(*q))
            .collect();
        let r_point = RistrettoPoint::multiscalar_mul(r_scalars, r_points);
        let r_compressed = r_point.compress();
        transcript.append_point(b"R", &r_compressed);
        r_vec.push(r_compressed);

        let u = transcript.challenge_scalar(b"u");
        let u_inv = u.invert();

        let new_g: Vec<RistrettoPoint> = g[..n]
            .iter()
            .zip(g[n..].iter())
            .map(|(gl, gr)| RistrettoPoint::multiscalar_mul([u_inv, u], [*gl, *gr]))
            .collect();
        let new_h: Vec<RistrettoPoint> = h[..n]
            .iter()
            .zip(h[n..].iter())
            .map(|(hl, hr)| RistrettoPoint::multiscalar_mul([u, u_inv], [*hl, *hr]))
            .collect();
        let new_a: Vec<Scalar> = a[..n]
            .iter()
            .zip(a[n..].iter())
            .map(|(al, ar)| *al * u + *ar * u_inv)
            .collect();
        let new_b: Vec<Scalar> = b[..n]
            .iter()
            .zip(b[n..].iter())
            .map(|(bl, br)| *bl * u_inv + *br * u)
            .collect();

        g = new_g;
        h = new_h;
        a = new_a;
        b = new_b;
    }

    InnerProductProof {
        l_vec,
        r_vec,
        a: a[0],
        b: b[0],
    }
}

/// Verify an inner product proof.
pub fn verify(
    transcript: &mut Transcript,
    q: &RistrettoPoint,
    g_vec: &[RistrettoPoint],
    h_vec: &[RistrettoPoint],
    p: &RistrettoPoint,
    proof: &InnerProductProof,
) -> BulletproofResult<()> {
    let n = g_vec.len();
    if !n.is_power_of_two() || h_vec.len() != n || proof.l_vec.len() != proof.r_vec.len() {
        return Err(BulletproofError::InnerProductFailed);
    }

    let lg_n = proof.l_vec.len();
    if (1usize << lg_n) != n {
        return Err(BulletproofError::InnerProductFailed);
    }

    let mut challenges = Vec::with_capacity(lg_n);
    let mut l_r_points = Vec::with_capacity(lg_n * 2);
    for (l, r) in proof.l_vec.iter().zip(proof.r_vec.iter()) {
        let l_point = l
            .decompress()
            .ok_or_else(|| BulletproofError::InvalidEncoding("bad L point".into()))?;
        let r_point = r
            .decompress()
            .ok_or_else(|| BulletproofError::InvalidEncoding("bad R point".into()))?;

        transcript.append_point(b"L", l);
        transcript.append_point(b"R", r);
        challenges.push(transcript.challenge_scalar(b"u"));
        l_r_points.push(l_point);
        l_r_points.push(r_point);
    }

    let mut g_scalars = vec![Scalar::ONE; n];
    let mut h_scalars = vec![Scalar::ONE; n];

    for (j, u) in challenges.iter().enumerate() {
        let u_inv = u.invert();
        for i in 0..n {
            if ((i >> (lg_n - 1 - j)) & 1) == 0 {
                g_scalars[i] *= u_inv;
                h_scalars[i] *= *u;
            } else {
                g_scalars[i] *= *u;
                h_scalars[i] *= u_inv;
            }
        }
    }

    for scalar in &mut g_scalars {
        *scalar *= proof.a;
    }
    for scalar in &mut h_scalars {
        *scalar *= proof.b;
    }

    let l_r_scalars: Vec<Scalar> = challenges
        .iter()
        .flat_map(|u| {
            let u_sq = *u * *u;
            let u_inv_sq = u.invert() * u.invert();
            [u_sq, u_inv_sq]
        })
        .collect();

    let ab = proof.a * proof.b;
    let all_scalars: Vec<Scalar> = g_scalars
        .iter()
        .copied()
        .chain(h_scalars.iter().copied())
        .chain(core::iter::once(ab))
        .collect();
    let all_points: Vec<RistrettoPoint> = g_vec
        .iter()
        .cloned()
        .chain(h_vec.iter().cloned())
        .chain(core::iter::once(*q))
        .collect();

    let folded_p = RistrettoPoint::multiscalar_mul(all_scalars, all_points);
    let adjustment = RistrettoPoint::multiscalar_mul(l_r_scalars, l_r_points);

    if folded_p == *p + adjustment {
        Ok(())
    } else {
        Err(BulletproofError::InnerProductFailed)
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};

    use super::*;
    use crate::{
        generators::{generator_g_vec, generator_h_vec, generator_h},
        transcript::Transcript,
    };

    #[test]
    fn ipa_prove_verify() {
        let n = 4usize;
        let g: Vec<RistrettoPoint> = (0..n).map(generator_g_vec).collect();
        let h: Vec<RistrettoPoint> = (0..n).map(generator_h_vec).collect();
        let q = generator_h();

        let a: Vec<Scalar> = (0..n as u64).map(Scalar::from).collect();
        let b: Vec<Scalar> = (0..n as u64).map(|i| Scalar::from(i + 1)).collect();
        let c: Scalar = a.iter().zip(b.iter()).map(|(ai, bi)| *ai * *bi).sum();

        let p = RistrettoPoint::multiscalar_mul(
            a.iter()
                .copied()
                .chain(b.iter().copied())
                .chain(core::iter::once(c)),
            g.iter()
                .cloned()
                .chain(h.iter().cloned())
                .chain(core::iter::once(q)),
        );

        let mut transcript_p = Transcript::new(b"test-ipa");
        let proof = prove(&mut transcript_p, &q, g.clone(), h.clone(), a, b);

        let mut transcript_v = Transcript::new(b"test-ipa");
        assert!(verify(&mut transcript_v, &q, &g, &h, &p, &proof).is_ok());
    }
}
