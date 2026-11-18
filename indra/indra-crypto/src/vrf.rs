//! RFC 9381 ECVRF-EDWARDS25519-SHA512-ELL2 (`suite_string = 0x04`).
//!
//! This in-tree path is testnet-only pending the independent review and
//! audited-implementation gates required before mainnet activation.
use crate::error::{CryptoError, CryptoResult};
use curve25519_dalek_v5::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};
/// Standard suite identifier.
pub const SUITE: u8 = 4;
/// Standard proof size.
pub const PROOF_BYTES: usize = 80;
/// Standard output size.
pub const OUTPUT_BYTES: usize = 64;
const DST: &[u8] = b"ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\x04";
/// Full RFC output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfOutput(pub [u8; 64]);
/// Canonical RFC proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfProof(pub Vec<u8>);
/// Seed-derived VRF keypair.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VrfKeypair {
    seed: [u8; 32],
    #[zeroize(skip)]
    /// Canonical public key.
    pub public_key: [u8; 32],
}
fn expand(seed: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let mut h = Sha512::digest(seed);
    let mut x = [0; 32];
    let (x_bytes, prefix_bytes) = h.as_slice().split_at(32);
    x.copy_from_slice(x_bytes);
    x[0] &= 248;
    x[31] &= 127;
    x[31] |= 64;
    let mut p = [0; 32];
    p.copy_from_slice(prefix_bytes);
    let scalar = Scalar::from_bits(x);
    // The digest and clamped bytes are transient copies derived from the
    // secret seed; the returned scalar and nonce prefix remain live.
    h.zeroize();
    x.zeroize();
    (scalar, p)
}
impl VrfKeypair {
    /// Derive from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let (mut x, mut prefix) = expand(seed);
        let keypair = Self {
            seed: *seed,
            public_key: EdwardsPoint::mul_base(&x).compress().to_bytes(),
        };
        // Key generation needs neither secret-derived expansion value after
        // the public key has been computed.
        x.zeroize();
        prefix.zeroize();
        keypair
    }
    /// Return the canonical public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
}
/// Reject identity, malformed, and noncanonical keys.
pub fn validate_vrf_public_key(pk: &[u8; 32]) -> CryptoResult<()> {
    let p = CompressedEdwardsY(*pk)
        .decompress()
        .ok_or(CryptoError::MalformedPublicKey {
            scheme: "ECVRF-EDWARDS25519-SHA512-ELL2",
            actual: 32,
        })?;
    if p.is_identity() || !p.is_torsion_free() || p.compress().to_bytes() != *pk {
        return Err(CryptoError::MalformedPublicKey {
            scheme: "ECVRF-EDWARDS25519-SHA512-ELL2",
            actual: 32,
        });
    }
    Ok(())
}
fn h2c(pk: &[u8; 32], alpha: &[u8]) -> EdwardsPoint {
    EdwardsPoint::encode_to_curve::<sha2_11::Sha512>(&[pk, alpha], &[DST])
}
fn nonce(prefix: &[u8; 32], h: &EdwardsPoint) -> Scalar {
    let mut d = Sha512::new();
    d.update(prefix);
    d.update(h.compress().as_bytes());
    let mut o = d.finalize();
    let mut w = [0; 64];
    w.copy_from_slice(&o);
    let scalar = Scalar::from_bytes_mod_order_wide(&w);
    // Both buffers contain the secret-derived deterministic nonce material.
    o.zeroize();
    w.zeroize();
    scalar
}
fn cs(c: &[u8; 16]) -> Scalar {
    let mut b = [0; 32];
    b[..16].copy_from_slice(c);
    Scalar::from_bytes_mod_order(b)
}
fn challenge(ps: [&EdwardsPoint; 5]) -> [u8; 16] {
    let mut d = Sha512::new();
    d.update([SUITE, 2]);
    for p in ps {
        d.update(p.compress().as_bytes())
    }
    d.update([0]);
    let o: [u8; 64] = d.finalize().into();
    let mut c = [0; 16];
    for (destination, source) in c.iter_mut().zip(o.iter()) {
        *destination = *source;
    }
    c
}
fn output(g: &EdwardsPoint) -> VrfOutput {
    let mut d = Sha512::new();
    d.update([SUITE, 3]);
    d.update(g.mul_by_cofactor().compress().as_bytes());
    d.update([0]);
    let b: [u8; 64] = d.finalize().into();
    VrfOutput(b)
}
/// Produce an RFC proof and output.
pub fn vrf_prove(kp: &VrfKeypair, alpha: &[u8]) -> (VrfOutput, VrfProof) {
    let (mut x, mut prefix) = expand(&kp.seed);
    let y = EdwardsPoint::mul_base(&x);
    let h = h2c(&kp.public_key, alpha);
    let g = x * h;
    let mut k = nonce(&prefix, &h);
    prefix.zeroize();
    let u = EdwardsPoint::mul_base(&k);
    let v = k * h;
    let c = challenge([&y, &h, &g, &u, &v]);
    let s = k + cs(&c) * x;
    let mut pi = Vec::with_capacity(80);
    pi.extend_from_slice(g.compress().as_bytes());
    pi.extend_from_slice(&c);
    pi.extend_from_slice(s.as_bytes());
    let result = (output(&g), VrfProof(pi));
    // x and k are the secret signing scalar and deterministic nonce. Public
    // Gamma and the proof response s intentionally remain available.
    x.zeroize();
    k.zeroize();
    result
}
/// Verify an RFC proof and its separately transmitted output.
pub fn vrf_verify(
    pk: &[u8; 32],
    alpha: &[u8],
    beta: &VrfOutput,
    pi: &VrfProof,
) -> CryptoResult<()> {
    validate_vrf_public_key(pk)?;
    if pi.0.len() != 80 {
        return Err(CryptoError::VrfProofFailed);
    }
    let y = CompressedEdwardsY(*pk)
        .decompress()
        .ok_or(CryptoError::InvalidPoint)?;
    let Some(gamma_bytes) = pi.0.get(..32) else {
        return Err(CryptoError::VrfProofFailed);
    };
    let mut gb = [0; 32];
    gb.copy_from_slice(gamma_bytes);
    let g = CompressedEdwardsY(gb)
        .decompress()
        .ok_or(CryptoError::InvalidPoint)?;
    if g.is_identity() || !g.is_torsion_free() || g.compress().to_bytes() != gb {
        return Err(CryptoError::VrfProofFailed);
    }
    let Some(challenge_bytes) = pi.0.get(32..48) else {
        return Err(CryptoError::VrfProofFailed);
    };
    let mut cb = [0; 16];
    cb.copy_from_slice(challenge_bytes);
    let c = cs(&cb);
    let Some(response_bytes) = pi.0.get(48..) else {
        return Err(CryptoError::VrfProofFailed);
    };
    let mut sb = [0; 32];
    sb.copy_from_slice(response_bytes);
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(sb))
        .ok_or(CryptoError::VrfProofFailed)?;
    let h = h2c(pk, alpha);
    let u = EdwardsPoint::vartime_double_scalar_mul_basepoint(&(-c), &y, &s);
    let v = s * h - c * g;
    if challenge([&y, &h, &g, &u, &v]) != cb || output(&g) != *beta {
        return Err(CryptoError::VrfProofFailed);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek_v5::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
    use curve25519_dalek_v5::traits::Identity;

    fn fixture(seed: u8, alpha: &[u8]) -> (VrfKeypair, VrfOutput, VrfProof) {
        let keypair = VrfKeypair::from_seed(&[seed; 32]);
        let (output, proof) = vrf_prove(&keypair, alpha);
        (keypair, output, proof)
    }

    fn proof_with_gamma(proof: &VrfProof, gamma: [u8; 32]) -> VrfProof {
        let mut bytes = proof.0.clone();
        bytes[..32].copy_from_slice(&gamma);
        VrfProof(bytes)
    }

    fn proof_with_scalar(proof: &VrfProof, scalar: [u8; 32]) -> VrfProof {
        let mut bytes = proof.0.clone();
        bytes[48..80].copy_from_slice(&scalar);
        VrfProof(bytes)
    }

    fn malformed_edwards_encoding() -> [u8; 32] {
        // Find a deterministic string that is not the encoding of any Edwards point,
        // avoiding an unexplained hard-coded byte sequence.
        for counter in 0u64.. {
            let digest = Sha512::digest(counter.to_le_bytes());
            let mut candidate = [0u8; 32];
            candidate.copy_from_slice(&digest[..32]);
            if CompressedEdwardsY(candidate).decompress().is_none() {
                return candidate;
            }
        }
        unreachable!()
    }

    fn noncanonical_identity_encoding() -> [u8; 32] {
        // y = p + 1 = 2^255 - 18 represents y = 1 modulo p (the identity),
        // but is not the canonical field encoding. The high bit is the x sign.
        let mut bytes = [0xff; 32];
        bytes[0] = 0xee;
        bytes[31] = 0x7f;
        bytes
    }

    fn noncanonical_y_zero_encoding() -> [u8; 32] {
        // y = p = 2^255 - 19 represents y = 0 modulo p. This is an alternate
        // encoding of the canonical order-four torsion point with y = 0.
        let mut bytes = [0xff; 32];
        bytes[0] = 0xed;
        bytes[31] = 0x7f;
        bytes
    }

    fn scalar_group_order() -> [u8; 32] {
        // q = 2^252 + 27742317777372353535851937790883648493, little-endian.
        hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn add_little_endian(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for index in 0..32 {
            let sum = u16::from(a[index]) + u16::from(b[index]) + carry;
            out[index] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "test input unexpectedly overflowed 256 bits");
        out
    }

    fn assert_rfc_vector(
        seed_hex: &str,
        alpha_hex: &str,
        pk_hex: &str,
        proof_hex: &str,
        output_hex: &str,
    ) {
        let seed: [u8; 32] = hex::decode(seed_hex).unwrap().try_into().unwrap();
        let alpha = hex::decode(alpha_hex).unwrap();
        let kp = VrfKeypair::from_seed(&seed);
        let (output, proof) = vrf_prove(&kp, &alpha);
        assert_eq!(hex::encode(kp.public_key), pk_hex);
        assert_eq!(hex::encode(&proof.0), proof_hex);
        assert_eq!(hex::encode(output.0), output_hex);
        vrf_verify(&kp.public_key(), &alpha, &output, &proof).unwrap();
    }

    #[test]
    fn rfc_examples_19_20_21() {
        assert_rfc_vector(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f14adf9a3cd8b8412d9038531e865c341cafa73589b023d14311c331a9ad15ff2fb37831e00f0acaa6d73bc9997b06501",
            "9d574bf9b8302ec0fc1e21c3ec5368269527b87b462ce36dab2d14ccf80c53cccf6758f058c5b1c856b116388152bbe509ee3b9ecfe63d93c3b4346c1fbc6c54",
        );
        assert_rfc_vector(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "72",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "47b327393ff2dd81336f8a2ef10339112401253b3c714eeda879f12c509072ef055b48372bb82efbdce8e10c8cb9a2f9d60e93908f93df1623ad78a86a028d6bc064dbfc75a6a57379ef855dc6733801",
            "38561d6b77b71d30eb97a062168ae12b667ce5c28caccdf76bc88e093e4635987cd96814ce55b4689b3dd2947f80e59aac7b7675f8083865b46c89b2ce9cc735",
        );
        assert_rfc_vector(
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "af82",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "926e895d308f5e328e7aa159c06eddbe56d06846abf5d98c2512235eaa57fdce35b46edfc655bc828d44ad09d1150f31374e7ef73027e14760d42e77341fe05467bb286cc2c9d7fde29120a0b2320d04",
            "121b7f9b9aaaa29099fc04a94ba52784d44eac976dd1a3cca458733be5cd090a7b5fbd148444f17f8daf1fb55cb04b1ae85a626e30a54b4b0f8abf4a43314a58",
        );
    }
    #[test]
    fn malformed_keys_and_proofs_fail_closed() {
        let kp = VrfKeypair::from_seed(&[7; 32]);
        let (o, p) = vrf_prove(&kp, b"alpha");
        assert!(validate_vrf_public_key(&[0; 32]).is_err());
        for len in [0, 31, 32, 47, 48, 79, 81] {
            let mut bytes = p.0.clone();
            bytes.resize(len, 0);
            assert!(
                vrf_verify(&kp.public_key(), b"alpha", &o, &VrfProof(bytes)).is_err(),
                "accepted proof length {len}"
            )
        }
        let mut noncanonical = p.0.clone();
        noncanonical[48..80].fill(0xff);
        assert!(vrf_verify(&kp.public_key(), b"alpha", &o, &VrfProof(noncanonical)).is_err());
        let mut wrong = o.clone();
        wrong.0[0] ^= 1;
        assert!(vrf_verify(&kp.public_key(), b"alpha", &wrong, &p).is_err())
    }

    #[test]
    fn truncated_vrf_proof_returns_typed_error() {
        let kp = VrfKeypair::from_seed(&[0x2a; 32]);
        let (output, proof) = vrf_prove(&kp, b"truncated");
        let truncated = VrfProof(proof.0[..PROOF_BYTES - 1].to_vec());
        assert_eq!(
            vrf_verify(&kp.public_key(), b"truncated", &output, &truncated),
            Err(CryptoError::VrfProofFailed)
        );
    }

    #[test]
    fn negative_public_key_rejection_is_complete_and_canonical() {
        let identity = EdwardsPoint::identity().compress().to_bytes();
        assert!(validate_vrf_public_key(&identity).is_err());

        for (index, point) in EIGHT_TORSION.iter().enumerate() {
            assert!(
                validate_vrf_public_key(point.compress().as_bytes()).is_err(),
                "accepted eight-torsion point {index}"
            );
        }

        let malformed = malformed_edwards_encoding();
        assert!(CompressedEdwardsY(malformed).decompress().is_none());
        assert!(validate_vrf_public_key(&malformed).is_err());

        for noncanonical in [
            noncanonical_identity_encoding(),
            noncanonical_y_zero_encoding(),
        ] {
            assert!(validate_vrf_public_key(&noncanonical).is_err());
        }

        let prime_order_plus_torsion = ED25519_BASEPOINT_POINT + EIGHT_TORSION[1];
        assert!(!prime_order_plus_torsion.is_torsion_free());
        assert!(validate_vrf_public_key(&prime_order_plus_torsion.compress().to_bytes()).is_err());
    }

    #[test]
    fn negative_gamma_rejection_is_complete_and_canonical() {
        let (keypair, output, proof) = fixture(0x21, b"gamma-rejection");
        let public_key = keypair.public_key();

        let identity = EdwardsPoint::identity().compress().to_bytes();
        assert!(vrf_verify(
            &public_key,
            b"gamma-rejection",
            &output,
            &proof_with_gamma(&proof, identity)
        )
        .is_err());

        for (index, point) in EIGHT_TORSION.iter().enumerate() {
            assert!(
                vrf_verify(
                    &public_key,
                    b"gamma-rejection",
                    &output,
                    &proof_with_gamma(&proof, point.compress().to_bytes())
                )
                .is_err(),
                "accepted eight-torsion Gamma {index}"
            );
        }

        for invalid in [
            malformed_edwards_encoding(),
            noncanonical_identity_encoding(),
            noncanonical_y_zero_encoding(),
        ] {
            assert!(vrf_verify(
                &public_key,
                b"gamma-rejection",
                &output,
                &proof_with_gamma(&proof, invalid)
            )
            .is_err());
        }
    }

    #[test]
    fn negative_scalar_rejection_covers_group_order_and_noncanonical_values() {
        let (keypair, output, proof) = fixture(0x22, b"scalar-rejection");
        let q = scalar_group_order();
        let mut one = [0u8; 32];
        one[0] = 1;
        let q_plus_one = add_little_endian(q, one);

        for (label, scalar) in [("q", q), ("q+1", q_plus_one), ("all-ff", [0xff; 32])] {
            assert!(
                Option::<Scalar>::from(Scalar::from_canonical_bytes(scalar)).is_none(),
                "{label} unexpectedly canonical"
            );
            assert!(
                vrf_verify(
                    &keypair.public_key(),
                    b"scalar-rejection",
                    &output,
                    &proof_with_scalar(&proof, scalar)
                )
                .is_err(),
                "accepted noncanonical scalar {label}"
            );
        }
    }

    #[test]
    fn negative_proof_framing_and_component_mutation_fail_closed() {
        let (keypair, output, proof) = fixture(0x23, b"proof-framing");
        let public_key = keypair.public_key();

        for len in 0..PROOF_BYTES {
            assert!(
                vrf_verify(
                    &public_key,
                    b"proof-framing",
                    &output,
                    &VrfProof(proof.0[..len].to_vec())
                )
                .is_err(),
                "accepted truncated proof length {len}"
            );
        }
        for bytes in [
            {
                let mut bytes = proof.0.clone();
                bytes.push(0);
                bytes
            },
            {
                let mut bytes = proof.0.clone();
                bytes.extend_from_slice(&[0xAA, 0x55]);
                bytes
            },
        ] {
            assert!(vrf_verify(&public_key, b"proof-framing", &output, &VrfProof(bytes)).is_err());
        }

        for range in [0..32, 32..48, 48..80] {
            for index in range {
                let mut altered = proof.0.clone();
                altered[index] ^= 1;
                assert!(
                    vrf_verify(&public_key, b"proof-framing", &output, &VrfProof(altered)).is_err(),
                    "accepted proof with altered byte {index}"
                );
            }
        }
    }

    #[test]
    fn negative_context_and_output_binding_reject_cross_use() {
        let (keypair_a, output_a, proof_a) = fixture(0x24, b"alpha-a");
        let (keypair_b, output_b, proof_b) = fixture(0x25, b"alpha-a");

        assert!(vrf_verify(&keypair_a.public_key(), b"wrong-alpha", &output_a, &proof_a).is_err());
        assert!(vrf_verify(&keypair_b.public_key(), b"alpha-a", &output_a, &proof_a).is_err());
        assert!(vrf_verify(&keypair_a.public_key(), b"alpha-a", &output_b, &proof_b).is_err());

        let mut modified_output = output_a.clone();
        modified_output.0[0] ^= 1;
        assert!(vrf_verify(
            &keypair_a.public_key(),
            b"alpha-a",
            &modified_output,
            &proof_a
        )
        .is_err());
        assert!(vrf_verify(&keypair_a.public_key(), b"alpha-a", &output_b, &proof_a).is_err());
    }

    #[test]
    fn negative_uniqueness_and_alternate_representation_attempts_are_rejected() {
        let (keypair, output, proof) = fixture(0x26, b"uniqueness");
        let public_key = keypair.public_key();
        vrf_verify(&public_key, b"uniqueness", &output, &proof).unwrap();

        // No distinct one-bit mutation of any proof byte is another accepted proof
        // for the fixed public key, alpha, and beta.
        for index in 0..PROOF_BYTES {
            for bit in 0..8 {
                let mut alternate = proof.0.clone();
                alternate[index] ^= 1 << bit;
                assert_ne!(alternate, proof.0);
                assert!(
                    vrf_verify(&public_key, b"uniqueness", &output, &VrfProof(alternate)).is_err(),
                    "accepted distinct mutation at byte {index}, bit {bit}"
                );
            }
        }

        // s + q denotes the same scalar mathematically, but its byte encoding is
        // noncanonical and therefore must not be accepted as an alternate proof.
        let mut canonical_s = [0u8; 32];
        canonical_s.copy_from_slice(&proof.0[48..80]);
        let same_scalar_noncanonical = add_little_endian(canonical_s, scalar_group_order());
        assert!(
            Option::<Scalar>::from(Scalar::from_canonical_bytes(same_scalar_noncanonical))
                .is_none()
        );
        assert!(vrf_verify(
            &public_key,
            b"uniqueness",
            &output,
            &proof_with_scalar(&proof, same_scalar_noncanonical)
        )
        .is_err());

        // Canonical y=0 and noncanonical y=p denote the same order-four Gamma;
        // both representations are rejected rather than normalized.
        let y_zero = EIGHT_TORSION
            .iter()
            .find(|point| point.compress().to_bytes()[..31] == [0u8; 31])
            .expect("Dalek torsion table contains a y=0 point")
            .compress()
            .to_bytes();
        for gamma in [y_zero, noncanonical_y_zero_encoding()] {
            assert!(vrf_verify(
                &public_key,
                b"uniqueness",
                &output,
                &proof_with_gamma(&proof, gamma)
            )
            .is_err());
        }
    }
}
