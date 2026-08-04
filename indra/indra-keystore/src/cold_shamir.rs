//! Offline Shamir backup ceremonies for validator cold-key seeds.
//!
//! This module deliberately implements only secret sharing and reconstruction.
//! It performs no network or chain-state access. The byte-wise GF(256)
//! construction is intentionally small and isolated for external review.

use std::path::Path;

use indra_crypto::{hybrid::ColdHybridKeypair, sha256};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{write_keys_secure, ColdKeysFile, KeystoreError, KeystoreResult};

const SHARE_FORMAT: &str = "indra-cold-key-share";
const SHARE_VERSION: u8 = 1;
const CHECKSUM_DOMAIN: &[u8] = b"INDRA-COLD-KEY-SHARE-CHECKSUM-v1";
const SECRET_BYTES: usize = 64;

/// Public description of one cold-key sharing ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColdShareManifest {
    pub format: String,
    pub version: u8,
    pub ceremony_id: String,
    pub created_unix_seconds: u64,
    pub validator_id: String,
    pub cold_classical_pk: String,
    pub cold_pq_pk: String,
    pub threshold: u8,
    pub share_count: u8,
}

/// One self-identifying, checksummed Shamir share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColdShareFile {
    #[serde(flatten)]
    pub manifest: ColdShareManifest,
    pub share_index: u8,
    pub share_value: String,
    pub share_checksum: String,
}

/// A generated public manifest and its complete share set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColdShareCeremony {
    pub manifest: ColdShareManifest,
    pub shares: Vec<ColdShareFile>,
}

fn share_error(detail: impl Into<String>) -> KeystoreError {
    KeystoreError::Crypto(format!("cold-share ceremony: {}", detail.into()))
}

fn validate_threshold(threshold: u8, share_count: u8) -> KeystoreResult<()> {
    if threshold < 2 {
        return Err(share_error("threshold must be at least 2"));
    }
    if threshold > share_count {
        return Err(share_error("threshold cannot exceed share count"));
    }
    Ok(())
}

// Multiplication in GF(2^8), reduced by x^8+x^4+x^3+x+1 (0x11B).
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

fn gf_pow(mut value: u8, mut exponent: u8) -> u8 {
    let mut result = 1u8;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, value);
        }
        value = gf_mul(value, value);
        exponent >>= 1;
    }
    result
}

fn gf_inv(value: u8) -> KeystoreResult<u8> {
    if value == 0 {
        return Err(share_error("attempted inversion of zero field element"));
    }
    Ok(gf_pow(value, 254))
}

fn evaluate(coefficients: &[u8], x: u8) -> u8 {
    coefficients
        .iter()
        .rev()
        .fold(0u8, |acc, coefficient| gf_mul(acc, x) ^ coefficient)
}

fn interpolate_at(points: &[(u8, u8)], x: u8) -> KeystoreResult<u8> {
    let mut result = 0u8;
    for (i, &(x_i, y_i)) in points.iter().enumerate() {
        let mut numerator = 1u8;
        let mut denominator = 1u8;
        for (j, &(x_j, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            numerator = gf_mul(numerator, x ^ x_j);
            denominator = gf_mul(denominator, x_i ^ x_j);
        }
        result ^= gf_mul(y_i, gf_mul(numerator, gf_inv(denominator)?));
    }
    Ok(result)
}

fn context_bytes(manifest: &ColdShareManifest) -> KeystoreResult<Vec<u8>> {
    let ceremony_id = decode_fixed::<32>(&manifest.ceremony_id, "ceremony_id")?;
    let validator_id = decode_fixed::<32>(&manifest.validator_id, "validator_id")?;
    let classical_pk = decode_fixed::<32>(&manifest.cold_classical_pk, "cold_classical_pk")?;
    let pq_pk = hex::decode(&manifest.cold_pq_pk)
        .map_err(|_| share_error("cold_pq_pk is not canonical hex"))?;
    let mut out = Vec::with_capacity(128 + pq_pk.len());
    out.extend_from_slice(&(manifest.format.len() as u16).to_le_bytes());
    out.extend_from_slice(manifest.format.as_bytes());
    out.push(manifest.version);
    out.extend_from_slice(&ceremony_id);
    out.extend_from_slice(&manifest.created_unix_seconds.to_le_bytes());
    out.extend_from_slice(&validator_id);
    out.extend_from_slice(&classical_pk);
    out.extend_from_slice(&(pq_pk.len() as u32).to_le_bytes());
    out.extend_from_slice(&pq_pk);
    out.push(manifest.threshold);
    out.push(manifest.share_count);
    Ok(out)
}

fn checksum(
    manifest: &ColdShareManifest,
    index: u8,
    value: &[u8; SECRET_BYTES],
) -> KeystoreResult<[u8; 32]> {
    let mut payload = context_bytes(manifest)?;
    payload.push(index);
    payload.extend_from_slice(value);
    let mut bytes = Vec::with_capacity(CHECKSUM_DOMAIN.len() + 4 + payload.len());
    bytes.extend_from_slice(CHECKSUM_DOMAIN);
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&payload);
    Ok(sha256(&bytes))
}

fn decode_fixed<const N: usize>(value: &str, field: &str) -> KeystoreResult<[u8; N]> {
    if value.len() != N * 2 || value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(share_error(format!(
            "{field} is not canonical lowercase hex"
        )));
    }
    let bytes = hex::decode(value).map_err(|_| share_error(format!("{field} is invalid hex")))?;
    bytes
        .try_into()
        .map_err(|_| share_error(format!("{field} has the wrong length")))
}

fn validate_manifest(manifest: &ColdShareManifest) -> KeystoreResult<()> {
    if manifest.format != SHARE_FORMAT || manifest.version != SHARE_VERSION {
        return Err(share_error("unsupported share format or version"));
    }
    validate_threshold(manifest.threshold, manifest.share_count)?;
    context_bytes(manifest)?;
    Ok(())
}

/// Split the two independent cold-key seeds into a new offline ceremony.
pub fn generate_cold_share_ceremony<R: CryptoRng + RngCore>(
    keys: &ColdKeysFile,
    validator_id: [u8; 32],
    threshold: u8,
    share_count: u8,
    created_unix_seconds: u64,
    rng: &mut R,
) -> KeystoreResult<ColdShareCeremony> {
    validate_threshold(threshold, share_count)?;
    keys.reconstruct()?;

    let mut ceremony_id = [0u8; 32];
    rng.fill_bytes(&mut ceremony_id);
    let mut secret = Zeroizing::new([0u8; SECRET_BYTES]);
    secret[..32].copy_from_slice(&keys.classical_seed);
    secret[32..].copy_from_slice(&keys.pq_seed);

    let coefficient_len = (threshold as usize - 1) * SECRET_BYTES;
    let mut random_coefficients = Zeroizing::new(vec![0u8; coefficient_len]);
    rng.fill_bytes(&mut random_coefficients);
    let mut values = vec![[0u8; SECRET_BYTES]; share_count as usize];
    for byte in 0..SECRET_BYTES {
        let mut coefficients = Zeroizing::new(vec![0u8; threshold as usize]);
        coefficients[0] = secret[byte];
        for degree in 1..threshold as usize {
            coefficients[degree] = random_coefficients[(degree - 1) * SECRET_BYTES + byte];
        }
        for (offset, value) in values.iter_mut().enumerate() {
            value[byte] = evaluate(&coefficients, (offset + 1) as u8);
        }
    }

    let public = keys.reconstruct()?.public_key();
    let public = public.as_complete_hybrid();
    let manifest = ColdShareManifest {
        format: SHARE_FORMAT.to_string(),
        version: SHARE_VERSION,
        ceremony_id: hex::encode(ceremony_id),
        created_unix_seconds,
        validator_id: hex::encode(validator_id),
        cold_classical_pk: hex::encode(public.classical.0),
        cold_pq_pk: hex::encode(public.pq.0.as_slice()),
        threshold,
        share_count,
    };

    let shares = values
        .iter()
        .enumerate()
        .map(|(offset, value)| {
            let index = (offset + 1) as u8;
            Ok(ColdShareFile {
                manifest: manifest.clone(),
                share_index: index,
                share_value: hex::encode(value),
                share_checksum: hex::encode(checksum(&manifest, index, value)?),
            })
        })
        .collect::<KeystoreResult<Vec<_>>>()?;
    values.zeroize();
    Ok(ColdShareCeremony { manifest, shares })
}

/// Validate and reconstruct a cold key from a threshold share collection.
pub fn reconstruct_cold_shares(shares: &[ColdShareFile]) -> KeystoreResult<ColdKeysFile> {
    let first = shares
        .first()
        .ok_or_else(|| share_error("no shares supplied"))?;
    validate_manifest(&first.manifest)?;
    if shares.len() < first.manifest.threshold as usize {
        return Err(share_error(format!(
            "need at least {} shares, received {}",
            first.manifest.threshold,
            shares.len()
        )));
    }
    let mut parsed = Vec::with_capacity(shares.len());
    let mut seen = [false; 256];
    for share in shares {
        validate_manifest(&share.manifest)?;
        if share.manifest != first.manifest {
            return Err(share_error("shares belong to different ceremonies"));
        }
        let index = share.share_index;
        if index == 0 || index > share.manifest.share_count || seen[index as usize] {
            return Err(share_error("share indices must be unique and within 1..=n"));
        }
        seen[index as usize] = true;
        let value = decode_fixed::<SECRET_BYTES>(&share.share_value, "share_value")?;
        let supplied_checksum = decode_fixed::<32>(&share.share_checksum, "share_checksum")?;
        if checksum(&share.manifest, index, &value)? != supplied_checksum {
            return Err(share_error(format!("share {index} checksum mismatch")));
        }
        parsed.push((index, value));
    }
    parsed.sort_by_key(|(index, _)| *index);
    let threshold = first.manifest.threshold as usize;
    let basis = &parsed[..threshold];
    let mut secret = Zeroizing::new([0u8; SECRET_BYTES]);
    for byte in 0..SECRET_BYTES {
        let points: Vec<(u8, u8)> = basis.iter().map(|(x, value)| (*x, value[byte])).collect();
        secret[byte] = interpolate_at(&points, 0)?;
        for (x, value) in parsed.iter().skip(threshold) {
            if interpolate_at(&points, *x)? != value[byte] {
                return Err(share_error(format!(
                    "share {x} is inconsistent with threshold set"
                )));
            }
        }
    }
    let mut classical_seed = [0u8; 32];
    let mut pq_seed = [0u8; 32];
    classical_seed.copy_from_slice(&secret[..32]);
    pq_seed.copy_from_slice(&secret[32..]);
    let keypair = ColdHybridKeypair::from_independent_seeds(classical_seed, pq_seed)
        .map_err(|e| share_error(e.to_string()))?;
    let public = keypair.public_key();
    let public = public.as_complete_hybrid();
    let expected_classical =
        decode_fixed::<32>(&first.manifest.cold_classical_pk, "cold_classical_pk")?;
    let expected_pq = hex::decode(&first.manifest.cold_pq_pk)
        .map_err(|_| share_error("cold_pq_pk is invalid hex"))?;
    if public.classical.0 != expected_classical || public.pq.0.as_slice() != expected_pq {
        return Err(share_error(
            "reconstructed secret does not match expected cold public key",
        ));
    }
    Ok(ColdKeysFile {
        classical_seed,
        pq_seed,
        classical_pk: expected_classical,
        pq_pk: expected_pq,
    })
}

/// Read and strictly decode one share file.
pub fn read_cold_share(path: &Path) -> KeystoreResult<ColdShareFile> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| KeystoreError::Io(format!("{}: {e}", path.display())))?;
    let share: ColdShareFile =
        serde_json::from_str(&json).map_err(|e| KeystoreError::Parse(e.to_string()))?;
    validate_manifest(&share.manifest)?;
    Ok(share)
}

/// Write one share with owner-only permissions and overwrite protection.
pub fn write_cold_share_secure(
    path: &Path,
    share: &ColdShareFile,
    force: bool,
) -> KeystoreResult<()> {
    if path.exists() && !force {
        return Err(KeystoreError::Io(format!(
            "{} already exists",
            path.display()
        )));
    }
    let json =
        serde_json::to_string_pretty(share).map_err(|e| KeystoreError::Parse(e.to_string()))?;
    write_keys_secure(
        path.to_str()
            .ok_or_else(|| KeystoreError::Io("share path is not UTF-8".into()))?,
        &json,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    struct IncrementingRng(u8);

    impl RngCore for IncrementingRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for IncrementingRng {}

    fn fixture() -> ColdKeysFile {
        let keypair = ColdHybridKeypair::from_independent_seeds([0x11; 32], [0x22; 32]).unwrap();
        let public = keypair.public_key();
        let public = public.as_complete_hybrid();
        ColdKeysFile {
            classical_seed: [0x11; 32],
            pq_seed: [0x22; 32],
            classical_pk: public.classical.0,
            pq_pk: public.pq.0.to_vec(),
        }
    }

    #[test]
    fn aes_field_vectors_and_interpolation_are_independent_oracles() {
        assert_eq!(gf_mul(0x57, 0x13), 0xfe);
        assert_eq!(gf_mul(0x53, 0xca), 0x01);
        let coefficients = [0x42, 0x19, 0xa7];
        let points = [
            (1, evaluate(&coefficients, 1)),
            (2, evaluate(&coefficients, 2)),
            (3, evaluate(&coefficients, 3)),
        ];
        assert_eq!(points, [(1, 0xfc), (2, 0xda), (3, 0x64)]);
        assert_eq!(interpolate_at(&points, 0).unwrap(), 0x42);
    }

    #[test]
    fn threshold_subsets_reconstruct_exact_original() {
        let keys = fixture();
        let mut rng = StdRng::from_seed([7; 32]);
        let ceremony = generate_cold_share_ceremony(&keys, [9; 32], 3, 5, 1234, &mut rng).unwrap();
        for first in 0..3 {
            for second in first + 1..4 {
                for third in second + 1..5 {
                    let shares = [
                        ceremony.shares[first].clone(),
                        ceremony.shares[second].clone(),
                        ceremony.shares[third].clone(),
                    ];
                    assert_eq!(reconstruct_cold_shares(&shares).unwrap(), keys);
                }
            }
        }
    }

    #[test]
    fn fixed_rng_end_to_end_vector() {
        let keys = fixture();
        let ceremony = generate_cold_share_ceremony(
            &keys,
            [0x33; 32],
            2,
            3,
            0x0102_0304_0506_0708,
            &mut IncrementingRng(0),
        )
        .unwrap();
        assert_eq!(
            ceremony.shares[0].share_value,
            "313033323534373639383b3a3d3c3f3e212023222524272629282b2a2d2c2f2e62636061666764656a6b68696e6f6c6d72737071767774757a7b78797e7f7c7d"
        );
        assert_eq!(
            ceremony.shares[0].share_checksum,
            "9e03726a5d619f6ed9f108bf054a38c1afa4293d684346c3c4a99d9ad6ac16c0"
        );
        assert_eq!(
            reconstruct_cold_shares(&ceremony.shares[1..]).unwrap(),
            keys
        );
    }

    #[test]
    fn fewer_than_threshold_is_rejected_and_one_byte_has_perfect_secrecy() {
        let keys = fixture();
        let mut rng = StdRng::from_seed([8; 32]);
        let ceremony = generate_cold_share_ceremony(&keys, [9; 32], 2, 3, 1234, &mut rng).unwrap();
        assert!(reconstruct_cold_shares(&ceremony.shares[..1]).is_err());

        // With one observation of a degree-one polynomial, every possible
        // secret byte has exactly one compatible slope.
        let x = 7u8;
        let observed = 0x91u8;
        for candidate_secret in 0u8..=255 {
            let slope = gf_mul(observed ^ candidate_secret, gf_inv(x).unwrap());
            assert_eq!(evaluate(&[candidate_secret, slope], x), observed);
        }

        // With two observations of a degree-two polynomial, every possible
        // secret byte likewise has exactly one compatible coefficient pair.
        let observations = [(5u8, 0x27u8), (11u8, 0xd4u8)];
        for candidate_secret in 0u8..=255 {
            let mut compatible_polynomials = 0usize;
            for linear in 0u8..=255 {
                let x = observations[0].0;
                let quadratic = gf_mul(
                    observations[0].1 ^ candidate_secret ^ gf_mul(linear, x),
                    gf_inv(gf_mul(x, x)).unwrap(),
                );
                if evaluate(&[candidate_secret, linear, quadratic], observations[1].0)
                    == observations[1].1
                {
                    compatible_polynomials += 1;
                }
            }
            assert_eq!(compatible_polynomials, 1);
        }
    }

    #[test]
    fn corruption_cross_ceremony_and_inconsistent_extra_share_fail_closed() {
        let keys = fixture();
        let mut rng_a = StdRng::from_seed([1; 32]);
        let mut rng_b = StdRng::from_seed([2; 32]);
        let a = generate_cold_share_ceremony(&keys, [9; 32], 2, 3, 1, &mut rng_a).unwrap();
        let b = generate_cold_share_ceremony(&keys, [9; 32], 2, 3, 1, &mut rng_b).unwrap();
        let mut corrupt = a.shares[0].clone();
        corrupt.share_value.replace_range(0..2, "ff");
        assert!(reconstruct_cold_shares(&[corrupt, a.shares[1].clone()]).is_err());
        assert!(reconstruct_cold_shares(&[a.shares[0].clone(), b.shares[1].clone()]).is_err());

        let mut malicious = a.shares[2].clone();
        malicious.share_value.replace_range(0..2, "00");
        let value = decode_fixed::<SECRET_BYTES>(&malicious.share_value, "share_value").unwrap();
        malicious.share_checksum =
            hex::encode(checksum(&malicious.manifest, malicious.share_index, &value).unwrap());
        assert!(
            reconstruct_cold_shares(&[a.shares[0].clone(), a.shares[1].clone(), malicious])
                .is_err()
        );

        // Even if an attacker recomputes the unkeyed checksum, a corrupted
        // threshold subset cannot silently reconstruct a different cold key.
        let mut threshold_only_tamper = a.shares[0].clone();
        threshold_only_tamper.share_value.replace_range(0..2, "00");
        let value = decode_fixed::<SECRET_BYTES>(&threshold_only_tamper.share_value, "share_value")
            .unwrap();
        threshold_only_tamper.share_checksum = hex::encode(
            checksum(
                &threshold_only_tamper.manifest,
                threshold_only_tamper.share_index,
                &value,
            )
            .unwrap(),
        );
        assert!(reconstruct_cold_shares(&[threshold_only_tamper, a.shares[1].clone()]).is_err());
    }

    #[test]
    fn threshold_and_unknown_json_fields_fail_closed() {
        let keys = fixture();
        let mut rng = StdRng::from_seed([3; 32]);
        assert!(generate_cold_share_ceremony(&keys, [0; 32], 1, 3, 0, &mut rng).is_err());
        assert!(generate_cold_share_ceremony(&keys, [0; 32], 4, 3, 0, &mut rng).is_err());
        let ceremony = generate_cold_share_ceremony(&keys, [0; 32], 2, 3, 0, &mut rng).unwrap();
        let mut value = serde_json::to_value(&ceremony.shares[0]).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), serde_json::json!(1));
        assert!(serde_json::from_value::<ColdShareFile>(value).is_err());
    }
}
