//! Authenticated Pedersen-verifiable cold-key sharing ceremonies.
//!
//! The 64 secret bytes are losslessly represented as four 128-bit limbs. Each
//! limb is shared by an independent Shamir polynomial over the Ristretto scalar
//! field. Hiding Pedersen coefficient commitments let one custodian verify one
//! share without reconstructing the secret or exposing a bare commitment to a
//! secret limb. The complete public manifest is signed by the validator's
//! registered hot hybrid identity.

use std::path::Path;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use indra_crypto::{
    hybrid::{
        ClassicalKeypair, ClassicalPublicKey, ClassicalSignature, ColdHybridKeypair, HybridKeypair,
        HybridPublicKey, HybridSignature, PqKeypair, PqPublicKey, PqSignature,
    },
    sha256, verify_hybrid, CLASSICAL_SIG_BYTES, PQ_PK_BYTES, PQ_SIG_BYTES,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    write_keys_secure, ColdKeysFile, KeysFile, KeystoreError, KeystoreResult, ValidatorKeys,
};

const SHARE_FORMAT: &str = "indra-cold-key-pedersen-share";
const SHARE_VERSION: u8 = 1;
const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"INDRA-COLD-SHARE-MANIFEST-v1";
const CHECKSUM_DOMAIN: &[u8] = b"INDRA-COLD-SHARE-CHECKSUM-v1";
const PEDERSEN_H_DOMAIN: &[u8] = b"INDRA-COLD-SHARE-PEDERSEN-H-v1";
const SECRET_BYTES: usize = 64;
const SECRET_LIMBS: usize = 4;
const LIMB_BYTES: usize = 16;
const SCALAR_BYTES: usize = 32;
const SHARE_BYTES: usize = SECRET_LIMBS * SCALAR_BYTES;

/// Public cold key expected independently by recovery policy or chain state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedColdPublicKey {
    /// Expected Ed25519 cold public key.
    pub classical: [u8; 32],
    /// Expected ML-DSA-87 cold public key.
    pub pq: Vec<u8>,
}

/// Public, hot-authenticated description of one cold-key sharing ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
pub struct ColdShareManifest {
    pub format: String,
    pub version: u8,
    pub ceremony_id: String,
    pub created_unix_seconds: u64,
    pub validator_id: String,
    pub hot_classical_pk: String,
    pub hot_pq_pk: String,
    pub cold_classical_pk: String,
    pub cold_pq_pk: String,
    pub threshold: u8,
    pub share_count: u8,
    /// Four rows of hiding Pedersen coefficient commitments.
    pub pedersen_commitments: Vec<Vec<String>>,
    pub hot_classical_signature: String,
    pub hot_pq_signature: String,
}

/// One authenticated, independently Pedersen-verifiable Shamir share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct ColdShareFile {
    #[serde(flatten)]
    pub manifest: ColdShareManifest,
    pub share_index: u8,
    pub share_value: String,
    pub blinding_value: String,
    pub share_checksum: String,
}

/// A generated public manifest and its complete secret share set.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
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

fn decode_fixed<const N: usize>(value: &str, field: &str) -> KeystoreResult<[u8; N]> {
    if value.len() != N * 2 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(share_error(format!(
            "{field} is not canonical lowercase hex"
        )));
    }
    let bytes = Zeroizing::new(
        hex::decode(value).map_err(|_| share_error(format!("{field} is invalid hex")))?,
    );
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| share_error(format!("{field} has the wrong length")))
}

fn decode_public_hex(value: &str, expected: usize, field: &str) -> KeystoreResult<Vec<u8>> {
    if value.len() != expected * 2 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(share_error(format!(
            "{field} is not canonical lowercase hex"
        )));
    }
    let bytes = hex::decode(value).map_err(|_| share_error(format!("{field} is invalid hex")))?;
    if bytes.len() != expected {
        return Err(share_error(format!("{field} has the wrong length")));
    }
    Ok(bytes)
}

fn hot_public(keys: &ValidatorKeys) -> KeystoreResult<HybridPublicKey> {
    let pq: [u8; PQ_PK_BYTES] = keys
        .hybrid_pq_pk
        .as_slice()
        .try_into()
        .map_err(|_| share_error("hot ML-DSA-87 public key has the wrong length"))?;
    Ok(HybridPublicKey {
        classical: ClassicalPublicKey(keys.hybrid_classical_pk),
        pq: PqPublicKey(pq),
    })
}

fn hot_keypair(keys: &KeysFile) -> KeystoreResult<HybridKeypair> {
    let classical = ClassicalKeypair::from_seed(&keys.ed25519_seed);
    let pq = PqKeypair::from_bytes(&keys.public.hybrid_pq_pk, &keys.ml_dsa_seed)
        .map_err(|error| share_error(error.to_string()))?;
    Ok(HybridKeypair::new(classical, pq))
}

fn manifest_signing_bytes(manifest: &ColdShareManifest) -> KeystoreResult<Zeroizing<Vec<u8>>> {
    let mut unsigned = manifest.clone();
    unsigned.hot_classical_signature.clear();
    unsigned.hot_pq_signature.clear();
    let encoded = serde_json::to_vec(&unsigned).map_err(|error| share_error(error.to_string()))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        MANIFEST_SIGNATURE_DOMAIN.len() + 4 + encoded.len(),
    ));
    bytes.extend_from_slice(MANIFEST_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn manifest_signature(manifest: &ColdShareManifest) -> KeystoreResult<HybridSignature> {
    Ok(HybridSignature {
        classical: ClassicalSignature(decode_fixed::<CLASSICAL_SIG_BYTES>(
            &manifest.hot_classical_signature,
            "hot_classical_signature",
        )?),
        pq: PqSignature(decode_fixed::<PQ_SIG_BYTES>(
            &manifest.hot_pq_signature,
            "hot_pq_signature",
        )?),
    })
}

fn pedersen_h() -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(PEDERSEN_H_DOMAIN)
}

fn parse_commitments(manifest: &ColdShareManifest) -> KeystoreResult<Vec<Vec<RistrettoPoint>>> {
    if manifest.pedersen_commitments.len() != SECRET_LIMBS {
        return Err(share_error(
            "Pedersen manifest must contain four polynomial rows",
        ));
    }
    manifest
        .pedersen_commitments
        .iter()
        .map(|row| {
            if row.len() != manifest.threshold as usize {
                return Err(share_error("Pedersen row length does not equal threshold"));
            }
            row.iter()
                .map(|encoded| {
                    let bytes = decode_fixed::<32>(encoded, "pedersen_commitment")?;
                    CompressedRistretto(bytes)
                        .decompress()
                        .ok_or_else(|| share_error("invalid compressed Ristretto commitment"))
                })
                .collect()
        })
        .collect()
}

fn validate_manifest_structure(manifest: &ColdShareManifest) -> KeystoreResult<()> {
    if manifest.format != SHARE_FORMAT || manifest.version != SHARE_VERSION {
        return Err(share_error("unsupported share format or version"));
    }
    validate_threshold(manifest.threshold, manifest.share_count)?;
    let validator_id = decode_fixed::<32>(&manifest.validator_id, "validator_id")?;
    let hot_classical = decode_fixed::<32>(&manifest.hot_classical_pk, "hot_classical_pk")?;
    decode_public_hex(&manifest.hot_pq_pk, PQ_PK_BYTES, "hot_pq_pk")?;
    decode_fixed::<32>(&manifest.cold_classical_pk, "cold_classical_pk")?;
    decode_public_hex(&manifest.cold_pq_pk, PQ_PK_BYTES, "cold_pq_pk")?;
    decode_fixed::<32>(&manifest.ceremony_id, "ceremony_id")?;
    manifest_signature(manifest)?;
    parse_commitments(manifest)?;
    if validator_id != sha256(&hot_classical) {
        return Err(share_error(
            "validator_id does not match hot Ed25519 identity",
        ));
    }
    Ok(())
}

/// Validate a manifest against independently known hot validator metadata.
pub fn validate_cold_share_manifest(
    manifest: &ColdShareManifest,
    expected_hot: &ValidatorKeys,
) -> KeystoreResult<()> {
    validate_manifest_structure(manifest)?;
    if manifest.validator_id != hex::encode(expected_hot.validator_id)
        || manifest.hot_classical_pk != hex::encode(expected_hot.hybrid_classical_pk)
        || manifest.hot_pq_pk != hex::encode(&expected_hot.hybrid_pq_pk)
    {
        return Err(share_error(
            "manifest hot identity does not match expected validator",
        ));
    }
    verify_hybrid(
        &manifest_signing_bytes(manifest)?,
        &manifest_signature(manifest)?,
        &hot_public(expected_hot)?,
    )
    .map_err(|_| share_error("manifest hot hybrid signature verification failed"))
}

fn random_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Scalar {
    let mut wide = Zeroizing::new([0u8; 64]);
    rng.fill_bytes(wide.as_mut());
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn secret_limbs(keys: &ColdKeysFile) -> [Scalar; SECRET_LIMBS] {
    let mut secret = Zeroizing::new([0u8; SECRET_BYTES]);
    secret[..32].copy_from_slice(&keys.classical_seed);
    secret[32..].copy_from_slice(&keys.pq_seed);
    std::array::from_fn(|limb| {
        let start = limb * LIMB_BYTES;
        let mut bytes = Zeroizing::new([0u8; LIMB_BYTES]);
        bytes.copy_from_slice(&secret[start..start + LIMB_BYTES]);
        Scalar::from(u128::from_le_bytes(*bytes))
    })
}

fn evaluate(coefficients: &[Scalar], x: Scalar) -> Scalar {
    coefficients
        .iter()
        .rev()
        .fold(Scalar::ZERO, |acc, coefficient| acc * x + coefficient)
}

fn encode_share(values: &[Scalar; SECRET_LIMBS]) -> String {
    let mut bytes = Zeroizing::new([0u8; SHARE_BYTES]);
    for (limb, value) in values.iter().enumerate() {
        let start = limb * SCALAR_BYTES;
        bytes[start..start + SCALAR_BYTES].copy_from_slice(value.as_bytes());
    }
    hex::encode(bytes.as_slice())
}

fn decode_share(value: &str) -> KeystoreResult<[Scalar; SECRET_LIMBS]> {
    let bytes = Zeroizing::new(decode_fixed::<SHARE_BYTES>(value, "share_value")?);
    let mut values = [Scalar::ZERO; SECRET_LIMBS];
    for (limb, output) in values.iter_mut().enumerate() {
        let start = limb * SCALAR_BYTES;
        let scalar_bytes = Zeroizing::new(
            bytes[start..start + SCALAR_BYTES]
                .try_into()
                .map_err(|_| share_error("share scalar has the wrong length"))?,
        );
        *output = Option::<Scalar>::from(Scalar::from_canonical_bytes(*scalar_bytes))
            .ok_or_else(|| share_error("share contains a non-canonical scalar"))?;
    }
    Ok(values)
}

fn checksum(
    manifest: &ColdShareManifest,
    index: u8,
    value: &str,
    blinding: &str,
) -> KeystoreResult<[u8; 32]> {
    let context = manifest_signing_bytes(manifest)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        CHECKSUM_DOMAIN.len() + context.len() + value.len() + blinding.len() + 1,
    ));
    bytes.extend_from_slice(CHECKSUM_DOMAIN);
    bytes.extend_from_slice(&context);
    bytes.push(index);
    bytes.extend_from_slice(value.as_bytes());
    bytes.extend_from_slice(blinding.as_bytes());
    Ok(sha256(&bytes))
}

/// Independently verify one custodian share without pooling or reconstruction.
pub fn verify_cold_share(
    share: &ColdShareFile,
    expected_hot: &ValidatorKeys,
) -> KeystoreResult<()> {
    validate_cold_share_manifest(&share.manifest, expected_hot)?;
    if share.share_index == 0 || share.share_index > share.manifest.share_count {
        return Err(share_error("share index is outside 1..=share_count"));
    }
    let supplied_checksum = decode_fixed::<32>(&share.share_checksum, "share_checksum")?;
    if checksum(
        &share.manifest,
        share.share_index,
        &share.share_value,
        &share.blinding_value,
    )? != supplied_checksum
    {
        return Err(share_error("share checksum mismatch"));
    }
    let values = Zeroizing::new(decode_share(&share.share_value)?);
    let blindings = Zeroizing::new(decode_share(&share.blinding_value)?);
    let commitments = parse_commitments(&share.manifest)?;
    let x = Scalar::from(u64::from(share.share_index));
    let h = pedersen_h();
    for limb in 0..SECRET_LIMBS {
        let expected = commitments[limb]
            .iter()
            .rev()
            .fold(RistrettoPoint::default(), |acc, commitment| {
                acc * x + commitment
            });
        let supplied = values[limb] * RISTRETTO_BASEPOINT_POINT + blindings[limb] * h;
        if supplied != expected {
            return Err(share_error(format!(
                "share {} fails Pedersen verification for limb {limb}",
                share.share_index
            )));
        }
    }
    Ok(())
}

/// Split the cold seeds using hot-authenticated Pedersen VSS.
pub fn generate_cold_share_ceremony<R: CryptoRng + RngCore>(
    keys: &ColdKeysFile,
    hot_keys: &KeysFile,
    threshold: u8,
    share_count: u8,
    created_unix_seconds: u64,
    rng: &mut R,
) -> KeystoreResult<ColdShareCeremony> {
    validate_threshold(threshold, share_count)?;
    keys.reconstruct()?;
    let mut ceremony_id = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(ceremony_id.as_mut());
    let secrets = Zeroizing::new(secret_limbs(keys));
    let mut polynomials =
        Zeroizing::new(vec![vec![Scalar::ZERO; threshold as usize]; SECRET_LIMBS]);
    let mut blinding_polynomials =
        Zeroizing::new(vec![vec![Scalar::ZERO; threshold as usize]; SECRET_LIMBS]);
    for limb in 0..SECRET_LIMBS {
        polynomials[limb][0] = secrets[limb];
        for coefficient in polynomials[limb].iter_mut().skip(1) {
            *coefficient = random_scalar(rng);
        }
        for coefficient in &mut blinding_polynomials[limb] {
            *coefficient = random_scalar(rng);
        }
    }
    let h = pedersen_h();
    let commitments: Vec<Vec<String>> = polynomials
        .iter()
        .zip(blinding_polynomials.iter())
        .map(|(polynomial, blinding_polynomial)| {
            polynomial
                .iter()
                .zip(blinding_polynomial.iter())
                .map(|(coefficient, blinding_coefficient)| {
                    hex::encode(
                        (coefficient * RISTRETTO_BASEPOINT_POINT + blinding_coefficient * h)
                            .compress()
                            .to_bytes(),
                    )
                })
                .collect()
        })
        .collect();
    let public = keys.reconstruct()?.public_key();
    let public = public.as_complete_hybrid();
    let mut manifest = ColdShareManifest {
        format: SHARE_FORMAT.to_string(),
        version: SHARE_VERSION,
        ceremony_id: hex::encode(ceremony_id.as_slice()),
        created_unix_seconds,
        validator_id: hex::encode(hot_keys.public.validator_id),
        hot_classical_pk: hex::encode(hot_keys.public.hybrid_classical_pk),
        hot_pq_pk: hex::encode(&hot_keys.public.hybrid_pq_pk),
        cold_classical_pk: hex::encode(public.classical.0),
        cold_pq_pk: hex::encode(public.pq.0),
        threshold,
        share_count,
        pedersen_commitments: commitments,
        hot_classical_signature: String::new(),
        hot_pq_signature: String::new(),
    };
    let signature = hot_keypair(hot_keys)?
        .sign(&manifest_signing_bytes(&manifest)?)
        .map_err(|error| share_error(error.to_string()))?;
    manifest.hot_classical_signature = hex::encode(signature.classical.0);
    manifest.hot_pq_signature = hex::encode(signature.pq.0);
    validate_cold_share_manifest(&manifest, &hot_keys.public)?;

    let mut values = Zeroizing::new(vec![[Scalar::ZERO; SECRET_LIMBS]; share_count as usize]);
    let mut blinding_values =
        Zeroizing::new(vec![[Scalar::ZERO; SECRET_LIMBS]; share_count as usize]);
    for (offset, share) in values.iter_mut().enumerate() {
        let x = Scalar::from((offset + 1) as u64);
        for limb in 0..SECRET_LIMBS {
            share[limb] = evaluate(&polynomials[limb], x);
            blinding_values[offset][limb] = evaluate(&blinding_polynomials[limb], x);
        }
    }
    let shares = values
        .iter()
        .zip(blinding_values.iter())
        .enumerate()
        .map(|(offset, (value, blinding_value))| {
            let index = (offset + 1) as u8;
            let encoded = Zeroizing::new(encode_share(value));
            let encoded_blinding = Zeroizing::new(encode_share(blinding_value));
            let share = ColdShareFile {
                manifest: manifest.clone(),
                share_index: index,
                share_checksum: hex::encode(checksum(
                    &manifest,
                    index,
                    &encoded,
                    &encoded_blinding,
                )?),
                share_value: encoded.to_string(),
                blinding_value: encoded_blinding.to_string(),
            };
            verify_cold_share(&share, &hot_keys.public)?;
            Ok(share)
        })
        .collect::<KeystoreResult<Vec<_>>>()?;
    Ok(ColdShareCeremony { manifest, shares })
}

fn interpolate_zero(points: &[(Scalar, Scalar)]) -> KeystoreResult<Scalar> {
    let mut result = Scalar::ZERO;
    for (i, (x_i, y_i)) in points.iter().enumerate() {
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for (j, (x_j, _)) in points.iter().enumerate() {
            if i != j {
                numerator *= -*x_j;
                denominator *= *x_i - *x_j;
            }
        }
        if denominator == Scalar::ZERO {
            return Err(share_error("duplicate interpolation point"));
        }
        result += y_i * numerator * denominator.invert();
    }
    Ok(result)
}

/// Reconstruct only after hot authentication, per-share VSS, and comparison
/// against an independently supplied expected cold public key.
pub fn reconstruct_cold_shares(
    shares: &[ColdShareFile],
    expected_hot: &ValidatorKeys,
    expected_cold: &ExpectedColdPublicKey,
) -> KeystoreResult<ColdKeysFile> {
    let first = shares
        .first()
        .ok_or_else(|| share_error("no shares supplied"))?;
    validate_cold_share_manifest(&first.manifest, expected_hot)?;
    if shares.len() < first.manifest.threshold as usize {
        return Err(share_error(format!(
            "need at least {} shares, received {}",
            first.manifest.threshold,
            shares.len()
        )));
    }
    if first.manifest.cold_classical_pk != hex::encode(expected_cold.classical)
        || first.manifest.cold_pq_pk != hex::encode(&expected_cold.pq)
    {
        return Err(share_error(
            "manifest cold key does not match independently expected key",
        ));
    }
    let mut parsed = Zeroizing::new(Vec::with_capacity(shares.len()));
    let mut seen = [false; 256];
    for share in shares {
        if share.manifest != first.manifest {
            return Err(share_error("shares belong to different ceremonies"));
        }
        verify_cold_share(share, expected_hot)?;
        let index = share.share_index;
        if seen[index as usize] {
            return Err(share_error("share indices must be unique"));
        }
        seen[index as usize] = true;
        parsed.push((index, decode_share(&share.share_value)?));
    }
    parsed.sort_by_key(|(index, _)| *index);
    let basis = &parsed[..first.manifest.threshold as usize];
    let mut secret = Zeroizing::new([0u8; SECRET_BYTES]);
    for limb in 0..SECRET_LIMBS {
        let points = Zeroizing::new(
            basis
                .iter()
                .map(|(index, values)| (Scalar::from(u64::from(*index)), values[limb]))
                .collect::<Vec<_>>(),
        );
        let scalar = Zeroizing::new(interpolate_zero(&points)?);
        let scalar_bytes = Zeroizing::new(scalar.to_bytes());
        if scalar_bytes[LIMB_BYTES..].iter().any(|byte| *byte != 0) {
            return Err(share_error(
                "reconstructed limb is outside the canonical 128-bit range",
            ));
        }
        let start = limb * LIMB_BYTES;
        secret[start..start + LIMB_BYTES].copy_from_slice(&scalar_bytes[..LIMB_BYTES]);
    }
    let mut classical_seed = Zeroizing::new([0u8; 32]);
    let mut pq_seed = Zeroizing::new([0u8; 32]);
    classical_seed.copy_from_slice(&secret[..32]);
    pq_seed.copy_from_slice(&secret[32..]);
    let keypair = ColdHybridKeypair::from_independent_seeds(*classical_seed, *pq_seed)
        .map_err(|error| share_error(error.to_string()))?;
    let public = keypair.public_key();
    let public = public.as_complete_hybrid();
    if public.classical.0 != expected_cold.classical || public.pq.0.as_slice() != expected_cold.pq {
        return Err(share_error(
            "reconstructed secret does not match expected cold public key",
        ));
    }
    Ok(ColdKeysFile {
        classical_seed: *classical_seed,
        pq_seed: *pq_seed,
        classical_pk: expected_cold.classical,
        pq_pk: expected_cold.pq.clone(),
    })
}

/// Read and strictly decode one canonical share file. Trust is established
/// separately by `verify_cold_share` against independently known hot metadata.
pub fn read_cold_share(path: &Path) -> KeystoreResult<ColdShareFile> {
    let json = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|error| KeystoreError::Io(format!("{}: {error}", path.display())))?,
    );
    let share: ColdShareFile =
        serde_json::from_str(&json).map_err(|error| KeystoreError::Parse(error.to_string()))?;
    validate_manifest_structure(&share.manifest)?;
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
    let json = Zeroizing::new(
        serde_json::to_string_pretty(share)
            .map_err(|error| KeystoreError::Parse(error.to_string()))?,
    );
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
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    fn hot_fixture(seed: [u8; 32]) -> KeysFile {
        crate::generate_from_master_seed("hot".into(), seed).unwrap()
    }

    fn cold_fixture() -> ColdKeysFile {
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

    fn expected(keys: &ColdKeysFile) -> ExpectedColdPublicKey {
        ExpectedColdPublicKey {
            classical: keys.classical_pk,
            pq: keys.pq_pk.clone(),
        }
    }

    fn ceremony() -> (KeysFile, ColdKeysFile, ColdShareCeremony) {
        let hot = hot_fixture([0x44; 32]);
        let cold = cold_fixture();
        let mut rng = StdRng::from_seed([7; 32]);
        let ceremony = generate_cold_share_ceremony(&cold, &hot, 3, 5, 1234, &mut rng).unwrap();
        (hot, cold, ceremony)
    }

    #[test]
    fn threshold_subsets_reconstruct_exact_original() {
        let (hot, cold, ceremony) = ceremony();
        for first in 0..3 {
            for second in first + 1..4 {
                for third in second + 1..5 {
                    let shares = [
                        ceremony.shares[first].clone(),
                        ceremony.shares[second].clone(),
                        ceremony.shares[third].clone(),
                    ];
                    assert_eq!(
                        reconstruct_cold_shares(&shares, &hot.public, &expected(&cold)).unwrap(),
                        cold
                    );
                }
            }
        }
    }

    #[test]
    fn one_custodian_detects_vss_inconsistent_share_without_pooling() {
        let (hot, _cold, ceremony) = ceremony();
        let mut tampered = ceremony.shares[0].clone();
        tampered.share_value.replace_range(0..2, "00");
        tampered.share_checksum = hex::encode(
            checksum(
                &tampered.manifest,
                tampered.share_index,
                &tampered.share_value,
                &tampered.blinding_value,
            )
            .unwrap(),
        );
        assert!(verify_cold_share(&tampered, &hot.public).is_err());

        let mut tampered_blinding = ceremony.shares[0].clone();
        tampered_blinding.blinding_value.replace_range(0..2, "00");
        tampered_blinding.share_checksum = hex::encode(
            checksum(
                &tampered_blinding.manifest,
                tampered_blinding.share_index,
                &tampered_blinding.share_value,
                &tampered_blinding.blinding_value,
            )
            .unwrap(),
        );
        assert!(verify_cold_share(&tampered_blinding, &hot.public).is_err());
    }

    #[test]
    fn substituted_or_tampered_manifest_is_rejected() {
        let (hot, cold, ceremony) = ceremony();
        let other = hot_fixture([0x55; 32]);
        assert!(validate_cold_share_manifest(&ceremony.manifest, &other.public).is_err());
        let mut tampered = ceremony.shares[0].clone();
        tampered.manifest.cold_classical_pk = hex::encode([0x99; 32]);
        assert!(verify_cold_share(&tampered, &hot.public).is_err());
        assert!(reconstruct_cold_shares(
            &ceremony.shares[..3],
            &hot.public,
            &ExpectedColdPublicKey {
                classical: [0x99; 32],
                pq: cold.pq_pk.clone(),
            }
        )
        .is_err());
    }

    #[test]
    fn pedersen_constant_commitment_is_hiding_and_rerandomized() {
        let (hot, cold, first) = ceremony();
        let commitments = parse_commitments(&first.manifest).unwrap();
        let limbs = Zeroizing::new(secret_limbs(&cold));
        for limb in 0..SECRET_LIMBS {
            let bare_secret_commitment = limbs[limb] * RISTRETTO_BASEPOINT_POINT;
            assert_ne!(commitments[limb][0], bare_secret_commitment);
        }

        let mut rng = StdRng::from_seed([8; 32]);
        let second = generate_cold_share_ceremony(&cold, &hot, 3, 5, 1234, &mut rng).unwrap();
        assert_ne!(
            first.manifest.pedersen_commitments,
            second.manifest.pedersen_commitments
        );
        assert_ne!(pedersen_h(), RistrettoPoint::default());
        assert_ne!(pedersen_h(), RISTRETTO_BASEPOINT_POINT);
    }

    #[test]
    fn threshold_and_unknown_fields_fail_closed() {
        let hot = hot_fixture([0x44; 32]);
        let cold = cold_fixture();
        let mut rng = StdRng::from_seed([3; 32]);
        assert!(generate_cold_share_ceremony(&cold, &hot, 1, 3, 0, &mut rng).is_err());
        assert!(generate_cold_share_ceremony(&cold, &hot, 4, 3, 0, &mut rng).is_err());
        let ceremony = generate_cold_share_ceremony(&cold, &hot, 2, 3, 0, &mut rng).unwrap();
        let mut value = serde_json::to_value(&ceremony.shares[0]).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), serde_json::json!(1));
        assert!(serde_json::from_value::<ColdShareFile>(value).is_err());
    }

    struct PanicZeroizeProbe {
        observed: Arc<AtomicBool>,
    }

    impl Zeroize for PanicZeroizeProbe {
        fn zeroize(&mut self) {
            self.observed.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn zeroizing_runs_during_panic_unwind() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<ColdShareFile>();
        assert_zeroize_on_drop::<ColdShareCeremony>();
        assert_zeroize_on_drop::<ColdKeysFile>();
        assert_zeroize_on_drop::<PqKeypair>();
        let observed = Arc::new(AtomicBool::new(false));
        let result = std::panic::catch_unwind({
            let observed = observed.clone();
            move || {
                let _secret = Zeroizing::new(PanicZeroizeProbe { observed });
                panic!("injected ceremony failure");
            }
        });
        assert!(result.is_err());
        assert!(observed.load(Ordering::SeqCst));
    }

    #[test]
    fn no_custom_branching_gf256_arithmetic_remains() {
        let source = include_str!("cold_shamir.rs");
        assert!(!source.contains(&["fn", "gf_mul"].join(" ")));
        assert!(!source.contains(&["fn", "gf_inv"].join(" ")));
    }
}
