//! BLS12-381 signature aggregation for Quorum Certificates.
//!
//! N validator Ed25519-equivalent signatures → 48 bytes total.
//! This makes QC overhead viable at 1500 validators on 50 Mbps.
//!
//! Only used for the classical component of QCs. The PQ (ML-DSA-87)
//! component uses individual sigs because Dilithium is not aggregatable.

use blst::min_pk::{PublicKey, SecretKey, Signature, AggregateSignature};
use blst::BLST_ERROR;

use crate::{
    constants::{BLS_PK_BYTES},
    error::{CryptoError, CryptoResult},
};

/// Domain Separation Tag — prevents cross-protocol signature reuse.
const DST: &[u8] = b"INDRA-BLS12381-G2-SHA256-v1";

/// A BLS12-381 public key (48 bytes, G1 point in min_pk mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlsPublicKey(pub [u8; BLS_PK_BYTES]);

/// A single BLS12-381 signature (96 bytes in min_pk mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlsSignature(pub Vec<u8>);

/// An aggregated BLS12-381 signature (same 96 bytes, covers N signers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlsAggregateSignature(pub Vec<u8>);

/// A BLS12-381 signing keypair.
pub struct BlsKeypair {
    sk: SecretKey,
    pk: PublicKey,
}

impl BlsKeypair {
    /// Create from a 32-byte IKM seed (must be cryptographically random).
    pub fn from_seed(seed: &[u8; 32]) -> CryptoResult<Self> {
        let sk = SecretKey::key_gen(seed, &[])
            .map_err(|_| CryptoError::BlsFailed { detail: "key_gen failed" })?;
        let pk = sk.sk_to_pk();
        Ok(Self { sk, pk })
    }

    /// Return the public key.
    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey(self.pk.to_bytes())
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        let sig = self.sk.sign(message, DST, &[]);
        BlsSignature(sig.to_bytes().to_vec())
    }
}

/// Aggregate multiple BLS signatures into one.
///
/// All signers must have signed the SAME message.
/// In the QC context the message is: SHA-256(height || round || block_hash).
pub fn aggregate_signatures(sigs: &[BlsSignature]) -> CryptoResult<BlsAggregateSignature> {
    if sigs.is_empty() {
        return Err(CryptoError::EmptySignerSet);
    }
    let parsed: Vec<Signature> = sigs.iter()
        .map(|s| Signature::from_bytes(&s.0)
            .map_err(|_| CryptoError::MalformedSignature {
                scheme: "BLS12-381",
                actual: s.0.len(),
            }))
        .collect::<CryptoResult<_>>()?;

    let refs: Vec<&Signature> = parsed.iter().collect();
    let agg = AggregateSignature::aggregate(&refs, true)
        .map_err(|_| CryptoError::BlsFailed { detail: "aggregation failed" })?;

    Ok(BlsAggregateSignature(agg.to_signature().to_bytes().to_vec()))
}

/// Verify an aggregated BLS signature against multiple public keys on the same message.
pub fn verify_aggregate(
    message: &[u8],
    agg_sig: &BlsAggregateSignature,
    public_keys: &[BlsPublicKey],
) -> CryptoResult<()> {
    if public_keys.is_empty() {
        return Err(CryptoError::EmptySignerSet);
    }
    let sig = Signature::from_bytes(&agg_sig.0)
        .map_err(|_| CryptoError::MalformedSignature {
            scheme: "BLS12-381 aggregate",
            actual: agg_sig.0.len(),
        })?;

    let parsed_pks: Vec<PublicKey> = public_keys.iter()
        .map(|pk| PublicKey::from_bytes(&pk.0)
            .map_err(|_| CryptoError::MalformedPublicKey {
                scheme: "BLS12-381",
                actual: pk.0.len(),
            }))
        .collect::<CryptoResult<_>>()?;

    let pk_refs: Vec<&PublicKey> = parsed_pks.iter().collect();
    let msgs: Vec<&[u8]> = vec![message; pk_refs.len()];

    match sig.aggregate_verify(true, &msgs, DST, &pk_refs, true) {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err(CryptoError::BlsFailed { detail: "aggregate_verify failed" }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(seed_byte: u8) -> BlsKeypair {
        BlsKeypair::from_seed(&[seed_byte; 32]).unwrap()
    }

    #[test]
    fn single_sign_and_verify() {
        let k = kp(0x01);
        let msg = b"INDRA QC height=1 round=0";
        let sig = k.sign(msg);
        let agg = aggregate_signatures(&[sig]).unwrap();
        assert!(verify_aggregate(msg, &agg, &[k.public_key()]).is_ok());
    }

    #[test]
    fn multi_signer_aggregate_verify() {
        let k1 = kp(0x01);
        let k2 = kp(0x02);
        let k3 = kp(0x03);
        let msg = b"INDRA QC consensus message";
        let agg = aggregate_signatures(&[k1.sign(msg), k2.sign(msg), k3.sign(msg)]).unwrap();
        let pks = vec![k1.public_key(), k2.public_key(), k3.public_key()];
        assert!(verify_aggregate(msg, &agg, &pks).is_ok());
    }

    #[test]
    fn wrong_message_fails() {
        let k = kp(0x10);
        let agg = aggregate_signatures(&[k.sign(b"signed this")]).unwrap();
        assert!(verify_aggregate(b"not this", &agg, &[k.public_key()]).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = kp(0x11);
        let k2 = kp(0x12);
        let msg = b"test";
        let agg = aggregate_signatures(&[k1.sign(msg)]).unwrap();
        assert!(verify_aggregate(msg, &agg, &[k2.public_key()]).is_err());
    }

    #[test]
    fn empty_signer_set_errors() {
        assert!(aggregate_signatures(&[]).is_err());
    }

    #[test]
    fn aggregate_is_96_bytes() {
        let k = kp(0xFF);
        let agg = aggregate_signatures(&[k.sign(b"size")]).unwrap();
        assert_eq!(agg.0.len(), 96); // G2 sig in min_pk mode
    }
}
