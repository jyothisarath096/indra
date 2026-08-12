//! On-wire cryptographic wrapper types.
//!
//! These types carry byte payloads and handle encode/decode.
//! Actual cryptographic operations (verify, sign) live in indra-crypto.

use crate::{
    codec::{ByteReader, Decode, Encode},
    error::IndraResult,
    types::primitives::{
        Bytes32, VariableBytes, MAX_CLASSICAL_SIG_BYTES, MAX_PQ_PK_BYTES, MAX_PQ_SIG_BYTES,
    },
};

/// Hybrid signature on the wire: Ed25519 + ML-DSA-87.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridSignature {
    /// Ed25519 signature (64 bytes).
    pub classical_sig: VariableBytes<MAX_CLASSICAL_SIG_BYTES>,
    /// ML-DSA-87 signature (4627 bytes).
    pub pq_sig: VariableBytes<MAX_PQ_SIG_BYTES>,
}

impl Encode for HybridSignature {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.classical_sig.encode(buf);
        self.pq_sig.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        self.classical_sig.encoded_len() + self.pq_sig.encoded_len()
    }
}

impl Decode for HybridSignature {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            classical_sig: VariableBytes::decode(r)?,
            pq_sig: VariableBytes::decode(r)?,
        })
    }
}

impl HybridSignature {
    /// Convert the wire signature into the crypto-layer representation.
    pub fn to_crypto_sig(&self) -> Result<indra_crypto::HybridSignature, String> {
        use indra_crypto::{
            ClassicalSignature, HybridSignature as CryptoSig, PqSignature, PQ_SIG_BYTES,
        };

        let classical_arr: [u8; 64] = self.classical_sig.as_slice().try_into().map_err(|_| {
            format!(
                "classical signature must be 64 bytes, got {}",
                self.classical_sig.len()
            )
        })?;

        let pq_arr: [u8; PQ_SIG_BYTES] = self.pq_sig.as_slice().try_into().map_err(|_| {
            format!(
                "pq signature must be {} bytes, got {}",
                PQ_SIG_BYTES,
                self.pq_sig.len()
            )
        })?;

        Ok(CryptoSig {
            classical: ClassicalSignature(classical_arr),
            pq: PqSignature(pq_arr),
        })
    }
}

/// Hybrid public key on the wire: Ed25519 + ML-DSA-87.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridPubKey {
    /// Ed25519 public key (32 bytes, fixed).
    pub classical_pk: Bytes32,
    /// ML-DSA-87 public key (2592 bytes).
    pub pq_pk: VariableBytes<MAX_PQ_PK_BYTES>,
}

impl Encode for HybridPubKey {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.classical_pk.encode(buf);
        self.pq_pk.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        32 + self.pq_pk.encoded_len()
    }
}

impl Decode for HybridPubKey {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            classical_pk: Bytes32::decode(r)?,
            pq_pk: VariableBytes::decode(r)?,
        })
    }
}

impl HybridPubKey {
    /// Convert the wire public key into the crypto-layer representation.
    pub fn to_crypto_pubkey(&self) -> Result<indra_crypto::HybridPublicKey, String> {
        use indra_crypto::{
            ClassicalPublicKey, HybridPublicKey as CryptoPk, PqPublicKey, PQ_PK_BYTES,
        };

        let pq_arr: [u8; PQ_PK_BYTES] = self.pq_pk.as_slice().try_into().map_err(|_| {
            format!(
                "pq public key must be {} bytes, got {}",
                PQ_PK_BYTES,
                self.pq_pk.len()
            )
        })?;

        Ok(CryptoPk {
            classical: ClassicalPublicKey(self.classical_pk.0),
            pq: PqPublicKey(pq_arr),
        })
    }
}

/// Validator cold-storage public key on the wire: Ed25519 + ML-DSA-87.
///
/// This is role-distinct from `HybridPubKey` while preserving its exact
/// component encodings and size checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColdHybridPubKey {
    /// Ed25519 public key (32 bytes, fixed).
    pub classical_pk: Bytes32,
    /// ML-DSA-87 public key (2592 bytes).
    pub pq_pk: VariableBytes<MAX_PQ_PK_BYTES>,
}

impl Encode for ColdHybridPubKey {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.classical_pk.encode(buf);
        self.pq_pk.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        32 + self.pq_pk.encoded_len()
    }
}

impl Decode for ColdHybridPubKey {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            classical_pk: Bytes32::decode(r)?,
            pq_pk: VariableBytes::decode(r)?,
        })
    }
}

impl ColdHybridPubKey {
    /// Convert the wire key into the role-specific crypto-layer representation.
    pub fn to_crypto_pubkey(&self) -> Result<indra_crypto::ColdHybridPublicKey, String> {
        let complete = HybridPubKey {
            classical_pk: self.classical_pk,
            pq_pk: self.pq_pk.clone(),
        }
        .to_crypto_pubkey()?;
        Ok(indra_crypto::ColdHybridPublicKey::from_complete_hybrid(
            complete,
        ))
    }
}

/// A single validator's PQ signature in the Quorum Certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PQVoteSig {
    /// Validator ID (SHA-256 of their hybrid public key bytes).
    pub validator_id: Bytes32,
    /// ML-DSA-87 signature (4627 bytes).
    pub pq_sig: VariableBytes<MAX_PQ_SIG_BYTES>,
}

impl Encode for PQVoteSig {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.validator_id.encode(buf);
        self.pq_sig.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        32 + self.pq_sig.encoded_len()
    }
}

impl Decode for PQVoteSig {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            validator_id: Bytes32::decode(r)?,
            pq_sig: VariableBytes::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Decode;

    #[test]
    fn hybrid_signature_round_trip() {
        let s = HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0xAAu8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0xBBu8; 4627]).unwrap(),
        };
        assert_eq!(
            s,
            HybridSignature::decode_exact(&s.encode_to_vec()).unwrap()
        );
    }

    #[test]
    fn cold_hybrid_pubkey_round_trip() {
        let keypair =
            indra_crypto::ColdHybridKeypair::from_independent_seeds([0x41; 32], [0x92; 32])
                .unwrap();
        let public = keypair.public_key();
        let cold = ColdHybridPubKey {
            classical_pk: Bytes32::from(public.as_complete_hybrid().classical.0),
            pq_pk: VariableBytes::from_slice(&public.as_complete_hybrid().pq.0).unwrap(),
        };

        let encoded = cold.encode_to_vec();
        assert_eq!(encoded.len(), 32 + 4 + indra_crypto::PQ_PK_BYTES);
        assert_eq!(cold, ColdHybridPubKey::decode_exact(&encoded).unwrap());
        assert_eq!(cold.to_crypto_pubkey().unwrap(), public);
    }

    #[test]
    fn pq_vote_sig_round_trip() {
        let s = PQVoteSig {
            validator_id: Bytes32::from([0x11u8; 32]),
            pq_sig: VariableBytes::from_slice(&[0xCCu8; 4627]).unwrap(),
        };
        assert_eq!(s, PQVoteSig::decode_exact(&s.encode_to_vec()).unwrap());
    }
}
