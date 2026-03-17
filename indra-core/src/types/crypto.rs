//! On-wire cryptographic wrapper types.
//!
//! These types carry byte payloads and handle encode/decode.
//! Actual cryptographic operations (verify, sign) live in indra-crypto.

use crate::{
    codec::{Encode, Decode, ByteReader},
    error::IndraResult,
    types::primitives::{
        Bytes32, VariableBytes,
        MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES, MAX_PQ_PK_BYTES,
    },
};

/// Hybrid signature on the wire: Ed25519 + Dilithium2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridSignature {
    /// Ed25519 signature (64 bytes).
    pub classical_sig: VariableBytes<MAX_CLASSICAL_SIG_BYTES>,
    /// Dilithium2 signature (~2420 bytes).
    pub pq_sig:        VariableBytes<MAX_PQ_SIG_BYTES>,
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
            pq_sig:        VariableBytes::decode(r)?,
        })
    }
}

/// Hybrid public key on the wire: Ed25519 + Dilithium2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridPubKey {
    /// Ed25519 public key (32 bytes, fixed).
    pub classical_pk: Bytes32,
    /// Dilithium2 public key (~1312 bytes).
    pub pq_pk:        VariableBytes<MAX_PQ_PK_BYTES>,
}

impl Encode for HybridPubKey {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.classical_pk.encode(buf);
        self.pq_pk.encode(buf);
    }
    fn encoded_len(&self) -> usize { 32 + self.pq_pk.encoded_len() }
}

impl Decode for HybridPubKey {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            classical_pk: Bytes32::decode(r)?,
            pq_pk:        VariableBytes::decode(r)?,
        })
    }
}

/// Pedersen commitment (compressed Ristretto255 point, 32 bytes).
///
/// Commitment = v·G + r·H
/// The 32-byte compressed point reveals nothing about v or r.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CommitmentV1 {
    /// Compressed Ristretto255 point.
    pub compressed_point: Bytes32,
}

impl Encode for CommitmentV1 {
    fn encode(&self, buf: &mut Vec<u8>) { self.compressed_point.encode(buf); }
    fn encoded_len(&self) -> usize { 32 }
}

impl Decode for CommitmentV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self { compressed_point: Bytes32::decode(r)? })
    }
}

/// A single validator's PQ signature in the Quorum Certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PQVoteSig {
    /// Validator ID (SHA-256 of their hybrid public key bytes).
    pub validator_id: Bytes32,
    /// Dilithium2 signature (~2420 bytes).
    pub pq_sig:       VariableBytes<MAX_PQ_SIG_BYTES>,
}

impl Encode for PQVoteSig {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.validator_id.encode(buf);
        self.pq_sig.encode(buf);
    }
    fn encoded_len(&self) -> usize { 32 + self.pq_sig.encoded_len() }
}

impl Decode for PQVoteSig {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            validator_id: Bytes32::decode(r)?,
            pq_sig:       VariableBytes::decode(r)?,
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
            pq_sig:        VariableBytes::from_slice(&[0xBBu8; 2420]).unwrap(),
        };
        assert_eq!(s, HybridSignature::decode_exact(&s.encode_to_vec()).unwrap());
    }

    #[test]
    fn commitment_round_trip() {
        let c = CommitmentV1 { compressed_point: Bytes32::from([0x55u8; 32]) };
        let enc = c.encode_to_vec();
        assert_eq!(enc.len(), 32);
        assert_eq!(c, CommitmentV1::decode_exact(&enc).unwrap());
    }

    #[test]
    fn pq_vote_sig_round_trip() {
        let s = PQVoteSig {
            validator_id: Bytes32::from([0x11u8; 32]),
            pq_sig:       VariableBytes::from_slice(&[0xCCu8; 2420]).unwrap(),
        };
        assert_eq!(s, PQVoteSig::decode_exact(&s.encode_to_vec()).unwrap());
    }
}
