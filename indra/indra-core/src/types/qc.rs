//! Quorum Certificate — proof that ≥ 2/3 stake precommitted to a block.
//!
//! INDRA QCs are hybrid: they contain one ML-DSA-87 signature and one Ed25519
//! signature per signer plus a signer bitfield, and no BLS aggregate signature.

use crate::{
    codec::{decode_list, encode_list, list_encoded_len, ByteReader, Decode, Encode},
    error::IndraResult,
    types::{
        crypto::PQVoteSig,
        primitives::{
            Bytes32, VariableBytes, MAX_CLASSICAL_SIG_BYTES, MAX_QC_SIGNERS, MAX_VALIDATORS,
        },
    },
};

/// Bytes needed for the signer bitfield. ceil(MAX_VALIDATORS / 8).
pub const SIGNER_BITFIELD_BYTES: usize = MAX_VALIDATORS.div_ceil(8);

/// Ed25519 vote signature carried inside a hybrid quorum certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassicalVoteSig {
    /// Validator whose vote signature this is.
    pub validator_id: Bytes32,
    /// Ed25519 signature bytes.
    pub classical_sig: VariableBytes<MAX_CLASSICAL_SIG_BYTES>,
}

impl Encode for ClassicalVoteSig {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.validator_id.encode(buf);
        self.classical_sig.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        32 + self.classical_sig.encoded_len()
    }
}

impl Decode for ClassicalVoteSig {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            validator_id: Bytes32::decode(r)?,
            classical_sig: VariableBytes::decode(r)?,
        })
    }
}

/// A Quorum Certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumCertificateV1 {
    /// Block height this QC certifies.
    pub height: u64,
    /// Round in which finalisation occurred.
    pub round: u32,
    /// Certified consensus value hash.
    ///
    /// The field name remains `block_hash` for compatibility with existing QC
    /// encoding, but it now carries the stable `value_hash`.
    pub block_hash: Bytes32,
    /// Bitfield: bit i = 1 → validator at slot i signed.
    pub signer_bitfield: [u8; SIGNER_BITFIELD_BYTES],
    /// Individual ML-DSA-87 signatures for included validators.
    pub pq_signatures: Vec<PQVoteSig>,
    /// Individual Ed25519 signatures for included validators.
    pub classical_signatures: Vec<ClassicalVoteSig>,
}

impl QuorumCertificateV1 {
    /// Count the number of signers indicated by the bitfield.
    pub fn signer_count(&self) -> usize {
        self.signer_bitfield
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum()
    }

    /// Return true if the validator at `slot` is marked as a signer.
    pub fn is_signer(&self, slot: usize) -> bool {
        if slot >= MAX_VALIDATORS {
            return false;
        }
        self.signer_bitfield
            .get(slot / 8)
            .map(|byte| (byte >> (slot % 8)) & 1 == 1)
            .unwrap_or(false)
    }
}

impl Encode for QuorumCertificateV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.height.encode(buf);
        self.round.encode(buf);
        self.block_hash.encode(buf);
        buf.extend_from_slice(&self.signer_bitfield);
        encode_list(&self.pq_signatures, buf);
        encode_list(&self.classical_signatures, buf);
    }
    fn encoded_len(&self) -> usize {
        8 + 4
            + 32
            + SIGNER_BITFIELD_BYTES
            + list_encoded_len(&self.pq_signatures)
            + list_encoded_len(&self.classical_signatures)
    }
}

impl Decode for QuorumCertificateV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let height = u64::decode(r)?;
        let round = u32::decode(r)?;
        let block_hash = Bytes32::decode(r)?;
        let bf_bytes = r.read_bytes(SIGNER_BITFIELD_BYTES)?;
        let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
        signer_bitfield.copy_from_slice(bf_bytes);
        let pq_signatures = decode_list(r, MAX_QC_SIGNERS, "pq_signatures")?;
        let classical_signatures = decode_list(r, MAX_QC_SIGNERS, "classical_signatures")?;
        Ok(Self {
            height,
            round,
            block_hash,
            signer_bitfield,
            pq_signatures,
            classical_signatures,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Decode;

    fn dummy_qc() -> QuorumCertificateV1 {
        QuorumCertificateV1 {
            height: 1_000,
            round: 0,
            block_hash: Bytes32::from([0x77u8; 32]),
            signer_bitfield: [0b11111111u8; SIGNER_BITFIELD_BYTES],
            pq_signatures: vec![],
            classical_signatures: vec![],
        }
    }

    #[test]
    fn qc_round_trip() {
        let qc = dummy_qc();
        assert_eq!(
            qc,
            QuorumCertificateV1::decode_exact(&qc.encode_to_vec()).unwrap()
        );
    }

    #[test]
    fn bitfield_size_is_correct() {
        // ceil(1500/8) = 188
        assert_eq!(SIGNER_BITFIELD_BYTES, 188);
    }

    #[test]
    fn is_signer_checks_bit() {
        let mut qc = dummy_qc();
        qc.signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
        qc.signer_bitfield[0] = 0b00000001; // bit 0 set
        assert!(qc.is_signer(0));
        assert!(!qc.is_signer(1));
    }

    #[test]
    fn out_of_bounds_slot_is_false() {
        let qc = dummy_qc();
        assert!(!qc.is_signer(MAX_VALIDATORS));
        assert!(!qc.is_signer(usize::MAX));
    }
}
