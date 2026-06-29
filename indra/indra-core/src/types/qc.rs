//! Quorum Certificate — proof that ≥ 2/3 stake precommitted to a block.
//!
//! INDRA QCs are hybrid: they contain one ML-DSA-87 signature and one Ed25519
//! signature per signer plus a signer bitfield, and no BLS aggregate signature.

use crate::{
    codec::{decode_list, encode_list, list_encoded_len, ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    types::{
        crypto::PQVoteSig,
        primitives::{
            hybrid_qc_active, Bytes32, VariableBytes, MAX_CLASSICAL_SIG_BYTES, MAX_QC_SIGNERS,
            MAX_VALIDATORS,
        },
    },
};

/// Bytes needed for the signer bitfield. ceil(MAX_VALIDATORS / 8).
pub const SIGNER_BITFIELD_BYTES: usize = MAX_VALIDATORS.div_ceil(8);
/// QC format version for pre-hybrid PQ-only signatures.
pub const QC_FORMAT_LEGACY: u8 = 1;
/// QC format version for hybrid PQ + Ed25519 signatures.
pub const QC_FORMAT_HYBRID: u8 = 2;

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
    /// Certified full block hash.
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
        if hybrid_qc_active(self.height) {
            QC_FORMAT_HYBRID.encode(buf);
        } else {
            QC_FORMAT_LEGACY.encode(buf);
        }
        self.height.encode(buf);
        self.round.encode(buf);
        self.block_hash.encode(buf);
        buf.extend_from_slice(&self.signer_bitfield);
        encode_list(&self.pq_signatures, buf);
        if hybrid_qc_active(self.height) {
            encode_list(&self.classical_signatures, buf);
        }
    }
    fn encoded_len(&self) -> usize {
        1 + 8
            + 4
            + 32
            + SIGNER_BITFIELD_BYTES
            + list_encoded_len(&self.pq_signatures)
            + if hybrid_qc_active(self.height) {
                list_encoded_len(&self.classical_signatures)
            } else {
                0
            }
    }
}

impl Decode for QuorumCertificateV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let format = u8::decode(r)?;
        if !matches!(format, QC_FORMAT_LEGACY | QC_FORMAT_HYBRID) {
            return Err(IndraError::InvalidQcFormat { format });
        }
        let height = u64::decode(r)?;
        let round = u32::decode(r)?;
        let block_hash = Bytes32::decode(r)?;
        let bf_bytes = r.read_bytes(SIGNER_BITFIELD_BYTES)?;
        let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
        signer_bitfield.copy_from_slice(bf_bytes);
        let pq_signatures = decode_list(r, MAX_QC_SIGNERS, "pq_signatures")?;
        let classical_signatures = if format == QC_FORMAT_HYBRID {
            decode_list(r, MAX_QC_SIGNERS, "classical_signatures")?
        } else {
            Vec::new()
        };
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
    fn legacy_qc_encodes_and_decodes_without_classical_sigs() {
        let qc = QuorumCertificateV1 {
            height: 1,
            round: 0,
            block_hash: Bytes32::from([0x01; 32]),
            signer_bitfield: [0u8; SIGNER_BITFIELD_BYTES],
            pq_signatures: vec![],
            classical_signatures: vec![],
        };

        let mut buf = Vec::new();
        QC_FORMAT_LEGACY.encode(&mut buf);
        qc.height.encode(&mut buf);
        qc.round.encode(&mut buf);
        qc.block_hash.encode(&mut buf);
        buf.extend_from_slice(&qc.signer_bitfield);
        encode_list(&qc.pq_signatures, &mut buf);

        let decoded = QuorumCertificateV1::decode_exact(&buf).unwrap();
        assert_eq!(decoded.height, qc.height);
        assert_eq!(decoded.round, qc.round);
        assert_eq!(decoded.block_hash, qc.block_hash);
        assert_eq!(decoded.pq_signatures, qc.pq_signatures);
        assert!(decoded.classical_signatures.is_empty());
    }

    #[test]
    fn hybrid_qc_encodes_and_decodes_with_classical_sigs() {
        let qc = QuorumCertificateV1 {
            height: 1,
            round: 0,
            block_hash: Bytes32::from([0x01; 32]),
            signer_bitfield: [0u8; SIGNER_BITFIELD_BYTES],
            pq_signatures: vec![],
            classical_signatures: vec![ClassicalVoteSig {
                validator_id: Bytes32::from([0x01; 32]),
                classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            }],
        };

        let encoded = qc.encode_to_vec();
        assert_eq!(encoded.first().copied(), Some(QC_FORMAT_HYBRID));
        assert_eq!(qc.encoded_len(), encoded.len());
        let decoded = QuorumCertificateV1::decode_exact(&encoded).unwrap();
        assert_eq!(decoded.classical_signatures.len(), 1);
        assert_eq!(decoded, qc);
    }

    #[test]
    fn unknown_qc_format_version_rejected() {
        let mut buf = Vec::new();
        0xFFu8.encode(&mut buf);
        buf.extend_from_slice(&[0u8; 44]);
        assert!(QuorumCertificateV1::decode_exact(&buf).is_err());
    }

    #[test]
    fn legacy_pq_only_qc_bytes_without_version_fail_gracefully() {
        let mut legacy = Vec::new();
        3u64.encode(&mut legacy);
        0u32.encode(&mut legacy);
        Bytes32::from([0xAB; 32]).encode(&mut legacy);
        legacy.extend_from_slice(&{
            let mut bitfield = [0u8; SIGNER_BITFIELD_BYTES];
            bitfield[0] = 0b0000_0111;
            bitfield
        });
        let pq_signatures = vec![
            PQVoteSig {
                validator_id: Bytes32::from([0x01; 32]),
                pq_sig: VariableBytes::from_slice(&[0x11; 32]).unwrap(),
            },
            PQVoteSig {
                validator_id: Bytes32::from([0x02; 32]),
                pq_sig: VariableBytes::from_slice(&[0x22; 32]).unwrap(),
            },
            PQVoteSig {
                validator_id: Bytes32::from([0x03; 32]),
                pq_sig: VariableBytes::from_slice(&[0x33; 32]).unwrap(),
            },
        ];
        encode_list(&pq_signatures, &mut legacy);

        assert!(
            QuorumCertificateV1::decode_exact(&legacy).is_err(),
            "old QC format without version byte must return Err"
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
