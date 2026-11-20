//! Quorum Certificate — proof that ≥ 2/3 stake precommitted to a block.
//!
//! INDRA QCs are hybrid: they contain one ML-DSA-87 signature and one Ed25519
//! signature per signer plus a signer bitfield, and no BLS aggregate signature.

use crate::types::{consensus_snapshot::ConsensusSnapshot, vote::VoteStep};
use crate::{
    codec::{decode_list, encode_list, list_encoded_len, ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    types::{
        crypto::{decode_fixed_signature, PQVoteSig},
        primitives::{
            Bytes32, VariableBytes, MAX_CLASSICAL_SIG_BYTES, MAX_QC_SIGNERS, MAX_VALIDATORS,
        },
    },
};
use indra_crypto::hybrid::{
    verify_classical, verify_pq, ClassicalPublicKey, ClassicalSignature, PqPublicKey, PqSignature,
};
use std::collections::{HashMap, HashSet};

/// Bytes needed for the signer bitfield. ceil(MAX_VALIDATORS / 8).
pub const SIGNER_BITFIELD_BYTES: usize = MAX_VALIDATORS.div_ceil(8);
/// QC format version for pre-hybrid PQ-only signatures.
/// QC format version for hybrid PQ + Ed25519 signatures.
pub const QC_FORMAT_HYBRID: u8 = 3;

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
            classical_sig: decode_fixed_signature::<{ indra_crypto::CLASSICAL_SIG_BYTES }>(
                r,
                "QC classical signature",
            )?,
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
    /// Root of the immutable consensus snapshot governing `height`.
    pub snapshot_root: Bytes32,
    /// Bitfield: bit i = 1 → validator at slot i signed.
    pub signer_bitfield: [u8; SIGNER_BITFIELD_BYTES],
    /// Individual ML-DSA-87 signatures for included validators.
    pub pq_signatures: Vec<PQVoteSig>,
    /// Individual Ed25519 signatures for included validators.
    pub classical_signatures: Vec<ClassicalVoteSig>,
}

/// Cryptographically verified QC authority, bound to one immutable snapshot.
///
/// Fields are private so state-transition callers cannot manufacture signer
/// attribution without passing the canonical hybrid-signature verifier.
#[derive(Debug, Clone)]
pub struct VerifiedQc {
    height: u64,
    block_hash: Bytes32,
    signer_ids: Vec<Bytes32>,
    encoded_qc: Vec<u8>,
}

impl VerifiedQc {
    /// Certified height.
    pub fn height(&self) -> u64 {
        self.height
    }
    /// Certified block hash.
    pub fn block_hash(&self) -> Bytes32 {
        self.block_hash
    }
    /// Validator IDs whose hybrid signatures were verified.
    pub fn signer_ids(&self) -> &[Bytes32] {
        &self.signer_ids
    }
    /// Whether this capability was minted from these exact canonical QC bytes.
    pub fn matches_encoded_qc(&self, bytes: &[u8]) -> bool {
        self.encoded_qc == bytes
    }
}

/// Failure from authoritative QC verification against a frozen snapshot.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QcVerificationError {
    /// QC round lies outside the finite consensus domain.
    #[error("QC contains an invalid consensus round")]
    InvalidRound,
    /// Chain identifiers cannot be represented in the vote-signing encoding.
    #[error("chain id longer than 65535 bytes")]
    InvalidChainId,
    /// QC names a snapshot other than the supplied governing snapshot.
    #[error("QC snapshot root does not match the governing snapshot")]
    SnapshotRootMismatch,
    /// A set bit has no corresponding snapshot member.
    #[error("QC signer bitfield references an absent validator")]
    UnknownSignerPosition,
    /// Verified signer weight is not strictly greater than two thirds.
    #[error("QC signed stake does not exceed two thirds")]
    InsufficientStake,
    /// One validator appears more than once in a signature list.
    #[error("QC contains a duplicate signer signature")]
    DuplicateSignature,
    /// Signature-list length disagrees with the signer bitfield.
    #[error("QC signature count does not match its signer bitfield")]
    SignatureCountMismatch,
    /// A bitfield signer lacks one component signature.
    #[error("QC is missing a signer signature")]
    MissingSignature,
    /// An ML-DSA-87 signature is malformed or invalid.
    #[error("QC contains an invalid ML-DSA-87 signature")]
    InvalidPqSignature,
    /// An Ed25519 signature is malformed or invalid.
    #[error("QC contains an invalid Ed25519 signature")]
    InvalidClassicalSignature,
}

/// Verify every hybrid vote signature and the exact strict-two-thirds stake
/// threshold against the immutable authority snapshot governing `qc.height`.
pub fn verify_qc_against_snapshot(
    qc: &QuorumCertificateV1,
    snapshot: &ConsensusSnapshot,
    chain_id: &str,
) -> Result<VerifiedQc, QcVerificationError> {
    crate::types::primitives::validate_consensus_round(qc.round)
        .map_err(|_| QcVerificationError::InvalidRound)?;
    if qc.snapshot_root != snapshot.snapshot_root {
        return Err(QcVerificationError::SnapshotRootMismatch);
    }
    let mut signers = Vec::new();
    for (byte_index, byte) in qc.signer_bitfield.iter().copied().enumerate() {
        for bit_index in 0..8 {
            let position = byte_index * 8 + bit_index;
            if position >= crate::types::primitives::MAX_VALIDATORS {
                break;
            }
            if (byte >> bit_index) & 1 == 1 {
                signers.push(
                    snapshot
                        .entries()
                        .get(position)
                        .ok_or(QcVerificationError::UnknownSignerPosition)?,
                );
            }
        }
    }
    let signed_stake = signers.iter().fold(0u64, |sum, entry| {
        sum.saturating_add(entry.consensus_weight_spark)
    });
    if !crate::types::primitives::has_strict_two_thirds_quorum(
        signed_stake,
        snapshot.total_weight_spark,
    ) {
        return Err(QcVerificationError::InsufficientStake);
    }
    if qc.pq_signatures.len() != signers.len() || qc.classical_signatures.len() != signers.len() {
        return Err(QcVerificationError::SignatureCountMismatch);
    }
    let mut pq = HashMap::new();
    let mut seen = HashSet::new();
    for signature in &qc.pq_signatures {
        if !seen.insert(signature.validator_id) {
            return Err(QcVerificationError::DuplicateSignature);
        }
        pq.insert(signature.validator_id, signature);
    }
    let mut classical = HashMap::new();
    seen.clear();
    for signature in &qc.classical_signatures {
        if !seen.insert(signature.validator_id) {
            return Err(QcVerificationError::DuplicateSignature);
        }
        classical.insert(signature.validator_id, signature);
    }
    let mut signer_ids = Vec::with_capacity(signers.len());
    for signer in signers {
        let signing_bytes = crate::types::vote_signing::vote_signing_bytes(
            qc.height,
            qc.round,
            VoteStep::Precommit,
            &qc.block_hash,
            &signer.validator_id,
            &qc.snapshot_root,
            chain_id,
        )
        .map_err(|_| QcVerificationError::InvalidChainId)?;
        let pq_signature = pq
            .get(&signer.validator_id)
            .ok_or(QcVerificationError::MissingSignature)?;
        let pq_bytes: [u8; indra_crypto::PQ_SIG_BYTES] = pq_signature
            .pq_sig
            .as_slice()
            .try_into()
            .map_err(|_| QcVerificationError::InvalidPqSignature)?;
        verify_pq(
            &signing_bytes,
            &PqSignature(pq_bytes),
            &PqPublicKey(signer.pq_vote_pk),
        )
        .map_err(|_| QcVerificationError::InvalidPqSignature)?;
        let classical_signature = classical
            .get(&signer.validator_id)
            .ok_or(QcVerificationError::MissingSignature)?;
        let classical_bytes: [u8; indra_crypto::CLASSICAL_SIG_BYTES] = classical_signature
            .classical_sig
            .as_slice()
            .try_into()
            .map_err(|_| QcVerificationError::InvalidClassicalSignature)?;
        verify_classical(
            &signing_bytes,
            &ClassicalSignature(classical_bytes),
            &ClassicalPublicKey(signer.classical_vote_pk),
        )
        .map_err(|_| QcVerificationError::InvalidClassicalSignature)?;
        signer_ids.push(signer.validator_id);
    }
    Ok(VerifiedQc {
        height: qc.height,
        block_hash: qc.block_hash,
        signer_ids,
        encoded_qc: qc.encode_to_vec(),
    })
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
        QC_FORMAT_HYBRID.encode(buf);
        self.height.encode(buf);
        self.round.encode(buf);
        self.block_hash.encode(buf);
        self.snapshot_root.encode(buf);
        buf.extend_from_slice(&self.signer_bitfield);
        encode_list(&self.pq_signatures, buf);
        encode_list(&self.classical_signatures, buf);
    }
    fn encoded_len(&self) -> usize {
        1 + 8
            + 4
            + 32
            + 32
            + SIGNER_BITFIELD_BYTES
            + list_encoded_len(&self.pq_signatures)
            + list_encoded_len(&self.classical_signatures)
    }
}

impl Decode for QuorumCertificateV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let format = u8::decode(r)?;
        if format != QC_FORMAT_HYBRID {
            return Err(IndraError::InvalidQcFormat { format });
        }
        let height = u64::decode(r)?;
        let round = crate::types::primitives::validate_consensus_round(u32::decode(r)?)?;
        let block_hash = Bytes32::decode(r)?;
        let snapshot_root = Bytes32::decode(r)?;
        let bf_bytes = r.read_bytes(SIGNER_BITFIELD_BYTES)?;
        let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
        signer_bitfield.copy_from_slice(bf_bytes);
        let pq_signatures = decode_list(r, MAX_QC_SIGNERS, "pq_signatures")?;
        let classical_signatures = decode_list(r, MAX_QC_SIGNERS, "classical_signatures")?;
        Ok(Self {
            height,
            round,
            block_hash,
            snapshot_root,
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
            snapshot_root: Bytes32::from([0x88u8; 32]),
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
    fn hybrid_qc_encodes_and_decodes_with_classical_sigs() {
        let qc = QuorumCertificateV1 {
            height: 1,
            round: 0,
            block_hash: Bytes32::from([0x01; 32]),
            snapshot_root: Bytes32::from([0x02; 32]),
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
    fn qc_classical_signature_decode_requires_exact_length() {
        for len in [
            0,
            indra_crypto::CLASSICAL_SIG_BYTES - 1,
            indra_crypto::CLASSICAL_SIG_BYTES + 1,
        ] {
            let mut encoded = Bytes32::ZERO.encode_to_vec();
            (len as u32).encode(&mut encoded);
            encoded.extend(std::iter::repeat_n(0xDD, len));
            assert!(ClassicalVoteSig::decode_exact(&encoded).is_err());
        }
    }

    #[test]
    fn unknown_qc_format_version_rejected() {
        let mut buf = Vec::new();
        0xFFu8.encode(&mut buf);
        buf.extend_from_slice(&[0u8; 44]);
        assert!(QuorumCertificateV1::decode_exact(&buf).is_err());
    }

    #[test]
    fn truncated_election_result_presence_flag_is_rejected() {
        let mut bytes = Vec::new();
        QC_FORMAT_HYBRID.encode(&mut bytes);
        7u64.encode(&mut bytes);
        2u32.encode(&mut bytes);
        Bytes32::from([0x44; 32]).encode(&mut bytes);
        assert!(QuorumCertificateV1::decode_exact(&bytes).is_err());
    }

    #[test]
    fn trailing_qc_bytes_are_rejected() {
        let mut encoded = dummy_qc().encode_to_vec();
        encoded.push(0xA5);
        assert!(QuorumCertificateV1::decode_exact(&encoded).is_err());
    }

    #[test]
    fn pq_only_qc_bytes_are_rejected() {
        let mut old_format = Vec::new();
        3u64.encode(&mut old_format);
        0u32.encode(&mut old_format);
        Bytes32::from([0xAB; 32]).encode(&mut old_format);
        old_format.extend_from_slice(&{
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
        encode_list(&pq_signatures, &mut old_format);

        assert!(
            QuorumCertificateV1::decode_exact(&old_format).is_err(),
            "old QC format without version byte must return Err"
        );
    }

    #[test]
    fn bitfield_size_is_correct() {
        // ceil(1500/8) = 188
        assert_eq!(SIGNER_BITFIELD_BYTES, 188);
    }

    #[test]
    fn decoder_enforces_finite_round_domain() {
        for round in [0, crate::types::primitives::MAX_ROUNDS_PER_HEIGHT - 1] {
            let mut qc = dummy_qc();
            qc.round = round;
            assert!(QuorumCertificateV1::decode_exact(&qc.encode_to_vec()).is_ok());
        }
        for round in [
            crate::types::primitives::MAX_ROUNDS_PER_HEIGHT,
            crate::types::primitives::MAX_ROUNDS_PER_HEIGHT + 1,
            u32::MAX,
        ] {
            let mut qc = dummy_qc();
            qc.round = round;
            assert!(QuorumCertificateV1::decode_exact(&qc.encode_to_vec()).is_err());
        }
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
