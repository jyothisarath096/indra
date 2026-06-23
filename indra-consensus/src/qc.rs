//! Quorum Certificate construction and verification.

use indra_core::types::qc::SIGNER_BITFIELD_BYTES;
use std::collections::{HashMap, HashSet};

use indra_core::types::{
    crypto::PQVoteSig,
    primitives::{
        bps_of, muldiv, Bytes32, VariableBytes, CONSENSUS_QUORUM_BPS, MAX_PQ_SIG_BYTES,
        MAX_VALIDATORS,
    },
    qc::QuorumCertificateV1,
    vote::{VoteStep, VoteV1},
};
use indra_crypto::hybrid::{verify_pq, PqPublicKey, PqSignature};

use crate::{
    error::{ConsensusError, ConsensusResult},
    vote::vote_signing_bytes,
};

/// A registered validator for QC construction and verification.
#[derive(Debug, Clone)]
pub struct QcValidator {
    /// Validator identity.
    pub validator_id: Bytes32,
    /// Position in the epoch's sorted validator list (0-indexed).
    pub position: usize,
    /// ML-DSA-87 public key bytes.
    pub pq_pk: Vec<u8>,
    /// Stake in Spark.
    pub stake: u64,
}

/// Canonical QC signing bytes.
///
/// Kept for compatibility with existing tests and callers. Individual PQ vote
/// signatures still verify against `vote_signing_bytes`, which binds the
/// validator identity.
pub fn qc_signing_bytes(height: u64, round: u32, block_hash: &Bytes32) -> Vec<u8> {
    vote_signing_bytes(
        height,
        round,
        VoteStep::Precommit,
        block_hash,
        &Bytes32::ZERO,
    )
}

/// A QC builder — accumulates votes and builds the QC when quorum is reached.
pub struct QcBuilder {
    height: u64,
    round: u32,
    block_hash: Bytes32,
    validators: Vec<QcValidator>,
    total_stake: u64,
    votes: HashMap<Bytes32, VoteV1>,
}

impl QcBuilder {
    /// Create a new QC builder.
    pub fn new(height: u64, round: u32, block_hash: Bytes32, validators: Vec<QcValidator>) -> Self {
        let total_stake = validators
            .iter()
            .map(|v| v.stake)
            .fold(0u64, |a, b| a.saturating_add(b));
        Self {
            height,
            round,
            block_hash,
            validators,
            total_stake,
            votes: HashMap::new(),
        }
    }

    /// Add a precommit vote to the builder.
    pub fn add_precommit(&mut self, vote: VoteV1) {
        if vote.height == self.height
            && vote.round == self.round
            && vote.block_hash == self.block_hash
        {
            self.votes.insert(vote.validator_id, vote);
        }
    }

    /// Current stake fraction in basis points.
    pub fn current_stake_bps(&self) -> u64 {
        if self.total_stake == 0 {
            return 0;
        }
        let voted: u64 = self
            .votes
            .keys()
            .filter_map(|id| self.validators.iter().find(|v| v.validator_id == *id))
            .map(|v| v.stake)
            .fold(0u64, |a, b| a.saturating_add(b));
        muldiv(voted, 10_000, self.total_stake)
    }

    /// Build the QC if quorum has been reached.
    pub fn build(&self) -> ConsensusResult<QuorumCertificateV1> {
        let stake_bps = self.current_stake_bps();
        if (stake_bps as u32) < CONSENSUS_QUORUM_BPS {
            return Err(ConsensusError::QuorumNotReached {
                have_bps: stake_bps,
                need_bps: CONSENSUS_QUORUM_BPS as u64,
            });
        }
        build_qc_from_votes(
            self.height,
            self.round,
            self.block_hash,
            &self.validators,
            self.votes.values().collect(),
        )
    }
}

/// Build a QC from a set of precommit votes.
pub fn build_qc(
    height: u64,
    round: u32,
    block_hash: Bytes32,
    validators: &[QcValidator],
    votes: Vec<&VoteV1>,
) -> ConsensusResult<QuorumCertificateV1> {
    build_qc_from_votes(height, round, block_hash, validators, votes)
}

fn build_qc_from_votes(
    height: u64,
    round: u32,
    block_hash: Bytes32,
    validators: &[QcValidator],
    votes: Vec<&VoteV1>,
) -> ConsensusResult<QuorumCertificateV1> {
    let by_id: HashMap<Bytes32, &QcValidator> =
        validators.iter().map(|v| (v.validator_id, v)).collect();

    let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
    let mut pq_sigs = Vec::new();

    for vote in &votes {
        let Some(validator) = by_id.get(&vote.validator_id) else {
            continue;
        };

        let pos = validator.position;
        if pos < MAX_VALIDATORS {
            let byte_index = pos / 8;
            if let Some(byte) = signer_bitfield.get_mut(byte_index) {
                *byte |= 1 << (pos % 8);
            }
        }

        pq_sigs.push(PQVoteSig {
            validator_id: vote.validator_id,
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(vote.signature.pq_sig.as_slice())
                .map_err(|_| ConsensusError::CryptoError {
                    detail: "PQ sig too large".to_string(),
                })?,
        });
    }

    if pq_sigs.is_empty() {
        return Err(ConsensusError::QuorumNotReached {
            have_bps: 0,
            need_bps: CONSENSUS_QUORUM_BPS as u64,
        });
    }

    Ok(QuorumCertificateV1 {
        height,
        round,
        block_hash,
        signer_bitfield,
        pq_signatures: pq_sigs,
    })
}

fn signer_validators<'a>(
    qc: &QuorumCertificateV1,
    validators: &'a [QcValidator],
) -> ConsensusResult<Vec<&'a QcValidator>> {
    let by_position: HashMap<usize, &QcValidator> = validators
        .iter()
        .map(|validator| (validator.position, validator))
        .collect();
    let mut signers = Vec::new();

    for (byte_idx, &byte) in qc.signer_bitfield.iter().enumerate() {
        for bit_idx in 0..8 {
            let pos = byte_idx * 8 + bit_idx;
            if pos >= MAX_VALIDATORS {
                break;
            }
            if (byte >> bit_idx) & 1 == 1 {
                let validator = by_position
                    .get(&pos)
                    .copied()
                    .ok_or(ConsensusError::QcVerificationFailed)?;
                signers.push(validator);
            }
        }
    }

    Ok(signers)
}

/// Verify a QC using ML-DSA-87 signatures only.
pub fn verify_qc(
    qc: &QuorumCertificateV1,
    validators: &[QcValidator],
    total_stake: u64,
) -> ConsensusResult<()> {
    let signers = signer_validators(qc, validators)?;
    let signed_stake = signers
        .iter()
        .fold(0u64, |acc, validator| acc.saturating_add(validator.stake));
    let quorum_stake = bps_of(total_stake, CONSENSUS_QUORUM_BPS);

    if signed_stake < quorum_stake {
        return Err(ConsensusError::InsufficientStake {
            have: signed_stake,
            need: quorum_stake,
        });
    }

    let mut seen = HashSet::new();
    let mut pq_by_validator = HashMap::new();
    for signature in &qc.pq_signatures {
        if !seen.insert(signature.validator_id) {
            return Err(ConsensusError::DuplicateSignature);
        }
        pq_by_validator.insert(signature.validator_id, signature);
    }

    if qc.pq_signatures.len() != signers.len() {
        return Err(ConsensusError::SignatureCountMismatch {
            expected: signers.len(),
            got: qc.pq_signatures.len(),
        });
    }

    for validator in signers {
        let pq_sig = pq_by_validator
            .get(&validator.validator_id)
            .copied()
            .ok_or(ConsensusError::MissingSignature {
                validator_id: validator.validator_id,
            })?;
        let signing_bytes = vote_signing_bytes(
            qc.height,
            qc.round,
            VoteStep::Precommit,
            &qc.block_hash,
            &validator.validator_id,
        );
        let pq_sig_bytes: [u8; indra_crypto::PQ_SIG_BYTES] =
            pq_sig.pq_sig.as_slice().try_into().map_err(|_| {
                ConsensusError::InvalidPQSignature {
                    validator_id: validator.validator_id,
                }
            })?;
        let pq_pk_bytes: [u8; indra_crypto::PQ_PK_BYTES] =
            validator.pq_pk.as_slice().try_into().map_err(|_| {
                ConsensusError::InvalidPQSignature {
                    validator_id: validator.validator_id,
                }
            })?;
        verify_pq(
            &signing_bytes,
            &PqSignature(pq_sig_bytes),
            &PqPublicKey(pq_pk_bytes),
        )
        .map_err(|_| ConsensusError::InvalidPQSignature {
            validator_id: validator.validator_id,
        })?;
    }

    Ok(())
}

/// Strict QC verification now aliases the same ML-DSA-only path.
pub fn verify_qc_strict(
    qc: &QuorumCertificateV1,
    validators: &[QcValidator],
    total_stake: u64,
) -> ConsensusResult<()> {
    verify_qc(qc, validators, total_stake)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vote::produce_vote;
    use indra_core::types::primitives::CONSENSUS_QUORUM_BPS;
    use indra_crypto::hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair};

    fn make_validator(seed: u8, position: usize, stake: u64) -> (QcValidator, HybridKeypair) {
        let classical = ClassicalKeypair::from_seed(&[seed; 32]);
        let pq = PqKeypair::generate();
        let hybrid_kp = HybridKeypair::new(classical, pq);
        let pk = hybrid_kp.public_key();
        let id = Bytes32::from(indra_crypto::sha256(&pk.classical.0));
        let v = QcValidator {
            validator_id: id,
            position,
            pq_pk: pk.pq.0.to_vec(),
            stake,
        };
        (v, hybrid_kp)
    }

    #[test]
    fn build_qc_single_validator() {
        let (v, kp) = make_validator(0x01, 0, 10_000);
        let block_hash = Bytes32::from([0xAAu8; 32]);
        let vote =
            produce_vote(1, 0, VoteStep::Precommit, block_hash, v.validator_id, &kp).unwrap();
        let qc = build_qc(1, 0, block_hash, &[v.clone()], vec![&vote]).unwrap();
        assert_eq!(qc.height, 1);
        assert_eq!(qc.block_hash, block_hash);
        assert_eq!(qc.signer_count(), 1);
    }

    #[test]
    fn qc_bitfield_set_correctly() {
        let (v, kp) = make_validator(0x02, 5, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let vote =
            produce_vote(1, 0, VoteStep::Precommit, block_hash, v.validator_id, &kp).unwrap();
        let qc = build_qc(1, 0, block_hash, &[v.clone()], vec![&vote]).unwrap();
        assert!(qc.is_signer(5));
        assert!(!qc.is_signer(0));
    }

    #[test]
    fn verify_qc_passes_with_quorum() {
        let (v, kp) = make_validator(0x03, 0, 10_000);
        let block_hash = Bytes32::from([0xCCu8; 32]);
        let vote =
            produce_vote(1, 0, VoteStep::Precommit, block_hash, v.validator_id, &kp).unwrap();
        let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
        signer_bitfield[0] = 0b0000_0001;
        let qc = QuorumCertificateV1 {
            height: 1,
            round: 0,
            block_hash,
            signer_bitfield,
            pq_signatures: vec![PQVoteSig {
                validator_id: v.validator_id,
                pq_sig: VariableBytes::from_slice(vote.signature.pq_sig.as_slice()).unwrap(),
            }],
        };
        assert!(verify_qc(&qc, &[v.clone()], 10_000).is_ok());
        assert!(verify_qc_strict(&qc, &[v], 10_000).is_ok());
    }

    #[test]
    fn verify_qc_rejects_insufficient_stake() {
        let (v1, kp1) = make_validator(0x01, 0, 3_000);
        let (v2, _) = make_validator(0x02, 1, 7_000);
        let block_hash = Bytes32::from([0xDDu8; 32]);
        let vote =
            produce_vote(1, 0, VoteStep::Precommit, block_hash, v1.validator_id, &kp1).unwrap();
        let qc = build_qc(1, 0, block_hash, &[v1.clone(), v2.clone()], vec![&vote]).unwrap();
        assert!(matches!(
            verify_qc(&qc, &[v1, v2], 10_000),
            Err(ConsensusError::InsufficientStake { .. })
        ));
    }

    #[test]
    fn verify_qc_rejects_invalid_pq_signature() {
        let (v, _) = make_validator(0x0A, 0, 10_000);
        let block_hash = Bytes32::from([0xABu8; 32]);
        let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
        signer_bitfield[0] = 0b0000_0001;
        let qc = QuorumCertificateV1 {
            height: 1,
            round: 0,
            block_hash,
            signer_bitfield,
            pq_signatures: vec![PQVoteSig {
                validator_id: v.validator_id,
                pq_sig: VariableBytes::from_slice(&[0x42u8; 32]).unwrap(),
            }],
        };
        assert!(matches!(
            verify_qc(&qc, &[v], 10_000),
            Err(ConsensusError::InvalidPQSignature { .. })
        ));
    }

    #[test]
    fn verify_qc_rejects_missing_pq_signature() {
        let (v, _) = make_validator(0x0B, 0, 10_000);
        let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
        signer_bitfield[0] = 0b0000_0001;
        let qc = QuorumCertificateV1 {
            height: 1,
            round: 0,
            block_hash: Bytes32::from([0x11u8; 32]),
            signer_bitfield,
            pq_signatures: vec![],
        };
        assert_eq!(
            verify_qc(&qc, &[v], 10_000),
            Err(ConsensusError::SignatureCountMismatch {
                expected: 1,
                got: 0
            })
        );
    }

    #[test]
    fn verify_qc_rejects_duplicate_pq_signatures() {
        let (v, kp) = make_validator(0x0C, 0, 10_000);
        let block_hash = Bytes32::from([0x12u8; 32]);
        let vote =
            produce_vote(1, 0, VoteStep::Precommit, block_hash, v.validator_id, &kp).unwrap();
        let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
        signer_bitfield[0] = 0b0000_0001;
        let sig = VariableBytes::from_slice(vote.signature.pq_sig.as_slice()).unwrap();
        let qc = QuorumCertificateV1 {
            height: 1,
            round: 0,
            block_hash,
            signer_bitfield,
            pq_signatures: vec![
                PQVoteSig {
                    validator_id: v.validator_id,
                    pq_sig: sig.clone(),
                },
                PQVoteSig {
                    validator_id: v.validator_id,
                    pq_sig: sig,
                },
            ],
        };
        assert_eq!(
            verify_qc(&qc, &[v], 10_000),
            Err(ConsensusError::DuplicateSignature)
        );
    }

    #[test]
    fn strict_consensus_quorum_is_above_two_thirds() {
        assert!(CONSENSUS_QUORUM_BPS > 6_666);
    }
}
