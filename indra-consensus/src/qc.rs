//! Quorum Certificate construction and verification.

use indra_core::types::qc::SIGNER_BITFIELD_BYTES;
use std::collections::HashMap;

use indra_core::{
    codec::Encode,
    types::{
        primitives::{
            Bytes32, CONSENSUS_QUORUM_BPS, MAX_VALIDATORS,
            VariableBytes, MAX_BLS_AGG_SIG_BYTES, MAX_PQ_SIG_BYTES,
        },
        qc::QuorumCertificateV1,
        crypto::PQVoteSig,
        vote::{VoteStep, VoteV1},
    },
};
use indra_crypto::{
    bls::{BlsAggregateSignature, BlsPublicKey, BlsSignature, verify_aggregate},
    hash::domains::VOTE_SIGN,
    hybrid::{PqPublicKey, PqSignature, verify_pq},
};

use crate::{
    error::{ConsensusError, ConsensusResult},
    vote::vote_signing_bytes,
};

/// A registered validator for QC construction.
#[derive(Debug, Clone)]
pub struct QcValidator {
    /// Validator identity.
    pub validator_id: Bytes32,
    /// Position in the epoch's sorted validator list (0-indexed).
    pub position: usize,
    /// BLS public key (48 bytes).
    pub bls_pk: [u8; 48],
    /// Dilithium2 public key bytes.
    pub pq_pk: Vec<u8>,
    /// Stake in Spark.
    pub stake: u64,
}

/// Canonical bytes signed by the QC BLS aggregate.
///
/// The aggregate signature covers the same message for every signer, so the
/// validator identity is intentionally omitted here. Individual PQ signatures
/// still bind the validator identity through `vote_signing_bytes`.
pub fn qc_signing_bytes(
    height: u64,
    round: u32,
    block_hash: &Bytes32,
) -> Vec<u8> {
    let mut buf = VOTE_SIGN.to_vec();
    height.encode(&mut buf);
    round.encode(&mut buf);
    VoteStep::Precommit.encode(&mut buf);
    block_hash.encode(&mut buf);
    buf
}

/// A QC builder — accumulates votes and builds the QC when quorum is reached.
pub struct QcBuilder {
    height:      u64,
    round:       u32,
    block_hash:  Bytes32,
    validators:  Vec<QcValidator>,
    total_stake: u64,
    votes:       HashMap<Bytes32, VoteV1>,
}

impl QcBuilder {
    /// Create a new QC builder.
    pub fn new(
        height: u64,
        round: u32,
        block_hash: Bytes32,
        validators: Vec<QcValidator>,
    ) -> Self {
        let total_stake = validators.iter()
            .map(|v| v.stake)
            .fold(0u64, |a, b| a.saturating_add(b));
        Self { height, round, block_hash, validators, total_stake, votes: HashMap::new() }
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
        if self.total_stake == 0 { return 0; }
        let voted: u64 = self.votes.keys()
            .filter_map(|id| self.validators.iter().find(|v| v.validator_id == *id))
            .map(|v| v.stake)
            .fold(0u64, |a, b| a.saturating_add(b));
        voted.saturating_mul(10_000) / self.total_stake
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
            self.height, self.round, self.block_hash,
            &self.validators, self.votes.values().collect(),
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
    let by_id: HashMap<Bytes32, &QcValidator> = validators.iter()
        .map(|v| (v.validator_id, v))
        .collect();

    let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
    let mut bls_sigs: Vec<BlsSignature> = Vec::new();
    let mut pq_sigs: Vec<PQVoteSig> = Vec::new();

    for vote in &votes {
        let validator = match by_id.get(&vote.validator_id) {
            Some(v) => v,
            None => continue,
        };

        // Set bitfield bit
        let pos = validator.position;
        if pos < MAX_VALIDATORS {
            let byte_index = pos / 8;
            if let Some(byte) = signer_bitfield.get_mut(byte_index) {
                *byte |= 1 << (pos % 8);
            }
        }

        // Collect BLS sig bytes (the classical_sig field carries Ed25519 in Phase 3/4;
        // full BLS signing wired in Phase 5)
        bls_sigs.push(BlsSignature(vote.signature.classical_sig.as_slice().to_vec()));

        // Collect PQ sig
        let pq_sig = PQVoteSig {
            validator_id: vote.validator_id,
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(
                vote.signature.pq_sig.as_slice()
            ).map_err(|_| ConsensusError::CryptoError {
                detail: "PQ sig too large".to_string(),
            })?,
        };
        pq_sigs.push(pq_sig);
    }

    if bls_sigs.is_empty() {
        return Err(ConsensusError::QuorumNotReached {
            have_bps: 0,
            need_bps: CONSENSUS_QUORUM_BPS as u64,
        });
    }

    // Phase 4 placeholder: use a zeroed 96-byte aggregate sig.
    // Real BLS aggregation over per-validator signing messages is wired in Phase 5
    // when validators sign with their BLS keys rather than their hybrid keys.
    let agg_bytes = vec![0u8; 96];

    let bls_agg_sig = VariableBytes::<MAX_BLS_AGG_SIG_BYTES>::from_slice(&agg_bytes)
        .map_err(|_| ConsensusError::CryptoError {
            detail: "BLS agg sig too large".to_string(),
        })?;

    Ok(QuorumCertificateV1 {
        height,
        round,
        block_hash,
        bls_agg_sig,
        signer_bitfield,
        pq_signatures: pq_sigs,
    })
}

fn signer_validators<'a>(
    qc: &QuorumCertificateV1,
    validators: &'a [QcValidator],
) -> ConsensusResult<Vec<&'a QcValidator>> {
    let by_position: HashMap<usize, &QcValidator> = validators.iter()
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
                let validator = by_position.get(&pos)
                    .copied()
                    .ok_or(ConsensusError::QcVerificationFailed)?;
                signers.push(validator);
            }
        }
    }

    Ok(signers)
}

/// Verify the stake and PQ signature portion of a QC.
pub fn verify_qc(
    qc: &QuorumCertificateV1,
    validators: &[QcValidator],
    total_stake: u64,
) -> ConsensusResult<()> {
    let signers = signer_validators(qc, validators)?;
    let signed_stake = signers.iter()
        .fold(0u64, |acc, validator| acc.saturating_add(validator.stake));

    let stake_bps = if total_stake > 0 {
        signed_stake.saturating_mul(10_000) / total_stake
    } else {
        0
    };

    if (stake_bps as u32) < CONSENSUS_QUORUM_BPS {
        return Err(ConsensusError::QuorumNotReached {
            have_bps: stake_bps,
            need_bps: CONSENSUS_QUORUM_BPS as u64,
        });
    }

    if qc.pq_signatures.len() != signers.len() {
        return Err(ConsensusError::QcVerificationFailed);
    }

    let pq_by_validator: HashMap<Bytes32, &PQVoteSig> = qc.pq_signatures.iter()
        .map(|signature| (signature.validator_id, signature))
        .collect();
    if pq_by_validator.len() != qc.pq_signatures.len() {
        return Err(ConsensusError::QcVerificationFailed);
    }

    for validator in signers {
        let pq_sig = pq_by_validator.get(&validator.validator_id)
            .copied()
            .ok_or(ConsensusError::QcVerificationFailed)?;
        let signing_bytes = vote_signing_bytes(
            qc.height,
            qc.round,
            VoteStep::Precommit,
            &qc.block_hash,
            &validator.validator_id,
        );
        verify_pq(
            &signing_bytes,
            &PqSignature(pq_sig.pq_sig.as_slice().to_vec()),
            &PqPublicKey(validator.pq_pk.clone()),
        )
        .map_err(|_| ConsensusError::QcVerificationFailed)?;
    }

    Ok(())
}

/// Verify a QC including its BLS aggregate signature.
///
/// This is the fail-closed path that nodes should use once strict header
/// verification is enabled.
pub fn verify_qc_strict(
    qc: &QuorumCertificateV1,
    validators: &[QcValidator],
    total_stake: u64,
) -> ConsensusResult<()> {
    verify_qc(qc, validators, total_stake)?;

    let signers = signer_validators(qc, validators)?;
    let signing_bytes = qc_signing_bytes(qc.height, qc.round, &qc.block_hash);
    let public_keys: Vec<BlsPublicKey> = signers.iter()
        .map(|validator| BlsPublicKey(validator.bls_pk))
        .collect();

    // Consensus QC construction still has a placeholder path in `build_qc_from_votes`.
    // Strict verification refuses to accept those placeholder bytes.
    let aggregate = BlsAggregateSignature(qc.bls_agg_sig.as_slice().to_vec());
    verify_aggregate(&signing_bytes, &aggregate, &public_keys)
        .map_err(|_| ConsensusError::QcVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::primitives::{CONSENSUS_QUORUM_BPS, VariableBytes};
    use indra_crypto::{
        bls::{BlsKeypair, aggregate_signatures},
        hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    };
    use indra_core::types::vote::VoteStep;
    use crate::vote::produce_vote;

    fn make_validator(seed: u8, position: usize, stake: u64)
        -> (QcValidator, HybridKeypair, BlsKeypair)
    {
        let classical = ClassicalKeypair::from_seed(&[seed; 32]);
        let pq = PqKeypair::generate();
        let hybrid_kp = HybridKeypair::new(classical, pq);
        let bls_kp = BlsKeypair::from_seed(&[seed; 32]).unwrap();
        let pk = hybrid_kp.public_key();
        let id = Bytes32::from(indra_crypto::sha256(&pk.classical.0));
        let v = QcValidator {
            validator_id: id,
            position,
            bls_pk: bls_kp.public_key().0,
            pq_pk: pk.pq.0.clone(),
            stake,
        };
        (v, hybrid_kp, bls_kp)
    }

    #[test]
    fn build_qc_single_validator() {
        let (v, kp, _) = make_validator(0x01, 0, 10_000);
        let block_hash = Bytes32::from([0xAAu8; 32]);
        let vote = produce_vote(1, 0, VoteStep::Precommit, block_hash, v.validator_id, &kp).unwrap();
        let qc = build_qc(1, 0, block_hash, &[v.clone()], vec![&vote]).unwrap();
        assert_eq!(qc.height, 1);
        assert_eq!(qc.block_hash, block_hash);
        assert_eq!(qc.signer_count(), 1);
    }

    #[test]
    fn qc_bitfield_set_correctly() {
        let (v, kp, _) = make_validator(0x02, 5, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let vote = produce_vote(1, 0, VoteStep::Precommit, block_hash, v.validator_id, &kp).unwrap();
        let qc = build_qc(1, 0, block_hash, &[v.clone()], vec![&vote]).unwrap();
        assert!(qc.is_signer(5));
        assert!(!qc.is_signer(0));
    }

    #[test]
    fn verify_qc_passes_with_quorum() {
        let (v, kp, bls) = make_validator(0x03, 0, 10_000);
        let block_hash = Bytes32::from([0xCCu8; 32]);
        let vote = produce_vote(1, 0, VoteStep::Precommit, block_hash, v.validator_id, &kp).unwrap();
        let bls_sig = bls.sign(&qc_signing_bytes(1, 0, &block_hash));
        let agg = aggregate_signatures(&[bls_sig]).unwrap();
        let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
        signer_bitfield[0] = 0b0000_0001;
        let qc = QuorumCertificateV1 {
            height: 1,
            round: 0,
            block_hash,
            bls_agg_sig: VariableBytes::from_slice(&agg.0).unwrap(),
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
    fn verify_qc_fails_below_threshold() {
        let (v1, kp1, _) = make_validator(0x01, 0, 3_000);
        let (v2, _kp2, _) = make_validator(0x02, 1, 7_000);
        let block_hash = Bytes32::from([0xDDu8; 32]);
        let vote = produce_vote(1, 0, VoteStep::Precommit, block_hash, v1.validator_id, &kp1).unwrap();
        let qc = build_qc(1, 0, block_hash, &[v1.clone(), v2.clone()], vec![&vote]).unwrap();
        assert!(matches!(
            verify_qc(&qc, &[v1, v2], 10_000),
            Err(ConsensusError::QuorumNotReached { .. })
        ));
    }

    #[test]
    fn verify_qc_strict_rejects_placeholder_bls_signature() {
        let (v, kp, _) = make_validator(0x09, 0, 10_000);
        let block_hash = Bytes32::from([0xEEu8; 32]);
        let vote = produce_vote(1, 0, VoteStep::Precommit, block_hash, v.validator_id, &kp).unwrap();
        let qc = build_qc(1, 0, block_hash, &[v.clone()], vec![&vote]).unwrap();
        assert_eq!(qc.bls_agg_sig.as_slice(), vec![0u8; 96].as_slice());
        assert_eq!(verify_qc_strict(&qc, &[v], 10_000), Err(ConsensusError::QcVerificationFailed));
    }

    #[test]
    fn verify_qc_rejects_mismatched_pq_signatures() {
        let (v, _kp, bls) = make_validator(0x0A, 0, 10_000);
        let block_hash = Bytes32::from([0xABu8; 32]);
        let bls_sig = bls.sign(&qc_signing_bytes(1, 0, &block_hash));
        let agg = aggregate_signatures(&[bls_sig]).unwrap();
        let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
        signer_bitfield[0] = 0b0000_0001;
        let qc = QuorumCertificateV1 {
            height: 1,
            round: 0,
            block_hash,
            bls_agg_sig: VariableBytes::from_slice(&agg.0).unwrap(),
            signer_bitfield,
            pq_signatures: vec![PQVoteSig {
                validator_id: v.validator_id,
                pq_sig: VariableBytes::from_slice(&[0x42u8; 32]).unwrap(),
            }],
        };
        assert_eq!(verify_qc(&qc, &[v], 10_000), Err(ConsensusError::QcVerificationFailed));
    }

    #[test]
    fn strict_consensus_quorum_is_above_two_thirds() {
        assert!(CONSENSUS_QUORUM_BPS > 6_666);
    }
}
