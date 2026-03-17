//! Quorum Certificate construction and verification.

use indra_core::types::qc::SIGNER_BITFIELD_BYTES;
use std::collections::HashMap;

use indra_core::{
    types::{
        primitives::{
            Bytes32, MAX_VALIDATORS, QUORUM_THRESHOLD_BPS,
            VariableBytes, MAX_BLS_AGG_SIG_BYTES, MAX_PQ_SIG_BYTES,
        },
        qc::QuorumCertificateV1,
        crypto::PQVoteSig,
        vote::{VoteStep, VoteV1},
    },
};
use indra_crypto::bls::BlsSignature;

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
        if (stake_bps as u32) < QUORUM_THRESHOLD_BPS {
            return Err(ConsensusError::QuorumNotReached {
                have_bps: stake_bps,
                need_bps: QUORUM_THRESHOLD_BPS as u64,
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
            signer_bitfield[pos / 8] |= 1 << (pos % 8);
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
            need_bps: QUORUM_THRESHOLD_BPS as u64,
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

/// Verify a QC against the validator set.
pub fn verify_qc(
    qc: &QuorumCertificateV1,
    validators: &[QcValidator],
    total_stake: u64,
) -> ConsensusResult<()> {
    // Count signed stake from bitfield
    let mut signed_stake = 0u64;
    for (byte_idx, &byte) in qc.signer_bitfield.iter().enumerate() {
        for bit_idx in 0..8 {
            let pos = byte_idx * 8 + bit_idx;
            if pos >= MAX_VALIDATORS { break; }
            if (byte >> bit_idx) & 1 == 1 {
                if let Some(v) = validators.iter().find(|v| v.position == pos) {
                    signed_stake = signed_stake.saturating_add(v.stake);
                }
            }
        }
    }

    let stake_bps = if total_stake > 0 {
        signed_stake.saturating_mul(10_000) / total_stake
    } else {
        0
    };

    if (stake_bps as u32) < QUORUM_THRESHOLD_BPS {
        return Err(ConsensusError::QuorumNotReached {
            have_bps: stake_bps,
            need_bps: QUORUM_THRESHOLD_BPS as u64,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_crypto::{
        bls::BlsKeypair,
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
        let (v, kp, _) = make_validator(0x03, 0, 10_000);
        let block_hash = Bytes32::from([0xCCu8; 32]);
        let vote = produce_vote(1, 0, VoteStep::Precommit, block_hash, v.validator_id, &kp).unwrap();
        let qc = build_qc(1, 0, block_hash, &[v.clone()], vec![&vote]).unwrap();
        assert!(verify_qc(&qc, &[v.clone()], 10_000).is_ok());
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
}
