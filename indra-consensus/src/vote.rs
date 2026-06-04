//! Vote production and collection.
//!
//! ## BFT consensus rounds
//!
//! Each height proceeds through rounds until a QC is formed:
//!
//!   1. Proposer broadcasts block
//!   2. Each validator broadcasts a PREVOTE for the block (or nil)
//!   3. Once 2/3 stake prevotes collected → each validator broadcasts PRECOMMIT
//!   4. Once 2/3 stake precommits collected → QC formed, block finalised
//!
//! ## Vote signing
//!
//! A vote is signed with the validator's hybrid keypair over:
//!   SHA-256(DOMAIN_VOTE || height || round || step || block_hash || validator_id)
//!
//! Both Ed25519 and Dilithium2 components are required.

use std::collections::HashMap;

use indra_core::{
    codec::Encode,
    types::{
        primitives::Bytes32,
        vote::{VoteStep, VoteV1},
        crypto::HybridSignature as CoreHybridSignature,
    },
};
use indra_crypto::{
    hash::domains::VOTE_SIGN,
    hybrid::{HybridKeypair, verify_hybrid, HybridPublicKey, ClassicalPublicKey, PqPublicKey, HybridSignature, ClassicalSignature, PqSignature},
};

use crate::error::{ConsensusError, ConsensusResult};

/// A registered voter: identity + public key for signature verification.
#[derive(Debug, Clone)]
pub struct RegisteredVoter {
    /// The validator's 32-byte identity.
    pub validator_id: Bytes32,
    /// Ed25519 public key (32 bytes).
    pub classical_pk: [u8; 32],
    /// Dilithium2 public key bytes.
    pub pq_pk: Vec<u8>,
    /// Stake in Spark.
    pub stake: u64,
}

/// The decision a vote collector can reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteDecision {
    /// Not enough votes yet.
    Waiting,
    /// Quorum reached for this block hash.
    QuorumReached {
        /// The block hash that received quorum.
        block_hash: Bytes32,
        /// Basis points of stake that voted.
        stake_bps: u64,
    },
}

/// Collects votes for a single height/round/step.
pub struct VoteCollector {
    height:       u64,
    round:        u32,
    step:         VoteStep,
    voters:       Vec<RegisteredVoter>,
    total_stake:  u64,
    // validator_id → (vote, stake)
    received:     HashMap<Bytes32, (VoteV1, u64)>,
}

impl VoteCollector {
    /// Create a new collector for a specific height/round/step.
    pub fn new(
        height: u64,
        round: u32,
        step: VoteStep,
        voters: Vec<RegisteredVoter>,
    ) -> Self {
        let total_stake = voters.iter()
            .map(|v| v.stake)
            .fold(0u64, |a, b| a.saturating_add(b));
        Self {
            height,
            round,
            step,
            voters,
            total_stake,
            received: HashMap::new(),
        }
    }

    /// Add a vote to the collector.
    ///
    /// Verifies:
    ///   - Height/round/step match
    ///   - Voter is registered
    ///   - No duplicate vote from this validator
    ///   - Hybrid signature is valid
    ///
    /// Returns the current decision after this vote.
    pub fn add_vote(&mut self, vote: VoteV1) -> ConsensusResult<VoteDecision> {
        // Height/round check
        if vote.height != self.height || vote.round != self.round {
            return Err(ConsensusError::VoteHeightMismatch {
                expected_height: self.height,
                expected_round:  self.round,
            });
        }
        if vote.step != self.step {
            return Err(ConsensusError::CryptoError {
                detail: "vote step mismatch".to_string(),
            });
        }

        // Find the voter
        let voter = self.voters.iter()
            .find(|v| v.validator_id == vote.validator_id)
            .ok_or(ConsensusError::UnknownVoter)?
            .clone();

        // Duplicate check
        if self.received.contains_key(&vote.validator_id) {
            return Err(ConsensusError::DuplicateVote);
        }

        // Verify signature
        let signing_bytes = vote_signing_bytes(
            vote.height,
            vote.round,
            vote.step,
            &vote.block_hash,
            &vote.validator_id,
        );

        let sig_classical: [u8; 64] = vote.signature.classical_sig.as_slice()
            .try_into()
            .map_err(|_| ConsensusError::CryptoError {
                detail: "malformed classical sig".to_string(),
            })?;

        let sig = HybridSignature {
            classical: ClassicalSignature(sig_classical),
            pq: PqSignature(vote.signature.pq_sig.as_slice().to_vec()),
        };

        let pk = HybridPublicKey {
            classical: ClassicalPublicKey(voter.classical_pk),
            pq: PqPublicKey(voter.pq_pk.clone()),
        };

        verify_hybrid(&signing_bytes, &sig, &pk)
            .map_err(|e| ConsensusError::CryptoError { detail: e.to_string() })?;

        let stake = voter.stake;
        self.received.insert(vote.validator_id, (vote, stake));

        Ok(self.current_decision())
    }

    /// Return the current decision without adding a vote.
    pub fn current_decision(&self) -> VoteDecision {
        use indra_core::types::primitives::CONSENSUS_QUORUM_BPS;

        if self.total_stake == 0 {
            return VoteDecision::Waiting;
        }

        // Count stake per block_hash
        let mut stake_by_hash: HashMap<Bytes32, u64> = HashMap::new();
        for (vote, stake) in self.received.values() {
            *stake_by_hash.entry(vote.block_hash).or_insert(0) += stake;
        }

        // Check if any hash crossed the quorum threshold
        for (block_hash, stake) in &stake_by_hash {
            let bps = stake.saturating_mul(10_000) / self.total_stake;
            if bps as u32 >= CONSENSUS_QUORUM_BPS {
                return VoteDecision::QuorumReached {
                    block_hash: *block_hash,
                    stake_bps: bps,
                };
            }
        }

        VoteDecision::Waiting
    }

    /// Return all accepted votes for QC construction.
    pub fn accepted_votes(&self) -> Vec<&VoteV1> {
        self.received.values().map(|(v, _)| v).collect()
    }

    /// Number of votes received.
    pub fn vote_count(&self) -> usize {
        self.received.len()
    }

    /// True if this collector already accepted a vote from `validator_id`.
    pub fn has_vote_from(&self, validator_id: &Bytes32) -> bool {
        self.received.contains_key(validator_id)
    }
}

/// Produce a signed vote.
pub fn produce_vote(
    height: u64,
    round: u32,
    step: VoteStep,
    block_hash: Bytes32,
    validator_id: Bytes32,
    keypair: &HybridKeypair,
) -> ConsensusResult<VoteV1> {
    use indra_core::types::primitives::{VariableBytes, MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES};

    let signing_bytes = vote_signing_bytes(height, round, step, &block_hash, &validator_id);
    let sig = keypair.sign(&signing_bytes)?;

    let classical_sig = VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(&sig.classical.0)
        .map_err(|_| ConsensusError::CryptoError {
            detail: "classical sig too large".to_string(),
        })?;
    let pq_sig = VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&sig.pq.0)
        .map_err(|_| ConsensusError::CryptoError {
            detail: "PQ sig too large".to_string(),
        })?;

    Ok(VoteV1 {
        height,
        round,
        step,
        block_hash,
        validator_id,
        signature: CoreHybridSignature { classical_sig, pq_sig },
    })
}

/// Produce the canonical bytes a vote signature covers.
pub fn vote_signing_bytes(
    height: u64,
    round: u32,
    step: VoteStep,
    block_hash: &Bytes32,
    validator_id: &Bytes32,
) -> Vec<u8> {
    let mut buf = VOTE_SIGN.to_vec();
    height.encode(&mut buf);
    round.encode(&mut buf);
    step.encode(&mut buf);
    block_hash.encode(&mut buf);
    validator_id.encode(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::vote::VoteStep;
    use indra_crypto::{hybrid::HybridKeypair, sha256};

    fn voter(seed: u8, stake: u64) -> (RegisteredVoter, HybridKeypair) {
        let classical = indra_crypto::hybrid::ClassicalKeypair::from_seed(&[seed; 32]);
        let pq = indra_crypto::hybrid::PqKeypair::generate();
        let kp = HybridKeypair::new(classical, pq);
        let pk = kp.public_key();
        let id = Bytes32::from(sha256(&pk.classical.0));
        let voter = RegisteredVoter {
            validator_id: id,
            classical_pk: pk.classical.0,
            pq_pk:        pk.pq.0.clone(),
            stake,
        };
        (voter, kp)
    }

    #[test]
    fn single_voter_reaches_quorum() {
        let (v, kp) = voter(0x01, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let mut collector = VoteCollector::new(1, 0, VoteStep::Precommit, vec![v.clone()]);

        let vote = produce_vote(1, 0, VoteStep::Precommit, block_hash, v.validator_id, &kp).unwrap();
        let decision = collector.add_vote(vote).unwrap();

        assert!(matches!(decision, VoteDecision::QuorumReached { .. }));
    }

    #[test]
    fn wrong_height_rejected() {
        let (v, kp) = voter(0x01, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let mut collector = VoteCollector::new(1, 0, VoteStep::Prevote, vec![v.clone()]);

        // Vote for height 99 instead of 1
        let vote = produce_vote(99, 0, VoteStep::Prevote, block_hash, v.validator_id, &kp).unwrap();
        assert!(matches!(
            collector.add_vote(vote),
            Err(ConsensusError::VoteHeightMismatch { .. })
        ));
    }

    #[test]
    fn duplicate_vote_rejected() {
        let (v, kp) = voter(0x01, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let mut collector = VoteCollector::new(1, 0, VoteStep::Prevote, vec![v.clone()]);

        let vote = produce_vote(1, 0, VoteStep::Prevote, block_hash, v.validator_id, &kp).unwrap();
        collector.add_vote(vote.clone()).unwrap();
        assert_eq!(collector.add_vote(vote), Err(ConsensusError::DuplicateVote));
    }

    #[test]
    fn unknown_voter_rejected() {
        let (v, _kp) = voter(0x01, 10_000);
        let (stranger, stranger_kp) = voter(0x99, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        // Register only v, not stranger
        let mut collector = VoteCollector::new(1, 0, VoteStep::Prevote, vec![v]);

        let vote = produce_vote(1, 0, VoteStep::Prevote, block_hash, stranger.validator_id, &stranger_kp).unwrap();
        assert_eq!(collector.add_vote(vote), Err(ConsensusError::UnknownVoter));
    }

    #[test]
    fn tampered_vote_rejected() {
        let (v, kp) = voter(0x01, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let mut collector = VoteCollector::new(1, 0, VoteStep::Prevote, vec![v.clone()]);

        let mut vote = produce_vote(1, 0, VoteStep::Prevote, block_hash, v.validator_id, &kp).unwrap();
        // Tamper with the block hash after signing
        vote.block_hash = Bytes32::from([0xFFu8; 32]);
        assert!(matches!(
            collector.add_vote(vote),
            Err(ConsensusError::CryptoError { .. })
        ));
    }

    #[test]
    fn two_thirds_stake_threshold() {
        // 3 validators: 34%, 33%, 33% stake
        let (v1, kp1) = voter(0x01, 3_400);
        let (v2, kp2) = voter(0x02, 3_200);
        let (v3, _kp3) = voter(0x03, 3_400);
        let block_hash = Bytes32::from([0xCCu8; 32]);

        let mut collector = VoteCollector::new(
            1, 0, VoteStep::Precommit,
            vec![v1.clone(), v2.clone(), v3.clone()],
        );

        // First two votes total 66%, which is below the strict > 2/3 threshold.
        let vote1 = produce_vote(1, 0, VoteStep::Precommit, block_hash, v1.validator_id, &kp1).unwrap();
        let vote2 = produce_vote(1, 0, VoteStep::Precommit, block_hash, v2.validator_id, &kp2).unwrap();

        let d1 = collector.add_vote(vote1).unwrap();
        let d2 = collector.add_vote(vote2).unwrap();

        assert!(matches!(d1, VoteDecision::Waiting));
        assert!(matches!(d2, VoteDecision::Waiting));
    }

    #[test]
    fn quorum_requires_two_thirds() {
        let (v1, kp1) = voter(0x11, 3_400);
        let (v2, kp2) = voter(0x12, 3_300);
        let (v3, kp3) = voter(0x13, 3_300);
        let block_hash = Bytes32::from([0xDDu8; 32]);

        let mut collector = VoteCollector::new(
            1, 0, VoteStep::Precommit,
            vec![v1.clone(), v2.clone(), v3.clone()],
        );

        let vote1 = produce_vote(1, 0, VoteStep::Precommit, block_hash, v1.validator_id, &kp1).unwrap();
        let vote2 = produce_vote(1, 0, VoteStep::Precommit, block_hash, v2.validator_id, &kp2).unwrap();
        let vote3 = produce_vote(1, 0, VoteStep::Precommit, block_hash, v3.validator_id, &kp3).unwrap();

        assert!(matches!(collector.add_vote(vote1).unwrap(), VoteDecision::Waiting));
        assert!(matches!(collector.add_vote(vote2).unwrap(), VoteDecision::QuorumReached { stake_bps, .. } if stake_bps == 6_700));
        assert!(matches!(collector.add_vote(vote3).unwrap(), VoteDecision::QuorumReached { stake_bps, .. } if stake_bps == 10_000));
    }
}
