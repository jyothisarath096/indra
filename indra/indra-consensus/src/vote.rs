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
//!   SHA-256(DOMAIN_VOTE || chain_id || height || round || step || full_block_hash || validator_id)
//!
//! Both Ed25519 and ML-DSA-87 components are required.

use std::collections::BTreeMap;

use indra_core::types::{
    crypto::HybridSignature as CoreHybridSignature,
    primitives::{has_strict_two_thirds_quorum, muldiv, validate_consensus_round, Bytes32},
    vote::{VoteStep, VoteV1},
};
use indra_crypto::hybrid::{
    verify_hybrid, ClassicalPublicKey, ClassicalSignature, HybridKeypair, HybridPublicKey,
    HybridSignature, PqPublicKey, PqSignature,
};

use crate::error::{ConsensusError, ConsensusResult};

/// A registered voter: identity + public key for signature verification.
#[derive(Debug, Clone)]
pub struct RegisteredVoter {
    /// The validator's 32-byte identity.
    pub validator_id: Bytes32,
    /// Ed25519 public key (32 bytes).
    pub classical_pk: [u8; 32],
    /// ML-DSA-87 public key bytes.
    pub pq_pk: Vec<u8>,
    /// Stake in Spark.
    pub stake: u64,
}

/// The decision a vote collector can reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteDecision {
    /// Not enough votes yet.
    Waiting,
    /// Quorum reached for this vote hash.
    QuorumReached {
        /// The value hash that received quorum.
        block_hash: Bytes32,
        /// Basis points of stake that voted.
        stake_bps: u64,
    },
}

/// Collects votes for a single height/round/step.
pub struct VoteCollector {
    height: u64,
    round: u32,
    step: VoteStep,
    chain_id: String,
    voters: Vec<RegisteredVoter>,
    snapshot_root: Bytes32,
    total_stake: u64,
    // validator_id → (vote, stake)
    received: BTreeMap<Bytes32, (VoteV1, u64)>,
}

impl VoteCollector {
    /// Create a new collector for a specific height/round/step.
    pub fn new(
        height: u64,
        round: u32,
        step: VoteStep,
        chain_id: String,
        snapshot_root: Bytes32,
        voters: Vec<RegisteredVoter>,
    ) -> Self {
        let total_stake = voters
            .iter()
            .map(|v| v.stake)
            .fold(0u64, |a, b| a.saturating_add(b));
        Self {
            height,
            round,
            step,
            chain_id,
            snapshot_root,
            voters,
            total_stake,
            received: BTreeMap::new(),
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
        validate_round(vote.round)?;
        self.validate_dimensions_membership_and_duplicate(&vote)?;
        verify_vote_authority(&vote, &self.chain_id, &self.snapshot_root, &self.voters)?;
        self.add_verified_vote(vote)
    }

    /// Add a vote whose membership and hybrid signature were already checked
    /// with [`verify_vote_authority`] against this collector's voter snapshot.
    ///
    /// This exists so callers can authenticate a vote before reserving any
    /// external admission slot without paying for the hybrid verification
    /// twice. Structural dimensions and duplicate admission remain enforced
    /// here.
    pub fn add_verified_vote(&mut self, vote: VoteV1) -> ConsensusResult<VoteDecision> {
        validate_round(vote.round)?;
        self.validate_dimensions_membership_and_duplicate(&vote)?;
        let voter = self
            .voters
            .iter()
            .find(|v| v.validator_id == vote.validator_id)
            .expect("membership checked above");
        let stake = voter.stake;
        self.received.insert(vote.validator_id, (vote, stake));

        Ok(self.current_decision())
    }

    fn validate_dimensions_membership_and_duplicate(&self, vote: &VoteV1) -> ConsensusResult<()> {
        // Height/round check
        if vote.height != self.height || vote.round != self.round {
            return Err(ConsensusError::VoteHeightMismatch {
                expected_height: self.height,
                expected_round: self.round,
            });
        }
        if vote.step != self.step {
            return Err(ConsensusError::CryptoError {
                detail: "vote step mismatch".to_string(),
            });
        }
        if vote.snapshot_root != self.snapshot_root {
            return Err(ConsensusError::CryptoError {
                detail: "vote snapshot root mismatch".to_string(),
            });
        }

        // Resolve stake from the same voter snapshot used by the authority
        // verification performed by the caller.
        self.voters
            .iter()
            .find(|v| v.validator_id == vote.validator_id)
            .ok_or(ConsensusError::UnknownVoter)?;

        // Duplicate check
        if self.received.contains_key(&vote.validator_id) {
            return Err(ConsensusError::DuplicateVote);
        }

        Ok(())
    }

    /// Return the current decision without adding a vote.
    pub fn current_decision(&self) -> VoteDecision {
        if self.total_stake == 0 {
            return VoteDecision::Waiting;
        }

        // Count stake per full block hash.
        // Ordered so a malformed edge case cannot make the selected value
        // depend on randomized HashMap iteration order.
        let mut stake_by_hash: BTreeMap<Bytes32, u64> = BTreeMap::new();
        for (vote, stake) in self.received.values() {
            *stake_by_hash.entry(vote.block_hash).or_insert(0) += stake;
        }

        // Check if any hash crossed the quorum threshold
        for (block_hash, stake) in &stake_by_hash {
            let bps = muldiv(*stake, 10_000, self.total_stake);
            if has_strict_two_thirds_quorum(*stake, self.total_stake) {
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

/// Verify that a vote claims a registered voter and carries a valid hybrid
/// signature for that authority. This function is deliberately state-free so
/// admission code can run it before mutating deduplication or slash-detection
/// state.
pub fn verify_vote_authority(
    vote: &VoteV1,
    chain_id: &str,
    expected_snapshot_root: &Bytes32,
    voters: &[RegisteredVoter],
) -> ConsensusResult<()> {
    validate_round(vote.round)?;
    if vote.snapshot_root != *expected_snapshot_root {
        return Err(ConsensusError::CryptoError {
            detail: "vote snapshot root mismatch".to_string(),
        });
    }
    let voter = voters
        .iter()
        .find(|v| v.validator_id == vote.validator_id)
        .ok_or(ConsensusError::UnknownVoter)?;
    let signing_bytes = vote_signing_bytes(
        vote.height,
        vote.round,
        vote.step,
        &vote.block_hash,
        &vote.validator_id,
        &vote.snapshot_root,
        chain_id,
    );
    let sig_classical: [u8; 64] =
        vote.signature
            .classical_sig
            .as_slice()
            .try_into()
            .map_err(|_| ConsensusError::CryptoError {
                detail: "malformed classical sig".to_string(),
            })?;
    let sig_pq: [u8; indra_crypto::PQ_SIG_BYTES] = vote
        .signature
        .pq_sig
        .as_slice()
        .try_into()
        .map_err(|_| ConsensusError::CryptoError {
            detail: "malformed pq sig".to_string(),
        })?;
    let pk_pq: [u8; indra_crypto::PQ_PK_BYTES] =
        voter
            .pq_pk
            .as_slice()
            .try_into()
            .map_err(|_| ConsensusError::CryptoError {
                detail: "malformed pq pk".to_string(),
            })?;
    let sig = HybridSignature {
        classical: ClassicalSignature(sig_classical),
        pq: PqSignature(sig_pq),
    };
    let pk = HybridPublicKey {
        classical: ClassicalPublicKey(voter.classical_pk),
        pq: PqPublicKey(pk_pq),
    };
    verify_hybrid(&signing_bytes, &sig, &pk).map_err(|e| ConsensusError::CryptoError {
        detail: e.to_string(),
    })
}

/// Produce a signed vote over the canonical full block identity.
pub fn produce_vote(
    height: u64,
    round: u32,
    step: VoteStep,
    block_hash: Bytes32,
    validator_id: Bytes32,
    snapshot_root: Bytes32,
    chain_id: &str,
    keypair: &HybridKeypair,
) -> ConsensusResult<VoteV1> {
    validate_round(round)?;
    use indra_core::types::primitives::{VariableBytes, MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES};
    let signing_bytes = vote_signing_bytes(
        height,
        round,
        step,
        &block_hash,
        &validator_id,
        &snapshot_root,
        chain_id,
    );
    let sig = keypair.sign(&signing_bytes)?;
    Ok(VoteV1 {
        height,
        round,
        step,
        block_hash,
        validator_id,
        snapshot_root,
        signature: CoreHybridSignature {
            classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(&sig.classical.0)
                .map_err(|_| ConsensusError::CryptoError {
                detail: "classical sig too large".into(),
            })?,
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&sig.pq.0).map_err(|_| {
                ConsensusError::CryptoError {
                    detail: "PQ sig too large".into(),
                }
            })?,
        },
    })
}

fn validate_round(round: u32) -> ConsensusResult<()> {
    validate_consensus_round(round)
        .map(|_| ())
        .map_err(|error| ConsensusError::InvalidRound {
            detail: error.to_string(),
        })
}

/// Produce the canonical bytes a vote signature covers.
pub fn vote_signing_bytes(
    height: u64,
    round: u32,
    step: VoteStep,
    block_hash: &Bytes32,
    validator_id: &Bytes32,
    snapshot_root: &Bytes32,
    chain_id: &str,
) -> Vec<u8> {
    indra_core::types::vote_signing::vote_signing_bytes(
        height,
        round,
        step,
        block_hash,
        validator_id,
        snapshot_root,
        chain_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::{primitives::DEFAULT_CHAIN_ID, vote::VoteStep};
    use indra_crypto::hybrid::HybridKeypair;

    const TEST_SNAPSHOT_ROOT: Bytes32 = Bytes32([0x5A; 32]);

    fn voter(seed: u8, stake: u64) -> (RegisteredVoter, HybridKeypair) {
        let classical = indra_crypto::hybrid::ClassicalKeypair::from_seed(&[seed; 32]);
        let pq = indra_crypto::hybrid::PqKeypair::generate();
        let kp = HybridKeypair::new(classical, pq);
        let pk = kp.public_key();
        let id = indra_core::types::crypto::hybrid_identity_id(&pk.classical.0, &pk.pq.0);
        let voter = RegisteredVoter {
            validator_id: id,
            classical_pk: pk.classical.0,
            pq_pk: pk.pq.0.to_vec(),
            stake,
        };
        (voter, kp)
    }

    #[test]
    fn single_voter_reaches_quorum() {
        let (v, kp) = voter(0x01, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let mut collector = VoteCollector::new(
            1,
            0,
            VoteStep::Precommit,
            DEFAULT_CHAIN_ID.to_string(),
            TEST_SNAPSHOT_ROOT,
            vec![v.clone()],
        );

        let vote = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            v.validator_id,
            TEST_SNAPSHOT_ROOT,
            DEFAULT_CHAIN_ID,
            &kp,
        )
        .unwrap();
        let decision = collector.add_vote(vote).unwrap();

        assert!(matches!(decision, VoteDecision::QuorumReached { .. }));
    }

    #[test]
    fn vote_production_rejects_round_limit_and_above() {
        let (voter, keypair) = voter(0x71, 10_000);
        for round in [
            indra_core::types::primitives::MAX_ROUNDS_PER_HEIGHT,
            indra_core::types::primitives::MAX_ROUNDS_PER_HEIGHT + 1,
            u32::MAX,
        ] {
            assert!(produce_vote(
                1,
                round,
                VoteStep::Prevote,
                TEST_SNAPSHOT_ROOT,
                voter.validator_id,
                TEST_SNAPSHOT_ROOT,
                DEFAULT_CHAIN_ID,
                &keypair,
            )
            .is_err());
        }
    }

    #[test]
    fn wrong_height_rejected() {
        let (v, kp) = voter(0x01, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let mut collector = VoteCollector::new(
            1,
            0,
            VoteStep::Prevote,
            DEFAULT_CHAIN_ID.to_string(),
            TEST_SNAPSHOT_ROOT,
            vec![v.clone()],
        );

        // Vote for height 99 instead of 1
        let vote = produce_vote(
            99,
            0,
            VoteStep::Prevote,
            block_hash,
            v.validator_id,
            TEST_SNAPSHOT_ROOT,
            DEFAULT_CHAIN_ID,
            &kp,
        )
        .unwrap();
        assert!(matches!(
            collector.add_vote(vote),
            Err(ConsensusError::VoteHeightMismatch { .. })
        ));
    }

    #[test]
    fn duplicate_vote_rejected() {
        let (v, kp) = voter(0x01, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let mut collector = VoteCollector::new(
            1,
            0,
            VoteStep::Prevote,
            DEFAULT_CHAIN_ID.to_string(),
            TEST_SNAPSHOT_ROOT,
            vec![v.clone()],
        );

        let vote = produce_vote(
            1,
            0,
            VoteStep::Prevote,
            block_hash,
            v.validator_id,
            TEST_SNAPSHOT_ROOT,
            DEFAULT_CHAIN_ID,
            &kp,
        )
        .unwrap();
        collector.add_vote(vote.clone()).unwrap();
        assert_eq!(collector.add_vote(vote), Err(ConsensusError::DuplicateVote));
    }

    #[test]
    fn unknown_voter_rejected() {
        let (v, _kp) = voter(0x01, 10_000);
        let (stranger, stranger_kp) = voter(0x99, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        // Register only v, not stranger
        let mut collector = VoteCollector::new(
            1,
            0,
            VoteStep::Prevote,
            DEFAULT_CHAIN_ID.to_string(),
            TEST_SNAPSHOT_ROOT,
            vec![v],
        );

        let vote = produce_vote(
            1,
            0,
            VoteStep::Prevote,
            block_hash,
            stranger.validator_id,
            TEST_SNAPSHOT_ROOT,
            DEFAULT_CHAIN_ID,
            &stranger_kp,
        )
        .unwrap();
        assert_eq!(collector.add_vote(vote), Err(ConsensusError::UnknownVoter));
    }

    #[test]
    fn tampered_vote_rejected() {
        let (v, kp) = voter(0x01, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let mut collector = VoteCollector::new(
            1,
            0,
            VoteStep::Prevote,
            DEFAULT_CHAIN_ID.to_string(),
            TEST_SNAPSHOT_ROOT,
            vec![v.clone()],
        );

        let mut vote = produce_vote(
            1,
            0,
            VoteStep::Prevote,
            block_hash,
            v.validator_id,
            TEST_SNAPSHOT_ROOT,
            DEFAULT_CHAIN_ID,
            &kp,
        )
        .unwrap();
        // Tamper with the block hash after signing
        vote.block_hash = Bytes32::from([0xFFu8; 32]);
        assert!(matches!(
            collector.add_vote(vote),
            Err(ConsensusError::CryptoError { .. })
        ));
    }

    #[test]
    fn vote_cross_chain_replay_fails() {
        let (v, kp) = voter(0x42, 10_000);
        let block_hash = Bytes32::from([0x42u8; 32]);
        let vote = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            v.validator_id,
            TEST_SNAPSHOT_ROOT,
            "indra-testnet-1",
            &kp,
        )
        .unwrap();
        let mut mainnet_collector = VoteCollector::new(
            1,
            0,
            VoteStep::Precommit,
            "indra-mainnet-1".to_string(),
            TEST_SNAPSHOT_ROOT,
            vec![v],
        );

        assert!(matches!(
            mainnet_collector.add_vote(vote),
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
            1,
            0,
            VoteStep::Precommit,
            DEFAULT_CHAIN_ID.to_string(),
            TEST_SNAPSHOT_ROOT,
            vec![v1.clone(), v2.clone(), v3.clone()],
        );

        // First two votes total 66%, which is below the strict > 2/3 threshold.
        let vote1 = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            v1.validator_id,
            TEST_SNAPSHOT_ROOT,
            DEFAULT_CHAIN_ID,
            &kp1,
        )
        .unwrap();
        let vote2 = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            v2.validator_id,
            TEST_SNAPSHOT_ROOT,
            DEFAULT_CHAIN_ID,
            &kp2,
        )
        .unwrap();

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
            1,
            0,
            VoteStep::Precommit,
            DEFAULT_CHAIN_ID.to_string(),
            TEST_SNAPSHOT_ROOT,
            vec![v1.clone(), v2.clone(), v3.clone()],
        );

        let vote1 = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            v1.validator_id,
            TEST_SNAPSHOT_ROOT,
            DEFAULT_CHAIN_ID,
            &kp1,
        )
        .unwrap();
        let vote2 = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            v2.validator_id,
            TEST_SNAPSHOT_ROOT,
            DEFAULT_CHAIN_ID,
            &kp2,
        )
        .unwrap();
        let vote3 = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            v3.validator_id,
            TEST_SNAPSHOT_ROOT,
            DEFAULT_CHAIN_ID,
            &kp3,
        )
        .unwrap();

        assert!(matches!(
            collector.add_vote(vote1).unwrap(),
            VoteDecision::Waiting
        ));
        assert!(
            matches!(collector.add_vote(vote2).unwrap(), VoteDecision::QuorumReached { stake_bps, .. } if stake_bps == 6_700)
        );
        assert!(
            matches!(collector.add_vote(vote3).unwrap(), VoteDecision::QuorumReached { stake_bps, .. } if stake_bps == 10_000)
        );
    }
}
