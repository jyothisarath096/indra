//! Slash evidence detection.
//!
//! Detects two types of slashable offences:
//!
//! ## Double precommit (equivocation)
//!
//! A validator signs two different precommit votes at the same height
//! and round for different block hashes. This is unambiguously malicious
//! (a validator cannot legitimately do this).
//!
//! Penalty: SLASH_DOUBLE_PRECOMMIT_BPS (5%) of stake.
//!
//! ## Surround vote
//!
//! A validator's outer vote (h1, r1) surrounds an inner vote (h2, r2)
//! where h1 < h2 and r1 > r2. This is the Ethereum-style long-range
//! attack vector.
//!
//! Penalty: SLASH_SURROUND_VOTE_BPS (100%) of stake.
//!
//! ## Evidence format
//!
//! Evidence is a pair of conflicting votes from the same validator.
//! The verifier checks:
//!   1. Both votes have the same validator_id
//!   2. Both signatures are valid
//!   3. The votes are actually conflicting (different hashes at same height/round,
//!      or surround relationship)

use std::collections::HashMap;

use indra_core::types::{
    primitives::Bytes32,
    vote::{VoteStep, VoteV1},
};

/// The type of slashable offence detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlashOffence {
    /// Two precommits at the same height/round for different blocks.
    DoublePrecommit,
    /// An outer vote surrounds an inner vote.
    SurroundVote,
}

/// A detected slashable offence with supporting evidence.
#[derive(Debug, Clone)]
pub struct SlashEvidence {
    /// The offending validator.
    pub validator_id: Bytes32,
    /// The type of offence.
    pub offence: SlashOffence,
    /// First conflicting vote.
    pub vote_a: VoteV1,
    /// Second conflicting vote.
    pub vote_b: VoteV1,
}

/// Tracks votes observed from validators to detect slashable behaviour.
pub struct SlashDetector {
    /// validator_id → list of observed precommits
    precommits: HashMap<Bytes32, Vec<VoteV1>>,
    /// validator_id → list of observed prevotes (for surround detection)
    prevotes:   HashMap<Bytes32, Vec<VoteV1>>,
}

impl SlashDetector {
    /// Create a new detector.
    pub fn new() -> Self {
        Self {
            precommits: HashMap::new(),
            prevotes:   HashMap::new(),
        }
    }

    /// Observe a vote. Returns slash evidence if this vote conflicts
    /// with a previously observed vote from the same validator.
    pub fn observe_vote(&mut self, vote: VoteV1) -> Option<SlashEvidence> {
        match vote.step {
            VoteStep::Precommit => self.observe_precommit(vote),
            VoteStep::Prevote   => self.observe_prevote(vote),
        }
    }

    fn observe_precommit(&mut self, vote: VoteV1) -> Option<SlashEvidence> {
        let existing = self.precommits
            .entry(vote.validator_id)
            .or_default();

        // Check for double precommit: same height+round, different block hash
        for prev in existing.iter() {
            if prev.height == vote.height
                && prev.round == vote.round
                && prev.block_hash != vote.block_hash
            {
                return Some(SlashEvidence {
                    validator_id: vote.validator_id,
                    offence: SlashOffence::DoublePrecommit,
                    vote_a: prev.clone(),
                    vote_b: vote,
                });
            }
        }

        existing.push(vote);
        None
    }

    fn observe_prevote(&mut self, vote: VoteV1) -> Option<SlashEvidence> {
        let existing = self.prevotes
            .entry(vote.validator_id)
            .or_default();

        // Check for surround vote:
        // outer (h1, r1) surrounds inner (h2, r2) if h1 < h2 and r1 > r2
        for prev in existing.iter() {
            if is_surround(prev, &vote) || is_surround(&vote, prev) {
                return Some(SlashEvidence {
                    validator_id: vote.validator_id,
                    offence: SlashOffence::SurroundVote,
                    vote_a: prev.clone(),
                    vote_b: vote,
                });
            }
        }

        existing.push(vote);
        None
    }

    /// Clear votes older than the given height (prune stale evidence).
    pub fn prune_below(&mut self, height: u64) {
        for votes in self.precommits.values_mut() {
            votes.retain(|v| v.height >= height);
        }
        for votes in self.prevotes.values_mut() {
            votes.retain(|v| v.height >= height);
        }
    }

    /// Number of validators being tracked.
    pub fn tracked_validators(&self) -> usize {
        let mut ids: std::collections::HashSet<Bytes32> = self.precommits.keys().copied().collect();
        ids.extend(self.prevotes.keys().copied());
        ids.len()
    }
}

/// Check if vote `outer` surrounds vote `inner`.
/// outer surrounds inner if outer.height < inner.height && outer.round > inner.round
fn is_surround(outer: &VoteV1, inner: &VoteV1) -> bool {
    outer.height < inner.height && outer.round > inner.round
}

impl Default for SlashDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        VariableBytes,
        types::{
            crypto::HybridSignature,
            primitives::{MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES},
            vote::VoteStep,
        },
    };

    fn dummy_vote(
        validator_id: [u8; 32],
        height: u64,
        round: u32,
        step: VoteStep,
        block_hash: [u8; 32],
    ) -> VoteV1 {
        VoteV1 {
            height,
            round,
            step,
            block_hash: Bytes32::from(block_hash),
            validator_id: Bytes32::from(validator_id),
            signature: HybridSignature {
                classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(&[0u8; 64]).unwrap(),
                pq_sig:        VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&[0u8; 32]).unwrap(),
            },
        }
    }

    #[test]
    fn no_slash_for_honest_validator() {
        let mut detector = SlashDetector::new();
        let v = [0x01u8; 32];

        // Two precommits at different heights — fine
        let r1 = detector.observe_vote(dummy_vote(v, 1, 0, VoteStep::Precommit, [0xAAu8; 32]));
        let r2 = detector.observe_vote(dummy_vote(v, 2, 0, VoteStep::Precommit, [0xBBu8; 32]));
        assert!(r1.is_none());
        assert!(r2.is_none());
    }

    #[test]
    fn double_precommit_detected() {
        let mut detector = SlashDetector::new();
        let v = [0x02u8; 32];

        // Same height+round, different block hash
        detector.observe_vote(dummy_vote(v, 5, 0, VoteStep::Precommit, [0xAAu8; 32]));
        let evidence = detector.observe_vote(dummy_vote(v, 5, 0, VoteStep::Precommit, [0xBBu8; 32]));

        assert!(evidence.is_some());
        assert_eq!(evidence.unwrap().offence, SlashOffence::DoublePrecommit);
    }

    #[test]
    fn same_vote_twice_no_slash() {
        let mut detector = SlashDetector::new();
        let v = [0x03u8; 32];

        // Same vote twice — not a double vote (same block hash)
        detector.observe_vote(dummy_vote(v, 5, 0, VoteStep::Precommit, [0xAAu8; 32]));
        let evidence = detector.observe_vote(dummy_vote(v, 5, 0, VoteStep::Precommit, [0xAAu8; 32]));
        assert!(evidence.is_none());
    }

    #[test]
    fn surround_vote_detected() {
        let mut detector = SlashDetector::new();
        let v = [0x04u8; 32];

        // Outer: height=1, round=10
        detector.observe_vote(dummy_vote(v, 1, 10, VoteStep::Prevote, [0xAAu8; 32]));
        // Inner: height=5, round=2 — surrounded by outer (1 < 5, 10 > 2)
        let evidence = detector.observe_vote(dummy_vote(v, 5, 2, VoteStep::Prevote, [0xBBu8; 32]));

        assert!(evidence.is_some());
        assert_eq!(evidence.unwrap().offence, SlashOffence::SurroundVote);
    }

    #[test]
    fn different_validators_no_slash() {
        let mut detector = SlashDetector::new();

        // Two different validators, same height+round, different hashes — NOT a slash
        detector.observe_vote(dummy_vote([0x01u8; 32], 5, 0, VoteStep::Precommit, [0xAAu8; 32]));
        let evidence = detector.observe_vote(dummy_vote([0x02u8; 32], 5, 0, VoteStep::Precommit, [0xBBu8; 32]));
        assert!(evidence.is_none());
    }

    #[test]
    fn prune_removes_old_votes() {
        let mut detector = SlashDetector::new();
        let v = [0x05u8; 32];

        detector.observe_vote(dummy_vote(v, 1, 0, VoteStep::Precommit, [0xAAu8; 32]));
        detector.observe_vote(dummy_vote(v, 2, 0, VoteStep::Precommit, [0xBBu8; 32]));

        detector.prune_below(3);

        // After pruning, the old precommits are gone — no conflict detected
        let evidence = detector.observe_vote(dummy_vote(v, 1, 0, VoteStep::Precommit, [0xCCu8; 32]));
        assert!(evidence.is_none());
    }
}
