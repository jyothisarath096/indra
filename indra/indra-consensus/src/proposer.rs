//! Deterministic proposer election and VRF proof generation.

use std::collections::BTreeMap;

use indra_core::types::primitives::{
    public_proposer_election_active, vrf_verified_output_active, Bytes32, MAX_ROUNDS_PER_HEIGHT,
};
use indra_core::types::vrf_election::VrfElectionResult;
use indra_crypto::{sha256, vrf_prove, VrfKeypair, VrfOutput, VrfProof};

use crate::error::{ConsensusError, ConsensusResult};

/// An entry in the proposer election: one candidate validator.
#[derive(Debug, Clone)]
pub struct ProposerCandidate {
    /// Validator's 32-byte identity.
    pub validator_id: Bytes32,
    /// Validator's VRF public key.
    pub vrf_pubkey: [u8; 32],
    /// Verified VRF output for this exact election slot, when available.
    pub verified_vrf_output: Option<VrfOutput>,
    /// Validator's stake in Spark.
    pub stake: u64,
}

/// The result of a proposer election for one height.
#[derive(Debug, Clone)]
pub struct SlotResult {
    /// The elected proposer's validator ID.
    pub proposer_id: Bytes32,
    /// Their VRF output for this height.
    pub vrf_output: VrfOutput,
    /// Their VRF proof (included in block header).
    pub vrf_proof: VrfProof,
    /// The VRF input used.
    pub vrf_input: [u8; 32],
}

/// Input to the proposer election algorithm.
pub struct ProposerElection {
    /// The epoch seed.
    pub epoch_seed: Bytes32,
    /// The height being proposed.
    pub height: u64,
    /// The consensus round for this height.
    pub round: u32,
    /// All active validators and their stakes.
    pub candidates: Vec<ProposerCandidate>,
}

impl ProposerElection {
    /// Compute the deterministic slot index for this election.
    pub fn slot_index(&self) -> u64 {
        proposer_slot_index(self.height, self.round)
    }

    /// Compute the deterministic VRF input for this election.
    pub fn vrf_input(&self) -> [u8; 32] {
        compute_vrf_input(&self.epoch_seed.0, self.height, self.round)
    }
}

/// Derive a unique deterministic slot index from `(height, round)`.
pub fn proposer_slot_index(height: u64, round: u32) -> u64 {
    height
        .saturating_mul(MAX_ROUNDS_PER_HEIGHT)
        .saturating_add(round as u64)
}

/// Encode the shared proposer-election input.
pub fn vrf_election_input(height: u64, round: u32, epoch_seed: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(8 + 4 + 8);
    data.extend_from_slice(&height.to_le_bytes());
    data.extend_from_slice(&round.to_le_bytes());
    data.extend_from_slice(&epoch_seed[..8]);
    data
}

/// Compute the VRF input deterministically.
pub fn compute_vrf_input(epoch_seed: &[u8; 32], height: u64, round: u32) -> [u8; 32] {
    use indra_crypto::hash::domains::VRF_INPUT;
    let mut data = VRF_INPUT.to_vec();
    data.extend_from_slice(&vrf_election_input(height, round, epoch_seed));
    sha256(&data)
}

/// Compute the stake-weighted election score for a VRF output.
/// Lower is better. Returns u64::MAX if stake is zero.
pub fn election_score(vrf_output: &VrfOutput, validator_stake: u64, total_stake: u64) -> u64 {
    if validator_stake == 0 || total_stake == 0 {
        return u64::MAX;
    }
    let output_val = u64::from_le_bytes(vrf_output.0[..8].try_into().unwrap_or([0xFF; 8]));
    let score =
        (output_val as u128).saturating_mul(total_stake as u128) / (validator_stake as u128);
    score.min(u64::MAX as u128) as u64
}

/// Compute the deterministic public election output for a candidate.
///
/// This is derived only from the public VRF key and election input, so every
/// node can reproduce the same ordering without access to any validator seed.
pub fn candidate_output(vrf_pubkey: &[u8; 32], vrf_input: &[u8; 32]) -> VrfOutput {
    let mut data = Vec::with_capacity(vrf_pubkey.len() + vrf_input.len());
    data.extend_from_slice(vrf_pubkey);
    data.extend_from_slice(vrf_input);
    VrfOutput(sha256(&data))
}

/// Compute a deterministic public proposer score for a candidate.
///
/// This replaces the old mixed-output election (one real VRF output vs.
/// public SHA256 fallbacks for others) with a single fully public function
/// evaluated identically by every validator.
///
/// The VRF proof in the block header still proves ownership of the registered
/// VRF key, but is not used for winner selection while
/// `PUBLIC_PROPOSER_ELECTION_HEIGHT` is active.
pub fn public_proposer_output(
    epoch_seed: &Bytes32,
    height: u64,
    round: u32,
    validator_id: &Bytes32,
    vrf_pubkey: &[u8; 32],
) -> VrfOutput {
    let mut data = b"INDRA-PROPOSER-PUBLIC-v1".to_vec();
    data.extend_from_slice(&epoch_seed.0);
    data.extend_from_slice(&height.to_le_bytes());
    data.extend_from_slice(&round.to_le_bytes());
    data.extend_from_slice(&validator_id.0);
    data.extend_from_slice(vrf_pubkey);
    VrfOutput(sha256(&data))
}

/// Elect the proposer for a given height.
pub fn elect_proposer(election: &ProposerElection, height: u64) -> ConsensusResult<Bytes32> {
    if election.candidates.is_empty() {
        return Err(ConsensusError::EmptyValidatorSet);
    }
    let vrf_input = election.vrf_input();
    let total_stake: u64 = election
        .candidates
        .iter()
        .map(|c| c.stake)
        .fold(0u64, |a, b| a.saturating_add(b));

    let winner = election
        .candidates
        .iter()
        .map(|candidate| {
            let output = if public_proposer_election_active(height) {
                // DETERMINISM SAFETY: winner selection must be a single public
                // function over the full candidate set. Do not use
                // `verified_vrf_output` here; a proposal only reveals one
                // validator's actual VRF output, which makes the old mixed
                // election perspective-dependent and permits multiple
                // apparent proposers for the same slot.
                public_proposer_output(
                    &election.epoch_seed,
                    election.height,
                    election.round,
                    &candidate.validator_id,
                    &candidate.vrf_pubkey,
                )
            } else if vrf_verified_output_active(height) {
                candidate
                    .verified_vrf_output
                    .clone()
                    .unwrap_or_else(|| candidate_output(&candidate.vrf_pubkey, &vrf_input))
            } else {
                candidate_output(&candidate.vrf_pubkey, &vrf_input)
            };
            let score = election_score(&output, candidate.stake, total_stake);
            (candidate, score, output)
        })
        .min_by(
            |(candidate_a, score_a, output_a), (candidate_b, score_b, output_b)| {
                score_a
                    .cmp(score_b)
                    .then_with(|| output_a.0.cmp(&output_b.0))
                    .then_with(|| candidate_a.validator_id.0.cmp(&candidate_b.validator_id.0))
            },
        )
        .map(|(candidate, _, _)| candidate.validator_id);

    winner.ok_or(ConsensusError::EmptyValidatorSet)
}

/// Sentinel VRF output used in the election-result hash for public fallback.
pub const VRF_FALLBACK_OUTPUT: Bytes32 = Bytes32([0xFF; 32]);

/// Compute the public deterministic fallback election result.
pub fn compute_fallback_election_result(
    election: &ProposerElection,
) -> ConsensusResult<VrfElectionResult> {
    let elected = elect_proposer(election, election.height)?;
    Ok(VrfElectionResult {
        height: election.height,
        round: election.round,
        elected_validator_id: elected,
        elected_vrf_output: VRF_FALLBACK_OUTPUT,
        fallback_used: true,
    })
}

/// Elect a proposer from a validated reveal set.
///
/// `revealed_outputs` maps validator ID to verified VRF output. Missing
/// validators receive the worst possible score. The denominator remains total
/// active stake, not revealed stake.
pub fn elect_proposer_from_reveals(
    election: &ProposerElection,
    revealed_outputs: &BTreeMap<Bytes32, Bytes32>,
) -> ConsensusResult<VrfElectionResult> {
    if election.candidates.is_empty() {
        return Err(ConsensusError::EmptyValidatorSet);
    }
    if revealed_outputs.is_empty() {
        return compute_fallback_election_result(election);
    }
    let total_stake: u64 = election
        .candidates
        .iter()
        .map(|c| c.stake)
        .fold(0u64, |a, b| a.saturating_add(b));

    let winner = election
        .candidates
        .iter()
        .map(|candidate| {
            let output = revealed_outputs
                .get(&candidate.validator_id)
                .copied()
                .unwrap_or(VRF_FALLBACK_OUTPUT);
            let score = election_score(&VrfOutput(output.0), candidate.stake, total_stake);
            (candidate.validator_id, score, output)
        })
        .min_by(|(id_a, score_a, output_a), (id_b, score_b, output_b)| {
            score_a
                .cmp(score_b)
                .then_with(|| output_a.0.cmp(&output_b.0))
                .then_with(|| id_a.0.cmp(&id_b.0))
        });

    winner
        .map(|(elected_validator_id, _, elected_vrf_output)| VrfElectionResult {
            height: election.height,
            round: election.round,
            elected_validator_id,
            elected_vrf_output,
            fallback_used: false,
        })
        .ok_or(ConsensusError::EmptyValidatorSet)
}

/// Compute the VRF output and proof for a validator at a given height.
pub fn compute_proposer_vrf(
    validator_id: Bytes32,
    keypair: &VrfKeypair,
    epoch_seed: &Bytes32,
    height: u64,
    round: u32,
) -> SlotResult {
    let vrf_input = compute_vrf_input(&epoch_seed.0, height, round);
    let (vrf_output, vrf_proof) = vrf_prove(keypair, &vrf_input);
    SlotResult {
        proposer_id: validator_id,
        vrf_output,
        vrf_proof,
        vrf_input,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id_byte: u8, stake: u64) -> ProposerCandidate {
        ProposerCandidate {
            validator_id: Bytes32::from([id_byte; 32]),
            vrf_pubkey: VrfKeypair::from_seed(&[id_byte; 32]).public_key(),
            verified_vrf_output: None,
            stake,
        }
    }

    fn election(candidates: Vec<ProposerCandidate>) -> ProposerElection {
        ProposerElection {
            epoch_seed: Bytes32::from([0x42u8; 32]),
            height: 1,
            round: 0,
            candidates,
        }
    }

    #[test]
    fn election_with_single_validator() {
        let e = election(vec![candidate(0x01, 1_000_000)]);
        let winner = elect_proposer(&e, e.height).unwrap();
        assert_eq!(winner, Bytes32::from([0x01u8; 32]));
    }

    #[test]
    fn election_is_deterministic() {
        let candidates = vec![
            candidate(0x01, 1_000_000),
            candidate(0x02, 2_000_000),
            candidate(0x03, 500_000),
        ];
        let e1 = election(candidates.clone());
        let e2 = election(candidates);
        let w1 = elect_proposer(&e1, e1.height).unwrap();
        let w2 = elect_proposer(&e2, e2.height).unwrap();
        assert_eq!(w1, w2);
    }

    #[test]
    fn empty_validator_set_errors() {
        assert_eq!(
            {
                let e = election(vec![]);
                elect_proposer(&e, e.height)
            },
            Err(ConsensusError::EmptyValidatorSet)
        );
    }

    #[test]
    fn vrf_input_depends_on_height_and_seed() {
        let seed = Bytes32::from([0x01u8; 32]);
        let i1 = compute_vrf_input(&seed.0, 1, 0);
        let i2 = compute_vrf_input(&seed.0, 2, 0);
        assert_ne!(i1, i2);
    }

    #[test]
    fn election_winner_varies_across_rounds() {
        let candidates = vec![candidate(0x01, 1_000_000), candidate(0x02, 1_000_000)];
        let mut winners = std::collections::BTreeSet::new();
        for round in 0..10u32 {
            let election = ProposerElection {
                epoch_seed: Bytes32::from([0x42u8; 32]),
                height: 7,
                round,
                candidates: candidates.clone(),
            };
            winners.insert(elect_proposer(&election, election.height).unwrap());
        }
        assert!(winners.len() > 1, "winner did not vary across rounds");
    }

    #[test]
    fn same_height_round_gives_same_winner() {
        let candidates = vec![candidate(0x01, 1_000_000), candidate(0x02, 1_000_000)];
        let election_a = ProposerElection {
            epoch_seed: Bytes32::from([0x42u8; 32]),
            height: 5,
            round: 2,
            candidates: candidates.clone(),
        };
        let election_b = ProposerElection {
            epoch_seed: Bytes32::from([0x42u8; 32]),
            height: 5,
            round: 2,
            candidates,
        };
        assert_eq!(
            elect_proposer(&election_a, election_a.height).unwrap(),
            elect_proposer(&election_b, election_b.height).unwrap()
        );
    }

    #[test]
    fn slot_index_depends_on_height_and_round() {
        assert_ne!(proposer_slot_index(5, 0), proposer_slot_index(5, 1));
        assert_ne!(proposer_slot_index(5, 0), proposer_slot_index(6, 0));
    }

    #[test]
    fn election_input_encoding_is_stable() {
        let epoch_seed = [0xABu8; 32];
        let input = vrf_election_input(9, 3, &epoch_seed);
        assert_eq!(&input[..8], &9u64.to_le_bytes());
        assert_eq!(&input[8..12], &3u32.to_le_bytes());
        assert_eq!(&input[12..20], &epoch_seed[..8]);
        assert_eq!(input.len(), 20);
    }

    #[test]
    fn high_stake_gets_lower_score() {
        // output_val = 1000 (from first 8 bytes as u64 little-endian)
        let mut bytes = [0u8; 32];
        bytes[0] = 0xe8;
        bytes[1] = 0x03; // 1000 in little-endian
        let output = VrfOutput(bytes);
        // low_stake: score = 1000 * 10000 / 100   = 100000
        // high_stake: score = 1000 * 10000 / 5000 = 2
        let low = election_score(&output, 100, 10_000);
        let high = election_score(&output, 5_000, 10_000);
        assert!(high < low);
    }

    #[test]
    fn compute_vrf_uses_validator_id_identity() {
        let validator_id = Bytes32::from([0x55u8; 32]);
        let keypair = VrfKeypair::from_seed(&[0x11u8; 32]);
        let slot = compute_proposer_vrf(validator_id, &keypair, &Bytes32::from([0x22u8; 32]), 7, 0);
        assert_eq!(slot.proposer_id, validator_id);
    }

    #[test]
    fn elect_proposer_returns_same_winner_regardless_of_verified_vrf_output() {
        let mut candidates_with_verified = vec![
            candidate(0x01, 1_000_000),
            candidate(0x02, 1_000_000),
            candidate(0x03, 1_000_000),
            candidate(0x04, 1_000_000),
        ];
        candidates_with_verified[2].verified_vrf_output = Some(VrfOutput([0u8; 32]));

        let election_with_verified = election(candidates_with_verified);
        let election_without_verified = election(vec![
            candidate(0x01, 1_000_000),
            candidate(0x02, 1_000_000),
            candidate(0x03, 1_000_000),
            candidate(0x04, 1_000_000),
        ]);

        assert_eq!(
            elect_proposer(&election_with_verified, election_with_verified.height).unwrap(),
            elect_proposer(&election_without_verified, election_without_verified.height).unwrap(),
            "verified_vrf_output must not affect public deterministic election"
        );
    }

    #[test]
    fn public_proposer_output_is_deterministic_and_domain_separated() {
        let epoch_seed = Bytes32::from([0x42u8; 32]);
        let validator_id = Bytes32::from([0x11u8; 32]);
        let vrf_pubkey = VrfKeypair::from_seed(&[0x11u8; 32]).public_key();

        let a = public_proposer_output(&epoch_seed, 10, 2, &validator_id, &vrf_pubkey);
        let b = public_proposer_output(&epoch_seed, 10, 2, &validator_id, &vrf_pubkey);
        assert_eq!(a.0, b.0, "same public election inputs must be stable");

        let mut other_domain = b"INDRA-PROPOSER-OTHER-v1".to_vec();
        other_domain.extend_from_slice(&epoch_seed.0);
        other_domain.extend_from_slice(&10u64.to_le_bytes());
        other_domain.extend_from_slice(&2u32.to_le_bytes());
        other_domain.extend_from_slice(&validator_id.0);
        other_domain.extend_from_slice(&vrf_pubkey);
        assert_ne!(
            a.0,
            sha256(&other_domain),
            "public proposer output must be domain separated"
        );
    }

    #[test]
    fn proposer_election_is_stake_weighted() {
        let candidates = vec![candidate(0x01, 2_000_000), candidate(0x02, 1_000_000)];
        let mut high_stake_wins = 0usize;
        let mut low_stake_wins = 0usize;

        for height in 1..=500u64 {
            for round in 0..10u32 {
                let election = ProposerElection {
                    epoch_seed: Bytes32::from([0x42u8; 32]),
                    height,
                    round,
                    candidates: candidates.clone(),
                };
                match elect_proposer(&election, election.height).unwrap().0[0] {
                    0x01 => high_stake_wins += 1,
                    0x02 => low_stake_wins += 1,
                    other => panic!("unexpected winner {other:#x}"),
                }
            }
        }

        assert!(
            high_stake_wins > low_stake_wins,
            "higher stake candidate should win more slots"
        );
        let ratio = high_stake_wins as f64 / low_stake_wins as f64;
        assert!(
            (1.5..=2.5).contains(&ratio),
            "2x stake should win roughly 2x slots, got ratio {ratio:.3}"
        );
    }

    #[test]
    fn commit_reveal_election_is_deterministic_from_same_reveals() {
        let election = ProposerElection {
            epoch_seed: Bytes32::from([0x99u8; 32]),
            height: 11,
            round: 3,
            candidates: vec![
                candidate(0x01, 1_000_000),
                candidate(0x02, 1_000_000),
                candidate(0x03, 1_000_000),
                candidate(0x04, 1_000_000),
            ],
        };
        let mut reveals = BTreeMap::new();
        reveals.insert(Bytes32::from([0x01u8; 32]), Bytes32::from([0x31u8; 32]));
        reveals.insert(Bytes32::from([0x02u8; 32]), Bytes32::from([0x12u8; 32]));
        reveals.insert(Bytes32::from([0x03u8; 32]), Bytes32::from([0x23u8; 32]));

        let a = elect_proposer_from_reveals(&election, &reveals).unwrap();
        let b = elect_proposer_from_reveals(&election, &reveals).unwrap();

        assert_eq!(a, b);
        assert!(!a.fallback_used);
        assert_eq!(a.hash(), b.hash());
    }

    #[test]
    fn withholding_validator_gets_worst_score() {
        let election = ProposerElection {
            epoch_seed: Bytes32::from([0x42u8; 32]),
            height: 2,
            round: 1,
            candidates: vec![candidate(0x01, 1_000_000), candidate(0x02, 1_000_000)],
        };
        let mut reveals = BTreeMap::new();
        reveals.insert(Bytes32::from([0x02u8; 32]), Bytes32::ZERO);

        let result = elect_proposer_from_reveals(&election, &reveals).unwrap();

        assert_eq!(result.elected_validator_id, Bytes32::from([0x02u8; 32]));
        assert_eq!(result.elected_vrf_output, Bytes32::ZERO);
        assert!(!result.fallback_used);
    }

    #[test]
    fn zero_reveals_use_public_fallback_result() {
        let election = ProposerElection {
            epoch_seed: Bytes32::from([0x42u8; 32]),
            height: 2,
            round: 1,
            candidates: vec![candidate(0x01, 1_000_000), candidate(0x02, 1_000_000)],
        };
        let reveals = BTreeMap::new();

        let result = elect_proposer_from_reveals(&election, &reveals).unwrap();
        let fallback = compute_fallback_election_result(&election).unwrap();

        assert_eq!(result, fallback);
        assert_eq!(result.elected_vrf_output, VRF_FALLBACK_OUTPUT);
        assert!(result.fallback_used);
    }
}
