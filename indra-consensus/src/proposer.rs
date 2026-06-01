//! Deterministic proposer election and VRF proof generation.

use indra_core::types::primitives::Bytes32;
use indra_crypto::{sha256, vrf_prove, VrfKeypair, VrfOutput, VrfProof};

use crate::error::{ConsensusError, ConsensusResult};

/// An entry in the proposer election: one candidate validator.
#[derive(Debug, Clone)]
pub struct ProposerCandidate {
    /// Validator's 32-byte identity.
    pub validator_id: Bytes32,
    /// Validator's VRF public key.
    pub vrf_pubkey: [u8; 32],
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
    /// All active validators and their stakes.
    pub candidates: Vec<ProposerCandidate>,
}

impl ProposerElection {
    /// Compute the deterministic VRF input for this election.
    pub fn vrf_input(&self) -> [u8; 32] {
        compute_vrf_input(&self.epoch_seed.0, self.height)
    }
}

/// Compute the VRF input deterministically.
pub fn compute_vrf_input(epoch_seed: &[u8; 32], height: u64) -> [u8; 32] {
    use indra_crypto::hash::domains::VRF_INPUT;
    let mut data = VRF_INPUT.to_vec();
    data.extend_from_slice(epoch_seed);
    data.extend_from_slice(&height.to_le_bytes());
    sha256(&data)
}

/// Compute the stake-weighted election score for a VRF output.
/// Lower is better. Returns u64::MAX if stake is zero.
pub fn election_score(vrf_output: &VrfOutput, validator_stake: u64, total_stake: u64) -> u64 {
    if validator_stake == 0 || total_stake == 0 {
        return u64::MAX;
    }
    let output_val = u64::from_le_bytes(
        vrf_output.0[..8].try_into().unwrap_or([0xFF; 8])
    );
    let score = (output_val as u128)
        .saturating_mul(total_stake as u128)
        / (validator_stake as u128);
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

/// Elect the proposer for a given height.
pub fn elect_proposer(election: &ProposerElection) -> ConsensusResult<Bytes32> {
    if election.candidates.is_empty() {
        return Err(ConsensusError::EmptyValidatorSet);
    }
    let vrf_input = election.vrf_input();
    let total_stake: u64 = election.candidates.iter()
        .map(|c| c.stake)
        .fold(0u64, |a, b| a.saturating_add(b));

    let winner = election.candidates.iter()
        .map(|candidate| {
            let output = candidate_output(&candidate.vrf_pubkey, &vrf_input);
            let score = election_score(&output, candidate.stake, total_stake);
            (candidate, score, output)
        })
        .min_by(|(candidate_a, score_a, output_a), (candidate_b, score_b, output_b)| {
            score_a
                .cmp(score_b)
                .then_with(|| output_a.0.cmp(&output_b.0))
                .then_with(|| candidate_a.validator_id.0.cmp(&candidate_b.validator_id.0))
        })
        .map(|(candidate, _, _)| candidate.validator_id);

    winner.ok_or(ConsensusError::EmptyValidatorSet)
}

/// Compute the VRF output and proof for a validator at a given height.
pub fn compute_proposer_vrf(
    validator_id: Bytes32,
    keypair: &VrfKeypair,
    epoch_seed: &Bytes32,
    height: u64,
) -> SlotResult {
    let vrf_input = compute_vrf_input(&epoch_seed.0, height);
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
            vrf_pubkey:   VrfKeypair::from_seed(&[id_byte; 32]).public_key(),
            stake,
        }
    }

    fn election(candidates: Vec<ProposerCandidate>) -> ProposerElection {
        ProposerElection {
            epoch_seed: Bytes32::from([0x42u8; 32]),
            height: 1,
            candidates,
        }
    }

    #[test]
    fn election_with_single_validator() {
        let e = election(vec![candidate(0x01, 1_000_000)]);
        let winner = elect_proposer(&e).unwrap();
        assert_eq!(winner, Bytes32::from([0x01u8; 32]));
    }

    #[test]
    fn election_is_deterministic() {
        let candidates = vec![
            candidate(0x01, 1_000_000),
            candidate(0x02, 2_000_000),
            candidate(0x03, 500_000),
        ];
        let w1 = elect_proposer(&election(candidates.clone())).unwrap();
        let w2 = elect_proposer(&election(candidates)).unwrap();
        assert_eq!(w1, w2);
    }

    #[test]
    fn empty_validator_set_errors() {
        assert_eq!(elect_proposer(&election(vec![])), Err(ConsensusError::EmptyValidatorSet));
    }

    #[test]
    fn vrf_input_depends_on_height_and_seed() {
        let seed = Bytes32::from([0x01u8; 32]);
        let i1 = compute_vrf_input(&seed.0, 1);
        let i2 = compute_vrf_input(&seed.0, 2);
        assert_ne!(i1, i2);
    }

    #[test]
    fn high_stake_gets_lower_score() {
        // output_val = 1000 (from first 8 bytes as u64 little-endian)
        let mut bytes = [0u8; 32];
        bytes[0] = 0xe8; bytes[1] = 0x03; // 1000 in little-endian
        let output = VrfOutput(bytes);
        // low_stake: score = 1000 * 10000 / 100   = 100000
        // high_stake: score = 1000 * 10000 / 5000 = 2
        let low  = election_score(&output, 100,   10_000);
        let high = election_score(&output, 5_000, 10_000);
        assert!(high < low);
    }

    #[test]
    fn compute_vrf_uses_validator_id_identity() {
        let validator_id = Bytes32::from([0x55u8; 32]);
        let keypair = VrfKeypair::from_seed(&[0x11u8; 32]);
        let slot = compute_proposer_vrf(validator_id, &keypair, &Bytes32::from([0x22u8; 32]), 7);
        assert_eq!(slot.proposer_id, validator_id);
    }
}
