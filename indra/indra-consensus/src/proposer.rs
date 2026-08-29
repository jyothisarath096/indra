//! RFC-VRF proposer eligibility and deterministic priority.
use crate::error::{ConsensusError, ConsensusResult};
use indra_core::{
    sortition::{evaluate, priority, CertifiedLogInterval},
    types::{
        consensus_snapshot::ConsensusSnapshot,
        primitives::{validate_consensus_round, Bytes32, Bytes64},
        proposal::proposer_vrf_alpha,
    },
};
use indra_crypto::{vrf_prove, VrfKeypair, VrfOutput, VrfProof};
/// One immutable snapshot candidate.
#[derive(Debug, Clone)]
pub struct ProposerCandidate {
    /// Full hybrid identity ID.
    pub validator_id: Bytes32,
    /// Registered standard VRF key.
    pub vrf_pubkey: [u8; 32],
    /// Frozen snapshot stake.
    pub stake: u64,
}
/// Complete election authority for one height and round.
#[derive(Debug, Clone)]
pub struct ProposerElection {
    /// Chain identifier bytes.
    pub chain_id: Vec<u8>,
    /// QC-certified current seed.
    pub election_seed: Bytes64,
    /// Governing snapshot root.
    pub snapshot_root: Bytes32,
    /// Immutable genesis `F`.
    pub active_slot_coefficient_numerator: u64,
    /// Authoritative state-root-committed Q768 logarithm certificate.
    pub sortition_log: CertifiedLogInterval,
    /// Height.
    pub height: u64,
    /// Round.
    pub round: u32,
    /// Frozen candidates.
    pub candidates: Vec<ProposerCandidate>,
}
/// Locally proven eligibility material.
#[derive(Debug, Clone)]
pub struct SlotResult {
    /// Proposer identity.
    pub proposer_id: Bytes32,
    /// Standard output.
    pub vrf_output: VrfOutput,
    /// Standard proof.
    pub vrf_proof: VrfProof,
    /// Exact RFC alpha.
    pub vrf_input: Vec<u8>,
    /// Whether the validator is eligible.
    pub eligible: bool,
    /// Full-width deterministic priority.
    pub priority: Bytes64,
}
impl ProposerElection {
    /// Construct election authority directly from a validated governing snapshot.
    pub fn from_snapshot(
        chain_id: &[u8],
        height: u64,
        round: u32,
        election_seed: Bytes64,
        snapshot: &ConsensusSnapshot,
    ) -> ConsensusResult<Self> {
        validate_consensus_round(round).map_err(|error| ConsensusError::InvalidRound {
            detail: error.to_string(),
        })?;
        let sortition_log =
            snapshot
                .sortition_log_interval()
                .map_err(|error| ConsensusError::CryptoError {
                    detail: error.to_string(),
                })?;
        let candidates = snapshot
            .entries()
            .iter()
            .map(|entry| ProposerCandidate {
                validator_id: entry.validator_id,
                vrf_pubkey: entry.vrf_pk,
                stake: entry.consensus_weight_spark,
            })
            .collect();
        Ok(Self {
            chain_id: chain_id.to_vec(),
            election_seed,
            snapshot_root: snapshot.snapshot_root,
            active_slot_coefficient_numerator: snapshot.active_slot_coefficient_numerator,
            sortition_log,
            height,
            round,
            candidates,
        })
    }

    /// Exact full-width alpha for a candidate.
    pub fn vrf_input(&self, id: &Bytes32) -> ConsensusResult<Vec<u8>> {
        proposer_vrf_alpha(
            &self.chain_id,
            &self.election_seed,
            self.height,
            self.round,
            &self.snapshot_root,
            id,
        )
        .map_err(|e| ConsensusError::CryptoError {
            detail: e.to_string(),
        })
    }
}
/// Prove and evaluate this local candidate against the governing snapshot.
pub fn compute_proposer_vrf(
    id: Bytes32,
    keypair: &VrfKeypair,
    election: &ProposerElection,
) -> ConsensusResult<SlotResult> {
    validate_consensus_round(election.round).map_err(|error| ConsensusError::InvalidRound {
        detail: error.to_string(),
    })?;
    let candidate = election
        .candidates
        .iter()
        .find(|c| c.validator_id == id && c.vrf_pubkey == keypair.public_key())
        .ok_or_else(|| {
            ConsensusError::wrong_proposer("local VRF key is absent from governing snapshot")
        })?;
    let input = election.vrf_input(&id)?;
    let (output, proof) = vrf_prove(keypair, &input);
    let total = election
        .candidates
        .iter()
        .try_fold(0u64, |a, c| a.checked_add(c.stake))
        .ok_or_else(|| ConsensusError::CryptoError {
            detail: "snapshot stake overflow".into(),
        })?;
    let result =
        evaluate(&election.sortition_log, candidate.stake, total, &output.0).map_err(|e| {
            ConsensusError::CryptoError {
                detail: e.to_string(),
            }
        })?;
    Ok(SlotResult {
        proposer_id: id,
        priority: Bytes64(priority(&output.0, &id.0)),
        vrf_output: output,
        vrf_proof: proof,
        vrf_input: input,
        eligible: result.eligible,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn input_binds_complete_seed_round_snapshot_and_identity() {
        let e = ProposerElection {
            chain_id: b"c".to_vec(),
            election_seed: Bytes64([1; 64]),
            snapshot_root: Bytes32([2; 32]),
            active_slot_coefficient_numerator: 1,
            sortition_log: indra_core::sortition::certified_log(1).unwrap(),
            height: 3,
            round: 4,
            candidates: vec![],
        };
        let a = e.vrf_input(&Bytes32([5; 32])).unwrap();
        let mut e2 = e.clone();
        e2.election_seed.0[63] ^= 1;
        assert_ne!(a, e2.vrf_input(&Bytes32([5; 32])).unwrap())
    }

    #[test]
    fn proposer_transcript_rejects_round_limit_and_above() {
        let mut election = ProposerElection {
            chain_id: b"c".to_vec(),
            election_seed: Bytes64([1; 64]),
            snapshot_root: Bytes32([2; 32]),
            active_slot_coefficient_numerator: 1,
            sortition_log: indra_core::sortition::certified_log(1).unwrap(),
            height: 3,
            round: 0,
            candidates: vec![],
        };
        for round in [
            indra_core::types::primitives::MAX_ROUNDS_PER_HEIGHT,
            indra_core::types::primitives::MAX_ROUNDS_PER_HEIGHT + 1,
            u32::MAX,
        ] {
            election.round = round;
            assert!(election.vrf_input(&Bytes32([5; 32])).is_err());
        }
    }

    #[test]
    fn one_candidate_withholding_cannot_change_another_candidates_result() {
        let a = VrfKeypair::from_seed(&[0x31; 32]);
        let b = VrfKeypair::from_seed(&[0x32; 32]);
        let a_id = Bytes32([0xA1; 32]);
        let election = ProposerElection {
            chain_id: b"c".to_vec(),
            election_seed: Bytes64([1; 64]),
            snapshot_root: Bytes32([2; 32]),
            active_slot_coefficient_numerator:
                indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
            sortition_log: indra_core::sortition::certified_log(
                indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
            )
            .unwrap(),
            height: 3,
            round: 4,
            candidates: vec![
                ProposerCandidate {
                    validator_id: a_id,
                    vrf_pubkey: a.public_key(),
                    stake: 60,
                },
                ProposerCandidate {
                    validator_id: Bytes32([0xB2; 32]),
                    vrf_pubkey: b.public_key(),
                    stake: 40,
                },
            ],
        };
        let before = compute_proposer_vrf(a_id, &a, &election).unwrap();
        // There is deliberately no submitted-proof collection in the
        // calculation: withholding B's private proof cannot alter A's alpha,
        // denominator, threshold, output, eligibility, or priority.
        let after = compute_proposer_vrf(a_id, &a, &election).unwrap();
        assert_eq!(before.vrf_input, after.vrf_input);
        assert_eq!(before.vrf_output, after.vrf_output);
        assert_eq!(before.eligible, after.eligible);
        assert_eq!(before.priority, after.priority);
    }

    #[test]
    fn proposer_evaluation_consumes_supplied_certificate_without_recomputing_f() {
        let keypair = VrfKeypair::from_seed(&[0x41; 32]);
        let validator_id = Bytes32([0x42; 32]);
        let base = ProposerElection {
            chain_id: b"certificate-authority-test".to_vec(),
            election_seed: Bytes64([0x43; 64]),
            snapshot_root: Bytes32([0x44; 32]),
            // Deliberately invalid as an independent input: ordinary proposer
            // evaluation must not recompute a certificate from this field.
            active_slot_coefficient_numerator: 0,
            sortition_log: indra_core::sortition::certified_log(
                indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
            )
            .unwrap(),
            height: 7,
            round: 0,
            candidates: vec![ProposerCandidate {
                validator_id,
                vrf_pubkey: keypair.public_key(),
                stake: 100,
            }],
        };

        let mut election = (0..4_096)
            .find_map(|round| {
                let mut election = base.clone();
                election.round = round;
                compute_proposer_vrf(validator_id, &keypair, &election)
                    .unwrap()
                    .eligible
                    .then_some(election)
            })
            .expect("mainnet active-slot coefficient must yield an eligible test round");

        // Replacing the supplied certificate with the zero interval changes
        // the decision even though F is untouched, proving evaluate consumes
        // the carried certificate. This interval cannot originate in a
        // validated snapshot; snapshot validation tests that boundary.
        election.sortition_log.lo = Default::default();
        election.sortition_log.hi = Default::default();
        assert!(
            !compute_proposer_vrf(validator_id, &keypair, &election)
                .unwrap()
                .eligible
        );
    }
}
