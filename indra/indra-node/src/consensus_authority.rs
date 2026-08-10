use std::collections::BTreeMap;

use indra_consensus::proposer::{ProposerCandidate, ProposerElection};
use indra_core::{types::consensus_snapshot::ConsensusSnapshot, Bytes32};

pub(crate) struct VrfConsensusAuthority {
    pub(crate) election: ProposerElection,
    pub(crate) weights: BTreeMap<Bytes32, u64>,
    pub(crate) total_weight: u64,
}

pub(crate) fn vrf_authority_from_snapshot(
    height: u64,
    round: u32,
    epoch_seed: Bytes32,
    snapshot: &ConsensusSnapshot,
) -> VrfConsensusAuthority {
    let candidates = snapshot
        .entries()
        .iter()
        .map(|entry| ProposerCandidate {
            validator_id: entry.validator_id,
            vrf_pubkey: entry.vrf_pk,
            stake: entry.consensus_weight_spark,
        })
        .collect();
    let weights = snapshot
        .entries()
        .iter()
        .map(|entry| (entry.validator_id, entry.consensus_weight_spark))
        .collect();
    VrfConsensusAuthority {
        election: ProposerElection {
            epoch_seed,
            height,
            round,
            candidates,
        },
        weights,
        total_weight: snapshot.total_weight_spark,
    }
}
