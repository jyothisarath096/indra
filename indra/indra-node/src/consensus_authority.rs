use indra_consensus::proposer::{ProposerCandidate, ProposerElection};
use indra_core::types::{consensus_snapshot::ConsensusSnapshot, primitives::Bytes64};

pub(crate) struct VrfConsensusAuthority {
    pub(crate) election: ProposerElection,
}

pub(crate) fn vrf_authority_from_snapshot(
    chain_id: &[u8],
    height: u64,
    round: u32,
    election_seed: Bytes64,
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
    VrfConsensusAuthority {
        election: ProposerElection {
            chain_id: chain_id.to_vec(),
            election_seed,
            snapshot_root: snapshot.snapshot_root,
            active_slot_coefficient_numerator: snapshot.active_slot_coefficient_numerator,
            height,
            round,
            candidates,
        },
    }
}
