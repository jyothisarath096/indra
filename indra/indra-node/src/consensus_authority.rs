use indra_consensus::{error::ConsensusResult, proposer::ProposerElection};
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
) -> ConsensusResult<VrfConsensusAuthority> {
    Ok(VrfConsensusAuthority {
        election: ProposerElection::from_snapshot(
            chain_id,
            height,
            round,
            election_seed,
            snapshot,
        )?,
    })
}
