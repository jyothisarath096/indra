//! All INDRA v2 protocol data structures.

pub mod authorization;
pub mod block;
pub mod checkpoint;
pub mod consensus_snapshot;
pub mod crypto;
pub mod epoch_record;
pub mod governance;
pub mod primitives;
pub mod qc;
pub mod reward_economic_snapshot;
pub mod slash_detector;
pub mod slash_membership;
pub mod slashing;
pub mod stake_position;
pub mod staking;
pub mod transaction;
pub mod vote;
pub mod vote_signing;
pub mod vrf_election;

pub use consensus_snapshot::{ConsensusSnapshot, ConsensusSnapshotEntry};
pub use epoch_record::EpochRecord;
pub use reward_economic_snapshot::{
    RewardEconomicDelegatorEntry, RewardEconomicSnapshot, RewardEconomicValidatorEntry,
};
pub use stake_position::{
    eviction_tranche_creation_id_v1, staking_op_id_v2, ActiveStakeAggregateV1, PositionCustodyV1,
    StakePositionV1, UnbondingTimingV1, UnbondingTrancheV1,
};
