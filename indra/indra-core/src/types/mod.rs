//! All INDRA v2 protocol data structures.

pub mod block;
pub mod checkpoint;
pub mod crypto;
pub mod epoch_record;
pub mod governance;
pub mod primitives;
pub mod qc;
pub mod slash_detector;
pub mod slashing;
pub mod staking;
pub mod transaction;
pub mod vote;
pub mod vote_signing;
pub mod vrf_election;

pub use epoch_record::EpochRecord;
