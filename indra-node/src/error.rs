//! Node-level error types.

use thiserror::Error;

/// All errors that can occur at the node level.
#[derive(Debug, Error)]
pub enum NodeError {
    /// A storage operation failed.
    #[error("storage error: {0}")]
    Storage(#[from] indra_storage::StorageError),

    /// A state machine error.
    #[error("state error: {0}")]
    State(#[from] indra_state::StateError),

    /// A staking operation was rejected before entering the local mempool.
    #[error("invalid staking op: {0}")]
    InvalidStakingOp(String),

    /// A consensus error.
    #[error("consensus error: {0}")]
    Consensus(#[from] indra_consensus::ConsensusError),

    /// A cryptographic error.
    #[error("crypto error: {0}")]
    Crypto(#[from] indra_crypto::CryptoError),

    /// A block failed validation before state application.
    #[error("block validation failed at height {height}: {reason}")]
    BlockInvalid {
        /// The block height.
        height: u64,
        /// Why it failed.
        reason: String,
    },

    /// The node is not the elected proposer for this slot.
    #[error("not the proposer for height {height}")]
    NotProposer {
        /// The height in question.
        height: u64,
    },

    /// Validator configuration is incomplete.
    #[error("validator configuration is incomplete: {detail}")]
    ValidatorConfigIncomplete {
        /// Which required fields were missing or inconsistent.
        detail: String,
    },

    /// The node is not configured as a validator for local signing.
    #[error("node is not configured as a validator")]
    NotValidator,

    /// No quorum certificate is available for the previous block, so this
    /// node cannot construct the next proposal yet.
    #[error("no QC available for height {height} proposal")]
    MissingQc {
        /// The height this node attempted to propose.
        height: u64,
    },

    /// Genesis state mismatch.
    #[error("genesis mismatch: stored genesis differs from configured genesis")]
    GenesisMismatch,

    /// Restarting from a pruned block log requires full state snapshots.
    #[error(
        "pruned block replay requires full state snapshots; lowest stored block is {lowest_height}"
    )]
    PrunedReplayUnsupported {
        /// Lowest block height still present in the local block store.
        lowest_height: u64,
    },

    /// Snapshot exists but the retained block log no longer covers the replay gap.
    #[error("snapshot at height {snapshot_height} cannot be replayed: block log starts at {lowest_block}, gap of {gap} blocks")]
    SnapshotReplayGap {
        /// Height encoded in the loaded snapshot.
        snapshot_height: u64,
        /// Lowest block height currently retained on disk.
        lowest_block: u64,
        /// Number of missing blocks between the snapshot and retained block window.
        gap: u64,
    },
}

/// Convenience alias.
pub type NodeResult<T> = Result<T, NodeError>;
