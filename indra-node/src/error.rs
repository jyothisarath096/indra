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

    /// Genesis state mismatch.
    #[error("genesis mismatch: stored genesis differs from configured genesis")]
    GenesisMismatch,

    /// Restarting from a pruned block log requires full state snapshots.
    #[error("pruned block replay requires full state snapshots; lowest stored block is {lowest_height}")]
    PrunedReplayUnsupported {
        /// Lowest block height still present in the local block store.
        lowest_height: u64,
    },
}

/// Convenience alias.
pub type NodeResult<T> = Result<T, NodeError>;
