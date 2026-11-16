//! Node-level error types.

use thiserror::Error;

/// All errors that can occur at the node level.
#[derive(Debug, Error)]
pub enum NodeError {
    /// Runtime configuration violates a node resource-safety invariant.
    #[error("invalid node configuration: {detail}")]
    InvalidConfiguration {
        /// Actionable description of the invalid setting.
        detail: String,
    },

    /// A storage operation failed.
    #[error("storage error: {0}")]
    Storage(#[from] indra_storage::StorageError),

    /// Durable storage cannot safely accept another state transition.
    #[error("critical local storage pressure: {detail}")]
    StoragePressure {
        /// Query failure or remaining-space detail.
        detail: String,
    },

    /// A state machine error.
    #[error("state error: {0}")]
    State(#[from] indra_state::StateError),

    /// Consensus snapshot lookup failed closed.
    #[error("consensus snapshot lookup error: {0}")]
    ConsensusSnapshotLookup(#[from] indra_state::ConsensusSnapshotLookupError),

    /// A staking operation was rejected before entering the local mempool.
    #[error("invalid staking op: {0}")]
    InvalidStakingOp(String),

    /// A governance operation was rejected before entering the local mempool.
    #[error("invalid governance op: {0}")]
    InvalidGovernanceOp(String),

    /// A consensus error.
    #[error("consensus error: {0}")]
    Consensus(#[from] indra_consensus::ConsensusError),

    /// The finite consensus-round domain was exhausted without a commit.
    #[error(
        "consensus round limit exceeded at height {height}: round {round} is the final legal round"
    )]
    RoundLimitExceeded {
        /// Height that failed to commit.
        height: u64,
        /// Final legal round.
        round: u32,
    },

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

    /// Snapshot was created by a newer schema than this binary supports.
    #[error("snapshot schema version {snapshot_version} is newer than node schema version {node_version}")]
    SchemaVersionTooNew {
        /// Schema version stored in the snapshot.
        snapshot_version: u8,
        /// Schema version supported by this node.
        node_version: u8,
    },

    /// Startup replay failed while verifying a persisted block.
    #[error("startup replay failed at height {height}: {reason}")]
    StartupReplayFailed {
        /// Height being replayed.
        height: u64,
        /// Why replay failed.
        reason: String,
    },

    /// Snapshot and retained block log disagree.
    #[error("snapshot/block mismatch at height {height}: {reason}")]
    SnapshotBlockMismatch {
        /// Snapshot height.
        height: u64,
        /// Why the snapshot and block log disagree.
        reason: String,
    },

    /// Durable vote-safety state exists but cannot be trusted at startup.
    #[error("vote safety unavailable: {detail}")]
    VoteSafetyUnavailable {
        /// Why the persisted safety record was rejected.
        detail: String,
    },

    /// A poisoned synchronization primitive means shared state may be torn.
    #[error("lock poisoned: {name}")]
    LockPoisoned {
        /// Stable name assigned to the poisoned lock.
        name: &'static str,
    },

    /// The published RPC snapshot could not be loaded or updated.
    #[error("RPC snapshot error: {0}")]
    RpcSnapshot(String),
}

/// Convenience alias.
pub type NodeResult<T> = Result<T, NodeError>;
