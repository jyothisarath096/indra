//! Storage error types.

use thiserror::Error;

/// All errors that can occur in the storage layer.
#[derive(Debug, Error)]
pub enum StorageError {
    /// An I/O error from the operating system.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A block at the requested height does not exist.
    #[error("block not found at height {height}")]
    BlockNotFound {
        /// The requested height.
        height: u64,
    },

    /// An epoch record at the requested epoch does not exist.
    #[error("epoch record not found at epoch {epoch}")]
    EpochNotFound {
        /// The requested epoch.
        epoch: u64,
    },

    /// Block has been pruned and is no longer available.
    #[error("block {height} has been pruned (lowest available: {lowest_available})")]
    BlockPruned {
        /// The requested height.
        height: u64,
        /// Lowest height currently retained by this node.
        lowest_available: u64,
    },

    /// The stored data failed to decode — likely corruption.
    #[error("data corruption at height {height}: {detail}")]
    Corruption {
        /// Which height was being read.
        height: u64,
        /// What went wrong.
        detail: String,
    },

    /// A block log entry checksum did not match the stored bytes.
    #[error(
        "block log checksum mismatch at height {height}: expected {expected:#010x}, got {actual:#010x}"
    )]
    BlockChecksumMismatch {
        /// Entry height.
        height: u64,
        /// Stored checksum.
        expected: u32,
        /// Recomputed checksum.
        actual: u32,
    },

    /// The block log has a missing height inside its retained range.
    #[error("block log gap: missing retained height {missing_height}")]
    BlockLogGap {
        /// Missing block height.
        missing_height: u64,
    },

    /// The WAL entry was truncated — incomplete write, safe to discard.
    #[error("truncated WAL entry at offset {offset}")]
    TruncatedEntry {
        /// File offset of the bad entry.
        offset: u64,
    },

    /// Tried to write a block at a non-sequential height.
    #[error("non-sequential write: expected height {expected}, got {actual}")]
    NonSequential {
        /// Expected next height.
        expected: u64,
        /// Actual height provided.
        actual: u64,
    },

    /// A snapshot sidecar root did not match the decoded snapshot.
    #[error("snapshot root mismatch at height {height}: {detail}")]
    SnapshotRootMismatch {
        /// Snapshot height.
        height: u64,
        /// What did not match.
        detail: String,
    },

    /// A snapshot tip hash did not match its sidecar or retained block.
    #[error("snapshot tip mismatch at height {height}: {detail}")]
    SnapshotTipMismatch {
        /// Snapshot height.
        height: u64,
        /// What did not match.
        detail: String,
    },

    /// Durable chain manifest did not match component storage.
    #[error("chain manifest mismatch: {detail}")]
    ManifestMismatch {
        /// What did not match.
        detail: String,
    },

    /// A synchronization primitive protecting a multi-step storage invariant
    /// was poisoned by a panic. Continuing could pair stale metadata with a
    /// different durable file generation, so callers must fail loudly.
    #[error("storage synchronization poisoned: {component}")]
    LockPoisoned {
        /// Protected storage component.
        component: &'static str,
    },

    /// A legacy monolithic block log was found where segmented storage is required.
    #[error("legacy block store detected at {path}; this node accepts only a clean data directory with segmented storage—stop the node, preserve {data_dir} as an offline backup, and configure a new empty data directory")]
    LegacyBlockStore {
        /// Legacy path that caused refusal.
        path: std::path::PathBuf,
        /// Data directory that must be replaced with a clean directory.
        data_dir: std::path::PathBuf,
    },
}

/// Convenience alias.
pub type StorageResult<T> = Result<T, StorageError>;
