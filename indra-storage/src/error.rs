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
}

/// Convenience alias.
pub type StorageResult<T> = Result<T, StorageError>;
