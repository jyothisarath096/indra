//! # indra-storage
//!
//! Persistent storage for the INDRA v2 node.
//!
//! ## Design
//!
//! Phase 5 uses simple flat-file storage:
//!
//! - **Block store**: append-only log of encoded blocks.
//!   Each entry is: u64 height || u32 length || block_bytes.
//!   Indexed by a separate height→offset map held in memory.
//!
//! - **State store**: periodic snapshots of `ChainState` written
//!   as length-prefixed encoded bytes. On startup the latest
//!   snapshot is loaded and blocks since the snapshot are replayed.
//!
//! - **Mempool WAL**: a write-ahead log of pending transactions.
//!   On crash recovery, WAL entries are replayed into the mempool.
//!
//! ## Phase 6 upgrade path
//!
//! Phase 6 replaces flat files with a RocksDB backend for:
//! - O(1) block lookup by hash
//! - Persistent Merkle trie for state roots
//! - UTXO set indexed by commitment
//!
//! ## Invariants
//!
//! - No unsafe code.
//! - All writes are atomic at the OS level (write then rename).
//! - Incomplete writes are detected and ignored on recovery.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod block_store;
pub mod error;
pub mod qc_store;
pub mod state_store;
pub mod wal;

pub use block_store::{BlockStore, PruneConfig};
pub use error::{StorageError, StorageResult};
pub use qc_store::{load_last_qc, save_last_qc};
pub use state_store::StateStore;
pub use wal::MempoolWal;
