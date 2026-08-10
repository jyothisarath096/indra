//! # indra-storage
//!
//! Persistent storage for the INDRA v2 node.
//!
//! ## Design
//!
//! Phase 5 uses simple flat-file storage:
//!
//! - **Block store**: append-only log of encoded blocks.
//!   Each entry is: u64 height || u32 length || block_bytes || CRC32.
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
//!
//! ## Schema policy before mainnet
//!
//! Storage has one canonical format and no migration ladder. Checkpoints made
//! before the eventual pure-mainnet schema (including the future tranche staking
//! model) are intentionally disposable; operators must replay from genesis or
//! start with fresh storage after an incompatible pre-mainnet schema change.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub(crate) mod atomic;
pub mod epoch_store;
pub mod error;
pub mod manifest;
pub mod qc_store;
pub mod segmented_block_store;
pub mod state_store;
pub mod vote_safety;
pub mod wal;

pub use epoch_store::{EpochStore, EpochStoreReadHandle};
pub use error::{StorageError, StorageResult};
pub use manifest::{load_chain_manifest, save_chain_manifest, ChainManifest};
pub use qc_store::{
    clear_pending_last_qc, load_last_qc, load_pending_last_qc, save_last_qc, save_pending_last_qc,
};
pub use segmented_block_store::{BlockStore, BlockStoreReadHandle, PruneConfig};
pub use state_store::StateStore;
pub use vote_safety::{VoteSafetyLoadResult, VoteSafetyRecord, VoteSafetyStore};
pub use wal::MempoolWal;
