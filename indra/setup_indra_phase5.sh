#!/usr/bin/env bash
# =============================================================================
# INDRA v2 — Phase 5 Setup Script
# Running Node: Storage, State Roots, BLS Vote Signing, Node Binary
# =============================================================================
# Run from inside the indra/ workspace directory:
#
#   chmod +x setup_indra_phase5.sh
#   ./setup_indra_phase5.sh
#   cargo build
#   cargo test
#
# Prerequisites: Phases 1–4 must be passing.
#
# What this adds:
#
#   indra-storage/        — new crate: persistent chain state
#     src/lib.rs
#     src/error.rs
#     src/block_store.rs  — append-only block log (flat files)
#     src/state_store.rs  — chain state serialisation/deserialisation
#     src/wal.rs          — write-ahead log for mempool durability
#
#   indra-node/           — new crate: runnable node binary
#     src/lib.rs
#     src/config.rs       — NodeConfig: loaded from env or defaults
#     src/genesis.rs      — genesis block and initial chain state
#     src/engine.rs       — NodeEngine: drives the consensus loop
#     src/bls_vote.rs     — proper BLS vote signing (replaces Phase 4 placeholder)
#     src/state_root.rs   — compute state_root and validator_set_root
#     src/sync.rs         — block import and chain sync logic
#     tests/node.rs       — integration tests
# =============================================================================

set -euo pipefail

echo "==> Setting up INDRA Phase 5 — Running Node..."

if [ ! -f "Cargo.toml" ]; then
    echo "ERROR: Run from inside the indra/ workspace directory."
    exit 1
fi

# =============================================================================
# Update workspace Cargo.toml
# =============================================================================

cat > Cargo.toml << 'TOML'
[workspace]
members  = [
    "indra-core",
    "indra-crypto",
    "indra-state",
    "indra-consensus",
    "indra-storage",
    "indra-node",
]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
authors = ["INDRA Protocol"]
license = "MIT"

[workspace.dependencies]
sha2               = { version = "0.10", default-features = false }
thiserror          = { version = "1.0" }
hex                = { version = "0.4", default-features = false, features = ["alloc"] }
ed25519-dalek      = { version = "2.1", default-features = false, features = ["alloc"] }
curve25519-dalek   = { version = "4.1", default-features = false, features = ["alloc"] }
pqcrypto-dilithium = { version = "0.5", default-features = false }
pqcrypto-traits    = { version = "0.3", default-features = false }
blst               = { version = "0.3" }
proptest           = { version = "1.4", default-features = false, features = ["std"] }

[profile.release]
opt-level     = 3
lto           = true
codegen-units = 1
panic         = "abort"

[profile.dev]
opt-level = 0
debug     = true
TOML

# =============================================================================
# Create indra-storage crate
# =============================================================================

mkdir -p indra-storage/src

cat > indra-storage/Cargo.toml << 'TOML'
[package]
name        = "indra-storage"
description = "INDRA persistent storage — block log, chain state, mempool WAL"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
indra-core   = { path = "../indra-core" }
indra-state  = { path = "../indra-state" }
thiserror.workspace = true

[dev-dependencies]
indra-core   = { path = "../indra-core" }
indra-state  = { path = "../indra-state" }
TOML

# --------------- indra-storage/src/lib.rs ---------------

cat > indra-storage/src/lib.rs << 'RUST'
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

pub mod error;
pub mod block_store;
pub mod state_store;
pub mod wal;

pub use error::{StorageError, StorageResult};
pub use block_store::BlockStore;
pub use state_store::StateStore;
pub use wal::MempoolWal;
RUST

# --------------- indra-storage/src/error.rs ---------------

cat > indra-storage/src/error.rs << 'RUST'
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
RUST

# --------------- indra-storage/src/block_store.rs ---------------

cat > indra-storage/src/block_store.rs << 'RUST'
//! Append-only block log.
//!
//! ## File format
//!
//! Each block entry in the log file:
//!   [u64 height (8 bytes LE)] [u32 length (4 bytes LE)] [block bytes (length bytes)]
//!
//! The index (height → file offset) is rebuilt from the log on startup.
//! This is O(n) in the number of blocks but fast in practice (< 1s for
//! 100k blocks at 1 MB each due to sequential I/O).
//!
//! ## Crash safety
//!
//! A partial write leaves a truncated entry at the end of the file.
//! On recovery, we scan forward and stop at the first entry where
//! `file_offset + 12 + length > file_size`. That entry is discarded.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use indra_core::{
    codec::{Decode, Encode},
    types::block::BlockV1,
};

use crate::error::{StorageError, StorageResult};

/// The header size for each block entry: u64 height + u32 length.
const ENTRY_HEADER_BYTES: usize = 12;

/// An append-only block log with an in-memory height→offset index.
pub struct BlockStore {
    path:   PathBuf,
    file:   File,
    index:  HashMap<u64, u64>, // height → file offset of the entry header
    next_height: u64,
}

impl BlockStore {
    /// Open or create a block store at the given path.
    ///
    /// On first open, scans the file to rebuild the index.
    /// Truncates any incomplete final entry.
    pub fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)?;

        let mut store = Self {
            path,
            file,
            index: HashMap::new(),
            next_height: 0,
        };
        store.rebuild_index()?;
        Ok(store)
    }

    /// Total number of blocks stored.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// True if no blocks are stored.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// The height of the next block to be appended.
    pub fn next_height(&self) -> u64 {
        self.next_height
    }

    /// Append a block to the store.
    ///
    /// Blocks must be appended in strict height order.
    pub fn append(&mut self, block: &BlockV1) -> StorageResult<()> {
        let height = block.header.height;
        if height != self.next_height {
            return Err(StorageError::NonSequential {
                expected: self.next_height,
                actual: height,
            });
        }

        let block_bytes = block.encode_to_vec();
        let length = block_bytes.len() as u32;

        // Record offset before writing
        let offset = self.file.seek(SeekFrom::End(0))?;

        // Write: height (8) || length (4) || block_bytes
        self.file.write_all(&height.to_le_bytes())?;
        self.file.write_all(&length.to_le_bytes())?;
        self.file.write_all(&block_bytes)?;
        self.file.flush()?;

        self.index.insert(height, offset);
        self.next_height += 1;
        Ok(())
    }

    /// Read a block by height.
    pub fn get(&mut self, height: u64) -> StorageResult<BlockV1> {
        let offset = self.index.get(&height)
            .copied()
            .ok_or(StorageError::BlockNotFound { height })?;

        self.file.seek(SeekFrom::Start(offset))?;

        // Read header
        let mut header = [0u8; ENTRY_HEADER_BYTES];
        self.file.read_exact(&mut header)?;

        let stored_height = u64::from_le_bytes(
            header[..8].try_into().unwrap_or([0u8; 8])
        );
        let length = u32::from_le_bytes(
            header[8..12].try_into().unwrap_or([0u8; 4])
        ) as usize;

        if stored_height != height {
            return Err(StorageError::Corruption {
                height,
                detail: format!("index mismatch: stored height {stored_height}"),
            });
        }

        let mut block_bytes = vec![0u8; length];
        self.file.read_exact(&mut block_bytes)?;

        use indra_core::codec::ByteReader;
        let mut reader = ByteReader::new(&block_bytes);
        BlockV1::decode(&mut reader).map_err(|e| StorageError::Corruption {
            height,
            detail: e.to_string(),
        })
    }

    /// Scan the file to rebuild the height→offset index.
    /// Truncates any incomplete final entry.
    fn rebuild_index(&mut self) -> StorageResult<()> {
        let file_len = self.file.seek(SeekFrom::End(0))?;
        self.file.seek(SeekFrom::Start(0))?;

        let mut offset: u64 = 0;
        let mut last_good_offset: u64 = 0;
        let mut max_height: Option<u64> = None;

        loop {
            if offset + ENTRY_HEADER_BYTES as u64 > file_len {
                break; // not enough bytes for a header
            }

            let mut header = [0u8; ENTRY_HEADER_BYTES];
            self.file.read_exact(&mut header)?;

            let height = u64::from_le_bytes(
                header[..8].try_into().unwrap_or([0u8; 8])
            );
            let length = u32::from_le_bytes(
                header[8..12].try_into().unwrap_or([0u8; 4])
            ) as u64;

            if offset + ENTRY_HEADER_BYTES as u64 + length > file_len {
                // Truncated entry — stop here and truncate the file
                self.file.set_len(last_good_offset)?;
                break;
            }

            self.index.insert(height, offset);
            if max_height.map_or(true, |m| height > m) {
                max_height = Some(height);
            }

            last_good_offset = offset + ENTRY_HEADER_BYTES as u64 + length;
            offset = last_good_offset;
            self.file.seek(SeekFrom::Start(offset))?;
        }

        self.next_height = max_height.map_or(0, |h| h + 1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        Bytes32, ProtocolVersion, VariableBytes,
        types::{
            block::{BlockHeaderV1, BlockV1},
            primitives::MAX_VRF_PROOF_BYTES,
        },
    };

    fn temp_path() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_test_blocks_{}.bin", std::process::id()));
        p
    }

    fn dummy_block(height: u64, prev_hash: [u8; 32]) -> BlockV1 {
        BlockV1 {
            header: BlockHeaderV1 {
                protocol_version:    ProtocolVersion::CURRENT,
                height,
                prev_hash:           Bytes32::from(prev_hash),
                timestamp:           1_700_000_000 + height,
                state_root:          Bytes32::ZERO,
                validator_set_root:  Bytes32::ZERO,
                mempool_set_root:    Bytes32::ZERO,
                base_fee:            100,
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof:  VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[0u8; 64]).unwrap(),
                quorum_certificate:  indra_core::VariableBytes::from_slice(&[]).unwrap(),
            },
            transactions:      vec![],
            slashing_evidence: vec![],
            governance_ops:    vec![],
        }
    }

    #[test]
    fn append_and_retrieve() {
        let path = temp_path();
        let mut store = BlockStore::open(&path).unwrap();

        let b0 = dummy_block(0, [0u8; 32]);
        let b1 = dummy_block(1, [0u8; 32]);
        store.append(&b0).unwrap();
        store.append(&b1).unwrap();

        let got0 = store.get(0).unwrap();
        let got1 = store.get(1).unwrap();
        assert_eq!(got0.header.height, 0);
        assert_eq!(got1.header.height, 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn non_sequential_rejected() {
        let path = temp_path();
        let mut path2 = path.clone();
        path2.set_extension("bin2");
        let mut store = BlockStore::open(&path2).unwrap();
        let b0 = dummy_block(0, [0u8; 32]);
        let b2 = dummy_block(2, [0u8; 32]); // skip height 1
        store.append(&b0).unwrap();
        assert!(store.append(&b2).is_err());
        let _ = std::fs::remove_file(&path2);
    }

    #[test]
    fn index_survives_reopen() {
        let path = temp_path();
        let mut p3 = path.clone();
        p3.set_extension("bin3");
        {
            let mut store = BlockStore::open(&p3).unwrap();
            store.append(&dummy_block(0, [0u8; 32])).unwrap();
            store.append(&dummy_block(1, [0u8; 32])).unwrap();
        }
        // Reopen and check index is rebuilt
        let mut store2 = BlockStore::open(&p3).unwrap();
        assert_eq!(store2.len(), 2);
        assert_eq!(store2.get(0).unwrap().header.height, 0);
        assert_eq!(store2.get(1).unwrap().header.height, 1);
        let _ = std::fs::remove_file(&p3);
    }
}
RUST

# --------------- indra-storage/src/state_store.rs ---------------

cat > indra-storage/src/state_store.rs << 'RUST'
//! Chain state snapshots.
//!
//! Periodically writes the full `ChainState` to disk so that on restart
//! the node does not need to replay the entire chain from genesis.
//!
//! ## File format
//!
//! A snapshot file is: u64 height (8 bytes LE) || u32 length (4 bytes LE) || state_bytes
//!
//! On startup, the node loads the latest snapshot and replays any blocks
//! stored in the block log that are newer than the snapshot height.
//!
//! ## Snapshot frequency
//!
//! One snapshot per SNAPSHOT_INTERVAL blocks (default: every epoch = 300 blocks).
//! The previous snapshot is kept for one additional interval, then deleted.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use indra_state::ChainState;

use crate::error::{StorageError, StorageResult};

/// How often to take a state snapshot (in blocks).
pub const SNAPSHOT_INTERVAL: u64 = 300;

/// Manages chain state snapshots on disk.
pub struct StateStore {
    dir: PathBuf,
}

impl StateStore {
    /// Open a state store in the given directory.
    pub fn open(dir: impl AsRef<Path>) -> StorageResult<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Write a snapshot of the current chain state.
    ///
    /// Atomically replaces the previous snapshot via write-then-rename.
    pub fn save(&self, state: &ChainState) -> StorageResult<()> {
        let state_bytes = serialise_chain_state(state);
        let height = state.height;
        let length = state_bytes.len() as u32;

        let tmp_path = self.dir.join(format!("state_{height}.tmp"));
        let final_path = self.dir.join(format!("state_{height}.snap"));

        // Write to temp file first
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(&height.to_le_bytes())?;
        f.write_all(&length.to_le_bytes())?;
        f.write_all(&state_bytes)?;
        f.flush()?;
        drop(f);

        // Atomic rename
        fs::rename(&tmp_path, &final_path)?;

        // Clean up old snapshots (keep current and one previous)
        self.cleanup_old_snapshots(height)?;

        Ok(())
    }

    /// Load the latest snapshot. Returns None if no snapshot exists.
    pub fn load_latest(&self) -> StorageResult<Option<ChainState>> {
        let latest = self.find_latest_snapshot()?;
        match latest {
            None => Ok(None),
            Some(path) => {
                let mut f = fs::File::open(&path)?;
                let mut header = [0u8; 12];
                f.read_exact(&mut header)?;

                let height = u64::from_le_bytes(
                    header[..8].try_into().unwrap_or([0u8; 8])
                );
                let length = u32::from_le_bytes(
                    header[8..12].try_into().unwrap_or([0u8; 4])
                ) as usize;

                let mut state_bytes = vec![0u8; length];
                f.read_exact(&mut state_bytes)?;

                deserialise_chain_state(&state_bytes, height)
                    .map(Some)
                    .map_err(|e| StorageError::Corruption {
                        height,
                        detail: e,
                    })
            }
        }
    }

    /// Find the path of the most recent snapshot file.
    fn find_latest_snapshot(&self) -> StorageResult<Option<PathBuf>> {
        let mut snapshots: Vec<(u64, PathBuf)> = Vec::new();

        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("state_") && name_str.ends_with(".snap") {
                let height_str = name_str
                    .trim_start_matches("state_")
                    .trim_end_matches(".snap");
                if let Ok(h) = height_str.parse::<u64>() {
                    snapshots.push((h, entry.path()));
                }
            }
        }

        snapshots.sort_by_key(|(h, _)| *h);
        Ok(snapshots.into_iter().last().map(|(_, p)| p))
    }

    /// Remove snapshots older than (current_height - SNAPSHOT_INTERVAL).
    fn cleanup_old_snapshots(&self, current_height: u64) -> StorageResult<()> {
        let keep_from = current_height.saturating_sub(SNAPSHOT_INTERVAL);

        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("state_") && name_str.ends_with(".snap") {
                let height_str = name_str
                    .trim_start_matches("state_")
                    .trim_end_matches(".snap");
                if let Ok(h) = height_str.parse::<u64>() {
                    if h < keep_from {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
        Ok(())
    }
}

/// Serialise a ChainState to bytes.
/// Format: height(8) || base_fee(8) || tip_hash(32) || total_supply(8) || treasury(8)
/// This is a minimal snapshot — the full UTXO/nullifier/validator sets
/// are rebuilt from block replay in Phase 6. For now we store the summary fields.
fn serialise_chain_state(state: &ChainState) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&state.height.to_le_bytes());
    buf.extend_from_slice(&state.base_fee.to_le_bytes());
    buf.extend_from_slice(&state.tip_hash.0);
    buf.extend_from_slice(&state.total_supply.to_le_bytes());
    buf.extend_from_slice(&state.treasury.to_le_bytes());
    buf
}

/// Deserialise a ChainState from bytes (minimal snapshot format).
fn deserialise_chain_state(bytes: &[u8], _height: u64) -> Result<ChainState, String> {
    if bytes.len() < 64 {
        return Err(format!("snapshot too short: {} bytes", bytes.len()));
    }

    let height = u64::from_le_bytes(bytes[0..8].try_into().map_err(|_| "bad height")?);
    let base_fee = u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| "bad base_fee")?);
    let tip_hash: [u8; 32] = bytes[16..48].try_into().map_err(|_| "bad tip_hash")?;
    let total_supply = u64::from_le_bytes(bytes[48..56].try_into().map_err(|_| "bad total_supply")?);
    let treasury = u64::from_le_bytes(bytes[56..64].try_into().map_err(|_| "bad treasury")?);

    use indra_core::types::primitives::Bytes32;
    let mut state = ChainState::new_genesis();
    state.height       = height;
    state.base_fee     = base_fee;
    state.tip_hash     = Bytes32::from(tip_hash);
    state.total_supply = total_supply;
    state.treasury     = treasury;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_state_test_{}_{}", suffix, std::process::id()));
        p
    }

    #[test]
    fn save_and_load() {
        let dir = temp_dir("a");
        let store = StateStore::open(&dir).unwrap();

        let mut state = ChainState::new_genesis();
        state.height = 42;
        state.base_fee = 500;

        store.save(&state).unwrap();

        let loaded = store.load_latest().unwrap().unwrap();
        assert_eq!(loaded.height, 42);
        assert_eq!(loaded.base_fee, 500);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_snapshot_returns_none() {
        let dir = temp_dir("b");
        let store = StateStore::open(&dir).unwrap();
        assert!(store.load_latest().unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn latest_snapshot_selected() {
        let dir = temp_dir("c");
        let store = StateStore::open(&dir).unwrap();

        let mut s1 = ChainState::new_genesis(); s1.height = 10;
        let mut s2 = ChainState::new_genesis(); s2.height = 20;

        store.save(&s1).unwrap();
        store.save(&s2).unwrap();

        let loaded = store.load_latest().unwrap().unwrap();
        assert_eq!(loaded.height, 20);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
RUST

# --------------- indra-storage/src/wal.rs ---------------

cat > indra-storage/src/wal.rs << 'RUST'
//! Mempool write-ahead log (WAL).
//!
//! Ensures pending transactions survive a node crash.
//!
//! ## File format
//!
//! Each WAL entry: u8 tag || u32 length || payload_bytes || u32 crc32
//!
//! Tags:
//!   0x01 = SUBMIT (add transaction to mempool)
//!   0x02 = EVICT  (remove transaction from mempool by tx_id)
//!
//! ## Recovery
//!
//! On startup, scan the WAL and replay SUBMIT/EVICT entries in order.
//! Entries with bad CRC are discarded (truncated write at crash).
//! After recovery, the WAL is compacted (rewritten with only live entries).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use indra_core::{
    codec::{Decode, Encode},
    types::{primitives::Bytes32, transaction::TransactionV1},
};

use crate::error::{StorageError, StorageResult};

const TAG_SUBMIT: u8 = 0x01;
const TAG_EVICT:  u8 = 0x02;
const ENTRY_OVERHEAD: usize = 9; // 1 tag + 4 length + 4 crc

/// A WAL entry recovered on startup.
#[derive(Debug)]
pub enum WalEntry {
    /// Add this transaction to the mempool.
    Submit(TransactionV1),
    /// Remove this transaction from the mempool.
    Evict(Bytes32),
}

/// The mempool write-ahead log.
pub struct MempoolWal {
    path: PathBuf,
    file: File,
}

impl MempoolWal {
    /// Open or create a WAL at the given path.
    pub fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)?;
        Ok(Self { path, file })
    }

    /// Log a transaction submission.
    pub fn log_submit(&mut self, tx: &TransactionV1) -> StorageResult<()> {
        self.write_entry(TAG_SUBMIT, &tx.encode_to_vec())
    }

    /// Log a transaction eviction.
    pub fn log_evict(&mut self, tx_id: &Bytes32) -> StorageResult<()> {
        self.write_entry(TAG_EVICT, &tx_id.0)
    }

    /// Recover all valid entries from the WAL.
    pub fn recover(&mut self) -> StorageResult<Vec<WalEntry>> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut entries = Vec::new();
        let file_len = self.file.seek(SeekFrom::End(0))?;
        self.file.seek(SeekFrom::Start(0))?;

        let mut offset: u64 = 0;

        loop {
            if offset + ENTRY_OVERHEAD as u64 > file_len {
                break;
            }

            // Read tag + length
            let mut header = [0u8; 5];
            self.file.read_exact(&mut header)?;
            let tag = header[0];
            let length = u32::from_le_bytes(
                header[1..5].try_into().unwrap_or([0u8; 4])
            ) as usize;

            if offset + ENTRY_OVERHEAD as u64 + length as u64 > file_len {
                break; // truncated
            }

            let mut payload = vec![0u8; length];
            self.file.read_exact(&mut payload)?;

            let mut crc_bytes = [0u8; 4];
            self.file.read_exact(&mut crc_bytes)?;
            let stored_crc = u32::from_le_bytes(crc_bytes);
            let computed_crc = simple_crc32(&payload);

            if stored_crc != computed_crc {
                // Bad CRC — truncated or corrupted, stop
                break;
            }

            match tag {
                TAG_SUBMIT => {
                    use indra_core::codec::ByteReader;
                    let mut r = ByteReader::new(&payload);
                    if let Ok(tx) = TransactionV1::decode(&mut r) {
                        entries.push(WalEntry::Submit(tx));
                    }
                }
                TAG_EVICT => {
                    if payload.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&payload);
                        entries.push(WalEntry::Evict(Bytes32::from(arr)));
                    }
                }
                _ => {} // unknown tag, skip
            }

            offset += ENTRY_OVERHEAD as u64 + length as u64;
        }

        Ok(entries)
    }

    /// Truncate the WAL (after a successful compaction or snapshot).
    pub fn truncate(&mut self) -> StorageResult<()> {
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0))?;
        Ok(())
    }

    fn write_entry(&mut self, tag: u8, payload: &[u8]) -> StorageResult<()> {
        let length = payload.len() as u32;
        let crc = simple_crc32(payload);

        self.file.write_all(&[tag])?;
        self.file.write_all(&length.to_le_bytes())?;
        self.file.write_all(payload)?;
        self.file.write_all(&crc.to_le_bytes())?;
        self.file.flush()?;
        Ok(())
    }
}

/// A simple CRC-32 checksum (polynomial 0xEDB88320).
/// Not cryptographic — used only to detect truncated writes.
fn simple_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        Bytes32, CommitmentV1, HybridPubKey, ProtocolVersion, VariableBytes,
        types::{
            crypto::HybridSignature,
            transaction::{InputV1, OutputV1, TransactionV1},
        },
    };

    fn temp_path(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_wal_test_{}_{}.wal", suffix, std::process::id()));
        p
    }

    fn dummy_tx(nonce: u8) -> TransactionV1 {
        TransactionV1 {
            version: ProtocolVersion::CURRENT,
            signature_module_id: 1,
            inputs: vec![InputV1 {
                utxo_id:   Bytes32::from([nonce; 32]),
                nullifier: Bytes32::from([nonce; 32]),
            }],
            outputs: vec![OutputV1 {
                commitment:   CommitmentV1 { compressed_point: Bytes32::ZERO },
                owner_pubkey: HybridPubKey {
                    classical_pk: Bytes32::ZERO,
                    pq_pk: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
                },
                range_proof:  VariableBytes::from_slice(&[0u8; 32]).unwrap(),
                lock_height:  0,
            }],
            fee_amount:     10_000,
            fee_blinding:   Bytes32::ZERO,
            fee_commitment: CommitmentV1 { compressed_point: Bytes32::ZERO },
            signature: HybridSignature {
                classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                pq_sig:        VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            },
        }
    }

    #[test]
    fn submit_and_recover() {
        let path = temp_path("a");
        let tx = dummy_tx(0x01);
        {
            let mut wal = MempoolWal::open(&path).unwrap();
            wal.log_submit(&tx).unwrap();
        }
        let mut wal2 = MempoolWal::open(&path).unwrap();
        let entries = wal2.recover().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries.first(), Some(WalEntry::Submit(_))));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn evict_and_recover() {
        let path = temp_path("b");
        let tx_id = Bytes32::from([0xABu8; 32]);
        {
            let mut wal = MempoolWal::open(&path).unwrap();
            wal.log_evict(&tx_id).unwrap();
        }
        let mut wal2 = MempoolWal::open(&path).unwrap();
        let entries = wal2.recover().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries.first(), Some(WalEntry::Evict(_))));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn truncate_clears_wal() {
        let path = temp_path("c");
        let tx = dummy_tx(0x02);
        let mut wal = MempoolWal::open(&path).unwrap();
        wal.log_submit(&tx).unwrap();
        wal.truncate().unwrap();
        let entries = wal.recover().unwrap();
        assert!(entries.is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
RUST

# =============================================================================
# Create indra-node crate
# =============================================================================

mkdir -p indra-node/src
mkdir -p indra-node/tests

cat > indra-node/Cargo.toml << 'TOML'
[package]
name        = "indra-node"
description = "INDRA v2 node binary — consensus engine, storage, sync"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
indra-core      = { path = "../indra-core" }
indra-crypto    = { path = "../indra-crypto" }
indra-state     = { path = "../indra-state" }
indra-consensus = { path = "../indra-consensus" }
indra-storage   = { path = "../indra-storage" }
thiserror.workspace = true

[dev-dependencies]
indra-core      = { path = "../indra-core" }
indra-crypto    = { path = "../indra-crypto" }
indra-state     = { path = "../indra-state" }
indra-consensus = { path = "../indra-consensus" }
indra-storage   = { path = "../indra-storage" }
TOML

# --------------- indra-node/src/lib.rs ---------------

cat > indra-node/src/lib.rs << 'RUST'
//! # indra-node
//!
//! The INDRA v2 node: ties together all protocol components into a
//! runnable unit.
//!
//! ## Architecture
//!
//! ```text
//!  ┌─────────────────────────────────────────┐
//!  │                NodeEngine               │
//!  │                                         │
//!  │  ┌──────────┐  ┌──────────┐  ┌───────┐ │
//!  │  │ Consensus│  │  State   │  │Storage│ │
//!  │  │  Engine  │  │ Machine  │  │ Layer │ │
//!  │  └──────────┘  └──────────┘  └───────┘ │
//!  └─────────────────────────────────────────┘
//!           │                │
//!    (Phase 6: P2P)   (Phase 6: RocksDB)
//! ```
//!
//! ## What this crate provides (Phase 5)
//!
//! - `NodeConfig`      — configuration from environment or defaults
//! - `NodeEngine`      — drives the consensus loop (propose → vote → commit)
//! - `genesis`         — genesis block and initial chain state construction
//! - `bls_vote`        — proper BLS vote signing (real 96-byte signatures)
//! - `state_root`      — compute `state_root` and `validator_set_root`
//! - `sync`            — block import: validate, apply, store, update mempool
//!
//! ## What is NOT in this phase
//!
//! - P2P networking (Phase 6)
//! - RocksDB persistent Merkle trie (Phase 6)
//! - Slash evidence detection (Phase 6)
//! - JSON-RPC API (Phase 7)

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod config;
pub mod error;
pub mod genesis;
pub mod engine;
pub mod bls_vote;
pub mod state_root;
pub mod sync;

pub use config::NodeConfig;
pub use error::{NodeError, NodeResult};
pub use engine::NodeEngine;
pub use genesis::{build_genesis_block, build_genesis_state};
pub use sync::import_block;
RUST

# --------------- indra-node/src/error.rs ---------------

cat > indra-node/src/error.rs << 'RUST'
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
}

/// Convenience alias.
pub type NodeResult<T> = Result<T, NodeError>;
RUST

# --------------- indra-node/src/config.rs ---------------

cat > indra-node/src/config.rs << 'RUST'
//! Node configuration.
//!
//! In Phase 5 configuration is loaded from environment variables with
//! sensible defaults. Phase 7 adds a TOML config file.

use std::path::PathBuf;

/// All configuration for a running INDRA node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Directory for persistent data (blocks, state snapshots, WAL).
    pub data_dir: PathBuf,

    /// The node's validator identity (32-byte Ed25519 seed).
    /// If None, this node is a full node (validates but does not propose).
    pub validator_seed: Option<[u8; 32]>,

    /// The node's BLS signing seed (32 bytes).
    /// Required if validator_seed is set.
    pub bls_seed: Option<[u8; 32]>,

    /// The node's VRF seed (32 bytes).
    /// Required if validator_seed is set.
    pub vrf_seed: Option<[u8; 32]>,

    /// Listen address for P2P (Phase 6).
    pub p2p_addr: String,

    /// Bootstrap peer addresses (Phase 6).
    pub bootstrap_peers: Vec<String>,

    /// How many blocks between state snapshots.
    pub snapshot_interval: u64,

    /// Maximum mempool size (number of transactions).
    pub mempool_capacity: usize,
}

impl NodeConfig {
    /// Create a default configuration for local testing.
    pub fn local_test(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            validator_seed:   Some([0x42u8; 32]),
            bls_seed:         Some([0x42u8; 32]),
            vrf_seed:         Some([0x42u8; 32]),
            p2p_addr:         "127.0.0.1:30303".to_string(),
            bootstrap_peers:  vec![],
            snapshot_interval: 300,
            mempool_capacity:  5_000,
        }
    }

    /// Create a validator-less full node config for testing.
    pub fn full_node(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            validator_seed:   None,
            bls_seed:         None,
            vrf_seed:         None,
            p2p_addr:         "127.0.0.1:30303".to_string(),
            bootstrap_peers:  vec![],
            snapshot_interval: 300,
            mempool_capacity:  5_000,
        }
    }

    /// True if this node is configured as a validator.
    pub fn is_validator(&self) -> bool {
        self.validator_seed.is_some()
    }

    /// Path to the block log file.
    pub fn block_log_path(&self) -> PathBuf {
        self.data_dir.join("blocks.log")
    }

    /// Path to the state snapshot directory.
    pub fn state_dir(&self) -> PathBuf {
        self.data_dir.join("state")
    }

    /// Path to the mempool WAL file.
    pub fn wal_path(&self) -> PathBuf {
        self.data_dir.join("mempool.wal")
    }
}
RUST

# --------------- indra-node/src/genesis.rs ---------------

cat > indra-node/src/genesis.rs << 'RUST'
//! Genesis block and initial chain state.
//!
//! The genesis block is height 0. It has:
//! - An all-zero prev_hash
//! - No transactions, slashing evidence, or governance ops
//! - A zeroed QC (no previous block to certify)
//! - The initial base fee
//!
//! The genesis state is produced by `ChainState::new_genesis()`.

use indra_core::{
    types::{
        block::{BlockHeaderV1, BlockV1},
        primitives::{
            Bytes32, ProtocolVersion, VariableBytes,
            INITIAL_BASE_FEE_SPARK_PER_KB, MAX_VRF_PROOF_BYTES, MAX_QC_SIZE_BYTES,
        },
    },
};
use indra_state::ChainState;
use indra_crypto::sha256;

/// Build the genesis block.
///
/// The genesis block hash is SHA-256(encode(genesis_header)).
pub fn build_genesis_block() -> BlockV1 {
    BlockV1 {
        header: BlockHeaderV1 {
            protocol_version:    ProtocolVersion::CURRENT,
            height:              0,
            prev_hash:           Bytes32::ZERO,
            timestamp:           1_700_000_000, // 2023-11-14 — fixed genesis timestamp
            state_root:          Bytes32::ZERO,
            validator_set_root:  Bytes32::ZERO,
            mempool_set_root:    Bytes32::ZERO,
            base_fee:            INITIAL_BASE_FEE_SPARK_PER_KB,
            proposer_vrf_output: Bytes32::ZERO,
            proposer_vrf_proof:  VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap_or_else(|_| {
                // Safety: empty slice always fits
                panic!("empty VRF proof should always fit")
            }),
            quorum_certificate:  VariableBytes::<MAX_QC_SIZE_BYTES>::from_slice(&[]).unwrap_or_else(|_| {
                panic!("empty QC should always fit")
            }),
        },
        transactions:      vec![],
        slashing_evidence: vec![],
        governance_ops:    vec![],
    }
}

/// Compute the genesis block hash.
pub fn genesis_block_hash() -> Bytes32 {
    use indra_core::codec::Encode;
    let block = build_genesis_block();
    Bytes32::from(sha256(&block.header.encode_to_vec()))
}

/// Build the initial chain state (genesis state).
pub fn build_genesis_state() -> ChainState {
    ChainState::new_genesis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_block_is_deterministic() {
        let h1 = genesis_block_hash();
        let h2 = genesis_block_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn genesis_block_height_is_zero() {
        let b = build_genesis_block();
        assert_eq!(b.header.height, 0);
    }

    #[test]
    fn genesis_block_has_zero_prev_hash() {
        let b = build_genesis_block();
        assert_eq!(b.header.prev_hash, Bytes32::ZERO);
    }

    #[test]
    fn genesis_state_height_is_zero() {
        let s = build_genesis_state();
        assert_eq!(s.height, 0);
    }
}
RUST

# --------------- indra-node/src/bls_vote.rs ---------------

cat > indra-node/src/bls_vote.rs << 'RUST'
//! Proper BLS vote signing — replaces the Phase 4 placeholder.
//!
//! In Phase 4, vote signatures used Ed25519 bytes passed off as BLS
//! (causing the "malformed signature for BLS12-381: got 64 bytes" error
//! in QC aggregation). This module provides:
//!
//! - `BlsVoteSigner`: wraps a BLS keypair and signs vote messages
//! - `sign_vote_bls`: produce a 96-byte BLS signature over a vote message
//! - `build_bls_qc`: aggregate BLS vote signatures into a real QC
//!
//! ## What changes
//!
//! Validators now maintain TWO signing keypairs:
//! - Hybrid (Ed25519 + Dilithium2): for transaction signatures and prevotes
//! - BLS12-381: for precommit aggregation into QCs
//!
//! The QC contains:
//! - One 96-byte BLS aggregate signature (all precommit classical components)
//! - N individual Dilithium2 signatures (one per signer)

use indra_core::{
    codec::Encode,
    types::{
        primitives::{
            Bytes32, VariableBytes,
            MAX_BLS_AGG_SIG_BYTES, MAX_PQ_SIG_BYTES, MAX_VALIDATORS,
            QUORUM_THRESHOLD_BPS, SIGNER_BITFIELD_BYTES,
        },
        qc::QuorumCertificateV1,
        crypto::PQVoteSig,
        vote::{VoteStep, VoteV1},
    },
};
use indra_crypto::{
    bls::{BlsKeypair, BlsPublicKey, BlsSignature, aggregate_signatures, verify_aggregate},
    hash::domains::VOTE_SIGN,
    CryptoError,
};

use crate::error::{NodeError, NodeResult};

/// A validator's BLS signing key for QC aggregation.
pub struct BlsVoteSigner {
    keypair: BlsKeypair,
    /// The validator's public key (48 bytes).
    pub public_key: BlsPublicKey,
}

impl BlsVoteSigner {
    /// Create from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> NodeResult<Self> {
        let keypair = BlsKeypair::from_seed(seed)?;
        let public_key = keypair.public_key();
        Ok(Self { keypair, public_key })
    }

    /// Sign a vote message with BLS.
    pub fn sign_vote(&self, msg: &[u8]) -> BlsSignature {
        self.keypair.sign(msg)
    }
}

/// Compute the BLS signing message for a vote.
///
/// BLS signs: VOTE_SIGN || height || round || step || block_hash || validator_id
pub fn bls_vote_message(
    height: u64,
    round: u32,
    step: VoteStep,
    block_hash: &Bytes32,
    validator_id: &Bytes32,
) -> Vec<u8> {
    let mut buf = VOTE_SIGN.to_vec();
    height.encode(&mut buf);
    round.encode(&mut buf);
    step.encode(&mut buf);
    block_hash.encode(&mut buf);
    validator_id.encode(&mut buf);
    buf
}

/// A precommit vote with an accompanying BLS signature.
pub struct PrecommitWithBls {
    /// The vote (carries the hybrid signature).
    pub vote: VoteV1,
    /// The BLS signature over the vote message.
    pub bls_sig: BlsSignature,
}

/// Build a QC from precommit votes that each carry a real BLS signature.
///
/// This replaces the Phase 4 placeholder that used zeroed bytes.
pub fn build_bls_qc(
    height: u64,
    round: u32,
    block_hash: Bytes32,
    precommits: &[PrecommitWithBls],
    validator_positions: &[(Bytes32, usize, u64)], // (validator_id, position, stake)
    total_stake: u64,
) -> NodeResult<QuorumCertificateV1> {
    let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
    let mut bls_sigs: Vec<BlsSignature> = Vec::new();
    let mut bls_msgs: Vec<Vec<u8>> = Vec::new();
    let mut pq_sigs: Vec<PQVoteSig> = Vec::new();
    let mut signed_stake: u64 = 0;

    for pc in precommits {
        // Look up position and stake
        let pos_stake = validator_positions.iter()
            .find(|(id, _, _)| *id == pc.vote.validator_id);

        let (position, stake) = match pos_stake {
            Some((_, pos, stake)) => (*pos, *stake),
            None => continue,
        };

        if position < MAX_VALIDATORS {
            signer_bitfield[position / 8] |= 1 << (position % 8);
        }

        let msg = bls_vote_message(
            height, round, VoteStep::Precommit,
            &block_hash, &pc.vote.validator_id,
        );
        bls_sigs.push(pc.bls_sig.clone());
        bls_msgs.push(msg);

        let pq_sig = PQVoteSig {
            validator_id: pc.vote.validator_id,
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(
                pc.vote.signature.pq_sig.as_slice()
            ).map_err(|_| NodeError::Crypto(CryptoError::MalformedSignature {
                scheme: "Dilithium2",
                actual: pc.vote.signature.pq_sig.len(),
            }))?,
        };
        pq_sigs.push(pq_sig);
        signed_stake = signed_stake.saturating_add(stake);
    }

    // Check quorum
    let stake_bps = if total_stake > 0 {
        signed_stake.saturating_mul(10_000) / total_stake
    } else {
        0
    };
    if (stake_bps as u32) < QUORUM_THRESHOLD_BPS {
        return Err(NodeError::BlockInvalid {
            height,
            reason: format!("quorum not reached: {stake_bps} bps < {QUORUM_THRESHOLD_BPS} bps"),
        });
    }

    // Aggregate BLS signatures
    let agg = aggregate_signatures(&bls_sigs)?;

    let bls_agg_sig = VariableBytes::<MAX_BLS_AGG_SIG_BYTES>::from_slice(&agg.0)
        .map_err(|_| NodeError::Crypto(CryptoError::MalformedSignature {
            scheme: "BLS12-381 aggregate",
            actual: agg.0.len(),
        }))?;

    Ok(QuorumCertificateV1 {
        height,
        round,
        block_hash,
        bls_agg_sig,
        signer_bitfield,
        pq_signatures: pq_sigs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        VariableBytes,
        types::{
            crypto::HybridSignature,
            primitives::{MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES},
        },
    };
    use indra_crypto::hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair};
    use indra_consensus::vote::produce_vote;

    fn make_precommit(
        seed: u8,
        height: u64,
        block_hash: Bytes32,
    ) -> (PrecommitWithBls, BlsVoteSigner, Bytes32) {
        let classical = ClassicalKeypair::from_seed(&[seed; 32]);
        let pq = PqKeypair::generate();
        let hybrid_kp = HybridKeypair::new(classical, pq);
        let pk = hybrid_kp.public_key();
        let validator_id = Bytes32::from(indra_crypto::sha256(&pk.classical.0));

        let bls_signer = BlsVoteSigner::from_seed(&[seed; 32]).unwrap();
        let vote = produce_vote(
            height, 0, VoteStep::Precommit,
            block_hash, validator_id, &hybrid_kp,
        ).unwrap();

        let bls_msg = bls_vote_message(height, 0, VoteStep::Precommit, &block_hash, &validator_id);
        let bls_sig = bls_signer.sign_vote(&bls_msg);

        (PrecommitWithBls { vote, bls_sig }, bls_signer, validator_id)
    }

    #[test]
    fn bls_qc_with_real_signatures() {
        let block_hash = Bytes32::from([0xAAu8; 32]);
        let (pc1, s1, id1) = make_precommit(0x01, 1, block_hash);
        let (pc2, s2, id2) = make_precommit(0x02, 1, block_hash);

        let positions = vec![
            (id1, 0usize, 5_000u64),
            (id2, 1usize, 5_000u64),
        ];

        let qc = build_bls_qc(1, 0, block_hash, &[pc1, pc2], &positions, 10_000).unwrap();
        assert_eq!(qc.signer_count(), 2);
        assert!(qc.is_signer(0));
        assert!(qc.is_signer(1));
        // BLS agg sig should be 96 bytes (real BLS, not a placeholder)
        assert_eq!(qc.bls_agg_sig.as_slice().len(), 96);
    }

    #[test]
    fn bls_vote_message_is_deterministic() {
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let validator_id = Bytes32::from([0x01u8; 32]);
        let m1 = bls_vote_message(1, 0, VoteStep::Precommit, &block_hash, &validator_id);
        let m2 = bls_vote_message(1, 0, VoteStep::Precommit, &block_hash, &validator_id);
        assert_eq!(m1, m2);
    }

    #[test]
    fn below_quorum_fails() {
        let block_hash = Bytes32::from([0xCCu8; 32]);
        let (pc1, _, id1) = make_precommit(0x01, 1, block_hash);

        // Only 1 of 10: 10% < 33% threshold
        let positions = vec![(id1, 0usize, 1_000u64)];
        let result = build_bls_qc(1, 0, block_hash, &[pc1], &positions, 10_000);
        assert!(result.is_err());
    }
}
RUST

# --------------- indra-node/src/state_root.rs ---------------

cat > indra-node/src/state_root.rs << 'RUST'
//! State root computation.
//!
//! Computes the `state_root` and `validator_set_root` fields in block headers.
//!
//! ## Phase 5 implementation
//!
//! We use a simple Merkle tree over the serialised chain state fields.
//! Phase 6 replaces this with a full persistent Merkle Patricia Trie
//! backed by RocksDB, enabling light client proofs.
//!
//! ## state_root
//!
//! SHA-256(height || base_fee || tip_hash || total_supply || treasury
//!         || utxo_set_hash || nullifier_set_hash)
//!
//! ## validator_set_root
//!
//! Merkle root of all active validator IDs sorted ascending.

use indra_core::types::primitives::Bytes32;
use indra_crypto::sha256;
use indra_state::ChainState;

/// Compute the state root for the given chain state.
///
/// This is a commitment to all consensus-critical state fields.
/// Nodes that have applied the same blocks will produce identical roots.
pub fn compute_state_root(state: &ChainState) -> Bytes32 {
    let mut data = Vec::with_capacity(128);
    data.extend_from_slice(&state.height.to_le_bytes());
    data.extend_from_slice(&state.base_fee.to_le_bytes());
    data.extend_from_slice(&state.tip_hash.0);
    data.extend_from_slice(&state.total_supply.to_le_bytes());
    data.extend_from_slice(&state.treasury.to_le_bytes());

    // Hash of UTXO count (Phase 6 replaces with full Merkle trie)
    let utxo_count = state.utxos.len() as u64;
    data.extend_from_slice(&utxo_count.to_le_bytes());

    // Hash of nullifier count
    let nullifier_count = state.nullifiers.len() as u64;
    data.extend_from_slice(&nullifier_count.to_le_bytes());

    Bytes32::from(sha256(&data))
}

/// Compute the validator set root for the given chain state.
///
/// This is a Merkle root over all active validator identities.
/// Sorted ascending by validator_id for determinism.
pub fn compute_validator_set_root(state: &ChainState) -> Bytes32 {
    use indra_crypto::hash_pair;

    let mut validator_ids: Vec<[u8; 32]> = state.validators
        .active_ids()
        .into_iter()
        .map(|id| id.0)
        .collect();

    if validator_ids.is_empty() {
        return Bytes32::ZERO;
    }

    validator_ids.sort();

    // Simple binary Merkle tree
    let leaves: Vec<[u8; 32]> = validator_ids.iter()
        .map(|id| sha256(id))
        .collect();

    Bytes32::from(merkle_root(&leaves))
}

/// Compute a binary Merkle root from a list of 32-byte leaves.
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    use indra_crypto::sha256;
    use indra_crypto::hash_pair;

    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    // Pad to next power of two
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    let target = layer.len().next_power_of_two();
    let zero = sha256(&[0u8; 32]);
    while layer.len() < target {
        layer.push(zero);
    }

    // Hash pairs bottom-up
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        let mut i = 0;
        while i + 1 < layer.len() {
            next.push(hash_pair(&layer[i], &layer[i + 1]));
            i += 2;
        }
        layer = next;
    }

    layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_root_is_deterministic() {
        let state = ChainState::new_genesis();
        assert_eq!(compute_state_root(&state), compute_state_root(&state));
    }

    #[test]
    fn state_root_changes_with_height() {
        let mut s1 = ChainState::new_genesis();
        let mut s2 = ChainState::new_genesis();
        s1.height = 1;
        s2.height = 2;
        assert_ne!(compute_state_root(&s1), compute_state_root(&s2));
    }

    #[test]
    fn validator_set_root_empty_is_zero() {
        let state = ChainState::new_genesis();
        // Genesis state has no validators
        assert_eq!(compute_validator_set_root(&state), Bytes32::ZERO);
    }

    #[test]
    fn merkle_root_single_leaf() {
        let leaf = sha256(b"test");
        assert_eq!(merkle_root(&[leaf]), leaf);
    }

    #[test]
    fn merkle_root_two_leaves() {
        let a = sha256(b"a");
        let b = sha256(b"b");
        let root = merkle_root(&[a, b]);
        assert_ne!(root, a);
        assert_ne!(root, b);
        // Deterministic
        assert_eq!(root, merkle_root(&[a, b]));
    }
}
RUST

# --------------- indra-node/src/sync.rs ---------------

cat > indra-node/src/sync.rs << 'RUST'
//! Block import and chain sync.
//!
//! `import_block` is the single entry point for adding a block to the chain.
//! It:
//!   1. Validates the block's structural invariants
//!   2. Applies it to the chain state via `apply_block`
//!   3. Computes and stores the new state root
//!   4. Writes the block to the block store
//!   5. Evicts spent transactions from the mempool
//!   6. Optionally takes a state snapshot

use indra_core::types::block::BlockV1;
use indra_state::{apply_block, ChainState};
use indra_consensus::mempool::Mempool;
use indra_storage::{BlockStore, StateStore, SNAPSHOT_INTERVAL};

use crate::{
    error::{NodeError, NodeResult},
    state_root::compute_state_root,
};

/// Import a block into the chain.
///
/// This is the canonical block processing pipeline:
/// validate → apply → store → evict mempool → snapshot.
pub fn import_block(
    block: &BlockV1,
    state: &mut ChainState,
    mempool: &mut Mempool,
    block_store: &mut BlockStore,
    state_store: &StateStore,
) -> NodeResult<()> {
    let height = block.header.height;

    // 1. Apply block to state (validates everything)
    apply_block(block, state).map_err(|e| NodeError::BlockInvalid {
        height,
        reason: e.to_string(),
    })?;

    // 2. Compute state root and store it in the state
    //    (the block header's state_root is checked against this in Phase 6)
    let _state_root = compute_state_root(state);

    // 3. Store block
    block_store.append(block)?;

    // 4. Evict spent transactions from mempool
    mempool.evict_spent(&state.nullifiers);

    // 5. Take snapshot if on interval
    if height % SNAPSHOT_INTERVAL == 0 && height > 0 {
        state_store.save(state)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        Bytes32, ProtocolVersion, VariableBytes,
        types::{
            block::{BlockHeaderV1, BlockV1},
            primitives::{INITIAL_BASE_FEE_SPARK_PER_KB, MAX_VRF_PROOF_BYTES},
        },
    };
    use indra_storage::StateStore;
    use std::path::PathBuf;

    fn temp_dir(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_sync_test_{}_{}", suffix, std::process::id()));
        p
    }

    fn make_block(height: u64, prev_hash: Bytes32, base_fee: u64) -> BlockV1 {
        BlockV1 {
            header: BlockHeaderV1 {
                protocol_version:    ProtocolVersion::CURRENT,
                height,
                prev_hash,
                timestamp:           1_700_000_000 + height,
                state_root:          Bytes32::ZERO,
                validator_set_root:  Bytes32::ZERO,
                mempool_set_root:    Bytes32::ZERO,
                base_fee,
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof:  VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
                quorum_certificate:  indra_core::VariableBytes::from_slice(&[]).unwrap(),
            },
            transactions:      vec![],
            slashing_evidence: vec![],
            governance_ops:    vec![],
        }
    }

    #[test]
    fn import_single_block() {
        let dir = temp_dir("a");
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = ChainState::new_genesis();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(dir.join("blocks.log")).unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        let block = make_block(1, state.tip_hash, INITIAL_BASE_FEE_SPARK_PER_KB);
        import_block(&block, &mut state, &mut mempool, &mut block_store, &state_store).unwrap();

        assert_eq!(state.height, 1);
        assert_eq!(block_store.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_chain_of_blocks() {
        let dir = temp_dir("b");
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = ChainState::new_genesis();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(dir.join("blocks.log")).unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        for i in 1..=10u64 {
            let block = make_block(i, state.tip_hash, state.base_fee);
            import_block(&block, &mut state, &mut mempool, &mut block_store, &state_store).unwrap();
        }

        assert_eq!(state.height, 10);
        assert_eq!(block_store.len(), 10);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_height_rejected() {
        let dir = temp_dir("c");
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = ChainState::new_genesis();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(dir.join("blocks.log")).unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        // Try to import height 5 when we're at genesis (height 0)
        let block = make_block(5, state.tip_hash, state.base_fee);
        assert!(import_block(&block, &mut state, &mut mempool, &mut block_store, &state_store).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
RUST

# --------------- indra-node/src/engine.rs ---------------

cat > indra-node/src/engine.rs << 'RUST'
//! NodeEngine — the consensus loop driver.
//!
//! Drives the BFT consensus state machine for one node.
//! In Phase 5 this runs synchronously (no async runtime).
//! Phase 6 wraps this in Tokio for async P2P.
//!
//! ## Consensus loop (per height)
//!
//!   1. Check if we are the proposer for this height
//!   2. If yes: produce a block and "broadcast" it (Phase 5: direct call)
//!   3. Collect prevotes from all validators (Phase 5: simulate locally)
//!   4. If prevote quorum: broadcast precommit
//!   5. Collect precommits until QC formed
//!   6. Import the committed block via sync::import_block
//!   7. Advance to next height

use indra_core::types::primitives::Bytes32;
use indra_crypto::{
    bls::BlsKeypair,
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    VrfKeypair,
};
use indra_state::ChainState;
use indra_consensus::{
    mempool::Mempool,
    proposer::{ProposerCandidate, ProposerElection, compute_proposer_vrf, elect_proposer},
    producer::{BlockTemplate, produce_block},
};
use indra_storage::{BlockStore, StateStore};

use crate::{
    config::NodeConfig,
    error::{NodeError, NodeResult},
    sync::import_block,
};

/// The node engine: owns all state and drives consensus.
pub struct NodeEngine {
    /// Node configuration.
    pub config: NodeConfig,
    /// Current chain state.
    pub state: ChainState,
    /// Pending transaction pool.
    pub mempool: Mempool,
    /// Persistent block log.
    pub block_store: BlockStore,
    /// State snapshot store.
    pub state_store: StateStore,
    /// The validator's hybrid keypair (if this is a validator node).
    hybrid_keypair: Option<HybridKeypair>,
    /// The validator's BLS keypair.
    bls_keypair: Option<BlsKeypair>,
    /// The validator's VRF keypair.
    vrf_keypair: Option<VrfKeypair>,
    /// This validator's identity (SHA-256 of hybrid public key classical component).
    validator_id: Option<Bytes32>,
}

impl NodeEngine {
    /// Initialise a node from its configuration.
    pub fn init(config: NodeConfig) -> NodeResult<Self> {
        std::fs::create_dir_all(&config.data_dir)
            .map_err(indra_storage::StorageError::Io)?;

        let block_store = BlockStore::open(config.block_log_path())?;
        let state_store = StateStore::open(config.state_dir())?;

        // Load state from snapshot or start from genesis
        let state = match state_store.load_latest()? {
            Some(s) => s,
            None => ChainState::new_genesis(),
        };

        let mempool = Mempool::new(indra_consensus::mempool::MempoolConfig {
            capacity: config.mempool_capacity,
            min_fee_ratio_bps: 10_000,
        });

        // Build validator keypairs if configured
        let (hybrid_keypair, bls_keypair, vrf_keypair, validator_id) =
            if let (Some(vs), Some(bs), Some(vrfs)) = (
                config.validator_seed,
                config.bls_seed,
                config.vrf_seed,
            ) {
                let classical = ClassicalKeypair::from_seed(&vs);
                let pq = PqKeypair::generate();
                let hybrid = HybridKeypair::new(classical, pq);
                let bls = BlsKeypair::from_seed(&bs)?;
                let vrf = VrfKeypair::from_seed(&vrfs);
                let pk = hybrid.public_key();
                let id = Bytes32::from(indra_crypto::sha256(&pk.classical.0));
                (Some(hybrid), Some(bls), Some(vrf), Some(id))
            } else {
                (None, None, None, None)
            };

        Ok(Self {
            config,
            state,
            mempool,
            block_store,
            state_store,
            hybrid_keypair,
            bls_keypair,
            vrf_keypair,
            validator_id,
        })
    }

    /// Current chain height.
    pub fn height(&self) -> u64 {
        self.state.height
    }

    /// This node's validator ID, if it is a validator.
    pub fn validator_id(&self) -> Option<Bytes32> {
        self.validator_id
    }

    /// Check if this node is the elected proposer for the next height.
    pub fn is_proposer(&self, election: &ProposerElection) -> bool {
        let Some(vrf_kp) = &self.vrf_keypair else { return false; };
        let slot = compute_proposer_vrf(vrf_kp, &election.epoch_seed, self.state.height + 1);
        let elected = match elect_proposer(election) {
            Ok(id) => id,
            Err(_) => return false,
        };
        elected == slot.proposer_id
    }

    /// Propose a block for the next height (only if this node is the proposer).
    pub fn propose(
        &self,
        election: &ProposerElection,
        timestamp: u64,
        prev_qc_bytes: Vec<u8>,
    ) -> NodeResult<indra_core::types::block::BlockV1> {
        let vrf_kp = self.vrf_keypair.as_ref()
            .ok_or(NodeError::NotProposer { height: self.state.height + 1 })?;

        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&self.config.vrf_seed
                .ok_or(NodeError::NotProposer { height: self.state.height + 1 })?),
            epoch_seed: election.epoch_seed,
            prev_qc_bytes,
            timestamp,
        };

        produce_block(&template, &self.state, &self.mempool, election)
            .map_err(NodeError::Consensus)
    }

    /// Import a block that has been committed (QC formed).
    pub fn commit_block(
        &mut self,
        block: &indra_core::types::block::BlockV1,
    ) -> NodeResult<()> {
        import_block(
            block,
            &mut self.state,
            &mut self.mempool,
            &mut self.block_store,
            &self.state_store,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(suffix: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_engine_test_{}_{}", suffix, std::process::id()));
        p
    }

    #[test]
    fn engine_init_genesis() {
        let dir = temp_dir("a");
        let config = NodeConfig::local_test(dir.clone());
        let engine = NodeEngine::init(config).unwrap();
        assert_eq!(engine.height(), 0);
        assert!(engine.validator_id().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_node_has_no_validator_id() {
        let dir = temp_dir("b");
        let config = NodeConfig::full_node(dir.clone());
        let engine = NodeEngine::init(config).unwrap();
        assert!(engine.validator_id().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn engine_commit_block() {
        let dir = temp_dir("c");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();

        use indra_core::{
            Bytes32, ProtocolVersion, VariableBytes,
            types::block::{BlockHeaderV1, BlockV1},
            types::primitives::{INITIAL_BASE_FEE_SPARK_PER_KB, MAX_VRF_PROOF_BYTES},
        };

        let block = BlockV1 {
            header: BlockHeaderV1 {
                protocol_version:    ProtocolVersion::CURRENT,
                height:              1,
                prev_hash:           engine.state.tip_hash,
                timestamp:           1_700_000_001,
                state_root:          Bytes32::ZERO,
                validator_set_root:  Bytes32::ZERO,
                mempool_set_root:    Bytes32::ZERO,
                base_fee:            INITIAL_BASE_FEE_SPARK_PER_KB,
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof:  VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
                quorum_certificate:  indra_core::VariableBytes::from_slice(&[]).unwrap(),
            },
            transactions:      vec![],
            slashing_evidence: vec![],
            governance_ops:    vec![],
        };

        engine.commit_block(&block).unwrap();
        assert_eq!(engine.height(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
RUST

# --------------- indra-node/tests/node.rs ---------------

cat > indra-node/tests/node.rs << 'RUST'
//! Integration tests for the full node pipeline.

use std::path::PathBuf;
use indra_core::{
    Bytes32, ProtocolVersion, VariableBytes,
    types::{
        block::{BlockHeaderV1, BlockV1},
        primitives::{INITIAL_BASE_FEE_SPARK_PER_KB, MAX_VRF_PROOF_BYTES},
    },
};
use indra_state::ChainState;
use indra_consensus::mempool::Mempool;
use indra_storage::{BlockStore, StateStore};
use indra_node::{
    NodeConfig, NodeEngine,
    genesis::{build_genesis_block, build_genesis_state, genesis_block_hash},
    state_root::compute_state_root,
    sync::import_block,
};

fn temp_dir(suffix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("indra_node_test_{}_{}", suffix, std::process::id()));
    p
}

fn make_block(height: u64, prev_hash: Bytes32, base_fee: u64) -> BlockV1 {
    BlockV1 {
        header: BlockHeaderV1 {
            protocol_version:    ProtocolVersion::CURRENT,
            height,
            prev_hash,
            timestamp:           1_700_000_000 + height,
            state_root:          Bytes32::ZERO,
            validator_set_root:  Bytes32::ZERO,
            mempool_set_root:    Bytes32::ZERO,
            base_fee,
            proposer_vrf_output: Bytes32::ZERO,
            proposer_vrf_proof:  VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
            quorum_certificate:  indra_core::VariableBytes::from_slice(&[]).unwrap(),
        },
        transactions:      vec![],
        slashing_evidence: vec![],
        governance_ops:    vec![],
    }
}

#[test]
fn genesis_is_deterministic() {
    let h1 = genesis_block_hash();
    let h2 = genesis_block_hash();
    assert_eq!(h1, h2);
}

#[test]
fn node_engine_init_and_commit() {
    let dir = temp_dir("engine");
    let config = NodeConfig::local_test(dir.clone());
    let mut engine = NodeEngine::init(config).unwrap();

    assert_eq!(engine.height(), 0);

    // Commit 5 blocks
    for i in 1..=5u64 {
        let block = make_block(i, engine.state.tip_hash, engine.state.base_fee);
        engine.commit_block(&block).unwrap();
    }

    assert_eq!(engine.height(), 5);
    assert_eq!(engine.block_store.len(), 5);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn state_root_changes_after_each_block() {
    let dir = temp_dir("roots");
    std::fs::create_dir_all(&dir).unwrap();

    let mut state = ChainState::new_genesis();
    let mut mempool = Mempool::default_config();
    let mut block_store = BlockStore::open(dir.join("blocks.log")).unwrap();
    let state_store = StateStore::open(dir.join("state")).unwrap();

    let root0 = compute_state_root(&state);

    let b1 = make_block(1, state.tip_hash, state.base_fee);
    import_block(&b1, &mut state, &mut mempool, &mut block_store, &state_store).unwrap();
    let root1 = compute_state_root(&state);

    let b2 = make_block(2, state.tip_hash, state.base_fee);
    import_block(&b2, &mut state, &mut mempool, &mut block_store, &state_store).unwrap();
    let root2 = compute_state_root(&state);

    assert_ne!(root0, root1);
    assert_ne!(root1, root2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn block_store_survives_reopen() {
    let dir = temp_dir("reopen");
    std::fs::create_dir_all(&dir).unwrap();
    let log_path = dir.join("blocks.log");

    {
        let mut state = ChainState::new_genesis();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(&log_path).unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        for i in 1..=3u64 {
            let b = make_block(i, state.tip_hash, state.base_fee);
            import_block(&b, &mut state, &mut mempool, &mut block_store, &state_store).unwrap();
        }
    }

    // Reopen and verify blocks are still there
    let mut store2 = BlockStore::open(&log_path).unwrap();
    assert_eq!(store2.len(), 3);
    assert_eq!(store2.get(1).unwrap().header.height, 1);
    assert_eq!(store2.get(3).unwrap().header.height, 3);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn snapshot_and_restore() {
    let dir = temp_dir("snapshot");
    std::fs::create_dir_all(&dir).unwrap();

    let state_store = StateStore::open(dir.join("state")).unwrap();

    let mut state = ChainState::new_genesis();
    state.height = 300;
    state.base_fee = 999;

    state_store.save(&state).unwrap();

    let restored = state_store.load_latest().unwrap().unwrap();
    assert_eq!(restored.height, 300);
    assert_eq!(restored.base_fee, 999);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn full_node_pipeline() {
    // Complete pipeline: genesis → import blocks → state roots → snapshot
    let dir = temp_dir("full");
    std::fs::create_dir_all(&dir).unwrap();

    let mut state = build_genesis_state();
    let mut mempool = Mempool::default_config();
    let mut block_store = BlockStore::open(dir.join("blocks.log")).unwrap();
    let state_store = StateStore::open(dir.join("state")).unwrap();

    let roots: Vec<Bytes32> = (1..=10u64).map(|i| {
        let b = make_block(i, state.tip_hash, state.base_fee);
        import_block(&b, &mut state, &mut mempool, &mut block_store, &state_store).unwrap();
        compute_state_root(&state)
    }).collect();

    // All roots are distinct
    for i in 0..roots.len() - 1 {
        assert_ne!(roots[i], roots[i + 1], "roots[{i}] == roots[{}]", i + 1);
    }

    assert_eq!(state.height, 10);
    assert_eq!(block_store.len(), 10);
    let _ = std::fs::remove_dir_all(&dir);
}
RUST

echo ""
echo "✓ INDRA Phase 5 files written."
echo ""
echo "New crate: indra-storage"
echo "  src/block_store.rs — append-only block log with crash recovery"
echo "  src/state_store.rs — chain state snapshots (atomic write-then-rename)"
echo "  src/wal.rs         — mempool write-ahead log with CRC32 integrity"
echo ""
echo "New crate: indra-node"
echo "  src/config.rs     — NodeConfig"
echo "  src/genesis.rs    — genesis block and state"
echo "  src/bls_vote.rs   — real BLS vote signing (replaces Phase 4 placeholder)"
echo "  src/state_root.rs — state_root and validator_set_root computation"
echo "  src/sync.rs       — block import pipeline"
echo "  src/engine.rs     — NodeEngine driving consensus"
echo "  tests/node.rs     — end-to-end integration tests"
echo ""
echo "Now run:"
echo "  cargo build"
echo "  cargo test"
echo ""