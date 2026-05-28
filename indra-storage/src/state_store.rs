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

                let height_bytes: [u8; 8] = header[..8]
                    .try_into()
                    .map_err(|_| StorageError::Corruption {
                        height: 0,
                        detail: "snapshot header truncated while reading height".to_string(),
                    })?;
                let height = u64::from_le_bytes(height_bytes);
                let length_bytes: [u8; 4] = header[8..12]
                    .try_into()
                    .map_err(|_| StorageError::Corruption {
                        height,
                        detail: "snapshot header truncated while reading length".to_string(),
                    })?;
                let length = u32::from_le_bytes(length_bytes) as usize;

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
/// Format: height(8) || base_fee(8) || tip_hash(32) || total_supply(8)
///      || treasury(8) || fee_reward_pool(8)
/// This is a minimal snapshot — the full UTXO/nullifier/validator sets
/// are rebuilt from block replay in Phase 6. For now we store the summary fields.
fn serialise_chain_state(state: &ChainState) -> Vec<u8> {
    let mut buf = Vec::with_capacity(72);
    buf.extend_from_slice(&state.height.to_le_bytes());
    buf.extend_from_slice(&state.base_fee.to_le_bytes());
    buf.extend_from_slice(&state.tip_hash.0);
    buf.extend_from_slice(&state.total_supply.to_le_bytes());
    buf.extend_from_slice(&state.treasury_balance.to_le_bytes());
    buf.extend_from_slice(&state.fee_reward_pool.to_le_bytes());
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
    let fee_reward_pool = if bytes.len() >= 72 {
        u64::from_le_bytes(bytes[64..72].try_into().map_err(|_| "bad fee_reward_pool")?)
    } else {
        0
    };

    use indra_core::types::primitives::Bytes32;
    let mut state = ChainState::new_genesis();
    state.height       = height;
    state.base_fee     = base_fee;
    state.tip_hash     = Bytes32::from(tip_hash);
    state.total_supply = total_supply;
    state.treasury_balance = treasury;
    state.fee_reward_pool = fee_reward_pool;
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
        state.fee_reward_pool = 777;

        store.save(&state).unwrap();

        let loaded = store.load_latest().unwrap().unwrap();
        assert_eq!(loaded.height, 42);
        assert_eq!(loaded.base_fee, 500);
        assert_eq!(loaded.fee_reward_pool, 777);

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
