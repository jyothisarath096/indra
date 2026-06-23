//! Vote safety persistence.
//!
//! Persists the highest `(height, round, step)` voted to disk before each local
//! vote. On restart, the validator skips past rounds it already voted in,
//! preventing accidental equivocation.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::StorageResult;

/// The persisted vote safety record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoteSafetyRecord {
    /// Proposal height the vote was cast for.
    pub height: u64,
    /// Consensus round the vote was cast in.
    pub round: u32,
    /// Vote step: 0 = prevote, 1 = precommit.
    pub step: u8,
}

/// Manages vote safety persistence.
pub struct VoteSafetyStore {
    path: PathBuf,
    tmp_path: PathBuf,
}

impl VoteSafetyStore {
    /// Open a vote safety store at the given path.
    pub fn open(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let tmp_path = path.with_extension("tmp");
        Self { path, tmp_path }
    }

    /// Persist a vote safety record atomically before casting a vote.
    pub fn record(&self, height: u64, round: u32, step: u8) -> StorageResult<()> {
        let mut buf = [0u8; 17];
        buf[0..8].copy_from_slice(&height.to_le_bytes());
        buf[8..12].copy_from_slice(&round.to_le_bytes());
        buf[12] = step;
        let crc = crc32(&buf[0..13]);
        buf[13..17].copy_from_slice(&crc.to_le_bytes());

        fs::write(&self.tmp_path, buf)?;
        fs::rename(&self.tmp_path, &self.path)?;
        Ok(())
    }

    /// Load the persisted vote safety record.
    ///
    /// Returns `None` if the file does not exist or fails CRC validation.
    pub fn load(&self) -> Option<VoteSafetyRecord> {
        let buf = fs::read(&self.path).ok()?;
        if buf.len() != 17 {
            return None;
        }

        let stored_crc = u32::from_le_bytes(buf[13..17].try_into().ok()?);
        let computed_crc = crc32(&buf[0..13]);
        if stored_crc != computed_crc {
            eprintln!("[vote_safety] corrupt vote safety file — ignoring");
            return None;
        }

        let height = u64::from_le_bytes(buf[0..8].try_into().ok()?);
        let round = u32::from_le_bytes(buf[8..12].try_into().ok()?);
        let step = buf[12];
        Some(VoteSafetyRecord {
            height,
            round,
            step,
        })
    }
}

/// CRC32 using the IEEE polynomial.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        let mut b = byte as u32;
        for _ in 0..8 {
            let mix = (crc ^ b) & 1;
            crc >>= 1;
            if mix != 0 {
                crc ^= 0xEDB8_8320;
            }
            b >>= 1;
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "indra_vote_safety_{}_{}.dat",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("tmp"));
        path
    }

    #[test]
    fn record_and_load_round_trip() {
        let path = tmp_path("round_trip");
        let store = VoteSafetyStore::open(&path);
        store.record(42, 7, 0).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.height, 42);
        assert_eq!(loaded.round, 7);
        assert_eq!(loaded.step, 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_nonexistent_returns_none() {
        let store = VoteSafetyStore::open(tmp_path("nonexistent"));
        assert!(store.load().is_none());
    }

    #[test]
    fn corrupt_crc_returns_none() {
        let path = tmp_path("corrupt");
        let store = VoteSafetyStore::open(&path);
        store.record(1, 1, 0).unwrap();
        let mut buf = std::fs::read(&path).unwrap();
        buf[0] ^= 0xFF;
        std::fs::write(&path, &buf).unwrap();
        assert!(store.load().is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn records_are_atomic_rename() {
        let path = tmp_path("atomic");
        let store = VoteSafetyStore::open(&path);
        store.record(1, 0, 0).unwrap();
        store.record(1, 1, 0).unwrap();
        store.record(1, 1, 1).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.round, 1);
        assert_eq!(loaded.step, 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn higher_round_precommit_persisted() {
        let path = tmp_path("precommit");
        let store = VoteSafetyStore::open(&path);
        store.record(100, 15, 1).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.height, 100);
        assert_eq!(loaded.round, 15);
        assert_eq!(loaded.step, 1);
        let _ = std::fs::remove_file(&path);
    }
}
