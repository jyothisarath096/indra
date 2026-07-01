//! Small helpers for durable single-file replacement.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use crate::error::StorageResult;

/// Write bytes to `tmp_path`, fsync them, atomically rename to `final_path`,
/// and fsync the parent directory when available.
pub(crate) fn write_atomic_synced(
    tmp_path: &Path,
    final_path: &Path,
    bytes: &[u8],
) -> StorageResult<()> {
    if let Some(parent) = final_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(tmp_path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    fs::rename(tmp_path, final_path)?;
    if let Some(parent) = final_path.parent() {
        fsync_dir(parent)?;
    }
    Ok(())
}

/// Best-effort directory fsync for atomic rename durability.
pub(crate) fn fsync_dir(path: &Path) -> StorageResult<()> {
    let dir = File::open(path)?;
    dir.sync_all()?;
    Ok(())
}

/// CRC32 using the IEEE polynomial. This is not cryptographic; it catches
/// torn/truncated local writes and accidental corruption.
pub(crate) fn crc32(data: &[u8]) -> u32 {
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
