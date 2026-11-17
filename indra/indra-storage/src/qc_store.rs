//! Persistence for the most recently committed quorum certificate bytes.

use std::path::Path;

use crate::atomic::write_atomic_synced;
use crate::error::StorageResult;

const LAST_QC_FILE: &str = "last_qc.bin";
const LAST_QC_TMP_FILE: &str = "last_qc.bin.tmp";
const PENDING_LAST_QC_FILE: &str = "pending_last_qc.bin";
const PENDING_LAST_QC_TMP_FILE: &str = "pending_last_qc.bin.tmp";

/// Write the last committed QC bytes to disk.
///
/// The file is replaced atomically via write-then-rename so a crash cannot
/// leave behind a partially written QC blob.
pub fn save_last_qc(state_dir: &Path, qc_bytes: &[u8]) -> StorageResult<()> {
    std::fs::create_dir_all(state_dir)?;
    let tmp = state_dir.join(LAST_QC_TMP_FILE);
    let final_path = state_dir.join(LAST_QC_FILE);
    write_atomic_synced(&tmp, &final_path, qc_bytes)?;
    Ok(())
}

/// Durably stage the QC for a block that is about to be committed.
///
/// Block headers carry the previous block's QC, so a locally finalising node
/// must persist the current-tip QC out-of-band. This pending file closes the
/// crash window between "QC has been built" and "`last_qc.bin` has been
/// promoted after the block commit": startup may use it only if the rebuilt
/// state height matches the QC's certified height.
pub fn save_pending_last_qc(state_dir: &Path, qc_bytes: &[u8]) -> StorageResult<()> {
    std::fs::create_dir_all(state_dir)?;
    let tmp = state_dir.join(PENDING_LAST_QC_TMP_FILE);
    let final_path = state_dir.join(PENDING_LAST_QC_FILE);
    write_atomic_synced(&tmp, &final_path, qc_bytes)?;
    Ok(())
}

/// Read the last committed QC bytes from disk.
///
/// Returns `Ok(None)` when no QC has been persisted yet.
pub fn load_last_qc(state_dir: &Path) -> StorageResult<Option<Vec<u8>>> {
    let path = state_dir.join(LAST_QC_FILE);
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// Remove a persisted QC that failed startup authority verification.
pub fn clear_last_qc(state_dir: &Path) -> StorageResult<()> {
    clear_qc_file(&state_dir.join(LAST_QC_FILE))
}

/// Read the staged current-tip QC bytes, if any.
pub fn load_pending_last_qc(state_dir: &Path) -> StorageResult<Option<Vec<u8>>> {
    let path = state_dir.join(PENDING_LAST_QC_FILE);
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// Remove the staged current-tip QC after it has been promoted or found stale.
pub fn clear_pending_last_qc(state_dir: &Path) -> StorageResult<()> {
    clear_qc_file(&state_dir.join(PENDING_LAST_QC_FILE))
}

fn clear_qc_file(path: &Path) -> StorageResult<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                crate::atomic::fsync_dir(parent)?;
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    fn temp_dir(label: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "indra_qc_store_test_{}_{}",
            label,
            std::process::id()
        ));
        p
    }

    #[test]
    fn save_and_load_last_qc_round_trip() {
        let dir = temp_dir("roundtrip");
        let bytes = vec![1, 2, 3, 4, 5, 6];
        save_last_qc(&dir, &bytes).unwrap();
        assert_eq!(load_last_qc(&dir).unwrap(), Some(bytes));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pending_last_qc_round_trip_and_clear() {
        let dir = temp_dir("pending_roundtrip");
        let bytes = vec![9, 8, 7, 6];
        save_pending_last_qc(&dir, &bytes).unwrap();
        assert_eq!(load_pending_last_qc(&dir).unwrap(), Some(bytes));
        clear_pending_last_qc(&dir).unwrap();
        assert_eq!(load_pending_last_qc(&dir).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_qc_file_returns_none() {
        let dir = temp_dir("missing");
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(load_last_qc(&dir).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_survives_concurrent_access() {
        let dir = temp_dir("atomic");
        std::fs::create_dir_all(&dir).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let writer_stop = Arc::clone(&stop);
        let writer_dir = dir.clone();
        let a = vec![0xAA; 64];
        let b = vec![0xBB; 96];
        let a_check = a.clone();
        let b_check = b.clone();

        let writer = std::thread::spawn(move || {
            for i in 0..200 {
                let payload = if i % 2 == 0 { &a } else { &b };
                save_last_qc(&writer_dir, payload).unwrap();
            }
            writer_stop.store(true, Ordering::SeqCst);
        });

        while !stop.load(Ordering::SeqCst) {
            if let Some(bytes) = load_last_qc(&dir).unwrap() {
                assert!(
                    bytes == a_check || bytes == b_check,
                    "observed torn QC file of {} bytes",
                    bytes.len()
                );
            }
        }

        writer.join().unwrap();
        let final_bytes = load_last_qc(&dir).unwrap().unwrap();
        assert!(final_bytes == a_check || final_bytes == b_check);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
