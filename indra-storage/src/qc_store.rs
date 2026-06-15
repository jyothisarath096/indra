//! Persistence for the most recently committed quorum certificate bytes.

use std::fs;
use std::path::Path;

use crate::error::StorageResult;

const LAST_QC_FILE: &str = "last_qc.bin";
const LAST_QC_TMP_FILE: &str = "last_qc.bin.tmp";

/// Write the last committed QC bytes to disk.
///
/// The file is replaced atomically via write-then-rename so a crash cannot
/// leave behind a partially written QC blob.
pub fn save_last_qc(state_dir: &Path, qc_bytes: &[u8]) -> StorageResult<()> {
    fs::create_dir_all(state_dir)?;
    let tmp = state_dir.join(LAST_QC_TMP_FILE);
    let final_path = state_dir.join(LAST_QC_FILE);
    fs::write(&tmp, qc_bytes)?;
    fs::rename(&tmp, final_path)?;
    Ok(())
}

/// Read the last committed QC bytes from disk.
///
/// Returns `Ok(None)` when no QC has been persisted yet.
pub fn load_last_qc(state_dir: &Path) -> StorageResult<Option<Vec<u8>>> {
    let path = state_dir.join(LAST_QC_FILE);
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    fn temp_dir(label: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_qc_store_test_{}_{}", label, std::process::id()));
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
