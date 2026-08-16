//! Append-only epoch summary log.
//!
//! File format: [u64 epoch][u32 length][EpochRecord bytes] repeated.
//! The in-memory index is rebuilt on open by scanning the file.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use indra_core::{
    codec::{ByteReader, Decode, Encode},
    types::primitives::SCHEMA_VERSION,
    EpochRecord,
};

use crate::error::{StorageError, StorageResult};

/// The header size for each epoch entry: u64 epoch + u32 length.
const ENTRY_HEADER_BYTES: usize = 12;
const FILE_HEADER_BYTES: u64 = 16;
const EPOCH_MAGIC: &[u8; 4] = b"INEP";
const EPOCH_FILE_VERSION: u8 = 1;

/// Append-only epoch summary log.
pub struct EpochStore {
    path: PathBuf,
    file: File,
    index: Arc<RwLock<HashMap<u64, u64>>>,
    next_epoch: u64,
}

impl EpochStore {
    /// Open or create an epoch store at the given path.
    pub fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;

        let file_len = file.seek(SeekFrom::End(0))?;
        if file_len == 0 {
            write_file_header(&mut file)?;
        } else {
            read_file_header(&mut file)?;
        }

        let mut store = Self {
            path,
            file,
            index: Arc::new(RwLock::new(HashMap::new())),
            next_epoch: 0,
        };
        store.rebuild_index()?;
        Ok(store)
    }

    /// Append a new epoch record. Epoch numbers must be monotonically increasing.
    pub fn append(&mut self, record: &EpochRecord) -> StorageResult<()> {
        if record.epoch != self.next_epoch {
            return Err(StorageError::NonSequential {
                expected: self.next_epoch,
                actual: record.epoch,
            });
        }

        let record_bytes = record.encode_to_vec();
        let length = record_bytes.len() as u32;
        let offset = self.file.seek(SeekFrom::End(0))?;

        self.file.write_all(&record.epoch.to_le_bytes())?;
        self.file.write_all(&length.to_le_bytes())?;
        self.file.write_all(&record_bytes)?;
        self.file.flush()?;
        self.file.sync_all()?;

        self.index
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(record.epoch, offset);
        self.next_epoch += 1;
        Ok(())
    }

    /// Quarantine and remove epoch records newer than the manifest commit.
    pub fn recover_to_latest(&mut self, latest: Option<u64>) -> StorageResult<()> {
        let confirmed_next = latest.map_or(0, |epoch| epoch.saturating_add(1));
        if self.next_epoch <= confirmed_next {
            return Ok(());
        }
        let cut = if confirmed_next == 0 {
            FILE_HEADER_BYTES
        } else {
            self.index
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&confirmed_next)
                .copied()
                .ok_or_else(|| StorageError::ManifestMismatch {
                    detail: format!("epoch recovery boundary {confirmed_next} is missing"),
                })?
        };
        let quarantine = self.path.with_extension("log.unconfirmed");
        std::fs::rename(&self.path, &quarantine)?;
        let mut source = File::open(&quarantine)?;
        let mut replacement = File::create(&self.path)?;
        std::io::copy(
            &mut std::io::Read::by_ref(&mut source).take(cut),
            &mut replacement,
        )?;
        replacement.flush()?;
        replacement.sync_all()?;
        if let Some(parent) = self.path.parent() {
            crate::atomic::fsync_dir(parent)?;
        }
        self.file = OpenOptions::new().read(true).write(true).open(&self.path)?;
        self.rebuild_index()?;
        Ok(())
    }

    /// Retrieve a specific epoch record.
    pub fn get(&self, epoch: u64) -> StorageResult<EpochRecord> {
        let offset = self
            .index
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&epoch)
            .copied()
            .ok_or(StorageError::EpochNotFound { epoch })?;

        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(offset))?;
        let mut header = [0u8; ENTRY_HEADER_BYTES];
        file.read_exact(&mut header)?;

        let stored_epoch =
            u64::from_le_bytes(
                header[..8]
                    .try_into()
                    .map_err(|_| StorageError::Corruption {
                        height: epoch,
                        detail: "entry header truncated while reading epoch".to_string(),
                    })?,
            );
        let length =
            u32::from_le_bytes(
                header[8..12]
                    .try_into()
                    .map_err(|_| StorageError::Corruption {
                        height: epoch,
                        detail: "entry header truncated while reading length".to_string(),
                    })?,
            ) as usize;

        if stored_epoch != epoch {
            return Err(StorageError::Corruption {
                height: epoch,
                detail: format!("epoch index mismatch: stored epoch {stored_epoch}"),
            });
        }

        let mut record_bytes = vec![0u8; length];
        file.read_exact(&mut record_bytes)?;
        let mut reader = ByteReader::new(&record_bytes);
        EpochRecord::decode(&mut reader).map_err(|e| StorageError::Corruption {
            height: epoch,
            detail: e.to_string(),
        })
    }

    /// Returns true if the given epoch has been recorded.
    pub fn has(&self, epoch: u64) -> bool {
        self.index
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&epoch)
    }

    /// The highest recorded epoch number. None if no epochs have been recorded.
    pub fn latest_epoch(&self) -> Option<u64> {
        self.index
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .max()
            .copied()
    }

    /// Returns up to `limit` records ending at `to_epoch`, most recent first.
    pub fn get_range(&self, to_epoch: u64, limit: usize) -> StorageResult<Vec<EpochRecord>> {
        let mut epochs: Vec<u64> = self
            .index
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .copied()
            .filter(|epoch| *epoch <= to_epoch)
            .collect();
        epochs.sort_by(|a, b| b.cmp(a));
        epochs
            .into_iter()
            .take(limit)
            .map(|epoch| self.get(epoch))
            .collect()
    }

    /// Total number of epoch records stored.
    pub fn len(&self) -> usize {
        self.index
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// True if no epochs have been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.index
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }

    fn rebuild_index(&mut self) -> StorageResult<()> {
        self.index
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.file.seek(SeekFrom::Start(FILE_HEADER_BYTES))?;
        let file_size = self.file.seek(SeekFrom::End(0))?;
        let mut offset = FILE_HEADER_BYTES;
        let mut max_epoch = None;

        while offset < file_size {
            if file_size.saturating_sub(offset) < ENTRY_HEADER_BYTES as u64 {
                self.file.set_len(offset)?;
                break;
            }

            self.file.seek(SeekFrom::Start(offset))?;
            let mut header = [0u8; ENTRY_HEADER_BYTES];
            self.file.read_exact(&mut header)?;
            let epoch = u64::from_le_bytes(header[..8].try_into().map_err(|_| {
                StorageError::Corruption {
                    height: offset,
                    detail: "epoch header decode failed".to_string(),
                }
            })?);
            let length = u32::from_le_bytes(header[8..12].try_into().map_err(|_| {
                StorageError::Corruption {
                    height: epoch,
                    detail: "epoch length decode failed".to_string(),
                }
            })?) as u64;
            let next_offset = offset
                .saturating_add(ENTRY_HEADER_BYTES as u64)
                .saturating_add(length);

            if next_offset > file_size {
                self.file.set_len(offset)?;
                break;
            }

            self.index
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(epoch, offset);
            max_epoch = Some(max_epoch.map_or(epoch, |max: u64| max.max(epoch)));
            offset = next_offset;
        }

        self.next_epoch = max_epoch.map_or(0, |epoch| epoch.saturating_add(1));
        self.file.seek(SeekFrom::End(0))?;
        Ok(())
    }

    /// Create a cloneable read handle independent of the canonical writer.
    pub fn read_handle(&self) -> EpochStoreReadHandle {
        EpochStoreReadHandle {
            path: self.path.clone(),
            index: Arc::clone(&self.index),
        }
    }
}

/// Cloneable epoch-log read capability independent of the canonical writer.
#[derive(Clone)]
pub struct EpochStoreReadHandle {
    path: PathBuf,
    index: Arc<RwLock<HashMap<u64, u64>>>,
}

impl EpochStoreReadHandle {
    /// Read one epoch record.
    pub fn get(&self, epoch: u64) -> StorageResult<EpochRecord> {
        let offset = self
            .index
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&epoch)
            .copied()
            .ok_or(StorageError::EpochNotFound { epoch })?;
        read_epoch_at(&self.path, epoch, offset)
    }

    /// Highest recorded epoch.
    pub fn latest_epoch(&self) -> Option<u64> {
        self.index
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .max()
            .copied()
    }

    /// Read a bounded descending epoch range.
    pub fn get_range(&self, to_epoch: u64, limit: usize) -> StorageResult<Vec<EpochRecord>> {
        let mut epochs: Vec<_> = self
            .index
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .copied()
            .filter(|epoch| *epoch <= to_epoch)
            .collect();
        epochs.sort_by(|a, b| b.cmp(a));
        epochs
            .into_iter()
            .take(limit)
            .map(|epoch| self.get(epoch))
            .collect()
    }
}

fn read_epoch_at(path: &Path, epoch: u64, offset: u64) -> StorageResult<EpochRecord> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut header = [0u8; ENTRY_HEADER_BYTES];
    file.read_exact(&mut header)?;
    let stored_epoch =
        u64::from_le_bytes(
            header[..8]
                .try_into()
                .map_err(|_| StorageError::Corruption {
                    height: epoch,
                    detail: "entry header truncated while reading epoch".to_string(),
                })?,
        );
    let length =
        u32::from_le_bytes(
            header[8..12]
                .try_into()
                .map_err(|_| StorageError::Corruption {
                    height: epoch,
                    detail: "entry header truncated while reading length".to_string(),
                })?,
        ) as usize;
    if stored_epoch != epoch {
        return Err(StorageError::Corruption {
            height: epoch,
            detail: format!("epoch index mismatch: stored epoch {stored_epoch}"),
        });
    }
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)?;
    EpochRecord::decode(&mut ByteReader::new(&bytes)).map_err(|error| StorageError::Corruption {
        height: epoch,
        detail: error.to_string(),
    })
}

fn write_file_header(file: &mut File) -> StorageResult<()> {
    file.seek(SeekFrom::Start(0))?;
    file.write_all(EPOCH_MAGIC)?;
    file.write_all(&[EPOCH_FILE_VERSION, SCHEMA_VERSION])?;
    file.write_all(&[0u8; 10])?;
    file.flush()?;
    Ok(())
}

fn read_file_header(file: &mut File) -> StorageResult<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; FILE_HEADER_BYTES as usize];
    file.read_exact(&mut header)?;
    if &header[0..4] != EPOCH_MAGIC {
        return Err(StorageError::Corruption {
            height: 0,
            detail: "epoch store missing INEP header".to_string(),
        });
    }
    if header[4] != EPOCH_FILE_VERSION {
        return Err(StorageError::Corruption {
            height: 0,
            detail: format!("unsupported epoch store file version {}", header[4]),
        });
    }
    let schema_version = header[5];
    if schema_version != SCHEMA_VERSION {
        return Err(StorageError::Corruption {
            height: 0,
            detail: format!(
                "epoch store schema version {} does not match node schema version {}",
                schema_version, SCHEMA_VERSION
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("indra_epoch_store_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn record(epoch: u64) -> EpochRecord {
        EpochRecord {
            epoch,
            start_height: epoch.saturating_mul(300),
            end_height: epoch.saturating_mul(300).saturating_add(299),
            timestamp_secs: 1_750_000_000 + epoch,
            active_validators: 4,
            total_staked_spark: 400_000_000_000,
            reward_minted_spark: 356_760_000_000,
            fee_rewards_distributed: epoch,
            fee_burned_spark: 0,
            slash_burned_spark: 0,
            governance_burned_spark: 0,
            total_burned_spark: 0,
            opening_total_supply_spark: 99_999_643_240_000_000,
            closing_total_supply_spark: 100_000_000_000_000_000,
            slash_event_count: 0,
            liveness_penalty_count: 0,
            avg_base_fee: 10,
            validators_joined: vec![indra_core::Bytes32::from([epoch as u8; 32])],
            validators_left: vec![],
            era: 1,
            block_reward_spark: 1_189_200_000,
        }
    }

    #[test]
    fn epoch_store_append_and_get() {
        let path = temp_path("append_get");
        let mut store = EpochStore::open(&path).unwrap();
        for epoch in 0..3 {
            store.append(&record(epoch)).unwrap();
        }
        for epoch in 0..3 {
            assert_eq!(store.get(epoch).unwrap(), record(epoch));
        }
    }

    #[test]
    fn epoch_store_file_header_written_on_new_file() {
        let path = temp_path("header");
        {
            let _store = EpochStore::open(&path).unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.starts_with(EPOCH_MAGIC));
        assert_eq!(bytes.len(), FILE_HEADER_BYTES as usize);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn epoch_store_old_headerless_file_rejected_gracefully() {
        let path = temp_path("legacy_headerless");
        let record = record(0);
        let record_bytes = record.encode_to_vec();
        {
            let mut file = File::create(&path).unwrap();
            file.write_all(&0u64.to_le_bytes()).unwrap();
            file.write_all(&(record_bytes.len() as u32).to_le_bytes())
                .unwrap();
            file.write_all(&record_bytes).unwrap();
            file.flush().unwrap();
        }
        let err = match EpochStore::open(&path) {
            Ok(_) => panic!("expected headerless epoch store to be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("missing INEP header"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn epoch_store_rejects_noncanonical_schema_version() {
        let path = temp_path("schema_mismatch");
        {
            let _store = EpochStore::open(&path).unwrap();
        }
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[5] = SCHEMA_VERSION.saturating_sub(1);
        std::fs::write(&path, bytes).unwrap();
        let err = match EpochStore::open(&path) {
            Ok(_) => panic!("expected schema mismatch rejection"),
            Err(err) => err,
        };
        assert!(err
            .to_string()
            .contains("does not match node schema version"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn epoch_store_get_range_descending() {
        let path = temp_path("range");
        let mut store = EpochStore::open(&path).unwrap();
        for epoch in 0..10 {
            store.append(&record(epoch)).unwrap();
        }
        let epochs: Vec<u64> = store
            .get_range(9, 5)
            .unwrap()
            .into_iter()
            .map(|record| record.epoch)
            .collect();
        assert_eq!(epochs, vec![9, 8, 7, 6, 5]);
    }

    #[test]
    fn read_handle_observes_only_requested_range_and_later_appends() {
        let path = temp_path("read_handle_range");
        let mut store = EpochStore::open(&path).unwrap();
        for epoch in 0..150 {
            store.append(&record(epoch)).unwrap();
        }
        let handle = store.read_handle();
        let page = handle.get_range(149, 3).unwrap();
        assert_eq!(
            page.iter().map(|item| item.epoch).collect::<Vec<_>>(),
            vec![149, 148, 147]
        );
        store.append(&record(150)).unwrap();
        assert_eq!(handle.latest_epoch(), Some(150));
        assert_eq!(handle.get(150).unwrap().epoch, 150);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn epoch_store_get_nonexistent_errors() {
        let path = temp_path("missing");
        let store = EpochStore::open(&path).unwrap();
        assert!(matches!(
            store.get(99),
            Err(StorageError::EpochNotFound { epoch: 99 })
        ));
    }

    #[test]
    fn epoch_store_open_empty() {
        let path = temp_path("empty");
        let store = EpochStore::open(&path).unwrap();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert_eq!(store.latest_epoch(), None);
    }

    #[test]
    fn epoch_store_reopen_rebuilds_index() {
        let path = temp_path("reopen");
        {
            let mut store = EpochStore::open(&path).unwrap();
            for epoch in 0..5 {
                store.append(&record(epoch)).unwrap();
            }
        }
        let store = EpochStore::open(&path).unwrap();
        assert_eq!(store.len(), 5);
        assert_eq!(store.latest_epoch(), Some(4));
        assert_eq!(store.get(4).unwrap(), record(4));
    }

    #[test]
    fn epoch_store_partial_write_recovery() {
        let path = temp_path("partial");
        {
            let mut store = EpochStore::open(&path).unwrap();
            store.append(&record(0)).unwrap();
        }
        {
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            let bytes = record(1).encode_to_vec();
            file.write_all(&1u64.to_le_bytes()).unwrap();
            file.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
            file.write_all(&bytes[..8]).unwrap();
            file.flush().unwrap();
        }
        let store = EpochStore::open(&path).unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.has(0));
        assert!(!store.has(1));
    }

    #[test]
    fn epoch_store_monotonicity_enforced() {
        let path = temp_path("monotonic");
        let mut store = EpochStore::open(&path).unwrap();
        store.append(&record(0)).unwrap();
        assert!(matches!(
            store.append(&record(3)),
            Err(StorageError::NonSequential {
                expected: 1,
                actual: 3
            })
        ));
    }
}
