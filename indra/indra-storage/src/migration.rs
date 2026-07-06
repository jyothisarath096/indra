//! State schema migrations and migration audit log.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use indra_core::types::primitives::SCHEMA_VERSION;
use indra_state::ChainState;

use crate::error::{StorageError, StorageResult};

/// One migration audit entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationRecord {
    /// Unix timestamp in seconds when the migration ran.
    pub timestamp_secs: u64,
    /// Schema version migrated from.
    pub from_version: u8,
    /// Schema version migrated to.
    pub to_version: u8,
    /// State height at the time of migration.
    pub state_height: u64,
    /// Number of validators present in the migrated state.
    pub validators_migrated: u32,
    /// Number of UTXOs present in the migrated state.
    pub utxos_migrated: u32,
}

/// Append-only migration audit log.
pub struct MigrationLog {
    path: PathBuf,
}

impl MigrationLog {
    /// Open a migration log at the supplied path.
    pub fn open(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Append one migration record.
    pub fn append(&self, record: &MigrationRecord) -> StorageResult<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&record.timestamp_secs.to_le_bytes())?;
        file.write_all(&[record.from_version, record.to_version])?;
        file.write_all(&record.state_height.to_le_bytes())?;
        file.write_all(&record.validators_migrated.to_le_bytes())?;
        file.write_all(&record.utxos_migrated.to_le_bytes())?;
        file.flush()?;
        Ok(())
    }

    /// Load all migration records.
    pub fn load_all(&self) -> StorageResult<Vec<MigrationRecord>> {
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(StorageError::Io(e)),
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        const RECORD_BYTES: usize = 26;
        if bytes.len() % RECORD_BYTES != 0 {
            return Err(StorageError::Corruption {
                height: 0,
                detail: "migration log has trailing partial record".to_string(),
            });
        }
        let mut records = Vec::with_capacity(bytes.len() / RECORD_BYTES);
        for chunk in bytes.chunks_exact(RECORD_BYTES) {
            let timestamp_secs = u64::from_le_bytes(copy_8(&chunk[0..8])?);
            let from_version = chunk[8];
            let to_version = chunk[9];
            let state_height = u64::from_le_bytes(copy_8(&chunk[10..18])?);
            let validators_migrated = u32::from_le_bytes(copy_4(&chunk[18..22])?);
            let utxos_migrated = u32::from_le_bytes(copy_4(&chunk[22..26])?);
            records.push(MigrationRecord {
                timestamp_secs,
                from_version,
                to_version,
                state_height,
                validators_migrated,
                utxos_migrated,
            });
        }
        Ok(records)
    }
}

/// Run schema migrations on a ChainState loaded from an older snapshot.
pub fn migrate_chain_state(mut state: ChainState, from_version: u8) -> Result<ChainState, String> {
    let mut version = from_version;
    while version < SCHEMA_VERSION {
        eprintln!(
            "[migration] migrating chain state from schema v{} to v{}",
            version,
            version.saturating_add(1)
        );
        state = match version {
            1 => migrate_v1_to_v2(state)?,
            2 => migrate_v2_to_v3(state)?,
            3 => migrate_v3_to_v4(state)?,
            other => return Err(format!("no migration path from schema version {other}")),
        };
        version = version.saturating_add(1);
    }
    eprintln!("[migration] migration complete — now at schema v{version}");
    Ok(state)
}

/// Build an audit record for a completed migration.
pub fn migration_record(state: &ChainState, from_version: u8, to_version: u8) -> MigrationRecord {
    MigrationRecord {
        timestamp_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        from_version,
        to_version,
        state_height: state.height,
        validators_migrated: state.validators.len() as u32,
        utxos_migrated: state.utxos.len() as u32,
    }
}

fn migrate_v1_to_v2(state: ChainState) -> Result<ChainState, String> {
    Ok(state)
}

fn migrate_v2_to_v3(state: ChainState) -> Result<ChainState, String> {
    Ok(state)
}

fn migrate_v3_to_v4(state: ChainState) -> Result<ChainState, String> {
    // v4 adds optional validator network-address fields. Existing v3
    // validators decode with `None` defaults, so no data rewrite is required.
    Ok(state)
}

fn copy_8(bytes: &[u8]) -> StorageResult<[u8; 8]> {
    bytes.try_into().map_err(|_| StorageError::Corruption {
        height: 0,
        detail: "failed to decode migration u64".to_string(),
    })
}

fn copy_4(bytes: &[u8]) -> StorageResult<[u8; 4]> {
    bytes.try_into().map_err(|_| StorageError::Corruption {
        height: 0,
        detail: "failed to decode migration u32".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("indra_migration_{name}_{}", std::process::id()))
    }

    #[test]
    fn migrate_v1_to_v2_preserves_all_fields() {
        let mut state = ChainState::new_genesis();
        state.height = 42;
        state.treasury_balance = 77;
        let migrated = migrate_chain_state(state.clone(), 1).unwrap();
        assert_eq!(migrated, state);
    }

    #[test]
    fn migration_log_append_and_load() {
        let path = temp_path("log");
        let _ = std::fs::remove_file(&path);
        let log = MigrationLog::open(&path);
        for i in 0..3u64 {
            log.append(&MigrationRecord {
                timestamp_secs: 100 + i,
                from_version: 1,
                to_version: 2,
                state_height: i,
                validators_migrated: 4,
                utxos_migrated: 5,
            })
            .unwrap();
        }
        let loaded = log.load_all().unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[2].state_height, 2);
        let _ = std::fs::remove_file(&path);
    }
}
