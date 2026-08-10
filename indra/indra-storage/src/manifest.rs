//! Durable chain commit manifest.

use std::path::{Path, PathBuf};

use indra_core::types::primitives::Bytes32;

use crate::{
    atomic::write_atomic_synced,
    error::{StorageError, StorageResult},
};

const MANIFEST_FILE: &str = "chain_manifest.bin";
const MANIFEST_TMP_FILE: &str = "chain_manifest.bin.tmp";
const MANIFEST_MAGIC: &[u8; 4] = b"INMF";
const MANIFEST_VERSION: u8 = 2;

/// Last fully durable chain commit observed by the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainManifest {
    /// Last committed height.
    pub committed_height: u64,
    /// Last committed block hash.
    pub committed_block_hash: Bytes32,
    /// State root at committed height.
    pub state_root: Bytes32,
    /// Latest snapshot height known at commit time.
    pub snapshot_height: u64,
    /// Block log next height after commit.
    pub block_log_next_height: u64,
    /// Height of persisted last QC, or 0 when absent.
    pub last_qc_height: u64,
    /// Latest epoch record, if any.
    pub epoch_log_latest_epoch: Option<u64>,
    /// Chain identifier.
    pub chain_id: String,
}

/// Save the manifest under the node data directory.
pub fn save_chain_manifest(data_dir: &Path, manifest: &ChainManifest) -> StorageResult<()> {
    let tmp = manifest_tmp_path(data_dir);
    let final_path = manifest_path(data_dir);
    write_atomic_synced(&tmp, &final_path, &manifest.encode())
}

/// Load the manifest, returning `None` only when the file does not exist.
pub fn load_chain_manifest(data_dir: &Path) -> StorageResult<Option<ChainManifest>> {
    let path = manifest_path(data_dir);
    match std::fs::read(&path) {
        Ok(bytes) => ChainManifest::decode(&bytes)
            .map(Some)
            .map_err(|detail| StorageError::ManifestMismatch { detail }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if store_has_committed_data(data_dir)? {
                Err(StorageError::ManifestMismatch {
                    detail: "nonempty store is missing chain manifest".to_string(),
                })
            } else {
                Ok(None)
            }
        }
        Err(err) => Err(err.into()),
    }
}

fn store_has_committed_data(data_dir: &Path) -> StorageResult<bool> {
    if data_dir.join("blocks.log").exists() {
        return Err(StorageError::LegacyBlockStore {
            path: data_dir.join("blocks.log"),
            data_dir: data_dir.to_path_buf(),
        });
    }
    match std::fs::read_dir(data_dir.join("block_segments")) {
        Ok(entries) => {
            if entries.count() > 0 {
                return Ok(true);
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    for (name, empty_header_len) in [("epochs.log", 16)] {
        let path = data_dir.join(name);
        match std::fs::metadata(path) {
            Ok(metadata) if metadata.len() > empty_header_len => return Ok(true),
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }

    let state_dir = data_dir.join("state");
    match std::fs::read_dir(state_dir) {
        Ok(entries) => {
            for entry in entries {
                let name = entry?.file_name();
                let name = name.to_string_lossy();
                if name.ends_with(".snap") || name == "last_qc.bin" || name == "pending_last_qc.bin"
                {
                    return Ok(true);
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    Ok(false)
}

fn manifest_path(data_dir: &Path) -> PathBuf {
    data_dir.join(MANIFEST_FILE)
}

fn manifest_tmp_path(data_dir: &Path) -> PathBuf {
    data_dir.join(MANIFEST_TMP_FILE)
}

impl ChainManifest {
    fn encode(&self) -> Vec<u8> {
        let chain_bytes = self.chain_id.as_bytes();
        let mut buf = Vec::with_capacity(4 + 1 + 8 * 4 + 32 * 2 + 1 + 8 + 2 + chain_bytes.len());
        buf.extend_from_slice(MANIFEST_MAGIC);
        buf.push(MANIFEST_VERSION);
        buf.extend_from_slice(&self.committed_height.to_le_bytes());
        buf.extend_from_slice(&self.committed_block_hash.0);
        buf.extend_from_slice(&self.state_root.0);
        buf.extend_from_slice(&self.snapshot_height.to_le_bytes());
        buf.extend_from_slice(&self.block_log_next_height.to_le_bytes());
        buf.extend_from_slice(&self.last_qc_height.to_le_bytes());
        match self.epoch_log_latest_epoch {
            Some(epoch) => {
                buf.push(1);
                buf.extend_from_slice(&epoch.to_le_bytes());
            }
            None => {
                buf.push(0);
                buf.extend_from_slice(&0u64.to_le_bytes());
            }
        }
        buf.extend_from_slice(&(chain_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(chain_bytes);
        buf
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        let min = 4 + 1 + 8 + 32 + 32 + 8 + 8 + 8 + 1 + 8 + 2;
        if bytes.len() < min {
            return Err("manifest truncated".into());
        }
        if &bytes[0..4] != MANIFEST_MAGIC {
            return Err("manifest magic mismatch".into());
        }
        if bytes[4] != MANIFEST_VERSION {
            return Err(format!("unsupported manifest version {}", bytes[4]));
        }
        let committed_height = u64::from_le_bytes(copy_8(&bytes[5..13])?);
        let committed_block_hash = Bytes32::from(copy_32(&bytes[13..45])?);
        let state_root = Bytes32::from(copy_32(&bytes[45..77])?);
        let snapshot_height = u64::from_le_bytes(copy_8(&bytes[77..85])?);
        let block_log_next_height = u64::from_le_bytes(copy_8(&bytes[85..93])?);
        let last_qc_height = u64::from_le_bytes(copy_8(&bytes[93..101])?);
        let epoch_log_latest_epoch = match bytes[101] {
            0 => None,
            1 => Some(u64::from_le_bytes(copy_8(&bytes[102..110])?)),
            other => return Err(format!("invalid epoch-present flag {other}")),
        };
        let chain_len = u16::from_le_bytes(copy_2(&bytes[110..112])?) as usize;
        if bytes.len() != 112 + chain_len {
            return Err("manifest length mismatch".into());
        }
        let chain_id = std::str::from_utf8(&bytes[112..])
            .map_err(|e| e.to_string())?
            .to_string();
        Ok(Self {
            committed_height,
            committed_block_hash,
            state_root,
            snapshot_height,
            block_log_next_height,
            last_qc_height,
            epoch_log_latest_epoch,
            chain_id,
        })
    }
}

fn copy_2(bytes: &[u8]) -> Result<[u8; 2], String> {
    bytes.try_into().map_err(|_| "failed to copy u16".into())
}

fn copy_8(bytes: &[u8]) -> Result<[u8; 8], String> {
    bytes.try_into().map_err(|_| "failed to copy u64".into())
}

fn copy_32(bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| "failed to copy Bytes32".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_round_trips() {
        let manifest = ChainManifest {
            committed_height: 9,
            committed_block_hash: Bytes32::from([1u8; 32]),
            state_root: Bytes32::from([2u8; 32]),
            snapshot_height: 6,
            block_log_next_height: 10,
            last_qc_height: 9,
            epoch_log_latest_epoch: Some(0),
            chain_id: "indra-testnet-1".into(),
        };
        assert_eq!(ChainManifest::decode(&manifest.encode()).unwrap(), manifest);
    }

    #[test]
    fn missing_manifest_is_allowed_only_for_pristine_store() {
        let dir =
            std::env::temp_dir().join(format!("indra_manifest_pristine_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("state")).unwrap();
        std::fs::create_dir_all(dir.join("block_segments")).unwrap();
        std::fs::write(dir.join("epochs.log"), [0u8; 16]).unwrap();
        assert!(load_chain_manifest(&dir).unwrap().is_none());

        std::fs::write(dir.join("state").join("last_qc.bin"), [1u8]).unwrap();
        let err = load_chain_manifest(&dir).unwrap_err();
        assert!(err
            .to_string()
            .contains("nonempty store is missing chain manifest"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn crash_before_manifest_rename_never_publishes_partial_generation() {
        let dir = std::env::temp_dir().join(format!(
            "indra_manifest_crash_before_rename_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("block_segments")).unwrap();
        let confirmed = ChainManifest {
            committed_height: 9,
            committed_block_hash: Bytes32::from([1u8; 32]),
            state_root: Bytes32::from([2u8; 32]),
            snapshot_height: 0,
            block_log_next_height: 10,
            last_qc_height: 9,
            epoch_log_latest_epoch: None,
            chain_id: "indra-testnet-1".into(),
        };
        save_chain_manifest(&dir, &confirmed).unwrap();
        // Model a process killed after creating/truncating the temporary next
        // manifest but before atomic rename of the durable commit marker.
        std::fs::write(dir.join(MANIFEST_TMP_FILE), &confirmed.encode()[..17]).unwrap();
        assert_eq!(load_chain_manifest(&dir).unwrap(), Some(confirmed));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
