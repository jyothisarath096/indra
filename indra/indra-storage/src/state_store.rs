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
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use indra_core::codec::{ByteReader, Decode, Encode};
use indra_core::types::primitives::{Bytes32, SCHEMA_VERSION};
use indra_state::{compute_state_roots, ChainState};

static SNAPSHOT_CLEANUP_FAILURES: AtomicU64 = AtomicU64::new(0);

fn report_snapshot_cleanup_failure(path: &Path, error: &std::io::Error) {
    SNAPSHOT_CLEANUP_FAILURES.fetch_add(1, Ordering::Relaxed);
    eprintln!(
        "[storage] WARNING: failed to remove stale snapshot artifact {}: {error}",
        path.display()
    );
}

use crate::atomic::{crc32, write_atomic_synced};
use crate::error::{StorageError, StorageResult};

/// How often to take a state snapshot (in blocks).
pub const SNAPSHOT_INTERVAL: u64 = 300;
const SNAPSHOT_FORMAT_VERSION: u8 = 1;
const SNAPSHOT_META_MAGIC: &[u8; 4] = b"INSM";
const SNAPSHOT_META_VERSION: u8 = 1;

/// Metadata sidecar that binds a snapshot to committed roots and tip hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotMeta {
    /// Snapshot height.
    pub height: u64,
    /// Block hash at this height (`ChainState::tip_hash`).
    pub block_hash: Bytes32,
    /// State root computed from the snapshot.
    pub state_root: Bytes32,
    /// Validator set root computed from the snapshot.
    pub validator_set_root: Bytes32,
    /// Chain identifier stored in the snapshot.
    pub chain_id: String,
    /// CRC32 of the complete `.snap` file bytes.
    pub checksum: u32,
}

/// Manages chain state snapshots on disk.
pub struct StateStore {
    dir: PathBuf,
}

impl StateStore {
    /// Count stale-snapshot cleanup failures observed by this process.
    pub fn cleanup_failure_count() -> u64 {
        SNAPSHOT_CLEANUP_FAILURES.load(Ordering::Relaxed)
    }
    /// Quarantine snapshots newer than the manifest-confirmed snapshot.
    pub fn quarantine_newer_than(&self, confirmed_height: u64) -> StorageResult<()> {
        let quarantine = self.dir.join("quarantine");
        fs::create_dir_all(&quarantine)?;
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let text = name.to_string_lossy();
            let height = text
                .strip_prefix("state_")
                .and_then(|rest| rest.split('.').next())
                .and_then(|value| value.parse::<u64>().ok());
            if height.is_some_and(|height| height > confirmed_height) {
                fs::rename(entry.path(), quarantine.join(name))?;
            }
        }
        crate::atomic::fsync_dir(&self.dir)?;
        Ok(())
    }
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
        let meta_tmp_path = self.dir.join(format!("state_{height}.snap.meta.tmp"));
        let meta_final_path = self.dir.join(format!("state_{height}.snap.meta"));

        let mut snapshot_bytes = Vec::with_capacity(12 + state_bytes.len());
        snapshot_bytes.extend_from_slice(&height.to_le_bytes());
        snapshot_bytes.extend_from_slice(&length.to_le_bytes());
        snapshot_bytes.extend_from_slice(&state_bytes);
        write_atomic_synced(&tmp_path, &final_path, &snapshot_bytes)?;

        let roots = compute_state_roots(state);
        let meta = SnapshotMeta {
            height,
            block_hash: state.tip_hash,
            state_root: roots.state_root,
            validator_set_root: roots.validator_set_root,
            chain_id: state.chain_id.clone(),
            checksum: crc32(&snapshot_bytes),
        };
        write_atomic_synced(&meta_tmp_path, &meta_final_path, &meta.encode())?;

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
                let file_bytes = fs::read(&path)?;
                if file_bytes.len() < 12 {
                    return Err(StorageError::Corruption {
                        height: 0,
                        detail: "snapshot header truncated".into(),
                    });
                }
                let header = &file_bytes[..12];

                let height_bytes: [u8; 8] =
                    header[..8]
                        .try_into()
                        .map_err(|_| StorageError::Corruption {
                            height: 0,
                            detail: "snapshot header truncated while reading height".to_string(),
                        })?;
                let height = u64::from_le_bytes(height_bytes);
                let length_bytes: [u8; 4] =
                    header[8..12]
                        .try_into()
                        .map_err(|_| StorageError::Corruption {
                            height,
                            detail: "snapshot header truncated while reading length".to_string(),
                        })?;
                let length = u32::from_le_bytes(length_bytes) as usize;

                if file_bytes.len() != 12 + length {
                    return Err(StorageError::Corruption {
                        height,
                        detail: format!(
                            "snapshot length mismatch: header says {}, file has {} payload bytes",
                            length,
                            file_bytes.len().saturating_sub(12)
                        ),
                    });
                }

                let state_bytes = &file_bytes[12..];

                let state = deserialise_chain_state(state_bytes, height)
                    .map_err(|e| StorageError::Corruption { height, detail: e })?;
                self.verify_snapshot_meta(&path, &state, crc32(&file_bytes))?;
                Ok(Some(state))
            }
        }
    }

    /// Return the schema version stored in the latest snapshot, if any.
    pub fn schema_version(&self) -> StorageResult<Option<u8>> {
        let Some(path) = self.find_latest_snapshot()? else {
            return Ok(None);
        };
        let mut f = fs::File::open(&path)?;
        let mut header = [0u8; 12];
        f.read_exact(&mut header)?;
        let height =
            u64::from_le_bytes(
                header[..8]
                    .try_into()
                    .map_err(|_| StorageError::Corruption {
                        height: 0,
                        detail: "snapshot header truncated while reading height".to_string(),
                    })?,
            );
        let length =
            u32::from_le_bytes(
                header[8..12]
                    .try_into()
                    .map_err(|_| StorageError::Corruption {
                        height,
                        detail: "snapshot header truncated while reading length".to_string(),
                    })?,
            ) as usize;
        let mut state_bytes = vec![0u8; length.min(2)];
        f.read_exact(&mut state_bytes)?;
        match state_bytes.as_slice() {
            [SNAPSHOT_FORMAT_VERSION, schema_version] if *schema_version == SCHEMA_VERSION => {
                Ok(Some(*schema_version))
            }
            [format_version, _] if *format_version != SNAPSHOT_FORMAT_VERSION => {
                Err(StorageError::Corruption {
                    height,
                    detail: format!("unsupported snapshot format version {format_version}"),
                })
            }
            [_, schema_version] => Err(StorageError::Corruption {
                height,
                detail: format!(
                    "snapshot schema version {schema_version} does not match node schema version {SCHEMA_VERSION}"
                ),
            }),
            _ => Err(StorageError::Corruption {
                height,
                detail: "snapshot payload missing format/schema discriminator".to_string(),
            }),
        }
    }

    /// Height of the newest snapshot, if any.
    pub fn latest_snapshot_height(&self) -> StorageResult<Option<u64>> {
        Ok(self.find_latest_snapshot()?.and_then(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| {
                    name.trim_start_matches("state_")
                        .trim_end_matches(".snap")
                        .parse::<u64>()
                        .ok()
                })
        }))
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
                        for path in [
                            entry.path(),
                            self.dir.join(format!("state_{h}.snap.meta")),
                            self.dir.join(format!("state_{h}.snap.meta.tmp")),
                        ] {
                            if let Err(error) = fs::remove_file(&path) {
                                if error.kind() != std::io::ErrorKind::NotFound {
                                    report_snapshot_cleanup_failure(&path, &error);
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn verify_snapshot_meta(
        &self,
        snapshot_path: &Path,
        state: &ChainState,
        checksum: u32,
    ) -> StorageResult<()> {
        let meta_path = snapshot_path.with_extension("snap.meta");
        let meta_bytes = fs::read(&meta_path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                StorageError::Corruption {
                    height: state.height,
                    detail: format!(
                        "snapshot metadata sidecar is missing for {}",
                        snapshot_path.display()
                    ),
                }
            } else {
                err.into()
            }
        })?;
        let meta =
            SnapshotMeta::decode(&meta_bytes).map_err(|detail| StorageError::Corruption {
                height: state.height,
                detail,
            })?;
        if meta.height != state.height {
            return Err(StorageError::SnapshotRootMismatch {
                height: state.height,
                detail: format!("metadata height {} does not match snapshot", meta.height),
            });
        }
        if meta.chain_id != state.chain_id {
            return Err(StorageError::SnapshotRootMismatch {
                height: state.height,
                detail: "chain_id mismatch".into(),
            });
        }
        if meta.checksum != checksum {
            return Err(StorageError::SnapshotRootMismatch {
                height: state.height,
                detail: format!(
                    "snapshot checksum mismatch: meta {}, actual {}",
                    meta.checksum, checksum
                ),
            });
        }
        let roots = compute_state_roots(state);
        if meta.state_root != roots.state_root {
            return Err(StorageError::SnapshotRootMismatch {
                height: state.height,
                detail: format!(
                    "state root meta {} actual {}",
                    hex_bytes(&meta.state_root.0),
                    hex_bytes(&roots.state_root.0)
                ),
            });
        }
        if meta.validator_set_root != roots.validator_set_root {
            return Err(StorageError::SnapshotRootMismatch {
                height: state.height,
                detail: format!(
                    "validator root meta {} actual {}",
                    hex_bytes(&meta.validator_set_root.0),
                    hex_bytes(&roots.validator_set_root.0)
                ),
            });
        }
        if meta.block_hash != state.tip_hash {
            return Err(StorageError::SnapshotTipMismatch {
                height: state.height,
                detail: format!(
                    "tip hash meta {} actual {}",
                    hex_bytes(&meta.block_hash.0),
                    hex_bytes(&state.tip_hash.0)
                ),
            });
        }
        Ok(())
    }
}

impl SnapshotMeta {
    fn encode(&self) -> Vec<u8> {
        let chain_bytes = self.chain_id.as_bytes();
        let mut buf = Vec::with_capacity(4 + 1 + 8 + 32 * 3 + 2 + chain_bytes.len() + 4);
        buf.extend_from_slice(SNAPSHOT_META_MAGIC);
        buf.push(SNAPSHOT_META_VERSION);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.block_hash.0);
        buf.extend_from_slice(&self.state_root.0);
        buf.extend_from_slice(&self.validator_set_root.0);
        buf.extend_from_slice(&(chain_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(chain_bytes);
        buf.extend_from_slice(&self.checksum.to_le_bytes());
        buf
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        let min = 4 + 1 + 8 + 32 * 3 + 2 + 4;
        if bytes.len() < min {
            return Err("snapshot metadata truncated".into());
        }
        if &bytes[0..4] != SNAPSHOT_META_MAGIC {
            return Err("snapshot metadata magic mismatch".into());
        }
        if bytes[4] != SNAPSHOT_META_VERSION {
            return Err(format!(
                "unsupported snapshot metadata version {}",
                bytes[4]
            ));
        }
        let height = u64::from_le_bytes(copy_8(&bytes[5..13])?);
        let block_hash = Bytes32::from(copy_32(&bytes[13..45])?);
        let state_root = Bytes32::from(copy_32(&bytes[45..77])?);
        let validator_set_root = Bytes32::from(copy_32(&bytes[77..109])?);
        let chain_len = u16::from_le_bytes(copy_2(&bytes[109..111])?) as usize;
        let chain_start = 111;
        let chain_end = chain_start + chain_len;
        if bytes.len() != chain_end + 4 {
            return Err("snapshot metadata length mismatch".into());
        }
        let chain_id = std::str::from_utf8(&bytes[chain_start..chain_end])
            .map_err(|e| e.to_string())?
            .to_string();
        let checksum = u32::from_le_bytes(copy_4(&bytes[chain_end..chain_end + 4])?);
        Ok(Self {
            height,
            block_hash,
            state_root,
            validator_set_root,
            chain_id,
            checksum,
        })
    }
}

fn copy_2(bytes: &[u8]) -> Result<[u8; 2], String> {
    bytes.try_into().map_err(|_| "failed to copy u16".into())
}

fn copy_4(bytes: &[u8]) -> Result<[u8; 4], String> {
    bytes.try_into().map_err(|_| "failed to copy u32".into())
}

fn copy_8(bytes: &[u8]) -> Result<[u8; 8], String> {
    bytes.try_into().map_err(|_| "failed to copy u64".into())
}

fn copy_32(bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| "failed to copy Bytes32".into())
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Serialise a complete chain state snapshot.
///
/// Payload format:
/// - canonical snapshot format discriminator
/// - current schema version byte
/// - canonical `ChainState` encoding
fn serialise_chain_state(state: &ChainState) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + state.encoded_len());
    buf.push(SNAPSHOT_FORMAT_VERSION);
    buf.push(SCHEMA_VERSION);
    state.encode(&mut buf);
    buf
}

/// Deserialise a chain state snapshot.
///
fn deserialise_chain_state(bytes: &[u8], file_height: u64) -> Result<ChainState, String> {
    let Some((&format_version, payload)) = bytes.split_first() else {
        return Err("snapshot payload is empty".to_string());
    };
    if format_version != SNAPSHOT_FORMAT_VERSION {
        return Err(format!(
            "unsupported snapshot format version {format_version}"
        ));
    }
    let Some((&schema_version, payload)) = payload.split_first() else {
        return Err("snapshot missing schema version".to_string());
    };
    if schema_version != SCHEMA_VERSION {
        return Err(format!(
            "snapshot schema version {schema_version} does not match node schema version {SCHEMA_VERSION}"
        ));
    }
    let mut reader = ByteReader::new(payload);
    let state = ChainState::decode(&mut reader).map_err(|e| e.to_string())?;
    if reader.remaining() != 0 {
        return Err(format!(
            "snapshot at height {} has {} trailing bytes",
            file_height,
            reader.remaining()
        ));
    }
    validate_snapshot_state(state, file_height)
}

fn validate_snapshot_state(mut state: ChainState, file_height: u64) -> Result<ChainState, String> {
    if state.height != file_height {
        return Err(format!(
            "snapshot height mismatch: file says {}, payload says {}",
            file_height, state.height
        ));
    }
    state.rebuild_state_commitment_v2(state.height);
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_failure_is_counted_and_not_silent() {
        let before = StateStore::cleanup_failure_count();
        report_snapshot_cleanup_failure(
            Path::new("injected-stale-snapshot"),
            &std::io::Error::other("injected deletion failure"),
        );
        assert_eq!(StateStore::cleanup_failure_count(), before + 1);
    }
    use indra_core::{
        types::block::{BlockHeaderVNext, BlockVNext},
        types::primitives::DUST_LIMIT_SPARK,
        Bytes32, ProtocolVersion, VariableBytes,
    };
    use indra_state::{
        apply_block_for_test as apply_block, compute_state_root, compute_validator_set_root,
        ValidatorEntry, ValidatorStatus,
    };
    use std::io::Write;

    fn temp_dir(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "indra_state_test_{}_{}",
            suffix,
            std::process::id()
        ));
        p
    }

    fn write_snapshot(dir: &Path, height: u64, payload: &[u8]) {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(format!("state_{height}.snap"));
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(&height.to_le_bytes()).unwrap();
        file.write_all(&(payload.len() as u32).to_le_bytes())
            .unwrap();
        file.write_all(payload).unwrap();
        file.flush().unwrap();
    }

    fn test_validator() -> ValidatorEntry {
        let classical = indra_crypto::ClassicalKeypair::from_seed(&[0x41; 32]);
        let pq = indra_crypto::PqKeypair::from_seed(&[0x42; 32]).unwrap();
        let public = indra_crypto::HybridKeypair::new(classical, pq).public_key();
        ValidatorEntry {
            validator_id: Bytes32::from([0x41; 32]),
            name: "validator-one".to_string(),
            hybrid_classical_pk: Some(public.classical.0),
            hybrid_pq_pk: Some(public.pq.0.to_vec()),
            vrf_pk: Some(indra_crypto::VrfKeypair::from_seed(&[0x43; 32]).public_key()),
            vrf_key_activation_epoch: 0,
            pending_vrf_pk: None,
            pending_vrf_activation_epoch: None,
            stake_spark: 1_000_000,
            status: ValidatorStatus::Active,
            registered_epoch: 7,
            last_active_epoch: 7,
            slashed_offense_id: Some(Bytes32::from([1; 32])),
            commission_bps: 900,
            pending_commission_bps: None,
            pending_commission_effective_epoch: None,
            min_delegation_spark: DUST_LIMIT_SPARK,
            auto_delegate_to: None,
            network_addr: None,
            network_addr_last_updated_epoch: None,
            cold_hybrid_classical_pk: Some(public.classical.0),
            cold_hybrid_pq_pk: Some(public.pq.0),
            cold_key_version: 1,
            cold_nonce: 0,
        }
    }

    fn finalized_test_state() -> ChainState {
        let mut state = ChainState::new_genesis();
        state.active_slot_coefficient_numerator =
            indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR;
        state.validators.upsert(test_validator()).unwrap();
        state.finalize_genesis().unwrap();
        state
    }

    fn move_genesis_principal_to_fee_pool(state: &mut ChainState, amount: u64) {
        let validator_id = state
            .validators
            .active_validators()
            .next()
            .unwrap()
            .validator_id;
        let mut position = state
            .stake_positions
            .values()
            .find(|position| position.validator_id == validator_id)
            .unwrap()
            .clone();
        let active = position.active.as_mut().unwrap();
        active.principal_spark = active.principal_spark.checked_sub(amount).unwrap();
        state.stake_positions.insert(position.position_id, position);
        state.validators.get_mut(&validator_id).unwrap().stake_spark = state
            .validators
            .get(&validator_id)
            .unwrap()
            .stake_spark
            .checked_sub(amount)
            .unwrap();
        state.fee_reward_pool = amount;
        state.monetary_aggregates = state.recompute_monetary_aggregates().unwrap();
    }

    #[test]
    fn save_and_load() {
        let dir = temp_dir("a");
        let store = StateStore::open(&dir).unwrap();

        let mut state = finalized_test_state();
        state.height = 42;
        state.base_fee = 500;
        move_genesis_principal_to_fee_pool(&mut state, 777);
        state.rebuild_state_commitment_v2(state.height);

        store.save(&state).unwrap();

        let loaded = store.load_latest().unwrap().unwrap();
        assert_eq!(loaded, state);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn canonical_snapshot_round_trips() {
        let dir = temp_dir("v3_round_trip");
        let store = StateStore::open(&dir).unwrap();
        let mut state = finalized_test_state();
        state.height = 123;
        move_genesis_principal_to_fee_pool(&mut state, 456);
        state.rebuild_state_commitment_v2(state.height);
        store.save(&state).unwrap();
        assert_eq!(store.schema_version().unwrap(), Some(SCHEMA_VERSION));
        let loaded = store.load_latest().unwrap().unwrap();
        assert_eq!(loaded, state);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_sidecar_verification_succeeds_for_canonical_snapshot() {
        let dir = temp_dir("canonical_sidecar");
        let store = StateStore::open(&dir).unwrap();
        let mut state = finalized_test_state();
        state.height = 0;
        state.tip_hash = Bytes32::from([0x99; 32]);

        store.save(&state).unwrap();

        assert_eq!(store.schema_version().unwrap(), Some(SCHEMA_VERSION));
        let loaded = store.load_latest().unwrap().unwrap();
        assert_eq!(loaded.height, state.height);
        assert_eq!(compute_state_root(&loaded), compute_state_root(&state));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_with_wrong_state_root_is_rejected() {
        let dir = temp_dir("bad_meta_state_root");
        let store = StateStore::open(&dir).unwrap();
        let mut state = finalized_test_state();
        state.height = 7;
        store.save(&state).unwrap();

        let meta_path = dir.join("state_7.snap.meta");
        let mut meta = std::fs::read(&meta_path).unwrap();
        meta[45] ^= 0x01; // first byte of state_root in sidecar
        std::fs::write(&meta_path, meta).unwrap();

        assert!(matches!(
            store.load_latest(),
            Err(StorageError::SnapshotRootMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_with_wrong_tip_hash_is_rejected() {
        let dir = temp_dir("bad_meta_tip_hash");
        let store = StateStore::open(&dir).unwrap();
        let mut state = finalized_test_state();
        state.height = 8;
        state.tip_hash = Bytes32::from([0xAB; 32]);
        store.save(&state).unwrap();

        let meta_path = dir.join("state_8.snap.meta");
        let mut meta = std::fs::read(&meta_path).unwrap();
        meta[13] ^= 0x01; // first byte of block_hash in sidecar
        std::fs::write(&meta_path, meta).unwrap();

        assert!(matches!(
            store.load_latest(),
            Err(StorageError::SnapshotTipMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_with_future_schema_version_rejected() {
        let dir = temp_dir("future_schema");
        let store = StateStore::open(&dir).unwrap();
        let mut state = ChainState::new_genesis();
        state.height = 7;
        let mut payload = Vec::new();
        payload.push(SNAPSHOT_FORMAT_VERSION);
        payload.push(255);
        state.encode(&mut payload);
        write_snapshot(&dir, state.height, &payload);

        let err = store.load_latest().unwrap_err();
        assert!(err
            .to_string()
            .contains("does not match node schema version"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_without_metadata_sidecar_is_rejected() {
        let dir = temp_dir("missing_sidecar");
        let store = StateStore::open(&dir).unwrap();
        let state = finalized_test_state();
        store.save(&state).unwrap();
        std::fs::remove_file(dir.join("state_0.snap.meta")).unwrap();

        let err = store.load_latest().unwrap_err();
        assert!(err.to_string().contains("metadata sidecar is missing"));
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
    fn crash_during_snapshot_temp_write_never_publishes_partial_snapshot() {
        let dir = temp_dir("partial_snapshot_tmp");
        let store = StateStore::open(&dir).unwrap();
        let state = finalized_test_state();
        store.save(&state).unwrap();
        std::fs::write(dir.join("state_300.tmp"), [0xAA; 19]).unwrap();
        std::fs::write(dir.join("state_300.snap.meta.tmp"), [0xBB; 11]).unwrap();
        assert_eq!(store.load_latest().unwrap(), Some(state));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn latest_snapshot_selected() {
        let dir = temp_dir("c");
        let store = StateStore::open(&dir).unwrap();

        let mut s1 = finalized_test_state();
        s1.height = 10;
        let mut s2 = finalized_test_state();
        s2.height = 20;

        store.save(&s1).unwrap();
        store.save(&s2).unwrap();

        let loaded = store.load_latest().unwrap().unwrap();
        assert_eq!(loaded.height, 20);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn make_block(state: &ChainState) -> BlockVNext {
        let quorum_certificate = if state.height == 0 {
            VariableBytes::from_slice(&[]).unwrap()
        } else {
            let keypair = indra_crypto::HybridKeypair::new(
                indra_crypto::ClassicalKeypair::from_seed(&[0x41; 32]),
                indra_crypto::PqKeypair::from_seed(&[0x42; 32]).unwrap(),
            );
            let snapshot = state.snapshot_for_consensus_height(state.height).unwrap();
            let entry = &snapshot.entries()[0];
            let bytes = indra_core::types::vote_signing::vote_signing_bytes(
                state.height,
                0,
                indra_core::types::vote::VoteStep::Precommit,
                &state.tip_hash,
                &entry.validator_id,
                &snapshot.snapshot_root,
                &state.chain_id,
            );
            let signature = keypair.sign(&bytes).unwrap();
            let qc = indra_core::types::qc::QuorumCertificateV1 {
                height: state.height,
                round: 0,
                block_hash: state.tip_hash,
                snapshot_root: snapshot.snapshot_root,
                signer_bitfield: {
                    let mut bits = [0u8; indra_core::types::qc::SIGNER_BITFIELD_BYTES];
                    bits[0] = 1;
                    bits
                },
                pq_signatures: vec![indra_core::types::crypto::PQVoteSig {
                    validator_id: entry.validator_id,
                    pq_sig: VariableBytes::from_slice(&signature.pq.0).unwrap(),
                }],
                classical_signatures: vec![indra_core::types::qc::ClassicalVoteSig {
                    validator_id: entry.validator_id,
                    classical_sig: VariableBytes::from_slice(&signature.classical.0).unwrap(),
                }],
            };
            VariableBytes::from_slice(&qc.encode_to_vec()).unwrap()
        };
        let mut block = BlockVNext {
            header: BlockHeaderVNext {
                protocol_version: ProtocolVersion::CURRENT,
                height: state.height + 1,
                prev_hash: state.tip_hash,
                timestamp: 1_700_000_000 + state.height + 1,
                state_root: Bytes32::ZERO,
                validator_set_root: Bytes32::ZERO,
                mempool_set_root: Bytes32::ZERO,
                value_hash: Bytes32::ZERO,
                base_fee: state.base_fee,
                proposer_round: 0,
                polc_round: None,
                proposer_id: Bytes32::from([0x84; 32]),
                vrf_suite: indra_core::types::block::VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
                election_seed: state.election_seed,
                proposer_vrf_output: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                proposer_vrf_proof: VariableBytes::from_slice(&[0u8; 80]).unwrap(),
                value_entropy: indra_core::types::block::ProposalEntropyV1 {
                    origin_proposer_id: Bytes32::from([0x84; 32]),
                    origin_round: 0,
                    vrf_output: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                    vrf_proof: VariableBytes::from_slice(&[0u8; 80]).unwrap(),
                },
                sortition_claim: indra_core::types::block::SortitionClaimV1::PraosThreshold,
                proposer_priority: indra_core::types::primitives::Bytes64([0; 64]),
                quorum_certificate,
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        };

        let mut projected = state.clone();
        apply_block(&mut projected, &block, 0).unwrap();
        let roots = compute_state_roots(&projected);
        block.header.state_root = roots.state_root;
        block.header.validator_set_root = roots.validator_set_root;
        block.header.value_hash = block.compute_value_hash(projected.total_supply);
        block
    }

    #[test]
    fn snapshot_round_trip_preserves_next_state_root() {
        let dir = temp_dir("next_state_root");
        let store = StateStore::open(&dir).unwrap();

        let mut original = finalized_test_state();
        for _ in 1u8..=12u8 {
            let block = make_block(&original);
            apply_block(&mut original, &block, 0).unwrap();
        }

        store.save(&original).unwrap();
        let decoded = store.load_latest().unwrap().unwrap();

        assert_eq!(decoded, original);
        assert_eq!(compute_state_root(&decoded), compute_state_root(&original));
        assert_eq!(
            decoded.utxos.root_at_height(decoded.height),
            original.utxos.root_at_height(original.height)
        );
        assert_eq!(
            compute_validator_set_root(&decoded),
            compute_validator_set_root(&original)
        );

        let next_block = make_block(&original);
        let mut original_next = original.clone();
        let mut decoded_next = decoded.clone();
        apply_block(&mut original_next, &next_block, 0).unwrap();
        apply_block(&mut decoded_next, &next_block, 0).unwrap();

        assert_eq!(original_next, decoded_next);
        assert_eq!(
            compute_state_root(&original_next),
            compute_state_root(&decoded_next)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_snapshot_format_is_rejected() {
        let dir = temp_dir("old_v1");
        let store = StateStore::open(&dir).unwrap();
        let path = dir.join("state_300.snap");

        let mut payload = Vec::with_capacity(72);
        payload.extend_from_slice(&300u64.to_le_bytes());
        payload.extend_from_slice(&500u64.to_le_bytes());
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&1_000u64.to_le_bytes());
        payload.extend_from_slice(&200u64.to_le_bytes());
        payload.extend_from_slice(&300u64.to_le_bytes());

        let mut file = fs::File::create(&path).unwrap();
        file.write_all(&300u64.to_le_bytes()).unwrap();
        file.write_all(&(payload.len() as u32).to_le_bytes())
            .unwrap();
        file.write_all(&payload).unwrap();
        file.flush().unwrap();
        drop(file);

        let err = store.load_latest().unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported snapshot format version"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
