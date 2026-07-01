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

use indra_core::codec::{ByteReader, Decode, Encode};
use indra_core::types::primitives::{SCHEMA_VERSION, SCHEMA_VERSION_GENESIS};
use indra_state::ChainState;

use crate::error::{StorageError, StorageResult};
use crate::migration::migrate_chain_state;

/// How often to take a state snapshot (in blocks).
pub const SNAPSHOT_INTERVAL: u64 = 300;
const SNAPSHOT_VERSION_V1_SUMMARY: u8 = 0x01;
const SNAPSHOT_VERSION_V2_COMPLETE: u8 = 0x02;
const SNAPSHOT_VERSION_V3_VERSIONED: u8 = 0x03;

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

                let mut state_bytes = vec![0u8; length];
                f.read_exact(&mut state_bytes)?;

                deserialise_chain_state(&state_bytes, height)
                    .map_err(|e| StorageError::Corruption { height, detail: e })
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
            [SNAPSHOT_VERSION_V3_VERSIONED, schema_version] => Ok(Some(*schema_version)),
            [SNAPSHOT_VERSION_V2_COMPLETE, ..] => Ok(Some(SCHEMA_VERSION_GENESIS)),
            [SNAPSHOT_VERSION_V1_SUMMARY, ..] => Ok(Some(SCHEMA_VERSION_GENESIS)),
            _ => Ok(None),
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

/// Serialise a complete chain state snapshot.
///
/// Payload format:
/// - `0x03` version discriminator for the schema-versioned complete-state format
/// - current schema version byte
/// - canonical `ChainState` encoding
fn serialise_chain_state(state: &ChainState) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + state.encoded_len());
    buf.push(SNAPSHOT_VERSION_V3_VERSIONED);
    buf.push(SCHEMA_VERSION);
    state.encode(&mut buf);
    buf
}

/// Deserialise a chain state snapshot.
///
/// Returns `Ok(None)` for legacy/incomplete snapshot payloads so startup can
/// gracefully fall back to full replay when possible.
fn deserialise_chain_state(bytes: &[u8], file_height: u64) -> Result<Option<ChainState>, String> {
    if bytes.len() == 72 {
        eprintln!(
            "[storage] warning: ignoring legacy unversioned summary snapshot at height {}",
            file_height
        );
        return Ok(None);
    }

    let Some((&version, payload)) = bytes.split_first() else {
        return Err("snapshot payload is empty".to_string());
    };

    match version {
        SNAPSHOT_VERSION_V1_SUMMARY => {
            eprintln!(
                "[storage] warning: ignoring legacy v1 summary snapshot at height {}",
                file_height
            );
            Ok(None)
        }
        SNAPSHOT_VERSION_V2_COMPLETE => {
            let (state, schema_version) = decode_legacy_snapshot(payload)
                .map_err(|e| format!("legacy snapshot decode failed: {e}"))?;
            let state = if schema_version < SCHEMA_VERSION {
                migrate_chain_state(state, schema_version)?
            } else {
                state
            };
            validate_snapshot_state(state, file_height)
        }
        SNAPSHOT_VERSION_V3_VERSIONED => {
            let Some((&schema_version, payload)) = payload.split_first() else {
                return Err("V3 snapshot missing schema version".to_string());
            };
            if schema_version > SCHEMA_VERSION {
                return Err(format!(
                    "snapshot schema version {} exceeds node's maximum {} — upgrade your node binary",
                    schema_version, SCHEMA_VERSION
                ));
            }
            let mut reader = ByteReader::new(payload);
            let state = if schema_version == 2 {
                ChainState::decode_schema_v2_snapshot(&mut reader).map_err(|e| e.to_string())?
            } else {
                ChainState::decode(&mut reader).map_err(|e| e.to_string())?
            };
            if reader.remaining() != 0 {
                return Err(format!(
                    "snapshot at height {} has {} trailing bytes",
                    file_height,
                    reader.remaining()
                ));
            }
            let state = if schema_version < SCHEMA_VERSION {
                migrate_chain_state(state, schema_version)?
            } else {
                state
            };
            validate_snapshot_state(state, file_height)
        }
        other => {
            eprintln!(
                "[storage] warning: ignoring incompatible snapshot version 0x{other:02x} at height {}",
                file_height
            );
            Ok(None)
        }
    }
}

fn decode_legacy_snapshot(payload: &[u8]) -> Result<(ChainState, u8), String> {
    let mut reader_v2 = ByteReader::new(payload);
    if let Ok(state) = ChainState::decode_legacy_snapshot(&mut reader_v2, SCHEMA_VERSION) {
        if reader_v2.remaining() == 0 {
            return Ok((state, SCHEMA_VERSION));
        }
    }

    let mut reader_v1 = ByteReader::new(payload);
    let state = ChainState::decode_legacy_snapshot(&mut reader_v1, SCHEMA_VERSION_GENESIS)
        .map_err(|e| e.to_string())?;
    if reader_v1.remaining() != 0 {
        return Err(format!(
            "legacy snapshot has {} trailing bytes",
            reader_v1.remaining()
        ));
    }
    Ok((state, SCHEMA_VERSION_GENESIS))
}

fn validate_snapshot_state(
    state: ChainState,
    file_height: u64,
) -> Result<Option<ChainState>, String> {
    if state.height != file_height {
        return Err(format!(
            "snapshot height mismatch: file says {}, payload says {}",
            file_height, state.height
        ));
    }
    Ok(Some(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        types::block::{BlockHeaderV1, BlockV1, NO_POLC_ROUND},
        types::primitives::MAX_VRF_PROOF_BYTES,
        Bytes32, ProtocolVersion, VariableBytes,
    };
    use indra_state::{apply_block, compute_state_root, compute_validator_set_root};

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
        assert_eq!(loaded, state);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v3_snapshot_round_trips() {
        let dir = temp_dir("v3_round_trip");
        let store = StateStore::open(&dir).unwrap();
        let mut state = ChainState::new_genesis();
        state.height = 123;
        state.treasury_balance = 456;
        store.save(&state).unwrap();
        assert_eq!(store.schema_version().unwrap(), Some(SCHEMA_VERSION));
        let loaded = store.load_latest().unwrap().unwrap();
        assert_eq!(loaded, state);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_with_future_schema_version_rejected() {
        let dir = temp_dir("future_schema");
        let store = StateStore::open(&dir).unwrap();
        let mut state = ChainState::new_genesis();
        state.height = 7;
        let mut payload = Vec::new();
        payload.push(SNAPSHOT_VERSION_V3_VERSIONED);
        payload.push(255);
        state.encode(&mut payload);
        write_snapshot(&dir, state.height, &payload);

        let err = store.load_latest().unwrap_err();
        assert!(err.to_string().contains("upgrade your node binary"));
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

        let mut s1 = ChainState::new_genesis();
        s1.height = 10;
        let mut s2 = ChainState::new_genesis();
        s2.height = 20;

        store.save(&s1).unwrap();
        store.save(&s2).unwrap();

        let loaded = store.load_latest().unwrap().unwrap();
        assert_eq!(loaded.height, 20);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn complete_snapshot_round_trip() {
        use indra_core::types::primitives::{Bytes32, DUST_LIMIT_SPARK};
        use indra_state::{ValidatorEntry, ValidatorStatus};

        let dir = temp_dir("round_trip");
        let store = StateStore::open(&dir).unwrap();

        let mut state = ChainState::new_genesis();
        state.height = 512;
        state.tip_hash = Bytes32::from([0x11; 32]);
        state.base_fee = 4242;
        state.total_supply = 9_999_999;
        state.treasury_balance = 123_456;
        state.burn_buffer = 654_321;
        state.fee_reward_pool = 888;

        state
            .utxos
            .insert(
                indra_core::types::transaction::OutputV1 {
                    value_spark: 50_000,
                    commitment: indra_core::CommitmentV1 {
                        compressed_point: Bytes32::from([0x21; 32]),
                    },
                    owner_pubkey: indra_core::HybridPubKey {
                        classical_pk: Bytes32::from([0x22; 32]),
                        pq_pk: indra_core::VariableBytes::from_slice(&[0x23; 64]).unwrap(),
                    },
                    range_proof: indra_core::VariableBytes::from_slice(&[0x24; 96]).unwrap(),
                    lock_height: 77,
                },
                512,
                0,
                0,
            )
            .unwrap();
        state.nullifiers.insert(Bytes32::from([0x31; 32]));

        state
            .validators
            .upsert(ValidatorEntry {
                validator_id: Bytes32::from([0x41; 32]),
                name: "validator-one".to_string(),
                hybrid_classical_pk: Some([0x42; 32]),
                hybrid_pq_pk: Some(vec![0x43; 80]),
                vrf_pk: Some([0x44; 32]),
                stake_spark: 1_000_000,
                status: ValidatorStatus::Active,
                registered_epoch: 7,
                last_active_epoch: 7,
                pending_rewards: 12,
                rewards_last_epoch: 6,
                self_report_count: 1,
                commission_bps: 900,
                pending_commission_bps: None,
                pending_commission_effective_epoch: None,
                min_delegation_spark: DUST_LIMIT_SPARK,
                auto_delegate_to: None,
            })
            .unwrap();
        state.delegations.add_delegation(
            Bytes32::from([0x41; 32]),
            Bytes32::from([0x51; 32]),
            25_000,
            7,
        );
        state
            .delegations
            .begin_undelegate(
                &Bytes32::from([0x41; 32]),
                &Bytes32::from([0x51; 32]),
                5_000,
                9,
            )
            .unwrap();

        store.save(&state).unwrap();
        let loaded = store.load_latest().unwrap().unwrap();
        assert_eq!(loaded, state);

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn make_block(state: &ChainState) -> BlockV1 {
        let mut block = BlockV1 {
            header: BlockHeaderV1 {
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
                polc_round: NO_POLC_ROUND,
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof: VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
                quorum_certificate: VariableBytes::from_slice(&[]).unwrap(),
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        };

        let mut projected = state.clone();
        apply_block(&mut projected, &block, 0).unwrap();
        block.header.state_root = compute_state_root(&projected);
        block.header.validator_set_root = compute_validator_set_root(&projected);
        block.header.value_hash = block.compute_value_hash(projected.total_supply);
        block
    }

    #[test]
    fn snapshot_round_trip_preserves_next_state_root() {
        let dir = temp_dir("next_state_root");
        let store = StateStore::open(&dir).unwrap();

        let mut original = ChainState::new_genesis();
        for _ in 1u8..=12u8 {
            let block = make_block(&original);
            apply_block(&mut original, &block, 0).unwrap();
        }

        store.save(&original).unwrap();
        let decoded = store.load_latest().unwrap().unwrap();

        assert_eq!(decoded, original);
        assert_eq!(compute_state_root(&decoded), compute_state_root(&original));
        assert_eq!(decoded.utxos.root(), original.utxos.root());
        assert_eq!(decoded.nullifiers.root(), original.nullifiers.root());
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
    fn old_v1_snapshot_rejected_gracefully() {
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

        assert!(store.load_latest().unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
