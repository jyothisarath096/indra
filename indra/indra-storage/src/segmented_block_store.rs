//! Checksummed, fixed-block-count segmented canonical block storage.
//!
//! Runtime code accepts only this format. No monolithic decoder is
//! compiled anywhere in the workspace.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};

use indra_core::{
    codec::{Decode, Encode},
    types::{block::BlockProposalVNext, primitives::MIN_PRUNE_KEEP_BLOCKS},
};

use crate::{
    atomic::{crc32, fsync_dir},
    error::{StorageError, StorageResult},
};

/// Number of blocks in one canonical segment; aligned to snapshot cadence.
pub const BLOCKS_PER_SEGMENT: u64 = 300;
const SEGMENT_DIR: &str = "block_segments";
const MAGIC: &[u8; 4] = b"INSG";
const VERSION: u8 = 1;
const FILE_HEADER_BYTES: u64 = 24;
const ENTRY_HEADER_BYTES: usize = 12;
const ENTRY_CRC_BYTES: usize = 4;

/// Pruning configuration for segmented block storage.
#[derive(Debug, Clone)]
pub struct PruneConfig {
    /// Maximum retained recent blocks, or none for archive mode.
    pub keep_blocks: Option<u64>,
}

impl PruneConfig {
    /// Archive mode retains every segment.
    pub fn archive() -> Self {
        Self { keep_blocks: None }
    }
    /// Custom retention with the protocol safety floor.
    pub fn keep(n: u64) -> Self {
        Self {
            keep_blocks: Some(n.max(MIN_PRUNE_KEEP_BLOCKS)),
        }
    }
}

#[derive(Debug, Clone)]
struct Location {
    path: PathBuf,
    offset: u64,
}

/// Segmented canonical block store.
pub struct BlockStore {
    dir: PathBuf,
    index: Arc<RwLock<BTreeMap<u64, Location>>>,
    next_height: u64,
    lowest_height: Arc<AtomicU64>,
    prune_cfg: PruneConfig,
}

/// Cloneable read-only segmented block-store handle.
#[derive(Clone)]
pub struct BlockStoreReadHandle {
    index: Arc<RwLock<BTreeMap<u64, Location>>>,
    lowest_height: Arc<AtomicU64>,
}

impl BlockStoreReadHandle {
    /// Read a retained block by height.
    pub fn get(&self, height: u64) -> StorageResult<BlockProposalVNext> {
        let location = lookup(&self.index, &self.lowest_height, height)?;
        read_location(height, &location)
    }
}

impl BlockStore {
    /// Open a segmented store, refusing a monolithic block log.
    pub fn open(block_log_path: impl AsRef<Path>, prune_cfg: PruneConfig) -> StorageResult<Self> {
        let block_log_path = block_log_path.as_ref();
        if block_log_path.exists() {
            return Err(StorageError::LegacyBlockStore {
                path: block_log_path.to_path_buf(),
                data_dir: block_log_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf(),
            });
        }
        let parent = block_log_path.parent().unwrap_or_else(|| Path::new("."));
        let dir = parent.join(SEGMENT_DIR);
        std::fs::create_dir_all(&dir)?;
        let (index, next_height, lowest) = scan_segments(&dir)?;
        Ok(Self {
            dir,
            index: Arc::new(RwLock::new(index)),
            next_height,
            lowest_height: Arc::new(AtomicU64::new(lowest)),
            prune_cfg,
        })
    }

    /// Append and fsync one sequential block.
    pub fn append(&mut self, block: &BlockProposalVNext) -> StorageResult<()> {
        let height = block.block.header.height;
        if height != self.next_height {
            return Err(StorageError::NonSequential {
                expected: self.next_height,
                actual: height,
            });
        }
        let start = segment_start(height);
        let path = segment_path(&self.dir, start);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        if file.metadata()?.len() == 0 {
            write_segment_header(&mut file, start)?;
        } else {
            verify_segment_header(&mut file, start)?;
        }
        let offset = file.seek(SeekFrom::End(0))?;
        write_entry(&mut file, height, &block.encode_to_vec())?;
        file.flush()?;
        file.sync_all()?;
        self.index
            .write()
            .map_err(|_| StorageError::LockPoisoned {
                component: "segmented block index",
            })?
            .insert(height, Location { path, offset });
        self.next_height = self.next_height.saturating_add(1);
        if self.len() == 1 {
            self.lowest_height.store(height, Ordering::Relaxed);
        }
        self.prune_complete_segments()?;
        Ok(())
    }

    /// Read a block by height.
    pub fn get(&mut self, height: u64) -> StorageResult<BlockProposalVNext> {
        self.get_read_only(height)
    }
    /// Read a block without mutably borrowing the writer.
    pub fn get_read_only(&self, height: u64) -> StorageResult<BlockProposalVNext> {
        let location = lookup(&self.index, &self.lowest_height, height)?;
        read_location(height, &location)
    }
    /// Create an independent read handle.
    pub fn read_handle(&self) -> BlockStoreReadHandle {
        BlockStoreReadHandle {
            index: Arc::clone(&self.index),
            lowest_height: Arc::clone(&self.lowest_height),
        }
    }
    /// Number of retained blocks.
    pub fn len(&self) -> usize {
        self.index
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
    /// Whether no blocks are retained.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Next append height.
    pub fn next_height(&self) -> u64 {
        self.next_height
    }
    /// Lowest retained height.
    pub fn lowest_height(&self) -> u64 {
        self.lowest_height.load(Ordering::Relaxed)
    }
    /// Whether archive mode is active.
    pub fn is_archive(&self) -> bool {
        self.prune_cfg.keep_blocks.is_none()
    }

    /// Quarantine durable entries newer than the manifest-confirmed generation.
    pub fn recover_to_next_height(&mut self, confirmed_next: u64) -> StorageResult<()> {
        if self.next_height <= confirmed_next {
            return Ok(());
        }
        let quarantine = self.dir.join("quarantine");
        std::fs::create_dir_all(&quarantine)?;
        let start = segment_start(confirmed_next);
        let cut_offset = self
            .index
            .read()
            .map_err(|_| StorageError::LockPoisoned {
                component: "segmented block index",
            })?
            .get(&confirmed_next)
            .map(|location| location.offset);
        let paths: Vec<PathBuf> = self
            .index
            .read()
            .map_err(|_| StorageError::LockPoisoned {
                component: "segmented block index",
            })?
            .range(confirmed_next..)
            .map(|(_, location)| location.path.clone())
            .collect();
        let mut paths = paths;
        paths.sort();
        paths.dedup();
        for path in paths {
            let file_start = path
                .file_stem()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix("segment_"))
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| StorageError::Corruption {
                    height: confirmed_next,
                    detail: "invalid segment filename during recovery".into(),
                })?;
            if file_start >= confirmed_next || file_start == start {
                let target =
                    quarantine.join(path.file_name().ok_or_else(|| StorageError::Corruption {
                        height: confirmed_next,
                        detail: "segment has no filename".into(),
                    })?);
                std::fs::rename(&path, &target)?;
                if file_start == start && confirmed_next > start {
                    let cut = cut_offset.ok_or_else(|| StorageError::ManifestMismatch {
                        detail: format!("manifest recovery boundary {confirmed_next} is absent from the active segment"),
                    })?;
                    let mut source = File::open(&target)?;
                    let mut replacement = File::create(&path)?;
                    std::io::copy(
                        &mut std::io::Read::by_ref(&mut source).take(cut),
                        &mut replacement,
                    )?;
                    replacement.flush()?;
                    replacement.sync_all()?;
                }
            }
        }
        fsync_dir(&self.dir)?;
        let (index, next, lowest) = scan_segments(&self.dir)?;
        *self.index.write().map_err(|_| StorageError::LockPoisoned {
            component: "segmented block index",
        })? = index;
        self.next_height = next;
        self.lowest_height.store(lowest, Ordering::Relaxed);
        if self.next_height != confirmed_next {
            return Err(StorageError::ManifestMismatch { detail: format!("recovery to manifest next height {confirmed_next} requires preserving part of a segment; partial-segment recovery artifact was quarantined and must be replayed") });
        }
        Ok(())
    }

    fn prune_complete_segments(&mut self) -> StorageResult<()> {
        let Some(keep) = self.prune_cfg.keep_blocks else {
            return Ok(());
        };
        let prune_below = self.next_height.saturating_sub(keep);
        let first_retained = self
            .index
            .read()
            .map_err(|_| StorageError::LockPoisoned {
                component: "segmented block index",
            })?
            .keys()
            .next()
            .copied();
        let Some(first_retained) = first_retained else {
            return Ok(());
        };
        let mut starts = Vec::new();
        let mut start = segment_start(first_retained);
        while let Some(end) = start.checked_add(BLOCKS_PER_SEGMENT) {
            if end > prune_below {
                break;
            }
            starts.push(start);
            start = end;
        }
        if starts.is_empty() {
            return Ok(());
        }
        let mut index = self.index.write().map_err(|_| StorageError::LockPoisoned {
            component: "segmented block index",
        })?;
        for start in starts {
            std::fs::remove_file(segment_path(&self.dir, start))?;
            let end = start
                .checked_add(BLOCKS_PER_SEGMENT)
                .expect("prunable segment end was checked during discovery");
            let heights: Vec<u64> = index.range(start..end).map(|(height, _)| *height).collect();
            for height in heights {
                index.remove(&height);
            }
        }
        fsync_dir(&self.dir)?;
        let lowest = index.keys().next().copied().unwrap_or(self.next_height);
        self.lowest_height.store(lowest, Ordering::Relaxed);
        Ok(())
    }
}

fn segment_start(height: u64) -> u64 {
    height / BLOCKS_PER_SEGMENT * BLOCKS_PER_SEGMENT
}
fn segment_path(dir: &Path, start: u64) -> PathBuf {
    dir.join(format!("segment_{start:020}.inbs"))
}

fn write_segment_header(file: &mut File, start: u64) -> StorageResult<()> {
    file.write_all(MAGIC)?;
    file.write_all(&[VERSION])?;
    file.write_all(&[0u8; 3])?;
    file.write_all(&start.to_le_bytes())?;
    file.write_all(&[0u8; 8])?;
    Ok(())
}
fn verify_segment_header(file: &mut File, expected_start: u64) -> StorageResult<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut h = [0u8; 24];
    file.read_exact(&mut h)?;
    if &h[..4] != MAGIC || h[4] != VERSION {
        return Err(StorageError::Corruption {
            height: expected_start,
            detail: "invalid block segment header".into(),
        });
    }
    let start = u64::from_le_bytes(h[8..16].try_into().map_err(|_| StorageError::Corruption {
        height: expected_start,
        detail: "truncated segment start".into(),
    })?);
    if start != expected_start {
        return Err(StorageError::Corruption {
            height: expected_start,
            detail: format!("segment start {start} does not match filename"),
        });
    }
    Ok(())
}
fn entry_crc(height: u64, len: u32, bytes: &[u8]) -> u32 {
    let mut v = Vec::with_capacity(12 + bytes.len());
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(&len.to_le_bytes());
    v.extend_from_slice(bytes);
    crc32(&v)
}
fn write_entry(file: &mut File, height: u64, bytes: &[u8]) -> StorageResult<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| StorageError::Corruption {
        height,
        detail: "block entry exceeds u32".into(),
    })?;
    file.write_all(&height.to_le_bytes())?;
    file.write_all(&len.to_le_bytes())?;
    file.write_all(bytes)?;
    file.write_all(&entry_crc(height, len, bytes).to_le_bytes())?;
    Ok(())
}

fn scan_segments(dir: &Path) -> StorageResult<(BTreeMap<u64, Location>, u64, u64)> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "inbs") {
            paths.push(path);
        }
    }
    paths.sort();
    let mut index = BTreeMap::new();
    for path in paths {
        let name =
            path.file_stem()
                .and_then(|n| n.to_str())
                .ok_or_else(|| StorageError::Corruption {
                    height: 0,
                    detail: "invalid segment filename".into(),
                })?;
        let start = name
            .strip_prefix("segment_")
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| StorageError::Corruption {
                height: 0,
                detail: "invalid segment filename".into(),
            })?;
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        verify_segment_header(&mut file, start)?;
        let size = file.metadata()?.len();
        let mut offset = FILE_HEADER_BYTES;
        while offset < size {
            if size - offset < (ENTRY_HEADER_BYTES + ENTRY_CRC_BYTES) as u64 {
                file.set_len(offset)?;
                break;
            }
            file.seek(SeekFrom::Start(offset))?;
            let mut h = [0u8; 12];
            file.read_exact(&mut h)?;
            let height =
                u64::from_le_bytes(h[..8].try_into().map_err(|_| StorageError::Corruption {
                    height: start,
                    detail: "truncated entry height".into(),
                })?);
            let len =
                u32::from_le_bytes(h[8..].try_into().map_err(|_| StorageError::Corruption {
                    height,
                    detail: "truncated entry length".into(),
                })?) as u64;
            let end = offset + 12 + len + 4;
            if end > size {
                file.set_len(offset)?;
                break;
            }
            let mut bytes = vec![0; len as usize];
            file.read_exact(&mut bytes)?;
            let mut c = [0; 4];
            file.read_exact(&mut c)?;
            let expected = u32::from_le_bytes(c);
            let actual = entry_crc(height, len as u32, &bytes);
            if expected != actual {
                return Err(StorageError::BlockChecksumMismatch {
                    height,
                    expected,
                    actual,
                });
            }
            let block =
                BlockProposalVNext::decode_exact(&bytes).map_err(|e| StorageError::Corruption {
                    height,
                    detail: e.to_string(),
                })?;
            if block.block.header.height != height {
                return Err(StorageError::Corruption {
                    height,
                    detail: "encoded block height mismatch".into(),
                });
            }
            index.insert(
                height,
                Location {
                    path: path.clone(),
                    offset,
                },
            );
            offset = end;
        }
    }
    let lowest = index.keys().next().copied().unwrap_or(0);
    let next = index.keys().next_back().map_or(0, |h| h + 1);
    if !index.is_empty() {
        for h in lowest..next {
            if !index.contains_key(&h) {
                return Err(StorageError::BlockLogGap { missing_height: h });
            }
        }
    }
    Ok((index, next, lowest))
}
fn lookup(
    index: &Arc<RwLock<BTreeMap<u64, Location>>>,
    lowest: &AtomicU64,
    height: u64,
) -> StorageResult<Location> {
    let map = index.read().map_err(|_| StorageError::LockPoisoned {
        component: "segmented block index",
    })?;
    let low = lowest.load(Ordering::Relaxed);
    if !map.is_empty() && height < low {
        return Err(StorageError::BlockPruned {
            height,
            lowest_available: low,
        });
    }
    map.get(&height)
        .cloned()
        .ok_or(StorageError::BlockNotFound { height })
}
fn read_location(height: u64, location: &Location) -> StorageResult<BlockProposalVNext> {
    let mut f = File::open(&location.path)?;
    f.seek(SeekFrom::Start(location.offset))?;
    let mut h = [0; 12];
    f.read_exact(&mut h)?;
    let stored = u64::from_le_bytes(h[..8].try_into().map_err(|_| StorageError::Corruption {
        height,
        detail: "truncated entry".into(),
    })?);
    let len = u32::from_le_bytes(h[8..].try_into().map_err(|_| StorageError::Corruption {
        height,
        detail: "truncated length".into(),
    })?) as usize;
    if stored != height {
        return Err(StorageError::Corruption {
            height,
            detail: "height index mismatch".into(),
        });
    }
    let mut bytes = vec![0; len];
    f.read_exact(&mut bytes)?;
    let mut c = [0; 4];
    f.read_exact(&mut c)?;
    let expected = u32::from_le_bytes(c);
    let actual = entry_crc(height, len as u32, &bytes);
    if expected != actual {
        return Err(StorageError::BlockChecksumMismatch {
            height,
            expected,
            actual,
        });
    }
    BlockProposalVNext::decode_exact(&bytes).map_err(|e| StorageError::Corruption {
        height,
        detail: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        types::{
            block::{BlockHeaderVNext, BlockVNext, SortitionClaimV1, VrfSuiteV1},
            primitives::{Bytes64, MAX_STANDARD_VRF_OUTPUT_BYTES, MAX_STANDARD_VRF_PROOF_BYTES},
        },
        ProtocolVersion, VariableBytes,
    };

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "indra_segmented_store_{name}_{}",
            std::process::id()
        ))
    }

    fn block(height: u64) -> BlockProposalVNext {
        BlockProposalVNext {
            block: BlockVNext {
                header: BlockHeaderVNext {
                    protocol_version: ProtocolVersion::CURRENT,
                    height,
                    prev_hash: indra_core::Bytes32::ZERO,
                    timestamp: height,
                    state_root: indra_core::Bytes32::ZERO,
                    validator_set_root: indra_core::Bytes32::ZERO,
                    mempool_set_root: indra_core::Bytes32::ZERO,
                    value_hash: indra_core::Bytes32::ZERO,
                    base_fee: 1,
                    proposer_round: 0,
                    polc_round: None,
                    proposer_id: indra_core::Bytes32::from([0x77; 32]),
                    vrf_suite: VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
                    election_seed: Bytes64([0x78; 64]),
                    proposer_vrf_output:
                        VariableBytes::<MAX_STANDARD_VRF_OUTPUT_BYTES>::from_slice(&[0; 64])
                            .unwrap(),
                    proposer_vrf_proof: VariableBytes::<MAX_STANDARD_VRF_PROOF_BYTES>::from_slice(
                        &[0; 80],
                    )
                    .unwrap(),
                    value_entropy: indra_core::types::block::ProposalEntropyV1 {
                        origin_proposer_id: indra_core::Bytes32::from([0x77; 32]),
                        origin_round: 0,
                        vrf_output: VariableBytes::from_slice(&[0; 64]).unwrap(),
                        vrf_proof: VariableBytes::from_slice(&[0; 80]).unwrap(),
                    },
                    sortition_claim: SortitionClaimV1::PraosThreshold,
                    proposer_priority: Bytes64([0x79; 64]),
                    quorum_certificate: VariableBytes::from_slice(&[]).unwrap(),
                },
                transactions: vec![],
                slashing_evidence: vec![],
                governance_ops: vec![],
                staking_ops: vec![],
            },
            proposer_authorization: indra_core::HybridSignature {
                classical_sig: VariableBytes::default(),
                pq_sig: VariableBytes::default(),
            },
        }
    }

    #[test]
    fn monolithic_block_log_is_rejected_without_segmented_read() {
        let dir = temp_dir("monolithic_block_log");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let block_log = dir.join("blocks.log");
        std::fs::write(&block_log, b"monolithic block bytes").unwrap();

        let error = match BlockStore::open(&block_log, PruneConfig::archive()) {
            Ok(_) => panic!("monolithic block log was opened as segmented storage"),
            Err(error) => error,
        };
        assert!(matches!(error, StorageError::LegacyBlockStore { .. }));
        assert!(!dir.join(SEGMENT_DIR).exists());

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn crash_truncated_block_entry_is_removed_on_reopen() {
        let dir = temp_dir("partial_entry");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            let mut store =
                BlockStore::open(dir.join("blocks.log"), PruneConfig::archive()).unwrap();
            store.append(&block(0)).unwrap();
        }
        let segment = segment_path(&dir.join(SEGMENT_DIR), 0);
        let confirmed_len = std::fs::metadata(&segment).unwrap().len();
        let mut file = OpenOptions::new().append(true).open(&segment).unwrap();
        file.write_all(&1u64.to_le_bytes()).unwrap();
        file.write_all(&999u32.to_le_bytes()).unwrap();
        file.write_all(&[0xAA; 7]).unwrap();
        file.flush().unwrap();
        drop(file);
        let store = BlockStore::open(dir.join("blocks.log"), PruneConfig::archive()).unwrap();
        assert_eq!(store.next_height(), 1);
        assert_eq!(std::fs::metadata(segment).unwrap().len(), confirmed_len);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn manifest_recovery_quarantines_unconfirmed_block_generation() {
        let dir = temp_dir("manifest_recovery");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut store = BlockStore::open(dir.join("blocks.log"), PruneConfig::archive()).unwrap();
        for height in 0..4 {
            store.append(&block(height)).unwrap();
        }
        store.recover_to_next_height(2).unwrap();
        assert_eq!(store.next_height(), 2);
        assert!(store.get_read_only(0).is_ok());
        assert!(store.get_read_only(1).is_ok());
        assert!(matches!(
            store.get_read_only(2),
            Err(StorageError::BlockNotFound { .. })
        ));
        assert!(dir.join(SEGMENT_DIR).join("quarantine").exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[ignore = "release-mode segmented-prune scaling benchmark"]
    fn benchmark_single_segment_prune_is_independent_of_retained_log_size() {
        fn measure(name: &str, keep: u64, prefill: u64) -> std::time::Duration {
            let dir = temp_dir(name);
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let mut store =
                BlockStore::open(dir.join("blocks.log"), PruneConfig::keep(keep)).unwrap();
            for height in 0..prefill {
                store.append(&block(height)).unwrap();
            }
            let started = std::time::Instant::now();
            store.append(&block(prefill)).unwrap();
            let elapsed = started.elapsed();
            let _ = std::fs::remove_dir_all(dir);
            elapsed
        }

        // Both final appends cross exactly one segment-prune boundary. Only
        // retained history differs (~1k versus ~50k blocks).
        let small = measure("prune_bench_small", 1_000, 1_599);
        let large = measure("prune_bench_large", 5_000, 5_599);
        eprintln!("segmented prune benchmark: retained_1k={small:?} retained_5k={large:?}");
        assert!(
            large
                < small
                    .saturating_mul(20)
                    .max(std::time::Duration::from_millis(20))
        );
    }
}
