//! Append-only block log.
//!
//! ## File format
//!
//! Each block entry in the log file:
//!   [u64 height (8 bytes LE)] [u32 length (4 bytes LE)] [block bytes (length bytes)]
//!
//! The index (height → file offset) is rebuilt from the log on startup.
//! This is O(n) in the number of blocks but fast in practice (< 1s for
//! 100k blocks at 1 MB each due to sequential I/O).
//!
//! ## Crash safety
//!
//! A partial write leaves a truncated entry at the end of the file.
//! On recovery, we scan forward and stop at the first entry where
//! `file_offset + 12 + length > file_size`. That entry is discarded.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use indra_core::{
    codec::{Decode, Encode},
    types::{
        block::BlockV1,
        primitives::{DEFAULT_PRUNE_KEEP_BLOCKS, MIN_PRUNE_KEEP_BLOCKS},
    },
};

use crate::error::{StorageError, StorageResult};

/// The header size for each block entry: u64 height + u32 length.
const ENTRY_HEADER_BYTES: usize = 12;

/// Pruning configuration for the block store.
#[derive(Debug, Clone)]
pub struct PruneConfig {
    /// Maximum number of recent blocks to keep.
    pub keep_blocks: Option<u64>,
}

impl PruneConfig {
    /// Default validator mode: keep the recent prune window.
    pub fn default_validator() -> Self {
        Self {
            keep_blocks: Some(DEFAULT_PRUNE_KEEP_BLOCKS),
        }
    }

    /// Archive mode: keep all blocks forever.
    pub fn archive() -> Self {
        Self { keep_blocks: None }
    }

    /// Custom keep window with a safety floor.
    pub fn keep(n: u64) -> Self {
        Self {
            keep_blocks: Some(n.max(MIN_PRUNE_KEEP_BLOCKS)),
        }
    }
}

/// An append-only block log with an in-memory height→offset index.
pub struct BlockStore {
    file: File,
    index: HashMap<u64, u64>, // height → file offset of the entry header
    next_height: u64,
    prune_cfg: PruneConfig,
    lowest_height: u64,
}

impl BlockStore {
    /// Open or create a block store at the given path.
    ///
    /// On first open, scans the file to rebuild the index.
    /// Truncates any incomplete final entry.
    pub fn open(path: impl AsRef<Path>, prune_cfg: PruneConfig) -> StorageResult<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let mut store = Self {
            file,
            index: HashMap::new(),
            next_height: 0,
            prune_cfg,
            lowest_height: 0,
        };
        store.rebuild_index()?;
        Ok(store)
    }

    /// Total number of blocks stored.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// True if no blocks are stored.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// The height of the next block to be appended.
    pub fn next_height(&self) -> u64 {
        self.next_height
    }

    /// Lowest block height currently stored.
    pub fn lowest_height(&self) -> u64 {
        self.lowest_height
    }

    /// True if this store keeps all blocks forever.
    pub fn is_archive(&self) -> bool {
        self.prune_cfg.keep_blocks.is_none()
    }

    /// Append a block to the store.
    ///
    /// Blocks must be appended in strict height order.
    pub fn append(&mut self, block: &BlockV1) -> StorageResult<()> {
        let height = block.header.height;
        if height != self.next_height {
            return Err(StorageError::NonSequential {
                expected: self.next_height,
                actual: height,
            });
        }

        let block_bytes = block.encode_to_vec();
        let length = block_bytes.len() as u32;

        // Record offset before writing
        let offset = self.file.seek(SeekFrom::End(0))?;

        // Write: height (8) || length (4) || block_bytes
        self.file.write_all(&height.to_le_bytes())?;
        self.file.write_all(&length.to_le_bytes())?;
        self.file.write_all(&block_bytes)?;
        self.file.flush()?;

        self.index.insert(height, offset);
        self.next_height += 1;

        if let Some(keep) = self.prune_cfg.keep_blocks {
            if height >= keep {
                let prune_below = height + 1 - keep;
                self.prune_below(prune_below)?;
            }
        }

        Ok(())
    }

    /// Read a block by height.
    pub fn get(&mut self, height: u64) -> StorageResult<BlockV1> {
        if !self.index.is_empty() && height < self.lowest_height {
            return Err(StorageError::BlockPruned {
                height,
                lowest_available: self.lowest_height,
            });
        }

        let offset = self
            .index
            .get(&height)
            .copied()
            .ok_or(StorageError::BlockNotFound { height })?;

        self.file.seek(SeekFrom::Start(offset))?;

        // Read header
        let mut header = [0u8; ENTRY_HEADER_BYTES];
        self.file.read_exact(&mut header)?;

        let stored_height_bytes: [u8; 8] =
            header[..8]
                .try_into()
                .map_err(|_| StorageError::Corruption {
                    height,
                    detail: "entry header truncated while reading height".to_string(),
                })?;
        let stored_height = u64::from_le_bytes(stored_height_bytes);
        let length_bytes: [u8; 4] =
            header[8..12]
                .try_into()
                .map_err(|_| StorageError::Corruption {
                    height,
                    detail: "entry header truncated while reading length".to_string(),
                })?;
        let length = u32::from_le_bytes(length_bytes) as usize;

        if stored_height != height {
            return Err(StorageError::Corruption {
                height,
                detail: format!("index mismatch: stored height {stored_height}"),
            });
        }

        let mut block_bytes = vec![0u8; length];
        self.file.read_exact(&mut block_bytes)?;

        use indra_core::codec::ByteReader;
        let mut reader = ByteReader::new(&block_bytes);
        BlockV1::decode(&mut reader).map_err(|e| StorageError::Corruption {
            height,
            detail: e.to_string(),
        })
    }

    /// Remove all blocks with heights below `prune_below`.
    fn prune_below(&mut self, prune_below: u64) -> StorageResult<()> {
        if prune_below <= self.lowest_height {
            return Ok(());
        }

        let keep_from_height = prune_below;
        let keep_offset = match self.index.get(&keep_from_height).copied() {
            Some(offset) => offset,
            None => {
                let next_available = self
                    .index
                    .keys()
                    .filter(|&&height| height >= keep_from_height)
                    .min()
                    .copied();
                match next_available {
                    Some(height) => self.index[&height],
                    None => return Ok(()),
                }
            }
        };

        if keep_offset == 0 {
            return Ok(());
        }

        let file_len = self.file.seek(SeekFrom::End(0))?;
        let keep_bytes = (file_len - keep_offset) as usize;
        let mut kept_data = vec![0u8; keep_bytes];
        self.file.seek(SeekFrom::Start(keep_offset))?;
        self.file.read_exact(&mut kept_data)?;

        self.file.seek(SeekFrom::Start(0))?;
        self.file.set_len(0)?;
        self.file.write_all(&kept_data)?;
        self.file.flush()?;

        let offset_adjustment = keep_offset;
        let mut new_index = HashMap::new();
        for (&height, &old_offset) in &self.index {
            if height >= keep_from_height {
                new_index.insert(height, old_offset.saturating_sub(offset_adjustment));
            }
        }
        self.index = new_index;
        self.lowest_height = self.index.keys().min().copied().unwrap_or(0);
        Ok(())
    }

    /// Scan the file to rebuild the height→offset index.
    /// Truncates any incomplete final entry.
    fn rebuild_index(&mut self) -> StorageResult<()> {
        let file_len = self.file.seek(SeekFrom::End(0))?;
        self.file.seek(SeekFrom::Start(0))?;

        let mut offset: u64 = 0;
        let mut last_good_offset: u64 = 0;
        let mut max_height: Option<u64> = None;

        loop {
            if offset + ENTRY_HEADER_BYTES as u64 > file_len {
                break; // not enough bytes for a header
            }

            let mut header = [0u8; ENTRY_HEADER_BYTES];
            self.file.read_exact(&mut header)?;

            let height_bytes: [u8; 8] =
                header[..8]
                    .try_into()
                    .map_err(|_| StorageError::Corruption {
                        height: self.next_height,
                        detail: "entry header truncated while rebuilding height index".to_string(),
                    })?;
            let height = u64::from_le_bytes(height_bytes);
            let length_bytes: [u8; 4] =
                header[8..12]
                    .try_into()
                    .map_err(|_| StorageError::Corruption {
                        height,
                        detail: "entry header truncated while rebuilding length index".to_string(),
                    })?;
            let length = u32::from_le_bytes(length_bytes) as u64;

            if offset + ENTRY_HEADER_BYTES as u64 + length > file_len {
                // Truncated entry — stop here and truncate the file
                self.file.set_len(last_good_offset)?;
                break;
            }

            self.index.insert(height, offset);
            if max_height.is_none_or(|m| height > m) {
                max_height = Some(height);
            }

            last_good_offset = offset + ENTRY_HEADER_BYTES as u64 + length;
            offset = last_good_offset;
            self.file.seek(SeekFrom::Start(offset))?;
        }

        self.next_height = max_height.map_or(0, |h| h + 1);
        self.lowest_height = self.index.keys().min().copied().unwrap_or(0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        types::{
            block::{BlockHeaderV1, BlockV1},
            primitives::MAX_VRF_PROOF_BYTES,
        },
        Bytes32, ProtocolVersion, VariableBytes,
    };
    use std::path::PathBuf;

    fn temp_path(label: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "indra_test_blocks_{}_{}.bin",
            label,
            std::process::id()
        ));
        p
    }

    fn dummy_block(height: u64, prev_hash: [u8; 32]) -> BlockV1 {
        BlockV1 {
            header: BlockHeaderV1 {
                protocol_version: ProtocolVersion::CURRENT,
                height,
                prev_hash: Bytes32::from(prev_hash),
                timestamp: 1_700_000_000 + height,
                state_root: Bytes32::ZERO,
                validator_set_root: Bytes32::ZERO,
                mempool_set_root: Bytes32::ZERO,
                value_hash: Bytes32::ZERO,
                base_fee: 100,
                proposer_round: 0,
                polc_round: indra_core::types::block::NO_POLC_ROUND,
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof: VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[0u8; 64])
                    .unwrap(),
                quorum_certificate: indra_core::VariableBytes::from_slice(&[]).unwrap(),
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        }
    }

    #[test]
    fn append_and_retrieve() {
        let path = temp_path("append");
        let mut store = BlockStore::open(&path, PruneConfig::archive()).unwrap();

        let b0 = dummy_block(0, [0u8; 32]);
        let b1 = dummy_block(1, [0u8; 32]);
        store.append(&b0).unwrap();
        store.append(&b1).unwrap();

        let got0 = store.get(0).unwrap();
        let got1 = store.get(1).unwrap();
        assert_eq!(got0.header.height, 0);
        assert_eq!(got1.header.height, 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn non_sequential_rejected() {
        let path = temp_path("nonseq");
        let mut path2 = path.clone();
        path2.set_extension("bin2");
        let mut store = BlockStore::open(&path2, PruneConfig::archive()).unwrap();
        let b0 = dummy_block(0, [0u8; 32]);
        let b2 = dummy_block(2, [0u8; 32]); // skip height 1
        store.append(&b0).unwrap();
        assert!(store.append(&b2).is_err());
        let _ = std::fs::remove_file(&path2);
    }

    #[test]
    fn index_survives_reopen() {
        let path = temp_path("reopen");
        let mut p3 = path.clone();
        p3.set_extension("bin3");
        {
            let mut store = BlockStore::open(&p3, PruneConfig::archive()).unwrap();
            store.append(&dummy_block(0, [0u8; 32])).unwrap();
            store.append(&dummy_block(1, [0u8; 32])).unwrap();
        }
        // Reopen and check index is rebuilt
        let mut store2 = BlockStore::open(&p3, PruneConfig::archive()).unwrap();
        assert_eq!(store2.len(), 2);
        assert_eq!(store2.get(0).unwrap().header.height, 0);
        assert_eq!(store2.get(1).unwrap().header.height, 1);
        let _ = std::fs::remove_file(&p3);
    }

    #[test]
    fn pruning_removes_old_blocks() {
        let path = temp_path("prune");
        let mut store = BlockStore::open(
            &path,
            PruneConfig {
                keep_blocks: Some(5),
            },
        )
        .unwrap();

        for height in 0..10u64 {
            store.append(&dummy_block(height, [0u8; 32])).unwrap();
        }

        assert!(store.get(0).is_err());
        assert!(store.get(4).is_err());
        assert!(store.get(5).is_ok());
        assert!(store.get(9).is_ok());
        assert_eq!(store.lowest_height(), 5);
        assert_eq!(store.len(), 5);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn archive_mode_keeps_all_blocks() {
        let path = temp_path("archive");
        let mut store = BlockStore::open(&path, PruneConfig::archive()).unwrap();

        for height in 0..20u64 {
            store.append(&dummy_block(height, [0u8; 32])).unwrap();
        }

        assert!(store.get(0).is_ok());
        assert!(store.get(19).is_ok());
        assert_eq!(store.len(), 20);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pruned_store_survives_reopen() {
        let path = temp_path("pruned_reopen");
        {
            let mut store = BlockStore::open(
                &path,
                PruneConfig {
                    keep_blocks: Some(3),
                },
            )
            .unwrap();
            for height in 0..10u64 {
                store.append(&dummy_block(height, [0u8; 32])).unwrap();
            }
            assert_eq!(store.lowest_height(), 7);
        }

        let mut store = BlockStore::open(
            &path,
            PruneConfig {
                keep_blocks: Some(3),
            },
        )
        .unwrap();
        assert!(store.get(6).is_err());
        assert!(store.get(7).is_ok());
        assert_eq!(store.len(), 3);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pruned_block_error_is_informative() {
        let path = temp_path("pruned_err");
        let mut store = BlockStore::open(
            &path,
            PruneConfig {
                keep_blocks: Some(5),
            },
        )
        .unwrap();
        for height in 0..10u64 {
            store.append(&dummy_block(height, [0u8; 32])).unwrap();
        }

        match store.get(0) {
            Err(StorageError::BlockPruned {
                height,
                lowest_available,
            }) => {
                assert_eq!(height, 0);
                assert_eq!(lowest_available, 5);
            }
            other => panic!("expected BlockPruned, got {:?}", other),
        }

        let _ = std::fs::remove_file(&path);
    }
}
