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
    types::block::BlockV1,
};

use crate::error::{StorageError, StorageResult};

/// The header size for each block entry: u64 height + u32 length.
const ENTRY_HEADER_BYTES: usize = 12;

/// An append-only block log with an in-memory height→offset index.
pub struct BlockStore {
    file:   File,
    index:  HashMap<u64, u64>, // height → file offset of the entry header
    next_height: u64,
}

impl BlockStore {
    /// Open or create a block store at the given path.
    ///
    /// On first open, scans the file to rebuild the index.
    /// Truncates any incomplete final entry.
    pub fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;

        let mut store = Self {
            file,
            index: HashMap::new(),
            next_height: 0,
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
        Ok(())
    }

    /// Read a block by height.
    pub fn get(&mut self, height: u64) -> StorageResult<BlockV1> {
        let offset = self.index.get(&height)
            .copied()
            .ok_or(StorageError::BlockNotFound { height })?;

        self.file.seek(SeekFrom::Start(offset))?;

        // Read header
        let mut header = [0u8; ENTRY_HEADER_BYTES];
        self.file.read_exact(&mut header)?;

        let stored_height_bytes: [u8; 8] = header[..8]
            .try_into()
            .map_err(|_| StorageError::Corruption {
                height,
                detail: "entry header truncated while reading height".to_string(),
            })?;
        let stored_height = u64::from_le_bytes(stored_height_bytes);
        let length_bytes: [u8; 4] = header[8..12]
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

            let height_bytes: [u8; 8] = header[..8]
                .try_into()
                .map_err(|_| StorageError::Corruption {
                    height: self.next_height,
                    detail: "entry header truncated while rebuilding height index".to_string(),
                })?;
            let height = u64::from_le_bytes(height_bytes);
            let length_bytes: [u8; 4] = header[8..12]
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use indra_core::{
        Bytes32, ProtocolVersion, VariableBytes,
        types::{
            block::{BlockHeaderV1, BlockV1},
            primitives::MAX_VRF_PROOF_BYTES,
        },
    };

    fn temp_path() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_test_blocks_{}.bin", std::process::id()));
        p
    }

    fn dummy_block(height: u64, prev_hash: [u8; 32]) -> BlockV1 {
        BlockV1 {
            header: BlockHeaderV1 {
                protocol_version:    ProtocolVersion::CURRENT,
                height,
                prev_hash:           Bytes32::from(prev_hash),
                timestamp:           1_700_000_000 + height,
                state_root:          Bytes32::ZERO,
                validator_set_root:  Bytes32::ZERO,
                mempool_set_root:    Bytes32::ZERO,
                base_fee:            100,
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof:  VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[0u8; 64]).unwrap(),
                quorum_certificate:  indra_core::VariableBytes::from_slice(&[]).unwrap(),
            },
            transactions:      vec![],
            slashing_evidence: vec![],
            governance_ops:    vec![],
        }
    }

    #[test]
    fn append_and_retrieve() {
        let path = temp_path();
        let mut store = BlockStore::open(&path).unwrap();

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
        let path = temp_path();
        let mut path2 = path.clone();
        path2.set_extension("bin2");
        let mut store = BlockStore::open(&path2).unwrap();
        let b0 = dummy_block(0, [0u8; 32]);
        let b2 = dummy_block(2, [0u8; 32]); // skip height 1
        store.append(&b0).unwrap();
        assert!(store.append(&b2).is_err());
        let _ = std::fs::remove_file(&path2);
    }

    #[test]
    fn index_survives_reopen() {
        let path = temp_path();
        let mut p3 = path.clone();
        p3.set_extension("bin3");
        {
            let mut store = BlockStore::open(&p3).unwrap();
            store.append(&dummy_block(0, [0u8; 32])).unwrap();
            store.append(&dummy_block(1, [0u8; 32])).unwrap();
        }
        // Reopen and check index is rebuilt
        let mut store2 = BlockStore::open(&p3).unwrap();
        assert_eq!(store2.len(), 2);
        assert_eq!(store2.get(0).unwrap().header.height, 0);
        assert_eq!(store2.get(1).unwrap().header.height, 1);
        let _ = std::fs::remove_file(&p3);
    }
}
