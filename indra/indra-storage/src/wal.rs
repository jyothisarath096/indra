//! Mempool write-ahead log (WAL).
//!
//! Ensures pending transactions survive a node crash.
//!
//! ## File format
//!
//! Each WAL entry: u8 tag || u32 length || payload_bytes || u32 crc32
//!
//! Tags:
//!   0x01 = SUBMIT (add transaction to mempool)
//!   0x02 = EVICT  (remove transaction from mempool by tx_id)
//!
//! ## Recovery
//!
//! On startup, scan the WAL and replay SUBMIT/EVICT entries in order.
//! Entries with bad CRC are discarded (truncated write at crash).
//! After recovery, the WAL is compacted (rewritten with only live entries).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use indra_core::{
    codec::{Decode, Encode},
    types::{primitives::Bytes32, transaction::TransactionV1},
};

use crate::error::{StorageError, StorageResult};

const TAG_SUBMIT: u8 = 0x01;
const TAG_EVICT: u8 = 0x02;
const ENTRY_OVERHEAD: usize = 9; // 1 tag + 4 length + 4 crc

/// A WAL entry recovered on startup.
#[derive(Debug)]
pub enum WalEntry {
    /// Add this transaction to the mempool.
    Submit(TransactionV1),
    /// Remove this transaction from the mempool.
    Evict(Bytes32),
}

/// The mempool write-ahead log.
pub struct MempoolWal {
    path: PathBuf,
    file: File,
}

impl MempoolWal {
    /// Open or create a WAL at the given path.
    pub fn open(path: impl AsRef<Path>) -> StorageResult<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)?;
        Ok(Self { path, file })
    }

    /// Log a transaction submission.
    pub fn log_submit(&mut self, tx: &TransactionV1) -> StorageResult<()> {
        self.write_entry(TAG_SUBMIT, &tx.encode_to_vec())
    }

    /// Log a transaction eviction.
    pub fn log_evict(&mut self, tx_id: &Bytes32) -> StorageResult<()> {
        self.write_entry(TAG_EVICT, &tx_id.0)
    }

    /// Recover all valid entries from the WAL.
    pub fn recover(&mut self) -> StorageResult<Vec<WalEntry>> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut entries = Vec::new();
        let file_len = self.file.seek(SeekFrom::End(0))?;
        self.file.seek(SeekFrom::Start(0))?;

        let mut offset: u64 = 0;

        loop {
            if offset + ENTRY_OVERHEAD as u64 > file_len {
                break;
            }

            // Read tag + length
            let mut header = [0u8; 5];
            self.file.read_exact(&mut header)?;
            let tag = header[0];
            let length_bytes: [u8; 4] = header[1..5]
                .try_into()
                .map_err(|_| crate::error::StorageError::TruncatedEntry { offset })?;
            let length = u32::from_le_bytes(length_bytes) as usize;

            if offset + ENTRY_OVERHEAD as u64 + length as u64 > file_len {
                break; // truncated
            }

            let mut payload = vec![0u8; length];
            self.file.read_exact(&mut payload)?;

            let mut crc_bytes = [0u8; 4];
            self.file.read_exact(&mut crc_bytes)?;
            let stored_crc = u32::from_le_bytes(crc_bytes);
            let computed_crc = simple_crc32(&payload);

            if stored_crc != computed_crc {
                // Bad CRC — truncated or corrupted, stop
                break;
            }

            match tag {
                TAG_SUBMIT => {
                    use indra_core::codec::ByteReader;
                    let mut r = ByteReader::new(&payload);
                    if let Ok(tx) = TransactionV1::decode(&mut r) {
                        entries.push(WalEntry::Submit(tx));
                    }
                }
                TAG_EVICT => {
                    if payload.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&payload);
                        entries.push(WalEntry::Evict(Bytes32::from(arr)));
                    }
                }
                other => {
                    return Err(StorageError::Corruption {
                        height: offset,
                        detail: format!("unknown WAL entry tag 0x{other:02x}"),
                    });
                }
            }

            offset += ENTRY_OVERHEAD as u64 + length as u64;
        }

        Ok(entries)
    }

    /// Truncate the WAL (after a successful compaction or snapshot).
    pub fn truncate(&mut self) -> StorageResult<()> {
        // Close and reopen the file to avoid Windows permission issues
        // with truncating an append-mode file handle.
        drop(std::mem::replace(
            &mut self.file,
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&self.path)?,
        ));
        Ok(())
    }

    fn write_entry(&mut self, tag: u8, payload: &[u8]) -> StorageResult<()> {
        let length = payload.len() as u32;
        let crc = simple_crc32(payload);

        self.file.write_all(&[tag])?;
        self.file.write_all(&length.to_le_bytes())?;
        self.file.write_all(payload)?;
        self.file.write_all(&crc.to_le_bytes())?;
        self.file.flush()?;
        Ok(())
    }
}

/// A simple CRC-32 checksum (polynomial 0xEDB88320).
/// Not cryptographic — used only to detect truncated writes.
fn simple_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        types::{
            crypto::HybridSignature,
            primitives::TRANSACTION_PROTOCOL_VERSION,
            transaction::{InputV1, OutputV1, TransactionV1},
        },
        Bytes32, HybridPubKey, ProtocolVersion, VariableBytes,
    };

    fn temp_path(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "indra_wal_test_{}_{}.wal",
            suffix,
            std::process::id()
        ));
        p
    }

    fn dummy_tx(nonce: u8) -> TransactionV1 {
        TransactionV1 {
            version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
            signature_module_id: 1,
            inputs: vec![InputV1 {
                utxo_id: Bytes32::from([nonce; 32]),
            }],
            outputs: vec![OutputV1 {
                value_spark: 1_000,
                owner_pubkey: HybridPubKey {
                    classical_pk: Bytes32::ZERO,
                    pq_pk: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
                },
                lock_height: 0,
            }],
            fee_amount: 10_000,
            signature: HybridSignature {
                classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                pq_sig: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            },
        }
    }

    #[test]
    fn submit_and_recover() {
        let path = temp_path("a");
        let tx = dummy_tx(0x01);
        {
            let mut wal = MempoolWal::open(&path).unwrap();
            wal.log_submit(&tx).unwrap();
        }
        let mut wal2 = MempoolWal::open(&path).unwrap();
        let entries = wal2.recover().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries.first(), Some(WalEntry::Submit(_))));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn evict_and_recover() {
        let path = temp_path("b");
        let tx_id = Bytes32::from([0xABu8; 32]);
        {
            let mut wal = MempoolWal::open(&path).unwrap();
            wal.log_evict(&tx_id).unwrap();
        }
        let mut wal2 = MempoolWal::open(&path).unwrap();
        let entries = wal2.recover().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries.first(), Some(WalEntry::Evict(_))));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn truncate_clears_wal() {
        let path = temp_path("c");
        let tx = dummy_tx(0x02);
        let mut wal = MempoolWal::open(&path).unwrap();
        wal.log_submit(&tx).unwrap();
        wal.truncate().unwrap();
        let entries = wal.recover().unwrap();
        assert!(entries.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unknown_tag_fails_closed() {
        let path = temp_path("unknown_tag");
        {
            let mut wal = MempoolWal::open(&path).unwrap();
            wal.write_entry(0xff, &[1, 2, 3]).unwrap();
        }
        let mut wal = MempoolWal::open(&path).unwrap();
        let err = wal.recover().unwrap_err();
        assert!(err.to_string().contains("unknown WAL entry tag 0xff"));
        let _ = std::fs::remove_file(&path);
    }
}
