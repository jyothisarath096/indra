//! Durable consensus vote and lock safety state.
//!
//! The single canonical record is atomically persisted before every local vote.
//! A non-nil precommit additionally carries the verified prevote PoLC that
//! created the Tendermint lock. Restart must restore and independently verify
//! that lock before the validator may vote again.

use std::fs;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};

use indra_core::{
    codec::{ByteReader, Decode, Encode},
    types::{
        block::BlockProposalVNext,
        primitives::{validate_consensus_round, Bytes32},
        vote::VoteV1,
    },
};

use crate::atomic::{crc32, write_atomic_synced};
use crate::error::StorageResult;

const SAFETY_FORMAT_VERSION: u8 = 3;
const MAX_PERSISTED_POLC_VOTES: usize = 200;
const MAX_SAFETY_FILE_BYTES: u64 = 25_165_824;

/// A durable Tendermint lock and the signed prevote PoLC that justifies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedConsensusLock {
    /// Height at which the lock applies.
    pub height: u64,
    /// Round in which the prevote PoLC formed.
    pub round: u32,
    /// Full block identity receiving the prevote quorum.
    pub block_hash: Bytes32,
    /// Stable value identity used for justified reproposals.
    pub value_hash: Bytes32,
    /// Independently verifiable proposal envelope for the locked block.
    pub proposal: BlockProposalVNext,
    /// Signed prevotes sufficient to independently reconstruct the PoLC.
    pub polc_votes: Vec<VoteV1>,
}

/// The persisted local consensus safety record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteSafetyRecord {
    /// Proposal height the latest vote was cast for.
    pub height: u64,
    /// Consensus round the latest vote was cast in.
    pub round: u32,
    /// Vote step: 0 = prevote, 1 = precommit.
    pub step: u8,
    /// Current lock, retained across later-round votes until height commit.
    pub consensus_lock: Option<PersistedConsensusLock>,
}

/// Result of reading the safety file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteSafetyLoadResult {
    /// No record exists yet — fresh validator start.
    NoRecord,
    /// A structurally valid canonical record was loaded. Cryptographic PoLC
    /// verification remains the consensus driver's responsibility.
    Record(Box<VoteSafetyRecord>),
    /// The file exists but is invalid/corrupt and voting must fail closed.
    Corrupt(String),
}

/// Manages durable vote and lock safety persistence.
pub struct VoteSafetyStore {
    path: PathBuf,
    tmp_path: PathBuf,
}

impl VoteSafetyStore {
    /// Open a safety store at the given path.
    pub fn open(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let tmp_path = path.with_extension("tmp");
        Self { path, tmp_path }
    }

    /// Persist the latest vote and current lock atomically before signing.
    pub fn record(
        &self,
        height: u64,
        round: u32,
        step: u8,
        consensus_lock: Option<&PersistedConsensusLock>,
    ) -> StorageResult<()> {
        validate_consensus_round(round)
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error.to_string()))?;
        if let VoteSafetyLoadResult::Record(existing) = self.load() {
            let existing_slot = (existing.height, existing.round, existing.step);
            let requested_slot = (height, round, step);
            if requested_slot <= existing_slot {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "vote safety slot is not strictly later than persisted slot",
                )
                .into());
            }
        }
        if let Some(lock) = consensus_lock {
            validate_consensus_round(lock.round)
                .map_err(|error| Error::new(ErrorKind::InvalidInput, error.to_string()))?;
            if lock.polc_votes.iter().any(|vote| vote.round != lock.round) {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "persisted PoLC vote round differs from lock round",
                )
                .into());
            }
        }
        if consensus_lock.is_some_and(|lock| lock.polc_votes.len() > MAX_PERSISTED_POLC_VOTES) {
            return Err(
                Error::new(ErrorKind::InvalidInput, "PoLC vote count exceeds maximum").into(),
            );
        }
        let record = VoteSafetyRecord {
            height,
            round,
            step,
            consensus_lock: consensus_lock.cloned(),
        };
        let payload = encode_record(&record);
        if payload.len() as u64 > MAX_SAFETY_FILE_BYTES.saturating_sub(4) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "safety record exceeds maximum size",
            )
            .into());
        }
        let mut bytes = payload;
        bytes.extend_from_slice(&crc32(&bytes).to_le_bytes());
        write_atomic_synced(&self.tmp_path, &self.path, &bytes)
    }

    /// Remove safety state only after the locked height has committed.
    pub fn clear(&self) -> StorageResult<()> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Load one canonical safety record. Unsupported formats are deliberately rejected.
    pub fn load(&self) -> VoteSafetyLoadResult {
        let metadata = match fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return VoteSafetyLoadResult::NoRecord
            }
            Err(error) => return VoteSafetyLoadResult::Corrupt(error.to_string()),
        };
        if metadata.len() > MAX_SAFETY_FILE_BYTES {
            return VoteSafetyLoadResult::Corrupt("safety record exceeds maximum size".into());
        }
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) => return VoteSafetyLoadResult::Corrupt(error.to_string()),
        };
        if bytes.len() < 5 {
            return VoteSafetyLoadResult::Corrupt("safety record truncated".into());
        }
        let payload_len = bytes.len() - 4;
        let stored_crc = u32::from_le_bytes(match bytes[payload_len..].try_into() {
            Ok(value) => value,
            Err(_) => return VoteSafetyLoadResult::Corrupt("CRC field truncated".into()),
        });
        if stored_crc != crc32(&bytes[..payload_len]) {
            return VoteSafetyLoadResult::Corrupt("CRC mismatch".into());
        }
        match decode_record(&bytes[..payload_len]) {
            Ok(record) => VoteSafetyLoadResult::Record(Box::new(record)),
            Err(error) => VoteSafetyLoadResult::Corrupt(error),
        }
    }
}

fn encode_record(record: &VoteSafetyRecord) -> Vec<u8> {
    let mut bytes = Vec::new();
    SAFETY_FORMAT_VERSION.encode(&mut bytes);
    record.height.encode(&mut bytes);
    record.round.encode(&mut bytes);
    record.step.encode(&mut bytes);
    match &record.consensus_lock {
        None => 0u8.encode(&mut bytes),
        Some(lock) => {
            1u8.encode(&mut bytes);
            lock.height.encode(&mut bytes);
            lock.round.encode(&mut bytes);
            lock.block_hash.encode(&mut bytes);
            lock.value_hash.encode(&mut bytes);
            let proposal = lock.proposal.encode_to_vec();
            (proposal.len() as u32).encode(&mut bytes);
            bytes.extend_from_slice(&proposal);
            (lock.polc_votes.len() as u32).encode(&mut bytes);
            for vote in &lock.polc_votes {
                let encoded = vote.encode_to_vec();
                (encoded.len() as u32).encode(&mut bytes);
                bytes.extend_from_slice(&encoded);
            }
        }
    }
    bytes
}

fn decode_record(bytes: &[u8]) -> Result<VoteSafetyRecord, String> {
    let mut reader = ByteReader::new(bytes);
    let version = u8::decode(&mut reader).map_err(|error| error.to_string())?;
    if version != SAFETY_FORMAT_VERSION {
        return Err(format!("unsupported safety format version {version}"));
    }
    let height = u64::decode(&mut reader).map_err(|error| error.to_string())?;
    let round =
        validate_consensus_round(u32::decode(&mut reader).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let step = u8::decode(&mut reader).map_err(|error| error.to_string())?;
    if step > 1 {
        return Err(format!("invalid vote step {step}"));
    }
    let consensus_lock = match u8::decode(&mut reader).map_err(|error| error.to_string())? {
        0 => None,
        1 => {
            let lock_height = u64::decode(&mut reader).map_err(|error| error.to_string())?;
            let lock_round = validate_consensus_round(
                u32::decode(&mut reader).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let block_hash = Bytes32::decode(&mut reader).map_err(|error| error.to_string())?;
            let value_hash = Bytes32::decode(&mut reader).map_err(|error| error.to_string())?;
            let block_len = u32::decode(&mut reader).map_err(|error| error.to_string())? as usize;
            let proposal = BlockProposalVNext::decode_exact(
                reader
                    .read_bytes(block_len)
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let count = u32::decode(&mut reader).map_err(|error| error.to_string())? as usize;
            if count == 0 || count > MAX_PERSISTED_POLC_VOTES {
                return Err(format!("invalid PoLC vote count {count}"));
            }
            let mut polc_votes = Vec::with_capacity(count);
            for _ in 0..count {
                let len = u32::decode(&mut reader).map_err(|error| error.to_string())? as usize;
                let vote_bytes = reader.read_bytes(len).map_err(|error| error.to_string())?;
                polc_votes
                    .push(VoteV1::decode_exact(vote_bytes).map_err(|error| error.to_string())?);
            }
            if polc_votes.iter().any(|vote| vote.round != lock_round) {
                return Err("persisted PoLC vote round differs from lock round".into());
            }
            Some(PersistedConsensusLock {
                height: lock_height,
                round: lock_round,
                block_hash,
                value_hash,
                proposal,
                polc_votes,
            })
        }
        flag => return Err(format!("invalid lock presence flag {flag}")),
    };
    if reader.remaining() != 0 {
        return Err(format!(
            "trailing safety record bytes: {}",
            reader.remaining()
        ));
    }
    Ok(VoteSafetyRecord {
        height,
        round,
        step,
        consensus_lock,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "indra_vote_safety_{name}_{}.dat",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("tmp"));
        path
    }

    #[test]
    fn record_and_load_round_trip() {
        let path = tmp_path("round_trip");
        let store = VoteSafetyStore::open(&path);
        store.record(42, 7, 0, None).unwrap();
        let VoteSafetyLoadResult::Record(loaded) = store.load() else {
            panic!("expected record")
        };
        assert_eq!((loaded.height, loaded.round, loaded.step), (42, 7, 0));
        assert!(loaded.consensus_lock.is_none());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn same_signing_slot_is_rejected_on_second_record() {
        let path = tmp_path("same_slot");
        let store = VoteSafetyStore::open(&path);
        store.record(1, 0, 0, None).unwrap();
        assert!(store.record(1, 0, 0, None).is_err());
        assert!(store.record(1, 0, 1, None).is_ok());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn signing_slot_ordering_matrix() {
        let path = tmp_path("matrix");
        let store = VoteSafetyStore::open(&path);
        assert!(store.record(10, 5, 0, None).is_ok());
        assert!(store.record(10, 5, 0, None).is_err());
        assert!(store.record(10, 5, 1, None).is_ok());
        assert!(store.record(10, 5, 0, None).is_err());
        assert!(store.record(10, 4, 1, None).is_err());
        assert!(store.record(9, 9, 1, None).is_err());
        assert!(store.record(10, 6, 0, None).is_ok());
        assert!(store.record(11, 0, 0, None).is_ok());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn unsupported_format_is_rejected_without_alternate_decoder() {
        let path = tmp_path("old_format");
        fs::write(&path, [0u8; 17]).unwrap();
        let store = VoteSafetyStore::open(&path);
        assert!(matches!(store.load(), VoteSafetyLoadResult::Corrupt(_)));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_nonexistent_returns_none() {
        assert_eq!(
            VoteSafetyStore::open(tmp_path("none")).load(),
            VoteSafetyLoadResult::NoRecord
        );
    }

    #[test]
    fn corrupt_crc_returns_corrupt() {
        let path = tmp_path("corrupt");
        let store = VoteSafetyStore::open(&path);
        store.record(1, 1, 0, None).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[1] ^= 0xff;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(store.load(), VoteSafetyLoadResult::Corrupt(_)));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn records_are_atomic_rename() {
        let path = tmp_path("atomic");
        let store = VoteSafetyStore::open(&path);
        store.record(1, 0, 0, None).unwrap();
        store.record(1, 1, 1, None).unwrap();
        let VoteSafetyLoadResult::Record(loaded) = store.load() else {
            panic!("expected record")
        };
        assert_eq!((loaded.round, loaded.step), (1, 1));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn higher_round_precommit_persisted() {
        let path = tmp_path("precommit");
        let store = VoteSafetyStore::open(&path);
        store.record(100, 15, 1, None).unwrap();
        let VoteSafetyLoadResult::Record(loaded) = store.load() else {
            panic!("expected valid vote safety record")
        };
        assert_eq!((loaded.height, loaded.round, loaded.step), (100, 15, 1));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn vote_safety_enforces_finite_round_domain_on_write_and_load() {
        let path = tmp_path("round_domain");
        let store = VoteSafetyStore::open(&path);
        for round in [0, indra_core::types::primitives::MAX_ROUNDS_PER_HEIGHT - 1] {
            store.record(1, round, 0, None).unwrap();
            assert!(matches!(
                store.load(),
                VoteSafetyLoadResult::Record(record) if record.round == round
            ));
        }
        for round in [
            indra_core::types::primitives::MAX_ROUNDS_PER_HEIGHT,
            indra_core::types::primitives::MAX_ROUNDS_PER_HEIGHT + 1,
            u32::MAX,
        ] {
            let error = store.record(1, round, 0, None).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "I/O error: invalid consensus round {round}; maximum legal round is {}",
                    indra_core::types::primitives::MAX_ROUNDS_PER_HEIGHT - 1
                )
            );

            // Recompute the CRC so this exercises semantic persisted-state
            // validation rather than corrupted-byte handling.
            let record = VoteSafetyRecord {
                height: 1,
                round,
                step: 0,
                consensus_lock: None,
            };
            let mut bytes = encode_record(&record);
            bytes.extend_from_slice(&crc32(&bytes).to_le_bytes());
            fs::write(&path, bytes).unwrap();
            assert!(matches!(store.load(), VoteSafetyLoadResult::Corrupt(_)));
        }
        let _ = fs::remove_file(path);
    }
}
