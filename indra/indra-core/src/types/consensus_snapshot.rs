//! Canonical, versioned consensus membership and weight snapshots.

use crate::{
    codec::{decode_list, encode_list, list_encoded_len, ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    types::primitives::{Bytes32, MAX_ACTIVE_VALIDATORS},
};
use indra_crypto::{
    sha256, validate_classical_public_key, validate_pq_public_key, validate_vrf_public_key,
    ClassicalPublicKey, PqPublicKey, PQ_PK_BYTES,
};

/// Consensus snapshot wire and root format version.
pub const CONSENSUS_SNAPSHOT_FORMAT_VERSION: u8 = 1;
/// Domain separator for the canonical snapshot root.
pub const CONSENSUS_SNAPSHOT_ROOT_DOMAIN: &[u8] = b"INDRA-CONSENSUS-SNAPSHOT-v1";

/// One immutable member of a consensus snapshot.
///
/// Bitfield position is deliberately absent: it is always the entry's index in
/// the snapshot's canonical ascending-validator-ID list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusSnapshotEntry {
    /// Validator identity.
    pub validator_id: Bytes32,
    /// Frozen consensus weight in Spark.
    pub consensus_weight_spark: u64,
    /// Ed25519 vote verification key.
    pub classical_vote_pk: [u8; 32],
    /// ML-DSA-87 vote verification key.
    pub pq_vote_pk: [u8; PQ_PK_BYTES],
    /// Ristretto VRF verification key.
    pub vrf_pk: [u8; 32],
}

impl ConsensusSnapshotEntry {
    /// Construct and validate a snapshot entry.
    pub fn new(
        validator_id: Bytes32,
        consensus_weight_spark: u64,
        classical_vote_pk: [u8; 32],
        pq_vote_pk: [u8; PQ_PK_BYTES],
        vrf_pk: [u8; 32],
    ) -> IndraResult<Self> {
        let entry = Self {
            validator_id,
            consensus_weight_spark,
            classical_vote_pk,
            pq_vote_pk,
            vrf_pk,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Validate weight and all consensus public keys.
    pub fn validate(&self) -> IndraResult<()> {
        if self.consensus_weight_spark == 0 {
            return invalid("entry has zero consensus weight");
        }
        validate_classical_public_key(&ClassicalPublicKey(self.classical_vote_pk))
            .map_err(|err| invalid_error(format!("malformed Ed25519 vote key: {err}")))?;
        validate_pq_public_key(&PqPublicKey(self.pq_vote_pk.clone()))
            .map_err(|err| invalid_error(format!("malformed ML-DSA-87 vote key: {err}")))?;
        validate_vrf_public_key(&self.vrf_pk)
            .map_err(|err| invalid_error(format!("malformed VRF key: {err}")))?;
        Ok(())
    }
}

impl Encode for ConsensusSnapshotEntry {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.validator_id.encode(buf);
        self.consensus_weight_spark.encode(buf);
        buf.extend_from_slice(&self.classical_vote_pk);
        buf.extend_from_slice(&self.pq_vote_pk);
        buf.extend_from_slice(&self.vrf_pk);
    }

    fn encoded_len(&self) -> usize {
        32 + 8 + 32 + PQ_PK_BYTES + 32
    }
}

impl Decode for ConsensusSnapshotEntry {
    fn decode(reader: &mut ByteReader<'_>) -> IndraResult<Self> {
        let entry = Self {
            validator_id: Bytes32::decode(reader)?,
            consensus_weight_spark: u64::decode(reader)?,
            classical_vote_pk: read_array::<32>(reader)?,
            pq_vote_pk: read_array::<PQ_PK_BYTES>(reader)?,
            vrf_pk: read_array::<32>(reader)?,
        };
        entry.validate()?;
        Ok(entry)
    }
}

/// Immutable consensus membership and weights for a height interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusSnapshot {
    /// Snapshot format version.
    pub format_version: u8,
    /// First consensus height governed by this snapshot.
    pub activation_height: u64,
    /// Boundary height whose final state selected this snapshot.
    pub source_boundary_height: u64,
    entries: Vec<ConsensusSnapshotEntry>,
    /// Canonical sum of all member weights.
    pub total_weight_spark: u64,
    /// Domain-separated commitment to all snapshot content except this field.
    pub snapshot_root: Bytes32,
}

impl ConsensusSnapshot {
    /// Construct and validate a canonical snapshot.
    pub fn new(
        activation_height: u64,
        source_boundary_height: u64,
        entries: Vec<ConsensusSnapshotEntry>,
    ) -> IndraResult<Self> {
        let total_weight_spark = recompute_total(&entries)?;
        let snapshot_root = compute_snapshot_root(
            CONSENSUS_SNAPSHOT_FORMAT_VERSION,
            activation_height,
            source_boundary_height,
            &entries,
            total_weight_spark,
        );
        let snapshot = Self {
            format_version: CONSENSUS_SNAPSHOT_FORMAT_VERSION,
            activation_height,
            source_boundary_height,
            entries,
            total_weight_spark,
            snapshot_root,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Canonically ordered entries.
    pub fn entries(&self) -> &[ConsensusSnapshotEntry] {
        &self.entries
    }

    /// Entry and canonical signer-bitfield position for `validator_id`.
    pub fn entry_with_position(
        &self,
        validator_id: &Bytes32,
    ) -> Option<(usize, &ConsensusSnapshotEntry)> {
        self.entries
            .binary_search_by_key(&validator_id.0, |entry| entry.validator_id.0)
            .ok()
            .map(|position| (position, &self.entries[position]))
    }

    /// Validate all canonical content and stored derived fields.
    pub fn validate(&self) -> IndraResult<()> {
        if self.format_version != CONSENSUS_SNAPSHOT_FORMAT_VERSION {
            return invalid("unsupported snapshot format version");
        }
        if self.entries.is_empty() {
            return invalid("snapshot is empty");
        }
        if self.entries.len() > MAX_ACTIVE_VALIDATORS {
            return Err(IndraError::LengthExceeded {
                field: "consensus_snapshot.entries",
                max: MAX_ACTIVE_VALIDATORS,
                actual: self.entries.len(),
            });
        }
        for (index, entry) in self.entries.iter().enumerate() {
            entry.validate()?;
            if index > 0 && self.entries[index - 1].validator_id >= entry.validator_id {
                return invalid("validator IDs are duplicate or not strictly ascending");
            }
        }
        let recomputed_total = recompute_total(&self.entries)?;
        if self.total_weight_spark != recomputed_total {
            return invalid("stored total weight does not match recomputation");
        }
        let recomputed_root = compute_snapshot_root(
            self.format_version,
            self.activation_height,
            self.source_boundary_height,
            &self.entries,
            self.total_weight_spark,
        );
        if self.snapshot_root != recomputed_root {
            return invalid("stored snapshot root does not match recomputation");
        }
        Ok(())
    }
}

impl Encode for ConsensusSnapshot {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.format_version.encode(buf);
        self.activation_height.encode(buf);
        self.source_boundary_height.encode(buf);
        encode_list(&self.entries, buf);
        self.total_weight_spark.encode(buf);
        self.snapshot_root.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        1 + 8 + 8 + list_encoded_len(&self.entries) + 8 + 32
    }
}

impl Decode for ConsensusSnapshot {
    fn decode(reader: &mut ByteReader<'_>) -> IndraResult<Self> {
        let snapshot = Self {
            format_version: u8::decode(reader)?,
            activation_height: u64::decode(reader)?,
            source_boundary_height: u64::decode(reader)?,
            entries: decode_list(reader, MAX_ACTIVE_VALIDATORS, "consensus_snapshot.entries")?,
            total_weight_spark: u64::decode(reader)?,
            snapshot_root: Bytes32::decode(reader)?,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }
}

fn recompute_total(entries: &[ConsensusSnapshotEntry]) -> IndraResult<u64> {
    entries.iter().try_fold(0u64, |total, entry| {
        total
            .checked_add(entry.consensus_weight_spark)
            .ok_or_else(|| {
                invalid_error("consensus snapshot total weight overflows u64".to_string())
            })
    })
}

fn compute_snapshot_root(
    format_version: u8,
    activation_height: u64,
    source_boundary_height: u64,
    entries: &[ConsensusSnapshotEntry],
    total_weight_spark: u64,
) -> Bytes32 {
    let mut material = Vec::with_capacity(
        CONSENSUS_SNAPSHOT_ROOT_DOMAIN.len() + 1 + 8 + 8 + list_encoded_len(entries) + 8,
    );
    material.extend_from_slice(CONSENSUS_SNAPSHOT_ROOT_DOMAIN);
    format_version.encode(&mut material);
    activation_height.encode(&mut material);
    source_boundary_height.encode(&mut material);
    encode_list(entries, &mut material);
    total_weight_spark.encode(&mut material);
    Bytes32::from(sha256(&material))
}

fn read_array<const N: usize>(reader: &mut ByteReader<'_>) -> IndraResult<[u8; N]> {
    reader
        .read_bytes(N)?
        .try_into()
        .map_err(|_| invalid_error("fixed-length snapshot key has wrong length".to_string()))
}

fn invalid<T>(reason: impl Into<String>) -> IndraResult<T> {
    Err(invalid_error(reason.into()))
}

fn invalid_error(reason: String) -> IndraError {
    IndraError::InvalidConsensusSnapshot(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::primitives::{
        consensus_snapshot_active, consensus_snapshot_height_is_aligned,
        hard_forks::CONSENSUS_SNAPSHOT_HEIGHT, EPOCH_DURATION_BLOCKS,
    };
    use indra_crypto::{ClassicalKeypair, PqKeypair, VrfKeypair};

    fn entry(id: u8, weight: u64, key_seed: u8) -> ConsensusSnapshotEntry {
        let classical = ClassicalKeypair::from_seed(&[key_seed; 32]);
        let pq = PqKeypair::from_seed(&[key_seed; 32]).unwrap();
        let vrf = VrfKeypair::from_seed(&[key_seed; 32]);
        let public = indra_crypto::HybridKeypair::new(classical, pq).public_key();
        ConsensusSnapshotEntry::new(
            Bytes32::from([id; 32]),
            weight,
            public.classical.0,
            public.pq.0,
            vrf.public_key(),
        )
        .unwrap()
    }

    fn snapshot() -> ConsensusSnapshot {
        ConsensusSnapshot::new(301, 300, vec![entry(1, 1_000, 11), entry(2, 2_000, 12)]).unwrap()
    }

    fn raw_snapshot(entries: Vec<ConsensusSnapshotEntry>) -> ConsensusSnapshot {
        let total_weight_spark = entries
            .iter()
            .map(|entry| entry.consensus_weight_spark)
            .sum();
        let snapshot_root = compute_snapshot_root(
            CONSENSUS_SNAPSHOT_FORMAT_VERSION,
            301,
            300,
            &entries,
            total_weight_spark,
        );
        ConsensusSnapshot {
            format_version: CONSENSUS_SNAPSHOT_FORMAT_VERSION,
            activation_height: 301,
            source_boundary_height: 300,
            entries,
            total_weight_spark,
            snapshot_root,
        }
    }

    #[test]
    fn entry_and_snapshot_construct_and_round_trip() {
        let original_entry = entry(1, 1_000, 11);
        let entry_bytes = original_entry.encode_to_vec();
        assert_eq!(
            ConsensusSnapshotEntry::decode_exact(&entry_bytes).unwrap(),
            original_entry
        );

        let original_snapshot = snapshot();
        assert_eq!(original_snapshot.total_weight_spark, 3_000);
        let bytes = original_snapshot.encode_to_vec();
        assert_eq!(bytes.len(), original_snapshot.encoded_len());
        let decoded = ConsensusSnapshot::decode_exact(&bytes).unwrap();
        assert_eq!(decoded, original_snapshot);
        decoded.validate().unwrap();
    }

    #[test]
    fn rejects_empty_snapshot() {
        assert!(ConsensusSnapshot::new(301, 300, vec![]).is_err());
    }

    #[test]
    fn rejects_duplicate_validator_ids() {
        assert!(
            ConsensusSnapshot::new(301, 300, vec![entry(1, 1_000, 11), entry(1, 2_000, 12)])
                .is_err()
        );
    }

    #[test]
    fn rejects_non_strict_validator_order() {
        assert!(
            ConsensusSnapshot::new(301, 300, vec![entry(2, 2_000, 12), entry(1, 1_000, 11)])
                .is_err()
        );
    }

    #[test]
    fn rejects_zero_weight() {
        let mut zero = entry(1, 1_000, 11);
        zero.consensus_weight_spark = 0;
        assert!(ConsensusSnapshot::new(301, 300, vec![zero]).is_err());
        assert!(ConsensusSnapshotEntry::new(
            Bytes32::from([1; 32]),
            0,
            entry(2, 1, 12).classical_vote_pk,
            entry(2, 1, 12).pq_vote_pk,
            entry(2, 1, 12).vrf_pk,
        )
        .is_err());
    }

    #[test]
    fn rejects_malformed_or_missing_ed25519_key() {
        let mut malformed = entry(1, 1_000, 11);
        malformed.classical_vote_pk = [0; 32];
        assert!(ConsensusSnapshot::new(301, 300, vec![malformed]).is_err());
    }

    #[test]
    fn rejects_malformed_or_missing_ml_dsa_key() {
        let mut malformed = entry(1, 1_000, 11);
        malformed.pq_vote_pk = [0; PQ_PK_BYTES];
        assert!(ConsensusSnapshot::new(301, 300, vec![malformed]).is_err());
    }

    #[test]
    fn rejects_malformed_or_missing_vrf_key() {
        let mut malformed = entry(1, 1_000, 11);
        malformed.vrf_pk = [0; 32];
        assert!(ConsensusSnapshot::new(301, 300, vec![malformed]).is_err());
    }

    #[test]
    fn rejects_truncated_fixed_length_key_encoding() {
        let mut bytes = entry(1, 1_000, 11).encode_to_vec();
        bytes.pop();
        assert!(ConsensusSnapshotEntry::decode_exact(&bytes).is_err());
    }

    #[test]
    fn rejects_more_than_maximum_active_validators() {
        let template = entry(1, 1_000, 11);
        let entries = (0..=MAX_ACTIVE_VALIDATORS)
            .map(|index| {
                let mut candidate = template.clone();
                let mut id = [0u8; 32];
                id[24..].copy_from_slice(&(index as u64).to_be_bytes());
                candidate.validator_id = Bytes32::from(id);
                candidate
            })
            .collect();
        assert!(ConsensusSnapshot::new(301, 300, entries).is_err());
    }

    #[test]
    fn rejects_stored_total_mismatch() {
        let mut malformed = snapshot();
        malformed.total_weight_spark += 1;
        assert!(malformed.validate().is_err());
        assert!(ConsensusSnapshot::decode_exact(&malformed.encode_to_vec()).is_err());
    }

    #[test]
    fn rejects_stored_root_mismatch() {
        let mut malformed = snapshot();
        malformed.snapshot_root = Bytes32::from([0xFF; 32]);
        assert!(malformed.validate().is_err());
        assert!(ConsensusSnapshot::decode_exact(&malformed.encode_to_vec()).is_err());
    }

    #[test]
    fn rejects_total_weight_overflow() {
        assert!(
            ConsensusSnapshot::new(301, 300, vec![entry(1, u64::MAX, 11), entry(2, 1, 12)])
                .is_err()
        );
    }

    #[test]
    fn snapshot_root_matches_independent_domain_separated_oracle() {
        let snapshot = snapshot();
        let mut oracle = b"INDRA-CONSENSUS-SNAPSHOT-v1".to_vec();
        oracle.push(1);
        oracle.extend_from_slice(&301u64.to_le_bytes());
        oracle.extend_from_slice(&300u64.to_le_bytes());
        oracle.extend_from_slice(&(snapshot.entries().len() as u32).to_le_bytes());
        for entry in snapshot.entries() {
            oracle.extend_from_slice(&entry.validator_id.0);
            oracle.extend_from_slice(&entry.consensus_weight_spark.to_le_bytes());
            oracle.extend_from_slice(&entry.classical_vote_pk);
            oracle.extend_from_slice(&entry.pq_vote_pk);
            oracle.extend_from_slice(&entry.vrf_pk);
        }
        oracle.extend_from_slice(&3_000u64.to_le_bytes());
        assert_eq!(snapshot.snapshot_root, Bytes32::from(sha256(&oracle)));
    }

    #[test]
    fn snapshot_root_is_sensitive_to_every_field_and_entry_count() {
        let baseline = snapshot();
        let replacement_keys = entry(1, 1_000, 13);
        let mut roots = vec![baseline.snapshot_root];
        roots.push(compute_snapshot_root(
            2,
            301,
            300,
            baseline.entries(),
            3_000,
        ));
        roots.push(
            ConsensusSnapshot::new(601, 300, baseline.entries().to_vec())
                .unwrap()
                .snapshot_root,
        );
        roots.push(
            ConsensusSnapshot::new(301, 0, baseline.entries().to_vec())
                .unwrap()
                .snapshot_root,
        );
        roots.push(
            ConsensusSnapshot::new(301, 300, vec![entry(1, 1_001, 11), entry(2, 2_000, 12)])
                .unwrap()
                .snapshot_root,
        );
        let mut changed_classical = baseline.entries()[0].clone();
        changed_classical.classical_vote_pk = replacement_keys.classical_vote_pk;
        roots.push(
            ConsensusSnapshot::new(
                301,
                300,
                vec![changed_classical, baseline.entries()[1].clone()],
            )
            .unwrap()
            .snapshot_root,
        );
        let mut changed_pq = baseline.entries()[0].clone();
        changed_pq.pq_vote_pk = replacement_keys.pq_vote_pk;
        roots.push(
            ConsensusSnapshot::new(301, 300, vec![changed_pq, baseline.entries()[1].clone()])
                .unwrap()
                .snapshot_root,
        );
        let mut changed_vrf = baseline.entries()[0].clone();
        changed_vrf.vrf_pk = replacement_keys.vrf_pk;
        roots.push(
            ConsensusSnapshot::new(301, 300, vec![changed_vrf, baseline.entries()[1].clone()])
                .unwrap()
                .snapshot_root,
        );
        roots.push(
            ConsensusSnapshot::new(
                301,
                300,
                vec![
                    entry(1, 1_000, 11),
                    entry(2, 2_000, 12),
                    entry(3, 3_000, 13),
                ],
            )
            .unwrap()
            .snapshot_root,
        );
        roots.sort_by_key(|root| root.0);
        roots.dedup();
        assert_eq!(roots.len(), 9);
    }

    #[test]
    fn bitfield_position_is_always_canonical_list_index() {
        let snapshot = ConsensusSnapshot::new(
            301,
            300,
            vec![
                entry(1, 1_000, 11),
                entry(2, 2_000, 12),
                entry(3, 3_000, 13),
            ],
        )
        .unwrap();
        for (expected_position, entry) in snapshot.entries().iter().enumerate() {
            let (actual_position, found) =
                snapshot.entry_with_position(&entry.validator_id).unwrap();
            assert_eq!(actual_position, expected_position);
            assert_eq!(found, entry);
        }
        // Neither entry nor snapshot encoding contains an independently
        // writable position field; position is derived only by lookup/index.
        assert_eq!(
            snapshot.entries()[0].encoded_len(),
            32 + 8 + 32 + PQ_PK_BYTES + 32
        );
    }

    #[test]
    fn gate_is_inert_and_alignment_validation_is_exact() {
        assert_eq!(CONSENSUS_SNAPSHOT_HEIGHT, u64::MAX);
        assert!(!consensus_snapshot_active(0));
        assert!(!consensus_snapshot_active(u64::MAX - 1));
        assert!(consensus_snapshot_active(u64::MAX));

        assert!(consensus_snapshot_height_is_aligned(u64::MAX));
        assert!(consensus_snapshot_height_is_aligned(1));
        assert!(consensus_snapshot_height_is_aligned(
            EPOCH_DURATION_BLOCKS + 1
        ));
        assert!(consensus_snapshot_height_is_aligned(
            EPOCH_DURATION_BLOCKS * 2 + 1
        ));
        assert!(!consensus_snapshot_height_is_aligned(0));
        assert!(!consensus_snapshot_height_is_aligned(EPOCH_DURATION_BLOCKS));
        assert!(!consensus_snapshot_height_is_aligned(
            EPOCH_DURATION_BLOCKS + 2
        ));
    }

    #[test]
    fn raw_snapshot_helper_still_runs_full_validation() {
        let malformed = raw_snapshot(vec![entry(2, 1_000, 12), entry(1, 1_000, 11)]);
        assert!(malformed.validate().is_err());
    }
}
