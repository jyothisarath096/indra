//! Canonical epoch-start commission and delegation snapshots for reward payout.

use crate::{
    codec::{decode_list, encode_list, list_encoded_len, ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    types::primitives::{Bytes32, MAX_ACTIVE_VALIDATORS},
};
use indra_crypto::sha256;

/// Canonical wire/root format version.
pub const REWARD_ECONOMIC_SNAPSHOT_FORMAT_VERSION: u8 = 1;
/// Domain separator for the snapshot's internal audit root.
pub const REWARD_ECONOMIC_SNAPSHOT_ROOT_DOMAIN: &[u8] = b"INDRA-REWARD-ECONOMIC-SNAPSHOT-v1";
/// Consensus ceiling for delegators recorded under one rewarded validator.
pub const MAX_REWARD_DELEGATORS_PER_VALIDATOR: usize = 100_000;

/// One identity's two independently credited epoch-start reward principals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardEconomicDelegatorEntry {
    /// Identity that owns both possible reward channels.
    pub delegator_id: Bytes32,
    /// Real bonded principal credited to `DelegatorEntry.pending_rewards`.
    pub bonded_active_principal_spark: u64,
    /// Virtual auto-delegated principal credited to `ValidatorEntry.pending_rewards`.
    pub auto_delegated_principal_spark: u64,
}

impl RewardEconomicDelegatorEntry {
    /// Construct an entry with at least one positive reward principal.
    pub fn new(
        delegator_id: Bytes32,
        bonded_active_principal_spark: u64,
        auto_delegated_principal_spark: u64,
    ) -> IndraResult<Self> {
        let entry = Self {
            delegator_id,
            bonded_active_principal_spark,
            auto_delegated_principal_spark,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Checked sum of bonded and virtual principal.
    pub fn total_active_principal_spark(&self) -> IndraResult<u64> {
        self.bonded_active_principal_spark
            .checked_add(self.auto_delegated_principal_spark)
            .ok_or_else(|| invalid_error("delegator principal overflows u64".to_string()))
    }

    /// Validate positive, non-overflowing combined principal.
    pub fn validate(&self) -> IndraResult<()> {
        if self.total_active_principal_spark()? == 0 {
            return invalid("delegator combined principal is zero");
        }
        Ok(())
    }
}

impl Encode for RewardEconomicDelegatorEntry {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.delegator_id.encode(buf);
        self.bonded_active_principal_spark.encode(buf);
        self.auto_delegated_principal_spark.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        48
    }
}

impl Decode for RewardEconomicDelegatorEntry {
    fn decode(reader: &mut ByteReader<'_>) -> IndraResult<Self> {
        Self::new(
            Bytes32::decode(reader)?,
            u64::decode(reader)?,
            u64::decode(reader)?,
        )
    }
}

/// Frozen commission and per-identity split for one consensus validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardEconomicValidatorEntry {
    /// Validator identity paired with consensus-snapshot membership.
    pub validator_id: Bytes32,
    /// Commission in force at snapshot creation.
    pub commission_bps: u32,
    /// Checked sum of all nested bonded and auto-delegated principal.
    pub total_active_delegated_spark: u64,
    delegators: Vec<RewardEconomicDelegatorEntry>,
}

impl RewardEconomicValidatorEntry {
    /// Construct a canonical validator entry.
    pub fn new(
        validator_id: Bytes32,
        commission_bps: u32,
        delegators: Vec<RewardEconomicDelegatorEntry>,
        max_commission_bps_at_creation: u32,
    ) -> IndraResult<Self> {
        let total_active_delegated_spark = recompute_delegated_total(&delegators)?;
        let entry = Self {
            validator_id,
            commission_bps,
            total_active_delegated_spark,
            delegators,
        };
        entry.validate(max_commission_bps_at_creation)?;
        Ok(entry)
    }

    /// Canonically ordered identities participating in the delegator pool.
    pub fn delegators(&self) -> &[RewardEconomicDelegatorEntry] {
        &self.delegators
    }

    /// Validate ordering, commission, positivity, and stored total.
    pub fn validate(&self, max_commission_bps_at_creation: u32) -> IndraResult<()> {
        if max_commission_bps_at_creation > 10_000 {
            return invalid("stored maximum commission exceeds 10,000 bps");
        }
        if self.commission_bps > max_commission_bps_at_creation {
            return invalid("validator commission exceeds frozen governance bound");
        }
        if self.delegators.len() > MAX_REWARD_DELEGATORS_PER_VALIDATOR {
            return Err(IndraError::LengthExceeded {
                field: "reward_economic_snapshot.delegators",
                max: MAX_REWARD_DELEGATORS_PER_VALIDATOR,
                actual: self.delegators.len(),
            });
        }
        for (index, delegator) in self.delegators.iter().enumerate() {
            delegator.validate()?;
            if index > 0 && self.delegators[index - 1].delegator_id >= delegator.delegator_id {
                return invalid("delegator IDs are duplicate or not strictly ascending");
            }
        }
        if self.total_active_delegated_spark != recompute_delegated_total(&self.delegators)? {
            return invalid("stored delegated total does not match recomputation");
        }
        Ok(())
    }
}

impl Encode for RewardEconomicValidatorEntry {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.validator_id.encode(buf);
        self.commission_bps.encode(buf);
        self.total_active_delegated_spark.encode(buf);
        encode_list(&self.delegators, buf);
    }

    fn encoded_len(&self) -> usize {
        32 + 4 + 8 + list_encoded_len(&self.delegators)
    }
}

impl Decode for RewardEconomicValidatorEntry {
    fn decode(reader: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            validator_id: Bytes32::decode(reader)?,
            commission_bps: u32::decode(reader)?,
            total_active_delegated_spark: u64::decode(reader)?,
            delegators: decode_list(
                reader,
                MAX_REWARD_DELEGATORS_PER_VALIDATOR,
                "reward_economic_snapshot.delegators",
            )?,
        })
    }
}

/// Immutable economic reward basis for one accruing epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardEconomicSnapshot {
    /// Snapshot wire/root format version.
    pub format_version: u8,
    /// First height whose epoch accrual uses this basis.
    pub activation_height: u64,
    /// Boundary whose settled state produced this basis.
    pub source_boundary_height: u64,
    /// Governance commission ceiling frozen with this snapshot.
    pub max_commission_bps_at_creation: u32,
    validators: Vec<RewardEconomicValidatorEntry>,
    /// Domain-separated commitment to all other fields.
    pub snapshot_root: Bytes32,
}

impl RewardEconomicSnapshot {
    /// Construct and validate a canonical economic snapshot.
    pub fn new(
        activation_height: u64,
        source_boundary_height: u64,
        max_commission_bps_at_creation: u32,
        validators: Vec<RewardEconomicValidatorEntry>,
    ) -> IndraResult<Self> {
        let snapshot_root = compute_snapshot_root(
            REWARD_ECONOMIC_SNAPSHOT_FORMAT_VERSION,
            activation_height,
            source_boundary_height,
            max_commission_bps_at_creation,
            &validators,
        );
        let snapshot = Self {
            format_version: REWARD_ECONOMIC_SNAPSHOT_FORMAT_VERSION,
            activation_height,
            source_boundary_height,
            max_commission_bps_at_creation,
            validators,
            snapshot_root,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Canonically ordered validator entries.
    pub fn validators(&self) -> &[RewardEconomicValidatorEntry] {
        &self.validators
    }

    /// Resolve one validator by canonical identity.
    pub fn validator(&self, id: &Bytes32) -> Option<&RewardEconomicValidatorEntry> {
        self.validators
            .binary_search_by_key(&id.0, |entry| entry.validator_id.0)
            .ok()
            .map(|position| &self.validators[position])
    }

    /// Validate format, ordering, nested entries, bound, and audit root.
    pub fn validate(&self) -> IndraResult<()> {
        if self.format_version != REWARD_ECONOMIC_SNAPSHOT_FORMAT_VERSION {
            return invalid("unsupported reward economic snapshot format version");
        }
        if self.max_commission_bps_at_creation > 10_000 {
            return invalid("stored maximum commission exceeds 10,000 bps");
        }
        if self.validators.is_empty() {
            return invalid("reward economic snapshot is empty");
        }
        if self.validators.len() > MAX_ACTIVE_VALIDATORS {
            return Err(IndraError::LengthExceeded {
                field: "reward_economic_snapshot.validators",
                max: MAX_ACTIVE_VALIDATORS,
                actual: self.validators.len(),
            });
        }
        for (index, validator) in self.validators.iter().enumerate() {
            validator.validate(self.max_commission_bps_at_creation)?;
            if index > 0 && self.validators[index - 1].validator_id >= validator.validator_id {
                return invalid("validator IDs are duplicate or not strictly ascending");
            }
        }
        let root = compute_snapshot_root(
            self.format_version,
            self.activation_height,
            self.source_boundary_height,
            self.max_commission_bps_at_creation,
            &self.validators,
        );
        if self.snapshot_root != root {
            return invalid("stored reward economic snapshot root does not match recomputation");
        }
        Ok(())
    }
}

impl Encode for RewardEconomicSnapshot {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.format_version.encode(buf);
        self.activation_height.encode(buf);
        self.source_boundary_height.encode(buf);
        self.max_commission_bps_at_creation.encode(buf);
        encode_list(&self.validators, buf);
        self.snapshot_root.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        1 + 8 + 8 + 4 + list_encoded_len(&self.validators) + 32
    }
}

impl Decode for RewardEconomicSnapshot {
    fn decode(reader: &mut ByteReader<'_>) -> IndraResult<Self> {
        let snapshot = Self {
            format_version: u8::decode(reader)?,
            activation_height: u64::decode(reader)?,
            source_boundary_height: u64::decode(reader)?,
            max_commission_bps_at_creation: u32::decode(reader)?,
            validators: decode_list(
                reader,
                MAX_ACTIVE_VALIDATORS,
                "reward_economic_snapshot.validators",
            )?,
            snapshot_root: Bytes32::decode(reader)?,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }
}

fn recompute_delegated_total(entries: &[RewardEconomicDelegatorEntry]) -> IndraResult<u64> {
    entries.iter().try_fold(0u64, |total, entry| {
        total
            .checked_add(entry.total_active_principal_spark()?)
            .ok_or_else(|| invalid_error("reward economic delegated total overflows u64".into()))
    })
}

fn compute_snapshot_root(
    format_version: u8,
    activation_height: u64,
    source_boundary_height: u64,
    max_commission_bps_at_creation: u32,
    validators: &[RewardEconomicValidatorEntry],
) -> Bytes32 {
    let mut material = Vec::with_capacity(
        REWARD_ECONOMIC_SNAPSHOT_ROOT_DOMAIN.len() + 1 + 8 + 8 + 4 + list_encoded_len(validators),
    );
    material.extend_from_slice(REWARD_ECONOMIC_SNAPSHOT_ROOT_DOMAIN);
    format_version.encode(&mut material);
    activation_height.encode(&mut material);
    source_boundary_height.encode(&mut material);
    max_commission_bps_at_creation.encode(&mut material);
    encode_list(validators, &mut material);
    Bytes32::from(sha256(&material))
}

fn invalid<T>(reason: impl Into<String>) -> IndraResult<T> {
    Err(invalid_error(reason.into()))
}

fn invalid_error(reason: String) -> IndraError {
    IndraError::InvalidRewardEconomicSnapshot(reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delegator(id: u8, bonded: u64, auto: u64) -> RewardEconomicDelegatorEntry {
        RewardEconomicDelegatorEntry::new(Bytes32::from([id; 32]), bonded, auto).unwrap()
    }

    fn validator(id: u8) -> RewardEconomicValidatorEntry {
        RewardEconomicValidatorEntry::new(
            Bytes32::from([id; 32]),
            1_000,
            vec![delegator(id + 10, 60, 40)],
            2_000,
        )
        .unwrap()
    }

    #[test]
    fn round_trip_and_domain_oracle() {
        let snapshot = RewardEconomicSnapshot::new(301, 300, 2_000, vec![validator(1)]).unwrap();
        assert_eq!(
            RewardEconomicSnapshot::decode_exact(&snapshot.encode_to_vec()).unwrap(),
            snapshot
        );
        assert_eq!(
            snapshot.snapshot_root,
            compute_snapshot_root(1, 301, 300, 2_000, snapshot.validators())
        );
    }

    #[test]
    fn split_principal_and_commission_invariants_fail_closed() {
        assert!(RewardEconomicDelegatorEntry::new(Bytes32::ZERO, 0, 0).is_err());
        assert!(RewardEconomicDelegatorEntry::new(Bytes32::ZERO, u64::MAX, 1).is_err());
        assert!(RewardEconomicValidatorEntry::new(
            Bytes32::from([1; 32]),
            2_001,
            vec![delegator(2, 1, 0)],
            2_000,
        )
        .is_err());
        assert!(RewardEconomicSnapshot::new(301, 300, 10_001, vec![validator(1)]).is_err());
    }

    #[test]
    fn ordering_and_stored_total_are_canonical() {
        let unsorted = vec![delegator(3, 1, 0), delegator(2, 1, 0)];
        assert!(
            RewardEconomicValidatorEntry::new(Bytes32::from([1; 32]), 1_000, unsorted, 2_000,)
                .is_err()
        );

        let valid = RewardEconomicSnapshot::new(301, 300, 2_000, vec![validator(1)]).unwrap();
        let mut bytes = valid.encode_to_vec();
        // total_active_delegated_spark begins after snapshot header/list prefix,
        // validator ID, and commission.
        let total_offset = 1 + 8 + 8 + 4 + 4 + 32 + 4;
        bytes[total_offset..total_offset + 8].copy_from_slice(&999u64.to_le_bytes());
        assert!(RewardEconomicSnapshot::decode_exact(&bytes).is_err());
    }

    #[test]
    fn root_is_sensitive_to_frozen_bound_and_each_principal_channel() {
        let base = RewardEconomicSnapshot::new(301, 300, 2_000, vec![validator(1)]).unwrap();
        let bound = RewardEconomicSnapshot::new(301, 300, 2_001, vec![validator(1)]).unwrap();
        let changed = RewardEconomicValidatorEntry::new(
            Bytes32::from([1; 32]),
            1_000,
            vec![delegator(11, 59, 41)],
            2_000,
        )
        .unwrap();
        let principal = RewardEconomicSnapshot::new(301, 300, 2_000, vec![changed]).unwrap();
        assert_ne!(base.snapshot_root, bound.snapshot_root);
        assert_ne!(base.snapshot_root, principal.snapshot_root);
    }
}
