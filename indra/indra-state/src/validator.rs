//! Validator set — the active set of staked validators.
//!
//! Tracks each validator's stake, status, and accumulated reward.
//! The validator set is snapshotted at each epoch boundary.

use std::collections::BTreeMap;

use indra_core::codec::{decode_list, encode_list, list_encoded_len, ByteReader, Decode, Encode};
use indra_core::error::{IndraError, IndraResult};
use indra_core::types::{
    primitives::{
        max_active_validators, muldiv, overflow_fix_active, Bytes32, DUST_LIMIT_SPARK,
        MAX_VALIDATORS, SCHEMA_VERSION, SCHEMA_VERSION_GENESIS,
    },
    transaction::OutputV1,
};

/// Lifecycle status of a validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorStatus {
    /// Registered: waiting for entry into the active set.
    Registered,
    /// Active: eligible to propose and vote.
    Active,
    /// Unbonding: initiated exit, stake locked until unbonding_end_epoch.
    Unbonding {
        /// Epoch at which the stake is released.
        unbonding_end_epoch: u64,
    },
    /// Slashed: permanently removed, stake partially or fully burned.
    Slashed,
    /// Exited: completed voluntary unbonding, no longer in active set.
    Exited,
}

impl Encode for ValidatorStatus {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Registered => 0u8.encode(buf),
            Self::Active => 1u8.encode(buf),
            Self::Unbonding {
                unbonding_end_epoch,
            } => {
                2u8.encode(buf);
                unbonding_end_epoch.encode(buf);
            }
            Self::Slashed => 3u8.encode(buf),
            Self::Exited => 4u8.encode(buf),
        }
    }

    fn encoded_len(&self) -> usize {
        match self {
            Self::Unbonding { .. } => 1 + 8,
            _ => 1,
        }
    }
}

impl Decode for ValidatorStatus {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        match u8::decode(r)? {
            0 => Ok(Self::Registered),
            1 => Ok(Self::Active),
            2 => Ok(Self::Unbonding {
                unbonding_end_epoch: u64::decode(r)?,
            }),
            3 => Ok(Self::Slashed),
            4 => Ok(Self::Exited),
            _ => Err(IndraError::InvariantViolation {
                message: "invalid validator status discriminator",
            }),
        }
    }
}

/// A single validator's entry in the validator set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorEntry {
    /// Validator identity: SHA-256(hybrid_public_key_bytes).
    pub validator_id: Bytes32,
    /// Human-readable validator display name.
    pub name: String,
    /// Ed25519 public key bytes for vote signature verification.
    pub hybrid_classical_pk: Option<[u8; 32]>,
    /// Dilithium public key bytes for vote signature verification.
    pub hybrid_pq_pk: Option<Vec<u8>>,
    /// VRF public key bytes for proposer verification.
    pub vrf_pk: Option<[u8; 32]>,
    /// Staked amount in Spark.
    pub stake_spark: u64,
    /// Current lifecycle status.
    pub status: ValidatorStatus,
    /// Epoch in which this validator was registered.
    pub registered_epoch: u64,
    /// Epoch in which this validator last cast a vote (for liveness tracking).
    pub last_active_epoch: u64,
    /// Accumulated unclaimed rewards in Spark.
    pub pending_rewards: u64,
    /// Epoch at which pending_rewards was last updated.
    pub rewards_last_epoch: u64,
    /// Number of self-reported bug slashes used (max 1 per lifetime).
    pub self_report_count: u32,
    /// Commission rate in basis points (e.g. 1000 = 10%).
    /// Bounded by [MIN_COMMISSION_BPS, MAX_COMMISSION_BPS].
    pub commission_bps: u32,
    /// Validator-specific minimum delegation amount in Spark.
    pub min_delegation_spark: u64,
    /// Optional target validator for epoch-scoped reward auto-delegation.
    pub auto_delegate_to: Option<Bytes32>,
}

impl Encode for ValidatorEntry {
    fn encode(&self, buf: &mut Vec<u8>) {
        SCHEMA_VERSION.encode(buf);
        self.validator_id.encode(buf);
        let name_bytes = self.name.as_bytes();
        (name_bytes.len() as u32).encode(buf);
        buf.extend_from_slice(name_bytes);
        self.hybrid_classical_pk.is_some().encode(buf);
        if let Some(pk) = self.hybrid_classical_pk {
            buf.extend_from_slice(&pk);
        }
        self.hybrid_pq_pk.is_some().encode(buf);
        if let Some(pk) = &self.hybrid_pq_pk {
            (pk.len() as u32).encode(buf);
            buf.extend_from_slice(pk);
        }
        self.vrf_pk.is_some().encode(buf);
        if let Some(pk) = self.vrf_pk {
            buf.extend_from_slice(&pk);
        }
        self.stake_spark.encode(buf);
        self.status.encode(buf);
        self.registered_epoch.encode(buf);
        self.last_active_epoch.encode(buf);
        self.pending_rewards.encode(buf);
        self.rewards_last_epoch.encode(buf);
        self.self_report_count.encode(buf);
        self.commission_bps.encode(buf);
        self.min_delegation_spark.encode(buf);
        self.auto_delegate_to.is_some().encode(buf);
        if let Some(target) = self.auto_delegate_to {
            target.encode(buf);
        }
    }

    fn encoded_len(&self) -> usize {
        32 + 4
            + self.name.len()
            + 1
            + self.hybrid_classical_pk.map(|_| 32).unwrap_or(0)
            + 1
            + self
                .hybrid_pq_pk
                .as_ref()
                .map(|pk| 4 + pk.len())
                .unwrap_or(0)
            + 1
            + self.vrf_pk.map(|_| 32).unwrap_or(0)
            + 8
            + self.status.encoded_len()
            + 8
            + 8
            + 8
            + 8
            + 4
            + 4
            + 8
            + 1
            + 1
            + self.auto_delegate_to.map(|_| 32).unwrap_or(0)
    }
}

impl Decode for ValidatorEntry {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let marker = u8::decode(r)?;
        match marker {
            SCHEMA_VERSION_GENESIS => decode_validator_entry_v1(r, None),
            SCHEMA_VERSION => decode_validator_entry_v2(r, None),
            other if r.remaining() == 0 => Err(unsupported_schema("ValidatorEntry", other)),
            first_byte => decode_validator_entry_v1(r, Some(first_byte)),
        }
    }
}

fn unsupported_schema(struct_name: &'static str, version: u8) -> IndraError {
    IndraError::UnsupportedSchemaVersion {
        struct_name,
        version,
        max_supported: SCHEMA_VERSION,
    }
}

fn decode_bytes32_with_first(
    r: &mut ByteReader<'_>,
    first_byte: Option<u8>,
) -> IndraResult<Bytes32> {
    match first_byte {
        Some(first) => {
            let mut bytes = [0u8; 32];
            bytes[0] = first;
            bytes[1..].copy_from_slice(r.read_bytes(31)?);
            Ok(Bytes32::from(bytes))
        }
        None => Bytes32::decode(r),
    }
}

fn decode_validator_entry_v1(
    r: &mut ByteReader<'_>,
    first_byte: Option<u8>,
) -> IndraResult<ValidatorEntry> {
    decode_validator_entry_fields(r, first_byte, false)
}

fn decode_validator_entry_v2(
    r: &mut ByteReader<'_>,
    first_byte: Option<u8>,
) -> IndraResult<ValidatorEntry> {
    decode_validator_entry_fields(r, first_byte, true)
}

impl ValidatorEntry {
    /// Decode the legacy unversioned schema V1 layout.
    pub fn decode_legacy_v1(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        decode_validator_entry_v1(r, None)
    }

    /// Decode the legacy unversioned schema V2 layout used before version bytes.
    pub fn decode_legacy_v2(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        decode_validator_entry_v2(r, None)
    }
}

fn decode_validator_entry_fields(
    r: &mut ByteReader<'_>,
    first_byte: Option<u8>,
    has_auto_delegate_to: bool,
) -> IndraResult<ValidatorEntry> {
    let validator_id = decode_bytes32_with_first(r, first_byte)?;
    let name_len = u32::decode(r)? as usize;
    let name_bytes = r.read_bytes(name_len)?;
    let name =
        String::from_utf8(name_bytes.to_vec()).map_err(|_| IndraError::InvariantViolation {
            message: "invalid UTF-8 validator name in snapshot",
        })?;

    let hybrid_classical_pk = if bool::decode(r)? {
        let bytes: [u8; 32] =
            r.read_bytes(32)?
                .try_into()
                .map_err(|_| IndraError::InvariantViolation {
                    message: "invalid classical pk length in snapshot",
                })?;
        Some(bytes)
    } else {
        None
    };

    let hybrid_pq_pk = if bool::decode(r)? {
        let len = u32::decode(r)? as usize;
        Some(r.read_bytes(len)?.to_vec())
    } else {
        None
    };

    let vrf_pk = if bool::decode(r)? {
        let bytes: [u8; 32] =
            r.read_bytes(32)?
                .try_into()
                .map_err(|_| IndraError::InvariantViolation {
                    message: "invalid vrf pk length in snapshot",
                })?;
        Some(bytes)
    } else {
        None
    };

    Ok(ValidatorEntry {
        validator_id,
        name,
        hybrid_classical_pk,
        hybrid_pq_pk,
        vrf_pk,
        stake_spark: u64::decode(r)?,
        status: ValidatorStatus::decode(r)?,
        registered_epoch: u64::decode(r)?,
        last_active_epoch: u64::decode(r)?,
        pending_rewards: u64::decode(r)?,
        rewards_last_epoch: u64::decode(r)?,
        self_report_count: u32::decode(r)?,
        commission_bps: u32::decode(r)?,
        min_delegation_spark: u64::decode(r)?,
        auto_delegate_to: if has_auto_delegate_to && bool::decode(r)? {
            Some(Bytes32::decode(r)?)
        } else {
            None
        },
    })
}

impl ValidatorEntry {
    /// True if this validator is currently active.
    pub fn is_active(&self) -> bool {
        matches!(self.status, ValidatorStatus::Active)
    }

    /// True if this validator's rewards have expired.
    ///
    /// Rewards expire if unclaimed after CLAIM_WINDOW_EPOCHS epochs.
    pub fn rewards_expired(&self, current_epoch: u64) -> bool {
        use indra_core::types::primitives::CLAIM_WINDOW_EPOCHS;
        current_epoch.saturating_sub(self.rewards_last_epoch) > CLAIM_WINDOW_EPOCHS
    }
}

/// The complete validator set.
///
/// Keyed by validator_id (Bytes32). Maximum MAX_VALIDATORS entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidatorSet {
    validators: BTreeMap<Bytes32, ValidatorEntry>,
}

impl Encode for ValidatorSet {
    fn encode(&self, buf: &mut Vec<u8>) {
        let mut validators: Vec<_> = self.validators.values().cloned().collect();
        validators.sort_by_key(|validator| validator.validator_id.0);
        encode_list(&validators, buf);
    }

    fn encoded_len(&self) -> usize {
        let mut validators: Vec<_> = self.validators.values().cloned().collect();
        validators.sort_by_key(|validator| validator.validator_id.0);
        list_encoded_len(&validators)
    }
}

impl Decode for ValidatorSet {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let validators: Vec<ValidatorEntry> =
            decode_list(r, MAX_VALIDATORS, "snapshot.validators")?;
        let mut set = Self::new();
        for validator in validators {
            if set.validators.contains_key(&validator.validator_id) {
                return Err(IndraError::DuplicateEntries {
                    field: "snapshot.validators",
                });
            }
            set.validators.insert(validator.validator_id, validator);
        }
        Ok(set)
    }
}

impl ValidatorSet {
    /// Create an empty validator set.
    pub fn new() -> Self {
        Self {
            validators: BTreeMap::new(),
        }
    }

    /// Decode a legacy unversioned validator set.
    pub fn decode_legacy(r: &mut ByteReader<'_>, schema_version: u8) -> IndraResult<Self> {
        let count = u32::decode(r)? as usize;
        if count > MAX_VALIDATORS {
            return Err(IndraError::LengthExceeded {
                field: "snapshot.validators",
                max: MAX_VALIDATORS,
                actual: count,
            });
        }
        let mut set = Self::new();
        for _ in 0..count {
            let validator = if schema_version <= SCHEMA_VERSION_GENESIS {
                ValidatorEntry::decode_legacy_v1(r)?
            } else {
                ValidatorEntry::decode_legacy_v2(r)?
            };
            if set
                .validators
                .insert(validator.validator_id, validator)
                .is_some()
            {
                return Err(IndraError::DuplicateEntries {
                    field: "snapshot.validators",
                });
            }
        }
        Ok(set)
    }

    /// Number of registered validators (active + unbonding).
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// True if no validators are registered.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Number of currently active validators.
    pub fn active_count(&self) -> usize {
        self.validators.values().filter(|v| v.is_active()).count()
    }

    /// Total stake of all active validators in Spark.
    pub fn total_active_stake(&self) -> u64 {
        self.validators
            .values()
            .filter(|v| v.is_active())
            .fold(0u64, |acc, v| acc.saturating_add(v.stake_spark))
    }

    /// Total stake of all validators eligible for active-set selection.
    pub fn total_selectable_self_stake(&self) -> u64 {
        self.validators
            .values()
            .filter(|v| {
                matches!(
                    v.status,
                    ValidatorStatus::Active | ValidatorStatus::Registered
                )
            })
            .fold(0u64, |acc, v| acc.saturating_add(v.stake_spark))
    }

    /// Stake of the lowest-ranked active validator, if any.
    pub fn effective_min_active_stake(&self, delegations: &DelegationMap) -> Option<u64> {
        self.active_validators()
            .map(|v| {
                v.stake_spark
                    .saturating_add(delegations.total_delegated(&v.validator_id))
            })
            .min()
    }

    /// Look up a validator by ID.
    pub fn get(&self, id: &Bytes32) -> Option<&ValidatorEntry> {
        self.validators.get(id)
    }

    /// Mutable lookup.
    pub fn get_mut(&mut self, id: &Bytes32) -> Option<&mut ValidatorEntry> {
        self.validators.get_mut(id)
    }

    /// Insert or update a validator entry.
    ///
    /// Returns an error if adding this validator would exceed MAX_VALIDATORS
    /// and the validator is not already registered.
    pub fn upsert(&mut self, entry: ValidatorEntry) -> crate::error::StateResult<()> {
        let id = entry.validator_id;
        if !self.validators.contains_key(&id) && self.validators.len() >= MAX_VALIDATORS {
            return Err(crate::error::StateError::InvariantViolation {
                message: "validator set at maximum capacity",
            });
        }
        self.validators.insert(id, entry);
        Ok(())
    }

    /// Iterate over all active validators.
    pub fn active_validators(&self) -> impl Iterator<Item = &ValidatorEntry> {
        self.validators.values().filter(|v| v.is_active())
    }

    /// Iterate over all validators regardless of status.
    pub fn all_validators(&self) -> impl Iterator<Item = &ValidatorEntry> {
        self.validators.values()
    }

    /// Expire rewards for validators who have not claimed within CLAIM_WINDOW.
    ///
    /// Called at epoch transition. Expired rewards are simply zeroed —
    /// they do not return to treasury (they are effectively burned).
    pub fn expire_stale_rewards(&mut self, current_epoch: u64) {
        for entry in self.validators.values_mut() {
            if entry.pending_rewards > 0 && entry.rewards_expired(current_epoch) {
                entry.pending_rewards = 0;
            }
        }
    }

    /// Reselect the active validator set by stake ranking.
    pub fn select_active_set(&mut self, delegations: &DelegationMap, total_staked_spark: u64) {
        let max_active = max_active_validators(total_staked_spark);
        let mut candidates: Vec<(Bytes32, u64)> = self
            .validators
            .values()
            .filter(|v| {
                matches!(
                    v.status,
                    ValidatorStatus::Active | ValidatorStatus::Registered
                )
            })
            .map(|v| {
                (
                    v.validator_id,
                    v.stake_spark
                        .saturating_add(delegations.total_delegated(&v.validator_id)),
                )
            })
            .collect();

        candidates.sort_by(|(id_a, stake_a), (id_b, stake_b)| {
            stake_b.cmp(stake_a).then_with(|| id_a.0.cmp(&id_b.0))
        });

        for (index, (id, _)) in candidates.iter().enumerate() {
            if let Some(validator) = self.validators.get_mut(id) {
                if index < max_active {
                    validator.status = ValidatorStatus::Active;
                } else {
                    validator.status = ValidatorStatus::Registered;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_validator(id_byte: u8, stake: u64, epoch: u64) -> ValidatorEntry {
        ValidatorEntry {
            validator_id: Bytes32::from([id_byte; 32]),
            name: format!("validator-{id_byte}"),
            hybrid_classical_pk: None,
            hybrid_pq_pk: None,
            vrf_pk: None,
            stake_spark: stake,
            status: ValidatorStatus::Active,
            registered_epoch: epoch,
            last_active_epoch: epoch,
            pending_rewards: 0,
            rewards_last_epoch: epoch,
            self_report_count: 0,
            commission_bps: 1_000,
            min_delegation_spark: DUST_LIMIT_SPARK,
            auto_delegate_to: None,
        }
    }

    fn encode_legacy_validator_v1(validator: &ValidatorEntry) -> Vec<u8> {
        let mut buf = Vec::new();
        validator.validator_id.encode(&mut buf);
        let name_bytes = validator.name.as_bytes();
        (name_bytes.len() as u32).encode(&mut buf);
        buf.extend_from_slice(name_bytes);
        validator.hybrid_classical_pk.is_some().encode(&mut buf);
        if let Some(pk) = validator.hybrid_classical_pk {
            buf.extend_from_slice(&pk);
        }
        validator.hybrid_pq_pk.is_some().encode(&mut buf);
        if let Some(pk) = &validator.hybrid_pq_pk {
            (pk.len() as u32).encode(&mut buf);
            buf.extend_from_slice(pk);
        }
        validator.vrf_pk.is_some().encode(&mut buf);
        if let Some(pk) = validator.vrf_pk {
            buf.extend_from_slice(&pk);
        }
        validator.stake_spark.encode(&mut buf);
        validator.status.encode(&mut buf);
        validator.registered_epoch.encode(&mut buf);
        validator.last_active_epoch.encode(&mut buf);
        validator.pending_rewards.encode(&mut buf);
        validator.rewards_last_epoch.encode(&mut buf);
        validator.self_report_count.encode(&mut buf);
        validator.commission_bps.encode(&mut buf);
        validator.min_delegation_spark.encode(&mut buf);
        buf
    }

    #[test]
    fn validator_entry_v1_decodes_with_auto_delegate_none() {
        let mut validator = make_validator(0x42, 10_000, 3);
        validator.auto_delegate_to = Some(Bytes32::from([0x99; 32]));
        let bytes = encode_legacy_validator_v1(&validator);
        let decoded = ValidatorEntry::decode_exact(&bytes).unwrap();
        assert_eq!(decoded.validator_id, validator.validator_id);
        assert_eq!(decoded.last_active_epoch, validator.last_active_epoch);
        assert_eq!(decoded.auto_delegate_to, None);
    }

    #[test]
    fn validator_entry_v2_round_trips_with_auto_delegate_some() {
        let mut validator = make_validator(0x43, 10_000, 3);
        let target = Bytes32::from([0x55; 32]);
        validator.auto_delegate_to = Some(target);
        let decoded = ValidatorEntry::decode_exact(&validator.encode_to_vec()).unwrap();
        assert_eq!(decoded, validator);
        assert_eq!(decoded.auto_delegate_to, Some(target));
    }

    #[test]
    fn validator_entry_unsupported_version_errors_clearly() {
        let err = ValidatorEntry::decode_exact(&[99]).unwrap_err();
        assert!(matches!(
            err,
            IndraError::UnsupportedSchemaVersion {
                struct_name: "ValidatorEntry",
                version: 99,
                max_supported: SCHEMA_VERSION
            }
        ));
    }

    #[test]
    fn insert_and_retrieve() {
        let mut vs = ValidatorSet::new();
        let v = make_validator(0x01, 10_000_000_000, 0);
        let id = v.validator_id;
        vs.upsert(v).unwrap();
        assert!(vs.get(&id).is_some());
        assert_eq!(vs.active_count(), 1);
    }

    #[test]
    fn total_active_stake_sums_correctly() {
        let mut vs = ValidatorSet::new();
        vs.upsert(make_validator(0x01, 1_000, 0)).unwrap();
        vs.upsert(make_validator(0x02, 2_000, 0)).unwrap();
        vs.upsert(make_validator(0x03, 3_000, 0)).unwrap();
        assert_eq!(vs.total_active_stake(), 6_000);
    }

    #[test]
    fn unbonding_validator_not_counted_as_active() {
        let mut vs = ValidatorSet::new();
        let mut v = make_validator(0x01, 5_000, 0);
        v.status = ValidatorStatus::Unbonding {
            unbonding_end_epoch: 10,
        };
        vs.upsert(v).unwrap();
        assert_eq!(vs.active_count(), 0);
        assert_eq!(vs.total_active_stake(), 0);
    }

    #[test]
    fn reward_expiry_zeroes_stale_rewards() {
        let mut vs = ValidatorSet::new();
        let mut v = make_validator(0x01, 5_000, 0);
        v.pending_rewards = 999;
        v.rewards_last_epoch = 0;
        vs.upsert(v).unwrap();

        use indra_core::types::primitives::CLAIM_WINDOW_EPOCHS;
        // Expire at exactly CLAIM_WINDOW + 1 epochs later
        vs.expire_stale_rewards(CLAIM_WINDOW_EPOCHS + 1);

        let id = Bytes32::from([0x01u8; 32]);
        assert_eq!(vs.get(&id).unwrap().pending_rewards, 0);
    }

    #[test]
    fn rewards_not_expired_within_window() {
        let mut vs = ValidatorSet::new();
        let mut v = make_validator(0x01, 5_000, 0);
        v.pending_rewards = 500;
        v.rewards_last_epoch = 0;
        vs.upsert(v).unwrap();

        // Still within the window
        vs.expire_stale_rewards(100);

        let id = Bytes32::from([0x01u8; 32]);
        assert_eq!(vs.get(&id).unwrap().pending_rewards, 500);
    }

    #[test]
    fn select_active_set_promotes_top_ranked_validators() {
        let mut vs = ValidatorSet::new();
        let mut waiting = make_validator(0x01, 500, 0);
        waiting.status = ValidatorStatus::Registered;
        vs.upsert(waiting).unwrap();
        vs.upsert(make_validator(0x02, 300, 0)).unwrap();
        vs.upsert(make_validator(0x03, 100, 0)).unwrap();

        let delegations = DelegationMap::new();
        vs.select_active_set(&delegations, 0);

        assert!(matches!(
            vs.get(&Bytes32::from([0x01; 32])).unwrap().status,
            ValidatorStatus::Active
        ));
        assert!(matches!(
            vs.get(&Bytes32::from([0x02; 32])).unwrap().status,
            ValidatorStatus::Active
        ));
        assert!(matches!(
            vs.get(&Bytes32::from([0x03; 32])).unwrap().status,
            ValidatorStatus::Active
        ));
    }

    #[test]
    fn effective_min_active_stake_tracks_lowest_active_validator() {
        let mut vs = ValidatorSet::new();
        vs.upsert(make_validator(0x01, 5_000, 0)).unwrap();
        vs.upsert(make_validator(0x02, 2_000, 0)).unwrap();
        vs.upsert(make_validator(0x03, 8_000, 0)).unwrap();

        let delegations = DelegationMap::new();
        assert_eq!(vs.effective_min_active_stake(&delegations), Some(2_000));
    }
}

/// A UTXO that has been bonded as delegation stake.
///
/// Active bonds earn rewards and count toward delegation totals. Unbonding
/// bonds are retained until their release epoch, then restored as spendable
/// UTXOs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeBondEntry {
    /// The UTXO ID that was bonded.
    pub utxo_id: Bytes32,
    /// Validator this bond is staked with.
    pub validator_id: Bytes32,
    /// Delegator identity.
    pub delegator_id: Bytes32,
    /// Amount staked in Spark.
    pub amount_spark: u64,
    /// Epoch when this bond was created.
    pub bonded_epoch: u64,
    /// None while active; Some(epoch) while unbonding.
    pub unbonding_end_epoch: Option<u64>,
    /// Original UTXO output, needed to reinsert when unbonding completes.
    pub original_output: OutputV1,
}

impl Encode for StakeBondEntry {
    fn encode(&self, buf: &mut Vec<u8>) {
        SCHEMA_VERSION.encode(buf);
        self.utxo_id.encode(buf);
        self.validator_id.encode(buf);
        self.delegator_id.encode(buf);
        self.amount_spark.encode(buf);
        self.bonded_epoch.encode(buf);
        self.unbonding_end_epoch.is_some().encode(buf);
        if let Some(epoch) = self.unbonding_end_epoch {
            epoch.encode(buf);
        }
        self.original_output.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        1 + self.utxo_id.encoded_len()
            + self.validator_id.encoded_len()
            + self.delegator_id.encoded_len()
            + self.amount_spark.encoded_len()
            + self.bonded_epoch.encoded_len()
            + 1
            + self.unbonding_end_epoch.map(|_| 8).unwrap_or(0)
            + self.original_output.encoded_len()
    }
}

impl Decode for StakeBondEntry {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let marker = u8::decode(r)?;
        match marker {
            SCHEMA_VERSION_GENESIS | SCHEMA_VERSION => decode_stake_bond_entry_fields(r, None),
            other if r.remaining() == 0 => Err(unsupported_schema("StakeBondEntry", other)),
            first_byte => decode_stake_bond_entry_fields(r, Some(first_byte)),
        }
    }
}

impl StakeBondEntry {
    /// Decode the legacy unversioned stake bond layout.
    pub fn decode_legacy(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        decode_stake_bond_entry_fields(r, None)
    }
}

fn decode_stake_bond_entry_fields(
    r: &mut ByteReader<'_>,
    first_byte: Option<u8>,
) -> IndraResult<StakeBondEntry> {
    let utxo_id = decode_bytes32_with_first(r, first_byte)?;
    Ok(StakeBondEntry {
        utxo_id,
        validator_id: Bytes32::decode(r)?,
        delegator_id: Bytes32::decode(r)?,
        amount_spark: u64::decode(r)?,
        bonded_epoch: u64::decode(r)?,
        unbonding_end_epoch: if bool::decode(r)? {
            Some(u64::decode(r)?)
        } else {
            None
        },
        original_output: OutputV1::decode(r)?,
    })
}

/// A single delegator's position with a validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatorEntry {
    /// Delegator identity: hash of their public key.
    pub delegator_id: Bytes32,
    /// Amount currently delegated in Spark.
    pub staked_spark: u64,
    /// Accumulated unclaimed rewards in Spark (after commission deduction).
    pub pending_rewards: u64,
    /// Epoch at which pending_rewards was last updated.
    pub rewards_last_epoch: u64,
    /// If unbonding: the epoch at which stake is released. None if active.
    pub unbonding_end_epoch: Option<u64>,
}

impl Encode for DelegatorEntry {
    fn encode(&self, buf: &mut Vec<u8>) {
        SCHEMA_VERSION.encode(buf);
        self.delegator_id.encode(buf);
        self.staked_spark.encode(buf);
        self.pending_rewards.encode(buf);
        self.rewards_last_epoch.encode(buf);
        self.unbonding_end_epoch.is_some().encode(buf);
        if let Some(epoch) = self.unbonding_end_epoch {
            epoch.encode(buf);
        }
    }

    fn encoded_len(&self) -> usize {
        1 + 32 + 8 + 8 + 8 + 1 + self.unbonding_end_epoch.map(|_| 8).unwrap_or(0)
    }
}

impl Decode for DelegatorEntry {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let marker = u8::decode(r)?;
        match marker {
            SCHEMA_VERSION_GENESIS | SCHEMA_VERSION => decode_delegator_entry_fields(r, None),
            other if r.remaining() == 0 => Err(unsupported_schema("DelegatorEntry", other)),
            first_byte => decode_delegator_entry_fields(r, Some(first_byte)),
        }
    }
}

impl DelegatorEntry {
    /// Decode the legacy unversioned delegator layout.
    pub fn decode_legacy(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        decode_delegator_entry_fields(r, None)
    }
}

fn decode_delegator_entry_fields(
    r: &mut ByteReader<'_>,
    first_byte: Option<u8>,
) -> IndraResult<DelegatorEntry> {
    let delegator_id = decode_bytes32_with_first(r, first_byte)?;
    let staked_spark = u64::decode(r)?;
    let pending_rewards = u64::decode(r)?;
    let rewards_last_epoch = u64::decode(r)?;
    let has_unbonding = bool::decode(r)?;
    Ok(DelegatorEntry {
        delegator_id,
        staked_spark,
        pending_rewards,
        rewards_last_epoch,
        unbonding_end_epoch: if has_unbonding {
            Some(u64::decode(r)?)
        } else {
            None
        },
    })
}

impl DelegatorEntry {
    /// True if this delegation is currently unbonding.
    pub fn is_unbonding(&self) -> bool {
        self.unbonding_end_epoch.is_some()
    }

    /// True if this delegator's rewards have expired.
    pub fn rewards_expired(&self, current_epoch: u64) -> bool {
        use indra_core::types::primitives::CLAIM_WINDOW_EPOCHS;
        current_epoch.saturating_sub(self.rewards_last_epoch) > CLAIM_WINDOW_EPOCHS
    }
}

/// Maps validator_id → list of delegator entries for that validator.
///
/// Stored separately from ValidatorSet to keep validator lookups fast.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DelegationMap {
    /// Inner map: validator_id → delegators.
    delegators: BTreeMap<Bytes32, Vec<DelegatorEntry>>,
}

impl Encode for DelegationMap {
    fn encode(&self, buf: &mut Vec<u8>) {
        let mut entries: Vec<_> = self.delegators.iter().collect();
        entries.sort_by_key(|(validator_id, _)| validator_id.0);
        (entries.len() as u32).encode(buf);
        for (validator_id, delegators) in entries {
            validator_id.encode(buf);
            encode_list(delegators, buf);
        }
    }

    fn encoded_len(&self) -> usize {
        let mut len = 4;
        let mut entries: Vec<_> = self.delegators.iter().collect();
        entries.sort_by_key(|(validator_id, _)| validator_id.0);
        for (validator_id, delegators) in entries {
            len += validator_id.encoded_len();
            len += list_encoded_len(delegators);
        }
        len
    }
}

impl Decode for DelegationMap {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let count = u32::decode(r)? as usize;
        let mut delegators = BTreeMap::new();
        for _ in 0..count {
            let validator_id = Bytes32::decode(r)?;
            if delegators.contains_key(&validator_id) {
                return Err(IndraError::DuplicateEntries {
                    field: "snapshot.delegations",
                });
            }
            let entries: Vec<DelegatorEntry> = decode_list(r, usize::MAX, "snapshot.delegators")?;
            delegators.insert(validator_id, entries);
        }
        Ok(Self { delegators })
    }
}

impl DelegationMap {
    /// Create an empty delegation map.
    pub fn new() -> Self {
        Self {
            delegators: BTreeMap::new(),
        }
    }

    /// Decode a legacy unversioned delegation map.
    pub fn decode_legacy(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let count = u32::decode(r)? as usize;
        let mut delegators = BTreeMap::new();
        for _ in 0..count {
            let validator_id = Bytes32::decode(r)?;
            if delegators.contains_key(&validator_id) {
                return Err(IndraError::DuplicateEntries {
                    field: "snapshot.delegations",
                });
            }
            let entry_count = u32::decode(r)? as usize;
            let mut entries = Vec::with_capacity(entry_count);
            for _ in 0..entry_count {
                entries.push(DelegatorEntry::decode_legacy(r)?);
            }
            delegators.insert(validator_id, entries);
        }
        Ok(Self { delegators })
    }

    /// Total delegated stake for a given validator in Spark.
    pub fn total_delegated(&self, validator_id: &Bytes32) -> u64 {
        self.delegators
            .get(validator_id)
            .map(|ds| {
                ds.iter()
                    .filter(|d| d.unbonding_end_epoch.is_none())
                    .fold(0u64, |acc, d| acc.saturating_add(d.staked_spark))
            })
            .unwrap_or(0)
    }

    /// Total active delegated stake across all validators.
    pub fn total_staked(&self) -> u64 {
        self.delegators
            .values()
            .flat_map(|entries| entries.iter())
            .filter(|entry| entry.unbonding_end_epoch.is_none())
            .fold(0u64, |acc, entry| acc.saturating_add(entry.staked_spark))
    }

    /// Get all delegators for a validator.
    pub fn get_delegators(&self, validator_id: &Bytes32) -> &[DelegatorEntry] {
        self.delegators
            .get(validator_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Iterate all validator delegator lists.
    pub fn all_delegators(&self) -> impl Iterator<Item = (&Bytes32, &Vec<DelegatorEntry>)> {
        self.delegators.iter()
    }

    /// Mutable access to delegators for a validator.
    pub fn get_delegators_mut(
        &mut self,
        validator_id: &Bytes32,
    ) -> Option<&mut Vec<DelegatorEntry>> {
        self.delegators.get_mut(validator_id)
    }

    /// Find a specific delegator entry for a validator (mutable).
    pub fn get_delegator_mut(
        &mut self,
        validator_id: &Bytes32,
        delegator_id: &Bytes32,
    ) -> Option<&mut DelegatorEntry> {
        self.delegators
            .get_mut(validator_id)?
            .iter_mut()
            .find(|d| &d.delegator_id == delegator_id)
    }

    /// Get pending rewards for a specific delegator entry.
    pub fn get_delegator_reward(&self, validator_id: &Bytes32, delegator_id: &Bytes32) -> u64 {
        self.delegators
            .get(validator_id)
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|d| &d.delegator_id == delegator_id)
                    .map(|d| d.pending_rewards)
            })
            .unwrap_or(0)
    }

    /// Remove a specific virtual delegation entry without unbonding.
    pub fn remove_virtual_delegation(&mut self, validator_id: &Bytes32, delegator_id: &Bytes32) {
        if let Some(entries) = self.delegators.get_mut(validator_id) {
            entries.retain(|d| &d.delegator_id != delegator_id);
            if entries.is_empty() {
                self.delegators.remove(validator_id);
            }
        }
    }

    /// Add a new delegation or increase an existing one.
    pub fn add_delegation(
        &mut self,
        validator_id: Bytes32,
        delegator_id: Bytes32,
        amount_spark: u64,
        current_epoch: u64,
    ) {
        let entries = self.delegators.entry(validator_id).or_default();
        if let Some(existing) = entries.iter_mut().find(|d| d.delegator_id == delegator_id) {
            existing.staked_spark = existing.staked_spark.saturating_add(amount_spark);
        } else {
            entries.push(DelegatorEntry {
                delegator_id,
                staked_spark: amount_spark,
                pending_rewards: 0,
                rewards_last_epoch: current_epoch,
                unbonding_end_epoch: None,
            });
        }
    }

    /// Begin unbonding a delegation. Returns error string if not found or already unbonding.
    pub fn begin_undelegate(
        &mut self,
        validator_id: &Bytes32,
        delegator_id: &Bytes32,
        amount_spark: u64,
        unbonding_end_epoch: u64,
    ) -> Result<(), &'static str> {
        let entries = self
            .delegators
            .get_mut(validator_id)
            .ok_or("validator has no delegators")?;
        let entry = entries
            .iter_mut()
            .find(|d| &d.delegator_id == delegator_id)
            .ok_or("delegator not found")?;
        if entry.is_unbonding() {
            return Err("already unbonding");
        }
        if amount_spark > entry.staked_spark {
            return Err("insufficient delegated stake");
        }
        entry.staked_spark = entry.staked_spark.saturating_sub(amount_spark);
        // If remaining stake is below dust, undelegate everything
        if entry.staked_spark < DUST_LIMIT_SPARK {
            entry.staked_spark = 0;
        }
        entry.unbonding_end_epoch = Some(unbonding_end_epoch);
        Ok(())
    }

    /// Release delegators whose unbonding period has ended.
    /// Returns the total Spark to be returned to delegators.
    pub fn release_unbonded(&mut self, current_epoch: u64) -> u64 {
        let mut released: u64 = 0;
        for entries in self.delegators.values_mut() {
            entries.retain(|d| {
                if let Some(end) = d.unbonding_end_epoch {
                    if end <= current_epoch {
                        released = released.saturating_add(d.staked_spark);
                        return false; // remove entry
                    }
                }
                true
            });
        }
        released
    }

    /// Expire stale delegator rewards across all validators.
    pub fn expire_stale_rewards(&mut self, current_epoch: u64) {
        for entries in self.delegators.values_mut() {
            for entry in entries.iter_mut() {
                if entry.pending_rewards > 0 && entry.rewards_expired(current_epoch) {
                    entry.pending_rewards = 0;
                }
            }
        }
    }

    /// Distribute rewards to delegators of a specific validator.
    ///
    /// `pool` is the total reward pool for delegators (after validator commission).
    /// Distributed proportionally by active stake.
    pub fn distribute_rewards(
        &mut self,
        validator_id: &Bytes32,
        pool: u64,
        current_epoch: u64,
        height: u64,
    ) -> u64 {
        let entries = match self.delegators.get_mut(validator_id) {
            Some(e) => e,
            None => return pool, // no delegators — return unspent pool
        };

        let total: u64 = entries
            .iter()
            .filter(|d| d.unbonding_end_epoch.is_none())
            .fold(0u64, |acc, d| acc.saturating_add(d.staked_spark));

        if total == 0 {
            return pool;
        }

        let mut distributed: u64 = 0;
        for entry in entries
            .iter_mut()
            .filter(|d| d.unbonding_end_epoch.is_none())
        {
            let reward = if overflow_fix_active(height) {
                muldiv(pool, entry.staked_spark, total)
            } else {
                pool.saturating_mul(entry.staked_spark) / total
            };
            entry.pending_rewards = entry.pending_rewards.saturating_add(reward);
            entry.rewards_last_epoch = current_epoch;
            distributed = distributed.saturating_add(reward);
        }

        pool.saturating_sub(distributed) // remainder back to treasury
    }
}

#[cfg(test)]
mod delegation_map_tests {
    use super::*;

    #[test]
    fn test_all_delegators_iterates_all_entries() {
        let mut map = DelegationMap::new();
        for validator in 1..=3u8 {
            for delegator in 1..=2u8 {
                map.add_delegation(
                    Bytes32::from([validator; 32]),
                    Bytes32::from([validator * 10 + delegator; 32]),
                    1_000,
                    0,
                );
            }
        }

        let mut counts: Vec<usize> = map
            .all_delegators()
            .map(|(_, entries)| entries.len())
            .collect();
        counts.sort_unstable();

        assert_eq!(counts, vec![2, 2, 2]);
        assert_eq!(map.all_delegators().count(), 3);
    }
}
