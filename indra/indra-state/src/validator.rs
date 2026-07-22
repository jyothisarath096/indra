//! Validator set — the active set of staked validators.
//!
//! Tracks each validator's stake, status, and accumulated reward.
//! The validator set is snapshotted at each epoch boundary.

use std::collections::BTreeMap;

use indra_core::codec::{decode_list, encode_list, list_encoded_len, ByteReader, Decode, Encode};
use indra_core::error::{IndraError, IndraResult};
use indra_core::types::{
    primitives::{
        compact_bond_pubkey_omission_active, compact_stake_bond_active, max_active_validators,
        muldiv, overflow_fix_active, Bytes32, VariableBytes, DUST_LIMIT_SPARK,
        MAX_DELEGATION_RETURN_EVENTS, MAX_RANGE_PROOF_BYTES, MAX_VALIDATORS,
        MAX_VALIDATOR_NETWORK_ADDR_LEN, SCHEMA_VERSION, SCHEMA_VERSION_GENESIS,
        SCHEMA_VERSION_PRE_VALIDATOR_NETWORK_ADDRESS,
    },
    transaction::OutputV1,
};

use crate::persistent::PersistentOrdMap;

/// Consensus ceiling for active delegator entries under one validator.
///
/// This is intentionally far above expected 200-validator mainnet operating
/// needs, but finite so live state cannot grow beyond what snapshots can later
/// decode on restart or sync.
pub const MAX_DELEGATORS_PER_VALIDATOR: usize = 100_000;

/// Defensive snapshot decode ceiling for delegators under one validator.
///
/// This intentionally matches the live write cap so state that can be accepted
/// during normal operation can always be decoded later from persisted snapshots.
pub const MAX_DELEGATORS_PER_VALIDATOR_DECODE: usize = MAX_DELEGATORS_PER_VALIDATOR;

const STAKE_BOND_COMPACT_MARKER: u8 = u8::MAX;
const STAKE_BOND_FULLY_COMPACT_MARKER: u8 = u8::MAX - 1;

/// Why a stake bond was returned outside the normal claim/undelegation flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationReturnReason {
    /// Validator was evicted from the bounded registry by a higher-stake
    /// registration; all associated bonds were returned immediately.
    ValidatorEvicted,
}

impl Encode for DelegationReturnReason {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::ValidatorEvicted => 1u8.encode(buf),
        }
    }

    fn encoded_len(&self) -> usize {
        1
    }
}

impl Decode for DelegationReturnReason {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        match u8::decode(r)? {
            1 => Ok(Self::ValidatorEvicted),
            _ => Err(IndraError::InvariantViolation {
                message: "invalid delegation return reason",
            }),
        }
    }
}

/// Consensus-visible event recording an automatic delegation principal return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationReturnEvent {
    /// Delegator whose stake bond was returned.
    pub delegator_id: Bytes32,
    /// Validator from which the stake bond was returned.
    pub validator_id: Bytes32,
    /// Original bonded UTXO ID.
    pub bond_utxo_id: Bytes32,
    /// Principal amount returned in Spark.
    pub amount_spark: u64,
    /// Why this return happened.
    pub reason: DelegationReturnReason,
    /// Epoch in which the return was applied.
    pub returned_epoch: u64,
    /// Height at which the return was applied.
    pub returned_height: u64,
    /// Newly created refund UTXO ID.
    pub refund_utxo_id: Bytes32,
}

impl Encode for DelegationReturnEvent {
    fn encode(&self, buf: &mut Vec<u8>) {
        SCHEMA_VERSION.encode(buf);
        self.delegator_id.encode(buf);
        self.validator_id.encode(buf);
        self.bond_utxo_id.encode(buf);
        self.amount_spark.encode(buf);
        self.reason.encode(buf);
        self.returned_epoch.encode(buf);
        self.returned_height.encode(buf);
        self.refund_utxo_id.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        1 + 32 + 32 + 32 + 8 + self.reason.encoded_len() + 8 + 8 + 32
    }
}

impl Decode for DelegationReturnEvent {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let marker = u8::decode(r)?;
        match marker {
            SCHEMA_VERSION_GENESIS
            | SCHEMA_VERSION_PRE_VALIDATOR_NETWORK_ADDRESS
            | SCHEMA_VERSION => Ok(Self {
                delegator_id: Bytes32::decode(r)?,
                validator_id: Bytes32::decode(r)?,
                bond_utxo_id: Bytes32::decode(r)?,
                amount_spark: u64::decode(r)?,
                reason: DelegationReturnReason::decode(r)?,
                returned_epoch: u64::decode(r)?,
                returned_height: u64::decode(r)?,
                refund_utxo_id: Bytes32::decode(r)?,
            }),
            _ => Err(IndraError::UnsupportedSchemaVersion {
                struct_name: "DelegationReturnEvent",
                version: marker,
                max_supported: SCHEMA_VERSION,
            }),
        }
    }
}

/// Encode the bounded global delegation-return event log.
pub fn encode_delegation_return_events(events: &[DelegationReturnEvent], buf: &mut Vec<u8>) {
    encode_list(events, buf);
}

/// Decode the bounded global delegation-return event log.
pub fn decode_delegation_return_events(
    r: &mut ByteReader<'_>,
) -> IndraResult<Vec<DelegationReturnEvent>> {
    decode_list(
        r,
        MAX_DELEGATION_RETURN_EVENTS,
        "snapshot.delegation_return_events",
    )
}

/// Encoded length of the bounded global delegation-return event log.
pub fn delegation_return_events_encoded_len(events: &[DelegationReturnEvent]) -> usize {
    list_encoded_len(events)
}

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
    /// Pending commission rate in basis points.
    ///
    /// Staged commission changes are applied at epoch transition once
    /// `pending_commission_effective_epoch <= current_epoch`.
    pub pending_commission_bps: Option<u16>,
    /// Epoch at which the pending commission change becomes active.
    pub pending_commission_effective_epoch: Option<u64>,
    /// Validator-specific minimum delegation amount in Spark.
    pub min_delegation_spark: u64,
    /// Optional target validator for epoch-scoped reward auto-delegation.
    pub auto_delegate_to: Option<Bytes32>,
    /// Validator-advertised P2P dial address, strict IP:port syntax.
    pub network_addr: Option<String>,
    /// Epoch in which `network_addr` was last set or cleared.
    pub network_addr_last_updated_epoch: Option<u64>,
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
        self.pending_commission_bps.is_some().encode(buf);
        if let Some(pending) = self.pending_commission_bps {
            pending.encode(buf);
        }
        self.pending_commission_effective_epoch
            .is_some()
            .encode(buf);
        if let Some(epoch) = self.pending_commission_effective_epoch {
            epoch.encode(buf);
        }
        self.min_delegation_spark.encode(buf);
        self.auto_delegate_to.is_some().encode(buf);
        if let Some(target) = self.auto_delegate_to {
            target.encode(buf);
        }
        self.network_addr.is_some().encode(buf);
        if let Some(addr) = &self.network_addr {
            let bytes = addr.as_bytes();
            debug_assert!(bytes.len() <= MAX_VALIDATOR_NETWORK_ADDR_LEN);
            (bytes.len() as u16).encode(buf);
            buf.extend_from_slice(bytes);
        }
        self.network_addr_last_updated_epoch.is_some().encode(buf);
        if let Some(epoch) = self.network_addr_last_updated_epoch {
            epoch.encode(buf);
        }
    }

    fn encoded_len(&self) -> usize {
        1 + 32
            + 4
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
            + 1
            + self.pending_commission_bps.map(|_| 2).unwrap_or(0)
            + 1
            + self
                .pending_commission_effective_epoch
                .map(|_| 8)
                .unwrap_or(0)
            + 8
            + 1
            + self.auto_delegate_to.map(|_| 32).unwrap_or(0)
            + 1
            + self
                .network_addr
                .as_ref()
                .map(|addr| 2 + addr.len())
                .unwrap_or(0)
            + 1
            + self.network_addr_last_updated_epoch.map(|_| 8).unwrap_or(0)
    }
}

impl Decode for ValidatorEntry {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let marker = u8::decode(r)?;
        match marker {
            SCHEMA_VERSION_GENESIS => decode_validator_entry_v1(r, None),
            SCHEMA_VERSION_PRE_VALIDATOR_NETWORK_ADDRESS => decode_validator_entry_v3(r, None),
            SCHEMA_VERSION => decode_validator_entry_v4(r, None),
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
    decode_validator_entry_fields(r, first_byte, false, false, false)
}

fn decode_validator_entry_v2(
    r: &mut ByteReader<'_>,
    first_byte: Option<u8>,
) -> IndraResult<ValidatorEntry> {
    decode_validator_entry_fields(r, first_byte, true, false, false)
}

fn decode_validator_entry_v3(
    r: &mut ByteReader<'_>,
    first_byte: Option<u8>,
) -> IndraResult<ValidatorEntry> {
    decode_validator_entry_fields(r, first_byte, true, true, false)
}

fn decode_validator_entry_v4(
    r: &mut ByteReader<'_>,
    first_byte: Option<u8>,
) -> IndraResult<ValidatorEntry> {
    decode_validator_entry_fields(r, first_byte, true, true, true)
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
    has_pending_commission: bool,
    has_network_addr: bool,
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

    let stake_spark = u64::decode(r)?;
    let status = ValidatorStatus::decode(r)?;
    let registered_epoch = u64::decode(r)?;
    let last_active_epoch = u64::decode(r)?;
    let pending_rewards = u64::decode(r)?;
    let rewards_last_epoch = u64::decode(r)?;
    let self_report_count = u32::decode(r)?;
    let commission_bps = u32::decode(r)?;
    let (pending_commission_bps, pending_commission_effective_epoch) = if has_pending_commission {
        let pending_bps = if bool::decode(r)? {
            Some(u16::decode(r)?)
        } else {
            None
        };
        let pending_epoch = if bool::decode(r)? {
            Some(u64::decode(r)?)
        } else {
            None
        };
        (pending_bps, pending_epoch)
    } else {
        (None, None)
    };
    let min_delegation_spark = u64::decode(r)?;
    let auto_delegate_to = if has_auto_delegate_to && bool::decode(r)? {
        Some(Bytes32::decode(r)?)
    } else {
        None
    };
    let (network_addr, network_addr_last_updated_epoch) = if has_network_addr {
        let network_addr = if bool::decode(r)? {
            let len = u16::decode(r)? as usize;
            if len > MAX_VALIDATOR_NETWORK_ADDR_LEN {
                return Err(IndraError::InvalidStakingOp(format!(
                    "validator network address length {} exceeds maximum {}",
                    len, MAX_VALIDATOR_NETWORK_ADDR_LEN
                )));
            }
            let bytes = r.read_bytes(len)?;
            Some(
                String::from_utf8(bytes.to_vec()).map_err(|_| IndraError::InvariantViolation {
                    message: "invalid UTF-8 validator network address in snapshot",
                })?,
            )
        } else {
            None
        };
        let last_updated = if bool::decode(r)? {
            Some(u64::decode(r)?)
        } else {
            None
        };
        (network_addr, last_updated)
    } else {
        (None, None)
    };

    Ok(ValidatorEntry {
        validator_id,
        name,
        hybrid_classical_pk,
        hybrid_pq_pk,
        vrf_pk,
        stake_spark,
        status,
        registered_epoch,
        last_active_epoch,
        pending_rewards,
        rewards_last_epoch,
        self_report_count,
        commission_bps,
        pending_commission_bps,
        pending_commission_effective_epoch,
        min_delegation_spark,
        auto_delegate_to,
        network_addr,
        network_addr_last_updated_epoch,
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

    /// Number of validator registry entries across all lifecycle statuses.
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

    /// Self-stake of the lowest-ranked active validator, if any.
    pub fn effective_min_active_stake(&self, _delegations: &DelegationMap) -> Option<u64> {
        self.active_validators().map(|v| v.stake_spark).min()
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

    /// Remove a validator entry from the registry.
    pub fn remove(&mut self, id: &Bytes32) -> Option<ValidatorEntry> {
        self.validators.remove(id)
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

    /// Reselect the active validator set by self-stake ranking.
    ///
    /// Consensus voting weight and epoch reward weights are based on
    /// `validator.stake_spark` only, so active-set selection must use the same
    /// self-stake model. Delegated stake affects delegator reward splitting,
    /// but it does not increase validator selection weight in the current
    /// protocol. This is deliberately distinct from registered-registry
    /// replacement, which uses total stake (self + delegated) only as a
    /// housekeeping rule for deciding which persisted validator entry gets a
    /// scarce registry slot when the registry is full.
    pub fn select_active_set(&mut self, _delegations: &DelegationMap, total_staked_spark: u64) {
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
            .map(|v| (v.validator_id, v.stake_spark))
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
            pending_commission_bps: None,
            pending_commission_effective_epoch: None,
            min_delegation_spark: DUST_LIMIT_SPARK,
            auto_delegate_to: None,
            network_addr: None,
            network_addr_last_updated_epoch: None,
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
    fn validator_entry_v4_round_trips_network_address() {
        let mut validator = make_validator(0x44, 10_000, 3);
        validator.network_addr = Some("203.0.113.44:30303".to_string());
        validator.network_addr_last_updated_epoch = Some(7);

        let decoded = ValidatorEntry::decode_exact(&validator.encode_to_vec()).unwrap();
        assert_eq!(decoded, validator);
        assert_eq!(decoded.network_addr.as_deref(), Some("203.0.113.44:30303"));
        assert_eq!(decoded.network_addr_last_updated_epoch, Some(7));
    }

    #[test]
    fn validator_entry_v3_decodes_network_address_defaults_none() {
        let validator = make_validator(0x45, 10_000, 3);
        let mut bytes = validator.encode_to_vec();
        bytes[0] = SCHEMA_VERSION_PRE_VALIDATOR_NETWORK_ADDRESS;
        // v4 appends network_addr presence and last_updated presence booleans
        // after the v3 layout. Removing them models a persisted v3 validator.
        bytes.truncate(bytes.len() - 2);

        let decoded = ValidatorEntry::decode_exact(&bytes).unwrap();
        assert_eq!(decoded.validator_id, validator.validator_id);
        assert_eq!(decoded.auto_delegate_to, None);
        assert_eq!(decoded.network_addr, None);
        assert_eq!(decoded.network_addr_last_updated_epoch, None);
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
    fn delegation_map_decode_rejects_excessive_delegator_count() {
        let mut bytes = Vec::new();
        1u32.encode(&mut bytes);
        Bytes32::from([0xAA; 32]).encode(&mut bytes);
        ((MAX_DELEGATORS_PER_VALIDATOR_DECODE + 1) as u32).encode(&mut bytes);

        let err = DelegationMap::decode_exact(&bytes).unwrap_err();
        assert!(matches!(
            err,
            IndraError::LengthExceeded {
                field: "snapshot.delegators",
                max: MAX_DELEGATORS_PER_VALIDATOR_DECODE,
                actual
            } if actual == MAX_DELEGATORS_PER_VALIDATOR_DECODE + 1
        ));
    }

    #[test]
    fn delegation_map_decode_accepts_realistic_delegator_count() {
        let validator_id = Bytes32::from([0xAB; 32]);
        let mut map = DelegationMap::new();
        for i in 0..3u8 {
            map.add_delegation(validator_id, Bytes32::from([i; 32]), 1_000 + i as u64, 7)
                .unwrap();
        }

        let decoded = DelegationMap::decode_exact(&map.encode_to_vec()).unwrap();
        assert_eq!(decoded.get_delegators(&validator_id).len(), 3);
        assert_eq!(
            decoded.total_delegated(&validator_id),
            1_000 + 1_001 + 1_002
        );
    }

    #[test]
    fn delegation_map_legacy_decode_rejects_excessive_delegator_count() {
        let mut bytes = Vec::new();
        1u32.encode(&mut bytes);
        Bytes32::from([0xAC; 32]).encode(&mut bytes);
        ((MAX_DELEGATORS_PER_VALIDATOR_DECODE + 1) as u32).encode(&mut bytes);
        let mut reader = ByteReader::new(&bytes);

        let err = DelegationMap::decode_legacy(&mut reader).unwrap_err();
        assert!(matches!(
            err,
            IndraError::LengthExceeded {
                field: "snapshot.delegators",
                max: MAX_DELEGATORS_PER_VALIDATOR_DECODE,
                actual
            } if actual == MAX_DELEGATORS_PER_VALIDATOR_DECODE + 1
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
    fn select_active_set_uses_self_stake_not_delegations() {
        let mut vs = ValidatorSet::new();
        let mut delegations = DelegationMap::new();

        for seed in 1u8..=20 {
            let mut validator = make_validator(seed, 1_000 + seed as u64, 0);
            validator.status = ValidatorStatus::Registered;
            vs.upsert(validator).unwrap();
        }

        let low_self_id = Bytes32::from([0xFE; 32]);
        let mut low_self = make_validator(0xFE, 1, 0);
        low_self.status = ValidatorStatus::Registered;
        vs.upsert(low_self).unwrap();
        delegations
            .add_delegation(low_self_id, Bytes32::from([0xAA; 32]), 1_000_000_000, 0)
            .unwrap();

        vs.select_active_set(&delegations, 0);

        assert!(
            matches!(
                vs.get(&low_self_id).unwrap().status,
                ValidatorStatus::Registered
            ),
            "delegated stake must not promote a validator with insufficient self-stake"
        );
        assert_eq!(vs.active_count(), 20);
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
pub struct StakeBondOutput {
    /// Public value in Spark for the bonded output.
    pub value_spark: u64,
    /// Pedersen commitment from the original bonded output.
    pub commitment: indra_core::types::crypto::CommitmentV1,
    /// Owner's hybrid public key. Fully compact bonds intentionally omit it.
    pub owner_pubkey: Option<indra_core::types::crypto::HybridPubKey>,
    /// Original range proof for legacy bonds. Compact bonds intentionally omit it.
    pub range_proof: Option<VariableBytes<MAX_RANGE_PROOF_BYTES>>,
    /// Block height at which this output unlocks.
    pub lock_height: u64,
}

impl StakeBondOutput {
    /// Convert to a full `OutputV1` only when this legacy record retained a proof.
    pub fn to_legacy_output(&self) -> Option<OutputV1> {
        Some(OutputV1 {
            value_spark: self.value_spark,
            commitment: self.commitment,
            owner_pubkey: self.owner_pubkey.clone()?,
            range_proof: self.range_proof.clone()?,
            lock_height: self.lock_height,
        })
    }

    fn encode_legacy(&self, buf: &mut Vec<u8>) {
        self.to_legacy_output()
            .expect("legacy stake bond output must retain a range proof")
            .encode(buf);
    }

    fn encode_compact(&self, buf: &mut Vec<u8>) {
        self.value_spark.encode(buf);
        self.commitment.encode(buf);
        self.owner_pubkey
            .as_ref()
            .expect("range-proof-compact stake bond output must retain an owner pubkey")
            .encode(buf);
        self.lock_height.encode(buf);
    }

    fn encode_fully_compact(&self, buf: &mut Vec<u8>) {
        self.value_spark.encode(buf);
        self.commitment.encode(buf);
        self.lock_height.encode(buf);
    }

    fn legacy_encoded_len(&self) -> usize {
        self.to_legacy_output()
            .expect("legacy stake bond output must retain a range proof")
            .encoded_len()
    }

    fn compact_encoded_len(&self) -> usize {
        self.value_spark.encoded_len()
            + self.commitment.encoded_len()
            + self
                .owner_pubkey
                .as_ref()
                .expect("range-proof-compact stake bond output must retain an owner pubkey")
                .encoded_len()
            + self.lock_height.encoded_len()
    }

    fn fully_compact_encoded_len(&self) -> usize {
        self.value_spark.encoded_len()
            + self.commitment.encoded_len()
            + self.lock_height.encoded_len()
    }
}

impl From<OutputV1> for StakeBondOutput {
    fn from(output: OutputV1) -> Self {
        Self {
            value_spark: output.value_spark,
            commitment: output.commitment,
            owner_pubkey: Some(output.owner_pubkey),
            range_proof: Some(output.range_proof),
            lock_height: output.lock_height,
        }
    }
}

impl From<StakeBondOutput> for OutputV1 {
    fn from(output: StakeBondOutput) -> Self {
        output
            .to_legacy_output()
            .expect("cannot convert compact stake bond output into full OutputV1")
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
    /// Original UTXO output metadata, needed to reinsert when unbonding completes.
    pub original_output: StakeBondOutput,
}

impl Encode for StakeBondEntry {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.encoding_marker().encode(buf);
        self.utxo_id.encode(buf);
        self.validator_id.encode(buf);
        self.delegator_id.encode(buf);
        self.amount_spark.encode(buf);
        self.bonded_epoch.encode(buf);
        self.unbonding_end_epoch.is_some().encode(buf);
        if let Some(epoch) = self.unbonding_end_epoch {
            epoch.encode(buf);
        }
        match self.encoding_marker() {
            SCHEMA_VERSION => self.original_output.encode_legacy(buf),
            STAKE_BOND_COMPACT_MARKER => self.original_output.encode_compact(buf),
            STAKE_BOND_FULLY_COMPACT_MARKER => self.original_output.encode_fully_compact(buf),
            _ => unreachable!("stake bond encoding marker is constrained"),
        }
    }

    fn encoded_len(&self) -> usize {
        1 + self.utxo_id.encoded_len()
            + self.validator_id.encoded_len()
            + self.delegator_id.encoded_len()
            + self.amount_spark.encoded_len()
            + self.bonded_epoch.encoded_len()
            + 1
            + self.unbonding_end_epoch.map(|_| 8).unwrap_or(0)
            + match self.encoding_marker() {
                SCHEMA_VERSION => self.original_output.legacy_encoded_len(),
                STAKE_BOND_COMPACT_MARKER => self.original_output.compact_encoded_len(),
                STAKE_BOND_FULLY_COMPACT_MARKER => self.original_output.fully_compact_encoded_len(),
                _ => unreachable!("stake bond encoding marker is constrained"),
            }
    }
}

impl Decode for StakeBondEntry {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let marker = u8::decode(r)?;
        match marker {
            SCHEMA_VERSION_GENESIS
            | SCHEMA_VERSION_PRE_VALIDATOR_NETWORK_ADDRESS
            | SCHEMA_VERSION => decode_stake_bond_entry_fields(r, None),
            STAKE_BOND_COMPACT_MARKER => decode_compact_stake_bond_entry_fields(r),
            STAKE_BOND_FULLY_COMPACT_MARKER => decode_fully_compact_stake_bond_entry_fields(r),
            other if r.remaining() == 0 => Err(unsupported_schema("StakeBondEntry", other)),
            first_byte => decode_stake_bond_entry_fields(r, Some(first_byte)),
        }
    }
}

impl StakeBondEntry {
    fn encoding_marker(&self) -> u8 {
        match (
            self.original_output.range_proof.is_some(),
            self.original_output.owner_pubkey.is_some(),
        ) {
            (true, true) => SCHEMA_VERSION,
            (false, true) => STAKE_BOND_COMPACT_MARKER,
            (false, false) => STAKE_BOND_FULLY_COMPACT_MARKER,
            (true, false) => {
                panic!("stake bond cannot retain a range proof without an owner pubkey")
            }
        }
    }

    /// Decode the legacy unversioned stake bond layout.
    pub fn decode_legacy(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        decode_stake_bond_entry_fields(r, None)
    }
}

#[cfg(test)]
mod stake_bond_entry_tests {
    use super::*;
    use indra_core::codec::Decode;
    use indra_core::types::crypto::{CommitmentV1, HybridPubKey};
    use indra_core::types::primitives::hard_forks::COMPACT_STAKE_BOND_HEIGHT;

    fn output(byte: u8, proof_len: usize) -> OutputV1 {
        OutputV1 {
            value_spark: 1_000,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from([byte; 32]),
            },
            owner_pubkey: HybridPubKey {
                classical_pk: Bytes32::from([byte.wrapping_add(1); 32]),
                pq_pk: VariableBytes::from_slice(&vec![byte.wrapping_add(2); 2_592]).unwrap(),
            },
            range_proof: VariableBytes::from_slice(&vec![byte.wrapping_add(3); proof_len]).unwrap(),
            lock_height: 17,
        }
    }

    fn legacy_bond(byte: u8) -> StakeBondEntry {
        StakeBondEntry::new(
            Bytes32::from([byte; 32]),
            Bytes32::from([0xA0; 32]),
            Bytes32::from([0xD0; 32]),
            1_000,
            3,
            output(byte, 674),
            COMPACT_STAKE_BOND_HEIGHT.saturating_sub(1),
        )
    }

    fn compact_bond(byte: u8) -> StakeBondEntry {
        StakeBondEntry::new(
            Bytes32::from([byte; 32]),
            Bytes32::from([0xA0; 32]),
            Bytes32::from([0xD0; 32]),
            1_000,
            3,
            output(byte, 674),
            COMPACT_STAKE_BOND_HEIGHT,
        )
    }

    fn fully_compact_bond(byte: u8) -> StakeBondEntry {
        StakeBondEntry::new_for_test_with_compact_and_pubkey_activation(
            Bytes32::from([byte; 32]),
            Bytes32::from([0xA0; 32]),
            Bytes32::from([0xD0; 32]),
            1_000,
            3,
            output(byte, 674),
            20,
            10,
            20,
        )
    }

    fn encode_old_layout(bond: &StakeBondEntry) -> Vec<u8> {
        let mut buf = Vec::new();
        SCHEMA_VERSION.encode(&mut buf);
        bond.utxo_id.encode(&mut buf);
        bond.validator_id.encode(&mut buf);
        bond.delegator_id.encode(&mut buf);
        bond.amount_spark.encode(&mut buf);
        bond.bonded_epoch.encode(&mut buf);
        bond.unbonding_end_epoch.is_some().encode(&mut buf);
        if let Some(epoch) = bond.unbonding_end_epoch {
            epoch.encode(&mut buf);
        }
        bond.original_output
            .to_legacy_output()
            .unwrap()
            .encode(&mut buf);
        buf
    }

    fn encode_range_proof_compact_layout(bond: &StakeBondEntry) -> Vec<u8> {
        let mut buf = Vec::new();
        STAKE_BOND_COMPACT_MARKER.encode(&mut buf);
        bond.utxo_id.encode(&mut buf);
        bond.validator_id.encode(&mut buf);
        bond.delegator_id.encode(&mut buf);
        bond.amount_spark.encode(&mut buf);
        bond.bonded_epoch.encode(&mut buf);
        bond.unbonding_end_epoch.is_some().encode(&mut buf);
        if let Some(epoch) = bond.unbonding_end_epoch {
            epoch.encode(&mut buf);
        }
        bond.original_output.value_spark.encode(&mut buf);
        bond.original_output.commitment.encode(&mut buf);
        bond.original_output
            .owner_pubkey
            .as_ref()
            .unwrap()
            .encode(&mut buf);
        bond.original_output.lock_height.encode(&mut buf);
        buf
    }

    #[test]
    fn legacy_stake_bond_encoding_is_byte_identical() {
        let bond = legacy_bond(0x11);
        assert!(bond.original_output.range_proof.is_some());
        assert!(bond.original_output.owner_pubkey.is_some());
        let encoded = bond.encode_to_vec();
        assert_eq!(encoded, encode_old_layout(&bond));
        let decoded = StakeBondEntry::decode(&mut ByteReader::new(&encoded)).unwrap();
        assert_eq!(decoded, bond);
        assert_eq!(decoded.encode_to_vec(), encoded);
    }

    #[test]
    fn compact_stake_bond_encoding_omits_range_proof_and_round_trips() {
        let bond = compact_bond(0x12);
        assert!(bond.original_output.range_proof.is_none());
        assert!(bond.original_output.owner_pubkey.is_some());
        let encoded = bond.encode_to_vec();
        assert_eq!(encoded[0], STAKE_BOND_COMPACT_MARKER);
        assert_eq!(encoded, encode_range_proof_compact_layout(&bond));
        assert_eq!(
            encoded.len(),
            encode_old_layout(&legacy_bond(0x12)).len() - (4 + 674)
        );
        let decoded = StakeBondEntry::decode(&mut ByteReader::new(&encoded)).unwrap();
        assert_eq!(decoded, bond);
        assert_eq!(decoded.encode_to_vec(), encoded);
    }

    #[test]
    fn fully_compact_bond_encoding_omits_range_proof_and_owner_pubkey_and_round_trips() {
        let bond = fully_compact_bond(0x16);
        assert!(bond.original_output.range_proof.is_none());
        assert!(bond.original_output.owner_pubkey.is_none());
        let encoded = bond.encode_to_vec();
        assert_eq!(encoded[0], STAKE_BOND_FULLY_COMPACT_MARKER);
        assert_eq!(
            encoded.len(),
            encode_old_layout(&legacy_bond(0x16)).len() - (4 + 674) - (4 + 2_624)
        );
        let decoded = StakeBondEntry::decode(&mut ByteReader::new(&encoded)).unwrap();
        assert_eq!(decoded, bond);
        assert_eq!(decoded.encode_to_vec(), encoded);
    }

    #[test]
    fn mutating_legacy_bond_after_compact_activation_keeps_stored_proof() {
        let mut bond = legacy_bond(0x13);
        let before = bond.original_output.range_proof.clone();
        bond.amount_spark = bond.amount_spark.saturating_sub(25);
        bond.unbonding_end_epoch = Some(99);
        assert_eq!(bond.original_output.range_proof, before);
        let decoded = StakeBondEntry::decode(&mut ByteReader::new(&bond.encode_to_vec())).unwrap();
        assert_eq!(decoded.original_output.range_proof, before);
    }

    #[test]
    fn compact_bond_measured_encoding_saves_range_proof_payload_and_length_prefix() {
        let legacy = legacy_bond(0x14);
        let compact = compact_bond(0x14);
        assert_eq!(
            legacy.encoded_len().saturating_sub(compact.encoded_len()),
            4 + 674
        );
    }

    #[test]
    fn fully_compact_bond_measured_encoding_saves_range_proof_and_owner_pubkey() {
        let legacy = legacy_bond(0x15);
        let range_only = compact_bond(0x15);
        let fully_compact = fully_compact_bond(0x15);
        assert_eq!(
            legacy
                .encoded_len()
                .saturating_sub(range_only.encoded_len()),
            678
        );
        assert_eq!(
            range_only
                .encoded_len()
                .saturating_sub(fully_compact.encoded_len()),
            2_628
        );
        assert_eq!(
            legacy
                .encoded_len()
                .saturating_sub(fully_compact.encoded_len()),
            3_306
        );
    }

    #[test]
    fn fully_compact_bond_scale_savings_capacity_curve() {
        let legacy = legacy_bond(0x17).encoded_len();
        let fully_compact = fully_compact_bond(0x17).encoded_len();
        let per_bond = legacy.saturating_sub(fully_compact);
        assert_eq!(per_bond, 3_306);
        for bonds in [1_000_000usize, 10_000_000, 150_000_000] {
            assert_eq!(
                legacy
                    .saturating_mul(bonds)
                    .saturating_sub(fully_compact.saturating_mul(bonds)),
                per_bond.saturating_mul(bonds)
            );
        }
    }

    #[test]
    fn bond_shape_replay_is_deterministic_across_range_and_pubkey_omission_boundaries() {
        fn replay() -> Vec<Vec<u8>> {
            [9u8, 10, 20]
                .into_iter()
                .map(|height| {
                    StakeBondEntry::new_for_test_with_compact_and_pubkey_activation(
                        Bytes32::from([height; 32]),
                        Bytes32::from([0xA0; 32]),
                        Bytes32::from([0xD0; 32]),
                        1_000,
                        height as u64,
                        output(height, 674),
                        height as u64,
                        10,
                        20,
                    )
                    .encode_to_vec()
                })
                .collect()
        }

        let first = replay();
        let second = replay();
        assert_eq!(first, second);
        assert_eq!(first[0][0], SCHEMA_VERSION);
        assert_eq!(first[1][0], STAKE_BOND_COMPACT_MARKER);
        assert_eq!(first[2][0], STAKE_BOND_FULLY_COMPACT_MARKER);
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
        original_output: OutputV1::decode(r)?.into(),
    })
}

fn decode_compact_stake_bond_entry_fields(r: &mut ByteReader<'_>) -> IndraResult<StakeBondEntry> {
    Ok(StakeBondEntry {
        utxo_id: Bytes32::decode(r)?,
        validator_id: Bytes32::decode(r)?,
        delegator_id: Bytes32::decode(r)?,
        amount_spark: u64::decode(r)?,
        bonded_epoch: u64::decode(r)?,
        unbonding_end_epoch: if bool::decode(r)? {
            Some(u64::decode(r)?)
        } else {
            None
        },
        original_output: StakeBondOutput {
            value_spark: u64::decode(r)?,
            commitment: indra_core::types::crypto::CommitmentV1::decode(r)?,
            owner_pubkey: Some(indra_core::types::crypto::HybridPubKey::decode(r)?),
            range_proof: None,
            lock_height: u64::decode(r)?,
        },
    })
}

fn decode_fully_compact_stake_bond_entry_fields(
    r: &mut ByteReader<'_>,
) -> IndraResult<StakeBondEntry> {
    Ok(StakeBondEntry {
        utxo_id: Bytes32::decode(r)?,
        validator_id: Bytes32::decode(r)?,
        delegator_id: Bytes32::decode(r)?,
        amount_spark: u64::decode(r)?,
        bonded_epoch: u64::decode(r)?,
        unbonding_end_epoch: if bool::decode(r)? {
            Some(u64::decode(r)?)
        } else {
            None
        },
        original_output: StakeBondOutput {
            value_spark: u64::decode(r)?,
            commitment: indra_core::types::crypto::CommitmentV1::decode(r)?,
            owner_pubkey: None,
            range_proof: None,
            lock_height: u64::decode(r)?,
        },
    })
}

impl StakeBondEntry {
    /// Build a new stake bond and choose its proof retention once, at creation.
    pub fn new(
        utxo_id: Bytes32,
        validator_id: Bytes32,
        delegator_id: Bytes32,
        amount_spark: u64,
        bonded_epoch: u64,
        original_output: OutputV1,
        current_height: u64,
    ) -> Self {
        let mut original_output: StakeBondOutput = original_output.into();
        if compact_stake_bond_active(current_height) {
            original_output.range_proof = None;
        }
        if compact_bond_pubkey_omission_active(current_height) {
            original_output.range_proof = None;
            original_output.owner_pubkey = None;
        }
        Self {
            utxo_id,
            validator_id,
            delegator_id,
            amount_spark,
            bonded_epoch,
            unbonding_end_epoch: None,
            original_output,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test_with_compact_activation(
        utxo_id: Bytes32,
        validator_id: Bytes32,
        delegator_id: Bytes32,
        amount_spark: u64,
        bonded_epoch: u64,
        original_output: OutputV1,
        current_height: u64,
        compact_activation_height: u64,
    ) -> Self {
        let mut original_output: StakeBondOutput = original_output.into();
        if current_height >= compact_activation_height {
            original_output.range_proof = None;
        }
        Self {
            utxo_id,
            validator_id,
            delegator_id,
            amount_spark,
            bonded_epoch,
            unbonding_end_epoch: None,
            original_output,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test_with_compact_and_pubkey_activation(
        utxo_id: Bytes32,
        validator_id: Bytes32,
        delegator_id: Bytes32,
        amount_spark: u64,
        bonded_epoch: u64,
        original_output: OutputV1,
        current_height: u64,
        compact_activation_height: u64,
        pubkey_omission_height: u64,
    ) -> Self {
        let mut original_output: StakeBondOutput = original_output.into();
        if current_height >= compact_activation_height {
            original_output.range_proof = None;
        }
        if current_height >= pubkey_omission_height {
            original_output.range_proof = None;
            original_output.owner_pubkey = None;
        }
        Self {
            utxo_id,
            validator_id,
            delegator_id,
            amount_spark,
            bonded_epoch,
            unbonding_end_epoch: None,
            original_output,
        }
    }
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
            SCHEMA_VERSION_GENESIS
            | SCHEMA_VERSION_PRE_VALIDATOR_NETWORK_ADDRESS
            | SCHEMA_VERSION => decode_delegator_entry_fields(r, None),
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
    ///
    /// The outer map is persistent/path-copying so ChainState clones share
    /// untouched validator delegation lists. The inner Vec deliberately stays
    /// unchanged because insertion order is consensus-visible in encoding.
    delegators: PersistentOrdMap<Bytes32, Vec<DelegatorEntry>>,
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
        if count > MAX_VALIDATORS {
            return Err(IndraError::LengthExceeded {
                field: "snapshot.delegations",
                max: MAX_VALIDATORS,
                actual: count,
            });
        }
        let mut delegators = PersistentOrdMap::new();
        for _ in 0..count {
            let validator_id = Bytes32::decode(r)?;
            if delegators.contains_key(&validator_id) {
                return Err(IndraError::DuplicateEntries {
                    field: "snapshot.delegations",
                });
            }
            let entries: Vec<DelegatorEntry> = decode_list(
                r,
                MAX_DELEGATORS_PER_VALIDATOR_DECODE,
                "snapshot.delegators",
            )?;
            delegators.insert(validator_id, entries);
        }
        Ok(Self { delegators })
    }
}

impl DelegationMap {
    /// Create an empty delegation map.
    pub fn new() -> Self {
        Self {
            delegators: PersistentOrdMap::new(),
        }
    }

    /// Decode a legacy unversioned delegation map.
    pub fn decode_legacy(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let count = u32::decode(r)? as usize;
        if count > MAX_VALIDATORS {
            return Err(IndraError::LengthExceeded {
                field: "snapshot.delegations",
                max: MAX_VALIDATORS,
                actual: count,
            });
        }
        let mut delegators = PersistentOrdMap::new();
        for _ in 0..count {
            let validator_id = Bytes32::decode(r)?;
            if delegators.contains_key(&validator_id) {
                return Err(IndraError::DuplicateEntries {
                    field: "snapshot.delegations",
                });
            }
            let entry_count = u32::decode(r)? as usize;
            if entry_count > MAX_DELEGATORS_PER_VALIDATOR_DECODE {
                return Err(IndraError::LengthExceeded {
                    field: "snapshot.delegators",
                    max: MAX_DELEGATORS_PER_VALIDATOR_DECODE,
                    actual: entry_count,
                });
            }
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

    /// Test/benchmark-only direct insertion helper for constructing very large
    /// synthetic delegation maps without making setup O(n²) through the normal
    /// live add path.
    #[cfg(test)]
    pub(crate) fn push_delegator_for_test(&mut self, validator_id: Bytes32, entry: DelegatorEntry) {
        let mut entries = self
            .delegators
            .get(&validator_id)
            .cloned()
            .unwrap_or_default();
        entries.push(entry);
        self.delegators.insert(validator_id, entries);
    }

    /// Update a specific delegator entry for a validator.
    pub fn update_delegator<R>(
        &mut self,
        validator_id: &Bytes32,
        delegator_id: &Bytes32,
        f: impl FnOnce(&mut DelegatorEntry) -> R,
    ) -> Option<R> {
        let mut entries = self.delegators.get(validator_id)?.clone();
        let result = {
            let entry = entries
                .iter_mut()
                .find(|d| &d.delegator_id == delegator_id)?;
            f(entry)
        };
        self.delegators.insert(*validator_id, entries);
        Some(result)
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

    /// Remove all delegation entries for a validator, returning them for
    /// immediate principal/reward settlement.
    pub fn take_delegators(&mut self, validator_id: &Bytes32) -> Vec<DelegatorEntry> {
        self.delegators.remove(validator_id).unwrap_or_default()
    }

    /// Remove a specific virtual delegation entry without unbonding.
    pub fn remove_virtual_delegation(&mut self, validator_id: &Bytes32, delegator_id: &Bytes32) {
        let Some(mut entries) = self.delegators.get(validator_id).cloned() else {
            return;
        };
        entries.retain(|d| &d.delegator_id != delegator_id);
        if entries.is_empty() {
            self.delegators.remove(validator_id);
        } else {
            self.delegators.insert(*validator_id, entries);
        }
    }

    /// Add a new delegation or increase an existing one.
    pub fn add_delegation(
        &mut self,
        validator_id: Bytes32,
        delegator_id: Bytes32,
        amount_spark: u64,
        current_epoch: u64,
    ) -> Result<(), &'static str> {
        let mut entries = self
            .delegators
            .get(&validator_id)
            .cloned()
            .unwrap_or_default();
        if let Some(existing) = entries.iter_mut().find(|d| d.delegator_id == delegator_id) {
            existing.staked_spark = existing.staked_spark.saturating_add(amount_spark);
        } else {
            if entries.len() >= MAX_DELEGATORS_PER_VALIDATOR {
                return Err("validator delegator count at maximum");
            }
            entries.push(DelegatorEntry {
                delegator_id,
                staked_spark: amount_spark,
                pending_rewards: 0,
                rewards_last_epoch: current_epoch,
                unbonding_end_epoch: None,
            });
        }
        self.delegators.insert(validator_id, entries);
        Ok(())
    }

    /// Begin unbonding a delegation. Returns error string if not found or already unbonding.
    pub fn begin_undelegate(
        &mut self,
        validator_id: &Bytes32,
        delegator_id: &Bytes32,
        amount_spark: u64,
        unbonding_end_epoch: u64,
    ) -> Result<(), &'static str> {
        let mut entries = self
            .delegators
            .get(validator_id)
            .cloned()
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
        self.delegators.insert(*validator_id, entries);
        Ok(())
    }

    /// Release delegators whose unbonding period has ended.
    /// Returns the total Spark to be returned to delegators.
    pub fn release_unbonded(&mut self, current_epoch: u64) -> u64 {
        let mut released: u64 = 0;
        let validator_ids: Vec<_> = self.delegators.iter().map(|(id, _)| *id).collect();
        for validator_id in validator_ids {
            let Some(mut entries) = self.delegators.get(&validator_id).cloned() else {
                continue;
            };
            entries.retain(|d| {
                if let Some(end) = d.unbonding_end_epoch {
                    if end <= current_epoch {
                        released = released.saturating_add(d.staked_spark);
                        return false; // remove entry
                    }
                }
                true
            });
            if entries.is_empty() {
                self.delegators.remove(&validator_id);
            } else {
                self.delegators.insert(validator_id, entries);
            }
        }
        released
    }

    /// Expire stale delegator rewards across all validators.
    pub fn expire_stale_rewards(&mut self, current_epoch: u64) {
        let validator_ids: Vec<_> = self.delegators.iter().map(|(id, _)| *id).collect();
        for validator_id in validator_ids {
            let Some(mut entries) = self.delegators.get(&validator_id).cloned() else {
                continue;
            };
            for entry in entries.iter_mut() {
                if entry.pending_rewards > 0 && entry.rewards_expired(current_epoch) {
                    entry.pending_rewards = 0;
                }
            }
            self.delegators.insert(validator_id, entries);
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
        let mut entries = match self.delegators.get(validator_id).cloned() {
            Some(entries) => entries,
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

        self.delegators.insert(*validator_id, entries);

        pool.saturating_sub(distributed) // remainder back to treasury
    }
}

#[cfg(test)]
mod delegation_map_tests {
    use super::*;
    use std::{env, time::Instant};

    fn test_id(domain: u8, index: usize) -> Bytes32 {
        let mut bytes = [0u8; 32];
        bytes[0] = domain;
        bytes[8..16].copy_from_slice(&(index as u64).to_be_bytes());
        Bytes32::from(bytes)
    }

    fn delegator_entry(index: usize) -> DelegatorEntry {
        DelegatorEntry {
            delegator_id: test_id(0xD0, index),
            staked_spark: 1_000,
            pending_rewards: 0,
            rewards_last_epoch: 0,
            unbonding_end_epoch: None,
        }
    }

    fn map_with_delegator_count(validator_id: Bytes32, count: usize) -> DelegationMap {
        let mut delegators = PersistentOrdMap::new();
        let entries = (0..count).map(delegator_entry).collect();
        delegators.insert(validator_id, entries);
        DelegationMap { delegators }
    }

    fn encode_legacy_btreemap(map: &BTreeMap<Bytes32, Vec<DelegatorEntry>>) -> Vec<u8> {
        let mut buf = Vec::new();
        (map.len() as u32).encode(&mut buf);
        for (validator_id, delegators) in map.iter() {
            validator_id.encode(&mut buf);
            encode_list(delegators, &mut buf);
        }
        buf
    }

    fn build_maps(
        total_delegators: usize,
    ) -> (DelegationMap, BTreeMap<Bytes32, Vec<DelegatorEntry>>, usize) {
        let validator_count = total_delegators
            .div_ceil(MAX_DELEGATORS_PER_VALIDATOR)
            .max(1);
        assert!(validator_count <= MAX_VALIDATORS);
        let mut persistent = PersistentOrdMap::new();
        let mut legacy = BTreeMap::new();
        let mut remaining = total_delegators;
        let mut next_delegator = 0usize;
        for validator_index in 0..validator_count {
            let validator_id = test_id(0xA0, validator_index);
            let count = remaining.min(MAX_DELEGATORS_PER_VALIDATOR);
            let entries: Vec<_> = (0..count)
                .map(|_| {
                    let entry = delegator_entry(next_delegator);
                    next_delegator += 1;
                    entry
                })
                .collect();
            persistent.insert(validator_id, entries.clone());
            legacy.insert(validator_id, entries);
            remaining -= count;
        }
        (
            DelegationMap {
                delegators: persistent,
            },
            legacy,
            validator_count,
        )
    }

    fn legacy_add_delegation(
        map: &mut BTreeMap<Bytes32, Vec<DelegatorEntry>>,
        validator_id: Bytes32,
        delegator_id: Bytes32,
        amount_spark: u64,
        current_epoch: u64,
    ) -> Result<(), &'static str> {
        let entries = map.entry(validator_id).or_default();
        if let Some(existing) = entries.iter_mut().find(|d| d.delegator_id == delegator_id) {
            existing.staked_spark = existing.staked_spark.saturating_add(amount_spark);
        } else {
            if entries.len() >= MAX_DELEGATORS_PER_VALIDATOR {
                return Err("validator delegator count at maximum");
            }
            entries.push(DelegatorEntry {
                delegator_id,
                staked_spark: amount_spark,
                pending_rewards: 0,
                rewards_last_epoch: current_epoch,
                unbonding_end_epoch: None,
            });
        }
        Ok(())
    }

    fn legacy_begin_undelegate(
        map: &mut BTreeMap<Bytes32, Vec<DelegatorEntry>>,
        validator_id: &Bytes32,
        delegator_id: &Bytes32,
        amount_spark: u64,
        unbonding_end_epoch: u64,
    ) -> Result<(), &'static str> {
        let entries = map
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
        if entry.staked_spark < DUST_LIMIT_SPARK {
            entry.staked_spark = 0;
        }
        entry.unbonding_end_epoch = Some(unbonding_end_epoch);
        Ok(())
    }

    #[test]
    fn delegation_map_persistent_encoding_matches_legacy_btreemap() {
        for total in [0usize, 3, 11] {
            let (map, legacy, _) = build_maps(total);
            assert_eq!(map.encode_to_vec(), encode_legacy_btreemap(&legacy));
            assert_eq!(
                DelegationMap::decode_exact(&map.encode_to_vec()).unwrap(),
                map
            );
        }
    }

    #[test]
    fn delegation_map_outer_insertion_order_independent_inner_order_preserved() {
        let validator_a = test_id(0xA0, 1);
        let validator_b = test_id(0xA0, 2);
        let inner = vec![delegator_entry(1), delegator_entry(2), delegator_entry(3)];

        let mut forward = DelegationMap::new();
        forward.delegators.insert(validator_a, inner.clone());
        forward
            .delegators
            .insert(validator_b, vec![delegator_entry(4)]);

        let mut reverse = DelegationMap::new();
        reverse
            .delegators
            .insert(validator_b, vec![delegator_entry(4)]);
        reverse.delegators.insert(validator_a, inner.clone());

        assert_eq!(forward.encode_to_vec(), reverse.encode_to_vec());

        let mut reversed_inner = inner;
        reversed_inner.reverse();
        let mut different_inner_order = DelegationMap::new();
        different_inner_order
            .delegators
            .insert(validator_a, reversed_inner);
        different_inner_order
            .delegators
            .insert(validator_b, vec![delegator_entry(4)]);

        assert_ne!(
            forward.encode_to_vec(),
            different_inner_order.encode_to_vec()
        );
    }

    #[test]
    #[ignore = "release-mode Stage 2c delegation-map encode/clone benchmark; run with --release --ignored"]
    fn delegation_map_persistent_encoding_and_clone_benchmark() {
        let sizes = env::var("INDRA_STAGE2C_DELEGATION_BENCH_SIZES")
            .unwrap_or_else(|_| "100000,1000000".to_string());
        for size in sizes
            .split(',')
            .map(|part| part.trim().parse::<usize>().unwrap())
        {
            let (map, legacy, validator_count) = build_maps(size);

            let legacy_encoded = encode_legacy_btreemap(&legacy);
            let migrated_encoded = map.encode_to_vec();
            assert_eq!(migrated_encoded, legacy_encoded);

            let persistent_clone_start = Instant::now();
            let persistent_clone = map.clone();
            let persistent_clone_elapsed = persistent_clone_start.elapsed();
            assert_eq!(
                persistent_clone.get_delegators(&test_id(0xA0, 0)).len(),
                size.min(MAX_DELEGATORS_PER_VALIDATOR)
            );

            let legacy_clone_start = Instant::now();
            let legacy_clone = legacy.clone();
            let legacy_clone_elapsed = legacy_clone_start.elapsed();
            assert_eq!(legacy_clone.len(), validator_count);

            println!(
                "stage2c_delegation_map_clone delegators={size} validators={validator_count} legacy_btreemap_clone={legacy_clone_elapsed:?} persistent_ord_map_clone={persistent_clone_elapsed:?}"
            );
        }
    }

    #[test]
    #[ignore = "release-mode Stage 2c single-validator Vec mutation benchmark; run with --release --ignored"]
    fn delegation_map_single_validator_vec_mutation_benchmark() {
        let validator_id = test_id(0xA0, 0);
        let existing_delegator = test_id(0xD0, MAX_DELEGATORS_PER_VALIDATOR - 1);

        let (mut migrated_existing, mut legacy_existing, _) =
            build_maps(MAX_DELEGATORS_PER_VALIDATOR);
        let legacy_existing_start = Instant::now();
        legacy_add_delegation(&mut legacy_existing, validator_id, existing_delegator, 1, 1)
            .unwrap();
        let legacy_existing_elapsed = legacy_existing_start.elapsed();
        let migrated_existing_start = Instant::now();
        migrated_existing
            .add_delegation(validator_id, existing_delegator, 1, 1)
            .unwrap();
        let migrated_existing_elapsed = migrated_existing_start.elapsed();
        assert_eq!(
            migrated_existing.encode_to_vec(),
            encode_legacy_btreemap(&legacy_existing)
        );

        let (mut migrated_add, mut legacy_add, _) = build_maps(MAX_DELEGATORS_PER_VALIDATOR - 1);
        let new_delegator = test_id(0xD1, MAX_DELEGATORS_PER_VALIDATOR);
        let legacy_add_start = Instant::now();
        legacy_add_delegation(&mut legacy_add, validator_id, new_delegator, 1_000, 1).unwrap();
        let legacy_add_elapsed = legacy_add_start.elapsed();
        let migrated_add_start = Instant::now();
        migrated_add
            .add_delegation(validator_id, new_delegator, 1_000, 1)
            .unwrap();
        let migrated_add_elapsed = migrated_add_start.elapsed();
        assert_eq!(
            migrated_add.encode_to_vec(),
            encode_legacy_btreemap(&legacy_add)
        );

        let (mut migrated_undelegate, mut legacy_undelegate, _) =
            build_maps(MAX_DELEGATORS_PER_VALIDATOR);
        let legacy_undelegate_start = Instant::now();
        legacy_begin_undelegate(
            &mut legacy_undelegate,
            &validator_id,
            &existing_delegator,
            1,
            42,
        )
        .unwrap();
        let legacy_undelegate_elapsed = legacy_undelegate_start.elapsed();
        let migrated_undelegate_start = Instant::now();
        migrated_undelegate
            .begin_undelegate(&validator_id, &existing_delegator, 1, 42)
            .unwrap();
        let migrated_undelegate_elapsed = migrated_undelegate_start.elapsed();
        assert_eq!(
            migrated_undelegate.encode_to_vec(),
            encode_legacy_btreemap(&legacy_undelegate)
        );

        println!(
            "stage2c_single_validator_vec_mutation delegators_per_validator={} increase_existing legacy={:?} migrated={:?} add_new_at_99999 legacy={:?} migrated={:?} begin_undelegate legacy={:?} migrated={:?}",
            MAX_DELEGATORS_PER_VALIDATOR,
            legacy_existing_elapsed,
            migrated_existing_elapsed,
            legacy_add_elapsed,
            migrated_add_elapsed,
            legacy_undelegate_elapsed,
            migrated_undelegate_elapsed,
        );
    }

    #[test]
    fn delegation_add_rejects_past_cap() {
        let validator_id = test_id(0xA0, 1);
        let mut map = map_with_delegator_count(validator_id, MAX_DELEGATORS_PER_VALIDATOR);

        let result = map.add_delegation(
            validator_id,
            test_id(0xD1, MAX_DELEGATORS_PER_VALIDATOR),
            1_000,
            0,
        );

        assert_eq!(result, Err("validator delegator count at maximum"));
        assert_eq!(
            map.get_delegators(&validator_id).len(),
            MAX_DELEGATORS_PER_VALIDATOR
        );
    }

    #[test]
    fn delegation_add_allows_up_to_cap() {
        let validator_id = test_id(0xA0, 2);
        let mut map = map_with_delegator_count(validator_id, MAX_DELEGATORS_PER_VALIDATOR - 1);

        map.add_delegation(
            validator_id,
            test_id(0xD1, MAX_DELEGATORS_PER_VALIDATOR - 1),
            1_000,
            0,
        )
        .unwrap();

        assert_eq!(
            map.get_delegators(&validator_id).len(),
            MAX_DELEGATORS_PER_VALIDATOR
        );
    }

    #[test]
    fn delegation_add_allows_existing_delegator_at_cap() {
        let validator_id = test_id(0xA0, 3);
        let existing_id = test_id(0xD0, 0);
        let mut map = map_with_delegator_count(validator_id, MAX_DELEGATORS_PER_VALIDATOR);

        map.add_delegation(validator_id, existing_id, 500, 0)
            .unwrap();

        let existing = map
            .get_delegators(&validator_id)
            .iter()
            .find(|entry| entry.delegator_id == existing_id)
            .unwrap();
        assert_eq!(existing.staked_spark, 1_500);
        assert_eq!(
            map.get_delegators(&validator_id).len(),
            MAX_DELEGATORS_PER_VALIDATOR
        );
    }

    #[test]
    fn live_delegation_cap_matches_decode_cap() {
        assert_eq!(
            MAX_DELEGATORS_PER_VALIDATOR,
            MAX_DELEGATORS_PER_VALIDATOR_DECODE
        );
    }

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
                )
                .unwrap();
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
