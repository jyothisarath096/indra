//! Validator set — the active set of staked validators.
//!
//! Tracks each validator's stake, status, and accumulated reward.
//! The validator set is snapshotted at each epoch boundary.

use std::{cell::RefCell, collections::BTreeMap, fmt};

use indra_core::codec::{decode_list, encode_list, list_encoded_len, ByteReader, Decode, Encode};
use indra_core::error::{IndraError, IndraResult};
use indra_core::types::{
    primitives::{
        max_active_validators, muldiv, Bytes32, VariableBytes, DUST_LIMIT_SPARK,
        MAX_DELEGATION_RETURN_EVENTS, MAX_RANGE_PROOF_BYTES, MAX_VALIDATORS,
        MAX_VALIDATOR_NETWORK_ADDR_LEN, MINIMUM_ACTIVE_SELF_STAKE_SPARK, SCHEMA_VERSION,
        SCHEMA_VERSION_GENESIS, SCHEMA_VERSION_PRE_VALIDATOR_NETWORK_ADDRESS,
        UNBONDING_PERIOD_EPOCHS,
    },
    transaction::OutputV1,
};

use crate::error::{StateError, StateResult};
use crate::persistent::PersistentOrdMap;

const VALIDATOR_ENTRY_FORMAT_VERSION: u8 = 1;
const STAKE_BOND_FORMAT_VERSION: u8 = 1;

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

/// Maximum unresolved validator self-bonds migrated by one enrollment.
pub const MAX_ATOMIC_COLD_KEY_MIGRATION_SELF_BONDS: usize = 4_096;

/// Why a stake bond principal was returned to a spendable UTXO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationReturnReason {
    /// Validator was evicted from the bounded registry by a higher-stake
    /// registration; all associated bonds were returned immediately.
    ValidatorEvicted,
    /// A normally unbonding stake bond reached its release epoch.
    UnbondingMatured,
}

impl Encode for DelegationReturnReason {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::ValidatorEvicted => 1u8.encode(buf),
            Self::UnbondingMatured => 2u8.encode(buf),
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
            2 => Ok(Self::UnbondingMatured),
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
    /// Ed25519 component of the independent cold authorization key.
    pub cold_hybrid_classical_pk: Option<[u8; 32]>,
    /// ML-DSA-87 component of the independent cold authorization key.
    pub cold_hybrid_pq_pk: Option<[u8; indra_crypto::PQ_PK_BYTES]>,
    /// Monotonic cold-key generation.
    pub cold_key_version: u64,
    /// Replay-protection nonce for cold-authorized operations.
    pub cold_nonce: u64,
}

impl Encode for ValidatorEntry {
    fn encode(&self, buf: &mut Vec<u8>) {
        VALIDATOR_ENTRY_FORMAT_VERSION.encode(buf);
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
        self.cold_hybrid_classical_pk.is_some().encode(buf);
        if let Some(pk) = self.cold_hybrid_classical_pk {
            buf.extend_from_slice(&pk);
        }
        self.cold_hybrid_pq_pk.is_some().encode(buf);
        if let Some(pk) = self.cold_hybrid_pq_pk {
            buf.extend_from_slice(&pk);
        }
        self.cold_key_version.encode(buf);
        self.cold_nonce.encode(buf);
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
            + 1
            + self.cold_hybrid_classical_pk.map(|_| 32).unwrap_or(0)
            + 1
            + self
                .cold_hybrid_pq_pk
                .map(|_| indra_crypto::PQ_PK_BYTES)
                .unwrap_or(0)
            + 8
            + 8
    }
}

impl Decode for ValidatorEntry {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let version = u8::decode(r)?;
        if version != VALIDATOR_ENTRY_FORMAT_VERSION {
            return Err(IndraError::UnsupportedSchemaVersion {
                struct_name: "ValidatorEntry",
                version,
                max_supported: VALIDATOR_ENTRY_FORMAT_VERSION,
            });
        }
        decode_validator_entry_fields(r)
    }
}

fn decode_validator_entry_fields(r: &mut ByteReader<'_>) -> IndraResult<ValidatorEntry> {
    let validator_id = Bytes32::decode(r)?;
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
    let pending_commission_bps = if bool::decode(r)? {
        Some(u16::decode(r)?)
    } else {
        None
    };
    let pending_commission_effective_epoch = if bool::decode(r)? {
        Some(u64::decode(r)?)
    } else {
        None
    };
    let min_delegation_spark = u64::decode(r)?;
    let auto_delegate_to = if bool::decode(r)? {
        Some(Bytes32::decode(r)?)
    } else {
        None
    };
    let (network_addr, network_addr_last_updated_epoch) = {
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
    };
    let cold_hybrid_classical_pk = if bool::decode(r)? {
        Some(
            r.read_bytes(32)?
                .try_into()
                .map_err(|_| IndraError::InvariantViolation {
                    message: "invalid cold classical pk length in snapshot",
                })?,
        )
    } else {
        None
    };
    let cold_hybrid_pq_pk = if bool::decode(r)? {
        Some(
            r.read_bytes(indra_crypto::PQ_PK_BYTES)?
                .try_into()
                .map_err(|_| IndraError::InvariantViolation {
                    message: "invalid cold PQ pk length in snapshot",
                })?,
        )
    } else {
        None
    };
    let cold_key_version = u64::decode(r)?;
    let cold_nonce = u64::decode(r)?;

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
        cold_hybrid_classical_pk,
        cold_hybrid_pq_pk,
        cold_key_version,
        cold_nonce,
    })
}

impl ValidatorEntry {
    /// Append the canonical cold-key projection.
    pub(crate) fn append_cold_key_commitment(&self, value: &mut Vec<u8>) {
        value.extend_from_slice(b"INDRA-VALIDATOR-COLD-KEY-V1");
        value.push(u8::from(self.cold_hybrid_classical_pk.is_some()));
        if let Some(pk) = self.cold_hybrid_classical_pk {
            value.extend_from_slice(&pk);
        }
        value.push(u8::from(self.cold_hybrid_pq_pk.is_some()));
        if let Some(pk) = self.cold_hybrid_pq_pk {
            value.extend_from_slice(&pk);
        }
        value.extend_from_slice(&self.cold_key_version.to_le_bytes());
        value.extend_from_slice(&self.cold_nonce.to_le_bytes());
    }

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

/// A complete cold hybrid public key that passed registry validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedColdKey {
    /// Validated Ed25519 component.
    pub classical_pk: [u8; 32],
    /// Validated ML-DSA-87 component.
    pub pq_pk: [u8; indra_crypto::PQ_PK_BYTES],
    /// Validated next key version.
    pub version: u64,
}

/// Validate a proposed cold key without mutating or enrolling the registry.
///
/// This enforces full-pair well-formedness, strictly sequential versions, and
/// global component-level uniqueness across both hot and cold roles.
pub fn validate_validator_cold_key(
    validators: &ValidatorSet,
    validator_id: &Bytes32,
    classical_bytes: &[u8],
    pq_bytes: &[u8],
    proposed_version: u64,
) -> StateResult<ValidatedColdKey> {
    let validator = validators.get(validator_id).ok_or_else(|| {
        StateError::InvalidStakingOp("cold-key validator is not registered".to_string())
    })?;
    let expected_version = validator
        .cold_key_version
        .checked_add(1)
        .ok_or_else(|| StateError::InvalidStakingOp("cold-key version overflow".to_string()))?;
    validate_cold_key_material(
        validators,
        validator_id,
        validator.hybrid_classical_pk,
        validator.hybrid_pq_pk.as_deref(),
        classical_bytes,
        pq_bytes,
        proposed_version,
        expected_version,
    )
}

/// Validate version-1 cold-key material for a not-yet-registered validator.
pub fn validate_new_validator_cold_key(
    validators: &ValidatorSet,
    validator_id: &Bytes32,
    proposed_hot_classical_pk: [u8; 32],
    proposed_hot_pq_pk: &[u8],
    classical_bytes: &[u8],
    pq_bytes: &[u8],
    proposed_version: u64,
) -> StateResult<ValidatedColdKey> {
    if validators.get(validator_id).is_some() {
        return Err(StateError::ValidatorAlreadyRegistered);
    }
    validate_cold_key_material(
        validators,
        validator_id,
        Some(proposed_hot_classical_pk),
        Some(proposed_hot_pq_pk),
        classical_bytes,
        pq_bytes,
        proposed_version,
        1,
    )
}

fn validate_cold_key_material(
    validators: &ValidatorSet,
    validator_id: &Bytes32,
    target_hot_classical_pk: Option<[u8; 32]>,
    target_hot_pq_pk: Option<&[u8]>,
    classical_bytes: &[u8],
    pq_bytes: &[u8],
    proposed_version: u64,
    expected_version: u64,
) -> StateResult<ValidatedColdKey> {
    if proposed_version == 0 || proposed_version != expected_version {
        return Err(StateError::InvalidStakingOp(format!(
            "cold-key version must be exactly {expected_version}, got {proposed_version}"
        )));
    }

    let classical_pk: [u8; 32] = classical_bytes.try_into().map_err(|_| {
        StateError::InvalidStakingOp(format!(
            "cold Ed25519 public key must be 32 bytes, got {}",
            classical_bytes.len()
        ))
    })?;
    let pq_pk: [u8; indra_crypto::PQ_PK_BYTES] = pq_bytes.try_into().map_err(|_| {
        StateError::InvalidStakingOp(format!(
            "cold ML-DSA-87 public key must be {} bytes, got {}",
            indra_crypto::PQ_PK_BYTES,
            pq_bytes.len()
        ))
    })?;
    indra_crypto::validate_classical_public_key(&indra_crypto::ClassicalPublicKey(classical_pk))
        .map_err(|err| {
            StateError::InvalidStakingOp(format!("malformed cold Ed25519 key: {err}"))
        })?;
    indra_crypto::validate_pq_public_key(&indra_crypto::PqPublicKey(pq_pk)).map_err(|err| {
        StateError::InvalidStakingOp(format!("malformed cold ML-DSA-87 key: {err}"))
    })?;
    if target_hot_classical_pk == Some(classical_pk) {
        return Err(StateError::DuplicateValidatorKey {
            reason: "cold Ed25519 component duplicates the validator hot component".to_string(),
        });
    }
    if target_hot_pq_pk.is_some_and(|hot| hot == pq_pk.as_slice()) {
        return Err(StateError::DuplicateValidatorKey {
            reason: "cold ML-DSA-87 component duplicates the validator hot component".to_string(),
        });
    }

    for existing in validators.all_validators() {
        if existing.validator_id != *validator_id
            && existing.cold_hybrid_classical_pk == Some(classical_pk)
            && existing.cold_hybrid_pq_pk == Some(pq_pk)
        {
            return Err(StateError::DuplicateValidatorKey {
                reason: "cold hybrid pair already registered to another validator".to_string(),
            });
        }
        if existing.hybrid_classical_pk == Some(classical_pk) {
            return Err(StateError::DuplicateValidatorKey {
                reason: "cold Ed25519 component duplicates a registered hot component".to_string(),
            });
        }
        if existing
            .hybrid_pq_pk
            .as_deref()
            .is_some_and(|hot| hot == pq_pk.as_slice())
        {
            return Err(StateError::DuplicateValidatorKey {
                reason: "cold ML-DSA-87 component duplicates a registered hot component"
                    .to_string(),
            });
        }
        if existing.cold_hybrid_classical_pk == Some(classical_pk) {
            return Err(StateError::DuplicateValidatorKey {
                reason: "cold Ed25519 component already registered".to_string(),
            });
        }
        if existing.cold_hybrid_pq_pk == Some(pq_pk) {
            return Err(StateError::DuplicateValidatorKey {
                reason: "cold ML-DSA-87 component already registered".to_string(),
            });
        }
    }

    Ok(ValidatedColdKey {
        classical_pk,
        pq_pk,
        version: proposed_version,
    })
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
        self.total_selectable_self_stake_at_height(0)
    }

    /// Total self-stake eligible for selection under the rules at `height`.
    pub fn total_selectable_self_stake_at_height(&self, height: u64) -> u64 {
        let _ = height;
        self.validators
            .values()
            .filter(|v| {
                matches!(
                    v.status,
                    ValidatorStatus::Active | ValidatorStatus::Registered
                ) && v.stake_spark >= MINIMUM_ACTIVE_SELF_STAKE_SPARK
            })
            .fold(0u64, |acc, v| acc.saturating_add(v.stake_spark))
    }

    /// Self-stake of the lowest-ranked active validator, if any.
    pub fn effective_min_active_stake(&self) -> Option<u64> {
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
    /// protocol. Full-registry replacement uses the same self-stake ranking
    /// model when deciding which persisted validator entry gets a scarce
    /// registry slot.
    pub fn select_active_set(&mut self, total_staked_spark: u64, height: u64) {
        let max_active = max_active_validators(total_staked_spark);
        let _ = height;
        let mut candidates: Vec<(Bytes32, u64)> = self
            .validators
            .values()
            .filter(|v| {
                matches!(
                    v.status,
                    ValidatorStatus::Active | ValidatorStatus::Registered
                ) && v.stake_spark >= MINIMUM_ACTIVE_SELF_STAKE_SPARK
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

    fn hybrid_components(seed: u8) -> ([u8; 32], [u8; indra_crypto::PQ_PK_BYTES]) {
        let keypair = indra_crypto::HybridKeypair::new(
            indra_crypto::ClassicalKeypair::from_seed(&[seed; 32]),
            indra_crypto::PqKeypair::from_seed(&[seed.wrapping_add(1); 32]).unwrap(),
        );
        let public = keypair.public_key();
        (public.classical.0, public.pq.0)
    }

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
            cold_hybrid_classical_pk: None,
            cold_hybrid_pq_pk: None,
            cold_key_version: 0,
            cold_nonce: 0,
        }
    }

    #[test]
    fn validator_cold_fields_roundtrip_in_canonical_format() {
        let base = make_validator(1, 10_000, 2);

        let (classical, pq) = hybrid_components(0x41);
        let mut active = base;
        active.cold_hybrid_classical_pk = Some(classical);
        active.cold_hybrid_pq_pk = Some(pq);
        active.cold_key_version = 1;
        active.cold_nonce = 7;
        let encoded = active.encode_to_vec();
        assert_eq!(encoded[0], VALIDATOR_ENTRY_FORMAT_VERSION);
        assert_eq!(ValidatorEntry::decode_exact(&encoded).unwrap(), active);
    }

    #[test]
    fn cold_registry_rejects_malformed_ed25519_keys() {
        let mut set = ValidatorSet::new();
        let validator = make_validator(1, 10_000, 0);
        let id = validator.validator_id;
        set.upsert(validator).unwrap();
        let (_, pq) = hybrid_components(0x31);

        assert!(validate_validator_cold_key(&set, &id, &[0xff; 31], &pq, 1).is_err());
        assert!(validate_validator_cold_key(&set, &id, &[0; 32], &pq, 1).is_err());
    }

    #[test]
    fn cold_registry_rejects_wrong_ml_dsa_87_length() {
        let mut set = ValidatorSet::new();
        let validator = make_validator(1, 10_000, 0);
        let id = validator.validator_id;
        set.upsert(validator).unwrap();
        let (classical, pq) = hybrid_components(0x32);

        assert!(
            validate_validator_cold_key(&set, &id, &classical, &pq[..pq.len() - 1], 1).is_err()
        );
    }

    #[test]
    fn cold_registry_rejects_component_pair_and_cross_role_reuse() {
        let (hot_a_classical, hot_a_pq) = hybrid_components(0x11);
        let (cold_a_classical, cold_a_pq) = hybrid_components(0x21);
        let (fresh_classical, fresh_pq) = hybrid_components(0x31);
        let mut a = make_validator(1, 10_000, 0);
        a.hybrid_classical_pk = Some(hot_a_classical);
        a.hybrid_pq_pk = Some(hot_a_pq.to_vec());
        a.cold_hybrid_classical_pk = Some(cold_a_classical);
        a.cold_hybrid_pq_pk = Some(cold_a_pq);
        a.cold_key_version = 1;
        let mut b = make_validator(2, 10_000, 0);
        let b_id = b.validator_id;
        let (hot_b_classical, hot_b_pq) = hybrid_components(0x41);
        b.hybrid_classical_pk = Some(hot_b_classical);
        b.hybrid_pq_pk = Some(hot_b_pq.to_vec());
        let mut set = ValidatorSet::new();
        set.upsert(a).unwrap();
        set.upsert(b).unwrap();

        assert!(
            validate_validator_cold_key(&set, &b_id, &cold_a_classical, &cold_a_pq, 1).is_err()
        );
        assert!(validate_validator_cold_key(&set, &b_id, &cold_a_classical, &fresh_pq, 1).is_err());
        assert!(validate_validator_cold_key(&set, &b_id, &fresh_classical, &cold_a_pq, 1).is_err());
        assert!(validate_validator_cold_key(&set, &b_id, &hot_a_classical, &fresh_pq, 1).is_err());
        assert!(validate_validator_cold_key(&set, &b_id, &fresh_classical, &hot_a_pq, 1).is_err());
        assert!(validate_validator_cold_key(&set, &b_id, &hot_b_classical, &fresh_pq, 1).is_err());
        assert!(validate_validator_cold_key(&set, &b_id, &fresh_classical, &hot_b_pq, 1).is_err());
    }

    #[test]
    fn cold_registry_rejects_same_pair_for_multiple_validator_ids() {
        let (classical, pq) = hybrid_components(0x61);
        let mut a = make_validator(1, 10_000, 0);
        a.cold_hybrid_classical_pk = Some(classical);
        a.cold_hybrid_pq_pk = Some(pq);
        a.cold_key_version = 1;
        let b = make_validator(2, 10_000, 0);
        let b_id = b.validator_id;
        let mut set = ValidatorSet::new();
        set.upsert(a).unwrap();
        set.upsert(b).unwrap();

        let err = validate_validator_cold_key(&set, &b_id, &classical, &pq, 1).unwrap_err();
        assert!(matches!(
            err,
            StateError::DuplicateValidatorKey { reason }
                if reason.contains("pair already registered")
        ));
    }

    #[test]
    fn cold_registry_rejects_own_cold_component_equal_to_hot_component() {
        let (hot_classical, hot_pq) = hybrid_components(0x71);
        let (fresh_classical, fresh_pq) = hybrid_components(0x72);
        let mut validator = make_validator(1, 10_000, 0);
        validator.hybrid_classical_pk = Some(hot_classical);
        validator.hybrid_pq_pk = Some(hot_pq.to_vec());
        let id = validator.validator_id;
        let mut set = ValidatorSet::new();
        set.upsert(validator).unwrap();

        assert!(validate_validator_cold_key(&set, &id, &hot_classical, &fresh_pq, 1).is_err());
        assert!(validate_validator_cold_key(&set, &id, &fresh_classical, &hot_pq, 1).is_err());
    }

    #[test]
    fn cold_registry_enforces_cross_validator_component_uniqueness() {
        let (hot_a_classical, hot_a_pq) = hybrid_components(0x81);
        let (fresh_classical, fresh_pq) = hybrid_components(0x82);
        let mut a = make_validator(1, 10_000, 0);
        a.hybrid_classical_pk = Some(hot_a_classical);
        a.hybrid_pq_pk = Some(hot_a_pq.to_vec());
        let b = make_validator(2, 10_000, 0);
        let b_id = b.validator_id;
        let mut set = ValidatorSet::new();
        set.upsert(a).unwrap();
        set.upsert(b).unwrap();

        assert!(validate_validator_cold_key(&set, &b_id, &hot_a_classical, &fresh_pq, 1).is_err());
        assert!(validate_validator_cold_key(&set, &b_id, &fresh_classical, &hot_a_pq, 1).is_err());
    }

    #[test]
    fn cold_registry_requires_exact_next_nonzero_version() {
        let mut set = ValidatorSet::new();
        let validator = make_validator(1, 10_000, 0);
        let id = validator.validator_id;
        set.upsert(validator).unwrap();
        let (classical, pq) = hybrid_components(0x51);

        assert!(validate_validator_cold_key(&set, &id, &classical, &pq, 0).is_err());
        assert!(validate_validator_cold_key(&set, &id, &classical, &pq, 2).is_err());
        assert_eq!(
            validate_validator_cold_key(&set, &id, &classical, &pq, 1)
                .unwrap()
                .version,
            1
        );
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





}

/// Cold-key custody retained after a validator is evicted from the bounded live registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictedColdCustodyV1 {
    /// Cold Ed25519 public key.
    pub classical_pk: [u8; 32],
    /// Cold ML-DSA-87 public key.
    pub pq_pk: [u8; indra_crypto::PQ_PK_BYTES],
    /// Last active cold-key version.
    pub key_version: u64,
}

impl Encode for EvictedColdCustodyV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.classical_pk);
        buf.extend_from_slice(&self.pq_pk);
        self.key_version.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        32 + indra_crypto::PQ_PK_BYTES + 8
    }
}

impl Decode for EvictedColdCustodyV1 {
    fn decode(reader: &mut ByteReader<'_>) -> IndraResult<Self> {
        let classical_pk = reader.read_bytes32()?;
        let mut pq_pk = [0u8; indra_crypto::PQ_PK_BYTES];
        pq_pk.copy_from_slice(reader.read_bytes(indra_crypto::PQ_PK_BYTES)?);
        Ok(Self {
            classical_pk,
            pq_pk,
            key_version: u64::decode(reader)?,
        })
    }
}

/// Maximum active position aggregates converted by one atomic eviction.
pub const MAX_ATOMIC_EVICTION_POSITION_CONVERSIONS: usize = 4_096;
/// Maximum position references retained by one tranche-native tombstone.
pub const MAX_RETAINED_POSITION_REFERENCES_PER_TOMBSTONE: usize = 4_096;
/// Maximum tranche references retained by one tranche-native tombstone.
pub const MAX_RETAINED_TRANCHE_REFERENCES_PER_TOMBSTONE: usize = 8_192;
/// Aggregate position-reference ceiling, inherited from canonical position storage.
pub const MAX_TOTAL_RETAINED_POSITION_REFERENCES: usize =
    indra_core::types::primitives::MAX_STAKE_POSITIONS_TOTAL;
/// Aggregate tranche-reference ceiling, inherited from canonical tranche storage.
pub const MAX_TOTAL_RETAINED_TRANCHE_REFERENCES: usize =
    indra_core::types::primitives::MAX_TRANCHES_TOTAL;

/// Final tranche-native retained record for an evicted validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictedValidatorTombstoneV2 {
    /// Evicted validator identity.
    pub validator_id: Bytes32,
    /// Height of the atomic eviction transition.
    pub eviction_height: u64,
    /// Epoch containing `eviction_height`.
    pub eviction_epoch: u64,
    /// Last validated Ed25519 consensus key.
    pub last_classical_vote_pk: [u8; 32],
    /// Last validated ML-DSA-87 consensus key.
    pub last_pq_vote_pk: [u8; indra_crypto::PQ_PK_BYTES],
    /// Last validated VRF key.
    pub last_vrf_pk: [u8; 32],
    /// Cold custody retained for validator-self principal and rewards.
    pub cold_custody: Option<EvictedColdCustodyV1>,
    /// Ordered unique canonical positions owned by this eviction.
    pub retained_position_ids: Vec<Bytes32>,
    /// Ordered unique canonical tranches owned by this eviction.
    pub retained_tranche_ids: Vec<Bytes32>,
}

impl EvictedValidatorTombstoneV2 {
    /// Validate local encoding invariants; creation additionally requires economic records.
    pub fn validate(&self, require_nonempty: bool) -> IndraResult<()> {
        if self.eviction_epoch
            != self.eviction_height / indra_core::types::primitives::EPOCH_DURATION_BLOCKS
        {
            return Err(IndraError::InvalidSlashMembershipProof(
                "tombstone eviction epoch mismatch".into(),
            ));
        }
        if self.retained_position_ids.len() > MAX_RETAINED_POSITION_REFERENCES_PER_TOMBSTONE
            || self.retained_tranche_ids.len() > MAX_RETAINED_TRANCHE_REFERENCES_PER_TOMBSTONE
            || !strictly_sorted(&self.retained_position_ids)
            || !strictly_sorted(&self.retained_tranche_ids)
            || (require_nonempty
                && self.retained_position_ids.is_empty()
                && self.retained_tranche_ids.is_empty())
        {
            return Err(IndraError::InvalidSlashMembershipProof(
                "malformed tranche-native tombstone references".into(),
            ));
        }
        Ok(())
    }
}

fn strictly_sorted(values: &[Bytes32]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

impl Encode for EvictedValidatorTombstoneV2 {
    fn encode(&self, buf: &mut Vec<u8>) {
        2u8.encode(buf);
        self.validator_id.encode(buf);
        self.eviction_height.encode(buf);
        self.eviction_epoch.encode(buf);
        buf.extend_from_slice(&self.last_classical_vote_pk);
        buf.extend_from_slice(&self.last_pq_vote_pk);
        buf.extend_from_slice(&self.last_vrf_pk);
        self.cold_custody.is_some().encode(buf);
        if let Some(cold) = &self.cold_custody {
            cold.encode(buf);
        }
        encode_list(&self.retained_position_ids, buf);
        encode_list(&self.retained_tranche_ids, buf);
    }
    fn encoded_len(&self) -> usize {
        1 + 32
            + 8
            + 8
            + 32
            + indra_crypto::PQ_PK_BYTES
            + 32
            + 1
            + self
                .cold_custody
                .as_ref()
                .map(Encode::encoded_len)
                .unwrap_or(0)
            + list_encoded_len(&self.retained_position_ids)
            + list_encoded_len(&self.retained_tranche_ids)
    }
}

impl Decode for EvictedValidatorTombstoneV2 {
    fn decode(reader: &mut ByteReader<'_>) -> IndraResult<Self> {
        let version = u8::decode(reader)?;
        if version != 2 {
            return Err(IndraError::UnsupportedVersion {
                version: version.into(),
            });
        }
        let validator_id = Bytes32::decode(reader)?;
        let eviction_height = u64::decode(reader)?;
        let eviction_epoch = u64::decode(reader)?;
        let last_classical_vote_pk = reader.read_bytes32()?;
        let mut last_pq_vote_pk = [0u8; indra_crypto::PQ_PK_BYTES];
        last_pq_vote_pk.copy_from_slice(reader.read_bytes(indra_crypto::PQ_PK_BYTES)?);
        let last_vrf_pk = reader.read_bytes32()?;
        let cold_custody = if bool::decode(reader)? {
            Some(EvictedColdCustodyV1::decode(reader)?)
        } else {
            None
        };
        let value = Self {
            validator_id,
            eviction_height,
            eviction_epoch,
            last_classical_vote_pk,
            last_pq_vote_pk,
            last_vrf_pk,
            cold_custody,
            retained_position_ids: decode_list(
                reader,
                MAX_RETAINED_POSITION_REFERENCES_PER_TOMBSTONE,
                "tombstone_v2.positions",
            )?,
            retained_tranche_ids: decode_list(
                reader,
                MAX_RETAINED_TRANCHE_REFERENCES_PER_TOMBSTONE,
                "tombstone_v2.tranches",
            )?,
        };
        value.validate(false)?;
        Ok(value)
    }
}
