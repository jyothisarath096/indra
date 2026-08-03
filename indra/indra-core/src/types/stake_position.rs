//! Canonical fresh-genesis staking positions and exact-height unbonding tranches.

use crate::{
    codec::{ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    types::{
        primitives::{Bytes32, EPOCH_DURATION_BLOCKS, UNBONDING_PERIOD_EPOCHS},
        staking::StakingOp,
    },
};
use indra_crypto::{sha256, PedersenCommitment};

/// Canonical `StakePositionV1` marker.
pub const STAKE_POSITION_FORMAT_V1: u8 = 1;
/// Canonical `ActiveStakeAggregateV1` marker.
pub const ACTIVE_STAKE_AGGREGATE_FORMAT_V1: u8 = 1;
/// Canonical `UnbondingTimingV1` marker.
pub const UNBONDING_TIMING_FORMAT_V1: u8 = 1;
/// Canonical `UnbondingTrancheV1` marker.
pub const UNBONDING_TRANCHE_FORMAT_V1: u8 = 1;
/// Canonical `PositionCustodyV1` marker.
pub const POSITION_CUSTODY_FORMAT_V1: u8 = 1;

/// Position-identifier hash domain.
pub const POSITION_ID_DOMAIN_V1: &[u8] = b"INDRA-STAKE-POSITION-v1";
/// Tranche-identifier hash domain.
pub const TRANCHE_ID_DOMAIN_V1: &[u8] = b"INDRA-UNBONDING-TRANCHE-v1";
/// Staking-operation intent identifier hash domain.
pub const STAKING_OP_ID_V2_DOMAIN: &[u8] = b"INDRA-STAKING-OP-ID-v2";
/// Synthetic creation identity for protocol-forced eviction tranches.
pub const EVICTION_TRANCHE_CREATION_DOMAIN_V1: &[u8] = b"INDRA-EVICTION-TRANCHE-CREATION-v1";

const CUSTODY_DELEGATOR: u8 = 1;
const CUSTODY_VALIDATOR_COLD: u8 = 2;
const TIMING_HEIGHT_PRECISE: u8 = 1;

/// Immutable refund-authorization role for one logical staking position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PositionCustodyV1 {
    /// Delegated principal owned by one registered delegator identity.
    DelegatorIdentity {
        /// Canonical delegator identity.
        delegator_id: Bytes32,
    },
    /// Validator self-principal controlled by its cold identity.
    ValidatorColdIdentity {
        /// Canonical validator identity.
        validator_id: Bytes32,
    },
}

impl PositionCustodyV1 {
    /// Require custody to match the position's validator/owner tuple.
    pub fn validate_for(
        &self,
        validator_id: Bytes32,
        principal_owner_id: Bytes32,
    ) -> IndraResult<()> {
        match self {
            Self::DelegatorIdentity { delegator_id } if *delegator_id == principal_owner_id => {
                Ok(())
            }
            Self::ValidatorColdIdentity {
                validator_id: custody_validator,
            } if *custody_validator == validator_id && principal_owner_id == validator_id => Ok(()),
            Self::DelegatorIdentity { .. } => {
                invalid("delegator custody does not match principal owner")
            }
            Self::ValidatorColdIdentity { .. } => {
                invalid("validator-cold custody does not match self position")
            }
        }
    }
}

impl Encode for PositionCustodyV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        POSITION_CUSTODY_FORMAT_V1.encode(buf);
        match self {
            Self::DelegatorIdentity { delegator_id } => {
                CUSTODY_DELEGATOR.encode(buf);
                delegator_id.encode(buf);
            }
            Self::ValidatorColdIdentity { validator_id } => {
                CUSTODY_VALIDATOR_COLD.encode(buf);
                validator_id.encode(buf);
            }
        }
    }

    fn encoded_len(&self) -> usize {
        34
    }
}

impl Decode for PositionCustodyV1 {
    fn decode(reader: &mut ByteReader<'_>) -> IndraResult<Self> {
        require_version(
            u8::decode(reader)?,
            POSITION_CUSTODY_FORMAT_V1,
            "PositionCustodyV1",
        )?;
        match u8::decode(reader)? {
            CUSTODY_DELEGATOR => Ok(Self::DelegatorIdentity {
                delegator_id: Bytes32::decode(reader)?,
            }),
            CUSTODY_VALIDATOR_COLD => Ok(Self::ValidatorColdIdentity {
                validator_id: Bytes32::decode(reader)?,
            }),
            _ => invalid("unknown position custody tag"),
        }
    }
}

/// One aggregated active principal balance and its contribution-height range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveStakeAggregateV1 {
    /// Authoritative active principal in Spark.
    pub principal_spark: u64,
    /// Earliest contribution height represented by this aggregate.
    pub first_contribution_height: u64,
    /// Latest contribution height represented by this aggregate.
    pub last_contribution_height: u64,
}

impl ActiveStakeAggregateV1 {
    /// Construct a positive aggregate with a non-reversed height range.
    pub fn new(principal_spark: u64, first: u64, last: u64) -> IndraResult<Self> {
        let value = Self {
            principal_spark,
            first_contribution_height: first,
            last_contribution_height: last,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate principal and contribution-height invariants.
    pub fn validate(&self) -> IndraResult<()> {
        if self.principal_spark == 0 {
            return invalid("active aggregate principal is zero");
        }
        if self.first_contribution_height > self.last_contribution_height {
            return invalid("active aggregate contribution heights are reversed");
        }
        Ok(())
    }

    /// Add positive principal with checked arithmetic and expand the range.
    pub fn checked_add_principal(&self, amount: u64, height: u64) -> IndraResult<Self> {
        if amount == 0 {
            return invalid("active aggregate contribution is zero");
        }
        Self::new(
            self.principal_spark
                .checked_add(amount)
                .ok_or_else(|| invalid_error("active aggregate principal overflows u64"))?,
            self.first_contribution_height.min(height),
            self.last_contribution_height.max(height),
        )
    }
}

impl Encode for ActiveStakeAggregateV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        ACTIVE_STAKE_AGGREGATE_FORMAT_V1.encode(buf);
        self.principal_spark.encode(buf);
        self.first_contribution_height.encode(buf);
        self.last_contribution_height.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        25
    }
}

impl Decode for ActiveStakeAggregateV1 {
    fn decode(reader: &mut ByteReader<'_>) -> IndraResult<Self> {
        require_version(
            u8::decode(reader)?,
            ACTIVE_STAKE_AGGREGATE_FORMAT_V1,
            "ActiveStakeAggregateV1",
        )?;
        Self::new(
            u64::decode(reader)?,
            u64::decode(reader)?,
            u64::decode(reader)?,
        )
    }
}

/// Exact-height unbonding timing. No legacy epoch-only representation exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnbondingTimingV1 {
    /// Principal began unbonding at an exact block height.
    HeightPrecise {
        /// Inclusion height of the exit operation.
        start_height: u64,
        /// Canonically derived maturity epoch.
        end_epoch: u64,
    },
}

impl UnbondingTimingV1 {
    /// Construct timing and derive its maturity epoch exactly.
    pub fn height_precise(start_height: u64) -> IndraResult<Self> {
        let end_epoch = start_height
            .checked_div(EPOCH_DURATION_BLOCKS)
            .and_then(|epoch| epoch.checked_add(UNBONDING_PERIOD_EPOCHS))
            .ok_or_else(|| invalid_error("unbonding end epoch overflows u64"))?;
        Ok(Self::HeightPrecise {
            start_height,
            end_epoch,
        })
    }

    /// Validate exact start-height/end-epoch correspondence.
    pub fn validate(&self) -> IndraResult<()> {
        let Self::HeightPrecise {
            start_height,
            end_epoch,
        } = self;
        let expected = start_height
            .checked_div(EPOCH_DURATION_BLOCKS)
            .and_then(|epoch| epoch.checked_add(UNBONDING_PERIOD_EPOCHS))
            .ok_or_else(|| invalid_error("unbonding end epoch overflows u64"))?;
        if *end_epoch != expected {
            return invalid("unbonding end epoch does not match start height");
        }
        Ok(())
    }

    /// Return the exact unbonding start height.
    pub fn start_height(&self) -> u64 {
        let Self::HeightPrecise { start_height, .. } = self;
        *start_height
    }
}

impl Encode for UnbondingTimingV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        UNBONDING_TIMING_FORMAT_V1.encode(buf);
        TIMING_HEIGHT_PRECISE.encode(buf);
        let Self::HeightPrecise {
            start_height,
            end_epoch,
        } = self;
        start_height.encode(buf);
        end_epoch.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        18
    }
}

impl Decode for UnbondingTimingV1 {
    fn decode(reader: &mut ByteReader<'_>) -> IndraResult<Self> {
        require_version(
            u8::decode(reader)?,
            UNBONDING_TIMING_FORMAT_V1,
            "UnbondingTimingV1",
        )?;
        if u8::decode(reader)? != TIMING_HEIGHT_PRECISE {
            return invalid("unknown unbonding timing tag");
        }
        let value = Self::HeightPrecise {
            start_height: u64::decode(reader)?,
            end_epoch: u64::decode(reader)?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Complete canonical staking relationship for one validator/owner/custody tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakePositionV1 {
    /// Recomputed canonical identifier; never independently mutable.
    pub position_id: Bytes32,
    /// Validator receiving the active stake.
    pub validator_id: Bytes32,
    /// Identity owning the principal and position rewards.
    pub principal_owner_id: Bytes32,
    /// Immutable refund authorization role.
    pub custody: PositionCustodyV1,
    /// Optional positive active-principal aggregate.
    pub active: Option<ActiveStakeAggregateV1>,
    /// Rewards accrued to this position.
    pub pending_rewards_spark: u64,
    /// Last epoch in which rewards were credited.
    pub rewards_last_epoch: u64,
}

impl StakePositionV1 {
    /// Construct a position and derive its canonical identifier.
    pub fn new(
        validator_id: Bytes32,
        principal_owner_id: Bytes32,
        custody: PositionCustodyV1,
        active: Option<ActiveStakeAggregateV1>,
        pending_rewards_spark: u64,
        rewards_last_epoch: u64,
    ) -> IndraResult<Self> {
        custody.validate_for(validator_id, principal_owner_id)?;
        if let Some(active) = active {
            active.validate()?;
        }
        let position_id = derive_position_id(validator_id, principal_owner_id, custody);
        Ok(Self {
            position_id,
            validator_id,
            principal_owner_id,
            custody,
            active,
            pending_rewards_spark,
            rewards_last_epoch,
        })
    }

    /// Recompute and validate every locally decidable invariant.
    pub fn validate(&self) -> IndraResult<()> {
        self.custody
            .validate_for(self.validator_id, self.principal_owner_id)?;
        if let Some(active) = self.active {
            active.validate()?;
        }
        if self.position_id
            != derive_position_id(self.validator_id, self.principal_owner_id, self.custody)
        {
            return invalid("stored position ID does not match canonical tuple");
        }
        Ok(())
    }
}

impl Encode for StakePositionV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        STAKE_POSITION_FORMAT_V1.encode(buf);
        self.position_id.encode(buf);
        self.validator_id.encode(buf);
        self.principal_owner_id.encode(buf);
        self.custody.encode(buf);
        self.active.is_some().encode(buf);
        if let Some(active) = self.active {
            active.encode(buf);
        }
        self.pending_rewards_spark.encode(buf);
        self.rewards_last_epoch.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        1 + 32 * 3
            + self.custody.encoded_len()
            + 1
            + self.active.map_or(0, |a| a.encoded_len())
            + 16
    }
}

impl Decode for StakePositionV1 {
    fn decode(reader: &mut ByteReader<'_>) -> IndraResult<Self> {
        require_version(
            u8::decode(reader)?,
            STAKE_POSITION_FORMAT_V1,
            "StakePositionV1",
        )?;
        let value = Self {
            position_id: Bytes32::decode(reader)?,
            validator_id: Bytes32::decode(reader)?,
            principal_owner_id: Bytes32::decode(reader)?,
            custody: PositionCustodyV1::decode(reader)?,
            active: if bool::decode(reader)? {
                Some(ActiveStakeAggregateV1::decode(reader)?)
            } else {
                None
            },
            pending_rewards_spark: u64::decode(reader)?,
            rewards_last_epoch: u64::decode(reader)?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Immutable exact-height exit record for principal removed from an aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbondingTrancheV1 {
    /// Recomputed canonical identifier; never independently mutable.
    pub tranche_id: Bytes32,
    /// Position from which principal exited.
    pub position_id: Bytes32,
    /// Remaining locked principal in Spark.
    pub principal_spark: u64,
    /// Protocol-owned commitment binding the tranche principal.
    pub source_commitment: PedersenCommitment,
    /// Exact-height unbonding schedule.
    pub timing: UnbondingTimingV1,
    /// Immutable refund authorization role.
    pub custody: PositionCustodyV1,
    /// Stable identifier of the operation that created this tranche.
    pub creation_op_id: Bytes32,
    /// Ordinal reserved for an operation producing multiple tranches.
    pub creation_ordinal: u32,
}

impl UnbondingTrancheV1 {
    /// Construct, validate, and derive the canonical tranche identifier.
    pub fn new(
        position_id: Bytes32,
        principal_spark: u64,
        source_commitment: PedersenCommitment,
        timing: UnbondingTimingV1,
        custody: PositionCustodyV1,
        creation_op_id: Bytes32,
        creation_ordinal: u32,
    ) -> IndraResult<Self> {
        if principal_spark == 0 {
            return invalid("unbonding tranche principal is zero");
        }
        timing.validate()?;
        source_commitment
            .decompress()
            .map_err(|_| invalid_error("source commitment is not a canonical Ristretto point"))?;
        let tranche_id = derive_tranche_id(
            position_id,
            creation_op_id,
            creation_ordinal,
            timing,
            principal_spark,
        );
        Ok(Self {
            tranche_id,
            position_id,
            principal_spark,
            source_commitment,
            timing,
            custody,
            creation_op_id,
            creation_ordinal,
        })
    }

    /// Recompute and validate every locally decidable invariant.
    pub fn validate(&self) -> IndraResult<()> {
        if self.principal_spark == 0 {
            return invalid("unbonding tranche principal is zero");
        }
        self.timing.validate()?;
        self.source_commitment
            .decompress()
            .map_err(|_| invalid_error("source commitment is not a canonical Ristretto point"))?;
        if self.tranche_id
            != derive_tranche_id(
                self.position_id,
                self.creation_op_id,
                self.creation_ordinal,
                self.timing,
                self.principal_spark,
            )
        {
            return invalid("stored tranche ID does not match canonical fields");
        }
        Ok(())
    }
}

impl Encode for UnbondingTrancheV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        UNBONDING_TRANCHE_FORMAT_V1.encode(buf);
        self.tranche_id.encode(buf);
        self.position_id.encode(buf);
        self.principal_spark.encode(buf);
        buf.extend_from_slice(&self.source_commitment.0);
        self.timing.encode(buf);
        self.custody.encode(buf);
        self.creation_op_id.encode(buf);
        self.creation_ordinal.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        1 + 32 + 32 + 8 + 32 + self.timing.encoded_len() + self.custody.encoded_len() + 32 + 4
    }
}

impl Decode for UnbondingTrancheV1 {
    fn decode(reader: &mut ByteReader<'_>) -> IndraResult<Self> {
        require_version(
            u8::decode(reader)?,
            UNBONDING_TRANCHE_FORMAT_V1,
            "UnbondingTrancheV1",
        )?;
        let tranche_id = Bytes32::decode(reader)?;
        let position_id = Bytes32::decode(reader)?;
        let principal_spark = u64::decode(reader)?;
        let source_commitment = PedersenCommitment(
            reader
                .read_bytes(32)?
                .try_into()
                .map_err(|_| invalid_error("malformed source commitment"))?,
        );
        let value = Self {
            tranche_id,
            position_id,
            principal_spark,
            source_commitment,
            timing: UnbondingTimingV1::decode(reader)?,
            custody: PositionCustodyV1::decode(reader)?,
            creation_op_id: Bytes32::decode(reader)?,
            creation_ordinal: u32::decode(reader)?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Hash the canonical chain-bound signed intent, deliberately excluding its signature.
pub fn staking_op_id_v2(op: &StakingOp, chain_id: &str) -> IndraResult<Bytes32> {
    staking_intent_id_v2(&op.signing_bytes(chain_id))
}

/// Derive the canonical synthetic operation identity for one forced eviction tranche.
pub fn eviction_tranche_creation_id_v1(
    chain_id: &str,
    validator_id: Bytes32,
    eviction_height: u64,
    position_id: Bytes32,
    principal_spark: u64,
) -> IndraResult<Bytes32> {
    let chain = chain_id.as_bytes();
    let chain_len = u16::try_from(chain.len())
        .map_err(|_| invalid_error("eviction tranche chain ID exceeds u16"))?;
    let mut material = Vec::with_capacity(
        EVICTION_TRANCHE_CREATION_DOMAIN_V1.len() + 2 + chain.len() + 32 + 8 + 32 + 8,
    );
    material.extend_from_slice(EVICTION_TRANCHE_CREATION_DOMAIN_V1);
    chain_len.encode(&mut material);
    material.extend_from_slice(chain);
    validator_id.encode(&mut material);
    eviction_height.encode(&mut material);
    position_id.encode(&mut material);
    principal_spark.encode(&mut material);
    Ok(Bytes32::from(sha256(&material)))
}

fn staking_intent_id_v2(signing_bytes: &[u8]) -> IndraResult<Bytes32> {
    let len = u32::try_from(signing_bytes.len())
        .map_err(|_| invalid_error("staking operation signing bytes exceed u32"))?;
    let mut material = Vec::with_capacity(STAKING_OP_ID_V2_DOMAIN.len() + 4 + signing_bytes.len());
    material.extend_from_slice(STAKING_OP_ID_V2_DOMAIN);
    material.extend_from_slice(&len.to_le_bytes());
    material.extend_from_slice(signing_bytes);
    Ok(Bytes32::from(sha256(&material)))
}

/// Derive the unique canonical identifier for a position tuple.
pub fn derive_position_id(
    validator_id: Bytes32,
    principal_owner_id: Bytes32,
    custody: PositionCustodyV1,
) -> Bytes32 {
    let mut material =
        Vec::with_capacity(POSITION_ID_DOMAIN_V1.len() + 1 + 32 + 32 + custody.encoded_len());
    material.extend_from_slice(POSITION_ID_DOMAIN_V1);
    material.push(STAKE_POSITION_FORMAT_V1);
    validator_id.encode(&mut material);
    principal_owner_id.encode(&mut material);
    custody.encode(&mut material);
    Bytes32::from(sha256(&material))
}

/// Derive the unique canonical identifier for an immutable tranche.
pub fn derive_tranche_id(
    position_id: Bytes32,
    creation_op_id: Bytes32,
    creation_ordinal: u32,
    timing: UnbondingTimingV1,
    principal_spark: u64,
) -> Bytes32 {
    let mut material =
        Vec::with_capacity(TRANCHE_ID_DOMAIN_V1.len() + 1 + 32 + 32 + 4 + timing.encoded_len() + 8);
    material.extend_from_slice(TRANCHE_ID_DOMAIN_V1);
    material.push(UNBONDING_TRANCHE_FORMAT_V1);
    position_id.encode(&mut material);
    creation_op_id.encode(&mut material);
    creation_ordinal.encode(&mut material);
    timing.encode(&mut material);
    principal_spark.encode(&mut material);
    Bytes32::from(sha256(&material))
}

fn require_version(actual: u8, expected: u8, name: &'static str) -> IndraResult<()> {
    if actual != expected {
        return Err(IndraError::UnsupportedSchemaVersion {
            struct_name: name,
            version: actual,
            max_supported: expected,
        });
    }
    Ok(())
}

fn invalid<T>(message: &'static str) -> IndraResult<T> {
    Err(invalid_error(message))
}
fn invalid_error(message: impl Into<String>) -> IndraError {
    IndraError::InvalidStakePosition(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::{Decode, Encode},
        types::{
            crypto::{HybridPubKey, HybridSignature},
            staking::{StakingBondProof, StakingOpBody},
        },
        VariableBytes,
    };
    use std::time::Instant;

    fn id(byte: u8) -> Bytes32 {
        Bytes32::from([byte; 32])
    }

    fn dummy_signature(byte: u8) -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[byte; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[byte; 4627]).unwrap(),
        }
    }

    fn operation(body: StakingOpBody, nonce: u64, signature_byte: u8) -> StakingOp {
        StakingOp {
            body,
            nonce,
            signature: dummy_signature(signature_byte),
        }
    }

    fn dummy_pubkey(byte: u8) -> HybridPubKey {
        HybridPubKey {
            classical_pk: id(byte),
            pq_pk: VariableBytes::from_slice(&vec![byte; indra_crypto::PQ_PK_BYTES]).unwrap(),
        }
    }

    fn position() -> StakePositionV1 {
        StakePositionV1::new(
            id(1),
            id(2),
            PositionCustodyV1::DelegatorIdentity {
                delegator_id: id(2),
            },
            Some(ActiveStakeAggregateV1::new(1_000, 10, 20).unwrap()),
            7,
            3,
        )
        .unwrap()
    }

    fn tranche() -> UnbondingTrancheV1 {
        let p = position();
        let timing = UnbondingTimingV1::height_precise(301).unwrap();
        UnbondingTrancheV1::new(
            p.position_id,
            400,
            indra_crypto::commit(400, &[9; 32]),
            timing,
            p.custody,
            id(3),
            0,
        )
        .unwrap()
    }

    #[test]
    fn canonical_structures_round_trip_and_have_exact_sizes() {
        let custody = PositionCustodyV1::ValidatorColdIdentity {
            validator_id: id(1),
        };
        assert_eq!(custody.encoded_len(), 34);
        assert_eq!(
            PositionCustodyV1::decode_exact(&custody.encode_to_vec()).unwrap(),
            custody
        );
        let active = ActiveStakeAggregateV1::new(9, 1, 2).unwrap();
        assert_eq!(active.encoded_len(), 25);
        assert_eq!(
            ActiveStakeAggregateV1::decode_exact(&active.encode_to_vec()).unwrap(),
            active
        );
        let timing = UnbondingTimingV1::height_precise(301).unwrap();
        assert_eq!(timing.encoded_len(), 18);
        assert_eq!(
            UnbondingTimingV1::decode_exact(&timing.encode_to_vec()).unwrap(),
            timing
        );
        let position = position();
        assert_eq!(position.encoded_len(), 173);
        assert_eq!(
            StakePositionV1::decode_exact(&position.encode_to_vec()).unwrap(),
            position
        );
        let empty_active = StakePositionV1::new(
            id(1),
            id(2),
            PositionCustodyV1::DelegatorIdentity {
                delegator_id: id(2),
            },
            None,
            7,
            3,
        )
        .unwrap();
        assert_eq!(empty_active.encoded_len(), 148);
        let tranche = tranche();
        assert_eq!(tranche.encoded_len(), 193);
        assert_eq!(
            UnbondingTrancheV1::decode_exact(&tranche.encode_to_vec()).unwrap(),
            tranche
        );
    }

    #[test]
    fn malformed_versions_tags_ids_timing_custody_and_principal_fail_closed() {
        let mut custody_version = position().custody.encode_to_vec();
        custody_version[0] = 2;
        assert!(PositionCustodyV1::decode_exact(&custody_version).is_err());
        let mut active_version = position().active.unwrap().encode_to_vec();
        active_version[0] = 2;
        assert!(ActiveStakeAggregateV1::decode_exact(&active_version).is_err());
        let mut timing_version = UnbondingTimingV1::height_precise(1)
            .unwrap()
            .encode_to_vec();
        timing_version[0] = 2;
        assert!(UnbondingTimingV1::decode_exact(&timing_version).is_err());
        let mut position_version = position().encode_to_vec();
        position_version[0] = 2;
        assert!(StakePositionV1::decode_exact(&position_version).is_err());
        let mut tranche_version = tranche().encode_to_vec();
        tranche_version[0] = 2;
        assert!(UnbondingTrancheV1::decode_exact(&tranche_version).is_err());
        let mut custody = PositionCustodyV1::DelegatorIdentity {
            delegator_id: id(2),
        }
        .encode_to_vec();
        custody[1] = 99;
        assert!(PositionCustodyV1::decode_exact(&custody).is_err());
        let mut timing = UnbondingTimingV1::height_precise(301)
            .unwrap()
            .encode_to_vec();
        timing[1] = 99;
        assert!(UnbondingTimingV1::decode_exact(&timing).is_err());
        let mut bad_position = position();
        bad_position.position_id = id(99);
        assert!(bad_position.validate().is_err());
        let mut bad_tranche = tranche();
        bad_tranche.tranche_id = id(98);
        assert!(bad_tranche.validate().is_err());
        bad_tranche = tranche();
        bad_tranche.principal_spark = 0;
        assert!(bad_tranche.validate().is_err());
        assert!(ActiveStakeAggregateV1::new(0, 1, 1).is_err());
        assert!(ActiveStakeAggregateV1::new(1, 2, 1).is_err());
        assert!(StakePositionV1::new(
            id(1),
            id(2),
            PositionCustodyV1::DelegatorIdentity {
                delegator_id: id(3)
            },
            None,
            0,
            0
        )
        .is_err());
        assert!(UnbondingTimingV1::HeightPrecise {
            start_height: 301,
            end_epoch: 1
        }
        .validate()
        .is_err());
    }

    #[test]
    fn staking_op_id_v2_is_stable_chain_bound_field_sensitive_and_signature_independent() {
        let base = operation(
            StakingOpBody::UpdateNetworkAddress {
                validator_id: id(1),
                network_addr: Some("127.0.0.1:9000".into()),
            },
            7,
            1,
        );
        let base_id = staking_op_id_v2(&base, "chain-a").unwrap();
        let signing = base.signing_bytes("chain-a");
        let mut oracle = STAKING_OP_ID_V2_DOMAIN.to_vec();
        oracle.extend_from_slice(&(signing.len() as u32).to_le_bytes());
        oracle.extend_from_slice(&signing);
        assert_eq!(base_id, Bytes32::from(sha256(&oracle)));
        let decoded = StakingOp::decode_exact(&base.encode_to_vec()).unwrap();
        assert_eq!(staking_op_id_v2(&decoded, "chain-a").unwrap(), base_id);
        let mut signature_changed = base.clone();
        signature_changed.signature = dummy_signature(9);
        assert_eq!(
            staking_op_id_v2(&signature_changed, "chain-a").unwrap(),
            base_id
        );
        assert_ne!(staking_op_id_v2(&base, "chain-b").unwrap(), base_id);
        let mut nonce_changed = base.clone();
        nonce_changed.nonce += 1;
        assert_ne!(
            staking_op_id_v2(&nonce_changed, "chain-a").unwrap(),
            base_id
        );
        let address_changed = operation(
            StakingOpBody::UpdateNetworkAddress {
                validator_id: id(1),
                network_addr: Some("127.0.0.1:9001".into()),
            },
            7,
            1,
        );
        let validator_changed = operation(
            StakingOpBody::UpdateNetworkAddress {
                validator_id: id(2),
                network_addr: Some("127.0.0.1:9000".into()),
            },
            7,
            1,
        );
        let tag_changed = operation(
            StakingOpBody::SetAutoDelegate {
                validator_id: id(1),
                target_validator_id: id(2),
                cold_authorization: None,
            },
            7,
            1,
        );
        for changed in [&address_changed, &validator_changed, &tag_changed] {
            assert_ne!(staking_op_id_v2(changed, "chain-a").unwrap(), base_id);
        }
        let ambiguous_a = operation(
            StakingOpBody::UpdateNetworkAddress {
                validator_id: id(1),
                network_addr: Some("ab".into()),
            },
            23,
            1,
        );
        let ambiguous_b = operation(
            StakingOpBody::UpdateNetworkAddress {
                validator_id: id(1),
                network_addr: Some("a".into()),
            },
            0x1762,
            1,
        );
        assert_ne!(
            staking_op_id_v2(&ambiguous_a, "c").unwrap(),
            staking_op_id_v2(&ambiguous_b, "c").unwrap()
        );
        // Block placement, operation ordering, and reproposal metadata are not inputs.
        assert_eq!(staking_op_id_v2(&base, "chain-a").unwrap(), base_id);

        let delegate = operation(
            StakingOpBody::Delegate {
                validator_id: id(11),
                bond_utxo_id: id(12),
                delegator_pubkey: dummy_pubkey(13),
                bond_proof: Some(StakingBondProof {
                    committed_value_spark: 14,
                    blinding_factor: id(15),
                }),
            },
            8,
            1,
        );
        let delegate_id = staking_op_id_v2(&delegate, "chain-a").unwrap();
        let delegate_variants = [
            operation(
                StakingOpBody::Delegate {
                    validator_id: id(21),
                    bond_utxo_id: id(12),
                    delegator_pubkey: dummy_pubkey(13),
                    bond_proof: Some(StakingBondProof {
                        committed_value_spark: 14,
                        blinding_factor: id(15),
                    }),
                },
                8,
                1,
            ),
            operation(
                StakingOpBody::Delegate {
                    validator_id: id(11),
                    bond_utxo_id: id(22),
                    delegator_pubkey: dummy_pubkey(13),
                    bond_proof: Some(StakingBondProof {
                        committed_value_spark: 14,
                        blinding_factor: id(15),
                    }),
                },
                8,
                1,
            ),
            operation(
                StakingOpBody::Delegate {
                    validator_id: id(11),
                    bond_utxo_id: id(12),
                    delegator_pubkey: dummy_pubkey(23),
                    bond_proof: Some(StakingBondProof {
                        committed_value_spark: 14,
                        blinding_factor: id(15),
                    }),
                },
                8,
                1,
            ),
            operation(
                StakingOpBody::Delegate {
                    validator_id: id(11),
                    bond_utxo_id: id(12),
                    delegator_pubkey: dummy_pubkey(13),
                    bond_proof: Some(StakingBondProof {
                        committed_value_spark: 24,
                        blinding_factor: id(15),
                    }),
                },
                8,
                1,
            ),
            operation(
                StakingOpBody::Delegate {
                    validator_id: id(11),
                    bond_utxo_id: id(12),
                    delegator_pubkey: dummy_pubkey(13),
                    bond_proof: Some(StakingBondProof {
                        committed_value_spark: 14,
                        blinding_factor: id(25),
                    }),
                },
                8,
                1,
            ),
            operation(
                StakingOpBody::Delegate {
                    validator_id: id(11),
                    bond_utxo_id: id(12),
                    delegator_pubkey: dummy_pubkey(13),
                    bond_proof: None,
                },
                8,
                1,
            ),
        ];
        for changed in &delegate_variants {
            assert_ne!(staking_op_id_v2(changed, "chain-a").unwrap(), delegate_id);
        }
    }

    #[test]
    fn live_exit_operation_binds_amount_nonce_position_custody_and_chain() {
        let custody = PositionCustodyV1::DelegatorIdentity {
            delegator_id: id(2),
        };
        let intent = operation(
            StakingOpBody::ExitStakePosition {
                position_id: id(1),
                amount_spark: 50,
                custody,
                cold_authorization: None,
            },
            7,
            3,
        );
        let baseline = staking_op_id_v2(&intent, "chain-a").unwrap();
        let decoded = StakingOp::decode_exact(&intent.encode_to_vec()).unwrap();
        assert_eq!(decoded, intent);
        assert_eq!(staking_op_id_v2(&decoded, "chain-a").unwrap(), baseline);
        let mut signature_changed = intent.clone();
        signature_changed.signature = dummy_signature(4);
        assert_eq!(
            staking_op_id_v2(&signature_changed, "chain-a").unwrap(),
            baseline
        );
        assert_ne!(staking_op_id_v2(&intent, "chain-b").unwrap(), baseline);
        let mut amount = intent.clone();
        let StakingOpBody::ExitStakePosition { amount_spark, .. } = &mut amount.body else {
            unreachable!()
        };
        *amount_spark += 1;
        assert_ne!(staking_op_id_v2(&amount, "chain-a").unwrap(), baseline);
        let mut nonce = intent.clone();
        nonce.nonce += 1;
        assert_ne!(staking_op_id_v2(&nonce, "chain-a").unwrap(), baseline);
        let mut position = intent.clone();
        let StakingOpBody::ExitStakePosition { position_id, .. } = &mut position.body else {
            unreachable!()
        };
        *position_id = id(9);
        assert_ne!(staking_op_id_v2(&position, "chain-a").unwrap(), baseline);
        let mut other_custody = intent.clone();
        let StakingOpBody::ExitStakePosition {
            custody: changed_custody,
            ..
        } = &mut other_custody.body
        else {
            unreachable!()
        };
        *changed_custody = PositionCustodyV1::ValidatorColdIdentity {
            validator_id: id(2),
        };
        assert_ne!(
            staking_op_id_v2(&other_custody, "chain-a").unwrap(),
            baseline
        );

        let zero = operation(
            StakingOpBody::ExitStakePosition {
                position_id: id(1),
                amount_spark: 0,
                custody,
                cold_authorization: None,
            },
            1,
            1,
        );
        assert!(zero.validate_structure().is_err());
    }

    #[test]
    fn eviction_creation_id_is_domain_separated_and_field_sensitive() {
        let base = eviction_tranche_creation_id_v1("chain-a", id(1), 300, id(2), 50).unwrap();
        assert_ne!(
            base,
            eviction_tranche_creation_id_v1("chain-b", id(1), 300, id(2), 50).unwrap()
        );
        assert_ne!(
            base,
            eviction_tranche_creation_id_v1("chain-a", id(3), 300, id(2), 50).unwrap()
        );
        assert_ne!(
            base,
            eviction_tranche_creation_id_v1("chain-a", id(1), 301, id(2), 50).unwrap()
        );
        assert_ne!(
            base,
            eviction_tranche_creation_id_v1("chain-a", id(1), 300, id(4), 50).unwrap()
        );
        assert_ne!(
            base,
            eviction_tranche_creation_id_v1("chain-a", id(1), 300, id(2), 51).unwrap()
        );
        assert_ne!(
            base,
            staking_op_id_v2(
                &operation(
                    StakingOpBody::UpdateNetworkAddress {
                        validator_id: id(1),
                        network_addr: None,
                    },
                    300,
                    1,
                ),
                "chain-a"
            )
            .unwrap()
        );
    }

    #[test]
    fn d10_stage1_encoded_size_and_algorithmic_measurement() {
        let sample = tranche();
        assert_eq!(sample.encoded_len(), 193);
        for count in [1usize, 63, 64, 128, 1024] {
            let start = Instant::now();
            let mut bytes = Vec::with_capacity(count * sample.encoded_len());
            for ordinal in 0..count {
                let timing = UnbondingTimingV1::height_precise(301 + ordinal as u64).unwrap();
                let item = UnbondingTrancheV1::new(
                    sample.position_id,
                    sample.principal_spark,
                    sample.source_commitment,
                    timing,
                    sample.custody,
                    sample.creation_op_id,
                    ordinal as u32,
                )
                .unwrap();
                item.encode(&mut bytes);
            }
            let elapsed = start.elapsed();
            assert_eq!(bytes.len(), count * 193);
            println!(
                "D10 count={count} bytes={} build_encode_ns={} ns_per_tranche={}",
                bytes.len(),
                elapsed.as_nanos(),
                elapsed.as_nanos() / count as u128
            );
        }
    }
}
