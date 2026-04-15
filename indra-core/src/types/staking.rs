//! Staking operations: delegation, undelegation, reward claims, validator registration.
//!
//! Unlike `TransactionV1` (confidential UTXO transfers), staking operations are
//! fully public — stake amounts must be visible so consensus can verify stake weights.
//!
//! `StakingOp` is embedded in `BlockV1` alongside transactions and governance ops.

use crate::{
    codec::{Encode, Decode, ByteReader},
    error::IndraResult,
    types::{
        primitives::{Bytes32, MIN_COMMISSION_BPS, MAX_COMMISSION_BPS},
        crypto::HybridPubKey,
    },
};

/// Discriminant tags for StakingOp variants.
const TAG_DELEGATE: u8            = 1;
const TAG_UNDELEGATE: u8          = 2;
const TAG_CLAIM_REWARDS: u8       = 3;
const TAG_REGISTER_VALIDATOR: u8  = 4;
const TAG_SET_COMMISSION: u8      = 5;

/// A public staking operation included in a block.
///
/// All amounts are in Spark (1 INDRA = 1_000_000 Spark).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StakingOp {
    /// Delegate Spark to a validator.
    /// Delegator earns rewards proportional to their share of the validator's total delegation.
    Delegate {
        /// Target validator.
        validator_id: Bytes32,
        /// Amount to delegate in Spark.
        amount_spark: u64,
        /// Delegator's public key — used to identify and pay out rewards.
        delegator_pubkey: HybridPubKey,
    },

    /// Begin undelegating from a validator.
    /// Stake is locked for UNBONDING_PERIOD_EPOCHS before it can be withdrawn.
    Undelegate {
        /// Target validator.
        validator_id: Bytes32,
        /// Amount to undelegate in Spark.
        amount_spark: u64,
        /// Delegator's public key.
        delegator_pubkey: HybridPubKey,
    },

    /// Claim accumulated delegation rewards from a validator.
    ClaimRewards {
        /// Validator the delegator staked with.
        validator_id: Bytes32,
        /// Delegator's public key.
        delegator_pubkey: HybridPubKey,
    },

    /// Register a new validator with an initial commission rate.
    RegisterValidator {
        /// Commission rate in basis points (e.g. 1000 = 10%).
        commission_bps: u32,
        /// Validator's public key.
        validator_pubkey: HybridPubKey,
    },

    /// Update a validator's commission rate.
    /// Takes effect at the next epoch boundary.
    SetCommission {
        /// Validator identity.
        validator_id: Bytes32,
        /// New commission rate in basis points.
        new_commission_bps: u32,
    },
}

impl StakingOp {
    /// Validate structural rules (does NOT verify crypto or state).
    pub fn validate_structure(&self) -> IndraResult<()> {
        use crate::error::IndraError;
        match self {
            StakingOp::Delegate { amount_spark, .. } => {
                if *amount_spark == 0 {
                    return Err(IndraError::InvalidStakingOp(
                        "delegate amount must be > 0".into()
                    ));
                }
            }
            StakingOp::Undelegate { amount_spark, .. } => {
                if *amount_spark == 0 {
                    return Err(IndraError::InvalidStakingOp(
                        "undelegate amount must be > 0".into()
                    ));
                }
            }
            StakingOp::RegisterValidator { commission_bps, .. } => {
                if *commission_bps < MIN_COMMISSION_BPS || *commission_bps > MAX_COMMISSION_BPS {
                    return Err(IndraError::CommissionOutOfRange {
                        actual: *commission_bps,
                        min: MIN_COMMISSION_BPS,
                        max: MAX_COMMISSION_BPS,
                    });
                }
            }
            StakingOp::SetCommission { new_commission_bps, .. } => {
                if *new_commission_bps < MIN_COMMISSION_BPS
                    || *new_commission_bps > MAX_COMMISSION_BPS
                {
                    return Err(IndraError::CommissionOutOfRange {
                        actual: *new_commission_bps,
                        min: MIN_COMMISSION_BPS,
                        max: MAX_COMMISSION_BPS,
                    });
                }
            }
            StakingOp::ClaimRewards { .. } => {}
        }
        Ok(())
    }
}

impl Encode for StakingOp {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            StakingOp::Delegate { validator_id, amount_spark, delegator_pubkey } => {
                buf.push(TAG_DELEGATE);
                validator_id.encode(buf);
                amount_spark.encode(buf);
                delegator_pubkey.encode(buf);
            }
            StakingOp::Undelegate { validator_id, amount_spark, delegator_pubkey } => {
                buf.push(TAG_UNDELEGATE);
                validator_id.encode(buf);
                amount_spark.encode(buf);
                delegator_pubkey.encode(buf);
            }
            StakingOp::ClaimRewards { validator_id, delegator_pubkey } => {
                buf.push(TAG_CLAIM_REWARDS);
                validator_id.encode(buf);
                delegator_pubkey.encode(buf);
            }
            StakingOp::RegisterValidator { commission_bps, validator_pubkey } => {
                buf.push(TAG_REGISTER_VALIDATOR);
                commission_bps.encode(buf);
                validator_pubkey.encode(buf);
            }
            StakingOp::SetCommission { validator_id, new_commission_bps } => {
                buf.push(TAG_SET_COMMISSION);
                validator_id.encode(buf);
                new_commission_bps.encode(buf);
            }
        }
    }

    fn encoded_len(&self) -> usize {
        1 + match self {
            StakingOp::Delegate { delegator_pubkey, .. }     => 32 + 8 + delegator_pubkey.encoded_len(),
            StakingOp::Undelegate { delegator_pubkey, .. }   => 32 + 8 + delegator_pubkey.encoded_len(),
            StakingOp::ClaimRewards { delegator_pubkey, .. } => 32 + delegator_pubkey.encoded_len(),
            StakingOp::RegisterValidator { validator_pubkey, .. } => 4 + validator_pubkey.encoded_len(),
            StakingOp::SetCommission { .. }                  => 32 + 4,
        }
    }
}

impl Decode for StakingOp {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        use crate::error::IndraError;
        let tag = u8::decode(r)?;
        match tag {
            TAG_DELEGATE => Ok(StakingOp::Delegate {
                validator_id:     Bytes32::decode(r)?,
                amount_spark:     u64::decode(r)?,
                delegator_pubkey: HybridPubKey::decode(r)?,
            }),
            TAG_UNDELEGATE => Ok(StakingOp::Undelegate {
                validator_id:     Bytes32::decode(r)?,
                amount_spark:     u64::decode(r)?,
                delegator_pubkey: HybridPubKey::decode(r)?,
            }),
            TAG_CLAIM_REWARDS => Ok(StakingOp::ClaimRewards {
                validator_id:     Bytes32::decode(r)?,
                delegator_pubkey: HybridPubKey::decode(r)?,
            }),
            TAG_REGISTER_VALIDATOR => Ok(StakingOp::RegisterValidator {
                commission_bps:   u32::decode(r)?,
                validator_pubkey: HybridPubKey::decode(r)?,
            }),
            TAG_SET_COMMISSION => Ok(StakingOp::SetCommission {
                validator_id:       Bytes32::decode(r)?,
                new_commission_bps: u32::decode(r)?,
            }),
            _ => Err(IndraError::InvalidStakingOp(
                format!("unknown staking op tag: {}", tag)
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{codec::Decode, types::primitives::VariableBytes};

    fn dummy_pubkey() -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::ZERO,
            pq_pk: VariableBytes::from_slice(&[0u8; 1312]).unwrap(),
        }
    }

    #[test]
    fn delegate_round_trip() {
        let op = StakingOp::Delegate {
            validator_id: Bytes32::from([1u8; 32]),
            amount_spark: 1_000_000,
            delegator_pubkey: dummy_pubkey(),
        };
        let encoded = op.encode_to_vec();
        assert_eq!(StakingOp::decode_exact(&encoded).unwrap(), op);
    }

    #[test]
    fn undelegate_round_trip() {
        let op = StakingOp::Undelegate {
            validator_id: Bytes32::from([2u8; 32]),
            amount_spark: 500_000,
            delegator_pubkey: dummy_pubkey(),
        };
        let encoded = op.encode_to_vec();
        assert_eq!(StakingOp::decode_exact(&encoded).unwrap(), op);
    }

    #[test]
    fn claim_rewards_round_trip() {
        let op = StakingOp::ClaimRewards {
            validator_id: Bytes32::from([3u8; 32]),
            delegator_pubkey: dummy_pubkey(),
        };
        let encoded = op.encode_to_vec();
        assert_eq!(StakingOp::decode_exact(&encoded).unwrap(), op);
    }

    #[test]
    fn register_validator_round_trip() {
        let op = StakingOp::RegisterValidator {
            commission_bps: 1_000,
            validator_pubkey: dummy_pubkey(),
        };
        let encoded = op.encode_to_vec();
        assert_eq!(StakingOp::decode_exact(&encoded).unwrap(), op);
    }

    #[test]
    fn set_commission_round_trip() {
        let op = StakingOp::SetCommission {
            validator_id: Bytes32::from([4u8; 32]),
            new_commission_bps: 1_500,
        };
        let encoded = op.encode_to_vec();
        assert_eq!(StakingOp::decode_exact(&encoded).unwrap(), op);
    }

    #[test]
    fn delegate_zero_amount_rejected() {
        let op = StakingOp::Delegate {
            validator_id: Bytes32::ZERO,
            amount_spark: 0,
            delegator_pubkey: dummy_pubkey(),
        };
        assert!(op.validate_structure().is_err());
    }

    #[test]
    fn commission_out_of_range_rejected() {
        let op = StakingOp::RegisterValidator {
            commission_bps: 50,
            validator_pubkey: dummy_pubkey(),
        };
        assert!(op.validate_structure().is_err());

        let op2 = StakingOp::SetCommission {
            validator_id: Bytes32::ZERO,
            new_commission_bps: 9_999,
        };
        assert!(op2.validate_structure().is_err());
    }

    #[test]
    fn commission_in_range_accepted() {
        let op = StakingOp::RegisterValidator {
            commission_bps: 1_000,
            validator_pubkey: dummy_pubkey(),
        };
        assert!(op.validate_structure().is_ok());
    }
}
