//! Staking operations: delegation, undelegation, reward claims, validator registration.
//!
//! Unlike `TransactionV1` (confidential UTXO transfers), staking operations are
//! fully public — stake amounts must be visible so consensus can verify stake weights.
//!
//! `StakingOp` is embedded in `BlockV1` alongside transactions and governance ops.

use crate::{
    codec::{ByteReader, Decode, Encode},
    error::IndraResult,
    types::{
        crypto::{HybridPubKey, HybridSignature},
        primitives::{Bytes32, MAX_COMMISSION_BPS, MIN_COMMISSION_BPS, STAKING_OP_DOMAIN},
    },
};

/// Discriminant tags for StakingOp variants.
const TAG_DELEGATE: u8 = 1;
const TAG_UNDELEGATE: u8 = 2;
const TAG_CLAIM_REWARDS: u8 = 3;
const TAG_REGISTER_VALIDATOR: u8 = 4;
const TAG_SET_COMMISSION: u8 = 5;

/// A public staking operation included in a block.
/// All operations carry a hybrid signature and a replay-protection nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakingOp {
    /// The operation payload.
    pub body: StakingOpBody,
    /// Monotonic nonce for replay protection.
    /// Must equal current_nonce(signer) + 1.
    pub nonce: u64,
    /// Hybrid signature over `signing_bytes`.
    pub signature: HybridSignature,
}

/// The operation payload: what the operation actually does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StakingOpBody {
    /// Delegate a specific UTXO as stake to a validator.
    Delegate {
        /// Target validator.
        validator_id: Bytes32,
        /// The UTXO being bonded as stake.
        bond_utxo_id: Bytes32,
        /// Delegator's public key.
        delegator_pubkey: HybridPubKey,
    },

    /// Begin undelegating a specific stake bond.
    Undelegate {
        /// Target validator.
        validator_id: Bytes32,
        /// The UTXO ID originally used in the Delegate operation.
        bond_utxo_id: Bytes32,
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
        /// Validator's VRF public key for proposer election.
        vrf_pk: [u8; 32],
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
    /// Canonical bytes covered by the signature.
    ///
    /// Format: domain || chain_id_len(2) || chain_id || nonce(8) || body_bytes.
    pub fn signing_bytes(&self, chain_id: &str) -> Vec<u8> {
        let chain_bytes = chain_id.as_bytes();
        let mut buf = Vec::with_capacity(
            STAKING_OP_DOMAIN.len() + 2 + chain_bytes.len() + 8 + self.body.encoded_len(),
        );
        buf.extend_from_slice(STAKING_OP_DOMAIN.as_bytes());
        (chain_bytes.len() as u16).encode(&mut buf);
        buf.extend_from_slice(chain_bytes);
        self.nonce.encode(&mut buf);
        self.body.encode(&mut buf);
        buf
    }

    /// The signer's identity for nonce tracking.
    pub fn signer_id(&self) -> Bytes32 {
        match &self.body {
            StakingOpBody::Delegate {
                delegator_pubkey, ..
            }
            | StakingOpBody::Undelegate {
                delegator_pubkey, ..
            }
            | StakingOpBody::ClaimRewards {
                delegator_pubkey, ..
            } => pubkey_to_id(delegator_pubkey),
            StakingOpBody::RegisterValidator {
                validator_pubkey, ..
            } => pubkey_to_id(validator_pubkey),
            StakingOpBody::SetCommission { validator_id, .. } => *validator_id,
        }
    }

    /// Validate structural rules (does NOT verify crypto or state).
    pub fn validate_structure(&self) -> IndraResult<()> {
        use crate::error::IndraError;
        match &self.body {
            StakingOpBody::Delegate { .. } => {}
            StakingOpBody::Undelegate { .. } => {}
            StakingOpBody::RegisterValidator { commission_bps, .. } => {
                if *commission_bps < MIN_COMMISSION_BPS || *commission_bps > MAX_COMMISSION_BPS {
                    return Err(IndraError::CommissionOutOfRange {
                        actual: *commission_bps,
                        min: MIN_COMMISSION_BPS,
                        max: MAX_COMMISSION_BPS,
                    });
                }
            }
            StakingOpBody::SetCommission {
                new_commission_bps, ..
            } => {
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
            StakingOpBody::ClaimRewards { .. } => {}
        }
        Ok(())
    }
}

impl Encode for StakingOpBody {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            StakingOpBody::Delegate {
                validator_id,
                bond_utxo_id,
                delegator_pubkey,
            } => {
                buf.push(TAG_DELEGATE);
                validator_id.encode(buf);
                bond_utxo_id.encode(buf);
                delegator_pubkey.encode(buf);
            }
            StakingOpBody::Undelegate {
                validator_id,
                bond_utxo_id,
                delegator_pubkey,
            } => {
                buf.push(TAG_UNDELEGATE);
                validator_id.encode(buf);
                bond_utxo_id.encode(buf);
                delegator_pubkey.encode(buf);
            }
            StakingOpBody::ClaimRewards {
                validator_id,
                delegator_pubkey,
            } => {
                buf.push(TAG_CLAIM_REWARDS);
                validator_id.encode(buf);
                delegator_pubkey.encode(buf);
            }
            StakingOpBody::RegisterValidator {
                commission_bps,
                validator_pubkey,
                vrf_pk,
            } => {
                buf.push(TAG_REGISTER_VALIDATOR);
                commission_bps.encode(buf);
                validator_pubkey.encode(buf);
                buf.extend_from_slice(vrf_pk);
            }
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps,
            } => {
                buf.push(TAG_SET_COMMISSION);
                validator_id.encode(buf);
                new_commission_bps.encode(buf);
            }
        }
    }

    fn encoded_len(&self) -> usize {
        1 + match self {
            StakingOpBody::Delegate {
                delegator_pubkey, ..
            } => 32 + 32 + delegator_pubkey.encoded_len(),
            StakingOpBody::Undelegate {
                delegator_pubkey, ..
            } => 32 + 32 + delegator_pubkey.encoded_len(),
            StakingOpBody::ClaimRewards {
                delegator_pubkey, ..
            } => 32 + delegator_pubkey.encoded_len(),
            StakingOpBody::RegisterValidator {
                validator_pubkey, ..
            } => 4 + validator_pubkey.encoded_len() + 32,
            StakingOpBody::SetCommission { .. } => 32 + 4,
        }
    }
}

impl Decode for StakingOpBody {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        use crate::error::IndraError;
        let tag = u8::decode(r)?;
        match tag {
            TAG_DELEGATE => Ok(StakingOpBody::Delegate {
                validator_id: Bytes32::decode(r)?,
                bond_utxo_id: Bytes32::decode(r)?,
                delegator_pubkey: HybridPubKey::decode(r)?,
            }),
            TAG_UNDELEGATE => Ok(StakingOpBody::Undelegate {
                validator_id: Bytes32::decode(r)?,
                bond_utxo_id: Bytes32::decode(r)?,
                delegator_pubkey: HybridPubKey::decode(r)?,
            }),
            TAG_CLAIM_REWARDS => Ok(StakingOpBody::ClaimRewards {
                validator_id: Bytes32::decode(r)?,
                delegator_pubkey: HybridPubKey::decode(r)?,
            }),
            TAG_REGISTER_VALIDATOR => Ok(StakingOpBody::RegisterValidator {
                commission_bps: u32::decode(r)?,
                validator_pubkey: HybridPubKey::decode(r)?,
                vrf_pk: r.read_bytes32()?,
            }),
            TAG_SET_COMMISSION => Ok(StakingOpBody::SetCommission {
                validator_id: Bytes32::decode(r)?,
                new_commission_bps: u32::decode(r)?,
            }),
            _ => Err(IndraError::InvalidStakingOp(format!(
                "unknown staking op tag: {}",
                tag
            ))),
        }
    }
}

impl Encode for StakingOp {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.body.encode(buf);
        self.nonce.encode(buf);
        self.signature.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        self.body.encoded_len() + self.nonce.encoded_len() + self.signature.encoded_len()
    }
}

impl Decode for StakingOp {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            body: StakingOpBody::decode(r)?,
            nonce: u64::decode(r)?,
            signature: HybridSignature::decode(r)?,
        })
    }
}

fn pubkey_to_id(pubkey: &HybridPubKey) -> Bytes32 {
    Bytes32::from(indra_crypto::sha256(&pubkey.encode_to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{codec::Decode, types::primitives::VariableBytes};

    fn dummy_pubkey() -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::ZERO,
            pq_pk: VariableBytes::from_slice(&[0u8; 2592]).unwrap(),
        }
    }

    fn dummy_signature() -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
        }
    }

    fn op(body: StakingOpBody) -> StakingOp {
        StakingOp {
            body,
            nonce: 1,
            signature: dummy_signature(),
        }
    }

    #[test]
    fn staking_op_encode_decode_round_trip() {
        let cases = vec![
            op(StakingOpBody::Delegate {
                validator_id: Bytes32::from([1u8; 32]),
                bond_utxo_id: Bytes32::from([0x11u8; 32]),
                delegator_pubkey: dummy_pubkey(),
            }),
            op(StakingOpBody::Undelegate {
                validator_id: Bytes32::from([2u8; 32]),
                bond_utxo_id: Bytes32::from([0x22u8; 32]),
                delegator_pubkey: dummy_pubkey(),
            }),
            op(StakingOpBody::ClaimRewards {
                validator_id: Bytes32::from([3u8; 32]),
                delegator_pubkey: dummy_pubkey(),
            }),
            op(StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                validator_pubkey: dummy_pubkey(),
                vrf_pk: [4u8; 32],
            }),
            op(StakingOpBody::SetCommission {
                validator_id: Bytes32::from([5u8; 32]),
                new_commission_bps: 1_500,
            }),
        ];

        for op in cases {
            let encoded = op.encode_to_vec();
            assert_eq!(StakingOp::decode_exact(&encoded).unwrap(), op);
        }
    }

    #[test]
    fn staking_op_signing_bytes_domain_separation() {
        let delegate = op(StakingOpBody::Delegate {
            validator_id: Bytes32::from([1u8; 32]),
            bond_utxo_id: Bytes32::from([0x11u8; 32]),
            delegator_pubkey: dummy_pubkey(),
        });
        let register = op(StakingOpBody::RegisterValidator {
            commission_bps: 1_000,
            validator_pubkey: dummy_pubkey(),
            vrf_pk: [9u8; 32],
        });
        let delegate_bytes = delegate.signing_bytes("indra-testnet-1");
        assert!(delegate_bytes.starts_with(STAKING_OP_DOMAIN.as_bytes()));
        assert_ne!(delegate_bytes, register.signing_bytes("indra-testnet-1"));
        assert_ne!(delegate_bytes, delegate.signing_bytes("indra-other"));
    }

    #[test]
    fn staking_op_validate_structure_accepts_bond_id_delegate() {
        let op = op(StakingOpBody::Delegate {
            validator_id: Bytes32::ZERO,
            bond_utxo_id: Bytes32::ZERO,
            delegator_pubkey: dummy_pubkey(),
        });
        assert!(op.validate_structure().is_ok());
    }

    #[test]
    fn staking_op_validate_structure_rejects_bad_commission() {
        let bad_register = op(StakingOpBody::RegisterValidator {
            commission_bps: 50,
            validator_pubkey: dummy_pubkey(),
            vrf_pk: [0u8; 32],
        });
        assert!(bad_register.validate_structure().is_err());

        let bad_set = op(StakingOpBody::SetCommission {
            validator_id: Bytes32::ZERO,
            new_commission_bps: 9_999,
        });
        assert!(bad_set.validate_structure().is_err());
    }

    #[test]
    fn commission_in_range_accepted() {
        let op = op(StakingOpBody::RegisterValidator {
            commission_bps: 1_000,
            validator_pubkey: dummy_pubkey(),
            vrf_pk: [0u8; 32],
        });
        assert!(op.validate_structure().is_ok());
    }

    #[test]
    fn staking_op_signer_id_deterministic() {
        let pubkey = dummy_pubkey();
        let a = op(StakingOpBody::Delegate {
            validator_id: Bytes32::from([1u8; 32]),
            bond_utxo_id: Bytes32::from([0x11u8; 32]),
            delegator_pubkey: pubkey.clone(),
        });
        let b = op(StakingOpBody::ClaimRewards {
            validator_id: Bytes32::from([2u8; 32]),
            delegator_pubkey: pubkey,
        });
        assert_eq!(a.signer_id(), b.signer_id());
    }
}
