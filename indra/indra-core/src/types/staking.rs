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
        authorization::AuthorizationEnvelope,
        crypto::{ColdHybridPubKey, HybridPubKey, HybridSignature},
        primitives::{Bytes32, MAX_VALIDATOR_NETWORK_ADDR_LEN, STAKING_OP_DOMAIN},
    },
};

/// Discriminant tags for StakingOp variants.
const TAG_DELEGATE: u8 = 1;
const TAG_UNDELEGATE: u8 = 2;
const TAG_CLAIM_REWARDS: u8 = 3;
const TAG_SET_COMMISSION: u8 = 5;
const TAG_SELF_STAKE: u8 = 6;
const TAG_SELF_UNSTAKE: u8 = 7;
const TAG_SET_AUTO_DELEGATE: u8 = 8;
const TAG_UPDATE_NETWORK_ADDRESS: u8 = 9;
const TAG_REGISTER_VALIDATOR_WITH_COLD_KEY: u8 = 11;
const TAG_COLD_CLAIM_REWARDS: u8 = 13;
const TAG_COLD_SET_COMMISSION: u8 = 14;
const TAG_COLD_SELF_STAKE: u8 = 15;
const TAG_COLD_SELF_UNSTAKE: u8 = 16;
const TAG_COLD_SET_AUTO_DELEGATE: u8 = 17;
const TAG_ROTATE_VALIDATOR_COLD_KEY: u8 = 23;

/// Stable operation tag used inside hot/cold registration envelopes.
pub const AUTH_TAG_REGISTER_VALIDATOR: u16 = TAG_REGISTER_VALIDATOR_WITH_COLD_KEY as u16;
/// Stable envelope tag for cold validator reward claims.
pub const AUTH_TAG_COLD_CLAIM_REWARDS: u16 = TAG_COLD_CLAIM_REWARDS as u16;
/// Stable envelope tag for cold commission updates.
pub const AUTH_TAG_COLD_SET_COMMISSION: u16 = TAG_COLD_SET_COMMISSION as u16;
/// Stable envelope tag for cold validator self-staking.
pub const AUTH_TAG_COLD_SELF_STAKE: u16 = TAG_COLD_SELF_STAKE as u16;
/// Stable envelope tag for cold validator self-unstaking.
pub const AUTH_TAG_COLD_SELF_UNSTAKE: u16 = TAG_COLD_SELF_UNSTAKE as u16;
/// Stable envelope tag for cold auto-delegation updates.
pub const AUTH_TAG_COLD_SET_AUTO_DELEGATE: u16 = TAG_COLD_SET_AUTO_DELEGATE as u16;
/// Stable envelope tag for validator cold-key rotation.
pub const AUTH_TAG_ROTATE_VALIDATOR_COLD_KEY: u16 = TAG_ROTATE_VALIDATOR_COLD_KEY as u16;

const REGISTER_VALIDATOR_DUAL_AUTH_DOMAIN: &[u8] =
    b"INDRA-register-validator-dual-authorization-v1";
const REGISTER_VALIDATOR_PAYLOAD_DOMAIN: &[u8] = b"INDRA-register-validator-payload-v1";
const ROTATE_VALIDATOR_COLD_KEY_DUAL_AUTH_DOMAIN: &[u8] =
    b"INDRA-rotate-validator-cold-key-dual-authorization-v1";
const ROTATE_VALIDATOR_COLD_KEY_PAYLOAD_DOMAIN: &[u8] =
    b"INDRA-rotate-validator-cold-key-payload-v1";

/// Proof that a staking UTXO's Pedersen commitment opens to exactly
/// `OutputV1.value_spark`.
///
/// This is an explicit opening rather than a zero-knowledge proof because
/// validator and delegation stake amounts are public economic state: they drive
/// active-set membership, consensus quorum, proposer election weight, and
/// reward distribution.
///
/// Security properties:
/// - proves knowledge of the Pedersen opening `C = v*G + r*H`;
/// - proves the committed value equals the public `value_spark` field once
///   checked against the UTXO read from state;
/// - is replay-safe because bonding spends the referenced UTXO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakingBondProof {
    /// The committed value. Must equal the bonded UTXO's `value_spark`.
    pub committed_value_spark: u64,
    /// Pedersen blinding factor `r` stored as raw bytes, matching the existing
    /// Pedersen API (`Scalar::from_bytes_mod_order` at verification time).
    pub blinding_factor: Bytes32,
}

/// Versioned replay metadata attached only to cold-authorized staking forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColdStakingAuthorization {
    /// Registered cold-key version that must authorize the operation.
    pub cold_key_version: u64,
    /// Next nonce in that version's cold-role nonce namespace.
    pub cold_nonce: u64,
}

impl Encode for ColdStakingAuthorization {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.cold_key_version.encode(buf);
        self.cold_nonce.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        16
    }
}

impl Decode for ColdStakingAuthorization {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            cold_key_version: u64::decode(r)?,
            cold_nonce: u64::decode(r)?,
        })
    }
}

impl Encode for StakingBondProof {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.committed_value_spark.encode(buf);
        self.blinding_factor.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        8 + 32
    }
}

impl Decode for StakingBondProof {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            committed_value_spark: u64::decode(r)?,
            blinding_factor: Bytes32::decode(r)?,
        })
    }
}

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
        /// Proof binding the bonded UTXO commitment to its public value.
        bond_proof: Option<StakingBondProof>,
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
        /// Present only for an enrolled validator claiming its own rewards.
        cold_authorization: Option<ColdStakingAuthorization>,
    },

    /// Register a new validator with an initial commission rate.
    RegisterValidator {
        /// Commission rate in basis points (e.g. 1000 = 10%).
        commission_bps: u32,
        /// Validator-owned UTXO atomically bonded at registration.
        bond_utxo_id: Bytes32,
        /// Validator's public key.
        validator_pubkey: HybridPubKey,
        /// Validator's VRF public key for proposer election.
        vrf_pk: [u8; 32],
        /// Proof binding the bonded UTXO commitment to its public value.
        bond_proof: Option<StakingBondProof>,
        /// Proposed independent cold hybrid public key.
        cold_pubkey: Option<ColdHybridPubKey>,
        /// Complete cold hybrid signature over the dual authorization message.
        cold_signature: Option<HybridSignature>,
    },

    /// Atomically replace an Active validator's cold hybrid key.
    RotateValidatorColdKey {
        /// Existing validator identity.
        validator_id: Bytes32,
        /// Currently registered cold-key version.
        current_cold_key_version: u64,
        /// Next version, exactly current + 1.
        new_cold_key_version: u64,
        /// Next nonce in the current version's cold-role namespace.
        current_cold_nonce: u64,
        /// Proposed independent replacement cold hybrid public key.
        new_cold_pubkey: ColdHybridPubKey,
        /// Complete proof-of-possession signature by the proposed new key.
        new_cold_signature: Option<HybridSignature>,
    },

    /// Update a validator's commission rate.
    /// Takes effect at the next epoch boundary.
    SetCommission {
        /// Validator identity.
        validator_id: Bytes32,
        /// New commission rate in basis points.
        new_commission_bps: u32,
        /// Present only for an enrolled validator.
        cold_authorization: Option<ColdStakingAuthorization>,
    },

    /// Bond a validator-owned UTXO as validator self-stake.
    SelfStake {
        /// The UTXO being bonded as validator self-stake.
        bond_utxo_id: Bytes32,
        /// Validator's public key.
        validator_pubkey: HybridPubKey,
        /// Proof binding the bonded UTXO commitment to its public value.
        bond_proof: Option<StakingBondProof>,
        /// Present only for an enrolled validator.
        cold_authorization: Option<ColdStakingAuthorization>,
    },

    /// Begin unbonding validator self-stake.
    SelfUnstake {
        /// The self-stake bond UTXO ID.
        bond_utxo_id: Bytes32,
        /// Validator's public key.
        validator_pubkey: HybridPubKey,
        /// Present only for an enrolled validator.
        cold_authorization: Option<ColdStakingAuthorization>,
    },

    /// Set or clear the auto-delegation target for this validator.
    SetAutoDelegate {
        /// This validator's identity.
        validator_id: Bytes32,
        /// Target validator to soft-delegate to. Bytes32::ZERO clears.
        target_validator_id: Bytes32,
        /// Present only for an enrolled validator.
        cold_authorization: Option<ColdStakingAuthorization>,
    },

    /// Set or clear the validator's advertised P2P dial address.
    UpdateNetworkAddress {
        /// This validator's identity.
        validator_id: Bytes32,
        /// Strict IP:port address. `None` clears the advertised address.
        network_addr: Option<String>,
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

    /// Canonical cold-role envelope for one of the six cold-only staking forms.
    pub fn cold_authorization_signing_bytes(&self, chain_id: &str) -> IndraResult<Option<Vec<u8>>> {
        let (operation_tag, identity_id, authorization) = match &self.body {
            StakingOpBody::ClaimRewards {
                delegator_pubkey,
                cold_authorization: Some(authorization),
                ..
            } => (
                AUTH_TAG_COLD_CLAIM_REWARDS,
                pubkey_to_id(delegator_pubkey),
                authorization,
            ),
            StakingOpBody::SetCommission {
                validator_id,
                cold_authorization: Some(authorization),
                ..
            } => (AUTH_TAG_COLD_SET_COMMISSION, *validator_id, authorization),
            StakingOpBody::SelfStake {
                validator_pubkey,
                cold_authorization: Some(authorization),
                ..
            } => (
                AUTH_TAG_COLD_SELF_STAKE,
                pubkey_to_id(validator_pubkey),
                authorization,
            ),
            StakingOpBody::SelfUnstake {
                validator_pubkey,
                cold_authorization: Some(authorization),
                ..
            } => (
                AUTH_TAG_COLD_SELF_UNSTAKE,
                pubkey_to_id(validator_pubkey),
                authorization,
            ),
            StakingOpBody::SetAutoDelegate {
                validator_id,
                cold_authorization: Some(authorization),
                ..
            } => (
                AUTH_TAG_COLD_SET_AUTO_DELEGATE,
                *validator_id,
                authorization,
            ),
            _ => return Ok(None),
        };
        let mut payload = self.body.encode_to_vec();
        self.nonce.encode(&mut payload);
        Ok(Some(
            AuthorizationEnvelope::new_cold(
                chain_id.as_bytes(),
                operation_tag,
                identity_id,
                authorization.cold_key_version,
                authorization.cold_nonce,
                &payload,
            )?
            .signing_bytes(),
        ))
    }

    /// Return cold replay metadata when this is a cold-form operation.
    pub fn cold_authorization(&self) -> Option<ColdStakingAuthorization> {
        match &self.body {
            StakingOpBody::ClaimRewards {
                cold_authorization, ..
            }
            | StakingOpBody::SetCommission {
                cold_authorization, ..
            }
            | StakingOpBody::SelfStake {
                cold_authorization, ..
            }
            | StakingOpBody::SelfUnstake {
                cold_authorization, ..
            }
            | StakingOpBody::SetAutoDelegate {
                cold_authorization, ..
            } => *cold_authorization,
            StakingOpBody::RotateValidatorColdKey {
                current_cold_key_version,
                current_cold_nonce,
                ..
            } => Some(ColdStakingAuthorization {
                cold_key_version: *current_cold_key_version,
                cold_nonce: *current_cold_nonce,
            }),
            _ => None,
        }
    }

    /// Canonical byte-identical message signed by both hot and cold keys for
    /// an extended validator registration.
    pub fn register_validator_dual_signing_bytes(
        &self,
        chain_id: &str,
    ) -> IndraResult<Option<Vec<u8>>> {
        let StakingOpBody::RegisterValidator {
            commission_bps,
            bond_utxo_id,
            validator_pubkey,
            vrf_pk,
            bond_proof,
            cold_pubkey: Some(cold_pubkey),
            ..
        } = &self.body
        else {
            return Ok(None);
        };

        let mut payload = Vec::new();
        payload.extend_from_slice(REGISTER_VALIDATOR_PAYLOAD_DOMAIN);
        commission_bps.encode(&mut payload);
        bond_utxo_id.encode(&mut payload);
        validator_pubkey.encode(&mut payload);
        payload.extend_from_slice(vrf_pk);
        encode_optional_bond_proof(bond_proof, &mut payload);
        cold_pubkey.encode(&mut payload);
        1u64.encode(&mut payload);

        let identity_id = pubkey_to_id(validator_pubkey);
        let hot = AuthorizationEnvelope::new_hot(
            chain_id.as_bytes(),
            AUTH_TAG_REGISTER_VALIDATOR,
            identity_id,
            1,
            self.nonce,
            &payload,
        )?;
        let cold = AuthorizationEnvelope::new_cold(
            chain_id.as_bytes(),
            AUTH_TAG_REGISTER_VALIDATOR,
            identity_id,
            1,
            0,
            &payload,
        )?;
        let hot_bytes = hot.signing_bytes();
        let cold_bytes = cold.signing_bytes();
        let mut message = Vec::with_capacity(
            REGISTER_VALIDATOR_DUAL_AUTH_DOMAIN.len() + 4 + hot_bytes.len() + 4 + cold_bytes.len(),
        );
        message.extend_from_slice(REGISTER_VALIDATOR_DUAL_AUTH_DOMAIN);
        (hot_bytes.len() as u32).encode(&mut message);
        message.extend_from_slice(&hot_bytes);
        (cold_bytes.len() as u32).encode(&mut message);
        message.extend_from_slice(&cold_bytes);
        Ok(Some(message))
    }

    /// Canonical byte-identical message signed by both the current and proposed
    /// cold hybrid pairs for an atomic rotation.
    pub fn rotate_validator_cold_key_dual_signing_bytes(
        &self,
        chain_id: &str,
    ) -> IndraResult<Option<Vec<u8>>> {
        let StakingOpBody::RotateValidatorColdKey {
            validator_id,
            current_cold_key_version,
            new_cold_key_version,
            current_cold_nonce,
            new_cold_pubkey,
            ..
        } = &self.body
        else {
            return Ok(None);
        };
        let mut payload = Vec::new();
        payload.extend_from_slice(ROTATE_VALIDATOR_COLD_KEY_PAYLOAD_DOMAIN);
        current_cold_key_version.encode(&mut payload);
        new_cold_key_version.encode(&mut payload);
        current_cold_nonce.encode(&mut payload);
        new_cold_pubkey.encode(&mut payload);
        let current = AuthorizationEnvelope::new_cold(
            chain_id.as_bytes(),
            AUTH_TAG_ROTATE_VALIDATOR_COLD_KEY,
            *validator_id,
            *current_cold_key_version,
            *current_cold_nonce,
            &payload,
        )?;
        let proposed = AuthorizationEnvelope::new_cold(
            chain_id.as_bytes(),
            AUTH_TAG_ROTATE_VALIDATOR_COLD_KEY,
            *validator_id,
            *new_cold_key_version,
            0,
            &payload,
        )?;
        let current_bytes = current.signing_bytes();
        let proposed_bytes = proposed.signing_bytes();
        let mut message = Vec::new();
        message.extend_from_slice(ROTATE_VALIDATOR_COLD_KEY_DUAL_AUTH_DOMAIN);
        (current_bytes.len() as u32).encode(&mut message);
        message.extend_from_slice(&current_bytes);
        (proposed_bytes.len() as u32).encode(&mut message);
        message.extend_from_slice(&proposed_bytes);
        Ok(Some(message))
    }

    /// Enforce the genesis-native cold-key registration shape.
    pub fn validate_register_validator_cold_extension(&self, _height: u64) -> IndraResult<()> {
        let StakingOpBody::RegisterValidator {
            cold_pubkey,
            cold_signature,
            ..
        } = &self.body
        else {
            return Ok(());
        };
        match (cold_pubkey.is_some(), cold_signature.is_some()) {
            (true, true) => Ok(()),
            (false, _) => Err(crate::error::IndraError::InvalidStakingOp(
                "validator registration requires a cold hybrid public key".into(),
            )),
            (true, false) => Err(crate::error::IndraError::InvalidStakingOp(
                "validator registration requires a cold hybrid signature".into(),
            )),
        }
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
            }
            | StakingOpBody::SelfStake {
                validator_pubkey, ..
            }
            | StakingOpBody::SelfUnstake {
                validator_pubkey, ..
            } => pubkey_to_id(validator_pubkey),
            StakingOpBody::SetCommission { validator_id, .. }
            | StakingOpBody::SetAutoDelegate { validator_id, .. }
            | StakingOpBody::UpdateNetworkAddress { validator_id, .. }
            | StakingOpBody::RotateValidatorColdKey { validator_id, .. } => *validator_id,
        }
    }

    /// Validate structural rules (does NOT verify crypto or state).
    pub fn validate_structure(&self) -> IndraResult<()> {
        self.validate_structure_at_height(u64::MAX)
    }

    /// Validate structural rules under the operation set active at `height`.
    pub fn validate_structure_at_height(&self, height: u64) -> IndraResult<()> {
        use crate::error::IndraError;
        if let Some(authorization) = self.cold_authorization() {
            if self.nonce != 0 {
                return Err(IndraError::InvalidStakingOp(
                    "cold-authorized staking operation outer nonce must be zero".into(),
                ));
            }
            if authorization.cold_key_version == 0 || authorization.cold_nonce == 0 {
                return Err(IndraError::InvalidStakingOp(
                    "cold-authorized staking operation requires nonzero version and cold nonce"
                        .into(),
                ));
            }
        }
        match &self.body {
            StakingOpBody::Delegate { .. } => {}
            StakingOpBody::Undelegate { .. } => {}
            StakingOpBody::SelfStake { .. } => {}
            StakingOpBody::SelfUnstake { .. } => {}
            StakingOpBody::RegisterValidator { commission_bps, .. } => {
                self.validate_register_validator_cold_extension(height)?;
                if *commission_bps > 10_000 {
                    return Err(IndraError::CommissionOutOfRange {
                        actual: *commission_bps,
                        min: 0,
                        max: 10_000,
                    });
                }
            }
            StakingOpBody::RotateValidatorColdKey {
                current_cold_key_version,
                new_cold_key_version,
                current_cold_nonce,
                new_cold_signature,
                ..
            } => {
                if self.nonce != 0
                    || *current_cold_key_version == 0
                    || *current_cold_nonce == 0
                    || current_cold_key_version.checked_add(1) != Some(*new_cold_key_version)
                {
                    return Err(IndraError::InvalidStakingOp(
                        "cold-key rotation requires outer nonce zero, a nonzero current version/nonce, and next version current+1".into(),
                    ));
                }
                if new_cold_signature.is_none() {
                    return Err(IndraError::InvalidStakingOp(
                        "validator cold-key rotation requires the proposed new key signature"
                            .into(),
                    ));
                }
            }
            StakingOpBody::SetCommission {
                new_commission_bps, ..
            } => {
                if *new_commission_bps > 10_000 {
                    return Err(IndraError::CommissionOutOfRange {
                        actual: *new_commission_bps,
                        min: 0,
                        max: 10_000,
                    });
                }
            }
            StakingOpBody::ClaimRewards { .. } => {}
            StakingOpBody::SetAutoDelegate { .. } => {}
            StakingOpBody::UpdateNetworkAddress { network_addr, .. } => {
                if let Some(addr) = network_addr {
                    validate_network_addr_string(addr)?;
                }
            }
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
                bond_proof,
            } => {
                buf.push(TAG_DELEGATE);
                validator_id.encode(buf);
                bond_utxo_id.encode(buf);
                delegator_pubkey.encode(buf);
                encode_optional_bond_proof(bond_proof, buf);
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
                cold_authorization,
            } => {
                buf.push(if cold_authorization.is_some() {
                    TAG_COLD_CLAIM_REWARDS
                } else {
                    TAG_CLAIM_REWARDS
                });
                validator_id.encode(buf);
                delegator_pubkey.encode(buf);
                if let Some(authorization) = cold_authorization {
                    authorization.encode(buf);
                }
            }
            StakingOpBody::RegisterValidator {
                commission_bps,
                bond_utxo_id,
                validator_pubkey,
                vrf_pk,
                bond_proof,
                cold_pubkey,
                cold_signature,
            } => {
                buf.push(TAG_REGISTER_VALIDATOR_WITH_COLD_KEY);
                commission_bps.encode(buf);
                bond_utxo_id.encode(buf);
                validator_pubkey.encode(buf);
                buf.extend_from_slice(vrf_pk);
                encode_optional_bond_proof(bond_proof, buf);
                cold_pubkey.is_some().encode(buf);
                if let Some(pubkey) = cold_pubkey {
                    pubkey.encode(buf);
                }
                cold_signature.is_some().encode(buf);
                if let Some(signature) = cold_signature {
                    signature.encode(buf);
                }
            }
            StakingOpBody::RotateValidatorColdKey {
                validator_id,
                current_cold_key_version,
                new_cold_key_version,
                current_cold_nonce,
                new_cold_pubkey,
                new_cold_signature,
            } => {
                buf.push(TAG_ROTATE_VALIDATOR_COLD_KEY);
                validator_id.encode(buf);
                current_cold_key_version.encode(buf);
                new_cold_key_version.encode(buf);
                current_cold_nonce.encode(buf);
                new_cold_pubkey.encode(buf);
                new_cold_signature.is_some().encode(buf);
                if let Some(signature) = new_cold_signature {
                    signature.encode(buf);
                }
            }
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps,
                cold_authorization,
            } => {
                buf.push(if cold_authorization.is_some() {
                    TAG_COLD_SET_COMMISSION
                } else {
                    TAG_SET_COMMISSION
                });
                validator_id.encode(buf);
                new_commission_bps.encode(buf);
                if let Some(authorization) = cold_authorization {
                    authorization.encode(buf);
                }
            }
            StakingOpBody::SelfStake {
                bond_utxo_id,
                validator_pubkey,
                bond_proof,
                cold_authorization,
            } => {
                buf.push(if cold_authorization.is_some() {
                    TAG_COLD_SELF_STAKE
                } else {
                    TAG_SELF_STAKE
                });
                bond_utxo_id.encode(buf);
                validator_pubkey.encode(buf);
                encode_optional_bond_proof(bond_proof, buf);
                if let Some(authorization) = cold_authorization {
                    authorization.encode(buf);
                }
            }
            StakingOpBody::SelfUnstake {
                bond_utxo_id,
                validator_pubkey,
                cold_authorization,
            } => {
                buf.push(if cold_authorization.is_some() {
                    TAG_COLD_SELF_UNSTAKE
                } else {
                    TAG_SELF_UNSTAKE
                });
                bond_utxo_id.encode(buf);
                validator_pubkey.encode(buf);
                if let Some(authorization) = cold_authorization {
                    authorization.encode(buf);
                }
            }
            StakingOpBody::SetAutoDelegate {
                validator_id,
                target_validator_id,
                cold_authorization,
            } => {
                buf.push(if cold_authorization.is_some() {
                    TAG_COLD_SET_AUTO_DELEGATE
                } else {
                    TAG_SET_AUTO_DELEGATE
                });
                validator_id.encode(buf);
                target_validator_id.encode(buf);
                if let Some(authorization) = cold_authorization {
                    authorization.encode(buf);
                }
            }
            StakingOpBody::UpdateNetworkAddress {
                validator_id,
                network_addr,
            } => {
                buf.push(TAG_UPDATE_NETWORK_ADDRESS);
                validator_id.encode(buf);
                encode_optional_network_addr(network_addr, buf);
            }
        }
    }

    fn encoded_len(&self) -> usize {
        1 + match self {
            StakingOpBody::Delegate {
                delegator_pubkey, ..
            } => {
                32 + 32
                    + delegator_pubkey.encoded_len()
                    + optional_bond_proof_encoded_len(match self {
                        StakingOpBody::Delegate { bond_proof, .. } => bond_proof,
                        _ => unreachable!(),
                    })
            }
            StakingOpBody::Undelegate {
                delegator_pubkey, ..
            } => 32 + 32 + delegator_pubkey.encoded_len(),
            StakingOpBody::ClaimRewards {
                delegator_pubkey,
                cold_authorization,
                ..
            } => {
                32 + delegator_pubkey.encoded_len()
                    + cold_authorization
                        .as_ref()
                        .map(Encode::encoded_len)
                        .unwrap_or(0)
            }
            StakingOpBody::RegisterValidator {
                validator_pubkey,
                bond_proof,
                cold_pubkey,
                cold_signature,
                ..
            } => {
                4 + 32
                    + validator_pubkey.encoded_len()
                    + 32
                    + optional_bond_proof_encoded_len(bond_proof)
                    + 1
                    + cold_pubkey.as_ref().map(Encode::encoded_len).unwrap_or(0)
                    + 1
                    + cold_signature
                        .as_ref()
                        .map(Encode::encoded_len)
                        .unwrap_or(0)
            }
            StakingOpBody::RotateValidatorColdKey {
                new_cold_pubkey,
                new_cold_signature,
                ..
            } => {
                32 + 8
                    + 8
                    + 8
                    + new_cold_pubkey.encoded_len()
                    + 1
                    + new_cold_signature
                        .as_ref()
                        .map(Encode::encoded_len)
                        .unwrap_or(0)
            }
            StakingOpBody::SetCommission {
                cold_authorization, ..
            } => {
                32 + 4
                    + cold_authorization
                        .as_ref()
                        .map(Encode::encoded_len)
                        .unwrap_or(0)
            }
            StakingOpBody::SelfStake {
                validator_pubkey,
                bond_proof,
                cold_authorization,
                ..
            } => {
                32 + validator_pubkey.encoded_len()
                    + optional_bond_proof_encoded_len(bond_proof)
                    + cold_authorization
                        .as_ref()
                        .map(Encode::encoded_len)
                        .unwrap_or(0)
            }
            StakingOpBody::SelfUnstake {
                validator_pubkey,
                cold_authorization,
                ..
            } => {
                32 + validator_pubkey.encoded_len()
                    + cold_authorization
                        .as_ref()
                        .map(Encode::encoded_len)
                        .unwrap_or(0)
            }
            StakingOpBody::SetAutoDelegate {
                cold_authorization, ..
            } => {
                32 + 32
                    + cold_authorization
                        .as_ref()
                        .map(Encode::encoded_len)
                        .unwrap_or(0)
            }
            StakingOpBody::UpdateNetworkAddress { network_addr, .. } => {
                32 + 1
                    + network_addr
                        .as_ref()
                        .map(|addr| 2 + addr.len())
                        .unwrap_or(0)
            }
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
                bond_proof: decode_optional_bond_proof(r)?,
            }),
            TAG_UNDELEGATE => Ok(StakingOpBody::Undelegate {
                validator_id: Bytes32::decode(r)?,
                bond_utxo_id: Bytes32::decode(r)?,
                delegator_pubkey: HybridPubKey::decode(r)?,
            }),
            TAG_CLAIM_REWARDS => Ok(StakingOpBody::ClaimRewards {
                validator_id: Bytes32::decode(r)?,
                delegator_pubkey: HybridPubKey::decode(r)?,
                cold_authorization: None,
            }),
            TAG_REGISTER_VALIDATOR_WITH_COLD_KEY => {
                let commission_bps = u32::decode(r)?;
                let bond_utxo_id = Bytes32::decode(r)?;
                let validator_pubkey = HybridPubKey::decode(r)?;
                let vrf_pk = r.read_bytes32()?;
                let bond_proof = decode_optional_bond_proof(r)?;
                let cold_pubkey = if bool::decode(r)? {
                    Some(ColdHybridPubKey::decode(r)?)
                } else {
                    None
                };
                let cold_signature = if bool::decode(r)? {
                    Some(HybridSignature::decode(r)?)
                } else {
                    None
                };
                if cold_pubkey.is_none() || cold_signature.is_none() {
                    return Err(crate::error::IndraError::InvalidStakingOp(
                        "validator registration requires complete cold-key authorization".into(),
                    ));
                }
                Ok(StakingOpBody::RegisterValidator {
                    commission_bps,
                    bond_utxo_id,
                    validator_pubkey,
                    vrf_pk,
                    bond_proof,
                    cold_pubkey,
                    cold_signature,
                })
            }
            TAG_ROTATE_VALIDATOR_COLD_KEY => {
                let validator_id = Bytes32::decode(r)?;
                let current_cold_key_version = u64::decode(r)?;
                let new_cold_key_version = u64::decode(r)?;
                let current_cold_nonce = u64::decode(r)?;
                let new_cold_pubkey = ColdHybridPubKey::decode(r)?;
                let new_cold_signature = if bool::decode(r)? {
                    Some(HybridSignature::decode(r)?)
                } else {
                    None
                };
                Ok(StakingOpBody::RotateValidatorColdKey {
                    validator_id,
                    current_cold_key_version,
                    new_cold_key_version,
                    current_cold_nonce,
                    new_cold_pubkey,
                    new_cold_signature,
                })
            }
            TAG_SET_COMMISSION => Ok(StakingOpBody::SetCommission {
                validator_id: Bytes32::decode(r)?,
                new_commission_bps: u32::decode(r)?,
                cold_authorization: None,
            }),
            TAG_SELF_STAKE => Ok(StakingOpBody::SelfStake {
                bond_utxo_id: Bytes32::decode(r)?,
                validator_pubkey: HybridPubKey::decode(r)?,
                bond_proof: decode_optional_bond_proof(r)?,
                cold_authorization: None,
            }),
            TAG_SELF_UNSTAKE => Ok(StakingOpBody::SelfUnstake {
                bond_utxo_id: Bytes32::decode(r)?,
                validator_pubkey: HybridPubKey::decode(r)?,
                cold_authorization: None,
            }),
            TAG_SET_AUTO_DELEGATE => Ok(StakingOpBody::SetAutoDelegate {
                validator_id: Bytes32::decode(r)?,
                target_validator_id: Bytes32::decode(r)?,
                cold_authorization: None,
            }),
            TAG_UPDATE_NETWORK_ADDRESS => Ok(StakingOpBody::UpdateNetworkAddress {
                validator_id: Bytes32::decode(r)?,
                network_addr: decode_optional_network_addr(r)?,
            }),
            TAG_COLD_CLAIM_REWARDS => Ok(StakingOpBody::ClaimRewards {
                validator_id: Bytes32::decode(r)?,
                delegator_pubkey: HybridPubKey::decode(r)?,
                cold_authorization: Some(ColdStakingAuthorization::decode(r)?),
            }),
            TAG_COLD_SET_COMMISSION => Ok(StakingOpBody::SetCommission {
                validator_id: Bytes32::decode(r)?,
                new_commission_bps: u32::decode(r)?,
                cold_authorization: Some(ColdStakingAuthorization::decode(r)?),
            }),
            TAG_COLD_SELF_STAKE => Ok(StakingOpBody::SelfStake {
                bond_utxo_id: Bytes32::decode(r)?,
                validator_pubkey: HybridPubKey::decode(r)?,
                bond_proof: decode_optional_bond_proof(r)?,
                cold_authorization: Some(ColdStakingAuthorization::decode(r)?),
            }),
            TAG_COLD_SELF_UNSTAKE => Ok(StakingOpBody::SelfUnstake {
                bond_utxo_id: Bytes32::decode(r)?,
                validator_pubkey: HybridPubKey::decode(r)?,
                cold_authorization: Some(ColdStakingAuthorization::decode(r)?),
            }),
            TAG_COLD_SET_AUTO_DELEGATE => Ok(StakingOpBody::SetAutoDelegate {
                validator_id: Bytes32::decode(r)?,
                target_validator_id: Bytes32::decode(r)?,
                cold_authorization: Some(ColdStakingAuthorization::decode(r)?),
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

fn encode_optional_bond_proof(proof: &Option<StakingBondProof>, buf: &mut Vec<u8>) {
    if let Some(proof) = proof {
        1u8.encode(buf);
        proof.encode(buf);
    } else {
        0u8.encode(buf);
    }
}

fn decode_optional_bond_proof(r: &mut ByteReader<'_>) -> IndraResult<Option<StakingBondProof>> {
    match u8::decode(r)? {
        0 => Ok(None),
        1 => Ok(Some(StakingBondProof::decode(r)?)),
        byte => Err(crate::error::IndraError::InvalidBool { byte }),
    }
}

fn optional_bond_proof_encoded_len(proof: &Option<StakingBondProof>) -> usize {
    1 + proof.as_ref().map(Encode::encoded_len).unwrap_or(0)
}

fn encode_optional_network_addr(addr: &Option<String>, buf: &mut Vec<u8>) {
    if let Some(addr) = addr {
        1u8.encode(buf);
        let bytes = addr.as_bytes();
        debug_assert!(bytes.len() <= MAX_VALIDATOR_NETWORK_ADDR_LEN);
        (bytes.len() as u16).encode(buf);
        buf.extend_from_slice(bytes);
    } else {
        0u8.encode(buf);
    }
}

fn decode_optional_network_addr(r: &mut ByteReader<'_>) -> IndraResult<Option<String>> {
    match u8::decode(r)? {
        0 => Ok(None),
        1 => {
            let len = u16::decode(r)? as usize;
            if len > MAX_VALIDATOR_NETWORK_ADDR_LEN {
                return Err(crate::error::IndraError::InvalidStakingOp(format!(
                    "validator network address length {} exceeds maximum {}",
                    len, MAX_VALIDATOR_NETWORK_ADDR_LEN
                )));
            }
            let bytes = r.read_bytes(len)?;
            let addr = String::from_utf8(bytes.to_vec()).map_err(|_| {
                crate::error::IndraError::InvalidStakingOp(
                    "validator network address is not valid UTF-8".into(),
                )
            })?;
            validate_network_addr_string(&addr)?;
            Ok(Some(addr))
        }
        byte => Err(crate::error::IndraError::InvalidBool { byte }),
    }
}

/// Consensus structural validation for validator-advertised network addresses.
///
/// v4 deliberately accepts only strict `SocketAddr` IP:port syntax: no
/// hostnames, schemes, paths, whitespace, or zero port. Reachability is a
/// networking concern and is not checked in consensus.
pub fn validate_network_addr_string(addr: &str) -> IndraResult<()> {
    if addr.is_empty()
        || addr.len() > MAX_VALIDATOR_NETWORK_ADDR_LEN
        || addr.chars().any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(crate::error::IndraError::InvalidStakingOp(
            "validator network address has invalid length or characters".into(),
        ));
    }
    let parsed: std::net::SocketAddr = addr.parse().map_err(|_| {
        crate::error::IndraError::InvalidStakingOp(
            "validator network address must be strict IP:port syntax".into(),
        )
    })?;
    if parsed.port() == 0 {
        return Err(crate::error::IndraError::InvalidStakingOp(
            "validator network address port must be non-zero".into(),
        ));
    }
    Ok(())
}

fn pubkey_to_id(pubkey: &HybridPubKey) -> Bytes32 {
    Bytes32::from(indra_crypto::sha256(&pubkey.classical_pk.0))
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

    fn dummy_cold_pubkey() -> ColdHybridPubKey {
        ColdHybridPubKey {
            classical_pk: Bytes32::from([0xC1; 32]),
            pq_pk: VariableBytes::from_slice(&[0xC2; indra_crypto::PQ_PK_BYTES]).unwrap(),
        }
    }

    fn dummy_bond_proof(byte: u8, value: u64) -> StakingBondProof {
        StakingBondProof {
            committed_value_spark: value,
            blinding_factor: Bytes32::from([byte; 32]),
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
                bond_proof: Some(dummy_bond_proof(0xA1, 10_000)),
            }),
            op(StakingOpBody::Undelegate {
                validator_id: Bytes32::from([2u8; 32]),
                bond_utxo_id: Bytes32::from([0x22u8; 32]),
                delegator_pubkey: dummy_pubkey(),
            }),
            op(StakingOpBody::ClaimRewards {
                validator_id: Bytes32::from([3u8; 32]),
                delegator_pubkey: dummy_pubkey(),
                cold_authorization: None,
            }),
            op(StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id: Bytes32::from([0x44; 32]),
                validator_pubkey: dummy_pubkey(),
                vrf_pk: [4u8; 32],
                bond_proof: Some(dummy_bond_proof(0xA2, 20_000)),
                cold_pubkey: Some(dummy_cold_pubkey()),
                cold_signature: Some(dummy_signature()),
            }),
            op(StakingOpBody::SetCommission {
                validator_id: Bytes32::from([5u8; 32]),
                new_commission_bps: 1_500,
                cold_authorization: None,
            }),
            op(StakingOpBody::SelfStake {
                bond_utxo_id: Bytes32::from([0x66u8; 32]),
                validator_pubkey: dummy_pubkey(),
                bond_proof: Some(dummy_bond_proof(0xA3, 30_000)),
                cold_authorization: None,
            }),
            op(StakingOpBody::SelfUnstake {
                bond_utxo_id: Bytes32::from([0x77u8; 32]),
                validator_pubkey: dummy_pubkey(),
                cold_authorization: None,
            }),
            op(StakingOpBody::SetAutoDelegate {
                validator_id: Bytes32::from([0x88u8; 32]),
                target_validator_id: Bytes32::from([0x99u8; 32]),
                cold_authorization: None,
            }),
            op(StakingOpBody::UpdateNetworkAddress {
                validator_id: Bytes32::from([0xAAu8; 32]),
                network_addr: Some("203.0.113.10:30303".to_string()),
            }),
            op(StakingOpBody::UpdateNetworkAddress {
                validator_id: Bytes32::from([0xABu8; 32]),
                network_addr: None,
            }),
        ];

        for op in cases {
            let encoded = op.encode_to_vec();
            assert_eq!(StakingOp::decode_exact(&encoded).unwrap(), op);
        }
    }

    #[test]
    fn cold_staking_wire_extensions_round_trip_and_legacy_bytes_are_unchanged() {
        let validator_id = Bytes32::from([0xD1; 32]);
        let validator_pubkey = dummy_pubkey();
        let authorization = ColdStakingAuthorization {
            cold_key_version: 7,
            cold_nonce: 9,
        };
        let legacy_and_cold = vec![
            (
                StakingOpBody::ClaimRewards {
                    validator_id,
                    delegator_pubkey: validator_pubkey.clone(),
                    cold_authorization: None,
                },
                StakingOpBody::ClaimRewards {
                    validator_id,
                    delegator_pubkey: validator_pubkey.clone(),
                    cold_authorization: Some(authorization),
                },
                TAG_CLAIM_REWARDS,
                TAG_COLD_CLAIM_REWARDS,
            ),
            (
                StakingOpBody::SetCommission {
                    validator_id,
                    new_commission_bps: 1_234,
                    cold_authorization: None,
                },
                StakingOpBody::SetCommission {
                    validator_id,
                    new_commission_bps: 1_234,
                    cold_authorization: Some(authorization),
                },
                TAG_SET_COMMISSION,
                TAG_COLD_SET_COMMISSION,
            ),
            (
                StakingOpBody::SelfStake {
                    bond_utxo_id: Bytes32::from([0xD3; 32]),
                    validator_pubkey: validator_pubkey.clone(),
                    bond_proof: Some(dummy_bond_proof(0xD4, 100)),
                    cold_authorization: None,
                },
                StakingOpBody::SelfStake {
                    bond_utxo_id: Bytes32::from([0xD3; 32]),
                    validator_pubkey: validator_pubkey.clone(),
                    bond_proof: Some(dummy_bond_proof(0xD4, 100)),
                    cold_authorization: Some(authorization),
                },
                TAG_SELF_STAKE,
                TAG_COLD_SELF_STAKE,
            ),
            (
                StakingOpBody::SelfUnstake {
                    bond_utxo_id: Bytes32::from([0xD5; 32]),
                    validator_pubkey: validator_pubkey.clone(),
                    cold_authorization: None,
                },
                StakingOpBody::SelfUnstake {
                    bond_utxo_id: Bytes32::from([0xD5; 32]),
                    validator_pubkey: validator_pubkey.clone(),
                    cold_authorization: Some(authorization),
                },
                TAG_SELF_UNSTAKE,
                TAG_COLD_SELF_UNSTAKE,
            ),
            (
                StakingOpBody::SetAutoDelegate {
                    validator_id,
                    target_validator_id: Bytes32::ZERO,
                    cold_authorization: None,
                },
                StakingOpBody::SetAutoDelegate {
                    validator_id,
                    target_validator_id: Bytes32::ZERO,
                    cold_authorization: Some(authorization),
                },
                TAG_SET_AUTO_DELEGATE,
                TAG_COLD_SET_AUTO_DELEGATE,
            ),
        ];

        for (legacy, cold, legacy_tag, cold_tag) in legacy_and_cold {
            let legacy_bytes = legacy.encode_to_vec();
            assert_eq!(legacy_bytes[0], legacy_tag);
            assert_eq!(legacy_bytes.len(), legacy.encoded_len());
            assert_eq!(StakingOpBody::decode_exact(&legacy_bytes).unwrap(), legacy);

            let cold_bytes = cold.encode_to_vec();
            assert_eq!(cold_bytes[0], cold_tag);
            assert_eq!(cold_bytes.len(), legacy_bytes.len() + 16);
            assert_eq!(StakingOpBody::decode_exact(&cold_bytes).unwrap(), cold);
            assert_ne!(legacy_bytes, cold_bytes);
        }
    }

    #[test]
    fn staking_op_signing_bytes_domain_separation() {
        let delegate = op(StakingOpBody::Delegate {
            validator_id: Bytes32::from([1u8; 32]),
            bond_utxo_id: Bytes32::from([0x11u8; 32]),
            delegator_pubkey: dummy_pubkey(),
            bond_proof: None,
        });
        let register = op(StakingOpBody::RegisterValidator {
            commission_bps: 1_000,
            bond_utxo_id: Bytes32::from([0x99; 32]),
            validator_pubkey: dummy_pubkey(),
            vrf_pk: [9u8; 32],
            bond_proof: None,
            cold_pubkey: None,
            cold_signature: None,
        });
        let delegate_bytes = delegate.signing_bytes("indra-testnet-1");
        assert!(delegate_bytes.starts_with(STAKING_OP_DOMAIN.as_bytes()));
        assert_ne!(delegate_bytes, register.signing_bytes("indra-testnet-1"));
        assert_ne!(delegate_bytes, delegate.signing_bytes("indra-other"));
    }

    #[test]
    fn update_network_address_rejects_unbounded_length() {
        let mut bytes = Vec::new();
        bytes.push(TAG_UPDATE_NETWORK_ADDRESS);
        Bytes32::from([0xAAu8; 32]).encode(&mut bytes);
        1u8.encode(&mut bytes);
        ((MAX_VALIDATOR_NETWORK_ADDR_LEN as u16) + 1).encode(&mut bytes);
        bytes.extend(std::iter::repeat_n(
            b'1',
            MAX_VALIDATOR_NETWORK_ADDR_LEN + 1,
        ));

        assert!(StakingOpBody::decode_exact(&bytes).is_err());
    }

    #[test]
    fn update_network_address_rejects_invalid_syntax() {
        for invalid in [
            "validator.example.com:30303",
            "http://203.0.113.10:30303",
            "203.0.113.10:30303/path",
            "203.0.113.10:30303 ",
            "203.0.113.10:0",
        ] {
            let body = StakingOpBody::UpdateNetworkAddress {
                validator_id: Bytes32::from([0xAAu8; 32]),
                network_addr: Some(invalid.to_string()),
            };
            assert!(StakingOp {
                body,
                nonce: 1,
                signature: dummy_signature()
            }
            .validate_structure()
            .is_err());
        }

        for valid in ["203.0.113.10:30303", "[2001:db8::1]:30303"] {
            let body = StakingOpBody::UpdateNetworkAddress {
                validator_id: Bytes32::from([0xAAu8; 32]),
                network_addr: Some(valid.to_string()),
            };
            assert!(StakingOp {
                body,
                nonce: 1,
                signature: dummy_signature()
            }
            .validate_structure()
            .is_ok());
        }
    }

    #[test]
    fn staking_op_validate_structure_accepts_bond_id_delegate() {
        let op = op(StakingOpBody::Delegate {
            validator_id: Bytes32::ZERO,
            bond_utxo_id: Bytes32::ZERO,
            delegator_pubkey: dummy_pubkey(),
            bond_proof: None,
        });
        assert!(op.validate_structure().is_ok());
    }

    #[test]
    fn staking_op_validate_structure_rejects_bad_commission() {
        let bad_register = op(StakingOpBody::RegisterValidator {
            commission_bps: 10_001,
            bond_utxo_id: Bytes32::ZERO,
            validator_pubkey: dummy_pubkey(),
            vrf_pk: [0u8; 32],
            bond_proof: None,
            cold_pubkey: None,
            cold_signature: None,
        });
        assert!(bad_register.validate_structure().is_err());

        let bad_set = op(StakingOpBody::SetCommission {
            validator_id: Bytes32::ZERO,
            new_commission_bps: 10_001,
            cold_authorization: None,
        });
        assert!(bad_set.validate_structure().is_err());
    }

    #[test]
    fn commission_in_range_accepted() {
        let op = op(StakingOpBody::RegisterValidator {
            commission_bps: 1_000,
            bond_utxo_id: Bytes32::ZERO,
            validator_pubkey: dummy_pubkey(),
            vrf_pk: [0u8; 32],
            bond_proof: None,
            cold_pubkey: Some(dummy_cold_pubkey()),
            cold_signature: Some(dummy_signature()),
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
            bond_proof: None,
        });
        let b = op(StakingOpBody::ClaimRewards {
            validator_id: Bytes32::from([2u8; 32]),
            delegator_pubkey: pubkey,
            cold_authorization: None,
        });
        assert_eq!(a.signer_id(), b.signer_id());
    }

    #[test]
    fn staking_op_self_stake_encode_decode_round_trip() {
        let op = op(StakingOpBody::SelfStake {
            bond_utxo_id: Bytes32::from([0xA1; 32]),
            validator_pubkey: dummy_pubkey(),
            bond_proof: Some(dummy_bond_proof(0xA4, 42)),
            cold_authorization: None,
        });
        let encoded = op.encode_to_vec();
        assert_eq!(StakingOp::decode_exact(&encoded).unwrap(), op);
    }

    #[test]
    fn staking_op_self_unstake_encode_decode_round_trip() {
        let op = op(StakingOpBody::SelfUnstake {
            bond_utxo_id: Bytes32::from([0xA2; 32]),
            validator_pubkey: dummy_pubkey(),
            cold_authorization: None,
        });
        let encoded = op.encode_to_vec();
        assert_eq!(StakingOp::decode_exact(&encoded).unwrap(), op);
    }

    #[test]
    fn staking_op_self_stake_signer_id_is_validator_id() {
        let pubkey = dummy_pubkey();
        let expected = pubkey_to_id(&pubkey);
        let op = op(StakingOpBody::SelfStake {
            bond_utxo_id: Bytes32::from([0xA3; 32]),
            validator_pubkey: pubkey,
            bond_proof: None,
            cold_authorization: None,
        });
        assert_eq!(op.signer_id(), expected);
    }

    #[test]
    fn staking_op_self_stake_signing_bytes_domain_separated_from_delegate() {
        let pubkey = dummy_pubkey();
        let bond_utxo_id = Bytes32::from([0xA4; 32]);
        let self_stake = op(StakingOpBody::SelfStake {
            bond_utxo_id,
            validator_pubkey: pubkey.clone(),
            bond_proof: None,
            cold_authorization: None,
        });
        let delegate = op(StakingOpBody::Delegate {
            validator_id: pubkey_to_id(&pubkey),
            bond_utxo_id,
            delegator_pubkey: pubkey,
            bond_proof: None,
        });
        assert_ne!(
            self_stake.signing_bytes("indra-testnet-1"),
            delegate.signing_bytes("indra-testnet-1")
        );
    }

    #[test]
    fn staking_bond_proof_encoding_round_trips() {
        let proof = dummy_bond_proof(0x42, 123_456);
        let encoded = proof.encode_to_vec();
        assert_eq!(encoded.len(), 40);
        assert_eq!(StakingBondProof::decode_exact(&encoded).unwrap(), proof);
    }

    #[test]
    fn staking_op_signing_bytes_include_bond_proof() {
        let base = op(StakingOpBody::SelfStake {
            bond_utxo_id: Bytes32::from([0xB1; 32]),
            validator_pubkey: dummy_pubkey(),
            bond_proof: Some(dummy_bond_proof(0x01, 100)),
            cold_authorization: None,
        });
        let changed = op(StakingOpBody::SelfStake {
            bond_utxo_id: Bytes32::from([0xB1; 32]),
            validator_pubkey: dummy_pubkey(),
            bond_proof: Some(dummy_bond_proof(0x02, 100)),
            cold_authorization: None,
        });
        assert_ne!(
            base.signing_bytes("indra-testnet-1"),
            changed.signing_bytes("indra-testnet-1")
        );
    }

    #[test]
    fn staking_op_set_auto_delegate_encode_decode() {
        let op = op(StakingOpBody::SetAutoDelegate {
            validator_id: Bytes32::from([0x31; 32]),
            target_validator_id: Bytes32::from([0x32; 32]),
            cold_authorization: None,
        });
        let encoded = op.encode_to_vec();
        assert_eq!(StakingOp::decode_exact(&encoded).unwrap(), op);
    }

    #[test]
    fn staking_op_set_auto_delegate_signer_is_validator_id() {
        let validator_id = Bytes32::from([0x33; 32]);
        let op = op(StakingOpBody::SetAutoDelegate {
            validator_id,
            target_validator_id: Bytes32::from([0x34; 32]),
            cold_authorization: None,
        });
        assert_eq!(op.signer_id(), validator_id);
    }

    #[test]
    fn staking_op_clear_auto_delegate_zero_target() {
        let op = op(StakingOpBody::SetAutoDelegate {
            validator_id: Bytes32::from([0x35; 32]),
            target_validator_id: Bytes32::ZERO,
            cold_authorization: None,
        });
        assert!(op.validate_structure().is_ok());
        let encoded = op.encode_to_vec();
        assert_eq!(StakingOp::decode_exact(&encoded).unwrap(), op);
    }
}
