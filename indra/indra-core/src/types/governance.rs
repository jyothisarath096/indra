//! Governance operation types.

use crate::{
    codec::{ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    ssz::sha256,
    types::{
        authorization::AuthorizationEnvelope,
        crypto::{HybridPubKey, HybridSignature},
        primitives::{
            Bytes32, VariableBytes, SCHEMA_VERSION, SCHEMA_VERSION_PRE_VALIDATOR_NETWORK_ADDRESS,
        },
    },
};

const TAG_COLD_PROPOSE: u8 = 19;
const TAG_COLD_COMMIT: u8 = 20;
const TAG_COLD_REVEAL: u8 = 21;
const TAG_COLD_CANCEL: u8 = 22;

/// Stable authorization-envelope tag for cold governance proposals.
pub const AUTH_TAG_COLD_PROPOSE: u16 = TAG_COLD_PROPOSE as u16;
/// Stable authorization-envelope tag for cold governance vote commitments.
pub const AUTH_TAG_COLD_COMMIT: u16 = TAG_COLD_COMMIT as u16;
/// Stable authorization-envelope tag for cold governance vote reveals.
pub const AUTH_TAG_COLD_REVEAL: u16 = TAG_COLD_REVEAL as u16;
/// Stable authorization-envelope tag for cold governance cancellation.
pub const AUTH_TAG_COLD_CANCEL: u16 = TAG_COLD_CANCEL as u16;

/// Versioned replay metadata attached only to cold-authorized governance forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColdGovernanceAuthorization {
    /// Registered cold-key version that must authorize the operation.
    pub cold_key_version: u64,
    /// Next nonce in the shared validator cold-role nonce namespace.
    pub cold_nonce: u64,
}

impl Encode for ColdGovernanceAuthorization {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.cold_key_version.encode(buf);
        self.cold_nonce.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        16
    }
}

impl Decode for ColdGovernanceAuthorization {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            cold_key_version: u64::decode(r)?,
            cold_nonce: u64::decode(r)?,
        })
    }
}

/// Governance action discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GovernanceActionType {
    /// Submit a new proposal.
    ProposeChange = 0,
    /// Commit to a hidden vote.
    CommitVote = 1,
    /// Reveal a committed vote.
    RevealVote = 2,
    /// Move governance vote weight for one proposal.
    GovernanceRedelegate = 3,
    /// Execute an approved proposal.
    ExecuteProposal = 4,
    /// Cancel a proposal during deliberation.
    CancelProposal = 5,
}

impl Encode for GovernanceActionType {
    fn encode(&self, buf: &mut Vec<u8>) {
        (*self as u8).encode(buf);
    }

    fn encoded_len(&self) -> usize {
        1
    }
}

impl Decode for GovernanceActionType {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        match u8::decode(r)? {
            0 => Ok(Self::ProposeChange),
            1 => Ok(Self::CommitVote),
            2 => Ok(Self::RevealVote),
            3 => Ok(Self::GovernanceRedelegate),
            4 => Ok(Self::ExecuteProposal),
            5 => Ok(Self::CancelProposal),
            b => Err(IndraError::InvalidBool { byte: b }),
        }
    }
}

/// Proposal tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProposalTier {
    /// Standard governance parameter.
    Standard = 0,
    /// Critical governance parameter.
    Critical = 1,
}

impl Encode for ProposalTier {
    fn encode(&self, buf: &mut Vec<u8>) {
        (*self as u8).encode(buf);
    }

    fn encoded_len(&self) -> usize {
        1
    }
}

impl Decode for ProposalTier {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        match u8::decode(r)? {
            0 => Ok(Self::Standard),
            1 => Ok(Self::Critical),
            b => Err(IndraError::InvalidBool { byte: b }),
        }
    }
}

/// Typed proposal payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernableAction {
    /// Set liveness miss threshold.
    SetSlashLivenessThresholdEpochs {
        /// New threshold value.
        value: u64,
    },
    /// Set global delegation floor.
    SetMinDelegationSpark {
        /// New minimum delegation in Spark.
        value: u64,
    },
    /// Set proposal deposit amount.
    SetProposalDepositSpark {
        /// New proposal deposit in Spark.
        value: u64,
    },
    /// Set liveness slash bps.
    SetSlashLivenessBps {
        /// New liveness slash in basis points.
        value: u32,
    },
    /// Set double-precommit slash bps.
    SetSlashDoublePrecommitBps {
        /// New double-precommit slash in basis points.
        value: u32,
    },
    /// Set surround-vote slash bps.
    SetSlashSurroundVoteBps {
        /// New surround-vote slash in basis points.
        value: u32,
    },
    /// Set max validator commission bps.
    SetMaxCommissionBps {
        /// New maximum commission in basis points.
        value: u32,
    },
    /// Set governance execution delay.
    SetGovernanceDelayEpochs {
        /// New governance delay in epochs.
        value: u64,
    },
    /// Set standard governance YES-stake threshold.
    ///
    /// This threshold is applied to total proposal snapshot stake, not
    /// participating stake. See docs/GOVERNANCE_THRESHOLD_DESIGN.md.
    SetGovernanceQuorumBps {
        /// New standard YES-stake threshold in basis points.
        value: u32,
    },
    /// Set critical governance YES-stake threshold.
    ///
    /// This threshold is applied to total proposal snapshot stake, not
    /// participating stake. See docs/GOVERNANCE_THRESHOLD_DESIGN.md.
    SetGovernanceCriticalQuorumBps {
        /// New critical YES-stake threshold in basis points.
        value: u32,
    },
}

impl GovernableAction {
    /// Return the tier required by this action.
    pub fn tier(&self) -> ProposalTier {
        match self {
            Self::SetSlashLivenessThresholdEpochs { .. }
            | Self::SetMinDelegationSpark { .. }
            | Self::SetProposalDepositSpark { .. } => ProposalTier::Standard,
            _ => ProposalTier::Critical,
        }
    }
}

impl Encode for GovernableAction {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::SetSlashLivenessThresholdEpochs { value } => {
                0u8.encode(buf);
                value.encode(buf);
            }
            Self::SetMinDelegationSpark { value } => {
                1u8.encode(buf);
                value.encode(buf);
            }
            Self::SetProposalDepositSpark { value } => {
                2u8.encode(buf);
                value.encode(buf);
            }
            Self::SetSlashLivenessBps { value } => {
                3u8.encode(buf);
                value.encode(buf);
            }
            Self::SetSlashDoublePrecommitBps { value } => {
                4u8.encode(buf);
                value.encode(buf);
            }
            Self::SetSlashSurroundVoteBps { value } => {
                5u8.encode(buf);
                value.encode(buf);
            }
            Self::SetMaxCommissionBps { value } => {
                6u8.encode(buf);
                value.encode(buf);
            }
            Self::SetGovernanceDelayEpochs { value } => {
                7u8.encode(buf);
                value.encode(buf);
            }
            Self::SetGovernanceQuorumBps { value } => {
                8u8.encode(buf);
                value.encode(buf);
            }
            Self::SetGovernanceCriticalQuorumBps { value } => {
                9u8.encode(buf);
                value.encode(buf);
            }
        }
    }

    fn encoded_len(&self) -> usize {
        1 + match self {
            Self::SetSlashLivenessThresholdEpochs { .. }
            | Self::SetMinDelegationSpark { .. }
            | Self::SetProposalDepositSpark { .. }
            | Self::SetGovernanceDelayEpochs { .. } => 8,
            _ => 4,
        }
    }
}

impl Decode for GovernableAction {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        match u8::decode(r)? {
            0 => Ok(Self::SetSlashLivenessThresholdEpochs {
                value: u64::decode(r)?,
            }),
            1 => Ok(Self::SetMinDelegationSpark {
                value: u64::decode(r)?,
            }),
            2 => Ok(Self::SetProposalDepositSpark {
                value: u64::decode(r)?,
            }),
            3 => Ok(Self::SetSlashLivenessBps {
                value: u32::decode(r)?,
            }),
            4 => Ok(Self::SetSlashDoublePrecommitBps {
                value: u32::decode(r)?,
            }),
            5 => Ok(Self::SetSlashSurroundVoteBps {
                value: u32::decode(r)?,
            }),
            6 => Ok(Self::SetMaxCommissionBps {
                value: u32::decode(r)?,
            }),
            7 => Ok(Self::SetGovernanceDelayEpochs {
                value: u64::decode(r)?,
            }),
            8 => Ok(Self::SetGovernanceQuorumBps {
                value: u32::decode(r)?,
            }),
            9 => Ok(Self::SetGovernanceCriticalQuorumBps {
                value: u32::decode(r)?,
            }),
            b => Err(IndraError::InvalidBool { byte: b }),
        }
    }
}

/// Action-specific governance payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernancePayload {
    /// New proposal.
    Propose {
        /// Action being proposed.
        action: GovernableAction,
        /// Deposit UTXO id.
        deposit_utxo_id: Bytes32,
        /// Proposer public key for deposit refunds and signature verification.
        proposer_pubkey: HybridPubKey,
        /// Title.
        title: VariableBytes<128>,
        /// Description.
        description: VariableBytes<1024>,
        /// Present only for an enrolled validator.
        cold_authorization: Option<ColdGovernanceAuthorization>,
    },
    /// Vote commitment.
    Commit {
        /// Proposal id.
        proposal_id: Bytes32,
        /// Domain-separated hidden-vote commitment.
        ///
        /// See [`governance_vote_commit_hash`] for the exact preimage.
        commit_hash: Bytes32,
        /// Present only for an enrolled validator.
        cold_authorization: Option<ColdGovernanceAuthorization>,
    },
    /// Vote reveal.
    Reveal {
        /// Proposal id.
        proposal_id: Bytes32,
        /// 0x00 = NO, 0x01 = YES.
        vote: u8,
        /// Commit nonce.
        nonce: Bytes32,
        /// Present only for an enrolled validator.
        cold_authorization: Option<ColdGovernanceAuthorization>,
    },
    /// Weight-only redelegation.
    Redelegate {
        /// Proposal id.
        proposal_id: Bytes32,
        /// Source validator.
        from_validator: Bytes32,
        /// Target validator.
        to_validator: Bytes32,
        /// Amount of weight to shift.
        amount_spark: u64,
    },
    /// Execute a proposal.
    Execute {
        /// Proposal id.
        proposal_id: Bytes32,
    },
    /// Cancel a proposal.
    Cancel {
        /// Proposal id.
        proposal_id: Bytes32,
        /// Present only for an enrolled validator.
        cold_authorization: Option<ColdGovernanceAuthorization>,
    },
}

impl GovernancePayload {
    /// Return the action type implied by this payload.
    pub fn action_type(&self) -> GovernanceActionType {
        match self {
            Self::Propose { .. } => GovernanceActionType::ProposeChange,
            Self::Commit { .. } => GovernanceActionType::CommitVote,
            Self::Reveal { .. } => GovernanceActionType::RevealVote,
            Self::Redelegate { .. } => GovernanceActionType::GovernanceRedelegate,
            Self::Execute { .. } => GovernanceActionType::ExecuteProposal,
            Self::Cancel { .. } => GovernanceActionType::CancelProposal,
        }
    }
}

impl Encode for GovernancePayload {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Propose {
                action,
                deposit_utxo_id,
                proposer_pubkey,
                title,
                description,
                cold_authorization,
            } => {
                if cold_authorization.is_some() {
                    TAG_COLD_PROPOSE.encode(buf);
                } else {
                    0u8.encode(buf);
                }
                action.encode(buf);
                deposit_utxo_id.encode(buf);
                proposer_pubkey.encode(buf);
                title.encode(buf);
                description.encode(buf);
                if let Some(authorization) = cold_authorization {
                    authorization.encode(buf);
                }
            }
            Self::Commit {
                proposal_id,
                commit_hash,
                cold_authorization,
            } => {
                if cold_authorization.is_some() {
                    TAG_COLD_COMMIT.encode(buf);
                } else {
                    1u8.encode(buf);
                }
                proposal_id.encode(buf);
                commit_hash.encode(buf);
                if let Some(authorization) = cold_authorization {
                    authorization.encode(buf);
                }
            }
            Self::Reveal {
                proposal_id,
                vote,
                nonce,
                cold_authorization,
            } => {
                if cold_authorization.is_some() {
                    TAG_COLD_REVEAL.encode(buf);
                } else {
                    2u8.encode(buf);
                }
                proposal_id.encode(buf);
                vote.encode(buf);
                nonce.encode(buf);
                if let Some(authorization) = cold_authorization {
                    authorization.encode(buf);
                }
            }
            Self::Redelegate {
                proposal_id,
                from_validator,
                to_validator,
                amount_spark,
            } => {
                3u8.encode(buf);
                proposal_id.encode(buf);
                from_validator.encode(buf);
                to_validator.encode(buf);
                amount_spark.encode(buf);
            }
            Self::Execute { proposal_id } => {
                4u8.encode(buf);
                proposal_id.encode(buf);
            }
            Self::Cancel {
                proposal_id,
                cold_authorization,
            } => {
                if cold_authorization.is_some() {
                    TAG_COLD_CANCEL.encode(buf);
                } else {
                    5u8.encode(buf);
                }
                proposal_id.encode(buf);
                if let Some(authorization) = cold_authorization {
                    authorization.encode(buf);
                }
            }
        }
    }

    fn encoded_len(&self) -> usize {
        1 + match self {
            Self::Propose {
                action,
                deposit_utxo_id,
                proposer_pubkey,
                title,
                description,
                cold_authorization,
            } => {
                action.encoded_len()
                    + deposit_utxo_id.encoded_len()
                    + proposer_pubkey.encoded_len()
                    + title.encoded_len()
                    + description.encoded_len()
                    + cold_authorization.as_ref().map_or(0, Encode::encoded_len)
            }
            Self::Commit {
                cold_authorization, ..
            } => 64 + cold_authorization.as_ref().map_or(0, Encode::encoded_len),
            Self::Reveal {
                cold_authorization, ..
            } => 65 + cold_authorization.as_ref().map_or(0, Encode::encoded_len),
            Self::Redelegate { .. } => 104,
            Self::Execute { .. } => 32,
            Self::Cancel {
                cold_authorization, ..
            } => 32 + cold_authorization.as_ref().map_or(0, Encode::encoded_len),
        }
    }
}

impl Decode for GovernancePayload {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        match u8::decode(r)? {
            0 => Ok(Self::Propose {
                action: GovernableAction::decode(r)?,
                deposit_utxo_id: Bytes32::decode(r)?,
                proposer_pubkey: HybridPubKey::decode(r)?,
                title: VariableBytes::decode(r)?,
                description: VariableBytes::decode(r)?,
                cold_authorization: None,
            }),
            1 => Ok(Self::Commit {
                proposal_id: Bytes32::decode(r)?,
                commit_hash: Bytes32::decode(r)?,
                cold_authorization: None,
            }),
            2 => Ok(Self::Reveal {
                proposal_id: Bytes32::decode(r)?,
                vote: u8::decode(r)?,
                nonce: Bytes32::decode(r)?,
                cold_authorization: None,
            }),
            3 => Ok(Self::Redelegate {
                proposal_id: Bytes32::decode(r)?,
                from_validator: Bytes32::decode(r)?,
                to_validator: Bytes32::decode(r)?,
                amount_spark: u64::decode(r)?,
            }),
            4 => Ok(Self::Execute {
                proposal_id: Bytes32::decode(r)?,
            }),
            5 => Ok(Self::Cancel {
                proposal_id: Bytes32::decode(r)?,
                cold_authorization: None,
            }),
            TAG_COLD_PROPOSE => Ok(Self::Propose {
                action: GovernableAction::decode(r)?,
                deposit_utxo_id: Bytes32::decode(r)?,
                proposer_pubkey: HybridPubKey::decode(r)?,
                title: VariableBytes::decode(r)?,
                description: VariableBytes::decode(r)?,
                cold_authorization: Some(ColdGovernanceAuthorization::decode(r)?),
            }),
            TAG_COLD_COMMIT => Ok(Self::Commit {
                proposal_id: Bytes32::decode(r)?,
                commit_hash: Bytes32::decode(r)?,
                cold_authorization: Some(ColdGovernanceAuthorization::decode(r)?),
            }),
            TAG_COLD_REVEAL => Ok(Self::Reveal {
                proposal_id: Bytes32::decode(r)?,
                vote: u8::decode(r)?,
                nonce: Bytes32::decode(r)?,
                cold_authorization: Some(ColdGovernanceAuthorization::decode(r)?),
            }),
            TAG_COLD_CANCEL => Ok(Self::Cancel {
                proposal_id: Bytes32::decode(r)?,
                cold_authorization: Some(ColdGovernanceAuthorization::decode(r)?),
            }),
            b => Err(IndraError::InvalidBool { byte: b }),
        }
    }
}

/// Authenticated governance operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceOpV2 {
    /// Operation type.
    pub action_type: GovernanceActionType,
    /// Signer identity.
    pub signer_id: Bytes32,
    /// Governance nonce.
    pub nonce: u64,
    /// Action-specific payload.
    pub payload: GovernancePayload,
    /// Hybrid signature.
    pub signature: HybridSignature,
}

impl GovernanceOpV2 {
    /// Return cold replay metadata for a cold-authorized validator operation.
    pub fn cold_authorization(&self) -> Option<ColdGovernanceAuthorization> {
        match &self.payload {
            GovernancePayload::Propose {
                cold_authorization, ..
            }
            | GovernancePayload::Commit {
                cold_authorization, ..
            }
            | GovernancePayload::Reveal {
                cold_authorization, ..
            }
            | GovernancePayload::Cancel {
                cold_authorization, ..
            } => *cold_authorization,
            GovernancePayload::Redelegate { .. } | GovernancePayload::Execute { .. } => None,
        }
    }

    /// Construct the canonical cold-role authorization envelope bytes.
    pub fn cold_authorization_signing_bytes(&self, chain_id: &str) -> IndraResult<Option<Vec<u8>>> {
        let Some(authorization) = self.cold_authorization() else {
            return Ok(None);
        };
        if self.nonce != 0 {
            return Err(IndraError::InvariantViolation {
                message: "cold-authorized governance op outer nonce must be zero",
            });
        }
        let operation_tag = match &self.payload {
            GovernancePayload::Propose { .. } => AUTH_TAG_COLD_PROPOSE,
            GovernancePayload::Commit { .. } => AUTH_TAG_COLD_COMMIT,
            GovernancePayload::Reveal { .. } => AUTH_TAG_COLD_REVEAL,
            GovernancePayload::Cancel { .. } => AUTH_TAG_COLD_CANCEL,
            GovernancePayload::Redelegate { .. } | GovernancePayload::Execute { .. } => {
                return Err(IndraError::InvariantViolation {
                    message: "governance payload cannot carry cold authorization",
                });
            }
        };
        let mut payload = self.payload.encode_to_vec();
        self.nonce.encode(&mut payload);
        Ok(Some(
            AuthorizationEnvelope::new_cold(
                chain_id.as_bytes(),
                operation_tag,
                self.signer_id,
                authorization.cold_key_version,
                authorization.cold_nonce,
                &payload,
            )?
            .signing_bytes(),
        ))
    }

    /// Enforce the enrollment-gated structural split between legacy and cold forms.
    pub fn validate_structure_at_height(&self, height: u64) -> IndraResult<()> {
        if self.payload.action_type() != self.action_type {
            return Err(IndraError::InvariantViolation {
                message: "governance payload/action type mismatch",
            });
        }
        if let Some(authorization) = self.cold_authorization() {
            if self.nonce != 0 {
                return Err(IndraError::InvariantViolation {
                    message: "cold-authorized governance op outer nonce must be zero",
                });
            }
            if authorization.cold_key_version == 0 || authorization.cold_nonce == 0 {
                return Err(IndraError::InvariantViolation {
                    message: "cold authorization requires non-zero key version and nonce",
                });
            }
        }
        Ok(())
    }
}

impl Encode for GovernanceOpV2 {
    fn encode(&self, buf: &mut Vec<u8>) {
        SCHEMA_VERSION.encode(buf);
        self.action_type.encode(buf);
        self.signer_id.encode(buf);
        self.nonce.encode(buf);
        self.payload.encode(buf);
        self.signature.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        1 + self.action_type.encoded_len()
            + self.signer_id.encoded_len()
            + self.nonce.encoded_len()
            + self.payload.encoded_len()
            + self.signature.encoded_len()
    }
}

impl Decode for GovernanceOpV2 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let schema_version = u8::decode(r)?;
        if schema_version != SCHEMA_VERSION
            && schema_version != SCHEMA_VERSION_PRE_VALIDATOR_NETWORK_ADDRESS
        {
            return Err(IndraError::UnsupportedSchemaVersion {
                struct_name: "GovernanceOpV2",
                version: schema_version,
                max_supported: SCHEMA_VERSION,
            });
        }
        let action_type = GovernanceActionType::decode(r)?;
        let signer_id = Bytes32::decode(r)?;
        let nonce = u64::decode(r)?;
        let payload = GovernancePayload::decode(r)?;
        if payload.action_type() != action_type {
            return Err(IndraError::InvariantViolation {
                message: "governance payload/action type mismatch",
            });
        }
        Ok(Self {
            action_type,
            signer_id,
            nonce,
            payload,
            signature: HybridSignature::decode(r)?,
        })
    }
}

/// Compute a deterministic proposal id.
pub fn compute_proposal_id(
    proposer: Bytes32,
    action: &GovernableAction,
    proposed_epoch: u64,
    chain_id: &str,
) -> Bytes32 {
    let mut buf = Vec::new();
    proposer.encode(&mut buf);
    action.encode(&mut buf);
    proposed_epoch.encode(&mut buf);
    buf.extend_from_slice(chain_id.as_bytes());
    Bytes32::from(sha256(&buf))
}

/// Governance signing domain.
pub fn governance_signing_domain(
    action_type: GovernanceActionType,
    signer_id: Bytes32,
    nonce: u64,
    payload: &GovernancePayload,
    chain_id: &str,
) -> Vec<u8> {
    let mut buf = b"INDRA-gov-v1:".to_vec();
    buf.push(action_type as u8);
    signer_id.encode(&mut buf);
    nonce.encode(&mut buf);
    payload.encode(&mut buf);
    buf.extend_from_slice(chain_id.as_bytes());
    buf
}

/// Compute a domain-separated hidden-vote commitment.
///
/// Preimage:
/// `INDRA-gov-commit-v1:` || `proposal_id` || `validator_id` || `vote` || `nonce`
///
/// The proposal and validator binding are intentionally inside the commitment
/// hash itself, not only in the surrounding signed governance operation, so a
/// reused `(vote, nonce)` pair cannot produce the same commitment across
/// proposals or validators.
pub fn governance_vote_commit_hash(
    proposal_id: Bytes32,
    validator_id: Bytes32,
    vote: u8,
    nonce: Bytes32,
) -> Bytes32 {
    let mut buf = b"INDRA-gov-commit-v1:".to_vec();
    proposal_id.encode(&mut buf);
    validator_id.encode(&mut buf);
    vote.encode(&mut buf);
    nonce.encode(&mut buf);
    Bytes32::from(sha256(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_sig() -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
        }
    }

    fn dummy_pubkey() -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::from([1u8; 32]),
            pq_pk: VariableBytes::from_slice(&[2u8; 2592]).unwrap(),
        }
    }

    #[test]
    fn governance_op_round_trip() {
        let op = GovernanceOpV2 {
            action_type: GovernanceActionType::ProposeChange,
            signer_id: Bytes32::from([3u8; 32]),
            nonce: 1,
            payload: GovernancePayload::Propose {
                action: GovernableAction::SetSlashLivenessBps { value: 20 },
                deposit_utxo_id: Bytes32::from([4u8; 32]),
                proposer_pubkey: dummy_pubkey(),
                title: VariableBytes::from_slice(b"title").unwrap(),
                description: VariableBytes::from_slice(b"description").unwrap(),
                cold_authorization: None,
            },
            signature: dummy_sig(),
        };
        assert_eq!(
            op,
            GovernanceOpV2::decode_exact(&op.encode_to_vec()).unwrap()
        );
    }

    #[test]
    fn cold_governance_wire_round_trip_preserves_legacy_bytes() {
        let legacy = GovernancePayload::Commit {
            proposal_id: Bytes32::from([0x11; 32]),
            commit_hash: Bytes32::from([0x22; 32]),
            cold_authorization: None,
        };
        let mut expected_legacy = vec![1u8];
        expected_legacy.extend_from_slice(&[0x11; 32]);
        expected_legacy.extend_from_slice(&[0x22; 32]);
        assert_eq!(legacy.encode_to_vec(), expected_legacy);

        let cold = GovernancePayload::Commit {
            proposal_id: Bytes32::from([0x11; 32]),
            commit_hash: Bytes32::from([0x22; 32]),
            cold_authorization: Some(ColdGovernanceAuthorization {
                cold_key_version: 7,
                cold_nonce: 9,
            }),
        };
        assert_eq!(cold.encode_to_vec()[0], TAG_COLD_COMMIT);
        assert_eq!(
            GovernancePayload::decode_exact(&cold.encode_to_vec()).unwrap(),
            cold
        );
        assert_ne!(cold.encode_to_vec(), legacy.encode_to_vec());
    }

    #[test]
    fn cold_governance_envelope_binds_role_metadata_and_outer_nonce() {
        let op = GovernanceOpV2 {
            action_type: GovernanceActionType::CommitVote,
            signer_id: Bytes32::from([0x33; 32]),
            nonce: 0,
            payload: GovernancePayload::Commit {
                proposal_id: Bytes32::from([0x44; 32]),
                commit_hash: Bytes32::from([0x55; 32]),
                cold_authorization: Some(ColdGovernanceAuthorization {
                    cold_key_version: 2,
                    cold_nonce: 6,
                }),
            },
            signature: dummy_sig(),
        };
        let bytes = op
            .cold_authorization_signing_bytes("indra-testnet-1")
            .unwrap()
            .unwrap();
        let envelope = AuthorizationEnvelope::decode_exact(&bytes).unwrap();
        assert_eq!(envelope.operation_tag(), AUTH_TAG_COLD_COMMIT);
        assert_eq!(envelope.identity_id(), op.signer_id);
        assert_eq!(envelope.authority_key_version(), 2);
        assert_eq!(envelope.role_nonce(), 6);

        let mut malformed = op.clone();
        malformed.nonce = 1;
        assert!(malformed
            .cold_authorization_signing_bytes("indra-testnet-1")
            .is_err());
    }

    #[test]
    fn commit_hash_includes_proposal_and_validator_binding() {
        let vote = 1;
        let nonce = Bytes32::from([0xAA; 32]);
        let proposal_a = Bytes32::from([0x11; 32]);
        let proposal_b = Bytes32::from([0x22; 32]);
        let validator_a = Bytes32::from([0x33; 32]);
        let validator_b = Bytes32::from([0x44; 32]);

        let base = governance_vote_commit_hash(proposal_a, validator_a, vote, nonce);

        assert_ne!(
            base,
            governance_vote_commit_hash(proposal_b, validator_a, vote, nonce),
            "same vote/nonce must not collide across proposals"
        );
        assert_ne!(
            base,
            governance_vote_commit_hash(proposal_a, validator_b, vote, nonce),
            "same vote/nonce must not collide across validators"
        );
    }
}
