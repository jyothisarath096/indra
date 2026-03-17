//! Governance operation types.

use crate::{
    codec::{Encode, Decode, ByteReader},
    error::{IndraError, IndraResult},
    types::primitives::{Bytes32, VariableBytes, MAX_GOV_PAYLOAD_BYTES},
};

/// Governance action discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GovernanceActionType {
    /// Submit a new proposal.
    ProposeChange   = 0,
    /// Vote on an existing proposal.
    CastVote        = 1,
    /// Execute an approved proposal after the delay period.
    ExecuteProposal = 2,
}

impl Encode for GovernanceActionType {
    fn encode(&self, buf: &mut Vec<u8>) { buf.push(*self as u8); }
    fn encoded_len(&self) -> usize { 1 }
}

impl Decode for GovernanceActionType {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        match r.read_u8()? {
            0 => Ok(Self::ProposeChange),
            1 => Ok(Self::CastVote),
            2 => Ok(Self::ExecuteProposal),
            b => Err(IndraError::InvalidBool { byte: b }),
        }
    }
}

/// A governance operation included in a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceOpV1 {
    /// Proposal identifier (SHA-256 of proposal content).
    pub proposal_id: Bytes32,
    /// Type of action.
    pub action_type: GovernanceActionType,
    /// Action-specific payload (max 4 KB).
    pub payload:     VariableBytes<MAX_GOV_PAYLOAD_BYTES>,
}

impl Encode for GovernanceOpV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.proposal_id.encode(buf);
        self.action_type.encode(buf);
        self.payload.encode(buf);
    }
    fn encoded_len(&self) -> usize { 32 + 1 + self.payload.encoded_len() }
}

impl Decode for GovernanceOpV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            proposal_id: Bytes32::decode(r)?,
            action_type: GovernanceActionType::decode(r)?,
            payload:     VariableBytes::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Decode;

    #[test]
    fn governance_op_round_trip() {
        let op = GovernanceOpV1 {
            proposal_id: Bytes32::from([0xDEu8; 32]),
            action_type: GovernanceActionType::CastVote,
            payload:     VariableBytes::from_slice(b"YES").unwrap(),
        };
        assert_eq!(op, GovernanceOpV1::decode_exact(&op.encode_to_vec()).unwrap());
    }
}
