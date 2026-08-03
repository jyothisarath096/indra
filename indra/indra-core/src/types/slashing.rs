//! Slash evidence types.

use crate::{
    codec::{ByteReader, Decode, Encode},
    error::IndraResult,
    types::{primitives::Bytes32, slash_membership::SlashMembershipProofV1, vote::VoteV1},
};

/// Evidence of a slashable offence: two conflicting votes from the same validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashEvidenceV1 {
    /// Validator who committed the offence.
    pub validator_id: Bytes32,
    /// First conflicting vote.
    pub vote_1: VoteV1,
    /// Second conflicting vote (same height, either different block or surround lock).
    pub vote_2: VoteV1,
}

impl Encode for SlashEvidenceV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.validator_id.encode(buf);
        self.vote_1.encode(buf);
        self.vote_2.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        32 + self.vote_1.encoded_len() + self.vote_2.encoded_len()
    }
}

impl Decode for SlashEvidenceV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            validator_id: Bytes32::decode(r)?,
            vote_1: VoteV1::decode(r)?,
            vote_2: VoteV1::decode(r)?,
        })
    }
}

/// Proof-carrying evidence for an infraction governed by membership roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashEvidenceV2 {
    /// Validator who committed the offence.
    pub validator_id: Bytes32,
    /// First conflicting vote.
    pub vote_1: VoteV1,
    /// Second conflicting vote.
    pub vote_2: VoteV1,
    /// Proof of historical consensus membership and vote keys.
    pub membership_proof: SlashMembershipProofV1,
}

impl Encode for SlashEvidenceV2 {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.validator_id.encode(buf);
        self.vote_1.encode(buf);
        self.vote_2.encode(buf);
        self.membership_proof.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        32 + self.vote_1.encoded_len()
            + self.vote_2.encoded_len()
            + self.membership_proof.encoded_len()
    }
}

impl Decode for SlashEvidenceV2 {
    fn decode(reader: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            validator_id: Bytes32::decode(reader)?,
            vote_1: VoteV1::decode(reader)?,
            vote_2: VoteV1::decode(reader)?,
            membership_proof: SlashMembershipProofV1::decode(reader)?,
        })
    }
}
