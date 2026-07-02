//! Vote type — the fundamental consensus message.

use crate::{
    codec::{ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    types::{crypto::HybridSignature, primitives::Bytes32},
};

/// Which consensus phase this vote belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VoteStep {
    /// Prevote phase.
    Prevote = 0,
    /// Precommit phase.
    Precommit = 1,
}

impl Encode for VoteStep {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(*self as u8);
    }
    fn encoded_len(&self) -> usize {
        1
    }
}

impl Decode for VoteStep {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        match r.read_u8()? {
            0 => Ok(VoteStep::Prevote),
            1 => Ok(VoteStep::Precommit),
            b => Err(IndraError::InvalidBool { byte: b }),
        }
    }
}

/// A validator's vote for a block.
///
/// Both hybrid signature components must verify.
/// validator_id = SHA-256(hybrid_public_key_bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteV1 {
    /// Chain height this vote applies to.
    pub height: u64,
    /// Round within the height.
    pub round: u32,
    /// Prevote or Precommit.
    pub step: VoteStep,
    /// Full block hash being voted for.
    pub block_hash: Bytes32,
    /// Validator's identity.
    pub validator_id: Bytes32,
    /// Hash of the commit-reveal election result observed by this validator.
    ///
    /// Present on precommit votes when commit-reveal proposer election is active.
    /// Absent on prevotes and pre-activation votes.
    pub election_result_hash: Option<Bytes32>,
    /// Hybrid signature over the canonical vote signing bytes.
    pub signature: HybridSignature,
}

impl Encode for VoteV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.height.encode(buf);
        self.round.encode(buf);
        self.step.encode(buf);
        self.block_hash.encode(buf);
        self.validator_id.encode(buf);
        if let Some(hash) = self.election_result_hash {
            1u8.encode(buf);
            hash.encode(buf);
        } else {
            0u8.encode(buf);
        }
        self.signature.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        8 + 4
            + 1
            + 32
            + 32
            + 1
            + self.election_result_hash.map(|_| 32).unwrap_or(0)
            + self.signature.encoded_len()
    }
}

impl Decode for VoteV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let height = u64::decode(r)?;
        let round = u32::decode(r)?;
        let step = VoteStep::decode(r)?;
        let block_hash = Bytes32::decode(r)?;
        let validator_id = Bytes32::decode(r)?;
        let flag = u8::decode(r)?;
        let election_result_hash = match flag {
            0 => None,
            1 => Some(Bytes32::decode(r)?),
            b => return Err(IndraError::InvalidBool { byte: b }),
        };
        Ok(Self {
            height,
            round,
            step,
            block_hash,
            validator_id,
            election_result_hash,
            signature: HybridSignature::decode(r)?,
        })
    }
}

impl VoteV1 {
    /// Construct a vote from the legacy pre-commit-reveal wire shape.
    ///
    /// This is only used by tests/tooling that deliberately decode old fixtures;
    /// the active encoder always writes the explicit election-result flag.
    pub fn legacy_without_election_result(
        height: u64,
        round: u32,
        step: VoteStep,
        block_hash: Bytes32,
        validator_id: Bytes32,
        signature: HybridSignature,
    ) -> Self {
        Self {
            height,
            round,
            step,
            block_hash,
            validator_id,
            election_result_hash: None,
            signature,
        }
    }
}

impl VoteV1 {
    /// True when this vote is a Tendermint nil vote.
    pub fn is_nil(&self) -> bool {
        self.block_hash == Bytes32::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Decode;
    use crate::types::primitives::VariableBytes;

    fn dummy_vote() -> VoteV1 {
        VoteV1 {
            height: 42_000,
            round: 1,
            step: VoteStep::Precommit,
            block_hash: Bytes32::from([0xAAu8; 32]),
            validator_id: Bytes32::from([0xBBu8; 32]),
            election_result_hash: Some(Bytes32::from([0xCCu8; 32])),
            signature: HybridSignature {
                classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
            },
        }
    }

    #[test]
    fn vote_round_trip() {
        let v = dummy_vote();
        assert_eq!(v, VoteV1::decode_exact(&v.encode_to_vec()).unwrap());
    }

    #[test]
    fn vote_step_encoding() {
        assert_eq!(VoteStep::Prevote.encode_to_vec(), vec![0x00]);
        assert_eq!(VoteStep::Precommit.encode_to_vec(), vec![0x01]);
    }

    #[test]
    fn invalid_step_byte_rejected() {
        let bad = [0x02u8];
        let mut r = crate::codec::ByteReader::new(&bad);
        assert!(VoteStep::decode(&mut r).is_err());
    }
}
