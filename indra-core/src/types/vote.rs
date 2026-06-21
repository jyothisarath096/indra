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
    /// Stable value hash being voted for.
    ///
    /// The field name remains `block_hash` for wire compatibility, but the
    /// payload now carries `BlockHeaderV1::value_hash` rather than the full
    /// per-round proposal hash.
    pub block_hash: Bytes32,
    /// Validator's identity.
    pub validator_id: Bytes32,
    /// Hybrid signature over (height || round || step || value_hash || validator_id).
    pub signature: HybridSignature,
}

impl Encode for VoteV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.height.encode(buf);
        self.round.encode(buf);
        self.step.encode(buf);
        self.block_hash.encode(buf);
        self.validator_id.encode(buf);
        self.signature.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        8 + 4 + 1 + 32 + 32 + self.signature.encoded_len()
    }
}

impl Decode for VoteV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            height: u64::decode(r)?,
            round: u32::decode(r)?,
            step: VoteStep::decode(r)?,
            block_hash: Bytes32::decode(r)?,
            validator_id: Bytes32::decode(r)?,
            signature: HybridSignature::decode(r)?,
        })
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
