//! Weak subjectivity checkpoint.
//!
//! Required when syncing after a gap > WS_WINDOW epochs.
//! Must carry hybrid signatures representing ≥ 2/3 stake.

use crate::{
    codec::{Encode, Decode, ByteReader, encode_list, decode_list, list_encoded_len},
    error::IndraResult,
    types::{
        primitives::{Bytes32, MAX_VALIDATORS},
        crypto::HybridSignature,
    },
};

/// One validator's signature on a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointSig {
    /// Validator ID.
    pub validator_id: Bytes32,
    /// Hybrid signature over the checkpoint content hash.
    pub signature:    HybridSignature,
}

impl Encode for CheckpointSig {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.validator_id.encode(buf);
        self.signature.encode(buf);
    }
    fn encoded_len(&self) -> usize { 32 + self.signature.encoded_len() }
}

impl Decode for CheckpointSig {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self { validator_id: Bytes32::decode(r)?, signature: HybridSignature::decode(r)? })
    }
}

/// A weak subjectivity checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointV1 {
    /// Height at which this checkpoint was taken.
    pub height:             u64,
    /// Finalised block hash at this height.
    pub block_hash:         Bytes32,
    /// State trie root at this height.
    pub state_root:         Bytes32,
    /// Validator set root at this height.
    pub validator_set_root: Bytes32,
    /// Hybrid signatures from validators representing ≥ 2/3 stake.
    pub signatures:         Vec<CheckpointSig>,
}

impl Encode for CheckpointV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.height.encode(buf);
        self.block_hash.encode(buf);
        self.state_root.encode(buf);
        self.validator_set_root.encode(buf);
        encode_list(&self.signatures, buf);
    }
    fn encoded_len(&self) -> usize {
        8 + 32 + 32 + 32 + list_encoded_len(&self.signatures)
    }
}

impl Decode for CheckpointV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            height:             u64::decode(r)?,
            block_hash:         Bytes32::decode(r)?,
            state_root:         Bytes32::decode(r)?,
            validator_set_root: Bytes32::decode(r)?,
            signatures:         decode_list(r, MAX_VALIDATORS, "checkpoint_sigs")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Decode;

    #[test]
    fn empty_checkpoint_round_trip() {
        let cp = CheckpointV1 {
            height:             100_000,
            block_hash:         Bytes32::from([0xFFu8; 32]),
            state_root:         Bytes32::from([0xEEu8; 32]),
            validator_set_root: Bytes32::from([0xDDu8; 32]),
            signatures:         vec![],
        };
        assert_eq!(cp, CheckpointV1::decode_exact(&cp.encode_to_vec()).unwrap());
    }
}
