//! Block and block header.

use crate::{
    codec::{Encode, Decode, ByteReader, encode_list, decode_list, list_encoded_len},
    error::IndraResult,
    types::{
        primitives::{
            Bytes32, ProtocolVersion, VariableBytes,
            MAX_TX_PER_BLOCK, MAX_SLASHES_PER_BLOCK, MAX_GOV_OPS_PER_BLOCK,
            MAX_VRF_PROOF_BYTES, MAX_QC_SIZE_BYTES,
        },
        governance::GovernanceOpV1,
        slashing::SlashEvidenceV1,
        transaction::TransactionV1,
    },
    ssz::sha256,
};

/// INDRA v1 block header.
///
/// block_hash = SHA-256(encode(BlockHeaderV1))
/// Field order is fixed and canonical. Any reordering is a consensus break.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeaderV1 {
    /// Must equal PROTOCOL_VERSION.
    pub protocol_version:    ProtocolVersion,
    /// Block height (starts at 1, monotonically increasing).
    pub height:              u64,
    /// Hash of the previous block header.
    pub prev_hash:           Bytes32,
    /// Unix timestamp in seconds. Informational only.
    pub timestamp:           u64,
    /// State trie root after applying this block.
    pub state_root:          Bytes32,
    /// Validator set hash tree root.
    pub validator_set_root:  Bytes32,
    /// Mempool commitment root.
    pub mempool_set_root:    Bytes32,
    /// Current base fee in Spark/KB (updated each block via EIP-1559 formula).
    pub base_fee:            u64,
    /// Proposer's VRF output (32 bytes).
    pub proposer_vrf_output: Bytes32,
    /// Proposer's VRF proof.
    pub proposer_vrf_proof:  VariableBytes<MAX_VRF_PROOF_BYTES>,
    /// Quorum certificate for the PREVIOUS block (proving it was finalised).
    pub quorum_certificate:  VariableBytes<MAX_QC_SIZE_BYTES>,
}

impl BlockHeaderV1 {
    /// Compute the block hash as SHA-256 of the canonical encoding.
    pub fn block_hash(&self) -> Bytes32 {
        Bytes32::from(sha256(&self.encode_to_vec()))
    }
}

impl Encode for BlockHeaderV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.protocol_version.encode(buf);
        self.height.encode(buf);
        self.prev_hash.encode(buf);
        self.timestamp.encode(buf);
        self.state_root.encode(buf);
        self.validator_set_root.encode(buf);
        self.mempool_set_root.encode(buf);
        self.base_fee.encode(buf);
        self.proposer_vrf_output.encode(buf);
        self.proposer_vrf_proof.encode(buf);
        self.quorum_certificate.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        2 + 8 + 32 + 8 + 32 + 32 + 32 + 8 + 32
            + self.proposer_vrf_proof.encoded_len()
            + self.quorum_certificate.encoded_len()
    }
}

impl Decode for BlockHeaderV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            protocol_version:    ProtocolVersion::decode(r)?,
            height:              u64::decode(r)?,
            prev_hash:           Bytes32::decode(r)?,
            timestamp:           u64::decode(r)?,
            state_root:          Bytes32::decode(r)?,
            validator_set_root:  Bytes32::decode(r)?,
            mempool_set_root:    Bytes32::decode(r)?,
            base_fee:            u64::decode(r)?,
            proposer_vrf_output: Bytes32::decode(r)?,
            proposer_vrf_proof:  VariableBytes::decode(r)?,
            quorum_certificate:  VariableBytes::decode(r)?,
        })
    }
}

/// A complete INDRA v1 block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockV1 {
    /// Block header.
    pub header:            BlockHeaderV1,
    /// Transactions (0–200).
    pub transactions:      Vec<TransactionV1>,
    /// Slash evidence (0–10).
    pub slashing_evidence: Vec<SlashEvidenceV1>,
    /// Governance operations (0–5).
    pub governance_ops:    Vec<GovernanceOpV1>,
}

impl Encode for BlockV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.header.encode(buf);
        encode_list(&self.transactions, buf);
        encode_list(&self.slashing_evidence, buf);
        encode_list(&self.governance_ops, buf);
    }
    fn encoded_len(&self) -> usize {
        self.header.encoded_len()
            + list_encoded_len(&self.transactions)
            + list_encoded_len(&self.slashing_evidence)
            + list_encoded_len(&self.governance_ops)
    }
}

impl Decode for BlockV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            header:            BlockHeaderV1::decode(r)?,
            transactions:      decode_list(r, MAX_TX_PER_BLOCK, "transactions")?,
            slashing_evidence: decode_list(r, MAX_SLASHES_PER_BLOCK, "slashing_evidence")?,
            governance_ops:    decode_list(r, MAX_GOV_OPS_PER_BLOCK, "governance_ops")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Decode;

    fn dummy_header() -> BlockHeaderV1 {
        BlockHeaderV1 {
            protocol_version:    ProtocolVersion::CURRENT,
            height:              1,
            prev_hash:           Bytes32::ZERO,
            timestamp:           1_700_000_000,
            state_root:          Bytes32::from([0x11u8; 32]),
            validator_set_root:  Bytes32::from([0x22u8; 32]),
            mempool_set_root:    Bytes32::from([0x33u8; 32]),
            base_fee:            100,
            proposer_vrf_output: Bytes32::from([0x44u8; 32]),
            proposer_vrf_proof:  VariableBytes::from_slice(&[0xAAu8; 80]).unwrap(),
            quorum_certificate:  VariableBytes::from_slice(&[0xBBu8; 256]).unwrap(),
        }
    }

    #[test]
    fn header_round_trip() {
        let h = dummy_header();
        assert_eq!(h, BlockHeaderV1::decode_exact(&h.encode_to_vec()).unwrap());
    }

    #[test]
    fn block_hash_is_deterministic() {
        let h = dummy_header();
        assert_eq!(h.block_hash(), h.block_hash());
    }

    #[test]
    fn block_hash_changes_with_height() {
        let mut h1 = dummy_header();
        let mut h2 = dummy_header();
        h1.height = 1;
        h2.height = 2;
        assert_ne!(h1.block_hash(), h2.block_hash());
    }

    #[test]
    fn empty_block_round_trip() {
        let b = BlockV1 {
            header: dummy_header(),
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
        };
        assert_eq!(b, BlockV1::decode_exact(&b.encode_to_vec()).unwrap());
    }
}
