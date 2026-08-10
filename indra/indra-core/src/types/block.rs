//! Block and block header.

use crate::{
    codec::{decode_list, encode_list, list_encoded_len, ByteReader, Decode, Encode},
    error::IndraResult,
    ssz::sha256,
    types::{
        governance::GovernanceOpV2,
        primitives::{
            Bytes32, ProtocolVersion, VariableBytes, BLOCK_FORMAT_VERSION, MAX_ACTIVE_VALIDATORS,
            MAX_GOV_OPS_PER_BLOCK, MAX_QC_SIZE_BYTES, MAX_SLASHES_PER_BLOCK,
            MAX_STAKING_OPS_PER_BLOCK, MAX_TX_PER_BLOCK, MAX_VRF_PROOF_BYTES,
        },
        slashing::SlashEvidenceV2,
        staking::StakingOp,
        transaction::TransactionV1,
        vrf_election::VrfRevealEvidence,
    },
};

/// Sentinel value meaning a proposal did not carry a prior PoLC round.
pub const NO_POLC_ROUND: u32 = u32::MAX;

/// Canonical INDRA block header.
///
/// `block_hash` is SHA-256 over the complete canonical header encoding. Votes,
/// QCs, chain links, and durable manifests all use this exact identity, so it
/// binds every serialized consensus field, including `value_hash` and
/// round-specific proposal metadata.
///
/// `value_hash` is the separately verified, round-stable content identity used
/// only to recognize a value across reproposals. It is not a substitute for
/// the full block hash certified by votes and QCs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeaderV1 {
    /// Must equal [`BLOCK_FORMAT_VERSION`].
    pub protocol_version: ProtocolVersion,
    /// Block height (starts at 1, monotonically increasing).
    pub height: u64,
    /// Hash of the previous block header.
    pub prev_hash: Bytes32,
    /// Unix timestamp in seconds. Informational only.
    pub timestamp: u64,
    /// State trie root after applying this block.
    pub state_root: Bytes32,
    /// Validator set hash tree root.
    pub validator_set_root: Bytes32,
    /// Mempool commitment root.
    pub mempool_set_root: Bytes32,
    /// Stable consensus value hash shared across rounds for the same block content.
    pub value_hash: Bytes32,
    /// Current base fee in Spark/KB (updated each block via EIP-1559 formula).
    pub base_fee: u64,
    /// Consensus round in which this block was proposed.
    pub proposer_round: u32,
    /// Round whose prevote quorum justified re-proposing this value.
    ///
    /// `NO_POLC_ROUND` means no prior PoLC was attached.
    pub polc_round: u32,
    /// Proposer's VRF output (32 bytes).
    pub proposer_vrf_output: Bytes32,
    /// Proposer's VRF proof.
    pub proposer_vrf_proof: VariableBytes<MAX_VRF_PROOF_BYTES>,
    /// Quorum certificate for the PREVIOUS block (proving it was finalised).
    pub quorum_certificate: VariableBytes<MAX_QC_SIZE_BYTES>,
    /// Hash of the commit-reveal VRF election result for this proposal.
    ///
    /// Present when commit-reveal proposer election is active. Because
    /// `block_hash()` hashes the canonical header encoding, QCs over the block
    /// hash also certify this election result hash.
    pub election_result_hash: Option<Bytes32>,
}

impl BlockHeaderV1 {
    /// Compute the canonical full-header block hash.
    pub fn block_hash(&self) -> Bytes32 {
        Bytes32::from(sha256(&self.encode_to_vec()))
    }

    /// Compute the stable consensus value hash for a block.
    pub fn compute_value_hash(
        height: u64,
        prev_hash: Bytes32,
        timestamp: u64,
        state_root: Bytes32,
        validator_set_root: Bytes32,
        mempool_set_root: Bytes32,
        base_fee: u64,
        total_supply: u64,
    ) -> Bytes32 {
        let mut buf = Vec::with_capacity(8 + 32 + 8 + 32 + 32 + 32 + 8 + 8);
        height.encode(&mut buf);
        prev_hash.encode(&mut buf);
        timestamp.encode(&mut buf);
        state_root.encode(&mut buf);
        validator_set_root.encode(&mut buf);
        mempool_set_root.encode(&mut buf);
        base_fee.encode(&mut buf);
        total_supply.encode(&mut buf);
        Bytes32::from(sha256(&buf))
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
        self.proposer_round.encode(buf);
        self.proposer_vrf_output.encode(buf);
        self.proposer_vrf_proof.encode(buf);
        self.quorum_certificate.encode(buf);
        self.polc_round.encode(buf);
        self.value_hash.encode(buf);
        if let Some(hash) = self.election_result_hash {
            1u8.encode(buf);
            hash.encode(buf);
        } else {
            0u8.encode(buf);
        }
    }
    fn encoded_len(&self) -> usize {
        2 + 8
            + 32
            + 8
            + 32
            + 32
            + 32
            + 32
            + 8
            + 4
            + 4
            + 32
            + self.proposer_vrf_proof.encoded_len()
            + self.quorum_certificate.encoded_len()
            + 1
            + self.election_result_hash.map(|_| 32).unwrap_or(0)
    }
}

impl Decode for BlockHeaderV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let protocol_version = ProtocolVersion::decode(r)?;
        if protocol_version.0 != BLOCK_FORMAT_VERSION {
            return Err(crate::error::IndraError::UnsupportedVersion {
                version: protocol_version.0,
            });
        }
        Ok(Self {
            protocol_version,
            height: u64::decode(r)?,
            prev_hash: Bytes32::decode(r)?,
            timestamp: u64::decode(r)?,
            state_root: Bytes32::decode(r)?,
            validator_set_root: Bytes32::decode(r)?,
            mempool_set_root: Bytes32::decode(r)?,
            base_fee: u64::decode(r)?,
            proposer_round: u32::decode(r)?,
            proposer_vrf_output: Bytes32::decode(r)?,
            proposer_vrf_proof: VariableBytes::decode(r)?,
            quorum_certificate: VariableBytes::decode(r)?,
            polc_round: u32::decode(r).unwrap_or(NO_POLC_ROUND),
            value_hash: Bytes32::decode(r).unwrap_or(Bytes32::ZERO),
            election_result_hash: match u8::decode(r) {
                Ok(0) => None,
                Ok(1) => Some(Bytes32::decode(r)?),
                Ok(b) => return Err(crate::error::IndraError::InvalidBool { byte: b }),
                Err(_) => None,
            },
        })
    }
}

/// A complete INDRA v1 block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockV1 {
    /// Block header.
    pub header: BlockHeaderV1,
    /// Transactions (0–200).
    pub transactions: Vec<TransactionV1>,
    /// Membership-proven slash evidence (0–3).
    pub slashing_evidence: Vec<SlashEvidenceV2>,
    /// Governance operations (0–5).
    pub governance_ops: Vec<GovernanceOpV2>,
    /// Staking operations (0–10).
    pub staking_ops: Vec<StakingOp>,
    /// Full VRF reveal evidence used to compute the commit-reveal election result.
    ///
    /// Always encoded, even when empty. Retention follows ordinary block-body
    /// retention: pruned validators keep
    /// it for their configured block window, while archive nodes keep it for
    /// full history.
    pub vrf_reveals: Vec<VrfRevealEvidence>,
}

impl Encode for BlockV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.header.encode(buf);
        encode_list(&self.transactions, buf);
        encode_list(&self.slashing_evidence, buf);
        encode_list(&self.governance_ops, buf);
        encode_list(&self.staking_ops, buf);
        encode_list(&self.vrf_reveals, buf);
    }
    fn encoded_len(&self) -> usize {
        self.header.encoded_len()
            + list_encoded_len(&self.transactions)
            + list_encoded_len(&self.slashing_evidence)
            + list_encoded_len(&self.governance_ops)
            + list_encoded_len(&self.staking_ops)
            + list_encoded_len(&self.vrf_reveals)
    }
}

impl Decode for BlockV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let header = BlockHeaderV1::decode(r)?;
        let transactions = decode_list(r, MAX_TX_PER_BLOCK, "transactions")?;
        let slashing_evidence = decode_list(r, MAX_SLASHES_PER_BLOCK, "slashing_evidence")?;
        Ok(Self {
            header,
            transactions,
            slashing_evidence,
            governance_ops: decode_list(r, MAX_GOV_OPS_PER_BLOCK, "governance_ops")?,
            staking_ops: decode_list(r, MAX_STAKING_OPS_PER_BLOCK, "staking_ops")?,
            vrf_reveals: decode_list(r, MAX_ACTIVE_VALIDATORS, "vrf_reveals")?,
        })
    }
}

impl BlockV1 {
    /// Recompute this block's stable consensus value hash from its stable
    /// content fields and projected post-state total supply.
    pub fn compute_value_hash(&self, total_supply: u64) -> Bytes32 {
        BlockHeaderV1::compute_value_hash(
            self.header.height,
            self.header.prev_hash,
            self.header.timestamp,
            self.header.state_root,
            self.header.validator_set_root,
            self.header.mempool_set_root,
            self.header.base_fee,
            total_supply,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Decode;

    fn dummy_header() -> BlockHeaderV1 {
        BlockHeaderV1 {
            protocol_version: ProtocolVersion::CURRENT,
            height: 1,
            prev_hash: Bytes32::ZERO,
            timestamp: 1_700_000_000,
            state_root: Bytes32::from([0x11u8; 32]),
            validator_set_root: Bytes32::from([0x22u8; 32]),
            mempool_set_root: Bytes32::from([0x33u8; 32]),
            value_hash: Bytes32::from([0x34u8; 32]),
            base_fee: 100,
            proposer_round: 0,
            polc_round: NO_POLC_ROUND,
            proposer_vrf_output: Bytes32::from([0x44u8; 32]),
            proposer_vrf_proof: VariableBytes::from_slice(&[0xAAu8; 80]).unwrap(),
            quorum_certificate: VariableBytes::from_slice(&[0xBBu8; 256]).unwrap(),
            election_result_hash: Some(Bytes32::from([0xCCu8; 32])),
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
    fn value_hash_is_stable_across_round_metadata_changes() {
        let h = dummy_header();
        let base = BlockHeaderV1::compute_value_hash(
            h.height,
            h.prev_hash,
            h.timestamp,
            h.state_root,
            h.validator_set_root,
            h.mempool_set_root,
            h.base_fee,
            123,
        );

        let mut changed = h.clone();
        changed.proposer_round = 7;
        changed.polc_round = 3;
        changed.proposer_vrf_output = Bytes32::from([0x55u8; 32]);

        let changed_hash = BlockHeaderV1::compute_value_hash(
            changed.height,
            changed.prev_hash,
            changed.timestamp,
            changed.state_root,
            changed.validator_set_root,
            changed.mempool_set_root,
            changed.base_fee,
            123,
        );

        assert_eq!(base, changed_hash);
    }

    #[test]
    fn empty_block_round_trip() {
        let b = BlockV1 {
            header: dummy_header(),
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            vrf_reveals: vec![],
        };
        assert_eq!(b, BlockV1::decode_exact(&b.encode_to_vec()).unwrap());
    }
}
