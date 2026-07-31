//! Block and block header.

use crate::{
    codec::{decode_list, encode_list, list_encoded_len, ByteReader, Decode, Encode},
    error::IndraResult,
    ssz::sha256,
    types::{
        governance::GovernanceOpV2,
        primitives::{
            Bytes32, ProtocolVersion, VariableBytes, BLOCK_PROTOCOL_VERSION_REVEAL_SET,
            MAX_ACTIVE_VALIDATORS, MAX_GOV_OPS_PER_BLOCK, MAX_QC_SIZE_BYTES, MAX_SLASHES_PER_BLOCK,
            MAX_STAKING_OPS_PER_BLOCK, MAX_TX_PER_BLOCK, MAX_VRF_PROOF_BYTES,
        },
        slashing::SlashEvidenceV1,
        staking::StakingOp,
        transaction::TransactionV1,
        vrf_election::VrfRevealEvidence,
    },
};

/// Sentinel value meaning a proposal did not carry a prior PoLC round.
pub const NO_POLC_ROUND: u32 = u32::MAX;

/// INDRA v1 block header.
///
/// `block_hash` is the SHA-256 of the canonical on-disk/on-wire header
/// encoding. That byte order is consensus-critical and must remain bit-for-bit
/// compatible with the historical `57398f5` chain data: protocol_version,
/// height, prev_hash, timestamp, state_root, validator_set_root,
/// mempool_set_root, base_fee, proposer_round, proposer_vrf_output,
/// proposer_vrf_proof, quorum_certificate, polc_round, value_hash.
///
/// `value_hash` is a separate consensus-layer identity that is stable across
/// rounds for the same block content, but it is still serialized inside the
/// header and therefore contributes to `block_hash()` for backwards
/// compatibility with the existing chain. Changing that relationship would
/// require a protocol-versioned hard fork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeaderV1 {
    /// Must equal PROTOCOL_VERSION.
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
    /// Compute the canonical block hash from the historical header encoding.
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
        Ok(Self {
            protocol_version: ProtocolVersion::decode(r)?,
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
    /// Slash evidence (0–10).
    pub slashing_evidence: Vec<SlashEvidenceV1>,
    /// Governance operations (0–5).
    pub governance_ops: Vec<GovernanceOpV2>,
    /// Staking operations (0–10).
    pub staking_ops: Vec<StakingOp>,
    /// Full VRF reveal evidence used to compute the commit-reveal election result.
    ///
    /// Present at/after REVEAL_SET_COMMITMENT_HEIGHT via block protocol version
    /// 2. Retention follows ordinary block-body retention: pruned validators keep
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
        if self.header.protocol_version.0 >= BLOCK_PROTOCOL_VERSION_REVEAL_SET {
            encode_list(&self.vrf_reveals, buf);
        }
    }
    fn encoded_len(&self) -> usize {
        self.header.encoded_len()
            + list_encoded_len(&self.transactions)
            + list_encoded_len(&self.slashing_evidence)
            + list_encoded_len(&self.governance_ops)
            + list_encoded_len(&self.staking_ops)
            + if self.header.protocol_version.0 >= BLOCK_PROTOCOL_VERSION_REVEAL_SET {
                list_encoded_len(&self.vrf_reveals)
            } else {
                0
            }
    }
}

impl Decode for BlockV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let header = BlockHeaderV1::decode(r)?;
        let use_reveal_set_body = header.protocol_version.0 >= BLOCK_PROTOCOL_VERSION_REVEAL_SET;
        Ok(Self {
            header,
            transactions: decode_list(r, MAX_TX_PER_BLOCK, "transactions")?,
            slashing_evidence: decode_list(r, MAX_SLASHES_PER_BLOCK, "slashing_evidence")?,
            governance_ops: decode_list(r, MAX_GOV_OPS_PER_BLOCK, "governance_ops")?,
            staking_ops: decode_list(r, MAX_STAKING_OPS_PER_BLOCK, "staking_ops")?,
            vrf_reveals: if use_reveal_set_body {
                decode_list(r, MAX_ACTIVE_VALIDATORS, "vrf_reveals")?
            } else {
                Vec::new()
            },
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
    use crate::types::primitives::{
        BLOCK_PROTOCOL_VERSION_CONSENSUS_SNAPSHOT,
        BLOCK_PROTOCOL_VERSION_DELEGATOR_BOND_ACCOUNTING,
        BLOCK_PROTOCOL_VERSION_EPOCH_TRANSITION_CONTEXT,
        BLOCK_PROTOCOL_VERSION_LIVE_BOND_COUNT_CAP, BLOCK_PROTOCOL_VERSION_SELF_UNSTAKE_HEIGHT,
    };

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
    fn old_header_encoding_without_value_hash_and_polc_still_decodes() {
        let h = dummy_header();
        let mut legacy = Vec::new();
        h.protocol_version.encode(&mut legacy);
        h.height.encode(&mut legacy);
        h.prev_hash.encode(&mut legacy);
        h.timestamp.encode(&mut legacy);
        h.state_root.encode(&mut legacy);
        h.validator_set_root.encode(&mut legacy);
        h.mempool_set_root.encode(&mut legacy);
        h.base_fee.encode(&mut legacy);
        h.proposer_round.encode(&mut legacy);
        h.proposer_vrf_output.encode(&mut legacy);
        h.proposer_vrf_proof.encode(&mut legacy);
        h.quorum_certificate.encode(&mut legacy);

        let decoded = BlockHeaderV1::decode_exact(&legacy).unwrap();
        assert_eq!(decoded.protocol_version, h.protocol_version);
        assert_eq!(decoded.height, h.height);
        assert_eq!(decoded.prev_hash, h.prev_hash);
        assert_eq!(decoded.timestamp, h.timestamp);
        assert_eq!(decoded.state_root, h.state_root);
        assert_eq!(decoded.validator_set_root, h.validator_set_root);
        assert_eq!(decoded.mempool_set_root, h.mempool_set_root);
        assert_eq!(decoded.value_hash, Bytes32::ZERO);
        assert_eq!(decoded.base_fee, h.base_fee);
        assert_eq!(decoded.proposer_round, h.proposer_round);
        assert_eq!(decoded.proposer_vrf_output, h.proposer_vrf_output);
        assert_eq!(decoded.proposer_vrf_proof, h.proposer_vrf_proof);
        assert_eq!(decoded.quorum_certificate, h.quorum_certificate);
        assert_eq!(decoded.polc_round, NO_POLC_ROUND);
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

    #[test]
    fn old_binary_decode_rejects_post_activation_block() {
        let mut h = dummy_header();
        h.protocol_version = ProtocolVersion(BLOCK_PROTOCOL_VERSION_REVEAL_SET);
        let legacy_body = BlockV1 {
            header: h.clone(),
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            vrf_reveals: vec![],
        };
        let mut bytes = Vec::new();
        h.encode(&mut bytes);
        encode_list(&legacy_body.transactions, &mut bytes);
        encode_list(&legacy_body.slashing_evidence, &mut bytes);
        encode_list(&legacy_body.governance_ops, &mut bytes);
        encode_list(&legacy_body.staking_ops, &mut bytes);

        assert!(
            BlockV1::decode_exact(&bytes).is_err(),
            "post-activation block protocol version must not decode without the reveal evidence body field"
        );
    }

    #[test]
    fn reveal_only_binary_rejects_consensus_snapshot_version_at_header_decode() {
        fn decode_as_reveal_only_binary(bytes: &[u8]) -> crate::error::IndraResult<()> {
            let mut reader = ByteReader::new(bytes);
            let version = reader.read_u16_le()?;
            if version != crate::types::primitives::PROTOCOL_VERSION
                && version != BLOCK_PROTOCOL_VERSION_REVEAL_SET
            {
                return Err(crate::error::IndraError::UnsupportedVersion { version });
            }
            Ok(())
        }

        let mut header = dummy_header();
        header.protocol_version = ProtocolVersion(BLOCK_PROTOCOL_VERSION_CONSENSUS_SNAPSHOT);
        let bytes = header.encode_to_vec();

        assert_eq!(
            decode_as_reveal_only_binary(&bytes),
            Err(crate::error::IndraError::UnsupportedVersion {
                version: BLOCK_PROTOCOL_VERSION_CONSENSUS_SNAPSHOT,
            }),
            "the pre-snapshot binary's strict version allow-list must reject cleanly at header decode"
        );
        assert_eq!(
            BlockHeaderV1::decode_exact(&bytes).unwrap(),
            header,
            "the upgraded binary must decode the same version-3 header"
        );
    }

    #[test]
    fn version_three_binary_rejects_height_precision_version_at_header_decode() {
        fn decode_as_version_three_binary(bytes: &[u8]) -> crate::error::IndraResult<()> {
            let mut reader = ByteReader::new(bytes);
            let version = reader.read_u16_le()?;
            if version != crate::types::primitives::PROTOCOL_VERSION
                && version != crate::types::primitives::BLOCK_PROTOCOL_VERSION_REVEAL_SET
                && version != BLOCK_PROTOCOL_VERSION_CONSENSUS_SNAPSHOT
            {
                return Err(crate::error::IndraError::UnsupportedVersion { version });
            }
            Ok(())
        }

        let mut header = dummy_header();
        header.protocol_version = ProtocolVersion(BLOCK_PROTOCOL_VERSION_SELF_UNSTAKE_HEIGHT);
        let bytes = header.encode_to_vec();
        assert_eq!(
            decode_as_version_three_binary(&bytes),
            Err(crate::error::IndraError::UnsupportedVersion {
                version: BLOCK_PROTOCOL_VERSION_SELF_UNSTAKE_HEIGHT,
            })
        );
        assert_eq!(BlockHeaderV1::decode_exact(&bytes).unwrap(), header);
    }

    #[test]
    fn version_four_binary_rejects_epoch_transition_version_at_header_decode() {
        fn decode_as_version_four_binary(bytes: &[u8]) -> crate::error::IndraResult<()> {
            let mut reader = ByteReader::new(bytes);
            let version = reader.read_u16_le()?;
            if version != crate::types::primitives::PROTOCOL_VERSION
                && version != crate::types::primitives::BLOCK_PROTOCOL_VERSION_REVEAL_SET
                && version != BLOCK_PROTOCOL_VERSION_CONSENSUS_SNAPSHOT
                && version != BLOCK_PROTOCOL_VERSION_SELF_UNSTAKE_HEIGHT
            {
                return Err(crate::error::IndraError::UnsupportedVersion { version });
            }
            Ok(())
        }

        let mut header = dummy_header();
        header.protocol_version = ProtocolVersion(BLOCK_PROTOCOL_VERSION_EPOCH_TRANSITION_CONTEXT);
        let bytes = header.encode_to_vec();
        assert_eq!(
            decode_as_version_four_binary(&bytes),
            Err(crate::error::IndraError::UnsupportedVersion {
                version: BLOCK_PROTOCOL_VERSION_EPOCH_TRANSITION_CONTEXT,
            })
        );
        assert_eq!(BlockHeaderV1::decode_exact(&bytes).unwrap(), header);
    }

    #[test]
    fn version_six_binary_rejects_live_bond_cap_version_at_header_decode() {
        fn decode_as_version_six_binary(bytes: &[u8]) -> crate::error::IndraResult<()> {
            let mut reader = ByteReader::new(bytes);
            let version = reader.read_u16_le()?;
            if version != crate::types::primitives::PROTOCOL_VERSION
                && version != crate::types::primitives::BLOCK_PROTOCOL_VERSION_REVEAL_SET
                && version != BLOCK_PROTOCOL_VERSION_CONSENSUS_SNAPSHOT
                && version != BLOCK_PROTOCOL_VERSION_SELF_UNSTAKE_HEIGHT
                && version != BLOCK_PROTOCOL_VERSION_EPOCH_TRANSITION_CONTEXT
                && version != BLOCK_PROTOCOL_VERSION_DELEGATOR_BOND_ACCOUNTING
            {
                return Err(crate::error::IndraError::UnsupportedVersion { version });
            }
            Ok(())
        }

        let mut header = dummy_header();
        header.protocol_version = ProtocolVersion(BLOCK_PROTOCOL_VERSION_LIVE_BOND_COUNT_CAP);
        let bytes = header.encode_to_vec();
        assert_eq!(
            decode_as_version_six_binary(&bytes),
            Err(crate::error::IndraError::UnsupportedVersion {
                version: BLOCK_PROTOCOL_VERSION_LIVE_BOND_COUNT_CAP,
            })
        );
        assert_eq!(BlockHeaderV1::decode_exact(&bytes).unwrap(), header);
    }
}
