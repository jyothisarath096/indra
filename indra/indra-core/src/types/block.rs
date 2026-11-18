//! Block and block header.

use crate::{
    codec::{decode_list, encode_list, list_encoded_len, ByteReader, Decode, Encode},
    error::IndraResult,
    ssz::sha256,
    types::{
        crypto::HybridSignature,
        governance::GovernanceOpV2,
        primitives::{
            Bytes32, Bytes64, ProtocolVersion, VariableBytes, BLOCK_FORMAT_VERSION,
            MAX_GOV_OPS_PER_BLOCK, MAX_QC_SIZE_BYTES, MAX_SLASHES_PER_BLOCK,
            MAX_STAKING_OPS_PER_BLOCK, MAX_STANDARD_VRF_OUTPUT_BYTES, MAX_STANDARD_VRF_PROOF_BYTES,
            MAX_TX_PER_BLOCK,
        },
        slashing::SlashEvidenceV2,
        staking::StakingOp,
        transaction::TransactionV1,
    },
};

/// Canonical commitment to the unordered set of transactions selected for a block.
///
/// Both proposal production and proposal verification must use this function.
pub fn transaction_set_root(transactions: &[TransactionV1]) -> Bytes32 {
    let mut tx_ids: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.tx_hash().0).collect();
    tx_ids.sort_unstable();
    let mut encoded = Vec::with_capacity(tx_ids.len().saturating_mul(32));
    for tx_id in tx_ids {
        encoded.extend_from_slice(&tx_id);
    }
    Bytes32::from(indra_crypto::sha256(&encoded))
}

/// Sole accepted standard VRF suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VrfSuiteV1 {
    /// RFC 9381 ECVRF-EDWARDS25519-SHA512-ELL2.
    EcvrfEdwards25519Sha512Ell2 = 1,
}
impl Encode for VrfSuiteV1 {
    fn encode(&self, b: &mut Vec<u8>) {
        (*self as u8).encode(b)
    }
    fn encoded_len(&self) -> usize {
        1
    }
}
impl Decode for VrfSuiteV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        match u8::decode(r)? {
            1 => Ok(Self::EcvrfEdwards25519Sha512Ell2),
            v => Err(crate::error::IndraError::InvalidSortition(format!(
                "unsupported VRF suite {v}"
            ))),
        }
    }
}
/// Sole accepted sortition construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortitionClaimV1 {
    /// Certified Praos threshold.
    PraosThreshold = 1,
}
impl Encode for SortitionClaimV1 {
    fn encode(&self, b: &mut Vec<u8>) {
        (*self as u8).encode(b)
    }
    fn encoded_len(&self) -> usize {
        1
    }
}
impl Decode for SortitionClaimV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        match u8::decode(r)? {
            1 => Ok(Self::PraosThreshold),
            v => Err(crate::error::IndraError::InvalidSortition(format!(
                "unsupported sortition claim {v}"
            ))),
        }
    }
}

/// Immutable, independently-verifiable entropy carried by one consensus value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalEntropyV1 {
    /// Validator whose first proposal fixed the value's entropy.
    pub origin_proposer_id: Bytes32,
    /// Round in which that validator first proposed the value.
    pub origin_round: u32,
    /// RFC 9381 output for the origin's height/round-bound alpha.
    pub vrf_output: VariableBytes<MAX_STANDARD_VRF_OUTPUT_BYTES>,
    /// RFC 9381 proof authenticating `vrf_output`.
    pub vrf_proof: VariableBytes<MAX_STANDARD_VRF_PROOF_BYTES>,
}

impl ProposalEntropyV1 {
    /// Canonical commitment used by the round-stable consensus value identity.
    ///
    /// The versioned domain is deliberately distinct from the seed-evolution
    /// transcript. The canonical codec makes every component unambiguous,
    /// including the bounded VRF output and proof lengths.
    pub fn commitment(&self) -> Bytes32 {
        let mut material = b"INDRA-PROPOSAL-ENTROPY-COMMIT-v1".to_vec();
        self.encode(&mut material);
        Bytes32::from(sha256(&material))
    }

    /// Empty form used only by the height-zero genesis anchor.
    pub fn genesis() -> Self {
        Self {
            origin_proposer_id: Bytes32::ZERO,
            origin_round: 0,
            vrf_output: VariableBytes::default(),
            vrf_proof: VariableBytes::default(),
        }
    }
}

impl Encode for ProposalEntropyV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.origin_proposer_id.encode(buf);
        self.origin_round.encode(buf);
        self.vrf_output.encode(buf);
        self.vrf_proof.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        32 + 4 + self.vrf_output.encoded_len() + self.vrf_proof.encoded_len()
    }
}

impl Decode for ProposalEntropyV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let origin_proposer_id = Bytes32::decode(r)?;
        let origin_round = crate::types::primitives::validate_consensus_round(u32::decode(r)?)?;
        Ok(Self {
            origin_proposer_id,
            origin_round,
            vrf_output: VariableBytes::decode(r)?,
            vrf_proof: VariableBytes::decode(r)?,
        })
    }
}

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
pub struct BlockHeaderVNext {
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
    /// `None` means no prior PoLC was attached; `Some(r)` is a legal PoLC round.
    pub polc_round: Option<u32>,
    /// Quorum certificate for the PREVIOUS block (proving it was finalised).
    pub quorum_certificate: VariableBytes<MAX_QC_SIZE_BYTES>,
    /// Snapshot identity of the proposer.
    pub proposer_id: Bytes32,
    /// Standard VRF suite.
    pub vrf_suite: VrfSuiteV1,
    /// Locally-derived election seed.
    pub election_seed: Bytes64,
    /// Full standard VRF output.
    pub proposer_vrf_output: VariableBytes<MAX_STANDARD_VRF_OUTPUT_BYTES>,
    /// Full standard VRF proof.
    pub proposer_vrf_proof: VariableBytes<MAX_STANDARD_VRF_PROOF_BYTES>,
    /// Round-stable entropy record retained unchanged across reproposals.
    pub value_entropy: ProposalEntropyV1,
    /// Sortition claim.
    pub sortition_claim: SortitionClaimV1,
    /// Full-width proposal priority.
    pub proposer_priority: Bytes64,
}

impl BlockHeaderVNext {
    /// Compute the canonical full-header block hash.
    pub fn block_hash(&self) -> Bytes32 {
        Bytes32::from(sha256(&self.encode_to_vec()))
    }

    /// Compute the stable consensus value hash for a block.
    pub fn compute_value_hash(input: &ValueHashInput<'_>) -> Bytes32 {
        let mut buf = Vec::with_capacity(8 + 32 + 8 + 32 + 32 + 32 + 32 + 8 + 8);
        input.height.encode(&mut buf);
        input.prev_hash.encode(&mut buf);
        input.timestamp.encode(&mut buf);
        input.state_root.encode(&mut buf);
        input.validator_set_root.encode(&mut buf);
        input.mempool_set_root.encode(&mut buf);
        input.value_entropy.commitment().encode(&mut buf);
        input.base_fee.encode(&mut buf);
        input.total_supply.encode(&mut buf);
        Bytes32::from(sha256(&buf))
    }
}

/// Immutable fields used to compute a block value hash.
pub struct ValueHashInput<'a> {
    /// Block height.
    pub height: u64,
    /// Parent block hash.
    pub prev_hash: Bytes32,
    /// Block timestamp.
    pub timestamp: u64,
    /// Post-state root.
    pub state_root: Bytes32,
    /// Validator-set root.
    pub validator_set_root: Bytes32,
    /// Mempool-set root.
    pub mempool_set_root: Bytes32,
    /// Stable proposal entropy.
    pub value_entropy: &'a ProposalEntropyV1,
    /// Base fee.
    pub base_fee: u64,
    /// Post-state total supply.
    pub total_supply: u64,
}

impl Encode for BlockHeaderVNext {
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
        self.quorum_certificate.encode(buf);
        match self.polc_round {
            None => 0u8.encode(buf),
            Some(round) => {
                1u8.encode(buf);
                round.encode(buf);
            }
        }
        self.value_hash.encode(buf);
        self.proposer_id.encode(buf);
        self.vrf_suite.encode(buf);
        self.election_seed.encode(buf);
        self.proposer_vrf_output.encode(buf);
        self.proposer_vrf_proof.encode(buf);
        self.value_entropy.encode(buf);
        self.sortition_claim.encode(buf);
        self.proposer_priority.encode(buf);
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
            + 1
            + usize::from(self.polc_round.is_some()) * 4
            + 4
            + self.quorum_certificate.encoded_len()
            + 32
            + 1
            + 64
            + self.proposer_vrf_output.encoded_len()
            + self.proposer_vrf_proof.encoded_len()
            + self.value_entropy.encoded_len()
            + 1
            + 64
    }
}

impl Decode for BlockHeaderVNext {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let protocol_version = ProtocolVersion::decode(r)?;
        if protocol_version.0 != BLOCK_FORMAT_VERSION {
            return Err(crate::error::IndraError::UnsupportedVersion {
                version: protocol_version.0,
            });
        }
        let height = u64::decode(r)?;
        let prev_hash = Bytes32::decode(r)?;
        let timestamp = u64::decode(r)?;
        let state_root = Bytes32::decode(r)?;
        let validator_set_root = Bytes32::decode(r)?;
        let mempool_set_root = Bytes32::decode(r)?;
        let base_fee = u64::decode(r)?;
        let proposer_round = crate::types::primitives::validate_consensus_round(u32::decode(r)?)?;
        let quorum_certificate = VariableBytes::decode(r)?;
        let polc_round = match u8::decode(r)? {
            0 => None,
            1 => Some(crate::types::primitives::validate_consensus_round(
                u32::decode(r)?,
            )?),
            byte => return Err(crate::error::IndraError::InvalidBool { byte }),
        };
        let header = Self {
            protocol_version,
            height,
            prev_hash,
            timestamp,
            state_root,
            validator_set_root,
            mempool_set_root,
            base_fee,
            proposer_round,
            quorum_certificate,
            polc_round,
            value_hash: Bytes32::decode(r)?,
            proposer_id: Bytes32::decode(r)?,
            vrf_suite: VrfSuiteV1::decode(r)?,
            election_seed: Bytes64::decode(r)?,
            proposer_vrf_output: VariableBytes::decode(r)?,
            proposer_vrf_proof: VariableBytes::decode(r)?,
            value_entropy: ProposalEntropyV1::decode(r)?,
            sortition_claim: SortitionClaimV1::decode(r)?,
            proposer_priority: Bytes64::decode(r)?,
        };
        let genesis_exception = header.height == 0
            && header.proposer_id == Bytes32::ZERO
            && header.proposer_vrf_output.is_empty()
            && header.proposer_vrf_proof.is_empty()
            && header.value_entropy == ProposalEntropyV1::genesis();
        if !genesis_exception
            && (header.proposer_vrf_output.len() != 64
                || header.proposer_vrf_proof.len() != 80
                || header.value_entropy.vrf_output.len() != 64
                || header.value_entropy.vrf_proof.len() != 80)
        {
            return Err(crate::error::IndraError::VrfProofInvalid);
        }
        Ok(header)
    }
}

/// A complete INDRA v1 block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockVNext {
    /// Block header.
    pub header: BlockHeaderVNext,
    /// Transactions (0–200).
    pub transactions: Vec<TransactionV1>,
    /// Membership-proven slash evidence (0–3).
    pub slashing_evidence: Vec<SlashEvidenceV2>,
    /// Governance operations (0–5).
    pub governance_ops: Vec<GovernanceOpV2>,
    /// Staking operations (0–10).
    pub staking_ops: Vec<StakingOp>,
}

impl Encode for BlockVNext {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.header.encode(buf);
        encode_list(&self.transactions, buf);
        encode_list(&self.slashing_evidence, buf);
        encode_list(&self.governance_ops, buf);
        encode_list(&self.staking_ops, buf);
    }
    fn encoded_len(&self) -> usize {
        self.header.encoded_len()
            + list_encoded_len(&self.transactions)
            + list_encoded_len(&self.slashing_evidence)
            + list_encoded_len(&self.governance_ops)
            + list_encoded_len(&self.staking_ops)
    }
}

impl Decode for BlockVNext {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let header = BlockHeaderVNext::decode(r)?;
        let transactions = decode_list(r, MAX_TX_PER_BLOCK, "transactions")?;
        let slashing_evidence = decode_list(r, MAX_SLASHES_PER_BLOCK, "slashing_evidence")?;
        Ok(Self {
            header,
            transactions,
            slashing_evidence,
            governance_ops: decode_list(r, MAX_GOV_OPS_PER_BLOCK, "governance_ops")?,
            staking_ops: decode_list(r, MAX_STAKING_OPS_PER_BLOCK, "staking_ops")?,
        })
    }
}

/// Canonical proposal envelope; authorization is excluded from block identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockProposalVNext {
    /// Complete unsigned block.
    pub block: BlockVNext,
    /// Full hybrid authorization.
    pub proposer_authorization: HybridSignature,
}
impl BlockProposalVNext {
    /// Exact full-block authorization transcript.
    pub fn signing_bytes(&self, chain_id: &[u8]) -> IndraResult<Vec<u8>> {
        crate::types::primitives::validate_consensus_round(self.block.header.proposer_round)?;
        crate::types::primitives::validate_consensus_round(
            self.block.header.value_entropy.origin_round,
        )?;
        if let Some(round) = self.block.header.polc_round {
            crate::types::primitives::validate_consensus_round(round)?;
        }
        let n = u16::try_from(chain_id.len()).map_err(|_| {
            crate::error::IndraError::LengthExceeded {
                field: "chain_id",
                max: u16::MAX as usize,
                actual: chain_id.len(),
            }
        })?;
        let block = self.block.encode_to_vec();
        let mut o = b"INDRA-PROPOSAL-AUTH-v1".to_vec();
        o.extend_from_slice(&n.to_be_bytes());
        o.extend_from_slice(chain_id);
        self.block.header.height.encode(&mut o);
        self.block.header.proposer_round.encode(&mut o);
        self.block.header.proposer_id.encode(&mut o);
        (block.len() as u64).encode(&mut o);
        o.extend_from_slice(&block);
        Ok(o)
    }
}
impl Encode for BlockProposalVNext {
    fn encode(&self, b: &mut Vec<u8>) {
        self.block.encode(b);
        self.proposer_authorization.encode(b)
    }
    fn encoded_len(&self) -> usize {
        self.block.encoded_len() + self.proposer_authorization.encoded_len()
    }
}
impl Decode for BlockProposalVNext {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            block: BlockVNext::decode(r)?,
            proposer_authorization: HybridSignature::decode(r)?,
        })
    }
}

impl core::ops::Deref for BlockProposalVNext {
    type Target = BlockVNext;
    fn deref(&self) -> &Self::Target {
        &self.block
    }
}
impl core::ops::DerefMut for BlockProposalVNext {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.block
    }
}

impl BlockVNext {
    /// Recompute this block's stable consensus value hash from its stable
    /// content fields and projected post-state total supply.
    pub fn compute_value_hash(&self, total_supply: u64) -> Bytes32 {
        BlockHeaderVNext::compute_value_hash(&ValueHashInput {
            height: self.header.height,
            prev_hash: self.header.prev_hash,
            timestamp: self.header.timestamp,
            state_root: self.header.state_root,
            validator_set_root: self.header.validator_set_root,
            mempool_set_root: self.header.mempool_set_root,
            value_entropy: &self.header.value_entropy,
            base_fee: self.header.base_fee,
            total_supply,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Decode;

    fn dummy_header() -> BlockHeaderVNext {
        BlockHeaderVNext {
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
            polc_round: None,
            proposer_id: Bytes32::from([0x43u8; 32]),
            vrf_suite: VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
            election_seed: Bytes64([0x42; 64]),
            proposer_vrf_output: VariableBytes::from_slice(&[0x44u8; 64]).unwrap(),
            proposer_vrf_proof: VariableBytes::from_slice(&[0xAAu8; 80]).unwrap(),
            value_entropy: ProposalEntropyV1 {
                origin_proposer_id: Bytes32::from([0x43u8; 32]),
                origin_round: 0,
                vrf_output: VariableBytes::from_slice(&[0x44u8; 64]).unwrap(),
                vrf_proof: VariableBytes::from_slice(&[0xAAu8; 80]).unwrap(),
            },
            sortition_claim: SortitionClaimV1::PraosThreshold,
            proposer_priority: Bytes64([0x45; 64]),
            quorum_certificate: VariableBytes::from_slice(&[0xBBu8; 256]).unwrap(),
        }
    }

    #[test]
    fn header_round_trip() {
        let h = dummy_header();
        assert_eq!(
            h,
            BlockHeaderVNext::decode_exact(&h.encode_to_vec()).unwrap()
        );
    }

    #[test]
    fn current_header_rejects_each_truncated_mandatory_tail_field_and_trailing_bytes() {
        let encoded = dummy_header().encode_to_vec();
        for removed in 1..=80 {
            assert!(BlockHeaderVNext::decode_exact(&encoded[..encoded.len() - removed]).is_err());
        }

        let mut trailing = encoded;
        trailing.push(0xA5);
        assert!(BlockHeaderVNext::decode_exact(&trailing).is_err());
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
        let base = BlockHeaderVNext::compute_value_hash(&ValueHashInput {
            height: h.height,
            prev_hash: h.prev_hash,
            timestamp: h.timestamp,
            state_root: h.state_root,
            validator_set_root: h.validator_set_root,
            mempool_set_root: h.mempool_set_root,
            value_entropy: &h.value_entropy,
            base_fee: h.base_fee,
            total_supply: 123,
        });

        let mut changed = h.clone();
        changed.proposer_round = 7;
        changed.polc_round = Some(3);
        changed.proposer_vrf_output = VariableBytes::from_slice(&[0x55u8; 64]).unwrap();

        let changed_hash = BlockHeaderVNext::compute_value_hash(&ValueHashInput {
            height: changed.height,
            prev_hash: changed.prev_hash,
            timestamp: changed.timestamp,
            state_root: changed.state_root,
            validator_set_root: changed.validator_set_root,
            mempool_set_root: changed.mempool_set_root,
            value_entropy: &changed.value_entropy,
            base_fee: changed.base_fee,
            total_supply: 123,
        });

        assert_eq!(base, changed_hash);
    }

    #[test]
    fn value_hash_commits_every_immutable_entropy_component() {
        let base = dummy_header();
        let hash = |entropy: &ProposalEntropyV1| {
            BlockHeaderVNext::compute_value_hash(&ValueHashInput {
                height: base.height,
                prev_hash: base.prev_hash,
                timestamp: base.timestamp,
                state_root: base.state_root,
                validator_set_root: base.validator_set_root,
                mempool_set_root: base.mempool_set_root,
                value_entropy: entropy,
                base_fee: base.base_fee,
                total_supply: 123,
            })
        };
        let original = hash(&base.value_entropy);

        let mut changed = base.value_entropy.clone();
        changed.origin_proposer_id.0[0] ^= 1;
        assert_ne!(original, hash(&changed));

        let mut changed = base.value_entropy.clone();
        changed.origin_round += 1;
        assert_ne!(original, hash(&changed));

        let mut changed = base.value_entropy.clone();
        let mut output = changed.vrf_output.as_slice().to_vec();
        output[0] ^= 1;
        changed.vrf_output = VariableBytes::new(output).unwrap();
        assert_ne!(original, hash(&changed));

        let mut changed = base.value_entropy.clone();
        let mut proof = changed.vrf_proof.as_slice().to_vec();
        proof[0] ^= 1;
        changed.vrf_proof = VariableBytes::new(proof).unwrap();
        assert_ne!(original, hash(&changed));
    }

    #[test]
    fn entropy_commitment_is_canonical_across_exact_round_trip() {
        let entropy = dummy_header().value_entropy;
        let decoded = ProposalEntropyV1::decode_exact(&entropy.encode_to_vec()).unwrap();
        assert_eq!(entropy, decoded);
        assert_eq!(entropy.commitment(), decoded.commitment());
    }

    #[test]
    fn empty_block_round_trip() {
        let b = BlockVNext {
            header: dummy_header(),
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        };
        assert_eq!(b, BlockVNext::decode_exact(&b.encode_to_vec()).unwrap());
    }

    #[test]
    fn proposal_envelope_is_exact_and_signing_transcript_binds_complete_block() {
        let block = BlockVNext {
            header: dummy_header(),
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        };
        let proposal = BlockProposalVNext {
            block,
            proposer_authorization: HybridSignature {
                classical_sig: VariableBytes::from_slice(&[1; 64]).unwrap(),
                pq_sig: VariableBytes::from_slice(&[2; 4627]).unwrap(),
            },
        };
        let unsigned_block_len = proposal.block.encoded_len();
        let encoded = proposal.encode_to_vec();
        assert_eq!(
            encoded.len() - unsigned_block_len,
            4 + 64 + 4 + 4_627,
            "mandatory hybrid proposer envelope adds exactly 4,699 bytes per stored block"
        );
        assert_eq!(
            proposal,
            BlockProposalVNext::decode_exact(&encoded).unwrap()
        );
        let mut trailing = encoded;
        trailing.push(0xA5);
        assert!(BlockProposalVNext::decode_exact(&trailing).is_err());

        let baseline = proposal.signing_bytes(b"indra-test").unwrap();
        let mut changed = proposal.clone();
        changed.block.header.timestamp += 1;
        assert_ne!(baseline, changed.signing_bytes(b"indra-test").unwrap());
        assert_ne!(baseline, proposal.signing_bytes(b"other-chain").unwrap());
    }

    #[test]
    fn block_and_entropy_decoders_enforce_finite_round_domain() {
        for round in [0, crate::types::primitives::MAX_ROUNDS_PER_HEIGHT - 1] {
            let mut header = dummy_header();
            header.proposer_round = round;
            header.value_entropy.origin_round = round;
            header.polc_round = Some(round);
            assert!(BlockHeaderVNext::decode_exact(&header.encode_to_vec()).is_ok());
        }
        for round in [
            crate::types::primitives::MAX_ROUNDS_PER_HEIGHT,
            crate::types::primitives::MAX_ROUNDS_PER_HEIGHT + 1,
            u32::MAX,
        ] {
            let mut header = dummy_header();
            header.proposer_round = round;
            let error = BlockHeaderVNext::decode_exact(&header.encode_to_vec()).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "invalid consensus round {round}; maximum legal round is {}",
                    crate::types::primitives::MAX_ROUNDS_PER_HEIGHT - 1
                )
            );

            let mut header = dummy_header();
            header.value_entropy.origin_round = round;
            let error = BlockHeaderVNext::decode_exact(&header.encode_to_vec()).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "invalid consensus round {round}; maximum legal round is {}",
                    crate::types::primitives::MAX_ROUNDS_PER_HEIGHT - 1
                )
            );

            let mut header = dummy_header();
            header.polc_round = Some(round);
            let error = BlockHeaderVNext::decode_exact(&header.encode_to_vec()).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "invalid consensus round {round}; maximum legal round is {}",
                    crate::types::primitives::MAX_ROUNDS_PER_HEIGHT - 1
                )
            );
        }
    }
}
