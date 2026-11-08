//! Block production — assembling a valid block from mempool transactions.
//!
//! ## Responsibilities
//!
//! The block producer:
//!   1. Selects transactions from the mempool (age-eligible first, then by fee)
//!   2. Computes the proposer's VRF output and proof
//!   3. Fills the block header (height, prev_hash, base_fee, VRF fields)
//!   4. Projects post-block state and fills real state_root / validator_set_root
//!   5. Embeds the QC for the previous height
//!
//! ## What the producer does NOT do
//!
//! - Apply the block to state (that's apply_block in indra-state)
//! - Broadcast the block (Phase 5 networking)
//! - Sign the block header (proposers don't sign headers — the QC does)

use indra_core::{
    codec::Encode,
    types::{
        block::{BlockHeaderVNext, BlockVNext, SortitionClaimV1, VrfSuiteV1},
        governance::GovernanceOpV2,
        primitives::{
            Bytes32, ProtocolVersion, VariableBytes, BLOCK_FORMAT_VERSION, MAX_BLOCK_SIZE_BYTES,
            MAX_QC_SIZE_BYTES, MAX_STANDARD_VRF_OUTPUT_BYTES, MAX_STANDARD_VRF_PROOF_BYTES,
        },
        slashing::SlashEvidenceV2,
        staking::StakingOp,
        transaction::TransactionV1,
    },
};
use indra_crypto::VrfKeypair;
use indra_state::{project_block_for_roots, ChainState};

use crate::{
    error::{ConsensusError, ConsensusResult},
    proposer::{compute_proposer_vrf, ProposerElection},
};

/// A block template — the inputs needed to produce a block.
pub struct BlockTemplate {
    /// The proposer's VRF keypair.
    pub proposer_vrf_keypair: VrfKeypair,
    /// The serialised QC for the previous height (to embed in this header).
    /// Empty bytes for the first block.
    pub prev_qc_bytes: Vec<u8>,
    /// Unix timestamp for the new block.
    pub timestamp: u64,
    /// Round whose prevote quorum justified re-proposal of this value.
    pub polc_round: Option<u32>,
    /// Transactions already selected against the shared scratch state.
    pub transactions: Vec<TransactionV1>,
    /// Staking operations selected for inclusion.
    pub staking_ops: Vec<StakingOp>,
    /// Governance operations selected for inclusion.
    pub governance_ops: Vec<GovernanceOpV2>,
    /// Slash evidence selected for inclusion.
    pub slash_evidence: Vec<SlashEvidenceV2>,
}

/// Produce a block from contents already selected against a shared scratch state.
///
/// This is the complete block production pipeline:
///   1. Verify the proposer won the slot election
///   2. Assemble the pre-selected contents
///   3. Assemble and return the block
///
/// The returned block is ready for broadcast and voting.
/// It has NOT been applied to state yet.
pub fn produce_block(
    template: &BlockTemplate,
    state: &mut ChainState,
    election: &ProposerElection,
) -> ConsensusResult<BlockVNext> {
    if let Some(round) = template.polc_round {
        indra_core::types::primitives::validate_consensus_round(round).map_err(|error| {
            ConsensusError::InvalidRound {
                detail: error.to_string(),
            }
        })?;
    }
    // Verify this keypair is the elected proposer
    let slot = compute_proposer_vrf(
        election
            .candidates
            .iter()
            .find(|candidate| candidate.vrf_pubkey == template.proposer_vrf_keypair.public_key())
            .map(|candidate| candidate.validator_id)
            .ok_or_else(|| {
                ConsensusError::wrong_proposer("local VRF key is not in election candidates")
            })?,
        &template.proposer_vrf_keypair,
        election,
    );
    let slot = slot?;
    if !slot.eligible {
        return Err(ConsensusError::wrong_proposer(
            "local validator is not eligible for this round",
        ));
    }

    let selected = template.transactions.clone();

    // Build VRF proof bytes for header
    let vrf_proof_bytes = VariableBytes::<MAX_STANDARD_VRF_PROOF_BYTES>::from_slice(
        &slot.vrf_proof.0,
    )
    .map_err(|_| ConsensusError::CryptoError {
        detail: "VRF proof too large".to_string(),
    })?;

    // Embed previous QC
    let qc_bytes = VariableBytes::<MAX_QC_SIZE_BYTES>::from_slice(&template.prev_qc_bytes)
        .map_err(|_| ConsensusError::CryptoError {
            detail: "QC bytes too large".to_string(),
        })?;

    let height = state.height + 1;

    let header = BlockHeaderVNext {
        protocol_version: ProtocolVersion(BLOCK_FORMAT_VERSION),
        height,
        prev_hash: state.tip_hash,
        timestamp: template.timestamp,
        state_root: Bytes32::ZERO,
        validator_set_root: Bytes32::ZERO,
        mempool_set_root: indra_core::types::block::transaction_set_root(&selected),
        value_hash: Bytes32::ZERO,
        base_fee: state.base_fee,
        proposer_round: election.round,
        polc_round: template.polc_round,
        proposer_id: slot.proposer_id,
        vrf_suite: VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
        election_seed: election.election_seed,
        proposer_vrf_output: VariableBytes::<MAX_STANDARD_VRF_OUTPUT_BYTES>::from_slice(
            &slot.vrf_output.0,
        )
        .map_err(|e| ConsensusError::CryptoError {
            detail: e.to_string(),
        })?,
        proposer_vrf_proof: vrf_proof_bytes,
        value_entropy: indra_core::types::block::ProposalEntropyV1 {
            origin_proposer_id: slot.proposer_id,
            origin_round: election.round,
            vrf_output: VariableBytes::from_slice(&slot.vrf_output.0).map_err(|e| {
                ConsensusError::CryptoError {
                    detail: e.to_string(),
                }
            })?,
            vrf_proof: VariableBytes::from_slice(&slot.vrf_proof.0).map_err(|e| {
                ConsensusError::CryptoError {
                    detail: e.to_string(),
                }
            })?,
        },
        sortition_claim: SortitionClaimV1::PraosThreshold,
        proposer_priority: slot.priority,
        quorum_certificate: qc_bytes,
    };

    let mut block = BlockVNext {
        header,
        transactions: selected,
        slashing_evidence: template.slash_evidence.clone(),
        governance_ops: template.governance_ops.clone(),
        staking_ops: template.staking_ops.clone(),
    };

    // Keep the largest deterministic prefix of the coordinator's selection.
    // Removing in reverse mutation order cannot invalidate an earlier item,
    // and omitted pool entries remain pending for a later block.
    while block.encode_to_vec().len() > MAX_BLOCK_SIZE_BYTES {
        if block.slashing_evidence.pop().is_none()
            && block.governance_ops.pop().is_none()
            && block.staking_ops.pop().is_none()
            && block.transactions.pop().is_none()
        {
            return Err(ConsensusError::CryptoError {
                detail: "fixed block fields exceed maximum encoded block size".to_string(),
            });
        }
    }
    block.header.mempool_set_root =
        indra_core::types::block::transaction_set_root(&block.transactions);

    let projected =
        project_block_for_roots(state, &block, 0).map_err(|err| ConsensusError::CryptoError {
            detail: format!("failed to project roots for produced block: {err}"),
        })?;
    block.header.state_root = projected.state_root;
    block.header.validator_set_root = projected.validator_set_root;
    block.header.value_hash = projected.value_hash;

    Ok(block)
}

/// Compute a simple selected-transaction root: SHA-256 of all selected tx_ids sorted and hashed.
///
/// This binds the header hash to the exact transaction set included in the block.
#[cfg(test)]
mod tests {
    use indra_core::types::primitives::TEST_CHAIN_ID;
    use super::*;
    use crate::mempool::Mempool;
    use indra_crypto::VrfKeypair;
    use indra_state::{
        apply_block_for_test as apply_block, state_root, ChainState, ValidatorEntry,
        ValidatorStatus,
    };

    fn finalized_state(vrf_seed: &[u8; 32]) -> ChainState {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        state.active_slot_coefficient_numerator =
            indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR;
        state.election_seed = indra_core::types::primitives::Bytes64([0x42; 64]);
        let hot = indra_crypto::HybridKeypair::new(
            indra_crypto::ClassicalKeypair::from_seed(&[0x31; 32]),
            indra_crypto::PqKeypair::from_seed(&[0x32; 32]).unwrap(),
        );
        let public = hot.public_key();
        let cold = indra_crypto::ColdHybridKeypair::from_independent_seeds([0x33; 32], [0x34; 32])
            .unwrap();
        let cold_public = cold.public_key();
        let cold_public = cold_public.as_complete_hybrid();
        let vrf_pk = VrfKeypair::from_seed(vrf_seed).public_key();
        let validator_id = Bytes32::from(indra_crypto::sha256(&vrf_pk));
        state
            .validators
            .upsert(ValidatorEntry {
                validator_id,
                name: "producer-test".into(),
                hybrid_classical_pk: Some(public.classical.0),
                hybrid_pq_pk: Some(public.pq.0.to_vec()),
                vrf_pk: Some(vrf_pk),
                vrf_key_activation_epoch: 0,
                pending_vrf_pk: None,
                pending_vrf_activation_epoch: None,
                stake_spark: 1_000_000,
                status: ValidatorStatus::Active,
                registered_epoch: 0,
                last_active_epoch: 0,
                slashed_offense_id: None,
                commission_bps: 1_000,
                pending_commission_bps: None,
                pending_commission_effective_epoch: None,
                min_delegation_spark: 1,
                auto_delegate_to: None,
                network_addr: None,
                network_addr_last_updated_epoch: None,
                cold_hybrid_classical_pk: Some(cold_public.classical.0),
                cold_hybrid_pq_pk: Some(cold_public.pq.0),
                cold_key_version: 1,
                cold_nonce: 0,
            })
            .unwrap();
        state.finalize_genesis().unwrap();
        state
    }

    fn make_election(
        seed: &[u8; 32],
        height: u64,
        round: u32,
        vrf_seed: [u8; 32],
        stake: u64,
    ) -> ProposerElection {
        let vrf_pubkey = VrfKeypair::from_seed(&vrf_seed).public_key();
        let validator_id = Bytes32::from(indra_crypto::sha256(&vrf_pubkey));
        ProposerElection {
            chain_id: b"indra-testnet-1".to_vec(),
            election_seed: indra_core::types::primitives::Bytes64([seed[0]; 64]),
            snapshot_root: Bytes32::from([0xA0; 32]),
            active_slot_coefficient_numerator:
                indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
            sortition_log: indra_core::sortition::certified_log(
                indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
            )
            .unwrap(),
            height,
            round,
            candidates: vec![crate::proposer::ProposerCandidate {
                validator_id,
                vrf_pubkey: vrf_pubkey,
                stake,
            }],
        }
    }

    fn eligible_election(
        seed: &[u8; 32],
        height: u64,
        vrf_seed: [u8; 32],
        stake: u64,
    ) -> ProposerElection {
        for round in 0..1024 {
            let election = make_election(seed, height, round, vrf_seed, stake);
            let candidate = &election.candidates[0];
            if compute_proposer_vrf(
                candidate.validator_id,
                &VrfKeypair::from_seed(&vrf_seed),
                &election,
            )
            .unwrap()
            .eligible
            {
                return election;
            }
        }
        panic!("test proposer did not become eligible within the protocol round bound")
    }

    fn parent_qc_bytes(state: &ChainState) -> Vec<u8> {
        if state.height == 0 {
            return Vec::new();
        }
        let hot = indra_crypto::HybridKeypair::new(
            indra_crypto::ClassicalKeypair::from_seed(&[0x31; 32]),
            indra_crypto::PqKeypair::from_seed(&[0x32; 32]).unwrap(),
        );
        let snapshot = state.snapshot_for_consensus_height(state.height).unwrap();
        let entry = &snapshot.entries()[0];
        let vote = crate::vote::produce_vote(
            state.height,
            0,
            indra_core::types::vote::VoteStep::Precommit,
            state.tip_hash,
            entry.validator_id,
            snapshot.snapshot_root,
            &state.chain_id,
            &hot,
        )
        .unwrap();
        crate::qc::build_qc(
            state.height,
            0,
            state.tip_hash,
            &state.chain_id,
            snapshot.snapshot_root,
            &[crate::qc::QcValidator {
                validator_id: entry.validator_id,
                position: 0,
                pq_pk: entry.pq_vote_pk.to_vec(),
                classical_pk: entry.classical_vote_pk,
                stake: entry.consensus_weight_spark,
            }],
            vec![&vote],
        )
        .unwrap()
        .encode_to_vec()
    }

    fn assert_produced_block_matches_clone_projection(block: &BlockVNext, pre_state: &ChainState) {
        let mut projected_candidate = block.clone();
        projected_candidate.header.state_root = Bytes32::ZERO;
        projected_candidate.header.validator_set_root = Bytes32::ZERO;
        projected_candidate.header.value_hash = Bytes32::ZERO;

        let mut scratch = pre_state.clone();
        apply_block(&mut scratch, &projected_candidate, 0).unwrap();
        let roots = state_root::compute_state_roots(&scratch);
        assert_eq!(block.header.state_root, roots.state_root);
        assert_eq!(block.header.validator_set_root, roots.validator_set_root);
        projected_candidate.header.state_root = block.header.state_root;
        projected_candidate.header.validator_set_root = block.header.validator_set_root;
        assert_eq!(
            block.header.value_hash,
            projected_candidate.compute_value_hash(scratch.total_supply)
        );
    }

    fn clone_reference_block_from_produced(
        produced: &BlockVNext,
        pre_state: &ChainState,
    ) -> BlockVNext {
        let mut reference = produced.clone();
        reference.header.state_root = Bytes32::ZERO;
        reference.header.validator_set_root = Bytes32::ZERO;
        reference.header.value_hash = Bytes32::ZERO;

        let mut scratch = pre_state.clone();
        apply_block(&mut scratch, &reference, 0).unwrap();
        let roots = state_root::compute_state_roots(&scratch);
        reference.header.state_root = roots.state_root;
        reference.header.validator_set_root = roots.validator_set_root;
        reference.header.value_hash = reference.compute_value_hash(scratch.total_supply);
        reference
    }

    #[test]
    fn produce_empty_block() {
        let seed = [0x42u8; 32];
        let mut state = finalized_state(&seed);
        let mempool = Mempool::default_config();
        let election = eligible_election(&seed, 1, seed, 1_000_000);

        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&seed),
            prev_qc_bytes: vec![],
            timestamp: 1_700_000_001,
            polc_round: None,
            transactions: mempool
                .select_for_block(
                    indra_core::types::primitives::MAX_TX_PER_BLOCK,
                    state.height,
                )
                .into_iter()
                .map(|entry| entry.tx.clone())
                .collect(),
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        };

        let block = produce_block(&template, &mut state, &election).unwrap();
        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.prev_hash, state.tip_hash);
        assert_eq!(block.transactions.len(), 0);
    }

    #[test]
    fn wrong_proposer_rejected() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let mempool = Mempool::default_config();
        let seed = [0x42u8; 32];
        let wrong_seed = [0x99u8; 32];

        // Election uses seed 0x42, but template uses wrong_seed
        let election = eligible_election(&seed, 1, seed, 1_000_000);
        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&wrong_seed),
            prev_qc_bytes: vec![],
            timestamp: 1_700_000_001,
            polc_round: None,
            transactions: mempool
                .select_for_block(
                    indra_core::types::primitives::MAX_TX_PER_BLOCK,
                    state.height,
                )
                .into_iter()
                .map(|entry| entry.tx.clone())
                .collect(),
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        };

        assert!(matches!(
            produce_block(&template, &mut state, &election),
            Err(ConsensusError::WrongProposer { reason })
                if reason == "local VRF key is not in election candidates"
        ));
    }

    #[test]
    fn block_height_increments() {
        let seed = [0x10u8; 32];
        let mut state = finalized_state(&seed);
        let mempool = Mempool::default_config();
        let election = eligible_election(&seed, 1, seed, 1_000_000);
        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&seed),
            prev_qc_bytes: vec![],
            timestamp: 1_700_000_001,
            polc_round: None,
            transactions: mempool
                .select_for_block(
                    indra_core::types::primitives::MAX_TX_PER_BLOCK,
                    state.height,
                )
                .into_iter()
                .map(|entry| entry.tx.clone())
                .collect(),
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        };
        let block = produce_block(&template, &mut state, &election).unwrap();
        assert_eq!(block.header.height, state.height + 1);
    }

    #[test]
    fn produce_block_matches_clone_based_reference() {
        let seed = [0x6Au8; 32];
        let mut state = finalized_state(&seed);
        let original = state.clone();
        let mempool = Mempool::default_config();
        let election = eligible_election(&seed, 1, seed, 1_000_000);
        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&seed),
            prev_qc_bytes: vec![],
            timestamp: 1_700_000_001,
            polc_round: None,
            transactions: mempool
                .select_for_block(
                    indra_core::types::primitives::MAX_TX_PER_BLOCK,
                    state.height,
                )
                .into_iter()
                .map(|entry| entry.tx.clone())
                .collect(),
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        };

        let block = produce_block(&template, &mut state, &election).unwrap();
        assert_produced_block_matches_clone_projection(&block, &original);
        assert_eq!(
            block,
            clone_reference_block_from_produced(&block, &original)
        );
        assert_eq!(
            state, original,
            "production projection must roll back and leave real state untouched"
        );
    }

    #[test]
    fn production_replay_determinism_matches_reference() {
        let consensus_seed = [0x70u8; 32];
        let mut new_state = finalized_state(&consensus_seed);
        let mut reference_state = new_state.clone();
        let mempool = Mempool::default_config();

        for (index, _seed_byte) in [0x70u8, 0x71, 0x72].into_iter().enumerate() {
            let seed = consensus_seed;
            let height = new_state.height + 1;
            let election = eligible_election(&seed, height, seed, 1_000_000);
            let template = BlockTemplate {
                proposer_vrf_keypair: VrfKeypair::from_seed(&seed),
                prev_qc_bytes: parent_qc_bytes(&new_state),
                timestamp: 1_700_000_001 + index as u64,
                polc_round: None,
                transactions: mempool
                    .select_for_block(
                        indra_core::types::primitives::MAX_TX_PER_BLOCK,
                        new_state.height,
                    )
                    .into_iter()
                    .map(|entry| entry.tx.clone())
                    .collect(),
                slash_evidence: vec![],
                governance_ops: vec![],
                staking_ops: vec![],
            };

            let produced = produce_block(&template, &mut new_state, &election).unwrap();
            let reference = clone_reference_block_from_produced(&produced, &reference_state);
            assert_eq!(
                produced, reference,
                "candidate block mismatch at step {index}"
            );
            apply_block(&mut new_state, &produced, 0).unwrap();
            apply_block(&mut reference_state, &reference, 0).unwrap();
            assert_eq!(new_state, reference_state, "state mismatch at step {index}");
        }
    }
}
