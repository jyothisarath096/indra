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

use indra_core::types::{
    block::{BlockHeaderV1, BlockV1, NO_POLC_ROUND},
    governance::GovernanceOpV2,
    primitives::{
        vrf_commit_reveal_election_active, Bytes32, ProtocolVersion, VariableBytes,
        MAX_QC_SIZE_BYTES, MAX_TX_PER_BLOCK, MAX_VRF_PROOF_BYTES,
    },
    slashing::SlashEvidenceV1,
    staking::StakingOp,
    transaction::TransactionV1,
    vrf_election::VrfElectionResult,
};
use indra_crypto::VrfKeypair;
use indra_state::{apply_block, compute_state_root, compute_validator_set_root, ChainState};

use crate::{
    error::{ConsensusError, ConsensusResult},
    mempool::Mempool,
    proposer::{compute_proposer_vrf, elect_proposer, ProposerElection, VRF_FALLBACK_OUTPUT},
};

/// A block template — the inputs needed to produce a block.
pub struct BlockTemplate {
    /// The proposer's VRF keypair.
    pub proposer_vrf_keypair: VrfKeypair,
    /// The epoch seed (SHA-256 of last epoch's final block hash).
    pub epoch_seed: Bytes32,
    /// The serialised QC for the previous height (to embed in this header).
    /// Empty bytes for the first block.
    pub prev_qc_bytes: Vec<u8>,
    /// Unix timestamp for the new block.
    pub timestamp: u64,
    /// Round whose prevote quorum justified re-proposal of this value.
    pub polc_round: Option<u32>,
    /// Staking operations selected for inclusion.
    pub staking_ops: Vec<StakingOp>,
    /// Governance operations selected for inclusion.
    pub governance_ops: Vec<GovernanceOpV2>,
    /// Slash evidence selected for inclusion.
    pub slash_evidence: Vec<SlashEvidenceV1>,
    /// Commit-reveal election result hash for this proposal, when active.
    pub election_result_hash: Option<Bytes32>,
}

/// Produce a block from the current state and mempool.
///
/// This is the complete block production pipeline:
///   1. Verify the proposer won the slot election
///   2. Select transactions from the mempool
///   3. Assemble and return the block
///
/// The returned block is ready for broadcast and voting.
/// It has NOT been applied to state yet.
pub fn produce_block(
    template: &BlockTemplate,
    state: &ChainState,
    mempool: &Mempool,
    election: &ProposerElection,
) -> ConsensusResult<BlockV1> {
    // Verify this keypair is the elected proposer
    let slot = compute_proposer_vrf(
        election
            .candidates
            .iter()
            .find(|candidate| candidate.vrf_pubkey == template.proposer_vrf_keypair.public_key())
            .map(|candidate| candidate.validator_id)
            .ok_or(ConsensusError::WrongProposer)?,
        &template.proposer_vrf_keypair,
        &template.epoch_seed,
        election.height,
        election.round,
    );

    if vrf_commit_reveal_election_active(election.height) {
        let expected_normal = VrfElectionResult {
            height: election.height,
            round: election.round,
            elected_validator_id: slot.proposer_id,
            elected_vrf_output: Bytes32::from(slot.vrf_output.0),
            fallback_used: false,
        }
        .hash();
        let expected_fallback = VrfElectionResult {
            height: election.height,
            round: election.round,
            elected_validator_id: slot.proposer_id,
            elected_vrf_output: VRF_FALLBACK_OUTPUT,
            fallback_used: true,
        }
        .hash();
        if template.election_result_hash != Some(expected_normal)
            && template.election_result_hash != Some(expected_fallback)
        {
            return Err(ConsensusError::WrongProposer);
        }
    } else {
        let elected = elect_proposer(election, election.height)?;
        if elected != slot.proposer_id {
            return Err(ConsensusError::WrongProposer);
        }
    }

    // Transaction selection policy:
    // - Transactions are selected from the mempool by age eligibility first,
    //   then fee rate, up to MAX_TX_PER_BLOCK.
    // - The proposer has discretion over whether to include any particular
    //   non-consensus-mandatory transaction; empty blocks remain valid.
    // - Proposers can censor or delay individual transactions by omitting
    //   them, but cannot earn extra base block reward by doing so because
    //   block rewards are epoch-based, not per-transaction.
    // - Front-running within a block is possible within the deterministic
    //   selected set/order constraints.
    // - Future mainnet consideration: inclusion rules, ordering commitments,
    //   or PBS may be needed if MEV risk grows.
    let selected: Vec<TransactionV1> = mempool
        .select_for_block(MAX_TX_PER_BLOCK, state.height)
        .into_iter()
        .map(|e| e.tx.clone())
        .collect();
    let mut selected = selected;
    selected.sort_by_key(|tx| tx.tx_hash().0);
    if selected.is_empty() && mempool.has_fee_eligible_transactions(state.base_fee) {
        eprintln!(
            "[proposer] WARNING: producing empty block at height={} but mempool has fee-eligible transactions — possible censorship",
            state.height.saturating_add(1),
        );
    }

    // Build VRF proof bytes for header
    let vrf_proof_bytes = VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&slot.vrf_proof.0)
        .map_err(|_| ConsensusError::CryptoError {
            detail: "VRF proof too large".to_string(),
        })?;

    // Embed previous QC
    let qc_bytes = VariableBytes::<MAX_QC_SIZE_BYTES>::from_slice(&template.prev_qc_bytes)
        .map_err(|_| ConsensusError::CryptoError {
            detail: "QC bytes too large".to_string(),
        })?;

    let height = state.height + 1;

    let header = BlockHeaderV1 {
        protocol_version: ProtocolVersion::CURRENT,
        height,
        prev_hash: state.tip_hash,
        timestamp: template.timestamp,
        state_root: Bytes32::ZERO,
        validator_set_root: Bytes32::ZERO,
        mempool_set_root: compute_selected_tx_root(&selected),
        value_hash: Bytes32::ZERO,
        base_fee: state.base_fee,
        proposer_round: election.round,
        polc_round: template.polc_round.unwrap_or(NO_POLC_ROUND),
        proposer_vrf_output: Bytes32::from(slot.vrf_output.0),
        proposer_vrf_proof: vrf_proof_bytes,
        quorum_certificate: qc_bytes,
        election_result_hash: template.election_result_hash,
    };

    let mut block = BlockV1 {
        header,
        transactions: selected,
        slashing_evidence: template.slash_evidence.clone(),
        governance_ops: template.governance_ops.clone(),
        staking_ops: template.staking_ops.clone(),
    };

    let mut projected = state.clone();
    apply_block(&mut projected, &block, 0).map_err(|err| ConsensusError::CryptoError {
        detail: format!("failed to project roots for produced block: {err}"),
    })?;
    block.header.state_root = compute_state_root(&projected);
    block.header.validator_set_root = compute_validator_set_root(&projected);
    block.header.value_hash = block.compute_value_hash(projected.total_supply);

    Ok(block)
}

/// Compute a simple selected-transaction root: SHA-256 of all selected tx_ids sorted and hashed.
///
/// This binds the header hash to the exact transaction set included in the block.
fn compute_selected_tx_root(transactions: &[TransactionV1]) -> Bytes32 {
    use indra_crypto::sha256;
    let mut tx_ids: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.tx_hash().0).collect();
    tx_ids.sort();

    let mut data = Vec::new();
    for id in &tx_ids {
        data.extend_from_slice(id);
    }
    Bytes32::from(sha256(&data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::Mempool;
    use indra_crypto::VrfKeypair;
    use indra_state::ChainState;

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
            epoch_seed: Bytes32::from(*seed),
            height,
            round,
            candidates: vec![crate::proposer::ProposerCandidate {
                validator_id,
                vrf_pubkey: vrf_pubkey,
                verified_vrf_output: None,
                stake,
            }],
        }
    }

    fn election_hash_for(election: &ProposerElection, vrf_seed: [u8; 32]) -> Bytes32 {
        let vrf = VrfKeypair::from_seed(&vrf_seed);
        let validator_id = election
            .candidates
            .iter()
            .find(|candidate| candidate.vrf_pubkey == vrf.public_key())
            .unwrap()
            .validator_id;
        let slot = compute_proposer_vrf(
            validator_id,
            &vrf,
            &election.epoch_seed,
            election.height,
            election.round,
        );
        VrfElectionResult {
            height: election.height,
            round: election.round,
            elected_validator_id: validator_id,
            elected_vrf_output: Bytes32::from(slot.vrf_output.0),
            fallback_used: false,
        }
        .hash()
    }

    #[test]
    fn produce_empty_block() {
        let state = ChainState::new_genesis();
        let mempool = Mempool::default_config();
        let seed = [0x42u8; 32];
        let election = make_election(&seed, 1, 0, seed, 1_000_000);

        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&seed),
            epoch_seed: Bytes32::from(seed),
            prev_qc_bytes: vec![],
            timestamp: 1_700_000_001,
            polc_round: None,
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            election_result_hash: Some(election_hash_for(&election, seed)),
        };

        let block = produce_block(&template, &state, &mempool, &election).unwrap();
        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.prev_hash, state.tip_hash);
        assert_eq!(block.transactions.len(), 0);
    }

    #[test]
    fn block_header_commits_to_election_result_hash() {
        let state = ChainState::new_genesis();
        let mempool = Mempool::default_config();
        let seed = [0x43u8; 32];
        let election = make_election(&seed, 1, 0, seed, 1_000_000);
        let election_hash = election_hash_for(&election, seed);
        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&seed),
            epoch_seed: Bytes32::from(seed),
            prev_qc_bytes: vec![],
            timestamp: 1_700_000_001,
            polc_round: None,
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            election_result_hash: Some(election_hash),
        };

        let block = produce_block(&template, &state, &mempool, &election).unwrap();
        let original_hash = block.header.block_hash();
        let mut tampered = block.header.clone();
        tampered.election_result_hash = Some(Bytes32::from([0x44; 32]));

        assert_eq!(block.header.election_result_hash, Some(election_hash));
        assert_ne!(original_hash, tampered.block_hash());
    }

    #[test]
    fn wrong_proposer_rejected() {
        let state = ChainState::new_genesis();
        let mempool = Mempool::default_config();
        let seed = [0x42u8; 32];
        let wrong_seed = [0x99u8; 32];

        // Election uses seed 0x42, but template uses wrong_seed
        let election = make_election(&seed, 1, 0, seed, 1_000_000);
        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&wrong_seed),
            epoch_seed: Bytes32::from(seed),
            prev_qc_bytes: vec![],
            timestamp: 1_700_000_001,
            polc_round: None,
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            election_result_hash: Some(election_hash_for(&election, seed)),
        };

        assert_eq!(
            produce_block(&template, &state, &mempool, &election),
            Err(ConsensusError::WrongProposer)
        );
    }

    #[test]
    fn block_height_increments() {
        let state = ChainState::new_genesis();
        let mempool = Mempool::default_config();
        let seed = [0x10u8; 32];
        let election = make_election(&seed, 1, 0, seed, 1_000_000);
        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&seed),
            epoch_seed: Bytes32::from(seed),
            prev_qc_bytes: vec![],
            timestamp: 1_700_000_001,
            polc_round: None,
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            election_result_hash: Some(election_hash_for(&election, seed)),
        };
        let block = produce_block(&template, &state, &mempool, &election).unwrap();
        assert_eq!(block.header.height, state.height + 1);
    }
}
