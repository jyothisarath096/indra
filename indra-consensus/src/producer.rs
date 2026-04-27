//! Block production — assembling a valid block from mempool transactions.
//!
//! ## Responsibilities
//!
//! The block producer:
//!   1. Selects transactions from the mempool (age-eligible first, then by fee)
//!   2. Computes the proposer's VRF output and proof
//!   3. Fills the block header (height, prev_hash, base_fee, VRF fields)
//!   4. Leaves state_root, validator_set_root as zero (computed post-application)
//!   5. Embeds the QC for the previous height
//!
//! ## What the producer does NOT do
//!
//! - Apply the block to state (that's apply_block in indra-state)
//! - Broadcast the block (Phase 5 networking)
//! - Sign the block header (proposers don't sign headers — the QC does)

use indra_core::{
    types::{
        primitives::{
            Bytes32, ProtocolVersion, VariableBytes,
            MAX_TX_PER_BLOCK, MAX_VRF_PROOF_BYTES, MAX_QC_SIZE_BYTES,
        },
        block::{BlockV1, BlockHeaderV1},
        transaction::TransactionV1,
    },
};
use indra_crypto::VrfKeypair;
use indra_state::ChainState;

use crate::{
    error::{ConsensusError, ConsensusResult},
    mempool::Mempool,
    proposer::{compute_proposer_vrf, ProposerElection, elect_proposer},
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
        &template.proposer_vrf_keypair,
        &template.epoch_seed,
        state.height + 1,
    );

    let elected = elect_proposer(election)?;
    if elected != slot.proposer_id {
        return Err(ConsensusError::WrongProposer);
    }

    // Select transactions — age-eligible first, then by fee rate
    let selected: Vec<TransactionV1> = mempool
        .select_for_block(MAX_TX_PER_BLOCK, state.height)
        .into_iter()
        .map(|e| e.tx.clone())
        .collect();

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
        protocol_version:    ProtocolVersion::CURRENT,
        height,
        prev_hash:           state.tip_hash,
        timestamp:           template.timestamp,
        // state_root and validator_set_root are computed AFTER block application
        // (in Phase 5 when we have persistent Merkle tries)
        state_root:          Bytes32::ZERO,
        validator_set_root:  Bytes32::ZERO,
        mempool_set_root:    compute_mempool_root(mempool, state.height),
        base_fee:            state.base_fee,
        proposer_vrf_output: Bytes32::from(slot.vrf_output.0),
        proposer_vrf_proof:  vrf_proof_bytes,
        quorum_certificate:  qc_bytes,
    };

    Ok(BlockV1 {
        header,
        transactions:      selected,
        slashing_evidence: vec![],
        governance_ops:    vec![],
    })
}

/// Compute a simple mempool root: SHA-256 of all tx_ids sorted and hashed.
///
/// In Phase 5 this becomes a proper Merkle root. For now it's a
/// commitment to the mempool state that enables basic censorship detection.
fn compute_mempool_root(mempool: &Mempool, _current_height: u64) -> Bytes32 {
    use indra_crypto::sha256;
    let mut tx_ids: Vec<[u8; 32]> = mempool
        .iter()
        .map(|e| e.tx_id.0)
        .collect();
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
    use indra_state::ChainState;
    use indra_crypto::VrfKeypair;
    use crate::{
        mempool::Mempool,
    };

    fn make_election(seed: &[u8; 32], height: u64, vrf_pk: [u8; 32], stake: u64) -> ProposerElection {
        // VrfKeypair::from_seed(vrf_pk).public_key() == sha256(vrf_pk)
        // compute_proposer_vrf returns proposer_id = sha256(public_key) = sha256(sha256(vrf_pk))
        // elect_proposer uses candidate.vrf_pubkey as the seed, same derivation, so IDs match.
        ProposerElection {
            epoch_seed: Bytes32::from(*seed),
            height,
            candidates: vec![
                crate::proposer::ProposerCandidate {
                    validator_id: Bytes32::from(indra_crypto::sha256(&indra_crypto::VrfKeypair::from_seed(&vrf_pk).public_key())),
                    vrf_pubkey:   vrf_pk,
                    stake,
                }
            ],
        }
    }

    #[test]
    fn produce_empty_block() {
        let state = ChainState::new_genesis();
        let mempool = Mempool::default_config();
        let seed = [0x42u8; 32];
        let election = make_election(&seed, 1, seed, 1_000_000);

        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&seed),
            epoch_seed: Bytes32::from(seed),
            prev_qc_bytes: vec![],
            timestamp: 1_700_000_001,
        };

        let block = produce_block(&template, &state, &mempool, &election).unwrap();
        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.prev_hash, state.tip_hash);
        assert_eq!(block.transactions.len(), 0);
    }

    #[test]
    fn wrong_proposer_rejected() {
        let state = ChainState::new_genesis();
        let mempool = Mempool::default_config();
        let seed = [0x42u8; 32];
        let wrong_seed = [0x99u8; 32];

        // Election uses seed 0x42, but template uses wrong_seed
        let election = make_election(&seed, 1, seed, 1_000_000);
        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&wrong_seed),
            epoch_seed: Bytes32::from(seed),
            prev_qc_bytes: vec![],
            timestamp: 1_700_000_001,
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
        let election = make_election(&seed, 1, seed, 1_000_000);
        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&seed),
            epoch_seed: Bytes32::from(seed),
            prev_qc_bytes: vec![],
            timestamp: 1_700_000_001,
        };
        let block = produce_block(&template, &state, &mempool, &election).unwrap();
        assert_eq!(block.header.height, state.height + 1);
    }
}
