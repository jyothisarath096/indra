//! Block import and chain sync.
//!
//! `import_block` is the single entry point for adding a block to the chain.
//! It:
//!   1. Validates the block's structural invariants
//!   2. Applies it to the chain state via `apply_block`
//!   3. Computes and stores the new state root
//!   4. Writes the block to the block store
//!   5. Evicts spent transactions from the mempool
//!   6. Optionally takes a state snapshot

use indra_core::types::block::BlockV1;
use indra_core::codec::Decode;
use indra_state::{apply_block, ChainState};
use indra_consensus::mempool::Mempool;
use indra_storage::{BlockStore, StateStore};
use indra_storage::state_store::SNAPSHOT_INTERVAL;
use indra_consensus::{
    proposer::{ProposerCandidate, compute_vrf_input},
    qc::{QcValidator, verify_qc, verify_qc_strict},
};
use indra_crypto::{VrfOutput, VrfProof, vrf_verify};

use crate::{
    error::{NodeError, NodeResult},
    genesis::build_genesis_block,
    state_root::{compute_state_root, compute_validator_set_root},
};

/// Import a block into the chain.
///
/// This is the canonical block processing pipeline:
/// validate → apply → store → evict mempool → snapshot.
pub fn import_block(
    block: &BlockV1,
    state: &mut ChainState,
    mempool: &mut Mempool,
    block_store: &mut BlockStore,
    state_store: &StateStore,
    strict_header_verification: bool,
) -> NodeResult<()> {
    let height = block.header.height;

    if state.validators.active_count() > 0 {
        verify_proposer_vrf(block, state, strict_header_verification)?;
    }

    if height > 1 {
        verify_block_qc(block, state, strict_header_verification)?;
    }

    verify_block_state_root(block, state, strict_header_verification)?;

    // 1. Apply block to state (validates everything)
    apply_block(state, block).map_err(|e| NodeError::BlockInvalid {
        height,
        reason: e.to_string(),
    })?;

    // 2. Compute state root and store it in the state
    //    (the block header's state_root is checked against this in Phase 6)
    let _state_root = compute_state_root(state);

    // 3. Store genesis placeholder if block_store is empty and this is height 1
    if block_store.is_empty() && height == 1 {
        let genesis = crate::genesis::build_genesis_block();
        block_store.append(&genesis)?;
    }
    block_store.append(block)?;

    // 4. Evict spent transactions from mempool
    mempool.evict_spent(&state.nullifiers);

    // 5. Take snapshot if on interval
    if height % SNAPSHOT_INTERVAL == 0 && height > 0 {
        state_store.save(state)?;
    }

    Ok(())
}

fn verify_proposer_vrf(
    block: &BlockV1,
    state: &ChainState,
    strict: bool,
) -> NodeResult<()> {
    let proof_bytes = block.header.proposer_vrf_proof.as_slice();
    let output = block.header.proposer_vrf_output;

    if proof_bytes.is_empty() || output == indra_core::Bytes32::ZERO {
        if strict {
            return Err(NodeError::BlockInvalid {
                height: block.header.height,
                reason: "missing proposer VRF proof/output".to_string(),
            });
        }
        eprintln!(
            "[sync] warning: skipping proposer VRF verification at height {} because the header uses placeholder VRF fields",
            block.header.height
        );
        return Ok(());
    }

    let candidates: Vec<ProposerCandidate> = state.validators.active_validators()
        .filter_map(|validator| validator.vrf_pk.map(|vrf_pk| ProposerCandidate {
            validator_id: validator.validator_id,
            vrf_pubkey: vrf_pk,
            stake: validator.stake_spark,
        }))
        .collect();

    if candidates.len() != state.validators.active_count() {
        if strict {
            return Err(NodeError::BlockInvalid {
                height: block.header.height,
                reason: "active validator set is missing VRF public keys".to_string(),
            });
        }
        eprintln!(
            "[sync] warning: skipping proposer VRF verification at height {} because validator VRF keys are incomplete",
            block.header.height
        );
        return Ok(());
    }

    let vrf_input = compute_vrf_input(&state.tip_hash.0, block.header.height);
    let proof = VrfProof(proof_bytes.to_vec());
    let output = VrfOutput(block.header.proposer_vrf_output.0);

    let matching_candidates: Vec<_> = candidates.iter()
        .filter(|candidate| vrf_verify(&candidate.vrf_pubkey, &vrf_input, &output, &proof).is_ok())
        .collect();

    if matching_candidates.len() != 1 {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: "proposer VRF proof does not match exactly one active validator".to_string(),
        });
    }

    // NOTE: the current block header does not carry enough information to
    // re-run the full stake-weighted proposer election for every validator.
    // This check proves ownership of the VRF proof by an active validator and
    // fails closed on ambiguity; a future header revision should commit the
    // elected proposer identity or the election transcript explicitly.
    Ok(())
}

fn verify_block_qc(
    block: &BlockV1,
    state: &ChainState,
    strict: bool,
) -> NodeResult<()> {
    let qc_bytes = block.header.quorum_certificate.as_slice();
    if qc_bytes.is_empty() {
        if strict {
            return Err(NodeError::BlockInvalid {
                height: block.header.height,
                reason: "missing quorum certificate".to_string(),
            });
        }
        eprintln!(
            "[sync] warning: skipping QC verification at height {} because the header carries an empty QC",
            block.header.height
        );
        return Ok(());
    }

    let mut reader = indra_core::codec::ByteReader::new(qc_bytes);
    let qc = indra_core::types::qc::QuorumCertificateV1::decode(&mut reader).map_err(|e| {
        NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!("invalid QC encoding: {e}"),
        }
    })?;

    let mut active_validators: Vec<_> = state.validators.active_validators().collect();
    active_validators.sort_by_key(|validator| validator.validator_id.0);

    let validators: Vec<QcValidator> = active_validators.into_iter()
        .enumerate()
        .filter_map(|(position, validator)| Some(QcValidator {
            validator_id: validator.validator_id,
            position,
            bls_pk: validator.bls_pk?,
            pq_pk: validator.hybrid_pq_pk.clone()?,
            stake: validator.stake_spark,
        }))
        .collect();

    if validators.len() != state.validators.active_count() {
        if strict {
            return Err(NodeError::BlockInvalid {
                height: block.header.height,
                reason: "active validator set is missing QC verification keys".to_string(),
            });
        }
        eprintln!(
            "[sync] warning: skipping QC verification at height {} because validator verification keys are incomplete",
            block.header.height
        );
        return Ok(());
    }

    let total_stake = state.validators.total_active_stake();
    let result = if strict {
        verify_qc_strict(&qc, &validators, total_stake)
    } else {
        verify_qc(&qc, &validators, total_stake)
    };
    result.map_err(NodeError::Consensus)
}

fn verify_block_state_root(
    block: &BlockV1,
    state: &ChainState,
    strict: bool,
) -> NodeResult<()> {
    let expected_state_root = block.header.state_root;
    let expected_validator_root = block.header.validator_set_root;

    if expected_state_root == indra_core::Bytes32::ZERO
        && expected_validator_root == indra_core::Bytes32::ZERO
    {
        if strict {
            return Err(NodeError::BlockInvalid {
                height: block.header.height,
                reason: "missing state_root and validator_set_root".to_string(),
            });
        }
        eprintln!(
            "[sync] warning: skipping state-root verification at height {} because the header uses placeholder roots",
            block.header.height
        );
        return Ok(());
    }

    let mut projected = state.clone();
    apply_block(&mut projected, block).map_err(|e| NodeError::BlockInvalid {
        height: block.header.height,
        reason: format!("block failed during pre-apply root verification: {e}"),
    })?;

    let actual_state_root = compute_state_root(&projected);
    if expected_state_root != indra_core::Bytes32::ZERO && actual_state_root != expected_state_root {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: "state_root mismatch".to_string(),
        });
    }

    let actual_validator_root = compute_validator_set_root(&projected);
    if expected_validator_root != indra_core::Bytes32::ZERO
        && actual_validator_root != expected_validator_root
    {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: "validator_set_root mismatch".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        Bytes32, ProtocolVersion, VariableBytes,
        types::{
            block::{BlockHeaderV1, BlockV1},
            primitives::{INITIAL_BASE_FEE_SPARK_PER_KB, MAX_VRF_PROOF_BYTES},
        },
    };
    use indra_storage::StateStore;
    use std::path::PathBuf;

    fn temp_dir(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_sync_test_{}_{}", suffix, std::process::id()));
        p
    }

    fn make_block(height: u64, prev_hash: Bytes32, base_fee: u64) -> BlockV1 {
        BlockV1 {
            header: BlockHeaderV1 {
                protocol_version:    ProtocolVersion::CURRENT,
                height,
                prev_hash,
                timestamp:           1_700_000_000 + height,
                state_root:          Bytes32::ZERO,
                validator_set_root:  Bytes32::ZERO,
                mempool_set_root:    Bytes32::ZERO,
                base_fee,
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof:  VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
                quorum_certificate:  indra_core::VariableBytes::from_slice(&[]).unwrap(),
            },
            transactions:      vec![],
            slashing_evidence: vec![],
            governance_ops:    vec![],
        }
    }

    #[test]
    fn import_single_block() {
        let dir = temp_dir("a");
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = ChainState::new_genesis();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(dir.join("blocks.log")).unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        let block = make_block(1, state.tip_hash, INITIAL_BASE_FEE_SPARK_PER_KB);
        import_block(&block, &mut state, &mut mempool, &mut block_store, &state_store, false).unwrap();

        assert_eq!(state.height, 1);
        assert_eq!(block_store.len(), 2); // genesis (0) + block 1

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_chain_of_blocks() {
        let dir = temp_dir("b");
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = ChainState::new_genesis();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(dir.join("blocks.log")).unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        for i in 1..=10u64 {
            let block = make_block(i, state.tip_hash, state.base_fee);
            import_block(&block, &mut state, &mut mempool, &mut block_store, &state_store, false).unwrap();
        }

        assert_eq!(state.height, 10);
        assert_eq!(block_store.len(), 11); // genesis (0) + blocks 1-10

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_height_rejected() {
        let dir = temp_dir("c");
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = ChainState::new_genesis();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(dir.join("blocks.log")).unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        // Try to import height 5 when we're at genesis (height 0)
        let block = make_block(5, state.tip_hash, state.base_fee);
        assert!(import_block(&block, &mut state, &mut mempool, &mut block_store, &state_store, false).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
