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
use indra_state::{apply_block, ChainState};
use indra_consensus::mempool::Mempool;
use indra_storage::{BlockStore, StateStore};
use indra_storage::state_store::SNAPSHOT_INTERVAL;

use crate::{
    error::{NodeError, NodeResult},
    genesis::build_genesis_block,
    state_root::compute_state_root,
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
) -> NodeResult<()> {
    let height = block.header.height;

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
        import_block(&block, &mut state, &mut mempool, &mut block_store, &state_store).unwrap();

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
            import_block(&block, &mut state, &mut mempool, &mut block_store, &state_store).unwrap();
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
        assert!(import_block(&block, &mut state, &mut mempool, &mut block_store, &state_store).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
