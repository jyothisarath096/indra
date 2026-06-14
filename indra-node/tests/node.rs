//! Integration tests for the full node pipeline.

use std::path::PathBuf;
use indra_core::{
    Bytes32, ProtocolVersion, VariableBytes,
    types::{
        block::{BlockHeaderV1, BlockV1},
        primitives::MAX_VRF_PROOF_BYTES,
    },
};
use indra_state::{ChainState, apply_block, compute_validator_set_root};
use indra_consensus::mempool::Mempool;
use indra_storage::{BlockStore, PruneConfig, StateStore};
use indra_node::{
    NodeConfig, NodeEngine,
    genesis::{build_genesis_state, genesis_block_hash},
    state_root::compute_state_root,
    sync::import_block,
};

fn temp_dir(suffix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("indra_node_test_{}_{}", suffix, std::process::id()));
    p
}

fn make_block(state: &ChainState) -> BlockV1 {
    let mut block = BlockV1 {
        header: BlockHeaderV1 {
            protocol_version:    ProtocolVersion::CURRENT,
            height:              state.height + 1,
            prev_hash:           state.tip_hash,
            timestamp:           1_700_000_000 + state.height + 1,
            state_root:          Bytes32::ZERO,
            validator_set_root:  Bytes32::ZERO,
            mempool_set_root:    Bytes32::ZERO,
            value_hash:          Bytes32::ZERO,
            base_fee:            state.base_fee,
            proposer_round:      0,
            polc_round:          indra_core::types::block::NO_POLC_ROUND,
            proposer_vrf_output: Bytes32::ZERO,
            proposer_vrf_proof:  VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
            quorum_certificate:  indra_core::VariableBytes::from_slice(&[]).unwrap(),
        },
        transactions:      vec![],
        slashing_evidence: vec![],
        governance_ops:    vec![],
    };

    let mut projected = state.clone();
    apply_block(&mut projected, &block).unwrap();
    block.header.state_root = compute_state_root(&projected);
    block.header.validator_set_root = compute_validator_set_root(&projected);
    block.header.value_hash = block.compute_value_hash(projected.total_supply);
    block
}

#[test]
fn genesis_is_deterministic() {
    let h1 = genesis_block_hash();
    let h2 = genesis_block_hash();
    assert_eq!(h1, h2);
}

#[test]
fn node_engine_init_and_commit() {
    let dir = temp_dir("engine");
    let config = NodeConfig::local_test(dir.clone());
    let mut engine = NodeEngine::init(config).unwrap();

    assert_eq!(engine.height(), 0);

    // Commit 5 blocks
    for i in 1..=5u64 {
        let block = make_block(&engine.state);
        engine.commit_block(&block).unwrap();
        assert_eq!(engine.height(), i);
    }

    assert_eq!(engine.height(), 5);
    assert_eq!(engine.block_store.len(), 6); // genesis + 5 blocks
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn state_root_changes_after_each_block() {
    let dir = temp_dir("roots");
    std::fs::create_dir_all(&dir).unwrap();

    let mut state = ChainState::new_genesis();
    let mut mempool = Mempool::default_config();
    let mut block_store = BlockStore::open(dir.join("blocks.log"), PruneConfig::archive()).unwrap();
    let state_store = StateStore::open(dir.join("state")).unwrap();

    let root0 = compute_state_root(&state);

    let b1 = make_block(&state);
    import_block(&b1, &mut state, &mut mempool, &mut block_store, &state_store, false).unwrap();
    let root1 = compute_state_root(&state);

    let b2 = make_block(&state);
    import_block(&b2, &mut state, &mut mempool, &mut block_store, &state_store, false).unwrap();
    let root2 = compute_state_root(&state);

    assert_ne!(root0, root1);
    assert_ne!(root1, root2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn block_store_survives_reopen() {
    let dir = temp_dir("reopen");
    std::fs::create_dir_all(&dir).unwrap();
    let log_path = dir.join("blocks.log");

    {
        let mut state = ChainState::new_genesis();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(&log_path, PruneConfig::archive()).unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        for i in 1..=3u64 {
            let b = make_block(&state);
            import_block(&b, &mut state, &mut mempool, &mut block_store, &state_store, false).unwrap();
            assert_eq!(state.height, i);
        }
    }

    // Reopen and verify blocks are still there
    let mut store2 = BlockStore::open(&log_path, PruneConfig::archive()).unwrap();
    assert_eq!(store2.len(), 4); // genesis + 3 blocks
    assert_eq!(store2.get(1).unwrap().header.height, 1);
    assert_eq!(store2.get(3).unwrap().header.height, 3);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn snapshot_and_restore() {
    let dir = temp_dir("snapshot");
    std::fs::create_dir_all(&dir).unwrap();

    let state_store = StateStore::open(dir.join("state")).unwrap();

    let mut state = ChainState::new_genesis();
    state.height = 300;
    state.base_fee = 999;

    state_store.save(&state).unwrap();

    let restored = state_store.load_latest().unwrap().unwrap();
    assert_eq!(restored.height, 300);
    assert_eq!(restored.base_fee, 999);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn full_node_pipeline() {
    // Complete pipeline: genesis → import blocks → state roots → snapshot
    let dir = temp_dir("full");
    std::fs::create_dir_all(&dir).unwrap();

    let mut state = build_genesis_state();
    let mut mempool = Mempool::default_config();
    let mut block_store = BlockStore::open(dir.join("blocks.log"), PruneConfig::archive()).unwrap();
    let state_store = StateStore::open(dir.join("state")).unwrap();

    let roots: Vec<Bytes32> = (1..=10u64).map(|i| {
        let b = make_block(&state);
        import_block(&b, &mut state, &mut mempool, &mut block_store, &state_store, false).unwrap();
        assert_eq!(state.height, i);
        compute_state_root(&state)
    }).collect();

    // All roots are distinct
    for i in 0..roots.len() - 1 {
        assert_ne!(roots[i], roots[i + 1], "roots[{i}] == roots[{}]", i + 1);
    }

    assert_eq!(state.height, 10);
    assert_eq!(block_store.len(), 11); // genesis + 10 blocks
    let _ = std::fs::remove_dir_all(&dir);
}
