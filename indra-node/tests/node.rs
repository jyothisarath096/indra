//! Integration tests for the full node pipeline.

use indra_consensus::mempool::Mempool;
use indra_consensus::{
    build_qc,
    producer::{produce_block, BlockTemplate},
    proposer::ProposerCandidate,
    qc::QcValidator,
    vote::produce_vote,
};
use indra_core::{
    codec::{Decode, Encode},
    types::{block::BlockV1, vote::VoteStep},
    Bytes32,
};
use indra_crypto::{
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    VrfKeypair,
};
use indra_node::{
    driver::{ConsensusDriver, DriverAction, DriverEvent},
    genesis::{build_genesis_state, genesis_block_hash},
    state_root::compute_state_root,
    sync::{import_block, SyncState},
    NodeConfig, NodeEngine,
};
use indra_state::ChainState;
use indra_storage::{BlockStore, PruneConfig, StateStore};
use std::path::PathBuf;

fn temp_dir(suffix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("indra_node_test_{}_{}", suffix, std::process::id()));
    p
}

fn anchored_genesis_state() -> ChainState {
    let mut state = ChainState::new_genesis();
    state.tip_hash = genesis_block_hash();
    state
}

fn make_strict_block(
    state: &ChainState,
    proposer_seed: [u8; 32],
    prev_qc_bytes: Vec<u8>,
) -> BlockV1 {
    let epoch_seed = Bytes32::from(indra_crypto::sha256(&state.tip_hash.0));
    let mut candidates: Vec<_> = state
        .validators
        .active_validators()
        .filter_map(|validator| {
            validator.vrf_pk.map(|vrf_pk| ProposerCandidate {
                validator_id: validator.validator_id,
                vrf_pubkey: vrf_pk,
                stake: validator.stake_spark,
            })
        })
        .collect();
    candidates.sort_by_key(|candidate| candidate.validator_id.0);
    let election = indra_consensus::proposer::ProposerElection {
        epoch_seed,
        height: state.height + 1,
        round: 0,
        candidates,
    };
    let template = BlockTemplate {
        proposer_vrf_keypair: VrfKeypair::from_seed(&proposer_seed),
        epoch_seed: election.epoch_seed,
        prev_qc_bytes,
        timestamp: 1_700_000_000 + state.height + 1,
        polc_round: None,
        slash_evidence: vec![],
        staking_ops: vec![],
    };
    produce_block(&template, state, &Mempool::default_config(), &election).unwrap()
}

fn install_active_validator(
    driver: &mut ConsensusDriver,
    seed: [u8; 32],
    name: &str,
) -> HybridKeypair {
    let classical = ClassicalKeypair::from_seed(&seed);
    let pq = PqKeypair::from_seed(&seed).unwrap();
    let hybrid = HybridKeypair::new(classical, pq);
    let public = hybrid.public_key();
    let vrf_pk = VrfKeypair::from_seed(&seed).public_key();
    let validator_id = Bytes32::from(indra_crypto::sha256(&public.classical.0));

    driver
        .engine
        .state
        .validators
        .upsert(indra_state::ValidatorEntry {
            validator_id,
            name: name.to_string(),
            hybrid_classical_pk: Some(public.classical.0),
            hybrid_pq_pk: Some(public.pq.0.to_vec()),
            vrf_pk: Some(vrf_pk),
            stake_spark: 1_000_000,
            status: indra_state::ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            pending_rewards: 0,
            rewards_last_epoch: 0,
            self_report_count: 0,
            commission_bps: indra_core::types::primitives::DEFAULT_COMMISSION_BPS,
            min_delegation_spark: indra_core::types::primitives::DUST_LIMIT_SPARK,
        })
        .unwrap();
    hybrid
}

fn install_state_validator(state: &mut ChainState, seed: [u8; 32], name: &str) -> HybridKeypair {
    let classical = ClassicalKeypair::from_seed(&seed);
    let pq = PqKeypair::from_seed(&seed).unwrap();
    let hybrid = HybridKeypair::new(classical, pq);
    let public = hybrid.public_key();
    let vrf_pk = VrfKeypair::from_seed(&seed).public_key();
    let validator_id = Bytes32::from(indra_crypto::sha256(&public.classical.0));

    state
        .validators
        .upsert(indra_state::ValidatorEntry {
            validator_id,
            name: name.to_string(),
            hybrid_classical_pk: Some(public.classical.0),
            hybrid_pq_pk: Some(public.pq.0.to_vec()),
            vrf_pk: Some(vrf_pk),
            stake_spark: 1_000_000,
            status: indra_state::ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            pending_rewards: 0,
            rewards_last_epoch: 0,
            self_report_count: 0,
            commission_bps: indra_core::types::primitives::DEFAULT_COMMISSION_BPS,
            min_delegation_spark: indra_core::types::primitives::DUST_LIMIT_SPARK,
        })
        .unwrap();
    hybrid
}

fn build_single_validator_qc_bytes(
    height: u64,
    round: u32,
    value_hash: Bytes32,
    seed: [u8; 32],
) -> Vec<u8> {
    let classical = ClassicalKeypair::from_seed(&seed);
    let pq = PqKeypair::from_seed(&seed).unwrap();
    let hybrid = HybridKeypair::new(classical, pq);
    let public = hybrid.public_key();
    let validator_id = Bytes32::from(indra_crypto::sha256(&public.classical.0));
    let vote = produce_vote(
        height,
        round,
        VoteStep::Precommit,
        value_hash,
        validator_id,
        &hybrid,
    )
    .unwrap();
    let qc = build_qc(
        height,
        round,
        value_hash,
        &[QcValidator {
            validator_id,
            position: 0,
            pq_pk: public.pq.0.to_vec(),
            stake: 1_000_000,
        }],
        vec![&vote],
    )
    .unwrap();
    qc.encode_to_vec()
}

fn local_driver(seed: [u8; 32], suffix: &str) -> (ConsensusDriver, PathBuf) {
    let dir = temp_dir(suffix);
    let mut config = NodeConfig::local_test(dir.clone());
    let pq = PqKeypair::from_seed(&seed).unwrap();
    config.validator_seed = Some(seed);
    config.vrf_seed = Some(seed);
    config.pq_pk = Some(pq.public_key().0.to_vec());
    config.pq_sk = Some(pq.secret_key_bytes());
    let engine = NodeEngine::init(config).unwrap();
    (ConsensusDriver::new(engine), dir)
}

fn assert_block_log_roundtrip_and_links(log_path: &std::path::Path) {
    let mut store = BlockStore::open(log_path, PruneConfig::archive()).unwrap();
    let mut previous: Option<BlockV1> = None;

    for height in 0..store.next_height() {
        let block = store.get(height).unwrap();
        let encoded = indra_core::codec::Encode::encode_to_vec(&block);
        let decoded = BlockV1::decode_exact(&encoded).unwrap();
        assert_eq!(decoded, block, "round-trip mismatch at height {}", height);

        if let Some(prev) = &previous {
            assert_eq!(
                block.header.prev_hash,
                prev.header.block_hash(),
                "hash chain mismatch at height {}",
                height
            );
        }

        previous = Some(block);
    }
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
    install_state_validator(&mut engine.state, [0x42u8; 32], "local");

    assert_eq!(engine.height(), 0);

    // Commit 5 blocks
    let mut last_qc = Vec::new();
    for i in 1..=5u64 {
        let block = make_strict_block(&engine.state, [0x42u8; 32], last_qc.clone());
        engine.commit_block(&block).unwrap();
        last_qc = build_single_validator_qc_bytes(i, 0, block.header.value_hash, [0x42u8; 32]);
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

    let mut state = anchored_genesis_state();
    install_state_validator(&mut state, [0x11u8; 32], "local");
    let mut mempool = Mempool::default_config();
    let mut block_store = BlockStore::open(dir.join("blocks.log"), PruneConfig::archive()).unwrap();
    let state_store = StateStore::open(dir.join("state")).unwrap();

    let root0 = compute_state_root(&state);

    let b1 = make_strict_block(&state, [0x11u8; 32], vec![]);
    import_block(
        &b1,
        &mut state,
        &mut mempool,
        &mut block_store,
        &state_store,
    )
    .unwrap();
    let root1 = compute_state_root(&state);

    let qc1 = build_single_validator_qc_bytes(1, 0, b1.header.value_hash, [0x11u8; 32]);
    let b2 = make_strict_block(&state, [0x11u8; 32], qc1);
    import_block(
        &b2,
        &mut state,
        &mut mempool,
        &mut block_store,
        &state_store,
    )
    .unwrap();
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
        let mut state = anchored_genesis_state();
        install_state_validator(&mut state, [0x12u8; 32], "local");
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(&log_path, PruneConfig::archive()).unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        let mut last_qc = Vec::new();
        for i in 1..=3u64 {
            let b = make_strict_block(&state, [0x12u8; 32], last_qc.clone());
            import_block(&b, &mut state, &mut mempool, &mut block_store, &state_store).unwrap();
            last_qc = build_single_validator_qc_bytes(i, 0, b.header.value_hash, [0x12u8; 32]);
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
fn restarted_block_store_preserves_hash_chain() {
    let dir = temp_dir("restart_chain");
    std::fs::create_dir_all(&dir).unwrap();
    let config = NodeConfig::local_test(dir.clone());

    {
        let mut engine = NodeEngine::init(config.clone()).unwrap();
        install_state_validator(&mut engine.state, [0x42u8; 32], "local");
        let mut last_qc = Vec::new();
        for _ in 0..5u64 {
            let height = engine.state.height + 1;
            let block = make_strict_block(&engine.state, [0x42u8; 32], last_qc.clone());
            engine.commit_block(&block).unwrap();
            last_qc =
                build_single_validator_qc_bytes(height, 0, block.header.value_hash, [0x42u8; 32]);
        }
    }

    let log_path = dir.join("blocks.log");
    assert_block_log_roundtrip_and_links(&log_path);

    let restarted = NodeEngine::init(config).unwrap();
    assert_eq!(restarted.height(), 5);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sync_state_downloads_full_chain_from_genesis() {
    let dir = temp_dir("sync_chain");
    std::fs::create_dir_all(&dir).unwrap();
    let source_log = dir.join("source.log");
    let follower_log = dir.join("follower.log");
    let source_state_dir = dir.join("source_state");
    let follower_state_dir = dir.join("follower_state");

    let mut source_state = anchored_genesis_state();
    install_state_validator(&mut source_state, [0x13u8; 32], "source");
    let mut source_mempool = Mempool::default_config();
    let mut source_store = BlockStore::open(&source_log, PruneConfig::archive()).unwrap();
    let source_state_store = StateStore::open(&source_state_dir).unwrap();

    let mut source_last_qc = Vec::new();
    for _ in 0..6u64 {
        let height = source_state.height + 1;
        let block = make_strict_block(&source_state, [0x13u8; 32], source_last_qc.clone());
        import_block(
            &block,
            &mut source_state,
            &mut source_mempool,
            &mut source_store,
            &source_state_store,
        )
        .unwrap();
        source_last_qc =
            build_single_validator_qc_bytes(height, 0, block.header.value_hash, [0x13u8; 32]);
    }

    let peer: std::net::SocketAddr = "127.0.0.1:30303".parse().unwrap();
    let mut follower_state = anchored_genesis_state();
    install_state_validator(&mut follower_state, [0x13u8; 32], "source");
    let mut follower_mempool = Mempool::default_config();
    let mut follower_store = BlockStore::open(&follower_log, PruneConfig::archive()).unwrap();
    let follower_state_store = StateStore::open(&follower_state_dir).unwrap();
    let mut sync = SyncState::follower(follower_state.height);

    let request = sync.observe_status(peer, source_state.height, follower_state.height);
    assert_eq!(request, Some((peer, 1, source_state.height)));

    for height in 1..=source_state.height {
        let block = source_store.get(height).unwrap();
        import_block(
            &block,
            &mut follower_state,
            &mut follower_mempool,
            &mut follower_store,
            &follower_state_store,
        )
        .unwrap();
        sync.on_block_imported(height);
    }

    assert!(sync
        .next_request_after_response(follower_state.height)
        .is_none());
    assert!(sync.is_caught_up());
    assert_eq!(follower_state.height, source_state.height);
    assert_block_log_roundtrip_and_links(&follower_log);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn current_binary_hashes_workspace_block_log_consistently() {
    let dir = temp_dir("generated_hash_chain");
    std::fs::create_dir_all(&dir).unwrap();

    let config = NodeConfig::local_test(dir.clone());
    {
        let mut engine = NodeEngine::init(config.clone()).unwrap();
        install_state_validator(&mut engine.state, [0x42u8; 32], "local");
        let mut last_qc = Vec::new();
        for _ in 0..3u64 {
            let height = engine.state.height + 1;
            let block = make_strict_block(&engine.state, [0x42u8; 32], last_qc.clone());
            engine.commit_block(&block).unwrap();
            last_qc =
                build_single_validator_qc_bytes(height, 0, block.header.value_hash, [0x42u8; 32]);
        }
    }

    let block_log = dir.join("blocks.log");
    let mut store = BlockStore::open(&block_log, PruneConfig::archive()).unwrap();
    assert!(store.next_height() > 2, "generated block log is too short");

    let genesis = store.get(0).unwrap();
    let block1 = store.get(1).unwrap();
    let block2 = store.get(2).unwrap();
    assert_eq!(
        block1.header.prev_hash,
        genesis.header.block_hash(),
        "block 1 prev_hash must match genesis block hash",
    );
    assert_eq!(
        block1.header.block_hash(),
        block2.header.prev_hash,
        "block 1 hash must match block 2 prev_hash",
    );

    assert_block_log_roundtrip_and_links(&block_log);
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
    state.tip_hash = genesis_block_hash();
    install_state_validator(&mut state, [0x14u8; 32], "local");
    let mut mempool = Mempool::default_config();
    let mut block_store = BlockStore::open(dir.join("blocks.log"), PruneConfig::archive()).unwrap();
    let state_store = StateStore::open(dir.join("state")).unwrap();

    let mut last_qc = Vec::new();
    let roots: Vec<Bytes32> = (1..=10u64)
        .map(|i| {
            let b = make_strict_block(&state, [0x14u8; 32], last_qc.clone());
            import_block(&b, &mut state, &mut mempool, &mut block_store, &state_store).unwrap();
            last_qc = build_single_validator_qc_bytes(i, 0, b.header.value_hash, [0x14u8; 32]);
            assert_eq!(state.height, i);
            compute_state_root(&state)
        })
        .collect();

    // All roots are distinct
    for i in 0..roots.len() - 1 {
        assert_ne!(roots[i], roots[i + 1], "roots[{i}] == roots[{}]", i + 1);
    }

    assert_eq!(state.height, 10);
    assert_eq!(block_store.len(), 11); // genesis + 10 blocks
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn node_syncs_before_joining_consensus() {
    let (mut driver, dir) = local_driver([0x71u8; 32], "join_after_sync");
    let _local = install_active_validator(&mut driver, [0x71u8; 32], "local");
    let remote = install_active_validator(&mut driver, [0x72u8; 32], "remote");
    driver.refresh_registered_voters();

    let peer: std::net::SocketAddr = "127.0.0.1:30303".parse().unwrap();
    let local_height = driver.height();
    let _ = driver.sync_mut().observe_status(peer, 10, local_height);
    assert!(!driver.sync().is_caught_up());

    let remote_id = Bytes32::from(indra_crypto::sha256(&remote.public_key().classical.0));
    let vote = indra_consensus::vote::produce_vote(
        1,
        0,
        VoteStep::Prevote,
        Bytes32::from([0xCCu8; 32]),
        remote_id,
        &remote,
    )
    .unwrap();

    let actions = driver.process(DriverEvent::InboundVote { from: peer, vote });
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastVote(_))),
        "node must not vote before catching up"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn full_restart_recovery_end_to_end() {
    let dir = temp_dir("restart_recovery");
    std::fs::create_dir_all(&dir).unwrap();

    let source_log = dir.join("source.log");
    let follower_a_log = dir.join("follower_a.log");
    let follower_b_log = dir.join("follower_b.log");
    let source_state_dir = dir.join("source_state");
    let follower_a_state_dir = dir.join("follower_a_state");
    let follower_b_state_dir = dir.join("follower_b_state");

    let mut source_state = anchored_genesis_state();
    install_state_validator(&mut source_state, [0x15u8; 32], "source");
    let mut source_mempool = Mempool::default_config();
    let mut source_store = BlockStore::open(&source_log, PruneConfig::archive()).unwrap();
    let source_state_store = StateStore::open(&source_state_dir).unwrap();

    let mut source_last_qc = Vec::new();
    for _ in 0..2u64 {
        let height = source_state.height + 1;
        let block = make_strict_block(&source_state, [0x15u8; 32], source_last_qc.clone());
        import_block(
            &block,
            &mut source_state,
            &mut source_mempool,
            &mut source_store,
            &source_state_store,
        )
        .unwrap();
        source_last_qc =
            build_single_validator_qc_bytes(height, 0, block.header.value_hash, [0x15u8; 32]);
    }

    for (follower_log, follower_state_dir) in [
        (&follower_a_log, &follower_a_state_dir),
        (&follower_b_log, &follower_b_state_dir),
    ] {
        let mut follower_state = anchored_genesis_state();
        install_state_validator(&mut follower_state, [0x15u8; 32], "source");
        let mut follower_mempool = Mempool::default_config();
        let mut follower_store = BlockStore::open(follower_log, PruneConfig::archive()).unwrap();
        let follower_state_store = StateStore::open(follower_state_dir).unwrap();

        let block1 = source_store.get(1).unwrap();
        import_block(
            &block1,
            &mut follower_state,
            &mut follower_mempool,
            &mut follower_store,
            &follower_state_store,
        )
        .unwrap();

        let peer: std::net::SocketAddr = "127.0.0.1:30304".parse().unwrap();
        let mut sync = SyncState::follower(follower_state.height);
        assert_eq!(
            sync.observe_status(peer, source_state.height, follower_state.height),
            Some((peer, 2, 2))
        );

        let block2 = source_store.get(2).unwrap();
        import_block(
            &block2,
            &mut follower_state,
            &mut follower_mempool,
            &mut follower_store,
            &follower_state_store,
        )
        .unwrap();
        sync.on_block_imported(2);
        assert!(sync.is_caught_up());
        assert_eq!(follower_state.height, source_state.height);
    }

    let _ = std::fs::remove_dir_all(&dir);
}
