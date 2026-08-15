//! Integration tests for the full node pipeline.

use indra_consensus::mempool::Mempool;
use indra_consensus::{
    build_qc,
    producer::{produce_block, BlockTemplate},
    proposer::{compute_proposer_vrf, ProposerCandidate},
    qc::QcValidator,
    vote::produce_vote,
};
use indra_core::{
    codec::{Decode, Encode},
    types::{
        crypto::HybridSignature,
        primitives::{VariableBytes, DEFAULT_CHAIN_ID},
        vote::{VoteStep, VoteV1},
    },
    Bytes32,
};
use indra_crypto::{
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    VrfKeypair,
};
use indra_network::{
    observer::{NODE_TYPE_FULL, NODE_TYPE_OBSERVER},
    perform_observer_handshake_initiator, perform_observer_handshake_responder, read_frame_plain,
    write_frame_plain, Message,
};
use indra_node::{
    driver::{ConsensusDriver, DriverAction, DriverEvent},
    genesis::{build_genesis_state, genesis_block_hash},
    state_root::compute_state_root,
    sync::{import_unfinalized_block_for_test, SyncState},
    NodeConfig, NodeEngine,
};
use indra_state::ChainState;
use indra_storage::{BlockStore, PruneConfig, StateStore};
use std::{path::PathBuf, time::Instant};

fn observe_sync_status(
    sync: &mut SyncState,
    peer: std::net::SocketAddr,
    peer_height: u64,
    local_height: u64,
) -> Option<(std::net::SocketAddr, u64, u64)> {
    let validator_id = Bytes32::from([0x13; 32]);
    sync.peer_connected(validator_id);
    sync.observe_status(
        validator_id,
        peer,
        peer_height,
        Bytes32::ZERO,
        100,
        100,
        local_height,
        Instant::now(),
    )
}

fn temp_dir(suffix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("indra_node_test_{}_{}", suffix, std::process::id()));
    p
}

fn anchored_genesis_state() -> ChainState {
    let mut state = build_genesis_state();
    state.active_slot_coefficient_numerator = 1u64 << 63;
    state.consensus_snapshots.clear();
    state.reward_economic_snapshot = None;
    state.slash_membership_roots.clear();
    state.finalize_genesis().unwrap();
    state.tip_hash = genesis_block_hash();
    state
}

fn make_strict_block(
    state: &ChainState,
    proposer_seed: [u8; 32],
    prev_qc_bytes: Vec<u8>,
) -> indra_core::types::block::BlockProposalVNext {
    let height = state.height + 1;
    let snapshot = state.snapshot_for_consensus_height(height).unwrap();
    let vrf = VrfKeypair::from_seed(&proposer_seed);
    let election = (0..4_096)
        .map(|round| indra_consensus::proposer::ProposerElection {
            chain_id: state.chain_id.as_bytes().to_vec(),
            election_seed: state.election_seed,
            snapshot_root: snapshot.snapshot_root,
            active_slot_coefficient_numerator: state.active_slot_coefficient_numerator,
            height,
            round,
            candidates: snapshot
                .entries()
                .iter()
                .map(|entry| ProposerCandidate {
                    validator_id: entry.validator_id,
                    vrf_pubkey: entry.vrf_pk,
                    stake: entry.consensus_weight_spark,
                })
                .collect(),
        })
        .find(|election| {
            election
                .candidates
                .iter()
                .find(|candidate| candidate.vrf_pubkey == vrf.public_key())
                .is_some_and(|candidate| {
                    compute_proposer_vrf(candidate.validator_id, &vrf, election)
                        .is_ok_and(|result| result.eligible)
                })
        })
        .expect("test proposer must become eligible in bounded rounds");
    let template = BlockTemplate {
        proposer_vrf_keypair: vrf,
        prev_qc_bytes,
        timestamp: 1_700_000_000 + height,
        polc_round: None,
        transactions: vec![],
        slash_evidence: vec![],
        governance_ops: vec![],
        staking_ops: vec![],
    };
    let mut projection_state = state.clone();
    let block = produce_block(&template, &mut projection_state, &election).unwrap();
    let signer = HybridKeypair::new(
        ClassicalKeypair::from_seed(&proposer_seed),
        PqKeypair::from_seed(&proposer_seed).unwrap(),
    );
    let mut proposal = indra_core::types::block::BlockProposalVNext {
        block,
        proposer_authorization: HybridSignature {
            classical_sig: VariableBytes::from_slice(&[]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[]).unwrap(),
        },
    };
    let transcript = proposal.signing_bytes(state.chain_id.as_bytes()).unwrap();
    let signature = signer.sign(&transcript).unwrap();
    proposal.proposer_authorization = HybridSignature {
        classical_sig: VariableBytes::from_slice(&signature.classical.0).unwrap(),
        pq_sig: VariableBytes::from_slice(&signature.pq.0).unwrap(),
    };
    proposal
}

async fn write_plain_msg<W>(writer: &mut W, msg: &Message)
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let wire = msg.encode_wire().unwrap();
    write_frame_plain(writer, &wire[4..]).await.unwrap();
}

fn dummy_vote() -> VoteV1 {
    VoteV1 {
        height: 1,
        round: 0,
        step: VoteStep::Precommit,
        block_hash: Bytes32::from([0xAB; 32]),
        validator_id: Bytes32::from([0xCD; 32]),
        signature: HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
        },
    }
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
    let validator_id =
        indra_core::types::crypto::hybrid_identity_id(&public.classical.0, &public.pq.0);

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
            vrf_key_activation_epoch: 0,
            pending_vrf_pk: None,
            pending_vrf_activation_epoch: None,
            stake_spark: 1_000_000,
            status: indra_state::ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            slashed_offense_id: None,
            commission_bps: indra_core::types::primitives::DEFAULT_COMMISSION_BPS,
            pending_commission_bps: None,
            pending_commission_effective_epoch: None,
            min_delegation_spark: indra_core::types::primitives::DUST_LIMIT_SPARK,
            auto_delegate_to: None,
            network_addr: None,
            network_addr_last_updated_epoch: None,
            cold_hybrid_classical_pk: None,
            cold_hybrid_pq_pk: None,
            cold_key_version: 0,
            cold_nonce: 0,
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
    let cold = indra_crypto::ColdHybridKeypair::from_independent_seeds(
        [seed[0] ^ 0xA5; 32],
        [seed[0] ^ 0x5A; 32],
    )
    .unwrap();
    let cold_public = cold.public_key();
    let cold_public = cold_public.as_complete_hybrid();
    let validator_id =
        indra_core::types::crypto::hybrid_identity_id(&public.classical.0, &public.pq.0);

    if state.height == 0 {
        state.validators = Default::default();
        state.consensus_snapshots.clear();
        state.reward_economic_snapshot = None;
        state.slash_membership_roots.clear();
    }

    state
        .validators
        .upsert(indra_state::ValidatorEntry {
            validator_id,
            name: name.to_string(),
            hybrid_classical_pk: Some(public.classical.0),
            hybrid_pq_pk: Some(public.pq.0.to_vec()),
            vrf_pk: Some(vrf_pk),
            vrf_key_activation_epoch: 0,
            pending_vrf_pk: None,
            pending_vrf_activation_epoch: None,
            stake_spark: 1_000_000,
            status: indra_state::ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            slashed_offense_id: None,
            commission_bps: indra_core::types::primitives::DEFAULT_COMMISSION_BPS,
            pending_commission_bps: None,
            pending_commission_effective_epoch: None,
            min_delegation_spark: indra_core::types::primitives::DUST_LIMIT_SPARK,
            auto_delegate_to: None,
            network_addr: None,
            network_addr_last_updated_epoch: None,
            cold_hybrid_classical_pk: Some(cold_public.classical.0),
            cold_hybrid_pq_pk: Some(cold_public.pq.0),
            cold_key_version: 1,
            cold_nonce: 0,
        })
        .unwrap();
    if state.height == 0 {
        state.finalize_genesis().unwrap();
    }
    hybrid
}

fn write_single_validator_genesis(dir: &std::path::Path, seed: [u8; 32], name: &str) -> String {
    std::fs::create_dir_all(dir).unwrap();
    let classical = ClassicalKeypair::from_seed(&seed);
    let pq = PqKeypair::from_seed(&seed).unwrap();
    let vrf = VrfKeypair::from_seed(&seed);
    let cold = indra_crypto::ColdHybridKeypair::from_independent_seeds(
        [seed[0] ^ 0xA5; 32],
        [seed[0] ^ 0x5A; 32],
    )
    .unwrap();
    let cold_public = cold.public_key();
    let cold_public = cold_public.as_complete_hybrid();
    let validator_id = indra_core::types::crypto::hybrid_identity_id(
        &classical.public_key().0,
        &pq.public_key().0,
    )
    .0;
    let genesis_path = dir.join("genesis.toml");
    let genesis = format!(
        "[genesis]\nchain_id = \"indra-testnet-1\"\nactive_slot_coefficient_numerator = \"9223372036854775808\"\nbitcoin_pow_entropy_header = \"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"\n\n[genesis.bitcoin_pow_entropy_source]\nscheme = 1\nnetwork_genesis_hash = \"0000000000000000000000000000000000000000000000000000000000000000\"\nannounced_height = 1\nheader_codec = 1\nextraction_algorithm = 1\nminimum_confirmations = 100\nreorg_policy = 1\n\n[[validators]]\nname = \"{}\"\nvalidator_id = \"{}\"\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\ncold_hybrid_classical_pk = \"{}\"\ncold_hybrid_pq_pk = \"{}\"\ncold_key_version = 1\ncold_nonce = 0\nstake = 1000000\n",
        name,
        hex::encode(validator_id),
        hex::encode(classical.public_key().0),
        hex::encode(pq.public_key().0),
        hex::encode(vrf.public_key()),
        hex::encode(cold_public.classical.0),
        hex::encode(cold_public.pq.0),
    );
    std::fs::write(&genesis_path, genesis).unwrap();
    genesis_path.to_string_lossy().to_string()
}

fn build_single_validator_qc_bytes(
    height: u64,
    round: u32,
    block_hash: Bytes32,
    seed: [u8; 32],
) -> Vec<u8> {
    let classical = ClassicalKeypair::from_seed(&seed);
    let pq = PqKeypair::from_seed(&seed).unwrap();
    let hybrid = HybridKeypair::new(classical, pq);
    let public = hybrid.public_key();
    let validator_id =
        indra_core::types::crypto::hybrid_identity_id(&public.classical.0, &public.pq.0);
    let vote = produce_vote(
        height,
        round,
        VoteStep::Precommit,
        block_hash,
        validator_id,
        DEFAULT_CHAIN_ID,
        &hybrid,
    )
    .unwrap();
    let qc = build_qc(
        height,
        round,
        block_hash,
        DEFAULT_CHAIN_ID,
        &[QcValidator {
            validator_id,
            position: 0,
            pq_pk: public.pq.0.to_vec(),
            classical_pk: public.classical.0,
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
    config.pq_seed = Some(pq.secret_key_bytes());
    let engine = NodeEngine::init(config).unwrap();
    let vote_safety = indra_storage::VoteSafetyStore::open(engine.config.vote_safety_path());
    (ConsensusDriver::new(engine, vote_safety), dir)
}

fn assert_block_log_roundtrip_and_links(log_path: &std::path::Path) {
    let mut store = BlockStore::open(log_path, PruneConfig::archive()).unwrap();
    let mut previous: Option<indra_core::types::block::BlockProposalVNext> = None;

    for height in 0..store.next_height() {
        let block = store.get(height).unwrap();
        let encoded = indra_core::codec::Encode::encode_to_vec(&block);
        let decoded = indra_core::types::block::BlockProposalVNext::decode_exact(&encoded).unwrap();
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
        engine.commit_proposal(&block).unwrap();
        last_qc = build_single_validator_qc_bytes(
            i,
            block.header.proposer_round,
            block.header.block_hash(),
            [0x42u8; 32],
        );
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
    import_unfinalized_block_for_test(
        &b1,
        &mut state,
        &mut mempool,
        &mut block_store,
        &state_store,
        0,
    )
    .unwrap();
    let root1 = compute_state_root(&state);

    let qc1 = build_single_validator_qc_bytes(
        1,
        b1.header.proposer_round,
        b1.header.block_hash(),
        [0x11u8; 32],
    );
    let b2 = make_strict_block(&state, [0x11u8; 32], qc1);
    import_unfinalized_block_for_test(
        &b2,
        &mut state,
        &mut mempool,
        &mut block_store,
        &state_store,
        0,
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
            import_unfinalized_block_for_test(
                &b,
                &mut state,
                &mut mempool,
                &mut block_store,
                &state_store,
                0,
            )
            .unwrap();
            last_qc = build_single_validator_qc_bytes(
                i,
                b.header.proposer_round,
                b.header.block_hash(),
                [0x12u8; 32],
            );
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
    let mut config = NodeConfig::local_test(dir.clone());
    config.genesis_path = Some(write_single_validator_genesis(&dir, [0x42u8; 32], "local"));

    {
        let mut engine = NodeEngine::init(config.clone()).unwrap();
        let mut last_qc = Vec::new();
        for _ in 0..5u64 {
            let height = engine.state.height + 1;
            let block = make_strict_block(&engine.state, [0x42u8; 32], last_qc.clone());
            engine.commit_proposal(&block).unwrap();
            last_qc = build_single_validator_qc_bytes(
                height,
                block.header.proposer_round,
                block.header.block_hash(),
                [0x42u8; 32],
            );
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
    let source_log = dir.join("source").join("blocks.log");
    let follower_log = dir.join("follower").join("blocks.log");
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
        import_unfinalized_block_for_test(
            &block,
            &mut source_state,
            &mut source_mempool,
            &mut source_store,
            &source_state_store,
            0,
        )
        .unwrap();
        source_last_qc = build_single_validator_qc_bytes(
            height,
            block.header.proposer_round,
            block.header.block_hash(),
            [0x13u8; 32],
        );
    }

    let peer: std::net::SocketAddr = "127.0.0.1:30303".parse().unwrap();
    let mut follower_state = anchored_genesis_state();
    install_state_validator(&mut follower_state, [0x13u8; 32], "source");
    let mut follower_mempool = Mempool::default_config();
    let mut follower_store = BlockStore::open(&follower_log, PruneConfig::archive()).unwrap();
    let follower_state_store = StateStore::open(&follower_state_dir).unwrap();
    let mut sync = SyncState::follower(follower_state.height);

    let request = observe_sync_status(&mut sync, peer, source_state.height, follower_state.height);
    assert_eq!(request, Some((peer, 1, source_state.height + 1)));

    for height in 1..=source_state.height {
        let block = source_store.get(height).unwrap();
        import_unfinalized_block_for_test(
            &block,
            &mut follower_state,
            &mut follower_mempool,
            &mut follower_store,
            &follower_state_store,
            0,
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
            engine.commit_proposal(&block).unwrap();
            last_qc = build_single_validator_qc_bytes(
                height,
                block.header.proposer_round,
                block.header.block_hash(),
                [0x42u8; 32],
            );
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

    let mut state = build_genesis_state();
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

    let mut state = anchored_genesis_state();
    install_state_validator(&mut state, [0x14u8; 32], "local");
    let mut mempool = Mempool::default_config();
    let mut block_store = BlockStore::open(dir.join("blocks.log"), PruneConfig::archive()).unwrap();
    let state_store = StateStore::open(dir.join("state")).unwrap();

    let mut last_qc = Vec::new();
    let roots: Vec<Bytes32> = (1..=10u64)
        .map(|i| {
            let b = make_strict_block(&state, [0x14u8; 32], last_qc.clone());
            import_unfinalized_block_for_test(
                &b,
                &mut state,
                &mut mempool,
                &mut block_store,
                &state_store,
                0,
            )
            .unwrap();
            last_qc = build_single_validator_qc_bytes(
                i,
                b.header.proposer_round,
                b.header.block_hash(),
                [0x14u8; 32],
            );
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

#[tokio::test]
async fn observer_connects_and_receives_status() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let result = perform_observer_handshake_responder(stream, NODE_TYPE_FULL)
            .await
            .unwrap();
        let mut stream = result.stream;
        write_plain_msg(
            &mut stream,
            &Message::Status {
                height: 7,
                tip_hash: Bytes32::from([0x11; 32]),
                round: 0,
            },
        )
        .await;
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let result = perform_observer_handshake_initiator(stream, NODE_TYPE_OBSERVER)
        .await
        .unwrap();
    let mut stream = result.stream;
    let frame = read_frame_plain(&mut stream).await.unwrap();
    let msg = Message::decode_wire(&frame).unwrap();
    assert!(matches!(msg, Message::Status { height: 7, .. }));
    server.await.unwrap();
}

#[tokio::test]
async fn observer_sync_downloads_blocks() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let result = perform_observer_handshake_responder(stream, NODE_TYPE_FULL)
            .await
            .unwrap();
        let mut stream = result.stream;
        write_plain_msg(
            &mut stream,
            &Message::Status {
                height: 5,
                tip_hash: Bytes32::from([0x22; 32]),
                round: 0,
            },
        )
        .await;
        let frame = read_frame_plain(&mut stream).await.unwrap();
        Message::decode_wire(&frame).unwrap()
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let result = perform_observer_handshake_initiator(stream, NODE_TYPE_OBSERVER)
        .await
        .unwrap();
    let mut stream = result.stream;
    let frame = read_frame_plain(&mut stream).await.unwrap();
    let msg = Message::decode_wire(&frame).unwrap();
    assert!(matches!(msg, Message::Status { height: 5, .. }));
    write_plain_msg(
        &mut stream,
        &Message::RequestBlocks {
            from_height: 1,
            to_height: 5,
        },
    )
    .await;
    let req = server.await.unwrap();
    assert!(matches!(
        req,
        Message::RequestBlocks {
            from_height: 1,
            to_height: 5
        }
    ));
}

#[tokio::test]
async fn observer_consensus_message_closes_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let result = perform_observer_handshake_responder(stream, NODE_TYPE_FULL)
            .await
            .unwrap();
        let mut stream = result.stream;
        let frame = read_frame_plain(&mut stream).await.unwrap();
        let msg = Message::decode_wire(&frame).unwrap();
        assert!(matches!(msg, Message::Vote(_)));
        drop(stream);
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let result = perform_observer_handshake_initiator(stream, NODE_TYPE_OBSERVER)
        .await
        .unwrap();
    let mut stream = result.stream;
    write_plain_msg(&mut stream, &Message::Vote(dummy_vote())).await;
    server.await.unwrap();
    let closed = read_frame_plain(&mut stream).await;
    assert!(closed.is_err());
}

#[tokio::test]
async fn observer_at_capacity_receives_status_then_closes() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let result = perform_observer_handshake_responder(stream, NODE_TYPE_FULL)
            .await
            .unwrap();
        let mut stream = result.stream;
        write_plain_msg(
            &mut stream,
            &Message::Status {
                height: 9,
                tip_hash: Bytes32::from([0x33; 32]),
                round: 0,
            },
        )
        .await;
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let result = perform_observer_handshake_initiator(stream, NODE_TYPE_OBSERVER)
        .await
        .unwrap();
    let mut stream = result.stream;
    let frame = read_frame_plain(&mut stream).await.unwrap();
    let msg = Message::decode_wire(&frame).unwrap();
    assert!(matches!(msg, Message::Status { height: 9, .. }));
    server.await.unwrap();
    assert!(read_frame_plain(&mut stream).await.is_err());
}

#[test]
fn node_syncs_before_joining_consensus() {
    let (mut driver, dir) = local_driver([0x71u8; 32], "join_after_sync");
    let _local = install_active_validator(&mut driver, [0x71u8; 32], "local");
    let remote = install_active_validator(&mut driver, [0x72u8; 32], "remote");
    driver.refresh_registered_voters();

    let peer: std::net::SocketAddr = "127.0.0.1:30303".parse().unwrap();
    let local_height = driver.height();
    let voter = driver.engine.registered_voters()[0].clone();
    driver.sync_mut().peer_connected(voter.validator_id);
    let _ = driver.sync_mut().observe_status(
        voter.validator_id,
        peer,
        10,
        Bytes32::ZERO,
        voter.stake,
        voter.stake,
        local_height,
        Instant::now(),
    );
    assert!(!driver.sync().is_caught_up());

    let remote_id = indra_core::types::crypto::hybrid_identity_id(
        &remote.public_key().classical.0,
        &remote.public_key().pq.0,
    );
    let vote = indra_consensus::vote::produce_vote(
        1,
        0,
        VoteStep::Prevote,
        Bytes32::from([0xCCu8; 32]),
        remote_id,
        DEFAULT_CHAIN_ID,
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

    let source_log = dir.join("source").join("blocks.log");
    let follower_a_log = dir.join("follower_a").join("blocks.log");
    let follower_b_log = dir.join("follower_b").join("blocks.log");
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
        import_unfinalized_block_for_test(
            &block,
            &mut source_state,
            &mut source_mempool,
            &mut source_store,
            &source_state_store,
            0,
        )
        .unwrap();
        source_last_qc = build_single_validator_qc_bytes(
            height,
            block.header.proposer_round,
            block.header.block_hash(),
            [0x15u8; 32],
        );
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
        import_unfinalized_block_for_test(
            &block1,
            &mut follower_state,
            &mut follower_mempool,
            &mut follower_store,
            &follower_state_store,
            0,
        )
        .unwrap();

        let peer: std::net::SocketAddr = "127.0.0.1:30304".parse().unwrap();
        let mut sync = SyncState::follower(follower_state.height);
        assert_eq!(
            observe_sync_status(&mut sync, peer, source_state.height, follower_state.height),
            Some((peer, 2, 3))
        );

        let block2 = source_store.get(2).unwrap();
        import_unfinalized_block_for_test(
            &block2,
            &mut follower_state,
            &mut follower_mempool,
            &mut follower_store,
            &follower_state_store,
            0,
        )
        .unwrap();
        sync.on_block_imported(2);
        assert!(sync.is_caught_up());
        assert_eq!(follower_state.height, source_state.height);
    }

    let _ = std::fs::remove_dir_all(&dir);
}
