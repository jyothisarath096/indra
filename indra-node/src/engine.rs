//! NodeEngine — the consensus loop driver.
//!
//! Drives the BFT consensus state machine for one node.
//! In Phase 5 this runs synchronously (no async runtime).
//! Phase 6 wraps this in Tokio for async P2P.
//!
//! ## Consensus loop (per height)
//!
//!   1. Check if we are the proposer for this height
//!   2. If yes: produce a block and "broadcast" it (Phase 5: direct call)
//!   3. Collect prevotes from all validators (Phase 5: simulate locally)
//!   4. If prevote quorum: broadcast precommit
//!   5. Collect precommits until QC formed
//!   6. Import the committed block via sync::import_block
//!   7. Advance to next height

use indra_core::types::{
    block::{BlockHeaderV1, BlockV1, NO_POLC_ROUND},
    primitives::{Bytes32, MAX_QC_SIZE_BYTES, MAX_VRF_PROOF_BYTES, VariableBytes},
    vote::VoteStep,
};
use indra_crypto::{
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    VrfKeypair,
};
use indra_state::ChainState;
use indra_consensus::{
    mempool::Mempool,
    proposer::{ProposerElection, compute_proposer_vrf, elect_proposer},
    producer::{BlockTemplate, produce_block},
    qc::QcValidator,
    vote::{RegisteredVoter, produce_vote},
};
use indra_storage::{BlockStore, StateStore};

use crate::{
    config::NodeConfig,
    error::{NodeError, NodeResult},
    genesis::build_genesis_block,
    sync::import_block,
};

/// The node engine: owns all state and drives consensus.
pub struct NodeEngine {
    /// Node configuration.
    pub config: NodeConfig,
    /// Current chain state.
    pub state: ChainState,
    /// Pending transaction pool.
    pub mempool: Mempool,
    /// Persistent block log.
    pub block_store: BlockStore,
    /// State snapshot store.
    pub state_store: StateStore,
    /// The validator's hybrid keypair (if this is a validator node).
    #[allow(dead_code)] // retained for future local signing flows
    hybrid_keypair: Option<HybridKeypair>,
    /// The validator's VRF keypair.
    vrf_keypair: Option<VrfKeypair>,
    /// This validator's identity (SHA-256 of hybrid public key classical component).
    validator_id: Option<Bytes32>,
}

impl NodeEngine {
    /// Initialise a node from its configuration.
    pub fn init(config: NodeConfig) -> NodeResult<Self> {
        std::fs::create_dir_all(&config.data_dir)
            .map_err(indra_storage::StorageError::Io)?;

        if let Some(keep) = config.prune_keep_blocks {
            assert!(
                keep > config.snapshot_interval * 2,
                "prune_keep_blocks ({}) must be greater than 2x snapshot_interval ({}) to guarantee snapshot-based restart is always possible",
                keep,
                config.snapshot_interval
            );
        }

        let mut block_store = BlockStore::open(config.block_log_path(), config.prune_config())?;
        let state_store = StateStore::open(config.state_dir())?;
        let startup_log;
        let state = if let Some(snapshot) = state_store.load_latest()? {
            let replay_start = snapshot.height.saturating_add(1);
            if !block_store.is_empty() && block_store.lowest_height() > replay_start {
                return Err(NodeError::SnapshotReplayGap {
                    snapshot_height: snapshot.height,
                    lowest_block: block_store.lowest_height(),
                    gap: block_store.lowest_height().saturating_sub(replay_start),
                });
            }

            startup_log = startup_mode_message(Some(snapshot.height), replay_start, block_store.next_height());
            let mut state = snapshot;
            rebuild_state_from_height(&mut state, &mut block_store, replay_start)?;
            state
        } else {
            if block_store.lowest_height() > 0 {
                return Err(NodeError::PrunedReplayUnsupported {
                    lowest_height: block_store.lowest_height(),
                });
            }

            startup_log = startup_mode_message(None, 1, block_store.next_height());
            let mut state = ChainState::new_genesis();
            rebuild_state_from_height(&mut state, &mut block_store, 1)?;
            state
        };
        eprintln!("{startup_log}");

        let mempool = Mempool::new(indra_consensus::mempool::MempoolConfig {
            capacity: config.mempool_capacity,
            min_fee_ratio_bps: 10_000,
        });

        // Build validator keypairs if configured
        let (hybrid_keypair, vrf_keypair, validator_id) =
            match (config.validator_seed, config.vrf_seed) {
                (Some(vs), Some(vrfs)) => {
                let classical = ClassicalKeypair::from_seed(&vs);
                let pq = if let (Some(pk), Some(sk)) = (
                    config.pq_pk.as_deref(),
                    config.pq_sk.as_deref(),
                ) {
                    PqKeypair::from_bytes(pk, sk)
                        .unwrap_or_else(|_| PqKeypair::generate())
                } else {
                    PqKeypair::generate()
                };
                let hybrid = HybridKeypair::new(classical, pq);
                let vrf = VrfKeypair::from_seed(&vrfs);
                let pk = hybrid.public_key();
                let id = Bytes32::from(indra_crypto::sha256(&pk.classical.0));
                (Some(hybrid), Some(vrf), Some(id))
                }
                (Some(_), None) => {
                    return Err(NodeError::ValidatorConfigIncomplete {
                        detail: "validator_seed was provided but vrf_seed was missing".to_string(),
                    });
                }
                (None, Some(_)) => {
                    return Err(NodeError::ValidatorConfigIncomplete {
                        detail: "vrf_seed was provided but validator_seed was missing".to_string(),
                    });
                }
                (None, None) => (None, None, None),
            };

        Ok(Self {
            config,
            state,
            mempool,
            block_store,
            state_store,
            hybrid_keypair,
            vrf_keypair,
            validator_id,
        })
    }

    /// Current chain height.
    pub fn height(&self) -> u64 {
        self.state.height
    }

    /// This node's validator ID, if it is a validator.
    pub fn validator_id(&self) -> Option<Bytes32> {
        self.validator_id
    }

    /// Load the last committed QC bytes persisted on disk, if any.
    pub fn load_persisted_qc(&self) -> NodeResult<Option<Vec<u8>>> {
        indra_storage::load_last_qc(&self.config.state_dir()).map_err(NodeError::Storage)
    }

    /// True if this node has a local VRF keypair loaded.
    pub fn has_vrf_keypair(&self) -> bool {
        self.vrf_keypair.is_some()
    }

    /// Rebuild the current chain state by replaying the block log on top of
    /// the current genesis-equivalent state.
    ///
    /// Callers should pre-load any genesis validators before invoking this so
    /// replay starts from the correct validator set.
    pub fn rebuild_state_from_block_log(&mut self) -> NodeResult<()> {
        let mut rebuilt = ChainState::new_genesis();
        rebuilt.validators = self.state.validators.clone();
        rebuilt.delegations = self.state.delegations.clone();
        rebuilt.utxos = self.state.utxos.clone();
        rebuilt.nullifiers = self.state.nullifiers.clone();
        rebuild_state_from_height(&mut rebuilt, &mut self.block_store, 1)?;
        self.state = rebuilt;
        Ok(())
    }

    /// Check if this node is the elected proposer for the next height.
    pub fn is_proposer(&self, election: &ProposerElection) -> bool {
        let my_id = self.validator_id
            .map(|id| hex::encode(&id.0[..4]))
            .unwrap_or_else(|| "none".to_string());
        let has_vrf = self.vrf_keypair.is_some();
        let cand_count = election.candidates.len();
        let in_candidates = self.validator_id
            .map(|validator_id| election.candidates.iter().any(|candidate| candidate.validator_id == validator_id))
            .unwrap_or(false);

        let Some(vrf_kp) = &self.vrf_keypair else {
            eprintln!(
                "[proposer] id={} has_vrf={} in_candidates={} candidates={} elected=none should_propose=false",
                my_id, has_vrf, in_candidates, cand_count
            );
            return false;
        };
        let Some(validator_id) = self.validator_id else {
            eprintln!(
                "[proposer] id={} has_vrf={} in_candidates={} candidates={} elected=none should_propose=false",
                my_id, has_vrf, in_candidates, cand_count
            );
            return false;
        };
        let slot = compute_proposer_vrf(
            validator_id,
            vrf_kp,
            &election.epoch_seed,
            election.height,
            election.round,
        );
        let elected = match elect_proposer(election) {
            Ok(id) => id,
            Err(_) => {
                eprintln!(
                    "[proposer] id={} has_vrf={} in_candidates={} candidates={} elected=err should_propose=false",
                    my_id, has_vrf, in_candidates, cand_count
                );
                return false;
            }
        };
        let should_propose = elected == slot.proposer_id;
        eprintln!(
            "[proposer] id={} has_vrf={} in_candidates={} candidates={} elected={} should_propose={}",
            my_id,
            has_vrf,
            in_candidates,
            cand_count,
            hex::encode(&elected.0[..4]),
            should_propose
        );
        should_propose
    }

    /// Propose a block for the next height (only if this node is the proposer).
    pub fn propose(
        &self,
        election: &ProposerElection,
        timestamp: u64,
        prev_qc_bytes: Vec<u8>,
        polc_round: Option<u32>,
    ) -> NodeResult<BlockV1> {
        let proposal_height = self.state.height + 1;
        if proposal_height > 1 && prev_qc_bytes.is_empty() {
            eprintln!(
                "[proposer] cannot produce block at height {}: no QC for previous block — waiting for peer proposal",
                proposal_height,
            );
            return Err(NodeError::MissingQc {
                height: proposal_height,
            });
        }

        let _vrf_kp = self.vrf_keypair.as_ref()
            .ok_or(NodeError::NotProposer { height: proposal_height })?;

        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&self.config.vrf_seed
                .ok_or(NodeError::NotProposer { height: proposal_height })?),
            epoch_seed: election.epoch_seed,
            prev_qc_bytes,
            timestamp,
            polc_round,
        };

        produce_block(&template, &self.state, &self.mempool, election)
            .map_err(NodeError::Consensus)
    }

    /// Re-propose an already validated value in a later round while keeping
    /// its stable consensus value hash unchanged.
    pub fn repropose(
        &self,
        original_block: &BlockV1,
        new_round: u32,
        valid_round: Option<u32>,
        election: &ProposerElection,
        timestamp: u64,
        last_qc: Vec<u8>,
    ) -> NodeResult<BlockV1> {
        let proposal_height = self.state.height + 1;
        if proposal_height > 1 && last_qc.is_empty() {
            eprintln!(
                "[proposer] cannot produce block at height {}: no QC for previous block — waiting for peer proposal",
                proposal_height,
            );
            return Err(NodeError::MissingQc {
                height: proposal_height,
            });
        }

        let vrf_kp = self.vrf_keypair.as_ref().ok_or(NodeError::NotProposer {
            height: proposal_height,
        })?;
        let validator_id = self.validator_id.ok_or(NodeError::NotProposer {
            height: proposal_height,
        })?;
        let slot = compute_proposer_vrf(
            validator_id,
            vrf_kp,
            &election.epoch_seed,
            election.height,
            election.round,
        );
        let elected = elect_proposer(election).map_err(NodeError::Consensus)?;
        if elected != slot.proposer_id {
            return Err(NodeError::NotProposer {
                height: proposal_height,
            });
        }

        let vrf_proof_bytes = VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&slot.vrf_proof.0)
            .map_err(|_| NodeError::Consensus(indra_consensus::error::ConsensusError::CryptoError {
                detail: "VRF proof too large".to_string(),
            }))?;
        let qc_bytes = VariableBytes::<MAX_QC_SIZE_BYTES>::from_slice(&last_qc).map_err(|_| {
            NodeError::Consensus(indra_consensus::error::ConsensusError::CryptoError {
                detail: "QC bytes too large".to_string(),
            })
        })?;

        let mut block = BlockV1 {
            header: BlockHeaderV1 {
                protocol_version: original_block.header.protocol_version,
                height: original_block.header.height,
                prev_hash: original_block.header.prev_hash,
                timestamp,
                state_root: original_block.header.state_root,
                validator_set_root: original_block.header.validator_set_root,
                mempool_set_root: original_block.header.mempool_set_root,
                value_hash: original_block.header.value_hash,
                base_fee: original_block.header.base_fee,
                proposer_round: new_round,
                polc_round: valid_round.unwrap_or(NO_POLC_ROUND),
                proposer_vrf_output: Bytes32::from(slot.vrf_output.0),
                proposer_vrf_proof: vrf_proof_bytes,
                quorum_certificate: qc_bytes,
            },
            transactions: original_block.transactions.clone(),
            slashing_evidence: original_block.slashing_evidence.clone(),
            governance_ops: original_block.governance_ops.clone(),
        };

        let mut projected = self.state.clone();
        indra_state::apply_block(&mut projected, &block)?;
        let expected_value_hash = block.compute_value_hash(projected.total_supply);
        if expected_value_hash != original_block.header.value_hash {
            return Err(NodeError::BlockInvalid {
                height: block.header.height,
                reason: "reproposal changed stable value hash".to_string(),
            });
        }
        block.header.value_hash = expected_value_hash;
        Ok(block)
    }

    /// Build the current epoch voter list from active validators.
    pub fn registered_voters(&self) -> Vec<RegisteredVoter> {
        let mut active: Vec<_> = self.state.validators.active_validators().collect();
        active.sort_by_key(|validator| validator.validator_id.0);
        active.into_iter()
            .filter_map(|validator| Some(RegisteredVoter {
                validator_id: validator.validator_id,
                classical_pk: validator.hybrid_classical_pk?,
                pq_pk: validator.hybrid_pq_pk.clone()?,
                stake: validator.stake_spark,
            }))
            .collect()
    }

    /// Build the QC validator list for the current epoch.
    pub fn qc_validators(&self) -> Vec<QcValidator> {
        let mut active: Vec<_> = self.state.validators.active_validators().collect();
        active.sort_by_key(|validator| validator.validator_id.0);
        active.into_iter()
            .enumerate()
            .filter_map(|(position, validator)| Some(QcValidator {
                validator_id: validator.validator_id,
                position,
                pq_pk: validator.hybrid_pq_pk.clone()?,
                stake: validator.stake_spark,
            }))
            .collect()
    }

    /// Sign a consensus vote with this node's validator keypair.
    pub fn sign_vote(
        &self,
        height: u64,
        round: u32,
        step: VoteStep,
        block_hash: Bytes32,
    ) -> NodeResult<indra_core::types::vote::VoteV1> {
        let validator_id = self.validator_id.ok_or(NodeError::NotValidator)?;
        let hybrid_keypair = self.hybrid_keypair.as_ref().ok_or(NodeError::NotValidator)?;
        produce_vote(height, round, step, block_hash, validator_id, hybrid_keypair)
            .map_err(NodeError::Consensus)
    }

    /// Import a block that has been committed (QC formed).
    pub fn commit_block(
        &mut self,
        block: &indra_core::types::block::BlockV1,
    ) -> NodeResult<()> {
        import_block(
            block,
            &mut self.state,
            &mut self.mempool,
            &mut self.block_store,
            &self.state_store,
            self.config.strict_header_verification,
        )
    }
}

fn startup_mode_message(snapshot_height: Option<u64>, replay_start: u64, next_height: u64) -> String {
    match snapshot_height {
        Some(snapshot_height) => {
            let replay_blocks = next_height.saturating_sub(replay_start);
            let replay_end = if replay_blocks == 0 {
                replay_start
            } else {
                next_height.saturating_sub(1)
            };
            format!(
                "[engine] startup: snapshot at height={}, replaying {} blocks from height={} to height={}",
                snapshot_height,
                replay_blocks,
                replay_start,
                replay_end,
            )
        }
        None => format!(
            "[engine] startup: no snapshot, replaying from genesis ({} blocks)",
            next_height.saturating_sub(1),
        ),
    }
}

fn rebuild_state_from_height(
    state: &mut ChainState,
    block_store: &mut BlockStore,
    start_height: u64,
) -> NodeResult<()> {
    let canonical_genesis = build_genesis_block();
    if block_store.is_empty() {
        if start_height <= 1 {
            state.tip_hash = canonical_genesis.header.block_hash();
        }
        return Ok(());
    }

    if start_height <= 1 {
        let genesis = block_store.get(0)?;
        if genesis.header.height != canonical_genesis.header.height {
            return Err(NodeError::GenesisMismatch);
        }

        // Anchor replay to the persisted genesis hash so block 1 must chain to
        // the exact genesis block stored on disk rather than an all-zero tip.
        state.tip_hash = genesis.header.block_hash();
    }

    for height in start_height.max(1)..block_store.next_height() {
        let block = block_store.get(height)?;
        indra_state::apply_block(state, &block)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_state::{ValidatorEntry, ValidatorStatus};
    use indra_core::types::primitives::{DEFAULT_COMMISSION_BPS, DUST_LIMIT_SPARK};

    fn temp_dir(suffix: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_engine_test_{}_{}", suffix, std::process::id()));
        p
    }

    fn install_active_validator(engine: &mut NodeEngine, seed: [u8; 32], name: &str) {
        let classical = ClassicalKeypair::from_seed(&seed);
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let public = HybridKeypair::new(classical, pq).public_key();
        let vrf_pk = VrfKeypair::from_seed(&seed).public_key();
        let validator_id = Bytes32::from(indra_crypto::sha256(&public.classical.0));

        engine
            .state
            .validators
            .upsert(ValidatorEntry {
                validator_id,
                name: name.to_string(),
                hybrid_classical_pk: Some(public.classical.0),
                hybrid_pq_pk: Some(public.pq.0.clone()),
                vrf_pk: Some(vrf_pk),
                stake_spark: 1_000_000,
                status: ValidatorStatus::Active,
                registered_epoch: 0,
                pending_rewards: 0,
                rewards_last_epoch: 0,
                self_report_count: 0,
                commission_bps: DEFAULT_COMMISSION_BPS,
                min_delegation_spark: DUST_LIMIT_SPARK,
            })
            .unwrap();
    }

    #[test]
    fn engine_init_genesis() {
        let dir = temp_dir("a");
        let config = NodeConfig::local_test(dir.clone());
        let engine = NodeEngine::init(config).unwrap();
        assert_eq!(engine.height(), 0);
        assert!(engine.validator_id().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_node_has_no_validator_id() {
        let dir = temp_dir("b");
        let config = NodeConfig::full_node(dir.clone());
        let engine = NodeEngine::init(config).unwrap();
        assert!(engine.validator_id().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validator_init_requires_vrf_seed() {
        let dir = temp_dir("b_missing_vrf");
        let mut config = NodeConfig::local_test(dir.clone());
        config.vrf_seed = None;
        assert!(matches!(
            NodeEngine::init(config),
            Err(NodeError::ValidatorConfigIncomplete { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn make_block(state: &indra_state::ChainState) -> indra_core::types::block::BlockV1 {
        use indra_core::{
            Bytes32, ProtocolVersion, VariableBytes,
            types::block::{BlockHeaderV1, BlockV1},
            types::primitives::MAX_VRF_PROOF_BYTES,
        };
        use indra_state::{apply_block, compute_state_root, compute_validator_set_root};

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
    fn engine_commit_block() {
        let dir = temp_dir("c");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let block = make_block(&engine.state);

        engine.commit_block(&block).unwrap();
        assert_eq!(engine.height(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_rebuilds_state_from_block_log() {
        let dir = temp_dir("d");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config.clone()).unwrap();

        for height in 1..=3u64 {
            let block = make_block(&engine.state);
            engine.commit_block(&block).unwrap();
            assert_eq!(engine.state.height, height);
        }

        let restarted = NodeEngine::init(config).unwrap();
        assert_eq!(restarted.state.height, 3);
        assert_eq!(restarted.state.tip_hash, engine.state.tip_hash);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_from_snapshot_with_pruned_log() {
        let dir = temp_dir("snapshot_pruned");
        let mut config = NodeConfig::local_test(dir.clone());
        config.prune_keep_blocks = Some(650);

        let final_tip_hash = {
            let mut engine = NodeEngine::init(config.clone()).unwrap();
            for height in 1..=1_000u64 {
                let block = make_block(&engine.state);
                engine.commit_block(&block).unwrap();
                assert_eq!(engine.state.height, height);
            }
            assert!(engine.block_store.lowest_height() > 0);
            engine.state.tip_hash
        };

        let restarted = NodeEngine::init(config).unwrap();
        assert_eq!(restarted.state.height, 1_000);
        assert_eq!(restarted.state.tip_hash, final_tip_hash);
        assert!(restarted.block_store.lowest_height() > 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_fails_on_snapshot_replay_gap() {
        let dir = temp_dir("snapshot_gap");
        let mut config = NodeConfig::local_test(dir.clone());
        config.prune_keep_blocks = Some(1_000);

        {
            let mut engine = NodeEngine::init(config.clone()).unwrap();
            for _ in 0..1_600u64 {
                let block = make_block(&engine.state);
                engine.commit_block(&block).unwrap();
            }
        }

        let state_dir = dir.join("state");
        for entry in std::fs::read_dir(&state_dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("snap") {
                std::fs::remove_file(path).unwrap();
            }
        }

        let state_store = StateStore::open(&state_dir).unwrap();
        let mut snapshot = ChainState::new_genesis();
        snapshot.height = 100;
        snapshot.tip_hash = Bytes32::from([0x55; 32]);
        state_store.save(&snapshot).unwrap();

        match NodeEngine::init(config) {
            Err(NodeError::SnapshotReplayGap {
                snapshot_height,
                lowest_block,
                gap,
            }) => {
                assert_eq!(snapshot_height, 100);
                assert_eq!(lowest_block, 601);
                assert_eq!(gap, 500);
            }
            Err(other) => panic!("expected SnapshotReplayGap, got {other}"),
            Ok(_) => panic!("expected SnapshotReplayGap, got successful startup"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[should_panic(expected = "prune_keep_blocks (100) must be greater than 2x snapshot_interval (150)")]
    fn prune_alignment_assertion_fires() {
        let dir = temp_dir("prune_alignment");
        let mut config = NodeConfig::local_test(dir.clone());
        config.snapshot_interval = 150;
        config.prune_keep_blocks = Some(100);
        let _ = NodeEngine::init(config);
    }

    #[test]
    fn startup_logs_mode_correctly() {
        let snapshot_message = startup_mode_message(Some(300), 301, 601);
        assert!(snapshot_message.contains("snapshot at height=300"));
        assert!(snapshot_message.contains("replaying 300 blocks from height=301 to height=600"));

        let genesis_message = startup_mode_message(None, 1, 11);
        assert!(genesis_message.contains("no snapshot"));
        assert!(genesis_message.contains("replaying from genesis (10 blocks)"));
    }

    #[test]
    fn rebuild_preserves_preloaded_genesis_utxos() {
        let dir = temp_dir("genesis_utxo");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();

        let classical = ClassicalKeypair::from_seed(&[0x11u8; 32]);
        let pq = PqKeypair::from_seed(&[0x11u8; 32]).unwrap();
        let vrf = VrfKeypair::from_seed(&[0x22u8; 32]);
        let validator_id = indra_crypto::sha256(&classical.public_key().0);
        let genesis_path = dir.join("genesis.toml");
        let genesis = format!(
            "[[validators]]\nname = \"alice\"\nvalidator_id = \"{}\"\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\nstake = 100000000000\n",
            hex::encode(validator_id),
            hex::encode(classical.public_key().0),
            hex::encode(pq.public_key().0),
            hex::encode(vrf.public_key()),
        );
        std::fs::write(&genesis_path, genesis).unwrap();

        crate::genesis::load_genesis_validators(genesis_path.to_str().unwrap(), &mut engine.state);
        assert_eq!(engine.state.utxos.len(), 1);

        engine.rebuild_state_from_block_log().unwrap();
        assert_eq!(engine.state.utxos.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn propose_rejects_missing_previous_qc_above_height_one() {
        let dir = temp_dir("missing_qc");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        install_active_validator(&mut engine, [0x71u8; 32], "local");
        engine.state.height = 2;
        engine.state.tip_hash = Bytes32::from([0x33u8; 32]);

        let candidate = engine
            .state
            .validators
            .active_validators()
            .next()
            .unwrap();
        let election = ProposerElection {
            epoch_seed: Bytes32::from(indra_crypto::sha256(&engine.state.tip_hash.0)),
            height: 3,
            round: 0,
            candidates: vec![indra_consensus::proposer::ProposerCandidate {
                validator_id: candidate.validator_id,
                vrf_pubkey: candidate.vrf_pk.unwrap(),
                stake: candidate.stake_spark,
            }],
        };

        let err = engine
            .propose(&election, 1_700_000_003, Vec::new(), None)
            .unwrap_err();
        assert!(matches!(err, NodeError::MissingQc { height: 3 }));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
