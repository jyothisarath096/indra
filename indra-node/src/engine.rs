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

use indra_core::types::primitives::Bytes32;
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

        let mut block_store = BlockStore::open(config.block_log_path(), config.prune_config())?;
        let state_store = StateStore::open(config.state_dir())?;

        if block_store.lowest_height() > 0 {
            return Err(NodeError::PrunedReplayUnsupported {
                lowest_height: block_store.lowest_height(),
            });
        }

        // Snapshots currently store only summary fields, so rebuild the
        // authoritative state from the append-only block log on startup.
        let _latest_snapshot = state_store.load_latest()?;
        let mut state = ChainState::new_genesis();
        rebuild_state_from_block_log(&mut state, &mut block_store)?;

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
        rebuild_state_from_block_log(&mut rebuilt, &mut self.block_store)?;
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
        let slot = compute_proposer_vrf(validator_id, vrf_kp, &election.epoch_seed, self.state.height + 1);
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
    ) -> NodeResult<indra_core::types::block::BlockV1> {
        let _vrf_kp = self.vrf_keypair.as_ref()
            .ok_or(NodeError::NotProposer { height: self.state.height + 1 })?;

        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&self.config.vrf_seed
                .ok_or(NodeError::NotProposer { height: self.state.height + 1 })?),
            epoch_seed: election.epoch_seed,
            prev_qc_bytes,
            timestamp,
        };

        produce_block(&template, &self.state, &self.mempool, election)
            .map_err(NodeError::Consensus)
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
        step: indra_core::types::vote::VoteStep,
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

fn rebuild_state_from_block_log(
    state: &mut ChainState,
    block_store: &mut BlockStore,
) -> NodeResult<()> {
    if block_store.is_empty() {
        return Ok(());
    }

    let genesis = block_store.get(0)?;
    if genesis.header.height != build_genesis_block().header.height {
        return Err(NodeError::GenesisMismatch);
    }

    for height in 1..block_store.next_height() {
        let block = block_store.get(height)?;
        indra_state::apply_block(state, &block)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(suffix: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_engine_test_{}_{}", suffix, std::process::id()));
        p
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

    #[test]
    fn engine_commit_block() {
        let dir = temp_dir("c");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();

        use indra_core::{
            Bytes32, ProtocolVersion, VariableBytes,
            types::block::{BlockHeaderV1, BlockV1},
            types::primitives::{INITIAL_BASE_FEE_SPARK_PER_KB, MAX_VRF_PROOF_BYTES},
        };

        let block = BlockV1 {
            header: BlockHeaderV1 {
                protocol_version:    ProtocolVersion::CURRENT,
                height:              1,
                prev_hash:           engine.state.tip_hash,
                timestamp:           1_700_000_001,
                state_root:          Bytes32::ZERO,
                validator_set_root:  Bytes32::ZERO,
                mempool_set_root:    Bytes32::ZERO,
                base_fee:            INITIAL_BASE_FEE_SPARK_PER_KB,
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof:  VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
                quorum_certificate:  indra_core::VariableBytes::from_slice(&[]).unwrap(),
            },
            transactions:      vec![],
            slashing_evidence: vec![],
            governance_ops:    vec![],
        };

        engine.commit_block(&block).unwrap();
        assert_eq!(engine.height(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_rebuilds_state_from_block_log() {
        let dir = temp_dir("d");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config.clone()).unwrap();

        use indra_core::{
            Bytes32, ProtocolVersion, VariableBytes,
            types::block::{BlockHeaderV1, BlockV1},
            types::primitives::MAX_VRF_PROOF_BYTES,
        };

        for height in 1..=3u64 {
            let block = BlockV1 {
                header: BlockHeaderV1 {
                    protocol_version:    ProtocolVersion::CURRENT,
                    height,
                    prev_hash:           engine.state.tip_hash,
                    timestamp:           1_700_000_000 + height,
                    state_root:          Bytes32::ZERO,
                    validator_set_root:  Bytes32::ZERO,
                    mempool_set_root:    Bytes32::ZERO,
                    base_fee:            engine.state.base_fee,
                    proposer_vrf_output: Bytes32::ZERO,
                    proposer_vrf_proof:  VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
                    quorum_certificate:  indra_core::VariableBytes::from_slice(&[]).unwrap(),
                },
                transactions:      vec![],
                slashing_evidence: vec![],
                governance_ops:    vec![],
            };
            engine.commit_block(&block).unwrap();
        }

        let restarted = NodeEngine::init(config).unwrap();
        assert_eq!(restarted.state.height, 3);
        assert_eq!(restarted.state.tip_hash, engine.state.tip_hash);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
