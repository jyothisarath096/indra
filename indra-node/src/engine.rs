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
    bls::BlsKeypair,
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    VrfKeypair,
};
use indra_state::ChainState;
use indra_consensus::{
    mempool::Mempool,
    proposer::{ProposerCandidate, ProposerElection, compute_proposer_vrf, elect_proposer},
    producer::{BlockTemplate, produce_block},
};
use indra_storage::{BlockStore, StateStore};

use crate::{
    config::NodeConfig,
    error::{NodeError, NodeResult},
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
    hybrid_keypair: Option<HybridKeypair>,
    /// The validator's BLS keypair.
    bls_keypair: Option<BlsKeypair>,
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

        let block_store = BlockStore::open(config.block_log_path())?;
        let state_store = StateStore::open(config.state_dir())?;

        // Load state from snapshot or start from genesis
        let state = match state_store.load_latest()? {
            Some(s) => s,
            None => ChainState::new_genesis(),
        };

        let mempool = Mempool::new(indra_consensus::mempool::MempoolConfig {
            capacity: config.mempool_capacity,
            min_fee_ratio_bps: 10_000,
        });

        // Build validator keypairs if configured
        let (hybrid_keypair, bls_keypair, vrf_keypair, validator_id) =
            if let (Some(vs), Some(bs), Some(vrfs)) = (
                config.validator_seed,
                config.bls_seed,
                config.vrf_seed,
            ) {
                let classical = ClassicalKeypair::from_seed(&vs);
                let pq = PqKeypair::generate();
                let hybrid = HybridKeypair::new(classical, pq);
                let bls = BlsKeypair::from_seed(&bs)?;
                let vrf = VrfKeypair::from_seed(&vrfs);
                let pk = hybrid.public_key();
                let id = Bytes32::from(indra_crypto::sha256(&pk.classical.0));
                (Some(hybrid), Some(bls), Some(vrf), Some(id))
            } else {
                (None, None, None, None)
            };

        Ok(Self {
            config,
            state,
            mempool,
            block_store,
            state_store,
            hybrid_keypair,
            bls_keypair,
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

    /// Check if this node is the elected proposer for the next height.
    pub fn is_proposer(&self, election: &ProposerElection) -> bool {
        let Some(vrf_kp) = &self.vrf_keypair else { return false; };
        let slot = compute_proposer_vrf(vrf_kp, &election.epoch_seed, self.state.height + 1);
        let elected = match elect_proposer(election) {
            Ok(id) => id,
            Err(_) => return false,
        };
        elected == slot.proposer_id
    }

    /// Propose a block for the next height (only if this node is the proposer).
    pub fn propose(
        &self,
        election: &ProposerElection,
        timestamp: u64,
        prev_qc_bytes: Vec<u8>,
    ) -> NodeResult<indra_core::types::block::BlockV1> {
        let vrf_kp = self.vrf_keypair.as_ref()
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
        )
    }
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
}
