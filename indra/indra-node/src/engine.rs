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

use indra_consensus::{
    mempool::Mempool,
    producer::{produce_block, BlockTemplate},
    proposer::{compute_proposer_vrf, elect_proposer, ProposerElection},
    qc::QcValidator,
    vote::{produce_vote, RegisteredVoter},
};
use indra_core::types::{
    block::{BlockHeaderV1, BlockV1, NO_POLC_ROUND},
    governance::GovernanceOpV2,
    primitives::{
        Bytes32, VariableBytes, MAX_GOV_OPS_PER_BLOCK, MAX_QC_SIZE_BYTES, MAX_SLASHES_PER_BLOCK,
        MAX_STAKING_OPS_PER_BLOCK, MAX_VRF_PROOF_BYTES,
    },
    slashing::SlashEvidenceV1,
    staking::StakingOp,
    vote::VoteStep,
};
use indra_crypto::{
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    VrfKeypair,
};
use indra_state::{apply::compute_slash_evidence_hash, ChainState};
use indra_storage::{migration_record, BlockStore, EpochStore, MigrationLog, StateStore};

use crate::{
    config::NodeConfig,
    error::{NodeError, NodeResult},
    genesis::{build_genesis_block, load_genesis_validators},
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
    /// Pending staking operations waiting to be included in a block.
    pub staking_mempool: Vec<StakingOp>,
    /// Pending governance operations waiting to be included in a block.
    pub governance_mempool: Vec<GovernanceOpV2>,
    /// Pending slash evidence waiting to be included in a block.
    pub pending_slashes: Vec<SlashEvidenceV1>,
    /// Persistent block log.
    pub block_store: BlockStore,
    /// Persistent epoch history log.
    pub epoch_store: EpochStore,
    /// State snapshot store.
    pub state_store: StateStore,
    /// Schema migration audit log.
    pub migration_log: MigrationLog,
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
        std::fs::create_dir_all(&config.data_dir).map_err(indra_storage::StorageError::Io)?;

        if let Some(keep) = config.prune_keep_blocks {
            assert!(
                keep > config.snapshot_interval * 2,
                "prune_keep_blocks ({}) must be greater than 2x snapshot_interval ({}) to guarantee snapshot-based restart is always possible",
                keep,
                config.snapshot_interval
            );
        }

        let mut block_store = BlockStore::open(config.block_log_path(), config.prune_config())?;
        let epoch_store = EpochStore::open(config.epoch_log_path())?;
        let state_store = StateStore::open(config.state_dir())?;
        let migration_log = MigrationLog::open(config.migration_log_path());
        let stored_schema_version = state_store.schema_version()?;
        if let Some(snapshot_version) = stored_schema_version {
            if snapshot_version > indra_core::types::primitives::SCHEMA_VERSION {
                return Err(NodeError::SchemaVersionTooNew {
                    snapshot_version,
                    node_version: indra_core::types::primitives::SCHEMA_VERSION,
                });
            }
        }
        let mut genesis_base = ChainState::new_genesis();
        if let Some(ref genesis_path) = config.genesis_path {
            load_genesis_validators(genesis_path, &mut genesis_base);
        }
        let startup_log;
        let state = if let Some(snapshot) = state_store.load_latest()? {
            if let Some(from_version) = stored_schema_version {
                if from_version < indra_core::types::primitives::SCHEMA_VERSION {
                    let record = migration_record(
                        &snapshot,
                        from_version,
                        indra_core::types::primitives::SCHEMA_VERSION,
                    );
                    migration_log.append(&record)?;
                    state_store.save(&snapshot)?;
                }
            }
            let replay_start = snapshot.height.saturating_add(1);
            if !block_store.is_empty() && block_store.lowest_height() > replay_start {
                return Err(NodeError::SnapshotReplayGap {
                    snapshot_height: snapshot.height,
                    lowest_block: block_store.lowest_height(),
                    gap: block_store.lowest_height().saturating_sub(replay_start),
                });
            }

            startup_log = startup_mode_message(
                Some(snapshot.height),
                replay_start,
                block_store.next_height(),
            );
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
            rebuild_state_from_height(&mut genesis_base, &mut block_store, 1)?;
            genesis_base
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
                    let pq = if let (Some(pk), Some(sk)) =
                        (config.pq_pk.as_deref(), config.pq_sk.as_deref())
                    {
                        PqKeypair::from_bytes(pk, sk).unwrap_or_else(|_| PqKeypair::generate())
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
            staking_mempool: Vec::new(),
            governance_mempool: Vec::new(),
            pending_slashes: Vec::new(),
            block_store,
            epoch_store,
            state_store,
            migration_log,
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

    /// Rebuild the current chain state by replaying the block log on top of a
    /// fresh genesis-equivalent state seeded from the configured genesis file.
    pub fn rebuild_state_from_block_log(&mut self) -> NodeResult<()> {
        let mut rebuilt = ChainState::new_genesis();
        if let Some(ref genesis_path) = self.config.genesis_path {
            load_genesis_validators(genesis_path, &mut rebuilt);
        }
        rebuild_state_from_height(&mut rebuilt, &mut self.block_store, 1)?;
        self.state = rebuilt;
        Ok(())
    }

    /// Add a staking operation to the pending pool.
    pub fn add_staking_op(&mut self, op: StakingOp) -> NodeResult<()> {
        op.validate_structure()
            .map_err(|e| NodeError::InvalidStakingOp(e.to_string()))?;
        let signer_id = op.signer_id();
        let nonce = op.nonce;
        if self
            .staking_mempool
            .iter()
            .any(|existing| existing.signer_id() == signer_id && existing.nonce == nonce)
        {
            return Err(NodeError::InvalidStakingOp(
                "duplicate staking op nonce".into(),
            ));
        }
        self.staking_mempool.push(op);
        Ok(())
    }

    /// Add a governance operation to the pending pool.
    pub fn add_governance_op(&mut self, op: GovernanceOpV2) -> NodeResult<()> {
        let signer_id = op.signer_id;
        let nonce = op.nonce;
        if self
            .governance_mempool
            .iter()
            .any(|existing| existing.signer_id == signer_id && existing.nonce == nonce)
        {
            return Err(NodeError::InvalidGovernanceOp(
                "duplicate governance op nonce".into(),
            ));
        }
        self.governance_mempool.push(op);
        Ok(())
    }

    /// Add slash evidence to the pending pool if it has not already been seen.
    pub fn add_slash_evidence(&mut self, evidence: SlashEvidenceV1) {
        let hash = compute_slash_evidence_hash(&evidence);
        let already_pending = self
            .pending_slashes
            .iter()
            .any(|existing| compute_slash_evidence_hash(existing) == hash);
        if !already_pending && !self.state.applied_slash_hashes.contains(&hash) {
            self.pending_slashes.push(evidence);
        }
    }

    /// Select slash evidence for the next proposed block.
    pub fn select_slash_evidence(&self) -> Vec<SlashEvidenceV1> {
        self.pending_slashes
            .iter()
            .take(MAX_SLASHES_PER_BLOCK)
            .cloned()
            .collect()
    }

    /// Remove slash evidence that has already been committed.
    pub fn evict_committed_slashes(&mut self, committed: &[SlashEvidenceV1]) {
        for evidence in committed {
            let hash = compute_slash_evidence_hash(evidence);
            self.pending_slashes
                .retain(|pending| compute_slash_evidence_hash(pending) != hash);
        }
    }

    /// Select staking operations for block inclusion.
    pub fn select_staking_ops(&self) -> Vec<StakingOp> {
        self.staking_mempool
            .iter()
            .take(MAX_STAKING_OPS_PER_BLOCK)
            .cloned()
            .collect()
    }

    /// Select governance operations for block inclusion.
    pub fn select_governance_ops(&self) -> Vec<GovernanceOpV2> {
        self.governance_mempool
            .iter()
            .take(MAX_GOV_OPS_PER_BLOCK)
            .cloned()
            .collect()
    }

    /// Remove staking operations included in a committed block.
    pub fn evict_committed_staking_ops(&mut self, committed_ops: &[StakingOp]) {
        for op in committed_ops {
            let signer_id = op.signer_id();
            let nonce = op.nonce;
            self.staking_mempool
                .retain(|existing| !(existing.signer_id() == signer_id && existing.nonce == nonce));
        }
    }

    /// Remove governance operations included in a committed block.
    pub fn evict_committed_governance_ops(&mut self, committed_ops: &[GovernanceOpV2]) {
        for op in committed_ops {
            let signer_id = op.signer_id;
            let nonce = op.nonce;
            self.governance_mempool
                .retain(|existing| !(existing.signer_id == signer_id && existing.nonce == nonce));
        }
    }

    /// Check if this node is the elected proposer for the next height.
    pub fn is_proposer(&self, election: &ProposerElection) -> bool {
        let my_id = self
            .validator_id
            .map(|id| hex::encode(&id.0[..4]))
            .unwrap_or_else(|| "none".to_string());
        let has_vrf = self.vrf_keypair.is_some();
        let cand_count = election.candidates.len();
        let in_candidates = self
            .validator_id
            .map(|validator_id| {
                election
                    .candidates
                    .iter()
                    .any(|candidate| candidate.validator_id == validator_id)
            })
            .unwrap_or(false);

        let Some(vrf_kp) = &self.vrf_keypair else {
            return false;
        };
        let Some(validator_id) = self.validator_id else {
            return false;
        };
        let slot = compute_proposer_vrf(
            validator_id,
            vrf_kp,
            &election.epoch_seed,
            election.height,
            election.round,
        );
        let mut effective_election = ProposerElection {
            epoch_seed: election.epoch_seed,
            height: election.height,
            round: election.round,
            candidates: election.candidates.clone(),
        };
        if let Some(candidate) = effective_election
            .candidates
            .iter_mut()
            .find(|candidate| candidate.validator_id == slot.proposer_id)
        {
            candidate.verified_vrf_output = Some(slot.vrf_output.clone());
        }
        let elected = match elect_proposer(&effective_election, election.height) {
            Ok(id) => id,
            Err(_) => {
                eprintln!(
                    "[proposer] id={} has_vrf={} in_candidates={} candidates={} elected=err should_propose=false",
                    my_id, has_vrf, in_candidates, cand_count
                );
                return false;
            }
        };
        elected == slot.proposer_id
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

        let _vrf_kp = self.vrf_keypair.as_ref().ok_or(NodeError::NotProposer {
            height: proposal_height,
        })?;

        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&self.config.vrf_seed.ok_or(
                NodeError::NotProposer {
                    height: proposal_height,
                },
            )?),
            epoch_seed: election.epoch_seed,
            prev_qc_bytes,
            timestamp,
            polc_round,
            slash_evidence: self.select_slash_evidence(),
            governance_ops: self.select_governance_ops(),
            staking_ops: self.select_staking_ops(),
        };

        eprintln!(
            "[proposer] producing block at height={} round={}",
            proposal_height, election.round
        );
        produce_block(&template, &self.state, &self.mempool, election).map_err(NodeError::Consensus)
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
        let mut effective_election = ProposerElection {
            epoch_seed: election.epoch_seed,
            height: election.height,
            round: election.round,
            candidates: election.candidates.clone(),
        };
        if let Some(candidate) = effective_election
            .candidates
            .iter_mut()
            .find(|candidate| candidate.validator_id == slot.proposer_id)
        {
            candidate.verified_vrf_output = Some(slot.vrf_output.clone());
        }
        let elected =
            elect_proposer(&effective_election, election.height).map_err(NodeError::Consensus)?;
        if elected != slot.proposer_id {
            return Err(NodeError::NotProposer {
                height: proposal_height,
            });
        }

        let vrf_proof_bytes = VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&slot.vrf_proof.0)
            .map_err(|_| {
            NodeError::Consensus(indra_consensus::error::ConsensusError::CryptoError {
                detail: "VRF proof too large".to_string(),
            })
        })?;
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
            staking_ops: original_block.staking_ops.clone(),
        };

        let mut projected = self.state.clone();
        indra_state::apply_block(&mut projected, &block, 0)?;
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
        active
            .into_iter()
            .filter_map(|validator| {
                Some(RegisteredVoter {
                    validator_id: validator.validator_id,
                    classical_pk: validator.hybrid_classical_pk?,
                    pq_pk: validator.hybrid_pq_pk.clone()?,
                    stake: validator.stake_spark,
                })
            })
            .collect()
    }

    /// Build the QC validator list for the current epoch.
    pub fn qc_validators(&self) -> Vec<QcValidator> {
        let mut active: Vec<_> = self.state.validators.active_validators().collect();
        active.sort_by_key(|validator| validator.validator_id.0);
        active
            .into_iter()
            .enumerate()
            .filter_map(|(position, validator)| {
                Some(QcValidator {
                    validator_id: validator.validator_id,
                    position,
                    pq_pk: validator.hybrid_pq_pk.clone()?,
                    classical_pk: validator.hybrid_classical_pk?,
                    stake: validator.stake_spark,
                })
            })
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
        let hybrid_keypair = self
            .hybrid_keypair
            .as_ref()
            .ok_or(NodeError::NotValidator)?;
        produce_vote(
            height,
            round,
            step,
            block_hash,
            validator_id,
            hybrid_keypair,
        )
        .map_err(NodeError::Consensus)
    }

    /// Import a block that has been committed (QC formed).
    pub fn commit_block(&mut self, block: &indra_core::types::block::BlockV1) -> NodeResult<()> {
        let epoch_record = import_block(
            block,
            &mut self.state,
            &mut self.mempool,
            &mut self.block_store,
            &self.state_store,
            current_timestamp_secs(),
        )?;
        if let Some(record) = epoch_record {
            self.epoch_store.append(&record)?;
        }
        // QC signer liveness is updated inside `apply_block` so live import,
        // sync import, replay, and block-production projection mutate state
        // identically.
        if self.state.height > 0
            && self
                .state
                .height
                .is_multiple_of(indra_storage::state_store::SNAPSHOT_INTERVAL)
        {
            self.state_store.save(&self.state)?;
        }
        self.evict_committed_staking_ops(&block.staking_ops);
        self.evict_committed_governance_ops(&block.governance_ops);
        self.evict_committed_slashes(&block.slashing_evidence);
        Ok(())
    }
}

fn current_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn startup_mode_message(
    snapshot_height: Option<u64>,
    replay_start: u64,
    next_height: u64,
) -> String {
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
        indra_state::apply_block(state, &block, 0)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_consensus::{
        build_qc,
        producer::{produce_block, BlockTemplate},
        proposer::ProposerCandidate,
        qc::QcValidator,
        vote::produce_vote,
    };
    use indra_core::codec::Encode;
    use indra_core::types::crypto::{HybridPubKey, HybridSignature};
    use indra_core::types::primitives::{DEFAULT_COMMISSION_BPS, DUST_LIMIT_SPARK};
    use indra_core::types::slashing::SlashEvidenceV1;
    use indra_core::types::staking::StakingOpBody;
    use indra_core::types::vote::{VoteStep, VoteV1};
    use indra_core::VariableBytes;
    use indra_state::{ValidatorEntry, ValidatorStatus};

    fn temp_dir(suffix: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "indra_engine_test_{}_{}",
            suffix,
            std::process::id()
        ));
        p
    }

    fn install_active_validator(
        engine: &mut NodeEngine,
        seed: [u8; 32],
        name: &str,
    ) -> HybridKeypair {
        let classical = ClassicalKeypair::from_seed(&seed);
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let hybrid = HybridKeypair::new(classical, pq);
        let public = hybrid.public_key();
        let vrf_pk = VrfKeypair::from_seed(&seed).public_key();
        let validator_id = Bytes32::from(indra_crypto::sha256(&public.classical.0));

        engine
            .state
            .validators
            .upsert(ValidatorEntry {
                validator_id,
                name: name.to_string(),
                hybrid_classical_pk: Some(public.classical.0),
                hybrid_pq_pk: Some(public.pq.0.to_vec()),
                vrf_pk: Some(vrf_pk),
                stake_spark: 1_000_000,
                status: ValidatorStatus::Active,
                registered_epoch: 0,
                last_active_epoch: 0,
                pending_rewards: 0,
                rewards_last_epoch: 0,
                self_report_count: 0,
                commission_bps: DEFAULT_COMMISSION_BPS,
                min_delegation_spark: DUST_LIMIT_SPARK,
                auto_delegate_to: None,
            })
            .unwrap();
        hybrid
    }

    fn dummy_signature() -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
        }
    }

    fn dummy_staking_op(seed: u8, nonce: u64) -> StakingOp {
        StakingOp {
            body: StakingOpBody::Delegate {
                validator_id: Bytes32::from([0xAA; 32]),
                bond_utxo_id: Bytes32::from([0xBB; 32]),
                delegator_pubkey: HybridPubKey {
                    classical_pk: Bytes32::from([seed; 32]),
                    pq_pk: VariableBytes::from_slice(&[seed; 2592]).unwrap(),
                },
            },
            nonce,
            signature: dummy_signature(),
        }
    }

    fn dummy_slash_evidence(seed: u8) -> SlashEvidenceV1 {
        let validator_id = Bytes32::from([seed; 32]);
        let vote = |block_byte| VoteV1 {
            height: 7,
            round: 0,
            step: VoteStep::Precommit,
            block_hash: Bytes32::from([block_byte; 32]),
            validator_id,
            signature: dummy_signature(),
        };
        SlashEvidenceV1 {
            validator_id,
            vote_1: vote(0xAA),
            vote_2: vote(0xBB),
        }
    }

    fn make_strict_block(
        state: &indra_state::ChainState,
        proposer_seed: [u8; 32],
        prev_qc_bytes: Vec<u8>,
    ) -> indra_core::types::block::BlockV1 {
        let epoch_seed = Bytes32::from(indra_crypto::sha256(&state.tip_hash.0));
        let mut candidates: Vec<_> = state
            .validators
            .active_validators()
            .filter_map(|validator| {
                validator.vrf_pk.map(|vrf_pk| ProposerCandidate {
                    validator_id: validator.validator_id,
                    vrf_pubkey: vrf_pk,
                    verified_vrf_output: None,
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
            governance_ops: vec![],
            staking_ops: vec![],
        };
        produce_block(
            &template,
            state,
            &indra_consensus::mempool::Mempool::default_config(),
            &election,
        )
        .unwrap()
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
                classical_pk: public.classical.0,
                stake: 1_000_000,
            }],
            vec![&vote],
        )
        .unwrap();
        qc.encode_to_vec()
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
    fn pending_slash_deduplicates_by_hash() {
        let dir = temp_dir("slash_dedupe");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let evidence = dummy_slash_evidence(0xA1);
        engine.add_slash_evidence(evidence.clone());
        engine.add_slash_evidence(evidence);
        assert_eq!(engine.pending_slashes.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evict_committed_slashes_removes_correct() {
        let dir = temp_dir("slash_evict");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let first = dummy_slash_evidence(0xA2);
        let second = dummy_slash_evidence(0xA3);
        engine.add_slash_evidence(first.clone());
        engine.add_slash_evidence(second.clone());
        engine.evict_committed_slashes(&[first]);
        assert_eq!(engine.pending_slashes, vec![second]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_slash_already_applied_ignored() {
        let dir = temp_dir("slash_applied");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let evidence = dummy_slash_evidence(0xA4);
        engine
            .state
            .applied_slash_hashes
            .insert(compute_slash_evidence_hash(&evidence));
        engine.add_slash_evidence(evidence);
        assert!(engine.pending_slashes.is_empty());
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
        install_active_validator(&mut engine, [0x42u8; 32], "local");
        let block = make_strict_block(&engine.state, [0x42u8; 32], vec![]);

        engine.commit_block(&block).unwrap();
        assert_eq!(engine.height(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_rebuilds_state_from_block_log() {
        let dir = temp_dir("d");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config.clone()).unwrap();
        install_active_validator(&mut engine, [0x42u8; 32], "local");
        let mut last_qc = Vec::new();

        for height in 1..=3u64 {
            let block = make_strict_block(&engine.state, [0x42u8; 32], last_qc.clone());
            engine.commit_block(&block).unwrap();
            last_qc =
                build_single_validator_qc_bytes(height, 0, block.header.value_hash, [0x42u8; 32]);
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
            install_active_validator(&mut engine, [0x42u8; 32], "local");
            let mut last_qc = Vec::new();
            for height in 1..=1_000u64 {
                let block = make_strict_block(&engine.state, [0x42u8; 32], last_qc.clone());
                engine.commit_block(&block).unwrap();
                last_qc = build_single_validator_qc_bytes(
                    height,
                    0,
                    block.header.value_hash,
                    [0x42u8; 32],
                );
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
    fn restart_from_snapshot_produces_same_state_as_continuous() {
        let dir = temp_dir("snapshot_state_root");
        let mut config = NodeConfig::local_test(dir.clone());
        config.prune_keep_blocks = Some(650);

        let (continuous_state, next_block) = {
            let mut engine = NodeEngine::init(config.clone()).unwrap();
            install_active_validator(&mut engine, [0x42u8; 32], "local");
            let mut last_qc = Vec::new();
            for height in 1..=610u64 {
                let block = make_strict_block(&engine.state, [0x42u8; 32], last_qc.clone());
                engine.commit_block(&block).unwrap();
                last_qc = build_single_validator_qc_bytes(
                    height,
                    0,
                    block.header.value_hash,
                    [0x42u8; 32],
                );
                assert_eq!(engine.state.height, height);
            }
            let next_block = make_strict_block(&engine.state, [0x42u8; 32], last_qc.clone());
            (engine.state.clone(), next_block)
        };

        let restarted = NodeEngine::init(config).unwrap();
        assert_eq!(restarted.state.height, continuous_state.height);
        assert_eq!(restarted.state.tip_hash, continuous_state.tip_hash);
        assert_eq!(
            indra_state::compute_state_root(&restarted.state),
            indra_state::compute_state_root(&continuous_state)
        );

        let mut continuous_next = continuous_state.clone();
        let mut restarted_next = restarted.state.clone();
        indra_state::apply_block(&mut continuous_next, &next_block, 0).unwrap();
        indra_state::apply_block(&mut restarted_next, &next_block, 0).unwrap();

        assert_eq!(
            indra_state::compute_state_root(&continuous_next),
            indra_state::compute_state_root(&restarted_next)
        );
        assert_eq!(
            indra_state::compute_validator_set_root(&continuous_next),
            indra_state::compute_validator_set_root(&restarted_next)
        );
        assert_eq!(continuous_next, restarted_next);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_id_survives_snapshot_restart() {
        let dir = temp_dir("chain_id_snapshot");
        let config = NodeConfig::local_test(dir.clone());

        {
            let mut engine = NodeEngine::init(config.clone()).unwrap();
            engine.state.chain_id = "indra-custom-testnet".to_string();
            engine.state_store.save(&engine.state).unwrap();
        }

        let restarted = NodeEngine::init(config).unwrap();
        assert_eq!(restarted.state.chain_id, "indra-custom-testnet");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_fails_on_snapshot_replay_gap() {
        let dir = temp_dir("snapshot_gap");
        let mut config = NodeConfig::local_test(dir.clone());
        config.prune_keep_blocks = Some(1_000);

        {
            let mut engine = NodeEngine::init(config.clone()).unwrap();
            install_active_validator(&mut engine, [0x42u8; 32], "local");
            let mut last_qc = Vec::new();
            for _ in 0..1_600u64 {
                let height = engine.state.height + 1;
                let block = make_strict_block(&engine.state, [0x42u8; 32], last_qc.clone());
                engine.commit_block(&block).unwrap();
                last_qc = build_single_validator_qc_bytes(
                    height,
                    0,
                    block.header.value_hash,
                    [0x42u8; 32],
                );
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
    #[should_panic(
        expected = "prune_keep_blocks (100) must be greater than 2x snapshot_interval (150)"
    )]
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
    fn init_loads_genesis_utxos_once() {
        let dir = temp_dir("genesis_utxo");
        std::fs::create_dir_all(&dir).unwrap();
        let mut config = NodeConfig::local_test(dir.clone());

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
        config.genesis_path = Some(genesis_path.to_string_lossy().to_string());

        let mut engine = NodeEngine::init(config).unwrap();
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

        let candidate = engine.state.validators.active_validators().next().unwrap();
        let election = ProposerElection {
            epoch_seed: Bytes32::from(indra_crypto::sha256(&engine.state.tip_hash.0)),
            height: 3,
            round: 0,
            candidates: vec![indra_consensus::proposer::ProposerCandidate {
                validator_id: candidate.validator_id,
                vrf_pubkey: candidate.vrf_pk.unwrap(),
                verified_vrf_output: None,
                stake: candidate.stake_spark,
            }],
        };

        let err = engine
            .propose(&election, 1_700_000_003, Vec::new(), None)
            .unwrap_err();
        assert!(matches!(err, NodeError::MissingQc { height: 3 }));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staking_mempool_deduplicates_by_nonce() {
        let dir = temp_dir("staking_mempool_dedup");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let op = dummy_staking_op(0x11, 1);

        engine.add_staking_op(op.clone()).unwrap();
        assert!(matches!(
            engine.add_staking_op(op),
            Err(NodeError::InvalidStakingOp(_))
        ));
        assert_eq!(engine.staking_mempool.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evict_committed_ops_removes_correct_entries() {
        let dir = temp_dir("staking_mempool_evict");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let committed = dummy_staking_op(0x11, 1);
        let retained = dummy_staking_op(0x11, 2);

        engine.add_staking_op(committed.clone()).unwrap();
        engine.add_staking_op(retained.clone()).unwrap();
        engine.evict_committed_staking_ops(&[committed]);

        assert_eq!(engine.staking_mempool, vec![retained]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
