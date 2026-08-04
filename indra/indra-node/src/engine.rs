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
    qc::{verify_qc, verify_qc_strict, QcValidator},
    vote::{produce_vote_with_election_result, RegisteredVoter},
};
use indra_core::codec::{ByteReader, Decode};
use indra_core::types::{
    block::{BlockHeaderV1, BlockV1, NO_POLC_ROUND},
    governance::GovernanceOpV2,
    primitives::{
        Bytes32, VariableBytes, MAX_GOV_OPS_PER_BLOCK, MAX_QC_SIZE_BYTES, MAX_SLASHES_PER_BLOCK,
        MAX_STAKING_OPS_PER_BLOCK, MAX_VRF_PROOF_BYTES,
    },
    slash_membership::build_slash_membership_proof,
    slashing::{SlashEvidenceV1, SlashEvidenceV2},
    staking::StakingOp,
    vote::VoteStep,
    vrf_election::{compute_reveal_set_commitment, VrfElectionResult, VrfRevealEvidence},
    ConsensusSnapshot,
};
use indra_crypto::{
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    VrfKeypair,
};
use indra_state::{
    apply::{compute_pending_slash_evidence_hash, compute_slash_evidence_v2_hash},
    apply_staking_op,
    epoch::epoch_for_height,
    governance_apply::{apply_governance_op, validate_governance_op},
    ChainState,
};
use indra_storage::{
    load_chain_manifest, load_last_qc, save_chain_manifest, BlockStore, ChainManifest, EpochStore,
    StateStore,
};

use crate::{
    config::NodeConfig,
    error::{NodeError, NodeResult},
    genesis::build_genesis_block,
    sync::{import_block, project_and_verify_block_state_root},
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
    /// The validator's hybrid keypair (if this is a validator node).
    #[allow(dead_code)] // retained for future local signing flows
    hybrid_keypair: Option<HybridKeypair>,
    /// The validator's VRF keypair.
    vrf_keypair: Option<VrfKeypair>,
    /// This validator's identity (SHA-256 of hybrid public key classical component).
    validator_id: Option<Bytes32>,
}

/// Validator authority used by authenticated transport, relay checks, and
/// on-chain peer discovery for one consensus height.
///
/// Membership and consensus keys are snapshot-authoritative after the
/// consensus-snapshot gate. `network_addr` remains live metadata because it is
/// deliberately mutable and is not committed into `ConsensusSnapshot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAuthorityMember {
    /// Validator identity authorized for the requested consensus height.
    pub validator_id: Bytes32,
    /// Ed25519 consensus verification key, when present on the legacy path.
    pub hybrid_classical_pk: Option<[u8; 32]>,
    /// ML-DSA-87 consensus/transport verification key.
    pub hybrid_pq_pk: Option<Vec<u8>>,
    /// VRF verification key, when present on the legacy path.
    pub vrf_pk: Option<[u8; 32]>,
    /// Current live network address for this authorized member, if available.
    pub network_addr: Option<String>,
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
        let stored_schema_version = state_store.schema_version()?;
        if let Some(snapshot_version) = stored_schema_version {
            if snapshot_version != indra_core::types::primitives::SCHEMA_VERSION {
                return Err(NodeError::SchemaVersionTooNew {
                    snapshot_version,
                    node_version: indra_core::types::primitives::SCHEMA_VERSION,
                });
            }
        }
        let mut genesis_base = crate::genesis::build_finalized_genesis_state_with_minimum(
            config.genesis_path.as_deref(),
            config.genesis_validator_minimum,
        )
        .map_err(|detail| NodeError::ValidatorConfigIncomplete { detail })?;
        let startup_log;
        let state = if let Some(snapshot) = state_store.load_latest()? {
            verify_snapshot_tip_against_retained_block(&snapshot, &mut block_store)?;
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
        validate_manifest_if_present(&config, &state, &mut block_store, &epoch_store)?;
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
        let mut rebuilt = crate::genesis::build_finalized_genesis_state_with_minimum(
            self.config.genesis_path.as_deref(),
            self.config.genesis_validator_minimum,
        )
        .map_err(|detail| NodeError::ValidatorConfigIncomplete { detail })?;
        rebuild_state_from_height(&mut rebuilt, &mut self.block_store, 1)?;
        self.state = rebuilt;
        Ok(())
    }

    /// Add a staking operation to the pending pool.
    pub fn add_staking_op(&mut self, op: StakingOp) -> NodeResult<()> {
        op.validate_structure()
            .map_err(|e| NodeError::InvalidStakingOp(e.to_string()))?;
        let signer_id = op.signer_id();
        let cold_authorization = op.cold_authorization();
        let mut scratch = self.state.clone();
        let chain_id = self.state.chain_id.clone();
        let validation_height = self.state.height.saturating_add(1);
        apply_staking_op(&mut scratch, &op, &chain_id, validation_height)
            .map_err(|e| NodeError::InvalidStakingOp(e.to_string()))?;
        if self.staking_mempool.iter().any(|existing| {
            existing.signer_id() == signer_id
                && match (existing.cold_authorization(), cold_authorization) {
                    (Some(existing), Some(submitted)) => existing == submitted,
                    (None, None) => existing.nonce == op.nonce,
                    _ => false,
                }
        }) {
            return Err(NodeError::InvalidStakingOp(
                "duplicate staking op nonce".into(),
            ));
        }
        if self.staking_mempool.len() >= self.config.staking_mempool_capacity {
            return Err(NodeError::InvalidStakingOp(format!(
                "staking mempool full: {} ops",
                self.config.staking_mempool_capacity
            )));
        }
        self.staking_mempool.push(op);
        Ok(())
    }

    /// Add a governance operation to the pending pool.
    pub fn add_governance_op(&mut self, op: GovernanceOpV2) -> NodeResult<()> {
        let signer_id = op.signer_id;
        let cold_authorization = op.cold_authorization();
        let current_epoch = epoch_for_height(self.state.height.saturating_add(1));
        validate_governance_op(&self.state, &op, current_epoch, &self.state.chain_id)
            .map_err(|error| NodeError::InvalidGovernanceOp(error.to_string()))?;
        if self.governance_mempool.iter().any(|existing| {
            existing.signer_id == signer_id
                && match (existing.cold_authorization(), cold_authorization) {
                    (Some(existing), Some(submitted)) => existing == submitted,
                    (None, None) => existing.nonce == op.nonce,
                    _ => false,
                }
        }) {
            return Err(NodeError::InvalidGovernanceOp(
                "duplicate governance op nonce".into(),
            ));
        }
        if self.governance_mempool.len() >= self.config.governance_mempool_capacity {
            return Err(NodeError::InvalidGovernanceOp(format!(
                "governance mempool full: {} ops",
                self.config.governance_mempool_capacity
            )));
        }
        self.governance_mempool.push(op);
        Ok(())
    }

    /// Remove governance operations that are no longer valid against the
    /// current tip before selecting them for a new block.
    pub fn prune_invalid_governance_ops(&mut self) {
        if self.governance_mempool.is_empty() {
            return;
        }
        let current_epoch = epoch_for_height(self.state.height.saturating_add(1));
        let chain_id = self.state.chain_id.clone();
        let state = self.state.clone();
        self.governance_mempool.retain(|op| {
            let valid = validate_governance_op(&state, op, current_epoch, &chain_id).is_ok();
            if !valid {
                eprintln!(
                    "[governance] evicting invalid pending op signer={} nonce={}",
                    hex::encode(&op.signer_id.0[..4]),
                    op.nonce
                );
            }
            valid
        });
    }

    /// Add slash evidence to the pending pool if it has not already been seen.
    pub fn add_slash_evidence(&mut self, evidence: SlashEvidenceV1) {
        let hash = compute_pending_slash_evidence_hash(&evidence);
        let already_pending = self
            .pending_slashes
            .iter()
            .any(|existing| compute_pending_slash_evidence_hash(existing) == hash);
        if !already_pending && !self.state.applied_slash_hashes.contains(&hash) {
            self.pending_slashes.push(evidence);
        }
    }

    /// Select and prove membership-authorized slash evidence.
    pub fn select_slash_evidence(&self) -> Vec<SlashEvidenceV2> {
        self.pending_slashes
            .iter()
            .filter_map(|evidence| {
                let snapshot = self
                    .state
                    .snapshot_for_consensus_height(evidence.vote_1.height)
                    .ok()?;
                let (position, _) = snapshot.entry_with_position(&evidence.validator_id)?;
                let membership_proof = build_slash_membership_proof(snapshot, position).ok()?;
                Some(SlashEvidenceV2 {
                    validator_id: evidence.validator_id,
                    vote_1: evidence.vote_1.clone(),
                    vote_2: evidence.vote_2.clone(),
                    membership_proof,
                })
            })
            .take(MAX_SLASHES_PER_BLOCK)
            .collect()
    }

    /// Remove slash evidence that has already been committed.
    pub fn evict_committed_slashes(&mut self, committed: &[SlashEvidenceV2]) {
        for evidence in committed {
            let hash = compute_slash_evidence_v2_hash(evidence);
            if !self.state.applied_slash_hashes.contains(&hash) {
                continue;
            }
            let legacy = SlashEvidenceV1 {
                validator_id: evidence.validator_id,
                vote_1: evidence.vote_1.clone(),
                vote_2: evidence.vote_2.clone(),
            };
            let legacy_hash = compute_pending_slash_evidence_hash(&legacy);
            self.pending_slashes
                .retain(|pending| compute_pending_slash_evidence_hash(pending) != legacy_hash);
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
    pub fn select_governance_ops(&mut self) -> Vec<GovernanceOpV2> {
        if self.governance_mempool.is_empty() {
            return Vec::new();
        }
        let current_epoch = epoch_for_height(self.state.height.saturating_add(1));
        let chain_id = self.state.chain_id.clone();
        let mut scratch = self.state.clone();
        let mut selected = Vec::new();
        let mut retained = Vec::new();
        for op in std::mem::take(&mut self.governance_mempool) {
            if selected.len() >= MAX_GOV_OPS_PER_BLOCK {
                retained.push(op);
                continue;
            }
            let current_height = scratch.height;
            match apply_governance_op(&mut scratch, &op, current_epoch, current_height, &chain_id) {
                Ok(()) => {
                    selected.push(op.clone());
                    retained.push(op);
                }
                Err(error) => {
                    eprintln!(
                        "[governance] evicting invalid pending op signer={} nonce={}: {}",
                        hex::encode(&op.signer_id.0[..4]),
                        op.nonce,
                        error
                    );
                }
            }
        }
        self.governance_mempool = retained;
        selected
    }

    /// Remove staking operations included in a committed block.
    pub fn evict_committed_staking_ops(&mut self, committed_ops: &[StakingOp]) {
        for op in committed_ops {
            let signer_id = op.signer_id();
            let cold_authorization = op.cold_authorization();
            self.staking_mempool.retain(|existing| {
                if existing.signer_id() != signer_id {
                    return true;
                }
                !match (existing.cold_authorization(), cold_authorization) {
                    (Some(existing), Some(committed)) => existing == committed,
                    (None, None) => existing.nonce == op.nonce,
                    _ => false,
                }
            });
        }
    }

    /// Remove governance operations included in a committed block.
    pub fn evict_committed_governance_ops(&mut self, committed_ops: &[GovernanceOpV2]) {
        for op in committed_ops {
            let signer_id = op.signer_id;
            let cold_authorization = op.cold_authorization();
            self.governance_mempool.retain(|existing| {
                if existing.signer_id != signer_id {
                    return true;
                }
                !match (existing.cold_authorization(), cold_authorization) {
                    (Some(existing), Some(committed)) => existing == committed,
                    (None, None) => existing.nonce == op.nonce,
                    _ => false,
                }
            });
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
        let Some(local_candidate) = election
            .candidates
            .iter()
            .find(|candidate| candidate.validator_id == validator_id)
        else {
            return false;
        };
        if local_candidate.vrf_pubkey != vrf_kp.public_key() {
            eprintln!(
                "[proposer] local VRF key does not match registered validator VRF key for validator {} — refusing to propose",
                hex::encode(&validator_id.0[..4])
            );
            return false;
        }
        let elected = match elect_proposer(election, election.height) {
            Ok(id) => id,
            Err(_) => {
                eprintln!(
                    "[proposer] id={} has_vrf={} in_candidates={} candidates={} elected=err should_propose=false",
                    my_id, has_vrf, in_candidates, cand_count
                );
                return false;
            }
        };
        elected == validator_id
    }

    /// Propose a block for the next height (only if this node is the proposer).
    /// Propose a block using the authoritative commit-reveal election result.
    pub fn propose(
        &mut self,
        election: &ProposerElection,
        timestamp: u64,
        prev_qc_bytes: Vec<u8>,
        polc_round: Option<u32>,
        election_result: Option<VrfElectionResult>,
        vrf_reveals: Vec<VrfRevealEvidence>,
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

        let vrf_kp = self
            .vrf_keypair
            .as_ref()
            .ok_or(NodeError::NotProposer {
                height: proposal_height,
            })?
            .clone();

        self.prune_invalid_governance_ops();

        let election_result = election_result.ok_or_else(|| {
            NodeError::Consensus(indra_consensus::ConsensusError::WrongProposer {
                reason: "missing authoritative election result",
            })
        })?;
        let election_result_hash = election_result.hash();
        let template = BlockTemplate {
            proposer_vrf_keypair: vrf_kp,
            epoch_seed: election.epoch_seed,
            prev_qc_bytes,
            timestamp,
            polc_round,
            slash_evidence: self.select_slash_evidence(),
            governance_ops: self.select_governance_ops(),
            staking_ops: self.select_staking_ops(),
            election_result_hash: Some(election_result_hash),
            election_result: Some(election_result),
            vrf_reveals,
        };

        eprintln!(
            "[proposer] producing block at height={} round={}",
            proposal_height, election.round
        );
        produce_block(&template, &mut self.state, &self.mempool, election)
            .map_err(NodeError::Consensus)
    }

    /// Re-propose an already validated value in a later round while keeping
    /// its stable consensus value hash unchanged.
    /// Re-propose a valid block using the authoritative commit-reveal election result.
    pub fn repropose(
        &mut self,
        original_block: &BlockV1,
        new_round: u32,
        valid_round: Option<u32>,
        election: &ProposerElection,
        timestamp: u64,
        last_qc: Vec<u8>,
        election_result: Option<VrfElectionResult>,
        vrf_reveals: Vec<VrfRevealEvidence>,
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
        let election_result = election_result.ok_or(NodeError::NotProposer {
            height: proposal_height,
        })?;
        let election_result_hash = election_result.hash();
        if election_result.height != election.height
            || election_result.round != election.round
            || election_result.elected_validator_id != slot.proposer_id
            || election_result.reveal_set_commitment != compute_reveal_set_commitment(&vrf_reveals)
        {
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
                election_result_hash: Some(election_result_hash),
            },
            transactions: original_block.transactions.clone(),
            slashing_evidence: original_block.slashing_evidence.clone(),
            governance_ops: original_block.governance_ops.clone(),
            staking_ops: original_block.staking_ops.clone(),
            vrf_reveals,
        };

        let projected = indra_state::project_block_for_roots(&mut self.state, &block, 0)?;
        let expected_value_hash = projected.value_hash;
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

    /// Build the immutable voter list for `height` from its resolved snapshot.
    ///
    /// The caller must pass `S(height)`, resolved by the authoritative
    /// height-derived lookup. `height` remains explicit so post-gate adapters
    /// cannot hide which consensus height they are serving.
    pub fn registered_voters_for_height(
        height: u64,
        snapshot: &ConsensusSnapshot,
    ) -> Vec<RegisteredVoter> {
        debug_assert!(snapshot.activation_height <= height);
        snapshot
            .entries()
            .iter()
            .map(|entry| RegisteredVoter {
                validator_id: entry.validator_id,
                classical_pk: entry.classical_vote_pk,
                pq_pk: entry.pq_vote_pk.to_vec(),
                stake: entry.consensus_weight_spark,
            })
            .collect()
    }

    /// Resolve the voter authority for one consensus height.
    ///
    /// Legacy heights preserve the original live-registry adapter exactly.
    /// Governed heights fail closed if their canonical snapshot is unavailable.
    pub fn voters_for_consensus_height(&self, height: u64) -> NodeResult<Vec<RegisteredVoter>> {
        let snapshot = self.state.snapshot_for_consensus_height(height)?;
        Ok(Self::registered_voters_for_height(height, snapshot))
    }

    /// Whether the local validator has consensus authority at `height`.
    pub fn voter_authorized_for_height(
        &self,
        height: u64,
        validator_id: Bytes32,
    ) -> NodeResult<bool> {
        Ok(self
            .voters_for_consensus_height(height)?
            .iter()
            .any(|voter| voter.validator_id == validator_id))
    }

    /// Resolve networking authority for one consensus height.
    ///
    /// Legacy heights preserve the original live-Active membership and key
    /// source. Snapshot-governed heights fail closed on lookup failure, take
    /// membership and keys from `S(height)`, and join only mutable address
    /// metadata from the live registry. A removed snapshot member therefore
    /// remains authenticated but has no on-chain discovery address.
    pub fn network_authority_for_height(
        &self,
        height: u64,
    ) -> NodeResult<Vec<NetworkAuthorityMember>> {
        let snapshot = self.state.snapshot_for_consensus_height(height)?;
        Ok(snapshot
            .entries()
            .iter()
            .map(|entry| NetworkAuthorityMember {
                validator_id: entry.validator_id,
                hybrid_classical_pk: Some(entry.classical_vote_pk),
                hybrid_pq_pk: Some(entry.pq_vote_pk.to_vec()),
                vrf_pk: Some(entry.vrf_pk),
                network_addr: self
                    .state
                    .validators
                    .get(&entry.validator_id)
                    .and_then(|validator| validator.network_addr.clone()),
            })
            .collect())
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

    /// Build canonical QC signer metadata from the snapshot governing `height`.
    pub fn qc_validators_for_height(height: u64, snapshot: &ConsensusSnapshot) -> Vec<QcValidator> {
        debug_assert!(snapshot.activation_height <= height);
        snapshot
            .entries()
            .iter()
            .enumerate()
            .map(|(position, entry)| QcValidator {
                validator_id: entry.validator_id,
                position,
                pq_pk: entry.pq_vote_pk.to_vec(),
                classical_pk: entry.classical_vote_pk,
                stake: entry.consensus_weight_spark,
            })
            .collect()
    }

    /// Resolve validators and total weight for the height being certified.
    ///
    /// Pre-gate behavior deliberately remains the original live-state adapter.
    pub fn qc_authority_for_height(&self, height: u64) -> NodeResult<(Vec<QcValidator>, u64)> {
        let snapshot = self.state.snapshot_for_consensus_height(height)?;
        Ok((
            Self::qc_validators_for_height(height, snapshot),
            snapshot.total_weight_spark,
        ))
    }

    /// Verify a QC against the authority frozen for its own certified height.
    pub fn verify_qc_for_height(
        &self,
        qc: &indra_core::types::qc::QuorumCertificateV1,
    ) -> NodeResult<()> {
        let (validators, total_weight) = self.qc_authority_for_height(qc.height)?;
        verify_qc(qc, &validators, total_weight, &self.state.chain_id).map_err(NodeError::Consensus)
    }

    /// Strictly verify a QC using one already-resolved immutable snapshot.
    pub(crate) fn verify_qc_with_snapshot(
        qc: &indra_core::types::qc::QuorumCertificateV1,
        snapshot: &ConsensusSnapshot,
        chain_id: &str,
    ) -> NodeResult<()> {
        let validators = Self::qc_validators_for_height(qc.height, snapshot);
        verify_qc_strict(qc, &validators, snapshot.total_weight_spark, chain_id)
            .map_err(NodeError::Consensus)
    }

    /// Sign a consensus vote with this node's validator keypair.
    pub fn sign_vote(
        &self,
        height: u64,
        round: u32,
        step: VoteStep,
        block_hash: Bytes32,
    ) -> NodeResult<indra_core::types::vote::VoteV1> {
        self.sign_vote_with_election_result(height, round, step, block_hash, None)
    }

    /// Sign a local vote with an optional commit-reveal election result hash.
    pub fn sign_vote_with_election_result(
        &self,
        height: u64,
        round: u32,
        step: VoteStep,
        block_hash: Bytes32,
        election_result_hash: Option<Bytes32>,
    ) -> NodeResult<indra_core::types::vote::VoteV1> {
        let validator_id = self.validator_id.ok_or(NodeError::NotValidator)?;
        let hybrid_keypair = self
            .hybrid_keypair
            .as_ref()
            .ok_or(NodeError::NotValidator)?;
        produce_vote_with_election_result(
            height,
            round,
            step,
            block_hash,
            validator_id,
            election_result_hash,
            &self.state.chain_id,
            hybrid_keypair,
        )
        .map_err(NodeError::Consensus)
    }

    /// Local validator hybrid keypair, if this node is a validator.
    pub(crate) fn local_hybrid_keypair(&self) -> Option<&HybridKeypair> {
        self.hybrid_keypair.as_ref()
    }

    /// Local validator VRF keypair, if this node is a validator.
    pub(crate) fn local_vrf_keypair(&self) -> Option<&VrfKeypair> {
        self.vrf_keypair.as_ref()
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
        self.write_chain_manifest()?;
        self.evict_committed_staking_ops(&block.staking_ops);
        self.evict_committed_governance_ops(&block.governance_ops);
        self.evict_committed_slashes(&block.slashing_evidence);
        Ok(())
    }

    /// Persist a durable manifest for the currently committed state.
    pub fn write_chain_manifest(&mut self) -> NodeResult<()> {
        let last_qc_height = load_last_qc(&self.config.state_dir())
            .ok()
            .flatten()
            .and_then(|bytes| {
                let mut reader = ByteReader::new(&bytes);
                indra_core::types::qc::QuorumCertificateV1::decode(&mut reader)
                    .ok()
                    .map(|qc| qc.height)
            })
            .unwrap_or(0);
        let manifest = ChainManifest {
            committed_height: self.state.height,
            committed_block_hash: self.state.tip_hash,
            state_root: indra_state::compute_state_root(&self.state),
            snapshot_height: self.state_store.latest_snapshot_height()?.unwrap_or(0),
            block_log_next_height: self.block_store.next_height(),
            last_qc_height,
            epoch_log_latest_epoch: self.epoch_store.latest_epoch(),
            chain_id: self.state.chain_id.clone(),
        };
        save_chain_manifest(&self.config.data_dir, &manifest)?;
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
        let projection =
            project_and_verify_block_state_root(&block, state, 0).map_err(|err| {
                NodeError::StartupReplayFailed {
                    height: block.header.height,
                    reason: format!(
                        "stored block failed header commitment verification during startup replay: {err}"
                    ),
                }
            })?;
        *state = projection.state;
    }

    Ok(())
}

fn verify_snapshot_tip_against_retained_block(
    snapshot: &ChainState,
    block_store: &mut BlockStore,
) -> NodeResult<()> {
    if snapshot.height == 0 || block_store.is_empty() {
        return Ok(());
    }
    if snapshot.height < block_store.lowest_height() {
        return Ok(());
    }
    if snapshot.height >= block_store.next_height() {
        return Err(NodeError::SnapshotBlockMismatch {
            height: snapshot.height,
            reason: format!(
                "snapshot is ahead of retained block log tip (next_height={})",
                block_store.next_height()
            ),
        });
    }
    let block = block_store.get(snapshot.height)?;
    let block_hash = block.header.block_hash();
    if block_hash != snapshot.tip_hash {
        return Err(NodeError::SnapshotBlockMismatch {
            height: snapshot.height,
            reason: format!(
                "snapshot tip {} does not match retained block {}",
                hex::encode(snapshot.tip_hash.0),
                hex::encode(block_hash.0)
            ),
        });
    }
    Ok(())
}

fn validate_manifest_if_present(
    config: &NodeConfig,
    state: &ChainState,
    block_store: &mut BlockStore,
    epoch_store: &EpochStore,
) -> NodeResult<()> {
    let Some(manifest) = load_chain_manifest(&config.data_dir)? else {
        return Ok(());
    };
    if manifest.chain_id != state.chain_id {
        return Err(indra_storage::StorageError::ManifestMismatch {
            detail: format!(
                "manifest chain_id {} does not match state {}",
                manifest.chain_id, state.chain_id
            ),
        }
        .into());
    }
    if block_store.next_height() < manifest.block_log_next_height {
        return Err(indra_storage::StorageError::ManifestMismatch {
            detail: format!(
                "block log next_height {} is behind manifest {}",
                block_store.next_height(),
                manifest.block_log_next_height
            ),
        }
        .into());
    }
    if state.height < manifest.committed_height {
        return Err(indra_storage::StorageError::ManifestMismatch {
            detail: format!(
                "state height {} is behind manifest committed height {}",
                state.height, manifest.committed_height
            ),
        }
        .into());
    }
    if state.height == manifest.committed_height {
        if state.tip_hash != manifest.committed_block_hash {
            return Err(indra_storage::StorageError::ManifestMismatch {
                detail: "state tip hash does not match manifest".into(),
            }
            .into());
        }
        let state_root = indra_state::compute_state_root(state);
        if state_root != manifest.state_root {
            return Err(indra_storage::StorageError::ManifestMismatch {
                detail: "state root does not match manifest".into(),
            }
            .into());
        }
    }
    if let Some(epoch) = manifest.epoch_log_latest_epoch {
        if !epoch_store.has(epoch) {
            return Err(indra_storage::StorageError::ManifestMismatch {
                detail: format!("epoch log missing manifest epoch {epoch}"),
            }
            .into());
        }
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
    use indra_core::types::governance::{
        governance_signing_domain, ColdGovernanceAuthorization, GovernableAction,
        GovernanceActionType, GovernanceOpV2, GovernancePayload,
    };
    use indra_core::types::primitives::{
        DEFAULT_CHAIN_ID, DEFAULT_COMMISSION_BPS, DUST_LIMIT_SPARK,
    };
    use indra_core::types::slashing::SlashEvidenceV1;
    use indra_core::types::staking::StakingOpBody;
    use indra_core::types::transaction::OutputV1;
    use indra_core::types::vote::{VoteStep, VoteV1};
    use indra_core::CommitmentV1;
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
        if engine.state.height == 0
            && engine
                .state
                .validators
                .all_validators()
                .any(|validator| validator.name == "local-test-validator")
        {
            engine.state.validators = Default::default();
            engine.state.consensus_snapshots.clear();
            engine.state.reward_economic_snapshot = None;
            engine.state.slash_membership_roots.clear();
        }
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
                pending_commission_bps: None,
                pending_commission_effective_epoch: None,
                min_delegation_spark: DUST_LIMIT_SPARK,
                auto_delegate_to: None,
                network_addr: None,
                network_addr_last_updated_epoch: None,
                cold_hybrid_classical_pk: Some(cold_public.classical.0),
                cold_hybrid_pq_pk: Some(cold_public.pq.0),
                cold_key_version: 1,
                cold_nonce: 0,
            })
            .unwrap();
        if engine.state.height == 0 {
            crate::genesis::finalize_test_genesis(&mut engine.state);
        }
        hybrid
    }

    fn assert_same_voters(left: &[RegisteredVoter], right: &[RegisteredVoter]) {
        assert_eq!(left.len(), right.len());
        for (left, right) in left.iter().zip(right) {
            assert_eq!(left.validator_id, right.validator_id);
            assert_eq!(left.classical_pk, right.classical_pk);
            assert_eq!(left.pq_pk, right.pq_pk);
            assert_eq!(left.stake, right.stake);
        }
    }

    fn write_single_validator_genesis(dir: &std::path::Path, seed: [u8; 32]) -> String {
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
        let validator_id = indra_crypto::sha256(&classical.public_key().0);
        let genesis_path = dir.join("genesis.toml");
        let mut genesis = format!(
            "[genesis]\nchain_id = \"indra-testnet-1\"\n\n[[validators]]\nname = \"local\"\nvalidator_id = \"{}\"\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\ncold_hybrid_classical_pk = \"{}\"\ncold_hybrid_pq_pk = \"{}\"\ncold_key_version = 1\ncold_nonce = 0\nstake = 1000000\n",
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
                deposit_utxo_id: Bytes32::from([0xBB; 32]),
                delegator_pubkey: HybridPubKey {
                    classical_pk: Bytes32::from([seed; 32]),
                    pq_pk: VariableBytes::from_slice(&[seed; 2592]).unwrap(),
                },
                deposit_proof: None,
            },
            nonce,
            signature: dummy_signature(),
        }
    }

    fn sign_staking_op(op: &mut StakingOp, keypair: &HybridKeypair, chain_id: &str) {
        let sig = keypair.sign(&op.signing_bytes(chain_id)).unwrap();
        op.signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
        };
    }

    fn cold_keypair_for_seed(seed: [u8; 32]) -> HybridKeypair {
        HybridKeypair::new(
            ClassicalKeypair::from_seed(&[seed[0] ^ 0xA5; 32]),
            PqKeypair::from_seed(&[seed[0] ^ 0x5A; 32]).unwrap(),
        )
    }

    fn sign_cold_staking_op(op: &mut StakingOp, keypair: &HybridKeypair, chain_id: &str) {
        let bytes = op
            .cold_authorization_signing_bytes(chain_id)
            .unwrap()
            .unwrap();
        let sig = keypair.sign(&bytes).unwrap();
        op.signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
        };
    }

    fn valid_set_commission_staking_op(
        engine: &NodeEngine,
        keypair: &HybridKeypair,
        cold_keypair: &HybridKeypair,
        nonce: u64,
        new_commission_bps: u32,
    ) -> StakingOp {
        let validator_id = Bytes32::from(indra_crypto::sha256(&keypair.public_key().classical.0));
        let mut op = StakingOp {
            body: StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps,
                cold_authorization: Some(indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 1,
                    cold_nonce: nonce,
                }),
            },
            nonce: 0,
            signature: dummy_signature(),
        };
        sign_cold_staking_op(&mut op, cold_keypair, &engine.state.chain_id);
        op
    }

    fn governance_pubkey_from_keypair(keypair: &HybridKeypair) -> HybridPubKey {
        let public = keypair.public_key();
        HybridPubKey {
            classical_pk: Bytes32::from(public.classical.0),
            pq_pk: VariableBytes::from_slice(&public.pq.0).unwrap(),
        }
    }

    fn sign_governance_op(op: &mut GovernanceOpV2, keypair: &HybridKeypair) {
        let domain = governance_signing_domain(
            op.action_type,
            op.signer_id,
            op.nonce,
            &op.payload,
            DEFAULT_CHAIN_ID,
        );
        let msg_hash = indra_crypto::sha256(&domain);
        let sig = keypair.sign(&msg_hash).unwrap();
        op.signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
        };
    }

    fn sign_cold_governance_op(op: &mut GovernanceOpV2, keypair: &HybridKeypair) {
        let bytes = op
            .cold_authorization_signing_bytes(DEFAULT_CHAIN_ID)
            .unwrap()
            .unwrap();
        let sig = keypair.sign(&bytes).unwrap();
        op.signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
        };
    }

    fn governance_deposit_output(owner_pubkey: HybridPubKey, value_spark: u64) -> OutputV1 {
        OutputV1 {
            value_spark,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::ZERO,
            },
            owner_pubkey,
            range_proof: VariableBytes::from_slice(&[]).unwrap(),
            lock_height: 0,
        }
    }

    fn valid_governance_propose_op(
        engine: &mut NodeEngine,
        keypair: &HybridKeypair,
        nonce: u64,
    ) -> GovernanceOpV2 {
        let proposer_pubkey = governance_pubkey_from_keypair(keypair);
        let signer_id = Bytes32::from(indra_crypto::sha256(&keypair.public_key().classical.0));
        let deposit_utxo_id = engine
            .state
            .utxos
            .insert(
                governance_deposit_output(
                    proposer_pubkey.clone(),
                    engine.state.governance.params.proposal_deposit_spark,
                ),
                0,
                nonce as u32,
                0,
            )
            .unwrap();
        let payload = GovernancePayload::Propose {
            action: GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK,
            },
            deposit_utxo_id,
            proposer_pubkey,
            title: VariableBytes::from_slice(b"test").unwrap(),
            description: VariableBytes::from_slice(b"test").unwrap(),
            cold_authorization: None,
        };
        let mut op = GovernanceOpV2 {
            action_type: GovernanceActionType::ProposeChange,
            signer_id,
            nonce,
            payload,
            signature: dummy_signature(),
        };
        sign_governance_op(&mut op, keypair);
        op
    }

    fn valid_cold_governance_propose_op(
        engine: &mut NodeEngine,
        hot_keypair: &HybridKeypair,
        cold_keypair: &HybridKeypair,
        cold_nonce: u64,
    ) -> GovernanceOpV2 {
        let signer_id = Bytes32::from(indra_crypto::sha256(&hot_keypair.public_key().classical.0));
        let cold_public = cold_keypair.public_key();
        let cold_pubkey = HybridPubKey {
            classical_pk: Bytes32::from(cold_public.classical.0),
            pq_pk: VariableBytes::from_slice(&cold_public.pq.0).unwrap(),
        };
        let validator = engine.state.validators.get_mut(&signer_id).unwrap();
        validator.cold_hybrid_classical_pk = Some(cold_public.classical.0);
        validator.cold_hybrid_pq_pk = Some(cold_public.pq.0);
        validator.cold_key_version = 1;
        let deposit_utxo_id = engine
            .state
            .utxos
            .insert(
                governance_deposit_output(
                    cold_pubkey.clone(),
                    engine.state.governance.params.proposal_deposit_spark,
                ),
                0,
                cold_nonce as u32,
                0,
            )
            .unwrap();
        let mut op = GovernanceOpV2 {
            action_type: GovernanceActionType::ProposeChange,
            signer_id,
            nonce: 0,
            payload: GovernancePayload::Propose {
                action: GovernableAction::SetMinDelegationSpark {
                    value: DUST_LIMIT_SPARK,
                },
                deposit_utxo_id,
                proposer_pubkey: cold_pubkey,
                title: VariableBytes::from_slice(b"cold test").unwrap(),
                description: VariableBytes::from_slice(b"cold test").unwrap(),
                cold_authorization: Some(ColdGovernanceAuthorization {
                    cold_key_version: 1,
                    cold_nonce,
                }),
            },
            signature: dummy_signature(),
        };
        sign_cold_governance_op(&mut op, cold_keypair);
        op
    }

    fn dummy_slash_evidence(seed: u8) -> SlashEvidenceV1 {
        let validator_id = Bytes32::from([seed; 32]);
        let vote = |block_byte| VoteV1 {
            height: 7,
            round: 0,
            step: VoteStep::Precommit,
            block_hash: Bytes32::from([block_byte; 32]),
            validator_id,
            election_result_hash: None,
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
        let preferred = VrfKeypair::from_seed(&proposer_seed);
        let mut keypairs = std::collections::BTreeMap::new();
        let mut revealed = std::collections::BTreeMap::new();
        let mut vrf_reveals = Vec::new();
        for candidate in &election.candidates {
            let keypair = if preferred.public_key() == candidate.vrf_pubkey {
                preferred.clone()
            } else {
                (0u8..=u8::MAX)
                    .map(|seed| VrfKeypair::from_seed(&[seed; 32]))
                    .find(|keypair| keypair.public_key() == candidate.vrf_pubkey)
                    .expect("test validator VRF seed must be recoverable")
            };
            let slot = compute_proposer_vrf(
                candidate.validator_id,
                &keypair,
                &election.epoch_seed,
                election.height,
                election.round,
            );
            let output = Bytes32::from(slot.vrf_output.0);
            revealed.insert(candidate.validator_id, output);
            vrf_reveals.push(VrfRevealEvidence {
                validator_id: candidate.validator_id,
                vrf_output: output,
                vrf_proof: VariableBytes::from_slice(&slot.vrf_proof.0).unwrap(),
            });
            keypairs.insert(candidate.validator_id, keypair);
        }
        let mut election_result =
            indra_consensus::proposer::elect_proposer_from_reveals(&election, &revealed).unwrap();
        election_result.reveal_set_commitment = compute_reveal_set_commitment(&vrf_reveals);
        let proposer_vrf = keypairs
            .remove(&election_result.elected_validator_id)
            .unwrap();
        let election_result_hash = election_result.hash();
        let template = BlockTemplate {
            proposer_vrf_keypair: proposer_vrf,
            epoch_seed: election.epoch_seed,
            prev_qc_bytes,
            timestamp: 1_700_000_000 + state.height + 1,
            polc_round: None,
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            election_result_hash: Some(election_result_hash),
            election_result: Some(election_result),
            vrf_reveals,
        };
        let mut projection_state = state.clone();
        produce_block(
            &template,
            &mut projection_state,
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
            &DEFAULT_CHAIN_ID,
            &hybrid,
        )
        .unwrap();
        let qc = build_qc(
            height,
            round,
            value_hash,
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
    fn post_gate_voters_use_snapshot_weight_not_mutated_live_stake() {
        let dir = temp_dir("snapshot_voter_weight");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        install_active_validator(&mut engine, [0x42; 32], "snapshot-voter");
        let snapshot = engine.state.build_genesis_consensus_snapshot().unwrap();
        let validator_id = snapshot.entries()[0].validator_id;
        let frozen_weight = snapshot.entries()[0].consensus_weight_spark;

        engine
            .state
            .validators
            .get_mut(&validator_id)
            .unwrap()
            .stake_spark = frozen_weight + 777;

        let voters = NodeEngine::registered_voters_for_height(1, &snapshot);
        assert_eq!(voters[0].stake, frozen_weight);
        assert_eq!(
            engine
                .registered_voters()
                .into_iter()
                .find(|voter| voter.validator_id == validator_id)
                .unwrap()
                .stake,
            frozen_weight + 777
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pre_gate_voter_adapter_is_unchanged_live_registry_path() {
        let dir = temp_dir("legacy_voter_adapter");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        install_active_validator(&mut engine, [0x43; 32], "legacy-voter");

        assert_same_voters(
            &engine.voters_for_consensus_height(1).unwrap(),
            &engine.registered_voters(),
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_height_round_adapters_remain_identical_after_live_mutation() {
        let dir = temp_dir("same_height_snapshot_voters");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        install_active_validator(&mut engine, [0x44; 32], "round-voter");
        let snapshot = engine.state.build_genesis_consensus_snapshot().unwrap();
        let round_zero_voters = NodeEngine::registered_voters_for_height(1, &snapshot);

        let validator_id = snapshot.entries()[0].validator_id;
        engine
            .state
            .validators
            .get_mut(&validator_id)
            .unwrap()
            .stake_spark += 999;
        let round_one_voters = NodeEngine::registered_voters_for_height(1, &snapshot);

        assert_same_voters(&round_zero_voters, &round_one_voters);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_boundary_vote_adapters_replay_deterministically() {
        let dir = temp_dir("snapshot_voter_boundary_replay");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let signer = install_active_validator(&mut engine, [0x45; 32], "replay-voter");
        let old_snapshot = engine.state.build_genesis_consensus_snapshot().unwrap();
        let validator_id = old_snapshot.entries()[0].validator_id;
        engine
            .state
            .validators
            .get_mut(&validator_id)
            .unwrap()
            .stake_spark += 300;
        let new_snapshot = engine.state.build_consensus_snapshot(301, 300).unwrap();
        assert_ne!(
            old_snapshot.entries()[0].consensus_weight_spark,
            new_snapshot.entries()[0].consensus_weight_spark
        );

        let replay = || {
            [300u64, 301]
                .into_iter()
                .map(|height| {
                    let snapshot = if height == 300 {
                        &old_snapshot
                    } else {
                        &new_snapshot
                    };
                    let voters = NodeEngine::registered_voters_for_height(height, snapshot);
                    let vote = produce_vote(
                        height,
                        0,
                        VoteStep::Prevote,
                        Bytes32::from([height as u8; 32]),
                        validator_id,
                        DEFAULT_CHAIN_ID,
                        &signer,
                    )
                    .unwrap();
                    let mut collector = indra_consensus::vote::VoteCollector::new(
                        height,
                        0,
                        VoteStep::Prevote,
                        DEFAULT_CHAIN_ID.to_string(),
                        voters,
                    );
                    collector.add_vote(vote).unwrap()
                })
                .collect::<Vec<_>>()
        };
        let first = replay();
        let second = replay();
        assert_eq!(first, second);
        assert!(first.iter().all(|decision| matches!(
            decision,
            indra_consensus::vote::VoteDecision::QuorumReached { .. }
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn qc_from_test_signers(
        height: u64,
        block_hash: Bytes32,
        snapshot: &ConsensusSnapshot,
        signers: &[&HybridKeypair],
    ) -> indra_core::types::qc::QuorumCertificateV1 {
        let validators = NodeEngine::qc_validators_for_height(height, snapshot);
        let votes: Vec<_> = signers
            .iter()
            .map(|signer| {
                let validator_id =
                    Bytes32::from(indra_crypto::sha256(&signer.public_key().classical.0));
                produce_vote(
                    height,
                    0,
                    VoteStep::Precommit,
                    block_hash,
                    validator_id,
                    DEFAULT_CHAIN_ID,
                    signer,
                )
                .unwrap()
            })
            .collect();
        build_qc(
            height,
            0,
            block_hash,
            DEFAULT_CHAIN_ID,
            &validators,
            votes.iter().collect(),
        )
        .unwrap()
    }

    #[test]
    fn genuine_pre_stake_change_qc_remains_verifiable_under_certified_height_snapshot() {
        let dir = temp_dir("qc_liveness_attack_reproduction");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let a = install_active_validator(&mut engine, [0x51; 32], "a");
        let b = install_active_validator(&mut engine, [0x52; 32], "b");
        let c = install_active_validator(&mut engine, [0x53; 32], "c");
        let a_id = Bytes32::from(indra_crypto::sha256(&a.public_key().classical.0));
        let b_id = Bytes32::from(indra_crypto::sha256(&b.public_key().classical.0));
        let c_id = Bytes32::from(indra_crypto::sha256(&c.public_key().classical.0));
        engine.state.validators.get_mut(&a_id).unwrap().stake_spark = 40;
        engine.state.validators.get_mut(&b_id).unwrap().stake_spark = 30;
        engine.state.validators.get_mut(&c_id).unwrap().stake_spark = 30;
        let snapshot = engine.state.build_genesis_consensus_snapshot().unwrap();
        let block_hash = Bytes32::from([0xA1; 32]);
        let qc = qc_from_test_signers(1, block_hash, &snapshot, &[&a, &b]);

        // Block H commits C's SelfStake after A+B formed the genuine QC for H.
        engine.state.validators.get_mut(&c_id).unwrap().stake_spark = 140;
        assert!(verify_qc_strict(
            &qc,
            &engine.qc_validators(),
            engine.state.validators.total_active_stake(),
            DEFAULT_CHAIN_ID,
        )
        .is_err());
        assert!(NodeEngine::verify_qc_with_snapshot(&qc, &snapshot, DEFAULT_CHAIN_ID).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn post_block_inflation_cannot_turn_single_signer_into_snapshot_quorum() {
        let dir = temp_dir("qc_safety_attack_reproduction");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let a = install_active_validator(&mut engine, [0x61; 32], "a");
        let b = install_active_validator(&mut engine, [0x62; 32], "b");
        let c = install_active_validator(&mut engine, [0x63; 32], "c");
        let a_id = Bytes32::from(indra_crypto::sha256(&a.public_key().classical.0));
        let b_id = Bytes32::from(indra_crypto::sha256(&b.public_key().classical.0));
        let c_id = Bytes32::from(indra_crypto::sha256(&c.public_key().classical.0));
        engine.state.validators.get_mut(&a_id).unwrap().stake_spark = 20;
        engine.state.validators.get_mut(&b_id).unwrap().stake_spark = 40;
        engine.state.validators.get_mut(&c_id).unwrap().stake_spark = 40;
        let snapshot = engine.state.build_genesis_consensus_snapshot().unwrap();
        let qc = qc_from_test_signers(1, Bytes32::from([0xA2; 32]), &snapshot, &[&a]);

        engine.state.validators.get_mut(&a_id).unwrap().stake_spark = 200;
        assert!(verify_qc_strict(
            &qc,
            &engine.qc_validators(),
            engine.state.validators.total_active_stake(),
            DEFAULT_CHAIN_ID,
        )
        .is_ok());
        assert!(NodeEngine::verify_qc_with_snapshot(&qc, &snapshot, DEFAULT_CHAIN_ID).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vote_collection_qc_construction_and_verification_share_one_snapshot() {
        let dir = temp_dir("qc_vote_snapshot_consistency");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let signer = install_active_validator(&mut engine, [0x71; 32], "a");
        let snapshot = engine.state.build_genesis_consensus_snapshot().unwrap();
        let voters = NodeEngine::registered_voters_for_height(1, &snapshot);
        let validators = NodeEngine::qc_validators_for_height(1, &snapshot);

        assert_eq!(voters.len(), validators.len());
        for (voter, validator) in voters.iter().zip(&validators) {
            assert_eq!(voter.validator_id, validator.validator_id);
            assert_eq!(voter.classical_pk, validator.classical_pk);
            assert_eq!(voter.pq_pk, validator.pq_pk);
            assert_eq!(voter.stake, validator.stake);
        }
        assert_eq!(
            voters.iter().map(|voter| voter.stake).sum::<u64>(),
            snapshot.total_weight_spark
        );
        let qc = qc_from_test_signers(1, Bytes32::from([0xA3; 32]), &snapshot, &[&signer]);
        assert!(NodeEngine::verify_qc_with_snapshot(&qc, &snapshot, DEFAULT_CHAIN_ID).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pre_gate_qc_authority_is_unchanged_live_registry_adapter() {
        let dir = temp_dir("legacy_qc_authority");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        install_active_validator(&mut engine, [0x72; 32], "legacy");
        let (actual, total) = engine.qc_authority_for_height(1).unwrap();
        let expected = engine.qc_validators();
        assert_eq!(actual.len(), expected.len());
        for (actual, expected) in actual.iter().zip(&expected) {
            assert_eq!(actual.validator_id, expected.validator_id);
            assert_eq!(actual.position, expected.position);
            assert_eq!(actual.pq_pk, expected.pq_pk);
            assert_eq!(actual.classical_pk, expected.classical_pk);
            assert_eq!(actual.stake, expected.stake);
        }
        assert_eq!(total, engine.state.validators.total_active_stake());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn governed_qc_verification_fails_closed_without_snapshot() {
        let dir = temp_dir("missing_qc_snapshot");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let signer = install_active_validator(&mut engine, [0x73; 32], "missing");
        let snapshot = engine.state.build_genesis_consensus_snapshot().unwrap();
        let qc = qc_from_test_signers(u64::MAX, Bytes32::from([0xA4; 32]), &snapshot, &[&signer]);
        engine.state.consensus_snapshots.clear();
        assert!(matches!(
            engine.verify_qc_for_height(&qc),
            Err(NodeError::ConsensusSnapshotLookup(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn qc_formation_and_verification_replay_across_snapshot_boundary() {
        let dir = temp_dir("qc_snapshot_boundary_replay");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let signer = install_active_validator(&mut engine, [0x74; 32], "boundary");
        let old_snapshot = engine.state.build_genesis_consensus_snapshot().unwrap();
        let id = old_snapshot.entries()[0].validator_id;
        engine.state.validators.get_mut(&id).unwrap().stake_spark += 500;
        let new_snapshot = engine.state.build_consensus_snapshot(301, 300).unwrap();

        let replay = || {
            let qc300 =
                qc_from_test_signers(300, Bytes32::from([0x30; 32]), &old_snapshot, &[&signer]);
            let qc301 =
                qc_from_test_signers(301, Bytes32::from([0x31; 32]), &new_snapshot, &[&signer]);
            NodeEngine::verify_qc_with_snapshot(&qc300, &old_snapshot, DEFAULT_CHAIN_ID).unwrap();
            NodeEngine::verify_qc_with_snapshot(&qc301, &new_snapshot, DEFAULT_CHAIN_ID).unwrap();
            (qc300.encode_to_vec(), qc301.encode_to_vec())
        };
        assert_eq!(replay(), replay());
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

    #[cfg(any())]
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
            .insert(compute_pending_slash_evidence_hash(&evidence));
        engine.add_slash_evidence(evidence);
        assert!(engine.pending_slashes.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_node_has_no_validator_id() {
        let dir = temp_dir("b");
        let mut config = NodeConfig::local_test(dir.clone());
        config.validator_seed = None;
        config.vrf_seed = None;
        config.pq_pk = None;
        config.pq_sk = None;
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
        let manifest = indra_storage::load_chain_manifest(&dir)
            .unwrap()
            .expect("commit should write manifest");
        assert_eq!(manifest.committed_height, 1);
        assert_eq!(manifest.committed_block_hash, engine.state.tip_hash);
        assert_eq!(
            manifest.state_root,
            indra_state::compute_state_root(&engine.state)
        );
        assert_eq!(
            manifest.block_log_next_height,
            engine.block_store.next_height()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_rebuilds_state_from_block_log() {
        let dir = temp_dir("d");
        let mut config = NodeConfig::local_test(dir.clone());
        config.genesis_path = Some(write_single_validator_genesis(&dir, [0x42u8; 32]));
        let mut engine = NodeEngine::init(config.clone()).unwrap();
        let mut last_qc = Vec::new();

        for height in 1..=3u64 {
            let block = make_strict_block(&engine.state, [0x42u8; 32], last_qc.clone());
            engine.commit_block(&block).unwrap();
            last_qc =
                build_single_validator_qc_bytes(height, 0, block.header.block_hash(), [0x42u8; 32]);
            assert_eq!(engine.state.height, height);
        }

        let restarted = NodeEngine::init(config).unwrap();
        assert_eq!(restarted.state.height, 3);
        assert_eq!(restarted.state.tip_hash, engine.state.tip_hash);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_replay_detects_corrupt_block_via_state_root_mismatch() {
        let dir = temp_dir("replay_bad_root");
        let mut config = NodeConfig::local_test(dir.clone());
        config.genesis_path = Some(write_single_validator_genesis(&dir, [0x42u8; 32]));
        {
            let mut engine = NodeEngine::init(config.clone()).unwrap();
            let mut block = make_strict_block(&engine.state, [0x42u8; 32], vec![]);
            block.header.state_root = Bytes32::from([0xEE; 32]);
            engine.block_store.append(&build_genesis_block()).unwrap();
            engine.block_store.append(&block).unwrap();
        }

        match NodeEngine::init(config) {
            Err(NodeError::StartupReplayFailed { height: 1, reason }) => {
                assert!(
                    reason.contains("state_root mismatch"),
                    "startup replay must preserve projected root-mismatch reason, got: {reason}"
                );
            }
            Ok(_) => panic!("startup replay unexpectedly accepted a corrupt stored block"),
            Err(other) => panic!("unexpected startup replay error: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_detects_block_log_behind_manifest() {
        let dir = temp_dir("manifest_block_log_behind");
        let config = NodeConfig::local_test(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        indra_storage::save_chain_manifest(
            &dir,
            &ChainManifest {
                committed_height: 99,
                committed_block_hash: Bytes32::from([0xAA; 32]),
                state_root: Bytes32::from([0xBB; 32]),
                snapshot_height: 0,
                block_log_next_height: 100,
                last_qc_height: 99,
                epoch_log_latest_epoch: None,
                chain_id: indra_core::types::primitives::DEFAULT_CHAIN_ID.into(),
            },
        )
        .unwrap();

        assert!(matches!(
            NodeEngine::init(config),
            Err(NodeError::Storage(
                indra_storage::StorageError::ManifestMismatch { .. }
            ))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_tip_hash_mismatch_with_retained_block_fails_startup() {
        let dir = temp_dir("snapshot_retained_block_mismatch");
        let mut config = NodeConfig::local_test(dir.clone());
        config.genesis_path = Some(write_single_validator_genesis(&dir, [0x42u8; 32]));
        {
            let mut engine = NodeEngine::init(config.clone()).unwrap();
            let block = make_strict_block(&engine.state, [0x42u8; 32], vec![]);
            engine.commit_block(&block).unwrap();
            let mut bad_snapshot = engine.state.clone();
            bad_snapshot.tip_hash = Bytes32::from([0xDD; 32]);
            engine.state_store.save(&bad_snapshot).unwrap();
        }

        assert!(matches!(
            NodeEngine::init(config),
            Err(NodeError::SnapshotBlockMismatch { height: 1, .. })
        ));
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
                    block.header.block_hash(),
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
                    block.header.block_hash(),
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
            engine.write_chain_manifest().unwrap();
        }

        let restarted = NodeEngine::init(config).unwrap();
        assert_eq!(restarted.state.chain_id, "indra-custom-testnet");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_fails_on_snapshot_replay_gap() {
        let dir = temp_dir("snapshot_gap");
        let mut config = NodeConfig::local_test(dir.clone());
        config.snapshot_interval = 30;
        config.prune_keep_blocks = Some(100);

        let extra_block = {
            let mut engine = NodeEngine::init(config.clone()).unwrap();
            install_active_validator(&mut engine, [0x42u8; 32], "local");
            let mut last_qc = Vec::new();
            for _ in 0..160u64 {
                let height = engine.state.height + 1;
                let block = make_strict_block(&engine.state, [0x42u8; 32], last_qc.clone());
                engine.commit_block(&block).unwrap();
                last_qc = build_single_validator_qc_bytes(
                    height,
                    0,
                    block.header.block_hash(),
                    [0x42u8; 32],
                );
            }
            make_strict_block(&engine.state, [0x42u8; 32], last_qc)
        };

        {
            let mut store = BlockStore::open(
                dir.join("blocks.log"),
                indra_storage::PruneConfig {
                    keep_blocks: Some(100),
                },
            )
            .unwrap();
            store.append(&extra_block).unwrap();
            assert_eq!(store.lowest_height(), 62);
        }

        let state_dir = dir.join("state");
        for entry in std::fs::read_dir(&state_dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("snap") {
                std::fs::remove_file(path).unwrap();
            }
        }

        let state_store = StateStore::open(&state_dir).unwrap();
        let mut snapshot = crate::genesis::canonical_test_genesis();
        snapshot.height = 10;
        snapshot.tip_hash = Bytes32::from([0x55; 32]);
        state_store.save(&snapshot).unwrap();

        match NodeEngine::init(config) {
            Err(NodeError::SnapshotReplayGap {
                snapshot_height,
                lowest_block,
                gap,
            }) => {
                assert_eq!(snapshot_height, 10);
                assert_eq!(lowest_block, 62);
                assert_eq!(gap, 51);
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
        let cold = cold_keypair_for_seed([0x11; 32]);
        let cold_public = cold.public_key();
        let validator_id = indra_crypto::sha256(&classical.public_key().0);
        let genesis_path = dir.join("genesis.toml");
        let mut genesis = format!(
            "[genesis]\nchain_id = \"indra-testnet-1\"\n\n[[validators]]\nname = \"alice\"\nvalidator_id = \"{}\"\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\ncold_hybrid_classical_pk = \"{}\"\ncold_hybrid_pq_pk = \"{}\"\ncold_key_version = 1\ncold_nonce = 0\nstake = 100000000000\n",
            hex::encode(validator_id),
            hex::encode(classical.public_key().0),
            hex::encode(pq.public_key().0),
            hex::encode(vrf.public_key()),
            hex::encode(cold_public.classical.0),
            hex::encode(cold_public.pq.0),
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
            .propose(&election, 1_700_000_003, Vec::new(), None, None, vec![])
            .unwrap_err();
        assert!(matches!(err, NodeError::MissingQc { height: 3 }));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fresh_genesis_height_one_block_production_succeeds() {
        let dir = temp_dir("height1_production");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        install_active_validator(&mut engine, [0x42u8; 32], "local");

        let candidate = engine.state.validators.active_validators().next().unwrap();
        let election = ProposerElection {
            epoch_seed: Bytes32::from(indra_crypto::sha256(&engine.state.tip_hash.0)),
            height: 1,
            round: 0,
            candidates: vec![ProposerCandidate {
                validator_id: candidate.validator_id,
                vrf_pubkey: candidate.vrf_pk.unwrap(),
                verified_vrf_output: None,
                stake: candidate.stake_spark,
            }],
        };

        assert!(
            engine.is_proposer(&election),
            "single local validator should be eligible to produce height 1"
        );
        let slot = compute_proposer_vrf(
            candidate.validator_id,
            &VrfKeypair::from_seed(&[0x42u8; 32]),
            &election.epoch_seed,
            election.height,
            election.round,
        );
        let evidence = vec![VrfRevealEvidence {
            validator_id: candidate.validator_id,
            vrf_output: Bytes32::from(slot.vrf_output.0),
            vrf_proof: VariableBytes::from_slice(&slot.vrf_proof.0).unwrap(),
        }];
        let result = VrfElectionResult {
            height: election.height,
            round: election.round,
            elected_validator_id: candidate.validator_id,
            elected_vrf_output: evidence[0].vrf_output,
            fallback_used: false,
            reveal_set_commitment: compute_reveal_set_commitment(&evidence),
        };
        let block = engine
            .propose(
                &election,
                1_700_000_001,
                Vec::new(),
                None,
                Some(result),
                evidence,
            )
            .unwrap();
        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.prev_hash, engine.state.tip_hash);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_proposer_rejects_registered_vrf_key_mismatch() {
        let dir = temp_dir("height1_vrf_mismatch");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let local_id = {
            install_active_validator(&mut engine, [0x42u8; 32], "local");
            engine.validator_id().unwrap()
        };
        engine.state.validators.get_mut(&local_id).unwrap().vrf_pk =
            Some(VrfKeypair::from_seed(&[0x99u8; 32]).public_key());

        let candidate = engine.state.validators.active_validators().next().unwrap();
        let election = ProposerElection {
            epoch_seed: Bytes32::from(indra_crypto::sha256(&engine.state.tip_hash.0)),
            height: 1,
            round: 0,
            candidates: vec![ProposerCandidate {
                validator_id: candidate.validator_id,
                vrf_pubkey: candidate.vrf_pk.unwrap(),
                verified_vrf_output: None,
                stake: candidate.stake_spark,
            }],
        };

        assert!(
            !engine.is_proposer(&election),
            "a node must not claim proposer eligibility when its local VRF key does not match the registered validator VRF key"
        );
        let err = engine
            .propose(&election, 1_700_000_001, Vec::new(), None, None, vec![])
            .unwrap_err();
        assert!(matches!(
            err,
            NodeError::Consensus(indra_consensus::ConsensusError::WrongProposer { reason })
                if reason == "missing authoritative election result"
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_one_validator_is_proposer_per_height_round_in_4_validator_set() {
        let seeds = [[0x51u8; 32], [0x52u8; 32], [0x53u8; 32], [0x54u8; 32]];
        let mut engines = Vec::new();
        let mut dirs = Vec::new();

        for (idx, seed) in seeds.iter().enumerate() {
            let dir = temp_dir(&format!("unique_proposer_{idx}"));
            let mut config = NodeConfig::local_test(dir.clone());
            config.validator_seed = Some(*seed);
            config.vrf_seed = Some(*seed);
            let mut engine = NodeEngine::init(config).unwrap();
            for validator_seed in seeds {
                install_active_validator(&mut engine, validator_seed, "validator");
            }
            dirs.push(dir);
            engines.push(engine);
        }

        for height in 1..=12u64 {
            for round in 0..8u32 {
                let epoch_seed = Bytes32::from(indra_crypto::sha256(&engines[0].state.tip_hash.0));
                let candidates: Vec<_> = engines[0]
                    .state
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
                let election = ProposerElection {
                    epoch_seed,
                    height,
                    round,
                    candidates,
                };
                let proposer_count = engines
                    .iter()
                    .filter(|engine| engine.is_proposer(&election))
                    .count();
                assert_eq!(
                    proposer_count, 1,
                    "exactly one validator must be proposer at height={height} round={round}"
                );
            }
        }

        for dir in dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn staking_mempool_deduplicates_by_nonce() {
        let dir = temp_dir("staking_mempool_dedup");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let keypair = install_active_validator(&mut engine, [0x71; 32], "stake");
        let cold = cold_keypair_for_seed([0x71; 32]);
        let op = valid_set_commission_staking_op(&engine, &keypair, &cold, 1, 1_100);

        engine.add_staking_op(op.clone()).unwrap();
        assert!(matches!(
            engine.add_staking_op(op),
            Err(NodeError::InvalidStakingOp(_))
        ));
        assert_eq!(engine.staking_mempool.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staking_mempool_rejects_structurally_invalid_staking_op_at_admission() {
        let dir = temp_dir("staking_mempool_invalid");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let op = dummy_staking_op(0x11, 1);

        assert!(matches!(
            engine.add_staking_op(op),
            Err(NodeError::InvalidStakingOp(_))
        ));
        assert!(engine.staking_mempool.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staking_mempool_capacity_is_enforced_at_admission() {
        let dir = temp_dir("staking_mempool_capacity");
        let mut config = NodeConfig::local_test(dir.clone());
        config.staking_mempool_capacity = 0;
        let mut engine = NodeEngine::init(config).unwrap();
        let keypair = install_active_validator(&mut engine, [0x74; 32], "stake-cap");
        let cold = cold_keypair_for_seed([0x74; 32]);
        let op = valid_set_commission_staking_op(&engine, &keypair, &cold, 1, 1_100);

        let err = engine.add_staking_op(op).unwrap_err().to_string();
        assert!(err.contains("staking mempool full"));
        assert!(engine.staking_mempool.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn governance_mempool_rejects_invalid_signature() {
        let dir = temp_dir("governance_bad_sig");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let keypair = install_active_validator(&mut engine, [0x51; 32], "gov");
        let mut op = valid_governance_propose_op(&mut engine, &keypair, 1);
        op.signature = dummy_signature();

        assert!(matches!(
            engine.add_governance_op(op),
            Err(NodeError::InvalidGovernanceOp(_))
        ));
        assert!(engine.governance_mempool.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn governance_mempool_rejects_op_for_nonexistent_proposal() {
        let dir = temp_dir("governance_missing_proposal");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let keypair = install_active_validator(&mut engine, [0x52; 32], "gov");
        let signer_id = Bytes32::from(indra_crypto::sha256(&keypair.public_key().classical.0));
        let mut op = GovernanceOpV2 {
            action_type: GovernanceActionType::CommitVote,
            signer_id,
            nonce: 1,
            payload: GovernancePayload::Commit {
                proposal_id: Bytes32::from([0x99; 32]),
                commit_hash: Bytes32::from([0x44; 32]),
                cold_authorization: None,
            },
            signature: dummy_signature(),
        };
        sign_governance_op(&mut op, &keypair);

        assert!(matches!(
            engine.add_governance_op(op),
            Err(NodeError::InvalidGovernanceOp(_))
        ));
        assert!(engine.governance_mempool.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn governance_mempool_accepts_valid_op() {
        let dir = temp_dir("governance_valid");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let keypair = install_active_validator(&mut engine, [0x53; 32], "gov");
        let cold = cold_keypair_for_seed([0x53; 32]);
        let op = valid_cold_governance_propose_op(&mut engine, &keypair, &cold, 1);

        engine.add_governance_op(op.clone()).unwrap();

        assert_eq!(engine.governance_mempool, vec![op]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn governance_mempool_deduplicates_and_evicts_by_cold_role_nonce() {
        let dir = temp_dir("governance_cold_role_nonce");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        engine.state.height = u64::MAX;
        let hot = install_active_validator(&mut engine, [0x73; 32], "cold-gov");
        let cold = cold_keypair_for_seed([0x73; 32]);
        let op1 = valid_cold_governance_propose_op(&mut engine, &hot, &cold, 1);

        engine.add_governance_op(op1.clone()).unwrap();
        assert!(matches!(
            engine.add_governance_op(op1.clone()),
            Err(NodeError::InvalidGovernanceOp(reason))
                if reason.contains("duplicate governance op nonce")
        ));

        let mut op2 = op1.clone();
        if let GovernancePayload::Propose {
            cold_authorization, ..
        } = &mut op2.payload
        {
            *cold_authorization = Some(ColdGovernanceAuthorization {
                cold_key_version: 1,
                cold_nonce: 2,
            });
        }
        sign_cold_governance_op(&mut op2, &cold);
        engine.governance_mempool.push(op2.clone());
        engine.evict_committed_governance_ops(&[op1]);
        assert_eq!(engine.governance_mempool, vec![op2]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn governance_mempool_empty_fast_paths_are_noops() {
        let dir = temp_dir("governance_empty_fast_path");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let original_state = engine.state.clone();

        engine.prune_invalid_governance_ops();
        let selected = engine.select_governance_ops();

        assert!(selected.is_empty());
        assert!(engine.governance_mempool.is_empty());
        assert_eq!(engine.state, original_state);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn governance_mempool_nonempty_selection_still_uses_validation_path() {
        let dir = temp_dir("governance_nonempty_selection");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let keypair = install_active_validator(&mut engine, [0x55; 32], "gov-select");
        let cold = cold_keypair_for_seed([0x55; 32]);
        let op = valid_cold_governance_propose_op(&mut engine, &keypair, &cold, 1);
        engine.governance_mempool.push(op.clone());

        let selected = engine.select_governance_ops();

        assert_eq!(selected, vec![op.clone()]);
        assert_eq!(engine.governance_mempool, vec![op]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn governance_mempool_capacity_is_enforced_at_admission() {
        let dir = temp_dir("governance_mempool_capacity");
        let mut config = NodeConfig::local_test(dir.clone());
        config.governance_mempool_capacity = 0;
        let mut engine = NodeEngine::init(config).unwrap();
        let keypair = install_active_validator(&mut engine, [0x54; 32], "gov-cap");
        let cold = cold_keypair_for_seed([0x54; 32]);
        let op = valid_cold_governance_propose_op(&mut engine, &keypair, &cold, 1);

        let err = engine.add_governance_op(op).unwrap_err().to_string();
        assert!(err.contains("governance mempool full"));
        assert!(engine.governance_mempool.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evict_committed_ops_removes_correct_entries() {
        let dir = temp_dir("staking_mempool_evict");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let keypair = install_active_validator(&mut engine, [0x72; 32], "stake");
        let retained_keypair = install_active_validator(&mut engine, [0x73; 32], "stake2");
        let cold = cold_keypair_for_seed([0x72; 32]);
        let retained_cold = cold_keypair_for_seed([0x73; 32]);
        let committed = valid_set_commission_staking_op(&engine, &keypair, &cold, 1, 1_100);
        let retained =
            valid_set_commission_staking_op(&engine, &retained_keypair, &retained_cold, 1, 1_200);

        engine.add_staking_op(committed.clone()).unwrap();
        engine.add_staking_op(retained.clone()).unwrap();
        engine.evict_committed_staking_ops(&[committed]);

        assert_eq!(engine.staking_mempool, vec![retained]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
