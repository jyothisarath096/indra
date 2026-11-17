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
//!   6. Durably publish the buffered, own-QC-verified sync projection
//!   7. Advance to next height

#[cfg(test)]
use indra_consensus::qc::verify_qc_strict;
use indra_consensus::{
    mempool::Mempool,
    producer::{produce_block, BlockTemplate},
    proposer::{compute_proposer_vrf, ProposerElection},
    qc::{verify_qc, QcValidator},
    vote::{produce_vote, RegisteredVoter},
};
use indra_core::codec::Decode;
use indra_core::types::{
    block::{BlockProposalVNext, BlockVNext},
    crypto::HybridPubKey,
    governance::GovernanceOpV2,
    primitives::{
        Bytes32, VariableBytes, DISK_CRITICAL_THRESHOLD_BYTES, MAX_CLASSICAL_SIG_BYTES,
        MAX_GOV_OPS_PER_BLOCK, MAX_PQ_SIG_BYTES, MAX_QC_SIZE_BYTES, MAX_SLASHES_PER_BLOCK,
        MAX_STAKE_POSITIONS_PER_VALIDATOR, MAX_STAKE_POSITIONS_TOTAL, MAX_STAKING_OPS_PER_BLOCK,
        MAX_TRANCHES_PER_POSITION, MAX_TRANCHES_PER_VALIDATOR, MAX_TRANCHES_TOTAL,
    },
    slash_membership::build_slash_membership_proof,
    slashing::{SlashEvidenceV1, SlashEvidenceV2},
    staking::StakingOp,
    vote::VoteStep,
    ConsensusSnapshot,
};

fn evaluate_disk_writable(available: std::io::Result<u64>) -> NodeResult<()> {
    match available {
        Ok(bytes) if bytes >= DISK_CRITICAL_THRESHOLD_BYTES => Ok(()),
        Ok(bytes) => Err(NodeError::StoragePressure {
            detail: format!(
                "only {} bytes available; at least {} required",
                bytes, DISK_CRITICAL_THRESHOLD_BYTES
            ),
        }),
        Err(error) => Err(NodeError::StoragePressure {
            detail: format!("free-space query failed: {error}"),
        }),
    }
}

fn ensure_disk_writable(data_dir: &std::path::Path) -> NodeResult<()> {
    evaluate_disk_writable(fs2::available_space(data_dir))
}

fn protocol_hybrid_pubkey_parts(classical: [u8; 32], pq: &[u8]) -> NodeResult<HybridPubKey> {
    Ok(HybridPubKey {
        classical_pk: Bytes32::from(classical),
        pq_pk: VariableBytes::from_slice(pq).map_err(|_| {
            NodeError::ValidatorConfigIncomplete {
                detail: "configured ML-DSA-87 public key is too large".to_string(),
            }
        })?,
    })
}

fn protocol_hybrid_pubkey(keypair: &HybridKeypair) -> NodeResult<HybridPubKey> {
    let public = keypair.public_key();
    protocol_hybrid_pubkey_parts(public.classical.0, &public.pq.0)
}
use indra_crypto::{
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    VrfKeypair,
};
use indra_state::{
    apply::compute_slash_evidence_v2_hash, epoch::epoch_for_height, try_apply_governance_candidate,
    try_apply_slash_candidate, try_apply_slash_candidate_at_index,
    try_apply_staking_candidate_at_index, try_apply_transaction_candidate_with_dust, ChainState,
};
use indra_storage::{
    load_chain_manifest, load_last_qc, save_chain_manifest, BlockStore, ChainManifest, EpochStore,
    StateStore,
};

use crate::{
    config::NodeConfig,
    error::{NodeError, NodeResult},
    genesis::build_genesis_block,
    pending_dependencies::{
        governance_footprint, slash_footprint, staking_footprint, DependencyIndex, DependencyKey,
    },
    qc_verification::NetworkQcVerifier,
    sync::{commit_prepared_with_durable_hook, verify_sync_candidate, PreparedSyncBlock},
};

/// The node engine: owns all state and drives consensus.
pub struct NodeEngine {
    /// Node configuration.
    pub config: NodeConfig,
    /// Current chain state.
    pub state: ChainState,
    /// Immutable canonical state published to RPC readers after each commit.
    pub rpc_snapshot: crate::rpc_snapshot::RpcSnapshotPublisher,
    /// Pending transaction pool.
    pub mempool: Mempool,
    /// Pending staking operations waiting to be included in a block.
    pub(crate) staking_mempool: Vec<StakingOp>,
    /// Pending governance operations waiting to be included in a block.
    pub(crate) governance_mempool: Vec<GovernanceOpV2>,
    /// Pending slash evidence waiting to be included in a block.
    pub(crate) pending_slashes: Vec<SlashEvidenceV2>,
    staking_dependency_index: DependencyIndex,
    governance_dependency_index: DependencyIndex,
    slash_dependency_index: DependencyIndex,
    pending_dependency_epoch: u64,
    verified_staking:
        std::collections::BTreeMap<Bytes32, indra_state::pending::VerifiedPendingStaking>,
    verified_governance:
        std::collections::BTreeMap<Bytes32, indra_state::pending::VerifiedPendingGovernance>,
    /// Persistent block log.
    pub block_store: BlockStore,
    /// Persistent epoch history log.
    pub epoch_store: EpochStore,
    /// State snapshot store.
    pub state_store: StateStore,
    /// Dedicated bounded verifier used only for peer-sourced QC candidates.
    pub(crate) network_qc_verifier: NetworkQcVerifier,
    /// The validator's hybrid keypair (if this is a validator node).
    hybrid_keypair: Option<HybridKeypair>,
    /// The protocol public key derived once from the validator keypair at startup.
    reporter_pubkey: Option<HybridPubKey>,
    /// The validator's VRF keypair.
    vrf_keypair: Option<VrfKeypair>,
    /// This validator's identity (SHA-256 of hybrid public key classical component).
    validator_id: Option<Bytes32>,
}

/// Slash evidence is large and only one pending record per validator is useful.
/// 1,024 entries provide more than five full active sets of reconfiguration
/// headroom while imposing a finite memory/verification bound.
pub const MAX_PENDING_SLASH_EVIDENCE: usize = 1_024;

#[derive(Debug)]
struct SelectedBlockContents {
    transactions: Vec<indra_core::types::transaction::TransactionV1>,
    staking_ops: Vec<StakingOp>,
    governance_ops: Vec<GovernanceOpV2>,
    slash_evidence: Vec<SlashEvidenceV2>,
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
    /// Ed25519 consensus verification key, when present.
    pub hybrid_classical_pk: Option<[u8; 32]>,
    /// ML-DSA-87 consensus/transport verification key.
    pub hybrid_pq_pk: Option<Vec<u8>>,
    /// VRF verification key, when present.
    pub vrf_pk: Option<[u8; 32]>,
    /// Current live network address for this authorized member, if available.
    pub network_addr: Option<String>,
}

impl NodeEngine {
    fn ensure_pending_indexes(&mut self) {
        let epoch = epoch_for_height(self.state.height.saturating_add(1));
        let epoch_changed = self.pending_dependency_epoch != epoch;
        if epoch_changed || self.staking_dependency_index.len() != self.staking_mempool.len() {
            self.staking_dependency_index = DependencyIndex::default();
            for op in &self.staking_mempool {
                self.staking_dependency_index.insert(
                    indra_state::pending::staking_op_id(op),
                    staking_footprint(&self.state, op, epoch),
                );
            }
        }
        if epoch_changed || self.governance_dependency_index.len() != self.governance_mempool.len()
        {
            self.governance_dependency_index = DependencyIndex::default();
            for op in &self.governance_mempool {
                self.governance_dependency_index.insert(
                    indra_state::pending::governance_op_id(op),
                    governance_footprint(op, epoch),
                );
            }
        }
        if epoch_changed || self.slash_dependency_index.len() != self.pending_slashes.len() {
            self.slash_dependency_index = DependencyIndex::default();
            for evidence in &self.pending_slashes {
                let id = compute_slash_evidence_v2_hash(evidence);
                self.slash_dependency_index
                    .insert(id, slash_footprint(&self.state, evidence, epoch));
            }
        }
        self.pending_dependency_epoch = epoch;
        self.debug_assert_pending_indexes();
    }

    fn debug_assert_pending_indexes(&self) {
        let epoch = epoch_for_height(self.state.height.saturating_add(1));
        self.staking_dependency_index
            .assert_reconstructed(self.staking_mempool.iter().map(|op| {
                (
                    indra_state::pending::staking_op_id(op),
                    staking_footprint(&self.state, op, epoch),
                )
            }));
        self.governance_dependency_index
            .assert_reconstructed(self.governance_mempool.iter().map(|op| {
                (
                    indra_state::pending::governance_op_id(op),
                    governance_footprint(op, epoch),
                )
            }));
        self.slash_dependency_index
            .assert_reconstructed(self.pending_slashes.iter().map(|evidence| {
                let id = compute_slash_evidence_v2_hash(evidence);
                (id, slash_footprint(&self.state, evidence, epoch))
            }));
    }

    fn apply_pending_canonical_effects(&mut self, effects: &indra_state::CanonicalStateEffects) {
        self.ensure_pending_indexes();

        let mut common = vec![DependencyKey::NextHeight];
        common.extend(effects.spent_utxos.iter().copied().map(DependencyKey::Utxo));
        if effects.base_fee_changed {
            common.push(DependencyKey::BaseFee);
        }
        for id in &effects.validators_changed {
            common.extend([
                DependencyKey::Validator(*id),
                DependencyKey::ValidatorPositionCapacity(*id),
                DependencyKey::ValidatorTrancheCapacity(*id),
            ]);
        }
        common.extend(
            effects
                .staking_nonces_changed
                .iter()
                .copied()
                .map(DependencyKey::StakingNonce),
        );
        common.extend(
            effects
                .governance_nonces_changed
                .iter()
                .copied()
                .map(DependencyKey::GovernanceNonce),
        );
        common.extend(
            effects
                .delegator_identities_changed
                .iter()
                .copied()
                .map(DependencyKey::DelegatorIdentity),
        );
        common.extend(
            effects
                .stake_positions_changed
                .iter()
                .copied()
                .map(DependencyKey::StakePosition),
        );
        common.extend(
            effects
                .position_tranche_capacity_changed_for
                .iter()
                .copied()
                .map(DependencyKey::PositionTrancheCapacity),
        );
        common.extend(
            effects
                .tombstones_changed
                .iter()
                .copied()
                .map(DependencyKey::Tombstone),
        );
        if !effects.tombstones_changed.is_empty() {
            common.push(DependencyKey::TombstoneRegistry);
        }
        common.extend(
            effects
                .proposals_changed
                .iter()
                .copied()
                .map(DependencyKey::Proposal),
        );
        if effects.validator_registry_changed || !effects.validator_keys_changed.is_empty() {
            common.push(DependencyKey::ValidatorRegistry);
        }
        if effects.retired_cold_components_changed {
            // Retired-component footprints are proposed-component-specific;
            // registry changes conservatively select registrations/rotations.
            common.push(DependencyKey::ValidatorRegistry);
        }
        if effects.global_position_tranche_capacity_changed {
            common.extend([
                DependencyKey::GlobalPositionCapacity,
                DependencyKey::GlobalTrancheCapacity,
            ]);
        }
        for id in &effects.validator_position_capacity_changed {
            common.push(DependencyKey::ValidatorPositionCapacity(*id));
        }
        for id in &effects.validator_tranche_capacity_changed {
            common.push(DependencyKey::ValidatorTrancheCapacity(*id));
        }
        if effects.governance_params_changed {
            common.extend((0..10).map(DependencyKey::GovernanceParam));
        }
        if !effects.proposals_changed.is_empty() {
            common.push(DependencyKey::ActiveProposalCount);
        }

        let mut affected_staking = self
            .staking_dependency_index
            .affected(common.iter().copied());
        let mut affected_governance = self
            .governance_dependency_index
            .affected(common.iter().copied());
        let mut affected_slashes = self.slash_dependency_index.affected(common.iter().copied());
        if effects.epoch_changed {
            affected_staking.extend(
                self.staking_mempool
                    .iter()
                    .map(indra_state::pending::staking_op_id),
            );
            affected_governance.extend(
                self.governance_mempool
                    .iter()
                    .map(indra_state::pending::governance_op_id),
            );
            affected_slashes.extend(
                self.pending_slashes
                    .iter()
                    .map(compute_slash_evidence_v2_hash),
            );
        }
        if effects.slash_membership_history_changed {
            affected_slashes.extend(
                self.pending_slashes
                    .iter()
                    .map(compute_slash_evidence_v2_hash),
            );
        }

        self.revalidate_affected_staking(&affected_staking);
        self.revalidate_affected_governance(&affected_governance);
        self.revalidate_affected_slashes(&affected_slashes);
        self.debug_assert_pending_indexes();
    }

    fn revalidate_affected_staking(&mut self, affected: &std::collections::BTreeSet<Bytes32>) {
        let height = self.state.height.saturating_add(1);
        let epoch = epoch_for_height(height);
        let state = &self.state;
        self.staking_mempool.retain(|op| {
            let id = indra_state::pending::staking_op_id(op);
            if !affected.contains(&id) {
                return true;
            }
            let mut scratch = state.clone();
            let refreshed = match self.verified_staking.get(&id) {
                Some(verified)
                    if indra_state::pending::staking_authority_unchanged(state, op, verified) =>
                {
                    indra_state::try_apply_verified_staking_candidate(
                        &mut scratch,
                        op,
                        verified,
                        height,
                    )
                    .is_ok()
                    .then(|| verified.clone())
                }
                _ => indra_state::pending::verify_pending_staking(state, op, height).ok(),
            };
            if let Some(verified) = &refreshed {
                self.staking_dependency_index
                    .insert(id, staking_footprint(state, op, epoch));
                self.verified_staking.insert(id, verified.clone());
            } else {
                self.staking_dependency_index.remove(&id);
                self.verified_staking.remove(&id);
            }
            refreshed.is_some()
        });
    }

    fn revalidate_affected_governance(&mut self, affected: &std::collections::BTreeSet<Bytes32>) {
        let height = self.state.height.saturating_add(1);
        let epoch = epoch_for_height(height);
        let state = &self.state;
        self.governance_mempool.retain(|op| {
            let id = indra_state::pending::governance_op_id(op);
            if !affected.contains(&id) {
                return true;
            }
            let mut scratch = state.clone();
            let refreshed = match self.verified_governance.get(&id) {
                Some(verified)
                    if indra_state::pending::governance_authority_unchanged(
                        state, op, verified,
                    ) =>
                {
                    indra_state::try_apply_verified_governance_candidate(
                        &mut scratch,
                        op,
                        verified,
                        epoch,
                        height,
                    )
                    .is_ok()
                    .then(|| verified.clone())
                }
                _ => indra_state::pending::verify_pending_governance(state, op, epoch, height).ok(),
            };
            if let Some(verified) = &refreshed {
                self.governance_dependency_index
                    .insert(id, governance_footprint(op, epoch));
                self.verified_governance.insert(id, verified.clone());
            } else {
                self.governance_dependency_index.remove(&id);
                self.verified_governance.remove(&id);
            }
            refreshed.is_some()
        });
    }

    fn revalidate_affected_slashes(&mut self, affected: &std::collections::BTreeSet<Bytes32>) {
        let height = self.state.height.saturating_add(1);
        let epoch = epoch_for_height(height);
        let state = &self.state;
        self.pending_slashes.retain(|evidence| {
            let id = compute_slash_evidence_v2_hash(evidence);
            if !affected.contains(&id) {
                return true;
            }
            let valid = indra_state::verify_slash_candidate(state, evidence, height).is_ok();
            if valid {
                self.slash_dependency_index
                    .insert(id, slash_footprint(state, evidence, epoch));
            } else {
                self.slash_dependency_index.remove(&id);
            }
            valid
        });
    }

    /// Initialise a node from its configuration.
    pub fn init(config: NodeConfig) -> NodeResult<Self> {
        if let Err(errors) = crate::config::validate_pool_capacities(
            config.mempool_capacity,
            config.staking_mempool_capacity,
            config.governance_mempool_capacity,
        ) {
            return Err(NodeError::InvalidConfiguration {
                detail: errors.join("; "),
            });
        }
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
        if let Some(manifest) = load_chain_manifest(&config.data_dir)? {
            block_store.recover_to_next_height(manifest.block_log_next_height)?;
        }
        let mut epoch_store = EpochStore::open(config.epoch_log_path())?;
        let state_store = StateStore::open(config.state_dir())?;
        if let Some(manifest) = load_chain_manifest(&config.data_dir)? {
            epoch_store.recover_to_latest(manifest.epoch_log_latest_epoch)?;
            state_store.quarantine_newer_than(manifest.snapshot_height)?;
        }
        let stored_schema_version = state_store.schema_version()?;
        if let Some(snapshot_version) = stored_schema_version {
            if snapshot_version != indra_core::types::primitives::SCHEMA_VERSION {
                return Err(NodeError::SchemaVersionTooNew {
                    snapshot_version,
                    node_version: indra_core::types::primitives::SCHEMA_VERSION,
                });
            }
        }
        let mut genesis_base = crate::genesis::build_finalized_genesis_state(
            config.genesis_path.as_deref(),
        )
        .map_err(|detail| NodeError::ValidatorConfigIncomplete { detail })?;
        if !block_store.is_empty() && block_store.lowest_height() == 0 {
            let stored = block_store.get(0)?;
            let expected = crate::genesis::build_genesis_proposal(&genesis_base)
                .map_err(|detail| NodeError::InvalidConfiguration { detail })?;
            if stored != expected {
                return Err(NodeError::GenesisMismatch);
            }
        }
        let startup_log;
        let state = if let Some(snapshot) = state_store.load_latest()? {
            if snapshot.genesis_fingerprint != genesis_base.genesis_fingerprint {
                return Err(NodeError::GenesisMismatch);
            }
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
                        (config.pq_pk.as_deref(), config.pq_seed.as_deref())
                    {
                        PqKeypair::from_bytes(pk, sk).unwrap_or_else(|_| PqKeypair::generate())
                    } else {
                        PqKeypair::generate()
                    };
                    let hybrid = HybridKeypair::new(classical, pq);
                    let vrf = VrfKeypair::from_seed(&vrfs);
                    let pk = hybrid.public_key();
                    let id = HybridPubKey {
                        classical_pk: Bytes32::from(pk.classical.0),
                        pq_pk: VariableBytes::from_slice(&pk.pq.0).map_err(|_| {
                            NodeError::ValidatorConfigIncomplete {
                                detail: "configured ML-DSA-87 public key is too large".to_string(),
                            }
                        })?,
                    }
                    .identity_id();
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
        let reporter_pubkey = hybrid_keypair
            .as_ref()
            .map(protocol_hybrid_pubkey)
            .transpose()?;
        if let (Some(id), Some(vrf)) = (validator_id, vrf_keypair.as_ref()) {
            let registered =
                state
                    .validators
                    .get(&id)
                    .ok_or_else(|| NodeError::ValidatorConfigIncomplete {
                        detail: format!(
                            "configured validator {id} is absent from genesis/registry"
                        ),
                    })?;
            if registered.vrf_pk != Some(vrf.public_key()) {
                return Err(NodeError::ValidatorConfigIncomplete {
                    detail: format!(
                        "configured VRF secret key does not match registered VRF public key for validator {id}"
                    ),
                });
            }
        }

        let pending_dependency_epoch = epoch_for_height(state.height.saturating_add(1));
        let rpc_snapshot = crate::rpc_snapshot::RpcSnapshotPublisher::new(
            &state,
            mempool.len(),
            !block_store.is_archive(),
            block_store.lowest_height(),
            block_store.len(),
        );
        Ok(Self {
            config,
            state,
            rpc_snapshot: rpc_snapshot.map_err(|detail| NodeError::InvalidConfiguration { detail })?,
            mempool,
            staking_mempool: Vec::new(),
            governance_mempool: Vec::new(),
            pending_slashes: Vec::new(),
            staking_dependency_index: DependencyIndex::default(),
            governance_dependency_index: DependencyIndex::default(),
            slash_dependency_index: DependencyIndex::default(),
            pending_dependency_epoch,
            verified_staking: std::collections::BTreeMap::new(),
            verified_governance: std::collections::BTreeMap::new(),
            block_store,
            epoch_store,
            state_store,
            network_qc_verifier: NetworkQcVerifier::new(),
            hybrid_keypair,
            reporter_pubkey,
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

    /// Bounded verifier for peer-sourced QC candidates.
    pub fn network_qc_verifier(&self) -> &NetworkQcVerifier {
        &self.network_qc_verifier
    }

    /// Load the last committed QC bytes persisted on disk, if any.
    pub fn load_persisted_qc(&self) -> NodeResult<Option<Vec<u8>>> {
        indra_storage::load_last_qc(&self.config.state_dir()).map_err(NodeError::Storage)
    }

    /// Rebuild the current chain state by replaying the block log on top of a
    /// fresh genesis-equivalent state seeded from the configured genesis file.
    pub fn rebuild_state_from_block_log(&mut self) -> NodeResult<()> {
        let mut rebuilt = crate::genesis::build_finalized_genesis_state(
            self.config.genesis_path.as_deref(),
        )
        .map_err(|detail| NodeError::ValidatorConfigIncomplete { detail })?;
        rebuild_state_from_height(&mut rebuilt, &mut self.block_store, 1)?;
        self.state = rebuilt;
        Ok(())
    }

    /// Add a staking operation to the pending pool.
    pub fn add_staking_op(&mut self, op: StakingOp) -> NodeResult<()> {
        ensure_disk_writable(&self.config.data_dir)?;
        self.ensure_pending_indexes();
        op.validate_structure()
            .map_err(|e| NodeError::InvalidStakingOp(e.to_string()))?;
        let validation_height = self.state.height.saturating_add(1);
        let verified =
            indra_state::pending::verify_pending_staking(&self.state, &op, validation_height)
                .map_err(|e| NodeError::InvalidStakingOp(e.to_string()))?;
        let epoch = epoch_for_height(validation_height);
        let footprint = staking_footprint(&self.state, &op, epoch);
        let exclusive_conflict = footprint.iter().any(|key| {
            matches!(
                key,
                DependencyKey::StakingNonce(_)
                    | DependencyKey::Utxo(_)
                    | DependencyKey::StakePosition(_)
                    | DependencyKey::ValidatorKey(_)
            ) && self.staking_dependency_index.contains_key(*key)
        });
        if exclusive_conflict {
            return Err(NodeError::InvalidStakingOp(
                "pending staking operation conflicts with an existing reservation".into(),
            ));
        }
        let new_position_validator = footprint.iter().find_map(|key| match key {
            DependencyKey::PendingPositionSlot(id) => Some(*id),
            _ => None,
        });
        if let Some(validator_id) = new_position_validator {
            let global_reserved = self
                .staking_dependency_index
                .affected([DependencyKey::PendingGlobalPositionSlot])
                .len();
            let validator_reserved = self
                .staking_dependency_index
                .affected([DependencyKey::PendingPositionSlot(validator_id)])
                .len();
            let global_used = self.state.stake_positions.len();
            let validator_used = self
                .state
                .stake_positions
                .values()
                .filter(|position| position.validator_id == validator_id)
                .count();
            if global_used.saturating_add(global_reserved) >= MAX_STAKE_POSITIONS_TOTAL
                || validator_used.saturating_add(validator_reserved)
                    >= MAX_STAKE_POSITIONS_PER_VALIDATOR
            {
                return Err(NodeError::InvalidStakingOp(
                    "pending staking reservations exhaust stake-position capacity".into(),
                ));
            }
        }
        let exit_position = footprint.iter().find_map(|key| match key {
            DependencyKey::PendingTrancheSlot(id) => Some(*id),
            _ => None,
        });
        if let Some(position_id) = exit_position {
            let validator_id = self
                .state
                .stake_positions
                .get(&position_id)
                .ok_or_else(|| {
                    NodeError::InvalidStakingOp(
                        "verified exit footprint references a missing stake position".into(),
                    )
                })?
                .validator_id;
            let reserved_position = self
                .staking_dependency_index
                .affected([DependencyKey::PendingTrancheSlot(position_id)])
                .len();
            let reserved_validator = self
                .staking_dependency_index
                .affected([DependencyKey::PendingValidatorTrancheSlot(validator_id)])
                .len();
            let reserved_global = self
                .staking_dependency_index
                .affected([DependencyKey::PendingGlobalTrancheSlot])
                .len();
            let used_position = self.state.tranche_ids_for_position(&position_id).len();
            let used_validator = self
                .state
                .unbonding_tranches
                .values()
                .filter(|tranche| {
                    self.state
                        .stake_positions
                        .get(&tranche.position_id)
                        .is_some_and(|position| position.validator_id == validator_id)
                })
                .count();
            let used_global = self.state.unbonding_tranches.len();
            if used_position.saturating_add(reserved_position) >= MAX_TRANCHES_PER_POSITION
                || used_validator.saturating_add(reserved_validator) >= MAX_TRANCHES_PER_VALIDATOR
                || used_global.saturating_add(reserved_global) >= MAX_TRANCHES_TOTAL
            {
                return Err(NodeError::InvalidStakingOp(
                    "pending staking reservations exhaust tranche capacity".into(),
                ));
            }
        }
        if footprint.contains(&DependencyKey::PendingGlobalFinalExitSlot) {
            let reserved_global = self
                .staking_dependency_index
                .affected([DependencyKey::PendingGlobalFinalExitSlot])
                .len();
            let active_global = self
                .state
                .stake_positions
                .values()
                .filter(|position| position.active.is_some())
                .count();
            if self
                .state
                .unbonding_tranches
                .len()
                .saturating_add(active_global)
                .saturating_add(reserved_global)
                >= MAX_TRANCHES_TOTAL
            {
                return Err(NodeError::InvalidStakingOp(
                    "pending staking reservations exhaust global final-exit capacity".into(),
                ));
            }
        }
        if let Some(validator_id) = footprint.iter().find_map(|key| match key {
            DependencyKey::PendingValidatorFinalExitSlot(id) => Some(*id),
            _ => None,
        }) {
            let reserved = self
                .staking_dependency_index
                .affected([DependencyKey::PendingValidatorFinalExitSlot(validator_id)])
                .len();
            let active = self
                .state
                .stake_positions
                .values()
                .filter(|position| {
                    position.validator_id == validator_id && position.active.is_some()
                })
                .count();
            let tranches = self
                .state
                .unbonding_tranches
                .values()
                .filter(|tranche| {
                    self.state
                        .stake_positions
                        .get(&tranche.position_id)
                        .is_some_and(|position| position.validator_id == validator_id)
                })
                .count();
            if tranches.saturating_add(active).saturating_add(reserved)
                >= MAX_TRANCHES_PER_VALIDATOR
            {
                return Err(NodeError::InvalidStakingOp(
                    "pending staking reservations exhaust validator final-exit capacity".into(),
                ));
            }
        }
        if self.staking_mempool.len() >= self.config.staking_mempool_capacity {
            return Err(NodeError::InvalidStakingOp(format!(
                "staking mempool full: {} ops",
                self.config.staking_mempool_capacity
            )));
        }
        let id = indra_state::pending::staking_op_id(&op);
        self.staking_mempool.push(op);
        self.staking_dependency_index.insert(id, footprint);
        self.verified_staking.insert(id, verified);
        self.debug_assert_pending_indexes();
        Ok(())
    }

    /// Add a governance operation to the pending pool.
    pub fn add_governance_op(&mut self, op: GovernanceOpV2) -> NodeResult<()> {
        ensure_disk_writable(&self.config.data_dir)?;
        self.ensure_pending_indexes();
        let current_epoch = epoch_for_height(self.state.height.saturating_add(1));
        let verified = indra_state::pending::verify_pending_governance(
            &self.state,
            &op,
            current_epoch,
            self.state.height.saturating_add(1),
        )
        .map_err(|error| NodeError::InvalidGovernanceOp(error.to_string()))?;
        if self
            .governance_dependency_index
            .contains_key(DependencyKey::GovernanceNonce(op.signer_id))
        {
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
        let id = indra_state::pending::governance_op_id(&op);
        let footprint = governance_footprint(&op, current_epoch);
        self.governance_mempool.push(op);
        self.governance_dependency_index.insert(id, footprint);
        self.verified_governance.insert(id, verified);
        self.debug_assert_pending_indexes();
        Ok(())
    }

    /// Validate and add a transaction while refreshing fast RPC metadata.
    pub fn add_transaction(
        &mut self,
        transaction: indra_core::types::transaction::TransactionV1,
    ) -> Result<Bytes32, indra_consensus::ConsensusError> {
        ensure_disk_writable(&self.config.data_dir)
            .map_err(|_| indra_consensus::ConsensusError::StoragePressure)?;
        let id = self.mempool.submit_validated(transaction, &self.state)?;
        self.rpc_snapshot.set_mempool_size(self.mempool.len());
        Ok(id)
    }

    /// Validate and add slash evidence to the bounded pending pool.
    pub fn add_slash_evidence(&mut self, evidence: SlashEvidenceV1) -> NodeResult<()> {
        self.ensure_pending_indexes();
        let already_pending = self.pending_slashes.iter().any(|existing| {
            existing.validator_id == evidence.validator_id
                && existing.vote_1 == evidence.vote_1
                && existing.vote_2 == evidence.vote_2
        });
        if already_pending {
            return Ok(());
        }
        if self
            .pending_slashes
            .iter()
            .any(|pending| pending.validator_id == evidence.validator_id)
        {
            return Err(NodeError::State(
                indra_state::StateError::InvalidSlashEvidence {
                    reason: "slash evidence for validator is already pending".into(),
                },
            ));
        }
        if self.pending_slashes.len() >= MAX_PENDING_SLASH_EVIDENCE {
            return Err(NodeError::State(
                indra_state::StateError::InvalidSlashEvidence {
                    reason: format!(
                        "slash evidence pool full: {MAX_PENDING_SLASH_EVIDENCE} entries"
                    ),
                },
            ));
        }
        let snapshot = self
            .state
            .snapshot_for_consensus_height(evidence.vote_1.height)?;
        let (position, _) = snapshot
            .entry_with_position(&evidence.validator_id)
            .ok_or_else(|| indra_state::StateError::InvalidSlashEvidence {
                reason: "claimed validator is absent from the infraction snapshot".into(),
            })?;
        let membership_proof =
            build_slash_membership_proof(snapshot, position).map_err(|error| {
                NodeError::State(indra_state::StateError::InvalidSlashEvidence {
                    reason: format!("failed to build membership proof: {error}"),
                })
            })?;
        let proof_evidence = SlashEvidenceV2 {
            validator_id: evidence.validator_id,
            vote_1: evidence.vote_1.clone(),
            vote_2: evidence.vote_2.clone(),
            membership_proof,
        };
        let v2_hash = compute_slash_evidence_v2_hash(&proof_evidence);
        let mut scratch = self.state.clone();
        try_apply_slash_candidate(
            &mut scratch,
            &proof_evidence,
            self.state.height.saturating_add(1),
            None,
        )?;
        let footprint = slash_footprint(
            &self.state,
            &proof_evidence,
            epoch_for_height(self.state.height.saturating_add(1)),
        );
        self.pending_slashes.push(proof_evidence);
        self.slash_dependency_index.insert(v2_hash, footprint);
        self.debug_assert_pending_indexes();
        Ok(())
    }

    /// Remove slash evidence that has already been committed.
    pub fn evict_committed_slashes(&mut self, committed: &[SlashEvidenceV2]) {
        let slashed: std::collections::HashSet<_> = committed
            .iter()
            .map(|evidence| evidence.validator_id)
            .collect();
        let removed: Vec<_> = self
            .pending_slashes
            .iter()
            .filter(|pending| slashed.contains(&pending.validator_id))
            .map(compute_slash_evidence_v2_hash)
            .collect();
        self.pending_slashes
            .retain(|pending| !slashed.contains(&pending.validator_id));
        for id in removed {
            self.slash_dependency_index.remove(&id);
        }
    }

    /// Select all candidate block contents against one evolving detached state.
    /// Pool order is preserved for staking, governance, and slashing; transaction
    /// ordering remains the mempool's age/fee/tx-id policy.
    fn select_block_contents(&mut self) -> NodeResult<SelectedBlockContents> {
        self.ensure_pending_indexes();
        let height = self.state.height.saturating_add(1);
        let current_epoch = epoch_for_height(height);
        let mut scratch = self.state.clone();
        let transaction_dust_limit =
            indra_core::types::primitives::transaction_dust_limit_spark(self.state.utxos.len());
        let reporter_pubkey = self.reporter_pubkey.as_ref();

        let transaction_candidates: Vec<_> = self
            .mempool
            .select_for_block(usize::MAX, self.state.height)
            .into_iter()
            .map(|entry| (entry.tx_id, entry.tx.clone()))
            .collect();
        let mut transactions = Vec::new();
        for (tx_id, tx) in transaction_candidates {
            if transactions.len() >= indra_core::types::primitives::MAX_TX_PER_BLOCK {
                break;
            }
            match try_apply_transaction_candidate_with_dust(
                &mut scratch,
                &tx,
                height,
                transactions.len() as u32,
                transaction_dust_limit,
            ) {
                Ok(()) => transactions.push(tx),
                Err(error) => {
                    eprintln!("[mempool] evicting conflicting candidate {tx_id}: {error}");
                    self.mempool.evict(&tx_id).map_err(NodeError::Consensus)?;
                }
            }
        }

        let mut staking_ops = Vec::new();
        let mut retained_staking = Vec::new();
        for op in std::mem::take(&mut self.staking_mempool) {
            if staking_ops.len() >= MAX_STAKING_OPS_PER_BLOCK {
                retained_staking.push(op);
                continue;
            }
            match try_apply_staking_candidate_at_index(
                &mut scratch,
                &op,
                height,
                staking_ops.len() as u32,
            ) {
                Ok(()) => {
                    staking_ops.push(op.clone());
                    retained_staking.push(op);
                }
                Err(error) => {
                    let id = indra_state::pending::staking_op_id(&op);
                    if !retained_staking
                        .iter()
                        .any(|retained| indra_state::pending::staking_op_id(retained) == id)
                    {
                        self.staking_dependency_index.remove(&id);
                        self.verified_staking.remove(&id);
                    }
                    eprintln!(
                        "[staking] evicting conflicting candidate signer={}: {error}",
                        hex::encode(&op.signer_id().0[..4]),
                    );
                }
            }
        }
        self.staking_mempool = retained_staking;

        let mut governance_ops = Vec::new();
        let mut retained_governance = Vec::new();
        for op in std::mem::take(&mut self.governance_mempool) {
            if governance_ops.len() >= MAX_GOV_OPS_PER_BLOCK {
                retained_governance.push(op);
                continue;
            }
            match try_apply_governance_candidate(&mut scratch, &op, current_epoch, height) {
                Ok(()) => {
                    governance_ops.push(op.clone());
                    retained_governance.push(op);
                }
                Err(error) => {
                    let id = indra_state::pending::governance_op_id(&op);
                    if !retained_governance
                        .iter()
                        .any(|retained| indra_state::pending::governance_op_id(retained) == id)
                    {
                        self.governance_dependency_index.remove(&id);
                        self.verified_governance.remove(&id);
                    }
                    eprintln!(
                        "[governance] evicting conflicting candidate signer={} nonce={}: {error}",
                        hex::encode(&op.signer_id.0[..4]),
                        op.nonce,
                    );
                }
            }
        }
        self.governance_mempool = retained_governance;

        let mut slash_evidence = Vec::new();
        let mut retained_slashes = Vec::new();
        for evidence in std::mem::take(&mut self.pending_slashes) {
            if slash_evidence.len() >= MAX_SLASHES_PER_BLOCK {
                retained_slashes.push(evidence);
                continue;
            }
            match try_apply_slash_candidate_at_index(
                &mut scratch,
                &evidence,
                height,
                reporter_pubkey,
                slash_evidence.len() as u32,
            ) {
                Ok(()) => {
                    slash_evidence.push(evidence.clone());
                    retained_slashes.push(evidence);
                }
                Err(error) => {
                    self.slash_dependency_index
                        .remove(&compute_slash_evidence_v2_hash(&evidence));
                    eprintln!(
                        "[slash] evicting conflicting candidate validator={}: {error}",
                        hex::encode(&evidence.validator_id.0[..4]),
                    );
                }
            }
        }
        self.pending_slashes = retained_slashes;
        self.debug_assert_pending_indexes();

        Ok(SelectedBlockContents {
            transactions,
            staking_ops,
            governance_ops,
            slash_evidence,
        })
    }

    /// Remove staking operations included in a committed block.
    pub fn evict_committed_staking_ops(&mut self, committed_ops: &[StakingOp]) {
        for op in committed_ops {
            let signer_id = op.signer_id();
            let cold_authorization = op.cold_authorization();
            let removed: Vec<_> = self
                .staking_mempool
                .iter()
                .filter(|existing| {
                    if existing.signer_id() != signer_id {
                        return false;
                    }
                    match (existing.cold_authorization(), cold_authorization) {
                        (Some(existing), Some(committed)) => existing == committed,
                        (None, None) => existing.nonce == op.nonce,
                        _ => false,
                    }
                })
                .map(indra_state::pending::staking_op_id)
                .collect();
            let removed_set: std::collections::BTreeSet<_> = removed.iter().copied().collect();
            self.staking_mempool.retain(|existing| {
                !removed_set.contains(&indra_state::pending::staking_op_id(existing))
            });
            for id in removed {
                self.staking_dependency_index.remove(&id);
                self.verified_staking.remove(&id);
            }
        }
    }

    /// Remove governance operations included in a committed block.
    pub fn evict_committed_governance_ops(&mut self, committed_ops: &[GovernanceOpV2]) {
        for op in committed_ops {
            let signer_id = op.signer_id;
            let cold_authorization = op.cold_authorization();
            let removed: Vec<_> = self
                .governance_mempool
                .iter()
                .filter(|existing| {
                    if existing.signer_id != signer_id {
                        return false;
                    }
                    match (existing.cold_authorization(), cold_authorization) {
                        (Some(existing), Some(committed)) => existing == committed,
                        (None, None) => existing.nonce == op.nonce,
                        _ => false,
                    }
                })
                .map(indra_state::pending::governance_op_id)
                .collect();
            let removed_set: std::collections::BTreeSet<_> = removed.iter().copied().collect();
            self.governance_mempool.retain(|existing| {
                !removed_set.contains(&indra_state::pending::governance_op_id(existing))
            });
            for id in removed {
                self.governance_dependency_index.remove(&id);
                self.verified_governance.remove(&id);
            }
        }
    }

    /// Check whether this node is independently eligible for the slot.
    pub fn is_proposer(&self, election: &ProposerElection) -> bool {
        let (Some(validator_id), Some(vrf_keypair)) =
            (self.validator_id, self.vrf_keypair.as_ref())
        else {
            return false;
        };
        compute_proposer_vrf(validator_id, vrf_keypair, election).is_ok_and(|slot| slot.eligible)
    }

    fn authorize_proposal(&self, block: BlockVNext) -> NodeResult<BlockProposalVNext> {
        let keypair = self
            .hybrid_keypair
            .as_ref()
            .ok_or(NodeError::NotValidator)?;
        let empty = indra_core::types::crypto::HybridSignature {
            classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(&[]).map_err(
                |error| NodeError::BlockInvalid {
                    height: block.header.height,
                    reason: error.to_string(),
                },
            )?,
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&[]).map_err(|error| {
                NodeError::BlockInvalid {
                    height: block.header.height,
                    reason: error.to_string(),
                }
            })?,
        };
        let mut proposal = BlockProposalVNext {
            block,
            proposer_authorization: empty,
        };
        let signing_bytes = proposal
            .signing_bytes(self.state.chain_id.as_bytes())
            .map_err(|error| NodeError::BlockInvalid {
                height: proposal.block.header.height,
                reason: error.to_string(),
            })?;
        let signature = keypair
            .sign(&signing_bytes)
            .map_err(|error| NodeError::BlockInvalid {
                height: proposal.block.header.height,
                reason: format!("failed to authorize proposal: {error}"),
            })?;
        proposal.proposer_authorization = indra_core::types::crypto::HybridSignature {
            classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(
                &signature.classical.0,
            )
            .map_err(|error| NodeError::BlockInvalid {
                height: proposal.block.header.height,
                reason: error.to_string(),
            })?,
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&signature.pq.0).map_err(
                |error| NodeError::BlockInvalid {
                    height: proposal.block.header.height,
                    reason: error.to_string(),
                },
            )?,
        };
        Ok(proposal)
    }

    /// Produce and fully authorize a proposal envelope for the next height.
    pub fn propose(
        &mut self,
        election: &ProposerElection,
        timestamp: u64,
        prev_qc_bytes: Vec<u8>,
        polc_round: Option<u32>,
    ) -> NodeResult<BlockProposalVNext> {
        if let Some(round) = polc_round {
            indra_core::types::primitives::validate_consensus_round(round).map_err(|error| {
                NodeError::BlockInvalid {
                    height: self.state.height + 1,
                    reason: error.to_string(),
                }
            })?;
        }
        ensure_disk_writable(&self.config.data_dir)?;
        let proposal_height = self.state.height + 1;
        if proposal_height > 1 && prev_qc_bytes.is_empty() {
            return Err(NodeError::MissingQc {
                height: proposal_height,
            });
        }
        let vrf_keypair = self
            .vrf_keypair
            .as_ref()
            .ok_or(NodeError::NotProposer {
                height: proposal_height,
            })?
            .clone();
        let contents = self.select_block_contents()?;
        let template = BlockTemplate {
            proposer_vrf_keypair: vrf_keypair,
            prev_qc_bytes,
            timestamp,
            polc_round,
            transactions: contents.transactions,
            slash_evidence: contents.slash_evidence,
            governance_ops: contents.governance_ops,
            staking_ops: contents.staking_ops,
        };
        let block =
            produce_block(&template, &mut self.state, election).map_err(NodeError::Consensus)?;
        self.authorize_proposal(block)
    }

    /// Re-propose an already validated value in a later round and authorize the
    /// new canonical envelope independently.
    pub fn repropose(
        &mut self,
        original_block: &BlockVNext,
        new_round: u32,
        valid_round: Option<u32>,
        election: &ProposerElection,
        timestamp: u64,
        last_qc: Vec<u8>,
    ) -> NodeResult<BlockProposalVNext> {
        indra_core::types::primitives::validate_consensus_round(new_round).map_err(|error| {
            NodeError::BlockInvalid {
                height: self.state.height + 1,
                reason: error.to_string(),
            }
        })?;
        if let Some(round) = valid_round {
            indra_core::types::primitives::validate_consensus_round(round).map_err(|error| {
                NodeError::BlockInvalid {
                    height: self.state.height + 1,
                    reason: error.to_string(),
                }
            })?;
        }
        ensure_disk_writable(&self.config.data_dir)?;
        let proposal_height = self.state.height + 1;
        if proposal_height > 1 && last_qc.is_empty() {
            return Err(NodeError::MissingQc {
                height: proposal_height,
            });
        }
        let vrf_keypair = self.vrf_keypair.as_ref().ok_or(NodeError::NotProposer {
            height: proposal_height,
        })?;
        let validator_id = self.validator_id.ok_or(NodeError::NotProposer {
            height: proposal_height,
        })?;
        let slot = compute_proposer_vrf(validator_id, vrf_keypair, election)
            .map_err(NodeError::Consensus)?;
        if !slot.eligible || new_round != election.round {
            return Err(NodeError::NotProposer {
                height: proposal_height,
            });
        }
        // A reproposal preserves the already validated stable value. With
        // signer-scoped rewards, replacing the original parent QC with a
        // different valid signer subset would change the projected reward
        // state root and therefore the stable value hash. The original block
        // QC is already parent-valid; retain it when present and use the
        // supplied QC only for the height-one compatibility case.
        let qc_source = if original_block.header.quorum_certificate.is_empty() {
            last_qc.as_slice()
        } else {
            original_block.header.quorum_certificate.as_slice()
        };
        let qc_bytes =
            VariableBytes::<MAX_QC_SIZE_BYTES>::from_slice(qc_source).map_err(|error| {
                NodeError::BlockInvalid {
                    height: proposal_height,
                    reason: error.to_string(),
                }
            })?;
        let mut block = original_block.clone();
        block.header.timestamp = timestamp;
        block.header.proposer_round = new_round;
        block.header.polc_round = valid_round;
        block.header.proposer_id = slot.proposer_id;
        block.header.vrf_suite = indra_core::types::block::VrfSuiteV1::EcvrfEdwards25519Sha512Ell2;
        block.header.election_seed = election.election_seed;
        block.header.proposer_vrf_output =
            VariableBytes::from_slice(&slot.vrf_output.0).map_err(|error| {
                NodeError::BlockInvalid {
                    height: proposal_height,
                    reason: error.to_string(),
                }
            })?;
        block.header.proposer_vrf_proof =
            VariableBytes::from_slice(&slot.vrf_proof.0).map_err(|error| {
                NodeError::BlockInvalid {
                    height: proposal_height,
                    reason: error.to_string(),
                }
            })?;
        block.header.sortition_claim = indra_core::types::block::SortitionClaimV1::PraosThreshold;
        block.header.proposer_priority = slot.priority;
        block.header.quorum_certificate = qc_bytes;
        let projected = indra_state::project_block_for_roots(&mut self.state, &block, 0)?;
        if projected.value_hash != original_block.header.value_hash {
            return Err(NodeError::BlockInvalid {
                height: proposal_height,
                reason: "reproposal changed stable value hash".into(),
            });
        }
        block.header.state_root = projected.state_root;
        block.header.validator_set_root = projected.validator_set_root;
        block.header.value_hash = projected.value_hash;
        self.authorize_proposal(block)
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
    /// Resolve authority from the retained snapshot governing this height.
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
    /// Snapshot-governed heights fail closed on lookup failure, take
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

    /// Verify an attacker-controlled network QC through the bounded worker.
    pub fn verify_network_qc_for_height(
        &self,
        qc: &indra_core::types::qc::QuorumCertificateV1,
    ) -> NodeResult<()> {
        let snapshot = self.state.snapshot_for_consensus_height(qc.height)?;
        self.network_qc_verifier
            .verify(qc, snapshot, &self.state.chain_id)
            .map_err(|err| NodeError::BlockInvalid {
                height: qc.height,
                reason: format!("network QC verification failed: {err}"),
            })
    }

    /// Strictly verify a QC using one already-resolved immutable snapshot.
    pub(crate) fn verify_qc_with_snapshot(
        qc: &indra_core::types::qc::QuorumCertificateV1,
        snapshot: &ConsensusSnapshot,
        chain_id: &str,
    ) -> NodeResult<()> {
        indra_core::types::qc::verify_qc_against_snapshot(qc, snapshot, chain_id)
            .map(|_| ())
            .map_err(|err| NodeError::BlockInvalid {
                height: qc.height,
                reason: format!("QC failed immutable-snapshot verification: {err}"),
            })
    }

    /// Sign a local vote over its complete consensus identity.
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
        let snapshot_root = self
            .state
            .snapshot_for_consensus_height(height)?
            .snapshot_root;
        produce_vote(
            height,
            round,
            step,
            block_hash,
            validator_id,
            snapshot_root,
            &self.state.chain_id,
            hybrid_keypair,
        )
        .map_err(NodeError::Consensus)
    }

    /// Import a fully authorized proposal that has been committed (QC formed).
    pub fn commit_proposal(&mut self, proposal: &BlockProposalVNext) -> NodeResult<()> {
        let prepared = verify_sync_candidate(proposal, &self.state, current_timestamp_secs())?;
        self.commit_prepared_sync_block(proposal, prepared)
    }

    /// Durably commit a sync block using its admission-time detached projection.
    pub fn commit_prepared_sync_block(
        &mut self,
        proposal: &BlockProposalVNext,
        prepared: PreparedSyncBlock,
    ) -> NodeResult<()> {
        let block = &proposal.block;
        let data_dir = self.config.data_dir.clone();
        let state_dir = self.config.state_dir();
        let state_store = &self.state_store;
        let epoch_store = &mut self.epoch_store;
        let last_qc_height = load_last_qc(&state_dir)
            .ok()
            .flatten()
            .and_then(|bytes| {
                indra_core::types::qc::QuorumCertificateV1::decode_exact(&bytes)
                    .ok()
                    .map(|qc| qc.height)
            })
            .unwrap_or(0);
        let outcome = commit_prepared_with_durable_hook(
            proposal,
            prepared,
            &mut self.state,
            &mut self.mempool,
            &mut self.block_store,
            state_store,
            |projected_state, epoch_record, block_log_next_height| {
                if let Some(record) = epoch_record {
                    epoch_store.append(record)?;
                }
                let manifest = ChainManifest {
                    committed_height: projected_state.height,
                    committed_block_hash: projected_state.tip_hash,
                    state_root: indra_state::compute_state_root(projected_state)
                        .map_err(|error| NodeError::InvalidConfiguration {
                            detail: error.to_string(),
                        })?,
                    snapshot_height: state_store.latest_snapshot_height()?.unwrap_or(0),
                    block_log_next_height,
                    last_qc_height,
                    epoch_log_latest_epoch: epoch_store.latest_epoch(),
                    chain_id: projected_state.chain_id.clone(),
                };
                save_chain_manifest(&data_dir, &manifest)?;
                Ok(())
            },
        )?;
        // QC signer liveness is updated inside `apply_block` so live import,
        // sync import, replay, and block-production projection mutate state
        // identically.
        self.evict_committed_staking_ops(&block.staking_ops);
        self.evict_committed_governance_ops(&block.governance_ops);
        self.evict_committed_slashes(&block.slashing_evidence);
        self.apply_pending_canonical_effects(&outcome.effects);
        self.rpc_snapshot.publish_with_effects(
            &self.state,
            &outcome.effects,
            self.mempool.len(),
            !self.block_store.is_archive(),
            self.block_store.lowest_height(),
            self.block_store.len(),
        )?;
        Ok(())
    }

    /// Persist a durable manifest for the currently committed state.
    pub fn write_chain_manifest(&mut self) -> NodeResult<()> {
        let last_qc_height = load_last_qc(&self.config.state_dir())
            .ok()
            .flatten()
            .and_then(|bytes| {
                indra_core::types::qc::QuorumCertificateV1::decode_exact(&bytes)
                    .ok()
                    .map(|qc| qc.height)
            })
            .unwrap_or(0);
        let manifest = ChainManifest {
            committed_height: self.state.height,
            committed_block_hash: self.state.tip_hash,
            state_root: indra_state::compute_state_root(&self.state).map_err(|error| {
                NodeError::InvalidConfiguration {
                    detail: error.to_string(),
                }
            })?,
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
    if block_store.is_empty() {
        if start_height <= 1 {
            let canonical_genesis = build_genesis_block(state)
                .map_err(|detail| NodeError::InvalidConfiguration { detail })?;
            state.tip_hash = canonical_genesis.header.block_hash();
        }
        return Ok(());
    }

    if start_height <= 1 {
        let canonical_genesis = build_genesis_block(state)
            .map_err(|detail| NodeError::InvalidConfiguration { detail })?;
        let genesis = block_store.get(0)?;
        if genesis.block != canonical_genesis {
            return Err(NodeError::GenesisMismatch);
        }

        // Anchor replay to the persisted genesis hash so block 1 must chain to
        // the exact genesis block stored on disk rather than an all-zero tip.
        state.tip_hash = genesis.block.header.block_hash();
    }

    for height in start_height.max(1)..block_store.next_height() {
        let proposal = block_store.get(height)?;
        let projection =
            verify_sync_candidate(&proposal, state, 0).map_err(|err| {
                NodeError::StartupReplayFailed {
                    height: proposal.block.header.height,
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
    let block_hash = block.block.header.block_hash();
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
        let state_root = indra_state::compute_state_root(state).map_err(|error| {
            NodeError::InvalidConfiguration {
                detail: error.to_string(),
            }
        })?;
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
    use indra_core::types::primitives::TEST_CHAIN_ID;
    use super::*;

    fn account_fixture_claims(state: &mut ChainState) {
        state.monetary_aggregates = state.recompute_monetary_aggregates().unwrap();
        let issued = state.monetary_aggregates.total_claims_spark().unwrap();
        state.total_supply = issued;
        state.monetary_ledger.genesis_issued_spark = issued;
        state.monetary_ledger.reward_budget_spark =
            indra_core::types::primitives::LIFETIME_SUPPLY_CAP_SPARK - issued;
        state.monetary_ledger.cumulative_reward_minted_spark = 0;
        state.monetary_ledger.epoch_reward_minted_spark = 0;
    }
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
        DEFAULT_COMMISSION_BPS, DUST_LIMIT_SPARK, MAX_ROUNDS_PER_HEIGHT,
        TRANSACTION_PROTOCOL_VERSION,
    };

    #[test]
    fn protocol_hybrid_pubkey_conversion_and_error_mapping() {
        let keypair = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0x11; 32]),
            PqKeypair::from_seed(&[0x11; 32]).expect("test PQ key"),
        );
        assert!(protocol_hybrid_pubkey(&keypair).is_ok());
        let error = protocol_hybrid_pubkey_parts([0u8; 32], &[0u8; MAX_PQ_SIG_BYTES + 1])
            .expect_err("oversized protocol key must fail");
        assert!(matches!(error, NodeError::ValidatorConfigIncomplete { .. }));
    }
    use indra_core::types::slashing::SlashEvidenceV1;
    use indra_core::types::stake_position::{
        ActiveStakeAggregateV1, PositionCustodyV1, StakePositionV1,
    };
    use indra_core::types::staking::StakingOpBody;
    use indra_core::types::transaction::{InputV1, OutputV1, TransactionV1};
    use indra_core::types::vote::VoteStep;
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
        let mut cold_classical_seed = seed;
        cold_classical_seed[0] ^= 0xA5;
        let mut cold_pq_seed = seed;
        cold_pq_seed[0] ^= 0x5A;
        let cold = indra_crypto::ColdHybridKeypair::from_independent_seeds(
            cold_classical_seed,
            cold_pq_seed,
        )
        .unwrap();
        let cold_public = cold.public_key();
        let cold_public = cold_public.as_complete_hybrid();
        let validator_id =
            indra_core::types::crypto::hybrid_identity_id(&public.classical.0, &public.pq.0);
        let has_custom_test_validator = engine.state.validators.all_validators().any(|validator| {
            validator.name != "local-test-validator"
                && !validator.name.starts_with("test-validator-")
        });
        if engine.state.height == 0
            && !has_custom_test_validator
            && engine
                .state
                .validators
                .get(&engine.validator_id.unwrap_or(Bytes32::ZERO))
                .is_none()
            && engine.state.validators.get(&validator_id).is_none()
        {
            let mut entries = [(seed, seed, seed); 4];
            for (index, entry) in entries.iter_mut().enumerate().skip(1) {
                let mut alternate = seed;
                alternate[0] = alternate[0].wrapping_add(index as u8);
                *entry = (alternate, alternate, alternate);
            }
            let genesis_path = engine
                .config
                .genesis_path
                .clone()
                .expect("local test engine has a genesis path");
            std::fs::write(
                &genesis_path,
                crate::genesis::test_genesis_toml_single_authority(
                    "indra-testnet-1",
                    &entries,
                ),
            )
            .expect("rewrite four-validator test genesis");
            engine.state = crate::genesis::build_finalized_genesis_state(Some(&genesis_path))
                .expect("four-validator test genesis must load");
        }
        let stake_spark = engine
            .state
            .validators
            .get(&validator_id)
            .map(|validator| validator.stake_spark)
            .unwrap_or(1_000_000);
        let validator_name = engine
            .state
            .validators
            .get(&validator_id)
            .map(|validator| validator.name.clone())
            .unwrap_or_else(|| name.to_string());
        let already_registered = engine.state.validators.get(&validator_id).is_some();

        if !already_registered {
            engine
            .state
            .validators
            .upsert(ValidatorEntry {
                validator_id,
                name: validator_name,
                hybrid_classical_pk: Some(public.classical.0),
                hybrid_pq_pk: Some(public.pq.0.to_vec()),
                vrf_pk: Some(vrf_pk),
                vrf_key_activation_epoch: 0,
                pending_vrf_pk: None,
                pending_vrf_activation_epoch: None,
                stake_spark,
                status: ValidatorStatus::Active,
                registered_epoch: 0,
                last_active_epoch: 0,
                slashed_offense_id: None,
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
        }
        if engine.state.height == 0 && !already_registered {
            crate::genesis::finalize_test_genesis(&mut engine.state);
        }
        // Keep the local signing capabilities aligned with the validator that
        // this fixture installs into consensus state. Authorization and VRF
        // eligibility are deliberately independent, but both must refer to
        // the same registered validator identity.
        engine.validator_id = Some(validator_id);
        engine.hybrid_keypair = Some(HybridKeypair::new(
            ClassicalKeypair::from_seed(&seed),
            PqKeypair::from_seed(&seed).unwrap(),
        ));
        engine.reporter_pubkey = engine
            .hybrid_keypair
            .as_ref()
            .map(protocol_hybrid_pubkey)
            .transpose()
            .unwrap();
        engine.vrf_keypair = Some(VrfKeypair::from_seed(&seed));
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
        let genesis_path = dir.join("genesis.toml");
        let genesis = crate::genesis::test_genesis_toml_single_authority(
            "indra-testnet-1",
            &[(seed, seed, seed), ([0xB2; 32], [0xB2; 32], [0xB2; 32]), ([0xC3; 32], [0xC3; 32], [0xC3; 32]), ([0xD4; 32], [0xD4; 32], [0xD4; 32])],
        );
        std::fs::write(&genesis_path, genesis).unwrap();
        genesis_path.to_string_lossy().to_string()
    }

    fn configure_validator_keys(config: &mut NodeConfig, seed: [u8; 32]) {
        let pq = PqKeypair::from_seed(&seed).unwrap();
        config.validator_seed = Some(seed);
        config.vrf_seed = Some(seed);
        config.pq_pk = Some(pq.public_key().0.to_vec());
        config.pq_seed = Some(pq.secret_key_bytes());
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

    fn valid_delegate_op(
        engine: &mut NodeEngine,
        validator_id: Bytes32,
        delegator: &HybridKeypair,
        seed: u8,
    ) -> StakingOp {
        let delegator_pubkey = governance_pubkey_from_keypair(delegator);
        let value = engine
            .state
            .governance
            .params
            .proposal_deposit_spark
            .max(engine.state.governance.params.min_delegation_spark)
            .max(DUST_LIMIT_SPARK);
        let deposit_utxo_id = engine
            .state
            .utxos
            .insert(
                OutputV1 {
                    value_spark: value,
                    owner_pubkey: delegator_pubkey.clone(),
                    lock_height: 0,
                },
                0,
                seed as u32,
                0,
            )
            .unwrap();
        let mut op = StakingOp {
            body: StakingOpBody::Delegate {
                validator_id,
                deposit_utxo_id,
                delegator_pubkey,
            },
            nonce: 1,
            signature: dummy_signature(),
        };
        sign_staking_op(&mut op, delegator, &engine.state.chain_id);
        op
    }

    fn valid_tx_spending(
        engine: &NodeEngine,
        utxo_id: Bytes32,
        owner: &HybridKeypair,
        _input_blinding: [u8; 32],
        _input_tag: u8,
    ) -> TransactionV1 {
        let input = engine.state.utxos.get(&utxo_id).unwrap().output.clone();
        let owner_pubkey = governance_pubkey_from_keypair(owner);
        let fee = engine.state.base_fee.saturating_mul(10);
        let output_value = input.value_spark.checked_sub(fee).unwrap();
        let mut tx = TransactionV1 {
            version: indra_core::ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
            signature_module_id: 1,
            inputs: vec![InputV1 { utxo_id }],
            outputs: vec![OutputV1 {
                value_spark: output_value,
                owner_pubkey: owner_pubkey.clone(),
                lock_height: 0,
            }],
            fee_amount: fee,
            signature: dummy_signature(),
        };
        let signature = owner
            .sign(&tx.signing_bytes(&engine.state.chain_id).unwrap())
            .unwrap();
        tx.signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&signature.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&signature.pq.0).unwrap(),
        };
        tx
    }

    fn cold_keypair_for_seed(seed: [u8; 32]) -> HybridKeypair {
        let mut classical_seed = seed;
        classical_seed[0] ^= 0xA5;
        let mut pq_seed = seed;
        pq_seed[0] ^= 0x5A;
        HybridKeypair::new(
            ClassicalKeypair::from_seed(&classical_seed),
            PqKeypair::from_seed(&pq_seed).unwrap(),
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
        let validator_id = indra_core::types::crypto::hybrid_identity_id(
            &keypair.public_key().classical.0,
            &keypair.public_key().pq.0,
        );
        let mut op = StakingOp {
            body: StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps,
                cold_authorization: indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 1,
                    cold_nonce: nonce,
                },
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
            TEST_CHAIN_ID,
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
            .cold_authorization_signing_bytes(TEST_CHAIN_ID)
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
            owner_pubkey,
            lock_height: 0,
        }
    }

    fn valid_governance_propose_op(
        engine: &mut NodeEngine,
        keypair: &HybridKeypair,
        nonce: u64,
    ) -> GovernanceOpV2 {
        let proposer_pubkey = governance_pubkey_from_keypair(keypair);
        let signer_id = indra_core::types::crypto::hybrid_identity_id(
            &keypair.public_key().classical.0,
            &keypair.public_key().pq.0,
        );
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
        let signer_id = indra_core::types::crypto::hybrid_identity_id(
            &hot_keypair.public_key().classical.0,
            &hot_keypair.public_key().pq.0,
        );
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

    fn signed_slash_evidence(
        engine: &NodeEngine,
        keypair: &HybridKeypair,
        height: u64,
        round_1: u32,
        round_2: u32,
        step_1: VoteStep,
        step_2: VoteStep,
        hash_1: Bytes32,
        hash_2: Bytes32,
    ) -> SlashEvidenceV1 {
        let validator_id = indra_core::types::crypto::hybrid_identity_id(
            &keypair.public_key().classical.0,
            &keypair.public_key().pq.0,
        );
        SlashEvidenceV1 {
            validator_id,
            vote_1: produce_vote(
                height,
                round_1,
                step_1,
                hash_1,
                validator_id,
                Bytes32::ZERO,
                &engine.state.chain_id,
                keypair,
            )
            .unwrap(),
            vote_2: produce_vote(
                height,
                round_2,
                step_2,
                hash_2,
                validator_id,
                Bytes32::ZERO,
                &engine.state.chain_id,
                keypair,
            )
            .unwrap(),
        }
    }

    fn proof_carrying_slash(engine: &NodeEngine, evidence: &SlashEvidenceV1) -> SlashEvidenceV2 {
        let snapshot = engine
            .state
            .snapshot_for_consensus_height(evidence.vote_1.height)
            .unwrap();
        let (position, _) = snapshot
            .entry_with_position(&evidence.validator_id)
            .unwrap();
        SlashEvidenceV2 {
            validator_id: evidence.validator_id,
            vote_1: evidence.vote_1.clone(),
            vote_2: evidence.vote_2.clone(),
            membership_proof: build_slash_membership_proof(snapshot, position).unwrap(),
        }
    }

    fn make_strict_block(
        state: &indra_state::ChainState,
        proposer_seed: [u8; 32],
        prev_qc_bytes: Vec<u8>,
    ) -> indra_core::types::block::BlockProposalVNext {
        let height = state.height + 1;
        let snapshot = state.snapshot_for_consensus_height(height).unwrap();
        let proposer_vrf = VrfKeypair::from_seed(&proposer_seed);
        let candidates = snapshot
            .entries()
            .iter()
            .map(|entry| ProposerCandidate {
                validator_id: entry.validator_id,
                vrf_pubkey: entry.vrf_pk,
                stake: entry.consensus_weight_spark,
            })
            .collect::<Vec<_>>();
        let election = (0..4_096)
            .find_map(|round| {
                let election = indra_consensus::proposer::ProposerElection {
                    chain_id: state.chain_id.as_bytes().to_vec(),
                    election_seed: state.election_seed,
                    snapshot_root: snapshot.snapshot_root,
                    active_slot_coefficient_numerator: state.active_slot_coefficient_numerator,
                    sortition_log: snapshot.sortition_log_interval().unwrap(),
                    height,
                    round,
                    candidates: candidates.clone(),
                };
                let candidate = election
                    .candidates
                    .iter()
                    .find(|candidate| candidate.vrf_pubkey == proposer_vrf.public_key())?;
                compute_proposer_vrf(candidate.validator_id, &proposer_vrf, &election)
                    .ok()?
                    .eligible
                    .then_some(election)
            })
            .expect("test proposer must become eligible within bounded round search");
        let template = BlockTemplate {
            proposer_vrf_keypair: proposer_vrf,
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
        let mut proposal = BlockProposalVNext {
            block,
            proposer_authorization: indra_core::types::crypto::HybridSignature {
                classical_sig: VariableBytes::from_slice(&[]).unwrap(),
                pq_sig: VariableBytes::from_slice(&[]).unwrap(),
            },
        };
        let transcript = proposal.signing_bytes(state.chain_id.as_bytes()).unwrap();
        let signature = signer.sign(&transcript).unwrap();
        proposal.proposer_authorization = indra_core::types::crypto::HybridSignature {
            classical_sig: VariableBytes::from_slice(&signature.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&signature.pq.0).unwrap(),
        };
        proposal
    }

    fn test_election(state: &ChainState, height: u64, round: u32) -> ProposerElection {
        let snapshot = state.snapshot_for_consensus_height(height).unwrap();
        ProposerElection {
            chain_id: state.chain_id.as_bytes().to_vec(),
            election_seed: state.election_seed,
            snapshot_root: snapshot.snapshot_root,
            active_slot_coefficient_numerator: state.active_slot_coefficient_numerator,
            sortition_log: snapshot.sortition_log_interval().unwrap(),
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
        }
    }

    fn first_eligible_test_election(
        state: &ChainState,
        height: u64,
        vrf: &VrfKeypair,
    ) -> ProposerElection {
        (0..MAX_ROUNDS_PER_HEIGHT)
            .find_map(|round| {
                let election = test_election(state, height, round);
                let candidate = election
                    .candidates
                    .iter()
                    .find(|candidate| candidate.vrf_pubkey == vrf.public_key())?;
                compute_proposer_vrf(candidate.validator_id, vrf, &election)
                    .ok()?
                    .eligible
                    .then_some(election)
            })
            .expect("test proposer must become eligible within bounded round search")
    }

    fn apply_verified_test(
        state: &mut ChainState,
        proposal: &BlockProposalVNext,
        timestamp_secs: u64,
    ) {
        let snapshot = state
            .snapshot_for_consensus_height(proposal.header.height)
            .unwrap();
        let verified = indra_core::types::proposal::verify_proposal(
            proposal,
            state.chain_id.as_bytes(),
            &state.election_seed,
            snapshot,
        )
        .unwrap();
        indra_state::apply_block(state, &verified, timestamp_secs).unwrap();
    }

    fn build_single_validator_qc_bytes(
        height: u64,
        round: u32,
        value_hash: Bytes32,
        classical_seed: [u8; 32],
        pq_seed: [u8; 32],
        snapshot_root: Bytes32,
    ) -> Vec<u8> {
        let seeds = [classical_seed, [0xB2; 32], [0xC3; 32], [0xD4; 32]];
        let mut validators = seeds
            .iter()
            .enumerate()
            .map(|(index, seed)| {
                let classical = ClassicalKeypair::from_seed(seed);
                let pq = if index == 0 {
                    PqKeypair::from_seed(&pq_seed).unwrap()
                } else {
                    PqKeypair::from_seed(seed).unwrap()
                };
                let public = HybridKeypair::new(classical, pq).public_key();
                let validator_id = indra_core::types::crypto::hybrid_identity_id(
                    &public.classical.0,
                    &public.pq.0,
                );
                let signer = HybridKeypair::new(
                    ClassicalKeypair::from_seed(seed),
                    if index == 0 {
                        PqKeypair::from_seed(&pq_seed).unwrap()
                    } else {
                        PqKeypair::from_seed(seed).unwrap()
                    },
                );
                (validator_id, public, signer, index)
            })
            .collect::<Vec<_>>();
        validators.sort_by_key(|(id, _, _, _)| id.0);
        let votes = validators
            .iter()
            .map(|(validator_id, _, signer, _)| {
                produce_vote(
                    height,
                    round,
                    VoteStep::Precommit,
                    value_hash,
                    *validator_id,
                    snapshot_root,
                    &TEST_CHAIN_ID,
                    signer,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let qc_validators = validators
            .iter()
            .enumerate()
            .map(|(position, (validator_id, public, _, index))| QcValidator {
                validator_id: *validator_id,
                position,
                pq_pk: public.pq.0.to_vec(),
                classical_pk: public.classical.0,
                stake: if *index == 0 { 1_000_000_000_000 } else { DUST_LIMIT_SPARK },
            })
            .collect::<Vec<_>>();
        let qc = build_qc(
            height,
            round,
            value_hash,
            TEST_CHAIN_ID,
            snapshot_root,
            &qc_validators,
            votes.iter().collect(),
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
        let signer = install_active_validator(&mut engine, [0x42; 32], "replay-voter");
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
                        snapshot.snapshot_root,
                        TEST_CHAIN_ID,
                        &signer,
                    )
                    .unwrap();
                    let mut collector = indra_consensus::vote::VoteCollector::new(
                        height,
                        0,
                        VoteStep::Prevote,
                        TEST_CHAIN_ID.to_string(),
                        snapshot.snapshot_root,
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
                let validator_id = indra_core::types::crypto::hybrid_identity_id(
                    &signer.public_key().classical.0,
                    &signer.public_key().pq.0,
                );
                produce_vote(
                    height,
                    0,
                    VoteStep::Precommit,
                    block_hash,
                    validator_id,
                    snapshot.snapshot_root,
                    TEST_CHAIN_ID,
                    signer,
                )
                .unwrap()
            })
            .collect();
        build_qc(
            height,
            0,
            block_hash,
            TEST_CHAIN_ID,
            snapshot.snapshot_root,
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
        let a = install_active_validator(&mut engine, [0x42; 32], "a");
        let b = install_active_validator(&mut engine, [0x52; 32], "b");
        let c = install_active_validator(&mut engine, [0x62; 32], "c");
        let d = install_active_validator(&mut engine, [0x72; 32], "d");
        let a_id = indra_core::types::crypto::hybrid_identity_id(
            &a.public_key().classical.0,
            &a.public_key().pq.0,
        );
        let b_id = indra_core::types::crypto::hybrid_identity_id(
            &b.public_key().classical.0,
            &b.public_key().pq.0,
        );
        let c_id = indra_core::types::crypto::hybrid_identity_id(
            &c.public_key().classical.0,
            &c.public_key().pq.0,
        );
        engine.state.validators.get_mut(&a_id).unwrap().stake_spark = 40;
        engine.state.validators.get_mut(&b_id).unwrap().stake_spark = 30;
        engine.state.validators.get_mut(&c_id).unwrap().stake_spark = 30;
        let d_id = indra_core::types::crypto::hybrid_identity_id(&d.public_key().classical.0, &d.public_key().pq.0);
        engine.state.validators.get_mut(&d_id).unwrap().stake_spark = 1;
        let snapshot = engine.state.build_genesis_consensus_snapshot().unwrap();
        let block_hash = Bytes32::from([0xA1; 32]);
        let qc = qc_from_test_signers(1, block_hash, &snapshot, &[&a, &b]);

        // Block H commits C's SelfStake after A+B formed the genuine QC for H.
        engine.state.validators.get_mut(&c_id).unwrap().stake_spark = 140;
        assert!(verify_qc_strict(
            &qc,
            &engine.qc_validators(),
            engine.state.validators.total_active_stake(),
            TEST_CHAIN_ID,
        )
        .is_err());
        assert!(NodeEngine::verify_qc_with_snapshot(&qc, &snapshot, TEST_CHAIN_ID).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn post_block_inflation_cannot_turn_single_signer_into_snapshot_quorum() {
        let dir = temp_dir("qc_safety_attack_reproduction");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let a = install_active_validator(&mut engine, [0x42; 32], "a");
        let b = install_active_validator(&mut engine, [0x52; 32], "b");
        let c = install_active_validator(&mut engine, [0x62; 32], "c");
        let d = install_active_validator(&mut engine, [0x72; 32], "d");
        let a_id = indra_core::types::crypto::hybrid_identity_id(
            &a.public_key().classical.0,
            &a.public_key().pq.0,
        );
        let b_id = indra_core::types::crypto::hybrid_identity_id(
            &b.public_key().classical.0,
            &b.public_key().pq.0,
        );
        let c_id = indra_core::types::crypto::hybrid_identity_id(
            &c.public_key().classical.0,
            &c.public_key().pq.0,
        );
        engine.state.validators.get_mut(&a_id).unwrap().stake_spark = 20;
        engine.state.validators.get_mut(&b_id).unwrap().stake_spark = 40;
        engine.state.validators.get_mut(&c_id).unwrap().stake_spark = 40;
        let d_id = indra_core::types::crypto::hybrid_identity_id(&d.public_key().classical.0, &d.public_key().pq.0);
        engine.state.validators.get_mut(&d_id).unwrap().stake_spark = 1;
        let snapshot = engine.state.build_genesis_consensus_snapshot().unwrap();
        let qc = qc_from_test_signers(1, Bytes32::from([0xA2; 32]), &snapshot, &[&a]);

        engine.state.validators.get_mut(&a_id).unwrap().stake_spark = 200;
        assert!(verify_qc_strict(
            &qc,
            &engine.qc_validators(),
            engine.state.validators.total_active_stake(),
            TEST_CHAIN_ID,
        )
        .is_ok());
        assert!(NodeEngine::verify_qc_with_snapshot(&qc, &snapshot, TEST_CHAIN_ID).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vote_collection_qc_construction_and_verification_share_one_snapshot() {
        let dir = temp_dir("qc_vote_snapshot_consistency");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let a = install_active_validator(&mut engine, [0x42; 32], "a");
        let b = install_active_validator(&mut engine, [0x52; 32], "b");
        let c = install_active_validator(&mut engine, [0x62; 32], "c");
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
        let qc = qc_from_test_signers(1, Bytes32::from([0xA3; 32]), &snapshot, &[&a, &b, &c]);
        assert!(NodeEngine::verify_qc_with_snapshot(&qc, &snapshot, TEST_CHAIN_ID).is_ok());
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
        let a = install_active_validator(&mut engine, [0x42; 32], "boundary-a");
        let b = install_active_validator(&mut engine, [0x52; 32], "boundary-b");
        let c = install_active_validator(&mut engine, [0x62; 32], "boundary-c");
        let old_snapshot = engine.state.build_genesis_consensus_snapshot().unwrap();
        let id = old_snapshot.entries()[0].validator_id;
        engine.state.validators.get_mut(&id).unwrap().stake_spark += 500;
        let new_snapshot = engine.state.build_consensus_snapshot(301, 300).unwrap();

        let replay = || {
            let qc300 =
                qc_from_test_signers(300, Bytes32::from([0x30; 32]), &old_snapshot, &[&a, &b, &c]);
            let qc301 =
                qc_from_test_signers(301, Bytes32::from([0x31; 32]), &new_snapshot, &[&a, &b, &c]);
            NodeEngine::verify_qc_with_snapshot(&qc300, &old_snapshot, TEST_CHAIN_ID).unwrap();
            NodeEngine::verify_qc_with_snapshot(&qc301, &new_snapshot, TEST_CHAIN_ID).unwrap();
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
        let keypair = install_active_validator(&mut engine, [0xA1; 32], "slash-dedupe");
        let evidence = signed_slash_evidence(
            &engine,
            &keypair,
            1,
            0,
            0,
            VoteStep::Precommit,
            VoteStep::Precommit,
            Bytes32::from([0xA1; 32]),
            Bytes32::from([0xA2; 32]),
        );
        engine.add_slash_evidence(evidence.clone()).unwrap();
        engine.add_slash_evidence(evidence).unwrap();
        assert_eq!(engine.pending_slashes.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn slash_admission_rejects_each_signed_shape_violation() {
        let dir = temp_dir("slash_shape_admission");
        let mut engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let keypair = install_active_validator(&mut engine, [0xA2; 32], "slash-shape");
        let cases = [
            (
                signed_slash_evidence(
                    &engine,
                    &keypair,
                    1,
                    0,
                    1,
                    VoteStep::Precommit,
                    VoteStep::Precommit,
                    Bytes32::from([1; 32]),
                    Bytes32::from([2; 32]),
                ),
                "same height and round",
            ),
            (
                signed_slash_evidence(
                    &engine,
                    &keypair,
                    1,
                    0,
                    0,
                    VoteStep::Prevote,
                    VoteStep::Precommit,
                    Bytes32::from([3; 32]),
                    Bytes32::from([4; 32]),
                ),
                "must both be precommits or both be prevotes",
            ),
            (
                signed_slash_evidence(
                    &engine,
                    &keypair,
                    1,
                    0,
                    0,
                    VoteStep::Precommit,
                    VoteStep::Precommit,
                    Bytes32::from([5; 32]),
                    Bytes32::from([5; 32]),
                ),
                "same block hash",
            ),
            (
                signed_slash_evidence(
                    &engine,
                    &keypair,
                    1,
                    0,
                    0,
                    VoteStep::Precommit,
                    VoteStep::Precommit,
                    Bytes32::ZERO,
                    Bytes32::from([6; 32]),
                ),
                "nil vote",
            ),
        ];
        for (evidence, expected) in cases {
            let error = engine.add_slash_evidence(evidence).unwrap_err().to_string();
            assert!(error.contains(expected), "unexpected error: {error}");
        }

        let mut bad_signature = signed_slash_evidence(
            &engine,
            &keypair,
            1,
            0,
            0,
            VoteStep::Precommit,
            VoteStep::Precommit,
            Bytes32::from([7; 32]),
            Bytes32::from([8; 32]),
        );
        bad_signature.vote_1.signature = dummy_signature();
        let error = engine
            .add_slash_evidence(bad_signature)
            .unwrap_err()
            .to_string();
        assert!(error.contains("vote_1 signature invalid"));
        assert!(engine.pending_slashes.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn slash_pool_capacity_is_enforced() {
        let dir = temp_dir("slash_pool_capacity");
        let mut engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let keypair = install_active_validator(&mut engine, [0xA3; 32], "slash-cap");
        let evidence = signed_slash_evidence(
            &engine,
            &keypair,
            1,
            0,
            0,
            VoteStep::Precommit,
            VoteStep::Precommit,
            Bytes32::from([9; 32]),
            Bytes32::from([10; 32]),
        );
        let template = proof_carrying_slash(&engine, &evidence);
        engine.pending_slashes = (0..MAX_PENDING_SLASH_EVIDENCE)
            .map(|index| {
                let mut pending = template.clone();
                let mut id = [0u8; 32];
                id[..8].copy_from_slice(&(index as u64).to_le_bytes());
                pending.validator_id = Bytes32::from(id);
                pending.vote_1.validator_id = pending.validator_id;
                pending.vote_2.validator_id = pending.validator_id;
                pending
            })
            .collect();
        let error = engine.add_slash_evidence(evidence).unwrap_err().to_string();
        assert!(error.contains("slash evidence pool full"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_validator_double_slash_selects_one_and_prunes_the_rest() {
        let dir = temp_dir("slash_same_validator_conflict");
        let mut engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let keypair = install_active_validator(&mut engine, [0xA4; 32], "slash-conflict");
        let first = signed_slash_evidence(
            &engine,
            &keypair,
            1,
            0,
            0,
            VoteStep::Precommit,
            VoteStep::Precommit,
            Bytes32::from([0x11; 32]),
            Bytes32::from([0x12; 32]),
        );
        let second = signed_slash_evidence(
            &engine,
            &keypair,
            1,
            1,
            1,
            VoteStep::Precommit,
            VoteStep::Precommit,
            Bytes32::from([0x13; 32]),
            Bytes32::from([0x14; 32]),
        );
        engine.pending_slashes = vec![
            proof_carrying_slash(&engine, &first),
            proof_carrying_slash(&engine, &second),
        ];

        let selected = engine.select_block_contents().unwrap().slash_evidence;
        assert_eq!(selected.len(), 1);
        assert_eq!(engine.pending_slashes.len(), 1);
        engine.evict_committed_slashes(&selected);
        assert!(engine.pending_slashes.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stored_v2_slash_survives_consensus_snapshot_retention_expiry() {
        let dir = temp_dir("slash_v2_outlives_snapshot");
        let mut engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let keypair = install_active_validator(&mut engine, [0xA5; 32], "slash-v2");
        let evidence = signed_slash_evidence(
            &engine,
            &keypair,
            1,
            0,
            0,
            VoteStep::Precommit,
            VoteStep::Precommit,
            Bytes32::from([0x21; 32]),
            Bytes32::from([0x22; 32]),
        );
        engine.add_slash_evidence(evidence).unwrap();
        assert_eq!(engine.pending_slashes.len(), 1);

        engine.state.consensus_snapshots.clear();
        let selected = engine.select_block_contents().unwrap().slash_evidence;
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], engine.pending_slashes[0]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn targeted_mixed_pool_invalidation_matches_full_authoritative_oracle() {
        let dir = temp_dir("targeted_mixed_pool_differential");
        let mut engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();

        let staking_hot = install_active_validator(&mut engine, [0xB1; 32], "diff-staking");
        let staking_cold = cold_keypair_for_seed([0xB1; 32]);
        let staking =
            valid_set_commission_staking_op(&engine, &staking_hot, &staking_cold, 1, 1_100);
        engine.add_staking_op(staking).unwrap();

        let governance_hot = install_active_validator(&mut engine, [0xB2; 32], "diff-governance");
        let governance_cold = cold_keypair_for_seed([0xB2; 32]);
        let governance =
            valid_cold_governance_propose_op(&mut engine, &governance_hot, &governance_cold, 1);
        let governance_deposit = match &governance.payload {
            GovernancePayload::Propose {
                deposit_utxo_id, ..
            } => *deposit_utxo_id,
            _ => unreachable!(),
        };
        engine.add_governance_op(governance).unwrap();

        let slash_key = install_active_validator(&mut engine, [0xB3; 32], "diff-slash");
        let slash_id = indra_core::types::crypto::hybrid_identity_id(
            &slash_key.public_key().classical.0,
            &slash_key.public_key().pq.0,
        );
        let slash = signed_slash_evidence(
            &engine,
            &slash_key,
            1,
            0,
            0,
            VoteStep::Precommit,
            VoteStep::Precommit,
            Bytes32::from([0x31; 32]),
            Bytes32::from([0x32; 32]),
        );
        engine.add_slash_evidence(slash).unwrap();

        let staking_id = indra_core::types::crypto::hybrid_identity_id(
            &staking_hot.public_key().classical.0,
            &staking_hot.public_key().pq.0,
        );
        engine
            .state
            .validators
            .get_mut(&staking_id)
            .unwrap()
            .cold_nonce = 1;
        engine.state.validators.get_mut(&slash_id).unwrap().status =
            indra_state::ValidatorStatus::Slashed;
        engine
            .state
            .utxos
            .spend_at_height(&governance_deposit, 1)
            .unwrap();

        let height = engine.state.height.saturating_add(1);
        let epoch = epoch_for_height(height);
        let oracle_staking: Vec<_> = engine
            .staking_mempool
            .iter()
            .filter(|op| {
                let mut scratch = engine.state.clone();
                indra_state::try_apply_staking_candidate(&mut scratch, op, height).is_ok()
            })
            .map(indra_state::pending::staking_op_id)
            .collect();
        let oracle_governance: Vec<_> = engine
            .governance_mempool
            .iter()
            .filter(|op| {
                let mut scratch = engine.state.clone();
                try_apply_governance_candidate(&mut scratch, op, epoch, height).is_ok()
            })
            .map(indra_state::pending::governance_op_id)
            .collect();
        let oracle_slashes: Vec<_> = engine
            .pending_slashes
            .iter()
            .filter(|evidence| {
                let mut scratch = engine.state.clone();
                try_apply_slash_candidate(&mut scratch, evidence, height, None).is_ok()
            })
            .map(compute_slash_evidence_v2_hash)
            .collect();

        let mut effects = indra_state::CanonicalStateEffects::default();
        effects.validators_changed.extend([staking_id, slash_id]);
        effects.spent_utxos.insert(governance_deposit);
        engine.apply_pending_canonical_effects(&effects);

        assert_eq!(
            engine
                .staking_mempool
                .iter()
                .map(indra_state::pending::staking_op_id)
                .collect::<Vec<_>>(),
            oracle_staking
        );
        assert_eq!(
            engine
                .governance_mempool
                .iter()
                .map(indra_state::pending::governance_op_id)
                .collect::<Vec<_>>(),
            oracle_governance
        );
        assert_eq!(
            engine
                .pending_slashes
                .iter()
                .map(compute_slash_evidence_v2_hash)
                .collect::<Vec<_>>(),
            oracle_slashes
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dependency_indexes_rebuild_cleanly_when_next_height_crosses_epoch() {
        let dir = temp_dir("dependency_index_epoch_rebuild");
        let mut engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        engine.staking_mempool.push(dummy_staking_op(0xD0, 1));
        engine.ensure_pending_indexes();
        let before = engine.pending_dependency_epoch;

        engine.state.height = indra_core::types::primitives::EPOCH_DURATION_BLOCKS - 1;
        engine.ensure_pending_indexes();

        assert_ne!(engine.pending_dependency_epoch, before);
        assert_eq!(
            engine.pending_dependency_epoch,
            epoch_for_height(engine.state.height.saturating_add(1))
        );
        engine.debug_assert_pending_indexes();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore = "release-mode Task 1b performance measurement; run explicitly with --release --ignored --nocapture"]
    fn targeted_invalidation_real_hardware_measurement() {
        use std::time::Instant;

        let dir = temp_dir("targeted_invalidation_benchmark");
        let mut engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();

        let transaction_owner = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0xC1; 32]),
            PqKeypair::from_seed(&[0xC1; 32]).unwrap(),
        );
        let transaction_owner_pubkey = governance_pubkey_from_keypair(&transaction_owner);
        let transaction_utxo = engine
            .state
            .utxos
            .insert(
                governance_deposit_output(transaction_owner_pubkey, 10_000_000_000),
                0,
                77,
                0,
            )
            .unwrap();
        let transaction =
            valid_tx_spending(&engine, transaction_utxo, &transaction_owner, [0; 32], 0xC1);
        let verified_transaction = indra_state::pending::verify_pending_transaction(
            &engine.state,
            &transaction,
            Mempool::tx_id(&transaction),
            engine.state.height.saturating_add(1),
        )
        .unwrap();
        let started = Instant::now();
        for _ in 0..5_000 {
            indra_state::pending::validate_verified_pending_transaction(
                &engine.state,
                &transaction,
                &verified_transaction,
                engine.state.height.saturating_add(1),
            )
            .unwrap();
        }
        let transaction_5k = started.elapsed();

        engine.mempool.clear();
        let input_output = engine
            .state
            .utxos
            .get(&transaction_utxo)
            .unwrap()
            .output
            .clone();
        for index in 0..5_000u32 {
            let utxo_id = engine
                .state
                .utxos
                .insert(input_output.clone(), 0, 10_000 + index, 0)
                .unwrap();
            let mut pending = transaction.clone();
            pending.inputs[0].utxo_id = utxo_id;
            let signature = transaction_owner
                .sign(&pending.signing_bytes(&engine.state.chain_id).unwrap())
                .unwrap();
            pending.signature = HybridSignature {
                classical_sig: VariableBytes::from_slice(&signature.classical.0).unwrap(),
                pq_sig: VariableBytes::from_slice(&signature.pq.0).unwrap(),
            };
            engine
                .mempool
                .submit_validated(pending, &engine.state)
                .unwrap();
        }
        let full_cycle_started = Instant::now();
        engine.mempool.apply_canonical_effects(
            &engine.state,
            &indra_state::CanonicalStateEffects {
                base_fee_changed: true,
                ..Default::default()
            },
        ).unwrap();
        let transaction_full_pool_cycle = full_cycle_started.elapsed();
        assert_eq!(engine.mempool.len(), 5_000);

        let staking_hot = install_active_validator(&mut engine, [0xC2; 32], "bench-staking");
        let staking_cold = cold_keypair_for_seed([0xC2; 32]);
        let staking =
            valid_set_commission_staking_op(&engine, &staking_hot, &staking_cold, 1, 1_100);
        let verified_staking = indra_state::pending::verify_pending_staking(
            &engine.state,
            &staking,
            engine.state.height.saturating_add(1),
        )
        .unwrap();
        assert!(indra_state::pending::staking_authority_unchanged(
            &engine.state,
            &staking,
            &verified_staking
        ));
        let started = Instant::now();
        for _ in 0..5_000 {
            let mut scratch = engine.state.clone();
            indra_state::try_apply_verified_staking_candidate(
                &mut scratch,
                &staking,
                &verified_staking,
                engine.state.height.saturating_add(1),
            )
            .unwrap();
        }
        let staking_5k_revalidation = started.elapsed();

        let started = Instant::now();
        for _ in 0..5_000 {
            std::hint::black_box(engine.state.clone());
        }
        let staking_5k_clone_only = started.elapsed();

        let started = Instant::now();
        for _ in 0..5_000 {
            let mut scratch = engine.state.clone();
            indra_state::try_apply_staking_candidate(
                &mut scratch,
                &staking,
                engine.state.height.saturating_add(1),
            )
            .unwrap();
        }
        let staking_5k_old_full_oracle = started.elapsed();

        let footprint_started = Instant::now();
        for _ in 0..5_000 {
            std::hint::black_box(staking_footprint(
                &engine.state,
                &staking,
                epoch_for_height(engine.state.height.saturating_add(1)),
            ));
        }
        let staking_5k_footprints = footprint_started.elapsed();

        for nonce in 2..5_001u64 {
            let pending = dummy_staking_op(0xD1, nonce);
            let id = indra_state::pending::staking_op_id(&pending);
            let footprint = staking_footprint(
                &engine.state,
                &pending,
                epoch_for_height(engine.state.height.saturating_add(1)),
            );
            engine.staking_mempool.push(pending);
            engine.staking_dependency_index.insert(id, footprint);
        }
        let admission_started = Instant::now();
        engine.add_staking_op(staking).unwrap();
        let staking_full_pool_admission = admission_started.elapsed();
        assert_eq!(engine.staking_mempool.len(), 5_000);

        let governance_hot = install_active_validator(&mut engine, [0xC3; 32], "bench-governance");
        let governance_cold = cold_keypair_for_seed([0xC3; 32]);
        let governance =
            valid_cold_governance_propose_op(&mut engine, &governance_hot, &governance_cold, 1);
        let height = engine.state.height.saturating_add(1);
        let epoch = epoch_for_height(height);
        let verified_governance = indra_state::pending::verify_pending_governance(
            &engine.state,
            &governance,
            epoch,
            height,
        )
        .unwrap();
        let started = Instant::now();
        for _ in 0..2_400 {
            let mut scratch = engine.state.clone();
            indra_state::try_apply_verified_governance_candidate(
                &mut scratch,
                &governance,
                &verified_governance,
                epoch,
                height,
            )
            .unwrap();
        }
        let governance_2400 = started.elapsed();
        assert!(indra_state::pending::governance_authority_unchanged(
            &engine.state,
            &governance,
            &verified_governance
        ));

        // End-to-end governance measurement: populate the production pool via
        // normal admission with 2,400 independently signed, canonically valid
        // delegator redelegations, then make one real dependency family dirty.
        let governance_dir = temp_dir("targeted_governance_full_pool_benchmark");
        let mut governance_config = NodeConfig::local_test(governance_dir.clone());
        governance_config.governance_mempool_capacity = 2_400;
        let mut governance_engine = NodeEngine::init(governance_config).unwrap();
        let proposer = install_active_validator(
            &mut governance_engine,
            [0xC5; 32],
            "bench-governance-proposer",
        );
        let proposer_cold = cold_keypair_for_seed([0xC5; 32]);
        let proposal =
            valid_cold_governance_propose_op(&mut governance_engine, &proposer, &proposer_cold, 1);
        let proposal_id = if let GovernancePayload::Propose { action, .. } = &proposal.payload {
            indra_core::types::governance::compute_proposal_id(
                proposal.signer_id,
                action,
                0,
                &governance_engine.state.chain_id,
            )
        } else {
            unreachable!()
        };
        try_apply_governance_candidate(
            &mut governance_engine.state,
            &proposal,
            epoch_for_height(1),
            1,
        )
        .unwrap();
        let from =
            install_active_validator(&mut governance_engine, [0xC6; 32], "bench-governance-from");
        let to =
            install_active_validator(&mut governance_engine, [0xC7; 32], "bench-governance-to");
        let from_id = indra_core::types::crypto::hybrid_identity_id(
            &from.public_key().classical.0,
            &from.public_key().pq.0,
        );
        let to_id = indra_core::types::crypto::hybrid_identity_id(
            &to.public_key().classical.0,
            &to.public_key().pq.0,
        );
        let record = governance_engine
            .state
            .governance
            .proposals
            .get_mut(&proposal_id)
            .unwrap();
        record.phase = indra_state::governance::ProposalPhase::Reveal;
        record.reveals.insert(
            from_id,
            indra_state::governance::VoteReveal {
                validator_id: from_id,
                vote: true,
                revealed_epoch: 0,
            },
        );
        record.reveals.insert(
            to_id,
            indra_state::governance::VoteReveal {
                validator_id: to_id,
                vote: true,
                revealed_epoch: 0,
            },
        );
        for index in 0..2_400u32 {
            let mut seed = [0xC8; 32];
            seed[..4].copy_from_slice(&index.to_le_bytes());
            let keypair = HybridKeypair::new(
                ClassicalKeypair::from_seed(&seed),
                PqKeypair::from_seed(&seed).unwrap(),
            );
            let pubkey = governance_pubkey_from_keypair(&keypair);
            let signer_id = pubkey.identity_id();
            governance_engine
                .state
                .delegator_identities
                .insert(signer_id, pubkey);
            let position = StakePositionV1::new(
                from_id,
                signer_id,
                PositionCustodyV1::DelegatorIdentity {
                    delegator_id: signer_id,
                },
                Some(ActiveStakeAggregateV1::new(1_000_000, 0, 0).unwrap()),
                1,
                0,
            )
            .unwrap();
            governance_engine
                .state
                .stake_positions
                .insert(position.position_id, position);
            let mut op = GovernanceOpV2 {
                action_type: GovernanceActionType::GovernanceRedelegate,
                signer_id,
                nonce: 1,
                payload: GovernancePayload::Redelegate {
                    proposal_id,
                    from_validator: from_id,
                    to_validator: to_id,
                    amount_spark: 1,
                },
                signature: dummy_signature(),
            };
            sign_governance_op(&mut op, &keypair);
            governance_engine.add_governance_op(op).unwrap();
        }
        assert_eq!(governance_engine.governance_mempool.len(), 2_400);
        let governance_pool_started = Instant::now();
        governance_engine.apply_pending_canonical_effects(&indra_state::CanonicalStateEffects {
            governance_params_changed: true,
            ..Default::default()
        });
        let governance_full_pool_cycle = governance_pool_started.elapsed();
        assert_eq!(governance_engine.governance_mempool.len(), 2_400);

        let slash_key = install_active_validator(&mut engine, [0xC4; 32], "bench-slash");
        let slash = signed_slash_evidence(
            &engine,
            &slash_key,
            1,
            0,
            0,
            VoteStep::Precommit,
            VoteStep::Precommit,
            Bytes32::from([0x41; 32]),
            Bytes32::from([0x42; 32]),
        );
        let slash = proof_carrying_slash(&engine, &slash);
        let started = Instant::now();
        for _ in 0..1_024 {
            let mut scratch = engine.state.clone();
            let verified = indra_state::verify_slash_candidate(&scratch, &slash, height).unwrap();
            indra_state::try_apply_verified_slash_candidate(
                &mut scratch,
                &slash,
                &verified,
                height,
                None,
            )
            .unwrap();
        }
        let slash_1024 = started.elapsed();

        // A production-admissible slash pool is bounded by proof-bearing
        // validator membership, not merely the 1,024 memory cap. Populate one
        // full mature-network snapshot (200 distinct validators) through the
        // real V1 admission path and time end-to-end targeted revalidation.
        let slash_dir = temp_dir("targeted_slash_reachable_pool_benchmark");
        let mut slash_engine = NodeEngine::init(NodeConfig::local_test(slash_dir.clone())).unwrap();
        let mut slash_keys = Vec::new();
        for index in 0..200u32 {
            let mut seed = [0xD0; 32];
            seed[..4].copy_from_slice(&index.to_le_bytes());
            let keypair =
                install_active_validator(&mut slash_engine, seed, &format!("bench-slash-{index}"));
            let validator_id = indra_core::types::crypto::hybrid_identity_id(
                &keypair.public_key().classical.0,
                &keypair.public_key().pq.0,
            );
            slash_engine
                .state
                .validators
                .get_mut(&validator_id)
                .unwrap()
                .stake_spark = 250_000_000_000;
            slash_keys.push(keypair);
        }
        slash_engine.state.consensus_snapshots.clear();
        slash_engine.state.reward_economic_snapshot = None;
        slash_engine.state.slash_membership_roots.clear();
        crate::genesis::finalize_test_genesis(&mut slash_engine.state);
        assert_eq!(
            slash_engine
                .state
                .snapshot_for_consensus_height(1)
                .unwrap()
                .entries()
                .len(),
            200
        );
        for (index, keypair) in slash_keys.iter().enumerate() {
            let mut left = [0u8; 32];
            left[..8].copy_from_slice(&(index as u64).to_le_bytes());
            left[31] = 0xE1;
            let mut right = left;
            right[31] = 0xE2;
            let evidence = signed_slash_evidence(
                &slash_engine,
                keypair,
                1,
                0,
                0,
                VoteStep::Precommit,
                VoteStep::Precommit,
                Bytes32::from(left),
                Bytes32::from(right),
            );
            slash_engine.add_slash_evidence(evidence).unwrap();
        }
        assert_eq!(slash_engine.pending_slashes.len(), 200);
        let slash_pool_started = Instant::now();
        slash_engine.apply_pending_canonical_effects(&indra_state::CanonicalStateEffects {
            epoch_changed: true,
            ..Default::default()
        });
        let slash_reachable_full_pool_cycle = slash_pool_started.elapsed();
        assert_eq!(slash_engine.pending_slashes.len(), 200);

        println!(
            "task1b benchmark: tx_state_only_5000={transaction_5k:?} tx_full_pool_cycle_5000={transaction_full_pool_cycle:?} staking_state_only_5000={staking_5k_revalidation:?} staking_clone_only_5000={staking_5k_clone_only:?} staking_old_full_oracle_same_fixture_5000={staking_5k_old_full_oracle:?} staking_footprints_5000={staking_5k_footprints:?} staking_admission_at_4999={staking_full_pool_admission:?} governance_state_only_2400={governance_2400:?} governance_full_pool_cycle_2400={governance_full_pool_cycle:?} slash_state_only_synthetic_1024={slash_1024:?} slash_full_reachable_pool_cycle_200={slash_reachable_full_pool_cycle:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&governance_dir);
        let _ = std::fs::remove_dir_all(&slash_dir);
    }

    #[test]
    fn add_slash_rejects_v2_hash_already_applied() {
        let dir = temp_dir("slash_applied");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        let keypair = install_active_validator(&mut engine, [0xA5; 32], "slash-applied");
        let evidence = signed_slash_evidence(
            &engine,
            &keypair,
            1,
            0,
            0,
            VoteStep::Precommit,
            VoteStep::Precommit,
            Bytes32::from([0xA4; 32]),
            Bytes32::from([0xA5; 32]),
        );
        let snapshot = engine.state.snapshot_for_consensus_height(1).unwrap();
        let (position, _) = snapshot
            .entry_with_position(&evidence.validator_id)
            .unwrap();
        let proof = build_slash_membership_proof(snapshot, position).unwrap();
        let v2 = SlashEvidenceV2 {
            validator_id: evidence.validator_id,
            vote_1: evidence.vote_1.clone(),
            vote_2: evidence.vote_2.clone(),
            membership_proof: proof,
        };
        engine
            .state
            .validators
            .get_mut(&v2.validator_id)
            .unwrap()
            .slashed_offense_id = Some(compute_slash_evidence_v2_hash(&v2));
        assert!(matches!(
            engine.add_slash_evidence(evidence),
            Err(NodeError::State(
                indra_state::StateError::SlashAlreadyApplied
            ))
        ));
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
        config.pq_seed = None;
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

        engine.commit_proposal(&block).unwrap();
        assert_eq!(engine.height(), 1);
        let manifest = indra_storage::load_chain_manifest(&dir)
            .unwrap()
            .expect("commit should write manifest");
        assert_eq!(manifest.committed_height, 1);
        assert_eq!(manifest.committed_block_hash, engine.state.tip_hash);
        assert_eq!(
            manifest.state_root,
            indra_state::compute_state_root(&engine.state).unwrap()
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
        configure_validator_keys(&mut config, [0x42u8; 32]);
        let mut engine = NodeEngine::init(config.clone()).unwrap();
        let mut last_qc = Vec::new();

        for height in 1..=3u64 {
            let block = make_strict_block(&engine.state, [0x42u8; 32], last_qc.clone());
            engine.commit_proposal(&block).unwrap();
            last_qc = build_single_validator_qc_bytes(
                height,
                block.header.proposer_round,
                block.header.block_hash(),
                [0x42u8; 32],
                [0x42u8; 32],
                engine
                    .state
                    .snapshot_for_consensus_height(height)
                    .unwrap()
                    .snapshot_root,
            );
            assert_eq!(engine.state.height, height);
        }

        let restarted = NodeEngine::init(config).unwrap();
        assert_eq!(restarted.state.height, 3);
        assert_eq!(restarted.state.tip_hash, engine.state.tip_hash);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn literal_height_zero_replay_is_byte_identical_to_continuous_state() {
        use indra_core::codec::Encode;

        let dir = temp_dir("literal_genesis_replay_identity");
        let mut config = NodeConfig::local_test(dir.clone());
        config.genesis_path = Some(write_single_validator_genesis(&dir, [0x42; 32]));
        configure_validator_keys(&mut config, [0x42; 32]);
        config.snapshot_interval = 10_000;

        let continuous = {
            let mut engine = NodeEngine::init(config.clone()).unwrap();
            let mut last_qc = Vec::new();
            for height in 1..=3 {
                let block = make_strict_block(&engine.state, [0x42; 32], last_qc.clone());
                engine.commit_proposal(&block).unwrap();
                last_qc = build_single_validator_qc_bytes(
                    height,
                    block.header.proposer_round,
                    block.header.block_hash(),
                    [0x42; 32],
                    [0x42; 32],
                    engine
                        .state
                        .snapshot_for_consensus_height(height)
                        .unwrap()
                        .snapshot_root,
                );
            }
            engine.state.clone()
        };

        // Remove the snapshot explicitly and point the durable manifest back
        // at height zero. The retained canonical envelope log is then the only
        // source from which startup can reconstruct heights 1..=3.
        let mut manifest = indra_storage::load_chain_manifest(&dir).unwrap().unwrap();
        manifest.snapshot_height = 0;
        indra_storage::save_chain_manifest(&dir, &manifest).unwrap();
        let state_dir = config.state_dir();
        if state_dir.exists() {
            std::fs::remove_dir_all(&state_dir).unwrap();
        }

        let replayed = NodeEngine::init(config).unwrap().state;
        assert_eq!(replayed.encode_to_vec(), continuous.encode_to_vec());
        assert_eq!(
            indra_state::compute_state_root(&replayed),
            indra_state::compute_state_root(&continuous)
        );
        assert_eq!(replayed, continuous);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_last_recovery_discards_all_unconfirmed_store_artifacts() {
        let dir = temp_dir("manifest_last_cross_store_recovery");
        let mut config = NodeConfig::local_test(dir.clone());
        config.genesis_path = Some(write_single_validator_genesis(&dir, [0x42u8; 32]));
        configure_validator_keys(&mut config, [0x42u8; 32]);
        let confirmed_tip;
        {
            let mut engine = NodeEngine::init(config.clone()).unwrap();
            let first = make_strict_block(&engine.state, [0x42u8; 32], vec![]);
            engine.commit_proposal(&first).unwrap();
            confirmed_tip = engine.state.tip_hash;

            // Model a process killed after every component store made the next
            // generation durable, but before manifest-v2 was atomically renamed.
            let parent_qc = build_single_validator_qc_bytes(
                engine.state.height,
                first.header.proposer_round,
                engine.state.tip_hash,
                [0x42u8; 32],
                [0x42u8; 32],
                engine
                    .state
                    .snapshot_for_consensus_height(engine.state.height)
                    .unwrap()
                    .snapshot_root,
            );
            let second = make_strict_block(&engine.state, [0x42u8; 32], parent_qc);
            let mut projected = engine.state.clone();
            apply_verified_test(&mut projected, &second, 0);
            engine.block_store.append(&second).unwrap();
            engine.state_store.save(&projected).unwrap();
            engine
                .epoch_store
                .append(&indra_core::EpochRecord {
                    epoch: 0,
                    start_height: 0,
                    end_height: 299,
                    timestamp_secs: 1,
                    active_validators: 1,
                    total_staked_spark: 1,
                    reward_minted_spark: 0,
                    fee_rewards_distributed: 0,
                    fee_burned_spark: 0,
                    slash_burned_spark: 0,
                    governance_burned_spark: 0,
                    total_burned_spark: 0,
                    opening_total_supply_spark: projected.total_supply,
                    closing_total_supply_spark: projected.total_supply,
                    slash_event_count: 0,
                    liveness_penalty_count: 0,
                    avg_base_fee: 1,
                    validators_joined: vec![],
                    validators_left: vec![],
                    era: 0,
                    block_reward_spark: 0,
                })
                .unwrap();
        }

        let restarted = NodeEngine::init(config).unwrap();
        assert_eq!(restarted.state.height, 1);
        assert_eq!(restarted.state.tip_hash, confirmed_tip);
        assert_eq!(restarted.block_store.next_height(), 2);
        assert_eq!(restarted.epoch_store.latest_epoch(), None);
        assert!(dir.join("block_segments").join("quarantine").exists());
        assert!(dir.join("state").join("quarantine").exists());
        assert!(dir.join("epochs.log.unconfirmed").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_replay_detects_corrupt_block_via_state_root_mismatch() {
        let dir = temp_dir("replay_bad_root");
        let mut config = NodeConfig::local_test(dir.clone());
        config.genesis_path = Some(write_single_validator_genesis(&dir, [0x42u8; 32]));
        configure_validator_keys(&mut config, [0x42u8; 32]);
        {
            let mut engine = NodeEngine::init(config.clone()).unwrap();
            let mut block = make_strict_block(&engine.state, [0x42u8; 32], vec![]);
            block.header.state_root = Bytes32::from([0xEE; 32]);
            let signer = HybridKeypair::new(
                ClassicalKeypair::from_seed(&[0x42; 32]),
                PqKeypair::from_seed(&[0x42; 32]).unwrap(),
            );
            let signature = signer
                .sign(
                    &block
                        .signing_bytes(engine.state.chain_id.as_bytes())
                        .unwrap(),
                )
                .unwrap();
            block.proposer_authorization = indra_core::types::crypto::HybridSignature {
                classical_sig: VariableBytes::from_slice(&signature.classical.0).unwrap(),
                pq_sig: VariableBytes::from_slice(&signature.pq.0).unwrap(),
            };
            engine
                .block_store
                .append(&crate::genesis::build_genesis_proposal(&engine.state).unwrap())
                .unwrap();
            engine.block_store.append(&block).unwrap();
            indra_storage::save_chain_manifest(
                &dir,
                &ChainManifest {
                    committed_height: 1,
                    committed_block_hash: block.header.block_hash(),
                    state_root: block.header.state_root,
                    snapshot_height: 0,
                    block_log_next_height: 2,
                    last_qc_height: 0,
                    epoch_log_latest_epoch: None,
                    chain_id: engine.state.chain_id.clone(),
                },
            )
            .unwrap();
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
                chain_id: indra_core::types::primitives::TEST_CHAIN_ID.into(),
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
        configure_validator_keys(&mut config, [0x42u8; 32]);
        {
            let mut engine = NodeEngine::init(config.clone()).unwrap();
            let block = make_strict_block(&engine.state, [0x42u8; 32], vec![]);
            engine.commit_proposal(&block).unwrap();
            let mut bad_snapshot = engine.state.clone();
            bad_snapshot.tip_hash = Bytes32::from([0xDD; 32]);
            engine.state_store.save(&bad_snapshot).unwrap();
            engine.write_chain_manifest().unwrap();
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
        config.genesis_path = Some(write_single_validator_genesis(&dir, [0x42u8; 32]));
        configure_validator_keys(&mut config, [0x42u8; 32]);
        config.prune_keep_blocks = Some(1_000);

        let final_tip_hash = {
            let mut engine = NodeEngine::init(config.clone()).unwrap();
            let mut last_qc = Vec::new();
            for height in 1..=1_300u64 {
                let block = make_strict_block(&engine.state, [0x42u8; 32], last_qc.clone());
                engine.commit_proposal(&block).unwrap();
                last_qc = build_single_validator_qc_bytes(
                    height,
                    block.header.proposer_round,
                    block.header.block_hash(),
                    [0x42u8; 32],
                    [0x42u8; 32],
                    engine
                        .state
                        .snapshot_for_consensus_height(height)
                        .unwrap()
                        .snapshot_root,
                );
                assert_eq!(engine.state.height, height);
            }
            assert!(engine.block_store.lowest_height() > 0);
            engine.state.tip_hash
        };

        let restarted = NodeEngine::init(config).unwrap();
        assert_eq!(restarted.state.height, 1_300);
        assert_eq!(restarted.state.tip_hash, final_tip_hash);
        assert!(restarted.block_store.lowest_height() > 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_from_snapshot_produces_same_state_as_continuous() {
        let dir = temp_dir("snapshot_state_root");
        let mut config = NodeConfig::local_test(dir.clone());
        config.genesis_path = Some(write_single_validator_genesis(&dir, [0x42u8; 32]));
        configure_validator_keys(&mut config, [0x42u8; 32]);
        config.prune_keep_blocks = Some(650);

        let (continuous_state, next_block) = {
            let mut engine = NodeEngine::init(config.clone()).unwrap();
            let mut last_qc = Vec::new();
            for height in 1..=610u64 {
                let block = make_strict_block(&engine.state, [0x42u8; 32], last_qc.clone());
                engine.commit_proposal(&block).unwrap();
                last_qc = build_single_validator_qc_bytes(
                    height,
                    block.header.proposer_round,
                    block.header.block_hash(),
                    [0x42u8; 32],
                    [0x42u8; 32],
                    engine
                        .state
                        .snapshot_for_consensus_height(height)
                        .unwrap()
                        .snapshot_root,
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
        apply_verified_test(&mut continuous_next, &next_block, 0);
        apply_verified_test(&mut restarted_next, &next_block, 0);

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
        let genesis_path = config.genesis_path.as_ref().unwrap();
        let genesis = crate::genesis::test_genesis_toml_single_authority(
            "indra-custom-testnet",
            &[([0x42; 32], [0x42; 32], [0x42; 32]), ([0xB2; 32], [0xB2; 32], [0xB2; 32]), ([0xC3; 32], [0xC3; 32], [0xC3; 32]), ([0xD4; 32], [0xD4; 32], [0xD4; 32])],
        );
        std::fs::write(genesis_path, genesis).unwrap();

        {
            let mut engine = NodeEngine::init(config.clone()).unwrap();
            engine.state_store.save(&engine.state).unwrap();
            engine.write_chain_manifest().unwrap();
        }

        let restarted = NodeEngine::init(config).unwrap();
        assert_eq!(restarted.state.chain_id, "indra-custom-testnet");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_rejects_changed_manifest_and_tampered_snapshot_fingerprint() {
        let manifest_dir = temp_dir("genesis_manifest_fingerprint_mismatch");
        let manifest_config = NodeConfig::local_test(manifest_dir.clone());
        {
            let mut engine = NodeEngine::init(manifest_config.clone()).unwrap();
            engine.state_store.save(&engine.state).unwrap();
            engine.write_chain_manifest().unwrap();
        }
        let genesis_path = manifest_config.genesis_path.as_ref().unwrap();
        let genesis = std::fs::read_to_string(genesis_path)
            .unwrap()
            .replace("stake = 1000000000000", "stake = 1000000000001");
        std::fs::write(genesis_path, genesis).unwrap();
        let changed_manifest_error = match NodeEngine::init(manifest_config) {
            Ok(_) => panic!("changed manifest unexpectedly accepted"),
            Err(error) => error,
        };
        assert!(matches!(changed_manifest_error, NodeError::GenesisMismatch));
        let _ = std::fs::remove_dir_all(&manifest_dir);

        let snapshot_dir = temp_dir("snapshot_fingerprint_mismatch");
        let snapshot_config = NodeConfig::local_test(snapshot_dir.clone());
        {
            let mut engine = NodeEngine::init(snapshot_config.clone()).unwrap();
            engine.state.genesis_fingerprint.0[0] ^= 1;
            engine.state_store.save(&engine.state).unwrap();
            engine.write_chain_manifest().unwrap();
        }
        assert!(matches!(
            NodeEngine::init(snapshot_config),
            Err(NodeError::GenesisMismatch)
        ));
        let _ = std::fs::remove_dir_all(&snapshot_dir);
    }

    #[test]
    fn engine_initialization_rejects_local_vrf_key_mismatch() {
        let dir = temp_dir("startup_vrf_mismatch");
        let mut config = NodeConfig::local_test(dir.clone());
        config.vrf_seed = Some([0x99; 32]);
        assert!(matches!(
            NodeEngine::init(config),
            Err(NodeError::ValidatorConfigIncomplete { detail })
                if detail.contains("VRF secret key does not match")
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_fails_on_snapshot_replay_gap() {
        let dir = temp_dir("snapshot_gap");
        let mut config = NodeConfig::local_test(dir.clone());
        config.genesis_path = Some(write_single_validator_genesis(&dir, [0x42u8; 32]));
        configure_validator_keys(&mut config, [0x42u8; 32]);
        config.snapshot_interval = 30;
        config.prune_keep_blocks = Some(1_000);

        let extra_block = {
            let mut engine = NodeEngine::init(config.clone()).unwrap();
            let mut last_qc = Vec::new();
            for _ in 0..1_300u64 {
                let height = engine.state.height + 1;
                let block = make_strict_block(&engine.state, [0x42u8; 32], last_qc.clone());
                engine.commit_proposal(&block).unwrap();
                last_qc = build_single_validator_qc_bytes(
                    height,
                    block.header.proposer_round,
                    block.header.block_hash(),
                    [0x42u8; 32],
                    [0x42u8; 32],
                    engine
                        .state
                        .snapshot_for_consensus_height(height)
                        .unwrap()
                        .snapshot_root,
                );
            }
            make_strict_block(&engine.state, [0x42u8; 32], last_qc)
        };

        {
            let mut store = BlockStore::open(
                dir.join("blocks.log"),
                indra_storage::PruneConfig {
                    keep_blocks: Some(1_000),
                },
            )
            .unwrap();
            store.append(&extra_block).unwrap();
            assert_eq!(store.lowest_height(), 300);
        }

        let state_dir = dir.join("state");
        for entry in std::fs::read_dir(&state_dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("snap") {
                std::fs::remove_file(path).unwrap();
            }
        }

        let state_store = StateStore::open(&state_dir).unwrap();
        let mut snapshot = crate::genesis::build_finalized_genesis_state(
            config.genesis_path.as_deref(),
        )
        .unwrap();
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
                assert_eq!(lowest_block, 300);
                assert_eq!(gap, 289);
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

        let genesis_path = dir.join("genesis.toml");
        let genesis = crate::genesis::test_genesis_toml_single_authority(
            "indra-testnet-1",
            &[
                ([0x11; 32], [0x11; 32], [0x22; 32]),
                ([0xB2; 32], [0xB2; 32], [0xB2; 32]),
                ([0xC3; 32], [0xC3; 32], [0xC3; 32]),
                ([0xD4; 32], [0xD4; 32], [0xD4; 32]),
            ],
        );
        std::fs::write(&genesis_path, genesis).unwrap();
        config.genesis_path = Some(genesis_path.to_string_lossy().to_string());
        config.validator_seed = Some([0x11; 32]);
        config.vrf_seed = Some([0x22; 32]);
        let configured_pq = PqKeypair::from_seed(&[0x11; 32]).unwrap();
        config.pq_pk = Some(configured_pq.public_key().0.to_vec());
        config.pq_seed = Some(configured_pq.secret_key_bytes());

        let mut engine = NodeEngine::init(config).unwrap();
        assert_eq!(engine.state.utxos.len(), 4);

        engine.rebuild_state_from_block_log().unwrap();
        assert_eq!(engine.state.utxos.len(), 4);

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

        let election = test_election(&engine.state, 3, 0);

        let err = engine
            .propose(&election, 1_700_000_003, Vec::new(), None)
            .unwrap_err();
        assert!(matches!(err, NodeError::MissingQc { height: 3 }));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fresh_four_validator_genesis_height_one_block_production_succeeds() {
        let dir = temp_dir("height1_production");
        let config = NodeConfig::local_test(dir.clone());
        let mut engine = NodeEngine::init(config).unwrap();
        install_active_validator(&mut engine, [0x42u8; 32], "local");

        let election =
            first_eligible_test_election(&engine.state, 1, &VrfKeypair::from_seed(&[0x42; 32]));

        assert_eq!(election.election_seed, engine.state.election_seed);
        assert!(
            engine.is_proposer(&election),
            "one of the four genesis validators should be eligible to produce height 1"
        );
        let block = engine
            .propose(&election, 1_700_000_001, Vec::new(), None)
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
        let local = install_active_validator(&mut engine, [0x42u8; 32], "local");
        let local_public = local.public_key();
        let local_id = indra_core::types::crypto::hybrid_identity_id(
            &local_public.classical.0,
            &local_public.pq.0,
        );
        engine.state.validators.get_mut(&local_id).unwrap().vrf_pk =
            Some(VrfKeypair::from_seed(&[0x99u8; 32]).public_key());

        crate::genesis::finalize_test_genesis(&mut engine.state);
        let registered_vrf = VrfKeypair::from_seed(&[0x99; 32]);
        let foreign_local_vrf = VrfKeypair::from_seed(&[0x42; 32]);
        let election = (0..MAX_ROUNDS_PER_HEIGHT)
            .map(|round| test_election(&engine.state, 1, round))
            .find(|election| {
                compute_proposer_vrf(local_id, &registered_vrf, election)
                    .is_ok_and(|result| result.eligible)
            })
            .expect("registered VRF key must become eligible within the legal round range");
        let alpha = election.vrf_input(&local_id).unwrap();
        let (foreign_output, foreign_proof) = indra_crypto::vrf_prove(&foreign_local_vrf, &alpha);
        assert!(indra_crypto::vrf_verify(
            &foreign_local_vrf.public_key(),
            &alpha,
            &foreign_output,
            &foreign_proof,
        )
        .is_ok());
        assert!(indra_crypto::vrf_verify(
            &registered_vrf.public_key(),
            &alpha,
            &foreign_output,
            &foreign_proof,
        )
        .is_err());
        assert!(
            compute_proposer_vrf(local_id, &registered_vrf, &election)
                .unwrap()
                .eligible,
            "the snapshot-registered VRF key fixture must be eligible at round 13"
        );
        assert!(compute_proposer_vrf(local_id, &foreign_local_vrf, &election).is_err());

        assert!(
            !engine.is_proposer(&election),
            "a node must not claim proposer eligibility when its local VRF key does not match the registered validator VRF key"
        );
        let err = engine
            .propose(&election, 1_700_000_001, Vec::new(), None)
            .unwrap_err();
        assert!(matches!(
            err,
            NodeError::Consensus(indra_consensus::ConsensusError::WrongProposer { reason })
                if reason == "local VRF key is not in election candidates"
        ));

        let _ = std::fs::remove_dir_all(&dir);
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
    fn staking_next_nonce_is_rejected_at_admission_and_targeted_pruning() {
        let dir = temp_dir("staking_one_pending_next_nonce");
        let mut engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let keypair = install_active_validator(&mut engine, [0x72; 32], "stake-next");
        let cold = cold_keypair_for_seed([0x72; 32]);
        let first = valid_set_commission_staking_op(&engine, &keypair, &cold, 1, 1_100);
        let second = valid_set_commission_staking_op(&engine, &keypair, &cold, 2, 1_200);

        engine.add_staking_op(first.clone()).unwrap();
        assert!(matches!(
            engine.add_staking_op(second.clone()),
            Err(NodeError::InvalidStakingOp(_))
        ));

        engine.staking_mempool.push(second);
        let mut effects = indra_state::CanonicalStateEffects::default();
        effects.validators_changed.insert(first.signer_id());
        engine.apply_pending_canonical_effects(&effects);
        assert_eq!(engine.staking_mempool, vec![first]);

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
    fn programmatic_config_rejects_zero_staking_mempool_capacity() {
        let dir = temp_dir("staking_mempool_capacity");
        let mut config = NodeConfig::local_test(dir.clone());
        config.staking_mempool_capacity = 0;
        let err = match NodeEngine::init(config) {
            Ok(_) => panic!("zero staking capacity unexpectedly initialized"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("storage.staking_mempool_capacity"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn programmatic_config_enforces_all_pool_capacity_ceilings_and_accepts_bounds() {
        let cases = [
            ("transaction-zero", 0, 1, 1, "storage.mempool_capacity"),
            (
                "transaction-high",
                crate::config::MAX_MEMPOOL_CAPACITY + 1,
                1,
                1,
                "storage.mempool_capacity",
            ),
            (
                "staking-high",
                1,
                crate::config::MAX_STAKING_MEMPOOL_CAPACITY + 1,
                1,
                "storage.staking_mempool_capacity",
            ),
            (
                "governance-high",
                1,
                1,
                crate::config::max_governance_mempool_capacity() + 1,
                "storage.governance_mempool_capacity",
            ),
        ];
        for (name, transaction, staking, governance, expected_key) in cases {
            let dir = temp_dir(name);
            let mut config = NodeConfig::local_test(dir.clone());
            config.mempool_capacity = transaction;
            config.staking_mempool_capacity = staking;
            config.governance_mempool_capacity = governance;
            let err = match NodeEngine::init(config) {
                Ok(_) => panic!("out-of-range capacity unexpectedly initialized"),
                Err(err) => err.to_string(),
            };
            assert!(err.contains(expected_key), "unexpected error: {err}");
            let _ = std::fs::remove_dir_all(dir);
        }

        let dir = temp_dir("pool-capacity-valid-maxima");
        let mut config = NodeConfig::local_test(dir.clone());
        config.mempool_capacity = crate::config::MAX_MEMPOOL_CAPACITY;
        config.staking_mempool_capacity = crate::config::MAX_STAKING_MEMPOOL_CAPACITY;
        config.governance_mempool_capacity = crate::config::max_governance_mempool_capacity();
        assert!(NodeEngine::init(config).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cross_signer_last_stake_position_slot_selects_exactly_one() {
        let dir = temp_dir("staking_last_position_slot");
        let mut engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let validator = install_active_validator(&mut engine, [0x81; 32], "position-target");
        let validator_id = indra_core::types::crypto::hybrid_identity_id(
            &validator.public_key().classical.0,
            &validator.public_key().pq.0,
        );
        // Genesis already contains the validator's self position.
        for ordinal in 0..(indra_core::types::primitives::MAX_STAKE_POSITIONS_PER_VALIDATOR - 2) {
            let owner = Bytes32::from(indra_crypto::sha256(&(ordinal as u64).to_le_bytes()));
            let position = StakePositionV1::new(
                validator_id,
                owner,
                PositionCustodyV1::DelegatorIdentity {
                    delegator_id: owner,
                },
                None,
                1,
                0,
            )
            .unwrap();
            engine
                .state
                .stake_positions
                .insert(position.position_id, position);
        }
        engine.state.rebuild_position_tranche_index().unwrap();
        let first_signer = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0x82; 32]),
            PqKeypair::from_seed(&[0x82; 32]).unwrap(),
        );
        let second_signer = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0x83; 32]),
            PqKeypair::from_seed(&[0x83; 32]).unwrap(),
        );
        let first = valid_delegate_op(&mut engine, validator_id, &first_signer, 0x82);
        let second = valid_delegate_op(&mut engine, validator_id, &second_signer, 0x83);
        engine.add_staking_op(first.clone()).unwrap();
        assert!(matches!(
            engine.add_staking_op(second.clone()),
            Err(NodeError::InvalidStakingOp(_))
        ));
        assert_eq!(engine.staking_mempool, vec![first.clone()]);
        // Bypass admission deliberately: this reproduces the historical race
        // where both were independently valid against the same pre-state.
        engine.staking_mempool = vec![first.clone(), second];

        let selected = engine.select_block_contents().unwrap().staking_ops;
        assert_eq!(selected, vec![first]);
        assert_eq!(engine.staking_mempool.len(), 1);
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
        let signer_id = indra_core::types::crypto::hybrid_identity_id(
            &keypair.public_key().classical.0,
            &keypair.public_key().pq.0,
        );
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

        let selected = engine.select_block_contents().unwrap().governance_ops;

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

        let selected = engine.select_block_contents().unwrap().governance_ops;

        assert_eq!(selected, vec![op.clone()]);
        assert_eq!(engine.governance_mempool, vec![op]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn governance_candidate_failure_rolls_back_nonce_and_all_state() {
        let dir = temp_dir("governance_atomic_candidate");
        let mut engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let keypair = install_active_validator(&mut engine, [0x56; 32], "gov-rollback");
        let mut op = valid_governance_propose_op(&mut engine, &keypair, 1);
        if let GovernancePayload::Propose {
            deposit_utxo_id, ..
        } = &mut op.payload
        {
            *deposit_utxo_id = Bytes32::from([0xFE; 32]);
        }
        sign_governance_op(&mut op, &keypair);
        let before = engine.state.clone();
        let mut scratch = before.clone();

        assert!(try_apply_governance_candidate(&mut scratch, &op, 0, 1).is_err());
        assert_eq!(scratch, before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn governance_deposit_conflicting_with_staking_is_evicted() {
        let dir = temp_dir("governance_staking_deposit_conflict");
        let mut engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let validator = install_active_validator(&mut engine, [0x57; 32], "gov-stake-target");
        let validator_id = indra_core::types::crypto::hybrid_identity_id(
            &validator.public_key().classical.0,
            &validator.public_key().pq.0,
        );
        let hot = install_active_validator(&mut engine, [0x58; 32], "gov-stake-signer");
        let cold = cold_keypair_for_seed([0x58; 32]);
        let governance = valid_cold_governance_propose_op(&mut engine, &hot, &cold, 1);
        let (deposit_utxo_id, delegator_pubkey) = match &governance.payload {
            GovernancePayload::Propose {
                deposit_utxo_id,
                proposer_pubkey,
                ..
            } => (*deposit_utxo_id, proposer_pubkey.clone()),
            _ => unreachable!(),
        };
        let mut staking = StakingOp {
            body: StakingOpBody::Delegate {
                validator_id,
                deposit_utxo_id,
                delegator_pubkey,
            },
            nonce: 1,
            signature: dummy_signature(),
        };
        sign_staking_op(&mut staking, &cold, &engine.state.chain_id);
        engine.staking_mempool = vec![staking.clone()];
        engine.governance_mempool = vec![governance];

        let selected = engine.select_block_contents().unwrap();
        assert_eq!(selected.staking_ops, vec![staking]);
        assert!(selected.governance_ops.is_empty());
        assert!(engine.governance_mempool.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transaction_conflicts_evict_later_staking_and_governance_candidates() {
        let dir = temp_dir("transaction_cross_pool_conflicts");
        let mut engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        let target = install_active_validator(&mut engine, [0x59; 32], "tx-conflict-target");
        let target_id = indra_core::types::crypto::hybrid_identity_id(
            &target.public_key().classical.0,
            &target.public_key().pq.0,
        );

        let delegator = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0x5A; 32]),
            PqKeypair::from_seed(&[0x5A; 32]).unwrap(),
        );
        let staking = valid_delegate_op(&mut engine, target_id, &delegator, 0x5A);
        let staking_utxo = match &staking.body {
            StakingOpBody::Delegate {
                deposit_utxo_id, ..
            } => *deposit_utxo_id,
            _ => unreachable!(),
        };
        let staking_tx = valid_tx_spending(&engine, staking_utxo, &delegator, [0; 32], 0x6A);
        engine
            .mempool
            .submit_validated(staking_tx.clone(), &engine.state)
            .unwrap();
        engine.staking_mempool = vec![staking];
        let selected = engine.select_block_contents().unwrap();
        assert_eq!(selected.transactions, vec![staking_tx]);
        assert!(selected.staking_ops.is_empty());
        assert!(engine.staking_mempool.is_empty());

        engine.mempool = Mempool::default_config();
        let hot = install_active_validator(&mut engine, [0x5B; 32], "tx-gov-signer");
        let cold = cold_keypair_for_seed([0x5B; 32]);
        let governance = valid_cold_governance_propose_op(&mut engine, &hot, &cold, 1);
        let governance_utxo = match &governance.payload {
            GovernancePayload::Propose {
                deposit_utxo_id, ..
            } => *deposit_utxo_id,
            _ => unreachable!(),
        };
        let governance_tx = valid_tx_spending(&engine, governance_utxo, &cold, [0; 32], 0x6B);
        engine
            .mempool
            .submit_validated(governance_tx.clone(), &engine.state)
            .unwrap();
        engine.governance_mempool = vec![governance];
        let selected = engine.select_block_contents().unwrap();
        assert_eq!(selected.transactions, vec![governance_tx]);
        assert!(selected.governance_ops.is_empty());
        assert!(engine.governance_mempool.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn combined_four_pool_conflicts_produce_deterministic_maximal_subset() {
        let dir = temp_dir("combined_four_pool_conflicts");
        let mut engine = NodeEngine::init(NodeConfig::local_test(dir.clone())).unwrap();
        // A finalized slash must leave a nonempty next-height authority set;
        // production genesis enforces four validators, so keep this synthetic
        // cross-pool fixture representative instead of slashing its sole member.
        let _survivor = install_active_validator(&mut engine, [0x41; 32], "combined-survivor");
        let proposer = install_active_validator(&mut engine, [0x42; 32], "combined-proposer");
        let proposer_id = indra_core::types::crypto::hybrid_identity_id(
            &proposer.public_key().classical.0,
            &proposer.public_key().pq.0,
        );

        // Two transactions spend the same UTXO; deterministic mempool order wins.
        let tx_owner = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0x61; 32]),
            PqKeypair::from_seed(&[0x61; 32]).unwrap(),
        );
        let tx_source = valid_delegate_op(&mut engine, proposer_id, &tx_owner, 0x61);
        let tx_utxo = match &tx_source.body {
            StakingOpBody::Delegate {
                deposit_utxo_id, ..
            } => *deposit_utxo_id,
            _ => unreachable!(),
        };
        let tx_a = valid_tx_spending(&engine, tx_utxo, &tx_owner, [0; 32], 0x71);
        let tx_b = valid_tx_spending(&engine, tx_utxo, &tx_owner, [0; 32], 0x72);
        engine.mempool.insert_unchecked_for_test(tx_a.clone(), 0).unwrap();
        engine.mempool.insert_unchecked_for_test(tx_b.clone(), 0).unwrap();
        let expected_tx = engine.mempool.select_for_block(1, 0)[0].tx.clone();

        // Duplicate staking candidates are individually valid against pre-state.
        let delegator = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0x62; 32]),
            PqKeypair::from_seed(&[0x62; 32]).unwrap(),
        );
        let staking = valid_delegate_op(&mut engine, proposer_id, &delegator, 0x62);
        engine.staking_mempool = vec![staking.clone(), staking.clone()];

        // Duplicate governance candidates contend for one nonce/deposit UTXO.
        let cold = cold_keypair_for_seed([0x42; 32]);
        let governance = valid_cold_governance_propose_op(&mut engine, &proposer, &cold, 1);
        engine.governance_mempool = vec![governance.clone(), governance.clone()];

        // Two valid equivocations target the same validator.
        let slash_a = signed_slash_evidence(
            &engine,
            &proposer,
            1,
            0,
            0,
            VoteStep::Precommit,
            VoteStep::Precommit,
            Bytes32::from([0x81; 32]),
            Bytes32::from([0x82; 32]),
        );
        let slash_b = signed_slash_evidence(
            &engine,
            &proposer,
            1,
            1,
            1,
            VoteStep::Precommit,
            VoteStep::Precommit,
            Bytes32::from([0x83; 32]),
            Bytes32::from([0x84; 32]),
        );
        engine.pending_slashes = vec![
            proof_carrying_slash(&engine, &slash_a),
            proof_carrying_slash(&engine, &slash_b),
        ];
        account_fixture_claims(&mut engine.state);

        let contents = engine.select_block_contents().unwrap();
        assert_eq!(contents.transactions, vec![expected_tx.clone()]);
        assert_eq!(contents.staking_ops, vec![staking.clone()]);
        assert_eq!(contents.governance_ops, vec![governance.clone()]);
        assert_eq!(contents.slash_evidence.len(), 1);
        assert_eq!(engine.mempool.len(), 1);
        assert_eq!(engine.staking_mempool, vec![staking]);
        assert_eq!(engine.governance_mempool, vec![governance]);
        assert_eq!(engine.pending_slashes.len(), 1);

        let election =
            first_eligible_test_election(&engine.state, 1, &VrfKeypair::from_seed(&[0x42; 32]));
        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&[0x42; 32]),
            prev_qc_bytes: vec![],
            timestamp: 1_700_000_001,
            polc_round: None,
            transactions: contents.transactions,
            staking_ops: contents.staking_ops,
            governance_ops: contents.governance_ops,
            slash_evidence: contents.slash_evidence,
        };
        let block = produce_block(&template, &mut engine.state, &election).unwrap();
        assert_eq!(block.transactions, vec![expected_tx]);
        assert_eq!(block.staking_ops.len(), 1);
        assert_eq!(block.governance_ops.len(), 1);
        assert_eq!(block.slashing_evidence.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn programmatic_config_rejects_zero_governance_mempool_capacity() {
        let dir = temp_dir("governance_mempool_capacity");
        let mut config = NodeConfig::local_test(dir.clone());
        config.governance_mempool_capacity = 0;
        let err = match NodeEngine::init(config) {
            Ok(_) => panic!("zero governance capacity unexpectedly initialized"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("storage.governance_mempool_capacity"));

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

    #[test]
    fn disk_pressure_is_fail_closed_at_threshold_and_on_query_failure() {
        assert!(evaluate_disk_writable(Ok(DISK_CRITICAL_THRESHOLD_BYTES)).is_ok());
        assert!(matches!(
            evaluate_disk_writable(Ok(DISK_CRITICAL_THRESHOLD_BYTES - 1)),
            Err(NodeError::StoragePressure { .. })
        ));
        assert!(matches!(
            evaluate_disk_writable(Err(std::io::Error::other("injected query failure"))),
            Err(NodeError::StoragePressure { .. })
        ));
    }
}
