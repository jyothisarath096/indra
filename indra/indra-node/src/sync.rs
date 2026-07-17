//! Block import and chain sync.
//!
//! `import_block` is the single entry point for adding a block to the chain.
//! It:
//!   1. Validates the block's structural invariants
//!   2. Projects the block once, verifies the projected header roots
//!   3. Commits the verified projection to chain state
//!   4. Writes the block to the block store
//!   5. Evicts spent/invalid transactions from the mempool
//!   6. Optionally takes a state snapshot

use std::net::SocketAddr;

use indra_consensus::mempool::Mempool;
use indra_consensus::{
    proposer::{
        compute_fallback_election_result, compute_vrf_input, elect_proposer,
        elect_proposer_from_reveals, ProposerCandidate, ProposerElection, VRF_FALLBACK_OUTPUT,
    },
    qc::{verify_qc_strict, QcValidator},
};
use indra_core::codec::Decode;
use indra_core::types::block::BlockV1;
use indra_core::types::primitives::{
    bps_of, reveal_set_commitment_active, vrf_commit_reveal_election_active, Bytes32,
    CONSENSUS_QUORUM_BPS, MAX_VRF_EMPTY_REVEAL_ROUNDS,
};
use indra_core::types::vrf_election::{compute_reveal_set_commitment, VrfElectionResult};
use indra_core::EpochRecord;
use indra_crypto::{vrf_verify, VrfOutput, VrfProof};
use indra_state::{apply_block, ChainState};
use indra_storage::state_store::SNAPSHOT_INTERVAL;
use indra_storage::{BlockStore, StateStore};

use crate::{
    error::{NodeError, NodeResult},
    state_root::compute_state_roots,
};

/// Maximum blocks to request in one sync batch.
pub const SYNC_BATCH_SIZE: u64 = 50;

/// Current synchronization phase for a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncPhase {
    /// Have not yet heard from any peer.
    AwaitingPeers,
    /// Downloading missing blocks from a peer.
    Downloading {
        /// The peer currently serving us blocks.
        peer: SocketAddr,
        /// Highest height we know we must reach.
        target_height: u64,
        /// Next block height expected from the response stream.
        next_expected: u64,
    },
    /// Local height matches the best known peer height.
    CaughtUp,
}

/// Driver-owned synchronization state machine.
#[derive(Debug, Clone)]
pub struct SyncState {
    phase: SyncPhase,
    best_peer_height: u64,
    received_peer_status: bool,
    is_bootstrap_node: bool,
}

impl SyncState {
    /// Create the bootstrap node sync state.
    pub fn bootstrap(local_height: u64) -> Self {
        Self {
            phase: if local_height == 0 {
                SyncPhase::CaughtUp
            } else {
                SyncPhase::AwaitingPeers
            },
            best_peer_height: local_height,
            received_peer_status: local_height == 0,
            is_bootstrap_node: true,
        }
    }

    /// Create the follower node sync state.
    pub fn follower(local_height: u64) -> Self {
        Self {
            phase: SyncPhase::AwaitingPeers,
            best_peer_height: local_height,
            received_peer_status: false,
            is_bootstrap_node: false,
        }
    }

    /// Return the current phase.
    pub fn phase(&self) -> &SyncPhase {
        &self.phase
    }

    /// True when the node may participate in consensus.
    pub fn is_caught_up(&self) -> bool {
        if !self.received_peer_status && !self.is_bootstrap_node {
            return false;
        }
        matches!(self.phase, SyncPhase::CaughtUp)
    }

    /// Current sync target height, if any.
    pub fn target_height(&self) -> Option<u64> {
        match self.phase {
            SyncPhase::Downloading { target_height, .. } => Some(target_height),
            SyncPhase::CaughtUp | SyncPhase::AwaitingPeers => None,
        }
    }

    /// Observe a peer's status and return a download request if we need one.
    pub fn observe_status(
        &mut self,
        peer: SocketAddr,
        peer_height: u64,
        local_height: u64,
    ) -> Option<(SocketAddr, u64, u64)> {
        self.received_peer_status = true;
        self.best_peer_height = self.best_peer_height.max(peer_height);

        if local_height >= self.best_peer_height {
            if matches!(self.phase, SyncPhase::AwaitingPeers) {
                self.phase = SyncPhase::CaughtUp;
            }
            if matches!(self.phase, SyncPhase::Downloading { .. }) {
                self.phase = SyncPhase::CaughtUp;
            }
            return None;
        }

        let from_height = local_height.saturating_add(1);
        let target_height = self.best_peer_height;
        let to_height = target_height.min(from_height.saturating_add(SYNC_BATCH_SIZE - 1));

        self.phase = SyncPhase::Downloading {
            peer,
            target_height,
            next_expected: from_height,
        };

        Some((peer, from_height, to_height))
    }

    /// Record one imported block while downloading.
    pub fn on_block_imported(&mut self, imported_height: u64) {
        if let SyncPhase::Downloading {
            target_height,
            next_expected,
            ..
        } = &mut self.phase
        {
            if imported_height >= *next_expected {
                *next_expected = imported_height.saturating_add(1);
            }
            *target_height = (*target_height).max(self.best_peer_height);
            if imported_height >= self.best_peer_height {
                self.phase = SyncPhase::CaughtUp;
            }
        }
    }

    /// After handling a block response, decide whether we need another batch.
    pub fn next_request_after_response(
        &mut self,
        local_height: u64,
    ) -> Option<(SocketAddr, u64, u64)> {
        match self.phase {
            SyncPhase::Downloading {
                peer,
                target_height,
                next_expected,
            } => {
                let target_height = target_height.max(self.best_peer_height);
                if local_height >= self.best_peer_height {
                    self.phase = SyncPhase::CaughtUp;
                    None
                } else {
                    let from_height = next_expected.max(local_height.saturating_add(1));
                    let to_height =
                        target_height.min(from_height.saturating_add(SYNC_BATCH_SIZE - 1));
                    Some((peer, from_height, to_height))
                }
            }
            SyncPhase::AwaitingPeers | SyncPhase::CaughtUp => None,
        }
    }

    /// Handle a block response that imported nothing.
    pub fn on_empty_response(&mut self, local_height: u64) {
        if let SyncPhase::Downloading { .. } = self.phase {
            if local_height >= self.best_peer_height.saturating_sub(1) {
                self.best_peer_height = local_height;
                self.phase = SyncPhase::CaughtUp;
            }
        }
    }

    /// Reset round state after catching up to a new height.
    pub fn mark_caught_up(&mut self, local_height: u64) {
        self.best_peer_height = self.best_peer_height.max(local_height);
        self.phase = SyncPhase::CaughtUp;
        // If we successfully committed/imported a block, we are caught up
        // enough to participate without waiting for the periodic peer Status
        // heartbeat. The block itself proves network communication happened.
        self.received_peer_status = true;
    }
}

/// Import a block into the chain.
///
/// This is the canonical block processing pipeline:
/// validate → project/verify → commit projection → evict mempool → store → snapshot.
pub fn import_block(
    block: &BlockV1,
    state: &mut ChainState,
    mempool: &mut Mempool,
    block_store: &mut BlockStore,
    state_store: &StateStore,
    timestamp_secs: u64,
) -> NodeResult<Option<EpochRecord>> {
    let height = block.header.height;

    let epoch_record = validate_and_apply_imported_block(block, state, mempool, timestamp_secs)?;

    // Store genesis placeholder if block_store is empty and this is height 1
    if block_store.is_empty() && height == 1 {
        let genesis = crate::genesis::build_genesis_block();
        block_store.append(&genesis)?;
    }
    block_store.append(block)?;

    // Take snapshot if on interval
    if height > 0 && height.is_multiple_of(SNAPSHOT_INTERVAL) {
        state_store.save(state)?;
    }

    Ok(epoch_record)
}

/// Validate and apply the canonical sync/import block pipeline up to, but not
/// including, durable block/snapshot writes.
///
/// `import_block` calls this helper before storage append. Tests that need to
/// exercise hard-fork boundary behavior at synthetic heights use this same
/// path because `BlockStore` itself intentionally requires contiguous heights
/// from genesis and cannot be jumped to `u64::MAX - 1`.
fn validate_and_apply_imported_block(
    block: &BlockV1,
    state: &mut ChainState,
    mempool: &mut Mempool,
    timestamp_secs: u64,
) -> NodeResult<Option<EpochRecord>> {
    let height = block.header.height;

    if state.validators.active_count() > 0 {
        verify_proposer_vrf(block, state)?;
    }

    if height > 1 {
        verify_block_qc(block, state)?;
    }

    let projection = project_and_verify_block_state_root(block, state, timestamp_secs)?;
    #[cfg(debug_assertions)]
    let verified_state_root = projection.state_root;
    #[cfg(debug_assertions)]
    let verified_validator_set_root = projection.validator_set_root;
    #[cfg(debug_assertions)]
    let verified_value_hash = projection.value_hash;
    let epoch_record = projection.epoch_record;
    *state = projection.state;
    #[cfg(debug_assertions)]
    {
        let committed_roots = compute_state_roots(state);
        debug_assert_eq!(committed_roots.state_root, verified_state_root);
        debug_assert_eq!(
            committed_roots.validator_set_root,
            verified_validator_set_root
        );
        debug_assert_eq!(
            block.compute_value_hash(state.total_supply),
            verified_value_hash
        );
    }

    // Evict spent transactions from mempool after the verified projection has
    // become the real state.
    mempool.evict_spent(&state.nullifiers);
    mempool.evict_invalid(state);

    Ok(epoch_record)
}

pub(crate) fn verify_proposer_vrf(block: &BlockV1, state: &ChainState) -> NodeResult<()> {
    let (matched_validator_id, candidates, epoch_seed) =
        verify_proposer_vrf_key_ownership(block, state)?;

    if vrf_commit_reveal_election_active(block.header.height) {
        return verify_commit_reveal_proposer_result(block, matched_validator_id, state);
    }

    let election = ProposerElection {
        epoch_seed,
        height: block.header.height,
        round: block.header.proposer_round,
        candidates,
    };
    let elected = elect_proposer(&election, block.header.height).map_err(NodeError::Consensus)?;
    if matched_validator_id != elected {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "proposer VRF mismatch: block claims proposer {} but elected proposer is {} at height {} round {}",
                hex::encode(&matched_validator_id.0[..4]),
                hex::encode(&elected.0[..4]),
                block.header.height,
                block.header.proposer_round,
            ),
        });
    }

    Ok(())
}

fn verify_proposer_vrf_key_ownership(
    block: &BlockV1,
    state: &ChainState,
) -> NodeResult<(
    indra_core::Bytes32,
    Vec<ProposerCandidate>,
    indra_core::Bytes32,
)> {
    let proof_bytes = block.header.proposer_vrf_proof.as_slice();
    let output = block.header.proposer_vrf_output;

    if proof_bytes.is_empty() || output == indra_core::Bytes32::ZERO {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "missing proposer VRF proof/output at height {} round {}",
                block.header.height, block.header.proposer_round,
            ),
        });
    }

    let candidates: Vec<ProposerCandidate> = state
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

    if candidates.len() != state.validators.active_count() {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "VRF verification impossible at height {} round {}: {} validators have VRF keys but {} are active",
                block.header.height,
                block.header.proposer_round,
                candidates.len(),
                state.validators.active_count(),
            ),
        });
    }

    // Bind VRF verification to the block's declared parent hash so the
    // verifier uses the same epoch seed the proposer saw when building
    // this header, even if the local node's mutable state has moved.
    let epoch_seed = indra_core::types::primitives::Bytes32::from(indra_crypto::sha256(
        &block.header.prev_hash.0,
    ));
    let vrf_input = compute_vrf_input(
        &epoch_seed.0,
        block.header.height,
        block.header.proposer_round,
    );
    let proof = VrfProof(proof_bytes.to_vec());
    let output = VrfOutput(block.header.proposer_vrf_output.0);

    let matching_candidates: Vec<_> = candidates
        .iter()
        .filter(|candidate| vrf_verify(&candidate.vrf_pubkey, &vrf_input, &output, &proof).is_ok())
        .collect();

    if matching_candidates.len() != 1 {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "proposer VRF proof matched {} active validators at height {} round {}",
                matching_candidates.len(),
                block.header.height,
                block.header.proposer_round,
            ),
        });
    }

    Ok((matching_candidates[0].validator_id, candidates, epoch_seed))
}

fn verify_commit_reveal_proposer_result(
    block: &BlockV1,
    proposer_id: indra_core::Bytes32,
    state: &ChainState,
) -> NodeResult<()> {
    if reveal_set_commitment_active(block.header.height) {
        let result = verify_reveal_set_evidence(block, state)?;
        if result.elected_validator_id != proposer_id {
            return Err(NodeError::BlockInvalid {
                height: block.header.height,
                reason: format!(
                    "reveal-set election elected {} but proposer VRF proof belongs to {}",
                    hex::encode(&result.elected_validator_id.0[..4]),
                    hex::encode(&proposer_id.0[..4]),
                ),
            });
        }
        return Ok(());
    }

    let Some(header_hash) = block.header.election_result_hash else {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "missing election_result_hash for commit-reveal proposer election at height {} round {}",
                block.header.height, block.header.proposer_round,
            ),
        });
    };

    let normal = VrfElectionResult {
        height: block.header.height,
        round: block.header.proposer_round,
        elected_validator_id: proposer_id,
        elected_vrf_output: block.header.proposer_vrf_output,
        fallback_used: false,
        reveal_set_commitment: Bytes32::ZERO,
    }
    .hash();
    let fallback = VrfElectionResult {
        height: block.header.height,
        round: block.header.proposer_round,
        elected_validator_id: proposer_id,
        elected_vrf_output: VRF_FALLBACK_OUTPUT,
        fallback_used: true,
        reveal_set_commitment: Bytes32::ZERO,
    }
    .hash();

    if header_hash != normal && header_hash != fallback {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "election_result_hash {} does not certify proposer {} at height {} round {}",
                hex::encode(&header_hash.0[..4]),
                hex::encode(&proposer_id.0[..4]),
                block.header.height,
                block.header.proposer_round,
            ),
        });
    }

    Ok(())
}

/// Verify post-activation reveal-set evidence from block data alone.
///
/// This is the VRF-07 sync/audit path: it does not rely on having observed
/// the original live gossip. Evidence retention follows normal block-body
/// retention semantics.
pub(crate) fn verify_reveal_set_evidence(
    block: &BlockV1,
    state: &ChainState,
) -> NodeResult<VrfElectionResult> {
    let Some(header_hash) = block.header.election_result_hash else {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: "missing election_result_hash for reveal-set election".into(),
        });
    };

    let mut last_id = None;
    let mut revealed_outputs = std::collections::BTreeMap::new();
    let mut revealed_stake = 0u64;
    let epoch_seed = Bytes32::from(indra_crypto::sha256(&block.header.prev_hash.0));
    let vrf_input = compute_vrf_input(
        &epoch_seed.0,
        block.header.height,
        block.header.proposer_round,
    );

    for evidence in &block.vrf_reveals {
        if last_id.is_some_and(|previous| evidence.validator_id <= previous) {
            return Err(NodeError::BlockInvalid {
                height: block.header.height,
                reason: "vrf reveal evidence must be sorted by unique validator_id".into(),
            });
        }
        last_id = Some(evidence.validator_id);

        let Some(validator) = state.validators.get(&evidence.validator_id) else {
            return Err(NodeError::BlockInvalid {
                height: block.header.height,
                reason: format!(
                    "vrf reveal evidence references unknown validator {}",
                    hex::encode(&evidence.validator_id.0[..4]),
                ),
            });
        };
        if !validator.is_active() {
            return Err(NodeError::BlockInvalid {
                height: block.header.height,
                reason: format!(
                    "vrf reveal evidence references inactive validator {}",
                    hex::encode(&evidence.validator_id.0[..4]),
                ),
            });
        }
        let Some(vrf_pk) = validator.vrf_pk else {
            return Err(NodeError::BlockInvalid {
                height: block.header.height,
                reason: format!(
                    "vrf reveal evidence validator {} has no registered VRF key",
                    hex::encode(&evidence.validator_id.0[..4]),
                ),
            });
        };
        let output = VrfOutput(evidence.vrf_output.0);
        let proof = VrfProof(evidence.vrf_proof.as_slice().to_vec());
        vrf_verify(&vrf_pk, &vrf_input, &output, &proof).map_err(|_| NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "invalid VRF reveal proof for validator {}",
                hex::encode(&evidence.validator_id.0[..4]),
            ),
        })?;

        revealed_stake = revealed_stake.saturating_add(validator.stake_spark);
        revealed_outputs.insert(evidence.validator_id, evidence.vrf_output);
    }

    let candidates: Vec<_> = state
        .validators
        .active_validators()
        .filter_map(|validator| {
            validator.vrf_pk.map(|vrf_pubkey| ProposerCandidate {
                validator_id: validator.validator_id,
                vrf_pubkey,
                verified_vrf_output: None,
                stake: validator.stake_spark,
            })
        })
        .collect();
    if candidates.len() != state.validators.active_count() {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: "reveal-set election impossible: not every active validator has a VRF key"
                .into(),
        });
    }
    let election = ProposerElection {
        epoch_seed,
        height: block.header.height,
        round: block.header.proposer_round,
        candidates,
    };

    let total_stake = state.validators.total_active_stake();
    if total_stake == 0 || revealed_stake < bps_of(total_stake, CONSENSUS_QUORUM_BPS) {
        if block.vrf_reveals.is_empty() {
            let mut fallback =
                compute_fallback_election_result(&election).map_err(NodeError::Consensus)?;
            fallback.reveal_set_commitment = compute_reveal_set_commitment(&[]);
            if header_hash == fallback.hash() {
                let minimum_fallback_round = MAX_VRF_EMPTY_REVEAL_ROUNDS.saturating_sub(1);
                if block.header.proposer_round < minimum_fallback_round {
                    return Err(NodeError::BlockInvalid {
                        height: block.header.height,
                        reason: format!(
                            "fallback election claimed at round {} before minimum fallback round {}",
                            block.header.proposer_round, minimum_fallback_round,
                        ),
                    });
                }
                return Ok(fallback);
            }
        }

        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "vrf reveal set below quorum: revealed_stake={} total_stake={} quorum_bps={}",
                revealed_stake, total_stake, CONSENSUS_QUORUM_BPS,
            ),
        });
    }

    let mut result =
        elect_proposer_from_reveals(&election, &revealed_outputs).map_err(NodeError::Consensus)?;
    result.reveal_set_commitment = compute_reveal_set_commitment(&block.vrf_reveals);

    if header_hash != result.hash() {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "election_result_hash {} does not match reveal-set result {}",
                hex::encode(&header_hash.0[..4]),
                hex::encode(&result.hash().0[..4]),
            ),
        });
    }

    Ok(result)
}

pub(crate) fn verify_block_qc(block: &BlockV1, state: &ChainState) -> NodeResult<()> {
    if block.header.height <= 1 {
        return Ok(());
    }

    let qc_bytes = block.header.quorum_certificate.as_slice();
    if qc_bytes.is_empty() {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "missing quorum certificate at height {} — only block 1 may omit a QC",
                block.header.height,
            ),
        });
    }

    let mut reader = indra_core::codec::ByteReader::new(qc_bytes);
    let qc = indra_core::types::qc::QuorumCertificateV1::decode(&mut reader).map_err(|e| {
        NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!("invalid QC encoding: {e}"),
        }
    })?;

    let expected_qc_height = block.header.height.saturating_sub(1);
    if qc.height != expected_qc_height {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "embedded QC height {} does not match expected {}",
                qc.height, expected_qc_height,
            ),
        });
    }
    if qc.block_hash != block.header.prev_hash {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "embedded QC certifies block {} but parent is {} — QC must certify the exact parent block",
                hex::encode(&qc.block_hash.0[..8]),
                hex::encode(&block.header.prev_hash.0[..8]),
            ),
        });
    }

    let mut active_validators: Vec<_> = state.validators.active_validators().collect();
    active_validators.sort_by_key(|validator| validator.validator_id.0);

    let validators: Vec<QcValidator> = active_validators
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
        .collect();

    if validators.len() != state.validators.active_count() {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "QC verification impossible at height {}: {} validators have verification keys but {} are active",
                block.header.height,
                validators.len(),
                state.validators.active_count(),
            ),
        });
    }

    let total_stake = state.validators.total_active_stake();
    verify_qc_strict(&qc, &validators, total_stake, &state.chain_id).map_err(NodeError::Consensus)
}

pub(crate) struct VerifiedBlockProjection {
    pub(crate) state: ChainState,
    pub(crate) epoch_record: Option<EpochRecord>,
    // Retained for debug/test defense-in-depth assertions after committing the
    // verified projection. Release builds skip those assertions, so these fields
    // are intentionally release-dead even though the values are consumed when
    // debug assertions are enabled.
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    pub(crate) state_root: Bytes32,
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    pub(crate) validator_set_root: Bytes32,
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    pub(crate) value_hash: Bytes32,
}

pub(crate) fn project_and_verify_block_state_root(
    block: &BlockV1,
    pre_state: &ChainState,
    timestamp_secs: u64,
) -> NodeResult<VerifiedBlockProjection> {
    let expected_state_root = block.header.state_root;
    let expected_validator_root = block.header.validator_set_root;

    // Verify against a detached projected state first. The caller commits this
    // same projection only after all header commitments match, so import/replay
    // never applies the same block a second time.
    let mut projected = pre_state.clone();
    let epoch_record = apply_block(&mut projected, block, timestamp_secs).map_err(|e| {
        NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!("block failed during pre-apply root verification: {e}"),
        }
    })?;

    let actual_roots = compute_state_roots(&projected);
    if actual_roots.state_root != expected_state_root {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "state_root mismatch: expected {}, got {}",
                hex::encode(expected_state_root.0),
                hex::encode(actual_roots.state_root.0),
            ),
        });
    }

    if actual_roots.validator_set_root != expected_validator_root {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "validator_set_root mismatch: expected {}, got {}",
                hex::encode(expected_validator_root.0),
                hex::encode(actual_roots.validator_set_root.0),
            ),
        });
    }

    // Skip value_hash verification for legacy blocks produced before the
    // value_hash feature was introduced. These blocks store Bytes32::ZERO.
    let actual_value_hash = block.compute_value_hash(projected.total_supply);
    if block.header.value_hash != indra_core::Bytes32::ZERO
        && actual_value_hash != block.header.value_hash
    {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "value_hash mismatch: expected {}, got {}",
                hex::encode(block.header.value_hash.0),
                hex::encode(actual_value_hash.0),
            ),
        });
    }

    Ok(VerifiedBlockProjection {
        state: projected,
        epoch_record,
        state_root: actual_roots.state_root,
        validator_set_root: actual_roots.validator_set_root,
        value_hash: actual_value_hash,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn verify_block_state_root(block: &BlockV1, state: &ChainState) -> NodeResult<()> {
    project_and_verify_block_state_root(block, state, 0).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_consensus::{
        producer::{produce_block, BlockTemplate},
        proposer::{compute_proposer_vrf, elect_proposer, ProposerCandidate, ProposerElection},
        qc::build_qc,
        vote::produce_vote,
    };
    use indra_core::{
        codec::Encode,
        types::{
            block::{BlockHeaderV1, BlockV1},
            primitives::{
                BLOCK_PROTOCOL_VERSION_REVEAL_SET, DEFAULT_CHAIN_ID, EPOCH_DURATION_BLOCKS,
                MAX_VRF_PROOF_BYTES,
            },
            transaction::OutputV1,
            vote::VoteStep,
            vrf_election::{compute_reveal_set_commitment, VrfRevealEvidence},
        },
        Bytes32, CommitmentV1, HybridPubKey, ProtocolVersion, QuorumCertificateV1, VariableBytes,
    };
    use indra_crypto::{
        hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
        VrfKeypair,
    };
    use indra_state::{
        apply_block, compute_state_root, compute_state_roots, compute_validator_set_root,
        validator::StakeBondEntry, ValidatorEntry, ValidatorStatus,
    };
    use indra_storage::StateStore;
    use std::path::PathBuf;

    fn temp_dir(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_sync_test_{}_{}", suffix, std::process::id()));
        p
    }

    fn install_active_validator(
        state: &mut ChainState,
        seed: u8,
        stake: u64,
        with_vrf_key: bool,
        with_pq_key: bool,
    ) -> (Bytes32, HybridKeypair) {
        let classical = ClassicalKeypair::from_seed(&[seed; 32]);
        let pq = PqKeypair::from_seed(&[seed; 32]).unwrap();
        let hybrid = HybridKeypair::new(classical, pq);
        let public = hybrid.public_key();
        let vrf = VrfKeypair::from_seed(&[seed; 32]);
        let validator_id = Bytes32::from(indra_crypto::sha256(&public.classical.0));

        state
            .validators
            .upsert(ValidatorEntry {
                validator_id,
                name: format!("validator-{seed}"),
                hybrid_classical_pk: Some(public.classical.0),
                hybrid_pq_pk: with_pq_key.then(|| public.pq.0.to_vec()),
                vrf_pk: with_vrf_key.then(|| vrf.public_key()),
                stake_spark: stake,
                status: ValidatorStatus::Active,
                registered_epoch: 0,
                last_active_epoch: 0,
                pending_rewards: 0,
                rewards_last_epoch: 0,
                self_report_count: 0,
                commission_bps: indra_core::types::primitives::DEFAULT_COMMISSION_BPS,
                pending_commission_bps: None,
                pending_commission_effective_epoch: None,
                min_delegation_spark: indra_core::types::primitives::DUST_LIMIT_SPARK,
                auto_delegate_to: None,
                network_addr: None,
                network_addr_last_updated_epoch: None,
            })
            .unwrap();

        (validator_id, hybrid)
    }

    fn build_election(state: &ChainState, height: u64, round: u32) -> ProposerElection {
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
        ProposerElection {
            epoch_seed,
            height,
            round,
            candidates,
        }
    }

    fn elect_with_verified_output_for_seed(
        election: &ProposerElection,
        seed: u8,
    ) -> Option<Bytes32> {
        let keypair = VrfKeypair::from_seed(&[seed; 32]);
        let validator_id = election
            .candidates
            .iter()
            .find(|candidate| candidate.vrf_pubkey == keypair.public_key())?
            .validator_id;
        let elected = elect_proposer(election, election.height).ok()?;
        (elected == validator_id).then_some(elected)
    }

    fn make_strict_block(
        state: &ChainState,
        proposer_seed: u8,
        round: u32,
        prev_qc_bytes: Vec<u8>,
    ) -> BlockV1 {
        let election = build_election(state, state.height + 1, round);
        let proposer_vrf = VrfKeypair::from_seed(&[proposer_seed; 32]);
        let proposer_id = election
            .candidates
            .iter()
            .find(|candidate| candidate.vrf_pubkey == proposer_vrf.public_key())
            .expect("proposer must be in active validator set")
            .validator_id;
        let slot = compute_proposer_vrf(
            proposer_id,
            &proposer_vrf,
            &election.epoch_seed,
            election.height,
            election.round,
        );
        let election_result_hash = VrfElectionResult {
            height: election.height,
            round: election.round,
            elected_validator_id: proposer_id,
            elected_vrf_output: Bytes32::from(slot.vrf_output.0),
            fallback_used: false,
            reveal_set_commitment: Bytes32::ZERO,
        }
        .hash();
        let template = BlockTemplate {
            proposer_vrf_keypair: proposer_vrf,
            epoch_seed: election.epoch_seed,
            prev_qc_bytes,
            timestamp: 1_700_000_000u64.saturating_add(state.height.saturating_add(1)),
            polc_round: None,
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            election_result_hash: Some(election_result_hash),
            election_result: None,
            vrf_reveals: vec![],
        };
        let mut projection_state = state.clone();
        produce_block(
            &template,
            &mut projection_state,
            &Mempool::default_config(),
            &election,
        )
        .unwrap()
    }

    fn make_reveal_set_block(
        state: &ChainState,
        active_seeds: &[u8],
        reveal_seeds: &[u8],
    ) -> BlockV1 {
        make_reveal_set_block_at(state, u64::MAX, active_seeds, reveal_seeds)
    }

    fn make_reveal_set_block_at(
        state: &ChainState,
        height: u64,
        active_seeds: &[u8],
        reveal_seeds: &[u8],
    ) -> BlockV1 {
        make_reveal_set_block_at_round(state, height, 0, active_seeds, reveal_seeds)
    }

    fn make_reveal_set_block_at_round(
        state: &ChainState,
        height: u64,
        round: u32,
        active_seeds: &[u8],
        reveal_seeds: &[u8],
    ) -> BlockV1 {
        let election = build_election(state, height, round);
        let mut revealed_outputs = std::collections::BTreeMap::new();
        let mut evidence = Vec::new();

        for seed in reveal_seeds {
            let keypair = VrfKeypair::from_seed(&[*seed; 32]);
            let validator_id = election
                .candidates
                .iter()
                .find(|candidate| candidate.vrf_pubkey == keypair.public_key())
                .expect("reveal seed must belong to active validator set")
                .validator_id;
            let slot =
                compute_proposer_vrf(validator_id, &keypair, &election.epoch_seed, height, round);
            let vrf_output = Bytes32::from(slot.vrf_output.0);
            revealed_outputs.insert(validator_id, vrf_output);
            evidence.push(VrfRevealEvidence {
                validator_id,
                vrf_output,
                vrf_proof: VariableBytes::from_slice(&slot.vrf_proof.0).unwrap(),
            });
        }
        evidence.sort_by_key(|item| item.validator_id.0);

        let mut result = elect_proposer_from_reveals(&election, &revealed_outputs).unwrap();
        result.reveal_set_commitment = compute_reveal_set_commitment(&evidence);
        let proposer_seed = active_seeds
            .iter()
            .find(|seed| {
                let keypair = VrfKeypair::from_seed(&[**seed; 32]);
                election.candidates.iter().any(|candidate| {
                    candidate.validator_id == result.elected_validator_id
                        && candidate.vrf_pubkey == keypair.public_key()
                })
            })
            .copied()
            .expect("elected proposer must be among active test seeds");
        let proposer_keypair = VrfKeypair::from_seed(&[proposer_seed; 32]);
        let proposer_slot = compute_proposer_vrf(
            result.elected_validator_id,
            &proposer_keypair,
            &election.epoch_seed,
            height,
            round,
        );

        let mut block = BlockV1 {
            header: BlockHeaderV1 {
                protocol_version: ProtocolVersion(BLOCK_PROTOCOL_VERSION_REVEAL_SET),
                height,
                prev_hash: state.tip_hash,
                timestamp: 1_800_000_000,
                state_root: Bytes32::ZERO,
                validator_set_root: Bytes32::ZERO,
                mempool_set_root: Bytes32::ZERO,
                value_hash: Bytes32::ZERO,
                base_fee: state.base_fee,
                proposer_round: round,
                polc_round: indra_core::types::block::NO_POLC_ROUND,
                proposer_vrf_output: Bytes32::from(proposer_slot.vrf_output.0),
                proposer_vrf_proof: VariableBytes::from_slice(&proposer_slot.vrf_proof.0).unwrap(),
                quorum_certificate: VariableBytes::from_slice(&[]).unwrap(),
                election_result_hash: Some(result.hash()),
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            vrf_reveals: evidence,
        };

        if state.height.saturating_add(1) == block.header.height {
            let mut projected = state.clone();
            apply_block(&mut projected, &block, 0).unwrap();
            let roots = compute_state_roots(&projected);
            block.header.state_root = roots.state_root;
            block.header.validator_set_root = roots.validator_set_root;
            block.header.value_hash = block.compute_value_hash(projected.total_supply);
        }
        block
    }

    fn build_qc_bytes(
        height: u64,
        round: u32,
        value_hash: Bytes32,
        validator_id: Bytes32,
        hybrid: &HybridKeypair,
        pq_pk: Vec<u8>,
        stake: u64,
    ) -> Vec<u8> {
        let vote = produce_vote(
            height,
            round,
            VoteStep::Precommit,
            value_hash,
            validator_id,
            DEFAULT_CHAIN_ID,
            hybrid,
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
                pq_pk,
                classical_pk: hybrid.public_key().classical.0,
                stake,
            }],
            vec![&vote],
        )
        .unwrap();
        qc.encode_to_vec()
    }

    fn make_block(state: &ChainState) -> BlockV1 {
        let mut block = BlockV1 {
            header: BlockHeaderV1 {
                protocol_version: ProtocolVersion::CURRENT,
                height: state.height + 1,
                prev_hash: state.tip_hash,
                timestamp: 1_700_000_000 + state.height + 1,
                state_root: Bytes32::ZERO,
                validator_set_root: Bytes32::ZERO,
                mempool_set_root: Bytes32::ZERO,
                value_hash: Bytes32::ZERO,
                base_fee: state.base_fee,
                proposer_round: 0,
                polc_round: indra_core::types::block::NO_POLC_ROUND,
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof: VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
                quorum_certificate: indra_core::VariableBytes::from_slice(&[]).unwrap(),
                election_result_hash: None,
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            vrf_reveals: vec![],
        };

        let mut projected = state.clone();
        apply_block(&mut projected, &block, 0).unwrap();
        let roots = compute_state_roots(&projected);
        block.header.state_root = roots.state_root;
        block.header.validator_set_root = roots.validator_set_root;
        block.header.value_hash = block.compute_value_hash(projected.total_supply);
        block
    }

    fn reference_two_step_validate_and_apply(
        block: &BlockV1,
        state: &mut ChainState,
        mempool: &mut Mempool,
        timestamp_secs: u64,
    ) -> NodeResult<Option<EpochRecord>> {
        verify_block_state_root(block, state)?;
        let epoch_record =
            apply_block(state, block, timestamp_secs).map_err(|e| NodeError::BlockInvalid {
                height: block.header.height,
                reason: e.to_string(),
            })?;
        let _state_root = compute_state_root(state);
        mempool.evict_spent(&state.nullifiers);
        mempool.evict_invalid(state);
        Ok(epoch_record)
    }

    fn assert_import_state_equivalent(
        reference_state: &ChainState,
        actual_state: &ChainState,
        block: &BlockV1,
    ) {
        assert_eq!(reference_state, actual_state);
        assert_eq!(
            reference_state.encode_to_vec(),
            actual_state.encode_to_vec(),
            "canonical encoded state must remain byte-identical"
        );
        assert_eq!(
            compute_state_root(reference_state),
            compute_state_root(actual_state)
        );
        assert_eq!(
            compute_validator_set_root(reference_state),
            compute_validator_set_root(actual_state)
        );
        assert_eq!(
            block.compute_value_hash(reference_state.total_supply),
            block.compute_value_hash(actual_state.total_supply)
        );
    }

    #[test]
    fn import_single_block() {
        let dir = temp_dir("a");
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = ChainState::new_genesis();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(
            dir.join("blocks.log"),
            indra_storage::PruneConfig::archive(),
        )
        .unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        let block = make_block(&state);
        import_block(
            &block,
            &mut state,
            &mut mempool,
            &mut block_store,
            &state_store,
            0,
        )
        .unwrap();

        assert_eq!(state.height, 1);
        assert_eq!(block_store.len(), 2); // genesis (0) + block 1

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn imported_projection_commit_matches_reference_two_step_sequence() {
        let mut reference_state = ChainState::new_genesis();
        let (validator_id, hybrid) =
            install_active_validator(&mut reference_state, 0x61, 10_000, true, true);
        let mut actual_state = reference_state.clone();
        let mut reference_mempool = Mempool::default_config();
        let mut actual_mempool = Mempool::default_config();
        let mut prev_qc = Vec::new();

        for _ in 0..5 {
            let block = make_strict_block(&actual_state, 0x61, 0, prev_qc.clone());
            let reference_record = reference_two_step_validate_and_apply(
                &block,
                &mut reference_state,
                &mut reference_mempool,
                1_900_000_000,
            )
            .unwrap();
            let actual_record = validate_and_apply_imported_block(
                &block,
                &mut actual_state,
                &mut actual_mempool,
                1_900_000_000,
            )
            .unwrap();

            assert_eq!(reference_record, actual_record);
            assert_import_state_equivalent(&reference_state, &actual_state, &block);
            assert_eq!(reference_mempool.len(), actual_mempool.len());
            assert_eq!(reference_mempool.is_empty(), actual_mempool.is_empty());

            prev_qc = build_qc_bytes(
                block.header.height,
                block.header.proposer_round,
                block.header.block_hash(),
                validator_id,
                &hybrid,
                hybrid.public_key().pq.0.to_vec(),
                10_000,
            );
        }
    }

    #[test]
    fn optimized_import_projection_roots_match_old_two_call_reference() {
        let mut state = ChainState::new_genesis();
        let (validator_id, hybrid) = install_active_validator(&mut state, 0x71, 10_000, true, true);
        let mut prev_qc = Vec::new();

        for _ in 0..4 {
            let block = make_strict_block(&state, 0x71, 0, prev_qc.clone());
            let mut old_reference = state.clone();
            let old_epoch_record = apply_block(&mut old_reference, &block, 1_900_000_000).unwrap();
            let old_state_root = compute_state_root(&old_reference);
            let old_validator_set_root = compute_validator_set_root(&old_reference);
            let old_value_hash = block.compute_value_hash(old_reference.total_supply);

            let optimized =
                project_and_verify_block_state_root(&block, &state, 1_900_000_000).unwrap();
            assert_eq!(optimized.epoch_record, old_epoch_record);
            assert_eq!(optimized.state, old_reference);
            assert_eq!(optimized.state_root, old_state_root);
            assert_eq!(optimized.validator_set_root, old_validator_set_root);
            assert_eq!(optimized.value_hash, old_value_hash);

            state = optimized.state;
            prev_qc = build_qc_bytes(
                block.header.height,
                block.header.proposer_round,
                block.header.block_hash(),
                validator_id,
                &hybrid,
                hybrid.public_key().pq.0.to_vec(),
                10_000,
            );
        }
    }

    #[test]
    #[ignore = "realistic live-import root verification benchmark; run explicitly with --ignored --nocapture"]
    fn project_and_verify_block_state_root_realistic_benchmark() {
        use std::time::Instant;

        fn realistic_state(staked_bonds: usize) -> ChainState {
            let mut state = ChainState::new_genesis();
            let validator_id = Bytes32::from([0x75; 32]);
            let pq_pk = VariableBytes::from_slice(&vec![0x99; 2_592]).unwrap();
            let range_proof = VariableBytes::from_slice(&vec![0xAA; 674]).unwrap();
            for index in 0..staked_bonds {
                let mut id_bytes = [0u8; 32];
                for (dst, src) in id_bytes
                    .iter_mut()
                    .zip((index as u64).to_le_bytes().into_iter())
                {
                    *dst = src;
                }
                let utxo_id = Bytes32::from(id_bytes);
                state.staked_bonds.insert(
                    utxo_id,
                    StakeBondEntry {
                        utxo_id,
                        validator_id,
                        delegator_id: Bytes32::from([0x66; 32]),
                        amount_spark: 1_000,
                        bonded_epoch: 0,
                        unbonding_end_epoch: None,
                        original_output: OutputV1 {
                            value_spark: 1_000,
                            commitment: CommitmentV1 {
                                compressed_point: Bytes32::from([0x77; 32]),
                            },
                            owner_pubkey: HybridPubKey {
                                classical_pk: Bytes32::from([0x88; 32]),
                                pq_pk: pq_pk.clone(),
                            },
                            range_proof: range_proof.clone(),
                            lock_height: 0,
                        },
                    },
                );
            }
            state
        }

        for size in [100_000usize, 1_000_000usize] {
            let state = realistic_state(size);
            let mut block = make_block(&state);
            let mut expected_projection = state.clone();
            apply_block(&mut expected_projection, &block, 0).unwrap();
            let expected_roots = compute_state_roots(&expected_projection);
            block.header.state_root = expected_roots.state_root;
            block.header.validator_set_root = expected_roots.validator_set_root;
            block.header.value_hash = block.compute_value_hash(expected_projection.total_supply);

            let start = Instant::now();
            let mut old_projection = state.clone();
            let old_epoch_record = apply_block(&mut old_projection, &block, 0).unwrap();
            let old_state_root = compute_state_root(&old_projection);
            let old_validator_set_root = compute_validator_set_root(&old_projection);
            let old_value_hash = block.compute_value_hash(old_projection.total_supply);
            let old_elapsed = start.elapsed();

            let start = Instant::now();
            let optimized = project_and_verify_block_state_root(&block, &state, 0).unwrap();
            let optimized_elapsed = start.elapsed();

            assert_eq!(optimized.epoch_record, old_epoch_record);
            assert_eq!(optimized.state, old_projection);
            assert_eq!(optimized.state_root, old_state_root);
            assert_eq!(optimized.validator_set_root, old_validator_set_root);
            assert_eq!(optimized.value_hash, old_value_hash);
            println!(
                "project_and_verify_block_state_root_realistic size={size} old_two_call={old_elapsed:?} optimized_paired={optimized_elapsed:?}"
            );
        }
    }

    #[test]
    fn live_import_projection_commit_preserves_epoch_record_timestamp() {
        let mut state = ChainState::new_genesis();
        let (validator_id, hybrid) = install_active_validator(&mut state, 0x62, 10_000, true, true);
        state.height = EPOCH_DURATION_BLOCKS - 1;
        state.tip_hash = Bytes32::from([0xA5; 32]);

        let parent_qc = build_qc_bytes(
            state.height,
            0,
            state.tip_hash,
            validator_id,
            &hybrid,
            hybrid.public_key().pq.0.to_vec(),
            10_000,
        );
        let mut mempool = Mempool::default_config();
        let timestamp_secs = 1_999_999_999;
        let block = make_strict_block(&state, 0x62, 0, parent_qc);

        let record =
            validate_and_apply_imported_block(&block, &mut state, &mut mempool, timestamp_secs)
                .unwrap()
                .expect("height 300 must produce an epoch record");

        assert_eq!(block.header.height, EPOCH_DURATION_BLOCKS);
        assert_eq!(record.epoch, 0);
        assert_eq!(record.start_height, 0);
        assert_eq!(record.end_height, EPOCH_DURATION_BLOCKS - 1);
        assert_eq!(record.timestamp_secs, timestamp_secs);
        assert_eq!(state.height, EPOCH_DURATION_BLOCKS);
        assert_eq!(compute_state_root(&state), block.header.state_root);
    }

    #[test]
    fn failed_projection_root_mismatch_rolls_back_state_mempool_and_storage() {
        let dir = temp_dir("projection_root_rollback");
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = ChainState::new_genesis();
        let original_state = state.clone();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(
            dir.join("blocks.log"),
            indra_storage::PruneConfig::archive(),
        )
        .unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();
        let mut block = make_block(&state);
        block.header.state_root = Bytes32::from([0xEE; 32]);

        let err = import_block(
            &block,
            &mut state,
            &mut mempool,
            &mut block_store,
            &state_store,
            0,
        )
        .unwrap_err();

        match err {
            NodeError::BlockInvalid { reason, .. } => {
                assert!(
                    reason.contains("state_root mismatch"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(state, original_state);
        assert_eq!(mempool.len(), 0);
        assert!(block_store.is_empty());
        assert_eq!(state_store.latest_snapshot_height().unwrap(), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_projection_apply_error_rolls_back_state_mempool_and_storage() {
        let dir = temp_dir("projection_apply_rollback");
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = ChainState::new_genesis();
        let original_state = state.clone();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(
            dir.join("blocks.log"),
            indra_storage::PruneConfig::archive(),
        )
        .unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();
        let mut block = make_block(&state);
        block.header.prev_hash = Bytes32::from([0xAB; 32]);

        let err = import_block(
            &block,
            &mut state,
            &mut mempool,
            &mut block_store,
            &state_store,
            0,
        )
        .unwrap_err();

        match err {
            NodeError::BlockInvalid { reason, .. } => {
                assert!(
                    reason.contains("block failed during pre-apply root verification"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(state, original_state);
        assert_eq!(mempool.len(), 0);
        assert!(block_store.is_empty());
        assert_eq!(state_store.latest_snapshot_height().unwrap(), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn projected_verifier_preserves_root_error_strings() {
        let state = ChainState::new_genesis();

        let mut bad_state_root = make_block(&state);
        bad_state_root.header.state_root = Bytes32::from([0xE1; 32]);
        let err = verify_block_state_root(&bad_state_root, &state).unwrap_err();
        assert!(err.to_string().contains("state_root mismatch"));

        let mut bad_validator_root = make_block(&state);
        bad_validator_root.header.validator_set_root = Bytes32::from([0xE2; 32]);
        let err = verify_block_state_root(&bad_validator_root, &state).unwrap_err();
        assert!(err.to_string().contains("validator_set_root mismatch"));

        let mut bad_value_hash = make_block(&state);
        bad_value_hash.header.value_hash = Bytes32::from([0xE3; 32]);
        let err = verify_block_state_root(&bad_value_hash, &state).unwrap_err();
        assert!(err.to_string().contains("value_hash mismatch"));

        let mut apply_failure = make_block(&state);
        apply_failure.header.prev_hash = Bytes32::from([0xE4; 32]);
        let err = verify_block_state_root(&apply_failure, &state).unwrap_err();
        assert!(err
            .to_string()
            .contains("block failed during pre-apply root verification"));
    }

    #[test]
    #[ignore = "synthetic import projection clone-cost benchmark; run explicitly with --ignored --nocapture"]
    fn import_projection_clone_cost_benchmark() {
        use std::time::Instant;

        let sizes = std::env::var("INDRA_IMPORT_PROJECTION_BENCH_SIZES")
            .unwrap_or_else(|_| "100000".to_string())
            .split(',')
            .filter_map(|part| part.trim().parse::<usize>().ok())
            .collect::<Vec<_>>();

        eprintln!(
            "[import-projection-bench] original Step 0 baseline: normal import/commit ≈7 clone-equivalents, 1M delegators ≈11.6-11.9s"
        );
        eprintln!(
            "[import-projection-bench] Round A current baseline before this patch: empty import ≈3 clone-equivalents; after this patch: ≈2 clone-equivalents"
        );

        for size in sizes {
            let setup_start = Instant::now();
            let state = synthetic_delegation_state(size);
            let setup_elapsed = setup_start.elapsed();
            let block = make_block(&state);

            let mut reference_state = state.clone();
            let mut reference_mempool = Mempool::default_config();
            let reference_start = Instant::now();
            reference_two_step_validate_and_apply(
                &block,
                &mut reference_state,
                &mut reference_mempool,
                0,
            )
            .unwrap();
            let reference_elapsed = reference_start.elapsed();

            let mut optimized_state = state.clone();
            let mut optimized_mempool = Mempool::default_config();
            let optimized_start = Instant::now();
            validate_and_apply_imported_block(
                &block,
                &mut optimized_state,
                &mut optimized_mempool,
                0,
            )
            .unwrap();
            let optimized_elapsed = optimized_start.elapsed();

            assert_import_state_equivalent(&reference_state, &optimized_state, &block);
            eprintln!(
                "[import-projection-bench] delegators={size} setup={:?} reference_two_step_3clones={:?} optimized_single_projection_2clones={:?}",
                setup_elapsed, reference_elapsed, optimized_elapsed
            );
        }
    }

    fn synthetic_delegation_state(delegators: usize) -> ChainState {
        let mut state = ChainState::new_genesis();
        let buckets = delegators.clamp(1, 10_000);
        for index in 0..delegators {
            let bucket = index % buckets;
            let mut validator = [0u8; 32];
            validator[0] = 0xB0;
            validator[8..16].copy_from_slice(&(bucket as u64).to_be_bytes());
            let mut delegator = [0u8; 32];
            delegator[0] = 0xD0;
            delegator[8..16].copy_from_slice(&(index as u64).to_be_bytes());
            state
                .delegations
                .add_delegation(Bytes32::from(validator), Bytes32::from(delegator), 1_000, 0)
                .unwrap();
        }
        state
    }

    #[test]
    fn import_chain_of_blocks() {
        let dir = temp_dir("b");
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = ChainState::new_genesis();
        let _ = install_active_validator(&mut state, 0x41, 10_000, true, true);
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(
            dir.join("blocks.log"),
            indra_storage::PruneConfig::archive(),
        )
        .unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        let classical = indra_crypto::hybrid::ClassicalKeypair::from_seed(&[0x41; 32]);
        let pq = indra_crypto::hybrid::PqKeypair::from_seed(&[0x41; 32]).unwrap();
        let hybrid = indra_crypto::hybrid::HybridKeypair::new(classical, pq);
        let validator_id = Bytes32::from(indra_crypto::sha256(&hybrid.public_key().classical.0));
        let pq_pk = hybrid.public_key().pq.0.to_vec();
        let mut prev_qc = Vec::new();
        for i in 1..=10u64 {
            let block = make_strict_block(&state, 0x41, 0, prev_qc.clone());
            import_block(
                &block,
                &mut state,
                &mut mempool,
                &mut block_store,
                &state_store,
                0,
            )
            .unwrap();
            prev_qc = build_qc_bytes(
                block.header.height,
                block.header.proposer_round,
                block.header.block_hash(),
                validator_id,
                &hybrid,
                pq_pk.clone(),
                10_000,
            );
            assert_eq!(state.height, i);
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
        let mut block_store = BlockStore::open(
            dir.join("blocks.log"),
            indra_storage::PruneConfig::archive(),
        )
        .unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        // Try to import height 5 when we're at genesis (height 0)
        let mut block = make_block(&state);
        block.header.height = 5;
        assert!(import_block(
            &block,
            &mut state,
            &mut mempool,
            &mut block_store,
            &state_store,
            0
        )
        .is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sync_tracks_highest_known_peer_height() {
        let peer_a: SocketAddr = "127.0.0.1:30001".parse().unwrap();
        let peer_b: SocketAddr = "127.0.0.1:30002".parse().unwrap();
        let mut sync = SyncState::follower(0);

        assert_eq!(sync.observe_status(peer_a, 550, 0), Some((peer_a, 1, 50)));
        assert_eq!(sync.observe_status(peer_b, 8_314, 0), Some((peer_b, 1, 50)));

        for height in 1..=550 {
            sync.on_block_imported(height);
        }

        assert_eq!(
            sync.next_request_after_response(550),
            Some((peer_b, 551, 600))
        );
        assert!(!sync.is_caught_up());
    }

    #[test]
    fn follower_waits_for_first_peer_status() {
        let peer: SocketAddr = "127.0.0.1:30004".parse().unwrap();
        let mut sync = SyncState::follower(10);

        assert!(!sync.is_caught_up());
        assert_eq!(sync.observe_status(peer, 10, 10), None);
        assert!(sync.is_caught_up());
    }

    #[test]
    fn mark_caught_up_sets_received_peer_status() {
        let mut sync = SyncState::follower(0);

        assert!(
            !sync.is_caught_up(),
            "follower must not be caught up before receiving Status"
        );

        sync.mark_caught_up(1);

        assert!(
            sync.is_caught_up(),
            "follower must be caught up after mark_caught_up (block committed)"
        );
    }

    #[test]
    fn follower_not_caught_up_before_any_communication() {
        let sync = SyncState::follower(0);
        assert!(!sync.is_caught_up());
    }

    #[test]
    fn follower_caught_up_after_status_then_commit() {
        let mut sync = SyncState::follower(0);
        let peer: SocketAddr = "1.2.3.4:30303".parse().unwrap();

        sync.observe_status(peer, 0, 0);
        assert!(sync.is_caught_up());

        sync.mark_caught_up(1);
        assert!(sync.is_caught_up());
    }

    #[test]
    fn bootstrap_node_at_nonzero_height_waits_for_peer_status() {
        let peer: SocketAddr = "127.0.0.1:30005".parse().unwrap();
        let mut sync = SyncState::bootstrap(10);

        assert!(!sync.is_caught_up());
        assert_eq!(sync.observe_status(peer, 10, 10), None);
        assert!(sync.is_caught_up());
    }

    #[test]
    fn empty_block_response_does_not_stall_sync() {
        let peer: SocketAddr = "127.0.0.1:30006".parse().unwrap();
        let mut sync = SyncState::follower(10);

        assert_eq!(sync.observe_status(peer, 11, 10), Some((peer, 11, 11)));
        assert!(!sync.is_caught_up());

        sync.on_empty_response(10);
        assert!(sync.is_caught_up());
        assert!(sync.next_request_after_response(10).is_none());
    }

    #[test]
    fn one_block_behind_recovers_automatically() {
        let peer: SocketAddr = "127.0.0.1:30003".parse().unwrap();
        let mut sync = SyncState::follower(530);

        assert_eq!(sync.observe_status(peer, 531, 530), Some((peer, 531, 531)));
        assert!(!sync.is_caught_up());

        sync.on_block_imported(531);
        assert!(sync.is_caught_up());
        assert!(sync.next_request_after_response(531).is_none());
    }

    #[test]
    fn strict_block_one_accepts_empty_qc() {
        let mut state = ChainState::new_genesis();
        let (_validator_id, _hybrid) =
            install_active_validator(&mut state, 0x11, 10_000, true, true);
        let block = make_strict_block(&state, 0x11, 0, vec![]);

        assert!(verify_proposer_vrf(&block, &state).is_ok());
        assert!(verify_block_qc(&block, &state).is_ok());
        assert!(verify_block_state_root(&block, &state).is_ok());
    }

    #[test]
    fn strict_block_two_rejects_empty_qc() {
        let mut state = ChainState::new_genesis();
        let (_validator_id, _hybrid) =
            install_active_validator(&mut state, 0x12, 10_000, true, true);
        let block1 = make_strict_block(&state, 0x12, 0, vec![]);
        apply_block(&mut state, &block1, 0).unwrap();

        let block2 = make_strict_block(&state, 0x12, 0, vec![]);
        let err = verify_block_qc(&block2, &state).unwrap_err();
        match err {
            NodeError::BlockInvalid { reason, .. } => {
                assert!(reason.contains("missing quorum certificate"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_block_qc_rejects_wrong_height_qc() {
        let mut state = ChainState::new_genesis();
        let (validator_id, hybrid) = install_active_validator(&mut state, 0x14, 10_000, true, true);

        let block1 = make_strict_block(&state, 0x14, 0, vec![]);
        apply_block(&mut state, &block1, 0).unwrap();

        let wrong_qc_bytes = build_qc_bytes(
            3,
            block1.header.proposer_round,
            block1.header.block_hash(),
            validator_id,
            &hybrid,
            hybrid.public_key().pq.0.to_vec(),
            10_000,
        );
        let block2 = make_strict_block(&state, 0x14, 0, wrong_qc_bytes);

        let err = verify_block_qc(&block2, &state).unwrap_err();
        match err {
            NodeError::BlockInvalid { reason, .. } => {
                assert!(
                    reason.contains("embedded QC height 3 does not match expected 1"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_block_qc_rejects_qc_certifying_wrong_parent_hash() {
        let mut state = ChainState::new_genesis();
        let (validator_id, hybrid) = install_active_validator(&mut state, 0x15, 10_000, true, true);

        let block1 = make_strict_block(&state, 0x15, 0, vec![]);
        let wrong_parent_hash = Bytes32::from([0xB0; 32]);
        assert_ne!(wrong_parent_hash, block1.header.block_hash());
        apply_block(&mut state, &block1, 0).unwrap();

        let wrong_parent_qc_bytes = build_qc_bytes(
            block1.header.height,
            block1.header.proposer_round,
            wrong_parent_hash,
            validator_id,
            &hybrid,
            hybrid.public_key().pq.0.to_vec(),
            10_000,
        );
        let block2 = make_strict_block(&state, 0x15, 0, wrong_parent_qc_bytes);

        let err = verify_block_qc(&block2, &state).unwrap_err();
        match err {
            NodeError::BlockInvalid { reason, .. } => {
                assert!(
                    reason.contains("QC must certify the exact parent block"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_block_qc_accepts_qc_certifying_correct_parent_hash() {
        let mut state = ChainState::new_genesis();
        let (validator_id, hybrid) = install_active_validator(&mut state, 0x16, 10_000, true, true);

        let block1 = make_strict_block(&state, 0x16, 0, vec![]);
        apply_block(&mut state, &block1, 0).unwrap();

        let qc_bytes = build_qc_bytes(
            block1.header.height,
            block1.header.proposer_round,
            block1.header.block_hash(),
            validator_id,
            &hybrid,
            hybrid.public_key().pq.0.to_vec(),
            10_000,
        );
        let block2 = make_strict_block(&state, 0x16, 0, qc_bytes);

        assert!(verify_block_qc(&block2, &state).is_ok());
    }

    #[test]
    fn strict_qc_rejects_incomplete_validator_keys() {
        let mut state = ChainState::new_genesis();
        let (validator_id, hybrid) =
            install_active_validator(&mut state, 0x13, 10_000, true, false);
        let block1 = make_strict_block(&state, 0x13, 0, vec![]);
        let vote = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block1.header.block_hash(),
            validator_id,
            DEFAULT_CHAIN_ID,
            &hybrid,
        )
        .unwrap();

        let dummy_qc = QuorumCertificateV1 {
            height: 1,
            round: 0,
            block_hash: block1.header.block_hash(),
            election_result_hash: None,
            signer_bitfield: {
                let mut bf = [0u8; indra_core::types::qc::SIGNER_BITFIELD_BYTES];
                bf[0] = 1;
                bf
            },
            pq_signatures: vec![indra_core::types::crypto::PQVoteSig {
                validator_id,
                pq_sig: VariableBytes::from_slice(vote.signature.pq_sig.as_slice()).unwrap(),
            }],
            classical_signatures: vec![indra_core::types::qc::ClassicalVoteSig {
                validator_id,
                classical_sig: VariableBytes::from_slice(vote.signature.classical_sig.as_slice())
                    .unwrap(),
            }],
        };

        let mut state_after = state.clone();
        apply_block(&mut state_after, &block1, 0).unwrap();
        let block2 = make_strict_block(&state_after, 0x13, 0, dummy_qc.encode_to_vec());

        let err = verify_block_qc(&block2, &state_after).unwrap_err();
        match err {
            NodeError::BlockInvalid { reason, .. } => {
                assert!(reason.contains("QC verification impossible"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn strict_vrf_mismatch_is_rejected() {
        let mut state = ChainState::new_genesis();
        let (validator_a, _hybrid_a) =
            install_active_validator(&mut state, 0x21, 10_000, true, true);
        let (validator_b, _hybrid_b) =
            install_active_validator(&mut state, 0x22, 10_000, true, true);

        let mismatch_round = (0..32u32)
            .find(|round| {
                let election = build_election(&state, 1, *round);
                elect_with_verified_output_for_seed(&election, 0x22) == Some(validator_b)
                    && elect_with_verified_output_for_seed(&election, 0x21) != Some(validator_a)
            })
            .expect("expected a round won by B and not by tampered A");

        let mut tampered = make_strict_block(&state, 0x22, mismatch_round, vec![]);
        let election = build_election(&state, 1, mismatch_round);
        let slot = compute_proposer_vrf(
            validator_a,
            &VrfKeypair::from_seed(&[0x21; 32]),
            &election.epoch_seed,
            1,
            mismatch_round,
        );
        tampered.header.proposer_vrf_output = Bytes32::from(slot.vrf_output.0);
        tampered.header.proposer_vrf_proof = VariableBytes::from_slice(&slot.vrf_proof.0).unwrap();
        let err = verify_proposer_vrf(&tampered, &state).unwrap_err();
        match err {
            NodeError::BlockInvalid { reason, .. } => {
                assert!(reason.contains("election_result_hash"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn sync_verify_accepts_commit_reveal_header_hash_without_ephemeral_messages() {
        let mut state = ChainState::new_genesis();
        install_active_validator(&mut state, 0x41, 10_000, true, true);
        install_active_validator(&mut state, 0x42, 10_000, true, true);

        let round = 2u32;
        let winner_block = make_strict_block(&state, 0x41, round, vec![]);
        assert!(
            verify_proposer_vrf(&winner_block, &state).is_ok(),
            "sync proposer verification must not require ephemeral commit/reveal messages"
        );
    }

    #[test]
    fn sync_verify_rejects_tampered_election_result_hash() {
        let mut state = ChainState::new_genesis();
        install_active_validator(&mut state, 0x41, 10_000, true, true);

        let mut loser_block = make_strict_block(&state, 0x41, 2, vec![]);
        loser_block.header.election_result_hash = Some(Bytes32::from([0xEE; 32]));

        let err = verify_proposer_vrf(&loser_block, &state).unwrap_err();
        match err {
            NodeError::BlockInvalid { reason, .. } => {
                assert!(
                    reason.contains("election_result_hash"),
                    "unexpected rejection reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn strict_valid_block_with_vrf_qc_and_state_root_passes() {
        let mut state = ChainState::new_genesis();
        let (validator_id, hybrid) = install_active_validator(&mut state, 0x31, 10_000, true, true);

        let block1 = make_strict_block(&state, 0x31, 0, vec![]);
        let dir = temp_dir("strict_ok");
        std::fs::create_dir_all(&dir).unwrap();
        let mut block_store = BlockStore::open(
            dir.join("blocks.log"),
            indra_storage::PruneConfig::archive(),
        )
        .unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();
        let mut mempool = Mempool::default_config();
        import_block(
            &block1,
            &mut state,
            &mut mempool,
            &mut block_store,
            &state_store,
            0,
        )
        .unwrap();

        let pq_pk = hybrid.public_key().pq.0.to_vec();
        let qc_bytes = build_qc_bytes(
            block1.header.height,
            block1.header.proposer_round,
            block1.header.block_hash(),
            validator_id,
            &hybrid,
            pq_pk,
            10_000,
        );
        let block2 = make_strict_block(&state, 0x31, 0, qc_bytes);

        assert!(verify_proposer_vrf(&block2, &state).is_ok());
        assert!(verify_block_qc(&block2, &state).is_ok());
        assert!(verify_block_state_root(&block2, &state).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposal_reveal_set_below_quorum_rejected() {
        let mut state = ChainState::new_genesis();
        for seed in [0x51, 0x52, 0x53, 0x54] {
            install_active_validator(&mut state, seed, 10_000, true, true);
        }

        let block = make_reveal_set_block(&state, &[0x51, 0x52, 0x53, 0x54], &[0x51]);
        let err = verify_reveal_set_evidence(&block, &state).unwrap_err();

        match err {
            NodeError::BlockInvalid { reason, .. } => {
                assert!(
                    reason.contains("below quorum"),
                    "unexpected rejection reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn fallback_reveal_set_evidence_verifies_without_quorum() {
        let mut state = ChainState::new_genesis();
        for seed in [0x55, 0x56, 0x57, 0x58] {
            install_active_validator(&mut state, seed, 10_000, true, true);
        }

        let threshold_round = MAX_VRF_EMPTY_REVEAL_ROUNDS.saturating_sub(1);
        let block = make_reveal_set_block_at_round(
            &state,
            u64::MAX,
            threshold_round,
            &[0x55, 0x56, 0x57, 0x58],
            &[],
        );
        let result = verify_reveal_set_evidence(&block, &state).unwrap();

        assert!(result.fallback_used);
        assert_eq!(
            result.reveal_set_commitment,
            compute_reveal_set_commitment(&[]),
            "deterministic fallback is verified from the canonical empty reveal evidence set"
        );
        assert_eq!(Some(result.hash()), block.header.election_result_hash);
    }

    #[test]
    fn fallback_claim_below_round_threshold_rejected() {
        let mut state = ChainState::new_genesis();
        for seed in [0x59, 0x5A, 0x5B, 0x5C] {
            install_active_validator(&mut state, seed, 10_000, true, true);
        }

        let block =
            make_reveal_set_block_at_round(&state, u64::MAX, 0, &[0x59, 0x5A, 0x5B, 0x5C], &[]);
        let err = verify_reveal_set_evidence(&block, &state).unwrap_err();

        match err {
            NodeError::BlockInvalid { reason, .. } => {
                assert!(
                    reason.contains("before minimum fallback round"),
                    "unexpected rejection reason: {reason}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn fallback_claim_at_threshold_round_accepted() {
        let mut state = ChainState::new_genesis();
        for seed in [0x5D, 0x5E, 0x5F, 0x60] {
            install_active_validator(&mut state, seed, 10_000, true, true);
        }

        let threshold_round = MAX_VRF_EMPTY_REVEAL_ROUNDS.saturating_sub(1);
        let block = make_reveal_set_block_at_round(
            &state,
            u64::MAX,
            threshold_round,
            &[0x5D, 0x5E, 0x5F, 0x60],
            &[],
        );
        let result = verify_reveal_set_evidence(&block, &state).unwrap();

        assert!(result.fallback_used);
        assert_eq!(result.round, threshold_round);
    }

    #[test]
    fn fallback_claim_above_threshold_round_accepted() {
        let mut state = ChainState::new_genesis();
        for seed in [0x65, 0x66, 0x67, 0x68] {
            install_active_validator(&mut state, seed, 10_000, true, true);
        }

        let threshold_round = MAX_VRF_EMPTY_REVEAL_ROUNDS.saturating_sub(1);
        let block = make_reveal_set_block_at_round(
            &state,
            u64::MAX,
            threshold_round.saturating_add(3),
            &[0x65, 0x66, 0x67, 0x68],
            &[],
        );
        let result = verify_reveal_set_evidence(&block, &state).unwrap();

        assert!(result.fallback_used);
        assert!(result.round > threshold_round);
    }

    #[test]
    fn reveal_set_evidence_durably_auditable_after_sync() {
        let mut state = ChainState::new_genesis();
        for seed in [0x61, 0x62, 0x63, 0x64] {
            install_active_validator(&mut state, seed, 10_000, true, true);
        }

        let block = make_reveal_set_block(&state, &[0x61, 0x62, 0x63, 0x64], &[0x61, 0x62, 0x63]);

        let result = verify_reveal_set_evidence(&block, &state).unwrap();
        assert_eq!(
            Some(result.hash()),
            block.header.election_result_hash,
            "synced block body must contain enough evidence to reconstruct the QC-attested election hash"
        );
        assert!(verify_proposer_vrf(&block, &state).is_ok());
    }

    #[test]
    fn voter_verifies_against_specified_set_not_local_view() {
        let mut state = ChainState::new_genesis();
        for seed in [0x71, 0x72, 0x73, 0x74] {
            install_active_validator(&mut state, seed, 10_000, true, true);
        }

        let specified =
            make_reveal_set_block(&state, &[0x71, 0x72, 0x73, 0x74], &[0x71, 0x72, 0x73]);
        let local_superset =
            make_reveal_set_block(&state, &[0x71, 0x72, 0x73, 0x74], &[0x71, 0x72, 0x73, 0x74]);

        assert_ne!(
            specified.header.election_result_hash, local_superset.header.election_result_hash,
            "test setup must model divergent local/proposer reveal views"
        );
        assert!(
            verify_reveal_set_evidence(&specified, &state).is_ok(),
            "verification must use the proposer-specified body set, not reject because a local superset would hash differently"
        );
    }

    #[test]
    fn activation_height_boundary_sync_compatible() {
        let mut state = ChainState::new_genesis();
        install_active_validator(&mut state, 0x81, 10_000, true, true);

        let pre_activation = make_strict_block(&state, 0x81, 0, vec![]);
        assert_eq!(
            pre_activation.header.protocol_version,
            ProtocolVersion::CURRENT
        );
        assert!(verify_proposer_vrf(&pre_activation, &state).is_ok());

        let post_activation = make_reveal_set_block(&state, &[0x81], &[0x81]);
        assert_eq!(
            post_activation.header.protocol_version,
            ProtocolVersion(BLOCK_PROTOCOL_VERSION_REVEAL_SET)
        );
        assert!(verify_reveal_set_evidence(&post_activation, &state).is_ok());
    }

    #[test]
    fn activation_height_boundary_import_pipeline_compatible() {
        let mut state = ChainState::new_genesis();
        let (validator_id, hybrid) = install_active_validator(&mut state, 0x91, 10_000, true, true);
        state.height = 5398;
        state.tip_hash = Bytes32::from([0x91; 32]);
        let mut mempool = Mempool::default_config();

        let parent_qc = build_qc_bytes(
            state.height,
            0,
            state.tip_hash,
            validator_id,
            &hybrid,
            hybrid.public_key().pq.0.to_vec(),
            10_000,
        );
        let pre_activation = make_strict_block(&state, 0x91, 0, parent_qc);
        assert_eq!(pre_activation.header.height, 5399);
        assert_eq!(
            pre_activation.header.protocol_version,
            ProtocolVersion::CURRENT
        );
        validate_and_apply_imported_block(&pre_activation, &mut state, &mut mempool, 0).unwrap();
        assert_eq!(state.height, 5399);

        let transition_qc = build_qc_bytes(
            pre_activation.header.height,
            pre_activation.header.proposer_round,
            pre_activation.header.block_hash(),
            validator_id,
            &hybrid,
            hybrid.public_key().pq.0.to_vec(),
            10_000,
        );
        let mut post_activation = make_reveal_set_block_at(&state, 5400, &[0x91], &[0x91]);
        post_activation.header.quorum_certificate =
            VariableBytes::from_slice(&transition_qc).unwrap();
        let mut projected = state.clone();
        apply_block(&mut projected, &post_activation, 0).unwrap();
        let roots = compute_state_roots(&projected);
        post_activation.header.state_root = roots.state_root;
        post_activation.header.validator_set_root = roots.validator_set_root;
        post_activation.header.value_hash =
            post_activation.compute_value_hash(projected.total_supply);
        assert_eq!(post_activation.header.height, 5400);
        assert_eq!(
            post_activation.header.protocol_version,
            ProtocolVersion(BLOCK_PROTOCOL_VERSION_REVEAL_SET)
        );

        validate_and_apply_imported_block(&post_activation, &mut state, &mut mempool, 0).unwrap();
        assert_eq!(
            state.height, 5400,
            "first post-activation block must pass the same import validate/apply pipeline"
        );
    }
}
