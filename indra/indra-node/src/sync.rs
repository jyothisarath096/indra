//! Block import and chain sync.
//!
//! `import_block` is the single entry point for adding a block to the chain.
//! It:
//!   1. Validates the block's structural invariants
//!   2. Applies it to the chain state via `apply_block`
//!   3. Computes and stores the new state root
//!   4. Writes the block to the block store
//!   5. Evicts spent transactions from the mempool
//!   6. Optionally takes a state snapshot

use std::net::SocketAddr;

use indra_consensus::mempool::Mempool;
use indra_consensus::{
    proposer::{compute_vrf_input, elect_proposer, ProposerCandidate, ProposerElection},
    qc::{verify_qc_strict, QcValidator},
};
use indra_core::codec::Decode;
use indra_core::types::block::BlockV1;
use indra_core::EpochRecord;
use indra_crypto::{vrf_verify, VrfOutput, VrfProof};
use indra_state::{apply_block, ChainState};
use indra_storage::state_store::SNAPSHOT_INTERVAL;
use indra_storage::{BlockStore, StateStore};

use crate::{
    error::{NodeError, NodeResult},
    state_root::{compute_state_root, compute_validator_set_root},
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
/// validate → apply → store → evict mempool → snapshot.
pub fn import_block(
    block: &BlockV1,
    state: &mut ChainState,
    mempool: &mut Mempool,
    block_store: &mut BlockStore,
    state_store: &StateStore,
    timestamp_secs: u64,
) -> NodeResult<Option<EpochRecord>> {
    let height = block.header.height;

    if state.validators.active_count() > 0 {
        verify_proposer_vrf(block, state)?;
    }

    if height > 1 {
        verify_block_qc(block, state)?;
    }

    verify_block_state_root(block, state)?;

    // 1. Apply block to state (validates everything)
    let epoch_record =
        apply_block(state, block, timestamp_secs).map_err(|e| NodeError::BlockInvalid {
            height,
            reason: e.to_string(),
        })?;

    // 2. Compute state root and store it in the state
    //    (the block header's state_root is checked against this in Phase 6)
    let _state_root = compute_state_root(state);

    // 3. Store genesis placeholder if block_store is empty and this is height 1
    if block_store.is_empty() && height == 1 {
        let genesis = crate::genesis::build_genesis_block();
        block_store.append(&genesis)?;
    }
    block_store.append(block)?;

    // 4. Evict spent transactions from mempool
    mempool.evict_spent(&state.nullifiers);
    mempool.evict_invalid(state);

    // 5. Take snapshot if on interval
    if height > 0 && height.is_multiple_of(SNAPSHOT_INTERVAL) {
        state_store.save(state)?;
    }

    Ok(epoch_record)
}

pub(crate) fn verify_proposer_vrf(block: &BlockV1, state: &ChainState) -> NodeResult<()> {
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

    let mut candidates: Vec<ProposerCandidate> = state
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

    let matched_validator_id = matching_candidates[0].validator_id;
    for candidate in &mut candidates {
        if candidate.validator_id == matched_validator_id {
            candidate.verified_vrf_output = Some(output.clone());
        }
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

fn verify_block_qc(block: &BlockV1, state: &ChainState) -> NodeResult<()> {
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
    verify_qc_strict(&qc, &validators, total_stake).map_err(NodeError::Consensus)
}

fn verify_block_state_root(block: &BlockV1, state: &ChainState) -> NodeResult<()> {
    let expected_state_root = block.header.state_root;
    let expected_validator_root = block.header.validator_set_root;

    // Intentionally verify against a cloned projected state first. Sync then
    // applies the same block a second time inside `import_block` to mutate the
    // real chain state only after all header commitments match.
    let mut projected = state.clone();
    apply_block(&mut projected, block, 0).map_err(|e| NodeError::BlockInvalid {
        height: block.header.height,
        reason: format!("block failed during pre-apply root verification: {e}"),
    })?;

    let actual_state_root = compute_state_root(&projected);
    if actual_state_root != expected_state_root {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "state_root mismatch: expected {}, got {}",
                hex::encode(expected_state_root.0),
                hex::encode(actual_state_root.0),
            ),
        });
    }

    let actual_validator_root = compute_validator_set_root(&projected);
    if actual_validator_root != expected_validator_root {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!(
                "validator_set_root mismatch: expected {}, got {}",
                hex::encode(expected_validator_root.0),
                hex::encode(actual_validator_root.0),
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

    Ok(())
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
            primitives::MAX_VRF_PROOF_BYTES,
            vote::VoteStep,
        },
        Bytes32, ProtocolVersion, QuorumCertificateV1, VariableBytes,
    };
    use indra_crypto::{
        hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
        VrfKeypair,
    };
    use indra_state::{
        apply_block, compute_state_root, compute_validator_set_root, ValidatorEntry,
        ValidatorStatus,
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
                min_delegation_spark: indra_core::types::primitives::DUST_LIMIT_SPARK,
                auto_delegate_to: None,
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
        let slot = compute_proposer_vrf(
            validator_id,
            &keypair,
            &election.epoch_seed,
            election.height,
            election.round,
        );
        let mut effective = ProposerElection {
            epoch_seed: election.epoch_seed,
            height: election.height,
            round: election.round,
            candidates: election.candidates.clone(),
        };
        if let Some(candidate) = effective
            .candidates
            .iter_mut()
            .find(|candidate| candidate.validator_id == slot.proposer_id)
        {
            candidate.verified_vrf_output = Some(slot.vrf_output);
        }
        elect_proposer(&effective, effective.height).ok()
    }

    fn make_strict_block(
        state: &ChainState,
        proposer_seed: u8,
        round: u32,
        prev_qc_bytes: Vec<u8>,
    ) -> BlockV1 {
        let election = build_election(state, state.height + 1, round);
        let template = BlockTemplate {
            proposer_vrf_keypair: VrfKeypair::from_seed(&[proposer_seed; 32]),
            epoch_seed: election.epoch_seed,
            prev_qc_bytes,
            timestamp: 1_700_000_000 + state.height + 1,
            polc_round: None,
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        };
        produce_block(&template, state, &Mempool::default_config(), &election).unwrap()
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
            hybrid,
        )
        .unwrap();
        let qc = build_qc(
            height,
            round,
            value_hash,
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
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        };

        let mut projected = state.clone();
        apply_block(&mut projected, &block, 0).unwrap();
        block.header.state_root = compute_state_root(&projected);
        block.header.validator_set_root = compute_validator_set_root(&projected);
        block.header.value_hash = block.compute_value_hash(projected.total_supply);
        block
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
            &hybrid,
        )
        .unwrap();

        let dummy_qc = QuorumCertificateV1 {
            height: 1,
            round: 0,
            block_hash: block1.header.block_hash(),
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
                assert!(reason.contains("proposer VRF mismatch"));
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
}
