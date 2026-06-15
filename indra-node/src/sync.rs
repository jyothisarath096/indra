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

use indra_core::types::block::BlockV1;
use indra_core::codec::Decode;
use indra_state::{apply_block, ChainState};
use indra_consensus::mempool::Mempool;
use indra_storage::{BlockStore, StateStore};
use indra_storage::state_store::SNAPSHOT_INTERVAL;
use indra_consensus::{
    proposer::{
        ProposerCandidate, ProposerElection, compute_vrf_input, elect_proposer,
    },
    qc::{QcValidator, verify_qc, verify_qc_strict},
};
use indra_crypto::{VrfOutput, VrfProof, vrf_verify};

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
}

impl SyncState {
    /// Create the bootstrap node sync state.
    pub fn bootstrap(local_height: u64) -> Self {
        Self {
            phase: SyncPhase::CaughtUp,
            best_peer_height: local_height,
        }
    }

    /// Create the follower node sync state.
    pub fn follower(local_height: u64) -> Self {
        Self {
            phase: SyncPhase::AwaitingPeers,
            best_peer_height: local_height,
        }
    }

    /// Return the current phase.
    pub fn phase(&self) -> &SyncPhase {
        &self.phase
    }

    /// True when the node may participate in consensus.
    pub fn is_caught_up(&self) -> bool {
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
        self.best_peer_height = self.best_peer_height.max(peer_height);
        let catchup_threshold = self.best_peer_height.saturating_sub(2);

        if local_height >= catchup_threshold {
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
    pub fn on_block_imported(
        &mut self,
        imported_height: u64,
    ) {
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
            if imported_height >= self.best_peer_height.saturating_sub(2) {
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
                if local_height >= self.best_peer_height.saturating_sub(2) {
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

    /// Reset round state after catching up to a new height.
    pub fn mark_caught_up(&mut self, local_height: u64) {
        self.best_peer_height = self.best_peer_height.max(local_height);
        self.phase = SyncPhase::CaughtUp;
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
    strict_header_verification: bool,
) -> NodeResult<()> {
    let height = block.header.height;

    if state.validators.active_count() > 0 {
        verify_proposer_vrf(block, state, strict_header_verification)?;
    }

    if height > 1 {
        verify_block_qc(block, state, strict_header_verification)?;
    }

    verify_block_state_root(block, state, strict_header_verification)?;

    // 1. Apply block to state (validates everything)
    apply_block(state, block).map_err(|e| NodeError::BlockInvalid {
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

    // 5. Take snapshot if on interval
    if height > 0 && height.is_multiple_of(SNAPSHOT_INTERVAL) {
        state_store.save(state)?;
    }

    Ok(())
}

pub(crate) fn verify_proposer_vrf(
    block: &BlockV1,
    state: &ChainState,
    strict: bool,
) -> NodeResult<()> {
    let proof_bytes = block.header.proposer_vrf_proof.as_slice();
    let output = block.header.proposer_vrf_output;

    if proof_bytes.is_empty() || output == indra_core::Bytes32::ZERO {
        if strict {
            return Err(NodeError::BlockInvalid {
                height: block.header.height,
                reason: "missing proposer VRF proof/output".to_string(),
            });
        }
        eprintln!(
            "[sync] warning: skipping proposer VRF verification at height {} because the header uses placeholder VRF fields",
            block.header.height
        );
        return Ok(());
    }

    let candidates: Vec<ProposerCandidate> = state.validators.active_validators()
        .filter_map(|validator| validator.vrf_pk.map(|vrf_pk| ProposerCandidate {
            validator_id: validator.validator_id,
            vrf_pubkey: vrf_pk,
            stake: validator.stake_spark,
        }))
        .collect();

    if candidates.len() != state.validators.active_count() {
        if strict {
            return Err(NodeError::BlockInvalid {
                height: block.header.height,
                reason: "active validator set is missing VRF public keys".to_string(),
            });
        }
        eprintln!(
            "[sync] warning: skipping proposer VRF verification at height {} because validator VRF keys are incomplete",
            block.header.height
        );
        return Ok(());
    }

    // Bind VRF verification to the block's declared parent hash so the
    // verifier uses the same epoch seed the proposer saw when building
    // this header, even if the local node's mutable state has moved.
    let epoch_seed = indra_core::types::primitives::Bytes32::from(
        indra_crypto::sha256(&block.header.prev_hash.0)
    );
    let vrf_input = compute_vrf_input(&epoch_seed.0, block.header.height, block.header.proposer_round);
    let proof = VrfProof(proof_bytes.to_vec());
    let output = VrfOutput(block.header.proposer_vrf_output.0);

    let matching_candidates: Vec<_> = candidates.iter()
        .filter(|candidate| vrf_verify(&candidate.vrf_pubkey, &vrf_input, &output, &proof).is_ok())
        .collect();

    if matching_candidates.len() != 1 {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: "proposer VRF proof does not match exactly one active validator".to_string(),
        });
    }

    let matched_validator_id = matching_candidates[0].validator_id;
    let election = ProposerElection {
        epoch_seed,
        height: block.header.height,
        round: block.header.proposer_round,
        candidates,
    };
    let elected = elect_proposer(&election).map_err(NodeError::Consensus)?;
    if matched_validator_id != elected {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: "block was proposed by a validator that did not win the slot".to_string(),
        });
    }

    Ok(())
}

fn verify_block_qc(
    block: &BlockV1,
    state: &ChainState,
    strict: bool,
) -> NodeResult<()> {
    let qc_bytes = block.header.quorum_certificate.as_slice();
    if qc_bytes.is_empty() {
        if strict {
            return Err(NodeError::BlockInvalid {
                height: block.header.height,
                reason: "missing quorum certificate".to_string(),
            });
        }
        eprintln!(
            "[sync] warning: skipping QC verification at height {} because the header carries an empty QC",
            block.header.height
        );
        return Ok(());
    }

    let mut reader = indra_core::codec::ByteReader::new(qc_bytes);
    let qc = indra_core::types::qc::QuorumCertificateV1::decode(&mut reader).map_err(|e| {
        NodeError::BlockInvalid {
            height: block.header.height,
            reason: format!("invalid QC encoding: {e}"),
        }
    })?;

    let mut active_validators: Vec<_> = state.validators.active_validators().collect();
    active_validators.sort_by_key(|validator| validator.validator_id.0);

    let validators: Vec<QcValidator> = active_validators.into_iter()
        .enumerate()
        .filter_map(|(position, validator)| Some(QcValidator {
            validator_id: validator.validator_id,
            position,
            pq_pk: validator.hybrid_pq_pk.clone()?,
            stake: validator.stake_spark,
        }))
        .collect();

    if validators.len() != state.validators.active_count() {
        if strict {
            return Err(NodeError::BlockInvalid {
                height: block.header.height,
                reason: "active validator set is missing QC verification keys".to_string(),
            });
        }
        eprintln!(
            "[sync] warning: skipping QC verification at height {} because validator verification keys are incomplete",
            block.header.height
        );
        return Ok(());
    }

    let total_stake = state.validators.total_active_stake();
    let result = if strict {
        verify_qc_strict(&qc, &validators, total_stake)
    } else {
        verify_qc(&qc, &validators, total_stake)
    };
    result.map_err(NodeError::Consensus)
}

fn verify_block_state_root(
    block: &BlockV1,
    state: &ChainState,
    _strict: bool,
) -> NodeResult<()> {
    let expected_state_root = block.header.state_root;
    let expected_validator_root = block.header.validator_set_root;

    let mut projected = state.clone();
    apply_block(&mut projected, block).map_err(|e| NodeError::BlockInvalid {
        height: block.header.height,
        reason: format!("block failed during pre-apply root verification: {e}"),
    })?;

    let actual_state_root = compute_state_root(&projected);
    if actual_state_root != expected_state_root {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: "state_root mismatch".to_string(),
        });
    }

    let actual_validator_root = compute_validator_set_root(&projected);
    if actual_validator_root != expected_validator_root {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: "validator_set_root mismatch".to_string(),
        });
    }

    let actual_value_hash = block.compute_value_hash(projected.total_supply);
    if actual_value_hash != block.header.value_hash {
        return Err(NodeError::BlockInvalid {
            height: block.header.height,
            reason: "value_hash mismatch".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        Bytes32, ProtocolVersion, VariableBytes,
        types::{
            block::{BlockHeaderV1, BlockV1},
            primitives::MAX_VRF_PROOF_BYTES,
        },
    };
    use indra_state::{apply_block, compute_state_root, compute_validator_set_root};
    use indra_storage::StateStore;
    use std::path::PathBuf;

    fn temp_dir(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_sync_test_{}_{}", suffix, std::process::id()));
        p
    }

    fn make_block(state: &ChainState) -> BlockV1 {
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
    fn import_single_block() {
        let dir = temp_dir("a");
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = ChainState::new_genesis();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(
            dir.join("blocks.log"),
            indra_storage::PruneConfig::archive(),
        ).unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        let block = make_block(&state);
        import_block(&block, &mut state, &mut mempool, &mut block_store, &state_store, false).unwrap();

        assert_eq!(state.height, 1);
        assert_eq!(block_store.len(), 2); // genesis (0) + block 1

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_chain_of_blocks() {
        let dir = temp_dir("b");
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = ChainState::new_genesis();
        let mut mempool = Mempool::default_config();
        let mut block_store = BlockStore::open(
            dir.join("blocks.log"),
            indra_storage::PruneConfig::archive(),
        ).unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        for i in 1..=10u64 {
            let block = make_block(&state);
            import_block(&block, &mut state, &mut mempool, &mut block_store, &state_store, false).unwrap();
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
        ).unwrap();
        let state_store = StateStore::open(dir.join("state")).unwrap();

        // Try to import height 5 when we're at genesis (height 0)
        let mut block = make_block(&state);
        block.header.height = 5;
        assert!(import_block(&block, &mut state, &mut mempool, &mut block_store, &state_store, false).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
