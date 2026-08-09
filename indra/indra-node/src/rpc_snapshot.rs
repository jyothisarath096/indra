//! Immutable, once-per-canonical-commit state published to RPC readers.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
};

use indra_core::types::{
    primitives::Bytes32,
    stake_position::{StakePositionV1, UnbondingTrancheV1},
};
use indra_state::{compute_state_root, ChainState};

/// Dedicated append-independent storage readers used by historical RPCs.
#[derive(Clone)]
pub struct RpcStorageReadHandles {
    /// Canonical block-log reader.
    pub blocks: indra_storage::BlockStoreReadHandle,
    /// Epoch-history reader.
    pub epochs: indra_storage::EpochStoreReadHandle,
}

/// Secondary indexes precomputed once when a canonical state is published.
#[derive(Debug, Default)]
pub struct RpcReadIndexes {
    /// Position identifiers grouped by principal owner.
    pub positions_by_owner: BTreeMap<Bytes32, Vec<Bytes32>>,
    /// Position identifiers grouped by validator.
    pub positions_by_validator: BTreeMap<Bytes32, Vec<Bytes32>>,
    /// Tranche identifiers grouped by parent position.
    pub tranches_by_position: BTreeMap<Bytes32, Vec<Bytes32>>,
    /// Tranche identifiers grouped by principal owner.
    pub tranches_by_owner: BTreeMap<Bytes32, Vec<Bytes32>>,
    /// Tranche identifiers grouped by validator.
    pub tranches_by_validator: BTreeMap<Bytes32, Vec<Bytes32>>,
    /// Position identifiers carrying rewards grouped by delegator.
    pub rewards_by_delegator: BTreeMap<Bytes32, Vec<Bytes32>>,
    /// Position identifiers carrying rewards grouped by validator.
    pub rewards_by_validator: BTreeMap<Bytes32, Vec<Bytes32>>,
}

/// Consistent immutable chain view used by all RPC read handlers.
#[derive(Debug)]
pub struct RpcReadSnapshot {
    chain: Arc<ChainState>,
    mempool_size: Arc<AtomicUsize>,
    pruned_mode: bool,
    lowest_block: u64,
    blocks_retained: usize,
    /// Canonical state root computed once at publication time.
    pub state_root: Bytes32,
    /// Read-optimized staking/reward indexes.
    pub indexes: RpcReadIndexes,
}

impl RpcReadSnapshot {
    /// Build a new immutable RPC snapshot from canonical state.
    pub fn build(
        state: &ChainState,
        mempool_size: Arc<AtomicUsize>,
        pruned_mode: bool,
        lowest_block: u64,
        blocks_retained: usize,
    ) -> Self {
        let chain = Arc::new(state.clone());
        let indexes = build_indexes(&chain);
        let state_root = compute_state_root(&chain);
        Self {
            chain,
            mempool_size,
            pruned_mode,
            lowest_block,
            blocks_retained,
            state_root,
            indexes,
        }
    }

    /// Canonical height represented by this snapshot.
    pub fn height(&self) -> u64 {
        self.chain.height
    }
}

impl indra_rpc::handlers::RpcEngineView for RpcReadSnapshot {
    fn chain_state(&self) -> &ChainState {
        &self.chain
    }

    fn mempool_size(&self) -> usize {
        // Fast-changing pool metadata is supplied separately by the listener.
        self.mempool_size.load(Ordering::Relaxed)
    }

    fn pruned_mode(&self) -> bool {
        self.pruned_mode
    }

    fn lowest_block(&self) -> u64 {
        self.lowest_block
    }

    fn blocks_retained(&self) -> usize {
        self.blocks_retained
    }

    fn state_root(&self) -> Bytes32 {
        self.state_root
    }

    fn position_ids_by_owner(&self, owner: &Bytes32) -> Option<&[Bytes32]> {
        self.indexes
            .positions_by_owner
            .get(owner)
            .map(Vec::as_slice)
    }

    fn position_ids_by_validator(&self, validator: &Bytes32) -> Option<&[Bytes32]> {
        self.indexes
            .positions_by_validator
            .get(validator)
            .map(Vec::as_slice)
    }

    fn tranche_ids_by_position(&self, position: &Bytes32) -> Option<&[Bytes32]> {
        self.indexes
            .tranches_by_position
            .get(position)
            .map(Vec::as_slice)
    }

    fn tranche_ids_by_owner(&self, owner: &Bytes32) -> Option<&[Bytes32]> {
        self.indexes.tranches_by_owner.get(owner).map(Vec::as_slice)
    }

    fn tranche_ids_by_validator(&self, validator: &Bytes32) -> Option<&[Bytes32]> {
        self.indexes
            .tranches_by_validator
            .get(validator)
            .map(Vec::as_slice)
    }

    fn reward_ids_by_delegator(&self, delegator: &Bytes32) -> Option<&[Bytes32]> {
        self.indexes
            .rewards_by_delegator
            .get(delegator)
            .map(Vec::as_slice)
    }

    fn reward_ids_by_validator(&self, validator: &Bytes32) -> Option<&[Bytes32]> {
        self.indexes
            .rewards_by_validator
            .get(validator)
            .map(Vec::as_slice)
    }
}

/// Atomically published immutable RPC state. Readers hold the lock only for
/// the duration of an `Arc::clone`.
#[derive(Debug, Clone)]
pub struct RpcSnapshotPublisher {
    current: Arc<RwLock<Arc<RpcReadSnapshot>>>,
    mempool_size: Arc<AtomicUsize>,
}

impl RpcSnapshotPublisher {
    /// Create a publisher initialized from canonical state.
    pub fn new(
        state: &ChainState,
        mempool_size: usize,
        pruned_mode: bool,
        lowest_block: u64,
        blocks_retained: usize,
    ) -> Self {
        let mempool_size = Arc::new(AtomicUsize::new(mempool_size));
        Self {
            current: Arc::new(RwLock::new(Arc::new(RpcReadSnapshot::build(
                state,
                Arc::clone(&mempool_size),
                pruned_mode,
                lowest_block,
                blocks_retained,
            )))),
            mempool_size,
        }
    }

    /// Obtain a consistent snapshot without touching the consensus mutex.
    pub fn load(&self) -> Arc<RpcReadSnapshot> {
        let snapshot = self
            .current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(&snapshot)
    }

    /// Build and publish the state following a successful canonical commit.
    pub fn publish(
        &self,
        state: &ChainState,
        mempool_size: usize,
        pruned_mode: bool,
        lowest_block: u64,
        blocks_retained: usize,
    ) {
        let next = Arc::new(RpcReadSnapshot::build(
            state,
            Arc::clone(&self.mempool_size),
            pruned_mode,
            lowest_block,
            blocks_retained,
        ));
        let mut current = self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *current = next;
        self.mempool_size.store(mempool_size, Ordering::Relaxed);
    }

    /// Publish fast-changing transaction-pool size without rebuilding chain state.
    pub fn set_mempool_size(&self, size: usize) {
        self.mempool_size.store(size, Ordering::Relaxed);
    }
}

fn build_indexes(state: &ChainState) -> RpcReadIndexes {
    let mut indexes = RpcReadIndexes::default();
    for (position_id, position) in &state.stake_positions {
        index_position(&mut indexes, *position_id, position);
    }
    for (tranche_id, tranche) in &state.unbonding_tranches {
        index_tranche(&mut indexes, state, *tranche_id, tranche);
    }
    indexes
}

fn index_position(indexes: &mut RpcReadIndexes, id: Bytes32, position: &StakePositionV1) {
    indexes
        .positions_by_owner
        .entry(position.principal_owner_id)
        .or_default()
        .push(id);
    indexes
        .positions_by_validator
        .entry(position.validator_id)
        .or_default()
        .push(id);
    if position.principal_owner_id != position.validator_id {
        indexes
            .rewards_by_validator
            .entry(position.validator_id)
            .or_default()
            .push(id);
    }
    if position.pending_rewards_spark > 0 && position.principal_owner_id != position.validator_id {
        indexes
            .rewards_by_delegator
            .entry(position.principal_owner_id)
            .or_default()
            .push(id);
    }
}

fn index_tranche(
    indexes: &mut RpcReadIndexes,
    state: &ChainState,
    id: Bytes32,
    tranche: &UnbondingTrancheV1,
) {
    indexes
        .tranches_by_position
        .entry(tranche.position_id)
        .or_default()
        .push(id);
    if let Some(position) = state.stake_positions.get(&tranche.position_id) {
        indexes
            .tranches_by_owner
            .entry(position.principal_owner_id)
            .or_default()
            .push(id);
        indexes
            .tranches_by_validator
            .entry(position.validator_id)
            .or_default()
            .push(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_is_prior_or_new_and_never_torn() {
        let old = ChainState::new_genesis();
        let publisher = RpcSnapshotPublisher::new(&old, 0, false, 0, 0);
        let held_old = publisher.load();
        let mut new = old.clone();
        new.height = 7;
        new.base_fee = 99;
        publisher.publish(&new, 0, false, 0, 0);
        let held_new = publisher.load();
        assert_eq!(
            (held_old.height(), held_old.chain.base_fee),
            (0, old.base_fee)
        );
        assert_eq!((held_new.height(), held_new.chain.base_fee), (7, 99));
    }
}
