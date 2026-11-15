//! Immutable, once-per-canonical-commit state published to RPC readers.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, RwLock,
};

use indra_core::types::{
    primitives::Bytes32,
    stake_position::{StakePositionV1, UnbondingTrancheV1},
};
use indra_state::{compute_state_root, ChainState, PersistentOrdMap};

/// Dedicated append-independent storage readers used by historical RPCs.
#[derive(Clone)]
pub struct RpcStorageReadHandles {
    /// Canonical block-log reader.
    pub blocks: indra_storage::BlockStoreReadHandle,
    /// Epoch-history reader.
    pub epochs: indra_storage::EpochStoreReadHandle,
}

/// Secondary indexes precomputed once when a canonical state is published.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RpcReadIndexes {
    /// Position identifiers grouped by principal owner.
    pub positions_by_owner: PersistentOrdMap<Bytes32, Vec<Bytes32>>,
    /// Position identifiers grouped by validator.
    pub positions_by_validator: PersistentOrdMap<Bytes32, Vec<Bytes32>>,
    /// Tranche identifiers grouped by parent position.
    pub tranches_by_position: PersistentOrdMap<Bytes32, Vec<Bytes32>>,
    /// Tranche identifiers grouped by principal owner.
    pub tranches_by_owner: PersistentOrdMap<Bytes32, Vec<Bytes32>>,
    /// Tranche identifiers grouped by validator.
    pub tranches_by_validator: PersistentOrdMap<Bytes32, Vec<Bytes32>>,
    /// Position identifiers carrying rewards grouped by delegator.
    pub rewards_by_delegator: PersistentOrdMap<Bytes32, Vec<Bytes32>>,
    /// Position identifiers carrying rewards grouped by validator.
    pub rewards_by_validator: PersistentOrdMap<Bytes32, Vec<Bytes32>>,
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
    ) -> Result<Self, String> {
        Self::build_with_index_timing(
            state,
            mempool_size,
            pruned_mode,
            lowest_block,
            blocks_retained,
        )
        .map(|built| built.0)
    }

    fn build_with_index_timing(
        state: &ChainState,
        mempool_size: Arc<AtomicUsize>,
        pruned_mode: bool,
        lowest_block: u64,
        blocks_retained: usize,
    ) -> Result<(Self, std::time::Duration), String> {
        let chain = Arc::new(state.clone());
        let index_started = std::time::Instant::now();
        let indexes = build_indexes(&chain);
        let index_rebuild_duration = index_started.elapsed();
        let state_root = compute_state_root(&chain).map_err(|error| error.to_string())?;
        Ok((
            Self {
                chain,
                mempool_size,
                pruned_mode,
                lowest_block,
                blocks_retained,
                state_root,
                indexes,
            },
            index_rebuild_duration,
        ))
    }

    fn build_incremental(
        previous: &RpcReadSnapshot,
        state: &ChainState,
        effects: &indra_state::CanonicalStateEffects,
        mempool_size: Arc<AtomicUsize>,
        pruned_mode: bool,
        lowest_block: u64,
        blocks_retained: usize,
    ) -> Result<Self, String> {
        let chain = Arc::new(state.clone());
        let mut indexes = previous.indexes.clone();
        for position_id in &effects.stake_positions_changed {
            if let Some(old) = previous.chain.stake_positions.get(position_id) {
                remove_value(
                    &mut indexes.positions_by_owner,
                    &old.principal_owner_id,
                    position_id,
                );
                remove_value(
                    &mut indexes.positions_by_validator,
                    &old.validator_id,
                    position_id,
                );
                remove_value(
                    &mut indexes.rewards_by_delegator,
                    &old.principal_owner_id,
                    position_id,
                );
                remove_value(
                    &mut indexes.rewards_by_validator,
                    &old.validator_id,
                    position_id,
                );
            }
            if let Some(position) = chain.stake_positions.get(position_id) {
                index_position(&mut indexes, *position_id, position);
            }
        }
        for position_id in &effects.position_tranche_capacity_changed_for {
            let old_ids = indexes
                .tranches_by_position
                .remove(position_id)
                .unwrap_or_default();
            for tranche_id in old_ids {
                if let Some(old_position) = previous.chain.stake_positions.get(position_id) {
                    remove_value(
                        &mut indexes.tranches_by_owner,
                        &old_position.principal_owner_id,
                        &tranche_id,
                    );
                    remove_value(
                        &mut indexes.tranches_by_validator,
                        &old_position.validator_id,
                        &tranche_id,
                    );
                }
            }
            {
                for tranche_id in chain.tranche_ids_for_position(position_id) {
                    if let Some(tranche) = chain.unbonding_tranches.get(tranche_id) {
                        index_tranche(&mut indexes, &chain, *tranche_id, tranche);
                    }
                }
            }
        }
        Ok(Self {
            state_root: compute_state_root(&chain).map_err(|error| error.to_string())?,
            chain,
            mempool_size,
            pruned_mode,
            lowest_block,
            blocks_retained,
            indexes,
        })
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

    fn state_root(&self) -> Result<Bytes32, String> {
        Ok(self.state_root)
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
    ) -> Result<Self, String> {
        let mempool_size = Arc::new(AtomicUsize::new(mempool_size));
        let (initial, index_rebuild_duration) = RpcReadSnapshot::build_with_index_timing(
            state,
            Arc::clone(&mempool_size),
            pruned_mode,
            lowest_block,
            blocks_retained,
        )?;
        eprintln!(
            "[rpc] startup secondary-index rebuild completed in {index_rebuild_duration:?} (positions={}, tranches={})",
            state.stake_positions.len(),
            state.unbonding_tranches.len()
        );
        Ok(Self {
            current: Arc::new(RwLock::new(Arc::new(initial))),
            mempool_size,
        })
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
    ) -> Result<(), String> {
        let next = Arc::new(RpcReadSnapshot::build(
            state,
            Arc::clone(&self.mempool_size),
            pruned_mode,
            lowest_block,
            blocks_retained,
        )?);
        let mut current = self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *current = next;
        self.mempool_size.store(mempool_size, Ordering::Relaxed);
        Ok(())
    }

    /// Incrementally update secondary indexes from canonical mutation effects.
    pub fn publish_with_effects(
        &self,
        state: &ChainState,
        effects: &indra_state::CanonicalStateEffects,
        mempool_size: usize,
        pruned_mode: bool,
        lowest_block: u64,
        blocks_retained: usize,
    ) -> Result<(), String> {
        let previous = self.load();
        let next = Arc::new(RpcReadSnapshot::build_incremental(
            &previous,
            state,
            effects,
            Arc::clone(&self.mempool_size),
            pruned_mode,
            lowest_block,
            blocks_retained,
        )?);
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = next;
        self.mempool_size.store(mempool_size, Ordering::Relaxed);
        Ok(())
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

fn remove_value(map: &mut PersistentOrdMap<Bytes32, Vec<Bytes32>>, key: &Bytes32, value: &Bytes32) {
    let Some(mut values) = map.get(key).cloned() else {
        return;
    };
    if let Ok(index) = values.binary_search(value) {
        values.remove(index);
    }
    if values.is_empty() {
        map.remove(key);
    } else {
        map.insert(*key, values);
    }
}

fn push_value(map: &mut PersistentOrdMap<Bytes32, Vec<Bytes32>>, key: Bytes32, value: Bytes32) {
    let mut values = map.get(&key).cloned().unwrap_or_default();
    match values.binary_search(&value) {
        Ok(_) => return,
        Err(index) => values.insert(index, value),
    }
    map.insert(key, values);
}

fn index_position(indexes: &mut RpcReadIndexes, id: Bytes32, position: &StakePositionV1) {
    push_value(
        &mut indexes.positions_by_owner,
        position.principal_owner_id,
        id,
    );
    push_value(
        &mut indexes.positions_by_validator,
        position.validator_id,
        id,
    );
    if position.principal_owner_id != position.validator_id {
        push_value(&mut indexes.rewards_by_validator, position.validator_id, id);
    }
    if position.pending_rewards_spark > 0 && position.principal_owner_id != position.validator_id {
        push_value(
            &mut indexes.rewards_by_delegator,
            position.principal_owner_id,
            id,
        );
    }
}

fn index_tranche(
    indexes: &mut RpcReadIndexes,
    state: &ChainState,
    id: Bytes32,
    tranche: &UnbondingTrancheV1,
) {
    push_value(&mut indexes.tranches_by_position, tranche.position_id, id);
    if let Some(position) = state.stake_positions.get(&tranche.position_id) {
        push_value(
            &mut indexes.tranches_by_owner,
            position.principal_owner_id,
            id,
        );
        push_value(
            &mut indexes.tranches_by_validator,
            position.validator_id,
            id,
        );
    }
}

#[cfg(test)]
mod tests {
    use indra_core::types::primitives::TEST_CHAIN_ID;
    use super::*;
    use indra_core::types::stake_position::{PositionCustodyV1, UnbondingTimingV1};
    use std::{
        collections::BTreeMap,
        time::{Duration, Instant},
    };

    fn numbered_id(number: u64) -> Bytes32 {
        let mut value = [0u8; 32];
        value[..8].copy_from_slice(&number.to_le_bytes());
        Bytes32(value)
    }

    fn populated_state(count: usize) -> ChainState {
        populated_state_with_distribution(count, false)
    }

    fn populated_state_with_distribution(count: usize, dominant_validator: bool) -> ChainState {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        for number in 0..count as u64 {
            let validator_id = if dominant_validator {
                numbered_id(1)
            } else {
                numbered_id(number % 200 + 1)
            };
            let owner_id = numbered_id(number + 1_000);
            let custody = PositionCustodyV1::DelegatorIdentity {
                delegator_id: owner_id,
            };
            let position =
                StakePositionV1::new(validator_id, owner_id, custody, None, 17 + number, 100)
                    .unwrap();
            let position_id = position.position_id;
            state.stake_positions.insert(position_id, position);
            let creation_op_id = numbered_id(number + 2_000_000);
            let tranche = UnbondingTrancheV1::new(
                position_id,
                500_000 + number,
                UnbondingTimingV1::height_precise(30_000).unwrap(),
                custody,
                creation_op_id,
                0,
            )
            .unwrap();
            state.unbonding_tranches.insert(tranche.tranche_id, tranche);
        }
        state.rebuild_position_tranche_index().unwrap();
        state
            .ensure_state_commitment_v2(state.height)
            .unwrap();
        state
    }

    fn build_indexes_bulk(state: &ChainState) -> RpcReadIndexes {
        #[derive(Default)]
        struct MutableIndexes {
            positions_by_owner: BTreeMap<Bytes32, Vec<Bytes32>>,
            positions_by_validator: BTreeMap<Bytes32, Vec<Bytes32>>,
            tranches_by_position: BTreeMap<Bytes32, Vec<Bytes32>>,
            tranches_by_owner: BTreeMap<Bytes32, Vec<Bytes32>>,
            tranches_by_validator: BTreeMap<Bytes32, Vec<Bytes32>>,
            rewards_by_delegator: BTreeMap<Bytes32, Vec<Bytes32>>,
            rewards_by_validator: BTreeMap<Bytes32, Vec<Bytes32>>,
        }
        let mut mutable = MutableIndexes::default();
        for (id, position) in &state.stake_positions {
            mutable
                .positions_by_owner
                .entry(position.principal_owner_id)
                .or_default()
                .push(*id);
            mutable
                .positions_by_validator
                .entry(position.validator_id)
                .or_default()
                .push(*id);
            if position.principal_owner_id != position.validator_id {
                mutable
                    .rewards_by_validator
                    .entry(position.validator_id)
                    .or_default()
                    .push(*id);
            }
            if position.pending_rewards_spark > 0
                && position.principal_owner_id != position.validator_id
            {
                mutable
                    .rewards_by_delegator
                    .entry(position.principal_owner_id)
                    .or_default()
                    .push(*id);
            }
        }
        for (id, tranche) in &state.unbonding_tranches {
            mutable
                .tranches_by_position
                .entry(tranche.position_id)
                .or_default()
                .push(*id);
            if let Some(position) = state.stake_positions.get(&tranche.position_id) {
                mutable
                    .tranches_by_owner
                    .entry(position.principal_owner_id)
                    .or_default()
                    .push(*id);
                mutable
                    .tranches_by_validator
                    .entry(position.validator_id)
                    .or_default()
                    .push(*id);
            }
        }
        RpcReadIndexes {
            positions_by_owner: mutable.positions_by_owner.into_iter().collect(),
            positions_by_validator: mutable.positions_by_validator.into_iter().collect(),
            tranches_by_position: mutable.tranches_by_position.into_iter().collect(),
            tranches_by_owner: mutable.tranches_by_owner.into_iter().collect(),
            tranches_by_validator: mutable.tranches_by_validator.into_iter().collect(),
            rewards_by_delegator: mutable.rewards_by_delegator.into_iter().collect(),
            rewards_by_validator: mutable.rewards_by_validator.into_iter().collect(),
        }
    }

    fn publisher_with_indexes(state: &ChainState, indexes: RpcReadIndexes) -> RpcSnapshotPublisher {
        let mempool_size = Arc::new(AtomicUsize::new(0));
        let snapshot = RpcReadSnapshot {
            chain: Arc::new(state.clone()),
            mempool_size: Arc::clone(&mempool_size),
            pruned_mode: false,
            lowest_block: 0,
            blocks_retained: 0,
            state_root: compute_state_root(state).unwrap(),
            indexes,
        };
        RpcSnapshotPublisher {
            current: Arc::new(RwLock::new(Arc::new(snapshot))),
            mempool_size,
        }
    }

    #[test]
    fn publication_is_prior_or_new_and_never_torn() {
        let old = ChainState::new_genesis(TEST_CHAIN_ID);
        let publisher = RpcSnapshotPublisher::new(&old, 0, false, 0, 0).unwrap();
        let held_old = publisher.load();
        let mut new = old.clone();
        new.height = 7;
        new.base_fee = 99;
        publisher.publish(&new, 0, false, 0, 0).unwrap();
        let held_new = publisher.load();
        assert_eq!(
            (held_old.height(), held_old.chain.base_fee),
            (0, old.base_fee)
        );
        assert_eq!((held_new.height(), held_new.chain.base_fee), (7, 99));
    }

    #[test]
    fn incremental_indexes_equal_full_rebuild_after_changed_position_and_tranche() {
        let before = populated_state(8);
        let publisher = RpcSnapshotPublisher::new(&before, 0, false, 0, 0).unwrap();
        let mut after = before.clone();
        let position_id = *after.stake_positions.iter().next().unwrap().0;
        let mut position = after.stake_positions.get(&position_id).unwrap().clone();
        position.pending_rewards_spark += 1;
        after.stake_positions.insert(position_id, position);
        let mut effects = indra_state::CanonicalStateEffects::default();
        effects.stake_positions_changed.insert(position_id);
        effects
            .position_tranche_capacity_changed_for
            .insert(position_id);
        publisher.publish_with_effects(&after, &effects, 0, false, 0, 0).unwrap();
        assert_eq!(publisher.load().indexes, build_indexes(&after));
    }

    #[test]
    fn incremental_indexes_equal_full_rebuild_after_sequential_changes_and_removals() {
        let mut state = populated_state(6);
        let publisher = RpcSnapshotPublisher::new(&state, 0, false, 0, 0).unwrap();
        let position_ids: Vec<_> = state.stake_positions.iter().map(|(id, _)| *id).collect();

        let changed_position_id = position_ids[0];
        let mut changed_position = state
            .stake_positions
            .get(&changed_position_id)
            .unwrap()
            .clone();
        changed_position.pending_rewards_spark = 0;
        state
            .stake_positions
            .insert(changed_position_id, changed_position);
        let mut effects = indra_state::CanonicalStateEffects::default();
        effects.stake_positions_changed.insert(changed_position_id);
        publisher.publish_with_effects(&state, &effects, 0, false, 0, 0).unwrap();
        assert_eq!(publisher.load().indexes, build_indexes(&state));

        let removed_position_id = position_ids[1];
        let removed_tranche_id = *state
            .tranche_ids_for_position(&removed_position_id)
            .first()
            .unwrap();
        state.unbonding_tranches.remove(&removed_tranche_id);
        state.rebuild_position_tranche_index().unwrap();
        let mut effects = indra_state::CanonicalStateEffects::default();
        effects
            .position_tranche_capacity_changed_for
            .insert(removed_position_id);
        publisher.publish_with_effects(&state, &effects, 0, false, 0, 0).unwrap();
        assert_eq!(publisher.load().indexes, build_indexes(&state));

        state.stake_positions.remove(&removed_position_id);
        let mut effects = indra_state::CanonicalStateEffects::default();
        effects.stake_positions_changed.insert(removed_position_id);
        publisher.publish_with_effects(&state, &effects, 0, false, 0, 0).unwrap();
        assert_eq!(publisher.load().indexes, build_indexes(&state));
    }

    /// Real-scale benchmark requested by the Segment 6 review. Run explicitly
    /// in release mode so it never inflates the ordinary test suite.
    #[test]
    #[ignore = "real-scale 104,096-position/tranche benchmark"]
    fn benchmark_incremental_vs_full_at_structural_cap() {
        const COUNT: usize = 104_096;
        let state = populated_state(COUNT);
        let publisher = RpcSnapshotPublisher::new(&state, 0, false, 0, 0).unwrap();
        let position_id = *state.stake_positions.iter().next().unwrap().0;
        let mut effects = indra_state::CanonicalStateEffects::default();
        effects.stake_positions_changed.insert(position_id);
        effects
            .position_tranche_capacity_changed_for
            .insert(position_id);

        let mut incremental = Vec::new();
        for _ in 0..7 {
            let started = Instant::now();
            publisher.publish_with_effects(&state, &effects, 0, false, 0, 0).unwrap();
            incremental.push(started.elapsed());
        }
        let mut full = Vec::new();
        for _ in 0..7 {
            let started = Instant::now();
            publisher.publish(&state, 0, false, 0, 0).unwrap();
            full.push(started.elapsed());
        }
        incremental.sort_unstable();
        full.sort_unstable();
        let incremental_median: Duration = incremental[incremental.len() / 2];
        let full_median: Duration = full[full.len() / 2];
        eprintln!(
            "rpc snapshot structural-cap benchmark: incremental_median={incremental_median:?} full_median={full_median:?} incremental_samples={incremental:?} full_samples={full:?} positions={COUNT} tranches={COUNT}"
        );
        assert!(incremental_median < full_median);
        assert_eq!(publisher.load().indexes, build_indexes(&state));
    }

    #[test]
    #[ignore = "real-scale 100,001-position dominant-validator benchmark"]
    fn benchmark_incremental_update_at_per_validator_structural_cap() {
        const COUNT: usize = 100_001;
        let state = populated_state_with_distribution(COUNT, true);
        let indexes = build_indexes_bulk(&state);
        assert_eq!(
            indexes
                .positions_by_validator
                .get(&numbered_id(1))
                .unwrap()
                .len(),
            COUNT
        );
        assert_eq!(
            indexes
                .tranches_by_validator
                .get(&numbered_id(1))
                .unwrap()
                .len(),
            COUNT
        );
        let publisher = publisher_with_indexes(&state, indexes);
        let position_id = *state.stake_positions.iter().next().unwrap().0;
        let mut effects = indra_state::CanonicalStateEffects::default();
        effects.stake_positions_changed.insert(position_id);
        effects
            .position_tranche_capacity_changed_for
            .insert(position_id);

        let mut samples = Vec::new();
        for _ in 0..9 {
            let started = Instant::now();
            publisher.publish_with_effects(&state, &effects, 0, false, 0, 0).unwrap();
            samples.push(started.elapsed());
        }
        samples.sort_unstable();
        eprintln!(
            "rpc snapshot dominant-validator incremental benchmark: median={:?} samples={samples:?} positions={COUNT} tranches={COUNT}",
            samples[samples.len() / 2]
        );
        assert_eq!(publisher.load().indexes, build_indexes_bulk(&state));
    }
}
