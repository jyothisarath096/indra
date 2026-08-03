//! Scoped rollback transaction for block application.
//!
//! This module removes `apply_block()`'s always-on full `ChainState` atomicity
//! clone. It does not replace the detached projection clone used by block import
//! and block production; those callers still need a separate projected state
//! before committing candidate roots to their real state.

#[cfg(test)]
use std::time::{Duration, Instant};

use indra_core::{
    types::{
        consensus_snapshot::ConsensusSnapshot,
        reward_economic_snapshot::RewardEconomicSnapshot,
        slash_membership::SlashMembershipRootRecord,
        stake_position::{StakePositionV1, UnbondingTrancheV1},
        transaction::OutputV1,
    },
    Bytes32,
};

use crate::{
    chain::ChainState,
    error::StateResult,
    governance::GovernanceState,
    persistent::{PersistentOrdMap, PersistentOrdSet},
    state_commitment::StateCommitmentV2,
    utxo::{UtxoEntry, UtxoSet},
    validator::{DelegationReturnEvent, EvictedValidatorTombstoneV2, ValidatorSet},
};
use indra_core::types::crypto::HybridPubKey;

#[derive(Clone)]
struct ScalarSnapshot {
    height: u64,
    tip_hash: Bytes32,
    base_fee: u64,
    total_supply: u64,
    treasury_balance: u64,
    burn_buffer: u64,
    fee_reward_pool: u64,
    epoch_fees_burned: u64,
    epoch_slashed_spark: u64,
    epoch_slash_event_count: u32,
}

enum UndoEntry {
    Scalars(ScalarSnapshot),
    UtxoSpent(UtxoEntry),
    UtxoInserted(Bytes32),
    NullifierInserted(Bytes32),
    Validators(ValidatorSet),
    PositionState {
        positions: PersistentOrdMap<Bytes32, StakePositionV1>,
        tranches: PersistentOrdMap<Bytes32, UnbondingTrancheV1>,
        index: std::collections::BTreeMap<Bytes32, Vec<Bytes32>>,
    },
    StakingNonces(PersistentOrdMap<Bytes32, u64>),
    SlashHashes(PersistentOrdSet<Bytes32>),
    #[allow(dead_code)]
    DelegatorIdentities(PersistentOrdMap<Bytes32, HybridPubKey>),
    RetiredColdClassical(PersistentOrdSet<[u8; 32]>),
    RetiredColdPq(PersistentOrdSet<[u8; indra_crypto::PQ_PK_BYTES]>),
    Governance(GovernanceState),
    Utxos(UtxoSet),
    DelegationReturnEvents(Vec<DelegationReturnEvent>),
    ConsensusSnapshots(Vec<ConsensusSnapshot>),
    RewardEconomicSnapshot(Option<RewardEconomicSnapshot>),
    SlashMembershipRoots(Vec<SlashMembershipRootRecord>),
    EvictedValidatorTombstones(PersistentOrdMap<Bytes32, EvictedValidatorTombstoneV2>),
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct StateTxnTiming {
    pub undo_recording: Duration,
    pub rollback: Duration,
}

/// In-place state transaction used by block application.
pub(crate) struct StateTxn<'a> {
    state: &'a mut ChainState,
    undo: Vec<UndoEntry>,
    committed: bool,
    height: u64,
    scalars_recorded: bool,
    validators_recorded: bool,
    position_state_recorded: bool,
    staking_nonces_recorded: bool,
    slash_hashes_recorded: bool,
    #[allow(dead_code)]
    delegator_identities_recorded: bool,
    #[allow(dead_code)]
    retired_cold_components_recorded: bool,
    governance_recorded: bool,
    utxos_recorded: bool,
    delegation_return_events_recorded: bool,
    consensus_snapshots_recorded: bool,
    reward_economic_snapshot_recorded: bool,
    slash_membership_roots_recorded: bool,
    evicted_validator_tombstones_recorded: bool,
    commitment_touched: bool,
    commitment_before: Option<StateCommitmentV2>,
}

impl<'a> StateTxn<'a> {
    /// Begin a new in-place transaction for `state`.
    pub(crate) fn begin(state: &'a mut ChainState, height: u64) -> Self {
        let commitment_before = state.state_commitment_v2.clone();
        Self {
            state,
            undo: Vec::new(),
            committed: false,
            height,
            scalars_recorded: false,
            validators_recorded: false,
            position_state_recorded: false,
            staking_nonces_recorded: false,
            slash_hashes_recorded: false,
            delegator_identities_recorded: false,
            retired_cold_components_recorded: false,
            governance_recorded: false,
            utxos_recorded: false,
            delegation_return_events_recorded: false,
            consensus_snapshots_recorded: false,
            reward_economic_snapshot_recorded: false,
            slash_membership_roots_recorded: false,
            evicted_validator_tombstones_recorded: false,
            commitment_touched: false,
            commitment_before,
        }
    }

    /// Read-only access to the current in-transaction state.
    pub(crate) fn state(&self) -> &ChainState {
        self.state
    }

    /// Mutable access for existing complex mutation helpers after their scope
    /// has been snapshotted by this transaction.
    pub(crate) fn state_mut(&mut self) -> &mut ChainState {
        self.state
    }

    /// Commit the transaction. The state has already been mutated in place.
    pub(crate) fn commit(mut self) {
        self.committed = true;
    }

    /// Ensure StateCommitmentV2 exists when active.
    pub(crate) fn ensure_state_commitment_v2(&mut self) -> StateResult<()> {
        self.mark_commitment_touched();
        self.state.ensure_state_commitment_v2(self.height);
        self.after_mutation()
    }

    /// Record scalar fields before the first scalar write.
    pub(crate) fn record_scalars(&mut self) {
        if self.scalars_recorded {
            return;
        }
        let snapshot = measure_undo_recording(|| ScalarSnapshot {
            height: self.state.height,
            tip_hash: self.state.tip_hash,
            base_fee: self.state.base_fee,
            total_supply: self.state.total_supply,
            treasury_balance: self.state.treasury_balance,
            burn_buffer: self.state.burn_buffer,
            fee_reward_pool: self.state.fee_reward_pool,
            epoch_fees_burned: self.state.epoch_fees_burned,
            epoch_slashed_spark: self.state.epoch_slashed_spark,
            epoch_slash_event_count: self.state.epoch_slash_event_count,
        });
        self.undo.push(UndoEntry::Scalars(snapshot));
        self.scalars_recorded = true;
    }

    /// Record the full staking mutation surface before delegating to existing
    /// staking helpers.
    pub(crate) fn snapshot_staking_scope(&mut self) {
        self.snapshot_validators();
        self.snapshot_position_state();
        self.snapshot_staking_nonces();
        self.snapshot_utxos();
        self.snapshot_delegation_return_events();
        self.snapshot_retired_cold_components();
        self.snapshot_evicted_validator_tombstones();
        self.record_scalars();
        self.mark_commitment_touched();
    }

    /// Record the full governance mutation surface before delegating to existing
    /// governance helpers.
    pub(crate) fn snapshot_governance_scope(&mut self) {
        // Cold-authorized governance operations advance the validator's
        // canonical cold nonce, so validator state is part of this scope.
        self.snapshot_validators();
        self.snapshot_governance();
        self.snapshot_utxos();
        self.record_scalars();
        self.mark_commitment_touched();
    }

    /// Record the slashing mutation surface before applying slash evidence.
    pub(crate) fn snapshot_slashing_scope(&mut self) {
        self.snapshot_validators();
        self.snapshot_position_state();
        self.snapshot_slash_hashes();
        self.snapshot_evicted_validator_tombstones();
        self.snapshot_utxos();
        self.record_scalars();
        self.mark_commitment_touched();
    }

    /// Record delegator identity registry state before test-only or future
    /// live-operation registry mutations.
    #[allow(dead_code)]
    pub(crate) fn snapshot_delegator_identity_scope(&mut self) {
        self.snapshot_delegator_identities();
        self.mark_commitment_touched();
    }

    /// Record the epoch transition mutation surface.
    pub(crate) fn snapshot_epoch_scope(&mut self) {
        self.snapshot_validators();
        self.snapshot_position_state();
        self.snapshot_governance();
        self.snapshot_utxos();
        self.snapshot_delegation_return_events();
        self.snapshot_consensus_snapshots();
        self.snapshot_reward_economic_snapshot();
        self.snapshot_slash_membership_roots();
        self.snapshot_evicted_validator_tombstones();
        self.record_scalars();
        self.mark_commitment_touched();
    }

    /// Record validator and commitment state before QC last-active updates.
    pub(crate) fn snapshot_validator_activity_scope(&mut self) {
        self.snapshot_validators();
        self.mark_commitment_touched();
    }

    /// Spend a UTXO with precise rollback.
    pub(crate) fn spend_utxo(&mut self, id: &Bytes32) -> StateResult<Option<UtxoEntry>> {
        let removed = self.state.utxos.spend_at_height(id, self.height);
        if let Some(entry) = &removed {
            let entry = measure_undo_recording(|| entry.clone());
            self.undo.push(UndoEntry::UtxoSpent(entry));
        }
        self.after_mutation()?;
        Ok(removed)
    }

    /// Insert a UTXO with precise rollback.
    pub(crate) fn insert_utxo(
        &mut self,
        output: OutputV1,
        height: u64,
        tx_index: u32,
        output_index: u32,
    ) -> StateResult<Bytes32> {
        let id = self
            .state
            .utxos
            .insert(output, height, tx_index, output_index)?;
        measure_undo_recording(|| self.undo.push(UndoEntry::UtxoInserted(id)));
        self.after_mutation()?;
        Ok(id)
    }

    /// Insert a nullifier with precise rollback.
    pub(crate) fn insert_nullifier(&mut self, nullifier: Bytes32) -> StateResult<()> {
        self.state
            .nullifiers
            .insert_or_double_spend_at_height(nullifier, self.height)?;
        measure_undo_recording(|| self.undo.push(UndoEntry::NullifierInserted(nullifier)));
        self.after_mutation()
    }

    /// Insert or replace one canonical staking position.
    pub(crate) fn put_stake_position(&mut self, position: StakePositionV1) -> StateResult<()> {
        self.snapshot_position_state();
        if let Some(commitment) = self.state.state_commitment_v2.as_mut() {
            commitment.put_stake_position(&position);
        }
        self.state
            .stake_positions
            .insert(position.position_id, position);
        self.after_mutation()
    }

    /// Delete one canonical staking position.
    pub(crate) fn delete_stake_position(&mut self, position_id: &Bytes32) -> StateResult<()> {
        self.snapshot_position_state();
        if let Some(commitment) = self.state.state_commitment_v2.as_mut() {
            commitment.delete_stake_position(position_id);
        }
        self.state.stake_positions.remove(position_id);
        self.state.position_tranche_index.remove(position_id);
        self.after_mutation()
    }

    /// Insert one immutable unbonding tranche.
    pub(crate) fn put_unbonding_tranche(&mut self, tranche: UnbondingTrancheV1) -> StateResult<()> {
        self.snapshot_position_state();
        if let Some(commitment) = self.state.state_commitment_v2.as_mut() {
            commitment.put_unbonding_tranche(&tranche);
        }
        self.state
            .unbonding_tranches
            .insert(tranche.tranche_id, tranche.clone());
        let ids = self
            .state
            .position_tranche_index
            .entry(tranche.position_id)
            .or_default();
        match ids.binary_search(&tranche.tranche_id) {
            Ok(_) => {}
            Err(index) => ids.insert(index, tranche.tranche_id),
        }
        self.after_mutation()
    }

    /// Delete one immutable unbonding tranche.
    pub(crate) fn delete_unbonding_tranche(&mut self, tranche_id: &Bytes32) -> StateResult<()> {
        self.snapshot_position_state();
        let position_id = self
            .state
            .unbonding_tranches
            .get(tranche_id)
            .map(|tranche| tranche.position_id);
        if let Some(commitment) = self.state.state_commitment_v2.as_mut() {
            commitment.delete_unbonding_tranche(tranche_id);
        }
        self.state.unbonding_tranches.remove(tranche_id);
        if let Some(position_id) = position_id {
            if let Some(ids) = self.state.position_tranche_index.get_mut(&position_id) {
                if let Ok(index) = ids.binary_search(tranche_id) {
                    ids.remove(index);
                }
                if ids.is_empty() {
                    self.state.position_tranche_index.remove(&position_id);
                }
            }
        }
        self.after_mutation()
    }

    /// Set the isolated lifecycle nonce for a principal owner.
    pub(crate) fn set_position_nonce(&mut self, owner_id: Bytes32, nonce: u64) -> StateResult<()> {
        self.snapshot_staking_nonces();
        if let Some(commitment) = self.state.state_commitment_v2.as_mut() {
            commitment.put_staking_nonce(&owner_id, nonce);
        }
        self.state.staking_nonces.insert(owner_id, nonce);
        self.after_mutation()
    }

    /// Mutate base fee.
    pub(crate) fn set_base_fee(&mut self, base_fee: u64) -> StateResult<()> {
        self.record_scalars();
        self.state.base_fee = base_fee;
        self.after_mutation()
    }

    /// Mutate height and tip hash.
    pub(crate) fn set_tip(&mut self, height: u64, tip_hash: Bytes32) -> StateResult<()> {
        self.record_scalars();
        self.state.height = height;
        self.state.tip_hash = tip_hash;
        self.after_mutation()
    }

    /// Add fee accounting.
    pub(crate) fn apply_fee_accounting(
        &mut self,
        burn_amount: u64,
        validator_amount: u64,
    ) -> StateResult<()> {
        self.record_scalars();
        self.state.total_supply = self.state.total_supply.saturating_sub(burn_amount);
        self.state.fee_reward_pool = self.state.fee_reward_pool.saturating_add(validator_amount);
        self.state.epoch_fees_burned = self.state.epoch_fees_burned.saturating_add(burn_amount);
        self.after_mutation()
    }

    /// Add explicit slash accounting.
    pub(crate) fn add_slash_accounting(&mut self, amount: u64) -> StateResult<()> {
        self.record_scalars();
        self.state.epoch_slashed_spark = self.state.epoch_slashed_spark.saturating_add(amount);
        self.state.epoch_slash_event_count = self.state.epoch_slash_event_count.saturating_add(1);
        self.after_mutation()
    }

    /// Mark StateCommitmentV2 as touched by this transaction.
    pub(crate) fn mark_commitment_touched(&mut self) {
        self.commitment_touched = true;
    }

    /// Failpoint hook after an undo-recorded mutation helper.
    pub(crate) fn after_mutation(&mut self) -> StateResult<()> {
        failpoint_after_mutation()
    }

    fn snapshot_validators(&mut self) {
        if !self.validators_recorded {
            let snapshot = measure_undo_recording(|| self.state.validators.clone());
            self.undo.push(UndoEntry::Validators(snapshot));
            self.validators_recorded = true;
        }
    }

    /// Record the isolated canonical position/tranche mutation surface.
    pub(crate) fn snapshot_position_state(&mut self) {
        if !self.position_state_recorded {
            self.undo.push(UndoEntry::PositionState {
                positions: self.state.stake_positions.clone(),
                tranches: self.state.unbonding_tranches.clone(),
                index: self.state.position_tranche_index.clone(),
            });
            self.position_state_recorded = true;
        }
        self.mark_commitment_touched();
    }

    fn snapshot_staking_nonces(&mut self) {
        if !self.staking_nonces_recorded {
            // `PersistentOrdMap::clone()` is an O(1) root-handle copy.
            let snapshot = measure_undo_recording(|| self.state.staking_nonces.clone());
            self.undo.push(UndoEntry::StakingNonces(snapshot));
            self.staking_nonces_recorded = true;
        }
    }

    fn snapshot_slash_hashes(&mut self) {
        if !self.slash_hashes_recorded {
            // `PersistentOrdSet::clone()` is an O(1) root-handle copy; applied
            // slash hashes keep the same coarse rollback boundary without a
            // full hash-table clone.
            let snapshot = measure_undo_recording(|| self.state.applied_slash_hashes.clone());
            self.undo.push(UndoEntry::SlashHashes(snapshot));
            self.slash_hashes_recorded = true;
        }
    }

    #[allow(dead_code)]
    fn snapshot_delegator_identities(&mut self) {
        if !self.delegator_identities_recorded {
            // `PersistentOrdMap::clone()` is an O(1) root-handle copy.
            let snapshot = measure_undo_recording(|| self.state.delegator_identities.clone());
            self.undo.push(UndoEntry::DelegatorIdentities(snapshot));
            self.delegator_identities_recorded = true;
        }
    }

    fn snapshot_retired_cold_components(&mut self) {
        if !self.retired_cold_components_recorded {
            self.undo.push(UndoEntry::RetiredColdClassical(
                self.state.retired_cold_classical_components.clone(),
            ));
            self.undo.push(UndoEntry::RetiredColdPq(
                self.state.retired_cold_pq_components.clone(),
            ));
            self.retired_cold_components_recorded = true;
        }
    }

    fn snapshot_governance(&mut self) {
        if !self.governance_recorded {
            let snapshot = measure_undo_recording(|| self.state.governance.clone());
            self.undo.push(UndoEntry::Governance(snapshot));
            self.governance_recorded = true;
        }
    }

    fn snapshot_utxos(&mut self) {
        if !self.utxos_recorded {
            let snapshot = measure_undo_recording(|| self.state.utxos.clone());
            self.undo.push(UndoEntry::Utxos(snapshot));
            self.utxos_recorded = true;
        }
    }

    fn snapshot_delegation_return_events(&mut self) {
        if !self.delegation_return_events_recorded {
            let snapshot = measure_undo_recording(|| self.state.delegation_return_events.clone());
            self.undo.push(UndoEntry::DelegationReturnEvents(snapshot));
            self.delegation_return_events_recorded = true;
        }
    }

    fn snapshot_consensus_snapshots(&mut self) {
        if !self.consensus_snapshots_recorded {
            let snapshot = self.state.consensus_snapshots.clone();
            self.undo.push(UndoEntry::ConsensusSnapshots(snapshot));
            self.consensus_snapshots_recorded = true;
        }
    }

    fn snapshot_reward_economic_snapshot(&mut self) {
        if !self.reward_economic_snapshot_recorded {
            self.undo.push(UndoEntry::RewardEconomicSnapshot(
                self.state.reward_economic_snapshot.clone(),
            ));
            self.reward_economic_snapshot_recorded = true;
        }
    }

    pub(crate) fn snapshot_slash_membership_root_scope(&mut self) {
        self.snapshot_slash_membership_roots();
        self.mark_commitment_touched();
    }

    fn snapshot_slash_membership_roots(&mut self) {
        if !self.slash_membership_roots_recorded {
            self.undo.push(UndoEntry::SlashMembershipRoots(
                self.state.slash_membership_roots.clone(),
            ));
            self.slash_membership_roots_recorded = true;
        }
    }

    fn snapshot_evicted_validator_tombstones(&mut self) {
        if !self.evicted_validator_tombstones_recorded {
            self.undo.push(UndoEntry::EvictedValidatorTombstones(
                self.state.evicted_validator_tombstones.clone(),
            ));
            self.evicted_validator_tombstones_recorded = true;
        }
    }

    fn rollback(&mut self) {
        #[cfg(test)]
        let rollback_start = Instant::now();
        while let Some(entry) = self.undo.pop() {
            match entry {
                UndoEntry::Scalars(snapshot) => {
                    self.state.height = snapshot.height;
                    self.state.tip_hash = snapshot.tip_hash;
                    self.state.base_fee = snapshot.base_fee;
                    self.state.total_supply = snapshot.total_supply;
                    self.state.treasury_balance = snapshot.treasury_balance;
                    self.state.burn_buffer = snapshot.burn_buffer;
                    self.state.fee_reward_pool = snapshot.fee_reward_pool;
                    self.state.epoch_fees_burned = snapshot.epoch_fees_burned;
                    self.state.epoch_slashed_spark = snapshot.epoch_slashed_spark;
                    self.state.epoch_slash_event_count = snapshot.epoch_slash_event_count;
                }
                UndoEntry::UtxoSpent(entry) => self
                    .state
                    .utxos
                    .restore_for_rollback_at_height(entry, self.height),
                UndoEntry::UtxoInserted(id) => {
                    let _ = self
                        .state
                        .utxos
                        .remove_for_rollback_at_height(&id, self.height);
                }
                UndoEntry::NullifierInserted(nullifier) => {
                    let _ = self
                        .state
                        .nullifiers
                        .remove_for_rollback_at_height(&nullifier, self.height);
                }
                UndoEntry::Validators(validators) => self.state.validators = validators,
                UndoEntry::PositionState {
                    positions,
                    tranches,
                    index,
                } => {
                    self.state.stake_positions = positions;
                    self.state.unbonding_tranches = tranches;
                    self.state.position_tranche_index = index;
                }
                UndoEntry::StakingNonces(nonces) => self.state.staking_nonces = nonces,
                UndoEntry::SlashHashes(hashes) => self.state.applied_slash_hashes = hashes,
                UndoEntry::DelegatorIdentities(identities) => {
                    self.state.delegator_identities = identities;
                }
                UndoEntry::RetiredColdClassical(components) => {
                    self.state.retired_cold_classical_components = components;
                }
                UndoEntry::RetiredColdPq(components) => {
                    self.state.retired_cold_pq_components = components;
                }
                UndoEntry::Governance(governance) => self.state.governance = governance,
                UndoEntry::Utxos(utxos) => self.state.utxos = utxos,
                UndoEntry::DelegationReturnEvents(events) => {
                    self.state.delegation_return_events = events;
                }
                UndoEntry::ConsensusSnapshots(snapshots) => {
                    self.state.consensus_snapshots = snapshots;
                }
                UndoEntry::RewardEconomicSnapshot(snapshot) => {
                    self.state.reward_economic_snapshot = snapshot;
                }
                UndoEntry::SlashMembershipRoots(roots) => {
                    self.state.slash_membership_roots = roots;
                }
                UndoEntry::EvictedValidatorTombstones(tombstones) => {
                    self.state.evicted_validator_tombstones = tombstones;
                }
            }
        }
        if self.commitment_touched {
            // The cache's projection height is not encoded in the cache and
            // cannot safely be inferred from either the restored tip or the
            // rejected block height at a gate boundary. Restore the exact
            // persistent-tree snapshot captured when the transaction began.
            self.state.state_commitment_v2 = self.commitment_before.clone();
        }
        #[cfg(test)]
        record_rollback_timing(rollback_start.elapsed());
    }
}

impl Drop for StateTxn<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.rollback();
        }
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_AFTER_MUTATION: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static MUTATION_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static TIMING: std::cell::Cell<StateTxnTiming> = const { std::cell::Cell::new(StateTxnTiming {
        undo_recording: Duration::ZERO,
        rollback: Duration::ZERO,
    }) };
}

#[cfg(test)]
fn add_timing(update: impl FnOnce(&mut StateTxnTiming)) {
    TIMING.with(|cell| {
        let mut timing = cell.get();
        update(&mut timing);
        cell.set(timing);
    });
}

#[cfg(test)]
fn measure_undo_recording<T>(f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let result = f();
    add_timing(|timing| {
        timing.undo_recording = timing.undo_recording.saturating_add(start.elapsed());
    });
    result
}

#[cfg(not(test))]
fn measure_undo_recording<T>(f: impl FnOnce() -> T) -> T {
    f()
}

#[cfg(test)]
fn record_rollback_timing(duration: Duration) {
    add_timing(|timing| {
        timing.rollback = timing.rollback.saturating_add(duration);
    });
}

#[cfg(test)]
fn failpoint_after_mutation() -> StateResult<()> {
    let count = MUTATION_COUNT.with(|counter| {
        let next = counter.get().saturating_add(1);
        counter.set(next);
        next
    });
    let should_fail = FAIL_AFTER_MUTATION.with(|target| target.get() == Some(count));
    if should_fail {
        return Err(crate::error::StateError::InvariantViolation {
            message: "state transaction failpoint injected after mutation",
        });
    }
    Ok(())
}

#[cfg(not(test))]
fn failpoint_after_mutation() -> StateResult<()> {
    Ok(())
}

#[cfg(test)]
pub(crate) fn set_fail_after_mutation(target: Option<usize>) {
    FAIL_AFTER_MUTATION.with(|cell| cell.set(target));
    MUTATION_COUNT.with(|cell| cell.set(0));
}

#[cfg(test)]
pub(crate) fn mutation_count() -> usize {
    MUTATION_COUNT.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn reset_timing() {
    TIMING.with(|cell| cell.set(StateTxnTiming::default()));
}

#[cfg(test)]
pub(crate) fn timing() -> StateTxnTiming {
    TIMING.with(std::cell::Cell::get)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        codec::Encode,
        types::{
            consensus_snapshot::{ConsensusSnapshot, ConsensusSnapshotEntry},
            crypto::HybridPubKey,
            primitives::VariableBytes,
            reward_economic_snapshot::{RewardEconomicSnapshot, RewardEconomicValidatorEntry},
        },
        CommitmentV1,
    };

    fn test_output(byte: u8) -> OutputV1 {
        OutputV1 {
            value_spark: 1_000_000,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from([byte; 32]),
            },
            owner_pubkey: HybridPubKey {
                classical_pk: Bytes32::from([byte; 32]),
                pq_pk: VariableBytes::from_slice(&[byte; 32]).unwrap(),
            },
            range_proof: VariableBytes::from_slice(&[byte; 32]).unwrap(),
            lock_height: 0,
        }
    }




    #[test]
    fn rollback_restores_slash_membership_root_history_and_commitment() {
        let height = u64::MAX;
        let original_record = SlashMembershipRootRecord {
            activation_height: height,
            membership_root: Bytes32::from([0xA1; 32]),
        };
        let mut state = ChainState::new_genesis();
        state.slash_membership_roots = vec![original_record];
        state.rebuild_state_commitment_v2(height);
        let root_before = state.state_commitment_v2_root(height);

        set_fail_after_mutation(Some(1));
        {
            let mut txn = StateTxn::begin(&mut state, height);
            txn.snapshot_slash_membership_root_scope();
            txn.state_mut().slash_membership_roots[0].membership_root = Bytes32::from([0xA2; 32]);
            assert!(txn.after_mutation().is_err());
        }
        set_fail_after_mutation(None);

        assert_eq!(state.slash_membership_roots, vec![original_record]);
        assert_eq!(state.state_commitment_v2_root(height), root_before);
    }

    #[test]
    fn epoch_scope_rollback_restores_consensus_snapshot_rotation() {
        let classical = indra_crypto::ClassicalKeypair::from_seed(&[0xE1; 32]);
        let pq = indra_crypto::PqKeypair::from_seed(&[0xE2; 32]).unwrap();
        let public = indra_crypto::HybridKeypair::new(classical, pq).public_key();
        let vrf = indra_crypto::VrfKeypair::from_seed(&[0xE3; 32]);
        let snapshot = |activation_height, boundary_height, weight| {
            ConsensusSnapshot::new(
                activation_height,
                boundary_height,
                vec![ConsensusSnapshotEntry::new(
                    Bytes32::from([0xE0; 32]),
                    weight,
                    public.classical.0,
                    public.pq.0,
                    vrf.public_key(),
                )
                .unwrap()],
            )
            .unwrap()
        };
        let mut state = ChainState::new_genesis();
        state.height = u64::MAX;
        state.consensus_snapshots = vec![
            snapshot(601, 600, 2_000_000_000),
            snapshot(901, 900, 3_000_000_000),
        ];
        state.reward_economic_snapshot = Some(
            RewardEconomicSnapshot::new(
                901,
                900,
                2_000,
                vec![RewardEconomicValidatorEntry::new(
                    Bytes32::from([0xE0; 32]),
                    1_000,
                    vec![],
                    2_000,
                )
                .unwrap()],
            )
            .unwrap(),
        );
        state.rebuild_state_commitment_v2(state.height);
        let original = state.clone();

        set_fail_after_mutation(Some(1));
        {
            let mut txn = StateTxn::begin(&mut state, u64::MAX);
            txn.snapshot_epoch_scope();
            txn.state_mut().consensus_snapshots = vec![
                snapshot(901, 900, 3_000_000_000),
                snapshot(1201, 1200, 4_000_000_000),
            ];
            txn.state_mut().reward_economic_snapshot = None;
            assert!(txn.after_mutation().is_err());
        }
        set_fail_after_mutation(None);

        assert_eq!(state.consensus_snapshots, original.consensus_snapshots);
        assert_eq!(state.state_commitment_v2, original.state_commitment_v2);
        assert_eq!(state, original);
    }

}
