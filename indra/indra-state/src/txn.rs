//! Scoped rollback transaction for block application.
//!
//! This module removes `apply_block()`'s always-on full `ChainState` atomicity
//! clone. It does not replace the detached projection clone used by block import
//! and block production; those callers still need a separate projected state
//! before committing candidate roots to their real state.

use std::collections::{BTreeMap, HashSet};

#[cfg(test)]
use std::time::{Duration, Instant};

use indra_core::{
    types::{primitives::state_commitment_v2_active, transaction::OutputV1},
    Bytes32,
};

use crate::{
    chain::ChainState,
    error::StateResult,
    governance::GovernanceState,
    utxo::{UtxoEntry, UtxoSet},
    validator::{DelegationMap, DelegationReturnEvent, StakeBondEntry, ValidatorSet},
};

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
    Delegations(DelegationMap),
    StakedBonds(BTreeMap<Bytes32, StakeBondEntry>),
    StakingNonces(BTreeMap<Bytes32, u64>),
    SlashHashes(HashSet<Bytes32>),
    Governance(GovernanceState),
    Utxos(UtxoSet),
    DelegationReturnEvents(Vec<DelegationReturnEvent>),
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
    delegations_recorded: bool,
    staked_bonds_recorded: bool,
    staking_nonces_recorded: bool,
    slash_hashes_recorded: bool,
    governance_recorded: bool,
    utxos_recorded: bool,
    delegation_return_events_recorded: bool,
    commitment_touched: bool,
}

impl<'a> StateTxn<'a> {
    /// Begin a new in-place transaction for `state`.
    pub(crate) fn begin(state: &'a mut ChainState, height: u64) -> Self {
        Self {
            state,
            undo: Vec::new(),
            committed: false,
            height,
            scalars_recorded: false,
            validators_recorded: false,
            delegations_recorded: false,
            staked_bonds_recorded: false,
            staking_nonces_recorded: false,
            slash_hashes_recorded: false,
            governance_recorded: false,
            utxos_recorded: false,
            delegation_return_events_recorded: false,
            commitment_touched: false,
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
        self.snapshot_delegations();
        self.snapshot_staked_bonds();
        self.snapshot_staking_nonces();
        self.snapshot_utxos();
        self.snapshot_delegation_return_events();
        self.record_scalars();
        self.mark_commitment_touched();
    }

    /// Record the full governance mutation surface before delegating to existing
    /// governance helpers.
    pub(crate) fn snapshot_governance_scope(&mut self) {
        self.snapshot_governance();
        self.snapshot_utxos();
        self.record_scalars();
    }

    /// Record the slashing mutation surface before applying slash evidence.
    pub(crate) fn snapshot_slashing_scope(&mut self) {
        self.snapshot_validators();
        self.snapshot_staked_bonds();
        self.snapshot_slash_hashes();
        self.snapshot_utxos();
        self.record_scalars();
        self.mark_commitment_touched();
    }

    /// Record the epoch transition mutation surface.
    pub(crate) fn snapshot_epoch_scope(&mut self) {
        self.snapshot_validators();
        self.snapshot_delegations();
        self.snapshot_staked_bonds();
        self.snapshot_governance();
        self.snapshot_utxos();
        self.snapshot_delegation_return_events();
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
        let removed = self.state.utxos.spend(id);
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
        self.state.nullifiers.insert_or_double_spend(nullifier)?;
        measure_undo_recording(|| self.undo.push(UndoEntry::NullifierInserted(nullifier)));
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
        self.state.epoch_slash_event_count =
            self.state.epoch_slash_event_count.saturating_add(1);
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

    fn snapshot_delegations(&mut self) {
        if !self.delegations_recorded {
            let snapshot = measure_undo_recording(|| self.state.delegations.clone());
            self.undo.push(UndoEntry::Delegations(snapshot));
            self.delegations_recorded = true;
        }
    }

    fn snapshot_staked_bonds(&mut self) {
        if !self.staked_bonds_recorded {
            let snapshot = measure_undo_recording(|| self.state.staked_bonds.clone());
            self.undo.push(UndoEntry::StakedBonds(snapshot));
            self.staked_bonds_recorded = true;
        }
    }

    fn snapshot_staking_nonces(&mut self) {
        if !self.staking_nonces_recorded {
            let snapshot = measure_undo_recording(|| self.state.staking_nonces.clone());
            self.undo.push(UndoEntry::StakingNonces(snapshot));
            self.staking_nonces_recorded = true;
        }
    }

    fn snapshot_slash_hashes(&mut self) {
        if !self.slash_hashes_recorded {
            let snapshot = measure_undo_recording(|| self.state.applied_slash_hashes.clone());
            self.undo.push(UndoEntry::SlashHashes(snapshot));
            self.slash_hashes_recorded = true;
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
                UndoEntry::UtxoSpent(entry) => self.state.utxos.restore_for_rollback(entry),
                UndoEntry::UtxoInserted(id) => {
                    let _ = self.state.utxos.remove_for_rollback(&id);
                }
                UndoEntry::NullifierInserted(nullifier) => {
                    let _ = self.state.nullifiers.remove_for_rollback(&nullifier);
                }
                UndoEntry::Validators(validators) => self.state.validators = validators,
                UndoEntry::Delegations(delegations) => self.state.delegations = delegations,
                UndoEntry::StakedBonds(staked_bonds) => self.state.staked_bonds = staked_bonds,
                UndoEntry::StakingNonces(nonces) => self.state.staking_nonces = nonces,
                UndoEntry::SlashHashes(hashes) => self.state.applied_slash_hashes = hashes,
                UndoEntry::Governance(governance) => self.state.governance = governance,
                UndoEntry::Utxos(utxos) => self.state.utxos = utxos,
                UndoEntry::DelegationReturnEvents(events) => {
                    self.state.delegation_return_events = events;
                }
            }
        }
        if self.commitment_touched {
            if state_commitment_v2_active(self.height) {
                self.state.rebuild_state_commitment_v2(self.height);
            } else {
                self.state.state_commitment_v2 = None;
            }
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
