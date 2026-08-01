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
        consensus_snapshot::ConsensusSnapshot, reward_economic_snapshot::RewardEconomicSnapshot,
        slash_membership::SlashMembershipRootRecord, transaction::OutputV1,
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
    validator::{DelegationMap, DelegationReturnEvent, StakeBondEntry, ValidatorSet},
};
use indra_core::types::crypto::HybridPubKey;
use indra_crypto::PaymentPubKeyV1;

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
    StakedBonds(PersistentOrdMap<Bytes32, StakeBondEntry>),
    StakingNonces(PersistentOrdMap<Bytes32, u64>),
    SlashHashes(PersistentOrdSet<Bytes32>),
    #[allow(dead_code)]
    DelegatorIdentities(PersistentOrdMap<Bytes32, HybridPubKey>),
    #[allow(dead_code)]
    PaymentIdentities(PersistentOrdMap<Bytes32, PaymentPubKeyV1>),
    RetiredColdClassical(PersistentOrdSet<[u8; 32]>),
    RetiredColdPq(PersistentOrdSet<[u8; indra_crypto::PQ_PK_BYTES]>),
    Governance(GovernanceState),
    Utxos(UtxoSet),
    DelegationReturnEvents(Vec<DelegationReturnEvent>),
    ConsensusSnapshots(Vec<ConsensusSnapshot>),
    RewardEconomicSnapshot(Option<RewardEconomicSnapshot>),
    SlashMembershipRoots(Vec<SlashMembershipRootRecord>),
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
    #[allow(dead_code)]
    delegator_identities_recorded: bool,
    #[allow(dead_code)]
    payment_identities_recorded: bool,
    retired_cold_components_recorded: bool,
    governance_recorded: bool,
    utxos_recorded: bool,
    delegation_return_events_recorded: bool,
    consensus_snapshots_recorded: bool,
    reward_economic_snapshot_recorded: bool,
    slash_membership_roots_recorded: bool,
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
            delegations_recorded: false,
            staked_bonds_recorded: false,
            staking_nonces_recorded: false,
            slash_hashes_recorded: false,
            delegator_identities_recorded: false,
            payment_identities_recorded: false,
            retired_cold_components_recorded: false,
            governance_recorded: false,
            utxos_recorded: false,
            delegation_return_events_recorded: false,
            consensus_snapshots_recorded: false,
            reward_economic_snapshot_recorded: false,
            slash_membership_roots_recorded: false,
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
        self.snapshot_delegations();
        self.snapshot_staked_bonds();
        self.snapshot_staking_nonces();
        self.snapshot_utxos();
        self.snapshot_delegation_return_events();
        self.snapshot_retired_cold_components();
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

    /// Record delegator identity registry state before test-only or future
    /// live-operation registry mutations.
    #[allow(dead_code)]
    pub(crate) fn snapshot_delegator_identity_scope(&mut self) {
        self.snapshot_delegator_identities();
        self.mark_commitment_touched();
    }

    /// Record payment identity registry state before test-only or future
    /// live-operation registry mutations.
    #[allow(dead_code)]
    pub(crate) fn snapshot_payment_identity_scope(&mut self) {
        self.snapshot_payment_identities();
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
        self.snapshot_consensus_snapshots();
        self.snapshot_reward_economic_snapshot();
        self.snapshot_slash_membership_roots();
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

    fn snapshot_delegations(&mut self) {
        if !self.delegations_recorded {
            let snapshot = measure_undo_recording(|| self.state.delegations.clone());
            self.undo.push(UndoEntry::Delegations(snapshot));
            self.delegations_recorded = true;
        }
    }

    fn snapshot_staked_bonds(&mut self) {
        if !self.staked_bonds_recorded {
            // `PersistentOrdMap::clone()` is an O(1) root-handle copy; the
            // coarse staking snapshot remains the same rollback boundary, but
            // no longer deep-copies every bonded position.
            let snapshot = measure_undo_recording(|| self.state.staked_bonds.clone());
            self.undo.push(UndoEntry::StakedBonds(snapshot));
            self.staked_bonds_recorded = true;
        }
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

    #[allow(dead_code)]
    fn snapshot_payment_identities(&mut self) {
        if !self.payment_identities_recorded {
            // `PersistentOrdMap::clone()` is an O(1) root-handle copy.
            let snapshot = measure_undo_recording(|| self.state.payment_identities.clone());
            self.undo.push(UndoEntry::PaymentIdentities(snapshot));
            self.payment_identities_recorded = true;
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
                UndoEntry::Delegations(delegations) => self.state.delegations = delegations,
                UndoEntry::StakedBonds(staked_bonds) => self.state.staked_bonds = staked_bonds,
                UndoEntry::StakingNonces(nonces) => self.state.staking_nonces = nonces,
                UndoEntry::SlashHashes(hashes) => self.state.applied_slash_hashes = hashes,
                UndoEntry::DelegatorIdentities(identities) => {
                    self.state.delegator_identities = identities;
                }
                UndoEntry::PaymentIdentities(identities) => {
                    self.state.payment_identities = identities;
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
    use crate::validator::DelegatorEntry;
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

    fn test_bond(byte: u8) -> StakeBondEntry {
        StakeBondEntry {
            utxo_id: Bytes32::from([byte; 32]),
            validator_id: Bytes32::from([0xA0 | byte; 32]),
            delegator_id: Bytes32::from([0xD0 | byte; 32]),
            amount_spark: 1_000_000,
            bonded_epoch: 7,
            unbonding_end_epoch: None,
            unbonding_precision: crate::validator::StakeBondUnbondingPrecision::LegacyEpochOnly,
            custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                Bytes32::from([0xD0 | byte; 32]),
            ),
            original_output: test_output(byte).into(),
        }
    }

    #[test]
    fn persistent_bond_and_nonce_snapshots_restore_after_failpoint() {
        let mut state = ChainState::new_genesis();
        let original_bond = test_bond(0x01);
        let original_bond_id = original_bond.utxo_id;
        state
            .staked_bonds
            .insert(original_bond_id, original_bond.clone());
        state.staking_nonces.insert(Bytes32::from([0x11; 32]), 7);
        let original = state.clone();

        set_fail_after_mutation(Some(1));
        {
            let mut txn = StateTxn::begin(&mut state, 1);
            txn.snapshot_staking_scope();
            txn.state_mut().staked_bonds.remove(&original_bond_id);
            txn.state_mut()
                .staked_bonds
                .insert(Bytes32::from([0x02; 32]), test_bond(0x02));
            txn.state_mut()
                .staking_nonces
                .insert(Bytes32::from([0x11; 32]), 8);
            txn.state_mut()
                .staking_nonces
                .insert(Bytes32::from([0x22; 32]), 1);
            assert!(txn.after_mutation().is_err());
        }
        set_fail_after_mutation(None);

        assert_eq!(state, original);
        assert_eq!(
            state.staked_bonds.get(&original_bond_id),
            Some(&original_bond)
        );
        assert_eq!(
            state.staking_nonces.get(&Bytes32::from([0x11; 32])),
            Some(&7)
        );
        assert!(state.staked_bonds.get(&Bytes32::from([0x02; 32])).is_none());
        assert!(state
            .staking_nonces
            .get(&Bytes32::from([0x22; 32]))
            .is_none());
    }

    #[test]
    fn rollback_restores_height_precise_bond_and_prior_commitment_root() {
        let height = 100;
        let mut state = ChainState::new_genesis();
        let mut original_bond = test_bond(0x03);
        original_bond.unbonding_precision =
            crate::validator::StakeBondUnbondingPrecision::HeightPrecise {
                unbonding_start_height: None,
            };
        let bond_id = original_bond.utxo_id;
        state.staked_bonds.insert(bond_id, original_bond.clone());
        state.rebuild_state_commitment_v2(height);
        let root_before = state.state_commitment_v2_root(height);

        set_fail_after_mutation(Some(1));
        {
            let mut txn = StateTxn::begin(&mut state, height);
            txn.snapshot_staking_scope();
            let mut unbonding = original_bond.clone();
            unbonding
                .begin_unbonding(
                    height,
                    indra_core::types::primitives::UNBONDING_PERIOD_EPOCHS,
                )
                .unwrap();
            txn.state_mut().staked_bonds.insert(bond_id, unbonding);
            assert!(txn.after_mutation().is_err());
        }
        set_fail_after_mutation(None);

        assert_eq!(state.staked_bonds.get(&bond_id), Some(&original_bond));
        assert_eq!(state.state_commitment_v2_root(height), root_before);
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

    #[test]
    fn delegation_side_index_restores_through_staking_scope_rollback() {
        let validator_id = Bytes32::from([0xA1; 32]);
        let delegator_id = Bytes32::from([0xD1; 32]);
        let added_delegator_id = Bytes32::from([0xD2; 32]);
        let mut state = ChainState::new_genesis();
        state.delegations.push_delegator_for_test(
            validator_id,
            DelegatorEntry {
                delegator_id,
                staked_spark: 1_000,
                pending_rewards: 7,
                rewards_last_epoch: 3,
                unbonding_end_epoch: None,
            },
        );
        assert_eq!(
            state
                .delegations
                .get_delegator_reward(&validator_id, &delegator_id),
            7
        );
        let original = state.clone();

        set_fail_after_mutation(Some(1));
        {
            let mut txn = StateTxn::begin(&mut state, 1);
            txn.snapshot_staking_scope();
            txn.state_mut()
                .delegations
                .add_delegation(validator_id, added_delegator_id, 500, 4)
                .unwrap();
            assert!(txn.after_mutation().is_err());
        }
        set_fail_after_mutation(None);

        assert_eq!(state, original);
        assert_eq!(
            state
                .delegations
                .get_delegator_reward(&validator_id, &delegator_id),
            7
        );
        assert_eq!(
            state
                .delegations
                .get_delegator_reward(&validator_id, &added_delegator_id),
            0
        );
        assert_eq!(
            state.delegations.encode_to_vec(),
            original.delegations.encode_to_vec()
        );
    }
}
