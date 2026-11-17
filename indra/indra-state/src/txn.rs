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
        stake_position::{StakePositionV1, TrancheRefundEventV1, UnbondingTrancheV1},
        transaction::OutputV1,
    },
    Bytes32,
};

use crate::monetary::{MonetaryAggregatesV1, MonetaryLedgerV1};
use crate::{
    chain::ChainState,
    effects::CanonicalStateEffects,
    error::StateResult,
    governance::GovernanceState,
    persistent::{PersistentOrdMap, PersistentOrdSet},
    state_commitment::StateCommitmentV2,
    utxo::{UtxoEntry, UtxoSet},
    validator::{EvictedValidatorTombstoneV2, ValidatorSet},
};
use indra_core::types::{crypto::HybridPubKey, primitives::Bytes64};

#[derive(Clone)]
struct ScalarSnapshot {
    height: u64,
    tip_hash: Bytes32,
    base_fee: u64,
    total_supply: u64,
    fee_reward_pool: u64,
    epoch_slash_event_count: u32,
    monetary_ledger: MonetaryLedgerV1,
    monetary_aggregates: MonetaryAggregatesV1,
    election_seed: Bytes64,
    election_seed_height: u64,
}

enum UndoEntry {
    Scalars(ScalarSnapshot),
    Validators(ValidatorSet),
    PositionState {
        positions: PersistentOrdMap<Bytes32, StakePositionV1>,
        tranches: PersistentOrdMap<Bytes32, UnbondingTrancheV1>,
        index: std::collections::BTreeMap<Bytes32, Vec<Bytes32>>,
    },
    StakingNonces(PersistentOrdMap<Bytes32, u64>),
    DelegatorIdentities(PersistentOrdMap<Bytes32, HybridPubKey>),
    RetiredColdClassical(PersistentOrdSet<[u8; 32]>),
    RetiredColdPq(PersistentOrdSet<[u8; indra_crypto::PQ_PK_BYTES]>),
    Governance(GovernanceState),
    Utxos(UtxoSet),
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
    delegator_identities_recorded: bool,
    retired_cold_components_recorded: bool,
    governance_recorded: bool,
    utxos_recorded: bool,
    consensus_snapshots_recorded: bool,
    reward_economic_snapshot_recorded: bool,
    slash_membership_roots_recorded: bool,
    evicted_validator_tombstones_recorded: bool,
    commitment_touched: bool,
    commitment_before: Option<StateCommitmentV2>,
    effects: CanonicalStateEffects,
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
            delegator_identities_recorded: false,
            retired_cold_components_recorded: false,
            governance_recorded: false,
            utxos_recorded: false,
            consensus_snapshots_recorded: false,
            reward_economic_snapshot_recorded: false,
            slash_membership_roots_recorded: false,
            evicted_validator_tombstones_recorded: false,
            commitment_touched: false,
            commitment_before,
            effects: CanonicalStateEffects::default(),
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
    pub(crate) fn commit(mut self) -> CanonicalStateEffects {
        self.populate_effects_from_undo();
        self.committed = true;
        std::mem::take(&mut self.effects)
    }

    /// Commit a detached scratch-state transaction without constructing a
    /// canonical effects journal. Candidate validation never publishes its
    /// projected state, so diffing large snapshotted collections here is both
    /// semantically meaningless and potentially dominant work.
    pub(crate) fn commit_scratch(mut self) {
        self.committed = true;
    }

    fn populate_effects_from_undo(&mut self) {
        use std::collections::{BTreeMap, BTreeSet};

        let state: &ChainState = self.state;
        let effects = &mut self.effects;
        for undo in &self.undo {
            match undo {
                UndoEntry::Scalars(before) => {
                    effects.height_changed |= before.height != state.height;
                    effects.tip_hash_changed |= before.tip_hash != state.tip_hash;
                    effects.base_fee_changed |= before.base_fee != state.base_fee;
                    effects.economic_accounting_changed |= before.total_supply
                        != state.total_supply
                        || before.fee_reward_pool != state.fee_reward_pool
                        || before.monetary_ledger != state.monetary_ledger
                        || before.monetary_aggregates != state.monetary_aggregates;
                    effects.epoch_summary_changed |= before.monetary_ledger
                        != state.monetary_ledger
                        || before.epoch_slash_event_count != state.epoch_slash_event_count;
                    effects.epoch_changed |= before.height
                        / indra_core::types::primitives::EPOCH_DURATION_BLOCKS
                        != state.height / indra_core::types::primitives::EPOCH_DURATION_BLOCKS;
                }
                UndoEntry::Validators(before) => {
                    let old: BTreeMap<_, _> = before
                        .all_validators()
                        .map(|validator| (validator.validator_id, validator))
                        .collect();
                    let new: BTreeMap<_, _> = state
                        .validators
                        .all_validators()
                        .map(|validator| (validator.validator_id, validator))
                        .collect();
                    let ids: BTreeSet<_> = old.keys().chain(new.keys()).copied().collect();
                    effects.validator_registry_changed |= old.keys().ne(new.keys());
                    for id in ids {
                        if old.get(&id) != new.get(&id) {
                            effects.validators_changed.insert(id);
                            effects.validator_registry_changed = true;
                        }
                        let old_keys = old.get(&id).map(|validator| {
                            (
                                &validator.hybrid_classical_pk,
                                &validator.hybrid_pq_pk,
                                &validator.vrf_pk,
                                &validator.cold_hybrid_classical_pk,
                                &validator.cold_hybrid_pq_pk,
                                validator.cold_key_version,
                            )
                        });
                        let new_keys = new.get(&id).map(|validator| {
                            (
                                &validator.hybrid_classical_pk,
                                &validator.hybrid_pq_pk,
                                &validator.vrf_pk,
                                &validator.cold_hybrid_classical_pk,
                                &validator.cold_hybrid_pq_pk,
                                validator.cold_key_version,
                            )
                        });
                        if old_keys != new_keys {
                            effects.validator_keys_changed.insert(id);
                        }
                    }
                }
                UndoEntry::PositionState {
                    positions,
                    tranches,
                    index,
                } => {
                    effects.position_tranche_index_changed |=
                        index != &state.position_tranche_index;
                    let position_ids: BTreeSet<_> = positions
                        .iter()
                        .map(|(id, _)| *id)
                        .chain(state.stake_positions.iter().map(|(id, _)| *id))
                        .collect();
                    for id in position_ids {
                        let old = positions.get(&id);
                        let new = state.stake_positions.get(&id);
                        if old != new {
                            effects.stake_positions_changed.insert(id);
                            effects.global_position_tranche_capacity_changed = true;
                            if let Some(validator_id) = old
                                .map(|position| position.validator_id)
                                .or_else(|| new.map(|position| position.validator_id))
                            {
                                effects
                                    .validator_position_capacity_changed
                                    .insert(validator_id);
                                effects
                                    .validator_tranche_capacity_changed
                                    .insert(validator_id);
                            }
                        }
                    }
                    let tranche_ids: BTreeSet<_> = tranches
                        .iter()
                        .map(|(id, _)| *id)
                        .chain(state.unbonding_tranches.iter().map(|(id, _)| *id))
                        .collect();
                    for id in tranche_ids {
                        let old = tranches.get(&id);
                        let new = state.unbonding_tranches.get(&id);
                        if old != new {
                            effects.global_position_tranche_capacity_changed = true;
                            if let Some(position_id) = old
                                .map(|tranche| tranche.position_id)
                                .or_else(|| new.map(|tranche| tranche.position_id))
                            {
                                effects
                                    .position_tranche_capacity_changed_for
                                    .insert(position_id);
                                let validator_id = positions
                                    .get(&position_id)
                                    .or_else(|| state.stake_positions.get(&position_id))
                                    .map(|position| position.validator_id);
                                if let Some(validator_id) = validator_id {
                                    effects
                                        .validator_tranche_capacity_changed
                                        .insert(validator_id);
                                }
                            }
                        }
                    }
                }
                UndoEntry::StakingNonces(before) => {
                    for id in before
                        .iter()
                        .map(|(id, _)| *id)
                        .chain(state.staking_nonces.iter().map(|(id, _)| *id))
                    {
                        if before.get(&id) != state.staking_nonces.get(&id) {
                            effects.staking_nonces_changed.insert(id);
                        }
                    }
                }
                UndoEntry::DelegatorIdentities(before) => {
                    for id in before
                        .iter()
                        .map(|(id, _)| *id)
                        .chain(state.delegator_identities.iter().map(|(id, _)| *id))
                    {
                        if before.get(&id) != state.delegator_identities.get(&id) {
                            effects.delegator_identities_changed.insert(id);
                        }
                    }
                }
                UndoEntry::RetiredColdClassical(before) => {
                    effects.retired_cold_components_changed |=
                        before != &state.retired_cold_classical_components;
                }
                UndoEntry::RetiredColdPq(before) => {
                    effects.retired_cold_components_changed |=
                        before != &state.retired_cold_pq_components;
                }
                UndoEntry::Governance(before) => {
                    effects.governance_state_changed |= before != &state.governance;
                    effects.governance_params_changed |= before.params != state.governance.params;
                    for id in before
                        .gov_nonces
                        .keys()
                        .chain(state.governance.gov_nonces.keys())
                        .copied()
                    {
                        if before.gov_nonces.get(&id) != state.governance.gov_nonces.get(&id) {
                            effects.governance_nonces_changed.insert(id);
                        }
                    }
                    for id in before
                        .proposals
                        .keys()
                        .chain(state.governance.proposals.keys())
                        .copied()
                    {
                        if before.proposals.get(&id) != state.governance.proposals.get(&id) {
                            effects.proposals_changed.insert(id);
                        }
                    }
                }
                UndoEntry::Utxos(before) => {
                    effects.utxo_set_changed |= before != &state.utxos;
                    for entry in before.all_entries() {
                        if !state.utxos.contains(&entry.utxo_id) {
                            effects.spent_utxos.insert(entry.utxo_id);
                        }
                    }
                }
                UndoEntry::SlashMembershipRoots(before) => {
                    effects.slash_membership_history_changed |=
                        before != &state.slash_membership_roots;
                }
                UndoEntry::EvictedValidatorTombstones(before) => {
                    for id in before
                        .iter()
                        .map(|(id, _)| *id)
                        .chain(state.evicted_validator_tombstones.iter().map(|(id, _)| *id))
                    {
                        if before.get(&id) != state.evicted_validator_tombstones.get(&id) {
                            effects.tombstones_changed.insert(id);
                        }
                    }
                }
                UndoEntry::ConsensusSnapshots(before) => {
                    effects.consensus_snapshots_changed |= before != &state.consensus_snapshots;
                }
                UndoEntry::RewardEconomicSnapshot(before) => {
                    effects.reward_economic_snapshot_changed |=
                        before != &state.reward_economic_snapshot;
                }
            }
        }
        effects.state_commitment_cache_changed |=
            self.commitment_before != state.state_commitment_v2;
    }

    /// Ensure StateCommitmentV2 exists when active.
    pub(crate) fn ensure_state_commitment_v2(&mut self) -> StateResult<()> {
        self.mark_commitment_touched();
        self.state.ensure_state_commitment_v2(self.height)?;
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
            fee_reward_pool: self.state.fee_reward_pool,
            epoch_slash_event_count: self.state.epoch_slash_event_count,
            monetary_ledger: self.state.monetary_ledger,
            monetary_aggregates: self.state.monetary_aggregates,
            election_seed: self.state.election_seed,
            election_seed_height: self.state.election_seed_height,
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
        self.snapshot_evicted_validator_tombstones();
        self.snapshot_utxos();
        self.record_scalars();
        self.mark_commitment_touched();
    }

    /// Record delegator identity registry state before live-operation registry mutations.
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
        self.snapshot_utxos();
        let removed = self.state.utxos.spend_at_height(id, self.height)?;
        if let Some(entry) = &removed {
            self.effects.spent_utxos.insert(entry.utxo_id);
            self.effects.utxo_set_changed = true;
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
        self.snapshot_utxos();
        let id = self
            .state
            .utxos
            .insert(output, height, tx_index, output_index)?;
        self.effects.utxo_set_changed = true;
        self.after_mutation()?;
        Ok(id)
    }

    /// Insert a tranche-refund UTXO with provenance bound to the same
    /// canonical lifetime and rollback entry.
    pub(crate) fn insert_tranche_refund_utxo(
        &mut self,
        output: OutputV1,
        height: u64,
        tx_index: u32,
        output_index: u32,
        event: TrancheRefundEventV1,
    ) -> StateResult<Bytes32> {
        self.snapshot_utxos();
        let id = self.state.utxos.insert_with_tranche_refund(
            output,
            height,
            tx_index,
            output_index,
            Some(event),
        )?;
        self.effects.utxo_set_changed = true;
        self.after_mutation()?;
        Ok(id)
    }

    /// Insert or replace one canonical staking position.
    pub(crate) fn put_stake_position(&mut self, position: StakePositionV1) -> StateResult<()> {
        self.snapshot_position_state();
        if let Some(commitment) = self.state.state_commitment_v2.as_mut() {
            commitment.put_stake_position(&position)?;
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
            commitment.delete_stake_position(position_id)?;
        }
        self.state.stake_positions.remove(position_id);
        self.state.position_tranche_index.remove(position_id);
        self.after_mutation()
    }

    /// Insert one immutable unbonding tranche.
    pub(crate) fn put_unbonding_tranche(&mut self, tranche: UnbondingTrancheV1) -> StateResult<()> {
        self.snapshot_position_state();
        if let Some(commitment) = self.state.state_commitment_v2.as_mut() {
            commitment.put_unbonding_tranche(&tranche)?;
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
            commitment.delete_unbonding_tranche(tranche_id)?;
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

    /// Mutate base fee.
    pub(crate) fn set_base_fee(&mut self, base_fee: u64) -> StateResult<()> {
        self.record_scalars();
        self.effects.base_fee_changed |= self.state.base_fee != base_fee;
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

    /// Publish the deterministic seed used for the next consensus height.
    pub(crate) fn set_election_seed(&mut self, seed: Bytes64, height: u64) -> StateResult<()> {
        self.record_scalars();
        self.state.election_seed = seed;
        self.state.election_seed_height = height;
        self.after_mutation()
    }

    /// Add fee accounting.
    pub(crate) fn apply_fee_accounting(
        &mut self,
        burn_amount: u64,
        validator_amount: u64,
    ) -> StateResult<()> {
        let gross = burn_amount
            .checked_add(validator_amount)
            .ok_or(crate::StateError::ValueOverflow)?;
        crate::monetary::MonetaryDeltaV1::split_burn(
            gross,
            validator_amount,
            burn_amount,
            crate::monetary::BurnSourceV1::TransactionFee,
        )?;
        self.record_scalars();
        self.state.total_supply = self.state.total_supply.checked_sub(burn_amount).ok_or(
            crate::StateError::InvariantViolation {
                message: "fee burn exceeds total supply",
            },
        )?;
        self.state.fee_reward_pool = self
            .state
            .fee_reward_pool
            .checked_add(validator_amount)
            .ok_or(crate::StateError::ValueOverflow)?;
        self.state.monetary_ledger.cumulative_fee_burned_spark = self
            .state
            .monetary_ledger
            .cumulative_fee_burned_spark
            .checked_add(burn_amount)
            .ok_or(crate::StateError::ValueOverflow)?;
        self.state.monetary_ledger.epoch_fee_burned_spark = self
            .state
            .monetary_ledger
            .epoch_fee_burned_spark
            .checked_add(burn_amount)
            .ok_or(crate::StateError::ValueOverflow)?;
        self.after_mutation()
    }

    /// Add explicit slash accounting.
    pub(crate) fn add_slash_accounting(&mut self, _amount: u64) -> StateResult<()> {
        self.record_scalars();
        self.state.epoch_slash_event_count = self
            .state
            .epoch_slash_event_count
            .checked_add(1)
            .ok_or(crate::StateError::ValueOverflow)?;
        self.after_mutation()
    }

    /// Record a structured slash event for publication only if this transaction commits.
    pub(crate) fn record_slash_event(&mut self, event: crate::CommittedSlashEvent) {
        self.effects.slash_events.push(event);
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
                    self.state.fee_reward_pool = snapshot.fee_reward_pool;
                    self.state.epoch_slash_event_count = snapshot.epoch_slash_event_count;
                    self.state.monetary_ledger = snapshot.monetary_ledger;
                    self.state.monetary_aggregates = snapshot.monetary_aggregates;
                    self.state.election_seed = snapshot.election_seed;
                    self.state.election_seed_height = snapshot.election_seed_height;
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

/// Test-only checkpoint for complex helpers that mutate through a snapshotted
/// `StateTxn` scope rather than through individual transaction methods.
pub(crate) fn complex_mutation_checkpoint() -> StateResult<()> {
    failpoint_after_mutation()
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn set_fail_after_mutation(target: Option<usize>) {
    FAIL_AFTER_MUTATION.with(|cell| cell.set(target));
    MUTATION_COUNT.with(|cell| cell.set(0));
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn mutation_count() -> usize {
    MUTATION_COUNT.with(std::cell::Cell::get)
}
#[cfg(test)]
mod tests {
    use indra_core::types::primitives::TEST_CHAIN_ID;
    use super::*;
    use indra_core::types::{
        consensus_snapshot::{ConsensusSnapshot, ConsensusSnapshotEntry},
        crypto::HybridPubKey,
        primitives::VariableBytes,
        reward_economic_snapshot::{RewardEconomicSnapshot, RewardEconomicValidatorEntry},
        stake_position::{ActiveStakeAggregateV1, PositionCustodyV1, StakePositionV1},
    };

    fn test_output(byte: u8) -> OutputV1 {
        OutputV1 {
            value_spark: 1_000_000,
            owner_pubkey: HybridPubKey {
                classical_pk: Bytes32::from([byte; 32]),
                pq_pk: VariableBytes::from_slice(&[byte; 32]).unwrap(),
            },
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
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        state.slash_membership_roots = vec![original_record];
        state.rebuild_state_commitment_v2(height).unwrap();
        let root_before = state.state_commitment_v2_root(height);

        set_fail_after_mutation(Some(1));
        {
            let mut txn = StateTxn::begin(&mut state, height);
            txn.snapshot_slash_membership_roots();
            txn.mark_commitment_touched();
            txn.state_mut().slash_membership_roots[0].membership_root = Bytes32::from([0xA2; 32]);
            assert!(txn.after_mutation().is_err());
        }
        set_fail_after_mutation(None);

        assert_eq!(state.slash_membership_roots, vec![original_record]);
        assert_eq!(state.state_commitment_v2_root(height), root_before);
    }

    #[test]
    fn rollback_restores_utxo_root_and_proof_after_mutation_and_error() {
        let height = 1;
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let original_id = state
            .utxos
            .insert(test_output(0xA1), height, 0, 0)
            .unwrap();
        let root_before = state.utxos.root_at_height(height);
        let proof_before = state.utxos.prove_at_height(&original_id, height);

        {
            let mut txn = StateTxn::begin(&mut state, height);
            txn.insert_utxo(test_output(0xA2), height, 1, 0).unwrap();
        }
        assert_eq!(state.utxos.root_at_height(height), root_before);
        assert_eq!(state.utxos.prove_at_height(&original_id, height), proof_before);

        set_fail_after_mutation(Some(1));
        {
            let mut txn = StateTxn::begin(&mut state, height);
            assert!(txn.insert_utxo(test_output(0xA3), height, 2, 0).is_err());
        }
        set_fail_after_mutation(None);
        assert_eq!(state.utxos.root_at_height(height), root_before);
        assert_eq!(state.utxos.prove_at_height(&original_id, height), proof_before);
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
                    indra_core::types::block::VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
                    0,
                )
                .unwrap()],
                indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
            )
            .unwrap()
        };
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
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
        state.rebuild_state_commitment_v2(state.height).unwrap();
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
    fn committed_effect_journal_covers_each_mutated_dependency_scope() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let signer = Bytes32::from([0x31; 32]);
        let validator = Bytes32::from([0x32; 32]);
        let governance_signer = Bytes32::from([0x33; 32]);
        let position = StakePositionV1::new(
            validator,
            signer,
            PositionCustodyV1::DelegatorIdentity {
                delegator_id: signer,
            },
            Some(ActiveStakeAggregateV1::new(1_000_000, 0, 0).unwrap()),
            0,
            0,
        )
        .unwrap();
        let position_id = position.position_id;
        let old_base_fee = state.base_fee;
        let before = state.clone();
        let mut txn = StateTxn::begin(
            &mut state,
            indra_core::types::primitives::EPOCH_DURATION_BLOCKS,
        );
        let utxo = txn.insert_utxo(test_output(0x35), 0, 0, 0).unwrap();
        txn.spend_utxo(&utxo).unwrap();
        txn.set_base_fee(old_base_fee.saturating_add(1)).unwrap();
        txn.snapshot_staking_scope();
        txn.state_mut().staking_nonces.insert(signer, 1);
        txn.put_stake_position(position).unwrap();
        txn.snapshot_governance_scope();
        txn.state_mut()
            .governance
            .gov_nonces
            .insert(governance_signer, 1);
        txn.state_mut().governance.params.max_commission_bps = txn
            .state()
            .governance
            .params
            .max_commission_bps
            .saturating_sub(1);
        txn.snapshot_epoch_scope();
        txn.state_mut()
            .slash_membership_roots
            .push(SlashMembershipRootRecord {
                activation_height: 1,
                membership_root: Bytes32::from([0x36; 32]),
            });
        txn.set_tip(
            indra_core::types::primitives::EPOCH_DURATION_BLOCKS,
            Bytes32::from([0x37; 32]),
        )
        .unwrap();
        let effects = txn.commit();

        assert!(effects.spent_utxos.contains(&utxo));
        assert!(effects.utxo_set_changed);
        assert!(effects.base_fee_changed);
        assert!(effects.staking_nonces_changed.contains(&signer));
        assert!(effects
            .governance_nonces_changed
            .contains(&governance_signer));
        assert!(effects.stake_positions_changed.contains(&position_id));
        assert!(effects
            .validator_position_capacity_changed
            .contains(&validator));
        assert!(effects.global_position_tranche_capacity_changed);
        assert!(effects.governance_params_changed);
        assert!(effects.slash_membership_history_changed);
        assert!(effects.epoch_changed);
        let uncovered: Vec<_> = ChainState::changed_fields(&before, &state)
            .into_iter()
            .filter(|field| !effects.covers_field(*field))
            .collect();
        assert!(
            uncovered.is_empty(),
            "uncovered changed fields: {uncovered:?}"
        );
    }
}
