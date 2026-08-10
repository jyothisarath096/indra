//! Epoch transition logic — INDRA v7.1
//!
//! ## What happens at an epoch boundary
//!
//! 1. Compute block reward for current era (pre-minted supply, not inflation)
//! 2. Distribute block reward to active validators proportionally by stake
//!    with saturation-based anti-concentration adjustment
//! 3. Distribute accumulated fee rewards to validators
//! 4. Expire stale rewards
//! 5. Release unbonded validators
//!
//! ## Zero inflation guarantee
//!
//! `state.total_supply` never increases during an epoch transition.
//! Supply only decreases via the fee burn path in `apply.rs`.

use std::collections::HashSet;

use indra_core::{
    types::primitives::{
        bps_of, muldiv, Bytes32, EPOCH_DURATION_BLOCKS, ERA_1_2_DURATION_BLOCKS,
        ERA_1_BLOCK_REWARD_SPARK, ERA_2_BLOCK_REWARD_SPARK, ERA_3_BLOCK_REWARD_SPARK,
        ERA_3_PLUS_DURATION_BLOCKS, HARD_CAP_SPARK, MINIMUM_ACTIVE_SELF_STAKE_SPARK,
        SATURATION_MIN_VALIDATORS,
    },
    EpochRecord,
};

use crate::{
    chain::ChainState,
    error::StateResult,
    governance::{
        GovernanceSnapshot, ProposalPhase, ProposalRecord, QueuedExecution,
        GOVERNANCE_DEPOSIT_RETURN_SUPPORT_BPS, MAX_RETAINED_TERMINAL_GOVERNANCE_PROPOSALS,
    },
    governance_apply::{return_governance_deposit, revalidate_queued_governance_action_or_fail},
    validator::ValidatorStatus,
};

/// Immutable, derived facts for one epoch-boundary state transition.
///
/// This value is deliberately ephemeral: it is never encoded, persisted in
/// `ChainState`, or committed to a state root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochTransitionContext {
    /// Height of the transition block.
    pub boundary_height: u64,
    /// Height certified by the transition block's parent QC.
    pub certified_parent_height: u64,
    /// Epoch whose final produced block is `boundary_height`.
    pub closing_epoch: u64,
    /// First produced block belonging to `closing_epoch`.
    pub closing_start_height: u64,
    /// Last produced block belonging to `closing_epoch`, inclusive.
    pub closing_end_height: u64,
    /// Epoch that begins after the boundary transition completes.
    pub opening_epoch: u64,
}

impl EpochTransitionContext {
    /// Construct and validate context derived from a boundary block and its QC.
    pub fn new(boundary_height: u64, certified_parent_height: u64) -> StateResult<Self> {
        if boundary_height == 0 || !boundary_height.is_multiple_of(EPOCH_DURATION_BLOCKS) {
            return Err(crate::error::StateError::InvariantViolation {
                message: "epoch transition context requires a nonzero boundary height",
            });
        }
        if certified_parent_height.checked_add(1) != Some(boundary_height) {
            return Err(crate::error::StateError::InvariantViolation {
                message: "certified parent height must immediately precede the boundary",
            });
        }
        let opening_epoch = epoch_for_height(boundary_height);
        let closing_epoch =
            opening_epoch
                .checked_sub(1)
                .ok_or(crate::error::StateError::InvariantViolation {
                    message: "epoch boundary has no closing epoch",
                })?;
        let closing_start_height = boundary_height
            .checked_sub(EPOCH_DURATION_BLOCKS)
            .and_then(|height| height.checked_add(1))
            .ok_or(crate::error::StateError::InvariantViolation {
                message: "closing epoch height range overflow",
            })?;
        Ok(Self {
            boundary_height,
            certified_parent_height,
            closing_epoch,
            closing_start_height,
            closing_end_height: boundary_height,
            opening_epoch,
        })
    }
}

/// Apply the epoch transition to the chain state.
pub fn apply_epoch_transition(
    state: &mut ChainState,
    context: &EpochTransitionContext,
    timestamp_secs: u64,
) -> StateResult<EpochRecord> {
    #[cfg(test)]
    install_reward_basis_if_missing(state)?;
    apply_epoch_transition_at_height(state, context, timestamp_secs)
}

/// Apply an epoch transition using an explicit, validated boundary context.
pub fn apply_epoch_transition_at_height(
    state: &mut ChainState,
    context: &EpochTransitionContext,
    timestamp_secs: u64,
) -> StateResult<EpochRecord> {
    apply_epoch_transition_final(state, context, timestamp_secs)
}

fn apply_epoch_transition_final(
    state: &mut ChainState,
    context: &EpochTransitionContext,
    timestamp_secs: u64,
) -> StateResult<EpochRecord> {
    let height = context.boundary_height;
    let current_epoch = context.opening_epoch;
    // DETERMINISM NOTE: timestamp_secs is stored ONLY in EpochRecord
    // and does NOT affect ChainState mutations. State root is computed
    // from ChainState only. EpochRecord is stored separately in EpochStore.
    eprintln!(
        "[epoch] transition at height={} epoch={} validators={} total_stake={} fee_pool={}",
        state.height,
        current_epoch,
        state.validators.active_count(),
        state.validators.total_active_stake(),
        state.fee_reward_pool,
    );
    apply_governance_phase_transitions(state, current_epoch, height)?;
    prune_governance_history_if_active(state, height);
    let closing_snapshot = state
        .snapshot_for_consensus_height(context.closing_end_height)
        .map_err(|error| crate::error::StateError::InvalidConsensusSnapshot(error.to_string()))?
        .clone();
    let active_before: HashSet<Bytes32> = state
        .validators
        .active_validators()
        .map(|v| v.validator_id)
        .collect();
    let active_validators_before =
        u32::try_from(closing_snapshot.entries().len()).map_err(|_| {
            crate::error::StateError::InvalidConsensusSnapshot(
                "closing snapshot membership does not fit EpochRecord".to_string(),
            )
        })?;
    // Active-set size and ranking use the same self-stake model as consensus
    // voting weight and reward weight. Delegations affect reward splitting,
    // but do not increase proposer/voter/election weight in this protocol.
    let total_staked = state
        .validators
        .total_selectable_self_stake_at_height(height);
    let record_total_staked = closing_snapshot.total_weight_spark;
    let fee_pool_before = state.fee_reward_pool;
    let fees_burned_this_epoch = state.epoch_fees_burned;
    let explicit_slashed_this_epoch = state.epoch_slashed_spark;
    let explicit_slash_count_this_epoch = state.epoch_slash_event_count;
    let record_epoch = context.closing_epoch;
    let record_start_height = context.closing_start_height;
    let record_end_height = context.closing_end_height;
    // `block_reward_spark` is intentionally the rate at the first rewarded
    // height. A closing epoch may span an era boundary; the exact mixed-rate
    // amount is carried by `block_rewards_distributed`.
    let reward_per_block = block_reward_at_height(context.closing_start_height);
    let epoch_block_reward =
        block_rewards_for_inclusive_range(context.closing_start_height, context.closing_end_height);

    state.validators.select_active_set(total_staked, height);
    let supply_before = state.total_supply;
    distribute_block_rewards(state, epoch_block_reward, current_epoch, height)?;

    assert!(
        state.total_supply <= HARD_CAP_SPARK,
        "CRITICAL: Hard cap violated. supply={} cap={}",
        state.total_supply,
        HARD_CAP_SPARK
    );
    debug_assert_eq!(
        state.total_supply, supply_before,
        "supply changed during epoch transition"
    );

    distribute_fee_rewards(state, current_epoch, height)?;
    let fee_rewards_distributed = fee_pool_before.saturating_sub(state.fee_reward_pool);
    // This boundary pays the epoch that just elapsed. Activate a due
    // commission only after both reward sources and virtual auto-delegation
    // accounting have used the rate that governed that elapsed epoch.
    apply_pending_commission_changes(state, current_epoch);
    state.validators.expire_stale_rewards(current_epoch);
    release_unbonded_validators(state, current_epoch);
    crate::stake_positions::release_matured_position_tranches(state, height)?;
    let liveness_epoch = context.closing_epoch;
    let closing_members = closing_snapshot
        .entries()
        .iter()
        .map(|entry| entry.validator_id)
        .collect::<Vec<_>>();
    let (liveness_slashed, liveness_penalty_count) =
        apply_liveness_penalties(state, liveness_epoch, height, Some(&closing_members));

    let mut active_after: Vec<Bytes32> = state
        .validators
        .active_validators()
        .map(|v| v.validator_id)
        .collect();
    active_after.sort_by_key(|id| id.0);
    let active_after_set: HashSet<Bytes32> = active_after.iter().copied().collect();
    let mut validators_joined: Vec<Bytes32> = active_after_set
        .difference(&active_before)
        .copied()
        .collect();
    validators_joined.sort_by_key(|id| id.0);
    let mut validators_left: Vec<Bytes32> = active_before
        .difference(&active_after_set)
        .copied()
        .collect();
    validators_left.sort_by_key(|id| id.0);

    let record = EpochRecord {
        epoch: record_epoch,
        start_height: record_start_height,
        end_height: record_end_height,
        timestamp_secs,
        active_validators: active_validators_before,
        total_staked_spark: record_total_staked,
        block_rewards_distributed: if state.validators.total_active_stake() == 0 {
            0
        } else {
            epoch_block_reward
        },
        fee_rewards_distributed,
        fees_burned: fees_burned_this_epoch,
        total_slashed_spark: explicit_slashed_this_epoch.saturating_add(liveness_slashed),
        slash_event_count: explicit_slash_count_this_epoch.saturating_add(liveness_penalty_count),
        liveness_penalty_count,
        avg_base_fee: state.base_fee,
        validators_joined,
        validators_left,
        era: era_for_height(record_start_height),
        block_reward_spark: reward_per_block,
        total_supply: state.total_supply,
        treasury_balance: state.treasury_balance,
    };

    eprintln!(
        "[epoch] complete epoch={} total_supply={} treasury={}",
        current_epoch, state.total_supply, state.treasury_balance,
    );
    state.epoch_fees_burned = 0;
    state.epoch_slashed_spark = 0;
    state.epoch_slash_event_count = 0;
    state.rebuild_state_commitment_v2(height);
    Ok(record)
}

fn block_rewards_for_inclusive_range(start_height: u64, end_height: u64) -> u64 {
    (start_height..=end_height).fold(0u64, |total, height| {
        total.saturating_add(block_reward_at_height(height))
    })
}

fn apply_pending_commission_changes(state: &mut ChainState, current_epoch: u64) {
    let validator_ids: Vec<Bytes32> = state
        .validators
        .all_validators()
        .filter(|validator| {
            validator
                .pending_commission_effective_epoch
                .map(|effective| effective <= current_epoch)
                .unwrap_or(false)
        })
        .map(|validator| validator.validator_id)
        .collect();

    for validator_id in validator_ids {
        if let Some(validator) = state.validators.get_mut(&validator_id) {
            if let Some(pending_bps) = validator.pending_commission_bps.take() {
                validator.commission_bps = pending_bps as u32;
                eprintln!(
                    "[epoch] validator {} commission change activated: {}bps",
                    hex::encode(&validator_id.0[..4]),
                    validator.commission_bps,
                );
            }
            validator.pending_commission_effective_epoch = None;
        }
    }
}

/// Compute the block reward in Spark for a given block height.
pub fn block_reward_at_height(height: u64) -> u64 {
    if height < ERA_1_2_DURATION_BLOCKS {
        ERA_1_BLOCK_REWARD_SPARK
    } else if height < ERA_1_2_DURATION_BLOCKS.saturating_mul(2) {
        ERA_2_BLOCK_REWARD_SPARK
    } else {
        let era_3_start = ERA_1_2_DURATION_BLOCKS.saturating_mul(2);
        let blocks_since_era_3 = height.saturating_sub(era_3_start);
        let era_index = blocks_since_era_3 / ERA_3_PLUS_DURATION_BLOCKS;
        ERA_3_BLOCK_REWARD_SPARK >> era_index.min(63)
    }
}

fn era_for_height(height: u64) -> u64 {
    if height < ERA_1_2_DURATION_BLOCKS {
        1
    } else if height < ERA_1_2_DURATION_BLOCKS.saturating_mul(2) {
        2
    } else {
        3 + height.saturating_sub(ERA_1_2_DURATION_BLOCKS.saturating_mul(2))
            / ERA_3_PLUS_DURATION_BLOCKS
    }
}

/// Apply governance phase transitions at an epoch boundary.
pub fn apply_governance_phase_transitions(
    state: &mut ChainState,
    current_epoch: u64,
    height: u64,
) -> StateResult<()> {
    // Governance ops in the boundary block are intentionally processed before
    // this epoch-transition pass runs (see `apply_block`). Therefore every
    // phase boundary is inclusive for the phase being closed: an action
    // included in the exact block that reaches `commit_start_epoch`,
    // `reveal_start_epoch`, or `tally_epoch` is still evaluated under the old
    // phase, and the transition takes effect immediately afterward.
    let proposal_ids: Vec<Bytes32> = state.governance.proposals.keys().copied().collect();
    for proposal_id in proposal_ids {
        let phase = match state.governance.proposals.get(&proposal_id) {
            Some(proposal) => proposal.phase,
            None => continue,
        };
        match phase {
            ProposalPhase::Deliberation => {
                let commit_start = state.governance.proposals[&proposal_id].commit_start_epoch;
                if current_epoch >= commit_start {
                    let snapshot1 = take_governance_snapshot(state);
                    if let Some(proposal) = state.governance.proposals.get_mut(&proposal_id) {
                        proposal.snapshot1 = Some(snapshot1);
                        proposal.phase = ProposalPhase::Commit;
                    }
                    eprintln!(
                        "[governance] proposal {} -> Commit phase",
                        hex::encode(&proposal_id.0[..4])
                    );
                }
            }
            ProposalPhase::Commit => {
                let reveal_start = state.governance.proposals[&proposal_id].reveal_start_epoch;
                if current_epoch >= reveal_start {
                    if let Some(proposal) = state.governance.proposals.get_mut(&proposal_id) {
                        proposal.phase = ProposalPhase::Reveal;
                    }
                    eprintln!(
                        "[governance] proposal {} -> Reveal phase",
                        hex::encode(&proposal_id.0[..4])
                    );
                }
            }
            ProposalPhase::Reveal => {
                let tally_epoch = state.governance.proposals[&proposal_id].tally_epoch;
                if current_epoch >= tally_epoch {
                    tally_proposal(state, proposal_id, height)?;
                }
            }
            ProposalPhase::ExecDelay => {
                auto_execute_ready(state, proposal_id, current_epoch, height);
            }
            _ => {}
        }
    }
    Ok(())
}

fn prune_governance_history_if_active(state: &mut ChainState, height: u64) {
    let pruned = state
        .governance
        .prune_terminal_proposals(MAX_RETAINED_TERMINAL_GOVERNANCE_PROPOSALS);
    if !pruned.is_empty() {
        eprintln!(
            "[governance] pruned {} terminal proposal records at height={} (retaining newest {})",
            pruned.len(),
            height,
            MAX_RETAINED_TERMINAL_GOVERNANCE_PROPOSALS
        );
    }
}

fn tally_proposal(state: &mut ChainState, proposal_id: Bytes32, height: u64) -> StateResult<()> {
    let snapshot2 = {
        let proposal = state
            .governance
            .proposals
            .get(&proposal_id)
            .ok_or(crate::error::StateError::GovernanceProposalNotFound)?;
        compute_snapshot2(proposal)
    };
    let mut should_return_deposit = false;
    let mut should_queue = None;
    if let Some(proposal) = state.governance.proposals.get_mut(&proposal_id) {
        proposal.snapshot2 = Some(snapshot2);
        let (yes, no, abstain) = tally_votes(proposal);
        proposal.yes_stake = yes;
        proposal.no_stake = no;
        proposal.abstain_stake = abstain;
        let snap2 = proposal.snapshot2.as_ref().ok_or_else(|| {
            crate::error::StateError::InvariantViolation {
                message: "snapshot2 missing after tally",
            }
        })?;
        // Governance "quorum" fields are intentionally YES-stake thresholds
        // over total proposal snapshot stake, not participation thresholds.
        // See docs/GOVERNANCE_THRESHOLD_DESIGN.md.
        let quorum_bps = match proposal.tier {
            indra_core::types::governance::ProposalTier::Standard => {
                state.governance.params.governance_quorum_bps
            }
            indra_core::types::governance::ProposalTier::Critical => {
                state.governance.params.governance_critical_quorum_bps
            }
        };
        let passed = snap2.quorum_met_at_height(yes, quorum_bps, height);
        proposal.passed = Some(passed);
        if passed {
            proposal.phase = ProposalPhase::ExecDelay;
            should_queue = Some(QueuedExecution {
                proposal_id,
                action: proposal.action.clone(),
                executable_epoch: proposal.executable_after_epoch,
                executed: false,
            });
            should_return_deposit = !proposal.deposit_burned;
        } else {
            let support_bps = snap2.support_bps_at_height(yes, height);
            if support_bps >= GOVERNANCE_DEPOSIT_RETURN_SUPPORT_BPS && !proposal.deposit_burned {
                should_return_deposit = true;
            } else {
                proposal.deposit_burned = true;
            }
            proposal.phase = ProposalPhase::Failed;
        }
    }
    if let Some(exec) = should_queue {
        state.governance.queued_executions.push(exec);
    }
    if should_return_deposit {
        return_governance_deposit(state, proposal_id, height)?;
    }
    Ok(())
}

fn auto_execute_ready(
    state: &mut ChainState,
    proposal_id: Bytes32,
    current_epoch: u64,
    height: u64,
) {
    let Some(exec_index) = state.governance.queued_executions.iter().position(|exec| {
        exec.proposal_id == proposal_id && !exec.executed && current_epoch >= exec.executable_epoch
    }) else {
        return;
    };
    let action = state.governance.queued_executions[exec_index]
        .action
        .clone();
    match revalidate_queued_governance_action_or_fail(state, proposal_id, &action, height) {
        Ok(true) => {
            state.governance.params.apply_action(&action);
            state.governance.queued_executions[exec_index].executed = true;
            if let Some(proposal) = state.governance.proposals.get_mut(&proposal_id) {
                proposal.phase = ProposalPhase::Executed;
            }
            eprintln!(
                "[governance] auto-executed proposal {} at epoch {}",
                hex::encode(&proposal_id.0[..4]),
                current_epoch
            );
        }
        Ok(false) => {
            state.governance.queued_executions[exec_index].executed = true;
        }
        Err(err) => {
            eprintln!(
                "[governance] auto-execute failed while handling proposal {}: {}",
                hex::encode(&proposal_id.0[..4]),
                err
            );
        }
    }
}

/// Take a governance stake snapshot.
pub fn take_governance_snapshot(state: &ChainState) -> GovernanceSnapshot {
    let mut weights = std::collections::BTreeMap::new();
    let mut total = 0u64;
    for validator in state.validators.all_validators() {
        if matches!(
            validator.status,
            ValidatorStatus::Active | ValidatorStatus::Registered
        ) {
            let delegated = state
                .stake_positions
                .values()
                .filter(|position| {
                    position.validator_id == validator.validator_id
                        && position.principal_owner_id != validator.validator_id
                })
                .filter_map(|position| position.active)
                .fold(0u64, |sum, active| {
                    sum.saturating_add(active.principal_spark)
                });
            let weight = validator.stake_spark.saturating_add(delegated);
            if weight > 0 {
                weights.insert(validator.validator_id, weight);
                total = total.saturating_add(weight);
            }
        }
    }
    GovernanceSnapshot {
        weights,
        total_stake: total,
    }
}

/// Compute Snapshot 2 by applying governance redelegation overlay.
pub fn compute_snapshot2(proposal: &ProposalRecord) -> GovernanceSnapshot {
    let mut weights = proposal
        .snapshot1
        .as_ref()
        .map(|snapshot| snapshot.weights.clone())
        .unwrap_or_default();
    let total = proposal
        .snapshot1
        .as_ref()
        .map(|snapshot| snapshot.total_stake)
        .unwrap_or(0);
    for redelegation in &proposal.redelegations {
        if !proposal.reveals.contains_key(&redelegation.from_validator) {
            continue;
        }
        if !proposal.reveals.contains_key(&redelegation.to_validator) {
            continue;
        }
        if !weights.contains_key(&redelegation.from_validator) {
            eprintln!(
                "[governance] skipping malformed redelegation: from_validator {} absent from snapshot1",
                hex::encode(&redelegation.from_validator.0[..4])
            );
            continue;
        }
        if !weights.contains_key(&redelegation.to_validator) {
            eprintln!(
                "[governance] skipping malformed redelegation: to_validator {} absent from snapshot1",
                hex::encode(&redelegation.to_validator.0[..4])
            );
            continue;
        }
        let from_weight = weights
            .get_mut(&redelegation.from_validator)
            .expect("from_validator presence checked above");
        if *from_weight < redelegation.amount_spark {
            eprintln!(
                "[governance] skipping malformed redelegation: amount {} exceeds snapshot weight {} for validator {}",
                redelegation.amount_spark,
                *from_weight,
                hex::encode(&redelegation.from_validator.0[..4])
            );
            continue;
        }
        *from_weight = from_weight.saturating_sub(redelegation.amount_spark);
        let to_weight = weights
            .get_mut(&redelegation.to_validator)
            .expect("to_validator presence checked above");
        *to_weight = to_weight.saturating_add(redelegation.amount_spark);
    }
    GovernanceSnapshot {
        weights,
        total_stake: total,
    }
}

/// Tally proposal votes.
pub fn tally_votes(proposal: &ProposalRecord) -> (u64, u64, u64) {
    let Some(snapshot2) = proposal.snapshot2.as_ref() else {
        return (0, 0, 0);
    };
    let snapshot1_total = proposal
        .snapshot1
        .as_ref()
        .map(|snapshot| snapshot.total_stake)
        .unwrap_or(snapshot2.total_stake);
    let mut yes = 0u64;
    let mut no = 0u64;
    let mut abstain = 0u64;
    for (validator_id, weight) in &snapshot2.weights {
        match proposal.reveals.get(validator_id) {
            Some(reveal) if reveal.vote => yes = yes.saturating_add(*weight),
            Some(_) => no = no.saturating_add(*weight),
            None => abstain = abstain.saturating_add(*weight),
        }
    }
    let counted = yes.saturating_add(no).saturating_add(abstain);
    if counted < snapshot1_total {
        abstain = abstain.saturating_add(snapshot1_total.saturating_sub(counted));
    }
    (yes, no, abstain)
}

fn saturation_adjusted_reward(
    raw_reward: u64,
    validator_stake: u64,
    total_active_stake: u64,
    active_validator_count: u64,
    height: u64,
) -> u64 {
    if total_active_stake == 0 || active_validator_count == 0 {
        return raw_reward;
    }

    if active_validator_count <= SATURATION_MIN_VALIDATORS {
        return raw_reward;
    }

    let saturation_point = total_active_stake / active_validator_count;
    if saturation_point == 0 || validator_stake <= saturation_point {
        return raw_reward;
    }

    proportional_reward(raw_reward, saturation_point, validator_stake, height)
}

fn proportional_reward(amount: u64, numerator: u64, denominator: u64, _height: u64) -> u64 {
    muldiv(amount, numerator, denominator)
}

fn distribute_block_rewards(
    state: &mut ChainState,
    epoch_block_reward: u64,
    current_epoch: u64,
    height: u64,
) -> crate::error::StateResult<()> {
    #[cfg(test)]
    install_reward_basis_if_missing(state)?;
    distribute_snapshot_rewards(
        state,
        epoch_block_reward,
        current_epoch,
        height,
        SnapshotRewardSource::Block,
    )
}

pub(crate) fn distribute_fee_rewards(
    state: &mut ChainState,
    current_epoch: u64,
    height: u64,
) -> crate::error::StateResult<()> {
    #[cfg(test)]
    install_reward_basis_if_missing(state)?;
    let fee_pool = state.fee_reward_pool;
    if fee_pool == 0 {
        return Ok(());
    }
    state.fee_reward_pool = 0;
    crate::txn::complex_mutation_checkpoint()?;
    let result = distribute_snapshot_rewards(
        state,
        fee_pool,
        current_epoch,
        height,
        SnapshotRewardSource::Fee,
    );
    if result.is_err() {
        state.fee_reward_pool = fee_pool;
    }
    result
}

#[cfg(test)]
fn install_reward_basis_if_missing(state: &mut ChainState) -> crate::error::StateResult<()> {
    if state.validators.active_count() == 0 {
        let classical = indra_crypto::ClassicalKeypair::from_seed(&[0xFE; 32]);
        let pq = indra_crypto::PqKeypair::from_seed(&[0xFD; 32]).expect("test PQ key");
        let public = indra_crypto::HybridKeypair::new(classical, pq).public_key();
        state.validators.upsert(crate::validator::ValidatorEntry {
            validator_id: Bytes32::from([0xFC; 32]),
            name: "epoch-test-authority".into(),
            hybrid_classical_pk: Some(public.classical.0),
            hybrid_pq_pk: Some(public.pq.0.to_vec()),
            vrf_pk: Some(indra_crypto::VrfKeypair::from_seed(&[0xFB; 32]).public_key()),
            stake_spark: indra_core::types::primitives::MINIMUM_ACTIVE_SELF_STAKE_SPARK,
            status: crate::validator::ValidatorStatus::Active,
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
            cold_hybrid_classical_pk: Some(public.classical.0),
            cold_hybrid_pq_pk: Some(public.pq.0),
            cold_key_version: 1,
            cold_nonce: 0,
        })?;
    }
    let active_ids = state
        .validators
        .active_validators()
        .map(|validator| validator.validator_id)
        .collect::<std::collections::BTreeSet<_>>();
    let snapshot_ids = state
        .consensus_snapshots
        .first()
        .map(|snapshot| {
            snapshot
                .entries()
                .iter()
                .map(|entry| entry.validator_id)
                .collect::<std::collections::BTreeSet<_>>()
        })
        .unwrap_or_default();
    if !active_ids.is_empty()
        && (state.consensus_snapshots.is_empty() || active_ids != snapshot_ids)
    {
        let validator_positions = state
            .validators
            .active_validators()
            .map(|validator| (validator.validator_id, validator.stake_spark))
            .collect::<Vec<_>>();
        for (validator_id, principal) in validator_positions {
            let custody =
                indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
                    validator_id,
                };
            let position_id = indra_core::types::stake_position::derive_position_id(
                validator_id,
                validator_id,
                custody,
            );
            if !state.stake_positions.contains_key(&position_id) {
                let position = indra_core::types::stake_position::StakePositionV1::new(
                    validator_id,
                    validator_id,
                    custody,
                    Some(
                        indra_core::types::stake_position::ActiveStakeAggregateV1::new(
                            principal, 0, 0,
                        )
                        .map_err(|error| {
                            crate::error::StateError::InvalidStakingOp(error.to_string())
                        })?,
                    ),
                    0,
                    0,
                )
                .map_err(|error| crate::error::StateError::InvalidStakingOp(error.to_string()))?;
                state.stake_positions.insert(position.position_id, position);
            }
        }
        state
            .rebuild_position_tranche_index()
            .map_err(|error| crate::error::StateError::InvalidStakingOp(error.to_string()))?;
        let consensus = state.build_consensus_snapshot(1, 0)?;
        let economic = state.build_reward_economic_snapshot(&consensus)?;
        state.consensus_snapshots = vec![consensus];
        state.reward_economic_snapshot = Some(economic);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum SnapshotRewardSource {
    Block,
    Fee,
}

fn distribute_snapshot_rewards(
    state: &mut ChainState,
    pool: u64,
    current_epoch: u64,
    height: u64,
    source: SnapshotRewardSource,
) -> crate::error::StateResult<()> {
    use crate::error::StateError;

    if pool == 0 {
        return Ok(());
    }
    // Clone the immutable basis so reward credits can mutate their canonical
    // destinations without borrowing authority from mutable live state.
    let (consensus, economic) = state.reward_economic_snapshot_for_height(height)?;
    let consensus = consensus.clone();
    let economic = economic.clone();
    let total_stake = consensus.total_weight_spark;
    if total_stake == 0 {
        return Err(StateError::InvalidRewardEconomicSnapshot(
            "paired consensus snapshot has zero total weight".to_string(),
        ));
    }
    let validator_count = consensus.entries().len() as u64;
    let mut distributed = 0u64;

    for member in consensus.entries() {
        let economic_entry = economic.validator(&member.validator_id).ok_or_else(|| {
            StateError::InvalidRewardEconomicSnapshot(
                "paired economic validator entry is missing".to_string(),
            )
        })?;
        let raw = proportional_reward(pool, member.consensus_weight_spark, total_stake, height);
        let validator_pool = match source {
            SnapshotRewardSource::Block => saturation_adjusted_reward(
                raw,
                member.consensus_weight_spark,
                total_stake,
                validator_count,
                height,
            ),
            SnapshotRewardSource::Fee => raw,
        };
        let delegated = economic_entry.total_active_delegated_spark;
        if delegated == 0 {
            credit_position_reward(
                state,
                member.validator_id,
                member.validator_id,
                indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
                    validator_id: member.validator_id,
                },
                validator_pool,
                current_epoch,
            )?;
            distributed = distributed.saturating_add(validator_pool);
            continue;
        }

        let commission = bps_of(validator_pool, economic_entry.commission_bps);
        let delegator_pool = validator_pool.saturating_sub(commission);
        credit_position_reward(
            state,
            member.validator_id,
            member.validator_id,
            indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
                validator_id: member.validator_id,
            },
            commission,
            current_epoch,
        )?;
        distributed = distributed.saturating_add(commission);

        let mut delegated_distributed = 0u64;
        for delegator in economic_entry.delegators() {
            let combined = delegator
                .total_active_principal_spark()
                .map_err(|error| StateError::InvalidRewardEconomicSnapshot(error.to_string()))?;
            let identity_reward = muldiv(delegator_pool, combined, delegated);
            let auto_reward = if delegator.auto_delegated_principal_spark == 0 {
                0
            } else {
                muldiv(
                    identity_reward,
                    delegator.auto_delegated_principal_spark,
                    combined,
                )
            };
            let bonded_reward = identity_reward.saturating_sub(auto_reward);

            if bonded_reward > 0 {
                credit_position_reward(
                    state,
                    member.validator_id,
                    delegator.delegator_id,
                    indra_core::types::stake_position::PositionCustodyV1::DelegatorIdentity {
                        delegator_id: delegator.delegator_id,
                    },
                    bonded_reward,
                    current_epoch,
                )?;
            }
            if auto_reward > 0 {
                credit_position_reward(
                    state,
                    delegator.delegator_id,
                    delegator.delegator_id,
                    indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
                        validator_id: delegator.delegator_id,
                    },
                    auto_reward,
                    current_epoch,
                )?;
            }
            delegated_distributed = delegated_distributed.saturating_add(identity_reward);
        }
        distributed = distributed.saturating_add(delegated_distributed);
    }

    let remainder = pool.saturating_sub(distributed);
    match source {
        SnapshotRewardSource::Block => {
            state.treasury_balance = state.treasury_balance.saturating_add(remainder)
        }
        SnapshotRewardSource::Fee => {
            state.fee_reward_pool = state.fee_reward_pool.saturating_add(remainder)
        }
    }
    crate::txn::complex_mutation_checkpoint()?;
    Ok(())
}

fn credit_position_reward(
    state: &mut ChainState,
    validator_id: Bytes32,
    principal_owner_id: Bytes32,
    custody: indra_core::types::stake_position::PositionCustodyV1,
    amount: u64,
    current_epoch: u64,
) -> crate::error::StateResult<()> {
    if amount == 0 {
        return Ok(());
    }
    let position_id = indra_core::types::stake_position::derive_position_id(
        validator_id,
        principal_owner_id,
        custody,
    );
    let mut position = state
        .stake_positions
        .get(&position_id)
        .cloned()
        .ok_or_else(|| {
            crate::error::StateError::InvalidRewardEconomicSnapshot(
                "frozen reward position destination is missing".into(),
            )
        })?;
    position.pending_rewards_spark = position.pending_rewards_spark.saturating_add(amount);
    position.rewards_last_epoch = current_epoch;
    state.stake_positions.insert(position_id, position.clone());
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_stake_position(&position);
    }
    crate::txn::complex_mutation_checkpoint()?;
    Ok(())
}

fn release_unbonded_validators(state: &mut ChainState, current_epoch: u64) {
    let mut ids: Vec<indra_core::types::primitives::Bytes32> = state
        .validators
        .all_validators()
        .filter(|v| {
            matches!(
                v.status,
                ValidatorStatus::Unbonding { unbonding_end_epoch }
                if unbonding_end_epoch <= current_epoch
            )
        })
        .map(|v| v.validator_id)
        .collect();
    ids.sort_by_key(|id| id.0);

    for id in ids {
        if let Some(entry) = state.validators.get_mut(&id) {
            entry.stake_spark = 0;
            entry.status = ValidatorStatus::Exited;
        }
    }
}

fn apply_liveness_penalties(
    state: &mut ChainState,
    current_epoch: u64,
    _height: u64,
    snapshot_members: Option<&[Bytes32]>,
) -> (u64, u32) {
    let mut total_slashed = 0u64;
    let mut penalty_count = 0u32;
    let threshold = state.governance.params.slash_liveness_threshold_epochs;
    let slash_bps = state.governance.params.slash_liveness_bps;
    let validator_ids: Vec<Bytes32> = match snapshot_members {
        Some(members) => members
            .iter()
            .copied()
            .filter(|validator_id| {
                state.validators.get(validator_id).is_some_and(|validator| {
                    matches!(
                        validator.status,
                        ValidatorStatus::Active | ValidatorStatus::Registered
                    )
                })
            })
            .collect(),
        None => state
            .validators
            .active_validators()
            .map(|v| v.validator_id)
            .collect(),
    };

    for validator_id in validator_ids {
        let (missed, stake) = {
            let v = match state.validators.get(&validator_id) {
                Some(v) => v,
                None => continue,
            };
            let missed = current_epoch.saturating_sub(v.last_active_epoch);
            (missed, v.stake_spark)
        };

        if missed >= threshold && stake > 0 {
            let penalty = bps_of(stake, slash_bps);
            if let Some(v) = state.validators.get_mut(&validator_id) {
                v.stake_spark = v.stake_spark.saturating_sub(penalty);
                if v.stake_spark < MINIMUM_ACTIVE_SELF_STAKE_SPARK {
                    v.status = ValidatorStatus::Registered;
                }
            }
            state.total_supply = state.total_supply.saturating_sub(penalty);
            total_slashed = total_slashed.saturating_add(penalty);
            penalty_count = penalty_count.saturating_add(1);
            eprintln!(
                "[liveness] validator {} missed {} epochs, penalty={} Spark burned",
                hex::encode(&validator_id.0[..4]),
                missed,
                penalty,
            );
        }
    }
    (total_slashed, penalty_count)
}

/// True if the given height is the last block of an epoch.
pub fn is_epoch_boundary(height: u64) -> bool {
    height > 0 && height.is_multiple_of(EPOCH_DURATION_BLOCKS)
}

/// Epoch number for a given height (0-indexed).
pub fn epoch_for_height(height: u64) -> u64 {
    height / EPOCH_DURATION_BLOCKS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compute_state_root,
        governance::{GovernanceRedelegation, ProposalRecord, VoteCommit, VoteReveal},
        validator::{ValidatorEntry, ValidatorStatus},
    };
    use indra_core::{
        codec::Encode,
        types::{
            crypto::HybridPubKey,
            governance::GovernableAction,
            primitives::{
                Bytes32, VariableBytes, COMMISSION_CHANGE_DELAY_EPOCHS, DEFAULT_COMMISSION_BPS,
                DUST_LIMIT_SPARK, ERA_1_2_DURATION_BLOCKS, ERA_1_BLOCK_REWARD_SPARK,
                ERA_2_BLOCK_REWARD_SPARK, ERA_3_BLOCK_REWARD_SPARK, ERA_3_PLUS_DURATION_BLOCKS,
                MINIMUM_ACTIVE_SELF_STAKE_SPARK, SLASH_LIVENESS_BPS,
                SLASH_LIVENESS_THRESHOLD_EPOCHS, SPARK_PER_INDRA,
            },
        },
    };

    fn governance_test_pubkey(byte: u8) -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::from([byte; 32]),
            pq_pk: VariableBytes::from_slice(&[byte; 32]).unwrap(),
        }
    }

    fn governance_pruning_test_id(index: u64) -> Bytes32 {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&index.to_le_bytes());
        Bytes32::from(bytes)
    }

    fn governance_pruning_test_proposal(
        index: u64,
        phase: ProposalPhase,
        proposed_epoch: u64,
    ) -> ProposalRecord {
        ProposalRecord {
            proposal_id: governance_pruning_test_id(index),
            proposer_id: Bytes32::from([0x71; 32]),
            proposer_pubkey: governance_test_pubkey(0x72),
            tier: GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK,
            }
            .tier(),
            action: GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK,
            },
            title: format!("proposal-{index}"),
            description: "terminal proposal pruning test".into(),
            deposit_spark: 0,
            deposit_burned: false,
            proposed_epoch,
            commit_start_epoch: proposed_epoch.saturating_add(30),
            reveal_start_epoch: proposed_epoch.saturating_add(50),
            tally_epoch: proposed_epoch.saturating_add(60),
            exec_delay_epochs: 0,
            executable_after_epoch: proposed_epoch.saturating_add(60),
            phase,
            snapshot1: None,
            commits: Default::default(),
            reveals: Default::default(),
            redelegations: Vec::new(),
            redelegated_delegators: Default::default(),
            snapshot2: None,
            yes_stake: 0,
            no_stake: 0,
            abstain_stake: 0,
            passed: match phase {
                ProposalPhase::Failed => Some(false),
                ProposalPhase::Executed => Some(true),
                _ => None,
            },
        }
    }

    fn make_validator(id_byte: u8, stake: u64) -> ValidatorEntry {
        let classical = indra_crypto::ClassicalKeypair::from_seed(&[id_byte; 32]);
        let pq = indra_crypto::PqKeypair::from_seed(&[id_byte.wrapping_add(1); 32]).unwrap();
        let public = indra_crypto::HybridKeypair::new(classical, pq).public_key();
        ValidatorEntry {
            validator_id: Bytes32::from([id_byte; 32]),
            name: format!("validator-{id_byte}"),
            hybrid_classical_pk: Some(public.classical.0),
            hybrid_pq_pk: Some(public.pq.0.to_vec()),
            vrf_pk: Some(
                indra_crypto::VrfKeypair::from_seed(&[id_byte.wrapping_add(2); 32]).public_key(),
            ),
            stake_spark: stake,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            pending_rewards: 0,
            rewards_last_epoch: 0,
            self_report_count: 0,
            commission_bps: DEFAULT_COMMISSION_BPS,
            pending_commission_bps: None,
            pending_commission_effective_epoch: None,
            min_delegation_spark: DUST_LIMIT_SPARK,
            auto_delegate_to: None,
            network_addr: None,
            network_addr_last_updated_epoch: None,
            cold_hybrid_classical_pk: Some(public.classical.0),
            cold_hybrid_pq_pk: Some(public.pq.0),
            cold_key_version: 1,
            cold_nonce: 0,
        }
    }

    fn make_snapshot_validator(id_byte: u8, stake: u64) -> ValidatorEntry {
        let mut validator = make_validator(id_byte, stake);
        let classical = indra_crypto::ClassicalKeypair::from_seed(&[id_byte; 32]);
        let pq = indra_crypto::PqKeypair::from_seed(&[id_byte.wrapping_add(1); 32]).unwrap();
        let public = indra_crypto::HybridKeypair::new(classical, pq).public_key();
        validator.hybrid_classical_pk = Some(public.classical.0);
        validator.hybrid_pq_pk = Some(public.pq.0.to_vec());
        validator.vrf_pk =
            Some(indra_crypto::VrfKeypair::from_seed(&[id_byte.wrapping_add(2); 32]).public_key());
        validator
    }

    #[test]
    fn epoch_transition_context_validates_and_derives_boundary_facts() {
        let context = EpochTransitionContext::new(300, 299).unwrap();
        assert_eq!(
            context,
            EpochTransitionContext {
                boundary_height: 300,
                certified_parent_height: 299,
                closing_epoch: 0,
                closing_start_height: 1,
                closing_end_height: 300,
                opening_epoch: 1,
            }
        );
        assert!(EpochTransitionContext::new(0, 0).is_err());
        assert!(EpochTransitionContext::new(299, 298).is_err());
        assert!(EpochTransitionContext::new(300, 298).is_err());
    }

    #[test]
    fn reward_snapshot_pairing_missing_or_mismatched_fails_closed() {
        let mut state = ChainState::new_genesis();
        state
            .validators
            .upsert(make_snapshot_validator(1, 1_000_000_000))
            .unwrap();
        let consensus = state
            .build_consensus_snapshot(u64::MAX, u64::MAX - 1)
            .unwrap();
        state.consensus_snapshots = vec![consensus];
        assert!(distribute_block_rewards(&mut state, 1_000, 1, u64::MAX).is_err());

        let other = state
            .build_consensus_snapshot(u64::MAX - 1, u64::MAX - 2)
            .unwrap();
        state.reward_economic_snapshot =
            Some(state.build_reward_economic_snapshot(&other).unwrap());
        assert!(distribute_block_rewards(&mut state, 1_000, 1, u64::MAX).is_err());
    }

    #[test]
    fn snapshot_liveness_uses_membership_but_live_stake_and_exempts_non_live_targets() {
        let mut state = ChainState::new_genesis();
        state.governance.params.slash_liveness_threshold_epochs = 1;
        state.governance.params.slash_liveness_bps = 1_000;

        let mut registered = make_validator(0xB1, 20_000);
        registered.status = ValidatorStatus::Registered;
        let registered_id = registered.validator_id;
        state.validators.upsert(registered).unwrap();

        let mut slashed = make_validator(0xB2, 30_000);
        slashed.status = ValidatorStatus::Slashed;
        let slashed_id = slashed.validator_id;
        state.validators.upsert(slashed).unwrap();

        let tombstoned_id = Bytes32::from([0xB3; 32]);
        state.evicted_validator_tombstones.insert(
            tombstoned_id,
            crate::validator::EvictedValidatorTombstoneV2 {
                validator_id: tombstoned_id,
                eviction_height: 300,
                eviction_epoch: 1,
                last_classical_vote_pk: [1; 32],
                last_pq_vote_pk: [2; indra_crypto::PQ_PK_BYTES],
                last_vrf_pk: [3; 32],
                cold_custody: None,
                retained_position_ids: Vec::new(),
                retained_tranche_ids: Vec::new(),
            },
        );

        let promoted = make_validator(0xB4, 40_000);
        let promoted_id = promoted.validator_id;
        state.validators.upsert(promoted).unwrap();

        let replay_initial = state.clone();
        let supply_before = state.total_supply;
        let (slashed_total, count) = apply_liveness_penalties(
            &mut state,
            1,
            600,
            Some(&[registered_id, slashed_id, tombstoned_id]),
        );
        assert_eq!(count, 1);
        assert_eq!(slashed_total, 2_000);
        assert_eq!(state.total_supply, supply_before - 2_000);
        assert_eq!(
            state.validators.get(&registered_id).unwrap().stake_spark,
            18_000
        );
        assert_eq!(
            state.validators.get(&slashed_id).unwrap().stake_spark,
            30_000
        );
        assert_eq!(
            state.validators.get(&promoted_id).unwrap().stake_spark,
            40_000
        );
        let mut replay = replay_initial;
        let replay_result = apply_liveness_penalties(
            &mut replay,
            1,
            600,
            Some(&[registered_id, slashed_id, tombstoned_id]),
        );
        assert_eq!(replay_result, (slashed_total, count));
        assert_eq!(replay.encode_to_vec(), state.encode_to_vec());
        assert_eq!(compute_state_root(&replay), compute_state_root(&state));
    }

    #[test]
    fn epoch_boundary_detection() {
        assert!(!is_epoch_boundary(0));
        assert!(!is_epoch_boundary(1));
        assert!(!is_epoch_boundary(299));
        assert!(is_epoch_boundary(300));
        assert!(!is_epoch_boundary(301));
        assert!(is_epoch_boundary(600));
    }

    #[test]
    fn epoch_for_height_correct() {
        assert_eq!(epoch_for_height(0), 0);
        assert_eq!(epoch_for_height(299), 0);
        assert_eq!(epoch_for_height(300), 1);
        assert_eq!(epoch_for_height(600), 2);
    }

    #[test]
    fn governance_pruning_changes_state_root_at_activation_when_records_removed() {
        let mut state = ChainState::new_genesis();
        state.height = 1;
        for index in 0..(MAX_RETAINED_TERMINAL_GOVERNANCE_PROPOSALS + 1) {
            let proposal =
                governance_pruning_test_proposal(index as u64, ProposalPhase::Failed, index as u64);
            state
                .governance
                .proposals
                .insert(proposal.proposal_id, proposal);
        }
        let before = compute_state_root(&state);
        let height = state.height;

        prune_governance_history_if_active(&mut state, height);

        assert_eq!(
            state.governance.proposals.len(),
            MAX_RETAINED_TERMINAL_GOVERNANCE_PROPOSALS
        );
        assert!(!state
            .governance
            .proposals
            .contains_key(&governance_pruning_test_id(0)));
        assert_ne!(compute_state_root(&state), before);
    }

    #[test]
    fn governance_pruning_replay_across_activation_is_deterministic() {
        let boundary_height = EPOCH_DURATION_BLOCKS;
        let mut continuous = ChainState::new_genesis();
        continuous.height = boundary_height;
        for index in 0..(MAX_RETAINED_TERMINAL_GOVERNANCE_PROPOSALS + 3) {
            let proposal =
                governance_pruning_test_proposal(index as u64, ProposalPhase::Failed, index as u64);
            continuous
                .governance
                .proposals
                .insert(proposal.proposal_id, proposal);
        }
        let mut replayed = continuous.clone();

        let context =
            EpochTransitionContext::new(boundary_height, boundary_height.saturating_sub(1))
                .unwrap();
        install_reward_basis_if_missing(&mut continuous).unwrap();
        install_reward_basis_if_missing(&mut replayed).unwrap();
        apply_epoch_transition_at_height(&mut continuous, &context, 111).unwrap();
        apply_epoch_transition_at_height(&mut replayed, &context, 999).unwrap();

        assert_eq!(
            continuous.governance.proposals.keys().collect::<Vec<_>>(),
            replayed.governance.proposals.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            compute_state_root(&continuous),
            compute_state_root(&replayed)
        );
    }

    #[test]
    fn block_reward_era_1() {
        assert_eq!(block_reward_at_height(0), ERA_1_BLOCK_REWARD_SPARK);
        assert_eq!(block_reward_at_height(1_000_000), ERA_1_BLOCK_REWARD_SPARK);
        assert_eq!(
            block_reward_at_height(ERA_1_2_DURATION_BLOCKS - 1),
            ERA_1_BLOCK_REWARD_SPARK
        );
    }

    #[test]
    fn block_reward_era_2() {
        assert_eq!(
            block_reward_at_height(ERA_1_2_DURATION_BLOCKS),
            ERA_2_BLOCK_REWARD_SPARK
        );
        assert_eq!(ERA_2_BLOCK_REWARD_SPARK, ERA_1_BLOCK_REWARD_SPARK / 2);
    }

    #[test]
    fn block_reward_era_3() {
        let era_3_start = ERA_1_2_DURATION_BLOCKS * 2;
        assert_eq!(
            block_reward_at_height(era_3_start),
            ERA_3_BLOCK_REWARD_SPARK
        );
        assert_eq!(ERA_3_BLOCK_REWARD_SPARK, ERA_2_BLOCK_REWARD_SPARK / 2);
    }

    #[test]
    fn block_reward_halves_each_era() {
        let r1 = block_reward_at_height(0);
        let r2 = block_reward_at_height(ERA_1_2_DURATION_BLOCKS);
        let era_3_start = ERA_1_2_DURATION_BLOCKS * 2;
        let r3 = block_reward_at_height(era_3_start);
        let r4 = block_reward_at_height(era_3_start + ERA_3_PLUS_DURATION_BLOCKS);
        assert_eq!(r2, r1 / 2);
        assert_eq!(r3, r2 / 2);
        assert_eq!(r4, r3 / 2);
    }

    #[test]
    fn reward_distribution_no_overflow_large_stake() {
        let epoch_block_reward: u64 = 356_760_000_000;
        let validator_stake: u64 = 100_000_000_000;
        let total_stake: u64 = 400_000_000_000;

        let result = muldiv(epoch_block_reward, validator_stake, total_stake);
        assert_eq!(
            result, 89_190_000_000,
            "Expected 89,190,000,000 Spark per validator, got {}",
            result
        );
    }

    #[test]
    fn muldiv_no_overflow() {
        let a: u64 = u64::MAX / 2;
        let b: u64 = 3;
        let c: u64 = 3;
        assert_eq!(muldiv(a, b, c), u64::MAX / 2);
    }

    #[test]
    fn bps_of_correct() {
        let value: u64 = 1_000_000_000 * SPARK_PER_INDRA;
        let result = bps_of(value, 1_000);
        assert_eq!(result, 100_000_000 * SPARK_PER_INDRA);
    }

    #[test]
    fn epoch_reward_correct_with_real_values() {
        let epoch_block_reward: u64 = ERA_1_BLOCK_REWARD_SPARK * EPOCH_DURATION_BLOCKS;
        let validator_stake: u64 = 100_000_000_000;
        let total_stake: u64 = 400_000_000_000;

        let raw = muldiv(epoch_block_reward, validator_stake, total_stake);
        assert_eq!(
            raw, 89_190_000_000,
            "Epoch reward wrong: got {} expected 89190000000",
            raw
        );
    }

    #[test]
    fn governance_deposit_refund_depends_on_support_not_unrelated_non_reveal() {
        let mut state = crate::chain::ChainState::new_genesis();
        let proposal_id = Bytes32::from([0x42; 32]);
        let yes_validator = Bytes32::from([0xA1; 32]);
        let missing_reveal_validator = Bytes32::from([0xB1; 32]);
        let proposer_pubkey = governance_test_pubkey(0x42);
        let action = GovernableAction::SetMinDelegationSpark {
            value: DUST_LIMIT_SPARK,
        };
        let mut weights = std::collections::BTreeMap::new();
        weights.insert(yes_validator, 10);
        weights.insert(missing_reveal_validator, 90);
        let snapshot1 = GovernanceSnapshot {
            weights,
            total_stake: 100,
        };
        let mut proposal = ProposalRecord {
            proposal_id,
            proposer_id: Bytes32::from([0x42; 32]),
            proposer_pubkey: proposer_pubkey.clone(),
            tier: action.tier(),
            action,
            title: "refund".into(),
            description: "non-reveal should not burn proposer deposit".into(),
            deposit_spark: 1_000,
            deposit_burned: false,
            proposed_epoch: 0,
            commit_start_epoch: 0,
            reveal_start_epoch: 0,
            tally_epoch: 0,
            exec_delay_epochs: 0,
            executable_after_epoch: 0,
            phase: ProposalPhase::Reveal,
            snapshot1: Some(snapshot1),
            commits: Default::default(),
            reveals: Default::default(),
            redelegations: Vec::new(),
            redelegated_delegators: Default::default(),
            snapshot2: None,
            yes_stake: 0,
            no_stake: 0,
            abstain_stake: 0,
            passed: None,
        };
        proposal.commits.insert(
            yes_validator,
            VoteCommit {
                validator_id: yes_validator,
                commit_hash: Bytes32::from([0xC1; 32]),
                committed_epoch: 0,
            },
        );
        proposal.commits.insert(
            missing_reveal_validator,
            VoteCommit {
                validator_id: missing_reveal_validator,
                commit_hash: Bytes32::from([0xC2; 32]),
                committed_epoch: 0,
            },
        );
        proposal.reveals.insert(
            yes_validator,
            VoteReveal {
                validator_id: yes_validator,
                vote: true,
                revealed_epoch: 0,
            },
        );
        state.governance.proposals.insert(proposal_id, proposal);

        apply_governance_phase_transitions(&mut state, 0, 0).unwrap();

        let proposal = state.governance.proposals.get(&proposal_id).unwrap();
        assert_eq!(proposal.phase, ProposalPhase::Failed);
        assert_eq!(proposal.passed, Some(false));
        assert_eq!(proposal.yes_stake, 10);
        assert_eq!(proposal.abstain_stake, 90);
        assert!(!proposal.deposit_burned);
        assert_eq!(proposal.deposit_spark, 0);
        assert!(state.utxos.all_entries().any(|entry| {
            entry.output.owner_pubkey == proposer_pubkey && entry.output.value_spark == 1_000
        }));
    }

    #[test]
    fn snapshot2_never_creates_weight_for_non_snapshot1_validator() {
        let proposal_id = Bytes32::from([0x51; 32]);
        let from_validator = Bytes32::from([0xA1; 32]);
        let non_snapshot_validator = Bytes32::from([0xB1; 32]);
        let mut weights = std::collections::BTreeMap::new();
        weights.insert(from_validator, 100);
        let mut proposal = ProposalRecord {
            proposal_id,
            proposer_id: Bytes32::from([0x01; 32]),
            proposer_pubkey: governance_test_pubkey(0x51),
            tier: GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK,
            }
            .tier(),
            action: GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK,
            },
            title: "snapshot2".into(),
            description: "defensive target bound".into(),
            deposit_spark: 0,
            deposit_burned: false,
            proposed_epoch: 0,
            commit_start_epoch: 0,
            reveal_start_epoch: 0,
            tally_epoch: 0,
            exec_delay_epochs: 0,
            executable_after_epoch: 0,
            phase: ProposalPhase::Reveal,
            snapshot1: Some(GovernanceSnapshot {
                weights,
                total_stake: 100,
            }),
            commits: Default::default(),
            reveals: Default::default(),
            redelegations: vec![GovernanceRedelegation {
                delegator_id: Bytes32::from([0xD1; 32]),
                from_validator,
                to_validator: non_snapshot_validator,
                amount_spark: 40,
            }],
            redelegated_delegators: Default::default(),
            snapshot2: None,
            yes_stake: 0,
            no_stake: 0,
            abstain_stake: 0,
            passed: None,
        };
        proposal.reveals.insert(
            from_validator,
            VoteReveal {
                validator_id: from_validator,
                vote: false,
                revealed_epoch: 0,
            },
        );
        proposal.reveals.insert(
            non_snapshot_validator,
            VoteReveal {
                validator_id: non_snapshot_validator,
                vote: true,
                revealed_epoch: 0,
            },
        );

        let snapshot2 = compute_snapshot2(&proposal);

        assert_eq!(snapshot2.weights.get(&from_validator), Some(&100));
        assert!(!snapshot2.weights.contains_key(&non_snapshot_validator));
        assert_eq!(snapshot2.total_stake, 100);
    }

    #[test]
    fn snapshot2_redelegation_moves_weight_when_both_validators_are_in_snapshot1() {
        let proposal_id = Bytes32::from([0x52; 32]);
        let from_validator = Bytes32::from([0xA2; 32]);
        let to_validator = Bytes32::from([0xB2; 32]);
        let mut weights = std::collections::BTreeMap::new();
        weights.insert(from_validator, 100);
        weights.insert(to_validator, 50);
        let mut proposal = ProposalRecord {
            proposal_id,
            proposer_id: Bytes32::from([0x02; 32]),
            proposer_pubkey: governance_test_pubkey(0x52),
            tier: GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK,
            }
            .tier(),
            action: GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK,
            },
            title: "snapshot2".into(),
            description: "normal redelegation".into(),
            deposit_spark: 0,
            deposit_burned: false,
            proposed_epoch: 0,
            commit_start_epoch: 0,
            reveal_start_epoch: 0,
            tally_epoch: 0,
            exec_delay_epochs: 0,
            executable_after_epoch: 0,
            phase: ProposalPhase::Reveal,
            snapshot1: Some(GovernanceSnapshot {
                weights,
                total_stake: 150,
            }),
            commits: Default::default(),
            reveals: Default::default(),
            redelegations: vec![GovernanceRedelegation {
                delegator_id: Bytes32::from([0xD2; 32]),
                from_validator,
                to_validator,
                amount_spark: 40,
            }],
            redelegated_delegators: Default::default(),
            snapshot2: None,
            yes_stake: 0,
            no_stake: 0,
            abstain_stake: 0,
            passed: None,
        };
        proposal.reveals.insert(
            from_validator,
            VoteReveal {
                validator_id: from_validator,
                vote: false,
                revealed_epoch: 0,
            },
        );
        proposal.reveals.insert(
            to_validator,
            VoteReveal {
                validator_id: to_validator,
                vote: true,
                revealed_epoch: 0,
            },
        );

        let snapshot2 = compute_snapshot2(&proposal);

        assert_eq!(snapshot2.weights.get(&from_validator), Some(&60));
        assert_eq!(snapshot2.weights.get(&to_validator), Some(&90));
        assert_eq!(snapshot2.total_stake, 150);
    }

    #[test]
    fn commission_change_takes_effect_after_delay() {
        let mut state = crate::chain::ChainState::new_genesis();
        let mut validator = make_validator(0xC1, 1_000);
        let validator_id = validator.validator_id;
        validator.commission_bps = 1_000;
        validator.pending_commission_bps = Some(1_500);
        validator.pending_commission_effective_epoch = Some(COMMISSION_CHANGE_DELAY_EPOCHS);
        state.validators.upsert(validator).unwrap();

        apply_epoch_transition(
            &mut state,
            &EpochTransitionContext::new(
                (COMMISSION_CHANGE_DELAY_EPOCHS - 1).saturating_mul(EPOCH_DURATION_BLOCKS),
                (COMMISSION_CHANGE_DELAY_EPOCHS - 1)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();
        let before_effective = state.validators.get(&validator_id).unwrap();
        assert_eq!(before_effective.commission_bps, 1_000);
        assert_eq!(before_effective.pending_commission_bps, Some(1_500));

        apply_epoch_transition(
            &mut state,
            &EpochTransitionContext::new(
                (COMMISSION_CHANGE_DELAY_EPOCHS).saturating_mul(EPOCH_DURATION_BLOCKS),
                (COMMISSION_CHANGE_DELAY_EPOCHS)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();
        let after_effective = state.validators.get(&validator_id).unwrap();
        assert_eq!(after_effective.commission_bps, 1_500);
        assert_eq!(after_effective.pending_commission_bps, None);
        assert_eq!(after_effective.pending_commission_effective_epoch, None);
    }

    #[test]
    fn proposer_cannot_earn_extra_reward_by_including_more_transactions() {
        let mut empty_block_state = crate::chain::ChainState::new_genesis();
        let mut full_block_state = crate::chain::ChainState::new_genesis();
        let validator = make_validator(0xC7, 1_000);
        let validator_id = validator.validator_id;
        empty_block_state
            .validators
            .upsert(validator.clone())
            .unwrap();
        full_block_state.validators.upsert(validator).unwrap();

        distribute_block_rewards(&mut empty_block_state, 1_000, 1, 1).unwrap();
        distribute_block_rewards(&mut full_block_state, 1_000, 1, 1).unwrap();

        assert_eq!(
            empty_block_state
                .validators
                .get(&validator_id)
                .unwrap()
                .pending_rewards,
            full_block_state
                .validators
                .get(&validator_id)
                .unwrap()
                .pending_rewards,
            "base block reward is epoch/stake based, not transaction-count based"
        );
    }

    #[test]
    fn saturation_below_point_full_reward() {
        let reward = saturation_adjusted_reward(1_000_000, 100, 200_000, 200, 0);
        assert_eq!(reward, 1_000_000);
    }

    #[test]
    fn saturation_above_point_reduced_reward() {
        let reward = saturation_adjusted_reward(1_000_000, 2_000, 200_000, 200, 0);
        assert_eq!(reward, 500_000);
    }

    #[test]
    fn saturation_at_point_full_reward() {
        let reward = saturation_adjusted_reward(1_000_000, 1_000, 200_000, 200, 0);
        assert_eq!(reward, 1_000_000);
    }

    #[test]
    fn saturation_disabled_for_small_validator_sets() {
        let reward = saturation_adjusted_reward(1_000_000, 50_000, 200_000, 20, 0);
        assert_eq!(reward, 1_000_000);
    }

    #[test]
    fn epoch_transition_does_not_increase_supply() {
        let mut state = crate::chain::ChainState::new_genesis();
        let supply_before = state.total_supply;
        apply_epoch_transition(
            &mut state,
            &EpochTransitionContext::new(
                (1u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (1u64)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();
        assert_eq!(state.total_supply, supply_before);
    }

    #[test]
    fn epoch_transition_does_not_increase_treasury() {
        let mut state = crate::chain::ChainState::new_genesis();
        let treasury_before = state.treasury_balance;
        apply_epoch_transition(
            &mut state,
            &EpochTransitionContext::new(
                (1u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (1u64)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();
        assert_eq!(state.treasury_balance, treasury_before);
    }

    #[test]
    fn liveness_penalty_applied_after_threshold() {
        let mut state = crate::chain::ChainState::new_genesis();
        let initial_stake = MINIMUM_ACTIVE_SELF_STAKE_SPARK + 2_000_000;
        let validator = make_validator(0x91, initial_stake);
        let validator_id = validator.validator_id;
        state.validators.upsert(validator).unwrap();
        apply_epoch_transition(
            &mut state,
            &EpochTransitionContext::new(
                (4u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (4u64)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();
        let expected_penalty = initial_stake.saturating_mul(SLASH_LIVENESS_BPS as u64) / 10_000;
        assert_eq!(
            state.validators.get(&validator_id).unwrap().stake_spark,
            initial_stake - expected_penalty
        );
        assert_eq!(
            state.validators.get(&validator_id).unwrap().status,
            ValidatorStatus::Active
        );
    }

    #[test]
    fn liveness_no_penalty_within_threshold() {
        let mut state = crate::chain::ChainState::new_genesis();
        let initial_stake = MINIMUM_ACTIVE_SELF_STAKE_SPARK + 2_000_000;
        let validator = make_validator(0x92, initial_stake);
        let validator_id = validator.validator_id;
        state.validators.upsert(validator).unwrap();
        apply_epoch_transition(
            &mut state,
            &EpochTransitionContext::new(
                (2u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (2u64)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();
        assert_eq!(
            state.validators.get(&validator_id).unwrap().stake_spark,
            initial_stake
        );
    }

    #[test]
    fn liveness_penalty_burns_supply() {
        let mut state = crate::chain::ChainState::new_genesis();
        let initial_stake = MINIMUM_ACTIVE_SELF_STAKE_SPARK + 2_000_000;
        state
            .validators
            .upsert(make_validator(0x93, initial_stake))
            .unwrap();
        let supply_before = state.total_supply;
        apply_epoch_transition(
            &mut state,
            &EpochTransitionContext::new(
                (4u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (4u64)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();
        let expected_penalty = initial_stake.saturating_mul(SLASH_LIVENESS_BPS as u64) / 10_000;
        assert_eq!(state.total_supply, supply_before - expected_penalty);
    }

    #[test]
    fn liveness_penalty_demotes_when_self_stake_crosses_below_minimum() {
        let mut state = crate::chain::ChainState::new_genesis();
        let initial_stake = MINIMUM_ACTIVE_SELF_STAKE_SPARK + 500_000;
        let validator = make_validator(0x94, initial_stake);
        let validator_id = validator.validator_id;
        state.validators.upsert(validator).unwrap();

        apply_epoch_transition(
            &mut state,
            &EpochTransitionContext::new(
                (4u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (4u64)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();

        let expected_penalty = initial_stake.saturating_mul(SLASH_LIVENESS_BPS as u64) / 10_000;
        let validator = state.validators.get(&validator_id).unwrap();
        assert_eq!(validator.stake_spark, initial_stake - expected_penalty);
        assert!(validator.stake_spark < MINIMUM_ACTIVE_SELF_STAKE_SPARK);
        assert_eq!(validator.status, ValidatorStatus::Registered);
    }

    #[test]
    fn liveness_penalty_policy_is_explicitly_documented() {
        let params = crate::governance::GovernableParams::default();
        assert_eq!(params.slash_liveness_bps, SLASH_LIVENESS_BPS);
        assert_eq!(
            params.slash_liveness_threshold_epochs,
            SLASH_LIVENESS_THRESHOLD_EPOCHS
        );
        assert!(SLASH_LIVENESS_BPS > 0);
        assert!(SLASH_LIVENESS_THRESHOLD_EPOCHS > 0);
    }

    #[test]
    fn epoch_transition_is_deterministic() {
        let mut s1 = crate::chain::ChainState::new_genesis();
        let mut s2 = crate::chain::ChainState::new_genesis();
        apply_epoch_transition(
            &mut s1,
            &EpochTransitionContext::new(
                (1u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (1u64)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();
        apply_epoch_transition(
            &mut s2,
            &EpochTransitionContext::new(
                (1u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (1u64)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();
        assert_eq!(s1.total_supply, s2.total_supply);
        assert_eq!(s1.treasury_balance, s2.treasury_balance);
    }

    #[test]
    fn epoch_transition_is_order_independent() {
        let validators = [
            make_validator(0x01, 1_000_000),
            make_validator(0x02, 2_000_000),
            make_validator(0x03, 3_000_000),
            make_validator(0x04, 4_000_000),
        ];

        let mut s1 = crate::chain::ChainState::new_genesis();
        let mut s2 = crate::chain::ChainState::new_genesis();
        s1.fee_reward_pool = 123_456;
        s2.fee_reward_pool = 123_456;

        for validator in validators.iter().cloned() {
            s1.validators.upsert(validator).unwrap();
        }
        for validator in validators.iter().cloned().rev() {
            s2.validators.upsert(validator).unwrap();
        }

        apply_epoch_transition(
            &mut s1,
            &EpochTransitionContext::new(
                (1u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (1u64)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();
        apply_epoch_transition(
            &mut s2,
            &EpochTransitionContext::new(
                (1u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (1u64)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();

        for validator in validators {
            let id = validator.validator_id;
            assert_eq!(
                s1.validators.get(&id).unwrap().pending_rewards,
                s2.validators.get(&id).unwrap().pending_rewards
            );
            assert_eq!(
                s1.validators.get(&id).unwrap().status,
                s2.validators.get(&id).unwrap().status
            );
        }

        assert_eq!(compute_state_root(&s1), compute_state_root(&s2));
    }

    #[test]
    fn minimum_active_stake_reselection_and_liveness_are_replay_deterministic() {
        let mut steady = make_validator(0xA1, MINIMUM_ACTIVE_SELF_STAKE_SPARK + 5_000_000);
        steady.status = ValidatorStatus::Registered;
        steady.last_active_epoch = 3;

        let mut below = make_validator(0xA2, MINIMUM_ACTIVE_SELF_STAKE_SPARK - 1);
        below.status = ValidatorStatus::Registered;
        below.last_active_epoch = 3;

        let penalized_initial_stake = MINIMUM_ACTIVE_SELF_STAKE_SPARK + 500_000;
        let penalized = make_validator(0xA3, penalized_initial_stake);

        let validators = [steady, below, penalized];
        let mut forward = crate::chain::ChainState::new_genesis();
        let mut reverse = crate::chain::ChainState::new_genesis();
        for validator in validators.iter().cloned() {
            forward.validators.upsert(validator).unwrap();
        }
        for validator in validators.iter().cloned().rev() {
            reverse.validators.upsert(validator).unwrap();
        }

        apply_epoch_transition(
            &mut forward,
            &EpochTransitionContext::new(
                (4u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (4u64)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();
        apply_epoch_transition(
            &mut reverse,
            &EpochTransitionContext::new(
                (4u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (4u64)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();

        assert_eq!(forward, reverse);
        assert_eq!(compute_state_root(&forward), compute_state_root(&reverse));
        assert_eq!(
            forward
                .validators
                .get(&Bytes32::from([0xA1; 32]))
                .unwrap()
                .status,
            ValidatorStatus::Active
        );
        assert_eq!(
            forward
                .validators
                .get(&Bytes32::from([0xA2; 32]))
                .unwrap()
                .status,
            ValidatorStatus::Registered
        );
        assert_eq!(
            forward
                .validators
                .get(&Bytes32::from([0xA3; 32]))
                .unwrap()
                .status,
            ValidatorStatus::Registered
        );
    }

    #[test]
    fn auto_delegation_skipped_if_target_not_active() {
        let mut state = crate::chain::ChainState::new_genesis();
        for i in 1..=22u8 {
            let mut validator =
                make_validator(i, (23u64 - i as u64) * MINIMUM_ACTIVE_SELF_STAKE_SPARK);
            if i == 22 {
                validator.auto_delegate_to = Some(Bytes32::from([0x15; 32]));
            }
            state.validators.upsert(validator).unwrap();
        }

        apply_epoch_transition(
            &mut state,
            &EpochTransitionContext::new(
                (1u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (1u64)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();

        let inactive_id = Bytes32::from([0x16; 32]);
        let target_id = Bytes32::from([0x15; 32]);
        assert_eq!(
            state.validators.get(&target_id).unwrap().status,
            ValidatorStatus::Registered
        );
        assert_eq!(
            state.validators.get(&inactive_id).unwrap().pending_rewards,
            0
        );
    }

    #[test]
    fn auto_delegation_does_not_affect_active_set_selection() {
        let mut state = crate::chain::ChainState::new_genesis();
        for i in 1..=22u8 {
            let mut validator =
                make_validator(i, (23u64 - i as u64) * MINIMUM_ACTIVE_SELF_STAKE_SPARK);
            if i == 22 {
                validator.auto_delegate_to = Some(Bytes32::from([0x15; 32]));
            }
            state.validators.upsert(validator).unwrap();
        }

        apply_epoch_transition(
            &mut state,
            &EpochTransitionContext::new(
                (1u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (1u64)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();

        assert_eq!(
            state
                .validators
                .get(&Bytes32::from([0x15; 32]))
                .unwrap()
                .status,
            ValidatorStatus::Registered
        );
        assert_eq!(
            state
                .validators
                .get(&Bytes32::from([0x16; 32]))
                .unwrap()
                .status,
            ValidatorStatus::Registered
        );
    }

    #[test]
    fn auto_delegate_to_changes_state_root() {
        let mut with_auto = crate::chain::ChainState::new_genesis();
        let mut without_auto = crate::chain::ChainState::new_genesis();
        let mut validator = make_validator(0x71, 1_000_000);
        without_auto.validators.upsert(validator.clone()).unwrap();
        validator.auto_delegate_to = Some(Bytes32::from([0x72; 32]));
        with_auto.validators.upsert(validator).unwrap();

        assert_ne!(
            compute_state_root(&with_auto),
            compute_state_root(&without_auto)
        );
    }

    #[test]
    fn auto_delegation_does_not_violate_supply_invariant() {
        let mut state = crate::chain::ChainState::new_genesis();
        for i in 1..=21u8 {
            let mut validator = make_validator(i, (22u64 - i as u64) * 1_000_000);
            if i == 21 {
                validator.auto_delegate_to = Some(Bytes32::from([0x01; 32]));
            }
            state.validators.upsert(validator).unwrap();
        }
        let supply_before = state.total_supply;

        apply_epoch_transition(
            &mut state,
            &EpochTransitionContext::new(
                (1u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (1u64)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();

        assert_eq!(state.total_supply, supply_before);
    }

    #[test]
    fn frozen_auto_delegation_edge_survives_target_eviction_for_payout() {
        let mut state = crate::chain::ChainState::new_genesis();
        let source_id = Bytes32::from([0xE1; 32]);
        let target_id = Bytes32::from([0xE2; 32]);
        let mut source = make_snapshot_validator(0xE1, 1_000_000);
        source.validator_id = source_id;
        source.auto_delegate_to = Some(target_id);
        let mut target = make_snapshot_validator(0xE2, 1_000_000);
        target.validator_id = target_id;
        state.validators.upsert(source).unwrap();
        state.validators.upsert(target).unwrap();
        for validator_id in [source_id, target_id] {
            let custody =
                indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
                    validator_id,
                };
            let position = indra_core::types::stake_position::StakePositionV1::new(
                validator_id,
                validator_id,
                custody,
                Some(
                    indra_core::types::stake_position::ActiveStakeAggregateV1::new(1_000_000, 1, 1)
                        .unwrap(),
                ),
                0,
                0,
            )
            .unwrap();
            state.stake_positions.insert(position.position_id, position);
        }
        state.finalize_genesis().unwrap();
        let source_position_id = indra_core::types::stake_position::derive_position_id(
            source_id,
            source_id,
            indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
                validator_id: source_id,
            },
        );
        state.validators.remove(&target_id);
        let before = state
            .stake_positions
            .get(&source_position_id)
            .unwrap()
            .pending_rewards_spark;
        distribute_block_rewards(&mut state, 1_000, 1, 1).unwrap();
        assert!(
            state
                .stake_positions
                .get(&source_position_id)
                .unwrap()
                .pending_rewards_spark
                > before,
            "the frozen derived edge must pay its source even after the target leaves the live registry"
        );
    }
}
