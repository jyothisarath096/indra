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
    types::{
        crypto::CommitmentV1,
        primitives::{
            bps_of, delegator_bond_accounting_active, governance_proposal_pruning_active, muldiv,
            normal_bond_release_blinding_active, overflow_fix_active, state_commitment_v2_active,
            validator_cold_key_enforcement_active, Bytes32, VariableBytes, BLOCKS_PER_YEAR,
            COMPACT_STAKE_BOND_RELEASE_BLINDING_DOMAIN, EPOCH_DURATION_BLOCKS,
            ERA_1_2_DURATION_BLOCKS, ERA_1_BLOCK_REWARD_SPARK, ERA_2_BLOCK_REWARD_SPARK,
            ERA_3_BLOCK_REWARD_SPARK, ERA_3_PLUS_DURATION_BLOCKS, HARD_CAP_SPARK,
            MINIMUM_ACTIVE_SELF_STAKE_SPARK, NORMAL_STAKE_BOND_RELEASE_BLINDING_DOMAIN,
            SATURATION_MIN_VALIDATORS, SLASH_BOND_RELEASE_BLINDING_DOMAIN,
            SLASH_EVIDENCE_WINDOW_EPOCHS, STAKING_TX_IDX,
        },
    },
    EpochRecord,
};
use rand::SeedableRng;

use crate::{
    chain::ChainState,
    delegation::reconcile_delegator_from_bonds,
    error::StateResult,
    governance::{
        GovernanceSnapshot, ProposalPhase, ProposalRecord, QueuedExecution,
        GOVERNANCE_DEPOSIT_RETURN_SUPPORT_BPS, MAX_RETAINED_TERMINAL_GOVERNANCE_PROPOSALS,
    },
    governance_apply::{return_governance_deposit, revalidate_queued_governance_action_or_fail},
    identity::resolve_bond_owner_pubkey,
    validator::{ColdKeyStatus, DelegationReturnEvent, DelegationReturnReason, ValidatorStatus},
};

/// Number of epochs per year (5,256,000 blocks/year / 300 blocks/epoch).
pub const EPOCHS_PER_YEAR: u64 = BLOCKS_PER_YEAR / EPOCH_DURATION_BLOCKS;

#[derive(Debug, Clone, Copy)]
struct AutoDelegationSnapshot {
    delegator_id: Bytes32,
    target_id: Bytes32,
    amount_spark: u64,
    previous_staked_spark: u64,
    previous_pending_rewards: u64,
    had_existing_entry: bool,
}

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
    apply_epoch_transition_at_height(state, context, timestamp_secs)
}

/// Apply an epoch transition using an explicit, validated boundary context.
pub fn apply_epoch_transition_at_height(
    state: &mut ChainState,
    context: &EpochTransitionContext,
    timestamp_secs: u64,
) -> StateResult<EpochRecord> {
    apply_epoch_transition_at_gate(
        state,
        context,
        timestamp_secs,
        indra_core::types::primitives::hard_forks::EPOCH_TRANSITION_CONTEXT_HEIGHT,
        indra_core::types::primitives::hard_forks::CONSENSUS_SNAPSHOT_HEIGHT,
    )
}

fn apply_epoch_transition_at_gate(
    state: &mut ChainState,
    context: &EpochTransitionContext,
    timestamp_secs: u64,
    gate_height: u64,
    consensus_snapshot_gate_height: u64,
) -> StateResult<EpochRecord> {
    let height = context.boundary_height;
    let current_epoch = context.opening_epoch;
    let context_active = height >= gate_height;
    enforce_validator_cold_key_enrollment(state, height);
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
    let closing_snapshot = if context.closing_end_height >= consensus_snapshot_gate_height {
        Some(
            state
                .snapshot_for_consensus_height_at_gate(
                    context.closing_end_height,
                    consensus_snapshot_gate_height,
                )
                .map_err(|error| {
                    crate::error::StateError::InvalidConsensusSnapshot(error.to_string())
                })?
                .clone(),
        )
    } else {
        None
    };
    let active_before: HashSet<Bytes32> = state
        .validators
        .active_validators()
        .map(|v| v.validator_id)
        .collect();
    let active_validators_before = match closing_snapshot.as_ref() {
        Some(snapshot) => u32::try_from(snapshot.entries().len()).map_err(|_| {
            crate::error::StateError::InvalidConsensusSnapshot(
                "closing snapshot membership does not fit EpochRecord".to_string(),
            )
        })?,
        None => active_before.len() as u32,
    };
    // Active-set size and ranking use the same self-stake model as consensus
    // voting weight and reward weight. Delegations affect reward splitting,
    // but do not increase proposer/voter/election weight in this protocol.
    let total_staked = state
        .validators
        .total_selectable_self_stake_at_height(height);
    let record_total_staked = closing_snapshot
        .as_ref()
        .map_or(total_staked, |snapshot| snapshot.total_weight_spark);
    let fee_pool_before = state.fee_reward_pool;
    let fees_burned_this_epoch = state.epoch_fees_burned;
    let explicit_slashed_this_epoch = state.epoch_slashed_spark;
    let explicit_slash_count_this_epoch = state.epoch_slash_event_count;
    let record_epoch = if context_active {
        context.closing_epoch
    } else {
        current_epoch.saturating_sub(1)
    };
    let record_start_height = if context_active {
        context.closing_start_height
    } else {
        record_epoch.saturating_mul(EPOCH_DURATION_BLOCKS)
    };
    let record_end_height = if context_active {
        context.closing_end_height
    } else {
        record_start_height
            .saturating_add(EPOCH_DURATION_BLOCKS)
            .saturating_sub(1)
    };
    // `block_reward_spark` is intentionally the rate at the first rewarded
    // height. A closing epoch may span an era boundary; the exact mixed-rate
    // amount is carried by `block_rewards_distributed`.
    let reward_per_block = block_reward_at_height(if context_active {
        context.closing_start_height
    } else {
        height
    });
    let epoch_block_reward = if context_active {
        block_rewards_for_inclusive_range(context.closing_start_height, context.closing_end_height)
    } else {
        reward_per_block.saturating_mul(EPOCH_DURATION_BLOCKS)
    };

    state
        .validators
        .select_active_set(&state.delegations, total_staked, height);

    if delegator_bond_accounting_active(height) {
        reconcile_all_delegators_from_bonds(state);
    }
    let virtual_delegations = if reward_economic_snapshot_active(height) {
        // Post-gate, auto-delegation was frozen into the epoch-start economic
        // snapshot and must not be recalculated from mutable boundary state.
        Vec::new()
    } else {
        apply_auto_delegations(state, current_epoch)
    };

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
    remove_auto_delegations(state, &virtual_delegations, current_epoch, height);
    // This boundary pays the epoch that just elapsed. Activate a due
    // commission only after both reward sources and virtual auto-delegation
    // accounting have used the rate that governed that elapsed epoch.
    apply_pending_commission_changes(state, current_epoch);
    state.validators.expire_stale_rewards(current_epoch);
    release_unbonded_validators(state, current_epoch);
    release_unbonded_bonds_at_height(state, current_epoch, height)?;
    let liveness_epoch = if context_active {
        context.closing_epoch
    } else {
        current_epoch
    };
    let closing_members = closing_snapshot.as_ref().map(|snapshot| {
        snapshot
            .entries()
            .iter()
            .map(|entry| entry.validator_id)
            .collect::<Vec<_>>()
    });
    let (liveness_slashed, liveness_penalty_count) =
        apply_liveness_penalties(state, liveness_epoch, height, closing_members.as_deref());

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
    if state_commitment_v2_active(height) {
        state.rebuild_state_commitment_v2(height);
    }
    Ok(record)
}

fn reconcile_all_delegators_from_bonds(state: &mut ChainState) {
    let positions: Vec<(Bytes32, Bytes32)> = state
        .delegations
        .all_delegators()
        .flat_map(|(validator_id, entries)| {
            entries
                .iter()
                .map(|entry| (*validator_id, entry.delegator_id))
                .collect::<Vec<_>>()
        })
        .collect();
    for (validator_id, delegator_id) in positions {
        reconcile_delegator_from_bonds(state, &validator_id, &delegator_id);
    }
}

fn block_rewards_for_inclusive_range(start_height: u64, end_height: u64) -> u64 {
    (start_height..=end_height).fold(0u64, |total, height| {
        total.saturating_add(block_reward_at_height(height))
    })
}

/// Apply the deterministic enforcement-height demotion. This is idempotent so
/// replay and snapshot restoration cannot retain or recreate an unenrolled
/// Active validator after enforcement.
pub(crate) fn enforce_validator_cold_key_enrollment(state: &mut ChainState, height: u64) {
    if !validator_cold_key_enforcement_active(height) {
        return;
    }
    let changed: Vec<Bytes32> = state
        .validators
        .all_validators()
        .filter(|validator| {
            validator.status == ValidatorStatus::Active
                && validator.cold_key_status == ColdKeyStatus::Unenrolled
        })
        .map(|validator| validator.validator_id)
        .collect();
    for validator_id in &changed {
        if let Some(validator) = state.validators.get_mut(validator_id) {
            validator.status = ValidatorStatus::Registered;
        }
    }
    if let Some(mut commitment) = state.state_commitment_v2.take() {
        for validator_id in changed {
            if let Some(validator) = state.validators.get(&validator_id) {
                commitment.put_validator(validator, height);
            }
        }
        state.state_commitment_v2 = Some(commitment);
    }
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
    if !governance_proposal_pruning_active(height) {
        return;
    }
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
            let delegated = if delegator_bond_accounting_active(state.height) {
                state
                    .delegations
                    .get_delegators(&validator.validator_id)
                    .iter()
                    .fold(0u64, |sum, entry| {
                        sum.saturating_add(crate::delegation::active_delegated_bond_stake(
                            state,
                            &validator.validator_id,
                            &entry.delegator_id,
                        ))
                    })
            } else {
                state.delegations.total_delegated(&validator.validator_id)
            };
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

fn apply_auto_delegations(
    state: &mut ChainState,
    current_epoch: u64,
) -> Vec<AutoDelegationSnapshot> {
    let mut virtual_delegations: Vec<(Bytes32, Bytes32, u64)> = state
        .validators
        .all_validators()
        .filter(|v| {
            matches!(v.status, ValidatorStatus::Registered)
                && v.auto_delegate_to.is_some()
                && v.stake_spark > 0
        })
        .filter_map(|v| {
            let target_id = v.auto_delegate_to?;
            let target = state.validators.get(&target_id)?;
            if !target.is_active() {
                return None;
            }
            Some((v.validator_id, target_id, v.stake_spark))
        })
        .collect();
    virtual_delegations.sort_by_key(|(delegator_id, target_id, _)| (target_id.0, delegator_id.0));

    let mut snapshots = Vec::with_capacity(virtual_delegations.len());
    for (delegator_id, target_id, amount_spark) in &virtual_delegations {
        let (previous_staked_spark, previous_pending_rewards, had_existing_entry) = state
            .delegations
            .get_delegators(target_id)
            .iter()
            .find(|entry| entry.delegator_id == *delegator_id)
            .map(|entry| (entry.staked_spark, entry.pending_rewards, true))
            .unwrap_or((0, 0, false));
        if let Err(reason) = state.delegations.add_delegation(
            *target_id,
            *delegator_id,
            *amount_spark,
            current_epoch,
        ) {
            eprintln!(
                "[epoch] auto-delegation skipped: validator {} -> {} ({})",
                hex::encode(&delegator_id.0[..4]),
                hex::encode(&target_id.0[..4]),
                reason,
            );
            continue;
        }
        snapshots.push(AutoDelegationSnapshot {
            delegator_id: *delegator_id,
            target_id: *target_id,
            amount_spark: *amount_spark,
            previous_staked_spark,
            previous_pending_rewards,
            had_existing_entry,
        });
        eprintln!(
            "[epoch] auto-delegation: validator {} -> {} ({} Spark)",
            hex::encode(&delegator_id.0[..4]),
            hex::encode(&target_id.0[..4]),
            amount_spark,
        );
    }

    snapshots
}

fn remove_auto_delegations(
    state: &mut ChainState,
    virtual_delegations: &[AutoDelegationSnapshot],
    current_epoch: u64,
    height: u64,
) {
    for snapshot in virtual_delegations {
        let accumulated = state
            .delegations
            .get_delegator_reward(&snapshot.target_id, &snapshot.delegator_id);
        let reward_delta = accumulated.saturating_sub(snapshot.previous_pending_rewards);
        let total_staked = snapshot
            .previous_staked_spark
            .saturating_add(snapshot.amount_spark);
        let virtual_reward = if total_staked == 0 {
            0
        } else {
            proportional_reward(reward_delta, snapshot.amount_spark, total_staked, height)
        };
        if virtual_reward > 0 {
            if let Some(v) = state.validators.get_mut(&snapshot.delegator_id) {
                v.pending_rewards = v.pending_rewards.saturating_add(virtual_reward);
                v.rewards_last_epoch = current_epoch;
            }
            eprintln!(
                "[epoch] auto-delegation reward: validator {} earned {} Spark",
                hex::encode(&snapshot.delegator_id.0[..4]),
                virtual_reward,
            );
        }
        if snapshot.had_existing_entry {
            let _ = state.delegations.update_delegator(
                &snapshot.target_id,
                &snapshot.delegator_id,
                |entry| {
                    let real_reward = reward_delta.saturating_sub(virtual_reward);
                    entry.staked_spark = snapshot.previous_staked_spark;
                    entry.pending_rewards = snapshot
                        .previous_pending_rewards
                        .saturating_add(real_reward);
                    entry.rewards_last_epoch = current_epoch;
                },
            );
        } else {
            state
                .delegations
                .remove_virtual_delegation(&snapshot.target_id, &snapshot.delegator_id);
        }
    }
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

fn proportional_reward(amount: u64, numerator: u64, denominator: u64, height: u64) -> u64 {
    if overflow_fix_active(height) {
        muldiv(amount, numerator, denominator)
    } else if denominator == 0 {
        0
    } else {
        amount.saturating_mul(numerator) / denominator
    }
}

fn distribute_block_rewards(
    state: &mut ChainState,
    epoch_block_reward: u64,
    current_epoch: u64,
    height: u64,
) -> crate::error::StateResult<()> {
    if reward_economic_snapshot_active(height) {
        return distribute_snapshot_rewards(
            state,
            epoch_block_reward,
            current_epoch,
            height,
            SnapshotRewardSource::Block,
        );
    }
    // Rewards are weighted by active validator self-stake, matching consensus
    // voting weight and active-set selection. Delegations only split a
    // validator's already-earned reward pool between validator and delegators.
    let total_stake = state.validators.total_active_stake();
    if total_stake == 0 || epoch_block_reward == 0 {
        return Ok(());
    }

    let mut active: Vec<(indra_core::types::primitives::Bytes32, u64)> = state
        .validators
        .active_validators()
        .map(|v| (v.validator_id, v.stake_spark))
        .collect();
    active.sort_by_key(|(id, _)| id.0);
    let active_validator_count = active.len() as u64;
    let mut distributed = 0u64;

    for (id, stake) in &active {
        let raw_reward = proportional_reward(epoch_block_reward, *stake, total_stake, height);
        let adjusted_reward = saturation_adjusted_reward(
            raw_reward,
            *stake,
            total_stake,
            active_validator_count,
            height,
        );

        let commission_bps = state
            .validators
            .get(id)
            .map(|v| v.commission_bps)
            .unwrap_or(1_000);
        eprintln!(
            "[epoch] validator {} reward={} Spark commission={}bps",
            hex::encode(&id.0[..4]),
            adjusted_reward,
            commission_bps,
        );
        let delegated = state.delegations.total_delegated(id);

        let (validator_share, delegator_pool) = if delegated == 0 {
            (adjusted_reward, 0)
        } else {
            let commission = if overflow_fix_active(height) {
                bps_of(adjusted_reward, commission_bps)
            } else {
                adjusted_reward.saturating_mul(commission_bps as u64) / 10_000
            };
            (commission, adjusted_reward.saturating_sub(commission))
        };

        if let Some(entry) = state.validators.get_mut(id) {
            entry.pending_rewards = entry.pending_rewards.saturating_add(validator_share);
            entry.rewards_last_epoch = current_epoch;
            distributed = distributed.saturating_add(validator_share);
        }

        let remainder =
            state
                .delegations
                .distribute_rewards(id, delegator_pool, current_epoch, height);
        distributed = distributed.saturating_add(delegator_pool.saturating_sub(remainder));
    }

    // Monetary policy for block-reward dust: any deterministic remainder
    // from proportional rounding, saturation adjustment, or delegator reward
    // splitting is routed to treasury. Rewards are pre-minted, so this does
    // not increase total_supply; it only makes formerly-unallocated dust
    // explicit and auditable.
    let reward_remainder = epoch_block_reward.saturating_sub(distributed);
    state.treasury_balance = state.treasury_balance.saturating_add(reward_remainder);
    Ok(())
}

fn distribute_fee_rewards(
    state: &mut ChainState,
    current_epoch: u64,
    height: u64,
) -> crate::error::StateResult<()> {
    if reward_economic_snapshot_active(height) {
        let fee_pool = state.fee_reward_pool;
        if fee_pool == 0 {
            return Ok(());
        }
        state.fee_reward_pool = 0;
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
        return result;
    }
    let fee_pool = state.fee_reward_pool;
    if fee_pool == 0 {
        return Ok(());
    }

    // Fee rewards use the same self-stake weighting as block rewards.
    let total_stake = state.validators.total_active_stake();
    if total_stake == 0 {
        return Ok(());
    }

    state.fee_reward_pool = 0;

    let mut active: Vec<(indra_core::types::primitives::Bytes32, u64)> = state
        .validators
        .active_validators()
        .map(|v| (v.validator_id, v.stake_spark))
        .collect();
    active.sort_by_key(|(id, _)| id.0);

    let mut distributed = 0u64;

    for (id, stake) in &active {
        let reward = proportional_reward(fee_pool, *stake, total_stake, height);
        let commission_bps = state
            .validators
            .get(id)
            .map(|v| v.commission_bps)
            .unwrap_or(1_000);
        let delegated = state.delegations.total_delegated(id);

        let (validator_share, delegator_pool) = if delegated == 0 {
            (reward, 0)
        } else {
            let commission = if overflow_fix_active(height) {
                bps_of(reward, commission_bps)
            } else {
                reward.saturating_mul(commission_bps as u64) / 10_000
            };
            (commission, reward.saturating_sub(commission))
        };

        if let Some(entry) = state.validators.get_mut(id) {
            entry.pending_rewards = entry.pending_rewards.saturating_add(validator_share);
            entry.rewards_last_epoch = current_epoch;
            distributed = distributed.saturating_add(validator_share);
        }

        let remainder =
            state
                .delegations
                .distribute_rewards(id, delegator_pool, current_epoch, height);
        distributed = distributed.saturating_add(delegator_pool.saturating_sub(remainder));
    }

    let remainder = fee_pool.saturating_sub(distributed);
    state.fee_reward_pool = state.fee_reward_pool.saturating_add(remainder);
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
            let validator = state
                .validators
                .get_mut(&member.validator_id)
                .ok_or_else(|| {
                    StateError::InvalidRewardEconomicSnapshot(
                        "rewarded validator destination is missing".to_string(),
                    )
                })?;
            validator.pending_rewards = validator.pending_rewards.saturating_add(validator_pool);
            validator.rewards_last_epoch = current_epoch;
            distributed = distributed.saturating_add(validator_pool);
            continue;
        }

        let commission = bps_of(validator_pool, economic_entry.commission_bps);
        let delegator_pool = validator_pool.saturating_sub(commission);
        let validator = state
            .validators
            .get_mut(&member.validator_id)
            .ok_or_else(|| {
                StateError::InvalidRewardEconomicSnapshot(
                    "rewarded validator destination is missing".to_string(),
                )
            })?;
        validator.pending_rewards = validator.pending_rewards.saturating_add(commission);
        validator.rewards_last_epoch = current_epoch;
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
                state
                    .delegations
                    .update_delegator(&member.validator_id, &delegator.delegator_id, |entry| {
                        entry.pending_rewards = entry.pending_rewards.saturating_add(bonded_reward);
                        entry.rewards_last_epoch = current_epoch;
                    })
                    .ok_or_else(|| {
                        StateError::InvalidRewardEconomicSnapshot(
                            "frozen bonded delegator destination is missing".to_string(),
                        )
                    })?;
            }
            if auto_reward > 0 {
                let source_validator = state
                    .validators
                    .get_mut(&delegator.delegator_id)
                    .ok_or_else(|| {
                        StateError::InvalidRewardEconomicSnapshot(
                            "frozen auto-delegation validator destination is missing".to_string(),
                        )
                    })?;
                source_validator.pending_rewards =
                    source_validator.pending_rewards.saturating_add(auto_reward);
                source_validator.rewards_last_epoch = current_epoch;
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

#[cfg(test)]
fn release_unbonded_bonds(state: &mut ChainState, current_epoch: u64) -> StateResult<()> {
    release_unbonded_bonds_at_height(
        state,
        current_epoch,
        current_epoch.saturating_mul(EPOCH_DURATION_BLOCKS),
    )
}

pub(crate) fn release_unbonded_bonds_at_height(
    state: &mut ChainState,
    current_epoch: u64,
    release_height: u64,
) -> StateResult<()> {
    let precise_accounting = delegator_bond_accounting_active(release_height);
    let mut to_release: Vec<Bytes32> = state
        .staked_bonds
        .values()
        .filter(|bond| {
            let matured = bond
                .unbonding_end_epoch
                .map(|end| end <= current_epoch)
                .unwrap_or(false);
            let frozen_unenrolled_self_bond = validator_cold_key_enforcement_active(release_height)
                && bond.validator_id == bond.delegator_id
                && state
                    .validators
                    .get(&bond.validator_id)
                    .is_some_and(|validator| {
                        validator.cold_key_status == ColdKeyStatus::Unenrolled
                    });
            matured && !frozen_unenrolled_self_bond
        })
        .map(|bond| bond.utxo_id)
        .collect();
    to_release.sort_by_key(|id| id.0);

    let mut affected_delegators = Vec::new();
    for (idx, utxo_id) in to_release.into_iter().enumerate() {
        if let Some(bond) = state.staked_bonds.remove(&utxo_id) {
            if precise_accounting && bond.validator_id != bond.delegator_id {
                affected_delegators.push((bond.validator_id, bond.delegator_id));
            }
            let output_index = u32::try_from(idx).unwrap_or(u32::MAX - 1).saturating_add(1);
            let output = released_bond_output(state, &bond, release_height)?;
            let refund_utxo_id = state
                .utxos
                .insert(output, release_height, STAKING_TX_IDX, output_index)
                .map_err(|_| crate::error::StateError::InvariantViolation {
                    message: "UTXO ID collision in staking bond release",
                })?;
            if legacy_normal_bond_release_uses_fresh_blinding(&bond, release_height) {
                state.push_delegation_return_event(DelegationReturnEvent {
                    delegator_id: bond.delegator_id,
                    validator_id: bond.validator_id,
                    bond_utxo_id: bond.utxo_id,
                    amount_spark: bond.amount_spark,
                    reason: DelegationReturnReason::UnbondingMatured,
                    returned_epoch: current_epoch,
                    returned_height: release_height,
                    refund_utxo_id,
                });
            }
            remove_released_tombstone_bond_reference(state, &bond.validator_id, &bond.utxo_id)?;
        }
    }
    if precise_accounting {
        affected_delegators
            .sort_by_key(|(validator_id, delegator_id)| (validator_id.0, delegator_id.0));
        affected_delegators.dedup();
        for (validator_id, delegator_id) in affected_delegators {
            reconcile_delegator_from_bonds(state, &validator_id, &delegator_id);
        }
    }
    prune_mature_evicted_validator_tombstones(state, current_epoch);
    Ok(())
}

fn remove_released_tombstone_bond_reference(
    state: &mut ChainState,
    validator_id: &Bytes32,
    bond_utxo_id: &Bytes32,
) -> StateResult<()> {
    let Some(mut tombstone) = state
        .evicted_validator_tombstones
        .get(validator_id)
        .cloned()
    else {
        return Ok(());
    };
    let old_len = tombstone.retained_bonds.len();
    tombstone
        .retained_bonds
        .retain(|reference| reference.bond_utxo_id != *bond_utxo_id);
    if tombstone.retained_bonds.len() + 1 != old_len {
        return Err(crate::error::StateError::InvariantViolation {
            message: "released tombstone bond did not have exactly one retained reference",
        });
    }
    state
        .evicted_validator_tombstones
        .insert(*validator_id, tombstone.clone());
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_evicted_validator_tombstone(&tombstone);
    }
    Ok(())
}

fn prune_mature_evicted_validator_tombstones(state: &mut ChainState, current_epoch: u64) {
    let mut prunable: Vec<(u64, Bytes32)> = state
        .evicted_validator_tombstones
        .values()
        .filter(|tombstone| {
            tombstone.retained_bonds.is_empty()
                && current_epoch
                    > tombstone
                        .eviction_epoch
                        .saturating_add(SLASH_EVIDENCE_WINDOW_EPOCHS)
        })
        .map(|tombstone| (tombstone.eviction_height, tombstone.validator_id))
        .collect();
    prunable.sort_by_key(|(height, validator_id)| (*height, validator_id.0));
    for (_, validator_id) in prunable {
        state.evicted_validator_tombstones.remove(&validator_id);
        if let Some(commitment) = state.state_commitment_v2.as_mut() {
            commitment.delete_evicted_validator_tombstone(&validator_id);
        }
    }
}

pub(crate) fn released_bond_output(
    state: &ChainState,
    bond: &crate::validator::StakeBondEntry,
    release_height: u64,
) -> StateResult<indra_core::types::transaction::OutputV1> {
    if bond.original_output.range_proof.is_none() {
        return regenerated_bond_output(
            bond,
            state,
            release_height,
            derive_compact_stake_bond_release_blinding(bond, release_height),
            "compact stake-bond release",
        );
    }

    if bond.delegator_id != bond.validator_id
        || bond.amount_spark >= bond.original_output.value_spark
    {
        if legacy_normal_bond_release_uses_fresh_blinding(bond, release_height) {
            return regenerated_bond_output(
                bond,
                state,
                release_height,
                derive_normal_stake_bond_release_blinding(
                    bond.validator_id,
                    bond.delegator_id,
                    bond.utxo_id,
                    release_height,
                    bond.amount_spark,
                ),
                "normal stake-bond release",
            );
        }

        return bond.original_output.to_legacy_output().ok_or_else(|| {
            crate::error::StateError::InvariantViolation {
                message: "legacy stake bond release missing stored range proof",
            }
        });
    }

    let mut blinding_input =
        Vec::with_capacity(SLASH_BOND_RELEASE_BLINDING_DOMAIN.len() + 32 + 32 + 8);
    blinding_input.extend_from_slice(SLASH_BOND_RELEASE_BLINDING_DOMAIN);
    blinding_input.extend_from_slice(&bond.validator_id.0);
    blinding_input.extend_from_slice(&bond.utxo_id.0);
    blinding_input.extend_from_slice(&release_height.to_le_bytes());
    let blinding = indra_crypto::sha256(&blinding_input);
    regenerated_bond_output(
        bond,
        state,
        release_height,
        blinding,
        "slashed self-stake release",
    )
}

fn legacy_normal_bond_release_uses_fresh_blinding(
    bond: &crate::validator::StakeBondEntry,
    release_height: u64,
) -> bool {
    bond.original_output.range_proof.is_some()
        && (bond.delegator_id != bond.validator_id
            || bond.amount_spark >= bond.original_output.value_spark)
        && normal_bond_release_blinding_active(release_height)
}

/// Deterministic blinding for a compact stake-bond release.
///
/// External wallets can reproduce this as:
/// `sha256(domain || validator_id || delegator_id || bond_utxo_id ||
/// release_height_le || released_amount_spark_le)`.
pub fn derive_compact_stake_bond_release_blinding(
    bond: &crate::validator::StakeBondEntry,
    release_height: u64,
) -> [u8; 32] {
    let mut blinding_input =
        Vec::with_capacity(COMPACT_STAKE_BOND_RELEASE_BLINDING_DOMAIN.len() + 32 + 32 + 32 + 8 + 8);
    blinding_input.extend_from_slice(COMPACT_STAKE_BOND_RELEASE_BLINDING_DOMAIN);
    blinding_input.extend_from_slice(&bond.validator_id.0);
    blinding_input.extend_from_slice(&bond.delegator_id.0);
    blinding_input.extend_from_slice(&bond.utxo_id.0);
    blinding_input.extend_from_slice(&release_height.to_le_bytes());
    blinding_input.extend_from_slice(&bond.amount_spark.to_le_bytes());
    indra_crypto::sha256(&blinding_input)
}

/// Deterministic blinding for a normal stake-bond release.
///
/// External wallets can reproduce this as:
/// `sha256(domain || validator_id || delegator_id || bond_utxo_id ||
/// release_height_le || released_amount_spark_le)`.
pub fn derive_normal_stake_bond_release_blinding(
    validator_id: Bytes32,
    delegator_id: Bytes32,
    bond_utxo_id: Bytes32,
    release_height: u64,
    released_amount_spark: u64,
) -> [u8; 32] {
    let mut blinding_input =
        Vec::with_capacity(NORMAL_STAKE_BOND_RELEASE_BLINDING_DOMAIN.len() + 32 + 32 + 32 + 8 + 8);
    blinding_input.extend_from_slice(NORMAL_STAKE_BOND_RELEASE_BLINDING_DOMAIN);
    blinding_input.extend_from_slice(&validator_id.0);
    blinding_input.extend_from_slice(&delegator_id.0);
    blinding_input.extend_from_slice(&bond_utxo_id.0);
    blinding_input.extend_from_slice(&release_height.to_le_bytes());
    blinding_input.extend_from_slice(&released_amount_spark.to_le_bytes());
    indra_crypto::sha256(&blinding_input)
}

fn regenerated_bond_output(
    bond: &crate::validator::StakeBondEntry,
    state: &ChainState,
    _release_height: u64,
    blinding: [u8; 32],
    context: &str,
) -> StateResult<indra_core::types::transaction::OutputV1> {
    let owner_pubkey = resolve_bond_owner_pubkey(bond, state).map_err(|_| {
        crate::error::StateError::InvariantViolation {
            message: "stake bond release owner pubkey is unresolvable",
        }
    })?;
    let commitment = indra_crypto::commit(bond.amount_spark, &blinding);
    let mut rng = rand::rngs::StdRng::from_seed(blinding);
    let proof =
        indra_crypto::prove_range(bond.amount_spark, &blinding, &mut rng).map_err(|_| {
            crate::error::StateError::InvalidStakingOp(format!(
                "failed to generate range proof for {context}"
            ))
        })?;

    let mut output = bond.original_output.to_legacy_output().unwrap_or_else(|| {
        indra_core::types::transaction::OutputV1 {
            value_spark: bond.original_output.value_spark,
            commitment: bond.original_output.commitment,
            owner_pubkey: owner_pubkey.clone(),
            range_proof: VariableBytes::default(),
            lock_height: bond.original_output.lock_height,
        }
    });
    output.value_spark = bond.amount_spark;
    output.commitment = CommitmentV1 {
        compressed_point: Bytes32::from(commitment.0),
    };
    output.owner_pubkey = owner_pubkey;
    output.range_proof = VariableBytes::from_slice(&proof)
        .map_err(|_| crate::error::StateError::InvalidStakingOp("range proof too large".into()))?;
    Ok(output)
}

fn apply_liveness_penalties(
    state: &mut ChainState,
    current_epoch: u64,
    height: u64,
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
            let penalty = if overflow_fix_active(height) {
                bps_of(stake, slash_bps)
            } else {
                stake.saturating_mul(slash_bps as u64) / 10_000
            };
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

fn reward_economic_snapshot_active_at_gate(height: u64, gate_height: u64) -> bool {
    height >= gate_height
}

fn reward_economic_snapshot_active(height: u64) -> bool {
    reward_economic_snapshot_active_at_gate(
        height,
        indra_core::types::primitives::hard_forks::CONSENSUS_SNAPSHOT_HEIGHT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compute_state_root,
        governance::{GovernanceRedelegation, ProposalRecord, VoteCommit, VoteReveal},
        validator::{StakeBondEntry, ValidatorEntry, ValidatorStatus},
    };
    use indra_core::{
        codec::Encode,
        types::{
            crypto::HybridPubKey,
            governance::GovernableAction,
            primitives::{
                compact_bond_pubkey_omission_active, compact_stake_bond_active,
                delegator_identity_registry_active,
                hard_forks::{
                    GOVERNANCE_PROPOSAL_PRUNING_HEIGHT, NORMAL_BOND_RELEASE_BLINDING_HEIGHT,
                },
                Bytes32, VariableBytes, COMMISSION_CHANGE_DELAY_EPOCHS, DEFAULT_COMMISSION_BPS,
                DUST_LIMIT_SPARK, ERA_1_2_DURATION_BLOCKS, ERA_1_BLOCK_REWARD_SPARK,
                ERA_2_BLOCK_REWARD_SPARK, ERA_3_BLOCK_REWARD_SPARK, ERA_3_PLUS_DURATION_BLOCKS,
                MAX_DELEGATION_RETURN_EVENTS, MINIMUM_ACTIVE_SELF_STAKE_SPARK, SLASH_LIVENESS_BPS,
                SLASH_LIVENESS_THRESHOLD_EPOCHS, SPARK_PER_INDRA,
            },
            transaction::OutputV1,
        },
        CommitmentV1,
    };

    fn make_validator(id_byte: u8, stake: u64) -> ValidatorEntry {
        ValidatorEntry {
            validator_id: Bytes32::from([id_byte; 32]),
            name: format!("validator-{id_byte}"),
            hybrid_classical_pk: None,
            hybrid_pq_pk: None,
            vrf_pk: None,
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
            cold_hybrid_classical_pk: None,
            cold_hybrid_pq_pk: None,
            cold_key_version: 0,
            cold_key_status: crate::validator::ColdKeyStatus::Unenrolled,
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

    fn install_reward_basis(state: &mut ChainState) {
        let consensus = state
            .build_consensus_snapshot(u64::MAX, u64::MAX - 1)
            .unwrap();
        let economic = state.build_reward_economic_snapshot(&consensus).unwrap();
        state.consensus_snapshots = vec![consensus];
        state.reward_economic_snapshot = Some(economic);
    }

    fn dummy_output(byte: u8) -> OutputV1 {
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

    fn manual_compact_release_blinding(bond: &StakeBondEntry, release_height: u64) -> [u8; 32] {
        let mut input = Vec::new();
        input.extend_from_slice(COMPACT_STAKE_BOND_RELEASE_BLINDING_DOMAIN);
        input.extend_from_slice(&bond.validator_id.0);
        input.extend_from_slice(&bond.delegator_id.0);
        input.extend_from_slice(&bond.utxo_id.0);
        input.extend_from_slice(&release_height.to_le_bytes());
        input.extend_from_slice(&bond.amount_spark.to_le_bytes());
        indra_crypto::sha256(&input)
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
    fn reward_snapshot_pays_frozen_alice_bob_not_boundary_time_bob_carol() {
        let target_id = Bytes32::from([1; 32]);
        let alice = Bytes32::from([0xA1; 32]);
        let bob = Bytes32::from([0xB1; 32]);
        let carol = Bytes32::from([0xC1; 32]);
        let mut state = ChainState::new_genesis();
        state
            .validators
            .upsert(make_snapshot_validator(1, 1_000_000_000))
            .unwrap();
        state
            .delegations
            .add_delegation(target_id, alice, 60, 0)
            .unwrap();
        state
            .delegations
            .add_delegation(target_id, bob, 40, 0)
            .unwrap();
        let alice_bond = compact_bond(0x31, target_id, alice, 60);
        let bob_bond = compact_bond(0x32, target_id, bob, 40);
        state.staked_bonds.insert(alice_bond.utxo_id, alice_bond);
        state.staked_bonds.insert(bob_bond.utxo_id, bob_bond);
        install_reward_basis(&mut state);

        // Boundary-time live state now says Bob=40 and Carol=100. The frozen
        // epoch-start basis must remain Alice=60 and Bob=40.
        state
            .delegations
            .update_delegator(&target_id, &alice, |entry| {
                entry.staked_spark = 0;
                entry.unbonding_end_epoch = Some(1008);
            })
            .unwrap();
        state
            .delegations
            .add_delegation(target_id, carol, 100, 1)
            .unwrap();
        let carol_bond = compact_bond(0x33, target_id, carol, 100);
        state.staked_bonds.insert(carol_bond.utxo_id, carol_bond);

        distribute_block_rewards(&mut state, 1_000, 1, u64::MAX).unwrap();
        assert_eq!(
            state.delegations.get_delegator_reward(&target_id, &alice),
            540
        );
        assert_eq!(
            state.delegations.get_delegator_reward(&target_id, &bob),
            360
        );
        assert_eq!(
            state.delegations.get_delegator_reward(&target_id, &carol),
            0
        );
        assert_eq!(
            state.validators.get(&target_id).unwrap().pending_rewards,
            100
        );

        state.fee_reward_pool = 1_000;
        distribute_fee_rewards(&mut state, 1, u64::MAX).unwrap();
        assert_eq!(
            state.delegations.get_delegator_reward(&target_id, &alice),
            1_080
        );
        assert_eq!(
            state.delegations.get_delegator_reward(&target_id, &bob),
            720
        );
        assert_eq!(
            state.delegations.get_delegator_reward(&target_id, &carol),
            0
        );
        assert_eq!(
            state.validators.get(&target_id).unwrap().pending_rewards,
            200
        );
    }

    #[test]
    fn reward_snapshot_freezes_and_separates_auto_delegation_destination() {
        let target_id = Bytes32::from([1; 32]);
        let source_id = Bytes32::from([2; 32]);
        let mut state = ChainState::new_genesis();
        state
            .validators
            .upsert(make_snapshot_validator(1, 1_000_000_000))
            .unwrap();
        let mut source = make_snapshot_validator(2, 40);
        source.status = ValidatorStatus::Registered;
        source.auto_delegate_to = Some(target_id);
        state.validators.upsert(source).unwrap();
        state
            .delegations
            .add_delegation(target_id, source_id, 60, 0)
            .unwrap();
        let real_bond = compact_bond(0x34, target_id, source_id, 60);
        state.staked_bonds.insert(real_bond.utxo_id, real_bond);
        install_reward_basis(&mut state);

        let frozen = state
            .reward_economic_snapshot
            .as_ref()
            .unwrap()
            .validator(&target_id)
            .unwrap()
            .delegators()[0]
            .clone();
        assert_eq!(frozen.bonded_active_principal_spark, 60);
        assert_eq!(frozen.auto_delegated_principal_spark, 40);

        // A mutable payout-time setting/stake change cannot alter frozen auto principal.
        let source = state.validators.get_mut(&source_id).unwrap();
        source.stake_spark = 400;
        source.auto_delegate_to = None;
        distribute_block_rewards(&mut state, 1_000, 1, u64::MAX).unwrap();
        assert_eq!(
            state
                .delegations
                .get_delegator_reward(&target_id, &source_id),
            540
        );
        assert_eq!(
            state.validators.get(&source_id).unwrap().pending_rewards,
            360
        );
        assert_eq!(
            state.validators.get(&target_id).unwrap().pending_rewards,
            100
        );
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
    fn first_snapshot_gate_boundary_is_legacy_then_next_boundary_is_frozen() {
        let synthetic_gate = 301u64;
        assert!(!reward_economic_snapshot_active_at_gate(
            300,
            synthetic_gate
        ));
        assert!(reward_economic_snapshot_active_at_gate(600, synthetic_gate));
    }

    #[test]
    fn post_gate_epoch_record_uses_inclusive_produced_block_range() {
        let context = EpochTransitionContext::new(300, 299).unwrap();
        let mut state = ChainState::new_genesis();
        let record =
            apply_epoch_transition_at_gate(&mut state, &context, 0, 300, u64::MAX).unwrap();
        assert_eq!(record.epoch, 0);
        assert_eq!(record.start_height, 1);
        assert_eq!(record.end_height, 300);
    }

    #[test]
    fn post_snapshot_gate_epoch_record_uses_frozen_closing_authority() {
        let context = EpochTransitionContext::new(600, 599).unwrap();
        let mut state = ChainState::new_genesis();
        let first = make_snapshot_validator(0xA1, MINIMUM_ACTIVE_SELF_STAKE_SPARK * 2);
        let first_id = first.validator_id;
        let second = make_snapshot_validator(0xA2, MINIMUM_ACTIVE_SELF_STAKE_SPARK * 3);
        state.validators.upsert(first).unwrap();
        state.validators.upsert(second).unwrap();
        state.consensus_snapshots = vec![state.build_consensus_snapshot(301, 300).unwrap()];

        let first_live = state.validators.get_mut(&first_id).unwrap();
        first_live.status = ValidatorStatus::Registered;
        first_live.stake_spark = MINIMUM_ACTIVE_SELF_STAKE_SPARK * 9;
        state
            .validators
            .upsert(make_snapshot_validator(
                0xA3,
                MINIMUM_ACTIVE_SELF_STAKE_SPARK * 7,
            ))
            .unwrap();

        let replay_initial = state.clone();
        let record = apply_epoch_transition_at_gate(&mut state, &context, 0, 600, 301).unwrap();
        assert_eq!(record.active_validators, 2);
        assert_eq!(
            record.total_staked_spark,
            MINIMUM_ACTIVE_SELF_STAKE_SPARK * 5
        );
        let mut replay = replay_initial;
        let replay_record =
            apply_epoch_transition_at_gate(&mut replay, &context, 0, 600, 301).unwrap();
        assert_eq!(replay_record, record);
        assert_eq!(replay.encode_to_vec(), state.encode_to_vec());
        assert_eq!(compute_state_root(&replay), compute_state_root(&state));
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
            crate::validator::EvictedValidatorTombstoneV1 {
                validator_id: tombstoned_id,
                eviction_height: 300,
                eviction_epoch: 1,
                last_classical_vote_pk: [1; 32],
                last_pq_vote_pk: [2; indra_crypto::PQ_PK_BYTES],
                last_vrf_pk: [3; 32],
                cold_custody: None,
                retained_bonds: Vec::new(),
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
    fn pre_gate_epoch_record_remains_legacy_byte_semantics() {
        let context = EpochTransitionContext::new(300, 299).unwrap();
        let mut state = ChainState::new_genesis();
        let record =
            apply_epoch_transition_at_gate(&mut state, &context, 0, 301, u64::MAX).unwrap();
        assert_eq!(record.epoch, 0);
        assert_eq!(record.start_height, 0);
        assert_eq!(record.end_height, 299);
        assert_eq!(record.block_reward_spark, block_reward_at_height(300));
        assert_eq!(record.active_validators, 0);
        assert_eq!(record.total_staked_spark, 0);
    }

    #[test]
    fn credited_closing_epoch_activity_prevents_same_boundary_liveness_penalty() {
        let context = EpochTransitionContext::new(300, 299).unwrap();
        let mut state = ChainState::new_genesis();
        state.governance.params.slash_liveness_threshold_epochs = 1;
        let mut validator = make_validator(0x92, MINIMUM_ACTIVE_SELF_STAKE_SPARK * 2);
        validator.last_active_epoch = context.closing_epoch;
        validator.cold_key_status = crate::validator::ColdKeyStatus::Active;
        let validator_id = validator.validator_id;
        let original_stake = validator.stake_spark;
        state.validators.upsert(validator).unwrap();

        let record =
            apply_epoch_transition_at_gate(&mut state, &context, 0, 300, u64::MAX).unwrap();
        assert_eq!(record.liveness_penalty_count, 0);
        assert_eq!(
            state.validators.get(&validator_id).unwrap().stake_spark,
            original_stake
        );
    }

    #[test]
    fn independent_replays_across_context_gate_are_byte_identical() {
        fn replay(mut state: ChainState) -> ChainState {
            let legacy = EpochTransitionContext::new(300, 299).unwrap();
            state.height = 300;
            apply_epoch_transition_at_gate(&mut state, &legacy, 0, 600, u64::MAX).unwrap();

            let upgraded = EpochTransitionContext::new(600, 599).unwrap();
            state.height = 600;
            apply_epoch_transition_at_gate(&mut state, &upgraded, 0, 600, u64::MAX).unwrap();
            state
        }

        let first = replay(ChainState::new_genesis());
        let second = replay(ChainState::new_genesis());
        assert_eq!(first.encode_to_vec(), second.encode_to_vec());
        assert_eq!(compute_state_root(&first), compute_state_root(&second));
    }

    #[test]
    fn mixed_rate_epoch_sums_each_governed_height_exactly() {
        let boundary = ERA_1_2_DURATION_BLOCKS;
        let start = boundary - EPOCH_DURATION_BLOCKS + 1;
        let expected = ERA_1_BLOCK_REWARD_SPARK
            .saturating_mul(EPOCH_DURATION_BLOCKS - 1)
            .saturating_add(ERA_2_BLOCK_REWARD_SPARK);
        assert_eq!(block_rewards_for_inclusive_range(start, boundary), expected);
        assert_eq!(block_reward_at_height(start), ERA_1_BLOCK_REWARD_SPARK);
        assert_eq!(block_reward_at_height(boundary), ERA_2_BLOCK_REWARD_SPARK);

        let context = EpochTransitionContext::new(boundary, boundary - 1).unwrap();
        let mut state = ChainState::new_genesis();
        let mut validator = make_validator(0x91, MINIMUM_ACTIVE_SELF_STAKE_SPARK * 2);
        validator.cold_key_status = crate::validator::ColdKeyStatus::Active;
        validator.last_active_epoch = context.closing_epoch;
        state.validators.upsert(validator).unwrap();
        let record =
            apply_epoch_transition_at_gate(&mut state, &context, 0, boundary, u64::MAX).unwrap();
        assert_eq!(record.block_reward_spark, ERA_1_BLOCK_REWARD_SPARK);
        assert_eq!(record.block_rewards_distributed, expected);
    }

    fn manual_normal_release_blinding(
        domain: &[u8],
        validator_id: Bytes32,
        delegator_id: Bytes32,
        bond_utxo_id: Bytes32,
        release_height: u64,
        released_amount_spark: u64,
    ) -> [u8; 32] {
        let mut input = Vec::new();
        input.extend_from_slice(domain);
        input.extend_from_slice(&validator_id.0);
        input.extend_from_slice(&delegator_id.0);
        input.extend_from_slice(&bond_utxo_id.0);
        input.extend_from_slice(&release_height.to_le_bytes());
        input.extend_from_slice(&released_amount_spark.to_le_bytes());
        indra_crypto::sha256(&input)
    }

    fn compact_bond(
        byte: u8,
        validator_id: Bytes32,
        delegator_id: Bytes32,
        amount_spark: u64,
    ) -> StakeBondEntry {
        StakeBondEntry::new_for_test_with_compact_activation(
            Bytes32::from([byte; 32]),
            validator_id,
            delegator_id,
            amount_spark,
            2,
            dummy_output(byte),
            10,
            10,
        )
    }

    fn fully_compact_bond(
        byte: u8,
        validator_id: Bytes32,
        delegator_id: Bytes32,
        amount_spark: u64,
    ) -> (StakeBondEntry, HybridPubKey) {
        let output = dummy_output(byte);
        let owner_pubkey = output.owner_pubkey.clone();
        let bond = StakeBondEntry::new_for_test_with_compact_and_pubkey_activation(
            Bytes32::from([byte; 32]),
            validator_id,
            delegator_id,
            amount_spark,
            2,
            output,
            20,
            10,
            20,
        );
        (bond, owner_pubkey)
    }

    fn legacy_bond(
        byte: u8,
        validator_id: Bytes32,
        delegator_id: Bytes32,
        amount_spark: u64,
    ) -> StakeBondEntry {
        StakeBondEntry::new_for_test_with_compact_activation(
            Bytes32::from([byte; 32]),
            validator_id,
            delegator_id,
            amount_spark,
            2,
            dummy_output(byte),
            9,
            10,
        )
    }

    #[test]
    fn enforcement_freezes_unenrolled_self_bond_release_and_pending_rewards() {
        let enforcement =
            indra_core::types::primitives::hard_forks::VALIDATOR_COLD_KEY_ENFORCEMENT_HEIGHT;
        let validator_id = Bytes32::from([0x0E; 32]);
        let mut validator = make_validator(0x0E, 1_000_000);
        validator.pending_rewards = 75_000;
        let mut bond = legacy_bond(0x0F, validator_id, validator_id, 1_000_000);
        bond.unbonding_end_epoch = Some(1);
        let bond_id = bond.utxo_id;
        let mut state = ChainState::new_genesis();
        state.validators.upsert(validator).unwrap();
        state.staked_bonds.insert(bond_id, bond);

        enforce_validator_cold_key_enrollment(&mut state, enforcement);
        release_unbonded_bonds_at_height(&mut state, 1, enforcement).unwrap();

        assert!(state.staked_bonds.contains_key(&bond_id));
        assert!(state.utxos.is_empty());
        let validator = state.validators.get(&validator_id).unwrap();
        assert_eq!(validator.status, ValidatorStatus::Registered);
        assert_eq!(validator.pending_rewards, 75_000);
        assert_eq!(validator.stake_spark, 1_000_000);
    }

    #[test]
    fn normal_release_blinding_matches_manual_kdf_oracle() {
        let validator_id = Bytes32::from([0x11; 32]);
        let delegator_id = Bytes32::from([0x22; 32]);
        let bond_utxo_id = Bytes32::from([0x33; 32]);
        let release_height = 123_456;
        let released_amount_spark = 9_876_543;

        let expected = manual_normal_release_blinding(
            NORMAL_STAKE_BOND_RELEASE_BLINDING_DOMAIN,
            validator_id,
            delegator_id,
            bond_utxo_id,
            release_height,
            released_amount_spark,
        );

        assert_eq!(
            derive_normal_stake_bond_release_blinding(
                validator_id,
                delegator_id,
                bond_utxo_id,
                release_height,
                released_amount_spark,
            ),
            expected
        );
    }

    #[test]
    fn normal_release_blinding_is_domain_separated() {
        let validator_id = Bytes32::from([0x41; 32]);
        let delegator_id = Bytes32::from([0x42; 32]);
        let bond_utxo_id = Bytes32::from([0x43; 32]);
        let release_height = 42;
        let released_amount_spark = 500_000;

        let normal = derive_normal_stake_bond_release_blinding(
            validator_id,
            delegator_id,
            bond_utxo_id,
            release_height,
            released_amount_spark,
        );
        let compact_domain = manual_normal_release_blinding(
            COMPACT_STAKE_BOND_RELEASE_BLINDING_DOMAIN,
            validator_id,
            delegator_id,
            bond_utxo_id,
            release_height,
            released_amount_spark,
        );
        let slash_domain = manual_normal_release_blinding(
            SLASH_BOND_RELEASE_BLINDING_DOMAIN,
            validator_id,
            delegator_id,
            bond_utxo_id,
            release_height,
            released_amount_spark,
        );

        assert_ne!(normal, compact_domain);
        assert_ne!(normal, slash_domain);
    }

    #[test]
    fn normal_release_blinding_is_sensitive_to_every_input() {
        let validator_id = Bytes32::from([0x51; 32]);
        let delegator_id = Bytes32::from([0x52; 32]);
        let bond_utxo_id = Bytes32::from([0x53; 32]);
        let release_height = 77;
        let released_amount_spark = 123_000;
        let base = derive_normal_stake_bond_release_blinding(
            validator_id,
            delegator_id,
            bond_utxo_id,
            release_height,
            released_amount_spark,
        );

        assert_ne!(
            base,
            derive_normal_stake_bond_release_blinding(
                Bytes32::from([0x61; 32]),
                delegator_id,
                bond_utxo_id,
                release_height,
                released_amount_spark,
            )
        );
        assert_ne!(
            base,
            derive_normal_stake_bond_release_blinding(
                validator_id,
                Bytes32::from([0x62; 32]),
                bond_utxo_id,
                release_height,
                released_amount_spark,
            )
        );
        assert_ne!(
            base,
            derive_normal_stake_bond_release_blinding(
                validator_id,
                delegator_id,
                Bytes32::from([0x63; 32]),
                release_height,
                released_amount_spark,
            )
        );
        assert_ne!(
            base,
            derive_normal_stake_bond_release_blinding(
                validator_id,
                delegator_id,
                bond_utxo_id,
                release_height + 1,
                released_amount_spark,
            )
        );
        assert_ne!(
            base,
            derive_normal_stake_bond_release_blinding(
                validator_id,
                delegator_id,
                bond_utxo_id,
                release_height,
                released_amount_spark + 1,
            )
        );
    }

    #[test]
    fn normal_release_blinding_is_deterministic() {
        let validator_id = Bytes32::from([0x71; 32]);
        let delegator_id = Bytes32::from([0x72; 32]);
        let bond_utxo_id = Bytes32::from([0x73; 32]);
        let release_height = 987_654;
        let released_amount_spark = 321_000;

        let first = derive_normal_stake_bond_release_blinding(
            validator_id,
            delegator_id,
            bond_utxo_id,
            release_height,
            released_amount_spark,
        );
        for _ in 0..8 {
            assert_eq!(
                derive_normal_stake_bond_release_blinding(
                    validator_id,
                    delegator_id,
                    bond_utxo_id,
                    release_height,
                    released_amount_spark,
                ),
                first
            );
        }
    }

    #[test]
    fn legacy_normal_release_before_normal_blinding_gate_is_byte_identical() {
        let validator_id = Bytes32::from([0x81; 32]);
        let delegator_id = Bytes32::from([0x82; 32]);
        let bond = legacy_bond(0x83, validator_id, delegator_id, 1_000_000);
        assert!(bond.original_output.range_proof.is_some());
        let expected = bond.original_output.to_legacy_output().unwrap();
        let state = ChainState::new_genesis();

        let output =
            released_bond_output(&state, &bond, NORMAL_BOND_RELEASE_BLINDING_HEIGHT - 1).unwrap();

        assert_eq!(output.encode_to_vec(), expected.encode_to_vec());
    }

    #[test]
    fn legacy_normal_release_at_normal_blinding_gate_uses_new_derivation() {
        let validator_id = Bytes32::from([0x84; 32]);
        let delegator_id = Bytes32::from([0x85; 32]);
        let bond = legacy_bond(0x86, validator_id, delegator_id, 1_000_000);
        let release_height = NORMAL_BOND_RELEASE_BLINDING_HEIGHT;
        let state = ChainState::new_genesis();

        let output = released_bond_output(&state, &bond, release_height).unwrap();
        let blinding = manual_normal_release_blinding(
            NORMAL_STAKE_BOND_RELEASE_BLINDING_DOMAIN,
            bond.validator_id,
            bond.delegator_id,
            bond.utxo_id,
            release_height,
            bond.amount_spark,
        );

        assert_eq!(
            blinding,
            derive_normal_stake_bond_release_blinding(
                bond.validator_id,
                bond.delegator_id,
                bond.utxo_id,
                release_height,
                bond.amount_spark,
            )
        );
        assert_ne!(
            output.encode_to_vec(),
            bond.original_output
                .to_legacy_output()
                .unwrap()
                .encode_to_vec()
        );
        assert_eq!(output.value_spark, bond.amount_spark);
        assert_eq!(
            Some(output.owner_pubkey.clone()),
            bond.original_output.owner_pubkey
        );
        assert_eq!(output.lock_height, bond.original_output.lock_height);
    }

    #[test]
    fn legacy_normal_release_at_normal_blinding_gate_opens_with_new_blinding() {
        let validator_id = Bytes32::from([0x87; 32]);
        let delegator_id = Bytes32::from([0x88; 32]);
        let bond = legacy_bond(0x89, validator_id, delegator_id, 1_000_000);
        let release_height = NORMAL_BOND_RELEASE_BLINDING_HEIGHT;
        let blinding = derive_normal_stake_bond_release_blinding(
            bond.validator_id,
            bond.delegator_id,
            bond.utxo_id,
            release_height,
            bond.amount_spark,
        );
        let state = ChainState::new_genesis();

        let output = released_bond_output(&state, &bond, release_height).unwrap();

        assert!(indra_crypto::verify_opening(
            &indra_crypto::PedersenCommitment(output.commitment.compressed_point.0),
            &indra_crypto::PedersenOpening {
                value: bond.amount_spark,
                blinding,
            },
        )
        .is_ok());
        assert!(indra_crypto::verify_range(
            &output.commitment.compressed_point.0,
            output.range_proof.as_slice(),
        )
        .is_ok());
    }

    #[test]
    fn normal_blinding_gate_does_not_change_compact_release_derivations() {
        let validator_id = Bytes32::from([0x8A; 32]);
        let delegator_id = Bytes32::from([0x8B; 32]);
        let release_height = NORMAL_BOND_RELEASE_BLINDING_HEIGHT;
        let compact = compact_bond(0x8C, validator_id, delegator_id, 1_000_000);
        let (fully_compact, owner_pubkey) =
            fully_compact_bond(0x8D, validator_id, delegator_id, 750_000);
        let mut state = ChainState::new_genesis();
        state
            .delegator_identities
            .insert(delegator_id, owner_pubkey);

        for bond in [&compact, &fully_compact] {
            let output = released_bond_output(&state, bond, release_height).unwrap();
            let compact_blinding = derive_compact_stake_bond_release_blinding(bond, release_height);
            let normal_blinding = derive_normal_stake_bond_release_blinding(
                bond.validator_id,
                bond.delegator_id,
                bond.utxo_id,
                release_height,
                bond.amount_spark,
            );

            assert!(indra_crypto::verify_opening(
                &indra_crypto::PedersenCommitment(output.commitment.compressed_point.0),
                &indra_crypto::PedersenOpening {
                    value: bond.amount_spark,
                    blinding: compact_blinding,
                },
            )
            .is_ok());
            assert_ne!(
                output.commitment.compressed_point.0,
                indra_crypto::commit(bond.amount_spark, &normal_blinding).0
            );
        }
    }

    #[test]
    fn normal_blinding_gate_boundary_release_replay_is_deterministic() {
        fn replay() -> ChainState {
            let validator_id = Bytes32::from([0x91; 32]);
            let delegator_id = Bytes32::from([0x92; 32]);
            let mut state = ChainState::new_genesis();
            let pre_gate = legacy_bond(0x93, validator_id, delegator_id, 1_000_000);
            let post_gate = legacy_bond(0x94, validator_id, delegator_id, 1_000_000);

            let old_output =
                released_bond_output(&state, &pre_gate, NORMAL_BOND_RELEASE_BLINDING_HEIGHT - 1)
                    .unwrap();
            state
                .utxos
                .insert(
                    old_output,
                    NORMAL_BOND_RELEASE_BLINDING_HEIGHT - 1,
                    STAKING_TX_IDX,
                    1,
                )
                .unwrap();
            let new_output =
                released_bond_output(&state, &post_gate, NORMAL_BOND_RELEASE_BLINDING_HEIGHT)
                    .unwrap();
            state
                .utxos
                .insert(
                    new_output,
                    NORMAL_BOND_RELEASE_BLINDING_HEIGHT,
                    STAKING_TX_IDX,
                    2,
                )
                .unwrap();
            state.height = NORMAL_BOND_RELEASE_BLINDING_HEIGHT;
            state
        }

        let a = replay();
        let b = replay();
        assert_eq!(a.encode_to_vec(), b.encode_to_vec());
        assert_eq!(compute_state_root(&a), compute_state_root(&b));
    }

    #[test]
    fn normal_release_capstone_lifecycle_crosses_test_configured_gate() {
        let activation_height = NORMAL_BOND_RELEASE_BLINDING_HEIGHT;
        let pre_epoch = activation_height / EPOCH_DURATION_BLOCKS;
        let post_epoch = pre_epoch + 1;
        let pre_height = pre_epoch * EPOCH_DURATION_BLOCKS;
        let post_height = post_epoch * EPOCH_DURATION_BLOCKS;
        assert!(pre_height < activation_height);
        assert!(post_height >= activation_height);
        assert!(compact_stake_bond_active(post_height));
        assert!(compact_bond_pubkey_omission_active(post_height));
        assert!(delegator_identity_registry_active(post_height));

        let validator_id = Bytes32::from([0xB0; 32]);
        let delegator_id = Bytes32::from([0xB1; 32]);
        let mut pre_gate_bond = legacy_bond(0xB2, validator_id, delegator_id, 1_000_000);
        let mut post_gate_bond = legacy_bond(0xB3, validator_id, delegator_id, 1_000_000);
        pre_gate_bond.unbonding_end_epoch = Some(pre_epoch);
        post_gate_bond.unbonding_end_epoch = Some(post_epoch);
        let pre_gate_original_output = pre_gate_bond.original_output.to_legacy_output().unwrap();
        let post_gate_original_output = post_gate_bond.original_output.to_legacy_output().unwrap();
        let post_gate_bond_utxo_id = post_gate_bond.utxo_id;
        let post_gate_amount = post_gate_bond.amount_spark;
        let mut state = ChainState::new_genesis();
        state
            .staked_bonds
            .insert(pre_gate_bond.utxo_id, pre_gate_bond.clone());
        state
            .staked_bonds
            .insert(post_gate_bond.utxo_id, post_gate_bond.clone());

        let pre_context =
            EpochTransitionContext::new(pre_height, pre_height.saturating_sub(1)).unwrap();
        apply_epoch_transition_at_height(&mut state, &pre_context, 1).unwrap();
        let pre_release_utxo_id = crate::utxo::UtxoSet::compute_utxo_id(
            &pre_gate_original_output,
            pre_height,
            STAKING_TX_IDX,
            1,
        );
        let pre_release = state.utxos.get(&pre_release_utxo_id).unwrap();
        assert_eq!(
            pre_release.output.encode_to_vec(),
            pre_gate_original_output.encode_to_vec()
        );
        assert!(state.delegation_return_events.is_empty());

        let post_context =
            EpochTransitionContext::new(post_height, post_height.saturating_sub(1)).unwrap();
        apply_epoch_transition_at_height(&mut state, &post_context, 2).unwrap();
        assert_eq!(state.delegation_return_events.len(), 1);
        let event = &state.delegation_return_events[0];
        assert_eq!(event.reason, DelegationReturnReason::UnbondingMatured);
        assert_eq!(event.validator_id, validator_id);
        assert_eq!(event.delegator_id, delegator_id);
        assert_eq!(event.bond_utxo_id, post_gate_bond_utxo_id);
        assert_eq!(event.amount_spark, post_gate_amount);
        assert_eq!(event.returned_epoch, post_epoch);
        assert_eq!(event.returned_height, post_height);
        let post_release = state.utxos.get(&event.refund_utxo_id).unwrap();
        assert_ne!(
            post_release.output.encode_to_vec(),
            post_gate_original_output.encode_to_vec()
        );
        let blinding = derive_normal_stake_bond_release_blinding(
            validator_id,
            delegator_id,
            post_gate_bond_utxo_id,
            post_height,
            post_gate_amount,
        );
        assert_eq!(
            post_release.output.commitment.compressed_point.0,
            indra_crypto::commit(post_gate_amount, &blinding).0
        );
        assert!(indra_crypto::verify_opening(
            &indra_crypto::PedersenCommitment(post_release.output.commitment.compressed_point.0),
            &indra_crypto::PedersenOpening {
                value: post_gate_amount,
                blinding,
            },
        )
        .is_ok());
    }

    #[test]
    fn normal_release_capstone_replay_mixed_bond_shapes_across_active_gates() {
        fn replay() -> ChainState {
            let activation_height = NORMAL_BOND_RELEASE_BLINDING_HEIGHT;
            let pre_epoch = activation_height / EPOCH_DURATION_BLOCKS;
            let post_epoch = pre_epoch + 1;
            let pre_height = pre_epoch * EPOCH_DURATION_BLOCKS;
            let post_height = post_epoch * EPOCH_DURATION_BLOCKS;
            assert!(pre_height < activation_height);
            assert!(post_height >= activation_height);
            assert!(compact_stake_bond_active(pre_height));
            assert!(compact_bond_pubkey_omission_active(pre_height));
            assert!(delegator_identity_registry_active(pre_height));
            assert!(compact_stake_bond_active(post_height));
            assert!(compact_bond_pubkey_omission_active(post_height));
            assert!(delegator_identity_registry_active(post_height));

            let validator_id = Bytes32::from([0xC0; 32]);
            let delegator_id = Bytes32::from([0xC1; 32]);
            let mut pre_legacy = legacy_bond(0xC2, validator_id, delegator_id, 1_000_000);
            let mut post_legacy = legacy_bond(0xC3, validator_id, delegator_id, 1_000_000);
            let mut compact = compact_bond(0xC4, validator_id, delegator_id, 1_000_000);
            let (mut fully_compact, owner_pubkey) =
                fully_compact_bond(0xC5, validator_id, delegator_id, 750_000);
            pre_legacy.unbonding_end_epoch = Some(pre_epoch);
            post_legacy.unbonding_end_epoch = Some(post_epoch);
            compact.unbonding_end_epoch = Some(post_epoch);
            fully_compact.unbonding_end_epoch = Some(post_epoch);

            let mut state = ChainState::new_genesis();
            state
                .delegator_identities
                .insert(delegator_id, owner_pubkey.clone());
            state.staked_bonds.insert(pre_legacy.utxo_id, pre_legacy);
            let post_legacy_utxo_id = post_legacy.utxo_id;
            state.staked_bonds.insert(post_legacy.utxo_id, post_legacy);
            state.staked_bonds.insert(compact.utxo_id, compact);
            state
                .staked_bonds
                .insert(fully_compact.utxo_id, fully_compact);

            let pre_context =
                EpochTransitionContext::new(pre_height, pre_height.saturating_sub(1)).unwrap();
            apply_epoch_transition_at_height(&mut state, &pre_context, 1).unwrap();
            assert!(state.delegation_return_events.is_empty());
            let post_context =
                EpochTransitionContext::new(post_height, post_height.saturating_sub(1)).unwrap();
            apply_epoch_transition_at_height(&mut state, &post_context, 2).unwrap();
            assert_eq!(state.delegation_return_events.len(), 1);
            assert_eq!(
                state.delegation_return_events[0].bond_utxo_id,
                post_legacy_utxo_id
            );
            assert_eq!(
                state.delegation_return_events[0].reason,
                DelegationReturnReason::UnbondingMatured
            );
            state.rebuild_state_commitment_v2(post_height);
            state
        }

        let a = replay();
        let b = replay();
        assert_eq!(a.encode_to_vec(), b.encode_to_vec());
        assert_eq!(compute_state_root(&a), compute_state_root(&b));
        assert_eq!(
            a.state_commitment_v2_root(NORMAL_BOND_RELEASE_BLINDING_HEIGHT),
            b.state_commitment_v2_root(NORMAL_BOND_RELEASE_BLINDING_HEIGHT)
        );
    }

    #[test]
    fn post_gate_matured_bond_release_records_return_event() {
        let current_epoch = u64::MAX;
        let release_height = u64::MAX;
        let validator_id = Bytes32::from([0x95; 32]);
        let delegator_id = Bytes32::from([0x96; 32]);
        let mut bond = legacy_bond(0x97, validator_id, delegator_id, 1_000_000);
        bond.unbonding_end_epoch = Some(current_epoch);
        let bond_utxo_id = bond.utxo_id;
        let amount_spark = bond.amount_spark;
        let mut state = ChainState::new_genesis();
        state.staked_bonds.insert(bond_utxo_id, bond);

        release_unbonded_bonds(&mut state, current_epoch).unwrap();

        assert_eq!(state.delegation_return_events.len(), 1);
        let event = &state.delegation_return_events[0];
        assert_eq!(event.validator_id, validator_id);
        assert_eq!(event.delegator_id, delegator_id);
        assert_eq!(event.bond_utxo_id, bond_utxo_id);
        assert_eq!(event.amount_spark, amount_spark);
        assert_eq!(event.reason, DelegationReturnReason::UnbondingMatured);
        assert_eq!(event.returned_epoch, current_epoch);
        assert_eq!(event.returned_height, release_height);
        assert!(state.utxos.contains(&event.refund_utxo_id));
    }

    #[test]
    fn pre_gate_matured_bond_release_records_no_return_event() {
        let current_epoch = 1;
        let validator_id = Bytes32::from([0x98; 32]);
        let delegator_id = Bytes32::from([0x99; 32]);
        let mut bond = legacy_bond(0x9A, validator_id, delegator_id, 1_000_000);
        bond.unbonding_end_epoch = Some(current_epoch);
        let mut state = ChainState::new_genesis();
        state.staked_bonds.insert(bond.utxo_id, bond);

        release_unbonded_bonds(&mut state, current_epoch).unwrap();

        assert!(state.delegation_return_events.is_empty());
    }

    #[test]
    fn matured_bond_release_events_follow_bounded_retention() {
        let mut state = ChainState::new_genesis();
        for i in 0..MAX_DELEGATION_RETURN_EVENTS {
            state.push_delegation_return_event(DelegationReturnEvent {
                delegator_id: Bytes32::from([0xA0; 32]),
                validator_id: Bytes32::from([0xA1; 32]),
                bond_utxo_id: Bytes32::from([(i % 251) as u8; 32]),
                amount_spark: 1,
                reason: DelegationReturnReason::ValidatorEvicted,
                returned_epoch: i as u64,
                returned_height: i as u64,
                refund_utxo_id: Bytes32::from([0xA2; 32]),
            });
        }
        let current_epoch = u64::MAX;
        let mut bond = legacy_bond(
            0x9B,
            Bytes32::from([0x9C; 32]),
            Bytes32::from([0x9D; 32]),
            1_000_000,
        );
        bond.unbonding_end_epoch = Some(current_epoch);
        let bond_utxo_id = bond.utxo_id;
        state.staked_bonds.insert(bond_utxo_id, bond);

        release_unbonded_bonds(&mut state, current_epoch).unwrap();

        assert_eq!(
            state.delegation_return_events.len(),
            MAX_DELEGATION_RETURN_EVENTS
        );
        assert_eq!(
            state
                .delegation_return_events
                .last()
                .map(|event| event.reason),
            Some(DelegationReturnReason::UnbondingMatured)
        );
        assert_eq!(
            state
                .delegation_return_events
                .last()
                .map(|event| event.bond_utxo_id),
            Some(bond_utxo_id)
        );
        assert_eq!(
            state
                .delegation_return_events
                .first()
                .map(|event| event.returned_epoch),
            Some(1)
        );
    }

    #[test]
    fn matured_bond_release_event_rolls_back_with_epoch_scope() {
        let current_epoch = u64::MAX;
        let validator_id = Bytes32::from([0x9E; 32]);
        let delegator_id = Bytes32::from([0x9F; 32]);
        let mut bond = legacy_bond(0xA4, validator_id, delegator_id, 1_000_000);
        bond.unbonding_end_epoch = Some(current_epoch);
        let mut state = ChainState::new_genesis();
        state.staked_bonds.insert(bond.utxo_id, bond);
        state.rebuild_state_commitment_v2(current_epoch);
        let original = state.clone();
        let original_root = state.state_commitment_v2_root(current_epoch);

        {
            let mut txn = crate::txn::StateTxn::begin(&mut state, current_epoch);
            txn.snapshot_epoch_scope();
            release_unbonded_bonds(txn.state_mut(), current_epoch).unwrap();
        }

        assert_eq!(state, original);
        assert_eq!(state.state_commitment_v2_root(current_epoch), original_root);
    }

    #[test]
    fn compact_normal_release_generates_fresh_valid_output_with_documented_blinding() {
        let validator_id = Bytes32::from([0xA1; 32]);
        let delegator_id = Bytes32::from([0xD1; 32]);
        let bond = compact_bond(0x31, validator_id, delegator_id, 1_000_000);
        assert!(bond.original_output.range_proof.is_none());
        let release_height = 900;
        let state = ChainState::new_genesis();

        let output = released_bond_output(&state, &bond, release_height).unwrap();
        let blinding = manual_compact_release_blinding(&bond, release_height);
        assert_eq!(
            derive_compact_stake_bond_release_blinding(&bond, release_height),
            blinding
        );
        assert_ne!(output.commitment, bond.original_output.commitment);
        assert_eq!(output.value_spark, bond.amount_spark);
        assert_eq!(
            Some(output.owner_pubkey.clone()),
            bond.original_output.owner_pubkey
        );
        assert_eq!(output.lock_height, bond.original_output.lock_height);
        assert!(indra_crypto::verify_opening(
            &indra_crypto::PedersenCommitment(output.commitment.compressed_point.0),
            &indra_crypto::PedersenOpening {
                value: output.value_spark,
                blinding,
            },
        )
        .is_ok());
        assert!(indra_crypto::verify_range(
            &output.commitment.compressed_point.0,
            output.range_proof.as_slice(),
        )
        .is_ok());
    }

    #[test]
    fn compact_slashed_release_generates_fresh_valid_output_with_documented_blinding() {
        let validator_id = Bytes32::from([0xA2; 32]);
        let bond = compact_bond(0x32, validator_id, validator_id, 400_000);
        let release_height = 1_200;
        let blinding = manual_compact_release_blinding(&bond, release_height);
        let state = ChainState::new_genesis();

        let output = released_bond_output(&state, &bond, release_height).unwrap();
        assert_eq!(output.value_spark, 400_000);
        assert!(indra_crypto::verify_opening(
            &indra_crypto::PedersenCommitment(output.commitment.compressed_point.0),
            &indra_crypto::PedersenOpening {
                value: 400_000,
                blinding,
            },
        )
        .is_ok());
        assert!(indra_crypto::verify_range(
            &output.commitment.compressed_point.0,
            output.range_proof.as_slice(),
        )
        .is_ok());
    }

    #[test]
    fn fully_compact_release_resolves_owner_from_registry() {
        let validator_id = Bytes32::from([0xA4; 32]);
        let delegator_id = Bytes32::from([0xD4; 32]);
        let (bond, owner_pubkey) = fully_compact_bond(0x34, validator_id, delegator_id, 750_000);
        assert!(bond.original_output.range_proof.is_none());
        assert!(bond.original_output.owner_pubkey.is_none());
        let mut state = ChainState::new_genesis();
        state
            .delegator_identities
            .insert(delegator_id, owner_pubkey.clone());

        let output = released_bond_output(&state, &bond, 1_500).unwrap();

        assert_eq!(output.owner_pubkey, owner_pubkey);
        assert_eq!(output.value_spark, bond.amount_spark);
        assert!(indra_crypto::verify_range(
            &output.commitment.compressed_point.0,
            output.range_proof.as_slice(),
        )
        .is_ok());
    }

    #[test]
    fn fully_compact_release_fails_loudly_without_registry_owner() {
        let validator_id = Bytes32::from([0xA5; 32]);
        let delegator_id = Bytes32::from([0xD5; 32]);
        let (bond, _) = fully_compact_bond(0x35, validator_id, delegator_id, 750_000);
        let state = ChainState::new_genesis();

        let err = released_bond_output(&state, &bond, 1_500).unwrap_err();

        assert!(matches!(
            err,
            crate::error::StateError::InvariantViolation {
                message: "stake bond release owner pubkey is unresolvable"
            }
        ));
    }

    #[test]
    fn compact_activation_replay_sequence_is_deterministic() {
        fn replay() -> ChainState {
            let activation = 10;
            let validator_id = Bytes32::from([0xA3; 32]);
            let delegator_id = Bytes32::from([0xD3; 32]);
            let mut state = ChainState::new_genesis();

            let legacy = StakeBondEntry::new_for_test_with_compact_activation(
                Bytes32::from([0x41; 32]),
                validator_id,
                delegator_id,
                1_000_000,
                0,
                dummy_output(0x41),
                activation - 1,
                activation,
            );
            let compact_normal = StakeBondEntry::new_for_test_with_compact_activation(
                Bytes32::from([0x42; 32]),
                validator_id,
                delegator_id,
                1_000_000,
                0,
                dummy_output(0x42),
                activation,
                activation,
            );
            let compact_slashed = StakeBondEntry::new_for_test_with_compact_activation(
                Bytes32::from([0x43; 32]),
                validator_id,
                validator_id,
                600_000,
                0,
                dummy_output(0x43),
                activation + 1,
                activation,
            );
            assert!(legacy.original_output.range_proof.is_some());
            assert!(compact_normal.original_output.range_proof.is_none());
            assert!(compact_slashed.original_output.range_proof.is_none());

            state.staked_bonds.insert(legacy.utxo_id, legacy);
            let normal_output =
                released_bond_output(&state, &compact_normal, activation + 2).unwrap();
            state
                .utxos
                .insert(normal_output, activation + 2, STAKING_TX_IDX, 1)
                .unwrap();
            let slashed_output =
                released_bond_output(&state, &compact_slashed, activation + 3).unwrap();
            state
                .utxos
                .insert(slashed_output, activation + 3, STAKING_TX_IDX, 2)
                .unwrap();
            state.height = activation + 3;
            state
        }

        let a = replay();
        let b = replay();
        assert_eq!(a.encode_to_vec(), b.encode_to_vec());
        assert_eq!(compute_state_root(&a), compute_state_root(&b));
    }

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
        let proposal_id = governance_pruning_test_id(index);
        ProposalRecord {
            proposal_id,
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
            description: "terminal proposal pruning test".to_string(),
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
    fn governance_pruning_pre_activation_state_root_unchanged() {
        let mut state = ChainState::new_genesis();
        state.height = GOVERNANCE_PROPOSAL_PRUNING_HEIGHT.saturating_sub(1);
        for index in 0..5 {
            let proposal = governance_pruning_test_proposal(index, ProposalPhase::Failed, index);
            state
                .governance
                .proposals
                .insert(proposal.proposal_id, proposal);
        }
        let before = compute_state_root(&state);
        let height = state.height;

        prune_governance_history_if_active(&mut state, height);

        assert_eq!(state.governance.proposals.len(), 5);
        assert_eq!(compute_state_root(&state), before);
    }

    #[test]
    fn governance_pruning_changes_state_root_at_activation_when_records_removed() {
        let mut state = ChainState::new_genesis();
        state.height = GOVERNANCE_PROPOSAL_PRUNING_HEIGHT;
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
        let boundary_height = GOVERNANCE_PROPOSAL_PRUNING_HEIGHT
            .div_ceil(EPOCH_DURATION_BLOCKS)
            .saturating_mul(EPOCH_DURATION_BLOCKS);
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
    fn rewards_are_weighted_by_self_stake_not_delegations() {
        let mut state = crate::chain::ChainState::new_genesis();
        let validator_a = make_validator(0xA1, 1_000);
        let validator_b = make_validator(0xB1, 1_000);
        let id_a = validator_a.validator_id;
        let id_b = validator_b.validator_id;
        let delegator_id = Bytes32::from([0xD1; 32]);
        state.validators.upsert(validator_a).unwrap();
        state.validators.upsert(validator_b).unwrap();
        state
            .delegations
            .add_delegation(id_b, delegator_id, 1_000_000, 0)
            .unwrap();

        distribute_block_rewards(&mut state, 2_000, 1, 0).unwrap();

        assert_eq!(state.validators.get(&id_a).unwrap().pending_rewards, 1_000);
        assert_eq!(
            state.validators.get(&id_b).unwrap().pending_rewards,
            100,
            "validator B gets 10% commission from its self-stake-weighted reward pool"
        );
        assert_eq!(
            state
                .delegations
                .get_delegators(&id_b)
                .iter()
                .find(|entry| entry.delegator_id == delegator_id)
                .unwrap()
                .pending_rewards,
            900,
            "delegated stake splits validator B's reward pool but does not increase its size"
        );
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
    fn activating_commission_applies_only_to_next_epoch_reward() {
        let mut state = crate::chain::ChainState::new_genesis();
        let mut validator = make_validator(0xC5, MINIMUM_ACTIVE_SELF_STAKE_SPARK.saturating_mul(2));
        let validator_id = validator.validator_id;
        validator.commission_bps = 1_000;
        validator.pending_commission_bps = Some(2_000);
        validator.pending_commission_effective_epoch = Some(COMMISSION_CHANGE_DELAY_EPOCHS);
        state.validators.upsert(validator).unwrap();
        let delegator_id = Bytes32::from([0xD5; 32]);
        state
            .delegations
            .add_delegation(
                validator_id,
                delegator_id,
                MINIMUM_ACTIVE_SELF_STAKE_SPARK,
                0,
            )
            .unwrap();

        let activation_epoch = COMMISSION_CHANGE_DELAY_EPOCHS;
        let activation_height = activation_epoch.saturating_mul(EPOCH_DURATION_BLOCKS);
        let reward_at_activation =
            block_reward_at_height(activation_height).saturating_mul(EPOCH_DURATION_BLOCKS);
        let fee_reward_at_activation = 10_000;
        state.fee_reward_pool = fee_reward_at_activation;
        apply_epoch_transition(
            &mut state,
            &EpochTransitionContext::new(
                (activation_epoch).saturating_mul(EPOCH_DURATION_BLOCKS),
                (activation_epoch)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();

        let validator_after_activation = state.validators.get(&validator_id).unwrap();
        assert_eq!(validator_after_activation.commission_bps, 2_000);
        let validator_rewards_after_activation = validator_after_activation.pending_rewards;
        assert_eq!(
            validator_rewards_after_activation,
            bps_of(reward_at_activation, 1_000)
                .saturating_add(bps_of(fee_reward_at_activation, 1_000)),
            "the activation boundary must pay the elapsed epoch at the old rate"
        );
        let delegator_after_activation = state
            .delegations
            .get_delegator_reward(&validator_id, &delegator_id);
        assert_eq!(
            delegator_after_activation,
            reward_at_activation
                .saturating_sub(bps_of(reward_at_activation, 1_000))
                .saturating_add(
                    fee_reward_at_activation
                        .saturating_sub(bps_of(fee_reward_at_activation, 1_000)),
                )
        );

        let next_epoch = activation_epoch.saturating_add(1);
        let next_height = next_epoch.saturating_mul(EPOCH_DURATION_BLOCKS);
        let next_reward = block_reward_at_height(next_height).saturating_mul(EPOCH_DURATION_BLOCKS);
        let next_fee_reward = 20_000;
        state.fee_reward_pool = next_fee_reward;
        apply_epoch_transition(
            &mut state,
            &EpochTransitionContext::new(
                (next_epoch).saturating_mul(EPOCH_DURATION_BLOCKS),
                (next_epoch)
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
                .get(&validator_id)
                .unwrap()
                .pending_rewards
                .saturating_sub(validator_rewards_after_activation),
            bps_of(next_reward, 2_000).saturating_add(bps_of(next_fee_reward, 2_000)),
            "the next epoch reward must use the newly activated rate"
        );
        assert_eq!(
            state
                .delegations
                .get_delegator_reward(&validator_id, &delegator_id)
                .saturating_sub(delegator_after_activation),
            next_reward
                .saturating_sub(bps_of(next_reward, 2_000))
                .saturating_add(next_fee_reward.saturating_sub(bps_of(next_fee_reward, 2_000)))
        );
    }

    #[test]
    fn boundary_without_pending_commission_uses_current_rate() {
        let mut state = crate::chain::ChainState::new_genesis();
        let mut validator = make_validator(0xC6, MINIMUM_ACTIVE_SELF_STAKE_SPARK.saturating_mul(2));
        let validator_id = validator.validator_id;
        validator.commission_bps = 1_250;
        state.validators.upsert(validator).unwrap();
        let delegator_id = Bytes32::from([0xD6; 32]);
        state
            .delegations
            .add_delegation(
                validator_id,
                delegator_id,
                MINIMUM_ACTIVE_SELF_STAKE_SPARK,
                0,
            )
            .unwrap();

        let epoch = 1;
        let height = epoch * EPOCH_DURATION_BLOCKS;
        let reward = block_reward_at_height(height).saturating_mul(EPOCH_DURATION_BLOCKS);
        apply_epoch_transition(
            &mut state,
            &EpochTransitionContext::new(
                (epoch).saturating_mul(EPOCH_DURATION_BLOCKS),
                (epoch)
                    .saturating_mul(EPOCH_DURATION_BLOCKS)
                    .saturating_sub(1),
            )
            .unwrap(),
            0,
        )
        .unwrap();

        assert_eq!(
            state.validators.get(&validator_id).unwrap().pending_rewards,
            bps_of(reward, 1_250)
        );
        assert_eq!(
            state
                .delegations
                .get_delegator_reward(&validator_id, &delegator_id),
            reward.saturating_sub(bps_of(reward, 1_250))
        );
    }

    #[test]
    fn delegator_rewards_use_pre_change_commission_during_delay() {
        let mut state = crate::chain::ChainState::new_genesis();
        let mut validator = make_validator(0xC2, 1_000);
        let validator_id = validator.validator_id;
        validator.commission_bps = 1_000;
        validator.pending_commission_bps = Some(2_000);
        validator.pending_commission_effective_epoch = Some(COMMISSION_CHANGE_DELAY_EPOCHS);
        state.validators.upsert(validator).unwrap();

        let delegator_id = Bytes32::from([0xD2; 32]);
        state
            .delegations
            .add_delegation(validator_id, delegator_id, 1_000, 0)
            .unwrap();

        distribute_block_rewards(&mut state, 1_000, 1, 0).unwrap();

        assert_eq!(
            state.validators.get(&validator_id).unwrap().pending_rewards,
            100,
            "old 10% commission must remain active during the delay window"
        );
        assert_eq!(
            state
                .delegations
                .get_delegators(&validator_id)
                .iter()
                .find(|entry| entry.delegator_id == delegator_id)
                .unwrap()
                .pending_rewards,
            900
        );
    }

    #[test]
    fn partial_bond_exit_keeps_sixty_unit_active_remainder_rewarded() {
        let mut state = ChainState::new_genesis();
        let mut validator = make_validator(0xD7, 1_000);
        validator.commission_bps = 1_000;
        let validator_id = validator.validator_id;
        state.validators.upsert(validator).unwrap();
        let delegator_id = Bytes32::from([0xD8; 32]);
        state
            .delegations
            .add_delegation(validator_id, delegator_id, 100, 0)
            .unwrap();
        let active = compact_bond(0xD9, validator_id, delegator_id, 60);
        let mut exiting = compact_bond(0xDA, validator_id, delegator_id, 40);
        exiting.unbonding_end_epoch = Some(1008);
        state.staked_bonds.insert(active.utxo_id, active);
        state.staked_bonds.insert(exiting.utxo_id, exiting);

        reconcile_all_delegators_from_bonds(&mut state);
        let entry = state
            .delegations
            .get_delegators(&validator_id)
            .first()
            .unwrap();
        assert_eq!(entry.staked_spark, 60);
        assert_eq!(entry.unbonding_end_epoch, None);

        distribute_block_rewards(&mut state, 1_000, 1, 0).unwrap();
        assert_eq!(
            state
                .delegations
                .get_delegator_reward(&validator_id, &delegator_id),
            900
        );
        assert_eq!(
            state.validators.get(&validator_id).unwrap().pending_rewards,
            100
        );

        state.fee_reward_pool = 1_000;
        distribute_fee_rewards(&mut state, 1, 0).unwrap();
        assert_eq!(
            state
                .delegations
                .get_delegator_reward(&validator_id, &delegator_id),
            1_800
        );
        assert_eq!(
            state.validators.get(&validator_id).unwrap().pending_rewards,
            200
        );
    }

    #[test]
    fn precise_accounting_removes_empty_aggregate_after_final_bond_matures() {
        let mut state = ChainState::new_genesis();
        let validator_id = Bytes32::from([0xE1; 32]);
        let delegator_id = Bytes32::from([0xE2; 32]);
        state
            .delegations
            .add_delegation(validator_id, delegator_id, 40, 0)
            .unwrap();
        let mut bond = compact_bond(0xE3, validator_id, delegator_id, 40);
        bond.unbonding_end_epoch = Some(1);
        state.staked_bonds.insert(bond.utxo_id, bond);

        release_unbonded_bonds_at_height(&mut state, 1, u64::MAX).unwrap();

        assert!(state.staked_bonds.is_empty());
        assert!(state.delegations.get_delegators(&validator_id).is_empty());
    }

    #[test]
    fn block_reward_dust_is_explicitly_routed() {
        let mut state = crate::chain::ChainState::new_genesis();
        let validator_a = make_validator(0xC3, 1);
        let validator_b = make_validator(0xC4, 1);
        let id_a = validator_a.validator_id;
        let id_b = validator_b.validator_id;
        state.validators.upsert(validator_a).unwrap();
        state.validators.upsert(validator_b).unwrap();
        let treasury_before = state.treasury_balance;

        distribute_block_rewards(&mut state, 101, 1, 0).unwrap();

        let reward_a = state.validators.get(&id_a).unwrap().pending_rewards;
        let reward_b = state.validators.get(&id_b).unwrap().pending_rewards;
        let treasury_delta = state.treasury_balance.saturating_sub(treasury_before);
        assert_eq!(reward_a + reward_b + treasury_delta, 101);
        assert_eq!(treasury_delta, 1);
    }

    #[test]
    fn fee_reward_dust_returns_to_pool() {
        let mut state = crate::chain::ChainState::new_genesis();
        let validator_a = make_validator(0xC5, 1);
        let validator_b = make_validator(0xC6, 1);
        let id_a = validator_a.validator_id;
        let id_b = validator_b.validator_id;
        state.validators.upsert(validator_a).unwrap();
        state.validators.upsert(validator_b).unwrap();
        state.fee_reward_pool = 101;

        distribute_fee_rewards(&mut state, 1, 0).unwrap();

        assert_eq!(state.validators.get(&id_a).unwrap().pending_rewards, 50);
        assert_eq!(state.validators.get(&id_b).unwrap().pending_rewards, 50);
        assert_eq!(state.fee_reward_pool, 1);
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

        distribute_block_rewards(&mut empty_block_state, 1_000, 1, 0).unwrap();
        distribute_block_rewards(&mut full_block_state, 1_000, 1, 0).unwrap();

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
                (3u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (3u64)
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
                (3u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (3u64)
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
                (3u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (3u64)
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
                (3u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (3u64)
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
                (3u64).saturating_mul(EPOCH_DURATION_BLOCKS),
                (3u64)
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
    fn auto_delegation_routes_rewards_when_not_in_active_set() {
        let mut state = crate::chain::ChainState::new_genesis();
        for i in 1..=21u8 {
            let mut validator =
                make_validator(i, (22u64 - i as u64) * MINIMUM_ACTIVE_SELF_STAKE_SPARK);
            if i == 21 {
                validator.auto_delegate_to = Some(Bytes32::from([0x01; 32]));
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

        let inactive_id = Bytes32::from([0x15; 32]);
        let target_id = Bytes32::from([0x01; 32]);
        let inactive = state.validators.get(&inactive_id).unwrap();
        let target = state.validators.get(&target_id).unwrap();

        assert_eq!(inactive.status, ValidatorStatus::Registered);
        assert!(inactive.pending_rewards > 0);
        assert!(target.pending_rewards > 0);
        assert!(state
            .delegations
            .get_delegators(&target_id)
            .iter()
            .all(|entry| entry.delegator_id != inactive_id));
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
    fn auto_delegation_virtual_entry_not_in_state_root_after_transition() {
        let mut state = crate::chain::ChainState::new_genesis();
        for i in 1..=21u8 {
            let mut validator =
                make_validator(i, (22u64 - i as u64) * MINIMUM_ACTIVE_SELF_STAKE_SPARK);
            if i == 21 {
                validator.auto_delegate_to = Some(Bytes32::from([0x01; 32]));
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
        let root_after_first = compute_state_root(&state);
        let target_id = Bytes32::from([0x01; 32]);
        let inactive_id = Bytes32::from([0x15; 32]);

        assert!(state
            .delegations
            .get_delegators(&target_id)
            .iter()
            .all(|entry| entry.delegator_id != inactive_id));
        assert_eq!(root_after_first, compute_state_root(&state));
    }

    #[test]
    fn auto_delegation_preserves_existing_real_delegation() {
        let mut state = crate::chain::ChainState::new_genesis();
        for i in 1..=21u8 {
            let mut validator = make_validator(i, (22u64 - i as u64) * 1_000_000);
            if i == 21 {
                validator.auto_delegate_to = Some(Bytes32::from([0x01; 32]));
            }
            state.validators.upsert(validator).unwrap();
        }
        let target_id = Bytes32::from([0x01; 32]);
        let inactive_id = Bytes32::from([0x15; 32]);
        state
            .delegations
            .add_delegation(target_id, inactive_id, 123_456, 0)
            .unwrap();

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

        let entries = state.delegations.get_delegators(&target_id);
        let restored = entries
            .iter()
            .find(|entry| entry.delegator_id == inactive_id)
            .unwrap();
        assert_eq!(restored.staked_spark, 123_456);
        assert!(restored.pending_rewards > 0);
        assert!(state.validators.get(&inactive_id).unwrap().pending_rewards > 0);
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
    fn unbonded_bonds_released_to_utxo_set() {
        let mut state = crate::chain::ChainState::new_genesis();
        let utxo_id = Bytes32::from([0xAB; 32]);
        state.staked_bonds.insert(
            utxo_id,
            StakeBondEntry {
                utxo_id,
                validator_id: Bytes32::from([0x01; 32]),
                delegator_id: Bytes32::from([0x02; 32]),
                amount_spark: 1_000_000,
                bonded_epoch: 0,
                unbonding_end_epoch: Some(1),
                unbonding_precision: crate::validator::StakeBondUnbondingPrecision::LegacyEpochOnly,
                custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                    Bytes32::from([0x02; 32]),
                ),
                original_output: dummy_output(0x44).into(),
            },
        );

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

        assert!(state.staked_bonds.is_empty());
        assert_eq!(state.utxos.len(), 1);
    }

    #[test]
    fn active_bonds_not_released_early() {
        let mut state = crate::chain::ChainState::new_genesis();
        let utxo_id = Bytes32::from([0xAC; 32]);
        state.staked_bonds.insert(
            utxo_id,
            StakeBondEntry {
                utxo_id,
                validator_id: Bytes32::from([0x01; 32]),
                delegator_id: Bytes32::from([0x02; 32]),
                amount_spark: 1_000_000,
                bonded_epoch: 0,
                unbonding_end_epoch: None,
                unbonding_precision: crate::validator::StakeBondUnbondingPrecision::LegacyEpochOnly,
                custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                    Bytes32::from([0x02; 32]),
                ),
                original_output: dummy_output(0x45).into(),
            },
        );

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

        assert!(state.staked_bonds.contains_key(&utxo_id));
        assert!(state.utxos.is_empty());
    }
}
