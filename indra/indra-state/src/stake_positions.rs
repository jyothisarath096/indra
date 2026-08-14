//! Isolated canonical staking-position lifecycle.
//!
//! These transitions deliberately do not replace live `StakingOp` dispatch yet.
//! They provide the atomic, replay-deterministic Stage 2 lifecycle that later
//! stages will wire into rewards, governance, slashing, tombstones, RPC, and
//! wallets.

use indra_core::types::{
    crypto::HybridPubKey,
    primitives::{
        Bytes32, VariableBytes, DUST_LIMIT_SPARK, MAX_STAKE_POSITIONS_PER_VALIDATOR,
        MAX_STAKE_POSITIONS_TOTAL, MAX_TRANCHES_PER_POSITION, MAX_TRANCHES_PER_VALIDATOR,
        MAX_TRANCHES_TOTAL, STAKING_TX_IDX,
    },
    stake_position::{
        derive_position_id, derive_tranche_id, ActiveStakeAggregateV1, PositionCustodyV1,
        StakePositionV1, UnbondingTimingV1, UnbondingTrancheV1,
    },
    staking::{StakingOp, StakingOpBody},
    transaction::OutputV1,
};

use crate::{
    error::{StateError, StateResult},
    identity::resolve_active_validator_cold_pubkey,
    txn::StateTxn,
    ChainState,
};

/// Deposit one owned UTXO into a canonical position, aggregating by tuple.
pub fn deposit_stake_position(
    state: &mut ChainState,
    validator_id: Bytes32,
    principal_owner_id: Bytes32,
    custody: PositionCustodyV1,
    custody_pubkey: &HybridPubKey,
    utxo_id: Bytes32,
    current_height: u64,
) -> StateResult<Bytes32> {
    custody
        .validate_for(validator_id, principal_owner_id)
        .map_err(invalid_position)?;
    if state.validators.get(&validator_id).is_none() {
        return Err(StateError::ValidatorNotFound);
    }
    let utxo = state.utxos.get(&utxo_id).ok_or(StateError::UnknownUtxo)?;
    let principal_spark = utxo.output.value_spark;
    if principal_spark < DUST_LIMIT_SPARK {
        return Err(StateError::BelowDustLimit {
            limit: DUST_LIMIT_SPARK,
        });
    }
    if current_height < utxo.output.lock_height {
        return Err(StateError::OutputLocked {
            lock_height: utxo.output.lock_height,
            current_height,
        });
    }
    let owner_matches_custody = match custody {
        PositionCustodyV1::DelegatorIdentity { delegator_id } => {
            custody_pubkey.identity_id() == delegator_id
                && utxo.output.owner_pubkey == *custody_pubkey
        }
        PositionCustodyV1::ValidatorColdIdentity { validator_id } => {
            let cold_pubkey =
                resolve_active_validator_cold_pubkey(state, &validator_id).map_err(|_| {
                    StateError::InvalidStakingOp(
                        "validator cold custody key cannot be resolved".to_string(),
                    )
                })?;
            *custody_pubkey == cold_pubkey && utxo.output.owner_pubkey == *custody_pubkey
        }
    };
    if !owner_matches_custody {
        return Err(StateError::InvalidStakingOp(
            "position deposit UTXO owner does not match custody authority".to_string(),
        ));
    }
    let position_id = derive_position_id(validator_id, principal_owner_id, custody);
    let existing = state.stake_positions.get(&position_id).cloned();
    preflight_deposit_capacity(state, validator_id, existing.is_none())?;
    let next = match existing {
        Some(mut position) => {
            position.active = Some(match position.active {
                Some(active) => active
                    .checked_add_principal(principal_spark, current_height)
                    .map_err(invalid_position)?,
                None => {
                    ActiveStakeAggregateV1::new(principal_spark, current_height, current_height)
                        .map_err(invalid_position)?
                }
            });
            position
        }
        None => StakePositionV1::new(
            validator_id,
            principal_owner_id,
            custody,
            Some(
                ActiveStakeAggregateV1::new(principal_spark, current_height, current_height)
                    .map_err(invalid_position)?,
            ),
            0,
            current_height / indra_core::types::primitives::EPOCH_DURATION_BLOCKS,
        )
        .map_err(invalid_position)?,
    };

    let mut txn = StateTxn::begin(state, current_height);
    txn.ensure_state_commitment_v2()?;
    let spent = txn.spend_utxo(&utxo_id)?;
    if spent.is_none() {
        return Err(StateError::UnknownUtxo);
    }
    txn.put_stake_position(next)?;
    txn.commit();
    Ok(position_id)
}

/// Move authorized active principal into one immutable exact-height tranche.
pub fn exit_stake_position(
    state: &mut ChainState,
    op: &StakingOp,
    current_height: u64,
) -> StateResult<Bytes32> {
    let StakingOpBody::ExitStakePosition {
        position_id,
        amount_spark,
        custody,
        ..
    } = op.body
    else {
        return Err(StateError::InvalidStakingOp(
            "expected stake-position exit operation".into(),
        ));
    };
    let position = state
        .stake_positions
        .get(&position_id)
        .cloned()
        .ok_or_else(|| StateError::InvalidStakingOp("unknown stake position".to_string()))?;
    if custody != position.custody {
        return Err(StateError::InvalidStakingOp(
            "position exit custody does not match position".to_string(),
        ));
    }
    let active = position
        .active
        .ok_or_else(|| StateError::InvalidStakingOp("position has no active principal".into()))?;
    if amount_spark > active.principal_spark {
        return Err(StateError::InvalidStakingOp(
            "position exit exceeds active principal".to_string(),
        ));
    }
    let remaining = active.principal_spark - amount_spark;
    if remaining != 0 && remaining < DUST_LIMIT_SPARK {
        return Err(StateError::BelowDustLimit {
            limit: DUST_LIMIT_SPARK,
        });
    }
    preflight_exit_capacity(state, &position, remaining == 0)?;

    let creation_op_id = indra_core::types::stake_position::staking_op_id_v2(op, &state.chain_id)
        .map_err(invalid_position)?;
    let timing = UnbondingTimingV1::height_precise(current_height).map_err(invalid_position)?;
    let tranche_id = derive_tranche_id(
        position.position_id,
        creation_op_id,
        0,
        timing,
        amount_spark,
    );
    if state.unbonding_tranches.contains_key(&tranche_id) {
        return Err(StateError::InvalidStakingOp(
            "duplicate position exit intent".to_string(),
        ));
    }
    let tranche = UnbondingTrancheV1::new(
        position.position_id,
        amount_spark,
        timing,
        position.custody,
        creation_op_id,
        0,
    )
    .map_err(invalid_position)?;
    if tranche.tranche_id != tranche_id {
        return Err(StateError::InvariantViolation {
            message: "precomputed tranche ID differs from canonical tranche",
        });
    }
    let mut updated_position = position;
    updated_position.active = if remaining == 0 {
        None
    } else {
        Some(
            ActiveStakeAggregateV1::new(
                remaining,
                active.first_contribution_height,
                active.last_contribution_height,
            )
            .map_err(invalid_position)?,
        )
    };

    let updated_validator = match updated_position.custody {
        PositionCustodyV1::ValidatorColdIdentity { validator_id } => {
            let mut validator = state
                .validators
                .get(&validator_id)
                .cloned()
                .ok_or(StateError::ValidatorNotFound)?;
            validator.stake_spark = validator.stake_spark.checked_sub(amount_spark).ok_or(
                StateError::InvariantViolation {
                    message: "self-position exit exceeds validator stake cache",
                },
            )?;
            if validator.status == crate::validator::ValidatorStatus::Active
                && validator.stake_spark
                    < indra_core::types::primitives::MINIMUM_ACTIVE_SELF_STAKE_SPARK
            {
                validator.status = crate::validator::ValidatorStatus::Registered;
            }
            Some(validator)
        }
        PositionCustodyV1::DelegatorIdentity { .. } => None,
    };
    let mut txn = StateTxn::begin(state, current_height);
    txn.snapshot_staking_scope();
    txn.ensure_state_commitment_v2()?;
    txn.put_stake_position(updated_position)?;
    txn.put_unbonding_tranche(tranche)?;
    if let Some(validator) = updated_validator {
        txn.state_mut().validators.upsert(validator.clone())?;
        if let Some(commitment) = txn.state_mut().state_commitment_v2.as_mut() {
            commitment.put_validator(&validator, current_height);
        }
    }
    txn.commit();
    Ok(tranche_id)
}

/// Release every mature tranche into a deterministic spend-key-protected UTXO.
pub fn release_matured_position_tranches(
    state: &mut ChainState,
    release_height: u64,
) -> StateResult<Vec<Bytes32>> {
    let current_epoch = release_height / indra_core::types::primitives::EPOCH_DURATION_BLOCKS;
    let mut mature = state
        .unbonding_tranches
        .values()
        .filter(|tranche| match tranche.timing {
            UnbondingTimingV1::HeightPrecise { end_epoch, .. } => end_epoch <= current_epoch,
        })
        .cloned()
        .collect::<Vec<_>>();
    mature.sort_by_key(|tranche| {
        let UnbondingTimingV1::HeightPrecise { end_epoch, .. } = tranche.timing;
        (end_epoch, tranche.tranche_id)
    });
    if mature.is_empty() {
        return Ok(Vec::new());
    }

    let mut prepared = Vec::with_capacity(mature.len());
    for (ordinal, tranche) in mature.iter().enumerate() {
        let position = state
            .stake_positions
            .get(&tranche.position_id)
            .ok_or_else(|| StateError::InvariantViolation {
                message: "mature tranche references missing position",
            })?;
        let owner = resolve_position_owner(state, position)?;
        let UnbondingTimingV1::HeightPrecise { end_epoch, .. } = tranche.timing;
        let output = OutputV1 {
            value_spark: tranche.principal_spark,
            owner_pubkey: owner,
            lock_height: 0,
        };
        let output_index = u32::try_from(ordinal).map_err(|_| StateError::InvariantViolation {
            message: "mature tranche output ordinal overflow",
        })?;
        let refund_utxo_id = crate::utxo::UtxoSet::compute_utxo_id(
            &output,
            release_height,
            STAKING_TX_IDX,
            output_index,
        );
        let event = indra_core::types::stake_position::TrancheRefundEventV1 {
            refund_utxo_id,
            position_id: tranche.position_id,
            tranche_id: tranche.tranche_id,
            principal_owner_id: position.principal_owner_id,
            custody: tranche.custody,
            principal_spark: tranche.principal_spark,
            release_height,
            end_epoch,
        };
        event
            .validate()
            .map_err(|error| StateError::InvalidStakingOp(error.to_string()))?;
        prepared.push((tranche.clone(), output, output_index, event));
    }

    let mut txn = StateTxn::begin(state, release_height);
    txn.ensure_state_commitment_v2()?;
    let mut output_ids = Vec::with_capacity(prepared.len());
    for (tranche, output, output_index, event) in prepared {
        output_ids.push(txn.insert_tranche_refund_utxo(
            output,
            release_height,
            STAKING_TX_IDX,
            output_index,
            event,
        )?);
        txn.delete_unbonding_tranche(&tranche.tranche_id)?;
        let remove_position = txn
            .state()
            .stake_positions
            .get(&tranche.position_id)
            .is_some_and(|position| {
                position.active.is_none()
                    && position.pending_rewards_spark == 0
                    && txn
                        .state()
                        .tranche_ids_for_position(&tranche.position_id)
                        .is_empty()
            });
        let tombstone_owner = txn
            .state()
            .evicted_validator_tombstones
            .iter()
            .find(|(_, tombstone)| {
                tombstone
                    .retained_tranche_ids
                    .binary_search(&tranche.tranche_id)
                    .is_ok()
            })
            .map(|(validator_id, _)| *validator_id);
        if let Some(validator_id) = tombstone_owner {
            let mut tombstone = txn
                .state()
                .evicted_validator_tombstones
                .get(&validator_id)
                .cloned()
                .ok_or(StateError::InvariantViolation {
                    message: "mature tranche tombstone disappeared",
                })?;
            let has_other_retained = tombstone.retained_tranche_ids.iter().any(|id| {
                *id != tranche.tranche_id
                    && txn
                        .state()
                        .unbonding_tranches
                        .get(id)
                        .is_some_and(|other| other.position_id == tranche.position_id)
            });
            crate::tranche_tombstone::clear_matured_tranche_reference_v2(
                &mut tombstone,
                tranche.tranche_id,
                tranche.position_id,
                remove_position,
                has_other_retained,
            )?;
            txn.state_mut()
                .evicted_validator_tombstones
                .insert(validator_id, tombstone.clone());
            if let Some(commitment) = txn.state_mut().state_commitment_v2.as_mut() {
                commitment.put_evicted_validator_tombstone(&tombstone);
            }
        }
        if remove_position {
            txn.delete_stake_position(&tranche.position_id)?;
        }
    }
    let current_epoch = release_height / indra_core::types::primitives::EPOCH_DURATION_BLOCKS;
    let prunable = txn
        .state()
        .evicted_validator_tombstones
        .iter()
        .filter(|(_, tombstone)| {
            crate::tranche_tombstone::tombstone_is_prunable_v2(tombstone, current_epoch)
        })
        .map(|(validator_id, _)| *validator_id)
        .collect::<Vec<_>>();
    for validator_id in prunable {
        txn.state_mut()
            .evicted_validator_tombstones
            .remove(&validator_id);
        if let Some(commitment) = txn.state_mut().state_commitment_v2.as_mut() {
            commitment.delete_evicted_validator_tombstone(&validator_id);
        }
    }
    txn.commit();
    Ok(output_ids)
}

fn resolve_position_owner(
    state: &ChainState,
    position: &StakePositionV1,
) -> StateResult<HybridPubKey> {
    match position.custody {
        PositionCustodyV1::DelegatorIdentity { delegator_id } => state
            .delegator_identities
            .get(&delegator_id)
            .cloned()
            .ok_or_else(|| StateError::InvalidStakingOp("missing delegator identity".to_string())),
        PositionCustodyV1::ValidatorColdIdentity { validator_id } => {
            let (classical, pq) = if let Some(validator) = state.validators.get(&validator_id) {
                (
                    validator.cold_hybrid_classical_pk.ok_or_else(|| {
                        StateError::InvalidStakingOp("missing validator cold identity".to_string())
                    })?,
                    validator.cold_hybrid_pq_pk.clone().ok_or_else(|| {
                        StateError::InvalidStakingOp("missing validator cold identity".to_string())
                    })?,
                )
            } else {
                let cold = state
                    .evicted_validator_tombstones
                    .get(&validator_id)
                    .and_then(|tombstone| tombstone.cold_custody.as_ref())
                    .ok_or(StateError::ValidatorNotFound)?;
                (cold.classical_pk, cold.pq_pk)
            };
            Ok(HybridPubKey {
                classical_pk: Bytes32::from(classical),
                pq_pk: VariableBytes::from_slice(&pq).map_err(|_| {
                    StateError::InvalidStakingOp("invalid validator cold identity".to_string())
                })?,
            })
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CapacityUsage {
    positions_total: usize,
    positions_validator: usize,
    active_positions_total: usize,
    active_positions_validator: usize,
    tranches_total: usize,
    tranches_validator: usize,
    tranches_position: usize,
}

fn usage(state: &ChainState, validator_id: Bytes32, position_id: Bytes32) -> CapacityUsage {
    CapacityUsage {
        positions_total: state.stake_positions.len(),
        positions_validator: state
            .stake_positions
            .values()
            .filter(|position| position.validator_id == validator_id)
            .count(),
        active_positions_total: state
            .stake_positions
            .values()
            .filter(|position| position.active.is_some())
            .count(),
        active_positions_validator: state
            .stake_positions
            .values()
            .filter(|position| position.validator_id == validator_id && position.active.is_some())
            .count(),
        tranches_total: state.unbonding_tranches.len(),
        tranches_validator: state
            .unbonding_tranches
            .values()
            .filter(|tranche| {
                state
                    .stake_positions
                    .get(&tranche.position_id)
                    .is_some_and(|position| position.validator_id == validator_id)
            })
            .count(),
        tranches_position: state.tranche_ids_for_position(&position_id).len(),
    }
}

fn preflight_deposit_capacity(
    state: &ChainState,
    validator_id: Bytes32,
    creates_position: bool,
) -> StateResult<()> {
    if !creates_position {
        return Ok(());
    }
    let u = usage(state, validator_id, Bytes32::ZERO);
    preflight_deposit_usage(u)
}

fn preflight_deposit_usage(u: CapacityUsage) -> StateResult<()> {
    check_capacity(
        u.positions_total + 1 <= MAX_STAKE_POSITIONS_TOTAL,
        "global position cap",
    )?;
    check_capacity(
        u.positions_validator + 1 <= MAX_STAKE_POSITIONS_PER_VALIDATOR,
        "per-validator position cap",
    )?;
    check_capacity(
        u.tranches_total + u.active_positions_total + 1 <= MAX_TRANCHES_TOTAL,
        "global final-exit reservation",
    )?;
    check_capacity(
        u.tranches_validator + u.active_positions_validator + 1 <= MAX_TRANCHES_PER_VALIDATOR,
        "per-validator final-exit reservation",
    )
}

fn preflight_exit_capacity(
    state: &ChainState,
    position: &StakePositionV1,
    full_exit: bool,
) -> StateResult<()> {
    let u = usage(state, position.validator_id, position.position_id);
    preflight_exit_usage(u, full_exit)
}

fn preflight_exit_usage(u: CapacityUsage, full_exit: bool) -> StateResult<()> {
    check_capacity(
        u.tranches_position + 1 <= MAX_TRANCHES_PER_POSITION,
        "per-position tranche cap",
    )?;
    check_capacity(
        u.tranches_position + 1 + usize::from(!full_exit) <= MAX_TRANCHES_PER_POSITION,
        "per-position final-exit reservation",
    )?;
    check_capacity(
        u.tranches_total + 1 <= MAX_TRANCHES_TOTAL,
        "global tranche cap",
    )?;
    check_capacity(
        u.tranches_validator + 1 <= MAX_TRANCHES_PER_VALIDATOR,
        "per-validator tranche cap",
    )?;
    let active_delta = usize::from(!full_exit);
    let active_total_after = u.active_positions_total - 1 + active_delta;
    let active_validator_after = u.active_positions_validator - 1 + active_delta;
    check_capacity(
        u.tranches_total + 1 + active_total_after <= MAX_TRANCHES_TOTAL,
        "global final-exit reservation",
    )?;
    check_capacity(
        u.tranches_validator + 1 + active_validator_after <= MAX_TRANCHES_PER_VALIDATOR,
        "per-validator final-exit reservation",
    )
}

fn check_capacity(condition: bool, reason: &'static str) -> StateResult<()> {
    if condition {
        Ok(())
    } else {
        Err(StateError::StakePositionCapacityExceeded {
            reason: reason.to_string(),
        })
    }
}

fn invalid_position(error: indra_core::error::IndraError) -> StateError {
    StateError::InvalidStakingOp(error.to_string())
}
#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        codec::{Decode, Encode},
        types::crypto::HybridSignature,
    };
    use indra_crypto::{ClassicalKeypair, HybridKeypair, PqKeypair};

    use crate::{
        state_root::compute_state_root,
        txn::set_fail_after_mutation,
        validator::{ValidatorEntry, ValidatorStatus},
    };

    fn id(byte: u8) -> Bytes32 {
        Bytes32::from([byte; 32])
    }

    fn keypair(seed: u8) -> HybridKeypair {
        HybridKeypair::new(
            ClassicalKeypair::from_seed(&[seed; 32]),
            PqKeypair::from_seed(&[seed.wrapping_add(1); 32]).unwrap(),
        )
    }

    fn wire_pubkey(keypair: &HybridKeypair) -> HybridPubKey {
        let public = keypair.public_key();
        HybridPubKey {
            classical_pk: Bytes32::from(public.classical.0),
            pq_pk: VariableBytes::from_slice(&public.pq.0).unwrap(),
        }
    }

    fn wire_signature(signature: &indra_crypto::HybridSignature) -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&signature.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&signature.pq.0).unwrap(),
        }
    }

    fn accounted_value(state: &ChainState) -> u64 {
        state
            .utxos
            .all_entries()
            .map(|entry| entry.output.value_spark)
            .sum::<u64>()
            .saturating_add(state.stake_positions.values().fold(0u64, |sum, position| {
                sum.saturating_add(
                    position
                        .active
                        .map(|active| active.principal_spark)
                        .unwrap_or(0),
                )
                .saturating_add(position.pending_rewards_spark)
            }))
            .saturating_add(
                state
                    .unbonding_tranches
                    .values()
                    .map(|tranche| tranche.principal_spark)
                    .sum::<u64>(),
            )
            .saturating_add(state.treasury_balance)
            .saturating_add(state.fee_reward_pool)
            .saturating_add(state.burn_buffer)
    }

    fn validator(validator_id: Bytes32, vote_keys: &HybridKeypair) -> ValidatorEntry {
        let vote_public = vote_keys.public_key();
        let vrf = indra_crypto::VrfKeypair::from_seed(&[0x77; 32]);
        ValidatorEntry {
            validator_id,
            name: "validator".to_string(),
            hybrid_classical_pk: Some(vote_public.classical.0),
            hybrid_pq_pk: Some(vote_public.pq.0.to_vec()),
            vrf_pk: Some(vrf.public_key()),
            vrf_key_activation_epoch: 0,
            pending_vrf_pk: None,
            pending_vrf_activation_epoch: None,
            stake_spark: 1_000_000_000,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            pending_rewards: 0,
            rewards_last_epoch: 0,
            self_report_count: 0,
            commission_bps: 1_000,
            pending_commission_bps: None,
            pending_commission_effective_epoch: None,
            min_delegation_spark: 1,
            auto_delegate_to: None,
            network_addr: None,
            network_addr_last_updated_epoch: None,
            cold_hybrid_classical_pk: Some(vote_public.classical.0),
            cold_hybrid_pq_pk: Some(vote_public.pq.0),
            cold_key_version: 1,
            cold_nonce: 0,
        }
    }

    fn setup() -> (ChainState, HybridKeypair, Bytes32, Bytes32) {
        let owner_keys = keypair(9);
        let owner_pubkey = wire_pubkey(&owner_keys);
        let owner_id = owner_pubkey.identity_id();
        let validator_id = id(7);
        let mut state = ChainState::new_genesis();
        state
            .validators
            .upsert(validator(validator_id, &owner_keys))
            .unwrap();
        state
            .delegator_identities
            .insert(owner_id, owner_pubkey.clone());
        state.finalize_genesis().unwrap();
        (state, owner_keys, validator_id, owner_id)
    }

    fn add_deposit_utxo(
        state: &mut ChainState,
        owner_keys: &HybridKeypair,
        amount: u64,
        _fixture_tag: [u8; 32],
        height: u64,
        ordinal: u32,
    ) -> Bytes32 {
        state
            .utxos
            .insert(
                OutputV1 {
                    value_spark: amount,
                    owner_pubkey: wire_pubkey(owner_keys),
                    lock_height: 0,
                },
                height,
                0,
                ordinal,
            )
            .unwrap()
    }

    fn signed_exit(
        keys: &HybridKeypair,
        state: &ChainState,
        position_id: Bytes32,
        owner_id: Bytes32,
        amount: u64,
        nonce: u64,
    ) -> StakingOp {
        let custody = PositionCustodyV1::DelegatorIdentity {
            delegator_id: owner_id,
        };
        let mut op = StakingOp {
            body: StakingOpBody::ExitStakePosition {
                position_id,
                amount_spark: amount,
                custody,
                cold_authorization: None,
            },
            nonce,
            signature: HybridSignature {
                classical_sig: VariableBytes::default(),
                pq_sig: VariableBytes::default(),
            },
        };
        op.signature = wire_signature(&keys.sign(&op.signing_bytes(&state.chain_id)).unwrap());
        op
    }

    #[test]
    fn deposits_aggregate_and_state_commitment_incremental_matches_rebuild() {
        let (mut state, keys, validator_id, owner_id) = setup();
        let custody = PositionCustodyV1::DelegatorIdentity {
            delegator_id: owner_id,
        };
        let first = add_deposit_utxo(&mut state, &keys, 600_000, [1; 32], 10, 0);
        let before_failed_deposit = state.clone();
        set_fail_after_mutation(Some(1));
        assert!(deposit_stake_position(
            &mut state,
            validator_id,
            owner_id,
            custody,
            &wire_pubkey(&keys),
            first,
            11,
        )
        .is_err());
        set_fail_after_mutation(None);
        assert_eq!(state, before_failed_deposit);
        let position_id = deposit_stake_position(
            &mut state,
            validator_id,
            owner_id,
            custody,
            &wire_pubkey(&keys),
            first,
            11,
        )
        .unwrap();
        let second = add_deposit_utxo(&mut state, &keys, 400_000, [2; 32], 12, 0);
        assert_eq!(
            deposit_stake_position(
                &mut state,
                validator_id,
                owner_id,
                custody,
                &wire_pubkey(&keys),
                second,
                13,
            )
            .unwrap(),
            position_id
        );
        let active = state
            .stake_positions
            .get(&position_id)
            .unwrap()
            .active
            .unwrap();
        assert_eq!(active.principal_spark, 1_000_000);
        assert_eq!(
            (
                active.first_contribution_height,
                active.last_contribution_height
            ),
            (11, 13)
        );
        let incremental = state.state_commitment_v2.as_ref().unwrap().root();
        state.rebuild_state_commitment_v2(13);
        assert_eq!(
            state.state_commitment_v2.as_ref().unwrap().root(),
            incremental
        );
    }

    #[test]
    fn repeated_deposits_consolidate_without_principal_drift_at_position_cap_boundaries() {
        let (mut state, keys, validator_id, owner_id) = setup();
        let custody = PositionCustodyV1::DelegatorIdentity {
            delegator_id: owner_id,
        };
        let deposits = 128u32;
        for ordinal in 0..deposits {
            let amount = DUST_LIMIT_SPARK + u64::from(ordinal);
            let blinding = [ordinal as u8; 32];
            let input = add_deposit_utxo(
                &mut state,
                &keys,
                amount,
                blinding,
                100 + u64::from(ordinal),
                ordinal,
            );
            deposit_stake_position(
                &mut state,
                validator_id,
                owner_id,
                custody,
                &wire_pubkey(&keys),
                input,
                100 + u64::from(ordinal),
            )
            .unwrap();
        }
        let owner_position_id = derive_position_id(validator_id, owner_id, custody);
        let expected = u64::from(deposits) * DUST_LIMIT_SPARK
            + u64::from(deposits) * (u64::from(deposits) - 1) / 2;
        assert_eq!(
            state
                .stake_positions
                .get(&owner_position_id)
                .unwrap()
                .active
                .unwrap()
                .principal_spark,
            expected
        );

        let mut usage = CapacityUsage {
            positions_total: MAX_STAKE_POSITIONS_TOTAL - 1,
            positions_validator: MAX_STAKE_POSITIONS_PER_VALIDATOR - 1,
            active_positions_total: MAX_STAKE_POSITIONS_TOTAL - 1,
            active_positions_validator: MAX_STAKE_POSITIONS_PER_VALIDATOR - 1,
            tranches_total: 0,
            tranches_validator: 0,
            tranches_position: 0,
        };
        assert!(preflight_deposit_usage(usage).is_ok());
        usage.positions_validator = MAX_STAKE_POSITIONS_PER_VALIDATOR;
        assert!(preflight_deposit_usage(usage).is_err());
        usage.positions_validator = MAX_STAKE_POSITIONS_PER_VALIDATOR - 1;
        usage.positions_total = MAX_STAKE_POSITIONS_TOTAL;
        assert!(preflight_deposit_usage(usage).is_err());
    }

    #[test]
    fn partial_exit_fragmentation_reserves_final_exit_and_never_truncates() {
        let (mut state, keys, validator_id, owner_id) = setup();
        let custody = PositionCustodyV1::DelegatorIdentity {
            delegator_id: owner_id,
        };
        let input = add_deposit_utxo(&mut state, &keys, 6_400_000, [0xA1; 32], 10, 0);
        let position_id = deposit_stake_position(
            &mut state,
            validator_id,
            owner_id,
            custody,
            &wire_pubkey(&keys),
            input,
            11,
        )
        .unwrap();
        for nonce in 1..MAX_TRANCHES_PER_POSITION as u64 {
            let intent = signed_exit(&keys, &state, position_id, owner_id, 100_000, nonce);
            exit_stake_position(&mut state, &intent, 100 + nonce).unwrap();
        }
        assert_eq!(
            state.tranche_ids_for_position(&position_id).len(),
            MAX_TRANCHES_PER_POSITION - 1
        );
        let before_rejected = state.clone();
        let partial = signed_exit(
            &keys,
            &state,
            position_id,
            owner_id,
            50_000,
            MAX_TRANCHES_PER_POSITION as u64,
        );
        assert!(exit_stake_position(&mut state, &partial, 200).is_err());
        assert_eq!(state, before_rejected);

        let remaining = state
            .stake_positions
            .get(&position_id)
            .unwrap()
            .active
            .unwrap()
            .principal_spark;
        let full = signed_exit(
            &keys,
            &state,
            position_id,
            owner_id,
            remaining,
            MAX_TRANCHES_PER_POSITION as u64,
        );
        exit_stake_position(&mut state, &full, 201).unwrap();
        assert_eq!(
            state.tranche_ids_for_position(&position_id).len(),
            MAX_TRANCHES_PER_POSITION
        );
        assert!(state
            .stake_positions
            .get(&position_id)
            .unwrap()
            .active
            .is_none());
    }

    #[test]
    fn partial_and_full_exits_create_immutable_precise_tranches_then_refund() {
        let (mut state, keys, validator_id, owner_id) = setup();
        let custody = PositionCustodyV1::DelegatorIdentity {
            delegator_id: owner_id,
        };
        let input = add_deposit_utxo(&mut state, &keys, 1_000_000, [3; 32], 20, 0);
        state.total_supply = accounted_value(&state);
        let conserved = state.total_supply;
        let position_id = deposit_stake_position(
            &mut state,
            validator_id,
            owner_id,
            custody,
            &wire_pubkey(&keys),
            input,
            21,
        )
        .unwrap();
        assert_eq!(accounted_value(&state), conserved);
        let first_intent = signed_exit(&keys, &state, position_id, owner_id, 400_000, 1);
        let first = exit_stake_position(&mut state, &first_intent, 100).unwrap();
        assert_eq!(accounted_value(&state), conserved);
        let frozen = state.unbonding_tranches.get(&first).unwrap().clone();
        assert_eq!(
            state
                .stake_positions
                .get(&position_id)
                .unwrap()
                .active
                .unwrap()
                .principal_spark,
            600_000
        );
        let second_intent = signed_exit(&keys, &state, position_id, owner_id, 600_000, 2);
        let second = exit_stake_position(&mut state, &second_intent, 101).unwrap();
        assert_eq!(accounted_value(&state), conserved);
        assert_eq!(state.unbonding_tranches.get(&first).unwrap(), &frozen);
        assert!(state
            .stake_positions
            .get(&position_id)
            .unwrap()
            .active
            .is_none());
        let mut expected_ids = vec![first, second];
        expected_ids.sort();
        assert_eq!(state.tranche_ids_for_position(&position_id), expected_ids);

        let end_epoch = match frozen.timing {
            UnbondingTimingV1::HeightPrecise { end_epoch, .. } => end_epoch,
        };
        let release_height = end_epoch * indra_core::types::primitives::EPOCH_DURATION_BLOCKS;
        let before_failed_release = state.clone();
        set_fail_after_mutation(None);
        let mut successful_release = state.clone();
        release_matured_position_tranches(&mut successful_release, release_height).unwrap();
        let release_mutations = crate::txn::mutation_count();
        assert!(release_mutations >= 4);
        for failpoint in 1..=release_mutations {
            set_fail_after_mutation(Some(failpoint));
            let mut candidate = before_failed_release.clone();
            assert!(release_matured_position_tranches(&mut candidate, release_height).is_err());
            assert_eq!(
                candidate.encode_to_vec(),
                before_failed_release.encode_to_vec()
            );
            assert_eq!(
                compute_state_root(&candidate),
                compute_state_root(&before_failed_release)
            );
        }
        set_fail_after_mutation(None);
        assert_eq!(state.encode_to_vec(), before_failed_release.encode_to_vec());
        let outputs = release_matured_position_tranches(&mut state, release_height).unwrap();
        assert_eq!(accounted_value(&state), conserved);
        assert_eq!(outputs.len(), 2);
        assert!(state.stake_positions.get(&position_id).is_none());
        assert!(state.unbonding_tranches.is_empty());
        let released = outputs
            .iter()
            .map(|id| state.utxos.get(id).unwrap().output.value_spark)
            .sum::<u64>();
        assert_eq!(released, 1_000_000);
    }

    #[test]
    fn failed_multi_mutation_exit_rolls_back_state_and_root() {
        let (mut state, keys, validator_id, owner_id) = setup();
        let custody = PositionCustodyV1::DelegatorIdentity {
            delegator_id: owner_id,
        };
        let input = add_deposit_utxo(&mut state, &keys, 1_000_000, [4; 32], 30, 0);
        let position_id = deposit_stake_position(
            &mut state,
            validator_id,
            owner_id,
            custody,
            &wire_pubkey(&keys),
            input,
            31,
        )
        .unwrap();
        let before = state.clone();
        let intent = signed_exit(&keys, &state, position_id, owner_id, 400_000, 1);
        set_fail_after_mutation(Some(2));
        assert!(exit_stake_position(&mut state, &intent, 32).is_err());
        set_fail_after_mutation(None);
        assert_eq!(state, before);
    }

    #[test]
    fn checkpoint_and_two_replays_are_byte_and_root_identical() {
        fn replay() -> ChainState {
            let (mut state, keys, validator_id, owner_id) = setup();
            let custody = PositionCustodyV1::DelegatorIdentity {
                delegator_id: owner_id,
            };
            let input = add_deposit_utxo(&mut state, &keys, 800_000, [5; 32], 40, 0);
            let position_id = deposit_stake_position(
                &mut state,
                validator_id,
                owner_id,
                custody,
                &wire_pubkey(&keys),
                input,
                41,
            )
            .unwrap();
            let intent = signed_exit(&keys, &state, position_id, owner_id, 200_000, 1);
            exit_stake_position(&mut state, &intent, 42).unwrap();
            state
        }
        let first = replay();
        let second = replay();
        assert_eq!(first.encode_to_vec(), second.encode_to_vec());
        assert_eq!(compute_state_root(&first), compute_state_root(&second));
        let decoded = ChainState::decode_exact(&first.encode_to_vec()).unwrap();
        assert_eq!(decoded.stake_positions, first.stake_positions);
        assert_eq!(decoded.unbonding_tranches, first.unbonding_tranches);
        assert_eq!(decoded.position_tranche_index, first.position_tranche_index);
    }

    #[test]
    fn all_five_cap_boundaries_and_reservation_are_exact() {
        let base = CapacityUsage {
            positions_total: 0,
            positions_validator: 0,
            active_positions_total: 0,
            active_positions_validator: 0,
            tranches_total: 0,
            tranches_validator: 0,
            tranches_position: 0,
        };
        let mut deposit = base;
        deposit.positions_total = MAX_STAKE_POSITIONS_TOTAL - 1;
        deposit.positions_validator = MAX_STAKE_POSITIONS_PER_VALIDATOR - 1;
        deposit.active_positions_total = MAX_STAKE_POSITIONS_TOTAL - 1;
        deposit.active_positions_validator = MAX_STAKE_POSITIONS_PER_VALIDATOR - 1;
        assert!(
            preflight_deposit_usage(deposit).is_ok(),
            "one new position reaches both exact caps"
        );
        deposit.positions_total = MAX_STAKE_POSITIONS_TOTAL;
        assert!(
            preflight_deposit_usage(deposit).is_err(),
            "global position cap rejects one over"
        );
        deposit.positions_total = MAX_STAKE_POSITIONS_TOTAL - 1;
        deposit.positions_validator = MAX_STAKE_POSITIONS_PER_VALIDATOR;
        assert!(
            preflight_deposit_usage(deposit).is_err(),
            "per-validator position cap rejects one over"
        );

        let mut exit = base;
        exit.active_positions_total = 1;
        exit.active_positions_validator = 1;
        exit.tranches_position = MAX_TRANCHES_PER_POSITION - 1;
        exit.tranches_total = MAX_TRANCHES_TOTAL - 1;
        exit.tranches_validator = MAX_TRANCHES_PER_VALIDATOR - 1;
        assert!(
            preflight_exit_usage(exit, true).is_ok(),
            "full exit reaches every exact tranche cap"
        );
        let mut over = exit;
        over.tranches_position = MAX_TRANCHES_PER_POSITION;
        assert!(
            preflight_exit_usage(over, true).is_err(),
            "per-position cap rejects one over"
        );
        let mut partial_position = base;
        partial_position.active_positions_total = 1;
        partial_position.active_positions_validator = 1;
        partial_position.tranches_position = MAX_TRANCHES_PER_POSITION - 2;
        assert!(
            preflight_exit_usage(partial_position, false).is_ok(),
            "partial exit may use the penultimate slot"
        );
        partial_position.tranches_position = MAX_TRANCHES_PER_POSITION - 1;
        assert!(
            preflight_exit_usage(partial_position, false).is_err(),
            "partial exit cannot consume the position's final-exit slot"
        );
        over = exit;
        over.tranches_total = MAX_TRANCHES_TOTAL;
        assert!(
            preflight_exit_usage(over, true).is_err(),
            "global tranche cap rejects one over"
        );
        over = exit;
        over.tranches_validator = MAX_TRANCHES_PER_VALIDATOR;
        assert!(
            preflight_exit_usage(over, true).is_err(),
            "per-validator tranche cap rejects one over"
        );
        assert!(
            preflight_exit_usage(exit, false).is_err(),
            "partial exit cannot consume reserved final-exit slot"
        );
    }
}
