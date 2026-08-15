//! Isolated tranche-native eviction planning and validation.

use std::collections::{BTreeMap, BTreeSet};

use indra_core::types::{
    primitives::{Bytes32, EPOCH_DURATION_BLOCKS, SLASH_EVIDENCE_WINDOW_EPOCHS},
    stake_position::{
        eviction_tranche_creation_id_v1, PositionCustodyV1, StakePositionV1, UnbondingTimingV1,
        UnbondingTrancheV1,
    },
};

use crate::{
    error::{StateError, StateResult},
    validator::{
        EvictedColdCustodyV1, EvictedValidatorTombstoneV2,
        MAX_ATOMIC_EVICTION_POSITION_CONVERSIONS, MAX_RETAINED_POSITION_REFERENCES_PER_TOMBSTONE,
        MAX_RETAINED_TRANCHE_REFERENCES_PER_TOMBSTONE, MAX_TOTAL_RETAINED_POSITION_REFERENCES,
        MAX_TOTAL_RETAINED_TRANCHE_REFERENCES,
    },
};

/// Fully preflighted atomic mutation returned by the isolated eviction planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrancheEvictionPlanV2 {
    /// Updated positions, ordered by canonical ID.
    pub positions: BTreeMap<Bytes32, StakePositionV1>,
    /// Existing plus newly-created tranches, ordered by canonical ID.
    pub tranches: BTreeMap<Bytes32, UnbondingTrancheV1>,
    /// Canonical retained record committed with the mutation.
    pub tombstone: EvictedValidatorTombstoneV2,
}

/// Historical keys and custody copied from the live validator before removal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TombstoneAuthorityV2 {
    /// Ed25519 vote key.
    pub classical_vote_pk: [u8; 32],
    /// ML-DSA-87 vote key.
    pub pq_vote_pk: [u8; indra_crypto::PQ_PK_BYTES],
    /// VRF key.
    pub vrf_pk: [u8; 32],
    /// Cold custody, required when self-owned economic records exist.
    pub cold_custody: Option<EvictedColdCustodyV1>,
    /// Canonical slash offense already applied before eviction, if any.
    pub slashed_offense_id: Option<Bytes32>,
}

/// Return the first ranked victim whose complete eviction is representable.
///
/// Capacity failures fall through; structural failures remain fatal.
pub fn first_representable_tranche_eviction_v2(
    chain_id: &str,
    eviction_height: u64,
    candidates: &[(Bytes32, TombstoneAuthorityV2)],
    positions: &BTreeMap<Bytes32, StakePositionV1>,
    tranches: &BTreeMap<Bytes32, UnbondingTrancheV1>,
) -> StateResult<(Bytes32, TrancheEvictionPlanV2)> {
    for (validator_id, authority) in candidates {
        match plan_tranche_native_eviction_v2(
            chain_id,
            *validator_id,
            eviction_height,
            authority.clone(),
            positions,
            tranches,
        ) {
            Ok(plan) => return Ok((*validator_id, plan)),
            Err(StateError::TombstoneCapacityExceeded) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(StateError::TombstoneCapacityExceeded)
}

/// Build a complete atomic eviction plan without mutating its inputs.
pub fn plan_tranche_native_eviction_v2(
    chain_id: &str,
    validator_id: Bytes32,
    eviction_height: u64,
    authority: TombstoneAuthorityV2,
    positions: &BTreeMap<Bytes32, StakePositionV1>,
    tranches: &BTreeMap<Bytes32, UnbondingTrancheV1>,
) -> StateResult<TrancheEvictionPlanV2> {
    let mut owned_positions = positions
        .values()
        .filter(|position| position.validator_id == validator_id)
        .cloned()
        .collect::<Vec<_>>();
    for position in &owned_positions {
        position.validate().map_err(invalid)?;
    }
    owned_positions.sort_by_key(|position| position.position_id);
    if owned_positions.is_empty()
        || owned_positions.len() > MAX_RETAINED_POSITION_REFERENCES_PER_TOMBSTONE
    {
        return Err(StateError::TombstoneCapacityExceeded);
    }
    let active_count = owned_positions
        .iter()
        .filter(|position| position.active.is_some())
        .count();
    if active_count > MAX_ATOMIC_EVICTION_POSITION_CONVERSIONS {
        return Err(StateError::TombstoneCapacityExceeded);
    }
    let position_ids = owned_positions
        .iter()
        .map(|position| position.position_id)
        .collect::<BTreeSet<_>>();
    let mut next_tranches = tranches.clone();
    for position in &mut owned_positions {
        let Some(active) = position.active.take() else {
            continue;
        };
        let timing = UnbondingTimingV1::height_precise(eviction_height).map_err(invalid)?;
        let creation = eviction_tranche_creation_id_v1(
            chain_id,
            validator_id,
            eviction_height,
            position.position_id,
            active.principal_spark,
        )
        .map_err(invalid)?;
        let tranche = UnbondingTrancheV1::new(
            position.position_id,
            active.principal_spark,
            timing,
            position.custody,
            creation,
            0,
        )
        .map_err(invalid)?;
        if next_tranches.insert(tranche.tranche_id, tranche).is_some() {
            return Err(StateError::InvariantViolation {
                message: "duplicate forced eviction tranche",
            });
        }
    }
    let mut retained_tranche_ids = next_tranches
        .values()
        .filter(|tranche| position_ids.contains(&tranche.position_id))
        .map(|tranche| tranche.tranche_id)
        .collect::<Vec<_>>();
    retained_tranche_ids.sort();
    if retained_tranche_ids.len() > MAX_RETAINED_TRANCHE_REFERENCES_PER_TOMBSTONE {
        return Err(StateError::TombstoneCapacityExceeded);
    }
    let requires_cold = owned_positions.iter().any(|position| matches!(
        position.custody, PositionCustodyV1::ValidatorColdIdentity { validator_id: id } if id == validator_id
    ));
    if requires_cold && authority.cold_custody.is_none() {
        return Err(StateError::TombstoneCapacityExceeded);
    }
    let tombstone = EvictedValidatorTombstoneV2 {
        validator_id,
        eviction_height,
        eviction_epoch: eviction_height / EPOCH_DURATION_BLOCKS,
        last_classical_vote_pk: authority.classical_vote_pk,
        last_pq_vote_pk: authority.pq_vote_pk,
        last_vrf_pk: authority.vrf_pk,
        cold_custody: authority.cold_custody,
        slashed_offense_id: authority.slashed_offense_id,
        retained_position_ids: owned_positions
            .iter()
            .map(|position| position.position_id)
            .collect(),
        retained_tranche_ids,
    };
    tombstone.validate(true).map_err(invalid)?;
    let mut next_positions = positions.clone();
    for position in owned_positions {
        next_positions.insert(position.position_id, position);
    }
    validate_tombstone_references_v2(&tombstone, &next_positions, &next_tranches, false)?;
    Ok(TrancheEvictionPlanV2 {
        positions: next_positions,
        tranches: next_tranches,
        tombstone,
    })
}

/// Validate both directions of one tombstone's economic references.
pub fn validate_tombstone_references_v2(
    tombstone: &EvictedValidatorTombstoneV2,
    positions: &BTreeMap<Bytes32, StakePositionV1>,
    tranches: &BTreeMap<Bytes32, UnbondingTrancheV1>,
    validator_is_live: bool,
) -> StateResult<()> {
    tombstone.validate(false).map_err(invalid)?;
    if validator_is_live {
        return Err(StateError::InvariantViolation {
            message: "tombstoned validator remains live",
        });
    }
    let position_ids = tombstone
        .retained_position_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    for id in &tombstone.retained_position_ids {
        let position = positions.get(id).ok_or(StateError::InvariantViolation {
            message: "tombstone references missing position",
        })?;
        if position.validator_id != tombstone.validator_id {
            return Err(StateError::InvariantViolation {
                message: "tombstone position belongs to another validator",
            });
        }
    }
    for id in &tombstone.retained_tranche_ids {
        let tranche = tranches.get(id).ok_or(StateError::InvariantViolation {
            message: "tombstone references missing tranche",
        })?;
        if !position_ids.contains(&tranche.position_id) {
            return Err(StateError::InvariantViolation {
                message: "tombstone tranche points outside retained positions",
            });
        }
        let position =
            positions
                .get(&tranche.position_id)
                .ok_or(StateError::InvariantViolation {
                    message: "missing tranche position",
                })?;
        if tranche.custody != position.custody {
            return Err(StateError::InvariantViolation {
                message: "tombstone tranche custody mismatch",
            });
        }
    }
    for position in positions
        .values()
        .filter(|position| position.validator_id == tombstone.validator_id)
    {
        if !position_ids.contains(&position.position_id) {
            return Err(StateError::InvariantViolation {
                message: "tombstone omits owned position",
            });
        }
    }
    let tranche_ids = tombstone
        .retained_tranche_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    for tranche in tranches.values() {
        if position_ids.contains(&tranche.position_id) && !tranche_ids.contains(&tranche.tranche_id)
        {
            return Err(StateError::InvariantViolation {
                message: "tombstone omits owned tranche",
            });
        }
    }
    let requires_cold = tombstone.retained_position_ids.iter().any(|id| {
        positions.get(id).is_some_and(|position| {
            matches!(position.custody,
                PositionCustodyV1::ValidatorColdIdentity { validator_id }
                    if validator_id == tombstone.validator_id)
        })
    });
    if requires_cold && tombstone.cold_custody.is_none() {
        return Err(StateError::InvariantViolation {
            message: "tombstone omits required cold custody",
        });
    }
    Ok(())
}

/// Validate aggregate bounds, reference uniqueness, and live-set separation.
pub fn validate_all_tombstone_references_v2(
    tombstones: &BTreeMap<Bytes32, EvictedValidatorTombstoneV2>,
    positions: &BTreeMap<Bytes32, StakePositionV1>,
    tranches: &BTreeMap<Bytes32, UnbondingTrancheV1>,
    live_validator_ids: &BTreeSet<Bytes32>,
) -> StateResult<()> {
    let mut owned_positions = BTreeSet::new();
    let mut owned_tranches = BTreeSet::new();
    for (validator_id, tombstone) in tombstones {
        if *validator_id != tombstone.validator_id {
            return Err(StateError::InvariantViolation {
                message: "tombstone map key mismatch",
            });
        }
        validate_tombstone_references_v2(
            tombstone,
            positions,
            tranches,
            live_validator_ids.contains(validator_id),
        )?;
        for id in &tombstone.retained_position_ids {
            if !owned_positions.insert(*id) {
                return Err(StateError::InvariantViolation {
                    message: "position retained by multiple tombstones",
                });
            }
        }
        for id in &tombstone.retained_tranche_ids {
            if !owned_tranches.insert(*id) {
                return Err(StateError::InvariantViolation {
                    message: "tranche retained by multiple tombstones",
                });
            }
        }
    }
    if owned_positions.len() > MAX_TOTAL_RETAINED_POSITION_REFERENCES
        || owned_tranches.len() > MAX_TOTAL_RETAINED_TRANCHE_REFERENCES
    {
        return Err(StateError::TombstoneCapacityExceeded);
    }
    Ok(())
}

/// Return self-principal records slashable for an infraction height.
pub fn slashable_self_targets_v2(
    tombstone: &EvictedValidatorTombstoneV2,
    positions: &BTreeMap<Bytes32, StakePositionV1>,
    tranches: &BTreeMap<Bytes32, UnbondingTrancheV1>,
    infraction_height: u64,
) -> StateResult<(Vec<Bytes32>, Vec<Bytes32>)> {
    validate_tombstone_references_v2(tombstone, positions, tranches, false)?;
    let self_positions = tombstone.retained_position_ids.iter().filter_map(|id| {
        positions.get(id).filter(|position| matches!(position.custody,
            PositionCustodyV1::ValidatorColdIdentity { validator_id } if validator_id == tombstone.validator_id)
        ).and_then(|position| position.active.map(|_| *id))
    }).collect();
    let self_tranches = tombstone.retained_tranche_ids.iter().filter_map(|id| {
        tranches.get(id).filter(|tranche| matches!(tranche.custody,
            PositionCustodyV1::ValidatorColdIdentity { validator_id } if validator_id == tombstone.validator_id)
            && tranche.timing.start_height() >= infraction_height).map(|_| *id)
    }).collect();
    Ok((self_positions, self_tranches))
}

/// Remove one canonically cleared tranche reference and optionally its empty position anchor.
pub fn clear_matured_tranche_reference_v2(
    tombstone: &mut EvictedValidatorTombstoneV2,
    tranche_id: Bytes32,
    position_id: Bytes32,
    position_is_empty: bool,
    position_has_other_retained_tranches: bool,
) -> StateResult<()> {
    if position_is_empty && position_has_other_retained_tranches {
        return Err(StateError::InvariantViolation {
            message: "cannot clear position while retained tranches remain",
        });
    }
    let before = tombstone.retained_tranche_ids.len();
    tombstone
        .retained_tranche_ids
        .retain(|id| *id != tranche_id);
    if tombstone.retained_tranche_ids.len() + 1 != before {
        return Err(StateError::InvariantViolation {
            message: "cleared tranche was not uniquely retained",
        });
    }
    if position_is_empty {
        tombstone
            .retained_position_ids
            .retain(|id| *id != position_id);
    }
    tombstone.validate(false).map_err(invalid)
}

/// Tombstones prune only after all economics clear and the evidence window expires.
pub fn tombstone_is_prunable_v2(
    tombstone: &EvictedValidatorTombstoneV2,
    current_epoch: u64,
) -> bool {
    tombstone.retained_position_ids.is_empty()
        && tombstone.retained_tranche_ids.is_empty()
        && current_epoch
            > tombstone
                .eviction_epoch
                .saturating_add(SLASH_EVIDENCE_WINDOW_EPOCHS)
}

fn invalid(error: indra_core::error::IndraError) -> StateError {
    StateError::InvalidStakingOp(error.to_string())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_commitment::{
        evicted_validator_tombstone_v3_key, evicted_validator_tombstone_v3_value_hash,
    };
    use indra_core::{
        codec::{Decode, Encode},
        types::stake_position::ActiveStakeAggregateV1,
    };
    use indra_crypto::PQ_PK_BYTES;

    fn id(byte: u8) -> Bytes32 {
        Bytes32([byte; 32])
    }

    fn numbered_id(number: u64) -> Bytes32 {
        let mut value = [0u8; 32];
        value[..8].copy_from_slice(&number.to_le_bytes());
        Bytes32(value)
    }

    fn position(validator: u8, owner: u8, principal: u64, self_owned: bool) -> StakePositionV1 {
        let validator_id = id(validator);
        let owner_id = if self_owned { validator_id } else { id(owner) };
        let custody = if self_owned {
            PositionCustodyV1::ValidatorColdIdentity { validator_id }
        } else {
            PositionCustodyV1::DelegatorIdentity {
                delegator_id: owner_id,
            }
        };
        StakePositionV1::new(
            validator_id,
            owner_id,
            custody,
            Some(ActiveStakeAggregateV1::new(principal, 1, 1).unwrap()),
            7,
            2,
        )
        .unwrap()
    }

    fn authority(with_cold: bool) -> TombstoneAuthorityV2 {
        TombstoneAuthorityV2 {
            classical_vote_pk: [3; 32],
            pq_vote_pk: [4; PQ_PK_BYTES],
            vrf_pk: [5; 32],
            cold_custody: with_cold.then_some(EvictedColdCustodyV1 {
                classical_pk: [6; 32],
                pq_pk: [7; PQ_PK_BYTES],
                key_version: 1,
            }),
            slashed_offense_id: None,
        }
    }

    fn maps() -> (
        BTreeMap<Bytes32, StakePositionV1>,
        BTreeMap<Bytes32, UnbondingTrancheV1>,
    ) {
        let self_position = position(1, 1, 60, true);
        let delegated = position(1, 2, 40, false);
        (
            [
                (self_position.position_id, self_position),
                (delegated.position_id, delegated),
            ]
            .into_iter()
            .collect(),
            BTreeMap::new(),
        )
    }

    #[test]
    fn eviction_is_complete_deterministic_and_preserves_rewards() {
        let (positions, tranches) = maps();
        let before = positions.clone();
        let first = plan_tranche_native_eviction_v2(
            "chain",
            id(1),
            300,
            authority(true),
            &positions,
            &tranches,
        )
        .unwrap();
        let second = plan_tranche_native_eviction_v2(
            "chain",
            id(1),
            300,
            authority(true),
            &positions,
            &tranches,
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(positions, before, "planning must not mutate its inputs");
        assert_eq!(first.tombstone.retained_position_ids.len(), 2);
        assert_eq!(first.tombstone.retained_tranche_ids.len(), 2);
        assert!(first.positions.values().all(|p| p.active.is_none()));
        assert!(first
            .positions
            .values()
            .all(|p| p.pending_rewards_spark == 7));
        assert!(first
            .tranches
            .values()
            .all(|t| { t.timing.start_height() == 300 && t.creation_ordinal == 0 }));
        validate_tombstone_references_v2(
            &first.tombstone,
            &first.positions,
            &first.tranches,
            false,
        )
        .unwrap();
        let bytes = first.tombstone.encode_to_vec();
        assert_eq!(bytes, second.tombstone.encode_to_vec());
    }

    #[test]
    fn reference_validation_fails_closed() {
        let (positions, tranches) = maps();
        let plan = plan_tranche_native_eviction_v2(
            "chain",
            id(1),
            300,
            authority(true),
            &positions,
            &tranches,
        )
        .unwrap();
        assert!(validate_tombstone_references_v2(
            &plan.tombstone,
            &plan.positions,
            &plan.tranches,
            true
        )
        .is_err());

        let mut omitted = plan.tombstone.clone();
        omitted.retained_tranche_ids.pop();
        assert!(
            validate_tombstone_references_v2(&omitted, &plan.positions, &plan.tranches, false)
                .is_err()
        );

        let mut duplicate = plan.tombstone.clone();
        duplicate
            .retained_position_ids
            .push(duplicate.retained_position_ids[0]);
        assert!(duplicate.validate(false).is_err());

        let mut no_cold = plan.tombstone.clone();
        no_cold.cold_custody = None;
        assert!(
            validate_tombstone_references_v2(&no_cold, &plan.positions, &plan.tranches, false)
                .is_err()
        );
    }

    #[test]
    fn slash_boundary_and_pruning_are_exact() {
        let (positions, tranches) = maps();
        let mut plan = plan_tranche_native_eviction_v2(
            "chain",
            id(1),
            300,
            authority(true),
            &positions,
            &tranches,
        )
        .unwrap();
        let (_, at_height) =
            slashable_self_targets_v2(&plan.tombstone, &plan.positions, &plan.tranches, 300)
                .unwrap();
        assert_eq!(at_height.len(), 1);
        let (_, after_height) =
            slashable_self_targets_v2(&plan.tombstone, &plan.positions, &plan.tranches, 301)
                .unwrap();
        assert!(after_height.is_empty());

        plan.tombstone.retained_tranche_ids.clear();
        plan.tombstone.retained_position_ids.clear();
        assert!(!tombstone_is_prunable_v2(
            &plan.tombstone,
            plan.tombstone.eviction_epoch + SLASH_EVIDENCE_WINDOW_EPOCHS
        ));
        assert!(tombstone_is_prunable_v2(
            &plan.tombstone,
            plan.tombstone.eviction_epoch + SLASH_EVIDENCE_WINDOW_EPOCHS + 1
        ));
    }

    #[test]
    fn ranked_fallback_skips_only_capacity_failures() {
        let (mut positions, tranches) = maps();
        // Candidate 9 has no representable economic record; candidate 1 does.
        let candidates = vec![(id(9), authority(false)), (id(1), authority(true))];
        let (selected, _) = first_representable_tranche_eviction_v2(
            "chain",
            300,
            &candidates,
            &positions,
            &tranches,
        )
        .unwrap();
        assert_eq!(selected, id(1));

        // A malformed owned position is structural, so it must not fall through.
        let mut malformed = position(9, 9, 1, true);
        malformed.position_id = id(99);
        positions.insert(malformed.position_id, malformed);
        assert!(matches!(
            first_representable_tranche_eviction_v2(
                "chain",
                300,
                &candidates,
                &positions,
                &tranches,
            ),
            Err(StateError::InvalidStakingOp(_)) | Err(StateError::InvariantViolation { .. })
        ));
    }

    #[test]
    fn tombstone_encoding_rejects_unknown_marker() {
        let (positions, tranches) = maps();
        let plan = plan_tranche_native_eviction_v2(
            "chain",
            id(1),
            300,
            authority(true),
            &positions,
            &tranches,
        )
        .unwrap();
        let mut bytes = plan.tombstone.encode_to_vec();
        bytes[0] = 2;
        assert!(EvictedValidatorTombstoneV2::decode_exact(&bytes).is_err());
    }

    #[test]
    fn exact_reference_caps_and_aggregate_caps_are_enforced() {
        let mut base = EvictedValidatorTombstoneV2 {
            validator_id: id(1),
            eviction_height: 300,
            eviction_epoch: 1,
            last_classical_vote_pk: [3; 32],
            last_pq_vote_pk: [4; PQ_PK_BYTES],
            last_vrf_pk: [5; 32],
            cold_custody: None,
            slashed_offense_id: None,
            retained_position_ids: (0..MAX_RETAINED_POSITION_REFERENCES_PER_TOMBSTONE as u64)
                .map(numbered_id)
                .collect(),
            retained_tranche_ids: (10_000
                ..10_000 + MAX_RETAINED_TRANCHE_REFERENCES_PER_TOMBSTONE as u64)
                .map(numbered_id)
                .collect(),
        };
        base.retained_position_ids.sort();
        base.retained_tranche_ids.sort();
        assert!(base.validate(true).is_ok());
        let mut too_many_positions = base.clone();
        too_many_positions
            .retained_position_ids
            .push(numbered_id(9_999));
        too_many_positions.retained_position_ids.sort();
        assert!(too_many_positions.validate(true).is_err());
        let mut too_many_tranches = base;
        too_many_tranches
            .retained_tranche_ids
            .push(numbered_id(20_000));
        too_many_tranches.retained_tranche_ids.sort();
        assert!(too_many_tranches.validate(true).is_err());
        assert_eq!(MAX_TOTAL_RETAINED_POSITION_REFERENCES, 104_096);
        assert_eq!(MAX_TOTAL_RETAINED_TRANCHE_REFERENCES, 104_096);
    }

    #[test]
    fn maturity_cleanup_keeps_empty_tombstone_until_window_expires() {
        let (positions, tranches) = maps();
        let mut plan = plan_tranche_native_eviction_v2(
            "chain",
            id(1),
            300,
            authority(true),
            &positions,
            &tranches,
        )
        .unwrap();
        let tranche_id = plan.tombstone.retained_tranche_ids[0];
        let position_id = plan.tranches[&tranche_id].position_id;
        assert!(clear_matured_tranche_reference_v2(
            &mut plan.tombstone,
            tranche_id,
            position_id,
            true,
            true,
        )
        .is_err());
        while let Some(tranche_id) = plan.tombstone.retained_tranche_ids.first().copied() {
            let position_id = plan.tranches[&tranche_id].position_id;
            let has_other = plan.tombstone.retained_tranche_ids.iter().any(|other| {
                *other != tranche_id && plan.tranches[other].position_id == position_id
            });
            clear_matured_tranche_reference_v2(
                &mut plan.tombstone,
                tranche_id,
                position_id,
                true,
                has_other,
            )
            .unwrap();
        }
        assert!(plan.tombstone.retained_position_ids.is_empty());
        assert!(!tombstone_is_prunable_v2(&plan.tombstone, 501));
        assert!(tombstone_is_prunable_v2(&plan.tombstone, 502));
    }

    #[test]
    fn tombstone_commitment_is_deterministic_and_field_sensitive() {
        let (positions, tranches) = maps();
        let plan = plan_tranche_native_eviction_v2(
            "chain",
            id(1),
            300,
            authority(true),
            &positions,
            &tranches,
        )
        .unwrap();
        let key = evicted_validator_tombstone_v3_key(&plan.tombstone.validator_id);
        assert_eq!(key, evicted_validator_tombstone_v3_key(&id(1)));
        assert_ne!(key, evicted_validator_tombstone_v3_key(&id(2)));
        let hash = evicted_validator_tombstone_v3_value_hash(&plan.tombstone);
        let mut changed = plan.tombstone.clone();
        changed.eviction_height = 600;
        changed.eviction_epoch = 2;
        assert_ne!(hash, evicted_validator_tombstone_v3_value_hash(&changed));
        let mut slashed = plan.tombstone.clone();
        slashed.slashed_offense_id = Some(id(0xA5));
        assert_ne!(hash, evicted_validator_tombstone_v3_value_hash(&slashed));
    }
}
