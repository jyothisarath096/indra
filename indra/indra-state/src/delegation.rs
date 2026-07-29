//! Delegation state transitions.
//!
//! Handles apply_delegate, apply_undelegate, apply_claim_rewards,
//! and apply_set_commission. Called from apply_block when a block
//! contains StakingOp entries.

use indra_core::types::{
    crypto::{ColdHybridPubKey, CommitmentV1, HybridPubKey, HybridSignature},
    primitives::{
        delegator_identity_registry_active, payment_blinding_active,
        registered_validator_cap_active, staking_commitment_proof_required,
        validator_cold_key_enforcement_active, validator_cold_key_enrollment_active,
        validator_network_address_active, Bytes32, VariableBytes, COMMISSION_CHANGE_DELAY_EPOCHS,
        DUST_LIMIT_SPARK, MAX_VALIDATORS, MINIMUM_ACTIVE_SELF_STAKE_SPARK,
        MINIMUM_VALIDATOR_BOND_SPARK, MIN_COMMISSION_BPS, STAKING_REWARD_BLINDING_DOMAIN,
        STAKING_TX_IDX, UNBONDING_PERIOD_EPOCHS,
    },
    staking::{validate_network_addr_string, StakingBondProof, StakingOp, StakingOpBody},
    transaction::OutputV1,
};
use rand::SeedableRng;

use crate::{
    chain::ChainState,
    epoch::epoch_for_height,
    error::{StateError, StateResult},
    identity::{
        resolve_active_validator_cold_pubkey, resolve_and_check_identity,
        resolve_bond_owner_pubkey, IdentityCheckOutcome, IdentityError,
    },
    validator::{
        validate_new_validator_cold_key, validate_validator_cold_key, ColdKeyStatus,
        DelegationReturnEvent, DelegationReturnReason, StakeBondCustodyOwner, StakeBondEntry,
        ValidatorEntry, ValidatorStatus, MAX_ATOMIC_COLD_KEY_MIGRATION_SELF_BONDS,
        MAX_DELEGATORS_PER_VALIDATOR,
    },
};

/// Apply a single staking operation to chain state.
///
/// Called after all transaction validation has passed.
/// Staking ops are applied in block order after UTXO transactions.
pub fn apply_staking_op(
    state: &mut ChainState,
    op: &StakingOp,
    chain_id: &str,
    current_height: u64,
) -> StateResult<()> {
    op.validate_structure_at_height(current_height)
        .map_err(|err| StateError::InvalidStakingOp(err.to_string()))?;
    apply_staking_op_with_identity_activation(
        state,
        op,
        chain_id,
        current_height,
        delegator_identity_registry_active(current_height),
    )
}

pub(crate) fn apply_staking_op_with_identity_activation(
    state: &mut ChainState,
    op: &StakingOp,
    chain_id: &str,
    current_height: u64,
    identity_registry_active: bool,
) -> StateResult<()> {
    if matches!(op.body, StakingOpBody::RegisterPaymentKey { .. })
        && !payment_blinding_active(current_height)
    {
        return Err(StateError::InvalidStakingOp(
            "RegisterPaymentKey is not active before PAYMENT_BLINDING_HEIGHT".into(),
        ));
    }

    if matches!(op.body, StakingOpBody::RotateValidatorColdKey { .. }) {
        return verify_and_apply_rotate_validator_cold_key(state, op, chain_id, current_height);
    }

    let signer_id = op.signer_id();
    let cold_designated = matches!(
        op.body,
        StakingOpBody::ClaimRewards { .. }
            | StakingOpBody::SetCommission { .. }
            | StakingOpBody::SelfStake { .. }
            | StakingOpBody::SelfUnstake { .. }
            | StakingOpBody::SetAutoDelegate { .. }
            | StakingOpBody::RegisterPaymentKey { .. }
    );
    let active_cold_validator = cold_designated
        && state
            .validators
            .get(&signer_id)
            .is_some_and(|validator| validator.cold_key_status == ColdKeyStatus::Active);
    if cold_designated
        && validator_cold_key_enforcement_active(current_height)
        && state
            .validators
            .get(&signer_id)
            .is_some_and(|validator| validator.cold_key_status == ColdKeyStatus::Unenrolled)
    {
        return Err(StateError::InvalidStakingOp(
            "unenrolled validator custody is frozen after VALIDATOR_COLD_KEY_ENFORCEMENT_HEIGHT; complete EnrollValidatorColdKey".into(),
        ));
    }

    if active_cold_validator {
        let authorization = op.cold_authorization().ok_or_else(|| {
            StateError::InvalidStakingOp(
                "active validator cold-designated operation requires cold authorization; hot fallback is prohibited"
                    .into(),
            )
        })?;
        if op.nonce != 0 {
            return Err(StateError::InvalidStakingOp(
                "cold-authorized staking operation outer nonce must be zero".into(),
            ));
        }
        let validator = state
            .validators
            .get(&signer_id)
            .ok_or(StateError::ValidatorNotFound)?;
        if authorization.cold_key_version != validator.cold_key_version {
            return Err(StateError::InvalidStakingOp(format!(
                "cold-key version mismatch: expected {}, got {}",
                validator.cold_key_version, authorization.cold_key_version
            )));
        }
        let expected_cold_nonce = validator
            .cold_nonce
            .checked_add(1)
            .ok_or_else(|| StateError::InvalidStakingOp("validator cold nonce exhausted".into()))?;
        if authorization.cold_nonce != expected_cold_nonce {
            return Err(StateError::StakingNonceInvalid {
                expected: expected_cold_nonce,
                got: authorization.cold_nonce,
            });
        }
        let cold_signing_bytes = op
            .cold_authorization_signing_bytes(chain_id)
            .map_err(|err| StateError::InvalidStakingOp(err.to_string()))?
            .ok_or_else(|| {
                StateError::InvalidStakingOp(
                    "active validator operation is missing canonical cold authorization".into(),
                )
            })?;
        let cold_classical = validator.cold_hybrid_classical_pk.ok_or_else(|| {
            StateError::StakingOpSignatureInvalid {
                reason: "active validator has no classical cold key registered".into(),
            }
        })?;
        let cold_pq = validator.cold_hybrid_pq_pk.as_ref().ok_or_else(|| {
            StateError::StakingOpSignatureInvalid {
                reason: "active validator has no PQ cold key registered".into(),
            }
        })?;
        verify_staking_sig(&cold_signing_bytes, &op.signature, &cold_classical, cold_pq)?;
    } else {
        if op.cold_authorization().is_some() {
            return Err(StateError::InvalidStakingOp(
                "cold authorization is valid only for an Active validator".into(),
            ));
        }
        let expected_nonce = state.staking_nonces.get(&signer_id).copied().unwrap_or(0) + 1;
        if op.nonce != expected_nonce {
            return Err(StateError::StakingNonceInvalid {
                expected: expected_nonce,
                got: op.nonce,
            });
        }
    }

    let signing_bytes = op.signing_bytes(chain_id);
    match &op.body {
        StakingOpBody::SetCommission { validator_id, .. }
        | StakingOpBody::SetAutoDelegate { validator_id, .. }
            if !active_cold_validator =>
        {
            let validator = state
                .validators
                .get(validator_id)
                .ok_or(StateError::ValidatorNotFound)?;
            let classical_pk = validator.hybrid_classical_pk.ok_or_else(|| {
                StateError::StakingOpSignatureInvalid {
                    reason: "validator has no classical key registered".into(),
                }
            })?;
            let pq_pk = validator.hybrid_pq_pk.as_deref().ok_or_else(|| {
                StateError::StakingOpSignatureInvalid {
                    reason: "validator has no PQ key registered".into(),
                }
            })?;
            verify_staking_sig(&signing_bytes, &op.signature, &classical_pk, pq_pk)?;
        }
        StakingOpBody::UpdateNetworkAddress { validator_id, .. } => {
            let validator = state
                .validators
                .get(validator_id)
                .ok_or(StateError::ValidatorNotFound)?;
            let classical_pk = validator.hybrid_classical_pk.ok_or_else(|| {
                StateError::StakingOpSignatureInvalid {
                    reason: "validator has no classical key registered".into(),
                }
            })?;
            let pq_pk = validator.hybrid_pq_pk.as_deref().ok_or_else(|| {
                StateError::StakingOpSignatureInvalid {
                    reason: "validator has no PQ key registered".into(),
                }
            })?;
            verify_staking_sig(&signing_bytes, &op.signature, &classical_pk, pq_pk)?;
        }
        StakingOpBody::Delegate {
            delegator_pubkey, ..
        }
        | StakingOpBody::Undelegate {
            delegator_pubkey, ..
        } => {
            verify_staking_sig(
                &signing_bytes,
                &op.signature,
                &delegator_pubkey.classical_pk.0,
                delegator_pubkey.pq_pk.as_slice(),
            )?;
        }
        StakingOpBody::ClaimRewards {
            delegator_pubkey, ..
        } if !active_cold_validator => {
            verify_staking_sig(
                &signing_bytes,
                &op.signature,
                &delegator_pubkey.classical_pk.0,
                delegator_pubkey.pq_pk.as_slice(),
            )?;
        }
        StakingOpBody::RegisterValidator {
            validator_pubkey,
            cold_pubkey,
            cold_signature,
            ..
        } => {
            if validator_cold_key_enrollment_active(current_height) {
                let cold_pubkey = cold_pubkey.as_ref().ok_or_else(|| {
                    StateError::InvalidStakingOp(
                        "validator registration requires a cold hybrid public key".into(),
                    )
                })?;
                let cold_signature = cold_signature.as_ref().ok_or_else(|| {
                    StateError::InvalidStakingOp(
                        "validator registration requires a cold hybrid signature".into(),
                    )
                })?;
                let message = op
                    .register_validator_dual_signing_bytes(chain_id)
                    .map_err(|err| StateError::InvalidStakingOp(err.to_string()))?
                    .ok_or_else(|| {
                        StateError::InvalidStakingOp(
                            "validator registration dual authorization message is absent".into(),
                        )
                    })?;
                let hot_pk = validator_pubkey
                    .to_crypto_pubkey()
                    .map_err(|reason| StateError::StakingOpSignatureInvalid { reason })?;
                let cold_pk = cold_pubkey
                    .to_crypto_pubkey()
                    .map_err(|reason| StateError::StakingOpSignatureInvalid { reason })?;
                let hot_sig = op
                    .signature
                    .to_crypto_sig()
                    .map_err(|reason| StateError::StakingOpSignatureInvalid { reason })?;
                let cold_sig = cold_signature
                    .to_crypto_sig()
                    .map_err(|reason| StateError::StakingOpSignatureInvalid { reason })?;
                indra_crypto::verify_dual_hybrid(
                    &message,
                    Some(&hot_sig),
                    &hot_pk,
                    Some(&cold_sig),
                    &cold_pk,
                )
                .map_err(|err| StateError::StakingOpSignatureInvalid {
                    reason: err.to_string(),
                })?;
            } else {
                verify_staking_sig(
                    &signing_bytes,
                    &op.signature,
                    &validator_pubkey.classical_pk.0,
                    validator_pubkey.pq_pk.as_slice(),
                )?;
            }
        }
        StakingOpBody::EnrollValidatorColdKey {
            validator_id,
            cold_pubkey,
            cold_signature,
        } => {
            let validator = state
                .validators
                .get(validator_id)
                .ok_or(StateError::ValidatorNotFound)?;
            if validator.cold_key_status != ColdKeyStatus::Unenrolled {
                return Err(StateError::InvalidStakingOp(
                    "validator cold key is already enrolled".into(),
                ));
            }
            let hot_classical_pk = validator.hybrid_classical_pk.ok_or_else(|| {
                StateError::StakingOpSignatureInvalid {
                    reason: "validator has no classical hot key registered".into(),
                }
            })?;
            let hot_pq_pk = validator.hybrid_pq_pk.as_deref().ok_or_else(|| {
                StateError::StakingOpSignatureInvalid {
                    reason: "validator has no PQ hot key registered".into(),
                }
            })?;
            let cold_signature = cold_signature.as_ref().ok_or_else(|| {
                StateError::InvalidStakingOp(
                    "validator cold-key enrollment requires a cold hybrid signature".into(),
                )
            })?;
            let message = op
                .enroll_validator_cold_key_dual_signing_bytes(chain_id)
                .map_err(|err| StateError::InvalidStakingOp(err.to_string()))?
                .ok_or_else(|| {
                    StateError::InvalidStakingOp(
                        "validator cold-key enrollment authorization message is absent".into(),
                    )
                })?;
            let hot_pk = hybrid_crypto_pubkey(&hot_classical_pk, hot_pq_pk)?;
            let cold_pk = cold_pubkey
                .to_crypto_pubkey()
                .map_err(|reason| StateError::StakingOpSignatureInvalid { reason })?;
            let hot_sig = op
                .signature
                .to_crypto_sig()
                .map_err(|reason| StateError::StakingOpSignatureInvalid { reason })?;
            let cold_sig = cold_signature
                .to_crypto_sig()
                .map_err(|reason| StateError::StakingOpSignatureInvalid { reason })?;
            indra_crypto::verify_dual_hybrid(
                &message,
                Some(&hot_sig),
                &hot_pk,
                Some(&cold_sig),
                &cold_pk,
            )
            .map_err(|err| StateError::StakingOpSignatureInvalid {
                reason: err.to_string(),
            })?;
        }
        StakingOpBody::SelfStake {
            validator_pubkey, ..
        }
        | StakingOpBody::SelfUnstake {
            validator_pubkey, ..
        } if !active_cold_validator => {
            verify_staking_sig(
                &signing_bytes,
                &op.signature,
                &validator_pubkey.classical_pk.0,
                validator_pubkey.pq_pk.as_slice(),
            )?;
        }
        StakingOpBody::RegisterPaymentKey { owner_pubkey, .. } if !active_cold_validator => {
            verify_staking_sig(
                &signing_bytes,
                &op.signature,
                &owner_pubkey.classical_pk.0,
                owner_pubkey.pq_pk.as_slice(),
            )?;
        }
        StakingOpBody::ClaimRewards { .. }
        | StakingOpBody::SetCommission { .. }
        | StakingOpBody::SelfStake { .. }
        | StakingOpBody::SelfUnstake { .. }
        | StakingOpBody::SetAutoDelegate { .. }
        | StakingOpBody::RegisterPaymentKey { .. } => {}
        StakingOpBody::RotateValidatorColdKey { .. } => unreachable!("rotation returned above"),
    }

    let result = match &op.body {
        StakingOpBody::Delegate {
            validator_id,
            bond_utxo_id,
            delegator_pubkey,
            bond_proof,
        } => apply_delegate(
            state,
            validator_id,
            *bond_utxo_id,
            delegator_pubkey,
            bond_proof.as_ref(),
            current_height,
            identity_registry_active,
        ),
        StakingOpBody::Undelegate {
            validator_id,
            bond_utxo_id,
            delegator_pubkey,
        } => apply_undelegate(
            state,
            validator_id,
            *bond_utxo_id,
            delegator_pubkey,
            current_height,
            identity_registry_active,
        ),
        StakingOpBody::ClaimRewards {
            validator_id,
            delegator_pubkey,
            ..
        } => apply_claim_rewards(
            state,
            validator_id,
            delegator_pubkey,
            current_height,
            identity_registry_active,
        ),
        StakingOpBody::RegisterValidator {
            commission_bps,
            bond_utxo_id,
            validator_pubkey,
            vrf_pk,
            bond_proof,
            cold_pubkey,
            ..
        } => apply_register_validator(
            state,
            *commission_bps,
            *bond_utxo_id,
            validator_pubkey,
            *vrf_pk,
            bond_proof.as_ref(),
            cold_pubkey.as_ref(),
            current_height,
            identity_registry_active,
        ),
        StakingOpBody::EnrollValidatorColdKey {
            validator_id,
            cold_pubkey,
            ..
        } => apply_enroll_validator_cold_key(state, *validator_id, cold_pubkey, current_height),
        StakingOpBody::SetCommission {
            validator_id,
            new_commission_bps,
            ..
        } => apply_set_commission(state, validator_id, *new_commission_bps, current_height),
        StakingOpBody::SetAutoDelegate {
            validator_id,
            target_validator_id,
            ..
        } => apply_set_auto_delegate(state, *validator_id, *target_validator_id, current_height),
        StakingOpBody::UpdateNetworkAddress {
            validator_id,
            network_addr,
        } => {
            apply_update_network_address(state, *validator_id, network_addr.clone(), current_height)
        }
        StakingOpBody::SelfStake {
            bond_utxo_id,
            validator_pubkey,
            bond_proof,
            ..
        } => apply_self_stake(
            state,
            *bond_utxo_id,
            validator_pubkey,
            bond_proof.as_ref(),
            current_height,
            identity_registry_active,
        ),
        StakingOpBody::SelfUnstake {
            bond_utxo_id,
            validator_pubkey,
            ..
        } => apply_self_unstake(
            state,
            *bond_utxo_id,
            validator_pubkey,
            current_height,
            identity_registry_active,
        ),
        StakingOpBody::RegisterPaymentKey {
            owner_pubkey,
            payment_pubkey,
            ..
        } => apply_register_payment_key(state, owner_pubkey, payment_pubkey),
        StakingOpBody::RotateValidatorColdKey { .. } => unreachable!("rotation returned above"),
    };

    result?;
    if active_cold_validator {
        let cold_nonce = op
            .cold_authorization()
            .expect("active cold authorization was verified")
            .cold_nonce;
        let validator = state
            .validators
            .get_mut(&signer_id)
            .ok_or(StateError::ValidatorNotFound)?;
        validator.cold_nonce = cold_nonce;
        if let Some(commitment) = state.state_commitment_v2.as_mut() {
            commitment.put_validator(validator, current_height);
        }
    } else {
        state.staking_nonces.insert(signer_id, op.nonce);
        if let Some(commitment) = state.state_commitment_v2.as_mut() {
            commitment.put_staking_nonce(&signer_id, op.nonce);
        }
    }
    Ok(())
}

fn apply_register_payment_key(
    state: &mut ChainState,
    owner_pubkey: &HybridPubKey,
    payment_pubkey: &indra_crypto::PaymentPubKeyV1,
) -> StateResult<()> {
    let owner_id = pubkey_to_id(owner_pubkey);
    state
        .payment_identities
        .insert(owner_id, payment_pubkey.clone());
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_payment_identity(&owner_id, payment_pubkey);
    }
    Ok(())
}

fn apply_enroll_validator_cold_key(
    state: &mut ChainState,
    validator_id: Bytes32,
    cold_pubkey: &ColdHybridPubKey,
    current_height: u64,
) -> StateResult<()> {
    let current = state
        .validators
        .get(&validator_id)
        .ok_or(StateError::ValidatorNotFound)?;
    if current.cold_key_status != ColdKeyStatus::Unenrolled {
        return Err(StateError::InvalidStakingOp(
            "validator cold key is already enrolled".into(),
        ));
    }
    validate_cold_components_not_retired(
        state,
        &cold_pubkey.classical_pk.0,
        cold_pubkey.pq_pk.as_slice(),
    )?;
    let validated = validate_validator_cold_key(
        &state.validators,
        &validator_id,
        &cold_pubkey.classical_pk.0,
        cold_pubkey.pq_pk.as_slice(),
        1,
    )?;
    let mut self_bond_ids: Vec<Bytes32> = state
        .staked_bonds
        .values()
        .filter(|bond| bond.validator_id == validator_id && bond.delegator_id == validator_id)
        .map(|bond| bond.utxo_id)
        .collect();
    self_bond_ids.sort_by_key(|id| id.0);
    if self_bond_ids.len() > MAX_ATOMIC_COLD_KEY_MIGRATION_SELF_BONDS {
        return Err(StateError::InvalidStakingOp(format!(
            "validator has {} unresolved self-bonds; atomic cold-key enrollment supports at most {}. Consolidate using SelfUnstake for the existing bonds, wait for maturity, SelfStake one consolidated UTXO, then enroll",
            self_bond_ids.len(),
            MAX_ATOMIC_COLD_KEY_MIGRATION_SELF_BONDS
        )));
    }
    for bond_id in self_bond_ids {
        let Some(mut bond) = state.staked_bonds.remove(&bond_id) else {
            return Err(StateError::InvariantViolation {
                message: "self-bond disappeared during cold-key enrollment migration",
            });
        };
        bond.custody_owner = StakeBondCustodyOwner::ValidatorColdIdentity(validator_id);
        state.staked_bonds.insert(bond_id, bond.clone());
        if let Some(commitment) = state.state_commitment_v2.as_mut() {
            commitment.put_staked_bond(&bond_id, &bond);
        }
    }
    let mut updated = current.clone();
    updated.cold_hybrid_classical_pk = Some(validated.classical_pk);
    updated.cold_hybrid_pq_pk = Some(validated.pq_pk);
    updated.cold_key_version = validated.version;
    updated.cold_key_status = ColdKeyStatus::Active;
    updated.cold_nonce = 0;
    state.validators.upsert(updated.clone())?;
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_validator(&updated, current_height);
    }
    Ok(())
}

fn validate_cold_components_not_retired(
    state: &ChainState,
    classical: &[u8; 32],
    pq: &[u8],
) -> StateResult<()> {
    if state.retired_cold_classical_components.contains(classical) {
        return Err(StateError::InvalidStakingOp(
            "proposed Ed25519 component is permanently retired".into(),
        ));
    }
    if pq.len() == indra_crypto::PQ_PK_BYTES {
        let mut component = [0u8; indra_crypto::PQ_PK_BYTES];
        component.copy_from_slice(pq);
        if state.retired_cold_pq_components.contains(&component) {
            return Err(StateError::InvalidStakingOp(
                "proposed ML-DSA-87 component is permanently retired".into(),
            ));
        }
    }
    Ok(())
}

fn verify_and_apply_rotate_validator_cold_key(
    state: &mut ChainState,
    op: &StakingOp,
    chain_id: &str,
    current_height: u64,
) -> StateResult<()> {
    let StakingOpBody::RotateValidatorColdKey {
        validator_id,
        current_cold_key_version,
        new_cold_key_version,
        current_cold_nonce,
        new_cold_pubkey,
        new_cold_signature,
    } = &op.body
    else {
        unreachable!()
    };
    let current = state
        .validators
        .get(validator_id)
        .ok_or(StateError::ValidatorNotFound)?
        .clone();
    if current.cold_key_status != ColdKeyStatus::Active {
        return Err(StateError::InvalidStakingOp(
            "RotateValidatorColdKey requires an Active cold key; use enrollment instead".into(),
        ));
    }
    if *current_cold_key_version != current.cold_key_version
        || current_cold_key_version.checked_add(1) != Some(*new_cold_key_version)
    {
        return Err(StateError::InvalidStakingOp(
            "cold-key rotation version mismatch".into(),
        ));
    }
    let expected_nonce = current
        .cold_nonce
        .checked_add(1)
        .ok_or_else(|| StateError::InvalidStakingOp("validator cold nonce exhausted".into()))?;
    if *current_cold_nonce != expected_nonce {
        return Err(StateError::StakingNonceInvalid {
            expected: expected_nonce,
            got: *current_cold_nonce,
        });
    }
    validate_cold_components_not_retired(
        state,
        &new_cold_pubkey.classical_pk.0,
        new_cold_pubkey.pq_pk.as_slice(),
    )?;
    let validated = validate_validator_cold_key(
        &state.validators,
        validator_id,
        &new_cold_pubkey.classical_pk.0,
        new_cold_pubkey.pq_pk.as_slice(),
        *new_cold_key_version,
    )?;
    let old_classical =
        current
            .cold_hybrid_classical_pk
            .ok_or_else(|| StateError::StakingOpSignatureInvalid {
                reason: "Active validator has no current Ed25519 cold component".into(),
            })?;
    let old_pq = current.cold_hybrid_pq_pk.as_ref().ok_or_else(|| {
        StateError::StakingOpSignatureInvalid {
            reason: "Active validator has no current ML-DSA-87 cold component".into(),
        }
    })?;
    let new_signature = new_cold_signature.as_ref().ok_or_else(|| {
        StateError::InvalidStakingOp(
            "cold-key rotation requires the proposed new key signature".into(),
        )
    })?;
    let message = op
        .rotate_validator_cold_key_dual_signing_bytes(chain_id)
        .map_err(|err| StateError::InvalidStakingOp(err.to_string()))?
        .ok_or_else(|| {
            StateError::InvalidStakingOp("cold-key rotation authorization message is absent".into())
        })?;
    let current_pk = hybrid_crypto_pubkey(&old_classical, old_pq)?;
    let proposed_pk = new_cold_pubkey
        .to_crypto_pubkey()
        .map_err(|reason| StateError::StakingOpSignatureInvalid { reason })?;
    let current_sig = op
        .signature
        .to_crypto_sig()
        .map_err(|reason| StateError::StakingOpSignatureInvalid { reason })?;
    let proposed_sig = new_signature
        .to_crypto_sig()
        .map_err(|reason| StateError::StakingOpSignatureInvalid { reason })?;
    indra_crypto::verify_dual_hybrid(
        &message,
        Some(&current_sig),
        &current_pk,
        Some(&proposed_sig),
        &proposed_pk,
    )
    .map_err(|err| StateError::StakingOpSignatureInvalid {
        reason: err.to_string(),
    })?;

    let mut retired_pq = [0u8; indra_crypto::PQ_PK_BYTES];
    retired_pq.copy_from_slice(old_pq);
    state
        .retired_cold_classical_components
        .insert(old_classical);
    state.retired_cold_pq_components.insert(retired_pq);
    let mut updated = current;
    updated.cold_hybrid_classical_pk = Some(validated.classical_pk);
    updated.cold_hybrid_pq_pk = Some(validated.pq_pk);
    updated.cold_key_version = validated.version;
    updated.cold_nonce = 0;
    state.validators.upsert(updated.clone())?;
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_retired_cold_component(0, &old_classical);
        commitment.put_retired_cold_component(1, &retired_pq);
        commitment.put_validator(&updated, current_height);
    }
    Ok(())
}

fn hybrid_crypto_pubkey(
    classical_pk: &[u8; 32],
    pq_pk_bytes: &[u8],
) -> StateResult<indra_crypto::HybridPublicKey> {
    use indra_crypto::{ClassicalPublicKey, HybridPublicKey, PqPublicKey, PQ_PK_BYTES};

    let pq_pk: [u8; PQ_PK_BYTES] =
        pq_pk_bytes
            .try_into()
            .map_err(|_| StateError::StakingOpSignatureInvalid {
                reason: format!(
                    "pq public key must be {} bytes, got {}",
                    PQ_PK_BYTES,
                    pq_pk_bytes.len()
                ),
            })?;
    Ok(HybridPublicKey {
        classical: ClassicalPublicKey(*classical_pk),
        pq: PqPublicKey(pq_pk),
    })
}

fn verify_staking_sig(
    signing_bytes: &[u8],
    signature: &HybridSignature,
    classical_pk: &[u8; 32],
    pq_pk_bytes: &[u8],
) -> StateResult<()> {
    use indra_crypto::verify_hybrid;

    let crypto_pk = hybrid_crypto_pubkey(classical_pk, pq_pk_bytes)?;
    let crypto_sig = signature
        .to_crypto_sig()
        .map_err(|reason| StateError::StakingOpSignatureInvalid { reason })?;
    verify_hybrid(signing_bytes, &crypto_sig, &crypto_pk).map_err(|e| {
        StateError::StakingOpSignatureInvalid {
            reason: e.to_string(),
        }
    })
}

/// Verify that a staking bond proof correctly opens the bonded UTXO
/// commitment to its public `value_spark`.
///
/// This must be called before spending the UTXO so a failed proof leaves
/// spendable state untouched.
pub fn validate_staking_bond_proof(output: &OutputV1, proof: &StakingBondProof) -> StateResult<()> {
    use indra_crypto::{verify_opening, PedersenCommitment, PedersenOpening};

    let opening = PedersenOpening {
        value: proof.committed_value_spark,
        blinding: proof.blinding_factor.0,
    };
    verify_opening(
        &PedersenCommitment(output.commitment.compressed_point.0),
        &opening,
    )
    .map_err(|_| StateError::StakingBondCommitmentMismatch)?;

    if proof.committed_value_spark != output.value_spark {
        return Err(StateError::StakingBondValueMismatch {
            public_value: output.value_spark,
            committed_value: proof.committed_value_spark,
        });
    }

    Ok(())
}

fn require_and_validate_bond_proof(
    current_height: u64,
    output: &OutputV1,
    proof: Option<&StakingBondProof>,
) -> StateResult<()> {
    match proof {
        Some(proof) => validate_staking_bond_proof(output, proof),
        None if staking_commitment_proof_required(current_height) => {
            Err(StateError::BondProofRequired)
        }
        None => Ok(()),
    }
}

fn apply_register_validator(
    state: &mut ChainState,
    commission_bps: u32,
    bond_utxo_id: Bytes32,
    validator_pubkey: &HybridPubKey,
    vrf_pk: [u8; 32],
    bond_proof: Option<&StakingBondProof>,
    cold_pubkey: Option<&ColdHybridPubKey>,
    current_height: u64,
    identity_registry_active: bool,
) -> StateResult<()> {
    if commission_bps < MIN_COMMISSION_BPS
        || commission_bps > state.governance.params.max_commission_bps
    {
        return Err(StateError::InvalidStakingOp(
            "commission out of range".into(),
        ));
    }

    let validator_id = pubkey_to_id(validator_pubkey);
    if state.validators.get(&validator_id).is_some() {
        return Err(StateError::ValidatorAlreadyRegistered);
    }
    if identity_registry_active {
        check_validator_identity_registry_if_present(state, &validator_id, validator_pubkey)?;
    }
    validate_cold_components_not_retired(
        state,
        &validator_pubkey.classical_pk.0,
        validator_pubkey.pq_pk.as_slice(),
    )?;
    let validated_cold_key = if validator_cold_key_enrollment_active(current_height) {
        let cold_pubkey = cold_pubkey.ok_or_else(|| {
            StateError::InvalidStakingOp(
                "validator registration requires a cold hybrid public key".into(),
            )
        })?;
        validate_cold_components_not_retired(
            state,
            &cold_pubkey.classical_pk.0,
            cold_pubkey.pq_pk.as_slice(),
        )?;
        Some(validate_new_validator_cold_key(
            &state.validators,
            &validator_id,
            validator_pubkey.classical_pk.0,
            validator_pubkey.pq_pk.as_slice(),
            &cold_pubkey.classical_pk.0,
            cold_pubkey.pq_pk.as_slice(),
            1,
        )?)
    } else {
        None
    };
    let new_classical_pk = validator_pubkey.classical_pk.0;
    let new_pq_pk = validator_pubkey.pq_pk.as_slice();
    for existing in state.validators.all_validators() {
        if existing.hybrid_classical_pk == Some(new_classical_pk) {
            return Err(StateError::DuplicateValidatorKey {
                reason: "hybrid_classical_pk already registered".into(),
            });
        }
        if existing.hybrid_pq_pk.as_deref() == Some(new_pq_pk) {
            return Err(StateError::DuplicateValidatorKey {
                reason: "hybrid_pq_pk already registered".into(),
            });
        }
        if existing.cold_hybrid_classical_pk == Some(new_classical_pk) {
            return Err(StateError::DuplicateValidatorKey {
                reason: "hot hybrid_classical_pk reuses an active cold component".into(),
            });
        }
        if existing.cold_hybrid_pq_pk.as_ref().map(|pk| pk.as_slice()) == Some(new_pq_pk) {
            return Err(StateError::DuplicateValidatorKey {
                reason: "hot hybrid_pq_pk reuses an active cold component".into(),
            });
        }
        if existing.vrf_pk == Some(vrf_pk) {
            return Err(StateError::DuplicateValidatorKey {
                reason: "vrf_pk already registered".into(),
            });
        }
    }

    if state.staked_bonds.contains_key(&bond_utxo_id) {
        return Err(StateError::InvalidStakingOp(
            "registration bond UTXO is already bonded as stake".into(),
        ));
    }

    let utxo_entry = state
        .utxos
        .get(&bond_utxo_id)
        .ok_or(StateError::UnknownUtxo)?
        .clone();
    let owner_matches = if let Some(cold_key) = &validated_cold_key {
        utxo_entry.output.owner_pubkey.classical_pk.0 == cold_key.classical_pk
            && utxo_entry.output.owner_pubkey.pq_pk.as_slice() == cold_key.pq_pk.as_slice()
    } else {
        pubkey_to_id(&utxo_entry.output.owner_pubkey) == validator_id
    };
    if !owner_matches {
        return Err(StateError::InvalidStakingOp(
            if validated_cold_key.is_some() {
                "registration bond UTXO is not owned by the proposed cold hybrid key".into()
            } else {
                "registration bond UTXO does not belong to the validator".into()
            },
        ));
    }
    require_and_validate_bond_proof(current_height, &utxo_entry.output, bond_proof)?;

    // Bond amount is taken from output.value_spark (public metadata field).
    // This field is not individually proven to match the Pedersen commitment;
    // the transaction-level aggregate balance equation prevents total-value
    // inflation, but individual output commitment binding is not enforced here.
    // See: docs/SECURITY_AUDIT_PHASE4.md ST-03 and Phase 2 T-08.
    let amount_spark = utxo_entry.output.value_spark;
    if amount_spark < MINIMUM_VALIDATOR_BOND_SPARK {
        return Err(StateError::InvalidStakingOp(format!(
            "registration self-bond {} Spark below minimum {} Spark",
            amount_spark, MINIMUM_VALIDATOR_BOND_SPARK,
        )));
    }

    let current_epoch = epoch_for_height(state.height);
    if state.validators.len() >= MAX_VALIDATORS {
        if !registered_validator_cap_active(current_height) {
            return Err(StateError::InvariantViolation {
                message: "validator set at maximum capacity",
            });
        }
        let (lowest_id, lowest_total) =
            lowest_ranked_registry_validator(state).ok_or(StateError::InvariantViolation {
                message: "validator set full but no evictable validator found",
            })?;
        if amount_spark <= lowest_total {
            return Err(StateError::InvalidStakingOp(format!(
                "validator registry at capacity; new total stake {} does not exceed lowest registered total stake {}",
                amount_spark, lowest_total
            )));
        }
        evict_validator_for_registry_replacement(state, lowest_id, current_epoch, current_height)?;
    }

    let original_output = utxo_entry.output;
    let spent = state.utxos.spend_at_height(&bond_utxo_id, current_height);
    if spent.is_none() {
        return Err(StateError::InvariantViolation {
            message: "registration bond UTXO disappeared during validator registration",
        });
    }

    let entry = ValidatorEntry {
        validator_id,
        name: hex::encode(&validator_id.0[..8]),
        hybrid_classical_pk: Some(validator_pubkey.classical_pk.0),
        hybrid_pq_pk: Some(validator_pubkey.pq_pk.as_slice().to_vec()),
        vrf_pk: Some(vrf_pk),
        stake_spark: amount_spark,
        status: ValidatorStatus::Registered,
        registered_epoch: current_epoch,
        last_active_epoch: current_epoch,
        pending_rewards: 0,
        rewards_last_epoch: current_epoch,
        self_report_count: 0,
        commission_bps,
        pending_commission_bps: None,
        pending_commission_effective_epoch: None,
        min_delegation_spark: DUST_LIMIT_SPARK,
        auto_delegate_to: None,
        network_addr: None,
        network_addr_last_updated_epoch: None,
        cold_hybrid_classical_pk: validated_cold_key
            .as_ref()
            .map(|cold_key| cold_key.classical_pk),
        cold_hybrid_pq_pk: validated_cold_key.as_ref().map(|cold_key| cold_key.pq_pk),
        cold_key_version: validated_cold_key
            .as_ref()
            .map(|cold_key| cold_key.version)
            .unwrap_or(0),
        cold_key_status: if validated_cold_key.is_some() {
            ColdKeyStatus::Active
        } else {
            ColdKeyStatus::Unenrolled
        },
        cold_nonce: 0,
    };
    state.validators.upsert(entry.clone())?;
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_validator(&entry, current_height);
    }
    let mut bond = StakeBondEntry::new(
        bond_utxo_id,
        validator_id,
        validator_id,
        amount_spark,
        epoch_for_height(current_height),
        original_output,
        current_height,
    );
    if validated_cold_key.is_some() {
        bond.custody_owner = StakeBondCustodyOwner::ValidatorColdIdentity(validator_id);
    }
    state.staked_bonds.insert(bond_utxo_id, bond.clone());
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_staked_bond(&bond_utxo_id, &bond);
    }
    if identity_registry_active {
        check_or_insert_validator_identity(state, &validator_id, validator_pubkey)?;
    }
    Ok(())
}

fn lowest_ranked_registry_validator(state: &ChainState) -> Option<(Bytes32, u64)> {
    state
        .validators
        .all_validators()
        .filter(|validator| {
            matches!(
                validator.status,
                ValidatorStatus::Active | ValidatorStatus::Registered
            )
        })
        .map(|validator| {
            let total = validator
                .stake_spark
                .saturating_add(state.delegations.total_delegated(&validator.validator_id));
            (validator.validator_id, total)
        })
        .min_by(|(id_a, total_a), (id_b, total_b)| {
            total_a.cmp(total_b).then_with(|| id_b.0.cmp(&id_a.0))
        })
}

fn evict_validator_for_registry_replacement(
    state: &mut ChainState,
    validator_id: Bytes32,
    current_epoch: u64,
    current_height: u64,
) -> StateResult<()> {
    let validator = state
        .validators
        .get(&validator_id)
        .cloned()
        .ok_or(StateError::ValidatorNotFound)?;
    if validator_cold_key_enforcement_active(current_height)
        && validator.cold_key_status == ColdKeyStatus::Unenrolled
    {
        return Err(StateError::InvalidStakingOp(
            "cannot evict an unenrolled validator after \
             VALIDATOR_COLD_KEY_ENFORCEMENT_HEIGHT: validator custody is frozen until \
             EnrollValidatorColdKey completes"
                .into(),
        ));
    }
    let delegators = state.delegations.take_delegators(&validator_id);
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        for entry in &delegators {
            commitment.delete_delegator(&validator_id, &entry.delegator_id);
        }
    }

    if validator.pending_rewards > 0 {
        payout_or_burn_pending_reward(
            state,
            &validator_id,
            &validator_id,
            validator.pending_rewards,
            validator_public_key(&validator)?,
            current_height,
        )?;
    }
    for entry in &delegators {
        if entry.pending_rewards > 0 {
            if let Some(bond) = state
                .staked_bonds
                .values()
                .find(|bond| {
                    bond.validator_id == validator_id && bond.delegator_id == entry.delegator_id
                })
                .cloned()
            {
                let owner_pubkey = resolve_bond_owner_pubkey(&bond, state).map_err(|_| {
                    StateError::InvariantViolation {
                        message: "delegator reward owner pubkey could not be resolved during validator eviction",
                    }
                })?;
                payout_or_burn_pending_reward(
                    state,
                    &validator_id,
                    &entry.delegator_id,
                    entry.pending_rewards,
                    owner_pubkey,
                    current_height,
                )?;
            } else if entry.pending_rewards < DUST_LIMIT_SPARK {
                eprintln!(
                    "[staking] burned dust pending reward {} for delegator {} during validator eviction; no bond pubkey found",
                    entry.pending_rewards,
                    hex::encode(&entry.delegator_id.0[..4])
                );
            } else {
                return Err(StateError::InvariantViolation {
                    message: "delegator reward could not be paid during validator eviction",
                });
            }
        }
    }

    let mut bond_ids: Vec<Bytes32> = state
        .staked_bonds
        .values()
        .filter(|bond| bond.validator_id == validator_id)
        .map(|bond| bond.utxo_id)
        .collect();
    bond_ids.sort_by_key(|id| id.0);
    for bond_id in bond_ids {
        if let Some(bond) = state.staked_bonds.remove(&bond_id) {
            if let Some(commitment) = state.state_commitment_v2.as_mut() {
                commitment.delete_staked_bond(&bond_id);
            }
            let output = crate::epoch::released_bond_output(state, &bond, current_height)?;
            let output_index =
                u32::try_from(state.utxos.len()).unwrap_or(u32::MAX.saturating_sub(1));
            let refund_utxo_id = state
                .utxos
                .insert(output, current_height, STAKING_TX_IDX, output_index)
                .map_err(|_| StateError::InvariantViolation {
                    message: "UTXO ID collision in validator eviction bond refund",
                })?;
            state.push_delegation_return_event(DelegationReturnEvent {
                delegator_id: bond.delegator_id,
                validator_id,
                bond_utxo_id: bond.utxo_id,
                amount_spark: bond.amount_spark,
                reason: DelegationReturnReason::ValidatorEvicted,
                returned_epoch: current_epoch,
                returned_height: current_height,
                refund_utxo_id,
            });
        }
    }

    state.validators.remove(&validator_id);
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.delete_validator(&validator_id);
    }
    eprintln!(
        "[staking] evicted validator {} from full registry and returned {} delegation entries",
        hex::encode(&validator_id.0[..4]),
        delegators.len()
    );
    Ok(())
}

fn validator_public_key(validator: &ValidatorEntry) -> StateResult<HybridPubKey> {
    if validator.cold_key_status == ColdKeyStatus::Active {
        let classical_pk =
            validator
                .cold_hybrid_classical_pk
                .ok_or(StateError::InvariantViolation {
                    message: "active validator missing cold classical key during eviction payout",
                })?;
        let pq_pk = validator
            .cold_hybrid_pq_pk
            .ok_or(StateError::InvariantViolation {
                message: "active validator missing cold PQ key during eviction payout",
            })?;
        return Ok(HybridPubKey {
            classical_pk: Bytes32::from(classical_pk),
            pq_pk: VariableBytes::from_slice(&pq_pk).map_err(|_| {
                StateError::InvariantViolation {
                    message: "validator cold PQ key too large during eviction payout",
                }
            })?,
        });
    }
    let classical_pk = validator
        .hybrid_classical_pk
        .ok_or(StateError::InvariantViolation {
            message: "validator missing classical key during eviction reward payout",
        })?;
    let pq_bytes = validator
        .hybrid_pq_pk
        .as_deref()
        .ok_or(StateError::InvariantViolation {
            message: "validator missing PQ key during eviction reward payout",
        })?;
    Ok(HybridPubKey {
        classical_pk: Bytes32::from(classical_pk),
        pq_pk: VariableBytes::from_slice(pq_bytes).map_err(|_| StateError::InvariantViolation {
            message: "validator PQ key too large during eviction reward payout",
        })?,
    })
}

fn payout_or_burn_pending_reward(
    state: &mut ChainState,
    validator_id: &Bytes32,
    delegator_id: &Bytes32,
    amount: u64,
    owner_pubkey: HybridPubKey,
    current_height: u64,
) -> StateResult<()> {
    if amount < DUST_LIMIT_SPARK {
        eprintln!(
            "[staking] burned dust pending reward {} for delegator {} during validator eviction",
            amount,
            hex::encode(&delegator_id.0[..4])
        );
        return Ok(());
    }
    let mut blinding_input = Vec::with_capacity(STAKING_REWARD_BLINDING_DOMAIN.len() + 32 + 32 + 8);
    blinding_input.extend_from_slice(STAKING_REWARD_BLINDING_DOMAIN);
    blinding_input.extend_from_slice(&validator_id.0);
    blinding_input.extend_from_slice(&delegator_id.0);
    blinding_input.extend_from_slice(&current_height.to_le_bytes());
    let blinding = indra_crypto::sha256(&blinding_input);
    let commitment = indra_crypto::commit(amount, &blinding);
    let mut rng = rand::rngs::StdRng::from_seed(blinding);
    let proof = indra_crypto::prove_range(amount, &blinding, &mut rng).map_err(|_| {
        StateError::InvalidStakingOp(
            "failed to generate range proof for eviction reward UTXO".into(),
        )
    })?;
    let output = OutputV1 {
        value_spark: amount,
        commitment: CommitmentV1 {
            compressed_point: Bytes32::from(commitment.0),
        },
        owner_pubkey,
        range_proof: VariableBytes::from_slice(&proof)
            .map_err(|_| StateError::InvalidStakingOp("range proof too large".into()))?,
        lock_height: 0,
    };
    let output_index = u32::try_from(state.utxos.len()).unwrap_or(u32::MAX.saturating_sub(1));
    state
        .utxos
        .insert(output, current_height, STAKING_TX_IDX, output_index)
        .map_err(|_| StateError::InvariantViolation {
            message: "UTXO ID collision in validator eviction reward payout",
        })?;
    Ok(())
}

/// Delegate stake to a validator.
///
/// The delegator's stake is added to the validator's delegation pool.
/// Rewards accrue from the next epoch boundary.
fn apply_delegate(
    state: &mut ChainState,
    validator_id: &Bytes32,
    bond_utxo_id: Bytes32,
    delegator_pubkey: &HybridPubKey,
    bond_proof: Option<&StakingBondProof>,
    current_height: u64,
    identity_registry_active: bool,
) -> StateResult<()> {
    let validator = state
        .validators
        .get(validator_id)
        .ok_or(StateError::ValidatorNotFound)?;
    if !matches!(
        validator.status,
        ValidatorStatus::Active | ValidatorStatus::Registered
    ) {
        return Err(StateError::ValidatorNotActive);
    }
    let min_delegation = validator
        .min_delegation_spark
        .max(state.governance.params.min_delegation_spark);

    if state.staked_bonds.contains_key(&bond_utxo_id) {
        return Err(StateError::InvalidStakingOp(
            "UTXO is already bonded as stake".into(),
        ));
    }

    let utxo_entry = state
        .utxos
        .get(&bond_utxo_id)
        .ok_or(StateError::UnknownUtxo)?
        .clone();

    let delegator_id = pubkey_to_id(delegator_pubkey);
    let utxo_owner_id = pubkey_to_id(&utxo_entry.output.owner_pubkey);
    if utxo_owner_id != delegator_id {
        return Err(StateError::InvalidStakingOp(
            "UTXO does not belong to the delegator".into(),
        ));
    }
    let identity_outcome = if identity_registry_active {
        Some(
            resolve_and_check_identity(&delegator_id, delegator_pubkey, state)
                .map_err(identity_error_to_state_error)?,
        )
    } else {
        None
    };
    require_and_validate_bond_proof(current_height, &utxo_entry.output, bond_proof)?;

    // Bond amount is taken from output.value_spark (public metadata field).
    // This field is not individually proven to match the Pedersen commitment;
    // the transaction-level aggregate balance equation prevents total-value
    // inflation, but individual output commitment binding is not enforced here.
    // See: docs/SECURITY_AUDIT_PHASE4.md ST-03 and Phase 2 T-08.
    let amount_spark = utxo_entry.output.value_spark;
    if amount_spark < min_delegation {
        return Err(StateError::InvalidStakingOp(format!(
            "delegation {} Spark below minimum {} Spark",
            amount_spark, min_delegation,
        )));
    }

    let current_epoch = epoch_for_height(current_height);
    let delegators = state.delegations.get_delegators(validator_id);
    let existing_delegator = delegators
        .iter()
        .any(|entry| entry.delegator_id == delegator_id);
    if !existing_delegator && delegators.len() >= MAX_DELEGATORS_PER_VALIDATOR {
        return Err(StateError::InvalidStakingOp(format!(
            "validator delegator count at maximum ({MAX_DELEGATORS_PER_VALIDATOR})"
        )));
    }

    let original_output = utxo_entry.output;
    let _ = state.utxos.spend_at_height(&bond_utxo_id, current_height);

    let bond = StakeBondEntry::new(
        bond_utxo_id,
        *validator_id,
        delegator_id,
        amount_spark,
        current_epoch,
        original_output,
        current_height,
    );
    state.staked_bonds.insert(bond_utxo_id, bond.clone());
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_staked_bond(&bond_utxo_id, &bond);
    }

    state
        .delegations
        .add_delegation(*validator_id, delegator_id, amount_spark, current_epoch)
        .map_err(|reason| StateError::InvalidStakingOp(reason.into()))?;
    if let (Some(commitment), Some(delegator)) = (
        state.state_commitment_v2.as_mut(),
        state
            .delegations
            .get_delegators(validator_id)
            .iter()
            .find(|entry| entry.delegator_id == delegator_id),
    ) {
        commitment.put_delegator(validator_id, delegator);
    }

    if matches!(
        identity_outcome,
        Some(IdentityCheckOutcome::NoPriorRecord | IdentityCheckOutcome::LegacyBondMatch)
    ) {
        state
            .delegator_identities
            .insert(delegator_id, delegator_pubkey.clone());
        if let Some(commitment) = state.state_commitment_v2.as_mut() {
            commitment.put_delegator_identity(&delegator_id, delegator_pubkey);
        }
    }

    Ok(())
}

fn identity_error_to_state_error(error: IdentityError) -> StateError {
    match error {
        IdentityError::RegistryPubkeyMismatch { delegator_id } => StateError::InvalidStakingOp(
            format!("delegator identity registry pubkey mismatch for {delegator_id}"),
        ),
        IdentityError::LegacyPubkeyMismatch { delegator_id } => StateError::InvalidStakingOp(
            format!("delegator identity legacy pubkey mismatch for {delegator_id}"),
        ),
        IdentityError::AmbiguousLegacyPubkeys { delegator_id } => StateError::InvalidStakingOp(
            format!("delegator identity has ambiguous legacy pubkeys for {delegator_id}"),
        ),
        IdentityError::UnresolvableIdentity { delegator_id, .. } => StateError::InvalidStakingOp(
            format!("delegator identity is unresolvable for {delegator_id}"),
        ),
    }
}

/// Begin undelegating from a validator.
///
/// Stake enters unbonding for UNBONDING_PERIOD_EPOCHS epochs.
/// During unbonding, stake earns no rewards and cannot be redelegated.
fn apply_undelegate(
    state: &mut ChainState,
    validator_id: &Bytes32,
    bond_utxo_id: Bytes32,
    delegator_pubkey: &HybridPubKey,
    current_height: u64,
    identity_registry_active: bool,
) -> StateResult<()> {
    let delegator_id = pubkey_to_id(delegator_pubkey);

    let mut bond = state
        .staked_bonds
        .get(&bond_utxo_id)
        .cloned()
        .ok_or_else(|| StateError::InvalidStakingOp("stake bond not found".into()))?;
    if bond.delegator_id != delegator_id {
        return Err(StateError::InvalidStakingOp(
            "bond does not belong to delegator".into(),
        ));
    }
    let identity_outcome = if identity_registry_active {
        let outcome = resolve_and_check_identity(&delegator_id, delegator_pubkey, state)
            .map_err(identity_error_to_state_error)?;
        if matches!(outcome, IdentityCheckOutcome::NoPriorRecord) {
            let owner_pubkey = resolve_bond_owner_pubkey(&bond, state).map_err(|_| {
                StateError::InvalidStakingOp(format!(
                    "delegator identity bond owner is unresolvable for {delegator_id}"
                ))
            })?;
            if owner_pubkey != *delegator_pubkey {
                return Err(StateError::InvalidStakingOp(format!(
                    "delegator identity bond owner pubkey mismatch for {delegator_id}"
                )));
            }
        }
        Some(outcome)
    } else {
        None
    };
    if bond.validator_id != *validator_id {
        return Err(StateError::InvalidStakingOp(
            "bond not staked with this validator".into(),
        ));
    }
    if bond.unbonding_end_epoch.is_some() {
        return Err(StateError::InvalidStakingOp(
            "bond is already unbonding".into(),
        ));
    }

    let current_epoch = epoch_for_height(current_height);
    let unbonding_end = current_epoch + UNBONDING_PERIOD_EPOCHS;
    bond.unbonding_end_epoch = Some(unbonding_end);
    let amount_spark = bond.amount_spark;
    let updated_bond = bond.clone();
    state
        .staked_bonds
        .insert(bond_utxo_id, updated_bond.clone());
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_staked_bond(&bond_utxo_id, &updated_bond);
    }

    state
        .delegations
        .begin_undelegate(validator_id, &delegator_id, amount_spark, unbonding_end)
        .map_err(|e| StateError::InvalidStakingOp(e.into()))?;
    if let (Some(commitment), Some(delegator)) = (
        state.state_commitment_v2.as_mut(),
        state
            .delegations
            .get_delegators(validator_id)
            .iter()
            .find(|entry| entry.delegator_id == delegator_id),
    ) {
        commitment.put_delegator(validator_id, delegator);
    }
    if matches!(
        identity_outcome,
        Some(IdentityCheckOutcome::NoPriorRecord | IdentityCheckOutcome::LegacyBondMatch)
    ) {
        state
            .delegator_identities
            .insert(delegator_id, delegator_pubkey.clone());
        if let Some(commitment) = state.state_commitment_v2.as_mut() {
            commitment.put_delegator_identity(&delegator_id, delegator_pubkey);
        }
    }
    Ok(())
}

/// Bond a validator-owned UTXO as validator self-stake.
fn apply_self_stake(
    state: &mut ChainState,
    bond_utxo_id: Bytes32,
    validator_pubkey: &HybridPubKey,
    bond_proof: Option<&StakingBondProof>,
    current_height: u64,
    identity_registry_active: bool,
) -> StateResult<()> {
    let validator_id = pubkey_to_id(validator_pubkey);
    let validator = state
        .validators
        .get(&validator_id)
        .ok_or(StateError::ValidatorNotFound)?;
    if identity_registry_active {
        check_validator_identity_consistency(state, &validator_id, validator_pubkey)?;
    }
    if !matches!(
        validator.status,
        ValidatorStatus::Active | ValidatorStatus::Registered
    ) {
        return Err(StateError::ValidatorNotActive);
    }

    if state.staked_bonds.contains_key(&bond_utxo_id) {
        return Err(StateError::InvalidStakingOp(
            "UTXO is already bonded as stake".into(),
        ));
    }

    let utxo_entry = state
        .utxos
        .get(&bond_utxo_id)
        .ok_or(StateError::UnknownUtxo)?
        .clone();
    if validator.cold_key_status == ColdKeyStatus::Active {
        let cold_owner = resolve_active_validator_cold_pubkey(state, &validator_id)
            .map_err(identity_error_to_state_error)?;
        if utxo_entry.output.owner_pubkey != cold_owner {
            return Err(StateError::InvalidStakingOp(
                "self-stake UTXO is not owned by the validator's active cold key".into(),
            ));
        }
    } else {
        let utxo_owner_id = pubkey_to_id(&utxo_entry.output.owner_pubkey);
        if utxo_owner_id != validator_id {
            return Err(StateError::InvalidStakingOp(
                "UTXO does not belong to the validator".into(),
            ));
        }
    }
    require_and_validate_bond_proof(current_height, &utxo_entry.output, bond_proof)?;

    // Bond amount is taken from output.value_spark (public metadata field).
    // This field is not individually proven to match the Pedersen commitment;
    // the transaction-level aggregate balance equation prevents total-value
    // inflation, but individual output commitment binding is not enforced here.
    // See: docs/SECURITY_AUDIT_PHASE4.md ST-03 and Phase 2 T-08.
    let amount_spark = utxo_entry.output.value_spark;
    if amount_spark < DUST_LIMIT_SPARK {
        return Err(StateError::InvalidStakingOp(format!(
            "self-stake {} Spark below dust limit {} Spark",
            amount_spark, DUST_LIMIT_SPARK,
        )));
    }

    let current_epoch = epoch_for_height(current_height);
    let original_output = utxo_entry.output;
    let _ = state.utxos.spend_at_height(&bond_utxo_id, current_height);
    let mut bond = StakeBondEntry::new(
        bond_utxo_id,
        validator_id,
        validator_id,
        amount_spark,
        current_epoch,
        original_output,
        current_height,
    );
    if state
        .validators
        .get(&validator_id)
        .is_some_and(|validator| validator.cold_key_status == ColdKeyStatus::Active)
    {
        bond.custody_owner = StakeBondCustodyOwner::ValidatorColdIdentity(validator_id);
    }
    state.staked_bonds.insert(bond_utxo_id, bond.clone());
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_staked_bond(&bond_utxo_id, &bond);
    }
    let mut updated_validator = None;
    if let Some(v) = state.validators.get_mut(&validator_id) {
        v.stake_spark = v.stake_spark.saturating_add(amount_spark);
        updated_validator = Some(v.clone());
    }
    if let (Some(commitment), Some(validator)) =
        (state.state_commitment_v2.as_mut(), updated_validator)
    {
        commitment.put_validator(&validator, current_height);
    }
    Ok(())
}

/// Begin unbonding validator self-stake.
fn apply_self_unstake(
    state: &mut ChainState,
    bond_utxo_id: Bytes32,
    validator_pubkey: &HybridPubKey,
    current_height: u64,
    identity_registry_active: bool,
) -> StateResult<()> {
    let validator_id = pubkey_to_id(validator_pubkey);
    let validator = state
        .validators
        .get(&validator_id)
        .ok_or(StateError::ValidatorNotFound)?;
    if identity_registry_active {
        check_validator_identity_consistency(state, &validator_id, validator_pubkey)?;
    }
    if !matches!(
        validator.status,
        ValidatorStatus::Active | ValidatorStatus::Registered
    ) {
        return Err(StateError::ValidatorNotActive);
    }

    let mut bond = state
        .staked_bonds
        .get(&bond_utxo_id)
        .cloned()
        .ok_or_else(|| StateError::InvalidStakingOp("self-stake bond not found".into()))?;
    if bond.delegator_id != validator_id {
        return Err(StateError::InvalidStakingOp(
            "bond is not validator self-stake".into(),
        ));
    }
    if bond.validator_id != validator_id {
        return Err(StateError::InvalidStakingOp(
            "bond not staked with this validator".into(),
        ));
    }
    if bond.unbonding_end_epoch.is_some() {
        return Err(StateError::InvalidStakingOp(
            "bond is already unbonding".into(),
        ));
    }

    let current_epoch = epoch_for_height(current_height);
    let unbonding_end = current_epoch + UNBONDING_PERIOD_EPOCHS;
    let amount_spark = bond.amount_spark;
    bond.unbonding_end_epoch = Some(unbonding_end);
    let updated_bond = bond.clone();
    state
        .staked_bonds
        .insert(bond_utxo_id, updated_bond.clone());
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_staked_bond(&bond_utxo_id, &updated_bond);
    }
    let mut updated_validator = None;
    if let Some(v) = state.validators.get_mut(&validator_id) {
        v.stake_spark = v.stake_spark.saturating_sub(amount_spark);
        if matches!(v.status, ValidatorStatus::Active)
            && v.stake_spark < MINIMUM_ACTIVE_SELF_STAKE_SPARK
        {
            eprintln!(
                "[staking] validator {} self-stake {} below active minimum {}; demoting to Registered",
                hex::encode(&validator_id.0[..4]),
                v.stake_spark,
                MINIMUM_ACTIVE_SELF_STAKE_SPARK
            );
            v.status = ValidatorStatus::Registered;
        }
        updated_validator = Some(v.clone());
    }
    if let (Some(commitment), Some(validator)) =
        (state.state_commitment_v2.as_mut(), updated_validator)
    {
        commitment.put_validator(&validator, current_height);
    }
    Ok(())
}

fn check_or_insert_validator_identity(
    state: &mut ChainState,
    validator_id: &Bytes32,
    validator_pubkey: &HybridPubKey,
) -> StateResult<()> {
    if state.delegator_identities.contains_key(validator_id) {
        check_validator_identity_registry_if_present(state, validator_id, validator_pubkey)?;
        return Ok(());
    }
    state
        .delegator_identities
        .insert(*validator_id, validator_pubkey.clone());
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_delegator_identity(validator_id, validator_pubkey);
    }
    Ok(())
}

fn check_validator_identity_registry_if_present(
    state: &ChainState,
    validator_id: &Bytes32,
    validator_pubkey: &HybridPubKey,
) -> StateResult<()> {
    if let Some(registered) = state.delegator_identities.get(validator_id) {
        if registered != validator_pubkey {
            return Err(StateError::InvalidStakingOp(format!(
                "validator identity registry pubkey mismatch for {validator_id}"
            )));
        }
    }
    Ok(())
}

fn check_validator_identity_consistency(
    state: &ChainState,
    validator_id: &Bytes32,
    submitted_pubkey: &HybridPubKey,
) -> StateResult<()> {
    let validator = state
        .validators
        .get(validator_id)
        .ok_or(StateError::ValidatorNotFound)?;
    let matches_validator_key = validator.hybrid_classical_pk
        == Some(submitted_pubkey.classical_pk.0)
        && validator.hybrid_pq_pk.as_deref() == Some(submitted_pubkey.pq_pk.as_slice());
    if !matches_validator_key {
        return Err(StateError::InvalidStakingOp(format!(
            "validator identity stored pubkey mismatch for {validator_id}"
        )));
    }
    if let Some(registered) = state.delegator_identities.get(validator_id) {
        if registered != submitted_pubkey {
            return Err(StateError::InvalidStakingOp(format!(
                "validator identity registry pubkey mismatch for {validator_id}"
            )));
        }
    }
    Ok(())
}

/// Claim pending rewards for a delegator.
///
/// Transfers pending_rewards to the delegator's UTXO set entry.
/// In Phase 3 this will create an actual UTXO output.
/// For now, rewards are zeroed and added to total supply as distributed.
fn apply_claim_rewards(
    state: &mut ChainState,
    validator_id: &Bytes32,
    delegator_pubkey: &HybridPubKey,
    current_height: u64,
    identity_registry_active: bool,
) -> StateResult<()> {
    let delegator_id = pubkey_to_id(delegator_pubkey);

    let delegation_claim = state
        .delegations
        .get_delegators(validator_id)
        .iter()
        .find(|entry| entry.delegator_id == delegator_id)
        .map(|entry| entry.pending_rewards);
    let validator_claim = state
        .validators
        .get(validator_id)
        .filter(|validator| validator.validator_id == delegator_id)
        .map(|validator| validator.pending_rewards);
    let claim_from_validator = delegation_claim.is_none() && validator_claim.is_some();
    let payout_pubkey = if claim_from_validator
        && state
            .validators
            .get(validator_id)
            .is_some_and(|validator| validator.cold_key_status == ColdKeyStatus::Active)
    {
        resolve_active_validator_cold_pubkey(state, validator_id).map_err(|_| {
            StateError::InvariantViolation {
                message: "active validator cold reward owner is unresolvable",
            }
        })?
    } else {
        delegator_pubkey.clone()
    };

    let claimed = delegation_claim
        .or(validator_claim)
        .ok_or(StateError::DelegatorNotFound)?;
    if claimed == 0 {
        return Ok(());
    }
    if claimed < DUST_LIMIT_SPARK {
        return Err(StateError::InvalidStakingOp(format!(
            "rewards {} Spark below dust limit {} Spark",
            claimed, DUST_LIMIT_SPARK
        )));
    }
    let identity_outcome = if identity_registry_active {
        let outcome = resolve_and_check_identity(&delegator_id, delegator_pubkey, state)
            .map_err(identity_error_to_state_error)?;
        if matches!(outcome, IdentityCheckOutcome::NoPriorRecord) {
            check_claim_owner_identity_for_first_record(
                state,
                validator_id,
                &delegator_id,
                delegator_pubkey,
                claim_from_validator,
            )?;
        }
        Some(outcome)
    } else {
        None
    };
    if claim_from_validator {
        let mut updated_validator = None;
        if let Some(validator) = state.validators.get_mut(validator_id) {
            validator.pending_rewards = 0;
            updated_validator = Some(validator.clone());
        }
        if let (Some(commitment), Some(validator)) =
            (state.state_commitment_v2.as_mut(), updated_validator)
        {
            commitment.put_validator(&validator, current_height);
        }
    } else if let Some(updated_entry) =
        state
            .delegations
            .update_delegator(validator_id, &delegator_id, |entry| {
                entry.pending_rewards = 0;
                entry.clone()
            })
    {
        if let Some(commitment) = state.state_commitment_v2.as_mut() {
            commitment.put_delegator(validator_id, &updated_entry);
        }
    }
    if matches!(
        identity_outcome,
        Some(IdentityCheckOutcome::NoPriorRecord | IdentityCheckOutcome::LegacyBondMatch)
    ) {
        state
            .delegator_identities
            .insert(delegator_id, delegator_pubkey.clone());
        if let Some(commitment) = state.state_commitment_v2.as_mut() {
            commitment.put_delegator_identity(&delegator_id, delegator_pubkey);
        }
    }

    let mut blinding_input = Vec::with_capacity(STAKING_REWARD_BLINDING_DOMAIN.len() + 32 + 32 + 8);
    blinding_input.extend_from_slice(STAKING_REWARD_BLINDING_DOMAIN);
    blinding_input.extend_from_slice(&validator_id.0);
    blinding_input.extend_from_slice(&delegator_id.0);
    blinding_input.extend_from_slice(&current_height.to_le_bytes());
    let blinding = indra_crypto::sha256(&blinding_input);
    let commitment = indra_crypto::commit(claimed, &blinding);
    let mut rng = rand::rngs::StdRng::from_seed(blinding);
    let proof = indra_crypto::prove_range(claimed, &blinding, &mut rng).map_err(|_| {
        StateError::InvalidStakingOp("failed to generate range proof for reward UTXO".into())
    })?;

    let output = OutputV1 {
        value_spark: claimed,
        commitment: CommitmentV1 {
            compressed_point: Bytes32::from(commitment.0),
        },
        owner_pubkey: payout_pubkey,
        range_proof: VariableBytes::from_slice(&proof)
            .map_err(|_| StateError::InvalidStakingOp("range proof too large".into()))?,
        lock_height: 0,
    };

    state
        .utxos
        .insert(output, current_height, STAKING_TX_IDX, 0)
        .map_err(|_| StateError::InvariantViolation {
            message: "UTXO ID collision in staking reward output",
        })?;

    Ok(())
}

fn check_claim_owner_identity_for_first_record(
    state: &ChainState,
    validator_id: &Bytes32,
    delegator_id: &Bytes32,
    submitted_pubkey: &HybridPubKey,
    claim_from_validator: bool,
) -> StateResult<()> {
    if claim_from_validator {
        let validator = state
            .validators
            .get(validator_id)
            .ok_or(StateError::ValidatorNotFound)?;
        let matches_validator_key = validator.hybrid_classical_pk
            == Some(submitted_pubkey.classical_pk.0)
            && validator.hybrid_pq_pk.as_deref() == Some(submitted_pubkey.pq_pk.as_slice());
        return if matches_validator_key {
            Ok(())
        } else {
            Err(StateError::InvalidStakingOp(format!(
                "delegator identity validator reward owner pubkey mismatch for {delegator_id}"
            )))
        };
    }

    let mut owner_pubkey: Option<HybridPubKey> = None;
    for bond in state.staked_bonds.values().filter(|bond| {
        bond.validator_id == *validator_id
            && bond.delegator_id == *delegator_id
            && bond.unbonding_end_epoch.is_none()
    }) {
        let resolved_pubkey = resolve_bond_owner_pubkey(bond, state).map_err(|_| {
            StateError::InvalidStakingOp(format!(
                "delegator identity claim owner is unresolvable for {delegator_id}"
            ))
        })?;
        match &owner_pubkey {
            Some(existing) if existing != &resolved_pubkey => {
                return Err(StateError::InvalidStakingOp(format!(
                    "delegator identity has ambiguous claim owner pubkeys for {delegator_id}"
                )));
            }
            Some(_) => {}
            None => owner_pubkey = Some(resolved_pubkey),
        }
    }

    let owner_pubkey = owner_pubkey.ok_or_else(|| {
        StateError::InvalidStakingOp(format!(
            "delegator identity claim owner is unresolvable for {delegator_id}"
        ))
    })?;
    if owner_pubkey != *submitted_pubkey {
        return Err(StateError::InvalidStakingOp(format!(
            "delegator identity claim owner pubkey mismatch for {delegator_id}"
        )));
    }

    Ok(())
}

/// Stage a validator's commission-rate change.
///
/// The new rate does not affect reward distribution until
/// `COMMISSION_CHANGE_DELAY_EPOCHS` epochs have elapsed, giving delegators a
/// small observation/exit window.
fn apply_set_commission(
    state: &mut ChainState,
    validator_id: &Bytes32,
    new_commission_bps: u32,
    current_height: u64,
) -> StateResult<()> {
    if new_commission_bps < MIN_COMMISSION_BPS
        || new_commission_bps > state.governance.params.max_commission_bps
    {
        return Err(StateError::InvalidStakingOp(
            "commission out of governance-set range".into(),
        ));
    }

    let validator = state
        .validators
        .get_mut(validator_id)
        .ok_or(StateError::ValidatorNotFound)?;

    if !matches!(
        validator.status,
        ValidatorStatus::Active | ValidatorStatus::Registered
    ) {
        return Err(StateError::ValidatorNotActive);
    }

    let pending = u16::try_from(new_commission_bps)
        .map_err(|_| StateError::InvalidStakingOp("commission exceeds u16 range".into()))?;
    let effective_epoch =
        epoch_for_height(current_height).saturating_add(COMMISSION_CHANGE_DELAY_EPOCHS);
    validator.pending_commission_bps = Some(pending);
    validator.pending_commission_effective_epoch = Some(effective_epoch);
    let updated_validator = validator.clone();
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_validator(&updated_validator, current_height);
    }
    eprintln!(
        "[staking] validator {} commission change staged: {}bps effective_epoch={}",
        hex::encode(&validator_id.0[..4]),
        new_commission_bps,
        effective_epoch,
    );
    Ok(())
}

fn apply_set_auto_delegate(
    state: &mut ChainState,
    validator_id: Bytes32,
    target_validator_id: Bytes32,
    current_height: u64,
) -> StateResult<()> {
    let validator = state
        .validators
        .get(&validator_id)
        .ok_or(StateError::ValidatorNotFound)?;

    if !matches!(
        validator.status,
        ValidatorStatus::Active | ValidatorStatus::Registered
    ) {
        return Err(StateError::ValidatorNotActive);
    }

    if target_validator_id == Bytes32::ZERO {
        let mut updated_validator = None;
        if let Some(v) = state.validators.get_mut(&validator_id) {
            v.auto_delegate_to = None;
            updated_validator = Some(v.clone());
        }
        if let (Some(commitment), Some(validator)) =
            (state.state_commitment_v2.as_mut(), updated_validator)
        {
            commitment.put_validator(&validator, current_height);
        }
        return Ok(());
    }

    if target_validator_id == validator_id {
        return Err(StateError::InvalidStakingOp(
            "cannot auto-delegate to self".to_string(),
        ));
    }

    if state.validators.get(&target_validator_id).is_none() {
        return Err(StateError::ValidatorNotFound);
    }

    if let Some(v) = state.validators.get_mut(&validator_id) {
        v.auto_delegate_to = Some(target_validator_id);
        let updated_validator = v.clone();
        if let Some(commitment) = state.state_commitment_v2.as_mut() {
            commitment.put_validator(&updated_validator, current_height);
        }
    }
    Ok(())
}

fn apply_update_network_address(
    state: &mut ChainState,
    validator_id: Bytes32,
    network_addr: Option<String>,
    current_height: u64,
) -> StateResult<()> {
    if !validator_network_address_active(current_height) {
        return Err(StateError::InvalidStakingOp(
            "validator network address updates are not active".into(),
        ));
    }
    if let Some(addr) = &network_addr {
        validate_network_addr_string(addr)
            .map_err(|e| StateError::InvalidStakingOp(e.to_string()))?;
    }

    let current_epoch = epoch_for_height(current_height);
    let validator = state
        .validators
        .get_mut(&validator_id)
        .ok_or(StateError::ValidatorNotFound)?;
    if !matches!(
        validator.status,
        ValidatorStatus::Active | ValidatorStatus::Registered
    ) {
        return Err(StateError::ValidatorNotActive);
    }
    if validator.network_addr_last_updated_epoch == Some(current_epoch) {
        return Err(StateError::InvalidStakingOp(
            "validator network address already updated this epoch".into(),
        ));
    }
    validator.network_addr = network_addr;
    validator.network_addr_last_updated_epoch = Some(current_epoch);
    let updated_validator = validator.clone();
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_validator(&updated_validator, current_height);
    }
    Ok(())
}

/// Derive a stable staking identity from a hybrid public key.
///
/// This must match `keys.json`'s canonical `validator_id`/account ID:
/// SHA-256 of the classical public key bytes. Do not hash the encoded
/// hybrid-pubkey object here; that produces a different identity from
/// live genesis validators and makes validator-owned reward claims
/// unreachable for real keys.
fn pubkey_to_id(pubkey: &indra_core::types::crypto::HybridPubKey) -> Bytes32 {
    let hash = indra_crypto::sha256(&pubkey.classical_pk.0);
    Bytes32::from(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain::ChainState,
        validator::{ValidatorEntry, ValidatorStatus},
    };
    use indra_core::codec::Encode;
    use indra_core::types::{
        crypto::{ColdHybridPubKey, CommitmentV1, HybridPubKey, HybridSignature},
        primitives::{
            hard_forks::{
                PAYMENT_BLINDING_HEIGHT, VALIDATOR_COLD_KEY_ENFORCEMENT_HEIGHT,
                VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT,
            },
            VariableBytes,
        },
        transaction::OutputV1,
    };
    use indra_crypto::{
        commit,
        hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
        prove_range, PaymentKeypairV1, PaymentPubKeyV1, PAYMENT_VERSION_V1,
    };
    use rand::{rngs::StdRng, SeedableRng};

    fn keypair(seed: u8) -> HybridKeypair {
        HybridKeypair::new(
            ClassicalKeypair::from_seed(&[seed; 32]),
            PqKeypair::from_seed(&[seed; 32]).unwrap(),
        )
    }

    fn mixed_keypair(classical_seed: u8, pq_seed: u8) -> HybridKeypair {
        HybridKeypair::new(
            ClassicalKeypair::from_seed(&[classical_seed; 32]),
            PqKeypair::from_seed(&[pq_seed; 32]).unwrap(),
        )
    }

    fn pubkey_from_keypair(keypair: &HybridKeypair) -> HybridPubKey {
        let public = keypair.public_key();
        HybridPubKey {
            classical_pk: Bytes32::from(public.classical.0),
            pq_pk: VariableBytes::from_slice(&public.pq.0).unwrap(),
        }
    }

    fn cold_pubkey_from_keypair(keypair: &HybridKeypair) -> ColdHybridPubKey {
        let public = keypair.public_key();
        ColdHybridPubKey {
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

    fn payment_pubkey(seed: u8) -> PaymentPubKeyV1 {
        PaymentKeypairV1 {
            version: PAYMENT_VERSION_V1,
            x25519_sk: [seed; 32],
            ml_kem_1024_seed: [seed.wrapping_add(1); 64],
        }
        .public_key()
    }

    fn test_output(value_spark: u64, owner_pubkey: HybridPubKey, seed: u8) -> OutputV1 {
        let blinding = [seed; 32];
        let commitment = commit(value_spark, &blinding);
        let mut rng = StdRng::from_seed([seed; 32]);
        let proof = prove_range(value_spark, &blinding, &mut rng).unwrap();
        OutputV1 {
            value_spark,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from(commitment.0),
            },
            owner_pubkey,
            range_proof: VariableBytes::from_slice(&proof).unwrap(),
            lock_height: 0,
        }
    }

    fn bond_proof(value_spark: u64, seed: u8) -> StakingBondProof {
        StakingBondProof {
            committed_value_spark: value_spark,
            blinding_factor: Bytes32::from([seed; 32]),
        }
    }

    fn proof_for_bond_utxo(state: &ChainState, bond_utxo_id: Bytes32) -> StakingBondProof {
        let Some(entry) = state.utxos.get(&bond_utxo_id) else {
            return bond_proof(0, 0);
        };
        for seed in 0u8..=u8::MAX {
            let candidate = commit(entry.output.value_spark, &[seed; 32]);
            if candidate.0 == entry.output.commitment.compressed_point.0 {
                return bond_proof(entry.output.value_spark, seed);
            }
        }
        bond_proof(entry.output.value_spark, 0)
    }

    fn insert_delegator_utxo(
        state: &mut ChainState,
        delegator_pubkey: HybridPubKey,
        value_spark: u64,
        seed: u8,
    ) -> Bytes32 {
        state
            .utxos
            .insert(
                test_output(value_spark, delegator_pubkey, seed),
                1,
                0,
                seed as u32,
            )
            .unwrap()
    }

    fn insert_mismatched_public_value_utxo(
        state: &mut ChainState,
        owner_pubkey: HybridPubKey,
        public_value_spark: u64,
        committed_value_spark: u64,
        seed: u8,
    ) -> Bytes32 {
        let blinding = [seed; 32];
        let commitment = commit(committed_value_spark, &blinding);
        let mut rng = StdRng::from_seed([seed; 32]);
        let proof = prove_range(committed_value_spark, &blinding, &mut rng).unwrap();
        state
            .utxos
            .insert(
                OutputV1 {
                    value_spark: public_value_spark,
                    commitment: CommitmentV1 {
                        compressed_point: Bytes32::from(commitment.0),
                    },
                    owner_pubkey,
                    range_proof: VariableBytes::from_slice(&proof).unwrap(),
                    lock_height: 0,
                },
                1,
                0,
                seed as u32,
            )
            .unwrap()
    }

    fn post_gate_registration_fixture(
        hot_keypair: &HybridKeypair,
        cold_keypair: &HybridKeypair,
        bond_seed: u8,
    ) -> (ChainState, Bytes32, StakingOp) {
        let mut state = ChainState::new_genesis();
        state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
        let cold_pubkey = pubkey_from_keypair(cold_keypair);
        let bond_utxo_id = insert_delegator_utxo(
            &mut state,
            cold_pubkey,
            MINIMUM_VALIDATOR_BOND_SPARK,
            bond_seed,
        );
        let op = dual_signed_register_op(
            bond_utxo_id,
            hot_keypair,
            cold_keypair,
            1,
            &state.chain_id,
            [bond_seed.wrapping_add(1); 32],
            bond_seed,
        );
        (state, bond_utxo_id, op)
    }

    fn dummy_signature() -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
        }
    }

    fn signed_op(
        body: StakingOpBody,
        nonce: u64,
        keypair: &HybridKeypair,
        chain_id: &str,
    ) -> StakingOp {
        let mut op = StakingOp {
            body,
            nonce,
            signature: dummy_signature(),
        };
        let sig = keypair.sign(&op.signing_bytes(chain_id)).unwrap();
        op.signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
        };
        op
    }

    fn cold_signed_op(
        body: StakingOpBody,
        cold_keypair: &HybridKeypair,
        chain_id: &str,
    ) -> StakingOp {
        let mut op = StakingOp {
            body,
            nonce: 0,
            signature: dummy_signature(),
        };
        let message = op
            .cold_authorization_signing_bytes(chain_id)
            .unwrap()
            .expect("cold-form operation");
        op.signature = wire_signature(&cold_keypair.sign(&message).unwrap());
        op
    }

    fn cold_auth(nonce: u64) -> Option<indra_core::types::staking::ColdStakingAuthorization> {
        Some(indra_core::types::staking::ColdStakingAuthorization {
            cold_key_version: 1,
            cold_nonce: nonce,
        })
    }

    fn set_cold_auth(body: &mut StakingOpBody, nonce: u64) {
        let slot = match body {
            StakingOpBody::ClaimRewards {
                cold_authorization, ..
            }
            | StakingOpBody::SetCommission {
                cold_authorization, ..
            }
            | StakingOpBody::SelfStake {
                cold_authorization, ..
            }
            | StakingOpBody::SelfUnstake {
                cold_authorization, ..
            }
            | StakingOpBody::SetAutoDelegate {
                cold_authorization, ..
            }
            | StakingOpBody::RegisterPaymentKey {
                cold_authorization, ..
            } => cold_authorization,
            _ => panic!("not a cold-designated staking body"),
        };
        *slot = cold_auth(nonce);
    }

    fn dual_signed_register_op(
        bond_utxo_id: Bytes32,
        hot_keypair: &HybridKeypair,
        cold_keypair: &HybridKeypair,
        nonce: u64,
        chain_id: &str,
        vrf_pk: [u8; 32],
        bond_seed: u8,
    ) -> StakingOp {
        let mut op = StakingOp {
            body: StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id,
                validator_pubkey: pubkey_from_keypair(hot_keypair),
                vrf_pk,
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, bond_seed)),
                cold_pubkey: Some(cold_pubkey_from_keypair(cold_keypair)),
                cold_signature: Some(dummy_signature()),
            },
            nonce,
            signature: dummy_signature(),
        };
        let message = op
            .register_validator_dual_signing_bytes(chain_id)
            .unwrap()
            .unwrap();
        op.signature = wire_signature(&hot_keypair.sign(&message).unwrap());
        let cold_signature = wire_signature(&cold_keypair.sign(&message).unwrap());
        let StakingOpBody::RegisterValidator {
            cold_signature: slot,
            ..
        } = &mut op.body
        else {
            unreachable!()
        };
        *slot = Some(cold_signature);
        op
    }

    fn dual_signed_enroll_op(
        validator_id: Bytes32,
        hot_keypair: &HybridKeypair,
        cold_keypair: &HybridKeypair,
        nonce: u64,
        chain_id: &str,
    ) -> StakingOp {
        let mut op = StakingOp {
            body: StakingOpBody::EnrollValidatorColdKey {
                validator_id,
                cold_pubkey: cold_pubkey_from_keypair(cold_keypair),
                cold_signature: Some(dummy_signature()),
            },
            nonce,
            signature: dummy_signature(),
        };
        let message = op
            .enroll_validator_cold_key_dual_signing_bytes(chain_id)
            .unwrap()
            .unwrap();
        op.signature = wire_signature(&hot_keypair.sign(&message).unwrap());
        let cold_signature = wire_signature(&cold_keypair.sign(&message).unwrap());
        let StakingOpBody::EnrollValidatorColdKey {
            cold_signature: slot,
            ..
        } = &mut op.body
        else {
            unreachable!()
        };
        *slot = Some(cold_signature);
        op
    }

    fn dual_signed_rotate_op(
        validator_id: Bytes32,
        current: &HybridKeypair,
        proposed: &HybridKeypair,
        current_version: u64,
        current_nonce: u64,
        chain_id: &str,
    ) -> StakingOp {
        let mut op = StakingOp {
            body: StakingOpBody::RotateValidatorColdKey {
                validator_id,
                current_cold_key_version: current_version,
                new_cold_key_version: current_version + 1,
                current_cold_nonce: current_nonce,
                new_cold_pubkey: cold_pubkey_from_keypair(proposed),
                new_cold_signature: Some(dummy_signature()),
            },
            nonce: 0,
            signature: dummy_signature(),
        };
        let message = op
            .rotate_validator_cold_key_dual_signing_bytes(chain_id)
            .unwrap()
            .unwrap();
        op.signature = wire_signature(&current.sign(&message).unwrap());
        let proposed_signature = wire_signature(&proposed.sign(&message).unwrap());
        let StakingOpBody::RotateValidatorColdKey {
            new_cold_signature, ..
        } = &mut op.body
        else {
            unreachable!()
        };
        *new_cold_signature = Some(proposed_signature);
        op
    }

    fn state_with_retired_cold_pair(seed: u8) -> (ChainState, HybridKeypair, HybridKeypair) {
        let mut state = ChainState::new_genesis();
        state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
        let (validator_id, hot) = make_active_validator(&mut state, seed);
        let old = mixed_keypair(seed.wrapping_add(1), seed.wrapping_add(2));
        let replacement = mixed_keypair(seed.wrapping_add(3), seed.wrapping_add(4));
        let chain_id = state.chain_id.clone();
        let height = state.height;
        let enroll = dual_signed_enroll_op(validator_id, &hot, &old, 1, &chain_id);
        apply_staking_op(&mut state, &enroll, &chain_id, height).unwrap();
        let rotate = dual_signed_rotate_op(validator_id, &old, &replacement, 1, 1, &chain_id);
        apply_staking_op(&mut state, &rotate, &chain_id, height).unwrap();
        (state, old, replacement)
    }

    fn activate_cold_for_test(state: &mut ChainState, validator_id: Bytes32, cold: &HybridKeypair) {
        let public = cold.public_key();
        let validator = state.validators.get_mut(&validator_id).unwrap();
        validator.cold_hybrid_classical_pk = Some(public.classical.0);
        validator.cold_hybrid_pq_pk = Some(public.pq.0);
        validator.cold_key_version = 1;
        validator.cold_key_status = ColdKeyStatus::Active;
        validator.cold_nonce = 0;
    }

    fn make_active_validator(state: &mut ChainState, seed: u8) -> (Bytes32, HybridKeypair) {
        let keypair = keypair(seed);
        let pubkey = pubkey_from_keypair(&keypair);
        let validator_id = pubkey_to_id(&pubkey);
        insert_active_validator_with_pubkey(state, validator_id, &pubkey, seed);
        (validator_id, keypair)
    }

    fn insert_active_validator_with_pubkey(
        state: &mut ChainState,
        validator_id: Bytes32,
        pubkey: &HybridPubKey,
        seed: u8,
    ) {
        let entry = ValidatorEntry {
            validator_id,
            name: format!("validator-{seed}"),
            hybrid_classical_pk: Some(pubkey.classical_pk.0),
            hybrid_pq_pk: Some(pubkey.pq_pk.as_slice().to_vec()),
            vrf_pk: Some([seed; 32]),
            stake_spark: 10_000_000_000,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            pending_rewards: 0,
            rewards_last_epoch: 0,
            self_report_count: 0,
            commission_bps: 1_000,
            pending_commission_bps: None,
            pending_commission_effective_epoch: None,
            min_delegation_spark: indra_core::types::primitives::DUST_LIMIT_SPARK,
            auto_delegate_to: None,
            network_addr: None,
            network_addr_last_updated_epoch: None,
            cold_hybrid_classical_pk: None,
            cold_hybrid_pq_pk: None,
            cold_key_version: 0,
            cold_key_status: crate::validator::ColdKeyStatus::Unenrolled,
            cold_nonce: 0,
        };
        state.validators.upsert(entry).unwrap();
    }

    #[test]
    fn staking_bond_proof_accepts_correct_opening() {
        let owner = pubkey_from_keypair(&keypair(0xE1));
        let output = test_output(1_000, owner, 0xE1);
        assert!(validate_staking_bond_proof(&output, &bond_proof(1_000, 0xE1)).is_ok());
    }

    #[test]
    fn staking_bond_proof_rejects_wrong_blinding() {
        let owner = pubkey_from_keypair(&keypair(0xE2));
        let output = test_output(1_000, owner, 0xE2);
        assert_eq!(
            validate_staking_bond_proof(&output, &bond_proof(1_000, 0xE3)),
            Err(StateError::StakingBondCommitmentMismatch)
        );
    }

    #[test]
    fn staking_bond_proof_rejects_committed_value_mismatch() {
        let owner = pubkey_from_keypair(&keypair(0xE4));
        let output = test_output(1_000, owner, 0xE4);
        assert_eq!(
            validate_staking_bond_proof(&output, &bond_proof(999, 0xE4)),
            Err(StateError::StakingBondCommitmentMismatch)
        );
    }

    #[test]
    fn st03_attack_is_closed() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0xE5);
        let delegator_keypair = keypair(0xE6);
        let pubkey = pubkey_from_keypair(&delegator_keypair);
        let bond_utxo_id =
            insert_mismatched_public_value_utxo(&mut state, pubkey, 100, 1_000_000, 0xE7);

        let chain_id = state.chain_id.clone();
        let correct_opening_wrong_public = signed_op(
            StakingOpBody::Delegate {
                validator_id,
                bond_utxo_id,
                delegator_pubkey: pubkey_from_keypair(&delegator_keypair),
                bond_proof: Some(bond_proof(1_000_000, 0xE7)),
            },
            1,
            &delegator_keypair,
            &state.chain_id,
        );
        assert_eq!(
            apply_staking_op(&mut state, &correct_opening_wrong_public, &chain_id, 1),
            Err(StateError::StakingBondValueMismatch {
                public_value: 100,
                committed_value: 1_000_000,
            })
        );
        assert!(state.utxos.contains(&bond_utxo_id));

        let public_value_wrong_opening = signed_op(
            StakingOpBody::Delegate {
                validator_id,
                bond_utxo_id,
                delegator_pubkey: pubkey_from_keypair(&delegator_keypair),
                bond_proof: Some(bond_proof(100, 0xE7)),
            },
            1,
            &delegator_keypair,
            &state.chain_id,
        );
        assert_eq!(
            apply_staking_op(&mut state, &public_value_wrong_opening, &chain_id, 1),
            Err(StateError::StakingBondCommitmentMismatch)
        );
        assert!(state.utxos.contains(&bond_utxo_id));
        assert!(!state.staked_bonds.contains_key(&bond_utxo_id));
    }

    fn delegate_op(
        state: &ChainState,
        validator_id: Bytes32,
        bond_utxo_id: Bytes32,
        delegator_keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        let bond_proof = proof_for_bond_utxo(state, bond_utxo_id);
        signed_op(
            StakingOpBody::Delegate {
                validator_id,
                bond_utxo_id,
                delegator_pubkey: pubkey_from_keypair(delegator_keypair),
                bond_proof: Some(bond_proof),
            },
            nonce,
            delegator_keypair,
            &state.chain_id,
        )
    }

    fn undelegate_op(
        state: &ChainState,
        validator_id: Bytes32,
        bond_utxo_id: Bytes32,
        delegator_keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        signed_op(
            StakingOpBody::Undelegate {
                validator_id,
                bond_utxo_id,
                delegator_pubkey: pubkey_from_keypair(delegator_keypair),
            },
            nonce,
            delegator_keypair,
            &state.chain_id,
        )
    }

    fn claim_rewards_op(
        state: &ChainState,
        validator_id: Bytes32,
        delegator_keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        signed_op(
            StakingOpBody::ClaimRewards {
                validator_id,
                delegator_pubkey: pubkey_from_keypair(delegator_keypair),
                cold_authorization: None,
            },
            nonce,
            delegator_keypair,
            &state.chain_id,
        )
    }

    fn self_stake_op(
        state: &ChainState,
        bond_utxo_id: Bytes32,
        validator_keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        let bond_proof = proof_for_bond_utxo(state, bond_utxo_id);
        signed_op(
            StakingOpBody::SelfStake {
                bond_utxo_id,
                validator_pubkey: pubkey_from_keypair(validator_keypair),
                bond_proof: Some(bond_proof),
                cold_authorization: None,
            },
            nonce,
            validator_keypair,
            &state.chain_id,
        )
    }

    fn self_unstake_op(
        state: &ChainState,
        bond_utxo_id: Bytes32,
        validator_keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        signed_op(
            StakingOpBody::SelfUnstake {
                bond_utxo_id,
                validator_pubkey: pubkey_from_keypair(validator_keypair),
                cold_authorization: None,
            },
            nonce,
            validator_keypair,
            &state.chain_id,
        )
    }

    fn set_auto_delegate_op(
        state: &ChainState,
        validator_id: Bytes32,
        target_validator_id: Bytes32,
        validator_keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        signed_op(
            StakingOpBody::SetAutoDelegate {
                validator_id,
                target_validator_id,
                cold_authorization: None,
            },
            nonce,
            validator_keypair,
            &state.chain_id,
        )
    }

    fn set_commission_op(
        state: &ChainState,
        validator_id: Bytes32,
        new_commission_bps: u32,
        validator_keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        signed_op(
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps,
                cold_authorization: None,
            },
            nonce,
            validator_keypair,
            &state.chain_id,
        )
    }

    #[test]
    fn delegate_bonds_utxo_and_removes_from_spendable() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&delegator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 1_000_000, 0x10);

        let op = delegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 1);
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &op, &chain_id, 1).unwrap();

        assert!(!state.utxos.contains(&bond_utxo_id));
        assert!(state.staked_bonds.contains_key(&bond_utxo_id));
        assert_eq!(state.delegations.total_delegated(&validator_id), 1_000_000);
    }

    #[test]
    fn delegate_pre_identity_gate_does_not_populate_registry() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x24);
        let delegator_keypair = keypair(0x25);
        let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        let bond_utxo_id = insert_delegator_utxo(&mut state, delegator_pubkey, 1_000_000, 0x25);
        let op = delegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 1);
        let chain_id = state.chain_id.clone();

        apply_staking_op_with_identity_activation(&mut state, &op, &chain_id, 1, false).unwrap();

        assert!(!state.delegator_identities.contains_key(&delegator_id));
        assert!(state.staked_bonds.contains_key(&bond_utxo_id));
    }

    #[test]
    fn delegate_post_identity_gate_new_identity_succeeds_and_populates_registry() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x26);
        let delegator_keypair = keypair(0x27);
        let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        let bond_utxo_id =
            insert_delegator_utxo(&mut state, delegator_pubkey.clone(), 1_000_000, 0x27);
        state.rebuild_state_commitment_v2(u64::MAX);
        let op = delegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 1);
        let chain_id = state.chain_id.clone();

        apply_staking_op_with_identity_activation(&mut state, &op, &chain_id, 1, true).unwrap();

        assert_eq!(
            state.delegator_identities.get(&delegator_id),
            Some(&delegator_pubkey)
        );
        assert!(state.staked_bonds.contains_key(&bond_utxo_id));
        let warm_root = state.state_commitment_v2_root(u64::MAX);
        state.rebuild_state_commitment_v2(u64::MAX);
        assert_eq!(state.state_commitment_v2_root(u64::MAX), warm_root);
    }

    #[test]
    fn delegate_post_identity_gate_registered_match_succeeds_without_changing_registry() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x28);
        let delegator_keypair = keypair(0x29);
        let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        state
            .delegator_identities
            .insert(delegator_id, delegator_pubkey.clone());
        let before = state.delegator_identities.clone();
        let bond_utxo_id =
            insert_delegator_utxo(&mut state, delegator_pubkey.clone(), 1_000_000, 0x29);
        let op = delegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 1);
        let chain_id = state.chain_id.clone();

        apply_staking_op_with_identity_activation(&mut state, &op, &chain_id, 1, true).unwrap();

        assert_eq!(state.delegator_identities, before);
        assert!(state.staked_bonds.contains_key(&bond_utxo_id));
    }

    #[test]
    fn delegate_post_identity_gate_rejects_classical_key_only_pq_substitution_attack() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x2A);
        let legitimate_keypair = mixed_keypair(0x2B, 0x2C);
        let legitimate_pubkey = pubkey_from_keypair(&legitimate_keypair);
        let delegator_id = pubkey_to_id(&legitimate_pubkey);
        state
            .delegator_identities
            .insert(delegator_id, legitimate_pubkey);

        let attacker_keypair = mixed_keypair(0x2B, 0x2D);
        let attacker_pubkey = pubkey_from_keypair(&attacker_keypair);
        assert_eq!(pubkey_to_id(&attacker_pubkey), delegator_id);
        let bond_utxo_id = insert_delegator_utxo(&mut state, attacker_pubkey, 1_000_000, 0x2D);
        let op = delegate_op(&state, validator_id, bond_utxo_id, &attacker_keypair, 1);
        let chain_id = state.chain_id.clone();

        let err = apply_staking_op_with_identity_activation(&mut state, &op, &chain_id, 1, true)
            .unwrap_err();
        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("delegator identity registry pubkey mismatch")
        ));
        assert!(state.utxos.contains(&bond_utxo_id));
        assert!(!state.staked_bonds.contains_key(&bond_utxo_id));
    }

    #[test]
    fn delegate_post_identity_gate_legacy_bonds_matching_submitted_key_populate_registry() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x2E);
        let delegator_keypair = keypair(0x2F);
        let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        let first_bond =
            insert_delegator_utxo(&mut state, delegator_pubkey.clone(), 1_000_000, 0x2F);
        let first = delegate_op(&state, validator_id, first_bond, &delegator_keypair, 1);
        let chain_id = state.chain_id.clone();
        apply_staking_op_with_identity_activation(&mut state, &first, &chain_id, 1, false).unwrap();
        assert!(state.delegator_identities.is_empty());

        let second_bond =
            insert_delegator_utxo(&mut state, delegator_pubkey.clone(), 1_000_000, 0x30);
        let second = delegate_op(&state, validator_id, second_bond, &delegator_keypair, 2);
        apply_staking_op_with_identity_activation(&mut state, &second, &chain_id, 1, true).unwrap();

        assert_eq!(
            state.delegator_identities.get(&delegator_id),
            Some(&delegator_pubkey)
        );
        assert!(state.staked_bonds.contains_key(&second_bond));
    }

    #[test]
    fn delegate_post_identity_gate_rejects_conflicting_legacy_bonds_even_if_submitted_matches_one()
    {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x31);
        let first_keypair = mixed_keypair(0x32, 0x33);
        let first_pubkey = pubkey_from_keypair(&first_keypair);
        let second_keypair = mixed_keypair(0x32, 0x34);
        let second_pubkey = pubkey_from_keypair(&second_keypair);
        let delegator_id = pubkey_to_id(&first_pubkey);
        assert_eq!(pubkey_to_id(&second_pubkey), delegator_id);

        let first_legacy = StakeBondEntry::new_for_test_with_compact_activation(
            Bytes32::from([0xA1; 32]),
            validator_id,
            delegator_id,
            1_000_000,
            0,
            test_output(1_000_000, first_pubkey.clone(), 0x31),
            0,
            u64::MAX,
        );
        let second_legacy = StakeBondEntry::new_for_test_with_compact_activation(
            Bytes32::from([0xA2; 32]),
            validator_id,
            delegator_id,
            1_000_000,
            0,
            test_output(1_000_000, second_pubkey, 0x32),
            0,
            u64::MAX,
        );
        state
            .staked_bonds
            .insert(first_legacy.utxo_id, first_legacy);
        state
            .staked_bonds
            .insert(second_legacy.utxo_id, second_legacy);

        let bond_utxo_id = insert_delegator_utxo(&mut state, first_pubkey, 1_000_000, 0x33);
        let op = delegate_op(&state, validator_id, bond_utxo_id, &first_keypair, 1);
        let chain_id = state.chain_id.clone();

        let err = apply_staking_op_with_identity_activation(&mut state, &op, &chain_id, 1, true)
            .unwrap_err();
        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("delegator identity has ambiguous legacy pubkeys")
        ));
        assert!(state.utxos.contains(&bond_utxo_id));
        assert!(!state.delegator_identities.contains_key(&delegator_id));
    }

    #[test]
    fn delegate_without_proof_fails_at_activation() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&delegator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 1_000_000, 0x18);

        let op = signed_op(
            StakingOpBody::Delegate {
                validator_id,
                bond_utxo_id,
                delegator_pubkey: pubkey_from_keypair(&delegator_keypair),
                bond_proof: None,
            },
            1,
            &delegator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::BondProofRequired)
        );
        assert!(state.utxos.contains(&bond_utxo_id));
    }

    #[test]
    fn delegate_mismatch_does_not_spend_utxo() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&delegator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 1_000_000, 0x19);

        let op = signed_op(
            StakingOpBody::Delegate {
                validator_id,
                bond_utxo_id,
                delegator_pubkey: pubkey_from_keypair(&delegator_keypair),
                bond_proof: Some(bond_proof(1_000_000, 0x1A)),
            },
            1,
            &delegator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::StakingBondCommitmentMismatch)
        );
        assert!(state.utxos.contains(&bond_utxo_id));
        assert!(!state.staked_bonds.contains_key(&bond_utxo_id));
    }

    #[test]
    fn delegate_rejects_mismatched_public_value_commitment() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&delegator_keypair);
        let bond_utxo_id =
            insert_mismatched_public_value_utxo(&mut state, pubkey, 1_000_000, 500_000, 0x30);

        let op = delegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 1);
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::StakingBondCommitmentMismatch)
        );
        assert!(state.utxos.contains(&bond_utxo_id));
        assert!(!state.staked_bonds.contains_key(&bond_utxo_id));
    }

    #[test]
    fn register_validator_rejects_mismatched_public_value_commitment() {
        let mut state = ChainState::new_genesis();
        let validator_keypair = keypair(0x20);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let validator_id = pubkey_to_id(&validator_pubkey);
        let bond_utxo_id = insert_mismatched_public_value_utxo(
            &mut state,
            validator_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            MINIMUM_VALIDATOR_BOND_SPARK / 2,
            0x21,
        );

        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id,
                validator_pubkey,
                vrf_pk: [0x20; 32],
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK / 2, 0x21)),
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::StakingBondValueMismatch {
                public_value: MINIMUM_VALIDATOR_BOND_SPARK,
                committed_value: MINIMUM_VALIDATOR_BOND_SPARK / 2,
            })
        );
        assert!(state.utxos.contains(&bond_utxo_id));
        assert!(state.validators.get(&validator_id).is_none());
    }

    #[test]
    fn self_stake_rejects_mismatched_public_value_commitment() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0x22);
        state.validators.get_mut(&validator_id).unwrap().stake_spark = 0;
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let bond_utxo_id = insert_mismatched_public_value_utxo(
            &mut state,
            validator_pubkey,
            2_000_000,
            1_000_000,
            0x23,
        );

        let op = signed_op(
            StakingOpBody::SelfStake {
                bond_utxo_id,
                validator_pubkey: pubkey_from_keypair(&validator_keypair),
                bond_proof: Some(bond_proof(1_000_000, 0x23)),
                cold_authorization: None,
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::StakingBondValueMismatch {
                public_value: 2_000_000,
                committed_value: 1_000_000,
            })
        );
        assert!(state.utxos.contains(&bond_utxo_id));
        assert!(!state.staked_bonds.contains_key(&bond_utxo_id));
    }

    #[test]
    fn commission_change_is_not_immediate() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0x41);
        let original_commission = state.validators.get(&validator_id).unwrap().commission_bps;

        let op = set_commission_op(&state, validator_id, 1_500, &validator_keypair, 1);
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &op, &chain_id, 1).unwrap();

        let validator = state.validators.get(&validator_id).unwrap();
        assert_eq!(
            validator.commission_bps, original_commission,
            "commission changes must be staged, not applied immediately"
        );
        assert_eq!(validator.pending_commission_bps, Some(1_500));
        assert_eq!(
            validator.pending_commission_effective_epoch,
            Some(COMMISSION_CHANGE_DELAY_EPOCHS)
        );
    }

    #[test]
    fn delegate_rejects_unknown_utxo() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);

        let op = delegate_op(
            &state,
            validator_id,
            Bytes32::from([0xFF; 32]),
            &delegator_keypair,
            1,
        );
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::UnknownUtxo)
        );
    }

    #[test]
    fn delegate_rejects_wrong_owner() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let wrong_owner = pubkey_from_keypair(&keypair(0x03));
        let bond_utxo_id = insert_delegator_utxo(&mut state, wrong_owner, 1_000_000, 0x11);

        let op = delegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 1);
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::InvalidStakingOp(_))
        ));
    }

    #[test]
    fn delegate_rejects_already_bonded_utxo() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&delegator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 1_000_000, 0x12);

        let first = delegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 1);
        let second = delegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 2);
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &first, &chain_id, 1).unwrap();
        assert!(matches!(
            apply_staking_op(&mut state, &second, &chain_id, 1),
            Err(StateError::InvalidStakingOp(_))
        ));
    }

    #[test]
    fn delegate_rejects_below_minimum() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        state
            .validators
            .get_mut(&validator_id)
            .unwrap()
            .min_delegation_spark = 2_000_000;
        let delegator_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&delegator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 1_000_000, 0x13);

        let op = delegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 1);
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::InvalidStakingOp(_))
        ));
    }

    #[test]
    fn undelegate_sets_unbonding_epoch() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&delegator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 1_000_000, 0x14);

        let chain_id = state.chain_id.clone();
        let delegate = delegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 1);
        apply_staking_op(&mut state, &delegate, &chain_id, 1).unwrap();
        let undelegate = undelegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 2);
        apply_staking_op(&mut state, &undelegate, &chain_id, 1).unwrap();

        assert_eq!(
            state
                .staked_bonds
                .get(&bond_utxo_id)
                .unwrap()
                .unbonding_end_epoch,
            Some(UNBONDING_PERIOD_EPOCHS)
        );
        assert_eq!(state.delegations.total_delegated(&validator_id), 0);
    }

    #[test]
    fn undelegate_pre_identity_gate_ignores_registry_mismatch_and_behaves_as_before() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x35);
        let legitimate_keypair = mixed_keypair(0x36, 0x37);
        let legitimate_pubkey = pubkey_from_keypair(&legitimate_keypair);
        let attacker_keypair = mixed_keypair(0x36, 0x38);
        let attacker_pubkey = pubkey_from_keypair(&attacker_keypair);
        let delegator_id = pubkey_to_id(&legitimate_pubkey);
        assert_eq!(pubkey_to_id(&attacker_pubkey), delegator_id);
        state
            .delegator_identities
            .insert(delegator_id, legitimate_pubkey.clone());

        let bond_utxo_id = insert_delegator_utxo(&mut state, legitimate_pubkey, 1_000_000, 0x35);
        let chain_id = state.chain_id.clone();
        let delegate = delegate_op(&state, validator_id, bond_utxo_id, &legitimate_keypair, 1);
        apply_staking_op_with_identity_activation(&mut state, &delegate, &chain_id, 1, false)
            .unwrap();

        let undelegate = undelegate_op(&state, validator_id, bond_utxo_id, &attacker_keypair, 2);
        apply_staking_op_with_identity_activation(&mut state, &undelegate, &chain_id, 1, false)
            .unwrap();

        assert_eq!(
            state
                .staked_bonds
                .get(&bond_utxo_id)
                .and_then(|bond| bond.unbonding_end_epoch),
            Some(UNBONDING_PERIOD_EPOCHS)
        );
    }

    #[test]
    fn undelegate_post_identity_gate_registered_match_succeeds_without_changing_registry() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x39);
        let delegator_keypair = keypair(0x3A);
        let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        state
            .delegator_identities
            .insert(delegator_id, delegator_pubkey.clone());

        let bond_utxo_id = insert_delegator_utxo(&mut state, delegator_pubkey, 1_000_000, 0x39);
        let chain_id = state.chain_id.clone();
        let delegate = delegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 1);
        apply_staking_op_with_identity_activation(&mut state, &delegate, &chain_id, 1, true)
            .unwrap();
        let before = state.delegator_identities.clone();

        let undelegate = undelegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 2);
        apply_staking_op_with_identity_activation(&mut state, &undelegate, &chain_id, 1, true)
            .unwrap();

        assert_eq!(state.delegator_identities, before);
        assert_eq!(
            state
                .staked_bonds
                .get(&bond_utxo_id)
                .and_then(|bond| bond.unbonding_end_epoch),
            Some(UNBONDING_PERIOD_EPOCHS)
        );
    }

    #[test]
    fn undelegate_post_identity_gate_rejects_classical_key_only_pq_substitution_attack() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x3B);
        let legitimate_keypair = mixed_keypair(0x3C, 0x3D);
        let legitimate_pubkey = pubkey_from_keypair(&legitimate_keypair);
        let delegator_id = pubkey_to_id(&legitimate_pubkey);
        state
            .delegator_identities
            .insert(delegator_id, legitimate_pubkey.clone());
        let attacker_keypair = mixed_keypair(0x3C, 0x3E);
        let attacker_pubkey = pubkey_from_keypair(&attacker_keypair);
        assert_eq!(pubkey_to_id(&attacker_pubkey), delegator_id);

        let bond_utxo_id =
            insert_delegator_utxo(&mut state, legitimate_pubkey.clone(), 1_000_000, 0x3B);
        let chain_id = state.chain_id.clone();
        let delegate = delegate_op(&state, validator_id, bond_utxo_id, &legitimate_keypair, 1);
        apply_staking_op_with_identity_activation(&mut state, &delegate, &chain_id, 1, true)
            .unwrap();

        let mut before_attack_reference = state.clone();
        let attack = signed_op(
            StakingOpBody::Undelegate {
                validator_id,
                bond_utxo_id,
                delegator_pubkey: attacker_pubkey,
            },
            2,
            &attacker_keypair,
            &state.chain_id,
        );
        apply_staking_op_with_identity_activation(
            &mut before_attack_reference,
            &attack,
            &chain_id,
            1,
            false,
        )
        .unwrap();
        assert_eq!(
            before_attack_reference
                .staked_bonds
                .get(&bond_utxo_id)
                .and_then(|bond| bond.unbonding_end_epoch),
            Some(UNBONDING_PERIOD_EPOCHS)
        );

        let err =
            apply_staking_op_with_identity_activation(&mut state, &attack, &chain_id, 1, true)
                .unwrap_err();
        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("delegator identity registry pubkey mismatch")
        ));
        assert_eq!(
            state
                .staked_bonds
                .get(&bond_utxo_id)
                .and_then(|bond| bond.unbonding_end_epoch),
            None
        );
    }

    #[test]
    fn undelegate_post_identity_gate_legacy_bonds_matching_submitted_key_populate_registry() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x3F);
        let delegator_keypair = keypair(0x40);
        let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        let bond_utxo_id =
            insert_delegator_utxo(&mut state, delegator_pubkey.clone(), 1_000_000, 0x3F);
        let chain_id = state.chain_id.clone();
        let delegate = delegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 1);
        apply_staking_op_with_identity_activation(&mut state, &delegate, &chain_id, 1, false)
            .unwrap();
        assert!(state.delegator_identities.is_empty());

        let undelegate = undelegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 2);
        apply_staking_op_with_identity_activation(&mut state, &undelegate, &chain_id, 1, true)
            .unwrap();

        assert_eq!(
            state.delegator_identities.get(&delegator_id),
            Some(&delegator_pubkey)
        );
        assert_eq!(
            state
                .staked_bonds
                .get(&bond_utxo_id)
                .and_then(|bond| bond.unbonding_end_epoch),
            Some(UNBONDING_PERIOD_EPOCHS)
        );
    }

    #[test]
    fn undelegate_post_identity_gate_compact_bond_no_prior_record_populates_when_owner_matches() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x43);
        let delegator_keypair = keypair(0x44);
        let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        let bond_utxo_id = Bytes32::from([0x44; 32]);
        let compact_bond = StakeBondEntry::new_for_test_with_compact_activation(
            bond_utxo_id,
            validator_id,
            delegator_id,
            1_000_000,
            0,
            test_output(1_000_000, delegator_pubkey.clone(), 0x44),
            2,
            1,
        );
        assert!(compact_bond.original_output.range_proof.is_none());
        state.staked_bonds.insert(bond_utxo_id, compact_bond);
        state
            .delegations
            .add_delegation(validator_id, delegator_id, 1_000_000, 0)
            .unwrap();
        let chain_id = state.chain_id.clone();

        let undelegate = undelegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 1);
        apply_staking_op_with_identity_activation(&mut state, &undelegate, &chain_id, 2, true)
            .unwrap();

        assert_eq!(
            state.delegator_identities.get(&delegator_id),
            Some(&delegator_pubkey)
        );
        assert_eq!(
            state
                .staked_bonds
                .get(&bond_utxo_id)
                .and_then(|bond| bond.unbonding_end_epoch),
            Some(UNBONDING_PERIOD_EPOCHS)
        );
    }

    #[test]
    fn undelegate_post_identity_gate_compact_bond_no_prior_record_rejects_owner_mismatch() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x45);
        let legitimate_keypair = mixed_keypair(0x46, 0x47);
        let legitimate_pubkey = pubkey_from_keypair(&legitimate_keypair);
        let attacker_keypair = mixed_keypair(0x46, 0x48);
        let attacker_pubkey = pubkey_from_keypair(&attacker_keypair);
        let delegator_id = pubkey_to_id(&legitimate_pubkey);
        assert_eq!(pubkey_to_id(&attacker_pubkey), delegator_id);
        let bond_utxo_id = Bytes32::from([0x46; 32]);
        let compact_bond = StakeBondEntry::new_for_test_with_compact_activation(
            bond_utxo_id,
            validator_id,
            delegator_id,
            1_000_000,
            0,
            test_output(1_000_000, legitimate_pubkey, 0x46),
            2,
            1,
        );
        assert!(compact_bond.original_output.range_proof.is_none());
        state.staked_bonds.insert(bond_utxo_id, compact_bond);
        state
            .delegations
            .add_delegation(validator_id, delegator_id, 1_000_000, 0)
            .unwrap();
        let chain_id = state.chain_id.clone();

        let undelegate = undelegate_op(&state, validator_id, bond_utxo_id, &attacker_keypair, 1);
        let err =
            apply_staking_op_with_identity_activation(&mut state, &undelegate, &chain_id, 2, true)
                .unwrap_err();

        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("delegator identity bond owner pubkey mismatch")
        ));
        assert_eq!(
            state
                .staked_bonds
                .get(&bond_utxo_id)
                .and_then(|bond| bond.unbonding_end_epoch),
            None
        );
        assert!(!state.delegator_identities.contains_key(&delegator_id));
    }

    #[test]
    fn undelegate_post_identity_gate_rejects_conflicting_legacy_bonds_even_if_submitted_matches_one(
    ) {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x41);
        let first_keypair = mixed_keypair(0x42, 0x43);
        let first_pubkey = pubkey_from_keypair(&first_keypair);
        let second_keypair = mixed_keypair(0x42, 0x44);
        let second_pubkey = pubkey_from_keypair(&second_keypair);
        let delegator_id = pubkey_to_id(&first_pubkey);
        assert_eq!(pubkey_to_id(&second_pubkey), delegator_id);

        let first_bond = insert_delegator_utxo(&mut state, first_pubkey.clone(), 1_000_000, 0x41);
        let second_bond = insert_delegator_utxo(&mut state, second_pubkey.clone(), 1_000_000, 0x42);
        let chain_id = state.chain_id.clone();
        let first_delegate = delegate_op(&state, validator_id, first_bond, &first_keypair, 1);
        apply_staking_op_with_identity_activation(&mut state, &first_delegate, &chain_id, 1, false)
            .unwrap();
        let second_delegate = delegate_op(&state, validator_id, second_bond, &second_keypair, 2);
        apply_staking_op_with_identity_activation(
            &mut state,
            &second_delegate,
            &chain_id,
            1,
            false,
        )
        .unwrap();

        let undelegate = undelegate_op(&state, validator_id, first_bond, &first_keypair, 3);
        let err =
            apply_staking_op_with_identity_activation(&mut state, &undelegate, &chain_id, 1, true)
                .unwrap_err();
        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("delegator identity has ambiguous legacy pubkeys")
        ));
        assert_eq!(
            state
                .staked_bonds
                .get(&first_bond)
                .and_then(|bond| bond.unbonding_end_epoch),
            None
        );
        assert!(!state.delegator_identities.contains_key(&delegator_id));
    }

    #[test]
    fn undelegate_rejects_wrong_delegator() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let wrong_keypair = keypair(0x03);
        let pubkey = pubkey_from_keypair(&delegator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 1_000_000, 0x15);

        let chain_id = state.chain_id.clone();
        let delegate = delegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 1);
        apply_staking_op(&mut state, &delegate, &chain_id, 1).unwrap();
        let undelegate = undelegate_op(&state, validator_id, bond_utxo_id, &wrong_keypair, 1);

        assert!(matches!(
            apply_staking_op(&mut state, &undelegate, &chain_id, 1),
            Err(StateError::InvalidStakingOp(_))
        ));
    }

    #[test]
    fn undelegate_rejects_already_unbonding() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&delegator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 1_000_000, 0x16);

        let chain_id = state.chain_id.clone();
        let delegate = delegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 1);
        apply_staking_op(&mut state, &delegate, &chain_id, 1).unwrap();
        let first = undelegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 2);
        let second = undelegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 3);
        apply_staking_op(&mut state, &first, &chain_id, 1).unwrap();

        assert!(matches!(
            apply_staking_op(&mut state, &second, &chain_id, 1),
            Err(StateError::InvalidStakingOp(_))
        ));
    }

    #[test]
    fn self_stake_bonds_validator_utxo_and_increases_stake() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0x01);
        state.validators.get_mut(&validator_id).unwrap().stake_spark = 0;
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 2_000_000, 0x30);

        let op = self_stake_op(&state, bond_utxo_id, &validator_keypair, 1);
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &op, &chain_id, 1).unwrap();

        assert!(!state.utxos.contains(&bond_utxo_id));
        let bond = state.staked_bonds.get(&bond_utxo_id).unwrap();
        assert_eq!(bond.validator_id, validator_id);
        assert_eq!(bond.delegator_id, validator_id);
        assert_eq!(bond.amount_spark, 2_000_000);
        assert_eq!(
            state.validators.get(&validator_id).unwrap().stake_spark,
            2_000_000
        );
    }

    #[test]
    fn validator_self_stake_pre_identity_gate_accepts_same_classical_different_pq_pubkey() {
        let mut state = ChainState::new_genesis();
        let legitimate_keypair = mixed_keypair(0x51, 0x52);
        let attacker_keypair = mixed_keypair(0x51, 0x53);
        let legitimate_pubkey = pubkey_from_keypair(&legitimate_keypair);
        let attacker_pubkey = pubkey_from_keypair(&attacker_keypair);
        let validator_id = pubkey_to_id(&legitimate_pubkey);
        assert_eq!(pubkey_to_id(&attacker_pubkey), validator_id);
        insert_active_validator_with_pubkey(&mut state, validator_id, &legitimate_pubkey, 0x51);
        state.validators.get_mut(&validator_id).unwrap().stake_spark = 0;
        let bond_utxo_id = insert_delegator_utxo(&mut state, legitimate_pubkey, 2_000_000, 0x51);
        let op = signed_op(
            StakingOpBody::SelfStake {
                bond_utxo_id,
                validator_pubkey: attacker_pubkey,
                bond_proof: Some(bond_proof(2_000_000, 0x51)),
                cold_authorization: None,
            },
            1,
            &attacker_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();

        apply_staking_op_with_identity_activation(&mut state, &op, &chain_id, 0, false).unwrap();

        assert!(state.staked_bonds.contains_key(&bond_utxo_id));
        assert!(state.delegator_identities.is_empty());
    }

    #[test]
    fn validator_self_stake_post_identity_gate_rejects_same_classical_different_pq_pubkey() {
        let mut state = ChainState::new_genesis();
        let legitimate_keypair = mixed_keypair(0x54, 0x55);
        let attacker_keypair = mixed_keypair(0x54, 0x56);
        let legitimate_pubkey = pubkey_from_keypair(&legitimate_keypair);
        let attacker_pubkey = pubkey_from_keypair(&attacker_keypair);
        let validator_id = pubkey_to_id(&legitimate_pubkey);
        assert_eq!(pubkey_to_id(&attacker_pubkey), validator_id);
        insert_active_validator_with_pubkey(&mut state, validator_id, &legitimate_pubkey, 0x54);
        state
            .delegator_identities
            .insert(validator_id, legitimate_pubkey.clone());
        let bond_utxo_id = insert_delegator_utxo(&mut state, legitimate_pubkey, 2_000_000, 0x54);
        let op = signed_op(
            StakingOpBody::SelfStake {
                bond_utxo_id,
                validator_pubkey: attacker_pubkey,
                bond_proof: Some(bond_proof(2_000_000, 0x54)),
                cold_authorization: None,
            },
            1,
            &attacker_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        let before = state.clone();

        let err = apply_staking_op_with_identity_activation(&mut state, &op, &chain_id, 1, true)
            .unwrap_err();

        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("validator identity stored pubkey mismatch")
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn validator_self_bond_post_identity_gate_matches_validator_entry_and_registry() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0x57);
        state.validators.get_mut(&validator_id).unwrap().stake_spark = 0;
        let pubkey = pubkey_from_keypair(&validator_keypair);
        state
            .delegator_identities
            .insert(validator_id, pubkey.clone());
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 2_000_000, 0x57);
        let chain_id = state.chain_id.clone();
        let stake = self_stake_op(&state, bond_utxo_id, &validator_keypair, 1);
        apply_staking_op_with_identity_activation(&mut state, &stake, &chain_id, 1, true).unwrap();
        let unstake = self_unstake_op(&state, bond_utxo_id, &validator_keypair, 2);
        apply_staking_op_with_identity_activation(&mut state, &unstake, &chain_id, 1, true)
            .unwrap();

        assert_eq!(
            state
                .staked_bonds
                .get(&bond_utxo_id)
                .unwrap()
                .unbonding_end_epoch,
            Some(UNBONDING_PERIOD_EPOCHS)
        );
    }

    #[test]
    fn validator_self_stake_post_identity_gate_rejects_registry_mismatch() {
        let mut state = ChainState::new_genesis();
        let legitimate_keypair = mixed_keypair(0x58, 0x59);
        let conflicting_keypair = mixed_keypair(0x58, 0x5A);
        let legitimate_pubkey = pubkey_from_keypair(&legitimate_keypair);
        let conflicting_pubkey = pubkey_from_keypair(&conflicting_keypair);
        let validator_id = pubkey_to_id(&legitimate_pubkey);
        assert_eq!(pubkey_to_id(&conflicting_pubkey), validator_id);
        insert_active_validator_with_pubkey(&mut state, validator_id, &legitimate_pubkey, 0x58);
        state
            .delegator_identities
            .insert(validator_id, conflicting_pubkey);
        let bond_utxo_id = insert_delegator_utxo(&mut state, legitimate_pubkey, 2_000_000, 0x58);
        let op = self_stake_op(&state, bond_utxo_id, &legitimate_keypair, 1);
        let chain_id = state.chain_id.clone();
        let before = state.clone();

        let err = apply_staking_op_with_identity_activation(&mut state, &op, &chain_id, 1, true)
            .unwrap_err();

        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("validator identity registry pubkey mismatch")
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn validator_self_unstake_post_identity_gate_rejects_validator_entry_mismatch_even_if_registry_matches(
    ) {
        let mut state = ChainState::new_genesis();
        let legitimate_keypair = mixed_keypair(0x5B, 0x5C);
        let attacker_keypair = mixed_keypair(0x5B, 0x5D);
        let legitimate_pubkey = pubkey_from_keypair(&legitimate_keypair);
        let attacker_pubkey = pubkey_from_keypair(&attacker_keypair);
        let validator_id = pubkey_to_id(&legitimate_pubkey);
        assert_eq!(pubkey_to_id(&attacker_pubkey), validator_id);
        insert_active_validator_with_pubkey(&mut state, validator_id, &legitimate_pubkey, 0x5B);
        state
            .delegator_identities
            .insert(validator_id, attacker_pubkey.clone());
        let bond_utxo_id =
            insert_delegator_utxo(&mut state, legitimate_pubkey.clone(), 2_000_000, 0x5B);
        let chain_id = state.chain_id.clone();
        let stake = self_stake_op(&state, bond_utxo_id, &legitimate_keypair, 1);
        apply_staking_op_with_identity_activation(&mut state, &stake, &chain_id, 1, false).unwrap();
        let op = signed_op(
            StakingOpBody::SelfUnstake {
                bond_utxo_id,
                validator_pubkey: attacker_pubkey,
                cold_authorization: None,
            },
            2,
            &attacker_keypair,
            &state.chain_id,
        );
        let before = state.clone();

        let err = apply_staking_op_with_identity_activation(&mut state, &op, &chain_id, 1, true)
            .unwrap_err();

        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("validator identity stored pubkey mismatch")
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn self_stake_without_proof_fails_at_activation() {
        let mut state = ChainState::new_genesis();
        let (_, validator_keypair) = make_active_validator(&mut state, 0x01);
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey.clone(), 2_000_000, 0x3B);
        let op = signed_op(
            StakingOpBody::SelfStake {
                bond_utxo_id,
                validator_pubkey: pubkey,
                bond_proof: None,
                cold_authorization: None,
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::BondProofRequired)
        );
        assert!(state.utxos.contains(&bond_utxo_id));
    }

    #[test]
    fn self_stake_mismatch_does_not_spend_utxo() {
        let mut state = ChainState::new_genesis();
        let (_, validator_keypair) = make_active_validator(&mut state, 0x01);
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey.clone(), 2_000_000, 0x3C);
        let op = signed_op(
            StakingOpBody::SelfStake {
                bond_utxo_id,
                validator_pubkey: pubkey,
                bond_proof: Some(bond_proof(2_000_000, 0x3D)),
                cold_authorization: None,
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::StakingBondCommitmentMismatch)
        );
        assert!(state.utxos.contains(&bond_utxo_id));
    }

    #[test]
    fn self_stake_rejects_unknown_utxo() {
        let mut state = ChainState::new_genesis();
        let (_, validator_keypair) = make_active_validator(&mut state, 0x01);
        let op = self_stake_op(&state, Bytes32::from([0x31; 32]), &validator_keypair, 1);
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::UnknownUtxo)
        );
    }

    #[test]
    fn self_stake_rejects_wrong_utxo_owner() {
        let mut state = ChainState::new_genesis();
        let (_, validator_keypair) = make_active_validator(&mut state, 0x01);
        let wrong_owner = pubkey_from_keypair(&keypair(0x02));
        let bond_utxo_id = insert_delegator_utxo(&mut state, wrong_owner, 2_000_000, 0x32);

        let op = self_stake_op(&state, bond_utxo_id, &validator_keypair, 1);
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::InvalidStakingOp(_))
        ));
    }

    #[test]
    fn self_stake_rejects_unregistered_validator() {
        let mut state = ChainState::new_genesis();
        let validator_keypair = keypair(0x01);
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 2_000_000, 0x33);

        let op = self_stake_op(&state, bond_utxo_id, &validator_keypair, 1);
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::ValidatorNotFound)
        );
    }

    #[test]
    fn self_stake_rejects_slashed_validator() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0x01);
        state.validators.get_mut(&validator_id).unwrap().status = ValidatorStatus::Slashed;
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 2_000_000, 0x34);

        let op = self_stake_op(&state, bond_utxo_id, &validator_keypair, 1);
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::ValidatorNotActive)
        );
    }

    #[test]
    fn self_stake_rejects_already_bonded_utxo() {
        let mut state = ChainState::new_genesis();
        let (_, validator_keypair) = make_active_validator(&mut state, 0x01);
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 2_000_000, 0x35);

        let chain_id = state.chain_id.clone();
        let first = self_stake_op(&state, bond_utxo_id, &validator_keypair, 1);
        let second = self_stake_op(&state, bond_utxo_id, &validator_keypair, 2);
        apply_staking_op(&mut state, &first, &chain_id, 1).unwrap();
        assert!(matches!(
            apply_staking_op(&mut state, &second, &chain_id, 1),
            Err(StateError::InvalidStakingOp(_))
        ));
    }

    #[test]
    fn self_stake_rejects_invalid_signature() {
        let mut state = ChainState::new_genesis();
        let (_, validator_keypair) = make_active_validator(&mut state, 0x01);
        let wrong_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey.clone(), 2_000_000, 0x36);
        let op = signed_op(
            StakingOpBody::SelfStake {
                bond_utxo_id,
                validator_pubkey: pubkey,
                bond_proof: Some(bond_proof(2_000_000, 0x36)),
                cold_authorization: None,
            },
            1,
            &wrong_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::StakingOpSignatureInvalid { .. })
        ));
    }

    #[test]
    fn self_unstake_sets_unbonding_and_reduces_stake() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0x01);
        state.validators.get_mut(&validator_id).unwrap().stake_spark = 0;
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 2_000_000, 0x37);

        let chain_id = state.chain_id.clone();
        let stake = self_stake_op(&state, bond_utxo_id, &validator_keypair, 1);
        apply_staking_op(&mut state, &stake, &chain_id, 1).unwrap();
        let unstake = self_unstake_op(&state, bond_utxo_id, &validator_keypair, 2);
        apply_staking_op(&mut state, &unstake, &chain_id, 1).unwrap();

        assert_eq!(
            state
                .staked_bonds
                .get(&bond_utxo_id)
                .unwrap()
                .unbonding_end_epoch,
            Some(UNBONDING_PERIOD_EPOCHS)
        );
        assert_eq!(state.validators.get(&validator_id).unwrap().stake_spark, 0);
    }

    #[test]
    fn self_unstake_below_active_minimum_demotes_validator() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0x24);
        state.validators.get_mut(&validator_id).unwrap().stake_spark =
            MINIMUM_ACTIVE_SELF_STAKE_SPARK - 1;
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 2_000_000, 0x25);

        let chain_id = state.chain_id.clone();
        let stake = self_stake_op(&state, bond_utxo_id, &validator_keypair, 1);
        apply_staking_op(&mut state, &stake, &chain_id, 1).unwrap();
        let before = state.validators.get(&validator_id).unwrap().stake_spark;
        assert!(before >= MINIMUM_ACTIVE_SELF_STAKE_SPARK);

        let unstake = self_unstake_op(&state, bond_utxo_id, &validator_keypair, 2);
        apply_staking_op(&mut state, &unstake, &chain_id, 1).unwrap();

        let validator = state.validators.get(&validator_id).unwrap();
        assert!(validator.stake_spark < MINIMUM_ACTIVE_SELF_STAKE_SPARK);
        assert!(matches!(validator.status, ValidatorStatus::Registered));
    }

    #[test]
    fn self_unstake_above_active_minimum_keeps_validator_active() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0x26);
        state.validators.get_mut(&validator_id).unwrap().stake_spark =
            MINIMUM_ACTIVE_SELF_STAKE_SPARK + 5_000_000;
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 2_000_000, 0x27);

        let chain_id = state.chain_id.clone();
        let stake = self_stake_op(&state, bond_utxo_id, &validator_keypair, 1);
        apply_staking_op(&mut state, &stake, &chain_id, 1).unwrap();
        let unstake = self_unstake_op(&state, bond_utxo_id, &validator_keypair, 2);
        apply_staking_op(&mut state, &unstake, &chain_id, 1).unwrap();

        let validator = state.validators.get(&validator_id).unwrap();
        assert!(validator.stake_spark >= MINIMUM_ACTIVE_SELF_STAKE_SPARK);
        assert!(matches!(validator.status, ValidatorStatus::Active));
    }

    #[test]
    fn registered_validator_self_unstake_remains_registered() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0x28);
        {
            let validator = state.validators.get_mut(&validator_id).unwrap();
            validator.status = ValidatorStatus::Registered;
            validator.stake_spark = 0;
        }
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 2_000_000, 0x29);

        let chain_id = state.chain_id.clone();
        let stake = self_stake_op(&state, bond_utxo_id, &validator_keypair, 1);
        apply_staking_op(&mut state, &stake, &chain_id, 1).unwrap();
        let unstake = self_unstake_op(&state, bond_utxo_id, &validator_keypair, 2);
        apply_staking_op(&mut state, &unstake, &chain_id, 1).unwrap();

        let validator = state.validators.get(&validator_id).unwrap();
        assert_eq!(validator.stake_spark, 0);
        assert!(matches!(validator.status, ValidatorStatus::Registered));
    }

    #[test]
    fn self_unstake_rejects_non_self_bond() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&delegator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 2_000_000, 0x38);
        let chain_id = state.chain_id.clone();
        let delegate = delegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 1);
        apply_staking_op(&mut state, &delegate, &chain_id, 1).unwrap();

        let unstake = self_unstake_op(&state, bond_utxo_id, &validator_keypair, 1);
        assert!(matches!(
            apply_staking_op(&mut state, &unstake, &chain_id, 1),
            Err(StateError::InvalidStakingOp(_))
        ));
    }

    #[test]
    fn self_unstake_rejects_wrong_validator() {
        let mut state = ChainState::new_genesis();
        let (_, validator_keypair) = make_active_validator(&mut state, 0x01);
        let (_, wrong_validator_keypair) = make_active_validator(&mut state, 0x02);
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 2_000_000, 0x39);
        let chain_id = state.chain_id.clone();
        let stake = self_stake_op(&state, bond_utxo_id, &validator_keypair, 1);
        apply_staking_op(&mut state, &stake, &chain_id, 1).unwrap();

        let unstake = self_unstake_op(&state, bond_utxo_id, &wrong_validator_keypair, 1);
        assert!(matches!(
            apply_staking_op(&mut state, &unstake, &chain_id, 1),
            Err(StateError::InvalidStakingOp(_))
        ));
    }

    #[test]
    fn self_unstake_rejects_already_unbonding() {
        let mut state = ChainState::new_genesis();
        let (_, validator_keypair) = make_active_validator(&mut state, 0x01);
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 2_000_000, 0x3A);
        let chain_id = state.chain_id.clone();
        let stake = self_stake_op(&state, bond_utxo_id, &validator_keypair, 1);
        apply_staking_op(&mut state, &stake, &chain_id, 1).unwrap();
        let first = self_unstake_op(&state, bond_utxo_id, &validator_keypair, 2);
        let second = self_unstake_op(&state, bond_utxo_id, &validator_keypair, 3);
        apply_staking_op(&mut state, &first, &chain_id, 1).unwrap();
        assert!(matches!(
            apply_staking_op(&mut state, &second, &chain_id, 1),
            Err(StateError::InvalidStakingOp(_))
        ));
    }

    #[test]
    fn apply_staking_op_rejects_wrong_nonce() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let op = signed_op(
            StakingOpBody::Delegate {
                validator_id,
                bond_utxo_id: Bytes32::from([0x31; 32]),
                delegator_pubkey: pubkey_from_keypair(&delegator_keypair),
                bond_proof: None,
            },
            5,
            &delegator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::StakingNonceInvalid {
                expected: 1,
                got: 5,
            })
        );
    }

    #[test]
    fn apply_staking_op_rejects_replay() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let chain_id = state.chain_id.clone();
        let pubkey = pubkey_from_keypair(&delegator_keypair);
        let bond_utxo_id = insert_delegator_utxo(&mut state, pubkey, 1_000_000, 0x17);
        let op = delegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 1);
        apply_staking_op(&mut state, &op, &chain_id, 1).unwrap();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::StakingNonceInvalid {
                expected: 2,
                got: 1,
            })
        );
    }

    #[test]
    fn apply_staking_op_rejects_bad_signature() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let wrong_keypair = keypair(0x03);
        let op = signed_op(
            StakingOpBody::Delegate {
                validator_id,
                bond_utxo_id: Bytes32::from([0x32; 32]),
                delegator_pubkey: pubkey_from_keypair(&delegator_keypair),
                bond_proof: None,
            },
            1,
            &wrong_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::StakingOpSignatureInvalid { .. })
        ));
    }

    #[test]
    fn register_payment_key_rejects_before_activation() {
        let mut state = ChainState::new_genesis();
        let owner_keypair = keypair(0x41);
        let owner_pubkey = pubkey_from_keypair(&owner_keypair);
        let op = signed_op(
            StakingOpBody::RegisterPaymentKey {
                owner_pubkey,
                payment_pubkey: payment_pubkey(0x42),
                cold_authorization: None,
            },
            1,
            &owner_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();

        let err =
            apply_staking_op(&mut state, &op, &chain_id, PAYMENT_BLINDING_HEIGHT - 1).unwrap_err();
        assert!(
            matches!(err, StateError::InvalidStakingOp(message) if message.contains("PAYMENT_BLINDING_HEIGHT"))
        );
        assert!(state.payment_identities.is_empty());
        assert!(state.staking_nonces.is_empty());
    }

    #[test]
    fn register_payment_key_succeeds_and_updates_commitment_after_activation() {
        let mut state = ChainState::new_genesis();
        let height = PAYMENT_BLINDING_HEIGHT;
        state.rebuild_state_commitment_v2(height);
        let before_root = state.state_commitment_v2_root(height);
        let owner_keypair = keypair(0x43);
        let owner_pubkey = pubkey_from_keypair(&owner_keypair);
        let owner_id = pubkey_to_id(&owner_pubkey);
        let payment_pubkey = payment_pubkey(0x44);
        let op = signed_op(
            StakingOpBody::RegisterPaymentKey {
                owner_pubkey,
                payment_pubkey: payment_pubkey.clone(),
                cold_authorization: None,
            },
            1,
            &owner_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();

        apply_staking_op(&mut state, &op, &chain_id, height).unwrap();

        assert_eq!(
            state.payment_identities.get(&owner_id),
            Some(&payment_pubkey)
        );
        assert_eq!(state.staking_nonces.get(&owner_id), Some(&1));
        let incremental_root = state.state_commitment_v2_root(height);
        assert_ne!(incremental_root, before_root);
        let rebuilt_root =
            crate::state_commitment::StateCommitmentV2::from_state(&state, height).root();
        assert_eq!(incremental_root, rebuilt_root);
    }

    #[test]
    fn register_payment_key_rejects_wrong_signer() {
        let mut state = ChainState::new_genesis();
        let owner_keypair = keypair(0x45);
        let wrong_keypair = keypair(0x46);
        let owner_pubkey = pubkey_from_keypair(&owner_keypair);
        let op = signed_op(
            StakingOpBody::RegisterPaymentKey {
                owner_pubkey,
                payment_pubkey: payment_pubkey(0x47),
                cold_authorization: None,
            },
            1,
            &wrong_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();

        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, u64::MAX),
            Err(StateError::StakingOpSignatureInvalid { .. })
        ));
    }

    #[test]
    fn register_payment_key_rejects_replayed_nonce() {
        let mut state = ChainState::new_genesis();
        let owner_keypair = keypair(0x48);
        let owner_pubkey = pubkey_from_keypair(&owner_keypair);
        let payment_pubkey = payment_pubkey(0x49);
        let op = signed_op(
            StakingOpBody::RegisterPaymentKey {
                owner_pubkey,
                payment_pubkey,
                cold_authorization: None,
            },
            1,
            &owner_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();

        apply_staking_op(&mut state, &op, &chain_id, u64::MAX).unwrap();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, u64::MAX),
            Err(StateError::StakingNonceInvalid {
                expected: 2,
                got: 1,
            })
        );
    }

    #[test]
    fn register_payment_key_allows_owner_rotation_by_replacement() {
        let mut state = ChainState::new_genesis();
        state.rebuild_state_commitment_v2(u64::MAX);
        let owner_keypair = keypair(0x4A);
        let owner_pubkey = pubkey_from_keypair(&owner_keypair);
        let owner_id = pubkey_to_id(&owner_pubkey);
        let first_pubkey = payment_pubkey(0x4B);
        let second_pubkey = payment_pubkey(0x4C);
        let first = signed_op(
            StakingOpBody::RegisterPaymentKey {
                owner_pubkey: owner_pubkey.clone(),
                payment_pubkey: first_pubkey,
                cold_authorization: None,
            },
            1,
            &owner_keypair,
            &state.chain_id,
        );
        let second = signed_op(
            StakingOpBody::RegisterPaymentKey {
                owner_pubkey,
                payment_pubkey: second_pubkey.clone(),
                cold_authorization: None,
            },
            2,
            &owner_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();

        apply_staking_op(&mut state, &first, &chain_id, u64::MAX).unwrap();
        let first_root = state.state_commitment_v2_root(u64::MAX);
        apply_staking_op(&mut state, &second, &chain_id, u64::MAX).unwrap();

        assert_eq!(
            state.payment_identities.get(&owner_id),
            Some(&second_pubkey)
        );
        assert_eq!(state.payment_identities.len(), 1);
        assert_eq!(state.staking_nonces.get(&owner_id), Some(&2));
        let second_root = state.state_commitment_v2_root(u64::MAX);
        assert_ne!(first_root, second_root);
        assert_eq!(
            second_root,
            crate::state_commitment::StateCommitmentV2::from_state(&state, u64::MAX).root()
        );
    }

    #[test]
    fn state_txn_rolls_back_register_payment_key_scope() {
        let mut state = ChainState::new_genesis();
        state.rebuild_state_commitment_v2(u64::MAX);
        let original = state.clone();
        let owner_keypair = keypair(0x4D);
        let owner_pubkey = pubkey_from_keypair(&owner_keypair);
        let op = signed_op(
            StakingOpBody::RegisterPaymentKey {
                owner_pubkey,
                payment_pubkey: payment_pubkey(0x4E),
                cold_authorization: None,
            },
            1,
            &owner_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();

        {
            let mut txn = crate::txn::StateTxn::begin(&mut state, u64::MAX);
            txn.snapshot_staking_scope();
            txn.snapshot_payment_identity_scope();
            apply_staking_op(txn.state_mut(), &op, &chain_id, u64::MAX).unwrap();
        }

        assert_eq!(state.payment_identities, original.payment_identities);
        assert_eq!(state.staking_nonces, original.staking_nonces);
        assert_eq!(
            state.state_commitment_v2_root(u64::MAX),
            original.state_commitment_v2_root(u64::MAX)
        );
    }

    #[test]
    fn claim_rewards_creates_utxo() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        state
            .delegations
            .add_delegation(validator_id, delegator_id, 1_000_000, 0)
            .unwrap();
        state
            .delegations
            .update_delegator(&validator_id, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();

        let op = signed_op(
            StakingOpBody::ClaimRewards {
                validator_id,
                delegator_pubkey,
                cold_authorization: None,
            },
            1,
            &delegator_keypair,
            &state.chain_id,
        );
        let before = state.utxos.len();
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &op, &chain_id, 42).unwrap();
        assert_eq!(state.utxos.len(), before + 1);
    }

    #[test]
    fn claim_rewards_zeroes_pending_rewards() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        state
            .delegations
            .add_delegation(validator_id, delegator_id, 1_000_000, 0)
            .unwrap();
        state
            .delegations
            .update_delegator(&validator_id, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();
        let op = signed_op(
            StakingOpBody::ClaimRewards {
                validator_id,
                delegator_pubkey,
                cold_authorization: None,
            },
            1,
            &delegator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &op, &chain_id, 42).unwrap();
        assert_eq!(
            state
                .delegations
                .get_delegators(&validator_id)
                .iter()
                .find(|entry| entry.delegator_id == delegator_id)
                .unwrap()
                .pending_rewards,
            0
        );
    }

    #[test]
    fn claim_rewards_below_dust_rejected() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        state
            .delegations
            .add_delegation(validator_id, delegator_id, 1_000_000, 0)
            .unwrap();
        state
            .delegations
            .update_delegator(&validator_id, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK - 1;
            })
            .unwrap();
        let op = signed_op(
            StakingOpBody::ClaimRewards {
                validator_id,
                delegator_pubkey,
                cold_authorization: None,
            },
            1,
            &delegator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 42),
            Err(StateError::InvalidStakingOp(_))
        ));
    }

    #[test]
    fn claim_rewards_pre_identity_gate_ignores_registry_mismatch_and_behaves_as_before() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x49);
        let legitimate_keypair = mixed_keypair(0x4A, 0x4B);
        let legitimate_pubkey = pubkey_from_keypair(&legitimate_keypair);
        let attacker_keypair = mixed_keypair(0x4A, 0x4C);
        let attacker_pubkey = pubkey_from_keypair(&attacker_keypair);
        let delegator_id = pubkey_to_id(&legitimate_pubkey);
        assert_eq!(pubkey_to_id(&attacker_pubkey), delegator_id);
        state
            .delegator_identities
            .insert(delegator_id, legitimate_pubkey);
        state
            .delegations
            .add_delegation(validator_id, delegator_id, 1_000_000, 0)
            .unwrap();
        state
            .delegations
            .update_delegator(&validator_id, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();

        let before_utxos = state.utxos.len();
        let claim = claim_rewards_op(&state, validator_id, &attacker_keypair, 1);
        let chain_id = state.chain_id.clone();
        apply_staking_op_with_identity_activation(&mut state, &claim, &chain_id, 42, false)
            .unwrap();

        assert_eq!(state.utxos.len(), before_utxos + 1);
        assert_eq!(
            state
                .delegations
                .get_delegators(&validator_id)
                .iter()
                .find(|entry| entry.delegator_id == delegator_id)
                .unwrap()
                .pending_rewards,
            0
        );
    }

    #[test]
    fn claim_rewards_post_identity_gate_registered_match_pays_legitimate_claimant() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x4D);
        let delegator_keypair = keypair(0x4E);
        let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        state
            .delegator_identities
            .insert(delegator_id, delegator_pubkey.clone());
        state
            .delegations
            .add_delegation(validator_id, delegator_id, 1_000_000, 0)
            .unwrap();
        state
            .delegations
            .update_delegator(&validator_id, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();

        let before_utxos = state.utxos.len();
        let claim = claim_rewards_op(&state, validator_id, &delegator_keypair, 1);
        let chain_id = state.chain_id.clone();
        apply_staking_op_with_identity_activation(&mut state, &claim, &chain_id, 42, true).unwrap();

        assert_eq!(state.utxos.len(), before_utxos + 1);
        assert_eq!(
            state
                .delegations
                .get_delegators(&validator_id)
                .iter()
                .find(|entry| entry.delegator_id == delegator_id)
                .unwrap()
                .pending_rewards,
            0
        );
        assert_eq!(
            state.delegator_identities.get(&delegator_id),
            Some(&delegator_pubkey)
        );
    }

    #[test]
    fn claim_rewards_post_identity_gate_rejects_direct_theft_pq_substitution_attack() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x4F);
        let legitimate_keypair = mixed_keypair(0x50, 0x51);
        let legitimate_pubkey = pubkey_from_keypair(&legitimate_keypair);
        let delegator_id = pubkey_to_id(&legitimate_pubkey);
        state
            .delegator_identities
            .insert(delegator_id, legitimate_pubkey);
        let attacker_keypair = mixed_keypair(0x50, 0x52);
        let attacker_pubkey = pubkey_from_keypair(&attacker_keypair);
        assert_eq!(pubkey_to_id(&attacker_pubkey), delegator_id);
        state
            .delegations
            .add_delegation(validator_id, delegator_id, 1_000_000, 0)
            .unwrap();
        state
            .delegations
            .update_delegator(&validator_id, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();

        let attack = claim_rewards_op(&state, validator_id, &attacker_keypair, 1);
        let before_utxos = state.utxos.len();
        let mut before_attack_reference = state.clone();
        let chain_id = state.chain_id.clone();
        apply_staking_op_with_identity_activation(
            &mut before_attack_reference,
            &attack,
            &chain_id,
            42,
            false,
        )
        .unwrap();
        assert_eq!(
            before_attack_reference
                .delegations
                .get_delegators(&validator_id)
                .iter()
                .find(|entry| entry.delegator_id == delegator_id)
                .unwrap()
                .pending_rewards,
            0
        );
        assert_eq!(before_attack_reference.utxos.len(), before_utxos + 1);

        let err =
            apply_staking_op_with_identity_activation(&mut state, &attack, &chain_id, 42, true)
                .unwrap_err();
        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("delegator identity registry pubkey mismatch")
        ));
        assert_eq!(state.utxos.len(), before_utxos);
        assert_eq!(
            state
                .delegations
                .get_delegators(&validator_id)
                .iter()
                .find(|entry| entry.delegator_id == delegator_id)
                .unwrap()
                .pending_rewards,
            DUST_LIMIT_SPARK
        );
    }

    #[test]
    fn claim_rewards_identity_failure_happens_before_zeroing_or_utxo_creation() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x53);
        let legitimate_keypair = mixed_keypair(0x54, 0x55);
        let legitimate_pubkey = pubkey_from_keypair(&legitimate_keypair);
        let delegator_id = pubkey_to_id(&legitimate_pubkey);
        state
            .delegator_identities
            .insert(delegator_id, legitimate_pubkey);
        let attacker_keypair = mixed_keypair(0x54, 0x56);
        state
            .delegations
            .add_delegation(validator_id, delegator_id, 1_000_000, 0)
            .unwrap();
        state
            .delegations
            .update_delegator(&validator_id, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();
        let before = state.clone();
        let attack = claim_rewards_op(&state, validator_id, &attacker_keypair, 1);
        let chain_id = state.chain_id.clone();

        let err =
            apply_staking_op_with_identity_activation(&mut state, &attack, &chain_id, 42, true)
                .unwrap_err();

        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("delegator identity registry pubkey mismatch")
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn claim_rewards_post_identity_gate_legacy_bonds_matching_submitted_key_populate_registry() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x57);
        let delegator_keypair = keypair(0x58);
        let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        let bond_utxo_id =
            insert_delegator_utxo(&mut state, delegator_pubkey.clone(), 1_000_000, 0x57);
        let chain_id = state.chain_id.clone();
        let delegate = delegate_op(&state, validator_id, bond_utxo_id, &delegator_keypair, 1);
        apply_staking_op_with_identity_activation(&mut state, &delegate, &chain_id, 1, false)
            .unwrap();
        state
            .delegations
            .update_delegator(&validator_id, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();
        assert!(state.delegator_identities.is_empty());

        let claim = claim_rewards_op(&state, validator_id, &delegator_keypair, 2);
        let before_utxos = state.utxos.len();
        apply_staking_op_with_identity_activation(&mut state, &claim, &chain_id, 42, true).unwrap();

        assert_eq!(state.utxos.len(), before_utxos + 1);
        assert_eq!(
            state.delegator_identities.get(&delegator_id),
            Some(&delegator_pubkey)
        );
    }

    #[test]
    fn claim_rewards_post_identity_gate_compact_no_prior_record_populates_when_owner_matches() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x59);
        let delegator_keypair = keypair(0x5A);
        let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        let bond_utxo_id = Bytes32::from([0x5A; 32]);
        let compact_bond = StakeBondEntry::new_for_test_with_compact_activation(
            bond_utxo_id,
            validator_id,
            delegator_id,
            1_000_000,
            0,
            test_output(1_000_000, delegator_pubkey.clone(), 0x5A),
            2,
            1,
        );
        state.staked_bonds.insert(bond_utxo_id, compact_bond);
        state
            .delegations
            .add_delegation(validator_id, delegator_id, 1_000_000, 0)
            .unwrap();
        state
            .delegations
            .update_delegator(&validator_id, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();
        let claim = claim_rewards_op(&state, validator_id, &delegator_keypair, 1);
        let chain_id = state.chain_id.clone();

        apply_staking_op_with_identity_activation(&mut state, &claim, &chain_id, 42, true).unwrap();

        assert_eq!(
            state.delegator_identities.get(&delegator_id),
            Some(&delegator_pubkey)
        );
        assert_eq!(
            state
                .delegations
                .get_delegators(&validator_id)
                .iter()
                .find(|entry| entry.delegator_id == delegator_id)
                .unwrap()
                .pending_rewards,
            0
        );
    }

    #[test]
    fn claim_rewards_post_identity_gate_rejects_conflicting_legacy_bonds() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x5B);
        let first_keypair = mixed_keypair(0x5C, 0x5D);
        let first_pubkey = pubkey_from_keypair(&first_keypair);
        let second_keypair = mixed_keypair(0x5C, 0x5E);
        let second_pubkey = pubkey_from_keypair(&second_keypair);
        let delegator_id = pubkey_to_id(&first_pubkey);
        assert_eq!(pubkey_to_id(&second_pubkey), delegator_id);

        let first_bond = insert_delegator_utxo(&mut state, first_pubkey, 1_000_000, 0x5B);
        let second_bond = insert_delegator_utxo(&mut state, second_pubkey, 1_000_000, 0x5C);
        let chain_id = state.chain_id.clone();
        let first_delegate = delegate_op(&state, validator_id, first_bond, &first_keypair, 1);
        apply_staking_op_with_identity_activation(&mut state, &first_delegate, &chain_id, 1, false)
            .unwrap();
        let second_delegate = delegate_op(&state, validator_id, second_bond, &second_keypair, 2);
        apply_staking_op_with_identity_activation(
            &mut state,
            &second_delegate,
            &chain_id,
            1,
            false,
        )
        .unwrap();
        state
            .delegations
            .update_delegator(&validator_id, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();
        let before = state.clone();

        let claim = claim_rewards_op(&state, validator_id, &first_keypair, 3);
        let err =
            apply_staking_op_with_identity_activation(&mut state, &claim, &chain_id, 42, true)
                .unwrap_err();

        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("delegator identity has ambiguous legacy pubkeys")
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn apply_register_validator_sets_vrf_key() {
        let mut state = ChainState::new_genesis();
        let validator_keypair = keypair(0x04);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let validator_id = pubkey_to_id(&validator_pubkey);
        let bond_utxo_id = insert_delegator_utxo(
            &mut state,
            validator_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xA0,
        );
        let vrf_pk = [0xA5; 32];
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id,
                validator_pubkey,
                vrf_pk,
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, 0xA0)),
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &op, &chain_id, 1).unwrap();
        assert_eq!(
            state.validators.get(&validator_id).unwrap().vrf_pk,
            Some(vrf_pk)
        );
        assert_eq!(
            state.validators.get(&validator_id).unwrap().stake_spark,
            MINIMUM_VALIDATOR_BOND_SPARK
        );
        assert!(state.staked_bonds.contains_key(&bond_utxo_id));
        assert!(!state.utxos.contains(&bond_utxo_id));
    }

    #[test]
    fn register_validator_pre_identity_gate_does_not_populate_registry() {
        let mut state = ChainState::new_genesis();
        let validator_keypair = keypair(0xB0);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let validator_id = pubkey_to_id(&validator_pubkey);
        let bond_utxo_id = insert_delegator_utxo(
            &mut state,
            validator_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xB0,
        );
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id,
                validator_pubkey,
                vrf_pk: [0xB0; 32],
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, 0xB0)),
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();

        apply_staking_op_with_identity_activation(&mut state, &op, &chain_id, 0, false).unwrap();

        assert!(state.validators.get(&validator_id).is_some());
        assert!(!state.delegator_identities.contains_key(&validator_id));
    }

    #[test]
    fn register_validator_post_identity_gate_populates_registry() {
        let mut state = ChainState::new_genesis();
        let validator_keypair = keypair(0xB1);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let validator_id = pubkey_to_id(&validator_pubkey);
        let bond_utxo_id = insert_delegator_utxo(
            &mut state,
            validator_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xB1,
        );
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id,
                validator_pubkey: validator_pubkey.clone(),
                vrf_pk: [0xB1; 32],
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, 0xB1)),
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();

        apply_staking_op_with_identity_activation(&mut state, &op, &chain_id, 1, true).unwrap();

        assert_eq!(
            state.delegator_identities.get(&validator_id),
            Some(&validator_pubkey)
        );
    }

    #[test]
    fn register_validator_post_identity_gate_rejects_preexisting_registry_mismatch() {
        let mut state = ChainState::new_genesis();
        let validator_keypair = mixed_keypair(0xB2, 0xB3);
        let conflicting_keypair = mixed_keypair(0xB2, 0xB4);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let conflicting_pubkey = pubkey_from_keypair(&conflicting_keypair);
        let validator_id = pubkey_to_id(&validator_pubkey);
        assert_eq!(pubkey_to_id(&conflicting_pubkey), validator_id);
        state
            .delegator_identities
            .insert(validator_id, conflicting_pubkey);
        let bond_utxo_id = insert_delegator_utxo(
            &mut state,
            validator_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xB2,
        );
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id,
                validator_pubkey,
                vrf_pk: [0xB2; 32],
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, 0xB2)),
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        let before = state.clone();

        let err = apply_staking_op_with_identity_activation(&mut state, &op, &chain_id, 1, true)
            .unwrap_err();

        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("validator identity registry pubkey mismatch")
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn validator_and_delegator_registry_keys_are_classical_pubkey_identity_hashes() {
        let validator_pubkey = pubkey_from_keypair(&keypair(0xB5));
        let delegator_pubkey = pubkey_from_keypair(&keypair(0xB6));
        let validator_id = pubkey_to_id(&validator_pubkey);
        let delegator_id = pubkey_to_id(&delegator_pubkey);

        assert_ne!(validator_id, delegator_id);
        assert_eq!(pubkey_to_id(&validator_pubkey), validator_id);
        assert_eq!(pubkey_to_id(&delegator_pubkey), delegator_id);
    }

    #[test]
    fn pre_activation_height_rejects_update_network_address_op() {
        let mut state = ChainState::new_genesis();
        let chain_id = state.chain_id.clone();
        let (validator_id, keypair) = make_active_validator(&mut state, 0xA1);
        let op = signed_op(
            StakingOpBody::UpdateNetworkAddress {
                validator_id,
                network_addr: Some("203.0.113.10:30303".to_string()),
            },
            1,
            &keypair,
            &chain_id,
        );

        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 0),
            Err(StateError::InvalidStakingOp(reason))
                if reason.contains("network address updates are not active")
        ));
    }

    #[test]
    fn update_network_address_requires_validator_signature() {
        let mut state = ChainState::new_genesis();
        let chain_id = state.chain_id.clone();
        let (validator_id, _keypair) = make_active_validator(&mut state, 0xA2);
        let attacker = keypair(0xA3);
        let op = signed_op(
            StakingOpBody::UpdateNetworkAddress {
                validator_id,
                network_addr: Some("203.0.113.11:30303".to_string()),
            },
            1,
            &attacker,
            &chain_id,
        );

        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, u64::MAX),
            Err(StateError::StakingOpSignatureInvalid { .. })
        ));
    }

    #[test]
    fn update_network_address_rejects_invalid_syntax_at_apply() {
        let mut state = ChainState::new_genesis();
        let chain_id = state.chain_id.clone();
        let (validator_id, keypair) = make_active_validator(&mut state, 0xA4);

        for invalid in [
            "validator.example.com:30303",
            "http://203.0.113.12:30303",
            "203.0.113.12:30303/path",
            "203.0.113.12:30303 ",
            "203.0.113.12:0",
        ] {
            let op = signed_op(
                StakingOpBody::UpdateNetworkAddress {
                    validator_id,
                    network_addr: Some(invalid.to_string()),
                },
                1,
                &keypair,
                &chain_id,
            );
            assert!(matches!(
                apply_staking_op(&mut state.clone(), &op, &chain_id, u64::MAX),
                Err(StateError::InvalidStakingOp(_))
            ));
        }

        let op = signed_op(
            StakingOpBody::UpdateNetworkAddress {
                validator_id,
                network_addr: Some("[2001:db8::12]:30303".to_string()),
            },
            1,
            &keypair,
            &chain_id,
        );
        apply_staking_op(&mut state, &op, &chain_id, u64::MAX).unwrap();
        assert_eq!(
            state
                .validators
                .get(&validator_id)
                .unwrap()
                .network_addr
                .as_deref(),
            Some("[2001:db8::12]:30303")
        );
    }

    #[test]
    fn update_network_address_cooldown_enforced() {
        let mut state = ChainState::new_genesis();
        let chain_id = state.chain_id.clone();
        let (validator_id, keypair) = make_active_validator(&mut state, 0xA5);
        let first = signed_op(
            StakingOpBody::UpdateNetworkAddress {
                validator_id,
                network_addr: Some("203.0.113.13:30303".to_string()),
            },
            1,
            &keypair,
            &chain_id,
        );
        apply_staking_op(&mut state, &first, &chain_id, u64::MAX).unwrap();

        let second = signed_op(
            StakingOpBody::UpdateNetworkAddress {
                validator_id,
                network_addr: Some("203.0.113.14:30303".to_string()),
            },
            2,
            &keypair,
            &chain_id,
        );
        assert!(matches!(
            apply_staking_op(&mut state, &second, &chain_id, u64::MAX),
            Err(StateError::InvalidStakingOp(reason))
                if reason.contains("already updated this epoch")
        ));
    }

    #[test]
    fn update_network_address_later_epoch_succeeds_and_clearing_counts_as_update() {
        let mut state = ChainState::new_genesis();
        let chain_id = state.chain_id.clone();
        let (validator_id, keypair) = make_active_validator(&mut state, 0xA6);
        let active_epoch = epoch_for_height(u64::MAX);
        state
            .validators
            .get_mut(&validator_id)
            .unwrap()
            .network_addr_last_updated_epoch = active_epoch.checked_sub(1);

        let set = signed_op(
            StakingOpBody::UpdateNetworkAddress {
                validator_id,
                network_addr: Some("203.0.113.15:30303".to_string()),
            },
            1,
            &keypair,
            &chain_id,
        );
        apply_staking_op(&mut state, &set, &chain_id, u64::MAX).unwrap();

        let clear_same_epoch = signed_op(
            StakingOpBody::UpdateNetworkAddress {
                validator_id,
                network_addr: None,
            },
            2,
            &keypair,
            &chain_id,
        );
        assert!(matches!(
            apply_staking_op(&mut state, &clear_same_epoch, &chain_id, u64::MAX),
            Err(StateError::InvalidStakingOp(reason))
                if reason.contains("already updated this epoch")
        ));
    }

    #[test]
    fn update_network_address_rejects_slashed_or_exited_validator() {
        let chain_id = "indra-testnet-1".to_string();
        for status in [ValidatorStatus::Slashed, ValidatorStatus::Exited] {
            let mut state = ChainState::new_genesis();
            state.chain_id = chain_id.clone();
            let (validator_id, keypair) = make_active_validator(&mut state, 0xA7);
            state.validators.get_mut(&validator_id).unwrap().status = status.clone();
            let op = signed_op(
                StakingOpBody::UpdateNetworkAddress {
                    validator_id,
                    network_addr: Some("203.0.113.16:30303".to_string()),
                },
                1,
                &keypair,
                &chain_id,
            );

            assert!(matches!(
                apply_staking_op(&mut state, &op, &chain_id, u64::MAX),
                Err(StateError::ValidatorNotActive)
            ));
        }
    }

    #[test]
    fn apply_register_validator_rejects_duplicate() {
        let mut state = ChainState::new_genesis();
        let validator_keypair = keypair(0x04);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let bond_utxo_id = insert_delegator_utxo(
            &mut state,
            validator_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xA1,
        );
        let first = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id,
                validator_pubkey: validator_pubkey.clone(),
                vrf_pk: [0xA5; 32],
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, 0xA1)),
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let second = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id: Bytes32::ZERO,
                validator_pubkey,
                vrf_pk: [0x5A; 32],
                bond_proof: None,
                cold_pubkey: None,
                cold_signature: None,
            },
            2,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &first, &chain_id, 1).unwrap();
        assert_eq!(
            apply_staking_op(&mut state, &second, &chain_id, 1),
            Err(StateError::ValidatorAlreadyRegistered)
        );
    }

    #[test]
    fn registration_without_bond_is_rejected() {
        let mut state = ChainState::new_genesis();
        let validator_keypair = keypair(0x44);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id: Bytes32::from([0xFE; 32]),
                validator_pubkey,
                vrf_pk: [0x44; 32],
                bond_proof: None,
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::UnknownUtxo)
        );
    }

    #[test]
    fn register_validator_without_proof_fails_at_activation() {
        let mut state = ChainState::new_genesis();
        let validator_keypair = keypair(0x4E);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let bond_utxo_id = insert_delegator_utxo(
            &mut state,
            validator_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xAB,
        );
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id,
                validator_pubkey,
                vrf_pk: [0x4E; 32],
                bond_proof: None,
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::BondProofRequired)
        );
        assert!(state.utxos.contains(&bond_utxo_id));
    }

    #[test]
    fn registration_with_bond_below_minimum_is_rejected() {
        let mut state = ChainState::new_genesis();
        let validator_keypair = keypair(0x45);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let bond_utxo_id = insert_delegator_utxo(
            &mut state,
            validator_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK - 1,
            0xA2,
        );
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id,
                validator_pubkey,
                vrf_pk: [0x45; 32],
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK - 1, 0xA2)),
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::InvalidStakingOp(_))
        ));
    }

    #[test]
    fn registration_rejects_duplicate_vrf_pk() {
        let mut state = ChainState::new_genesis();
        let first_keypair = keypair(0x46);
        let first_pubkey = pubkey_from_keypair(&first_keypair);
        let first_bond = insert_delegator_utxo(
            &mut state,
            first_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xA3,
        );
        let second_keypair = keypair(0x47);
        let second_pubkey = pubkey_from_keypair(&second_keypair);
        let second_bond = insert_delegator_utxo(
            &mut state,
            second_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xA4,
        );
        let duplicate_vrf = [0xDD; 32];
        let first = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id: first_bond,
                validator_pubkey: first_pubkey,
                vrf_pk: duplicate_vrf,
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, 0xA3)),
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &first_keypair,
            &state.chain_id,
        );
        let second = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id: second_bond,
                validator_pubkey: second_pubkey,
                vrf_pk: duplicate_vrf,
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, 0xA4)),
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &second_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &first, &chain_id, 1).unwrap();
        assert!(matches!(
            apply_staking_op(&mut state, &second, &chain_id, 1),
            Err(StateError::DuplicateValidatorKey { reason })
                if reason.contains("vrf_pk")
        ));
    }

    #[test]
    fn registration_rejects_duplicate_classical_pk() {
        let mut state = ChainState::new_genesis();
        let first_keypair = keypair(0x48);
        let first_pubkey = pubkey_from_keypair(&first_keypair);
        let first_bond = insert_delegator_utxo(
            &mut state,
            first_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xA5,
        );
        let second_keypair = mixed_keypair(0x48, 0x49);
        let second_pubkey = pubkey_from_keypair(&second_keypair);
        let second_bond = insert_delegator_utxo(
            &mut state,
            second_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xA6,
        );
        let first = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id: first_bond,
                validator_pubkey: first_pubkey,
                vrf_pk: [0x48; 32],
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, 0xA5)),
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &first_keypair,
            &state.chain_id,
        );
        let second = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id: second_bond,
                validator_pubkey: second_pubkey,
                vrf_pk: [0x49; 32],
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, 0xA6)),
                cold_pubkey: None,
                cold_signature: None,
            },
            2,
            &second_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &first, &chain_id, 1).unwrap();
        assert!(matches!(
            apply_staking_op(&mut state, &second, &chain_id, 1),
            Err(StateError::ValidatorAlreadyRegistered)
        ));
    }

    #[test]
    fn registration_rejects_duplicate_pq_pk() {
        let mut state = ChainState::new_genesis();
        let first_keypair = keypair(0x4A);
        let first_pubkey = pubkey_from_keypair(&first_keypair);
        let first_bond = insert_delegator_utxo(
            &mut state,
            first_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xA7,
        );
        let second_keypair = mixed_keypair(0x4B, 0x4A);
        let second_pubkey = pubkey_from_keypair(&second_keypair);
        let second_bond = insert_delegator_utxo(
            &mut state,
            second_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xA8,
        );
        let first = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id: first_bond,
                validator_pubkey: first_pubkey,
                vrf_pk: [0x4A; 32],
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, 0xA7)),
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &first_keypair,
            &state.chain_id,
        );
        let second = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id: second_bond,
                validator_pubkey: second_pubkey,
                vrf_pk: [0x4B; 32],
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, 0xA8)),
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &second_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &first, &chain_id, 1).unwrap();
        assert!(matches!(
            apply_staking_op(&mut state, &second, &chain_id, 1),
            Err(StateError::DuplicateValidatorKey { reason })
                if reason.contains("hybrid_pq_pk")
        ));
    }

    #[test]
    fn registration_with_all_unique_keys_succeeds() {
        let mut state = ChainState::new_genesis();
        let first_keypair = keypair(0x4C);
        let first_pubkey = pubkey_from_keypair(&first_keypair);
        let first_bond = insert_delegator_utxo(
            &mut state,
            first_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xA9,
        );
        let second_keypair = keypair(0x4D);
        let second_pubkey = pubkey_from_keypair(&second_keypair);
        let second_bond = insert_delegator_utxo(
            &mut state,
            second_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xAA,
        );
        let first = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id: first_bond,
                validator_pubkey: first_pubkey,
                vrf_pk: [0x4C; 32],
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, 0xA9)),
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &first_keypair,
            &state.chain_id,
        );
        let second = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id: second_bond,
                validator_pubkey: second_pubkey,
                vrf_pk: [0x4D; 32],
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, 0xAA)),
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &second_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &first, &chain_id, 1).unwrap();
        apply_staking_op(&mut state, &second, &chain_id, 1).unwrap();
    }

    #[test]
    fn set_auto_delegate_stores_target() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0xB1);
        let (target_id, _) = make_active_validator(&mut state, 0xB2);
        let op = set_auto_delegate_op(&state, validator_id, target_id, &validator_keypair, 1);
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &op, &chain_id, 1).unwrap();
        assert_eq!(
            state
                .validators
                .get(&validator_id)
                .and_then(|v| v.auto_delegate_to),
            Some(target_id)
        );
    }

    #[test]
    fn set_auto_delegate_clears_with_zero() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0xB3);
        let (target_id, _) = make_active_validator(&mut state, 0xB4);
        let chain_id = state.chain_id.clone();
        let set = set_auto_delegate_op(&state, validator_id, target_id, &validator_keypair, 1);
        apply_staking_op(&mut state, &set, &chain_id, 1).unwrap();
        let clear =
            set_auto_delegate_op(&state, validator_id, Bytes32::ZERO, &validator_keypair, 2);
        apply_staking_op(&mut state, &clear, &chain_id, 1).unwrap();
        assert_eq!(
            state
                .validators
                .get(&validator_id)
                .and_then(|v| v.auto_delegate_to),
            None
        );
    }

    #[test]
    fn set_auto_delegate_rejects_self() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0xB5);
        let op = set_auto_delegate_op(&state, validator_id, validator_id, &validator_keypair, 1);
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::InvalidStakingOp(msg)) if msg.contains("cannot auto-delegate to self")
        ));
    }

    #[test]
    fn set_auto_delegate_rejects_nonexistent_target() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0xB6);
        let op = set_auto_delegate_op(
            &state,
            validator_id,
            Bytes32::from([0xCC; 32]),
            &validator_keypair,
            1,
        );
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::ValidatorNotFound)
        ));
    }

    #[test]
    fn set_auto_delegate_rejects_slashed_validator() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0xB7);
        let (target_id, _) = make_active_validator(&mut state, 0xB8);
        if let Some(v) = state.validators.get_mut(&validator_id) {
            v.status = ValidatorStatus::Slashed;
        }
        let op = set_auto_delegate_op(&state, validator_id, target_id, &validator_keypair, 1);
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::ValidatorNotActive)
        ));
    }

    fn raw_pubkey(byte: u8) -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::from([byte; 32]),
            pq_pk: VariableBytes::from_slice(&[byte; 32]).unwrap(),
        }
    }

    fn raw_output(value_spark: u64, owner_pubkey: HybridPubKey, byte: u8) -> OutputV1 {
        OutputV1 {
            value_spark,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from([byte; 32]),
            },
            owner_pubkey,
            range_proof: VariableBytes::from_slice(&[byte]).unwrap(),
            lock_height: 0,
        }
    }

    fn raw_id(domain: u8, index: usize) -> Bytes32 {
        let mut bytes = [0u8; 32];
        bytes[0] = domain;
        bytes[8..16].copy_from_slice(&(index as u64).to_be_bytes());
        Bytes32::from(bytes)
    }

    fn insert_registry_entry_for_cap_test(
        state: &mut ChainState,
        index: usize,
        stake: u64,
    ) -> Bytes32 {
        let validator_id = raw_id(0x44, index);
        let pk_byte = (index % 200) as u8;
        let pubkey = raw_pubkey(pk_byte);
        let bond_utxo_id = raw_id(0x55, index);
        state
            .validators
            .upsert(ValidatorEntry {
                validator_id,
                name: format!("cap-{index}"),
                hybrid_classical_pk: Some(pubkey.classical_pk.0),
                hybrid_pq_pk: Some(pubkey.pq_pk.as_slice().to_vec()),
                vrf_pk: Some(raw_id(0x66, index).0),
                stake_spark: stake,
                status: ValidatorStatus::Registered,
                registered_epoch: 0,
                last_active_epoch: 0,
                pending_rewards: 0,
                rewards_last_epoch: 0,
                self_report_count: 0,
                commission_bps: 1_000,
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
            })
            .unwrap();
        state.staked_bonds.insert(
            bond_utxo_id,
            StakeBondEntry {
                utxo_id: bond_utxo_id,
                validator_id,
                delegator_id: validator_id,
                amount_spark: stake,
                bonded_epoch: 0,
                unbonding_end_epoch: None,
                custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                    validator_id,
                ),
                original_output: raw_output(stake, pubkey, (index % 200) as u8).into(),
            },
        );
        validator_id
    }

    fn fill_registry_to_cap(state: &mut ChainState, lowest_stake: u64) -> Bytes32 {
        let lowest_id = insert_registry_entry_for_cap_test(state, 0, lowest_stake);
        for index in 1..MAX_VALIDATORS {
            insert_registry_entry_for_cap_test(
                state,
                index,
                lowest_stake
                    .saturating_add(DUST_LIMIT_SPARK.saturating_mul(10))
                    .saturating_add(index as u64),
            );
        }
        lowest_id
    }

    fn registration_op_with_bond(
        state: &mut ChainState,
        seed: u8,
        amount: u64,
        nonce: u64,
    ) -> (StakingOp, Bytes32) {
        let keypair = keypair(seed);
        let pubkey = pubkey_from_keypair(&keypair);
        let bond_utxo_id = insert_delegator_utxo(state, pubkey.clone(), amount, seed);
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id,
                validator_pubkey: pubkey,
                vrf_pk: [seed; 32],
                bond_proof: Some(bond_proof(amount, seed)),
                cold_pubkey: None,
                cold_signature: None,
            },
            nonce,
            &keypair,
            &state.chain_id,
        );
        (op, bond_utxo_id)
    }

    #[test]
    fn registration_at_cap_pre_activation_rejects_unchanged() {
        let mut state = ChainState::new_genesis();
        fill_registry_to_cap(&mut state, MINIMUM_VALIDATOR_BOND_SPARK);
        let (op, bond_utxo_id) = registration_op_with_bond(
            &mut state,
            0xF1,
            MINIMUM_VALIDATOR_BOND_SPARK.saturating_mul(10),
            1,
        );
        let chain_id = state.chain_id.clone();

        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::InvariantViolation { message })
                if message == "validator set at maximum capacity"
        ));
        assert!(state.utxos.contains(&bond_utxo_id));
        assert_eq!(state.validators.len(), MAX_VALIDATORS);
    }

    #[test]
    fn registration_at_cap_post_activation_rejects_if_not_higher_total_stake() {
        let mut state = ChainState::new_genesis();
        fill_registry_to_cap(&mut state, MINIMUM_VALIDATOR_BOND_SPARK);
        let (op, bond_utxo_id) =
            registration_op_with_bond(&mut state, 0xF2, MINIMUM_VALIDATOR_BOND_SPARK, 1);
        let chain_id = state.chain_id.clone();

        assert!(matches!(
            apply_staking_op(
                &mut state,
                &op,
                &chain_id,
                VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT - 1,
            ),
            Err(StateError::InvalidStakingOp(reason))
                if reason.contains("validator registry at capacity")
        ));
        assert!(state.utxos.contains(&bond_utxo_id));
        assert_eq!(state.validators.len(), MAX_VALIDATORS);
    }

    #[test]
    fn registration_at_cap_post_activation_evicts_lowest_and_refunds_all_bonds() {
        let mut state = ChainState::new_genesis();
        let lowest_id = fill_registry_to_cap(&mut state, MINIMUM_VALIDATOR_BOND_SPARK);
        let delegator = raw_id(0x77, 1);
        let delegator_bond = raw_id(0x78, 1);
        let delegator_pubkey = raw_pubkey(0x7A);
        state
            .delegations
            .add_delegation(lowest_id, delegator, DUST_LIMIT_SPARK, 0)
            .unwrap();
        state.staked_bonds.insert(
            delegator_bond,
            StakeBondEntry {
                utxo_id: delegator_bond,
                validator_id: lowest_id,
                delegator_id: delegator,
                amount_spark: DUST_LIMIT_SPARK,
                bonded_epoch: 0,
                unbonding_end_epoch: None,
                custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                    delegator,
                ),
                original_output: test_output(DUST_LIMIT_SPARK, delegator_pubkey, 0x7A).into(),
            },
        );
        let (op, new_bond) = registration_op_with_bond(
            &mut state,
            0xF3,
            MINIMUM_VALIDATOR_BOND_SPARK
                .saturating_add(DUST_LIMIT_SPARK)
                .saturating_add(1),
            1,
        );
        let chain_id = state.chain_id.clone();

        apply_staking_op(
            &mut state,
            &op,
            &chain_id,
            VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT - 1,
        )
        .unwrap();

        assert_eq!(state.validators.len(), MAX_VALIDATORS);
        assert!(state.validators.get(&lowest_id).is_none());
        assert!(state.staked_bonds.contains_key(&new_bond));
        assert!(!state.staked_bonds.contains_key(&delegator_bond));
        assert!(state.delegations.get_delegators(&lowest_id).is_empty());
        assert_eq!(state.delegation_return_events.len(), 2);
        assert!(state
            .delegation_return_events
            .iter()
            .any(|event| event.delegator_id == lowest_id
                && event.reason == DelegationReturnReason::ValidatorEvicted));
        assert!(state
            .delegation_return_events
            .iter()
            .any(|event| event.delegator_id == delegator
                && event.reason == DelegationReturnReason::ValidatorEvicted));
    }

    #[test]
    fn enforcement_prevents_registry_eviction_from_bypassing_frozen_custody() {
        let mut state = ChainState::new_genesis();
        let validator_id =
            insert_registry_entry_for_cap_test(&mut state, 0, MINIMUM_VALIDATOR_BOND_SPARK);
        let validator = state.validators.get_mut(&validator_id).unwrap();
        validator.status = ValidatorStatus::Registered;
        validator.pending_rewards = DUST_LIMIT_SPARK;
        let bond_count = state.staked_bonds.len();

        let error = evict_validator_for_registry_replacement(
            &mut state,
            validator_id,
            0,
            VALIDATOR_COLD_KEY_ENFORCEMENT_HEIGHT,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            StateError::InvalidStakingOp(reason)
                if reason.contains("custody is frozen")
                    && reason.contains("EnrollValidatorColdKey")
        ));
        assert!(state.validators.get(&validator_id).is_some());
        assert_eq!(state.staked_bonds.len(), bond_count);
        assert_eq!(
            state.validators.get(&validator_id).unwrap().pending_rewards,
            DUST_LIMIT_SPARK
        );
        assert!(state.delegation_return_events.is_empty());
    }

    #[test]
    fn validator_eviction_pays_claimable_rewards_and_burns_dust_rewards() {
        let mut state = ChainState::new_genesis();
        let lowest_id = fill_registry_to_cap(&mut state, MINIMUM_VALIDATOR_BOND_SPARK);
        state
            .validators
            .get_mut(&lowest_id)
            .unwrap()
            .pending_rewards = DUST_LIMIT_SPARK;
        let delegator = raw_id(0x79, 1);
        let delegator_bond = raw_id(0x7B, 1);
        state
            .delegations
            .add_delegation(lowest_id, delegator, DUST_LIMIT_SPARK, 0)
            .unwrap();
        state
            .delegations
            .update_delegator(&lowest_id, &delegator, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK - 1;
            })
            .unwrap();
        state.staked_bonds.insert(
            delegator_bond,
            StakeBondEntry {
                utxo_id: delegator_bond,
                validator_id: lowest_id,
                delegator_id: delegator,
                amount_spark: DUST_LIMIT_SPARK,
                bonded_epoch: 0,
                unbonding_end_epoch: None,
                custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                    delegator,
                ),
                original_output: test_output(DUST_LIMIT_SPARK, raw_pubkey(0x7C), 0x7C).into(),
            },
        );
        let utxos_before = state.utxos.len();
        let (op, _) = registration_op_with_bond(
            &mut state,
            0xF4,
            MINIMUM_VALIDATOR_BOND_SPARK
                .saturating_add(DUST_LIMIT_SPARK)
                .saturating_add(1),
            1,
        );
        let chain_id = state.chain_id.clone();

        apply_staking_op(
            &mut state,
            &op,
            &chain_id,
            VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT - 1,
        )
        .unwrap();

        assert!(state.validators.get(&lowest_id).is_none());
        assert!(state.utxos.len() >= utxos_before.saturating_add(2));
        assert!(state
            .delegation_return_events
            .iter()
            .any(|event| event.delegator_id == delegator));
    }

    #[test]
    fn validator_eviction_resolves_fully_compact_bond_owner_from_registry() {
        let mut state = ChainState::new_genesis();
        let lowest_id = fill_registry_to_cap(&mut state, MINIMUM_VALIDATOR_BOND_SPARK);
        let delegator = raw_id(0x7D, 1);
        let delegator_bond = raw_id(0x7E, 1);
        let delegator_pubkey = raw_pubkey(0x7F);
        state
            .delegator_identities
            .insert(delegator, delegator_pubkey.clone());
        state
            .delegations
            .add_delegation(lowest_id, delegator, DUST_LIMIT_SPARK, 0)
            .unwrap();
        state
            .delegations
            .update_delegator(&lowest_id, &delegator, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();
        let compact_bond = StakeBondEntry::new_for_test_with_compact_and_pubkey_activation(
            delegator_bond,
            lowest_id,
            delegator,
            DUST_LIMIT_SPARK,
            0,
            test_output(DUST_LIMIT_SPARK, delegator_pubkey.clone(), 0x7F),
            20,
            10,
            20,
        );
        assert!(compact_bond.original_output.owner_pubkey.is_none());
        state.staked_bonds.insert(delegator_bond, compact_bond);
        let (op, _) = registration_op_with_bond(
            &mut state,
            0xF5,
            MINIMUM_VALIDATOR_BOND_SPARK
                .saturating_add(DUST_LIMIT_SPARK)
                .saturating_add(1),
            1,
        );
        let chain_id = state.chain_id.clone();

        apply_staking_op(
            &mut state,
            &op,
            &chain_id,
            VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT - 1,
        )
        .unwrap();

        assert!(state.validators.get(&lowest_id).is_none());
        let matching_outputs = state
            .utxos
            .all_entries()
            .filter(|entry| {
                entry.output.owner_pubkey == delegator_pubkey
                    && entry.output.value_spark == DUST_LIMIT_SPARK
            })
            .count();
        assert!(
            matching_outputs >= 2,
            "expected reward payout and returned principal to resolve to registry owner"
        );
    }

    #[test]
    fn delegation_return_event_log_prunes_oldest_entries() {
        let mut state = ChainState::new_genesis();
        for i in 0..=indra_core::types::primitives::MAX_DELEGATION_RETURN_EVENTS {
            state.push_delegation_return_event(DelegationReturnEvent {
                delegator_id: raw_id(0xA0, i),
                validator_id: raw_id(0xA1, i),
                bond_utxo_id: raw_id(0xA2, i),
                amount_spark: 1,
                reason: DelegationReturnReason::ValidatorEvicted,
                returned_epoch: i as u64,
                returned_height: i as u64,
                refund_utxo_id: raw_id(0xA3, i),
            });
        }
        assert_eq!(
            state.delegation_return_events.len(),
            indra_core::types::primitives::MAX_DELEGATION_RETURN_EVENTS
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
    fn validator_owned_ops_do_not_force_remove_specific_delegators() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0xC1);
        let delegator_keypair = keypair(0xC2);
        let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        state
            .delegations
            .add_delegation(validator_id, delegator_id, DUST_LIMIT_SPARK, 0)
            .unwrap();
        let chain_id = state.chain_id.clone();
        let op = set_auto_delegate_op(&state, validator_id, Bytes32::ZERO, &validator_keypair, 1);

        apply_staking_op(&mut state, &op, &chain_id, 1).unwrap();

        assert!(state
            .delegations
            .get_delegators(&validator_id)
            .iter()
            .any(|entry| entry.delegator_id == delegator_id));
    }

    #[test]
    fn register_validator_pre_cold_gate_legacy_hot_only_succeeds() {
        let mut state = ChainState::new_genesis();
        let hot = keypair(0xD1);
        let hot_pubkey = pubkey_from_keypair(&hot);
        let bond_utxo_id = insert_delegator_utxo(
            &mut state,
            hot_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xD1,
        );
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id,
                validator_pubkey: hot_pubkey.clone(),
                vrf_pk: [0xD2; 32],
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, 0xD1)),
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &hot,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        apply_staking_op(
            &mut state,
            &op,
            &chain_id,
            VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT - 1,
        )
        .unwrap();
        let entry = state.validators.get(&pubkey_to_id(&hot_pubkey)).unwrap();
        assert_eq!(entry.cold_key_status, ColdKeyStatus::Unenrolled);
        assert_eq!(entry.cold_key_version, 0);
        assert_eq!(entry.cold_nonce, 0);
    }

    #[test]
    fn register_validator_post_gate_dual_signature_installs_active_cold_key() {
        let hot = keypair(0xD3);
        let cold = mixed_keypair(0xD4, 0xD5);
        let expected_cold = cold.public_key();
        let (mut state, bond_utxo_id, op) = post_gate_registration_fixture(&hot, &cold, 0xD6);
        let chain_id = state.chain_id.clone();

        apply_staking_op(
            &mut state,
            &op,
            &chain_id,
            VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT,
        )
        .unwrap();

        let validator_id = pubkey_to_id(&pubkey_from_keypair(&hot));
        let entry = state.validators.get(&validator_id).unwrap();
        assert_eq!(entry.cold_key_status, ColdKeyStatus::Active);
        assert_eq!(entry.cold_key_version, 1);
        assert_eq!(entry.cold_nonce, 0);
        assert_eq!(
            entry.cold_hybrid_classical_pk,
            Some(expected_cold.classical.0)
        );
        assert_eq!(entry.cold_hybrid_pq_pk, Some(expected_cold.pq.0));
        assert!(!state.utxos.contains(&bond_utxo_id));
        assert!(state.staked_bonds.contains_key(&bond_utxo_id));
    }

    #[test]
    fn register_validator_post_gate_rejects_missing_cold_key() {
        let mut state = ChainState::new_genesis();
        state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
        let hot = keypair(0xD7);
        let hot_pubkey = pubkey_from_keypair(&hot);
        let bond_utxo_id = insert_delegator_utxo(
            &mut state,
            hot_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xD7,
        );
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id,
                validator_pubkey: hot_pubkey,
                vrf_pk: [0xD8; 32],
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, 0xD7)),
                cold_pubkey: None,
                cold_signature: None,
            },
            1,
            &hot,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();

        assert!(apply_staking_op(
            &mut state,
            &op,
            &chain_id,
            VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT
        )
        .is_err());
        assert!(state.utxos.contains(&bond_utxo_id));
    }

    #[test]
    fn register_validator_post_gate_rejects_single_and_mixed_hybrid_signatures() {
        let cases = ["hot-only", "cold-only", "mixed"];
        for (index, case) in cases.into_iter().enumerate() {
            let hot = keypair(0xE0 + index as u8);
            let cold = mixed_keypair(0xE4 + index as u8, 0xE8 + index as u8);
            let (mut state, bond_utxo_id, mut op) =
                post_gate_registration_fixture(&hot, &cold, 0xEC + index as u8);
            match case {
                "hot-only" => {
                    let StakingOpBody::RegisterValidator { cold_signature, .. } = &mut op.body
                    else {
                        unreachable!()
                    };
                    *cold_signature = None;
                }
                "cold-only" => op.signature = dummy_signature(),
                "mixed" => {
                    let StakingOpBody::RegisterValidator {
                        cold_signature: Some(cold_signature),
                        ..
                    } = &op.body
                    else {
                        unreachable!()
                    };
                    op.signature.pq_sig = cold_signature.pq_sig.clone();
                }
                _ => unreachable!(),
            }
            let chain_id = state.chain_id.clone();
            assert!(
                apply_staking_op(
                    &mut state,
                    &op,
                    &chain_id,
                    VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT
                )
                .is_err(),
                "{case} registration must fail"
            );
            assert!(state.utxos.contains(&bond_utxo_id));
            assert!(state.validators.is_empty());
        }
    }

    #[test]
    fn register_validator_post_gate_rejects_cross_role_component_reuse() {
        let mut state = ChainState::new_genesis();
        state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
        let (_, existing_hot) = make_active_validator(&mut state, 0xA1);
        let hot = keypair(0xA2);
        let cold = mixed_keypair(0xA1, 0xA3);
        let cold_owner = pubkey_from_keypair(&cold);
        let bond_utxo_id =
            insert_delegator_utxo(&mut state, cold_owner, MINIMUM_VALIDATOR_BOND_SPARK, 0xA4);
        let op = dual_signed_register_op(
            bond_utxo_id,
            &hot,
            &cold,
            1,
            &state.chain_id,
            [0xA5; 32],
            0xA4,
        );
        let chain_id = state.chain_id.clone();
        let before_count = state.validators.len();

        assert!(apply_staking_op(
            &mut state,
            &op,
            &chain_id,
            VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT
        )
        .is_err());
        assert_eq!(state.validators.len(), before_count);
        assert!(state.utxos.contains(&bond_utxo_id));
        drop(existing_hot);
    }

    #[test]
    fn register_validator_cold_gate_boundary_replay_is_deterministic() {
        fn replay() -> ChainState {
            let mut state = ChainState::new_genesis();
            let pre_hot = keypair(0xB1);
            let pre_pubkey = pubkey_from_keypair(&pre_hot);
            let pre_bond = insert_delegator_utxo(
                &mut state,
                pre_pubkey.clone(),
                MINIMUM_VALIDATOR_BOND_SPARK,
                0xB1,
            );
            let pre_op = signed_op(
                StakingOpBody::RegisterValidator {
                    commission_bps: 1_000,
                    bond_utxo_id: pre_bond,
                    validator_pubkey: pre_pubkey,
                    vrf_pk: [0xB2; 32],
                    bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, 0xB1)),
                    cold_pubkey: None,
                    cold_signature: None,
                },
                1,
                &pre_hot,
                &state.chain_id,
            );
            state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT - 1;
            let pre_height = state.height;
            let chain_id = state.chain_id.clone();
            apply_staking_op(&mut state, &pre_op, &chain_id, pre_height).unwrap();

            let post_hot = keypair(0xB3);
            let post_cold = mixed_keypair(0xB4, 0xB5);
            let post_bond = insert_delegator_utxo(
                &mut state,
                pubkey_from_keypair(&post_cold),
                MINIMUM_VALIDATOR_BOND_SPARK,
                0xB6,
            );
            let post_op = dual_signed_register_op(
                post_bond,
                &post_hot,
                &post_cold,
                1,
                &state.chain_id,
                [0xB7; 32],
                0xB6,
            );
            state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
            let post_height = state.height;
            apply_staking_op(&mut state, &post_op, &chain_id, post_height).unwrap();
            state
        }

        let first = replay();
        let second = replay();
        assert_eq!(first, second);
        assert_eq!(
            crate::compute_state_root(&first),
            crate::compute_state_root(&second)
        );
        assert_eq!(
            first
                .validators
                .all_validators()
                .filter(|entry| entry.cold_key_status == ColdKeyStatus::Active)
                .count(),
            1
        );
    }

    #[test]
    fn enroll_validator_cold_key_pre_gate_is_structurally_rejected() {
        let mut state = ChainState::new_genesis();
        let (validator_id, hot) = make_active_validator(&mut state, 0x31);
        let cold = mixed_keypair(0x32, 0x33);
        let op = dual_signed_enroll_op(validator_id, &hot, &cold, 1, &state.chain_id);
        let chain_id = state.chain_id.clone();

        assert!(apply_staking_op(
            &mut state,
            &op,
            &chain_id,
            VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT - 1,
        )
        .is_err());
        let entry = state.validators.get(&validator_id).unwrap();
        assert_eq!(entry.cold_key_status, ColdKeyStatus::Unenrolled);
        assert_eq!(entry.cold_key_version, 0);
    }

    #[test]
    fn enroll_validator_cold_key_post_gate_succeeds_for_unenrolled_validator() {
        let mut state = ChainState::new_genesis();
        state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
        let (validator_id, hot) = make_active_validator(&mut state, 0x34);
        let cold = mixed_keypair(0x35, 0x36);
        let expected = cold.public_key();
        let op = dual_signed_enroll_op(validator_id, &hot, &cold, 1, &state.chain_id);
        let chain_id = state.chain_id.clone();

        apply_staking_op(
            &mut state,
            &op,
            &chain_id,
            VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT,
        )
        .unwrap();

        let entry = state.validators.get(&validator_id).unwrap();
        assert_eq!(entry.cold_key_status, ColdKeyStatus::Active);
        assert_eq!(entry.cold_key_version, 1);
        assert_eq!(entry.cold_nonce, 0);
        assert_eq!(entry.cold_hybrid_classical_pk, Some(expected.classical.0));
        assert_eq!(entry.cold_hybrid_pq_pk, Some(expected.pq.0));
        assert_eq!(state.staking_nonces.get(&validator_id), Some(&1));
    }

    #[test]
    fn enroll_validator_cold_key_rejects_unregistered_validator() {
        let mut state = ChainState::new_genesis();
        state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
        let hot = keypair(0x37);
        let validator_id = pubkey_to_id(&pubkey_from_keypair(&hot));
        let cold = mixed_keypair(0x38, 0x39);
        let op = dual_signed_enroll_op(validator_id, &hot, &cold, 1, &state.chain_id);
        let chain_id = state.chain_id.clone();

        assert_eq!(
            apply_staking_op(
                &mut state,
                &op,
                &chain_id,
                VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT,
            ),
            Err(StateError::ValidatorNotFound)
        );
        assert!(state.validators.is_empty());
    }

    #[test]
    fn enroll_validator_cold_key_rejects_already_active_validator() {
        let mut state = ChainState::new_genesis();
        state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
        let (validator_id, hot) = make_active_validator(&mut state, 0x3A);
        let existing_cold = mixed_keypair(0x3B, 0x3C).public_key();
        {
            let entry = state.validators.get_mut(&validator_id).unwrap();
            entry.cold_hybrid_classical_pk = Some(existing_cold.classical.0);
            entry.cold_hybrid_pq_pk = Some(existing_cold.pq.0);
            entry.cold_key_version = 1;
            entry.cold_key_status = ColdKeyStatus::Active;
        }
        let proposed = mixed_keypair(0x3D, 0x3E);
        let op = dual_signed_enroll_op(validator_id, &hot, &proposed, 1, &state.chain_id);
        let chain_id = state.chain_id.clone();

        assert!(matches!(
            apply_staking_op(
                &mut state,
                &op,
                &chain_id,
                VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT,
            ),
            Err(StateError::InvalidStakingOp(reason))
                if reason.contains("already enrolled")
        ));
        let entry = state.validators.get(&validator_id).unwrap();
        assert_eq!(
            entry.cold_hybrid_classical_pk,
            Some(existing_cold.classical.0)
        );
        assert_eq!(entry.cold_hybrid_pq_pk, Some(existing_cold.pq.0));
        assert_eq!(entry.cold_key_version, 1);
    }

    #[test]
    fn enroll_validator_cold_key_requires_both_complete_hybrid_signatures() {
        for case in ["hot-only", "cold-only", "mixed-hot-slot", "mixed-cold-slot"] {
            let mut state = ChainState::new_genesis();
            state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
            let (validator_id, hot) = make_active_validator(&mut state, 0x40);
            let cold = mixed_keypair(0x41, 0x42);
            let mut op = dual_signed_enroll_op(validator_id, &hot, &cold, 1, &state.chain_id);
            let StakingOpBody::EnrollValidatorColdKey { cold_signature, .. } = &mut op.body else {
                unreachable!()
            };
            match case {
                "hot-only" => *cold_signature = None,
                "cold-only" => op.signature = dummy_signature(),
                "mixed-hot-slot" => {
                    op.signature.pq_sig = cold_signature.as_ref().unwrap().pq_sig.clone()
                }
                "mixed-cold-slot" => {
                    cold_signature.as_mut().unwrap().classical_sig =
                        op.signature.classical_sig.clone()
                }
                _ => unreachable!(),
            }
            let chain_id = state.chain_id.clone();

            assert!(
                apply_staking_op(
                    &mut state,
                    &op,
                    &chain_id,
                    VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT,
                )
                .is_err(),
                "{case} enrollment must fail"
            );
            assert_eq!(
                state.validators.get(&validator_id).unwrap().cold_key_status,
                ColdKeyStatus::Unenrolled
            );
            assert!(state.staking_nonces.get(&validator_id).is_none());
        }
    }

    #[test]
    fn enroll_validator_cold_key_rejects_cross_role_component_reuse() {
        let mut state = ChainState::new_genesis();
        state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
        let (target_id, target_hot) = make_active_validator(&mut state, 0x43);
        let (_, other_hot) = make_active_validator(&mut state, 0x44);
        let proposed_cold = mixed_keypair(0x44, 0x45);
        let op = dual_signed_enroll_op(target_id, &target_hot, &proposed_cold, 1, &state.chain_id);
        let chain_id = state.chain_id.clone();

        assert!(matches!(
            apply_staking_op(
                &mut state,
                &op,
                &chain_id,
                VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT,
            ),
            Err(StateError::DuplicateValidatorKey { .. })
        ));
        assert_eq!(
            state.validators.get(&target_id).unwrap().cold_key_status,
            ColdKeyStatus::Unenrolled
        );
        drop(other_hot);
    }

    #[test]
    fn enroll_validator_cold_key_activation_boundary_replay_is_deterministic() {
        fn replay() -> ChainState {
            let mut state = ChainState::new_genesis();
            let (validator_id, hot) = make_active_validator(&mut state, 0x46);
            let commission = signed_op(
                StakingOpBody::SetCommission {
                    validator_id,
                    new_commission_bps: 1_250,
                    cold_authorization: None,
                },
                1,
                &hot,
                &state.chain_id,
            );
            state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT - 1;
            let chain_id = state.chain_id.clone();
            let pre_height = state.height;
            apply_staking_op(&mut state, &commission, &chain_id, pre_height).unwrap();

            let cold = mixed_keypair(0x47, 0x48);
            let enrollment = dual_signed_enroll_op(validator_id, &hot, &cold, 2, &state.chain_id);
            state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
            let enrollment_height = state.height;
            apply_staking_op(&mut state, &enrollment, &chain_id, enrollment_height).unwrap();

            let address = signed_op(
                StakingOpBody::UpdateNetworkAddress {
                    validator_id,
                    network_addr: Some("203.0.113.46:30303".into()),
                },
                3,
                &hot,
                &state.chain_id,
            );
            apply_staking_op(&mut state, &address, &chain_id, enrollment_height).unwrap();
            state
        }

        let first = replay();
        let second = replay();
        assert_eq!(first, second);
        assert_eq!(
            crate::compute_state_root(&first),
            crate::compute_state_root(&second)
        );
        let enrolled = first
            .validators
            .all_validators()
            .find(|entry| entry.cold_key_status == ColdKeyStatus::Active)
            .unwrap();
        assert_eq!(enrolled.cold_key_version, 1);
        assert_eq!(enrolled.cold_nonce, 0);
        assert_eq!(first.staking_nonces.get(&enrolled.validator_id), Some(&3));
    }

    #[test]
    #[ignore = "release-mode atomic cold-key migration cost benchmark"]
    fn atomic_cold_key_migration_cap_cost_benchmark() {
        use std::time::Instant;

        let mut state = ChainState::new_genesis();
        state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
        let (validator_id, hot) = make_active_validator(&mut state, 0x71);
        let owner = pubkey_from_keypair(&hot);
        for index in 0..MAX_ATOMIC_COLD_KEY_MIGRATION_SELF_BONDS {
            let mut raw = [0u8; 32];
            raw[..8].copy_from_slice(&(index as u64).to_le_bytes());
            let id = Bytes32::from(raw);
            let bond = StakeBondEntry::new(
                id,
                validator_id,
                validator_id,
                DUST_LIMIT_SPARK,
                0,
                raw_output(DUST_LIMIT_SPARK, owner.clone(), (index % 251) as u8 + 1),
                VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT - 1,
            );
            state.staked_bonds.insert(id, bond);
        }
        state.rebuild_state_commitment_v2(VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT);
        let cold = mixed_keypair(0x72, 0x73);
        let op = dual_signed_enroll_op(validator_id, &hot, &cold, 1, &state.chain_id);
        let chain_id = state.chain_id.clone();
        let start = Instant::now();
        apply_staking_op(
            &mut state,
            &op,
            &chain_id,
            VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT,
        )
        .unwrap();
        let elapsed = start.elapsed();
        println!(
            "atomic_cold_key_migration bonds={} elapsed={elapsed:?}",
            MAX_ATOMIC_COLD_KEY_MIGRATION_SELF_BONDS
        );
        assert!(elapsed < std::time::Duration::from_secs(2));
    }

    fn insert_self_bonds(
        state: &mut ChainState,
        validator_id: Bytes32,
        owner: &HybridPubKey,
        count: usize,
    ) {
        for index in 0..count {
            let mut raw = [0u8; 32];
            raw[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
            raw[8] = validator_id.0[0];
            let id = Bytes32::from(raw);
            let bond = StakeBondEntry::new(
                id,
                validator_id,
                validator_id,
                DUST_LIMIT_SPARK,
                0,
                raw_output(DUST_LIMIT_SPARK, owner.clone(), (index % 251) as u8 + 1),
                VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT - 1,
            );
            state.staked_bonds.insert(id, bond);
        }
    }

    #[test]
    fn enrolled_validator_migrates_realistic_self_bond_population_atomically() {
        let mut state = ChainState::new_genesis();
        state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
        let (validator_id, hot) = make_active_validator(&mut state, 0x74);
        insert_self_bonds(&mut state, validator_id, &pubkey_from_keypair(&hot), 64);
        let cold = mixed_keypair(0x75, 0x76);
        let op = dual_signed_enroll_op(validator_id, &hot, &cold, 1, &state.chain_id);
        let chain_id = state.chain_id.clone();
        let height = state.height;
        apply_staking_op(&mut state, &op, &chain_id, height).unwrap();
        assert_eq!(
            state
                .staked_bonds
                .values()
                .filter(|bond| bond.custody_owner
                    == StakeBondCustodyOwner::ValidatorColdIdentity(validator_id))
                .count(),
            64
        );

        let migrated = state.staked_bonds.values().next().unwrap().clone();
        let release = crate::epoch::released_bond_output(&state, &migrated, state.height).unwrap();
        let expected_cold = pubkey_from_keypair(&cold);
        assert_eq!(release.owner_pubkey, expected_cold);
        let release_blinding =
            crate::epoch::derive_compact_stake_bond_release_blinding(&migrated, state.height);
        indra_crypto::verify_opening(
            &indra_crypto::PedersenCommitment(release.commitment.compressed_point.0),
            &indra_crypto::PedersenOpening {
                value: release.value_spark,
                blinding: release_blinding,
            },
        )
        .unwrap();

        state
            .validators
            .get_mut(&validator_id)
            .unwrap()
            .pending_rewards = DUST_LIMIT_SPARK;
        let claim = cold_signed_op(
            StakingOpBody::ClaimRewards {
                validator_id,
                delegator_pubkey: pubkey_from_keypair(&hot),
                cold_authorization: cold_auth(1),
            },
            &cold,
            &state.chain_id,
        );
        let claim_height = state.height;
        apply_staking_op(&mut state, &claim, &chain_id, claim_height).unwrap();
        let reward = state
            .utxos
            .all_entries()
            .find(|entry| entry.output.owner_pubkey == expected_cold)
            .unwrap()
            .output
            .clone();
        assert_eq!(reward.owner_pubkey, expected_cold);
        let reward_blinding = indra_crypto::sha256(
            &[
                STAKING_REWARD_BLINDING_DOMAIN,
                validator_id.0.as_slice(),
                validator_id.0.as_slice(),
                claim_height.to_le_bytes().as_slice(),
            ]
            .concat(),
        );
        indra_crypto::verify_opening(
            &indra_crypto::PedersenCommitment(reward.commitment.compressed_point.0),
            &indra_crypto::PedersenOpening {
                value: reward.value_spark,
                blinding: reward_blinding,
            },
        )
        .unwrap();
    }

    #[test]
    fn unenrolled_validator_and_ordinary_delegator_outputs_remain_legacy_owned() {
        let mut state = ChainState::new_genesis();
        let (validator_id, hot) = make_active_validator(&mut state, 0x7E);
        state
            .delegator_identities
            .insert(validator_id, pubkey_from_keypair(&hot));
        insert_self_bonds(&mut state, validator_id, &pubkey_from_keypair(&hot), 1);
        let self_bond = state.staked_bonds.values().next().unwrap().clone();
        let self_release = crate::epoch::released_bond_output(
            &state,
            &self_bond,
            VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT - 1,
        )
        .unwrap();
        assert_eq!(self_release.owner_pubkey, pubkey_from_keypair(&hot));

        let delegator = keypair(0x7F);
        let delegator_pubkey = pubkey_from_keypair(&delegator);
        state
            .delegator_identities
            .insert(pubkey_to_id(&delegator_pubkey), delegator_pubkey.clone());
        let mut delegated = StakeBondEntry::new(
            Bytes32::from([0x80; 32]),
            validator_id,
            pubkey_to_id(&delegator_pubkey),
            DUST_LIMIT_SPARK,
            0,
            raw_output(DUST_LIMIT_SPARK, delegator_pubkey.clone(), 0x80),
            VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT - 1,
        );
        delegated.unbonding_end_epoch = Some(0);
        let delegated_release = crate::epoch::released_bond_output(
            &state,
            &delegated,
            VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT,
        )
        .unwrap();
        assert_eq!(delegated_release.owner_pubkey, delegator_pubkey);
        assert_eq!(
            delegated.custody_owner,
            StakeBondCustodyOwner::DelegatorIdentity(pubkey_to_id(&delegated_release.owner_pubkey))
        );
    }

    #[test]
    fn mixed_cold_and_legacy_owner_resolution_replays_deterministically() {
        fn replay() -> Vec<Vec<u8>> {
            let mut state = ChainState::new_genesis();
            state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
            let (cold_id, cold_hot) = make_active_validator(&mut state, 0x81);
            let (legacy_id, legacy_hot) = make_active_validator(&mut state, 0x82);
            state
                .delegator_identities
                .insert(legacy_id, pubkey_from_keypair(&legacy_hot));
            insert_self_bonds(&mut state, cold_id, &pubkey_from_keypair(&cold_hot), 3);
            insert_self_bonds(&mut state, legacy_id, &pubkey_from_keypair(&legacy_hot), 2);
            let cold = mixed_keypair(0x83, 0x84);
            let enroll = dual_signed_enroll_op(cold_id, &cold_hot, &cold, 1, &state.chain_id);
            let chain_id = state.chain_id.clone();
            let height = state.height;
            apply_staking_op(&mut state, &enroll, &chain_id, height).unwrap();
            state
                .staked_bonds
                .values()
                .map(|bond| {
                    crate::epoch::released_bond_output(&state, bond, height)
                        .unwrap()
                        .encode_to_vec()
                })
                .collect()
        }
        assert_eq!(replay(), replay());
    }

    #[test]
    fn enrollment_rejects_self_bond_count_above_atomic_cap() {
        let mut state = ChainState::new_genesis();
        state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
        let (validator_id, hot) = make_active_validator(&mut state, 0x77);
        insert_self_bonds(
            &mut state,
            validator_id,
            &pubkey_from_keypair(&hot),
            MAX_ATOMIC_COLD_KEY_MIGRATION_SELF_BONDS + 1,
        );
        let cold = mixed_keypair(0x78, 0x79);
        let op = dual_signed_enroll_op(validator_id, &hot, &cold, 1, &state.chain_id);
        let chain_id = state.chain_id.clone();
        let height = state.height;
        let err = apply_staking_op(&mut state, &op, &chain_id, height).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("4097 unresolved self-bonds"));
        assert!(text.contains("at most 4096"));
        assert!(text.contains("SelfUnstake"));
        assert!(text.contains("SelfStake one consolidated UTXO"));
        assert_eq!(
            state.validators.get(&validator_id).unwrap().cold_key_status,
            ColdKeyStatus::Unenrolled
        );
    }

    #[test]
    fn consolidation_to_one_self_bond_allows_enrollment_after_cap_rejection() {
        let mut state = ChainState::new_genesis();
        state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
        let (validator_id, hot) = make_active_validator(&mut state, 0x7A);
        insert_self_bonds(
            &mut state,
            validator_id,
            &pubkey_from_keypair(&hot),
            MAX_ATOMIC_COLD_KEY_MIGRATION_SELF_BONDS + 1,
        );
        let cold = mixed_keypair(0x7B, 0x7C);
        let rejected = dual_signed_enroll_op(validator_id, &hot, &cold, 1, &state.chain_id);
        let chain_id = state.chain_id.clone();
        let enrollment_height = state.height;
        assert!(apply_staking_op(&mut state, &rejected, &chain_id, enrollment_height).is_err());

        // State after existing SelfUnstake operations mature and an ordinary
        // owner-authorized transaction consolidates their released UTXOs.
        state.staked_bonds = crate::persistent::PersistentOrdMap::new();
        state.validators.get_mut(&validator_id).unwrap().stake_spark = 0;
        let consolidated = insert_delegator_utxo(
            &mut state,
            pubkey_from_keypair(&hot),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0x7D,
        );
        let restake = signed_op(
            StakingOpBody::SelfStake {
                bond_utxo_id: consolidated,
                validator_pubkey: pubkey_from_keypair(&hot),
                bond_proof: Some(bond_proof(MINIMUM_VALIDATOR_BOND_SPARK, 0x7D)),
                cold_authorization: None,
            },
            1,
            &hot,
            &state.chain_id,
        );
        apply_staking_op(&mut state, &restake, &chain_id, enrollment_height - 1).unwrap();
        let enrollment = dual_signed_enroll_op(validator_id, &hot, &cold, 2, &state.chain_id);
        apply_staking_op(&mut state, &enrollment, &chain_id, enrollment_height).unwrap();
        assert_eq!(state.staked_bonds.len(), 1);
        assert_eq!(
            state.staked_bonds.get(&consolidated).unwrap().custody_owner,
            StakeBondCustodyOwner::ValidatorColdIdentity(validator_id)
        );
    }

    fn enrolled_authority_fixture(
        hot_seed: u8,
        cold_classical_seed: u8,
        cold_pq_seed: u8,
    ) -> (ChainState, Bytes32, HybridKeypair, HybridKeypair) {
        let mut state = ChainState::new_genesis();
        state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
        let (validator_id, hot) = make_active_validator(&mut state, hot_seed);
        let cold = mixed_keypair(cold_classical_seed, cold_pq_seed);
        let enroll = dual_signed_enroll_op(validator_id, &hot, &cold, 1, &state.chain_id);
        let chain_id = state.chain_id.clone();
        apply_staking_op(
            &mut state,
            &enroll,
            &chain_id,
            VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT,
        )
        .unwrap();
        (state, validator_id, hot, cold)
    }

    fn six_cold_operations(
        state: &mut ChainState,
        validator_id: Bytes32,
        hot: &HybridKeypair,
        cold: &HybridKeypair,
        seed: u8,
    ) {
        state
            .validators
            .get_mut(&validator_id)
            .unwrap()
            .pending_rewards = DUST_LIMIT_SPARK;
        let hot_pubkey = pubkey_from_keypair(hot);
        let cold_pubkey = pubkey_from_keypair(cold);
        let self_stake_utxo = insert_delegator_utxo(state, cold_pubkey, DUST_LIMIT_SPARK, seed);
        let operations = vec![
            cold_signed_op(
                StakingOpBody::ClaimRewards {
                    validator_id,
                    delegator_pubkey: hot_pubkey.clone(),
                    cold_authorization: cold_auth(1),
                },
                cold,
                &state.chain_id,
            ),
            cold_signed_op(
                StakingOpBody::SetCommission {
                    validator_id,
                    new_commission_bps: 1_234,
                    cold_authorization: cold_auth(2),
                },
                cold,
                &state.chain_id,
            ),
            cold_signed_op(
                StakingOpBody::SetAutoDelegate {
                    validator_id,
                    target_validator_id: Bytes32::ZERO,
                    cold_authorization: cold_auth(3),
                },
                cold,
                &state.chain_id,
            ),
            cold_signed_op(
                StakingOpBody::RegisterPaymentKey {
                    owner_pubkey: hot_pubkey.clone(),
                    payment_pubkey: payment_pubkey(seed),
                    cold_authorization: cold_auth(4),
                },
                cold,
                &state.chain_id,
            ),
            cold_signed_op(
                StakingOpBody::SelfStake {
                    bond_utxo_id: self_stake_utxo,
                    validator_pubkey: hot_pubkey.clone(),
                    bond_proof: Some(bond_proof(DUST_LIMIT_SPARK, seed)),
                    cold_authorization: cold_auth(5),
                },
                cold,
                &state.chain_id,
            ),
            cold_signed_op(
                StakingOpBody::SelfUnstake {
                    bond_utxo_id: self_stake_utxo,
                    validator_pubkey: hot_pubkey,
                    cold_authorization: cold_auth(6),
                },
                cold,
                &state.chain_id,
            ),
        ];
        let chain_id = state.chain_id.clone();
        for operation in operations {
            apply_staking_op(
                state,
                &operation,
                &chain_id,
                VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT,
            )
            .unwrap();
        }
        assert_eq!(state.validators.get(&validator_id).unwrap().cold_nonce, 6);
        assert_eq!(state.staking_nonces.get(&validator_id), Some(&1));
    }

    #[test]
    fn enrolled_validator_all_six_cold_only_operations_succeed() {
        let (mut state, validator_id, hot, cold) = enrolled_authority_fixture(0x91, 0x92, 0x93);
        six_cold_operations(&mut state, validator_id, &hot, &cold, 0x94);
    }

    #[test]
    fn enrolled_validator_all_six_reject_hot_signatures_without_fallback() {
        let (state, validator_id, hot, _) = enrolled_authority_fixture(0x95, 0x96, 0x97);
        let hot_pubkey = pubkey_from_keypair(&hot);
        let bodies = vec![
            StakingOpBody::ClaimRewards {
                validator_id,
                delegator_pubkey: hot_pubkey.clone(),
                cold_authorization: None,
            },
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps: 1_111,
                cold_authorization: None,
            },
            StakingOpBody::SetAutoDelegate {
                validator_id,
                target_validator_id: Bytes32::ZERO,
                cold_authorization: None,
            },
            StakingOpBody::RegisterPaymentKey {
                owner_pubkey: hot_pubkey.clone(),
                payment_pubkey: payment_pubkey(0x98),
                cold_authorization: None,
            },
            StakingOpBody::SelfStake {
                bond_utxo_id: Bytes32::from([0x99; 32]),
                validator_pubkey: hot_pubkey.clone(),
                bond_proof: Some(bond_proof(DUST_LIMIT_SPARK, 0x99)),
                cold_authorization: None,
            },
            StakingOpBody::SelfUnstake {
                bond_utxo_id: Bytes32::from([0x9A; 32]),
                validator_pubkey: hot_pubkey,
                cold_authorization: None,
            },
        ];
        for body in bodies {
            let mut candidate = state.clone();
            let hot_only = signed_op(body.clone(), 2, &hot, &candidate.chain_id);
            let chain_id = candidate.chain_id.clone();
            assert!(matches!(
                apply_staking_op(
                    &mut candidate,
                    &hot_only,
                    &chain_id,
                    VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT,
                ),
                Err(StateError::InvalidStakingOp(reason))
                    if reason.contains("hot fallback is prohibited")
            ));
            assert_eq!(
                candidate.validators.get(&validator_id).unwrap().cold_nonce,
                0
            );
            assert_eq!(candidate.staking_nonces.get(&validator_id), Some(&1));

            let mut cold_form_body = body;
            set_cold_auth(&mut cold_form_body, 1);
            let hot_in_cold_slot = cold_signed_op(cold_form_body, &hot, &candidate.chain_id);
            assert!(matches!(
                apply_staking_op(
                    &mut candidate,
                    &hot_in_cold_slot,
                    &chain_id,
                    VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT,
                ),
                Err(StateError::StakingOpSignatureInvalid { .. })
            ));
            assert_eq!(
                candidate.validators.get(&validator_id).unwrap().cold_nonce,
                0
            );
        }
    }

    #[test]
    fn unenrolled_validator_all_six_legacy_hot_operations_still_succeed() {
        let mut state = ChainState::new_genesis();
        let (validator_id, hot) = make_active_validator(&mut state, 0x9B);
        let hot_pubkey = pubkey_from_keypair(&hot);
        state
            .validators
            .get_mut(&validator_id)
            .unwrap()
            .pending_rewards = DUST_LIMIT_SPARK;
        let self_stake_utxo =
            insert_delegator_utxo(&mut state, hot_pubkey.clone(), DUST_LIMIT_SPARK, 0x9C);
        let bodies = vec![
            StakingOpBody::ClaimRewards {
                validator_id,
                delegator_pubkey: hot_pubkey.clone(),
                cold_authorization: None,
            },
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps: 1_222,
                cold_authorization: None,
            },
            StakingOpBody::SetAutoDelegate {
                validator_id,
                target_validator_id: Bytes32::ZERO,
                cold_authorization: None,
            },
            StakingOpBody::RegisterPaymentKey {
                owner_pubkey: hot_pubkey.clone(),
                payment_pubkey: payment_pubkey(0x9D),
                cold_authorization: None,
            },
            StakingOpBody::SelfStake {
                bond_utxo_id: self_stake_utxo,
                validator_pubkey: hot_pubkey.clone(),
                bond_proof: Some(bond_proof(DUST_LIMIT_SPARK, 0x9C)),
                cold_authorization: None,
            },
            StakingOpBody::SelfUnstake {
                bond_utxo_id: self_stake_utxo,
                validator_pubkey: hot_pubkey,
                cold_authorization: None,
            },
        ];
        let chain_id = state.chain_id.clone();
        for (index, body) in bodies.into_iter().enumerate() {
            let operation = signed_op(body, index as u64 + 1, &hot, &chain_id);
            apply_staking_op(
                &mut state,
                &operation,
                &chain_id,
                VALIDATOR_COLD_KEY_ENFORCEMENT_HEIGHT - 1,
            )
            .unwrap();
        }
        assert_eq!(state.staking_nonces.get(&validator_id), Some(&6));
        assert_eq!(state.validators.get(&validator_id).unwrap().cold_nonce, 0);
    }

    #[test]
    fn delegator_claim_and_payment_registration_ignore_validator_cold_status() {
        let (mut state, validator_id, _, _) = enrolled_authority_fixture(0xA1, 0xA2, 0xA3);
        let delegator = keypair(0xA4);
        let delegator_pubkey = pubkey_from_keypair(&delegator);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        state
            .delegator_identities
            .insert(delegator_id, delegator_pubkey.clone());
        state
            .delegations
            .add_delegation(validator_id, delegator_id, 1_000_000, 0)
            .unwrap();
        state
            .delegations
            .update_delegator(&validator_id, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();
        let claim = signed_op(
            StakingOpBody::ClaimRewards {
                validator_id,
                delegator_pubkey: delegator_pubkey.clone(),
                cold_authorization: None,
            },
            1,
            &delegator,
            &state.chain_id,
        );
        let payment = signed_op(
            StakingOpBody::RegisterPaymentKey {
                owner_pubkey: delegator_pubkey,
                payment_pubkey: payment_pubkey(0xA5),
                cold_authorization: None,
            },
            2,
            &delegator,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        apply_staking_op(
            &mut state,
            &claim,
            &chain_id,
            VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT,
        )
        .unwrap();
        apply_staking_op(
            &mut state,
            &payment,
            &chain_id,
            VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT,
        )
        .unwrap();
        assert_eq!(state.staking_nonces.get(&delegator_id), Some(&2));
        assert_eq!(state.validators.get(&validator_id).unwrap().cold_nonce, 0);
    }

    #[test]
    fn mixed_hot_cold_and_delegator_authority_replay_is_deterministic() {
        fn replay() -> ChainState {
            let (mut state, enrolled_id, enrolled_hot, enrolled_cold) =
                enrolled_authority_fixture(0xA6, 0xA7, 0xA8);
            six_cold_operations(&mut state, enrolled_id, &enrolled_hot, &enrolled_cold, 0xA9);

            let (legacy_id, legacy_hot) = make_active_validator(&mut state, 0xAA);
            let legacy_commission = signed_op(
                StakingOpBody::SetCommission {
                    validator_id: legacy_id,
                    new_commission_bps: 1_333,
                    cold_authorization: None,
                },
                1,
                &legacy_hot,
                &state.chain_id,
            );
            let delegator = keypair(0xAB);
            let delegator_pubkey = pubkey_from_keypair(&delegator);
            let delegator_id = pubkey_to_id(&delegator_pubkey);
            state
                .delegator_identities
                .insert(delegator_id, delegator_pubkey.clone());
            state
                .delegations
                .add_delegation(enrolled_id, delegator_id, 1_000_000, 0)
                .unwrap();
            state
                .delegations
                .update_delegator(&enrolled_id, &delegator_id, |entry| {
                    entry.pending_rewards = DUST_LIMIT_SPARK;
                })
                .unwrap();
            let claim = signed_op(
                StakingOpBody::ClaimRewards {
                    validator_id: enrolled_id,
                    delegator_pubkey,
                    cold_authorization: None,
                },
                1,
                &delegator,
                &state.chain_id,
            );
            let chain_id = state.chain_id.clone();
            let error = apply_staking_op(
                &mut state,
                &legacy_commission,
                &chain_id,
                VALIDATOR_COLD_KEY_ENFORCEMENT_HEIGHT,
            )
            .unwrap_err();
            assert!(matches!(
                error,
                StateError::InvalidStakingOp(reason) if reason.contains("custody is frozen")
            ));
            apply_staking_op(
                &mut state,
                &claim,
                &chain_id,
                VALIDATOR_COLD_KEY_ENFORCEMENT_HEIGHT,
            )
            .unwrap();
            state
        }
        let first = replay();
        let second = replay();
        assert_eq!(first, second);
        assert_eq!(
            crate::compute_state_root(&first),
            crate::compute_state_root(&second)
        );
    }

    #[test]
    fn rotate_validator_cold_key_is_atomic_and_permanently_retires_components() {
        let mut state = ChainState::new_genesis();
        state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
        let height = state.height;
        let (validator_id, hot) = make_active_validator(&mut state, 0xD0);
        let cold_v1 = mixed_keypair(0xD1, 0xD2);
        let chain_id = state.chain_id.clone();
        let enroll = dual_signed_enroll_op(validator_id, &hot, &cold_v1, 1, &chain_id);
        apply_staking_op(&mut state, &enroll, &chain_id, height).unwrap();
        let cold_v2 = mixed_keypair(0xD3, 0xD4);
        let rotate = dual_signed_rotate_op(validator_id, &cold_v1, &cold_v2, 1, 1, &chain_id);
        apply_staking_op(&mut state, &rotate, &chain_id, height).unwrap();
        let entry = state.validators.get(&validator_id).unwrap();
        assert_eq!(entry.cold_key_version, 2);
        assert_eq!(entry.cold_nonce, 0);
        assert_eq!(
            entry.cold_hybrid_classical_pk,
            Some(cold_v2.public_key().classical.0)
        );
        assert!(state
            .retired_cold_classical_components
            .contains(&cold_v1.public_key().classical.0));
        assert!(state
            .retired_cold_pq_components
            .contains(&cold_v1.public_key().pq.0));

        let reuse = dual_signed_rotate_op(validator_id, &cold_v2, &cold_v1, 2, 1, &chain_id);
        let err = apply_staking_op(&mut state, &reuse, &chain_id, height).unwrap_err();
        assert!(err.to_string().contains("permanently retired"));

        let new_key_op = cold_signed_op(
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps: 1_200,
                cold_authorization: Some(indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 2,
                    cold_nonce: 1,
                }),
            },
            &cold_v2,
            &chain_id,
        );
        apply_staking_op(&mut state, &new_key_op, &chain_id, height).unwrap();
        assert_eq!(state.validators.get(&validator_id).unwrap().cold_nonce, 1);

        let old_key_op = cold_signed_op(
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps: 1_300,
                cold_authorization: Some(indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 2,
                    cold_nonce: 2,
                }),
            },
            &cold_v1,
            &chain_id,
        );
        assert!(apply_staking_op(&mut state, &old_key_op, &chain_id, height).is_err());
    }

    #[test]
    fn competing_rotations_are_first_commit_wins() {
        let mut state = ChainState::new_genesis();
        state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
        let height = state.height;
        let (validator_id, hot) = make_active_validator(&mut state, 0xE0);
        let current = mixed_keypair(0xE1, 0xE2);
        let chain_id = state.chain_id.clone();
        let enroll = dual_signed_enroll_op(validator_id, &hot, &current, 1, &chain_id);
        apply_staking_op(&mut state, &enroll, &chain_id, height).unwrap();
        let a = mixed_keypair(0xE3, 0xE4);
        let b = mixed_keypair(0xE5, 0xE6);
        let first = dual_signed_rotate_op(validator_id, &current, &a, 1, 1, &chain_id);
        let second = dual_signed_rotate_op(validator_id, &current, &b, 1, 1, &chain_id);
        apply_staking_op(&mut state, &first, &chain_id, height).unwrap();
        assert!(apply_staking_op(&mut state, &second, &chain_id, height).is_err());
        assert_eq!(
            state
                .validators
                .get(&validator_id)
                .unwrap()
                .cold_hybrid_classical_pk,
            Some(a.public_key().classical.0)
        );
    }

    #[test]
    fn different_validator_enrollment_and_rotation_reject_retired_components() {
        let (mut state, retired, _) = state_with_retired_cold_pair(0x80);
        let chain_id = state.chain_id.clone();
        let height = state.height;

        let (other_id, other_hot) = make_active_validator(&mut state, 0x90);
        let reused_classical = mixed_keypair(0x81, 0x91);
        let enroll = dual_signed_enroll_op(other_id, &other_hot, &reused_classical, 1, &chain_id);
        let err = apply_staking_op(&mut state, &enroll, &chain_id, height).unwrap_err();
        assert!(err.to_string().contains("permanently retired"));

        let fresh = mixed_keypair(0x92, 0x93);
        let enroll = dual_signed_enroll_op(other_id, &other_hot, &fresh, 1, &chain_id);
        apply_staking_op(&mut state, &enroll, &chain_id, height).unwrap();
        let reused_pq = mixed_keypair(0x94, 0x82);
        let rotate = dual_signed_rotate_op(other_id, &fresh, &reused_pq, 1, 1, &chain_id);
        let err = apply_staking_op(&mut state, &rotate, &chain_id, height).unwrap_err();
        assert!(err.to_string().contains("permanently retired"));
        drop(retired);
    }

    #[test]
    fn register_validator_rejects_retired_component_in_hot_or_cold_role() {
        let (mut state, retired, _) = state_with_retired_cold_pair(0xA0);
        let chain_id = state.chain_id.clone();
        let height = state.height;

        let hot_reusing_retired_classical = mixed_keypair(0xA1, 0xB0);
        let fresh_cold = mixed_keypair(0xB1, 0xB2);
        let bond = insert_delegator_utxo(
            &mut state,
            pubkey_from_keypair(&fresh_cold),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xB3,
        );
        let register = dual_signed_register_op(
            bond,
            &hot_reusing_retired_classical,
            &fresh_cold,
            1,
            &chain_id,
            [0xB4; 32],
            0xB3,
        );
        let err = apply_staking_op(&mut state, &register, &chain_id, height).unwrap_err();
        assert!(err.to_string().contains("permanently retired"));

        let fresh_hot = mixed_keypair(0xB5, 0xB6);
        let cold_reusing_retired_pq = mixed_keypair(0xB7, 0xA2);
        let bond = insert_delegator_utxo(
            &mut state,
            pubkey_from_keypair(&cold_reusing_retired_pq),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xB8,
        );
        let register = dual_signed_register_op(
            bond,
            &fresh_hot,
            &cold_reusing_retired_pq,
            1,
            &chain_id,
            [0xB9; 32],
            0xB8,
        );
        let err = apply_staking_op(&mut state, &register, &chain_id, height).unwrap_err();
        assert!(err.to_string().contains("permanently retired"));
        drop(retired);
    }

    #[test]
    fn enforcement_leaves_enrolled_validator_active_and_cold_authorized() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0xC0);
        let cold = mixed_keypair(0xC1, 0xC2);
        activate_cold_for_test(&mut state, validator_id, &cold);
        crate::epoch::enforce_validator_cold_key_enrollment(
            &mut state,
            indra_core::types::primitives::hard_forks::VALIDATOR_COLD_KEY_ENFORCEMENT_HEIGHT,
        );
        assert_eq!(
            state.validators.get(&validator_id).unwrap().status,
            ValidatorStatus::Active
        );
        let op = cold_signed_op(
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps: 1_100,
                cold_authorization: Some(indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 1,
                    cold_nonce: 1,
                }),
            },
            &cold,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        apply_staking_op(
            &mut state,
            &op,
            &chain_id,
            indra_core::types::primitives::hard_forks::VALIDATOR_COLD_KEY_ENFORCEMENT_HEIGHT,
        )
        .unwrap();
    }

    #[test]
    fn enforcement_demotes_and_freezes_unenrolled_then_late_enrollment_requalifies() {
        let mut state = ChainState::new_genesis();
        let (validator_id, hot) = make_active_validator(&mut state, 0xC3);
        state
            .validators
            .get_mut(&validator_id)
            .unwrap()
            .pending_rewards = 50_000;
        let enforcement =
            indra_core::types::primitives::hard_forks::VALIDATOR_COLD_KEY_ENFORCEMENT_HEIGHT;
        crate::epoch::enforce_validator_cold_key_enrollment(&mut state, enforcement);
        assert_eq!(
            state.validators.get(&validator_id).unwrap().status,
            ValidatorStatus::Registered
        );

        let legacy = signed_op(
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps: 1_200,
                cold_authorization: None,
            },
            1,
            &hot,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        let err = apply_staking_op(&mut state, &legacy, &chain_id, enforcement).unwrap_err();
        assert!(err.to_string().contains("custody is frozen"));
        assert_eq!(
            state.validators.get(&validator_id).unwrap().pending_rewards,
            50_000
        );

        let cold_v1 = mixed_keypair(0xC4, 0xC5);
        let enroll = dual_signed_enroll_op(validator_id, &hot, &cold_v1, 1, &chain_id);
        apply_staking_op(&mut state, &enroll, &chain_id, enforcement).unwrap();
        assert_eq!(
            state.validators.get(&validator_id).unwrap().status,
            ValidatorStatus::Registered
        );
        state
            .validators
            .select_active_set(&state.delegations, 0, enforcement);
        assert_eq!(
            state.validators.get(&validator_id).unwrap().status,
            ValidatorStatus::Active
        );

        let cold_op = cold_signed_op(
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps: 1_300,
                cold_authorization: Some(indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 1,
                    cold_nonce: 1,
                }),
            },
            &cold_v1,
            &chain_id,
        );
        apply_staking_op(&mut state, &cold_op, &chain_id, enforcement).unwrap();
        let cold_v2 = mixed_keypair(0xC6, 0xC7);
        let rotate = dual_signed_rotate_op(validator_id, &cold_v1, &cold_v2, 1, 2, &chain_id);
        apply_staking_op(&mut state, &rotate, &chain_id, enforcement).unwrap();
        assert_eq!(
            state
                .validators
                .get(&validator_id)
                .unwrap()
                .cold_key_version,
            2
        );
    }

    #[test]
    fn enforcement_mixed_enrollment_replay_is_deterministic() {
        fn replay() -> ChainState {
            let mut state = ChainState::new_genesis();
            let (enrolled_id, _) = make_active_validator(&mut state, 0xD8);
            let enrolled_cold = mixed_keypair(0xD9, 0xDA);
            activate_cold_for_test(&mut state, enrolled_id, &enrolled_cold);
            let (late_id, late_hot) = make_active_validator(&mut state, 0xDB);
            let enforcement =
                indra_core::types::primitives::hard_forks::VALIDATOR_COLD_KEY_ENFORCEMENT_HEIGHT;
            crate::epoch::enforce_validator_cold_key_enrollment(&mut state, enforcement);
            assert_eq!(
                state.validators.get(&late_id).unwrap().status,
                ValidatorStatus::Registered
            );
            let chain_id = state.chain_id.clone();
            let enrolled_op = cold_signed_op(
                StakingOpBody::SetCommission {
                    validator_id: enrolled_id,
                    new_commission_bps: 1_050,
                    cold_authorization: Some(
                        indra_core::types::staking::ColdStakingAuthorization {
                            cold_key_version: 1,
                            cold_nonce: 1,
                        },
                    ),
                },
                &enrolled_cold,
                &chain_id,
            );
            apply_staking_op(&mut state, &enrolled_op, &chain_id, enforcement).unwrap();
            let late_cold = mixed_keypair(0xDC, 0xDD);
            let enrollment = dual_signed_enroll_op(late_id, &late_hot, &late_cold, 1, &chain_id);
            apply_staking_op(&mut state, &enrollment, &chain_id, enforcement).unwrap();
            state
                .validators
                .select_active_set(&state.delegations, 0, enforcement);
            state
        }
        let first = replay();
        let second = replay();
        assert_eq!(first, second);
        assert_eq!(
            crate::compute_state_root(&first),
            crate::compute_state_root(&second)
        );
    }

    #[test]
    fn hot_cold_capstone_adversarial_sequence_is_atomic_and_noncontaminating() {
        let mut state = ChainState::new_genesis();
        let (validator_id, hot) = make_active_validator(&mut state, 0xE0);
        let cold_v1 = mixed_keypair(0xE1, 0xE2);
        let chain_id = state.chain_id.clone();
        let enroll = dual_signed_enroll_op(validator_id, &hot, &cold_v1, 1, &chain_id);
        apply_staking_op(&mut state, &enroll, &chain_id, u64::MAX).unwrap();

        let mut legitimate = cold_signed_op(
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps: 1_010,
                cold_authorization: cold_auth(1),
            },
            &cold_v1,
            &chain_id,
        );
        apply_staking_op(&mut state, &legitimate, &chain_id, u64::MAX).unwrap();

        let assert_rejected_without_mutation = |state: &mut ChainState, operation: &StakingOp| {
            let before = state.clone();
            assert!(apply_staking_op(state, operation, &chain_id, u64::MAX).is_err());
            assert_eq!(*state, before);
        };

        let hot_fallback = signed_op(
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps: 1_020,
                cold_authorization: None,
            },
            2,
            &hot,
            &chain_id,
        );
        assert_rejected_without_mutation(&mut state, &hot_fallback);

        let wrong_version = cold_signed_op(
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps: 1_030,
                cold_authorization: Some(indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 2,
                    cold_nonce: 2,
                }),
            },
            &cold_v1,
            &chain_id,
        );
        assert_rejected_without_mutation(&mut state, &wrong_version);

        let wrong_nonce = cold_signed_op(
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps: 1_040,
                cold_authorization: cold_auth(3),
            },
            &cold_v1,
            &chain_id,
        );
        assert_rejected_without_mutation(&mut state, &wrong_nonce);

        let attacker = mixed_keypair(0xE3, 0xE4);
        legitimate.body = StakingOpBody::SetCommission {
            validator_id,
            new_commission_bps: 1_050,
            cold_authorization: cold_auth(2),
        };
        let message = legitimate
            .cold_authorization_signing_bytes(&chain_id)
            .unwrap()
            .unwrap();
        let valid_signature = cold_v1.sign(&message).unwrap();
        let attacker_signature = attacker.sign(&message).unwrap();
        legitimate.signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&valid_signature.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&attacker_signature.pq.0).unwrap(),
        };
        assert_rejected_without_mutation(&mut state, &legitimate);

        let cold_v2 = mixed_keypair(0xE5, 0xE6);
        let rotate = dual_signed_rotate_op(validator_id, &cold_v1, &cold_v2, 1, 2, &chain_id);
        apply_staking_op(&mut state, &rotate, &chain_id, u64::MAX).unwrap();

        let old_key_fallback = cold_signed_op(
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps: 1_060,
                cold_authorization: Some(indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 1,
                    cold_nonce: 3,
                }),
            },
            &cold_v1,
            &chain_id,
        );
        assert_rejected_without_mutation(&mut state, &old_key_fallback);

        let reuse_retired =
            dual_signed_rotate_op(validator_id, &cold_v2, &cold_v1, 2, 1, &chain_id);
        assert_rejected_without_mutation(&mut state, &reuse_retired);

        let (frozen_id, frozen_hot) = make_active_validator(&mut state, 0xE7);
        crate::epoch::enforce_validator_cold_key_enrollment(&mut state, u64::MAX);
        let frozen_attempt = signed_op(
            StakingOpBody::SetCommission {
                validator_id: frozen_id,
                new_commission_bps: 1_070,
                cold_authorization: None,
            },
            1,
            &frozen_hot,
            &chain_id,
        );
        assert_rejected_without_mutation(&mut state, &frozen_attempt);

        let legitimate_v2 = cold_signed_op(
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps: 1_080,
                cold_authorization: Some(indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 2,
                    cold_nonce: 1,
                }),
            },
            &cold_v2,
            &chain_id,
        );
        apply_staking_op(&mut state, &legitimate_v2, &chain_id, u64::MAX).unwrap();

        let mut pre_gate = ChainState::new_genesis();
        let (pre_id, pre_hot) = make_active_validator(&mut pre_gate, 0xE8);
        let pre_cold = mixed_keypair(0xE9, 0xEA);
        let pre_chain_id = pre_gate.chain_id.clone();
        let pre_enroll = dual_signed_enroll_op(pre_id, &pre_hot, &pre_cold, 1, &pre_chain_id);
        let before = pre_gate.clone();
        assert!(apply_staking_op(
            &mut pre_gate,
            &pre_enroll,
            &pre_chain_id,
            VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT - 1,
        )
        .is_err());
        assert_eq!(pre_gate, before);
    }

    #[test]
    fn consensus_snapshot_capstone_mixed_gate_state_transcript_replays_byte_identically() {
        fn replay() -> Vec<(u64, Vec<u8>, Bytes32)> {
            use indra_core::types::primitives::hard_forks::{
                COMPACT_BOND_PUBKEY_OMISSION_HEIGHT, CONSENSUS_SNAPSHOT_HEIGHT,
                DELEGATOR_IDENTITY_REGISTRY_HEIGHT, NORMAL_BOND_RELEASE_BLINDING_HEIGHT,
            };

            let mut transcript = Vec::new();
            let mut state = ChainState::new_genesis();
            let (validator_id, hot) = make_active_validator(&mut state, 0xB0);
            let delegator = keypair(0xB1);
            let delegator_pubkey = pubkey_from_keypair(&delegator);
            let delegator_id = pubkey_to_id(&delegator_pubkey);

            state.height = DELEGATOR_IDENTITY_REGISTRY_HEIGHT;
            state
                .delegator_identities
                .insert(delegator_id, delegator_pubkey.clone());
            state
                .delegations
                .add_delegation(validator_id, delegator_id, DUST_LIMIT_SPARK, 0)
                .unwrap();
            transcript.push((
                state.height,
                state.encode_to_vec(),
                crate::compute_state_root(&state),
            ));

            state.height = COMPACT_BOND_PUBKEY_OMISSION_HEIGHT;
            let compact_bond_id = Bytes32::from([0xB2; 32]);
            state.staked_bonds.insert(
                compact_bond_id,
                StakeBondEntry {
                    utxo_id: compact_bond_id,
                    validator_id,
                    delegator_id,
                    amount_spark: DUST_LIMIT_SPARK,
                    bonded_epoch: 0,
                    unbonding_end_epoch: Some(1),
                    custody_owner: StakeBondCustodyOwner::DelegatorIdentity(delegator_id),
                    original_output: test_output(DUST_LIMIT_SPARK, delegator_pubkey, 0xB2).into(),
                },
            );
            transcript.push((
                state.height,
                state.encode_to_vec(),
                crate::compute_state_root(&state),
            ));

            state.height = PAYMENT_BLINDING_HEIGHT;
            state
                .payment_identities
                .insert(delegator_id, payment_pubkey(0xB3));
            transcript.push((
                state.height,
                state.encode_to_vec(),
                crate::compute_state_root(&state),
            ));

            state.height = NORMAL_BOND_RELEASE_BLINDING_HEIGHT;
            crate::epoch::release_unbonded_bonds_at_height(
                &mut state,
                1,
                NORMAL_BOND_RELEASE_BLINDING_HEIGHT,
            )
            .unwrap();
            assert!(!state.staked_bonds.contains_key(&compact_bond_id));
            assert!(state
                .delegation_return_events
                .iter()
                .any(|event| event.bond_utxo_id == compact_bond_id));
            transcript.push((
                state.height,
                state.encode_to_vec(),
                crate::compute_state_root(&state),
            ));

            state.height = VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT;
            let cold = mixed_keypair(0xB5, 0xB6);
            let chain_id = state.chain_id.clone();
            let enroll = dual_signed_enroll_op(validator_id, &hot, &cold, 1, &chain_id);
            apply_staking_op(
                &mut state,
                &enroll,
                &chain_id,
                VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT,
            )
            .unwrap();
            transcript.push((
                state.height,
                state.encode_to_vec(),
                crate::compute_state_root(&state),
            ));

            let (unenrolled_id, _) = make_active_validator(&mut state, 0xB7);
            state.height = VALIDATOR_COLD_KEY_ENFORCEMENT_HEIGHT;
            crate::epoch::enforce_validator_cold_key_enrollment(
                &mut state,
                VALIDATOR_COLD_KEY_ENFORCEMENT_HEIGHT,
            );
            assert_eq!(
                state.validators.get(&unenrolled_id).unwrap().status,
                ValidatorStatus::Registered
            );
            assert_eq!(
                state.validators.get(&validator_id).unwrap().status,
                ValidatorStatus::Active
            );
            transcript.push((
                state.height,
                state.encode_to_vec(),
                crate::compute_state_root(&state),
            ));

            // The snapshot gate remains production-inert. For this transcript,
            // u64::MAX is the explicit test activation height. Cold enforcement
            // settles policy first at the same unscheduled height; snapshot
            // construction then freezes the fully-settled Active authority.
            assert_eq!(CONSENSUS_SNAPSHOT_HEIGHT, u64::MAX);
            state.validators.get_mut(&validator_id).unwrap().vrf_pk =
                Some(indra_crypto::VrfKeypair::from_seed(&[0xB8; 32]).public_key());
            let snapshot = state
                .build_consensus_snapshot(CONSENSUS_SNAPSHOT_HEIGHT, CONSENSUS_SNAPSHOT_HEIGHT - 1)
                .unwrap();
            state.consensus_snapshots = vec![snapshot];
            state.rebuild_state_commitment_v2(CONSENSUS_SNAPSHOT_HEIGHT);
            transcript.push((
                state.height,
                state.encode_to_vec(),
                crate::compute_state_root(&state),
            ));
            transcript
        }

        let first = replay();
        let second = replay();
        assert_eq!(first, second);
        assert_eq!(first.len(), 7);
        assert_eq!(
            first.iter().map(|entry| entry.0).collect::<Vec<_>>(),
            vec![
                indra_core::types::primitives::hard_forks::DELEGATOR_IDENTITY_REGISTRY_HEIGHT,
                indra_core::types::primitives::hard_forks::COMPACT_BOND_PUBKEY_OMISSION_HEIGHT,
                PAYMENT_BLINDING_HEIGHT,
                indra_core::types::primitives::hard_forks::NORMAL_BOND_RELEASE_BLINDING_HEIGHT,
                VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT,
                VALIDATOR_COLD_KEY_ENFORCEMENT_HEIGHT,
                indra_core::types::primitives::hard_forks::CONSENSUS_SNAPSHOT_HEIGHT,
            ]
        );
    }
}
