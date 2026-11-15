//! Delegation state transitions.
//!
//! Handles apply_delegate, apply_undelegate, apply_claim_rewards,
//! and apply_set_commission. Called from apply_block when a block
//! contains StakingOp entries.

use indra_core::types::{
    crypto::{ColdHybridPubKey, HybridPubKey, HybridSignature},
    primitives::{
        Bytes32, Bytes64, VariableBytes, COMMISSION_CHANGE_DELAY_EPOCHS, DUST_LIMIT_SPARK,
        MAX_STAKE_POSITIONS_PER_VALIDATOR, MAX_STANDARD_VRF_PROOF_BYTES, MAX_VALIDATORS,
        MINIMUM_VALIDATOR_SELF_STAKE_SPARK, MIN_COMMISSION_BPS, STAKING_REWARD_TX_IDX,
    },
    staking::{validate_network_addr_string, StakingOp, StakingOpBody},
    transaction::OutputV1,
};

use crate::{
    chain::ChainState,
    epoch::epoch_for_height,
    error::{StateError, StateResult},
    identity::{
        resolve_active_validator_cold_pubkey, resolve_and_check_identity, IdentityCheckOutcome,
        IdentityError,
    },
    validator::{
        validate_new_validator_cold_key, validate_validator_cold_key, EvictedColdCustodyV1,
        ValidatorEntry, ValidatorStatus,
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
    apply_staking_op_at_index(state, op, chain_id, current_height, 0)
}

pub(crate) fn apply_staking_op_at_index(
    state: &mut ChainState,
    op: &StakingOp,
    chain_id: &str,
    current_height: u64,
    synthetic_output_index: u32,
) -> StateResult<()> {
    op.validate_structure()
        .map_err(|err| StateError::InvalidStakingOp(err.to_string()))?;
    apply_staking_op_mode(
        state,
        op,
        chain_id,
        current_height,
        synthetic_output_index,
        true,
    )
}

/// Apply an admission-verified staking operation without repeating intrinsic crypto.
///
/// The certificate is checked against both the operation and current canonical
/// authority before the intrinsic cryptographic checks may be reused.
pub fn apply_verified_staking_op(
    state: &mut ChainState,
    op: &StakingOp,
    verified: &crate::pending::VerifiedPendingStaking,
    chain_id: &str,
    current_height: u64,
) -> StateResult<()> {
    if !crate::pending::staking_authority_unchanged(state, op, verified) {
        return Err(StateError::InvariantViolation {
            message: "pending staking certificate does not match operation or canonical authority",
        });
    }
    op.validate_structure()
        .map_err(|err| StateError::InvalidStakingOp(err.to_string()))?;
    apply_staking_op_mode(state, op, chain_id, current_height, 0, false)
}

fn apply_staking_op_mode(
    state: &mut ChainState,
    op: &StakingOp,
    chain_id: &str,
    current_height: u64,
    synthetic_output_index: u32,
    verify_crypto: bool,
) -> StateResult<()> {
    if matches!(op.body, StakingOpBody::RotateValidatorColdKey { .. }) {
        return verify_and_apply_rotate_validator_cold_key(
            state,
            op,
            chain_id,
            current_height,
            verify_crypto,
        );
    }

    let signer_id = op.signer_id();
    let cold_designated = matches!(
        op.body,
        StakingOpBody::ClaimRewards { .. }
            | StakingOpBody::SetCommission { .. }
            | StakingOpBody::SelfStake { .. }
            | StakingOpBody::ExitStakePosition {
                custody:
                    indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity { .. },
                ..
            }
            | StakingOpBody::SetAutoDelegate { .. }
    );
    let active_cold_validator = cold_designated && state.validators.get(&signer_id).is_some();
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
        if verify_crypto {
            verify_staking_sig(&cold_signing_bytes, &op.signature, &cold_classical, cold_pq)?;
        }
    } else {
        if op.cold_authorization().is_some() {
            return Err(StateError::InvalidStakingOp(
                "cold authorization is valid only for an Active validator".into(),
            ));
        }
        let expected_nonce = state
            .staking_nonces
            .get(&signer_id)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| StateError::InvalidStakingOp("staking nonce exhausted".into()))?;
        if op.nonce != expected_nonce {
            return Err(StateError::StakingNonceInvalid {
                expected: expected_nonce,
                got: op.nonce,
            });
        }
    }

    let signing_bytes = op.signing_bytes(chain_id);
    if verify_crypto {
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
            StakingOpBody::RegisterVrfKey {
                validator_id,
                vrf_pubkey,
                activation_epoch_id,
                vrf_possession_output,
                vrf_possession_proof,
                ..
            } => {
                let validator = state
                    .validators
                    .get(validator_id)
                    .ok_or(StateError::ValidatorNotFound)?;
                let classical = validator.hybrid_classical_pk.ok_or_else(|| {
                    StateError::StakingOpSignatureInvalid {
                        reason: "validator has no classical key registered".into(),
                    }
                })?;
                let pq = validator.hybrid_pq_pk.as_deref().ok_or_else(|| {
                    StateError::StakingOpSignatureInvalid {
                        reason: "validator has no PQ key registered".into(),
                    }
                })?;
                verify_staking_sig(&signing_bytes, &op.signature, &classical, pq)?;
                let challenge = StakingOp::vrf_possession_challenge(
                    chain_id,
                    validator_id,
                    vrf_pubkey,
                    *activation_epoch_id,
                )
                .map_err(|e| StateError::InvalidStakingOp(e.to_string()))?;
                indra_crypto::vrf_verify(
                    &vrf_pubkey.0,
                    &challenge,
                    &indra_crypto::VrfOutput(vrf_possession_output.0),
                    &indra_crypto::VrfProof(vrf_possession_proof.as_slice().to_vec()),
                )
                .map_err(|_| {
                    StateError::InvalidStakingOp(
                        "VRF secret-key possession proof is invalid".into(),
                    )
                })?;
            }
            StakingOpBody::Delegate {
                delegator_pubkey, ..
            } => {
                verify_staking_sig(
                    &signing_bytes,
                    &op.signature,
                    &delegator_pubkey.classical_pk.0,
                    delegator_pubkey.pq_pk.as_slice(),
                )?;
            }
            StakingOpBody::ExitStakePosition { .. } if !active_cold_validator => {
                let owner = state.delegator_identities.get(&signer_id).ok_or_else(|| {
                    StateError::InvalidStakingOp("missing delegator identity".into())
                })?;
                verify_staking_sig(
                    &signing_bytes,
                    &op.signature,
                    &owner.classical_pk.0,
                    owner.pq_pk.as_slice(),
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
            }
            StakingOpBody::SelfStake {
                validator_pubkey, ..
            } if !active_cold_validator => {
                verify_staking_sig(
                    &signing_bytes,
                    &op.signature,
                    &validator_pubkey.classical_pk.0,
                    validator_pubkey.pq_pk.as_slice(),
                )?;
            }
            StakingOpBody::ClaimRewards { .. }
            | StakingOpBody::SetCommission { .. }
            | StakingOpBody::SelfStake { .. }
            | StakingOpBody::ExitStakePosition { .. }
            | StakingOpBody::SetAutoDelegate { .. } => {}
            StakingOpBody::RotateValidatorColdKey { .. } => unreachable!("rotation returned above"),
        }
    }

    let result = match &op.body {
        StakingOpBody::Delegate {
            validator_id,
            deposit_utxo_id,
            delegator_pubkey,
        } => apply_delegate(
            state,
            validator_id,
            *deposit_utxo_id,
            delegator_pubkey,
            current_height,
            Some(MAX_STAKE_POSITIONS_PER_VALIDATOR),
        ),
        StakingOpBody::ExitStakePosition { .. } => {
            crate::stake_positions::exit_stake_position(state, op, current_height).map(|_| ())
        }
        StakingOpBody::ClaimRewards {
            validator_id,
            delegator_pubkey,
            ..
        } => apply_claim_rewards(
            state,
            validator_id,
            delegator_pubkey,
            current_height,
            synthetic_output_index,
        ),
        StakingOpBody::RegisterValidator {
            commission_bps,
            deposit_utxo_id,
            validator_pubkey,
            vrf_pk,
            vrf_possession_output,
            vrf_possession_proof,
            cold_pubkey,
            ..
        } => apply_register_validator(
            state,
            *commission_bps,
            *deposit_utxo_id,
            validator_pubkey,
            *vrf_pk,
            vrf_possession_output,
            vrf_possession_proof,
            cold_pubkey,
            chain_id,
            current_height,
        ),
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
        StakingOpBody::RegisterVrfKey {
            validator_id,
            vrf_pubkey,
            activation_epoch_id,
            ..
        } => {
            let expected = epoch_for_height(current_height)
                .checked_add(1)
                .ok_or_else(|| {
                    StateError::InvalidStakingOp("VRF activation epoch overflow".into())
                })?;
            if *activation_epoch_id != expected {
                return Err(StateError::InvalidStakingOp(format!(
                    "VRF key must activate in next snapshot epoch {expected}"
                )));
            }
            indra_crypto::validate_vrf_public_key(&vrf_pubkey.0)
                .map_err(|e| StateError::InvalidStakingOp(e.to_string()))?;
            if state
                .validators
                .all_validators()
                .any(|v| v.vrf_pk == Some(vrf_pubkey.0) || v.pending_vrf_pk == Some(vrf_pubkey.0))
            {
                return Err(StateError::InvalidStakingOp(
                    "VRF public key is already registered".into(),
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
            if let (Some(pending), Some(activation)) = (
                validator.pending_vrf_pk,
                validator.pending_vrf_activation_epoch,
            ) {
                if activation <= epoch_for_height(current_height) {
                    validator.vrf_pk = Some(pending);
                    validator.vrf_key_activation_epoch = activation;
                }
            }
            validator.pending_vrf_pk = Some(vrf_pubkey.0);
            validator.pending_vrf_activation_epoch = Some(*activation_epoch_id);
            Ok(())
        }
        StakingOpBody::SelfStake {
            deposit_utxo_id,
            validator_pubkey,
            ..
        } => apply_self_stake(
            state,
            *deposit_utxo_id,
            validator_pubkey,
            current_height,
            Some(MAX_STAKE_POSITIONS_PER_VALIDATOR),
        ),
        StakingOpBody::RotateValidatorColdKey { .. } => unreachable!("rotation returned above"),
    };

    result?;
    if active_cold_validator {
        let Some(authorization) = op.cold_authorization() else {
            return Err(StateError::InvalidStakingOp(
                "active cold authorization was verified".into(),
            ));
        };
        let cold_nonce = authorization.cold_nonce;
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
    verify_crypto: bool,
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
    if verify_crypto {
        let new_signature = new_cold_signature.as_ref().ok_or_else(|| {
            StateError::InvalidStakingOp(
                "cold-key rotation requires the proposed new key signature".into(),
            )
        })?;
        let message = op
            .rotate_validator_cold_key_dual_signing_bytes(chain_id)
            .map_err(|err| StateError::InvalidStakingOp(err.to_string()))?
            .ok_or_else(|| {
                StateError::InvalidStakingOp(
                    "cold-key rotation authorization message is absent".into(),
                )
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
    }

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

fn apply_register_validator(
    state: &mut ChainState,
    commission_bps: u32,
    deposit_utxo_id: Bytes32,
    validator_pubkey: &HybridPubKey,
    vrf_pk: [u8; 32],
    vrf_possession_output: &Bytes64,
    vrf_possession_proof: &VariableBytes<MAX_STANDARD_VRF_PROOF_BYTES>,
    cold_pubkey: &ColdHybridPubKey,
    chain_id: &str,
    current_height: u64,
) -> StateResult<()> {
    if commission_bps < MIN_COMMISSION_BPS
        || commission_bps > state.governance.params.max_commission_bps
    {
        return Err(StateError::InvalidStakingOp(
            "commission out of range".into(),
        ));
    }

    // Reject malformed VRF public keys before they can enter live validator state.
    indra_crypto::validate_vrf_public_key(&vrf_pk)
        .map_err(|e| StateError::InvalidStakingOp(e.to_string()))?;

    let validator_id = validator_pubkey.identity_id();
    let challenge =
        StakingOp::vrf_possession_challenge(chain_id, &validator_id, &Bytes32::from(vrf_pk), 0)
            .map_err(|error| StateError::InvalidStakingOp(error.to_string()))?;
    indra_crypto::vrf_verify(
        &vrf_pk,
        &challenge,
        &indra_crypto::VrfOutput(vrf_possession_output.0),
        &indra_crypto::VrfProof(vrf_possession_proof.as_slice().to_vec()),
    )
    .map_err(|_| {
        StateError::InvalidStakingOp(
            "validator-registration VRF secret-key possession proof is invalid".into(),
        )
    })?;
    if state.validators.get(&validator_id).is_some() {
        return Err(StateError::ValidatorAlreadyRegistered);
    }
    if state
        .evicted_validator_tombstones
        .contains_key(&validator_id)
    {
        return Err(StateError::InvalidStakingOp(
            "validator ID is retained by an evicted-validator tombstone".into(),
        ));
    }
    check_validator_identity_registry_if_present(state, &validator_id, validator_pubkey)?;
    validate_cold_components_not_retired(
        state,
        &validator_pubkey.classical_pk.0,
        validator_pubkey.pq_pk.as_slice(),
    )?;
    let validated_cold_key = {
        validate_cold_components_not_retired(
            state,
            &cold_pubkey.classical_pk.0,
            cold_pubkey.pq_pk.as_slice(),
        )?;
        validate_new_validator_cold_key(
            &state.validators,
            &validator_id,
            validator_pubkey.classical_pk.0,
            validator_pubkey.pq_pk.as_slice(),
            &cold_pubkey.classical_pk.0,
            cold_pubkey.pq_pk.as_slice(),
            1,
        )?
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

    let utxo_entry = state
        .utxos
        .get(&deposit_utxo_id)
        .ok_or(StateError::UnknownUtxo)?
        .clone();
    let owner_matches = utxo_entry.output.owner_pubkey.classical_pk.0
        == validated_cold_key.classical_pk
        && utxo_entry.output.owner_pubkey.pq_pk.as_slice() == validated_cold_key.pq_pk.as_slice();
    if !owner_matches {
        return Err(StateError::InvalidStakingOp(
            "registration bond UTXO is not owned by the proposed cold hybrid key".into(),
        ));
    }
    // Principal is derived exclusively from the referenced, custody-checked UTXO.
    let amount_spark = utxo_entry.output.value_spark;
    if amount_spark < MINIMUM_VALIDATOR_SELF_STAKE_SPARK {
        return Err(StateError::InvalidStakingOp(format!(
            "registration self-bond {} Spark below minimum {} Spark",
            amount_spark, MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
        )));
    }

    let current_epoch = epoch_for_height(state.height);
    if state.validators.len() >= MAX_VALIDATORS {
        let candidate = lowest_representable_registry_validator(state, current_height)?;
        let (lowest_id, lowest_self_stake) = candidate;
        if amount_spark <= lowest_self_stake {
            return Err(StateError::InvalidStakingOp(format!(
                "validator registry at capacity; new self-stake {} does not exceed lowest evictable registered self-stake {}",
                amount_spark, lowest_self_stake
            )));
        }
        evict_validator_for_registry_replacement(state, lowest_id, current_epoch, current_height)?;
    }

    let entry = ValidatorEntry {
        validator_id,
        name: hex::encode(&validator_id.0[..8]),
        hybrid_classical_pk: Some(validator_pubkey.classical_pk.0),
        hybrid_pq_pk: Some(validator_pubkey.pq_pk.as_slice().to_vec()),
        vrf_pk: Some(vrf_pk),
        vrf_key_activation_epoch: 0,
        pending_vrf_pk: None,
        pending_vrf_activation_epoch: None,
        stake_spark: amount_spark,
        status: ValidatorStatus::Registered,
        registered_epoch: current_epoch,
        last_active_epoch: current_epoch,
        slashed_offense_id: None,
        commission_bps,
        pending_commission_bps: None,
        pending_commission_effective_epoch: None,
        min_delegation_spark: DUST_LIMIT_SPARK,
        auto_delegate_to: None,
        network_addr: None,
        network_addr_last_updated_epoch: None,
        cold_hybrid_classical_pk: Some(validated_cold_key.classical_pk),
        cold_hybrid_pq_pk: Some(validated_cold_key.pq_pk),
        cold_key_version: validated_cold_key.version,
        cold_nonce: 0,
    };
    state.validators.upsert(entry.clone())?;
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_validator(&entry, current_height);
    }
    crate::stake_positions::deposit_stake_position(
        state,
        validator_id,
        validator_id,
        indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
            validator_id,
        },
        &utxo_entry.output.owner_pubkey,
        deposit_utxo_id,
        current_height,
    )?;
    check_or_insert_validator_identity(state, &validator_id, validator_pubkey)?;
    Ok(())
}

fn lowest_representable_registry_validator(
    state: &ChainState,
    current_height: u64,
) -> StateResult<(Bytes32, u64)> {
    let mut candidates: Vec<(Bytes32, u64)> = state
        .validators
        .all_validators()
        .filter(|validator| {
            matches!(
                validator.status,
                ValidatorStatus::Active | ValidatorStatus::Registered
            )
        })
        .map(|validator| (validator.validator_id, validator.stake_spark))
        .collect();
    candidates.sort_by(|a, b| registry_eviction_order(state, a, b));
    for candidate in candidates {
        if build_evicted_validator_tombstone(state, candidate.0, current_height).is_ok() {
            return Ok(candidate);
        }
    }
    Err(StateError::TombstoneCapacityExceeded)
}

fn registry_eviction_order(
    state: &ChainState,
    (id_a, stake_a): &(Bytes32, u64),
    (id_b, stake_b): &(Bytes32, u64),
) -> std::cmp::Ordering {
    stake_a
        .cmp(stake_b)
        .then_with(|| {
            let epoch_a = state.validators.get(id_a).map_or(u64::MAX, |v| v.registered_epoch);
            let epoch_b = state.validators.get(id_b).map_or(u64::MAX, |v| v.registered_epoch);
            epoch_b.cmp(&epoch_a)
        })
        .then_with(|| id_b.0.cmp(&id_a.0))
}

fn build_evicted_validator_tombstone(
    state: &ChainState,
    validator_id: Bytes32,
    current_height: u64,
) -> StateResult<crate::tranche_tombstone::TrancheEvictionPlanV2> {
    if state.evicted_validator_tombstones.len() >= MAX_VALIDATORS {
        return Err(StateError::TombstoneCapacityExceeded);
    }
    let validator = state
        .validators
        .get(&validator_id)
        .ok_or(StateError::ValidatorNotFound)?;
    let classical = validator
        .hybrid_classical_pk
        .ok_or(StateError::TombstoneCapacityExceeded)?;
    let pq_bytes = validator
        .hybrid_pq_pk
        .as_deref()
        .ok_or(StateError::TombstoneCapacityExceeded)?;
    let pq: [u8; indra_crypto::PQ_PK_BYTES] = pq_bytes
        .try_into()
        .map_err(|_| StateError::TombstoneCapacityExceeded)?;
    let current_epoch = epoch_for_height(current_height);
    let vrf = match (
        validator.pending_vrf_pk,
        validator.pending_vrf_activation_epoch,
    ) {
        (Some(pending), Some(activation)) if activation <= current_epoch => pending,
        _ => validator
            .vrf_pk
            .ok_or(StateError::TombstoneCapacityExceeded)?,
    };
    indra_crypto::validate_classical_public_key(&indra_crypto::ClassicalPublicKey(classical))
        .map_err(|_| StateError::TombstoneCapacityExceeded)?;
    indra_crypto::validate_pq_public_key(&indra_crypto::PqPublicKey(pq))
        .map_err(|_| StateError::TombstoneCapacityExceeded)?;
    indra_crypto::validate_vrf_public_key(&vrf)
        .map_err(|_| StateError::TombstoneCapacityExceeded)?;
    let cold_custody = Some(EvictedColdCustodyV1 {
        classical_pk: validator
            .cold_hybrid_classical_pk
            .ok_or(StateError::TombstoneCapacityExceeded)?,
        pq_pk: validator
            .cold_hybrid_pq_pk
            .ok_or(StateError::TombstoneCapacityExceeded)?,
        key_version: validator.cold_key_version,
    });
    if let Some(cold) = &cold_custody {
        indra_crypto::validate_classical_public_key(&indra_crypto::ClassicalPublicKey(
            cold.classical_pk,
        ))
        .map_err(|_| StateError::TombstoneCapacityExceeded)?;
        indra_crypto::validate_pq_public_key(&indra_crypto::PqPublicKey(cold.pq_pk))
            .map_err(|_| StateError::TombstoneCapacityExceeded)?;
    }
    let positions = state
        .stake_positions
        .iter()
        .map(|(id, position)| (*id, position.clone()))
        .collect();
    let tranches = state
        .unbonding_tranches
        .iter()
        .map(|(id, tranche)| (*id, tranche.clone()))
        .collect();
    let plan = crate::tranche_tombstone::plan_tranche_native_eviction_v2(
        &state.chain_id,
        validator_id,
        current_height,
        crate::tranche_tombstone::TombstoneAuthorityV2 {
            classical_vote_pk: classical,
            pq_vote_pk: pq,
            vrf_pk: vrf,
            cold_custody,
            slashed_offense_id: validator.slashed_offense_id,
        },
        &positions,
        &tranches,
    )?;
    let mut tombstones = state
        .evicted_validator_tombstones
        .iter()
        .map(|(id, tombstone)| (*id, tombstone.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    tombstones.insert(validator_id, plan.tombstone.clone());
    let live_ids = state
        .validators
        .all_validators()
        .filter(|validator| validator.validator_id != validator_id)
        .map(|validator| validator.validator_id)
        .collect();
    crate::tranche_tombstone::validate_all_tombstone_references_v2(
        &tombstones,
        &plan.positions,
        &plan.tranches,
        &live_ids,
    )?;
    Ok(plan)
}

fn evict_validator_for_registry_replacement(
    state: &mut ChainState,
    validator_id: Bytes32,
    current_epoch: u64,
    current_height: u64,
) -> StateResult<()> {
    evict_validator_to_tombstone(state, validator_id, current_epoch, current_height)
}

fn evict_validator_to_tombstone(
    state: &mut ChainState,
    validator_id: Bytes32,
    _current_epoch: u64,
    current_height: u64,
) -> StateResult<()> {
    let plan = build_evicted_validator_tombstone(state, validator_id, current_height)?;
    commit_tranche_eviction_plan(state, validator_id, plan, current_height)
}

pub(crate) fn commit_tranche_eviction_plan(
    state: &mut ChainState,
    validator_id: Bytes32,
    plan: crate::tranche_tombstone::TrancheEvictionPlanV2,
    current_height: u64,
) -> StateResult<()> {
    state.validators.remove(&validator_id);
    crate::txn::complex_mutation_checkpoint()?;
    state.stake_positions = plan.positions.into_iter().collect();
    crate::txn::complex_mutation_checkpoint()?;
    state.unbonding_tranches = plan.tranches.into_iter().collect();
    crate::txn::complex_mutation_checkpoint()?;
    state
        .rebuild_position_tranche_index()
        .map_err(|error| StateError::InvalidStakingOp(error.to_string()))?;
    state
        .evicted_validator_tombstones
        .insert(validator_id, plan.tombstone);
    crate::txn::complex_mutation_checkpoint()?;
    state.rebuild_state_commitment_v2(current_height)?;
    crate::txn::complex_mutation_checkpoint()?;
    Ok(())
}

/// Delegate stake to a validator.
///
/// The delegator's stake is added to the validator's delegation pool.
/// Rewards accrue from the next epoch boundary.
fn enforce_validator_position_capacity(
    state: &ChainState,
    validator_id: &Bytes32,
    cap: Option<usize>,
) -> StateResult<()> {
    let Some(cap) = cap else {
        return Ok(());
    };
    let count = state
        .stake_positions
        .values()
        .filter(|position| position.validator_id == *validator_id)
        .take(cap)
        .count();
    if validator_position_capacity_reached(count, cap) {
        return Err(StateError::ValidatorPositionCountAtMaximum {
            validator_id: *validator_id,
            max: cap,
        });
    }
    Ok(())
}

#[inline]
fn validator_position_capacity_reached(count: usize, cap: usize) -> bool {
    count >= cap
}

fn apply_delegate(
    state: &mut ChainState,
    validator_id: &Bytes32,
    deposit_utxo_id: Bytes32,
    delegator_pubkey: &HybridPubKey,
    current_height: u64,
    bond_count_cap: Option<usize>,
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
    enforce_validator_position_capacity(state, validator_id, bond_count_cap)?;
    let min_delegation = validator
        .min_delegation_spark
        .max(state.governance.params.min_delegation_spark);

    let utxo_entry = state
        .utxos
        .get(&deposit_utxo_id)
        .ok_or(StateError::UnknownUtxo)?
        .clone();

    let delegator_id = delegator_pubkey.identity_id();
    if utxo_entry.output.owner_pubkey != *delegator_pubkey {
        return Err(StateError::InvalidStakingOp(
            "UTXO does not belong to the delegator".into(),
        ));
    }
    let identity_outcome = resolve_and_check_identity(&delegator_id, delegator_pubkey, state)
        .map_err(identity_error_to_state_error)?;
    // Principal is derived exclusively from the referenced, custody-checked UTXO.
    let amount_spark = utxo_entry.output.value_spark;
    if amount_spark < min_delegation {
        return Err(StateError::InvalidStakingOp(format!(
            "delegation {} Spark below minimum {} Spark",
            amount_spark, min_delegation,
        )));
    }

    crate::stake_positions::deposit_stake_position(
        state,
        *validator_id,
        delegator_id,
        indra_core::types::stake_position::PositionCustodyV1::DelegatorIdentity { delegator_id },
        delegator_pubkey,
        deposit_utxo_id,
        current_height,
    )?;

    if matches!(identity_outcome, IdentityCheckOutcome::NoPriorRecord) {
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
        IdentityError::UnresolvableIdentity { delegator_id, .. } => StateError::InvalidStakingOp(
            format!("delegator identity is unresolvable for {delegator_id}"),
        ),
    }
}

pub(crate) fn active_delegated_position_stake(
    state: &ChainState,
    validator_id: &Bytes32,
    delegator_id: &Bytes32,
) -> u64 {
    state
        .stake_positions
        .values()
        .filter(|position| {
            position.validator_id == *validator_id
                && position.principal_owner_id == *delegator_id
                && position.validator_id != position.principal_owner_id
        })
        .filter_map(|position| position.active)
        .fold(0u64, |sum, active| {
            sum.saturating_add(active.principal_spark)
        })
}

/// Bond a validator-owned UTXO as validator self-stake.
fn apply_self_stake(
    state: &mut ChainState,
    deposit_utxo_id: Bytes32,
    validator_pubkey: &HybridPubKey,
    current_height: u64,
    bond_count_cap: Option<usize>,
) -> StateResult<()> {
    let validator_id = validator_pubkey.identity_id();
    let validator = state
        .validators
        .get(&validator_id)
        .ok_or(StateError::ValidatorNotFound)?;
    check_validator_identity_consistency(state, &validator_id, validator_pubkey)?;
    if !matches!(
        validator.status,
        ValidatorStatus::Active | ValidatorStatus::Registered
    ) {
        return Err(StateError::ValidatorNotActive);
    }
    enforce_validator_position_capacity(state, &validator_id, bond_count_cap)?;

    let utxo_entry = state
        .utxos
        .get(&deposit_utxo_id)
        .ok_or(StateError::UnknownUtxo)?
        .clone();
    let cold_owner = resolve_active_validator_cold_pubkey(state, &validator_id)
        .map_err(identity_error_to_state_error)?;
    if utxo_entry.output.owner_pubkey != cold_owner {
        return Err(StateError::InvalidStakingOp(
            "self-stake UTXO is not owned by the validator's cold key".into(),
        ));
    }
    // Principal is derived exclusively from the referenced, custody-checked UTXO.
    let amount_spark = utxo_entry.output.value_spark;
    if amount_spark < DUST_LIMIT_SPARK {
        return Err(StateError::InvalidStakingOp(format!(
            "self-stake {} Spark below dust limit {} Spark",
            amount_spark, DUST_LIMIT_SPARK,
        )));
    }

    let updated_stake_spark = state
        .validators
        .get(&validator_id)
        .ok_or(StateError::ValidatorNotFound)?
        .stake_spark
        .checked_add(amount_spark)
        .ok_or(StateError::InvariantViolation {
            message: "validator self-stake cache overflow",
        })?;

    crate::stake_positions::deposit_stake_position(
        state,
        validator_id,
        validator_id,
        indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
            validator_id,
        },
        &cold_owner,
        deposit_utxo_id,
        current_height,
    )?;
    let mut updated_validator = None;
    if let Some(v) = state.validators.get_mut(&validator_id) {
        v.stake_spark = updated_stake_spark;
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
/// Materializes already-issued pending rewards as a canonical synthetic UTXO;
/// this is a balance transfer and does not mint or change total supply.
fn apply_claim_rewards(
    state: &mut ChainState,
    validator_id: &Bytes32,
    delegator_pubkey: &HybridPubKey,
    current_height: u64,
    synthetic_output_index: u32,
) -> StateResult<()> {
    let delegator_id = delegator_pubkey.identity_id();
    let claim_from_validator = *validator_id == delegator_id;
    let custody = if claim_from_validator {
        indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
            validator_id: *validator_id,
        }
    } else {
        indra_core::types::stake_position::PositionCustodyV1::DelegatorIdentity { delegator_id }
    };
    let position_id =
        indra_core::types::stake_position::derive_position_id(*validator_id, delegator_id, custody);
    let claimed = state
        .stake_positions
        .get(&position_id)
        .map(|position| position.pending_rewards_spark)
        .ok_or(StateError::DelegatorNotFound)?;
    let payout_pubkey = if claim_from_validator {
        resolve_active_validator_cold_pubkey(state, validator_id).map_err(|_| {
            StateError::InvariantViolation {
                message: "active validator cold reward owner is unresolvable",
            }
        })?
    } else {
        delegator_pubkey.clone()
    };

    if claimed == 0 {
        return Ok(());
    }
    if claimed < DUST_LIMIT_SPARK {
        return Err(StateError::InvalidStakingOp(format!(
            "rewards {} Spark below dust limit {} Spark",
            claimed, DUST_LIMIT_SPARK
        )));
    }
    let identity_outcome = resolve_and_check_identity(&delegator_id, delegator_pubkey, state)
        .map_err(identity_error_to_state_error)?;
    if matches!(identity_outcome, IdentityCheckOutcome::NoPriorRecord) {
        check_claim_owner_identity_for_first_record(
            state,
            validator_id,
            &delegator_id,
            delegator_pubkey,
            claim_from_validator,
        )?;
    }
    let mut position = state
        .stake_positions
        .get(&position_id)
        .cloned()
        .ok_or(StateError::DelegatorNotFound)?;
    position.pending_rewards_spark = 0;
    state.stake_positions.insert(position_id, position.clone());
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_stake_position(&position);
    }
    if matches!(identity_outcome, IdentityCheckOutcome::NoPriorRecord) {
        state
            .delegator_identities
            .insert(delegator_id, delegator_pubkey.clone());
        if let Some(commitment) = state.state_commitment_v2.as_mut() {
            commitment.put_delegator_identity(&delegator_id, delegator_pubkey);
        }
    }

    let output = OutputV1 {
        value_spark: claimed,
        owner_pubkey: payout_pubkey,
        lock_height: 0,
    };

    state
        .utxos
        .insert(
            output,
            current_height,
            STAKING_REWARD_TX_IDX,
            synthetic_output_index,
        )
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

    let owner_pubkey = state
        .delegator_identities
        .get(delegator_id)
        .ok_or_else(|| {
            StateError::InvalidStakingOp(format!(
                "delegator identity claim owner is unresolvable for {delegator_id}"
            ))
        })?;
    if owner_pubkey != submitted_pubkey {
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
    let effective_epoch = epoch_for_height(current_height)
        .checked_add(COMMISSION_CHANGE_DELAY_EPOCHS)
        .ok_or_else(|| {
            StateError::InvalidStakingOp("commission activation epoch overflow".into())
        })?;
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

#[cfg(test)]
mod tests {
    use indra_core::types::primitives::TEST_CHAIN_ID;
    use super::*;
    use crate::{
        chain::ChainState,
        validator::{ValidatorEntry, ValidatorStatus},
    };
    use indra_core::types::{
        crypto::{ColdHybridPubKey, HybridPubKey, HybridSignature},
        primitives::VariableBytes,
        transaction::OutputV1,
    };
    use indra_crypto::hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair};

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

    fn test_vrf_public_key(seed: u8) -> [u8; 32] {
        indra_crypto::VrfKeypair::from_seed(&[seed; 32]).public_key()
    }

    fn test_registration_vrf_pop(
        chain_id: &str,
        validator_pubkey: &HybridPubKey,
        seed: u8,
    ) -> (
        [u8; 32],
        Bytes64,
        VariableBytes<MAX_STANDARD_VRF_PROOF_BYTES>,
    ) {
        let keypair = indra_crypto::VrfKeypair::from_seed(&[seed; 32]);
        let vrf_pk = keypair.public_key();
        let challenge = StakingOp::vrf_possession_challenge(
            chain_id,
            &validator_pubkey.identity_id(),
            &Bytes32::from(vrf_pk),
            0,
        )
        .unwrap();
        let (output, proof) = indra_crypto::vrf_prove(&keypair, &challenge);
        (
            vrf_pk,
            Bytes64(output.0),
            VariableBytes::from_slice(&proof.0).unwrap(),
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

    fn test_output(value_spark: u64, owner_pubkey: HybridPubKey, _seed: u8) -> OutputV1 {
        OutputV1 {
            value_spark,
            owner_pubkey,
            lock_height: 0,
        }
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

    fn insert_registration_utxo(
        state: &mut ChainState,
        hot_pubkey: HybridPubKey,
        value_spark: u64,
        seed: u8,
    ) -> Bytes32 {
        let cold = derived_test_cold_keypair_from_classical(&hot_pubkey.classical_pk.0);
        insert_delegator_utxo(state, pubkey_from_keypair(&cold), value_spark, seed)
    }

    fn dummy_signature() -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
        }
    }

    fn derived_test_cold_keypair(hot: &HybridKeypair) -> HybridKeypair {
        derived_test_cold_keypair_from_classical(&hot.public_key().classical.0)
    }

    fn derived_test_cold_keypair_from_classical(hot_classical: &[u8; 32]) -> HybridKeypair {
        let mut classical_seed = indra_crypto::sha256(hot_classical);
        let mut pq_material = Vec::from(*hot_classical);
        pq_material.extend_from_slice(b"INDRA-TEST-COLD-PQ");
        let pq_seed = indra_crypto::sha256(&pq_material);
        classical_seed[0] ^= 0xA5;
        HybridKeypair::new(
            ClassicalKeypair::from_seed(&classical_seed),
            PqKeypair::from_seed(&pq_seed).unwrap(),
        )
    }

    fn signed_op(
        mut body: StakingOpBody,
        nonce: u64,
        keypair: &HybridKeypair,
        chain_id: &str,
    ) -> StakingOp {
        // Pure-protocol validator operations are cold-authorized from genesis.
        // Tests use one deterministic keypair for both roles unless they are
        // specifically exercising key separation.
        match &mut body {
            StakingOpBody::SetCommission {
                cold_authorization, ..
            }
            | StakingOpBody::SelfStake {
                cold_authorization, ..
            }
            | StakingOpBody::SetAutoDelegate {
                cold_authorization, ..
            } => {
                *cold_authorization = indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 1,
                    cold_nonce: nonce,
                };
            }
            StakingOpBody::ExitStakePosition {
                custody:
                    indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
                        ..
                    },
                cold_authorization,
                ..
            } => {
                *cold_authorization = Some(indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 1,
                    cold_nonce: nonce,
                });
            }
            _ => {}
        }
        let cold_designated = matches!(
            &body,
            StakingOpBody::SetCommission { .. }
                | StakingOpBody::SelfStake { .. }
                | StakingOpBody::ExitStakePosition {
                    custody: indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity { .. }, ..
                }
                | StakingOpBody::SetAutoDelegate { .. }
        );
        let mut op = StakingOp {
            body,
            nonce: if cold_designated { 0 } else { nonce },
            signature: dummy_signature(),
        };
        if let StakingOpBody::RegisterValidator {
            cold_pubkey,
            cold_signature,
            ..
        } = &mut op.body
        {
            let cold_keypair = derived_test_cold_keypair(keypair);
            *cold_pubkey = cold_pubkey_from_keypair(&cold_keypair);
            *cold_signature = dummy_signature();
            let message = op
                .register_validator_dual_signing_bytes(chain_id)
                .unwrap()
                .unwrap();
            op.signature = wire_signature(&keypair.sign(&message).unwrap());
            let cold_sig = wire_signature(&cold_keypair.sign(&message).unwrap());
            let StakingOpBody::RegisterValidator { cold_signature, .. } = &mut op.body else {
                unreachable!()
            };
            *cold_signature = cold_sig;
            return op;
        }
        let signing_bytes = op
            .cold_authorization_signing_bytes(chain_id)
            .unwrap()
            .unwrap_or_else(|| op.signing_bytes(chain_id));
        let sig = if cold_designated {
            derived_test_cold_keypair(keypair)
                .sign(&signing_bytes)
                .unwrap()
        } else {
            keypair.sign(&signing_bytes).unwrap()
        };
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

    fn dual_signed_register_op(
        deposit_utxo_id: Bytes32,
        hot_keypair: &HybridKeypair,
        cold_keypair: &HybridKeypair,
        nonce: u64,
        chain_id: &str,
        vrf_pk: [u8; 32],
        vrf_prover: &indra_crypto::VrfKeypair,
    ) -> StakingOp {
        let validator_pubkey = pubkey_from_keypair(hot_keypair);
        let challenge = StakingOp::vrf_possession_challenge(
            chain_id,
            &validator_pubkey.identity_id(),
            &Bytes32::from(vrf_pk),
            0,
        )
        .unwrap();
        let (vrf_output, vrf_proof) = indra_crypto::vrf_prove(vrf_prover, &challenge);
        let mut op = StakingOp {
            body: StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                deposit_utxo_id,
                validator_pubkey,
                vrf_pk,
                vrf_possession_output: Bytes64(vrf_output.0),
                vrf_possession_proof: VariableBytes::from_slice(&vrf_proof.0).unwrap(),
                cold_pubkey: cold_pubkey_from_keypair(cold_keypair),
                cold_signature: dummy_signature(),
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
        *slot = cold_signature;
        op
    }

    fn resign_register_op(
        op: &mut StakingOp,
        hot_keypair: &HybridKeypair,
        cold_keypair: &HybridKeypair,
        chain_id: &str,
    ) {
        if let StakingOpBody::RegisterValidator { cold_signature, .. } = &mut op.body {
            *cold_signature = dummy_signature();
        }
        op.signature = dummy_signature();
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
        *slot = cold_signature;
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

    fn activate_cold_for_test(state: &mut ChainState, validator_id: Bytes32, cold: &HybridKeypair) {
        let public = cold.public_key();
        let validator = state.validators.get_mut(&validator_id).unwrap();
        validator.cold_hybrid_classical_pk = Some(public.classical.0);
        validator.cold_hybrid_pq_pk = Some(public.pq.0);
        validator.cold_key_version = 1;
        validator.cold_nonce = 0;
    }

    fn make_active_validator(state: &mut ChainState, seed: u8) -> (Bytes32, HybridKeypair) {
        let keypair = keypair(seed);
        let pubkey = pubkey_from_keypair(&keypair);
        let validator_id = pubkey.identity_id();
        insert_active_validator_with_pubkey(state, validator_id, &pubkey, seed);
        let cold = derived_test_cold_keypair(&keypair).public_key();
        let entry = state.validators.get_mut(&validator_id).unwrap();
        entry.cold_hybrid_classical_pk = Some(cold.classical.0);
        entry.cold_hybrid_pq_pk = Some(cold.pq.0);
        (validator_id, keypair)
    }

    fn insert_active_validator_with_pubkey(
        state: &mut ChainState,
        validator_id: Bytes32,
        pubkey: &HybridPubKey,
        seed: u8,
    ) {
        let cold = derived_test_cold_keypair_from_classical(&pubkey.classical_pk.0).public_key();
        let entry = ValidatorEntry {
            validator_id,
            name: format!("validator-{seed}"),
            hybrid_classical_pk: Some(pubkey.classical_pk.0),
            hybrid_pq_pk: Some(pubkey.pq_pk.as_slice().to_vec()),
            vrf_pk: Some(test_vrf_public_key(seed)),
            vrf_key_activation_epoch: 0,
            pending_vrf_pk: None,
            pending_vrf_activation_epoch: None,
            stake_spark: 10_000_000_000,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            slashed_offense_id: None,
            commission_bps: 1_000,
            pending_commission_bps: None,
            pending_commission_effective_epoch: None,
            min_delegation_spark: indra_core::types::primitives::DUST_LIMIT_SPARK,
            auto_delegate_to: None,
            network_addr: None,
            network_addr_last_updated_epoch: None,
            cold_hybrid_classical_pk: Some(cold.classical.0),
            cold_hybrid_pq_pk: Some(cold.pq.0),
            cold_key_version: 1,
            cold_nonce: 0,
        };
        state.validators.upsert(entry).unwrap();
    }

    fn vrf_registration_op(
        validator_id: Bytes32,
        vrf_pubkey: Bytes32,
        activation_epoch_id: u64,
        signer: &HybridKeypair,
        vrf_keypair: &indra_crypto::VrfKeypair,
        chain_id: &str,
    ) -> StakingOp {
        let challenge = StakingOp::vrf_possession_challenge(
            chain_id,
            &validator_id,
            &vrf_pubkey,
            activation_epoch_id,
        )
        .unwrap();
        let (output, proof) = indra_crypto::vrf_prove(vrf_keypair, &challenge);
        signed_op(
            StakingOpBody::RegisterVrfKey {
                validator_id,
                vrf_suite: indra_core::types::block::VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
                vrf_pubkey,
                activation_epoch_id,
                vrf_possession_output: indra_core::types::primitives::Bytes64(output.0),
                vrf_possession_proof: VariableBytes::from_slice(&proof.0).unwrap(),
            },
            1,
            signer,
            chain_id,
        )
    }

    #[test]
    fn vrf_rotation_is_snapshot_delayed_and_public_key_squatting_is_rejected() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        state.active_slot_coefficient_numerator =
            indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR;
        let (validator_id, signer) = make_active_validator(&mut state, 31);
        let old_vrf = indra_crypto::VrfKeypair::from_seed(&[31; 32]).public_key();
        state.validators.get_mut(&validator_id).unwrap().vrf_pk = Some(old_vrf);
        state.finalize_genesis().unwrap();
        let genesis_snapshot = state.snapshot_for_consensus_height(1).unwrap().clone();

        let new_vrf_keypair = indra_crypto::VrfKeypair::from_seed(&[99; 32]);
        let new_vrf = Bytes32::from(new_vrf_keypair.public_key());
        let op = vrf_registration_op(
            validator_id,
            new_vrf,
            1,
            &signer,
            &new_vrf_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &op, &chain_id, 1).unwrap();
        assert_eq!(
            state.snapshot_for_consensus_height(1).unwrap(),
            &genesis_snapshot
        );
        let next = state.build_consensus_snapshot(301, 300).unwrap();
        let (_, activated) = next.entry_with_position(&validator_id).unwrap();
        assert_eq!(activated.vrf_pk, new_vrf.0);
        assert_eq!(activated.vrf_key_activation_epoch, 1);

        let victim_vrf = indra_crypto::VrfKeypair::from_seed(&[100; 32]);
        let replacement = Bytes32::from(victim_vrf.public_key());
        let attacker_vrf = indra_crypto::VrfKeypair::from_seed(&[101; 32]);
        let challenge =
            StakingOp::vrf_possession_challenge(&chain_id, &validator_id, &replacement, 1).unwrap();
        let (attacker_output, attacker_proof) = indra_crypto::vrf_prove(&attacker_vrf, &challenge);
        let bad = signed_op(
            StakingOpBody::RegisterVrfKey {
                validator_id,
                vrf_suite: indra_core::types::block::VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
                vrf_pubkey: replacement,
                activation_epoch_id: 1,
                vrf_possession_output: indra_core::types::primitives::Bytes64(attacker_output.0),
                vrf_possession_proof: VariableBytes::from_slice(&attacker_proof.0).unwrap(),
            },
            2,
            &signer,
            &chain_id,
        );
        assert!(apply_staking_op(&mut state, &bad, &chain_id, 1).is_err());
    }

    #[test]
    fn vrf_registration_rejects_slashed_and_exited_validators() {
        for status in [ValidatorStatus::Slashed, ValidatorStatus::Exited] {
            let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
            let (validator_id, signer) = make_active_validator(&mut state, 0x6A);
            state.validators.get_mut(&validator_id).unwrap().status = status;
            let vrf = indra_crypto::VrfKeypair::from_seed(&[0x6B; 32]);
            let op = vrf_registration_op(
                validator_id,
                Bytes32::from(vrf.public_key()),
                1,
                &signer,
                &vrf,
                &state.chain_id,
            );
            let chain_id = state.chain_id.clone();
            assert!(matches!(
                apply_staking_op(&mut state, &op, &chain_id, 1),
                Err(StateError::ValidatorNotActive)
            ));
        }
    }

    #[test]
    fn hot_staking_nonce_exhaustion_fails_closed() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let signer = keypair(0x6C);
        let signer_id = pubkey_from_keypair(&signer).identity_id();
        state.staking_nonces.insert(signer_id, u64::MAX);
        let op = delegate_op(&state, Bytes32::from([0x6D; 32]), Bytes32::ZERO, &signer, 0);
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::InvalidStakingOp(reason)) if reason == "staking nonce exhausted"
        ));
    }

    #[test]
    fn self_stake_cache_overflow_fails_before_consuming_utxo() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, hot) = make_active_validator(&mut state, 0x6E);
        state.validators.get_mut(&validator_id).unwrap().stake_spark = u64::MAX;
        let cold_owner = resolve_active_validator_cold_pubkey(&state, &validator_id).unwrap();
        let deposit = insert_delegator_utxo(
            &mut state,
            cold_owner,
            indra_core::types::primitives::DUST_LIMIT_SPARK,
            0x6F,
        );
        let before = state.clone();
        let result = apply_self_stake(
            &mut state,
            deposit,
            &pubkey_from_keypair(&hot),
            1,
            Some(MAX_STAKE_POSITIONS_PER_VALIDATOR),
        );
        assert!(matches!(result, Err(StateError::InvariantViolation { .. })));
        assert_eq!(state, before);
    }

    fn delegate_op(
        state: &ChainState,
        validator_id: Bytes32,
        deposit_utxo_id: Bytes32,
        delegator_keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        signed_op(
            StakingOpBody::Delegate {
                validator_id,
                deposit_utxo_id,
                delegator_pubkey: pubkey_from_keypair(delegator_keypair),
            },
            nonce,
            delegator_keypair,
            &state.chain_id,
        )
    }

    fn self_stake_op(
        state: &ChainState,
        deposit_utxo_id: Bytes32,
        validator_keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        signed_op(
            StakingOpBody::SelfStake {
                deposit_utxo_id,
                validator_pubkey: pubkey_from_keypair(validator_keypair),
                cold_authorization: indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 1,
                    cold_nonce: nonce,
                },
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
                cold_authorization: indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 1,
                    cold_nonce: nonce,
                },
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
                cold_authorization: indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 1,
                    cold_nonce: nonce,
                },
            },
            nonce,
            validator_keypair,
            &state.chain_id,
        )
    }

    #[test]
    fn commission_change_is_not_immediate() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
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
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
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
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let wrong_owner = pubkey_from_keypair(&keypair(0x03));
        let deposit_utxo_id = insert_delegator_utxo(&mut state, wrong_owner, 1_000_000, 0x11);

        let op = delegate_op(&state, validator_id, deposit_utxo_id, &delegator_keypair, 1);
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::InvalidStakingOp(_))
        ));
    }

    #[test]
    fn delegate_rejects_same_classical_key_with_substituted_pq_key() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, _) = make_active_validator(&mut state, 0x21);
        let legitimate_keypair = mixed_keypair(0x22, 0x23);
        let attacker_keypair = mixed_keypair(0x22, 0x24);
        let legitimate_pubkey = pubkey_from_keypair(&legitimate_keypair);
        let attacker_pubkey = pubkey_from_keypair(&attacker_keypair);
        assert_eq!(legitimate_pubkey.classical_pk, attacker_pubkey.classical_pk);
        assert_ne!(legitimate_pubkey, attacker_pubkey);
        let deposit_utxo_id = insert_delegator_utxo(&mut state, legitimate_pubkey, 1_000_000, 0x25);
        let op = delegate_op(&state, validator_id, deposit_utxo_id, &attacker_keypair, 1);
        let chain_id = state.chain_id.clone();
        let before = state.clone();

        let error = apply_staking_op(&mut state, &op, &chain_id, 1).unwrap_err();

        assert!(matches!(error, StateError::InvalidStakingOp(message)
            if message.contains("does not belong to the delegator")));
        assert_eq!(state, before);
    }

    #[test]
    fn delegate_rejects_below_minimum() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        state
            .validators
            .get_mut(&validator_id)
            .unwrap()
            .min_delegation_spark = 2_000_000;
        let delegator_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&delegator_keypair);
        let deposit_utxo_id = insert_delegator_utxo(&mut state, pubkey, 1_000_000, 0x13);

        let op = delegate_op(&state, validator_id, deposit_utxo_id, &delegator_keypair, 1);
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::InvalidStakingOp(_))
        ));
    }

    #[test]
    fn substituted_pq_key_cannot_resolve_victim_validator_identity() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let legitimate_keypair = mixed_keypair(0x54, 0x55);
        let attacker_keypair = mixed_keypair(0x54, 0x56);
        let legitimate_pubkey = pubkey_from_keypair(&legitimate_keypair);
        let attacker_pubkey = pubkey_from_keypair(&attacker_keypair);
        let validator_id = legitimate_pubkey.identity_id();
        assert_ne!(attacker_pubkey.identity_id(), validator_id);
        insert_active_validator_with_pubkey(&mut state, validator_id, &legitimate_pubkey, 0x54);
        state
            .delegator_identities
            .insert(validator_id, legitimate_pubkey.clone());
        let deposit_utxo_id = insert_delegator_utxo(&mut state, legitimate_pubkey, 2_000_000, 0x54);
        let op = signed_op(
            StakingOpBody::SelfStake {
                deposit_utxo_id,
                validator_pubkey: attacker_pubkey,
                cold_authorization: indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 1,
                    cold_nonce: 1,
                },
            },
            1,
            &attacker_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        let before = state.clone();

        let err = apply_staking_op(&mut state, &op, &chain_id, 1).unwrap_err();

        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("cold authorization is valid only for an Active validator")
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn first_registration_with_compromised_classical_key_cannot_squat_victim_identity_id() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let victim_keypair = mixed_keypair(0x5B, 0x5C);
        let attacker_keypair = mixed_keypair(0x5B, 0x5D);
        let victim_pubkey = pubkey_from_keypair(&victim_keypair);
        let attacker_pubkey = pubkey_from_keypair(&attacker_keypair);
        let victim_id = victim_pubkey.identity_id();
        let attacker_id = attacker_pubkey.identity_id();
        assert_eq!(victim_pubkey.classical_pk, attacker_pubkey.classical_pk);
        assert_ne!(victim_pubkey.pq_pk, attacker_pubkey.pq_pk);
        assert_ne!(victim_id, attacker_id);

        let attacker_cold = derived_test_cold_keypair(&attacker_keypair);
        let deposit_utxo_id = insert_delegator_utxo(
            &mut state,
            pubkey_from_keypair(&attacker_cold),
            MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
            0x5E,
        );
        let op = dual_signed_register_op(
            deposit_utxo_id,
            &attacker_keypair,
            &attacker_cold,
            1,
            &state.chain_id,
            test_vrf_public_key(0x5F),
            &indra_crypto::VrfKeypair::from_seed(&[0x5F; 32]),
        );
        let chain_id = state.chain_id.clone();

        apply_staking_op(&mut state, &op, &chain_id, 1).unwrap();

        assert!(state.validators.get(&attacker_id).is_some());
        assert!(state.validators.get(&victim_id).is_none());
    }

    #[test]
    fn validator_self_stake_post_identity_gate_rejects_registry_mismatch() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let legitimate_keypair = mixed_keypair(0x58, 0x59);
        let conflicting_keypair = mixed_keypair(0x58, 0x5A);
        let legitimate_pubkey = pubkey_from_keypair(&legitimate_keypair);
        let conflicting_pubkey = pubkey_from_keypair(&conflicting_keypair);
        let validator_id = legitimate_pubkey.identity_id();
        assert_ne!(conflicting_pubkey.identity_id(), validator_id);
        insert_active_validator_with_pubkey(&mut state, validator_id, &legitimate_pubkey, 0x58);
        state
            .delegator_identities
            .insert(validator_id, conflicting_pubkey);
        let deposit_utxo_id = insert_delegator_utxo(&mut state, legitimate_pubkey, 2_000_000, 0x58);
        let op = self_stake_op(&state, deposit_utxo_id, &legitimate_keypair, 1);
        let chain_id = state.chain_id.clone();
        let before = state.clone();

        let err = apply_staking_op(&mut state, &op, &chain_id, 1).unwrap_err();

        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("validator identity registry pubkey mismatch")
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn self_stake_rejects_unknown_utxo() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
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
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (_, validator_keypair) = make_active_validator(&mut state, 0x01);
        let wrong_owner = pubkey_from_keypair(&keypair(0x02));
        let deposit_utxo_id = insert_delegator_utxo(&mut state, wrong_owner, 2_000_000, 0x32);

        let op = self_stake_op(&state, deposit_utxo_id, &validator_keypair, 1);
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::InvalidStakingOp(_))
        ));
    }

    #[test]
    fn self_stake_rejects_unregistered_validator() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let validator_keypair = keypair(0x01);
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let deposit_utxo_id = insert_delegator_utxo(&mut state, pubkey, 2_000_000, 0x33);

        let op = self_stake_op(&state, deposit_utxo_id, &validator_keypair, 1);
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::InvalidStakingOp(message))
                if message.contains("cold authorization is valid only for an Active validator")
        ));
    }

    #[test]
    fn self_stake_rejects_slashed_validator() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0x01);
        state.validators.get_mut(&validator_id).unwrap().status = ValidatorStatus::Slashed;
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let deposit_utxo_id = insert_delegator_utxo(&mut state, pubkey, 2_000_000, 0x34);

        let op = self_stake_op(&state, deposit_utxo_id, &validator_keypair, 1);
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::ValidatorNotActive)
        );
    }

    #[test]
    fn self_stake_rejects_invalid_signature() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (_, validator_keypair) = make_active_validator(&mut state, 0x01);
        let wrong_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let deposit_utxo_id = insert_delegator_utxo(&mut state, pubkey.clone(), 2_000_000, 0x36);
        let op = signed_op(
            StakingOpBody::SelfStake {
                deposit_utxo_id,
                validator_pubkey: pubkey,
                cold_authorization: indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 1,
                    cold_nonce: 1,
                },
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
    fn apply_staking_op_rejects_wrong_nonce() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let op = signed_op(
            StakingOpBody::Delegate {
                validator_id,
                deposit_utxo_id: Bytes32::from([0x31; 32]),
                delegator_pubkey: pubkey_from_keypair(&delegator_keypair),
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
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let chain_id = state.chain_id.clone();
        let pubkey = pubkey_from_keypair(&delegator_keypair);
        let deposit_utxo_id = insert_delegator_utxo(&mut state, pubkey, 1_000_000, 0x17);
        let op = delegate_op(&state, validator_id, deposit_utxo_id, &delegator_keypair, 1);
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
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let wrong_keypair = keypair(0x03);
        let op = signed_op(
            StakingOpBody::Delegate {
                validator_id,
                deposit_utxo_id: Bytes32::from([0x32; 32]),
                delegator_pubkey: pubkey_from_keypair(&delegator_keypair),
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
    fn register_validator_post_identity_gate_rejects_preexisting_registry_mismatch() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let validator_keypair = mixed_keypair(0xB2, 0xB3);
        let conflicting_keypair = mixed_keypair(0xB2, 0xB4);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let conflicting_pubkey = pubkey_from_keypair(&conflicting_keypair);
        let validator_id = validator_pubkey.identity_id();
        assert_ne!(conflicting_pubkey.identity_id(), validator_id);
        state
            .delegator_identities
            .insert(validator_id, conflicting_pubkey);
        let deposit_utxo_id = insert_registration_utxo(
            &mut state,
            validator_pubkey.clone(),
            MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
            0xB2,
        );
        let (vrf_pk, vrf_possession_output, vrf_possession_proof) =
            test_registration_vrf_pop(&state.chain_id, &validator_pubkey, 0xB2);
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                deposit_utxo_id,
                validator_pubkey,
                vrf_pk,
                vrf_possession_output,
                vrf_possession_proof,
                cold_pubkey: cold_pubkey_from_keypair(&derived_test_cold_keypair(
                    &validator_keypair,
                )),
                cold_signature: dummy_signature(),
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        let before = state.clone();

        let err = apply_staking_op(&mut state, &op, &chain_id, 1).unwrap_err();

        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("validator identity registry pubkey mismatch")
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn validator_and_delegator_registry_keys_bind_complete_hybrid_pubkeys() {
        let validator_pubkey = pubkey_from_keypair(&keypair(0xB5));
        let delegator_pubkey = pubkey_from_keypair(&keypair(0xB6));
        let validator_id = validator_pubkey.identity_id();
        let delegator_id = delegator_pubkey.identity_id();

        assert_ne!(validator_id, delegator_id);
        assert_eq!(validator_pubkey.identity_id(), validator_id);
        assert_eq!(delegator_pubkey.identity_id(), delegator_id);
    }

    #[test]
    fn update_network_address_requires_validator_signature() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
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
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
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
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
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
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
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
            let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
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
    fn registration_without_bond_is_rejected() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let validator_keypair = keypair(0x44);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let (vrf_pk, vrf_possession_output, vrf_possession_proof) =
            test_registration_vrf_pop(&state.chain_id, &validator_pubkey, 0x44);
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                deposit_utxo_id: Bytes32::from([0xFE; 32]),
                validator_pubkey,
                vrf_pk,
                vrf_possession_output,
                vrf_possession_proof,
                cold_pubkey: cold_pubkey_from_keypair(&derived_test_cold_keypair(
                    &validator_keypair,
                )),
                cold_signature: dummy_signature(),
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
    fn registration_with_bond_below_minimum_is_rejected() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let validator_keypair = keypair(0x45);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let deposit_utxo_id = insert_registration_utxo(
            &mut state,
            validator_pubkey.clone(),
            MINIMUM_VALIDATOR_SELF_STAKE_SPARK - 1,
            0xA2,
        );
        let (vrf_pk, vrf_possession_output, vrf_possession_proof) =
            test_registration_vrf_pop(&state.chain_id, &validator_pubkey, 0x45);
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                deposit_utxo_id,
                validator_pubkey,
                vrf_pk,
                vrf_possession_output,
                vrf_possession_proof,
                cold_pubkey: cold_pubkey_from_keypair(&derived_test_cold_keypair(
                    &validator_keypair,
                )),
                cold_signature: dummy_signature(),
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
    fn set_auto_delegate_stores_target() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
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
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
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
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
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
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
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
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
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

    fn registration_op_with_cold_deposit(
        state: &mut ChainState,
        hot_seed: u8,
        cold_classical_seed: u8,
        cold_pq_seed: u8,
        bond_seed: u8,
    ) -> (StakingOp, Bytes32, Bytes32) {
        let hot = keypair(hot_seed);
        let cold = mixed_keypair(cold_classical_seed, cold_pq_seed);
        let cold_owner = pubkey_from_keypair(&cold);
        let deposit_utxo_id = insert_delegator_utxo(
            state,
            cold_owner,
            MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
            bond_seed,
        );
        let validator_id = pubkey_from_keypair(&hot).identity_id();
        let op = dual_signed_register_op(
            deposit_utxo_id,
            &hot,
            &cold,
            1,
            &state.chain_id,
            test_vrf_public_key(bond_seed.wrapping_add(1)),
            &indra_crypto::VrfKeypair::from_seed(&[bond_seed.wrapping_add(1); 32]),
        );
        (op, deposit_utxo_id, validator_id)
    }

    fn cold_self_stake_op(
        state: &ChainState,
        deposit_utxo_id: Bytes32,
        hot: &HybridKeypair,
        cold: &HybridKeypair,
        cold_nonce: u64,
    ) -> StakingOp {
        let validator_id = pubkey_from_keypair(hot).identity_id();
        let cold_key_version = state
            .validators
            .get(&validator_id)
            .expect("self-stake validator")
            .cold_key_version;
        cold_signed_op(
            StakingOpBody::SelfStake {
                deposit_utxo_id,
                validator_pubkey: pubkey_from_keypair(hot),
                cold_authorization: indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version,
                    cold_nonce,
                },
            },
            cold,
            &state.chain_id,
        )
    }

    #[test]
    fn register_validator_accepts_distinct_hot_and_cold_custody() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (op, deposit_id, validator_id) =
            registration_op_with_cold_deposit(&mut state, 0x81, 0x82, 0x83, 0x84);
        let chain_id = state.chain_id.clone();

        apply_staking_op(&mut state, &op, &chain_id, 1).unwrap();

        assert!(!state.utxos.contains(&deposit_id));
        let custody = indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
            validator_id,
        };
        let position_id = indra_core::types::stake_position::derive_position_id(
            validator_id,
            validator_id,
            custody,
        );
        let position = state.stake_positions.get(&position_id).unwrap();
        assert_eq!(position.validator_id, validator_id);
        assert_eq!(position.principal_owner_id, validator_id);
        assert_eq!(position.custody, custody);
        assert_eq!(position.position_id, position_id);
    }

    #[test]
    fn self_stake_accepts_distinct_hot_and_current_cold_custody() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, hot) = make_active_validator(&mut state, 0x85);
        let cold = mixed_keypair(0x86, 0x87);
        activate_cold_for_test(&mut state, validator_id, &cold);
        let deposit_id =
            insert_delegator_utxo(&mut state, pubkey_from_keypair(&cold), 2_000_000, 0x88);
        let op = cold_self_stake_op(&state, deposit_id, &hot, &cold, 1);
        let chain_id = state.chain_id.clone();

        apply_staking_op(&mut state, &op, &chain_id, 1).unwrap();

        assert!(!state.utxos.contains(&deposit_id));
        let custody = indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
            validator_id,
        };
        let position_id = indra_core::types::stake_position::derive_position_id(
            validator_id,
            validator_id,
            custody,
        );
        let position = state.stake_positions.get(&position_id).unwrap();
        assert_eq!(position.position_id, position_id);
        assert_eq!(position.validator_id, validator_id);
        assert_eq!(position.principal_owner_id, validator_id);
        assert_eq!(position.custody, custody);

        // All downstream self/delegation classification is deliberately based
        // on this logical tuple, not on the funding UTXO's custody key.
        let snapshot = crate::epoch::take_governance_snapshot(&state);
        assert_eq!(
            snapshot.weights.get(&validator_id),
            Some(&state.validators.get(&validator_id).unwrap().stake_spark)
        );
        assert_eq!(state.total_active_delegated_stake(), 0);

        let mut rewarded = position.clone();
        rewarded.pending_rewards_spark = DUST_LIMIT_SPARK;
        state.stake_positions.insert(position_id, rewarded);
        let claim = cold_signed_op(
            StakingOpBody::ClaimRewards {
                validator_id,
                delegator_pubkey: pubkey_from_keypair(&hot),
                cold_authorization: Some(indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 1,
                    cold_nonce: 2,
                }),
            },
            &cold,
            &chain_id,
        );
        apply_staking_op(&mut state, &claim, &chain_id, 2).unwrap();
        assert_eq!(
            state
                .stake_positions
                .get(&position_id)
                .unwrap()
                .pending_rewards_spark,
            0
        );

        let exit = cold_signed_op(
            StakingOpBody::ExitStakePosition {
                position_id,
                amount_spark: 2_000_000,
                custody,
                cold_authorization: Some(indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 1,
                    cold_nonce: 3,
                }),
            },
            &cold,
            &chain_id,
        );
        apply_staking_op(&mut state, &exit, &chain_id, 3).unwrap();
        let tranche = state.unbonding_tranches.values().next().unwrap();
        let indra_core::types::stake_position::UnbondingTimingV1::HeightPrecise {
            end_epoch, ..
        } = tranche.timing;
        let release_height = end_epoch * indra_core::types::primitives::EPOCH_DURATION_BLOCKS;
        let refunds =
            crate::stake_positions::release_matured_position_tranches(&mut state, release_height)
                .unwrap();
        assert_eq!(refunds.len(), 1);
        assert_eq!(
            state.utxos.get(&refunds[0]).unwrap().output.owner_pubkey,
            pubkey_from_keypair(&cold)
        );

        let incremental_root = state.state_commitment_v2_root(release_height);
        state.rebuild_state_commitment_v2(release_height).unwrap();
        assert_eq!(
            state.state_commitment_v2_root(release_height),
            incremental_root
        );
    }

    #[test]
    fn validator_position_deposits_reject_hot_or_foreign_cold_custody() {
        for (label, owner_kind) in [("hot", 0_u8), ("foreign-cold", 1_u8)] {
            let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
            let hot = keypair(0x89);
            let cold = mixed_keypair(0x8A, 0x8B);
            let foreign_cold = mixed_keypair(0x8C, 0x8D);
            let owner = if owner_kind == 0 {
                pubkey_from_keypair(&hot)
            } else {
                pubkey_from_keypair(&foreign_cold)
            };
            let deposit_id = insert_delegator_utxo(
                &mut state,
                owner,
                MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
                0x8E + owner_kind,
            );
            let op = dual_signed_register_op(
                deposit_id,
                &hot,
                &cold,
                1,
                &state.chain_id,
                test_vrf_public_key(0x8F + owner_kind),
                &indra_crypto::VrfKeypair::from_seed(&[0x8F + owner_kind; 32]),
            );
            let before = state.clone();
            let chain_id = state.chain_id.clone();
            let error = apply_staking_op(&mut state, &op, &chain_id, 1).unwrap_err();
            assert!(
                matches!(error, StateError::InvalidStakingOp(ref message)
                    if message.contains("proposed cold hybrid key")
                        || message.contains("custody authority")),
                "{label}: {error}"
            );
            assert_eq!(state, before, "{label} registration must be atomic");
        }

        for (label, owner_kind) in [("hot", 0_u8), ("foreign-cold", 1_u8)] {
            let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
            let (validator_id, hot) = make_active_validator(&mut state, 0x90);
            let cold = mixed_keypair(0x91, 0x92);
            let foreign_cold = mixed_keypair(0x93, 0x94);
            activate_cold_for_test(&mut state, validator_id, &cold);
            let owner = if owner_kind == 0 {
                pubkey_from_keypair(&hot)
            } else {
                pubkey_from_keypair(&foreign_cold)
            };
            let deposit_id = insert_delegator_utxo(&mut state, owner, 2_000_000, 0x95 + owner_kind);
            let op = cold_self_stake_op(&state, deposit_id, &hot, &cold, 1);
            let before = state.clone();
            let chain_id = state.chain_id.clone();
            let error = apply_staking_op(&mut state, &op, &chain_id, 1).unwrap_err();
            assert!(
                matches!(error, StateError::InvalidStakingOp(ref message) if message.contains("cold key")),
                "{label}: {error}"
            );
            assert_eq!(state, before, "{label} self-stake must be atomic");
        }
    }

    #[test]
    fn self_stake_uses_rotated_current_cold_key() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, hot) = make_active_validator(&mut state, 0x96);
        let old_cold = mixed_keypair(0x97, 0x98);
        let new_cold = mixed_keypair(0x99, 0x9A);
        activate_cold_for_test(&mut state, validator_id, &old_cold);
        let rotate =
            dual_signed_rotate_op(validator_id, &old_cold, &new_cold, 1, 1, &state.chain_id);
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &rotate, &chain_id, 1).unwrap();

        let old_deposit =
            insert_delegator_utxo(&mut state, pubkey_from_keypair(&old_cold), 2_000_000, 0x9B);
        let old_op = cold_self_stake_op(&state, old_deposit, &hot, &new_cold, 1);
        assert!(apply_staking_op(&mut state, &old_op, &chain_id, 2).is_err());
        assert!(state.utxos.contains(&old_deposit));

        let new_deposit =
            insert_delegator_utxo(&mut state, pubkey_from_keypair(&new_cold), 2_000_000, 0x9C);
        let new_op = cold_self_stake_op(&state, new_deposit, &hot, &new_cold, 1);
        apply_staking_op(&mut state, &new_op, &chain_id, 2).unwrap();
        assert!(!state.utxos.contains(&new_deposit));
    }

    #[test]
    fn live_delegate_exit_and_maturity_use_positions_end_to_end() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (validator_id, _) = make_active_validator(&mut state, 0xD1);
        let delegator_keypair = keypair(0xD2);
        let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);
        let delegator_id = delegator_pubkey.identity_id();
        let deposit_id =
            insert_delegator_utxo(&mut state, delegator_pubkey.clone(), 1_000_000, 0xD3);
        let chain_id = state.chain_id.clone();
        let delegate = delegate_op(&state, validator_id, deposit_id, &delegator_keypair, 1);
        apply_staking_op(&mut state, &delegate, &chain_id, 1).unwrap();

        assert!(!state.utxos.contains(&deposit_id));
        let position = state
            .stake_positions
            .values()
            .find(|position| {
                position.validator_id == validator_id && position.principal_owner_id == delegator_id
            })
            .cloned()
            .unwrap();
        assert_eq!(position.active.unwrap().principal_spark, 1_000_000);

        let exit = signed_op(
            StakingOpBody::ExitStakePosition {
                position_id: position.position_id,
                amount_spark: 400_000,
                custody: position.custody,
                cold_authorization: None,
            },
            2,
            &delegator_keypair,
            &chain_id,
        );
        apply_staking_op(&mut state, &exit, &chain_id, 2).unwrap();
        assert_eq!(
            state
                .stake_positions
                .get(&position.position_id)
                .unwrap()
                .active
                .unwrap()
                .principal_spark,
            600_000
        );
        let tranche = state.unbonding_tranches.values().next().cloned().unwrap();
        assert_eq!(tranche.principal_spark, 400_000);
        let indra_core::types::stake_position::UnbondingTimingV1::HeightPrecise {
            end_epoch, ..
        } = tranche.timing;
        let release_height = end_epoch * indra_core::types::primitives::EPOCH_DURATION_BLOCKS;
        let refunds =
            crate::stake_positions::release_matured_position_tranches(&mut state, release_height)
                .unwrap();
        assert_eq!(refunds.len(), 1);
        assert!(state.unbonding_tranches.is_empty());
        assert_eq!(
            state.utxos.get(&refunds[0]).unwrap().output.value_spark,
            400_000
        );
    }

    #[test]
    fn register_validator_with_malformed_vrf_key_poisoning_snapshot_regression() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);

        // Existing test helpers: create a legitimate hot/cold validator identity.
        let hot = mixed_keypair(0xA1, 0xA2);
        let cold = mixed_keypair(0xA3, 0xA4);

        let cold_owner = pubkey_from_keypair(&cold);

        let deposit_utxo_id = insert_delegator_utxo(
            &mut state,
            cold_owner,
            MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
            0xA5,
        );

        // Regression for VRF-001: initial validator registration must reject
        // malformed VRF public keys before they can enter validator state.
        let malformed_vrf_pk = [0u8; 32];

        assert!(
            indra_crypto::validate_vrf_public_key(&malformed_vrf_pk).is_err(),
            "test precondition: chosen VRF key must be invalid"
        );

        let op = dual_signed_register_op(
            deposit_utxo_id,
            &hot,
            &cold,
            1,
            &state.chain_id,
            malformed_vrf_pk,
            &indra_crypto::VrfKeypair::from_seed(&[0xA5; 32]),
        );

        let chain_id = state.chain_id.clone();
        let before = state.clone();

        let err = apply_staking_op(&mut state, &op, &chain_id, 1)
            .expect_err("malformed VRF key must be rejected at registration");

        assert!(
            matches!(err, StateError::InvalidStakingOp(_)),
            "unexpected error type: {err}"
        );

        assert_eq!(
            state, before,
            "failed validator registration must leave state unchanged"
        );
    }

    #[test]
    fn register_validator_rejects_foreign_vrf_key_without_secret_possession() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);

        // Attacker controls these legitimate validator hot/cold identities.
        let attacker_hot = mixed_keypair(0xC1, 0xC2);
        let attacker_cold = mixed_keypair(0xC3, 0xC4);

        let attacker_cold_owner = pubkey_from_keypair(&attacker_cold);

        let deposit_utxo_id = insert_delegator_utxo(
            &mut state,
            attacker_cold_owner,
            MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
            0xC5,
        );

        // This VRF key belongs to a completely independent party.
        // The attacker knows only the public key.
        let victim_vrf_keypair = indra_crypto::VrfKeypair::from_seed(&[0xD1; 32]);

        let victim_vrf_pk = victim_vrf_keypair.public_key();

        // Precondition: unlike VRF-001, this is a perfectly valid VRF key.
        indra_crypto::validate_vrf_public_key(&victim_vrf_pk)
            .expect("victim VRF public key must be valid");

        let op = dual_signed_register_op(
            deposit_utxo_id,
            &attacker_hot,
            &attacker_cold,
            1,
            &state.chain_id,
            victim_vrf_pk,
            &indra_crypto::VrfKeypair::from_seed(&[0xC5; 32]),
        );

        let chain_id = state.chain_id.clone();

        let before = state.clone();
        let error = apply_staking_op(&mut state, &op, &chain_id, 1)
            .expect_err("foreign VRF key without its secret-key proof must be rejected");
        assert!(matches!(error, StateError::InvalidStakingOp(message)
            if message.contains("possession proof is invalid")));
        assert_eq!(
            state, before,
            "failed PoP verification must not mutate state"
        );
    }

    #[test]
    fn register_validator_accepts_correct_vrf_possession_proof() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let hot = mixed_keypair(0xD2, 0xD3);
        let cold = mixed_keypair(0xD4, 0xD5);
        let deposit_utxo_id = insert_delegator_utxo(
            &mut state,
            pubkey_from_keypair(&cold),
            MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
            0xD6,
        );
        let vrf = indra_crypto::VrfKeypair::from_seed(&[0xD7; 32]);
        let op = dual_signed_register_op(
            deposit_utxo_id,
            &hot,
            &cold,
            1,
            &state.chain_id,
            vrf.public_key(),
            &vrf,
        );
        let chain_id = state.chain_id.clone();

        apply_staking_op(&mut state, &op, &chain_id, 1)
            .expect("matching VRF secret-key possession proof must register");
        assert_eq!(
            state
                .validators
                .get(&pubkey_from_keypair(&hot).identity_id())
                .unwrap()
                .vrf_pk,
            Some(vrf.public_key())
        );
    }

    #[test]
    fn register_validator_rejects_vrf_proof_after_public_key_is_altered() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let hot = mixed_keypair(0xD8, 0xD9);
        let cold = mixed_keypair(0xDA, 0xDB);
        let deposit_utxo_id = insert_delegator_utxo(
            &mut state,
            pubkey_from_keypair(&cold),
            MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
            0xDC,
        );
        let original_vrf = indra_crypto::VrfKeypair::from_seed(&[0xDD; 32]);
        let mut op = dual_signed_register_op(
            deposit_utxo_id,
            &hot,
            &cold,
            1,
            &state.chain_id,
            original_vrf.public_key(),
            &original_vrf,
        );
        let altered_vrf = indra_crypto::VrfKeypair::from_seed(&[0xDE; 32]);
        let StakingOpBody::RegisterValidator { vrf_pk, .. } = &mut op.body else {
            unreachable!()
        };
        *vrf_pk = altered_vrf.public_key();
        let chain_id = state.chain_id.clone();
        resign_register_op(&mut op, &hot, &cold, &chain_id);
        let before = state.clone();

        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::InvalidStakingOp(message))
                if message.contains("possession proof is invalid")
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn register_validator_vrf_proof_binds_chain_and_validator_identity_context() {
        for wrong_identity in [false, true] {
            let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
            let hot = mixed_keypair(0xE0, 0xE1);
            let cold = mixed_keypair(0xE2, 0xE3);
            let validator_pubkey = pubkey_from_keypair(&hot);
            let deposit_utxo_id = insert_delegator_utxo(
                &mut state,
                pubkey_from_keypair(&cold),
                MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
                0xE4,
            );
            let vrf = indra_crypto::VrfKeypair::from_seed(&[0xE5; 32]);
            let mut op = dual_signed_register_op(
                deposit_utxo_id,
                &hot,
                &cold,
                1,
                &state.chain_id,
                vrf.public_key(),
                &vrf,
            );
            let wrong_chain = if wrong_identity {
                state.chain_id.as_str()
            } else {
                "indra-wrong-chain"
            };
            let wrong_validator_id = if wrong_identity {
                Bytes32::from([0xE6; 32])
            } else {
                validator_pubkey.identity_id()
            };
            let challenge = StakingOp::vrf_possession_challenge(
                wrong_chain,
                &wrong_validator_id,
                &Bytes32::from(vrf.public_key()),
                0,
            )
            .unwrap();
            let (output, proof) = indra_crypto::vrf_prove(&vrf, &challenge);
            let StakingOpBody::RegisterValidator {
                vrf_possession_output,
                vrf_possession_proof,
                ..
            } = &mut op.body
            else {
                unreachable!()
            };
            *vrf_possession_output = Bytes64(output.0);
            *vrf_possession_proof = VariableBytes::from_slice(&proof.0).unwrap();
            let chain_id = state.chain_id.clone();
            resign_register_op(&mut op, &hot, &cold, &chain_id);
            let before = state.clone();

            assert!(matches!(
                apply_staking_op(&mut state, &op, &chain_id, 1),
                Err(StateError::InvalidStakingOp(message))
                    if message.contains("possession proof is invalid")
            ));
            assert_eq!(state, before);
        }
    }

    #[test]
    fn registry_eviction_ties_prefer_latest_registration_then_larger_id() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (first_id, _) = make_active_validator(&mut state, 0xA1);
        let (second_id, _) = make_active_validator(&mut state, 0xB2);
        state.validators.get_mut(&first_id).unwrap().registered_epoch = 4;
        state.validators.get_mut(&second_id).unwrap().registered_epoch = 5;

        let first = (first_id, 10_000_000_000);
        let second = (second_id, 10_000_000_000);
        assert_eq!(registry_eviction_order(&state, &first, &second), std::cmp::Ordering::Greater);

        state.validators.get_mut(&second_id).unwrap().registered_epoch = 4;
        let (low, high) = if first_id < second_id {
            (first, second)
        } else {
            (second, first)
        };
        assert_eq!(registry_eviction_order(&state, &low, &high), std::cmp::Ordering::Greater);
    }
}
