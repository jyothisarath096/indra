//! Delegation state transitions.
//!
//! Handles apply_delegate, apply_undelegate, apply_claim_rewards,
//! and apply_set_commission. Called from apply_block when a block
//! contains StakingOp entries.

use indra_core::types::{
    crypto::{ColdHybridPubKey, CommitmentV1, HybridPubKey, HybridSignature},
    primitives::{
        Bytes32, VariableBytes, COMMISSION_CHANGE_DELAY_EPOCHS, DUST_LIMIT_SPARK,
        MAX_STAKE_POSITIONS_PER_VALIDATOR, MAX_VALIDATORS, MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
        MIN_COMMISSION_BPS, STAKING_REWARD_BLINDING_DOMAIN, STAKING_TX_IDX,
    },
    staking::{validate_network_addr_string, StakeDepositProof, StakingOp, StakingOpBody},
    transaction::OutputV1,
};
use rand::SeedableRng;

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
    op.validate_structure_at_height(current_height)
        .map_err(|err| StateError::InvalidStakingOp(err.to_string()))?;
    apply_staking_op_with_identity_activation_mode(state, op, chain_id, current_height, true, true)
}

/// Apply an admission-verified staking operation without repeating intrinsic crypto.
///
/// Callers must compare the operation's authority fingerprint with the one
/// captured during full admission verification before using this function.
pub fn apply_verified_staking_op(
    state: &mut ChainState,
    op: &StakingOp,
    chain_id: &str,
    current_height: u64,
) -> StateResult<()> {
    op.validate_structure_at_height(current_height)
        .map_err(|err| StateError::InvalidStakingOp(err.to_string()))?;
    apply_staking_op_with_identity_activation_mode(state, op, chain_id, current_height, true, false)
}

#[cfg(test)]
pub(crate) fn apply_staking_op_with_identity_activation(
    state: &mut ChainState,
    op: &StakingOp,
    chain_id: &str,
    current_height: u64,
    identity_registry_active: bool,
) -> StateResult<()> {
    apply_staking_op_with_identity_activation_mode(
        state,
        op,
        chain_id,
        current_height,
        identity_registry_active,
        true,
    )
}

fn apply_staking_op_with_identity_activation_mode(
    state: &mut ChainState,
    op: &StakingOp,
    chain_id: &str,
    current_height: u64,
    identity_registry_active: bool,
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
        let expected_nonce = state.staking_nonces.get(&signer_id).copied().unwrap_or(0) + 1;
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
            deposit_proof,
        } => apply_delegate(
            state,
            validator_id,
            *deposit_utxo_id,
            delegator_pubkey,
            deposit_proof.as_ref(),
            current_height,
            identity_registry_active,
            Some(MAX_STAKE_POSITIONS_PER_VALIDATOR),
            verify_crypto,
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
            identity_registry_active,
        ),
        StakingOpBody::RegisterValidator {
            commission_bps,
            deposit_utxo_id,
            validator_pubkey,
            vrf_pk,
            deposit_proof,
            cold_pubkey,
            ..
        } => apply_register_validator(
            state,
            *commission_bps,
            *deposit_utxo_id,
            validator_pubkey,
            *vrf_pk,
            deposit_proof.as_ref(),
            cold_pubkey.as_ref(),
            current_height,
            verify_crypto,
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
        StakingOpBody::SelfStake {
            deposit_utxo_id,
            validator_pubkey,
            deposit_proof,
            ..
        } => apply_self_stake(
            state,
            *deposit_utxo_id,
            validator_pubkey,
            deposit_proof.as_ref(),
            current_height,
            identity_registry_active,
            Some(MAX_STAKE_POSITIONS_PER_VALIDATOR),
            verify_crypto,
        ),
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

/// Verify that a stake-deposit opening proof correctly opens the source UTXO
/// commitment to its public `value_spark`.
///
/// This must be called before spending the UTXO so a failed proof leaves
/// spendable state untouched.
pub fn validate_staking_deposit_proof(
    output: &OutputV1,
    proof: &StakeDepositProof,
) -> StateResult<()> {
    use indra_crypto::{verify_opening, PedersenCommitment, PedersenOpening};

    let opening = PedersenOpening {
        value: proof.committed_value_spark,
        blinding: proof.blinding_factor.0,
    };
    verify_opening(
        &PedersenCommitment(output.commitment.compressed_point.0),
        &opening,
    )
    .map_err(|_| StateError::StakeDepositCommitmentMismatch)?;

    if proof.committed_value_spark != output.value_spark {
        return Err(StateError::StakeDepositValueMismatch {
            public_value: output.value_spark,
            committed_value: proof.committed_value_spark,
        });
    }

    Ok(())
}

fn require_and_validate_deposit_proof(
    _current_height: u64,
    output: &OutputV1,
    proof: Option<&StakeDepositProof>,
    verify_crypto: bool,
) -> StateResult<()> {
    match proof {
        Some(proof) if verify_crypto => validate_staking_deposit_proof(output, proof),
        Some(proof) if proof.committed_value_spark != output.value_spark => {
            Err(StateError::StakeDepositValueMismatch {
                public_value: output.value_spark,
                committed_value: proof.committed_value_spark,
            })
        }
        Some(_) => Ok(()),
        None => Err(StateError::DepositProofRequired),
    }
}

fn apply_register_validator(
    state: &mut ChainState,
    commission_bps: u32,
    deposit_utxo_id: Bytes32,
    validator_pubkey: &HybridPubKey,
    vrf_pk: [u8; 32],
    deposit_proof: Option<&StakeDepositProof>,
    cold_pubkey: Option<&ColdHybridPubKey>,
    current_height: u64,
    verify_crypto: bool,
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
    require_and_validate_deposit_proof(
        current_height,
        &utxo_entry.output,
        deposit_proof,
        verify_crypto,
    )?;

    // Bond amount is taken from output.value_spark (public metadata field).
    // This field is not individually proven to match the Pedersen commitment;
    // the transaction-level aggregate balance equation prevents total-value
    // inflation, but individual output commitment binding is not enforced here.
    // See: docs/SECURITY_AUDIT_PHASE4.md ST-03 and Phase 2 T-08.
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
        cold_hybrid_classical_pk: Some(validated_cold_key.classical_pk),
        cold_hybrid_pq_pk: Some(validated_cold_key.pq_pk),
        cold_key_version: validated_cold_key.version,
        cold_nonce: 0,
    };
    state.validators.upsert(entry.clone())?;
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_validator(&entry, current_height);
    }
    let proof = deposit_proof.ok_or_else(|| {
        StateError::InvalidStakingOp("registration position requires a bond opening".into())
    })?;
    crate::stake_positions::deposit_stake_position(
        state,
        validator_id,
        validator_id,
        indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
            validator_id,
        },
        deposit_utxo_id,
        crate::stake_positions::PositionDepositOpeningV1 {
            principal_spark: amount_spark,
            blinding: proof.blinding_factor.0,
        },
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
    candidates.sort_by(|(id_a, stake_a), (id_b, stake_b)| {
        stake_a.cmp(stake_b).then_with(|| id_b.0.cmp(&id_a.0))
    });
    for candidate in candidates {
        if build_evicted_validator_tombstone(state, candidate.0, current_height).is_ok() {
            return Ok(candidate);
        }
    }
    Err(StateError::TombstoneCapacityExceeded)
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
    let vrf = validator
        .vrf_pk
        .ok_or(StateError::TombstoneCapacityExceeded)?;
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
    _legacy_current_epoch: u64,
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
    state.rebuild_state_commitment_v2(current_height);
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
    deposit_proof: Option<&StakeDepositProof>,
    current_height: u64,
    identity_registry_active: bool,
    bond_count_cap: Option<usize>,
    verify_crypto: bool,
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
    require_and_validate_deposit_proof(
        current_height,
        &utxo_entry.output,
        deposit_proof,
        verify_crypto,
    )?;

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

    let proof = deposit_proof.ok_or_else(|| {
        StateError::InvalidStakingOp("position deposit requires a bond opening".into())
    })?;
    crate::stake_positions::deposit_stake_position(
        state,
        *validator_id,
        delegator_id,
        indra_core::types::stake_position::PositionCustodyV1::DelegatorIdentity { delegator_id },
        deposit_utxo_id,
        crate::stake_positions::PositionDepositOpeningV1 {
            principal_spark: amount_spark,
            blinding: proof.blinding_factor.0,
        },
        current_height,
    )?;

    if matches!(identity_outcome, Some(IdentityCheckOutcome::NoPriorRecord)) {
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
    deposit_proof: Option<&StakeDepositProof>,
    current_height: u64,
    identity_registry_active: bool,
    bond_count_cap: Option<usize>,
    verify_crypto: bool,
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
    require_and_validate_deposit_proof(
        current_height,
        &utxo_entry.output,
        deposit_proof,
        verify_crypto,
    )?;

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

    let proof = deposit_proof.ok_or_else(|| {
        StateError::InvalidStakingOp("self-position deposit requires a bond opening".into())
    })?;
    crate::stake_positions::deposit_stake_position(
        state,
        validator_id,
        validator_id,
        indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
            validator_id,
        },
        deposit_utxo_id,
        crate::stake_positions::PositionDepositOpeningV1 {
            principal_spark: amount_spark,
            blinding: proof.blinding_factor.0,
        },
        current_height,
    )?;
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
    if matches!(identity_outcome, Some(IdentityCheckOutcome::NoPriorRecord)) {
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
    use indra_core::types::{
        crypto::{ColdHybridPubKey, CommitmentV1, HybridPubKey, HybridSignature},
        primitives::VariableBytes,
        transaction::OutputV1,
    };
    use indra_crypto::{
        commit,
        hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
        prove_range,
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

    fn deposit_proof(value_spark: u64, seed: u8) -> StakeDepositProof {
        StakeDepositProof {
            committed_value_spark: value_spark,
            blinding_factor: Bytes32::from([seed; 32]),
        }
    }

    fn proof_for_bond_utxo(state: &ChainState, deposit_utxo_id: Bytes32) -> StakeDepositProof {
        let Some(entry) = state.utxos.get(&deposit_utxo_id) else {
            return deposit_proof(0, 0);
        };
        for seed in 0u8..=u8::MAX {
            let candidate = commit(entry.output.value_spark, &[seed; 32]);
            if candidate.0 == entry.output.commitment.compressed_point.0 {
                return deposit_proof(entry.output.value_spark, seed);
            }
        }
        deposit_proof(entry.output.value_spark, 0)
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

    fn insert_self_stake_utxo(
        state: &mut ChainState,
        hot_pubkey: HybridPubKey,
        value_spark: u64,
        seed: u8,
    ) -> Bytes32 {
        insert_registration_utxo(state, hot_pubkey, value_spark, seed)
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

    fn insert_mismatched_self_stake_utxo(
        state: &mut ChainState,
        hot_pubkey: HybridPubKey,
        public_value_spark: u64,
        committed_value_spark: u64,
        seed: u8,
    ) -> Bytes32 {
        let cold = derived_test_cold_keypair_from_classical(&hot_pubkey.classical_pk.0);
        insert_mismatched_public_value_utxo(
            state,
            pubkey_from_keypair(&cold),
            public_value_spark,
            committed_value_spark,
            seed,
        )
    }

    fn insert_mismatched_registration_utxo(
        state: &mut ChainState,
        hot_pubkey: HybridPubKey,
        public_value_spark: u64,
        committed_value_spark: u64,
        seed: u8,
    ) -> Bytes32 {
        insert_mismatched_self_stake_utxo(
            state,
            hot_pubkey,
            public_value_spark,
            committed_value_spark,
            seed,
        )
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
                *cold_authorization = Some(indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 1,
                    cold_nonce: nonce,
                });
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
            *cold_pubkey = Some(cold_pubkey_from_keypair(&cold_keypair));
            *cold_signature = Some(dummy_signature());
            let message = op
                .register_validator_dual_signing_bytes(chain_id)
                .unwrap()
                .unwrap();
            op.signature = wire_signature(&keypair.sign(&message).unwrap());
            let cold_sig = wire_signature(&cold_keypair.sign(&message).unwrap());
            let StakingOpBody::RegisterValidator { cold_signature, .. } = &mut op.body else {
                unreachable!()
            };
            *cold_signature = Some(cold_sig);
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
        bond_seed: u8,
    ) -> StakingOp {
        let mut op = StakingOp {
            body: StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                deposit_utxo_id,
                validator_pubkey: pubkey_from_keypair(hot_keypair),
                vrf_pk,
                deposit_proof: Some(deposit_proof(MINIMUM_VALIDATOR_SELF_STAKE_SPARK, bond_seed)),
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
        let validator_id = pubkey_to_id(&pubkey);
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
            cold_hybrid_classical_pk: Some(cold.classical.0),
            cold_hybrid_pq_pk: Some(cold.pq.0),
            cold_key_version: 1,
            cold_nonce: 0,
        };
        state.validators.upsert(entry).unwrap();
    }

    #[test]
    fn staking_deposit_proof_accepts_correct_opening() {
        let owner = pubkey_from_keypair(&keypair(0xE1));
        let output = test_output(1_000, owner, 0xE1);
        assert!(validate_staking_deposit_proof(&output, &deposit_proof(1_000, 0xE1)).is_ok());
    }

    #[test]
    fn staking_deposit_proof_rejects_wrong_blinding() {
        let owner = pubkey_from_keypair(&keypair(0xE2));
        let output = test_output(1_000, owner, 0xE2);
        assert_eq!(
            validate_staking_deposit_proof(&output, &deposit_proof(1_000, 0xE3)),
            Err(StateError::StakeDepositCommitmentMismatch)
        );
    }

    #[test]
    fn staking_deposit_proof_rejects_committed_value_mismatch() {
        let owner = pubkey_from_keypair(&keypair(0xE4));
        let output = test_output(1_000, owner, 0xE4);
        assert_eq!(
            validate_staking_deposit_proof(&output, &deposit_proof(999, 0xE4)),
            Err(StateError::StakeDepositCommitmentMismatch)
        );
    }

    fn delegate_op(
        state: &ChainState,
        validator_id: Bytes32,
        deposit_utxo_id: Bytes32,
        delegator_keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        let deposit_proof = proof_for_bond_utxo(state, deposit_utxo_id);
        signed_op(
            StakingOpBody::Delegate {
                validator_id,
                deposit_utxo_id,
                delegator_pubkey: pubkey_from_keypair(delegator_keypair),
                deposit_proof: Some(deposit_proof),
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
        let deposit_proof = proof_for_bond_utxo(state, deposit_utxo_id);
        signed_op(
            StakingOpBody::SelfStake {
                deposit_utxo_id,
                validator_pubkey: pubkey_from_keypair(validator_keypair),
                deposit_proof: Some(deposit_proof),
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
    fn delegate_without_proof_fails_at_activation() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&delegator_keypair);
        let deposit_utxo_id = insert_delegator_utxo(&mut state, pubkey, 1_000_000, 0x18);

        let op = signed_op(
            StakingOpBody::Delegate {
                validator_id,
                deposit_utxo_id,
                delegator_pubkey: pubkey_from_keypair(&delegator_keypair),
                deposit_proof: None,
            },
            1,
            &delegator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::DepositProofRequired)
        );
        assert!(state.utxos.contains(&deposit_utxo_id));
    }

    #[test]
    fn register_validator_rejects_mismatched_public_value_commitment() {
        let mut state = ChainState::new_genesis();
        let validator_keypair = keypair(0x20);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let validator_id = pubkey_to_id(&validator_pubkey);
        let deposit_utxo_id = insert_mismatched_registration_utxo(
            &mut state,
            validator_pubkey.clone(),
            MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
            MINIMUM_VALIDATOR_SELF_STAKE_SPARK / 2,
            0x21,
        );

        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                deposit_utxo_id,
                validator_pubkey,
                vrf_pk: [0x20; 32],
                deposit_proof: Some(deposit_proof(MINIMUM_VALIDATOR_SELF_STAKE_SPARK / 2, 0x21)),
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
            Err(StateError::StakeDepositValueMismatch {
                public_value: MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
                committed_value: MINIMUM_VALIDATOR_SELF_STAKE_SPARK / 2,
            })
        );
        assert!(state.utxos.contains(&deposit_utxo_id));
        assert!(state.validators.get(&validator_id).is_none());
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
        let deposit_utxo_id = insert_delegator_utxo(&mut state, wrong_owner, 1_000_000, 0x11);

        let op = delegate_op(&state, validator_id, deposit_utxo_id, &delegator_keypair, 1);
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
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
        let deposit_utxo_id = insert_delegator_utxo(&mut state, pubkey, 1_000_000, 0x13);

        let op = delegate_op(&state, validator_id, deposit_utxo_id, &delegator_keypair, 1);
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::InvalidStakingOp(_))
        ));
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
        let deposit_utxo_id = insert_delegator_utxo(&mut state, legitimate_pubkey, 2_000_000, 0x54);
        let op = signed_op(
            StakingOpBody::SelfStake {
                deposit_utxo_id,
                validator_pubkey: attacker_pubkey,
                deposit_proof: Some(deposit_proof(2_000_000, 0x54)),
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
        let deposit_utxo_id = insert_delegator_utxo(&mut state, legitimate_pubkey, 2_000_000, 0x58);
        let op = self_stake_op(&state, deposit_utxo_id, &legitimate_keypair, 1);
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
    fn self_stake_without_proof_fails_at_activation() {
        let mut state = ChainState::new_genesis();
        let (_, validator_keypair) = make_active_validator(&mut state, 0x01);
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let deposit_utxo_id = insert_self_stake_utxo(&mut state, pubkey.clone(), 2_000_000, 0x3B);
        let op = signed_op(
            StakingOpBody::SelfStake {
                deposit_utxo_id,
                validator_pubkey: pubkey,
                deposit_proof: None,
                cold_authorization: None,
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::DepositProofRequired)
        );
        assert!(state.utxos.contains(&deposit_utxo_id));
    }

    #[test]
    fn self_stake_mismatch_does_not_spend_utxo() {
        let mut state = ChainState::new_genesis();
        let (_, validator_keypair) = make_active_validator(&mut state, 0x01);
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let deposit_utxo_id = insert_self_stake_utxo(&mut state, pubkey.clone(), 2_000_000, 0x3C);
        let op = signed_op(
            StakingOpBody::SelfStake {
                deposit_utxo_id,
                validator_pubkey: pubkey,
                deposit_proof: Some(deposit_proof(2_000_000, 0x3D)),
                cold_authorization: None,
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id, 1),
            Err(StateError::StakeDepositCommitmentMismatch)
        );
        assert!(state.utxos.contains(&deposit_utxo_id));
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
        let mut state = ChainState::new_genesis();
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
        let mut state = ChainState::new_genesis();
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
        let mut state = ChainState::new_genesis();
        let (_, validator_keypair) = make_active_validator(&mut state, 0x01);
        let wrong_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&validator_keypair);
        let deposit_utxo_id = insert_delegator_utxo(&mut state, pubkey.clone(), 2_000_000, 0x36);
        let op = signed_op(
            StakingOpBody::SelfStake {
                deposit_utxo_id,
                validator_pubkey: pubkey,
                deposit_proof: Some(deposit_proof(2_000_000, 0x36)),
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
    fn apply_staking_op_rejects_wrong_nonce() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let op = signed_op(
            StakingOpBody::Delegate {
                validator_id,
                deposit_utxo_id: Bytes32::from([0x31; 32]),
                delegator_pubkey: pubkey_from_keypair(&delegator_keypair),
                deposit_proof: None,
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
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let wrong_keypair = keypair(0x03);
        let op = signed_op(
            StakingOpBody::Delegate {
                validator_id,
                deposit_utxo_id: Bytes32::from([0x32; 32]),
                delegator_pubkey: pubkey_from_keypair(&delegator_keypair),
                deposit_proof: None,
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
        let deposit_utxo_id = insert_registration_utxo(
            &mut state,
            validator_pubkey.clone(),
            MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
            0xB2,
        );
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                deposit_utxo_id,
                validator_pubkey,
                vrf_pk: [0xB2; 32],
                deposit_proof: Some(deposit_proof(MINIMUM_VALIDATOR_SELF_STAKE_SPARK, 0xB2)),
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
    fn registration_without_bond_is_rejected() {
        let mut state = ChainState::new_genesis();
        let validator_keypair = keypair(0x44);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                deposit_utxo_id: Bytes32::from([0xFE; 32]),
                validator_pubkey,
                vrf_pk: [0x44; 32],
                deposit_proof: None,
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
        let deposit_utxo_id = insert_registration_utxo(
            &mut state,
            validator_pubkey.clone(),
            MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
            0xAB,
        );
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                deposit_utxo_id,
                validator_pubkey,
                vrf_pk: [0x4E; 32],
                deposit_proof: None,
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
            Err(StateError::DepositProofRequired)
        );
        assert!(state.utxos.contains(&deposit_utxo_id));
    }

    #[test]
    fn registration_with_bond_below_minimum_is_rejected() {
        let mut state = ChainState::new_genesis();
        let validator_keypair = keypair(0x45);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let deposit_utxo_id = insert_registration_utxo(
            &mut state,
            validator_pubkey.clone(),
            MINIMUM_VALIDATOR_SELF_STAKE_SPARK - 1,
            0xA2,
        );
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                deposit_utxo_id,
                validator_pubkey,
                vrf_pk: [0x45; 32],
                deposit_proof: Some(deposit_proof(MINIMUM_VALIDATOR_SELF_STAKE_SPARK - 1, 0xA2)),
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
        let validator_id = pubkey_to_id(&pubkey_from_keypair(&hot));
        let op = dual_signed_register_op(
            deposit_utxo_id,
            &hot,
            &cold,
            1,
            &state.chain_id,
            [bond_seed.wrapping_add(1); 32],
            bond_seed,
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
        let validator_id = pubkey_to_id(&pubkey_from_keypair(hot));
        let cold_key_version = state
            .validators
            .get(&validator_id)
            .expect("self-stake validator")
            .cold_key_version;
        cold_signed_op(
            StakingOpBody::SelfStake {
                deposit_utxo_id,
                validator_pubkey: pubkey_from_keypair(hot),
                deposit_proof: Some(proof_for_bond_utxo(state, deposit_utxo_id)),
                cold_authorization: Some(indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version,
                    cold_nonce,
                }),
            },
            cold,
            &state.chain_id,
        )
    }

    #[test]
    fn register_validator_accepts_distinct_hot_and_cold_custody() {
        let mut state = ChainState::new_genesis();
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
        let mut state = ChainState::new_genesis();
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
        state.rebuild_state_commitment_v2(release_height);
        assert_eq!(
            state.state_commitment_v2_root(release_height),
            incremental_root
        );
    }

    #[test]
    fn validator_position_deposits_reject_hot_or_foreign_cold_custody() {
        for (label, owner_kind) in [("hot", 0_u8), ("foreign-cold", 1_u8)] {
            let mut state = ChainState::new_genesis();
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
                [0x8F + owner_kind; 32],
                0x8E + owner_kind,
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
            let mut state = ChainState::new_genesis();
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
        let mut state = ChainState::new_genesis();
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
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0xD1);
        let delegator_keypair = keypair(0xD2);
        let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
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
}
