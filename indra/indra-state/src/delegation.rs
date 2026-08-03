//! Delegation state transitions.
//!
//! Handles apply_delegate, apply_undelegate, apply_claim_rewards,
//! and apply_set_commission. Called from apply_block when a block
//! contains StakingOp entries.

use indra_core::types::{
    crypto::{ColdHybridPubKey, CommitmentV1, HybridPubKey, HybridSignature},
    primitives::{
        Bytes32, VariableBytes, COMMISSION_CHANGE_DELAY_EPOCHS, DUST_LIMIT_SPARK,
        MAX_LIVE_BONDS_PER_VALIDATOR, MAX_VALIDATORS, MINIMUM_ACTIVE_SELF_STAKE_SPARK,
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
        validate_new_validator_cold_key, validate_validator_cold_key, DelegationReturnEvent,
        DelegationReturnReason, EvictedBondReferenceV1, EvictedColdCustodyV1,
        EvictedValidatorTombstoneV1, StakeBondCustodyOwner, StakeBondEntry, ValidatorEntry,
        ValidatorStatus, MAX_ATOMIC_COLD_KEY_MIGRATION_SELF_BONDS, MAX_DELEGATORS_PER_VALIDATOR,
        MAX_RETAINED_BOND_REFERENCES_PER_TOMBSTONE, MAX_TOTAL_RETAINED_BOND_REFERENCES,
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
    apply_staking_op_with_identity_activation(state, op, chain_id, current_height, true)
}

pub(crate) fn apply_staking_op_with_identity_activation(
    state: &mut ChainState,
    op: &StakingOp,
    chain_id: &str,
    current_height: u64,
    identity_registry_active: bool,
) -> StateResult<()> {
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
        StakingOpBody::ClaimRewards { .. }
        | StakingOpBody::SetCommission { .. }
        | StakingOpBody::SelfStake { .. }
        | StakingOpBody::SelfUnstake { .. }
        | StakingOpBody::SetAutoDelegate { .. } => {}
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
            true,
            Some(MAX_LIVE_BONDS_PER_VALIDATOR),
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
            true,
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
            Some(MAX_LIVE_BONDS_PER_VALIDATOR),
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
    _current_height: u64,
    output: &OutputV1,
    proof: Option<&StakingBondProof>,
) -> StateResult<()> {
    match proof {
        Some(proof) => validate_staking_bond_proof(output, proof),
        None => Err(StateError::BondProofRequired),
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
    let owner_matches = utxo_entry.output.owner_pubkey.classical_pk.0
        == validated_cold_key.classical_pk
        && utxo_entry.output.owner_pubkey.pq_pk.as_slice() == validated_cold_key.pq_pk.as_slice();
    if !owner_matches {
        return Err(StateError::InvalidStakingOp(
            "registration bond UTXO is not owned by the proposed cold hybrid key".into(),
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
        cold_hybrid_classical_pk: Some(validated_cold_key.classical_pk),
        cold_hybrid_pq_pk: Some(validated_cold_key.pq_pk),
        cold_key_version: validated_cold_key.version,
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
    bond.custody_owner = StakeBondCustodyOwner::ValidatorColdIdentity(validator_id);
    state.staked_bonds.insert(bond_utxo_id, bond.clone());
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_staked_bond(&bond_utxo_id, &bond);
    }
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
) -> StateResult<EvictedValidatorTombstoneV1> {
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
    let mut bonds: Vec<StakeBondEntry> = state
        .staked_bonds
        .values()
        .filter(|bond| bond.validator_id == validator_id)
        .cloned()
        .collect();
    bonds.sort_by_key(|bond| bond.utxo_id.0);
    if bonds.is_empty() || bonds.len() > MAX_RETAINED_BOND_REFERENCES_PER_TOMBSTONE {
        return Err(StateError::TombstoneCapacityExceeded);
    }
    let existing_references: usize = state
        .evicted_validator_tombstones
        .values()
        .map(|tombstone| tombstone.retained_bonds.len())
        .sum();
    if existing_references
        .checked_add(bonds.len())
        .is_none_or(|total| total > MAX_TOTAL_RETAINED_BOND_REFERENCES)
    {
        return Err(StateError::TombstoneCapacityExceeded);
    }
    let requires_cold = bonds.iter().any(|bond| {
        matches!(
            bond.custody_owner,
            StakeBondCustodyOwner::ValidatorColdIdentity(id) if id == validator_id
        )
    });
    let cold_custody = if requires_cold {
        Some(EvictedColdCustodyV1 {
            classical_pk: validator
                .cold_hybrid_classical_pk
                .ok_or(StateError::TombstoneCapacityExceeded)?,
            pq_pk: validator
                .cold_hybrid_pq_pk
                .ok_or(StateError::TombstoneCapacityExceeded)?,
            key_version: validator.cold_key_version,
        })
    } else {
        None
    };
    if let Some(cold) = &cold_custody {
        indra_crypto::validate_classical_public_key(&indra_crypto::ClassicalPublicKey(
            cold.classical_pk,
        ))
        .map_err(|_| StateError::TombstoneCapacityExceeded)?;
        indra_crypto::validate_pq_public_key(&indra_crypto::PqPublicKey(cold.pq_pk))
            .map_err(|_| StateError::TombstoneCapacityExceeded)?;
    }
    let current_epoch = epoch_for_height(current_height);
    let unbonding_end = current_epoch
        .checked_add(UNBONDING_PERIOD_EPOCHS)
        .ok_or(StateError::TombstoneCapacityExceeded)?;
    let retained_bonds = bonds
        .iter()
        .map(|bond| EvictedBondReferenceV1 {
            bond_utxo_id: bond.utxo_id,
            delegator_id: bond.delegator_id,
            unbonding_end_epoch: bond.unbonding_end_epoch.unwrap_or(unbonding_end),
        })
        .collect();
    Ok(EvictedValidatorTombstoneV1 {
        validator_id,
        eviction_height: current_height,
        eviction_epoch: current_epoch,
        last_classical_vote_pk: classical,
        last_pq_vote_pk: pq,
        last_vrf_pk: vrf,
        cold_custody,
        retained_bonds,
    })
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
    let current_epoch = epoch_for_height(current_height);
    let tombstone = build_evicted_validator_tombstone(state, validator_id, current_height)?;
    let validator = state
        .validators
        .get(&validator_id)
        .cloned()
        .ok_or(StateError::ValidatorNotFound)?;
    let delegators = state.delegations.get_delegators(&validator_id).to_vec();
    let validator_reward_owner = validator_public_key(&validator)?;
    let mut delegator_reward_owners = Vec::with_capacity(delegators.len());
    for entry in &delegators {
        let owner = if entry.pending_rewards >= DUST_LIMIT_SPARK {
            let bond = state
                .staked_bonds
                .values()
                .find(|bond| {
                    bond.validator_id == validator_id && bond.delegator_id == entry.delegator_id
                })
                .ok_or(StateError::InvariantViolation {
                    message: "delegator reward has no retained bond during tombstone preflight",
                })?;
            Some(resolve_bond_owner_pubkey(bond, state).map_err(|_| {
                StateError::InvariantViolation {
                    message:
                        "delegator reward owner could not be resolved during tombstone preflight",
                }
            })?)
        } else {
            None
        };
        delegator_reward_owners.push(owner);
    }
    if validator.pending_rewards > 0 {
        payout_or_burn_pending_reward(
            state,
            &validator_id,
            &validator_id,
            validator.pending_rewards,
            validator_reward_owner,
            current_height,
        )?;
    }
    for (entry, preflight_owner) in delegators.iter().zip(delegator_reward_owners) {
        if entry.pending_rewards == 0 {
            continue;
        }
        if let Some(owner) = preflight_owner {
            payout_or_burn_pending_reward(
                state,
                &validator_id,
                &entry.delegator_id,
                entry.pending_rewards,
                owner,
                current_height,
            )?;
        } else if entry.pending_rewards >= DUST_LIMIT_SPARK {
            return Err(StateError::InvariantViolation {
                message: "delegator reward could not be paid during tombstone eviction",
            });
        }
    }
    let removed_delegators = state.delegations.take_delegators(&validator_id);
    debug_assert_eq!(removed_delegators, delegators);
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        for entry in &delegators {
            commitment.delete_delegator(&validator_id, &entry.delegator_id);
        }
    }
    let unbonding_end = current_epoch.checked_add(UNBONDING_PERIOD_EPOCHS).ok_or(
        StateError::InvariantViolation {
            message: "eviction unbonding epoch overflow",
        },
    )?;
    for reference in &tombstone.retained_bonds {
        let mut bond = state
            .staked_bonds
            .get(&reference.bond_utxo_id)
            .cloned()
            .ok_or(StateError::InvariantViolation {
                message: "preflighted eviction bond disappeared",
            })?;
        if bond.unbonding_end_epoch.is_none() {
            bond.begin_unbonding(current_height, unbonding_end)?;
        }
        let updated = bond.clone();
        state
            .staked_bonds
            .insert(reference.bond_utxo_id, updated.clone());
        if let Some(commitment) = state.state_commitment_v2.as_mut() {
            commitment.put_staked_bond(&reference.bond_utxo_id, &updated);
        }
    }
    state.validators.remove(&validator_id);
    state
        .evicted_validator_tombstones
        .insert(validator_id, tombstone.clone());
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.delete_validator(&validator_id);
        commitment.put_evicted_validator_tombstone(&tombstone);
    }
    Ok(())
}

fn validator_public_key(validator: &ValidatorEntry) -> StateResult<HybridPubKey> {
    let classical_pk =
        validator
            .cold_hybrid_classical_pk
            .ok_or(StateError::InvariantViolation {
                message: "validator missing cold classical key during eviction payout",
            })?;
    let pq_bytes = validator
        .cold_hybrid_pq_pk
        .ok_or(StateError::InvariantViolation {
            message: "validator missing cold PQ key during eviction payout",
        })?;
    Ok(HybridPubKey {
        classical_pk: Bytes32::from(classical_pk),
        pq_pk: VariableBytes::from_slice(&pq_bytes).map_err(|_| {
            StateError::InvariantViolation {
                message: "validator cold PQ key too large during eviction payout",
            }
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
fn enforce_validator_bond_capacity(
    state: &ChainState,
    validator_id: &Bytes32,
    cap: Option<usize>,
) -> StateResult<()> {
    let Some(cap) = cap else {
        return Ok(());
    };
    let count = state
        .staked_bonds
        .values()
        .filter(|bond| bond.validator_id == *validator_id)
        .take(cap)
        .count();
    if validator_bond_capacity_reached(count, cap) {
        return Err(StateError::ValidatorBondCountAtMaximum {
            validator_id: *validator_id,
            max: cap,
        });
    }
    Ok(())
}

#[inline]
fn validator_bond_capacity_reached(count: usize, cap: usize) -> bool {
    count >= cap
}

fn apply_delegate(
    state: &mut ChainState,
    validator_id: &Bytes32,
    bond_utxo_id: Bytes32,
    delegator_pubkey: &HybridPubKey,
    bond_proof: Option<&StakingBondProof>,
    current_height: u64,
    identity_registry_active: bool,
    bond_accounting_active: bool,
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
    enforce_validator_bond_capacity(state, validator_id, bond_count_cap)?;
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
    if bond_accounting_active {
        reconcile_delegator_from_bonds(state, validator_id, &delegator_id);
    }
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
    bond_accounting_active: bool,
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
    bond.begin_unbonding(current_height, unbonding_end)?;
    let amount_spark = bond.amount_spark;
    let updated_bond = bond.clone();
    state
        .staked_bonds
        .insert(bond_utxo_id, updated_bond.clone());
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_staked_bond(&bond_utxo_id, &updated_bond);
    }

    if bond_accounting_active {
        let active_stake_spark = active_delegated_bond_stake(state, validator_id, &delegator_id);
        state
            .delegations
            .begin_undelegate_from_bonds(
                validator_id,
                &delegator_id,
                active_stake_spark,
                unbonding_end,
            )
            .map_err(|e| StateError::InvalidStakingOp(e.into()))?;
    } else {
        state
            .delegations
            .begin_undelegate(validator_id, &delegator_id, amount_spark, unbonding_end)
            .map_err(|e| StateError::InvalidStakingOp(e.into()))?;
    }
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

pub(crate) fn active_delegated_bond_stake(
    state: &ChainState,
    validator_id: &Bytes32,
    delegator_id: &Bytes32,
) -> u64 {
    state
        .staked_bonds
        .values()
        .filter(|bond| {
            bond.validator_id == *validator_id
                && bond.delegator_id == *delegator_id
                && bond.validator_id != bond.delegator_id
                && bond.unbonding_end_epoch.is_none()
        })
        .fold(0u64, |sum, bond| sum.saturating_add(bond.amount_spark))
}

pub(crate) fn reconcile_delegator_from_bonds(
    state: &mut ChainState,
    validator_id: &Bytes32,
    delegator_id: &Bytes32,
) {
    let mut active = 0u64;
    let mut latest_unbonding_end = None;
    let mut has_any = false;
    for bond in state.staked_bonds.values().filter(|bond| {
        bond.validator_id == *validator_id
            && bond.delegator_id == *delegator_id
            && bond.validator_id != bond.delegator_id
    }) {
        has_any = true;
        match bond.unbonding_end_epoch {
            None => active = active.saturating_add(bond.amount_spark),
            Some(end) => {
                latest_unbonding_end =
                    Some(latest_unbonding_end.map_or(end, |old: u64| old.max(end)))
            }
        }
    }
    state.delegations.reconcile_from_bonds(
        validator_id,
        delegator_id,
        active,
        latest_unbonding_end,
        has_any,
    );
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        if let Some(entry) = state
            .delegations
            .get_delegators(validator_id)
            .iter()
            .find(|entry| entry.delegator_id == *delegator_id)
        {
            commitment.put_delegator(validator_id, entry);
        } else {
            commitment.delete_delegator(validator_id, delegator_id);
        }
    }
}

/// Bond a validator-owned UTXO as validator self-stake.
fn apply_self_stake(
    state: &mut ChainState,
    bond_utxo_id: Bytes32,
    validator_pubkey: &HybridPubKey,
    bond_proof: Option<&StakingBondProof>,
    current_height: u64,
    identity_registry_active: bool,
    bond_count_cap: Option<usize>,
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
    enforce_validator_bond_capacity(state, &validator_id, bond_count_cap)?;

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
    let cold_owner = resolve_active_validator_cold_pubkey(state, &validator_id)
        .map_err(identity_error_to_state_error)?;
    if utxo_entry.output.owner_pubkey != cold_owner {
        return Err(StateError::InvalidStakingOp(
            "self-stake UTXO is not owned by the validator's cold key".into(),
        ));
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
    bond.custody_owner = StakeBondCustodyOwner::ValidatorColdIdentity(validator_id);
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
    bond.begin_unbonding(current_height, unbonding_end)?;
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
    let payout_pubkey = if claim_from_validator {
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
            | StakingOpBody::SelfUnstake {
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
            _ => {}
        }
        let cold_designated = matches!(
            &body,
            StakingOpBody::SetCommission { .. }
                | StakingOpBody::SelfStake { .. }
                | StakingOpBody::SelfUnstake { .. }
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
        let bond_utxo_id = insert_mismatched_registration_utxo(
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
        let bond_utxo_id = insert_mismatched_self_stake_utxo(
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
    fn per_bond_accounting_preserves_active_remainder_and_allows_later_exit() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x81);
        let delegator_keypair = keypair(0x82);
        let pubkey = pubkey_from_keypair(&delegator_keypair);
        let delegator_id = pubkey_to_id(&pubkey);
        let bond_60 = insert_delegator_utxo(&mut state, pubkey.clone(), 60_000_000, 0x83);
        let bond_40 = insert_delegator_utxo(&mut state, pubkey.clone(), 40_000_000, 0x84);
        let chain_id = state.chain_id.clone();
        for (nonce, bond) in [(1, bond_60), (2, bond_40)] {
            let op = delegate_op(&state, validator_id, bond, &delegator_keypair, nonce);
            apply_staking_op(&mut state, &op, &chain_id, 1).unwrap();
        }

        apply_undelegate(&mut state, &validator_id, bond_40, &pubkey, 2, false, true).unwrap();
        let entry = state
            .delegations
            .get_delegators(&validator_id)
            .iter()
            .find(|entry| entry.delegator_id == delegator_id)
            .unwrap();
        assert_eq!(entry.staked_spark, 60_000_000);
        assert_eq!(entry.unbonding_end_epoch, None);
        assert_eq!(state.delegations.total_delegated(&validator_id), 60_000_000);

        // A fresh bond is aggregated as active rather than inheriting a stale
        // lifecycle flag from the independently-unbonding bond.
        let bond_20 = insert_delegator_utxo(&mut state, pubkey.clone(), 20_000_000, 0x85);
        let op = delegate_op(&state, validator_id, bond_20, &delegator_keypair, 3);
        let StakingOpBody::Delegate {
            bond_proof,
            delegator_pubkey,
            ..
        } = &op.body
        else {
            unreachable!()
        };
        apply_delegate(
            &mut state,
            &validator_id,
            bond_20,
            delegator_pubkey,
            bond_proof.as_ref(),
            3,
            false,
            true,
            None,
        )
        .unwrap();
        assert_eq!(
            active_delegated_bond_stake(&state, &validator_id, &delegator_id),
            80_000_000
        );
        assert_eq!(
            state
                .delegations
                .get_delegators(&validator_id)
                .iter()
                .find(|entry| entry.delegator_id == delegator_id)
                .unwrap()
                .unbonding_end_epoch,
            None
        );

        // The original still-active bond can independently begin unbonding.
        apply_undelegate(&mut state, &validator_id, bond_60, &pubkey, 4, false, true).unwrap();
        assert_eq!(
            active_delegated_bond_stake(&state, &validator_id, &delegator_id),
            20_000_000
        );
    }

    #[test]
    fn live_bond_cap_does_not_block_exit_or_maturity_paths() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0xA1);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let delegator_keypair = keypair(0xA2);
        let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);

        let delegated_bond =
            insert_delegator_utxo(&mut state, delegator_pubkey.clone(), 1_000_000, 0xA3);
        let delegate = delegate_op(&state, validator_id, delegated_bond, &delegator_keypair, 1);
        let StakingOpBody::Delegate { bond_proof, .. } = &delegate.body else {
            unreachable!()
        };
        apply_delegate(
            &mut state,
            &validator_id,
            delegated_bond,
            &delegator_pubkey,
            bond_proof.as_ref(),
            1,
            false,
            true,
            Some(2),
        )
        .unwrap();

        let self_bond =
            insert_self_stake_utxo(&mut state, validator_pubkey.clone(), 1_000_000, 0xA4);
        let self_stake = self_stake_op(&state, self_bond, &validator_keypair, 1);
        let StakingOpBody::SelfStake { bond_proof, .. } = &self_stake.body else {
            unreachable!()
        };
        apply_self_stake(
            &mut state,
            self_bond,
            &validator_pubkey,
            bond_proof.as_ref(),
            1,
            false,
            Some(2),
        )
        .unwrap();
        assert!(matches!(
            enforce_validator_bond_capacity(&state, &validator_id, Some(2)),
            Err(StateError::ValidatorBondCountAtMaximum { max: 2, .. })
        ));

        // The cap is creation-only: both exit paths remain available at the
        // limit and normal maturity removes the records so capacity recovers.
        apply_undelegate(
            &mut state,
            &validator_id,
            delegated_bond,
            &delegator_pubkey,
            2,
            false,
            true,
        )
        .unwrap();
        apply_self_unstake(&mut state, self_bond, &validator_pubkey, 2, false).unwrap();
        state
            .delegator_identities
            .insert(pubkey_to_id(&delegator_pubkey), delegator_pubkey.clone());
        crate::epoch::release_unbonded_bonds_at_height(&mut state, UNBONDING_PERIOD_EPOCHS, 2)
            .unwrap();
        assert!(!state.staked_bonds.contains_key(&delegated_bond));
        assert!(!state.staked_bonds.contains_key(&self_bond));
        assert!(enforce_validator_bond_capacity(&state, &validator_id, Some(2)).is_ok());
    }

    #[test]
    fn live_bond_cap_replay_is_deterministic_across_activation_modes() {
        fn replay() -> (Vec<u8>, Bytes32) {
            let mut state = ChainState::new_genesis();
            let (validator_id, _) = make_active_validator(&mut state, 0xB1);
            let delegator_keypair = keypair(0xB2);
            let delegator_pubkey = pubkey_from_keypair(&delegator_keypair);

            // Legacy/pre-gate mode permits creation without consulting a cap.
            for (nonce, seed) in [(1, 0xB3), (2, 0xB4)] {
                let bond =
                    insert_delegator_utxo(&mut state, delegator_pubkey.clone(), 1_000_000, seed);
                let op = delegate_op(&state, validator_id, bond, &delegator_keypair, nonce);
                let StakingOpBody::Delegate { bond_proof, .. } = &op.body else {
                    unreachable!()
                };
                apply_delegate(
                    &mut state,
                    &validator_id,
                    bond,
                    &delegator_pubkey,
                    bond_proof.as_ref(),
                    nonce,
                    false,
                    true,
                    None,
                )
                .unwrap();
            }

            // Post-gate mode deterministically rejects the next creation when
            // the test-sized limit is reached, without altering consensus state.
            let rejected_bond =
                insert_delegator_utxo(&mut state, delegator_pubkey.clone(), 1_000_000, 0xB5);
            let rejected = delegate_op(&state, validator_id, rejected_bond, &delegator_keypair, 3);
            let before = state.clone();
            let StakingOpBody::Delegate { bond_proof, .. } = &rejected.body else {
                unreachable!()
            };
            assert!(matches!(
                apply_delegate(
                    &mut state,
                    &validator_id,
                    rejected_bond,
                    &delegator_pubkey,
                    bond_proof.as_ref(),
                    3,
                    false,
                    true,
                    Some(2),
                ),
                Err(StateError::ValidatorBondCountAtMaximum { max: 2, .. })
            ));
            assert_eq!(state, before);
            (state.encode_to_vec(), crate::compute_state_root(&state))
        }

        let first = replay();
        let second = replay();
        assert_eq!(first, second);
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
        let bond_utxo_id = insert_self_stake_utxo(&mut state, pubkey, 2_000_000, 0x30);

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
        let bond_utxo_id = insert_self_stake_utxo(&mut state, pubkey, 2_000_000, 0x57);
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
            insert_self_stake_utxo(&mut state, legitimate_pubkey.clone(), 2_000_000, 0x5B);
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
        let bond_utxo_id = insert_self_stake_utxo(&mut state, pubkey.clone(), 2_000_000, 0x3B);
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
        let bond_utxo_id = insert_self_stake_utxo(&mut state, pubkey.clone(), 2_000_000, 0x3C);
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
        let bond_utxo_id = insert_self_stake_utxo(&mut state, pubkey, 2_000_000, 0x35);

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
        let bond_utxo_id = insert_self_stake_utxo(&mut state, pubkey, 2_000_000, 0x37);

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
        let bond_utxo_id = insert_self_stake_utxo(&mut state, pubkey, 2_000_000, 0x25);

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
        let bond_utxo_id = insert_self_stake_utxo(&mut state, pubkey, 2_000_000, 0x27);

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
        let bond_utxo_id = insert_self_stake_utxo(&mut state, pubkey, 2_000_000, 0x29);

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
        let bond_utxo_id = insert_self_stake_utxo(&mut state, pubkey, 2_000_000, 0x39);
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
        let bond_utxo_id = insert_self_stake_utxo(&mut state, pubkey, 2_000_000, 0x3A);
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
    fn claim_rewards_creates_utxo() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
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
    fn apply_register_validator_sets_vrf_key() {
        let mut state = ChainState::new_genesis();
        let validator_keypair = keypair(0x04);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let validator_id = pubkey_to_id(&validator_pubkey);
        let bond_utxo_id = insert_registration_utxo(
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
    fn register_validator_post_identity_gate_populates_registry() {
        let mut state = ChainState::new_genesis();
        let validator_keypair = keypair(0xB1);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let validator_id = pubkey_to_id(&validator_pubkey);
        let bond_utxo_id = insert_registration_utxo(
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
        let bond_utxo_id = insert_registration_utxo(
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
        let bond_utxo_id = insert_registration_utxo(
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
        let bond_utxo_id = insert_registration_utxo(
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
        let bond_utxo_id = insert_registration_utxo(
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
        let first_bond = insert_registration_utxo(
            &mut state,
            first_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xA3,
        );
        let second_keypair = keypair(0x47);
        let second_pubkey = pubkey_from_keypair(&second_keypair);
        let second_bond = insert_registration_utxo(
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
        let first_bond = insert_registration_utxo(
            &mut state,
            first_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xA5,
        );
        let second_keypair = mixed_keypair(0x48, 0x49);
        let second_pubkey = pubkey_from_keypair(&second_keypair);
        let second_bond = insert_registration_utxo(
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
        let first_bond = insert_registration_utxo(
            &mut state,
            first_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xA7,
        );
        let second_keypair = mixed_keypair(0x4B, 0x4A);
        let second_pubkey = pubkey_from_keypair(&second_keypair);
        let second_bond = insert_registration_utxo(
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
        let first_bond = insert_registration_utxo(
            &mut state,
            first_pubkey.clone(),
            MINIMUM_VALIDATOR_BOND_SPARK,
            0xA9,
        );
        let second_keypair = keypair(0x4D);
        let second_pubkey = pubkey_from_keypair(&second_keypair);
        let second_bond = insert_registration_utxo(
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
                hybrid_pq_pk: Some(vec![pk_byte; indra_crypto::PQ_PK_BYTES]),
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
                unbonding_start_height: None,
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

    fn fill_representable_registry_to_cap(state: &mut ChainState, lowest_stake: u64) -> Bytes32 {
        let lowest_id = fill_registry_to_cap(state, lowest_stake);
        let hot = keypair(0xC1).public_key();
        let cold = keypair(0xC2).public_key();
        let vrf = indra_crypto::VrfKeypair::from_seed(&[0xC3; 32]).public_key();
        let validator_ids: Vec<_> = state
            .validators
            .all_validators()
            .map(|validator| validator.validator_id)
            .collect();
        for validator_id in validator_ids {
            let validator = state.validators.get_mut(&validator_id).unwrap();
            validator.hybrid_classical_pk = Some(hot.classical.0);
            validator.hybrid_pq_pk = Some(hot.pq.0.to_vec());
            validator.vrf_pk = Some(vrf);
            validator.cold_hybrid_classical_pk = Some(cold.classical.0);
            validator.cold_hybrid_pq_pk = Some(cold.pq.0);
            validator.cold_key_version = 1;
        }
        lowest_id
    }

    fn mark_cap_registry_entry_cold_active(state: &mut ChainState, validator_id: Bytes32) {
        let validator = state.validators.get_mut(&validator_id).unwrap();
        validator.cold_hybrid_classical_pk = validator.hybrid_classical_pk;
        validator.cold_hybrid_pq_pk = Some([validator_id.0[0]; indra_crypto::PQ_PK_BYTES]);
        validator.cold_key_version = 1;
    }

    fn install_valid_cap_registry_keys(state: &mut ChainState, validator_id: Bytes32, seed: u8) {
        let hot = keypair(seed);
        let hot_public = hot.public_key();
        let cold = keypair(seed.wrapping_add(1));
        let cold_public = cold.public_key();
        let validator = state.validators.get_mut(&validator_id).unwrap();
        validator.hybrid_classical_pk = Some(hot_public.classical.0);
        validator.hybrid_pq_pk = Some(hot_public.pq.0.to_vec());
        validator.vrf_pk =
            Some(indra_crypto::VrfKeypair::from_seed(&[seed.wrapping_add(2); 32]).public_key());
        validator.cold_hybrid_classical_pk = Some(cold_public.classical.0);
        validator.cold_hybrid_pq_pk = Some(cold_public.pq.0);
        validator.cold_key_version = 1;
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

    fn registration_op_with_cold_bond(
        state: &mut ChainState,
        hot_seed: u8,
        cold_classical_seed: u8,
        cold_pq_seed: u8,
        bond_seed: u8,
    ) -> (StakingOp, Bytes32, Bytes32) {
        let hot = keypair(hot_seed);
        let cold = mixed_keypair(cold_classical_seed, cold_pq_seed);
        let cold_owner = pubkey_from_keypair(&cold);
        let bond_utxo_id =
            insert_delegator_utxo(state, cold_owner, MINIMUM_VALIDATOR_BOND_SPARK, bond_seed);
        let validator_id = pubkey_to_id(&pubkey_from_keypair(&hot));
        let op = dual_signed_register_op(
            bond_utxo_id,
            &hot,
            &cold,
            1,
            &state.chain_id,
            [bond_seed.wrapping_add(1); 32],
            bond_seed,
        );
        (op, bond_utxo_id, validator_id)
    }

    fn full_registry_fallback_fixture(
    ) -> (ChainState, StakingOp, Bytes32, Bytes32, Bytes32, Bytes32) {
        let mut state = ChainState::new_genesis();
        let lowest_stake =
            MINIMUM_VALIDATOR_BOND_SPARK.saturating_sub(DUST_LIMIT_SPARK.saturating_mul(20));
        let frozen_lowest = fill_registry_to_cap(&mut state, lowest_stake);
        let next_evictable = raw_id(0x44, 1);
        for index in 1..MAX_VALIDATORS {
            mark_cap_registry_entry_cold_active(&mut state, raw_id(0x44, index));
        }
        install_valid_cap_registry_keys(&mut state, next_evictable, 0xB9);
        let (op, new_bond, new_validator) =
            registration_op_with_cold_bond(&mut state, 0xE1, 0xE2, 0xE3, 0xE4);
        (
            state,
            op,
            frozen_lowest,
            next_evictable,
            new_validator,
            new_bond,
        )
    }

    fn synthetic_tombstone(reference_count: usize) -> EvictedValidatorTombstoneV1 {
        EvictedValidatorTombstoneV1 {
            validator_id: raw_id(0xA0, 0),
            eviction_height: u64::MAX - 1,
            eviction_epoch: epoch_for_height(u64::MAX - 1),
            last_classical_vote_pk: [0xA1; 32],
            last_pq_vote_pk: [0xA2; indra_crypto::PQ_PK_BYTES],
            last_vrf_pk: [0xA3; 32],
            cold_custody: None,
            retained_bonds: (0..reference_count)
                .map(|index| EvictedBondReferenceV1 {
                    bond_utxo_id: raw_id(0xA4, index),
                    delegator_id: raw_id(0xA5, index),
                    unbonding_end_epoch: 1,
                })
                .collect(),
        }
    }

    #[test]
    fn post_gate_registry_eviction_retains_bonds_and_frees_live_slot() {
        let (mut state, op, frozen_lowest, next_evictable, new_validator, _) =
            full_registry_fallback_fixture();
        let victim_bond = state
            .staked_bonds
            .values()
            .find(|bond| bond.validator_id == next_evictable)
            .unwrap()
            .utxo_id;
        let chain_id = state.chain_id.clone();

        apply_staking_op(&mut state, &op, &chain_id, u64::MAX).unwrap();

        assert_eq!(state.validators.len(), MAX_VALIDATORS);
        assert!(state.validators.get(&frozen_lowest).is_some());
        assert!(state.validators.get(&next_evictable).is_none());
        assert!(state.validators.get(&new_validator).is_some());
        let tombstone = state
            .evicted_validator_tombstones
            .get(&next_evictable)
            .expect("eviction must retain a tombstone");
        assert_eq!(tombstone.retained_bonds.len(), 1);
        assert_eq!(tombstone.retained_bonds[0].bond_utxo_id, victim_bond);
        assert_eq!(
            state
                .staked_bonds
                .get(&victim_bond)
                .unwrap()
                .unbonding_end_epoch,
            Some(epoch_for_height(u64::MAX) + UNBONDING_PERIOD_EPOCHS)
        );
    }

    #[test]
    fn post_gate_registration_rejects_tombstoned_validator_id_before_spending_bond() {
        let mut state = ChainState::new_genesis();
        let (op, bond_id, validator_id) =
            registration_op_with_cold_bond(&mut state, 0xC1, 0xC2, 0xC3, 0xC4);
        let mut tombstone = synthetic_tombstone(0);
        tombstone.validator_id = validator_id;
        state
            .evicted_validator_tombstones
            .insert(validator_id, tombstone);
        let chain_id = state.chain_id.clone();

        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id, u64::MAX),
            Err(StateError::InvalidStakingOp(reason)) if reason.contains("tombstone")
        ));
        assert!(state.utxos.contains(&bond_id));
        assert!(state.validators.get(&validator_id).is_none());
    }

    #[test]
    fn tombstone_capacity_skips_lowest_and_fails_when_no_candidate_fits() {
        let mut state = ChainState::new_genesis();
        let lowest =
            insert_registry_entry_for_cap_test(&mut state, 0, MINIMUM_VALIDATOR_BOND_SPARK);
        let next =
            insert_registry_entry_for_cap_test(&mut state, 1, MINIMUM_VALIDATOR_BOND_SPARK + 1);
        mark_cap_registry_entry_cold_active(&mut state, lowest);
        mark_cap_registry_entry_cold_active(&mut state, next);
        install_valid_cap_registry_keys(&mut state, lowest, 0xBA);
        install_valid_cap_registry_keys(&mut state, next, 0xBB);
        let extra_id = raw_id(0xB0, 0);
        let mut extra = state
            .staked_bonds
            .values()
            .find(|bond| bond.validator_id == lowest)
            .unwrap()
            .clone();
        extra.utxo_id = extra_id;
        state.staked_bonds.insert(extra_id, extra);
        let existing = synthetic_tombstone(MAX_TOTAL_RETAINED_BOND_REFERENCES - 1);
        state
            .evicted_validator_tombstones
            .insert(existing.validator_id, existing);

        assert_eq!(
            lowest_representable_registry_validator(&state, u64::MAX).unwrap(),
            (next, MINIMUM_VALIDATOR_BOND_SPARK + 1)
        );

        let full = synthetic_tombstone(MAX_TOTAL_RETAINED_BOND_REFERENCES);
        state.evicted_validator_tombstones = crate::persistent::PersistentOrdMap::new();
        state
            .evicted_validator_tombstones
            .insert(full.validator_id, full);
        assert_eq!(
            lowest_representable_registry_validator(&state, u64::MAX),
            Err(StateError::TombstoneCapacityExceeded)
        );
    }

    #[test]
    fn tombstone_bond_matures_on_original_schedule_and_empty_record_waits_for_window() {
        let mut state = ChainState::new_genesis();
        let validator_id =
            insert_registry_entry_for_cap_test(&mut state, 7, MINIMUM_VALIDATOR_BOND_SPARK);
        let bond_id = state
            .staked_bonds
            .values()
            .find(|bond| bond.validator_id == validator_id)
            .unwrap()
            .utxo_id;
        state.validators.remove(&validator_id);
        let eviction_height = u64::MAX - 1;
        let eviction_epoch = epoch_for_height(eviction_height);
        let maturity_epoch = eviction_epoch + 1;
        let mut bond = state.staked_bonds.get(&bond_id).unwrap().clone();
        bond.unbonding_end_epoch = Some(maturity_epoch);
        state.staked_bonds.insert(bond_id, bond);
        let mut tombstone = synthetic_tombstone(0);
        tombstone.validator_id = validator_id;
        tombstone.eviction_height = eviction_height;
        tombstone.eviction_epoch = eviction_epoch;
        tombstone.retained_bonds = vec![EvictedBondReferenceV1 {
            bond_utxo_id: bond_id,
            delegator_id: validator_id,
            unbonding_end_epoch: maturity_epoch,
        }];
        state
            .evicted_validator_tombstones
            .insert(validator_id, tombstone);

        crate::epoch::release_unbonded_bonds_at_height(&mut state, maturity_epoch - 1, u64::MAX)
            .unwrap();
        assert!(state.staked_bonds.contains_key(&bond_id));

        crate::epoch::release_unbonded_bonds_at_height(&mut state, maturity_epoch, u64::MAX)
            .unwrap();
        assert!(!state.staked_bonds.contains_key(&bond_id));
        assert!(state
            .evicted_validator_tombstones
            .get(&validator_id)
            .unwrap()
            .retained_bonds
            .is_empty());

        crate::epoch::release_unbonded_bonds_at_height(
            &mut state,
            eviction_epoch + indra_core::types::primitives::SLASH_EVIDENCE_WINDOW_EPOCHS + 1,
            u64::MAX,
        )
        .unwrap();
        assert!(state
            .evicted_validator_tombstones
            .get(&validator_id)
            .is_none());
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
}
