//! Delegation state transitions.
//!
//! Handles apply_delegate, apply_undelegate, apply_claim_rewards,
//! and apply_set_commission. Called from apply_block when a block
//! contains StakingOp entries.

use indra_core::types::{
    crypto::{HybridPubKey, HybridSignature},
    primitives::{
        Bytes32, DUST_LIMIT_SPARK, MAX_COMMISSION_BPS, MIN_COMMISSION_BPS, UNBONDING_PERIOD_EPOCHS,
    },
    staking::{StakingOp, StakingOpBody},
};

use crate::{
    chain::ChainState,
    epoch::epoch_for_height,
    error::{StateError, StateResult},
    validator::{ValidatorEntry, ValidatorStatus},
};

/// Apply a single staking operation to chain state.
///
/// Called after all transaction validation has passed.
/// Staking ops are applied in block order after UTXO transactions.
pub fn apply_staking_op(state: &mut ChainState, op: &StakingOp, chain_id: &str) -> StateResult<()> {
    let signer_id = op.signer_id();
    let expected_nonce = state.staking_nonces.get(&signer_id).copied().unwrap_or(0) + 1;
    if op.nonce != expected_nonce {
        return Err(StateError::StakingNonceInvalid {
            expected: expected_nonce,
            got: op.nonce,
        });
    }

    let signing_bytes = op.signing_bytes(chain_id);
    match &op.body {
        StakingOpBody::SetCommission { validator_id, .. } => {
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
        }
        | StakingOpBody::ClaimRewards {
            delegator_pubkey, ..
        } => {
            verify_staking_sig(
                &signing_bytes,
                &op.signature,
                &delegator_pubkey.classical_pk.0,
                delegator_pubkey.pq_pk.as_slice(),
            )?;
        }
        StakingOpBody::RegisterValidator {
            validator_pubkey, ..
        } => {
            verify_staking_sig(
                &signing_bytes,
                &op.signature,
                &validator_pubkey.classical_pk.0,
                validator_pubkey.pq_pk.as_slice(),
            )?;
        }
    }

    state.staking_nonces.insert(signer_id, op.nonce);

    match &op.body {
        StakingOpBody::Delegate {
            validator_id,
            amount_spark,
            delegator_pubkey,
        } => apply_delegate(state, validator_id, *amount_spark, delegator_pubkey),
        StakingOpBody::Undelegate {
            validator_id,
            amount_spark,
            delegator_pubkey,
        } => apply_undelegate(state, validator_id, *amount_spark, delegator_pubkey),
        StakingOpBody::ClaimRewards {
            validator_id,
            delegator_pubkey,
        } => apply_claim_rewards(state, validator_id, delegator_pubkey),
        StakingOpBody::RegisterValidator {
            commission_bps,
            validator_pubkey,
            vrf_pk,
        } => apply_register_validator(state, *commission_bps, validator_pubkey, *vrf_pk),
        StakingOpBody::SetCommission {
            validator_id,
            new_commission_bps,
        } => apply_set_commission(state, validator_id, *new_commission_bps),
    }
}

fn verify_staking_sig(
    signing_bytes: &[u8],
    signature: &HybridSignature,
    classical_pk: &[u8; 32],
    pq_pk_bytes: &[u8],
) -> StateResult<()> {
    use indra_crypto::{
        verify_hybrid, ClassicalPublicKey, HybridPublicKey, PqPublicKey, PQ_PK_BYTES,
    };

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
    let crypto_pk = HybridPublicKey {
        classical: ClassicalPublicKey(*classical_pk),
        pq: PqPublicKey(pq_pk),
    };
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
    validator_pubkey: &HybridPubKey,
    vrf_pk: [u8; 32],
) -> StateResult<()> {
    if commission_bps < MIN_COMMISSION_BPS || commission_bps > MAX_COMMISSION_BPS {
        return Err(StateError::InvalidStakingOp(
            "commission out of range".into(),
        ));
    }

    let validator_id = pubkey_to_id(validator_pubkey);
    if state.validators.get(&validator_id).is_some() {
        return Err(StateError::ValidatorAlreadyRegistered);
    }

    let current_epoch = epoch_for_height(state.height);
    let entry = ValidatorEntry {
        validator_id,
        name: hex::encode(&validator_id.0[..8]),
        hybrid_classical_pk: Some(validator_pubkey.classical_pk.0),
        hybrid_pq_pk: Some(validator_pubkey.pq_pk.as_slice().to_vec()),
        vrf_pk: Some(vrf_pk),
        stake_spark: 0,
        status: ValidatorStatus::Registered,
        registered_epoch: current_epoch,
        pending_rewards: 0,
        rewards_last_epoch: current_epoch,
        self_report_count: 0,
        commission_bps,
        min_delegation_spark: DUST_LIMIT_SPARK,
    };
    state.validators.upsert(entry)
}

/// Delegate stake to a validator.
///
/// The delegator's stake is added to the validator's delegation pool.
/// Rewards accrue from the next epoch boundary.
fn apply_delegate(
    state: &mut ChainState,
    validator_id: &Bytes32,
    amount_spark: u64,
    delegator_pubkey: &indra_core::types::crypto::HybridPubKey,
) -> StateResult<()> {
    // Validator must exist and be active
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
    if amount_spark < validator.min_delegation_spark {
        return Err(StateError::InvalidStakingOp(format!(
            "delegation below validator minimum: have {} Spark, need {} Spark",
            amount_spark, validator.min_delegation_spark,
        )));
    }

    // Derive delegator_id from pubkey bytes
    let delegator_id = pubkey_to_id(delegator_pubkey);
    let current_epoch = epoch_for_height(state.height);

    state
        .delegations
        .add_delegation(*validator_id, delegator_id, amount_spark, current_epoch);

    Ok(())
}

/// Begin undelegating from a validator.
///
/// Stake enters unbonding for UNBONDING_PERIOD_EPOCHS epochs.
/// During unbonding, stake earns no rewards and cannot be redelegated.
fn apply_undelegate(
    state: &mut ChainState,
    validator_id: &Bytes32,
    amount_spark: u64,
    delegator_pubkey: &indra_core::types::crypto::HybridPubKey,
) -> StateResult<()> {
    let delegator_id = pubkey_to_id(delegator_pubkey);
    let current_epoch = epoch_for_height(state.height);
    let unbonding_end = current_epoch + UNBONDING_PERIOD_EPOCHS;

    state
        .delegations
        .begin_undelegate(validator_id, &delegator_id, amount_spark, unbonding_end)
        .map_err(|e| StateError::InvalidStakingOp(e.into()))
}

/// Claim pending rewards for a delegator.
///
/// Transfers pending_rewards to the delegator's UTXO set entry.
/// In Phase 3 this will create an actual UTXO output.
/// For now, rewards are zeroed and added to total supply as distributed.
fn apply_claim_rewards(
    state: &mut ChainState,
    validator_id: &Bytes32,
    delegator_pubkey: &indra_core::types::crypto::HybridPubKey,
) -> StateResult<()> {
    let delegator_id = pubkey_to_id(delegator_pubkey);

    let entry = state
        .delegations
        .get_delegator_mut(validator_id, &delegator_id)
        .ok_or(StateError::DelegatorNotFound)?;

    // Zero out pending rewards — in Phase 3 this creates a UTXO
    let _claimed = entry.pending_rewards;
    entry.pending_rewards = 0;

    Ok(())
}

/// Update a validator's commission rate.
///
/// Takes effect immediately for future epoch reward distributions.
/// Does not affect already-accrued pending rewards.
fn apply_set_commission(
    state: &mut ChainState,
    validator_id: &Bytes32,
    new_commission_bps: u32,
) -> StateResult<()> {
    if !(MIN_COMMISSION_BPS..=MAX_COMMISSION_BPS).contains(&new_commission_bps) {
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

    validator.commission_bps = new_commission_bps;
    Ok(())
}

/// Derive a stable delegator ID from their hybrid public key.
///
/// Uses SHA-256 of the encoded public key bytes, matching how
/// validator_id is derived from validator public keys.
fn pubkey_to_id(pubkey: &indra_core::types::crypto::HybridPubKey) -> Bytes32 {
    use indra_core::codec::Encode;
    let bytes = pubkey.encode_to_vec();
    // Simple SHA-256 via standard library — matches validator_id derivation
    let hash = indra_crypto::sha256(&bytes);
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
        crypto::{HybridPubKey, HybridSignature},
        primitives::VariableBytes,
    };
    use indra_crypto::hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair};

    fn keypair(seed: u8) -> HybridKeypair {
        HybridKeypair::new(
            ClassicalKeypair::from_seed(&[seed; 32]),
            PqKeypair::from_seed(&[seed; 32]).unwrap(),
        )
    }

    fn pubkey_from_keypair(keypair: &HybridKeypair) -> HybridPubKey {
        let public = keypair.public_key();
        HybridPubKey {
            classical_pk: Bytes32::from(public.classical.0),
            pq_pk: VariableBytes::from_slice(&public.pq.0).unwrap(),
        }
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

    fn make_active_validator(state: &mut ChainState, seed: u8) -> (Bytes32, HybridKeypair) {
        let keypair = keypair(seed);
        let pubkey = pubkey_from_keypair(&keypair);
        let validator_id = pubkey_to_id(&pubkey);
        let entry = ValidatorEntry {
            validator_id,
            name: format!("validator-{seed}"),
            hybrid_classical_pk: Some(pubkey.classical_pk.0),
            hybrid_pq_pk: Some(pubkey.pq_pk.as_slice().to_vec()),
            vrf_pk: Some([seed; 32]),
            stake_spark: 10_000_000_000,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            pending_rewards: 0,
            rewards_last_epoch: 0,
            self_report_count: 0,
            commission_bps: 1_000,
            min_delegation_spark: indra_core::types::primitives::DUST_LIMIT_SPARK,
        };
        state.validators.upsert(entry).unwrap();
        (validator_id, keypair)
    }

    #[test]
    fn delegate_to_active_validator_succeeds() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&delegator_keypair);

        let op = signed_op(
            StakingOpBody::Delegate {
                validator_id,
                amount_spark: 1_000_000,
                delegator_pubkey: pubkey,
            },
            1,
            &delegator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert!(apply_staking_op(&mut state, &op, &chain_id).is_ok());
        assert_eq!(state.delegations.total_delegated(&validator_id), 1_000_000);
    }

    #[test]
    fn delegate_to_unknown_validator_fails() {
        let mut state = ChainState::new_genesis();
        let delegator_keypair = keypair(0x01);
        let pubkey = pubkey_from_keypair(&delegator_keypair);

        let op = signed_op(
            StakingOpBody::Delegate {
                validator_id: Bytes32::from([0xFFu8; 32]),
                amount_spark: 1_000_000,
                delegator_pubkey: pubkey,
            },
            1,
            &delegator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert!(apply_staking_op(&mut state, &op, &chain_id).is_err());
    }

    #[test]
    fn delegate_below_validator_minimum_fails() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        state
            .validators
            .get_mut(&validator_id)
            .unwrap()
            .min_delegation_spark = 2_000_000;
        let delegator_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&delegator_keypair);

        let op = signed_op(
            StakingOpBody::Delegate {
                validator_id,
                amount_spark: 1_000_000,
                delegator_pubkey: pubkey,
            },
            1,
            &delegator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert!(apply_staking_op(&mut state, &op, &chain_id).is_err());
    }

    #[test]
    fn delegate_to_registered_validator_succeeds() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        state.validators.get_mut(&validator_id).unwrap().status = ValidatorStatus::Registered;
        let delegator_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&delegator_keypair);

        let op = signed_op(
            StakingOpBody::Delegate {
                validator_id,
                amount_spark: 1_000_000,
                delegator_pubkey: pubkey,
            },
            1,
            &delegator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert!(apply_staking_op(&mut state, &op, &chain_id).is_ok());
        assert_eq!(state.delegations.total_delegated(&validator_id), 1_000_000);
    }

    #[test]
    fn set_commission_valid_range_succeeds() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0x01);

        let op = signed_op(
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps: 1_500,
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert!(apply_staking_op(&mut state, &op, &chain_id).is_ok());
        assert_eq!(
            state.validators.get(&validator_id).unwrap().commission_bps,
            1_500
        );
    }

    #[test]
    fn set_commission_out_of_range_fails() {
        let mut state = ChainState::new_genesis();
        let (validator_id, validator_keypair) = make_active_validator(&mut state, 0x01);

        let op = signed_op(
            StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps: 9_999,
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert!(apply_staking_op(&mut state, &op, &chain_id).is_err());
    }

    #[test]
    fn undelegate_then_no_active_stake() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let pubkey = pubkey_from_keypair(&delegator_keypair);

        // First delegate
        let delegate_op = signed_op(
            StakingOpBody::Delegate {
                validator_id,
                amount_spark: 1_000_000,
                delegator_pubkey: pubkey.clone(),
            },
            1,
            &delegator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &delegate_op, &chain_id).unwrap();

        // Then undelegate
        let undelegate_op = signed_op(
            StakingOpBody::Undelegate {
                validator_id,
                amount_spark: 1_000_000,
                delegator_pubkey: pubkey,
            },
            2,
            &delegator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert!(apply_staking_op(&mut state, &undelegate_op, &chain_id).is_ok());
        // Active delegation should now be 0
        assert_eq!(state.delegations.total_delegated(&validator_id), 0);
    }

    #[test]
    fn apply_staking_op_rejects_wrong_nonce() {
        let mut state = ChainState::new_genesis();
        let (validator_id, _) = make_active_validator(&mut state, 0x01);
        let delegator_keypair = keypair(0x02);
        let op = signed_op(
            StakingOpBody::Delegate {
                validator_id,
                amount_spark: 1_000_000,
                delegator_pubkey: pubkey_from_keypair(&delegator_keypair),
            },
            5,
            &delegator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id),
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
        let op = signed_op(
            StakingOpBody::Delegate {
                validator_id,
                amount_spark: 1_000_000,
                delegator_pubkey: pubkey_from_keypair(&delegator_keypair),
            },
            1,
            &delegator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &op, &chain_id).unwrap();
        assert_eq!(
            apply_staking_op(&mut state, &op, &chain_id),
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
                amount_spark: 1_000_000,
                delegator_pubkey: pubkey_from_keypair(&delegator_keypair),
            },
            1,
            &wrong_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_staking_op(&mut state, &op, &chain_id),
            Err(StateError::StakingOpSignatureInvalid { .. })
        ));
    }

    #[test]
    fn apply_register_validator_sets_vrf_key() {
        let mut state = ChainState::new_genesis();
        let validator_keypair = keypair(0x04);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let validator_id = pubkey_to_id(&validator_pubkey);
        let vrf_pk = [0xA5; 32];
        let op = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                validator_pubkey,
                vrf_pk,
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &op, &chain_id).unwrap();
        assert_eq!(state.validators.get(&validator_id).unwrap().vrf_pk, Some(vrf_pk));
    }

    #[test]
    fn apply_register_validator_rejects_duplicate() {
        let mut state = ChainState::new_genesis();
        let validator_keypair = keypair(0x04);
        let validator_pubkey = pubkey_from_keypair(&validator_keypair);
        let first = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                validator_pubkey: validator_pubkey.clone(),
                vrf_pk: [0xA5; 32],
            },
            1,
            &validator_keypair,
            &state.chain_id,
        );
        let second = signed_op(
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                validator_pubkey,
                vrf_pk: [0x5A; 32],
            },
            2,
            &validator_keypair,
            &state.chain_id,
        );
        let chain_id = state.chain_id.clone();
        apply_staking_op(&mut state, &first, &chain_id).unwrap();
        assert_eq!(
            apply_staking_op(&mut state, &second, &chain_id),
            Err(StateError::ValidatorAlreadyRegistered)
        );
    }
}
