//! Delegation state transitions.
//!
//! Handles apply_delegate, apply_undelegate, apply_claim_rewards,
//! and apply_set_commission. Called from apply_block when a block
//! contains StakingOp entries.

use indra_core::types::{
    crypto::{CommitmentV1, HybridPubKey, HybridSignature},
    primitives::{
        registered_validator_cap_active, staking_commitment_proof_required,
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
    validator::{
        DelegationReturnEvent, DelegationReturnReason, StakeBondEntry, ValidatorEntry,
        ValidatorStatus, MAX_DELEGATORS_PER_VALIDATOR,
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
        StakingOpBody::SetCommission { validator_id, .. }
        | StakingOpBody::SetAutoDelegate { validator_id, .. }
        | StakingOpBody::UpdateNetworkAddress { validator_id, .. } => {
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
        }
        | StakingOpBody::SelfStake {
            validator_pubkey, ..
        }
        | StakingOpBody::SelfUnstake {
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
        ),
        StakingOpBody::ClaimRewards {
            validator_id,
            delegator_pubkey,
        } => apply_claim_rewards(state, validator_id, delegator_pubkey, current_height),
        StakingOpBody::RegisterValidator {
            commission_bps,
            bond_utxo_id,
            validator_pubkey,
            vrf_pk,
            bond_proof,
        } => apply_register_validator(
            state,
            *commission_bps,
            *bond_utxo_id,
            validator_pubkey,
            *vrf_pk,
            bond_proof.as_ref(),
            current_height,
        ),
        StakingOpBody::SetCommission {
            validator_id,
            new_commission_bps,
        } => apply_set_commission(state, validator_id, *new_commission_bps, current_height),
        StakingOpBody::SetAutoDelegate {
            validator_id,
            target_validator_id,
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
        } => apply_self_stake(
            state,
            *bond_utxo_id,
            validator_pubkey,
            bond_proof.as_ref(),
            current_height,
        ),
        StakingOpBody::SelfUnstake {
            bond_utxo_id,
            validator_pubkey,
        } => apply_self_unstake(state, *bond_utxo_id, validator_pubkey, current_height),
    };

    result?;
    state.staking_nonces.insert(signer_id, op.nonce);
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_staking_nonce(&signer_id, op.nonce);
    }
    Ok(())
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
    current_height: u64,
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
    let utxo_owner_id = pubkey_to_id(&utxo_entry.output.owner_pubkey);
    if utxo_owner_id != validator_id {
        return Err(StateError::InvalidStakingOp(
            "registration bond UTXO does not belong to the validator".into(),
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
    };
    state.validators.upsert(entry.clone())?;
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_validator(&entry, current_height);
    }
    let bond = StakeBondEntry::new(
        bond_utxo_id,
        validator_id,
        validator_id,
        amount_spark,
        epoch_for_height(current_height),
        original_output,
        current_height,
    );
    state.staked_bonds.insert(bond_utxo_id, bond.clone());
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_staked_bond(&bond_utxo_id, &bond);
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
                payout_or_burn_pending_reward(
                    state,
                    &validator_id,
                    &entry.delegator_id,
                    entry.pending_rewards,
                    bond.original_output.owner_pubkey,
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
            let output = crate::epoch::released_bond_output(&bond, current_height)?;
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

    Ok(())
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
    Ok(())
}

/// Bond a validator-owned UTXO as validator self-stake.
fn apply_self_stake(
    state: &mut ChainState,
    bond_utxo_id: Bytes32,
    validator_pubkey: &HybridPubKey,
    bond_proof: Option<&StakingBondProof>,
    current_height: u64,
) -> StateResult<()> {
    let validator_id = pubkey_to_id(validator_pubkey);
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
    let utxo_owner_id = pubkey_to_id(&utxo_entry.output.owner_pubkey);
    if utxo_owner_id != validator_id {
        return Err(StateError::InvalidStakingOp(
            "UTXO does not belong to the validator".into(),
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
    let bond = StakeBondEntry::new(
        bond_utxo_id,
        validator_id,
        validator_id,
        amount_spark,
        current_epoch,
        original_output,
        current_height,
    );
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
) -> StateResult<()> {
    let validator_id = pubkey_to_id(validator_pubkey);
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
        owner_pubkey: delegator_pubkey.clone(),
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
    use indra_core::types::{
        crypto::{CommitmentV1, HybridPubKey, HybridSignature},
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
        };
        state.validators.upsert(entry).unwrap();
        (validator_id, keypair)
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
            apply_staking_op(&mut state, &op, &chain_id, u64::MAX),
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

        apply_staking_op(&mut state, &op, &chain_id, u64::MAX).unwrap();

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

        apply_staking_op(&mut state, &op, &chain_id, u64::MAX).unwrap();

        assert!(state.validators.get(&lowest_id).is_none());
        assert!(state.utxos.len() >= utxos_before.saturating_add(2));
        assert!(state
            .delegation_return_events
            .iter()
            .any(|event| event.delegator_id == delegator));
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
