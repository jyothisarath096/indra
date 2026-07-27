//! Governance operation application.

use indra_core::types::{
    crypto::HybridPubKey,
    governance::{
        compute_proposal_id, governance_signing_domain, governance_vote_commit_hash,
        GovernanceOpV2, GovernancePayload,
    },
    primitives::{delegator_identity_registry_active, Bytes32},
    transaction::OutputV1,
};
use indra_crypto::{commit, prove_range, sha256, verify_hybrid};
use rand::{rngs::StdRng, SeedableRng};

use crate::{
    error::{StateError, StateResult},
    governance::{
        GovernableParams, GovernanceRedelegation, GovernanceState, ProposalPhase, ProposalRecord,
        VoteCommit, VoteReveal, GOVERNANCE_CRITICAL_COMMIT_EPOCHS, GOVERNANCE_DELIBERATION_EPOCHS,
        GOVERNANCE_PROPOSAL_COOLDOWN_EPOCHS, GOVERNANCE_REVEAL_EPOCHS,
        GOVERNANCE_STANDARD_COMMIT_EPOCHS, MAX_ACTIVE_GOVERNANCE_PROPOSALS,
        MAX_ACTIVE_GOVERNANCE_PROPOSALS_PER_PROPOSER,
    },
    identity::{
        resolve_active_validator_cold_pubkey, resolve_delegator_identity_for_redelegation,
        IdentityError,
    },
    validator::{ColdKeyStatus, ValidatorStatus},
    ChainState,
};

/// Apply one governance op.
pub fn apply_governance_op(
    state: &mut ChainState,
    op: &GovernanceOpV2,
    current_epoch: u64,
    current_height: u64,
    chain_id: &str,
) -> StateResult<()> {
    op.validate_structure_at_height(current_height)
        .map_err(|error| StateError::InvalidGovernanceOp {
            reason: error.to_string(),
        })?;
    let identity_registry_active = delegator_identity_registry_active(current_height);
    let cold_authorized = verify_governance_sig(state, op, chain_id, identity_registry_active)?;
    apply_governance_nonce(state, op, current_height, cold_authorized)?;

    match &op.payload {
        GovernancePayload::Propose {
            action,
            deposit_utxo_id,
            proposer_pubkey,
            title,
            description,
            ..
        } => apply_propose(
            state,
            op,
            current_epoch,
            chain_id,
            action,
            deposit_utxo_id,
            proposer_pubkey,
            title.as_slice(),
            description.as_slice(),
            current_height,
        ),
        GovernancePayload::Commit {
            proposal_id,
            commit_hash,
            ..
        } => apply_commit(state, op, current_epoch, proposal_id, commit_hash),
        GovernancePayload::Reveal {
            proposal_id,
            vote,
            nonce,
            ..
        } => apply_reveal(state, op, current_epoch, proposal_id, *vote, nonce),
        GovernancePayload::Redelegate {
            proposal_id,
            from_validator,
            to_validator,
            amount_spark,
        } => apply_redelegate(
            state,
            op,
            proposal_id,
            from_validator,
            to_validator,
            *amount_spark,
            identity_registry_active,
        ),
        GovernancePayload::Execute { proposal_id } => {
            apply_execute(state, current_epoch, current_height, proposal_id)
        }
        GovernancePayload::Cancel { proposal_id, .. } => apply_cancel(state, op, proposal_id),
    }
}

/// Validate a governance op against a scratch copy of the provided state.
///
/// This is used by mempool/RPC admission so malformed governance operations do
/// not sit in the pending pool and later poison honest block proposals.
pub fn validate_governance_op(
    state: &ChainState,
    op: &GovernanceOpV2,
    current_epoch: u64,
    chain_id: &str,
) -> StateResult<()> {
    let mut scratch = state.clone();
    apply_governance_op(&mut scratch, op, current_epoch, state.height, chain_id)
}

fn apply_propose(
    state: &mut ChainState,
    op: &GovernanceOpV2,
    current_epoch: u64,
    chain_id: &str,
    action: &indra_core::types::governance::GovernableAction,
    deposit_utxo_id: &Bytes32,
    proposer_pubkey: &HybridPubKey,
    title_bytes: &[u8],
    description_bytes: &[u8],
    current_height: u64,
) -> StateResult<()> {
    let proposer = state
        .validators
        .get(&op.signer_id)
        .ok_or(StateError::ValidatorNotFound)?;
    if !matches!(
        proposer.status,
        ValidatorStatus::Active | ValidatorStatus::Registered
    ) {
        return invalid("proposer must be active or registered validator");
    }
    if state.governance.active_proposal_count() >= MAX_ACTIVE_GOVERNANCE_PROPOSALS {
        return invalid("global active proposal cap exceeded");
    }
    if state.governance.active_proposals_by(&op.signer_id)
        >= MAX_ACTIVE_GOVERNANCE_PROPOSALS_PER_PROPOSER
    {
        return invalid("proposer already has an active proposal");
    }
    if state
        .governance
        .has_active_proposal_for_action_target(action)
    {
        return invalid(
            "a proposal targeting this parameter is already active - wait for it to resolve before submitting a new one",
        );
    }
    if let Some(last) = state.governance.last_proposal_epoch.get(&op.signer_id) {
        if current_epoch < last.saturating_add(GOVERNANCE_PROPOSAL_COOLDOWN_EPOCHS) {
            return invalid("proposer cooldown not elapsed");
        }
    }
    state
        .governance
        .params
        .validate_action(action)
        .map_err(|reason| StateError::InvalidGovernanceOp { reason })?;

    let deposit = state
        .utxos
        .get(deposit_utxo_id)
        .ok_or_else(|| StateError::InvalidGovernanceOp {
            reason: "deposit UTXO not found".into(),
        })?
        .clone();
    let required_deposit = state.governance.params.proposal_deposit_spark;
    if deposit.output.owner_pubkey != *proposer_pubkey {
        return invalid("proposal deposit UTXO is not owned by the proposer");
    }
    if deposit.output.value_spark < required_deposit {
        return invalid("deposit UTXO value below required proposal deposit");
    }
    let proposal_id = compute_proposal_id(op.signer_id, action, current_epoch, chain_id);
    if state.governance.proposals.contains_key(&proposal_id) {
        return invalid("proposal already exists");
    }
    let change_spark = deposit.output.value_spark.saturating_sub(required_deposit);
    let change_output = if change_spark > 0 {
        Some(governance_change_output(
            proposer_pubkey,
            change_spark,
            proposal_id,
        )?)
    } else {
        None
    };

    let _ = state.utxos.spend_at_height(deposit_utxo_id, current_height);
    if let Some(change_output) = change_output {
        let output_index = state.utxos.len() as u32;
        state
            .utxos
            .insert(change_output, current_height, u32::MAX - 3, output_index)
            .map_err(|_| StateError::InvariantViolation {
                message: "UTXO ID collision in governance deposit change output",
            })?;
    }

    let commit_duration = match action.tier() {
        indra_core::types::governance::ProposalTier::Standard => GOVERNANCE_STANDARD_COMMIT_EPOCHS,
        indra_core::types::governance::ProposalTier::Critical => GOVERNANCE_CRITICAL_COMMIT_EPOCHS,
    };
    let commit_start_epoch = current_epoch.saturating_add(GOVERNANCE_DELIBERATION_EPOCHS);
    let reveal_start_epoch = commit_start_epoch.saturating_add(commit_duration);
    let tally_epoch = reveal_start_epoch.saturating_add(GOVERNANCE_REVEAL_EPOCHS);
    let executable_after_epoch =
        tally_epoch.saturating_add(state.governance.params.governance_delay_epochs);
    let title =
        String::from_utf8(title_bytes.to_vec()).map_err(|_| StateError::InvalidGovernanceOp {
            reason: "title must be valid UTF-8".into(),
        })?;
    let description = String::from_utf8(description_bytes.to_vec()).map_err(|_| {
        StateError::InvalidGovernanceOp {
            reason: "description must be valid UTF-8".into(),
        }
    })?;

    state.governance.proposals.insert(
        proposal_id,
        ProposalRecord {
            proposal_id,
            proposer_id: op.signer_id,
            proposer_pubkey: proposer_pubkey.clone(),
            tier: action.tier(),
            action: action.clone(),
            title,
            description,
            deposit_spark: required_deposit,
            deposit_burned: false,
            proposed_epoch: current_epoch,
            commit_start_epoch,
            reveal_start_epoch,
            tally_epoch,
            exec_delay_epochs: state.governance.params.governance_delay_epochs,
            executable_after_epoch,
            phase: ProposalPhase::Deliberation,
            snapshot1: None,
            commits: Default::default(),
            reveals: Default::default(),
            redelegations: Vec::new(),
            redelegated_delegators: Default::default(),
            snapshot2: None,
            yes_stake: 0,
            no_stake: 0,
            abstain_stake: 0,
            passed: None,
        },
    );
    state
        .governance
        .last_proposal_epoch
        .insert(op.signer_id, current_epoch);
    eprintln!(
        "[governance] proposal {} created by {}",
        hex::encode(&proposal_id.0[..4]),
        hex::encode(&op.signer_id.0[..4])
    );
    Ok(())
}

fn apply_commit(
    state: &mut ChainState,
    op: &GovernanceOpV2,
    current_epoch: u64,
    proposal_id: &Bytes32,
    commit_hash: &Bytes32,
) -> StateResult<()> {
    let proposal = state
        .governance
        .proposals
        .get_mut(proposal_id)
        .ok_or(StateError::GovernanceProposalNotFound)?;
    if proposal.phase != ProposalPhase::Commit {
        return invalid("proposal is not in commit phase");
    }
    let snapshot1 = proposal
        .snapshot1
        .as_ref()
        .ok_or_else(|| StateError::InvalidGovernanceOp {
            reason: "snapshot1 missing".into(),
        })?;
    if !snapshot1.weights.contains_key(&op.signer_id) {
        return invalid("signer is not eligible in snapshot1");
    }
    if proposal.commits.contains_key(&op.signer_id) {
        return invalid("duplicate commit");
    }
    if *commit_hash == Bytes32::ZERO {
        return invalid("commit hash cannot be zero");
    }
    proposal.commits.insert(
        op.signer_id,
        VoteCommit {
            validator_id: op.signer_id,
            commit_hash: *commit_hash,
            committed_epoch: current_epoch,
        },
    );
    Ok(())
}

fn apply_reveal(
    state: &mut ChainState,
    op: &GovernanceOpV2,
    current_epoch: u64,
    proposal_id: &Bytes32,
    vote: u8,
    nonce: &Bytes32,
) -> StateResult<()> {
    if vote > 1 {
        return invalid("vote must be 0 or 1");
    }
    let proposal = state
        .governance
        .proposals
        .get_mut(proposal_id)
        .ok_or(StateError::GovernanceProposalNotFound)?;
    if proposal.phase != ProposalPhase::Reveal {
        return invalid("proposal is not in reveal phase");
    }
    let commit =
        proposal
            .commits
            .get(&op.signer_id)
            .ok_or_else(|| StateError::InvalidGovernanceOp {
                reason: "signer did not commit".into(),
            })?;
    if proposal.reveals.contains_key(&op.signer_id) {
        return invalid("duplicate reveal");
    }
    let expected = governance_vote_commit_hash(*proposal_id, op.signer_id, vote, *nonce);
    if expected != commit.commit_hash {
        return invalid("reveal does not match commit hash");
    }
    proposal.reveals.insert(
        op.signer_id,
        VoteReveal {
            validator_id: op.signer_id,
            vote: vote == 1,
            revealed_epoch: current_epoch,
        },
    );
    Ok(())
}

fn apply_redelegate(
    state: &mut ChainState,
    op: &GovernanceOpV2,
    proposal_id: &Bytes32,
    from_validator: &Bytes32,
    to_validator: &Bytes32,
    amount_spark: u64,
    identity_registry_active: bool,
) -> StateResult<()> {
    if amount_spark == 0 {
        return invalid("redelegation amount cannot be zero");
    }
    {
        let proposal = state
            .governance
            .proposals
            .get(proposal_id)
            .ok_or(StateError::GovernanceProposalNotFound)?;
        if proposal.phase != ProposalPhase::Reveal {
            return invalid("proposal is not in reveal phase");
        }
        if !proposal.reveals.contains_key(from_validator) {
            return invalid("from validator has not revealed");
        }
        if !proposal.reveals.contains_key(to_validator) {
            return invalid("to validator has not revealed");
        }
        if proposal.redelegated_delegators.contains_key(&op.signer_id) {
            return invalid("delegator already redelegated for proposal");
        }
    }
    let should_populate_identity =
        identity_registry_active && !state.delegator_identities.contains_key(&op.signer_id);
    let resolved_identity = if should_populate_identity {
        Some(
            resolve_delegator_identity_for_redelegation(from_validator, &op.signer_id, state)
                .map_err(identity_error_to_governance_error)?,
        )
    } else {
        None
    };
    let entry = state
        .delegations
        .get_delegators(from_validator)
        .iter()
        .find(|entry| entry.delegator_id == op.signer_id && entry.unbonding_end_epoch.is_none())
        .ok_or(StateError::DelegatorNotFound)?;
    if amount_spark > entry.staked_spark {
        return invalid("redelegation exceeds active delegated stake");
    }
    let proposal = state
        .governance
        .proposals
        .get_mut(proposal_id)
        .ok_or(StateError::GovernanceProposalNotFound)?;
    proposal.redelegations.push(GovernanceRedelegation {
        delegator_id: op.signer_id,
        from_validator: *from_validator,
        to_validator: *to_validator,
        amount_spark,
    });
    proposal.redelegated_delegators.insert(op.signer_id, ());
    if let Some(pubkey) = resolved_identity {
        state
            .delegator_identities
            .insert(op.signer_id, pubkey.clone());
        if let Some(commitment) = state.state_commitment_v2.as_mut() {
            commitment.put_delegator_identity(&op.signer_id, &pubkey);
        }
    }
    Ok(())
}

fn apply_execute(
    state: &mut ChainState,
    current_epoch: u64,
    current_height: u64,
    proposal_id: &Bytes32,
) -> StateResult<()> {
    let exec_index = state
        .governance
        .queued_executions
        .iter()
        .position(|exec| exec.proposal_id == *proposal_id)
        .ok_or(StateError::GovernanceProposalNotFound)?;
    let exec = &state.governance.queued_executions[exec_index];
    if exec.executed {
        return invalid("proposal already executed");
    }
    if current_epoch < exec.executable_epoch {
        return invalid("proposal execution delay has not elapsed");
    }
    let action = exec.action.clone();
    if !revalidate_queued_governance_action_or_fail(state, *proposal_id, &action, current_height)? {
        state.governance.queued_executions[exec_index].executed = true;
        return Ok(());
    }
    state.governance.params.apply_action(&action);
    state.governance.queued_executions[exec_index].executed = true;
    if let Some(proposal) = state.governance.proposals.get_mut(proposal_id) {
        proposal.phase = ProposalPhase::Executed;
    }
    eprintln!(
        "[governance] executed proposal {}",
        hex::encode(&proposal_id.0[..4])
    );
    Ok(())
}

/// Revalidate a queued governance action against the current parameter state.
///
/// Actions are validated when proposed, but governance parameters can change
/// before execution. Rechecking here preserves monotonic safety constraints
/// such as "governance YES-stake thresholds can only increase" even when
/// multiple proposals are queued.
pub(crate) fn revalidate_queued_governance_action_or_fail(
    state: &mut ChainState,
    proposal_id: Bytes32,
    action: &indra_core::types::governance::GovernableAction,
    current_height: u64,
) -> StateResult<bool> {
    if let Err(reason) = state.governance.params.validate_action(action) {
        if let Some(proposal) = state.governance.proposals.get_mut(&proposal_id) {
            proposal.phase = ProposalPhase::Failed;
        }
        eprintln!(
            "[governance] queued proposal {} failed execution-time revalidation: {} — marking failed, not applying",
            hex::encode(&proposal_id.0[..4]),
            reason
        );
        return_governance_deposit(state, proposal_id, current_height)?;
        return Ok(false);
    }
    Ok(true)
}

fn apply_cancel(
    state: &mut ChainState,
    op: &GovernanceOpV2,
    proposal_id: &Bytes32,
) -> StateResult<()> {
    let proposal = state
        .governance
        .proposals
        .get_mut(proposal_id)
        .ok_or(StateError::GovernanceProposalNotFound)?;
    if proposal.phase != ProposalPhase::Deliberation {
        return invalid("proposal can only be cancelled during deliberation");
    }
    if op.signer_id != proposal.proposer_id {
        return invalid("only proposer may cancel proposal");
    }
    proposal.phase = ProposalPhase::Cancelled;
    proposal.deposit_burned = true;
    Ok(())
}

fn apply_governance_nonce(
    state: &mut ChainState,
    op: &GovernanceOpV2,
    current_height: u64,
    cold_authorized: bool,
) -> StateResult<()> {
    if cold_authorized {
        let cold_nonce = op
            .cold_authorization()
            .expect("verified cold governance operation has authorization")
            .cold_nonce;
        let validator = state
            .validators
            .get_mut(&op.signer_id)
            .ok_or(StateError::ValidatorNotFound)?;
        validator.cold_nonce = cold_nonce;
        if let Some(commitment) = state.state_commitment_v2.as_mut() {
            commitment.put_validator(validator, current_height);
        }
        return Ok(());
    }
    let expected = state
        .governance
        .gov_nonces
        .get(&op.signer_id)
        .copied()
        .unwrap_or(0)
        .saturating_add(1);
    if op.nonce != expected {
        return Err(StateError::GovernanceNonceInvalid {
            expected,
            got: op.nonce,
        });
    }
    state.governance.gov_nonces.insert(op.signer_id, op.nonce);
    Ok(())
}

fn verify_governance_sig(
    state: &ChainState,
    op: &GovernanceOpV2,
    chain_id: &str,
    identity_registry_active: bool,
) -> StateResult<bool> {
    let cold_designated = matches!(
        op.payload,
        GovernancePayload::Propose { .. }
            | GovernancePayload::Commit { .. }
            | GovernancePayload::Reveal { .. }
            | GovernancePayload::Cancel { .. }
    );
    let active_cold_validator = cold_designated
        && state
            .validators
            .get(&op.signer_id)
            .is_some_and(|validator| validator.cold_key_status == ColdKeyStatus::Active);

    if active_cold_validator {
        let authorization = op.cold_authorization().ok_or_else(|| {
            StateError::InvalidGovernanceOp {
                reason: "active validator cold-designated governance operation requires cold authorization; hot fallback is prohibited".into(),
            }
        })?;
        let validator = state
            .validators
            .get(&op.signer_id)
            .ok_or(StateError::ValidatorNotFound)?;
        if authorization.cold_key_version != validator.cold_key_version {
            return invalid(&format!(
                "cold-key version mismatch: expected {}, got {}",
                validator.cold_key_version, authorization.cold_key_version
            ));
        }
        let expected_cold_nonce =
            validator
                .cold_nonce
                .checked_add(1)
                .ok_or_else(|| StateError::InvalidGovernanceOp {
                    reason: "validator cold nonce exhausted".into(),
                })?;
        if authorization.cold_nonce != expected_cold_nonce {
            return Err(StateError::GovernanceNonceInvalid {
                expected: expected_cold_nonce,
                got: authorization.cold_nonce,
            });
        }
        let pubkey = resolve_active_validator_cold_pubkey(state, &op.signer_id)
            .map_err(identity_error_to_governance_error)?;
        if let GovernancePayload::Propose {
            proposer_pubkey, ..
        } = &op.payload
        {
            if proposer_pubkey != &pubkey {
                return invalid("cold proposal deposit owner must equal registered cold key");
            }
        }
        let signing_bytes = op
            .cold_authorization_signing_bytes(chain_id)
            .map_err(|error| StateError::InvalidGovernanceOp {
                reason: error.to_string(),
            })?
            .ok_or_else(|| StateError::InvalidGovernanceOp {
                reason: "active validator operation is missing canonical cold authorization".into(),
            })?;
        verify_governance_sig_with_pubkey(&signing_bytes, &op.signature, &pubkey)?;
        return Ok(true);
    }

    if op.cold_authorization().is_some() {
        return invalid("cold authorization is valid only for an Active validator");
    }
    let pubkey = governance_signer_pubkey(state, op, identity_registry_active)?;
    let domain = governance_signing_domain(
        op.action_type,
        op.signer_id,
        op.nonce,
        &op.payload,
        chain_id,
    );
    let msg_hash = sha256(&domain);
    verify_governance_sig_with_pubkey(&msg_hash, &op.signature, &pubkey)?;
    Ok(false)
}

fn verify_governance_sig_with_pubkey(
    message: &[u8],
    signature: &indra_core::types::crypto::HybridSignature,
    pubkey: &HybridPubKey,
) -> StateResult<()> {
    let sig = signature
        .to_crypto_sig()
        .map_err(|reason| StateError::GovernanceSignatureInvalid { reason })?;
    let pk = pubkey
        .to_crypto_pubkey()
        .map_err(|reason| StateError::GovernanceSignatureInvalid { reason })?;
    verify_hybrid(message, &sig, &pk).map_err(|e| StateError::GovernanceSignatureInvalid {
        reason: e.to_string(),
    })
}

fn governance_signer_pubkey(
    state: &ChainState,
    op: &GovernanceOpV2,
    identity_registry_active: bool,
) -> StateResult<HybridPubKey> {
    match &op.payload {
        GovernancePayload::Propose {
            proposer_pubkey, ..
        } => {
            if pubkey_to_id(proposer_pubkey) != op.signer_id {
                return Err(StateError::GovernanceSignatureInvalid {
                    reason: "proposer pubkey does not match signer_id".into(),
                });
            }
            Ok(proposer_pubkey.clone())
        }
        GovernancePayload::Commit { .. } | GovernancePayload::Reveal { .. } => {
            validator_pubkey(state, &op.signer_id)
        }
        GovernancePayload::Redelegate { from_validator, .. } => {
            if identity_registry_active {
                resolve_delegator_identity_for_redelegation(from_validator, &op.signer_id, state)
                    .map_err(identity_error_to_governance_error)
            } else {
                delegation_pubkey(state, from_validator, &op.signer_id)
            }
        }
        GovernancePayload::Execute { .. } => validator_pubkey(state, &op.signer_id),
        GovernancePayload::Cancel { proposal_id, .. } => {
            if let Some(proposal) = state.governance.proposals.get(proposal_id) {
                if proposal.proposer_id == op.signer_id {
                    return Ok(proposal.proposer_pubkey.clone());
                }
            }
            validator_pubkey(state, &op.signer_id)
        }
    }
}

fn validator_pubkey(state: &ChainState, validator_id: &Bytes32) -> StateResult<HybridPubKey> {
    let validator = state
        .validators
        .get(validator_id)
        .ok_or(StateError::ValidatorNotFound)?;
    let classical_pk =
        validator
            .hybrid_classical_pk
            .ok_or_else(|| StateError::GovernanceSignatureInvalid {
                reason: "validator has no classical public key".into(),
            })?;
    let pq_pk =
        validator
            .hybrid_pq_pk
            .clone()
            .ok_or_else(|| StateError::GovernanceSignatureInvalid {
                reason: "validator has no PQ public key".into(),
            })?;
    Ok(HybridPubKey {
        classical_pk: Bytes32::from(classical_pk),
        pq_pk: indra_core::VariableBytes::from_slice(&pq_pk).map_err(|_| {
            StateError::GovernanceSignatureInvalid {
                reason: "PQ public key too large".into(),
            }
        })?,
    })
}

fn delegation_pubkey(
    state: &ChainState,
    validator_id: &Bytes32,
    delegator_id: &Bytes32,
) -> StateResult<HybridPubKey> {
    state
        .staked_bonds
        .values()
        .find(|bond| {
            &bond.validator_id == validator_id
                && &bond.delegator_id == delegator_id
                && bond.unbonding_end_epoch.is_none()
        })
        .and_then(|bond| bond.original_output.owner_pubkey.clone())
        .ok_or(StateError::DelegatorNotFound)
}

fn identity_error_to_governance_error(err: IdentityError) -> StateError {
    let reason = match err {
        IdentityError::RegistryPubkeyMismatch { delegator_id } => {
            format!("delegator identity registry pubkey mismatch for {delegator_id}")
        }
        IdentityError::LegacyPubkeyMismatch { delegator_id } => {
            format!("delegator identity legacy pubkey mismatch for {delegator_id}")
        }
        IdentityError::AmbiguousLegacyPubkeys { delegator_id } => {
            format!("delegator identity has ambiguous legacy pubkeys for {delegator_id}")
        }
        IdentityError::UnresolvableIdentity {
            validator_id,
            delegator_id,
        } => match validator_id {
            Some(validator_id) => {
                format!(
                    "delegator identity is unresolvable for {delegator_id} from validator {validator_id}"
                )
            }
            None => format!("delegator identity is unresolvable for {delegator_id}"),
        },
    };
    StateError::InvalidGovernanceOp { reason }
}

/// Return a deposit to a proposer as a new UTXO.
pub fn return_governance_deposit(
    state: &mut ChainState,
    proposal_id: Bytes32,
    current_height: u64,
) -> StateResult<()> {
    let Some(proposal) = state.governance.proposals.get(&proposal_id).cloned() else {
        return Err(StateError::GovernanceProposalNotFound);
    };
    if proposal.deposit_burned || proposal.deposit_spark == 0 {
        return Ok(());
    }
    // Deposit refund goes to proposer_pubkey, which is the same entity that
    // owns the deposit UTXO (enforced at proposal time).
    let output = governance_refund_output(
        &proposal.proposer_pubkey,
        proposal.deposit_spark,
        proposal_id,
    )?;
    let output_index = state.utxos.len() as u32;
    state
        .utxos
        .insert(output, current_height, u32::MAX - 2, output_index)
        .map_err(|_| StateError::InvariantViolation {
            message: "UTXO ID collision in governance refund output",
        })?;
    if let Some(proposal) = state.governance.proposals.get_mut(&proposal_id) {
        proposal.deposit_spark = 0;
    }
    Ok(())
}

fn governance_refund_output(
    owner: &HybridPubKey,
    amount_spark: u64,
    proposal_id: Bytes32,
) -> StateResult<OutputV1> {
    let blinding = sha256(
        &[
            b"governance-refund-blinding".as_slice(),
            proposal_id.0.as_slice(),
        ]
        .concat(),
    );
    let commitment = commit(amount_spark, &blinding);
    let mut rng = StdRng::from_seed(proposal_id.0);
    let proof = prove_range(amount_spark, &blinding, &mut rng).map_err(|_| {
        StateError::InvalidGovernanceOp {
            reason: "failed to generate governance refund range proof".into(),
        }
    })?;
    Ok(OutputV1 {
        value_spark: amount_spark,
        commitment: indra_core::types::crypto::CommitmentV1 {
            compressed_point: Bytes32::from(commitment.0),
        },
        owner_pubkey: owner.clone(),
        range_proof: indra_core::VariableBytes::from_slice(&proof).map_err(|_| {
            StateError::InvalidGovernanceOp {
                reason: "governance refund range proof too large".into(),
            }
        })?,
        lock_height: 0,
    })
}

fn governance_change_output(
    owner: &HybridPubKey,
    amount_spark: u64,
    proposal_id: Bytes32,
) -> StateResult<OutputV1> {
    let blinding = sha256(
        &[
            b"governance-deposit-change-blinding".as_slice(),
            proposal_id.0.as_slice(),
        ]
        .concat(),
    );
    let commitment = commit(amount_spark, &blinding);
    let mut rng = StdRng::from_seed(sha256(
        &[
            b"governance-deposit-change-proof".as_slice(),
            proposal_id.0.as_slice(),
        ]
        .concat(),
    ));
    let proof = prove_range(amount_spark, &blinding, &mut rng).map_err(|_| {
        StateError::InvalidGovernanceOp {
            reason: "failed to generate governance change range proof".into(),
        }
    })?;
    Ok(OutputV1 {
        value_spark: amount_spark,
        commitment: indra_core::types::crypto::CommitmentV1 {
            compressed_point: Bytes32::from(commitment.0),
        },
        owner_pubkey: owner.clone(),
        range_proof: indra_core::VariableBytes::from_slice(&proof).map_err(|_| {
            StateError::InvalidGovernanceOp {
                reason: "governance change range proof too large".into(),
            }
        })?,
        lock_height: 0,
    })
}

fn pubkey_to_id(pubkey: &HybridPubKey) -> Bytes32 {
    Bytes32::from(sha256(&pubkey.classical_pk.0))
}

fn invalid<T>(reason: impl Into<String>) -> StateResult<T> {
    Err(StateError::InvalidGovernanceOp {
        reason: reason.into(),
    })
}

#[allow(dead_code)]
fn _assert_params_send(_: &GovernableParams, _: &GovernanceState) {}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        codec::Encode,
        types::{
            crypto::{CommitmentV1, HybridSignature},
            governance::{ColdGovernanceAuthorization, GovernableAction, GovernanceActionType},
            primitives::{
                VariableBytes, DEFAULT_CHAIN_ID, DEFAULT_COMMISSION_BPS, DUST_LIMIT_SPARK,
            },
            staking::{ColdStakingAuthorization, StakingOp, StakingOpBody},
        },
        Bytes32,
    };
    use indra_crypto::{ClassicalKeypair, HybridKeypair, PqKeypair};

    use crate::{delegation::apply_staking_op, validator::StakeBondEntry};

    fn keypair(seed: u8) -> (HybridPubKey, HybridKeypair) {
        let seed = [seed; 32];
        let classical = ClassicalKeypair::from_seed(&seed);
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let keypair = HybridKeypair::new(classical, pq);
        let public = keypair.public_key();
        (
            HybridPubKey {
                classical_pk: Bytes32::from(public.classical.0),
                pq_pk: VariableBytes::from_slice(&public.pq.0).unwrap(),
            },
            keypair,
        )
    }

    fn mixed_keypair(classical_seed: u8, pq_seed: u8) -> (HybridPubKey, HybridKeypair) {
        let classical = ClassicalKeypair::from_seed(&[classical_seed; 32]);
        let pq = PqKeypair::from_seed(&[pq_seed; 32]).unwrap();
        let keypair = HybridKeypair::new(classical, pq);
        let public = keypair.public_key();
        (
            HybridPubKey {
                classical_pk: Bytes32::from(public.classical.0),
                pq_pk: VariableBytes::from_slice(&public.pq.0).unwrap(),
            },
            keypair,
        )
    }

    fn dummy_sig() -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
        }
    }

    fn sign_governance_op(op: &mut GovernanceOpV2, keypair: &HybridKeypair, chain_id: &str) {
        let domain = governance_signing_domain(
            op.action_type,
            op.signer_id,
            op.nonce,
            &op.payload,
            chain_id,
        );
        let msg_hash = sha256(&domain);
        let sig = keypair.sign(&msg_hash).unwrap();
        op.signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
        };
    }

    fn activate_cold_key(
        state: &mut ChainState,
        validator_id: Bytes32,
        cold_keypair: &HybridKeypair,
    ) {
        let public = cold_keypair.public_key();
        let validator = state.validators.get_mut(&validator_id).unwrap();
        validator.cold_hybrid_classical_pk = Some(public.classical.0);
        validator.cold_hybrid_pq_pk = Some(public.pq.0);
        validator.cold_key_version = 1;
        validator.cold_key_status = ColdKeyStatus::Active;
        validator.cold_nonce = 0;
    }

    fn set_cold_authorization(op: &mut GovernanceOpV2, cold_nonce: u64) {
        let authorization = Some(ColdGovernanceAuthorization {
            cold_key_version: 1,
            cold_nonce,
        });
        match &mut op.payload {
            GovernancePayload::Propose {
                cold_authorization, ..
            }
            | GovernancePayload::Commit {
                cold_authorization, ..
            }
            | GovernancePayload::Reveal {
                cold_authorization, ..
            }
            | GovernancePayload::Cancel {
                cold_authorization, ..
            } => *cold_authorization = authorization,
            GovernancePayload::Redelegate { .. } | GovernancePayload::Execute { .. } => {
                panic!("operation has no cold governance form")
            }
        }
        op.nonce = 0;
    }

    fn sign_cold_governance_op(
        op: &mut GovernanceOpV2,
        cold_keypair: &HybridKeypair,
        chain_id: &str,
    ) {
        let bytes = op
            .cold_authorization_signing_bytes(chain_id)
            .unwrap()
            .unwrap();
        let sig = cold_keypair.sign(&bytes).unwrap();
        op.signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
        };
    }

    fn sign_cold_staking_op(op: &mut StakingOp, cold_keypair: &HybridKeypair, chain_id: &str) {
        let bytes = op
            .cold_authorization_signing_bytes(chain_id)
            .unwrap()
            .unwrap();
        let sig = cold_keypair.sign(&bytes).unwrap();
        op.signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
        };
    }

    fn install_governance_validator(state: &mut ChainState, pubkey: &HybridPubKey) -> Bytes32 {
        let validator_id = pubkey_to_id(pubkey);
        state
            .validators
            .upsert(crate::validator::ValidatorEntry {
                validator_id,
                name: "governance-test-validator".into(),
                hybrid_classical_pk: Some(pubkey.classical_pk.0),
                hybrid_pq_pk: Some(pubkey.pq_pk.as_slice().to_vec()),
                vrf_pk: Some([validator_id.0[0]; 32]),
                stake_spark: 1_000,
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
            })
            .unwrap();
        validator_id
    }

    fn deposit_output(owner_pubkey: HybridPubKey, value_spark: u64) -> OutputV1 {
        OutputV1 {
            value_spark,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::ZERO,
            },
            owner_pubkey,
            range_proof: VariableBytes::from_slice(&[]).unwrap(),
            lock_height: 0,
        }
    }

    fn redelegate_op(
        signer_id: Bytes32,
        keypair: &HybridKeypair,
        proposal_id: Bytes32,
        from_validator: Bytes32,
        to_validator: Bytes32,
        amount_spark: u64,
        nonce: u64,
    ) -> GovernanceOpV2 {
        let payload = GovernancePayload::Redelegate {
            proposal_id,
            from_validator,
            to_validator,
            amount_spark,
        };
        let mut op = GovernanceOpV2 {
            action_type: GovernanceActionType::GovernanceRedelegate,
            signer_id,
            nonce,
            payload,
            signature: dummy_sig(),
        };
        sign_governance_op(&mut op, keypair, DEFAULT_CHAIN_ID);
        op
    }

    fn propose_op(
        signer_id: Bytes32,
        keypair: &HybridKeypair,
        proposer_pubkey: HybridPubKey,
        deposit_utxo_id: Bytes32,
        nonce: u64,
    ) -> GovernanceOpV2 {
        propose_op_with_action(
            signer_id,
            keypair,
            proposer_pubkey,
            deposit_utxo_id,
            nonce,
            GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK,
            },
        )
    }

    fn propose_op_with_action(
        signer_id: Bytes32,
        keypair: &HybridKeypair,
        proposer_pubkey: HybridPubKey,
        deposit_utxo_id: Bytes32,
        nonce: u64,
        action: GovernableAction,
    ) -> GovernanceOpV2 {
        let payload = GovernancePayload::Propose {
            action,
            deposit_utxo_id,
            proposer_pubkey,
            title: VariableBytes::from_slice(b"test").unwrap(),
            description: VariableBytes::from_slice(b"test proposal").unwrap(),
            cold_authorization: None,
        };
        let mut op = GovernanceOpV2 {
            action_type: GovernanceActionType::ProposeChange,
            signer_id,
            nonce,
            payload,
            signature: dummy_sig(),
        };
        sign_governance_op(&mut op, keypair, DEFAULT_CHAIN_ID);
        op
    }

    fn install_proposer_with_deposit(
        state: &mut ChainState,
        seed: u8,
        deposit_value: u64,
        output_index: u32,
    ) -> (HybridPubKey, HybridKeypair, Bytes32, Bytes32) {
        let (pubkey, keypair) = keypair(seed);
        let proposer_id = install_governance_validator(state, &pubkey);
        let deposit = state
            .utxos
            .insert(
                deposit_output(pubkey.clone(), deposit_value),
                0,
                0,
                output_index,
            )
            .unwrap();
        (pubkey, keypair, proposer_id, deposit)
    }

    fn proposal_record(
        proposal_id: Bytes32,
        proposer_pubkey: HybridPubKey,
        action: GovernableAction,
        phase: ProposalPhase,
    ) -> ProposalRecord {
        ProposalRecord {
            proposal_id,
            proposer_id: pubkey_to_id(&proposer_pubkey),
            proposer_pubkey,
            tier: action.tier(),
            action,
            title: "queued".into(),
            description: "queued".into(),
            deposit_spark: 0,
            deposit_burned: false,
            proposed_epoch: 0,
            commit_start_epoch: 0,
            reveal_start_epoch: 0,
            tally_epoch: 0,
            exec_delay_epochs: 0,
            executable_after_epoch: 0,
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
            passed: Some(true),
        }
    }

    fn install_reveal_phase_proposal(
        state: &mut ChainState,
        proposal_id: Bytes32,
        from_validator: Bytes32,
        to_validator: Bytes32,
    ) {
        let (proposer_pubkey, _) = keypair(proposal_id.0[0]);
        let mut proposal = proposal_record(
            proposal_id,
            proposer_pubkey,
            GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK,
            },
            ProposalPhase::Reveal,
        );
        proposal.reveals.insert(
            from_validator,
            VoteReveal {
                validator_id: from_validator,
                vote: true,
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
        state.governance.proposals.insert(proposal_id, proposal);
    }

    fn install_legacy_redelegation_bond(
        state: &mut ChainState,
        bond_utxo_id: Bytes32,
        validator_id: Bytes32,
        delegator_id: Bytes32,
        owner_pubkey: HybridPubKey,
        amount_spark: u64,
        byte: u8,
    ) {
        let bond = StakeBondEntry::new_for_test_with_compact_activation(
            bond_utxo_id,
            validator_id,
            delegator_id,
            amount_spark,
            0,
            deposit_output(owner_pubkey, amount_spark),
            0,
            u64::MAX,
        );
        assert!(bond.original_output.range_proof.is_some());
        state.staked_bonds.insert(bond_utxo_id, bond);
        state
            .delegations
            .add_delegation(validator_id, delegator_id, amount_spark, 0)
            .unwrap_or_else(|err| panic!("legacy redelegation bond {byte:#x} failed: {err}"));
    }

    fn install_fully_compact_redelegation_bond(
        state: &mut ChainState,
        bond_utxo_id: Bytes32,
        validator_id: Bytes32,
        delegator_id: Bytes32,
        owner_pubkey: HybridPubKey,
        amount_spark: u64,
    ) {
        let bond = StakeBondEntry::new_for_test_with_compact_and_pubkey_activation(
            bond_utxo_id,
            validator_id,
            delegator_id,
            amount_spark,
            0,
            deposit_output(owner_pubkey, amount_spark),
            2,
            1,
            2,
        );
        assert!(bond.original_output.range_proof.is_none());
        assert!(bond.original_output.owner_pubkey.is_none());
        state.staked_bonds.insert(bond_utxo_id, bond);
        state
            .delegations
            .add_delegation(validator_id, delegator_id, amount_spark, 0)
            .unwrap();
    }

    #[test]
    fn governance_redelegation_pre_identity_gate_uses_first_matching_active_bond() {
        let mut state = ChainState::new_genesis();
        let from_validator = Bytes32::from([0xA0; 32]);
        let to_validator = Bytes32::from([0xA1; 32]);
        let proposal_id = Bytes32::from([0xA2; 32]);
        install_reveal_phase_proposal(&mut state, proposal_id, from_validator, to_validator);
        let (first_pubkey, first_keypair) = mixed_keypair(0xA3, 0xA4);
        let (second_pubkey, _) = mixed_keypair(0xA3, 0xA5);
        let delegator_id = pubkey_to_id(&first_pubkey);
        assert_eq!(pubkey_to_id(&second_pubkey), delegator_id);
        install_legacy_redelegation_bond(
            &mut state,
            Bytes32::from([0x01; 32]),
            from_validator,
            delegator_id,
            first_pubkey,
            1_000,
            0x01,
        );
        install_legacy_redelegation_bond(
            &mut state,
            Bytes32::from([0x02; 32]),
            from_validator,
            delegator_id,
            second_pubkey,
            1_000,
            0x02,
        );

        let op = redelegate_op(
            delegator_id,
            &first_keypair,
            proposal_id,
            from_validator,
            to_validator,
            500,
            1,
        );

        apply_governance_op(&mut state, &op, 0, 0, DEFAULT_CHAIN_ID).unwrap();

        let proposal = state.governance.proposals.get(&proposal_id).unwrap();
        assert_eq!(proposal.redelegations.len(), 1);
        assert!(state.delegator_identities.is_empty());
    }

    #[test]
    fn governance_redelegation_post_identity_gate_registry_entry_verifies() {
        let mut state = ChainState::new_genesis();
        let from_validator = Bytes32::from([0xA6; 32]);
        let to_validator = Bytes32::from([0xA7; 32]);
        let proposal_id = Bytes32::from([0xA8; 32]);
        install_reveal_phase_proposal(&mut state, proposal_id, from_validator, to_validator);
        let (delegator_pubkey, delegator_keypair) = keypair(0xA9);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        state
            .delegator_identities
            .insert(delegator_id, delegator_pubkey.clone());
        install_legacy_redelegation_bond(
            &mut state,
            Bytes32::from([0x03; 32]),
            from_validator,
            delegator_id,
            delegator_pubkey.clone(),
            1_000,
            0x03,
        );
        let before_registry = state.delegator_identities.clone();

        let op = redelegate_op(
            delegator_id,
            &delegator_keypair,
            proposal_id,
            from_validator,
            to_validator,
            500,
            1,
        );

        apply_governance_op(&mut state, &op, 0, u64::MAX, DEFAULT_CHAIN_ID).unwrap();

        let proposal = state.governance.proposals.get(&proposal_id).unwrap();
        assert_eq!(proposal.redelegations.len(), 1);
        assert_eq!(state.delegator_identities, before_registry);
    }

    #[test]
    fn active_validator_cold_governance_authorizes_all_discretionary_actions() {
        let mut state = ChainState::new_genesis();
        state.governance.params.proposal_deposit_spark = 1_000;
        let (hot_pubkey, hot_keypair) = keypair(0xD1);
        let validator_id = install_governance_validator(&mut state, &hot_pubkey);
        let (cold_pubkey, cold_keypair) = keypair(0xD2);
        activate_cold_key(&mut state, validator_id, &cold_keypair);

        let deposit = state
            .utxos
            .insert(deposit_output(cold_pubkey.clone(), 1_000), 0, 0, 0)
            .unwrap();
        let mut propose = propose_op(validator_id, &hot_keypair, cold_pubkey.clone(), deposit, 1);
        set_cold_authorization(&mut propose, 1);
        sign_cold_governance_op(&mut propose, &cold_keypair, DEFAULT_CHAIN_ID);
        apply_governance_op(&mut state, &propose, 0, u64::MAX, DEFAULT_CHAIN_ID).unwrap();
        let proposal_id = compute_proposal_id(
            validator_id,
            &GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK,
            },
            0,
            DEFAULT_CHAIN_ID,
        );

        let mut cancel = GovernanceOpV2 {
            action_type: GovernanceActionType::CancelProposal,
            signer_id: validator_id,
            nonce: 0,
            payload: GovernancePayload::Cancel {
                proposal_id,
                cold_authorization: Some(ColdGovernanceAuthorization {
                    cold_key_version: 1,
                    cold_nonce: 2,
                }),
            },
            signature: dummy_sig(),
        };
        sign_cold_governance_op(&mut cancel, &cold_keypair, DEFAULT_CHAIN_ID);
        apply_governance_op(&mut state, &cancel, 0, u64::MAX, DEFAULT_CHAIN_ID).unwrap();

        let vote_proposal_id = Bytes32::from([0xD3; 32]);
        let vote_nonce = Bytes32::from([0xD4; 32]);
        let commit_hash =
            governance_vote_commit_hash(vote_proposal_id, validator_id, 1, vote_nonce);
        let mut vote_proposal = proposal_record(
            vote_proposal_id,
            cold_pubkey,
            GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK,
            },
            ProposalPhase::Commit,
        );
        vote_proposal.proposer_id = validator_id;
        vote_proposal.snapshot1 = Some(crate::governance::GovernanceSnapshot {
            weights: [(validator_id, 1_000)].into_iter().collect(),
            total_stake: 1_000,
        });
        state
            .governance
            .proposals
            .insert(vote_proposal_id, vote_proposal);

        let mut commit = GovernanceOpV2 {
            action_type: GovernanceActionType::CommitVote,
            signer_id: validator_id,
            nonce: 0,
            payload: GovernancePayload::Commit {
                proposal_id: vote_proposal_id,
                commit_hash,
                cold_authorization: Some(ColdGovernanceAuthorization {
                    cold_key_version: 1,
                    cold_nonce: 3,
                }),
            },
            signature: dummy_sig(),
        };
        sign_cold_governance_op(&mut commit, &cold_keypair, DEFAULT_CHAIN_ID);
        apply_governance_op(&mut state, &commit, 0, u64::MAX, DEFAULT_CHAIN_ID).unwrap();

        state
            .governance
            .proposals
            .get_mut(&vote_proposal_id)
            .unwrap()
            .phase = ProposalPhase::Reveal;
        let mut reveal = GovernanceOpV2 {
            action_type: GovernanceActionType::RevealVote,
            signer_id: validator_id,
            nonce: 0,
            payload: GovernancePayload::Reveal {
                proposal_id: vote_proposal_id,
                vote: 1,
                nonce: vote_nonce,
                cold_authorization: Some(ColdGovernanceAuthorization {
                    cold_key_version: 1,
                    cold_nonce: 4,
                }),
            },
            signature: dummy_sig(),
        };
        sign_cold_governance_op(&mut reveal, &cold_keypair, DEFAULT_CHAIN_ID);
        apply_governance_op(&mut state, &reveal, 0, u64::MAX, DEFAULT_CHAIN_ID).unwrap();

        assert_eq!(state.validators.get(&validator_id).unwrap().cold_nonce, 4);
        assert!(state.governance.gov_nonces.get(&validator_id).is_none());
        assert_eq!(
            state.governance.proposals[&proposal_id].phase,
            ProposalPhase::Cancelled
        );
        assert!(state.governance.proposals[&vote_proposal_id]
            .reveals
            .contains_key(&validator_id));
    }

    #[test]
    fn active_validator_governance_rejects_both_hot_bypass_shapes() {
        let mut state = ChainState::new_genesis();
        let (hot_pubkey, hot_keypair) = keypair(0xD5);
        let validator_id = install_governance_validator(&mut state, &hot_pubkey);
        let (_, cold_keypair) = keypair(0xD6);
        activate_cold_key(&mut state, validator_id, &cold_keypair);
        let mut legacy_hot = GovernanceOpV2 {
            action_type: GovernanceActionType::CommitVote,
            signer_id: validator_id,
            nonce: 1,
            payload: GovernancePayload::Commit {
                proposal_id: Bytes32::from([0xD7; 32]),
                commit_hash: Bytes32::from([0xD8; 32]),
                cold_authorization: None,
            },
            signature: dummy_sig(),
        };
        sign_governance_op(&mut legacy_hot, &hot_keypair, DEFAULT_CHAIN_ID);
        assert!(matches!(
            apply_governance_op(&mut state, &legacy_hot, 0, u64::MAX, DEFAULT_CHAIN_ID),
            Err(StateError::InvalidGovernanceOp { reason })
                if reason.contains("hot fallback is prohibited")
        ));

        let mut cold_form_signed_hot = legacy_hot;
        set_cold_authorization(&mut cold_form_signed_hot, 1);
        sign_cold_governance_op(&mut cold_form_signed_hot, &hot_keypair, DEFAULT_CHAIN_ID);
        assert!(matches!(
            apply_governance_op(
                &mut state,
                &cold_form_signed_hot,
                0,
                u64::MAX,
                DEFAULT_CHAIN_ID
            ),
            Err(StateError::GovernanceSignatureInvalid { .. })
        ));
        assert_eq!(state.validators.get(&validator_id).unwrap().cold_nonce, 0);
    }

    #[test]
    fn execute_remains_hot_for_active_cold_validator() {
        let mut state = ChainState::new_genesis();
        let (hot_pubkey, hot_keypair) = keypair(0xD9);
        let validator_id = install_governance_validator(&mut state, &hot_pubkey);
        let (_, cold_keypair) = keypair(0xDA);
        activate_cold_key(&mut state, validator_id, &cold_keypair);
        let proposal_id = Bytes32::from([0xDB; 32]);
        state
            .governance
            .queued_executions
            .push(crate::governance::QueuedExecution {
                proposal_id,
                action: GovernableAction::SetMinDelegationSpark {
                    value: DUST_LIMIT_SPARK,
                },
                executable_epoch: 0,
                executed: false,
            });
        let mut execute = GovernanceOpV2 {
            action_type: GovernanceActionType::ExecuteProposal,
            signer_id: validator_id,
            nonce: 1,
            payload: GovernancePayload::Execute { proposal_id },
            signature: dummy_sig(),
        };
        sign_governance_op(&mut execute, &hot_keypair, DEFAULT_CHAIN_ID);
        apply_governance_op(&mut state, &execute, 0, u64::MAX, DEFAULT_CHAIN_ID).unwrap();
        assert!(state.governance.queued_executions[0].executed);
        assert_eq!(state.governance.gov_nonces.get(&validator_id), Some(&1));
        assert_eq!(state.validators.get(&validator_id).unwrap().cold_nonce, 0);
    }

    #[test]
    fn validator_cold_enrollment_does_not_change_delegator_redelegate_authority() {
        let mut state = ChainState::new_genesis();
        let (validator_pubkey, _) = keypair(0xDC);
        let enrolled_validator = install_governance_validator(&mut state, &validator_pubkey);
        let (_, cold_keypair) = keypair(0xDD);
        activate_cold_key(&mut state, enrolled_validator, &cold_keypair);
        let from_validator = Bytes32::from([0xDE; 32]);
        let to_validator = Bytes32::from([0xDF; 32]);
        let proposal_id = Bytes32::from([0xE0; 32]);
        install_reveal_phase_proposal(&mut state, proposal_id, from_validator, to_validator);
        let (delegator_pubkey, delegator_keypair) = keypair(0xE1);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        state
            .delegator_identities
            .insert(delegator_id, delegator_pubkey.clone());
        install_legacy_redelegation_bond(
            &mut state,
            Bytes32::from([0xE2; 32]),
            from_validator,
            delegator_id,
            delegator_pubkey,
            1_000,
            0xE2,
        );
        let op = redelegate_op(
            delegator_id,
            &delegator_keypair,
            proposal_id,
            from_validator,
            to_validator,
            500,
            1,
        );
        apply_governance_op(&mut state, &op, 0, u64::MAX, DEFAULT_CHAIN_ID).unwrap();
        assert_eq!(
            state.governance.proposals[&proposal_id].redelegations[0].delegator_id,
            delegator_id
        );
        assert_eq!(
            state
                .validators
                .get(&enrolled_validator)
                .unwrap()
                .cold_nonce,
            0
        );
    }

    #[test]
    fn mixed_hot_cold_governance_and_staking_replay_is_deterministic() {
        let mut base = ChainState::new_genesis();
        base.governance.params.proposal_deposit_spark = 1_000;

        let (active_hot_pubkey, active_hot_keypair) = keypair(0xE3);
        let active_id = install_governance_validator(&mut base, &active_hot_pubkey);
        let (active_cold_pubkey, active_cold_keypair) = keypair(0xE4);
        activate_cold_key(&mut base, active_id, &active_cold_keypair);
        let cold_deposit = base
            .utxos
            .insert(deposit_output(active_cold_pubkey.clone(), 1_000), 0, 0, 1)
            .unwrap();
        let mut cold_propose = propose_op(
            active_id,
            &active_hot_keypair,
            active_cold_pubkey,
            cold_deposit,
            1,
        );
        set_cold_authorization(&mut cold_propose, 1);
        sign_cold_governance_op(&mut cold_propose, &active_cold_keypair, DEFAULT_CHAIN_ID);

        let mut cold_commission = StakingOp {
            body: StakingOpBody::SetCommission {
                validator_id: active_id,
                new_commission_bps: 900,
                cold_authorization: Some(ColdStakingAuthorization {
                    cold_key_version: 1,
                    cold_nonce: 2,
                }),
            },
            nonce: 0,
            signature: dummy_sig(),
        };
        sign_cold_staking_op(&mut cold_commission, &active_cold_keypair, DEFAULT_CHAIN_ID);

        let (legacy_pubkey, legacy_keypair) = keypair(0xE5);
        let legacy_id = install_governance_validator(&mut base, &legacy_pubkey);
        let legacy_deposit = base
            .utxos
            .insert(deposit_output(legacy_pubkey.clone(), 1_000), 0, 0, 2)
            .unwrap();
        let legacy_propose = propose_op_with_action(
            legacy_id,
            &legacy_keypair,
            legacy_pubkey,
            legacy_deposit,
            1,
            GovernableAction::SetSlashLivenessThresholdEpochs { value: 2 },
        );

        let replay = |state: &mut ChainState| {
            apply_governance_op(state, &cold_propose, 0, u64::MAX, DEFAULT_CHAIN_ID).unwrap();
            apply_staking_op(state, &cold_commission, DEFAULT_CHAIN_ID, u64::MAX).unwrap();
            apply_governance_op(state, &legacy_propose, 0, u64::MAX, DEFAULT_CHAIN_ID).unwrap();
        };
        let mut first = base.clone();
        let mut second = base;
        replay(&mut first);
        replay(&mut second);

        assert_eq!(first, second);
        assert_eq!(first.validators.get(&active_id).unwrap().cold_nonce, 2);
        assert_eq!(first.governance.gov_nonces.get(&legacy_id), Some(&1));
        assert!(first.governance.gov_nonces.get(&active_id).is_none());
    }

    #[test]
    fn governance_redelegation_post_identity_gate_fully_compact_bond_uses_registry_pubkey() {
        let mut state = ChainState::new_genesis();
        let from_validator = Bytes32::from([0xA9; 32]);
        let to_validator = Bytes32::from([0xAA; 32]);
        let proposal_id = Bytes32::from([0xAB; 32]);
        install_reveal_phase_proposal(&mut state, proposal_id, from_validator, to_validator);
        let (delegator_pubkey, delegator_keypair) = keypair(0xAC);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        state
            .delegator_identities
            .insert(delegator_id, delegator_pubkey.clone());
        install_fully_compact_redelegation_bond(
            &mut state,
            Bytes32::from([0x33; 32]),
            from_validator,
            delegator_id,
            delegator_pubkey.clone(),
            1_000,
        );

        let op = redelegate_op(
            delegator_id,
            &delegator_keypair,
            proposal_id,
            from_validator,
            to_validator,
            500,
            1,
        );

        apply_governance_op(&mut state, &op, 0, u64::MAX, DEFAULT_CHAIN_ID).unwrap();

        let proposal = state.governance.proposals.get(&proposal_id).unwrap();
        assert_eq!(proposal.redelegations.len(), 1);
        assert_eq!(proposal.redelegations[0].delegator_id, delegator_id);
    }

    #[test]
    fn governance_redelegation_post_identity_gate_unambiguous_legacy_fallback_verifies_and_populates(
    ) {
        let mut state = ChainState::new_genesis();
        let from_validator = Bytes32::from([0xAA; 32]);
        let to_validator = Bytes32::from([0xAB; 32]);
        let proposal_id = Bytes32::from([0xAC; 32]);
        install_reveal_phase_proposal(&mut state, proposal_id, from_validator, to_validator);
        let (delegator_pubkey, delegator_keypair) = keypair(0xAD);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        install_legacy_redelegation_bond(
            &mut state,
            Bytes32::from([0x04; 32]),
            from_validator,
            delegator_id,
            delegator_pubkey.clone(),
            1_000,
            0x04,
        );
        assert!(state.delegator_identities.is_empty());

        let op = redelegate_op(
            delegator_id,
            &delegator_keypair,
            proposal_id,
            from_validator,
            to_validator,
            500,
            1,
        );

        apply_governance_op(&mut state, &op, 0, u64::MAX, DEFAULT_CHAIN_ID).unwrap();

        let proposal = state.governance.proposals.get(&proposal_id).unwrap();
        assert_eq!(proposal.redelegations.len(), 1);
        assert_eq!(
            state.delegator_identities.get(&delegator_id),
            Some(&delegator_pubkey)
        );
    }

    #[test]
    fn governance_redelegation_post_identity_gate_rejects_ambiguous_legacy_bonds() {
        let mut state = ChainState::new_genesis();
        let from_validator = Bytes32::from([0xAE; 32]);
        let to_validator = Bytes32::from([0xAF; 32]);
        let proposal_id = Bytes32::from([0xB0; 32]);
        install_reveal_phase_proposal(&mut state, proposal_id, from_validator, to_validator);
        let (first_pubkey, first_keypair) = mixed_keypair(0xB1, 0xB2);
        let (second_pubkey, _) = mixed_keypair(0xB1, 0xB3);
        let delegator_id = pubkey_to_id(&first_pubkey);
        assert_eq!(pubkey_to_id(&second_pubkey), delegator_id);
        install_legacy_redelegation_bond(
            &mut state,
            Bytes32::from([0x05; 32]),
            from_validator,
            delegator_id,
            first_pubkey,
            1_000,
            0x05,
        );
        install_legacy_redelegation_bond(
            &mut state,
            Bytes32::from([0x06; 32]),
            from_validator,
            delegator_id,
            second_pubkey,
            1_000,
            0x06,
        );
        let op = redelegate_op(
            delegator_id,
            &first_keypair,
            proposal_id,
            from_validator,
            to_validator,
            500,
            1,
        );
        let mut old_behavior = state.clone();
        apply_governance_op(&mut old_behavior, &op, 0, 0, DEFAULT_CHAIN_ID).unwrap();
        assert_eq!(
            old_behavior
                .governance
                .proposals
                .get(&proposal_id)
                .unwrap()
                .redelegations
                .len(),
            1
        );

        let before = state.clone();
        let err = apply_governance_op(&mut state, &op, 0, u64::MAX, DEFAULT_CHAIN_ID).unwrap_err();

        assert!(matches!(
            err,
            StateError::InvalidGovernanceOp { reason }
                if reason.contains("delegator identity has ambiguous legacy pubkeys")
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn governance_redelegation_post_identity_gate_rejects_unresolvable_identity() {
        let mut state = ChainState::new_genesis();
        let from_validator = Bytes32::from([0xB4; 32]);
        let to_validator = Bytes32::from([0xB5; 32]);
        let proposal_id = Bytes32::from([0xB6; 32]);
        install_reveal_phase_proposal(&mut state, proposal_id, from_validator, to_validator);
        let (delegator_pubkey, delegator_keypair) = keypair(0xB7);
        let delegator_id = pubkey_to_id(&delegator_pubkey);
        state
            .delegations
            .add_delegation(from_validator, delegator_id, 1_000, 0)
            .unwrap();

        let op = redelegate_op(
            delegator_id,
            &delegator_keypair,
            proposal_id,
            from_validator,
            to_validator,
            500,
            1,
        );
        let before = state.clone();

        let err = apply_governance_op(&mut state, &op, 0, u64::MAX, DEFAULT_CHAIN_ID).unwrap_err();

        assert!(matches!(
            err,
            StateError::InvalidGovernanceOp { reason }
                if reason.contains("delegator identity is unresolvable")
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn governance_proposal_rejects_deposit_utxo_not_owned_by_proposer() {
        let mut state = ChainState::new_genesis();
        state.governance.params.proposal_deposit_spark = 1_000;
        let (attacker_pubkey, attacker_keypair) = keypair(0x11);
        let (victim_pubkey, _) = keypair(0x22);
        let attacker_id = install_governance_validator(&mut state, &attacker_pubkey);
        let victim_deposit = state
            .utxos
            .insert(deposit_output(victim_pubkey, 1_000), 0, 0, 0)
            .unwrap();

        let op = propose_op(
            attacker_id,
            &attacker_keypair,
            attacker_pubkey,
            victim_deposit,
            1,
        );
        let result = apply_governance_op(&mut state, &op, 0, 0, DEFAULT_CHAIN_ID);

        assert!(matches!(
            result,
            Err(StateError::InvalidGovernanceOp { reason })
                if reason.contains("not owned by the proposer")
        ));
        assert!(
            state.utxos.get(&victim_deposit).is_some(),
            "victim deposit UTXO must remain unspent"
        );
    }

    #[test]
    fn governance_proposal_accepts_deposit_utxo_owned_by_proposer() {
        let mut state = ChainState::new_genesis();
        state.governance.params.proposal_deposit_spark = 1_000;
        let (proposer_pubkey, proposer_keypair) = keypair(0x33);
        let proposer_id = install_governance_validator(&mut state, &proposer_pubkey);
        let deposit = state
            .utxos
            .insert(deposit_output(proposer_pubkey.clone(), 1_000), 0, 0, 0)
            .unwrap();
        let op = propose_op(
            proposer_id,
            &proposer_keypair,
            proposer_pubkey.clone(),
            deposit,
            1,
        );

        apply_governance_op(&mut state, &op, 0, 0, DEFAULT_CHAIN_ID).unwrap();

        assert!(state.utxos.get(&deposit).is_none());
        assert_eq!(state.governance.proposals.len(), 1);
        let proposal = state.governance.proposals.values().next().unwrap();
        assert_eq!(proposal.proposer_pubkey, proposer_pubkey);
    }

    #[test]
    fn proposal_submission_with_overfunded_utxo_returns_change() {
        let mut state = ChainState::new_genesis();
        state.governance.params.proposal_deposit_spark = 1_000;
        let (proposer_pubkey, proposer_keypair) = keypair(0x35);
        let proposer_id = install_governance_validator(&mut state, &proposer_pubkey);
        let deposit = state
            .utxos
            .insert(deposit_output(proposer_pubkey.clone(), 1_500), 0, 0, 0)
            .unwrap();
        let initial_utxo_count = state.utxos.len();
        let op = propose_op(
            proposer_id,
            &proposer_keypair,
            proposer_pubkey.clone(),
            deposit,
            1,
        );

        apply_governance_op(&mut state, &op, 0, 0, DEFAULT_CHAIN_ID).unwrap();

        assert!(state.utxos.get(&deposit).is_none());
        assert_eq!(
            state.utxos.len(),
            initial_utxo_count,
            "spending one deposit UTXO and creating one change UTXO should be net-neutral"
        );
        assert!(state.utxos.all_entries().any(|entry| {
            entry.output.owner_pubkey == proposer_pubkey && entry.output.value_spark == 500
        }));
        let proposal = state.governance.proposals.values().next().unwrap();
        assert_eq!(
            proposal.deposit_spark, 1_000,
            "only required deposit should be locked/at risk"
        );
    }

    #[test]
    fn proposal_submission_with_exact_utxo_creates_no_change() {
        let mut state = ChainState::new_genesis();
        state.governance.params.proposal_deposit_spark = 1_000;
        let (proposer_pubkey, proposer_keypair) = keypair(0x36);
        let proposer_id = install_governance_validator(&mut state, &proposer_pubkey);
        let deposit = state
            .utxos
            .insert(deposit_output(proposer_pubkey.clone(), 1_000), 0, 0, 0)
            .unwrap();
        let initial_utxo_count = state.utxos.len();
        let op = propose_op(
            proposer_id,
            &proposer_keypair,
            proposer_pubkey.clone(),
            deposit,
            1,
        );

        apply_governance_op(&mut state, &op, 0, 0, DEFAULT_CHAIN_ID).unwrap();

        assert!(state.utxos.get(&deposit).is_none());
        assert_eq!(
            state.utxos.len(),
            initial_utxo_count.saturating_sub(1),
            "exact deposit spend should not create a zero-value change UTXO"
        );
        assert!(!state.utxos.all_entries().any(|entry| {
            entry.output.owner_pubkey == proposer_pubkey && entry.output.value_spark == 0
        }));
    }

    #[test]
    fn proposal_submission_rejects_underfunded_utxo_without_spending_it() {
        let mut state = ChainState::new_genesis();
        state.governance.params.proposal_deposit_spark = 1_000;
        let (proposer_pubkey, proposer_keypair) = keypair(0x37);
        let proposer_id = install_governance_validator(&mut state, &proposer_pubkey);
        let deposit = state
            .utxos
            .insert(deposit_output(proposer_pubkey.clone(), 999), 0, 0, 0)
            .unwrap();
        let op = propose_op(proposer_id, &proposer_keypair, proposer_pubkey, deposit, 1);

        let result = apply_governance_op(&mut state, &op, 0, 0, DEFAULT_CHAIN_ID);

        assert!(matches!(
            result,
            Err(StateError::InvalidGovernanceOp { reason })
                if reason.contains("below required proposal deposit")
        ));
        assert!(
            state.utxos.get(&deposit).is_some(),
            "underfunded deposit UTXO must remain unspent"
        );
        assert!(state.governance.proposals.is_empty());
    }

    #[test]
    fn proposal_submission_rejects_conflicting_active_parameter_target() {
        let mut state = ChainState::new_genesis();
        state.governance.params.proposal_deposit_spark = 1_000;
        let (first_pubkey, first_keypair, first_id, first_deposit) =
            install_proposer_with_deposit(&mut state, 0x38, 1_000, 0);
        let (second_pubkey, second_keypair, second_id, second_deposit) =
            install_proposer_with_deposit(&mut state, 0x39, 1_000, 1);

        let first = propose_op_with_action(
            first_id,
            &first_keypair,
            first_pubkey,
            first_deposit,
            1,
            GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK,
            },
        );
        apply_governance_op(&mut state, &first, 0, 0, DEFAULT_CHAIN_ID).unwrap();

        let second = propose_op_with_action(
            second_id,
            &second_keypair,
            second_pubkey,
            second_deposit,
            1,
            GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK + 1,
            },
        );
        let result = apply_governance_op(&mut state, &second, 0, 0, DEFAULT_CHAIN_ID);

        assert!(matches!(
            result,
            Err(StateError::InvalidGovernanceOp { reason })
                if reason.contains("targeting this parameter is already active")
        ));
        assert_eq!(state.governance.proposals.len(), 1);
    }

    #[test]
    fn proposal_submission_allows_same_parameter_after_prior_resolves() {
        for terminal_phase in [
            ProposalPhase::Failed,
            ProposalPhase::Cancelled,
            ProposalPhase::Executed,
        ] {
            let mut state = ChainState::new_genesis();
            state.governance.params.proposal_deposit_spark = 1_000;
            let (first_pubkey, first_keypair, first_id, first_deposit) =
                install_proposer_with_deposit(&mut state, 0x3a, 1_000, 0);
            let (second_pubkey, second_keypair, second_id, second_deposit) =
                install_proposer_with_deposit(&mut state, 0x3b, 1_000, 1);

            let first = propose_op_with_action(
                first_id,
                &first_keypair,
                first_pubkey,
                first_deposit,
                1,
                GovernableAction::SetMinDelegationSpark {
                    value: DUST_LIMIT_SPARK,
                },
            );
            apply_governance_op(&mut state, &first, 0, 0, DEFAULT_CHAIN_ID).unwrap();
            let first_proposal_id = *state.governance.proposals.keys().next().unwrap();
            state
                .governance
                .proposals
                .get_mut(&first_proposal_id)
                .unwrap()
                .phase = terminal_phase;

            let second = propose_op_with_action(
                second_id,
                &second_keypair,
                second_pubkey,
                second_deposit,
                1,
                GovernableAction::SetMinDelegationSpark {
                    value: DUST_LIMIT_SPARK + 1,
                },
            );

            apply_governance_op(&mut state, &second, 0, 0, DEFAULT_CHAIN_ID)
                .unwrap_or_else(|err| panic!("terminal phase {terminal_phase:?} blocked: {err}"));
            assert_eq!(state.governance.proposals.len(), 2);
        }
    }

    #[test]
    fn proposal_submission_allows_different_parameters_concurrently() {
        let mut state = ChainState::new_genesis();
        state.governance.params.proposal_deposit_spark = 1_000;
        let (first_pubkey, first_keypair, first_id, first_deposit) =
            install_proposer_with_deposit(&mut state, 0x3c, 1_000, 0);
        let (second_pubkey, second_keypair, second_id, second_deposit) =
            install_proposer_with_deposit(&mut state, 0x3d, 1_000, 1);

        let first = propose_op_with_action(
            first_id,
            &first_keypair,
            first_pubkey,
            first_deposit,
            1,
            GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK,
            },
        );
        apply_governance_op(&mut state, &first, 0, 0, DEFAULT_CHAIN_ID).unwrap();

        let second = propose_op_with_action(
            second_id,
            &second_keypair,
            second_pubkey,
            second_deposit,
            1,
            GovernableAction::SetSlashLivenessThresholdEpochs { value: 4 },
        );
        apply_governance_op(&mut state, &second, 0, 0, DEFAULT_CHAIN_ID).unwrap();

        assert_eq!(state.governance.proposals.len(), 2);
    }

    #[test]
    fn governance_deposit_refund_goes_to_proposer() {
        let mut state = ChainState::new_genesis();
        state.governance.params.proposal_deposit_spark = 1_000;
        let (proposer_pubkey, proposer_keypair) = keypair(0x44);
        let proposer_id = install_governance_validator(&mut state, &proposer_pubkey);
        let deposit = state
            .utxos
            .insert(deposit_output(proposer_pubkey.clone(), 1_000), 0, 0, 0)
            .unwrap();
        let op = propose_op(
            proposer_id,
            &proposer_keypair,
            proposer_pubkey.clone(),
            deposit,
            1,
        );
        apply_governance_op(&mut state, &op, 0, 0, DEFAULT_CHAIN_ID).unwrap();
        let proposal_id = *state.governance.proposals.keys().next().unwrap();

        return_governance_deposit(&mut state, proposal_id, 0).unwrap();

        assert!(state.utxos.all_entries().any(|entry| {
            entry.output.owner_pubkey == proposer_pubkey && entry.output.value_spark == 1_000
        }));
        assert_eq!(
            state
                .governance
                .proposals
                .get(&proposal_id)
                .unwrap()
                .deposit_spark,
            0
        );
    }

    #[test]
    fn queued_governance_action_revalidated_before_execution() {
        let mut state = ChainState::new_genesis();
        let (proposer_pubkey, _) = keypair(0x55);
        state.governance.params.governance_quorum_bps = 7_000;
        let proposal_id = Bytes32::from([0x55; 32]);
        let stale_action = GovernableAction::SetGovernanceQuorumBps { value: 6_000 };
        state.governance.proposals.insert(
            proposal_id,
            proposal_record(
                proposal_id,
                proposer_pubkey,
                stale_action.clone(),
                ProposalPhase::ExecDelay,
            ),
        );
        state
            .governance
            .queued_executions
            .push(crate::governance::QueuedExecution {
                proposal_id,
                action: stale_action,
                executable_epoch: 0,
                executed: false,
            });

        apply_execute(&mut state, 0, 0, &proposal_id).unwrap();

        assert_eq!(state.governance.params.governance_quorum_bps, 7_000);
        assert_eq!(
            state.governance.proposals[&proposal_id].phase,
            ProposalPhase::Failed
        );
        assert!(state.governance.queued_executions[0].executed);
    }

    #[test]
    fn valid_queued_governance_action_still_executes() {
        let mut state = ChainState::new_genesis();
        let (proposer_pubkey, _) = keypair(0x66);
        state.governance.params.governance_quorum_bps = 5_000;
        let proposal_id = Bytes32::from([0x66; 32]);
        let action = GovernableAction::SetGovernanceQuorumBps { value: 6_000 };
        state.governance.proposals.insert(
            proposal_id,
            proposal_record(
                proposal_id,
                proposer_pubkey,
                action.clone(),
                ProposalPhase::ExecDelay,
            ),
        );
        state
            .governance
            .queued_executions
            .push(crate::governance::QueuedExecution {
                proposal_id,
                action,
                executable_epoch: 0,
                executed: false,
            });

        apply_execute(&mut state, 0, 0, &proposal_id).unwrap();

        assert_eq!(state.governance.params.governance_quorum_bps, 6_000);
        assert_eq!(
            state.governance.proposals[&proposal_id].phase,
            ProposalPhase::Executed
        );
        assert!(state.governance.queued_executions[0].executed);
    }

    #[test]
    fn auto_execute_revalidates_stale_proposals() {
        let mut state = ChainState::new_genesis();
        let (proposer_pubkey, _) = keypair(0x77);
        state.governance.params.governance_quorum_bps = 7_000;
        let proposal_id = Bytes32::from([0x77; 32]);
        let stale_action = GovernableAction::SetGovernanceQuorumBps { value: 6_000 };
        state.governance.proposals.insert(
            proposal_id,
            proposal_record(
                proposal_id,
                proposer_pubkey,
                stale_action.clone(),
                ProposalPhase::ExecDelay,
            ),
        );
        state
            .governance
            .queued_executions
            .push(crate::governance::QueuedExecution {
                proposal_id,
                action: stale_action,
                executable_epoch: 0,
                executed: false,
            });

        crate::epoch::apply_governance_phase_transitions(&mut state, 0, 0).unwrap();

        assert_eq!(state.governance.params.governance_quorum_bps, 7_000);
        assert_eq!(
            state.governance.proposals[&proposal_id].phase,
            ProposalPhase::Failed
        );
        assert!(state.governance.queued_executions[0].executed);
    }

    #[test]
    fn failed_execution_time_revalidation_marks_proposal_failed() {
        let mut state = ChainState::new_genesis();
        let (proposer_pubkey, _) = keypair(0x88);
        state.governance.params.governance_quorum_bps = 7_000;
        let proposal_id = Bytes32::from([0x88; 32]);
        let stale_action = GovernableAction::SetGovernanceQuorumBps { value: 6_000 };
        let mut proposal = proposal_record(
            proposal_id,
            proposer_pubkey.clone(),
            stale_action.clone(),
            ProposalPhase::ExecDelay,
        );
        proposal.deposit_spark = 1_000;
        proposal.deposit_burned = false;
        state.governance.proposals.insert(proposal_id, proposal);
        state
            .governance
            .queued_executions
            .push(crate::governance::QueuedExecution {
                proposal_id,
                action: stale_action,
                executable_epoch: 0,
                executed: false,
            });

        apply_execute(&mut state, 0, 0, &proposal_id).unwrap();

        let proposal = state.governance.proposals.get(&proposal_id).unwrap();
        assert_eq!(proposal.phase, ProposalPhase::Failed);
        assert_eq!(proposal.deposit_spark, 0);
        assert!(state.utxos.all_entries().any(|entry| {
            entry.output.owner_pubkey == proposer_pubkey && entry.output.value_spark == 1_000
        }));
    }

    #[test]
    fn state_rejects_invalid_reveal_value() {
        let mut state = ChainState::new_genesis();
        let proposal_id = Bytes32::from([0x99; 32]);
        let validator_id = Bytes32::from([0xAA; 32]);
        let nonce = Bytes32::from([0xBB; 32]);
        let mut commit_bytes = Vec::new();
        2u8.encode(&mut commit_bytes);
        nonce.encode(&mut commit_bytes);
        let commit_hash = Bytes32::from(sha256(&commit_bytes));

        let (proposer_pubkey, _) = keypair(0x99);
        let mut proposal = proposal_record(
            proposal_id,
            proposer_pubkey,
            GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK,
            },
            ProposalPhase::Reveal,
        );
        proposal.commits.insert(
            validator_id,
            VoteCommit {
                validator_id,
                commit_hash,
                committed_epoch: 0,
            },
        );
        state.governance.proposals.insert(proposal_id, proposal);
        let op = GovernanceOpV2 {
            action_type: GovernanceActionType::RevealVote,
            signer_id: validator_id,
            nonce: 1,
            payload: GovernancePayload::Reveal {
                proposal_id,
                vote: 2,
                nonce,
                cold_authorization: None,
            },
            signature: dummy_sig(),
        };

        let result = apply_reveal(&mut state, &op, 0, &proposal_id, 2, &nonce);

        assert!(matches!(
            result,
            Err(StateError::InvalidGovernanceOp { reason }) if reason.contains("vote must be 0 or 1")
        ));
    }

    #[test]
    fn reveal_verification_uses_domain_separated_hash() {
        let mut state = ChainState::new_genesis();
        let proposal_id = Bytes32::from([0xAB; 32]);
        let validator_id = Bytes32::from([0xCD; 32]);
        let nonce = Bytes32::from([0xEF; 32]);
        let vote = 1u8;
        let (proposer_pubkey, _) = keypair(0xAB);
        let mut proposal = proposal_record(
            proposal_id,
            proposer_pubkey,
            GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK,
            },
            ProposalPhase::Reveal,
        );
        proposal.commits.insert(
            validator_id,
            VoteCommit {
                validator_id,
                commit_hash: governance_vote_commit_hash(proposal_id, validator_id, vote, nonce),
                committed_epoch: 0,
            },
        );
        state.governance.proposals.insert(proposal_id, proposal);
        let op = GovernanceOpV2 {
            action_type: GovernanceActionType::RevealVote,
            signer_id: validator_id,
            nonce: 1,
            payload: GovernancePayload::Reveal {
                proposal_id,
                vote,
                nonce,
                cold_authorization: None,
            },
            signature: dummy_sig(),
        };

        apply_reveal(&mut state, &op, 0, &proposal_id, vote, &nonce).unwrap();

        assert!(state.governance.proposals[&proposal_id]
            .reveals
            .get(&validator_id)
            .map(|reveal| reveal.vote)
            .unwrap_or(false));
    }
}
