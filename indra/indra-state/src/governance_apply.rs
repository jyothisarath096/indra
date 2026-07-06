//! Governance operation application.

use indra_core::{
    codec::Encode,
    types::{
        crypto::HybridPubKey,
        governance::{
            compute_proposal_id, governance_signing_domain, GovernanceOpV2, GovernancePayload,
        },
        primitives::Bytes32,
        transaction::OutputV1,
    },
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
    validator::ValidatorStatus,
    ChainState,
};

/// Apply one governance op.
pub fn apply_governance_op(
    state: &mut ChainState,
    op: &GovernanceOpV2,
    current_epoch: u64,
    chain_id: &str,
) -> StateResult<()> {
    if op.payload.action_type() != op.action_type {
        return invalid("payload/action type mismatch");
    }
    verify_governance_sig(state, op, chain_id)?;
    apply_governance_nonce(state, op)?;

    match &op.payload {
        GovernancePayload::Propose {
            action,
            deposit_utxo_id,
            proposer_pubkey,
            title,
            description,
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
        ),
        GovernancePayload::Commit {
            proposal_id,
            commit_hash,
        } => apply_commit(state, op, current_epoch, proposal_id, commit_hash),
        GovernancePayload::Reveal {
            proposal_id,
            vote,
            nonce,
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
        ),
        GovernancePayload::Execute { proposal_id } => {
            apply_execute(state, current_epoch, proposal_id)
        }
        GovernancePayload::Cancel { proposal_id } => apply_cancel(state, op, proposal_id),
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
    apply_governance_op(&mut scratch, op, current_epoch, chain_id)
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
    let _ = state.utxos.spend(deposit_utxo_id);

    let proposal_id = compute_proposal_id(op.signer_id, action, current_epoch, chain_id);
    if state.governance.proposals.contains_key(&proposal_id) {
        return invalid("proposal already exists");
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
    let mut bytes = Vec::with_capacity(33);
    vote.encode(&mut bytes);
    nonce.encode(&mut bytes);
    let expected = Bytes32::from(sha256(&bytes));
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
) -> StateResult<()> {
    if amount_spark == 0 {
        return invalid("redelegation amount cannot be zero");
    }
    let proposal = state
        .governance
        .proposals
        .get_mut(proposal_id)
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
    let entry = state
        .delegations
        .get_delegators(from_validator)
        .iter()
        .find(|entry| entry.delegator_id == op.signer_id && entry.unbonding_end_epoch.is_none())
        .ok_or(StateError::DelegatorNotFound)?;
    if amount_spark > entry.staked_spark {
        return invalid("redelegation exceeds active delegated stake");
    }
    proposal.redelegations.push(GovernanceRedelegation {
        delegator_id: op.signer_id,
        from_validator: *from_validator,
        to_validator: *to_validator,
        amount_spark,
    });
    proposal.redelegated_delegators.insert(op.signer_id, ());
    Ok(())
}

fn apply_execute(
    state: &mut ChainState,
    current_epoch: u64,
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
    if !revalidate_queued_governance_action_or_fail(state, *proposal_id, &action)? {
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
/// such as "quorum can only increase" even when multiple proposals are queued.
pub(crate) fn revalidate_queued_governance_action_or_fail(
    state: &mut ChainState,
    proposal_id: Bytes32,
    action: &indra_core::types::governance::GovernableAction,
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
        return_governance_deposit(state, proposal_id)?;
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

fn apply_governance_nonce(state: &mut ChainState, op: &GovernanceOpV2) -> StateResult<()> {
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
) -> StateResult<()> {
    let pubkey = governance_signer_pubkey(state, op)?;
    let domain = governance_signing_domain(
        op.action_type,
        op.signer_id,
        op.nonce,
        &op.payload,
        chain_id,
    );
    let msg_hash = sha256(&domain);
    let sig = op
        .signature
        .to_crypto_sig()
        .map_err(|reason| StateError::GovernanceSignatureInvalid { reason })?;
    let pk = pubkey
        .to_crypto_pubkey()
        .map_err(|reason| StateError::GovernanceSignatureInvalid { reason })?;
    verify_hybrid(&msg_hash, &sig, &pk).map_err(|e| StateError::GovernanceSignatureInvalid {
        reason: e.to_string(),
    })
}

fn governance_signer_pubkey(state: &ChainState, op: &GovernanceOpV2) -> StateResult<HybridPubKey> {
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
            delegation_pubkey(state, from_validator, &op.signer_id)
        }
        GovernancePayload::Execute { proposal_id } | GovernancePayload::Cancel { proposal_id } => {
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
        .map(|bond| bond.original_output.owner_pubkey.clone())
        .ok_or(StateError::DelegatorNotFound)
}

/// Return a deposit to a proposer as a new UTXO.
pub fn return_governance_deposit(state: &mut ChainState, proposal_id: Bytes32) -> StateResult<()> {
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
        .insert(output, state.height, u32::MAX - 2, output_index)
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
        types::{
            crypto::{CommitmentV1, HybridSignature},
            governance::{GovernableAction, GovernanceActionType},
            primitives::{
                VariableBytes, DEFAULT_CHAIN_ID, DEFAULT_COMMISSION_BPS, DUST_LIMIT_SPARK,
            },
        },
        Bytes32,
    };
    use indra_crypto::{ClassicalKeypair, HybridKeypair, PqKeypair};

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

    fn propose_op(
        signer_id: Bytes32,
        keypair: &HybridKeypair,
        proposer_pubkey: HybridPubKey,
        deposit_utxo_id: Bytes32,
        nonce: u64,
    ) -> GovernanceOpV2 {
        let payload = GovernancePayload::Propose {
            action: GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK,
            },
            deposit_utxo_id,
            proposer_pubkey,
            title: VariableBytes::from_slice(b"test").unwrap(),
            description: VariableBytes::from_slice(b"test proposal").unwrap(),
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
        let result = apply_governance_op(&mut state, &op, 0, DEFAULT_CHAIN_ID);

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

        apply_governance_op(&mut state, &op, 0, DEFAULT_CHAIN_ID).unwrap();

        assert!(state.utxos.get(&deposit).is_none());
        assert_eq!(state.governance.proposals.len(), 1);
        let proposal = state.governance.proposals.values().next().unwrap();
        assert_eq!(proposal.proposer_pubkey, proposer_pubkey);
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
        apply_governance_op(&mut state, &op, 0, DEFAULT_CHAIN_ID).unwrap();
        let proposal_id = *state.governance.proposals.keys().next().unwrap();

        return_governance_deposit(&mut state, proposal_id).unwrap();

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

        apply_execute(&mut state, 0, &proposal_id).unwrap();

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

        apply_execute(&mut state, 0, &proposal_id).unwrap();

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

        apply_execute(&mut state, 0, &proposal_id).unwrap();

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
            },
            signature: dummy_sig(),
        };

        let result = apply_reveal(&mut state, &op, 0, &proposal_id, 2, &nonce);

        assert!(matches!(
            result,
            Err(StateError::InvalidGovernanceOp { reason }) if reason.contains("vote must be 0 or 1")
        ));
    }
}
