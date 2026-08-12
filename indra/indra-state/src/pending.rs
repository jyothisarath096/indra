//! Cryptographically verified pending-item certificates.
//!
//! These certificates let pending pools repeat only state-dependent checks
//! after canonical state advances. Raw block application never trusts them.

use std::collections::HashSet;

use indra_core::{
    codec::Encode,
    types::{
        crypto::HybridPubKey, governance::GovernanceOpV2, staking::StakingOp,
        transaction::TransactionV1,
    },
    Bytes32,
};

use crate::{apply::validate_transaction, ChainState, StateError, StateResult, UtxoEntry};

/// State-selected authority material consumed by staking signature validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakingAuthorityFingerprint {
    /// Full signer validator record; existence also controls hot/cold classification.
    signer_validator: Option<crate::validator::ValidatorEntry>,
    /// Registered delegator identity used by exit authorization when present.
    delegator_identity: Option<HybridPubKey>,
}

/// Admission certificate for a staking operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPendingStaking {
    /// Canonical operation identifier.
    op_id: Bytes32,
    /// Authority material used during admission verification.
    authority: StakingAuthorityFingerprint,
}

/// State-selected authority material consumed by governance verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceAuthorityFingerprint {
    /// Full signer validator record; existence controls cold classification.
    signer_validator: Option<crate::validator::ValidatorEntry>,
    /// Registered delegator identity used by redelegation when present.
    delegator_identity: Option<HybridPubKey>,
    /// Proposal-stored authority used by cancellation when applicable.
    proposal_authority: Option<HybridPubKey>,
}

/// Admission certificate for a governance operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPendingGovernance {
    /// Canonical operation identifier.
    op_id: Bytes32,
    /// Authority material used during admission verification.
    authority: GovernanceAuthorityFingerprint,
}

/// Compute the canonical identifier of a pending staking operation.
pub fn staking_op_id(op: &StakingOp) -> Bytes32 {
    Bytes32::from(indra_crypto::sha256(&op.encode_to_vec()))
}

/// Capture the canonical authority state used by a staking operation.
pub fn staking_authority_fingerprint(
    state: &ChainState,
    op: &StakingOp,
) -> StakingAuthorityFingerprint {
    let signer = op.signer_id();
    StakingAuthorityFingerprint {
        signer_validator: state.validators.get(&signer).cloned(),
        delegator_identity: state.delegator_identities.get(&signer).cloned(),
    }
}

/// Build a staking certificate after authoritative admission succeeds.
fn certify_pending_staking(state: &ChainState, op: &StakingOp) -> VerifiedPendingStaking {
    VerifiedPendingStaking {
        op_id: staking_op_id(op),
        authority: staking_authority_fingerprint(state, op),
    }
}

/// Fully validate staking admission and return a reusable crypto certificate.
pub fn verify_pending_staking(
    state: &ChainState,
    op: &StakingOp,
    current_height: u64,
) -> StateResult<VerifiedPendingStaking> {
    let mut scratch = state.clone();
    crate::apply_staking_op(&mut scratch, op, &state.chain_id, current_height)?;
    Ok(certify_pending_staking(state, op))
}

/// Return whether a staking certificate still authorizes crypto reuse.
pub fn staking_authority_unchanged(
    state: &ChainState,
    op: &StakingOp,
    verified: &VerifiedPendingStaking,
) -> bool {
    verified.op_id == staking_op_id(op)
        && verified.authority == staking_authority_fingerprint(state, op)
}

/// Compute the canonical identifier of a pending governance operation.
pub fn governance_op_id(op: &GovernanceOpV2) -> Bytes32 {
    Bytes32::from(indra_crypto::sha256(&op.encode_to_vec()))
}

/// Capture canonical authority state used by a governance operation.
pub fn governance_authority_fingerprint(
    state: &ChainState,
    op: &GovernanceOpV2,
) -> GovernanceAuthorityFingerprint {
    let proposal_authority = match &op.payload {
        indra_core::types::governance::GovernancePayload::Cancel { proposal_id, .. } => state
            .governance
            .proposals
            .get(proposal_id)
            .map(|proposal| proposal.proposer_pubkey.clone()),
        _ => None,
    };
    GovernanceAuthorityFingerprint {
        signer_validator: state.validators.get(&op.signer_id).cloned(),
        delegator_identity: state.delegator_identities.get(&op.signer_id).cloned(),
        proposal_authority,
    }
}

/// Build a governance certificate after authoritative admission succeeds.
fn certify_pending_governance(
    state: &ChainState,
    op: &GovernanceOpV2,
) -> VerifiedPendingGovernance {
    VerifiedPendingGovernance {
        op_id: governance_op_id(op),
        authority: governance_authority_fingerprint(state, op),
    }
}

/// Fully validate governance admission and return a reusable crypto certificate.
pub fn verify_pending_governance(
    state: &ChainState,
    op: &GovernanceOpV2,
    current_epoch: u64,
    current_height: u64,
) -> StateResult<VerifiedPendingGovernance> {
    let mut scratch = state.clone();
    crate::apply_governance_op(
        &mut scratch,
        op,
        current_epoch,
        current_height,
        &state.chain_id,
    )?;
    Ok(certify_pending_governance(state, op))
}

/// Return whether a governance certificate still authorizes crypto reuse.
pub fn governance_authority_unchanged(
    state: &ChainState,
    op: &GovernanceOpV2,
    verified: &VerifiedPendingGovernance,
) -> bool {
    verified.op_id == governance_op_id(op)
        && verified.authority == governance_authority_fingerprint(state, op)
}

/// Admission-time proof that a transaction's intrinsic checks were completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPendingTransaction {
    /// Canonical transaction identifier certified at admission.
    tx_id: Bytes32,
    /// Exact immutable UTXO records consumed by ownership and crypto checks.
    input_utxos: Vec<(Bytes32, UtxoEntry)>,
}

/// Fully verify a transaction and build its reusable pending certificate.
pub fn verify_pending_transaction(
    state: &ChainState,
    tx: &TransactionV1,
    tx_id: Bytes32,
    current_height: u64,
) -> StateResult<VerifiedPendingTransaction> {
    let mut input_ids = HashSet::new();
    validate_transaction(state, tx, &state.chain_id, &mut input_ids, current_height)?;
    let input_utxos = tx
        .inputs
        .iter()
        .map(|input| {
            state
                .utxos
                .get(&input.utxo_id)
                .cloned()
                .map(|entry| (input.utxo_id, entry))
                .ok_or(StateError::UnknownUtxo)
        })
        .collect::<StateResult<Vec<_>>>()?;
    Ok(VerifiedPendingTransaction { tx_id, input_utxos })
}

/// Recheck only transaction validity that can change after admission.
pub fn validate_verified_pending_transaction(
    state: &ChainState,
    tx: &TransactionV1,
    verified: &VerifiedPendingTransaction,
    current_height: u64,
) -> StateResult<()> {
    if verified.tx_id != Bytes32::from(indra_crypto::sha256(&tx.encode_to_vec()))
        || verified.input_utxos.len() != tx.inputs.len()
    {
        return Err(StateError::InvariantViolation {
            message: "pending transaction certificate does not match transaction",
        });
    }

    for (input, (certified_id, certified_entry)) in tx.inputs.iter().zip(&verified.input_utxos) {
        if input.utxo_id != *certified_id {
            return Err(StateError::InvariantViolation {
                message: "pending transaction input certificate order mismatch",
            });
        }
        let current = state
            .utxos
            .get(&input.utxo_id)
            .ok_or(StateError::UnknownUtxo)?;
        if current != certified_entry {
            return Err(StateError::InvariantViolation {
                message: "immutable pending transaction UTXO changed",
            });
        }
        if current.output.lock_height > current_height {
            return Err(StateError::OutputLocked {
                lock_height: current.output.lock_height,
                current_height,
            });
        }
    }

    let weight_kb = (tx.encode_to_vec().len() as u64).div_ceil(1024);
    let required_fee = state
        .base_fee
        .checked_mul(weight_kb)
        .ok_or(StateError::ValueOverflow)?;
    if tx.fee_amount < required_fee {
        return Err(StateError::FeeTooLow {
            actual: tx.fee_amount,
            required: required_fee,
        });
    }
    Ok(())
}
