//! Block application — the core state transition function.
//!
//! `apply_block(state, block, timestamp_secs)` is the heart of the protocol.
//!
//! ## Validation order (Spec Section C)
//!
//! Block-level checks (fail fast before touching any state):
//!   1. Protocol version == 1
//!   2. Height == state.height + 1
//!   3. prev_hash == state.tip_hash
//!   4. Encoded block size ≤ MAX_BLOCK_SIZE_BYTES
//!   5. Transaction count ≤ MAX_TX_PER_BLOCK
//!   6. base_fee field matches our computed value
//!
//! Per-transaction checks (in order, for each tx):
//!   7.  At least 1 input, at least 1 output
//!   8.  No duplicate input UTXO references within the block
//!   10. All input UTXOs exist in the UTXO set
//!   11. All input UTXOs are past their lock_height
//!   12. fee_amount ≥ base_fee × tx_weight_kb
//!
//! State updates (only after ALL checks pass):
//!   - Spend inputs by atomically removing them from the UTXO set
//!   - Create outputs (insert into UTXO set)
//!   - Update base_fee
//!   - If epoch boundary: apply epoch transition
//!   - Update height and tip_hash
//!
//! ## Atomicity
//!
//! State is only mutated after all validation passes.
//! On any error, the original state is unchanged.

use std::collections::{BTreeSet, HashSet};

use indra_core::{
    EpochRecord,
    codec::{Decode, Encode},
    types::{
        block::BlockVNext,
        crypto::HybridPubKey,
        governance::GovernanceOpV2,
        primitives::{
            BLOCK_FORMAT_VERSION, Bytes32, LIFETIME_SUPPLY_CAP_SPARK, MAX_BLOCK_SIZE_BYTES,
            MAX_GOV_OPS_PER_BLOCK, MAX_STAKING_OPS_PER_BLOCK, MAX_TX_PER_BLOCK,
            SLASH_EVIDENCE_WINDOW_EPOCHS, SLASH_REWARD_TX_IDX, TRANSACTION_PROTOCOL_VERSION,
        },
        proposal::VerifiedProposal,
        qc::{QuorumCertificateV1, VerifiedQc, verify_qc_against_snapshot},
        slash_membership::SlashMembershipRootRecord,
        slashing::{SlashEvidenceV1, SlashEvidenceV2},
        staking::StakingOp,
        transaction::{OutputV1, TransactionV1},
        vote::VoteV1,
    },
};
use indra_crypto::{validate_classical_public_key, validate_pq_public_key, verify_hybrid};

use crate::{
    chain::ChainState,
    delegation::apply_staking_op_at_index,
    epoch::{epoch_for_height, is_epoch_boundary},
    error::{StateError, StateResult},
    fee::compute_next_base_fee,
    governance_apply::apply_governance_op,
    txn::StateTxn,
};

/// Roots and value commitment produced by temporarily projecting a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedBlockRoots {
    /// State root after applying the projected block.
    pub state_root: Bytes32,
    /// Validator/delegation/staking root after applying the projected block.
    pub validator_set_root: Bytes32,
    /// Block value hash computed from the projected total supply.
    pub value_hash: Bytes32,
    /// Total supply after applying the projected block.
    pub total_supply: u64,
    /// Epoch record produced by the projected block, if it crosses an epoch boundary.
    pub epoch_record: Option<EpochRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SlashAccounting {
    validator_id: Bytes32,
    slash_bps: u32,
    slash_amount: u64,
    burned: u64,
    self_principal_slashed: u64,
    reporter_reward: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SlashTarget {
    Position(Bytes32),
    Tranche(Bytes32),
}

/// Internal proof that a slash has been authorized and its principal scope has
/// been fixed before mutation begins.  Its fields are private so callers
/// cannot bypass the evidence/liveness verification paths that construct it.
#[derive(Debug)]
pub(crate) struct VerifiedSlashDirectiveV1 {
    validator_id: Bytes32,
    slash_bps: u32,
    infraction_height: u64,
    position_ids: Vec<Bytes32>,
    tranche_ids: Vec<Bytes32>,
}

#[derive(Debug)]
struct AppliedPrincipalSlash {
    slash_amount: u64,
    active_principal_slashed: u64,
    tranche_successors: Vec<(
        Bytes32,
        Option<indra_core::types::stake_position::UnbondingTrancheV1>,
    )>,
}

fn checked_slash_allocation(
    targets: &[(SlashTarget, u64)],
    slash_bps: u32,
) -> StateResult<(u64, std::collections::BTreeMap<SlashTarget, u64>)> {
    let total_principal = targets.iter().try_fold(0u64, |sum, (_, principal)| {
        sum.checked_add(*principal).ok_or(StateError::ValueOverflow)
    })?;
    let aggregate_u128 = (total_principal as u128)
        .checked_mul(slash_bps as u128)
        .ok_or(StateError::ValueOverflow)?
        / 10_000u128;
    let aggregate = u64::try_from(aggregate_u128).map_err(|_| StateError::ValueOverflow)?;

    let mut ranked = Vec::with_capacity(targets.len());
    let mut allocations = std::collections::BTreeMap::new();
    let mut allocated = 0u64;
    for (target, principal) in targets {
        let product = (*principal as u128)
            .checked_mul(slash_bps as u128)
            .ok_or(StateError::ValueOverflow)?;
        let floor = u64::try_from(product / 10_000u128).map_err(|_| StateError::ValueOverflow)?;
        let remainder = (product % 10_000u128) as u16;
        allocated = allocated
            .checked_add(floor)
            .ok_or(StateError::ValueOverflow)?;
        allocations.insert(*target, floor);
        ranked.push((std::cmp::Reverse(remainder), *target));
    }
    ranked.sort_unstable();
    let leftover = aggregate
        .checked_sub(allocated)
        .ok_or(StateError::InvariantViolation {
            message: "slash allocation exceeds aggregate",
        })?;
    if leftover as usize > ranked.len() {
        return Err(StateError::InvariantViolation {
            message: "slash largest-remainder allocation is not representable",
        });
    }
    for (_, target) in ranked.into_iter().take(leftover as usize) {
        let amount = allocations
            .get_mut(&target)
            .ok_or(StateError::InvariantViolation {
                message: "slash allocation target disappeared",
            })?;
        *amount = amount.checked_add(1).ok_or(StateError::ValueOverflow)?;
    }
    let exact = allocations.values().try_fold(0u64, |sum, amount| {
        sum.checked_add(*amount).ok_or(StateError::ValueOverflow)
    })?;
    if exact != aggregate {
        return Err(StateError::InvariantViolation {
            message: "slash allocation does not equal aggregate",
        });
    }
    Ok((aggregate, allocations))
}

fn apply_verified_slash_directive(
    state: &mut ChainState,
    directive: &VerifiedSlashDirectiveV1,
) -> StateResult<AppliedPrincipalSlash> {
    let mut targets =
        Vec::with_capacity(directive.position_ids.len() + directive.tranche_ids.len());
    for id in &directive.position_ids {
        let position = state
            .stake_positions
            .get(id)
            .ok_or(StateError::InvariantViolation {
                message: "verified slash position target disappeared",
            })?;
        if position.validator_id != directive.validator_id {
            return Err(StateError::InvariantViolation {
                message: "verified slash position belongs to another validator",
            });
        }
        let principal = position
            .active
            .ok_or(StateError::InvariantViolation {
                message: "verified slash position has no active principal",
            })?
            .principal_spark;
        targets.push((SlashTarget::Position(*id), principal));
    }
    for id in &directive.tranche_ids {
        let tranche = state
            .unbonding_tranches
            .get(id)
            .ok_or(StateError::InvariantViolation {
                message: "verified slash tranche target disappeared",
            })?;
        if tranche.timing.start_height() < directive.infraction_height {
            return Err(StateError::InvariantViolation {
                message: "verified slash contains a pre-infraction tranche",
            });
        }
        targets.push((SlashTarget::Tranche(*id), tranche.principal_spark));
    }
    let (slash_amount, allocations) = checked_slash_allocation(&targets, directive.slash_bps)?;
    let mut active_principal_slashed = 0u64;
    for position_id in &directive.position_ids {
        let mut position = state.stake_positions.get(position_id).cloned().ok_or(
            StateError::InvariantViolation {
                message: "verified slash position disappeared",
            },
        )?;
        let active = position.active.ok_or(StateError::InvariantViolation {
            message: "verified slash position lost active principal",
        })?;
        let amount = allocations[&SlashTarget::Position(*position_id)];
        let remaining = active
            .principal_spark
            .checked_sub(amount)
            .ok_or(StateError::ValueOverflow)?;
        position.active =
            (remaining != 0).then_some(indra_core::types::stake_position::ActiveStakeAggregateV1 {
                principal_spark: remaining,
                ..active
            });
        active_principal_slashed = active_principal_slashed
            .checked_add(amount)
            .ok_or(StateError::ValueOverflow)?;
        state.stake_positions.insert(*position_id, position.clone());
        if let Some(commitment) = state.state_commitment_v2.as_mut() {
            commitment.put_stake_position(&position);
        }
        crate::txn::complex_mutation_checkpoint()?;
    }
    let mut tranche_successors = Vec::with_capacity(directive.tranche_ids.len());
    for tranche_id in &directive.tranche_ids {
        let tranche = state.unbonding_tranches.get(tranche_id).cloned().ok_or(
            StateError::InvariantViolation {
                message: "verified slash tranche disappeared",
            },
        )?;
        let amount = allocations[&SlashTarget::Tranche(*tranche_id)];
        let remaining = tranche
            .principal_spark
            .checked_sub(amount)
            .ok_or(StateError::ValueOverflow)?;
        let successor = if remaining == 0 {
            None
        } else {
            let successor = indra_core::types::stake_position::UnbondingTrancheV1::new(
                tranche.position_id,
                remaining,
                tranche.timing,
                tranche.custody,
                tranche.creation_op_id,
                tranche.creation_ordinal,
            )
            .map_err(|error| StateError::InvalidSlashEvidence {
                reason: error.to_string(),
            })?;
            if successor.tranche_id != *tranche_id
                && state.unbonding_tranches.contains_key(&successor.tranche_id)
            {
                return Err(StateError::InvariantViolation {
                    message: "verified slash successor tranche collision",
                });
            }
            Some(successor)
        };
        tranche_successors.push((*tranche_id, successor));
    }
    for (old_id, successor) in &tranche_successors {
        state.unbonding_tranches.remove(old_id);
        if let Some(commitment) = state.state_commitment_v2.as_mut() {
            commitment.delete_unbonding_tranche(old_id);
        }
        crate::txn::complex_mutation_checkpoint()?;
        if let Some(successor) = successor {
            state
                .unbonding_tranches
                .insert(successor.tranche_id, successor.clone());
            if let Some(commitment) = state.state_commitment_v2.as_mut() {
                commitment.put_unbonding_tranche(successor);
            }
            crate::txn::complex_mutation_checkpoint()?;
        }
    }
    state
        .rebuild_position_tranche_index()
        .map_err(|error| StateError::InvalidStakingOp(error.to_string()))?;
    let exact = active_principal_slashed
        .checked_add(directive.tranche_ids.iter().try_fold(0u64, |sum, id| {
            sum.checked_add(allocations[&SlashTarget::Tranche(*id)])
                .ok_or(StateError::ValueOverflow)
        })?)
        .ok_or(StateError::ValueOverflow)?;
    if exact != slash_amount {
        return Err(StateError::InvariantViolation {
            message: "verified slash reductions do not equal aggregate",
        });
    }
    Ok(AppliedPrincipalSlash {
        slash_amount,
        active_principal_slashed,
        tranche_successors,
    })
}

/// Apply a deterministic liveness directive to real self-custody principal.
///
/// The directive's authority is created only by the finalized epoch transition;
/// callers supply the canonical first-missed-block infraction height.
pub(crate) fn apply_liveness_principal_slash(
    state: &mut ChainState,
    validator_id: Bytes32,
    slash_bps: u32,
    infraction_height: u64,
) -> StateResult<u64> {
    let mut position_ids = Vec::new();
    let mut tranche_ids = Vec::new();
    for position in state.stake_positions.values().filter(|position| {
        position.validator_id == validator_id
            && matches!(
                position.custody,
                indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
                    validator_id: id
                } if id == validator_id
            )
    }) {
        if position.active.is_some() {
            position_ids.push(position.position_id);
        }
        tranche_ids.extend(
            state
                .tranche_ids_for_position(&position.position_id)
                .iter()
                .filter(|id| {
                    state
                        .unbonding_tranches
                        .get(id)
                        .is_some_and(|tranche| tranche.timing.start_height() >= infraction_height)
                })
                .copied(),
        );
    }
    if position_ids.is_empty() && tranche_ids.is_empty() {
        return Ok(0);
    }
    let directive = VerifiedSlashDirectiveV1 {
        validator_id,
        slash_bps,
        infraction_height,
        position_ids,
        tranche_ids,
    };
    let applied = apply_verified_slash_directive(state, &directive)?;
    if let Some(validator) = state.validators.get_mut(&validator_id) {
        validator.stake_spark = validator
            .stake_spark
            .checked_sub(applied.active_principal_slashed)
            .ok_or(StateError::ValueOverflow)?;
        if validator.stake_spark < indra_core::types::primitives::MINIMUM_ACTIVE_SELF_STAKE_SPARK {
            validator.status = crate::validator::ValidatorStatus::Registered;
        }
    }
    crate::monetary::MonetaryDeltaV1::burn(
        applied.slash_amount,
        crate::monetary::BurnSourceV1::ValidatorSlash,
    )?;
    state.total_supply = state
        .total_supply
        .checked_sub(applied.slash_amount)
        .ok_or(StateError::ValueOverflow)?;
    state.monetary_ledger.cumulative_slash_burned_spark = state
        .monetary_ledger
        .cumulative_slash_burned_spark
        .checked_add(applied.slash_amount)
        .ok_or(StateError::ValueOverflow)?;
    state.monetary_ledger.epoch_slash_burned_spark = state
        .monetary_ledger
        .epoch_slash_burned_spark
        .checked_add(applied.slash_amount)
        .ok_or(StateError::ValueOverflow)?;
    Ok(applied.slash_amount)
}

/// Unforgeable proof that one slash candidate passed full cryptographic validation
/// against a specific candidate height and canonical offense identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSlashCandidate {
    offense_id: Bytes32,
    inclusion_height: u64,
}

#[derive(Clone, Copy)]
enum SlashCryptoMode<'a> {
    Verify,
    PreviouslyVerified(&'a VerifiedSlashCandidate),
}

fn apply_slash_v2_at_height_with_accounting_mode(
    state: &mut ChainState,
    evidence: &SlashEvidenceV2,
    chain_id: &str,
    height: u64,
    reporter_pubkey: Option<&HybridPubKey>,
    synthetic_output_index: u32,
    crypto_mode: SlashCryptoMode<'_>,
) -> StateResult<SlashAccounting> {
    if evidence.vote_1.height > height || evidence.vote_2.height > height {
        return Err(StateError::InvalidSlashEvidence {
            reason: "slash evidence infraction height is in the future".into(),
        });
    }
    let offense_id = compute_slash_evidence_v2_hash(evidence);
    if let SlashCryptoMode::PreviouslyVerified(verified) = crypto_mode {
        if verified.offense_id != offense_id || verified.inclusion_height != height {
            return Err(StateError::InvalidSlashEvidence {
                reason: "verified slash capability does not match candidate".into(),
            });
        }
    }
    if evidence.membership_proof.entry.validator_id != evidence.validator_id
        || evidence.vote_1.validator_id != evidence.validator_id
        || evidence.vote_2.validator_id != evidence.validator_id
    {
        return Err(StateError::InvalidSlashEvidence {
            reason: "membership entry and votes do not match claimed validator".to_string(),
        });
    }
    let record = slash_membership_record_for_validation(state, evidence.vote_1.height)?;
    evidence.membership_proof.verify(&record).map_err(|error| {
        StateError::InvalidSlashEvidence {
            reason: error.to_string(),
        }
    })?;
    let shared_shape = SlashEvidenceV1 {
        validator_id: evidence.validator_id,
        vote_1: evidence.vote_1.clone(),
        vote_2: evidence.vote_2.clone(),
    };
    apply_slash_common(
        state,
        &shared_shape,
        offense_id,
        Some((
            evidence.membership_proof.entry.classical_vote_pk,
            evidence.membership_proof.entry.pq_vote_pk.to_vec(),
        )),
        chain_id,
        height,
        reporter_pubkey,
        synthetic_output_index,
        crypto_mode,
    )
}

#[cfg(test)]
fn apply_slash_v2_at_height_with_accounting(
    state: &mut ChainState,
    evidence: &SlashEvidenceV2,
    chain_id: &str,
    height: u64,
    reporter_pubkey: Option<&HybridPubKey>,
) -> StateResult<SlashAccounting> {
    apply_slash_v2_at_height_with_accounting_at_index(
        state,
        evidence,
        chain_id,
        height,
        reporter_pubkey,
        0,
    )
}

fn apply_slash_v2_at_height_with_accounting_at_index(
    state: &mut ChainState,
    evidence: &SlashEvidenceV2,
    chain_id: &str,
    height: u64,
    reporter_pubkey: Option<&HybridPubKey>,
    synthetic_output_index: u32,
) -> StateResult<SlashAccounting> {
    apply_slash_v2_at_height_with_accounting_mode(
        state,
        evidence,
        chain_id,
        height,
        reporter_pubkey,
        synthetic_output_index,
        SlashCryptoMode::Verify,
    )
}

/// Atomically apply proof-carrying evidence whose vote signatures were verified at admission.
pub fn try_apply_verified_slash_candidate(
    state: &mut ChainState,
    evidence: &SlashEvidenceV2,
    verified: &VerifiedSlashCandidate,
    height: u64,
    reporter_pubkey: Option<&HybridPubKey>,
) -> StateResult<()> {
    let chain_id = state.chain_id.clone();
    let mut txn = StateTxn::begin(state, height);
    txn.snapshot_slashing_scope();
    let accounting = apply_slash_v2_at_height_with_accounting_mode(
        txn.state_mut(),
        evidence,
        &chain_id,
        height,
        reporter_pubkey,
        0,
        SlashCryptoMode::PreviouslyVerified(verified),
    )?;
    txn.add_slash_accounting(accounting.slash_amount)?;
    txn.state_mut().refresh_and_reconcile_monetary_state()?;
    txn.commit_scratch();
    Ok(())
}

/// Fully validate a slash candidate and mint a capability for later application.
pub fn verify_slash_candidate(
    state: &ChainState,
    evidence: &SlashEvidenceV2,
    height: u64,
) -> StateResult<VerifiedSlashCandidate> {
    let mut scratch = state.clone();
    try_apply_slash_candidate(&mut scratch, evidence, height, None)?;
    Ok(VerifiedSlashCandidate {
        offense_id: compute_slash_evidence_v2_hash(evidence),
        inclusion_height: height,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::primitives::TEST_CHAIN_ID;

    fn apply_block(
        state: &mut ChainState,
        block: &BlockVNext,
        timestamp: u64,
    ) -> StateResult<Option<EpochRecord>> {
        apply_block_with_effects(state, block, timestamp).map(|outcome| outcome.epoch_record)
    }
    fn apply_block_with_effects(
        state: &mut ChainState,
        block: &BlockVNext,
        timestamp: u64,
    ) -> StateResult<crate::AppliedBlockOutcome> {
        super::apply_block_contents(state, block, timestamp)
    }

    use crate::chain::ChainState;
    use crate::governance::{
        GovernanceSnapshot, ProposalPhase, ProposalRecord, QueuedExecution, VoteCommit, VoteReveal,
    };
    use crate::state_root::compute_state_root;
    use crate::validator::{ValidatorEntry, ValidatorStatus};
    use indra_core::{
        Bytes32, HybridPubKey, HybridSignature, ProtocolVersion, VariableBytes,
        codec::Encode,
        types::{
            block::{BlockHeaderVNext, BlockVNext},
            crypto::PQVoteSig,
            governance::{
                GovernableAction, GovernanceActionType, GovernanceOpV2, GovernancePayload,
                compute_proposal_id, governance_signing_domain, governance_vote_commit_hash,
            },
            primitives::{
                BLOCK_FORMAT_VERSION, DUST_LIMIT_SPARK, INITIAL_BASE_FEE_SPARK_PER_KB,
                MAX_STAKING_OPS_PER_BLOCK, MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
                TRANSACTION_PROTOCOL_VERSION,
            },
            slash_membership::build_slash_membership_proof,
            slashing::SlashEvidenceV2,
            staking::{StakingOp, StakingOpBody},
            transaction::{InputV1, OutputV1, TransactionV1},
            vote::{VoteStep, VoteV1},
        },
    };
    use indra_crypto::{ClassicalKeypair, HybridKeypair, PqKeypair, sha256};
    use std::collections::BTreeMap;

    const TEST_INPUT_VALUE: u64 = 1_000_000;

    // ── Test helpers ──────────────────────────────────────────────────────

    fn make_test_keypair(seed: [u8; 32]) -> (HybridPubKey, HybridKeypair) {
        let classical = ClassicalKeypair::from_seed(&seed);
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let keypair = HybridKeypair::new(classical, pq);
        let public = keypair.public_key();
        let wire = HybridPubKey {
            classical_pk: Bytes32::from(public.classical.0),
            pq_pk: VariableBytes::from_slice(&public.pq.0).unwrap(),
        };
        (wire, keypair)
    }

    fn dummy_sig() -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
        }
    }

    fn sign_transaction(
        keypair: &HybridKeypair,
        chain_id: &str,
        tx: &TransactionV1,
    ) -> HybridSignature {
        let sig = keypair.sign(&tx.signing_bytes(chain_id).unwrap()).unwrap();
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
        }
    }

    fn staking_delegator_id_for_test(pubkey: &HybridPubKey) -> Bytes32 {
        pubkey.identity_id()
    }

    fn sign_staking_op(keypair: &HybridKeypair, chain_id: &str, op: &mut StakingOp) {
        let signing_bytes = op
            .cold_authorization_signing_bytes(chain_id)
            .unwrap()
            .unwrap_or_else(|| op.signing_bytes(chain_id));
        let sig = keypair.sign(&signing_bytes).unwrap();
        op.signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
        };
    }

    fn governance_validator_id(pubkey: &HybridPubKey) -> Bytes32 {
        pubkey.identity_id()
    }

    fn sign_governance_op(op: &mut GovernanceOpV2, keypair: &HybridKeypair, chain_id: &str) {
        if matches!(
            op.payload,
            GovernancePayload::Propose { .. }
                | GovernancePayload::Commit { .. }
                | GovernancePayload::Reveal { .. }
                | GovernancePayload::Cancel { .. }
        ) {
            let cold_nonce = op.nonce;
            let authorization = Some(indra_core::types::governance::ColdGovernanceAuthorization {
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
                } => {
                    *cold_authorization = authorization;
                }
                _ => unreachable!(),
            }
            op.nonce = 0;
            let bytes = op
                .cold_authorization_signing_bytes(chain_id)
                .unwrap()
                .unwrap();
            let sig = keypair.sign(&bytes).unwrap();
            op.signature = HybridSignature {
                classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
                pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
            };
            return;
        }
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

    fn install_governance_validator(
        state: &mut ChainState,
        seed: [u8; 32],
        stake_spark: u64,
    ) -> (HybridPubKey, HybridKeypair, Bytes32) {
        let (pubkey, keypair) = make_test_keypair(seed);
        let validator_id = governance_validator_id(&pubkey);
        state
            .validators
            .upsert(ValidatorEntry {
                validator_id,
                name: "governance-txn-validator".into(),
                hybrid_classical_pk: Some(pubkey.classical_pk.0),
                hybrid_pq_pk: Some(pubkey.pq_pk.as_slice().to_vec()),
                vrf_pk: Some(indra_crypto::VrfKeypair::from_seed(&seed).public_key()),
                vrf_key_activation_epoch: 0,
                pending_vrf_pk: None,
                pending_vrf_activation_epoch: None,
                stake_spark,
                status: ValidatorStatus::Active,
                registered_epoch: 0,
                last_active_epoch: 0,
                slashed_offense_id: None,
                commission_bps: 1_000,
                pending_commission_bps: None,
                pending_commission_effective_epoch: None,
                min_delegation_spark: 1,
                auto_delegate_to: None,
                network_addr: None,
                network_addr_last_updated_epoch: None,
                cold_hybrid_classical_pk: Some(pubkey.classical_pk.0),
                cold_hybrid_pq_pk: Some(pubkey.pq_pk.as_slice().try_into().unwrap()),
                cold_key_version: 1,
                cold_nonce: 0,
            })
            .unwrap();
        (pubkey, keypair, validator_id)
    }

    fn canonical_test_genesis() -> ChainState {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        install_governance_validator(&mut state, [0xF0; 32], MINIMUM_VALIDATOR_SELF_STAKE_SPARK);
        state.finalize_genesis().unwrap();
        state
    }

    fn governance_deposit_output(owner_pubkey: HybridPubKey, value_spark: u64) -> OutputV1 {
        output_with_value(value_spark, owner_pubkey, 0x44)
    }

    fn governance_propose_op(
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
            title: VariableBytes::from_slice(b"txn oracle").unwrap(),
            description: VariableBytes::from_slice(b"state txn governance test").unwrap(),
            cold_authorization: None,
        };
        let mut op = GovernanceOpV2 {
            action_type: GovernanceActionType::ProposeChange,
            signer_id,
            nonce,
            payload,
            signature: dummy_sig(),
        };
        sign_governance_op(&mut op, keypair, TEST_CHAIN_ID);
        op
    }

    fn governance_commit_op(
        signer_id: Bytes32,
        keypair: &HybridKeypair,
        proposal_id: Bytes32,
        commit_hash: Bytes32,
        nonce: u64,
    ) -> GovernanceOpV2 {
        let payload = GovernancePayload::Commit {
            proposal_id,
            commit_hash,
            cold_authorization: None,
        };
        let mut op = GovernanceOpV2 {
            action_type: GovernanceActionType::CommitVote,
            signer_id,
            nonce,
            payload,
            signature: dummy_sig(),
        };
        sign_governance_op(&mut op, keypair, TEST_CHAIN_ID);
        op
    }

    fn governance_reveal_op(
        signer_id: Bytes32,
        keypair: &HybridKeypair,
        proposal_id: Bytes32,
        vote: u8,
        vote_nonce: Bytes32,
        nonce: u64,
    ) -> GovernanceOpV2 {
        let payload = GovernancePayload::Reveal {
            proposal_id,
            vote,
            nonce: vote_nonce,
            cold_authorization: None,
        };
        let mut op = GovernanceOpV2 {
            action_type: GovernanceActionType::RevealVote,
            signer_id,
            nonce,
            payload,
            signature: dummy_sig(),
        };
        sign_governance_op(&mut op, keypair, TEST_CHAIN_ID);
        op
    }

    fn governance_redelegate_op(
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
        sign_governance_op(&mut op, keypair, TEST_CHAIN_ID);
        op
    }

    fn governance_execute_op(
        signer_id: Bytes32,
        keypair: &HybridKeypair,
        proposal_id: Bytes32,
        nonce: u64,
    ) -> GovernanceOpV2 {
        let payload = GovernancePayload::Execute { proposal_id };
        let mut op = GovernanceOpV2 {
            action_type: GovernanceActionType::ExecuteProposal,
            signer_id,
            nonce,
            payload,
            signature: dummy_sig(),
        };
        sign_governance_op(&mut op, keypair, TEST_CHAIN_ID);
        op
    }

    fn governance_cancel_op(
        signer_id: Bytes32,
        keypair: &HybridKeypair,
        proposal_id: Bytes32,
        nonce: u64,
    ) -> GovernanceOpV2 {
        let payload = GovernancePayload::Cancel {
            proposal_id,
            cold_authorization: None,
        };
        let mut op = GovernanceOpV2 {
            action_type: GovernanceActionType::CancelProposal,
            signer_id,
            nonce,
            payload,
            signature: dummy_sig(),
        };
        sign_governance_op(&mut op, keypair, TEST_CHAIN_ID);
        op
    }

    fn signed_register_validator_op(
        state: &mut ChainState,
        seed: [u8; 32],
        nonce: u64,
    ) -> (StakingOp, Bytes32) {
        let (validator_pubkey, keypair) = make_test_keypair(seed);
        let mut cold_seed = seed;
        cold_seed[0] = cold_seed[0].wrapping_add(1);
        let (cold_pubkey, cold_keypair) = make_test_keypair(cold_seed);
        let validator_id = staking_delegator_id_for_test(&validator_pubkey);
        let vrf_keypair = indra_crypto::VrfKeypair::from_seed(&seed);
        let vrf_pk = vrf_keypair.public_key();
        let challenge = StakingOp::vrf_possession_challenge(
            &state.chain_id,
            &validator_id,
            &Bytes32::from(vrf_pk),
            0,
        )
        .unwrap();
        let (vrf_output, vrf_proof) = indra_crypto::vrf_prove(&vrf_keypair, &challenge);
        let deposit_utxo_id = state
            .utxos
            .insert(
                output_with_value(
                    MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
                    cold_pubkey.clone(),
                    seed[0],
                ),
                0,
                0,
                seed[0] as u32,
            )
            .unwrap();
        let mut op = StakingOp {
            body: StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                deposit_utxo_id,
                validator_pubkey,
                vrf_pk,
                vrf_possession_output: indra_core::types::primitives::Bytes64(vrf_output.0),
                vrf_possession_proof: VariableBytes::from_slice(&vrf_proof.0).unwrap(),
                cold_pubkey: indra_core::types::crypto::ColdHybridPubKey {
                    classical_pk: cold_pubkey.classical_pk,
                    pq_pk: cold_pubkey.pq_pk,
                },
                cold_signature: dummy_sig(),
            },
            nonce,
            signature: dummy_sig(),
        };
        let message = op
            .register_validator_dual_signing_bytes(&state.chain_id)
            .unwrap()
            .unwrap();
        let hot_sig = keypair.sign(&message).unwrap();
        op.signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&hot_sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&hot_sig.pq.0).unwrap(),
        };
        let cold_sig = cold_keypair.sign(&message).unwrap();
        let StakingOpBody::RegisterValidator { cold_signature, .. } = &mut op.body else {
            unreachable!()
        };
        *cold_signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&cold_sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&cold_sig.pq.0).unwrap(),
        };
        (op, validator_id)
    }

    fn signed_delegate_op(
        state: &ChainState,
        validator_id: Bytes32,
        deposit_utxo_id: Bytes32,
        delegator_pubkey: HybridPubKey,
        keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        let mut op = StakingOp {
            body: StakingOpBody::Delegate {
                validator_id,
                deposit_utxo_id,
                delegator_pubkey,
            },
            nonce,
            signature: dummy_sig(),
        };
        sign_staking_op(keypair, &state.chain_id, &mut op);
        op
    }

    fn signed_undelegate_op(
        state: &ChainState,
        validator_id: Bytes32,
        _deposit_utxo_id: Bytes32,
        delegator_pubkey: HybridPubKey,
        keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        let delegator_id = staking_delegator_id_for_test(&delegator_pubkey);
        let position = state
            .stake_positions
            .values()
            .find(|position| {
                position.validator_id == validator_id && position.principal_owner_id == delegator_id
            })
            .expect("delegation must have created a position");
        let mut op = StakingOp {
            body: StakingOpBody::ExitStakePosition {
                position_id: position.position_id,
                amount_spark: position.active.expect("active position").principal_spark,
                custody: position.custody,
                cold_authorization: None,
            },
            nonce,
            signature: dummy_sig(),
        };
        sign_staking_op(keypair, &state.chain_id, &mut op);
        op
    }

    fn signed_claim_rewards_op(
        state: &ChainState,
        validator_id: Bytes32,
        delegator_pubkey: HybridPubKey,
        keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        let mut op = StakingOp {
            body: StakingOpBody::ClaimRewards {
                validator_id,
                delegator_pubkey,
                cold_authorization: None,
            },
            nonce,
            signature: dummy_sig(),
        };
        sign_staking_op(keypair, &state.chain_id, &mut op);
        op
    }

    fn signed_self_stake_op(
        state: &ChainState,
        deposit_utxo_id: Bytes32,
        validator_pubkey: HybridPubKey,
        keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        let mut op = StakingOp {
            body: StakingOpBody::SelfStake {
                deposit_utxo_id,
                validator_pubkey,
                cold_authorization: indra_core::types::staking::ColdStakingAuthorization {
                    cold_key_version: 1,
                    cold_nonce: nonce,
                },
            },
            nonce,
            signature: dummy_sig(),
        };
        sign_staking_op(keypair, &state.chain_id, &mut op);
        op
    }

    fn slash_validator_state(seed: [u8; 32], stake: u64) -> (ChainState, Bytes32, HybridKeypair) {
        let classical = ClassicalKeypair::from_seed(&seed);
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let keypair = HybridKeypair::new(classical, pq);
        let public = keypair.public_key();
        let validator_id =
            indra_core::types::crypto::hybrid_identity_id(&public.classical.0, &public.pq.0);
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        state
            .validators
            .upsert(ValidatorEntry {
                validator_id,
                name: "slash-validator".into(),
                hybrid_classical_pk: Some(public.classical.0),
                hybrid_pq_pk: Some(public.pq.0.to_vec()),
                vrf_pk: Some(indra_crypto::VrfKeypair::from_seed(&seed).public_key()),
                vrf_key_activation_epoch: 0,
                pending_vrf_pk: None,
                pending_vrf_activation_epoch: None,
                stake_spark: stake,
                status: ValidatorStatus::Active,
                registered_epoch: 0,
                last_active_epoch: 0,
                slashed_offense_id: None,
                commission_bps: 1_000,
                pending_commission_bps: None,
                pending_commission_effective_epoch: None,
                min_delegation_spark: 1,
                auto_delegate_to: None,
                network_addr: None,
                network_addr_last_updated_epoch: None,
                cold_hybrid_classical_pk: None,
                cold_hybrid_pq_pk: None,
                cold_key_version: 0,
                cold_nonce: 0,
            })
            .unwrap();
        state.finalize_genesis().unwrap();
        (state, validator_id, keypair)
    }

    fn assert_verified_staking_matches_full(
        label: &str,
        state: &ChainState,
        op: &StakingOp,
        height: u64,
    ) {
        let verified = crate::pending::verify_pending_staking(state, op, height)
            .unwrap_or_else(|error| panic!("{label} fixture must be independently valid: {error}"));
        assert!(crate::pending::staking_authority_unchanged(
            state, op, &verified
        ));
        let mut full = state.clone();
        let mut targeted = state.clone();
        let full_result = try_apply_staking_candidate(&mut full, op, height);
        let targeted_result =
            try_apply_verified_staking_candidate(&mut targeted, op, &verified, height);
        assert_eq!(full_result.is_ok(), targeted_result.is_ok());
        assert_eq!(full.encode_to_vec(), targeted.encode_to_vec());

        let mut mismatched_op = op.clone();
        mismatched_op.nonce = mismatched_op.nonce.saturating_add(1);
        let mut mismatch_state = state.clone();
        assert!(matches!(
            try_apply_verified_staking_candidate(
                &mut mismatch_state,
                &mismatched_op,
                &verified,
                height,
            ),
            Err(StateError::InvariantViolation { .. })
        ));

        // A canonical nonce advance is sufficient to make every operation
        // variant stale. This compares the retained/evicted decision, which
        // is the pool-level observable targeted invalidation must preserve.
        let mut changed = state.clone();
        let signer = op.signer_id();
        if let Some(validator) = changed.validators.get_mut(&signer) {
            validator.cold_nonce = validator.cold_nonce.saturating_add(1);
        } else {
            changed.staking_nonces.insert(signer, op.nonce.max(1));
        }
        let mut full_changed = changed.clone();
        let mut targeted_changed = changed;
        let targeted_changed_result =
            if crate::pending::staking_authority_unchanged(&targeted_changed, op, &verified) {
                try_apply_verified_staking_candidate(&mut targeted_changed, op, &verified, height)
            } else {
                assert!(matches!(
                    try_apply_verified_staking_candidate(
                        &mut targeted_changed.clone(),
                        op,
                        &verified,
                        height,
                    ),
                    Err(StateError::InvariantViolation { .. })
                ));
                match crate::pending::verify_pending_staking(&targeted_changed, op, height) {
                    Ok(refreshed) => try_apply_verified_staking_candidate(
                        &mut targeted_changed,
                        op,
                        &refreshed,
                        height,
                    ),
                    Err(error) => Err(error),
                }
            };
        assert_eq!(
            try_apply_staking_candidate(&mut full_changed, op, height).is_ok(),
            targeted_changed_result.is_ok(),
        );
    }

    fn assert_verified_governance_matches_full(
        label: &str,
        state: &ChainState,
        op: &GovernanceOpV2,
        epoch: u64,
        height: u64,
    ) {
        let verified = crate::pending::verify_pending_governance(state, op, epoch, height)
            .unwrap_or_else(|error| panic!("{label} fixture must be independently valid: {error}"));
        assert!(crate::pending::governance_authority_unchanged(
            state, op, &verified
        ));
        let mut full = state.clone();
        let mut targeted = state.clone();
        assert_eq!(
            try_apply_governance_candidate(&mut full, op, epoch, height).is_ok(),
            try_apply_verified_governance_candidate(&mut targeted, op, &verified, epoch, height)
                .is_ok(),
        );
        assert_eq!(full.encode_to_vec(), targeted.encode_to_vec());

        let mut mismatched_op = op.clone();
        mismatched_op.nonce = mismatched_op.nonce.saturating_add(1);
        let mut mismatch_state = state.clone();
        assert!(matches!(
            try_apply_verified_governance_candidate(
                &mut mismatch_state,
                &mismatched_op,
                &verified,
                epoch,
                height,
            ),
            Err(StateError::InvariantViolation { .. })
        ));

        let mut changed = state.clone();
        if let Some(validator) = changed.validators.get_mut(&op.signer_id) {
            validator.cold_nonce = validator.cold_nonce.saturating_add(1);
        } else {
            changed
                .governance
                .gov_nonces
                .insert(op.signer_id, op.nonce.max(1));
        }
        let mut full_changed = changed.clone();
        let mut targeted_changed = changed;
        let targeted_changed_result =
            if crate::pending::governance_authority_unchanged(&targeted_changed, op, &verified) {
                try_apply_verified_governance_candidate(
                    &mut targeted_changed,
                    op,
                    &verified,
                    epoch,
                    height,
                )
            } else {
                assert!(matches!(
                    try_apply_verified_governance_candidate(
                        &mut targeted_changed.clone(),
                        op,
                        &verified,
                        epoch,
                        height,
                    ),
                    Err(StateError::InvariantViolation { .. })
                ));
                match crate::pending::verify_pending_governance(
                    &targeted_changed,
                    op,
                    epoch,
                    height,
                ) {
                    Ok(refreshed) => try_apply_verified_governance_candidate(
                        &mut targeted_changed,
                        op,
                        &refreshed,
                        epoch,
                        height,
                    ),
                    Err(error) => Err(error),
                }
            };
        assert_eq!(
            try_apply_governance_candidate(&mut full_changed, op, epoch, height,).is_ok(),
            targeted_changed_result.is_ok(),
        );
    }

    #[test]
    fn all_nine_staking_variants_match_full_revalidation_oracle() {
        let height = 1;

        // RegisterValidator (dual hot/new-cold authority).
        let mut register_state = canonical_test_genesis();
        let (register, _) = signed_register_validator_op(&mut register_state, [0x61; 32], 1);
        assert_verified_staking_matches_full("register", &register_state, &register, height);

        let mut state = canonical_test_genesis();
        let (validator_pubkey, validator_hot, validator_id) =
            install_governance_validator(&mut state, [0x62; 32], 2_000_000);
        let (target_pubkey, _target_hot, target_id) =
            install_governance_validator(&mut state, [0x63; 32], 2_000_000);

        // Delegate (hot delegator authority).
        let (delegator_pubkey, delegator) = make_test_keypair([0x64; 32]);
        let deposit = state
            .utxos
            .insert(
                output_with_value(1_000_000, delegator_pubkey.clone(), 0x64),
                0,
                64,
                0,
            )
            .unwrap();
        let delegate = signed_delegate_op(
            &state,
            validator_id,
            deposit,
            delegator_pubkey.clone(),
            &delegator,
            1,
        );
        assert_verified_staking_matches_full("delegate", &state, &delegate, height);

        // Build the canonical position used by ExitStakePosition and ClaimRewards.
        let mut positioned = state.clone();
        try_apply_staking_candidate(&mut positioned, &delegate, height).unwrap();
        let position_id = positioned
            .stake_positions
            .values()
            .find(|position| position.validator_id == validator_id)
            .unwrap()
            .position_id;
        let exit = signed_undelegate_op(
            &positioned,
            validator_id,
            deposit,
            delegator_pubkey.clone(),
            &delegator,
            2,
        );
        assert_verified_staking_matches_full("exit", &positioned, &exit, height + 1);

        let mut rewards = positioned.clone();
        let mut rewarded_position = rewards.stake_positions.get(&position_id).unwrap().clone();
        rewarded_position.pending_rewards_spark = DUST_LIMIT_SPARK;
        rewards
            .stake_positions
            .insert(position_id, rewarded_position);
        let claim =
            signed_claim_rewards_op(&rewards, validator_id, delegator_pubkey, &delegator, 2);
        assert_verified_staking_matches_full("claim", &rewards, &claim, height + 1);

        // SelfStake (validator cold authority).
        let self_deposit = state
            .utxos
            .insert(
                output_with_value(1_000_000, validator_pubkey.clone(), 0x65),
                0,
                65,
                0,
            )
            .unwrap();
        let mut self_stake =
            signed_self_stake_op(&state, self_deposit, validator_pubkey, &validator_hot, 1);
        if let StakingOpBody::SelfStake {
            cold_authorization, ..
        } = &mut self_stake.body
        {
            *cold_authorization = indra_core::types::staking::ColdStakingAuthorization {
                cold_key_version: 1,
                cold_nonce: 1,
            };
        }
        self_stake.nonce = 0;
        sign_staking_op(&validator_hot, &state.chain_id, &mut self_stake);
        assert_verified_staking_matches_full("self-stake", &state, &self_stake, height);

        let cold_auth = indra_core::types::staking::ColdStakingAuthorization {
            cold_key_version: 1,
            cold_nonce: 1,
        };
        let mut commission = StakingOp {
            body: StakingOpBody::SetCommission {
                validator_id,
                new_commission_bps: 1_100,
                cold_authorization: cold_auth,
            },
            nonce: 0,
            signature: dummy_sig(),
        };
        sign_staking_op(&validator_hot, &state.chain_id, &mut commission);
        assert_verified_staking_matches_full("commission", &state, &commission, height);

        let mut auto_delegate = StakingOp {
            body: StakingOpBody::SetAutoDelegate {
                validator_id,
                target_validator_id: target_id,
                cold_authorization: cold_auth,
            },
            nonce: 0,
            signature: dummy_sig(),
        };
        sign_staking_op(&validator_hot, &state.chain_id, &mut auto_delegate);
        assert_verified_staking_matches_full("auto-delegate", &state, &auto_delegate, height);

        let proposed_cold = make_test_keypair([0x66; 32]).1;
        let current_cold = make_test_keypair([0x62; 32]).1;
        let mut rotate = StakingOp {
            body: StakingOpBody::RotateValidatorColdKey {
                validator_id,
                current_cold_key_version: 1,
                new_cold_key_version: 2,
                current_cold_nonce: 1,
                new_cold_pubkey: indra_core::types::crypto::ColdHybridPubKey {
                    classical_pk: Bytes32::from(proposed_cold.public_key().classical.0),
                    pq_pk: VariableBytes::from_slice(&proposed_cold.public_key().pq.0).unwrap(),
                },
                new_cold_signature: Some(dummy_sig()),
            },
            nonce: 0,
            signature: dummy_sig(),
        };
        let rotate_bytes = rotate
            .rotate_validator_cold_key_dual_signing_bytes(&state.chain_id)
            .unwrap()
            .unwrap();
        rotate.signature = {
            let sig = current_cold.sign(&rotate_bytes).unwrap();
            HybridSignature {
                classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
                pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
            }
        };
        if let StakingOpBody::RotateValidatorColdKey {
            new_cold_signature, ..
        } = &mut rotate.body
        {
            let sig = proposed_cold.sign(&rotate_bytes).unwrap();
            *new_cold_signature = Some(HybridSignature {
                classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
                pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
            });
        }
        assert_verified_staking_matches_full("rotate", &state, &rotate, height);

        let mut network = StakingOp {
            body: StakingOpBody::UpdateNetworkAddress {
                validator_id,
                network_addr: Some("203.0.113.10:30303".into()),
            },
            nonce: 1,
            signature: dummy_sig(),
        };
        sign_staking_op(&validator_hot, &state.chain_id, &mut network);
        assert_verified_staking_matches_full("network", &state, &network, u64::MAX);
        let _ = target_pubkey;
    }

    #[test]
    fn all_six_governance_variants_hot_and_cold_match_full_revalidation_oracle() {
        let epoch = 0;
        let height = 1;

        let mut propose_state = canonical_test_genesis();
        propose_state.governance.params.proposal_deposit_spark = 1_000;
        let (proposer_pubkey, proposer_keypair, proposer_id) =
            install_governance_validator(&mut propose_state, [0x71; 32], 100_000);
        let deposit = propose_state
            .utxos
            .insert(
                governance_deposit_output(proposer_pubkey.clone(), 1_500),
                0,
                71,
                0,
            )
            .unwrap();
        let propose = governance_propose_op(
            proposer_id,
            &proposer_keypair,
            proposer_pubkey,
            deposit,
            1,
            GovernableAction::SetMinDelegationSpark { value: 100_000 },
        );
        assert_verified_governance_matches_full("propose", &propose_state, &propose, epoch, height);

        let vote_nonce = Bytes32::from([0x72; 32]);
        let (commit_state, _, proposer_keypair, proposer_id, proposal_id) =
            governance_proposal_state(ProposalPhase::Commit);
        let commit_hash = governance_vote_commit_hash(proposal_id, proposer_id, 1, vote_nonce);
        let commit =
            governance_commit_op(proposer_id, &proposer_keypair, proposal_id, commit_hash, 1);
        assert_verified_governance_matches_full("commit", &commit_state, &commit, epoch, height);

        let (mut reveal_state, _, proposer_keypair, proposer_id, proposal_id) =
            governance_proposal_state(ProposalPhase::Reveal);
        let commit_hash = governance_vote_commit_hash(proposal_id, proposer_id, 1, vote_nonce);
        reveal_state
            .governance
            .proposals
            .get_mut(&proposal_id)
            .unwrap()
            .commits
            .insert(
                proposer_id,
                VoteCommit {
                    validator_id: proposer_id,
                    commit_hash,
                    committed_epoch: 0,
                },
            );
        reveal_state
            .validators
            .get_mut(&proposer_id)
            .unwrap()
            .cold_nonce = 1;
        let reveal = governance_reveal_op(
            proposer_id,
            &proposer_keypair,
            proposal_id,
            1,
            vote_nonce,
            2,
        );
        assert_verified_governance_matches_full("reveal", &reveal_state, &reveal, epoch, height);

        let (mut redelegate_state, _, _, _, proposal_id) =
            governance_proposal_state(ProposalPhase::Reveal);
        let (_, _, from_validator) =
            install_governance_validator(&mut redelegate_state, [0x73; 32], 100_000);
        let (_, _, to_validator) =
            install_governance_validator(&mut redelegate_state, [0x74; 32], 100_000);
        let proposal = redelegate_state
            .governance
            .proposals
            .get_mut(&proposal_id)
            .unwrap();
        for validator_id in [from_validator, to_validator] {
            proposal.reveals.insert(
                validator_id,
                VoteReveal {
                    validator_id,
                    vote: true,
                    revealed_epoch: 0,
                },
            );
        }
        let (delegator_pubkey, delegator_keypair) = make_test_keypair([0x75; 32]);
        let delegator_id = governance_validator_id(&delegator_pubkey);
        redelegate_state
            .delegator_identities
            .insert(delegator_id, delegator_pubkey);
        let position = indra_core::types::stake_position::StakePositionV1::new(
            from_validator,
            delegator_id,
            indra_core::types::stake_position::PositionCustodyV1::DelegatorIdentity {
                delegator_id,
            },
            Some(
                indra_core::types::stake_position::ActiveStakeAggregateV1::new(100_000, 0, 0)
                    .unwrap(),
            ),
            1,
            0,
        )
        .unwrap();
        redelegate_state
            .stake_positions
            .insert(position.position_id, position);
        let redelegate = governance_redelegate_op(
            delegator_id,
            &delegator_keypair,
            proposal_id,
            from_validator,
            to_validator,
            1,
            1,
        );
        assert_verified_governance_matches_full(
            "redelegate",
            &redelegate_state,
            &redelegate,
            epoch,
            height,
        );

        let (mut execute_state, _, proposer_keypair, proposer_id, proposal_id) =
            governance_proposal_state(ProposalPhase::ExecDelay);
        execute_state
            .governance
            .queued_executions
            .push(QueuedExecution {
                proposal_id,
                action: GovernableAction::SetMinDelegationSpark { value: 100_001 },
                executable_epoch: 0,
                executed: false,
            });
        let execute = governance_execute_op(proposer_id, &proposer_keypair, proposal_id, 1);
        assert_verified_governance_matches_full("execute", &execute_state, &execute, epoch, height);

        let (cancel_state, _, proposer_keypair, proposer_id, proposal_id) =
            governance_proposal_state(ProposalPhase::Deliberation);
        let cancel = governance_cancel_op(proposer_id, &proposer_keypair, proposal_id, 1);
        assert_verified_governance_matches_full("cancel", &cancel_state, &cancel, epoch, height);
    }

    fn capstone_accounted_value(state: &ChainState) -> u64 {
        let utxos = state
            .utxos
            .all_entries()
            .map(|entry| entry.output.value_spark)
            .sum::<u64>();
        let positions = state.stake_positions.values().fold(0u64, |sum, position| {
            sum.saturating_add(
                position
                    .active
                    .map(|active| active.principal_spark)
                    .unwrap_or(0),
            )
            .saturating_add(position.pending_rewards_spark)
        });
        let tranches = state
            .unbonding_tranches
            .values()
            .map(|tranche| tranche.principal_spark)
            .sum::<u64>();
        utxos
            .saturating_add(positions)
            .saturating_add(tranches)
            .saturating_add(state.fee_reward_pool)
    }

    const TEST_SNAPSHOT_ROOT: Bytes32 = Bytes32([0x5A; 32]);

    fn signed_vote(
        keypair: &HybridKeypair,
        validator_id: Bytes32,
        height: u64,
        round: u32,
        step: VoteStep,
        block_hash: Bytes32,
    ) -> VoteV1 {
        signed_vote_with_snapshot_root(
            keypair,
            validator_id,
            height,
            round,
            step,
            block_hash,
            TEST_SNAPSHOT_ROOT,
        )
    }

    fn signed_vote_with_snapshot_root(
        keypair: &HybridKeypair,
        validator_id: Bytes32,
        height: u64,
        round: u32,
        step: VoteStep,
        block_hash: Bytes32,
        snapshot_root: Bytes32,
    ) -> VoteV1 {
        let signing_bytes = indra_core::types::vote_signing::vote_signing_bytes(
            height,
            round,
            step,
            &block_hash,
            &validator_id,
            &snapshot_root,
            TEST_CHAIN_ID,
        )
        .unwrap();
        let sig = keypair.sign(&signing_bytes).unwrap();
        VoteV1 {
            height,
            round,
            step,
            block_hash,
            validator_id,
            snapshot_root,
            signature: HybridSignature {
                classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
                pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
            },
        }
    }

    fn dummy_output(byte: u8, owner_pubkey: HybridPubKey) -> OutputV1 {
        let value = TEST_INPUT_VALUE + byte as u64;
        output_with_value(value, owner_pubkey, byte)
    }

    fn output_with_value(value: u64, owner_pubkey: HybridPubKey, _byte: u8) -> OutputV1 {
        OutputV1 {
            value_spark: value,
            owner_pubkey,
            lock_height: 0,
        }
    }

    /// Build a state that has one pre-existing UTXO ready to be spent.
    fn state_with_utxo() -> (ChainState, Bytes32, HybridKeypair, [u8; 32], u64) {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        install_governance_validator(&mut state, [0xF1; 32], MINIMUM_VALIDATOR_SELF_STAKE_SPARK);
        let (owner_pubkey, keypair) = make_test_keypair([0x11; 32]);
        let output = dummy_output(0x01, owner_pubkey);
        let utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();
        state.finalize_genesis().unwrap();
        (state, utxo_id, keypair, [0x01; 32], TEST_INPUT_VALUE + 1)
    }

    #[test]
    fn transaction_rejects_new_output_with_noncanonical_hybrid_owner_key() {
        let (state, utxo_id, keypair, fixture_tag, value) = state_with_utxo();
        let mut tx = make_tx(&state, &keypair, utxo_id, value, fixture_tag);
        tx.outputs[0].owner_pubkey.pq_pk =
            VariableBytes::from_slice(&[0u8; indra_crypto::PQ_PK_BYTES]).unwrap();
        tx.signature = sign_transaction(&keypair, &state.chain_id, &tx);

        let error =
            validate_transaction(&state, &tx, &state.chain_id, &mut HashSet::new(), 1).unwrap_err();

        assert!(matches!(error, StateError::InvalidOutputOwnerKey { .. }));
    }

    fn make_tx(
        state: &ChainState,
        keypair: &HybridKeypair,
        utxo_id: Bytes32,
        input_value: u64,
        _input_blinding: [u8; 32],
    ) -> TransactionV1 {
        let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 10;
        let output_value = input_value - fee;
        let (owner_pubkey, _) = make_test_keypair([0x11; 32]);
        let mut tx = TransactionV1 {
            version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
            signature_module_id: 1,
            inputs: vec![InputV1 { utxo_id }],
            outputs: vec![OutputV1 {
                value_spark: output_value,
                owner_pubkey,
                lock_height: 0,
            }],
            fee_amount: fee,
            signature: dummy_sig(),
        };
        tx.signature = sign_transaction(keypair, &state.chain_id, &tx);
        tx
    }

    fn make_block(state: &ChainState, txs: Vec<TransactionV1>) -> BlockVNext {
        let height = state.height + 1;
        make_block_at_height(state, txs, height, 1_700_000_000 + height)
    }

    #[test]
    #[ignore = "real-hardware release benchmark; run explicitly with --release --ignored --nocapture"]
    fn max_transaction_block_validation_real_hardware_benchmark() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        install_governance_validator(&mut state, [0xF1; 32], MINIMUM_VALIDATOR_SELF_STAKE_SPARK);
        let (owner_pubkey, keypair) = make_test_keypair([0x11; 32]);
        let mut inputs = Vec::with_capacity(MAX_TX_PER_BLOCK);
        for index in 0..MAX_TX_PER_BLOCK {
            let byte = (index + 1) as u8;
            let output = dummy_output(byte, owner_pubkey.clone());
            let value = TEST_INPUT_VALUE + u64::from(byte);
            let utxo_id = state.utxos.insert(output, 0, 0, index as u32).unwrap();
            inputs.push((utxo_id, value, [byte; 32]));
        }
        state.finalize_genesis().unwrap();
        let transactions = inputs
            .into_iter()
            .map(|(utxo_id, value, fixture_tag)| {
                make_tx(&state, &keypair, utxo_id, value, fixture_tag)
            })
            .collect();
        let block = make_block(&state, transactions);
        let mut samples = Vec::new();
        for _ in 0..5 {
            let mut projected = state.clone();
            let started = std::time::Instant::now();
            std::hint::black_box(apply_block_with_effects(&mut projected, &block, 0).unwrap());
            samples.push(started.elapsed());
        }
        samples.sort_unstable();
        eprintln!(
            "MAX_TX_BLOCK_BENCH samples={samples:?} median_ms={:.3}",
            samples[samples.len() / 2].as_secs_f64() * 1_000.0
        );
    }

    fn make_block_at_height(
        state: &ChainState,
        txs: Vec<TransactionV1>,
        height: u64,
        timestamp: u64,
    ) -> BlockVNext {
        let quorum_certificate = if height <= 1 {
            VariableBytes::from_slice(&[]).unwrap()
        } else {
            let snapshot = state.snapshot_for_consensus_height(height - 1).unwrap();
            let votes: Vec<_> = snapshot
                .entries()
                .iter()
                .map(|entry| {
                    let keypair = [[0xF0; 32], [0xF1; 32], [0xD9; 32]]
                        .into_iter()
                        .map(make_test_keypair)
                        .find(|(key, _)| key.identity_id() == entry.validator_id)
                        .map(|(_, keypair)| keypair)
                        .expect("test snapshot validator seed must be known");
                    signed_vote_with_snapshot_root(
                        &keypair,
                        entry.validator_id,
                        height - 1,
                        0,
                        VoteStep::Precommit,
                        state.tip_hash,
                        snapshot.snapshot_root,
                    )
                })
                .collect();
            let qc = QuorumCertificateV1 {
                height: height - 1,
                round: 0,
                block_hash: state.tip_hash,
                snapshot_root: snapshot.snapshot_root,
                signer_bitfield: {
                    let mut bits = [0u8; indra_core::types::qc::SIGNER_BITFIELD_BYTES];
                    for position in 0..votes.len() {
                        bits[position / 8] |= 1 << (position % 8);
                    }
                    bits
                },
                pq_signatures: votes
                    .iter()
                    .map(|vote| PQVoteSig {
                        validator_id: vote.validator_id,
                        pq_sig: vote.signature.pq_sig.clone(),
                    })
                    .collect(),
                classical_signatures: votes
                    .iter()
                    .map(|vote| indra_core::types::qc::ClassicalVoteSig {
                        validator_id: vote.validator_id,
                        classical_sig: vote.signature.classical_sig.clone(),
                    })
                    .collect(),
            };
            VariableBytes::from_slice(&qc.encode_to_vec()).unwrap()
        };
        BlockVNext {
            header: BlockHeaderVNext {
                protocol_version: ProtocolVersion(BLOCK_FORMAT_VERSION),
                height,
                prev_hash: state.tip_hash,
                timestamp,
                state_root: Bytes32::ZERO,
                validator_set_root: Bytes32::ZERO,
                mempool_set_root: Bytes32::ZERO,
                value_hash: Bytes32::ZERO,
                base_fee: state.base_fee,
                proposer_round: 0,
                polc_round: None,
                proposer_id: Bytes32::from([0x91; 32]),
                vrf_suite: indra_core::types::block::VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
                election_seed: state.election_seed,
                proposer_vrf_output: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                proposer_vrf_proof: VariableBytes::from_slice(&[0u8; 80]).unwrap(),
                value_entropy: indra_core::types::block::ProposalEntropyV1 {
                    origin_proposer_id: Bytes32::from([0x91; 32]),
                    origin_round: 0,
                    vrf_output: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                    vrf_proof: VariableBytes::from_slice(&[0u8; 80]).unwrap(),
                },
                sortition_claim: indra_core::types::block::SortitionClaimV1::PraosThreshold,
                proposer_priority: indra_core::types::primitives::Bytes64([0; 64]),
                quorum_certificate,
            },
            transactions: txs,
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        }
    }

    fn install_inert_gate_snapshot_fixture(state: &mut ChainState) {
        state.rebuild_state_commitment_v2(state.height);
    }

    fn assert_same_consensus_state(left: &ChainState, right: &ChainState) {
        assert_eq!(left.encode_to_vec(), right.encode_to_vec());
        assert_eq!(
            crate::state_root::compute_state_root(left),
            crate::state_root::compute_state_root(right)
        );
        assert_eq!(
            crate::state_root::compute_validator_set_root(left),
            crate::state_root::compute_validator_set_root(right)
        );
    }

    #[derive(Debug)]
    struct OracleOutcome {
        state: ChainState,
    }

    fn clone_atomic_reference_apply_block(
        pre_state: &ChainState,
        block: &BlockVNext,
        timestamp_secs: u64,
    ) -> StateResult<OracleOutcome> {
        let mut scratch = pre_state.clone();
        apply_block(&mut scratch, block, timestamp_secs)?;
        Ok(OracleOutcome { state: scratch })
    }

    fn test_proposal_record(
        proposal_id: Bytes32,
        proposer_id: Bytes32,
        proposer_pubkey: HybridPubKey,
        action: GovernableAction,
        phase: ProposalPhase,
    ) -> ProposalRecord {
        ProposalRecord {
            proposal_id,
            proposer_id,
            proposer_pubkey,
            tier: action.tier(),
            action,
            title: "state-txn".into(),
            description: "state transaction test proposal".into(),
            deposit_spark: 1_000,
            deposit_burned: false,
            proposed_epoch: 0,
            commit_start_epoch: 0,
            reveal_start_epoch: 0,
            tally_epoch: 0,
            exec_delay_epochs: 0,
            quorum_bps: 5_000,
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
            passed: None,
        }
    }

    fn governance_proposal_state(
        phase: ProposalPhase,
    ) -> (ChainState, HybridPubKey, HybridKeypair, Bytes32, Bytes32) {
        let mut state = canonical_test_genesis();
        state.governance.params.proposal_deposit_spark = 1_000;
        let (proposer_pubkey, proposer_keypair, proposer_id) =
            install_governance_validator(&mut state, [0x91; 32], 100_000);
        state.consensus_snapshots.clear();
        state.reward_economic_snapshot = None;
        state.slash_membership_roots.clear();
        state.finalize_genesis().unwrap();
        state.rebuild_state_commitment_v2(0);
        let action = GovernableAction::SetMinDelegationSpark { value: 100_000 };
        let proposal_id = compute_proposal_id(proposer_id, &action, 0, TEST_CHAIN_ID);
        let mut proposal = test_proposal_record(
            proposal_id,
            proposer_id,
            proposer_pubkey.clone(),
            action,
            phase,
        );
        proposal.snapshot1 = Some(GovernanceSnapshot {
            weights: BTreeMap::from([(proposer_id, 100_000)]),
            total_stake: 100_000,
        });
        state.governance.proposals.insert(proposal_id, proposal);
        state.monetary_aggregates = state.recompute_monetary_aggregates().unwrap();
        state.total_supply = state.monetary_aggregates.total_claims_spark().unwrap();
        state.monetary_ledger =
            crate::monetary::MonetaryLedgerV1::genesis(state.total_supply).unwrap();
        (
            state,
            proposer_pubkey,
            proposer_keypair,
            proposer_id,
            proposal_id,
        )
    }

    fn assert_all_failpoints_roll_back(state: &ChainState, block: &BlockVNext) -> usize {
        crate::txn::set_fail_after_mutation(None);
        let mut success_state = state.clone();
        apply_block(&mut success_state, block, 0).unwrap();
        let mutation_count = crate::txn::mutation_count();
        assert!(mutation_count > 0);
        println!(
            "state_txn_failpoint_coverage height={} mutation_count={mutation_count}",
            block.header.height
        );

        for fail_after in 1..=mutation_count {
            crate::txn::set_fail_after_mutation(Some(fail_after));
            let mut candidate = state.clone();
            let err = apply_block(&mut candidate, block, 0).unwrap_err();
            assert!(
                err.to_string()
                    .contains("state transaction failpoint injected after mutation"),
                "unexpected error at failpoint {fail_after}: {err}"
            );
            assert_same_consensus_state(&candidate, state);
        }
        crate::txn::set_fail_after_mutation(None);
        mutation_count
    }

    fn empty_block_at(state: &ChainState, height: u64, timestamp: u64) -> BlockVNext {
        make_block_at_height(state, vec![], height, timestamp)
    }

    // ── Tests ─────────────────────────────────────────────────────────────

    #[test]
    fn project_block_for_roots_restores_state_on_success() {
        let mut state = canonical_test_genesis();
        install_inert_gate_snapshot_fixture(&mut state);
        state.height = 0;
        state.tip_hash = Bytes32::ZERO;
        state.state_commitment_v2 = None;
        let original = state.clone();
        let block = empty_block_at(&state, 1, 0);

        let projected = project_block_for_roots(&mut state, &block, 0).unwrap();
        assert_ne!(projected.state_root, Bytes32::ZERO);
        assert_same_consensus_state(&state, &original);
        assert!(
            state.state_commitment_v2.is_none(),
            "projection must not leave behind a warmed StateCommitmentV2 cache"
        );
        assert_eq!(state, original);
    }

    #[test]
    fn project_block_for_roots_restores_state_on_apply_failure() {
        let state = canonical_test_genesis();
        let mut block = make_block(&state, vec![]);
        block.header.prev_hash = Bytes32::from([0xEE; 32]);
        let reference_err = clone_atomic_reference_apply_block(&state, &block, 0).unwrap_err();

        let mut projected_state = state.clone();
        let projected_err = project_block_for_roots(&mut projected_state, &block, 0).unwrap_err();
        assert_eq!(projected_err.to_string(), reference_err.to_string());
        assert_same_consensus_state(&projected_state, &state);
        assert_eq!(
            projected_state.state_commitment_v2.is_some(),
            state.state_commitment_v2.is_some()
        );
    }

    #[test]
    fn project_block_for_roots_preserves_active_state_commitment_v2_cache() {
        let mut state = canonical_test_genesis();
        install_inert_gate_snapshot_fixture(&mut state);
        state.height = 0;
        state.tip_hash = Bytes32::ZERO;
        state.rebuild_state_commitment_v2(state.height);
        assert!(
            state.state_commitment_v2.is_some(),
            "test setup must start with a warm StateCommitmentV2 cache"
        );
        let original = state.clone();
        let original_root = state.state_commitment_v2_root(state.height);
        let mut rebuilt_original = state.clone();
        rebuilt_original.rebuild_state_commitment_v2(state.height);
        assert_eq!(
            rebuilt_original.state_commitment_v2_root(state.height),
            original_root,
            "test setup cache must already match a full rebuild"
        );

        let success_block = empty_block_at(&state, 1, 0);
        let projected = project_block_for_roots(&mut state, &success_block, 0).unwrap();
        assert_ne!(projected.state_root, Bytes32::ZERO);
        assert_same_consensus_state(&state, &original);
        assert!(
            state.state_commitment_v2.is_some(),
            "successful rollback projection must preserve a cache that was already warm"
        );
        let success_rollback_root = state.state_commitment_v2_root(original.height);
        state.rebuild_state_commitment_v2(original.height);
        assert_eq!(
            state.state_commitment_v2_root(original.height),
            success_rollback_root,
            "cache after successful rollback projection must match full rebuild"
        );
        assert_eq!(state, original);

        let mut failing_state = original.clone();
        let mut failing_block = success_block;
        failing_block.header.prev_hash = Bytes32::from([0xEE; 32]);
        let err = project_block_for_roots(&mut failing_state, &failing_block, 0).unwrap_err();
        assert_eq!(
            err.to_string(),
            clone_atomic_reference_apply_block(&original, &failing_block, 0)
                .unwrap_err()
                .to_string()
        );
        assert_same_consensus_state(&failing_state, &original);
        assert!(
            failing_state.state_commitment_v2.is_some(),
            "failed rollback projection must preserve a cache that was already warm"
        );
        let failure_rollback_root = failing_state.state_commitment_v2_root(original.height);
        failing_state.rebuild_state_commitment_v2(original.height);
        assert_eq!(
            failing_state.state_commitment_v2_root(original.height),
            failure_rollback_root,
            "cache after failed rollback projection must match full rebuild"
        );
        assert_eq!(failing_state, original);
    }

    #[test]
    fn project_block_for_roots_failpoint_rollback_covers_each_mutation() {
        let (state, utxo_id, keypair, blinding, value) = state_with_utxo();
        let tx = make_tx(&state, &keypair, utxo_id, value, blinding);
        let block = make_block(&state, vec![tx]);

        crate::txn::set_fail_after_mutation(None);
        let mut success_state = state.clone();
        project_block_for_roots(&mut success_state, &block, 0).unwrap();
        let mutation_count = crate::txn::mutation_count();
        assert!(mutation_count > 0);

        for fail_after in 1..=mutation_count {
            crate::txn::set_fail_after_mutation(Some(fail_after));
            let mut candidate = state.clone();
            let err = project_block_for_roots(&mut candidate, &block, 0).unwrap_err();
            assert!(
                err.to_string()
                    .contains("state transaction failpoint injected after mutation"),
                "unexpected error at failpoint {fail_after}: {err}"
            );
            assert_same_consensus_state(&candidate, &state);
            assert_eq!(
                candidate.state_commitment_v2.is_some(),
                state.state_commitment_v2.is_some()
            );
        }
        crate::txn::set_fail_after_mutation(None);
    }

    #[test]
    fn committed_effect_journal_covers_transaction_validity_state_diff() {
        let (mut state, utxo_id, keypair, blinding, value) = state_with_utxo();
        let tx = make_tx(&state, &keypair, utxo_id, value, blinding);
        let block = make_block(&state, vec![tx]);
        let before = state.clone();
        let outcome = apply_block_with_effects(&mut state, &block, 0).unwrap();

        assert_ne!(before.utxos, state.utxos);
        assert!(outcome.effects.utxo_set_changed);
        assert!(outcome.effects.spent_utxos.contains(&utxo_id));
        assert_eq!(
            before.base_fee != state.base_fee,
            outcome.effects.base_fee_changed
        );
        assert_eq!(
            before.staking_nonces != state.staking_nonces,
            !outcome.effects.staking_nonces_changed.is_empty()
        );
        assert_eq!(
            before.governance.params != state.governance.params,
            outcome.effects.governance_params_changed
        );
        let uncovered: Vec<_> = ChainState::changed_fields(&before, &state)
            .into_iter()
            .filter(|field| !outcome.effects.covers_field(*field))
            .collect();
        assert!(
            uncovered.is_empty(),
            "uncovered changed fields: {uncovered:?}"
        );
    }

    #[test]
    fn state_txn_rolls_back_after_each_transaction_mutation_failpoint() {
        let (state, utxo_id, keypair, blinding, value) = state_with_utxo();
        let tx = make_tx(&state, &keypair, utxo_id, value, blinding);
        let block = make_block(&state, vec![tx]);

        let mutation_count = assert_all_failpoints_roll_back(&state, &block);
        assert!(
            mutation_count >= 6,
            "transaction block should exercise several undo-recorded mutations, got {mutation_count}"
        );
    }

    #[test]
    fn transaction_candidate_adapter_rolls_back_partial_application() {
        let (state, utxo_id, keypair, blinding, value) = state_with_utxo();
        let tx = make_tx(&state, &keypair, utxo_id, value, blinding);
        let before = state.clone();
        let mut scratch = state;
        let dust_limit =
            indra_core::types::primitives::transaction_dust_limit_spark(scratch.utxos.len());
        crate::txn::set_fail_after_mutation(Some(1));
        assert!(
            try_apply_transaction_candidate_with_dust(&mut scratch, &tx, 1, 0, dust_limit).is_err()
        );
        crate::txn::set_fail_after_mutation(None);
        assert_eq!(scratch.encode_to_vec(), before.encode_to_vec());
        assert_eq!(scratch, before);
    }

    #[test]
    fn staking_candidate_adapter_rolls_back_partial_application() {
        let mut state = canonical_test_genesis();
        let validator_id = state
            .validators
            .active_validators()
            .next()
            .unwrap()
            .validator_id;
        let (delegator_pubkey, delegator_keypair) = make_test_keypair([0xC2; 32]);
        let deposit = state
            .utxos
            .insert(
                output_with_value(100_000, delegator_pubkey.clone(), 0x22),
                0,
                1,
                0,
            )
            .unwrap();
        state.consensus_snapshots.clear();
        state.reward_economic_snapshot = None;
        state.slash_membership_roots.clear();
        state.finalize_genesis().unwrap();
        let op = signed_delegate_op(
            &state,
            validator_id,
            deposit,
            delegator_pubkey,
            &delegator_keypair,
            1,
        );
        let before = state.clone();
        let mut scratch = state;
        crate::txn::set_fail_after_mutation(Some(1));
        assert!(try_apply_staking_candidate(&mut scratch, &op, 1).is_err());
        crate::txn::set_fail_after_mutation(None);
        assert_eq!(scratch.encode_to_vec(), before.encode_to_vec());
        assert_eq!(scratch, before);
    }

    #[test]
    fn governance_candidate_adapter_rolls_back_partial_application() {
        let mut state = canonical_test_genesis();
        state.governance.params.proposal_deposit_spark = 1_000;
        let (pubkey, keypair, signer_id) =
            install_governance_validator(&mut state, [0xC3; 32], 100_000);
        let deposit = state
            .utxos
            .insert(governance_deposit_output(pubkey.clone(), 1_500), 0, 2, 0)
            .unwrap();
        let op = governance_propose_op(
            signer_id,
            &keypair,
            pubkey,
            deposit,
            1,
            GovernableAction::SetMinDelegationSpark { value: 100_000 },
        );
        let before = state.clone();
        let mut scratch = state;
        crate::txn::set_fail_after_mutation(Some(1));
        assert!(try_apply_governance_candidate(&mut scratch, &op, 0, 1).is_err());
        crate::txn::set_fail_after_mutation(None);
        assert_eq!(scratch.encode_to_vec(), before.encode_to_vec());
        assert_eq!(scratch, before);
    }

    #[test]
    fn slash_candidate_adapter_rolls_back_partial_application() {
        let (state, validator_id, keypair) = slash_validator_state([0xC4; 32], 1_000_000);
        let snapshot = state.build_genesis_consensus_snapshot().unwrap();
        let (position, _) = snapshot.entry_with_position(&validator_id).unwrap();
        let proof = build_slash_membership_proof(&snapshot, position).unwrap();
        let evidence = SlashEvidenceV2 {
            validator_id,
            vote_1: signed_vote(
                &keypair,
                validator_id,
                1,
                0,
                VoteStep::Precommit,
                Bytes32::from([0xC5; 32]),
            ),
            vote_2: signed_vote(
                &keypair,
                validator_id,
                1,
                0,
                VoteStep::Precommit,
                Bytes32::from([0xC6; 32]),
            ),
            membership_proof: proof,
        };
        let before = state.clone();
        let mut scratch = state;
        crate::txn::set_fail_after_mutation(Some(1));
        assert!(try_apply_slash_candidate(&mut scratch, &evidence, 1, None).is_err());
        crate::txn::set_fail_after_mutation(None);
        assert_eq!(scratch.encode_to_vec(), before.encode_to_vec());
        assert_eq!(scratch, before);
    }

    #[test]
    fn state_txn_rolls_back_governance_proposal_failpoints() {
        let mut state = canonical_test_genesis();
        state.governance.params.proposal_deposit_spark = 1_000;
        let (proposer_pubkey, proposer_keypair, proposer_id) =
            install_governance_validator(&mut state, [0x81; 32], 100_000);
        let deposit = state
            .utxos
            .insert(
                governance_deposit_output(proposer_pubkey.clone(), 1_500),
                0,
                0,
                0,
            )
            .unwrap();
        state.consensus_snapshots.clear();
        state.reward_economic_snapshot = None;
        state.slash_membership_roots.clear();
        state.finalize_genesis().unwrap();
        let op = governance_propose_op(
            proposer_id,
            &proposer_keypair,
            proposer_pubkey,
            deposit,
            1,
            GovernableAction::SetMinDelegationSpark { value: 100_000 },
        );
        let mut block = make_block(&state, vec![]);
        block.governance_ops.push(op);
        let mutation_count = assert_all_failpoints_roll_back(&state, &block);
        assert!(
            mutation_count >= 4,
            "governance proposal block should exercise scoped undo mutations, got {mutation_count}"
        );
    }

    #[test]
    fn state_txn_rolls_back_governance_commit_reveal_execute_cancel_failpoints() {
        let vote_nonce = Bytes32::from([0xA7; 32]);

        let (commit_state, _, proposer_keypair, proposer_id, proposal_id) =
            governance_proposal_state(ProposalPhase::Commit);
        let commit_hash = governance_vote_commit_hash(proposal_id, proposer_id, 1, vote_nonce);
        let commit_op =
            governance_commit_op(proposer_id, &proposer_keypair, proposal_id, commit_hash, 1);
        let mut commit_block = make_block(&commit_state, vec![]);
        commit_block.governance_ops.push(commit_op);
        let commit_count = assert_all_failpoints_roll_back(&commit_state, &commit_block);
        assert!(
            commit_count >= 3,
            "governance commit block should exercise scoped undo mutations, got {commit_count}"
        );

        let (mut reveal_state, _, proposer_keypair, proposer_id, proposal_id) =
            governance_proposal_state(ProposalPhase::Reveal);
        let commit_hash = governance_vote_commit_hash(proposal_id, proposer_id, 1, vote_nonce);
        reveal_state
            .governance
            .proposals
            .get_mut(&proposal_id)
            .unwrap()
            .commits
            .insert(
                proposer_id,
                VoteCommit {
                    validator_id: proposer_id,
                    commit_hash,
                    committed_epoch: 0,
                },
            );
        // Commit/reveal authorization is cold-key-native in the pure protocol.
        // Model the preceding commit by advancing the validator's cold nonce.
        reveal_state
            .validators
            .get_mut(&proposer_id)
            .unwrap()
            .cold_nonce = 1;
        let reveal_op = governance_reveal_op(
            proposer_id,
            &proposer_keypair,
            proposal_id,
            1,
            vote_nonce,
            2,
        );
        let mut reveal_block = make_block(&reveal_state, vec![]);
        reveal_block.governance_ops.push(reveal_op);
        let reveal_count = assert_all_failpoints_roll_back(&reveal_state, &reveal_block);
        assert!(
            reveal_count >= 3,
            "governance reveal block should exercise scoped undo mutations, got {reveal_count}"
        );

        let (mut execute_state, _, proposer_keypair, proposer_id, proposal_id) =
            governance_proposal_state(ProposalPhase::ExecDelay);
        execute_state
            .governance
            .queued_executions
            .push(QueuedExecution {
                proposal_id,
                action: GovernableAction::SetMinDelegationSpark { value: 100_001 },
                executable_epoch: 0,
                executed: false,
            });
        let execute_op = governance_execute_op(proposer_id, &proposer_keypair, proposal_id, 1);
        let mut execute_block = make_block(&execute_state, vec![]);
        execute_block.governance_ops.push(execute_op);
        let execute_count = assert_all_failpoints_roll_back(&execute_state, &execute_block);
        assert!(
            execute_count >= 3,
            "governance execute block should exercise scoped undo mutations, got {execute_count}"
        );

        let (cancel_state, _, proposer_keypair, proposer_id, proposal_id) =
            governance_proposal_state(ProposalPhase::Deliberation);
        let cancel_op = governance_cancel_op(proposer_id, &proposer_keypair, proposal_id, 1);
        let mut cancel_block = make_block(&cancel_state, vec![]);
        cancel_block.governance_ops.push(cancel_op);
        let cancel_count = assert_all_failpoints_roll_back(&cancel_state, &cancel_block);
        assert!(
            cancel_count >= 3,
            "governance cancel block should exercise scoped undo mutations, got {cancel_count}"
        );
    }

    #[test]
    fn state_txn_rebuilds_state_commitment_v2_cache_after_rollback() {
        let mut state = canonical_test_genesis();
        install_inert_gate_snapshot_fixture(&mut state);
        state.height = 0;
        state.tip_hash = Bytes32::ZERO;
        let block = empty_block_at(&state, 1, 0);

        let mut success = state.clone();
        crate::txn::set_fail_after_mutation(None);
        apply_block(&mut success, &block, 0).unwrap();
        let success_root = success.state_commitment_v2_root(block.header.height);
        success.rebuild_state_commitment_v2(block.header.height);
        assert_eq!(
            success.state_commitment_v2_root(block.header.height),
            success_root
        );

        let mut rolled_back = state.clone();
        crate::txn::set_fail_after_mutation(Some(1));
        let err = apply_block(&mut rolled_back, &block, 0).unwrap_err();
        assert!(
            err.to_string()
                .contains("state transaction failpoint injected after mutation")
        );
        assert_same_consensus_state(&rolled_back, &state);
        let rollback_root = rolled_back.state_commitment_v2_root(rolled_back.height);
        rolled_back.rebuild_state_commitment_v2(rolled_back.height);
        assert_eq!(
            rolled_back.state_commitment_v2_root(rolled_back.height),
            rollback_root
        );
        crate::txn::set_fail_after_mutation(None);
    }

    #[test]
    fn state_txn_replay_determinism_rejected_block_then_valid_block() {
        let mut reference = canonical_test_genesis();
        let mut candidate = reference.clone();
        let mut bad_block = make_block(&reference, vec![]);
        bad_block.header.prev_hash = Bytes32::from([0xEE; 32]);
        let reference_before = reference.clone();
        assert!(clone_atomic_reference_apply_block(&reference, &bad_block, 0).is_err());
        assert!(apply_block(&mut candidate, &bad_block, 0).is_err());
        assert_same_consensus_state(&reference, &reference_before);
        assert_same_consensus_state(&candidate, &reference_before);

        let valid_block = make_block(&reference, vec![]);
        reference = clone_atomic_reference_apply_block(&reference, &valid_block, 0)
            .unwrap()
            .state;
        apply_block(&mut candidate, &valid_block, 0).unwrap();
        assert_same_consensus_state(&candidate, &reference);
    }

    #[test]
    fn block_protocol_version_validation_is_strict_allow_list() {
        let mut state = canonical_test_genesis();
        let mut block = make_block(&state, vec![]);
        block.header.protocol_version = ProtocolVersion(999);

        let err = apply_block(&mut state, &block, 0).unwrap_err();
        assert!(
            matches!(err, StateError::UnsupportedVersion { version: 999 }),
            "block validity must reject unrecognized protocol versions before applying state"
        );
        assert_eq!(state.height, 0);
    }

    #[test]
    fn forged_qc_cannot_drive_state_projection_or_liveness_attribution() {
        let mut state = canonical_test_genesis();
        state.height = 1;
        state.tip_hash = Bytes32::from([0x29; 32]);
        let snapshot = state.snapshot_for_consensus_height(1).unwrap();
        let validator_id = snapshot.entries()[0].validator_id;
        let qc = QuorumCertificateV1 {
            height: 1,
            round: 0,
            block_hash: state.tip_hash,
            snapshot_root: snapshot.snapshot_root,
            signer_bitfield: {
                let mut bits = [0u8; indra_core::types::qc::SIGNER_BITFIELD_BYTES];
                bits[0] = 1;
                bits
            },
            pq_signatures: vec![PQVoteSig {
                validator_id,
                pq_sig: VariableBytes::from_slice(&[1]).unwrap(),
            }],
            classical_signatures: vec![indra_core::types::qc::ClassicalVoteSig {
                validator_id,
                classical_sig: VariableBytes::from_slice(&[2; 64]).unwrap(),
            }],
        };
        let mut block = make_block_at_height(&state, vec![], 2, 0);
        block.header.quorum_certificate = VariableBytes::from_slice(&qc.encode_to_vec()).unwrap();
        let before = state.clone();
        assert!(project_block_for_roots(&mut state, &block, 0).is_err());
        assert_eq!(state, before, "failed verification must not project state");
        assert!(apply_block_with_effects(&mut state, &block, 0).is_err());
        assert_eq!(
            state, before,
            "failed verification must not attribute liveness"
        );
    }

    #[test]
    fn apply_block_rejects_too_many_staking_ops() {
        let mut state = canonical_test_genesis();
        let (op, _) = signed_register_validator_op(&mut state, [0x41; 32], 1);
        let mut block = make_block(&state, vec![]);
        block.staking_ops = vec![op; MAX_STAKING_OPS_PER_BLOCK + 1];
        let mut check_state = state.clone();

        assert_eq!(
            apply_block(&mut check_state, &block, 0),
            Err(StateError::TooManyStakingOps {
                actual: MAX_STAKING_OPS_PER_BLOCK + 1,
                max: MAX_STAKING_OPS_PER_BLOCK,
            })
        );
    }

    #[test]
    fn apply_block_with_staking_ops_atomicity() {
        let mut state = canonical_test_genesis();
        let (op, validator_id) = signed_register_validator_op(&mut state, [0x42; 32], 1);
        let original = state.clone();
        let mut block = make_block(&state, vec![]);
        block.staking_ops = vec![op.clone(), op];

        assert!(apply_block(&mut state, &block, 0).is_err());
        assert_eq!(state, original);
        assert!(state.validators.get(&validator_id).is_none());
    }

    #[test]
    fn staking_nonces_committed_to_state_root() {
        let mut a = canonical_test_genesis();
        let mut b = canonical_test_genesis();
        a.staking_nonces.insert(Bytes32::from([0xAA; 32]), 1);
        b.staking_nonces.insert(Bytes32::from([0xAA; 32]), 2);
        a.rebuild_state_commitment_v2(a.height);
        b.rebuild_state_commitment_v2(b.height);

        assert_ne!(
            crate::state_root::compute_state_root(&a),
            crate::state_root::compute_state_root(&b)
        );
    }

    #[test]
    fn apply_empty_block_advances_height() {
        let mut state = canonical_test_genesis();
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block, 0).unwrap();
        assert_eq!(state.height, 1);
    }

    #[test]
    fn apply_block_nonempty_governance_shadow_still_rejects_invalid_op_before_real_apply() {
        let mut state = canonical_test_genesis();
        let mut block = make_block(&state, vec![]);
        block.governance_ops = vec![GovernanceOpV2 {
            action_type: GovernanceActionType::ExecuteProposal,
            signer_id: Bytes32::from([0xAB; 32]),
            nonce: 1,
            payload: GovernancePayload::Execute {
                proposal_id: Bytes32::from([0xCD; 32]),
            },
            signature: dummy_sig(),
        }];

        let original = state.clone();
        let err = apply_block(&mut state, &block, 0).unwrap_err();
        assert!(
            !matches!(
                err,
                StateError::InvariantViolation {
                    message: "governance op failed on real state after shadow validation"
                }
            ),
            "non-empty governance blocks must still run the shadow validation path before real apply"
        );
        assert_eq!(state, original);
    }

    #[test]
    fn apply_block_updates_tip_hash() {
        let mut state = canonical_test_genesis();
        let block = make_block(&state, vec![]);
        let expected_hash = block.header.block_hash();
        apply_block(&mut state, &block, 0).unwrap();
        assert_eq!(state.tip_hash, expected_hash);
    }

    #[test]
    fn apply_block_with_tx_spends_utxo() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        let tx = make_tx(&state, &keypair, utxo_id, input_value, input_blinding);
        let block = make_block(&state, vec![tx]);
        apply_block(&mut state, &block, 0).unwrap();

        // Input UTXO must be gone
        assert!(!state.utxos.contains(&utxo_id));
        // Output UTXO must exist
        assert_eq!(state.utxos.len(), 1);
    }

    #[test]
    fn apply_transaction_fails_loudly_if_utxo_already_spent() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        let tx = make_tx(&state, &keypair, utxo_id, input_value, input_blinding);
        assert!(state.utxos.spend(&utxo_id).is_some());

        let mut txn = StateTxn::begin(&mut state, 1);
        assert_eq!(
            apply_transaction(&mut txn, &tx, 1, 0),
            Err(StateError::InvariantViolation {
                message: "attempted to spend an already-spent UTXO during apply_transaction",
            })
        );
    }

    #[test]
    fn replay_spend_rejected_after_atomic_utxo_removal() {
        let (mut state, utxo_id, keypair, fixture_tag, input_value) = state_with_utxo();
        let tx = make_tx(&state, &keypair, utxo_id, input_value, fixture_tag);
        let first = make_block(&state, vec![tx.clone()]);
        apply_block(&mut state, &first, 0).unwrap();
        assert!(!state.utxos.contains(&utxo_id));

        let replay = make_block(&state, vec![tx]);
        assert_eq!(
            apply_block(&mut state, &replay, 0),
            Err(StateError::UnknownUtxo)
        );
        assert_eq!(state.height, 1);
    }

    #[test]
    fn wrong_height_rejected() {
        let mut state = canonical_test_genesis();
        let mut block = make_block(&state, vec![]);
        block.header.height = 99; // wrong
        assert!(matches!(
            apply_block(&mut state, &block, 0),
            Err(StateError::InvalidHeight {
                expected: 1,
                actual: 99
            })
        ));
    }

    #[test]
    fn wrong_prev_hash_rejected() {
        let mut state = canonical_test_genesis();
        let mut block = make_block(&state, vec![]);
        block.header.prev_hash = Bytes32::from([0xFFu8; 32]); // wrong
        assert_eq!(
            apply_block(&mut state, &block, 0),
            Err(StateError::PrevHashMismatchDetailed {
                height: 1,
                expected: Bytes32::ZERO,
                got: Bytes32::from([0xFFu8; 32]),
            })
        );
    }

    #[test]
    fn wrong_base_fee_rejected() {
        let mut state = canonical_test_genesis();
        let mut block = make_block(&state, vec![]);
        block.header.base_fee = 9999; // wrong
        assert!(matches!(
            apply_block(&mut state, &block, 0),
            Err(StateError::BaseFeeIncorrect { .. })
        ));
    }

    #[test]
    fn unknown_utxo_rejected() {
        let mut state = canonical_test_genesis();
        let fake_utxo = Bytes32::from([0xDEu8; 32]);
        let (_, keypair) = make_test_keypair([0x22; 32]);
        let tx = make_tx(
            &state,
            &keypair,
            fake_utxo,
            TEST_INPUT_VALUE + 1,
            [0x01; 32],
        );
        let block = make_block(&state, vec![tx]);
        assert_eq!(
            apply_block(&mut state, &block, 0),
            Err(StateError::UnknownUtxo)
        );
    }

    #[test]
    fn fee_too_low_rejected() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        let mut tx = make_tx(&state, &keypair, utxo_id, input_value, input_blinding);
        tx.fee_amount = 0; // too low
        tx.signature = sign_transaction(&keypair, &state.chain_id, &tx);
        let block = make_block(&state, vec![tx]);
        assert!(matches!(
            apply_block(&mut state, &block, 0),
            Err(StateError::FeeTooLow { .. })
        ));
    }

    #[test]
    fn fee_burns_supply() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        let initial_supply = state.total_supply;
        let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 10;
        let tx = make_tx(&state, &keypair, utxo_id, input_value, input_blinding);
        let block = make_block(&state, vec![tx]);
        apply_block(&mut state, &block, 0).unwrap();
        let reward =
            crate::monetary::block_reward_for_budget(state.monetary_ledger.reward_budget_spark, 1)
                .unwrap();
        assert_eq!(
            state.total_supply,
            initial_supply.checked_add(reward).unwrap() - (fee / 2)
        );
        assert_eq!(state.fee_reward_pool, fee - (fee / 2));
    }

    #[test]
    fn state_unchanged_on_error() {
        let mut state = canonical_test_genesis();
        let height_before = state.height;
        let supply_before = state.total_supply;
        let utxos_before = state.utxos.len();

        // Block with wrong height — will fail
        let mut block = make_block(&state, vec![]);
        block.header.height = 99;
        let _ = apply_block(&mut state, &block, 0);

        assert_eq!(state.height, height_before);
        assert_eq!(state.total_supply, supply_before);
        assert_eq!(state.utxos.len(), utxos_before);
    }

    #[test]
    fn consecutive_blocks_chain_correctly() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();

        // Block 1: spend the UTXO
        let tx = make_tx(&state, &keypair, utxo_id, input_value, input_blinding);
        let block1 = make_block(&state, vec![tx]);
        apply_block(&mut state, &block1, 0).unwrap();
        assert_eq!(state.height, 1);

        // Block 2: empty, but chains correctly off block 1
        let block2 = make_block(&state, vec![]);
        apply_block(&mut state, &block2, 0).unwrap();
        assert_eq!(state.height, 2);
    }

    #[test]
    fn locked_utxo_rejected_before_unlock() {
        let mut state = canonical_test_genesis();
        let (owner_pubkey, keypair) = make_test_keypair([0x11; 32]);
        let mut output = dummy_output(0x01, owner_pubkey);
        output.lock_height = 100; // locked until height 100
        let utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();

        let tx = make_tx(&state, &keypair, utxo_id, TEST_INPUT_VALUE + 1, [0x01; 32]);
        let block = make_block(&state, vec![tx]); // height will be 1 < 100
        assert!(matches!(
            apply_block(&mut state, &block, 0),
            Err(StateError::OutputLocked { .. })
        ));
    }

    #[test]
    fn valid_signature_accepted() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        let tx = make_tx(&state, &keypair, utxo_id, input_value, input_blinding);
        let block = make_block(&state, vec![tx]);
        apply_block(&mut state, &block, 0).unwrap();
        assert_eq!(state.height, 1);
    }

    #[test]
    fn wrong_signature_rejected() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        let mut tx = make_tx(&state, &keypair, utxo_id, input_value, input_blinding);
        let (_, wrong_keypair) = make_test_keypair([0x33; 32]);
        tx.signature = sign_transaction(&wrong_keypair, &state.chain_id, &tx);
        let block = make_block(&state, vec![tx]);
        assert!(matches!(
            apply_block(&mut state, &block, 0),
            Err(StateError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn zeroed_signature_rejected() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        let mut tx = make_tx(&state, &keypair, utxo_id, input_value, input_blinding);
        tx.signature = dummy_sig();
        let block = make_block(&state, vec![tx]);
        assert!(matches!(
            apply_block(&mut state, &block, 0),
            Err(StateError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn wrong_chain_id_rejected() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        let mut tx = make_tx(&state, &keypair, utxo_id, input_value, input_blinding);
        tx.signature = sign_transaction(&keypair, "indra-mainnet-1", &tx);
        let block = make_block(&state, vec![tx]);
        assert!(matches!(
            apply_block(&mut state, &block, 0),
            Err(StateError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn wrong_version_rejected() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        let mut tx = make_tx(&state, &keypair, utxo_id, input_value, input_blinding);
        tx.version = ProtocolVersion(99);
        let block = make_block(&state, vec![tx]);
        assert_eq!(
            apply_block(&mut state, &block, 0),
            Err(StateError::UnsupportedTxVersion { version: 99 })
        );
    }

    #[test]
    fn wrong_module_id_rejected() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        let mut tx = make_tx(&state, &keypair, utxo_id, input_value, input_blinding);
        tx.signature_module_id = 7;
        let block = make_block(&state, vec![tx]);
        assert_eq!(
            apply_block(&mut state, &block, 0),
            Err(StateError::UnsupportedSignatureModule { module_id: 7 })
        );
    }

    #[test]
    fn reward_then_slash_then_eviction_composes_without_principal_or_reward_loss() {
        let (mut state, validator_id, keypair) = slash_validator_state([0xD1; 32], 1_000_000);
        state.height = u64::MAX - 1;
        let snapshot = state
            .build_consensus_snapshot(u64::MAX, u64::MAX - 1)
            .unwrap();
        let proof = build_slash_membership_proof(&snapshot, 0).unwrap();
        state.slash_membership_roots = vec![
            indra_core::types::slash_membership::SlashMembershipRootRecord {
                activation_height: snapshot.activation_height,
                membership_root:
                    indra_core::types::slash_membership::compute_slash_membership_root(&snapshot)
                        .unwrap(),
            },
        ];
        state.reward_economic_snapshot =
            Some(state.build_reward_economic_snapshot(&snapshot).unwrap());
        state.consensus_snapshots = vec![snapshot];
        let evidence = SlashEvidenceV2 {
            validator_id,
            vote_1: signed_vote(
                &keypair,
                validator_id,
                u64::MAX,
                0,
                VoteStep::Precommit,
                Bytes32::from([0xA1; 32]),
            ),
            vote_2: signed_vote(
                &keypair,
                validator_id,
                u64::MAX,
                0,
                VoteStep::Precommit,
                Bytes32::from([0xB1; 32]),
            ),
            membership_proof: proof,
        };
        let chain_id = state.chain_id.clone();
        let self_position_id = indra_core::types::stake_position::derive_position_id(
            validator_id,
            validator_id,
            indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
                validator_id,
            },
        );
        state.fee_reward_pool = 25_000;
        state.total_supply = capstone_accounted_value(&state);
        let conserved = state.total_supply;
        let pre_reward = state.clone();
        crate::txn::set_fail_after_mutation(None);
        {
            let mut txn = crate::txn::StateTxn::begin(&mut state, u64::MAX);
            txn.snapshot_epoch_scope();
            crate::epoch::distribute_fee_rewards(txn.state_mut(), 1, u64::MAX).unwrap();
            txn.after_mutation().unwrap();
            txn.commit();
        }
        let reward_mutations = crate::txn::mutation_count();
        assert!(reward_mutations >= 3);
        for failpoint in 1..=reward_mutations {
            crate::txn::set_fail_after_mutation(Some(failpoint));
            let mut candidate = pre_reward.clone();
            {
                let mut txn = crate::txn::StateTxn::begin(&mut candidate, u64::MAX);
                txn.snapshot_epoch_scope();
                let result = crate::epoch::distribute_fee_rewards(txn.state_mut(), 1, u64::MAX)
                    .and_then(|_| txn.after_mutation());
                assert!(result.is_err());
            }
            assert_eq!(candidate.encode_to_vec(), pre_reward.encode_to_vec());
            assert_eq!(
                compute_state_root(&candidate),
                compute_state_root(&pre_reward)
            );
        }
        crate::txn::set_fail_after_mutation(None);
        assert_eq!(capstone_accounted_value(&state), conserved);
        let current = state.validators.get_mut(&validator_id).unwrap();
        current.hybrid_classical_pk = None;
        current.hybrid_pq_pk = None;

        let pre_slash = state.clone();
        crate::txn::set_fail_after_mutation(None);
        {
            let mut txn = crate::txn::StateTxn::begin(&mut state, u64::MAX);
            txn.snapshot_slashing_scope();
            apply_slash_v2_at_height_with_accounting(
                txn.state_mut(),
                &evidence,
                &chain_id,
                u64::MAX,
                None,
            )
            .unwrap();
            txn.after_mutation().unwrap();
            txn.commit();
        }
        let slash_mutations = crate::txn::mutation_count();
        assert!(slash_mutations >= 4);
        for failpoint in 1..=slash_mutations {
            crate::txn::set_fail_after_mutation(Some(failpoint));
            let mut candidate = pre_slash.clone();
            {
                let mut txn = crate::txn::StateTxn::begin(&mut candidate, u64::MAX);
                txn.snapshot_slashing_scope();
                let result = apply_slash_v2_at_height_with_accounting(
                    txn.state_mut(),
                    &evidence,
                    &chain_id,
                    u64::MAX,
                    None,
                )
                .and_then(|_| txn.after_mutation());
                assert!(result.is_err());
            }
            assert_eq!(candidate.encode_to_vec(), pre_slash.encode_to_vec());
            assert_eq!(
                compute_state_root(&candidate),
                compute_state_root(&pre_slash)
            );
        }
        crate::txn::set_fail_after_mutation(None);

        assert_eq!(
            state.validators.get(&validator_id).unwrap().stake_spark,
            950_000
        );
        assert_eq!(
            state
                .stake_positions
                .get(&self_position_id)
                .unwrap()
                .pending_rewards_spark,
            25_000,
            "prospective slashing must preserve rewards already credited in the epoch"
        );

        let validator = state.validators.get(&validator_id).unwrap().clone();
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
        let public = keypair.public_key();
        let plan = crate::tranche_tombstone::plan_tranche_native_eviction_v2(
            &chain_id,
            validator_id,
            u64::MAX,
            crate::tranche_tombstone::TombstoneAuthorityV2 {
                classical_vote_pk: public.classical.0,
                pq_vote_pk: public.pq.0,
                vrf_pk: validator.vrf_pk.unwrap(),
                cold_custody: Some(crate::validator::EvictedColdCustodyV1 {
                    classical_pk: public.classical.0,
                    pq_pk: public.pq.0,
                    key_version: 1,
                }),
                slashed_offense_id: validator.slashed_offense_id,
            },
            &positions,
            &tranches,
        )
        .unwrap();
        let converted = plan
            .tranches
            .values()
            .find(|tranche| tranche.position_id == self_position_id)
            .unwrap();
        assert_eq!(converted.principal_spark, 950_000);
        assert_eq!(
            plan.positions
                .get(&self_position_id)
                .unwrap()
                .pending_rewards_spark,
            25_000
        );
        let pre_eviction = state.clone();
        crate::txn::set_fail_after_mutation(None);
        {
            let mut txn = crate::txn::StateTxn::begin(&mut state, u64::MAX);
            txn.snapshot_staking_scope();
            crate::delegation::commit_tranche_eviction_plan(
                txn.state_mut(),
                validator_id,
                plan.clone(),
                u64::MAX,
            )
            .unwrap();
            txn.after_mutation().unwrap();
            txn.commit();
        }
        let eviction_mutations = crate::txn::mutation_count();
        assert!(eviction_mutations >= 6);
        for failpoint in 1..=eviction_mutations {
            crate::txn::set_fail_after_mutation(Some(failpoint));
            let mut candidate = pre_eviction.clone();
            {
                let mut txn = crate::txn::StateTxn::begin(&mut candidate, u64::MAX);
                txn.snapshot_staking_scope();
                let result = crate::delegation::commit_tranche_eviction_plan(
                    txn.state_mut(),
                    validator_id,
                    plan.clone(),
                    u64::MAX,
                )
                .and_then(|_| txn.after_mutation());
                assert!(result.is_err());
            }
            assert_eq!(candidate.encode_to_vec(), pre_eviction.encode_to_vec());
            assert_eq!(
                compute_state_root(&candidate),
                compute_state_root(&pre_eviction)
            );
        }
        crate::txn::set_fail_after_mutation(None);
        assert_eq!(capstone_accounted_value(&state), state.total_supply);
    }

    #[test]
    fn full_stack_atomic_eviction_cap_measurement() {
        let (mut state, validator_id, keypair) = slash_validator_state([0xE8; 32], 1_000_000);
        for ordinal in 1..crate::validator::MAX_ATOMIC_EVICTION_POSITION_CONVERSIONS {
            let owner_id = Bytes32::from(indra_crypto::sha256(&(ordinal as u64).to_le_bytes()));
            let custody = indra_core::types::stake_position::PositionCustodyV1::DelegatorIdentity {
                delegator_id: owner_id,
            };
            let position = indra_core::types::stake_position::StakePositionV1::new(
                validator_id,
                owner_id,
                custody,
                Some(
                    indra_core::types::stake_position::ActiveStakeAggregateV1::new(
                        indra_core::types::primitives::DUST_LIMIT_SPARK,
                        1,
                        1,
                    )
                    .unwrap(),
                ),
                0,
                0,
            )
            .unwrap();
            state.stake_positions.insert(position.position_id, position);
        }
        state.rebuild_position_tranche_index().unwrap();
        state.rebuild_state_commitment_v2(1);
        let public = keypair.public_key();
        let started = std::time::Instant::now();
        let consensus = state.build_consensus_snapshot(1, 0).unwrap();
        state.reward_economic_snapshot =
            Some(state.build_reward_economic_snapshot(&consensus).unwrap());
        let economic_elapsed = started.elapsed();
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
            2,
            crate::tranche_tombstone::TombstoneAuthorityV2 {
                classical_vote_pk: public.classical.0,
                pq_vote_pk: public.pq.0,
                vrf_pk: state.validators.get(&validator_id).unwrap().vrf_pk.unwrap(),
                cold_custody: Some(crate::validator::EvictedColdCustodyV1 {
                    classical_pk: public.classical.0,
                    pq_pk: public.pq.0,
                    key_version: 1,
                }),
                slashed_offense_id: None,
            },
            &positions,
            &tranches,
        )
        .unwrap();
        let plan_elapsed = started.elapsed();
        crate::txn::set_fail_after_mutation(None);
        {
            let mut txn = crate::txn::StateTxn::begin(&mut state, 2);
            txn.snapshot_staking_scope();
            crate::delegation::commit_tranche_eviction_plan(txn.state_mut(), validator_id, plan, 2)
                .unwrap();
            txn.after_mutation().unwrap();
            txn.commit();
        }
        let commit_elapsed = started.elapsed();
        // Exercise the complete checkpoint and external-view projection costs
        // after the consensus mutation rather than timing the planner alone.
        let checkpoint = state.encode_to_vec();
        assert!(!checkpoint.is_empty());
        let checkpoint_elapsed = started.elapsed();
        let projected_positions = state
            .stake_positions
            .values()
            .map(|position| {
                (
                    position.position_id,
                    position.validator_id,
                    position.pending_rewards_spark,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            projected_positions.len(),
            crate::validator::MAX_ATOMIC_EVICTION_POSITION_CONVERSIONS
        );
        let elapsed = started.elapsed();
        println!(
            "full_stack_atomic_eviction_4096 economic_ms={} plan_ms={} commit_ms={} checkpoint_ms={} total_ms={}",
            economic_elapsed.as_millis(),
            plan_elapsed.saturating_sub(economic_elapsed).as_millis(),
            commit_elapsed.saturating_sub(plan_elapsed).as_millis(),
            checkpoint_elapsed
                .saturating_sub(commit_elapsed)
                .as_millis(),
            elapsed.as_millis()
        );
        // The debug suite proves the complete mutation/projection path. Wall
        // clock limits are host-load-sensitive and only gate the optimized
        // release profile that validators actually execute.
        if !cfg!(debug_assertions) {
            assert!(
                elapsed < std::time::Duration::from_secs(6),
                "full-stack eviction exceeded budget: {elapsed:?}"
            );
        }
    }

    #[test]
    fn membership_proven_slash_targets_same_height_eviction_tombstone() {
        let (mut state, validator_id, keypair) = slash_validator_state([0xD3; 32], 1_000_000);
        let custody = indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
            validator_id,
        };
        let position = indra_core::types::stake_position::StakePositionV1::new(
            validator_id,
            validator_id,
            custody,
            None,
            0,
            0,
        )
        .unwrap();
        let timing =
            indra_core::types::stake_position::UnbondingTimingV1::height_precise(u64::MAX).unwrap();
        let creation_op_id = Bytes32::from([0xD4; 32]);
        let tranche = indra_core::types::stake_position::UnbondingTrancheV1::new(
            position.position_id,
            1_000_000,
            timing,
            custody,
            creation_op_id,
            0,
        )
        .unwrap();
        state
            .stake_positions
            .insert(position.position_id, position.clone());
        state
            .unbonding_tranches
            .insert(tranche.tranche_id, tranche.clone());
        state.rebuild_position_tranche_index().unwrap();
        state.height = u64::MAX - 1;
        let snapshot = state
            .build_consensus_snapshot(u64::MAX, u64::MAX - 1)
            .unwrap();
        let proof = build_slash_membership_proof(&snapshot, 0).unwrap();
        state.slash_membership_roots = vec![
            indra_core::types::slash_membership::SlashMembershipRootRecord {
                activation_height: snapshot.activation_height,
                membership_root:
                    indra_core::types::slash_membership::compute_slash_membership_root(&snapshot)
                        .unwrap(),
            },
        ];
        state.consensus_snapshots = vec![snapshot];
        let evidence = SlashEvidenceV2 {
            validator_id,
            vote_1: signed_vote(
                &keypair,
                validator_id,
                u64::MAX,
                0,
                VoteStep::Precommit,
                Bytes32::from([0xA3; 32]),
            ),
            vote_2: signed_vote(
                &keypair,
                validator_id,
                u64::MAX,
                0,
                VoteStep::Precommit,
                Bytes32::from([0xB3; 32]),
            ),
            membership_proof: proof,
        };
        let mut validator = state.validators.get(&validator_id).unwrap().clone();
        validator.cold_hybrid_classical_pk = validator.hybrid_classical_pk;
        validator.cold_hybrid_pq_pk = validator
            .hybrid_pq_pk
            .clone()
            .map(|pq| pq.try_into().unwrap());
        validator.cold_key_version = 1;
        state.validators.remove(&validator_id);
        state.evicted_validator_tombstones.insert(
            validator_id,
            crate::validator::EvictedValidatorTombstoneV2 {
                validator_id,
                eviction_height: u64::MAX,
                eviction_epoch: epoch_for_height(u64::MAX),
                last_classical_vote_pk: validator.hybrid_classical_pk.unwrap(),
                last_pq_vote_pk: validator.hybrid_pq_pk.unwrap().try_into().unwrap(),
                last_vrf_pk: validator.vrf_pk.unwrap(),
                cold_custody: Some(crate::validator::EvictedColdCustodyV1 {
                    classical_pk: validator.cold_hybrid_classical_pk.unwrap(),
                    pq_pk: validator.cold_hybrid_pq_pk.unwrap(),
                    key_version: validator.cold_key_version,
                }),
                slashed_offense_id: validator.slashed_offense_id,
                retained_position_ids: vec![position.position_id],
                retained_tranche_ids: vec![tranche.tranche_id],
            },
        );
        let tranche_count_before = state.unbonding_tranches.len();
        let chain_id = state.chain_id.clone();
        let pre_successor_slash = state.clone();
        crate::txn::set_fail_after_mutation(None);
        {
            let mut txn = crate::txn::StateTxn::begin(&mut state, u64::MAX);
            txn.snapshot_slashing_scope();
            apply_slash_v2_at_height_with_accounting(
                txn.state_mut(),
                &evidence,
                &chain_id,
                u64::MAX,
                None,
            )
            .unwrap();
            txn.after_mutation().unwrap();
            txn.commit();
        }
        let successor_mutations = crate::txn::mutation_count();
        for failpoint in 1..=successor_mutations {
            crate::txn::set_fail_after_mutation(Some(failpoint));
            let mut candidate = pre_successor_slash.clone();
            {
                let mut txn = crate::txn::StateTxn::begin(&mut candidate, u64::MAX);
                txn.snapshot_slashing_scope();
                let result = apply_slash_v2_at_height_with_accounting(
                    txn.state_mut(),
                    &evidence,
                    &chain_id,
                    u64::MAX,
                    None,
                )
                .and_then(|_| txn.after_mutation());
                assert!(result.is_err());
            }
            assert_eq!(
                candidate.encode_to_vec(),
                pre_successor_slash.encode_to_vec()
            );
            assert_eq!(
                compute_state_root(&candidate),
                compute_state_root(&pre_successor_slash)
            );
        }
        crate::txn::set_fail_after_mutation(None);
        assert_eq!(state.unbonding_tranches.len(), tranche_count_before);
        assert!(!state.unbonding_tranches.contains_key(&tranche.tranche_id));
        let successor = state.unbonding_tranches.values().next().unwrap();
        assert_eq!(successor.principal_spark, 950_000);
        assert_eq!(successor.creation_op_id, tranche.creation_op_id);
        assert_eq!(successor.creation_ordinal, tranche.creation_ordinal);
        assert_eq!(successor.timing, tranche.timing);
        assert_eq!(successor.custody, tranche.custody);
        assert_eq!(
            state
                .evicted_validator_tombstones
                .get(&validator_id)
                .unwrap()
                .retained_tranche_ids,
            vec![successor.tranche_id]
        );

        let mut swapped = evidence.clone();
        std::mem::swap(&mut swapped.vote_1, &mut swapped.vote_2);
        assert_eq!(
            compute_slash_evidence_v2_hash(&evidence),
            compute_slash_evidence_v2_hash(&swapped),
            "presentation order must not change canonical offense identity"
        );
        assert!(matches!(
            apply_slash_v2_at_height_with_accounting(
                &mut state,
                &swapped,
                &chain_id,
                u64::MAX,
                None,
            ),
            Err(StateError::SlashAlreadyApplied)
        ));

        let mut already_evicted = state.clone();
        already_evicted
            .evicted_validator_tombstones
            .get(&validator_id)
            .cloned()
            .map(|mut tombstone| {
                tombstone.eviction_height = u64::MAX - 1;
                tombstone.slashed_offense_id = None;
                already_evicted
                    .evicted_validator_tombstones
                    .insert(validator_id, tombstone);
            });
        assert!(matches!(
            apply_slash_v2_at_height_with_accounting(
                &mut already_evicted,
                &evidence,
                &chain_id,
                u64::MAX,
                None,
            ),
            Err(StateError::InvalidSlashEvidence { reason })
                if reason.contains("evicted before")
        ));
    }

    #[test]
    fn membership_proven_slash_rejects_wrong_root_and_missing_root() {
        let (mut state, validator_id, keypair) = slash_validator_state([0xD2; 32], 1_000_000);
        state.height = u64::MAX - 1;
        let snapshot = state
            .build_consensus_snapshot(u64::MAX, u64::MAX - 1)
            .unwrap();
        let proof = build_slash_membership_proof(&snapshot, 0).unwrap();
        let evidence = SlashEvidenceV2 {
            validator_id,
            vote_1: signed_vote(
                &keypair,
                validator_id,
                u64::MAX,
                0,
                VoteStep::Precommit,
                Bytes32::from([0xA2; 32]),
            ),
            vote_2: signed_vote(
                &keypair,
                validator_id,
                u64::MAX,
                0,
                VoteStep::Precommit,
                Bytes32::from([0xB2; 32]),
            ),
            membership_proof: proof,
        };
        let chain_id = state.chain_id.clone();
        assert!(
            apply_slash_v2_at_height_with_accounting(
                &mut state,
                &evidence,
                &chain_id,
                u64::MAX,
                None,
            )
            .is_err()
        );

        state.consensus_snapshots = vec![snapshot];
        state.height = u64::MAX;
        state.slash_membership_roots = vec![SlashMembershipRootRecord {
            activation_height: u64::MAX,
            membership_root: Bytes32::from([0xEE; 32]),
        }];
        assert!(
            apply_slash_v2_at_height_with_accounting(
                &mut state,
                &evidence,
                &chain_id,
                u64::MAX,
                None,
            )
            .is_err()
        );

        state.slash_membership_roots = vec![SlashMembershipRootRecord {
            activation_height: u64::MAX,
            membership_root: indra_core::types::slash_membership::compute_slash_membership_root(
                &state.consensus_snapshots[0],
            )
            .unwrap(),
        }];
        let error = apply_slash_v2_at_height_with_accounting(
            &mut state,
            &evidence,
            &chain_id,
            u64::MAX - 1,
            None,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            StateError::InvalidSlashEvidence { reason }
                if reason.contains("future")
        ));
    }

    #[test]
    fn double_precommit_evidence_window_is_inclusive_at_boundary() {
        use indra_core::types::stake_position::{
            ActiveStakeAggregateV1, PositionCustodyV1, StakePositionV1,
        };

        let (mut state, validator_id, keypair) = slash_validator_state([0xD5; 32], 1_000_000);
        let custody = PositionCustodyV1::ValidatorColdIdentity { validator_id };
        let position = StakePositionV1::new(
            validator_id,
            validator_id,
            custody,
            Some(ActiveStakeAggregateV1::new(1_000_000, 1, 1).unwrap()),
            0,
            0,
        )
        .unwrap();
        state.stake_positions.insert(position.position_id, position);
        state.rebuild_position_tranche_index().unwrap();
        let snapshot = state.consensus_snapshots[0].clone();
        let evidence = SlashEvidenceV2 {
            validator_id,
            vote_1: signed_vote(
                &keypair,
                validator_id,
                1,
                0,
                VoteStep::Precommit,
                Bytes32::from([0xD5; 32]),
            ),
            vote_2: signed_vote(
                &keypair,
                validator_id,
                1,
                0,
                VoteStep::Precommit,
                Bytes32::from([0xD6; 32]),
            ),
            membership_proof: build_slash_membership_proof(&snapshot, 0).unwrap(),
        };
        let chain_id = state.chain_id.clone();
        let boundary_height = indra_core::types::primitives::SLASH_EVIDENCE_WINDOW_EPOCHS
            * indra_core::types::primitives::EPOCH_DURATION_BLOCKS;
        let mut accepted = state.clone();
        apply_slash_v2_at_height_with_accounting(
            &mut accepted,
            &evidence,
            &chain_id,
            boundary_height,
            None,
        )
        .unwrap();

        let mut rejected = state;
        let error = apply_slash_v2_at_height_with_accounting(
            &mut rejected,
            &evidence,
            &chain_id,
            boundary_height + indra_core::types::primitives::EPOCH_DURATION_BLOCKS,
            None,
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid slash evidence: slash evidence outside evidence window: infraction_epoch=0, current_epoch=151, window=150"
        );
    }

    #[test]
    fn largest_remainder_two_ten_spark_records_at_five_percent_is_exact() {
        let targets = [
            (SlashTarget::Position(Bytes32::from([1; 32])), 10),
            (SlashTarget::Position(Bytes32::from([2; 32])), 10),
        ];
        let (aggregate, allocations) = checked_slash_allocation(&targets, 500).unwrap();
        assert_eq!(aggregate, 1);
        assert_eq!(allocations.values().copied().sum::<u64>(), aggregate);
        assert_eq!(
            allocations.values().filter(|amount| **amount == 1).count(),
            1
        );
    }

    #[test]
    fn largest_remainder_fragmentation_cannot_reduce_effective_slash_rate() {
        let whole = [(SlashTarget::Position(Bytes32::from([1; 32])), 100)];
        let fragmented = (0u16..100)
            .map(|index| {
                let mut id = [0u8; 32];
                id[..2].copy_from_slice(&index.to_le_bytes());
                (SlashTarget::Position(Bytes32::from(id)), 1)
            })
            .collect::<Vec<_>>();
        let (whole_slash, _) = checked_slash_allocation(&whole, 500).unwrap();
        let (fragmented_slash, allocations) = checked_slash_allocation(&fragmented, 500).unwrap();
        assert_eq!(whole_slash, 5);
        assert_eq!(fragmented_slash, whole_slash);
        assert_eq!(allocations.values().copied().sum::<u64>(), whole_slash);
    }

    #[test]
    fn unified_liveness_directive_slashes_active_and_post_infraction_self_tranche_only() {
        use indra_core::types::stake_position::{
            ActiveStakeAggregateV1, PositionCustodyV1, StakePositionV1, UnbondingTimingV1,
            UnbondingTrancheV1,
        };

        let (mut state, validator_id, _) = slash_validator_state([0x6A; 32], 1_000_000);
        let self_custody = PositionCustodyV1::ValidatorColdIdentity { validator_id };
        let self_position_id = indra_core::types::stake_position::derive_position_id(
            validator_id,
            validator_id,
            self_custody,
        );
        let mut self_position = state
            .stake_positions
            .get(&self_position_id)
            .unwrap()
            .clone();
        self_position.active = Some(ActiveStakeAggregateV1::new(600_000, 0, 0).unwrap());
        state
            .stake_positions
            .insert(self_position_id, self_position);

        let infraction_height = 1_000;
        let old = UnbondingTrancheV1::new(
            self_position_id,
            100_000,
            UnbondingTimingV1::height_precise(infraction_height - 1).unwrap(),
            self_custody,
            Bytes32::from([0x61; 32]),
            0,
        )
        .unwrap();
        let eligible = UnbondingTrancheV1::new(
            self_position_id,
            100_000,
            UnbondingTimingV1::height_precise(infraction_height).unwrap(),
            self_custody,
            Bytes32::from([0x62; 32]),
            0,
        )
        .unwrap();
        state.unbonding_tranches.insert(old.tranche_id, old.clone());
        state
            .unbonding_tranches
            .insert(eligible.tranche_id, eligible.clone());

        let delegator_id = Bytes32::from([0x63; 32]);
        let delegated_custody = PositionCustodyV1::DelegatorIdentity { delegator_id };
        let delegated = StakePositionV1::new(
            validator_id,
            delegator_id,
            delegated_custody,
            Some(ActiveStakeAggregateV1::new(200_000, 0, 0).unwrap()),
            0,
            0,
        )
        .unwrap();
        state
            .stake_positions
            .insert(delegated.position_id, delegated.clone());
        state.validators.get_mut(&validator_id).unwrap().stake_spark = 600_000;
        state.rebuild_position_tranche_index().unwrap();
        state.monetary_aggregates = state.recompute_monetary_aggregates().unwrap();
        state.reconcile_monetary_state().unwrap();

        let burned =
            apply_liveness_principal_slash(&mut state, validator_id, 1_000, infraction_height)
                .unwrap();

        assert_eq!(burned, 70_000);
        assert_eq!(
            state
                .stake_positions
                .get(&self_position_id)
                .unwrap()
                .active
                .unwrap()
                .principal_spark,
            540_000
        );
        assert_eq!(
            state
                .stake_positions
                .get(&delegated.position_id)
                .unwrap()
                .active
                .unwrap()
                .principal_spark,
            200_000,
            "delegated principal is outside the approved slash burden"
        );
        assert_eq!(
            state
                .unbonding_tranches
                .get(&old.tranche_id)
                .unwrap()
                .principal_spark,
            100_000
        );
        assert!(!state.unbonding_tranches.contains_key(&eligible.tranche_id));
        assert!(state.unbonding_tranches.values().any(|tranche| {
            tranche.position_id == self_position_id
                && tranche.timing.start_height() == infraction_height
                && tranche.principal_spark == 90_000
        }));
        state.monetary_aggregates = state.recompute_monetary_aggregates().unwrap();
        state.reconcile_monetary_state().unwrap();
    }

    fn apply_reporter_reward_case(
        stake: u64,
        expected_potential_reward: u64,
        expected_paid_reward: u64,
        expect_reward_utxo: bool,
    ) {
        let (mut state, validator_id, validator_keypair) = slash_validator_state([0xDA; 32], stake);
        let (reporter_pubkey, _) = make_test_keypair([0xDB; 32]);
        let snapshot = state.snapshot_for_consensus_height(1).unwrap();
        let (position, _) = snapshot.entry_with_position(&validator_id).unwrap();
        let evidence = SlashEvidenceV2 {
            validator_id,
            vote_1: signed_vote(
                &validator_keypair,
                validator_id,
                1,
                0,
                VoteStep::Precommit,
                Bytes32::from([0xA1; 32]),
            ),
            vote_2: signed_vote(
                &validator_keypair,
                validator_id,
                1,
                0,
                VoteStep::Precommit,
                Bytes32::from([0xB1; 32]),
            ),
            membership_proof: build_slash_membership_proof(snapshot, position).unwrap(),
        };
        let supply_before = state.total_supply;
        let stake_before = state.validators.get(&validator_id).unwrap().stake_spark;
        let chain_id = state.chain_id.clone();
        let accounting = apply_slash_v2_at_height_with_accounting(
            &mut state,
            &evidence,
            &chain_id,
            1,
            Some(&reporter_pubkey),
        )
        .unwrap();
        let expected_slash = u64::try_from(
            (stake as u128)
                .checked_mul(indra_core::types::primitives::SLASH_DOUBLE_PRECOMMIT_BPS as u128)
                .unwrap()
                / 10_000,
        )
        .unwrap();
        let calculated_potential_reward = u64::try_from(
            (expected_slash as u128)
                .checked_mul(indra_core::types::primitives::SLASH_REPORTER_REWARD_BPS as u128)
                .unwrap()
                / 10_000,
        )
        .unwrap();

        assert_eq!(accounting.slash_amount, expected_slash);
        assert_eq!(accounting.self_principal_slashed, expected_slash);
        assert_eq!(calculated_potential_reward, expected_potential_reward);
        assert_eq!(accounting.reporter_reward, expected_paid_reward);
        assert_eq!(
            accounting.burned + accounting.reporter_reward,
            expected_slash
        );
        assert_eq!(supply_before - state.total_supply, accounting.burned);
        assert_eq!(
            stake_before - state.validators.get(&validator_id).unwrap().stake_spark,
            expected_slash
        );

        let rewards = state
            .utxos
            .all_entries()
            .filter(|entry| entry.tx_index == SLASH_REWARD_TX_IDX)
            .collect::<Vec<_>>();
        assert_eq!(rewards.len(), usize::from(expect_reward_utxo));
        if let Some(reward) = rewards.first() {
            assert_eq!(reward.output.value_spark, expected_paid_reward);
            assert_eq!(reward.output.owner_pubkey, reporter_pubkey);
        }

        // Re-presenting the same offense cannot mint a second reward or alter
        // supply after the canonical offense has been applied once.
        let after_first = state.encode_to_vec();
        assert!(matches!(
            apply_slash_v2_at_height_with_accounting(
                &mut state,
                &evidence,
                &chain_id,
                1,
                Some(&reporter_pubkey),
            ),
            Err(StateError::SlashAlreadyApplied)
        ));
        assert_eq!(state.encode_to_vec(), after_first);
    }

    #[test]
    fn reporter_reward_pays_exact_five_percent_and_conserves_full_slash_flow() {
        // 100,000,000 stake -> 5,000,000 slash -> 250,000 reporter reward.
        apply_reporter_reward_case(100_000_000, 250_000, 250_000, true);
    }

    #[test]
    fn reporter_reward_dust_boundary_is_exact_and_sub_dust_share_is_burned() {
        let dust = indra_core::types::primitives::DUST_LIMIT_SPARK;
        // A slash of exactly 20*dust yields an exact-dust 5% reward and pays.
        apply_reporter_reward_case(dust.checked_mul(400).unwrap(), dust, dust, true);
        // One Spark less slash yields dust-1 after the reporter-share floor;
        // no reward UTXO is created and the entire slash is burned.
        apply_reporter_reward_case(
            dust.checked_mul(400).unwrap().checked_sub(20).unwrap(),
            dust - 1,
            0,
            false,
        );
    }

    #[test]
    fn verified_slash_capability_is_bound_to_offense_and_inclusion_height() {
        let (state, validator_id, keypair) = slash_validator_state([0xD9; 32], 1_000_000);
        let snapshot = state.snapshot_for_consensus_height(1).unwrap();
        let (position, _) = snapshot.entry_with_position(&validator_id).unwrap();
        let proof = build_slash_membership_proof(snapshot, position).unwrap();
        let evidence = SlashEvidenceV2 {
            validator_id,
            vote_1: signed_vote(
                &keypair,
                validator_id,
                1,
                0,
                VoteStep::Precommit,
                Bytes32::from([0x11; 32]),
            ),
            vote_2: signed_vote(
                &keypair,
                validator_id,
                1,
                0,
                VoteStep::Precommit,
                Bytes32::from([0x22; 32]),
            ),
            membership_proof: proof,
        };
        let verified = verify_slash_candidate(&state, &evidence, 1).unwrap();

        let mut different = evidence.clone();
        different.vote_2 = signed_vote(
            &keypair,
            validator_id,
            1,
            0,
            VoteStep::Precommit,
            Bytes32::from([0x33; 32]),
        );
        let mut candidate = state.clone();
        assert!(matches!(
            try_apply_verified_slash_candidate(
                &mut candidate,
                &different,
                &verified,
                1,
                None,
            ),
            Err(StateError::InvalidSlashEvidence { reason })
                if reason.contains("capability")
        ));

        let mut wrong_height = state.clone();
        assert!(matches!(
            try_apply_verified_slash_candidate(
                &mut wrong_height,
                &evidence,
                &verified,
                2,
                None,
            ),
            Err(StateError::InvalidSlashEvidence { reason })
                if reason.contains("capability")
        ));
    }

    #[test]
    fn concurrent_identical_synthetic_rewards_have_distinct_utxo_coordinates() {
        let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
        let (owner, _) = make_test_keypair([0xD8; 32]);
        let amount = indra_core::types::primitives::DUST_LIMIT_SPARK;
        let height = 77;

        let first = create_slash_reporter_reward_utxo(
            &mut state,
            &Bytes32::from([1; 32]),
            height,
            amount,
            &owner,
            0,
        )
        .unwrap();
        let second = create_slash_reporter_reward_utxo(
            &mut state,
            &Bytes32::from([2; 32]),
            height,
            amount,
            &owner,
            1,
        )
        .unwrap();
        assert_ne!(
            first, second,
            "distinct slash events must never share a UTXO ID"
        );

        let staking_id = state
            .utxos
            .insert(
                OutputV1 {
                    value_spark: amount,
                    owner_pubkey: owner,
                    lock_height: 0,
                },
                height,
                indra_core::types::primitives::STAKING_REWARD_TX_IDX,
                0,
            )
            .unwrap();
        assert_ne!(
            first, staking_id,
            "staking and slash rewards need separate namespaces"
        );
    }
}

fn slash_membership_record_for_validation(
    state: &ChainState,
    infraction_height: u64,
) -> StateResult<SlashMembershipRootRecord> {
    state
        .slash_membership_root_for_height(infraction_height)
        .copied()
        .map_err(|_| StateError::InvalidSlashEvidence {
            reason: format!("missing membership root for height {infraction_height}"),
        })
}

fn apply_slash_common(
    state: &mut ChainState,
    evidence: &SlashEvidenceV1,
    evidence_hash: Bytes32,
    historical_keys: Option<([u8; 32], Vec<u8>)>,
    chain_id: &str,
    height: u64,
    reporter_pubkey: Option<&HybridPubKey>,
    synthetic_output_index: u32,
    crypto_mode: SlashCryptoMode<'_>,
) -> StateResult<SlashAccounting> {
    use crate::ValidatorStatus;
    use indra_core::types::{
        primitives::{DUST_LIMIT_SPARK, SLASH_REPORTER_REWARD_BPS},
        vote::VoteStep,
    };

    let validator_id = evidence.validator_id;

    let live_validator = state.validators.get(&validator_id);
    let tombstone = state.evicted_validator_tombstones.get(&validator_id);
    if live_validator.is_none() {
        let tombstone = tombstone.ok_or(StateError::ValidatorNotFound)?;
        if tombstone.slashed_offense_id.is_some() {
            return Err(StateError::SlashAlreadyApplied);
        }
        if historical_keys.is_none() || tombstone.eviction_height < evidence.vote_1.height {
            return Err(StateError::InvalidSlashEvidence {
                reason: "validator was evicted before the alleged infraction height".into(),
            });
        }
    }
    let current_keys =
        live_validator.and_then(|v| match (v.hybrid_classical_pk, v.hybrid_pq_pk.clone()) {
            (Some(classical), Some(pq)) => Some((classical, pq)),
            _ => None,
        });
    let (classical_pk, pq_pk_bytes) = match historical_keys {
        Some(keys) => keys,
        None => current_keys.ok_or_else(|| StateError::InvalidSlashEvidence {
            reason: "validator has incomplete current hybrid public keys".into(),
        })?,
    };

    if let Some(v) = live_validator {
        if v.slashed_offense_id.is_some() {
            return Err(StateError::SlashAlreadyApplied);
        }
        if matches!(v.status, ValidatorStatus::Slashed | ValidatorStatus::Exited) {
            return Err(StateError::InvalidSlashEvidence {
                reason: "validator already slashed or exited".into(),
            });
        }
    }

    if matches!(crypto_mode, SlashCryptoMode::Verify) {
        verify_vote_sig_with_keys(&evidence.vote_1, &classical_pk, &pq_pk_bytes, chain_id)
            .map_err(|e| StateError::InvalidSlashEvidence {
                reason: format!("vote_1 signature invalid: {e}"),
            })?;
        verify_vote_sig_with_keys(&evidence.vote_2, &classical_pk, &pq_pk_bytes, chain_id)
            .map_err(|e| StateError::InvalidSlashEvidence {
                reason: format!("vote_2 signature invalid: {e}"),
            })?;
    }

    if evidence.vote_1.validator_id != validator_id || evidence.vote_2.validator_id != validator_id
    {
        return Err(StateError::InvalidSlashEvidence {
            reason: "votes not from claimed validator".into(),
        });
    }

    if evidence.vote_1.height != evidence.vote_2.height
        || evidence.vote_1.round != evidence.vote_2.round
    {
        return Err(StateError::InvalidSlashEvidence {
            reason: "votes not at same height and round".into(),
        });
    }

    let infraction_epoch = epoch_for_height(evidence.vote_1.height);
    let current_epoch = epoch_for_height(height);
    if current_epoch > infraction_epoch.saturating_add(SLASH_EVIDENCE_WINDOW_EPOCHS) {
        return Err(StateError::InvalidSlashEvidence {
            reason: format!(
                "slash evidence outside evidence window: infraction_epoch={infraction_epoch}, current_epoch={current_epoch}, window={SLASH_EVIDENCE_WINDOW_EPOCHS}",
            ),
        });
    }

    if evidence.vote_1.block_hash == evidence.vote_2.block_hash {
        return Err(StateError::InvalidSlashEvidence {
            reason: "votes have same block hash — not equivocation".into(),
        });
    }
    if evidence.vote_1.block_hash == Bytes32::ZERO || evidence.vote_2.block_hash == Bytes32::ZERO {
        return Err(StateError::InvalidSlashEvidence {
            reason: "nil vote is not slashable equivocation".into(),
        });
    }

    if evidence.vote_1.step != evidence.vote_2.step {
        return Err(StateError::InvalidSlashEvidence {
            reason: "votes must both be precommits or both be prevotes".into(),
        });
    }

    let slash_bps = match evidence.vote_1.step {
        VoteStep::Precommit => state.governance.params.slash_double_precommit_bps,
        VoteStep::Prevote => {
            // Prevote conflicts are intentionally not slashable right now.
            // POLC/valid-round logic can make prevote semantics more subtle
            // than precommit equivocation, and node-side detection only emits
            // automatic evidence for double precommits. Keep the state layer
            // aligned with the enforced slashing model until a future protocol
            // version explicitly enables prevote slashing.
            return Err(StateError::InvalidSlashEvidence {
                reason: "prevote conflicts are not slashable".into(),
            });
        }
    };

    let mut position_ids = Vec::new();
    let mut tranche_ids = Vec::new();
    if let Some(tombstone) = tombstone {
        let positions = state
            .stake_positions
            .iter()
            .map(|(id, value)| (*id, value.clone()))
            .collect();
        let tranches = state
            .unbonding_tranches
            .iter()
            .map(|(id, value)| (*id, value.clone()))
            .collect();
        (position_ids, tranche_ids) = crate::tranche_tombstone::slashable_self_targets_v2(
            tombstone,
            &positions,
            &tranches,
            evidence.vote_1.height,
        )?;
    } else {
        for position in state.stake_positions.values().filter(|position| {
            position.validator_id == validator_id
                && matches!(position.custody,
                    indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity { validator_id: id }
                        if id == validator_id)
        }) {
            if position.active.is_some() {
                position_ids.push(position.position_id);
            }
            tranche_ids.extend(
                state
                    .tranche_ids_for_position(&position.position_id)
                    .iter()
                    .filter(|id| state.unbonding_tranches.get(id).is_some_and(|tranche| {
                        tranche.timing.start_height() >= evidence.vote_1.height
                    }))
                    .copied(),
            );
        }
    }
    if live_validator.is_none() && position_ids.is_empty() && tranche_ids.is_empty() {
        return Err(StateError::InvalidSlashEvidence {
            reason: "tombstone has no retained self principal slashable at the infraction height"
                .into(),
        });
    }
    if position_ids.is_empty() && tranche_ids.is_empty() {
        return Err(StateError::InvalidSlashEvidence {
            reason: "validator has no real self-custody principal at the infraction height".into(),
        });
    }
    let directive = VerifiedSlashDirectiveV1 {
        validator_id,
        slash_bps,
        infraction_height: evidence.vote_1.height,
        position_ids,
        tranche_ids,
    };
    let applied = apply_verified_slash_directive(state, &directive)?;
    let slash_amount = applied.slash_amount;
    let potential_reporter_reward = u64::try_from(
        (slash_amount as u128)
            .checked_mul(SLASH_REPORTER_REWARD_BPS as u128)
            .ok_or(StateError::ValueOverflow)?
            / 10_000u128,
    )
    .map_err(|_| StateError::ValueOverflow)?;

    let tranche_successors = &applied.tranche_successors;
    if let Some(mut tombstone) = state
        .evicted_validator_tombstones
        .get(&validator_id)
        .cloned()
    {
        for (old_id, successor) in tranche_successors {
            let index = tombstone
                .retained_tranche_ids
                .binary_search(old_id)
                .map_err(|_| StateError::InvariantViolation {
                    message: "slash target is absent from tombstone",
                })?;
            tombstone.retained_tranche_ids.remove(index);
            if let Some(successor) = successor {
                tombstone.retained_tranche_ids.push(successor.tranche_id);
            }
        }
        tombstone.retained_tranche_ids.sort();
        tombstone.slashed_offense_id = Some(evidence_hash);
        tombstone
            .validate(false)
            .map_err(|error| StateError::InvalidSlashEvidence {
                reason: error.to_string(),
            })?;
        state
            .evicted_validator_tombstones
            .insert(validator_id, tombstone.clone());
        if let Some(commitment) = state.state_commitment_v2.as_mut() {
            commitment.put_evicted_validator_tombstone(&tombstone);
        }
        crate::txn::complex_mutation_checkpoint()?;
    }
    let mut updated_validator = None;
    if let Some(v) = state.validators.get_mut(&validator_id) {
        let stake_slash = applied.active_principal_slashed;
        v.stake_spark = v
            .stake_spark
            .checked_sub(stake_slash)
            .ok_or(StateError::ValueOverflow)?;
        // Equivocation slashing is prospective-only by policy. Rewards already
        // credited to `pending_rewards` are never clawed back retroactively;
        // the penalty is the immediate stake reduction here plus permanent
        // exclusion from future reward eligibility through `Slashed` status.
        v.status = ValidatorStatus::Slashed;
        v.slashed_offense_id = Some(evidence_hash);
        updated_validator = Some(v.clone());
        crate::txn::complex_mutation_checkpoint()?;
    }
    if let (Some(commitment), Some(validator)) =
        (state.state_commitment_v2.as_mut(), updated_validator)
    {
        commitment.put_validator(&validator, height);
    }

    let reporter_reward = if potential_reporter_reward >= DUST_LIMIT_SPARK {
        if let Some(pubkey) = reporter_pubkey {
            create_slash_reporter_reward_utxo(
                state,
                &evidence_hash,
                height,
                potential_reporter_reward,
                pubkey,
                synthetic_output_index,
            )?;
            potential_reporter_reward
        } else {
            0
        }
    } else {
        0
    };
    let burned = slash_amount
        .checked_sub(reporter_reward)
        .ok_or(StateError::ValueOverflow)?;
    crate::monetary::MonetaryDeltaV1::split_burn(
        slash_amount,
        reporter_reward,
        burned,
        crate::monetary::BurnSourceV1::ValidatorSlash,
    )?;
    state.total_supply = state
        .total_supply
        .checked_sub(burned)
        .ok_or(StateError::ValueOverflow)?;
    state.monetary_ledger.cumulative_slash_burned_spark = state
        .monetary_ledger
        .cumulative_slash_burned_spark
        .checked_add(burned)
        .ok_or(StateError::ValueOverflow)?;
    state.monetary_ledger.epoch_slash_burned_spark = state
        .monetary_ledger
        .epoch_slash_burned_spark
        .checked_add(burned)
        .ok_or(StateError::ValueOverflow)?;
    crate::txn::complex_mutation_checkpoint()?;

    Ok(SlashAccounting {
        validator_id,
        slash_bps,
        slash_amount,
        burned,
        self_principal_slashed: slash_amount,
        reporter_reward,
    })
}

/// Compute the canonical proof-carrying evidence hash used for deduplication.
pub fn compute_slash_evidence_v2_hash(evidence: &SlashEvidenceV2) -> Bytes32 {
    const DOMAIN: &[u8] = b"INDRA-SLASH-OFFENSE-v1";
    let first = evidence.vote_1.encode_to_vec();
    let second = evidence.vote_2.encode_to_vec();
    let (low, high) = if first <= second {
        (first, second)
    } else {
        (second, first)
    };
    let mut preimage = Vec::with_capacity(DOMAIN.len() + 32 + 8 + low.len() + high.len());
    preimage.extend_from_slice(DOMAIN);
    preimage.extend_from_slice(evidence.validator_id.as_ref());
    preimage.extend_from_slice(&(low.len() as u32).to_le_bytes());
    preimage.extend_from_slice(&low);
    preimage.extend_from_slice(&(high.len() as u32).to_le_bytes());
    preimage.extend_from_slice(&high);
    Bytes32::from(indra_crypto::sha256(&preimage))
}

fn create_slash_reporter_reward_utxo(
    state: &mut ChainState,
    _evidence_hash: &Bytes32,
    block_height: u64,
    reporter_reward: u64,
    reporter_pubkey: &HybridPubKey,
    synthetic_output_index: u32,
) -> StateResult<Bytes32> {
    let output = OutputV1 {
        value_spark: reporter_reward,
        owner_pubkey: reporter_pubkey.clone(),
        lock_height: 0,
    };
    let reward_utxo_id = state
        .utxos
        .insert(
            output,
            block_height,
            SLASH_REWARD_TX_IDX,
            synthetic_output_index,
        )
        .map_err(|_| StateError::InvariantViolation {
            message: "UTXO ID collision in slash reporter reward output",
        })?;
    eprintln!(
        "[slash] reporter reward {} Spark -> UTXO {} for proposer {}",
        reporter_reward,
        hex::encode(&reward_utxo_id.0[..4]),
        hex::encode(&reporter_pubkey.classical_pk.0[..4]),
    );
    Ok(reward_utxo_id)
}

fn slash_reporter_pubkey_for_block(
    state: &ChainState,
    block: &BlockVNext,
) -> StateResult<Option<HybridPubKey>> {
    let snapshot = state
        .snapshot_for_consensus_height(block.header.height)
        .map_err(|error| StateError::InvalidConsensusSnapshot(error.to_string()))?;
    Ok(snapshot
        .entries()
        .iter()
        .find(|entry| entry.validator_id == block.header.proposer_id)
        .and_then(|entry| {
            Some(HybridPubKey {
                classical_pk: Bytes32::from(entry.classical_vote_pk),
                pq_pk: indra_core::VariableBytes::from_slice(&entry.pq_vote_pk).ok()?,
            })
        }))
}

fn verify_vote_sig_with_keys(
    vote: &VoteV1,
    classical_pk: &[u8; 32],
    pq_pk_bytes: &[u8],
    chain_id: &str,
) -> Result<(), String> {
    use indra_crypto::{
        ClassicalPublicKey, HybridPublicKey, PQ_PK_BYTES, PqPublicKey, verify_hybrid,
    };

    let pq_pk: [u8; PQ_PK_BYTES] = pq_pk_bytes.try_into().map_err(|_| {
        format!(
            "pq public key must be {} bytes, got {}",
            PQ_PK_BYTES,
            pq_pk_bytes.len()
        )
    })?;
    let signing_bytes = indra_core::types::vote_signing::vote_signing_bytes(
        vote.height,
        vote.round,
        vote.step,
        &vote.block_hash,
        &vote.validator_id,
        &vote.snapshot_root,
        chain_id,
    )
    .map_err(|error| error.to_string())?;
    let pk = HybridPublicKey {
        classical: ClassicalPublicKey(*classical_pk),
        pq: PqPublicKey(pq_pk),
    };
    let sig = vote.signature.to_crypto_sig().map_err(|e| e.to_string())?;
    verify_hybrid(&signing_bytes, &sig, &pk).map_err(|e| e.to_string())
}

/// Apply a block to the chain state, updating UTXOs, fees and validators.
pub fn apply_block(
    state: &mut ChainState,
    verified_proposal: &VerifiedProposal<'_>,
    timestamp_secs: u64, // Wall-clock time (live) or 0 (replay).
) -> StateResult<Option<EpochRecord>> {
    apply_block_with_effects(state, verified_proposal, timestamp_secs)
        .map(|outcome| outcome.epoch_record)
}

/// Apply a block and return the effects of the committed canonical transition.
///
/// Effects are produced by the same transaction that performs mutation and
/// are returned only after that transaction commits successfully.
pub fn apply_block_with_effects(
    state: &mut ChainState,
    verified_proposal: &VerifiedProposal<'_>,
    timestamp_secs: u64,
) -> StateResult<crate::AppliedBlockOutcome> {
    apply_block_contents(state, verified_proposal.block(), timestamp_secs)
}

// Deliberately private: only the capability-bearing public entry point and
// this module's state-machine unit tests may apply unsigned block contents.
fn apply_block_contents(
    state: &mut ChainState,
    block: &BlockVNext,
    timestamp_secs: u64,
) -> StateResult<crate::AppliedBlockOutcome> {
    validate_block_header(state, block)?;
    let verified_qc = verify_embedded_parent_qc(state, block)?;
    // Consensus atomicity: validation is read-only, then mutations happen
    // through a scoped undo log. If any mutation step fails, the transaction
    // drops without commit and rolls back every recorded change.
    let mut txn = StateTxn::begin(state, block.header.height);
    let epoch_record = apply_block_inner(&mut txn, block, verified_qc.as_ref(), timestamp_secs)?;
    let effects = txn.commit();
    Ok(crate::AppliedBlockOutcome {
        epoch_record,
        effects,
    })
}

#[cfg(any(debug_assertions, feature = "test-support"))]
#[doc(hidden)]
pub fn apply_block_for_test(
    state: &mut ChainState,
    block: &BlockVNext,
    timestamp_secs: u64,
) -> StateResult<Option<EpochRecord>> {
    apply_block_contents(state, block, timestamp_secs).map(|outcome| outcome.epoch_record)
}

/// Atomically validate/apply a candidate with a block-attempt-frozen dust floor.
pub fn try_apply_transaction_candidate_with_dust(
    state: &mut ChainState,
    tx: &TransactionV1,
    height: u64,
    tx_index: u32,
    dust_limit_spark: u64,
) -> StateResult<()> {
    let mut block_input_utxos = HashSet::new();
    validate_transaction_with_dust(
        state,
        tx,
        &state.chain_id,
        &mut block_input_utxos,
        height,
        dust_limit_spark,
    )?;
    let mut txn = StateTxn::begin(state, height);
    apply_transaction(&mut txn, tx, height, tx_index)?;
    txn.commit_scratch();
    Ok(())
}

/// Atomically apply one staking operation to an evolving candidate state.
pub fn try_apply_staking_candidate(
    state: &mut ChainState,
    op: &StakingOp,
    height: u64,
) -> StateResult<()> {
    try_apply_staking_candidate_at_index(state, op, height, 0)
}

/// Atomically apply one staking operation at its candidate-block ordinal.
pub fn try_apply_staking_candidate_at_index(
    state: &mut ChainState,
    op: &StakingOp,
    height: u64,
    operation_index: u32,
) -> StateResult<()> {
    let chain_id = state.chain_id.clone();
    let mut txn = StateTxn::begin(state, height);
    txn.snapshot_staking_scope();
    txn.snapshot_delegator_identity_scope();
    apply_staking_op_at_index(txn.state_mut(), op, &chain_id, height, operation_index)?;
    txn.after_mutation()?;
    txn.commit_scratch();
    Ok(())
}

/// Atomically apply an admission-certified staking candidate using state-only checks.
pub fn try_apply_verified_staking_candidate(
    state: &mut ChainState,
    op: &StakingOp,
    verified: &crate::pending::VerifiedPendingStaking,
    height: u64,
) -> StateResult<()> {
    let chain_id = state.chain_id.clone();
    let mut txn = StateTxn::begin(state, height);
    txn.snapshot_staking_scope();
    txn.snapshot_delegator_identity_scope();
    crate::apply_verified_staking_op(txn.state_mut(), op, verified, &chain_id, height)?;
    txn.after_mutation()?;
    txn.commit_scratch();
    Ok(())
}

/// Atomically apply one governance operation to an evolving candidate state.
pub fn try_apply_governance_candidate(
    state: &mut ChainState,
    op: &GovernanceOpV2,
    current_epoch: u64,
    height: u64,
) -> StateResult<()> {
    let chain_id = state.chain_id.clone();
    let mut txn = StateTxn::begin(state, height);
    txn.snapshot_governance_scope();
    txn.snapshot_delegator_identity_scope();
    apply_governance_op(txn.state_mut(), op, current_epoch, height, &chain_id)?;
    txn.after_mutation()?;
    txn.commit_scratch();
    Ok(())
}

/// Atomically apply an admission-certified governance candidate using state-only checks.
pub fn try_apply_verified_governance_candidate(
    state: &mut ChainState,
    op: &GovernanceOpV2,
    verified: &crate::pending::VerifiedPendingGovernance,
    current_epoch: u64,
    height: u64,
) -> StateResult<()> {
    let chain_id = state.chain_id.clone();
    let mut txn = StateTxn::begin(state, height);
    txn.snapshot_governance_scope();
    txn.snapshot_delegator_identity_scope();
    crate::apply_verified_governance_op(
        txn.state_mut(),
        op,
        verified,
        current_epoch,
        height,
        &chain_id,
    )?;
    txn.after_mutation()?;
    txn.commit_scratch();
    Ok(())
}

/// Atomically validate and apply one proof-carrying slash-evidence candidate.
///
/// `reporter_pubkey` is the elected proposer's reward destination when this is
/// used during block construction. Admission validation passes `None`.
pub fn try_apply_slash_candidate(
    state: &mut ChainState,
    evidence: &SlashEvidenceV2,
    height: u64,
    reporter_pubkey: Option<&HybridPubKey>,
) -> StateResult<()> {
    try_apply_slash_candidate_at_index(state, evidence, height, reporter_pubkey, 0)
}

/// Atomically apply slash evidence at its candidate-block ordinal.
pub fn try_apply_slash_candidate_at_index(
    state: &mut ChainState,
    evidence: &SlashEvidenceV2,
    height: u64,
    reporter_pubkey: Option<&HybridPubKey>,
    evidence_index: u32,
) -> StateResult<()> {
    let chain_id = state.chain_id.clone();
    let mut txn = StateTxn::begin(state, height);
    txn.snapshot_slashing_scope();
    let accounting = apply_slash_v2_at_height_with_accounting_at_index(
        txn.state_mut(),
        evidence,
        &chain_id,
        height,
        reporter_pubkey,
        evidence_index,
    )?;
    txn.add_slash_accounting(accounting.slash_amount)?;
    txn.commit_scratch();
    Ok(())
}

/// Temporarily apply a block, compute its post-state roots, then roll back.
///
/// This helper is intentionally fully synchronous. It mutates `state` only
/// inside a scoped [`StateTxn`], never commits that transaction, and restores the
/// exact pre-call in-memory cache presence before returning. It is used by block
/// production/reproposal to fill candidate headers without paying for a full
/// detached `ChainState` clone.
pub fn project_block_for_roots(
    state: &mut ChainState,
    block: &BlockVNext,
    timestamp_secs: u64,
) -> StateResult<ProjectedBlockRoots> {
    validate_block_header(state, block)?;
    let verified_qc = verify_embedded_parent_qc(state, block)?;
    let started_without_state_commitment_v2 = state.state_commitment_v2.is_none();
    let projected = {
        let mut txn = StateTxn::begin(state, block.header.height);
        match apply_block_inner(&mut txn, block, verified_qc.as_ref(), timestamp_secs) {
            Ok(epoch_record) => {
                let projected_state = txn.state();
                let roots = crate::state_root::compute_state_roots(projected_state);
                let mut value_block = block.clone();
                value_block.header.state_root = roots.state_root;
                value_block.header.validator_set_root = roots.validator_set_root;
                Ok(ProjectedBlockRoots {
                    state_root: roots.state_root,
                    validator_set_root: roots.validator_set_root,
                    value_hash: value_block.compute_value_hash(projected_state.total_supply),
                    total_supply: projected_state.total_supply,
                    epoch_record,
                })
            }
            Err(error) => Err(error),
        }
    };
    if started_without_state_commitment_v2 {
        state.state_commitment_v2 = None;
    }
    projected
}

fn apply_block_inner(
    txn: &mut StateTxn<'_>,
    block: &BlockVNext,
    verified_qc: Option<&VerifiedQc>,
    timestamp_secs: u64,
) -> StateResult<Option<EpochRecord>> {
    // DETERMINISM NOTE: timestamp_secs is NOT written into ChainState.
    // It is only stored in the returned EpochRecord for historical records.
    // Replay passes 0 for this parameter — this is intentional and safe
    // because timestamp_secs does not affect state root computation.
    //
    // WARNING: Do NOT use timestamp_secs in any computation that writes
    // to ChainState fields. If epoch-based timing logic is ever needed,
    // use block.header.timestamp (committed, deterministic) instead.

    // ── Phase 1: Block-level validation (read-only) ───────────────────────

    validate_block_header(txn.state(), block)?;
    let governing_snapshot_root = txn
        .state()
        .snapshot_for_consensus_height(block.header.height)
        .map_err(|error| StateError::InvalidConsensusSnapshot(error.to_string()))?
        .snapshot_root;
    let next_seed = indra_core::types::proposal::next_election_seed(
        txn.state().chain_id.as_bytes(),
        &txn.state().election_seed,
        block,
        &governing_snapshot_root,
    )
    .map_err(|error| StateError::InvalidConsensusSnapshot(error.to_string()))?;
    let transition_context = if is_epoch_boundary(block.header.height) {
        let expected_parent =
            block
                .header
                .height
                .checked_sub(1)
                .ok_or(StateError::InvariantViolation {
                    message: "epoch boundary has no certified parent",
                })?;
        if block.header.quorum_certificate.as_slice().is_empty() {
            return Err(StateError::InvariantViolation {
                message: "boundary block is missing its parent quorum certificate",
            });
        }
        let verified_qc = verified_qc.ok_or(StateError::InvariantViolation {
            message: "boundary block lacks verified parent quorum authority",
        })?;
        if verified_qc.height() != expected_parent {
            return Err(StateError::InvariantViolation {
                message: "boundary quorum certificate does not certify the parent height",
            });
        }
        Some(crate::epoch::EpochTransitionContext::new(
            block.header.height,
            expected_parent,
        )?)
    } else {
        None
    };
    let state = txn.state();

    if block.staking_ops.len() > MAX_STAKING_OPS_PER_BLOCK {
        return Err(StateError::TooManyStakingOps {
            actual: block.staking_ops.len(),
            max: MAX_STAKING_OPS_PER_BLOCK,
        });
    }
    if block.governance_ops.len() > MAX_GOV_OPS_PER_BLOCK {
        return Err(StateError::TooManyGovernanceOps {
            actual: block.governance_ops.len(),
            max: MAX_GOV_OPS_PER_BLOCK,
        });
    }
    let mut seen_slash_hashes: HashSet<Bytes32> = HashSet::new();
    for evidence in &block.slashing_evidence {
        if !seen_slash_hashes.insert(compute_slash_evidence_v2_hash(evidence)) {
            return Err(StateError::DuplicateSlashEvidence);
        }
    }

    // ── Phase 2: Transaction validation (read-only) ───────────────────────

    // Check for duplicate transactions within the block
    let mut seen_tx_hashes: HashSet<Vec<u8>> = HashSet::new();
    for tx in &block.transactions {
        let tx_bytes = tx.encode_to_vec();
        if !seen_tx_hashes.insert(tx_bytes) {
            return Err(StateError::DuplicateTransaction);
        }
    }

    // Validate each transaction against current state
    // We do a dry-run: check but don't mutate yet
    // Track input UTXO IDs seen in this block to catch intra-block double spends
    // before any mutation occurs.
    let mut block_input_utxos: HashSet<Bytes32> = HashSet::new();
    let transaction_dust_limit =
        indra_core::types::primitives::transaction_dust_limit_spark(state.utxos.len());

    for tx in &block.transactions {
        validate_transaction_with_dust(
            state,
            tx,
            &state.chain_id,
            &mut block_input_utxos,
            block.header.height,
            transaction_dust_limit,
        )?;
    }

    if !block.staking_ops.is_empty() {
        let mut shadow = state.clone();
        let chain_id = state.chain_id.clone();
        for (operation_index, op) in block.staking_ops.iter().enumerate() {
            op.validate_structure()
                .map_err(|e| StateError::InvalidStakingOp(e.to_string()))?;
            let operation_index =
                u32::try_from(operation_index).map_err(|_| StateError::InvariantViolation {
                    message: "staking operation index overflow",
                })?;
            apply_staking_op_at_index(
                &mut shadow,
                op,
                &chain_id,
                block.header.height,
                operation_index,
            )?;
        }
    }

    if !block.governance_ops.is_empty() {
        let mut shadow = state.clone();
        let chain_id = state.chain_id.clone();
        let current_epoch =
            governance_operation_epoch(block.header.height, transition_context.as_ref());
        for op in &block.governance_ops {
            apply_governance_op(
                &mut shadow,
                op,
                current_epoch,
                block.header.height,
                &chain_id,
            )?;
        }
    }

    if !block.slashing_evidence.is_empty() {
        let mut shadow = state.clone();
        let chain_id_clone = state.chain_id.clone();
        let reporter_pubkey = slash_reporter_pubkey_for_block(&shadow, block)?;
        for (evidence_index, evidence) in block.slashing_evidence.iter().enumerate() {
            let evidence_index =
                u32::try_from(evidence_index).map_err(|_| StateError::InvariantViolation {
                    message: "slash evidence index overflow",
                })?;
            apply_slash_v2_at_height_with_accounting_at_index(
                &mut shadow,
                evidence,
                &chain_id_clone,
                block.header.height,
                reporter_pubkey.as_ref(),
                evidence_index,
            )?;
        }
    }

    // ── Phase 3: State mutation (all validation passed) ───────────────────

    txn.ensure_state_commitment_v2()?;

    // Apply each transaction
    for (tx_idx, tx) in block.transactions.iter().enumerate() {
        apply_transaction(txn, tx, block.header.height, tx_idx as u32)?;
    }

    let chain_id = txn.state().chain_id.clone();
    for (operation_index, op) in block.staking_ops.iter().enumerate() {
        txn.snapshot_staking_scope();
        txn.snapshot_delegator_identity_scope();
        let operation_index =
            u32::try_from(operation_index).map_err(|_| StateError::InvariantViolation {
                message: "staking operation index overflow",
            })?;
        apply_staking_op_at_index(
            txn.state_mut(),
            op,
            &chain_id,
            block.header.height,
            operation_index,
        )
        .map_err(|_| StateError::InvariantViolation {
            message: "staking op failed on real state after shadow validation",
        })?;
        txn.after_mutation()?;
    }

    let current_epoch =
        governance_operation_epoch(block.header.height, transition_context.as_ref());
    let chain_id = txn.state().chain_id.clone();
    for op in &block.governance_ops {
        txn.snapshot_governance_scope();
        txn.snapshot_delegator_identity_scope();
        apply_governance_op(
            txn.state_mut(),
            op,
            current_epoch,
            block.header.height,
            &chain_id,
        )
        .map_err(|_| StateError::InvariantViolation {
            message: "governance op failed on real state after shadow validation",
        })?;
        txn.after_mutation()?;
    }

    let chain_id_for_slash = txn.state().chain_id.clone();
    let reporter_pubkey = slash_reporter_pubkey_for_block(txn.state(), block)?;
    let mut revoked_consensus_authorities = std::collections::BTreeSet::new();
    for (evidence_index, evidence) in block.slashing_evidence.iter().enumerate() {
        txn.snapshot_slashing_scope();
        let evidence_index =
            u32::try_from(evidence_index).map_err(|_| StateError::InvariantViolation {
                message: "slash evidence index overflow",
            })?;
        let accounting = apply_slash_v2_at_height_with_accounting_at_index(
            txn.state_mut(),
            evidence,
            &chain_id_for_slash,
            block.header.height,
            reporter_pubkey.as_ref(),
            evidence_index,
        )
        .map_err(|_| StateError::InvariantViolation {
            message: "slash failed on real state after shadow validation",
        })?;
        txn.add_slash_accounting(accounting.slash_amount)?;
        if txn
            .state()
            .snapshot_for_consensus_height(block.header.height)
            .is_ok_and(|snapshot| {
                snapshot
                    .entry_with_position(&accounting.validator_id)
                    .is_some()
            })
        {
            revoked_consensus_authorities.insert(accounting.validator_id);
        }
        txn.record_slash_event(crate::CommittedSlashEvent {
            validator_id: accounting.validator_id,
            slash_bps: accounting.slash_bps,
            burned: accounting.burned,
            self_principal_slashed: accounting.self_principal_slashed,
            reporter_reward: accounting.reporter_reward,
        });
    }
    // Update base fee for next block
    let next_fee = compute_next_base_fee(txn.state().base_fee, block.transactions.len());
    txn.set_base_fee(next_fee)?;

    // Advance height and tip hash
    txn.set_tip(block.header.height, block.header.block_hash())?;
    txn.set_election_seed(next_seed, block.header.height.saturating_add(1))?;

    // Rewards are issued at their actual finalized height, never pre-minted or
    // accumulated into an epoch reserve. This transition also fails closed if
    // the persisted cumulative target is inconsistent with the prior height.
    txn.snapshot_epoch_scope();
    let reward_selector =
        verified_qc.map_or(crate::epoch::RewardRecipientSelector::AllMembers, |qc| {
            crate::epoch::RewardRecipientSelector::Signers(
                qc.signer_ids().iter().copied().collect::<BTreeSet<_>>(),
            )
        });
    crate::epoch::apply_block_reward_issuance_with_selector(
        txn.state_mut(),
        block.header.height,
        &reward_selector,
    )?;
    txn.after_mutation()?;

    // A slash finalized at H revokes only the affected frozen authorities at
    // H+1. Epoch-boundary blocks use the regular post-transition snapshot below,
    // which observes the same slash plus every scheduled boundary mutation.
    if transition_context.is_none() && !revoked_consensus_authorities.is_empty() {
        txn.snapshot_epoch_scope();
        txn.state_mut().rotate_consensus_snapshot_after_slash(
            block.header.height,
            &revoked_consensus_authorities,
        )?;
        txn.state_mut()
            .rebuild_state_commitment_v2(block.header.height);
        txn.after_mutation()?;
    }

    // Credit the certified parent's activity before the transition
    // so the closing epoch's final QC participates in liveness evaluation.
    if let Some(context) = transition_context {
        txn.snapshot_validator_activity_scope();
        update_last_active_epoch_from_block_qc(
            txn.state_mut(),
            block,
            verified_qc,
            Some(&context),
        )?;
        txn.after_mutation()?;
    }

    // Apply epoch transition if this is the last block of an epoch.
    let epoch_record = if let Some(context) = transition_context {
        txn.snapshot_epoch_scope();
        Some(
            crate::epoch::apply_epoch_transition_at_height_with_selector(
                txn.state_mut(),
                &context,
                timestamp_secs,
                &reward_selector,
            )?,
        )
    } else {
        None
    };
    if epoch_record.is_some() {
        txn.after_mutation()?;
    }

    txn.state_mut().refresh_and_reconcile_monetary_state()?;
    if txn.state().total_supply > LIFETIME_SUPPLY_CAP_SPARK {
        return Err(StateError::InvariantViolation {
            message: "CRITICAL: total supply exceeds hard cap — constitutional invariant violated",
        });
    }

    if transition_context.is_none() {
        txn.snapshot_validator_activity_scope();
        update_last_active_epoch_from_block_qc(txn.state_mut(), block, verified_qc, None)?;
        txn.after_mutation()?;
    }

    // Snapshot rotation is deliberately last: it must observe the fully
    // settled post-boundary validator state after reselection, rewards,
    // releases, liveness penalties, and QC activity accounting.
    if let Some(context) = transition_context {
        let boundary_height = context.boundary_height;
        txn.state_mut()
            .create_consensus_snapshot_after_boundary(boundary_height)?;
        txn.state_mut().rebuild_state_commitment_v2(boundary_height);
        txn.after_mutation()?;
    }

    Ok(epoch_record)
}

fn governance_operation_epoch(
    height: u64,
    context: Option<&crate::epoch::EpochTransitionContext>,
) -> u64 {
    context.map_or_else(|| epoch_for_height(height), |context| context.closing_epoch)
}

/// Update validator liveness from the QC embedded in the applied block.
///
/// This is consensus state because `last_active_epoch` is committed in the
/// validator-set root. Keeping this mutation inside `apply_block` ensures live
/// import, sync import, snapshot replay, and block-production projection all
/// execute the same state transition.
fn update_last_active_epoch_from_block_qc(
    state: &mut ChainState,
    block: &BlockVNext,
    verified_qc: Option<&VerifiedQc>,
    context: Option<&crate::epoch::EpochTransitionContext>,
) -> StateResult<()> {
    if block.header.quorum_certificate.as_slice().is_empty() {
        return Ok(());
    }

    let qc = verified_qc.ok_or(StateError::InvariantViolation {
        message: "QC activity attribution lacks verified signer authority",
    })?;

    let current_epoch = if let Some(context) = context {
        if qc.height() != context.certified_parent_height {
            return Err(StateError::InvariantViolation {
                message: "QC activity height does not match epoch transition context",
            });
        }
        epoch_for_height(context.certified_parent_height)
    } else {
        epoch_for_height(block.header.height)
    };
    let mut changed = Vec::new();
    for validator_id in qc.signer_ids() {
        if let Some(validator) = state.validators.get_mut(validator_id) {
            validator.last_active_epoch = current_epoch;
            changed.push(*validator_id);
        }
    }
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        for validator_id in changed {
            if let Some(validator) = state.validators.get(&validator_id) {
                commitment.put_validator(validator, block.header.height);
            }
        }
    }
    Ok(())
}

fn verify_embedded_parent_qc(
    state: &ChainState,
    block: &BlockVNext,
) -> StateResult<Option<VerifiedQc>> {
    if block.header.height <= 1 {
        if !block.header.quorum_certificate.as_slice().is_empty() {
            return Err(StateError::InvariantViolation {
                message: "genesis-height block must not carry a quorum certificate",
            });
        }
        return Ok(None);
    }
    let bytes = block.header.quorum_certificate.as_slice();
    let qc =
        QuorumCertificateV1::decode_exact(bytes).map_err(|_| StateError::InvariantViolation {
            message: "block has malformed quorum certificate",
        })?;
    let expected_height = block.header.height - 1;
    if qc.height != expected_height || qc.block_hash != block.header.prev_hash {
        return Err(StateError::InvariantViolation {
            message: "quorum certificate does not certify the exact parent",
        });
    }
    let snapshot = state
        .snapshot_for_consensus_height(qc.height)
        .map_err(|_| StateError::InvariantViolation {
            message: "no immutable authority snapshot governs the certified height",
        })?;
    let verified = verify_qc_against_snapshot(&qc, snapshot, &state.chain_id).map_err(|_| {
        StateError::InvariantViolation {
            message: "quorum certificate failed hybrid quorum verification",
        }
    })?;
    if !verified.matches_encoded_qc(bytes) {
        return Err(StateError::InvariantViolation {
            message: "verified quorum capability is not bound to embedded bytes",
        });
    }
    Ok(Some(verified))
}

/// Validate block-level invariants (does not touch state).
fn validate_block_header(state: &ChainState, block: &BlockVNext) -> StateResult<()> {
    // Protocol version
    if block.header.protocol_version.0 != BLOCK_FORMAT_VERSION {
        return Err(StateError::UnsupportedVersion {
            version: block.header.protocol_version.0,
        });
    }

    // Height must be exactly state.height + 1
    let expected_height = state.height + 1;
    if block.header.height != expected_height {
        return Err(StateError::InvalidHeight {
            expected: expected_height,
            actual: block.header.height,
        });
    }

    // prev_hash must match our current tip
    if block.header.prev_hash != state.tip_hash {
        return Err(StateError::PrevHashMismatchDetailed {
            height: block.header.height,
            expected: state.tip_hash,
            got: block.header.prev_hash,
        });
    }

    // Block size
    let block_size = block.encode_to_vec().len();
    if block_size > MAX_BLOCK_SIZE_BYTES {
        return Err(StateError::BlockTooLarge {
            actual: block_size,
            max: MAX_BLOCK_SIZE_BYTES,
        });
    }

    // Transaction count
    if block.transactions.len() > MAX_TX_PER_BLOCK {
        return Err(StateError::TooManyTransactions {
            actual: block.transactions.len(),
            max: MAX_TX_PER_BLOCK,
        });
    }
    // base_fee field must match what we computed for this height
    // (the block proposer must use the correct fee or be rejected)
    if block.header.base_fee != state.base_fee {
        return Err(StateError::BaseFeeIncorrect {
            block_fee: block.header.base_fee,
            computed_fee: state.base_fee,
        });
    }

    Ok(())
}

/// Validate one transaction against the current state.
///
/// `block_input_utxos` accumulates input UTXO IDs seen so far in THIS block,
/// preventing the same UTXO from being counted more than once.
pub fn validate_transaction(
    state: &ChainState,
    tx: &TransactionV1,
    chain_id: &str,
    block_input_utxos: &mut HashSet<Bytes32>,
    current_height: u64,
) -> StateResult<()> {
    validate_transaction_with_dust(
        state,
        tx,
        chain_id,
        block_input_utxos,
        current_height,
        indra_core::types::primitives::transaction_dust_limit_spark(state.utxos.len()),
    )
}

/// Validate a transaction with the dust floor frozen from block pre-state.
pub fn validate_transaction_with_dust(
    state: &ChainState,
    tx: &TransactionV1,
    chain_id: &str,
    block_input_utxos: &mut HashSet<Bytes32>,
    current_height: u64,
    dust_limit_spark: u64,
) -> StateResult<()> {
    if tx.inputs.is_empty() {
        return Err(StateError::ZeroInputs);
    }
    if tx.outputs.is_empty() {
        return Err(StateError::ZeroOutputs);
    }
    if tx.version.0 != TRANSACTION_PROTOCOL_VERSION {
        return Err(StateError::UnsupportedTxVersion {
            version: tx.version.0,
        });
    }
    if tx.signature_module_id != 1 {
        return Err(StateError::UnsupportedSignatureModule {
            module_id: tx.signature_module_id,
        });
    }

    let mut total_input_value = 0u64;
    let mut owner_pubkey: Option<indra_core::types::crypto::HybridPubKey> = None;

    for input in &tx.inputs {
        if !block_input_utxos.insert(input.utxo_id) {
            return Err(StateError::DuplicateUtxoSpend {
                utxo_id: input.utxo_id,
            });
        }

        // Referenced UTXO must exist
        let entry = state
            .utxos
            .get(&input.utxo_id)
            .ok_or(StateError::UnknownUtxo)?;
        total_input_value = total_input_value
            .checked_add(entry.output.value_spark)
            .ok_or(StateError::ValueOverflow)?;
        match &owner_pubkey {
            Some(existing) if existing != &entry.output.owner_pubkey => {
                return Err(StateError::InvariantViolation {
                    message: "all transaction inputs must belong to the same owner",
                });
            }
            None => owner_pubkey = Some(entry.output.owner_pubkey.clone()),
            _ => {}
        }

        // UTXO must be past its lock height
        if entry.output.lock_height > current_height {
            return Err(StateError::OutputLocked {
                lock_height: entry.output.lock_height,
                current_height,
            });
        }
    }

    let owner_pubkey = owner_pubkey.ok_or(StateError::UnknownUtxo)?;
    let crypto_pk = owner_pubkey
        .to_crypto_pubkey()
        .map_err(|reason| StateError::SignatureInvalid { reason })?;
    let crypto_sig = tx
        .signature
        .to_crypto_sig()
        .map_err(|reason| StateError::SignatureInvalid { reason })?;
    let signing_bytes = tx
        .signing_bytes(chain_id)
        .map_err(|e| StateError::SignatureInvalid {
            reason: e.to_string(),
        })?;
    verify_hybrid(&signing_bytes, &crypto_sig, &crypto_pk).map_err(|e| {
        StateError::SignatureInvalid {
            reason: e.to_string(),
        }
    })?;

    // Fee check: fee_amount must cover base_fee × weight
    let weight_kb = {
        let bytes = tx.encode_to_vec().len() as u64;
        bytes.div_ceil(1024)
    };
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

    let total_output_value = tx
        .outputs
        .iter()
        .try_fold(0u64, |acc, output| acc.checked_add(output.value_spark))
        .ok_or(StateError::ValueOverflow)?;
    let required_total = total_output_value
        .checked_add(tx.fee_amount)
        .ok_or(StateError::ValueOverflow)?;
    if total_input_value != required_total {
        return Err(StateError::InvariantViolation {
            message: "transaction inputs must equal outputs plus fee",
        });
    }

    for output in &tx.outputs {
        let crypto_owner = output
            .owner_pubkey
            .to_crypto_pubkey()
            .map_err(|reason| StateError::InvalidOutputOwnerKey { reason })?;
        validate_classical_public_key(&crypto_owner.classical).map_err(|error| {
            StateError::InvalidOutputOwnerKey {
                reason: error.to_string(),
            }
        })?;
        validate_pq_public_key(&crypto_owner.pq).map_err(|error| {
            StateError::InvalidOutputOwnerKey {
                reason: error.to_string(),
            }
        })?;
        if output.value_spark < dust_limit_spark {
            return Err(StateError::InvariantViolation {
                message: "transaction output below dust limit",
            });
        }
    }

    Ok(())
}

/// Apply one transaction's state changes.
///
/// Called only after validate_transaction has passed for all transactions.
fn apply_transaction(
    txn: &mut StateTxn<'_>,
    tx: &TransactionV1,
    height: u64,
    tx_index: u32,
) -> StateResult<()> {
    for input in &tx.inputs {
        if txn.spend_utxo(&input.utxo_id)?.is_none() {
            return Err(StateError::InvariantViolation {
                message: "attempted to spend an already-spent UTXO during apply_transaction",
            });
        }
    }

    // Create outputs: insert new UTXOs
    for (out_idx, output) in tx.outputs.iter().enumerate() {
        txn.insert_utxo(output.clone(), height, tx_index, out_idx as u32)?;
    }

    let burn_amount = tx.fee_amount / 2;
    let validator_amount = tx
        .fee_amount
        .checked_sub(burn_amount)
        .ok_or(StateError::ValueOverflow)?;
    txn.apply_fee_accounting(burn_amount, validator_amount)?;

    Ok(())
}
