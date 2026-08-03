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
//!   8.  No duplicate nullifiers within the transaction
//!   9.  No duplicate nullifiers against the nullifier set
//!   10. All input UTXOs exist in the UTXO set
//!   11. All input UTXOs are past their lock_height
//!   12. fee_amount ≥ base_fee × tx_weight_kb
//!
//! State updates (only after ALL checks pass):
//!   - Spend inputs (remove from UTXO set, add nullifiers)
//!   - Create outputs (insert into UTXO set)
//!   - Update base_fee
//!   - If epoch boundary: apply epoch transition
//!   - Update height and tip_hash
//!
//! ## Atomicity
//!
//! State is only mutated after all validation passes.
//! On any error, the original state is unchanged.

use std::collections::HashSet;

use indra_core::{
    codec::{ByteReader, Decode, Encode},
    types::{
        block::BlockV1,
        crypto::{CommitmentV1, HybridPubKey},
        primitives::{
            bps_of, Bytes32, BLOCK_FORMAT_VERSION, HARD_CAP_SPARK, MAX_BLOCK_SIZE_BYTES,
            MAX_GOV_OPS_PER_BLOCK, MAX_STAKING_OPS_PER_BLOCK, MAX_TX_PER_BLOCK,
            SLASH_EVIDENCE_WINDOW_EPOCHS, STAKING_TX_IDX,
            TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES, UNBONDING_PERIOD_EPOCHS,
        },
        qc::QuorumCertificateV1,
        slash_membership::SlashMembershipRootRecord,
        slashing::{SlashEvidenceV1, SlashEvidenceV2},
        transaction::{OutputV1, TransactionV1},
        vote::VoteV1,
        vrf_election::VrfElectionResult,
    },
    EpochRecord,
};
use indra_crypto::{
    verify_balance, verify_hybrid, verify_opening, verify_range, PedersenCommitment,
    PedersenOpening,
};
use rand::{rngs::StdRng, SeedableRng};

use crate::{
    chain::ChainState,
    delegation::apply_staking_op,
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
    slash_amount: u64,
    burned: u64,
    reporter_reward: u64,
}

fn apply_slash_v2_at_height_with_accounting(
    state: &mut ChainState,
    evidence: &SlashEvidenceV2,
    chain_id: &str,
    height: u64,
    reporter_pubkey: Option<&HybridPubKey>,
) -> StateResult<SlashAccounting> {
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
    let legacy_shape = SlashEvidenceV1 {
        validator_id: evidence.validator_id,
        vote_1: evidence.vote_1.clone(),
        vote_2: evidence.vote_2.clone(),
    };
    apply_slash_common(
        state,
        &legacy_shape,
        compute_slash_evidence_v2_hash(evidence),
        Some((
            evidence.membership_proof.entry.classical_vote_pk,
            evidence.membership_proof.entry.pq_vote_pk.to_vec(),
        )),
        chain_id,
        height,
        reporter_pubkey,
    )
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
) -> StateResult<SlashAccounting> {
    use crate::ValidatorStatus;
    use indra_core::types::{
        primitives::{DUST_LIMIT_SPARK, SLASH_REPORTER_REWARD_BPS},
        vote::VoteStep,
    };

    if state.applied_slash_hashes.contains(&evidence_hash) {
        return Err(StateError::SlashAlreadyApplied);
    }

    let validator_id = evidence.validator_id;

    let live_validator = state.validators.get(&validator_id);
    let tombstone = state.evicted_validator_tombstones.get(&validator_id);
    if live_validator.is_none() {
        let tombstone = tombstone.ok_or(StateError::ValidatorNotFound)?;
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
        if matches!(v.status, ValidatorStatus::Slashed | ValidatorStatus::Exited) {
            return Err(StateError::InvalidSlashEvidence {
                reason: "validator already slashed or exited".into(),
            });
        }
    }

    verify_vote_sig_with_keys(&evidence.vote_1, &classical_pk, &pq_pk_bytes, chain_id).map_err(
        |e| StateError::InvalidSlashEvidence {
            reason: format!("vote_1 signature invalid: {e}"),
        },
    )?;
    verify_vote_sig_with_keys(&evidence.vote_2, &classical_pk, &pq_pk_bytes, chain_id).map_err(
        |e| StateError::InvalidSlashEvidence {
            reason: format!("vote_2 signature invalid: {e}"),
        },
    )?;

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

    let bps = |amount, rate| bps_of(amount, rate);

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
    let slashable_position_stake = position_ids.iter().fold(0u64, |acc, id| {
        acc.saturating_add(
            state
                .stake_positions
                .get(id)
                .and_then(|position| position.active)
                .map(|active| active.principal_spark)
                .unwrap_or(0),
        )
    });
    let slashable_tranche_stake = tranche_ids.iter().fold(0u64, |acc, id| {
        acc.saturating_add(
            state
                .unbonding_tranches
                .get(id)
                .map(|tranche| tranche.principal_spark)
                .unwrap_or(0),
        )
    });
    let slashable_principal = slashable_position_stake.saturating_add(slashable_tranche_stake);
    let current_stake = state
        .validators
        .get(&validator_id)
        .map(|v| v.stake_spark)
        .unwrap_or(0);
    let slash_base = slashable_principal.max(current_stake);
    let slash_amount = bps(slash_base, slash_bps);
    let potential_reporter_reward = bps(slash_amount, SLASH_REPORTER_REWARD_BPS);

    let mut total_principal_slashed: u64 = 0;
    let mut active_principal_slashed: u64 = 0;
    for position_id in &position_ids {
        if let Some(mut position) = state.stake_positions.get(position_id).cloned() {
            if let Some(active) = position.active {
                let amount = bps(active.principal_spark, slash_bps);
                let remaining = active.principal_spark.saturating_sub(amount);
                position.active = (remaining > 0).then(|| {
                    indra_core::types::stake_position::ActiveStakeAggregateV1 {
                        principal_spark: remaining,
                        ..active
                    }
                });
                active_principal_slashed = active_principal_slashed.saturating_add(amount);
                total_principal_slashed = total_principal_slashed.saturating_add(amount);
                state.stake_positions.insert(*position_id, position.clone());
                if let Some(commitment) = state.state_commitment_v2.as_mut() {
                    commitment.put_stake_position(&position);
                }
            }
        }
    }
    let mut tranche_successors = Vec::new();
    for tranche_id in &tranche_ids {
        if let Some(tranche) = state.unbonding_tranches.get(tranche_id).cloned() {
            let amount = bps(tranche.principal_spark, slash_bps);
            let remaining = tranche.principal_spark.saturating_sub(amount);
            total_principal_slashed = total_principal_slashed.saturating_add(amount);
            if remaining == 0 {
                tranche_successors.push((*tranche_id, None));
            } else {
                let successor_id = indra_core::types::stake_position::derive_tranche_id(
                    tranche.position_id,
                    tranche.creation_op_id,
                    tranche.creation_ordinal,
                    tranche.timing,
                    remaining,
                );
                let source_blinding = indra_crypto::derive_tranche_source_blinding_v1(
                    &indra_crypto::TrancheSourceBlindingInputsV1 {
                        chain_id: state.chain_id.as_bytes(),
                        position_id: tranche.position_id.0,
                        tranche_id: successor_id.0,
                        principal_spark: remaining,
                        start_height: tranche.timing.start_height(),
                        creation_op_id: tranche.creation_op_id.0,
                    },
                )
                .map_err(|error| StateError::InvalidSlashEvidence {
                    reason: error.to_string(),
                })?;
                let successor = indra_core::types::stake_position::UnbondingTrancheV1::new(
                    tranche.position_id,
                    remaining,
                    indra_crypto::commit(remaining, &source_blinding),
                    tranche.timing,
                    tranche.custody,
                    tranche.creation_op_id,
                    tranche.creation_ordinal,
                )
                .map_err(|error| StateError::InvalidSlashEvidence {
                    reason: error.to_string(),
                })?;
                if successor.tranche_id != successor_id
                    || (successor_id != *tranche_id
                        && state.unbonding_tranches.contains_key(&successor_id))
                {
                    return Err(StateError::InvariantViolation {
                        message: "slash successor tranche identity collision",
                    });
                }
                tranche_successors.push((*tranche_id, Some(successor)));
            }
        }
    }
    // A slash is a canonical consume-and-successor transition. Nonzero
    // reductions are exactly one-for-one and therefore cannot consume tranche
    // capacity; a complete slash only decreases the count.
    for (old_id, successor) in &tranche_successors {
        state.unbonding_tranches.remove(old_id);
        if let Some(commitment) = state.state_commitment_v2.as_mut() {
            commitment.delete_unbonding_tranche(old_id);
        }
        if let Some(successor) = successor {
            state
                .unbonding_tranches
                .insert(successor.tranche_id, successor.clone());
            if let Some(commitment) = state.state_commitment_v2.as_mut() {
                commitment.put_unbonding_tranche(successor);
            }
        }
    }
    if let Some(mut tombstone) = state
        .evicted_validator_tombstones
        .get(&validator_id)
        .cloned()
    {
        for (old_id, successor) in &tranche_successors {
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
    }
    state
        .rebuild_position_tranche_index()
        .map_err(|error| StateError::InvalidSlashEvidence {
            reason: error.to_string(),
        })?;

    let mut updated_validator = None;
    if let Some(v) = state.validators.get_mut(&validator_id) {
        let stake_slash = if slashable_principal > 0 {
            active_principal_slashed
        } else {
            slash_amount
        };
        v.stake_spark = v.stake_spark.saturating_sub(stake_slash);
        // Equivocation slashing is prospective-only by policy. Rewards already
        // credited to `pending_rewards` are never clawed back retroactively;
        // the penalty is the immediate stake reduction here plus permanent
        // exclusion from future reward eligibility through `Slashed` status.
        v.status = ValidatorStatus::Slashed;
        updated_validator = Some(v.clone());
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
            )?;
            potential_reporter_reward
        } else {
            0
        }
    } else {
        0
    };
    let burned = slash_amount.saturating_sub(reporter_reward);
    state.total_supply = state.total_supply.saturating_sub(burned);
    state.applied_slash_hashes.insert(evidence_hash);
    if let Some(commitment) = state.state_commitment_v2.as_mut() {
        commitment.put_slash_hash(&evidence_hash);
    }

    eprintln!(
        "[slash] validator {} slashed {}bps — burned={} self_bond_slashed={} reporter_reward={}",
        hex::encode(&validator_id.0[..4]),
        slash_bps,
        burned,
        total_principal_slashed,
        reporter_reward,
    );

    Ok(SlashAccounting {
        slash_amount,
        burned,
        reporter_reward,
    })
}

/// Compute the canonical proof-carrying evidence hash used for deduplication.
pub fn compute_slash_evidence_v2_hash(evidence: &SlashEvidenceV2) -> Bytes32 {
    Bytes32::from(indra_crypto::sha256(&evidence.encode_to_vec()))
}

/// Hash an unproven equivocation pair while it is held in the node-local
/// pending pool. Only `SlashEvidenceV2` is accepted by blocks/state transition.
pub fn compute_pending_slash_evidence_hash(evidence: &SlashEvidenceV1) -> Bytes32 {
    Bytes32::from(indra_crypto::sha256(&evidence.encode_to_vec()))
}

fn derive_slash_reward_blinding(evidence_hash: &Bytes32, block_height: u64) -> [u8; 32] {
    let mut data = b"INDRA-SLASH-REWARD-BLINDING-v1".to_vec();
    data.extend_from_slice(&evidence_hash.0);
    data.extend_from_slice(&block_height.to_le_bytes());
    indra_crypto::sha256(&data)
}

fn create_slash_reporter_reward_utxo(
    state: &mut ChainState,
    evidence_hash: &Bytes32,
    block_height: u64,
    reporter_reward: u64,
    reporter_pubkey: &HybridPubKey,
) -> StateResult<Bytes32> {
    let blinding = derive_slash_reward_blinding(evidence_hash, block_height);
    let commitment = indra_crypto::commit(reporter_reward, &blinding);
    let mut rng = StdRng::from_seed(blinding);
    let proof = indra_crypto::prove_range(reporter_reward, &blinding, &mut rng).map_err(|_| {
        StateError::InvalidSlashEvidence {
            reason: "failed to generate range proof for slash reporter reward".into(),
        }
    })?;
    let output = OutputV1 {
        value_spark: reporter_reward,
        commitment: CommitmentV1 {
            compressed_point: Bytes32::from(commitment.0),
        },
        owner_pubkey: reporter_pubkey.clone(),
        range_proof: indra_core::VariableBytes::from_slice(&proof).map_err(|_| {
            StateError::InvalidSlashEvidence {
                reason: "slash reporter reward range proof too large".into(),
            }
        })?,
        lock_height: 0,
    };
    let reward_utxo_id = state
        .utxos
        .insert(output, block_height, STAKING_TX_IDX, 0)
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

const VRF_FALLBACK_OUTPUT_BYTES: Bytes32 = Bytes32([0xFF; 32]);

fn slash_reporter_pubkey_for_block(
    state: &ChainState,
    block: &BlockV1,
) -> StateResult<Option<HybridPubKey>> {
    let snapshot = state
        .snapshot_for_consensus_height(block.header.height)
        .map_err(|error| StateError::InvalidConsensusSnapshot(error.to_string()))?;
    let proposer_id = slash_reporter_validator_id_from_candidate_ids(
        snapshot.entries().iter().map(|entry| entry.validator_id),
        block,
    );
    Ok(proposer_id.and_then(|proposer_id| {
        snapshot
            .entries()
            .iter()
            .find(|entry| entry.validator_id == proposer_id)
            .and_then(|entry| {
                Some(HybridPubKey {
                    classical_pk: Bytes32::from(entry.classical_vote_pk),
                    pq_pk: indra_core::VariableBytes::from_slice(&entry.pq_vote_pk).ok()?,
                })
            })
    }))
}

fn slash_reporter_validator_id_from_candidate_ids<I>(
    candidate_ids: I,
    block: &BlockV1,
) -> Option<Bytes32>
where
    I: IntoIterator<Item = Bytes32>,
{
    let header_hash = block.header.election_result_hash?;
    let mut matches = candidate_ids.into_iter().filter_map(|validator_id| {
        let normal = VrfElectionResult {
            height: block.header.height,
            round: block.header.proposer_round,
            elected_validator_id: validator_id,
            elected_vrf_output: block.header.proposer_vrf_output,
            fallback_used: false,
            reveal_set_commitment: Bytes32::ZERO,
        }
        .hash();
        let fallback = VrfElectionResult {
            height: block.header.height,
            round: block.header.proposer_round,
            elected_validator_id: validator_id,
            elected_vrf_output: VRF_FALLBACK_OUTPUT_BYTES,
            fallback_used: true,
            reveal_set_commitment: Bytes32::ZERO,
        }
        .hash();
        (header_hash == normal || header_hash == fallback).then_some(validator_id)
    });
    let proposer_id = matches.next()?;
    matches.next().is_none().then_some(proposer_id)
}

fn verify_vote_sig_with_keys(
    vote: &VoteV1,
    classical_pk: &[u8; 32],
    pq_pk_bytes: &[u8],
    chain_id: &str,
) -> Result<(), String> {
    use indra_crypto::{
        verify_hybrid, ClassicalPublicKey, HybridPublicKey, PqPublicKey, PQ_PK_BYTES,
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
        vote.election_result_hash.as_ref(),
        chain_id,
    );
    let pk = HybridPublicKey {
        classical: ClassicalPublicKey(*classical_pk),
        pq: PqPublicKey(pq_pk),
    };
    let sig = vote.signature.to_crypto_sig().map_err(|e| e.to_string())?;
    verify_hybrid(&signing_bytes, &sig, &pk).map_err(|e| e.to_string())
}

/// Apply a block to the chain state, updating UTXOs, nullifiers, fees and validators.
pub fn apply_block(
    state: &mut ChainState,
    block: &BlockV1,
    timestamp_secs: u64, // Wall-clock time (live) or 0 (replay).
) -> StateResult<Option<EpochRecord>> {
    // Consensus atomicity: validation is read-only, then mutations happen
    // through a scoped undo log. If any mutation step fails, the transaction
    // drops without commit and rolls back every recorded change.
    let mut txn = StateTxn::begin(state, block.header.height);
    let epoch_record = apply_block_inner(&mut txn, block, timestamp_secs)?;
    txn.commit();
    Ok(epoch_record)
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
    block: &BlockV1,
    timestamp_secs: u64,
) -> StateResult<ProjectedBlockRoots> {
    let started_without_state_commitment_v2 = state.state_commitment_v2.is_none();
    let projected = {
        let mut txn = StateTxn::begin(state, block.header.height);
        match apply_block_inner(&mut txn, block, timestamp_secs) {
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
    block: &BlockV1,
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
        let mut reader = ByteReader::new(block.header.quorum_certificate.as_slice());
        let qc = QuorumCertificateV1::decode(&mut reader).map_err(|_| {
            StateError::InvariantViolation {
                message: "boundary block has malformed quorum certificate",
            }
        })?;
        if qc.height != expected_parent {
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
    // Track nullifiers and input UTXO IDs seen in THIS block to catch
    // intra-block double spends before any mutation occurs.
    let mut block_nullifiers: HashSet<Bytes32> = HashSet::new();
    let mut block_input_utxos: HashSet<Bytes32> = HashSet::new();

    for tx in &block.transactions {
        validate_transaction(
            state,
            tx,
            &state.chain_id,
            &mut block_nullifiers,
            &mut block_input_utxos,
            block.header.height,
        )?;
    }

    if !block.staking_ops.is_empty() {
        let mut shadow = state.clone();
        let chain_id = state.chain_id.clone();
        for op in &block.staking_ops {
            op.validate_structure_at_height(block.header.height)
                .map_err(|e| StateError::InvalidStakingOp(e.to_string()))?;
            apply_staking_op(&mut shadow, op, &chain_id, block.header.height)?;
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
        for evidence in &block.slashing_evidence {
            apply_slash_v2_at_height_with_accounting(
                &mut shadow,
                evidence,
                &chain_id_clone,
                block.header.height,
                reporter_pubkey.as_ref(),
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
    for op in &block.staking_ops {
        txn.snapshot_staking_scope();
        txn.snapshot_delegator_identity_scope();
        apply_staking_op(txn.state_mut(), op, &chain_id, block.header.height).map_err(|_| {
            StateError::InvariantViolation {
                message: "staking op failed on real state after shadow validation",
            }
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
    for evidence in &block.slashing_evidence {
        txn.snapshot_slashing_scope();
        let accounting = apply_slash_v2_at_height_with_accounting(
            txn.state_mut(),
            evidence,
            &chain_id_for_slash,
            block.header.height,
            reporter_pubkey.as_ref(),
        )
        .map_err(|_| StateError::InvariantViolation {
            message: "slash failed on real state after shadow validation",
        })?;
        txn.add_slash_accounting(accounting.slash_amount)?;
    }
    // Update base fee for next block
    let next_fee = compute_next_base_fee(txn.state().base_fee, block.transactions.len());
    txn.set_base_fee(next_fee)?;

    // Advance height and tip hash
    txn.set_tip(block.header.height, block.header.block_hash())?;

    // Credit the certified parent's activity before the transition
    // so the closing epoch's final QC participates in liveness evaluation.
    if let Some(context) = transition_context {
        txn.snapshot_validator_activity_scope();
        update_last_active_epoch_from_block_qc(txn.state_mut(), block, Some(&context))?;
        txn.after_mutation()?;
    }

    // Apply epoch transition if this is the last block of an epoch.
    let epoch_record = if let Some(context) = transition_context {
        txn.snapshot_epoch_scope();
        Some(crate::epoch::apply_epoch_transition_at_height(
            txn.state_mut(),
            &context,
            timestamp_secs,
        )?)
    } else {
        None
    };
    if epoch_record.is_some() {
        txn.after_mutation()?;
    }

    if txn.state().total_supply > HARD_CAP_SPARK {
        return Err(StateError::InvariantViolation {
            message: "CRITICAL: total supply exceeds hard cap — constitutional invariant violated",
        });
    }

    if transition_context.is_none() {
        txn.snapshot_validator_activity_scope();
        update_last_active_epoch_from_block_qc(txn.state_mut(), block, None)?;
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
    block: &BlockV1,
    context: Option<&crate::epoch::EpochTransitionContext>,
) -> StateResult<()> {
    if block.header.quorum_certificate.as_slice().is_empty() {
        return Ok(());
    }

    let mut reader = ByteReader::new(block.header.quorum_certificate.as_slice());
    let Ok(qc) = QuorumCertificateV1::decode(&mut reader) else {
        return Ok(());
    };

    let current_epoch = if let Some(context) = context {
        if qc.height != context.certified_parent_height {
            return Err(StateError::InvariantViolation {
                message: "QC activity height does not match epoch transition context",
            });
        }
        epoch_for_height(context.certified_parent_height)
    } else {
        epoch_for_height(block.header.height)
    };
    let mut changed = Vec::new();
    for signature in qc.pq_signatures {
        if let Some(validator) = state.validators.get_mut(&signature.validator_id) {
            validator.last_active_epoch = current_epoch;
            changed.push(signature.validator_id);
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

/// Validate block-level invariants (does not touch state).
fn validate_block_header(state: &ChainState, block: &BlockV1) -> StateResult<()> {
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
/// `block_nullifiers` accumulates nullifiers seen so far in THIS block,
/// allowing detection of intra-block double spends.
/// `block_input_utxos` accumulates input UTXO IDs seen so far in THIS block,
/// preventing the same UTXO from being counted more than once with distinct
/// nullifiers.
pub fn validate_transaction(
    state: &ChainState,
    tx: &TransactionV1,
    chain_id: &str,
    block_nullifiers: &mut HashSet<Bytes32>,
    block_input_utxos: &mut HashSet<Bytes32>,
    current_height: u64,
) -> StateResult<()> {
    if tx.inputs.is_empty() {
        return Err(StateError::ZeroInputs);
    }
    if tx.outputs.is_empty() {
        return Err(StateError::ZeroOutputs);
    }
    if tx.version.0 != TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES {
        return Err(StateError::UnsupportedTxVersion {
            version: tx.version.0,
        });
    }
    if tx.payment_notes.len() != tx.outputs.len() {
        return Err(StateError::InvariantViolation {
            message: "payment_notes length must equal outputs length",
        });
    }
    for (output, note) in tx.outputs.iter().zip(&tx.payment_notes) {
        if note.owner_id != indra_crypto::sha256(&output.owner_pubkey.classical_pk.0) {
            return Err(StateError::InvariantViolation {
                message: "payment note owner_id does not match output owner",
            });
        }
    }
    if tx.signature_module_id != 1 {
        return Err(StateError::UnsupportedSignatureModule {
            module_id: tx.signature_module_id,
        });
    }

    let mut total_input_value = 0u64;
    let mut owner_pubkey: Option<indra_core::types::crypto::HybridPubKey> = None;
    let mut input_commitments = Vec::with_capacity(tx.inputs.len());

    for input in &tx.inputs {
        if !block_input_utxos.insert(input.utxo_id) {
            return Err(StateError::DuplicateUtxoSpend {
                utxo_id: input.utxo_id,
            });
        }

        // Duplicate nullifier within this transaction
        if block_nullifiers.contains(&input.nullifier) {
            return Err(StateError::DuplicateNullifier);
        }

        // Already spent in a previous block
        if state.nullifiers.contains(&input.nullifier) {
            return Err(StateError::DoubleSpend);
        }

        // Referenced UTXO must exist
        let entry = state
            .utxos
            .get(&input.utxo_id)
            .ok_or(StateError::UnknownUtxo)?;
        input_commitments.push(PedersenCommitment(
            entry.output.commitment.compressed_point.0,
        ));

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

        block_nullifiers.insert(input.nullifier);
    }

    let owner_pubkey = owner_pubkey.ok_or(StateError::UnknownUtxo)?;
    let crypto_pk = owner_pubkey
        .to_crypto_pubkey()
        .map_err(|reason| StateError::SignatureInvalid { reason })?;
    let crypto_sig = tx
        .signature
        .to_crypto_sig()
        .map_err(|reason| StateError::SignatureInvalid { reason })?;
    let signing_bytes = tx.signing_bytes(chain_id);
    verify_hybrid(&signing_bytes, &crypto_sig, &crypto_pk).map_err(|e| {
        StateError::SignatureInvalid {
            reason: e.to_string(),
        }
    })?;

    verify_opening(
        &PedersenCommitment(tx.fee_commitment.compressed_point.0),
        &PedersenOpening {
            value: tx.fee_amount,
            blinding: tx.fee_blinding.0,
        },
    )
    .map_err(|_| StateError::FeeCommitmentMismatch)?;

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

    let mut output_commitments = Vec::with_capacity(tx.outputs.len());
    for (idx, output) in tx.outputs.iter().enumerate() {
        if output.value_spark < indra_core::types::primitives::DUST_LIMIT_SPARK {
            return Err(StateError::InvariantViolation {
                message: "transaction output below dust limit",
            });
        }
        output_commitments.push(PedersenCommitment(output.commitment.compressed_point.0));
        let commitment_bytes = output.commitment.compressed_point.0;
        let proof_bytes = output.range_proof.as_slice();
        verify_range(&commitment_bytes, proof_bytes)
            .map_err(|_| StateError::RangeProofInvalid { index: idx })?;
    }

    verify_balance(
        &input_commitments,
        &output_commitments,
        &PedersenCommitment(tx.fee_commitment.compressed_point.0),
    )
    .map_err(|_| StateError::CommitmentBalanceInvalid)?;

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
        txn.insert_nullifier(input.nullifier)?;
    }

    // Create outputs: insert new UTXOs
    for (out_idx, output) in tx.outputs.iter().enumerate() {
        txn.insert_utxo(output.clone(), height, tx_index, out_idx as u32)?;
    }

    let burn_amount = tx.fee_amount / 2;
    let validator_amount = tx.fee_amount.saturating_sub(burn_amount);
    txn.apply_fee_accounting(burn_amount, validator_amount)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainState;
    use crate::governance::{
        GovernanceSnapshot, ProposalPhase, ProposalRecord, QueuedExecution, VoteCommit, VoteReveal,
        GOVERNANCE_DELIBERATION_EPOCHS,
    };
    use crate::validator::{ValidatorEntry, ValidatorSet, ValidatorStatus};
    use curve25519_dalek::scalar::Scalar;
    use indra_core::{
        codec::Encode,
        types::{
            block::{BlockHeaderV1, BlockV1},
            crypto::PQVoteSig,
            governance::{
                compute_proposal_id, governance_signing_domain, governance_vote_commit_hash,
                GovernableAction, GovernanceActionType, GovernanceOpV2, GovernancePayload,
            },
            primitives::{
                BLOCK_FORMAT_VERSION, DEFAULT_CHAIN_ID, DUST_LIMIT_SPARK, EPOCH_DURATION_BLOCKS,
                GENESIS_SUPPLY_SPARK, INITIAL_BASE_FEE_SPARK_PER_KB, MAX_GOV_OPS_PER_BLOCK,
                MAX_INPUTS, MAX_OUTPUTS, MAX_SLASHES_PER_BLOCK, MAX_STAKING_OPS_PER_BLOCK,
                MAX_TX_PER_BLOCK, MINIMUM_VALIDATOR_BOND_SPARK, SLASH_EVIDENCE_WINDOW_EPOCHS,
                STAKING_TX_IDX, TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES,
                UNBONDING_PERIOD_EPOCHS,
            },
            slash_membership::build_slash_membership_proof,
            slashing::{SlashEvidenceV1, SlashEvidenceV2},
            staking::{StakingOp, StakingOpBody},
            transaction::{InputV1, OutputV1, TransactionV1},
            vote::{VoteStep, VoteV1},
        },
        Bytes32, CommitmentV1, HybridPubKey, HybridSignature, ProtocolVersion, VariableBytes,
    };
    use indra_crypto::{
        commit, prove_range, sha256, ClassicalKeypair, HybridKeypair, PaymentBlindingNoteV1,
        PqKeypair, PAYMENT_VERSION_V1,
    };
    use rand::{rngs::StdRng, SeedableRng};
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

    fn make_mixed_test_keypair(
        classical_seed: [u8; 32],
        pq_seed: [u8; 32],
    ) -> (HybridPubKey, HybridKeypair) {
        let classical = ClassicalKeypair::from_seed(&classical_seed);
        let pq = PqKeypair::from_seed(&pq_seed).unwrap();
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
        let sig = keypair.sign(&tx.signing_bytes(chain_id)).unwrap();
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
        }
    }

    fn mandatory_note(owner_pubkey: &HybridPubKey, seed: u8) -> PaymentBlindingNoteV1 {
        PaymentBlindingNoteV1 {
            version: PAYMENT_VERSION_V1,
            owner_id: sha256(&owner_pubkey.classical_pk.0),
            payment_pubkey_hash: [seed; 32],
            sender_x25519_ephemeral_pk: [seed.wrapping_add(1); 32],
            ml_kem_1024_ciphertext: [seed.wrapping_add(2); 1568],
            note_nonce: [seed.wrapping_add(3); 32],
        }
    }

    fn staking_pubkey_from_keypair(keypair: &HybridKeypair) -> HybridPubKey {
        let public = keypair.public_key();
        HybridPubKey {
            classical_pk: Bytes32::from(public.classical.0),
            pq_pk: VariableBytes::from_slice(&public.pq.0).unwrap(),
        }
    }

    fn pubkey_to_id_for_test(pubkey: &HybridPubKey) -> Bytes32 {
        use indra_core::codec::Encode;
        Bytes32::from(indra_crypto::sha256(&pubkey.encode_to_vec()))
    }

    fn staking_delegator_id_for_test(pubkey: &HybridPubKey) -> Bytes32 {
        Bytes32::from(sha256(&pubkey.classical_pk.0))
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
        Bytes32::from(sha256(&pubkey.classical_pk.0))
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
                stake_spark,
                status: ValidatorStatus::Active,
                registered_epoch: 0,
                last_active_epoch: 0,
                pending_rewards: 0,
                rewards_last_epoch: 0,
                self_report_count: 0,
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
        let mut state = ChainState::new_genesis();
        install_governance_validator(&mut state, [0xF0; 32], MINIMUM_VALIDATOR_BOND_SPARK);
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
        sign_governance_op(&mut op, keypair, DEFAULT_CHAIN_ID);
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
        sign_governance_op(&mut op, keypair, DEFAULT_CHAIN_ID);
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
        sign_governance_op(&mut op, keypair, DEFAULT_CHAIN_ID);
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
        sign_governance_op(&mut op, keypair, DEFAULT_CHAIN_ID);
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
        sign_governance_op(&mut op, keypair, DEFAULT_CHAIN_ID);
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
        sign_governance_op(&mut op, keypair, DEFAULT_CHAIN_ID);
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
        let bond_utxo_id = state
            .utxos
            .insert(
                output_with_value(MINIMUM_VALIDATOR_BOND_SPARK, cold_pubkey.clone(), seed[0]),
                0,
                0,
                seed[0] as u32,
            )
            .unwrap();
        let mut op = StakingOp {
            body: StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                bond_utxo_id,
                validator_pubkey,
                vrf_pk: indra_crypto::VrfKeypair::from_seed(&seed).public_key(),
                bond_proof: Some(indra_core::types::staking::StakingBondProof {
                    committed_value_spark: MINIMUM_VALIDATOR_BOND_SPARK,
                    blinding_factor: Bytes32::from([seed[0]; 32]),
                }),
                cold_pubkey: Some(indra_core::types::crypto::ColdHybridPubKey {
                    classical_pk: cold_pubkey.classical_pk,
                    pq_pk: cold_pubkey.pq_pk,
                }),
                cold_signature: Some(dummy_sig()),
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
        *cold_signature = Some(HybridSignature {
            classical_sig: VariableBytes::from_slice(&cold_sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&cold_sig.pq.0).unwrap(),
        });
        (op, validator_id)
    }

    fn signed_delegate_op(
        state: &ChainState,
        validator_id: Bytes32,
        bond_utxo_id: Bytes32,
        delegator_pubkey: HybridPubKey,
        keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        let bond_proof = state.utxos.get(&bond_utxo_id).and_then(|entry| {
            (0u8..=u8::MAX).find_map(|seed| {
                let candidate = commit(entry.output.value_spark, &[seed; 32]);
                (candidate.0 == entry.output.commitment.compressed_point.0).then(|| {
                    indra_core::types::staking::StakingBondProof {
                        committed_value_spark: entry.output.value_spark,
                        blinding_factor: Bytes32::from([seed; 32]),
                    }
                })
            })
        });
        let mut op = StakingOp {
            body: StakingOpBody::Delegate {
                validator_id,
                bond_utxo_id,
                delegator_pubkey,
                bond_proof,
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
        _bond_utxo_id: Bytes32,
        delegator_pubkey: HybridPubKey,
        keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        let delegator_id = pubkey_to_id_for_test(&delegator_pubkey);
        let position = state
            .stake_positions
            .values()
            .find(|position| {
                position.validator_id == validator_id
                    && position.principal_owner_id == delegator_id
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
        bond_utxo_id: Bytes32,
        validator_pubkey: HybridPubKey,
        keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        let bond_proof = state.utxos.get(&bond_utxo_id).and_then(|entry| {
            (0u8..=u8::MAX).find_map(|seed| {
                let candidate = commit(entry.output.value_spark, &[seed; 32]);
                (candidate.0 == entry.output.commitment.compressed_point.0).then(|| {
                    indra_core::types::staking::StakingBondProof {
                        committed_value_spark: entry.output.value_spark,
                        blinding_factor: Bytes32::from([seed; 32]),
                    }
                })
            })
        });
        let mut op = StakingOp {
            body: StakingOpBody::SelfStake {
                bond_utxo_id,
                validator_pubkey,
                bond_proof,
                cold_authorization: None,
            },
            nonce,
            signature: dummy_sig(),
        };
        sign_staking_op(keypair, &state.chain_id, &mut op);
        op
    }

    fn active_validator(validator_id: Bytes32) -> ValidatorEntry {
        ValidatorEntry {
            validator_id,
            name: "test-validator".into(),
            hybrid_classical_pk: None,
            hybrid_pq_pk: None,
            vrf_pk: None,
            stake_spark: 1_000_000,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            pending_rewards: 0,
            rewards_last_epoch: 0,
            self_report_count: 0,
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
        }
    }

    fn slash_validator_state(seed: [u8; 32], stake: u64) -> (ChainState, Bytes32, HybridKeypair) {
        let classical = ClassicalKeypair::from_seed(&seed);
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let keypair = HybridKeypair::new(classical, pq);
        let public = keypair.public_key();
        let validator_id = Bytes32::from(indra_crypto::sha256(&public.classical.0));
        let mut state = ChainState::new_genesis();
        state
            .validators
            .upsert(ValidatorEntry {
                validator_id,
                name: "slash-validator".into(),
                hybrid_classical_pk: Some(public.classical.0),
                hybrid_pq_pk: Some(public.pq.0.to_vec()),
                vrf_pk: Some(indra_crypto::VrfKeypair::from_seed(&seed).public_key()),
                stake_spark: stake,
                status: ValidatorStatus::Active,
                registered_epoch: 0,
                last_active_epoch: 0,
                pending_rewards: 0,
                rewards_last_epoch: 0,
                self_report_count: 0,
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

    fn signed_vote(
        keypair: &HybridKeypair,
        validator_id: Bytes32,
        height: u64,
        round: u32,
        step: VoteStep,
        block_hash: Bytes32,
    ) -> VoteV1 {
        let signing_bytes = indra_core::types::vote_signing::vote_signing_bytes(
            height,
            round,
            step,
            &block_hash,
            &validator_id,
            None,
            DEFAULT_CHAIN_ID,
        );
        let sig = keypair.sign(&signing_bytes).unwrap();
        VoteV1 {
            height,
            round,
            step,
            block_hash,
            validator_id,
            election_result_hash: None,
            signature: HybridSignature {
                classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
                pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
            },
        }
    }

    fn derive_fee_blinding(
        input_blindings: &[[u8; 32]],
        output_blindings: &[[u8; 32]],
    ) -> [u8; 32] {
        let input_sum = input_blindings.iter().fold(Scalar::ZERO, |acc, blinding| {
            acc + Scalar::from_bytes_mod_order(*blinding)
        });
        let output_sum = output_blindings.iter().fold(Scalar::ZERO, |acc, blinding| {
            acc + Scalar::from_bytes_mod_order(*blinding)
        });
        (input_sum - output_sum).to_bytes()
    }

    fn dummy_output(byte: u8, owner_pubkey: HybridPubKey) -> OutputV1 {
        let value = TEST_INPUT_VALUE + byte as u64;
        output_with_value(value, owner_pubkey, byte)
    }

    fn output_with_value(value: u64, owner_pubkey: HybridPubKey, byte: u8) -> OutputV1 {
        let blinding = [byte; 32];
        let commitment = commit(value, &blinding);
        let mut rng = StdRng::from_seed([byte; 32]);
        let proof = prove_range(value, &blinding, &mut rng).unwrap();

        OutputV1 {
            value_spark: value,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from(commitment.0),
            },
            owner_pubkey,
            range_proof: VariableBytes::from_slice(&proof).unwrap(),
            lock_height: 0,
        }
    }

    /// Build a state that has one pre-existing UTXO ready to be spent.
    fn state_with_utxo() -> (ChainState, Bytes32, HybridKeypair, [u8; 32], u64) {
        let mut state = ChainState::new_genesis();
        install_governance_validator(&mut state, [0xF1; 32], MINIMUM_VALIDATOR_BOND_SPARK);
        let (owner_pubkey, keypair) = make_test_keypair([0x11; 32]);
        let output = dummy_output(0x01, owner_pubkey);
        let utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();
        state.finalize_genesis().unwrap();
        (state, utxo_id, keypair, [0x01; 32], TEST_INPUT_VALUE + 1)
    }

    fn make_tx(
        state: &ChainState,
        keypair: &HybridKeypair,
        utxo_id: Bytes32,
        input_value: u64,
        input_blinding: [u8; 32],
        nullifier: Bytes32,
    ) -> TransactionV1 {
        let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 10;
        let output_value = input_value - fee;
        let blinding = [0x02u8; 32];
        let fee_blinding = derive_fee_blinding(&[input_blinding], &[blinding]);
        let commitment = commit(output_value, &blinding);
        let fee_commitment = commit(fee, &fee_blinding);
        let mut rng = StdRng::from_seed([0x02u8; 32]);
        let proof = prove_range(output_value, &blinding, &mut rng).unwrap();
        let (owner_pubkey, _) = make_test_keypair([0x11; 32]);
        let mut tx = TransactionV1 {
            version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES),
            signature_module_id: 1,
            inputs: vec![InputV1 { utxo_id, nullifier }],
            outputs: vec![OutputV1 {
                value_spark: output_value,
                commitment: CommitmentV1 {
                    compressed_point: Bytes32::from(commitment.0),
                },
                owner_pubkey: owner_pubkey.clone(),
                range_proof: VariableBytes::from_slice(&proof).unwrap(),
                lock_height: 0,
            }],
            payment_notes: vec![mandatory_note(&owner_pubkey, 0x41)],
            fee_amount: fee,
            fee_blinding: Bytes32::from(fee_blinding),
            fee_commitment: CommitmentV1 {
                compressed_point: Bytes32::from(fee_commitment.0),
            },
            signature: dummy_sig(),
        };
        tx.signature = sign_transaction(keypair, &state.chain_id, &tx);
        tx
    }

    fn make_multi_io_tx(
        state: &ChainState,
        keypair: &HybridKeypair,
        inputs: &[(Bytes32, u64, [u8; 32], Bytes32)],
        output_count: usize,
    ) -> TransactionV1 {
        assert_eq!(inputs.len(), MAX_INPUTS);
        assert_eq!(output_count, MAX_OUTPUTS);
        let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 100;
        let input_total = inputs.iter().map(|(_, value, _, _)| *value).sum::<u64>();
        let spendable = input_total - fee;
        let base_output_value = spendable / output_count as u64;
        let mut output_blindings = Vec::new();
        let mut outputs = Vec::new();
        let (owner_pubkey, _) = make_test_keypair([0x5A; 32]);
        for idx in 0..output_count {
            let value = if idx + 1 == output_count {
                spendable - base_output_value * (output_count as u64 - 1)
            } else {
                base_output_value
            };
            let blinding = [0x80u8.saturating_add(idx as u8); 32];
            output_blindings.push(blinding);
            let commitment = commit(value, &blinding);
            let mut rng = StdRng::from_seed(blinding);
            let proof = prove_range(value, &blinding, &mut rng).unwrap();
            outputs.push(OutputV1 {
                value_spark: value,
                commitment: CommitmentV1 {
                    compressed_point: Bytes32::from(commitment.0),
                },
                owner_pubkey: owner_pubkey.clone(),
                range_proof: VariableBytes::from_slice(&proof).unwrap(),
                lock_height: 0,
            });
        }
        let input_blindings = inputs
            .iter()
            .map(|(_, _, blinding, _)| *blinding)
            .collect::<Vec<_>>();
        let fee_blinding = derive_fee_blinding(&input_blindings, &output_blindings);
        let fee_commitment = commit(fee, &fee_blinding);
        let mut tx = TransactionV1 {
            version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES),
            signature_module_id: 1,
            inputs: inputs
                .iter()
                .map(|(utxo_id, _, _, nullifier)| InputV1 {
                    utxo_id: *utxo_id,
                    nullifier: *nullifier,
                })
                .collect(),
            payment_notes: outputs
                .iter()
                .enumerate()
                .map(|(index, output)| mandatory_note(&output.owner_pubkey, index as u8))
                .collect(),
            outputs,
            fee_amount: fee,
            fee_blinding: Bytes32::from(fee_blinding),
            fee_commitment: CommitmentV1 {
                compressed_point: Bytes32::from(fee_commitment.0),
            },
            signature: dummy_sig(),
        };
        tx.signature = sign_transaction(keypair, &state.chain_id, &tx);
        tx
    }

    fn make_block(state: &ChainState, txs: Vec<TransactionV1>) -> BlockV1 {
        let height = state.height + 1;
        make_block_at_height(state, txs, height, 1_700_000_000 + height)
    }

    fn make_block_at_height(
        state: &ChainState,
        txs: Vec<TransactionV1>,
        height: u64,
        timestamp: u64,
    ) -> BlockV1 {
        let quorum_certificate = if height > 0 && height % EPOCH_DURATION_BLOCKS == 0 {
            let qc = QuorumCertificateV1 {
                height: height - 1,
                round: 0,
                block_hash: state.tip_hash,
                election_result_hash: None,
                signer_bitfield: [0u8; indra_core::types::qc::SIGNER_BITFIELD_BYTES],
                pq_signatures: vec![],
                classical_signatures: vec![],
            };
            VariableBytes::from_slice(&qc.encode_to_vec()).unwrap()
        } else {
            VariableBytes::from_slice(&[0u8; 32]).unwrap()
        };
        BlockV1 {
            header: BlockHeaderV1 {
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
                polc_round: indra_core::types::block::NO_POLC_ROUND,
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
                quorum_certificate,
                election_result_hash: None,
            },
            transactions: txs,
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            vrf_reveals: vec![],
        }
    }

    fn install_inert_gate_snapshot_fixture(state: &mut ChainState) {
        let (_, _, validator_id) =
            install_governance_validator(state, [0xD9; 32], MINIMUM_VALIDATOR_BOND_SPARK);
        state.validators.get_mut(&validator_id).unwrap().vrf_pk =
            Some(indra_crypto::VrfKeypair::from_seed(&[0xD9; 32]).public_key());
        let snapshot = state
            .build_consensus_snapshot(u64::MAX, u64::MAX - 1)
            .unwrap();
        state.reward_economic_snapshot =
            Some(state.build_reward_economic_snapshot(&snapshot).unwrap());
        state.consensus_snapshots = vec![snapshot];
        state.rebuild_state_commitment_v2(u64::MAX);
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
        state_root: Bytes32,
        validator_set_root: Bytes32,
        value_hash: Bytes32,
        epoch_record: Option<EpochRecord>,
    }

    fn clone_atomic_reference_apply_block(
        pre_state: &ChainState,
        block: &BlockV1,
        timestamp_secs: u64,
    ) -> StateResult<OracleOutcome> {
        let mut scratch = pre_state.clone();
        let epoch_record = apply_block(&mut scratch, block, timestamp_secs)?;
        let roots = crate::state_root::compute_state_roots(&scratch);
        Ok(OracleOutcome {
            state_root: roots.state_root,
            validator_set_root: roots.validator_set_root,
            value_hash: block.compute_value_hash(scratch.total_supply),
            state: scratch,
            epoch_record,
        })
    }

    fn undo_apply_block_outcome(
        pre_state: &ChainState,
        block: &BlockV1,
        timestamp_secs: u64,
    ) -> StateResult<OracleOutcome> {
        let mut state = pre_state.clone();
        let epoch_record = apply_block(&mut state, block, timestamp_secs)?;
        let roots = crate::state_root::compute_state_roots(&state);
        Ok(OracleOutcome {
            state_root: roots.state_root,
            validator_set_root: roots.validator_set_root,
            value_hash: block.compute_value_hash(state.total_supply),
            state,
            epoch_record,
        })
    }

    fn assert_oracle_matches(pre_state: &ChainState, block: &BlockV1, timestamp_secs: u64) {
        let reference = clone_atomic_reference_apply_block(pre_state, block, timestamp_secs)
            .expect("clone-atomic reference apply must succeed");
        let candidate = undo_apply_block_outcome(pre_state, block, timestamp_secs)
            .expect("undo apply must succeed");
        assert_eq!(
            candidate.state.encode_to_vec(),
            reference.state.encode_to_vec()
        );
        assert_eq!(candidate.state_root, reference.state_root);
        assert_eq!(candidate.validator_set_root, reference.validator_set_root);
        assert_eq!(candidate.value_hash, reference.value_hash);
        assert_eq!(candidate.epoch_record, reference.epoch_record);
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

    fn install_reveal_phase_governance_proposal(
        state: &mut ChainState,
        proposal_id: Bytes32,
        from_validator: Bytes32,
        to_validator: Bytes32,
    ) {
        let (proposer_pubkey, _, proposer_id) =
            install_governance_validator(state, [proposal_id.0[0]; 32], 100_000);
        let mut proposal = test_proposal_record(
            proposal_id,
            proposer_id,
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


    fn governance_proposal_state(
        phase: ProposalPhase,
    ) -> (ChainState, HybridPubKey, HybridKeypair, Bytes32, Bytes32) {
        let mut state = canonical_test_genesis();
        state.governance.params.proposal_deposit_spark = 1_000;
        let (proposer_pubkey, proposer_keypair, proposer_id) =
            install_governance_validator(&mut state, [0x91; 32], 100_000);
        let snapshot = state.build_genesis_consensus_snapshot().unwrap();
        state.reward_economic_snapshot =
            Some(state.build_reward_economic_snapshot(&snapshot).unwrap());
        state.slash_membership_roots = vec![
            indra_core::types::slash_membership::SlashMembershipRootRecord {
                activation_height: 1,
                membership_root:
                    indra_core::types::slash_membership::compute_slash_membership_root(&snapshot)
                        .unwrap(),
            },
        ];
        state.consensus_snapshots = vec![snapshot];
        state.rebuild_state_commitment_v2(0);
        let action = GovernableAction::SetMinDelegationSpark { value: 100_000 };
        let proposal_id = compute_proposal_id(proposer_id, &action, 0, DEFAULT_CHAIN_ID);
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
        (
            state,
            proposer_pubkey,
            proposer_keypair,
            proposer_id,
            proposal_id,
        )
    }

    fn assert_all_failpoints_roll_back(state: &ChainState, block: &BlockV1) -> usize {
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

    fn empty_block_at(state: &ChainState, height: u64, timestamp: u64) -> BlockV1 {
        BlockV1 {
            header: BlockHeaderV1 {
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
                polc_round: indra_core::types::block::NO_POLC_ROUND,
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
                quorum_certificate: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
                election_result_hash: None,
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            vrf_reveals: vec![],
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────

    #[test]
    fn project_block_for_roots_restores_state_on_success() {
        let mut state = canonical_test_genesis();
        install_inert_gate_snapshot_fixture(&mut state);
        state.height = u64::MAX - 1;
        state.tip_hash = Bytes32::ZERO;
        state.state_commitment_v2 = None;
        let original = state.clone();
        let block = empty_block_at(&state, u64::MAX, 0);

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
        state.height = u64::MAX - 1;
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

        let success_block = empty_block_at(&state, u64::MAX, 0);
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
        let tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            value,
            blinding,
            Bytes32::from([0xC1; 32]),
        );
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
    fn state_txn_rolls_back_after_each_transaction_mutation_failpoint() {
        let (state, utxo_id, keypair, blinding, value) = state_with_utxo();
        let tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            value,
            blinding,
            Bytes32::from([0xA1; 32]),
        );
        let block = make_block(&state, vec![tx]);

        let mutation_count = assert_all_failpoints_roll_back(&state, &block);
        assert!(
            mutation_count >= 6,
            "transaction block should exercise several undo-recorded mutations, got {mutation_count}"
        );
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
        state.height = u64::MAX - 1;
        state.tip_hash = Bytes32::ZERO;
        let block = BlockV1 {
            header: BlockHeaderV1 {
                protocol_version: ProtocolVersion(BLOCK_FORMAT_VERSION),
                height: u64::MAX,
                prev_hash: Bytes32::ZERO,
                timestamp: 0,
                state_root: Bytes32::ZERO,
                validator_set_root: Bytes32::ZERO,
                mempool_set_root: Bytes32::ZERO,
                value_hash: Bytes32::ZERO,
                base_fee: state.base_fee,
                proposer_round: 0,
                polc_round: indra_core::types::block::NO_POLC_ROUND,
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
                quorum_certificate: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
                election_result_hash: None,
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            vrf_reveals: vec![],
        };

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
        assert!(err
            .to_string()
            .contains("state transaction failpoint injected after mutation"));
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
    fn boundary_qc_activity_uses_certified_parent_epoch_post_gate() {
        let validator_id = Bytes32::from([0xA7; 32]);
        let mut state = canonical_test_genesis();
        state
            .validators
            .upsert(ValidatorEntry {
                validator_id,
                name: "activity".into(),
                hybrid_classical_pk: None,
                hybrid_pq_pk: None,
                vrf_pk: None,
                stake_spark: MINIMUM_VALIDATOR_BOND_SPARK,
                status: ValidatorStatus::Active,
                registered_epoch: 0,
                last_active_epoch: 99,
                pending_rewards: 0,
                rewards_last_epoch: 0,
                self_report_count: 0,
                commission_bps: 0,
                pending_commission_bps: None,
                pending_commission_effective_epoch: None,
                min_delegation_spark: 0,
                auto_delegate_to: None,
                network_addr: None,
                network_addr_last_updated_epoch: None,
                cold_hybrid_classical_pk: None,
                cold_hybrid_pq_pk: None,
                cold_key_version: 0,
                cold_nonce: 0,
            })
            .unwrap();
        let qc = QuorumCertificateV1 {
            height: 299,
            round: 0,
            block_hash: Bytes32::from([0x29; 32]),
            election_result_hash: None,
            signer_bitfield: [0u8; indra_core::types::qc::SIGNER_BITFIELD_BYTES],
            pq_signatures: vec![PQVoteSig {
                validator_id,
                pq_sig: VariableBytes::from_slice(&[1]).unwrap(),
            }],
            classical_signatures: vec![],
        };
        let mut block = make_block_at_height(&state, vec![], 300, 0);
        block.header.quorum_certificate = VariableBytes::from_slice(&qc.encode_to_vec()).unwrap();
        let context = crate::epoch::EpochTransitionContext::new(300, 299).unwrap();
        update_last_active_epoch_from_block_qc(&mut state, &block, Some(&context)).unwrap();
        assert_eq!(
            state
                .validators
                .get(&validator_id)
                .unwrap()
                .last_active_epoch,
            0
        );

        state
            .validators
            .get_mut(&validator_id)
            .unwrap()
            .last_active_epoch = 99;
        update_last_active_epoch_from_block_qc(&mut state, &block, None).unwrap();
        assert_eq!(
            state
                .validators
                .get(&validator_id)
                .unwrap()
                .last_active_epoch,
            1
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
        let nullifier = Bytes32::from([0x99u8; 32]);
        let tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            input_value,
            input_blinding,
            nullifier,
        );
        let block = make_block(&state, vec![tx]);
        apply_block(&mut state, &block, 0).unwrap();

        // Input UTXO must be gone
        assert!(!state.utxos.contains(&utxo_id));
        // Output UTXO must exist
        assert_eq!(state.utxos.len(), 1);
        // Nullifier must be recorded
        assert!(state.nullifiers.contains(&nullifier));
    }

    #[test]
    fn apply_transaction_fails_loudly_if_utxo_already_spent() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        let tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            input_value,
            input_blinding,
            Bytes32::from([0x9A; 32]),
        );
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
    fn double_spend_rejected() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        let nullifier = Bytes32::from([0xAAu8; 32]);
        let tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            input_value,
            input_blinding,
            nullifier,
        );
        let block1 = make_block(&state, vec![tx.clone()]);
        apply_block(&mut state, &block1, 0).unwrap();

        // Re-insert the output so the utxo_id exists again
        // but the nullifier is already spent
        let output = dummy_output(0x01, make_test_keypair([0x11; 32]).0);
        state.utxos.insert(output, 0, 0, 0).unwrap();

        let block2 = make_block(
            &state,
            vec![make_tx(
                &state,
                &keypair,
                utxo_id,
                input_value,
                input_blinding,
                nullifier,
            )],
        );
        assert_eq!(
            apply_block(&mut state, &block2, 0),
            Err(StateError::DoubleSpend)
        );
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
        let nullifier = Bytes32::from([0xADu8; 32]);
        let (_, keypair) = make_test_keypair([0x22; 32]);
        let tx = make_tx(
            &state,
            &keypair,
            fake_utxo,
            TEST_INPUT_VALUE + 1,
            [0x01; 32],
            nullifier,
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
        let mut tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            input_value,
            input_blinding,
            Bytes32::from([0x01u8; 32]),
        );
        tx.fee_amount = 0; // too low
        let fee_commitment = commit(tx.fee_amount, &tx.fee_blinding.0);
        tx.fee_commitment = CommitmentV1 {
            compressed_point: Bytes32::from(fee_commitment.0),
        };
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
        let tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            input_value,
            input_blinding,
            Bytes32::from([0x11u8; 32]),
        );
        let block = make_block(&state, vec![tx]);
        apply_block(&mut state, &block, 0).unwrap();
        assert_eq!(state.total_supply, initial_supply - (fee / 2));
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
        let nullifier = Bytes32::from([0x55u8; 32]);
        let tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            input_value,
            input_blinding,
            nullifier,
        );
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

        let tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            TEST_INPUT_VALUE + 1,
            [0x01; 32],
            Bytes32::from([0x01u8; 32]),
        );
        let block = make_block(&state, vec![tx]); // height will be 1 < 100
        assert!(matches!(
            apply_block(&mut state, &block, 0),
            Err(StateError::OutputLocked { .. })
        ));
    }

    #[test]
    fn valid_signature_accepted() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        let tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            input_value,
            input_blinding,
            Bytes32::from([0x44; 32]),
        );
        let block = make_block(&state, vec![tx]);
        apply_block(&mut state, &block, 0).unwrap();
        assert_eq!(state.height, 1);
    }

    #[test]
    fn wrong_signature_rejected() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        let mut tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            input_value,
            input_blinding,
            Bytes32::from([0x45; 32]),
        );
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
        let mut tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            input_value,
            input_blinding,
            Bytes32::from([0x46; 32]),
        );
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
        let mut tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            input_value,
            input_blinding,
            Bytes32::from([0x47; 32]),
        );
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
        let mut tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            input_value,
            input_blinding,
            Bytes32::from([0x48; 32]),
        );
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
        let mut tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            input_value,
            input_blinding,
            Bytes32::from([0x49; 32]),
        );
        tx.signature_module_id = 7;
        let block = make_block(&state, vec![tx]);
        assert_eq!(
            apply_block(&mut state, &block, 0),
            Err(StateError::UnsupportedSignatureModule { module_id: 7 })
        );
    }

    #[test]
    fn fee_commitment_mismatch_rejected() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        let mut tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            input_value,
            input_blinding,
            Bytes32::from([0x4A; 32]),
        );
        tx.fee_commitment = CommitmentV1 {
            compressed_point: Bytes32::from([0x77; 32]),
        };
        tx.signature = sign_transaction(&keypair, &state.chain_id, &tx);
        let block = make_block(&state, vec![tx]);
        assert_eq!(
            apply_block(&mut state, &block, 0),
            Err(StateError::FeeCommitmentMismatch)
        );
    }

    #[test]
    fn commitment_balance_mismatch_rejected() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        let mut tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            input_value,
            input_blinding,
            Bytes32::from([0x4B; 32]),
        );
        tx.fee_blinding = Bytes32::from([0x09; 32]);
        let fee_commitment = commit(tx.fee_amount, &tx.fee_blinding.0);
        tx.fee_commitment = CommitmentV1 {
            compressed_point: Bytes32::from(fee_commitment.0),
        };
        tx.signature = sign_transaction(&keypair, &state.chain_id, &tx);
        let block = make_block(&state, vec![tx]);
        assert_eq!(
            apply_block(&mut state, &block, 0),
            Err(StateError::CommitmentBalanceInvalid)
        );
    }

    #[test]
    fn membership_proven_slash_uses_bootstrap_snapshot_and_historical_keys() {
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
        let current = state.validators.get_mut(&validator_id).unwrap();
        current.hybrid_classical_pk = None;
        current.hybrid_pq_pk = None;

        apply_slash_v2_at_height_with_accounting(&mut state, &evidence, &chain_id, u64::MAX, None)
            .unwrap();

        assert_eq!(
            state.validators.get(&validator_id).unwrap().stake_spark,
            950_000
        );
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
        let timing = indra_core::types::stake_position::UnbondingTimingV1::height_precise(
            u64::MAX,
        )
        .unwrap();
        let creation_op_id = Bytes32::from([0xD4; 32]);
        let provisional_id = indra_core::types::stake_position::derive_tranche_id(
            position.position_id,
            creation_op_id,
            0,
            timing,
            1_000_000,
        );
        let blinding = indra_crypto::derive_tranche_source_blinding_v1(
            &indra_crypto::TrancheSourceBlindingInputsV1 {
                chain_id: state.chain_id.as_bytes(),
                position_id: position.position_id.0,
                tranche_id: provisional_id.0,
                principal_spark: 1_000_000,
                start_height: u64::MAX,
                creation_op_id: creation_op_id.0,
            },
        )
        .unwrap();
        let tranche = indra_core::types::stake_position::UnbondingTrancheV1::new(
            position.position_id,
            1_000_000,
            indra_crypto::commit(1_000_000, &blinding),
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
        validator.cold_hybrid_pq_pk = validator.hybrid_pq_pk.clone().map(|pq| pq.try_into().unwrap());
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
                retained_position_ids: vec![position.position_id],
                retained_tranche_ids: vec![tranche.tranche_id],
            },
        );
        let tranche_count_before = state.unbonding_tranches.len();
        let chain_id = state.chain_id.clone();
        apply_slash_v2_at_height_with_accounting(&mut state, &evidence, &chain_id, u64::MAX, None)
            .unwrap();
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

        let mut already_evicted = state.clone();
        already_evicted.applied_slash_hashes = crate::persistent::PersistentOrdSet::new();
        already_evicted
            .evicted_validator_tombstones
            .get(&validator_id)
            .cloned()
            .map(|mut tombstone| {
                tombstone.eviction_height = u64::MAX - 1;
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
        assert!(apply_slash_v2_at_height_with_accounting(
            &mut state,
            &evidence,
            &chain_id,
            u64::MAX,
            None,
        )
        .is_err());

        state.consensus_snapshots = vec![snapshot];
        state.height = u64::MAX;
        state.slash_membership_roots = vec![SlashMembershipRootRecord {
            activation_height: u64::MAX,
            membership_root: Bytes32::from([0xEE; 32]),
        }];
        assert!(apply_slash_v2_at_height_with_accounting(
            &mut state,
            &evidence,
            &chain_id,
            u64::MAX,
            None,
        )
        .is_err());
    }

    #[test]
    fn slash_reporter_identity_multiple_match_returns_none() {
        let proposer_id = Bytes32::from([0xD1; 32]);
        let state = canonical_test_genesis();
        let mut block = make_block(&state, vec![]);
        block.header.proposer_vrf_output = Bytes32::from([0x4F; 32]);
        block.header.election_result_hash = Some(
            VrfElectionResult {
                height: block.header.height,
                round: block.header.proposer_round,
                elected_validator_id: proposer_id,
                elected_vrf_output: block.header.proposer_vrf_output,
                fallback_used: false,
                reveal_set_commitment: Bytes32::ZERO,
            }
            .hash(),
        );

        assert_eq!(
            slash_reporter_validator_id_from_candidate_ids([proposer_id, proposer_id], &block),
            None,
            "ambiguous candidate matches must preserve the prior uniqueness-required behavior"
        );
    }

    #[test]
    fn slash_reward_utxo_blinding_is_deterministic() {
        let hash = Bytes32::from([0xC7; 32]);
        assert_eq!(
            derive_slash_reward_blinding(&hash, 123),
            derive_slash_reward_blinding(&hash, 123)
        );
        assert_ne!(
            derive_slash_reward_blinding(&hash, 123),
            derive_slash_reward_blinding(&hash, 124)
        );
    }
}
