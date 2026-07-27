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
            block_protocol_version_for_height, bps_of, delegator_identity_registry_active,
            overflow_fix_active, payment_blinding_active, vrf_commit_reveal_election_active,
            Bytes32, HARD_CAP_SPARK, MAX_BLOCK_SIZE_BYTES, MAX_GOV_OPS_PER_BLOCK,
            MAX_STAKING_OPS_PER_BLOCK, MAX_TX_PER_BLOCK, PROTOCOL_VERSION,
            SLASH_EVIDENCE_WINDOW_EPOCHS, STAKING_TX_IDX,
            TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES, UNBONDING_PERIOD_EPOCHS,
        },
        qc::QuorumCertificateV1,
        slashing::SlashEvidenceV1,
        staking::StakingOpBody,
        transaction::{OutputV1, TransactionV1},
        vote::VoteV1,
        vrf_election::VrfElectionResult,
    },
    EpochRecord,
};
use indra_crypto::{
    verify_balance, verify_hybrid, verify_opening, verify_range, vrf_verify, PedersenCommitment,
    PedersenOpening, VrfOutput, VrfProof,
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

/// Apply slash evidence to chain state.
///
/// Verification is fail-fast and performs no state mutation until all checks pass.
pub fn apply_slash(
    state: &mut ChainState,
    evidence: &SlashEvidenceV1,
    chain_id: &str,
) -> StateResult<()> {
    apply_slash_at_height(state, evidence, chain_id, state.height, None)
}

/// Apply slash evidence using the arithmetic rules active at `height`.
pub fn apply_slash_at_height(
    state: &mut ChainState,
    evidence: &SlashEvidenceV1,
    chain_id: &str,
    height: u64,
    reporter_pubkey: Option<&HybridPubKey>,
) -> StateResult<()> {
    apply_slash_at_height_with_accounting(state, evidence, chain_id, height, reporter_pubkey)
        .map(|_| ())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SlashAccounting {
    slash_amount: u64,
    burned: u64,
    reporter_reward: u64,
}

fn apply_slash_at_height_with_accounting(
    state: &mut ChainState,
    evidence: &SlashEvidenceV1,
    chain_id: &str,
    height: u64,
    reporter_pubkey: Option<&HybridPubKey>,
) -> StateResult<SlashAccounting> {
    use crate::ValidatorStatus;
    use indra_core::types::{
        primitives::{DUST_LIMIT_SPARK, SLASH_REPORTER_REWARD_BPS},
        vote::VoteStep,
    };

    let evidence_hash = compute_slash_evidence_hash(evidence);
    if state.applied_slash_hashes.contains(&evidence_hash) {
        return Err(StateError::SlashAlreadyApplied);
    }

    let validator_id = evidence.validator_id;

    let (classical_pk, pq_pk_bytes) = {
        let v = state
            .validators
            .get(&validator_id)
            .ok_or(StateError::ValidatorNotFound)?;
        let cpk = v
            .hybrid_classical_pk
            .ok_or_else(|| StateError::InvalidSlashEvidence {
                reason: "validator has no classical public key".into(),
            })?;
        let ppk = v
            .hybrid_pq_pk
            .clone()
            .ok_or_else(|| StateError::InvalidSlashEvidence {
                reason: "validator has no PQ public key".into(),
            })?;
        (cpk, ppk)
    };

    {
        let v = state.validators.get(&validator_id).unwrap();
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

    let bps = |amount, rate| {
        if overflow_fix_active(height) {
            bps_of(amount, rate)
        } else {
            amount.saturating_mul(rate as u64) / 10_000
        }
    };

    let bond_ids: Vec<Bytes32> = state
        .staked_bonds
        .values()
        .filter(|bond| {
            if bond.validator_id != validator_id || bond.delegator_id != validator_id {
                return false;
            }
            match bond.unbonding_end_epoch {
                None => true,
                Some(end_epoch) => {
                    let unbonding_start = end_epoch.saturating_sub(UNBONDING_PERIOD_EPOCHS);
                    unbonding_start > infraction_epoch
                }
            }
        })
        .map(|bond| bond.utxo_id)
        .collect();
    let slashable_bond_stake = bond_ids.iter().fold(0u64, |acc, bond_id| {
        acc.saturating_add(
            state
                .staked_bonds
                .get(bond_id)
                .map(|bond| bond.amount_spark)
                .unwrap_or(0),
        )
    });
    let current_stake = state
        .validators
        .get(&validator_id)
        .map(|v| v.stake_spark)
        .unwrap_or(0);
    let slash_base = slashable_bond_stake.max(current_stake);
    let slash_amount = bps(slash_base, slash_bps);
    let potential_reporter_reward = bps(slash_amount, SLASH_REPORTER_REWARD_BPS);

    let mut total_bond_slashed: u64 = 0;
    let mut active_bond_slashed: u64 = 0;
    for bond_id in &bond_ids {
        let updated_bond = if let Some(mut bond) = state.staked_bonds.remove(bond_id) {
            let bond_slash = bps(bond.amount_spark, slash_bps);
            if bond.unbonding_end_epoch.is_none() {
                active_bond_slashed = active_bond_slashed.saturating_add(bond_slash);
            }
            bond.amount_spark = bond.amount_spark.saturating_sub(bond_slash);
            total_bond_slashed = total_bond_slashed.saturating_add(bond_slash);
            state.staked_bonds.insert(*bond_id, bond.clone());
            Some(bond)
        } else {
            None
        };
        if let (Some(commitment), Some(bond)) = (state.state_commitment_v2.as_mut(), updated_bond) {
            commitment.put_staked_bond(bond_id, &bond);
        }
    }

    let mut updated_validator = None;
    if let Some(v) = state.validators.get_mut(&validator_id) {
        let stake_slash = if slashable_bond_stake > 0 {
            active_bond_slashed
        } else {
            slash_amount
        };
        v.stake_spark = v.stake_spark.saturating_sub(stake_slash);
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
        total_bond_slashed,
        reporter_reward,
    );

    Ok(SlashAccounting {
        slash_amount,
        burned,
        reporter_reward,
    })
}

/// Compute the canonical slash-evidence hash used for deduplication.
pub fn compute_slash_evidence_hash(evidence: &SlashEvidenceV1) -> Bytes32 {
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

fn slash_reporter_pubkey_for_block(state: &ChainState, block: &BlockV1) -> Option<HybridPubKey> {
    let proposer_id = slash_reporter_validator_id_for_block(state, block)?;
    let validator = state.validators.get(&proposer_id)?;
    Some(HybridPubKey {
        classical_pk: Bytes32::from(validator.hybrid_classical_pk?),
        pq_pk: indra_core::VariableBytes::from_slice(validator.hybrid_pq_pk.as_deref()?).ok()?,
    })
}

fn slash_reporter_validator_id_for_block(state: &ChainState, block: &BlockV1) -> Option<Bytes32> {
    if !vrf_commit_reveal_election_active(block.header.height) {
        // Legacy pre-commit-reveal path: there is no QC-attested
        // election_result_hash to recover the proposer from, so retain the
        // original live VRF proof verification for alternate/future chain
        // configurations. With VRF_COMMIT_REVEAL_ELECTION_HEIGHT = 0 this
        // branch is unreachable on the current chain configuration.
        return proposer_id_from_vrf_proof(state, block);
    }

    slash_reporter_validator_id_from_election_hash(state, block)
}

fn slash_reporter_validator_id_from_election_hash(
    state: &ChainState,
    block: &BlockV1,
) -> Option<Bytes32> {
    slash_reporter_validator_id_from_candidate_ids(
        state
            .validators
            .active_validators()
            .map(|validator| validator.validator_id),
        block,
    )
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

fn proposer_id_from_vrf_proof(state: &ChainState, block: &BlockV1) -> Option<Bytes32> {
    let proof_bytes = block.header.proposer_vrf_proof.as_slice();
    if proof_bytes.is_empty() || block.header.proposer_vrf_output == Bytes32::ZERO {
        return None;
    }
    let epoch_seed = Bytes32::from(indra_crypto::sha256(&block.header.prev_hash.0));
    let vrf_input = compute_vrf_input_for_block(
        &epoch_seed,
        block.header.height,
        block.header.proposer_round,
    );
    let proof = VrfProof(proof_bytes.to_vec());
    let output = VrfOutput(block.header.proposer_vrf_output.0);
    let mut matches = state
        .validators
        .active_validators()
        .filter_map(|validator| {
            let vrf_pk = validator.vrf_pk?;
            vrf_verify(&vrf_pk, &vrf_input, &output, &proof)
                .is_ok()
                .then_some(validator.validator_id)
        });
    let proposer_id = matches.next()?;
    matches.next().is_none().then_some(proposer_id)
}

fn compute_vrf_input_for_block(epoch_seed: &Bytes32, height: u64, round: u32) -> [u8; 32] {
    use indra_crypto::hash::domains::VRF_INPUT;
    let mut input = Vec::new();
    input.extend_from_slice(VRF_INPUT);
    input.extend_from_slice(&height.to_le_bytes());
    input.extend_from_slice(&round.to_le_bytes());
    input.extend_from_slice(&epoch_seed.0[..8]);
    indra_crypto::sha256(&input)
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

    let state = txn.state();
    validate_block_header(state, block)?;

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
        if !seen_slash_hashes.insert(compute_slash_evidence_hash(evidence)) {
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
        let current_epoch = epoch_for_height(block.header.height);
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
        let reporter_pubkey = slash_reporter_pubkey_for_block(&shadow, block);
        for evidence in &block.slashing_evidence {
            apply_slash_at_height(
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
        if delegator_identity_registry_active(block.header.height) {
            txn.snapshot_delegator_identity_scope();
        }
        if matches!(op.body, StakingOpBody::RegisterPaymentKey { .. }) {
            txn.snapshot_payment_identity_scope();
        }
        apply_staking_op(txn.state_mut(), op, &chain_id, block.header.height).map_err(|_| {
            StateError::InvariantViolation {
                message: "staking op failed on real state after shadow validation",
            }
        })?;
        txn.after_mutation()?;
    }

    let current_epoch = epoch_for_height(block.header.height);
    let chain_id = txn.state().chain_id.clone();
    for op in &block.governance_ops {
        txn.snapshot_governance_scope();
        if delegator_identity_registry_active(block.header.height) {
            txn.snapshot_delegator_identity_scope();
        }
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
    let reporter_pubkey = slash_reporter_pubkey_for_block(txn.state(), block);
    for evidence in &block.slashing_evidence {
        txn.snapshot_slashing_scope();
        let accounting = apply_slash_at_height_with_accounting(
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

    // Apply epoch transition if this is the last block of an epoch
    let epoch_record = if is_epoch_boundary(txn.state().height) {
        let epoch = epoch_for_height(txn.state().height);
        txn.snapshot_epoch_scope();
        Some(crate::epoch::apply_epoch_transition_at_height(
            txn.state_mut(),
            epoch,
            timestamp_secs,
            block.header.height,
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

    txn.snapshot_validator_activity_scope();
    update_last_active_epoch_from_block_qc(txn.state_mut(), block);
    txn.after_mutation()?;

    Ok(epoch_record)
}

/// Update validator liveness from the QC embedded in the applied block.
///
/// This is consensus state because `last_active_epoch` is committed in the
/// validator-set root. Keeping this mutation inside `apply_block` ensures live
/// import, sync import, snapshot replay, and block-production projection all
/// execute the same state transition.
fn update_last_active_epoch_from_block_qc(state: &mut ChainState, block: &BlockV1) {
    if block.header.quorum_certificate.as_slice().is_empty() {
        return;
    }

    let mut reader = ByteReader::new(block.header.quorum_certificate.as_slice());
    let Ok(qc) = QuorumCertificateV1::decode(&mut reader) else {
        return;
    };

    let current_epoch = epoch_for_height(block.header.height);
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
}

/// Validate block-level invariants (does not touch state).
fn validate_block_header(state: &ChainState, block: &BlockV1) -> StateResult<()> {
    // Protocol version
    let expected_protocol_version = block_protocol_version_for_height(block.header.height);
    if block.header.protocol_version.0 != expected_protocol_version {
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
    match tx.version.0 {
        PROTOCOL_VERSION => {
            if !tx.payment_notes.is_empty() {
                return Err(StateError::InvariantViolation {
                    message: "v1 transaction cannot carry payment notes",
                });
            }
        }
        TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES => {
            if !payment_blinding_active(current_height) {
                return Err(StateError::UnsupportedTxVersion {
                    version: tx.version.0,
                });
            }
            if tx.payment_notes.len() != tx.outputs.len() {
                return Err(StateError::InvariantViolation {
                    message: "payment_notes length must equal outputs length",
                });
            }
        }
        version => return Err(StateError::UnsupportedTxVersion { version }),
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
    };
    use crate::validator::{StakeBondEntry, ValidatorEntry, ValidatorSet, ValidatorStatus};
    use curve25519_dalek::scalar::Scalar;
    use indra_core::{
        codec::Encode,
        types::{
            block::{BlockHeaderV1, BlockV1},
            governance::{
                compute_proposal_id, governance_signing_domain, governance_vote_commit_hash,
                GovernableAction, GovernanceActionType, GovernanceOpV2, GovernancePayload,
            },
            primitives::{
                hard_forks::{DELEGATOR_IDENTITY_REGISTRY_HEIGHT, PAYMENT_BLINDING_HEIGHT},
                DEFAULT_CHAIN_ID, DUST_LIMIT_SPARK, EPOCH_DURATION_BLOCKS, GENESIS_SUPPLY_SPARK,
                INITIAL_BASE_FEE_SPARK_PER_KB, MAX_GOV_OPS_PER_BLOCK, MAX_INPUTS, MAX_OUTPUTS,
                MAX_SLASHES_PER_BLOCK, MAX_STAKING_OPS_PER_BLOCK, MAX_TX_PER_BLOCK,
                MINIMUM_VALIDATOR_BOND_SPARK, SLASH_EVIDENCE_WINDOW_EPOCHS, STAKING_TX_IDX,
                TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES, UNBONDING_PERIOD_EPOCHS,
            },
            slashing::SlashEvidenceV1,
            staking::{StakingOp, StakingOpBody},
            transaction::{InputV1, OutputV1, TransactionV1},
            vote::{VoteStep, VoteV1},
        },
        Bytes32, CommitmentV1, HybridPubKey, HybridSignature, ProtocolVersion, VariableBytes,
    };
    use indra_crypto::{
        commit, prove_range, sha256, ClassicalKeypair, HybridKeypair, PaymentBlindingNoteV1,
        PaymentKeypairV1, PaymentPubKeyV1, PqKeypair, PAYMENT_VERSION_V1,
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

    fn pubkey_to_id_for_test(pubkey: &HybridPubKey) -> Bytes32 {
        use indra_core::codec::Encode;
        Bytes32::from(indra_crypto::sha256(&pubkey.encode_to_vec()))
    }

    fn staking_delegator_id_for_test(pubkey: &HybridPubKey) -> Bytes32 {
        Bytes32::from(sha256(&pubkey.classical_pk.0))
    }

    fn sign_staking_op(keypair: &HybridKeypair, chain_id: &str, op: &mut StakingOp) {
        let sig = keypair.sign(&op.signing_bytes(chain_id)).unwrap();
        op.signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
        };
    }

    fn payment_pubkey(seed: u8) -> PaymentPubKeyV1 {
        PaymentKeypairV1 {
            version: PAYMENT_VERSION_V1,
            x25519_sk: [seed; 32],
            ml_kem_1024_seed: [seed.wrapping_add(1); 64],
        }
        .public_key()
    }

    fn payment_note(seed: u8) -> PaymentBlindingNoteV1 {
        PaymentBlindingNoteV1 {
            version: PAYMENT_VERSION_V1,
            owner_id: [seed; 32],
            payment_pubkey_hash: [seed.wrapping_add(1); 32],
            sender_x25519_ephemeral_pk: [seed.wrapping_add(2); 32],
            ml_kem_1024_ciphertext: [seed.wrapping_add(3); 1568],
            note_nonce: [seed.wrapping_add(4); 32],
        }
    }

    fn set_v2_payment_notes(
        tx: &mut TransactionV1,
        keypair: &HybridKeypair,
        chain_id: &str,
        payment_notes: Vec<Option<PaymentBlindingNoteV1>>,
    ) {
        tx.version = ProtocolVersion(TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES);
        tx.payment_notes = payment_notes;
        tx.signature = sign_transaction(keypair, chain_id, tx);
    }

    fn staking_pubkey_from_keypair(keypair: &HybridKeypair) -> HybridPubKey {
        let public = keypair.public_key();
        HybridPubKey {
            classical_pk: Bytes32::from(public.classical.0),
            pq_pk: VariableBytes::from_slice(&public.pq.0).unwrap(),
        }
    }

    fn signed_register_payment_key_op(
        state: &ChainState,
        owner_keypair: &HybridKeypair,
        payment_pubkey: PaymentPubKeyV1,
        nonce: u64,
    ) -> StakingOp {
        let mut op = StakingOp {
            body: StakingOpBody::RegisterPaymentKey {
                owner_pubkey: staking_pubkey_from_keypair(owner_keypair),
                payment_pubkey,
                cold_authorization: None,
            },
            nonce,
            signature: dummy_sig(),
        };
        sign_staking_op(owner_keypair, &state.chain_id, &mut op);
        op
    }

    fn governance_validator_id(pubkey: &HybridPubKey) -> Bytes32 {
        Bytes32::from(sha256(&pubkey.classical_pk.0))
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
                vrf_pk: Some(seed),
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
                cold_hybrid_classical_pk: None,
                cold_hybrid_pq_pk: None,
                cold_key_version: 0,
                cold_key_status: crate::validator::ColdKeyStatus::Unenrolled,
                cold_nonce: 0,
            })
            .unwrap();
        (pubkey, keypair, validator_id)
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
        let validator_id = staking_delegator_id_for_test(&validator_pubkey);
        let bond_utxo_id = state
            .utxos
            .insert(
                output_with_value(
                    MINIMUM_VALIDATOR_BOND_SPARK,
                    validator_pubkey.clone(),
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
                bond_utxo_id,
                validator_pubkey,
                vrf_pk: seed,
                bond_proof: Some(indra_core::types::staking::StakingBondProof {
                    committed_value_spark: MINIMUM_VALIDATOR_BOND_SPARK,
                    blinding_factor: Bytes32::from([seed[0]; 32]),
                }),
                cold_pubkey: None,
                cold_signature: None,
            },
            nonce,
            signature: dummy_sig(),
        };
        sign_staking_op(&keypair, &state.chain_id, &mut op);
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
        bond_utxo_id: Bytes32,
        delegator_pubkey: HybridPubKey,
        keypair: &HybridKeypair,
        nonce: u64,
    ) -> StakingOp {
        let mut op = StakingOp {
            body: StakingOpBody::Undelegate {
                validator_id,
                bond_utxo_id,
                delegator_pubkey,
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
            cold_key_status: crate::validator::ColdKeyStatus::Unenrolled,
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
                vrf_pk: Some(seed),
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
                cold_key_status: crate::validator::ColdKeyStatus::Unenrolled,
                cold_nonce: 0,
            })
            .unwrap();
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

    fn slash_evidence(
        keypair: &HybridKeypair,
        validator_id: Bytes32,
        step: VoteStep,
    ) -> SlashEvidenceV1 {
        SlashEvidenceV1 {
            validator_id,
            vote_1: signed_vote(keypair, validator_id, 7, 0, step, Bytes32::from([0xAA; 32])),
            vote_2: signed_vote(keypair, validator_id, 7, 0, step, Bytes32::from([0xBB; 32])),
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
        let (owner_pubkey, keypair) = make_test_keypair([0x11; 32]);
        let output = dummy_output(0x01, owner_pubkey);
        let utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();
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
            version: ProtocolVersion::CURRENT,
            signature_module_id: 1,
            inputs: vec![InputV1 { utxo_id, nullifier }],
            outputs: vec![OutputV1 {
                value_spark: output_value,
                commitment: CommitmentV1 {
                    compressed_point: Bytes32::from(commitment.0),
                },
                owner_pubkey,
                range_proof: VariableBytes::from_slice(&proof).unwrap(),
                lock_height: 0,
            }],
            payment_notes: Vec::new(),
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
            version: ProtocolVersion::CURRENT,
            signature_module_id: 1,
            inputs: inputs
                .iter()
                .map(|(utxo_id, _, _, nullifier)| InputV1 {
                    utxo_id: *utxo_id,
                    nullifier: *nullifier,
                })
                .collect(),
            outputs,
            payment_notes: Vec::new(),
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
        BlockV1 {
            header: BlockHeaderV1 {
                protocol_version: ProtocolVersion(block_protocol_version_for_height(height)),
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
            transactions: txs,
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            vrf_reveals: vec![],
        }
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
            output_with_value(amount_spark, owner_pubkey, byte),
            0,
            u64::MAX,
        );
        assert!(bond.original_output.range_proof.is_some());
        state.staked_bonds.insert(bond_utxo_id, bond);
        state
            .delegations
            .add_delegation(validator_id, delegator_id, amount_spark, 0)
            .unwrap();
    }

    fn governance_proposal_state(
        phase: ProposalPhase,
    ) -> (ChainState, HybridPubKey, HybridKeypair, Bytes32, Bytes32) {
        let mut state = ChainState::new_genesis();
        state.governance.params.proposal_deposit_spark = 1_000;
        let (proposer_pubkey, proposer_keypair, proposer_id) =
            install_governance_validator(&mut state, [0x91; 32], 100_000);
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
                protocol_version: ProtocolVersion(block_protocol_version_for_height(height)),
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
    fn project_block_for_roots_matches_clone_projection() {
        let mut cases: Vec<(String, ChainState, BlockV1, u64)> = Vec::new();

        let empty_state = ChainState::new_genesis();
        cases.push((
            "empty".into(),
            empty_state.clone(),
            make_block(&empty_state, vec![]),
            0,
        ));

        let (tx_state, utxo_id, keypair, blinding, value) = state_with_utxo();
        let tx = make_tx(
            &tx_state,
            &keypair,
            utxo_id,
            value,
            blinding,
            Bytes32::from([0xA1; 32]),
        );
        cases.push((
            "transaction".into(),
            tx_state.clone(),
            make_block(&tx_state, vec![tx]),
            0,
        ));

        let mut staking_state = ChainState::new_genesis();
        let (staking_op, _) = signed_register_validator_op(&mut staking_state, [0x61; 32], 1);
        let mut staking_block = make_block(&staking_state, vec![]);
        staking_block.staking_ops.push(staking_op);
        cases.push(("staking".into(), staking_state, staking_block, 0));

        let mut governance_state = ChainState::new_genesis();
        governance_state.governance.params.proposal_deposit_spark = 1_000;
        let (proposer_pubkey, proposer_keypair, proposer_id) =
            install_governance_validator(&mut governance_state, [0x81; 32], 100_000);
        let deposit = governance_state
            .utxos
            .insert(
                governance_deposit_output(proposer_pubkey.clone(), 1_500),
                0,
                0,
                0,
            )
            .unwrap();
        let governance_op = governance_propose_op(
            proposer_id,
            &proposer_keypair,
            proposer_pubkey,
            deposit,
            1,
            GovernableAction::SetMinDelegationSpark { value: 100_000 },
        );
        let mut governance_block = make_block(&governance_state, vec![]);
        governance_block.governance_ops.push(governance_op);
        cases.push(("governance".into(), governance_state, governance_block, 0));

        let (slash_state, validator_id, slash_keypair) =
            slash_validator_state([0x62; 32], MINIMUM_VALIDATOR_BOND_SPARK);
        let mut slash_block = make_block(&slash_state, vec![]);
        slash_block.slashing_evidence.push(slash_evidence(
            &slash_keypair,
            validator_id,
            VoteStep::Precommit,
        ));
        cases.push(("slashing".into(), slash_state, slash_block, 0));

        let mut epoch_state = ChainState::new_genesis();
        epoch_state.height = EPOCH_DURATION_BLOCKS - 1;
        let epoch_block = make_block(&epoch_state, vec![]);
        assert!(is_epoch_boundary(epoch_block.header.height));
        cases.push(("epoch-boundary".into(), epoch_state, epoch_block, 123_456));

        for (label, state, block, timestamp_secs) in cases {
            let reference =
                clone_atomic_reference_apply_block(&state, &block, timestamp_secs).unwrap();
            let mut projected_state = state.clone();
            let projected =
                project_block_for_roots(&mut projected_state, &block, timestamp_secs).unwrap();
            assert_eq!(projected.state_root, reference.state_root, "{label}");
            assert_eq!(
                projected.validator_set_root, reference.validator_set_root,
                "{label}"
            );
            let mut reference_block = block.clone();
            reference_block.header.state_root = reference.state_root;
            reference_block.header.validator_set_root = reference.validator_set_root;
            assert_eq!(
                projected.value_hash,
                reference_block.compute_value_hash(reference.state.total_supply),
                "{label}"
            );
            assert_eq!(
                projected.total_supply, reference.state.total_supply,
                "{label}"
            );
            assert_eq!(projected.epoch_record, reference.epoch_record, "{label}");
            assert_same_consensus_state(&projected_state, &state);
            assert_eq!(
                projected_state.state_commitment_v2.is_some(),
                state.state_commitment_v2.is_some(),
                "{label}"
            );
        }
    }

    #[test]
    fn project_block_for_roots_restores_state_on_success() {
        let mut state = ChainState::new_genesis();
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
        let state = ChainState::new_genesis();
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
        let mut state = ChainState::new_genesis();
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
    fn state_txn_rolls_back_staking_scope_failpoints() {
        let mut state = ChainState::new_genesis();
        let (op, _) = signed_register_validator_op(&mut state, [0x61; 32], 1);
        let mut block = make_block(&state, vec![]);
        block.staking_ops.push(op);
        let mutation_count = assert_all_failpoints_roll_back(&state, &block);
        assert!(
            mutation_count >= 4,
            "staking block should exercise scoped undo mutations, got {mutation_count}"
        );
    }

    #[test]
    fn state_txn_rolls_back_delegation_mutation_failpoints() {
        let mut state = ChainState::new_genesis();
        let (delegator_pubkey, keypair) = make_test_keypair([0x71; 32]);
        let output = dummy_output(0x08, delegator_pubkey.clone());
        let bond_utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();
        let validator_id = Bytes32::from([0x72; 32]);
        state
            .validators
            .upsert(active_validator(validator_id))
            .unwrap();

        let delegate_op = signed_delegate_op(
            &state,
            validator_id,
            bond_utxo_id,
            delegator_pubkey.clone(),
            &keypair,
            1,
        );
        let mut delegate_block = make_block(&state, vec![]);
        delegate_block.staking_ops.push(delegate_op);
        let delegate_mutations = assert_all_failpoints_roll_back(&state, &delegate_block);
        assert!(
            delegate_mutations >= 5,
            "delegation block should exercise delegation rollback mutations, got {delegate_mutations}"
        );

        apply_block(&mut state, &delegate_block, 0).unwrap();
        let undelegate_op = signed_undelegate_op(
            &state,
            validator_id,
            bond_utxo_id,
            delegator_pubkey,
            &keypair,
            2,
        );
        let mut undelegate_block = make_block(&state, vec![]);
        undelegate_block.staking_ops.push(undelegate_op);
        let undelegate_mutations = assert_all_failpoints_roll_back(&state, &undelegate_block);
        assert!(
            undelegate_mutations >= 4,
            "undelegation block should exercise delegation rollback mutations, got {undelegate_mutations}"
        );
    }

    #[test]
    fn delegation_side_index_replay_determinism_independent_of_cache_state() {
        let mut base = ChainState::new_genesis();
        let (delegator_pubkey, keypair) = make_test_keypair([0x75; 32]);
        let delegator_id = staking_delegator_id_for_test(&delegator_pubkey);
        let output = dummy_output(0x0A, delegator_pubkey.clone());
        let bond_utxo_id = base.utxos.insert(output, 0, 0, 0).unwrap();
        let validator_id = Bytes32::from([0x76; 32]);
        base.validators
            .upsert(active_validator(validator_id))
            .unwrap();

        let delegate_op = signed_delegate_op(
            &base,
            validator_id,
            bond_utxo_id,
            delegator_pubkey.clone(),
            &keypair,
            1,
        );
        let mut delegate_block = make_block(&base, vec![]);
        delegate_block.staking_ops.push(delegate_op);

        let mut cache_cold = base.clone();
        let mut cache_warm = base.clone();
        apply_block(&mut cache_cold, &delegate_block, 0).unwrap();
        apply_block(&mut cache_warm, &delegate_block, 0).unwrap();
        assert_same_consensus_state(&cache_cold, &cache_warm);

        cache_cold.delegations.invalidate_delegator_index_for_test();
        assert_eq!(
            cache_warm
                .delegations
                .get_delegator_reward(&validator_id, &delegator_id),
            0
        );

        let undelegate_op = signed_undelegate_op(
            &cache_warm,
            validator_id,
            bond_utxo_id,
            delegator_pubkey,
            &keypair,
            2,
        );
        let mut undelegate_block = make_block(&cache_warm, vec![]);
        undelegate_block.staking_ops.push(undelegate_op);

        apply_block(&mut cache_cold, &undelegate_block, 0).unwrap();
        apply_block(&mut cache_warm, &undelegate_block, 0).unwrap();

        assert_same_consensus_state(&cache_cold, &cache_warm);
    }

    #[test]
    fn state_txn_rolls_back_delegate_identity_registry_population_failpoints() {
        let mut state = ChainState::new_genesis();
        state.height = DELEGATOR_IDENTITY_REGISTRY_HEIGHT;
        state.tip_hash = Bytes32::ZERO;
        let (delegator_pubkey, keypair) = make_test_keypair([0x73; 32]);
        let delegator_id = staking_delegator_id_for_test(&delegator_pubkey);
        let output = dummy_output(0x09, delegator_pubkey.clone());
        let bond_utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();
        let validator_id = Bytes32::from([0x74; 32]);
        state
            .validators
            .upsert(active_validator(validator_id))
            .unwrap();

        let delegate_op = signed_delegate_op(
            &state,
            validator_id,
            bond_utxo_id,
            delegator_pubkey,
            &keypair,
            1,
        );
        let mut block =
            make_block_at_height(&state, vec![], DELEGATOR_IDENTITY_REGISTRY_HEIGHT + 1, 0);
        block.staking_ops.push(delegate_op);

        crate::txn::set_fail_after_mutation(None);
        let mut success = state.clone();
        apply_block(&mut success, &block, 0).unwrap();
        assert!(success.delegator_identities.contains_key(&delegator_id));
        let success_bond = success.staked_bonds.get(&bond_utxo_id).unwrap();
        assert!(success_bond.original_output.range_proof.is_none());
        assert!(success_bond.original_output.owner_pubkey.is_some());

        let mutation_count = assert_all_failpoints_roll_back(&state, &block);
        assert!(
            mutation_count >= 5,
            "delegate identity population should be rollback-covered, got {mutation_count}"
        );
        assert!(!state.delegator_identities.contains_key(&delegator_id));
        assert!(!state.staked_bonds.contains_key(&bond_utxo_id));
    }

    #[test]
    fn state_txn_rolls_back_undelegate_identity_registry_population_failpoints() {
        let mut state = ChainState::new_genesis();
        let (delegator_pubkey, keypair) = make_test_keypair([0x79; 32]);
        let delegator_id = staking_delegator_id_for_test(&delegator_pubkey);
        let output = dummy_output(0x0D, delegator_pubkey.clone());
        let bond_utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();
        let validator_id = Bytes32::from([0x7A; 32]);
        state
            .validators
            .upsert(active_validator(validator_id))
            .unwrap();
        let chain_id = state.chain_id.clone();
        let delegate_op = signed_delegate_op(
            &state,
            validator_id,
            bond_utxo_id,
            delegator_pubkey.clone(),
            &keypair,
            1,
        );
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut state,
            &delegate_op,
            &chain_id,
            1,
            false,
        )
        .unwrap();
        assert!(state.delegator_identities.is_empty());
        assert_eq!(
            state
                .staked_bonds
                .get(&bond_utxo_id)
                .and_then(|bond| bond.unbonding_end_epoch),
            None
        );
        state.height = DELEGATOR_IDENTITY_REGISTRY_HEIGHT;
        state.tip_hash = Bytes32::ZERO;

        let undelegate_op = signed_undelegate_op(
            &state,
            validator_id,
            bond_utxo_id,
            delegator_pubkey,
            &keypair,
            2,
        );
        let mut block =
            make_block_at_height(&state, vec![], DELEGATOR_IDENTITY_REGISTRY_HEIGHT + 1, 0);
        block.staking_ops.push(undelegate_op);

        crate::txn::set_fail_after_mutation(None);
        let mut success = state.clone();
        apply_block(&mut success, &block, 0).unwrap();
        assert!(success.delegator_identities.contains_key(&delegator_id));
        assert_eq!(
            success
                .staked_bonds
                .get(&bond_utxo_id)
                .and_then(|bond| bond.unbonding_end_epoch)
                .is_some(),
            true
        );

        let mutation_count = assert_all_failpoints_roll_back(&state, &block);
        assert!(
            mutation_count >= 4,
            "undelegate identity population should be rollback-covered, got {mutation_count}"
        );
        assert!(!state.delegator_identities.contains_key(&delegator_id));
        assert_eq!(
            state
                .staked_bonds
                .get(&bond_utxo_id)
                .and_then(|bond| bond.unbonding_end_epoch),
            None
        );
    }

    #[test]
    fn state_txn_rolls_back_claim_rewards_identity_registry_population_failpoints() {
        let mut state = ChainState::new_genesis();
        let (delegator_pubkey, keypair) = make_test_keypair([0x80; 32]);
        let delegator_id = staking_delegator_id_for_test(&delegator_pubkey);
        let output = dummy_output(0x10, delegator_pubkey.clone());
        let bond_utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();
        let validator_id = Bytes32::from([0x81; 32]);
        state
            .validators
            .upsert(active_validator(validator_id))
            .unwrap();
        let chain_id = state.chain_id.clone();
        let delegate_op = signed_delegate_op(
            &state,
            validator_id,
            bond_utxo_id,
            delegator_pubkey.clone(),
            &keypair,
            1,
        );
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut state,
            &delegate_op,
            &chain_id,
            1,
            false,
        )
        .unwrap();
        state
            .delegations
            .update_delegator(&validator_id, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();
        assert!(state.delegator_identities.is_empty());
        state.height = DELEGATOR_IDENTITY_REGISTRY_HEIGHT;
        state.tip_hash = Bytes32::ZERO;

        let claim_op = signed_claim_rewards_op(&state, validator_id, delegator_pubkey, &keypair, 2);
        let mut block =
            make_block_at_height(&state, vec![], DELEGATOR_IDENTITY_REGISTRY_HEIGHT + 1, 0);
        block.staking_ops.push(claim_op);

        crate::txn::set_fail_after_mutation(None);
        let mut success = state.clone();
        apply_block(&mut success, &block, 0).unwrap();
        assert!(success.delegator_identities.contains_key(&delegator_id));
        assert_eq!(
            success
                .delegations
                .get_delegators(&validator_id)
                .iter()
                .find(|entry| entry.delegator_id == delegator_id)
                .unwrap()
                .pending_rewards,
            0
        );
        assert_eq!(success.utxos.len(), state.utxos.len() + 1);

        let mutation_count = assert_all_failpoints_roll_back(&state, &block);
        assert!(
            mutation_count >= 4,
            "claim rewards identity population should be rollback-covered, got {mutation_count}"
        );
        assert!(!state.delegator_identities.contains_key(&delegator_id));
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
    fn state_txn_rolls_back_governance_redelegation_identity_population_failpoints() {
        let mut state = ChainState::new_genesis();
        let from_validator = Bytes32::from([0x87; 32]);
        let to_validator = Bytes32::from([0x88; 32]);
        let proposal_id = Bytes32::from([0x89; 32]);
        install_reveal_phase_governance_proposal(
            &mut state,
            proposal_id,
            from_validator,
            to_validator,
        );
        let (delegator_pubkey, delegator_keypair) = make_test_keypair([0x8A; 32]);
        let delegator_id = staking_delegator_id_for_test(&delegator_pubkey);
        install_legacy_redelegation_bond(
            &mut state,
            Bytes32::from([0x8B; 32]),
            from_validator,
            delegator_id,
            delegator_pubkey.clone(),
            1_000,
            0x8B,
        );
        assert!(state.delegator_identities.is_empty());
        state.height = DELEGATOR_IDENTITY_REGISTRY_HEIGHT;
        state.tip_hash = Bytes32::ZERO;

        let op = governance_redelegate_op(
            delegator_id,
            &delegator_keypair,
            proposal_id,
            from_validator,
            to_validator,
            500,
            1,
        );
        let mut block =
            make_block_at_height(&state, vec![], DELEGATOR_IDENTITY_REGISTRY_HEIGHT + 1, 0);
        block.governance_ops.push(op);

        crate::txn::set_fail_after_mutation(None);
        let mut success = state.clone();
        apply_block(&mut success, &block, 0).unwrap();
        assert_eq!(
            success.delegator_identities.get(&delegator_id),
            Some(&delegator_pubkey)
        );
        assert_eq!(
            success
                .governance
                .proposals
                .get(&proposal_id)
                .unwrap()
                .redelegations
                .len(),
            1
        );

        let mutation_count = assert_all_failpoints_roll_back(&state, &block);
        assert!(
            mutation_count >= 3,
            "governance redelegation identity population should be rollback-covered, got {mutation_count}"
        );
        assert!(!state.delegator_identities.contains_key(&delegator_id));
        assert!(state
            .governance
            .proposals
            .get(&proposal_id)
            .unwrap()
            .redelegations
            .is_empty());
    }

    #[test]
    fn state_txn_rolls_back_register_validator_identity_population_failpoints() {
        let mut state = ChainState::new_genesis();
        state.validators = ValidatorSet::new();
        state.height = DELEGATOR_IDENTITY_REGISTRY_HEIGHT;
        state.tip_hash = Bytes32::ZERO;
        let (op, validator_id) = signed_register_validator_op(&mut state, [0x93; 32], 1);
        let validator_pubkey = match &op.body {
            StakingOpBody::RegisterValidator {
                validator_pubkey, ..
            } => validator_pubkey.clone(),
            _ => unreachable!(),
        };
        let mut block =
            make_block_at_height(&state, vec![], DELEGATOR_IDENTITY_REGISTRY_HEIGHT + 1, 0);
        block.staking_ops.push(op);

        crate::txn::set_fail_after_mutation(None);
        let mut success = state.clone();
        apply_block(&mut success, &block, 0).unwrap();
        assert_eq!(
            success.delegator_identities.get(&validator_id),
            Some(&validator_pubkey)
        );
        assert!(success.validators.get(&validator_id).is_some());

        let mutation_count = assert_all_failpoints_roll_back(&state, &block);
        assert!(
            mutation_count >= 3,
            "validator identity registration should be rollback-covered, got {mutation_count}"
        );
        assert!(!state.delegator_identities.contains_key(&validator_id));
        assert!(state.validators.get(&validator_id).is_none());
    }

    #[test]
    fn delegate_identity_activation_replay_is_deterministic_before_gate_and_rejects_after_gate() {
        let activation_height = 2;
        let mut reference = ChainState::new_genesis();
        let mut candidate = reference.clone();
        let validator_id = Bytes32::from([0x75; 32]);
        reference
            .validators
            .upsert(active_validator(validator_id))
            .unwrap();
        candidate
            .validators
            .upsert(active_validator(validator_id))
            .unwrap();

        let (legit_pubkey, legit_keypair) = make_mixed_test_keypair([0x76; 32], [0x77; 32]);
        let delegator_id = staking_delegator_id_for_test(&legit_pubkey);
        let (attacker_pubkey, attacker_keypair) = make_mixed_test_keypair([0x76; 32], [0x78; 32]);
        assert_eq!(
            staking_delegator_id_for_test(&attacker_pubkey),
            delegator_id
        );
        assert_ne!(attacker_pubkey, legit_pubkey);

        let pre_gate_reference_utxo = reference
            .utxos
            .insert(dummy_output(0x0A, legit_pubkey.clone()), 0, 0, 0)
            .unwrap();
        let pre_gate_candidate_utxo = candidate
            .utxos
            .insert(dummy_output(0x0A, legit_pubkey.clone()), 0, 0, 0)
            .unwrap();
        assert_eq!(pre_gate_reference_utxo, pre_gate_candidate_utxo);
        let pre_gate_reference = signed_delegate_op(
            &reference,
            validator_id,
            pre_gate_reference_utxo,
            legit_pubkey.clone(),
            &legit_keypair,
            1,
        );
        let pre_gate_candidate = signed_delegate_op(
            &candidate,
            validator_id,
            pre_gate_candidate_utxo,
            legit_pubkey.clone(),
            &legit_keypair,
            1,
        );
        let reference_chain_id = reference.chain_id.clone();
        let candidate_chain_id = candidate.chain_id.clone();
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut reference,
            &pre_gate_reference,
            &reference_chain_id,
            1,
            false,
        )
        .unwrap();
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut candidate,
            &pre_gate_candidate,
            &candidate_chain_id,
            1,
            false,
        )
        .unwrap();
        assert_eq!(reference.encode_to_vec(), candidate.encode_to_vec());
        assert!(candidate.delegator_identities.is_empty());

        let establish_reference_utxo = reference
            .utxos
            .insert(dummy_output(0x0B, legit_pubkey.clone()), 1, 0, 0)
            .unwrap();
        let establish_candidate_utxo = candidate
            .utxos
            .insert(dummy_output(0x0B, legit_pubkey.clone()), 1, 0, 0)
            .unwrap();
        assert_eq!(establish_reference_utxo, establish_candidate_utxo);
        let establish_reference = signed_delegate_op(
            &reference,
            validator_id,
            establish_reference_utxo,
            legit_pubkey.clone(),
            &legit_keypair,
            2,
        );
        let establish_candidate = signed_delegate_op(
            &candidate,
            validator_id,
            establish_candidate_utxo,
            legit_pubkey.clone(),
            &legit_keypair,
            2,
        );
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut reference,
            &establish_reference,
            &reference_chain_id,
            activation_height,
            false,
        )
        .unwrap();
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut candidate,
            &establish_candidate,
            &candidate_chain_id,
            activation_height,
            true,
        )
        .unwrap();
        assert_eq!(
            candidate.delegator_identities.get(&delegator_id),
            Some(&legit_pubkey)
        );

        let attack_reference_utxo = reference
            .utxos
            .insert(dummy_output(0x0C, attacker_pubkey.clone()), 2, 0, 0)
            .unwrap();
        let attack_candidate_utxo = candidate
            .utxos
            .insert(dummy_output(0x0C, attacker_pubkey.clone()), 2, 0, 0)
            .unwrap();
        assert_eq!(attack_reference_utxo, attack_candidate_utxo);
        let attack_reference = signed_delegate_op(
            &reference,
            validator_id,
            attack_reference_utxo,
            attacker_pubkey.clone(),
            &attacker_keypair,
            3,
        );
        let attack_candidate = signed_delegate_op(
            &candidate,
            validator_id,
            attack_candidate_utxo,
            attacker_pubkey,
            &attacker_keypair,
            3,
        );

        crate::delegation::apply_staking_op_with_identity_activation(
            &mut reference,
            &attack_reference,
            &reference_chain_id,
            activation_height + 1,
            false,
        )
        .unwrap();
        let candidate_before_attack = candidate.clone();
        let err = crate::delegation::apply_staking_op_with_identity_activation(
            &mut candidate,
            &attack_candidate,
            &candidate_chain_id,
            activation_height + 1,
            true,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("delegator identity registry pubkey mismatch")
        ));
        assert_eq!(candidate, candidate_before_attack);
        assert!(reference.staked_bonds.contains_key(&attack_reference_utxo));
        assert!(!candidate.staked_bonds.contains_key(&attack_candidate_utxo));
    }

    #[test]
    fn undelegate_identity_activation_replay_is_deterministic_before_gate_and_rejects_after_gate() {
        let activation_height = 2;
        let mut reference = ChainState::new_genesis();
        let mut candidate = reference.clone();
        let first_validator_id = Bytes32::from([0x7B; 32]);
        let second_validator_id = Bytes32::from([0x7F; 32]);
        reference
            .validators
            .upsert(active_validator(first_validator_id))
            .unwrap();
        reference
            .validators
            .upsert(active_validator(second_validator_id))
            .unwrap();
        candidate
            .validators
            .upsert(active_validator(first_validator_id))
            .unwrap();
        candidate
            .validators
            .upsert(active_validator(second_validator_id))
            .unwrap();

        let (legit_pubkey, legit_keypair) = make_mixed_test_keypair([0x7C; 32], [0x7D; 32]);
        let delegator_id = staking_delegator_id_for_test(&legit_pubkey);
        let (attacker_pubkey, attacker_keypair) = make_mixed_test_keypair([0x7C; 32], [0x7E; 32]);
        assert_eq!(
            staking_delegator_id_for_test(&attacker_pubkey),
            delegator_id
        );
        assert_ne!(attacker_pubkey, legit_pubkey);

        let first_reference_utxo = reference
            .utxos
            .insert(dummy_output(0x0E, legit_pubkey.clone()), 0, 0, 0)
            .unwrap();
        let first_candidate_utxo = candidate
            .utxos
            .insert(dummy_output(0x0E, legit_pubkey.clone()), 0, 0, 0)
            .unwrap();
        assert_eq!(first_reference_utxo, first_candidate_utxo);
        let first_reference_delegate = signed_delegate_op(
            &reference,
            first_validator_id,
            first_reference_utxo,
            legit_pubkey.clone(),
            &legit_keypair,
            1,
        );
        let first_candidate_delegate = signed_delegate_op(
            &candidate,
            first_validator_id,
            first_candidate_utxo,
            legit_pubkey.clone(),
            &legit_keypair,
            1,
        );
        let reference_chain_id = reference.chain_id.clone();
        let candidate_chain_id = candidate.chain_id.clone();
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut reference,
            &first_reference_delegate,
            &reference_chain_id,
            1,
            false,
        )
        .unwrap();
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut candidate,
            &first_candidate_delegate,
            &candidate_chain_id,
            1,
            false,
        )
        .unwrap();
        assert_eq!(reference.encode_to_vec(), candidate.encode_to_vec());
        assert!(candidate.delegator_identities.is_empty());

        let second_reference_utxo = reference
            .utxos
            .insert(dummy_output(0x0F, legit_pubkey.clone()), 1, 0, 0)
            .unwrap();
        let second_candidate_utxo = candidate
            .utxos
            .insert(dummy_output(0x0F, legit_pubkey.clone()), 1, 0, 0)
            .unwrap();
        assert_eq!(second_reference_utxo, second_candidate_utxo);
        let second_reference_delegate = signed_delegate_op(
            &reference,
            second_validator_id,
            second_reference_utxo,
            legit_pubkey.clone(),
            &legit_keypair,
            2,
        );
        let second_candidate_delegate = signed_delegate_op(
            &candidate,
            second_validator_id,
            second_candidate_utxo,
            legit_pubkey.clone(),
            &legit_keypair,
            2,
        );
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut reference,
            &second_reference_delegate,
            &reference_chain_id,
            1,
            false,
        )
        .unwrap();
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut candidate,
            &second_candidate_delegate,
            &candidate_chain_id,
            1,
            false,
        )
        .unwrap();
        assert_eq!(reference.encode_to_vec(), candidate.encode_to_vec());

        let establish_reference = signed_undelegate_op(
            &reference,
            first_validator_id,
            first_reference_utxo,
            legit_pubkey.clone(),
            &legit_keypair,
            3,
        );
        let establish_candidate = signed_undelegate_op(
            &candidate,
            first_validator_id,
            first_candidate_utxo,
            legit_pubkey.clone(),
            &legit_keypair,
            3,
        );
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut reference,
            &establish_reference,
            &reference_chain_id,
            activation_height,
            false,
        )
        .unwrap();
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut candidate,
            &establish_candidate,
            &candidate_chain_id,
            activation_height,
            true,
        )
        .unwrap();
        assert_eq!(
            candidate.delegator_identities.get(&delegator_id),
            Some(&legit_pubkey)
        );
        assert_eq!(
            reference
                .staked_bonds
                .get(&first_reference_utxo)
                .and_then(|bond| bond.unbonding_end_epoch),
            Some(UNBONDING_PERIOD_EPOCHS)
        );
        assert_eq!(
            candidate
                .staked_bonds
                .get(&first_candidate_utxo)
                .and_then(|bond| bond.unbonding_end_epoch),
            Some(UNBONDING_PERIOD_EPOCHS)
        );

        let attack_reference = signed_undelegate_op(
            &reference,
            second_validator_id,
            second_reference_utxo,
            attacker_pubkey.clone(),
            &attacker_keypair,
            4,
        );
        let attack_candidate = signed_undelegate_op(
            &candidate,
            second_validator_id,
            second_candidate_utxo,
            attacker_pubkey,
            &attacker_keypair,
            4,
        );

        crate::delegation::apply_staking_op_with_identity_activation(
            &mut reference,
            &attack_reference,
            &reference_chain_id,
            activation_height + 1,
            false,
        )
        .unwrap();
        let candidate_before_attack = candidate.clone();
        let err = crate::delegation::apply_staking_op_with_identity_activation(
            &mut candidate,
            &attack_candidate,
            &candidate_chain_id,
            activation_height + 1,
            true,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("delegator identity registry pubkey mismatch")
        ));
        assert_eq!(candidate, candidate_before_attack);
        assert_eq!(
            reference
                .staked_bonds
                .get(&second_reference_utxo)
                .and_then(|bond| bond.unbonding_end_epoch),
            Some(UNBONDING_PERIOD_EPOCHS)
        );
        assert_eq!(
            candidate
                .staked_bonds
                .get(&second_candidate_utxo)
                .and_then(|bond| bond.unbonding_end_epoch),
            None
        );
    }

    #[test]
    fn claim_rewards_identity_activation_replay_is_deterministic_before_gate_and_rejects_after_gate(
    ) {
        let activation_height = 2;
        let mut reference = ChainState::new_genesis();
        let mut candidate = reference.clone();
        let first_validator_id = Bytes32::from([0x82; 32]);
        let second_validator_id = Bytes32::from([0x83; 32]);
        reference
            .validators
            .upsert(active_validator(first_validator_id))
            .unwrap();
        reference
            .validators
            .upsert(active_validator(second_validator_id))
            .unwrap();
        candidate
            .validators
            .upsert(active_validator(first_validator_id))
            .unwrap();
        candidate
            .validators
            .upsert(active_validator(second_validator_id))
            .unwrap();

        let (legit_pubkey, legit_keypair) = make_mixed_test_keypair([0x84; 32], [0x85; 32]);
        let delegator_id = staking_delegator_id_for_test(&legit_pubkey);
        let (attacker_pubkey, attacker_keypair) = make_mixed_test_keypair([0x84; 32], [0x86; 32]);
        assert_eq!(
            staking_delegator_id_for_test(&attacker_pubkey),
            delegator_id
        );
        assert_ne!(attacker_pubkey, legit_pubkey);

        let first_reference_utxo = reference
            .utxos
            .insert(dummy_output(0x11, legit_pubkey.clone()), 0, 0, 0)
            .unwrap();
        let first_candidate_utxo = candidate
            .utxos
            .insert(dummy_output(0x11, legit_pubkey.clone()), 0, 0, 0)
            .unwrap();
        assert_eq!(first_reference_utxo, first_candidate_utxo);
        let first_reference_delegate = signed_delegate_op(
            &reference,
            first_validator_id,
            first_reference_utxo,
            legit_pubkey.clone(),
            &legit_keypair,
            1,
        );
        let first_candidate_delegate = signed_delegate_op(
            &candidate,
            first_validator_id,
            first_candidate_utxo,
            legit_pubkey.clone(),
            &legit_keypair,
            1,
        );
        let reference_chain_id = reference.chain_id.clone();
        let candidate_chain_id = candidate.chain_id.clone();
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut reference,
            &first_reference_delegate,
            &reference_chain_id,
            1,
            false,
        )
        .unwrap();
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut candidate,
            &first_candidate_delegate,
            &candidate_chain_id,
            1,
            false,
        )
        .unwrap();
        assert_eq!(reference.encode_to_vec(), candidate.encode_to_vec());

        let second_reference_utxo = reference
            .utxos
            .insert(dummy_output(0x12, legit_pubkey.clone()), 1, 0, 0)
            .unwrap();
        let second_candidate_utxo = candidate
            .utxos
            .insert(dummy_output(0x12, legit_pubkey.clone()), 1, 0, 0)
            .unwrap();
        assert_eq!(second_reference_utxo, second_candidate_utxo);
        let second_reference_delegate = signed_delegate_op(
            &reference,
            second_validator_id,
            second_reference_utxo,
            legit_pubkey.clone(),
            &legit_keypair,
            2,
        );
        let second_candidate_delegate = signed_delegate_op(
            &candidate,
            second_validator_id,
            second_candidate_utxo,
            legit_pubkey.clone(),
            &legit_keypair,
            2,
        );
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut reference,
            &second_reference_delegate,
            &reference_chain_id,
            1,
            false,
        )
        .unwrap();
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut candidate,
            &second_candidate_delegate,
            &candidate_chain_id,
            1,
            false,
        )
        .unwrap();
        reference
            .delegations
            .update_delegator(&first_validator_id, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();
        candidate
            .delegations
            .update_delegator(&first_validator_id, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();
        reference
            .delegations
            .update_delegator(&second_validator_id, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();
        candidate
            .delegations
            .update_delegator(&second_validator_id, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();
        assert_eq!(reference.encode_to_vec(), candidate.encode_to_vec());
        assert!(candidate.delegator_identities.is_empty());

        let establish_reference = signed_claim_rewards_op(
            &reference,
            first_validator_id,
            legit_pubkey.clone(),
            &legit_keypair,
            3,
        );
        let establish_candidate = signed_claim_rewards_op(
            &candidate,
            first_validator_id,
            legit_pubkey.clone(),
            &legit_keypair,
            3,
        );
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut reference,
            &establish_reference,
            &reference_chain_id,
            activation_height,
            false,
        )
        .unwrap();
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut candidate,
            &establish_candidate,
            &candidate_chain_id,
            activation_height,
            true,
        )
        .unwrap();
        assert_eq!(
            candidate.delegator_identities.get(&delegator_id),
            Some(&legit_pubkey)
        );
        assert_eq!(
            reference
                .delegations
                .get_delegators(&first_validator_id)
                .iter()
                .find(|entry| entry.delegator_id == delegator_id)
                .unwrap()
                .pending_rewards,
            0
        );
        assert_eq!(
            candidate
                .delegations
                .get_delegators(&first_validator_id)
                .iter()
                .find(|entry| entry.delegator_id == delegator_id)
                .unwrap()
                .pending_rewards,
            0
        );

        let attack_reference = signed_claim_rewards_op(
            &reference,
            second_validator_id,
            attacker_pubkey.clone(),
            &attacker_keypair,
            4,
        );
        let attack_candidate = signed_claim_rewards_op(
            &candidate,
            second_validator_id,
            attacker_pubkey,
            &attacker_keypair,
            4,
        );
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut reference,
            &attack_reference,
            &reference_chain_id,
            activation_height + 1,
            false,
        )
        .unwrap();
        let candidate_before_attack = candidate.clone();
        let err = crate::delegation::apply_staking_op_with_identity_activation(
            &mut candidate,
            &attack_candidate,
            &candidate_chain_id,
            activation_height + 1,
            true,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            StateError::InvalidStakingOp(message)
                if message.contains("delegator identity registry pubkey mismatch")
        ));
        assert_eq!(candidate, candidate_before_attack);
        assert_eq!(
            reference
                .delegations
                .get_delegators(&second_validator_id)
                .iter()
                .find(|entry| entry.delegator_id == delegator_id)
                .unwrap()
                .pending_rewards,
            0
        );
        assert_eq!(
            candidate
                .delegations
                .get_delegators(&second_validator_id)
                .iter()
                .find(|entry| entry.delegator_id == delegator_id)
                .unwrap()
                .pending_rewards,
            DUST_LIMIT_SPARK
        );
    }

    #[test]
    fn governance_redelegation_identity_activation_replay_is_deterministic_before_gate_and_rejects_after_gate(
    ) {
        let mut state = ChainState::new_genesis();
        let from_validator = Bytes32::from([0x8C; 32]);
        let to_validator = Bytes32::from([0x8D; 32]);
        let pre_gate_proposal = Bytes32::from([0x8E; 32]);
        let post_gate_proposal = Bytes32::from([0x8F; 32]);
        install_reveal_phase_governance_proposal(
            &mut state,
            pre_gate_proposal,
            from_validator,
            to_validator,
        );
        install_reveal_phase_governance_proposal(
            &mut state,
            post_gate_proposal,
            from_validator,
            to_validator,
        );
        let (first_pubkey, first_keypair) = make_mixed_test_keypair([0x90; 32], [0x91; 32]);
        let (second_pubkey, _) = make_mixed_test_keypair([0x90; 32], [0x92; 32]);
        let delegator_id = staking_delegator_id_for_test(&first_pubkey);
        assert_eq!(staking_delegator_id_for_test(&second_pubkey), delegator_id);
        install_legacy_redelegation_bond(
            &mut state,
            Bytes32::from([0x01; 32]),
            from_validator,
            delegator_id,
            first_pubkey,
            1_000,
            0x90,
        );
        install_legacy_redelegation_bond(
            &mut state,
            Bytes32::from([0x02; 32]),
            from_validator,
            delegator_id,
            second_pubkey,
            1_000,
            0x91,
        );
        state.height = DELEGATOR_IDENTITY_REGISTRY_HEIGHT - 2;
        state.tip_hash = Bytes32::ZERO;

        let pre_gate = governance_redelegate_op(
            delegator_id,
            &first_keypair,
            pre_gate_proposal,
            from_validator,
            to_validator,
            500,
            1,
        );
        let mut pre_gate_block =
            make_block_at_height(&state, vec![], DELEGATOR_IDENTITY_REGISTRY_HEIGHT - 1, 0);
        pre_gate_block.governance_ops.push(pre_gate);
        apply_block(&mut state, &pre_gate_block, 0).unwrap();
        assert!(state.delegator_identities.is_empty());
        assert_eq!(
            state
                .governance
                .proposals
                .get(&pre_gate_proposal)
                .unwrap()
                .redelegations
                .len(),
            1
        );

        let post_gate = governance_redelegate_op(
            delegator_id,
            &first_keypair,
            post_gate_proposal,
            from_validator,
            to_validator,
            500,
            2,
        );
        let mut old_behavior = state.clone();
        apply_governance_op(
            &mut old_behavior,
            &post_gate,
            0,
            DELEGATOR_IDENTITY_REGISTRY_HEIGHT - 1,
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        assert_eq!(
            old_behavior
                .governance
                .proposals
                .get(&post_gate_proposal)
                .unwrap()
                .redelegations
                .len(),
            1
        );

        let before_post_gate = state.clone();
        let mut post_gate_block =
            make_block_at_height(&state, vec![], DELEGATOR_IDENTITY_REGISTRY_HEIGHT, 0);
        post_gate_block.governance_ops.push(post_gate);
        let err = apply_block(&mut state, &post_gate_block, 0).unwrap_err();
        assert!(matches!(
            err,
            StateError::InvalidGovernanceOp { reason }
                if reason.contains("delegator identity has ambiguous legacy pubkeys")
        ));
        assert_eq!(state, before_post_gate);
    }

    #[test]
    fn validator_identity_activation_replay_is_deterministic_before_gate_and_populates_after_gate()
    {
        let mut initial = ChainState::new_genesis();
        initial.validators = ValidatorSet::new();
        initial.height = DELEGATOR_IDENTITY_REGISTRY_HEIGHT - 2;
        initial.tip_hash = Bytes32::ZERO;

        let (pre_op, pre_validator_id) = signed_register_validator_op(&mut initial, [0x94; 32], 1);
        let pre_pubkey = match &pre_op.body {
            StakingOpBody::RegisterValidator {
                validator_pubkey, ..
            } => validator_pubkey.clone(),
            _ => unreachable!(),
        };
        let mut pre_block =
            make_block_at_height(&initial, vec![], DELEGATOR_IDENTITY_REGISTRY_HEIGHT - 1, 0);
        pre_block.staking_ops.push(pre_op);

        let mut first_replay = initial.clone();
        let mut second_replay = initial.clone();
        apply_block(&mut first_replay, &pre_block, 0).unwrap();
        apply_block(&mut second_replay, &pre_block, 0).unwrap();
        assert_eq!(first_replay, second_replay);
        assert!(first_replay.validators.get(&pre_validator_id).is_some());
        assert!(!first_replay
            .delegator_identities
            .contains_key(&pre_validator_id));
        assert_ne!(
            first_replay.delegator_identities.get(&pre_validator_id),
            Some(&pre_pubkey)
        );

        let (post_op, post_validator_id) =
            signed_register_validator_op(&mut first_replay, [0x95; 32], 1);
        let post_pubkey = match &post_op.body {
            StakingOpBody::RegisterValidator {
                validator_pubkey, ..
            } => validator_pubkey.clone(),
            _ => unreachable!(),
        };
        second_replay = first_replay.clone();
        let mut post_block =
            make_block_at_height(&first_replay, vec![], DELEGATOR_IDENTITY_REGISTRY_HEIGHT, 0);
        post_block.staking_ops.push(post_op.clone());
        let mut post_block_second = make_block_at_height(
            &second_replay,
            vec![],
            DELEGATOR_IDENTITY_REGISTRY_HEIGHT,
            0,
        );
        post_block_second.staking_ops.push(post_op);

        apply_block(&mut first_replay, &post_block, 0).unwrap();
        apply_block(&mut second_replay, &post_block_second, 0).unwrap();
        assert_eq!(first_replay, second_replay);
        assert_eq!(
            first_replay.delegator_identities.get(&post_validator_id),
            Some(&post_pubkey)
        );
        assert!(!first_replay
            .delegator_identities
            .contains_key(&pre_validator_id));
    }

    #[test]
    fn payment_key_activation_replay_is_deterministic_before_gate_and_populates_after_gate() {
        let mut initial = ChainState::new_genesis();
        initial.height = PAYMENT_BLINDING_HEIGHT - 2;
        initial.tip_hash = Bytes32::ZERO;

        let owner_keypair = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0xA6; 32]),
            PqKeypair::from_seed(&[0xA6; 32]).unwrap(),
        );
        let owner_pubkey = staking_pubkey_from_keypair(&owner_keypair);
        let owner_id = staking_delegator_id_for_test(&owner_pubkey);
        let pre_payment_pubkey = payment_pubkey(0xA7);
        let pre_op =
            signed_register_payment_key_op(&initial, &owner_keypair, pre_payment_pubkey, 1);
        let mut pre_block = make_block_at_height(&initial, vec![], PAYMENT_BLINDING_HEIGHT - 1, 0);
        pre_block.staking_ops.push(pre_op);

        let mut first_replay = initial.clone();
        let mut second_replay = initial.clone();
        let first_err = apply_block(&mut first_replay, &pre_block, 0).unwrap_err();
        let second_err = apply_block(&mut second_replay, &pre_block, 0).unwrap_err();
        assert!(
            matches!(first_err, StateError::InvalidStakingOp(message) if message.contains("PAYMENT_BLINDING_HEIGHT"))
        );
        assert!(
            matches!(second_err, StateError::InvalidStakingOp(message) if message.contains("PAYMENT_BLINDING_HEIGHT"))
        );
        assert_eq!(first_replay, initial);
        assert_eq!(second_replay, initial);

        let mut activated_initial = initial.clone();
        activated_initial.height = PAYMENT_BLINDING_HEIGHT - 1;
        activated_initial.tip_hash = Bytes32::ZERO;
        first_replay = activated_initial.clone();
        second_replay = activated_initial.clone();

        let post_payment_pubkey = payment_pubkey(0xA8);
        let post_op = signed_register_payment_key_op(
            &activated_initial,
            &owner_keypair,
            post_payment_pubkey.clone(),
            1,
        );
        let mut post_block =
            make_block_at_height(&activated_initial, vec![], PAYMENT_BLINDING_HEIGHT, 0);
        post_block.staking_ops.push(post_op.clone());
        let mut post_block_second =
            make_block_at_height(&second_replay, vec![], PAYMENT_BLINDING_HEIGHT, 0);
        post_block_second.staking_ops.push(post_op);

        apply_block(&mut first_replay, &post_block, 0).unwrap();
        apply_block(&mut second_replay, &post_block_second, 0).unwrap();
        assert_eq!(first_replay, second_replay);
        assert_eq!(
            first_replay.payment_identities.get(&owner_id),
            Some(&post_payment_pubkey)
        );
        assert_eq!(first_replay.staking_nonces.get(&owner_id), Some(&1));
    }

    #[test]
    fn payment_notes_transaction_is_rejected_before_gate() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        state.height = PAYMENT_BLINDING_HEIGHT - 2;
        state.tip_hash = Bytes32::ZERO;

        let mut tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            input_value,
            input_blinding,
            Bytes32::from([0xB1; 32]),
        );
        set_v2_payment_notes(
            &mut tx,
            &keypair,
            &state.chain_id.clone(),
            vec![Some(payment_note(0xB2))],
        );
        let block = make_block_at_height(&state, vec![tx], PAYMENT_BLINDING_HEIGHT - 1, 0);

        let before = state.clone();
        let err = apply_block(&mut state, &block, 0).unwrap_err();
        assert!(matches!(
            err,
            StateError::UnsupportedTxVersion {
                version: TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES
            }
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn payment_notes_transaction_is_accepted_after_gate_and_mutates_no_new_state() {
        let (mut state, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        state.height = PAYMENT_BLINDING_HEIGHT - 1;
        state.tip_hash = Bytes32::ZERO;
        let original_payment_registry = state.payment_identities.clone();

        let mut tx = make_tx(
            &state,
            &keypair,
            utxo_id,
            input_value,
            input_blinding,
            Bytes32::from([0xB3; 32]),
        );
        set_v2_payment_notes(
            &mut tx,
            &keypair,
            &state.chain_id.clone(),
            vec![Some(payment_note(0xB4))],
        );
        let block = make_block_at_height(&state, vec![tx], PAYMENT_BLINDING_HEIGHT, 0);

        apply_block(&mut state, &block, 0).unwrap();
        assert_eq!(state.payment_identities, original_payment_registry);
        assert!(!state.utxos.contains(&utxo_id));
        assert!(state.nullifiers.contains(&Bytes32::from([0xB3; 32])));
    }

    #[test]
    fn payment_notes_all_none_has_same_spendability_after_gate() {
        let (mut initial, utxo_id, keypair, input_blinding, input_value) = state_with_utxo();
        initial.height = PAYMENT_BLINDING_HEIGHT - 1;
        initial.tip_hash = Bytes32::ZERO;

        let legacy_tx = make_tx(
            &initial,
            &keypair,
            utxo_id,
            input_value,
            input_blinding,
            Bytes32::from([0xB5; 32]),
        );
        let mut explicit_none_tx = legacy_tx.clone();
        set_v2_payment_notes(
            &mut explicit_none_tx,
            &keypair,
            &initial.chain_id.clone(),
            vec![None],
        );

        let mut legacy_state = initial.clone();
        let legacy_block =
            make_block_at_height(&legacy_state, vec![legacy_tx], PAYMENT_BLINDING_HEIGHT, 0);
        apply_block(&mut legacy_state, &legacy_block, 0).unwrap();

        let mut explicit_none_state = initial;
        let explicit_none_block = make_block_at_height(
            &explicit_none_state,
            vec![explicit_none_tx],
            PAYMENT_BLINDING_HEIGHT,
            0,
        );
        apply_block(&mut explicit_none_state, &explicit_none_block, 0).unwrap();

        assert_eq!(legacy_state.total_supply, explicit_none_state.total_supply);
        assert_eq!(legacy_state.burn_buffer, explicit_none_state.burn_buffer);
        assert_eq!(
            legacy_state.fee_reward_pool,
            explicit_none_state.fee_reward_pool
        );
        assert_eq!(
            legacy_state.utxos.all_entries().count(),
            explicit_none_state.utxos.all_entries().count()
        );
        assert_eq!(
            legacy_state
                .utxos
                .all_entries()
                .map(|entry| entry.output.value_spark)
                .collect::<Vec<_>>(),
            explicit_none_state
                .utxos
                .all_entries()
                .map(|entry| entry.output.value_spark)
                .collect::<Vec<_>>()
        );
        assert!(!legacy_state.utxos.contains(&utxo_id));
        assert!(!explicit_none_state.utxos.contains(&utxo_id));
    }

    #[test]
    fn payment_notes_activation_boundary_replay_is_deterministic_for_mixed_transactions() {
        let mut initial = ChainState::new_genesis();
        initial.height = PAYMENT_BLINDING_HEIGHT - 1;
        initial.tip_hash = Bytes32::ZERO;
        let (owner_pubkey, keypair) = make_test_keypair([0xB6; 32]);
        let mut inputs = Vec::new();
        for index in 0..3u8 {
            let input_blinding = [0xB7u8.wrapping_add(index); 32];
            let output = output_with_value(
                TEST_INPUT_VALUE + index as u64,
                owner_pubkey.clone(),
                0xB7u8.wrapping_add(index),
            );
            let utxo_id = initial.utxos.insert(output, 0, 0, index as u32).unwrap();
            inputs.push((utxo_id, TEST_INPUT_VALUE + index as u64, input_blinding));
        }

        let legacy_tx = make_tx(
            &initial,
            &keypair,
            inputs[0].0,
            inputs[0].1,
            inputs[0].2,
            Bytes32::from([0xBA; 32]),
        );
        let mut noted_tx = make_tx(
            &initial,
            &keypair,
            inputs[1].0,
            inputs[1].1,
            inputs[1].2,
            Bytes32::from([0xBB; 32]),
        );
        set_v2_payment_notes(
            &mut noted_tx,
            &keypair,
            &initial.chain_id.clone(),
            vec![Some(payment_note(0xBC))],
        );
        let mut all_none_tx = make_tx(
            &initial,
            &keypair,
            inputs[2].0,
            inputs[2].1,
            inputs[2].2,
            Bytes32::from([0xBD; 32]),
        );
        set_v2_payment_notes(
            &mut all_none_tx,
            &keypair,
            &initial.chain_id.clone(),
            vec![None],
        );

        let mut first_replay = initial.clone();
        let mut second_replay = initial;
        let first_block = make_block_at_height(
            &first_replay,
            vec![legacy_tx.clone(), noted_tx.clone(), all_none_tx.clone()],
            PAYMENT_BLINDING_HEIGHT,
            0,
        );
        let second_block = make_block_at_height(
            &second_replay,
            vec![legacy_tx, noted_tx, all_none_tx],
            PAYMENT_BLINDING_HEIGHT,
            0,
        );

        apply_block(&mut first_replay, &first_block, 0).unwrap();
        apply_block(&mut second_replay, &second_block, 0).unwrap();
        assert_eq!(first_replay, second_replay);
    }

    #[test]
    fn payment_blinding_capstone_cross_gate_block_sequence_is_deterministic() {
        let mut initial = ChainState::new_genesis();
        initial.height = PAYMENT_BLINDING_HEIGHT - 2;
        initial.tip_hash = Bytes32::ZERO;
        let (tx_owner_pubkey, tx_keypair) = make_test_keypair([0xC0; 32]);
        let mut spendable = Vec::new();
        for index in 0..4u8 {
            let blinding = [0xC1u8.wrapping_add(index); 32];
            let output = output_with_value(
                TEST_INPUT_VALUE + 50_000 + index as u64,
                tx_owner_pubkey.clone(),
                0xC1u8.wrapping_add(index),
            );
            let utxo_id = initial.utxos.insert(output, 0, 10, index as u32).unwrap();
            spendable.push((utxo_id, TEST_INPUT_VALUE + 50_000 + index as u64, blinding));
        }

        let pre_gate_tx = make_tx(
            &initial,
            &tx_keypair,
            spendable[0].0,
            spendable[0].1,
            spendable[0].2,
            Bytes32::from([0xD0; 32]),
        );
        let pre_gate_tx_bytes = pre_gate_tx.encode_to_vec();
        let pre_gate_block = make_block_at_height(
            &initial,
            vec![pre_gate_tx.clone()],
            PAYMENT_BLINDING_HEIGHT - 1,
            111,
        );
        let mut first = initial.clone();
        let mut second = initial;
        apply_block(&mut first, &pre_gate_block, 0).unwrap();
        apply_block(&mut second, &pre_gate_block, 0).unwrap();
        assert_eq!(pre_gate_tx.encode_to_vec(), pre_gate_tx_bytes);
        assert_same_consensus_state(&first, &second);
        assert!(first.payment_identities.is_empty());

        let mut post_base = first;
        let (registered_validator_op, registered_validator_id) =
            signed_register_validator_op(&mut post_base, [0xD1; 32], 1);
        let (governance_pubkey, governance_keypair, governance_validator_id) =
            install_governance_validator(&mut post_base, [0xD2; 32], 10_000_000_000);
        let governance_deposit_id = post_base
            .utxos
            .insert(
                governance_deposit_output(
                    governance_pubkey.clone(),
                    post_base.governance.params.proposal_deposit_spark,
                ),
                0,
                11,
                0,
            )
            .unwrap();

        let legacy_post_gate_tx = make_tx(
            &post_base,
            &tx_keypair,
            spendable[1].0,
            spendable[1].1,
            spendable[1].2,
            Bytes32::from([0xD3; 32]),
        );
        let mut noted_post_gate_tx = make_tx(
            &post_base,
            &tx_keypair,
            spendable[2].0,
            spendable[2].1,
            spendable[2].2,
            Bytes32::from([0xD4; 32]),
        );
        set_v2_payment_notes(
            &mut noted_post_gate_tx,
            &tx_keypair,
            &post_base.chain_id.clone(),
            vec![Some(payment_note(0xD5))],
        );
        let mut all_none_post_gate_tx = make_tx(
            &post_base,
            &tx_keypair,
            spendable[3].0,
            spendable[3].1,
            spendable[3].2,
            Bytes32::from([0xD6; 32]),
        );
        set_v2_payment_notes(
            &mut all_none_post_gate_tx,
            &tx_keypair,
            &post_base.chain_id.clone(),
            vec![None],
        );

        let (payment_owner_pubkey, payment_owner_keypair) = make_test_keypair([0xD7; 32]);
        let payment_owner_id = Bytes32::from(sha256(&payment_owner_pubkey.classical_pk.0));
        let payment_key = payment_pubkey(0xD8);
        let register_payment_op = signed_register_payment_key_op(
            &post_base,
            &payment_owner_keypair,
            payment_key.clone(),
            1,
        );
        let governance_op = governance_propose_op(
            governance_validator_id,
            &governance_keypair,
            governance_pubkey,
            governance_deposit_id,
            1,
            GovernableAction::SetMinDelegationSpark {
                value: DUST_LIMIT_SPARK,
            },
        );

        let mut post_block = make_block_at_height(
            &post_base,
            vec![
                legacy_post_gate_tx,
                noted_post_gate_tx,
                all_none_post_gate_tx,
            ],
            PAYMENT_BLINDING_HEIGHT,
            222,
        );
        post_block.staking_ops = vec![register_payment_op, registered_validator_op];
        post_block.governance_ops = vec![governance_op];

        let mut first_post_replay = post_base.clone();
        let mut second_post_replay = post_base;
        apply_block(&mut first_post_replay, &post_block, 0).unwrap();
        apply_block(&mut second_post_replay, &post_block, 0).unwrap();

        assert_same_consensus_state(&first_post_replay, &second_post_replay);
        assert_eq!(
            first_post_replay.payment_identities.get(&payment_owner_id),
            Some(&payment_key)
        );
        assert!(first_post_replay
            .validators
            .get(&registered_validator_id)
            .is_some());
        assert_eq!(first_post_replay.governance.proposals.len(), 1);
    }

    #[test]
    fn identity_registry_capstone_rejects_all_substitution_attacks_and_preserves_state() {
        let mut base = ChainState::new_genesis();
        let first_validator = Bytes32::from([0xA1; 32]);
        let second_validator = Bytes32::from([0xA2; 32]);
        base.validators
            .upsert(active_validator(first_validator))
            .unwrap();
        base.validators
            .upsert(active_validator(second_validator))
            .unwrap();

        let (legit_pubkey, legit_keypair) = make_mixed_test_keypair([0xA3; 32], [0xA4; 32]);
        let (attacker_pubkey, attacker_keypair) = make_mixed_test_keypair([0xA3; 32], [0xA5; 32]);
        let delegator_id = staking_delegator_id_for_test(&legit_pubkey);
        assert_eq!(
            staking_delegator_id_for_test(&attacker_pubkey),
            delegator_id
        );
        assert_ne!(attacker_pubkey, legit_pubkey);
        base.delegator_identities
            .insert(delegator_id, legit_pubkey.clone());

        install_legacy_redelegation_bond(
            &mut base,
            Bytes32::from([0xA6; 32]),
            first_validator,
            delegator_id,
            legit_pubkey.clone(),
            DUST_LIMIT_SPARK,
            0xA6,
        );
        install_legacy_redelegation_bond(
            &mut base,
            Bytes32::from([0xA7; 32]),
            second_validator,
            delegator_id,
            legit_pubkey.clone(),
            DUST_LIMIT_SPARK,
            0xA7,
        );
        base.delegations
            .update_delegator(&second_validator, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();

        let proposal_id = Bytes32::from([0xA8; 32]);
        install_reveal_phase_governance_proposal(
            &mut base,
            proposal_id,
            first_validator,
            second_validator,
        );

        let (validator_pubkey, validator_keypair) = make_mixed_test_keypair([0xA9; 32], [0xAA; 32]);
        let (attacker_validator_pubkey, attacker_validator_keypair) =
            make_mixed_test_keypair([0xA9; 32], [0xAB; 32]);
        let validator_id = staking_delegator_id_for_test(&validator_pubkey);
        assert_eq!(
            staking_delegator_id_for_test(&attacker_validator_pubkey),
            validator_id
        );
        base.validators
            .upsert(ValidatorEntry {
                validator_id,
                name: "capstone-validator".into(),
                hybrid_classical_pk: Some(validator_pubkey.classical_pk.0),
                hybrid_pq_pk: Some(validator_pubkey.pq_pk.as_slice().to_vec()),
                vrf_pk: Some([0xA9; 32]),
                stake_spark: MINIMUM_VALIDATOR_BOND_SPARK,
                status: ValidatorStatus::Active,
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
                cold_key_status: crate::validator::ColdKeyStatus::Unenrolled,
                cold_nonce: 0,
            })
            .unwrap();
        base.delegator_identities
            .insert(validator_id, validator_pubkey.clone());

        let chain_id = base.chain_id.clone();

        let mut legitimate_delegate_state = base.clone();
        let legit_delegate_utxo = legitimate_delegate_state
            .utxos
            .insert(
                output_with_value(DUST_LIMIT_SPARK, legit_pubkey.clone(), 0xB0),
                0,
                0,
                0,
            )
            .unwrap();
        let legit_delegate = signed_delegate_op(
            &legitimate_delegate_state,
            second_validator,
            legit_delegate_utxo,
            legit_pubkey.clone(),
            &legit_keypair,
            1,
        );
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut legitimate_delegate_state,
            &legit_delegate,
            &chain_id,
            DELEGATOR_IDENTITY_REGISTRY_HEIGHT,
            true,
        )
        .unwrap();
        let new_bond = legitimate_delegate_state
            .staked_bonds
            .get(&legit_delegate_utxo)
            .unwrap();
        assert!(new_bond.original_output.range_proof.is_none());
        assert!(new_bond.original_output.owner_pubkey.is_some());

        let attack_delegate_utxo = base
            .utxos
            .insert(
                output_with_value(DUST_LIMIT_SPARK, attacker_pubkey.clone(), 0xB1),
                0,
                0,
                1,
            )
            .unwrap();
        let delegate_attack = signed_delegate_op(
            &base,
            first_validator,
            attack_delegate_utxo,
            attacker_pubkey.clone(),
            &attacker_keypair,
            1,
        );
        let mut candidate = base.clone();
        let err = crate::delegation::apply_staking_op_with_identity_activation(
            &mut candidate,
            &delegate_attack,
            &chain_id,
            DELEGATOR_IDENTITY_REGISTRY_HEIGHT,
            true,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            StateError::InvalidStakingOp(reason)
                if reason.contains("delegator identity registry pubkey mismatch")
        ));
        assert_eq!(candidate, base);

        let undelegate_attack = signed_undelegate_op(
            &base,
            first_validator,
            Bytes32::from([0xA6; 32]),
            attacker_pubkey.clone(),
            &attacker_keypair,
            1,
        );
        let mut candidate = base.clone();
        let err = crate::delegation::apply_staking_op_with_identity_activation(
            &mut candidate,
            &undelegate_attack,
            &chain_id,
            DELEGATOR_IDENTITY_REGISTRY_HEIGHT,
            true,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            StateError::InvalidStakingOp(reason)
                if reason.contains("delegator identity registry pubkey mismatch")
        ));
        assert_eq!(candidate, base);

        let claim_attack = signed_claim_rewards_op(
            &base,
            second_validator,
            attacker_pubkey.clone(),
            &attacker_keypair,
            1,
        );
        let mut candidate = base.clone();
        let err = crate::delegation::apply_staking_op_with_identity_activation(
            &mut candidate,
            &claim_attack,
            &chain_id,
            DELEGATOR_IDENTITY_REGISTRY_HEIGHT,
            true,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            StateError::InvalidStakingOp(reason)
                if reason.contains("delegator identity registry pubkey mismatch")
        ));
        assert_eq!(candidate, base);

        let governance_attack = governance_redelegate_op(
            delegator_id,
            &attacker_keypair,
            proposal_id,
            first_validator,
            second_validator,
            DUST_LIMIT_SPARK / 2,
            1,
        );
        let mut candidate = base.clone();
        let err = apply_governance_op(
            &mut candidate,
            &governance_attack,
            0,
            DELEGATOR_IDENTITY_REGISTRY_HEIGHT,
            DEFAULT_CHAIN_ID,
        )
        .unwrap_err();
        assert!(matches!(err, StateError::GovernanceSignatureInvalid { .. }));
        assert_eq!(candidate, base);

        let self_stake_utxo = base
            .utxos
            .insert(
                output_with_value(DUST_LIMIT_SPARK, attacker_validator_pubkey.clone(), 0xB2),
                0,
                0,
                2,
            )
            .unwrap();
        let self_stake_attack = signed_self_stake_op(
            &base,
            self_stake_utxo,
            attacker_validator_pubkey,
            &attacker_validator_keypair,
            1,
        );
        let mut candidate = base.clone();
        let err = crate::delegation::apply_staking_op_with_identity_activation(
            &mut candidate,
            &self_stake_attack,
            &chain_id,
            DELEGATOR_IDENTITY_REGISTRY_HEIGHT,
            true,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            StateError::InvalidStakingOp(reason)
                if reason.contains("validator identity stored pubkey mismatch")
        ));
        assert_eq!(candidate, base);

        let mut legitimate_claim_state = base.clone();
        let legit_claim = signed_claim_rewards_op(
            &legitimate_claim_state,
            second_validator,
            legit_pubkey.clone(),
            &legit_keypair,
            1,
        );
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut legitimate_claim_state,
            &legit_claim,
            &chain_id,
            DELEGATOR_IDENTITY_REGISTRY_HEIGHT,
            true,
        )
        .unwrap();
        assert_eq!(
            legitimate_claim_state
                .delegations
                .get_delegators(&second_validator)
                .iter()
                .find(|entry| entry.delegator_id == delegator_id)
                .unwrap()
                .pending_rewards,
            0
        );

        let mut legitimate_governance_state = base.clone();
        let legitimate_governance = governance_redelegate_op(
            delegator_id,
            &legit_keypair,
            proposal_id,
            first_validator,
            second_validator,
            DUST_LIMIT_SPARK / 2,
            1,
        );
        apply_governance_op(
            &mut legitimate_governance_state,
            &legitimate_governance,
            0,
            DELEGATOR_IDENTITY_REGISTRY_HEIGHT,
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        assert_eq!(
            legitimate_governance_state
                .governance
                .proposals
                .get(&proposal_id)
                .unwrap()
                .redelegations
                .len(),
            1
        );

        let mut legitimate_self_stake_state = base.clone();
        let self_stake_utxo = legitimate_self_stake_state
            .utxos
            .insert(
                output_with_value(DUST_LIMIT_SPARK, validator_pubkey.clone(), 0xB3),
                0,
                0,
                3,
            )
            .unwrap();
        let legitimate_self_stake = signed_self_stake_op(
            &legitimate_self_stake_state,
            self_stake_utxo,
            validator_pubkey,
            &validator_keypair,
            1,
        );
        crate::delegation::apply_staking_op_with_identity_activation(
            &mut legitimate_self_stake_state,
            &legitimate_self_stake,
            &chain_id,
            DELEGATOR_IDENTITY_REGISTRY_HEIGHT,
            true,
        )
        .unwrap();
        let self_bond = legitimate_self_stake_state
            .staked_bonds
            .get(&self_stake_utxo)
            .unwrap();
        assert!(self_bond.original_output.owner_pubkey.is_some());
    }

    #[test]
    fn identity_registry_capstone_rejected_mixed_block_rolls_back_prior_successes() {
        let mut state = ChainState::new_genesis();
        state.height = DELEGATOR_IDENTITY_REGISTRY_HEIGHT - 1;
        state.tip_hash = Bytes32::ZERO;
        let validator_id = Bytes32::from([0xB4; 32]);
        state
            .validators
            .upsert(active_validator(validator_id))
            .unwrap();

        let (legit_pubkey, legit_keypair) = make_mixed_test_keypair([0xB5; 32], [0xB6; 32]);
        let (attacker_pubkey, attacker_keypair) = make_mixed_test_keypair([0xB5; 32], [0xB7; 32]);
        let delegator_id = staking_delegator_id_for_test(&legit_pubkey);
        state
            .delegator_identities
            .insert(delegator_id, legit_pubkey.clone());
        state.staking_nonces.insert(delegator_id, 1);
        install_legacy_redelegation_bond(
            &mut state,
            Bytes32::from([0xB8; 32]),
            validator_id,
            delegator_id,
            legit_pubkey.clone(),
            DUST_LIMIT_SPARK,
            0xB8,
        );
        state
            .delegations
            .update_delegator(&validator_id, &delegator_id, |entry| {
                entry.pending_rewards = DUST_LIMIT_SPARK;
            })
            .unwrap();
        let legit_utxo = state
            .utxos
            .insert(
                output_with_value(DUST_LIMIT_SPARK, legit_pubkey.clone(), 0xB9),
                0,
                0,
                0,
            )
            .unwrap();

        let legit_delegate = signed_delegate_op(
            &state,
            validator_id,
            legit_utxo,
            legit_pubkey,
            &legit_keypair,
            2,
        );
        let attack_claim =
            signed_claim_rewards_op(&state, validator_id, attacker_pubkey, &attacker_keypair, 3);
        let mut rejected_block =
            make_block_at_height(&state, vec![], DELEGATOR_IDENTITY_REGISTRY_HEIGHT, 0);
        rejected_block.staking_ops.push(legit_delegate.clone());
        rejected_block.staking_ops.push(attack_claim);

        let before = state.clone();
        let err = apply_block(&mut state, &rejected_block, 0).unwrap_err();
        assert!(matches!(
            err,
            StateError::InvalidStakingOp(reason)
                if reason.contains("delegator identity registry pubkey mismatch")
        ));
        assert_eq!(state, before);
        assert!(!state.staked_bonds.contains_key(&legit_utxo));
        assert_eq!(state.staking_nonces.get(&delegator_id), Some(&1));
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

        let mut clean_block =
            make_block_at_height(&state, vec![], DELEGATOR_IDENTITY_REGISTRY_HEIGHT, 0);
        clean_block.staking_ops.push(legit_delegate);
        apply_block(&mut state, &clean_block, 0).unwrap();
        let clean_bond = state.staked_bonds.get(&legit_utxo).unwrap();
        assert!(clean_bond.original_output.range_proof.is_none());
        assert!(clean_bond.original_output.owner_pubkey.is_some());
        assert_eq!(state.staking_nonces.get(&delegator_id), Some(&2));
    }

    #[test]
    fn state_txn_rolls_back_slashing_scope_failpoints() {
        let (state, validator_id, keypair) =
            slash_validator_state([0x62; 32], MINIMUM_VALIDATOR_BOND_SPARK);
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let mut block = make_block(&state, vec![]);
        block.slashing_evidence.push(evidence);
        let mutation_count = assert_all_failpoints_roll_back(&state, &block);
        assert!(
            mutation_count >= 4,
            "slashing block should exercise scoped undo mutations, got {mutation_count}"
        );
    }

    #[test]
    fn state_txn_rolls_back_epoch_transition_scope_failpoints() {
        let mut state = ChainState::new_genesis();
        state.height = EPOCH_DURATION_BLOCKS - 1;
        let block = make_block(&state, vec![]);
        assert!(is_epoch_boundary(block.header.height));
        let mutation_count = assert_all_failpoints_roll_back(&state, &block);
        assert!(
            mutation_count >= 4,
            "epoch-boundary block should exercise scoped undo mutations, got {mutation_count}"
        );
    }

    #[test]
    fn state_txn_rolls_back_governance_proposal_failpoints() {
        let mut state = ChainState::new_genesis();
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
        reveal_state.governance.gov_nonces.insert(proposer_id, 1);
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
        let mut state = ChainState::new_genesis();
        state.height = u64::MAX - 1;
        state.tip_hash = Bytes32::ZERO;
        let block = BlockV1 {
            header: BlockHeaderV1 {
                protocol_version: ProtocolVersion(block_protocol_version_for_height(u64::MAX)),
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
        let rollback_root = rolled_back.state_commitment_v2_root(block.header.height);
        rolled_back.rebuild_state_commitment_v2(block.header.height);
        assert_eq!(
            rolled_back.state_commitment_v2_root(block.header.height),
            rollback_root
        );
        crate::txn::set_fail_after_mutation(None);
    }

    #[test]
    fn state_txn_oracle_matches_clone_atomic_reference_across_block_types() {
        let state = ChainState::new_genesis();
        assert_oracle_matches(&state, &make_block(&state, vec![]), 0);

        let (tx_state, utxo_id, keypair, blinding, value) = state_with_utxo();
        let tx = make_tx(
            &tx_state,
            &keypair,
            utxo_id,
            value,
            blinding,
            Bytes32::from([0xB1; 32]),
        );
        assert_oracle_matches(&tx_state, &make_block(&tx_state, vec![tx]), 0);

        let mut staking_state = ChainState::new_genesis();
        let (staking_op, _) = signed_register_validator_op(&mut staking_state, [0xB2; 32], 1);
        let mut staking_block = make_block(&staking_state, vec![]);
        staking_block.staking_ops.push(staking_op);
        assert_oracle_matches(&staking_state, &staking_block, 0);

        let mut governance_state = ChainState::new_genesis();
        governance_state.governance.params.proposal_deposit_spark = 1_000;
        let (proposer_pubkey, proposer_keypair, proposer_id) =
            install_governance_validator(&mut governance_state, [0xB3; 32], 100_000);
        let deposit = governance_state
            .utxos
            .insert(
                governance_deposit_output(proposer_pubkey.clone(), 1_000),
                0,
                0,
                0,
            )
            .unwrap();
        let governance_op = governance_propose_op(
            proposer_id,
            &proposer_keypair,
            proposer_pubkey,
            deposit,
            1,
            GovernableAction::SetMinDelegationSpark { value: 100_000 },
        );
        let mut governance_block = make_block(&governance_state, vec![]);
        governance_block.governance_ops.push(governance_op);
        assert_oracle_matches(&governance_state, &governance_block, 0);

        let (slash_state, validator_id, slash_keypair) =
            slash_validator_state([0xB4; 32], MINIMUM_VALIDATOR_BOND_SPARK);
        let mut slash_block = make_block(&slash_state, vec![]);
        slash_block.slashing_evidence.push(slash_evidence(
            &slash_keypair,
            validator_id,
            VoteStep::Precommit,
        ));
        assert_oracle_matches(&slash_state, &slash_block, 0);

        let mut epoch_state = ChainState::new_genesis();
        epoch_state.height = EPOCH_DURATION_BLOCKS - 1;
        let epoch_block = make_block(&epoch_state, vec![]);
        assert!(is_epoch_boundary(epoch_block.header.height));
        assert_oracle_matches(&epoch_state, &epoch_block, 123_456);
    }

    fn assert_reference_and_candidate_sequences_match(
        initial: ChainState,
        mut make_next_block: impl FnMut(&ChainState, usize) -> BlockV1,
        count: usize,
    ) {
        let mut reference = initial.clone();
        let mut candidate = initial;
        for index in 0..count {
            let reference_block = make_next_block(&reference, index);
            let candidate_block = reference_block.clone();
            let reference_outcome =
                clone_atomic_reference_apply_block(&reference, &reference_block, index as u64)
                    .unwrap();
            reference = reference_outcome.state;
            apply_block(&mut candidate, &candidate_block, index as u64).unwrap();
            assert_same_consensus_state(&candidate, &reference);
        }
    }

    #[test]
    fn state_txn_replay_determinism_normal_and_epoch_boundary_sequences() {
        assert_reference_and_candidate_sequences_match(
            ChainState::new_genesis(),
            |state, _| make_block(state, vec![]),
            5,
        );

        let mut epoch_initial = ChainState::new_genesis();
        epoch_initial.height = EPOCH_DURATION_BLOCKS - 2;
        assert_reference_and_candidate_sequences_match(
            epoch_initial,
            |state, _| make_block(state, vec![]),
            3,
        );
    }

    #[test]
    fn state_txn_replay_determinism_governance_phase_boundary_sequence() {
        let (mut initial, _, _, proposer_id, proposal_id) =
            governance_proposal_state(ProposalPhase::Deliberation);
        initial.height = EPOCH_DURATION_BLOCKS - 1;
        {
            let proposal = initial.governance.proposals.get_mut(&proposal_id).unwrap();
            proposal.commit_start_epoch = 1;
            proposal.reveal_start_epoch = 2;
            proposal.tally_epoch = 3;
            proposal.executable_after_epoch = 4;
            proposal.snapshot1 = None;
        }
        initial.governance.params.governance_quorum_bps = 4_000;

        let mut reference = initial.clone();
        let mut candidate = initial;
        for target_epoch in 1..=4 {
            reference.height = target_epoch * EPOCH_DURATION_BLOCKS - 1;
            candidate.height = reference.height;
            let block = make_block(&reference, vec![]);
            if target_epoch == 2 {
                let vote_nonce = Bytes32::from([0xC2; 32]);
                let commit_hash =
                    governance_vote_commit_hash(proposal_id, proposer_id, 1, vote_nonce);
                if let Some(proposal) = reference.governance.proposals.get_mut(&proposal_id) {
                    proposal.commits.insert(
                        proposer_id,
                        VoteCommit {
                            validator_id: proposer_id,
                            commit_hash,
                            committed_epoch: 1,
                        },
                    );
                }
                if let Some(proposal) = candidate.governance.proposals.get_mut(&proposal_id) {
                    proposal.commits.insert(
                        proposer_id,
                        VoteCommit {
                            validator_id: proposer_id,
                            commit_hash,
                            committed_epoch: 1,
                        },
                    );
                }
            }
            if target_epoch == 3 {
                if let Some(proposal) = reference.governance.proposals.get_mut(&proposal_id) {
                    proposal.reveals.insert(
                        proposer_id,
                        crate::governance::VoteReveal {
                            validator_id: proposer_id,
                            vote: true,
                            revealed_epoch: 2,
                        },
                    );
                }
                if let Some(proposal) = candidate.governance.proposals.get_mut(&proposal_id) {
                    proposal.reveals.insert(
                        proposer_id,
                        crate::governance::VoteReveal {
                            validator_id: proposer_id,
                            vote: true,
                            revealed_epoch: 2,
                        },
                    );
                }
            }
            let outcome =
                clone_atomic_reference_apply_block(&reference, &block, target_epoch).unwrap();
            reference = outcome.state;
            apply_block(&mut candidate, &block, target_epoch).unwrap();
            assert_same_consensus_state(&candidate, &reference);
        }
    }

    #[test]
    fn state_txn_replay_determinism_rejected_block_then_valid_block() {
        let mut reference = ChainState::new_genesis();
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
    #[ignore = "realistic state transaction clone-cost benchmark; run explicitly with --ignored --nocapture"]
    fn state_txn_realistic_import_clone_cost_benchmark() {
        use std::time::Instant;

        fn realistic_state(staked_bonds: usize) -> ChainState {
            let mut state = ChainState::new_genesis();
            let validator_id = Bytes32::from([0x55; 32]);
            let pq_pk = VariableBytes::from_slice(&vec![0x99; 2_592]).unwrap();
            let range_proof = VariableBytes::from_slice(&vec![0xAA; 674]).unwrap();
            for index in 0..staked_bonds {
                let mut id_bytes = [0u8; 32];
                for (dst, src) in id_bytes
                    .iter_mut()
                    .zip((index as u64).to_le_bytes().into_iter())
                {
                    *dst = src;
                }
                let utxo_id = Bytes32::from(id_bytes);
                let output = OutputV1 {
                    value_spark: 1_000,
                    commitment: CommitmentV1 {
                        compressed_point: Bytes32::from([0x77; 32]),
                    },
                    owner_pubkey: HybridPubKey {
                        classical_pk: Bytes32::from([0x88; 32]),
                        pq_pk: pq_pk.clone(),
                    },
                    range_proof: range_proof.clone(),
                    lock_height: 0,
                };
                state.staked_bonds.insert(
                    utxo_id,
                    StakeBondEntry {
                        utxo_id,
                        validator_id,
                        delegator_id: Bytes32::from([0x66; 32]),
                        amount_spark: 1_000,
                        bonded_epoch: 0,
                        unbonding_end_epoch: None,
                        custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                            Bytes32::from([0x66; 32]),
                        ),
                        original_output: output.into(),
                    },
                );
            }
            state
        }

        for size in [100_000usize, 1_000_000usize] {
            let state = realistic_state(size);
            let block = make_block(&state, vec![]);

            let start = Instant::now();
            let mut projected_before = state.clone();
            let mut scratch_before = projected_before.clone();
            apply_block(&mut scratch_before, &block, 0).unwrap();
            projected_before = scratch_before;
            let before = start.elapsed();

            let start = Instant::now();
            let mut projected_after = state.clone();
            apply_block(&mut projected_after, &block, 0).unwrap();
            let after = start.elapsed();

            let mut undo_only_state = state.clone();
            let start = Instant::now();
            apply_block(&mut undo_only_state, &block, 0).unwrap();
            let undo_only = start.elapsed();

            println!(
                "state_txn_realistic_import_clone_cost size={size} simulated_before_two_clones={before:?} after_outer_clone_plus_undo={after:?} undo_only={undo_only:?} final_heights=({}, {}, {})",
                projected_before.height,
                projected_after.height,
                undo_only_state.height
            );
        }
    }

    #[test]
    #[ignore = "realistic production/reproposal projection benchmark; run explicitly with --ignored --nocapture"]
    fn project_block_for_roots_realistic_projection_benchmark() {
        use std::time::Instant;

        fn realistic_state(staked_bonds: usize) -> ChainState {
            let mut state = ChainState::new_genesis();
            let validator_id = Bytes32::from([0x75; 32]);
            let pq_pk = VariableBytes::from_slice(&vec![0x99; 2_592]).unwrap();
            let range_proof = VariableBytes::from_slice(&vec![0xAA; 674]).unwrap();
            for index in 0..staked_bonds {
                let mut id_bytes = [0u8; 32];
                for (dst, src) in id_bytes
                    .iter_mut()
                    .zip((index as u64).to_le_bytes().into_iter())
                {
                    *dst = src;
                }
                let utxo_id = Bytes32::from(id_bytes);
                let output = OutputV1 {
                    value_spark: 1_000,
                    commitment: CommitmentV1 {
                        compressed_point: Bytes32::from([0x77; 32]),
                    },
                    owner_pubkey: HybridPubKey {
                        classical_pk: Bytes32::from([0x88; 32]),
                        pq_pk: pq_pk.clone(),
                    },
                    range_proof: range_proof.clone(),
                    lock_height: 0,
                };
                state.staked_bonds.insert(
                    utxo_id,
                    StakeBondEntry {
                        utxo_id,
                        validator_id,
                        delegator_id: Bytes32::from([0x66; 32]),
                        amount_spark: 1_000,
                        bonded_epoch: 0,
                        unbonding_end_epoch: None,
                        custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                            Bytes32::from([0x66; 32]),
                        ),
                        original_output: output.into(),
                    },
                );
            }
            state
        }

        for size in [100_000usize, 1_000_000usize] {
            let mut state = realistic_state(size);
            let block = make_block(&state, vec![]);

            let start = Instant::now();
            let mut clone_projection = state.clone();
            apply_block(&mut clone_projection, &block, 0).unwrap();
            let state_root = crate::state_root::compute_state_root(&clone_projection);
            let validator_set_root =
                crate::state_root::compute_validator_set_root(&clone_projection);
            let mut clone_projected_block = block.clone();
            clone_projected_block.header.state_root = state_root;
            clone_projected_block.header.validator_set_root = validator_set_root;
            let clone_value_hash =
                clone_projected_block.compute_value_hash(clone_projection.total_supply);
            let clone_projection_elapsed = start.elapsed();

            let start = Instant::now();
            let projected = project_block_for_roots(&mut state, &block, 0).unwrap();
            let rollback_projection_elapsed = start.elapsed();

            assert_eq!(projected.state_root, state_root);
            assert_eq!(projected.validator_set_root, validator_set_root);
            assert_eq!(projected.value_hash, clone_value_hash);
            println!(
                "project_block_for_roots_realistic_projection size={size} clone_based_projection={clone_projection_elapsed:?} rollback_projection={rollback_projection_elapsed:?}"
            );
        }
    }

    fn max_cap_stress_state_and_block() -> (ChainState, BlockV1) {
        let mut state = ChainState::new_genesis();

        let (tx_owner_pubkey, tx_keypair) = make_test_keypair([0xD0; 32]);
        let mut multi_inputs = Vec::new();
        for index in 0..MAX_INPUTS {
            let seed = 0x10u8.saturating_add(index as u8);
            let value = TEST_INPUT_VALUE + seed as u64 + 10_000;
            let utxo_id = state
                .utxos
                .insert(
                    output_with_value(value, tx_owner_pubkey.clone(), seed),
                    0,
                    0,
                    index as u32,
                )
                .unwrap();
            multi_inputs.push((utxo_id, value, [seed; 32], Bytes32::from([seed; 32])));
        }
        let mut transactions = vec![make_multi_io_tx(
            &state,
            &tx_keypair,
            &multi_inputs,
            MAX_OUTPUTS,
        )];
        for index in 1..MAX_TX_PER_BLOCK {
            let seed = 0x30u8.wrapping_add(index as u8);
            let value = TEST_INPUT_VALUE + seed as u64 + 10_000;
            let utxo_id = state
                .utxos
                .insert(
                    output_with_value(value, tx_owner_pubkey.clone(), seed),
                    0,
                    1,
                    index as u32,
                )
                .unwrap();
            transactions.push(make_tx(
                &state,
                &tx_keypair,
                utxo_id,
                value,
                [seed; 32],
                Bytes32::from([seed.wrapping_add(1); 32]),
            ));
        }
        assert_eq!(transactions.len(), MAX_TX_PER_BLOCK);
        assert_eq!(transactions[0].inputs.len(), MAX_INPUTS);
        assert_eq!(transactions[0].outputs.len(), MAX_OUTPUTS);

        let mut staking_ops = Vec::new();
        for index in 0..MAX_STAKING_OPS_PER_BLOCK {
            let seed = [0xE0u8.wrapping_add(index as u8); 32];
            let (op, _) = signed_register_validator_op(&mut state, seed, 1);
            staking_ops.push(op);
        }
        assert_eq!(staking_ops.len(), MAX_STAKING_OPS_PER_BLOCK);

        let (proposer_pubkey, proposer_keypair, proposer_id) =
            install_governance_validator(&mut state, [0xA1; 32], 100_000);
        let action = GovernableAction::SetMinDelegationSpark { value: 100_000 };
        let proposal_id = compute_proposal_id(proposer_id, &action, 0, DEFAULT_CHAIN_ID);
        let mut proposal = test_proposal_record(
            proposal_id,
            proposer_id,
            proposer_pubkey,
            action,
            ProposalPhase::Commit,
        );
        let mut weights = BTreeMap::from([(proposer_id, 100_000)]);
        let mut governance_signers = vec![(proposer_id, proposer_keypair)];
        for index in 1..MAX_GOV_OPS_PER_BLOCK {
            let (_, keypair, validator_id) =
                install_governance_validator(&mut state, [0xA1u8 + index as u8; 32], 100_000);
            weights.insert(validator_id, 100_000);
            governance_signers.push((validator_id, keypair));
        }
        proposal.snapshot1 = Some(GovernanceSnapshot {
            weights,
            total_stake: 100_000 * MAX_GOV_OPS_PER_BLOCK as u64,
        });
        state.governance.proposals.insert(proposal_id, proposal);
        let governance_ops = governance_signers
            .iter()
            .enumerate()
            .map(|(index, (validator_id, keypair))| {
                governance_commit_op(
                    *validator_id,
                    keypair,
                    proposal_id,
                    Bytes32::from([0xB0u8.wrapping_add(index as u8); 32]),
                    1,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(governance_ops.len(), MAX_GOV_OPS_PER_BLOCK);

        let mut slashing_evidence = Vec::new();
        for index in 0..MAX_SLASHES_PER_BLOCK {
            let (slash_state, validator_id, keypair) =
                slash_validator_state([0xC0u8.wrapping_add(index as u8); 32], 100_000);
            let validator = slash_state.validators.get(&validator_id).unwrap().clone();
            state.validators.upsert(validator).unwrap();
            slashing_evidence.push(slash_evidence(&keypair, validator_id, VoteStep::Precommit));
        }
        assert_eq!(slashing_evidence.len(), MAX_SLASHES_PER_BLOCK);

        let mut block = make_block(&state, transactions);
        block.staking_ops = staking_ops;
        block.governance_ops = governance_ops;
        block.slashing_evidence = slashing_evidence;

        (state, block)
    }

    #[test]
    #[ignore = "max-cap block validation timing guard; run explicitly with --release --ignored --nocapture"]
    fn max_cap_block_apply_release_timing_guard() {
        use std::time::{Duration, Instant};

        const RELEASE_APPLY_LIMIT: Duration = Duration::from_secs(4);

        if cfg!(debug_assertions) {
            eprintln!(
                "max_cap_block_apply_release_timing_guard skipped: run with `cargo test -p indra-state max_cap_block_apply_release_timing_guard --release -- --ignored --nocapture`. Debug builds are expected to be dramatically slower and must not be interpreted as release-regression evidence."
            );
            return;
        }

        // This fixture intentionally mirrors the max-cap StateTxn stress case:
        // 200 transactions total, including one 16-input/16-output transaction,
        // plus 10 staking ops, 5 governance ops, and 3 slash evidence entries.
        //
        // This guard is meaningful only for optimized validator-style builds.
        // In debug mode, the same crypto-heavy validation path has measured
        // roughly 14x slower during this session; debug timing is useful for
        // local profiling only, not for deployment-risk conclusions.
        //
        // The 4s limit is deliberately below the 6s target block time while
        // leaving broad headroom over the current ~1.3s release measurement on
        // the development Mac. If this trips in release mode, re-check hardware
        // and load first, then treat a repeatable failure as a real regression.
        let (state, block) = max_cap_stress_state_and_block();
        let start = Instant::now();
        let mut applied = state.clone();
        apply_block(&mut applied, &block, 0).unwrap();
        let elapsed = start.elapsed();
        println!(
            "max_cap_block_apply_release_timing_guard elapsed={elapsed:?} limit={RELEASE_APPLY_LIMIT:?} txs={} max_inputs={} max_outputs={} staking_ops={} governance_ops={} slashes={}",
            MAX_TX_PER_BLOCK,
            MAX_INPUTS,
            MAX_OUTPUTS,
            MAX_STAKING_OPS_PER_BLOCK,
            MAX_GOV_OPS_PER_BLOCK,
            MAX_SLASHES_PER_BLOCK,
        );
        assert!(
            elapsed < RELEASE_APPLY_LIMIT,
            "max-cap block apply took {elapsed:?}, exceeding release guard {RELEASE_APPLY_LIMIT:?}"
        );
    }

    #[test]
    #[ignore = "max-cap StateTxn stress benchmark; run explicitly with --ignored --nocapture"]
    fn state_txn_stress_max_op_caps_applies_and_rolls_back() {
        use std::time::Instant;

        let (state, block) = max_cap_stress_state_and_block();

        let time_apply_case = |label: &str, block: &BlockV1| {
            let start = Instant::now();
            let mut candidate = state.clone();
            apply_block(&mut candidate, block, 0).unwrap();
            let elapsed = start.elapsed();
            println!("state_txn_max_cap_component {label}={elapsed:?}");
            elapsed
        };
        let tx_only = make_block(&state, block.transactions.clone());
        let mut staking_only = make_block(&state, vec![]);
        staking_only.staking_ops = block.staking_ops.clone();
        let mut governance_only = make_block(&state, vec![]);
        governance_only.governance_ops = block.governance_ops.clone();
        let mut slash_only = make_block(&state, vec![]);
        slash_only.slashing_evidence = block.slashing_evidence.clone();
        let start = Instant::now();
        let mut seen_tx_hashes: HashSet<Vec<u8>> = HashSet::new();
        let mut block_nullifiers: HashSet<Bytes32> = HashSet::new();
        let mut block_input_utxos: HashSet<Bytes32> = HashSet::new();
        for tx in &tx_only.transactions {
            assert!(seen_tx_hashes.insert(tx.encode_to_vec()));
            validate_transaction(
                &state,
                tx,
                &state.chain_id,
                &mut block_nullifiers,
                &mut block_input_utxos,
                tx_only.header.height,
            )
            .unwrap();
        }
        let tx_validation_only_elapsed = start.elapsed();
        let tx_input_count = tx_only
            .transactions
            .iter()
            .map(|tx| tx.inputs.len())
            .sum::<usize>();
        let tx_output_count = tx_only
            .transactions
            .iter()
            .map(|tx| tx.outputs.len())
            .sum::<usize>();
        println!(
            "state_txn_max_cap_component tx_validation_only={tx_validation_only_elapsed:?} tx_inputs={tx_input_count} tx_outputs={tx_output_count}"
        );
        let tx_only_elapsed = time_apply_case("tx_only", &tx_only);
        let staking_only_elapsed = time_apply_case("staking_only", &staking_only);
        let governance_only_elapsed = time_apply_case("governance_only", &governance_only);
        let slash_only_elapsed = time_apply_case("slash_only", &slash_only);

        crate::txn::reset_timing();
        crate::txn::set_fail_after_mutation(None);
        let start = Instant::now();
        let mut applied = state.clone();
        apply_block(&mut applied, &block, 0).unwrap();
        let apply_elapsed = start.elapsed();
        let apply_txn_timing = crate::txn::timing();

        let mutation_count = crate::txn::mutation_count();
        let fail_after = mutation_count.max(1);
        crate::txn::set_fail_after_mutation(Some(fail_after));
        crate::txn::reset_timing();
        let start = Instant::now();
        let mut rolled_back = state.clone();
        let err = apply_block(&mut rolled_back, &block, 0).unwrap_err();
        let rollback_elapsed = start.elapsed();
        let rollback_txn_timing = crate::txn::timing();
        assert!(err
            .to_string()
            .contains("state transaction failpoint injected after mutation"));
        assert_same_consensus_state(&rolled_back, &state);
        crate::txn::set_fail_after_mutation(None);

        println!(
            "state_txn_max_cap_stress txs={} max_inputs={} max_outputs={} staking_ops={} governance_ops={} slashes={} mutation_count={} fail_after={} apply={apply_elapsed:?} rollback={rollback_elapsed:?} apply_undo_recording={:?} rollback_undo_recording={:?} rollback_only={:?} components=(tx_only:{tx_only_elapsed:?}, staking_only:{staking_only_elapsed:?}, governance_only:{governance_only_elapsed:?}, slash_only:{slash_only_elapsed:?})",
            MAX_TX_PER_BLOCK,
            MAX_INPUTS,
            MAX_OUTPUTS,
            MAX_STAKING_OPS_PER_BLOCK,
            MAX_GOV_OPS_PER_BLOCK,
            MAX_SLASHES_PER_BLOCK,
            mutation_count,
            fail_after,
            apply_txn_timing.undo_recording,
            rollback_txn_timing.undo_recording,
            rollback_txn_timing.rollback,
        );
    }

    #[test]
    fn block_protocol_version_validation_is_strict_allow_list() {
        let mut state = ChainState::new_genesis();
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
    fn apply_block_rejects_too_many_staking_ops() {
        let mut state = ChainState::new_genesis();
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
        let mut state = ChainState::new_genesis();
        let (op, validator_id) = signed_register_validator_op(&mut state, [0x42; 32], 1);
        let original = state.clone();
        let mut block = make_block(&state, vec![]);
        block.staking_ops = vec![op.clone(), op];

        assert!(matches!(
            apply_block(&mut state, &block, 0),
            Err(StateError::StakingNonceInvalid { .. })
        ));
        assert_eq!(state, original);
        assert!(state.validators.get(&validator_id).is_none());
    }

    #[test]
    fn staking_nonces_committed_to_state_root() {
        let mut a = ChainState::new_genesis();
        let mut b = ChainState::new_genesis();
        a.staking_nonces.insert(Bytes32::from([0xAA; 32]), 1);
        b.staking_nonces.insert(Bytes32::from([0xAA; 32]), 2);

        assert_ne!(
            crate::state_root::compute_state_root(&a),
            crate::state_root::compute_state_root(&b)
        );
    }

    #[test]
    fn staked_bonds_in_state_root() {
        let mut a = ChainState::new_genesis();
        let mut b = ChainState::new_genesis();
        let (delegator_pubkey, _) = make_test_keypair([0x77; 32]);
        let delegator_id = pubkey_to_id_for_test(&delegator_pubkey);
        let validator_id = Bytes32::from([0x66; 32]);
        let output = dummy_output(0x07, delegator_pubkey);

        a.staked_bonds.insert(
            Bytes32::from([0xA1; 32]),
            StakeBondEntry {
                utxo_id: Bytes32::from([0xA1; 32]),
                validator_id,
                delegator_id,
                amount_spark: 1_000_000,
                bonded_epoch: 1,
                unbonding_end_epoch: None,
                custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                    delegator_id,
                ),
                original_output: output.clone().into(),
            },
        );
        b.staked_bonds.insert(
            Bytes32::from([0xB2; 32]),
            StakeBondEntry {
                utxo_id: Bytes32::from([0xB2; 32]),
                validator_id,
                delegator_id,
                amount_spark: 1_000_000,
                bonded_epoch: 1,
                unbonding_end_epoch: None,
                custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                    delegator_id,
                ),
                original_output: output.into(),
            },
        );

        assert_ne!(
            crate::state_root::compute_state_root(&a),
            crate::state_root::compute_state_root(&b)
        );
    }

    #[test]
    fn apply_empty_block_advances_height() {
        let mut state = ChainState::new_genesis();
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block, 0).unwrap();
        assert_eq!(state.height, 1);
    }

    #[test]
    fn apply_block_empty_and_nonempty_fast_paths_replay_deterministically() {
        let mut initial = ChainState::new_genesis();
        let (register_op, _validator_id) =
            signed_register_validator_op(&mut initial, [0x91; 32], 1);

        let mut continuous = initial.clone();
        let mut blocks = Vec::new();
        let mut continuous_roots = Vec::new();

        let block1 = make_block(&continuous, vec![]);
        apply_block(&mut continuous, &block1, 0).unwrap();
        continuous_roots.push(crate::state_root::compute_state_root(&continuous));
        blocks.push(block1);

        let mut block2 = make_block(&continuous, vec![]);
        block2.staking_ops = vec![register_op];
        apply_block(&mut continuous, &block2, 0).unwrap();
        assert_eq!(continuous.validators.len(), 1);
        continuous_roots.push(crate::state_root::compute_state_root(&continuous));
        blocks.push(block2);

        let block3 = make_block(&continuous, vec![]);
        apply_block(&mut continuous, &block3, 0).unwrap();
        continuous_roots.push(crate::state_root::compute_state_root(&continuous));
        blocks.push(block3);

        let mut replayed = initial;
        for (block, expected_root) in blocks.iter().zip(continuous_roots.iter()) {
            apply_block(&mut replayed, block, 0).unwrap();
            assert_eq!(
                crate::state_root::compute_state_root(&replayed),
                *expected_root
            );
        }
        assert_eq!(replayed, continuous);
    }

    #[test]
    fn apply_block_nonempty_governance_shadow_still_rejects_invalid_op_before_real_apply() {
        let mut state = ChainState::new_genesis();
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
    fn apply_block_success_at_epoch_boundary_commits_all_changes() {
        let mut state = ChainState::new_genesis();
        state.height = EPOCH_DURATION_BLOCKS - 1;
        let block = make_block(&state, vec![]);
        let expected_hash = block.header.block_hash();

        let record = apply_block(&mut state, &block, 0).unwrap();

        assert!(record.is_some());
        assert_eq!(state.height, EPOCH_DURATION_BLOCKS);
        assert_eq!(state.tip_hash, expected_hash);
    }

    #[test]
    fn apply_block_epoch_transition_failure_leaves_state_unchanged() {
        let mut state = ChainState::new_genesis();
        state.height = EPOCH_DURATION_BLOCKS - 1;
        let (owner_pubkey, _) = make_test_keypair([0x62; 32]);
        let validator_id = Bytes32::from([0x63; 32]);
        let bond_id = Bytes32::from([0x64; 32]);
        let output = output_with_value(1_000_000, owner_pubkey, 0x65);
        state
            .utxos
            .insert(output.clone(), EPOCH_DURATION_BLOCKS, STAKING_TX_IDX, 1)
            .unwrap();
        state.staked_bonds.insert(
            bond_id,
            StakeBondEntry {
                utxo_id: bond_id,
                validator_id,
                delegator_id: validator_id,
                amount_spark: 1_000_000,
                bonded_epoch: 0,
                unbonding_end_epoch: Some(epoch_for_height(EPOCH_DURATION_BLOCKS)),
                custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                    validator_id,
                ),
                original_output: output.into(),
            },
        );
        let original = state.clone();
        let block = make_block(&state, vec![]);

        assert_eq!(
            apply_block(&mut state, &block, 0),
            Err(StateError::InvariantViolation {
                message: "UTXO ID collision in staking bond release",
            })
        );
        assert_eq!(
            state, original,
            "epoch-transition failure must not partially mutate block state"
        );
    }

    #[test]
    fn apply_block_updates_tip_hash() {
        let mut state = ChainState::new_genesis();
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
    fn apply_block_with_delegate_removes_utxo() {
        let mut state = ChainState::new_genesis();
        let (delegator_pubkey, keypair) = make_test_keypair([0x71; 32]);
        let output = dummy_output(0x08, delegator_pubkey.clone());
        let bond_utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();
        let validator_id = Bytes32::from([0x72; 32]);
        state
            .validators
            .upsert(active_validator(validator_id))
            .unwrap();

        let op = signed_delegate_op(
            &state,
            validator_id,
            bond_utxo_id,
            delegator_pubkey,
            &keypair,
            1,
        );
        let mut block = make_block(&state, vec![]);
        block.staking_ops = vec![op];

        apply_block(&mut state, &block, 0).unwrap();

        assert!(!state.utxos.contains(&bond_utxo_id));
        assert!(state.staked_bonds.contains_key(&bond_utxo_id));
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
        let mut state = ChainState::new_genesis();
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
        let mut state = ChainState::new_genesis();
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
        let mut state = ChainState::new_genesis();
        let mut block = make_block(&state, vec![]);
        block.header.base_fee = 9999; // wrong
        assert!(matches!(
            apply_block(&mut state, &block, 0),
            Err(StateError::BaseFeeIncorrect { .. })
        ));
    }

    #[test]
    fn unknown_utxo_rejected() {
        let mut state = ChainState::new_genesis();
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
        let mut state = ChainState::new_genesis();
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
        let mut state = ChainState::new_genesis();
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
    fn apply_slash_double_precommit_reduces_stake_5pct() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x81; 32], 1_000_000);
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let chain_id = state.chain_id.clone();
        apply_slash(&mut state, &evidence, &chain_id).unwrap();
        assert_eq!(
            state.validators.get(&validator_id).unwrap().stake_spark,
            950_000
        );
    }

    #[test]
    fn apply_slash_rejects_prevote_conflict() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x82; 32], 1_000_000);
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Prevote);
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_slash(&mut state, &evidence, &chain_id),
            Err(StateError::InvalidSlashEvidence { .. })
        ));
        assert_eq!(
            state.validators.get(&validator_id).unwrap().stake_spark,
            1_000_000
        );
    }

    #[test]
    fn apply_slash_rejects_duplicate_evidence() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x83; 32], 1_000_000);
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let chain_id = state.chain_id.clone();
        apply_slash(&mut state, &evidence, &chain_id).unwrap();
        assert_eq!(
            apply_slash(&mut state, &evidence, &chain_id),
            Err(StateError::SlashAlreadyApplied)
        );
    }

    #[test]
    fn apply_slash_rejects_invalid_vote_signature() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x84; 32], 1_000_000);
        let mut evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        evidence.vote_2.signature.classical_sig = VariableBytes::from_slice(&[0x42; 64]).unwrap();
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_slash(&mut state, &evidence, &chain_id),
            Err(StateError::InvalidSlashEvidence { .. })
        ));
    }

    #[test]
    fn apply_slash_rejects_nil_votes() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x85; 32], 1_000_000);
        let evidence = SlashEvidenceV1 {
            validator_id,
            vote_1: signed_vote(
                &keypair,
                validator_id,
                7,
                0,
                VoteStep::Precommit,
                Bytes32::ZERO,
            ),
            vote_2: signed_vote(
                &keypair,
                validator_id,
                7,
                0,
                VoteStep::Precommit,
                Bytes32::from([0xBB; 32]),
            ),
        };
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_slash(&mut state, &evidence, &chain_id),
            Err(StateError::InvalidSlashEvidence { .. })
        ));
    }

    #[test]
    fn apply_slash_rejects_same_block_hash() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x86; 32], 1_000_000);
        let hash = Bytes32::from([0xAA; 32]);
        let evidence = SlashEvidenceV1 {
            validator_id,
            vote_1: signed_vote(&keypair, validator_id, 7, 0, VoteStep::Precommit, hash),
            vote_2: signed_vote(&keypair, validator_id, 7, 0, VoteStep::Precommit, hash),
        };
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_slash(&mut state, &evidence, &chain_id),
            Err(StateError::InvalidSlashEvidence { .. })
        ));
    }

    #[test]
    fn apply_slash_rejects_already_slashed_validator() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x87; 32], 1_000_000);
        state.validators.get_mut(&validator_id).unwrap().status = ValidatorStatus::Slashed;
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let chain_id = state.chain_id.clone();
        assert!(matches!(
            apply_slash(&mut state, &evidence, &chain_id),
            Err(StateError::InvalidSlashEvidence { .. })
        ));
    }

    #[test]
    fn apply_slash_burns_stake_reduces_total_supply() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x88; 32], 1_000_000);
        let before = state.total_supply;
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let chain_id = state.chain_id.clone();
        apply_slash(&mut state, &evidence, &chain_id).unwrap();
        assert_eq!(state.total_supply, before - 50_000);
    }

    #[test]
    fn slash_without_reporter_burns_full_amount() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x89; 32], 1_000_000);
        let supply_before = state.total_supply;
        let treasury_before = state.treasury_balance;
        let utxo_count_before = state.utxos.len();
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let chain_id = state.chain_id.clone();
        apply_slash(&mut state, &evidence, &chain_id).unwrap();
        assert_eq!(state.total_supply, supply_before - 50_000);
        assert_eq!(state.treasury_balance, treasury_before);
        assert_eq!(state.utxos.len(), utxo_count_before);
    }

    #[test]
    fn slash_reporter_identity_recovered_without_vrf_verify() {
        let mut state = ChainState::new_genesis();
        let proposer_id = Bytes32::from([0xA9; 32]);
        let other_id = Bytes32::from([0xB9; 32]);
        state
            .validators
            .upsert(active_validator(proposer_id))
            .unwrap();
        state.validators.upsert(active_validator(other_id)).unwrap();

        let mut block = make_block(&state, vec![]);
        block.header.proposer_vrf_output = Bytes32::from([0x4D; 32]);
        block.header.proposer_vrf_proof = VariableBytes::from_slice(&[]).unwrap();
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
            slash_reporter_validator_id_for_block(&state, &block),
            Some(proposer_id),
            "commit-reveal reporter identity must come from QC-attested election_result_hash, not live VRF proof verification"
        );
    }

    #[test]
    fn slash_reporter_identity_no_match_returns_none() {
        let mut state = ChainState::new_genesis();
        state
            .validators
            .upsert(active_validator(Bytes32::from([0xC1; 32])))
            .unwrap();
        state
            .validators
            .upsert(active_validator(Bytes32::from([0xC2; 32])))
            .unwrap();

        let mut block = make_block(&state, vec![]);
        block.header.proposer_vrf_output = Bytes32::from([0x4E; 32]);
        block.header.election_result_hash = Some(Bytes32::from([0xEE; 32]));

        assert_eq!(slash_reporter_validator_id_for_block(&state, &block), None);
    }

    #[test]
    fn slash_reporter_identity_multiple_match_returns_none() {
        let proposer_id = Bytes32::from([0xD1; 32]);
        let state = ChainState::new_genesis();
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
    fn slash_reporter_reward_is_50_percent() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x97; 32], 10_000_000);
        let (reporter_pubkey, _) = make_test_keypair([0xA1; 32]);
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let chain_id = state.chain_id.clone();
        let supply_before = state.total_supply;

        let accounting = apply_slash_at_height_with_accounting(
            &mut state,
            &evidence,
            &chain_id,
            9,
            Some(&reporter_pubkey),
        )
        .unwrap();

        assert_eq!(accounting.slash_amount, 500_000);
        assert_eq!(accounting.reporter_reward, 250_000);
        assert_eq!(accounting.burned, 250_000);
        assert_eq!(state.total_supply, supply_before - 250_000);
    }

    #[test]
    fn slash_creates_utxo_for_reporter() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x98; 32], 10_000_000);
        let (reporter_pubkey, _) = make_test_keypair([0xA2; 32]);
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let evidence_hash = compute_slash_evidence_hash(&evidence);
        let blinding = derive_slash_reward_blinding(&evidence_hash, 9);
        let chain_id = state.chain_id.clone();

        apply_slash_at_height(&mut state, &evidence, &chain_id, 9, Some(&reporter_pubkey)).unwrap();

        let reward = state
            .utxos
            .all_entries()
            .find(|entry| {
                entry.created_height == 9
                    && entry.output.owner_pubkey == reporter_pubkey
                    && entry.output.value_spark == 250_000
            })
            .expect("reporter reward UTXO must exist");
        assert!(indra_crypto::verify_opening(
            &PedersenCommitment(reward.output.commitment.compressed_point.0),
            &PedersenOpening {
                value: 250_000,
                blinding,
            }
        )
        .is_ok());
        assert!(indra_crypto::verify_range(
            &reward.output.commitment.compressed_point.0,
            reward.output.range_proof.as_slice(),
        )
        .is_ok());
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

    #[test]
    fn slash_reward_below_dust_limit_burns_entirely() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x99; 32], 1_000_000);
        let (reporter_pubkey, _) = make_test_keypair([0xA3; 32]);
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let chain_id = state.chain_id.clone();
        let supply_before = state.total_supply;
        let utxo_count_before = state.utxos.len();

        let accounting = apply_slash_at_height_with_accounting(
            &mut state,
            &evidence,
            &chain_id,
            9,
            Some(&reporter_pubkey),
        )
        .unwrap();

        assert_eq!(accounting.slash_amount, 50_000);
        assert_eq!(accounting.reporter_reward, 0);
        assert_eq!(accounting.burned, 50_000);
        assert_eq!(state.total_supply, supply_before - 50_000);
        assert_eq!(state.utxos.len(), utxo_count_before);
    }

    #[test]
    fn treasury_no_longer_receives_slash_reporter_reward() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x9A; 32], 10_000_000);
        let (reporter_pubkey, _) = make_test_keypair([0xA4; 32]);
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let chain_id = state.chain_id.clone();
        let treasury_before = state.treasury_balance;

        apply_slash_at_height(&mut state, &evidence, &chain_id, 9, Some(&reporter_pubkey)).unwrap();

        assert_eq!(state.treasury_balance, treasury_before);
    }

    #[test]
    fn total_supply_invariant_after_slash_with_reporter() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x9B; 32], 10_000_000);
        let (reporter_pubkey, _) = make_test_keypair([0xA5; 32]);
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let chain_id = state.chain_id.clone();
        let supply_before = state.total_supply;
        let treasury_before = state.treasury_balance;

        let accounting = apply_slash_at_height_with_accounting(
            &mut state,
            &evidence,
            &chain_id,
            9,
            Some(&reporter_pubkey),
        )
        .unwrap();

        assert_eq!(
            accounting.slash_amount,
            accounting.burned + accounting.reporter_reward
        );
        assert_eq!(state.total_supply, supply_before - accounting.burned);
        assert_eq!(state.treasury_balance, treasury_before);
        let reporter_utxo_total: u64 = state
            .utxos
            .all_entries()
            .filter(|entry| entry.output.owner_pubkey == reporter_pubkey)
            .map(|entry| entry.output.value_spark)
            .sum();
        assert_eq!(reporter_utxo_total, accounting.reporter_reward);
    }

    #[test]
    fn apply_slash_reduces_staked_bonds_proportionally() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x8A; 32], 1_000_000);
        let bond_id = Bytes32::from([0xB1; 32]);
        let (owner, _) = make_test_keypair([0x91; 32]);
        state.staked_bonds.insert(
            bond_id,
            StakeBondEntry {
                utxo_id: bond_id,
                validator_id,
                delegator_id: validator_id,
                amount_spark: 200_000,
                bonded_epoch: 0,
                unbonding_end_epoch: None,
                custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                    validator_id,
                ),
                original_output: dummy_output(0x20, owner).into(),
            },
        );
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let chain_id = state.chain_id.clone();
        apply_slash(&mut state, &evidence, &chain_id).unwrap();
        assert_eq!(
            state.staked_bonds.get(&bond_id).unwrap().amount_spark,
            190_000
        );
    }

    #[test]
    fn apply_slash_leaves_delegator_bond_accounting_unchanged() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x8B; 32], 1_000_000);
        let delegator_id = Bytes32::from([0xD2; 32]);
        let bond_id = Bytes32::from([0xB2; 32]);
        let (owner, _) = make_test_keypair([0x92; 32]);
        state
            .delegations
            .add_delegation(validator_id, delegator_id, 200_000, 0)
            .unwrap();
        state.staked_bonds.insert(
            bond_id,
            StakeBondEntry {
                utxo_id: bond_id,
                validator_id,
                delegator_id,
                amount_spark: 200_000,
                bonded_epoch: 0,
                unbonding_end_epoch: None,
                custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                    delegator_id,
                ),
                original_output: dummy_output(0x21, owner).into(),
            },
        );
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let chain_id = state.chain_id.clone();
        apply_slash(&mut state, &evidence, &chain_id).unwrap();
        assert_eq!(
            state
                .delegations
                .get_delegators(&validator_id)
                .iter()
                .find(|entry| entry.delegator_id == delegator_id)
                .unwrap()
                .staked_spark,
            200_000
        );
    }

    #[test]
    fn self_unstake_before_slash_evidence_does_not_reduce_slash_amount() {
        let original_bond = 1_000_000u64;
        let (mut state, validator_id, keypair) = slash_validator_state([0x8F; 32], 0);
        let bond_id = Bytes32::from([0xC1; 32]);
        let (owner, _) = make_test_keypair([0x93; 32]);
        state.staked_bonds.insert(
            bond_id,
            StakeBondEntry {
                utxo_id: bond_id,
                validator_id,
                delegator_id: validator_id,
                amount_spark: original_bond,
                bonded_epoch: 0,
                unbonding_end_epoch: Some(1 + UNBONDING_PERIOD_EPOCHS),
                custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                    validator_id,
                ),
                original_output: output_with_value(original_bond, owner, 0x22).into(),
            },
        );

        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let chain_id = state.chain_id.clone();
        apply_slash_at_height(
            &mut state,
            &evidence,
            &chain_id,
            EPOCH_DURATION_BLOCKS + 1,
            None,
        )
        .unwrap();

        assert_eq!(
            state.staked_bonds.get(&bond_id).unwrap().amount_spark,
            950_000,
            "unbonding self-bond must remain slashable for pre-unbonding equivocation"
        );
        assert_eq!(state.total_supply, GENESIS_SUPPLY_SPARK - 50_000);
    }

    #[test]
    fn self_unstake_after_evidence_window_is_not_slashable() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x90; 32], 1_000_000);
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let chain_id = state.chain_id.clone();
        let too_late_height =
            (SLASH_EVIDENCE_WINDOW_EPOCHS + 1).saturating_mul(EPOCH_DURATION_BLOCKS);

        assert!(matches!(
            apply_slash_at_height(&mut state, &evidence, &chain_id, too_late_height, None),
            Err(StateError::InvalidSlashEvidence { reason })
                if reason.contains("outside evidence window")
        ));
        assert_eq!(
            state.validators.get(&validator_id).unwrap().stake_spark,
            1_000_000
        );
    }

    #[test]
    fn slash_covers_both_active_and_unbonding_bonds_within_window() {
        let active_bond = 600_000u64;
        let unbonding_bond = 400_000u64;
        let (mut state, validator_id, keypair) = slash_validator_state([0x91; 32], active_bond);
        let active_bond_id = Bytes32::from([0xC2; 32]);
        let unbonding_bond_id = Bytes32::from([0xC3; 32]);
        let (owner_active, _) = make_test_keypair([0x94; 32]);
        let (owner_unbonding, _) = make_test_keypair([0x95; 32]);
        state.staked_bonds.insert(
            active_bond_id,
            StakeBondEntry {
                utxo_id: active_bond_id,
                validator_id,
                delegator_id: validator_id,
                amount_spark: active_bond,
                bonded_epoch: 0,
                unbonding_end_epoch: None,
                custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                    validator_id,
                ),
                original_output: output_with_value(active_bond, owner_active, 0x23).into(),
            },
        );
        state.staked_bonds.insert(
            unbonding_bond_id,
            StakeBondEntry {
                utxo_id: unbonding_bond_id,
                validator_id,
                delegator_id: validator_id,
                amount_spark: unbonding_bond,
                bonded_epoch: 0,
                unbonding_end_epoch: Some(1 + UNBONDING_PERIOD_EPOCHS),
                custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                    validator_id,
                ),
                original_output: output_with_value(unbonding_bond, owner_unbonding, 0x24).into(),
            },
        );

        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let chain_id = state.chain_id.clone();
        apply_slash_at_height(
            &mut state,
            &evidence,
            &chain_id,
            EPOCH_DURATION_BLOCKS + 1,
            None,
        )
        .unwrap();

        assert_eq!(
            state
                .staked_bonds
                .get(&active_bond_id)
                .unwrap()
                .amount_spark,
            570_000
        );
        assert_eq!(
            state
                .staked_bonds
                .get(&unbonding_bond_id)
                .unwrap()
                .amount_spark,
            380_000
        );
        assert_eq!(
            state.validators.get(&validator_id).unwrap().stake_spark,
            570_000,
            "active stake should track only the active bond slash"
        );
        assert_eq!(state.total_supply, GENESIS_SUPPLY_SPARK - 50_000);
    }

    #[test]
    fn apply_block_with_slash_evidence_full_flow() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x8C; 32], 1_000_000);
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let mut block = make_block(&state, vec![]);
        block.slashing_evidence = vec![evidence.clone()];
        apply_block(&mut state, &block, 0).unwrap();
        assert!(state
            .applied_slash_hashes
            .contains(&compute_slash_evidence_hash(&evidence)));
        assert!(matches!(
            state.validators.get(&validator_id).unwrap().status,
            ValidatorStatus::Slashed
        ));
    }

    #[test]
    fn apply_block_rejects_duplicate_slash_in_same_block() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x8D; 32], 1_000_000);
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let mut block = make_block(&state, vec![]);
        block.slashing_evidence = vec![evidence.clone(), evidence];
        assert_eq!(
            apply_block(&mut state, &block, 0),
            Err(StateError::DuplicateSlashEvidence)
        );
    }

    #[test]
    fn applied_slash_hashes_change_state_root() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x8E; 32], 1_000_000);
        let before = crate::state_root::compute_state_root(&state);
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        state
            .applied_slash_hashes
            .insert(compute_slash_evidence_hash(&evidence));
        assert_ne!(before, crate::state_root::compute_state_root(&state));
    }
}
