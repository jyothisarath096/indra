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
    codec::Encode,
    types::{
        block::BlockV1,
        primitives::{
            Bytes32, ProtocolVersion, HARD_CAP_SPARK, MAX_BLOCK_SIZE_BYTES, MAX_GOV_OPS_PER_BLOCK,
            MAX_STAKING_OPS_PER_BLOCK, MAX_TX_PER_BLOCK, PROTOCOL_VERSION,
        },
        slashing::SlashEvidenceV1,
        transaction::TransactionV1,
        vote::VoteV1,
    },
    EpochRecord,
};
use indra_crypto::{
    verify_balance, verify_hybrid, verify_opening, verify_range, PedersenCommitment,
    PedersenOpening,
};

use crate::{
    chain::ChainState,
    delegation::apply_staking_op,
    epoch::{apply_epoch_transition, epoch_for_height, is_epoch_boundary},
    error::{StateError, StateResult},
    fee::compute_next_base_fee,
    governance_apply::apply_governance_op,
};

/// Apply slash evidence to chain state.
///
/// Verification is fail-fast and performs no state mutation until all checks pass.
pub fn apply_slash(
    state: &mut ChainState,
    evidence: &SlashEvidenceV1,
    chain_id: &str,
) -> StateResult<()> {
    use crate::ValidatorStatus;
    use indra_core::types::{primitives::SLASH_REPORTER_REWARD_BPS, vote::VoteStep};

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
        VoteStep::Prevote => state.governance.params.slash_surround_vote_bps,
    };

    let current_stake = state
        .validators
        .get(&validator_id)
        .map(|v| v.stake_spark)
        .unwrap_or(0);
    let slash_amount = current_stake
        .saturating_mul(slash_bps as u64)
        .saturating_div(10_000);
    let reporter_reward = slash_amount
        .saturating_mul(SLASH_REPORTER_REWARD_BPS as u64)
        .saturating_div(10_000);
    let burned = slash_amount.saturating_sub(reporter_reward);

    if let Some(v) = state.validators.get_mut(&validator_id) {
        v.stake_spark = v.stake_spark.saturating_sub(slash_amount);
        v.status = ValidatorStatus::Slashed;
    }

    let bond_ids: Vec<Bytes32> = state
        .staked_bonds
        .values()
        .filter(|bond| {
            bond.validator_id == validator_id
                && bond.delegator_id == validator_id
                && bond.unbonding_end_epoch.is_none()
        })
        .map(|bond| bond.utxo_id)
        .collect();

    let mut total_bond_slashed: u64 = 0;
    for bond_id in &bond_ids {
        if let Some(bond) = state.staked_bonds.get_mut(bond_id) {
            let bond_slash = bond
                .amount_spark
                .saturating_mul(slash_bps as u64)
                .saturating_div(10_000);
            bond.amount_spark = bond.amount_spark.saturating_sub(bond_slash);
            total_bond_slashed = total_bond_slashed.saturating_add(bond_slash);
        }
    }

    state.total_supply = state.total_supply.saturating_sub(burned);
    state.treasury_balance = state.treasury_balance.saturating_add(reporter_reward);
    state.applied_slash_hashes.insert(evidence_hash);

    eprintln!(
        "[slash] validator {} slashed {}bps — stake_burned={} self_bond_slashed={} treasury_reward={}",
        hex::encode(&validator_id.0[..4]),
        slash_bps,
        burned,
        total_bond_slashed,
        reporter_reward,
    );

    Ok(())
}

/// Compute the canonical slash-evidence hash used for deduplication.
pub fn compute_slash_evidence_hash(evidence: &SlashEvidenceV1) -> Bytes32 {
    Bytes32::from(indra_crypto::sha256(&evidence.encode_to_vec()))
}

fn verify_vote_sig_with_keys(
    vote: &VoteV1,
    classical_pk: &[u8; 32],
    pq_pk_bytes: &[u8],
    _chain_id: &str,
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
    timestamp_secs: u64,
) -> StateResult<Option<EpochRecord>> {
    // ── Phase 1: Block-level validation (read-only) ───────────────────────

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
    // Track nullifiers seen in THIS block to catch intra-block double spends
    let mut block_nullifiers: HashSet<Bytes32> = HashSet::new();

    for tx in &block.transactions {
        validate_transaction(
            state,
            tx,
            &state.chain_id,
            &mut block_nullifiers,
            block.header.height,
        )?;
    }

    {
        let mut shadow = state.clone();
        let chain_id = state.chain_id.clone();
        for op in &block.staking_ops {
            op.validate_structure()
                .map_err(|e| StateError::InvalidStakingOp(e.to_string()))?;
            apply_staking_op(&mut shadow, op, &chain_id, block.header.height)?;
        }
    }

    {
        let mut shadow = state.clone();
        let chain_id = state.chain_id.clone();
        let current_epoch = epoch_for_height(block.header.height);
        for op in &block.governance_ops {
            apply_governance_op(&mut shadow, op, current_epoch, &chain_id)?;
        }
    }

    if !block.slashing_evidence.is_empty() {
        let mut shadow = state.clone();
        let chain_id_clone = state.chain_id.clone();
        for evidence in &block.slashing_evidence {
            apply_slash(&mut shadow, evidence, &chain_id_clone)?;
        }
    }

    // ── Phase 3: State mutation (all validation passed) ───────────────────

    // Apply each transaction
    for (tx_idx, tx) in block.transactions.iter().enumerate() {
        apply_transaction(state, tx, block.header.height, tx_idx as u32)?;
    }

    let chain_id = state.chain_id.clone();
    for op in &block.staking_ops {
        apply_staking_op(state, op, &chain_id, block.header.height).map_err(|_| {
            StateError::InvariantViolation {
                message: "staking op failed on real state after shadow validation",
            }
        })?;
    }

    let current_epoch = epoch_for_height(block.header.height);
    let chain_id = state.chain_id.clone();
    for op in &block.governance_ops {
        apply_governance_op(state, op, current_epoch, &chain_id).map_err(|_| {
            StateError::InvariantViolation {
                message: "governance op failed on real state after shadow validation",
            }
        })?;
    }

    let chain_id_for_slash = state.chain_id.clone();
    for evidence in &block.slashing_evidence {
        let supply_before = state.total_supply;
        let treasury_before = state.treasury_balance;
        apply_slash(state, evidence, &chain_id_for_slash)
            .expect("slash failed on real state after shadow validation — invariant violation");
        let burned = supply_before.saturating_sub(state.total_supply);
        let treasury_reward = state.treasury_balance.saturating_sub(treasury_before);
        state.epoch_slashed_spark = state
            .epoch_slashed_spark
            .saturating_add(burned.saturating_add(treasury_reward));
        state.epoch_slash_event_count = state.epoch_slash_event_count.saturating_add(1);
    }

    // Update base fee for next block
    let next_fee = compute_next_base_fee(state.base_fee, block.transactions.len());
    state.base_fee = next_fee;

    // Advance height and tip hash
    state.height = block.header.height;
    state.tip_hash = block.header.block_hash();

    // Apply epoch transition if this is the last block of an epoch
    let epoch_record = if is_epoch_boundary(state.height) {
        let epoch = epoch_for_height(state.height);
        Some(apply_epoch_transition(state, epoch, timestamp_secs)?)
    } else {
        None
    };

    if state.total_supply > HARD_CAP_SPARK {
        return Err(StateError::InvariantViolation {
            message: "CRITICAL: total supply exceeds hard cap — constitutional invariant violated",
        });
    }

    Ok(epoch_record)
}

/// Validate block-level invariants (does not touch state).
fn validate_block_header(state: &ChainState, block: &BlockV1) -> StateResult<()> {
    // Protocol version
    if block.header.protocol_version.0 != PROTOCOL_VERSION {
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
pub fn validate_transaction(
    state: &ChainState,
    tx: &TransactionV1,
    chain_id: &str,
    block_nullifiers: &mut HashSet<Bytes32>,
    current_height: u64,
) -> StateResult<()> {
    if tx.inputs.is_empty() {
        return Err(StateError::ZeroInputs);
    }
    if tx.outputs.is_empty() {
        return Err(StateError::ZeroOutputs);
    }
    if tx.version != ProtocolVersion::CURRENT {
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
    let mut input_commitments = Vec::with_capacity(tx.inputs.len());

    for input in &tx.inputs {
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

        total_input_value = total_input_value.saturating_add(entry.output.value_spark);
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
    let required_fee = state.base_fee.saturating_mul(weight_kb);
    if tx.fee_amount < required_fee {
        return Err(StateError::FeeTooLow {
            actual: tx.fee_amount,
            required: required_fee,
        });
    }

    let total_output_value = tx
        .outputs
        .iter()
        .fold(0u64, |acc, output| acc.saturating_add(output.value_spark));
    let required_total = total_output_value.saturating_add(tx.fee_amount);
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
    state: &mut ChainState,
    tx: &TransactionV1,
    height: u64,
    tx_index: u32,
) -> StateResult<()> {
    for input in &tx.inputs {
        state.utxos.spend(&input.utxo_id);
        state.nullifiers.insert_or_double_spend(input.nullifier)?;
    }

    // Create outputs: insert new UTXOs
    for (out_idx, output) in tx.outputs.iter().enumerate() {
        state
            .utxos
            .insert(output.clone(), height, tx_index, out_idx as u32)?;
    }

    let burn_amount = tx.fee_amount / 2;
    let validator_amount = tx.fee_amount.saturating_sub(burn_amount);
    state.total_supply = state.total_supply.saturating_sub(burn_amount);
    state.fee_reward_pool = state.fee_reward_pool.saturating_add(validator_amount);
    state.epoch_fees_burned = state.epoch_fees_burned.saturating_add(burn_amount);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainState;
    use crate::validator::{StakeBondEntry, ValidatorEntry, ValidatorStatus};
    use curve25519_dalek::scalar::Scalar;
    use indra_core::{
        types::{
            block::{BlockHeaderV1, BlockV1},
            primitives::INITIAL_BASE_FEE_SPARK_PER_KB,
            slashing::SlashEvidenceV1,
            staking::{StakingOp, StakingOpBody},
            transaction::{InputV1, OutputV1, TransactionV1},
            vote::{VoteStep, VoteV1},
        },
        Bytes32, CommitmentV1, HybridPubKey, HybridSignature, ProtocolVersion, VariableBytes,
    };
    use indra_crypto::{commit, prove_range, ClassicalKeypair, HybridKeypair, PqKeypair};
    use rand::{rngs::StdRng, SeedableRng};

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

    fn sign_staking_op(keypair: &HybridKeypair, chain_id: &str, op: &mut StakingOp) {
        let sig = keypair.sign(&op.signing_bytes(chain_id)).unwrap();
        op.signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
        };
    }

    fn signed_register_validator_op(
        state: &ChainState,
        seed: [u8; 32],
        nonce: u64,
    ) -> (StakingOp, Bytes32) {
        let (validator_pubkey, keypair) = make_test_keypair(seed);
        let validator_id = pubkey_to_id_for_test(&validator_pubkey);
        let mut op = StakingOp {
            body: StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                validator_pubkey,
                vrf_pk: seed,
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
        let mut op = StakingOp {
            body: StakingOpBody::Delegate {
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
            min_delegation_spark: 1,
            auto_delegate_to: None,
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
                min_delegation_spark: 1,
                auto_delegate_to: None,
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
        );
        let sig = keypair.sign(&signing_bytes).unwrap();
        VoteV1 {
            height,
            round,
            step,
            block_hash,
            validator_id,
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
        BlockV1 {
            header: BlockHeaderV1 {
                protocol_version: ProtocolVersion::CURRENT,
                height,
                prev_hash: state.tip_hash,
                timestamp: 1_700_000_000 + height,
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
            },
            transactions: txs,
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────

    #[test]
    fn apply_block_rejects_too_many_staking_ops() {
        let state = ChainState::new_genesis();
        let (op, _) = signed_register_validator_op(&state, [0x41; 32], 1);
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
        let original = state.clone();
        let (op, validator_id) = signed_register_validator_op(&state, [0x42; 32], 1);
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
                original_output: output.clone(),
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
                original_output: output,
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
    fn apply_slash_surround_vote_reduces_stake_10pct() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x82; 32], 1_000_000);
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Prevote);
        let chain_id = state.chain_id.clone();
        apply_slash(&mut state, &evidence, &chain_id).unwrap();
        assert_eq!(
            state.validators.get(&validator_id).unwrap().stake_spark,
            900_000
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
        assert_eq!(state.total_supply, before - 47_500);
    }

    #[test]
    fn apply_slash_rewards_treasury_5pct_of_slash() {
        let (mut state, validator_id, keypair) = slash_validator_state([0x89; 32], 1_000_000);
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let chain_id = state.chain_id.clone();
        apply_slash(&mut state, &evidence, &chain_id).unwrap();
        assert_eq!(state.treasury_balance, 2_500);
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
                original_output: dummy_output(0x20, owner),
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
            .add_delegation(validator_id, delegator_id, 200_000, 0);
        state.staked_bonds.insert(
            bond_id,
            StakeBondEntry {
                utxo_id: bond_id,
                validator_id,
                delegator_id,
                amount_spark: 200_000,
                bonded_epoch: 0,
                unbonding_end_epoch: None,
                original_output: dummy_output(0x21, owner),
            },
        );
        let evidence = slash_evidence(&keypair, validator_id, VoteStep::Precommit);
        let chain_id = state.chain_id.clone();
        apply_slash(&mut state, &evidence, &chain_id).unwrap();
        assert_eq!(
            state
                .delegations
                .get_delegator_mut(&validator_id, &delegator_id)
                .unwrap()
                .staked_spark,
            200_000
        );
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
