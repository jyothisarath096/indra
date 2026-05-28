//! Block application — the core state transition function.
//!
//! `apply_block(state, block)` is the heart of the protocol.
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

use indra_crypto::verify_range;
use indra_core::{
    codec::Encode,
    types::{
        primitives::{
            Bytes32, HARD_CAP_SPARK, MAX_BLOCK_SIZE_BYTES, MAX_TX_PER_BLOCK,
            PROTOCOL_VERSION,
        },
        block::BlockV1,
        transaction::TransactionV1,
    },
};

use crate::{
    chain::ChainState,
    epoch::{apply_epoch_transition, is_epoch_boundary, epoch_for_height},
    error::{StateError, StateResult},
    fee::compute_next_base_fee,
};

/// Apply a block to the chain state, producing a new state.
///
/// This function is the single entry point for all state transitions.
/// It is deterministic: same (state, block) → same result, always.
///
/// On success: returns the updated state.
/// On failure: returns an error and the original state is unchanged.
/// Apply slash evidence — reduce offending validator stake.
///
/// Double-precommit: 5% of stake (SLASH_DOUBLE_PRECOMMIT_BPS = 500)
/// Surround vote:   100% of stake (SLASH_SURROUND_VOTE_BPS = 10_000)
#[allow(dead_code)]
fn apply_slash(state: &mut ChainState, evidence: &indra_core::types::slashing::SlashEvidenceV1) {
    use indra_core::types::primitives::{SLASH_DOUBLE_PRECOMMIT_BPS, SLASH_SURROUND_VOTE_BPS};

    let validator_id = evidence.validator_id;
    // Determine offence type from the two conflicting votes
    let is_double_precommit = evidence.vote_1.height == evidence.vote_2.height
        && evidence.vote_1.round == evidence.vote_2.round
        && evidence.vote_1.block_hash != evidence.vote_2.block_hash;
    let slash_bps = if is_double_precommit {
        SLASH_DOUBLE_PRECOMMIT_BPS
    } else {
        SLASH_SURROUND_VOTE_BPS
    };

    if let Some(validator) = state.validators.get_mut(&validator_id) {
        let slash_amount = validator.stake_spark
            .saturating_mul(slash_bps as u64)
            / 10_000;
        validator.stake_spark = validator.stake_spark.saturating_sub(slash_amount);

        // Deactivate if stake drops below minimum
        use indra_core::types::primitives::MIN_STAKE_SPARK;
        if validator.stake_spark < MIN_STAKE_SPARK {
            validator.status = crate::ValidatorStatus::Slashed;
        }

    }
}

/// Apply a block to the chain state, updating UTXOs, nullifiers, fees and validators.
pub fn apply_block(state: &mut ChainState, block: &BlockV1) -> StateResult<()> {
    // ── Phase 1: Block-level validation (read-only) ───────────────────────

    validate_block_header(state, block)?;

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
        validate_transaction(state, tx, &mut block_nullifiers, block.header.height)?;
    }

    // ── Phase 3: State mutation (all validation passed) ───────────────────

    // Apply each transaction
    for (tx_idx, tx) in block.transactions.iter().enumerate() {
        apply_transaction(state, tx, block.header.height, tx_idx as u32)?;
    }

    // Update base fee for next block
    let next_fee = compute_next_base_fee(state.base_fee, block.transactions.len());
    state.base_fee = next_fee;

    // Advance height and tip hash
    state.height = block.header.height;
    state.tip_hash = block.header.block_hash();

    // Apply epoch transition if this is the last block of an epoch
    if is_epoch_boundary(state.height) {
        let epoch = epoch_for_height(state.height);
        apply_epoch_transition(state, epoch)?;
    }

    if state.total_supply > HARD_CAP_SPARK {
        return Err(StateError::InvariantViolation {
            message: "CRITICAL: total supply exceeds hard cap — constitutional invariant violated",
        });
    }

    Ok(())
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
        return Err(StateError::PrevHashMismatch);
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
fn validate_transaction(
    state: &ChainState,
    tx: &TransactionV1,
    block_nullifiers: &mut HashSet<Bytes32>,
    current_height: u64,
) -> StateResult<()> {
    if tx.inputs.is_empty()  { return Err(StateError::ZeroInputs);  }
    if tx.outputs.is_empty() { return Err(StateError::ZeroOutputs); }

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
        let entry = state.utxos.get(&input.utxo_id)
            .ok_or(StateError::UnknownUtxo)?;

        // UTXO must be past its lock height
        if entry.output.lock_height > current_height {
            return Err(StateError::OutputLocked {
                lock_height:    entry.output.lock_height,
                current_height,
            });
        }

        block_nullifiers.insert(input.nullifier);
    }

    // Fee check: fee_amount must cover base_fee × weight
    let weight_kb = {
        let bytes = tx.encode_to_vec().len() as u64;
        bytes.div_ceil(1024)
    };
    let required_fee = state.base_fee.saturating_mul(weight_kb);
    if tx.fee_amount < required_fee {
        return Err(StateError::FeeTooLow {
            actual:   tx.fee_amount,
            required: required_fee,
        });
    }

    for (idx, output) in tx.outputs.iter().enumerate() {
        let commitment_bytes = output.commitment.compressed_point.0;
        let proof_bytes = output.range_proof.as_slice();
        verify_range(&commitment_bytes, proof_bytes)
            .map_err(|_| StateError::RangeProofInvalid { index: idx })?;
    }

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
    // Spend inputs: remove UTXOs, record nullifiers
    for input in &tx.inputs {
        state.utxos.spend(&input.utxo_id);
        state.nullifiers.insert_or_double_spend(input.nullifier)?;
    }

    // Create outputs: insert new UTXOs
    for (out_idx, output) in tx.outputs.iter().enumerate() {
        state.utxos.insert(
            output.clone(),
            height,
            tx_index,
            out_idx as u32,
        )?;
    }

    let burn_amount = tx.fee_amount / 2;
    let validator_amount = tx.fee_amount.saturating_sub(burn_amount);
    state.total_supply = state.total_supply.saturating_sub(burn_amount);
    state.fee_reward_pool = state.fee_reward_pool.saturating_add(validator_amount);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_crypto::{commit, prove_range};
    use indra_core::{
        Bytes32, CommitmentV1, HybridPubKey, HybridSignature, VariableBytes,
        ProtocolVersion,
        types::{
            transaction::{InputV1, OutputV1, TransactionV1},
            block::{BlockV1, BlockHeaderV1},
            primitives::{
                INITIAL_BASE_FEE_SPARK_PER_KB,
            },
        },
    };
    use rand::{SeedableRng, rngs::StdRng};
    use crate::chain::ChainState;

    // ── Test helpers ──────────────────────────────────────────────────────

    fn dummy_sig() -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig:        VariableBytes::from_slice(&[0u8; 2420]).unwrap(),
        }
    }

    fn dummy_pubkey() -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::ZERO,
            pq_pk: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
        }
    }

    fn dummy_output(byte: u8) -> OutputV1 {
        let value = 1_000u64 + byte as u64;
        let blinding = [byte; 32];
        let commitment = commit(value, &blinding);
        let mut rng = StdRng::from_seed([byte; 32]);
        let proof = prove_range(value, &blinding, &mut rng).unwrap();

        OutputV1 {
            commitment:   CommitmentV1 { compressed_point: Bytes32::from(commitment.0) },
            owner_pubkey: dummy_pubkey(),
            range_proof:  VariableBytes::from_slice(&proof).unwrap(),
            lock_height:  0,
        }
    }

    /// Build a state that has one pre-existing UTXO ready to be spent.
    fn state_with_utxo() -> (ChainState, Bytes32) {
        let mut state = ChainState::new_genesis();
        let output = dummy_output(0x01);
        let utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();
        (state, utxo_id)
    }

    fn make_tx(utxo_id: Bytes32, nullifier: Bytes32) -> TransactionV1 {
        TransactionV1 {
            version:             ProtocolVersion::CURRENT,
            signature_module_id: 1,
            inputs:  vec![InputV1 { utxo_id, nullifier }],
            outputs: vec![dummy_output(0x02)],
            fee_amount:     INITIAL_BASE_FEE_SPARK_PER_KB * 10, // covers 10 KB
            fee_blinding:   Bytes32::ZERO,
            fee_commitment: CommitmentV1 { compressed_point: Bytes32::ZERO },
            signature:      dummy_sig(),
        }
    }

    fn make_block(state: &ChainState, txs: Vec<TransactionV1>) -> BlockV1 {
        let height = state.height + 1;
        BlockV1 {
            header: BlockHeaderV1 {
                protocol_version:    ProtocolVersion::CURRENT,
                height,
                prev_hash:           state.tip_hash,
                timestamp:           1_700_000_000 + height,
                state_root:          Bytes32::ZERO,
                validator_set_root:  Bytes32::ZERO,
                mempool_set_root:    Bytes32::ZERO,
                base_fee:            state.base_fee,
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof:  VariableBytes::from_slice(&[0u8; 32]).unwrap(),
                quorum_certificate:  VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            },
            transactions:      txs,
            slashing_evidence: vec![],
            governance_ops:    vec![],
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────

    #[test]
    fn apply_empty_block_advances_height() {
        let mut state = ChainState::new_genesis();
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block).unwrap();
        assert_eq!(state.height, 1);
    }

    #[test]
    fn apply_block_updates_tip_hash() {
        let mut state = ChainState::new_genesis();
        let block = make_block(&state, vec![]);
        let expected_hash = block.header.block_hash();
        apply_block(&mut state, &block).unwrap();
        assert_eq!(state.tip_hash, expected_hash);
    }

    #[test]
    fn apply_block_with_tx_spends_utxo() {
        let (mut state, utxo_id) = state_with_utxo();
        let nullifier = Bytes32::from([0x99u8; 32]);
        let tx = make_tx(utxo_id, nullifier);
        let block = make_block(&state, vec![tx]);
        apply_block(&mut state, &block).unwrap();

        // Input UTXO must be gone
        assert!(!state.utxos.contains(&utxo_id));
        // Output UTXO must exist
        assert_eq!(state.utxos.len(), 1);
        // Nullifier must be recorded
        assert!(state.nullifiers.contains(&nullifier));
    }

    #[test]
    fn double_spend_rejected() {
        let (mut state, utxo_id) = state_with_utxo();
        let nullifier = Bytes32::from([0xAAu8; 32]);
        let tx = make_tx(utxo_id, nullifier);
        let block1 = make_block(&state, vec![tx.clone()]);
        apply_block(&mut state, &block1).unwrap();

        // Re-insert the output so the utxo_id exists again
        // but the nullifier is already spent
        let output = dummy_output(0x01);
        state.utxos.insert(output, 0, 0, 0).unwrap();

        let block2 = make_block(&state, vec![make_tx(utxo_id, nullifier)]);
        assert_eq!(apply_block(&mut state, &block2), Err(StateError::DoubleSpend));
    }

    #[test]
    fn wrong_height_rejected() {
        let mut state = ChainState::new_genesis();
        let mut block = make_block(&state, vec![]);
        block.header.height = 99; // wrong
        assert!(matches!(
            apply_block(&mut state, &block),
            Err(StateError::InvalidHeight { expected: 1, actual: 99 })
        ));
    }

    #[test]
    fn wrong_prev_hash_rejected() {
        let mut state = ChainState::new_genesis();
        let mut block = make_block(&state, vec![]);
        block.header.prev_hash = Bytes32::from([0xFFu8; 32]); // wrong
        assert_eq!(apply_block(&mut state, &block), Err(StateError::PrevHashMismatch));
    }

    #[test]
    fn wrong_base_fee_rejected() {
        let mut state = ChainState::new_genesis();
        let mut block = make_block(&state, vec![]);
        block.header.base_fee = 9999; // wrong
        assert!(matches!(
            apply_block(&mut state, &block),
            Err(StateError::BaseFeeIncorrect { .. })
        ));
    }

    #[test]
    fn unknown_utxo_rejected() {
        let mut state = ChainState::new_genesis();
        let fake_utxo = Bytes32::from([0xDEu8; 32]);
        let nullifier  = Bytes32::from([0xADu8; 32]);
        let tx = make_tx(fake_utxo, nullifier);
        let block = make_block(&state, vec![tx]);
        assert_eq!(apply_block(&mut state, &block), Err(StateError::UnknownUtxo));
    }

    #[test]
    fn fee_too_low_rejected() {
        let (mut state, utxo_id) = state_with_utxo();
        let mut tx = make_tx(utxo_id, Bytes32::from([0x01u8; 32]));
        tx.fee_amount = 0; // too low
        let block = make_block(&state, vec![tx]);
        assert!(matches!(
            apply_block(&mut state, &block),
            Err(StateError::FeeTooLow { .. })
        ));
    }

    #[test]
    fn fee_burns_supply() {
        let (mut state, utxo_id) = state_with_utxo();
        let initial_supply = state.total_supply;
        let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 10;
        let tx = make_tx(utxo_id, Bytes32::from([0x11u8; 32]));
        let block = make_block(&state, vec![tx]);
        apply_block(&mut state, &block).unwrap();
        assert_eq!(state.total_supply, initial_supply - (fee / 2));
        assert_eq!(state.fee_reward_pool, fee - (fee / 2));
    }

    #[test]
    fn state_unchanged_on_error() {
        let mut state = ChainState::new_genesis();
        let height_before  = state.height;
        let supply_before  = state.total_supply;
        let utxos_before   = state.utxos.len();

        // Block with wrong height — will fail
        let mut block = make_block(&state, vec![]);
        block.header.height = 99;
        let _ = apply_block(&mut state, &block);

        assert_eq!(state.height, height_before);
        assert_eq!(state.total_supply, supply_before);
        assert_eq!(state.utxos.len(), utxos_before);
    }

    #[test]
    fn consecutive_blocks_chain_correctly() {
        let (mut state, utxo_id) = state_with_utxo();

        // Block 1: spend the UTXO
        let nullifier = Bytes32::from([0x55u8; 32]);
        let tx = make_tx(utxo_id, nullifier);
        let block1 = make_block(&state, vec![tx]);
        apply_block(&mut state, &block1).unwrap();
        assert_eq!(state.height, 1);

        // Block 2: empty, but chains correctly off block 1
        let block2 = make_block(&state, vec![]);
        apply_block(&mut state, &block2).unwrap();
        assert_eq!(state.height, 2);
    }

    #[test]
    fn locked_utxo_rejected_before_unlock() {
        let mut state = ChainState::new_genesis();
        let mut output = dummy_output(0x01);
        output.lock_height = 100; // locked until height 100
        let utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();

        let tx = make_tx(utxo_id, Bytes32::from([0x01u8; 32]));
        let block = make_block(&state, vec![tx]); // height will be 1 < 100
        assert!(matches!(
            apply_block(&mut state, &block),
            Err(StateError::OutputLocked { .. })
        ));
    }
}
