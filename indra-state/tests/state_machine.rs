//! Integration tests for the complete state machine.
//!
//! These tests verify multi-block scenarios, epoch transitions,
//! and fee evolution over sequences of blocks.

use indra_core::{
    Bytes32, CommitmentV1, HybridPubKey, HybridSignature, VariableBytes,
    ProtocolVersion,
    types::{
        block::{BlockV1, BlockHeaderV1},
        transaction::{InputV1, OutputV1, TransactionV1},
        primitives::{
            EPOCH_DURATION_BLOCKS, INITIAL_BASE_FEE_SPARK_PER_KB,
            GENESIS_SUPPLY_SPARK,
        },
    },
};
use indra_crypto::{commit, prove_range};
use indra_state::{
    apply_block, ChainState,
    utxo::UtxoSet,
};
use rand::{SeedableRng, rngs::StdRng};

// ── Helpers ───────────────────────────────────────────────────────────────────

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

fn make_output(byte: u8) -> OutputV1 {
    let value = 10_000u64 + byte as u64;
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

fn make_tx(utxo_id: Bytes32, nullifier_byte: u8, out_byte: u8) -> TransactionV1 {
    TransactionV1 {
        version:             ProtocolVersion::CURRENT,
        signature_module_id: 1,
        inputs:  vec![InputV1 {
            utxo_id,
            nullifier: Bytes32::from([nullifier_byte; 32]),
        }],
        outputs: vec![make_output(out_byte)],
        fee_amount:     INITIAL_BASE_FEE_SPARK_PER_KB * 10,
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn genesis_state_constants() {
    let state = ChainState::new_genesis();
    assert_eq!(state.total_supply, GENESIS_SUPPLY_SPARK);
    assert_eq!(state.height, 0);
    assert_eq!(state.base_fee, INITIAL_BASE_FEE_SPARK_PER_KB);
}

#[test]
fn one_hundred_empty_blocks() {
    let mut state = ChainState::new_genesis();
    for _ in 0..100 {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block).unwrap();
    }
    assert_eq!(state.height, 100);
}

#[test]
fn utxo_lifecycle_across_blocks() {
    let mut state = ChainState::new_genesis();

    // Create a UTXO by inserting it at genesis
    let output = make_output(0x01);
    let utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();

    // Block 1: spend that UTXO, create a new one
    let tx = make_tx(utxo_id, 0xAA, 0x02);
    let block1 = make_block(&state, vec![tx]);
    apply_block(&mut state, &block1).unwrap();

    assert!(!state.utxos.contains(&utxo_id), "old UTXO should be spent");
    assert_eq!(state.utxos.len(), 1, "one new UTXO created");
    assert!(state.nullifiers.contains(&Bytes32::from([0xAAu8; 32])));

    // Block 2: spend the new UTXO
    // Find the new UTXO id — it was inserted at height 1, tx 0, output 0
    let new_utxo_id = UtxoSet::compute_utxo_id(&make_output(0x02), 1, 0, 0);
    let tx2 = make_tx(new_utxo_id, 0xBB, 0x03);
    let block2 = make_block(&state, vec![tx2]);
    apply_block(&mut state, &block2).unwrap();

    assert_eq!(state.height, 2);
    assert_eq!(state.utxos.len(), 1);
    assert!(state.nullifiers.contains(&Bytes32::from([0xBBu8; 32])));
}

#[test]
fn fee_evolves_over_blocks() {
    let mut state = ChainState::new_genesis();
    let fee_at_genesis = state.base_fee;

    // Apply 10 empty blocks — fee should decrease (below target utilisation)
    for _ in 0..10 {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block).unwrap();
    }
    // Fee should have decreased from initial
    assert!(state.base_fee <= fee_at_genesis);
    // But never below minimum
    assert!(state.base_fee >= indra_core::types::primitives::MIN_BASE_FEE_SPARK_PER_KB);
}

#[test]
fn epoch_transition_fires_at_boundary() {
    let mut state = ChainState::new_genesis();
    let supply_before = state.total_supply;

    // Apply exactly one epoch worth of blocks
    for _ in 0..EPOCH_DURATION_BLOCKS {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block).unwrap();
    }

    assert_eq!(state.height, EPOCH_DURATION_BLOCKS);
    assert_eq!(state.current_epoch(), 1);
    // Supply should have increased (inflation minted)
    assert!(state.total_supply > supply_before);
    // Treasury should have received its share
    assert!(state.treasury_balance > 0);
}

#[test]
fn two_epochs_inflate_twice() {
    let mut state = ChainState::new_genesis();

    // First epoch
    for _ in 0..EPOCH_DURATION_BLOCKS {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block).unwrap();
    }
    let supply_after_epoch1 = state.total_supply;

    // Second epoch
    for _ in 0..EPOCH_DURATION_BLOCKS {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block).unwrap();
    }

    assert!(state.total_supply > supply_after_epoch1);
    assert_eq!(state.current_epoch(), 2);
}

#[test]
fn fees_are_burned() {
    let mut state = ChainState::new_genesis();

    // Insert a spendable UTXO
    let output = make_output(0x01);
    let utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();
    let supply_before = state.total_supply;

    let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 10;
    let tx = make_tx(utxo_id, 0xCC, 0x02);
    assert_eq!(tx.fee_amount, fee);

    let block = make_block(&state, vec![tx]);
    apply_block(&mut state, &block).unwrap();

    // Supply must have decreased by exactly the fee
    assert_eq!(state.total_supply, supply_before - fee);
}

#[test]
fn chain_is_deterministic() {
    // Two independent nodes starting from genesis and applying the same blocks
    // must arrive at identical state
    let mut state_a = ChainState::new_genesis();
    let mut state_b = ChainState::new_genesis();

    for i in 0..50u64 {
        let block_a = make_block(&state_a, vec![]);
        let block_b = make_block(&state_b, vec![]);
        // Blocks are identical because states are identical
        assert_eq!(
            block_a.header.block_hash(),
            block_b.header.block_hash(),
            "block hashes must match at height {}",
            i + 1
        );
        apply_block(&mut state_a, &block_a).unwrap();
        apply_block(&mut state_b, &block_b).unwrap();
        assert_eq!(state_a.height, state_b.height);
        assert_eq!(state_a.tip_hash, state_b.tip_hash);
        assert_eq!(state_a.total_supply, state_b.total_supply);
        assert_eq!(state_a.base_fee, state_b.base_fee);
    }
}
