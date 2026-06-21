//! Integration tests: serialisation round-trips and cross-type consistency.
//!
//! These are the Phase 1 acceptance tests.
//! All tests must pass before Phase 2 begins.

use indra_core::codec::{Decode, Encode};
use indra_core::types::primitives::{
    DUST_LIMIT_SPARK, FEE_BURN_BPS, FEE_VALIDATOR_BPS, GENESIS_SUPPLY_INDRA, GENESIS_SUPPLY_SPARK,
    HARD_CAP_SPARK, MAX_INPUTS, MAX_OUTPUTS, MIN_BASE_FEE_SPARK_PER_KB, SPARK_PER_INDRA,
    VALIDATOR_REWARDS_POOL_SPARK,
};
use indra_core::types::qc::SIGNER_BITFIELD_BYTES;
use indra_core::types::vote::VoteStep;
use indra_core::IndraError;
use indra_core::{
    BlockHeaderV1, BlockV1, Bytes32, CheckpointV1, CommitmentV1, HybridPubKey, HybridSignature,
    InputV1, OutputV1, ProtocolVersion, QuorumCertificateV1, TransactionV1, VariableBytes, VoteV1,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn sig() -> HybridSignature {
    HybridSignature {
        classical_sig: VariableBytes::from_slice(&[0xAAu8; 64]).unwrap(),
        pq_sig: VariableBytes::from_slice(&[0xBBu8; 4627]).unwrap(),
    }
}

fn pubkey() -> HybridPubKey {
    HybridPubKey {
        classical_pk: Bytes32::from([0xCCu8; 32]),
        pq_pk: VariableBytes::from_slice(&[0xDDu8; 2592]).unwrap(),
    }
}

fn commitment(byte: u8) -> CommitmentV1 {
    CommitmentV1 {
        compressed_point: Bytes32::from([byte; 32]),
    }
}

fn input(utxo_byte: u8, null_byte: u8) -> InputV1 {
    InputV1 {
        utxo_id: Bytes32::from([utxo_byte; 32]),
        nullifier: Bytes32::from([null_byte; 32]),
    }
}

fn output(c: u8) -> OutputV1 {
    OutputV1 {
        value_spark: 100_000 + c as u64,
        commitment: commitment(c),
        owner_pubkey: pubkey(),
        range_proof: VariableBytes::from_slice(&[0u8; 674]).unwrap(),
        lock_height: 0,
    }
}

fn minimal_tx() -> TransactionV1 {
    TransactionV1 {
        version: ProtocolVersion::CURRENT,
        signature_module_id: 1,
        inputs: vec![input(0x01, 0x02)],
        outputs: vec![output(0x03)],
        fee_amount: 1_000,
        fee_blinding: Bytes32::ZERO,
        fee_commitment: commitment(0x00),
        signature: sig(),
    }
}

fn dummy_header() -> BlockHeaderV1 {
    BlockHeaderV1 {
        protocol_version: ProtocolVersion::CURRENT,
        height: 1,
        prev_hash: Bytes32::ZERO,
        timestamp: 1_700_000_000,
        state_root: Bytes32::from([0x11u8; 32]),
        validator_set_root: Bytes32::from([0x22u8; 32]),
        mempool_set_root: Bytes32::from([0x33u8; 32]),
        value_hash: Bytes32::from([0x34u8; 32]),
        base_fee: 100,
        proposer_round: 0,
        polc_round: indra_core::types::block::NO_POLC_ROUND,
        proposer_vrf_output: Bytes32::from([0x44u8; 32]),
        proposer_vrf_proof: VariableBytes::from_slice(&[0xAAu8; 80]).unwrap(),
        quorum_certificate: VariableBytes::from_slice(&[0xBBu8; 256]).unwrap(),
    }
}

// ── Round-trip tests ──────────────────────────────────────────────────────────

#[test]
fn bytes32_round_trip() {
    let b = Bytes32::from([0xFEu8; 32]);
    assert_eq!(b, Bytes32::decode_exact(&b.encode_to_vec()).unwrap());
}

#[test]
fn hybrid_sig_round_trip() {
    let s = sig();
    assert_eq!(
        s,
        HybridSignature::decode_exact(&s.encode_to_vec()).unwrap()
    );
}

#[test]
fn hybrid_pubkey_round_trip() {
    let pk = pubkey();
    assert_eq!(pk, HybridPubKey::decode_exact(&pk.encode_to_vec()).unwrap());
}

#[test]
fn transaction_round_trip() {
    let tx = minimal_tx();
    assert_eq!(
        tx,
        TransactionV1::decode_exact(&tx.encode_to_vec()).unwrap()
    );
}

#[test]
fn transaction_max_inputs_and_outputs() {
    let mut tx = minimal_tx();
    tx.inputs = (0..MAX_INPUTS as u8)
        .map(|i| input(i, i.wrapping_add(100)))
        .collect();
    tx.outputs = (0..MAX_OUTPUTS as u8).map(|i| output(i)).collect();
    assert_eq!(
        tx,
        TransactionV1::decode_exact(&tx.encode_to_vec()).unwrap()
    );
}

#[test]
fn vote_round_trip() {
    let v = VoteV1 {
        height: 500_000,
        round: 2,
        step: VoteStep::Prevote,
        block_hash: Bytes32::from([0x77u8; 32]),
        validator_id: Bytes32::from([0x88u8; 32]),
        signature: sig(),
    };
    assert_eq!(v, VoteV1::decode_exact(&v.encode_to_vec()).unwrap());
}

#[test]
fn block_header_round_trip() {
    let h = dummy_header();
    assert_eq!(h, BlockHeaderV1::decode_exact(&h.encode_to_vec()).unwrap());
}

#[test]
fn block_with_transactions_round_trip() {
    let b = BlockV1 {
        header: dummy_header(),
        transactions: vec![minimal_tx(), minimal_tx()],
        slashing_evidence: vec![],
        governance_ops: vec![],
        staking_ops: vec![],
    };
    assert_eq!(b, BlockV1::decode_exact(&b.encode_to_vec()).unwrap());
}

#[test]
fn quorum_certificate_round_trip() {
    let qc = QuorumCertificateV1 {
        height: 42,
        round: 0,
        block_hash: Bytes32::from([0xFFu8; 32]),
        signer_bitfield: [0b10101010u8; SIGNER_BITFIELD_BYTES],
        pq_signatures: vec![],
    };
    assert_eq!(
        qc,
        QuorumCertificateV1::decode_exact(&qc.encode_to_vec()).unwrap()
    );
}

#[test]
fn checkpoint_round_trip() {
    let cp = CheckpointV1 {
        height: 300_000,
        block_hash: Bytes32::from([0xABu8; 32]),
        state_root: Bytes32::from([0xCDu8; 32]),
        validator_set_root: Bytes32::from([0xEFu8; 32]),
        signatures: vec![],
    };
    assert_eq!(cp, CheckpointV1::decode_exact(&cp.encode_to_vec()).unwrap());
}

// ── Validation tests ──────────────────────────────────────────────────────────

#[test]
fn zero_inputs_rejected() {
    let mut tx = minimal_tx();
    tx.inputs.clear();
    assert_eq!(tx.validate_structure(), Err(IndraError::ZeroInputs));
}

#[test]
fn zero_outputs_rejected() {
    let mut tx = minimal_tx();
    tx.outputs.clear();
    assert_eq!(tx.validate_structure(), Err(IndraError::ZeroOutputs));
}

#[test]
fn duplicate_nullifier_within_tx_rejected() {
    let mut tx = minimal_tx();
    tx.inputs.push(tx.inputs[0].clone());
    assert_eq!(tx.validate_structure(), Err(IndraError::DuplicateNullifier));
}

#[test]
fn fee_below_base_rejected() {
    let mut tx = minimal_tx();
    tx.fee_amount = 0;
    assert!(tx.validate_fee(MIN_BASE_FEE_SPARK_PER_KB).is_err());
}

// ── Canonicality tests ────────────────────────────────────────────────────────

#[test]
fn encoding_is_deterministic() {
    let tx = minimal_tx();
    assert_eq!(tx.encode_to_vec(), tx.encode_to_vec());
}

#[test]
fn block_hash_is_deterministic() {
    let h = dummy_header();
    assert_eq!(h.block_hash(), h.block_hash());
}

#[test]
fn two_different_headers_have_different_hashes() {
    let mut h1 = dummy_header();
    let mut h2 = dummy_header();
    h1.height = 100;
    h2.height = 101;
    assert_ne!(h1.block_hash(), h2.block_hash());
}

#[test]
fn trailing_bytes_rejected() {
    let tx = minimal_tx();
    let mut encoded = tx.encode_to_vec();
    encoded.push(0xFF); // corrupt: add a trailing byte
    assert!(TransactionV1::decode_exact(&encoded).is_err());
}

#[test]
fn truncated_bytes_rejected() {
    let tx = minimal_tx();
    let encoded = tx.encode_to_vec();
    let truncated = &encoded[..encoded.len() - 1];
    assert!(TransactionV1::decode_exact(truncated).is_err());
}

// ── Protocol constant consistency tests ───────────────────────────────────────

#[test]
fn genesis_supply_consistency() {
    assert_eq!(GENESIS_SUPPLY_SPARK, GENESIS_SUPPLY_INDRA * SPARK_PER_INDRA);
    assert_eq!(GENESIS_SUPPLY_SPARK, 100_000_000_000_000_000u64);
    assert_eq!(HARD_CAP_SPARK, GENESIS_SUPPLY_SPARK);
}

#[test]
fn allocation_shares_sum_to_ten_thousand() {
    assert_eq!(FEE_BURN_BPS + FEE_VALIDATOR_BPS, 10_000);
    assert_eq!(VALIDATOR_REWARDS_POOL_SPARK, GENESIS_SUPPLY_SPARK);
}

#[test]
fn dust_limit_is_nonzero() {
    assert!(DUST_LIMIT_SPARK > 0);
}

#[test]
fn signer_bitfield_covers_all_validators() {
    use indra_core::types::primitives::MAX_VALIDATORS;
    // Must have enough bits for all validator slots
    assert!(SIGNER_BITFIELD_BYTES * 8 >= MAX_VALIDATORS);
    // Must be the minimum needed (no excessive padding)
    assert_eq!(SIGNER_BITFIELD_BYTES, (MAX_VALIDATORS + 7) / 8);
}
