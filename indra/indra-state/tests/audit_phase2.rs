//! Phase 2 security-audit proof-of-concept tests.
//!
//! These tests intentionally document vulnerabilities found by the audit.
//! They are ignored so normal CI is not trained to accept an exploit as
//! correct behaviour. Run explicitly with:
//!
//!   cargo test -p indra-state --test audit_phase2 -- --ignored

use curve25519_dalek::scalar::Scalar;
use indra_core::types::{
    block::{BlockHeaderV1, BlockV1, NO_POLC_ROUND},
    crypto::{CommitmentV1, HybridPubKey, HybridSignature},
    primitives::{
        Bytes32, ProtocolVersion, VariableBytes, DEFAULT_CHAIN_ID, INITIAL_BASE_FEE_SPARK_PER_KB,
        MAX_QC_SIZE_BYTES, MAX_RANGE_PROOF_BYTES, MAX_VRF_PROOF_BYTES,
        TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES,
    },
    transaction::{InputV1, OutputV1, TransactionV1},
};
use indra_crypto::{
    commit, constants::ML_KEM_1024_CT_BYTES, prove_range, sha256, ClassicalKeypair, HybridKeypair,
    PaymentBlindingNoteV1, PqKeypair,
};
use indra_state::{apply_block, ChainState, StateError};
use rand::{rngs::StdRng, SeedableRng};

fn keypair(seed: [u8; 32]) -> (HybridPubKey, HybridKeypair) {
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

fn sign_tx(tx: &TransactionV1, keypair: &HybridKeypair, chain_id: &str) -> HybridSignature {
    let sig = keypair.sign(&tx.signing_bytes(chain_id)).unwrap();
    HybridSignature {
        classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
        pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
    }
}

fn note(owner: &HybridPubKey) -> PaymentBlindingNoteV1 {
    PaymentBlindingNoteV1 {
        version: 1,
        owner_id: sha256(&owner.classical_pk.0),
        payment_pubkey_hash: [0; 32],
        sender_x25519_ephemeral_pk: [0; 32],
        ml_kem_1024_ciphertext: [0; ML_KEM_1024_CT_BYTES],
        note_nonce: [0; 32],
    }
}

fn output(
    value: u64,
    blinding: [u8; 32],
    owner_pubkey: HybridPubKey,
    proof_seed: [u8; 32],
) -> OutputV1 {
    let commitment = commit(value, &blinding);
    let mut rng = StdRng::from_seed(proof_seed);
    let proof = prove_range(value, &blinding, &mut rng).unwrap();
    OutputV1 {
        value_spark: value,
        commitment: CommitmentV1 {
            compressed_point: Bytes32::from(commitment.0),
        },
        owner_pubkey,
        range_proof: VariableBytes::<MAX_RANGE_PROOF_BYTES>::from_slice(&proof).unwrap(),
        lock_height: 0,
    }
}

fn tx_spending(
    utxo_id: Bytes32,
    nullifier: Bytes32,
    value_in: u64,
    input_blinding: [u8; 32],
    owner_pubkey: HybridPubKey,
    keypair: &HybridKeypair,
    output_blinding: [u8; 32],
    proof_seed: [u8; 32],
) -> TransactionV1 {
    let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 10;
    let value_out = value_in - fee;
    let fee_blinding = (Scalar::from_bytes_mod_order(input_blinding)
        - Scalar::from_bytes_mod_order(output_blinding))
    .to_bytes();
    let fee_commitment = commit(fee, &fee_blinding);

    let mut tx = TransactionV1 {
        version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES),
        signature_module_id: 1,
        inputs: vec![InputV1 { utxo_id, nullifier }],
        outputs: vec![output(
            value_out,
            output_blinding,
            owner_pubkey.clone(),
            proof_seed,
        )],
        payment_notes: vec![note(&owner_pubkey)],
        fee_amount: fee,
        fee_blinding: Bytes32::from(fee_blinding),
        fee_commitment: CommitmentV1 {
            compressed_point: Bytes32::from(fee_commitment.0),
        },
        signature: HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
        },
    };
    tx.signature = sign_tx(&tx, keypair, DEFAULT_CHAIN_ID);
    tx
}

fn tx_spending_same_utxo_twice(
    utxo_id: Bytes32,
    nullifier_a: Bytes32,
    nullifier_b: Bytes32,
    value_in: u64,
    input_blinding: [u8; 32],
    owner_pubkey: HybridPubKey,
    keypair: &HybridKeypair,
) -> TransactionV1 {
    let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 10;
    let value_out = value_in
        .checked_mul(2)
        .and_then(|v| v.checked_sub(fee))
        .unwrap();
    let output_blinding = [0x31; 32];
    let fee_blinding = (Scalar::from_bytes_mod_order(input_blinding)
        + Scalar::from_bytes_mod_order(input_blinding)
        - Scalar::from_bytes_mod_order(output_blinding))
    .to_bytes();
    let fee_commitment = commit(fee, &fee_blinding);

    let mut tx = TransactionV1 {
        version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES),
        signature_module_id: 1,
        inputs: vec![
            InputV1 {
                utxo_id,
                nullifier: nullifier_a,
            },
            InputV1 {
                utxo_id,
                nullifier: nullifier_b,
            },
        ],
        outputs: vec![output(
            value_out,
            output_blinding,
            owner_pubkey.clone(),
            [0x71; 32],
        )],
        payment_notes: vec![note(&owner_pubkey)],
        fee_amount: fee,
        fee_blinding: Bytes32::from(fee_blinding),
        fee_commitment: CommitmentV1 {
            compressed_point: Bytes32::from(fee_commitment.0),
        },
        signature: HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
        },
    };
    tx.signature = sign_tx(&tx, keypair, DEFAULT_CHAIN_ID);
    tx
}

fn block_with_transactions(state: &ChainState, transactions: Vec<TransactionV1>) -> BlockV1 {
    BlockV1 {
        header: BlockHeaderV1 {
            protocol_version: ProtocolVersion::CURRENT,
            height: state.height + 1,
            prev_hash: state.tip_hash,
            timestamp: 1_700_000_000,
            state_root: Bytes32::ZERO,
            validator_set_root: Bytes32::ZERO,
            mempool_set_root: Bytes32::ZERO,
            value_hash: Bytes32::ZERO,
            base_fee: state.base_fee,
            proposer_round: 0,
            polc_round: NO_POLC_ROUND,
            proposer_vrf_output: Bytes32::ZERO,
            proposer_vrf_proof: VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
            quorum_certificate: VariableBytes::<MAX_QC_SIZE_BYTES>::from_slice(&[]).unwrap(),
            election_result_hash: None,
        },
        transactions,
        slashing_evidence: vec![],
        slashing_evidence_v2: vec![],
        governance_ops: vec![],
        staking_ops: vec![],
        vrf_reveals: vec![],
    }
}

#[test]
fn transaction_with_overflowing_input_sum_is_rejected() {
    let mut state = ChainState::new_genesis();
    let (owner_pubkey, _owner_keypair) = keypair([0x45; 32]);
    let huge_output_a = OutputV1 {
        value_spark: u64::MAX,
        commitment: CommitmentV1 {
            compressed_point: Bytes32::ZERO,
        },
        owner_pubkey: owner_pubkey.clone(),
        range_proof: VariableBytes::<MAX_RANGE_PROOF_BYTES>::from_slice(&[0u8; 32]).unwrap(),
        lock_height: 0,
    };
    let huge_output_b = OutputV1 {
        value_spark: 1,
        commitment: CommitmentV1 {
            compressed_point: Bytes32::ZERO,
        },
        owner_pubkey,
        range_proof: VariableBytes::<MAX_RANGE_PROOF_BYTES>::from_slice(&[0u8; 32]).unwrap(),
        lock_height: 0,
    };
    let utxo_a = state.utxos.insert(huge_output_a, 0, 0, 0).unwrap();
    let utxo_b = state.utxos.insert(huge_output_b, 0, 0, 1).unwrap();

    let overflow_owner = keypair([0x46; 32]).0;
    let tx = TransactionV1 {
        version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES),
        signature_module_id: 1,
        inputs: vec![
            InputV1 {
                utxo_id: utxo_a,
                nullifier: Bytes32::from([0xE1; 32]),
            },
            InputV1 {
                utxo_id: utxo_b,
                nullifier: Bytes32::from([0xE2; 32]),
            },
        ],
        outputs: vec![OutputV1 {
            value_spark: INITIAL_BASE_FEE_SPARK_PER_KB,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::ZERO,
            },
            owner_pubkey: overflow_owner.clone(),
            range_proof: VariableBytes::<MAX_RANGE_PROOF_BYTES>::from_slice(&[0u8; 32]).unwrap(),
            lock_height: 0,
        }],
        payment_notes: vec![note(&overflow_owner)],
        fee_amount: INITIAL_BASE_FEE_SPARK_PER_KB,
        fee_blinding: Bytes32::ZERO,
        fee_commitment: CommitmentV1 {
            compressed_point: Bytes32::ZERO,
        },
        signature: HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
        },
    };
    let block = block_with_transactions(&state, vec![tx]);

    assert_eq!(
        apply_block(&mut state, &block, 0),
        Err(StateError::ValueOverflow)
    );
    assert_eq!(state.height, 0);
    assert!(state.utxos.contains(&utxo_a));
    assert!(state.utxos.contains(&utxo_b));
}

#[test]
fn t02_duplicate_utxo_spend_across_two_transactions_in_one_block_is_rejected() {
    let mut state = ChainState::new_genesis();
    let (owner_pubkey, owner_keypair) = keypair([0x42; 32]);
    let input_value = 10_000_000_000u64;
    let input_blinding = [0x11; 32];
    let original_output = output(
        input_value,
        input_blinding,
        owner_pubkey.clone(),
        [0x51; 32],
    );
    let utxo_id = state.utxos.insert(original_output, 0, 0, 0).unwrap();

    let tx_a = tx_spending(
        utxo_id,
        Bytes32::from([0xA1; 32]),
        input_value,
        input_blinding,
        owner_pubkey.clone(),
        &owner_keypair,
        [0x21; 32],
        [0x61; 32],
    );
    let tx_b = tx_spending(
        utxo_id,
        Bytes32::from([0xB2; 32]),
        input_value,
        input_blinding,
        owner_pubkey,
        &owner_keypair,
        [0x22; 32],
        [0x62; 32],
    );

    let block = block_with_transactions(&state, vec![tx_a, tx_b]);

    assert_eq!(
        apply_block(&mut state, &block, 0),
        Err(StateError::DuplicateUtxoSpend { utxo_id })
    );
    assert!(state.utxos.contains(&utxo_id));
    assert_eq!(state.utxos.len(), 1);
    assert_eq!(state.nullifiers.len(), 0);
    assert_eq!(state.height, 0);
}

#[test]
fn t02_duplicate_utxo_spend_within_single_transaction_inputs_is_rejected() {
    let mut state = ChainState::new_genesis();
    let (owner_pubkey, owner_keypair) = keypair([0x43; 32]);
    let input_value = 10_000_000_000u64;
    let input_blinding = [0x12; 32];
    let original_output = output(
        input_value,
        input_blinding,
        owner_pubkey.clone(),
        [0x52; 32],
    );
    let utxo_id = state.utxos.insert(original_output, 0, 0, 0).unwrap();
    let tx = tx_spending_same_utxo_twice(
        utxo_id,
        Bytes32::from([0xC1; 32]),
        Bytes32::from([0xC2; 32]),
        input_value,
        input_blinding,
        owner_pubkey,
        &owner_keypair,
    );
    let block = block_with_transactions(&state, vec![tx]);

    assert_eq!(
        apply_block(&mut state, &block, 0),
        Err(StateError::DuplicateUtxoSpend { utxo_id })
    );
    assert!(state.utxos.contains(&utxo_id));
    assert_eq!(state.utxos.len(), 1);
    assert_eq!(state.nullifiers.len(), 0);
    assert_eq!(state.height, 0);
}

#[test]
fn legitimate_single_spend_still_works_after_duplicate_utxo_fix() {
    let mut state = ChainState::new_genesis();
    let (owner_pubkey, owner_keypair) = keypair([0x44; 32]);
    let input_value = 10_000_000_000u64;
    let input_blinding = [0x13; 32];
    let original_output = output(
        input_value,
        input_blinding,
        owner_pubkey.clone(),
        [0x53; 32],
    );
    let utxo_id = state.utxos.insert(original_output, 0, 0, 0).unwrap();
    let nullifier = Bytes32::from([0xD1; 32]);
    let tx = tx_spending(
        utxo_id,
        nullifier,
        input_value,
        input_blinding,
        owner_pubkey,
        &owner_keypair,
        [0x23; 32],
        [0x63; 32],
    );
    let block = block_with_transactions(&state, vec![tx]);

    apply_block(&mut state, &block, 0).unwrap();

    assert!(!state.utxos.contains(&utxo_id));
    assert_eq!(state.utxos.len(), 1);
    assert!(state.nullifiers.contains(&nullifier));
    assert_eq!(state.height, 1);
}
