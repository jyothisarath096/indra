//! Reusable test fixtures for benchmarks.

use indra_core::{
    types::{
        block::{BlockHeaderV1, BlockV1},
        crypto::HybridSignature,
        primitives::{
            INITIAL_BASE_FEE_SPARK_PER_KB, MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES,
            MAX_VRF_PROOF_BYTES, TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES,
        },
        transaction::{InputV1, OutputV1, TransactionV1},
    },
    Bytes32, CommitmentV1, HybridPubKey, ProtocolVersion, VariableBytes,
};
use indra_crypto::{
    constants::ML_KEM_1024_CT_BYTES,
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    sha256, PaymentBlindingNoteV1, VrfKeypair,
};

/// A pre-built transaction for benchmarks.
pub fn dummy_tx(nonce: u8, fee: u64) -> TransactionV1 {
    TransactionV1 {
        version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES),
        signature_module_id: 1,
        inputs: vec![InputV1 {
            utxo_id: Bytes32::from([nonce; 32]),
            nullifier: Bytes32::from([nonce; 32]),
        }],
        outputs: vec![OutputV1 {
            value_spark: 1_000_000,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::ZERO,
            },
            owner_pubkey: HybridPubKey {
                classical_pk: Bytes32::ZERO,
                pq_pk: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            },
            range_proof: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            lock_height: 0,
        }],
        payment_notes: vec![PaymentBlindingNoteV1 {
            version: 1,
            owner_id: sha256(&[0; 32]),
            payment_pubkey_hash: [0; 32],
            sender_x25519_ephemeral_pk: [0; 32],
            ml_kem_1024_ciphertext: [0; ML_KEM_1024_CT_BYTES],
            note_nonce: [0; 32],
        }],
        fee_amount: fee,
        fee_blinding: Bytes32::ZERO,
        fee_commitment: CommitmentV1 {
            compressed_point: Bytes32::ZERO,
        },
        signature: HybridSignature {
            classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(&[0u8; 64])
                .unwrap(),
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&[0u8; 32]).unwrap(),
        },
    }
}

/// A block with N transactions.
pub fn dummy_block(height: u64, prev_hash: Bytes32, tx_count: usize) -> BlockV1 {
    let txs: Vec<TransactionV1> = (0..tx_count)
        .map(|i| dummy_tx(i as u8, INITIAL_BASE_FEE_SPARK_PER_KB * 10))
        .collect();

    BlockV1 {
        header: BlockHeaderV1 {
            protocol_version: ProtocolVersion::CURRENT,
            height,
            prev_hash,
            timestamp: 1_700_000_000 + height,
            state_root: Bytes32::ZERO,
            validator_set_root: Bytes32::ZERO,
            mempool_set_root: Bytes32::ZERO,
            value_hash: Bytes32::ZERO,
            base_fee: INITIAL_BASE_FEE_SPARK_PER_KB,
            proposer_round: 0,
            polc_round: indra_core::types::block::NO_POLC_ROUND,
            proposer_vrf_output: Bytes32::ZERO,
            proposer_vrf_proof: VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
            quorum_certificate: VariableBytes::from_slice(&[]).unwrap(),
            election_result_hash: None,
        },
        transactions: txs,
        slashing_evidence: vec![],
        slashing_evidence_v2: vec![],
        governance_ops: vec![],
        staking_ops: vec![],
        vrf_reveals: vec![],
    }
}

/// A hybrid keypair for benchmarks.
pub fn hybrid_keypair(seed: u8) -> HybridKeypair {
    let classical = ClassicalKeypair::from_seed(&[seed; 32]);
    let pq = PqKeypair::generate();
    HybridKeypair::new(classical, pq)
}

/// A VRF keypair for benchmarks.
pub fn vrf_keypair(seed: u8) -> VrfKeypair {
    VrfKeypair::from_seed(&[seed; 32])
}
