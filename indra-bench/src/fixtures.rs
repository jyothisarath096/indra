//! Reusable test fixtures for benchmarks.

use indra_core::{
    Bytes32, CommitmentV1, HybridPubKey, ProtocolVersion, VariableBytes,
    types::{
        block::{BlockHeaderV1, BlockV1},
        crypto::HybridSignature,
        primitives::{
            INITIAL_BASE_FEE_SPARK_PER_KB, MAX_VRF_PROOF_BYTES,
            MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES,
        },
        transaction::{InputV1, OutputV1, TransactionV1},
    },
};
use indra_crypto::{
    bls::BlsKeypair,
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    VrfKeypair,
};

/// A pre-built transaction for benchmarks.
pub fn dummy_tx(nonce: u8, fee: u64) -> TransactionV1 {
    TransactionV1 {
        version: ProtocolVersion::CURRENT,
        signature_module_id: 1,
        inputs: vec![InputV1 {
            utxo_id:   Bytes32::from([nonce; 32]),
            nullifier: Bytes32::from([nonce; 32]),
        }],
        outputs: vec![OutputV1 {
            commitment:   CommitmentV1 { compressed_point: Bytes32::ZERO },
            owner_pubkey: HybridPubKey {
                classical_pk: Bytes32::ZERO,
                pq_pk: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            },
            range_proof:  VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            lock_height:  0,
        }],
        fee_amount:     fee,
        fee_blinding:   Bytes32::ZERO,
        fee_commitment: CommitmentV1 { compressed_point: Bytes32::ZERO },
        signature: HybridSignature {
            classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(&[0u8; 64]).unwrap(),
            pq_sig:        VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&[0u8; 32]).unwrap(),
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
            protocol_version:    ProtocolVersion::CURRENT,
            height,
            prev_hash,
            timestamp:           1_700_000_000 + height,
            state_root:          Bytes32::ZERO,
            validator_set_root:  Bytes32::ZERO,
            mempool_set_root:    Bytes32::ZERO,
            base_fee:            INITIAL_BASE_FEE_SPARK_PER_KB,
            proposer_vrf_output: Bytes32::ZERO,
            proposer_vrf_proof:  VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
            quorum_certificate:  VariableBytes::from_slice(&[]).unwrap(),
        },
        transactions:      txs,
        slashing_evidence: vec![],
        governance_ops:    vec![],
    }
}

/// A hybrid keypair for benchmarks.
pub fn hybrid_keypair(seed: u8) -> HybridKeypair {
    let classical = ClassicalKeypair::from_seed(&[seed; 32]);
    let pq = PqKeypair::generate();
    HybridKeypair::new(classical, pq)
}

/// A BLS keypair for benchmarks.
pub fn bls_keypair(seed: u8) -> BlsKeypair {
    BlsKeypair::from_seed(&[seed; 32]).unwrap()
}

/// A VRF keypair for benchmarks.
pub fn vrf_keypair(seed: u8) -> VrfKeypair {
    VrfKeypair::from_seed(&[seed; 32])
}
