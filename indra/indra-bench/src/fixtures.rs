//! Reusable test fixtures for benchmarks.

use indra_core::{
    types::{
        block::{BlockHeaderVNext, BlockProposalVNext, BlockVNext, SortitionClaimV1, VrfSuiteV1},
        crypto::HybridSignature,
        primitives::{
            Bytes64, INITIAL_BASE_FEE_SPARK_PER_KB, MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES,
            MAX_STANDARD_VRF_OUTPUT_BYTES, MAX_STANDARD_VRF_PROOF_BYTES,
            TRANSACTION_PROTOCOL_VERSION,
        },
        transaction::{InputV1, OutputV1, TransactionV1},
    },
    Bytes32, HybridPubKey, ProtocolVersion, VariableBytes,
};
use indra_crypto::{
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    VrfKeypair,
};

fn must<T, E>(value: Result<T, E>) -> T {
    match value {
        Ok(value) => value,
        Err(_) => std::process::abort(),
    }
}

/// A pre-built transaction for benchmarks.
pub fn dummy_tx(nonce: u8, fee: u64) -> TransactionV1 {
    TransactionV1 {
        version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
        signature_module_id: 1,
        inputs: vec![InputV1 {
            utxo_id: Bytes32::from([nonce; 32]),
        }],
        outputs: vec![OutputV1 {
            value_spark: 1_000_000,
            owner_pubkey: HybridPubKey {
                classical_pk: Bytes32::ZERO,
                pq_pk: must(VariableBytes::from_slice(&[0u8; 32])),
            },
            lock_height: 0,
        }],
        fee_amount: fee,
        signature: HybridSignature {
            classical_sig: must(VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(
                &[0u8; 64],
            )),
            pq_sig: must(VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&[0u8; 32])),
        },
    }
}

/// A block with N transactions.
pub fn dummy_block(height: u64, prev_hash: Bytes32, tx_count: usize) -> BlockVNext {
    let txs: Vec<TransactionV1> = (0..tx_count)
        .map(|i| dummy_tx(i as u8, INITIAL_BASE_FEE_SPARK_PER_KB * 10))
        .collect();

    let vrf = VrfKeypair::from_seed(&[0x42; 32]);
    let (vrf_output, vrf_proof) = indra_crypto::vrf_prove(&vrf, b"INDRA-BENCH-VRF-FIXTURE-v1");
    BlockVNext {
        header: BlockHeaderVNext {
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
            polc_round: None,
            proposer_id: Bytes32::ZERO,
            vrf_suite: VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
            election_seed: Bytes64([0; 64]),
            proposer_vrf_output: must(VariableBytes::<MAX_STANDARD_VRF_OUTPUT_BYTES>::from_slice(
                &vrf_output.0,
            )),
            proposer_vrf_proof: must(VariableBytes::<MAX_STANDARD_VRF_PROOF_BYTES>::from_slice(
                &vrf_proof.0,
            )),
            value_entropy: indra_core::types::block::ProposalEntropyV1 {
                origin_proposer_id: Bytes32::ZERO,
                origin_round: 0,
                vrf_output: must(VariableBytes::from_slice(&vrf_output.0)),
                vrf_proof: must(VariableBytes::from_slice(&vrf_proof.0)),
            },
            sortition_claim: SortitionClaimV1::PraosThreshold,
            proposer_priority: Bytes64([0; 64]),
            quorum_certificate: must(VariableBytes::from_slice(&[])),
        },
        transactions: txs,
        slashing_evidence: vec![],
        governance_ops: vec![],
        staking_ops: vec![],
    }
}

/// A canonical envelope for storage-only benchmarks.
pub fn dummy_proposal(height: u64, prev_hash: Bytes32, tx_count: usize) -> BlockProposalVNext {
    BlockProposalVNext {
        block: dummy_block(height, prev_hash, tx_count),
        proposer_authorization: HybridSignature {
            classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::default(),
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::default(),
        },
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
