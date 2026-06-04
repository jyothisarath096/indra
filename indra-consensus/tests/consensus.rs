//! Integration tests for the full consensus pipeline.
//!
//! Tests the complete path: mempool → block production → voting → QC.

use indra_core::{
    Bytes32, CommitmentV1, HybridPubKey, ProtocolVersion, VariableBytes,
    types::{
        crypto::HybridSignature,
        transaction::{InputV1, OutputV1, TransactionV1},
        vote::VoteStep,
    },
};
use indra_crypto::{
    hybrid::HybridKeypair,
    VrfKeypair,
};
use indra_state::ChainState;
use indra_consensus::{
    mempool::Mempool,
    proposer::{ProposerCandidate, ProposerElection},
    producer::{BlockTemplate, produce_block},
    vote::{RegisteredVoter, VoteCollector, VoteDecision, produce_vote},
    qc::{QcBuilder, QcValidator, verify_qc, verify_qc_strict},
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn dummy_tx(fee: u64, nonce: u8) -> TransactionV1 {
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
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig:        VariableBytes::from_slice(&[0u8; 32]).unwrap(),
        },
    }
}

struct TestValidator {
    hybrid_kp: HybridKeypair,
    id:        Bytes32,
    stake:     u64,
}

impl TestValidator {
    fn new(seed: u8, stake: u64) -> Self {
        let classical = indra_crypto::hybrid::ClassicalKeypair::from_seed(&[seed; 32]);
        let pq = indra_crypto::hybrid::PqKeypair::generate();
        let hybrid_kp = HybridKeypair::new(classical, pq);
        let pk = hybrid_kp.public_key();
        let id = Bytes32::from(indra_crypto::sha256(&pk.classical.0));
        Self { hybrid_kp, id, stake }
    }

    fn as_registered_voter(&self) -> RegisteredVoter {
        let pk = self.hybrid_kp.public_key();
        RegisteredVoter {
            validator_id: self.id,
            classical_pk: pk.classical.0,
            pq_pk:        pk.pq.0.clone(),
            stake:        self.stake,
        }
    }

    fn as_qc_validator(&self, position: usize) -> QcValidator {
        let pk = self.hybrid_kp.public_key();
        QcValidator {
            validator_id: self.id,
            position,
            pq_pk:        pk.pq.0.clone(),
            stake:        self.stake,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn mempool_to_block_pipeline() {
    let state = ChainState::new_genesis();
    let mut mempool = Mempool::default_config();

    // Submit some transactions
    for i in 1..=5u8 {
        mempool.submit(dummy_tx(10_000 * i as u64, i), state.base_fee, state.height).unwrap();
    }
    assert_eq!(mempool.len(), 5);

    // Set up election with single validator
    let seed = [0x42u8; 32];
    let vrf_pubkey = indra_crypto::VrfKeypair::from_seed(&seed).public_key();
    let election = ProposerElection {
        epoch_seed: Bytes32::from(seed),
        height: 1,
        round: 0,
        candidates: vec![ProposerCandidate {
            validator_id: Bytes32::from(indra_crypto::sha256(&vrf_pubkey)),
            vrf_pubkey,
            stake:        1_000_000,
        }],
    };

    let template = BlockTemplate {
        proposer_vrf_keypair: VrfKeypair::from_seed(&seed),
        epoch_seed:           Bytes32::from(seed),
        prev_qc_bytes:        vec![],
        timestamp:            1_700_000_001,
    };

    let block = produce_block(&template, &state, &mempool, &election).unwrap();
    assert_eq!(block.transactions.len(), 5);
    assert_eq!(block.header.height, 1);
}

#[test]
fn full_consensus_round() {
    // 3 validators, each with ~33% stake
    let validators = vec![
        TestValidator::new(0x01, 3_400),
        TestValidator::new(0x02, 3_300),
        TestValidator::new(0x03, 3_300),
    ];
    let total_stake: u64 = validators.iter().map(|v| v.stake).sum();
    let block_hash = Bytes32::from([0xAAu8; 32]);
    let height = 1u64;
    let round  = 0u32;

    // All 3 validators cast precommit votes
    let voters: Vec<RegisteredVoter> = validators.iter()
        .map(|v| v.as_registered_voter())
        .collect();

    let mut collector = VoteCollector::new(height, round, VoteStep::Precommit, voters);

    for v in &validators {
        let vote = produce_vote(height, round, VoteStep::Precommit, block_hash, v.id, &v.hybrid_kp).unwrap();
        collector.add_vote(vote).unwrap();
    }

    assert!(matches!(
        collector.current_decision(),
        VoteDecision::QuorumReached { .. }
    ));

    // Build QC
    let qc_validators: Vec<QcValidator> = validators.iter().enumerate()
        .map(|(i, v)| v.as_qc_validator(i))
        .collect();

    let mut builder = QcBuilder::new(height, round, block_hash, qc_validators.clone());
    for vote in collector.accepted_votes() {
        builder.add_precommit(vote.clone());
    }

    let qc = builder.build().unwrap();
    assert_eq!(qc.signer_count(), 3);

    assert!(verify_qc(&qc, &qc_validators, total_stake).is_ok());
    assert!(verify_qc_strict(&qc, &qc_validators, total_stake).is_ok());
}

#[test]
fn age_eligible_txs_included_first() {
    let state = ChainState::new_genesis();
    let mut mempool = Mempool::default_config();

    // Old tx (age-eligible) with low fee
    mempool.submit(dummy_tx(1_000, 0x01), state.base_fee, 1).unwrap();
    // New tx with high fee
    mempool.submit(dummy_tx(999_000, 0x02), state.base_fee, 100).unwrap();

    // At height 51+ the first tx is age-eligible
    let selected = mempool.select_for_block(
        10,
        1 + indra_consensus::mempool::AGE_INCLUSION_BLOCKS,
    );

    // Age-eligible tx (fee=1_000) must come first
    assert_eq!(selected.first().map(|e| e.tx.fee_amount), Some(1_000));
}

#[test]
fn qc_builder_quorum_detection() {
    let v1 = TestValidator::new(0x10, 7_000);
    let v2 = TestValidator::new(0x20, 3_000);
    let block_hash = Bytes32::from([0x55u8; 32]);

    let qc_validators = vec![
        v1.as_qc_validator(0),
        v2.as_qc_validator(1),
    ];

    let mut builder = QcBuilder::new(1, 0, block_hash, qc_validators.clone());

    // Before any votes
    assert_eq!(builder.current_stake_bps(), 0);

    // v1 votes (70%) → quorum reached (need > 2/3)
    let vote1 = produce_vote(1, 0, VoteStep::Precommit, block_hash, v1.id, &v1.hybrid_kp).unwrap();
    builder.add_precommit(vote1);
    assert!(builder.current_stake_bps() >= 6_667);
    assert!(builder.build().is_ok());
}

#[test]
fn strict_qc_verification_accepts_dilithium_only_qc() {
    use indra_core::types::crypto::PQVoteSig;
    use indra_core::types::primitives::{MAX_PQ_SIG_BYTES, VariableBytes};
    use indra_core::types::qc::{QuorumCertificateV1, SIGNER_BITFIELD_BYTES};

    let validators = vec![
        TestValidator::new(0x21, 3_400),
        TestValidator::new(0x22, 3_300),
        TestValidator::new(0x23, 3_300),
    ];
    let qc_validators: Vec<QcValidator> = validators.iter().enumerate()
        .map(|(i, v)| v.as_qc_validator(i))
        .collect();
    let block_hash = Bytes32::from([0xEFu8; 32]);
    let height = 7u64;
    let round = 0u32;

    let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
    let mut pq_signatures = Vec::new();
    validators.iter().enumerate().for_each(|(position, validator)| {
        signer_bitfield[position / 8] |= 1 << (position % 8);
        let vote = produce_vote(height, round, VoteStep::Precommit, block_hash, validator.id, &validator.hybrid_kp).unwrap();
        pq_signatures.push(PQVoteSig {
            validator_id: validator.id,
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(vote.signature.pq_sig.as_slice()).unwrap(),
        });
    });
    let qc = QuorumCertificateV1 {
        height,
        round,
        block_hash,
        signer_bitfield,
        pq_signatures,
    };

    assert!(verify_qc_strict(&qc, &qc_validators, 10_000).is_ok());
}
