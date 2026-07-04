//! Integration tests for the full consensus pipeline.
//!
//! Tests the complete path: mempool → block production → voting → QC.

use curve25519_dalek::scalar::Scalar;
use indra_consensus::{
    mempool::Mempool,
    producer::{produce_block, BlockTemplate},
    proposer::{ProposerCandidate, ProposerElection},
    qc::{verify_qc, verify_qc_strict, QcBuilder, QcValidator},
    vote::{produce_vote, RegisteredVoter, VoteCollector, VoteDecision},
};
use indra_core::{
    types::{
        crypto::HybridSignature,
        primitives::DEFAULT_CHAIN_ID,
        transaction::{InputV1, OutputV1, TransactionV1},
        vote::VoteStep,
        vrf_election::VrfElectionResult,
    },
    Bytes32, CommitmentV1, HybridPubKey, ProtocolVersion, VariableBytes,
};
use indra_crypto::{commit, prove_range, ClassicalKeypair, HybridKeypair, PqKeypair};
use indra_state::ChainState;
use rand::{rngs::StdRng, SeedableRng};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_user_keypair(seed: u8) -> (HybridPubKey, HybridKeypair) {
    let seed_bytes = [seed; 32];
    let classical = ClassicalKeypair::from_seed(&seed_bytes);
    let pq = PqKeypair::from_seed(&seed_bytes).unwrap();
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

fn derive_fee_blinding(input_blinding: [u8; 32], output_blinding: [u8; 32]) -> [u8; 32] {
    (Scalar::from_bytes_mod_order(input_blinding) - Scalar::from_bytes_mod_order(output_blinding))
        .to_bytes()
}

fn dummy_output(nonce: u8, value_spark: u64, owner_pubkey: HybridPubKey) -> OutputV1 {
    let blinding = [nonce; 32];
    let commitment = commit(value_spark, &blinding);
    let mut rng = StdRng::from_seed([nonce; 32]);
    let proof = prove_range(value_spark, &blinding, &mut rng).unwrap();
    OutputV1 {
        value_spark,
        commitment: CommitmentV1 {
            compressed_point: Bytes32::from(commitment.0),
        },
        owner_pubkey,
        range_proof: VariableBytes::from_slice(&proof).unwrap(),
        lock_height: 0,
    }
}

fn dummy_tx(
    chain_id: &str,
    keypair: &HybridKeypair,
    owner_pubkey: HybridPubKey,
    utxo_id: Bytes32,
    fee: u64,
    nonce: u8,
) -> TransactionV1 {
    let output_value = 1_100_000u64.saturating_sub(fee);
    let output_blinding = [nonce; 32];
    let fee_blinding = derive_fee_blinding([nonce; 32], output_blinding);
    let fee_commitment = commit(fee, &fee_blinding);
    let mut tx = TransactionV1 {
        version: ProtocolVersion::CURRENT,
        signature_module_id: 1,
        inputs: vec![InputV1 {
            utxo_id,
            nullifier: Bytes32::from([nonce; 32]),
        }],
        outputs: vec![dummy_output(nonce, output_value, owner_pubkey)],
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
    let sig = keypair.sign(&tx.signing_bytes(chain_id)).unwrap();
    tx.signature = HybridSignature {
        classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
        pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
    };
    tx
}

struct TestValidator {
    hybrid_kp: HybridKeypair,
    id: Bytes32,
    stake: u64,
}

impl TestValidator {
    fn new(seed: u8, stake: u64) -> Self {
        let classical = indra_crypto::hybrid::ClassicalKeypair::from_seed(&[seed; 32]);
        let pq = indra_crypto::hybrid::PqKeypair::generate();
        let hybrid_kp = HybridKeypair::new(classical, pq);
        let pk = hybrid_kp.public_key();
        let id = Bytes32::from(indra_crypto::sha256(&pk.classical.0));
        Self {
            hybrid_kp,
            id,
            stake,
        }
    }

    fn as_registered_voter(&self) -> RegisteredVoter {
        let pk = self.hybrid_kp.public_key();
        RegisteredVoter {
            validator_id: self.id,
            classical_pk: pk.classical.0,
            pq_pk: pk.pq.0.to_vec(),
            stake: self.stake,
        }
    }

    fn as_qc_validator(&self, position: usize) -> QcValidator {
        let pk = self.hybrid_kp.public_key();
        QcValidator {
            validator_id: self.id,
            position,
            pq_pk: pk.pq.0.to_vec(),
            classical_pk: pk.classical.0,
            stake: self.stake,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn mempool_to_block_pipeline() {
    let mut state = ChainState::new_genesis();
    let mut mempool = Mempool::default_config();
    let (owner_pubkey, owner_keypair) = make_user_keypair(0x55);

    // Seed spendable UTXOs, then submit some transactions that consume them.
    for i in 1..=5u8 {
        let utxo_id = state
            .utxos
            .insert(
                dummy_output(i, 1_100_000, owner_pubkey.clone()),
                0,
                0,
                i as u32,
            )
            .unwrap();
        mempool
            .submit(
                dummy_tx(
                    &state.chain_id,
                    &owner_keypair,
                    owner_pubkey.clone(),
                    utxo_id,
                    10_000 * i as u64,
                    i,
                ),
                state.base_fee,
                state.height,
            )
            .unwrap();
    }
    assert_eq!(mempool.len(), 5);

    // Set up election with single validator
    let seed = [0x42u8; 32];
    let vrf_keypair = indra_crypto::VrfKeypair::from_seed(&seed);
    let vrf_pubkey = vrf_keypair.public_key();
    let validator_id = Bytes32::from(indra_crypto::sha256(&vrf_pubkey));
    let election = ProposerElection {
        epoch_seed: Bytes32::from(seed),
        height: 1,
        round: 0,
        candidates: vec![ProposerCandidate {
            validator_id,
            vrf_pubkey,
            verified_vrf_output: None,
            stake: 1_000_000,
        }],
    };
    let slot = indra_consensus::proposer::compute_proposer_vrf(
        validator_id,
        &vrf_keypair,
        &election.epoch_seed,
        election.height,
        election.round,
    );
    let election_result_hash = VrfElectionResult {
        height: election.height,
        round: election.round,
        elected_validator_id: validator_id,
        elected_vrf_output: Bytes32::from(slot.vrf_output.0),
        fallback_used: false,
        reveal_set_commitment: Bytes32::ZERO,
    }
    .hash();

    let template = BlockTemplate {
        proposer_vrf_keypair: vrf_keypair,
        epoch_seed: Bytes32::from(seed),
        prev_qc_bytes: vec![],
        timestamp: 1_700_000_001,
        polc_round: None,
        slash_evidence: vec![],
        governance_ops: vec![],
        staking_ops: vec![],
        election_result_hash: Some(election_result_hash),
        election_result: None,
        vrf_reveals: vec![],
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
    let round = 0u32;

    // All 3 validators cast precommit votes
    let voters: Vec<RegisteredVoter> = validators.iter().map(|v| v.as_registered_voter()).collect();

    let mut collector = VoteCollector::new(
        height,
        round,
        VoteStep::Precommit,
        DEFAULT_CHAIN_ID.to_string(),
        voters,
    );

    for v in &validators {
        let vote = produce_vote(
            height,
            round,
            VoteStep::Precommit,
            block_hash,
            v.id,
            DEFAULT_CHAIN_ID,
            &v.hybrid_kp,
        )
        .unwrap();
        collector.add_vote(vote).unwrap();
    }

    assert!(matches!(
        collector.current_decision(),
        VoteDecision::QuorumReached { .. }
    ));

    // Build QC
    let qc_validators: Vec<QcValidator> = validators
        .iter()
        .enumerate()
        .map(|(i, v)| v.as_qc_validator(i))
        .collect();

    let mut builder = QcBuilder::new(
        height,
        round,
        block_hash,
        DEFAULT_CHAIN_ID.to_string(),
        qc_validators.clone(),
    );
    for vote in collector.accepted_votes() {
        builder.add_precommit(vote.clone());
    }

    let qc = builder.build().unwrap();
    assert_eq!(qc.signer_count(), 3);

    assert!(verify_qc(&qc, &qc_validators, total_stake, DEFAULT_CHAIN_ID).is_ok());
    assert!(verify_qc_strict(&qc, &qc_validators, total_stake, DEFAULT_CHAIN_ID).is_ok());
}

#[test]
fn age_eligible_txs_included_first() {
    let state = ChainState::new_genesis();
    let mut mempool = Mempool::default_config();
    let (owner_pubkey, owner_keypair) = make_user_keypair(0x66);

    // Old tx (age-eligible) with low fee
    mempool
        .submit(
            dummy_tx(
                &state.chain_id,
                &owner_keypair,
                owner_pubkey.clone(),
                Bytes32::from([0x01; 32]),
                1_000,
                0x01,
            ),
            state.base_fee,
            1,
        )
        .unwrap();
    // New tx with high fee
    mempool
        .submit(
            dummy_tx(
                &state.chain_id,
                &owner_keypair,
                owner_pubkey,
                Bytes32::from([0x02; 32]),
                999_000,
                0x02,
            ),
            state.base_fee,
            100,
        )
        .unwrap();

    // At height 51+ the first tx is age-eligible
    let selected = mempool.select_for_block(10, 1 + indra_consensus::mempool::AGE_INCLUSION_BLOCKS);

    // Age-eligible tx (fee=1_000) must come first
    assert_eq!(selected.first().map(|e| e.tx.fee_amount), Some(1_000));
}

#[test]
fn qc_builder_quorum_detection() {
    let v1 = TestValidator::new(0x10, 7_000);
    let v2 = TestValidator::new(0x20, 3_000);
    let block_hash = Bytes32::from([0x55u8; 32]);

    let qc_validators = vec![v1.as_qc_validator(0), v2.as_qc_validator(1)];

    let mut builder = QcBuilder::new(
        1,
        0,
        block_hash,
        DEFAULT_CHAIN_ID.to_string(),
        qc_validators.clone(),
    );

    // Before any votes
    assert_eq!(builder.current_stake_bps(), 0);

    // v1 votes (70%) → quorum reached (need > 2/3)
    let vote1 = produce_vote(
        1,
        0,
        VoteStep::Precommit,
        block_hash,
        v1.id,
        DEFAULT_CHAIN_ID,
        &v1.hybrid_kp,
    )
    .unwrap();
    builder.add_precommit(vote1);
    assert!(builder.current_stake_bps() >= 6_667);
    assert!(builder.build().is_ok());
}

#[test]
fn strict_qc_verification_accepts_hybrid_qc() {
    use indra_core::types::crypto::PQVoteSig;
    use indra_core::types::primitives::{VariableBytes, MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES};
    use indra_core::types::qc::{ClassicalVoteSig, QuorumCertificateV1, SIGNER_BITFIELD_BYTES};

    let validators = vec![
        TestValidator::new(0x21, 3_400),
        TestValidator::new(0x22, 3_300),
        TestValidator::new(0x23, 3_300),
    ];
    let qc_validators: Vec<QcValidator> = validators
        .iter()
        .enumerate()
        .map(|(i, v)| v.as_qc_validator(i))
        .collect();
    let block_hash = Bytes32::from([0xEFu8; 32]);
    let height = 7u64;
    let round = 0u32;

    let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
    let mut pq_signatures = Vec::new();
    let mut classical_signatures = Vec::new();
    validators
        .iter()
        .enumerate()
        .for_each(|(position, validator)| {
            signer_bitfield[position / 8] |= 1 << (position % 8);
            let vote = produce_vote(
                height,
                round,
                VoteStep::Precommit,
                block_hash,
                validator.id,
                DEFAULT_CHAIN_ID,
                &validator.hybrid_kp,
            )
            .unwrap();
            pq_signatures.push(PQVoteSig {
                validator_id: validator.id,
                pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(
                    vote.signature.pq_sig.as_slice(),
                )
                .unwrap(),
            });
            classical_signatures.push(ClassicalVoteSig {
                validator_id: validator.id,
                classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(
                    vote.signature.classical_sig.as_slice(),
                )
                .unwrap(),
            });
        });
    let qc = QuorumCertificateV1 {
        height,
        round,
        block_hash,
        election_result_hash: None,
        signer_bitfield,
        pq_signatures,
        classical_signatures,
    };

    assert!(verify_qc_strict(&qc, &qc_validators, 10_000, DEFAULT_CHAIN_ID).is_ok());
}
