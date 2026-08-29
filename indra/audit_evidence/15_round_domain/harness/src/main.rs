use indra_consensus::{
    qc::{build_qc, verify_qc, QcValidator},
    vote::produce_vote,
};
use indra_core::{
    codec::{Decode, Encode},
    types::{
        block::{BlockHeaderVNext, ProposalEntropyV1, SortitionClaimV1, VrfSuiteV1},
        crypto::HybridSignature,
        primitives::{
            Bytes32, Bytes64, ProtocolVersion, VariableBytes, BLOCK_FORMAT_VERSION,
            DEFAULT_CHAIN_ID, MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES,
        },
        qc::{QuorumCertificateV1, SIGNER_BITFIELD_BYTES},
        vote::{VoteStep, VoteV1},
    },
};
use indra_crypto::hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair};
use indra_storage::{VoteSafetyLoadResult, VoteSafetyStore};

const LEGAL_ROUNDS: [u32; 2] = [0, 1023];
const ILLEGAL_ROUNDS: [u32; 3] = [1024, 1025, u32::MAX];

fn header(round: u32) -> BlockHeaderVNext {
    BlockHeaderVNext {
        protocol_version: ProtocolVersion(BLOCK_FORMAT_VERSION),
        height: 0,
        prev_hash: Bytes32::ZERO,
        timestamp: 0,
        state_root: Bytes32::ZERO,
        validator_set_root: Bytes32::ZERO,
        mempool_set_root: Bytes32::ZERO,
        value_hash: Bytes32::ZERO,
        base_fee: 0,
        proposer_round: round,
        polc_round: None,
        quorum_certificate: VariableBytes::default(),
        proposer_id: Bytes32::ZERO,
        vrf_suite: VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
        election_seed: Bytes64::ZERO,
        proposer_vrf_output: VariableBytes::default(),
        proposer_vrf_proof: VariableBytes::default(),
        value_entropy: ProposalEntropyV1::genesis(),
        sortition_claim: SortitionClaimV1::PraosThreshold,
        proposer_priority: Bytes64::ZERO,
    }
}

fn vote(round: u32) -> VoteV1 {
    VoteV1 {
        height: 1,
        round,
        step: VoteStep::Prevote,
        block_hash: Bytes32::ZERO,
        validator_id: Bytes32::ZERO,
        signature: HybridSignature {
            classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::default(),
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::default(),
        },
    }
}

fn qc(round: u32) -> QuorumCertificateV1 {
    QuorumCertificateV1 {
        height: 1,
        round,
        block_hash: Bytes32::ZERO,
        signer_bitfield: [0; SIGNER_BITFIELD_BYTES],
        pq_signatures: vec![],
        classical_signatures: vec![],
    }
}

fn main() {
    let keypair = HybridKeypair::new(
        ClassicalKeypair::from_seed(&[0x31; 32]),
        PqKeypair::from_seed(&[0x32; 32]).unwrap(),
    );
    let public_key = keypair.public_key();
    let validator = QcValidator {
        validator_id: indra_core::types::crypto::hybrid_identity_id(
            &public_key.classical.0,
            &public_key.pq.0,
        ),
        position: 0,
        pq_pk: public_key.pq.0.to_vec(),
        classical_pk: public_key.classical.0,
        stake: 10_000,
    };
    let block_hash = Bytes32::from([0xA5; 32]);
    let path = std::env::temp_dir().join(format!(
        "indra-round-domain-audit-{}.dat",
        std::process::id()
    ));
    let store = VoteSafetyStore::open(&path);
    for round in LEGAL_ROUNDS {
        assert_eq!(
            BlockHeaderVNext::decode_exact(&header(round).encode_to_vec())
                .unwrap()
                .proposer_round,
            round
        );
        assert_eq!(
            VoteV1::decode_exact(&vote(round).encode_to_vec())
                .unwrap()
                .round,
            round
        );
        assert_eq!(
            QuorumCertificateV1::decode_exact(&qc(round).encode_to_vec())
                .unwrap()
                .round,
            round
        );
        let signed_vote = produce_vote(
            1,
            round,
            VoteStep::Precommit,
            block_hash,
            validator.validator_id,
            DEFAULT_CHAIN_ID,
            &keypair,
        )
        .unwrap();
        let signed_qc = build_qc(
            1,
            round,
            block_hash,
            DEFAULT_CHAIN_ID,
            std::slice::from_ref(&validator),
            vec![&signed_vote],
        )
        .unwrap();
        verify_qc(
            &signed_qc,
            std::slice::from_ref(&validator),
            validator.stake,
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        store.record(1, round, 0, None).unwrap();
        assert!(matches!(
            store.load(),
            VoteSafetyLoadResult::Record(record) if record.round == round
        ));
    }
    for round in ILLEGAL_ROUNDS {
        assert!(BlockHeaderVNext::decode_exact(&header(round).encode_to_vec()).is_err());
        assert!(VoteV1::decode_exact(&vote(round).encode_to_vec()).is_err());
        assert!(QuorumCertificateV1::decode_exact(&qc(round).encode_to_vec()).is_err());
        assert!(produce_vote(
            1,
            round,
            VoteStep::Precommit,
            block_hash,
            validator.validator_id,
            DEFAULT_CHAIN_ID,
            &keypair,
        )
        .is_err());
        assert!(store.record(1, round, 0, None).is_err());
    }
    let _ = std::fs::remove_file(path);
    println!("round-domain regression: PASS (0/1023 accepted; 1024/1025/MAX rejected)");
}
