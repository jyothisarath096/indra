use indra_consensus::{
    qc::{build_qc, QcValidator},
    vote::produce_vote,
};
use indra_core::types::{
    block::VrfSuiteV1,
    consensus_snapshot::{ConsensusSnapshot, ConsensusSnapshotEntry},
    primitives::{Bytes32, DEFAULT_CHAIN_ID, MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR},
    qc::verify_qc_against_snapshot,
    vote::VoteStep,
};
use indra_crypto::{
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    VrfKeypair,
};

fn main() {
    let signer = HybridKeypair::new(
        ClassicalKeypair::from_seed(&[0x41; 32]),
        PqKeypair::from_seed(&[0x42; 32]).unwrap(),
    );
    let public = signer.public_key();
    let validator_id =
        indra_core::types::crypto::hybrid_identity_id(&public.classical.0, &public.pq.0);
    let vrf_pk = VrfKeypair::from_seed(&[0x43; 32]).public_key();

    let entry = |weight| {
        ConsensusSnapshotEntry::new(
            validator_id,
            weight,
            public.classical.0,
            public.pq.0,
            vrf_pk,
            VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
            0,
        )
        .unwrap()
    };
    let snapshot_a = ConsensusSnapshot::new(
        1,
        0,
        vec![entry(1)],
        MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
    )
    .unwrap();
    let snapshot_b = ConsensusSnapshot::new(
        1,
        0,
        vec![entry(2)],
        MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
    )
    .unwrap();
    assert_ne!(snapshot_a.snapshot_root, snapshot_b.snapshot_root);

    let block_hash = Bytes32([0xA5; 32]);
    let vote = produce_vote(
        1,
        0,
        VoteStep::Precommit,
        block_hash,
        validator_id,
        snapshot_a.snapshot_root,
        DEFAULT_CHAIN_ID,
        &signer,
    )
    .unwrap();
    let validator = QcValidator {
        validator_id,
        position: 0,
        pq_pk: public.pq.0.to_vec(),
        classical_pk: public.classical.0,
        stake: 1,
    };
    let qc = build_qc(
        1,
        0,
        block_hash,
        DEFAULT_CHAIN_ID,
        snapshot_a.snapshot_root,
        &[validator],
        vec![&vote],
    )
    .unwrap();

    let accepted_a = verify_qc_against_snapshot(&qc, &snapshot_a, DEFAULT_CHAIN_ID).is_ok();
    let accepted_b = verify_qc_against_snapshot(&qc, &snapshot_b, DEFAULT_CHAIN_ID).is_ok();
    println!(
        "snapshot_a_root={}",
        hex::encode(snapshot_a.snapshot_root.0)
    );
    println!(
        "snapshot_b_root={}",
        hex::encode(snapshot_b.snapshot_root.0)
    );
    println!("same_qc_accepted_under_snapshot_a={accepted_a}");
    println!("same_qc_accepted_under_snapshot_b={accepted_b}");
    assert!(accepted_a && !accepted_b);
}
