use indra_core::types::{
    block::VrfSuiteV1,
    consensus_snapshot::{ConsensusSnapshot, ConsensusSnapshotEntry},
    primitives::{Bytes32, Bytes64},
    proposal::proposer_vrf_alpha,
    staking::StakingOp,
};
use indra_crypto::{vrf_prove, vrf_verify, VrfKeypair};

fn rejected(
    pk: &[u8; 32],
    alpha: &[u8],
    output: &indra_crypto::VrfOutput,
    proof: &indra_crypto::VrfProof,
) -> bool {
    vrf_verify(pk, alpha, output, proof).is_err()
}

fn main() {
    let key = VrfKeypair::from_seed(&[0x31; 32]);
    let other_key = VrfKeypair::from_seed(&[0x32; 32]);
    let proposer = Bytes32([0x41; 32]);
    let other_proposer = Bytes32([0x42; 32]);
    let seed = Bytes64([0x51; 64]);
    let snapshot = ConsensusSnapshot::new(
        1,
        0,
        vec![ConsensusSnapshotEntry::new(
            proposer,
            1,
            [0x11; 32],
            indra_crypto::PqKeypair::from_seed(&[0x12; 32])
                .unwrap()
                .public_key()
                .0,
            key.public_key(),
            VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
            0,
        )
        .unwrap()],
        1u64 << 63,
    )
    .unwrap();
    let snapshot_other_activation = ConsensusSnapshot::new(
        2,
        1,
        vec![ConsensusSnapshotEntry::new(
            proposer,
            1,
            [0x11; 32],
            indra_crypto::PqKeypair::from_seed(&[0x12; 32])
                .unwrap()
                .public_key()
                .0,
            key.public_key(),
            VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
            1,
        )
        .unwrap()],
        1u64 << 63,
    )
    .unwrap();

    let alpha = proposer_vrf_alpha(
        b"indra-audit",
        &seed,
        7,
        3,
        &snapshot.snapshot_root,
        &proposer,
    )
    .unwrap();
    let (output, proof) = vrf_prove(&key, &alpha);
    vrf_verify(&key.public_key(), &alpha, &output, &proof).unwrap();

    let election_cases = [
        (
            "wrong_chain",
            proposer_vrf_alpha(
                b"indra-other",
                &seed,
                7,
                3,
                &snapshot.snapshot_root,
                &proposer,
            )
            .unwrap(),
        ),
        (
            "wrong_height",
            proposer_vrf_alpha(
                b"indra-audit",
                &seed,
                8,
                3,
                &snapshot.snapshot_root,
                &proposer,
            )
            .unwrap(),
        ),
        (
            "wrong_round",
            proposer_vrf_alpha(
                b"indra-audit",
                &seed,
                7,
                4,
                &snapshot.snapshot_root,
                &proposer,
            )
            .unwrap(),
        ),
        (
            "wrong_validator",
            proposer_vrf_alpha(
                b"indra-audit",
                &seed,
                7,
                3,
                &snapshot.snapshot_root,
                &other_proposer,
            )
            .unwrap(),
        ),
        (
            "wrong_snapshot",
            proposer_vrf_alpha(
                b"indra-audit",
                &seed,
                7,
                3,
                &snapshot_other_activation.snapshot_root,
                &proposer,
            )
            .unwrap(),
        ),
    ];
    for (name, wrong_alpha) in election_cases {
        assert!(rejected(&key.public_key(), &wrong_alpha, &output, &proof));
        println!("election_{name}=rejected");
    }
    assert!(rejected(&other_key.public_key(), &alpha, &output, &proof));
    println!("election_wrong_key=rejected");

    let pop = StakingOp::vrf_possession_challenge(
        "indra-audit",
        &proposer,
        &Bytes32(key.public_key()),
        9,
    )
    .unwrap();
    let (pop_output, pop_proof) = vrf_prove(&key, &pop);
    vrf_verify(&key.public_key(), &pop, &pop_output, &pop_proof).unwrap();
    let pop_cases = [
        StakingOp::vrf_possession_challenge(
            "indra-other",
            &proposer,
            &Bytes32(key.public_key()),
            9,
        )
        .unwrap(),
        StakingOp::vrf_possession_challenge(
            "indra-audit",
            &other_proposer,
            &Bytes32(key.public_key()),
            9,
        )
        .unwrap(),
        StakingOp::vrf_possession_challenge(
            "indra-audit",
            &proposer,
            &Bytes32(key.public_key()),
            10,
        )
        .unwrap(),
    ];
    for (index, wrong_pop) in pop_cases.iter().enumerate() {
        assert!(rejected(
            &key.public_key(),
            wrong_pop,
            &pop_output,
            &pop_proof
        ));
        println!("pop_wrong_context_{index}=rejected");
    }

    assert!(rejected(&key.public_key(), &alpha, &pop_output, &pop_proof));
    assert!(rejected(&key.public_key(), &pop, &output, &proof));
    println!("registration_pop_as_election=rejected");
    println!("election_proof_as_registration_pop=rejected");
    println!(
        "same_membership_different_snapshot_root={}",
        snapshot.snapshot_root != snapshot_other_activation.snapshot_root
    );
}
