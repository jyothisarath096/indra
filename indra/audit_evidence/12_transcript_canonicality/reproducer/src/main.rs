use indra_core::{
    codec::Encode,
    sortition::evaluate,
    types::{
        block::{
            BlockHeaderVNext, BlockProposalVNext, BlockVNext, ProposalEntropyV1, SortitionClaimV1,
            VrfSuiteV1,
        },
        consensus_snapshot::{ConsensusSnapshot, ConsensusSnapshotEntry},
        crypto::{HybridPubKey, HybridSignature},
        primitives::{Bytes32, Bytes64, ProtocolVersion, VariableBytes},
        proposal::{next_election_seed, proposer_vrf_alpha, verify_proposal},
    },
};
use indra_crypto::{HybridKeypair, VrfKeypair};

fn wire_signature(sig: indra_crypto::HybridSignature) -> HybridSignature {
    HybridSignature {
        classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
        pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
    }
}

fn sign(
    mut proposal: BlockProposalVNext,
    chain_id: &[u8],
    key: &HybridKeypair,
) -> BlockProposalVNext {
    let bytes = proposal.signing_bytes(chain_id).unwrap();
    proposal.proposer_authorization = wire_signature(key.sign(&bytes).unwrap());
    proposal
}

fn main() {
    let chain_id = b"indra-transcript-audit";
    let seed = Bytes64([0x42; 64]);
    let hot = HybridKeypair::new(
        indra_crypto::ClassicalKeypair::from_seed(&[0x11; 32]),
        indra_crypto::PqKeypair::from_seed(&[0x12; 32]).unwrap(),
    );
    let hp = hot.public_key();
    let wire_pk = HybridPubKey {
        classical_pk: Bytes32(hp.classical.0),
        pq_pk: VariableBytes::from_slice(&hp.pq.0).unwrap(),
    };
    let proposer_id = wire_pk.identity_id();

    // Deterministically find one key eligible in rounds 0, 1, and 2.
    let (vrf, snapshot, claims) = (0u32..)
        .find_map(|counter| {
            let mut key_seed = [0x33; 32];
            key_seed[..4].copy_from_slice(&counter.to_le_bytes());
            let vrf = VrfKeypair::from_seed(&key_seed);
            let entry = ConsensusSnapshotEntry::new(
                proposer_id,
                1,
                hp.classical.0,
                hp.pq.0,
                vrf.public_key(),
                VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
                0,
            )
            .unwrap();
            let snapshot = ConsensusSnapshot::new(1, 0, vec![entry], 1u64 << 63).unwrap();
            let log = snapshot.sortition_log_interval().unwrap();
            let mut claims = Vec::new();
            for round in 0..=2 {
                let alpha = proposer_vrf_alpha(
                    chain_id,
                    &seed,
                    7,
                    round,
                    &snapshot.snapshot_root,
                    &proposer_id,
                )
                .unwrap();
                let (output, proof) = indra_crypto::vrf_prove(&vrf, &alpha);
                if !evaluate(&log, 1, 1, &output.0).unwrap().eligible {
                    return None;
                }
                claims.push((output, proof));
            }
            Some((vrf, snapshot, claims))
        })
        .expect("bounded deterministic search finds three eligible rounds");
    let _keep_key_alive = vrf;

    let current = &claims[2];
    let entropy_round_zero = &claims[0];
    let entropy_round_one = &claims[1];
    let empty_sig = HybridSignature {
        classical_sig: VariableBytes::default(),
        pq_sig: VariableBytes::default(),
    };
    let base_header = BlockHeaderVNext {
        protocol_version: ProtocolVersion::CURRENT,
        height: 7,
        prev_hash: Bytes32([0x01; 32]),
        timestamp: 123,
        state_root: Bytes32([0x02; 32]),
        validator_set_root: Bytes32([0x03; 32]),
        mempool_set_root: Bytes32::from(indra_crypto::sha256(&[])),
        value_hash: BlockHeaderVNext::compute_value_hash(
            7,
            Bytes32([0x01; 32]),
            123,
            Bytes32([0x02; 32]),
            Bytes32([0x03; 32]),
            Bytes32::from(indra_crypto::sha256(&[])),
            &ProposalEntropyV1 {
                origin_proposer_id: proposer_id,
                origin_round: 0,
                vrf_output: VariableBytes::from_slice(&entropy_round_zero.0 .0).unwrap(),
                vrf_proof: VariableBytes::from_slice(&entropy_round_zero.1 .0).unwrap(),
            },
            0,
            0,
        ),
        base_fee: 0,
        proposer_round: 2,
        polc_round: 0,
        quorum_certificate: VariableBytes::default(),
        proposer_id,
        vrf_suite: VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
        election_seed: seed,
        proposer_vrf_output: VariableBytes::from_slice(&current.0 .0).unwrap(),
        proposer_vrf_proof: VariableBytes::from_slice(&current.1 .0).unwrap(),
        value_entropy: ProposalEntropyV1 {
            origin_proposer_id: proposer_id,
            origin_round: 0,
            vrf_output: VariableBytes::from_slice(&entropy_round_zero.0 .0).unwrap(),
            vrf_proof: VariableBytes::from_slice(&entropy_round_zero.1 .0).unwrap(),
        },
        sortition_claim: SortitionClaimV1::PraosThreshold,
        proposer_priority: Bytes64(indra_core::sortition::priority(
            &current.0 .0,
            &proposer_id.0,
        )),
    };
    let block = BlockVNext {
        header: base_header,
        transactions: vec![],
        slashing_evidence: vec![],
        governance_ops: vec![],
        staking_ops: vec![],
    };
    let original = sign(
        BlockProposalVNext {
            block,
            proposer_authorization: empty_sig.clone(),
        },
        chain_id,
        &hot,
    );
    let mut substituted = original.clone();
    substituted.block.header.value_entropy = ProposalEntropyV1 {
        origin_proposer_id: proposer_id,
        origin_round: 1,
        vrf_output: VariableBytes::from_slice(&entropy_round_one.0 .0).unwrap(),
        vrf_proof: VariableBytes::from_slice(&entropy_round_one.1 .0).unwrap(),
    };
    substituted.block.header.value_hash = substituted.block.compute_value_hash(0);
    substituted.proposer_authorization = empty_sig;
    substituted = sign(substituted, chain_id, &hot);

    assert_ne!(
        original.block.header.value_hash,
        substituted.block.header.value_hash
    );
    assert_ne!(
        original.block.header.value_entropy,
        substituted.block.header.value_entropy
    );
    let first = verify_proposal(&original, chain_id, &seed, &snapshot);
    let second = verify_proposal(&substituted, chain_id, &seed, &snapshot);
    let next_seed_original =
        next_election_seed(chain_id, &seed, &original.block, &snapshot.snapshot_root).unwrap();
    let next_seed_substituted =
        next_election_seed(chain_id, &seed, &substituted.block, &snapshot.snapshot_root).unwrap();
    assert_ne!(next_seed_original, next_seed_substituted);
    println!(
        "original_value_hash={}",
        hex(&original.block.header.value_hash.0)
    );
    println!(
        "substituted_value_hash={}",
        hex(&substituted.block.header.value_hash.0)
    );
    println!(
        "original_polc_authorizes_substituted={}",
        original.block.header.value_hash == substituted.block.header.value_hash
    );
    println!(
        "original_entropy={}",
        hex(&original.block.header.value_entropy.encode_to_vec())
    );
    println!(
        "substituted_entropy={}",
        hex(&substituted.block.header.value_entropy.encode_to_vec())
    );
    println!(
        "original_authorization_transcript={}",
        hex(&original.signing_bytes(chain_id).unwrap())
    );
    println!(
        "substituted_authorization_transcript={}",
        hex(&substituted.signing_bytes(chain_id).unwrap())
    );
    println!("original_verifies={}", first.is_ok());
    println!("substituted_verifies={}", second.is_ok());
    println!("next_seed_original={}", hex(&next_seed_original.0));
    println!("next_seed_substituted={}", hex(&next_seed_substituted.0));
    println!(
        "next_seeds_differ={}",
        next_seed_original != next_seed_substituted
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
