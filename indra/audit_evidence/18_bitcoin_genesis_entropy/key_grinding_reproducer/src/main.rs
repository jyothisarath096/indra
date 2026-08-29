use indra_core::types::{
    block::VrfSuiteV1,
    consensus_snapshot::{ConsensusSnapshot, ConsensusSnapshotEntry},
    crypto::HybridPubKey,
    primitives::{Bytes32, VariableBytes, MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR},
    staking::StakingOp,
};
use indra_core::{sortition::{evaluate, priority}, types::proposal::proposer_vrf_alpha};
use indra_crypto::{
    sha256, vrf_prove, vrf_verify, ClassicalKeypair, PqKeypair, VrfKeypair,
};
use indra_node::genesis::{derive_genesis_election_seed, BitcoinPowEntropySourceV1, GenesisSettings};

const CHAIN_ID: &str = "indra-key-grinding-audit-v1";
const STAKE: u64 = 100_000_000_000;
const ROUNDS: u32 = 32;

fn seed(domain: &[u8], i: u32) -> [u8; 32] {
    let mut material = domain.to_vec();
    material.extend_from_slice(&i.to_le_bytes());
    sha256(&material)
}

fn fixed_identity(i: u32) -> (Bytes32, [u8; 32], [u8; indra_crypto::PQ_PK_BYTES]) {
    let classical = ClassicalKeypair::from_seed(&seed(b"INDRA-GRIND-ID-ED-v1", i));
    let pq = PqKeypair::from_seed(&seed(b"INDRA-GRIND-ID-PQ-v1", i)).unwrap();
    let classical_pk = classical.public_key().0;
    let pq_pk = pq.public_key().0;
    let identity = HybridPubKey {
        classical_pk: Bytes32(classical_pk),
        pq_pk: VariableBytes::from_slice(&pq_pk).unwrap(),
    };
    (identity.identity_id(), classical_pk, pq_pk)
}

fn snapshot(candidate: &VrfKeypair) -> (ConsensusSnapshot, Bytes32) {
    let mut entries = Vec::new();
    let candidate_id = fixed_identity(0).0;
    for i in 0..4 {
        let (id, classical, pq) = fixed_identity(i);
        let vrf_pk = if i == 0 {
            candidate.public_key()
        } else {
            VrfKeypair::from_seed(&seed(b"INDRA-GRIND-FIXED-VRF-v1", i)).public_key()
        };
        entries.push(
            ConsensusSnapshotEntry::new(
                id,
                STAKE,
                classical,
                pq,
                vrf_pk,
                VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
                0,
            )
            .unwrap(),
        );
    }
    entries.sort_by_key(|entry| entry.validator_id);
    let snapshot = ConsensusSnapshot::new(
        1,
        0,
        entries,
        MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
    )
    .unwrap();
    (snapshot, candidate_id)
}

fn main() {
    let settings = GenesisSettings {
        chain_id: CHAIN_ID.to_string(),
        active_slot_coefficient_numerator: MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
        bitcoin_pow_entropy_source: BitcoinPowEntropySourceV1 {
            scheme: 1,
            network_genesis_hash: "11".repeat(32),
            announced_height: 900_000,
            header_codec: 1,
            extraction_algorithm: 1,
            minimum_confirmations: 100,
            reorg_policy: 1,
        },
        bitcoin_pow_entropy_header: "42".repeat(80),
    };
    let election_seed = derive_genesis_election_seed(&settings).unwrap();
    println!("election_seed={}", hex::encode(election_seed.0));
    println!("stake={STAKE} total_stake={} f_numerator={MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR}", STAKE * 4);

    let limits = [2usize, 16, 256, 4096];
    let reference_key = VrfKeypair::from_seed(&seed(b"INDRA-GENESIS-VRF-GRIND-v1", 0));
    let (reference_snapshot, _) = snapshot(&reference_key);
    let log = reference_snapshot.sortition_log_interval().unwrap();
    let threshold_integer = evaluate(&log, STAKE, STAKE * 4, &[0; 64]).unwrap().threshold;
    let encoded_threshold = threshold_integer.to_bytes_be();
    let mut threshold = [0u8; 64];
    threshold[64 - encoded_threshold.len()..].copy_from_slice(&encoded_threshold);
    let mut best: Option<(u32, [u8; 64], usize, [u8; 32], Bytes32)> = None;
    for index in 0..4096usize {
        let key = VrfKeypair::from_seed(&seed(b"INDRA-GENESIS-VRF-GRIND-v1", index as u32));
        let (snapshot, id) = snapshot(&key);

        // Every candidate is a genuine key with a valid genesis PoP.
        let challenge = StakingOp::vrf_possession_challenge(
            CHAIN_ID,
            &id,
            &Bytes32(key.public_key()),
            0,
        )
        .unwrap();
        let (pop_output, pop_proof) = vrf_prove(&key, &challenge);
        vrf_verify(&key.public_key(), &challenge, &pop_output, &pop_proof).unwrap();

        let mut first = u32::MAX;
        let mut first_priority = [0xff; 64];
        let mut eligible_32 = 0usize;
        for round in 0..ROUNDS {
            let alpha = proposer_vrf_alpha(
                CHAIN_ID.as_bytes(),
                &election_seed,
                1, round,
                &snapshot.snapshot_root,
                &id,
            )
            .unwrap();
            let (output, _) = vrf_prove(&key, &alpha);
            if output.0 < threshold {
                eligible_32 += 1;
                if first == u32::MAX {
                    first = round;
                    first_priority = priority(&output.0, &id.0);
                }
            }
        }
        let score = (first, first_priority, usize::MAX - eligible_32, key.public_key(), snapshot.snapshot_root);
        if best.as_ref().map_or(true, |old| score < *old) {
            best = Some(score);
        }
        if limits.contains(&(index + 1)) {
            let (first, priority, inverse_count, pk, root) = best.unwrap();
            println!(
                "candidates={} best_first_eligible_round={} eligible_first_32={} best_pk={} snapshot_root={} first_priority={}",
                index + 1,
                if first == u32::MAX { "none".to_string() } else { first.to_string() },
                usize::MAX - inverse_count,
                hex::encode(pk),
                root,
                hex::encode(priority),
            );
        }
    }
}
