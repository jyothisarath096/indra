#![no_main]

use indra_crypto::{vrf_prove, vrf_verify, VrfKeypair, VrfOutput, VrfProof};
use libfuzzer_sys::fuzz_target;

const MAX_ALPHA_BYTES: usize = 4_096;

fuzz_target!(|data: &[u8]| {
    if data.len() < 33 {
        return;
    }
    let seed: [u8; 32] = data[..32].try_into().unwrap();
    let selector = data[32];
    let alpha = &data[33..data.len().min(33 + MAX_ALPHA_BYTES)];
    let keypair = VrfKeypair::from_seed(&seed);
    let (output, proof) = vrf_prove(&keypair, alpha);
    assert!(vrf_verify(&keypair.public_key, alpha, &output, &proof).is_ok());

    let mut mutated_key = keypair.public_key;
    let mut mutated_alpha = alpha.to_vec();
    let mut mutated_output = output.0;
    let mut mutated_proof = proof.0.clone();
    let index = usize::from(selector);
    match selector % 6 {
        0 => mutated_key[index % 32] ^= 1 << (selector % 8),
        1 => {
            if mutated_alpha.is_empty() {
                mutated_alpha.push(1);
            } else {
                let len = mutated_alpha.len();
                mutated_alpha[index % len] ^= 1 << (selector % 8);
            }
        }
        2 => mutated_output[index % 64] ^= 1 << (selector % 8),
        3 => mutated_proof[index % 32] ^= 1 << (selector % 8),
        4 => mutated_proof[32 + index % 16] ^= 1 << (selector % 8),
        _ => mutated_proof[48 + index % 32] ^= 1 << (selector % 8),
    }
    assert!(vrf_verify(
        &mutated_key,
        &mutated_alpha,
        &VrfOutput(mutated_output),
        &VrfProof(mutated_proof),
    )
    .is_err());
});
