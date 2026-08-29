#![no_main]

use indra_crypto::{vrf_verify, VrfOutput, VrfProof};
use libfuzzer_sys::fuzz_target;

const MAX_ALPHA_BYTES: usize = 4_096;

fuzz_target!(|data: &[u8]| {
    if data.len() < 98 {
        return;
    }
    let public_key: [u8; 32] = data[..32].try_into().unwrap();
    let output = VrfOutput(data[32..96].try_into().unwrap());
    let requested_alpha_len = usize::from(u16::from_le_bytes([data[96], data[97]]));
    let available = data.len() - 98;
    let alpha_len = requested_alpha_len.min(available).min(MAX_ALPHA_BYTES);
    let alpha = &data[98..98 + alpha_len];
    let proof = VrfProof(data[98 + alpha_len..].to_vec());
    let _ = vrf_verify(&public_key, alpha, &output, &proof);
});
