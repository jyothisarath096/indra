#![no_main]

use indra_crypto::{vrf_prove, vrf_verify, VrfKeypair};
use libfuzzer_sys::fuzz_target;

const MAX_ALPHA_BYTES: usize = 4_096;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let seed: [u8; 32] = data[..32].try_into().unwrap();
    let alpha = &data[32..data.len().min(32 + MAX_ALPHA_BYTES)];
    let keypair = VrfKeypair::from_seed(&seed);
    let first = vrf_prove(&keypair, alpha);
    let second = vrf_prove(&keypair, alpha);
    assert_eq!(first, second);
    assert!(vrf_verify(&keypair.public_key, alpha, &first.0, &first.1).is_ok());
});
