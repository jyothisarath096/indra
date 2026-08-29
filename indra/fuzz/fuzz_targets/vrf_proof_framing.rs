#![no_main]

use indra_crypto::{vrf_prove, vrf_verify, VrfKeypair, VrfProof};
use libfuzzer_sys::fuzz_target;

const RFC9381_ELL2_PROOF_BYTES: usize = 80;

fuzz_target!(|data: &[u8]| {
    let keypair = VrfKeypair::from_seed(&[0x5a; 32]);
    let (output, _) = vrf_prove(&keypair, b"vrf-proof-framing-fuzz");
    let result = vrf_verify(
        &keypair.public_key,
        b"vrf-proof-framing-fuzz",
        &output,
        &VrfProof(data.to_vec()),
    );
    if data.len() != RFC9381_ELL2_PROOF_BYTES {
        assert!(result.is_err());
    }
});
