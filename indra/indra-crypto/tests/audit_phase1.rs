//! Proof-of-concept checks for `docs/SECURITY_AUDIT_PHASE1.md`.
//!
//! These tests do not fix vulnerabilities. They either demonstrate an attack
//! surface or lock in security properties verified during the audit.

use indra_crypto::{
    sha256, verify_hybrid, ClassicalKeypair, HybridKeypair, HybridPublicKey, HybridSignature,
    PqKeypair, VrfKeypair, VrfOutput,
};

fn candidate_output(vrf_pubkey: &[u8; 32], vrf_input: &[u8; 32]) -> VrfOutput {
    let mut data = Vec::with_capacity(vrf_pubkey.len() + vrf_input.len());
    data.extend_from_slice(vrf_pubkey);
    data.extend_from_slice(vrf_input);
    VrfOutput(sha256(&data))
}

#[test]
fn audit_hybrid_rejects_single_component_forgery() {
    let classical = ClassicalKeypair::from_seed(&[0x11; 32]);
    let pq = PqKeypair::from_seed(&[0x22; 32]).unwrap();
    let honest = HybridKeypair::new(classical, pq);

    let attacker_classical = ClassicalKeypair::from_seed(&[0x33; 32]);
    let attacker_pq = PqKeypair::from_seed(&[0x44; 32]).unwrap();
    let attacker = HybridKeypair::new(attacker_classical, attacker_pq);

    let message = b"audit hybrid signature message";
    let honest_sig = honest.sign(message).unwrap();
    let attacker_sig = attacker.sign(message).unwrap();

    let mixed_sig = HybridSignature {
        classical: honest_sig.classical,
        pq: attacker_sig.pq,
    };
    let honest_pk: HybridPublicKey = honest.public_key();

    assert!(
        verify_hybrid(message, &mixed_sig, &honest_pk).is_err(),
        "a signature with only one valid component must not verify"
    );
}

#[test]
fn audit_vrf_public_candidate_output_is_grindable() {
    let vrf_input = sha256(b"fixed public election input");
    let mut best = u8::MAX;
    let mut best_seed = 0u16;

    for seed in 0u16..2048 {
        let mut seed_bytes = [0u8; 32];
        seed_bytes[..2].copy_from_slice(&seed.to_le_bytes());
        let keypair = VrfKeypair::from_seed(&seed_bytes);
        let output = candidate_output(&keypair.public_key(), &vrf_input);
        if output.0[0] < best {
            best = output.0[0];
            best_seed = seed;
        }
    }

    assert!(
        best < 4,
        "with 2048 public-key trials, an attacker should be able to grind a very low public election byte; best={best} seed={best_seed}"
    );
}
