//! Cryptographic operation benchmarks.

use std::time::Duration;

use indra_crypto::{
    hybrid::{verify_hybrid, ClassicalKeypair, PqKeypair},
    sha256,
    vrf::{vrf_prove, vrf_verify},
};

use crate::{
    fixtures::{hybrid_keypair, vrf_keypair},
    timer::bench,
};

/// Benchmark Ed25519 sign + verify.
pub fn bench_ed25519(iterations: u64) {
    let kp = ClassicalKeypair::from_seed(&[0x01u8; 32]);
    let msg = b"INDRA benchmark message for Ed25519 signing";

    let r = bench("ed25519_sign", iterations, || {
        let _ = kp.sign(msg);
    });
    r.print();
    r.assert_faster_than(Duration::from_micros(200));

    let sig = kp.sign(msg);
    let pk = kp.public_key();

    let r = bench("ed25519_verify", iterations, || {
        let _ = indra_crypto::hybrid::verify_classical(msg, &sig, &pk);
    });
    r.print();
    r.assert_faster_than(Duration::from_micros(400));
}

/// Benchmark ML-DSA-87 sign + verify.
pub fn bench_dilithium2(iterations: u64) {
    let kp = PqKeypair::generate();
    let msg = b"INDRA benchmark message for ML-DSA-87 signing";

    let r = bench("dilithium2_sign", iterations, || {
        let _ = kp.sign(msg);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(2));

    let Ok(sig) = kp.sign(msg) else {
        return;
    };
    let pk = kp.public_key();

    let r = bench("dilithium2_verify", iterations, || {
        let _ = indra_crypto::hybrid::verify_pq(msg, &sig, &pk);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(1));
}

/// Benchmark full hybrid sign + verify (Ed25519 + ML-DSA-87 together).
pub fn bench_hybrid(iterations: u64) {
    let kp = hybrid_keypair(0x01);
    let msg = b"INDRA benchmark message for hybrid signing";

    let r = bench("hybrid_sign", iterations, || {
        let _ = kp.sign(msg);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(3));

    let Ok(sig) = kp.sign(msg) else {
        return;
    };
    let pk = kp.public_key();

    let r = bench("hybrid_verify", iterations, || {
        let _ = verify_hybrid(msg, &sig, &pk);
    });
    r.print();
    r.assert_faster_than(Duration::from_millis(2));
}

/// Benchmark SHA-256 on a 1 KB message.
pub fn bench_sha256(iterations: u64) {
    let data = vec![0xABu8; 1024];

    let r = bench("sha256_1kb", iterations, || {
        let _ = sha256(&data);
    });
    r.print();
    r.assert_faster_than(Duration::from_micros(50));
}

/// Benchmark VRF prove + verify.
pub fn bench_vrf(iterations: u64) {
    let kp = vrf_keypair(0x01);
    let input = sha256(b"INDRA VRF benchmark input");

    let r = bench("vrf_prove", iterations, || {
        let _ = vrf_prove(&kp, &input);
    });
    r.print();
    r.assert_faster_than(Duration::from_micros(500));

    let (output, proof) = vrf_prove(&kp, &input);
    let pk = kp.public_key();

    let r = bench("vrf_verify", iterations, || {
        let _ = vrf_verify(&pk, &input, &output, &proof);
    });
    r.print();
    r.assert_faster_than(Duration::from_micros(500));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_ed25519_runs() {
        bench_ed25519(50);
    }

    #[test]
    fn bench_dilithium2_runs() {
        bench_dilithium2(20);
    }

    #[test]
    fn bench_hybrid_runs() {
        bench_hybrid(20);
    }

    #[test]
    fn bench_sha256_runs() {
        bench_sha256(1000);
    }

    #[test]
    fn bench_vrf_runs() {
        bench_vrf(100);
    }
}
