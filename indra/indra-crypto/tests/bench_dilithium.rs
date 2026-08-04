use std::time::Instant;

#[test]
fn bench_qc_verification_timing() {
    let message = b"indra-qc-vote-signing-message-32";
    let kp = indra_crypto::PqKeypair::generate();
    let pk = kp.public_key();
    let sig = kp.sign(message).expect("sign failed");

    println!("\n=== ML-DSA-87 QC Verification Benchmark (Apple M-series) ===");

    for n in [10usize, 50, 100, 150, 200] {
        let start = Instant::now();
        for _ in 0..n {
            indra_crypto::verify_pq(message, &sig, &pk).expect("verify failed");
        }
        let elapsed = start.elapsed();
        let per_us = elapsed.as_micros() / n as u128;
        println!(
            "  {:>3} validators: {:>5}ms total  ({:>4}µs per sig)",
            n,
            elapsed.as_millis(),
            per_us
        );
    }

    let start = Instant::now();
    for _ in 0..150 {
        indra_crypto::verify_pq(message, &sig, &pk).unwrap();
    }
    let elapsed_150 = start.elapsed();
    println!("\n  Block time:              6000ms");
    println!("  QC overhead (150 vals):  {}ms", elapsed_150.as_millis());
    println!(
        "  QC as % of block time:   {:.3}%",
        elapsed_150.as_millis() as f64 / 6000.0 * 100.0
    );
    println!("===================================================");

    // Debug CI is a correctness run and is inherently sensitive to host load.
    // The hard budget is meaningful only for the optimized binary deployed by
    // validators, so retain it exclusively in release-profile benchmark runs.
    if !cfg!(debug_assertions) {
        assert!(
            elapsed_150.as_millis() < 2000,
            "150 ML-DSA-87 verifications took {}ms",
            elapsed_150.as_millis()
        );
    }
}
