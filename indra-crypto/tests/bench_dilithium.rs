use std::time::Instant;

#[test]
fn bench_qc_verification_timing() {
    use pqcrypto_dilithium::dilithium2;
    use pqcrypto_traits::sign::SignedMessage;

    let message = b"indra-qc-vote-signing-message-32";
    let (pk, sk) = dilithium2::keypair();
    let signed = dilithium2::sign(message, &sk);

    println!("\n=== Dilithium2 QC Verification Benchmark (Apple M-series) ===");

    for n in [10usize, 50, 100, 150, 200] {
        let start = Instant::now();
        for _ in 0..n {
            let _ = dilithium2::open(&signed, &pk).expect("verify failed");
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
        let _ = dilithium2::open(&signed, &pk).unwrap();
    }
    let elapsed_150 = start.elapsed();
    println!("\n  Block time:              6000ms");
    println!("  QC overhead (150 vals):  {}ms", elapsed_150.as_millis());
    println!("  QC as % of block time:   {:.3}%",
        elapsed_150.as_millis() as f64 / 6000.0 * 100.0);
    println!("===================================================");

    assert!(elapsed_150.as_millis() < 2000,
        "150 Dilithium2 verifications took {}ms", elapsed_150.as_millis());
}
