//! Kani harnesses over INDRA's shipped Q768 sortition implementation.

#[cfg(kani)]
mod proofs {
    use indra_core::sortition::{certified_log, evaluate, MAX_F, MAX_INTERVAL_WIDTH};
    use num_bigint::BigUint;

    fn admissible_inputs() -> (u64, u64, u64, [u8; 64]) {
        let f: u64 = kani::any();
        let validator_stake: u64 = kani::any();
        let total_stake: u64 = kani::any();
        let vrf_output: [u8; 64] = kani::any();
        kani::assume(f > 0);
        kani::assume(f <= MAX_F);
        kani::assume(total_stake > 0);
        kani::assume(validator_stake > 0);
        kani::assume(validator_stake <= total_stake);
        (f, validator_stake, total_stake, vrf_output)
    }

    #[kani::proof]
    fn q768_runtime_certificate_width_is_strictly_below_2_pow_24() {
        let (f, validator_stake, total_stake, vrf_output) = admissible_inputs();
        let log = certified_log(f).expect("admissible f must produce a certificate");
        let result = evaluate(&log, validator_stake, total_stake, &vrf_output)
            .expect("admissible stake inputs must evaluate");
        assert!(result.interval_width < BigUint::from(MAX_INTERVAL_WIDTH));
    }

    #[kani::proof]
    fn q768_admissible_domain_has_no_panic_or_arithmetic_error() {
        let (f, validator_stake, total_stake, vrf_output) = admissible_inputs();
        let log = certified_log(f).expect("admissible f must produce a certificate");
        let _ = evaluate(&log, validator_stake, total_stake, &vrf_output)
            .expect("admissible stake inputs must evaluate");
    }

    #[kani::proof]
    fn certified_log_interval_is_ordered() {
        let f: u64 = kani::any();
        kani::assume(f > 0);
        kani::assume(f <= MAX_F);
        let log = certified_log(f).expect("admissible f must produce a certificate");
        assert!(log.lo <= log.hi);
    }

    #[kani::proof]
    fn stake_to_sigma_conversion_is_monotone() {
        let f: u64 = kani::any();
        let lower_stake: u64 = kani::any();
        let higher_stake: u64 = kani::any();
        let total_stake: u64 = kani::any();
        kani::assume(f > 0);
        kani::assume(f <= MAX_F);
        kani::assume(total_stake > 0);
        kani::assume(lower_stake > 0);
        kani::assume(lower_stake <= higher_stake);
        kani::assume(higher_stake <= total_stake);
        let log = certified_log(f).expect("admissible f must produce a certificate");
        let lower = evaluate(&log, lower_stake, total_stake, &[0; 64])
            .expect("admissible lower stake must evaluate");
        let higher = evaluate(&log, higher_stake, total_stake, &[0; 64])
            .expect("admissible higher stake must evaluate");
        assert!(lower.threshold <= higher.threshold);
    }

    #[kani::proof]
    fn vrf_big_endian_conversion_matches_eligibility_comparison() {
        let (f, validator_stake, total_stake, vrf_output) = admissible_inputs();
        let log = certified_log(f).expect("admissible f must produce a certificate");
        let result = evaluate(&log, validator_stake, total_stake, &vrf_output)
            .expect("admissible stake inputs must evaluate");
        let converted_output = BigUint::from_bytes_be(&vrf_output);
        assert_eq!(result.eligible, converted_output < result.threshold);
        assert!(result.threshold.bits() <= 512);
    }
}
