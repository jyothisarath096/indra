//! Praos/Minotaur sortition with deterministic outward-rounded Q768 arithmetic.
use crate::error::{IndraError, IndraResult};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Zero};
use sha2::{Digest, Sha512};
/// Normative fractional precision.
pub const Q_BITS: usize = 768;
/// Mandatory live certificate bound.
pub const MAX_INTERVAL_WIDTH: u64 = 1 << 24;
/// Largest admitted numerator in `f=F/2^64`.
pub const MAX_F: u64 = 1 << 63;
fn s() -> BigUint {
    BigUint::one() << Q_BITS
}
fn ceil(n: &BigUint, d: &BigUint) -> BigUint {
    if n.is_zero() {
        BigUint::zero()
    } else {
        (n + d - BigUint::one()) / d
    }
}
fn bound(v: &BigUint, b: u64, n: &str) -> IndraResult<()> {
    if v.bits() > b {
        Err(IndraError::InvalidSortition(format!(
            "{n} exceeds {b} bits"
        )))
    } else {
        Ok(())
    }
}
#[derive(Clone)]
struct I {
    lo: BigUint,
    hi: BigUint,
}
fn mul(a: &I, b: &I) -> IndraResult<I> {
    let scale = s();
    let lo = &a.lo * &b.lo;
    let hi = &a.hi * &b.hi;
    bound(&lo, 2048, "scratch")?;
    bound(&hi, 2048, "scratch")?;
    let o = I {
        lo: lo / &scale,
        hi: ceil(&hi, &scale),
    };
    bound(&o.lo, 1024, "endpoint")?;
    bound(&o.hi, 1024, "endpoint")?;
    Ok(o)
}
fn divi(a: &I, d: u64) -> I {
    let d = BigUint::from(d);
    I {
        lo: &a.lo / &d,
        hi: ceil(&a.hi, &d),
    }
}
/// Snapshot-cached certified interval for `-ln(1-f)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedLogInterval {
    /// Lower endpoint.
    pub lo: BigUint,
    /// Upper endpoint.
    pub hi: BigUint,
}
/// Certified election result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortitionResult {
    /// Eligibility.
    pub eligible: bool,
    /// Downward-rounded 512-bit threshold.
    pub threshold: BigUint,
    /// Actual certified interval width.
    pub interval_width: BigUint,
}
/// Enforce `1 <= F <= 2^63`.
pub fn validate_f(f: u64) -> IndraResult<()> {
    if f == 0 || f > MAX_F {
        Err(IndraError::InvalidSortition(
            "active_slot_coefficient_numerator outside 1..=2^63".into(),
        ))
    } else {
        Ok(())
    }
}

/// Enforce the sole active-slot coefficient admitted by mainnet consensus.
///
/// `validate_f` intentionally remains broader for arithmetic audit coverage;
/// production genesis and persisted consensus objects must call this function.
pub fn validate_mainnet_f(f: u64) -> IndraResult<()> {
    if f != crate::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR {
        Err(IndraError::InvalidSortition(format!(
            "mainnet active_slot_coefficient_numerator must equal {}",
            crate::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR
        )))
    } else {
        Ok(())
    }
}
/// Compute the 256-term cached logarithm and analytic positive tail.
pub fn certified_log(f: u64) -> IndraResult<CertifiedLogInterval> {
    validate_f(f)?;
    let scale = s();
    let fq = BigUint::from(f) << (Q_BITS - 64);
    let den = (&scale << 1usize) - &fq;
    let y = I {
        lo: (&fq * &scale) / &den,
        hi: ceil(&(&fq * &scale), &den),
    };
    let y2 = mul(&y, &y)?;
    let mut p = y;
    let (mut lo, mut hi) = (BigUint::zero(), BigUint::zero());
    for n in 0..256u64 {
        let t = divi(&p, 2 * n + 1);
        lo += t.lo;
        hi += t.hi;
        if n != 255 {
            p = mul(&p, &y2)?
        }
    }
    let y513 = mul(&p, &y2)?;
    let rn = BigUint::from(2u8) * &y513.hi * &scale;
    let rd = BigUint::from(513u16) * (&scale - &y2.hi);
    Ok(CertifiedLogInterval {
        lo: lo << 1usize,
        hi: (hi << 1usize) + ceil(&rn, &rd),
    })
}
fn phi(z: BigUint, terms: u64, lower: bool) -> IndraResult<BigUint> {
    let zi = I {
        lo: z.clone(),
        hi: z,
    };
    let mut t = zi.clone();
    let mut sum = BigInt::zero();
    for k in 1..=terms {
        if k > 1 {
            t = divi(&mul(&t, &zi)?, k)
        }
        let v = if k % 2 == 1 {
            if lower {
                &t.lo
            } else {
                &t.hi
            }
        } else if lower {
            &t.hi
        } else {
            &t.lo
        };
        let v = BigInt::from_biguint(Sign::Plus, v.clone());
        if k % 2 == 1 {
            sum += v
        } else {
            sum -= v
        }
    }
    Ok(if sum.sign() == Sign::Minus {
        BigUint::zero()
    } else {
        sum.to_biguint().unwrap_or_default()
    })
}
/// Evaluate the full 512-bit output against the conservative threshold.
pub fn evaluate(
    log: &CertifiedLogInterval,
    w: u64,
    total: u64,
    out: &[u8; 64],
) -> IndraResult<SortitionResult> {
    if w == 0 || total == 0 || w > total {
        return Err(IndraError::InvalidSortition(
            "stake must satisfy 0 < w <= W".into(),
        ));
    }
    let w = BigUint::from(w);
    let total = BigUint::from(total);
    let zl = &log.lo * &w / &total;
    let zh = ceil(&(&log.hi * &w), &total);
    let scale = s();
    let pl = phi(zl, 128, true)?.min(scale.clone());
    let ph = phi(zh, 129, false)?.min(scale);
    if ph < pl {
        return Err(IndraError::InvalidSortition("inverted interval".into()));
    }
    let width = &ph - &pl;
    if width > BigUint::from(MAX_INTERVAL_WIDTH) {
        return Err(IndraError::InvalidSortition(
            "runtime Q768 width exceeds 2^24".into(),
        ));
    }
    let threshold = &pl >> (Q_BITS - 512);
    Ok(SortitionResult {
        eligible: BigUint::from_bytes_be(out) < threshold,
        threshold,
        interval_width: width,
    })
}
/// Full-width priority tie-break.
pub fn priority(out: &[u8; 64], id: &[u8; 32]) -> [u8; 64] {
    let mut d = Sha512::new();
    d.update(b"INDRA-PROPOSER-PRIORITY-v1");
    d.update(out);
    d.update([1]);
    d.update(id);
    let mut r = [0; 64];
    r.copy_from_slice(&d.finalize());
    r
}
#[cfg(test)]
mod tests {
    use super::*;
    use rug::{float::Round, Float, Integer};

    fn mpfr_threshold(f: u64, weight: u64, total: u64) -> BigUint {
        const PRECISION: u32 = 1_024;
        let one = Float::with_val(PRECISION, 1);
        let mut base = Float::with_val(PRECISION, f);
        base /= Float::with_val(PRECISION, Integer::from(1u8) << 64);
        base = &one - base;
        let exponent = Float::with_val(PRECISION, weight) / Float::with_val(PRECISION, total);
        let probability = &one - (base.ln() * exponent).exp();
        let scaled = probability * Float::with_val(PRECISION, Integer::from(1u8) << 512);
        let (integer, _) = scaled
            .to_integer_round(Round::Down)
            .expect("finite positive MPFR oracle");
        BigUint::from_bytes_be(&integer.to_digits::<u8>(rug::integer::Order::MsfBe))
    }

    #[test]
    fn half_full_stake() {
        let l = certified_log(1 << 63).unwrap();
        let r = evaluate(&l, 1, 1, &[0; 64]).unwrap();
        assert!(r.eligible);
        assert!(r.interval_width <= BigUint::from(MAX_INTERVAL_WIDTH))
    }

    #[test]
    fn admitted_f_endpoints_and_runtime_certificate_hold_at_validator_cap() {
        for f in [1, MAX_F] {
            let log = certified_log(f).unwrap();
            for validator_count in [1u64, 2, 3, 17, 200] {
                for stake in 1..=validator_count {
                    let result = evaluate(&log, stake, validator_count, &[0; 64]).unwrap();
                    assert!(result.interval_width <= BigUint::from(MAX_INTERVAL_WIDTH));
                    assert!(result.threshold.bits() <= 512);
                }
            }
        }
    }

    #[test]
    fn q768_threshold_matches_high_precision_oracle_on_reduced_exhaustive_grid() {
        let f_values = [1, 2, 3, (1u64 << 32) - 1, 1u64 << 32, MAX_F - 1, MAX_F];
        for f in f_values {
            let log = certified_log(f).unwrap();
            for total in 1..=16u64 {
                for weight in 1..=total {
                    let result = evaluate(&log, weight, total, &[0; 64]).unwrap();
                    let oracle = mpfr_threshold(f, weight, total);
                    assert!(
                        result.threshold <= oracle,
                        "canonical downward threshold exceeded oracle for F={f}, w={weight}, W={total}"
                    );
                    assert!(
                        &oracle - &result.threshold <= BigUint::one(),
                        "Q768 result diverged by more than one 512-bit threshold unit for F={f}, w={weight}, W={total}"
                    );
                    assert!(result.interval_width <= BigUint::from(MAX_INTERVAL_WIDTH));
                }
            }
        }
    }

    #[test]
    fn full_width_integer_boundary_is_canonical() {
        let log = certified_log(MAX_F).unwrap();
        let result = evaluate(&log, 1, 1, &[0; 64]).unwrap();
        assert!(!result.threshold.is_zero());
        let below = &result.threshold - BigUint::one();
        let at = result.threshold.clone();
        let below_bytes = below.to_bytes_be();
        let at_bytes = at.to_bytes_be();
        let mut below_out = [0u8; 64];
        let mut at_out = [0u8; 64];
        below_out[64 - below_bytes.len()..].copy_from_slice(&below_bytes);
        at_out[64 - at_bytes.len()..].copy_from_slice(&at_bytes);
        assert!(evaluate(&log, 1, 1, &below_out).unwrap().eligible);
        assert!(!evaluate(&log, 1, 1, &at_out).unwrap().eligible);
    }

    #[test]
    fn threshold_is_monotone_in_stake_and_f() {
        let low = certified_log(1).unwrap();
        let high = certified_log(MAX_F).unwrap();
        let mut prior = BigUint::zero();
        for stake in 1..=200u64 {
            let threshold = evaluate(&high, stake, 200, &[0; 64]).unwrap().threshold;
            assert!(threshold >= prior);
            prior = threshold;
            assert!(
                evaluate(&low, stake, 200, &[0; 64]).unwrap().threshold <= prior,
                "increasing F must not reduce eligibility"
            );
        }
    }

    #[test]
    fn all_output_bits_participate_in_integer_ordering_and_priority() {
        let zero = [0u8; 64];
        let id = [7u8; 32];
        for bit in 0..512 {
            let mut changed = zero;
            changed[bit / 8] ^= 1 << (bit % 8);
            assert_ne!(BigUint::from_bytes_be(&changed), BigUint::zero());
            assert_ne!(priority(&changed, &id), priority(&zero, &id));
        }
    }

    #[test]
    fn consensus_sortition_source_contains_no_floating_point_types() {
        let production = include_str!("sortition.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!production.contains("f32"));
        assert!(!production.contains("f64"));
        assert!(!production.contains("partial_cmp"));
    }

    #[test]
    fn invalid_f() {
        assert!(certified_log(0).is_err());
        assert!(certified_log((1 << 63) + 1).is_err())
    }

    #[test]
    fn mainnet_f_is_exact_while_math_domain_remains_broad() {
        let preferred = crate::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR;
        assert!(validate_mainnet_f(preferred).is_ok());
        for invalid in [preferred - 1, preferred + 1, 1, MAX_F] {
            assert!(validate_mainnet_f(invalid).is_err());
            assert!(validate_f(invalid).is_ok());
        }
    }
}
