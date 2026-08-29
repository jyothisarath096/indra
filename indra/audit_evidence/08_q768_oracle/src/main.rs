use indra_core::sortition::{
    certified_log, evaluate, CertifiedLogInterval, MAX_F, MAX_INTERVAL_WIDTH,
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rug::{
    float::Round,
    ops::{DivAssignRound, MulAssignRound, SubAssignRound},
    Float, Integer,
};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    time::Instant,
};

const INITIAL_PRECISION: u32 = 2_048;
const MAX_PRECISION: u32 = 32_768;
const RANDOM_CASES: usize = 10_000;
const F_GRID: [u64; 10] = [
    1,
    2,
    3,
    (1 << 16) - 1,
    1 << 16,
    (1 << 32) - 1,
    1 << 32,
    1 << 48,
    MAX_F - 1,
    MAX_F,
];

#[derive(Default)]
struct Stats {
    exhaustive: u64,
    random_extreme: u64,
    monotonic: u64,
    endpoint: u64,
    split_merge: u64,
    diff0: u64,
    diff1: u64,
    max_width: BigUint,
    max_width_case: (u64, u64, u64),
    width_bits: BTreeMap<u64, u64>,
    max_precision: u32,
    full_exact: u64,
    full_minus_one: u64,
    max_split_numerator: BigUint,
    max_split_denominator_bits: u64,
    max_split_case: String,
}

fn integer_to_big(value: Integer) -> BigUint {
    BigUint::from_bytes_be(&value.to_digits::<u8>(rug::integer::Order::MsfBe))
}

fn ratio_bounds(n: u64, d: u64, precision: u32) -> (Float, Float) {
    let mut lo = Float::with_val(precision, n);
    lo.div_assign_round(Float::with_val(precision, d), Round::Down);
    let mut hi = Float::with_val(precision, n);
    hi.div_assign_round(Float::with_val(precision, d), Round::Up);
    (lo, hi)
}

/// MPFR interval evaluation, structurally independent of INDRA's series code.
fn oracle_interval(f: u64, w: u64, total: u64, precision: u32) -> (BigUint, BigUint) {
    if w == total {
        let exact = BigUint::from(f) << 448usize;
        return (exact.clone(), exact);
    }
    let (f_lo, f_hi) = ratio_bounds(f, 1u64 << 63, precision);
    // ratio_bounds used 2^63 because 2^64 does not fit u64; divide once more.
    let mut f_lo = f_lo;
    f_lo.div_assign_round(2, Round::Down);
    let mut f_hi = f_hi;
    f_hi.div_assign_round(2, Round::Up);
    let one = Float::with_val(precision, 1);
    let mut base_lo = one.clone();
    base_lo.sub_assign_round(&f_hi, Round::Down);
    let mut base_hi = one.clone();
    base_hi.sub_assign_round(&f_lo, Round::Up);
    base_lo.ln_round(Round::Down);
    base_hi.ln_round(Round::Up);
    let (alpha_lo, alpha_hi) = ratio_bounds(w, total, precision);
    // ln(base) is negative and alpha positive.
    let mut exponent_lo = base_lo;
    exponent_lo.mul_assign_round(alpha_hi, Round::Down);
    let mut exponent_hi = base_hi;
    exponent_hi.mul_assign_round(alpha_lo, Round::Up);
    exponent_lo.exp_round(Round::Down);
    exponent_hi.exp_round(Round::Up);
    let mut phi_lo = one.clone();
    phi_lo.sub_assign_round(&exponent_hi, Round::Down);
    let mut phi_hi = one;
    phi_hi.sub_assign_round(&exponent_lo, Round::Up);
    let scale = Float::with_val(precision, Integer::from(1) << 512);
    phi_lo.mul_assign_round(&scale, Round::Down);
    phi_hi.mul_assign_round(scale, Round::Up);
    let (lo, _) = phi_lo
        .to_integer_round(Round::Down)
        .expect("finite lower bound");
    let (hi, _) = phi_hi
        .to_integer_round(Round::Down)
        .expect("finite upper bound");
    (integer_to_big(lo), integer_to_big(hi))
}

fn oracle_threshold(f: u64, w: u64, total: u64, stats: &mut Stats) -> Result<BigUint, String> {
    let mut precision = INITIAL_PRECISION;
    loop {
        let (lo, hi) = oracle_interval(f, w, total, precision);
        if lo == hi {
            stats.max_precision = stats.max_precision.max(precision);
            return Ok(lo);
        }
        precision *= 2;
        if precision > MAX_PRECISION {
            return Err(format!("oracle floor remains ambiguous at {MAX_PRECISION} bits: F={f}, w={w}, W={total}, floor interval=[{lo},{hi}]"));
        }
    }
}

fn oracle_no_election(f: u64, w: u64, total: u64, precision: u32) -> Float {
    let mut fraction = Float::with_val(precision, f);
    fraction /= Float::with_val(precision, Integer::from(1) << 64);
    let mut base = Float::with_val(precision, 1) - fraction;
    base.ln_mut();
    base *= Float::with_val(precision, w) / Float::with_val(precision, total);
    base.exp_mut();
    base
}

fn log_for(
    cache: &mut HashMap<u64, CertifiedLogInterval>,
    f: u64,
) -> Result<CertifiedLogInterval, String> {
    if let Some(log) = cache.get(&f) {
        return Ok(log.clone());
    }
    let log = certified_log(f).map_err(|e| format!("certified_log failed for legal F={f}: {e}"))?;
    cache.insert(f, log.clone());
    Ok(log)
}

fn check_case(
    f: u64,
    w: u64,
    total: u64,
    cache: &mut HashMap<u64, CertifiedLogInterval>,
    stats: &mut Stats,
) -> Result<BigUint, String> {
    let log = log_for(cache, f)?;
    let result = evaluate(&log, w, total, &[0; 64])
        .map_err(|e| format!("production error: F={f}, w={w}, W={total}: {e}"))?;
    let ideal = oracle_threshold(f, w, total, stats)?;
    if result.threshold > ideal {
        return Err(format!("SECURITY FAILURE production>ideal: F={f}, w={w}, W={total}, production={}, ideal={}, log_lo={}, log_hi={}, width={}", result.threshold, ideal, log.lo, log.hi, result.interval_width));
    }
    let difference = &ideal - &result.threshold;
    if difference > BigUint::one() {
        return Err(format!("THRESHOLD FAILURE difference>1: F={f}, w={w}, W={total}, production={}, ideal={}, difference={}, log_lo={}, log_hi={}, width={}", result.threshold, ideal, difference, log.lo, log.hi, result.interval_width));
    }
    if difference.is_zero() {
        stats.diff0 += 1
    } else {
        stats.diff1 += 1
    }
    if result.interval_width > BigUint::from(MAX_INTERVAL_WIDTH) {
        return Err(format!(
            "CERTIFICATE FAILURE: F={f}, w={w}, W={total}, width={}",
            result.interval_width
        ));
    }
    if result.threshold.bits() > 512 {
        return Err(format!(
            "threshold exceeds 512 bits: F={f}, w={w}, W={total}"
        ));
    }
    *stats
        .width_bits
        .entry(result.interval_width.bits())
        .or_default() += 1;
    if result.interval_width > stats.max_width {
        stats.max_width = result.interval_width.clone();
        stats.max_width_case = (f, w, total);
    }
    Ok(result.threshold)
}

fn to_output(value: &BigUint) -> [u8; 64] {
    let bytes = value.to_bytes_be();
    assert!(bytes.len() <= 64);
    let mut out = [0u8; 64];
    out[64 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn endpoint_check(
    f: u64,
    w: u64,
    total: u64,
    cache: &mut HashMap<u64, CertifiedLogInterval>,
    stats: &mut Stats,
) -> Result<(), String> {
    let log = log_for(cache, f)?;
    let result = evaluate(&log, w, total, &[0; 64]).map_err(|e| e.to_string())?;
    let t = result.threshold;
    if !t.is_zero() {
        let below = &t - BigUint::one();
        if !evaluate(&log, w, total, &to_output(&below))
            .map_err(|e| e.to_string())?
            .eligible
        {
            return Err(format!("T-1 ineligible: F={f},w={w},W={total},T={t}"));
        }
    }
    if evaluate(&log, w, total, &to_output(&t))
        .map_err(|e| e.to_string())?
        .eligible
    {
        return Err(format!("T eligible: F={f},w={w},W={total},T={t}"));
    }
    let max = (BigUint::one() << 512usize) - BigUint::one();
    if t < max {
        let above = &t + BigUint::one();
        if evaluate(&log, w, total, &to_output(&above))
            .map_err(|e| e.to_string())?
            .eligible
        {
            return Err(format!("T+1 eligible: F={f},w={w},W={total},T={t}"));
        }
    }
    stats.endpoint += 1;
    Ok(())
}

fn next_u64(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn exact_split_deviation(
    f: u64,
    parts: &[u64],
    total: u64,
    cache: &mut HashMap<u64, CertifiedLogInterval>,
    stats: &mut Stats,
) -> Result<(), String> {
    let log = log_for(cache, f)?;
    let grid = BigUint::one() << 512usize;
    let mut split_no = BigUint::one();
    for &part in parts {
        let t = evaluate(&log, part, total, &[0; 64])
            .map_err(|e| e.to_string())?
            .threshold;
        split_no *= &grid - t;
    }
    let merged_weight: u64 = parts.iter().sum();
    let merged_t = evaluate(&log, merged_weight, total, &[0; 64])
        .map_err(|e| e.to_string())?
        .threshold;
    let merged_no = (&grid - merged_t) * grid.pow((parts.len() - 1) as u32);
    let delta = if split_no >= merged_no {
        &split_no - &merged_no
    } else {
        &merged_no - &split_no
    };
    if delta > stats.max_split_numerator {
        stats.max_split_numerator = delta;
        stats.max_split_denominator_bits = 512 * parts.len() as u64;
        let partition = if parts.iter().all(|part| *part == parts[0]) {
            format!("{} parts of weight {}", parts.len(), parts[0])
        } else {
            format!("parts={parts:?}")
        };
        stats.max_split_case = format!("F={f}, {partition}, W={total}");
    }
    // Independently evaluate the unfloored real-valued identity with MPFR.
    let precision = 4096;
    let mut product = Float::with_val(precision, 1);
    for &part in parts {
        product *= oracle_no_election(f, part, total, precision);
    }
    let merged_q = oracle_no_election(f, merged_weight, total, precision);
    let error = (product - merged_q).abs();
    if error >= Float::with_val(precision, 1) >> 500 {
        return Err(format!(
            "split/merge oracle discrepancy: {error}, F={f}, parts={parts:?}, W={total}"
        ));
    }
    stats.split_merge += 1;
    Ok(())
}

fn main() -> Result<(), String> {
    let started = Instant::now();
    let mut cache = HashMap::new();
    let mut stats = Stats::default();

    for f in F_GRID {
        for total in 1..=200u64 {
            for weight in 1..=total {
                check_case(f, weight, total, &mut cache, &mut stats)?;
                stats.exhaustive += 1;
            }
        }
    }

    let full_f = [1, 2, 3, (1 << 32) - 1, 1 << 32, MAX_F - 1, MAX_F];
    let full_totals = [1, 200, u32::MAX as u64, u64::MAX - 1, u64::MAX];
    let mut full_rows = Vec::new();
    for f in full_f {
        for total in full_totals {
            let threshold = check_case(f, total, total, &mut cache, &mut stats)?;
            let ideal = BigUint::from(f) << 448usize;
            let delta = &ideal - &threshold;
            if delta.is_zero() {
                stats.full_exact += 1
            } else {
                stats.full_minus_one += 1
            }
            full_rows.push(format!("| {f} | {total} | {delta} |"));
        }
    }

    for &(f, w, total) in &[
        (1, 1, 200),
        (1 << 32, 1, 200),
        (1 << 48, 99, 200),
        (MAX_F, 1, 1),
        (MAX_F, 100, 200),
        (MAX_F, 199, 200),
    ] {
        endpoint_check(f, w, total, &mut cache, &mut stats)?;
    }

    let extremes = [
        (1, 1, u64::MAX),
        (MAX_F, 1, u64::MAX),
        (MAX_F, u64::MAX - 1, u64::MAX),
        (MAX_F, u64::MAX, u64::MAX),
        (1 << 32, u64::MAX / 2, u64::MAX),
        (1 << 48, u64::MAX / 2 + 1, u64::MAX),
    ];
    for (f, w, total) in extremes {
        check_case(f, w, total, &mut cache, &mut stats)?;
        stats.random_extreme += 1;
    }
    let mut rng = 0x494e_4452_4151_3736u64;
    for _ in 0..RANDOM_CASES {
        let f = 1 + next_u64(&mut rng) % MAX_F;
        let total = next_u64(&mut rng).max(1);
        let weight = 1 + next_u64(&mut rng) % total;
        check_case(f, weight, total, &mut cache, &mut stats)?;
        stats.random_extreme += 1;
    }

    // Dense adjacent-F and wide-domain F monotonicity.
    for start in [1u64, (1 << 32) - 128, MAX_F - 255] {
        let mut prior = BigUint::zero();
        for f in start..=start + 255 {
            let t = check_case(f, 73, 200, &mut cache, &mut stats)?;
            if t < prior {
                return Err(format!("F monotonicity failure at F={f},w=73,W=200"));
            }
            prior = t;
            stats.monotonic += 1;
        }
    }
    for _ in 0..1_000 {
        let a = 1 + next_u64(&mut rng) % MAX_F;
        let b = 1 + next_u64(&mut rng) % MAX_F;
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        let total = 1 + next_u64(&mut rng) % u64::MAX;
        let weight = 1 + next_u64(&mut rng) % total;
        let tl = check_case(lo, weight, total, &mut cache, &mut stats)?;
        let th = check_case(hi, weight, total, &mut cache, &mut stats)?;
        if tl > th {
            return Err(format!(
                "F monotonicity failure: F1={lo},F2={hi},w={weight},W={total}"
            ));
        }
        stats.monotonic += 1;
    }
    for f in [1, 1 << 16, 1 << 32, 1 << 48, MAX_F] {
        let log = log_for(&mut cache, f)?;
        let mut prior = BigUint::zero();
        for w in 1..=200 {
            let t = evaluate(&log, w, 200, &[0; 64])
                .map_err(|e| e.to_string())?
                .threshold;
            if t < prior {
                return Err(format!("stake monotonicity failure: F={f},w={w},W=200"));
            }
            prior = t;
            stats.monotonic += 1;
        }
    }

    for f in [1, 1 << 32, 1 << 48, MAX_F] {
        for n in [2usize, 3, 17, 100, 200] {
            let total = 200u64;
            let base = total / n as u64;
            let mut parts = vec![base; n];
            let assigned = base * n as u64;
            for part in parts.iter_mut().take((total - assigned) as usize) {
                *part += 1;
            }
            parts.retain(|p| *p > 0);
            exact_split_deviation(f, &parts, total, &mut cache, &mut stats)?;
        }
    }

    if certified_log(0).is_ok() || certified_log(MAX_F + 1).is_ok() {
        return Err("invalid F accepted".into());
    }
    let log = certified_log(1).map_err(|e| e.to_string())?;
    for (w, total) in [(0, 1), (1, 0), (2, 1)] {
        if evaluate(&log, w, total, &[0; 64]).is_ok() {
            return Err(format!("invalid stake domain accepted: w={w},W={total}"));
        }
    }
    for (f, w, total) in [(1, 1, 1), (MAX_F, 1, 1), (MAX_F, 200, 200)] {
        check_case(f, w, total, &mut cache, &mut stats)?;
    }

    let elapsed = started.elapsed();
    let revision = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| e.to_string())?;
    let revision = String::from_utf8_lossy(&revision.stdout).trim().to_owned();
    let source_hash = std::process::Command::new("sh")
        .args([
            "-c",
            "shasum -a 256 indra-core/src/sortition.rs | cut -d' ' -f1",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    let source_hash = String::from_utf8_lossy(&source_hash.stdout)
        .trim()
        .to_owned();
    fs::write(
        "audit_evidence/08_q768_oracle/MAX_SPLIT_DEVIATION_NUMERATOR.txt",
        stats.max_split_numerator.to_str_radix(10),
    )
    .map_err(|e| e.to_string())?;
    let split_numerator_bits = stats.max_split_numerator.bits();
    let split_binary_exponent =
        split_numerator_bits as i64 - stats.max_split_denominator_bits as i64;
    let report=format!("# Q768 independent mathematical oracle\n\n- INDRA revision: `{revision}`\n- `sortition.rs` SHA-256: `{source_hash}`\n- Oracle: MPFR via Rug, directed interval arithmetic, initial precision {INITIAL_PRECISION} bits, adaptive through {MAX_PRECISION} bits\n- Structural independence: direct evaluation of `1-exp((w/W)*ln(1-F/2^64))`; no INDRA series or Q768 rounding logic reused\n- Runtime: {:.3?}\n- Maximum precision required: {} bits\n\n## Threshold contract\n\n- Exhaustive cases (`W=1..=200`, all `w`, 10 F values): {}\n- Random/extreme cases: {} ({} fixed extreme + {} fixed-seed random)\n- Difference 0: {}\n- Difference 1: {}\n- Difference >1: 0\n- Production above ideal: 0\n\n## Full-stake invariant\n\n- Exact: {}\n- One below: {}\n\n| F | W | ideal-production |\n|---:|---:|---:|\n{}\n\n## Eligibility endpoints\n\n{} representative thresholds passed `T-1`, `T`, `T+1`.\n\n## Monotonicity\n\n{} dense/wide checks passed for stake and F monotonicity.\n\n## Split/merge\n\n{} representative partitions through 200 validators passed the direct 4096-bit MPFR ideal no-election identity check. The maximum exact production finite-grid deviation had a {}-bit numerator over denominator `2^{}`, hence is strictly below `2^{}`; reproducer: `{}`. The complete exact numerator is retained in `MAX_SPLIT_DEVIATION_NUMERATOR.txt`. This is measured independently rather than assuming the design's aggregate bound.\n\n## Runtime certificate and integer bounds\n\n- Maximum width: {} at `F={}, w={}, W={}`\n- Required bound: `<= {}`\n- Width bit-length histogram: `{:?}`\n- No scratch/endpoint bound errors, panics, or thresholds wider than 512 bits.\n\n## Invalid domain\n\nRejected `F=0`, `F>2^63`, `w=0`, `W=0`, and `w>W`; accepted all legal endpoints tested.\n\n## Result\n\nPASS. No mismatch, invariant violation, certificate failure, or unexpected production error was observed.\n",elapsed,stats.max_precision,stats.exhaustive,stats.random_extreme,extremes.len(),RANDOM_CASES,stats.diff0,stats.diff1,stats.full_exact,stats.full_minus_one,full_rows.join("\n"),stats.endpoint,stats.monotonic,stats.split_merge,split_numerator_bits,stats.max_split_denominator_bits,split_binary_exponent,stats.max_split_case,stats.max_width,stats.max_width_case.0,stats.max_width_case.1,stats.max_width_case.2,MAX_INTERVAL_WIDTH,stats.width_bits);
    fs::write("audit_evidence/08_q768_oracle/ORACLE_RESULTS.md", report)
        .map_err(|e| e.to_string())?;
    println!(
        "PASS: {} exhaustive, {} random/extreme, runtime {:.3?}",
        stats.exhaustive, stats.random_extreme, elapsed
    );
    Ok(())
}
