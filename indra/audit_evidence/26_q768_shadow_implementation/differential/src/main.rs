use indra_core::{
    sortition as real_production, types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
};
use indra_q768_fixed_shadow::{
    certified_log as shadow_certified_log, differential_trace as shadow_trace,
    evaluate as shadow_evaluate, CertifiedLogInterval as ShadowLog, Threshold512, Uint, MAX_F,
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Write as _,
    fs,
    path::Path,
    time::Instant,
};

// These shims let the current production source's executable tokens compile as
// a second, instrumentable module in this verification-only binary. The build
// script removes only its leading inner module-doc line. Public API results from
// this module are checked against the real `indra_core` dependency.
pub mod error {
    use core::fmt;

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum IndraError {
        InvalidSortition(String),
    }

    impl fmt::Display for IndraError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::InvalidSortition(detail) => formatter.write_str(detail),
            }
        }
    }

    impl std::error::Error for IndraError {}

    pub type IndraResult<T> = Result<T, IndraError>;
}

pub mod types {
    pub mod primitives {
        pub use indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR;
    }
}

#[allow(dead_code)]
mod instrumented_production {
    include!(concat!(env!("OUT_DIR"), "/instrumented_sortition.rs"));

    pub mod stage_trace {
        use super::*;

        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct LogTrace {
            pub y_lo: BigUint,
            pub y_hi: BigUint,
            pub y2_lo: BigUint,
            pub y2_hi: BigUint,
            pub certificate: CertifiedLogInterval,
        }

        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct EvaluateTrace {
            pub zlo: BigUint,
            pub zhi: BigUint,
            pub phi_lower_raw: BigUint,
            pub phi_upper_raw: BigUint,
            pub probability_lo: BigUint,
            pub probability_hi: BigUint,
            pub result: SortitionResult,
        }

        pub fn certified_log_trace(f: u64) -> IndraResult<LogTrace> {
            validate_f(f)?;
            let scale = s();
            let fq = BigUint::from(f) << (Q_BITS - 64);
            let den = (&scale << 1usize) - &fq;
            let y = I {
                lo: (&fq * &scale) / &den,
                hi: ceil(&(&fq * &scale), &den),
            };
            let y2 = mul(&y, &y)?;
            let mut power = y.clone();
            let (mut lo, mut hi) = (BigUint::zero(), BigUint::zero());
            for n in 0..256u64 {
                let term = divi(&power, 2 * n + 1);
                lo += term.lo;
                hi += term.hi;
                if n != 255 {
                    power = mul(&power, &y2)?;
                }
            }
            let y513 = mul(&power, &y2)?;
            let tail_numerator = BigUint::from(2u8) * &y513.hi * &scale;
            let tail_denominator = BigUint::from(513u16) * (&scale - &y2.hi);
            let certificate = CertifiedLogInterval {
                lo: lo << 1usize,
                hi: (hi << 1usize) + ceil(&tail_numerator, &tail_denominator),
            };
            Ok(LogTrace {
                y_lo: y.lo,
                y_hi: y.hi,
                y2_lo: y2.lo,
                y2_hi: y2.hi,
                certificate,
            })
        }

        pub fn evaluate_trace(
            log: &CertifiedLogInterval,
            validator_stake: u64,
            total_stake: u64,
            output: &[u8; 64],
        ) -> IndraResult<EvaluateTrace> {
            if validator_stake == 0 || total_stake == 0 || validator_stake > total_stake {
                return Err(IndraError::InvalidSortition(
                    "stake must satisfy 0 < w <= W".into(),
                ));
            }
            let stake = BigUint::from(validator_stake);
            let total = BigUint::from(total_stake);
            let zlo = &log.lo * &stake / &total;
            let zhi = ceil(&(&log.hi * &stake), &total);
            let scale = s();
            let phi_lower_raw = phi(zlo.clone(), 128, true)?;
            let phi_upper_raw = phi(zhi.clone(), 129, false)?;
            let probability_lo = phi_lower_raw.clone().min(scale.clone());
            let probability_hi = phi_upper_raw.clone().min(scale);
            if probability_hi < probability_lo {
                return Err(IndraError::InvalidSortition("inverted interval".into()));
            }
            let interval_width = &probability_hi - &probability_lo;
            if interval_width > BigUint::from(MAX_INTERVAL_WIDTH) {
                return Err(IndraError::InvalidSortition(
                    "runtime Q768 width exceeds 2^24".into(),
                ));
            }
            let threshold = &probability_lo >> (Q_BITS - 512);
            let result = SortitionResult {
                eligible: BigUint::from_bytes_be(output) < threshold,
                threshold,
                interval_width,
            };
            Ok(EvaluateTrace {
                zlo,
                zhi,
                phi_lower_raw,
                phi_upper_raw,
                probability_lo,
                probability_hi,
                result,
            })
        }
    }
}

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
const ORIGINAL_RANDOM_CASES: usize = 10_000;
const NEW_RANDOM_F_POOL: usize = 8_192;
const NEW_RANDOM_CASES: usize = 250_000;
const ORIGINAL_SEED: u64 = 0x494e_4452_4151_3736;
const NEW_SEED: u64 = 0x5144_4946_465f_5632;

#[derive(Clone)]
struct PreparedLog {
    real: real_production::CertifiedLogInterval,
    instrumented: instrumented_production::CertifiedLogInterval,
    production_trace: instrumented_production::stage_trace::LogTrace,
    shadow: ShadowLog,
    shadow_trace: shadow_trace::LogTrace,
}

struct CaseContext<'a> {
    corpus: &'a str,
    index: u64,
    f: u64,
    w: u64,
    total: u64,
    output: &'a [u8; 64],
}

#[derive(Default)]
struct Stats {
    cases: u64,
    stage_comparisons: u64,
    unique_f: u64,
    mismatches: Vec<String>,
    by_corpus: BTreeMap<&'static str, u64>,
}

fn next_u64(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn uint_to_big(value: &Uint) -> BigUint {
    let mut bytes = [0u8; 128];
    for (index, limb) in value.0.iter().enumerate() {
        bytes[index * 8..index * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    BigUint::from_bytes_le(&bytes)
}

fn threshold_to_big(value: &Threshold512) -> BigUint {
    let mut bytes = [0u8; 64];
    for (index, limb) in value.0.iter().enumerate() {
        bytes[index * 8..index * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    BigUint::from_bytes_le(&bytes)
}

fn bytes_hex(value: &[u8; 64]) -> String {
    let mut result = String::with_capacity(128);
    for byte in value {
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    result
}

fn record_mismatch(
    stats: &mut Stats,
    context: &CaseContext<'_>,
    stage: &str,
    left_impl: &str,
    right_impl: &str,
    left: &str,
    right: &str,
) {
    stats.mismatches.push(format!(
        "{{\"corpus\":\"{}\",\"index\":{},\"F\":{},\"w\":{},\"W\":{},\"output\":\"{}\",\"stage\":\"{}\",\"left_impl\":\"{}\",\"right_impl\":\"{}\",\"left\":\"{}\",\"right\":\"{}\"}}",
        context.corpus,
        context.index,
        context.f,
        context.w,
        context.total,
        bytes_hex(context.output),
        stage,
        left_impl,
        right_impl,
        left,
        right,
    ));
}

fn compare_big(
    stats: &mut Stats,
    context: &CaseContext<'_>,
    stage: &str,
    left_impl: &str,
    right_impl: &str,
    left: &BigUint,
    right: &BigUint,
) {
    stats.stage_comparisons += 1;
    if left != right {
        record_mismatch(
            stats,
            context,
            stage,
            left_impl,
            right_impl,
            &format!("0x{}", left.to_str_radix(16)),
            &format!("0x{}", right.to_str_radix(16)),
        );
    }
}

fn compare_bool(
    stats: &mut Stats,
    context: &CaseContext<'_>,
    stage: &str,
    left_impl: &str,
    right_impl: &str,
    left: bool,
    right: bool,
) {
    stats.stage_comparisons += 1;
    if left != right {
        record_mismatch(
            stats,
            context,
            stage,
            left_impl,
            right_impl,
            &left.to_string(),
            &right.to_string(),
        );
    }
}

fn prepare_log(
    f: u64,
    cache: &mut HashMap<u64, PreparedLog>,
    stats: &mut Stats,
) -> Result<(), String> {
    if cache.contains_key(&f) {
        return Ok(());
    }
    let real = real_production::certified_log(f)
        .map_err(|error| format!("real production certified_log failed for F={f}: {error}"))?;
    let instrumented = instrumented_production::certified_log(f).map_err(|error| {
        format!("instrumented production certified_log failed for F={f}: {error}")
    })?;
    let production_trace = instrumented_production::stage_trace::certified_log_trace(f)
        .map_err(|error| format!("production stage trace failed for F={f}: {error}"))?;
    let shadow = shadow_certified_log(f)
        .map_err(|error| format!("shadow certified_log failed for F={f}: {error:?}"))?;
    let shadow_trace = shadow_trace::certified_log_trace(f)
        .map_err(|error| format!("shadow log trace failed for F={f}: {error:?}"))?;

    let output = [0u8; 64];
    let context = CaseContext {
        corpus: "unique_f_preparation",
        index: stats.unique_f,
        f,
        w: 0,
        total: 0,
        output: &output,
    };
    compare_big(
        stats,
        &context,
        "public_log.lo",
        "real_indra_core",
        "instrumented_current_source",
        &real.lo,
        &instrumented.lo,
    );
    compare_big(
        stats,
        &context,
        "public_log.hi",
        "real_indra_core",
        "instrumented_current_source",
        &real.hi,
        &instrumented.hi,
    );
    compare_big(
        stats,
        &context,
        "trace_log.lo",
        "real_indra_core",
        "instrumented_trace",
        &real.lo,
        &production_trace.certificate.lo,
    );
    compare_big(
        stats,
        &context,
        "trace_log.hi",
        "real_indra_core",
        "instrumented_trace",
        &real.hi,
        &production_trace.certificate.hi,
    );
    compare_big(
        stats,
        &context,
        "shadow_trace_log.lo",
        "shadow_public",
        "shadow_trace",
        &uint_to_big(&shadow.lo),
        &uint_to_big(&shadow_trace.certificate.lo),
    );
    compare_big(
        stats,
        &context,
        "shadow_trace_log.hi",
        "shadow_public",
        "shadow_trace",
        &uint_to_big(&shadow.hi),
        &uint_to_big(&shadow_trace.certificate.hi),
    );
    for (stage, production_value, shadow_value) in [
        ("y.lo", &production_trace.y_lo, &shadow_trace.y_lo),
        ("y.hi", &production_trace.y_hi, &shadow_trace.y_hi),
        ("y2.lo", &production_trace.y2_lo, &shadow_trace.y2_lo),
        ("y2.hi", &production_trace.y2_hi, &shadow_trace.y2_hi),
        (
            "log.lo",
            &production_trace.certificate.lo,
            &shadow_trace.certificate.lo,
        ),
        (
            "log.hi",
            &production_trace.certificate.hi,
            &shadow_trace.certificate.hi,
        ),
    ] {
        compare_big(
            stats,
            &context,
            stage,
            "production_trace",
            "shadow_trace",
            production_value,
            &uint_to_big(shadow_value),
        );
    }

    cache.insert(
        f,
        PreparedLog {
            real,
            instrumented,
            production_trace,
            shadow,
            shadow_trace,
        },
    );
    stats.unique_f += 1;
    Ok(())
}

fn check_case(
    corpus: &'static str,
    index: u64,
    f: u64,
    w: u64,
    total: u64,
    output: &[u8; 64],
    cache: &mut HashMap<u64, PreparedLog>,
    stats: &mut Stats,
) -> Result<(), String> {
    prepare_log(f, cache, stats)?;
    let prepared = cache.get(&f).expect("prepared log must be cached");
    let real = real_production::evaluate(&prepared.real, w, total, output).map_err(|error| {
        format!("real production evaluate failed at F={f},w={w},W={total}: {error}")
    })?;
    let instrumented = instrumented_production::evaluate(&prepared.instrumented, w, total, output)
        .map_err(|error| {
            format!("instrumented production evaluate failed at F={f},w={w},W={total}: {error}")
        })?;
    let production_trace = instrumented_production::stage_trace::evaluate_trace(
        &prepared.production_trace.certificate,
        w,
        total,
        output,
    )
    .map_err(|error| {
        format!("production evaluate trace failed at F={f},w={w},W={total}: {error}")
    })?;
    let shadow = shadow_evaluate(&prepared.shadow, w, total, output)
        .map_err(|error| format!("shadow evaluate failed at F={f},w={w},W={total}: {error:?}"))?;
    let shadow_trace =
        shadow_trace::evaluate_trace(&prepared.shadow_trace.certificate, w, total, output)
            .map_err(|error| {
                format!("shadow evaluate trace failed at F={f},w={w},W={total}: {error:?}")
            })?;
    let context = CaseContext {
        corpus,
        index,
        f,
        w,
        total,
        output,
    };

    compare_big(
        stats,
        &context,
        "production_public.threshold",
        "real_indra_core",
        "instrumented_current_source",
        &real.threshold,
        &instrumented.threshold,
    );
    compare_big(
        stats,
        &context,
        "production_public.interval_width",
        "real_indra_core",
        "instrumented_current_source",
        &real.interval_width,
        &instrumented.interval_width,
    );
    compare_bool(
        stats,
        &context,
        "production_public.eligible",
        "real_indra_core",
        "instrumented_current_source",
        real.eligible,
        instrumented.eligible,
    );
    compare_big(
        stats,
        &context,
        "production_trace.threshold",
        "real_indra_core",
        "instrumented_trace",
        &real.threshold,
        &production_trace.result.threshold,
    );
    compare_big(
        stats,
        &context,
        "production_trace.interval_width",
        "real_indra_core",
        "instrumented_trace",
        &real.interval_width,
        &production_trace.result.interval_width,
    );
    compare_bool(
        stats,
        &context,
        "production_trace.eligible",
        "real_indra_core",
        "instrumented_trace",
        real.eligible,
        production_trace.result.eligible,
    );

    compare_big(
        stats,
        &context,
        "shadow_trace.threshold",
        "shadow_public",
        "shadow_trace",
        &threshold_to_big(&shadow.threshold),
        &threshold_to_big(&shadow_trace.result.threshold),
    );
    compare_big(
        stats,
        &context,
        "shadow_trace.interval_width",
        "shadow_public",
        "shadow_trace",
        &uint_to_big(&shadow.interval_width),
        &uint_to_big(&shadow_trace.result.interval_width),
    );
    compare_bool(
        stats,
        &context,
        "shadow_trace.eligible",
        "shadow_public",
        "shadow_trace",
        shadow.eligible,
        shadow_trace.result.eligible,
    );

    for (stage, production_value, shadow_value) in [
        ("zlo", &production_trace.zlo, &shadow_trace.zlo),
        ("zhi", &production_trace.zhi, &shadow_trace.zhi),
        (
            "phi_lower_raw",
            &production_trace.phi_lower_raw,
            &shadow_trace.phi_lower_raw,
        ),
        (
            "phi_upper_raw",
            &production_trace.phi_upper_raw,
            &shadow_trace.phi_upper_raw,
        ),
        (
            "probability_lo",
            &production_trace.probability_lo,
            &shadow_trace.probability_lo,
        ),
        (
            "probability_hi",
            &production_trace.probability_hi,
            &shadow_trace.probability_hi,
        ),
        (
            "interval_width",
            &production_trace.result.interval_width,
            &shadow_trace.result.interval_width,
        ),
    ] {
        compare_big(
            stats,
            &context,
            stage,
            "production_trace",
            "shadow_trace",
            production_value,
            &uint_to_big(shadow_value),
        );
    }
    compare_big(
        stats,
        &context,
        "threshold",
        "real_indra_core",
        "shadow_public",
        &real.threshold,
        &threshold_to_big(&shadow.threshold),
    );
    compare_bool(
        stats,
        &context,
        "eligible",
        "real_indra_core",
        "shadow_public",
        real.eligible,
        shadow.eligible,
    );

    stats.cases += 1;
    *stats.by_corpus.entry(corpus).or_default() += 1;
    Ok(())
}

fn to_output(value: &BigUint) -> [u8; 64] {
    let bytes = value.to_bytes_be();
    assert!(bytes.len() <= 64);
    let mut output = [0u8; 64];
    output[64 - bytes.len()..].copy_from_slice(&bytes);
    output
}

fn random_output(state: &mut u64) -> [u8; 64] {
    let mut output = [0u8; 64];
    for chunk in output.chunks_exact_mut(8) {
        chunk.copy_from_slice(&next_u64(state).to_be_bytes());
    }
    output
}

fn main() -> Result<(), String> {
    let started = Instant::now();
    let mut cache = HashMap::new();
    let mut stats = Stats::default();
    let zero = [0u8; 64];

    let mut index = 0u64;
    for f in F_GRID {
        for total in 1..=200u64 {
            for weight in 1..=total {
                check_case(
                    "oracle_exhaustive",
                    index,
                    f,
                    weight,
                    total,
                    &zero,
                    &mut cache,
                    &mut stats,
                )?;
                index += 1;
            }
        }
    }

    for (extreme_index, (f, w, total)) in [
        (1, 1, u64::MAX),
        (MAX_F, 1, u64::MAX),
        (MAX_F, u64::MAX - 1, u64::MAX),
        (MAX_F, u64::MAX, u64::MAX),
        (1 << 32, u64::MAX / 2, u64::MAX),
        (1 << 48, u64::MAX / 2 + 1, u64::MAX),
    ]
    .into_iter()
    .enumerate()
    {
        check_case(
            "oracle_extremes",
            extreme_index as u64,
            f,
            w,
            total,
            &zero,
            &mut cache,
            &mut stats,
        )?;
    }

    let mut original_rng = ORIGINAL_SEED;
    for random_index in 0..ORIGINAL_RANDOM_CASES {
        let f = 1 + next_u64(&mut original_rng) % MAX_F;
        let total = next_u64(&mut original_rng).max(1);
        let weight = 1 + next_u64(&mut original_rng) % total;
        check_case(
            "oracle_fixed_seed_random",
            random_index as u64,
            f,
            weight,
            total,
            &zero,
            &mut cache,
            &mut stats,
        )?;
    }

    let mut boundary_index = 0u64;
    for f in [1, MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR, MAX_F] {
        for total in [4u64, 8, 20, u64::MAX] {
            for weight in [1, total] {
                prepare_log(f, &mut cache, &mut stats)?;
                let threshold = real_production::evaluate(
                    &cache.get(&f).expect("boundary log").real,
                    weight,
                    total,
                    &zero,
                )
                .map_err(|error| error.to_string())?
                .threshold;
                let below = if threshold.is_zero() {
                    BigUint::zero()
                } else {
                    &threshold - BigUint::one()
                };
                let above = &threshold + BigUint::one();
                for output in [
                    zero,
                    [0xff; 64],
                    to_output(&below),
                    to_output(&threshold),
                    to_output(&above),
                ] {
                    check_case(
                        "deliberate_boundaries",
                        boundary_index,
                        f,
                        weight,
                        total,
                        &output,
                        &mut cache,
                        &mut stats,
                    )?;
                    boundary_index += 1;
                }
            }
        }
    }

    let mut random_rng = NEW_SEED;
    let mut f_pool = Vec::with_capacity(NEW_RANDOM_F_POOL);
    for _ in 0..NEW_RANDOM_F_POOL {
        f_pool.push(1 + next_u64(&mut random_rng) % MAX_F);
    }
    for random_index in 0..NEW_RANDOM_CASES {
        let f = f_pool[next_u64(&mut random_rng) as usize % f_pool.len()];
        let total = next_u64(&mut random_rng).max(1);
        let weight = 1 + next_u64(&mut random_rng) % total;
        let output = random_output(&mut random_rng);
        check_case(
            "new_large_random",
            random_index as u64,
            f,
            weight,
            total,
            &output,
            &mut cache,
            &mut stats,
        )?;
    }

    let mismatch_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("differential crate has a parent")
        .join("DIFFERENTIAL_MISMATCHES.jsonl");
    let mismatch_data = if stats.mismatches.is_empty() {
        String::new()
    } else {
        format!("{}\n", stats.mismatches.join("\n"))
    };
    fs::write(&mismatch_path, mismatch_data).map_err(|error| error.to_string())?;

    println!("cases={}", stats.cases);
    println!("unique_f={}", stats.unique_f);
    println!("stage_comparisons={}", stats.stage_comparisons);
    for (corpus, count) in &stats.by_corpus {
        println!("corpus.{corpus}={count}");
    }
    println!("mismatches={}", stats.mismatches.len());
    println!("elapsed_seconds={:.6}", started.elapsed().as_secs_f64());
    println!("mismatch_file={}", mismatch_path.display());

    if stats.mismatches.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} differential mismatches; see {}",
            stats.mismatches.len(),
            mismatch_path.display()
        ))
    }
}
