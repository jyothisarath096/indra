use indra_core::sortition::{certified_log, evaluate, CertifiedLogInterval, MAX_F, Q_BITS};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};

const CORPUS_VERSION: u32 = 1;
const RANDOM_CASES: usize = 10_000;
const SEED: u64 = 0x494e_4452_412d_5137;

#[derive(Clone, Serialize, Deserialize)]
struct Case {
    id: u64,
    kind: String,
    f: u64,
    w: u64,
    total: u64,
    log_lo_be_hex: Option<String>,
    log_hi_be_hex: Option<String>,
    output_be_hex: String,
}

#[derive(Serialize, Deserialize)]
struct Corpus {
    schema: String,
    version: u32,
    prng: String,
    seed_u64_hex: String,
    cases: Vec<Case>,
}

#[derive(Serialize)]
struct Record {
    id: u64,
    kind: String,
    f_u64: String,
    w_u64: String,
    total_u64: String,
    certified_log_lo_q768_be_hex: String,
    certified_log_hi_q768_be_hex: String,
    phi_lo_q768_be_hex: String,
    phi_hi_q768_be_hex: String,
    interval_width_be_hex: String,
    threshold_u512_be_hex: String,
    vrf_output_u512_be_hex: String,
    eligible: Option<bool>,
    error_category: Option<String>,
}

fn scale() -> BigUint {
    BigUint::one() << Q_BITS
}
fn ceil(n: &BigUint, d: &BigUint) -> BigUint {
    if n.is_zero() {
        BigUint::zero()
    } else {
        (n + d - BigUint::one()) / d
    }
}
#[derive(Clone)]
struct Interval {
    lo: BigUint,
    hi: BigUint,
}
fn mul(a: &Interval, b: &Interval) -> Result<Interval, String> {
    let s = scale();
    let lo = &a.lo * &b.lo;
    let hi = &a.hi * &b.hi;
    if lo.bits() > 2048 || hi.bits() > 2048 {
        return Err("scratch_exceeds_2048_bits".into());
    }
    let out = Interval {
        lo: lo / &s,
        hi: ceil(&hi, &s),
    };
    if out.lo.bits() > 1024 || out.hi.bits() > 1024 {
        return Err("endpoint_exceeds_1024_bits".into());
    }
    Ok(out)
}
fn divi(a: &Interval, d: u64) -> Interval {
    let d = BigUint::from(d);
    Interval {
        lo: &a.lo / &d,
        hi: ceil(&a.hi, &d),
    }
}
fn phi(z: BigUint, terms: u64, lower: bool) -> Result<BigUint, String> {
    let zi = Interval {
        lo: z.clone(),
        hi: z,
    };
    let mut t = zi.clone();
    let mut sum = BigInt::zero();
    for k in 1..=terms {
        if k > 1 {
            t = divi(&mul(&t, &zi)?, k);
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
fn private_endpoints(
    log: &CertifiedLogInterval,
    w: u64,
    total: u64,
) -> Result<(BigUint, BigUint), String> {
    if w == 0 || total == 0 || w > total {
        return Err("invalid_stake_domain".into());
    }
    let w = BigUint::from(w);
    let total = BigUint::from(total);
    let zl = &log.lo * &w / &total;
    let zh = ceil(&(&log.hi * &w), &total);
    let s = scale();
    Ok((
        phi(zl, 128, true)?.min(s.clone()),
        phi(zh, 129, false)?.min(s),
    ))
}

fn fixed_hex(v: &BigUint, bytes: usize) -> String {
    let raw = v.to_bytes_be();
    if raw.len() > bytes {
        return format!("overflow:{}", hex(&raw));
    }
    let mut padded = vec![0u8; bytes - raw.len()];
    padded.extend(raw);
    hex(&padded)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
fn parse_big(s: &str) -> Result<BigUint, String> {
    Ok(BigUint::from_bytes_be(&unhex(s)?))
}
fn parse_output(s: &str) -> Result<[u8; 64], String> {
    let bytes = unhex(s)?;
    bytes
        .try_into()
        .map_err(|_| "output is not 64 bytes".into())
}
fn classify_error(message: &str) -> String {
    if message.contains("outside 1..=2^63") {
        "invalid_f"
    } else if message.contains("0 < w <= W") {
        "invalid_stake_domain"
    } else if message.contains("inverted interval") {
        "inverted_interval"
    } else if message.contains("runtime Q768 width") {
        "certificate_width_exceeded"
    } else if message.contains("scratch") {
        "scratch_exceeds_2048_bits"
    } else if message.contains("endpoint") {
        "endpoint_exceeds_1024_bits"
    } else {
        "other_error"
    }
    .into()
}

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}
fn output_from(value: &BigUint) -> String {
    fixed_hex(value, 64)
}
fn add_case(
    cases: &mut Vec<Case>,
    kind: &str,
    f: u64,
    w: u64,
    total: u64,
    output: BigUint,
    explicit_log: Option<(BigUint, BigUint)>,
) {
    let (lo, hi) = explicit_log
        .map(|(l, h)| (Some(fixed_hex(&l, 96)), Some(fixed_hex(&h, 96))))
        .unwrap_or((None, None));
    cases.push(Case {
        id: cases.len() as u64,
        kind: kind.into(),
        f,
        w,
        total,
        log_lo_be_hex: lo,
        log_hi_be_hex: hi,
        output_be_hex: output_from(&output),
    });
}
fn generate(path: &Path) -> Result<(), String> {
    let mut cases = Vec::new();
    let fs = [1, 2, 3, (1u64 << 32) - 1, 1u64 << 32, MAX_F - 1, MAX_F];
    let totals = [1, 200, u64::MAX];
    for f in fs {
        for total in totals {
            let mut weights = vec![1, total];
            if total > 1 {
                weights.push(total - 1);
            }
            weights.sort_unstable();
            weights.dedup();
            for w in weights {
                let log = certified_log(f).map_err(|e| e.to_string())?;
                let base = evaluate(&log, w, total, &[0; 64]).map_err(|e| e.to_string())?;
                add_case(
                    &mut cases,
                    "boundary/random-output",
                    f,
                    w,
                    total,
                    BigUint::from(f ^ w ^ total),
                    None,
                );
                if !base.threshold.is_zero() {
                    add_case(
                        &mut cases,
                        "threshold-minus-one",
                        f,
                        w,
                        total,
                        &base.threshold - BigUint::one(),
                        None,
                    );
                }
                add_case(
                    &mut cases,
                    "threshold",
                    f,
                    w,
                    total,
                    base.threshold.clone(),
                    None,
                );
                if base.threshold.bits() < 512 {
                    add_case(
                        &mut cases,
                        "threshold-plus-one",
                        f,
                        w,
                        total,
                        &base.threshold + BigUint::one(),
                        None,
                    );
                }
            }
        }
    }
    let mut state = SEED;
    for _ in 0..RANDOM_CASES {
        let f = 1 + xorshift64(&mut state) % MAX_F;
        let total = 1 + xorshift64(&mut state);
        let w = 1 + xorshift64(&mut state) % total;
        let mut out = [0u8; 64];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&xorshift64(&mut state).to_be_bytes());
        }
        add_case(
            &mut cases,
            "deterministic-random",
            f,
            w,
            total,
            BigUint::from_bytes_be(&out),
            None,
        );
    }
    add_case(&mut cases, "invalid-f-zero", 0, 1, 1, BigUint::zero(), None);
    add_case(
        &mut cases,
        "invalid-f-high",
        MAX_F + 1,
        1,
        1,
        BigUint::zero(),
        None,
    );
    add_case(&mut cases, "invalid-w-zero", 1, 0, 1, BigUint::zero(), None);
    add_case(
        &mut cases,
        "invalid-total-zero",
        1,
        1,
        0,
        BigUint::zero(),
        None,
    );
    add_case(
        &mut cases,
        "invalid-w-over-total",
        1,
        2,
        1,
        BigUint::zero(),
        None,
    );
    add_case(
        &mut cases,
        "malformed-certificate-inverted",
        1,
        1,
        1,
        BigUint::zero(),
        Some((scale() - BigUint::one(), BigUint::zero())),
    );
    let corpus = Corpus {
        schema: "indra-q768-determinism-corpus".into(),
        version: CORPUS_VERSION,
        prng: "xorshift64(13,7,17)".into(),
        seed_u64_hex: format!("{SEED:016x}"),
        cases,
    };
    fs::write(
        path,
        serde_json::to_vec(&corpus).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn run(corpus_path: &Path, result_path: &Path) -> Result<(), String> {
    let corpus: Corpus = serde_json::from_slice(&fs::read(corpus_path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if corpus.version != CORPUS_VERSION {
        return Err("unsupported corpus version".into());
    }
    let mut records = Vec::with_capacity(corpus.cases.len());
    for case in corpus.cases {
        let out = parse_output(&case.output_be_hex)?;
        let log_result = match (&case.log_lo_be_hex, &case.log_hi_be_hex) {
            (Some(lo), Some(hi)) => Ok(CertifiedLogInterval {
                lo: parse_big(lo)?,
                hi: parse_big(hi)?,
            }),
            (None, None) => certified_log(case.f).map_err(|e| e.to_string()),
            _ => return Err(format!("case {} has partial certificate", case.id)),
        };
        let mut rec = Record {
            id: case.id,
            kind: case.kind,
            f_u64: case.f.to_string(),
            w_u64: case.w.to_string(),
            total_u64: case.total.to_string(),
            certified_log_lo_q768_be_hex: "".into(),
            certified_log_hi_q768_be_hex: "".into(),
            phi_lo_q768_be_hex: "".into(),
            phi_hi_q768_be_hex: "".into(),
            interval_width_be_hex: "".into(),
            threshold_u512_be_hex: "".into(),
            vrf_output_u512_be_hex: hex(&out),
            eligible: None,
            error_category: None,
        };
        match log_result {
            Err(e) => rec.error_category = Some(classify_error(&e)),
            Ok(log) => {
                rec.certified_log_lo_q768_be_hex = fixed_hex(&log.lo, 96);
                rec.certified_log_hi_q768_be_hex = fixed_hex(&log.hi, 96);
                match evaluate(&log, case.w, case.total, &out) {
                    Err(e) => rec.error_category = Some(classify_error(&e.to_string())),
                    Ok(prod) => {
                        let (pl, ph) = private_endpoints(&log, case.w, case.total)?;
                        if (&pl >> (Q_BITS - 512)) != prod.threshold
                            || (&ph - &pl) != prod.interval_width
                        {
                            return Err(format!(
                                "audit mirror disagrees with production at case {}",
                                case.id
                            ));
                        }
                        rec.phi_lo_q768_be_hex = fixed_hex(&pl, 96);
                        rec.phi_hi_q768_be_hex = fixed_hex(&ph, 96);
                        rec.interval_width_be_hex = fixed_hex(&prod.interval_width, 4);
                        rec.threshold_u512_be_hex = fixed_hex(&prod.threshold, 64);
                        rec.eligible = Some(prod.eligible);
                    }
                }
            }
        }
        records.push(rec);
    }
    let bytes = serde_json::to_vec(&records).map_err(|e| e.to_string())?;
    fs::write(result_path, &bytes).map_err(|e| e.to_string())?;
    eprintln!(
        "cases={} sha256={}",
        records.len(),
        hex(&Sha256::digest(&bytes))
    );
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let result = match args.as_slice() {
        [_, cmd, path] if cmd == "generate" => generate(Path::new(path)),
        [_, cmd, corpus, out] if cmd == "run" => run(Path::new(corpus), Path::new(out)),
        _ => Err("usage: indra-q768-determinism generate CORPUS | run CORPUS RESULTS".into()),
    };
    if let Err(e) = result {
        eprintln!("ERROR: {e}");
        std::process::exit(1);
    }
}
