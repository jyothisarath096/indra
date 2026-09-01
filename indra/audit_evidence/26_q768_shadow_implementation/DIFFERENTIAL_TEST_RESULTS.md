# Q768 fixed-limb shadow versus production: differential-test results

Date: 2026-09-01

## Result

The production `num_bigint` implementation and the fixed-limb shadow agreed on
every compared value in **461,126 admissible input cases**:

- **18,203 distinct `F` values** had their `y`, `y²`, and certified-log interval
  endpoints compared;
- every case had stake-scaled `zlo`/`zhi`, raw lower/upper phi outputs, clamped
  probability endpoints, interval width, 512-bit threshold, and eligibility
  compared;
- the run made **8,518,704 exact stage comparisons**;
- discrepancies: **0**;
- arithmetic errors on admissible inputs: **0**;
- shadow fixes made as a result: **none**.

`DIFFERENTIAL_MISMATCHES.jsonl` is present and exactly zero bytes. The harness
would append one complete JSON object per differing stage, including the corpus,
case index, exact `F`, `w`, `W`, all 64 VRF-output bytes, implementation labels,
and both full hexadecimal values. There are no discrepancies to enumerate.

This is strong empirical conformance evidence over the tested corpus. It is not
an exhaustive proof over the full `u64`/512-bit domain.

## Revision and implementation identity

- INDRA revision: `a6a3029e07d9f06bfe59eaffdc945a354714bd5d`
- `indra-core/src/sortition.rs` SHA-256:
  `e966f92885e4b0c463e2c90d2746abab2739f2456c4c62a0ca7fbfd2f772dbfd`
- shadow `src/lib.rs` SHA-256 after adding observation-only tracing:
  `a4c769a51fb2ff71c133b57225272f4109930e741d633660e37b6a69c22d612c`
- differential `src/main.rs` SHA-256:
  `56e93d14704c9e08d4ddcd66185cfbef19bc9c2925b6d058eee8aaf79c7622d9`
- differential `build.rs` SHA-256:
  `5fc5166102ff7e647ea6648f099d0bd774efba957137b43833a87c2a645c6ab0`

The production files were read but not modified.

## Why instrumentation was necessary

The real public API exposes the certified log interval and final
`SortitionResult`, but production's `I`, `mul`, `divi`, and `phi` are private
(`indra-core/src/sortition.rs:31-55` and `129-163`). Therefore a normal external
test cannot observe `y`, `y²`, `zlo`/`zhi`, or raw phi endpoints.

The differential crate uses three mutually checking paths:

1. It links and directly calls the real
   `indra_core::sortition::{certified_log, evaluate}` API
   (`differential/src/main.rs:1-7`, `315-325`, and `443-465`).
2. Its build script reads the current production `sortition.rs`, removes only
   the leading `//!` module-documentation line required to make `include!`
   legal, and writes all remaining executable tokens unchanged to Cargo's
   `OUT_DIR` (`differential/build.rs:1-17`). A byte comparison of that generated
   file against `tail -n +2 indra-core/src/sortition.rs` passed.
3. An instrumented wrapper in the same module calls production's actual private
   `ceil`, `mul`, `divi`, and `phi` functions while retaining the named stage
   values (`differential/src/main.rs:49-158`). Its public log certificate,
   threshold, width, and eligibility are checked back against the real linked
   `indra_core` API for every applicable input.

The shadow adds a default-disabled `differential-trace` feature. It repeats the
public high-level path using the same private fixed-limb primitives and returns
the named stage values (`src/lib.rs:787-907`). Its certificate and final result
are checked back against the ordinary shadow `certified_log` and `evaluate`
functions. The existing arithmetic functions were not changed; the Git diff is
one feature declaration plus this observation-only module.

This arrangement matters because simply copying two standalone algorithms into
a test would compare reimplementations rather than the artifacts under review.
Here, the real public production crate and the real public shadow crate remain
the final anchors, while the trace paths expose their private-stage arithmetic
and must reproduce their public outputs.

## Values compared

### Once per distinct `F`

For each of 18,203 distinct values of `F`, the harness performed 12 checks:

- real production log `lo`/`hi` versus the included current-source production
  module;
- real production log `lo`/`hi` versus the production trace's recomposed log;
- shadow public log `lo`/`hi` versus the shadow trace's recomposed log;
- production trace versus shadow trace for `y.lo`, `y.hi`, `y2.lo`, `y2.hi`,
  `log.lo`, and `log.hi`.

The log trace is cached by `F` because none of these values depends on stake or
VRF output. Reusing a previously compared certificate does not omit a distinct
arithmetic input.

### Once per full case

For each of 461,126 `(F,w,W,output)` cases, the harness performed 18 checks:

- real production versus included-current-source production: threshold, width,
  eligibility;
- real production versus production trace: threshold, width, eligibility;
- shadow public versus shadow trace: threshold, width, eligibility;
- production trace versus shadow trace: `zlo`, `zhi`, raw 128-term lower phi,
  raw 129-term upper phi, clamped probability `lo`/`hi`, and interval width;
- real production versus shadow public: final threshold and eligibility.

The total is therefore:

```text
18,203 * 12 + 461,126 * 18 = 8,518,704 stage comparisons
```

All comparisons are integer equality. No tolerance, averaging, sampling of
stages, or floating-point conversion is involved.

## Corpus

### Reused MPFR threshold-contract corpus: 211,006 cases

Topic 08 did not retain a separate input-data file, but its generator remains
in `audit_evidence/08_q768_oracle/src/main.rs`. This run reproduced its
threshold-contract corpus and generator exactly:

- **201,000 exhaustive cases**: every `1 <= w <= W` for `W = 1..=200`, at the
  ten established values
  `{1,2,3,2^16-1,2^16,2^32-1,2^32,2^48,2^63-1,2^63}`, with an all-zero output;
- **6 fixed extreme cases**: the exact Topic 08 tuples using `W = u64::MAX`;
- **10,000 fixed-seed random cases**: the same xorshift64 generator, seed
  `0x494e445241513736`, and the same three draws for `F`, `W`, and `w`, with an
  all-zero output.

This reproduces the “200,000+ cases” referred to by the earlier evidence. The
MPFR oracle itself was not rerun here: this task compares representations and
implementations, while Topic 08 separately compares production with ideal
real-valued mathematics.

### Deliberate boundaries: 120 cases

The boundary Cartesian product was:

- `F` in `{1, 6_917_529_027_641_081_856, 2^63}`. The middle value is the exact
  mainnet constant at `indra-core/src/types/primitives.rs:78`;
- `W` in `{4,8,20,u64::MAX}`;
- `w` in `{1,W}`;
- output at zero, all `0xFF`, `threshold-1`, exactly `threshold`, and
  `threshold+1`.

That is `3 * 4 * 2 * 5 = 120` cases. The threshold-boundary output was derived
from the real production result, converted to a full 64-byte big-endian value,
then submitted independently to both implementations. This exercises the strict
`output < threshold` convention rather than checking only a likely eligibility
outcome.

### New large random corpus: 250,000 cases

The added randomized corpus exceeds the entire 211,006-case Topic 08
threshold-contract corpus on its own:

- fixed seed: `0x51444946465f5632`;
- deterministic xorshift64 generator, matching the already-established simple
  corpus-generation idiom;
- 8,192 generated `F` values, each uniform modulo the admitted
  `1..=2^63` domain;
- arbitrary nonzero `W` across `u64`, and `w` generated in `1..=W`;
- eight fresh `u64` draws per case to fill every byte of the 512-bit output.

The finite `F` pool makes the 250,000-case run reproducible and permits cached
log certificates while still testing thousands of widely distributed log
inputs. Stake and output are newly generated for every case.

### Exact counts

```text
corpus.oracle_exhaustive=201000
corpus.oracle_extremes=6
corpus.oracle_fixed_seed_random=10000
corpus.deliberate_boundaries=120
corpus.new_large_random=250000
cases=461126
unique_f=18203
stage_comparisons=8518704
mismatches=0
```

## Mismatch handling

The run does not stop at the first unequal value. Every unequal stage is retained
and written to `DIFFERENTIAL_MISMATCHES.jsonl` after the corpus finishes. Each
record contains enough information for an exact reproducer. The process returns
an error if the list is nonempty.

For this run:

```text
wc -c DIFFERENTIAL_MISMATCHES.jsonl
0 DIFFERENTIAL_MISMATCHES.jsonl
```

No mismatch was suppressed, rounded, deduplicated across distinct full cases,
or silently patched. No shadow arithmetic bug was found, so no arithmetic fix
was made.

## Runtime and toolchain

```text
rustc 1.93.1 (01f6ddf75 2026-02-11)
cargo 1.93.1 (083ac5135 2025-12-15)
target: aarch64-apple-darwin
```

The harness's internal timer, which starts immediately before corpus creation,
reported `813.297445` seconds. `/usr/bin/time` around `cargo run --release`,
including the release build, reported:

```text
real 831.08
user 799.46
sys 3.58
```

## Verification and reproduction

From the INDRA workspace root:

```sh
# Confirm the instrumented executable source differs only by the removed doc line.
generated=$(find audit_evidence/26_q768_shadow_implementation/differential/target/release/build \
  -path '*/out/instrumented_sortition.rs' -print -quit)
cmp <(tail -n +2 indra-core/src/sortition.rs) "$generated"

# Static/build checks.
RUSTFLAGS='-D warnings' cargo check --release \
  --manifest-path audit_evidence/26_q768_shadow_implementation/differential/Cargo.toml
cargo test \
  --manifest-path audit_evidence/26_q768_shadow_implementation/Cargo.toml

# Full differential run.
/usr/bin/time -p cargo run --release \
  --manifest-path audit_evidence/26_q768_shadow_implementation/differential/Cargo.toml
```

Observed auxiliary results:

- generated-source byte comparison: pass;
- differential release check with all warnings denied: pass;
- shadow ordinary tests: 6 passed, 0 failed;
- shadow doc tests: 0 tests, pass.

## What this establishes

For the 461,126 declared cases, this run is direct evidence that the fixed-limb
shadow and current production code produced bit-identical named intermediate
endpoints and final results. In particular, the shadow's exact cancellation in
the initial `y` division did not alter floor/ceiling results for any of the
18,203 tested `F` values, and its fixed sign/magnitude phi accumulator matched
production's `BigInt` accumulator for every stake case.

This materially strengthens confidence beyond comparing eligibility alone: a
disagreement hidden by both outputs landing on the same side of the threshold
would have been caught at `y`, `y²`, log, stake scaling, raw phi, clamped phi,
width, or threshold.

## What this does not establish

- It is not exhaustive over all admitted `F,w,W` triples or all `2^512` outputs.
- It is not a formal proof that the shadow conforms to production for every
  input. The Kani full-path harnesses from the preceding report remain
  inconclusive.
- Private production-stage visibility is provided by a reviewed high-level
  trace wrapper around executable tokens copied from the current source. The
  wrapper's correct correspondence to the original control flow is part of this
  test's trusted base, mitigated—but not formally eliminated—by comparing its
  final certificate/result back to the real linked production API on every
  input.
- This does not prove the production `num_bigint` implementation conforms to
  Topic 25's Rocq model. It provides empirical bridge evidence only.
- This does not establish bit-identical behavior on every supported platform or
  close R1 cross-platform determinism.
- It does not rerun or replace the independent MPFR real-mathematics oracle.

## Recommendation

The shadow is now sufficiently credible to justify investment in the proposed
Verus/invariant work. The reasons are concrete: zero differences across the
entire established 211,006-case corpus, an additional 250,000 randomized cases,
explicit small/maximum-domain and threshold boundaries, and equality at every
named internal representation boundary rather than only final eligibility.

That investment should still be described accurately. A Verus proof of the
fixed-limb shadow would establish properties of the shadow. This differential
evidence would remain an empirical—not deductive—bridge to the present
`num_bigint` production implementation unless production adopts the verified
fixed-limb implementation or a separate conformance proof is completed.
