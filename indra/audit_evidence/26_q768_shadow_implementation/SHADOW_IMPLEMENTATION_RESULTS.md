# Q768 fixed-limb shadow implementation: construction and Kani results

Date: 2026-09-01
Repository revision inspected: `b7a55e36586e31c04d436738e0edc6dcc44647ce`

## Result in one paragraph

A standalone, dependency-free, `no_std` shadow crate now implements the shipped
Q768 algorithm with 1024-bit value arrays (`[u64; 16]`) and 2048-bit product
arrays (`[u64; 32]`). It reproduces the 256-term `atanh` log construction, the
128/129-term signed phi recurrences, every lower-floor/upper-ceiling choice, the
stake conversion, clamp, 512-bit threshold conversion, and VRF comparison. Six
ordinary tests pass. Kani 0.67.0 exhaustively verified the isolated 512-bit
VRF byte-order/comparison property: 85 checks, zero failures. Kani did **not**
close any of the five full-algorithm harnesses. They timed out while expanding
the fixed-depth arithmetic loops and produced no counterexample or SAT/UNSAT
answer. Fixed limbs remove the original dynamic-allocation/modeling blocker, but
they do not make brute-force unrolling of 256 + 128 + 129 rounds tractable at
this width. The honest status is therefore one verified conversion sub-property
and five inconclusive full-path properties, not a Kani-verified Q768 algorithm.

This topic does not compare the shadow against production. That intentionally
remains the separately reviewable follow-up task.

## Step 0: exact target from shipped code

### Domain and scale

Production defines `Q_BITS = 768`, `S = 2^768`, and admits
`1 <= F <= 2^63` at `indra-core/src/sortition.rs:6-13` and
`indra-core/src/sortition.rs:75-83`. Thus `S` itself has bit length 769 even
though a value strictly below `S` has at most 768 bits.

The table below gives tight bit lengths over that full arithmetic-audit domain,
not just the single mainnet `F`. They were obtained by tracing the exact integer
recurrences and directed rounding in the cited shipped code. The upper
recurrences are monotone in `F` through `y`; their maxima occur at
`F = 2^63`. The denominator/tail-denominator maximum that goes the other way was
also evaluated at `F = 1`. These are value bit lengths; a zero has bit length
zero.

| Production stage | Shipped construction | Exact maximum bit length |
|---|---|---:|
| `S` | `1 << 768` | 769 |
| `fq` | `F << 704` | 768 |
| `den = 2S - fq` | log substitution denominator | 769 |
| raw `fq * S` | numerator before the `y` division | 1536 |
| `y.lo`, `y.hi` | floor/ceil of `fq*S/den` | 767 |
| raw `y*y` | first interval scratch product | 1533 |
| `y2.lo`, `y2.hi` | rescaled outward-rounded square | 765 |
| later raw `p*y2` | 256-term recurrence scratch product | 1532 |
| `p`, divided term, running `lo`/`hi` sum | before the final factor of two | 767 |
| `y513.lo`, `y513.hi` | final outward-rounded log-series power | 0 / 1 |
| tail numerator `2*y513.hi*S` | analytic positive-tail numerator | 770 |
| tail denominator `513*(S-y2.hi)` | analytic positive-tail denominator | 778 |
| final certified log endpoints | doubled sum plus outward tail | 768 |
| raw log-endpoint times `u64` stake | stake-scaling product | 832 |
| `zlo`, `zhi` | floor/ceil stake-scaled endpoints | 768 |
| first/raw phi interval product | `z*z`, the largest phi scratch product | 1535 |
| phi interval term | each rescaled/divided recurrence term | 768 |
| signed phi accumulator magnitude | alternating 128/129-term sum | 768 |
| phi output / clamped probability endpoint | `min(value, S)` | 768 (the separate clamp operand `S` is 769) |
| final threshold | lower endpoint shifted by 256 | 512 |

The shipped implementation separately enforces permissive representation
guards of 2048 bits for raw interval products and 1024 bits for their rescaled
endpoints (`indra-core/src/sortition.rs:36-48`). Those guards are broader than
the stage-specific maxima above. The stake products and the two phi calls are
visible at `indra-core/src/sortition.rs:176-182`; the final width, shift, and
big-endian VRF comparison are at `indra-core/src/sortition.rs:183-197`.

### Selected limb widths

The shadow uses:

- `Uint([u64; 16])`: 1024 value bits;
- `Wide([u64; 32])`: 2048 scratch-product bits.

The constants are at `src/lib.rs:9-14`. A 1024-bit value has 191 bits of
headroom over the largest ordinary 832-bit stake product if that product were
narrowed, 255 bits over `S`, and 256 bits over ordinary Q768 endpoints. The
2048-bit product has 512 bits of headroom over the 1536-bit maximum raw product.
It also exactly matches production's explicit scratch guard. This is deliberate
headroom, rather than sizing the arrays at the observed maxima.

### Arithmetic and directed rounding that must be replicated

Production performs the following semantically relevant operations:

1. Checked/guarded unsigned addition and subtraction for denominators, interval
   sums, tail construction, and widths; a signed `BigInt` addition/subtraction
   for the alternating phi accumulator.
2. Exact full-width unsigned multiplication.
3. Interval multiplication with
   `lo = floor(a.lo*b.lo/S)` and
   `hi = ceil(a.hi*b.hi/S)`
   (`indra-core/src/sortition.rs:36-48`).
4. Division by the positive integer `d` with
   `lo = floor(a.lo/d)` and `hi = ceil(a.hi/d)`
   (`indra-core/src/sortition.rs:15-20` and `50-55`).
5. The same floor/ceiling convention for `y` at
   `indra-core/src/sortition.rs:104-110`, for the analytic tail at
   `indra-core/src/sortition.rs:121-126`, and for stake scaling at
   `indra-core/src/sortition.rs:176-180`.
6. Odd/even and lower/upper endpoint selection into a signed alternating
   accumulator at `indra-core/src/sortition.rs:129-162`.
7. Clamp, subtraction, right shift, big-endian integer conversion, and strict
   `<` at `indra-core/src/sortition.rs:181-197`.

The shadow implements fixed-limb checked add/subtract/shift at
`src/lib.rs:73-168`, schoolbook multiplication at `src/lib.rs:170-202`, scalar
floor/ceiling division at `src/lib.rs:204-284`, exact fixed-limb long division
at `src/lib.rs:478-510`, and floor/ceiling division by `S` at
`src/lib.rs:445-476`. `mul_interval` and `div_interval_u64` centralize the same
outward directions at `src/lib.rs:523-535`.

For the initial `y` quotient, the shadow cancels the exact common factor
`2^(768-64)` from numerator and denominator before division
(`src/lib.rs:604-620`). This does not change either quotient or remainder-zero
status, so it preserves both floor and ceiling exactly; it only avoids asking
CBMC to unroll a 2048-step generic divider before reaching the series. The
ordinary test at `src/lib.rs:917-940` compares the cancelled and uncancelled
fixed-limb divisions at both domain endpoints. The analytic tail still uses the
general fixed-limb ceiling divider, rather than substituting a theorem-derived
constant, at `src/lib.rs:635-641`.

### Algorithm variant

This is the shipped algorithm, not an alternative approximation:

- `y = f/(2-f)` represented by `fq*S/(2S-fq)`;
- `2 * sum_(n=0)^255 y^(2n+1)/(2n+1)` plus the shipped positive geometric-tail
  ceiling (`src/lib.rs:604-643`, corresponding to
  `indra-core/src/sortition.rs:100-127`);
- signed, directed 128-term lower and 129-term upper recurrences for
  `1-exp(-z)` (`src/lib.rs:645-673`, corresponding to
  `indra-core/src/sortition.rs:129-162`);
- outward stake scaling, `min(S)` clamp, interval-width guard, Q768-to-512
  shift, and strict comparison (`src/lib.rs:755-785`, corresponding to
  `indra-core/src/sortition.rs:164-197`).

These are the same 256/128/129 finite recurrences formalized in Topic 25. This
crate does not use a direct logarithm series, floating point, or a replacement
probability formula.

## Shadow-crate isolation and construction

The topic's `Cargo.toml` contains its own empty `[workspace]`, so Cargo treats it
as a standalone workspace rather than a member of INDRA's production
workspace. `Cargo.lock` contains only the shadow package. `src/lib.rs` is
`#![no_std]`, has no dependency declarations, no `alloc`, no `Vec`, no `unsafe`,
and no production import. All arithmetic storage is one of `[u64; 16]`,
`[u64; 32]`, `[u64; 8]`, or the input `[u8; 64]`.

The fixed arithmetic reports explicit errors for division by zero, overflow,
underflow, quotient overflow, invalid input, inverted intervals, width-guard
failure, and threshold overflow. The no-error harness therefore has observable
failure branches rather than relying on wrapping arithmetic.

## Production-domain preconditions and call-site check

The Kani domain is the broad domain accepted by the shipped public arithmetic,
not the narrower mainnet constant:

```text
1 <= f <= 2^63
0 < validator_stake <= total_stake <= u64::MAX
output is any [u8; 64]
```

This is independently re-confirmed from current code:

- `certified_log` calls `validate_f`, which enforces `1 <= f <= 2^63`, at
  `indra-core/src/sortition.rs:75-83` and `100-104`.
- Mainnet snapshots apply the still-narrower `validate_mainnet_f` and recompute
  the log certificate at
  `indra-core/src/types/consensus_snapshot.rs:206-218`.
- `evaluate` defensively rejects `w = 0`, `W = 0`, and `w > W` before any phi
  call at `indra-core/src/sortition.rs:165-180`.
- Every snapshot entry rejects zero consensus weight at
  `indra-core/src/types/consensus_snapshot.rs:68-79`. Snapshot validation runs
  that check for every entry, recomputes the checked total, and compares it to
  the stored total at `indra-core/src/types/consensus_snapshot.rs:227-249`;
  decoded snapshots are validated at
  `indra-core/src/types/consensus_snapshot.rs:272-286`.
- Local proposal production finds a snapshot candidate, computes the total with
  `checked_add`, and calls `evaluate` at
  `indra-consensus/src/proposer.rs:121-142`.
- Received proposal and value-entropy validation call `evaluate` with an
  already-validated snapshot entry and `snapshot.total_weight_spark` at
  `indra-core/src/types/proposal.rs:147-153` and
  `indra-core/src/types/proposal.rs:193-198`.

Thus the harness assumptions match the real public function contracts and all
current production call paths. They do not assume an arithmetic result, a width
bound, interval ordering, or absence of an error.

## Ordinary validation

Commands on the final source:

```sh
cd audit_evidence/26_q768_shadow_implementation
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

Results:

- format check: pass;
- unit tests: 6 passed, 0 failed, 0 ignored;
- doc tests: 0 tests, pass;
- Clippy with warnings denied: pass.

The unit tests cover fixed shapes, outward multiplication/rescaling, generic
floor/ceiling long division, the exact `y` cancellation, both admitted `F`
endpoints through the full algorithm, and a simple positive-threshold VRF case.
They are construction checks, not exhaustive evidence and not a differential
test against production.

## Kani setup

Versions used:

```text
cargo-kani 0.67.0
Kani Rust Verifier 0.67.0
CBMC 6.8.0, 64-bit arm64 macOS
Kani Rust toolchain: nightly-2025-11-21-aarch64-apple-darwin
Host rustc: 1.93.1 (01f6ddf75 2026-02-11)
Host cargo: 1.93.1 (083ac5135 2025-12-15)
```

`cargo kani list` discovers six proof harnesses. Five are the requested
full-property harnesses; the sixth isolates the conversion/comparison core so a
full-path timeout cannot hide whether that final step itself is tractable.

## Kani results

| Property / harness | Declared symbolic state | Limit and wall time | Outcome |
|---|---|---:|---|
| Width `<= 1537`: `certificate_width_is_at_most_1537` | admissible `f,w,W`; arbitrary 512-bit output | 20 s; 23.75 s wall | **Inconclusive: CBMC timeout** |
| No panic/overflow/arithmetic error: `admissible_domain_has_no_panic_overflow_or_arithmetic_error` | same full domain | 20 s; 24.00 s wall | **Inconclusive: CBMC timeout** |
| Ordering: `certified_log_and_probability_intervals_are_ordered` | same full domain | 300 s; 302.67 s wall | **Inconclusive: CBMC timeout** |
| Stake monotonicity: `stake_to_threshold_conversion_is_monotone` | symbolic `f,W,w1,w2`, `0<w1<=w2<=W` | 20 s; 23.51 s wall | **Inconclusive: CBMC timeout** |
| Full-path VRF comparison: `vrf_big_endian_conversion_matches_eligibility_comparison` | admissible `f,w,W`; arbitrary 512-bit output | 20 s; 23.51 s wall | **Inconclusive: CBMC timeout** |
| Isolated VRF conversion/comparison: `fixed_limb_vrf_comparison_core_is_correct` | arbitrary `[u8;64]` and arbitrary `[u64;8]` | 5.48 s wall; 3.2440143 s verification | **Verified: 0 of 85 checks failed** |

Kani prints `VERIFICATION:- FAILED` for each timed-out harness. In this table that
tool label is deliberately reported as **inconclusive**, because CBMC emitted
`CBMC timed out` and produced neither a counterexample nor a completed proof.
No property was disproved.

The five-minute ordering run remained in GOTO-program generation/loop unwinding
inside `certified_log`. Its last reported outer-loop unwind was iteration 43 of
256 at `src/lib.rs:626`; it did not reach the 128/129-round phi recurrences or a
solver result. An earlier unoptimized experiment using generic 2048-step long
division for the initial `y` quotient spent its entire 60-second window in that
divider. Exact common-factor cancellation allowed CBMC to enter the 256-term
recurrence, demonstrating that fixed limbs fixed the dynamic representation
problem, but nested 16x16 multiplication and per-limb division loops repeated
across all fixed series rounds remain too large for direct unrolling. A linear
extrapolation from 43 rounds would put syntactic generation of the log recurrence
alone near 30 minutes; it says nothing favorable about the two remaining phi
unwinds or subsequent SAT solving.

The successful isolated harness exhaustively checks, over its declared finite
state space, that direct lexicographic comparison of the 64 big-endian VRF bytes
equals independent conversion to eight little-endian `u64` limbs followed by
integer `Ord`. Its final output was:

```text
SUMMARY:
 ** 0 of 85 failed

VERIFICATION:- SUCCESSFUL
Verification Time: 3.2440143s

Manual Harness Summary:
Complete - 1 successfully verified harnesses, 0 failures, 1 total.
real 5.48
user 4.07
sys 0.51
```

This closes the standalone conversion/comparison sub-property. It does not
close the end-to-end property because computing the symbolic threshold first is
exactly the part that times out.

## Assumptions and trusted base

Kani has no direct `Print Assumptions` command. The comparable scrutiny for this
artifact is:

- The common harness has exactly five assumptions at `src/lib.rs:796-801`:
  `f > 0`, `f <= 2^63`, `W > 0`, `w > 0`, and `w <= W`.
- The monotonicity harness has exactly six assumptions at
  `src/lib.rs:838-843`: the same `f,W` domain plus
  `0 < lower_stake <= higher_stake <= W`.
- The isolated VRF harness has no assumptions.
- There are no Kani stubs, function contracts, `unsafe` blocks, foreign calls in
  the crate, allocator use, or reduced-width substitutes.
- No assumption excludes overflow, an error variant, an interval inversion, a
  wide certificate, or an unfavorable VRF value.

Kani reports one unsupported `caller_location` and one unsupported foreign
function while compiling the crate, with the qualification that verification
fails if either is reachable. These arise through Rust/Kani panic and assertion
infrastructure, not through a declared shadow-crate FFI. The successful isolated
harness establishes they are unreachable on that path. Because the full-path
no-error harness timed out, their unreachability on the full algorithm is not an
established result and remains part of the open no-panic/no-error property.

The trusted computing base for the one completed result includes Kani 0.67.0,
CBMC 6.8.0, Kani's pinned Rust compiler/toolchain and lowering, the host/runtime,
and the correctness of this shadow specification. This is exhaustive,
bit-precise bounded model checking over the declared finite state space; it is
not a Rocq-kernel theorem and it is not third-party certification.

Most importantly, the shadow's conformance to production is **not** in the
trusted result yet. The planned differential pass is required before the shadow
can be used as implementation-conformance evidence.

## Recommendation

Simply increasing the Kani timeouts is unlikely to be a good next move. The
five-minute diagnostic reached only log iteration 43 of 256 while syntactically
expanding the first of three long fixed recurrences, before SAT solving. The
monotonicity harness evaluates the whole algorithm twice and is strictly harder.

For the five open full-path properties, Verus now looks more promising than
plain Kani because it can specify fixed-limb arithmetic once and use loop
invariants/induction across the 256/128/129 recurrences instead of materializing
every operation in one CBMC formula. The already kernel-checked Topic 25
analytic bounds can guide those invariants. Kani remains useful for bounded
low-level units such as add/subtract, individual limb multiplication/division,
array bounds, shifts, and the now-closed 512-bit conversion/comparison. Kani's
experimental loop/function contracts are another possible path, but supplying
and validating their invariants is essentially the same proof-engineering work;
it is not a free extension of this run.

Recommended sequence:

1. Review this shadow for arithmetic fidelity.
2. Perform the separately scoped differential test against production across
   boundary and randomized inputs.
3. If the shadow survives that comparison, either formalize the fixed-limb
   primitives and recurrence invariants in Verus, or decompose Kani into
   individually specified arithmetic lemmas plus contracts rather than retrying
   a monolithic full-path unwind.

## Reproduction

```sh
cd audit_evidence/26_q768_shadow_implementation

cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo kani list

cargo kani --harness fixed_limb_vrf_comparison_core_is_correct

cargo kani --harness certificate_width_is_at_most_1537 \
  -Z unstable-options --harness-timeout 20s
cargo kani --harness admissible_domain_has_no_panic_overflow_or_arithmetic_error \
  -Z unstable-options --harness-timeout 20s
cargo kani --harness certified_log_and_probability_intervals_are_ordered \
  -Z unstable-options --harness-timeout 300s
cargo kani --harness stake_to_threshold_conversion_is_monotone \
  -Z unstable-options --harness-timeout 20s
cargo kani --harness vrf_big_endian_conversion_matches_eligibility_comparison \
  -Z unstable-options --harness-timeout 20s
```

No single end-to-end task timer was started at receipt. The observable new-file
window was 13:50:12 to 14:16:29 IST (26 minutes 17 seconds), excluding the
earlier read-only production trace. Exact final Kani wall times are reported in
the results table rather than replacing that missing overall timer with an
invented precision.

## Scope boundary

Nothing in this topic is imported by or wired into production, and no production
Rust file was modified. No production-vs-shadow differential test was attempted.
The one completed Kani result applies only to the verification-only shadow's
512-bit comparison core. The five full algorithm properties, production
conformance, and the separate R1 bit-identical cross-platform determinism
question all remain open.
