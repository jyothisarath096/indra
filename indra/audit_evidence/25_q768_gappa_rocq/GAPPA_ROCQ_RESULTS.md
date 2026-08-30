# Q768 Gappa/Rocq formalization: feasibility and first attempt

Date: 2026-08-30
Repository revision inspected: `75ec43631d891dd45d2ae4e15ef590d0ffe1ef6d`

## Outcome

**Partial, with a precise formalization boundary.** This pass obtained:

1. a Gappa-automatic certificate for the Q768 primitive directed-rounding and
   width-propagation obligations, accepted by the Rocq kernel;
2. Rocq-kernel-accepted exact computations of the finite 256-term log and
   128/129-term phi error-budget recurrences and all numerical constants used by
   the analytical proof; and
3. Rocq-kernel-accepted composition lemmas showing that the desired bracket,
   `<1538` real width, `<=1537` integer width, and `<1281` lower error follow
   from the remaining analytic and recurrence-soundness obligations.

The full theorem is **not kernel-checked**. The logarithm/atanh series identity
and geometric remainder, the alternating exponential-series remainder, and the
inductive bridge from the primitive rounding lemmas to every iteration of the
abstract recurrence remain unformalized. The exact unfinished theorem goals are
retained with `Abort`, so they do not enter the Rocq environment as assumptions
or theorems.

Most importantly, this work says nothing about whether the shipped Rust
implementation implements the mathematical model. It does **not** close the
implementation-conformance gap identified by Topic 24. No Rust source was
changed.

## 1. Phase 0: existing evidence and exact target

### 1.1 Existing analytical proof

Topic 09 fixes `S = 2^768` and interprets each integer endpoint `a` as `a/S`
(`09_q768_proof/Q768_ERROR_BOUND_PROOF.md:24-28`). Its result is the stronger
universal bound

```text
phi_hi - phi_lo <= 1537 < 2^11 < 2^24
0 <= phi_true - phi_lo/S < 1281/S < 2^-757
```

(`Q768_ERROR_BOUND_PROOF.md:7-18`). The stated domain is
`1 <= F <= 2^63` and `1 <= w <= W` (`Q768_ERROR_BOUND_PROOF.md:113-128`);
production integer types additionally give `W <= 2^64 - 1`.

The proof has three materially different components:

- outward-rounded fixed-point interval arithmetic and finite width recurrences
  (`Q768_ERROR_BOUND_PROOF.md:40-110`, `157-183`, `270-295`);
- analytic series facts: the 256-term atanh/log tail and the 128/129-term
  alternating-exp remainders (`Q768_ERROR_BOUND_PROOF.md:134-155`, `247-268`);
- a final telescoping composition and integer sharpening
  (`Q768_ERROR_BOUND_PROOF.md:297-343`, `345-380`).

Topic 09 explicitly classified itself as an analytical proof plus exact-integer
checker, not theorem-prover verification (`Q768_ERROR_BOUND_PROOF.md:14-18`,
`440-450`). Its checker uses arbitrary-precision integers to reconstruct the
derived endpoint/width recurrences and assert the constants 1025, 1537, and
1281; it neither imports production code nor performs a parameter sweep
(`09_q768_proof/check_bound.py:1-24`, `45-130` and
`Q768_ERROR_BOUND_PROOF.md:391-399`).

The audited source has since gained `validate_mainnet_f` and a corresponding
test, shifting later line numbers, but `git diff` from Topic 09's pinned revision
`b6404ccacc508d92a022f50ad1af3da4d4e31a02` shows no change to the Q768
arithmetic. Current locations are:

- Q768 precision and admitted domain: `indra-core/src/sortition.rs:6-13`;
- primitive ceiling, multiplication, and integer division:
  `sortition.rs:15-21`, `36-55`;
- the exact 256-iteration log recurrence: `sortition.rs:100-127`;
- the parameterized phi recurrence: `sortition.rs:129-163`;
- production calls with exactly 128 and 129 terms: `sortition.rs:176-192`.

This comparison is orientation only. The formal files deliberately target the
abstract recurrence, not the Rust implementation.

### 1.2 Oracle evidence

Topic 08 independently evaluates
`1-exp((w/W)*ln(1-F/2^64))` with directed MPFR intervals and does not reuse the
Q768 series or rounding logic (`08_q768_oracle/ORACLE_RESULTS.md:3-8` and
`08_q768_oracle/src/main.rs:57-105`). It recorded 201,000 exhaustive and 10,006
random/extreme cases, with ideal-minus-production always zero or one
(`ORACLE_RESULTS.md:10-17`), and a maximum observed interval width of 642
(`ORACLE_RESULTS.md:74-79`).

That is strong differential-testing evidence, but it is finite empirical
evidence. It supplies no universal series or rounding theorem and is not used as
a premise in the Rocq files.

### 1.3 Kani facts relevant to feasibility

Topic 24 established that production uses dynamically allocated
`num_bigint::{BigUint, BigInt}`, not a fixed limb array
(`24_q768_kani/KANI_RESULTS.md:19-37`). It also established that the numerical
loops are fixed: 256 log terms and literal 128/129 phi terms, with no
convergence-controlled termination (`KANI_RESULTS.md:39-49`). Kani then stalled
during model construction in heap-backed big-integer arithmetic rather than
finding a counterexample (`KANI_RESULTS.md:98-111`).

The fixed term counts are the key positive fact for this task: the abstract
mathematical state space is a large but finite recurrence, so no loop-termination
or convergence stopping criterion has to be proved.

### 1.4 Precise target theorem

Let

\[
S=2^{768},\qquad
f=\frac{F}{2^{64}},\qquad
\alpha=\frac{w}{W},\qquad
p(F,w,W)=1-(1-f)^\alpha.
\]

For

\[
1\le F\le 2^{63},\qquad 1\le w\le W\le 2^{64}-1,
\]

let `C(F,w,W) = (lo,hi)` be the exact abstract integer recurrence in
`Q768AbstractModel.v`: Q768 floor/ceiling endpoints, 256 log terms plus the
positive tail bound, stake scaling, the 128-term lower phi evaluation, the
129-term upper phi evaluation, and final clamping to `[0,S]`.

The theorem to establish is

\[
\frac{lo}{S}\le p(F,w,W)\le\frac{hi}{S},
\tag{T1}
\]

\[
0\le hi-lo\le1537<2^{24},
\tag{T2}
\]

and the stronger conservative-threshold statement

\[
0\le p(F,w,W)-\frac{lo}{S}
 <\frac{1281}{S}<2^{-757}.
\tag{T3}
\]

Consequently,

\[
\left\lfloor 2^{512}p(F,w,W)\right\rfloor
-\left\lfloor\frac{lo}{2^{256}}\right\rfloor\in\{0,1\}.
\tag{T4}
\]

`Q768AbstractModel.v:1-99` defines `C` and `p` with the real production term
counts and precision. `full_q768_abstract_target` at lines 101-114 is the exact
formal target corresponding to T1-T3. It is intentionally `Abort`ed and hence
is **not** a theorem in the compiled artifact.

The target is broader than merely “the truncated series has small error.” It
requires:

1. the 256-term series to bracket `-ln(1-f)` after outward rounding;
2. stake scaling to preserve that bracket;
3. the 128/129 phi recurrences to bracket `1-exp(-z)` after outward rounding;
4. the accumulated width and lower-error constants; and
5. monotone clamping and integer threshold extraction.

It is narrower than an implementation theorem: it does not claim that Rust,
`num-bigint`, compilation, or serialization matches `C`.

## 2. Phase 1: tool-specific feasibility

### 2.1 Gappa

Gappa is designed to verify numerical programs using fixed- or floating-point
arithmetic and can emit certificates for Rocq. Its fixed-point syntax directly
models directed rounding at a selected least-significant-bit weight. See the
[official Gappa site](https://gappa.gitlabpages.inria.fr/) and
[arithmetic documentation](https://gappa.gitlabpages.inria.fr/gappa/arithmetic.html).

The fixed Q768 recurrence is therefore a good match for Gappa at the primitive
operation level. The known finite term counts also make straight-line expansion
possible in principle. They materially improve feasibility compared with a
convergence-controlled or infinite computation.

They do not make the complete proof a Gappa-only problem:

- Gappa's expression prover has no native theorem stating the atanh/log power
  series identity or the alternating-series remainder for `exp`.
- A generated 256+128+129-term expression could bound a finite polynomial, but
  it would still need a proof relating that polynomial to `ln` and `exp`.
- The reusable proof is naturally inductive: one generic interval-operation
  lemma plus loop invariants. Expanding hundreds of operations loses that
  structure and produces a large certificate without solving the analytic gap.

Verdict: **Gappa can discharge primitive rounding and selected algebraic
sublemmas, but cannot automatically discharge the full theorem.** Rocq is
needed for induction and transcendental analysis. Gappa can remain the numeric
backend for local rounding goals. The official documentation describes both
certificate generation and its Rocq integration
([invocation/backend documentation](https://gappa.gitlabpages.inria.fr/gappa/invoking.html),
[Rocq integration](https://gappa.gitlabpages.inria.fr/gappa/tools.html)).

### 2.2 Rocq

Rocq readily evaluates the exact finite `N` recurrences and accepts the
resulting closed propositions. It can also express the real-analysis target and
prove the final linear composition. The hard work is library-level analysis,
not the 256-step termination:

- instantiate or develop a formal power-series theorem for
  `ln((1+y)/(1-y))` on `0<y<=1/3`;
- prove the exact geometric tail with first omitted power 513;
- instantiate or develop the alternating-series remainder for `exp` at exactly
  128 and 129 terms on `0<=x<7/10`;
- prove loop invariants connecting each abstract interval recurrence to its
  exact real term; and
- connect those invariants to the checked numerical budgets.

Verdict: **feasible in Rocq, but not complete in a same-day first attempt.** A
reasonable estimate for an engineer already comfortable with Rocq real-analysis
libraries is approximately one to three focused engineer-weeks for the abstract
proof, depending on how directly existing power-series lemmas instantiate.
That estimate excludes Rust/model conformance.

## 3. Phase 2 artifacts and checked results

### 3.1 Gappa primitive certificate

`q768_primitives.g` uses exact `fixed<-768,dn>` and `fixed<-768,up>` operators.
Over nonnegative normalized endpoints and every positive divisor through
`2^64-1`, it automatically establishes:

- downward error in `[-2^-768,0]` and upward error in `[0,2^-768]`;
- the corresponding directed errors for multiplication and division; and
- the real width bounds

\[
\operatorname{wd}(A\cdot B)
 \le b_h\operatorname{wd}(A)+a_l\operatorname{wd}(B)+2\cdot2^{-768},
\]

\[
\operatorname{wd}(A/d)
 \le \operatorname{wd}(A)/d+2\cdot2^{-768}.
\]

Gappa 1.8.2 accepted the script. Its `-Bcoq` backend generated
`Q768Primitives_generated.v`, and Rocq 9.2.0 accepted that certificate against
Gappa's Rocq support library 1.11.0 and Flocq 4.2.2. This is a kernel-checked
theorem about the stated real fixed-point operators. It does not contain the
log/exp series theorems, loop induction, or Rust.

Gappa prints a warning that `d` was assumed nonzero while it validates each
division rewrite hint. The proved implication includes `d in
[1,18446744073709551615]`; the generated Rocq certificate discharges the
nonzero requirement from that premise and contains no axiom or admission.

Gappa gives inclusive one-unit enclosures. Topic 09's sharper final `1537`
integer result relies on strict analytic remainders followed by integer
sharpening; Gappa's inclusive primitive result alone must not be described as
establishing that final constant.

### 3.2 Exact finite recurrence constants

`Q768FiniteBounds.v` is the Rocq analogue of `check_bound.py`, using exact
`N` arithmetic and the real production counts. Rocq's kernel accepted all of
the following closed examples:

| Checked proposition | Result |
|---|---:|
| Sum of 256 log term-width bounds | 512 |
| Scaled log-tail ceiling in the modeled bound | 1 |
| Log interval width budget | 1025 |
| Log upper endpoint domain | `10*log_hi < 7*S` |
| 128-term phi rounding-width sum | 254 |
| 129-term phi rounding-width sum | 256 |
| Exact 129 and 130 factorial inequalities | both `< 1` scaled Q768 unit |
| Stake-input uncertainty budget | 1026 |
| Strict composed real-width budget | 1538 |
| Integer interval-width bound | 1537 `< 2^24` |
| Strict lower-error budget | 1281 `< 2^11` |

The exact recurrences are at `Q768FiniteBounds.v:5-98`; the accepted
propositions are at lines 100-149. `vm_compute; reflexivity` is used to reduce
these closed finite expressions. This is stronger than re-running Python in the
sense that Rocq accepts the propositions into a `.vo`; it is not a proof that
the recurrences are sound bounds for the transcendental functions.

In particular, the theorem named `analytic_log_tail_rounds_to_one` checks the
integer ceiling of the already-selected analytic tail formula. It does not
prove that this formula bounds the true omitted log series.

### 3.3 Composition

`Q768Composition.v:5-46` proves, under named hypotheses for endpoint ordering,
series ordering, rounding gaps, and the 1026 propagated-input gap, that the
certificate brackets the true value, has real width `<1538`, and has lower
error `<1281`. Lines 50-57 prove the exact integer step

\[
\operatorname{IZR}(n)<1538\Longrightarrow n\le1537.
\]

These theorems are kernel-checked. Their hypotheses are not all discharged in
this pass.

### 3.4 Exact open obligations

`Q768AnalyticObligations.v` defines the real finite sums, with exactly 256 log
terms and exactly 128/129 phi terms (`Q768AnalyticObligations.v:5-26`). It then
states:

- the exact 256-term log lower bound and first-omitted-power-513 geometric tail
  (`Q768AnalyticObligations.v:29-41`); and
- the exact 128/129 alternating-exp bracket and first-omitted-term remainder
  bounds (`Q768AnalyticObligations.v:44-56`).

Both proofs end in `Abort`. Rocq therefore parses and type-checks the statements
but exports neither theorem. No `Axiom`, `Admitted`, or opaque assumption is used
to make the final result appear complete.

`Q768AbstractModel.v` similarly defines the complete abstract recurrence and
true probability at the real shipped precision/counts, then `Abort`s the final
T1-T3 theorem. This is the honest first-attempt boundary.

## 4. Reproduction

Versions used:

```text
Gappa 1.8.2
The Rocq Prover 9.2.0 (OCaml 5.5.0)
Flocq 4.2.2
Gappa Rocq support library 1.11.0
macOS arm64
```

Gappa and its Rocq support library were obtained from the
[official release page](https://gappa.gitlabpages.inria.fr/). Flocq 4.2.2 was
obtained from the [official Flocq site](https://flocq.gitlabpages.inria.fr/),
which lists support through Rocq 9.2.

With `gappa`, `coqc`, Flocq, and the Gappa support library installed in their
standard search paths:

```sh
cd audit_evidence/25_q768_gappa_rocq

gappa q768_primitives.g
gappa -Bcoq q768_primitives.g > Q768Primitives_generated.v
coqc Q768Primitives_generated.v

coqc Q768FiniteBounds.v
coqc Q768Composition.v
coqc Q768AnalyticObligations.v
coqc Q768AbstractModel.v
```

For libraries installed outside Rocq's standard search path, the certificate
check used:

```sh
coqc \
  -R /path/to/Flocq Flocq \
  -R /path/to/gappalib/src Gappa \
  Q768Primitives_generated.v
```

The two files containing `Abort` compile successfully by design; successful
compilation confirms syntax/type correctness, not completion of those aborted
theorems. Search for the explicit boundary with:

```sh
rg -n 'Abort|Admitted|Axiom' *.v
```

It should report exactly three `Abort` commands and no `Admitted` or `Axiom`.

This run additionally checked each produced module with `rocqchk`, while
explicitly admitting already-compiled dependencies:

```sh
rocqchk -bytecode-compiler yes -norec Q768FiniteBounds
```

The equivalent command accepted all five modules. `-norec` matters: this checks
the selected module but does not recursively recheck Stdlib, Flocq, or the Gappa
support library. A recursive `rocqchk` attempt remained CPU-active without an
error after ten minutes and was stopped as an impractical dependency-closure
run for this pass. That timeout is not a disproof or a failure of any Q768
obligation; it also is not a completed recursive dependency audit.

The earlier independent exact checker remains reproducible with:

```sh
python3 ../09_q768_proof/check_bound.py
```

## 5. Trusted computing base and exact claim status

What is kernel-checked in this topic:

- the Gappa-generated proof certificate for the declared Q768 real
  fixed-point primitive obligations;
- the exact closed finite recurrence and numerical inequalities in
  `Q768FiniteBounds.v`; and
- the conditional composition and integer-sharpening theorems in
  `Q768Composition.v`.

The trusted computing base for those results includes the Rocq kernel and
standard library. Certificate generation used Gappa, but the generated proof is
checked by Rocq; Flocq and Gappa's Rocq support library supply the fixed-point
definitions and lemmas. The `vm_compute` path also relies on Rocq's VM reduction
mechanism to build conversion evidence subsequently accepted in the compiled
development. `coqc` accepted every module, and `rocqchk -norec` independently
accepted each selected `.vo`; the full recursive support-library closure was
not completed in this pass.

What is not kernel-checked:

- the log/atanh power-series identity and geometric remainder;
- the alternating-exp remainder theorem at 128/129 terms;
- the induction connecting the generic primitive lemmas to every recurrence
  step;
- stake scaling, monotonicity/Lipschitz, clamping, and threshold corollary as one
  discharged end-to-end theorem;
- equivalence between `Q768AbstractModel.v` and shipped Rust;
- `num-bigint` exactness, Rust panic/overflow behavior, compiler behavior, or
  bit-identical cross-platform determinism.

Therefore the accurate status is:

> Rocq-kernel-checked primitive and finite-budget subresults; full abstract
> Q768 bracketing/error theorem still incomplete.

It would be incorrect to summarize this as “Q768 formally proved.”

## 6. Recommendation

Continue with **Rocq plus Gappa**, rather than asking Gappa to unroll the entire
algorithm. The next authorized proof pass should:

1. use an established Rocq real-analysis/power-series library if it supplies
   suitable `ln`, `exp`, geometric-tail, and alternating-remainder theorems;
2. close the two exact goals in `Q768AnalyticObligations.v` without changing
   their term counts or domains;
3. prove generic soundness lemmas for `imul` and `idivi`, using or importing the
   Gappa certificate, then induct over the exact recurrences;
4. discharge the stake-scaling, monotonicity, and clamping obligations;
5. replace the three `Abort`s with completed proofs and have `rocqchk` inspect
   the resulting `.vo` dependency closure; and
6. separately obtain a human decision on Rust/model conformance. A fixed-limb
   rewrite plus Kani, translation validation, or another equivalence mechanism
   remains necessary for that distinct question.

Gappa alone is the wrong tool for the transcendental series bridge. Verus would
not improve this abstract real-analysis task; it becomes relevant only to the
separate implementation-conformance layer. Gappa/Rocq remains the most
defensible route for the mathematical theorem.

This report intentionally repeats the boundary: **none of these results
establishes that the shipped Rust implementation matches the abstract model.**
That remains the still-blocked Kani/representation decision from Topic 24.
