# Q768 phi `x = 0` reachability and theorem repair

Date: 2026-08-30

## 1. Scope and conclusion

This addendum traces phi's argument through the shipped Rust and abstract Rocq
models, then records the approved strict-domain repair. No Rust production file
was changed and none of the three incomplete proof obligations was closed.

**Conclusion with certainty:** `x = 0` is not reachable by an admitted
production sortition evaluation. On the valid domain,

\[
x=\frac{w}{W}\left[-\ln\left(1-\frac{F}{2^{64}}\right)\right],
\]

with `F > 0`, `0 < w <= W`, and `W > 0`; hence `x > 0`. The shipped integer
Q768 lower endpoint also cannot round this positive value to zero under the
`u64` input bounds. Independently, `evaluate()` rejects `w = 0` before either
call to `phi`.

The repaired analytic theorem therefore has domain `0 < x < 7/10`. Exact
zero-value lemmas now state the separate mathematical boundary case without
weakening the production end theorem.

## 2. Exact production derivation

Let `S = 2^768`. Rust fixes that precision in `sortition.rs:6-13`.

### 2.1 Logarithm input from `F`

`certified_log(F)` first enforces `1 <= F <= 2^63`
(`sortition.rs:75-83`, called at `sortition.rs:101-103`). It then computes

```text
fq  = F * 2^(768-64)
den = 2*S - fq
y   = fq / den                    (Q768, outward rounded)
L   = 2 * sum[n=0..255] y^(2n+1)/(2n+1) + certified tail
```

at `sortition.rs:104-127`. Mathematically,

\[
y=\frac{f}{2-f},\quad f=F/2^{64},\qquad
L=-\ln(1-f)>0.
\]

Production snapshots narrow `F` further to the immutable mainnet value
`F = 6_917_529_027_641_081_856`, i.e. `f = 3/8`
(`primitives.rs:72-78`). `ConsensusSnapshot::new` checks that value and creates
the certificate with `certified_log` (`consensus_snapshot.rs:139-149`). Snapshot
validation recomputes the certificate and requires exact equality with the
stored endpoints (`consensus_snapshot.rs:206-219`). A zero or inverted stored
lower endpoint is separately rejected (`consensus_snapshot.rs:191-203`).

### 2.2 Stake scaling and phi calls

`evaluate()` computes, at `sortition.rs:176-182`,

```text
zl = floor(log.lo * w / W)
zh = ceil (log.hi * w / W)
pl = phi(zl, 128, lower=true)
ph = phi(zh, 129, lower=false)
```

The real argument represented by those Q768 integers is therefore

\[
x=\alpha L,qquad \alpha=w/W,qquad
L=-\ln(1-F/2^{64}).
\]

It depends on all three inputs, but multiplicatively on `w`. On the admitted
domain `F > 0` and `W > 0`, `L > 0`, so `x = 0` if and only if `w = 0`.
`F = 0` could also make `x = 0` outside that domain, but `validate_f` rejects it
and mainnet admits only `F = 3*2^61`.

### 2.3 Q768 flooring cannot create a zero at positive stake

This is not merely a real-number argument. Even over the abstract audit domain's
smallest `F` and `w`, the integer lower endpoint remains positive:

- `F >= 1` gives `fq >= 2^704`;
- `den < 2^769`, so
  `floor(fq*S/den) >= 2^703` for the lower endpoint of `y`;
- the `n = 0` log term is exactly that positive lower endpoint and the final
  log lower endpoint doubles the nonnegative sum, so `log.lo >= 2^704`; and
- `w >= 1`, while the type and admitted model give `W <= 2^64-1`; therefore
  `floor(log.lo*w/W) >= 2^640 > 0`.

These operations are visible in Rust at `sortition.rs:104-126` and
`sortition.rs:176-182`. Thus both the true real argument and the lower integer
argument sent to `phi` are strictly positive for every admitted input. The
mainnet `F = 3/8` case is much farther from zero than this deliberately broad
`F = 1` audit boundary.

## 3. Every production `evaluate()` call path

A repository-wide search of non-test production sources found three calls:

1. **Local proposer evaluation:** `compute_proposer_vrf` selects a candidate
   from `ProposerElection.candidates` and calls `evaluate` at
   `indra-consensus/src/proposer.rs:121-142`. Normal construction copies those
   candidates from a validated `ConsensusSnapshot` at
   `proposer.rs:58-95`.
2. **Received proposal eligibility:** `verify_proposal` obtains the proposer
   entry from the governing snapshot at
   `indra-core/src/types/proposal.rs:109-113`, then calls `evaluate` at
   `proposal.rs:147-153`.
3. **Received entropy-origin eligibility:** the same verifier obtains the
   entropy entry at `proposal.rs:165-171` and calls `evaluate` at
   `proposal.rs:193-198`.

The enforcement is redundant:

- every `ConsensusSnapshotEntry` rejects
  `consensus_weight_spark == 0` in `ConsensusSnapshotEntry::validate`
  (`consensus_snapshot.rs:68-79`);
- both entry construction and wire decoding call that validation
  (`consensus_snapshot.rs:44-65` and `99-111`);
- whole-snapshot validation rejects an empty snapshot, validates every entry,
  and verifies the recomputed total (`consensus_snapshot.rs:206-236`); and
- most decisively, `evaluate()` itself rejects `w == 0`, `W == 0`, or `w > W`
  at `sortition.rs:165-175`. The calls to `phi` occur later at lines 181-182.

Consequently even an incorrectly constructed public `ProposerElection` cannot
cause `phi` to run with zero stake: the common callee returns first. There is no
production path around this guard.

## 4. Abstract-model correspondence

`Q768AbstractModel.v:40-52` constructs the same 256-term certified log interval.
`certificate_model` then computes

```coq
let zlo := (l.(ilo) * w) / total in
let zhi := ceil_div (l.(ihi) * w) total in
```

and passes those endpoints to the 128/129-term phi recurrences
(`Q768AbstractModel.v:81-86`). The real model now names the corresponding value
explicitly:

```coq
Definition phi_argument (f w total : N) : R :=
  let fr := NR f / NR (2 ^ 64)%N in
  let alpha := NR w / NR total in
  alpha * (- ln (1 - fr)).
```

The end theorem's `admissible` predicate requires `1 <= f <= 2^63`, `1 <= w`,
`w <= total`, and `total <= 2^64-1`
(`Q768AbstractModel.v:109-111`). These facts entail `total > 0` and strict
positivity of `phi_argument`. The end theorem therefore remains a production-
domain theorem; it does not need a new zero-valued production branch or an
extra premise.

## 5. Applied formal-statement repair

### 5.1 `Q768AnalyticObligations.v`

The false inclusive lower endpoint was changed exactly as approved:

```diff
-    0 <= x < 7 / 10 ->
+    0 < x < 7 / 10 ->
```

Two checked helper lemmas now isolate the excluded boundary:

```coq
Lemma phi_partial_at_zero :
  forall terms : nat, phi_partial terms 0 = 0.

Lemma phi_at_zero_is_exact :
  true_phi 0 = 0 /\
  phi_partial 128%nat 0 = 0 /\
  phi_partial 129%nat 0 = 0.
```

The log/atanh theorem and its `Abort` were not changed.

### 5.2 `Q768AbstractModel.v`

The expression formerly inlined in `true_probability` was factored, without a
semantic change, into the named `phi_argument`. The separate exact-zero bridge
is kernel-checked:

```coq
Lemma true_probability_at_zero_phi_argument :
  forall f w total : N,
    phi_argument f w total = 0 ->
    true_probability f w total = 0.
```

The comment at the incomplete end proof now directs a future proof to establish
`0 < phi_argument f w total` before invoking the repaired strict theorem, and
to use the exact-zero lemma if the end theorem is ever generalized beyond its
current production domain.

The statement of `full_q768_abstract_target` itself was deliberately not
weakened or widened: `admissible` already excludes zero stake, and Part A proves
that its phi argument is strictly positive. Adding a redundant positivity
premise or allowing `w = 0` would change the original theorem rather than repair
its analytic dependency.

## 6. Verification

From `audit_evidence/25_q768_gappa_rocq/`:

```sh
coqc Q768AnalyticObligations.v
coqc Q768AbstractModel.v
```

Both commands completed successfully with Rocq 9.2.0. The exact incomplete
proof boundary remains:

```text
Q768AbstractModel.v:129:Abort.
Q768AnalyticObligations.v:65:Abort.
Q768AnalyticObligations.v:80:Abort.
```

There are exactly **three** `Abort` commands and no `Admitted` or `Axiom` in the
topic's `.v` files. Compilation establishes that the repaired statements and
new exact-zero lemmas type-check; it does not establish either analytic theorem
or the full abstract target.

This remains an abstract mathematical/model repair only. It does not establish
that the shipped Rust implementation conforms to the Rocq model.
