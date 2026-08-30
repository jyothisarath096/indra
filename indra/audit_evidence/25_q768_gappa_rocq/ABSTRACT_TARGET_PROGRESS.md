# Q768 abstract end theorem: recurrence-conformance progress

Date: 2026-08-30  
Repository revision at start: `4907d88eb7f15d2efedc35d6ae3a24880b340518`

## Outcome

`full_q768_abstract_target` did **not** close in this pass. It remains terminated
with `Abort`; no `Admitted` or `Axiom` was introduced. The attempt nevertheless
closed the complete integer/real bridge through the production-shaped log
recurrence and stake-scaling stage. The remaining formal gap is now isolated to
the signed 128/129-step phi recurrence, its two clamps, and the final error
budget assembly.

The new checked bridge establishes, for every input satisfying `admissible`,
that the exact interval produced by `certified_log_model`, followed by the exact
floor/ceiling stake operations used by `certificate_model`, contains

\[
S\,\frac{w}{W}\left[-\ln\left(1-\frac{F}{2^{64}}\right)\right]
=S\,\mathtt{phi\_argument}(F,w,W),\qquad S=2^{768},
\]

and that this scaled interval has upper endpoint at most the checked finite
`log_hi` constant and width at most `log_width + 1 = 1026` Q768 units. This is
now the kernel-checked theorem `certificate_log_and_stake_bridge`.

This is meaningful progress, but it is not the requested end theorem. There is
therefore no `Print Assumptions full_q768_abstract_target` output: an aborted
goal does not introduce that theorem into Rocq's environment.

## Step 0: exact target and composition chain

`certificate_model` has the following actual composition, in order:

1. `certified_log_model f` constructs `y = f/(2-f)` as a directed Q768
   interval, runs exactly 256 atanh terms, and adds the positive geometric tail
   (`Q768AbstractModel.v:42-54`).
2. Its endpoints are scaled by `w/total`: the lower endpoint uses integer floor
   and the upper endpoint uses `ceil_div` (`Q768AbstractModel.v:83-88`).
3. The lower integer endpoint is evaluated by the 128-term, lower-directed phi
   recurrence and the upper endpoint by the 129-term, upper-directed recurrence
   (`Q768AbstractModel.v:56-81`, `83-88`).
4. Both results are clamped with `N.min q768_scale`; the theorem then claims a
   real bracket, an integer width at most 1537, and lower error strictly below
   `1281/S` (`Q768AbstractModel.v:1156-1171`).

The required proof obligations are consequently:

- **(a) Log enclosure.** The actual finite integer recurrence must bracket
  `L = -ln(1-F/2^64)`, not merely have a checked numeric width.
- **(b) Stake scaling.** Floor/ceiling of a bracket multiplied by the positive
  rational `w/total` must bracket `x = (w/total)L` and retain the derived width.
- **(c) Phi enclosure.** The actual signed, directed fixed-point recurrences at
  the two integer endpoints must correspond to `phi_partial 128` and
  `phi_partial 129`, so the already-closed analytic phi theorem can be applied.
- **(d) Final assembly.** `Z.to_N` and `N.min S` must preserve the bracket and
  not increase the width; the checked arithmetic and analytic budgets must then
  imply the exact certificate statement.

This pass closed (a) and (b). It did not close (c) or (d).

### Which width is the target?

The theorem statement remains the stronger Topic 09 result

\[
hi-lo\le 1537,
\qquad
0\le p-lo/S<1281/S.
\]

This naturally matches the already-checked finite constants in
`Q768FiniteBounds.v`; it was not weakened merely to make the proof easier.
`1537 < 2^24`, so closure of the current statement would imply the production
runtime guard. The runtime-enforced property is the strict `< 2^24` check; the
1537 result is the stronger analytical target, not a distinct runtime limit.

## Kernel-checked work completed in this pass

The formal addition to `Q768AbstractModel.v` is 1,049 added and 7 changed or
removed lines relative to the starting revision. The principal checked pieces
are:

1. Exact `N`/`Z`/`R` conversion and floor/ceiling lemmas, including lower and
   upper real interpretations and one-unit rounding gaps
   (`Q768AbstractModel.v:115-339`).
2. Generic interval enclosure and finite-width composition for multiplication,
   division, addition, and the log accumulator (`Q768AbstractModel.v:221-489`).
3. Exact production-domain conversion from `F` to the atanh argument, proving
   `0 < y <= 1/3` (`Q768AbstractModel.v:491-610`, `855-885`).
4. A generic 256-step log recurrence invariant tied to
   `Q768FiniteBounds.final_log_state`, including the actual geometric-tail
   rounding (`Q768AbstractModel.v:612-710`).
5. A real recurrence normalization proving that the integer loop encloses the
   exact 256-term `log_partial`, followed by application of the already-closed
   `log_tail_after_exactly_256_terms` and `log_y_substitution_identity`
   (`Q768AbstractModel.v:712-1055`).
6. Exact semantic and width preservation through stake scaling
   (`Q768AbstractModel.v:1057-1121`).
7. The end-to-end log-plus-stake theorem
   `certificate_log_and_stake_bridge` (`Q768AbstractModel.v:1123-1154`).

These are ordinary `Qed` lemmas. None relies on the unfinished end theorem.

### Library facts versus project-specific work

Rocq Stdlib supplied exact natural-number division/modulus facts, conversions
between `N`, `Z`, and `R`, ordered-field facts, and the `lia`/`nia`/`lra`/`nra`
and ring tactics. Coquelicot supplied the two analytic results already closed
in the preceding passes.

The recurrence invariants, Q768 scaling identities, denominator bounds,
correspondence between `Q768FiniteBounds` and the actual abstract recurrence,
geometric-tail rounding bridge, and stake interval theorem are project-specific
work. The floor/ceiling facts use Stdlib primitives, but their exact Q768
interval formulations and compositions are also project-specific.

## Exact remaining blocker

The remaining proof is not a missing invocation of either closed analytic
theorem. It needs a simultaneous invariant for `phi_recurrence` that tracks:

1. the current interval term as an enclosure of
   `S * x^k/k!` under the exact `imul` then `idivi` operation order;
2. the signed `Z` accumulator against the exact alternating partial sum;
3. lower mode's odd-low/even-high choices and upper mode's
   odd-high/even-low choices from `selected_endpoint`;
4. accumulated arithmetic error against `phi_rounding_width 128 = 254` and
   `phi_rounding_width 129 = 256`;
5. the `Z.to_N` behavior when a directed lower accumulator is negative;
6. the analytic remainder at each *different* input endpoint, including the
   repaired `x=0` equality case for a rounded lower endpoint;
7. monotonicity and the one-Lipschitz bound for
   `S*(1-exp(-x/S))` across the at-most-1026-unit input interval; and
8. monotonicity/nonexpansiveness of the final `N.min S` clamp.

Only after those facts are joined can the strict real budget

```text
256 + (<1) + 1026 + (<1) + 254 < 1538
```

be sharpened to the integer result `hi - lo <= 1537`, and the lower-side chain
to `< 1281/S`. `Q768FiniteBounds.v` kernel-checks the individual closed numeric
constants, but that computation does not by itself prove that
`phi_recurrence` obeys the recurrence invariant described above.

The important small-domain subtlety is that production's true
`phi_argument` is positive, but the *rounded lower integer endpoint* can still
be zero. A sound proof therefore must use `phi_at_zero_is_exact` for that
branch, rather than applying the strict-domain theorem at zero.

## Revised effort estimate

The earlier library survey estimated 6--10 focused engineer-days for the
abstract recurrence/end theorem, followed by 2--3 days of dependency cleanup,
`rocqchk`, CI, and review. Approximately five hours in this pass produced the
generic interval machinery and completed the log and stake bridges, but the
signed phi invariant remains the most delicate part.

A grounded remaining estimate is **3--6 focused engineer-days** to finish and
review (c) and (d), followed by the previously identified **2--3 days** for
dependency/CI cleanup and independent review. This moves the proof-writing
portion down from 6--10 days because the 256-step log recurrence and stake
bridge are now checked. It is not reduced to a few hours: signed integer
accumulation, zero clamping, strict inequalities, and two unequal endpoint
evaluations create substantially more cases than the unsigned log recurrence.

## Verification

The dependency stack was the same as the preceding Topic 25 passes:

- Rocq Prover 9.2.0;
- Coquelicot 3.4.5;
- MathComp 1.19.0's ssreflect core with the already-documented Rocq-9.2
  proof-script compatibility adjustment.

From `audit_evidence/25_q768_gappa_rocq`, the isolated commands are:

```sh
coqc \
  -Q /tmp/q768-assumptions/mathcomp-flat mathcomp \
  -R /tmp/q768-assumptions/coquelicot-3.4.5/theories Coquelicot \
  Q768AnalyticObligations.v
coqc \
  -Q /tmp/q768-assumptions/mathcomp-flat mathcomp \
  -R /tmp/q768-assumptions/coquelicot-3.4.5/theories Coquelicot \
  Q768FiniteBounds.v
coqc \
  -Q /tmp/q768-assumptions/mathcomp-flat mathcomp \
  -R /tmp/q768-assumptions/coquelicot-3.4.5/theories Coquelicot \
  Q768AbstractModel.v
grep -n 'Abort\|Admitted\|Axiom' *.v
```

All three files compile. The trust-marker scan after this pass is exactly:

```text
Q768AbstractModel.v:1171:Abort.
```

That is one `Abort` and zero `Admitted`/`Axiom` occurrences.

Elapsed wall-clock time for this pass was approximately **5 hours**, including
formal development, failed proof-shape experiments, recompilation, and report
preparation.

## Scope and non-claim

Even if `full_q768_abstract_target` is later closed, it will establish a
Rocq-kernel-checked theorem about the **abstract mathematical model** in
`Q768AbstractModel.v`. This pass has not closed even that theorem.

Neither the checked helper lemmas nor eventual closure would establish that the
shipped Rust implementation—still using dynamically allocated `num_bigint`—is
bit-for-bit conformant with this model. They also do not close the separate R1
bit-identical cross-platform determinism question. No Rust source was changed
in this pass.
