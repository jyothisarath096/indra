# Q768 abstract end theorem: final closure

Date: 2026-09-01  
Repository revision at start: `5c3f11a32188fe1ebb98e23148bd449a8548a73e`

## Outcome

`full_q768_abstract_target` is now closed with `Qed`. All three original
`Abort`s in Topic 25 are gone. The theorem retains the stronger Topic 09
certificate bounds; it was not weakened to the production runtime guard:

\[
\frac{lo}{2^{768}} \le p \le \frac{hi}{2^{768}},\qquad
hi-lo\le 1537,\qquad
0\le p-\frac{lo}{2^{768}}<\frac{1281}{2^{768}}.
\]

The proof connects the actual abstract `certificate_model` composition to the
two already-closed analytic theorems, including the signed `Z` accumulator,
directed odd/even endpoint selection, `Z.to_N`, both `N.min` clamps, and the
final integer/real budget conversion. There are zero `Abort`, `Admitted`, or
`Axiom` markers in the topic's Rocq sources.

This is a Rocq-kernel-checked theorem about the **abstract mathematical model**
in `Q768AbstractModel.v`. It does **not** establish that the shipped Rust
implementation, which still uses dynamically allocated `num_bigint`, conforms
to this model bit-for-bit. It also does **not** close the separate R1
bit-identical cross-platform determinism question. Those two implementation
questions remain open.

## Exact closed composition

The checked proof now covers the complete chain:

1. `certificate_log_and_stake_bridge` supplies the already-checked enclosure
   and 1026-unit stake-scaled log width.
2. `stake_lower_endpoint_bound` proves the lower endpoint is not merely
   nonzero but satisfies `2^640 <= zlo` on every `admissible` input. No
   unreachable `zlo = 0` branch is used.
3. `phi_recurrence_sound` tracks the exact production-shaped `phi_recurrence`
   term interval and signed accumulator against the alternating real partial
   sum and the finite rounding-width recurrence.
4. `phi_lower_model_error` and `phi_upper_model_error` specialize that generic
   correspondence to the actual 128-term lower and 129-term upper calls,
   including `Z.to_N`. Their strict arithmetic-plus-analytic budgets are
   respectively `< 255` and `< 257` Q768 units.
5. `true_phi_monotone_lipschitz` and
   `scaled_true_phi_endpoint_gap` bound movement of the true probability over
   the stake-scaled log interval by at most its 1026-unit endpoint width.
6. `lower_q768_clamp_identity` proves the lower clamp is exactly the raw lower
   value; `upper_q768_clamp_preserves` proves the upper clamp preserves the
   bracket and cannot increase the upper error.
7. `full_q768_abstract_assembly` combines the components. The final exported
   theorem uses `certificate_model_shape` to instantiate that assembly with
   the literal `certificate_model` computation.

The key real width calculation is

```text
upper phi error < 257
endpoint movement <= 1026
lower phi error < 255
--------------------------------
raw/clamped width < 1538
```

Because the clamped endpoints are naturals, strict real width `< 1538`
implies the literal integer result `hi - lo <= 1537`. The lower-only chain is
`1026 + (<255) < 1281`, which yields the theorem's strict
`1281 / 2^768` lower-error bound. Thus the checked 1537 bound also implies the
production guard `< 2^24`, while remaining substantially stronger.

## Principal additions

The signed recurrence and final assembly occupy
`Q768AbstractModel.v:1156-2256`. The principal definitions and checked lemmas
are:

- recurrence normalization and invariants: `phi_exact_term`,
  `next_phi_term`, `next_phi_sum`, `phi_sum_sound`,
  `phi_recurrence_step`, and `phi_recurrence_sound`;
- exact finite-bound specialization: `phi_raw_sum_sound`,
  `phi_lower_raw_error`, and `phi_upper_raw_error`;
- signed-to-natural conversion: `phi_model_as_raw_sum`,
  `lower_Z_to_N_preserves_error`, `upper_Z_to_N_preserves_error`,
  `phi_lower_model_error`, and `phi_upper_model_error`;
- strict production-domain endpoint result:
  `certified_log_model_lower_bound` and `stake_lower_endpoint_bound`;
- final analytic/combinatorial assembly: `true_phi_monotone_lipschitz`,
  `scaled_true_phi_endpoint_gap`, the two clamp lemmas,
  `full_q768_abstract_assembly`, and `full_q768_abstract_target`.

Relative to the starting revision, `Q768AbstractModel.v` contains 1,091 added
and 6 removed lines (net +1,085). This count includes definitions, supporting
lemmas, comments, and the final theorem; it is not presented as a count of
tactic lines alone.

The recurrence-heavy proof was deliberately factored through the opaque
`full_q768_abstract_assembly` lemma. A monolithic proof discharged all goals
but caused Rocq 9.2 to spend more than two minutes in final dependent
conversion checking. Factoring preserves the same theorem and concrete model
connection while reducing `Q768AbstractModel.v`'s clean compile to about 4.8
seconds.

## `Print Assumptions`

The temporary command was:

```coq
Print Assumptions full_q768_abstract_target.
```

It produced the following output verbatim:

```text
Axioms:
ClassicalDedekindReals.sig_not_dec : forall P : Prop, {~ ~ P} + {~ P}
ClassicalDedekindReals.sig_forall_dec :
  forall P : nat -> Prop,
  (forall n : nat, {P n} + {~ P n}) ->
  {n : nat | ~ P n} + {forall n : nat, P n}
FunctionalExtensionality.functional_extensionality_dep :
  forall (A : Type) (B : A -> Type) (f g : forall x : A, B x),
  (forall x : A, f x = g x) -> f = g
Classical_Prop.classic : forall P : Prop, P \/ ~ P
```

These are recognizable Rocq real-analysis/classical foundations and
functional extensionality. No assumption originates in the MathComp
compatibility adjustment, the project, or an unproved local witness. The
temporary `Print Assumptions` line was removed after capture.

## Verification

Versions and dependency layout match the preceding Topic 25 passes:

- Rocq Prover 9.2.0, compiled with OCaml 5.5.0;
- Coquelicot 3.4.5;
- MathComp 1.19.0 ssreflect core with the previously documented Rocq-9.2
  proof-script compatibility adjustment.

From `audit_evidence/25_q768_gappa_rocq`, the checked command form was:

```sh
coqc \
  -Q /tmp/q768-assumptions/mathcomp-flat mathcomp \
  -R /tmp/q768-assumptions/coquelicot-3.4.5/theories Coquelicot \
  FILE.v
```

All five Rocq sources in the directory compiled cleanly in dependency order:

```text
Q768Primitives_generated.v   0.14 s
Q768Composition.v            0.60 s
Q768FiniteBounds.v          46.76 s
Q768AnalyticObligations.v    1.85 s
Q768AbstractModel.v          4.76 s
```

The required trust-marker command now has empty output:

```sh
grep -n 'Abort\|Admitted\|Axiom' *.v
```

`git diff --check` also succeeds. Build artifacts were removed after these
checks.

## Elapsed time

The recorded wall-clock interval for this pass was approximately **13 hours
18 minutes**, from 2026-08-31 20:02 IST to 2026-09-01 09:20 IST. That interval
includes the overnight task pause, iterative proof construction, failed
monolithic proof-shape experiments, final factorization, compilation, and
report preparation; it should not be interpreted as 13 hours 18 minutes of
continuous active editing.

## Scope boundary

With this closure, the Topic 25 abstract real-valued model is completely
kernel-checked relative to the assumptions printed above. This is the formal
milestone requested by this task.

It remains explicitly **not** an implementation-conformance result. The proof
does not show that Rust's dynamically allocated Q768 arithmetic implements
these recurrences bit-for-bit, does not make Kani's representation obstacle go
away, and does not establish R1 cross-platform bit-identical determinism. No
Rust production file was changed.
