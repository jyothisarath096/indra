# Q768 phi obligation proof via Coquelicot `Taylor_Lagrange`

Date: 2026-08-30  
Repository revision at start: `80b3f6b37cf033e0198ff7849b793c5368d7f10a`

## Outcome

The phi/exponential-remainder obligation is now closed without `Admitted`, a
new `Axiom`, or a change to its approved post-repair statement. Rocq accepts
`phi_bracket_at_exactly_128_and_129_terms` for the exact production truncation
depths 128 and 129 and the exact domain `0 < x < 7/10`.

This closes exactly one of the three previously aborted goals. The remaining
trust-marker scan contains exactly:

```text
Q768AnalyticObligations.v:193:Abort.
Q768AbstractModel.v:129:Abort.
```

Those are, respectively, the 256-term log/atanh obligation and the abstract
end theorem. Neither was changed in this pass. There are zero occurrences of
`Admitted` or `Axiom` in the topic's `.v` files.

This result is a Rocq-kernel-checked theorem about the abstract real-valued
definitions in `Q768AnalyticObligations.v`, relative to Rocq Stdlib's real
number foundations and Coquelicot's checked `Taylor_Lagrange` theorem. It does
**not** establish that the shipped Rust Q768 implementation conforms to this
abstract model. That implementation-conformance question remains separate and
open, as documented in Topics 24 and 25.

## Proof route

The proof applies `Coquelicot.Derive.Taylor_Lagrange` to
`fun t => exp (-t)` over `[0,x]` twice:

- at `n = 128`, the 129th derivative has negative sign, so the Taylor
  polynomial for `exp(-x)` is above `exp(-x)` and `phi_partial 128 x` is below
  `1-exp(-x)`;
- at `n = 129`, the 130th derivative has positive sign, giving the opposite
  bracket and placing `phi_partial 129 x` above `1-exp(-x)`.

For each call, `Taylor_Lagrange` supplies a witness `zeta` with
`0 < zeta < x`. Therefore `0 < exp(-zeta) < 1`, making each absolute remainder
strictly smaller than its first omitted term. This is precisely the strictness
that the repaired theorem requires.

The proof actually needs only `0 < x`; the retained `x < 7/10` hypothesis is
part of the approved production-specific statement but is not needed for this
Taylor-Lagrange remainder argument. The theorem statement was not broadened.

## Supporting definitions and lemmas

The following material was added to
`Q768AnalyticObligations.v` before the target theorem:

1. `factorial_R_eq_INR_fact`

   ```coq
   forall n, factorial_R n = INR (fact n)
   ```

   This connects the project's recursive real factorial to Coquelicot's
   Taylor denominator.

2. `ex_derive_n_exp_all`

   ```coq
   forall n x, ex_derive_n exp n x
   ```

3. `is_derive_n_exp_neg`

   ```coq
   forall n x,
     is_derive_n (fun t => exp (-t)) n x ((-1)^n * exp (-x))
   ```

   This uses Coquelicot's `is_derive_n_exp` together with its existing
   `is_derive_n_comp_opp` composition lemma.

4. `Derive_n_exp_neg`

   ```coq
   forall n x,
     Derive_n (fun t => exp (-t)) n x = (-1)^n * exp (-x)
   ```

5. `alternating_sign_from_even`

   ```coq
   forall k a,
     (if Nat.even k then -a else a) = -(a * (-1)^k)
   ```

6. `phi_partial_as_taylor`

   ```coq
   forall n x, phi_partial n x = 1 - exp_neg_taylor n x
   ```

   Here `exp_neg_taylor n x` is the inclusive finite sum from `k=0` through
   `k=n` using the Stdlib factorial.

7. `exp_neg_taylor_lagrange`

   ```coq
   forall n x, 0 < x ->
     exists zeta, 0 < zeta < x /\
       exp (-x) = exp_neg_taylor n x +
         x^(S n) / INR (fact (S n)) *
         ((-1)^(S n) * exp (-zeta))
   ```

   This is the reusable exact finite-order Taylor-Lagrange specialization.

8. `exp_neg_between_zero_and_one`

   ```coq
   forall z, 0 < z -> 0 < exp (-z) < 1
   ```

9. `positive_lagrange_factor_is_strictly_smaller`

   ```coq
   forall n x z, 0 < x -> 0 < z ->
     0 < x^n / INR (fact n) * exp (-z) <
         x^n / INR (fact n)
   ```

The final theorem specializes the generic Lagrange lemma at exactly 128 and
129, normalizes the two parities (129 odd, 130 even), derives exact equations
for the two errors, and uses the strict factor lemma to establish both the
bracket and strict remainder bounds.

## Size and effort versus estimate

The formal addition occupies 179 source lines from the first bridge lemma
through the completed target proof (166 nonblank lines), including the helper
definition and nine supporting lemmas. This is within the library survey's
150--300-line estimate.

Elapsed wall-clock work in this environment was approximately 35 minutes,
including resolving and building a compatible local Coquelicot dependency
stack. That is materially below the earlier 2--4 focused engineer-day estimate.
The main reasons are that Coquelicot 3.4.5 already contains both
`is_derive_n_comp_opp` and the exact finite-order `Taylor_Lagrange` witness, and
the remaining normalization closes cleanly with Rocq's ring and nonlinear
arithmetic tactics. This outcome does not revise the separate estimates for the
log/atanh proof or the abstract recurrence/end theorem.

## Toolchain and reproduction

The successful run used:

- Rocq Prover 9.2.0, compiled with OCaml 5.5.0;
- Coquelicot 3.4.5 from the official source archive already pinned and hashed
  in `LIBRARY_SURVEY.md`;
- the MathComp 1.19.0 ssreflect core as Coquelicot's build dependency.

The host did not have Coquelicot installed globally. For this run it was built
under `/tmp/coquelicot-3.4.5`. MathComp 1.19.0 required the same one-token
Rocq-9.2 rewrite-pattern compatibility adjustment used by newer MathComp at
`ssreflect/seq.v:1375` (`rewrite (fun_if undup) [_ = _]fun_if`). This changes
proof-script elaboration, not a theorem statement or proof axiom; Rocq's kernel
checked the resulting dependency and proof objects. A normal package-managed
installation of a Rocq-9.2-compatible MathComp/Coquelicot stack does not need
the local `/tmp` layout.

With Coquelicot installed in Rocq's normal load path, reproduce from this
directory with:

```sh
cd audit_evidence/25_q768_gappa_rocq
coqc Q768AnalyticObligations.v
rg -n 'Abort|Admitted|Axiom' *.v
```

The exact isolated command used in this environment was:

```sh
coqc \
  -Q /tmp/mathcomp-flat mathcomp \
  -R /tmp/coquelicot-3.4.5/theories Coquelicot \
  Q768AnalyticObligations.v
```

No Gappa tactic or generated Gappa certificate is used for this obligation;
the proof is Rocq plus Coquelicot throughout.

## Scope caveat

The checked result is the mathematical statement

\[
P_{128}(x) \le 1-e^{-x} \le P_{129}(x),
\]

with both strict first-omitted-term error bounds for `0 < x < 7/10`. It does
not connect `phi_partial` to the production fixed-point recurrence, directed
rounding operations, `num-bigint`, or the Rust call paths. In particular, it
does not close `full_q768_abstract_target`, and it must not be described as a
formal verification of the shipped Rust implementation.

## `Print Assumptions` verification

The theorem was recompiled under the same isolated dependency stack documented
above (Rocq 9.2.0, Coquelicot 3.4.5, and the MathComp 1.19.0 ssreflect core),
with the following command temporarily placed after its `Qed`:

```coq
Print Assumptions phi_bracket_at_exactly_128_and_129_terms.
```

Rocq printed the following complete output verbatim:

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

All four names are recognizable foundations from Rocq's standard classical
real-analysis stack: two principles exposed by `ClassicalDedekindReals`,
dependent functional extensionality, and classical excluded middle. There is
no MathComp-namespaced assumption, no reference to the MathComp compatibility
patch, and no project-local or otherwise unrecognized axiom. The classical
principles in the closure are consistent with the foundations used by Rocq's
Reals library and Coquelicot; the Taylor-Lagrange witness introduces no
additional unexpected assumption.

The temporary `Print Assumptions` command was removed after capture. It is not
present in `Q768AnalyticObligations.v`.
