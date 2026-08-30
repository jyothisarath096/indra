# Q768 Gappa/Rocq real-analysis library survey

Date: 2026-08-30

## 1. Scope and result

This addendum answers the library-availability question left open by
`GAPPA_ROCQ_RESULTS.md`. It does not complete any proof, change any existing
Rocq file, or establish correspondence between the abstract model and the
shipped Rust implementation.

The short result is:

- **Exponential/phi:** no one-call theorem exactly matches the production
  `phi_partial 128`/`phi_partial 129` statements. Coquelicot's
  `Taylor_Lagrange` is nevertheless a strong, finite-order starting point. It
  can be instantiated at exactly 128 and 129 and should yield the desired
  strict first-omitted-term errors for `0 < x < 7/10` after a moderate amount
  of derivative, indexing, and normalization work. Rocq Stdlib's alternating
  series theorems can establish the bracket, but do not directly deliver both
  strict, first-omitted-term bounds in the form currently stated.
- **Log/atanh:** neither surveyed library contains the needed
  `ln((1+y)/(1-y))` odd-power identity together with a specific 256-term
  geometric tail. Coquelicot contains the integration, differentiation, and
  finite-series components from which it can be proved, but the proof must be
  assembled in this project.
- **Blocking statement defect:** the current strict phi theorem is false at
  `x = 0`. Its two strict inequalities reduce to `0 < 0`. Therefore the three
  `Abort`s cannot literally be closed as written, irrespective of library
  support. A future proof-writing task first needs an approved statement repair.
- **Estimate:** for the intended, repaired theorem, the prior estimate moves
  **up from 1--3 to approximately 3--5 focused engineer-weeks** for an engineer
  already productive in Rocq real analysis. The two analytic obligations alone
  are approximately 1.5--2.5 weeks; the remaining time is the recurrence/model
  soundness work hidden by the third `Abort`, integration, and review. The
  estimate still excludes Rust/model conformance.

## 2. Survey basis and reproducibility

The installed prover is **Rocq 9.2.0**. The installed Stdlib source was surveyed
under `$COQLIB/user-contrib/Stdlib/Reals` and was byte-compared for the relevant
files against the official
[Stdlib `V9.2.0` tag](https://github.com/rocq-prover/stdlib/tree/V9.2.0/theories/Reals)
(tag commit `8dd155bc10529814202f8f4c643e5ae6c2c88fa6`). The four compared files
(`AltSeries.v`, `Ratan.v`, `Exp_prop.v`, and `PartSum.v`) matched their tagged
counterparts by SHA-256.

Coquelicot was not already installed. The survey used the complete source of
**Coquelicot 3.4.5**, which the official
[Rocq package page](https://rocq-prover.org/p/coq-coquelicot/3.4.5) listed as the
current release on the survey date. The official
[source archive](https://coquelicot.gitlabpages.inria.fr/releases/coquelicot-3.4.5.tar.gz)
was verified against its published SHA-512:

```text
6a94f674715175347ff9938f8ac0f6e865c0019e6b6317d292e4c9d7e30df7e
bd41dfe48205a61f66c0bde0da1702d9831161439189dbc8337524d51f05e1a99
```

The source survey searched both complete trees for `atanh`, `artanh`,
log/series combinations, alternating remainder names, and the relevant generic
series, Taylor, derivative, and integral interfaces. Absence findings below are
therefore version-specific: Rocq Stdlib 9.2.0 and Coquelicot 3.4.5.

## 3. Exact obligations being surveyed

`Q768AnalyticObligations.v:31-41` asks, for `0 < y <= 1/3`, for

\[
L_{256}(y) \le \log\!\left(\frac{1+y}{1-y}\right),\qquad
\log\!\left(\frac{1+y}{1-y}\right)-L_{256}(y)
\le \frac{2y^{513}}{513(1-y^2)},
\]

where

\[
L_{256}(y)=2\sum_{n=0}^{255}\frac{y^{2n+1}}{2n+1}.
\]

`Q768AnalyticObligations.v:44-56` asks, for `0 <= x < 7/10`, for

\[
P_{128}(x)\le 1-e^{-x}\le P_{129}(x),
\]

and

\[
(1-e^{-x})-P_{128}(x)<\frac{x^{129}}{129!},\qquad
P_{129}(x)-(1-e^{-x})<\frac{x^{130}}{130!},
\]

where

\[
P_m(x)=\sum_{k=1}^{m}(-1)^{k+1}\frac{x^k}{k!}.
\]

The target is thus not merely convergence of two infinite series. It needs
finite truncations at the exact production term counts, one-sided orientation,
and explicit remainder bounds strong enough to feed the existing Q768 integer
budgets.

### 3.1 The current phi statement is false at the included endpoint

At `x = 0`, `true_phi 0 = phi_partial 128 0 = phi_partial 129 0 = 0` and both
displayed right-hand sides are zero. The two strict goals become `0 < 0`.

The future proof task therefore needs a human-approved repair before attempting
to replace the `Abort`. Two mathematically faithful options are:

1. state the strict first-omitted-term claims only for `0 < x < 7/10`, and
   handle `x = 0` by exact equality in the end theorem; or
2. use non-strict `<=` first-omitted-term bounds on `0 <= x < 7/10`, then prove
   the actually required strict “error below one Q768 unit” result by splitting
   the `x = 0` case.

No source file was changed in this survey.

## 4. Coquelicot 3.4.5 findings

### 4.1 Exponential/phi candidates

#### `Coquelicot.Derive.Taylor_Lagrange`

```coq
Theorem Taylor_Lagrange :
  forall f n x y, x < y ->
  (forall t, x <= t <= y ->
     forall k, (k <= S n)%nat -> ex_derive_n f k t) ->
  exists zeta, x < zeta < y /\
    f y =
      sum_f_R0
        (fun m => (y-x)^m / INR (fact m) * Derive_n f m x) n
      + (y-x)^(S n) / INR (fact (S n)) *
        Derive_n f (S n) zeta.
```

**Applicability:** adaptable, but not direct. Apply it to
`f(t) = exp(-t)` on `[0,x]`, once with `n = 128` and once with `n = 129`.
For `x > 0`, the remainder is exactly an alternating sign times
`exp(-zeta) * x^(n+1)/(n+1)!`; `0 < zeta < x` gives
`0 < exp(-zeta) < 1`. This route supplies the desired strictness, unlike a
plain alternating-series bracket.

The proof still needs separate lemmas for:

- all iterated derivatives of `t |-> exp(-t)` and their signs;
- equality between the `sum_f_R0` Taylor polynomial and the project's
  `phi_partial`/`factorial_R` definitions;
- the 128/129 parity and sign normalization; and
- the repaired `x = 0` boundary case.

`Coquelicot.ElemFct.is_derive_n_exp` provides the narrower fact

```coq
Lemma is_derive_n_exp :
  forall n x, is_derive_n exp n x (exp x).
```

It helps discharge Taylor's derivative premises, but composition with negation
and the alternating sign formula still have to be proved.

#### `Coquelicot.ElemFct.is_exp_Reals` and `exp_Reals`

```coq
Lemma is_exp_Reals (x : R) :
  is_pseries (fun n => / INR (fact n)) x (exp x).

Lemma exp_Reals (x : R) :
  exp x = PSeries (fun n => / INR (fact n)) x.
```

**Applicability:** infinite-series identity only. These identify `exp` with its
power series but do not state a specific-N remainder or its sign. Building the
fixed 128/129 error from them would still require a finite-tail argument.
Taylor--Lagrange is the shorter Coquelicot route for this obligation.

#### `Coquelicot.ElemFct.exp_ge_taylor`

```coq
Lemma exp_ge_taylor (x : R) (n : nat) :
  0 <= x ->
  sum_f_R0 (fun k => x^k / INR (fact k)) n <= exp x.
```

**Applicability:** not directly useful for the alternating expansion of
`exp(-x)`. It is a one-sided result for nonnegative `x` and the all-positive
Taylor polynomial.

### 4.2 Log/atanh candidates

No theorem named for `atanh`/`artanh` exists in the surveyed source, and no
`ln` theorem states the odd-power expansion or a finite truncation error.
`Coquelicot.ElemFct.is_derive_ln` gives only the derivative:

```coq
Lemma is_derive_ln x :
  0 < x -> is_derive ln x (/ x)%R.
```

The following lemmas are useful construction pieces, not a directly applicable
solution.

#### `Coquelicot.Series.is_series_geom` / `Series_geom`

```coq
Lemma is_series_geom (q : R) :
  Rabs q < 1 -> is_series (fun n => q^n) (/ (1-q)).

Lemma Series_geom (q : R) :
  Rabs q < 1 -> Series (fun n => q^n) = / (1-q).
```

**Applicability:** general infinite geometric series only. These can establish
the derivative series for `2/(1-y^2)`, but do not identify its integral with
`ln((1+y)/(1-y))` or provide the exact tail after term 255.

#### `Coquelicot.ElemFct.is_RInt_pow`

```coq
Lemma is_RInt_pow :
  forall a b n,
  is_RInt (fun x => pow x n) a b
    (pow b (S n) / INR (S n) -
     pow a (S n) / INR (S n)).
```

#### `Coquelicot.RInt_analysis.is_RInt_derive`

```coq
Lemma is_RInt_derive (f df : R -> V) (a b : R) :
  (forall x, Rmin a b <= x <= Rmax a b ->
     is_derive f x (df x)) ->
  (forall x, Rmin a b <= x <= Rmax a b -> continuous df x) ->
  is_RInt df a b (minus (f b) (f a)).
```

#### `Coquelicot.RInt.is_RInt_le`

```coq
Lemma is_RInt_le (f g : R -> R) (a b If Ig : R) :
  a <= b ->
  is_RInt f a b If ->
  is_RInt g a b Ig ->
  (forall x, a < x < b -> f x <= g x) ->
  If <= Ig.
```

Together with `Coquelicot.RInt.is_RInt_ext`, `is_RInt_scal`, and
`is_RInt_plus`, these support a finite proof that avoids first formalizing an
infinite atanh series:

1. use a finite geometric identity to decompose
   \(2/(1-t^2)\) into the first 256 even powers plus
   \(2t^{512}/(1-t^2)\);
2. integrate from zero to `y` and use `is_RInt_pow` to obtain exactly the 256
   odd-power terms;
3. use `is_derive_ln`, the derivative combinators in `Coquelicot.Derive`, and
   `is_RInt_derive` to identify the left integral with
   `ln((1+y)/(1-y))`; and
4. use positivity and `is_RInt_le` to bound the remainder integrand by replacing
   `1-t^2` with `1-y^2`, yielding
   `2*y^513/(513*(1-y^2))`.

This route uses real shipped `256`/`513` parameters, but it is a project proof,
not an existing library lemma.

## 5. Rocq Stdlib 9.2.0 findings

### 5.1 Exponential/phi candidates

#### `Stdlib.Reals.AltSeries.alternated_series_ineq`

```coq
Theorem alternated_series_ineq :
  forall (Un : nat -> R) (l : R) (N : nat),
  Un_decreasing Un ->
  Un_cv Un 0 ->
  Un_cv (fun N => sum_f_R0 (tg_alt Un) N) l ->
  sum_f_R0 (tg_alt Un) (S (2*N)) <= l <=
  sum_f_R0 (tg_alt Un) (2*N).
```

**Applicability:** close to direct for the bracket, not for the complete current
goal. With `Un k = x^k/k!`, it can bracket `exp(-x)` between odd and even
partial sums after proving monotonicity, convergence to zero, and convergence
of the alternating sums to `exp(-x)`. It gives non-strict bracketing and no
explicit first-omitted-term inequality. Indexing must also be translated from
the exponential sum beginning at `k=0` to `phi_partial` beginning at `k=1`.

#### `Stdlib.Reals.Ratan.Alt_first_term_bound`

```coq
Lemma Alt_first_term_bound :
  forall f l N n,
  Un_decreasing f ->
  Un_cv f 0 ->
  Un_cv (sum_f_R0 (tg_alt f)) l ->
  (N <= n)%nat ->
  Rdist (sum_f_R0 (tg_alt f) n) l <= f N.
```

**Applicability:** generic finite error, but not a direct first-omitted-term
lemma. Instantiating it without a shifted-tail construction bounds the error by
an included term (`N <= n`), not by term `n+1`, and it is non-strict. The proof
of this generic lemma itself occupies about 100 source lines, illustrating the
amount of shift/parity machinery that a Stdlib-only adaptation would inherit.

#### `Stdlib.Reals.Exp_prop.E1_cvg`

```coq
Definition E1 (x : R) (N : nat) :=
  sum_f_R0 (fun k => / INR (fact k) * x^k) N.

Lemma E1_cvg : forall x : R, Un_cv (E1 x) (exp x).
```

**Applicability:** identifies the limit, but supplies neither a finite remainder
nor its sign. `Stdlib.Reals.Rpower` contains a concrete use of
`alternated_series_ineq` to bound `exp(-1)`; that example confirms the bracket
route but does not add a fixed-N remainder theorem.

### 5.2 Log/atanh candidates

The survey found no Stdlib `atanh`/`artanh` function theorem and no
`ln((1+y)/(1-y))` power-series identity or fixed truncation result.

`Stdlib.Reals.PartSum.tech3` states the exact finite geometric sum:

```coq
Lemma tech3 :
  forall (k : R) (N : nat),
  k <> 1 ->
  sum_f_R0 (fun i => k^i) N = (1-k^(S N))/(1-k).
```

**Applicability:** directly useful as an algebraic sublemma with `k = t^2` and
`N = 255`. It does not perform the integral or identify the logarithm. Stdlib
does not provide a Taylor--Lagrange theorem comparable to Coquelicot's in the
surveyed `Reals` tree.

The abstract constructive lemmas
`Stdlib.Reals.Abstract.ConstructiveSum.series_cv_remainder_maj` and
`series_cv_abs_remainder` are not shortcuts here: they use the constructive-real
API and already require either a remainder estimate or the sum of the absolute
tail. Adapting the current classical-`R` development to them would add plumbing
without supplying the missing log identity or specific tail.

## 6. What must be proved if the recommended library route is used

No direct theorem closes either existing analytic `Abort`. The expected custom
work is:

### 6.1 Phi obligation: approximately 6--9 supporting lemmas

- `factorial_R n = INR (fact n)`;
- normalization of `phi_partial n x` to the relevant Taylor polynomial;
- the iterated derivative formula for `exp(-t)`;
- the 128 and 129 sign/parity specializations;
- positivity and strict `< 1` for the Lagrange factor `exp(-zeta)` when
  `0 < zeta`;
- exact `x = 0` handling under the approved repaired statement; and
- final bracket/remainder assembly.

Expected size: roughly 150--300 proof lines and **2--4 focused engineer-days**.
Coquelicot's `Taylor_Lagrange` is the reason this estimate is measured in days
rather than requiring a new general alternating-remainder library.

### 6.2 Log obligation: approximately 8--14 supporting lemmas

- specialization and rearrangement of the finite geometric identity at 256
  terms;
- derivative of `ln((1+t)/(1-t))` on `[0,y]`;
- continuity/nonzero-denominator facts on `0 <= t <= y <= 1/3`;
- induction/linearity for integrating the finite sum;
- monomial integrals and exact normalization to `log_partial 256`;
- positivity of the residual integral;
- the denominator monotonicity and pointwise residual-integrand bound; and
- the final integral comparison and algebraic normalization to the stated
  `2*y^513/(513*(1-y^2))` expression.

Expected size: roughly 300--650 proof lines and **5--8 focused engineer-days**.
This is the main estimate increase: no surveyed lemma packages the identity and
specific finite tail.

### 6.3 Third `Abort`: recurrence/model soundness remains separate work

Even after importing the two analytic results, the `Abort` at
`Q768AbstractModel.v:101-114` does not follow automatically. It must connect the
finite integer interval recurrences to the real series, carry primitive
rounding soundness through `imul`/`idivi`, justify stake scaling and clamping,
and instantiate the already-checked finite budgets and abstract composition
lemmas.

Expected size: **6--10 focused engineer-days**, followed by **2--3 days** for
dependency cleanup, `rocqchk`, CI/reproducibility work, and review. This estimate
is necessarily less precise than the two analytic estimates because the
current file states the end theorem but contains no intermediate recurrence
invariants.

## 7. Revised estimate and recommendation

### 7.1 Literal current goals

There is no finite completion estimate for all three `Abort`s *without changing
their statements*: the phi obligation is false at `x = 0`. This is a logical
blocker, not a tactic or library limitation.

### 7.2 Intended goals after an approved boundary repair

For one engineer already experienced with Rocq's real-number tactics and
Coquelicot:

| Work item | Focused time |
|---|---:|
| Statement repair and library integration scaffold | 0.5--1 day |
| Exact 128/129 phi Taylor remainder | 2--4 days |
| Exact 256-term log identity and tail | 5--8 days |
| Abstract recurrence and end-theorem soundness | 6--10 days |
| Kernel/dependency checks, cleanup, review support | 2--3 days |
| **Total** | **15.5--26 days, approximately 3--5 engineer-weeks** |

This moves the original **1--3 engineer-week** estimate **up**. Coquelicot
reduces the exponential obligation materially, but it does not supply the
log/atanh theorem whose availability was the largest uncertainty in that
estimate. The false zero-endpoint statement and the still-unwritten recurrence
invariants add real work that should not be hidden inside a best-case range.

Recommended future proof route:

1. obtain a human decision on the phi boundary repair;
2. use **Coquelicot `Taylor_Lagrange`** for the exact 128/129 exponential
   remainder;
3. use the **finite geometric plus Coquelicot integration** route for the
   256-term log theorem, rather than developing an unnecessarily general
   infinite atanh-series library; and
4. keep the recurrence-soundness proof as a distinct milestone before attempting
   to replace the final `Abort`.

The estimate assumes no Rust code changes and no proof of implementation
conformance. Completing these abstract Rocq goals would still **not** establish
that the shipped Rust Q768 implementation matches this mathematical model.
