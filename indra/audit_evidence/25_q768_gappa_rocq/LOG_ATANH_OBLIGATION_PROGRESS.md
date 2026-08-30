# Q768 log/atanh obligation: feasibility and completed proof

Date: 2026-08-30  
Repository revision at start: `4891d8f0043eddbbe2db41ccf0a5e4d8ccca2419`

## Outcome

The exact 256-term log/atanh obligation is now closed with `Qed`. The proof
uses the same finite polynomial and geometric-tail expression as
`certified_log`; it does not replace the shipped algorithm with a direct Taylor
series in `f` or another easier model.

The checked theorem remains exactly:

```coq
Theorem log_tail_after_exactly_256_terms :
  forall y : R,
    0 < y <= 1 / 3 ->
    log_partial 256%nat y <= true_log_from_y y /\
    true_log_from_y y - log_partial 256%nat y
      <= 2 * y ^ 513 / (513 * (1 - y ^ 2)).
```

No `Admitted` or new `Axiom` was introduced. The only remaining `Abort` in the
topic's Rocq sources is `Q768AbstractModel.v`'s end theorem. The already-closed
phi theorem was not edited, and no Rust source was changed.

As with the phi result, this is a Rocq-kernel-checked theorem about the abstract
real-valued model. It does **not** establish that the Rust fixed-point
implementation conforms to the model, and it does not close
`full_q768_abstract_target`.

## Step 0: Taylor--Lagrange feasibility

### Directly on the atanh-form logarithm

For

\[
g(y)=\log\!\left(\frac{1+y}{1-y}\right),
\]

Taylor--Lagrange at order 512 would recover the correct odd polynomial through
degree 511, but its remainder has the form

\[
\frac{y^{513}}{513}
\left(\frac{1}{(1-\zeta)^{513}}+
      \frac{1}{(1+\zeta)^{513}}\right),
\qquad 0<\zeta<y.
\]

The library theorem gives no additional control over `zeta`. Bounding this
witness over the whole interval produces a factor involving
`(1-y)^(-513)`, which is far looser than the required geometric-tail factor

\[
\frac{2}{1-y^2}.
\]

Therefore the same `Taylor_Lagrange` route that closed phi does not cleanly
imply this obligation's exact tail constant.

### Directly on `-ln(1-f)`

The derivatives are indeed simple:

\[
\frac{d^n}{df^n}[-\ln(1-f)]=\frac{(n-1)!}{(1-f)^n}.
\]

However, Taylor expansion in `f` produces powers of `f`, while production
computes the odd-power polynomial in

\[
y=\frac{f}{2-f}.
\]

That route neither normalizes to `log_partial 256 y` term-by-term nor supplies
the shipped geometric tail. Using it would require a second substantial proof
relating a different finite polynomial and remainder to the actual recurrence,
so it is not a clean or faithful closure route.

### Substitution identity

Taylor--Lagrange could prove the substitution identity indirectly by showing
two differentiable functions have the same derivative and value at zero, but
that is unnecessary. The identity is algebraic:

\[
1-\frac{2y}{1+y}=\frac{1-y}{1+y},
\]

or, in production's direction,

\[
\log\!\left(
  \frac{1+f/(2-f)}{1-f/(2-f)}
\right)=-\ln(1-f).
\]

This pass closed that bridge directly as:

```coq
Lemma log_y_substitution_identity :
  forall f : R,
    0 <= f < 1 ->
    true_log_from_y (f / (2 - f)) = - ln (1 - f).
```

It uses exact field algebra and Stdlib's `ln_Rinv`; no series theorem is
needed. The integer-to-real proof that production's `F <= 2^63` implies
`f <= 1/2`, hence `0 < y <= 1/3`, remains part of the separate abstract end
theorem rather than this analytic lemma.

## Available primitives versus project-specific work

The library survey's absence result was confirmed: neither Coquelicot 3.4.5 nor
Rocq Stdlib 9.2.0 has a direct theorem for this exact finite atanh truncation
and its `513 * (1-y^2)` tail.

Coquelicot does provide the following relevant primitives:

| Primitive | Module | Status in this proof |
|---|---|---|
| `Taylor_Lagrange` | `Coquelicot.Derive` | Assessed, not used: its witness bound is too loose here. |
| `is_series_geom`, `Series_geom` | `Coquelicot.Series` | Available for an infinite-series route, but not needed. |
| `is_RInt_pow` | `Coquelicot.ElemFct` | Available for termwise finite integration, but not needed. |
| `is_derive_ln` | `Coquelicot.ElemFct` | Used to differentiate the true logarithm. |
| `is_derive_pow`, `is_derive_plus`, `is_derive_minus`, `is_derive_div`, `is_derive_comp` | `Coquelicot.Derive` | Used for the exact finite polynomial and comparison functions. |
| `MVT_gen` | `Coquelicot.Derive` | Used twice to convert nonnegative derivatives into the two required bounds. |
| `ln_Rinv` | Rocq Stdlib `Reals` | Used for the production substitution identity. |

The project-specific pieces that had to be built are:

1. the exact finite even-power sum
   `even_geom_partial terms x = sum_(n < terms) x^(2n)`;
2. its finite geometric identity
   `(1-x^2) * even_geom_partial N x = 1-x^(2N)`;
3. derivative normalization for the recursive `log_partial` definition;
4. the derivative of `true_log_from_y`, namely `2/(1-x^2)`;
5. the exact remainder derivative
   `2*x^(2N)/(1-x^2)`;
6. the exact project tail function and the derivative of its gap over the true
   remainder; and
7. nonnegativity and mean-value arguments on `[0,y]`.

This finite-geometric route is equivalent to the intended power-series
argument but avoids introducing an infinite sum merely to eliminate it again.
It proves facts about the exact `N`-term polynomial computed by the model, then
specializes `N = 256`.

## Formal proof structure

The main checked chain in `Q768AnalyticObligations.v` is:

- `even_geom_partial_finite_identity` establishes the finite geometric sum;
- `is_derive_log_series_term` and `is_derive_log_partial` differentiate the
  exact recursive polynomial;
- `is_derive_true_log_from_y` establishes
  `true_log_from_y'(x) = 2/(1-x^2)` on `-1 < x < 1`;
- `is_derive_log_remainder` combines those results to obtain

  \[
  R_N'(x)=\frac{2x^{2N}}{1-x^2};
  \]

- `is_derive_log_tail_bound` proves that the derivative of

  \[
  B_N(x)=\frac{2x^{2N+1}}{(2N+1)(1-x^2)}
  \]

  is `R_N'(x)` plus the nonnegative quantity

  \[
  \frac{4x^{2N+2}}{(2N+1)(1-x^2)^2};
  \]

- `log_remainder_nonnegative` applies `MVT_gen` to `R_N`, using `R_N(0)=0`;
- `log_tail_gap_nonnegative` applies `MVT_gen` to `B_N-R_N`, also zero at
  the origin; and
- `log_tail_after_exactly_256_terms` instantiates `N=256`, normalizes
  `2N+1=513`, and assembles both required inequalities.

The generic comparison proof only needs `0 <= y < 1`. The theorem retains the
production-specific, stronger domain `0 < y <= 1/3` unchanged.

## Effort and remaining work

The obligation closed in this pass, so there is no remaining estimate for the
log/atanh theorem itself. The earlier 5--8 focused engineer-day estimate was
conservative because it assumed an infinite-series differentiation and
integration development. The finite geometric identity plus mean-value
comparison avoided that library-integration layer while preserving the exact
production polynomial and bound.

This does not revise the estimate for `full_q768_abstract_target`: that theorem
still needs recurrence soundness, fixed-point rounding composition, the
integer/real domain bridge (including `F -> f -> y`), clamping, and final width
assembly. Rust/model conformance remains separately blocked as previously
documented.

## Reproduction and trust-marker result

The successful environment was the same as the phi proof:

- Rocq Prover 9.2.0, compiled with OCaml 5.5.0;
- Coquelicot 3.4.5;
- MathComp 1.19.0's ssreflect core with the previously documented Rocq-9.2
  proof-script compatibility adjustment.

With those dependencies on the normal Rocq load path:

```sh
cd audit_evidence/25_q768_gappa_rocq
coqc Q768AnalyticObligations.v
rg -n 'Abort|Admitted|Axiom' *.v
```

The exact isolated compile command used in this environment was:

```sh
coqc \
  -Q /tmp/q768-assumptions/mathcomp-flat mathcomp \
  -R /tmp/q768-assumptions/coquelicot-3.4.5/theories Coquelicot \
  Q768AnalyticObligations.v
```

Expected trust-marker output after this pass:

```text
Q768AbstractModel.v:129:Abort.
```

That is exactly one `Abort`, with zero `Admitted` and zero `Axiom` occurrences
across the topic's `.v` files.
