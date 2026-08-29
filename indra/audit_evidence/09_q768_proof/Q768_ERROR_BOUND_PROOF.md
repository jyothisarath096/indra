# Rigorous independent audit of the INDRA Q768 error bound

## Classification

**PROVED WITH EXPLICIT ASSUMPTIONS**

The production computation satisfies the stronger universal bounds

```text
phi_hi - phi_lo <= 1537 < 2^11 < 2^24             (Q768 integer units)
0 <= phi_true - phi_lo/S < 1281/S < 2^-757
```

and therefore satisfies the design's `<2^-744` lower-error claim and its
at-most-one 512-bit threshold-unit theorem. The assumptions are listed in
Section 12. This is an independently derived analytic proof plus an exact
finite-integer checker; it is not a claim of machine-checked theorem-prover
verification.

Audited production source: `indra-core/src/sortition.rs`, SHA-256
`5a305765d29a28b2e65f763b62c80d17e7cd90010058e12ac5635d1a0e5082ef`,
at repository revision `b6404ccacc508d92a022f50ad1af3da4d4e31a02`.

## 1. Model and notation

Let `S=2^768`. An integer endpoint `a` denotes the real number `a/S`.
For a nonnegative interval `A=[a_l,a_h]`, write `wd(A)=a_h-a_l` in integer
Q768 units. All divisions below have positive denominators.

The correspondence to production is exact:

- `ceil` is lines 15–21;
- interval multiplication `mul` is lines 36–49;
- positive-integer division `divi` is lines 50–56;
- the logarithm graph is lines 86–113;
- the alternating polynomial graph is lines 114–148;
- stake scaling, clamping, certificate enforcement, and threshold extraction
  are lines 150–182.

## 2. Primitive interval lemmas

### Lemma 2.1: floor and ceiling

For real `r`, `floor(r)<=r<=ceil(r)`, `r-floor(r)<1`, and
`ceil(r)-r<1` unless `r` is integral, when both errors are zero. These facts
also hold at zero; production's explicit zero branch implements `ceil(0/d)=0`.

### Lemma 2.2: multiplication

For nonnegative `A=[a_l,a_h]` and `B=[b_l,b_h]`, production returns

```text
[ floor(a_l*b_l/S), ceil(a_h*b_h/S) ].
```

Monotonicity of multiplication on nonnegative reals proves enclosure. Moreover,

```text
a_h*b_h-a_l*b_l
 = b_h*(a_h-a_l)+a_l*(b_h-b_l)
 <= b_h*wd(A)+a_h*wd(B).
```

Applying the two strict rounding errors gives

```text
wd(mul(A,B))
 < b_h*wd(A)/S + a_h*wd(B)/S + 2.
```

Thus the design's non-strict `...+2` real inequality is valid (and loose).
The checker uses the conservative integer consequence
`ceil((b_h*wd(A)+a_h*wd(B))/S)+1`. No positivity stronger than
nonnegativity is used, so zero lower endpoints are covered.

### Lemma 2.3: division

Production only implements division of an interval by a positive integer `d`:

```text
[floor(a_l/d), ceil(a_h/d)]
```

and hence `wd < wd(A)/d+2`; the checker uses `ceil(wd(A)/d)+1`.

For the more general design-document lemma, interval division encoded at scale
`S` would have width bounded by

```text
S*wd(A)/b_l + S*a_h*wd(B)/b_l^2 + 2,
```

because `a_h/b_l-a_l/b_h = wd(A)/b_l +
a_l*wd(B)/(b_l*b_h)` and `a_l<=a_h`, `b_h>=b_l>0`.
This is exactly the stated inequality. The general operator is not called by
the audited Rust implementation.

### Lemma 2.4: linear operations and clamping

Minkowski interval addition adds widths exactly. Multiplication by a
nonnegative integer scales both endpoints and the width exactly; the logarithm
final `<<1` therefore doubles its accumulated width. For an alternating sum,
choosing lower endpoints for positive terms and upper endpoints for negative
terms is a lower enclosure; reversing the choices is an upper enclosure. The
gap from either exact polynomial endpoint is at most the sum of the individual
term widths.

The maps `max(0,x)` and `min(S,x)` are monotone and 1-Lipschitz. Applied to an
already ordered enclosing interval they preserve enclosure and cannot increase
width. This covers both the negative-sum guard in `phi` and the two `.min(S)`
calls.

## 3. Complete real domain

`1<=F<=2^63` and `f=F/2^64` give `0<f<=1/2` exactly. Since
`y=f/(2-f)`, its denominator is positive and the function has derivative
`2/(2-f)^2>0`; therefore

```text
0<y<= (1/2)/(3/2)=1/3.
```

For `1<=w<=W`, put `alpha=w/W`, so `0<alpha<=1`. Since `-ln(1-f)`
is increasing on this domain,

```text
0<z=alpha[-ln(1-f)]<=-ln(1/2)=ln(2).
```

Finally `ln(2)<7/10<1` without decimals: the first four positive terms of
`exp(7/10)` sum to `12013/6000>2`, hence `exp(7/10)>2` and monotonicity of
`ln` gives `ln(2)<7/10`.

## 4. Logarithm interval

### 4.1 Exact identity and analytic tail

For `0<y<=1/3`, the geometric series gives

```text
2*atanh(y)=2*sum(n>=0, y^(2n+1)/(2n+1)).
```

After terms `n=0..255`,

```text
R = 2*sum(n>=256, y^(2n+1)/(2n+1))
  <= 2/513 * sum(n>=256, y^(2n+1))
  = 2*y^513/[513*(1-y^2)].
```

All terms are positive, so `R>0`. This proves precisely the production tail
shape at lines 106–111. `y513.hi` encloses `S*y^513`, `y2.hi` encloses
`S*y^2`, and the function is increasing in both positive arguments while
`y2.hi<S`; consequently production's ceiling is a valid scaled upper bound.

### 4.2 Rounding-width recurrence

Initial conversion at lines 89–94 encloses `y` with width at most one. The
universal endpoint `y<=1/3` gives `y_hi<=ceil(S/3)=(S+2)/3` because
`S mod 3=1`. Apply Lemmas 2.2 and 2.3 exactly along:

```text
y2 = mul(y,y)
p=y
for n=0..255:
    t=divi(p,2*n+1)
    if n!=255: p=mul(p,y2)
y513=mul(p,y2)
```

The exact checker obtains:

```text
sum of 256 term-width bounds = 512
scaled analytic-tail ceiling = 1
wd(L) <= 2*512+1 = 1025.
```

The loop exponent is correct: before iteration `n`, `p` encloses
`y^(2n+1)`; after `n=255` it encloses `y^511`, and the final multiplication
encloses `y^513`. The checker also proves `10*L_hi<7*S`, so every later
production `z_hi` is strictly below `7/10`, not merely below one.

## 5. Stake scaling

Lines 163–164 compute

```text
z_l=floor(L_l*w/W),  z_h=ceil(L_h*w/W).
```

Write `lambda=S[-ln(1-f)]` for the exact scaled logarithm and
`z_true=lambda*w/W` for the exact scaled exponent. The certified logarithm
enclosure is

```text
0 <= L_l <= lambda <= L_h.
```

Multiplication by the positive rational `w/W` preserves order, so

```text
L_l*w/W <= z_true <= L_h*w/W.
```

For every real `a`, `floor(a)<=a<=ceil(a)`. Consequently,

```text
z_l=floor(L_l*w/W) <= z_true <= ceil(L_h*w/W)=z_h.       (5.1)
```

The missing integer endpoint lemma is:

> For integers `L_h>=0` and `1<=w<=W`,
> `ceil(L_h*w/W)<=L_h`.

Indeed, `L_h*w<=L_h*W`; division by positive `W` gives
`L_h*w/W<=L_h`. Since `L_h` is itself an integer, monotonicity of ceiling
gives `ceil(L_h*w/W)<=ceil(L_h)=L_h`. This proof includes `L_h=0` and both
stake endpoints. Combining it with (5.1) and Section 4's strict logarithm
bound yields the complete scaled chain

```text
0 <= z_l <= z_true <= z_h <= L_h < 7*S/10.               (5.2)
```

There is no hidden fractional representation in the recurrence: `z_l` and
`z_h` are integer results of integer floor/ceiling division. Each is therefore
a **point Q768 integer**, representing exactly `z_l/S` or `z_h/S`. Production
passes each endpoint separately to `phi`, which initializes `I { lo: z,
hi: z }`; its input interval width is exactly zero. The uncertainty of the
true `z` is solely the distance between these two distinct point inputs. It is
not an initial arithmetic width inside either polynomial evaluation.

For completeness, put `A=L_h*w/W` and `B=L_l*w/W`. Then
`ceil(A)-floor(B)<A-B+2`; because the left side is an integer,

```text
wd(z) <= ceil(w*wd(L)/W)+1 <= wd(L)+1 <=1026.
```

At `w=W`, both divisions are exact and the sharper bound is 1025. At `w=1`
and `W=2^64-1`, the same derivation remains valid: the only denominator fact
used is `W>0`, and no reciprocal approximation occurs.

## 6. Exponential / phi interval

### 6.1 Alternating-series validity

For every production endpoint `0<=x<7/10`, terms
`a_k=x^k/k!` are nonnegative and

```text
a_(k+1)/a_k=x/(k+1)<1.
```

They decrease to zero. Therefore the even 128-term partial sum of
`1-exp(-x)` is below the function, the odd 129-term partial sum is above it,
and their errors are strictly below `x^129/129!` and `x^130/130!`,
respectively. Exact arithmetic in the checker establishes

```text
S*(7/10)^129/129! < 1
S*(7/10)^130/130! < 1.
```

Thus each omitted tail is strictly below one Q768 integer unit.

### 6.2 Term recurrence and rounding

Lines 115–123 initialize `t=x` exactly and, for `k>1`, execute

```text
t = divi(mul(t,x),k).
```

By induction this encloses `S*(x/S)^k/k!`. For each call, `x` is one of the
point Q768 integers established in Section 5, so the recurrence begins with
`term=[x,x]` and input width zero. Here `x<=L_h<7S/10`. Applying the primitive
recurrences gives exact conservative sums of arithmetic-rounding widths:

```text
terms 1..128: 254
terms 1..129: 256.
```

These are two separate point-evaluation results: `254` bounds arithmetic
rounding while evaluating the 128-term polynomial at the single integer
`z_l`; `256` bounds arithmetic rounding while evaluating the 129-term
polynomial at the single integer `z_h`. Neither number contains the
`z_true in [z_l,z_h]` uncertainty.

The sign choices at lines 125–140 are exactly the required lower choices for
the even partial sum and upper choices for the odd partial sum.

### 6.3 Combined phi width

Let `g(x)=S*(1-exp(-x/S))`, let `P_128(x)` and `P_129(x)` be the exact scaled
even and odd partial sums, and let `PL` and `PH` be the respective production
lower and upper polynomial endpoints before the final `min(S)` clamp. The
point-evaluation and alternating-series results give

```text
0 <= P_128(z_l)-PL       <= 254          lower arithmetic rounding
0 <= g(z_l)-P_128(z_l)   <  1            lower alternating remainder
0 <= P_129(z_h)-g(z_h)   <  1            upper alternating remainder
0 <= PH-P_129(z_h)       <= 256          upper arithmetic rounding.
```

Moreover `g'(x)=exp(-x/S)<=1` in scaled coordinates. By (5.1), monotonicity,
and the mean-value theorem,

```text
0 <= g(z_h)-g(z_l) <= z_h-z_l <= 1026.  (6.1)
```

Thus the requested explicit chain is the exact telescoping identity followed
by the bound on every transition:

```text
PH-PL
 = [PH-P_129(z_h)]                       <= 256
 + [P_129(z_h)-g(z_h)]                   <  1
 + [g(z_h)-g(z_l)]                       <= 1026
 + [g(z_l)-P_128(z_l)]                   <  1
 + [P_128(z_l)-PL]                       <= 254
 < 1538.
```

The internal `max(0)` cannot worsen the lower enclosure/error (it can only
raise a negative rounded lower endpoint toward the nonnegative exact sum),
and the certified upper endpoint is already nonnegative. The final monotone
`min(S)` clamp cannot enlarge interval width or exclude `g`, which lies below
`S`. Hence the returned endpoints obey the same bound. Since their width is
an integer,

```text
phi_hi-phi_lo <=1537<2^11<2^24.
```

Clamping cannot enlarge this result by Lemma 2.4. This proves the runtime
certificate universally; it does not rely on observing the runtime check.

## 7. Lower error and the 512-bit threshold theorem

Because (5.1) places `z_true` between the point endpoints, the analogous
explicit lower-side chain is

```text
g(z_true)-PL
 = [g(z_true)-g(z_l)]                    <= z_true-z_l
 + [g(z_l)-P_128(z_l)]                   <  1
 + [P_128(z_l)-PL]                       <= 254
 <= 1026 + (<1) + 254
 < 1281.
```

Every term is nonnegative: `g` is monotone, the 128-term sum is the lower
alternating partial sum, and `PL` is its outward-rounded lower evaluation.
The same `max(0)`/`min(S)` argument can only reduce this lower-side error.
Therefore

```text
0 <= phi_true-phi_lo/S < (1026+1+254)/S
                             =1281/2^768
                             <2^11/2^768
                             =2^-757 <2^-744.
```

Let `A=2^512*phi_true` and `P=phi_lo/2^256`. Then `0<=A-P<2^-245`
(the design's looser bound is `2^-232`). Since two nonnegative reals less than
one apart have floors differing by at most one,

```text
floor(A)-floor(P) is 0 or 1.
```

Production line 177 computes `floor(P)` by a 256-bit right shift. It can never
exceed the ideal threshold.

## 8. Integer-width guards

All interval endpoints used by multiplication are below `S`; the checker
proves this explicitly for the largest logarithm endpoint, and phi terms only
decrease. Thus a raw product is below `S^2`, whose bit length is at most 1537,
strictly below the 2048-bit scratch guard. Rounded endpoints have at most 769
bits, below the 1024-bit endpoint guard. These arguments include `F=2^63`,
`w=W`, `F=1`, and `W=2^64-1`.

## 9. Exact checker

`check_bound.py` uses Python arbitrary-precision integers only. It reconstructs
the derived endpoint/width recurrences, checks representative exact instances
of the stake-endpoint inequalities, checks the two factorial inequalities,
proves `L_hi<7S/10`, and asserts the final constants 1025, 1537, and 1281.
The checker labels its stake instances as supporting checks: the universal
stake-endpoint result is the algebraic proof in Section 5, not finite testing.
It neither imports production code nor performs a numerical parameter sweep.

Run:

```sh
python3 audit_evidence/09_q768_proof/check_bound.py
```

## 10. Adversarial proof review

| Attack on lemma | Result |
|---|---|
| Denominator `2S-fq` at `F=2^63` | At least `3S/2>0`; yields `y<=1/3`. |
| Tail denominator `S-y2_hi` | Exact checker proves `y2_hi<S`. |
| Zero lower endpoints | Primitive proofs require only nonnegativity; zero is explicitly covered. |
| Stake ceiling endpoint | `L_h*w<=L_h*W` implies `ceil(L_h*w/W)<=L_h`; no approximation or strict-positivity assumption on `L_h`. |
| Scaled true-z enclosure | Order is preserved by positive `w/W`, then exact floor/ceiling inequalities give (5.1). |
| Multiplication off-by-one | Used strict two-rounding-error bound and a more conservative exact integer recurrence. |
| Division off-by-one | Included `+1` after ceiling the propagated width, including point intervals not divisible by `d`. |
| Recurrence initialization | `t=x`; multiplication starts only at `k=2`, matching lines 119–124. |
| Polynomial input width | Each call receives one computed integer endpoint as `[z,z]`; logarithm/stake uncertainty is represented only by the separation of the two calls. |
| Log loop count | Exactly 256 iterations, `n=0..255`. |
| Omitted-tail exponent | Last included log power is 511; first omitted is 513. Lower phi omits 129; upper excess begins at 130. |
| Sign choices | Odd positive/even negative; lower selects odd lows/even highs, upper the reverse. |
| `F=2^63` | Supplies the monotone maximum `y=1/3`; all endpoint bounds use it. |
| `F=1` | Positivity holds; absolute rounding bounds do not divide by `F` or `y`. |
| `w=W` | Scaling is exact and is narrower than the universal `+1` bound. |
| `W=2^64-1` | Only positive exact integer division is used; no overflow-width assumption enters the proof. |
| Clamping | Monotone 1-Lipschitz; cannot widen an ordered enclosure. |
| Integer guards | Maximum raw multiplication is below `S^2`; guard margins are proved in Section 8. |

No counterexample was found in this falsification pass.

## 11. Implementation correspondence verdict

The implementation uses the proved operation order, loop counts, exponents,
signs, and tail denominator. No proof step describes an unimplemented or
reordered algorithm. The specification's intermediate claims `<2^20` for the
log and `<2^22` for phi are confirmed with much stronger bounds (`1025` and
`1537` respectively).

## 12. Explicit assumptions and residual status

1. Standard mathematical facts about ordered integers/reals, monotonicity of
   multiplication/division on nonnegative operands, and the analytic power
   series for `atanh` and `exp` are assumed.
2. `num_bigint::BigUint` and `BigInt` implement exact integer arithmetic and
   Rust's loop ranges execute according to their language semantics.
3. This artifact is independently reviewable but is not encoded in
   Lean/Coq/Isabelle. For that reason the classification is **PROVED WITH
   EXPLICIT ASSUMPTIONS**, not an assertion that the separate mainnet
   machine-checked-proof gate has been fulfilled.

No unresolved analytic step remains under these assumptions.
