# INDRA Layer 2 Phase 7 — mainnet `f` calibration

Date: 2026-08-18  
Result: **RECOMMENDED RANGE**  
Production changes: **none**

```text
hard minimum:  f >= 0.36
preferred:     f  = 0.375 = 3/8
hard maximum:  f <= 0.40
```

The exact deployable integer values are specified in Section 9. This phase
recommends policy; it does not alter genesis or consensus validation.

## 1. Production timing and stochastic model

Eligibility remains:

```text
p_i = 1 - (1-f)^(w_i/W).
```

The proposer alpha binds chain, seed, height, round, snapshot root and validator
identity (`indra-core/src/types/proposal.rs:34-56`). Production evaluates the
full 512-bit output against the snapshot-certified threshold
(`indra-consensus/src/proposer.rs:24-153`; `indra-core/src/sortition.rs:150-180`).

Timeouts are 8 seconds propose, 3 seconds prevote and 3 seconds precommit
(`indra-node/src/bin/node.rs:57-59`). If no proposal is staged, propose timeout
emits a nil prevote, prevote timeout emits a nil precommit, and precommit timeout
advances the round (`indra-node/src/driver.rs:2237-2276`). Therefore:

```text
minimum absent-proposer round = 8 + 3 + 3 = 14 seconds
```

plus up to the loop's 100 ms polling granularity and processing overhead.

Proposal selection intentionally remains open until the eight-second propose
timeout so nodes can switch to a better priority. Under synchrony with one-way
vote propagation bound `Delta`, a normal successful round is modeled as:

```text
8 seconds + Delta(prevotes) + Delta(precommits) = 8 + 2*Delta.
```

This is an explicit operational model, not a protocol guarantee. Results include
`Delta` of 0.5, 1 and 2 seconds.

## 2. Acceptance criteria

No universal standard fixes an acceptable grinding TV distance. The selected
criteria are therefore explicit engineering/security policy:

| Metric | Acceptance limit | Operational/security rationale |
|---|---:|---|
| Expected rounds to an honest proposer near beta=1/3 | <=4 | Keeps expected proposer-stage latency near one minute even at the Byzantine boundary. |
| No honest proposer for 10 rounds | <=6% | Ten empty-proposer rounds consume at least 140 seconds; repeated multi-minute stalls should be uncommon. |
| No honest proposer for 20 rounds | <=0.5% | Twenty rounds consume at least 280 seconds; establishes a sub-percent long-tail SLO. |
| Multiple proposers, 200 equal validators | <=10% | Bounds worst-cap proposal contention to about one round in ten. |
| Byzantine-only proposer, beta=1/3 | <=12% | Bounds rounds in which the coalition alone owns publication choice. |
| Adaptive next-eligibility absolute bias | <=5 percentage points | Prevents the publish/withhold bit from adding a large absolute election probability. |
| Balanced-predicate TV lower bound | <=10% | Explicitly accepts bounded consensus-seed bias while forbidding use as application randomness. |
| Split coalition multiple outputs conditional on any, k=200 | <=9% | Bounds identity-splitting choice at the active-set cap. |

The TV and five-percentage-point limits are not cryptographic constants. They
are candidate acceptance policy. Stricter alternatives have consequences:

* Requiring TV <=5% gives **no candidate in the legal `f<=0.5` domain** at
  beta=1/3 under the Phase-6 strategy; protocol redesign would be required.
* Requiring absolute next-election bias <=4% caps `f` near 0.303 and conflicts
  with the four-round liveness target.
* The adopted TV <=10% and absolute bias <=5 pp recognize that the seed is only
  consensus sortition entropy, hybrid authorization remains independent, and
  applications are forbidden to consume it as unbiased randomness.

## 3. Liveness floor

With online honest stake fraction `h`, the probability of no honest proposer
for `r` rounds is:

```text
q_h^r = (1-f)^(h*r).
```

At the beta-to-one-third limit with no unrelated outage, `h -> 2/3`. The exact
candidate lower bounds are:

```text
E[rounds] <= 4:       f >= 1-(3/4)^(3/2)
                         = 0.3504809471616710149...

P(no honest,10)<=6%: f >= 1-0.06^(3/20)
                         = 0.3442735720044295961...

P(no honest,20)<=0.5%:
                     f >= 1-0.005^(3/40)
                         = 0.3279172475347835542...
```

The expected-round target is binding. The hard minimum is raised to **0.36**
rather than set at the mathematical boundary, leaving margin for quantization,
model error, and stake just below the one-third safety boundary.

At the hard minimum (`f≈0.36`, beta->1/3):

```text
expected rounds                 3.886
P(no honest for 5 rounds)      22.591%
P(no honest for 10 rounds)      5.103%
P(no honest for 20 rounds)      0.260%
expected time, Delta=1s        50.40s
```

## 4. Grinding and multiplicity ceiling

At beta=1/3, exact numerical roots of the candidate ceilings are:

| Constraint | Boundary `f` |
|---|---:|
| 200-validator multiple-proposer probability =10% | 0.413244130469609... |
| adaptive absolute bias =5 pp | 0.429471715926046... |
| split-200 conditional multiplicity =9% | 0.428766280919773... |
| Byzantine-only probability =12% | 0.443152332955893... |

The proposer-multiplicity ceiling binds first. The recommended hard maximum is
**0.40**, not 0.413244..., preserving approximately 0.69 percentage points of
contention margin and providing a simple auditable boundary.

At `f=0.40`, beta=1/3:

```text
P(multiple proposers), 200 equal       9.311%
P(only Byzantine proposer)            11.138%
adaptive absolute bias                 4.806 pp
adaptive relative advantage           30.693%
effective grinding advantage           0.386 bits
balanced-predicate TV lower bound       8.087%
split-200 P(multiple | coalition any)   8.233%
```

## 5. Sweep around the selected range

Worst grinding rows use beta=1/3; liveness assumes honest online stake tends to
2/3 from above.

| f | E honest rounds | Tail 10 | Tail 20 | Multi, n=200 | Only Byzantine | Abs bias | Relative | TV lower | Split-200 multi given any |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.30 | 4.725 | 9.275% | 0.860% | 5.010% | 8.837% | 3.970 pp | 35.420% | 8.637% | 5.799% |
| 0.33 | 4.268 | 6.926% | 0.480% | 6.141% | 9.568% | 4.249 pp | 33.998% | 8.478% | 6.495% |
| 0.35 | 4.006 | 5.659% | 0.320% | 6.969% | 10.037% | 4.421 pp | 33.052% | 8.369% | 6.975% |
| **0.36** | **3.886** | **5.103%** | **0.260%** | **7.406%** | **10.265%** | **4.503 pp** | **32.579%** | **8.314%** | **7.219%** |
| **0.375** | **3.718** | **4.357%** | **0.190%** | **8.090%** | **10.600%** | **4.622 pp** | **31.872%** | **8.230%** | **7.593%** |
| **0.40** | **3.465** | **3.319%** | **0.110%** | **9.311%** | **11.138%** | **4.806 pp** | **30.693%** | **8.087%** | **8.233%** |
| 0.41 | 3.372 | 2.967% | 0.088% | 9.829% | 11.345% | 4.874 pp | 30.223% | 8.029% | 8.496% |
| 0.42 | 3.284 | 2.648% | 0.070% | 10.363% | 11.548% | 4.940 pp | 29.752% | 7.970% | 8.763% |
| 0.50 | 2.702 | 0.977% | 0.010% | 15.283% | 12.996% | 5.283 pp | 26.007% | 7.365% | 11.057% |

The complete 22-value sweep, including every value required by the task, is in
`calibration_results.csv`.

## 6. Preferred value

The preferred value is **`f=3/8=0.375`**:

* It is exactly representable, avoiding policy-boundary rounding.
* Expected honest-proposer rounds near beta=1/3 are 3.718.
* Ten- and twenty-round absence tails are 4.357% and 0.190%.
* With `Delta=0.5/1/2s`, expected completion time is 47.05/48.05/50.05s.
* Worst-cap multi-proposer probability is 8.090%.
* Adaptive bias is 4.622 pp and the balanced-predicate TV lower bound is 8.230%.
* Split-200 conditional multiple-output probability is 7.593%.

This is not copied from another chain. It is the midpoint of the derived INDRA
operating envelope and has a simple exact binary rational representation.

## 7. Byzantine and unavailable stake combinations

`calibration_results.csv` evaluates beta=10%, 20%, and 1/3 against 0%, 10%,
and 20% unavailable honest stake separately and jointly. At preferred `f=0.375`:

| beta | Other unavailable stake | Online honest stake | E proposer rounds | Tail 10 | Tail 20 | QC possible without Byzantine votes? |
|---:|---:|---:|---:|---:|---:|---|
| 10% | 0% | 90% | 2.899 | 1.455% | 0.021% | yes |
| 10% | 10% | 80% | 3.191 | 2.328% | 0.054% | yes |
| 10% | 20% | 70% | 3.567 | 3.725% | 0.139% | yes |
| 20% | 0% | 80% | 3.191 | 2.328% | 0.054% | yes |
| 20% | 10% | 70% | 3.567 | 3.725% | 0.139% | yes |
| 20% | 20% | 60% | 4.070 | 5.960% | 0.355% | **no** |
| 1/3 | 0% | 2/3 | 3.718 | 4.357% | 0.190% | **no at exact boundary** |
| 1/3 | 10% | 56.67% | 4.277 | 6.971% | 0.486% | **no** |
| 1/3 | 20% | 46.67% | 5.077 | 11.154% | 1.244% | **no** |

This distinction is essential: `f` can improve proposer availability but cannot
repair BFT voting liveness when honest online voting stake is not strictly above
two-thirds. At exactly beta=1/3, Byzantine vote withholding prevents a strict
QC regardless of proposer election. The beta=1/3 calculations are limiting
security/grinding values, not a promise of QC liveness at the boundary.

## 8. Stake splitting

For beta=1/3 and `k=1,2,5,10,50,200`, total coalition eligibility remains:

```text
P(any) = 1-(1-f)^(1/3)
```

for every `k`. At preferred `f=0.375`, splitting raises
`P(multiple | any)` from 0% for one key toward 7.593% at 200 keys. At the hard
maximum it reaches 8.233%, below the selected 9% ceiling. The current 200-member
active-set cap bounds the lever; no additional identity-count rule is required
for this envelope, though increasing the cap requires recalibration.

## 9. Exact consensus integers

Consensus must never parse floating-point literals. Policy quantization is:

```text
ordinary selected f: nearest integer to f*2^64, half ties upward
hard minimum:        ceil(0.36*2^64)
hard maximum:        floor(0.40*2^64)
```

Exact values:

| Role | Requested f | Exact F | Effective rational f |
|---|---:|---:|---|
| Hard minimum | 0.36 | `6640827866535438582` | `3320413933267719291 / 9223372036854775808` |
| Preferred | 0.375 | `6917529027641081856` | exactly `3/8` |
| Hard maximum | 0.40 | `7378697629483820646` | `3689348814741910323 / 9223372036854775808` |

The inclusive mainnet configuration rule is therefore:

```text
6640827866535438582 <= F <= 7378697629483820646
```

with `6917529027641081856` recommended for genesis.

## 10. GR-01 and GR-02 disposition

```text
GR-01: ACCEPTED RESIDUAL
GR-02: CLOSABLE BY PARAMETER CONSTRAINT
```

GR-01 is accepted only within this envelope and under these restrictions:

1. election seed remains consensus-sortition entropy, never application or
   gambling randomness;
2. active validator count remains at most 200;
3. Byzantine stake remains strictly below one-third;
4. the documented publish/withhold model and its <=5 pp candidate acceptance
   limit remain part of mainnet review;
5. changing this envelope or validator cap requires recalibration.

A policy demanding balanced-predicate TV below 5%, or materially less than four
percentage points of absolute next-election bias, cannot be met together with
the stated liveness target by parameter tuning. Such a policy requires a unique
threshold randomness beacon or another protocol redesign.

GR-02 closes once mainnet genesis/configuration structurally rejects `F` outside
the exact integer envelope. No unsafe testnet compatibility path should remain.
The broad Q768 arithmetic helper domain may remain for mathematical tests, but
it must not define deployable consensus configuration.

## 11. Reproduction

```bash
python3 audit_evidence/14_f_calibration/calibration.py
```

The model uses 100-digit `Decimal` arithmetic, contains no Monte Carlo path, and
emits 3,916 deterministic rows.
