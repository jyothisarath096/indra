# INDRA Layer 2 Phase 6 — grinding resistance and liveness

Date: 2026-08-18  
Classification: **FINDING**  
Production changes: **none**

## Executive result

The Praos split/merge identity is correct: in the ideal model, the probability
of at least one eligible validator is exactly `f`, independently of stake
distribution and identity splitting. VRF-007 remains closed: one stable value
now commits exactly one `ProposalEntropyV1`.

Two quantitative findings trigger review before parameter activation:

| ID | Class | Result |
|---|---|---|
| L2-GR-01 | FINDING | The already-documented whole-proposal withholding bit produces material adaptive seed bias at the repository example `f=0.5`: a 33% coalition raises next-height round-0 coalition eligibility from **20.446% to 25.701%** (+5.255 percentage points, +25.701% relative). A balanced seed predicate has a **7.373% total-variation lower bound** under the same conservative strategy. |
| L2-GR-02 | FINDING | The consensus-legal domain includes `F=1`, or `f=2^-64`. With all stake online, expected progress is `1/f = 2^64` rounds—about 4.68 trillion years at the eight-second propose timeout. Validation enforces the arithmetic domain, not an operational liveness floor. |

L2-GR-01 is not a newly discovered substitution mechanism: the design already
names proposer publish/withhold as residual risk and forbids using the election
seed as general application randomness. This audit establishes that its size is
material at the checked-in example parameter and supplies the missing
quantitative acceptance question. No remediation is attempted.

## Evidence categories

* **Mathematical result:** analytic formulas evaluated with Python `Decimal` at
  100 significant decimal digits; no Monte Carlo estimates are used.
* **Protocol assumption:** RFC 9381 outputs are unique/pseudorandom and distinct
  key/transcript outputs are computationally independent.
* **Operational assumption:** an honest online eligible proposer reaches quorum
  within its round; the proposer timeout is eight seconds.
* **External-data requirement:** current Bitcoin hashpower, rentable capacity,
  attack cost, rewards, and ceremony value are intentionally not invented.

The executable model is `model.py`, inputs are in `assumptions.json`, all 844
analytic outputs are in `results.csv`, and the smallest material adaptive case
is preserved in `GRINDING_REPRODUCER.json`.

## 1. Exact production election model — PASS

For validator weight `w_i`, total snapshot weight `W`, and `f=F/2^64`, the
ideal eligibility threshold is:

```text
p_i = 1 - (1-f)^(w_i/W).
```

Production accepts `1 <= F <= 2^63` and `0 < w <= W`
(`indra-core/src/sortition.rs:75-83,150-180`). It evaluates all 512 output bits
against a conservative Q768 threshold. `ProposerElection` derives candidates,
weights, root and the certified logarithm from the validated governing snapshot
(`indra-consensus/src/proposer.rs:24-91`) and computes one RFC proof for the
candidate's chain/seed/height/round/snapshot/identity-bound alpha
(`proposer.rs:93-153`; `indra-core/src/types/proposal.rs:34-56`).

Assuming independent validator keys and RFC pseudorandomness, eligibility
indicators are independent Bernoulli variables for a fixed round. Distinct
rounds change alpha and are modeled as independent pseudorandom samples. This
is computational independence, not information-theoretic independence.

For a partition of all stake:

```text
P(no proposer) = product_i (1-p_i)
               = product_i (1-f)^(w_i/W)
               = 1-f.
```

Thus `P(at least one)=f` exactly in the ideal model. The production finite-grid
threshold can withhold at most one of `2^512` outputs per identity under the
separately audited Q768 bound; at 200 identities this is below `200/2^512`.

## 2. Proposer-count distribution — PASS, parameter selection OPEN

The count is Poisson-binomial, with:

```text
E[N]   = sum p_i
Var[N] = sum p_i(1-p_i).
```

At the repository example `F=2^63`, hence `f=0.5`
(`genesis.toml.example:24`):

| Stake shape | P(0) | P(1) | P(>=2) | E[N] | Variance |
|---|---:|---:|---:|---:|---:|
| one validator | 50.000% | 50.000% | 0% | 0.5000 | 0.2500 |
| four equal (deployment-manifest shape) | 50.000% | 37.841% | 12.159% | 0.6364 | 0.5352 |
| ten equal | 50.000% | 35.887% | 14.113% | 0.6697 | 0.6248 |
| 200 equal | 50.000% | 34.717% | 15.283% | 0.6919 | 0.6896 |
| moderate 20 | 50.000% | 35.422% | 14.578% | 0.6784 | 0.6499 |
| concentrated 20 | 50.000% | 37.294% | 12.706% | 0.6480 | 0.5702 |

Concentration changes multiplicity, not the empty-round probability. No
calibration artifact selecting an intended production `F` was located. The
design explicitly says it must be calibrated; the example uses the maximum.

## 3. Independent and correlated outages — OPEN operationally

For a deterministic unavailable stake fraction `d`, honest online stake is
`1-d` and:

```text
P(no online proposer) = (1-f)^(1-d)
E[rounds to progress] = 1 / (1-(1-f)^(1-d)).
```

At `f=0.5`:

| Unavailable stake | P(no online proposer) | Expected rounds | P(no progress for 10 rounds) |
|---:|---:|---:|---:|
| 0% | 50.000% | 2.000 | 0.0977% |
| 5% | 51.763% | 2.073 | 0.1381% |
| 10% | 53.589% | 2.155 | 0.1953% |
| 20% | 57.435% | 2.349 | 0.3906% |
| 33% | 62.851% | 2.692 | 0.9618% |
| 40% | 65.975% | 2.939 | 1.5625% |

Independent validator failure with probability `d` is instead
`product_i[1-(1-d)p_i]`; `results.csv` covers 4/20/200 equal validators.
Correlated provider/region/top-k failure is the deterministic-stake formula,
but the repository contains no validator-to-provider/region allocation. Those
real scenarios remain OPEN pending deployment topology data.

These numbers cover proposer availability only. BFT progress still requires
strictly more than two-thirds online voting weight; a correlated outage at or
above one-third can halt QC formation even when an eligible proposer exists.

## 4. Byzantine withholding — OPEN documented residual

For Byzantine stake `beta` and honest online stake `h=1-beta`:

```text
P(at least one honest) = 1-(1-f)^h
P(only Byzantine)      = [1-(1-f)^beta] (1-f)^h
P(no honest proposer)  = (1-f)^h.
```

If all Byzantine proposals are withheld, at `f=0.5`:

| Byzantine stake | P(no honest) | P(only Byzantine) | Expected rounds | P(delay >=10 rounds) |
|---:|---:|---:|---:|---:|
| 5% | 51.763% | 1.763% | 2.073 | 0.138% |
| 10% | 53.589% | 3.589% | 2.155 | 0.195% |
| 20% | 57.435% | 7.435% | 2.349 | 0.391% |
| 33% | 62.851% | 12.851% | 2.692 | 0.962% |

The timeout is fixed at 8/3/3 seconds for propose/prevote/precommit
(`indra-node/src/bin/node.rs:57-59`), so expected wall-clock latency depends on
whether failed rounds reach later phases; the report does not collapse that
state machine into a false single-duration estimate.

## 5. Static grinding degrees of freedom

| Choice | Current alpha | Immutable entropy | Next seed | Ex-post selectable? | Result |
|---|---|---|---|---|---|
| transaction ordering/inclusion | no | no | no | yes | NO GRINDING LEVER |
| other block content/timestamp | no | no | no | yes | NO GRINDING LEVER |
| legitimate reproposal metadata | changes current proof only | preserved | preserved | yes | NO GRINDING LEVER after VRF-007 |
| current round | yes | fixes origin round on first proposal | yes if committed | round advances publicly | BOUNDED LEVER |
| which controlled eligible identity proposes | identity-specific alpha | fixes selected origin/output | yes | after local outputs known | BOUNDED LEVER |
| proposal withholding | no new alpha in same round | selects publish/no-publish | yes/no commit | yes | BOUNDED, quantitatively material |
| key registration/rotation timing | future snapshot/root | future outputs | indirectly | before activation; PoP required | BOUNDED LEVER |
| entropy-origin substitution for stable value | n/a | commitment rejects | rejected | no | NO GRINDING LEVER |
| fork/value choice | alpha independent of content | each new value carries same origin output for that proposal | committed winner only | content selectable, output not | NO content-grinding lever; withholding remains |

The origin output is created from the elected slot when a block is first built
(`indra-consensus/src/producer.rs:120-148`). Reproposal recomputes only the
current proposer proof while cloning the immutable entropy and rejects any
stable-hash change (`indra-node/src/engine.rs:1287-1359`).

## 6. Adaptive multi-round grinding — FINDING L2-GR-01

Consider a coalition that knows its own next-height VRF eligibility under a
candidate seed. In an adversary-only eligible current round it publishes iff
that candidate seed elects the coalition at next height round 0. It withholds
otherwise. In mixed rounds this conservative model awards progress to honest
proposals, so it does not depend on winning a priority race.

Let `p_b=phi_f(beta)`, `p_h=phi_f(1-beta)`, `a=p_b(1-p_h)`, and target
probability `t=p_b`. Repeating independent rounds gives:

```text
P(adversary favorable seed wins race) = a*t / (p_h + a*t)
P(target in committed seed)           = t + (1-t) * race_probability.
```

At `f=0.5`:

| beta | Baseline next eligibility | Biased | Absolute | Relative | Effective bits | Expected current-height rounds |
|---:|---:|---:|---:|---:|---:|---:|
| 5% | 3.406% | 3.526% | 0.120 pp | 3.526% | 0.05 | 2.071 |
| 10% | 6.697% | 7.177% | 0.481 pp | 7.177% | 0.10 | 2.144 |
| 20% | 12.945% | 14.870% | 1.925 pp | 14.870% | 0.20 | 2.297 |
| 33% | 20.446% | 25.701% | 5.255 pp | 25.701% | 0.33 | 2.514 |

For an arbitrary balanced one-bit predicate the corresponding full-seed total
variation distance is at least 1.861%, 4.016%, and 7.373% for beta 10%, 20%,
and 33%. These are lower bounds obtained by projecting the full distribution
onto one bit/predicate, not claims that all bias is captured.

The strategy is bounded: honest eligibility eventually terminates it with
geometric probability, and there is no unbounded set of entropy variants for a
single stable value. It is nevertheless material at beta near one-third and
must be included in `F` calibration/security acceptance.

## 7. Coalition identity splitting — PASS for eligibility, OPEN for choice

For `k` equal split keys totaling beta:

```text
P(any coalition key eligible) = 1-(1-f)^beta
```

exactly, so stake splitting does not increase total ideal eligibility. It does
increase the chance of multiple simultaneously valid coalition outputs. At
`f=0.5`, beta=33%:

| Keys | P(any) | P(multiple) | P(multiple | any) |
|---:|---:|---:|---:|
| 1 | 20.446% | 0% | 0% |
| 2 | 20.446% | 1.168% | 5.712% |
| 5 | 20.446% | 1.827% | 8.934% |
| 10 | 20.446% | 2.040% | 9.976% |
| 50 | 20.446% | 2.208% | 10.797% |
| 200 | 20.446% | 2.239% | 10.950% |

Thus conservation holds for being elected, but operational entropy choice is
not identity-invariant. The 200-validator cap bounds this choice. Finite-grid
threshold rounding can change total probability by at most negligible
`k/2^512` scale under the Q768 theorem; it does not explain the visible
multiplicity effect.

## 8. Post-VRF-007 entropy binding — PASS

`ProposalEntropyV1` contains origin identity, origin round, output and proof
(`indra-core/src/types/block.rs:87-143`). Its domain-separated commitment is
included in stable value identity (`block.rs:100-110,208-230`). The complete
Phase-5 regressions establish:

```text
same entropy + new legitimate round => same value_hash
changed entropy                     => different value_hash
old PoLC + changed entropy          => rejected before vote/lock mutation
```

No remaining path supplies more than one entropy record for one stable value.
The only remaining choice is whether a whole newly-originated proposal/value is
published.

## 9. Genesis Bitcoin entropy — OPEN external economics

The canonical descriptor fixes Bitcoin network genesis hash, future height,
80-byte header codec, double-SHA-256 extraction, at least 100 confirmations and
same-height reorg restart policy (`indra-node/src/genesis.rs:73-151`). No
deadline fallback is encoded in the design. This removes operator choice among
heights or encodings after observing entropy.

For an attacker controlling Bitcoin hash fraction `q<1/2`, a simple biased
random-walk upper model for ever catching up from `z=100` blocks is:

```text
(q/(1-q))^100.
```

| q | Eventual catch-up probability |
|---:|---:|
| 10% | 3.76e-96 |
| 20% | 6.22e-61 |
| 30% | 1.59e-37 |
| 40% | 2.46e-18 |
| 49% | 1.83% |
| >=50% | 1 |

This is not an economic-cost estimate and does not model selfish mining,
temporary majority rental, eclipsed assembly tooling, or miner header grinding
at the announced height. Current hash rate, rental capacity/cost, rewards and
the value obtainable by biasing testnet/mainnet sortition require external,
ceremony-time evidence. The 100-confirmation floor is strong against a
minority catch-up reorg but is not a substitute for trusted Bitcoin-chain
observation or an economic assessment.

## 10. Parameter sensitivity and L2-GR-02

With all stake online, expected rounds are exactly `1/f`. Therefore:

| f | Empty-round probability | Expected rounds |
|---:|---:|---:|
| 2^-64 | approximately 1 | 18,446,744,073,709,551,616 |
| 0.01 | 99% | 100 |
| 0.05 | 95% | 20 |
| 0.10 | 90% | 10 |
| 0.20 | 80% | 5 |
| 0.50 | 50% | 2 |

At an eight-second propose phase alone, `f=0.01` already implies roughly 800
seconds expected proposer waiting before prevote/precommit overhead. `F=1`
implies about 4.68 trillion years. The broad arithmetic domain is therefore not
an acceptable operational domain by itself. A reviewed genesis parameter and
quantitative acceptance envelope remain necessary.

## 11. Final classifications

| Area | Classification | Reason |
|---|---|---|
| stochastic model / split-merge law | PASS | analytic identity and exact high-precision evaluation |
| proposer count | PASS | Poisson-binomial results; multiplicity characterized |
| production `F` calibration | FINDING | legal range contains practically dead values; no calibration record found |
| independent offline stake | PASS mathematically | exact formulas and tails |
| correlated provider/region outage | OPEN | deployment topology/stake mapping absent |
| Byzantine delay | OPEN | bounded and quantified; depends on network delivery/QC assumptions |
| adaptive entropy grinding | FINDING | material documented withholding bias quantified at `f=0.5` |
| stake-splitting eligibility | PASS | total probability conserved |
| stake-splitting entropy multiplicity | OPEN | bounded but rises to 10.95% conditional multi-output at beta=33%, k=200 |
| post-VRF-007 stable entropy | PASS | immutable commitment survives reproposal/sync/restart |
| genesis entropy mechanics | PASS | fixed source/height/codec/depth/reorg rule |
| genesis entropy economics | OPEN | requires current external Bitcoin evidence |

## Reproduction

```bash
python3 audit_evidence/13_grinding_liveness/model.py
```

The model is deterministic and uses no random source. Re-running must produce
844 CSV rows. Any future Monte Carlo extension must declare and pin its seed;
none was necessary for the strategies analyzed here.
