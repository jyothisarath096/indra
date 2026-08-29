# Dandelion++ simulation v2: small-N relay eligibility and refined embargo

**Scope:** simulation and design recommendation only; no production-code change  
**Repository snapshot:** `20448f3d2fd68181481947da13dbd5d17b503e35`  
**Evidence run:** 2026-08-30  
**New model:** `dandelion_topology_model_v2.py`  
**New raw data:** `simulation_results_v2.csv`  
**New metadata:** `simulation_metadata_v2.json`

## Executive result

Policy B solves the specific small-N eligibility defect. At q=.20, one relay,
and a 30-second embargo, the fraction of transactions encountering no eligible
relay moved:

```text
N=4: 62.9% → 0%   (−62.9 percentage points)
N=8: 46.5% → 0%   (−46.5 percentage points)
```

It does not materially improve anonymity by itself. Averaged across the requested
coalition labels, first-spy precision/recall changed from `.494/.476` to
`.509/.509` at N=4 (slightly worse) and from `.401/.387` to `.362/.348` at N=8
(better). Those 1.5–3.9 percentage-point changes are close to the run's sampling
resolution and point in opposite directions. The defensible conclusion is that
Policy B removes a frequent fallback/privacy failure without a demonstrated
systematic first-spy regression or gain.

The added path diversity is not free. Policy B creates directed cycles and
convergent paths that Policy A's small-N identity orientation suppressed. At the
30-second comparison, 28.5% of N=4 transactions and 23.9% of N=8 transactions
encountered a duplicate stem and fluffed through loop detection. Full coverage
remained `.999` and `1.000`, respectively.

The refined embargo sweep finds **no latency-only diminishing-returns plateau**
within 3–30 seconds. Shortening the base continued to materially lower p95 and
p99 all the way to the shortest tested value, 3 seconds. At 3 seconds, averaged
p95/p99 added latency was `5.68/10.64s` at N=4 and `4.94/9.30s` at N=8. This is
not automatically the best privacy choice: first-spy precision/recall worsened to
`.555/.569` and `.427/.422`, respectively. The useful privacy/latency compromise
is around **9–10 seconds**, not a pure latency knee.

**Updated candidate for human approval:** 

```text
q = 0.20
relay_count = 1
relay eligibility = Policy B (any authenticated connection at N≤9;
                               outbound-only at N>9)
embargo base = 3 × MIN_ROUND_TIME_MS = 9 seconds, exponential randomized
```

This report recommends expressing the timeout as the multiplier, not finalizing
it. Three round floors is directly represented in the tested round-relative
sweep, is adjacent to the flat sweep's favorable 10-second point, and avoids a
fixed constant silently diverging if protocol timing is deliberately changed.

## 1. Preservation and reproducibility

The v1 artifacts were not modified. Their post-v2 hashes remain:

```text
00d2b9e9e4a2decd0afd470819909de6473dc48519e3bf4af25f7f7cff977c43  dandelion_topology_model.py
781c56d95672494f92d70b96000cce19cf57863d7bed657207c73304a1fdbca3  simulation_results.csv
4aa024511cfbd9b2e10b22ca4850cf7e1cba5c9535c90abdabebe9843a5d4c41  SIMULATION_RESULTS.md
```

V2 imports the frozen v1 model and changes only the relay-eligibility view of the
small complete topology. It generated 72 new Policy-B cells × 1,000 transactions
= 72,000 new transactions. The v2 CSV also contains eight exact q=.20,
one-relay, 30-second Policy-A reference rows copied from the frozen v1 CSV, for
80 rows total.

Reproduce:

```bash
python3 audit_evidence/22_gossip_origin_privacy/dandelion_topology_model_v2.py \
  --transactions-per-cell 1000
```

V2 evidence hashes:

```text
7f15746af2c3ff9685ecf6fcd9de4d228c79b3c3372e1baeb462d97850d33b0c  dandelion_topology_model_v2.py
bebb9c4e3efb6158a328e843249a2feb7e0132c609b87035f6f7beb9e8a4d874  simulation_results_v2.csv
619b4f50e3d96b44ecee6be9d863bd0c71ea524e9cc00dc9c834dc1ed8039005  simulation_metadata_v2.json
```

The new seed, sweep membership, source-row provenance, and inherited v1
assumptions are recorded in `simulation_metadata_v2.json`. Each CSV row says
whether it is newly simulated or copied reference evidence.

## 2. Current constants and exact policy boundary

`TARGET_OUTBOUND_PEERS` is still 8
(`indra-core/src/types/primitives.rs:434-435`). Therefore the complete-small-set
threshold is exactly:

```text
N ≤ TARGET_OUTBOUND_PEERS + 1 = 9
```

The refined timing anchor is also current:

```text
MIN_ROUND_TIME_MS = 3,000 ms
```

It is described as the immutable, non-governable hard floor on total round time
at `indra-core/src/types/primitives.rs:51-52`.

The v2 policies are:

* **Policy A:** outbound-initiated authenticated connections only, at every N.
  This is the frozen v1 behavior.
* **Policy B:** at N≤9, select the epoch relay from every authenticated connected
  validator, whether the local or remote endpoint initiated the connection. At
  N>9, resume outbound-only eligibility exactly as Policy A.

## 3. Why Policy B is justified specifically for INDRA

Dandelion++'s outbound preference is a defense for large open networks: an
attacker should not be able to create many cheap anonymous inbound connections
and force itself into the stem graph. INDRA's validator mesh has a materially
different admission boundary:

* the handshake allow-list is the height-specific known-validator set
  (`indra-network/src/handshake.rs:69-79`);
* both initiator and responder authenticate the remote validator identity with
  its registered PQ signature key (`indra-network/src/handshake.rs:317-418`);
* `peers_by_validator` holds one logical connection per authenticated identity
  (`indra-network/src/peer_manager.rs:954-1026`,
  `indra-network/src/peer_manager.rs:1102-1123`).

An inbound connection is therefore not a cheap anonymous Sybil. It is another
active, PQ-signature-authenticated validator identity. At N=4 or N=8, where the
physical mesh is already complete, excluding a peer solely because it won the
inbound side of deterministic connection ownership removes relay choices without
removing an adversarial identity.

Policy B is intentionally narrow. At N>9 the graph is partial, outbound selection
again provides useful local control over stem edges, and v2 returns to Policy A.

## 4. Part A: direct Policy A versus Policy B results

All comparisons below use N∈{4,8}, q=.20, one relay, 30-second exponential
embargo, and the same four requested coalition labels. Policy-A values are copied
exactly from v1; Policy-B values are independent deterministic v2 Monte Carlo
cells. They are not paired transaction-for-transaction.

### 4.1 Per-coalition comparison

| N | requested coalition | policy | realized coalition | zero-eligible tx | precision | recall | full coverage | p50 added | p95 | p99 |
|---:|---:|:---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 | 5% | A | 25% | .470 | .523 | .535 | .999 | 3.08s | 55.69s | 92.69s |
| 4 | 5% | B | 25% | **.000** | .450 | .454 | .998 | 4.09s | 55.40s | 93.71s |
| 4 | 10% | A | 25% | .607 | .524 | .515 | .998 | 3.00s | 46.06s | 91.41s |
| 4 | 10% | B | 25% | **.000** | .503 | .486 | .999 | 2.97s | 56.25s | 93.25s |
| 4 | 20% | A | 25% | .827 | .411 | .359 | .997 | 3.00s | 3.21s | 45.77s |
| 4 | 20% | B | 25% | **.000** | .512 | .504 | .999 | 1.69s | 52.06s | 104.29s |
| 4 | 33% | A | 25% | .612 | .517 | .496 | .997 | 3.00s | 45.09s | 100.21s |
| 4 | 33% | B | 25% | **.000** | .571 | .590 | .999 | .22s | 40.19s | 99.04s |
| 8 | 5% | A | 12.5% | .521 | .294 | .306 | 1.000 | 3.06s | 38.10s | 94.91s |
| 8 | 5% | B | 12.5% | **.000** | .317 | .301 | 1.000 | .35s | 42.78s | 74.37s |
| 8 | 10% | A | 12.5% | .478 | .365 | .365 | 1.000 | 3.06s | 46.14s | 86.31s |
| 8 | 10% | B | 12.5% | **.000** | .301 | .309 | 1.000 | .31s | 41.98s | 102.99s |
| 8 | 20% | A | 25% | .510 | .432 | .388 | 1.000 | 3.07s | 48.17s | 92.16s |
| 8 | 20% | B | 25% | **.000** | .393 | .381 | 1.000 | .44s | 49.84s | 88.09s |
| 8 | 33% | A | 37.5% | .352 | .512 | .492 | 1.000 | 3.17s | 65.62s | 101.87s |
| 8 | 33% | B | 37.5% | **.000** | .438 | .399 | 1.000 | 4.42s | 59.29s | 121.78s |

At N=4, all four labels are the same one-validator coalition. Their row-to-row
variation is sampling/topology-epoch variation and must not be presented as a
fraction trend.

### 4.2 Average movement across requested labels

| N | policy | zero-eligible tx | precision | recall | full coverage | p50 | p95 | p99 | embargo fluff | loop tx |
|---:|:---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 | A | .629 | .494 | .476 | .998 | 3.02s | 37.51s | 82.52s | .340 | .000 |
| 4 | B | **.000** | .509 | .509 | .999 | 2.24s | 50.97s | 97.57s | .523 | .285 |
| 8 | A | .465 | .401 | .387 | 1.000 | 3.09s | 49.51s | 93.81s | .457 | .000 |
| 8 | B | **.000** | .362 | .348 | 1.000 | 1.38s | 48.47s | 96.81s | .474 | .239 |

### 4.3 Decision-relevant effect size

In one paragraph: **Policy B eliminated 62.9 percentage points of zero-eligible
transactions at N=4 and 46.5 points at N=8. First-spy precision/recall moved only
+1.5/+3.3 points at N=4 and −3.9/−3.9 points at N=8, with unchanged practical
coverage. Median added latency improved by .78s and 1.71s, while p95 worsened by
13.46s at N=4 and improved by 1.03s at N=8. The cost was a new loop/duplicate
path on 28.5% and 23.9% of transactions.** The fix is worth modeling into the v1
design because it removes a deterministic fallback defect, not because it proves
better anonymity.

The N=4 p95 increase is explainable: Policy A frequently converted a path into a
fixed three-second immediate-fluff fallback. Policy B keeps that path in stem,
where a colluder can black-hole it until an exponential embargo. Removing the
fallback improves intended semantics while exposing the real embargo tail.

## 5. Part B: refined embargo sweep

The two requested framings produce a deduplicated set of nine simulated bases:

```text
flat seconds:       5, 10, 15, 20, 30
round relative:     3, 6, 9, 12, 15, 30 seconds
                    (k = 1, 2, 3, 4, 5, 10)
deduplicated union: 3, 5, 6, 9, 10, 12, 15, 20, 30
```

All cells use Policy B, q=.20, one relay, and four coalition labels.

### 5.1 N=4 averages

| embargo | framing | precision | recall | embargo fluff | loop tx | full coverage | p50 | p95 | p99 |
|---:|:---|---:|---:|---:|---:|---:|---:|---:|---:|
| 3s | 1× round | .555 | .569 | .575 | .271 | .998 | .38s | **5.68s** | **10.64s** |
| 5s | flat | .549 | .549 | .634 | .207 | .999 | .85s | 9.96s | 16.14s |
| 6s | 2× round | .593 | .606 | .497 | .327 | .998 | .59s | 10.50s | 19.37s |
| 9s | 3× round | .536 | .540 | .457 | .339 | .999 | .67s | 14.42s | 26.62s |
| 10s | flat | **.495** | **.506** | .494 | .312 | .998 | .52s | 16.64s | 30.88s |
| 12s | 4× round | .501 | .491 | .578 | .244 | .998 | 1.56s | 21.11s | 39.77s |
| 15s | flat; 5× | .541 | .551 | .628 | .214 | 1.000 | 2.34s | 29.12s | 48.16s |
| 20s | flat | .575 | .582 | .631 | .228 | .998 | 3.15s | 40.61s | 80.16s |
| 30s | flat; 10× | .509 | .509 | .523 | .285 | .999 | 2.24s | 50.97s | 97.57s |

### 5.2 N=8 averages

| embargo | framing | precision | recall | embargo fluff | loop tx | full coverage | p50 | p95 | p99 |
|---:|:---|---:|---:|---:|---:|---:|---:|---:|---:|
| 3s | 1× round | .427 | .422 | .561 | .189 | 1.000 | .51s | **4.94s** | **9.30s** |
| 5s | flat | .411 | .421 | .559 | .204 | 1.000 | .60s | 8.25s | 16.11s |
| 6s | 2× round | .412 | .413 | .613 | .160 | 1.000 | .91s | 10.64s | 19.47s |
| 9s | 3× round | .406 | .407 | .495 | .253 | 1.000 | .76s | 14.38s | 28.57s |
| 10s | flat | **.365** | **.368** | .573 | .189 | 1.000 | 1.25s | 16.95s | 32.85s |
| 12s | 4× round | .403 | .404 | .515 | .233 | 1.000 | 1.12s | 20.48s | 39.42s |
| 15s | flat; 5× | .397 | .401 | .492 | .234 | 1.000 | 1.38s | 24.65s | 48.06s |
| 20s | flat | .369 | .370 | .580 | .186 | 1.000 | 2.72s | 35.47s | 61.65s |
| 30s | flat; 10× | .362 | .348 | .474 | .239 | 1.000 | 1.38s | 48.47s | 96.81s |

### 5.3 Diminishing returns

There is no observed latency plateau. Moving from 5s to 3s still reduced average
p95 by 4.28s at N=4 and 3.31s at N=8, and p99 by 5.51s and 6.81s. The shortest
tested base remained materially faster. Therefore the data cannot honestly name
a point where p95/p99 “stops” decreasing.

The decision knee appears only after privacy is considered. One-round/3s embargo
makes the origin's fail-safe race very quickly and has worse first-spy averages
than the 9–10s region. Ten seconds produced the lowest aggregate first-spy
precision at both N=4 and N=8 in this run while keeping p95 below 17 seconds.
Nine seconds is adjacent, has p95 near 14.4 seconds, and is the exact 3×
round-relative point. The 9-versus-10 privacy gap is not robust enough to justify
a bespoke one-second fixed offset: cells are independent Monte Carlo samples and
simple proportions have roughly 1.6-point standard error near .5 before topology
clustering.

## 6. Flat versus round-relative framing

The round-relative and flat sweeps do not imply materially different operating
regions. They overlap exactly at 15s and 30s; 9s/12s bracket the flat 10s point;
and all show the same approximately linear tail-latency cost as the base grows.

The **multiplier is more defensible as the implementation-facing parameter**:

* `MIN_ROUND_TIME_MS` is the protocol's explicit immutable round-time floor, so
  reviewers can understand the latency budget in consensus units;
* three floors (9s) is directly simulated and close to the favorable fixed 10s
  cell;
* if a future protocol change deliberately changes the floor, the embargo does
  not silently retain a timing assumption that was calibrated against 3s rounds.

This does not mean consensus timing mathematically determines privacy timeout.
The multiplier is a configuration-expression and drift-control choice. Any
change to `MIN_ROUND_TIME_MS` must rerun this model rather than assuming scaling
preserves privacy.

## 7. Part C: revised recommendation

### Candidate for human approval

```text
q                       = 0.20
relay_count             = 1
relay_eligibility       = any authenticated validator connection at N<=9;
                          outbound-only at N>9
embargo_base            = 3 × MIN_ROUND_TIME_MS = 9 seconds
embargo distribution    = independent exponential per honest stem holder
```

Why:

1. q=.20 and one relay retain the v1 privacy-first conclusions and expected
   five-hop stem length.
2. Policy B eliminates the small complete mesh's structural zero-relay state.
3. A 9s base cuts the Policy-B 30s p95 from 50.97s to 14.42s at N=4 and from
   48.47s to 14.38s at N=8; p99 falls from 97.57s to 26.62s and from 96.81s to
   28.57s.
4. One-round/3s is faster but worsens first-spy averages. Longer than 12s adds
   large tail latency without a stable privacy improvement.
5. Three round floors is easier to keep auditable than a fixed 10-second constant,
   while the observed 9/10 difference is within the limits of this evidence.

At the recommended 9s candidate, averaged first-spy precision/recall is
`.536/.540` at N=4 and `.406/.407` at N=8. Exact per-coalition rows are in the
v2 CSV. These are not strong anonymity numbers.

### Required security-claim wording

The v1 warning remains necessary, with one operational clarification:

> Transaction stem relay reduces other validators' confidence in the RPC-entry
> validator. At four validators the protection remains weak: a one-validator
> coalition identifies approximately half of honest entry validators under the
> modeled first-spy attack. Allowing any authenticated connection as the small-N
> relay removes the frequent zero-outbound fallback, but does not enlarge the
> validator anonymity set or hide the submitting wallet from its RPC validator.
> Material anonymity-set benefits still require a larger validator set.

Do not claim that Policy B “solves small-N anonymity.” It solves relay eligibility.

## 8. Remaining human decisions and implementation prerequisites

1. Approve or reject Policy B's N≤9 boundary. It is justified by authenticated
   membership but creates 24–29% loop-detected fluff in this model.
2. Approve or reject the 3× round-floor candidate. The data does not authorize a
   final value.
3. Decide whether loop-triggered fluff at the measured rate is acceptable or
   whether relay selection needs deterministic per-inbound mapping to reduce
   cycles before production implementation.
4. Decide whether N=4 privacy is sufficient to enable the feature, or whether
   the correct product posture is “eligibility works, anonymity remains weak.”
5. Revalidate with paired trials and more than 1,000 transactions/cell if a
   3–5 percentage-point first-spy difference will drive the final decision.
6. Preserve the bounded reconnect attempt and alert for genuine physical
   no-connection states even under Policy B.

## 9. Limitations

V2 inherits every v1 model limitation. It is Monte Carlo evidence, not a formal
anonymity proof or packet emulator. The Policy-A comparison uses frozen v1 cells
rather than paired common-random-number trials. Coalition-fraction quantization is
especially severe at N=4. The 2% link-churn and latency distribution remain
explicit experiment assumptions rather than production measurements.

Policy B is modeled only at N=4 and N=8, as requested. Its N>9 behavior is defined
as identical to Policy A but was not redundantly resimulated. The report does not
authorize or implement any change in `peer_manager.rs`.
