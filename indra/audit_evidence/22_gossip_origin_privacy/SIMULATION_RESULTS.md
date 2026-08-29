# INDRA-specific Dandelion++ topology/adversary simulation

**Scope:** simulation and data generation only; no production source change  
**Repository snapshot:** `20448f3d2fd68181481947da13dbd5d17b503e35`  
**Evidence run:** 2026-08-30, deterministic seed `0x1D4A20260830`  
**Model:** `dandelion_topology_model.py`  
**Raw aggregate data:** `simulation_results.csv`  
**Machine-readable assumptions:** `simulation_metadata.json`

## Executive result

The simulation supports a **provisional v1 recommendation for human approval**
of:

```text
(q = 0.20, relay_count = 1, embargo_base = 30 seconds)
```

This is a recommendation from the settled sweep, not a final parameter decision
or implementation authorization.

The honest conclusion is not “Dandelion++ solves origin privacy at launch.” At
INDRA's near-term N=4–8 sizes, it provides only limited entry-validator
obfuscation:

* At N=4, one colluder is already 25% of the set. For the recommended candidate,
  first-spy precision/recall across the requested fraction labels average
  **0.494 / 0.476**. Because all four requested fractions round to one identity,
  the labels are not independent threat points at N=4.
* At N=8, results range from **0.294 / 0.306** with one colluder (12.5% realized)
  to **0.512 / 0.492** with three colluders (37.5% realized). Averaged across the
  requested sweep: **0.401 / 0.387**.
* The current immediate-flood baseline in a complete N=4 or N=8 graph gives a
  colluder directly connected to every honest origin, so the same first-spy
  estimator identifies the entry validator with precision and recall **1.0** in
  this model. The proposed mechanism is an improvement, but values around 0.5 at
  N=4 are not strong anonymity.
* Useful protection begins to emerge around **N≈20** for small coalitions: at the
  recommended candidate, 5% and 10% collusions yield precision/recall
  **0.139/0.145** and **0.168/0.166**. Protection necessarily degrades as the
  colluding fraction grows; at a realized 35% coalition it is **0.400/0.401**.

Two relays are not supported for a privacy-first v1. At N=4 and N=8 with a
30-second embargo, two relays consistently expose the stem to more colluders and
raise average first-spy precision/recall. They also create convergent duplicate
paths: loop/duplicate-transaction rates reach 8.9–15.6% at N=4 and 21.4–34.8% at
N=8 across q. Two relays materially improve tail latency, but that is a liveness
trade rather than a privacy win.

The 30-second embargo is the only defensible point in the swept set for a v1
experiment. A longer embargo does not produce a stable small-N privacy
improvement, while it roughly doubles to quadruples p95/p99 tail latency during
black holes. Even at 30 seconds, the exponential timer produces large tails:
for the recommended candidate, p95 added latency averages 37.5 seconds at N=4
and 49.5 seconds at N=8 across coalition labels. This is evidence for a human
latency/privacy decision, not grounds to hide the cost.

## 1. Current-code anchors

The model constants were rechecked at the audited snapshot:

| Input | Current value | Source |
|---|---:|---|
| Hard active-validator floor | 4 | `parse_genesis_manifest_str` calls `parse_genesis_manifest_str_with_minimum(content, 4)` at `indra-node/src/genesis.rs:317-320`; the protocol constant is `MIN_ACTIVE_VALIDATORS = 4` at `indra-core/src/types/primitives.rs:259-263`. |
| Target outbound peers | 8 | `indra-core/src/types/primitives.rs:434-435` |
| Maximum inbound peers | 64 | `indra-core/src/types/primitives.rs:437-438` |
| Maximum peer-table entries | 80 | `indra-network/src/peer.rs:34-35` |
| Mature active-set maximum | 200 | `indra-core/src/types/primitives.rs:262-263` |

The selected N values are 4, 8, 20, 50, 100, and 200. The last four also align
with current fanout-test checkpoints: `derive_consensus_relay_fanout` is asserted
at 20→8, 50→10, 100→12, and 200→13
(`indra-network/src/peer_manager.rs:2068-2076`). Dandelion transaction relay is
not modeled with those consensus fanouts; the checkpoints are used for direct
topology-scale comparability only.

## 2. Model and reproducibility

### 2.1 Evidence volume

The Cartesian sweep contains:

```text
6 N values
× 4 requested adversary fractions
× 3 q values
× 2 relay counts
× 3 embargo bases
= 432 cells
```

Each cell contains 1,000 transactions over 10 independently generated topology/
relay epochs: **432,000 simulated transactions total**. Each CSV row is one exact
`(N, adversary fraction, q, relay count, embargo)` cell and contains all required
metrics. The run is deterministic.

Reproduce from the repository root:

```bash
python3 audit_evidence/22_gossip_origin_privacy/dandelion_topology_model.py \
  --transactions-per-cell 1000
```

Evidence SHA-256 values:

```text
00d2b9e9e4a2decd0afd470819909de6473dc48519e3bf4af25f7f7cff977c43  dandelion_topology_model.py
781c56d95672494f92d70b96000cce19cf57863d7bed657207c73304a1fdbca3  simulation_results.csv
e92d30ca75b0220817bf4caaf560e0bb2902b524e6bfd3df4629d6fe5b2ca761  simulation_metadata.json
```

### 2.2 Topology construction

Connections are undirected for message transport but retain the initiator as the
outbound owner, matching `ManagedPeer::is_outbound`. For N≤9, every pair connects
because the eight-outbound cap permits a complete graph. When duplicate opposite
dials resolve, the lower simulated validator identity owns the outbound side,
matching `tie_break_keep_new`'s initiator/responder identity ordering
(`indra-network/src/peer_manager.rs:455-466`). This deliberately exposes the
small-N edge case: the highest identity has a complete set of inbound connections
but zero outbound-designated relays.

For N>9, validators dial shuffled candidates until reaching eight outbound
connections, subject to 64 inbound and 80 total peer caps. The resulting nominal
topologies were:

| N | Mean edges | Mean undirected degree | Nodes with zero outbound |
|---:|---:|---:|---:|
| 4 | 6 | 3 | 25.0% |
| 8 | 28 | 7 | 12.5% |
| 20 | 158.4 | 15.84 | 0% |
| 50 | 400 | 16 | 0% |
| 100 | 800 | 16 | 0% |
| 200 | 1,600 | 16 | 0% |

The N=4 and N=8 graphs are therefore fully connected, not idealized sparse
regular graphs. Any weak anonymity result at those sizes cannot be blamed on
artificially low connectivity.

### 2.3 Coalition placement and behavior

The requested identity fraction is converted to the nearest representable
integer coalition, rounding half upward and retaining at least one spy:

| N | requested 5% | 10% | 20% | 33% |
|---:|---:|---:|---:|---:|
| 4 | 1 (25%) | 1 (25%) | 1 (25%) | 1 (25%) |
| 8 | 1 (12.5%) | 1 (12.5%) | 2 (25%) | 3 (37.5%) |
| 20 | 1 (5%) | 2 (10%) | 4 (20%) | 7 (35%) |
| 50 | 3 (6%) | 5 (10%) | 10 (20%) | 17 (34%) |
| 100 | 5 (5%) | 10 (10%) | 20 (20%) | 33 (33%) |
| 200 | 10 (5%) | 20 (10%) | 40 (20%) | 66 (33%) |

Coalitions are resampled by identity each topology epoch. Because connections
retain direction, colluders occur on both honest outbound and inbound edges. The
CSV records `honest_nodes_with_adversarial_outbound_fraction` and
`honest_nodes_with_adversarial_inbound_fraction` for every cell. For example, at
N=20 those exposure fractions rise from about 0.43/0.41 for one colluder to
1.00/1.00 for seven colluders.

A colluding validator records the first honest predecessor from which it observes
the transaction and then black-holes stem traffic. During fluff it receives but
does not forward. This is deliberately adversarial: it measures both first-spy
correlation and the fail-safe's response to coalition withholding.

### 2.4 Stem, fluff, loops, and failure behavior

* A local origin always stems; it does not take a q coin.
* Each first honest stem recipient independently fluffs with probability q or
  continues through its epoch-selected outbound relay(s).
* Every honest stem holder arms an independent exponential embargo with the named
  base/mean of 30, 60, or 120 seconds.
* A duplicate stem receipt causes immediate fluff and counts as a loop/duplicate.
* Relay count two forks to two outbound peers. This is intentionally evaluated as
  a production simplification candidate, not claimed to reproduce the paper's
  4-regular mapping.
* Each connection has a 2% independent transient-down probability per transaction.
  If an epoch relay is unavailable, the node spends a bounded two seconds trying
  another connected outbound peer. If no outbound peer is available, it waits a
  total bounded three-second window, immediately fluffs, and records an alert
  event. There is no silent steady-state no-relay branch.

The reported `zero_outbound_tx_fraction` means the transaction encountered this
condition at least once anywhere on its stem path; it is not merely the fraction
of origins with zero outbound degree.

### 2.5 Latency and coverage

Per-edge latency is independently lognormal with 80 ms median and log sigma 0.35.
The immediate-flood baseline and Dandelion case use the same active graph and edge
latencies. Added latency is:

```text
Dandelion full-propagation completion − immediate-flood completion
```

Diffusion runs over active honest-forwarding paths. Colluders receive but do not
forward. Coverage is measured over all validators within a 180-second reasonable
bound. A missing node is counted as non-full coverage; the latency calculation
uses the bound rather than pretending it arrived.

These latency and churn values are explicit experiment assumptions, not measured
INDRA production distributions. The report supports comparison within the sweep;
absolute deployment latency must be revalidated with observed mainnet/testnet
telemetry.

## 3. Metric definitions

The first-spy estimator guesses that the honest predecessor of the coalition's
earliest observation was the source.

* **Precision:** correct coalition source guesses divided by all coalition source
  guesses. The CSV also includes macro precision by guessed identity.
* **Recall:** for each honest source, correctly identified transactions divided by
  its originated transactions, macro-averaged over honest sources.
* **Embargo fluff fraction:** transactions whose first fluff transition was an
  embargo expiry, rather than a normal q coin, loop, or zero-outbound fallback.
* **Loop transaction rate:** fraction encountering at least one duplicate stem at
  an honest validator.
* **Duplicate stem rate:** duplicate honest stem receipts divided by stem sends.
* **Coverage:** mean validator fraction reached and fraction reaching the full set.
* **Added latency:** p50/p95/p99 versus the same transaction's immediate-flood
  baseline.

With 1,000 transactions per cell, a simple Bernoulli proportion near 0.5 has
standard error about 0.016 before topology clustering. Differences of only a few
percentage points should not be overinterpreted; the stable large effects—one
versus two relays and 30 versus 120 seconds—are the decision-relevant evidence.

## 4. Full sweep data

`simulation_results.csv` is the authoritative per-combination result. It has 432
rows and includes, for **every** `(N, requested adversary fraction, q, relay
count, embargo)` combination:

* requested and realized coalition size/fraction;
* inbound/outbound coalition exposure;
* first-spy micro and macro precision, recall, and observation rate;
* embargo, loop, and duplicate rates;
* mean and full propagation coverage;
* p50/p95/p99 added latency;
* zero-outbound and reconnect-substitution rates.

The report tables below highlight decision boundaries without duplicating all 432
machine-readable rows into Markdown.

## 5. Small-N results: parameter choice must start here

### 5.1 N=4 and N=8, 30-second embargo

Values below average the four requested coalition labels. At N=4 those labels all
represent the same realizable one-validator/25% coalition; variation is Monte
Carlo/topology-epoch noise, not four different coalition sizes.

| N | q | relays | precision | recall | embargo fluff | loop tx | full coverage | latency p50 | p95 | p99 | zero-outbound tx |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 | .10 | 1 | .538 | .542 | .467 | .000 | .998 | 3.10s | 51.95s | 98.71s | .562 |
| 4 | .15 | 1 | .531 | .541 | .407 | .000 | .999 | 3.06s | 49.13s | 95.72s | .593 |
| 4 | .20 | 1 | **.494** | **.476** | .340 | .000 | .998 | 3.02s | **37.51s** | **82.52s** | .629 |
| 4 | .10 | 2 | .587 | .582 | .228 | .156 | .998 | 3.00s | 18.28s | 53.78s | .756 |
| 4 | .15 | 2 | .664 | .662 | .275 | .094 | .999 | 3.00s | 23.60s | 54.43s | .683 |
| 4 | .20 | 2 | .608 | .615 | .259 | .089 | .999 | 3.00s | 23.56s | 49.28s | .673 |
| 8 | .10 | 1 | **.349** | **.338** | .381 | .000 | 1.000 | 3.09s | 36.42s | 76.06s | .626 |
| 8 | .15 | 1 | .358 | .355 | .406 | .000 | 1.000 | 3.10s | **34.31s** | 81.19s | .568 |
| 8 | .20 | 1 | .401 | .387 | .457 | .000 | 1.000 | 3.09s | 49.51s | 93.81s | .465 |
| 8 | .10 | 2 | .466 | .466 | .228 | .348 | 1.000 | 1.41s | 17.49s | 44.68s | .613 |
| 8 | .15 | 2 | .462 | .451 | .232 | .273 | 1.000 | 1.26s | **17.11s** | **42.26s** | .555 |
| 8 | .20 | 2 | .484 | .482 | .203 | .214 | 1.000 | 1.36s | 18.01s | 48.74s | .524 |

No candidate is uniformly best under sampling noise. The q=.10 one-relay cell is
better on N=8 first-spy metrics, while q=.20 is clearly better at N=4 and matches
the original audit's rationale of limiting expected stem length to five hops in a
small set. q=.20 also avoids choosing a ten-hop expectation for a four- or
eight-node graph, where identities must repeat or terminate. The recommendation
therefore favors q=.20 as the more defensible cross-size v1 setting, not because
it wins every isolated Monte Carlo cell.

### 5.2 Exact recommended-candidate small-N results

| N | requested coalition | realized coalition | precision | recall | embargo fluff | full coverage | p50 | p95 | p99 | zero-outbound tx |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 | 5% | 1/4 (25%) | .523 | .535 | .483 | .999 | 3.08s | 55.69s | 92.69s | .470 |
| 4 | 10% | 1/4 (25%) | .524 | .515 | .375 | .998 | 3.00s | 46.06s | 91.41s | .607 |
| 4 | 20% | 1/4 (25%) | .411 | .359 | .153 | .997 | 3.00s | 3.21s | 45.77s | .827 |
| 4 | 33% | 1/4 (25%) | .517 | .496 | .348 | .997 | 3.00s | 45.09s | 100.21s | .612 |
| 8 | 5% | 1/8 (12.5%) | .294 | .306 | .352 | 1.000 | 3.06s | 38.10s | 94.91s | .521 |
| 8 | 10% | 1/8 (12.5%) | .365 | .365 | .433 | 1.000 | 3.06s | 46.14s | 86.31s | .478 |
| 8 | 20% | 2/8 (25%) | .432 | .388 | .449 | 1.000 | 3.07s | 48.17s | 92.16s | .510 |
| 8 | 33% | 3/8 (37.5%) | .512 | .492 | .594 | 1.000 | 3.17s | 65.62s | 101.87s | .352 |

The apparent spread among the four N=4 rows is not an adversary-fraction trend;
all use one colluder. This is an unavoidable quantization fact and should be
presented that way in product/security claims.

### 5.3 What small N actually permits

At N=4, every validator has only three peers. A single colluder sees every honest
validator's diffusion directly, and there are only three honest candidates. The
mechanism reduces the immediate-flood certainty but does not create a large
anonymity set. **Document N=4 support as weak correlation resistance, not sender
anonymity.**

At N=8, one colluder's precision/recall around 0.29–0.37 is a meaningful reduction
from 1.0, but a 25–37.5% coalition brings identification back toward 0.4–0.5.
This is still limited protection and depends on the adversary not being global.

## 6. Scaling and adversary-fraction results

For the recommended candidate:

| N | requested coalition | realized | precision | recall | embargo fluff | loop tx | duplicate stem | full coverage | p95 added |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 20 | 5% | 5% | .139 | .145 | .241 | .185 | .055 | 1.000 | 16.17s |
| 20 | 10% | 10% | .168 | .166 | .292 | .174 | .053 | 1.000 | 22.02s |
| 20 | 20% | 20% | .292 | .302 | .580 | .088 | .039 | 1.000 | 45.72s |
| 20 | 33% | 35% | .400 | .401 | .754 | .028 | .015 | 1.000 | 63.76s |
| 50 | 5% | 6% | .073 | .075 | .358 | .021 | .006 | 1.000 | 22.89s |
| 50 | 10% | 10% | .135 | .142 | .329 | .122 | .038 | 1.000 | 29.33s |
| 50 | 20% | 20% | .261 | .254 | .572 | .049 | .020 | 1.000 | 55.32s |
| 50 | 33% | 34% | .331 | .338 | .718 | .024 | .011 | 1.000 | 55.01s |
| 100 | 5% | 5% | .072 | .067 | .163 | .094 | .024 | 1.000 | 9.87s |
| 100 | 10% | 10% | .141 | .135 | .365 | .051 | .016 | 1.000 | 26.08s |
| 100 | 20% | 20% | .213 | .209 | .564 | .030 | .012 | 1.000 | 45.83s |
| 100 | 33% | 33% | .349 | .353 | .730 | .005 | .002 | 1.000 | 57.17s |
| 200 | 5% | 5% | .060 | .060 | .268 | .021 | .005 | 1.000 | 17.19s |
| 200 | 10% | 10% | .121 | .109 | .458 | .011 | .003 | 1.000 | 28.92s |
| 200 | 20% | 20% | .223 | .229 | .577 | .014 | .005 | 1.000 | 44.77s |
| 200 | 33% | 33% | .361 | .356 | .720 | .009 | .004 | 1.000 | 59.70s |

First-spy values approach the coalition fraction as N grows, which is the
expected limitation: a large colluding fraction frequently occupies a stem edge.
The mechanism provides its strongest relative value against small coalitions in
sets of at least roughly 20–50 validators.

## 7. Embargo and black-hole results

For q=.20/one relay, averaged across coalition labels:

| N | embargo | precision | recall | embargo fluff | latency p95 | p99 |
|---:|---:|---:|---:|---:|---:|---:|
| 4 | 30s | .494 | .476 | .340 | 37.51s | 82.52s |
| 4 | 60s | .528 | .533 | .432 | 112.39s | 177.80s |
| 4 | 120s | .454 | .432 | .242 | 147.23s | 180.00s |
| 8 | 30s | .401 | .387 | .457 | 49.51s | 93.81s |
| 8 | 60s | .351 | .360 | .462 | 96.91s | 173.93s |
| 8 | 120s | .403 | .414 | .455 | 161.23s | 180.00s |
| 20 | 30s | .250 | .253 | .467 | 36.92s | 80.58s |
| 20 | 60s | .233 | .228 | .387 | 68.61s | 145.25s |
| 20 | 120s | .249 | .256 | .468 | 140.32s | 180.00s |
| 50 | 30s | .200 | .202 | .494 | 40.63s | 82.21s |
| 50 | 60s | .202 | .204 | .436 | 77.79s | 155.47s |
| 50 | 120s | .212 | .212 | .473 | 143.67s | 180.00s |
| 100 | 30s | .194 | .191 | .455 | 34.74s | 86.15s |
| 100 | 60s | .182 | .183 | .452 | 74.04s | 135.49s |
| 100 | 120s | .176 | .174 | .467 | 142.76s | 180.00s |
| 200 | 30s | .191 | .188 | .506 | 37.64s | 84.78s |
| 200 | 60s | .172 | .163 | .452 | 67.82s | 132.73s |
| 200 | 120s | .187 | .187 | .461 | 136.16s | 175.09s |

Embargo firing is common because colluders intentionally black-hole stem traffic.
For one relay, the fraction generally rises with coalition exposure. This is the
fail-safe doing real work, not an edge case. The 60/120-second values sometimes
shift precision by sampling-scale amounts but impose very large and consistent
tail-latency penalties. The sweep therefore supports 30 seconds among the tested
values.

The exact timeout distribution deserves a later production-design review. This
model uses the paper-aligned exponential form; a hard 30-second timer would have
different origin and latency behavior and is not supported by these results.

## 8. Zero-outbound/reconnect evidence

Nominal N=4/N=8 graphs contain one structurally zero-outbound validator. A stem
can also arrive there after originating elsewhere. Under q=.20/one relay/30s,
the transaction-level zero-outbound encounter rate is:

| N | 5% label | 10% | 20% | 33% | range |
|---:|---:|---:|---:|---:|---:|
| 4 | .470 | .607 | .827 | .612 | 47.0–82.7% |
| 8 | .521 | .478 | .510 | .352 | 35.2–52.1% |
| 20 | .000 | .000 | .000 | .000 | 0% in this run |
| 50 | .000 | .000 | .000 | .000 | 0% in this run |
| 100 | .000 | .000 | .000 | .000 | 0% in this run |
| 200 | .000 | .000 | .000 | .000 | 0% in this run |

For N≥20, eight nominal outbound edges plus only 2% independent transient edge
loss made loss of every eligible outbound edge too rare to observe in 1,000
transactions/cell. Reconnect substitution for individual selected-relay failures
still occurs and is recorded separately in the CSV.

At N=4–8, the fallback is not rare and cannot be treated only as an operational
alert. The current `is_outbound`-only recommendation collides with complete-graph
connection ownership. Before implementation, humans must choose one of:

1. accept frequent three-second fallback fluff and its privacy loss at N≤8;
2. allow an authenticated inbound peer as a stem relay after the bounded reconnect
   attempt; or
3. change connection-direction/relay eligibility semantics for small complete
   sets.

This simulation used option 1 because it was the settled input. It does not
silently switch to inbound relays.

## 9. Coverage and reliability

Mean coverage rounds to 1.000 throughout the sweep. Full-coverage rates for the
recommended candidate are 0.997–0.999 at N=4 and 1.000 at N≥8 in the displayed
cells. Rare N=4 misses arise from transient edge loss plus adversaries refusing
to forward; Dandelion is not the cause of every physical partition.

The high coverage result must be read together with tail latency. Embargo ensures
eventual diffusion under black holes, but an exponential 30-second base can still
produce 80–115-second p99 added latency in several coalition cells. “Eventually
reaches everyone” is not equivalent to “meets a wallet/product latency target.”

## 10. Recommendation and human decision boundary

### Recommended evidence candidate

```text
q = 0.20
relay_count = 1
embargo_base = 30 seconds, exponential randomized per stem holder
```

Rationale:

* **One relay** gives the best first-spy resistance. Two relays expose more first
  hops and generate convergent duplicates; its latency benefit does not justify
  calling it the privacy choice.
* **q=.20** bounds expected normal stem length at five hops. Although q=.10 has
  lower N=8 averages in this finite run, its ten-hop expectation is structurally
  mismatched to N=4–8 and increases dependence on loops, black holes, or fallback.
  q=.20 has the best N=4 privacy averages and was the original paper-supported
  upper bound selected for small-mesh evaluation.
* **30 seconds** has no consistently worse privacy outcome than longer points and
  dramatically reduces p95/p99 black-hole delay. It still incurs nontrivial tail
  latency and should be product-approved explicitly.

### Required wording if approved

The v1 security claim should say:

> Transaction stem relay reduces other validators' confidence in the RPC-entry
> validator. At four validators the protection is weak; a one-validator coalition
> still identifies roughly half of honest entry validators under the modeled
> first-spy attack. Material anonymity-set benefits require a larger validator
> set, with the modeled transition becoming useful around 20 validators for small
> coalitions.

It should not say “hides transaction origin” without those qualifications.

### Still requires human decision

1. Approve or reject the recommended triple; this report does not finalize it.
2. Decide whether p95 added latency of roughly 38–50 seconds at N=4–8 under active
   black holes is acceptable.
3. Decide the small-N zero-outbound policy. The settled immediate-fluff fallback
   is hit frequently enough that inbound-relay fallback deserves explicit review.
4. Decide whether N=4 privacy is worth enabling at all, versus enabling stem mode
   only at N≥8 or N≥20 and documenting immediate flood below that threshold.
5. Validate the assumed 2% transient link-loss and latency distribution against
   real deployment telemetry before treating absolute latency as an SLA.

## 11. Limitations

This is a topology/adversary Monte Carlo model, not a formal proof or packet-level
network emulator. It does not model a global passive observer, wallet-to-RPC
traffic, stake-weighted coalition choice, congestion/queue feedback, validator
geography, TCP retransmission, correlated regional failure, adaptive coalition
placement by centrality, or cross-epoch intersection attacks. The primary settled
threat is colluding validator identities.

Coalition fractions are identity fractions, as requested. At small N they are
quantized. Equal transaction rates per honest validator are assumed. Colluders
black-hole every stem they receive; less aggressive attackers reduce embargo
frequency but may gather observations over longer paths. Relay selections and
coalitions rotate per modeled epoch, while 1,000-cell sample sizes leave ordinary
Monte Carlo noise.

The raw CSV is intentionally richer than the report. Any later decision analysis
should operate on it directly and preserve requested versus realized coalition
fractions.
