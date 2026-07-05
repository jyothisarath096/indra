# Scale-Validation Phase 1 — VRF Timing Windows Under Realistic Latency

## Status

This began as a Step 0 + design artifact. Phase 1's final implementation step
has now applied the recommended timing constants:

- `VRF_COMMIT_WINDOW_MS = 1500`
- `VRF_REVEAL_WINDOW_MS = 1500`
- `VRF_ELECTION_SETTLE_MS = 2500`

Initial result: under a conservative global-latency model layered onto the
existing N=200 partial-mesh relay topology, the previous 500ms commit/reveal
windows reached quorum in moderate loss/jitter cases. The promoted stress
simulation found the binding point: 500ms fails under a non-uniform stake
distribution where high-stake validators sit in a slow region, especially when
combined with regional queuing/bootstrap saturation.

## Step 0 — Current Mechanics Confirmed

### Timing constants

`indra-core/src/types/primitives.rs` defines:

- `VRF_COMMIT_WINDOW_MS = 1_500`
- `VRF_REVEAL_WINDOW_MS = 1_500`
- `VRF_ELECTION_SETTLE_MS = 2_500`
- `MAX_VRF_EMPTY_REVEAL_ROUNDS = 3`
- `MIN_ROUND_TIME_MS = 3_000`
- `MAX_ROUND_TIME_MS = 15_000`

The comments at `primitives.rs:65-84` say the commit/reveal windows close after
the duration or quorum, and the settle window is intentionally longer than the
reveal window so fast prevote quorum does not force nil precommit immediately
before the election result arrives.

### Commit/reveal window behavior

`ConsensusDriver::advance_vrf_round` (`indra-node/src/driver.rs:1244-1307`)
drives the local VRF sub-phases:

1. Commit phase opens reveal when either committed stake reaches quorum or
   `commit_started_at >= VRF_COMMIT_WINDOW_MS`.
2. Reveal phase computes election when either revealed stake reaches quorum or
   `reveal_started_at >= VRF_REVEAL_WINDOW_MS`.
3. If computation returns `None`, the driver calls
   `request_missing_reveals_for_slot`, so reveal recovery runs after the window
   closes.

### Insufficient-data fallback behavior

`compute_and_store_vrf_election` (`indra-node/src/driver.rs:1310-1431`) now
uses one bounded fallback counter for both relevant insufficient-data cases:

- post-reveal-set-activation sub-quorum reveal sets increment
  `consecutive_empty_reveal_rounds` once per `(height, round)` and return
  `None` until `MAX_VRF_EMPTY_REVEAL_ROUNDS` is reached
  (`driver.rs:1322-1345`);
- zero-reveal rounds use the same counter and threshold
  (`driver.rs:1365-1381`);
- once the threshold is reached, `compute_fallback_election_result` is used and
  the reveal evidence set is the canonical empty set (`driver.rs:1345-1354`,
  `driver.rs:1381-1392`);
- quorum-backed success resets the counter (`driver.rs:1417-1422`).

This means the simulation should model a round as successful when a validator
receives quorum-sufficient reveal stake before its reveal window closes. A
failed round does not wait forever; it contributes to the fixed 3-round Option-D
fallback bound while still attempting reveal recovery.

### Reveal recovery path

`request_missing_reveals_for_slot` (`indra-node/src/driver.rs:977-1009`) emits
`DriverAction::RequestVrfReveals` when reveal-set commitment is active and local
revealed stake is below quorum. The request path is debounced by
`should_emit_vrf_reveal_request` (`driver.rs:958-974`), so a simulation should
count recovery attempts as concurrent with, not a replacement for, fallback
accounting.

### Precommit settle behavior

If precommit is reached before a local election result exists,
`sign_and_record_local_vote` delays nil precommit until
`VRF_ELECTION_SETTLE_MS` has elapsed since entering precommit
(`indra-node/src/driver.rs:1988-2023`). If the election result appears during
that settle window, the node can sign the block precommit; otherwise it casts a
nil precommit after 1.5s.

`retry_precommit_if_waiting` (`driver.rs:1450-1458`) is called by the node loop
during precommit (`indra-node/src/bin/node.rs:2294-2308`), so the settle window
is actively retried.

### Relation to round timeouts

The live node loop currently uses:

- `PROPOSE_TIMEOUT = 8s`
- `PREVOTE_TIMEOUT = 3s`
- `PRECOMMIT_TIMEOUT = 3s`

These are defined in `indra-node/src/bin/node.rs:47-49` and drive the phase loop
at `node.rs:1990-2264`, `node.rs:2278-2291`, and `node.rs:2294-2308`.

`MIN_ROUND_TIME_MS` and `MAX_ROUND_TIME_MS` are present in core constants, but a
repo-wide call-site search found:

- `MAX_ROUND_TIME_MS` has no active reference outside its definition and this
  document.
- `MIN_ROUND_TIME_MS` is referenced only by
  `bench_pre_relay_verification_cost_n200`
  (`indra-network/src/peer_manager.rs:2764-2765`) as a benchmark assertion that
  800 pre-relay verifications should take less than the nominal minimum round
  time. It is not used to drive consensus round timing.

So these constants are vestigial with respect to live consensus timing. The
200-validator audit table's characterization of them as active round bounds
should be corrected in a documentation/cleanup follow-up. The VRF windows are
sub-phase timers inside the proposer/VRF election path; outer round progress is
governed by the node loop's propose/prevote/precommit phase timers and the fixed
3-round fallback threshold.

## Reusing the Existing Relay Simulation

The existing N=200 relay simulation is directly reusable as the topology layer.
`partial_mesh_propagates_to_quorum_at_n200_realistic_topology`
(`indra-network/src/peer_manager.rs:2062-2240`) already builds:

- a bounded random graph with `TARGET_OUTBOUND = 8` and `MAX_INBOUND = 64`;
- a bootstrap-first graph that reflects the real hub-and-spoke startup shape;
- the same derived relay fanout used by production
  (`derive_consensus_relay_fanout`, `peer_manager.rs:368-375`);
- the same block fanout multiplier path used for block relay.

For this phase, the right approach is to extend this model rather than build a
parallel simulator:

1. keep the existing topology generation and fanout derivation;
2. assign each simulated validator a geographic region;
3. assign each edge a one-way latency based on the endpoint regions;
4. run weighted earliest-arrival propagation for commit messages;
5. derive each validator's local reveal-window start from either commit quorum
   arrival or `VRF_COMMIT_WINDOW_MS`;
6. run weighted earliest-arrival propagation for reveal messages;
7. measure quorum-sufficient reveals by each validator's local reveal deadline.

## Latency Model Basis

This design should not use the current four-node testnet latency as evidence;
those nodes are low-latency and same-provider.

Recommended source basis:

- physical propagation in ordinary telecom fiber is approximately
  180,000-200,000 km/s, or roughly 5.0-5.5 microseconds/km
  ([fiber-optic cable propagation reference](https://en.wikipedia.org/wiki/Fiber-optic_cable));
- the speed of light page gives the same order of magnitude and notes that
  real routes are longer than geodesic shortest paths because fiber paths are
  not straight and include equipment delays
  ([speed-of-light latency discussion](https://en.wikipedia.org/wiki/Speed_of_light));
- Bozkurt et al., *Dissecting Latency in the Internet's Fiber Infrastructure*,
  report a common Internet-latency rule of thumb: line-of-sight distance
  multiplied by routing inflation before dividing by fiber speed
  ([arXiv:1811.10737](https://arxiv.org/abs/1811.10737));
- CloudCast measured thousands of public-cloud inter-region links and is a good
  follow-up source if this phase is later calibrated to cloud-provider regions
  rather than physical bounds
  ([arXiv:2201.06989](https://arxiv.org/abs/2201.06989)).

For the preliminary simulation below, validators were assigned to six global
clusters:

- North America East: 40
- North America West: 35
- Europe West: 45
- South Asia/India: 30
- East Asia/Singapore: 30
- South America: 20

The p50 one-way matrix used conservative WAN values derived from fiber lower
bounds plus routing overhead, with same-region 8ms and long cross-region paths
up to 145ms one-way. A stressed-tail model added deterministic jitter of up to
75% plus 10ms per edge.

## Promoted Simulation Test

The deterministic Rust simulation lives in
`indra-network/src/peer_manager.rs` as:

- `partial_mesh_propagates_to_quorum_at_n200_realistic_topology` — default
  topology/hop-count regression;
- `vrf_timing_windows_under_n200_latency_stress` — ignored by default because
  it is a full N=200 weighted propagation stress simulation. Run explicitly
  with:
- `vrf_timing_windows_finalization_cost_margin_and_settle` — ignored by
  default; quantifies normal-case cost, 1500ms stress margin, and settle-window
  consistency. Run explicitly with:

```bash
cargo test -p indra-network \
  peer_manager::tests::vrf_timing_windows_under_n200_latency_stress \
  -- --ignored --nocapture

cargo test -p indra-network \
  peer_manager::tests::vrf_timing_windows_finalization_cost_margin_and_settle \
  -- --ignored --nocapture
```

The stress test reuses the same topology helpers and fanout derivation as the
relay simulation. It is intentionally deterministic: no random seed or wall
clock behavior affects pass/fail.

## Simulation Results

These numbers come from the promoted deterministic simulation unless marked
otherwise.

The model included:

- N=200 validators, equal stake;
- quorum threshold `ceil(2N/3) = 134`;
- `TARGET_OUTBOUND=8`, `MAX_INBOUND=64`;
- base relay fanout 13;
- 2ms per-hop relay processing overhead;
- commit-window start skew: each validator opens reveal at
  `min(commit-quorum-arrival-time, commit_window)`;
- reveal success measured at each validator's local
  `reveal_start + reveal_window` deadline.

### Moderate latency/loss baseline

The initial p50/stressed-tail model from the Step 0 pass showed that, without
loss/stake skew/congestion strong enough to bind the window, 500ms clears
quorum. That remains true in the promoted test for packet loss alone:

| Scenario | Window | Validators with reveal quorum | Stake min / median / max | Worst compute time |
| --- | ---: | ---: | --- | ---: |
| 1% loss | 500ms | 200/200 | 200 / 200 / 200 | 469.7ms |
| 1% loss | 750ms | 200/200 | 200 / 200 / 200 | 469.7ms |
| 1% loss | 1000ms | 200/200 | 200 / 200 / 200 | 469.7ms |
| 1% loss | 1500ms | 200/200 | 200 / 200 / 200 | 469.7ms |
| 5% loss | 500ms | 200/200 | 200 / 200 / 200 | 482.8ms |
| 5% loss | 750ms | 200/200 | 200 / 200 / 200 | 482.8ms |
| 5% loss | 1000ms | 200/200 | 200 / 200 / 200 | 482.8ms |
| 5% loss | 1500ms | 200/200 | 200 / 200 / 200 | 482.8ms |

Packet loss alone at 1-5% is not enough to bind 500ms under the modeled relay
fanout and topology.

### Regional queuing and bootstrap saturation

| Scenario | Window | Validators with reveal quorum | Stake min / median / max | Worst compute time |
| --- | ---: | ---: | --- | ---: |
| East Asia queue spike | 500ms | 200/200 | 170 / 170 / 174 | 869.0ms |
| East Asia queue spike | 750ms | 200/200 | 170 / 170 / 175 | 869.0ms |
| East Asia queue spike | 1000ms | 200/200 | 174 / 184 / 194 | 869.0ms |
| East Asia queue spike | 1500ms | 200/200 | 200 / 200 / 200 | 869.0ms |
| Bootstrap saturation | 500ms | 200/200 | 199 / 199 / 200 | 887.2ms |
| Bootstrap saturation | 750ms | 200/200 | 199 / 199 / 200 | 887.2ms |
| Bootstrap saturation | 1000ms | 200/200 | 199 / 199 / 200 | 887.2ms |
| Bootstrap saturation | 1500ms | 200/200 | 200 / 200 / 200 | 887.2ms |

These scenarios increase absolute compute time, but local reveal windows still
reach quorum at 500ms because enough stake remains available through alternate
paths. Longer windows improve completeness of the reveal set, but not quorum
success.

### Binding scenarios: high-stake slow region

| Scenario | Window | Validators with reveal quorum | Stake min / median / max | Worst compute time |
| --- | ---: | ---: | --- | ---: |
| Slow region holds high stake | 500ms | 0/200 | 50 / 180 / 250 | 1000.0ms |
| Slow region holds high stake | 750ms | 84/200 | 230 / 780 / 980 | 1500.0ms |
| Slow region holds high stake | 1000ms | 84/200 | 230 / 780 / 980 | 2000.0ms |
| Slow region holds high stake | 1500ms | 200/200 | 1180 / 1180 / 1180 | 2256.5ms |
| Combined tail | 500ms | 0/200 | 1 / 149 / 250 | 1000.0ms |
| Combined tail | 750ms | 74/200 | 150 / 774 / 1030 | 1500.0ms |
| Combined tail | 1000ms | 74/200 | 150 / 774 / 1030 | 2000.0ms |
| Combined tail | 1500ms | 200/200 | 1180 / 1180 / 1180 | 2322.8ms |

This is the point where window choice starts to matter. The previous 500ms
window is not robust to a plausible mainnet stake/latency skew where a
geographically slow region carries disproportionate voting power. In the
combined-tail scenario, 750ms/1000ms improve over 500ms but still do not fully
recover; 1500ms is the first tested value that restores 200/200 quorum
availability.

## Finalization Analysis — Cost, Margin, and Settle Interaction

### Normal-case cost of 1500ms/1500ms

The finalization simulation compares the previous 500ms/500ms baseline against
the now-applied 1500ms/1500ms values under the non-stressed p50 model.

| Window | Validators with reveal quorum | Window hits commit / reveal | Average compute | Worst compute |
| ---: | ---: | ---: | ---: | ---: |
| 500ms | 200/200 | 0 / 0 | 398.3ms | 468.1ms |
| 1500ms | 200/200 | 0 / 0 | 398.3ms | 468.1ms |

Measured normal-case average delta: **0.0ms**.

Measured normal-case worst observed delta: **0.0ms**.

Interpretation: in normal p50 conditions, quorum arrives before either the
500ms or 1500ms ceiling, so raising the ceilings does not slow the common case
in this model. The theoretical worst case remains up to +2000ms per affected
round if both commit and reveal phases hit their ceilings, but the modeled
normal case has zero ceiling hits.

### 1500ms margin under worse slow-region severity

The previous stress test used a +420ms slow-region penalty with 50x stake in
South America. The finalization test sweeps the slow-region penalty while
keeping the high-stake distribution fixed.

| Slow-region extra delay | Validators with reveal quorum at 1500ms | Window hits commit / reveal | Stake min / median / max | Worst compute |
| ---: | ---: | ---: | --- | ---: |
| +420ms | 200/200 | 0 / 0 | 1180 / 1180 / 1180 | 2256.5ms |
| +500ms | 200/200 | 0 / 0 | 1180 / 1180 / 1180 | 2576.5ms |
| +600ms | 200/200 | 0 / 0 | 830 / 1030 / 1180 | 2976.5ms |
| +700ms | 84/200 | 20 / 116 | 230 / 780 / 980 | 3000.0ms |
| +800ms | 84/200 | 20 / 116 | 230 / 780 / 980 | 3000.0ms |
| +900ms | 84/200 | 20 / 116 | 230 / 780 / 980 | 3000.0ms |
| +1000ms | 84/200 | 20 / 116 | 230 / 780 / 980 | 3000.0ms |

Finding: 1500ms is not a bare pass, but it is not unbounded margin either. It
survives the modeled +420ms case and a moderately worse +600ms case, then
breaks at +700ms. That gives roughly **+180ms of extra modeled slow-region delay
margin** beyond the originally failing stress case.

Stake-concentration sweep at the original +420ms delay:

| Slow-region stake multiplier | Validators with reveal quorum at 1500ms | Window hits commit / reveal | Stake min / median / max | Worst compute |
| ---: | ---: | ---: | --- | ---: |
| 50x | 200/200 | 0 / 0 | 1180 / 1180 / 1180 | 2256.5ms |
| 75x | 200/200 | 0 / 0 | 1680 / 1680 / 1680 | 2256.5ms |
| 100x | 200/200 | 0 / 0 | 2180 / 2180 / 2180 | 2256.5ms |

Interpretation: in this model, delay severity is the binding dimension once the
slow region already dominates stake. Increasing the slow region's stake
multiplier does not itself hurt quorum as long as those high-stake reveals
arrive within the window.

### Settle-window interaction

The current relationship is:

- `VRF_REVEAL_WINDOW_MS = 1500`
- `VRF_ELECTION_SETTLE_MS = 2500`
- settle margin over reveal window = `+1000ms`

The original design comment says settle is intentionally longer than the reveal
window so a fast prevote quorum does not force nil precommit just before reveal
timeout computes the election.

If reveal moved to 1500ms while settle stayed at 1500ms, that design intent
would be violated: settle would be equal to reveal, not longer. The simulation
also shows 1500ms-window stressed cases whose absolute election compute time
reaches roughly 2.26-2.32s from the start of the commit/reveal sequence. That
does not directly translate one-for-one into precommit-settle elapsed time,
because settle starts when precommit phase begins, but it is enough to reject a
no-margin equal-settle design.

To preserve the existing relationship, the mechanically consistent value is:

```text
new_settle = new_reveal_window + old_settle_margin
           = 1500ms + (1500ms - 500ms)
           = 2500ms
```

The applied constant set therefore uses **2500ms** settle, not 1500ms.

### Asymmetric latency

| Scenario | Window | Validators with reveal quorum | Stake min / median / max | Worst compute time |
| --- | ---: | ---: | --- | ---: |
| Asymmetric latency | 500ms | 200/200 | 200 / 200 / 200 | 507.8ms |
| Asymmetric latency | 750ms | 200/200 | 200 / 200 / 200 | 507.8ms |
| Asymmetric latency | 1000ms | 200/200 | 200 / 200 / 200 | 507.8ms |
| Asymmetric latency | 1500ms | 200/200 | 200 / 200 / 200 | 507.8ms |

Asymmetry alone does not bind the window in this model. It can push absolute
compute time over 500ms, but the correct success metric is stake received by
each validator's local reveal deadline, not a single global timestamp.

### Initial throwaway model, retained for comparison

#### Bootstrap-first topology

| Model | Window | Validators with reveal quorum | Reveal-count min / median / max | Worst compute time |
| --- | ---: | ---: | --- | ---: |
| p50 | 500ms | 200/200 | 200 / 200 / 200 | 313ms |
| p50 | 750ms | 200/200 | 200 / 200 / 200 | 313ms |
| p50 | 1000ms | 200/200 | 200 / 200 / 200 | 313ms |
| p50 | 1500ms | 200/200 | 200 / 200 / 200 | 313ms |
| stressed tail | 500ms | 200/200 | 200 / 200 / 200 | 466ms |
| stressed tail | 750ms | 200/200 | 200 / 200 / 200 | 466ms |
| stressed tail | 1000ms | 200/200 | 200 / 200 / 200 | 466ms |
| stressed tail | 1500ms | 200/200 | 200 / 200 / 200 | 466ms |

### Random bounded topology

| Model | Window | Validators with reveal quorum | Reveal-count min / median / max | Worst compute time |
| --- | ---: | ---: | --- | ---: |
| p50 | 500ms | 200/200 | 200 / 200 / 200 | 318ms |
| p50 | 750ms | 200/200 | 200 / 200 / 200 | 318ms |
| p50 | 1000ms | 200/200 | 200 / 200 / 200 | 318ms |
| p50 | 1500ms | 200/200 | 200 / 200 / 200 | 318ms |
| stressed tail | 500ms | 200/200 | 200 / 200 / 200 | 472ms |
| stressed tail | 750ms | 200/200 | 200 / 200 / 200 | 472ms |
| stressed tail | 1000ms | 200/200 | 200 / 200 / 200 | 472ms |
| stressed tail | 1500ms | 200/200 | 200 / 200 / 200 | 472ms |

Interpretation:

- The initial model was useful because it showed the happy-path margin was
  narrow, but it did not bind the window.
- The promoted stress scenarios do bind the window once stake distribution is
  non-uniform and the high-stake region is slow.
- The old `VRF_ELECTION_SETTLE_MS=1500ms` value was adequate for moderate
  latency/loss, but it did not preserve the intended margin once the reveal
  window moved to 1500ms. The applied `VRF_ELECTION_SETTLE_MS=2500ms` keeps the
  original +1000ms margin over the reveal window.

## Measurement Methodology for the Follow-Up Implementation

The follow-up implementation should add a deterministic Rust simulation test or
bench module rather than a standalone script.

For each topology and latency model:

1. Build the existing N=200 bootstrap-first graph.
2. Optionally also keep the random bounded graph as a comparison baseline.
3. Assign validators to configurable region distributions.
4. For each simulated round:
   - every validator broadcasts a VRF commit at t=0;
   - propagate commits through the relay graph with edge latency and relay-hop
     processing delay;
   - each validator opens reveal at the earlier of commit quorum arrival or the
     configured commit-window deadline;
   - every validator broadcasts a VRF reveal at its local reveal-open time;
   - propagate reveals through the same relay graph;
   - record, for each validator, revealed stake received by its local reveal
     deadline.
5. Sweep window pairs:
   - 500ms / 500ms
   - 750ms / 750ms
   - 1000ms / 1000ms
   - 1500ms / 1500ms
6. Report:
   - percentage of validators with reveal quorum by window close;
   - expected proposer-success probability, approximated by the same percentage
     under uniform proposer selection, or stake-weighted if a non-uniform stake
     distribution is added;
   - p50/p95/p99 election-compute times;
   - number of consecutive insufficient rounds before fallback under each
     latency/loss profile;
   - whether precommit settle (`VRF_ELECTION_SETTLE_MS`) covers p99 election
     availability with adequate margin.

The implementation should also add stress scenarios not included in the quick
model:

- 1-5% message loss with relay retry disabled;
- regional queuing spikes;
- temporary bootstrap-node saturation;
- non-uniform stake distribution, including high-stake validators placed in a
  high-latency region;
- asymmetric latency, because Internet paths are not guaranteed symmetric.

## Updated Recommendation

The follow-up constant-change task applied the recommended mutually consistent
set. No further Phase 1 timing-window change is recommended without a new
simulation result.

Final Phase 1 recommendation:

1. 500ms/500ms is adequate only under equal-stake or moderately stressed global
   latency assumptions.
2. 500ms/500ms is not adequate under the modeled high-stake slow-region stress
   scenario.
3. 750ms/1000ms are partial improvements, not complete fixes, under the harshest
   combined-tail scenario.
4. 1500ms/1500ms is the first tested window pair that fully restores quorum in
   the high-stake slow-region and combined-tail scenarios.
5. Normal-case measured cost of 1500ms/1500ms is 0ms in the p50 model because
   quorum resolves early; worst-case affected rounds can still pay up to +2000ms
   if both windows hit their ceilings.
6. 1500ms has real but finite margin: it survives the originally modeled +420ms
   slow-region delay and a +600ms variant, then breaks at +700ms.
7. The mutually consistent constant set is now applied:
   - `VRF_COMMIT_WINDOW_MS = 1500`
   - `VRF_REVEAL_WINDOW_MS = 1500`
   - `VRF_ELECTION_SETTLE_MS = 2500`
8. If 1500ms/1500ms is considered too expensive for worst-case round latency,
   the accepted tradeoff should be stated explicitly: shorter windows rely on
   the fixed 3-round fallback under adverse stake/latency geography.
