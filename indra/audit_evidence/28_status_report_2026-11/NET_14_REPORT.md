Across all nine preserved runs, the quorum-side round at the restart/resume boundary was 20 for the two 300-second pauses, 62 for the 900-second pause, and 8 for every restart run; the first height-4 commit was 1–5 rounds later, with recovery of 13.39–69.43 seconds. The evidence supports a bounded post-join cost in these runs (one round per roughly 11–14 seconds, nominally 8+3+3 seconds), and does not establish a proposer-selection or relay defect.

## Scope and unfinished fields

This is an analysis-only report. No Rust source, build artifact, preserved run directory, or live node was changed. The attached NET_14 instructions are treated as task constraints; the user request is the request to implement NET_14, which here means producing this report.

The requested proposer identity cannot be computed from the preserved logs under the “read saved logs only” constraint. The logs contain no proposer-election result, proposer VRF output/proof, election seed/snapshot-root record for each failed `(height, round)`, or proposal sender identity. Therefore the proposer, proposer-side proposal presence, and a proposer-specific prevote explanation are deliberately reported as **not derivable**, not guessed. This leaves those required fields unfinished pending an evidence run that records the election result or the complete public inputs plus VRF results.

## Measurement definition

For pause runs, time zero is `timeline.log` `t_cont t_ms`; for restart runs, it is `timeline.log` `t_restart t_ms`. The quorum-side round is the common last `[timing] ROUND ADVANCED` round for nodes 0, 2, and 3 at or before that timestamp. The post-join round is the first round supported by node 1 at the same height-4 recovery sequence: the explicit `stake-supported round advance` target (or, for the two 300-second pauses, the first target at/above the side’s round). “Failed rounds” is defined as `commit_round - join_round`: the rounds after node 1 has joined the quorum-side round and before the committing round.

The height-4 commit round is taken from node 1’s `[commit] finalizing ... height=4 round=...` line. Recovery seconds are the preserved harness `recovery_seconds` value, cross-checked against `t_first_block_after_cont`.

## Nine-run result

| run | t0 state `(n0,n1,n2,n3)` round/height | join round | commit `(height,round)` | failed rounds | recovery s | s / failed round |
|---|---|---:|---:|---:|---:|---:|
| `net11-stop300` | `(20/3, 5/2, 20/3, 20/3)` | 20 | `(4,21)` | 1 | 13.390 | 13.390 |
| `o-net12-stop300` | `(20/3, 6/2, 20/3, 20/3)` | 20 | `(4,24)` | 4 | 44.670 | 11.168 |
| `net11-pause900` | `(62/3, 2/2, 62/3, 62/3)` | 62 | `(4,67)` | 5 | 65.057 | 13.011 |
| `restart-1` | `(2/2, 2/2, 8/3, 8/3)` | 8 | `(4,12)` | 4 | 58.091 | 14.523 |
| `restart-2` | `(1/1, 1/1, 8/3, 8/3)` | 8 | `(4,12)` | 4 | 60.315 | 15.079 |
| `restart-3` | `(6/1, 6/1, 8/3, 8/3)` | 8 | `(4,10)` | 2 | 35.936 | 17.968 |
| `restart-4` | `(5/0, 5/0, 8/3, 8/3)` | 8 | `(4,11)` | 3 | 47.201 | 15.734 |
| `restart-5` | `(8/1, 8/1, 8/3, 8/3)` | 8 | `(4,10)` | 2 | 36.047 | 18.024 |
| `restart-6` | `(2/2, 2/2, 8/3, 8/3)` | 8 | `(4,13)` | 5 | 69.433 | 13.887 |

The restart table’s per-round ratio includes connection/restart and event-placement overhead, so it is not expected to equal exactly 14 seconds. The round-transition timing lines in the logs are generally about 11.1–11.5 seconds apart; the protocol phase budget requested for analysis is 8+3+3 = 14 seconds.

## Defining evidence lines

### Pause runs

At `net11-stop300`, nodes 0/2/3 last logged round 20 at height 3 immediately before `t_cont=1795180860855`; node 1 was still at height 3 round 5 before it stopped. Node 1 then recorded:

```text
[consensus] stake-supported round advance: 19 → 20 at height=4 (>1/3 evidence)
[consensus] stake-supported round advance: 20 → 21 at height=4 (>1/3 evidence)
[commit] finalizing 43ded927 at height=4 round=21
[timing] t=1795180872412ms HEIGHT ADVANCED to 4 (was 3)
```

At `o-net12-stop300`, nodes 0/2/3 last logged round 20 at height 3 immediately before `t_cont=1795199177898`; node 1 was at height 3 round 6. The relevant node-1 lines are:

```text
[consensus] stake-supported round advance: 19 → 20 at height=4 (>1/3 evidence)
[consensus] stake-supported round advance: 20 → 21 at height=4 (>1/3 evidence)
[consensus] stake-supported round advance: 21 → 22 at height=4 (>1/3 evidence)
[timing] t=1795199210550ms ROUND ADVANCED to 23 at height=3
[timing] t=1795199221965ms ROUND ADVANCED to 24 at height=3
[commit] finalizing 6b316b51 at height=4 round=24
[timing] t=1795199222410ms HEIGHT ADVANCED to 4 (was 3)
```

At `net11-pause900`, nodes 0/2/3 last logged round 62 at height 3 immediately before `t_cont=1795190276087`; node 1 was at height 3 round 2. The defining jump and commit are:

```text
[consensus] stake-supported round advance: 18 → 19 at height=4 (>1/3 evidence)
[consensus] stake-supported round advance: 19 → 62 at height=4 (>1/3 evidence)
[timing] t=1795190294407ms ROUND ADVANCED to 63 at height=3
[timing] t=1795190305766ms ROUND ADVANCED to 64 at height=3
[timing] t=1795190317132ms ROUND ADVANCED to 65 at height=3
[timing] t=1795190328394ms ROUND ADVANCED to 66 at height=3
[timing] t=1795190339660ms ROUND ADVANCED to 67 at height=3
[commit] finalizing 59c3e5c8 at height=4 round=67
[timing] t=1795190340039ms HEIGHT ADVANCED to 4 (was 3)
```

The 900-second pause therefore demonstrates the NET6 jump directly. The two 300-second pauses do not show a single large jump: node 1 receives successive one-round stake-supported advances through the height-4 recovery path.

### Restart runs

All six restart timelines record `t_restart` after a 120-second node-1 outage. In every run, node 1’s first height-4 support line is `0 → 8`, while nodes 2 and 3 were at round 8/height 3 at restart time:

```text
run-1: [consensus] stake-supported round advance: 0 → 8 at height=4 (>1/3 evidence)
       [commit] finalizing c5310c82 at height=4 round=12
run-2: [consensus] stake-supported round advance: 0 → 8 at height=4 (>1/3 evidence)
       [commit] finalizing f49de82f at height=4 round=12
run-3: [consensus] stake-supported round advance: 0 → 8 at height=4 (>1/3 evidence)
       [commit] finalizing 8d3431c2 at height=4 round=10
run-4: [consensus] stake-supported round advance: 0 → 8 at height=4 (>1/3 evidence)
       [commit] finalizing 3c83b10c at height=4 round=11
run-5: [consensus] stake-supported round advance: 0 → 8 at height=4 (>1/3 evidence)
       [commit] finalizing 7ea48864 at height=4 round=10
run-6: [consensus] stake-supported round advance: 0 → 8 at height=4 (>1/3 evidence)
       [commit] finalizing 6e6fcf12 at height=4 round=13
```

The preserved `harness.out` summaries give recovery values `58.091, 60.315, 35.936, 47.201, 36.047, 69.433` seconds respectively, with all four nodes reaching the target and no panic/stale-sync/exit failures.

## Failed-round attribution: what is and is not evidenced

The failed-round sets are the rounds after the join round and before the committing round; the count is still `commit_round - join_round`:

```text
net11-stop300:       {21 - 20}                 = {20}
o-net12-stop300:     {24 - 20}                 = {20..23}
net11-pause900:      {67 - 62}                = {62..66}
restart-1:           {12 - 8}                 = {8..11}
restart-2:           {12 - 8}                 = {8..11}
restart-3:           {10 - 8}                 = {8..9}
restart-4:           {11 - 8}                 = {8..10}
restart-5:           {10 - 8}                 = {8..9}
restart-6:           {13 - 8}                 = {8..12}
```

For each listed round, the exact missing datum is the proposer identity. `indra-consensus/src/proposer.rs:60-94` constructs candidates from the governing snapshot; `:98-110` derives the exact alpha from chain id, election seed, height, round, snapshot root, and candidate id; `:113-125` requires the candidate’s VRF keypair to produce/evaluate the slot result. The saved node logs do not record that result or the required per-round VRF proof/output. Consequently it is not possible, from these preserved logs alone, to answer “which validator proposed” or to test whether that validator was node 1.

Likewise, no preserved line identifies a proposal sender for every failed round. The available `[vote]` lines show local produced/broadcast votes, but do not provide a complete, sender-attributed prevote set for each `(height=4, round)`; the logs therefore cannot distinguish “proposal not received before propose timeout” from “received a different-round proposal” or “nil prevotes” for every failed round. The exact requested per-round attribution is intentionally stopped here.

The saved evidence does show both kinds of post-join outcome: other-round activity exists, and failed rounds are not limited by a proven node-1-proposer condition. It does **not** prove the reason for any particular failed round. No `rate_limit_drop`/relay-window line is established as the causal reason for the post-join failed rounds. There are ordinary P2P tie-break “dropping new connection” lines, and the pause-resume window contains rate-limit drops around mesh reformation, but the preserved logs do not correlate those drops to a particular failed `(height, round)`.

## Code reasoning and bound

The relevant round-sync rule is `indra-node/src/driver.rs:1086-1108`: once a verified target has more than one third of registered stake, `maybe_advance_to_stake_supported_round` calls `start_round(target_round)` and then attempts the local prevote. The certified-round path at `indra-node/src/driver.rs:1842-1897` requires a target within `current_round + MAX_ACCEPTED_ROUND_JUMP` and a strict two-thirds stake certificate before starting that round. `MAX_ACCEPTED_ROUND_JUMP` is 8 at `indra-core/src/types/primitives.rs:63-65`.

The commit rule is `indra-node/src/driver.rs:2106-2122` and `:2247-2256`: the block must be staged, the precommit collector must produce a valid QC, and only then does the engine commit and log the finalizing height/round. A failed round costs the propose, prevote, and precommit phases; the requested nominal budget is 14 seconds, while these logs show roughly 11.1–11.5-second round transitions.

The evidence supports a conditional bound after a usable verified round target is received: a node can jump to the quorum-side round when the one-third evidence path accepts it, then the remaining cost is the observed number of rounds until a proposer/QC succeeds. It does not establish a universal fixed bound on the number of failed proposer rounds, because proposer eligibility and message arrival are not recorded sufficiently here. The 900-second pause’s `19 → 62` jump proves that pause duration itself does not force 186 sequential catch-up rounds; both 300-second runs instead show sequential advances in the saved node-1 log.

## Recommendation

Treat the observed 13–65-second pause recovery and 36–69-second restart recovery as protocol-inherent/acceptable for this evidence set, subject to the missing proposer instrumentation. The logs do not justify a networking fix or a consensus-visible change. If a defect investigation continues, the next evidence-only run should record `(height, round, proposer_id, eligible, priority, vrf proof/output)` plus sender-attributed proposal and vote events; only then should a code fix be proposed.

## Status

This report is the only file added for NET_14. Existing untracked audit artifacts and preserved evidence were left untouched.
