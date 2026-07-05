# CS-05 Commit-Reveal VRF — Implementation Audit

## Executive Summary

The current CS-05 commit-reveal implementation is materially safer than the pre-fix proposer election: the multi-winner perspective bug is gone, non-nil precommits now require an `election_result_hash`, QC construction refuses mixed election-result attestations, and sync verifies that a commit-reveal block header certifies the claimed proposer identity/output.

No direct consensus safety break was found. Full `block_hash()` voting remains the decisive safety boundary, and a forged proposer result cannot make honest validators precommit unless it matches their locally computed commit-reveal result.

Fix status update:

- **VRF-03 — FIXED:** non-nil precommit no longer immediately falls back to nil when the local VRF election result is missing. The driver now waits up to `VRF_ELECTION_SETTLE_MS = 2500ms`, retries during the precommit phase, and only nil-precommits after the settle window expires.
- **VRF-04 — FIXED / HEIGHT-GATED:** post-activation proposals carry the exact signed reveal evidence set in the block body, and voters verify the proposer-specified set instead of each validator's local reveal view. The reveal set must represent quorum stake and its Merkle commitment is folded into `election_result_hash`.
- **VRF-05 — FIXED:** before finalizing a precommit quorum, the driver now verifies that the subgroup agreeing on `(block_hash, election_result_hash)` independently reaches consensus quorum. Mixed election-result precommits no longer feed a QC build that later fails.
- **VRF-06 — FIXED:** zero-reveal fallback now matches the mainnet-grade policy: fallback is produced only after `MAX_VRF_EMPTY_REVEAL_ROUNDS = 3` consecutive empty reveal rounds. Earlier empty rounds produce no election result and advance normally.
- **VRF-07 — FIXED / HEIGHT-GATED:** post-activation blocks contain durable reveal evidence sufficient for a syncing/auditing node to reconstruct and verify the reveal-set commitment and election result from block data alone.

The main remaining issues are liveness/performance and larger-validator-set scalability:

1. The node loop enforces a 6-second minimum interval before proposing, which dominates the theoretical 1-second VRF window and explains the observed ~6-12 second block times.
2. Commit/reveal gossip remains O(n) signed messages per round before gossip fanout. The new reveal-set body evidence is modest at the current and planned active-set bounds, but larger-validator-set benchmarking remains required before increasing limits.

Overall status: the previously open VRF timing/quorum/fallback correctness issues are fixed for testnet operation. VRF-04/VRF-07 are implemented behind `REVEAL_SET_COMMITMENT_HEIGHT`; the activation height is intentionally unscheduled until coordinated validator deployment is approved.

## Investigation 1: Pipelining

### 1.1 Is pipelining implemented for next-height?

No. The implementation has current/next-round state for the same height, not next-height pipelining.

Evidence:

- `start_round` sets `height = self.next_height()` and stores `vrf_states[0]` for `(height, round)` and `vrf_states[1]` for `(height, round + 1)` only. It also retains local VRF outputs only for that same `height` and the current/next round (`indra-node/src/driver.rs:569-584`).
- `ensure_vrf_election_for_round` creates/broadcasts a commit for the `ProposerElection` it is passed, and the node loop passes `height = d.engine.state.height + 1`, i.e. the current next block after the previous height has already committed (`indra-node/src/bin/node.rs:1826-1866`).
- There is no path found that starts VRF commit/reveal for height `N+1` while height `N` is in prevote/precommit. The only pre-allocation is `round + 1` at the same height.

Conclusion: the implemented “pipelining” is next-round pipelining, not next-height pipelining. This is a liveness/performance gap: every new height must start its commit-reveal sequence after the parent commits.

Severity: Medium, performance/liveness.

### 1.2 Minimum latency per block

Current theoretical sequence:

1. Height `N-1` commits; `finalize_block_on_quorum` calls `start_round(0)` for height `N` during finalization cleanup (`indra-node/src/driver.rs:2045-2077`).
2. Node loop enters `RoundPhase::Propose`.
3. Node loop calls `ensure_vrf_election_for_round`, which broadcasts local `VrfCommit` and drives `advance_vrf_round` (`indra-node/src/bin/node.rs:1825-1866`, `indra-node/src/driver.rs:823-847`).
4. Commit window closes when committed stake reaches quorum or `VRF_COMMIT_WINDOW_MS = 1500ms` elapses (`indra-node/src/driver.rs:855-870`, `indra-core/src/types/primitives.rs:65-69`).
5. Reveal window closes when revealed stake reaches quorum or another 1500ms elapses (`indra-node/src/driver.rs:881-891`).
6. Election result is computed and stored (`indra-node/src/driver.rs:914-950`).
7. Elected proposer can propose only when `election_result` exists (`indra-node/src/bin/node.rs:1867-1885`).
8. Normal prevote/precommit/finalization follows.

VRF theoretical lower bound under prompt delivery is roughly one network/loop turn plus 0-3000ms: if 2/3 commit and reveal stake arrives quickly, both windows can close before timeout; otherwise the timeout path costs 1500ms + 1500ms.

The observed 6-12 seconds is primarily explained by `MIN_BLOCK_INTERVAL_SECS = 6`, enforced before producing a proposal (`indra-node/src/bin/node.rs:45-48`, `indra-node/src/bin/node.rs:1927-1944`). If a round misses and advances, add `PROPOSE_TIMEOUT = 8s`, `PREVOTE_TIMEOUT = 3s`, or `PRECOMMIT_TIMEOUT = 3s` depending on where it stalls (`indra-node/src/bin/node.rs:45-47`, `indra-node/src/bin/node.rs:2043-2085`).

### 1.3 Does the precommit gate add unnecessary latency?

The gate is necessary for safety, and the previously identified nil-precommit race is fixed.

The local non-nil precommit path now requires a local VRF election result. If missing, it delays nil precommit for `VRF_ELECTION_SETTLE_MS = 2500ms`. During that wait, the node loop retries the precommit path, and the driver also retries immediately when an election result arrives while already in precommit phase and the local validator has not yet precommitted.

The fixed behavior is:

- Precommit phase can begin immediately when prevote quorum arrives (`indra-node/src/driver.rs:1886-1902`).
- If the election result is missing, the validator does not cast a nil vote immediately.
- If the election result arrives during the settle window, the validator casts the block precommit with `Some(election_result_hash)`.
- If the election result remains unavailable after the settle window, the validator casts a nil precommit to avoid signing a block precommit without election attestation.

This adds at most 2.5 seconds to the affected edge case and avoids wasting a full round solely because precommit outran local election computation.

Status: Fixed.

## Investigation 2: Safety

### 2.1 Can validators disagree on the election result?

Yes, at the ephemeral VRF layer, validators can compute different election results if they observe different valid reveal sets before reveal timeout. Example with four equal-stake validators:

- Validator A sees reveals `{A, B, C}` and computes winner `B`.
- Validator D sees reveals `{B, C, D}` and computes winner `D`.

This is possible because the election result is computed from locally observed `state.reveals` (`indra-node/src/driver.rs:918-925`) and there is no durable reveal-set certificate or consensus step that first agrees on the reveal set.

This does not create a known fork-safety issue because:

- The proposed block includes `election_result_hash` in its header.
- `block_hash()` includes the header fields, including `election_result_hash`.
- Prevotes and precommits are for full `block_hash`.
- A block QC requires >2/3 stake on one full hash, and standard quorum intersection prevents two conflicting full hashes from both reaching QC with <1/3 Byzantine stake.
- The local proposal intake path rejects a block if its header election hash disagrees with the local commit-reveal result when that result is available (`indra-node/src/driver.rs:1563-1575`).

Risk: liveness degradation from honest disagreement on valid proposer, not safety failure.

Severity: Medium liveness.

### 2.2 Precommit gate bypass paths

Relevant runtime calls to `sign_and_record_local_vote(..., VoteStep::Precommit, ...)`:

- `maybe_precommit_current_round_proposal` signs the locked value or nil after election result computation retry (`indra-node/src/driver.rs:955-968`).
- Prevote quorum for a non-nil block transitions to precommit and calls `sign_and_record_local_vote` with the quorum block hash (`indra-node/src/driver.rs:1886-1902`).
- Nil prevote quorum calls it with `Bytes32::ZERO` (`indra-node/src/driver.rs:1903-1910`).
- `on_prevote_timeout` calls it with `Bytes32::ZERO` (`indra-node/src/driver.rs:2392-2401`).

The common signing function enforces the commit-reveal-active non-nil precommit gate (`indra-node/src/driver.rs:1441-1468`). Therefore, no normal runtime path was found that signs a non-nil precommit without the gate.

Tests and helper constructors still manually produce precommit votes in several places, but those are not live runtime paths.

Severity: Safe.

### 2.3 Is election_result_hash verified on inbound precommits?

Yes for votes that reach `record_vote_passive` or `record_vote_and_actions`. Both call `validate_precommit_election_result_hash` before adding the vote to the collector (`indra-node/src/driver.rs:1752-1778`, `indra-node/src/driver.rs:1837-1865`).

The validation rejects non-nil commit-reveal-active precommits with `election_result_hash = None`. If the block is already staged locally, it also rejects mismatches against the staged block header (`indra-node/src/driver.rs:1759-1777`).

Important caveat: if a non-nil vote arrives before the block is staged, `process_vote` buffers it and requests the proposal (`indra-node/src/driver.rs:1727-1747`). The validation runs when buffered votes are replayed after staging (`indra-node/src/driver.rs:1565-1572`), so a bad buffered vote should not contribute once the block is known.

Severity: Safe, with delayed validation for vote-before-block.

### 2.4 Can a validator forge an election result?

A non-elected validator can create a block with its own valid VRF proof and an arbitrary `election_result_hash`, but honest nodes reject it unless the hash certifies that proposer/output pair and, in live consensus, matches their local commit-reveal result.

Verification layers:

- `verify_proposer_vrf_key_ownership` requires the block VRF proof/output to match exactly one active validator’s registered VRF key (`indra-node/src/sync.rs:295-373`).
- `verify_commit_reveal_proposer_result` requires `header.election_result_hash` to equal either the normal result hash for that proposer/output or the fallback result hash for that proposer/fallback sentinel (`indra-node/src/sync.rs:376-421`).
- Live proposal intake also rejects if local commit-reveal result exists and does not match the header (`indra-node/src/driver.rs:1563-1575`).
- Precommit signing refuses non-nil votes unless local result matches (`indra-node/src/driver.rs:1441-1468`).

Forgery would require making honest validators compute the same election result for the attacker. Without controlling the reveal set enough to actually win or trigger fallback to the attacker, the fake block cannot gather honest precommit quorum.

Severity: Safe.

## Investigation 3: Liveness

### 3.1 Elected proposer withholds reveal

If a validator commits and then withholds its reveal, it is excluded from `revealed` because `compute_and_store_vrf_election` builds the election input from `state.reveals` only (`indra-node/src/driver.rs:918-925`). With 4 validators and one withholding validator, the remaining 3 equal-stake validators constitute 75% stake, exceeding the 2/3 reveal threshold. The election result is computed from those 3 reveals; the withholding validator cannot win from a missing reveal.

If the replacement winner is among the revealers and computes the same result, it can propose because the node loop checks `election_result.elected_validator_id == local validator_id` (`indra-node/src/bin/node.rs:1867-1885`).

Risk remains if honest nodes have different 3-of-4 reveal subsets; they can disagree on replacement winner and waste a round.

Severity: Low/Medium liveness.

### 3.2 All-withhold fallback handling

If no valid reveals exist by reveal timeout, the driver increments `consecutive_empty_reveal_rounds`. Fallback is not produced until the counter reaches `MAX_VRF_EMPTY_REVEAL_ROUNDS = 3`. Before that threshold, the VRF state is marked complete without an election result, causing the round to time out/advance rather than electing from an empty reveal set.

When the empty-round threshold is reached, `compute_fallback_election_result` is used, the resulting `VrfElectionResult` has `fallback_used = true`, and the fallback result hash is passed into block production as `election_result_hash` by the node loop. Block production accepts either the normal result hash or fallback hash for the proposer (`indra-consensus/src/producer.rs:75-101`). Sync verification likewise accepts the normal or fallback hash (`indra-node/src/sync.rs:390-407`).

This now matches the documented mainnet-grade policy: advance rounds first, fallback only after repeated empty reveal rounds.

Status: Fixed.

### 3.3 Round timeout and VRF state cleanup

On round advance, `start_round` replaces state with the current round and `round + 1`, and retains only local VRF outputs for the same height and those two rounds (`indra-node/src/driver.rs:569-584`). Old round state is therefore cleared. On sync catch-up, all VRF state and local VRF outputs are cleared (`indra-node/src/driver.rs:520-538`).

Stale commits/reveals for old or far-future rounds are dropped cheaply because `process_vrf_commit`/`process_vrf_reveal` require a matching `vrf_slot_index` (`indra-node/src/driver.rs:2160-2164`, `indra-node/src/driver.rs:2214-2218`).

Severity: Safe.

### 3.4 Maximum rounds before guaranteed liveness

There is no strict deterministic guarantee of progress within a bounded number of rounds under arbitrary message delay or reveal-set disagreement. Under eventual synchrony with at least one honest proposer elected by a common reveal/fallback result, progress should resume.

Reasons:

- `MAX_VRF_EMPTY_REVEAL_ROUNDS = 3` is now a real fallback threshold for consecutive zero-reveal rounds, not just phase metadata.
- If reveal subsets differ, validators can compute different non-empty election results for multiple consecutive rounds.
- If the elected proposer is offline or censored, a round can still time out.
- The consensus round cap in primitives is described as logical slot derivation, not a runtime retry cap (`indra-core/src/types/primitives.rs:59-63`).

Practical expectation on 4 validators: a single delayed/missing reveal round should normally resolve by the next round or fallback. Formal guarantee: only under eventual synchrony and honest majority participation, not within a fixed small round count.

Severity: Medium liveness modeling gap.

## Investigation 4: Performance

### 4.1 Consensus tick analysis

The main consensus loop is timer-driven with blocking `recv_timeout(100ms)` waits between checks (`indra-node/src/bin/node.rs:1747-2085`). It is partially event-assisted through `height_rx`, but VRF window closure is not driven by a dedicated timer; it advances when the propose-phase loop calls `ensure_vrf_election_for_round` or when commit/reveal messages are processed.

The effective block cadence is dominated by:

- `MIN_BLOCK_INTERVAL_SECS = 6`, checked before proposal production (`indra-node/src/bin/node.rs:45-48`, `indra-node/src/bin/node.rs:1927-1944`).
- VRF commit/reveal windows, 1500ms each if quorum does not arrive earlier (`indra-core/src/types/primitives.rs:65-69`).
- Round timeouts: propose 8s, prevote 3s, precommit 3s (`indra-node/src/bin/node.rs:45-47`).

### 4.2 VRF message volume

Per successful round, each active validator emits at most:

- 1 `VrfCommit`
- 1 `VrfReveal`

With gossip broadcast, each accepted commit/reveal is rebroadcast (`process_vrf_commit` and `insert_valid_vrf_reveal` push `BroadcastVrfCommit`/`BroadcastVrfReveal`; `indra-node/src/driver.rs:2194-2198`, `indra-node/src/driver.rs:1032-1035`). Peer-manager duplicate filtering from the rate-limiter fix should limit repeated driver processing, but network fanout still scales with peer count.

Approximate per-round protocol message count before gossip duplicates:

| Active validators | Commits | Reveals | Total signed VRF messages |
|-------------------|---------|---------|----------------------------|
| 4 | 4 | 4 | 8 |
| 100 | 100 | 100 | 200 |
| 1000 | 1000 | 1000 | 2000 |

Wire size is dominated by hybrid signatures and VRF proof bytes. At 1000 validators, full broadcast of all commits/reveals each round is significant and should be revisited before mainnet-scale active sets.

Severity: Medium scalability.

### 4.3 Lock contention

VRF processing happens under the consensus driver mutex in the node loop and peer event paths. Signature and VRF proof verification are performed inside driver methods. Recent ordering changes reduce unnecessary expensive work for far-future/duplicate messages, but valid commit/reveal verification still occurs under lock.

The API-09 clone-and-release pattern mitigates public RPC read contention, but P2P consensus events still serialize on the driver lock. With 4 validators this is fine. With hundreds of validators, bursts of `VrfReveal` verification under the lock can delay proposal/vote handling.

Severity: Low now, Medium at larger validator counts.

## Investigation 5: Edge Cases

### 5.1 Node restart mid-round

VRF round state is ephemeral and not persisted. On restart:

- `vrf_states` starts empty/current at round initialization.
- `local_vrf_rounds` is empty.
- Recomputed VRF output/proof for the same `(height, round)` should be deterministic for the same key/input.

Liveness caveat: peers that already accepted the validator’s old commit will reject a duplicate commit for the same validator/slot. If the restarted node lost its local proof state and cannot reveal against the already accepted commit in peers’ state, its reveal for that round may be absent. This is not safety-critical, but it can reduce reveal stake and cause a round miss.

Severity: Low liveness.

### 5.2 VRF state memory bounds

`vrf_states` is bounded to two slots: current and next round (`indra-node/src/driver.rs:322`, `indra-node/src/driver.rs:569-584`). `local_vrf_rounds` is a `BTreeMap`, but `start_round` retains only the current height and current/next round (`indra-node/src/driver.rs:583-584`), and sync catch-up clears it (`indra-node/src/driver.rs:530`). This is bounded during normal round advancement.

Severity: Safe.

### 5.3 pending_reveals bounds

`pending_reveals` stores reveal-before-commit entries, keyed by validator ID. Insertion is capped by `MAX_VRF_ROUND_ENTRIES`, which equals `MAX_VALIDATORS` (`indra-node/src/driver.rs:991-995`, `indra-core/src/types/primitives.rs:74-75`). Since `vrf_states` is two slots, total pending reveal memory is bounded by roughly `2 * MAX_VALIDATORS`.

Severity: Safe.

### 5.4 Chain ID hash in VRF commits

Inbound `VrfCommit` rejects mismatched `chain_id_hash` before slot/signature verification (`indra-node/src/driver.rs:2141-2153`). Inbound `VrfReveal` does the same before insertion/proof verification (`indra-node/src/driver.rs:2211-2218`). The commit hash itself also includes `chain_id_hash` (`indra-core/src/types/vrf_election.rs:164-189`).

Severity: Safe.

## Findings Summary

| ID | Category | Finding | Severity | Recommended Action |
|----|----------|---------|----------|-------------------|
| VRF-01 | Pipelining | Next-height pipelining is not implemented; only next-round same-height state exists. | Medium | Add height `N+1` VRF precompute once parent seed is known, or document 6s testnet-only latency. |
| VRF-02 | Performance | 6-second minimum proposal interval dominates block time. | Low | Keep for testnet stability or make target-driven/configurable after measuring. |
| VRF-03 | Liveness | Precommit gate can nil-precommit if local election result has not advanced, and cannot retry block precommit after nil vote. | Medium | **FIXED:** added `VRF_ELECTION_SETTLE_MS` wait, precommit retry hook, and nil fallback only after settle window. |
| VRF-04 | Safety/Liveness | Validators can compute different election results from different reveal subsets. Safety holds via block hash/QC, but liveness can churn. | Medium | **FIXED / HEIGHT-GATED:** proposal body carries the signed reveal set; voters verify that exact quorum set and its Merkle commitment. |
| VRF-05 | QC/Votes | `VoteCollector` quorum is keyed by `block_hash` only, while QC requires `election_result_hash` agreement. | Medium | **FIXED:** finalization now requires an ERH-agreeing precommit subgroup to independently reach quorum before QC build. |
| VRF-06 | Fallback policy | Zero-reveal fallback is available immediately; `MAX_VRF_EMPTY_REVEAL_ROUNDS` only changes phase labeling. | Medium | **FIXED:** fallback is now gated until `MAX_VRF_EMPTY_REVEAL_ROUNDS` consecutive empty reveal rounds. |
| VRF-07 | Sync evidence | Sync verifies header digest/proposer output but not durable commit/reveal evidence. | Medium | **FIXED / HEIGHT-GATED:** block body carries full reveal evidence; sync/audit recomputes the reveal-set Merkle root and election hash. |
| VRF-08 | Scalability | Commit/reveal gossip is O(n) signed messages per round before gossip fanout; hybrid signatures make this costly at 1000 validators. | Medium | Benchmark at 100/1000 validators; consider aggregation, committees, or compact certificates. |
| VRF-09 | Restart | Mid-round restart can lose local reveal contribution for already accepted commits. | Low | Accept as round-level liveness loss or persist local VRF slot proof until round/height exits. |
| VRF-10 | Bounds | `vrf_states`, `local_vrf_rounds`, and `pending_reveals` are bounded. | Safe | No action required. |
| VRF-11 | Replay | VRF commit/reveal chain ID binding is enforced. | Safe | No action required. |

## Recommended Fixes (Priority Order)

1. **VRF-05 — Count precommit quorum by `(block_hash, election_result_hash)` — FIXED**
   - The driver filters precommit quorum candidates at finalization and only builds a QC from votes whose `election_result_hash` agrees with the staged block and independently reaches quorum.
   - This prevents mixed ERH vote sets from producing a late `build_qc` failure.

2. **VRF-03 — Make VRF election advancement event/timer driven — FIXED**
   - The driver now records when precommit begins, waits `VRF_ELECTION_SETTLE_MS` before nil-precommitting for a missing election result, and the node loop retries the precommit path while waiting.
   - If the election result arrives during the wait, the validator casts the block precommit with `Some(election_result_hash)`.

3. **VRF-01 — Implement true next-height pipelining or document intentional non-pipelined testnet behavior**
   - True next-height pipelining is only possible after the parent seed is known. If the seed is the parent hash, round-0 next-height election cannot start before parent commit, but it can begin immediately at commit instead of waiting for the next loop turn.
   - If future design uses a seed known earlier, start height `N+1` commit/reveal during height `N`.

4. **VRF-06 — Clarify/enforce fallback policy — FIXED**
   - The implementation now enforces fallback only after `MAX_VRF_EMPTY_REVEAL_ROUNDS` consecutive empty reveal rounds.
   - A successful reveal round resets the empty-round counter.

5. **VRF-04 / VRF-07 — Proposer-specified reveal set and durable evidence — FIXED / HEIGHT-GATED**
   - `BlockV1` carries full sorted `(validator_id, vrf_output, vrf_proof)` evidence at/after `REVEAL_SET_COMMITMENT_HEIGHT`.
   - `VrfElectionResult::hash()` includes the reveal-set Merkle commitment at/after the same height, making the set QC-attested through the existing `election_result_hash`.
   - Voters verify the proposer-specified quorum reveal set instead of their local superset/subset; missing specified reveals trigger `RequestVrfReveals`/`VrfRevealsResponse` recovery.
   - Retention follows normal block-body retention: pruned validators retain reveal evidence for their configured block window, while archive/full-history nodes retain it for as long as they retain full blocks. No special indefinite retention guarantee is introduced for reveal evidence.

6. **VRF-08 — Benchmark and optimize at larger validator counts**
   - Measure commit/reveal CPU and network fanout at 100 and 1000 validators before increasing active-set size.

7. **VRF-09 — Consider persisting local mid-round VRF proof**
   - Low priority. The current behavior is safe and only costs one validator’s reveal after restart.
