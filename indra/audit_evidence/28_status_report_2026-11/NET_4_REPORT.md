Part 1 conclusion: NET_4 replaces NET_3 strict slot equality with a bounded relay window of adjacent heights and driver-derived ±8 rounds, preserving deduplication, origin exclusion, fanout, and verification while allowing timing-skew propagation. Real topology tests and release live runs pass, and the strict-equality mutation fails the skew test as expected.
Part 2 conclusion: the fixed readiness gate is correctly one authenticated validator peer for liveness because relay connectivity and strict >2/3 stake QC formation are separate concerns. A one-peer eclipse or withholding validator can make the node progress locally but cannot finalize a fork without the required authenticated quorum; non-validator authenticated peers are not admitted as validator peers.
Unfinished: none.

# NET_4 implementation report

## Scope

Implemented the attached NET_4 request on top of the NET_3 working tree. Existing unrelated untracked audit artifacts were preserved. No commit, staging, stash, reset, or lint suppression was used.

## Part 1 — relay slot filter

### Current behavior and driver comparison

`PeerManagerActor::relay_if_eligible` is at `indra-network/src/peer_manager.rs:659-689`. The context installed by the node is `(driver height + 1, driver current round)` (`node.rs:3754`), so `height` below means the next consensus height the receiving driver is preparing for.

| Message slot relative to installed context | NET_3 strict equality | NET_4 | Direct driver behavior |
|---|---|---|---|
| Same height, current round | relayed | relayed | admitted after snapshot/signature/authority checks |
| Same height, earlier round within 8 | dropped | relayed | retained/usable by round-scoped collections; stale evidence is pruned outside the window |
| Same height, later round r+1 through r+8 | dropped | relayed | accepted/buffered and can contribute to certified round advancement |
| Same height, later than r+8 | dropped | dropped and `InvalidMessage` score path applied | rejected before consensus mutation |
| Adjacent height (previous or next), bounded round | dropped unless exactly equal context height | relayed | direct vote admission is exact-next-height, but relay propagation must bridge a one-height lag so the message can reach a peer whose context differs |
| Height two or more away / far future | dropped | dropped and scored as invalid consensus traffic | rejected/ignored by exact-height driver admission |
| Non-relay message class (QC request/response, etc.) | not relayed | not relayed | handled by their point-to-point paths |

PRE-NET_3 had no pre-relay consensus-context filter: relay eligibility proceeded through message-class/key, deduplication, signature/VRF verification, conflict checks, and fanout. The NET_3 equality filter was therefore stricter than the driver for future-round and late-round gossip. NET_4 uses the driver’s `MAX_ACCEPTED_ROUND_JUMP` from `indra-core/src/types/primitives.rs:64` in both driver pruning/admission and network relay; there is no duplicated `8` in the driver or relay filter. `MAX_RELAY_HEIGHT_SKEW = 1` is the explicit bounded graph-propagation allowance at `primitives.rs:67`.

The driver still remains authoritative: `process_vote` validates the round domain, requires `vote.height == next_height`, rejects rounds above `current_round + MAX_ACCEPTED_ROUND_JUMP`, verifies snapshot authority, requests and buffers a missing proposal, and records valid evidence. A directly received previous-height vote is not used by the driver; relay admission is intentionally a bounded superset for forwarding across a lagging peer, not a consensus-admission change.

### Tests and mutation proof

Added/updated real relay-path tests in `indra-network/src/peer_manager.rs`:

- `relay_timing_skew_bridges_adjacent_slots_but_not_garbage`: line topology 0-1-2-3, one-round-ahead vote and adjacent-height vote reach the endpoint; far-round traffic does not amplify.
- `pre_relay_slot_context_rejects_wrong_height_and_round`: current, earlier, later-within-window, adjacent-height, and out-of-window height cases; metrics and receiver behavior are asserted.
- Existing `relay_reaches_all_nodes_through_line_star_and_ring` and `relay_bounds_duplicate_and_conflicting_messages` continue to pass, preserving topology reachability and dedup/conflict safety.

Mutation proof: temporarily restored `message_height == height && message_round == round`; `relay_timing_skew_bridges_adjacent_slots_but_not_garbage` failed with `left: 2, right: 4` (endpoint starvation), then restored the bounded-window implementation. Final post-restore run passed the skew test and the peer-gate test.

Out-of-window validly signed messages increment relay drops and use `ScoreEvent::InvalidMessage` through the existing validator score/ban path before returning, so a distinct garbage-slot flood does not relay and is penalized. Existing relay deduplication, per-origin sender exclusion, fanout, queue limits, signature/VRF verification, and block conflict handling are unchanged.

## Part 2 — readiness gate

`git log -S'MIN_CONSENSUS_PEERS'` found only the NET_3 introduction because the symbol was new. The historical pre-NET_3 commit was:

> `fix(consensus): pause consensus when fewer than 2 peers connected`

Its exact code/log rationale was only:

> `if connected < 2 { eprintln!("[consensus] waiting for peers (have {}, need 2)", connected); ... continue; }`

There was no additional body rationale. NET_4 retains a fixed one-peer liveness gate with a doc comment at `indra-node/src/bin/node.rs:94-101`: authenticated validator-graph relay permits startup with one peer, but strict >2/3 stake QC verification remains the safety boundary. `connected` comes from `gossip.connection_count()`, which counts registered authenticated peer identities, not raw sockets or dialable addresses. Handshake admission rejects unknown validators; existing network test `handshake_rejects_unknown_validator` and the non-validator per-IP tests cover that boundary.

The concrete risks are explicit: one adversarial authenticated validator can eclipse message flow or withhold votes, causing rounds/timeouts and stalled progress; it cannot create a valid QC or finalize a conflicting fork without the required validator stake. A validator set requiring three or more reachable validators may therefore start with one connection and harmlessly stall; the gate is not presented as quorum reachability. Gate tests cover 0, 1, 2, and 3 counts, and assert the exact log text `[consensus] waiting for peers (have 0, need 1)`.

## Part 3 — release live proof

Release binaries were built into fresh target directory `/tmp/indra-net4-release.dkTq7l` and used for both live runs.

Ordinary line run:

- command: `NODE_BIN=/tmp/indra-net4-release.dkTq7l/release/node GENESIS_BIN=/tmp/indra-net4-release.dkTq7l/release/indra-genesis KEYGEN_BIN=/tmp/indra-net4-release.dkTq7l/release/indra-keygen TARGET_HEIGHT=10 CAP_SECONDS=2400 scripts/line_topology_live.sh <run-dir>`
- result: PASS, target height 10, elapsed 416 seconds, identical tip on all four nodes, panics 0, stale sync 0, exits zero 1.

Skew smoke:

- script: `scripts/line_skew_live.sh`
- behavior: nodes 0/2/3 start first; node 1 starts after 30 seconds; node 2 receives SIGSTOP for 20 seconds and SIGCONT; same four-node line and release binaries.
- command: `NODE_BIN=/tmp/indra-net4-release.dkTq7l/release/node GENESIS_BIN=/tmp/indra-net4-release.dkTq7l/release/indra-genesis KEYGEN_BIN=/tmp/indra-net4-release.dkTq7l/release/indra-keygen TARGET_HEIGHT=5 CAP_SECONDS=600 scripts/line_skew_live.sh <run-dir>`
- result: PASS, target height 5, elapsed 245 seconds, identical tip on all four nodes, panics 0, stale sync 0, exits zero 1.

Owner full skew command: set `TARGET_HEIGHT=10 CAP_SECONDS=2400` in the command above.

## Checks

- `cargo clippy --workspace --all-targets --no-deps -- -D warnings`: PASS, debug; completed in the isolated target after the upstream GMP/MPFR self-checks.
- `cargo clippy --release --workspace --all-targets --no-deps -- -D warnings`: PASS.
- `scripts/check_no_lint_allows.sh`: PASS.
- `cargo test -p indra-core --test lint_guard`: PASS, 2 passed, 0 failed.
- New debug tests: relay skew 1 passed; slot-window test 1 passed; gate count test 1 passed; log-text test 1 passed. The broader relay-filter suite was 23 passed, 0 failed, 1 pre-existing ignored.
- `cargo test --workspace --release --no-fail-fast`: 49 suites, 1,685 passed, 0 failed, 10 ignored. Baseline 1,682 passed; NET_4 adds 3 new tests (the modified slot-context test is not counted as new).
- `cargo audit`: advisories OK.
- `cargo deny check`: advisories/bans/licenses/sources OK; existing duplicate-crate warnings were reported and are unrelated to NET_4.

### Diff stat by crate/scope

| Scope | Files | Diff |
|---|---:|---:|
| `indra-core` | 1 | 6 insertions |
| `indra-network` | 1 | 130 insertions / 51 deletions |
| `indra-node` | 2 | 53 insertions / 0 deletions |
| `scripts` | 2 | 19 modified-line insertions plus new `line_skew_live.sh` (12 lines) |
| Total tracked diff | 5 | 157 insertions / 51 deletions |

Final disk check (`df -h .`): `/dev/disk3s5`, 228 GiB total, 200 GiB used, 4.4 GiB available, 98% capacity. This is above the 3 GiB stop threshold.
