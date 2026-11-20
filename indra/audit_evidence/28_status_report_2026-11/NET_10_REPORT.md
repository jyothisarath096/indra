The NET_10 root cause was receiver-local consensus validation treating an honest peer's ahead-of-height/ahead-of-round messages as peer faults, repeatedly scoring the peer until its identity ban was persisted. The resumed node then continued dialing the banned identity, producing the observed connection churn until the ban window ended.
Unfinished: the broad debug `cargo test -p indra-node --lib` run was interrupted after exceeding ten minutes; the complete release workspace suite passed, including the node tests, and no NET_10 code remains untested by the targeted tests. The build-policy digest check is a pre-existing failure at the earliest requested commit (`fc1d3e02`), so no policy pin was changed.

## Implementation

- `indra-node/src/driver.rs` now treats receiver-local snapshot availability, snapshot-root mismatch, collector-local replay/slot/round errors, stale/future height, and other local-state-dependent results as drops. They no longer produce `DisconnectInvalidConsensusPeer`.
- Provable vote faults remain punishable: unknown voter, invalid round, and cryptographic failures other than the explicitly local snapshot-root mismatch still produce the existing invalid-consensus action. Existing QC verification and equivocation/conflict protections were not weakened.
- Drops retain the existing bounded admission/rate-limit and sync/QC recovery paths; the live evidence shows the corresponding `dropping excess Vote ... no score penalty` path and no ban.
- `indra-node/src/bin/node.rs` remembers an identity ban for `BAN_DURATION`, retains the authenticated address-to-identity mapping for banned peers, and makes the dialer skip active banned identities with the existing per-address rate-limited `skip reason=banned until=<ts>` log. Expired entries are pruned and become dialable on the next interval.
- `indra-network/src/lib.rs` re-exports the existing `BAN_DURATION` constant for the runtime ban gate.
- `scripts/line_restart_repeat.sh` runs the restart scenario in independent directories, prints PASS/FAIL, recovery seconds, and event counts, and exits nonzero if any run fails.
- Tests cover local snapshot mismatch not causing a disconnect, provable cryptographic/identity faults remaining punishable, and the existing network ban/reconnect behavior. Existing NET_5/NET_6 regression coverage remains green.

## Evidence and root-cause quantification

The owner release run `/tmp/o-pause900/timeline.log` records:

- `t_stop=1795173886107`, node 1 at height 3;
- `t_cont=1795174786207`, a 900.1-second pause;
- both neighbours reconnected at `1795175387560`, about 601.35 seconds after continuation;
- the first post-continuation block arrived at `1795175506948`, recovery 720.74 seconds from stop;
- all nodes reached height 8 at `1795175586514`.

The owner logs contain no authoritative ban after this change. They contain repeated authenticated vote drops explicitly marked `no score penalty`, and only expected duplicate-connection tie-break disconnects. This is the contrast with the NET_9 evidence: the earlier node-1 log showed node 2 disconnected with `reason ban` immediately after node 1 resumed, while the honest peer was ahead. The old 440-event churn was therefore caused by the persisted one-hour identity ban plus a dialer that did not consult the ban state; it was not ban expiry or score recovery ending the 601-second window.

Relevant code locations:

- `indra-node/src/driver.rs:1669` (`process_vote`) is the authoritative vote admission boundary; `:1733` is now the only vote path that creates `DisconnectInvalidConsensusPeer`.
- `indra-node/src/driver.rs:1956` and `:2093` drop collector-local errors without peer scoring.
- `indra-node/src/driver.rs:2455-2474` retains the existing provable invalid-QC score actions.
- `indra-node/src/bin/node.rs:4576` applies driver actions; `:4641` sends the invalid-consensus disconnect command.
- `indra-network/src/peer_manager.rs:953-977` applies invalid-consensus and other score events. `indra-network/src/peer.rs:43-117` defines the initial score, deltas, zero-score ban, and one-hour duration; `peer_manager.rs:1113` enforces the persistent identity ban on inbound registration.
- `indra-node/src/bin/node.rs:1604-1648` records a ban expiry and retains identity/address knowledge; `:1970-2004` skips banned dial candidates.

The ban remains identity-based and persistent through the existing `BanStore`; the one-hour duration was not changed because the NET_9 evidence did not establish expiry as the cause of recovery. Volume limiting remains separate from score bans.

## Verification

- `cargo clippy --workspace --all-targets --no-deps -- -D warnings`: passed in debug and release.
- `./scripts/check_no_lint_allows.sh`: passed.
- `cargo test -p indra-core --test lint_guard`: 2 passed.
- `cargo test --workspace --release --no-fail-fast`: passed. Notable totals include `indra-ffi` 28 passed, `indra-network` 168 passed/1 ignored, `indra-node` 360 passed/5 ignored plus node binary 102 passed, with no failures; all remaining workspace crates and doc tests passed.
- `cargo audit`: passed with no advisory findings.
- `cargo deny check`: passed advisories, bans, licenses, and sources; existing duplicate-package warnings remain.
- Golden/replay/vector coverage passed in the release workspace suite; no golden/vector files were changed.
- `bash -n scripts/line_restart_repeat.sh scripts/line_restart_live.sh scripts/line_topology_live.sh`: passed.
- The policy script was run in detached worktrees at `fc1d3e02`, `31099348`, `5e7496fc`, `f9ee07cd`, and HEAD. Every one failed with `consensus build policy error: Cargo.lock changed; review dependencies and update the audited matrix digest`; the first failing requested commit is `fc1d3e02`. The failure is the SHA-256 comparison in `scripts/check_consensus_build_policy.py` against `ci/consensus-build-matrix.toml`; `Cargo.lock` was not modified by NET_10.

## Live smoke

The isolated release STOP300 run `/tmp/net10-stop300` passed:

`target_height=10 reached=1 same_tip=1 panics=0 stale_sync=0 exits_zero=1 peer_counts_ok=1 ... recovery_seconds=83.295 ... post-resume connection events=0`.

The passed smoke directory `/tmp/net10-stop300` was retained as additional evidence; owner evidence directories were preserved. No failed NET_10 run directory was deleted.

## Owner commands

Run each command alone with the release binaries and preserve any failed directory:

```bash
cd /Users/bonkai/Desktop/indra/project_indra/indra
export NODE_BIN="$PWD/target/release/node" GENESIS_BIN="$PWD/target/release/indra-genesis" KEYGEN_BIN="$PWD/target/release/indra-keygen"
STOP_SECONDS=900 TARGET_HEIGHT=8 CAP_SECONDS=2400 STOP_NODE_INDEX=1 EXPECT_PEER_COUNTS='1,2,2,1' scripts/line_topology_live.sh /tmp/net10-pause900
DOWN_SECONDS=900 TARGET_HEIGHT=8 CAP_SECONDS=2400 STOP_NODE_INDEX=1 EXPECT_PEER_COUNTS='1,2,2,1' scripts/line_restart_live.sh /tmp/net10-restart900
RUNS=6 DOWN_SECONDS=120 TARGET_HEIGHT=10 CAP_SECONDS=1800 STOP_NODE_INDEX=1 EXPECT_PEER_COUNTS='1,2,2,1' scripts/line_restart_repeat.sh /tmp/net10-restart-repeat
TARGET_HEIGHT=10 CAP_SECONDS=900 EXPECT_PEER_COUNTS='1,2,2,1' scripts/line_topology_live.sh /tmp/net10-quiet10m
```

## Intentional NET_10 files

- `indra-network/src/lib.rs`
- `indra-node/src/bin/node.rs`
- `indra-node/src/driver.rs`
- `indra-node/src/driver_tests.rs`
- `scripts/line_restart_repeat.sh`
- this report
