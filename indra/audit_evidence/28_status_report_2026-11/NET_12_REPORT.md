NET_12 is implemented: excess traffic is dropped and counted by stable message class, peer, and Prometheus counters; sustained abuse disconnects with `rate_limit_disconnect` without score changes, bans, or cooldowns. Debug/release clippy, lint/audit/deny gates, focused tests, the corrected full release workspace suite including `indra-ffi`, and golden/replay/vector coverage passed; the new STOP300 harness run was retained as incomplete because it hung after the stop event.

Unfinished live evidence: `/tmp/net12-stop300` reached `t_stop` at height 3 but did not complete its post-stop phase, so it was terminated and preserved. The previously successful release smoke remains `/tmp/net11-stop300`; no failed evidence directory was deleted.

## Implementation

- Removed the unused `StrikeCounter`, its escalating penalty path, and its tests. No production reader remained outside the removed implementation.
- Added `RateLimitMetrics` with stable per-class counters for `vote`, `block_or_proposal`, `status`, `peer_list`, `block_request`, `tx`, `staking_op`, `governance_op`, `ping_pong`, `block_response`, and `qc_response`, plus `indra_p2p_rate_limit_disconnects_total`.
- Added `PeerInfo.rate_limit_drops` as the per-peer total exposed by peer status, incremented for every dropped violation.
- Added a documented sustained-flood policy: more than 400 drops in each of three consecutive 10-second windows causes one explicit `rate_limit_disconnect`; the connection is removed, the identity is not banned, its score is unchanged, and normal reconnect behavior remains available.
- Added per-(validator,class) one-second summary logging. A summary reports the aggregate number dropped in the interval; the million-record simulation emitted at most 1,000 summaries.
- Global large-payload overages now enter the same counted, non-punitive path.

## Mutation-proof evidence

The scratch worktree `/tmp/net12-pre` was patched to restore the pre-NET11 score/ban handler, and the test setup was changed to register the peer through the real managed-peer path. The targeted test then failed as required:

```text
thread 'peer_manager::tests::authenticated_validator_non_consensus_rate_limit_flood_is_not_banned' panicked
assertion `left == right` failed
left: 0
right: 100
test ...authenticated_validator_non_consensus_rate_limit_flood_is_not_banned ... FAILED
```

The scratch file was restored to its original HEAD contents after capture. Focused coverage now includes consensus-class violations, per-peer byte overage, global large-payload limiting, managed-peer backlog/drop behavior, honest-burst tolerance, sustained-flood triggering, reconnect-safe non-ban semantics, metrics export, and bounded logging.

## Honest backlog measurements and thresholds

From the preserved NET11 owner runs:

| Evidence | BlockOrProposal | PeerList | Vote | Total | Max 1 s | Max 10 s |
|---|---:|---:|---:|---:|---:|---:|
| `/tmp/net11-pause900` | 49 | 7 | 326 | 382 | 382 | 382 |
| `/tmp/net11-stop300` | 0 | 1 | 135 | 136 | 136 | 136 |

The sustained threshold is 401 drops per 10-second window for three consecutive windows. Therefore neither measured honest backlog burst can trip it, even if all drops are concentrated in one second; an honest freeze is dropped and counted but is not disconnected.

## 65-second first-block explanation

The owner’s pause-900 timestamps show both neighbours connected at approximately `t_cont+0.2 s`, with the first post-resume block at `recovery_seconds=65.057`; the paused node had missed 186 rounds. The logs show normal networking recovery followed by stake-supported round advances and timed round transitions while the common height/round state converges; the delay is not the former 600-second rate-limit ban. The pause-300 comparison recovered in 13.390 seconds, so the observed delay is not a fixed one-round constant and is sensitive to the backlog/round state, but no consensus-visible rule was changed in NET_12. A full per-second proposer/in-sync table and a consensus-path change were intentionally not added: the available logs establish the networking/round-sync symptom and the rate-limit ban cause, but do not provide enough authoritative proposer-state evidence to justify changing consensus rules.

## Verification

- `cargo test -p indra-network --lib`: 170 passed, 1 ignored.
- `cargo clippy --workspace --all-targets --no-deps -- -D warnings`: passed debug and release.
- `scripts/check_no_lint_allows.sh`, `cargo test -p indra-core --test lint_guard`, `cargo audit`, `cargo deny check`, and `bash -n scripts/pause_threshold.sh`: passed.
- `cargo test --workspace --release --no-fail-fast`: passed on the corrected rerun; all workspace targets, including `indra-ffi`, passed. The captured log is `/tmp/net12-full-release.log`.
- No formatter was run. No commit, stage, stash, restore, or deletion of owner/failed evidence directories was performed.

## Owner commands

Run each live scenario alone, with no build or test process running:

```bash
cd /Users/bonkai/Desktop/indra/project_indra/indra
export NODE_BIN="$PWD/target/release/node" GENESIS_BIN="$PWD/target/release/indra-genesis" KEYGEN_BIN="$PWD/target/release/indra-keygen"
STOP_SECONDS=900 TARGET_HEIGHT=8 CAP_SECONDS=2400 STOP_NODE_INDEX=1 EXPECT_PEER_COUNTS='1,2,2,1' scripts/line_topology_live.sh /tmp/net12-pause900
scripts/pause_threshold.sh /tmp/net12-pause-threshold
RUNS=6 DOWN_SECONDS=120 TARGET_HEIGHT=10 CAP_SECONDS=1800 STOP_NODE_INDEX=1 EXPECT_PEER_COUNTS='1,2,2,1' scripts/line_restart_repeat.sh /tmp/net12-restart-repeat
TARGET_HEIGHT=10 CAP_SECONDS=900 EXPECT_PEER_COUNTS='1,2,2,1' scripts/line_topology_live.sh /tmp/net12-quiet10m
```

## Intentional files

- `indra-network/src/lib.rs`
- `indra-network/src/net_types.rs`
- `indra-network/src/peer.rs`
- `indra-network/src/peer_manager.rs`
- `indra-network/src/rate_limit.rs`
- `indra-node/src/bin/node.rs`
- `indra-node/src/metrics.rs`
- `scripts/pause_threshold.sh` (existing NET11 change retained and used by the NET12 proof commands)
- `audit_evidence/28_status_report_2026-11/NET_12_REPORT.md`
