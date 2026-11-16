# Node Fix 1 report

This report records the implementation and checks for `CODEX_NODE_FIX_1.md`.
Commands were run from `/Users/bonkai/Desktop/indra/project_indra/indra` unless a worktree path is stated. No commit, stage, restore, checkout, or stash was performed.

## Disk and parity

`df -h .` was run before edits. Output:

```text
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   186Gi    15Gi    93%    2.0M  156M    1%   /System/Volumes/Data
```

The pre-edit parity worktree was `/Users/bonkai/Desktop/indra/indra_parity_node1`. Its captured result was `indra-node` 322 passed, 0 failed, 5 ignored in 1116.35s. The worktree was removed after the comparison as required. The post-edit package run was saved as `parity_node1_after.txt` in the main workspace and reported 329 passed, 0 failed, 5 ignored in 1021.79s.

## Changes

### Driver

- `indra-node/src/driver.rs:274,722-730,1982-2067`: `ConsensusDriver::try_new` propagates vote-safety restoration errors; the test-only `new` wrapper fails the test explicitly. `reset_round`, `on_sync_caught_up`, `start_round`, and `apply_vote_safety` use `NodeResult<()>`. The persisted vote-safety path and round transitions propagate errors. `polc_round` uses a `match`. QC formation returns `DriverAction::Fatal(NodeError)` when its governing snapshot is absent; the node reports that event to the main-thread supervisor.
- `indra-node/src/bin/node.rs:2660,3078,3226,3352,3935`: production driver callers handle round-reset and catch-up errors; the new supervisor path is consumed by the main loop for non-zero exit.

### Engine

- `indra-node/src/engine.rs:63-76,718-754,1932-1943`: the missing stake-position dependency is a typed `InvalidStakingOp` rejection. The reporter `HybridPubKey` is derived once during `NodeEngine::init` and reused for block selection. The conversion helper has normal and error-mapping tests.

### RPC and metrics

- `indra-node/src/hardened_read_rpc.rs:205-213,279-298,638-656`: poisoned per-IP admission state rejects the connection and restores the global count; handler panics are caught, logged, counted, and the listener continues. A poison/counter regression test was added.
- `indra-node/src/metrics.rs:42-50,206-240,409-479,850-870`: next-height overflow and unavailable reward are typed `MetricsError`s; metrics snapshot construction returns `Result`; metrics handlers return HTTP 500 for snapshot errors and isolate connection-handler panics with `indra_handler_panics_total{component=...}`.

### Supervision

- `indra-node/src/supervisor.rs:24-150` and `indra-node/src/bin/node.rs:1245,2526,3352`: `CriticalTasks` owns the P2P runtime, authenticated network-event loop, and consensus-driver handles. `critical_task_decision` is pure and tested for panic/error and clean-shutdown outcomes. Unexpected task exits and fatal consensus actions are reported to the main loop, which logs, flushes stderr, and exits non-zero.

The existing QC verifier worker, block-store persistence path, observer runtime, and RPC listener ownership were not fully migrated to `CriticalTasks`; those remain open against the attachment’s complete supervision requirement.

## Verification run records

The first workspace debug run was started before the final source edits and is retained only as an intermediate log: `/tmp/node_fix1_workspace_debug.log`. The authoritative post-edit runs are `/tmp/node_fix1_workspace_debug_final.log` and `/tmp/node_fix1_workspace_release.log`.

Commands run successfully during this task include:

```text
cargo check -p indra-node --all-targets
cargo clippy -p indra-node --lib --no-deps
cargo test -p indra-node --lib supervisor -- --test-threads=1
cargo test -p indra-node --lib metrics:: -- --test-threads=1
cargo test -p indra-node --lib hardened_read_rpc:: -- --test-threads=1
```

The targeted results were 3/0/0 for supervisor, 11/0/0 for metrics, and 6/0/0 for hardened RPC (passed/failed/ignored). The workspace aggregate was 1618/0/10 in both debug and release. The final node library target was 329/0/5 in debug and release. The exact per-target result lines are in the raw logs listed below.

## Appendix: raw command outputs and remaining checks

The required final logs are kept as separate files:

- `/tmp/node_fix1_workspace_debug_final.log`
- `/tmp/node_fix1_workspace_release.log`
- `/tmp/node_fix1_workspace_check_final.log`
- `/tmp/node_fix1_node_package_final.log`
- `/tmp/node_fix1_clippy_final.log`
- `parity_node1_after.txt` in the workspace (the worktree baseline was removed after its result line was captured).

Final exact result lines:

```text
workspace debug aggregate: passed=1618 failed=0 ignored=10
workspace release aggregate: passed=1618 failed=0 ignored=10
node library debug: 329 passed; 0 failed; 5 ignored; finished in 1040.86s
node library release: 329 passed; 0 failed; 5 ignored; finished in 58.33s
node package after: 329 passed; 0 failed; 5 ignored; finished in 1021.79s
```

The normalized parity diff contained only the expected seven newly added node tests and wall-time changes: 322→329 passed, 5 ignored unchanged, 0 failed in both runs. The raw diff command was `diff -u <(rg "test result:" parity_node1_before.txt) <(rg "test result:" parity_node1_after.txt)`.

Clippy completed successfully with 13 warnings and no errors/denied diagnostics. The observed warnings are style/complexity warnings in `driver.rs`, `discovery.rs`, `genesis.rs`, `metrics.rs`, and `sync.rs`; no `#[allow]` was added.

Final `cargo check --workspace --all-targets` completed successfully in `/tmp/node_fix1_workspace_check_final.log`.
