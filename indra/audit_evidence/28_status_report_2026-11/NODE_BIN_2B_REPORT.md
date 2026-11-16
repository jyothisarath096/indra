# NODE_BIN_2B report

## Unfinished or unproven

- The requested `unused_must_use` class is complete: the 13 warnings present before this task are absent from the final `cargo check --workspace` log. The node binary still has 93 pre-existing `clippy::unwrap_used` errors, concentrated in `start_network_runtime` (47) and `main` (46); this task did not convert those unrelated lock sites.
- The stale QC-response test proves the counter helper and the no-supervisor-report behavior of that path, but it is not an end-to-end network-thread race test. The certificate stale case is intentionally fail-closed and reports to the supervisor; it is not counted as a drop.
- No worktree or target directory was created by this task, so there was nothing task-created to delete.

## 1. Fallible helper results

The pre-change command was:

```text
cargo check --workspace 2>&1 | tee /tmp/node_bin2b_check_before.log
```

Its exact diagnostics reported 13 `unused std::result::Result` warnings in `indra-node/src/bin/node.rs`, at call sites 2686, 2810, 3416, 3420, 3460, 3472, 3478, 3532, 3772, 3787, 3803, 3819, and 3871. The warning text was `this Result may be an Err variant, which should be handled`; the log ended with `indra-node (bin "node") generated 13 warnings`.

Each call site now handles the result at its boundary in `indra-node/src/bin/node.rs`: spawned network and consensus tasks log the error, report it through `supervisor::report_unexpected`, and return; the startup/main-thread call prints `ERROR:` and exits 1. `#![deny(unused_must_use)]` is present in `indra-node/src/lib.rs` and every binary under `indra-node/src/bin/`.

The final check was:

```text
cargo check --workspace 2>&1 | tee /tmp/node_bin2b_workspace_check_final.log
```

It finished successfully. Counting `^warning:` and `unused \`std::result::Result\`` in that log produced no matches. No new check warning was emitted.

## 2. Real-binary startup test

The binary opens and validates the configured genesis through `NodeEngine::init` before it opens the vote-safety store in `indra-node/src/bin/node.rs` around lines 2510–2532; encrypted key loading occurs first in `load_keys_data` around lines 4700–4727. The corrected integration fixture therefore builds a valid four-validator manifest whose first hot validator is the generated encrypted keystore, then writes corrupt `data/vote_safety.dat` before launching the real binary.

The test is `node_refuses_corrupt_vote_safety_record_without_panic`, at `indra-node/tests/node_bin.rs:182`. It asserts non-zero exit, stderr containing `vote safety`, and no `panicked at` or `RUST_BACKTRACE`. The helper `valid_genesis_for` is at `indra-node/tests/node_bin.rs:68` and builds the valid manifest using the production crypto and PoP functions; it does not weaken the four-validator rule.

The exact command and final result were:

```text
cargo test -p indra-node --test node_bin -- --test-threads=1 2>&1 | tee /tmp/node_bin2b_node_bin_test.log

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.96s
```

The six tests are:

```text
node_refuses_corrupt_vote_safety_record_without_panic
node_refuses_invalid_genesis_without_panic
node_refuses_missing_config_without_panic
node_refuses_missing_keystore_without_panic
node_refuses_permissive_password_file_without_panic
node_refuses_wrong_keystore_password_without_panic
```

## 3. Stale provisional paths

The complete source search was:

```text
rg -n "take_provisional|clear_provisional|on_sync_caught_up|mark_caught_up|expire_outstanding|reset_round|provisional = None" indra-node/src/bin/node.rs indra-node/src/driver.rs indra-node/src/sync.rs
```

The paths are:

| Path | Role | Can clear between verification and take? |
|---|---|---|
| `indra-node/src/bin/node.rs:2766` | QCResponse verification is performed, then the provisional is taken under a later driver lock | Yes; this is the lock-gap stale-response path |
| `indra-node/src/bin/node.rs:3204` | Certificate verification and take occur while the same driver guard is held | No independent lock gap at this site |
| `indra-node/src/sync.rs:517` | `SyncState::take_provisional` consumes the slot | Called by the two paths above |
| `indra-node/src/sync.rs:522-523` | `SyncState::clear_provisional` | Called at the wrong-branch and invalid-proposal paths at `node.rs:3284` and `3300` |
| `indra-node/src/sync.rs:258` | Peer disconnect while caught up clears the provisional | May race with the QCResponse path |
| `indra-node/src/bin/node.rs:2642` and `indra-node/src/sync.rs:459` | Outstanding request expiry rotates a failed source | Does not directly take the provisional, but can lead to source failure and later clearing |
| `indra-node/src/bin/node.rs:3404` and `indra-node/src/driver.rs:730-731` | Catch-up transition calls `on_sync_caught_up`, which marks the sync state caught up | The transition can clear sync state through the surrounding sync flow |
| `indra-node/src/driver.rs:2160` and `indra-node/src/sync.rs:628` | Driver-side caught-up marking | State transition only; no direct take |
| `indra-node/src/bin/node.rs:2795` and `3253` | Round reset after successful import | Does not clear provisional itself |

At `node.rs:2766`, `None` is a stale QCResponse after verification and is now logged, counted as `kind="qc_response"`, and dropped without a supervisor report. At `node.rs:3204`, the guard spans verification and take; `None` is therefore a broken invariant, so it now logs `CRITICAL`, reports `authenticated-network-events` to the supervisor, and terminates that critical task rather than silently dropping the certificate.

The metrics implementation is in `indra-node/src/metrics.rs:175-187`: `MetricsState::record_stale_sync_response` increments the bounded `qc_response` or `certificate` counter, and the rendered endpoint exposes `indra_stale_sync_responses_total{kind="qc_response"}` and `{kind="certificate"}`. The focused test `stale_qc_response_is_counted_without_supervisor_report` is at `indra-node/src/metrics.rs:966`. It exercises the counter and confirms the certificate counter remains zero; a live network race test was not added.

## 4. Remaining lock/read/write inventory

The inventory command was:

```text
rg -n "\\.(?:lock|read|write)\\(\\)" indra-node/src --glob '*.rs'
```

The full 163-line captured inventory, including function and production/test-only classification, is `/tmp/node_bin2b_lock_table.txt`. The following table groups every remaining non-converted use by source region; the exact line-by-line rows are in that captured output.

| File and lines | Function(s) | Pattern / poison behavior | Scope |
|---|---|---|---|
| `indra-node/src/bin/node.rs:168,193` | `ExpensiveSemaphore::{acquire_until,drop}` | `.lock().ok()?` / `if let Ok`; fail closed or silently skip semaphore bookkeeping | production |
| `indra-node/src/bin/node.rs:685,699,2947,2995,3081,4168,5829` | operation relay and broadcast helpers | `if let Ok` cache lock; operation dedup/cache update is skipped on poison | production |
| `indra-node/src/bin/node.rs:1233-1854` | `start_network_runtime` | many `.unwrap()` mutex/RwLock reads and writes; a poisoned lock panics | production |
| `indra-node/src/bin/node.rs:2560-4163` | `main` network and consensus loops | many `.unwrap()` driver, handshake, discovery, and cache locks; poison panics | production |
| `indra-node/src/bin/node.rs:4813,4885` | `spawn_rpc_listener` | `match` on lock result; listener returns an error path on poison | production |
| `indra-node/src/bin/node.rs:5502,5829,5891` | `handle_rpc`, `lock_driver_for_rpc` | matched or `if let Ok` lock handling; RPC fails closed or reports an error | production |
| `indra-node/src/bin/observer.rs:284,416,438,447` | observer serving/status helpers | mapped error at 284/416, but `unwrap` at 438 and `unwrap_or(0)` at 447 | production |
| `indra-node/src/hardened_read_rpc.rs:114,137,160,249,286` | limiter and hardened observer RPC | `.ok()?`, `if let Ok`, or matched error; capacity operation fails closed | production |
| `indra-node/src/metrics.rs:147,154,168,229,253,517` | metrics registration/rendering | `unwrap_or_else` poison recovery for telemetry, `if let Ok` for optional counters, and matched lock failures for snapshots | production |
| `indra-node/src/qc_verification.rs:87` | `take_worker_handle` | `.lock().ok()?`; worker handle retrieval fails closed | production |
| `indra-node/src/rpc_snapshot.rs:296,319,348` | snapshot `load`, `publish`, `publish_with_effects` | direct `read`/`write` locks; remaining handling is outside the requested conversion | production |
| `indra-node/src/bin/node.rs:6082,6846,7199-7392,7808,8325-8329` | node binary unit tests | test-only `.unwrap()` assertions and fixture locks | test-only |
| `indra-node/src/hardened_read_rpc.rs:643`, `indra-node/src/metrics.rs:939` | unit tests | test-only poisoning/metrics fixture locks | test-only |

These remaining sites were not converted in this task. The requested helper conversions use `indra-node/src/locks.rs`, whose poisoned-lock path calls `supervisor::report_unexpected` and returns `NodeError::LockPoisoned`.

## 5. Clippy inventory

The comparison commands were:

```text
cargo clippy -p indra-node --bin node --no-deps --message-format=short 2>&1 | tee /tmp/node_bin2_clippy_before.log
cargo clippy -p indra-node --bin node --no-deps --message-format=short 2>&1 | tee /tmp/node_bin2b_clippy_final.log
```

The earlier NODE_BIN_2 log reported 126 `used unwrap()` errors. The final command reports 93 `used unwrap()` errors and 31 warning lines across the node library and binary output. The 93 remaining errors group by function as follows, using the current `node.rs` source ranges:

| Function | Remaining `unwrap()` errors |
|---|---:|
| `start_network_runtime` | 47 |
| `main` | 46 |

Those are outside the specifically converted helper set. No `#[allow]` was added.

## 6. Workspace verification

The final corrected-tree debug command was:

```text
cargo test --workspace 2>&1 | tee /tmp/node_bin2b_workspace_debug_final.log
```

It finished with `test result: ok. 335 passed; 0 failed; 5 ignored` for `indra-node`’s library target and `test result: ok. 6 passed; 0 failed; 0 ignored` for `tests/node_bin.rs`. The aggregate over all `test result:` lines is **1,631 passed; 0 failed; 10 ignored**.

The final corrected-tree release command was:

```text
cargo test --workspace --release 2>&1 | tee /tmp/node_bin2b_workspace_release.log
```

It finished with `test result: ok. 335 passed; 0 failed; 5 ignored` for the node library and `test result: ok. 6 passed; 0 failed; 0 ignored` for `tests/node_bin.rs`. The aggregate is **1,631 passed; 0 failed; 10 ignored**.

Per-target counts, in the same order in both logs, are:

| Package/target | Passed | Failed | Ignored |
|---|---:|---:|---:|
| `indra-bench` lib | 19 | 0 | 0 |
| `indra-cli` lib | 85 | 0 | 0 |
| CLI genesis/governance/keygen/send/stake/tx/wallet-scan bins | 7 / 9 / 1 / 1 / 9 / 2 / 3 | 0 | 0 |
| CLI integration `tests/cli.rs` | 24 | 0 | 0 |
| `indra-consensus` lib + integration | 60 + 5 | 0 | 0 |
| `indra-core` lib + serialisation | 154 + 21 | 0 | 0 |
| `indra-crypto` lib + audit/benchmark integration | 38 + 2 + 1 | 0 | 0 |
| `indra-ffi` lib | 26 | 0 | 0 |
| `indra-keystore` lib | 22 | 0 | 0 |
| `indra-network` lib + integration | 158 + 4 | 0 | 1 |
| `indra-node` lib | 335 | 0 | 5 |
| `indra-node` binary unit tests | 93 | 0 | 0 |
| `indra-node/tests/node.rs` | 17 | 0 | 0 |
| `indra-node/tests/node_bin.rs` | 6 | 0 | 0 |
| `indra-rpc` lib + integration | 68 + 35 | 0 | 0 |
| `indra-state` lib + audit_phase2/monetary/state_machine | 337 + 4 + 10 + 25 | 0 | 3 |
| `indra-storage` lib | 48 | 0 | 1 |
| doc tests (`indra-rpc` only nonzero) | 1 | 0 | 0 |

The first debug run in `/tmp/node_bin2b_workspace_debug.log` is retained as a diagnostic record: it ran the pre-format-fix binary and failed only `metrics::tests::test_render_metrics_prometheus_format`; it ended `334 passed; 1 failed; 5 ignored`. The corrected focused rerun was `/tmp/node_bin2b_metrics_format_fix.log`, with `1 passed; 0 failed; 0 ignored`, followed by the clean full debug log above.

## 7. Disk and change summary

The required initial disk check was:

```text
df -h .
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   192Gi    10Gi    95%    2.0M  107M    2%   /System/Volumes/Data
```

The final check was:

```text
df -h .
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   192Gi   9.9Gi    96%    2.0M  104M    2%   /System/Volumes/Data
```

No task-created worktree or target directory existed. The source diff summary for this task’s selected files was:

```text
indra-node/src/bin/audit_block_log.rs      |   1 +
indra-node/src/bin/dns_seed_sign.rs        |   1 +
indra-node/src/bin/indra-sync-recover.rs   |   1 +
indra-node/src/bin/node.rs                 | 374 ++++++++++++++++---------
indra-node/src/bin/observer.rs             |   1 +
indra-node/src/lib.rs                       |   1 +
indra-node/src/metrics.rs                   |  38 +++
7 files changed, 292 insertions(+), 125 deletions(-)
```

`indra-node/tests/node_bin.rs` and this report are untracked additions. Existing unrelated untracked audit reports and prior working-tree changes were preserved.
