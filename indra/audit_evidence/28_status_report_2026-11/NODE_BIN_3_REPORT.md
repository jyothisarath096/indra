# Node Bin 3 report

Unfinished or unproven:

- The live P2P runtime was not exercised with an injected poisoned lock; the lock inventory is a source scan plus the existing typed poison tests.
- The supervisor reports every supervised Tokio-task exit, but this task did not add a production shutdown flag; the shutdown watcher exits the process after saving peers.
- The existing 46 `clippy::unwrap_used` errors in `main` remain. The requested `start_network_runtime` group is reduced to zero; no unrelated `main` cleanup was performed.

## Scope and disk check

Verified just now from `/Users/bonkai/Desktop/indra/project_indra/indra`. The starting `df -h .` output reported 9.9 GiB available, so the task proceeded. No worktree or additional target directory was created by this task.

## Lock handling

`start_network_runtime` now routes its lock and read sites through the fail-closed wrappers at `indra-node/src/bin/node.rs:1226-1248`, which call `indra-node/src/locks.rs:7-16`. The wrapper emits an error, reports `p2p-runtime` to the supervisor, and terminates the process; it does not recover a poisoned guard. The source inventory is copied into [NODE_BIN_3_LOCK_INVENTORY.md](NODE_BIN_3_LOCK_INVENTORY.md).

The direct-pattern scan found no lock `.lock()`, `.read()`, `.write()`, or `if let Ok(` sites in the function. The only remaining `.ok()` calls are parsing conversions at the scan’s reported local lines 376 and 427. This is a source-scan result, not a proof that every future edit will preserve the policy.

## Tokio task supervision

The four process-lifetime P2P tasks are supervised by `indra-node/src/supervisor.rs:145-175` and invoked at `indra-node/src/bin/node.rs:1335`, `1442`, `1556`, and `1855`: event forwarding, inbound listener, outbound dialer/discovery, and the shutdown watcher. The helper awaits the child `JoinHandle` and reports normal return, `NodeResult` error, cancellation, or panic.

Inbound and outbound per-connection tasks at `indra-node/src/bin/node.rs:1518` and `1789` use `supervisor::spawn_connection` at `indra-node/src/supervisor.rs:178-193`. A panic is caught, logged, and counted via `MetricsState::record_handler_panic` rather than terminating the runtime.

Library tests run just now: `supervisor::tests::critical_task_return_is_reported_once`, `critical_task_panic_is_reported_once`, and `connection_task_panic_is_counted_without_stopping_runtime` all passed, along with the four existing supervisor tests: 7 passed, 0 failed, 0 ignored. These are helper-level tests; no live socket task panic was injected.

## Clippy and check status

The current command `cargo clippy -p indra-node --bin node --no-deps --message-format=short` reports 0 `unwrap()` errors in `start_network_runtime` and 46 remaining `unwrap()` errors in `main`. The full raw output is `/tmp/node_bin3_clippy_final2.log`. `cargo check --workspace` completed successfully with no warnings; raw output is `/tmp/node_bin3_workspace_check_final.log`.

## Raw command outputs

The complete outputs are retained at:

- `/tmp/node_bin3_check1.log` through `/tmp/node_bin3_check10.log` (incremental node-bin checks).
- `/tmp/node_bin3_supervisor_test_final.log`.
- `/tmp/node_bin3_clippy_final2.log`.
- `/tmp/node_bin3_workspace_check_final.log`.
- `/tmp/node_bin3_workspace_debug_final.log`.
- `/tmp/node_bin3_workspace_release_final.log`.

## Verification results

`cargo check --workspace` passed with no warnings: `/tmp/node_bin3_workspace_check_final.log`.

`cargo test --workspace` passed: 1,634 passed, 0 failed, 10 ignored. The per-target result lines are in `/tmp/node_bin3_workspace_debug_final.log`; the principal targets were:

| Target | Passed | Failed | Ignored |
|---|---:|---:|---:|
| `indra-bench` unit | 19 | 0 | 0 |
| `indra-cli` unit | 85 | 0 | 0 |
| `indra-cli` `genesis` binary | 7 | 0 | 0 |
| `indra-cli` `governance` binary | 9 | 0 | 0 |
| `indra-cli` `keygen` binary | 1 | 0 | 0 |
| `indra-cli` `send` binary | 1 | 0 | 0 |
| `indra-cli` `stake` binary | 9 | 0 | 0 |
| `indra-cli` `tx` binary | 2 | 0 | 0 |
| `indra-cli` `wallet_scan` binary | 3 | 0 | 0 |
| `indra-cli` integration | 24 | 0 | 0 |
| `indra-consensus` unit | 60 | 0 | 0 |
| `indra-consensus` integration | 5 | 0 | 0 |
| `indra-core` unit | 154 | 0 | 0 |
| `indra-core` integration | 21 | 0 | 0 |
| `indra-crypto` unit | 38 | 0 | 0 |
| `indra-crypto` integration `audit_phase1` | 2 | 0 | 0 |
| `indra-crypto` integration `bench_dilithium` | 1 | 0 | 0 |
| `indra-ffi` unit | 26 | 0 | 0 |
| `indra-keystore` unit | 22 | 0 | 0 |
| `indra-network` unit | 158 | 0 | 1 |
| `indra-network` integration | 4 | 0 | 0 |
| `indra-node` library | 338 | 0 | 5 |
| `node` binary unit | 93 | 0 | 0 |
| `indra-node` integration | 17 | 0 | 0 |
| `node_bin` integration | 6 | 0 | 0 |
| `indra-rpc` unit | 68 | 0 | 0 |
| `indra-node` filtered binary unit invocation | 1 | 0 | 0 |
| `indra-state` unit | 337 | 0 | 3 |
| `indra-state` integration `audit_phase2` | 4 | 0 | 0 |
| `indra-state` integration `monetary_invariants` | 10 | 0 | 0 |
| `indra-state` integration `state_machine` | 25 | 0 | 0 |
| `indra-storage` unit | 48 | 0 | 1 |
| `indra-storage` doc-test invocations | 1 | 0 | 0 |
| `indra-rpc` doc test | 1 | 0 | 0 |

`cargo test --workspace --release` passed: 1,634 passed, 0 failed, 10 ignored. The corresponding raw per-target lines are in `/tmp/node_bin3_workspace_release_final.log`; the target counts are the same as the debug run, with the node library at 338/0/5, node binary at 93/0/0, node integration at 17/0/0, and `node_bin` at 6/0/0.

`cargo test -p indra-node --lib supervisor:: -- --test-threads=1` passed: 7 passed, 0 failed, 0 ignored; `/tmp/node_bin3_supervisor_test_final.log`.

`cargo clippy -p indra-node --bin node --no-deps --message-format=short` produced 0 `unwrap()` errors in `start_network_runtime` and 46 remaining `unwrap()` errors in `main`; `/tmp/node_bin3_clippy_final2.log`.

No test failed in either full workspace run.
