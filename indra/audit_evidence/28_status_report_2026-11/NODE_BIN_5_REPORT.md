# Node Bin 5 report

Anything unfinished or unproven: the complete workspace suites and final clippy run are green, but the source guard is text-based and therefore cannot detect lock aliases, macro expansion, generated code, or synchronization primitives in other crates. The report does not claim a formal proof that every future lock use will be caught.

## Scope and behavior

Node Bin 5 removes the remaining production paths that converted poisoned locks into absence, recovered values, or silent telemetry loss. The centralized policy is implemented by `indra-node/src/locks.rs:12-52`: report through the supervisor first, return `NodeError::LockPoisoned`, and let the boundary fail closed. Condition-variable waits use the same helper at `indra-node/src/locks.rs:35-44`.

Converted boundaries include:

- `indra-node/src/qc_verification.rs:89`: `take_worker_handle` returns `NodeResult<Option<JoinHandle<()>>>`; a poisoned handle slot is an error, not `None`.
- `indra-node/src/rpc_snapshot.rs:294-350`: `load`, `publish`, and `publish_with_effects` return `NodeResult`; `indra-node/src/error.rs` has the explicit `RpcSnapshot` error for snapshot-build failures.
- `indra-node/src/metrics.rs:148-172,219-263,510-825`: metrics registration, aggregation, panic recording, driver/engine rendering and rendering of shared counters propagate typed errors rather than rendering a lock-error gauge or swallowing poison.
- `indra-node/src/hardened_read_rpc.rs:113-153,168-308`: observer semaphore, `Drop`, engine acquisition and per-IP accounting use the helper; `Permit::drop` terminates fatally because `Drop` cannot return a result.
- `indra-node/src/bin/node.rs:194-229,4860-4955,5560-5685,5888-5990` and `indra-node/src/bin/observer.rs:285-460`: RPC, observer, semaphore, diagnostics, relay-cache and cleanup boundaries fail closed.

For `Drop`, the guard has not yet returned to the caller when the lock is poisoned, so `terminate_fatal` is used immediately after the helper reports. No later code runs to observe or partially release the permit; the process exits before another state transition can use that semaphore.

## Tests added or changed

- `indra-node/src/qc_verification.rs:214-226`, `qc_verification::tests::poisoned_worker_handle_is_not_reported_as_absent`: a deliberately poisoned worker-handle slot returns `NodeError::LockPoisoned`.
- `indra-node/src/rpc_snapshot.rs:595-607`, `rpc_snapshot::tests::poisoned_snapshot_is_not_served_as_current_or_replaced`: both `load` and `publish` fail on a poisoned current-snapshot lock.
- `indra-node/src/locks.rs:119-146`, `locks::tests::production_lock_inventory_has_no_direct_lock_calls`: scans production source text for forbidden direct/fallback lock patterns.
- Existing lock tests in `indra-node/src/locks.rs:48-116` continue to assert one report per poisoned mutex/RwLock and no deadlock.

## Verification

All commands ran from `/Users/bonkai/Desktop/indra/project_indra/indra`.

| command | result | log |
|---|---|---|
| `df -h .` before work | 12 GiB available | terminal output; final check below |
| `cargo check --workspace` | PASS | `/tmp/node_bin5_workspace_check_final.log` |
| `cargo test --workspace` | PASS; 1,641 passed / 0 failed / 10 ignored | `/tmp/node_bin5_workspace_debug_final4.log` |
| `cargo test --workspace --release` | PASS; 1,641 passed / 0 failed / 10 ignored | `/tmp/node_bin5_workspace_release_final3.log` |
| `cargo clippy -p indra-node --bin node --lib --no-deps` | PASS; 0 errors and 0 denied findings; 32 warning lines (13 library and 17 node-binary warnings, with repeated warning headers) | `/tmp/node_bin5_clippy_final.log` |
| focused QC poison tests | PASS; 2 passed / 0 failed | `/tmp/node_bin5_qc_tests_final.log` |
| focused snapshot poison test | PASS; 1 passed / 0 failed | terminal output |
| production lock inventory guard | PASS; 1 passed / 0 failed | terminal output |

Workspace target totals from the final debug and release logs are identical. Per crate, the totals are: `indra-bench` 19/0/0; `indra-cli` 141/0/0; `indra-consensus` 65/0/0; `indra-core` 175/0/0; `indra-crypto` 41/0/0; `indra-ffi` 26/0/0; `indra-keystore` 22/0/0; `indra-network` 162/0/1; `indra-node` 462/0/5; `indra-rpc` 103/0/0; `indra-state` 376/0/3; `indra-storage` 49/0/1. The workspace sum is 1,641 passed / 0 failed / 10 ignored. Within `indra-node`, the library is 344/0/5, the binary unit/integration targets are 1+93+17+7 passed, and the remaining binary targets have no tests. Other ignored tests are the pre-existing release benchmarks: network 1, state 3, and storage 1.

The first final release attempt (`/tmp/node_bin5_workspace_release_final2.log`) exposed a test-only cross-test supervisor-channel race: `qc_worker_exit_is_reported_as_task_exit` observed `TaskExited { name: "poisoned-lock", reason: "lock network-qc-verifier.worker_handle is poisoned" }`; the test now ignores unrelated supervisor outcomes while waiting for its named worker, and the rerun in `final3` is green. This does not change production behavior.

The full debug workspace log predates only that final test-only wait-loop adjustment; `/tmp/node_bin5_qc_tests_final.log` reran both affected QC tests afterward, and no production source changed between the debug workspace run and that adjustment.

The clippy warnings are non-fatal existing lint classes (documentation spacing, print literal, `io_other_error`, large enum variants, manual saturating arithmetic, argument-count/type-complexity, `len_zero`, collapsible-if, needless-borrow and single-match). No warning was promoted to an error and no new `allow` was added.

## Final filesystem check

Final `df -h .` output:

```text
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   189Gi    12Gi    95%    2.0M  122M    2%   /System/Volumes/Data
```

The report and inventory are untracked. Existing unrelated worktree changes and reports were preserved; no commit, stage, stash, restore, or checkout was performed.
