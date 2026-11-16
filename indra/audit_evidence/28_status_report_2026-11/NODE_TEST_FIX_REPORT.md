# Node test fixture race fix report

## Scope and result

[verified just now] The repository was inspected at /Users/bonkai/Desktop/indra/project_indra/indra; the workspace HEAD was 857d5cb2682304294475f0cf2e0b2133bdd78fda.

[verified just now] Only indra-node/src/driver_tests.rs and this report are changed in the current checkout. No production source, manifest, rust-toolchain.toml, or Cargo.lock was edited by this task. The final status shows Cargo.lock is clean in this checkout, contrary to the stale task context that described an existing lockfile change. No assertion, timestamp, seed, or test logic was changed.

[verified just now] cargo tree -i tempfile -e all shows tempfile v3.27.0 under indra-node's dev-dependencies, so the fix required no manifest change.

[verified just now] temp_dir now obtains a unique directory from tempfile::Builder::new().prefix(...).tempdir().unwrap().keep(). The returned PathBuf is retained by the test and remains stable for the life of that test. local_driver delegates to local_driver_at_dir, allowing restart tests to reopen the same path. last_qc_restored_on_restart now passes its existing path explicitly to local_driver_at_dir instead of recreating a process-ID/suffix path.

[verified just now] The five default-parallel node-library runs, the complete single-threaded node-library run, the correctly qualified isolated multiseed test, the workspace test run, and the audit-harness feature run all completed without failures. The strict-prevote and multiseed failures described in the earlier diagnosis did not recur after the fix.

## Verification labels

[verified just now] “Verified just now” means the command or source inspection was performed during this task on 6 November 2026 and its raw log is identified below. “Taken from an earlier report” is used only for historical comparison supplied by the earlier diagnosis.

## Part 1: fix verification

[verified just now] The source diff is limited to this behavior: a fixture call receives a fresh tempfile directory; the directory is kept as a PathBuf; drivers, engines, and stores continue to be constructed from that path; and the restart test reuses the same path explicitly. Existing test-owned cleanup remains in the tests that already performed it. No cleanup was added that removes a shared fixed name.

[verified just now] The owner of a kept temporary directory is the returned PathBuf held by the test. In the restart case, the path local is declared before the driver and is reused for the reopened driver, so the path value outlives both driver instances. The patch did not alter the existing driver/store drop scopes or cleanup assertions.

## Part 2: test results

### Five default-parallel runs

[verified just now] Command: cargo test -p indra-node --lib. Logs: /tmp/indra-node-fix-parallel-20261106/run-1.log through run-5.log.

| Run | Exit | Shell wall time | Test result |
|---|---:|---:|---|
| 1 | 0 | 406 s | 302 passed; 0 failed; 5 ignored; finished in 401.85s |
| 2 | 0 | 418 s | 302 passed; 0 failed; 5 ignored; finished in 416.89s |
| 3 | 0 | 444 s | 302 passed; 0 failed; 5 ignored; finished in 444.46s |
| 4 | 0 | 451 s | 302 passed; 0 failed; 5 ignored; finished in 451.10s |
| 5 | 0 | 465 s | 302 passed; 0 failed; 5 ignored; finished in 464.75s |

[verified just now] No failing test name or failure text was emitted in any of the five logs. The default-parallel run was green on all five attempts.

### Complete single-threaded run

[verified just now] Command: nohup cargo test -p indra-node --lib -- --test-threads=1, polled in the background, log /tmp/indra-node-fix-serial-correct-20261106.log. It exited 0 and completed in 1237.10s according to Cargo, approximately 20m37.10s wall time. The final test reached was sync::tests::wrong_height_rejected.

[verified just now] Exact final result: 302 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 1237.10s. The single-threaded run was green to completion.

[taken from an earlier report] The earlier diagnosis described a 307-test node library target and intermittent audit failures; the current result separates that total into 302 passing and 5 ignored tests.

### Isolated multiseed test

[verified just now] The literal command requested, cargo test -p indra-node --lib audit_harness_four_validator_multiseed_chaos_converges -- --exact --test-threads=1, selected zero tests because the exact test name is module-qualified. Its exact result was 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s, with /usr/bin/time reporting real 0.37.

[verified just now] The correctly qualified command was then run without an alarm: cargo test -p indra-node --lib driver::tests::audit_harness_four_validator_multiseed_chaos_converges -- --exact --test-threads=1. Log: /tmp/indra-node-fix-multiseed-full-20261106.log. Exact result: 1 passed; 0 failed; 0 ignored; 0 measured; 306 filtered out; finished in 228.72s; /usr/bin/time reported real 229.04, user 215.39, and sys 1.28. It finished in about 3m49.04s, well below the 60-minute cap.

### Workspace and feature runs

[verified just now] cargo test --workspace exited 0. /usr/bin/time reported real 666.48, user 2100.36, and sys 15.58, about 11m06.48s wall time. All targets passed; the raw log is /tmp/indra-fix-workspace-20261106.log.

[verified just now] The workspace run's per-target pass/fail/ignored counts were: indra-bench lib 19/0/0; indra-cli lib 52/0/0 and cli.rs 12/0/0; indra-genesis 2/0/0; indra-governance 9/0/0; indra-keygen 0/0/0; indra-send 1/0/0; indra-stake 9/0/0; indra-tx 2/0/0; indra-wallet_scan 0/0/0; indra-consensus lib 59/0/0 and consensus.rs 5/0/0; indra-core lib 148/0/0 and serialisation.rs 21/0/0; indra-crypto lib 38/0/0, audit_phase1.rs 2/0/0, and bench_dilithium.rs 1/0/0; indra-ffi 26/0/0; indra-keystore 22/0/0; indra-network lib 158/0/1 and network.rs 4/0/0; indra-node lib 302/0/5, node.rs integration tests 15/0/0, and the node binary targets emitted 1/0/0 and 91/0/0; indra-rpc lib 68/0/0 and rpc.rs 35/0/0; indra-state lib 316/0/2, audit_phase2.rs 4/0/0, monetary_invariants.rs 10/0/0, and state_machine.rs 22/0/0; indra-storage lib 47/0/1. The remaining doctest targets were zero-test successes except for the RPC doctest, which was 1/0/0.

[verified just now] cargo test -p indra-node --features audit-harness exited 0. /usr/bin/time reported real 492.60, user 1784.45, and sys 11.49, about 8m12.60s wall time. The node library result was 302 passed; 0 failed; 5 ignored; the node binary and integration targets also passed. Raw log: /tmp/indra-fix-audit-harness-20261106.log.

### Residual failures

[verified just now] There were no residual failures after the fix. The strict-prevote test passed in the complete serial run, and the isolated multiseed test passed with one test selected. Therefore neither observed error is currently evidence of a separate post-fix logic regression.

## Part 3: other temporary-directory helpers

[verified just now] git grep over indra-node/src found the following helpers and PID-containing paths. These helpers were inspected but not edited.

| File and lines | Helper/path | Same-module collision assessment |
|---|---|---|
| indra-node/src/config_file.rs:627-636 | temp_file uses PID plus MetricsState::new().started_at.elapsed().as_nanos() | Not process-ID-only. Calls use distinct names in the module; a collision would require the same name and identical nanosecond suffix. |
| indra-node/src/discovery.rs:1766-1773 | Inline state path uses PID plus elapsed nanoseconds | Not process-ID-only; no fixed same-module path was found. |
| indra-node/src/discovery.rs:2058-2061 | indra_peers_<pid>_round_trip.json | Only the round-trip test uses this fixed suffix; the missing-file test uses a different suffix, so no same-module collision was found. |
| indra-node/src/engine.rs:1899-1907 | temp_dir(suffix) uses indra_engine_test_<suffix>_<pid> | The inspected call sites use distinct suffixes; no duplicate suffix in this module was found. Reusing a suffix would collide because PID is shared, but current calls do not do so. |
| indra-node/src/genesis.rs:1167-1170, 1250-1253, 1283, 1343-1346 | Four PID-based entropy, fingerprint, order, and transparent-output paths | Each path is used by a distinct test and no same-module duplicate fixed path was found. |
| indra-node/src/sync.rs:1211-1215 | indra_sync_test_<suffix>_<pid> | Call suffixes inspected were distinct; no same-module collision was found. Reusing a suffix would collide because PID is shared. |
| indra-node/src/bin/node.rs:5765-5769 | Private config path includes PID and random u64 | Random component makes same-module collision unlikely; it is not PID-only. |
| indra-node/src/bin/node.rs:5790-5796 | indra_node_proposer_authority_<suffix>_<pid> | PID-containing and suffix-based; no duplicate suffix call was found in the inspected test helper. |
| indra-node/src/bin/node.rs:8155-8156, 8179-8180 | indra_node_pruned_blocks_<pid> and indra_node_in_range_blocks_<pid> | Different suffixes and distinct tests; no collision between the two paths was found. |

[verified just now] The former driver_tests.rs helper used indra_driver_test_<suffix>_<pid>, and shared_four_validator_fixture reused fixed suffixes. The new tempfile allocation removes that shared-name collision for every fixture call in that file.

## Appendix: raw command outputs

### Dependency confirmation

[verified just now] Command: cargo tree -i tempfile -e all

    tempfile v3.27.0
    ├── tempfile feature "default"
    │   └── indra-bench ... [normal]
    │       ...
    │   [dev-dependencies]
    │   └── indra-node ...

[verified just now] The complete dependency tree was written by Cargo; the relevant lines above show tempfile available through indra-node dev-dependencies. No manifest edit was necessary.

### Node-library raw result lines

[verified just now] The five parallel log result lines were:

    test result: ok. 302 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 401.85s
    test result: ok. 302 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 416.89s
    test result: ok. 302 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 444.46s
    test result: ok. 302 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 451.10s
    test result: ok. 302 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 464.75s

[verified just now] The serial log ended with:

    test sync::tests::wrong_height_rejected ... ok

    test result: ok. 302 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 1237.10s

[verified just now] The isolated multiseed log was:

    running 1 test
    test driver::tests::audit_harness_four_validator_multiseed_chaos_converges ... ok

    test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 306 filtered out; finished in 228.72s

    real 229.04
    user 215.39
    sys 1.28

[verified just now] The literal unqualified command produced:

    running 0 tests
    test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
    real 0.37

[verified just now] cargo test --workspace and cargo test -p indra-node --features audit-harness both ended with exit code 0. Their complete raw outputs remain in /tmp/indra-fix-workspace-20261106.log and /tmp/indra-fix-audit-harness-20261106.log; the per-target result lines are summarized above without alteration to their counts.

[verified just now] A read-only cargo fmt --all -- --check was also run. It reported existing repository-wide formatting differences and was not applied; no source files were changed by that command. git diff --check produced no whitespace-error output for the changes made in this task.

## Final working-tree check

[verified just now] The final git status --short and git diff --stat were run after writing this report. The status showed the edited driver test, the pre-existing untracked root entries, and the untracked report directory. Cargo.lock did not appear because it is clean in this checkout. The diff stat counted only tracked-file diffs, so the new untracked report file does not appear in it.

    M indra/indra-node/src/driver_tests.rs
    ?? indra/14340
    ?? indra/6148
    ?? indra/8196
    ?? indra/audit_evidence/28_status_report_2026-11/

    indra/indra-node/src/driver_tests.rs | 19 ++++++++++---------
    1 file changed, 10 insertions(+), 9 deletions(-)

