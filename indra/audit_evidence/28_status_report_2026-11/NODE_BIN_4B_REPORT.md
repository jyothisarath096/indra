# Node Bin 4B report

Anything unfinished or unproven: the node binary and metrics per-connection threads use local `catch_unwind` containment rather than the node supervisor because they are short-lived request handlers; the report records that distinction explicitly. The started-node SIGINT variant was not added because SIGTERM is the POSIX service-manager signal exercised here.

All paths below are relative to /Users/bonkai/Desktop/indra/project_indra/indra. Changes are layered on the uncommitted Node Bin 4 work; no commit, stage, stash, restore, or checkout was performed.

## 1. Direct lock handling

The direct-lock audit was run with:

    rg -n '\.lock\(\)|\.read\(\)|\.write\(\)' indra-node/src/bin/node.rs

The 13 sites identified by the Bin 4 inventory were the relay-dedup and driver locks in the authenticated network event loop, the main peer-list cache insertion, the RPC diagnostics driver, RPC transaction relay cache, and lock_driver_for_rpc. They now use supervised_lock!, locks::lock, or a reporting map_err as follows:

| Location | Code shape after the change | Poison handling |
|---|---|---|
| indra-node/src/bin/node.rs:2958-2965 | supervised_lock!(op_relay_seen, ...staking); supervised_lock!(driver, ...staking) | locks::lock reports poisoned-lock and the task returns |
| indra-node/src/bin/node.rs:2989-2996 | governance relay and driver use supervised_lock! | report, then task returns |
| indra-node/src/bin/node.rs:3015-3024 | transaction relay and driver use supervised_lock! | report, then task returns |
| indra-node/src/bin/node.rs:3027-3028 | accepted transaction cache insertion uses supervised_lock! | report, then task returns |
| indra-node/src/bin/node.rs:3050-3062 | transaction-stem relay and driver use supervised_lock! | report, then task returns |
| indra-node/src/bin/node.rs:3065-3066 | transaction-stem cache insertion uses supervised_lock! | report, then task returns |
| indra-node/src/bin/node.rs:3142-3143 | peer-list cache insertion uses supervised_lock! | report, then task returns |
| indra-node/src/bin/node.rs:4208-4209 | main peer-list cache insertion uses locks::lock(...)? | reports and returns NodeError from run |
| indra-node/src/bin/node.rs:5542-5562 | diagnostics uses lock_driver_for_rpc | reports and returns a typed RPC error |
| indra-node/src/bin/node.rs:5898-5918 | transaction relay cache has an explicit reporting match | reports and returns an internal RPC error |
| indra-node/src/bin/node.rs:5977-5983 | lock_driver_for_rpc reports in map_err | reports and returns the error to the RPC caller |

The two helper functions at indra-node/src/bin/node.rs:710-718 and :724-733 now call locks::lock and report before returning without broadcasting. These guard relay-dedup state and are not safe to treat as cache misses.

The RPC semaphore at indra-node/src/bin/node.rs:193-249 now reports poison while acquiring, waiting, or releasing. It fails closed by returning no permit. The per-IP RPC peer state at indra-node/src/bin/node.rs:4877-4895 and :4953-4970 reports poison and rejects or completes the connection without using corrupted state.

The GossipState lock calls around indra-node/src/bin/node.rs:7330-7350 are inside the binary's cfg(test) mod tests at :6133, not production. They remain test setup assertions. Metrics-only lock failures in indra-node/src/metrics.rs remain telemetry fallbacks and are listed in the inventory below.

## 2. Started-node shutdown proof

Added test: node_started_from_valid_fixture_stops_cleanly_on_sigterm in indra-node/tests/node_bin.rs (the test uses the same four-validator valid-genesis fixture and encrypted keystore helper as node_refuses_corrupt_vote_safety_record_without_panic). It starts the real node binary, disables observer and metrics listeners, binds a real ephemeral P2P port, waits up to 60 seconds for both Starting P2P and consensus and [shutdown] watcher ready, sends SIGTERM, waits up to 10 seconds, and asserts exit code 0 with no ERROR or panicked at in stderr.

The test initially demonstrated that sending SIGTERM immediately after the startup line was too early: the process exited with signal 15. The test now waits for the watcher-ready marker emitted in indra-node/src/bin/node.rs:1890-1892, so the signal is delivered after the watcher is installed. The final focused run passed:

    cargo test -p indra-node --test node_bin node_started_from_valid_fixture_stops_cleanly_on_sigterm -- --nocapture
    test node_started_from_valid_fixture_stops_cleanly_on_sigterm ... ok
    test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out; finished in 3.94s

The runtime path is: wait_for_shutdown_signal at indra-node/src/bin/node.rs:94-116 receives SIGTERM/SIGINT; the watcher at :1884-1903 saves discovered and connected peers, prints the save result, and calls std::process::exit(0). It flushes no explicit stderr at that call site, but each eprintln! is line-buffered by the process stderr and the test observed a clean exit. The main supervisor loop at :4120-4126 reports unexpected task exits only when it receives TaskExited; the watcher exits the whole process directly, so no later supervisor report can race the clean exit.

## 3. New failure-path coverage

Added tests:

* indra-node/src/locks.rs:73-89, poisoned_lock_in_spawned_task_reports_once_and_returns_error: a poisoned mutex is accessed from a spawned thread through the production lock helper; the task returns a LockPoisoned error and exactly one report is counted.
* indra-node/src/locks.rs:93-113, simultaneous_poisoned_locks_report_without_deadlock: two mutexes are poisoned concurrently, then both fail closed and produce exactly two reports.
* indra-node/src/supervisor.rs:316-333, terminate_fatal_subprocess_exits_one_and_reports_once: a subprocess re-enters the test with an environment marker, calls terminate_fatal, and asserts exit code 1, one ERROR: supervisor test cause, and no panic text.

The focused lock and supervisor runs passed:

    cargo test -p indra-node --lib poisoned -- --nocapture
    test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 342 filtered out
    cargo test -p indra-node --lib simultaneous_poisoned -- --nocapture
    test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 345 filtered out
    cargo test -p indra-node --lib terminate_fatal_subprocess -- --nocapture
    test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 345 filtered out

The lock tests serialize their process-local report counter with TEST_SERIAL because Rust's test harness runs test functions in parallel. The production lock helpers are unchanged in semantics: each poisoned lock reports and returns NodeError::LockPoisoned.

## 4. Production spawn coverage

| File:line | What | Lifetime | Coverage |
|---|---|---|---|
| indra-node/src/bin/node.rs:1333-1910 | P2P runtime thread | process | CriticalTasks::spawn("p2p-runtime") |
| indra-node/src/bin/node.rs:1366,1472,1577,1884 | event forwarder, listener, dialer, shutdown watcher | process | spawn_critical; watcher exits cleanly |
| indra-node/src/bin/node.rs:1539,1818,2039 | inbound, outbound, observer writer connections | per-connection | spawn_connection |
| indra-node/src/bin/node.rs:1936-1987 | observer runtime | process | adopted by CriticalTasks in run |
| indra-node/src/bin/node.rs:4861-4970 | full/public RPC listener and handlers | listener/per-connection | listener adopted; handlers use catch_unwind in run_isolated_handler |
| indra-node/src/bin/observer.rs:226-264 | observer reserve runtime | process | now returned and adopted as observer-reserve-runtime |
| indra-node/src/bin/observer.rs:255-261 | observer reserve connection | per-connection | spawn_connection |
| indra-node/src/metrics.rs:278-331 | metrics listener and handlers | process/per-connection | listener handle adopted by caller; handler has catch_unwind and records telemetry |
| indra-node/src/metrics.rs:344-388 | observer metrics listener and handlers | process/per-connection | listener handle adopted by caller; handler has catch_unwind and records telemetry |
| indra-node/src/hardened_read_rpc.rs:175-246 | hardened observer RPC listener and handlers | process/per-connection | listener handle adopted by observer; handler has catch_unwind |
| indra-node/src/sync.rs:3044-3046 | QC verification stress-test workers | short-lived test | each handle is joined by the test |
| indra-node/src/qc_verification.rs:76 | bounded QC verification worker | process/object | handle is taken and adopted by node supervisor |
| indra-node/src/bin/node.rs:6912-6928 | cooldown stress-test workers | short-lived test | each handle is joined by the test |

The observer reserve runtime was the one production runtime thread without an owner in the previous Bin 4 inventory. It now returns its JoinHandle and is adopted by CriticalTasks; no detached production listener remains in that path.

## 5. Handling inventory

| File:line | Function | Kind | Handling |
|---|---|---|---|
| indra-node/src/bin/node.rs:193-249 | RpcSemaphore acquire_until/drop | production | explicit match; supervisor report; fail closed |
| indra-node/src/bin/node.rs:710-718 | broadcast_locally_accepted_op | production | locks::lock; report; return |
| indra-node/src/bin/node.rs:724-733 | rebroadcast_inbound_accepted_op | production | locks::lock; report; return |
| indra-node/src/bin/node.rs:2958-3143 | authenticated network event loop | production | supervised_lock!; report; task return |
| indra-node/src/bin/node.rs:4208-4209 | main peer-list cache | production | locks::lock(...)?; report; run error |
| indra-node/src/bin/node.rs:4877-4895,4953-4970 | RPC per-IP state | production | report; reject/finish connection |
| indra-node/src/bin/node.rs:5542-5562,5977-5983 | RPC driver | production | lock_driver_for_rpc; report; RPC error |
| indra-node/src/metrics.rs:147-170,229-260,517-519,939-941 | telemetry snapshots/counters | production | typed metrics fallback or telemetry lock path; not consensus state |
| indra-node/src/hardened_read_rpc.rs:114-170,286-289 | observer read/RPC admission state | production | existing explicit fail-closed error/rejection path; poison is not accepted |
| indra-node/src/qc_verification.rs:87 | worker handle | production | ok()?.take() is shutdown ownership state, not consensus data; worker is adopted before normal node operation |
| indra-node/src/bin/node.rs:7260-7465 | GossipState test helpers | test | test-only unwraps |

## 6. Verification status

Verified after the source edits: `cargo check --workspace` completed successfully; its raw log is `/tmp/node_bin4b_workspace_check_final.log`.

The final full workspace runs were green:

* `/tmp/node_bin4b_workspace_debug_final.log`: 1,638 passed; 0 failed; 10 ignored across the workspace. `indra-node` targets: library 341/0/5, binary unit tests 93/0/0, `tests/node.rs` 17/0/0, `tests/node_bin.rs` 7/0/0.
* `/tmp/node_bin4b_workspace_release.log`: 1,638 passed; 0 failed; 10 ignored across the workspace. The same node target counts passed in release.
* `/tmp/node_bin4b_clippy_final.log`: `cargo clippy -p indra-node --bin node --no-deps` passed with zero errors and zero denied findings. It emitted 13 library warnings and 16 node-binary warnings. These are remaining warnings, not ordinary or cleared: library lint groups were `empty_line_after_doc_comments` (1), `print_literal` (1), `io_other_error` (3), `large_enum_variant` (2), `manual_saturating_arithmetic` (3), `manual_is_multiple_of` (1), `too_many_arguments` (2); binary groups were `len_zero` (1), `too_many_arguments` (7), `type_complexity` (1), `collapsible_if` (2), `needless_borrow` (2), and `single_match` (3).

## Appendix A — commands and raw outputs

### Disk space before work

    $ df -h .
    Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
    /dev/disk3s5   228Gi   187Gi    13Gi    94%    2.0M  134M    1%   /System/Volumes/Data

### Focused SIGTERM test

    $ cargo test -p indra-node --test node_bin node_started_from_valid_fixture_stops_cleanly_on_sigterm -- --nocapture
    running 1 test
    test node_started_from_valid_fixture_stops_cleanly_on_sigterm ... ok
    test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out; finished in 3.94s

### Focused lock/supervisor tests

    $ cargo test -p indra-node --lib poisoned -- --nocapture
    test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 342 filtered out
    $ cargo test -p indra-node --lib simultaneous_poisoned -- --nocapture
    test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 345 filtered out
    $ cargo test -p indra-node --lib terminate_fatal_subprocess -- --nocapture
    test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 345 filtered out

### Check

    $ cargo check --workspace
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 3.31s

### Clippy

    $ cargo clippy -p indra-node --bin node --no-deps
    Finished dev profile [unoptimized + debuginfo] target(s) in 5.77s
    warning totals: library 13; binary 16; errors 0

### Final workspace result lines

    $ cargo test --workspace
    indra-node library: test result: ok. 341 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 1119.14s
    node binary unit tests: test result: ok. 93 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.57s
    node integration tests: test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 8.22s
    node_bin integration tests: test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 4.21s
    workspace sum: 1,638 passed; 0 failed; 10 ignored

    $ cargo test --workspace --release
    indra-node library: test result: ok. 341 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 68.17s
    node binary unit tests: test result: ok. 93 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.95s
    node integration tests: test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.39s
    node_bin integration tests: test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.82s
    workspace sum: 1,638 passed; 0 failed; 10 ignored

### Per-crate totals

The following are the exact totals computed from every `test result:` line in each raw log (passed, failed, ignored):

    indra-bench 19 0 0
    indra-cli 85 0 0
    indra-consensus 65 0 0
    indra-core 175 0 0
    indra-crypto 41 0 0
    indra-ffi 26 0 0
    indra-genesis 7 0 0
    indra-governance 9 0 0
    indra-keygen 1 0 0
    indra-keystore 22 0 0
    indra-network 162 0 1
    indra-node 341 0 5
    indra-rpc 103 0 0
    indra-send 1 0 0
    indra-stake 9 0 0
    indra-state 376 0 3
    indra-storage 49 0 1
    indra-sync-recover 118 0 0
    indra-tx 2 0 0
    indra-wallet-scan 27 0 0
    SUM 1638 0 10

The repeated zero-test storage/doc-test harness lines are included in the raw logs but do not change these crate totals.
