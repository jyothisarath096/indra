# Node binary, Bin 4

## Unfinished or unproven at report creation

This report was created before the Node Bin 4 source changes. The pre-change state is recorded below; the final results are appended after implementation. The remaining limitation is explicit: the SIGTERM command below exercised an early configuration failure, not a fully started node, so it does not prove the supervised shutdown watcher’s runtime exit path.

## Part 0 — pre-change evidence

All commands in this section were run from `/Users/bonkai/Desktop/indra/project_indra/indra` before Node Bin 4 edits.

### 0.1 Disk space

Command: `df -h .`

```text
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   192Gi   9.7Gi    96%    2.0M  102M    2%   /System/Volumes/Data
```

The required 3 GiB free-space threshold was met before changes.

### 0.2 Existing lock wrappers and process termination

Before the change, `indra-node/src/bin/node.rs` defined `fatal_lock!` and `fatal_read!` inside `start_network_runtime` (current lines 1227–1248). On wrapper error they printed `[p2p] lock failure (...)`, called `supervisor::report_unexpected`, and then called `std::process::exit(1)`. Thus the wrappers terminated the process directly; they did not return to the supervisor main loop. The stderr flush was not explicit in those wrappers.

Before the change, `indra-node/src/locks.rs` provided `lock`, `read`, and `write`. Each mapped poisoning to `NodeError::LockPoisoned` and called `supervisor::report_unexpected("poisoned-lock", ...)`. Its test `poisoned_mutex_and_rwlock_report_once_each` checked two reports sequentially, but did not exercise simultaneous poisoning from two threads.

### 0.3 Spawn inventory before the change

The pre-change search command was:

```text
rg -n 'tokio::spawn|std::thread::spawn|thread::spawn|Builder::new\("' indra-node/src -g '*.rs'
```

The hits were:

```text
indra-node/src/locks.rs:44:        thread::spawn(move || {
indra-node/src/locks.rs:57:        thread::spawn(move || {
indra-node/src/qc_verification.rs:76:        let worker_handle = std::thread::spawn(move || worker(receiver, &worker_count));
indra-node/src/metrics.rs:278:    std::thread::spawn(move || {
indra-node/src/metrics.rs:297:                    std::thread::spawn(move || {
indra-node/src/metrics.rs:344:    std::thread::spawn(move || {
indra-node/src/metrics.rs:362:                    std::thread::spawn(move || {
indra-node/src/metrics.rs:1197:            workers.push(std::thread::spawn(move || {
indra-node/src/sync.rs:3044:            threads.push(std::thread::spawn(move || {
indra-node/src/supervisor.rs:153:    tokio::spawn(async move {
indra-node/src/supervisor.rs:154:        let joined = tokio::spawn(task).await;
indra-node/src/supervisor.rs:180:    tokio::spawn(async move {
indra-node/src/supervisor.rs:181:        let joined = tokio::spawn(task).await;
indra-node/src/supervisor.rs:197:    tokio::spawn(async move {
indra-node/src/supervisor.rs:246:        let handle = thread::spawn(|| {});
indra-node/src/hardened_read_rpc.rs:175:    Some(std::thread::spawn(move || {
indra-node/src/hardened_read_rpc.rs:228:            std::thread::spawn(move || {
indra-node/src/hardened_read_rpc.rs:642:        let _ = std::thread::spawn(move || {
indra-node/src/bin/node.rs:1913:    Ok(std::thread::spawn(move || {
indra-node/src/bin/node.rs:1926:            tokio::spawn(observer_block_poller(Arc::clone(&driver), block_tx.clone()));
indra-node/src/bin/node.rs:1940:                tokio::spawn(async move {
indra-node/src/bin/node.rs:2021:    let writer_task = tokio::spawn(async move {
indra-node/src/bin/node.rs:4802:    std::thread::spawn(move || {
indra-node/src/bin/node.rs:4864:                    std::thread::spawn(move || {
indra-node/src/bin/node.rs:6849:                workers.push(std::thread::spawn(move || {
indra-node/src/bin/node.rs:8613:        let sender = std::thread::spawn(move || {
indra-node/src/bin/observer.rs:220:    std::thread::spawn(move || {
indra-node/src/bin/observer.rs:249:                tokio::spawn(async move {
```

The `locks.rs`, `supervisor.rs`, and test-only spawn sites are test/support code. The pre-change production sites requiring Bin 4 review were the observer poller and observer connection tasks in `node.rs`, plus the RPC listener and per-connection threads, metrics listeners, hardened read RPC, QC verifier, and sync verification workers. The prior Node Bin 3 report had already wrapped the network runtime's long-lived and per-connection Tokio tasks; this task must verify the remaining sites rather than assume that report is sufficient.

### 0.4 Extraction status

Before the change, no separate named functions had been extracted for the lock-touching portions of `main`. The existing lock wrappers were extracted in the network-runtime helper, but the 46 `main` lock sites remained inline. No poison tests existed for functions extracted from those `main` sites because no such functions existed.

## Implementation and verification

To be completed after the source changes. Raw command output and final lock inventory will be appended here; no final pass/fail claim is made in this pre-change section.

## Final implementation

### Lock handling

The 46 direct lock unwrap sites in the node `main` body were removed. The body now runs in `run() -> indra_node::NodeResult<()>`, and `main()` prints `ERROR: {error}`, flushes stderr, and exits 1 when `run()` returns an error. Main-thread lock sites use `locks::lock`/`locks::read` with `?`. Lock sites inside the authenticated network and consensus task closures use the supervised lock macros; a poison error reports through the supervisor and returns from that task, allowing the supervisor’s main loop to terminate the process. The network-runtime wrappers use `supervisor::terminate_fatal`, which reports, flushes stderr, and exits 1 for a failure that occurs before a task can return a `NodeResult`.

No additional lock-touching business-logic functions were extracted from `run()`: the large closure captures runtime state and was left inline to preserve behavior. The only structural extraction in this pass is `run()` plus `wait_for_shutdown_signal`; neither contains a new independently testable consensus algorithm. The existing typed poison test remains `locks::tests::poisoned_mutex_and_rwlock_report_once_each`.

### Spawn and shutdown coverage

The observer block poller is now `supervisor::spawn_critical` (`indra-node/src/bin/node.rs`), observer connections and observer writers use `supervisor::spawn_connection`, and the standalone observer reserve connections use the same connection wrapper (`indra-node/src/bin/observer.rs`). The existing long-lived network, RPC, metrics, and observer runtime threads are adopted by `CriticalTasks`; RPC/metrics per-connection handlers already use panic isolation; the QC verifier handle is adopted; and sync verification threads are joined by their caller. The complete lock inventory is in `NODE_BIN_4_LOCK_INVENTORY.md`.

The shutdown watcher now waits for both Tokio Ctrl-C/SIGINT and Unix SIGTERM in `wait_for_shutdown_signal`. A normal signal saves peers and intentionally calls `std::process::exit(0)` in the watcher. A manual real-SIGTERM command was run against a node that failed before startup:

```text
pid=67202 exit=1 dir=/tmp/node_bin4_sigterm.IseXhU
ERROR: cannot read config file /tmp/node_bin4_sigterm.IseXhU/missing.toml: No such file or directory (os error 2)
```

That is a real binary SIGTERM invocation, but the process had already returned its configuration error before the signal; a fully started-node SIGTERM proof was not run.

## Verification

All commands below were run from `/Users/bonkai/Desktop/indra/project_indra/indra`.

### Workspace check

Command: `cargo check --workspace`

Log: `/tmp/node_bin4_workspace_check_final.log`

Result: PASS; the log ended with `Finished 'dev' profile [unoptimized + debuginfo] target(s) in 4.34s` and contained no warnings.

### Focused node tests

Command: `cargo test -p indra-node --lib --bin node --tests`

Log: `/tmp/node_bin4_node_tests.log`

Result: PASS. The log reports 338 passed / 0 failed / 5 ignored for the node library, 93 / 0 / 0 for the node binary unit target, 17 / 0 / 0 for `tests/node.rs`, and 6 / 0 / 0 for `tests/node_bin.rs`. The node library finished in 1076.11 seconds.

### Full workspace debug

Command: `cargo test --workspace`

Log: `/tmp/node_bin4_workspace_debug.log`

Result: PASS. Per-target result lines are in the raw log. The principal targets were: `indra-bench` 19/0/0; `indra-cli` library 85/0/0, genesis binary 7/0/0, keygen 1/0/0, send 1/0/0, stake 9/0/0, tx 2/0/0, wallet-scan 3/0/0, CLI integration 24/0/0; `indra-consensus` library 60/0/0 and integration 5/0/0; `indra-core` library 154/0/0 and serialization 21/0/0; `indra-crypto` library 38/0/0, audit phase 1 2/0/0, benchmark 1/0/0; `indra-ffi` 26/0/0; `indra-keystore` 22/0/0; `indra-network` library 158/0/1 and integration 4/0/0; `indra-node` library 338/0/5, binary unit 93/0/0, node integration 17/0/0, startup binary integration 6/0/0; `indra-rpc` library 68/0/0 and integration 35/0/0; `indra-state` library 337/0/3, audit phase 2 4/0/0, monetary invariants 10/0/0, state machine 25/0/0; `indra-storage` library 48/0/1. Doc tests were all green, with `indra-rpc` 1/0/0 and the other doc-test targets 0/0/0.

### Full workspace release

Command: `cargo test --workspace --release`

Log: `/tmp/node_bin4_workspace_release.log`

Result: PASS. The same per-target counts were preserved in release: node library 338/0/5, node binary unit 93/0/0, node integration 17/0/0, node startup binary integration 6/0/0, network library 158/0/1, state library 337/0/3, and storage library 48/0/1. All other target result lines are green in the raw log.

The two full workspace runs above completed before a final two-branch fail-closed return tightening in `run()` (the branches are only reached when the local gossip address query errors). After that final source edit, `cargo check --workspace` and the node-binary clippy command were rerun successfully; the full test suites were not rerun after those two error-path-only changes.

### Node binary clippy

Command: `cargo clippy -p indra-node --bin node --no-deps`

Log: `/tmp/node_bin4_clippy_final.log`

The command completed successfully and emitted no denied `unwrap_used`, `expect_used`, or `panic` findings from the node binary. It emitted 13 ordinary warnings from the existing `indra-node` library and 16 ordinary warnings from the node binary, covering `len_zero`, `too_many_arguments`, `type_complexity`, `collapsible_if`, `needless_borrow`, and `single_match`. These were not changed in this task because they are not lock-poison handling and the requested no-`#[allow]` rule does not authorize unrelated refactors.

## Files changed in this pass

Production/runtime changes: `indra-node/src/bin/node.rs` (run wrapper, lock handling, signal handling, observer task supervision); `indra-node/src/bin/observer.rs` (reserve connection supervision); `indra-node/src/supervisor.rs` (fatal error termination helper). The report files are `NODE_BIN_4_REPORT.md` and `NODE_BIN_4_LOCK_INVENTORY.md`. No target directory or git worktree was created by this task.

Final disk check command: `df -h .`.

```text
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   193Gi   9.4Gi    96%    2.0M   99M    2%   /System/Volumes/Data
```
