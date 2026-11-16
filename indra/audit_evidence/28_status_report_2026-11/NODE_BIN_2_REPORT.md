# Node Bin 2 report

**Status: partially complete / unproven in the remaining slices.** This report records the implemented and tested portion of Node Bin 2. The complete lock-policy conversion requested by the task is not proven: the node binary still has 93 `clippy::unwrap_used` errors outside the functions converted in this pass.

## Scope and commands

All commands were run from `/Users/bonkai/Desktop/indra/project_indra/indra`. No git operation was run. The available disk space before work was 4.7 GiB (`df -h .`); the task's 3 GiB stop threshold was not reached.

## Part A — real-binary refusal tests

Added `/Users/bonkai/Desktop/indra/project_indra/indra/indra-node/tests/node_bin.rs`. Each test launches `env!("CARGO_BIN_EXE_node")`, captures stdout/stderr, polls for at most 30 seconds, kills only a timed-out child, requires a non-zero exit, checks a cause string, and rejects `panicked at` and `RUST_BACKTRACE` in stderr.

The real run was:

```text
cargo test -p indra-node --test node_bin -- --test-threads=1
```

Result:

```text
running 6 tests
test node_refuses_corrupt_vote_safety_record_without_panic ... ok
test node_refuses_invalid_genesis_without_panic ... ok
test node_refuses_missing_config_without_panic ... ok
test node_refuses_missing_keystore_without_panic ... ok
test node_refuses_permissive_password_file_without_panic ... ok
test node_refuses_wrong_keystore_password_without_panic ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.37s
```

The corrupt-vote-safety test creates `vote_safety.dat`, but intentionally supplies invalid genesis too. Startup validates/loads the key and genesis before the driver opens vote-safety, so this test proves the nearest reachable refusal and does not claim end-to-end vote-safety refusal. The in-process property remains covered by `indra-node/src/driver.rs` test `corrupt_vote_safety_record_refuses_startup`.

## Part B — lock conversions

`indra-node/src/bin/node.rs` now uses `indra_node::locks::{lock, read, write}` in these requested helpers: `NetworkBridge::validator_for_addr`, `has_connected_ip`, `reserve_inbound_connection`, `release_inbound_connection`, `record_peer_connected_event`, `refresh_handshake_and_relay_config`, `observer_block_poller`, `current_status_message`, `observer_blocks_for_range`, `process_driver_actions`, `announce_status_and_recovery`, `broadcast_status`, and the discovered-peer read in `handle_rpc`.

The typed error is `NodeError::LockPoisoned` from `indra-node/src/error.rs`; `indra-node/src/locks.rs` reports through `supervisor::report_unexpected` before returning the typed error. The normal reserve/release and peer-event tests were updated for `NodeResult`; their workspace results remained passing. The existing unit test `locks::tests::poisoned_mutex_and_rwlock_report_once_each` covers one supervisor report per poisoned primitive.

The provisional-QC second-take paths in `indra-node/src/bin/node.rs` now log and drop stale responses/carriers when `take_provisional()` returns `None`, rather than reporting a false supervisor fatal. The relevant state mutation paths are `SyncState::take_provisional` and `SyncState::clear_provisional` in `indra-node/src/sync.rs`; `SyncState::provisional_qc_response_requires_selected_peer_and_height` exercises the clear-then-reject behavior.

## Part C — relay and supervision findings

`op_relay_key` in `indra-node/src/bin/node.rs` returns `Some` for `Message::StakingOp` and `Message::GovernanceOp`, hashing their canonical encoded bytes. Every other `Message` variant is intentionally non-operation traffic and returns `None`; those variants are not passed to the operation relay cache. The complete enum is in `indra-network/src/message.rs` (`Block`, `Vote`, `Tx`, `PeerList`, `Ping`, `Pong`, `RequestBlocks`, `BlockResponse`, `Status`, `RequestProposal`, `RequestQC`, `QCResponse`, `StakingOp`, `GovernanceOp`, `TxStem`). `Encode::encode_to_vec` and `sha256` return values for both operation variants, so no accepted staking/governance operation has a `None` relay key.

`supervisor::report_unexpected` sends `CriticalTaskOutcome::TaskExited` through the process-global reporter in `indra-node/src/supervisor.rs`. The main node loop in `indra-node/src/bin/node.rs` receives `TaskExited`, prints the critical message, flushes stderr, and calls `std::process::exit(1)`. The existing supervisor tests cover task exit, task panic, clean shutdown, and decision reporting. A separate end-to-end subprocess test for each possible network/consensus/thread call into the supervisor was not added; this is an evidence limit.

## Part D — remaining lock survey

The read-only survey command was:

```text
rg -n -U "(?:\\.lock\\(\\)|\\.read\\(\\)|\\.write\\(\\))\\.(?:unwrap|map|ok|is_ok)|(?:\\.lock\\(\\)|\\.read\\(\\)|\\.write\\(\\))" indra-node/src --glob '*.rs'
```

The full captured output is `/tmp/node_bin2_lock_survey.log`. Important non-converted slices include:

```text
indra-node/src/qc_verification.rs:87:        self.worker_handle.lock().ok()?.take()
indra-node/src/observer.rs:283:                    let mut engine = engine.lock().map_err(|_| "engine lock poisoned")?;
indra-node/src/observer.rs:415:        .lock()
indra-node/src/observer.rs:437:    let engine = engine.lock().unwrap();
indra-node/src/observer.rs:446:    engine.lock().map(|engine| engine.height()).unwrap_or(0)
indra-node/src/metrics.rs:162:        if let Ok(mut counts) = self.handler_panics_total.lock() {
indra-node/src/metrics.rs:497:    if let Ok(panics) = metrics_state.handler_panics_total.lock() {
indra-node/src/hardened_read_rpc.rs:114:        let mut available = self.available.lock().ok()?;
indra-node/src/hardened_read_rpc.rs:137:        if let Ok(mut available) = self.semaphore.available.lock() {
indra-node/src/hardened_read_rpc.rs:249:                if let Ok(mut counts) = per_ip_connections.lock() {
indra-node/src/bin/node.rs:684:        if let Ok(mut seen) = op_relay_seen.lock() {
indra-node/src/bin/node.rs:698:        if let Ok(mut seen) = op_relay_seen.lock() {
```

The remaining `node.rs` lock errors are predominantly in the discovery/event-loop and consensus-loop code outside the function list in the task. They are not claimed fixed by this report. The requested size guard was not exceeded for the listed helper conversion; no production consensus rule was changed.

## Verification

The pre-change clippy command was run as:

```text
cargo clippy -p indra-node --bin node --no-deps --message-format=short
```

Raw output: `/tmp/node_bin2_clippy_before.log`. It reported 126 `used unwrap()` errors in the node binary.

The post-change command was run as:

```text
cargo clippy -p indra-node --bin node --no-deps --message-format=short
```

Raw output: `/tmp/node_bin2_clippy_after.log`. It reported 93 `used unwrap()` errors, plus 29 warnings total for the node binary/lib output. The remaining errors are not claimed resolved; the exact list is in the log.

Workspace check:

```text
cargo check --workspace 2>&1 | tee /tmp/node_bin2_check.log
```

Result: finished successfully, with 13 `unused std::result::Result` warnings at the current call sites of the newly fallible helpers. The exact warning text is in `/tmp/node_bin2_check.log`.

Workspace debug tests:

```text
cargo test --workspace 2>&1 | tee /tmp/node_bin2_workspace_debug.log
```

Per-target result lines are in the log. The node library target ended `334 passed; 0 failed; 5 ignored` after 1076.03 seconds. The release run completed the same target with `334 passed; 0 failed; 5 ignored` after 59.11 seconds.

The debug workspace aggregate, computed from every `test result:` line in the captured log, was `1630 passed; 0 failed; 10 ignored`. The release workspace aggregate was also `1630 passed; 0 failed; 10 ignored`.

## Raw command-output appendix

```text
startup test: 6 passed; 0 failed; 0 ignored; finished in 9.37s
workspace check: Finished `dev` profile [unoptimized + debuginfo]
clippy before: 126 node-bin `used unwrap()` errors
clippy after: 93 node-bin `used unwrap()` errors; 29 warnings
workspace debug log: /tmp/node_bin2_workspace_debug.log — 1630 passed; 0 failed; 10 ignored
workspace release log: /tmp/node_bin2_workspace_release.log — 1630 passed; 0 failed; 10 ignored
```

The required release workspace testing completed successfully; its exact per-target output is in `/tmp/node_bin2_workspace_release.log`.
