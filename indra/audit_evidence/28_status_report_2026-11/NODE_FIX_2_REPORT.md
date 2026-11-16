# Node Fix 2 report

## Not finished or not proven

The requested block-store writer task does not exist in the current source. `rg -n 'writer_task|BlockStoreWriter|block.*writer' indra-node/src indra-storage/src` found only the observer connection writer at `indra-node/src/bin/node.rs:1966-2040`; canonical block persistence is synchronous in `indra-node/src/sync.rs:745-753` and the engine commit path. Therefore no block-store writer handle or writer-channel send could be registered or tested without inventing a new persistence architecture. The observer connection writer is not the requested block-store writer.

The QC verifier and the listeners that exist were registered below. The requested restore-refusal behavior remains open: current code fails closed at voting time, rather than refusing construction for every corrupt/invalid record.

## Part 1 — critical-task supervision

`CriticalTasks::adopt` in `indra-node/src/supervisor.rs` now watches an already-created `JoinHandle`, converts normal return and panic into `CriticalTaskOutcome::TaskExited`, and sends that outcome to the node’s existing main-loop supervisor. The new regression test is `supervisor::tests::adopted_task_exit_is_reported` in `indra-node/src/supervisor.rs`.

`NetworkQcVerifier::new` now retains its worker handle in `indra-node/src/qc_verification.rs:63-91`; `take_worker_handle` transfers it to the supervisor. The node registers it as `network-qc-verifier` in `indra-node/src/bin/node.rs:2493-2495`. The test `qc_verification::tests::qc_worker_exit_is_reported_as_task_exit` closes the verifier sender and asserts `TaskExited`.

The node now adopts handles for `observer-runtime`, `metrics-listener`, `full-rpc-listener`, and `public-rpc-listener` in `indra-node/src/bin/node.rs:2510-2538` and `3775-3830`. The metrics APIs return their listener handles from `indra-node/src/metrics.rs:247-312` and `315-375`. The observer RPC API returns an optional listener handle from `indra-node/src/hardened_read_rpc.rs:147-268`; the standalone observer adopts it and its metrics listener in `indra-node/src/bin/observer.rs:149-178` and checks for task exit in its main loop at `:184-190`.

Full-RPC connection handlers already use `catch_unwind(AssertUnwindSafe(...))` at `indra-node/src/bin/node.rs:4581-4621`; the handler panic is recorded through `MetricsState::record_handler_panic`. Observer connection handlers now use `FutureExt::catch_unwind` at `indra-node/src/bin/node.rs:1884-1906`; a panic is logged, counted as `observer`, and does not terminate the listener. The per-IP lock is handled with a poison error branch at `indra-node/src/bin/node.rs:4560-4570`; there is no `lock().unwrap()` at the referenced full-RPC admission site in this tree.

The failed-send portion of the requested block-store test is not applicable to the current synchronous persistence path. The observer writer’s `write_tx.send` results remain intentionally connection-local at `indra-node/src/bin/node.rs:1966-2040`; they are not block persistence sends.

## Part 2 — proof inventory

### `target_round`

The only function parameter and assignment use is `ConsensusDriver::maybe_advance_to_certified_round(height, target_round)` at `indra-node/src/driver.rs:1677-1679` and its definition at `:1715-1768`. The caller passes `vote.round`, after `validate_consensus_round(vote.round)` has already been enforced by vote admission in the surrounding `record_vote_and_actions` path. The function itself repeats the check at `:1721-1728` before reading evidence or starting the round. There is no other assignment to `target_round` in the workspace. The final `start_round(target_round)` call is therefore reached only after the explicit round-domain check and bounded-jump check.

### Vote-safety restart

The write path records the `(height, round, step)` before signing at `indra-node/src/driver.rs:1327-1343`. Restore is entered by `ConsensusDriver::try_new` at `:274-318`, which calls `apply_vote_safety` at `:317`; the restore logic loads the durable record at `:908-969`, advances to `record.round + 1` when safe, and `sign_and_record_local_vote` refuses the recorded slot through the persisted guard at `:1309-1318` and the durable record write at `:1327-1343`. Existing test `driver::tests::audit_restart_conflicting_vote_reproducer_ordinary_height` in `indra-node/src/driver_tests.rs:705-720` records a vote, drops the driver, reconstructs through `ConsensusDriver::new` (the test-only wrapper over `try_new`), and asserts that signing again at the same slot emits no broadcast. `driver::tests::crash_restart_restores_lock_and_rejects_conflicting_no_polc_prevote` in `indra-node/src/driver_tests.rs:1339-1370` covers the persisted lock variant.

### Restore failure behavior

The current `apply_vote_safety` behavior is fail-closed for voting but does not refuse construction for every corrupt/invalid record: it records `vote_safety_unavailable` and returns `Ok(())` at `indra-node/src/driver.rs:920-963`; later signing returns no vote at `:1309-1318`. Thus the report cannot claim that every restore error now prevents `try_new` from returning. The existing tests `restart_after_vote_in_final_round_fails_closed`, `corrupt_vote_safety_record_prevents_voting`, and `restart_rejects_persisted_lock_with_invalid_proposer_authorization` document this current fail-closed behavior at `indra-node/src/driver_tests.rs:5921-5967` and `:6091-6139`.

### `DriverAction::Fatal`

The current production producer is `indra-node/src/driver.rs:2065`, where a missing governing snapshot returns `DriverAction::Fatal`. `process_driver_actions` matches it at `indra-node/src/bin/node.rs:3966-3971`, reports `consensus-driver` through `supervisor::report_unexpected`, and returns; the main loop checks the critical-task channel at `:3839-3844` and exits with status 1 for `TaskExited`. The pure supervisor decision tests are `supervisor::tests::decision_reports_task_panic`, `decision_reports_task_error`, and `clean_shutdown_is_not_fatal` at `indra-node/src/supervisor.rs:154-180`.

## Verification logs

These commands were run from `/Users/bonkai/Desktop/indra/project_indra/indra`.

- `cargo check --workspace --all-targets 2>&1 | tee /tmp/node_fix2_workspace_check_final.log`: PASS; final line is `Finished \`dev\` profile [unoptimized + debuginfo] target(s) in 1.09s`.
- `cargo test -p indra-node --lib supervisor:: -- --test-threads=1`: PASS, `test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 332 filtered out; finished in 0.00s`.
- `cargo test -p indra-node --lib qc_verification:: -- --test-threads=1`: PASS, `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 335 filtered out; finished in 0.00s`.
- `cargo test --workspace 2>&1 | tee /tmp/node_fix2_workspace_debug_final.log`: PASS. Aggregate of the verbatim `test result:` lines: 1,621 passed / 0 failed / 10 ignored. The node library line is `test result: ok. 331 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 1419.11s`. The node binary now reports 93/0/0 because of the full-RPC isolation regression test. Other per-target counts are unchanged from the target-by-target summary in the preceding run: indra-bench 19/0/0; indra-cli lib 85/0/0, genesis bin 7/0/0, governance bin 9/0/0, keygen bin 1/0/0, send bin 1/0/0, stake bin 9/0/0, tx bin 2/0/0, wallet-scan bin 3/0/0, CLI integration 24/0/0; indra-consensus lib 60/0/0 and integration 5/0/0; indra-core lib 154/0/0 and serialization 21/0/0; indra-crypto lib 38/0/0, phase1 2/0/0, benchmark 1/0/0; indra-ffi 26/0/0; indra-keystore 22/0/0; indra-network lib 158/0/1 and integration 4/0/0; indra-node integration 17/0/0; indra-rpc lib 68/0/0 and integration 35/0/0; indra-state lib 337/0/3, audit phase2 4/0/0, monetary 10/0/0, state machine 25/0/0; indra-storage lib 48/0/1. The remaining zero-test binary/doc targets are present verbatim in the log.
- `cargo test --workspace --release 2>&1 | tee /tmp/node_fix2_workspace_release_final.log`: PASS. Aggregate: 1,621 passed / 0 failed / 10 ignored. Node library: `test result: ok. 331 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 67.40s`; node binary 93/0/0. The same per-target counts as debug passed; release timing is recorded verbatim in the log.
- `cargo clippy -p indra-node --lib --no-deps 2>&1 | tee /tmp/node_fix2_clippy_final.log`: PASS with exit code 0 and zero denied diagnostics. It emitted 13 warning diagnostics, including `driver.rs:64`, `discovery.rs:741`, `795`, `925`, `979`, large enum warnings at `driver.rs:79` and `:127`, saturating-arithmetic warnings at `driver.rs:986`, `:1567`, `:1725`, `genesis.rs:285`, and the signature warning `metrics.rs:248` for too many arguments. No `#[allow]` was added.

## Files changed for Node Fix 2

- `indra-node/Cargo.toml`: direct `futures-util` dependency for async `catch_unwind`.
- `indra-node/src/supervisor.rs`: adopted task watcher and test.
- `indra-node/src/qc_verification.rs`: retained worker handle and test.
- `indra-node/src/bin/node.rs`: listener adoption and observer connection panic isolation.
- `indra-node/src/bin/observer.rs`: adopted observer listener handles and exit detection.
- `indra-node/src/hardened_read_rpc.rs`: return listener handle.
- `indra-node/src/metrics.rs`: return listener handles.

