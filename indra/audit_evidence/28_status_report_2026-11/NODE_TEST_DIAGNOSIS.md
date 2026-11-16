# INDRA node test diagnosis — 2026-11-05

Scope: read-only diagnosis. No repository source, manifest, or Cargo.lock file was changed. Historical worktrees were created under /tmp with separate target directories and removed after use.

## Executive diagnosis

- [verified just now] The audit failures are primarily a temporary-directory race, not the advisory lock update. indra-node/src/driver_tests.rs:20-26 names every helper directory as indra_driver_test_<suffix>_<process id>. Multiple audit tests call shared_four_validator_fixture(), which reuses shared_four_template and shared_four_0 through shared_four_3 and removes those directories while other tests can still use them.
- [verified just now] Parallel failures referenced the same process-ID-derived indra_driver_test_shared_four_template_<pid>/genesis.toml, followed by No such file or directory, Directory not empty, Storage(Io(...NotFound)), and fixture assertions.
- [verified just now] Every completed test run alone passed 3/3. audit_harness_four_validator_multiseed_chaos_converges did not complete within the unbounded several-minute attempt; bounded current and old-lock runs hit a 90-second alarm while still inside the test. It was not counted as a pass.
- [verified just now] The full single-threaded node command was not green as a completed command: all audit tests reached in the log passed, including multiseed, but the run then stopped at engine::tests::startup_fails_on_snapshot_replay_gap and was interrupted with exit 130. That engine test constructs and processes 1,300 blocks at indra-node/src/engine.rs:4240-4252, so this is a separate non-completion observation.

## Part 1 — classification

### Feature wiring

- [verified just now] indra-node/src/driver.rs:2401-2402 includes driver_tests.rs under cfg(test). indra-node/src/lib.rs:49-50 feature-gates only the separate audit_harness module.
- [verified just now] cargo test -p indra-node --lib therefore runs audit_* functions without enabling audit-harness. cargo tree -e features -i indra-node showed only default paths through indra-bench and indra-cli; no workspace crate enabled indra-node/audit-harness.
- [verified just now] The explicit audit-harness feature adds the adapter module, but the failing functions are ordinary tests in driver_tests.rs and already run without that feature.

### Outcomes

[verified just now] The parallel baseline used the current main tree and advisory-updated lock. The alone column is three separate invocations with --exact --test-threads=1. Old lock is the same isolated invocation in the 45ea17ec worktree with cargo +1.93.1 and a separate CARGO_TARGET_DIR.

| Test | Parallel current tree | Alone current, 3 runs | Alone old lock |
|---|---|---|---|
| audit_collection_bounds_valid_traffic_pressure_production_admission | failed at driver_tests.rs:362:47: called Result::unwrap() on an Err value: Os { code: 66, kind: DirectoryNotEmpty, message: "Directory not empty" } | pass 3/3 | pass |
| audit_fixture_shared_genesis_four_distinct_validators | failed at driver_tests.rs:365:55: ValidatorConfigIncomplete, cannot read genesis.toml: No such file or directory | pass 3/3 | pass |
| audit_fixture_shared_genesis_two_distinct_validators | failed at driver_tests.rs:834:9: assertion left == right failed | pass 3/3 | pass |
| audit_harness_four_validator_byzantine_equivocation_preserves_safety | failed at driver_tests.rs:846:75: Result unwrap, Os code 2 NotFound | pass 3/3 | pass |
| audit_harness_four_validator_gst_delayed_delivery_recovers | failed at driver_tests.rs:846:75: No such file or directory | pass 3/3 | pass |
| audit_harness_four_validator_multiseed_chaos_converges | failed at driver_tests.rs:3574:26: Option unwrap on None in one run; another run had shared-genesis NotFound | timed out at 90s; unbounded attempt did not complete | timed out at 90s |
| audit_harness_four_validator_partition_heal_converges | failed at driver_tests.rs:846:75: No such file or directory | pass 3/3 | pass |
| audit_harness_four_validator_restart_storm_recovers_safely | failed at driver_tests.rs:362:47: No such file or directory | pass 3/3 | pass |
| audit_harness_four_validator_strict_precommit_quorum_finalizes | failed at driver_tests.rs:362:47: No such file or directory | pass 3/3 | pass |
| audit_harness_four_validator_strict_prevote_quorum_boundary | failed at driver_tests.rs:917:236: assertion left == right failed; observed round 4 versus round 0 | pass 3/3 | pass |
| audit_harness_four_validator_topology_churn_recovers | failed at driver_tests.rs:314:55: Storage(Io(Os code 2 NotFound)) | pass 3/3 | pass |
| audit_harness_four_validator_valid_traffic_pressure_recovers | failed at driver_tests.rs:314:55: Storage(Io(Os code 2 NotFound)) | pass 3/3 | pass |
| audit_harness_four_validators_accept_one_production_proposal | failed at driver_tests.rs:314:55: Storage(Io(Os code 2 NotFound)) | pass 3/3 | pass |
| audit_harness_four_validators_converge_across_two_heights | failed at driver_tests.rs:314:55: Storage(Io(Os code 2 NotFound)) | pass 3/3 | pass |
| audit_harness_post_finalization_stale_and_conflicting_traffic_is_safe | failed at driver_tests.rs:314:55: Storage(Io(Os code 2 NotFound)) | pass 3/3 | pass |

- [verified just now] The parallel current result was FAILED. 287 passed; 15 failed; 5 ignored when all 21 names matching audit_ were selected. The earlier full workspace result had 13 node failures because two of the 15 were run-dependent.
- [verified just now] The completed isolated outcomes are deterministic passes for 14 tests. Multiseed is non-classifiable as pass/fail under the bounded isolated run because it timed out; its parallel failure is run-dependent. The full serial command is not green as a completed command because it did not reach a result summary.

## Part 2 — temporary-directory race

- [verified just now] driver_tests.rs:20-26 defines temp_dir as temp_dir().join(format!("indra_driver_test_{}_{}", suffix, process::id())). The process ID is constant for all Rust test threads in one test process.
- [verified just now] driver_tests.rs:841-861 defines shared_four_validator_fixture(). It creates a template using local_driver(..., "shared_four_template"), removes dir0 at line 847, then creates shared_four_0 through shared_four_3 at line 853.
- [verified just now] Independent tests call that helper, including driver_tests.rs:865, 877, 904, 967, 1059, 1094, 1183, 1240, 1285, 1823, 2265, 2691, 4276, and 4291. Each caller receives the same names within one process because the suffixes and process ID are the same.
- [verified just now] Callers remove those directories, for example at lines 873, 900, 963, 1055, 1090, 1178, 1235, 1281, and 1818. One test can therefore delete a directory another test is reading or initializing. This is direct code evidence for the observed failures at lines 846, 314, 362, 365, and 834.
- [verified just now] audit_harness.rs is only a production adapter and has no temporary-directory helper. engine.rs:1899-1905 and genesis.rs/discovery.rs also use process-ID-based names, but the observed audit failures specifically share driver_tests.rs paths.
- [verified just now] Proposed fix, not applied: allocate a unique directory per fixture invocation using a collision-resistant temporary-directory API or atomic unique suffix, retain ownership until all engines/stores are dropped, and remove only that owned directory.

## Part 3 — lock-file neutrality

- [verified just now] A detached worktree at /tmp/indra-45ea17ec was created at 45ea17ec81aa3dd288569ceaf15874a7b8b5a100 with CARGO_TARGET_DIR=/tmp/indra-target-45ea17ec and explicit cargo +1.93.1.
- [verified just now] The main tree used the advisory-updated lock; the old worktree used the old lock. All completed isolated tests had the same result in both trees: pass when run alone. Multiseed hit the same 90-second bound in both.
- [verified just now] The lock update did not change the observed audit-test outcome. The failure requires concurrent tests sharing process-ID-derived paths.

## Part 4 — historical candidates

- [taken from an earlier report] c2babf46 was the last known good point: its driver_tests module passed 113 of 113 tests. This is the module count, not the node library total.
- [verified just now] At 7885415a, cargo +1.93.1 test -p indra-node --lib --no-run does not compile. First errors include cannot find value NO_POLC_ROUND, missing snapshot_root in VoteV1, wrong argument counts, missing genesis_precommit_hash, and access to .election on a Result. It ended with could not compile indra-node (lib test) due to 62 previous errors.
- [verified just now] At 14ae0569 the same no-run target also does not compile with the stale-test/API mismatch errors.
- [verified just now] At 20448f3d the target compiles. Running the 21 audit_ tests with eight test threads failed 14 and passed 7 in 5.56 seconds; errors included shared-genesis missing-file, DirectoryNotEmpty, storage NotFound, and strict-prevote assertion failures.
- [verified just now] At c197f441 the target compiles and the same 21-test parallel selection failed 13 and passed 8 in 4.44 seconds. Dandelion++ changed network files, but the shared fixture race remained in driver_tests.rs.
- [verified just now] The first candidate at which the updated target compiles and the audit failure is observable is 20448f3d. 7885415a changed production consensus/genesis/vote-safety APIs; 20448f3d supplied the large updated driver_tests module, including the reusable process-ID-only shared fixture.
- [verified just now] Plausible responsible hunks are driver_tests.rs:20-26, :841-861, and cleanup at :847 and :873 onward. A separate production hardening hunk from 7885415a in indra-storage/src/vote_safety.rs rejects a requested slot that is not strictly later than persisted state; this explains the refusal message, while shared paths let unrelated tests encounter another instance’s persisted state.

## Part 5 — unwrap invariant and time

- [verified just now] driver_tests.rs:1141 is in audit_harness_four_validators_converge_across_two_heights. It calls on_propose_timeout() for each of four drivers and unwraps the first BroadcastVote; the next assertion requires height, round, step, and block hash to match the expected proposal. The invariant is that every validator emits a prevote at that scheduled proposal step.
- [verified just now] The same pattern occurs at lines 2781 and 3574. The observed refusal, vote safety slot is not strictly later than persisted slot, comes from the hardened VoteSafetyStore::record path introduced in 7885415a (current indra-storage/src/vote_safety.rs:89-105). Shared persisted state can suppress a vote and make find_map(...).unwrap() fail.
- [verified just now] Fixture-byte and genesis.toml failures occur before consensus logic in shared_four_validator_fixture(), at driver_tests.rs:846 and :853-859. They indicate fixture lifetime/path ownership, not Dandelion or a date change.
- [verified just now] The strict-prevote failure observed left round 4 versus right round 0 with the same block hash. That is consistent with shared persisted state or concurrent fixture interference.
- [verified just now] Failing audit tests use fixed timestamps such as 1_700_000_000, 1_700_000_050, and 1_700_000_100 at driver_tests.rs:1128, :1248, and :1271. git grep found no sleep, std::thread::sleep, tokio::time::sleep, or current_timestamp_secs() in the failing audit tests.
- [verified just now] engine.rs:1589 calls current_timestamp_secs(), implemented at :1682-1686, for commit_proposal. The failing audit traces do not pass through it. Instant::now() is used for timing/metrics at driver.rs:2227 and driver_tests.rs:8099 and :8132, not for campaign timestamps.
- [verified just now] Proposed fix, not applied: after making fixture paths unique, rerun; if any standalone failure remains, instrument and assert uniqueness of each driver vote_safety_path before signing.

## Appendix — raw command records

[verified just now] Full serial command: cargo test -p indra-node --lib -- --test-threads=1. Captured in /tmp/indra-node-serial-2.log. It reached test engine::tests::startup_fails_on_snapshot_replay_gap ... and was interrupted with exit 130 after no further output.

[verified just now] Current isolated logs are in /tmp/indra-node-individual-20261105/. Each completed test emitted test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 306 filtered out. Multiseed ended after test ... multiseed_chaos_converges ...; the bounded rerun exited 142.

[verified just now] Old-lock isolated logs are in /tmp/indra-node-old-individual-20261105/. Every completed test passed; multiseed exited 142 under the 90-second bound.

[verified just now] Historical logs: /tmp/indra-788-compile.log (exit 101, 62 errors), /tmp/indra-14ae-compile.log (exit 101), /tmp/indra-204-compile.log (successful), /tmp/indra-204-audit.log (FAILED. 7 passed; 14 failed; 0 ignored), /tmp/indra-c197-compile.log (successful), and /tmp/indra-c197-audit.log (FAILED. 8 passed; 13 failed; 0 ignored).

[verified just now] Representative raw parallel errors:
called Result::unwrap() on an Err value: Os { code: 2, kind: NotFound, message: "No such file or directory" }
called Result::unwrap() on an Err value: Storage(Io(Os { code: 2, kind: NotFound, message: "No such file or directory" }))
called Result::unwrap() on an Err value: Os { code: 66, kind: DirectoryNotEmpty, message: "Directory not empty" }
called Option::unwrap() on a None value
assertion left == right failed

[verified just now] Historical worktrees /tmp/indra-45ea17ec, /tmp/indra-788, /tmp/indra-204, /tmp/indra-14ae, and /tmp/indra-c197 were removed. No historical worktree remains.

