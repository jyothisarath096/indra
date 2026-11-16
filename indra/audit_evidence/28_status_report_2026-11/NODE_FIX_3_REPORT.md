# Node Fix 3 report

## Unfinished or unproven

The poisoned-lock conversion is intentionally incomplete. The requested eight helpers have 38 matches in node.rs and 30 outside-function call sites. Per the task's size guard, this report stops after the shared helper and the first two helpers. The remaining helpers were not changed: validator_for_addr, has_connected_ip, reserve_inbound_connection, release_inbound_connection, record_peer_connected_event, and refresh_handshake_and_relay_config.

The full debug workspace run was compiled before the final ahead-of-chain test was added. That test was run separately and passed; the release workspace run includes it. No separate block-store writer task exists in this repository; persistence is synchronous in the engine/sync paths.

## Vote-safety startup refusal

NodeError::VoteSafetyUnavailable is defined at indra-node/src/error.rs:147-152. ConsensusDriver::apply_vote_safety now returns that typed error for invalid current-height locks at indra-node/src/driver.rs:915-921, locks ahead of the next chain height at :922-929, and corrupt or unreadable records at :956-962. A missing record is a fresh start at :910-913. A readable older-height record is ignored; apply_vote_safety_ignores_old_height is at indra-node/src/driver_tests.rs:5939-5951.

ConsensusDriver::try_new propagates this error at indra-node/src/driver.rs:317. The node startup path prints the error and exits nonzero at indra-node/src/bin/node.rs:2484-2488.

The final-legal-round case remains fail-closed for voting only: it sets the unavailable flag and returns Ok at indra-node/src/driver.rs:932-947. The public accessor is at :967-971. The Prometheus gauge indra_vote_safety_unavailable is rendered at indra-node/src/metrics.rs:556-564 and populated from the driver at :407-422. Its test is metrics::tests::vote_safety_unavailable_gauge_is_exported at indra-node/src/metrics.rs:904-923.

The old corrupt-record test was replaced by corrupt_vote_safety_record_refuses_startup at indra-node/src/driver_tests.rs:5954-5971. The invalid proposer-authorization test remains named restart_rejects_persisted_lock_with_invalid_proposer_authorization and now asserts typed startup refusal at indra-node/src/driver_tests.rs:6143-6191. The explicit ahead-of-chain test is persisted_vote_safety_lock_ahead_of_chain_refuses_startup at indra-node/src/driver_tests.rs:5974-6014. The final-round test remains restart_after_vote_in_final_round_fails_closed at indra-node/src/driver_tests.rs:5925-5937.

Before signing, sign_and_record_local_vote persists the safety record and returns no broadcast action if persistence fails at indra-node/src/driver.rs:1320-1336. After commit, vote_safety.clear failure is warning-only at :2159-2165. A stale record for the committed height is older than the next height and does not match either the ahead-lock branch or current-height round-skip branch at :909 and :922-932.

## Poisoned locks

NodeError::LockPoisoned is at indra-node/src/error.rs:154-159. The lock, read, and write wrappers are at indra-node/src/locks.rs:10-29. Poison is reported through supervisor::report_unexpected before returning the typed error at :10-15. The test poisoned_mutex_and_rwlock_report_once_each at indra-node/src/locks.rs:39-67 checks one report per operation and both typed errors.

The converted first two helpers are NetworkBridge::connected_addrs and NetworkBridge::peer_topology at indra-node/src/bin/node.rs:583-609. Their boundary handling is at node.rs:2604-2617, :2939-2958, :3910-3927, :3949-3962, :3991-4002, and :5361-5380.

The call-site inventory used a loop running rg -n for each of these eight function names over indra-node/src/bin/node.rs. Detailed outside-call counts were 6, 1, 7, 2, 5, 4, 4, and 1 respectively, totaling 30; this exceeds the 25-call-site guard.

## Parity test list

The baseline parity worktree was outside the repository at /private/tmp/indra-node-fix3-parity.Ojz8Ow, used a separate target directory, and was removed after comparison. The only list changes were:

-driver::tests::corrupt_vote_safety_record_prevents_voting: test
+driver::tests::corrupt_vote_safety_record_refuses_startup: test
+driver::tests::persisted_vote_safety_lock_ahead_of_chain_refuses_startup: test
+locks::tests::poisoned_mutex_and_rwlock_report_once_each: test
+metrics::tests::vote_safety_unavailable_gauge_is_exported: test

restart_rejects_persisted_lock_with_invalid_proposer_authorization was retained with a changed assertion.

## Verification

Debug command: cargo test --workspace 2>&1 | tee /tmp/node_fix3_workspace_debug.log

Main debug result lines:
indra-node library: test result: ok. 333 passed; 0 failed; 5 ignored; finished in 1107.78s
indra-node node binary: test result: ok. 93 passed; 0 failed; 0 ignored; finished in 5.26s
indra-network library: test result: ok. 158 passed; 0 failed; 1 ignored; finished in 7.27s
indra-state library: test result: ok. 337 passed; 0 failed; 3 ignored; finished in 20.83s
indra-storage library: test result: ok. 48 passed; 0 failed; 1 ignored; finished in 2.24s
Debug aggregate: 1623 passed; 0 failed; 10 ignored.
This log predates the final ahead-of-chain test; that test passed separately in /tmp/node_fix3_vote_safety_ahead.log.

Release command: cargo test --workspace --release 2>&1 | tee /tmp/node_fix3_workspace_release.log

Main release result lines:
indra-node library: test result: ok. 334 passed; 0 failed; 5 ignored; finished in 58.62s
indra-node node binary: test result: ok. 93 passed; 0 failed; 0 ignored; finished in 5.13s
indra-network library: test result: ok. 158 passed; 0 failed; 1 ignored; finished in 5.01s
indra-state library: test result: ok. 337 passed; 0 failed; 3 ignored; finished in 0.85s
indra-storage library: test result: ok. 48 passed; 0 failed; 1 ignored; finished in 2.37s
Release aggregate: 1624 passed; 0 failed; 10 ignored.

Final targeted log: /tmp/node_fix3_targeted_final.log. It contains passing runs of persisted_vote_safety_lock_ahead_of_chain_refuses_startup, corrupt_vote_safety_record_refuses_startup, vote_safety_unavailable_gauge_is_exported, and poisoned_mutex_and_rwlock_report_once_each.

Workspace check command: cargo check --workspace --all-targets 2>&1 | tee /tmp/node_fix3_workspace_check.log
Final output: Finished dev profile [unoptimized + debuginfo] target(s) in 6.58s

Clippy library before and after both returned success with 13 warning diagnostics. Logs: /tmp/node_fix3_clippy_before_lib.log and /tmp/node_fix3_clippy_lib.log. The unchanged warning classes are driver doc/enum/arithmetic warnings, discovery formatting/io suggestions, genesis is_multiple_of, metrics argument count, and sync argument count.

Clippy node binary before and after both returned success with 29 warning lines, or 13 unique diagnostic locations after dependency-emitted duplicates. Logs: /tmp/node_fix3_clippy_before_bin.log and /tmp/node_fix3_clippy_bin.log. No denied diagnostics were emitted.

## Changed files

indra-node/src/error.rs
indra-node/src/locks.rs
indra-node/src/lib.rs
indra-node/src/driver.rs
indra-node/src/driver_tests.rs
indra-node/src/metrics.rs
indra-node/src/bin/node.rs

No manifest, lockfile, consensus-rule, or persistence-writer file was changed by this fix.
