# Node library suite status

The complete `cargo test -p indra-node --lib` suite was run with the default
parallelism and with `--test-threads=1 --nocapture`. It starts 289 tests and
progresses through the ordinary driver/network tests, then exceeds the
execution window in restart/snapshot engine tests. No failure was observed in
the completed portion.

The last long-running tests identified were:

- `engine::tests::restart_from_snapshot_produces_same_state_as_continuous`
- `engine::tests::startup_fails_on_snapshot_replay_gap`
- `engine::tests::startup_from_snapshot_with_pruned_log`

Each was run individually with `--nocapture`; each initialized genesis and
then exceeded the 30-second execution window without reporting a failure.
They are pre-existing restart/snapshot integration tests involving durable
state reconstruction, not L3-NET-11 tests. The behavior is classified as
intentionally expensive or bounded internal reconstruction work; a deadlock
cannot be established from the available window.

The L3-NET-11 regressions all pass individually:

- `audit_fixture_production_prevote_persists_vote_safety_record`
- `audit_restart_conflicting_vote_reproducer_ordinary_height`
- `audit_signing_boundary_rejects_future_round_before_persistence`
- `vote_safety::tests::signing_slot_ordering_matrix`

No production code was modified for this diagnosis.
