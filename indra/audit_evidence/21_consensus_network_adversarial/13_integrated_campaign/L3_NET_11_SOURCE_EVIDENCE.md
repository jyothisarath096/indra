# L3-NET-11 source provenance

Current source hashes (recomputed 2026-08-29):

- `indra-storage/src/vote_safety.rs` SHA-256 `2d46a862db865f595b66629e09f6447144713ea60d4e2ca3c97db82e8d819f85`
- `indra-node/src/driver.rs` SHA-256 `bbb6f84d14327314f3253a5444bc45555a1105521011d3bea99c00b0dea498ab`

`VoteSafetyStore::record` is at `indra-storage/src/vote_safety.rs:84-137`.
It calls `self.load()`, compares `(height, round, step)` with the persisted
tuple, and returns `ErrorKind::InvalidInput` with
`vote safety slot is not strictly later than persisted slot` before encoding
or `write_atomic_synced`.

`ConsensusDriver::sign_and_record_local_vote` is at
`indra-node/src/driver.rs:1256-1348`. Its canonical `next_height()` and
`current_round` checks precede authority lookup, `VoteSafetyStore::record`,
`engine.sign_vote`, and `BroadcastVote` construction.

Regression tests are at `driver.rs:3069` (fixture persistence), `3092`
(ordinary-height restart conflict), and `3110` (future-round signer boundary);
the direct store test is at `vote_safety.rs:309`.

`ConsensusDriver::next_height` is at `indra-node/src/driver.rs:959-961`:
`self.engine.state.height + 1`. It reads the current durable engine height and
returns the legal next local signing height (genesis 0 -> 1; ordinary height 1
-> 2). This is ordinary `u64` addition, neither checked nor saturating; at
`u64::MAX` it overflows in checked/debug builds and wraps in unchecked release
builds. That maximum is not reachable through normal consensus progression.

The direct `signing_slot_ordering_matrix` at `vote_safety.rs:319` proves first
prevote acceptance, same-slot/lower-step/lower-round/lower-height rejection,
same H/R precommit acceptance, and later-round/later-height acceptance.

Legitimate progression coverage already present includes
`precommit_timeout_advances_round` (`driver.rs:3934`),
`valid_vote_safety_record_constrains_future_rounds` (`driver.rs:4535`),
`vote_before_block_requests_proposal_then_commits` (`driver.rs:3495`), and
`reproposal_converges_after_disruption` (`driver.rs:6484`). These cover
same-H/R vote progression, later-round progression, and commit/next-height
progression; no additional production behavior was added.

Validation results are recorded below after execution.

Validation run on 2026-08-29:

- `cargo test -p indra-storage`: PASS (47 passed, 1 ignored).
- `cargo test -p indra-consensus`: PASS (59 unit + 5 integration passed).
- `cargo test -p indra-state`: PASS (318 tests; no failures observed).
- `cargo test -p indra-network --lib`: PASS (149 tests; no failures observed).
- `cargo test -p indra-node --lib`: the suite reached the remediation tests but
  did not complete within the execution window; an unrelated existing test
  initially used `u64::MAX` signing height and failed the newly enforced
  canonical-height guard. Its test input was corrected to legal height 1; no
  production behavior was changed. A complete pass remains to be rerun by
  independent review.
- Node-suite diagnosis is documented in `NODE_SUITE_INCOMPLETE.md`: the
  restart/snapshot tests `restart_from_snapshot_produces_same_state_as_continuous`,
  `startup_fails_on_snapshot_replay_gap`, and `startup_from_snapshot_with_pruned_log`
  each exceed the execution window individually without failure output.
- `cargo fmt --all -- --check`: FAIL due pre-existing formatting differences in
  `indra-node/src/audit_harness.rs`, `indra-node/src/driver.rs`, and module
  ordering in `indra-node/src/lib.rs`; no formatter changes were applied.
- `git diff --check`: PASS.

- `cargo test --workspace --no-run --quiet`: PASS (exit 0).

The bundle is a current-source evidence export and is not dependent on a clean
historical baseline.
