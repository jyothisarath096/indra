NET_5 is implemented: slot-distance-only relay drops no longer change the authenticated validator's score, while authoritative invalid-consensus scoring remains unchanged. The relay slot gate remains before signature verification, and focused tests prove honest lag is dropped without disconnection while 10,000 distinct out-of-window payloads incur zero verification work.

Nothing remains unfinished for NET_5.

## Findings and code facts

- The relay method receives the authenticated peer identity as `sender` from `handle_control`; the slot check extracts the message's height/round, but does not score the message origin separately.
- Before this fix, the out-of-window branch incremented the relay class's `dropped` counter and called `score_validator(sender, ScoreEvent::InvalidMessage, BAN_DURATION)`. `InvalidMessage` is −10, peers start at 100, the ban floor is 0, and the identity ban is persisted for one hour. Thus 10 out-of-window messages from one honest validator were enough to reach 0 and disconnect/ban it.
- The existing metric is the per-message-class `RelayMetrics::dropped` counter (the focused tests identify the vote-class counter). No signature verification is attempted for a slot-distance drop; `verification_failed` remains zero.
- Authoritative invalid-consensus outcomes still call `score_validator(..., InvalidMessage, BAN_DURATION)`, including `DisconnectInvalidConsensusPeer`. Pre-relay signature and validator-key failures remain rejected and counted as `verification_failed`; authoritative validation retains responsibility for penalties.
- A banned identity is stored in `BanStore` until its one-hour expiry. Reconnect is rejected while the persisted ban is active; expiry cleanup removes the active ban without operator action.

## Honest scenarios

- Restart/syncing validator: the node consensus loop skips participation while `sync_caught_up` is false, and the driver also requires the vote height to equal `next_height`. Old in-flight messages can nevertheless arrive at a neighbour; they are dropped by relay slot admission, counted, and no longer penalize the sender.
- Partition healing: a vote more than eight rounds from the receiver's relay context is dropped and counted, but the sender score is unchanged. The validator can deliver current-slot traffic after its context catches up.
- SIGSTOP/stall: resumed traffic may carry an old height or round and follows the same drop-only path; catch-up is not blocked by a score ban.
- Clock skew: consensus slot validation is height/round based; clock-induced slot distance is treated as relay ineligibility, not proof of invalidity.
- Late joiner/restart far behind: old-height traffic is dropped before cryptographic verification and before scoring; normal synchronization and current-slot relay remain available.

## Tests and mutation proof

- `out_of_window_honest_lag_is_dropped_without_scoring_or_blocking_catchup`: covers 3-heights-behind, 20-heights-behind, and 9-rounds-ahead traffic; asserts 3 drops, zero verification failures, score 100, connected status, and successful current-slot relay.
- `ten_thousand_out_of_window_votes_are_rejected_before_verification`: asserts 10,000 drops, zero verification failures, score 100, and connected status.
- Existing tests continue to cover invalid signatures, unregistered validators, conflicting blocks, and authoritative invalid-message scoring.
- Mutation proof: temporarily reinstating the NET_4 score call made the honest-lag test fail with score 70 instead of 100 after three dropped messages; the mutation was removed.

## Live lag smoke run

Command used:

```text
NODE_BIN=/tmp/indra-net5-smoke-target-20261119/release/node GENESIS_BIN=/tmp/indra-net5-smoke-target-20261119/release/indra-genesis KEYGEN_BIN=/tmp/indra-net5-smoke-target-20261119/release/indra-keygen LAG_SECONDS=90 CAP_SECONDS=360 TARGET_HEIGHT=10 scripts/line_lag_live.sh /tmp/indra-net5-lag-run-20261119
```

Result: PASS in 255 seconds; all nodes reached height 10, all four tips were identical, peer counts were 1/2/2/1, panics were 0, stale-sync responses were 0, and all exits were zero.

Owner full-version command:

```text
NODE_BIN=$PWD/target/release/node GENESIS_BIN=$PWD/target/release/indra-genesis KEYGEN_BIN=$PWD/target/release/indra-keygen LAG_SECONDS=360 scripts/line_lag_live.sh
```

## Required checks

Passed:

- `cargo clippy --workspace --all-targets --no-deps -- -D warnings`
- `cargo clippy --workspace --all-targets --no-deps --release -- -D warnings`
- `scripts/check_no_lint_allows.sh`
- `cargo test -p indra-core --test lint_guard`: 2 passed, 0 failed.
- `cargo test --workspace --release --no-fail-fast`: 1,687 passed, 0 failed, 10 ignored; baseline 1,685, so NET_5 adds 2 passing tests.
- `cargo audit`: passed with no advisories reported.
- `cargo deny check`: passed; existing duplicate-crate warnings were non-fatal.
- Focused debug NET_5 run: 2 passed, 0 failed.

The release workspace network suite reports 168 tests, 167 passed and 1 ignored; the two new NET_5 tests are included in that total.

## Changed files

Changed implementation files by crate:

- `indra-network`: `src/peer_manager.rs` — drop-only slot-distance admission and two regression tests.
- `scripts`: `line_topology_live.sh` — optional peer-count assertion; `line_lag_live.sh` — four-node SIGSTOP/SIGCONT lag harness.
- `audit_evidence`: this report.

No consensus constants, vote validation rules, or authoritative invalid-message scoring paths were changed.

## Temporary directories

Directories created in `/tmp` for this turn and deleted by exact path:

- `/tmp/indra-net5-debug-20261119`
- `/tmp/indra-net5-smoke-target-20261119`
- `/tmp/indra-net5-lag-run-20261119`

Final `df -h .` after deletion: 12 GiB available, 94% capacity used.
