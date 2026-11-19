NET_6 root cause was a split round admission rule: the driver and relay discarded valid same-height votes more than eight rounds from local state, while existing certified-round advancement required evidence that could never be admitted. The fix records one highest verified round per active validator, relays each validator's newly observed distant round once, and jumps only when strict integer arithmetic shows more than one third of active stake supports that round.

Nothing remains unfinished for NET_6.

## Root cause facts

- Consensus phase timeouts are fixed at 8 seconds propose + 3 seconds prevote + 3 seconds precommit, approximately 14 seconds per round; they do not grow. A 360-second pause can therefore leave the active validators roughly 25 rounds ahead.
- Before NET_6, `process_vote` rejected votes above `current_round + MAX_ACCEPTED_ROUND_JUMP` before authoritative verification. `prune_round_advance_evidence` also retained only that same window, and relay admission dropped the same-height distant rounds.
- The existing certified-round path required strict >2/3 stake, but distant evidence could not reach it because of the +8 admission/pruning gate. QC recovery handles the last committed height/current tip and did not provide a round synchronisation mechanism for the still-uncommitted height.

## Fix

- `ConsensusDriver::highest_verified_round_by_validator` stores at most one record per active validator at the next height, updated only after `verify_vote_authority` succeeds.
- The largest candidate round whose recorded validators hold strictly more than one third of total stake is selected using `u128` arithmetic (`supported * 3 > total`). One of four equal validators cannot jump; two can; a single 40% validator can.
- Distant votes remain out of the bounded vote/proposal collections unless the node has advanced to their round. Existing >2/3 certified-round evidence, locking, and persisted vote-safety checks remain in place.
- Relay keeps a bounded `(height, validator)` high-round record. A valid same-height message above the local +8 window is relayed only when it is a new highest round for that validator; repeats and same-round alternate-step messages are dropped. Normal adjacent-height relay rules remain unchanged.

## Safety and boundedness

- Round jumps call `start_round` and `apply_vote_safety`; they do not clear `locked_round`, `locked_value`, `locked_value_hash`, or `locked_polc_votes`.
- Invalid signatures and non-validator signers still fail authoritative verification before evidence is recorded or a jump occurs.
- The per-validator evidence table is bounded by the active validator set; relay high-round state is bounded by current-height validator identities. Vote collections remain independently capped.

## Tests and mutation proof

- `cargo test --workspace --release --no-fail-fast`: passed. The release run included 169 network-library tests (168 passed, 1 ignored), 364 node-library tests (359 passed, 5 ignored), and all integration, benchmark, replay, golden-vector, and doc-test targets passed.
- NET_6 focused coverage passed: 3-validator round-20/round-0 recovery, one-validator 1,000,000-round replay repeated 10,000 times, exact 2/4 and unequal 40% stake thresholds, lock/restart preservation, partition/recovery, distant relay verification/deduplication, and production-admission collection bounds.
- Mutation proof: restoring the former `current_round + MAX_ACCEPTED_ROUND_JUMP` rejection caused `distant_verified_rounds_jump_on_more_than_one_third_stake` to fail because no high-round evidence was retained; removing that mutation made the test pass.

## Live proof

- Fixed `LAG_SECONDS=300 CAP_SECONDS=900` line smoke passed against release binaries: all four nodes reached height 10 with identical tip `61d79...c1c4`, peer counts 1/2/2/1, zero panics, zero stale nodes, and zero nonzero exits.
- Plain line smoke passed at target height 5 with identical tip `33b3...a809`; skew smoke passed at target height 5 with identical tip `ab139...fbef`. Both retained peer counts 1/2/2/1 and clean exits.
- Owner full command: `NODE_BIN=$PWD/target/release/node GENESIS_BIN=$PWD/target/release/indra-genesis KEYGEN_BIN=$PWD/target/release/indra-keygen LAG_SECONDS=900 CAP_SECONDS=2400 scripts/line_lag_live.sh`

## Required checks

- Debug and release `cargo clippy --workspace --all-targets --no-deps -- -D warnings`: passed.
- `scripts/check_no_lint_allows.sh` and `cargo test -p indra-core --test lint_guard`: passed; no new lint suppression was added.
- `cargo audit`: passed with advisories clear; duplicate dependency warnings are pre-existing lockfile diagnostics. `cargo deny check`: passed for advisories, bans, licenses, and sources.
- Golden/replay/vector coverage passed in the release workspace run; no consensus vector or replay fixture changed.

## Changed files

- `indra-core/src/types/primitives.rs`: documented the ordinary +8 admission bound versus distant verified evidence.
- `indra-network/src/peer_manager.rs`: added verified per-validator distant-round relay high-water tracking and deduplication; updated the superseded NET_5 lag expectation; added relay coverage.
- `indra-node/src/driver.rs`: added bounded per-validator verified-round evidence, strict >1/3 `u128` stake jump selection, lifecycle pruning, and preservation of the existing strict >2/3/QC/locking path.
- `indra-node/src/driver_tests.rs`: added threshold, bounded-replay, lock, partition, and admission-pressure tests; updated the 2/4 threshold expectation.
- Diff stat: core 3 lines, network 86 lines, node driver 133 lines, node tests 200 lines, plus this report.

## Temporary directories

Created under `/tmp` for NET_6 and deleted after verification: `/tmp/indra-net6-release-20261119`, `/tmp/indra-net6-lag300-20261119`, `/tmp/indra-net6-line-20261119`, and `/tmp/indra-net6-skew-20261119`. The final filesystem check retained more than the required 3 GiB free space.
