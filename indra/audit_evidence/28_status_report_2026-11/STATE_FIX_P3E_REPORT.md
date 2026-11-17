# State-fix P3E report

Scope: P3E changes and verification in the existing working tree. Commands were run from `/Users/bonkai/Desktop/indra/project_indra/indra` unless stated otherwise. This report does not claim a fresh debug workspace run: the requested full debug run was explicitly left to the owner.

## Unfinished or unproven items

**Verified just now — `indra/indra-storage/src/segmented_block_store.rs:280-303`:** no direct overflow test was added for the second `checked_add`. The loop first executes `start.checked_add(BLOCKS_PER_SEGMENT)` at lines 282-287 and pushes `start` only after that addition succeeds. The later check at lines 297-302 therefore cannot see an overflowing `start + BLOCKS_PER_SEGMENT` under the current construction. A test would require an impossible `starts` entry or a production-logic change, so no test was invented.

**Verified just now from the benchmark helper and its output:** the proof comparison uses SHA-256 of Rust `Debug` formatting for the first 1,000 proofs, not a canonical proof serialization. The equal digests are evidence of equal sampled debug output, not a proof that every field of every proof has canonical byte equality.

**Verified just now from the requested run list:** the complete debug workspace suite was not rerun in P3E. The release workspace suite was run after the P3E edits and passed.

## 1. Vote membership and snapshot consistency

**Verified just now — `indra/indra-consensus/src/vote.rs:108-112`, `VoteCollector::add_vote`:** `add_vote` validates round dimensions, membership and duplicate status, calls `verify_vote_authority` with `&self.voters`, then calls `self.add_verified_vote(vote)`.

**Verified just now — `indra/indra-consensus/src/vote.rs:122-135`, `VoteCollector::add_verified_vote`:** the method repeats structural membership/duplicate checks against the collector’s `self.voters`; a missing voter returns the typed `ConsensusError::InternalInvariant { detail: "verified vote missing from collector membership" }`.

**Verified just now — `indra/indra-consensus/src/vote.rs:220-255`, `verify_vote_authority`:** authority lookup and signature verification use the `voters: &[RegisteredVoter]` slice passed by the caller.

**Verified just now — `indra/indra-node/src/driver.rs:1632-1645`, `Driver::handle_vote`:** inbound authority verification uses `&self.registered_voters`; failure produces `DisconnectInvalidConsensusPeer` and returns before admission.

**Verified just now — `indra/indra-node/src/driver.rs:1807-1818` and `1864-1875`:** both collector-creation paths pass `self.registered_voters.clone()` into `VoteCollector::new`; the corresponding `authority_verified` value is produced from the same driver voter snapshot before `add_verified_vote` is called. The collector owns its cloned membership vector, so the verification/admission pair does not read a mutable live vector that can change between those operations.

**Verified just now — focused test:** `vote::tests::verified_unknown_voter_rejected_by_same_snapshot_membership` constructs a collector with one registered voter, submits a signed vote from another voter, and asserts the exact typed `ConsensusError::UnknownVoter` from the public `add_vote` path. The test was run with `cargo test -p indra-consensus --lib unknown_voter` and passed 2/2; raw output is in `/tmp/state_fix_p3e_vote_tests.log`.

## 2. Rollback equivalence

**Verified just now — existing reference helpers:** `indra/indra-state/src/apply.rs:1887-1897`, `assert_same_consensus_state`, compares encoded `ChainState`, state root, and validator-set root. Lines 1904-1912, `clone_atomic_reference_apply_block`, applies the same block to a cloned state.

**Verified just now — existing tests:** `project_block_for_roots_restores_state_on_apply_failure` at `indra/indra-state/src/apply.rs:2044`, `project_block_for_roots_preserves_active_state_commitment_v2_cache` at `:2061`, `project_block_for_roots_failpoint_rollback_covers_each_mutation` at `:2124`, `state_txn_rolls_back_after_each_transaction_mutation_failpoint` at `:2249`, and governance failpoint tests beginning at `:2352` and `:2388` exercise narrower failure/rollback cases.

**Verified just now — new test:** `indra/indra-state/src/apply.rs:2154`, `rollback_matches_clone_reference_across_deterministic_mixed_sequence`, runs 200 deterministic steps. Steps divisible by 10 submit two identical transactions in one block, causing a mid-block duplicate-spend failure; steps congruent to 5 submit a wrong-parent block; all other steps submit valid empty blocks. Thus 20 of 200 steps are deliberate mid-block failures, i.e. 10%.

**Verified just now — new test assertions at `indra/indra-state/src/apply.rs:2188-2236`:** after every step it compares success/error parity, encoded state and both roots, 20 sampled UTXO proofs, `total_supply`, `base_fee`, and the validator set. The encoded-state comparison covers fields serialized by `ChainState`, including the fee-pool state if present in that encoding. The focused test passed 1/1 in `/tmp/state_fix_p3e_rollback_test.log` in 39.85 seconds.

## 3. Storage overflow branch

**Verified just now — `indra/indra-storage/src/segmented_block_store.rs:263-312`, `SegmentedBlockStore::prune_complete_segments`:** `start` is initialized at line 281. The loop at lines 282-288 exits when `checked_add` returns `None`, and only pushes `start` after a successful addition. The second check at lines 297-302 is consequently defensive but unreachable for a value obtained from `starts`. No storage source change was made for P3E, and no false reachability test was added.

## 4. Corrected rollback benchmark

**Verified just now from `/tmp/state_fix_p3e_bench_old_final.log` and `/tmp/state_fix_p3e_bench_new_final.log`:** both helpers were built in release mode and each benchmark was run 20 times. The UTXO proxy uses 10,000 and 500,000 entries, 32 mutating operations, distinct present keys, and `black_box` on query inputs and outputs. The tree cases use 100,000 initial leaves, 10,000 inserts/deletes, and 100,000 proofs; proof outputs are black-boxed.

| Case | Earlier implementation: min / median / max µs | Current implementation: min / median / max µs |
|---|---:|---:|
| UTXO 10,000 clone + 32 mutations | 932 / 948 / 1,092 | 894 / 908 / 1,010 |
| UTXO 500,000 clone + 32 mutations | 1,621 / 1,687 / 2,168 | 1,535 / 1,597 / 2,122 |
| Compressed tree insert 10,000 | 59,250 / 96,846 / 123,112 | 56,003 / 93,421 / 118,427 |
| Compressed tree delete 10,000 | 51,096 / 56,739 / 83,500 | 48,868 / 55,305 / 78,046 |
| Compressed tree prove 100,000 | 8,811 / 9,870 / 275,868 | 2,444 / 2,618 / 220,390 |
| Persistent tree insert 10,000 | 72,472 / 110,237 / 140,318 | 67,934 / 108,130 / 135,066 |
| Persistent tree delete 10,000 | 61,784 / 65,381 / 96,681 | 57,560 / 60,229 / 90,855 |
| Persistent tree prove 100,000 | 8,650 / 9,362 / 287,646 | 2,371 / 2,492 / 219,778 |

**Verified just now:** the earlier and current proof digests were both `4a032109284cf2e5fb2d67510d9dd3d0c9437fc234a79ce7c36a174e565d33b3`. This is the sampled Debug-string digest described above. The large proof-median difference is measured by the helper, but the cause beyond the observed implementation/output equality is not established. The max/min spread shows local timing noise; no other cargo/rustc/benchmark process was running for the standalone final runs.

**Verified just now:** a 1,000,000-entry live UTXO case could not be run because the repository limit rejected it with `LiveStateCapacityExceeded { collection: "UTXO set", current: 500000, max: 500000 }`. The 500,000-entry case is therefore the tested worst case, not a 1,000,000-entry result.

## 5. Attribution audit for the earlier P3D report

**Verified just now with `git diff --numstat` and `git diff`:** the 14 files that the earlier report had incorrectly characterized as owner work contain only crate-root lint-attribute changes from the P3B/P3D work:

| File | Diff | Classification |
|---|---:|---|
| `indra/indra-bench/src/lib.rs` | `1 0` | added `#![deny(unused_must_use)]` |
| `indra/indra-cli/src/bin/genesis.rs`, `governance.rs`, `keygen.rs`, `send.rs`, `stake.rs`, `tx.rs`, `wallet_scan.rs` | `1 1` each | extended crate-root denial list with `clippy::unreachable`, `clippy::todo`, `clippy::unimplemented` |
| `indra/indra-cli/src/lib.rs` | `13 1` | root denial additions and test-only lint-attribute update |
| `indra/indra-node/src/bin/audit_block_log.rs`, `dns_seed_sign.rs`, `indra-sync-recover.rs`, `node.rs`, `observer.rs` | `1 1` each | extended crate-root denial list with the same three Clippy lints |

**Verified just now:** the current `git diff --numstat` also contains broader pre-existing P3B/P3D source edits in consensus, node, RPC, state and storage. Those are not attributed to P3E. The P3E source additions are the vote test and state rollback test described above; the storage implementation was not altered for the unreachable branch.

## 6. Verification results

### P3E commands run by Codex

`cargo check --workspace` — **PASS**, exact final line: `Finished \`dev\` profile [unoptimized + debuginfo] target(s) in 10.89s`. Log: `/tmp/state_fix_p3e_check.log`. No warning lines appeared in that log.

`cargo test -p indra-consensus --lib unknown_voter` — **PASS**, `2 passed; 0 failed; 0 ignored; 0 measured; 61 filtered out`. Log: `/tmp/state_fix_p3e_vote_tests.log`.

`cargo test -p indra-state --lib apply::tests::rollback_matches_clone_reference_across_deterministic_mixed_sequence -- --exact` — **PASS**, `1 passed; 0 failed; 0 ignored; 0 measured; 344 filtered out; finished in 39.85s`. Log: `/tmp/state_fix_p3e_rollback_test.log`.

`cargo test -p indra-state --lib smt::tests::p3_golden_roots_and_proof_bytes_are_stable -- --exact` — **PASS**, `1 passed; 0 failed; 0 ignored; 0 measured; 344 filtered out; finished in 9.00s`. Log: `/tmp/state_fix_p3e_golden.log`.

`cargo test --workspace --release` — **PASS**, all result lines in `/tmp/state_fix_p3e_workspace_release.log` reported zero failures. The aggregate from those lines is `1,650 passed; 0 failed; 10 ignored`. Important per-target lines include:

```text
test result: ok. 63 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
test result: ok. 158 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 5.01s
test result: ok. 344 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 73.71s
test result: ok. 93 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.11s
test result: ok. 48 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 2.25s
```

`cargo audit` — **PASS**, log `/tmp/state_fix_p3e_cargo_audit.log`; the exact terminal status was `audit_exit=0`.

`cargo deny check` — **PASS**, log `/tmp/state_fix_p3e_cargo_deny.log`; exact final status was `advisories ok, bans ok, licenses ok, sources ok`, with `deny_exit=0` in the combined command output.

### Raw output appendix

The raw release result lines are exactly the output of:

```sh
grep -E '^test result:' /tmp/state_fix_p3e_workspace_release.log
```

The aggregate was computed exactly with:

```text
passed=1650 failed=0 ignored=10
```

The raw focused outputs are preserved at `/tmp/state_fix_p3e_vote_tests.log`, `/tmp/state_fix_p3e_rollback_test.log`, and `/tmp/state_fix_p3e_golden.log`; the raw benchmark outputs are preserved at `/tmp/state_fix_p3e_bench_old_final.log` and `/tmp/state_fix_p3e_bench_new_final.log`.

## Final workspace facts

**Verified just now:** the temporary P3E old worktree `/tmp/indra-state-p3e-old` and benchmark target directories created for the standalone comparison were removed. The repository remains uncommitted; the pre-existing source edits and untracked audit evidence remain visible in `git status --short`. The final filesystem check was:

```text
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   193Gi   8.3Gi    96%    2.0M   87M    2%
```

