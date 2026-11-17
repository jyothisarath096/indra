UNFINISHED / UNPROVEN: the requested full old-inverse/new-transaction differential run was not completed, and a 1,000,000-entry UTXO benchmark could not run because the repository's hard in-memory UTXO cap is 500,000. The release workspace run passed; the final debug workspace run was terminated after 19:56 with three long node tests still active.
UNFINISHED / UNPROVEN: the requested `cargo clippy --workspace --all-targets --no-deps -- -D warnings` gate is not passable in the current tree because existing test and production warnings remain; no blanket warning suppression was added.

# STATE_FIX_P3D report

All repository commands below were run from `/Users/bonkai/Desktop/indra/project_indra` or its `indra/` workspace. This report is the P3D work on top of the existing uncommitted P3/P3B/P3C tree. No commit, stage, restore, checkout, or stash was used.

## 1. Capacity and rollback representation

**Verified just now — `df -h .`:**

```text
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   192Gi   8.5Gi    96%    2.0M   89M    2%   /System/Volumes/Data
```

The free space was 8.5 GiB, above the 3 GiB stop threshold.

**Verified just now — `indra/indra-state/src/utxo.rs:46-61,122-131`:**

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoEntry {
    pub utxo_id: Bytes32,
    pub output: OutputV1,
    pub created_height: u64,
    pub tx_index: u32,
    pub output_index: u32,
    pub tranche_refund: Option<TrancheRefundEventV1>,
}

#[derive(Debug, Clone)]
pub struct UtxoSet {
    entries: PersistentOrdMap<Bytes32, UtxoEntry>,
    compressed: PersistentAuthTree,
}
```

`UtxoSet` has no created-at index, spent-at index, output sidecar, counter, or pruning index. `created_height`, transaction/output indexes, and tranche provenance are fields inside each `UtxoEntry`; restoring the whole `UtxoSet` restores them together. The old height-taking methods remain only as API shape: `spend_at_height` and the test-only `restore_for_rollback_at_height` are at `indra/indra-state/src/utxo.rs:323-341`, and `root_at_height`/`prove_at_height` at `:354-365` ignore the height because the current compressed root is not height-indexed. `PersistentOrdMap` stores its root in `Option<Arc<MapNode<...>>>` at `indra/indra-state/src/persistent.rs:20-33`; `PersistentAuthTree` stores `Arc<PersistentAuthNode>` at `:850-865`. Therefore `Clone` is structural sharing of the persistent roots, not a deep clone of every entry, while mutations path-copy touched nodes. This establishes the representation and its fields, not constant-time end-to-end rollback.

**Verified just now — release benchmark commands and logs:** the helper in `/tmp/state_fix_p3d_bench` was built with `cargo run --release`; it used `Instant::now().as_micros()`, 20 samples, a 100,000-leaf tree baseline, 10,000 inserts, 10,000 deletes, and 100,000 proofs per tree. The old helper used the same source and flags against a detached worktree at `65833603`.

Exact measured output from `/tmp/state_fix_p3d_bench_new_corrected.log`:

```text
UtxoSet clone+32-mutating-rollback_proxy entries=10000 min_us=900 median_us=909 max_us=994
UtxoSet clone+32-mutating-rollback_proxy entries=500000 min_us=1557 median_us=1590 max_us=2076
CompressedAuthTree insert_10000 min_us=56924 median_us=92864 max_us=116706
CompressedAuthTree delete_10000 min_us=47707 median_us=50677 max_us=76351
CompressedAuthTree prove_100000 min_us=2077 median_us=2172 max_us=221177
PersistentAuthTree insert_10000 min_us=68620 median_us=104594 max_us=138090
PersistentAuthTree delete_10000 min_us=58226 median_us=62483 max_us=94055
PersistentAuthTree prove_100000 min_us=2172 median_us=2248 max_us=228127
```

Exact old output from `/tmp/state_fix_p3d_bench_old_corrected.log`:

```text
UtxoSet clone+32-mutating-rollback_proxy entries=10000 min_us=912 median_us=924 max_us=996
UtxoSet clone+32-mutating-rollback_proxy entries=500000 min_us=1725 median_us=2153 max_us=2511
CompressedAuthTree insert_10000 min_us=56603 median_us=96125 max_us=165751
CompressedAuthTree delete_10000 min_us=50023 median_us=55205 max_us=84797
CompressedAuthTree prove_100000 min_us=7411 median_us=8431 max_us=260836
PersistentAuthTree insert_10000 min_us=70463 median_us=107461 max_us=155051
PersistentAuthTree delete_10000 min_us=60262 median_us=63329 max_us=94812
PersistentAuthTree prove_100000 min_us=7601 median_us=7700 max_us=270813
```

The requested 1,000,000-entry run was not possible: the helper's exact failure was `LiveStateCapacityExceeded { collection: "UTXO set", current: 500000, max: 500000 }`. The UTXO measurement is a clone plus 32 valid spend/insert mutations, not a direct timed `StateTxn::begin` plus rollback; the required exact apply/rollback 20-run benchmark is therefore **NOT RUN**. The measured 10,000-to-500,000 median grows from 909 µs to 1,590 µs in the new tree and from 924 µs to 2,153 µs in the old tree. Because the 1,000,000 case and direct rollback measurement were not established, no claim of denial-of-service-safe rollback cost is made.

**Differential equivalence:** **NOT RUN / UNPROVEN.** `apply_block_for_test` is exported at `indra/indra-state/src/apply.rs:4416-4424`; the in-tree test reference `clone_atomic_reference_apply_block` at `indra/indra-state/src/apply.rs:1904-1912` is clone-based, not the requested old inverse-operation implementation. No long old/new sequence comparing serialized state, roots, proofs, supply, fees, indexes, and validators was completed. The requested redesign trigger therefore remains open if direct rollback cost proves size-dependent.

## 2. Tree timing and bit-index conversions

**Verified just now — tree timing:** both old and new helpers used the same release profile, microsecond clock, 20 samples, 10,000 inserts, 10,000 deletes, and 100,000 proofs. The exact outputs are above. Comparing medians, the new tree is faster for compressed insert/delete/prove (92,864/50,677/2,172 µs versus 96,125/55,205/8,431 µs) and persistent insert/delete/prove (104,594/62,483/2,248 µs versus 107,461/63,329/7,700 µs). This is not a proof of all production workloads; the proof maxima are outliers and the helper is external.

**Verified just now — conversion changes:** `NodeLoc.depth` and `PersistentSparseNodeLoc.depth` are `usize`; `depth_from_bit` and `sparse_depth_from_bit` return the already-typed `usize` at `indra/indra-state/src/smt.rs:1086-1088` and `persistent.rs:563-565`. Bit offsets use `7usize - (bit_index % 8)` at `smt.rs:1106-1112,1132-1139` and `persistent.rs:583-589,609-618`; the modulo result is in 0..=7, so the subtraction is infallible. No integer conversion default remains at these six sites.

The proof paths now call `child_bitmap_from_map` at `smt.rs:873-877` and `persistent.rs:1304-1308`. The helper folds the validated map-derived children at `smt.rs:1014-1018` and `persistent.rs:1432-1435`; it has no zero-on-error fallback. The old `child_bitmap` validators remain for their direct validation role at `smt.rs:1001-1012` and `persistent.rs:1419-1430`. The empty-hash fallback in `smt.rs:407-412` is a lookup of the precomputed empty-hash vector for the empty proof value, not a child-bitmap conversion.

## 3. Fail-closed handlers and invariant sites

**Verified just now — RPC:** `indra-rpc/src/handlers.rs:1680-1702` filters only the validator and principal IDs, then converts a missing active state into `RpcError::Internal("validator self-stake position is missing active state")` at `:1690-1692` and collects a `RpcResult`. The focused test at `indra-rpc/src/handlers.rs:2907-2924` constructs the missing-active-state position and asserts that exact variant and text. The old silent omission is removed.

| Site | Producer/invariant | Reachability | Test status |
|---|---|---|---|
| `indra/indra-consensus/src/mempool.rs:294-327` | checked sum of evicted bytes, prior accounting, and new encoded size; failure is `InternalInvariant` | test-only manipulated byte counter can reach it | **Tested** by `inconsistent_mempool_byte_total_returns_typed_overflow_error` at `:912-925` |
| `indra/indra-consensus/src/mempool.rs:418-439` | `remove_entry` checks the stored entry's encoded size against the accounting total | test-only manipulated counter can reach it | **Tested** by `inconsistent_mempool_byte_total_returns_typed_underflow_error` at `:927-949` |
| `indra/indra-consensus/src/vote.rs:122-135` | `add_verified_vote` requires the vote ID to remain in this collector's voter snapshot | peer input reaches the public method only after the caller's authority verification; an epoch/snapshot race must be rejected by the caller rather than converted to a silent omission | no focused race test completed; **UNPROVEN** for a live membership change between verification and insertion |
| `indra/indra-storage/src/segmented_block_store.rs:277-307` | pruning starts from the indexed first retained height and checked segment arithmetic; overflow returns `StorageError::Corruption` | disk/prune state can reach it; the checked loop and checked removal end are fail-closed | no new focused overflow test completed; **UNPROVEN** for a crafted near-`u64::MAX` store |
| `indra/indra-rpc/src/handlers.rs:1680-1702` | every matching self-stake position must have `active` state | malformed/inconsistent state is constructible in the RPC unit test | **Tested** by the exact internal-error test above |

The vote site is intentionally not called a peer-reachable internal error: `add_verified_vote` documents that membership/signature verification was already done against the collector snapshot, while `add_vote` performs both checks in sequence at `vote.rs:108-112`. A caller that verifies against a different, mutable membership must reject the vote through that caller's existing invalid-vote path; this report does not establish that no such race exists.

## 4. Attribution and lint scope

**Verified just now — current diff stat:**

```text
42 files changed, 953 insertions(+), 387 deletions(-)
```

The P3/P3B/P3C/P3D attribution is:

- **P3/P3B state and tree work:** `indra/indra-state/src/apply.rs`, `delegation.rs`, `epoch.rs`, `error.rs`, `governance_apply.rs`, `lib.rs`, `persistent.rs`, `smt.rs`, `stake_positions.rs`, `state_commitment.rs`, `txn.rs`, and `utxo.rs`.
- **P3C fail-closed work:** `indra/indra-consensus/src/error.rs`, `mempool.rs`, `vote.rs`; `indra/indra-node/src/engine.rs` and `sync.rs`; `indra/indra-rpc/src/handlers.rs`; and `indra/indra-storage/src/segmented_block_store.rs`.
- **P3D lint/test-scope work:** crate-root lint additions in the changed `src/lib.rs` files, including the test-only exemption of `unreachable`, `todo`, and `unimplemented` alongside the existing `unwrap`, `expect`, and `panic` test exemptions. `indra-node/src/lib.rs` uses `cfg(any(test, feature = "test-support"))` because test-support helpers are compiled in that feature mode.

The following files are unexplained by P3D and are treated as pre-existing owner work: `indra/indra-bench/src/lib.rs`; the eight `indra-cli` files (`src/lib.rs` and the seven binaries); and `indra-node/src/bin/audit_block_log.rs`, `dns_seed_sign.rs`, `indra-sync-recover.rs`, `node.rs`, and `observer.rs`. Their first diff hunks are preserved verbatim in `/tmp/state_fix_p3d_unexplained_first20.log`; they are primarily prior lint-policy edits (for example, adding `deny(unused_must_use)` and additional denied Clippy lints), not altered here.

**Verified just now — Clippy:** `cargo clippy --workspace --all-targets --no-deps` completed with exit 0 in `/tmp/state_fix_p3d_clippy_after_allfix.log`, but emitted warnings. The output reports: `indra-state` lib 23; `indra-network` lib 8; `indra-rpc` lib 4; `indra-consensus` lib 2; `indra-storage` lib 3; `indra-node` lib 13; `indra-cli` lib-test 4; `indra-ffi` lib 18; plus duplicated target/test warnings listed in that log. There were no denied findings in this run.

**Verified just now — strict Clippy:** `cargo clippy --workspace --all-targets --no-deps -- -D warnings` failed. The exact first errors include existing test warnings at `indra-core/tests/serialisation.rs:128,268,275,277` (`redundant_closure`, `assertions_on_constants`, and `manual_div_ceil`) and production/test warnings in `indra-state/src/stake_positions.rs:493-533`, among many others. The complete output is `/tmp/state_fix_p3d_clippy_dwarnings.log`. No unrelated test code was rewritten and no broad `#[allow]` was added to force this gate green.

## 5. Verification commands

**Verified just now — `cargo check --workspace`:** exit 0, `Finished dev profile ... in 16.07s`; raw log `/tmp/state_fix_p3d_check_final.log`.

**Verified just now — `cargo test --workspace --release`:** exit 0; raw log `/tmp/state_fix_p3d_workspace_release.log`. Exact result lines include:

```text
test result: ok. 344 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 73.83s
test result: ok. 158 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 5.01s
test result: ok. 341 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out; finished in 1.78s
test result: ok. 48 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 2.44s
```

The release log contains `test result: ok` for every target and no `error:` line.

**Debug workspace run:** `/tmp/state_fix_p3d_workspace_debug_final.log` was launched after the final source edits and terminated at 19:56 by sending SIGTERM only to its identified test binary. The final raw lines were:

```text
test engine::tests::restart_from_snapshot_produces_same_state_as_continuous ... ok
error: test failed, to rerun this test, pass `-p indra-node --lib`

Caused by:
process didn't exit successfully: `/Users/bonkai/Desktop/indra/project_indra/indra/target/debug/deps/indra_node-8c70f20aa1ef579d` (signal: 15, SIGTERM: termination signal)
```

The active tests at termination were `startup_fails_on_snapshot_replay_gap` and `startup_from_snapshot_with_pruned_log`. It is **NOT COMPLETE**; no green debug-workspace claim is made here. The earlier debug run `/tmp/state_fix_p3d_workspace_debug.log` was also terminated and is not a pass result.

**Verified just now — golden test:** `cargo test -p indra-state --lib smt::tests::p3_golden_roots_and_proof_bytes_are_stable -- --exact` passed 1, failed 0, ignored 0; log `/tmp/state_fix_p3d_golden.log`. This confirms the existing golden roots/proof bytes were not regenerated.

**Verified just now — focused tests:** the RPC invariant test passed 1/0/0 in `/tmp/state_fix_p3d_rpc_test_final.log`; the two mempool invariant tests passed 1/0/0 in `/tmp/state_fix_p3d_mempool_overflow_final.log` and `/tmp/state_fix_p3d_mempool_underflow_final.log`.

**Verified just now — dependency checks:** `cargo audit` exited 0 and `cargo deny check` exited 0 in `/tmp/state_fix_p3d_cargo_audit.log` and `/tmp/state_fix_p3d_cargo_deny.log`. The exact final line was `advisories ok, bans ok, licenses ok, sources ok` for cargo-deny.

## Appendix: command/output index

The raw outputs are retained at these paths and were not rewritten:

```text
/tmp/state_fix_p3d_check_final.log
/tmp/state_fix_p3d_workspace_debug_final.log
/tmp/state_fix_p3d_workspace_release.log
/tmp/state_fix_p3d_clippy_after_allfix.log
/tmp/state_fix_p3d_clippy_dwarnings.log
/tmp/state_fix_p3d_cargo_audit.log
/tmp/state_fix_p3d_cargo_deny.log
/tmp/state_fix_p3d_bench_new_corrected.log
/tmp/state_fix_p3d_bench_old_corrected.log
/tmp/state_fix_p3d_unexplained_first20.log
```

The final free-space check was the exact `df -h .` output in section 1. The detached comparison worktree was `/tmp/indra-state-p3d-old` at `65833603`; it was used for the old benchmark. The requested old/new full-state differential test was not completed, so its output is **NOT RUN**.

**Verified just now — final `df -h .` after removing the temporary comparison worktree and benchmark target directories:**

```text
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   192Gi   8.8Gi    96%    2.0M   93M    2%   /System/Volumes/Data
```
