# State Fix P3C report

UNFINISHED / UNPROVEN (verified just now): the timing comparison is one local run per benchmark, not a statistical performance study; the compressed-tree insertion measurement crossed the requested 5% threshold. No fuzz campaign or independent performance reproduction was run. The existing uncommitted working tree contains earlier work outside P3C; this report does not attribute every pre-existing edit to P3C.

All commands in this report were run from `/Users/bonkai/Desktop/indra/project_indra/indra`, except repository-status/diff commands run from the repository root `/Users/bonkai/Desktop/indra/project_indra`. No commit, stage, restore, checkout, or stash was performed.

## 1. Rollback and `Drop`

### 1.1 Disk check

Verified just now before the work: `df -h .` reported 11 GiB available. The final check reported 10 GiB available. Both exceed the requested 3 GiB stop threshold. Final output is in Appendix A.

### 1.2 Rollback code

Taken from `git show HEAD:indra/indra-state/src/txn.rs` before the P3C edits: the former complete rollback/`Drop` code was:

```rust
fn rollback(&mut self) {
    #[cfg(test)]
    let rollback_start = Instant::now();
    while let Some(entry) = self.undo.pop() {
        match entry {
            UndoEntry::Scalars(snapshot) => {
                self.state.height = snapshot.height;
                self.state.tip_hash = snapshot.tip_hash;
                self.state.base_fee = snapshot.base_fee;
                self.state.total_supply = snapshot.total_supply;
                self.state.fee_reward_pool = snapshot.fee_reward_pool;
                self.state.epoch_slash_event_count = snapshot.epoch_slash_event_count;
                self.state.monetary_ledger = snapshot.monetary_ledger;
                self.state.monetary_aggregates = snapshot.monetary_aggregates;
                self.state.election_seed = snapshot.election_seed;
                self.state.election_seed_height = snapshot.election_seed_height;
            }
            UndoEntry::UtxoSpent(entry) => self
                .state
                .utxos
                .restore_for_rollback_at_height(entry, self.height),
            UndoEntry::UtxoInserted(id) => {
                let _ = self
                    .state
                    .utxos
                    .remove_for_rollback_at_height(&id, self.height);
            }
            UndoEntry::Validators(validators) => self.state.validators = validators,
            UndoEntry::PositionState { positions, tranches, index } => {
                self.state.stake_positions = positions;
                self.state.unbonding_tranches = tranches;
                self.state.position_tranche_index = index;
            }
            UndoEntry::StakingNonces(nonces) => self.state.staking_nonces = nonces,
            UndoEntry::DelegatorIdentities(identities) => {
                self.state.delegator_identities = identities;
            }
            UndoEntry::RetiredColdClassical(components) => {
                self.state.retired_cold_classical_components = components;
            }
            UndoEntry::RetiredColdPq(components) => {
                self.state.retired_cold_pq_components = components;
            }
            UndoEntry::Governance(governance) => self.state.governance = governance,
            UndoEntry::Utxos(utxos) => self.state.utxos = utxos,
            UndoEntry::ConsensusSnapshots(snapshots) => {
                self.state.consensus_snapshots = snapshots;
            }
            UndoEntry::RewardEconomicSnapshot(snapshot) => {
                self.state.reward_economic_snapshot = snapshot;
            }
            UndoEntry::SlashMembershipRoots(roots) => {
                self.state.slash_membership_roots = roots;
            }
            UndoEntry::EvictedValidatorTombstones(tombstones) => {
                self.state.evicted_validator_tombstones = tombstones;
            }
        }
    }
    if self.commitment_touched {
        self.state.state_commitment_v2 = self.commitment_before.clone();
    }
    #[cfg(test)]
    record_rollback_timing(rollback_start.elapsed());
}

impl Drop for StateTxn<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.rollback();
        }
    }
}
```

The current `indra-state/src/txn.rs:772-841` `StateTxn::rollback` is:

```rust
fn rollback(&mut self) {
    #[cfg(test)]
    let rollback_start = Instant::now();
    while let Some(entry) = self.undo.pop() {
        match entry {
            UndoEntry::Scalars(snapshot) => {
                self.state.height = snapshot.height;
                self.state.tip_hash = snapshot.tip_hash;
                self.state.base_fee = snapshot.base_fee;
                self.state.total_supply = snapshot.total_supply;
                self.state.fee_reward_pool = snapshot.fee_reward_pool;
                self.state.epoch_slash_event_count = snapshot.epoch_slash_event_count;
                self.state.monetary_ledger = snapshot.monetary_ledger;
                self.state.monetary_aggregates = snapshot.monetary_aggregates;
                self.state.election_seed = snapshot.election_seed;
                self.state.election_seed_height = snapshot.election_seed_height;
            }
            UndoEntry::Validators(validators) => self.state.validators = validators,
            UndoEntry::PositionState { positions, tranches, index } => {
                self.state.stake_positions = positions;
                self.state.unbonding_tranches = tranches;
                self.state.position_tranche_index = index;
            }
            UndoEntry::StakingNonces(nonces) => self.state.staking_nonces = nonces,
            UndoEntry::DelegatorIdentities(identities) => {
                self.state.delegator_identities = identities;
            }
            UndoEntry::RetiredColdClassical(components) => {
                self.state.retired_cold_classical_components = components;
            }
            UndoEntry::RetiredColdPq(components) => {
                self.state.retired_cold_pq_components = components;
            }
            UndoEntry::Governance(governance) => self.state.governance = governance,
            UndoEntry::Utxos(utxos) => self.state.utxos = utxos,
            UndoEntry::ConsensusSnapshots(snapshots) => {
                self.state.consensus_snapshots = snapshots;
            }
            UndoEntry::RewardEconomicSnapshot(snapshot) => {
                self.state.reward_economic_snapshot = snapshot;
            }
            UndoEntry::SlashMembershipRoots(roots) => {
                self.state.slash_membership_roots = roots;
            }
            UndoEntry::EvictedValidatorTombstones(tombstones) => {
                self.state.evicted_validator_tombstones = tombstones;
            }
        }
    }
    if self.commitment_touched {
        // The cache's projection height is not encoded in the cache and
        // cannot safely be inferred from either the restored tip or the
        // rejected block height at a gate boundary. Restore the exact
        // persistent-tree snapshot captured when the transaction began.
        self.state.state_commitment_v2 = self.commitment_before.clone();
    }
    #[cfg(test)]
    record_rollback_timing(rollback_start.elapsed());
}

impl Drop for StateTxn<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.rollback();
        }
    }
}
```

Verified just now from `indra-state/src/txn.rs:772-841`: rollback restores saved immutable snapshots, including the saved `state_commitment_v2` tree (`Arc`-backed state), by assignment. It performs no fallible operation and drops no `Result`. `indra-state/src/txn.rs:975-1026` adds `rollback_restores_utxo_root_and_proof_after_mutation_and_error`: it checks root and proof bytes after a normal mutation/drop and after a mutation that returns `Err`. The full state tests passed.

The UTXO undo variants and fallible rollback helpers were removed from production rollback. `indra-state/src/txn.rs` now snapshots the UTXO collection before mutation and restores that saved value. `indra-state/src/utxo.rs` retains `restore_for_rollback_at_height` only under `#[cfg(test)]` for its unit tests; the removed production `remove_for_rollback_at_height` is no longer present.

## 2. Attribution of the existing state hardening diff

The requested pre-P3C baseline was 34 files, 607 insertions, and 278 deletions. In the current tree, after P3C, the tracked diff is 42 files, 764 insertions, and 361 deletions. The extra files and lines include P3C changes and pre-existing work. The following attribution is by inspected diff and current source.

### (a) Crate-root lint additions

The `#![deny(unused_must_use)]` addition is present in these crate roots: `indra-bench/src/lib.rs`, `indra-cli/src/lib.rs`, `indra-consensus/src/lib.rs`, `indra-core/src/lib.rs`, `indra-crypto/src/lib.rs`, `indra-ffi/src/lib.rs`, `indra-keystore/src/lib.rs`, `indra-network/src/lib.rs`, `indra-node/src/lib.rs`, `indra-rpc/src/lib.rs`, `indra-state/src/lib.rs`, and `indra-storage/src/lib.rs`. `indra-node/src/lib.rs` already contained the lint before this pass; the others were checked and listed after the P3C change. Binary-root lint edits and unrelated CLI/node files in the current diff are pre-existing work outside the state rollback task.

### (b) Fallible authenticated-tree API callers

The fallible tree API and typed propagation are in `indra-state/src/persistent.rs`, `indra-state/src/smt.rs`, `state_commitment.rs`, `txn.rs`, `apply.rs`, `delegation.rs`, `epoch.rs`, `governance_apply.rs`, `stake_positions.rs`, `utxo.rs`, and `error.rs`. Callers now use `?` where the enclosing operation returns a state result; test-only helpers use explicit `.unwrap()` where a test fixture requires success. The node and consensus propagation sites are `indra-node/src/engine.rs`, `indra-node/src/sync.rs`, `indra-consensus/src/mempool.rs`, `indra-consensus/src/vote.rs`, `indra-consensus/src/error.rs`, `indra-storage/src/segmented_block_store.rs`, and `indra-rpc/src/handlers.rs`.

### (c) Explicit test failures and root/proof conventions

Test fixture variant assumptions in `indra-state/src/apply.rs`, `delegation.rs`, and `governance_apply.rs` now use explicit panic messages. The new rollback test in `indra-state/src/txn.rs:975-1026` compares both the UTXO root and proof bytes. The constructible invariant tests are `indra-state/src/persistent.rs` (`empty_persistent_prefix_input_returns_typed_invariant_error`) and `indra-state/src/smt.rs` (`empty_compressed_prefix_input_returns_typed_invariant_error`).

### (d) Other files

`indra-consensus/src/mempool.rs`, `vote.rs`, `error.rs`, `indra-node/src/engine.rs`, `sync.rs`, `indra-storage/src/segmented_block_store.rs`, and `indra-rpc/src/handlers.rs` contain the P3C typed-error and result-propagation changes described above. The remaining current-diff files, including earlier CLI, binary, node, and crate-root edits, are not explained by P3/P3B/P3C and remain owner work in the shared tree; they were not reverted.

## 3. Timing comparison

Verified just now with the same external helper harness, using commit `65833603` in the temporary worktree `/tmp/indra-state-p3c-old` for the old run and the current workspace for the new run. The helper and separate target directories were outside the repository. Each value is milliseconds (`ms`).

| Operation | Old | New | Change | Result |
|---|---:|---:|---:|---|
| `SparseMerkleTree` insert 10,000 | 1692 | 1767 | +4.43% | within 5% |
| `CompressedAuthTree` insert 10,000 | 38 | 40 | +5.26% | exceeds 5%; likely coarse 1-ms timing plus fallible-path propagation |
| `PersistentAuthTree` insert 10,000 | 48 | 49 | +2.08% | within 5% |
| `CompressedAuthTree` delete 10,000 | 34 | 35 | +2.94% | within 5% |
| `PersistentAuthTree` delete 10,000 | 43 | 44 | +2.33% | within 5% |
| `CompressedAuthTree` prove 1,000 | 1 | 0 | not meaningful | 0-ms new measurement |
| `PersistentAuthTree` prove 1,000 | 0 | 0 | not meaningful | both below 1 ms |

Exact old and new output is in `/tmp/state_fix_p3c_timing_old.log` and `/tmp/state_fix_p3c_timing_new.log`. The helper used `let _ =` only for compatibility with the old/new benchmark function return types in the temporary helper; it is not repository code and not a protocol fallback.

## 4. Remaining fallbacks in `persistent.rs` and `smt.rs`

Verified just now with `rg -n -i "unwrap_or|\.ok\(\)|let .*else|if let Some" indra-state/src/persistent.rs indra-state/src/smt.rs`. The full hit list is Appendix B. The classification is:

- `smt.rs:352,379,385,389,411,479-481,500,509,519,532,548` and `persistent.rs:359,431,435,457,487,497,510,526,554,564,1150` use fixed-depth empty hashes, absent sibling hashes, empty child nodes, or zero depth/bitmap values. These are authenticated-tree protocol representations of an empty subtree or absent sibling, not silent acceptance of a malformed path.
- `smt.rs:242,280,317,443,457,475,755,879,995,1066,1072,1129` and `persistent.rs:549,555,612,646,668,692,708,735,799,1184,1310,1413` handle optional structural children/levels. Their absence is the tree shape being traversed; malformed constructor inputs are rejected by typed `InternalInvariant` paths rather than silently skipped.
- `smt.rs:411,876` and `persistent.rs:1307` use a zero bitmap fallback for a structurally empty child map. This is the canonical empty bitmap.
- `smt.rs:929,937` and `persistent.rs:1347,1355` are now explicit `InternalInvariant` returns for empty pairs or missing prefix elements; the new tests exercise the constructible empty-pairs paths. The private missing-index branches are only reachable from malformed internal representation and are not constructible through the public tree constructors.
- `smt.rs:1033-1034` and `persistent.rs:1451-1452` convert invalid compressed encodings into typed string errors; they are not silent fallbacks.
- `smt.rs:1081,1102,1128` and `persistent.rs:564,585,611` are bounded bit-index conversions; the default is the protocol’s zero bit offset/depth after prior bounds arithmetic.
- `persistent.rs:318,322` returns height/length zero for an absent optional node, which is the empty-tree value.
- `persistent.rs:1989,1992,1996` is test-only benchmark environment parsing: invalid or absent `INDRA_STATE_BENCH_SIZES` falls back to the benchmark’s default size list. It does not affect protocol state.
- `let Some(... ) else` branches in proof and delete traversal return a valid absence/empty proof or preserve the tree shape; no P3 compressed-tree builder continues after a missing required element.

## 5. Five production `expect` sites

Verified just now by inspecting the current source and running the final clippy command:

| Former site | Current handling | Reachability / result |
|---|---|---|
| `indra-consensus/src/mempool.rs:313` | Byte accounting is precomputed with checked add/sub and returns `ConsensusError::InternalInvariant` at `:305-307`; insertion no longer uses an unchecked `expect`. | The arithmetic error is constructible only by inconsistent internal accounting; it now fails closed with a typed error. |
| `indra-consensus/src/mempool.rs:417` | `remove_entry` at `:419-439` returns `ConsensusResult<Option<MempoolEntry>>` and uses checked subtraction at `:422-426`. | Underflow is an internal invariant failure and is returned, not discarded. |
| `indra-consensus/src/vote.rs:125` | Membership lookup at `:125-131` returns `ConsensusError::InternalInvariant` when a previously validated vote is absent from collector membership. | The branch is theoretically reachable only from inconsistent collector state; it fails closed. |
| `indra-storage/src/segmented_block_store.rs:297` | `start.checked_add(BLOCKS_PER_SEGMENT)` at `:297-302` returns `StorageError::Corruption` on overflow. | The overflow branch is constructible only for an invalid segment height; it is typed corruption. |
| `indra-rpc/src/handlers.rs:1691` | The active position is selected by the preceding filter and is accessed with `filter_map`/`as_ref()?`; no panic is possible. | A missing active position yields no result and is not exposed as a self-stake record. |

The final `cargo clippy --workspace --lib --bins --no-deps` exited 0. Its warning-level output was retained in `/tmp/state_fix_p3c_clippy_final.log`; no denied finding remained. Test-only `unreachable!`/`todo!`/`unimplemented!` conventions in crypto/core were not converted into production fallbacks.

## 6. Verification

### 6.1 Result summaries

Verified just now. Both workspace test logs contain 48 `test result:` lines and the following exact aggregate command output was computed from those lines:

```text
debug targets=48 passed=1645 failed=0 ignored=10
release targets=48 passed=1645 failed=0 ignored=10
```

The principal per-target counts, as printed in both logs, were: `indra-bench` 19/0/0; `indra-cli` library 85/0/0 plus its binary/integration targets; `indra-consensus` library 60/0/0 and integration 5/0/0; `indra-core` library 154/0/0, serialisation 21/0/0, audit_phase1 2/0/0, bench_dilithium 1/0/0; `indra-crypto` 38/0/0; `indra-ffi` 26/0/0; `indra-keystore` 22/0/0; `indra-network` 158/0/1 plus network integration 4/0/0; `indra-node` library 344/0/5, node binary targets 1/0/92 filtered, 93/0/0, and node integrations 17/0/0 and 7/0/0; `indra-rpc` 68/0/0 and 35/0/0; `indra-state` library 341/0/3 and integration targets 4/0/0, 10/0/0, and 25/0/0; `indra-storage` 48/0/1. The exact raw per-target lines are in the two logs.

| Command | Result | Raw log |
|---|---|---|
| `cargo check --workspace` | exit 0; `Finished dev profile [unoptimized + debuginfo] target(s) in 7.17s`; no warnings | `/tmp/state_fix_p3c_workspace_check_final.log` |
| `cargo test --workspace` | exit 0; 1,645 passed / 0 failed / 10 ignored across 48 result targets | `/tmp/state_fix_p3c_workspace_debug_final.log` |
| `cargo test --workspace --release` | exit 0; 1,645 passed / 0 failed / 10 ignored across 48 result targets | `/tmp/state_fix_p3c_workspace_release_final.log` |
| `cargo audit` | exit 0; 282 dependencies scanned, no advisory output | `/tmp/state_fix_p3c_cargo_audit.log` |
| `cargo deny check` | exit 0; `advisories ok, bans ok, licenses ok, sources ok` | `/tmp/state_fix_p3c_cargo_deny.log` |
| `cargo clippy --workspace --lib --bins --no-deps --message-format=short` | exit 0; warnings only, no denied findings | `/tmp/state_fix_p3c_clippy_final.log` |

The unchanged golden test `smt::tests::p3_golden_roots_and_proof_bytes_are_stable` passed in the debug and release workspace logs. No golden root or proof-byte literal was changed by P3C.

### 6.2 Final disk and diff facts

Verified just now: final `df -h .` reported 10 GiB available. The temporary P3C worktree and benchmark target directories were removed after the measurements. The current tracked diff, including pre-existing work, is 42 files, 764 insertions, and 361 deletions. Existing untracked audit reports and logs remain untouched.

## Appendix A: exact command/result excerpts

```text
$ df -h .
/dev/disk3s5      228Gi  191Gi   10Gi    95%    2.0M  106M    2%   /System/Volumes/Data

$ awk '/^test result: ok\\./ {p+=$4; f+=$6; i+=$8; n++} END {printf "debug targets=%d passed=%d failed=%d ignored=%d\\n",n,p,f,i}' /tmp/state_fix_p3c_workspace_debug_final.log
debug targets=48 passed=1645 failed=0 ignored=10

$ awk '/^test result: ok\\./ {p+=$4; f+=$6; i+=$8; n++} END {printf "release targets=%d passed=%d failed=%d ignored=%d\\n",n,p,f,i}' /tmp/state_fix_p3c_workspace_release_final.log
release targets=48 passed=1645 failed=0 ignored=10

$ cargo audit
Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
Loaded 1509 security advisories (from /Users/bonkai/.cargo/advisory-db)
Scanning Cargo.lock for vulnerabilities (282 crate dependencies)

$ cargo deny check
advisories ok, bans ok, licenses ok, sources ok
```

The complete stdout/stderr for every command is preserved at the raw paths in Section 6.1. The exact per-target result lines can be reproduced with:

```text
rg '^test result:' /tmp/state_fix_p3c_workspace_debug_final.log
rg '^test result:' /tmp/state_fix_p3c_workspace_release_final.log
```

## Appendix B: fallback command output

The complete fallback inventory requested in Section 4 is preserved verbatim in `/tmp/state_fix_p3c_fallbacks.log`, generated with:

```text
rg -n -i "unwrap_or|\\.ok\\(\\)|let .*else|if let Some" indra-state/src/persistent.rs indra-state/src/smt.rs
```

## Appendix C: changed-state safety grep

Verified just now with:

```text
git diff -- indra/indra-state/src | grep -nE '^\\+.*(unreachable|unimplemented|todo!|panic!|assert|unwrap_or|expect\\(|let _ =|\\.ok\\(\\))'
```

The output contains only test assertions/panic messages and the existing test-oriented lint additions; no new production `unreachable!`, `unimplemented!`, `todo!`, `panic!`, `unwrap_or`, `expect`, discarded `Result`, or `.ok()` was introduced in the changed `indra-state` production paths.

Final repository status and the full diff stat were collected read-only after verification. They include the owner’s pre-existing uncommitted files and the new report; no tracked source outside the P3C implementation was reverted.
