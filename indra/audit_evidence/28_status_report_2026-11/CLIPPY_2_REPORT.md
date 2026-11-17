# Clippy 2 report

**Unfinished / unproven:** the requested Clippy-2 pass is not fully complete. The release workspace suite passed, but the final Clippy run still reports test-only `needless_range_loop` findings and the required wire/ABI comparison against `da184a16` was not completed. The report below records exactly what was changed and what remains.

## Preconditions and Stage 1

`df -h .` before work:

```text
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   193Gi   8.4Gi    96%    2.0M   88M    2%   /System/Volumes/Data
```

The final free-space check was 6.8 GiB available; no build was stopped for disk pressure.

The initial release gate was run as:

```text
cargo test --workspace --release 2>&1 | tee /tmp/clippy2_stage1_release.log
```

It passed. The raw `test result:` lines are in `/tmp/clippy2_stage1_release.log`; all lines report `0 failed`. The largest crate targets were `indra-node`: `344 passed; 0 failed; 5 ignored`, `indra-network`: `158 passed; 0 failed; 1 ignored`, and `indra-state`: `342 passed; 0 failed; 3 ignored`.

The advisory checks were run as:

```text
cargo audit 2>&1 | tee /tmp/clippy2_audit.log
cargo deny check 2>&1 | tee /tmp/clippy2_deny.log
```

`cargo audit` completed after scanning 282 dependencies without an advisory failure. `cargo deny check` ended with `advisories ok, bans ok, licenses ok, sources ok`; it also printed the existing duplicate-package warnings for `block-buffer`, `chacha20`, `cpufeatures`, `thiserror`, `thiserror-impl`, and `windows-sys`.

## Applied changes

The mechanical Clippy pass and follow-up fixes touched the existing dirty tree in these areas:

- boxed internal payloads in `indra-network/src/net_types.rs`, `peer_manager.rs`, `transport.rs`, and `indra-storage/src/vote_safety.rs`; `indra-network/src/message.rs` now boxes only the `Message::Block` enum payload while its manual payload encoder still calls `BlockProposalVNext::encode_to_vec()` through deref;
- boxed `SigningMaterial` payload structs in `indra-ffi/src/handles.rs` and retained explicit zeroization of all seed arrays in its `Drop` implementation;
- `Default` implementations for the three rate-limit types in `indra-network/src/rate_limit.rs`;
- mechanical `from_ref` and indexing cleanups applied by Clippy in CLI, consensus, discovery, and test code;
- checked segment-end construction in `indra-storage/src/segmented_block_store.rs`;
- FFI safety documentation and existing mechanical warning fixes from the preceding Clippy pass.

No manifest, lockfile, workflow, or consensus-rule file was intentionally changed by this task. The tree already contained many unrelated uncommitted files before this pass; the final status is recorded below.

## Stale collector check

The current `ConsensusDriver::set_voters` implementation in `indra-node/src/driver.rs` clears `vote_collectors` and `round_advance_evidence` before replacing `registered_voters`; `refresh_registered_voters` calls it as the single update path. Collector creation clones the current registered voter set. Height transition and sync-catch-up paths also clear collectors. Thus the code does not leave a live collector bound to the replaced voter set. No stale-vote metric or action was added.

## `apply.rs` reorder proof

The commands were:

```text
git diff --numstat -- ./indra-state/src/apply.rs
git diff --color-moved=dimmed-zebra --stat -- ./indra-state/src/apply.rs
```

The raw output was:

```text
4413  4412  indra/indra-state/src/apply.rs
 indra/indra-state/src/apply.rs | 8825 ++++++++++++++++++++--------------------
 1 file changed, 4413 insertions(+), 4412 deletions(-)
```

The extracted function-name lists from `git show HEAD:indra/indra-state/src/apply.rs` and the working tree both had 100 entries and `diff -u` produced no output. A sorted whole-file comparison was not empty: it identified three non-move changes, including the `tombstone.clone()` binding and an `inspect` conversion. Therefore the large diff is predominantly the test-module relocation, but it is not provably a pure move from the command evidence alone.

## Final Clippy result

Command:

```text
cargo clippy --workspace --all-targets --no-deps --message-format=short 2>&1 | tee /tmp/clippy2_final_clippy.log
```

The remaining findings are:

- allowed for the next pass: `too_many_arguments` in state, consensus, node, and the state-machine test;
- allowed for the next pass: `type_complexity` in state, node, and FFI;
- not yet fixed: `needless_range_loop` in `indra-node/src/driver_tests.rs` test code;
- not yet proven: the requested independent wire/ABI comparison for every boxed enum.

The final Clippy run had no remaining `large_enum_variant`, `large_err_variant`, `new_without_default`, `clone_on_ref_ptr`, or FFI `missing_safety_doc` findings outside the explicitly deferred categories, except that the node test enum still reports a large-enum warning in the test target. The complete raw output is `/tmp/clippy2_final_clippy.log`.

## Verification after edits

Release workspace:

```text
cargo test --workspace --release 2>&1 | tee /tmp/clippy2_final_release.log
```

This completed successfully. The node library line was:

```text
test result: ok. 344 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 84.48s
```

No `test result:` line in `/tmp/clippy2_final_release.log` contains a nonzero failure count.

Focused debug tests:

```text
{ cargo test -p indra-network --lib; cargo test -p indra-ffi --lib; cargo test -p indra-cli --lib; cargo test -p indra-storage --lib; cargo test -p indra-consensus --lib; cargo test -p indra-state --lib; cargo test -p indra-node --lib 'genesis::tests::golden_vector_values' -- --exact; } 2>&1 | tee /tmp/clippy2_focused_debug.log
```

The raw result lines were:

```text
158 passed; 0 failed; 1 ignored
85 passed; 0 failed; 0 ignored
48 passed; 0 failed; 1 ignored
63 passed; 0 failed; 0 ignored
342 passed; 0 failed; 3 ignored
1 passed; 0 failed; 0 ignored
```

The targeted golden-vector test passed. The complete log is `/tmp/clippy2_focused_debug.log`.

The focused release log `/tmp/clippy2_focused_release.log` contains the network message suite result:

```text
test result: ok. 37 passed; 0 failed; 0 ignored; 0 measured; 122 filtered out; finished in 0.01s
```

The other requested focused release commands were not completed in that combined shell invocation; no result is claimed for them.

## Wire/ABI neutrality limits

`Message::Block` remains manually encoded by `encode_payload` and decoded by `decode_payload`; the box changes allocation/layout only. The boxed `NetworkEvent`, `PeerManagerMessage`, `RecvStatus`, and `VoteSafetyLoadResult` are internal enums and are not directly encoded or exported through a C ABI. However, the required comparison against a clean `da184a16` worktree and byte-vector output was not run, so wire/ABI neutrality is not fully proven by this report.

## Diff summary and final disk/status evidence

The final `git diff --stat` output was:

```text
46 files changed, 4745 insertions(+), 4705 deletions(-)
```

The 8,825-line `indra-state/src/apply.rs` relocation dominates that number. The report itself and the other audit files shown by `git status --short` are untracked pre-existing report artifacts; they were not removed.

Final `df -h .`:

```text
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   194Gi   6.8Gi    97%    2.0M   71M    3%   /System/Volumes/Data
```

Final `git status --short` was captured immediately before this report was written; it showed the existing modified source tree plus the existing untracked audit reports and logs. No commit, stage, restore, checkout, or stash operation was run.
