# State Fix P3B report

## Scope and outcome

Verified just now from `/Users/bonkai/Desktop/indra/project_indra/indra`. This pass removes the P3 `unreachable!` implementation from the authenticated-tree paths, removes the P3 silent nibble defaults on those paths, and propagates tree invariant failures as `StateError::InternalInvariant { site }` (`indra-state/src/error.rs:27-33`). It also adds `clippy::unreachable`, `clippy::todo`, and `clippy::unimplemented` denies to the crate roots that already deny unwrap/expect/panic. Existing uncommitted work was preserved; no commit, stage, restore, checkout, or stash was performed.

The final tracked diff includes the pre-existing working-tree edits as well as this pass. The new report is untracked.

## Former P3 sites

Verified just now by `rg -n 'unreachable!' indra-state/src` plus inspection of the edited functions. No `unreachable!` remains in `indra-state/src` production code. The former P3 sites are handled as follows:

| Site | Current handling |
|---|---|
| `persistent.rs:PersistentAuthTree::from_pairs` and `smt.rs:CompressedAuthTree::from_pairs` duplicate-key windows | Adjacent iterator zip; the two-element window pattern is no longer represented as a destructuring fallback. |
| `persistent.rs:remove_min` | A direct `match` on `node.left`; the recursive branch receives an actual child. |
| `persistent.rs:build_persistent_subtree` and `smt.rs:build_compressed_subtree` singleton pair | Slice-pattern matching; malformed cardinality returns `InternalInvariant` at `persistent::build_persistent_subtree singleton` or `smt::build_compressed_subtree singleton`. |
| The same subtree builders' index, end, group, child-nibble, and other-nibble accesses | `get`/iterator access with `InternalInvariant` sites: `... index`, `... end`, `... group`, `... child nibble`, and `... other nibble`. The builder returns `StateResult` and propagates with `?`. |
| `persistent_insert` and `compressed_insert` prefix, split-nibble, child-nibble, and recursive-child paths | Both insertion functions return `StateResult`; missing path elements return named `InternalInvariant` errors and are propagated. |
| `persistent_delete` and `compressed_delete` child-nibble paths | Missing checked path elements return named `InternalInvariant` errors; delete returns `StateResult`. |
| `collapse_or_persistent_branch` and `collapse_or_branch` | `pop_first` is matched; an inconsistent one-child branch returns `InternalInvariant` rather than panicking or silently constructing a default. |
| `make_persistent_branch` and `make_branch` hash construction | Hash-construction errors return `InternalInvariant`; the old empty-hash fallback is removed. |
| `persistent_prove` and `compressed_prove` target nibble | The checked iterator path returns a prefix-mismatch proof if the representation is inconsistent; no panic or skipped child is used. |
| `longest_common_prefix_for_pairs` in both implementations | Empty input returns `InternalInvariant`; bounded iteration constructs the prefix without indexing. |
| `pack_nibbles` in both implementations | `chunks_exact` plus an explicit two-item match; a malformed chunk returns `None` from the encoding helper. |
| Existing test-only variant assumptions in `apply.rs`, `delegation.rs`, and `governance_apply.rs` | Replaced with explicit test panic messages. They are under test code and are not production paths. |

The tree mutation APIs now return `StateResult`: `CompressedAuthTree::insert/delete`, `PersistentAuthTree::insert/delete`, and the state-commitment setters. UTXO insertion/spending and normal state-transition callers propagate these results. The rollback `Drop` path cannot return a result by Rust’s `Drop` contract and therefore still records the existing rollback operation without a new public fallback; this is a remaining design limitation, not a default hash or skipped mutation.

## Silent fallback review

Verified just now by inspecting `persistent.rs` and `smt.rs`. The P3-specific `nibbles.get(...).copied().unwrap_or(0)`, `other...unwrap_or(0)`, and `let [first, second] = window else { continue }` paths are gone. The remaining `unwrap_or` expressions in those files are in the fixed-depth sparse-tree implementation or represent absent sibling/leaf hashes, where the empty-tree hash is the protocol value; they are not the P3 compressed-tree construction paths. The final changed-source check was:

```text
$ git diff -- indra/indra-state/src | grep -nE '^\\+.*(unreachable|unimplemented|todo!|panic!|assert|unwrap_or|expect\\()' || true
```

It produced no output.

## Lint policy

Verified just now by `rg -n '#!\[deny\(clippy::(unwrap_used|expect_used|panic)' indra --glob '*.rs'`. The new deny group was added to the existing roots in `indra-cli`, `indra-core`, `indra-consensus`, `indra-crypto`, `indra-ffi`, `indra-keystore`, `indra-network`, `indra-node` (library and binaries), `indra-rpc`, `indra-state`, and `indra-storage`.

`cargo clippy -p indra-state --all-targets --no-deps --message-format=short` passed with exit 0 and no denied findings. It emitted warning-level findings only: 23 library warnings, repeated in the lib-test target, plus test-target warnings in `monetary_invariants.rs` and `state_machine.rs`. Raw output: `/tmp/state_fix_p3b_clippy_state.log`.

The full `cargo clippy --workspace --all-targets --message-format=short` did not pass because the newly enforced lints expose pre-existing non-state test/library issues outside the requested state fix. The exact blockers are recorded in `/tmp/state_fix_p3b_clippy_workspace.log` and `/tmp/state_fix_p3b_clippy_each.log`:

| Crate | Result | Findings |
|---|---|---|
| `indra-core` | PASS (`--lib`) | no errors |
| `indra-consensus` | FAIL (`--lib`) | `src/mempool.rs:313`, `src/mempool.rs:417`, `src/vote.rs:125`: existing `expect()` findings |
| `indra-node` | PASS (`--lib`) | warning-level findings only |
| `indra-crypto` | PASS (`--lib`) | no errors |
| `indra-network` | PASS (`--lib`) | warning-level findings only |
| `indra-storage` | FAIL (`--lib`) | `src/segmented_block_store.rs:297`: existing `expect()` finding |
| `indra-cli` | PASS (`--lib`) | warning-level findings only |
| `indra-ffi` | PASS (`--lib`) | warning-level unsafe-doc findings only |
| `indra-rpc` | FAIL (`--lib`) | `src/handlers.rs:1691`: existing `expect()` finding |
| `indra-keystore` | PASS (`--lib`) | no errors |
| `indra-state` | PASS (`--all-targets`) | no errors; warning-level findings only |
|

These external findings were not changed in this state-only hardening pass.

## Production assertions survey

Verified just now with a workspace `git grep` survey and manual classification. Assertions in source outside test modules are concentrated in existing validation and fail-closed checks in the CLI, RPC, node, and state paths; they are not newly introduced by this pass. Test-only assertion hits remain in `#[cfg(test)]` modules and integration-test files. No production `assert!`, `assert_eq!`, `assert_ne!`, or `debug_assert!` was added by the P3B tree changes.

## Determinism and performance

Verified just now by the unchanged golden test:

```text
test smt::tests::p3_golden_roots_and_proof_bytes_are_stable ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 340 filtered out; finished in 4.90s
```

The five golden roots and proof digest remain the P3 values: empty `aee65339a08b06fbd1665922de21c2d317f62b6cdccde6a3734a3e76adcbf85d`, one leaf `4a3b7eeee9681c532ca0e5ca63b3585305fa01c0cbcd633756d86290fff99bbb`, colliding leaves `0ce4559c1b8d6d89df0c9dc1cf156a055ace5fa6559bed9394f2be50b9a8e2a4`, random `695f52706fe2a51746f330f5e3d33201cb77d88cee2983352deee79b5d6010f1`, sequence `d68a447318b2b7dbc8262a07dba08692a52dbb8dae6fcbf2d3bd87034009e9c8`, and proof digest `b5a8b2f4a91b9e63a251b86239faa359844755b37797818bddedd0676c7acf4e`. These values are taken from the existing P3 report and rechecked by the golden test just now.

The earlier P3 timing reference, taken from `STATE_FIX_P3_REPORT.md`, was sparse 44,522 ms, compressed 639 ms, and persistent 677 ms. P3B did not rerun the external timing helper; the requested timing comparison is therefore **NOT RUN in this pass**, and no new performance conclusion is claimed.

## Verification just now

All commands ran from `/Users/bonkai/Desktop/indra/project_indra/indra`.

| Command | Exact result line / result | Log |
|---|---|---|
| `cargo check --workspace` | `Finished 'dev' profile [unoptimized + debuginfo] target(s) in 6.63s`; exit 0, no warnings | `/tmp/state_fix_p3b_workspace_check_final.log` |
| `cargo test --workspace` | `test result: ok. 1,642 passed; 0 failed; 10 ignored` in the aggregate; exit 0 | `/tmp/state_fix_p3b_workspace_debug.log` |
| `cargo test --workspace --release` | aggregate count parsed from exact per-target result lines: 1,642 passed; 0 failed; 10 ignored; exit 0 | `/tmp/state_fix_p3b_workspace_release.log` |
| `cargo audit` | `Scanning Cargo.lock for vulnerabilities (282 crate dependencies)` with no advisory output; exit 0 | `/tmp/state_fix_p3b_cargo_audit_final.log` |
| `cargo deny check` | `advisories ok, bans ok, licenses ok, sources ok`; exit 0 | `/tmp/state_fix_p3b_cargo_deny_final.log` |
| `cargo clippy -p indra-state --all-targets --no-deps --message-format=short` | `Finished 'dev' profile ...`; exit 0, 0 errors | `/tmp/state_fix_p3b_clippy_state.log` |
| `cargo clippy --workspace --all-targets --message-format=short` | exit 101 due the external findings listed above | `/tmp/state_fix_p3b_clippy_workspace.log` |

Debug and release per-target counts were identical:

| Target group | Passed | Failed | Ignored |
|---|---:|---:|---:|
| `indra-bench` | 19 | 0 | 0 |
| `indra-cli` | 141 | 0 | 0 |
| `indra-consensus` | 65 | 0 | 0 |
| `indra-core` | 175 | 0 | 0 |
| `indra-crypto` | 41 | 0 | 0 |
| `indra-ffi` | 26 | 0 | 0 |
| `indra-keystore` | 22 | 0 | 0 |
| `indra-network` | 162 | 0 | 1 |
| `indra-node` | 462 | 0 | 5 |
| `indra-rpc` | 103 | 0 | 0 |
| `indra-state` | 377 | 0 | 3 |
| `indra-storage` | 49 | 0 | 1 |
| **Total** | **1,642** | **0** | **10** |

Within `indra-node`, the library target was 344 passed / 0 failed / 5 ignored. Within `indra-state`, the library target was 338 passed / 0 failed / 3 ignored, with integration targets adding 39 passed.

## Final workspace facts

Verified just now by `df -h .`: 10 GiB available on the workspace filesystem, so the 3 GiB stop threshold was not reached. The final tracked `git diff --stat` was:

```text
34 files changed, 607 insertions(+), 278 deletions(-)
```

The tracked list includes existing uncommitted changes outside this P3B pass; this report does not claim those files were authored by P3B. `Cargo.lock` was not modified by this pass.

## Appendix: raw command output locations

The complete raw outputs are retained at:

```text
/tmp/state_fix_p3b_workspace_check_final.log
/tmp/state_fix_p3b_workspace_debug.log
/tmp/state_fix_p3b_workspace_release.log
/tmp/state_fix_p3b_clippy_state.log
/tmp/state_fix_p3b_clippy_workspace.log
/tmp/state_fix_p3b_clippy_each.log
/tmp/state_fix_p3b_cargo_audit_final.log
/tmp/state_fix_p3b_cargo_deny_final.log
```

Final status was collected with `git status --short`; it includes the pre-existing uncommitted source/report inventory plus this new untracked report. No git mutation command was used.
