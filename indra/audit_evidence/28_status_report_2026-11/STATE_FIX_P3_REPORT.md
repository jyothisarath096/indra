# State Fix P3 report

No pre-edit site was reachable from corrupt on-disk bytes or peer/RPC-influenced input: the 48 findings are in standalone tree algorithms, and neither `persistent.rs` nor `smt.rs` decodes storage, snapshots, commit logs, peer messages, RPC requests, or transactions at these sites. Anything unfinished or unproven: the checked proof-byte value below is a test-local canonical encoding of `MerkleProof`, because the public proof type has no protocol `Encode` implementation; the source guard is structural rather than a formal proof of all future indexing.

## Scope and classification

The repository root/workspace used for every command was `/Users/bonkai/Desktop/indra/project_indra/indra`. The initial disk check was `df -h .`: 12 GiB available, so the requested stop threshold was not reached. The pre-edit command was:

```text
cargo clippy -p indra-state --lib --no-deps --message-format=short
```

It reported 48 errors: 3 `expect_used` findings and 45 `indexing_slicing` findings. The table below records every pre-edit error site. Classification `(c)` means a tree-internal consistency condition; `(d)` means the loop, match arm, or prior length/path check proves the access is construction-bounded. No site was classified `(a)` or `(b)`, so no new malformed-record `StateError` variant was needed and there are no decode fixtures for truncated, oversized-length, or flipped-length inputs.

| pre-edit file:line | function / operation | index, slice, or expect | bound or proof in code | class |
|---|---|---|---|---|
| `persistent.rs:370` | `PersistentSparseMerkleTree::from_pairs` | `window[0]`, `window[1]` | `windows(2)` supplies a two-element window | d |
| `persistent.rs:778` | `remove_min` | `as_ref().expect` | the preceding `node.left.is_none()` branch returns; recursive call is only for a present left child | c |
| `persistent.rs:890` | `PersistentAuthTree::from_pairs` | `window[0]`, `window[1]` | `windows(2)` supplies a two-element window | d |
| `persistent.rs:987` | `build_persistent_subtree` | `pairs[0]` | match arm is `pairs.len() == 1` | d |
| `persistent.rs:999` | `build_persistent_subtree` | `pairs[index]` | `index < pairs.len()` loop guard | d |
| `persistent.rs:1003` | `build_persistent_subtree` | `pairs[end]` | `end < pairs.len()` loop guard | d |
| `persistent.rs:1011` | `build_persistent_subtree` | `pairs[index..end]` | `index` and `end` are maintained as ordered bounds inside `pairs` | d |
| `persistent.rs:1046` | `persistent_insert` | `key_nibbles[..prefix_len]` | common-prefix length is computed from both 64-nibble keys | c |
| `persistent.rs:1049` | `persistent_insert` | `existing_nibbles[prefix_len]` | distinct equal-length keys have a differing nibble at the first non-common position | c |
| `persistent.rs:1057` | `persistent_insert` | `key_nibbles[prefix_len]` | same distinct-key invariant | c |
| `persistent.rs:1073` | `persistent_insert` | `prefix[shared]` | branch split only when `shared < prefix.len()` | c |
| `persistent.rs:1074` | `persistent_insert` | `key_nibbles[shared]` | the shared prefix is shorter than the key path | c |
| `persistent.rs:1088` | `persistent_insert` | `key_nibbles[..shared]` | `shared` is a common-prefix length bounded by the key | c |
| `persistent.rs:1124` | `persistent_delete` | `key_nibbles[prefix.len()]` | prior prefix-match and strict-length checks | c |
| `persistent.rs:1146` | `collapse_or_persistent_branch` | `pop_first().expect` | match arm is `children.len() == 1` | d |
| `persistent.rs:1225` | `persistent_prove` | `key_nibbles[prefix.len()]` | prior prefix-match and strict-length checks | c |
| `persistent.rs:1266` | `longest_common_prefix_for_pairs` | `pairs[0]` | called from subtree construction with non-empty pairs | d |
| `persistent.rs:1269` | `longest_common_prefix_for_pairs` | `first[len]` | `len < first.len()` loop guard | d |
| `persistent.rs:1280` | `longest_common_prefix_for_pairs` | `first[..len]` | loop leaves `len <= first.len()` | d |
| `persistent.rs:1285` | `common_nibble_prefix_len` | `a[index]`, `b[index]` | both lengths are checked in the loop condition | d |
| `persistent.rs:1292` | `starts_with_nibbles` | `key[..prefix.len()]` | `key.len() >= prefix.len()` guard | d |
| `persistent.rs:1314` | `pack_nibbles` | `chunk[0]` | `chunks(2)` never yields an empty chunk | d |
| `smt.rs:180` | `CompressedAuthTree::from_pairs` | `window[0]`, `window[1]` | `windows(2)` supplies a two-element window | d |
| `smt.rs:288` | `CompressedAuthTree::verify_proof` | `key_nibbles[branch_prefix.len()]` | valid path, prefix match, and strict-length checks | c |
| `smt.rs:555` | `build_compressed_subtree` | `pairs[0]` | match arm is `pairs.len() == 1` | d |
| `smt.rs:567` | `build_compressed_subtree` | `pairs[index]` | `index < pairs.len()` loop guard | d |
| `smt.rs:571` | `build_compressed_subtree` | `pairs[end]` | `end < pairs.len()` loop guard | d |
| `smt.rs:577` | `build_compressed_subtree` | `pairs[index..end]` | ordered bounds maintained inside `pairs` | d |
| `smt.rs:608` | `compressed_insert` | `key_nibbles[..prefix_len]` | common-prefix length is bounded by both 64-nibble keys | c |
| `smt.rs:611` | `compressed_insert` | `existing_nibbles[prefix_len]` | distinct equal-length keys have a differing nibble there | c |
| `smt.rs:619` | `compressed_insert` | `key_nibbles[prefix_len]` | same distinct-key invariant | c |
| `smt.rs:637` | `compressed_insert` | `prefix[shared]` | split only when `shared < prefix.len()` | c |
| `smt.rs:638` | `compressed_insert` | `key_nibbles[shared]` | shared index is inside the key path | c |
| `smt.rs:649` | `compressed_insert` | `key_nibbles[..shared]` | shared prefix length is bounded by the key | c |
| `smt.rs:689` | `compressed_delete` | `key_nibbles[prefix.len()]` | prior prefix-match and strict-length checks | c |
| `smt.rs:709` | `collapse_or_branch` | `pop_first().expect` | match arm is `children.len() == 1` | d |
| `smt.rs:785` | `compressed_prove` | `key_nibbles[prefix.len()]` | prior prefix-match and strict-length checks | c |
| `smt.rs:839` | `longest_common_prefix_for_pairs` | `pairs[0]` | called from subtree construction with non-empty pairs | d |
| `smt.rs:842` | `longest_common_prefix_for_pairs` | `first[len]` | `len < first.len()` loop guard | d |
| `smt.rs:853` | `longest_common_prefix_for_pairs` | `first[..len]` | loop leaves `len <= first.len()` | d |
| `smt.rs:858` | `common_nibble_prefix_len` | `a[index]`, `b[index]` | both lengths are checked in the loop condition | d |
| `smt.rs:865` | `starts_with_nibbles` | `key[..prefix.len()]` | `key.len() >= prefix.len()` guard | d |
| `smt.rs:887` | `pack_nibbles` | `chunk[0]` | `chunks(2)` never yields an empty chunk | d |

## Changes

`persistent.rs` and `smt.rs` now use slice/iterator access with explicit invariant failure messages: `get`, `first`, `get(..range)`, slice-pattern destructuring, and explicit `match` handling replace every denied index, slice, or `expect`. No fallback value is introduced, and no `StateError` is swallowed. The public tree behavior and hash inputs are unchanged.

The added test `smt::tests::p3_golden_roots_and_proof_bytes_are_stable` covers the five requested deterministic cases. Its proof digest is SHA-256 of a test-local canonical byte sequence consisting of proof key, value-presence/value, sibling count as big-endian `u32`, and sibling hashes.

## Golden vectors and differential comparison

The pre-edit vectors were produced by a helper outside the repository using the committed pre-edit tree at `65833603`, and the post-edit vectors were produced by the same helper against the working tree. The command was `CARGO_TARGET_DIR=... cargo run --quiet --manifest-path /tmp/state_fix_p3_harness/Cargo.toml`; raw outputs were saved in `/tmp/state_fix_p3_before_vectors.log`, `/tmp/state_fix_p3_bench_before.log`, and `/tmp/state_fix_p3_bench_after.log`.

| case | pre-edit root | post-edit root |
|---|---|---|
| empty | `aee65339a08b06fbd1665922de21c2d317f62b6cdccde6a3734a3e76adcbf85d` | identical |
| one leaf | `4a3b7eeee9681c532ca0e5ca63b3585305fa01c0cbcd633756d86290fff99bbb` | identical |
| two colliding-prefix leaves | `0ce4559c1b8d6d89df0c9dc1cf156a055ace5fa6559bed9394f2be50b9a8e2a4` | identical |
| 1,000 fixed-seed pseudo-random leaves | `695f52706fe2a51746f330f5e3d33201cb77d88cee2983352deee79b5d6010f1` | identical |
| insert/delete/update sequence | `d68a447318b2b7dbc8262a07dba08692a52dbb8dae6fcbf2d3bd87034009e9c8` | identical |
| sampled proof-byte digest | `b5a8b2f4a91b9e63a251b86239faa359844755b37797818bddedd0676c7acf4e` | identical |

## Performance

The helper timed one 10,000-leaf insertion loop per implementation. Before/after values are exact command output, in milliseconds:

| loop | before | after | change |
|---|---:|---:|---:|
| `SparseMerkleTree` | 44,522 | 44,821 | +0.67% |
| `CompressedAuthTree` | 639 | 656 | +2.66% |
| `PersistentAuthTree` | 677 | 694 | +2.51% |

No measured path slowed by more than 5%.

## Verification

All commands below ran from `/Users/bonkai/Desktop/indra/project_indra/indra`.

| command | result | raw log |
|---|---|---|
| `cargo clippy -p indra-state --lib --no-deps --message-format=short` | PASS with 0 denied findings; 23 pre-existing non-denied warnings | `/tmp/state_fix_p3_clippy_after1.log` |
| `cargo clippy -p indra-state --all-targets --no-deps --message-format=short` | PASS with 0 errors; 42 warning lines. Test-only warnings: 34 in the lib-test target, 1 in `tests/monetary_invariants.rs`, and 3 in `tests/state_machine.rs`; the lib-test count includes 23 duplicated library warnings | `/tmp/state_fix_p3_clippy_all_targets.log` |
| `cargo check --workspace` | PASS, no warning lines | `/tmp/state_fix_p3_workspace_check.log` |
| `cargo audit` | PASS, exit 0 | `/tmp/state_fix_p3_cargo_audit_final.log` |
| `cargo deny check` | PASS, exit 0; `advisories ok, bans ok, licenses ok, sources ok` | `/tmp/state_fix_p3_cargo_deny_final.log` |
| `cargo test --workspace` | PASS; 1,642 passed / 0 failed / 10 ignored | `/tmp/state_fix_p3_workspace_debug.log` |
| `cargo test --workspace --release` | PASS; 1,642 passed / 0 failed / 10 ignored | `/tmp/state_fix_p3_workspace_release.log` |

Per-crate totals, debug and release identical:

| crate | passed | failed | ignored |
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
| **total** | **1,642** | **0** | **10** |

`indra-state` increased from 376 to 377 passed tests because the new golden-vector test is included. The node library remained 344 passed / 0 failed / 5 ignored.

## Files and cleanup

The final `git diff --stat` for tracked files was:

```text
indra/indra-state/src/persistent.rs |  97 ++++++++++++++------
indra/indra-state/src/smt.rs        | 171 +++++++++++++++++++++++++++++++-----
2 files changed, 222 insertions(+), 46 deletions(-)
```

The only tracked source files changed by this task are `indra-state/src/persistent.rs` and `indra-state/src/smt.rs`; the report itself is new and untracked. The temporary harness, target directories, and detached worktree created for the pre-edit comparison were removed. No commit, stage, restore, checkout, or stash was performed.

Final `df -h .`:

```text
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   189Gi    11Gi    95%    2.0M  117M    2%   /System/Volumes/Data
```
