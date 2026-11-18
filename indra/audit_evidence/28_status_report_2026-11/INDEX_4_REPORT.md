# INDEX_4 report

Old-code external reachability: the old network/RPC indexing sites were reachable from peer bytes, RPC parameters, persistent ban-store bytes, and transport frames; the old node sites were reachable from sync responses, configuration strings, HTTP request bodies, and metrics reads; the old FFI sites were reachable from C caller lengths and pointers. The old CLI RPC-client sites were reachable from CLI argument vectors. These are the reasons the replacements use checked extraction or existing typed error returns.

Unfinished: a fresh four-node current-vs-`fc1d3e02` handshake run reaching 50 blocks was not completed in this task. No result is claimed for that live comparison. The release replay tests did complete. The report records all completed checks and this remaining live-infrastructure item explicitly.

## 1. Indexing fixes

The initial trace was produced by `cargo clippy -p <crate> --lib --bins --no-deps -- -D clippy::indexing_slicing`; raw initial logs are `/tmp/index4_indra-node_indexing.log`, `/tmp/index4_indra-cli_indexing.log`, and `/tmp/index4_indra-ffi_indexing.log`. The 17 requested sites were:

| Site | Old code and reachability | Current handling |
|---|---|---|
| `indra-node/src/sync.rs:432` | `supporters[0]`; peer-derived supporter vector, with a non-empty invariant only implied by earlier quorum checks | `supporters.first().copied()?`; empty is rejected from the optional corroborated target path. |
| `indra-node/src/sync.rs:494` | `pair[1]` and `pair[0]`; peer response block windows | slice-pattern destructuring, returning the existing non-contiguous response error if the window is malformed. |
| `indra-node/src/config_file.rs:589-594` | `parts[1]` and `parts[0]`; configuration address text | `rsplit_once`, explicit host/port validation. |
| `indra-node/src/metrics.rs:879` | `buf[..n]`; socket read count | checked `buf.get(..n)` with a typed `InvalidData` I/O error. |
| `indra-node/src/hardened_read_rpc.rs:579-582` | `body[offset..]`; HTTP body length and socket progress | checked `body.get_mut(offset..)`, returning the existing string error path. |
| `indra-cli/src/rpc_client.rs:238-243` | `pair[0]`/`pair[1]`; command-line flag/value pairs | slice-pattern `find_map`, so malformed windows do not panic. |
| `indra-ffi/src/staking.rs:109-114` | output prefix and NUL terminator; C caller output length | checked mutable slices, returning `BufferTooSmall`. |
| `indra-ffi/src/lib.rs:316-323` | mnemonic output prefix and terminator; C caller buffer length | checked mutable slices, returning `BufferTooSmall`. |
| `indra-ffi/src/lib.rs:618-625` | transaction-hex output prefix and terminator; C caller buffer length | checked mutable slices, returning `BufferTooSmall`. |
| `indra-ffi/src/lib.rs:653-658` | transaction result output prefix; C caller declared length | checked mutable slice, returning `BufferTooSmall`. |
| `indra-ffi/src/lib.rs:683-688` | spent-index result output prefix; C caller declared length | checked mutable slice, returning `BufferTooSmall`. |

The remaining FFI output-buffer sites were part of the same two functions and are represented by the two `get_mut` checks per NUL-terminated output. The new production paths do not default, skip, or write beyond the declared buffer. Existing tests cover the malformed classes: `sync::tests::response_binding_rejects_unsolicited_wrong_peer_and_out_of_range`, `hardened_read_rpc::tests::observer_progress_policy_rejects_slow_drip_after_grace`, `rpc_client::tests::response_cap_is_rejected`, `handle_tests::exact_length_utf8_input_never_scans_past_short_allocation`, `handle_tests::transaction_builder_rejects_oversized_address_before_dereferencing_slice`, and the FFI invalid-handle/null/buffer tests.

The new crate-root lint policy also exposed unchecked indexing in test-only network/RPC code once test exemptions were ordered correctly; those tests remain exempt under the existing `cfg_attr(test, allow(...))` convention. Production targets pass the deny gate.

## 2. Canonical lint policy

The canonical production list is `unused_must_use`, `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`, `clippy::indexing_slicing`, `clippy::unreachable`, `clippy::todo`, and `clippy::unimplemented`; `missing_docs` remains on crates that already require it. Every workspace library, binary, and benchmark target carries the list. `indra/indra-ffi/Cargo.toml` now gives its dev build `indra-core`'s `test-support` feature so FFI tests can use the test-only chain identifier without enabling it in release production dependencies.

`scripts/check_lint_policy.sh` scans workspace roots and is called by `indra-core/tests/lint_guard.rs::canonical_lint_policy_guard_passes`. A planted removal of the `clippy::todo` deny from `indra-bench/benches/full_bench.rs` produced exit 1 and these exact diagnostics in `/tmp/index4_lint_guard_planted.log`:

```text
missing canonical deny clippy::unreachable: .../indra-bench/benches/full_bench.rs
missing canonical deny clippy::todo: .../indra-bench/benches/full_bench.rs
missing canonical deny clippy::unimplemented: .../indra-bench/benches/full_bench.rs
```

The line was restored; the guard then passed with two tests in `/tmp/index4_lint_guard_test.log`. The refreshed root table is [CLIPPY_FINAL_STATUS.md](CLIPPY_FINAL_STATUS.md).

## 3. Test-only supervisor seam

`REPORT_COUNT` is now compiled only under `cfg(any(test, feature = "test-support"))` in `indra-node/src/supervisor.rs:14-15`; the increment in `report_unexpected` and `reset_report_count`/`report_count` are gated at `:143-166`. The node-bin poison-cache test uses the seam only when `test-support` is enabled, while the default node binary still compiles without it. `cargo build --release -p indra-node --bin node` passed in `/tmp/index4_node_release_build.log`; both `nm -gU target/release/node | grep -E 'report_count|reset_report_count'` and the corresponding `strings` check produced no matching output (`/tmp/index4_node_nm_report_count.log`, `/tmp/index4_node_strings_report_count.log`).

## 4. Replay tests

The release replay commands completed:

```text
test engine::tests::startup_fails_on_snapshot_replay_gap ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 348 filtered out; finished in 44.30s

test engine::tests::startup_from_snapshot_with_pruned_log ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 348 filtered out; finished in 43.97s
```

Raw logs: `/tmp/index4_replay_gap_release.log` and `/tmp/index4_pruned_replay_release.log`.

## 5. Verification

All commands below were run from `/Users/bonkai/Desktop/indra/project_indra/indra`.

| Check | Result | Log |
|---|---|---|
| `cargo check --workspace --all-targets` | PASS, finished in 15.82s | `/tmp/index4_workspace_check.log` |
| debug strict Clippy | PASS, exit 0 | `/tmp/index4_clippy_workspace_debug4.log` |
| release strict Clippy | PASS, exit 0 | `/tmp/index4_clippy_workspace_release.log` |
| all-features strict Clippy | PASS, exit 0 | `/tmp/index4_clippy_all_features.log` |
| lint suppression script | PASS, exit 0 | `/tmp/index4_lint_suppression_guard.log` plus policy guard `/tmp/index4_lint_guard_test_final.log` |
| node config tests | PASS, `26 passed; 0 failed; 0 ignored` | `/tmp/index4_node_config_tests_after.log` |
| node sync focused test | PASS, `1 passed; 0 failed; 0 ignored` | `/tmp/index4_node_sync_test.log` |
| node metrics tests | PASS, `13 passed; 0 failed; 0 ignored` | `/tmp/index4_node_metrics_tests.log` |
| hardened RPC tests | PASS, `6 passed; 0 failed; 0 ignored` | `/tmp/index4_node_rpc_tests.log` |
| CLI RPC-client tests | PASS, `8 passed; 0 failed; 0 ignored` | `/tmp/index4_cli_rpc_tests.log` |
| `cargo test -p indra-cli` | PASS; library `85 passed`, integration target `24 passed`, all other targets passed | `/tmp/index4_cli_debug.log` |
| `cargo test -p indra-ffi` | PASS, `26 passed; 0 failed; 0 ignored` | `/tmp/index4_ffi_debug_after.log` |
| `cargo test -p indra-bench` | PASS, `19 passed; 0 failed; 0 ignored` | `/tmp/index4_bench_debug.log` |
| node binary debug with `test-support` | PASS, `96 passed; 0 failed; 0 ignored` | `/tmp/index4_node_bin_debug.log` |
| default node binary test target compile | PASS | `/tmp/index4_node_bin_default_no_run_final.log` |
| `cargo test --workspace --release` | PASS; node library `344 passed; 0 failed; 5 ignored`; state library `342/0/3`; network library `158/0/1`; storage library `48/0/1`; all other targets passed | `/tmp/index4_workspace_release_final.log` |
| touched-crate release tests | PASS: CLI, FFI `26/0/0`, bench `19/0/0`, node binary `96/0/0` | `/tmp/index4_cli_release.log`, `/tmp/index4_ffi_release.log`, `/tmp/index4_bench_release.log`, `/tmp/index4_node_bin_release.log` |
| `cargo audit` | PASS, `advisories ok` | `/tmp/index4_audit.log` |
| `cargo deny check` | PASS, `advisories ok, bans ok, licenses ok, sources ok`; duplicate-package warnings remain | `/tmp/index4_deny.log` |
| `cargo test -p indra-node --lib golden_vector_values -- --nocapture` | PASS, `1 passed; 0 failed; 0 ignored` | `/tmp/index4_golden.log` |
| `cargo test -p indra-network --test network` | PASS, `4 passed; 0 failed; 0 ignored` | `/tmp/index4_network_vector.log` |

An earlier workspace release run at `/tmp/index4_workspace_release.log` was started before the final `is_valid_addr` correction and failed two existing config tests. The final run at `/tmp/index4_workspace_release_final.log` was run after that correction and passed all targets; the node library result was `344 passed; 0 failed; 5 ignored`.

## 6. Live handshake comparison

No fresh four-node current-vs-`fc1d3e02` run is claimed. The repository contains historical loopback run artifacts under `audit_evidence/28_status_report_2026-11/logs/`, but using them would not satisfy the requested fresh run. Consequently there is no honest current/old height, tip, blocks-per-minute, peer-count, exit-code, panic, or metrics summary for this Index 4 task. The existing historical run reports are not substituted for that evidence.

## 7. Diff and disk

Index 4 source changes are in `indra-node`, `indra-cli`, `indra-ffi`, `indra-bench`, the FFI dev-dependency configuration, the lint-policy script/test, and the refreshed Clippy report. No consensus rule, wire encoding, C ABI signature, golden vector, or storage format was intentionally changed.

Final `df -h .` output after the last build:

```text
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   191Gi    13Gi    94%    2.0M  138M    1%   /System/Volumes/Data
```
