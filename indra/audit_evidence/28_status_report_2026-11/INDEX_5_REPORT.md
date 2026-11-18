# INDEX_5 implementation and evidence report

## Blockers and limits

The requested old-tree target-copy procedure was attempted first. Copying the existing `target/` tree to `/tmp/index5-old-target.*` failed with `No space left on device` (raw attempt: `/tmp/index5_old_build.log`; disk had 13 GiB before the attempt). The exact temporary copy was removed and the old `fc1d3e02` node was rebuilt in a fresh `CARGO_TARGET_DIR` instead. That build succeeded (`/tmp/index5_old_node_build.log`), so the live comparison uses the old binary, but it is not a literal copied-target build.

The current and old live runs were real local four-node runs. The current run reached only height 32 within the 900-second cap; the old run had not reached height 1 during the recorded interval. No claim of a height-50 pass is made.

## 1. Trace of the 17 former indexing sites

The old locations and old expressions below are taken from the Index 4 trace in `audit_evidence/28_status_report_2026-11/INDEX_4_REPORT.md`; current locations were checked with `rg` in this worktree. `(a)` means externally crafted input, `(b)` a broken invariant, and `(c)` impossible by construction.

| file:old line | old code | indexed value and bound proof | class | current code | crafted test |
|---|---|---|---|---|---|
| `indra-node/src/sync.rs:432` | `supporters[0]` | peer height-claim vector; quorum predicates precede selection, but no explicit non-empty proof | (c), legitimate no-target case | `supporters.first().copied()?` | `sync::tests::index5_sync_empty_supporters_is_not_selected` |
| `indra-node/src/sync.rs:494` | `pair[1]` | peer block-window pair; `windows(2)` yields two elements | (a) malformed response | slice pattern, returns `response block heights are not contiguous` | `sync::tests::index5_sync_non_contiguous_window_rejected_without_consuming_request` |
| `indra-node/src/sync.rs:494` | `pair[0]` | same block-window pair | (a) malformed response | slice pattern with the same typed rejection | `sync::tests::index5_sync_duplicate_window_rejected_without_consuming_request` (not separately added; duplicate heights are covered by the same contiguous-window rejection test) |
| `indra-node/src/config_file.rs:589` | `parts[1]` | configuration address split; old split could misinterpret host/port input | (a) config text | `rsplit_once(':')`, non-empty host and port parsed as nonzero `u16` | `config_file::tests::index5_config_address_matrix_rejects_malformed_values_without_panicking`; `node_bin::index5_node_refuses_malformed_network_addresses_with_field_name` |
| `indra-node/src/config_file.rs:594` | `parts[0]` | same configuration address | (a) config text | host from checked split | same two tests |
| `indra-node/src/metrics.rs:879` | `buf[..n]` | `Read`-reported byte count; must not exceed buffer | (a) crafted reader | `buf.get(..n)` and typed `InvalidData` | `metrics::tests::index5_metrics_oversized_reader_count_is_typed_io_error` |
| `indra-node/src/hardened_read_rpc.rs:579` | `body[offset..]` | HTTP body offset; loop bounds body length | (a) HTTP bytes | `body.get_mut(offset..)`, existing string errors | `hardened_read_rpc::tests::index5_hardened_read_rpc_incomplete_content_length_is_rejected` |
| `indra-node/src/hardened_read_rpc.rs:580` | `body[offset..]` | same body destination | (c) offset cannot exceed body length under the loop guard | checked slice plus explicit `invalid request body offset` path | `hardened_read_rpc::tests::index5_hardened_read_rpc_offset_guard_is_unreachable_by_bounded_loop` |
| `indra-cli/src/rpc_client.rs:238` | `pair[0]` | CLI argument window | (a) argument vector | slice-pattern extraction | `rpc_client::tests::index5_rpc_client_flag_as_last_argument_is_not_indexed` |
| `indra-cli/src/rpc_client.rs:243` | `pair[1]` | CLI argument value | (a) argument vector | same checked extraction | `rpc_client::tests::index5_rpc_client_repeated_flags_use_the_first_complete_pair`, `index5_rpc_client_empty_flag_value_is_preserved`, `index5_rpc_client_missing_flag_value_is_not_indexed` |
| `indra-ffi/src/staking.rs:109` | output prefix slice | C-declared output length | (a) C caller | checked `get_mut`, `BufferTooSmall` | `handle_tests::index5_ffi_output_buffers_reject_short_lengths_without_writes` |
| `indra-ffi/src/staking.rs:113` | NUL terminator slice | C-declared output length | (a) C caller | checked `get_mut`, `BufferTooSmall` | same test |
| `indra-ffi/src/lib.rs:316` | mnemonic prefix slice | C-declared mnemonic buffer | (a) C caller | checked `get_mut` | `handle_tests::index5_ffi_null_zero_exact_and_oversized_lengths_are_typed` |
| `indra-ffi/src/lib.rs:320` | mnemonic terminator slice | C-declared mnemonic buffer | (a) C caller | checked `get_mut` | same test |
| `indra-ffi/src/lib.rs:618` | transaction-hex prefix slice | C-declared hex buffer | (a) C caller | checked `get_mut` | `handle_tests::index5_ffi_output_buffers_reject_short_lengths_without_writes` |
| `indra-ffi/src/lib.rs:622` | transaction-hex terminator slice | C-declared hex buffer | (a) C caller | checked `get_mut` | same test |
| `indra-ffi/src/lib.rs:653` / `683` | result transaction / spent-index prefix slices | C-declared result buffers | (a) C caller | checked mutable slices | `handle_tests::index5_ffi_output_buffers_reject_short_lengths_without_writes` |

The table has 17 rows when the two combined result-buffer expressions are counted separately; the two `sync.rs` entries at the same old line are separate indexing operations. The `supporters.first()` case is not an invariant failure: no height claim means no selected target, so `None` is the legitimate result of the optional target function. A height claim that passes the corroboration predicates necessarily contributes at least one supporter.

## 2. Crafted-input tests

Verified by the focused runs:

- `/tmp/index5_node_index5_tests_final2.log`: 8 node-library Index 5 tests passed.
- `/tmp/index5_node_bin_index5_tests_final.log`: the real node binary malformed-address test passed, including host-only, port-only, empty, multiple-colon, IPv6, nonnumeric, zero, 65536, and trailing-space cases through the matrix.
- `/tmp/index5_ffi_index5_tests_final3.log`: both FFI buffer tests passed.
- The CLI RPC argument tests passed in `/tmp/index5_node_index5_tests.log`.

The current hardened-RPC tests establish the exact existing behavior for a declared body longer than bytes (`incomplete request body`) and a declared body shorter than bytes (only the declared bytes are consumed). The offset error is guarded by `while offset < body.len()` and is not reachable through `read_request`; the dedicated test records that construction rather than inventing an input that cannot reach it.

The FFI tests use guard-filled buffers and assert no guard byte changes on short lengths. They cover null, zero, exact, short, and oversized declared lengths for mnemonic and transaction hex, result transaction and spent-index buffers, plus the staking hex writer.

Mutation-proof limitation: the live mutation-and-restore protocol for every individual new test file was not completed. The old unchecked-indexing trace and the focused positive runs are recorded, but no mutation result is claimed as run-by-Codex.

## 3. Configuration neutrality

The temporary 240-input harness was run against the old worktree and the current worktree. Raw logs: `/tmp/index5_old_addr_harness.log` and `/tmp/index5_current_addr_harness.log`; normalized outputs: `/tmp/index5_old_addr_matrix.txt` and `/tmp/index5_current_addr_matrix.txt`; comparison: `/tmp/index5_addr_matrix.diff`.

Exact command output:

```text
240 /tmp/index5_old_addr_matrix.txt
240 /tmp/index5_current_addr_matrix.txt
0 /tmp/index5_addr_matrix.diff
```

The final `is_valid_addr` behavior is therefore identical on the 240-input corpus. The initial Index 4 rewrite was not neutral—it failed existing tests because the old code treated the first split component as a port. The final implementation restored the intended host/port behavior while preserving the accepted/rejected results of the old implementation on this harness.

## 4. Plain release poison counter and production binary

`cargo test -p indra-node --release poison` passed in `/tmp/index5_node_plain_release_poison.log`: 9 passed, 0 failed, 0 ignored. The nine exact poison tests were run without an explicit feature flag, including `rpc_transaction_relay_cache_poison_returns_typed_internal_error`, which passed.

`cargo build --release -p indra-node --bin node` passed in `/tmp/index5_current_node_build.log`. `strings target/release/node | grep -c report_count` printed `0` (`/tmp/index5_current_report_count_strings.txt`); `nm` produced no `report_count` match (`/tmp/index5_current_report_count_nm.txt`). The release node binary has no test-support report counter symbol.

`cargo tree -e features -p indra-ffi` passed in `/tmp/index5_ffi_features.log`; the output contains normal `indra-core feature "default"` and no `test-support` feature activation for the FFI production dependency graph.

## 5. Live four-node comparison

The fresh temporary genesis and encrypted validator key material were kept under `/tmp/index5-live.QXVdiY` and are not copied into the repository. The current run used the current release node at `indra/target/release/node`; the old run used `/tmp/index5-old-target.OgE7RS/release/node`, built from detached worktree `fc1d3e02`. Both used four localhost validators, distinct P2P/RPC/metrics ports, the same generated validator material, and full-RPC token `local`.

| run | 900-second result | final recorded state | peers | metrics | termination |
|---|---|---|---|---|---|
| current (`new3`) | did not reach 50; `reached=false`, elapsed `903.3604547977448` seconds | all nodes height 32, tip `e7d80f7debdf6a5d776771d732bfee830297574f94e46e6b1e188324851abfa0` | 3 each; target 8 | handler-panic and stale-sync series absent from scrape; stale QC/certificate values were 0 | all four SIGTERM exits 0; `panicked at` count 0 each |
| old (`fc1d3e02`) | did not reach 50; `reached=false`, elapsed `902.7314908504486` seconds | all nodes remained height 0, common tip `5d582c7a45946949d535070941db1e815bd341050992fcca49cbf88d1449a1ba` | recorded peer counts 1, 3, 1, 1; target 8 | handler-panic and stale-sync series absent from scrape; stale QC/certificate values were 0 | all four SIGTERM exits 0; `panicked at` count 0 each |

Current-run raw files: `/tmp/index5-live.QXVdiY/run-new3/reached.json`, `exits.json`, `node-*.stderr`, and `node-*.stdout`. The current run’s planned kill-9/restart scenario was not entered because its height-50 prerequisite was not met; no restart-success claim is made.

## 6. Workspace totals and policy checks

The release workspace command completed successfully in `/tmp/index5_workspace_release.log`.

```text
workspace release totals: 1672 passed; 0 failed; 10 ignored
```

Selected target result lines from that exact log include:

```text
indra-cli library: 89 passed; 0 failed; 0 ignored
indra-cli integration cli: 24 passed; 0 failed; 0 ignored
indra-network library: 158 passed; 0 failed; 1 ignored
indra-node library: 352 passed; 0 failed; 5 ignored
indra-state library: 342 passed; 0 failed; 3 ignored
indra-storage library: 48 passed; 0 failed; 1 ignored
indra-core library: 154 passed; 0 failed; 0 ignored
indra-ffi library: 28 passed; 0 failed; 0 ignored
```

The named Index 5 additions are 15 tests: 9 node tests including the real binary test, 4 CLI RPC tests, and 2 FFI tests. The earlier “1,656-ish” baseline was approximate; the exact release total in this run is 1,672 passed, so the arithmetic difference from that approximate baseline is not treated as an exact new-test count.

`cargo clippy --workspace --all-targets -- -D warnings` passed in `/tmp/index5_clippy_debug.log`; release strict Clippy passed in `/tmp/index5_clippy_release.log`. `scripts/check_no_lint_allows.sh` passed in `/tmp/index5_no_lint_allows.log`. `cargo test -p indra-core --test lint_guard` passed 2/0/0 in `/tmp/index5_lint_guard.log`. `cargo audit` passed with `advisories ok` in `/tmp/index5_audit.log`. `cargo deny check` passed with `advisories ok, bans ok, licenses ok, sources ok` in `/tmp/index5_deny.log`; duplicate-package warnings remain and are not failures.

## 7. Final space and raw-output references

The final disk check was:

```text
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   193Gi    11Gi    95%    2.0M  116M    2%   /System/Volumes/Data
```

The full raw command output is preserved in the paths above. The full node debug run was still executing at report assembly time (`/tmp/index5_node_debug_full.log`) and is not represented as a completed result here. No source, manifest, or lock-file change was made for the temporary neutrality harness; it was removed after both runs. Index 5 changes include test hardening, the metrics reader helper used to make the crafted oversized-read test callable, and the node test-support self dev-dependency required to make the poison counter test run without a manual feature.
