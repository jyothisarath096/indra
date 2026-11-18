# INDEX_1 report

## Incomplete work (first-line disclosure)

The ordered indexing pass is complete for `indra-crypto`, `indra-keystore`, and `indra-storage`. The requested measurements are complete for every listed crate. The network, RPC, node, CLI, and FFI diagnostics remain for the next task because this pass was scoped to measure/list those subsystems after fully fixing crypto and the two <=25-site-or-classify storage subsystems. The relay-cache test exercises the extracted production failure path and asserts the typed error; it does not instrument a supervisor counter.

## What changed

- `indra-crypto` now denies `clippy::indexing_slicing` for non-test production targets and no longer uses unchecked address/proof parsing ranges.
- `indra-keystore` and `indra-storage` replace their reported unchecked indexing with checked ranges, exact conversions, and iterator-based fixed-width handling.
- The node RPC transaction relay path now reports a poisoned relay cache through the supervisor and returns `internal relay state unavailable`; the tests are `rpc_token_wiring_keeps_admin_and_access_roles_distinct` and `rpc_transaction_relay_cache_poison_returns_typed_internal_error`.
- Removed unjustified module-level `missing_docs`, one `unused_mut`, and a dead audit-harness marker. Added `indra/scripts/check_no_lint_allows.sh`, which enforces the reviewed file list.

No consensus encoding, wire format, ABI, golden vector, or replay fixture was regenerated.

## Token-wiring evidence

The existing real-listener test `read_only_handle_rejects_transaction_before_authoritative_submission` proves that the public/read-only listener rejects a write before transaction decoding. The new `rpc_token_wiring_keeps_admin_and_access_roles_distinct` test exercises the same token-status and method-policy functions used by `handle_rpc`: distinct admin `admin-A` and access `access-B` values do not interchange; admin policy rejects an invalid admin status and accepts a valid one; read-only policy rejects `indra_sendTransaction`. The existing `indra-rpc/tests/rpc.rs` tests additionally cover correct, wrong, missing, and read-only admin-token cases through the RPC dispatch policy. The extracted `record_transaction_relay_seen` path is covered by `rpc_transaction_relay_cache_poison_returns_typed_internal_error`; the production branch calls `supervisor::report_unexpected` once before returning the typed error body.

## Commands and results

All commands were run from `/Users/bonkai/Desktop/indra/project_indra/indra`. The raw logs are outside the repository:

| command | result | log |
|---|---|---|
| `cargo check --workspace --all-targets` | PASS, no warnings | `/tmp/index1_final_workspace_check.log` |
| `cargo test -p indra-crypto --lib` | 40 passed, 0 failed, 0 ignored | `/tmp/index1_final_crypto_test.log` |
| `cargo test -p indra-keystore --lib` | 22 passed, 0 failed, 0 ignored | `/tmp/index1_final_keystore_test.log` |
| `cargo test -p indra-storage --lib` | 48 passed, 0 failed, 1 ignored | `/tmp/index1_final_storage_test.log` |
| `cargo test -p indra-node --bin node` | 95 passed, 0 failed, 0 ignored | `/tmp/index1_final_node_bin_test.log` |
| `cargo clippy --workspace --all-targets --no-deps -- -D warnings` | PASS | `/tmp/index1_clippy_debug_final.log` |
| `cargo clippy --workspace --all-targets --no-deps --release -- -D warnings` | PASS | `/tmp/index1_clippy_release_final.log` |
| `cargo audit` | `advisories ok` | `/tmp/index1_audit.log` |
| `cargo deny check` | `advisories ok, bans ok, licenses ok, sources ok` | `/tmp/index1_deny.log` |
| `cargo test --workspace --release` | PASS; 1,654 passed, 0 failed, 10 ignored | `/tmp/index1_final_workspace_release.log` |

The release per-target totals are recorded verbatim in the raw log. The aggregate was computed from every `test result:` line with:

```text
rg '^test result:' /tmp/index1_final_workspace_release.log | awk '{p+=$4; f+=$6; i+=$8} END {print "passed="p", failed="f", ignored="i}'
passed=1654, failed=0, ignored=10
```

The prohibited full debug workspace suite was not run.

## Disk guard

Initial command: `df -h .`; available space was 15 GiB. Final command: `df -h .`; available space was 14 GiB. No build output was deleted. Temporary logs remain under `/tmp` and were not copied into the repository.

## Limits

The remaining 21 network, 11 RPC, 7 node, 2 CLI, and 8 FFI indexing diagnostics are listed in `INDEX_1_INVENTORY.md` with their current diagnostic locations and highest-count files. They are not claimed fixed. The lint-allow guard is file-granular and does not prove semantic necessity of exceptions. The relay-cache test does not count supervisor reports; a future test should add an injectable reporter or an equivalent observable counter before claiming that exact count.

## Diff scope

The working tree already contained unrelated changes and many untracked audit reports. This task’s newly added files are this report, the inventory, and `indra/scripts/check_no_lint_allows.sh`; source edits are limited to the lint/parser and RPC files listed in the change summary. No staging or commit was performed.
