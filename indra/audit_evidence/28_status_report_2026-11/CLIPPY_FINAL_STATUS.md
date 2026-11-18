# Clippy final status

All rows below refer to the Index 4 tree at commit `f9602ed7f1e68bc1c3d7762bfea4d25285d30569` plus the current unstaged Index 4 edits. The required commands `cargo clippy --workspace --all-targets --no-deps -- -D warnings`, its release equivalent, and the all-features equivalent exited 0 with no warning diagnostics. Test-only indexing is exempt through the existing `cfg_attr(test, allow(...))` form; production roots deny the canonical list.

| Crate | Denied lint set at crate root | Target types checked | `clippy -D warnings` result | Production panic/unwrap/expect/indexing/unreachable/todo findings | Date/commit |
|---|---|---|---|---|---|
| `indra-core` | `unused_must_use`, `missing_docs`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unreachable`, `todo`, `unimplemented` (`indra-core/src/lib.rs:15-30`) | lib, integration tests | pass | 0 under required gate | 2026-11-17 / `f627eea` |
| `indra-crypto` | `missing_docs`, `unused_must_use`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unreachable`, `todo`, `unimplemented` (`indra-crypto/src/lib.rs:3-18`) | lib, integration tests | pass | 0 under required gate | 2026-11-18 / `f9602ed` |
| `indra-keystore` | `unused_must_use`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unreachable`, `todo`, `unimplemented` (`indra-keystore/src/lib.rs:7-22`) | lib | pass | 0 under required gate | 2026-11-18 / `f9602ed` |
| `indra-state` | `unused_must_use`, `missing_docs`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unreachable`, `todo`, `unimplemented` (`indra-state/src/lib.rs:33-51`) | lib, integration tests | pass | 0 under required gate | 2026-11-17 / `f627eea` |
| `indra-storage` | `unused_must_use`, `missing_docs`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unreachable`, `todo`, `unimplemented` (`indra-storage/src/lib.rs:41-59`) | lib | pass | 0 under required gate | 2026-11-18 / `f9602ed` |
| `indra-network` | `unused_must_use`, `missing_docs`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unreachable`, `todo`, `unimplemented` (`indra-network/src/lib.rs:43-61`, test-exempt via `cfg_attr`) | lib, integration tests | pass | 0 under required gate | 2026-11-18 / `f9602ed` |
| `indra-consensus` | `unused_must_use`, `missing_docs`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unreachable`, `todo`, `unimplemented` (`indra-consensus/src/lib.rs:42-59`) | lib, integration tests | pass | 0 under required gate | 2026-11-17 / `f627eea` |
| `indra-rpc` | `unused_must_use`, `missing_docs`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unreachable`, `todo`, `unimplemented` (`indra-rpc/src/lib.rs:44-62`, test-exempt via `cfg_attr`) | lib, integration tests | pass | 0 under required gate | 2026-11-18 / `f9602ed` |
| `indra-node` library | `unused_must_use`, `missing_docs`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unreachable`, `todo`, `unimplemented` (`indra-node/src/lib.rs:26-43`) | lib, integration tests | pass | 0 under required gate | 2026-11-18 / `f9602ed` |
| `indra-node` binaries | `unused_must_use`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unreachable`, `todo`, `unimplemented` (for example `indra-node/src/bin/node.rs:1-12`) | `node`, `observer`, `audit_block_log`, `dns_seed_sign`, `indra-sync-recover` bins; bin tests | pass | 0 under required gate | 2026-11-18 / `f9602ed` |
| `indra-cli` library | `unused_must_use`, `missing_docs`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unreachable`, `todo`, `unimplemented` (`indra-cli/src/lib.rs:32-51`) | lib, integration tests | pass | 0 under required gate | 2026-11-18 / `f9602ed` |
| `indra-cli` binaries | `unused_must_use`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unreachable`, `todo`, `unimplemented` (`indra-cli/src/bin/genesis.rs:1-3`, same policy in other CLI bins) | genesis, governance, keygen, send, stake, tx, wallet-scan bins; bin tests | pass | 0 under required gate | 2026-11-18 / `f9602ed` |
| `indra-ffi` | `unused_must_use`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unreachable`, `todo`, `unimplemented` (`indra-ffi/src/lib.rs:14-29`) | lib | pass | 0 under required gate | 2026-11-18 / `f9602ed` |
| `indra-bench` | `unused_must_use`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unreachable`, `todo`, `unimplemented` (`indra-bench/src/lib.rs:69-84`; benchmark target `benches/full_bench.rs:4-7`) | lib and bench target | pass | 0 under required gate | 2026-11-18 / `f9602ed` |

The canonical policy is checked by `scripts/check_lint_policy.sh`, and `indra-core/tests/lint_guard.rs` runs it. A planted removal of the `todo` deny from `indra-bench/benches/full_bench.rs` produced a non-zero result naming that file and lint; the line was restored and the guard then passed.

## Release workspace totals

`cargo test --workspace --release` after the final edit: 48 result lines, 1,650 passed, 0 failed, 10 ignored. Raw log: `/tmp/clippy3c_final_workspace_release.log`.

