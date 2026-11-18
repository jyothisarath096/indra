# INDEX_2 report

## Incomplete scope — read first

The network/RPC `indexing_slicing` pass, production-allow removal, lint guard, affected tests, release workspace tests, strict Clippy, audit, deny, and workspace check were completed. The detached `fc1d3e02` old/new neutrality harness was **not run**, so byte-neutrality and old/new malformed-error equivalence are not claimed. The requested real HTTP listener token test with `AdminToken`/`AccessToken` newtypes and the supervisor-report counting assertion were **not implemented**; the existing token-policy and typed relay-cache tests remain. Node, CLI, and FFI indexing diagnostics were measured but not fixed.

## Changes

- Added checked access throughout the network parsers and transport framing. Existing typed network errors remain the rejection path; no defaults or silent `continue` paths were introduced.
- Added checked RPC parameter access and propagated compressed-proof nibble encoding errors through the existing RPC internal-error response.
- Added non-test `clippy::indexing_slicing` denial to `indra-network` and `indra-rpc`.
- Removed production `too_many_arguments` suppressions by introducing typed input/context structs in authorization, block value hashing, consensus snapshot roots, observer RPC handling, RPC network policy construction, and staking confirmation.
- Removed dead-code suppressions in `indra-state`.
- Replaced the old file allowlist lint guard with a location-based guard and added `indra-core/tests/lint_guard.rs`.

## Token and relay status

The existing `rpc_token_wiring_keeps_admin_and_access_roles_distinct` test exercises the shared token/method policy helpers, and `read_only_handle_rejects_transaction_before_authoritative_submission` exercises the real read-only listener path. The requested new full HTTP listener test for distinct admin/access token newtypes was not added in this pass; the listener configuration still uses its existing representation. `rpc_transaction_relay_cache_poison_returns_typed_internal_error` covers the poisoned relay-state error path, but it does not count supervisor reports; the requested exactly-one counting assertion is therefore not claimed.

## Verification

All commands below ran from `/Users/bonkai/Desktop/indra/project_indra/indra`.

| command | result | log |
|---|---|---|
| `cargo check --workspace --all-targets` | PASS | command output in task session |
| `cargo test -p indra-core --lib` | 154 passed, 0 failed, 0 ignored | command output in task session |
| `cargo test -p indra-network --lib` | 158 passed, 0 failed, 1 ignored | command output in task session |
| `cargo test -p indra-rpc --lib` | 69 passed, 0 failed, 0 ignored | command output in task session |
| `cargo test -p indra-state --lib` | 342 passed, 0 failed, 3 ignored | `/tmp/index2_state_test.log` |
| `cargo test -p indra-node --bin node` | 95 passed, 0 failed, 0 ignored | `/tmp/index2_node_test.log` |
| `cargo clippy --workspace --all-targets --no-deps -- -D warnings` | PASS | `/tmp/index2_clippy_debug.log` |
| `cargo clippy --workspace --all-targets --no-deps --release -- -D warnings` | PASS | `/tmp/index2_clippy_release.log` |
| `cargo test --workspace --release` | 1,655 passed, 0 failed, 10 ignored | `/tmp/index2_workspace_release.log` |
| `cargo audit` | `advisories ok` | `/tmp/index2_audit.log` |
| `cargo deny check` | `advisories ok, bans ok, licenses ok, sources ok` | `/tmp/index2_deny.log` |
| `scripts/check_no_lint_allows.sh` | exit 0 | command output in task session |
| `cargo test -p indra-core --test lint_guard` | 1 passed, 0 failed | command output in task session |

The guard was also planted with a temporary production-source `#[allow(dead_code)]`; it exited 1 and reported `indra-core/src/index2_planted.rs:1`, then the temporary file was removed. The guard intentionally accepts the remaining test-only crate-root `cfg_attr` lines.

## Release per-target and neutrality limits

The release workspace aggregate was computed from every `test result:` line in `/tmp/index2_workspace_release.log`:

```text
passed=1655, failed=0, ignored=10
```

The extra passing test relative to the previous 1,654 aggregate is the new `indra-core` lint-guard integration test. The old/new detached-worktree comparisons requested in Part A are NOT RUN; no empty `diff` output is claimed and no golden/replay/vector output was regenerated.

## Final disk state

Final `df -h .` reported 17 GiB available. No generated build output or pre-existing audit artifact was deleted.

## Remaining work

1. Build the required detached `fc1d3e02` helper harness for payment-address, VRF, Shamir, manifest, snapshot, and vote-safety byte/error neutrality.
2. Replace the remaining listener token representation with distinct `AdminToken` and `AccessToken` types and add real ephemeral-port HTTP coverage for admin/access/public behavior.
3. Add an injectable/counting supervisor-report seam and assert exactly one relay-cache poison report.
4. Fix the remaining 7 node, 2 CLI, and 8 FFI production indexing diagnostics with crafted-input tests.
