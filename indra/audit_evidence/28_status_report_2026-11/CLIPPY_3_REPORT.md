UNFINISHED / UNPROVEN: Clippy 3 is incomplete. State, node sync/metrics, and test-helper refactors were applied and compiled; the public `produce_vote` API and the remaining node-binary helpers were not refactored. The strict Clippy gate therefore still fails on `indra-consensus/src/vote.rs:283`.

# Clippy 3

## Initial conditions

Verified just now from `/Users/bonkai/Desktop/indra/project_indra/indra`: `df -h .` reports 18Gi available, so the requested 3Gi stop threshold was not reached. The initial command was `cargo clippy --workspace --all-targets --no-deps --message-format=short`; it completed successfully and reported only the requested `too_many_arguments` and `type_complexity` sites.

## Refactor plan recorded before editing

The source changes below are intended to preserve evaluation order, lock scopes, borrowing, wire/state encodings, and public behavior. No lint allowance or lint downgrade is planned.

| File and current site | Current issue | Planned semantic grouping |
|---|---|---|
| `indra-state/src/apply.rs:577` | `apply_slash_common` has nine parameters | slash accounting context containing chain/height/reporter/output/crypto mode |
| `indra-state/src/delegation.rs:707` | `apply_register_validator` has ten parameters | validator registration input |
| `indra-state/src/governance_apply.rs:150` | `apply_propose` has ten parameters | proposal payload/context |
| `indra-state/src/validator.rs:540` | `validate_cold_key_material` has eight parameters | cold-key validation input |
| `indra-consensus/src/vote.rs:283` | `produce_vote` has eight parameters and is public | public vote-production context; all callers must be updated |
| `indra-node/src/metrics.rs:267` | `start_metrics_server` has eight parameters | metrics server context, retaining `Arc` handles |
| `indra-node/src/sync.rs:283` | `SyncState::observe_status` has nine parameters | peer status observation value |
| `indra-node/src/sync.rs:1405` | test `build_qc_bytes` has eight parameters | test QC input |
| `indra-node/src/engine.rs:2413` | test `signed_slash_evidence` has nine parameters | test slash-evidence input |
| `indra-node/src/bin/node.rs:1005` | `record_peer_connected_event` has fifteen parameters | peer connection event/context |
| `indra-node/src/bin/node.rs:1093` | `insert_on_chain_validator_network_addrs` has eight parameters | network-address insertion context |
| `indra-node/src/bin/node.rs:1249` | `start_network_runtime` has thirteen parameters | network runtime context, retaining `Arc` handles |
| `indra-node/src/bin/node.rs:4221` | `process_driver_actions` has eight parameters | driver-action processing context |
| `indra-node/src/bin/node.rs:4793` | `spawn_rpc_listener` has fifteen parameters | RPC listener context, retaining `Arc` handles |
| `indra-node/src/bin/node.rs:5309` | `handle_rpc` has twenty-two parameters | RPC request context, retaining references/`Arc`s |
| `indra-state/tests/state_machine.rs:209` | test `make_tx` has eight parameters | transaction fixture input |
| `indra-state/src/chain.rs:1782` | complex decoder return tuple | named return alias preserving codec types |
| `indra-state/src/persistent.rs:474` | complex root tuple | named root-pair alias preserving types |
| `indra-state/src/persistent.rs:771` | complex `remove_min` tuple | named removal-result alias preserving types |
| `indra-state/src/smt.rs:460` | complex child grouping map value | named child-hash pair alias |
| `indra-node/src/bin/node.rs:1263` | complex runtime return tuple | named runtime-result alias preserving handles |
| `indra-ffi/src/handles.rs:605` | complex test hook type | named private checkpoint-hook alias; no ABI/header change |

## Verification status

Not run yet: post-edit Clippy, checks, tests, audit, deny, release workspace, golden/replay tests, and final disk-space check.

## Changes applied

Verified just now by source inspection and compilation: the following changes were made with no `#[allow]` or lint downgrade: named aliases for retired-cold decode output, persistent-tree root/removal outputs, compressed-tree child hashes, and the FFI checkpoint hook; semantic input structs for slash application, validator registration, cold-key validation, and governance proposal application; `PeerStatusObservation` for sync status; `MetricsServerConfig` for the metrics listener; and `TxFixture`/`QcFixture` for state and node test helpers. Call sites for the changed sync, metrics, state-test, and QC-test APIs were updated. The changed source files are under `indra-state/src/`, `indra-node/src/`, and `indra-ffi/src/handles.rs`.

## Unfinished sites

Verified just now from `cargo clippy --workspace --all-targets --no-deps -- -D warnings`: the command fails at:

```text
error: this function has too many arguments (8/7)
   --> indra-consensus/src/vote.rs:283:1
283 | / pub fn produce_vote(
...
292 | | ) -> ConsensusResult<VoteV1> {
```

The remaining node-binary sites were not reached by that fail-fast invocation; the earlier non-deny Clippy run reported `too_many_arguments` at `indra-node/src/bin/node.rs:1005,1093,1249,4221,4793,5309` and `type_complexity` at `indra-node/src/bin/node.rs:1263`. These remain unfinished. `indra-node/src/engine.rs:2413` also remains a test helper with `too_many_arguments`, and `indra-consensus/src/vote.rs:283` is a public API whose all-workspace callers would need coordinated updates.

## Verification run after the partial refactor

Verified just now from `/Users/bonkai/Desktop/indra/project_indra/indra`:

- `df -h .`: 18Gi available before edits; the requested 3Gi stop threshold was not reached.
- `cargo check --workspace --all-targets`: PASS, exit 0.
- `cargo test -p indra-state -p indra-consensus --lib`: PASS — indra-consensus 63 passed, 0 failed, 0 ignored; indra-state 342 passed, 0 failed, 3 ignored.
- `cargo test --release -p indra-state -p indra-consensus --lib`: PASS — indra-consensus 63 passed, 0 failed, 0 ignored; indra-state 342 passed, 0 failed, 3 ignored.
- `cargo check --release -p indra-node --all-targets`: PASS, exit 0.
- `cargo clippy --workspace --all-targets --no-deps -- -D warnings`: FAIL at the residual `produce_vote` site above.

Not run: the requested full release workspace test, feature-specific Clippy variants, `cargo audit`, `cargo deny check`, the node golden/replay tests, and the final grouped diff/stat requested for a completed pass. They should not be represented as verified by this report.

## Final disk check

Verified just now by a final `df -h .`: 17Gi available, still above the 3Gi stop threshold.
