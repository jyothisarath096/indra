UNFINISHED / UNPROVEN: Part 2 is intentionally unfinished. spawn_rpc_listener and handle_rpc remain excluded as requested; strict Clippy reports only those two functions. All Part 1 grouped refactors and required verification runs completed.

# Clippy 3B report

All commands were run from /Users/bonkai/Desktop/indra/project_indra/indra. Existing working-tree changes were preserved. No commit, stage, restore, checkout, or stash operation was run.

## Initial disk check

Verified just now with df -h . before editing:

```
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   185Gi    16Gi    92%    2.0M  170M    1%   /System/Volumes/Data
```

## Changes

Group A changed `indra-consensus/src/vote.rs:283-301` to a public `VoteRequest<'a>` plus `produce_vote(request, keypair)`. All callers in vote.rs, producer.rs, qc.rs, consensus tests, node engine.rs, sync.rs, driver_tests.rs, and node tests were updated. The vote-safety ordering remains record-before-sign/broadcast; `audit_fixture_production_prevote_persists_vote_safety_record`, `audit_signing_boundary_rejects_future_round_before_persistence`, and `vote_safety_write_failure_prevents_vote_broadcast` passed.

Group B changed the test helper `indra-node/src/engine.rs:2414-2438` to use `SignedSlashEvidenceInput`; production engine APIs were unchanged.

Group C changed `indra-node/src/bin/node.rs:1026-1085` to use `PeerConnectionEvent` and `PeerConnectionState`, `:1103-1150` to use `OnChainAddressContext`, and `:4304-4475` to use `DriverActionContext`. Existing Arc handles, lock scopes/order, and supervised/fatal lock macros were preserved.

Group D changed `node.rs:1289-1328` to named `NetworkRuntimeConfig` and `NetworkRuntime`; startup destructuring is at `:2715-2742`.

## Verification

Run just now:

```
cargo check --workspace --all-targets
Finished dev profile [unoptimized + debuginfo] target(s) in 6.31s

cargo test -p indra-consensus --lib
test result: ok. 63 passed; 0 failed; 0 ignored

cargo test -p indra-node --lib driver::
test result: ok. 115 passed; 0 failed; 0 ignored; finished in 207.69s

cargo test -p indra-node --test node_bin --release
test result: ok. 7 passed; 0 failed; 0 ignored

cargo test -p indra-node --bin node --release
test result: ok. 93 passed; 0 failed; 0 ignored

cargo test -p indra-node --lib 'engine::'
test result: ok. 60 passed; 0 failed; 1 ignored; finished in 955.48s

cargo test -p indra-node --lib 'sync::'
test result: ok. 43 passed; 0 failed; 2 ignored

cargo test -p indra-node --lib 'metrics::'
test result: ok. 13 passed; 0 failed; 0 ignored

cargo test -p indra-node --lib 'supervisor::'
test result: ok. 8 passed; 0 failed; 0 ignored

cargo test -p indra-node --lib locks::tests::production_lock_inventory_has_no_direct_lock_calls
test result: ok. 1 passed; 0 failed; 0 ignored
```

The initial combined multi-filter command was rejected with `error: unexpected argument 'sync::' found`; the filters were then run separately.

Strict Clippy:

```
cargo clippy --workspace --all-targets --no-deps -- -D warnings
```

Only the explicitly excluded RPC functions remain:
`indra-node/src/bin/node.rs:4897 spawn_rpc_listener` (15/7 arguments) and `:5413 handle_rpc` (22/7 arguments). No Part 1 lint remains. No `#[allow]`, lint downgrade, fallback, or consensus-rule change was added.

`cargo audit` completed without advisory findings. `cargo deny check` completed with `advisories ok, bans ok, licenses ok, sources ok`; duplicate-package messages were warnings, not failures.

Release workspace output was captured at `/tmp/clippy3b_workspace_release.log`:

```
cargo test --workspace --release
per-target aggregate: 1650 passed; 0 failed; 10 ignored
```

Per-target release totals: indra-bench 19/0/0; indra-cli 85/0/0 library, 7/0/0 genesis, 9/0/0 governance, 1/0/0 keygen, 1/0/0 send, 9/0/0 stake, 2/0/0 tx, 3/0/0 wallet-scan, 24/0/0 integration; indra-consensus 63/0/0 and 5/0/0 integration; indra-core 154/0/0 and 21/0/0 serialisation; indra-crypto 38/0/0, 2/0/0 audit_phase1, 1/0/0 bench; indra-ffi 26/0/0; indra-keystore 22/0/0; indra-network 158/0/1 and 4/0/0 integration; indra-node 344/0/5 library, 93/0/0 node binary, 17/0/0 integration, 7/0/0 node_bin; indra-rpc 69/0/0 and 35/0/0 integration; indra-state 342/0/3, 4/0/0 audit_phase2, 10/0/0 monetary, 25/0/0 state_machine; indra-storage 48/0/1. Zero-test/doc targets passed.

Final disk check, verified just now with df -h .:

```
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   185Gi    16Gi    93%    2.0M  164M    1%   /System/Volumes/Data
```

## Limits

Part 2 remains intentionally open: only `spawn_rpc_listener` and `handle_rpc` still fail strict Clippy, and they were explicitly excluded. Existing unrelated worktree changes remain present; this report does not claim the complete worktree diff belongs to Clippy 3B.

