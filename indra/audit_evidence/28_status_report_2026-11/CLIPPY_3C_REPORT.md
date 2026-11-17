# Clippy 3C report

## Initial refactor plan (written before source edits)

The working directory is `/Users/bonkai/Desktop/indra/project_indra/indra`. The initial disk check was `df -h .`; it reported 16 GiB available. The two target functions and their call sites were inspected before editing.

| Function | Current parameter | Type/category | Call sites before refactor |
|---|---|---|---|
| `spawn_rpc_listener` | `label` | `&'static str`; listener identity/logging | full listener at `indra-node/src/bin/node.rs:4111`; public listener at `:4145` |
| `spawn_rpc_listener` | `rpc_addr` | `String`; bind address | same two startup call sites |
| `spawn_rpc_listener` | `mode` | `indra_rpc::handlers::RpcMode`; full/read-only policy | same two startup call sites |
| `spawn_rpc_listener` | `policy` | `RpcListenerPolicy`; request/rate limits | same two startup call sites |
| `spawn_rpc_listener` | `driver` | `Arc<Mutex<ConsensusDriver>>`; mutable consensus state | same two startup call sites and forwarded to each handler thread |
| `spawn_rpc_listener` | `rpc_snapshot` | `RpcSnapshotPublisher`; immutable published state | same two startup call sites |
| `spawn_rpc_listener` | `rpc_storage` | `RpcStorageReadHandles`; block/epoch reads | same two startup call sites |
| `spawn_rpc_listener` | `gossip` | `Arc<NetworkBridge>`; peer/relay/network actions | same two startup call sites |
| `spawn_rpc_listener` | `discovered_peers` | `Arc<Mutex<HashSet<String>>>`; peer discovery state | same two startup call sites |
| `spawn_rpc_listener` | `op_relay_seen` | `Arc<Mutex<InboundDedupCaches>>`; relay dedup state | same two startup call sites |
| `spawn_rpc_listener` | `observer_count` | `Arc<AtomicUsize>`; observer metric/state | same two startup call sites |
| `spawn_rpc_listener` | `cors_origins` | `Vec<String>`; response headers | same two startup call sites |
| `spawn_rpc_listener` | `admin_token` | `Option<String>`; admin authorization secret | full listener call site only; `None` public listener |
| `spawn_rpc_listener` | `access_token` | `Option<String>`; full-RPC authorization secret | full listener call site only; `None` public listener |
| `spawn_rpc_listener` | `metrics` | `Arc<MetricsState>`; request/limit/lock telemetry | same two startup call sites |
| `handle_rpc` | `stream` | `TcpStream`; request and response bytes | handler thread in `spawn_rpc_listener`; direct read-only test at `node.rs:7949` |
| `handle_rpc` | `driver` | `&Arc<Mutex<ConsensusDriver>>`; diagnostics and writes | forwarded from listener and direct test |
| `handle_rpc` | `rpc_snapshot` | `&RpcSnapshotPublisher`; read snapshot | forwarded from listener and direct test |
| `handle_rpc` | `rpc_storage` | `&RpcStorageReadHandles`; historical block/epoch reads | forwarded from listener and direct test |
| `handle_rpc` | `gossip` | `&Arc<NetworkBridge>`; peers and transaction/op relay | forwarded from listener and direct test |
| `handle_rpc` | `discovered_peers` | `&Arc<Mutex<HashSet<String>>>`; discovered peer count | forwarded from listener and direct test |
| `handle_rpc` | `op_relay_seen` | `&Arc<Mutex<InboundDedupCaches>>`; transaction/op dedup | forwarded from listener and direct test |
| `handle_rpc` | `observer_count` | `&Arc<AtomicUsize>`; observer count | forwarded from listener and direct test |
| `handle_rpc` | `peer_ip` | `Option<IpAddr>`; per-IP limits | forwarded from listener and direct test |
| `handle_rpc` | `rate_limiter` | `&RpcRateLimiter`; per-IP request limiter | forwarded from listener and direct test |
| `handle_rpc` | `global_rate_limiter` | `Option<&RpcGlobalRateLimiter>`; global request limiter | forwarded from listener and direct test |
| `handle_rpc` | `expensive_limiter` | `&RpcWindowRateLimiter`; expensive per-IP window | forwarded from listener and direct test |
| `handle_rpc` | `expensive_global_limiter` | `&RpcGlobalWindowRateLimiter`; expensive global window | forwarded from listener and direct test |
| `handle_rpc` | `expensive_semaphore` | `&RpcSemaphore`; expensive concurrency bound | forwarded from listener and direct test |
| `handle_rpc` | `rejection_counters` | `&RpcRejectionCounters`; rejection telemetry | forwarded from listener and direct test |
| `handle_rpc` | `cors_origins` | `&[String]`; response CORS policy | forwarded from listener and direct test |
| `handle_rpc` | `rpc_mode` | `RpcMode`; full/read-only access | forwarded from listener and direct test |
| `handle_rpc` | `policy` | `&RpcListenerPolicy`; request/body/deadline policy | forwarded from listener and direct test |
| `handle_rpc` | `configured_admin_token` | `Option<&str>`; admin authorization | forwarded from listener and direct test |
| `handle_rpc` | `configured_access_token` | `Option<&str>`; full-RPC authorization | forwarded from listener and direct test |
| `handle_rpc` | `metrics` | `&MetricsState`; request/response/lock telemetry | forwarded from listener and direct test |
| `handle_rpc` | `limiter_telemetry` | `&RpcLimiterTelemetry`; limiter map telemetry | forwarded from listener and direct test |

### `handle_rpc` dispatch inventory

The handler first performs HTTP parsing, listener authorization, request/global/per-IP/expensive limits, and snapshot acquisition. Its `dispatch_with_admin` result has three write variants (`SubmitStakingOp`, `SubmitGovernanceOp`, `SubmitTransaction`) and a ready response. The RPC methods and actual parameter use are implemented in `indra-rpc/src/handlers.rs`: parameter-free state methods use `&NodeState`; parameterized methods consume `params` plus `&NodeState`; write methods consume `params` and return encoded bytes for node-side submission. The current methods are: height, tip, chain info, mempool size, block, canonical blocks, transaction, scan challenge, authorized provenance explanation, UTXO proof, peers, staking nonce, stake positions, stake position, unbonding tranches, unbonding tranche, validator stake positions, owner stake positions, delegator rewards, delegator identity debug, staking summary, consensus snapshots, epoch info/record/history/latest, proposals/proposal/proposal votes, governance params/nonce, validator rewards, validator/self-stake/auto-delegate/set, peer topology, sync diagnostics, RPC policy, and the three submission methods.

## Work log and source change

`spawn_rpc_listener` now accepts `RpcListenerConfig` and `RpcListenerState` at `indra-node/src/bin/node.rs:4926-4929`; the two production call sites construct those categories at `:4111-4137` and `:4149-4169`. `handle_rpc` now accepts `RpcHandlerNode`, `RpcHandlerLimits`, and `RpcHandlerAuth` at `:5494-5499`, with the same lock-bearing `Arc` handles and limiters. The public-light dispatcher's former allowance was also removed: `RpcPublicLightContext` is at `:5337-5345` and `dispatch_public_light_method` takes it at `:5347-5350`. No consensus code, RPC wire format, error code, limiter behavior, or lock order was changed.

The RPC dispatch arms remain in `indra-rpc/src/handlers.rs:568-610`. Parameter-free arms use `&NodeState`; state-query arms use `params` and `&NodeState`; staking/governance/transaction submission arms use `params` and return the existing `DispatchResult` byte payloads. The node-side arms retain their existing snapshot, lock, decode, relay, and metric paths.

## Focused proof runs

All commands below were run from `/Users/bonkai/Desktop/indra/project_indra/indra` after the final edit.

| Command | Result | Log |
|---|---|---|
| `cargo check --workspace --all-targets` | exit 0; `Finished dev profile` with no warnings | `/tmp/clippy3c_final_check.log` |
| `cargo test -p indra-node --bin node` | 93 passed, 0 failed, 0 ignored | `/tmp/clippy3c_final_node_bin.log` |
| `cargo test -p indra-node --test node_bin` | 7 passed, 0 failed, 0 ignored | `/tmp/clippy3c_node_bin_integration.log` and the final workspace-release log |
| `cargo test -p indra-node --test node` | 17 passed, 0 failed, 0 ignored | `/tmp/clippy3c_node_integration.log` and the final workspace-release log |
| `cargo test -p indra-rpc` | 69 unit passed, 0 failed; 35 integration passed, 0 failed; 1 doctest passed, 0 failed | `/tmp/clippy3c_final_rpc.log` |

The required proof-test names are present in the committed test code: handler panic isolation is `full_rpc_handler_panic_is_counted_and_next_handler_runs` at `indra-node/src/bin/node.rs:6345`; the per-IP limit is `rpc_per_ip_connection_cap_rejects_fifth_connection` at `:7943`; semaphore acquire/release is `expensive_semaphore_is_bounded_per_listener` at `:8124`; driver-lock ordering is checked by `rpc_write_paths_have_one_authoritative_driver_lock_each` at `:7961`; read-only write admission is checked by `read_only_handle_rejects_transaction_before_authoritative_submission` at `:7995`; dispatch coverage is `test_all_methods_reachable_via_dispatch` at `indra-rpc/tests/rpc.rs:400`; request parsing/dispatch is `rpc_full_request_parse_and_dispatch` at `:113`; malformed transaction bytes are covered by `generic_rpc_rejects_transaction_with_trailing_bytes` at `indra-rpc/src/server.rs:698`; and the status/read path is covered by `rpc_get_height` at `indra-rpc/tests/rpc.rs:43` and `call_rpc_get_height` at `indra-rpc/src/server.rs:678`. No RPC match arm lacked a method-level test, so no new response-vector test was added. No existing test directly forces the exceptional `internal relay state unavailable` branch at `indra-node/src/bin/node.rs:6083-6094`; that is an untested error branch, not an untested RPC method arm.

## Old-commit parity check

The old binary was built from detached worktree `e1fc28ef` under `/tmp` with `CARGO_TARGET_DIR` outside the repository; the worktree and target were removed afterwards. The first attempted copy of the repository target was stopped when the required disk guard reached 2.8 GiB free; the exact temporary copy was removed and the final build was completed in a fresh temporary target. The old and current release binaries had different SHA-256 values, as expected for different source commits. `diff -u /tmp/clippy3c_old_help.txt /tmp/clippy3c_new_help.txt` and `diff -u /tmp/clippy3c_old_version.txt /tmp/clippy3c_new_version.txt` produced no output (empty diffs). Build log: `/tmp/clippy3c_old_build_parity.log`.

## Clippy and policy gates

These exact commands all exited 0 with no warning diagnostics:

```text
cargo clippy --workspace --all-targets --no-deps -- -D warnings
cargo clippy --workspace --all-targets --release --no-deps -- -D warnings
cargo clippy -p indra-node --all-targets --features test-support --no-deps -- -D warnings
cargo clippy --workspace --all-targets --all-features --no-deps -- -D warnings
```

Logs are `/tmp/clippy3c_gate_debug.log`, `/tmp/clippy3c_gate_release.log`, `/tmp/clippy3c_gate_node_testsupport.log`, and `/tmp/clippy3c_gate_allfeatures.log`. `test-support` was run for `indra-node`; `--all-features` was run for the workspace packages that expose features (`indra-core`, `indra-state`, `indra-consensus`, and `indra-node`).

`cargo test --workspace --release` was rerun after the last source edit. Its raw log is `/tmp/clippy3c_final_workspace_release.log`. The exact aggregate extracted from its `test result` lines is `targets=48 passed=1650 failed=0 ignored=10`. The node library line is `344 passed; 0 failed; 5 ignored`; node binary `93/0/0`; node integration `17/0/0`; node-bin integration `7/0/0`; RPC library `69/0/0`; RPC integration `35/0/0`; RPC doctest `1/0/0`. The full per-target raw result lines are in that log.

`cargo audit` reported no advisory findings; raw log `/tmp/clippy3c_audit.log`. `cargo deny check` ended with `advisories ok, bans ok, licenses ok, sources ok`; raw log `/tmp/clippy3c_deny.log`. It also reported duplicate-package warnings already present in the lockfile; this refactor did not change `Cargo.lock`.

### Required gate tail output

```text
$ cargo clippy --workspace --all-targets --no-deps -- -D warnings
    Checking indra-rpc v0.1.0
    Checking indra-consensus v0.1.0
    Checking indra-storage v0.1.0
    Checking indra-node v0.1.0
    Checking indra-cli v0.1.0
    Checking indra-bench v0.1.0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 14.56s

$ cargo clippy --workspace --all-targets --release --no-deps -- -D warnings
    Checking indra-rpc v0.1.0
    Checking indra-storage v0.1.0
    Checking indra-node v0.1.0
    Checking indra-cli v0.1.0
    Checking indra-bench v0.1.0
    Finished `release` profile [optimized] target(s) in 4.24s

$ cargo clippy -p indra-node --all-targets --features test-support --no-deps -- -D warnings
    Checking indra-storage v0.1.0
    Checking indra-consensus v0.1.0
    Checking indra-rpc v0.1.0
    Checking indra-node v0.1.0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 5.58s

$ cargo clippy --workspace --all-targets --all-features --no-deps -- -D warnings
    Checking indra-node v0.1.0
    Checking indra-cli v0.1.0
    Checking indra-bench v0.1.0
    Checking indra-ffi v0.1.0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 8.18s

$ cargo check --workspace --all-targets
    Checking indra-node v0.1.0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.38s

$ cargo test --workspace --release
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
   Doc-tests indra_storage

$ cargo audit
    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
      Loaded 1527 security advisories (from /Users/bonkai/.cargo/advisory-db)
    Updating crates.io index
    Scanning Cargo.lock for vulnerabilities (282 crate dependencies)

$ cargo deny check
advisories ok, bans ok, licenses ok, sources ok
```

## Final disk check

The final `df -h .` was:

```text
Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   186Gi    15Gi    93%    2.0M  161M    1%   /System/Volumes/Data
```
