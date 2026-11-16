# Node Bin 5 lock inventory

## Production rows

| file:line | function / site | production/test | helper used | on poison |
|---|---|---|---|---|
| `indra-node/src/locks.rs:20-52` | `lock`, `read`, `write`, `wait_timeout` | production helper | the centralized lock helpers | report to supervisor first; return `NodeError::LockPoisoned` |
| `indra-node/src/bin/node.rs:195,205,225` | `RpcSemaphore::{acquire_until, Drop}` | production | `indra_node::locks::{lock,wait_timeout}` | request fails closed; `Drop` calls `terminate_fatal` |
| `indra-node/src/bin/node.rs:620,629,648,720,739,755,878,894,1027-1055,1065,1070` | network bridge state and relay/dedup helpers | production | `locks::lock` | caller returns `NodeResult` or rejects the event; helper reports first |
| `indra-node/src/bin/node.rs:1227-1239,1272,1283,1299` | handshake configuration and network-runtime startup | production | `locks::{read,write,lock}` and supervised macros | task returns/fails closed after one report |
| `indra-node/src/bin/node.rs:2004,2008,2150,2167,2219,2231` | observer/driver bridge paths | production | `locks::{lock,read}` and supervised macros | task ends or returns the typed error |
| `indra-node/src/bin/node.rs:2638,2757,4005,4024,4109,4136,4151,4164-4177,4209,4219,4282,4381,4400,4408,4446` | startup, status, discovery, consensus and action processing | production | `locks::{lock,read}` | `run`/task returns `NodeError`; no fallback value |
| `indra-node/src/bin/node.rs:4864,4937` | RPC per-IP connection admission/cleanup | production | `indra_node::locks::lock` | connection is rejected/cleanup fails closed; helper reports first |
| `indra-node/src/bin/node.rs:5566,5679,5900,5975` | diagnostics, RPC semaphore, relay cache, driver RPC helper | production | `locks::lock` | internal RPC error/handler return; no stale or empty fallback |
| `indra-node/src/bin/observer.rs:291,423,445,455` | observer block import, local status and height | production | `indra_node::locks::lock` | observer request returns an error |
| `indra-node/src/hardened_read_rpc.rs:114,121,144` | `Semaphore::acquire` and `Permit::drop` | production | `crate::locks::{lock,wait_timeout}` | request fails closed; `Drop` calls `terminate_fatal` |
| `indra-node/src/hardened_read_rpc.rs:170,264,304` | observer engine and per-IP connection state | production | `crate::locks::lock` | startup/connection path returns or rejects after reporting |
| `indra-node/src/qc_verification.rs:88-89` | `NetworkQcVerifier::take_worker_handle` | production | `locks::lock` | returns `NodeResult::Err`; poisoned slot cannot mean `None` |
| `indra-node/src/rpc_snapshot.rs:294-346` | `RpcSnapshotPublisher::{load,publish,publish_with_effects}` | production | `locks::{read,write}` | returns `NodeResult`; readers do not receive a stale/empty snapshot |
| `indra-node/src/metrics.rs:148-168,219-263,518-522` | metrics registration, totals, panic recording and rendering | production | `locks::lock` | typed node/metrics errors propagate; no telemetry fallback |

The `node.rs` line list above is the complete production-region `rg` result for `locks::{lock,read,write,wait_timeout}`; direct `.lock/.read/.write` calls in production are absent from the guard-tested regions. Test-only direct locks are intentionally retained for constructing poisoned primitives and assertions.

## Guard

`locks::tests::production_lock_inventory_has_no_direct_lock_calls` scans the production portions of `bin/node.rs`, `bin/observer.rs`, `metrics.rs`, `hardened_read_rpc.rs`, `qc_verification.rs`, and `rpc_snapshot.rs`. It rejects the specified `.ok`, `.map`, `.unwrap_or`, and direct lock-call patterns. It is a source-text guard: macros, aliases, generated code, and locks in other crates are blind spots.
