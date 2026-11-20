The NET_11 root cause was the authenticated peer rate limiter escalating non-consensus volume violations into score penalties, a persisted 600-second identity ban, and a disconnect; node 2 then rejected every reconnect from node 1 while node 1 retried on its five-second dial interval. The apparent 601-second heal was the end of that rate-limit ban, not a half-open TCP timer or consensus recovery timer.
Unfinished: the long owner-only pause-threshold matrix and 900-second proof run were not run locally; the required STOP300 smoke passed, all automated regression/check commands passed, and the owner commands are provided for the longer runs.

## Evidence

The preserved owner log `/tmp/o-pause900` contains the decisive sequence:

- Continuation: `t_cont=1795174786207` from `timeline.log`.
- Node 2 applied the rate-limit ban to node 1: `/tmp/o-pause900/node-2.stderr:813`, `peer 1b2f5f7f (127.0.0.1:55447) banned 10min for sustained rate limit violations`.
- Node 2 disconnected that inbound connection at `t=1795174786341ms` (`:836`), 134 ms after continuation.
- Node 2 then logged repeated `rejected actively banned validator 1b2f5f7f` entries, while node 1 logged authenticated outbound connections to `127.0.0.1:32720` followed immediately by `reason=read error`.
- The first stable inbound reconnection on node 2 was `t=1795175386695ms`, an elapsed 600.488 seconds from `t_cont`; both neighbours were reported connected at `1795175387560`, 601.353 seconds after continuation. This matches the 600-second ban plus scheduling/connection overhead. It was not ban expiry inferred indirectly: the ban line and its immediate disconnect are explicit.

Node 2 continued round advancement and dial attempts while the identity was rejected; there were no evidence lines showing a second independent half-open-peer timer, a per-IP authenticated-cap rejection, or a handshake semaphore exhaustion. The old bare `rejected actively banned validator` line also explains why the remote node mostly observed `read error`: the responder dropped the authenticated stream before an application-level rejection reason was surfaced to the initiator.

## Code path

Before NET_11, `indra-network/src/peer_manager.rs:519-556` treated rate-limit violations for non-protocol-necessary classes as score penalties. `BAN_DURATION_RATE_LIMIT` at `indra-network/src/peer.rs:45` was 600 seconds; after the score reached zero, the code persisted the validator identity in `BanStore`, emitted the 10-minute ban message, and dropped the peer with `PeerDisconnectReason::Ban`. `peer_manager.rs:1125-1133` rejected later inbound handshakes by identity. The global large-payload limiter at the old `:1090-1095` also applied a score decrement with the same 600-second duration.

The limiter itself is keyed by authenticated validator in `limiters_by_validator`; its token buckets are per message class plus a per-peer byte bucket. The strike counter supplies escalating diagnostic penalties, but it is no longer connected to peer score or ban state. This preserves bounded work and drops excess traffic without locking an active validator out of its neighbours.

The other >=300-second values inspected were not the cause: the 600-second consensus relay dedup TTL, dandelion state/epoch TTLs, and node admission-seen TTL are bounded caches, not connection bans; the 60-second ban cleanup and 60-second post-auth cooldown retention cannot explain a 600-second rejection window. The NET_10 identity-ban dialer protection remains for provable invalid-consensus bans, but rate-limit drops never enter that path.

## Fix

- Removed `BAN_DURATION_RATE_LIMIT` entirely.
- All authenticated rate-limit violations now emit timestamped `rate_limit_drop` logs, drop the excess message, and retain the connection and score. This applies equally to consensus-adjacent, transaction, staking, governance, status, request, and byte-limit violations.
- Global large-payload drops no longer alter peer score.
- Active inbound identity-ban rejections now use the explicit timestamped label `banned_inbound_rejected`; rate-limit bans can no longer generate that label because the rate limiter no longer creates bans.
- Added `scripts/pause_threshold.sh`, which runs the requested 300/420/540/660/780-second threshold matrix in independent directories and preserves failed runs.

No wire format or handshake bytes changed. No new liveness mechanism was added because the saved evidence identifies a concrete 600-second rate-limit ban and no independent stale-peer defect; authenticated reconnect is now allowed immediately after a volume drop.

## Tests and verification

- New mutation-proof test: `peer_manager::tests::authenticated_validator_non_consensus_rate_limit_flood_is_not_banned`. It exhausts a non-consensus limiter 32 times and asserts score, ban state, and connected peer status are unchanged.
- `cargo test -p indra-network --lib`: 169 passed, 1 ignored.
- `cargo check -p indra-node -p indra-network`: passed.
- `bash -n scripts/pause_threshold.sh scripts/line_restart_repeat.sh scripts/line_restart_live.sh scripts/line_topology_live.sh`: passed.
- `cargo clippy --workspace --all-targets --no-deps -- -D warnings`: passed in debug and release.
- `scripts/check_no_lint_allows.sh`: passed.
- `cargo test -p indra-core --test lint_guard`: 2 passed.
- `cargo audit`: passed with no advisory findings.
- `cargo deny check`: passed advisories, bans, licenses, and sources; existing duplicate-package warnings remain.
- `cargo test --workspace --release --no-fail-fast`: passed on the final rerun, including `indra-ffi`; the node target reported 360 passed/5 ignored, and no target failed.
- Golden/replay/vector coverage passed in the release workspace suite; no golden/vector files were changed.

## Owner commands

Run live commands alone, with no build or test process running:

```bash
cd /Users/bonkai/Desktop/indra/project_indra/indra
export NODE_BIN="$PWD/target/release/node" GENESIS_BIN="$PWD/target/release/indra-genesis" KEYGEN_BIN="$PWD/target/release/indra-keygen"
STOP_SECONDS=900 TARGET_HEIGHT=8 CAP_SECONDS=2400 STOP_NODE_INDEX=1 EXPECT_PEER_COUNTS='1,2,2,1' scripts/line_topology_live.sh /tmp/net11-pause900
scripts/pause_threshold.sh /tmp/net11-pause-threshold
RUNS=6 DOWN_SECONDS=120 TARGET_HEIGHT=10 CAP_SECONDS=1800 STOP_NODE_INDEX=1 EXPECT_PEER_COUNTS='1,2,2,1' scripts/line_restart_repeat.sh /tmp/net11-restart-repeat
TARGET_HEIGHT=10 CAP_SECONDS=900 EXPECT_PEER_COUNTS='1,2,2,1' scripts/line_topology_live.sh /tmp/net11-quiet10m
```

The local STOP300 release smoke `/tmp/net11-stop300` passed with `recovery_seconds=13.390`, `post-resume connection events=0`, `same_tip=1`, `panics=0`, and `stale_sync=0`. It also emitted timestamped `rate_limit_drop` lines during the resume burst and retained the connection, demonstrating the new non-punitive behavior. The successful run directory was retained; no failed run directory was deleted.

## Intentional NET_11 files

- `indra-network/src/peer.rs`
- `indra-network/src/peer_manager.rs`
- `scripts/pause_threshold.sh`
- this report
