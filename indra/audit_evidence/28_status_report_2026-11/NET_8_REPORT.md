Root cause: the dialer treated `TARGET_OUTBOUND_PEERS = 8` as a mandatory target even when a small topology had only one or two eligible peer addresses, so healthy line nodes repeatedly redialed already-connected neighbours every five seconds and triggered tie-break/read/write churn. The 900-second pause exposed the same loop after resume; it was not caused by a stale handshake timestamp, an idle transport timeout, or a wire-format change.
The fix bounds the outbound target to the number of eligible candidates, while retaining the target of eight for larger meshes; successful authenticated connections still reset bounded backoff, and duplicate tie-breaking remains deterministic.
Measured before/after: owner NET_7 evidence was recovery 625.352 s with post-resume events 0/389/7/0 after a 900 s SIGSTOP, while the fixed release run after a 300 s SIGSTOP recovered in 11.995 s with events 0/0/0/0; the fixed quiet run recorded 0/0/0/0 after mesh formation, versus the old harness's 3/2/4/3.
Unfinished: none for NET_8; the owner-only 900 s pause and 900 s process-down runs are provided below as exact commands and were not repeated locally.

# NET_8 implementation report

## Evidence reconstruction

The preserved owner logs remain untouched at `/tmp/net7-pause900` and `/tmp/net7-quiet`.

For `/tmp/net7-pause900`, `t_cont=1795123272568`, `paused_node_both_neighbours_ms=1795123879264`, and the final summary reports `recovery_seconds=625.352`, `rounds_reached_during_pause=186`, and peer counts 1/2/2/1. Node 1's first 60-second histogram after continuation was:

```text
second:events
0:1 5:2 10:2 15:2 20:3 25:2 30:3 35:2 40:2 45:2 50:2 55:2 60:4
```

The first 60 seconds were almost entirely node-1 outbound attempts to node 2 at the fixed five-second dial interval. Each attempt authenticated and then immediately disconnected with `read error`; occasional inbound ephemeral connections ended with `read error` or `write error`, and the first event at continuation on node 2 was a `ban`. Over the full 389 node-1 events, the reason counts were `read error=187`, `write error=11`, and `duplicate connection dropped by tie-break=2`; node 2 recorded `read error=1`, `write error=1`, `duplicate connection dropped by tie-break=1`, and `ban=1` in the same interval. The repeated event cadence, fixed five-second spacing, and unchanged peer counts identify reconnect churn rather than a progressing handshake-freshness failure.

Before the pause, node 1 was behind at height 2 while nodes 0 and 2 had advanced to height 3; the paused node resumed into a long round sequence and reached round 105 at height 3 before sync/round-jump progress moved it to height 6 and then height 7. The 625 seconds therefore consisted of the paused node being absent, neighbours advancing rounds, repeated reconnect/tie-break attempts, and eventual catch-up/QC recovery—not 625 seconds of a transport idle timeout. The 300-second fixed run reached the first block after continuation in 11.995 s and reached a common tip at height 8; 60 rounds advanced during the pause.

The quiet owner run's 3/2/4/3 events were startup topology formation: initial outbound/inbound authentications plus one duplicate tie-break and its resulting disconnect. They were not post-formation flaps. The old harness incorrectly used `t_cont=0` when there was no pause, thereby counting startup events; it now records `mesh_formed_ms` when all expected peer counts first appear and counts quiet events only after that reference.

## Code-path findings and fix

- Handshake freshness was not involved. `indra-network/src/handshake.rs` wraps both initiator and responder handshakes in the configured full-handshake timeout; the handshake carries the chain/genesis identity and fresh ephemeral key material, not a pause-sensitive wall-clock freshness field.
- Read-side disconnects are emitted by the authenticated peer reader when `FrameReader::read_frame` fails. Writer failures and queue-full protection are separate paths. NET_8 adds `PeerDisconnectReason` to the event/log path so evidence distinguishes remote close, read/write error, timeout, duplicate tie-break, ban, and operator disconnect without changing wire bytes.
- Duplicate replacement remains deterministic in `PeerManager::register_peer`; stale disconnects are ignored when the validator's current address has already been replaced. The existing bounded `CooldownTracker` doubles from a two-second minimum to a capped 60-second maximum and is reset on successful authentication; it does not grow with elapsed offline time. Inbound post-auth cooldowns remain keyed by validator identity plus IP and are reset on a successful inbound connection.
- The actual loop was in `indra-node/src/bin/node.rs`: the dialer computed its deficit against eight even when the filtered candidate set contained only the one or two line neighbours. The new `desired_outbound_peer_target` computes `min(TARGET_OUTBOUND_PEERS, candidates.len())` after eligibility filtering. A line node now stops dialing once every eligible line address is covered; a larger mesh still uses the normal target eight.

No handshake or application wire bytes changed. Existing tie-break, stale-disconnect, cooldown-cap, handshake, replay, golden-vector, and serialization coverage remained green.

## Tests and live proof

- Debug new regression: `cargo test -p indra-node --bin node outbound_target_is_bounded_by_eligible_candidates` — 1 passed.
- Debug network suite: `cargo test -p indra-network --lib --no-default-features` — 168 passed, 1 ignored. Focused stale-disconnect and deterministic tie-break tests passed.
- Quiet release run, target height 20, expected peers 1/2/2/1: all nodes converged, zero post-mesh events on every node.
- Restart smoke, `DOWN_SECONDS=120`: SIGKILL node 1, restart with the same data directory; recovery 35.359 s, peer counts 1/2/2/1, events 1/2/1/0, identical tips, exits 0, no panics, no stale sync responses.
- Fixed release pause, `STOP_SECONDS=300`: recovery 11.995 s, events 0/0/0/0, 60 rounds during pause, identical tips, exits 0, peer counts 1/2/2/1, no panics, no stale sync responses.
- `cargo clippy --workspace --all-targets --no-deps -- -D warnings` — pass.
- Release clippy with the same flags and `--release` — pass.
- `scripts/check_no_lint_allows.sh` — pass.
- `cargo test -p indra-core --test lint_guard` — 2 passed.
- `cargo test --workspace --release --no-fail-fast` — pass; key totals include indra-core 154, indra-network 168 plus 1 ignored, indra-node library 359 plus 5 ignored, node binary 100, and all integration/doc tests passed.
- `cargo audit` — advisories clear; `cargo deny check` — bans, licenses, and sources clear. Existing duplicate-dependency warnings remain.
- `bash -n scripts/line_topology_live.sh scripts/line_restart_live.sh scripts/line_lag_live.sh scripts/line_skew_live.sh` and `git diff --check` — pass.

## Owner commands

```bash
STOP_SECONDS=900 TARGET_HEIGHT=8 CAP_SECONDS=2400 STOP_NODE_INDEX=1 \
EXPECT_PEER_COUNTS=1,2,2,1 NODE_BIN="$PWD/target/release/node" \
GENESIS_BIN="$PWD/target/release/indra-genesis" KEYGEN_BIN="$PWD/target/release/indra-keygen" \
scripts/line_topology_live.sh /tmp/net8-pause900
```

```bash
DOWN_SECONDS=900 TARGET_HEIGHT=10 CAP_SECONDS=1800 STOP_NODE_INDEX=1 \
EXPECT_PEER_COUNTS=1,2,2,1 NODE_BIN="$PWD/target/release/node" \
GENESIS_BIN="$PWD/target/release/indra-genesis" KEYGEN_BIN="$PWD/target/release/indra-keygen" \
scripts/line_restart_live.sh /tmp/net8-restart900
```

```bash
TARGET_HEIGHT=20 CAP_SECONDS=900 EXPECT_PEER_COUNTS=1,2,2,1 \
NODE_BIN="$PWD/target/release/node" GENESIS_BIN="$PWD/target/release/indra-genesis" \
KEYGEN_BIN="$PWD/target/release/indra-keygen" \
scripts/line_topology_live.sh /tmp/net8-quiet10m
```

## Changed areas

- `indra-node`: bounded candidate-aware outbound target, regression test, timestamped connection evidence, and restart/live-harness integration.
- `indra-network`: structured disconnect reasons and propagation through reader, writer, ban, operator, and tie-break paths.
- `scripts`: corrected quiet-run event reference, mesh-formed timeline, restart harness, and pause/recovery reporting.

Temporary NET_8 run directories removed after verification: `/tmp/indra-net8-quiet-20261120`, `/tmp/indra-net8-restart120-20261120`, `/tmp/indra-net8-pause300-20261120`, and `/tmp/indra-net8-pause300-fixed-20261120`. Preserved owner evidence `/tmp/net7-pause900` and `/tmp/net7-quiet` was not deleted.
