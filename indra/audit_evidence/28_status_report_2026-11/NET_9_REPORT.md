NET_8's permanent partition was caused by applying the discovered-peer outbound target after filtering candidates and then subtracting the already-connected outbound count: a node with one remaining configured neighbour and one existing outbound neighbour computed target=1 and deficit=0. NET_9 fixes this by treating configured/bootstrap/genesis addresses as liveness obligations outside the discovered-peer target, while retaining the target budget for discovered peers only.
Unfinished: the 120-second restart harness reconnected node 1 to both configured neighbours, but consensus catch-up remained unresolved at height 3 after its 901-second cap; network reconnection and consensus catch-up are reported separately.

# NET_9 implementation report

## Scope and root-cause evidence

The NET_8 owner evidence shows the lost 1-2 edge explicitly:

- `/tmp/net8-pause900/node-1.stderr`: node 1 authenticated `127.0.0.1:32720` outbound at `1795149101335ms`, then disconnected it at `1795150042200ms` with reason `ban`.
- `/tmp/net8-pause900/node-2.stderr`: node 2 authenticated the corresponding inbound connection from node 1 at `1795149101335ms`, then disconnected it at `1795150041656ms` with reason `read error`.
- There is no subsequent dial attempt for `32720` in node 1's timestamped dialer output through the end of the 2400-second owner run. Node 1 retained only node 0 and node 2 retained only node 3, matching the permanent partition.

In the NET_8 code, candidates were assembled from `peer_sources` plus `discovered_peers`, then filtered for self, connected validator identity, and cooldown. The code computed `desired_outbound_peer_target(candidates.len())`, subtracted `network_bridge.connected_outbound_peer_count()`, and passed only the deficit to randomized selection. The count is outbound authenticated connections, so node 1's connection to node 0 consumed the only target slot even though node 2 was a configured address. Inbound connections do not satisfy the outbound count; duplicate authenticated connections are resolved by the existing validator/address tie-breaker.

## Implementation

Only `indra-node/src/bin/node.rs` was intentionally edited.

- Configured candidates are partitioned from discovered candidates before dialing. Every eligible configured candidate is selected independently of the discovered target.
- The discovered target remains `min(TARGET_OUTBOUND_PEERS, eligible_discovered_candidates)` and is reduced only by currently connected discovered outbound addresses. Configured outbound connections are counted separately from the authenticated outbound address set.
- Configured failures use `OutboundCooldownKey::Address`, so backoff is per configured address and never collapses distinct configured addresses through a learned validator identity. Successful authenticated connections reset both address and validator cooldown keys and clear failure counts.
- Completed outbound handshakes remember address-to-validator identity. Peer-list entries carrying a validator identity are remembered as well. The map is bounded at `MAX_DISCOVERED_PEERS` and learned entries are removed when the mapped validator disconnects; connected identities are skipped in either direction.
- Dial attempts carry monotonic timestamps and source labels. Connected-validator and backoff skip messages are rate-limited per address to 30 seconds.
- Existing duplicate tie-break and stale-disconnect paths were not changed.

## Tests

Added regression coverage for the configured-versus-discovered budget split and bounded authenticated address memory. The existing outbound target property remains true for discovered candidates.

- `cargo test -p indra-node --bin node`: 102 passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo clippy --release --workspace --all-targets -- -D warnings`: passed.
- `scripts/check_lint_policy.sh`, `scripts/check_no_lint_allows.sh`, `scripts/check_fuzz_builds.sh`, and `bash -n` for all shell scripts: passed.
- `cargo test --release --workspace --exclude indra-ffi`: passed; node library 359 passed/5 ignored, node binary 102 passed, node integration 17 passed, and all workspace crate suites/doc tests passed.
- `cargo deny check`: advisories, bans, licenses, and sources passed.
- `python3 scripts/check_consensus_build_policy.py`: failed its pre-existing Cargo.lock digest gate (“Cargo.lock changed”); `git diff` shows no Cargo.lock change and the dependency audit itself passed.
- Golden, replay, serialization, and vector suites passed in the release workspace run; no wire, handshake, or vector files changed.

## Live proof

Release STOP300 command:

```sh
NODE_BIN="$PWD/target/release/node" GENESIS_BIN="$PWD/target/release/indra-genesis" KEYGEN_BIN="$PWD/target/release/indra-keygen" STOP_SECONDS=300 CAP_SECONDS=900 TARGET_HEIGHT=10 STOP_NODE_INDEX=1 EXPECT_PEER_COUNTS='1,2,2,1' scripts/line_topology_live.sh /tmp/net9-stop300
```

Result: PASS; common tip/height reached, peer counts 1/2/2/1, zero post-resume connection events, zero panics, zero stale-sync alarms, 60 rounds during the pause, and `recovery_seconds=23.580`. The report's recovery value is the time from resume until the all-node tip check; the harness also reports `t_all_nodes_at_tip_ms` separately from `mesh_formed_ms`.

Restart command:

```sh
NODE_BIN="$PWD/target/release/node" GENESIS_BIN="$PWD/target/release/indra-genesis" KEYGEN_BIN="$PWD/target/release/indra-keygen" DOWN_SECONDS=120 CAP_SECONDS=900 TARGET_HEIGHT=10 STOP_NODE_INDEX=1 EXPECT_PEER_COUNTS='1,2,2,1' scripts/line_restart_live.sh /tmp/net9-restart120
```

The restart harness re-established node 1's two configured neighbours (`peer_count=2`) after the 120-second outage and ended with peer counts 1/2/2/1, zero panics, and zero stale-sync alarms. It failed the overall target because all nodes remained at height 3 after 901 seconds and consensus round churn; this is successful network reconnection evidence but not a successful consensus catch-up proof.

Owner long-run commands:

```sh
STOP_SECONDS=900 TARGET_HEIGHT=8 CAP_SECONDS=2400 STOP_NODE_INDEX=1 scripts/line_topology_live.sh /tmp/net9-pause900
DOWN_SECONDS=900 TARGET_HEIGHT=8 CAP_SECONDS=2400 STOP_NODE_INDEX=1 scripts/line_restart_live.sh /tmp/net9-restart900
TARGET_HEIGHT=10 CAP_SECONDS=900 EXPECT_PEER_COUNTS='1,2,2,1' scripts/line_topology_live.sh /tmp/net9-quiet10m
```

## NET_8 77-file commit audit

Part 0 was performed in detached worktree `/tmp/net9-format-audit`, based on `f9ee07cd~1`. Read-only `cargo fmt --all -- --check` was run first and reported 579 `Diff in` output lines. Formatting was then normalized only inside that detached audit worktree for comparison; the main worktree was never formatted during NET_9.

I found one known earlier workspace-wide formatter command during NET_8:

```sh
cargo fmt -- indra-node/src/bin/node.rs indra-network/src/net_types.rs indra-network/src/lib.rs indra-network/src/peer_manager.rs indra-node/src/driver.rs indra-node/src/bin/node.rs indra-node/src/driver_tests.rs
```

Cargo fmt ignored the intended file restriction and formatted the workspace. No earlier formatter command is known from the available history. Comparing the normalized detached parent with `f9ee07cd` found these non-format changes:

- `indra-node/src/bin/node.rs` — NET_8 semantic changes: bounded eligible outbound target helper, candidate filtering before target calculation, deficit-based randomized dialing, connected-validator skip behavior, and the corresponding regression test.
- `scripts/line_topology_live.sh` — NET_8 semantic harness changes: restart mode, node restart/start helper, mesh-formation and event-reference timing, and post-resume/live evidence reporting.
- `scripts/line_restart_live.sh` — new NET_8 restart harness wrapper, not a formatting-only change.
- `audit_evidence/28_status_report_2026-11/NET_8_REPORT.md` — new NET_8 report artifact, not a formatting-only change.

The remaining cli, consensus, core, state, storage, ffi, rpc, and unrelated node files in the 77-file commit were formatting-only according to the detached normalized comparison. Therefore the large portion of f9ee07cd was pure formatting, with the semantic changes confined to the NET_8 node/harness/report files listed above.

## Cleanup and final disk check

The detached `/tmp/net9-format-audit` worktree and `/tmp/net9-fmt-check.out` were removed after the audit. Owner evidence directories were preserved. The final `df -h .` check is recorded in the handoff message.
