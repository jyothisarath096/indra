# NET_1 report

Root cause: the node dialer and peer-list admission treated any already-connected IP as occupied, so four authenticated validators sharing `127.0.0.1` suppressed valid peers on different ports. This left the mesh dependent on startup ordering and caused partial topologies that could stall consensus; the fix removes IP-only suppression while retaining exact self-address and authenticated-validator identity checks.

Unfinished: the full workspace clippy/audit/deny and 1,672+ release-test sweep were not run in this task; targeted network/node verification and the requested 10-start stability measurements were run.

## Implementation

- Removed `has_connected_ip` and `has_connected_ip_from_socket_addrs` from validator dialing and discovery admission in `indra-node/src/bin/node.rs`.
- A candidate is still rejected when it is the configured local endpoint, when its authenticated validator identity is already connected, or when it is the exact already-connected endpoint.
- Added `distinct_authenticated_peers_on_one_ip_are_not_filtered`; the test was run before the fix and failed, then passed after the fix.
- Added [`scripts/mesh_stability.sh`](/Users/bonkai/Desktop/indra/project_indra/indra/scripts/mesh_stability.sh), with fresh four-validator genesis/key material, explicit full-mesh bootstrap, 60-second starts, peer-gate results, and failed-start topology capture.
- Updated [`scripts/live_compare.sh`](/Users/bonkai/Desktop/indra/project_indra/indra/scripts/live_compare.sh) to document and preserve retry-free S1/S2 gates; only the ordinary comparison runs retain the Index 7 startup retry policy.

## Root-cause reconstruction

The authenticated peer manager already has a deterministic duplicate rule keyed by validator IDs and connection direction. On duplicate registration it keeps the connection initiated by the lexicographically smaller validator ID, and stale disconnect events are ignored when their address is no longer current; both sides therefore converge on the same socket. The missing mesh edges were not caused by that rule.

The node dialer runs continuously every five seconds, but before this fix its eligibility filter called `has_connected_ip`, which returned true for any connection from the same IP. The peer-list filter had the same IP-only rule. The authenticated handshake provides validator IDs, and the existing `connected_validator_ids` check is the correct duplicate identity guard; IP address is not a validator identity.

The saved `/tmp/index7-full/new-s1/` logs have no timestamps, so event order below is file order. The observed sequence was:

1. Node 0 authenticated connections to nodes 1, 2, and 3.
2. Node 1 authenticated an inbound ephemeral connection from node 0, then authenticated node 3 and node 2. A duplicate node-0 attempt was dropped by the deterministic tie-break.
3. Node 3 authenticated node 0 and node 2-side/ephemeral connections, then replaced one duplicate with the node-1 configured endpoint; the old ephemeral connection emitted a disconnect.
4. Node 2 authenticated only two peers in its final view.

The final effective topology was missing the node-2 ↔ node-3 edge; node 3 also reported only two peers. The disconnect events were duplicate-connection reconciliation events, not evidence that the missing edge had ever been healthy. The underlying cause was that each node stopped considering same-IP candidates after its first localhost connection, so node-2/node-3 was never reliably dialed.

## Vote and block propagation

Votes are not restricted to one direct hop. The peer manager validates inbound vote signatures, deduplicates them, and relays eligible votes to authenticated relay targets; blocks use the corresponding relay path with stricter conflict checks. Local broadcasts also enqueue to all currently connected peers. Therefore a partial mesh can still reach quorum when the authenticated relay overlay connects the relevant validators, but an isolated validator or a disconnected cut cannot contribute its vote; this task does not change consensus or vote propagation.

## Stability measurements

The exact requested 10-start totals were run as two 5-start invocations per binary, with `WAIT_SECONDS=60`, no startup retry, and isolated port ranges:

| binary | starts | pass | fail |
|---|---:|---:|---:|
| fixed HEAD | 10 | 10 | 0 |
| old `fc1d3e02` | 10 | 6 | 4 |

Fixed runs:

- `/tmp/net1-new-5-fixed/summary.md`: 5/5
- `/tmp/net1-new-5-fixed-b/summary.md`: 5/5

Old runs:

- `/tmp/net1-old-5/summary.md`: 2/5
- `/tmp/net1-old-5-b/summary.md`: 4/5

The old failures show nodes with one or two peers while other nodes had three, matching the pre-fix partial-mesh signature. The fixed runs reached three peers on every node without a retry. A one-start fixed smoke run also passed at `/tmp/net1-smoke2/summary.md`.

## Verification

- `df -h .` before work: 10 GiB available, 95% capacity.
- Pre-fix regression test: `cargo test --release -p indra-node --bin node distinct_authenticated_peers_on_one_ip_are_not_filtered -- --nocapture` failed at the new assertion.
- Post-fix regression test passed.
- `cargo test -p indra-network --lib -- --nocapture`: 158 passed, 1 ignored.
- `cargo build --release -p indra-node --bin node`: passed.
- `bash -n scripts/live_compare.sh scripts/mesh_stability.sh`: passed.
- `git diff --check`: passed.

The Index 7 exact smoke’s S1/S2 results remain valid: S1 recovered to a common tip and S2 synchronized the late node. The updated live comparison scenarios use one peer gate and fail immediately on a gate failure; no retry was added to hide S1/S2 failures.

## Owner commands

Full new-binary comparison:

```sh
OLD_NODE_BIN=/tmp/index7-old-target/release/node \
NEW_NODE_BIN=/Users/bonkai/Desktop/indra/project_indra/indra/target/release/node \
OLD_GENESIS_BIN=/tmp/index7-old-target/release/indra-genesis \
NEW_GENESIS_BIN=/Users/bonkai/Desktop/indra/project_indra/indra/target/release/indra-genesis \
OLD_KEYGEN_BIN=/tmp/index7-old-target/release/indra-keygen \
NEW_KEYGEN_BIN=/Users/bonkai/Desktop/indra/project_indra/indra/target/release/indra-keygen \
RUNS=3 scripts/live_compare.sh /tmp/net1-live-compare
```

Twenty-start stability run:

```sh
NODE_BIN=/Users/bonkai/Desktop/indra/project_indra/indra/target/release/node \
GENESIS_BIN=/Users/bonkai/Desktop/indra/project_indra/indra/target/release/indra-genesis \
KEYGEN_BIN=/Users/bonkai/Desktop/indra/project_indra/indra/target/release/indra-keygen \
RUNS=20 WAIT_SECONDS=60 scripts/mesh_stability.sh /tmp/net1-stability-20
```

Final `df -h .`: 10 GiB available, 96% capacity.
