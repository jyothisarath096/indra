Finding (1): NET_1 removed only IP-based validator dialing/discovery suppression, but the node still has a pre-auth inbound per-IP cap and total inbound cap; the peer manager had no post-auth distinction between non-validator and active-validator identities. Active validators are now exempt after authenticated membership in `relay_keys`, while non-validators are capped at three authenticated peers per IP and the global peer table remains capped at 80.

Finding (2): A single missing edge does not stall consensus in the in-process four-validator harness because authenticated vote/block relay over the remaining connected graph still supplies quorum. A two-component partition has no quorum by design, and the existing partition-heal harness shows nil rounds until the partition is healed, followed by convergent commit.

Unfinished: The owner-only 35-minute full debug `indra-node` library run was not repeated in this pass; the full workspace release run, debug network library run, focused node liveness tests, clippy, lint guard, audit, and deny checks all completed. Golden/replay/vector coverage was verified by repository inventory and the full workspace release test run, rather than by inventing a new NET_2-specific vector target.

# Codex NET_2 implementation report

## Scope and policy

NET_2 adds the missing authenticated per-IP admission policy and liveness evidence without changing consensus code or the wire protocol. The policy is deliberately identity-aware:

| Gate | Location | Limit / behavior | Applies before or after authentication |
|---|---|---|---|
| Inbound total | `indra-node/src/bin/node.rs:862-877` | `MAX_INBOUND_PEERS = 64` | Before authentication |
| Inbound per IP | `indra-node/src/bin/node.rs:883-894` | `MAX_INBOUND_PER_IP = 3` | Before authentication |
| Concurrent handshakes | `indra-node/src/bin/node.rs:1612-1626` | bounded semaphore | During authentication |
| Authenticated non-validator per IP | `indra-network/src/peer_manager.rs:1064-1090` | `MAX_NON_VALIDATOR_PEERS_PER_IP = 3` | After authentication |
| Active validator exemption | `indra-network/src/peer_manager.rs:1064-1065` | membership in authenticated `relay_keys` | After authentication |
| Authenticated global peer table | `indra-network/src/peer.rs:34-35,178-183` | `MAX_PEERS = 80` | After authentication |
| Outbound target | `indra-core/src/types/primitives.rs:424`; `indra-node/src/bin/node.rs:1791-1842` | `TARGET_OUTBOUND_PEERS = 8` | Dial scheduling |
| Peer-list payload | `indra-core/src/types/primitives.rs:418`; `indra-node/src/bin/node.rs:3187` | `MAX_PEER_LIST_SIZE = 20` | Discovery exchange |
| Persisted candidate sanitization | `indra-node/src/discovery.rs:1334-1368` | one deterministic port per IP | Candidate persistence only |

The inbound listener reserves total and per-IP capacity before the handshake (`node.rs:1580-1634`), then releases it after the handshake task completes (`node.rs:1634-1667`). This protects resources against unauthenticated floods. The new peer-manager check is intentionally separate: after the authenticated validator ID is known, non-active identities from one IP cannot consume an unbounded number of authenticated slots, while active validators are identified by their authenticated ID rather than by IP. Non-validators still consume the global authenticated table and all existing ban, duplicate, scoring, and rate-limit controls remain active.

Other IP/subnet-related state was audited and is not a hidden validator-capacity gate:

- `NetworkGroup` and `PreAuthInboundKey` in `indra-node/src/bin/node.rs:254-264` group cooldown state by IPv4 /24 or IPv6 /64, while the actual admission counter remains keyed by exact `IpAddr`.
- `InboundCooldowns` (`node.rs:275-350`) records failure backoff, not successful-connection capacity. Post-auth failure history is keyed by validator ID and IP.
- `indra-node/src/discovery.rs:1342-1368` collapses loaded persisted candidates to one port per IP because persisted `ip:port` entries cannot prove connection direction. It does not remove an already authenticated connection.
- Outbound eligibility (`node.rs:1807-1829`) skips exact configured self addresses, already authenticated validators, and cooldown keys. It does not suppress another validator merely because its IP is already connected.
- The node has separate RPC request per-IP controls elsewhere in `node.rs`; those are RPC admission controls, not validator P2P connection limits.
- BanStore identity bans, peer scores, message rate limiters, and the peer-table cap remain independent safety controls.

## Implementation

`indra-network/src/peer_manager.rs` now counts existing authenticated peers from the incoming IP whose authenticated IDs are not in the active relay-validator set. A new non-active validator is rejected once that count reaches three. An already-connected validator ID is not double-counted by this gate, and an active validator bypasses the per-IP authenticated cap. The check runs after self-connection and identity-ban checks and before duplicate-connection tie-breaking.

New tests cover:

- three same-IP non-validator identities accepted and the fourth rejected;
- an active validator sharing that IP accepted above the cap, with the exemption removed when its active-set membership is removed;
- deterministic duplicate tie-breaking for 200 varied validator-ID cases, in addition to the existing duplicate/tie-break tests.

Mutation proof for the new cap: temporarily removing the authenticated cap block caused `cargo test -p indra-network --lib non_validator_authenticated_peers_are_capped_per_ip -- --nocapture` to fail at `peer_manager.rs:1622` with actual length 4 versus expected length 3. The block was restored and the network library suite passed.

## Liveness and partition evidence

`indra-node/src/driver_tests.rs:1024-1087` adds `audit_harness_four_validators_commit_with_one_missing_edge`. It delivers the proposal and votes across every edge except the edge between validators 2 and 3, then requires all four validators to reach height 1 with the same tip and QC. This is a deterministic in-process one-missing-edge commit test and passed in debug mode.

`indra-node/src/driver_tests.rs:1193-1250` exercises a four-validator path partition. The isolated two-component graph cannot form quorum during the partition; after the graph is healed, the harness delivers the pending messages and verifies convergence. It passed and demonstrates that the no-quorum result is the expected safety behavior, not a relay deadlock.

The live S1 topology evidence from NET_1 remains relevant: the old behavior produced a partial mesh while IP-only connected-peer suppression was present, and the fixed behavior reached 10/10 successful five-node runs in the existing NET_1 stability evidence. NET_2 does not add a second IP-only suppression rule; authenticated relay selection remains identity-based and `relay_if_eligible` continues to verify and relay eligible votes/blocks to authenticated relay targets.

## Verification

Commands completed:

- `cargo clippy --workspace --all-targets --no-deps -- -D warnings` — passed.
- `cargo clippy --release --workspace --all-targets --no-deps -- -D warnings` — passed.
- `scripts/check_no_lint_allows.sh` — passed.
- `cargo test -p indra-core --test lint_guard` — 2 passed.
- `cargo test -p indra-network --lib` — 160 passed, 1 ignored.
- `cargo test -p indra-network --lib --release` — 160 passed, 1 ignored.
- Focused missing-edge and partition-heal node tests — both passed.
- Duplicate tie-break 200-case regression — passed.
- `cargo audit` — advisories passed; existing duplicate-dependency notices were reported.
- `cargo deny check` — bans, licenses, and sources passed; existing duplicate-dependency notices were reported.
- `cargo test --workspace --release --no-fail-fast` — clean rerun: 49 targets, 1,678 passed, 0 failed, 10 ignored. An earlier workspace attempt saw a transient `indra-network` test-binary SIGBUS; the isolated release network suite and the complete workspace release rerun both passed.
- `git diff --check` — passed.

The workspace release test inventory includes existing golden-vector, replay, and protocol-vector tests, including `indra-cli` golden vectors, `indra-crypto` NIST/RFC vectors, network replay protection, consensus replay determinism, and node snapshot/QC replay tests.

## Diff accounting

The NET_2 source diff is limited to two crates:

| Crate | Files | Insertions |
|---|---:|---:|
| `indra-network` | 1 | 130 |
| `indra-node` | 1 | 77 |
| Total | 2 | 207 |

No consensus implementation file was changed. The final filesystem check was `df -h .`: 10 GiB available, 96% used.
