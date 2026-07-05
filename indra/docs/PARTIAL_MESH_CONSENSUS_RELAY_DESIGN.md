# Partial-Mesh Consensus Message Relay — Step 0 and Concrete Design

Status: design for review only. No relay implementation is included in this document.

## Summary

INDRA should implement consensus-message relay inside the current authenticated
`PeerManager`, not by activating the dormant legacy `GossipEngine`.

The current live broadcast path sends node-originated consensus messages only to
currently-connected authenticated validators. With the intended 200-validator
target and current connection caps, that is insufficient unless every validator
is connected to enough of the network and messages are relayed across the
partial mesh.

Relay should be additive: it should improve propagation across the validator
network while preserving the existing authenticated transport, per-peer rate
limits, global large-payload limits, duplicate filtering, slash detection, and
driver-level consensus validation.

## Step 0 — Current inbound message pipeline

The current authenticated network path is `PeerManager`, not the older
`GossipEngine`.

`indra-node` spawns `PeerManager` through `spawn_peer_manager` and receives
`NetworkEvent`s from it. See `indra-node/src/bin/node.rs:601-608`.

Driver-originated broadcasts are converted to `Message` in
`indra-node/src/net_driver.rs:70-82`, then `process_driver_actions` sends them
through `broadcast_driver_message`, which calls `NetworkBridge::broadcast`.
See `indra-node/src/bin/node.rs:2441-2443` and
`indra-node/src/bin/node.rs:2562-2570`.

`NetworkBridge::broadcast` sends `NetworkCommand::Broadcast` to the
`PeerManagerHandle`. See `indra-node/src/bin/node.rs:88-92`.

`PeerManagerActor::handle_command` handles `NetworkCommand::Broadcast` by
iterating `self.peers_by_validator.keys()` and sending the message once to each
currently-connected authenticated validator. See
`indra-network/src/peer_manager.rs:315-329`.

The inbound path after a peer has completed the authenticated handshake is:

1. `register_peer` stores the authenticated peer under its validator id and
   starts a read task and write task. See `indra-network/src/peer_manager.rs:439-612`.
2. The read task reads an encrypted frame using `FrameReader`. See
   `indra-network/src/peer_manager.rs:499-508`.
3. It extracts the message payload and decodes with `Message::decode_wire`.
   See `indra-network/src/peer_manager.rs:510-519`.
4. For `Vote`, slash detection observes the vote before duplicate filtering or
   rate limiting. See `indra-network/src/peer_manager.rs:520-535`.
5. Exact consensus duplicates are dropped by `ConsensusDuplicateFilter`. See
   `indra-network/src/peer_manager.rs:536-540`.
6. `Status` messages are coalesced before they take driver-lock time. See
   `indra-network/src/peer_manager.rs:541-543`.
7. The per-peer `PeerRateLimiter` runs. See
   `indra-network/src/peer_manager.rs:544-553`.
8. Accepted messages are sent to the actor as `PeerManagerMessage::InboundMessage`.
   See `indra-network/src/peer_manager.rs:554-560`.
9. In the actor, large payloads are checked against the global byte limiter
   before forwarding to the node. See `indra-network/src/peer_manager.rs:410-426`.
10. The message is then emitted as `NetworkEvent::Message` to `indra-node`.
    See `indra-network/src/peer_manager.rs:427-434`.

Important ordering note: slash detection currently runs before duplicate drop.
Relay must preserve this property. A duplicate/equivocating vote should not be
hidden from the slash detector merely because it is not forwarded to consensus.

## Existing duplicate identity mechanisms

`PeerManager` already has a consensus duplicate key:
`ConsensusMessageKey`, defined at `indra-network/src/peer_manager.rs:98-123`.

Current keys:

- `VrfCommit`: validator id, height, round, commit hash, full content hash.
- `VrfReveal`: validator id, height, round, commit hash, VRF output, full
  content hash.
- `Vote`: validator id, height, round, step, block hash, full content hash.

The full content hash is computed from `msg.encode_wire()` in
`consensus_message_key`. See `indra-network/src/peer_manager.rs:190-219`.

`ConsensusDuplicateFilter` is a bounded ring buffer with oldest-entry eviction.
See `indra-network/src/peer_manager.rs:125-156`. Its current capacity is
`CONSENSUS_DUPLICATE_FILTER_CAPACITY = 512`, defined at
`indra-network/src/peer_manager.rs:38`.

Relay should reuse the same message identity concept. It should not introduce a
separate incompatible definition of “same message.”

However, the existing duplicate filter is per read task/per peer. Relay needs a
node-wide seen/forwarded cache owned by `PeerManagerActor`, because “have I
already relayed this message?” is a node-level question, not a per-inbound-peer
question.

## Message classes to relay

Relay candidates are the messages currently emitted as broadcast driver actions
and currently delivered only to connected authenticated peers:

- `Message::Block` / `DriverAction::BroadcastBlock`
- `Message::Vote` / `DriverAction::BroadcastVote`
- `Message::VrfCommit` / `DriverAction::BroadcastVrfCommit`
- `Message::VrfReveal` / `DriverAction::BroadcastVrfReveal`

The action-to-message mapping is in `indra-node/src/net_driver.rs:70-82`.

These are the only consensus messages that need epidemic propagation across a
partial validator mesh.

Messages that should not be blindly relayed:

- `RequestQC`
- `QCResponse`
- `RequestVrfReveals`
- `VrfRevealsResponse`
- `RequestBlocks`
- `BlockResponse`
- `RequestProposal`
- `Status`
- `PeerList`
- `Ping` / `Pong`
- `Tx`, unless a separate mempool-relay design explicitly chooses to cover it

Reason: request/response messages are point-to-point recovery/sync traffic.
`process_driver_actions` currently sends `RequestQC` and `RequestVrfReveals`
directly to connected validators, not via `action_to_message`, at
`indra-node/src/bin/node.rs:2485-2525`. Blindly relaying responses would create
a spoofing/amplification surface and would blur requester/responder semantics.

## Connection tracking available for relay

`PeerManagerActor` tracks:

- `peers_by_validator: HashMap<Bytes32, ManagedPeer>` at
  `indra-network/src/peer_manager.rs:83-85`.
- `validator_by_addr: HashMap<SocketAddr, Bytes32>` at
  `indra-network/src/peer_manager.rs:83-85`.
- each `ManagedPeer` has `small_tx`, `large_tx`, and `addr`; see
  `indra-network/src/peer_manager.rs:69-75`.

That is sufficient to answer:

- who sent the message (`validator_id` in `PeerManagerMessage::InboundMessage`);
- which peers are currently connected (`peers_by_validator.keys()`);
- which peer should be excluded as the inbound sender;
- which queue should be used (`message_queue`, `indra-network/src/peer_manager.rs:260-268`).

To avoid sending the same message repeatedly to the same peer, the actor should
maintain a bounded relay cache containing the message identity plus a small
record of which peers it already forwarded that message to. This state should
live in the actor, not in each read task.

## Concrete design

### 1. Node-wide relay seen cache

Add a node-wide relay cache to `PeerManagerActor`, conceptually:

```rust
struct RelaySeenCache {
    entries: VecDeque<RelaySeenEntry>,
    by_key: HashMap<RelayMessageKey, RelaySeenMeta>,
    capacity: usize,
}

struct RelaySeenMeta {
    first_seen_at: Instant,
    received_from: SmallVec<[Bytes32; 4]>,
    forwarded_to: SmallVec<[Bytes32; RELAY_FANOUT]>,
}
```

The key should be the same identity used by `consensus_message_key`, extended
for blocks:

- for Vote/VrfCommit/VrfReveal: use `ConsensusMessageKey`;
- for Block: use full `Message::Block` wire hash plus block height/round/hash
  if cheaply available.

The cache should be bounded. Initial recommendation:

- `CONSENSUS_RELAY_SEEN_CAPACITY = 16_384`.

Rationale: at 200 validators, one height/round can generate roughly:

- 200 VRF commits,
- 200 VRF reveals,
- 200 prevotes,
- 200 precommits,
- at least one proposal block, with more in failed rounds.

That is ~800+ relayable messages per active round. A 16,384-entry cache covers
roughly 20 rounds of consensus-slot traffic, enough to prevent normal loops
without unbounded memory. This can be tuned after simulation.

Eviction policy: oldest-entry eviction, same style as `ConsensusDuplicateFilter`.

The relay cache and the existing per-peer `ConsensusDuplicateFilter` should
share key construction helpers so they cannot drift.

### 2. Relay trigger point

Relay should be triggered in `PeerManagerActor::handle_control` when processing
`PeerManagerMessage::InboundMessage`, after:

- frame decrypt/read,
- wire decode,
- vote slash observation,
- exact duplicate drop,
- status coalescing,
- per-peer rate limit,
- global large-payload byte limit.

Concretely, the insertion point should be after the global large-payload check
at `indra-network/src/peer_manager.rs:416-426` and before sending
`NetworkEvent::Message` at `indra-network/src/peer_manager.rs:427-434`.

That means malformed, duplicate, per-peer-rate-limited, or globally
large-payload-limited messages are never relayed.

For node-originated messages handled by `NetworkCommand::Broadcast`, the same
relay cache should be marked before sending, so if the message later arrives
back from a peer it is not re-forwarded indefinitely.

### 3. Fanout and peer selection

Use bounded randomized fanout, not “all peers minus sender.”

Initial recommendation:

- `CONSENSUS_RELAY_FANOUT = 8`
- exclude the inbound sender;
- exclude peers recorded in `forwarded_to` for that message;
- prefer peers with healthy scores and open queue capacity;
- randomize among eligible peers, optionally weighted by score bucket.

Why not all peers? With 200 validators and 64-80 connections per node, “relay
to all except sender” turns every received message into a large local fanout
burst, recreating much of full-mesh bandwidth pressure.

Why fanout 8? The dormant `GossipEngine` used `MAX_GOSSIP_FANOUT = 8` at
`indra-network/src/gossip.rs:33-36`; this is also in the same family as
epidemic gossip designs used by Ethereum-style devp2p/gossipsub-like systems:
send to a bounded subset, rely on redundancy and seen caches for propagation,
not all-to-all forwarding.

Because INDRA’s validator set is authenticated and bounded at 200, the design
can be simpler than public open-network gossip:

- no untrusted anonymous peers;
- no unbounded peer population;
- no relayer authority;
- no need for a complex public scoring/mesh maintenance protocol in the first
  iteration, though score-aware peer choice is still useful.

Open design choice for review: whether block proposals should use a larger
fanout than small consensus messages. Blocks are large and latency-sensitive.
Possible options:

1. same fanout 8 for all relayable consensus messages;
2. `Block` fanout 12 or 16, Vote/VRF fanout 8;
3. all connected peers for local proposer-originated block broadcast, bounded
   fanout only for relays.

Recommendation: start with option 3. It preserves current proposer behavior to
direct peers, while preventing repeated all-peer fanout on every relay hop.

### 4. Bounding relay depth

Use seen-cache-only bounding, not an on-wire TTL, for the first design.

Reasoning:

- consensus messages already have signed slot fields: height, round, step,
  validator id, block hash, etc.;
- the validator network is bounded at `MAX_ACTIVE_VALIDATORS = 200`;
- connections are authenticated;
- relayed messages are byte-identical; relayers do not modify or re-sign;
- a bounded seen cache prevents infinite loops without changing wire format.

An on-wire TTL would require a wire-format change or message wrapping, and it
would either break existing signatures or require a relay envelope. That is not
necessary for a closed authenticated validator set.

Relay loops are bounded by:

- node-wide seen cache;
- per-peer duplicate filters;
- driver-level per-slot dedup;
- existing queue limits and byte limits.

### 5. Security hardening

#### Original signatures remain the sole authority

Relayers forward the original `Message` unchanged. They do not sign, wrap, or
attest. The driver continues to verify original Vote/VRF/block validity.

The message enum carries the original signed objects directly:
`Message::Vote`, `Message::VrfCommit`, `Message::VrfReveal`, and
`Message::Block`; see `indra-network/src/message.rs:139-223`.

#### Existing limits must apply before relay

Per-peer rate limiting currently runs in the read task before
`PeerManagerMessage::InboundMessage` is emitted. See
`indra-network/src/peer_manager.rs:544-553`.

Global byte limiting currently runs in the actor before forwarding to the node.
See `indra-network/src/peer_manager.rs:416-426`.

Relay must happen after both. No separate weaker relay path should exist.

#### Amplification bound

Worst-case per accepted relayable message from one peer:

- one inbound message consumes that peer’s rate/byte budget;
- if accepted and unseen, this node forwards it to at most
  `CONSENSUS_RELAY_FANOUT` peers;
- with fanout 8, immediate local amplification is at most 8 outbound sends per
  accepted inbound message.

This is acceptable only because:

- senders are authenticated validators;
- Vote/VRF messages are protocol-slot-bounded by driver validation and existing
  duplicate filters;
- Blocks are globally byte-limited before relay;
- queue limits prevent unbounded local buffering.

The implementation task should add tests for a malicious validator repeatedly
sending distinct but invalid relayable messages. Important subtlety: some
invalid messages may pass decode/rate-limit but fail driver validation later.
If relay happens before driver validation, invalid-but-well-formed messages can
be amplified. That is the main remaining security tradeoff.

Two possible mitigations:

1. Relay only after cheap structural/authenticity checks available in
   `PeerManager`; keep expensive consensus validation in driver.
2. For Vote/VRF, add cheap pre-relay signature/slot sanity checks in
   `PeerManager` only if keys/state are available without pulling consensus
   state into networking.

Recommendation: do not pull consensus state into `PeerManager` in the first
design. Instead, relay only messages that pass existing transport/rate/duplicate
checks, keep fanout bounded, and rely on driver invalid-consensus disconnect
paths. Revisit if simulation shows malformed relay amplification is high.

#### Slash detection must not lose visibility

Vote slash observation currently happens before duplicate filtering at
`indra-network/src/peer_manager.rs:520-535`.

Relay must not move duplicate filtering before slash observation. If relay adds
a node-wide seen cache, it must not suppress slash observation for votes before
the existing detector has seen them.

### 6. What does not change

The following should remain unchanged:

- authenticated transport handshake and validator identity model;
- `PeerManager` ownership of connections;
- per-peer rate limiter policy;
- global large-payload limiter;
- point-to-point request/response handling;
- driver-level validation and invalid-consensus disconnect behavior;
- connection limits, unless later simulation shows the current ranges are too
  low even with relay.

Relay is not a replacement for authenticated connections. It is only a
propagation layer across a bounded partial mesh.

## Why not activate `GossipEngine`

`GossipEngine` contains useful concepts but is not a viable foundation as-is.

It owns a legacy `Connection`/`PeerTable` model and does not use the current
authenticated validator identity model. See `indra-network/src/gossip.rs:105-175`.

Its comments describe receive-and-forward flooding, but the visible
implementation has `broadcast` and `recv_from`; it does not implement the full
active receive/decode/relay path used by the node. See
`indra-network/src/gossip.rs:183-242`.

Its tests cover seen-cache eviction, score/banning, and duplicate same-IP
connections, but not relay propagation, authenticated validator semantics, or
rate-limit integration. See `indra-network/src/gossip.rs:324-409`.

The current security-critical network code lives in `PeerManager`, including
authenticated validator ids, duplicate filtering, slash observation, rate
limiting, queues, and global byte limits. Relay should be implemented there.

## Tests required for the implementation task

The follow-up implementation task should include at least:

1. `relay_forwards_vote_to_fanout_excluding_sender`
2. `relay_does_not_forward_duplicate_vote`
3. `relay_preserves_slash_detection_before_duplicate_drop`
4. `relay_forwards_vrf_commit_and_reveal`
5. `relay_forwards_block_with_global_byte_limit_enforced_first`
6. `relay_does_not_forward_request_or_response_messages`
7. `node_originated_broadcast_marks_seen_to_prevent_echo_relay`
8. `partial_mesh_propagates_vote_to_quorum_in_simulation`
9. `relay_cache_is_bounded_and_evicts_old_entries`
10. `relay_does_not_relay_to_peer_already_forwarded_to`

The most important test is a partial-mesh propagation simulation. Unit tests
that prove one hop works are necessary but not sufficient for the mainnet-scale
claim.

## Open questions for Buddhi / review

1. Should block proposals use a higher relay fanout than Vote/VRF messages?
2. Is fanout 8 acceptable as an initial constant, or should it be derived from
   active validator count, e.g. `ceil(sqrt(N))` with min/max bounds?
3. Should relay be enabled for `Tx`, or should mempool gossip remain a separate
   design?
4. Is it acceptable to relay well-formed messages before full driver validation,
   relying on bounded fanout and invalid-consensus disconnects, or should
   networking gain extra cheap pre-relay validity checks?
5. Should relay metrics be mandatory in the first implementation? Recommended:
   yes — count relayed/dropped/duplicate messages by class and peer.

## Recommendation

Proceed with a new `PeerManager`-native relay design, not `GossipEngine`
activation.

Use:

- node-wide bounded seen/forwarded cache;
- shared `ConsensusMessageKey`-style identity;
- relay insertion after existing decode/slash/duplicate/rate/global-byte checks;
- randomized score-aware fanout;
- seen-cache-only loop bounding;
- no relay for point-to-point request/response messages;
- no wire-format change.

This keeps INDRA on the partial-mesh path chosen for mainnet while preserving
the security boundary already established in the authenticated peer manager.
