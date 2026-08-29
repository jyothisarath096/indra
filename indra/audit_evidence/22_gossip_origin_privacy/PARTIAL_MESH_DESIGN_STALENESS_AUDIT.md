# `PARTIAL_MESH_CONSENSUS_RELAY_DESIGN.md` staleness and accuracy audit

**Document audited:** `docs/PARTIAL_MESH_CONSENSUS_RELAY_DESIGN.md`  
**Code snapshot:** `20448f3d2fd68181481947da13dbd5d17b503e35`  
**Audit date:** 2026-08-30  
**Method:** current-code inspection plus `git log`, `git show`, and `git blame`

## Executive result

The document is useful as a historical design record, but it is not an accurate
description of current code. Its core architectural recommendation was
implemented and remains correct: consensus relay lives in the authenticated
`PeerManager`, uses a node-wide bounded seen/forwarded cache, relays inbound
consensus messages with bounded fanout, marks local broadcasts as forwarded, and
does not add a relay TTL to the wire.

The material drift is:

1. Standalone `VrfCommit`, `VrfReveal`, `RequestVrfReveals`, and
   `VrfRevealsResponse` messages no longer exist. Commit
   `16d72bc9ee6b68a16c796d44d2ab23418b8243e0` on 2026-08-15 replaced the
   commit/reveal election protocol with standard VRF proof/output and sortition
   evidence embedded in `BlockHeaderVNext`, plus a full-hybrid-authorized
   `BlockProposalVNext`. Current relay classes are only `Block` and `Vote`.
2. The document's “current” line citations all predate substantial code movement.
3. The old `GossipEngine` was deleted in commit
   `a062873e9d28ad1c4eec73fa2a5776ceecb121f2` on 2026-08-06. The recommendation
   not to activate it remains directionally right, but the detailed description
   of that module is now historical, not current.
4. Slash-observation and limiting order changed in commit
   `dcb87aecddddfde65a4aca38d74b487da26cb211` on 2026-08-08. The document's
   exact pipeline ordering is stale.
5. The five “open questions” were not all left open. Questions 1, 2, 4, and the
   class-level portion of 5 were answered in the implementation commit itself
   (`66d956287d84fa02066f56a40e7603eec1c79bd1`, 2026-07-05), although the
   document was never updated. Transaction relay was omitted and remains a
   separate unresolved design/product question, rather than a recorded “no.”

The clean disposition is to preserve the original as the design-time artifact
and use this addendum as its current-status companion.

## 1. History and interpretation

The document was added by commit `66d95628` on 2026-07-05 under the subject
“feat: partial-mesh consensus message relay (mainnet scale readiness).” That same
commit added the production relay implementation and its tests. Its commit
message explicitly says two open questions were resolved:

* full hybrid signature verification before relay; and
* fanout derived as `ceil(2 ln N) + 2`, clamped to `4..=16`, with larger block
  fanout.

Therefore phrases such as “should implement,” “add,” “initial recommendation,”
and “follow-up implementation task” describe the pre-implementation design even
though the checked-in document arrived with implementation. They must not be read
as current missing-work statements.

Commit `af0c918f` on 2026-07-06 appended the validator bandwidth requirement.
No later commit updated the rest of the document.

## 2. Claim-by-claim cross-check

The tables below cover each concrete code, symbol, value, variant, class, and
behavior claim. Pure recommendations are classified by whether current code
implemented them.

### 2.1 Summary and live path (document lines 3–68)

| Doc line(s) / claim | Status | Current evidence and correction |
|---|---|---|
| 3: “design for review only; no relay implementation” | **Stale** | Relay is implemented in `PeerManagerActor::relay_if_eligible` (`indra-network/src/peer_manager.rs:647-712`) and invoked from inbound control handling (`indra-network/src/peer_manager.rs:895-949`). It was implemented in the same `66d95628` commit that added the document. |
| 7–8, 21–24: authenticated `PeerManager`, not legacy `GossipEngine`, is the live path | **Confirmed in substance** | The node spawns `PeerManager` at `indra-node/src/bin/node.rs:1243-1256`; authenticated connections are registered into it at `indra-node/src/bin/node.rs:1422-1440`. `GossipEngine` no longer exists; deletion was `a062873e` on 2026-08-06. |
| 10–14: local consensus broadcast reaches current authenticated validators; 200 target and connection caps require partial-mesh relay | **Confirmed** | Local driver messages call full broadcast (`indra-node/src/bin/node.rs:3816-3818`, `indra-node/src/bin/node.rs:3891-3899`); broadcast enumerates `peers_by_validator` (`indra-network/src/peer_manager.rs:714-749`). `MAX_ACTIVE_VALIDATORS=200`, `TARGET_OUTBOUND_PEERS=8`, `MAX_INBOUND_PEERS=64` (`indra-core/src/types/primitives.rs:259-263`, `indra-core/src/types/primitives.rs:434-438`), while `MAX_PEERS=80` (`indra-network/src/peer.rs:35`). |
| 16–19: relay preserves authenticated transport, rate limits, large-payload limits, duplicate filtering, slash detection, and driver validation | **Confirmed with ordering caveat** | These mechanisms remain, but current relay performs its own cryptographic precheck and slash observation only for first node-wide-seen votes (`indra-network/src/peer_manager.rs:551-580`, `indra-network/src/peer_manager.rs:647-685`). Rate/global limiting precede relay (`indra-network/src/peer_manager.rs:917-941`); driver delivery follows (`indra-network/src/peer_manager.rs:942-949`). |
| 26–27: spawn/event citation at old `node.rs:601-608` | **Claim confirmed; citation stale** | Current spawn/config/event bridge is `indra-node/src/bin/node.rs:1243-1256`. |
| 29–33: `action_to_message` then `process_driver_actions` → `broadcast_driver_message` → broadcast | **Confirmed; citations stale** | Current mapping is only Block/Vote at `indra-node/src/net_driver.rs:49-56`; broadcast path is `indra-node/src/bin/node.rs:3816-3818` and `indra-node/src/bin/node.rs:3891-3899`. |
| 35–36: `NetworkBridge::broadcast` sends `NetworkCommand::Broadcast` | **Confirmed; citation stale** | Command semantics are `indra-network/src/net_types.rs:61-73`; current bridge call sites use the command-backed handle. The old `node.rs:88-92` citation no longer identifies it. |
| 38–41: broadcast iterates all `peers_by_validator` once | **Confirmed; citation stale** | `indra-network/src/peer_manager.rs:714-749`; command dispatch is `indra-network/src/peer_manager.rs:834-843`. |
| 45–50: `register_peer` stores authenticated peer, starts read/write tasks, reads encrypted `FrameReader`, decodes wire | **Confirmed; citations stale** | Registration and task setup: `indra-network/src/peer_manager.rs:954-1113`; read/decode/dedup/event handoff: `indra-network/src/peer_manager.rs:1034-1077`. |
| 51–68: vote slash detection precedes duplicate and rate limiting, and relay must preserve this exact property | **Stale/incorrect ordering** | Current per-connection `ConsensusDuplicateFilter` runs in the read task before actor delivery (`indra-network/src/peer_manager.rs:1034-1066`). Actor rate/global limits run at `indra-network/src/peer_manager.rs:917-937`. Relay-time vote slash observation is inside `relay_if_eligible`, after those limits and only when the node-wide relay key is not already seen (`indra-network/src/peer_manager.rs:647-678`). This changed in `dcb87aec` on 2026-08-08. Equivocating votes have different content/block keys and remain observable; the old blanket ordering claim is nevertheless false. |
| 57–64: per-peer limiter in read task; global limiter in actor; then event | **Partly stale** | Per-peer limiting moved into actor control handling (`indra-network/src/peer_manager.rs:917-926`), followed by global limiting (`:927-937`), relay (`:941`), then event (`:942-949`). |

### 2.2 Duplicate identities (document lines 70–96)

| Doc line(s) / claim | Status | Current evidence and correction |
|---|---|---|
| 72–80: `ConsensusMessageKey` exists and has VrfCommit, VrfReveal, Vote variants | **Partly confirmed, materially stale** | The enum exists at `indra-network/src/peer_manager.rs:123-133`, but now has only `Vote`. VRF variants were removed by `16d72bc9` on 2026-08-15. |
| 80: Vote key fields are validator, height, round, step, block hash, content hash | **Confirmed** | `indra-network/src/peer_manager.rs:124-133`; construction at `indra-network/src/peer_manager.rs:293-307`. |
| 82–83: full content hash comes from `msg.encode_wire()` | **Confirmed; citation stale** | `indra-network/src/peer_manager.rs:293-305`. |
| 85–88: duplicate filter is bounded ring/oldest eviction, capacity 512 | **Confirmed in effect; terminology imprecise; citations stale** | Capacity remains 512 (`indra-network/src/peer_manager.rs:43-49`). `ConsensusDuplicateFilter` wraps `BoundedTtlSet`, not the document's direct ring-buffer shape (`indra-network/src/peer_manager.rs:175-192`); current entries also expire after the shared 10-minute TTL. This storage change is visible in `a062873e` (2026-08-06). |
| 93–96: per-read-task/per-peer duplicate state is insufficient; relay needs actor-owned node-wide state | **Confirmed and implemented** | A filter is created in each read task (`indra-network/src/peer_manager.rs:1034-1053`), while `PeerManagerActor` owns `relay_seen` (`indra-network/src/peer_manager.rs:91-115`). |

### 2.3 Relay message classes and exclusions (document lines 98–131)

| Doc line(s) / claim | Status | Current evidence and correction |
|---|---|---|
| 100–108: relay candidates are Block, Vote, VrfCommit, VrfReveal and corresponding driver actions | **Stale** | Current action mapping has only `BroadcastBlock` and `BroadcastVote` (`indra-node/src/net_driver.rs:49-56`). `RelayMessageClass` and `relay_message_class` cover only Block/Vote (`indra-network/src/peer_manager.rs:135-139`, `indra-network/src/peer_manager.rs:309-315`). VRF message/actions were deleted by `16d72bc9`. |
| 110–111: those four are the only consensus messages needing epidemic propagation | **Stale formulation** | The current set is Block and Vote. Proposer VRF evidence travels inside `Block`, not as standalone epidemic messages (`indra-core/src/types/block.rs:181-198`, encode at `indra-core/src/types/block.rs:252-260`). |
| 113–125: listed request/response/control messages and Tx should not be blindly relayed | **Mostly confirmed, with deleted variants** | `relay_message_class` returns `None` for everything except Block/Vote (`indra-network/src/peer_manager.rs:309-315`). `RequestVrfReveals` and `VrfRevealsResponse` no longer exist (`indra-network/src/message.rs:44-98`, `indra-network/src/message.rs:132-198`). Current additional non-relayed classes include `StakingOp` and `GovernanceOp`; they were not listed in the original exclusion list. Tx/staking/governance are separately validated and rebroadcast by node admission logic, not peer-manager epidemic relay (`indra-node/src/bin/node.rs:2672-2768`). |
| 127–131: request/response traffic is point-to-point; RequestQC and RequestVrfReveals are directly sent | **Partly confirmed, partly deleted** | `RequestQC` remains point-to-point in `process_driver_actions` (`indra-node/src/bin/node.rs:3831-3845`); `RequestVrfReveals` was removed by `16d72bc9`. Request/response messages remain excluded from relay. |

### 2.4 Connection tracking (document lines 133–154)

| Doc line(s) / claim | Status | Current evidence and correction |
|---|---|---|
| 135–142: actor owns `peers_by_validator`, `validator_by_addr`; peer has address and two queues | **Confirmed; citations stale; one field omitted** | Actor fields: `indra-network/src/peer_manager.rs:91-115`; `ManagedPeer` fields: `indra-network/src/peer_manager.rs:82-89`. It now also records `is_outbound`. |
| 144–149: actor knows sender, connected peers, exclusion target, and queue class | **Confirmed; citation stale** | Inbound identity/message at `indra-network/src/peer_manager.rs:895-900`; candidates/sender exclusion at `indra-network/src/peer_manager.rs:608-645`; queue classification at `indra-network/src/peer_manager.rs:468-475`. |
| 151–154: actor should own bounded per-message forwarded-to state | **Confirmed and implemented** | `RelaySeenCache` maps keys to `HashSet<Bytes32>` of forwarded validators (`indra-network/src/peer_manager.rs:159-164`, `indra-network/src/peer_manager.rs:201-253`). |

### 2.5 Relay cache design (document lines 156–203)

| Doc line(s) / claim | Status | Current evidence and correction |
|---|---|---|
| 160–174: proposed cache shape with entry metadata, first-seen, received-from and small vectors | **Implemented differently** | Current cache is `order: VecDeque<(key, expiry)>`, `forwarded: HashMap<key, HashSet<validator>>`, capacity and TTL (`indra-network/src/peer_manager.rs:159-164`). It does not retain `first_seen_at` or `received_from`, and uses `HashSet`, not `SmallVec`. |
| 176–181: share consensus identity; Block uses wire hash plus height/round/hash | **Confirmed after VRF removal** | `RelayMessageKey::Consensus(ConsensusMessageKey)` and Block fields are at `indra-network/src/peer_manager.rs:141-150`; construction uses encoded wire hash plus block header height, proposer round, block hash (`indra-network/src/peer_manager.rs:317-331`). Vote is the only remaining consensus-key variant. |
| 183–186: capacity 16,384 | **Confirmed** | `indra-network/src/peer_manager.rs:48`. |
| 187–197: approximately 800+ messages/round and about 20 rounds of coverage, based on 200 commits/reveals/prevotes/precommits | **Stale model** | Commit/reveal traffic was deleted by `16d72bc9`; a nominal round now has votes plus block proposals, not 200 standalone commits and 200 reveals. Capacity remains 16,384, but this rationale overstates current per-round message count and should be recalculated. |
| 199: oldest-entry eviction | **Confirmed plus TTL** | Capacity eviction removes the front entry and entries expire after 10 minutes (`indra-network/src/peer_manager.rs:201-253`). TTL was added/standardized by `a062873e`. |
| 201–202: relay/per-peer duplicate keys should share construction | **Confirmed for Vote** | Both use `consensus_message_key`; relay extends it for Block (`indra-network/src/peer_manager.rs:293-331`). |

### 2.6 Trigger point and validation order (document lines 204–226)

| Doc line(s) / claim | Status | Current evidence and correction |
|---|---|---|
| 206–219: relay in actor inbound handling after all listed gates, before node event | **Confirmed at the high level; ordering list stale** | Relay call is exactly before event (`indra-network/src/peer_manager.rs:941-949`), after actor per-peer/global limit checks (`:917-937`). Decode/per-connection dedup/status coalescing occur in the read task (`indra-network/src/peer_manager.rs:1034-1066`). Slash observation now occurs inside relay rather than before actor duplicate/rate checks (`indra-network/src/peer_manager.rs:647-678`). |
| 221–222: malformed, duplicate, rate-limited, globally limited messages are never relayed | **Needs qualification** | Decode failures and per-connection duplicates are dropped before actor relay; rate/global violations are dropped. A copy already seen node-wide can still be forwarded to eligible peers not yet in its `forwarded_to` set—intentional recovery, not a duplicate leak (`indra-network/src/peer_manager.rs:655-711`). “Malformed” at wire level is true; well-formed but consensus-invalid messages are subject only to relay prechecks, not full driver validation. |
| 224–226: local broadcasts mark relay cache | **Confirmed** | `broadcast_to_validators` records only successfully enqueued peers (`indra-network/src/peer_manager.rs:729-749`). The success-only behavior was corrected by `d6d9a327` on 2026-07-05 after the first implementation marked failed sends. |

### 2.7 Fanout and peer selection (document lines 228–279)

| Doc line(s) / claim | Status | Current evidence and correction |
|---|---|---|
| 230: bounded randomized fanout, not all-minus-sender | **Confirmed in bound, not literally random** | Targets are bounded, sender/forwarded peers excluded, score sorted, then deterministically ordered by SHA-256 of message key plus validator ID (`indra-network/src/peer_manager.rs:608-645`). There is no runtime RNG; “deterministic hash-shuffled/score-aware” is more accurate than “randomized.” |
| 232–238: initial constant fanout 8, exclude sender/forwarded, prefer score/open queue, randomize | **Partly stale** | Fanout is derived, not constant (`indra-network/src/peer_manager.rs:333-346`). Sender/forwarded exclusions and score preference are implemented (`:608-645`). Queue capacity is not used during selection; nonblocking `try_send` detects full queues afterward (`indra-network/src/peer_manager.rs:763-792`). Ordering is deterministic, not random. |
| 240–242: 200 validators and 64–80 connections make all-minus-sender expensive | **Confirmed as design rationale** | Current caps remain outbound 8, inbound 64, total peer table 80 (`indra-core/src/types/primitives.rs:434-438`, `indra-network/src/peer.rs:35`). |
| 244–248: dormant `GossipEngine` had fanout 8 | **Historically accurate, now stale** | `MAX_GOSSIP_FANOUT=8` existed before `indra-network/src/gossip.rs` was deleted by `a062873e` on 2026-08-06. No current file/line exists. |
| 250–257: authenticated bounded set, no anonymous population/relayer authority/complex public mesh protocol | **Confirmed** | Handshake authorization uses the active known-validator set (`indra-network/src/handshake.rs:69-79`, `indra-network/src/handshake.rs:317-418`); set maximum remains 200. Current relay uses existing peer scores but no separate mesh protocol. |
| 259–269: block-fanout options; recommendation local full broadcast plus bounded relay | **Confirmed and implemented with a stronger block relay fanout** | Local driver-originated Block/Vote still full-broadcast (`indra-node/src/bin/node.rs:3816-3818`, `indra-node/src/bin/node.rs:3891-3899`). Inbound Block relay uses `2 * base`, capped 24; Vote uses base (`indra-network/src/peer_manager.rs:348-355`). |
| 271–279: 250 Mbps minimum, 1 Gbps preferred; 70/75/250 Mbps timing figures | **Confirmed** | Current operator document gives the same values at `docs/MAINNET_VALIDATOR_REQUIREMENTS.md:9-10` and `docs/MAINNET_VALIDATOR_REQUIREMENTS.md:28-40`. The “200 reveal-set evidence entries” provenance is historical because the reveal-set architecture was later removed; the recorded benchmark remains historical evidence, not a current block-shape model. |

### 2.8 Relay depth and security (document lines 281–371)

| Doc line(s) / claim | Status | Current evidence and correction |
|---|---|---|
| 283–296: seen-cache-only depth, no on-wire TTL/envelope; messages stay byte-identical | **Confirmed** | Relay sends `msg.clone()` without mutation (`indra-network/src/peer_manager.rs:695-710`); cache is node-local. Current `Message` has no relay TTL/envelope (`indra-network/src/message.rs:132-198`). Active set max remains 200. |
| 287–288: consensus messages have signed slot fields including validator ID | **Confirmed for Vote/Block in current forms** | Vote key fields are explicit (`indra-network/src/peer_manager.rs:124-133`); block header carries height, round, proposer and proof material (`indra-core/src/types/block.rs:165-198`). |
| 298–303: loops bounded by node cache, per-peer duplicate, driver dedup, queues/byte limits | **Confirmed in substance** | Relevant current mechanisms are `RelaySeenCache` (`peer_manager.rs:201-253`), per-read filter (`:1034-1053`), finite queues (`:43-44`, `:763-792`), and rate/global limits (`:917-937`). |
| 307–314: unchanged original signed Vote/VRF/Block objects; enum contains four named variants | **Partly confirmed, VRF portion stale** | Relayers still forward unchanged signed objects. Current enum has `Vote(Block...)` and `Block(BlockProposalVNext)` but no VRF message variants (`indra-network/src/message.rs:132-198`). VRF proof is embedded in the block header and the proposal carries separate hybrid authorization. |
| 316–325: per-peer and global limits before relay | **Confirmed; old citations/order stale** | Both are in actor handling before line 941 relay (`indra-network/src/peer_manager.rs:917-941`). |
| 327–343: immediate amplification bounded at constant 8; Vote/VRF protocol-slot bounded; Blocks globally limited | **Partly stale** | The amplification bound is dynamic: Vote up to derived base 4–16; Block up to twice base capped 24 (`indra-network/src/peer_manager.rs:333-355`). No VRF message classes remain. Block large payloads are globally limited (`indra-network/src/rate_limit.rs:146-149`, `indra-network/src/peer_manager.rs:927-937`). |
| 345–362: invalid well-formed amplification is the remaining tradeoff; recommendation was no consensus state/precheck initially | **Stale: implementation chose pre-relay cryptographic checks** | Current relay validates Vote hybrid signatures and Block proposal hybrid authorization against refreshed relay validator keys (`indra-network/src/peer_manager.rs:551-580`). It also rejects same-proposer same-slot conflicting blocks (`:582-605`). It does **not** perform full driver consensus validation; the current test explicitly says block relay verifies embedded proposer VRF structure but not election authority (`indra-network/src/peer_manager.rs:2507-2520`). This choice was recorded in `66d95628`. |
| 364–371: slash observation before duplicate filtering | **Stale** | See §2.1: current placement is `relay_if_eligible` after per-connection duplicate and actor limits, only for a node-wide unseen relay key (`indra-network/src/peer_manager.rs:647-678`). Changed by `dcb87aec`. |

### 2.9 “What does not change” and `GossipEngine` (document lines 373–407)

| Doc line(s) / claim | Status | Current evidence and correction |
|---|---|---|
| 375–387: authenticated identity, peer-manager ownership, limiters, point-to-point handling, driver validation, connection caps remain | **Confirmed** | Current code retains each boundary. Relay remains a propagation feature of `PeerManagerActor`, not an authentication replacement. |
| 389–407: legacy `GossipEngine` exists but is dormant/inadequate | **Stale because deleted; historical rationale confirmed** | The whole module `indra-network/src/gossip.rs` was deleted by `a062873e` on 2026-08-06. There are no current citations for its structs, methods, or tests. `PeerManager` remains the security-critical implementation. |

### 2.10 Required tests (document lines 409–426)

| Proposed test/claim | Status in current code |
|---|---|
| Vote fanout excluding sender | **Implemented:** `relay_forwards_vote_to_fanout_excluding_sender` (`indra-network/src/peer_manager.rs:2396`). |
| Duplicate vote not forwarded | **Implemented:** `relay_does_not_forward_duplicate_vote` (`indra-network/src/peer_manager.rs:2453`). |
| Slash ordering test | **Original invariant superseded.** Slash placement changed in `dcb87aec`; current adversarial relay/verification tests cover the new flow, but the exact named test/invariant from the doc is not current. |
| VRF commit/reveal forwarding | **Obsolete:** variants deleted by `16d72bc9`. |
| Block relay after global byte limit | **Behavior implemented; exact historical test name absent.** Actor ordering proves global check before relay (`indra-network/src/peer_manager.rs:927-941`); block relay tests begin at `indra-network/src/peer_manager.rs:2507`. |
| No request/response relay | **Implemented:** `relay_does_not_forward_request_or_response_messages` (`indra-network/src/peer_manager.rs:2641`). |
| Local broadcast marks seen | **Implemented in production:** `broadcast_to_validators` (`indra-network/src/peer_manager.rs:729-749`), with success-only recovery tests at `indra-network/src/peer_manager.rs:2197` and `:2245`. |
| N=200 partial-mesh quorum simulation | **Implemented:** `partial_mesh_propagates_to_quorum_at_n200_realistic_topology` (`indra-network/src/peer_manager.rs:2820`). |
| Bounded relay cache eviction | **Implemented:** `relay_cache_is_bounded_and_evicts_old_entries` (`indra-network/src/peer_manager.rs:2082`). |
| Skip already-forwarded peer | **Implemented:** `relay_targets_skip_already_forwarded_peers` (`indra-network/src/peer_manager.rs:2105`). |

The document's assertion that partial-mesh simulation is more important than a
one-hop-only unit test remains sound and the requested N=200 simulation exists.

## 3. The VRF commit/reveal architectural shift

This is the largest semantic incompatibility with the design document.

Before 2026-08-15, network message discriminants `0x0D` through `0x10` represented
`VrfCommit`, `VrfReveal`, `RequestVrfReveals`, and `VrfRevealsResponse`, and
`DriverAction` had matching broadcast/request/response actions. The design's
relay sizing and message-class inventory were written for that architecture.

Commit `16d72bc9` removed all four wire variants, their codecs, their driver-event
and action mappings, and the corresponding peer-manager relay classes/keys/tests.
Its commit message states that the commit/reveal protocol's withholding bias was
eliminated and the election seed now evolves from the finalized proposer's unique
VRF output once QC-certified.

Current architecture:

* `MessageType` has no VRF commit/reveal discriminants
  (`indra-network/src/message.rs:44-98`).
* `Message` has no VRF commit/reveal/request/response variants
  (`indra-network/src/message.rs:132-198`).
* `action_to_message` maps only `BroadcastBlock` and `BroadcastVote`
  (`indra-node/src/net_driver.rs:49-56`).
* `BlockHeaderVNext` embeds `vrf_suite`, `election_seed`, full
  `proposer_vrf_output`, full `proposer_vrf_proof`, `value_entropy`, sortition
  claim, and priority (`indra-core/src/types/block.rs:181-198`); these fields are
  canonical header encoding (`indra-core/src/types/block.rs:252-260`).
* `Message::Block` carries `BlockProposalVNext`, whose proposer authorization is
  prechecked for relay (`indra-network/src/peer_manager.rs:568-577`).
* Current relay classes are exactly Block and Vote
  (`indra-network/src/peer_manager.rs:135-139`,
  `indra-network/src/peer_manager.rs:309-315`).

Consequences for the old document:

* every VRF message/action/identity/test reference is obsolete;
* the ~800 messages/round cache rationale is obsolete;
* Vote/VRF fanout comparisons reduce to Vote fanout versus Block fanout;
* “200 reveal-set evidence entries” describes the historical benchmark payload,
  not the current block format;
* block relay now transports all proposer VRF evidence, so its higher fanout is
  the relevant election-proof propagation path.

## 4. Disposition of the five open questions

### Q1. Higher block fanout than Vote/VRF?

**Resolved in code: yes.** Blocks use twice the derived base fanout, capped at 24;
Votes use the base (`indra-network/src/peer_manager.rs:348-355`). Local
driver-originated blocks still broadcast to all current peers
(`indra-node/src/bin/node.rs:3816-3818`, `indra-node/src/bin/node.rs:3891-3899`).
Standalone VRF messages no longer exist. This resolution landed in `66d95628`.

### Q2. Constant 8 or derived fanout?

**Resolved in code: derived, but not `ceil(sqrt(N))`.** The implementation uses:

```text
base = clamp(ceil(2 * ln(N)) + 2, 4, 16)
```

with zero active validators returning 4
(`indra-network/src/peer_manager.rs:333-346`). Tests record N=20→8, 50→10,
100→12, 200→13 (`indra-network/src/peer_manager.rs:2066-2074`). This resolution
landed in `66d95628` and is explicitly described in that commit message.

### Q3. Relay `Tx` or keep mempool relay separate?

**Implicit current answer: no peer-manager epidemic relay; policy decision still
open.** `relay_message_class` excludes Tx (`indra-network/src/peer_manager.rs:309-315`).
However, Tx is not simply dropped: after node-level dedup/admission, an inbound Tx
is broadcast to all peers except its sender (`indra-node/src/bin/node.rs:2736-2768`),
and a locally RPC-accepted Tx is broadcast to all peers
(`indra-node/src/bin/node.rs:5378-5418`).

No commit message reviewed records a deliberate permanent “no” for Tx; omission
preserved the preexisting mempool flood path. Therefore this is **not resolved as
a design decision**. It is answered “no” only as a description of current
peer-manager relay coverage. The separate origin-privacy audit at
`audit_evidence/22_gossip_origin_privacy/GOSSIP_ORIGIN_PRIVACY_AUDIT.md` proposes
a dedicated Tx design rather than reusing consensus relay.

### Q4. Relay before full driver validation, or add cheap network prechecks?

**Resolved as a hybrid.** Relay occurs before full driver validation, but
networking performs full hybrid signature/authorization verification using its
read-only validator-key snapshot (`indra-network/src/peer_manager.rs:551-580`).
It also suppresses conflicting same-proposer blocks in one slot
(`indra-network/src/peer_manager.rs:582-605`). Full eligibility/state validation
remains in the driver; the test name at `indra-network/src/peer_manager.rs:2507`
explicitly distinguishes embedded proposer VRF checking from election authority.
This choice was recorded in `66d95628`; the block checks evolved with
`16d72bc9`.

### Q5. Mandatory relay metrics in v1, by class and peer?

**Partially resolved.** Class-level in-memory metrics exist for relayed,
duplicate, dropped, verification-failed, and queue-full counts
(`indra-network/src/peer_manager.rs:166-173`,
`indra-network/src/peer_manager.rs:543-549`). Tests cover them
(`indra-network/src/peer_manager.rs:2157-2193`). Queue-full logs include peer
validator/address (`indra-network/src/peer_manager.rs:751-759`).

There is no per-peer relay-metric map: `relay_metrics` is keyed only by
`RelayMessageClass` (`indra-network/src/peer_manager.rs:114`). Thus the
recommendation “by class and peer” was implemented **by class**, with peer context
in some logs, but not as per-peer counters. Whether metrics must be exported to
the production metrics surface or broken down per peer remains genuinely open.

## 5. Current authoritative relay description

For maintainers needing a compact replacement for the stale design-time state:

1. Local `BroadcastBlock`/`BroadcastVote` actions are sent to every currently
   connected authenticated validator and successful enqueue targets are recorded
   in `RelaySeenCache` (`indra-node/src/net_driver.rs:49-56`,
   `indra-network/src/peer_manager.rs:714-749`).
2. Each peer read task decrypts/decodes, applies per-connection Vote duplicate
   filtering and Status coalescing, then hands the message to the actor
   (`indra-network/src/peer_manager.rs:1034-1066`).
3. The actor applies per-validator rate limits and the global large-payload limit
   (`indra-network/src/peer_manager.rs:895-937`).
4. Only Block and Vote are relay eligible. First-seen instances undergo
   relay-layer hybrid verification; first-seen votes are slash-observed, and
   conflicting blocks for the same proposer/height/round are suppressed
   (`indra-network/src/peer_manager.rs:551-605`,
   `indra-network/src/peer_manager.rs:647-685`).
5. Eligible targets exclude the inbound sender and already-successful targets,
   prefer higher peer score, use deterministic message-key-derived ordering, and
   are bounded by dynamic class fanout (`indra-network/src/peer_manager.rs:608-645`).
6. Vote fanout is `clamp(ceil(2 ln N)+2, 4, 16)`; Block fanout is twice that,
   capped at 24 (`indra-network/src/peer_manager.rs:333-355`).
7. Forwarded state is recorded only for successful nonblocking queue enqueues;
   failed targets remain eligible for later recovery
   (`indra-network/src/peer_manager.rs:695-749`,
   `indra-network/src/peer_manager.rs:763-792`).
8. The cache is bounded to 16,384 keys and a 10-minute TTL
   (`indra-network/src/peer_manager.rs:48-49`,
   `indra-network/src/peer_manager.rs:201-253`).
9. Relay happens before node/driver delivery and uses no wire envelope or TTL
   (`indra-network/src/peer_manager.rs:941-949`).
10. Tx, staking, and governance propagation remains separate node-level
    admission/rebroadcast logic; all request/response/control classes are
    ineligible for consensus relay.

## 6. Recommended documentation action

Keep `docs/PARTIAL_MESH_CONSENSUS_RELAY_DESIGN.md` unchanged as the design and
decision-history artifact. Add a short banner/link to this audit only in a later
documentation-maintenance task if desired. A wholesale rewrite would erase useful
evidence of why the relay was introduced and which tradeoffs were considered.

Any future current-architecture document should derive the message inventory from
`relay_message_class`, not repeat the pre-August VRF enum list, and should state
the present slash/rate/relay order exactly as in §5.
