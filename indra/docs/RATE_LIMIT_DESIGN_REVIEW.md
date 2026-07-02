# Rate Limiter Design Review — Consensus Message Handling

## Problem Summary

The observed height-50 stall is consistent with the current transport rate limiter treating consensus liveness traffic as ordinary flood traffic. `MessageClass::from_message` classifies `VrfCommit` and `VrfReveal` as `VrfElection`, and `PeerRateLimiter::new` gives that class only `TokenBucket::new(8, 16)`. The same limiter returns escalating penalties when a bucket is exhausted.

The peer-manager read task decodes each authenticated peer message, runs the per-peer limiter, and sends `RateLimitViolation` to the peer-manager actor before the message reaches the node/driver. The actor applies `-penalty` to the peer's score with the 10-minute rate-limit ban duration and drops the peer once the score reaches zero. There is no special handling for authenticated validator peers or consensus messages.

The strike schedule is:

- 1st violation: `-2`
- 2nd through 5th violation: `-5` each
- 6th and later violations: `-10` each

Peers start at score 100. With a fresh score, sustained rate-limit violations ban after 14 rapid violations (`2 + 4*5 + 9*10 = 112`). With prior penalties, it can take fewer. In a 4-validator network, cyclic validator bans can easily drop nodes below the 3-validator connectivity needed for BFT progress.

Code evidence:

- `indra-network/src/rate_limit.rs:98-113` — `VrfCommit` and `VrfReveal` map to `MessageClass::VrfElection`.
- `indra-network/src/rate_limit.rs:177-190` — vote, status, request, response, and VRF token buckets; VRF is `8/sec`, burst `16`.
- `indra-network/src/rate_limit.rs:147-161` — escalating strike penalties.
- `indra-network/src/peer_manager.rs:331-373` — per-connection read task checks the limiter before forwarding messages.
- `indra-network/src/peer_manager.rs:211-240` — rate-limit violations adjust score and ban/drop peers at score zero.
- `indra-network/src/peer.rs:34-45` and `indra-network/src/peer.rs:121-127` — score starts at 100, score zero is banned, rate-limit ban duration is 10 minutes.

## Component 1 Analysis: Per-Slot Dedup vs Token Buckets

Verdict: the direction is correct, but the safest implementation is not "network dedup only." The follow-up fix should remove punitive count-bucket handling for valid consensus slot messages and rely on protocol slot bounds, while also adding cheap pre-validation/range filtering so invalid or far-future consensus messages cannot become a signature-verification CPU flood.

### Q1 — Does the driver already deduplicate VRF commits/reveals?

Yes.

`VrfRoundState` stores `commits`, `reveals`, and `pending_reveals` as `BTreeMap<Bytes32, ...>`, keyed by `validator_id`. This naturally allows at most one commit and one reveal per validator per `VrfRoundState`.

`process_vrf_commit`:

1. Rejects inactive-height or invalid commits.
2. Finds a driver VRF slot for exactly `(height, round)`.
3. Drops the commit if `state.commits.contains_key(&commit.validator_id)` is already true.
4. Drops the commit if `state.commits.len() >= MAX_VRF_ROUND_ENTRIES`.

`process_vrf_reveal` delegates to `insert_valid_vrf_reveal`, which:

1. Validates the reveal.
2. Stores pending reveals only while `pending_reveals.len() < MAX_VRF_ROUND_ENTRIES`.
3. Drops the reveal if a matching commit is absent and the pending map is full.
4. Drops the reveal if `state.reveals.contains_key(&reveal.validator_id)` is already true.
5. Drops the reveal if `state.reveals.len() >= MAX_VRF_ROUND_ENTRIES`.

The driver therefore already enforces the protocol-level one-commit/one-reveal-per-validator-per-slot bound once messages reach it.

Code evidence:

- `indra-node/src/driver.rs:100-118` — `VrfRoundState` maps commits/reveals by validator ID.
- `indra-node/src/driver.rs:555-577` — only current and next VRF rounds are retained in `vrf_states`.
- `indra-node/src/driver.rs:1940-1964` — duplicate commits and over-capacity commits are ignored.
- `indra-node/src/driver.rs:923-955` — duplicate reveals, pending reveals, and per-round caps are enforced.

### Q2 — Does vote handling already deduplicate by slot?

Yes. `process_vote` uses:

```text
(validator_id, height, round, step) -> block_hash
```

in `seen_round_votes`. If the same validator sends the same vote again, the duplicate is ignored. If it sends a different `block_hash` for the same `(height, round, step)`, the driver logs an equivocation warning and returns without feeding the second vote into the collector. The map is bounded by `MAX_STALLED_HEIGHT_ENTRIES` through `prune_seen_round_votes`.

Separately, `VoteCollector::add_vote` also deduplicates at the collector level, and the transport slash detector observes votes before the limiter, so equivocation evidence can still be detected.

Code evidence:

- `indra-node/src/driver.rs:1577-1613` — vote slot dedup by `(validator_id, height, round, step)`.
- `indra-node/src/driver.rs:1142-1161` — `seen_round_votes` pruning.
- `indra-network/src/peer_manager.rs:349-363` — transport slash detector observes votes before the rate limiter.

### Q3 — Is network-layer dedup necessary?

Not necessary for consensus correctness, because the driver drops duplicates and caps retained VRF/vote state.

It is still useful as a performance and blast-radius control. A duplicate VRF commit that reaches the driver costs:

- message decode;
- peer-manager queue work;
- node-driver lock acquisition;
- at least some driver validation work;
- possible hybrid signature verification before duplicate/range rejection, depending on the path.

For valid exact duplicates, this cost is small but not zero. For invalid or far-future messages, the current driver path is more expensive than ideal: `process_vrf_commit` calls `validate_vrf_commit` before checking whether the `(height, round)` is one of the retained VRF slots, and `validate_vrf_commit` includes hybrid signature verification. `insert_valid_vrf_reveal` also validates before checking for a matching commit. That means a Byzantine validator can send signed but irrelevant commits/reveals for many heights/rounds and force cryptographic checks before they are dropped.

Recommendation:

- The driver should cheaply reject VRF messages whose `(height, round)` is not currently retained before signature/VRF proof verification.
- The transport/peer-manager may add a small bounded "seen consensus slot" cache to drop exact duplicates earlier, but it should not need full `VrfRoundState`.

### Q4 — Can network dedup be implemented without driver state?

Yes, for exact duplicates and rough per-slot bounds.

The peer-manager already knows the authenticated peer's validator identity from the handshake, and decoded messages carry their claimed `validator_id`, `height`, `round`, and type. A bounded cache can be keyed by:

```text
(peer_validator_id, claimed_validator_id, height, round, msg_kind)
```

or stricter:

```text
(claimed_validator_id, height, round, msg_kind)
```

per connection/peer. The cache should be capped and pruned by height/round proximity or insertion order. Exact duplicates should be dropped silently or with rate-limited logs.

Important caveat: this should not become the authoritative consensus rule. The driver must remain authoritative because it knows the active validator set, chain ID, registered VRF keys, current height/round, and vote safety context.

## Component 2 Analysis: No Ban for Consensus Message Excess

Verdict: correct for valid duplicates/excess consensus messages, but incomplete unless "valid duplicate" is distinguished from "invalid consensus message." The correct behavior should be:

- valid duplicate or already-seen consensus slot message: drop and optionally log at a rate limit;
- valid but irrelevant/far-future consensus message: cheap drop, no ban for the first few, disconnect if it becomes an obvious flood;
- invalid consensus message that fails signature, chain ID, key match, or VRF proof validation: disconnect and score as invalid behavior; do not let it accumulate quietly;
- non-consensus flood and large payload flood: keep punitive rate limiting and bans.

### Q1 — Is the same penalty path applied to validators and observers?

For authenticated validator transport peers, yes. The peer-manager read task is spawned only after an authenticated handshake. Every decoded message goes through one `PeerRateLimiter`, and every limiter violation becomes `PeerManagerMessage::RateLimitViolation`. The actor applies score penalties and can ban/drop the peer.

Observer/full-node connections have separate observer-specific limits in the node/observer path; they are not the subject of this validator-peer limiter.

### Q2 — What is the current threshold?

Starting from score 100:

- violation 1: score 98
- violations 2-5: score 78
- violations 6-13: score  -2 after clamping at/below zero

So a fresh peer bans on the 14th rapid violation. With any prior negative score history, fewer violations are needed. The strike counter decays only after 60 seconds since the last violation, so a stall with rapid round cycling can build strikes without decay.

### Q3 — Does current logic distinguish consensus excess, non-consensus floods, and malformed messages?

No.

The current rate limiter classifies by broad message class, not by whether the message is a valid duplicate, invalid, consensus-critical, or non-consensus. `RateLimitViolation` has only `(validator_id, addr, penalty)`, so the actor cannot make a nuanced decision later.

Malformed decode failures currently break the read loop and disconnect the peer, but they do not go through the score/ban path shown for rate-limit violations. Driver-level invalid consensus messages generally return `DriverAction::None`; they are not currently surfaced back to peer-manager scoring.

### Q4 — Could a Byzantine validator exploit "no ban for consensus excess"?

Yes, if "no ban" is implemented as "never penalize any consensus-class message."

Examples:

- many invalid `VrfCommit` messages with wrong signatures;
- many validly signed but far-future `(height, round)` commits;
- many `VrfReveal` messages with invalid VRF proofs;
- many votes for impossible heights/rounds or wrong chain context.

Those should not be treated like harmless duplicates. Without a punitive count bucket, invalid consensus messages need another response path.

Recommended distinction:

1. Cheap syntactic/range checks first: drop impossible/far-away messages before crypto.
2. Exact duplicate valid slot messages: drop/no score change.
3. Cryptographically invalid messages from an authenticated validator: disconnect immediately and apply an invalid-message score penalty.
4. Repeated irrelevant but syntactically valid consensus messages: disconnect after a small per-peer threshold; avoid long bans unless the behavior is sustained across reconnects.

### Q5 — Correct response to repeatedly invalid consensus messages

Repeated consensus messages that fail validation are Byzantine or badly corrupted behavior. They should not ban an honest validator for ordinary duplicate gossip, but they also should not be free.

Recommended response:

- First invalid signature/chain-ID/key/VRF proof: drop message, log warning with validator short ID and reason, disconnect current connection.
- Repeated invalid messages across reconnects: score as `InvalidMessage` and allow normal peer-table protection to ban after sustained abuse.
- Valid equivocation votes should continue to produce slash evidence rather than merely disconnect.

This requires a follow-up interface change because the driver currently returns only actions, not a validation/error classification that can be sent back to the peer-manager.

## Component 3 Analysis: Reconnect Grace Period

Verdict: a reconnect grace period is not the primary fix and should not be required for VRF/vote liveness once Component 1 is implemented correctly. It may still be useful for non-consensus catch-up traffic, but applying it to consensus messages risks masking the wrong architectural issue.

### Q1 — Does peer-manager track connection age or reconnect count?

The current code stores connected peers by validator ID and address, and `PeerInfo` stores `last_seen`, status, score, and ban metadata. The shown peer-manager does not use a connection-age or reconnect-count field when making rate-limit decisions. The `PeerRateLimiter` is created fresh inside each read task, so reconnecting resets token buckets and strike counters for that task, while peer-table score persists by address.

Code evidence:

- `indra-network/src/peer_manager.rs:331-333` — new `PeerRateLimiter` per read task.
- `indra-network/src/peer.rs:62-82` — `PeerInfo` fields; no connection age/reconnect count.

### Q2 — Is grace the right solution?

Not for the VRF stall. If VRF and vote messages are governed by per-slot protocol dedup instead of token-bucket penalties, a reconnecting validator sending one commit and one reveal for current/next rounds will not hit a punitive count bucket. The driver's `vrf_states` cap and per-validator maps already bound memory.

### Q3 — Is grace unnecessary after Component 1?

For the reported VRF banning failure, yes. Component 1 plus the Component 2 distinction between duplicates and invalid messages should eliminate the reconnect burst problem.

Grace may still be worth considering for:

- `Status`/`Ping` startup bursts;
- `RequestQC`/`QCResponse` recovery after sync;
- block sync traffic from observer/full nodes.

But it should be a separate operational hardening task, not a substitute for fixing consensus message handling.

## Vote Rate Limit Risk (Q4)

Votes have the same architectural mismatch, though the current bucket is less likely to trip in normal operation.

Current vote bucket: `TokenBucket::new(20, 80)`.

With 4 validators, each validator should normally send at most:

- one prevote per `(height, round)`;
- one precommit per `(height, round)`;
- possible nil votes still count as the same step/slot and are governed by vote safety.

During rapid stalled rounds, an honest validator can generate two vote messages per round. At 20 votes/sec and burst 80, this allows roughly 40 rapid rounds from one peer before penalties, assuming no refill. That is much more forgiving than VRF `8/sec`, burst `16`, but it is still not a protocol-correct boundary. A prolonged stall, timer bug, or reconnect/rebroadcast storm could trip it.

Because the driver already deduplicates votes by `(validator_id, height, round, step)`, votes should follow the same design as VRF:

- no punitive count-bucket banning for valid duplicate/excess vote gossip;
- retain byte/frame limits;
- retain slash detection for equivocation;
- penalize/disconnect invalid signed votes or malformed messages.

## DoS Protection Preservation (Q5)

Removing the VRF/Vote token bucket without replacement would be too broad. Replacing it with protocol-aware bounds preserves DoS protection better than the current design if implemented carefully.

Existing protections that remain valid:

- Frame/message size limits still apply in the transport and message decoder.
- VRF retained state is bounded to two `Option<VrfRoundState>` slots: current round and next round.
- `MAX_VRF_ROUND_ENTRIES` caps commits, reveals, and pending reveals per round.
- Vote dedup state is bounded by `MAX_STALLED_HEIGHT_ENTRIES`.
- Vote collectors and other stalled collections have pruning paths.

What must be corrected:

- Cheap height/round slot checks should happen before expensive VRF commit signature verification and before VRF reveal proof verification.
- Peer-manager-level exact duplicate caches should be bounded.
- Invalid consensus messages should produce disconnect/score events, not silent free CPU work.

With those corrections, per-slot dedup does not re-open the Phase 6 DoS vector. It closes the liveness failure while keeping memory bounded by consensus rules rather than arbitrary message rates.

## Other Vulnerable Buckets (Q6)

| Class | Current bucket | Stress risk | Recommendation |
|---|---:|---|---|
| `VrfElection` | 8/sec, burst 16 | HIGH. Confirmed live stall/bans under commit-reveal round churn. | Remove punitive token-bucket handling. Use slot dedup/range filtering and invalid-message disconnect/scoring. |
| `Vote` | 20/sec, burst 80 | MEDIUM. Less likely than VRF but same architectural mismatch during prolonged rapid round cycling. | Apply the same consensus-message treatment as VRF. |
| `BlockOrProposal` | 5/sec, burst 10 | MEDIUM. Competing proposals/reproposal churn can burst, but blocks are large and expensive. | Keep byte/global limits. Consider slot-aware duplicate proposal drops before score penalties; do not remove protection for full-block floods. |
| `Status` / `PeerList` | 2/sec, burst 4 | MEDIUM. Status is consensus-adjacent; reconnect/startup and round sync can burst. PeerList is discovery and should stay limited. | Split `Status` and `PeerList` classes. `Status` should be bounded by latest-per-peer coalescing/drop, not validator bans during recovery. Keep PeerList rate limiting. |
| `BlockRequest` | 5/sec, burst 10 | LOW/MEDIUM. Sync recovery can request repeatedly; serving cost matters. | Keep rate limiting, but ensure legitimate sync has request-aware behavior where possible. |
| `BlockResponse` | 20/sec, burst 64 + byte buckets | LOW after previous tuning. | Keep current count/byte limits; request-correlation remains ideal long-term. |
| `QCResponse` | 5/sec, burst 10 | MEDIUM. QC recovery after stale-QC/sync incidents can burst across reconnects. | Consider request-aware exemption similar to BlockResponse; avoid validator bans for solicited QC responses. |
| `Tx` | 50/sec, burst 200 + byte bucket | LOW for consensus liveness; DoS-facing. | Keep punitive rate limiting. |
| `PingPong` | 2/sec, burst 4 | LOW/MEDIUM. Startup keepalive bursts may annoy but not consensus-critical. | Keep, but disconnect/drop rather than long validator bans if authenticated validators exceed mildly. |

## Final Recommendation

Implement a corrected version of the proposed design:

1. Treat consensus slot messages (`Vote`, `VrfCommit`, `VrfReveal`) as protocol-bounded messages, not count-bucket-ban messages.
2. Remove or bypass the punitive token bucket for `MessageClass::VrfElection`.
3. Apply the same design to `Vote`; otherwise the same liveness failure remains latent.
4. Keep byte/frame limits and global large-payload limits.
5. Add cheap pre-crypto slot/range rejection in the driver for VRF commits/reveals.
6. Add bounded peer-manager duplicate caches for exact consensus duplicates if early drops are desired, but keep driver dedup authoritative.
7. Add a way for the driver or node message handler to classify invalid consensus messages so the peer-manager can disconnect/score genuinely invalid behavior.
8. Do not use reconnect grace period as the main fix. Reassess it later for non-consensus startup/sync traffic.

The simplest safe follow-up patch is:

- bypass count-bucket penalties for `VrfElection` and `Vote` in `PeerRateLimiter::check`;
- add a bounded `ConsensusDuplicateFilter` in peer-manager for `Vote`, `VrfCommit`, and `VrfReveal`;
- preserve transport slash detection for votes;
- reorder driver VRF checks so slot membership is checked before signature/proof verification;
- add explicit tests proving valid duplicate consensus messages are dropped without penalty, while invalid consensus messages still cause disconnect/scoring.

## Implementation Checklist (for follow-up fix task)

Files to change:

- `indra-network/src/rate_limit.rs`
- `indra-network/src/peer_manager.rs`
- `indra-node/src/driver.rs`
- `indra-node/src/net_driver.rs` or the node event loop if validation classification needs to cross layers
- Tests in `indra-network` and `indra-node`

Recommended changes:

1. Add `MessageClass::is_consensus_slot_message()` or equivalent for `Vote`, `VrfElection`.
2. In `PeerRateLimiter::check`, do not consume count-bucket tokens or return rate-limit penalties for consensus slot messages. Continue applying byte/frame limits where applicable.
3. Add a bounded duplicate filter in `PeerManagerActor` or the read task:
   - key votes by `(validator_id, height, round, step, block_hash)` for exact duplicate drop;
   - key VRF commits by `(validator_id, height, round, VrfCommit, commit_hash)`;
   - key VRF reveals by `(validator_id, height, round, VrfReveal, commit_hash, vrf_output)`;
   - cap entries and prune by insertion order.
4. Do not use this network filter to decide equivocation safety. Continue forwarding first-seen non-duplicate messages to the driver/slash detector.
5. Reorder `process_vrf_commit`:
   - check activation;
   - check `vrf_slot_index(height, round)`;
   - check duplicate/cap;
   - then verify signature/key.
6. Reorder `insert_valid_vrf_reveal` similarly where safe:
   - check slot exists before call;
   - check duplicate/cap/pending-cap where possible;
   - then run expensive signature/VRF proof validation.
7. Add a driver/node feedback path for invalid consensus messages:
   - valid duplicate/excess: no score change;
   - invalid signature/chain ID/key/proof: disconnect and score invalid;
   - equivocation vote: preserve slash evidence path.
8. Consider splitting `Status` from `PeerList` into separate rate-limit classes; status should be coalesced/dropped under stress, while PeerList should remain discovery-rate-limited.
9. Reconnect grace period is optional and should not be part of the critical VRF fix unless a separate test proves a remaining legitimate reconnect burst.

Tests needed:

1. `vrf_commit_duplicate_does_not_rate_limit_or_penalize_authenticated_validator`
2. `vrf_reveal_duplicate_does_not_rate_limit_or_penalize_authenticated_validator`
3. `vote_duplicate_does_not_rate_limit_or_penalize_authenticated_validator`
4. `invalid_vrf_commit_signature_disconnects_or_scores_invalid`
5. `invalid_vrf_reveal_proof_disconnects_or_scores_invalid`
6. `far_future_vrf_commit_is_dropped_before_signature_verification`
7. `vrf_duplicate_filter_is_bounded`
8. `vote_duplicate_filter_is_bounded`
9. `non_consensus_flood_still_rate_limited_and_can_ban`
10. `large_block_or_block_response_still_hits_byte_limits`

## Design Review Checklist

- `rate_limit.rs` read in full: complete.
- `peer_manager.rs` ban/penalty logic read: complete.
- `driver.rs` VRF dedup logic read: complete.
- `driver.rs` vote dedup logic read: complete.
- Message definitions/classes read: complete.
- Node routing for inbound/outbound consensus messages read: complete.
- Code changes made in this task: none; this document is analysis only.
