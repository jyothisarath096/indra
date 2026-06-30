# INDRA Operational Workaround Audit

## Executive Summary

This audit found that the major previously recurring incidents are now mostly root-caused and fixed in code, not merely hidden by state wipes: hybrid QC codec incompatibility, vote silence from sync-state gating, live/replay `last_active_epoch` divergence, mempool equal-fee nondeterminism, value-hash QC safety violation, and self-connection peer pollution all have corresponding commits and tests. The two highest-risk follow-up findings from this audit are now also fixed locally: consensus-driver stalled-height collections are capped, and peer `Status` round jumps are bounded per message. Remaining live risks are lower priority but still worth follow-up: sync rate limiting may be too aggressive during large catch-up, peer-list discovery remains permissive before handshake, and persistent tie-break churn may indicate duplicate-address dial hygiene issues.

## Incident 1 — Siddhi Round Desync

### Re-investigation finding: ROOT CAUSE CLASS FIXED / HISTORICAL TRIGGER STILL NOT REPLAYABLE

Siddhi reaching round 1358 while other validators were near round 5-10 is not explained by a single confirmed historical root cause in the current docs or git history. There are two plausible code-supported explanations:

1. **A genuine stall can naturally drive rounds very high.** `ConsensusDriver::on_precommit_timeout` advances with `self.start_round(self.current_round.saturating_add(1))` while the node stays at the same height. A node stuck for long enough can reach round 1358 without any counter-reset bug.
2. **Round sync can propagate an already-runaway round.** `process_status` accepts a peer-reported `round` and, when `height == our_height + 1`, `peer_round > current_round`, and the node is caught up, calls `start_round(peer_round)`. There is no sanity cap such as "only jump by one/few rounds" or "only trust several peers." A peer at a runaway round can pull others forward.

Code evidence:

- Round increment path: `indra-node/src/driver.rs:1218-1223`.
- Round reset paths:
  - `reset_round()` calls `start_round(0)` at `indra-node/src/driver.rs:335-340`.
  - sync catch-up calls `start_round(0)` at `indra-node/src/driver.rs:343-361`.
  - successful commit clears lock/valid state and calls `start_round(0)` at `indra-node/src/driver.rs:985-991`.
- Round jump from peer status: `indra-node/src/driver.rs:1058-1074`.
- Sync block import path calls `d.reset_round()` for every imported block at `indra-node/src/bin/node.rs:1169-1183`.

Conclusion: I found no path where a committed height advances without a round reset. The round-1358 symptom most likely means siddhi did not commit that height for a long time, or it accepted a high peer `Status.round`. The later self-connection peer pollution bug is a plausible shared cause because peer starvation can prevent proposals/votes/commits while the timeout loop continues advancing rounds. The exact historical trigger is still not replayable from retained evidence, but the live code-level hazard is now fixed: a single `Status` message can advance the local round by at most `MAX_ACCEPTED_ROUND_JUMP` instead of teleporting directly to an arbitrary peer-claimed round.

Status: **FIXED locally.** Round-jump sanity and warning logs were added. Multi-peer corroboration is intentionally deferred because a 4-validator network with partial connectivity can deadlock if a node requires multiple matching statuses before any catch-up jump.

## Incident 2 — Repeated Stalls: Fix Verification

### Status of each prior fix: VERIFIED FIXED

| Stall / failure | Doc reference | Root cause | Fix commit | Verified? |
|---|---|---|---|---|
| Height 25885 / replay state-root mismatch after restart | `docs/DETERMINISM_AUDIT_PHASE2.md` | Live-only QC signer liveness update mutated `last_active_epoch` outside canonical `apply_block`; replay skipped it. | `6ccede5 fix: Phase 2 determinism — last_active_epoch and mempool tiebreaker` | Yes. Report marks fixed; code now moves QC signer `last_active_epoch` update into canonical state transition, and snapshot/replay tests cover it. |
| Height 9872 / possible nondeterminism after wipe | `docs/DETERMINISM_AUDIT_PHASE2.md` | Equal-stake tiebreaker was suspected but found safe; actual fixed issues included live/replay `last_active_epoch` and mempool tiebreakers. | `6ccede5`, plus earlier `17e252a` / `a1aa658` determinism fixes | Mostly yes. The original height-9872 exact trigger is not fully reproduced in the report, but the concrete bugs found were fixed and tested. |
| Height 3 vote silence / no votes after startup | `docs/VOTE_SILENCE_DIAGNOSTIC.md` | `SyncState::mark_caught_up` set phase to `CaughtUp` but not `received_peer_status`; followers silently refused to prevote before first 6s status heartbeat. | `b14a99c fix: vote silence — mark_caught_up sets received_peer_status=true` | Yes. Code changed and sync tests exist (`mark_caught_up_sets_received_peer_status`, follower status tests). |
| Hybrid QC deployment stall | `docs/HYBRID_QC_DIAGNOSTIC.md` | New QC decoder expected classical signatures for all QCs; old/persisted PQ-only QC bytes failed decode. | `be14848 fix: hybrid QC codec compatibility — version byte for backward compat` | Yes. QC format version tests exist in core QC tests. |
| Height 4 / multi-tip safety violation | `docs/CONSENSUS_SAFETY_DIAGNOSTIC.md` | Votes/QCs certified `value_hash` while chain tip used full `block_hash()`, allowing different staged full headers to be committed for the same certified value. | `d5b2c6c fix: consensus safety v2 — votes/QCs certify full block_hash()` | Yes. Driver tests now assert votes target full `block_hash`, competing same-value proposals cannot both reach quorum, and reproposals vote their own full hash. |
| Self-connection peer-table pollution after long uptime | Current task context / git log | Authenticated self-connections were accepted into peer bookkeeping and persisted discovery, producing thousands of self ephemeral addresses. | `21e087f fix: reject self-connections at handshake and bookkeeping layers` | Yes for the exact vector. Node and peer-manager tests cover self identity rejection; discovered peer cap test exists. |

Overall conclusion: most repeated stalls were not merely "fixed by wipe"; the codebase now contains matching fixes. The remaining caution is that some incidents were diagnosed after the fact and the original production/log state is gone, so the fixes are verified by targeted tests rather than replaying the exact historical runtime.

## Incident 3 — Rate Limiter Aggressiveness

### Finding: DANGEROUS / NEEDS FIX

The rate limiter can still penalize legitimate catch-up sync bursts.

Code evidence:

- `PeerRateLimiter::new` gives `BlockResponse` only `TokenBucket::new(2, 4)` at `indra-network/src/rate_limit.rs:171-181`.
- Large block/block-response bytes also consume a per-peer byte bucket of 32 MiB/s with 64 MiB burst at `indra-network/src/rate_limit.rs:183-186`.
- `BlockResponse` messages are classified as large/global-byte-limited at `indra-network/src/rate_limit.rs:102-123`.
- On rate-limit violation, peer manager applies an escalating penalty and may ban/drop the peer for sustained violations at `indra-network/src/peer_manager.rs:180-207`.
- Sync requests up to `SYNC_BATCH_SIZE = 50` blocks in one response (`indra-node/src/sync.rs:27`) and request continuation immediately after processing a response (`indra-node/src/bin/node.rs:1157-1220`).

Why this matters:

- The count bucket permits only 4 block responses as burst and refills at 2/sec. If a catching-up node asks repeatedly and a serving peer answers quickly, this is near the limit even when behavior is honest.
- The byte bucket may also trip if blocks are large. The current maximum block size is high enough that a single 50-block batch could be much larger than the burst limit in worst case.
- The earlier observed log `penalty=-10` means the strike counter had escalated past 5 violations, consistent with sustained repeated legitimate sync responses being dropped.

Counterpoint:

- `BlockResponse` is a response to a local `RequestBlocks`, so abusive inbound unsolicited responses are less likely from honest peers. But the rate limiter does not currently correlate responses to outstanding requests or scale allowance by requested range.

Conclusion: this is still a live operational risk for long restart/catch-up after downtime. It may not be causing current stalls, but it is the same shape as the self-connection issue: hidden after wipes, triggered by extended operation/restart sync.

Recommended fix direction: add request-correlated sync allowances, raise/disable count penalties for valid `BlockResponse` within requested ranges, and rate-limit by bytes/validated range rather than raw message count.

## Incident 4 — Tie-Break Connection Churn

### Finding: SYMPTOM OF DEEPER ISSUE

The tie-break logic itself is normal P2P behavior: simultaneous bidirectional dials are resolved deterministically by comparing initiator/responder validator IDs.

Code evidence:

- Duplicate connection handling is in `PeerManagerActor::register_peer`.
- If a connection to the same validator already exists, the actor computes `(initiator_id, responder_id)` and keeps the new connection only if `initiator_id < responder_id`; otherwise it logs "keeping existing connection ... dropping new ..." and returns.
- This starts at `indra-network/src/peer_manager.rs:252-263`.

Benign case:

- Two validators dial each other at the same time during startup. One connection is kept, one is dropped. A short burst of tie-break logs is expected.

Suspicious case:

- The log appearing every few seconds for days suggests the dialer repeatedly attempts to connect to an already-connected validator.
- The dial loop skips peers by connected IP (`has_connected_ip`) and stops at `TARGET_OUTBOUND_PEERS`, but it merges bootstrap peers and discovered peers every cycle. If the same validator is reachable through different IP strings/ports, or discovery contains ephemeral/self/stale addresses, it can redial unnecessarily.
- This is related to the self-connection root cause: discovery accepted addresses without validator identity until after handshake. The self-fix now rejects own identity after handshake, but it does not fully solve "multiple addresses for same remote validator" churn.

Conclusion: occasional tie-break logs are benign; persistent high-frequency tie-break logs are an operational smell and likely indicate discovery/dial hygiene issues. The recently-added self-connection fix should reduce the worst case, but duplicate remote-address churn remains possible.

Recommended fix direction: maintain an address-to-validator cache for rejected/replaced connections, suppress dialing alternate addresses for a validator already connected, and track dial attempts per validator, not only per socket/IP string.

## Unbounded Collection Growth — Findings

| Collection | Location | Bounded? | Risk |
|---|---|---|---|
| `ConsensusDriver.vote_collectors` | `indra-node/src/driver.rs` | **Now bounded** | **Fixed.** Pruned to `MAX_STALLED_HEIGHT_ENTRIES` by height/round distance from the current slot. |
| `ConsensusDriver.pending_blocks` | `driver.rs` | **Now bounded** | **Fixed.** Pruned to the closest current-height/current-round staged blocks. |
| `ConsensusDriver.future_proposals` | `driver.rs` | **Now bounded** | **Fixed.** Existing height-window pruning remains; total retained future proposals and per-key vectors are capped. |
| `ConsensusDriver.buffered_votes` | `driver.rs` | **Now bounded** | **Fixed.** Unknown-proposal vote buffers are capped while stalled. |
| `ConsensusDriver.requested_proposals` | `driver.rs` | **Now bounded** | **Fixed.** Missing-proposal request keys are capped while stalled. |
| `ConsensusDriver.seen_round_votes` | `driver.rs` | **Now bounded** | **Fixed.** First-vote tracking is capped while stalled. |
| `ConsensusDriver.pending_precommit_quorum` | `driver.rs` | **Now bounded** | **Fixed.** Buffered precommit-quorum keys are capped while stalled. |
| `Node discovered_peers` | `indra-node/src/bin/node.rs`, `HashSet<String>` | **Now capped at 256** | **Fixed for exact self-pollution vector.** Still accepts arbitrary public addresses from peer gossip. |
| `retry_after` / `retry_delay` | `node.rs`, `HashMap<String, Instant/Duration>` around dialer | Not globally capped; entries removed on successful/skipped connected IP | **Medium.** Failed DNS/gossip/stale addresses can accumulate retry state, though discovered peer cap limits one source. Bootstrap list is uncapped by config. |
| `connected_addrs` | `node.rs` `HashMap<IpAddr, usize>` | Bounded by connected peers if disconnects cleanly | **Low.** Self-connection fix reduces pollution. Stale disconnect handling should decrement/remove. |
| `peer_addrs` / `addr_validators` | `node.rs` | Bounded by authenticated connected validator count if disconnects cleanly | **Low.** Self identity is now rejected. |
| `PeerManager.peers_by_validator` | `indra-network/src/peer_manager.rs:76` | Bounded by validator identities actually connected | **Low.** Duplicate validators are tie-broken; self is now rejected. |
| `PeerManager.validator_by_addr` | `peer_manager.rs:77` | Bounded by connected managed peers | **Low.** Cleaned in `drop_peer`. |
| `PeerTable.peers` | `indra-network/src/peer.rs:167` | Bounded by `MAX_PEERS` in `PeerTable::add` | **Low.** It has a hard cap, though the surrounding node discovery table previously did not. |
| `Mempool.entries` | `indra-consensus/src/mempool.rs:83` | Bounded by `config.capacity` | **Safe.** Submit enforces capacity and deterministic eviction at `mempool.rs:155-184`; selection ties are deterministic at `235-260`. |

Most concerning pattern: consensus-driver collections depend on height advancement for cleanup. When the node is stuck, the exact state that needs bounding most is least likely to be pruned.

## Missing Identity/Sanity Checks — Findings

1. **FIXED: Peer `Status.round` large local round jumps.**
   - `process_status` now caps each peer-induced round advance to `MAX_ACCEPTED_ROUND_JUMP`.
   - Oversized claims are logged and advanced gradually instead of being trusted as an arbitrary jump target.
   - This addresses the best code-level explanation for propagating "round 1358" once one node is already stuck.

2. **MEDIUM: Peer `Status.height` can drive sync target to arbitrary high values.**
   - `SyncState::observe_status` sets `best_peer_height = max(best_peer_height, peer_height)` and requests blocks toward that height.
   - Empty responses can reduce best height only if `local_height >= best_peer_height - 1`, so implausibly high peer heights can keep a node in download mode longer than needed.
   - Blocks are still verified before import, so this is availability/resource risk, not direct safety risk.

3. **MEDIUM: PeerList accepts arbitrary routable-looking addresses without validator identity.**
   - `Message::PeerList` entries are parsed and filtered only against exact local configured address and currently connected IPs.
   - There is no rejection of loopback/private/link-local/public-self IPs (except exact configured self), no per-sender reputation effect for bad addresses, and no validation that an address belongs to an active validator before it enters discovery.
   - The self-connection fix catches own validator identity after handshake; it does not prevent all dial churn from invalid/stale addresses.

4. **LOW/MEDIUM: RequestProposal fallback still accepts `value_hash` as well as full `block_hash`.**
   - `node.rs` request handling serves a proposal if either `block.header.block_hash() == hash` or `block.header.value_hash == hash`.
   - This is likely backward-compatibility from the pre-v2 value-hash vote era. Since current votes request full hashes, keeping the value-hash fallback can reintroduce ambiguity if old peers or stale logic request by value hash.

5. **LOW: Successful vote/broadcast paths remain mostly unlogged.**
   - Prior vote-silence diagnosis showed "no vote logs" was ambiguous. The code has added a sync-gate diagnostic, but successful votes still do not log by default.
   - This is not a correctness bug, but it slows future diagnosis and makes workarounds more tempting.

## Time-Bomb Conditions — Findings

1. **Round runaway at one height.**
   - `current_round` is `u32` and advances with `saturating_add`; it will not wrap, but it can grow indefinitely in practice while stalled.
   - The worst memory-pressure side effect is now mitigated because consensus-driver per-height/round collections are capped.
   - Peer `Status` can no longer jump a node directly to an arbitrary high round in one message.

2. **Epoch boundary paths are tested, but live soak coverage still matters.**
   - Unit/integration tests include epoch transition boundaries and replay determinism, but operational testnet wipes can still hide multi-epoch liveness/reward behavior, especially validator inactivity and peer churn.
   - The codebase has tests for epoch transition, timestamp safety, and replay, so this is a coverage/soak concern rather than an identified bug.

3. **Long restart/catch-up sync.**
   - Sync requests 50-block batches. Rate limiting and global byte buckets may be fine in normal blocks but can fail under large block bursts or many rapid responses.
   - A fresh wipe hides this because nodes start near genesis together and do not perform large catch-up from peers.

4. **Peer discovery over many hours.**
   - The self-connection fix caps discovery and rejects own identity, but long uptime can still accumulate stale/unreachable peer hints up to the cap and retry maps for repeated failures.
   - Soak tests should inspect both `peers.json` size and dial-failure rates, not just chain height.

5. **Validator set changes / active key availability.**
   - `verify_block_qc` and `verify_proposer_vrf` require all active validators to have verification/VRF keys. This is correct for current staking rules, but a bad validator registration or migration gap could become an availability cliff at epoch transition.
   - Existing registration tests cover VRF key storage, but live validator-set churn should be included in soak.

## Ranked Findings

1. **FIXED — Consensus-driver unbounded buffers while stalled.** `buffered_votes`, `requested_proposals`, `vote_collectors`, `seen_round_votes`, `pending_blocks`, `future_proposals`, and `pending_precommit_quorum` are now capped.
2. **FIXED — Unsanitized round jumps from peer `Status`.** Peer-induced jumps are now capped and logged.
3. **MEDIUM/HIGH — Rate limiter can penalize legitimate sync responses.** The `BlockResponse` count bucket is low relative to burst catch-up behavior, and penalties can escalate to disconnect/ban.
4. **MEDIUM — Persistent tie-break churn indicates dial/discovery hygiene gaps.** Tie-break itself is benign; frequent spam means redial attempts are not being suppressed by validator identity.
5. **MEDIUM — PeerList still accepts arbitrary addresses pre-handshake.** Self identity is fixed post-handshake, but invalid/stale/private/alternate-address churn can still consume dialer effort.
6. **LOW/MEDIUM — `RequestProposal` can still serve by `value_hash`.** This is a compatibility footgun after full-hash voting.
7. **LOW — Diagnostic blind spots remain.** Successful vote paths and some silent drops can make the next time-bomb look like "nothing is happening."

## Recommended Next Steps

1. **Completed locally: bound consensus-driver per-height/round collections.** Caps and eviction policies now cover `buffered_votes`, `requested_proposals`, `vote_collectors`, `seen_round_votes`, `pending_blocks`, `future_proposals`, and `pending_precommit_quorum`.
2. **Completed locally: sanitize peer status round claims.** Round jumps are capped and oversized claims are logged. Corroboration for large jumps remains a possible future hardening item.
3. **Make sync rate limiting request-aware.** Exempt or raise allowances for valid `BlockResponse` messages matching outstanding `RequestBlocks`, and enforce byte/range limits instead of a small raw message-count bucket.
4. **Reduce duplicate connection churn by validator identity.** Track known validator-to-address mappings and suppress dialing alternate addresses for already-connected validators. Add a metric/log counter for tie-break frequency per peer.
5. **Harden PeerList ingestion.** Reject loopback/private/link-local addresses unless explicitly configured for local dev; rate-limit bad peer hints per sender; consider storing discovered addresses as untrusted until a successful handshake maps them to a non-local validator.
6. **Remove or gate `value_hash` fallback in proposal serving.** Current consensus votes request full block hashes; value-hash fallback should be legacy-gated or removed after testnet wipe.
7. **Add operational soak assertions.** During 2h/24h soaks, track: max round at each height, size of each driver collection, `peers.json` size, dial failures by IP, tie-break count, rate-limit penalties, and sync request/response throughput.
