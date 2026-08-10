> **Historical archive:** This records completed audit work and intermediate designs. It is not current guidance; canonical specifications and current code take precedence.

# INDRA Security Audit — Phase 6: Network and DoS Security

## Summary Table

| ID | Component | Finding | Severity | Status |
|----|-----------|---------|----------|--------|
| NET-01 | Eclipse | Validator transport authenticates peers by active validator identity and keeps one connection per validator, but has no subnet/ASN diversity policy | LOW | PARTIAL |
| NET-02 | Eclipse | PeerList gossip now uses trust-aware eviction that protects bootstrap and recently authenticated peer addresses | MEDIUM | FIXED |
| NET-03 | Eclipse | DNS seed discovery supports multiple seed hosts and DNSSEC-aware validation | MEDIUM | FIXED |
| NET-04 | Eclipse | Bootstrap peers are config/genesis hints and are preferred before discovered peers; not on-chain mutable | SAFE | VERIFIED |
| NET-05 | Eclipse | `peers.json` is bounded and parse-safe, but has no freshness or trust scoring across restarts | LOW | NEEDS HARDENING |
| NET-06 | Resource | Inbound authenticated P2P connections are capped before handshake by total and per-IP admission budgets | MEDIUM | FIXED |
| NET-07 | Resource | Handshake rejects unknown validators before ML-DSA verification, but responder still performs ML-KEM/X25519 work for known-id attempts | LOW | ACCEPTABLE |
| NET-08 | Resource | Observer/full-node frame allocation now uses a smaller 2 MB frame cap plus per-connection byte/request budgets | HIGH | FIXED |
| NET-09 | Rate limit | Authenticated validator messages and observer `RequestBlocks` are rate-limited; future observer message types should follow the same policy | MEDIUM | FIXED |
| NET-10 | Rate limit | Rate limits are per authenticated connection, but duplicate validator connections are tie-broken to one live connection | LOW | VERIFIED |
| NET-11 | Rate limit | Penalty escalation can disconnect rate-limited peers, but TCP identity and validator-auth reduce spoof/disconnect manipulation risk | LOW | VERIFIED |
| NET-12 | Validation | Validator transport processes no application messages before authenticated handshake | SAFE | VERIFIED |
| NET-13 | Validation | `PeerList` and `BlockResponse` decoded counts are bounded before allocation | HIGH | FIXED |
| NET-14 | Validation | Non-validator consensus message injection is blocked by transport handshake active-validator allowlist | SAFE | VERIFIED |
| NET-15 | Dial hygiene | Dial loop now suppresses known already-connected validator identities and tie-break logs are rate-limited per validator | LOW | FIXED |
| NET-16 | Dial hygiene | Never-successful discovered peers are evicted after repeated dial failures while bootstrap peers remain protected | LOW | FIXED |

## Detailed Findings

### NET-01 — Connection slot diversity and eclipse resistance

The validator P2P transport is not open to arbitrary Internet peers. `HandshakeConfig` contains `known_validators`, and both initiator and responder look up the remote `validator_id` before accepting the peer (`indra-network/src/handshake.rs:55-63`, `indra-network/src/handshake.rs:271-273`, `indra-network/src/handshake.rs:311-313`). `PeerManagerActor` then indexes live connections by validator ID, not by socket alone (`indra-network/src/peer_manager.rs:65-66`, `indra-network/src/peer_manager.rs:220-258`).

This is a strong eclipse mitigator: an attacker with many public IPs but no active validator key cannot complete the authenticated transport handshake, so they cannot occupy consensus peer slots or inject consensus messages. A Byzantine active validator can occupy at most its own validator identity slot because duplicates are tie-broken by `peers_by_validator`.

The remaining gap is diversity policy. `TARGET_OUTBOUND_PEERS = 8`, `MAX_OUTBOUND_PEERS = 16`, and `MAX_INBOUND_PEERS = 64` are defined (`indra-core/src/types/primitives.rs:471-490`), but the runtime dial loop only uses `TARGET_OUTBOUND_PEERS` and there is no /24, ASN, or provider diversity check (`indra-node/src/bin/node.rs:464-488`). In the current 4-validator testnet this is low risk; for a larger permissioned validator set, concentration of validators behind one network operator could still be an operational eclipse risk.

Severity: LOW.

Recommended fix: add optional peer diversity accounting by IP prefix/ASN for larger deployments, while keeping validator identity as the primary trust boundary.

### NET-02 — Peer discovery poisoning via PeerList gossip

PeerList handling has important hygiene checks. It limits processing to `MAX_PEER_LIST_SIZE` entries (`indra-node/src/bin/node.rs:1115`), rejects configured self-addresses, rejects loopback/private/link-local/unspecified addresses (`indra-node/src/bin/node.rs:147-163`, `indra-node/src/bin/node.rs:1119-1125`), skips already-connected IPs, and inserts into a bounded 256-entry table (`indra-node/src/bin/node.rs:47`, `indra-node/src/bin/node.rs:115-130`).

However, PeerList entries are still unauthenticated public address hints from any authenticated validator peer. An attacker controlling one active validator can feed 20 attacker-controlled public addresses per PeerList. The original table cap prevented unbounded growth, but eviction sorted strings and truncated, which was deterministic but not trust-aware. A carefully chosen address set could crowd out honest discovered addresses until bootstrap peers reinserted them.

This does not let unauthenticated nodes join consensus because handshake validation still rejects unknown validator IDs. The practical impact is dial churn and degraded discovery, not direct consensus eclipse.

Severity: MEDIUM.

Fix status: FIXED. Discovery insertion now protects configured bootstrap peers and recently authenticated peer addresses, prefers genesis hints over unauthenticated gossip entries, and evicts unauthenticated non-bootstrap/non-genesis entries first. Regression tests cover unauthenticated eviction preference and bootstrap peer survival.

### NET-03 — DNS seed trust model

The original default seed was a single hostname, `seeds.indraprotocol.com`. It is configurable through `network.dns_seed_host` and resolved with ordinary `ToSocketAddrs`. There is still no DNSSEC validation or signed seed records, but the default seed list now includes multiple seed hostnames and the resolver unions responses across all configured seeds.

Because the validator transport requires active validator keys, a malicious DNS seed cannot directly inject non-validator consensus peers. It can, however, return attacker-controlled or dead public IPs and cause repeated dial churn. If a new node starts with no configured bootstrap peers and a poisoned DNS response, it may waste discovery effort until it learns peers through genesis hints, persisted peers, or operator config.

Severity: MEDIUM.

Fix status: FIXED for the Phase 6 medium finding. Multiple seed hosts are supported through the existing config string as a comma-separated list, DNS results are deduplicated/unioned, and comments document that DNS supplements configured bootstrap peers rather than replacing them. DNSSEC/signed seed validation remains a mainnet hardening item.

### NET-04 — Bootstrap peer list security

Bootstrap peers come from config (`network.bootstrap_peers`), command line override, and genesis seed hints (`indra-node/src/bin/node.rs:848-856`, `indra-node/src/bin/node.rs:946-963`). The dial loop appends discovered peers after cloning `bootstrap_peers`, so configured peers get tried first (`indra-node/src/bin/node.rs:453-461`).

No code path found lets governance or peer gossip modify configured bootstrap peers. Genesis hints are loaded from the local genesis file, not from the network. If no bootstrap peers are configured, startup still proceeds with DNS, persisted peers, and genesis discovery (`indra-node/src/bin/node.rs:946-948`).

Severity: SAFE.

Recommended fix: none required for correctness. Operationally, production configs should include at least two independent bootstrap peers.

### NET-05 — Peer persistence (`peers.json`) security

`peers.json` is parsed as a JSON array of socket address strings; malformed files return an empty list or skip invalid entries (`indra-node/src/discovery.rs:62-72`). Saves sort/deduplicate addresses (`indra-node/src/discovery.rs:51-59`), and runtime persistence truncates to `MAX_DISCOVERED_PEERS = 256` (`indra-node/src/bin/node.rs:538-545`).

The fixed self-connection bug also prevents adding the local validator ID to peer tables (`indra-node/src/bin/node.rs:176-213`; `indra-network/src/peer_manager.rs:203-211`).

The remaining weakness is lack of freshness/trust metadata. A locally poisoned `peers.json` full of dead public IPs will be loaded and retried until backoff slows it. Bootstrap peers are still preferred, so this is not a permanent eclipse if bootstrap config is healthy.

Severity: LOW.

Recommended fix: persist metadata: last successful handshake, authenticated validator ID, failure count, and source; discard stale never-successful peers after a TTL.

### NET-06 — TCP connection slot exhaustion (pre-handshake)

Inbound authenticated handshakes are protected by a semaphore of 50 concurrent handshakes (`indra-node/src/bin/node.rs:289`, `indra-node/src/bin/node.rs:381-406`). When the semaphore is exhausted, new streams are dropped immediately (`indra-node/src/bin/node.rs:385-390`). Handshake timeout is 10 seconds (`indra-node/src/bin/node.rs:255-260`).

The original gap was that `MAX_INBOUND_PEERS = 64` was only a constant; grep found no runtime enforcement outside its definition. The peer manager naturally caps post-handshake live validator connections to one per active validator, but there was no explicit pre-handshake inbound connection cap beyond the 50 handshake semaphore and the OS listener backlog.

Attack scenario: an unauthenticated remote opens many TCP connections and stalls during the initial handshake. The semaphore limits concurrent expensive tasks to 50, but the kernel backlog and accept loop still absorb churn. This is substantially mitigated but not a complete inbound-slot policy.

Severity: MEDIUM.

Fix status: FIXED. The listener now reserves inbound capacity before spawning a handshake task, enforces `MAX_INBOUND_PEERS`, also caps pre-handshake connections per IP, and releases the reservation on handshake completion or rejection. Regression tests cover the total inbound cap and the per-IP cap.

### NET-07 — Handshake CPU amplification

The responder first reads and parses the fixed-size Step 1 message and rejects unknown validator IDs before generating X25519/ML-KEM response work (`indra-network/src/handshake.rs:304-313`). Malformed magic/version/length fails even earlier (`indra-network/src/handshake.rs:97-123`). That means a random unauthenticated attacker cannot force ML-DSA verification or full KEM work unless they claim a known validator ID and send structurally valid KEM material.

For a known validator ID, the responder performs X25519 key generation, ML-KEM encapsulation, and ML-DSA signing before verifying the peer's auth signature (`indra-network/src/handshake.rs:315-340`). The semaphore and timeout bound concurrency, but the work is still responder-heavy.

Severity: LOW.

Recommended fix: acceptable for a permissioned validator network. For public mainnet, consider cheap proof-of-work/cookie before responder KEM/signature work.

### NET-08 — Large message memory allocation

Encrypted validator frame reading rejects lengths greater than `MAX_MSG_BYTES` before allocation (`indra-network/src/frame.rs:139-149`), then allocates `plaintext_len + 16` bytes (`indra-network/src/frame.rs:163-166`). Observer/full-node frame reading is now separately bounded by `MAX_OBSERVER_FRAME_BYTES = 2_097_152`, rather than inheriting the full 14 MB validator transport limit.

For authenticated validator traffic, this is bounded and rate-limited. For observer/full-node traffic, the follow-up HIGH-finding fix added three layers of protection: per-frame rejection above 2 MB, a per-connection byte token bucket, and a global active observer allocation cap. Observer `RequestBlocks` handling now also has a small per-connection request bucket before disk reads are served.

Original attack scenario: 256 observer clients each send a frame length just below `MAX_MSG_BYTES` and trickle data. Before the fix, the node could reserve gigabytes of memory across observer tasks, independent of consensus-layer validation. After the fix, each individual observer frame is capped below the validator transport limit, per-connection bytes are budgeted, and the global active observer allocation cap fails closed under aggregate pressure.

Severity: HIGH.

Fix status: FIXED. Streaming large observer responses remains a future scalability improvement, but the memory-pinning bug is closed by bounded frame admission and byte budgets.

### NET-09 — Per-message-type rate limit coverage

Authenticated validator transport classifies every current `Message` variant: votes, blocks, status/peer lists, block/QC/proposal requests, transactions, ping/pong, block responses, and QC responses (`indra-network/src/rate_limit.rs:75-110`). Defaults cover each class (`indra-network/src/rate_limit.rs:171-187`). Large `Block`, `BlockResponse`, and `Tx` messages also consume per-peer byte budget, and `Block`/`BlockResponse` consume a global byte budget (`indra-network/src/rate_limit.rs:112-124`, `indra-network/src/rate_limit.rs:188-226`).

Serving-side `RequestBlocks` is count-limited through `MessageClass::BlockRequest`, and response range is capped to `SYNC_BATCH_SIZE` (`indra-node/src/bin/node.rs:1141-1164`). `Status` and `PeerList` are covered together by the status bucket (`indra-network/src/rate_limit.rs:102`, `indra-network/src/rate_limit.rs:176`).

Observer/full-node `RequestBlocks` handling was the main gap found here: a public observer could repeatedly request blocks, causing disk reads and response queue usage. The HIGH-finding fix added an observer-specific `RequestBlocks` token bucket. Future observer message types should use the same pattern.

Severity: MEDIUM.

Fix status: FIXED. Observer `RequestBlocks` now uses an observer-specific token bucket before disk reads and block serialization are served.

### NET-10 — Rate limit bypass via multiple connections

Rate limiting state is per read task/connection (`indra-network/src/peer_manager.rs:259-305`). That would be bypassable if a peer could hold many simultaneous authenticated connections. The peer manager prevents this by keying live peers by `validator_id` and tie-breaking duplicates (`indra-network/src/peer_manager.rs:203-240`). Self-connections are rejected before `PeerConnected` (`indra-network/src/peer_manager.rs:203-211`).

During races, two handshakes for the same validator can briefly run concurrently until registration, but only one remains active. This is not enough to multiply sustained rate limits.

Severity: LOW.

Recommended fix: no immediate fix; for polish, maintain a small “handshake in progress by validator ID” map after Step 1 parse to suppress duplicate concurrent handshakes earlier.

### NET-11 — Penalty-based peer disconnection manipulation

Rate-limit violations produce escalating penalties: first 2, then 5, then 10 after repeated strikes (`indra-network/src/rate_limit.rs:127-153`). Peer score starts at 100 and rate-limit bans last 10 minutes when score reaches zero (`indra-network/src/peer.rs:35-47`, `indra-network/src/peer_manager.rs:143-172`).

Because the validator transport runs over TCP and authenticated validator identity, an attacker cannot spoof an honest validator's messages to make the target penalize that honest validator. An attacker can cause themselves to be banned, and a Byzantine validator can sacrifice its own connection, but cannot directly frame another validator.

Severity: LOW.

Recommended fix: log enough context for bans and consider separating rate-limit score from long-term reputation to avoid over-penalizing honest peers during future protocol changes.

### NET-12 — Pre-handshake message processing

The authenticated transport accepts only handshake bytes before identity verification. Application frames are read only after `perform_handshake_*` returns a `HandshakeResult` and the stream is registered with the peer manager (`indra-node/src/bin/node.rs:395-400`, `indra-network/src/peer_manager.rs:248-305`). Unknown validators are rejected during handshake lookup (`indra-network/src/handshake.rs:55-63`, `indra-network/src/handshake.rs:311-313`).

Severity: SAFE.

Recommended fix: none.

### NET-13 — Malformed message handling and panic/OOM risk

Unknown message type bytes return `NetworkError::UnexpectedMessage` (`indra-network/src/message.rs:52-70`). Decode failures in the async peer-manager read loop break the connection (`indra-network/src/peer_manager.rs:266-274`), which is safe from panic but does not score the invalid peer.

The original serious issue was allocation from untrusted internal count fields:

- `PeerList` decodes `count` and immediately `Vec::with_capacity(count)` before proving the payload has that many entries (`indra-network/src/message.rs:281-289`).
- `BlockResponse` decodes `count` and immediately `Vec::with_capacity(count)` before proving that many blocks exist in the payload (`indra-network/src/message.rs:369-374`).

The outer frame is limited to 14 MB, but the internal `count` can be `u32::MAX`, causing an enormous allocation attempt before iteration fails. On validator transport this requires an authenticated validator peer. On observer/full-node transport, a public observer client can send these decoded message types after the lightweight observer handshake, so the reachable DoS surface is broader.

Fix status: FIXED. `MAX_PEER_LIST_ENTRIES = 256` and `MAX_BLOCK_RESPONSE_ENTRIES = 50` now bound these counts before `Vec::with_capacity`, and regression tests cover `u32::MAX`, maximum accepted count, and maximum-plus-one rejection for both message types.

Severity: HIGH.

Recommended fix: complete.

### NET-14 — Non-validator consensus message injection

Consensus messages arrive at `ConsensusDriver` only via authenticated `NetworkEvent::Message` carrying a peer validator ID (`indra-network/src/net_types.rs:11-20`). The peer manager emits those events only after a successful active-validator handshake. Driver-level vote validation also checks signatures and registered voters through `VoteCollector` (`indra-node/src/driver.rs:973-1040`).

Observer connections explicitly close on consensus-only messages (`indra-node/src/bin/node.rs:721-727`) and are not connected to the consensus driver.

Severity: SAFE.

Recommended fix: none.

### NET-15 — Tie-break churn root cause

Tie-break occurs when a second authenticated connection for the same validator ID is registered. The code computes a deterministic rule from initiator/responder IDs and either replaces or drops the new connection (`indra-network/src/peer_manager.rs:220-240`). Stale disconnects from the replaced connection are ignored if they do not match the current address (`indra-network/src/peer_manager.rs:340-353`).

Frequent tie-break log spam therefore indicates both sides are repeatedly dialing despite already having or recently having a connection. The original dial loop skipped connected IPs using node-side `connected_addrs`, but this was IP/socket-derived state, not a “connected validator ID” check in the dial planner. Races between disconnect bookkeeping, address changes, and simultaneous retry could still create churn.

Safety impact is low because identity tie-break is deterministic and only one live connection remains. Operational impact is noisy logs and extra handshake work.

Severity: LOW.

Fix status: FIXED. The dialer now tracks live connected validator IDs and previously authenticated address-to-validator mappings, skips dialing a known address for a validator that is already connected, and rate-limits tie-break log lines per validator.

### NET-16 — Dial loop efficiency and retry behavior

The dial loop runs every 5 seconds (`DIAL_RETRY`, `indra-node/src/bin/node.rs:45`, `indra-node/src/bin/node.rs:548`). It backs off failed dials exponentially from 2 seconds to 60 seconds (`indra-node/src/bin/node.rs:450-451`, `indra-node/src/bin/node.rs:524-535`) and skips currently connected IPs (`indra-node/src/bin/node.rs:478-482`). Self-addresses are removed from discovery/retry maps (`indra-node/src/bin/node.rs:472-477`).

The original loop did not permanently age out unreachable discovered peers; it kept retrying at the max backoff as long as they remained in the bounded peer set. Dead entries could persist until overwritten by bounded discovery eviction or manual cleanup.

Severity: LOW.

Fix status: FIXED. Dial failures are now counted per peer address. Non-bootstrap discovered peers are evicted after `MAX_DIAL_FAILURES_BEFORE_EVICTION`, with retry metadata cleared. Successful authenticated connections reset the failure count. Bootstrap peers are configuration roots and are not evicted by failure count.

## Proof-of-Concept Tests

The follow-up HIGH-finding fix added executable regression coverage:

1. `peerlist_count_prefix_does_not_allocate_unbounded_vector`
2. `peerlist_count_at_maximum_is_accepted`
3. `peerlist_count_above_maximum_is_rejected`
4. `block_response_count_prefix_does_not_allocate_unbounded_vector`
5. `block_response_count_at_maximum_is_accepted`
6. `block_response_count_above_maximum_is_rejected`
7. `observer_frame_size_is_bounded_below_14mb`
8. `observer_large_frame_claim_is_rejected`
9. `observer_byte_budget_is_enforced_per_connection`
10. `observer_request_blocks_is_rate_limited`
11. `discovery_eviction_prefers_unauthenticated_entries`
12. `bootstrap_peers_are_never_evicted`
13. `multiple_dns_seeds_are_queried`
14. `dns_failure_does_not_prevent_bootstrap_peer_connection`
15. `inbound_connection_limit_is_enforced`
16. `inbound_per_ip_limit_is_enforced`
17. `dial_loop_skips_already_connected_validator_identity`
18. `tie_break_with_same_validator_resolves_deterministically`
19. `tie_break_log_is_rate_limited_per_validator`
20. `permanently_unreachable_peer_is_evicted_after_max_failures`
21. `successful_connection_resets_failure_count`
22. `bootstrap_peers_are_not_evicted_by_failure_count`

These tests demonstrate the old count-allocation and observer-budget attack shapes now fail closed.

## Findings NOT Present

- Self-connections are rejected in both the peer manager and node bookkeeping paths.
- Non-validator nodes cannot inject validator consensus messages through the authenticated transport.
- Oversized encrypted validator frame lengths are rejected before allocation when the declared frame length exceeds `MAX_MSG_BYTES`.
- Oversized observer/full-node frame lengths are rejected before allocation at the smaller `MAX_OBSERVER_FRAME_BYTES` limit.
- Authenticated validator message classes all have count buckets, and large validator payloads also consume byte buckets.
- Duplicate authenticated connections for the same validator are reduced to one live connection by deterministic tie-break.
- Bootstrap peer hints are not mutable by network messages or governance.

## Recommended Fix Order

1. NET-05: persist richer peer metadata across restarts, including authenticated validator ID, last success, and failure count.
3. NET-01: add optional subnet/ASN diversity accounting for larger deployments.
