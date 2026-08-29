# Relay-Origin Attribution & Cross-Relay Multiplication Audit

## Final disposition

**PASS** for this subphase. No L3-NET-10 HIGH/CRITICAL condition was reproduced. No production code was modified.

## Attribution map

| Message | Transport identity | Signed/logical identity | Limiter | Peer score/penalty | Dedup/relay exclusion | Consensus identity |
|---|---|---|---|---|---|---|
| Vote | authenticated `InboundMessage.validator_id` / socket address | `Vote.validator_id` and signed fields | authenticated transport validator | transport address/validator | canonical vote key includes signed validator, slot, block hash, content hash | signed validator and snapshot authority |
| Block/proposal | authenticated transport validator/address | proposer ID in signed block header | transport validator | transport address/validator | block key includes proposer slot, block hash, content hash | signed proposer and governing snapshot |
| QC/QC-bearing response | authenticated transport validator | QC signer set/object | transport validator; exact QC-response cache is node-wide bounded | transport peer for rate-limit violations | bounded wire-hash QC response cache | QC verification authority |
| Tx/StakingOp/GovernanceOp | authenticated transport validator/address | operation signer embedded in signed operation | transport validator | transport peer | operation relay seen state where applicable | operation signer in state validation |

## Production path

`FrameReader` decodes a message and the connection task sends
`PeerManagerMessage::InboundMessage { validator_id: peer_validator_id, addr,
msg, msg_size }`. The peer-manager actor applies the validator-keyed limiter and
global byte limiter, then calls `relay_if_eligible(validator_id, &msg)` and emits
`NetworkEvent::Message { from: addr, validator_id, msg }`. Relay verification looks
up the embedded vote/proposer identity in current `relay_keys`; it does not trust
the transport identity for the signature. The node converts the event to a driver
event. Invalid consensus actions are passed to `NetworkBridge::disconnect_invalid_consensus_peer(addr, ...)`,
which resolves the validator from the authenticated address map, thereby charging
the transporter rather than the claimed signer. Consensus equivocation evidence is
constructed from the cryptographically signed vote identity.

## Results

- A cannot consume B's validator limiter: **No**. Limiter entries are keyed by the authenticated transport validator.
- A cannot peer-penalize B with crafted traffic: **No**. Disconnect/score resolution uses the supplied transport address.
- Same-validator multiple sockets multiply allowance: **No observed**. Peer manager retains one validator connection with deterministic tie-break and one shared limiter.
- Cross-peer duplicates multiply expensive work: **No unbounded multiplication**. Per-connection duplicate filters, node-wide bounded QC cache, canonical vote relay keys, and relay-seen cache suppress repeated forwarding; a duplicate arriving on another peer may reach the actor's bounded checks but does not bypass validator-level limits.
- Invalid-first cache poisoning: **No**. Relay seen state is recorded only after relay verification; consensus duplicate state is recorded only after authoritative admission.
- Relay cycles: **Suppressed** by sender exclusion, forwarded-to tracking, TTL, and bounded relay cache.
- Equivocation attribution: **Signer B** for cryptographic slash evidence; **transporter A** for network penalties.
- Signer spoofing: A may transport a legitimately signed B object (supported relay behavior), but cannot forge B's signature or redirect A's network penalty to B.

## Deterministic test evidence

Existing peer-manager tests passed for exact vote duplicate filtering, relay duplicate
suppression, relay target exclusion, successful-enqueue tracking, invalid relay
signature rejection, transport slash-detector behavior, relay metrics, and
validator-keyed near-duplicate budgets. Existing node/driver tests passed for forged
votes, conflicting votes, and invalid consensus disconnect handling. These tests
cover A→B cross-peer logical duplicates, invalid claimed identities, and signer-vs-
transporter attribution without modifying production code.

The 80-token vote boundary and reconnect persistence tests also passed; the same
validator limiter remains actor-owned across replacement connections. Relay fanout
is bounded by the configured 4..16 validator fanout (blocks capped at 24).

Request/response families, outbound/sync cooldown cardinality, and generic connection
races are intentionally outside this subphase.
