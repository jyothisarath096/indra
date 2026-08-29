# Peer Topology / Discovery Poisoning / Eclipse Resistance Audit

## Final disposition

**PASS WITH NON-CRITICAL FINDINGS**. No deterministic full eclipse of an honest
node was reproduced with less than one-third Byzantine authority. A discovery
poisoning/churn hardening concern is documented.

## Topology and selection

The node targets 8 outbound peers and permits 64 inbound peers, with an inbound
per-IP cap of 3. Authenticated peer-manager state is one logical peer per
validator and replacement uses deterministic initiator tie-breaking. Discovery
accepts at most 20 PeerList entries per message and stores at most 256 addresses.
Outbound selection resolves/deduplicates socket addresses, shuffles candidates,
and enforces network-group diversity plus source reservations.

## Discovery poisoning result

A single authenticated validator can advertise many distinct addresses before
those addresses authenticate. The 256-entry set therefore counts addresses, not
validator identities. When full, eviction chooses the lexicographically smallest
non-authenticated, non-bootstrap/genesis entry; a new honest address can evict an
attacker entry, so saturation is not permanent. However, repeated attacker
PeerLists can continuously churn the bounded candidate set and influence dial
opportunities. After authentication, duplicate validator registration collapses
to one logical peer and cannot multiply active validator slots.

IPv6/port multiplicity has the same bounded behavior. Candidate share can be
attacker-heavy (especially with 10+ addresses per Byzantine validator), but
randomized diverse dialing, configured/genesis reservations, and independent
outbound targeting prevent a deterministic full eclipse in the tested model.

## Bootstrap, restart, and inbound behavior

Configured bootstrap/genesis peers are independent trusted roots and are not
evicted by ordinary discovery. Persisted discovery is sanitized and reinserted
through the same 256-entry bound. Inbound connections cannot satisfy the
outbound target; the node continues dialing when outbound count is below 8.
Restart preserves configured peers and bounded persisted discovery while clearing
in-memory cooldowns; it does not create additional logical validator slots.

## Finding (low hardening)

Discovery admission is address-weighted before authentication. An attacker with
one or a few valid validator credentials can consume many candidate slots using
address multiplicity and cause bounded dial churn. This is a discovery-quality
and reconnection-latency risk, not a reproduced full/practical eclipse or
consensus safety failure. Recommended next action is a focused policy review of
pre-auth candidate diversity/validator provenance; no remediation was performed.

## Validation and assumptions

Existing node discovery tests pass, including bounded table, authenticated-peer
protection, deterministic eviction, PeerList limits, and outbound target tests.
`cargo test -p indra-network --lib`, `cargo test -p indra-node --lib`, formatting,
and diff checks passed in the preceding Phase 2D audits. No production code was
changed. The model assumes configured bootstrap/genesis addresses are honest or
operationally controlled and that randomized OS entropy is not adversarially
predictable.
