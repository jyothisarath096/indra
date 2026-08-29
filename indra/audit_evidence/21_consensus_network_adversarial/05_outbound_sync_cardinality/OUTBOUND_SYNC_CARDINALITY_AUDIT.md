# Outbound / Sync Cooldown & State Cardinality Audit

## Scope and disposition

Audit-only review of outbound dialing, discovery, synchronization cooldowns,
failure tracking, height claims, provisional/outstanding state, and expiry.
No production files were changed. Existing L3-NET-07..10 remediation changes
were treated as pre-existing.

**Final disposition: PASS WITH NON-CRITICAL FINDINGS**

## Production path

PeerList messages enter the authenticated node event loop, are limited to
`MAX_PEER_LIST_SIZE` entries, resolved, filtered, and inserted through
`insert_discovered_peer_bounded`. The discovered set is capped at
`MAX_DISCOVERED_PEERS = 256`; selection then drives the outbound dial loop.
Dial failures increment an address-keyed counter and after 20 failures remove
the candidate and reset its cooldown. Successful authenticated connections
reset address and validator cooldown keys. Sync status claims are validator
keyed and retained for 30 seconds. A sync request has one outstanding slot;
responses require exact validator/socket/range binding before projection.

## Cardinality and bounds

The discovered peer set and relay caches are hard bounded. PeerList input and
IPv6/port churn therefore cannot create unbounded dial candidates. Failure
counters are coupled to those candidates and removed on eviction/success.
`outbound_cooldowns` is a generic map without a sweep, but network-discovered
keys are bounded by the candidate set; configured bootstrap/genesis addresses
are an operator-controlled assumption.

Authenticated validator limiter state is capped by the 200-validator authority
bound. `height_claims`, outstanding, and provisional state are bounded/expired.

## Finding: historical sync cooldown keys (non-critical)

`sync_cooldowns` is a local `CooldownTracker<Bytes32>` in the sync event-loop.
It records timeout/validation failures by validator and resets successful
sources, but has no authority-epoch pruning. A sequence of legitimate authority
rotations can leave historical validator IDs in the map after their cooldown
expires. This is not attacker-controlled without causing/obtaining successive
authority rotations, and no unbounded network-address or consensus mutation was
reproduced. It is a low/medium maintenance and memory-hardening concern, not a
stop-condition finding. Recommended next action: define an epoch/lifetime prune
and add a bounded rotation regression in a later focused task.

`expensive_failure_sources` similarly retains empty outer height keys after its
inner 60-second source entries expire; `circuit_open_until` retains expired
height keys until `circuit_open` is called. The insertion path is gated by the
single outstanding/provisional sync flow and authenticated candidates, so an
attacker cannot supply arbitrary heights at wire speed. These are documented
assumptions and observability risks, not reproduced unbounded production growth.

## Adversarial cases

| Case | Result |
|---|---|
| 200,000 PeerList addresses | accepted discovery cardinality stayed 256 |
| 200,000 IPv6/port variants | same 256 bound; no fresh namespace per address beyond set |
| 200,000 outbound failure labels | only selected bounded candidates reach failure tracker; evicted entries removed |
| 200 authenticated validator IDs | bounded by authority cap; historical sync cooldown entries persist across rotation |
| 200,000 arbitrary heights | not production reachable without authenticated selected sync flow; no direct injection |
| expiry/reconnect/restart | expiry is local; process restart clears in-memory state; reconnect does not multiply discovered cap |

## Validation

The existing production tests cover bounded discovery, dial-failure eviction,
sync height-claim expiry, exact response binding, and relay cache capacities.
Commands run for this audit included `cargo test -p indra-node --lib` (286 tests
passed), `cargo fmt --all -- --check`, and `git diff --check` (clean). The
broader package/workspace commands remain the required next validation pass;
this audit added no production code and did not alter their inputs.

## Open assumptions

Configured bootstrap/genesis peer lists are finite operator input; authority
rotation frequency is protocol-governed; the sync event loop remains serialized;
and no alternate caller injects `note_expensive_failure` with attacker-chosen
heights. These assumptions should be revisited in the broader peer-churn audit.
