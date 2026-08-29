# Concurrency matrix — Phase 2C continuation

| Case | Ownership/serialization evidence | Result |
|---|---|---|
| Same validator, two sockets | `peers_by_validator` admits one connection after deterministic tie-break | No parallel live bucket observed |
| Same validator, simultaneous messages | All `InboundMessage` limiter mutation occurs in the single peer-manager actor loop | Serialized by design; stress run not performed after stop |
| Token refill boundary | Existing deterministic `last_refill` tests cover 49 ms rejection and 50 ms acceptance | Source/test identified; full validation halted |
| Disconnect while spending | Disconnect and inbound messages share the actor mailbox | Serialized; ordering-specific stress run halted |
| Pre-auth Sybil connections | Atomic global count, mutex per-IP count, and 50-permit semaphore bound concurrency | Concurrent work bounded; L3-NET-07 regression remains bounded |

## Continuation race review

The peer manager owns `limiters_by_validator`, `peers_by_validator`, and relay
state in one actor loop. The node owns cooldown maps behind mutexes; disconnect,
connect, and blocked checks lock the same map. Repeated source inspection and the
existing actor tests found no fresh limiter creation on disconnect, token
double-spend, or stale-disconnect removal of a replacement peer. A deterministic
100-iteration model of mailbox orderings (connect/connect, disconnect/connect,
message/disconnect, and refill/message) preserved one validator-keyed limiter and
one live peer. This is a serialization result, not a claim about arbitrary future
concurrency outside the actor boundary.

## Bound review

`limiters_by_validator` is keyed only after authenticated admission and is bounded
by the governing validator identity set (maximum 200 in the current protocol).
`qc_response_seen` (2,048), relay seen (16,384), and duplicate filters (512) are
explicitly bounded TTL structures. `discovered_peers` is capped at 256. The
outbound `CooldownTracker<Address>` and sync `CooldownTracker<Validator>` are
uncapped generic maps; reachable keys are currently constrained by bounded
discovery/connected-authority sources, but historical authority rotation and static
configuration cardinality are operational assumptions requiring a later focused
bound proof. No attacker-controlled unbounded growth was reproduced in this turn.

L3-NET-07 and L3-NET-08 bounded-state regressions remain established. L3-NET-09 is
tracked separately for historical namespace reclamation. Relay/request branches
remain incomplete pending the continuation audit.
