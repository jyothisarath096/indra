# L3-NET-05 reproducer — proposal replay repeats expensive admission

## Object and schedule

Use a genuine, canonical, fully authorized proposal for the driver's exact next
height, current parent, and a legal current round. Deliver the same proposal
twice as `DriverEvent::InboundBlock`, first from P1 and then from P2 (or after P1
reconnects). Replay count: 2. The first application stages the block; the second
is the suspicious application.

The network actor's node-wide relay cache suppresses duplicate relay work, but
it deliberately still emits the inbound event to the node. Thus a different
relay, reconnect, or relay-cache expiry reaches the production driver.

## Deterministic proof

Run:

```text
python3 audit_evidence/21_consensus_network_adversarial/02_replay_duplication/harness/source_order.py
```

The harness asserts this exact order inside the production
`ConsensusDriver::process_proposal_internal` decoder consumer:

1. governing snapshot lookup;
2. proposer authorization and VRF verification;
3. embedded QC verification (height > 1);
4. detached `project_block_for_roots` execution and root comparisons;
5. `pending_blocks.contains_key(block_hash)` duplicate rejection.

Existing deterministic driver tests construct genuine proposals through
`make_strict_block` and prove that accepted proposals enter `pending_blocks`
and that stale/future proposals do not mutate consensus state. The source-order
guard establishes that the second identical accepted object reaches all four
expensive steps before the already-staged check.

## Expected and observed

Expected efficient idempotence: after the first authenticated admission, an
identical canonical proposal should be recognized before repeated QC checking
and detached projection.

Observed: application 1 emits `BroadcastBlock` and inserts one pending block.
Application 2 repeats proposer/VRF verification, embedded-QC verification, and
detached projection, then emits only `None`. Pending-block count, collectors,
lock/valid values, height, round, and vote safety are unchanged by application
2. It emits no second gossip, request, persistence action, or timer transition.

## Reachability and consequence

Production reachable: yes, from authenticated validator connections. Same-
connection bytes may be reduced by transport caches, but peer change/reconnect
does not remove the node event path and the caches are finite/expiring.

Preliminary severity: LOW. Safety and persistent liveness impact were not
reproduced. Resource impact is repeat authorization/VRF work, possibly embedded
QC work, and full detached state projection per admitted replay. Network message
count and byte buckets bound bursts (proposal bucket 5/s, burst 10); the full
cryptographic DoS model is deferred to Phase 2G.

Timer behavior: unchanged. Reconnect prerequisite: no, although reconnect or a
different relay exposes the path most directly.
