# L3-NET-06 reproducer — cross-path vote replay repeats authority verification

## Object and schedule

Construct one genuine canonical signed prevote (the same result holds for a
precommit) for the exact next height and a legal round within the driver's
accepted `current_round + 8` window. Deliver the same object twice: application
1 from P1, application 2 from P2, or application 2 after reconnect. Replay
count: 2.

The per-connection 512-entry vote filter drops an exact replay on the same
connection. The node-wide relay cache prevents second gossip/relay verification,
but the inbound event is still delivered to consensus. Its 10-minute/16,384
entry state is also finite.

## Deterministic proof

Run the evidence harness. Production tests prove exact vote duplicate filtering,
node-wide relay suppression, reconnect-resistant validator accounting, and
collector duplicate rejection. `source_order.py` additionally asserts the
driver order:

1. governing snapshot lookup;
2. `verify_vote_authority` (Ed25519/ML-DSA hybrid verification);
3. slash-detector observation;
4. `seen_round_votes` duplicate lookup.

## Expected and observed

Application 1 inserts the validator/height/round/step slot and can update its
collector, gossip once, and request a missing proposal once. Application 2 is
cryptographically verified, observed by the slash detector, then finds the same
block hash and returns without collector insertion, quorum recomputation, QC
construction, request, gossip, persistence, round change, or timer change.

The duplicate is semantically idempotent but not computationally idempotent.
Collector-local `VoteCollector::add_vote` itself rejects duplicates before
crypto; the repeated work occurs earlier in the production driver.

## Reachability and consequence

Production reachable: yes, for authenticated validator traffic arriving through
a fresh connection/source path or after finite cache expiry/eviction. Reconnect
is not required; a different relay suffices.

Preliminary severity: LOW. No safety mutation, double-signing, timer reset, or
persistent liveness impact was reproduced. Resource impact is repeated snapshot
lookup and hybrid signature verification. Validator-level accounting survives
reconnect and vote admission is rate/byte limited (20/s, burst 80), so this did
not meet the critical unbounded-work stop condition. Quantitative crypto-cost
analysis is deferred to Phase 2G.
