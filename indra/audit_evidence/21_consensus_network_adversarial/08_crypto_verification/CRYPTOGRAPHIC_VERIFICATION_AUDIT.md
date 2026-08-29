# Cryptographic Verification DoS & Auth-Before-Expensive-Work Audit

## Final disposition

**PASS WITH NON-CRITICAL FINDINGS**. No unauthenticated expensive PQ path,
authority-bypass verification, or unbounded per-message signer loop was
reproduced. No production code was modified.

## Ordering results

The peer-manager authenticates the transport validator and applies the
validator-scoped limiter before dispatching messages. Consensus duplicate keys
are checked in the read task and accepted-object fast paths in the driver avoid
repeating proposal/vote verification. Votes perform height/round/step and
snapshot/authority checks before hybrid authorization and collector mutation.
Proposals perform current-context, proposer, duplicate, and VRF/QC checks before
state projection. QC responses now require an outstanding provisional request
and exact validator/socket/height before QC decoding and verification (L3-NET-10).
Block responses require exact outstanding request/range and the 50-block bound
before projection and QC verification.

## Pre-authentication cryptography

Handshake cryptography is performed only by tasks holding the inbound handshake
semaphore (50 permits), with finite command/control channels and transport frame
length bounds. Invalid/unknown handshakes do not reach consensus verification.
Repeated failed handshakes therefore consume bounded concurrent work rather than
creating an unbounded verifier queue.

## Adversarial cases

Stale/future/invalid-round votes are rejected before hybrid verification;
wrong-validator and wrong-snapshot votes cannot poison accepted replay state.
100,000 exact proposal replays and vote replays exercise the existing accepted
state/duplicate filters and do not repeat the expensive path. Wrong-peer and
wrong-height QC responses are rejected before QC verification. Malformed QC
signers/signatures fail structural and membership checks before reaching the
bounded signer verification loop. PeerList, transaction, staking, and governance
inputs remain rate limited and structurally bounded.

## Cost and residual concern

Each accepted authenticated message can still cause its protocol-mandated
cryptographic verification, and aggregate authenticated traffic can be large
across the authority set. This is a bounded policy/capacity issue reserved for a
future cryptographic performance audit, not a reproduced unbounded or
pre-authentication DoS. No verification was observed while holding the central
consensus mutex across an attacker-controlled unbounded loop.

## Validation

`cargo test -p indra-network --lib` (149 passed) and `cargo test -p indra-node
--lib` passed. `cargo fmt --all -- --check` and `git diff --check` passed.
Existing deterministic tests cover exact replay suppression, invalid-round and
wrong-snapshot rejection, QC signer bounds, L3-NET-10 source binding, frame
maximum enforcement, and authenticated rate limits.

## Open assumptions

Cryptographic microbenchmarks and full aggregate-core saturation measurements
were not run in this audit-only pass; no production instrumentation was added.
The current authority and message-rate limits remain the governing aggregate
bounds.
