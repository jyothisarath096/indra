# Project INDRA — Layer 3 Phase 2B replay/duplication audit

## Scope and disposition

This was an audit-only review of production replay, duplicate, stale, future,
request/response, reconnect, and timer behavior. No production source was
changed. L3-NET-01 through L3-NET-04 remain closed; no regression evidence was
found and none was reopened.

Two production-reachable, bounded repeated-work anomalies were reproduced. No
replay caused conflicting safety state, double-signing, stale-state revival,
unbounded state growth, recursive amplification, or timer suppression.

## Production replay call graph

```text
authenticated encrypted frame
  -> FrameReader nonce/replay check
  -> Message::decode_framed_wire (exact canonical frame/payload)
  -> connection-local vote duplicate filter / Status coalescer
  -> PeerManagerActor::handle_control
       -> node-wide QCResponse exact-wire cache
       -> validator/per-peer rate and byte accounting
       -> relay_seen for Proposal/Vote (relay crypto + gossip only once)
       -> NetworkEvent::Message (still delivered for Proposal/Vote duplicates)
  -> node event dispatcher
       -> ConsensusDriver::process Proposal/Vote/Status/QC request/response
       -> SyncState::accept_response for BlockResponse
       -> bounded request handlers for Proposal/Block/QC requests
  -> structural height/round/parent/request-binding checks
  -> snapshot and cryptographic validation where admitted
  -> bounded pending/collector/sync mutation
  -> DriverAction emission
```

The transport nonce rejects replay of the same encrypted frame, but a peer can
send a newly framed copy of the same canonical message. This audit therefore
uses semantic object replay, not only ciphertext replay.

## Deduplication mechanisms

- Votes: a 512-entry FIFO per read task uses validator, height, round, step,
  block hash, and canonical content hash. It is before actor/rate/crypto but
  resets on reconnect. A node-wide 16,384-entry, 10-minute relay cache survives
  reconnect and peer changes, but controls relay work rather than node delivery.
- Proposals: the same node-wide relay cache prevents repeated gossip. Driver
  `pending_blocks` provides state idempotence and is bounded to 256 stalled
  entries, but its lookup follows full proposal admission.
- Driver votes: `seen_round_votes`, collectors, evidence, buffers, requested
  proposals, and pending quorum sets are height/round pruned and capped at 256.
- QCResponse: node-wide SHA-256 canonical-wire cache, capacity 2,048, TTL 10
  minutes, before node delivery. The driver additionally accepts only the
  current committed height while its persisted last QC is stale.
- Sync responses: exactly one outstanding request bound to validator identity,
  socket address, and range. Acceptance consumes it before block validation;
  replay has no outstanding binding.
- PeerList: canonical-wire hash cache, capacity 10,000, TTL 30 seconds.
- Status: 500 ms connection coalescing plus validator-ID-keyed height claims
  expiring after 30 seconds. One outstanding sync request prevents request
  multiplication.

Full field-by-field results are in `replay_matrix.csv`.

## Vote replay results

Same-connection identical votes are dropped before actor admission. Reconnect,
a distinct relay peer, expiry, or eviction can deliver the same vote to the
driver. A previously seen vote then repeats snapshot lookup and full hybrid
authority verification before `seen_round_votes` returns. It cannot insert into
the collector twice, recompute a new quorum/QC, gossip twice, issue a second
proposal request, mutate vote safety, or reset a timer. This is L3-NET-06.

VoteCollector's direct `add_vote` path checks validator duplication before its
own crypto verification. The inefficiency is specifically at the earlier node
driver admission boundary.

## Proposal replay results

A current-height genuine proposal is relayed and staged once. A later identical
proposal is snapshot-checked, proposer/VRF-verified, embedded-QC-verified for
height > 1, and detached-state-projected before the pending-block check returns
`None`. It cannot insert twice, gossip twice, change lock/valid value twice,
produce a vote twice, or alter the timeout deadline. This is L3-NET-05.

After round or height advancement, the proposal is either in bounded current
state or rejected by height/selection guards. Finalized-height proposals are
rejected before snapshot/crypto. Future proposals are not buffered (L3-CS-02).

## QC replay results

There is no standalone QC gossip variant. QCs occur embedded in proposals or as
raw exact-decoded `QCResponse` payloads. Exact duplicate responses are removed
node-wide before driver lookup. Once one response updates `last_qc_bytes`, the
stale guard makes later distinct-but-valid QCs for that height no-ops before
signature-set verification. Embedded-QC replay inherits proposal behavior; the
bounded short-lived QC verification cache can reduce repeated signature-set
work, but proposal authentication/projection remain repeated.

No repeated QC caused a second transition, sync trigger, gossip, or request.

## Stale and future messages

Finalized/previous-height proposals and votes fail the driver height guard before
snapshot lookup and crypto and cannot revive collectors, lock/valid values, or
finality. Future proposals at next-height+1 and beyond are dropped rather than
buffered. Votes must match the exact next height; only rounds through
`current_round + 8` can enter bounded evidence/collectors. Advancement still
requires authenticated strict >2/3 stake. Rounds 1024 and `u32::MAX` fail closed;
round 1023 is legal but also subject to the +8 window.

See `stale_future_matrix.csv` for every tested boundary and effect.

## Request and response replay

- RequestProposal has no semantic request cache. Each accepted replay performs
  pending/store lookup and sends at most one matching ordinary Block response.
- RequestBlocks similarly repeats a capped storage range read, serialization,
  and one response. BlockResponse is capped at 50 entries and transport/rate
  bounded.
- RequestQC repeats current/retained-height lookup and one response if present.
- BlockResponse replay is rejected by the consume-once outstanding binding.
- Dependency request/response messages do not exist. `pending_dependencies.rs`
  maintains local reverse indexes only.
- A separate ProposalResponse message does not exist; proposals are returned as
  ordinary Block messages. “Sync request/response” maps to RequestBlocks and
  BlockResponse.

Repeated request service is intentional and bounded but not semantically
deduplicated. The full amplification/rate-limit assessment remains deferred.

## Reconnect and alternate-source behavior

The per-connection vote cache and Status coalescer reset. Actor-wide relay,
QCResponse, validator score, and validator-accounting state survive connection
replacement; driver consensus state survives. Sync disconnect removes the old
source binding and outstanding request, so a response from the old path is not
accepted. Reconnect exposes repeated validation for proposals/votes but did not
multiply persistent mutation or validator-level admission accounting.

## Timer interaction

The node owns one timer origin and resets it only for an observed
height/round/phase transition, explicit peer/sync pause-resume, or an actual
timeout transition. Duplicate handlers returning no state change do not touch
it. Timeout methods are phase-guarded, so a stale duplicate timeout cannot cause
a second transition. `timer_replay_matrix.md` records boundary schedules. No
indefinite timer suppression or concurrent timer creation was reproduced.

## Idempotence and repeated work

All consensus-critical applications were semantically idempotent:

- vote two: same collector size, quorum, QC, lock, vote safety, and actions;
- proposal two: same pending map, lock/valid values, height/round, and actions;
- QCResponse two: unchanged last QC/finality;
- BlockResponse two: rejected before import because its binding was consumed.

The exceptions are computational: L3-NET-05 repeats proposal verification and
projection; L3-NET-06 repeats vote authority verification across source paths.
Request replays repeat bounded reads/serialization/outbound traffic. None is
attacker-unbounded state, and all network entry is authenticated and subject to
message/byte admission controls. Phase 2G should quantify cost rather than infer
DoS severity here.

## Findings

### L3-NET-05 — proposal duplicate check follows expensive admission

- Preliminary severity: LOW
- Production reachable: yes
- Safety impact: none reproduced
- Liveness impact: no persistent effect reproduced
- Resource impact: repeated proposer/VRF, embedded-QC, and detached projection
- Replay prerequisite: one genuine valid current-height proposal
- Reconnect prerequisite: no; alternate relay/cache expiry also suffices
- Reproducer: `L3-NET-05_REPRODUCER.md`
- Recommended next action: quantify projection/QC cost and admission budgets in
  Phase 2G; independently review whether a safe authenticated-object cache or
  earlier exact pending check is appropriate.

### L3-NET-06 — cross-path vote duplicate check follows hybrid verification

- Preliminary severity: LOW
- Production reachable: yes
- Safety impact: none reproduced
- Liveness impact: no persistent effect reproduced
- Resource impact: repeated snapshot lookup and Ed25519/ML-DSA verification
- Replay prerequisite: one genuine valid current-height vote
- Reconnect prerequisite: no; a different relay suffices
- Reproducer: `L3-NET-06_REPRODUCER.md`
- Recommended next action: quantify hybrid verification cost and actor/driver
  cache interactions in Phase 2G; preserve equivocation detection semantics in
  any later design review.

## Anomalies investigated but not classified as findings

- Requests are not semantically deduplicated, but each request produces at most
  one bounded response and is authenticated/rate-limited.
- Status replays replace validator-keyed claims and cannot advance consensus
  round; one outstanding sync request prevents storms.
- Alternative valid QC signer subsets are distinct cryptographic certificates,
  not wire ambiguity; after recovery the last-QC freshness guard prevents work.
- Relay/QC caches evict and expire, but eviction restores only bounded validation
  work, not persistent duplicate mutation.

## Open assumptions

- This phase did not quantify ML-DSA, QC, detached projection, database, or
  serialization costs; that belongs to Phase 2G.
- Restart persistence was evaluated structurally: finalized height and vote
  safety persist, while ephemeral caches reset. No live multi-process restart
  adversary harness was added.
- Concurrent duplicate arrival is serialized through the peer-manager actor and
  driver mutex; no second writer to driver state was found.
- Existing workspace modifications predate this audit. Only this evidence
  directory was created by Phase 2B.

## Validation

All required commands completed successfully on 2026-08-21:

| Command | Result |
|---|---|
| `bash audit_evidence/21_consensus_network_adversarial/02_replay_duplication/harness/run_replay_audit.sh` | PASS; eight focused production tests plus both source-order assertions |
| `cargo test -p indra-network` | PASS; 140 library + 4 integration tests, 1 ignored |
| `cargo test -p indra-consensus` | PASS; 59 library + 5 integration tests |
| `cargo test -p indra-node` | PASS; all library, binary, 79 node-binary, and 15 integration tests |
| `cargo test --workspace` | PASS; all workspace and doc tests, only declared ignored tests ignored |
| `cargo test --workspace --no-run` | PASS |
| `cargo fmt --all -- --check` | PASS |
| `git diff --check` | PASS |

CSV schema validation (`python3` `csv.reader`) reports 22 columns for every
`replay_matrix.csv` row and 8 columns for every `stale_future_matrix.csv` row.
`bash -n` also accepts the deterministic harness.

`git status --short` was dirty before this phase across numerous production and
prior-audit files. Phase 2B added only
`audit_evidence/21_consensus_network_adversarial/02_replay_duplication/`; those
pre-existing modifications are not attributed to this audit.

## Final disposition

PASS WITH NON-CRITICAL FINDINGS
