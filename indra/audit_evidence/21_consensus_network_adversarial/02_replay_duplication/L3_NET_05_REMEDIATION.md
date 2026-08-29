# L3-NET-05 Remediation Evidence

Status: remediation submitted for independent review. This report does not mark L3-NET-05 closed.

## Original root cause and production path

Inbound canonical `Message::Block` objects pass encrypted frame replay protection,
exact message decoding, authenticated peer admission, and the peer-manager relay
cache before being emitted to the node. The relay cache suppresses repeat gossip,
but it intentionally does not suppress node delivery, so the same proposal can
arrive through another peer, a replacement connection, or after cache expiry.

`ConsensusDriver::process_proposal` first rejects illegal rounds, uncaught-up
state, stale/future heights, and wrong parents. Before remediation it then called
`process_proposal_internal`, which performed, in order:

1. governing snapshot lookup;
2. proposer hybrid authorization and VRF verification;
3. embedded-QC verification above height one;
4. detached state projection and state/value/validator-root comparisons;
5. only then `pending_blocks.contains_key(block_hash)`.

The first valid proposal passed all checks and entered `pending_blocks`. An exact
replay repeated steps 1-4 before the late duplicate check returned `None`.

## Duplicate identity and trusted-validity boundary

The remediation uses the proposal's authoritative consensus `block_hash`, not
raw network bytes and not `value_hash` alone. The early check is performed only
against the existing `pending_blocks` map after legal-round, caught-up,
current-height, and current-parent guards.

`pending_blocks` is trusted accepted state: production inserts an entry only
after proposer/VRF verification, embedded-QC verification, detached projection,
and all commitment-root comparisons succeed. No unverified object is inserted
by the new path, and no new replay cache exists.

The block hash binds the concrete proposal block, including its consensus
height/round, proposer and entropy commitments, stable value identity, parent,
QC/PoLC fields, contents, and roots. Therefore:

- exact accepted proposal replay matches and exits cheaply;
- the same stable value reproposed at another round has a different block hash;
- a different entropy commitment has a different block hash;
- a conflicting value or proposer proposal has a different block hash;
- proposer equivocation remains eligible for full validation and existing
  selection/evidence behavior.

The original late `pending_blocks` check remains as defense in depth after full
validation, including for a same-block envelope variation that did not match an
early trusted entry in a future representation change.

## Source changes

Production change in `indra-node/src/driver.rs`:

- compute the current proposal block hash after existing height/parent guards;
- return `DriverAction::None` when that hash already exists in authoritative
  `pending_blocks`;
- leave the complete first-delivery admission path and late duplicate guard
  unchanged.

Test-only changes add `ProposalAdmissionMetrics`, compiled only under `cfg(test)`,
to count calls reaching proposal/VRF verification, embedded-QC verification, and
detached projection. These counters do not alter production layout or semantics.

The Phase 2B source-order harness now asserts that the authoritative replay guard
precedes `process_proposal_internal`; its L3-NET-06 vote-order assertion is
unchanged. Three focused production tests were added to the replay harness.

## First-delivery and replay measurement

Deterministic counters produced:

| Scenario | Proposal/VRF calls | QC calls | Detached projections | Result |
|---|---:|---:|---:|---|
| First valid height-1 delivery | 1 | 0 | 1 | accepted and broadcast once |
| Exact height-1 replay from another peer | +0 | +0 | +0 | `None`; no mutation/action |
| First valid height-2 delivery | +1 | +1 | +1 | accepted and broadcast once |
| Exact height-2 replay from another peer | +0 | +0 | +0 | `None`; no mutation/action |

The replay tests also compare pending-map size and consensus phase before/after.
No repeat gossip, request, vote, persistent mutation, phase change, or timer input
is emitted.

Before remediation, the original reproducer and source-order evidence showed the
same replay reached all applicable expensive operations once more. That evidence
is preserved unchanged in `L3-NET-05_REPRODUCER.md`.

## Invalid-first / valid-second

`invalid_proposal_cannot_poison_accepted_replay_state` sends a proposal with the
same block hash as the later genuine object but a corrupted proposer signature.
The invalid object reaches proposer verification, fails, and does not populate
`pending_blocks`. The genuine proposal then performs complete verification and
projection and is accepted normally. Measured proposal-verification count moves
from one after the rejected attempt to two after the valid attempt; projection
moves from zero to one.

This proves unverified input cannot create trusted replay suppression.

## Conflicts, equivocation, reproposal, and PoLC

The key deliberately does not use `value_hash`. Existing permanent regressions
exercise the relevant distinct identities:

- `proposal_selection_switches_to_better_priority_only_before_prevote` delivers
  two different valid same-round proposals and proves the second remains visible
  to authoritative proposal selection;
- `reproposal_is_voted_with_its_own_block_hash` forms a genuine prevote PoLC,
  constructs a same-value proposal at another legal round, validates it, and
  votes for its distinct full block hash;
- `repropose_preserves_value_hash`, `repropose_matches_clone_based_reference`,
  and `reproposal_converges_after_disruption` preserve stable-value and PoLC
  semantics;
- `vrf007_substituted_entropy_is_rejected_before_vote_or_lock_mutation` proves a
  changed entropy commitment cannot reuse stable value identity to bypass full
  admission.

All pass with the early exact block-hash guard. No conflicting or equivocating
proposal is hidden.

## Lifecycle, reconnect, and restart behavior

`pending_blocks` belongs to `ConsensusDriver`, not a peer or connection. A replay
from another socket in the focused regression receives the same cheap result,
modeling alternate relay and reconnect behavior while the consensus context
remains active.

The existing state is capped at `MAX_STALLED_HEIGHT_ENTRIES = 256` proposals.
It is pruned by height/round relevance, cleared on sync catch-up, and old entries
are removed on finalization/height transition. Legal rounds remain capped at
1,024. The remediation adds zero production entries and zero production bytes.

Ordinary pending proposals are intentionally not persisted. After restart, an
uncommitted proposal absent from reconstructed authoritative state receives full
validation again. Durable locks are independently proposal/PoLC-verified during
restore; the remediation does not add persistence or trust a network replay based
on pre-crash ephemeral state. Existing restart tests continue to reject invalid
persisted authorization and preserve lock safety.

## Interaction with L3-CS-02 and wire semantics

The guard runs only after exact-next-height/current-parent checks. Future and
wrong-parent proposals still fail before any replay entry lookup can create
state. L3-CS-02 future proposal buffering remains deleted; no opaque or unverified
future cache was introduced.

Canonical encoding, message discriminators, signed transcripts, `block_hash`,
`value_hash`, field order, and wire bytes are unchanged. Consensus selection,
lock, PoLC, equivocation, finality, and timer semantics are unchanged. Only
computational handling of an already accepted exact proposal is optimized.

L3-NET-06 code and behavior were not modified.

## Validation results

- Focused exact replay/counter regression: PASS.
- Invalid-first/valid-second poisoning regression: PASS.
- Height-2 embedded-QC replay/counter regression: PASS.
- Conflicting-proposal selection regression: PASS.
- PoLC-backed reproposal regression: PASS.
- Updated Phase 2B replay harness: PASS.
- `cargo test -p indra-network`: PASS (140 passed, 1 ignored; 4 integration tests passed).
- `cargo test -p indra-core`: PASS (148 unit and 21 integration tests passed).
- `cargo test -p indra-consensus`: PASS (59 unit and 5 integration tests passed).
- `cargo test -p indra-node`: PASS (all 279 library tests; 79 node-binary and 15 integration tests passed).
- `cargo test --workspace`: PASS (all workspace and doc tests; only declared ignored tests ignored).
- `cargo test --workspace --no-run`: PASS.
- `cargo fmt --all -- --check`: PASS.
- `git diff --check`: PASS.
- Focused diff reverse-application check: PASS.

The repository had extensive pre-existing tracked and untracked changes. They
were preserved and are not attributed to L3-NET-05. The focused diff contains
only this remediation's production, test, and Phase 2B harness changes.

## Review disposition

Focused remediation complete and returned for independent review. L3-NET-05 remains OPEN pending that review.
