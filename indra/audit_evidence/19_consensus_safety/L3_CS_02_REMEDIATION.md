# L3-CS-02 remediation — strict future-proposal admission

Status: **L3-CS-02 — LOW — FIXED**

## Purpose and decision

`future_proposals` retained decoded `BlockProposalVNext` objects up to two
heights ahead so they could be retried after the local tip advanced. Because the
future parent state does not yet exist, the driver could not project the block or
verify all roots before storage. That made an unverified object look like trusted
consensus proposal state.

The buffer was not required for safety or liveness. A peer vote for a missing
current-height proposal already causes `RequestProposal` and bounded vote
buffering (`indra-node/src/driver.rs:1550-1570` after this change), and ordinary
sync/request-response retrieves blocks after height advancement. The clean
design therefore drops every non-current or wrong-parent proposal.

## Protocol invariant

`ConsensusDriver::process_proposal` now requires both:

```text
proposal.height == canonical_tip.height + 1
proposal.prev_hash == canonical_tip.hash
```

before entering `process_proposal_internal`. Only that internal path may insert
into `pending_blocks`; it verifies proposer authority/VRF, the governing
snapshot, embedded QC/PoLC, and a detached full state projection before any
pending, vote, lock or gossip mutation (`indra-node/src/driver.rs:1325-1458`).

The following surfaces were deleted outright:

- `ConsensusDriver::future_proposals`;
- its pruning/activation functions;
- `DriverAction::ActivateBufferedProposal`;
- recursive node action handling for activation;
- commit/reset/sync cleanup for the deleted container.

There is no replacement opaque queue and therefore no new resource surface.

## Regression evidence

`future_and_wrong_parent_proposals_are_dropped_before_consensus_mutation`
constructs a legitimate future envelope plus wrong-parent, invalid-signature,
invalid-VRF/ineligible, invalid-QC, wrong-value-hash, wrong-state/transition and
wrong-validator-root variants. Every case returns only `DriverAction::None` and
preserves pending blocks, vote collectors, lock, valid value, round, and the
durable safety record exactly.

Current-height liveness remains covered by
`bounded_collections_do_not_break_normal_consensus_operation`; missing-proposal
recovery remains covered by `vote_before_block_requests_proposal_then_commits`.
The deleted buffer provided an optimization only; a future proposal must be sent
or requested again once its parent is canonical.

## Compatibility

No wire format changed. Runtime behavior intentionally changes: early future
proposals are dropped instead of cached. There is no compatibility fallback.

## Validation

- `cargo test -p indra-node`: PASS — 271 library tests passed, 5 ignored;
  79 binary tests passed; 15 integration tests passed.
- `cargo test --workspace`: all executed crates passed until the previously
  identified unrelated timing-sensitive test
  `near_duplicate_votes_share_one_validator_identity_budget` failed at
  `indra-network/src/peer_manager.rs:1977` (81 delivered, fixed expectation 80).
  It is outside this remediation and was not modified.
- `cargo fmt --all -- --check`: PASS.
- `git diff --check`: PASS.
