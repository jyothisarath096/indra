# INDRA Consensus Safety Diagnostic

## Executive Summary

The height-4 fork is caused by a split between the identity that consensus votes certify and the identity the chain stores as its tip. Votes and QCs certify `value_hash`, but committed chain links use the full `block_hash()`, which includes round/proposer metadata, VRF proof/output, embedded QC bytes, `polc_round`, and `value_hash`. During finalization, `ConsensusDriver::finalize_block_on_quorum` receives a precommit quorum for a `value_hash`, then selects the first locally staged `BlockV1` with that `value_hash` from `pending_blocks: HashMap<Bytes32, BlockV1>`. If multiple proposal/reproposal headers carry the same `value_hash`, different validators can pick different full block headers due to different arrival sets or randomized `HashMap` iteration order. They then commit different full block hashes at the same height even though the QC signatures are valid for the same value. C-08’s verified-VRF fallback is also dangerous because it can admit multiple accepted proposals for a slot, making this split easier to trigger, but the direct safety violation is the non-canonical `value_hash` → `BlockV1` commit selection.

Status: **FIXED** by canonical block selection in `finalize_block_on_quorum`: when multiple staged blocks carry the certified `value_hash`, the driver now selects the lexicographically lowest full `block_hash()` instead of the first `HashMap` entry. `verify_block_qc` also now rejects embedded QCs whose `qc.height` is not `block.header.height - 1`.

## Area 1 — QC Verification Signing Bytes

Votes are signed over:

```rust
vote_signing_bytes(height, round, step, block_hash, validator_id)
```

where `VoteV1.block_hash` is documented and used as the stable `value_hash`.

Evidence:

- `indra-core/src/types/vote_signing.rs:9-22` encodes domain, height, round, step, supplied hash, and validator id.
- `indra-consensus/src/vote.rs:232-266` signs `vote_signing_bytes(height, round, step, &block_hash, &validator_id)` and stores that same hash in `VoteV1.block_hash`.
- `indra-consensus/src/vote.rs:124-169` verifies received votes over `vote.block_hash`.
- `indra-consensus/src/qc.rs:306-312` verifies QC signatures over `vote_signing_bytes(qc.height, qc.round, Precommit, &qc.block_hash, &validator.validator_id)`.

The signed bytes and QC verification bytes match if `qc.block_hash == vote.block_hash`. In the current design, both fields carry `value_hash`; `QuorumCertificateV1.block_hash` explicitly documents that the field name remains for compatibility but now carries the stable `value_hash` (`indra-core/src/types/qc.rs:61-65`).

Finding: **SAFE for signature-byte consistency, but contributes to the root cause because the certified identity is not the full committed block hash.**

## Area 2 — Block Hash vs Value Hash

`BlockHeaderV1` has two identities:

- `block_hash()` is SHA-256 of the full encoded header (`indra-core/src/types/block.rs:23-36`, `71-75`).
- `value_hash` is a stable consensus value hash computed from height, previous full tip hash, timestamp, state root, validator root, mempool root, base fee, and total supply (`indra-core/src/types/block.rs:77-98`).

The full `block_hash()` includes metadata that can differ across reproposals:

- `proposer_round`
- `polc_round`
- `proposer_vrf_output`
- `proposer_vrf_proof`
- `quorum_certificate`
- `value_hash`

Votes use `value_hash`:

- `maybe_prevote_current_round_proposal` votes for `block.header.value_hash` (`indra-node/src/driver.rs:489-520`).
- `VoteCollector::current_decision` counts stake per `vote.block_hash`, with comments saying this carries `value_hash` (`indra-consensus/src/vote.rs:185-190`).
- `finalize_block_on_quorum` builds the QC for the quorum `block_hash` argument, which is actually the value hash (`indra-node/src/driver.rs:930-936`).

But the chain tip is the full header hash:

- `produce_block` sets `prev_hash: state.tip_hash` (`indra-consensus/src/producer.rs:130-145`).
- `import_block` appends the exact full block object to the block store (`indra-node/src/sync.rs:210-257`).
- Later proposals extend `state.tip_hash`, which is the committed full header hash.

The dangerous bridge is `finalize_block_on_quorum`:

```rust
self.pending_blocks
    .iter()
    .find(|(_, block)| block.header.value_hash == block_hash)
```

This turns a quorum over `value_hash` into an arbitrary locally staged full `BlockV1` (`indra-node/src/driver.rs:884-906`). Because `pending_blocks` is a `HashMap`, if more than one staged block has that `value_hash`, the selected full block is not canonical.

Finding: **ROOT CAUSE — FIXED. Consensus certifies `value_hash`; finalization previously committed a non-canonical full `block_hash()`.**

## Area 3 — VRF Proposer Election Determinism

`elect_proposer` is deterministic only for a fully specified `ProposerElection`. After C-08, however, the election can be context-dependent because it uses a verified VRF output for candidates that have one and falls back to public `candidate_output(vrf_pubkey, vrf_input)` for candidates that do not (`indra-consensus/src/proposer.rs:105-143`).

Production path:

- `NodeEngine::is_proposer` computes the local validator’s VRF output and sets `verified_vrf_output` only for that local candidate before calling `elect_proposer` (`indra-node/src/engine.rs:343-398`).
- `produce_block` does the same for the proposer keypair (`indra-consensus/src/producer.rs:74-105`).

Verification path:

- `verify_proposer_vrf` verifies the proposal’s VRF proof, sets `verified_vrf_output` only for the matched proposer, then calls `elect_proposer` with all other candidates still using fallback output (`indra-node/src/sync.rs:260-357`).

This means each proposal is judged using the proposed validator’s actual VRF output and everyone else’s fallback public hash. A different proposal from another validator is judged under a different effective election. Therefore two validators can each believe they are the proposer, and receivers can accept multiple proposals for the same height/round under different “one verified candidate” views.

Finding: **DANGEROUS. This does not by itself explain three different committed tip hashes, but it increases the chance of multiple staged proposals/reproposals with the same or competing value identities.**

## Area 4 — Hybrid QC Quorum With Signature Failures

`verify_qc` requires PQ signatures for every signer and, when `hybrid_qc_active(qc.height)` is true, also requires classical signatures for every signer:

- `qc.pq_signatures.len() != signers.len()` is rejected (`indra-consensus/src/qc.rs:274-279`).
- `qc.classical_signatures.len() != signers.len()` is rejected when hybrid is active (`indra-consensus/src/qc.rs:281-297`).
- PQ signatures are verified over the QC signing bytes (`indra-consensus/src/qc.rs:299-332`).
- Classical signatures are verified over the same bytes (`indra-consensus/src/qc.rs:334-362`).
- `verify_qc_strict` aliases `verify_qc` (`indra-consensus/src/qc.rs:368-375`).

I found no path where `verify_qc` accepts an invalid or missing classical signature while `hybrid_qc_active(qc.height)` is true.

The remaining concern is height linkage: `verify_block_qc` verifies the embedded QC cryptographically but does not check `qc.height == block.header.height - 1` or that the QC certifies the local previous tip’s `value_hash` (`indra-node/src/sync.rs:360-413`). That is a validity gap, but not the direct source of the observed three tip hashes.

Finding: **SAFE for hybrid signature enforcement; DANGEROUS for missing embedded-QC linkage checks.**

## Area 5 — pending_precommit_quorum

`pending_precommit_quorum` is only a deferred-finalization queue for quorums that arrive before the matching proposal is staged:

- It inserts `(height, round, block_hash)` when precommit quorum exists but no staged block with matching `value_hash` exists (`indra-node/src/driver.rs:895-904`).
- It removes and finalizes when a later proposal with the matching `value_hash` arrives (`indra-node/src/driver.rs:663-672`).

It does not prevent competing finalizations:

- The key includes the hash, so it distinguishes `(height, round, X)` from `(height, round, Y)`.
- It is not a lock or safety guard.
- It does not canonicalize which full block corresponds to a certified `value_hash`.

Finding: **SAFE as a deferred queue; NOT a safety mechanism. It does not prevent this bug.**

## Area 6 — QC Embedding in Block Headers

Block production embeds the previous height’s QC bytes directly into the next block header:

- `BlockTemplate.prev_qc_bytes` is documented as the serialized QC for the previous height (`indra-consensus/src/producer.rs:38-50`).
- `produce_block` stores it in `header.quorum_certificate` (`indra-consensus/src/producer.rs:122-145`).
- `finalize_block_on_quorum` stores `last_qc_bytes = qc.encode_to_vec()` after commit (`indra-node/src/driver.rs:949-966`).
- `last_qc_bytes()` returns those bytes for the next proposal (`indra-node/src/driver.rs:272-274`).

Verification:

- `verify_block_qc` decodes `block.header.quorum_certificate` and verifies the QC against the active validator set (`indra-node/src/sync.rs:360-413`).

The codec version byte path is working structurally, but the embedded QC is not linked to the block’s declared parent:

- No check that `qc.height == block.header.height - 1`.
- No check that `qc.block_hash` is the previous block’s certified `value_hash`.
- Since the local state only stores `tip_hash` as the full block hash, there is no immediately available canonical previous `value_hash` to compare unless the previous block is loaded.

Finding: **DANGEROUS validity gap, but secondary to the root cause. The immediate fork can occur even with valid QC bytes because the QC certifies a value hash, not a canonical full header hash.**

## Root Cause

Different validators commit different full block headers at height 4 because `finalize_block_on_quorum` turns a valid precommit quorum for a `value_hash` into whichever locally staged `BlockV1` with that `value_hash` happens to be found first in a `HashMap`, while the chain tip and next block’s `prev_hash` use the full `block_hash()`.

## Proof of Concept

Minimal reasoning:

1. A block `X` is proposed at height `H`, round `0`, with `value_hash = V` and full hash `HX`.
2. A later reproposal `Y` carries the same block content and same `value_hash = V`, but different round/proposer metadata, so `Y.block_hash() = HY`, and `HY != HX`. This is explicitly expected by the existing reproposal test: `assert_eq!(block_y.header.value_hash, value_hash); assert_ne!(block_y.header.block_hash(), block_x.header.block_hash())` (`indra-node/src/driver.rs:2356-2369`).
3. Validators precommit `V`, not `HX` or `HY`.
4. On quorum, each node calls `finalize_block_on_quorum(H, R, V)`.
5. The code searches `pending_blocks: HashMap<full_hash, BlockV1>` for the first block whose `header.value_hash == V` (`indra-node/src/driver.rs:890-894`).
6. Node A may have only `X`, or may encounter `X` first; Node B may have only `Y`, or may encounter `Y` first.
7. Both build a valid QC for `V`, then commit their chosen full block object (`indra-node/src/driver.rs:930-960`).
8. The resulting state transition can be identical, but `state.tip_hash`/block-store tip differs because it is the full header hash. This matches the observed symptom: all validators at height 4, but with multiple tip hashes.

This is enough to create a visible chain fork without requiring forged signatures, broken hybrid QC verification, or arithmetic/state-root divergence.

## Fix Direction

Make the identity that QCs certify identical to the identity that the chain commits and extends: either vote/QC over a canonical full block id, or make the committed tip hash derive only from the canonical `value_hash`; in either design, remove the arbitrary `HashMap` search from `value_hash` to full `BlockV1` and store one deterministic canonical block per certified value.
