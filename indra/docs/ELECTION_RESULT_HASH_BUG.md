# election_result_hash QC Build Failure — Diagnostic

## Diagnosis Confirmed/Refuted

Partially confirmed, but the proposed root-cause sequence is not fully supported by the current code.

The confirmed part: `indra-consensus/src/qc.rs::build_qc_from_votes` requires every vote included in the QC to have the same `election_result_hash` value, including exact agreement on `None` vs `Some(hash)`.

```rust
let election_result_hash = votes.iter().find_map(|vote| vote.election_result_hash);
if votes.iter().any(|vote| vote.election_result_hash != election_result_hash) {
    return Err(ConsensusError::CryptoError {
        detail: "QC votes disagree on election_result_hash".to_string(),
    });
}
```

So if the precommit collector reaches quorum by `block_hash` with a mixed set such as `{Some(X), Some(X), None}`, `build_qc` will fail and the block will not finalize.

The refuted part: the current local precommit path does not simply sign `None` when the local VRF round state has not yet computed `election_result`. In `indra-node/src/driver.rs::sign_and_record_local_vote`, precommit votes use:

```rust
self.vrf_election_result(height, round)
    .map(|result| result.hash())
    .or_else(|| {
        self.pending_block(&block_hash)
            .and_then(|block| block.header.election_result_hash)
    })
```

For a non-nil precommit, the block should already be staged locally. Proposal intake also verifies commit-reveal-active proposals through `verify_proposer_vrf`, and that path requires the proposed block header to carry a valid `election_result_hash`. Therefore, with the current code and a staged non-nil block, even a validator whose local VRF round result is not yet available should sign the block header’s `Some(election_result_hash)`, not `None`.

There is also a guard before prevoting: `maybe_prevote_current_round_proposal` treats `block.header.election_result_hash != local_vrf_result.map(hash)` as an election mismatch. If the local result is still missing, it returns without prevoting rather than nil-prevoting immediately. That further reduces the chance of honest current-code validators producing non-nil precommits with `None`.

Conclusion: the QC builder can fail on mixed `election_result_hash` votes, but the specific “some validators precommit non-nil with `None` because VRF result is not ready” path appears unlikely in the current code. If the live logs really show QC build failure at height 50, likely causes are:

1. Some validators are running an older or mismatched binary that signs precommits without `election_result_hash`.
2. A path outside normal local proposal/vote handling constructs `VoteV1` using `produce_vote` instead of `produce_vote_with_election_result`.
3. The vote collector is counting quorum by `block_hash` only, so a malformed/mixed vote set can trigger finalization even though no quorum exists for a single `(block_hash, election_result_hash)` attestation.

## Error Logging Gap

The QC build error is not fully silent in the current code. `indra-node/src/driver.rs::finalize_block_on_quorum` logs:

```rust
eprintln!(
    "[commit] failed to build QC for {} at height={} round={}: {}",
    ...
);
return vec![DriverAction::None];
```

So the exact `ConsensusError::CryptoError { detail: "QC votes disagree on election_result_hash" }` should appear as a `[commit] failed to build QC ...` log line if this is the active failure.

However, the returned action is still only `DriverAction::None`; no higher-level recovery, peer disconnection, metric, or explicit consensus-fatal signal is emitted. If logs are filtered around proposal/QC recovery messages, the failure can look like a silent `DriverAction::None` loop.

Recommended logging hardening:

- Add a specific metric/counter for QC build failures by reason.
- Include each accepted precommit’s validator ID and `election_result_hash` short hash in diagnostic-level logging when QC construction fails.
- Keep the normal `eprintln!` but make the message searchable by including the literal reason string.

## Correct Fix

Do not implement Option A as written.

Option A says to set the QC’s `election_result_hash` to `None` if any vote lacks it. That is not signature-safe. Vote signatures bind the optional `election_result_hash` in `vote_signing_bytes`; `verify_qc` verifies every QC signature against the single `qc.election_result_hash`. If a signer signed `Some(X)` and the QC is downgraded to `None`, that signer’s signature should fail QC verification. If the QC keeps those signatures but advertises `None`, it is invalid. If the builder drops the `Some(X)` signers, it must re-check quorum on the remaining `None` signers.

Option B is directionally correct but incomplete. It is correct that honest validators should not sign a non-nil precommit for a commit-reveal-active block unless they can bind the vote to the election result. The current code already mostly does this through either the local VRF result or the staged block header fallback.

The mainnet-grade fix should be stricter and more structural:

1. Treat precommit quorum as quorum over `(block_hash, election_result_hash)`, not just `block_hash`, when commit-reveal election is active.
2. For commit-reveal-active non-nil precommits, require `election_result_hash.is_some()` at vote collection time. Reject or ignore non-nil precommits with `None`.
3. Keep nil precommits allowed with `None`; they are timeout/safety votes and never form a block QC.
4. Build the QC only from the exact subgroup that reached quorum for the same `(block_hash, election_result_hash)`.
5. In `finalize_block_on_quorum`, assert `qc.election_result_hash == block.header.election_result_hash` before committing.

This preserves the CS-05 security guarantee: a QC for a commit-reveal-active block proves that 2/3+ stake signed the same full block hash and the same election result hash.

If a validator cannot compute or learn the election result in time, it should not non-nil precommit that block. It should wait until the existing timeout path advances the round or precommit nil on prevote timeout. It should not emit a non-nil precommit with `None`.

## Height 50 Specificity

The current code does not contain a consensus hard-fork at height 50. `VRF_COMMIT_REVEAL_ELECTION_HEIGHT` is `0`, so commit-reveal election is active from genesis on this testnet configuration.

Height 50 is suspicious for a different reason: sync uses `SYNC_BATCH_SIZE = 50` in `indra-node/src/sync.rs`. A repeated stall at height 50 with logs like:

- `proposal skipped at height 51: no QC for previous block`
- repeated `requesting QC for height 50`

is at least as consistent with missing/stale `last_qc_bytes` for the current tip as it is with a direct block-50 QC build failure. `NodeEngine::propose` refuses to produce block 51 if `last_qc_bytes` is empty. That exact refusal emits the observed proposal-skipped log.

If block 50 actually committed locally, but `last_qc_bytes` was not set/persisted for height 50, validators will be at height 50 and unable to propose height 51. They will request QC recovery for height 50 in a loop. That failure mode can be caused by:

1. QC construction failure at height 50 before `last_qc_bytes` assignment, if state height somehow advanced by another path.
2. A recovery/import path that advances state to height 50 without also having a valid last QC for height 50.
3. A stale-QC clearing path that clears `last_qc_bytes` after reaching height 50 and cannot recover it from peers.
4. Sync batch boundary behavior: nodes import a 50-block batch and then need QC recovery at the new tip.

The first next diagnostic should therefore be to capture the logs immediately before height 50 advances:

- Was `[commit] finalizing ... at height=50` printed?
- Was `[commit] failed to build QC ... QC votes disagree on election_result_hash` printed?
- Was `[driver] WARNING: failed to persist last_qc_bytes` printed?
- Did any node import height 50 through sync rather than live finalization?

If there is no `[commit] failed to build QC` line, the proposed QC-mixed-vote diagnosis is probably not the direct height-50 cause.

## Other Affected Code Paths

`indra-node/src/sync.rs::verify_proposer_vrf` does enforce that a commit-reveal-active proposed block has an `election_result_hash` that certifies the proposer for that block’s height/round. This protects proposal intake and sync block verification for the block being imported.

`indra-node/src/sync.rs::verify_block_qc` verifies:

- height linkage: `qc.height == block.header.height - 1`
- parent hash linkage: `qc.block_hash == block.header.prev_hash`
- QC signatures/stake via `verify_qc_strict`

It does not compare `qc.election_result_hash` to the parent block header’s `election_result_hash`. The child block does not itself contain the full parent header, only `prev_hash`, so a local comparison requires loading the retained parent block from storage or carrying the parent header through the import verifier.

Risk: a sync/import path can accept a QC whose signatures are internally valid for `qc.election_result_hash = None`, even if the certified parent block header had `election_result_hash = Some(X)`, unless the parent block is separately checked. That is not a direct signature forgery, but it weakens the intended attestation semantics.

Recommended hardening:

- During live finalization, require built QC `election_result_hash` to equal the finalized block header’s `election_result_hash` when commit-reveal is active.
- During sync/import, when the parent block is retained, require embedded QC `election_result_hash` to match the retained parent header’s `election_result_hash` for commit-reveal-active parent heights.
- Add an archive/pruned fallback policy: if the parent block is pruned, rely on strict QC signature validity plus the parent hash linkage, but log that the parent election-result cross-check could not be performed.

## Implementation Plan

No implementation was performed in this diagnostic task.

Recommended code changes:

1. `indra-consensus/src/vote.rs`
   - Change `VoteDecision::QuorumReached` to carry `election_result_hash: Option<Bytes32>`.
   - For precommit decisions, count stake by `(block_hash, election_result_hash)` instead of only `block_hash`.
   - If commit-reveal activation is not available inside `VoteCollector`, add a constructor flag such as `require_election_result_hash_for_non_nil_precommit`.
   - Reject or ignore non-nil precommit votes with `election_result_hash == None` when that flag is active.

2. `indra-node/src/driver.rs`
   - When constructing vote collectors, set the commit-reveal-active flag for the collector height.
   - In `sign_and_record_local_vote`, fail closed for non-nil commit-reveal-active precommits if both local VRF result and staged block header hash are unavailable.
   - In `finalize_block_on_quorum`, build the QC from only votes matching the `VoteDecision`’s `(block_hash, election_result_hash)`.
   - After building the QC, assert that `qc.election_result_hash == block.header.election_result_hash` for commit-reveal-active non-nil blocks.
   - Improve logs on QC build failure with per-vote election hash diagnostics.

3. `indra-consensus/src/qc.rs`
   - Keep the all-votes-agree invariant.
   - Optionally make the error include counts by `election_result_hash` to ease diagnosis.
   - Add tests proving mixed `None`/`Some` votes cannot be used to build a QC unless one exact hash group independently reaches quorum.

4. `indra-node/src/sync.rs`
   - When verifying a block with an embedded parent QC, compare `qc.election_result_hash` to the retained parent block’s `header.election_result_hash` if the parent is available and commit-reveal is active at `qc.height`.

Required tests:

1. `mixed_election_result_hash_precommits_do_not_reach_quorum`
   - Three equal-stake precommits for the same block hash with `{Some(X), Some(X), None}` must not produce `QuorumReached` in a 4-validator set.

2. `qc_build_uses_only_votes_with_matching_election_result_hash`
   - If `{Some(X), Some(X), Some(X)}` reaches quorum and `{None}` also exists, the QC uses only/signs as `Some(X)` or rejects the mixed input before QC construction.

3. `non_nil_precommit_without_election_result_hash_rejected_when_commit_reveal_active`
   - A commit-reveal-active non-nil precommit with `None` is rejected at vote collection.

4. `nil_precommit_without_election_result_hash_still_allowed`
   - Nil timeout precommit keeps `None` and remains valid.

5. `finalize_rejects_qc_election_hash_mismatch_with_block_header`
   - Live finalization cannot commit a block if the QC’s election hash does not match the block header.

6. `sync_rejects_parent_qc_election_hash_mismatch_when_parent_available`
   - Sync/import rejects a child block whose embedded QC certifies the parent hash but not the parent election result hash.

7. `qc_build_failure_logs_vote_election_hash_distribution`
   - Diagnostic logging includes enough information to distinguish `None`/`Some` disagreement from signature/stake failures.
