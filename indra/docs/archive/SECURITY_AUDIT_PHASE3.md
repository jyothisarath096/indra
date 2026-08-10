> **Historical archive:** This records completed audit work and intermediate designs. It is not current guidance; canonical specifications and current code take precedence.

# INDRA Security Audit — Phase 3: Consensus Safety and Liveness

## Summary Table

| ID | Property | Finding | Severity | Status |
|----|----------|---------|----------|--------|
| CS-01 | Safety | Votes/QCs certify full `block_hash()` and embedded QC is checked against parent `prev_hash` | SAFE | FIXED |
| CS-02 | Safety | POLC rule uses full hash for vote target and value hash for same-value reproposal checks | SAFE | Checked |
| CS-03 | Safety | QC verification requires quorum stake plus PQ and Ed25519 signatures; stale strict-wrapper comment corrected | SAFE | FIXED |
| CS-04 | Liveness | Timeout progression is local and uncapped; peer-status round jumps are capped | SAFE / LOW | Checked |
| CS-05 | Liveness | Proposer election uses commit-reveal VRF with QC-attested election result hash | SAFE | FIXED |
| CS-06 | Liveness | Sync catch-up refreshes voter set and recovers stale/missing tip QC | SAFE | Checked |
| CS-07 | Equivocation | Slash detector compares vote full `block_hash()` and no stale `value_hash` path was found | SAFE | Checked |
| CS-08 | Equivocation | Slash evidence requires forged hybrid precommit signatures; prevote conflicts are explicitly non-slashable | SAFE | FIXED |
| CS-09 | Byzantine | Equivocating proposer cannot create two QCs for different full hashes with < 1/3 Byzantine stake | SAFE, affected by CS-05 liveness | Checked |
| CS-10 | Byzantine | Invalid proposals are rejected before voting, including VRF, embedded QC, and projected roots | SAFE | Checked |
| CS-11 | Partition | 2/2 partition cannot reach 2/3 quorum; recovery depends on normal sync/status exchange | SAFE | Checked |
| CS-12 | Replay | Vote replay, stale QC-height replay, and wrong-parent QC replay are rejected | SAFE | FIXED |

Severity key: CRITICAL / HIGH / MEDIUM / LOW / INFO / SAFE.

## Detailed Findings

### CS-01 — Votes/QCs certify full `block_hash()` and embedded QC is linked to the parent hash

**Description:** The core consensus safety v2 fix is mostly present: votes carry full `block_hash()`, `VoteCollector::current_decision` counts stake per `vote.block_hash`, `finalize_block_on_quorum` finalizes by direct lookup in `pending_blocks` keyed by full hash, and `build_qc` stores that same full hash in `QuorumCertificateV1.block_hash`.

`sync::verify_block_qc` now checks that the embedded QC has `qc.height == block.header.height - 1`, that `qc.block_hash == block.header.prev_hash`, and that its signatures verify. Since votes/QCs now certify full block hashes, this parent linkage check is consensus-critical: a child block must prove the exact parent it extends.

**Attack scenario:** A block at height `H` carries `prev_hash = A` but embeds a valid QC for height `H-1` certifying `B`. If `B != A`, `verify_block_qc` now rejects it with `QC must certify the exact parent block`.

Height 1 remains correctly excluded because genesis has no meaningful previous QC; the check applies only to blocks above height 1.

**Code location:**

- `indra-node/src/driver.rs::maybe_prevote_current_round_proposal` votes for `block.header.block_hash()`.
- `indra-node/src/driver.rs::finalize_block_on_quorum` uses direct `pending_blocks.get(&block_hash)` and passes `block_hash` to `build_qc`.
- `indra-consensus/src/vote.rs::VoteCollector::current_decision` counts per `vote.block_hash`.
- `indra-node/src/sync.rs::verify_block_qc` checks QC height, parent hash linkage, and signatures.

**Analysis/proof:** The previous diagnostic was correct that the old `value_hash` vote target could fork. That specific bug is closed. The remaining parent-linkage gap is also now closed: a QC certifying a full hash that is not the block's `prev_hash` is rejected before signature verification is even needed.

**Severity:** SAFE after fix.

**Fix applied:** `verify_block_qc` now requires `qc.block_hash == block.header.prev_hash`. Regression coverage was added for both the rejection case and the normal accepted case.

### CS-02 — POLC rule correctness

**Description:** The implementation separates the full hash used for actual votes from the stable value hash used only for same-value POLC checks.

**Attack scenario checked:** A Byzantine proposer claims a `polc_round` where no local prevote quorum actually existed, attempting to make validators unlock or prevote a reproposal.

**Code location:**

- `indra-node/src/driver.rs::maybe_prevote_current_round_proposal`
- `indra-node/src/driver.rs::has_quorum_for_value_hash`
- `indra-node/src/driver.rs::record_vote_and_actions`

**Analysis/proof:** Rule 2 votes for the proposal's full `block.header.block_hash()` only if unlocked or already locked on the same full hash. Rule 3 uses `block.header.polc_round`, but it does not trust the proposer's claim directly: it calls `has_quorum_for_value_hash`, which checks the local `VoteCollector` decision for that round and then compares the locally staged block's `value_hash`. `locked_value` stores the full hash, while `locked_value_hash` stores the stable value for reproposal comparisons.

**Severity:** SAFE.

**Recommended fix:** None for the audited path.

### CS-03 — QC verification completeness

**Description:** `verify_qc` verifies signer bitfield, quorum stake, PQ signatures, and Ed25519 signatures when `hybrid_qc_active(qc.height)` is true. The `verify_qc_strict` wrapper currently aliases `verify_qc`.

**Attack scenario checked:** A QC with valid PQ signatures but missing/invalid classical signatures is accepted after the hybrid QC fix.

**Code location:**

- `indra-consensus/src/qc.rs::verify_qc`
- `indra-consensus/src/qc.rs::verify_qc_strict`
- `indra-node/src/sync.rs::verify_block_qc`
- `indra-node/src/driver.rs::handle_qc_response`

**Analysis/proof:** `verify_qc` enforces `qc.classical_signatures.len() == signers.len()` when hybrid QC is active, maps signatures by validator ID, and verifies `vote_signing_bytes(qc.height, qc.round, Precommit, qc.block_hash, validator_id, chain_id)` with both `verify_pq` and `verify_classical`. Block import calls `verify_qc_strict` via `verify_block_qc`, and QC recovery responses call `verify_qc` before caching recovered `last_qc_bytes`.

The stale comment above `verify_qc_strict` has been corrected. The function body delegates to hybrid `verify_qc`.

**Severity:** SAFE.

**Fix applied:** Comment-only cleanup; no consensus logic changed.

### CS-04 — Round timeout and recovery

**Description:** Local timeout-driven round advancement is uncapped and proceeds through Propose → Prevote → Precommit → next round. Peer-status-driven round jumps are capped at `MAX_ACCEPTED_ROUND_JUMP = 8`.

**Attack scenario checked:** The round-jump cap prevents a legitimately behind node from catching up, or local timeout advancement is accidentally capped.

**Code location:**

- `indra-node/src/driver.rs::on_propose_timeout`
- `indra-node/src/driver.rs::on_prevote_timeout`
- `indra-node/src/driver.rs::on_precommit_timeout`
- `indra-node/src/driver.rs::process_status`
- `indra-node/src/bin/node.rs` constants `PROPOSE_TIMEOUT = 8s`, `PREVOTE_TIMEOUT = 3s`, `PRECOMMIT_TIMEOUT = 3s`

**Analysis/proof:** Local `on_precommit_timeout` calls `start_round(self.current_round.saturating_add(1))` with no `MAX_ACCEPTED_ROUND_JUMP` cap. The cap exists only in `process_status`, where one peer status can advance the local round by at most 8. Repeated status messages can still catch up gradually; local timeout progression is always available.

The remaining liveness caveat is that timeouts are constant rather than adaptive/exponential. Constant timeouts are simpler and testnet-friendly, but under high-latency or unstable WAN conditions they can cause repeated nil votes/reproposals. This is a LOW operational tuning risk, not a safety issue.

**Severity:** SAFE / LOW.

**Recommended fix:** Consider adaptive timeout growth in Phase 3 follow-up, especially for geographically distributed validator sets.

### CS-05 — Proposer election uniqueness

**Description:** FIXED. Proposer election now uses a short-lived commit-reveal VRF round for each `(height, round)`. Validators first gossip `VrfCommit`, then open with `VrfReveal`. The local live voting path elects the winner from verified reveals, assigning non-revealers the worst score and falling back to the public deterministic election only when no reveals are available.

The elected result is represented by `VrfElectionResult` and committed as `election_result_hash` in `BlockHeaderV1`. Precommit votes sign the same hash, `QuorumCertificateV1` stores it for signature verification, and `block_hash()` includes it. Thus the QC attests both the block hash and the proposer-election result hash.

Sync/import verification remains bounded: historical nodes verify the proposer owns the registered VRF key and that the header `election_result_hash` certifies that proposer/output (or the fallback sentinel). They do not need historical ephemeral commit/reveal gossip.

**Attack scenario blocked:** The original CS-05 bug let validators A and B both honestly believe they were proposer for the same height/round because each compared their own actual VRF output against other candidates' public fallback hashes. The interim public deterministic fix removed multi-winner rounds but made the schedule predictable. The commit-reveal fix removes the perspective-dependent winner while restoring per-round private VRF unpredictability until reveal.

**Code location:**

- `indra-consensus/src/proposer.rs::elect_proposer_from_reveals`
- `indra-core/src/types/vrf_election.rs::VrfCommit`
- `indra-core/src/types/vrf_election.rs::VrfReveal`
- `indra-core/src/types/vrf_election.rs::VrfElectionResult`
- `indra-node/src/driver.rs::ensure_vrf_election_for_round`
- `indra-node/src/driver.rs::process_vrf_commit`
- `indra-node/src/driver.rs::process_vrf_reveal`
- `indra-consensus/src/producer.rs::produce_block`
- `indra-node/src/sync.rs::verify_proposer_vrf`
- `indra-core/src/types/primitives.rs::VRF_COMMIT_REVEAL_ELECTION_HEIGHT`

**Analysis/proof:** The new tests verify that:

- the same reveal set deterministically produces the same `VrfElectionResult`;
- validators that withhold reveals receive the worst score;
- zero-reveal rounds use the explicit fallback result hash;
- reveals without prior commits, mismatched commitments, invalid VRF proofs, and wrong-chain commits are rejected;
- block headers commit to `election_result_hash`;
- precommit votes carry `election_result_hash`, while prevotes do not;
- sync verification accepts a correct commit-reveal header hash without ephemeral messages and rejects tampered result hashes.

**Severity:** SAFE after fix. This is a consensus-rule and wire-format change for proposer validity, votes/QCs, and P2P gossip. It should be activated from genesis after a fresh testnet reset or via a hard-fork height. It does not change cryptographic derivation or genesis validator key material.

**Historical resolution, corrected for the final design:** Complete. The canonical protocol now uses commit/reveal VRF election with durable reveal evidence and a QC-attested `election_result_hash`; the public deterministic design described here was interim.

### CS-06 — Sync and catch-up correctness

**Description:** Restarted or behind nodes have explicit catch-up behavior, voter refresh, stale-QC clearing, and QC recovery.

**Attack scenario checked:** A node catches up by sync import but retains stale `last_qc_bytes`, then later proposes with a QC for `H-2`.

**Code location:**

- `indra-node/src/driver.rs::last_qc_is_stale`
- `indra-node/src/driver.rs::clear_last_qc_if_stale`
- `indra-node/src/driver.rs::request_qc_if_needed`
- `indra-node/src/driver.rs::handle_qc_response`
- `indra-node/src/driver.rs::on_sync_caught_up`
- `indra-node/src/bin/node.rs` `Message::BlockResponse` path
- `indra-node/src/sync.rs::SyncState::mark_caught_up`

**Analysis/proof:** Sync import calls `engine.commit_block`, refreshes registered voters, advances sync state, resets round, clears stale `last_qc_bytes`, and calls `on_sync_caught_up`. If the driver is caught up, it then runs `request_qc_if_needed`. QC responses are decoded, height-checked, and verified with `verify_qc` before being cached and persisted. `mark_caught_up` sets `received_peer_status = true`, closing the prior vote-silence gap.

**Severity:** SAFE.

**Recommended fix:** None for the audited path. The CS-01 parent-hash QC linkage now applies before any embedded QC is used to justify a child.

### CS-07 — Slash detector uses correct hash type

**Description:** The slash detector stores observed votes and compares `VoteV1.block_hash`, which now means full block hash.

**Attack scenario checked:** After the `value_hash` → `block_hash()` safety fix, the slash detector still compares old value hashes and misses full-hash equivocation.

**Code location:**

- `indra-core/src/types/slash_detector.rs::observe_precommit`
- `indra-core/src/types/slash_detector.rs::observe_prevote`
- `indra-node/src/driver.rs::process_vote`

**Analysis/proof:** The detector compares `prev.block_hash == vote.block_hash`. Since `VoteV1.block_hash` is documented and produced as full block hash, equivocation detection aligns with the current vote target. The driver also rejects a second observed vote from the same validator/height/round/step with a different hash via `seen_round_votes`.

**Severity:** SAFE.

**Recommended fix:** None for full-hash equivocation detection.

### CS-08 — Slash evidence forgery resistance

**Description:** Applying slash evidence verifies both vote signatures against the claimed validator's registered hybrid public keys and the current chain ID.

**Attack scenario checked:** A Byzantine validator forges slash evidence to slash a correct validator.

**Code location:**

- `indra-state/src/apply.rs::apply_slash_at_height`
- `indra-state/src/apply.rs::verify_vote_sig_with_keys`
- `indra-node/src/driver.rs::process_vote`

**Analysis/proof:** `apply_slash_at_height` loads the claimed validator's Ed25519 and PQ keys, verifies both votes with `verify_hybrid` over `vote_signing_bytes(..., chain_id)`, requires both votes' `validator_id` to match the evidence validator, requires same height/round, requires different non-nil block hashes, and requires same step. It now accepts only precommit equivocation as slashable. Forging evidence against a correct validator therefore requires forging that validator's hybrid precommit signatures.

**Decision:** Prevote conflicts are intentionally non-slashable for now. POLC/valid-round rules make prevote semantics more subtle than precommit equivocation, and the node-side detector already treats same-slot prevote conflicts as non-slashable. The state layer has been aligned with that model by rejecting prevote slash evidence.

Separate policy note: epoch liveness penalties are intentionally retained as an inactivity penalty, not as slash evidence for equivocation. They are governed by the liveness penalty parameters in state/governance, burn stake/supply after the configured inactivity threshold, and are covered by Phase 4 monetary-invariant tests. This does not change the CS-08 conclusion that the slash-evidence path accepts only hybrid-signed precommit equivocation.

**Severity:** SAFE.

**Fix applied:** `apply_slash_at_height` now rejects `VoteStep::Prevote` evidence with `InvalidSlashEvidence`; `SlashDetector` has regression coverage that same-slot prevote conflicts do not emit slash evidence. Double-precommit slashing remains active.

### CS-09 — Byzantine equivocating proposer fork attempt

**Description:** A proposer can send different blocks for the same slot to different validators, but votes now target full block hashes.

**Attack scenario checked:** A Byzantine proposer sends two blocks with the same `value_hash` but different full `block_hash()` values to different subsets, trying to reproduce the old fork.

**Code location:**

- `indra-node/src/driver.rs::process_block_internal`
- `indra-node/src/driver.rs::pending_blocks`
- `indra-node/src/driver.rs::process_vote`
- `indra-consensus/src/vote.rs::VoteCollector::current_decision`

**Analysis/proof:** For each slot, `process_block_internal` stages one block and rejects later different blocks for that same `(height, proposer_round)` locally. Votes are for the full staged block hash. If the network splits, each subset votes for a different full hash. With 4 equal validators, one conflicting full hash needs 3 votes to reach quorum; two conflicting full hashes cannot both obtain 3 votes unless at least 2 validators equivocate, exceeding f=1. `VoteCollector` returns quorum per exact full hash.

The CS-05 public deterministic proposer-election fix now removes the known honest multi-proposer source of split votes for the same slot. A Byzantine proposer can still equivocate by sending different blocks to different peers, but full-hash voting means conflicting full hashes cannot both reach quorum under the f < n/3 assumption.

**Severity:** SAFE.

**Recommended fix:** None for safety. Keep full-hash voting and the public deterministic proposer election.

### CS-10 — Invalid proposal early rejection

**Description:** Proposal intake validates proposer VRF, embedded QC, and projected state commitments before staging/voting.

**Attack scenario checked:** A Byzantine proposer sends an invalid block that validators vote for and only reject after precommit quorum.

**Code location:**

- `indra-node/src/driver.rs::process_block_internal`
- `indra-node/src/sync.rs::verify_proposer_vrf`
- `indra-node/src/sync.rs::verify_block_qc`
- `indra-node/src/sync.rs::verify_block_state_root`

**Analysis/proof:** `process_block_internal` rejects non-elected/fake-proposer blocks via `verify_proposer_vrf`, rejects malformed/stale embedded QCs via `verify_block_qc`, and runs `indra_state::apply_block` on a clone before staging. Separately, sync import runs `verify_block_state_root`, which projects the block and verifies state root, validator-set root, and value hash. Therefore invalid state-transition proposals are not intentionally voted on.

**Severity:** SAFE.

**Recommended fix:** None for this path. The CS-01 parent-QC linkage check is now part of the shared `verify_block_qc` function used at proposal intake and sync import.

### CS-11 — 2/2 partition behavior

**Description:** With 4 equal-stake validators, quorum is > 2/3 stake. A 2/2 partition cannot commit.

**Attack scenario checked:** Both sides of a 2/2 partition commit independently with 50% stake.

**Code location:**

- `indra-consensus/src/vote.rs::VoteCollector::current_decision`
- `indra-consensus/src/qc.rs::verify_qc`
- `indra-node/src/sync.rs::SyncState`
- `indra-node/src/driver.rs::process_status`

**Analysis/proof:** Quorum threshold uses `CONSENSUS_QUORUM_BPS` and requires > 2/3 total active stake. Two of four equal validators produce 50%, below threshold. The expected behavior under a 2/2 partition is a stall, not independent progress. After healing, Status messages drive sync requests, `mark_caught_up` restores voting eligibility, and QC recovery can fetch missing tip QC.

**Severity:** SAFE.

**Recommended fix:** None for safety. For operations, monitor prolonged 2/2 stalls and ensure peer status/QC recovery logs are alerting-grade.

### CS-12 — Vote and QC replay protection

**Description:** Vote signatures bind height, round, step, full block hash, validator ID, and chain ID. Vote collectors reject wrong height/round/step. Embedded QC replay is rejected both by height and by parent-hash linkage.

**Attack scenario checked:** Replaying an old vote or QC at a later height disrupts consensus.

**Code location:**

- `indra-core/src/types/vote_signing.rs::vote_signing_bytes`
- `indra-consensus/src/vote.rs::VoteCollector::add_vote`
- `indra-node/src/sync.rs::verify_block_qc`
- `indra-node/src/driver.rs::handle_qc_response`

**Analysis/proof:** `vote_signing_bytes` includes chain ID when `vote_chain_id_active(height)` is true, plus height, round, step, block hash, and validator ID. `VoteCollector::add_vote` rejects votes whose height/round/step do not match the collector. QC recovery rejects a QC whose decoded `qc.height` is not the requested/current height. `verify_block_qc` rejects embedded QCs whose height is not `block.height - 1` and rejects QCs whose certified full hash does not match `block.header.prev_hash`.

**Severity:** SAFE after fix.

**Fix applied:** Same shared `verify_block_qc` parent-linkage check as CS-01.

## Fix Priority

1. **CS-04 — adaptive timeouts:** consider exponential/adaptive round timeouts for WAN stability. This is operational liveness hardening, not a correctness blocker.
2. **Mainnet proposer-election design:** resolved by the canonical commit/reveal VRF scheme with durable reveal evidence and QC-attested election results.

## Proof-of-Concept Tests

The CS-01 / CS-12 follow-up fix added regression tests in `indra-node/src/sync.rs`:

- `verify_block_qc_rejects_qc_certifying_wrong_parent_hash`
- `verify_block_qc_accepts_qc_certifying_correct_parent_hash`

The CS-08 cleanup added/updated regression tests for the chosen slashing model:

- `apply_slash_rejects_prevote_conflict`
- `same_slot_prevote_conflict_does_not_trigger_slash`
- existing double-precommit slashing tests remain active.

Remaining recommended follow-up test:

- Two validators whose actual VRF outputs each beat all public fallback scores for the same round should demonstrate that both proposals can pass `verify_proposer_vrf` independently under the current one-sided verified-output election.
