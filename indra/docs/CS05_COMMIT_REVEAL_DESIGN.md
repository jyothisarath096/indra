# CS-05 Commit-Reveal VRF Proposer Election Design

> **Status note (superseded by `16d72bc9`):** The proposer-election
> `VrfCommit`/`VrfReveal` implementation described below was removed from the
> active protocol by commit `16d72bc9`. The active protocol uses standard VRF
> proposer authorization and sortition. The commit-reveal material below is
> historical design context, not an active wire protocol.

## Scope

This document originally did two things:

1. Verifies the current CS-05 Option D fix: public deterministic proposer election.
2. Designs a future Option C commit-reveal VRF proposer election suitable for a follow-up implementation task.

## Implementation Status — FIXED

CS-05 has now been upgraded from the interim public deterministic proposer
election to a commit-reveal VRF proposer election.

Implemented architecture:

- Validators gossip ephemeral `VrfCommit` and `VrfReveal` messages for each
  `(height, round)`.
- Commits bind `chain_id_hash`, `height`, `round`, `validator_id`, `vrf_pk`,
  VRF input, VRF output, and the VRF proof hash under the
  `INDRA-VRF-COMMIT-v1` domain.
- Reveals are accepted only if the validator is active, the registered VRF key
  matches, the hybrid signature verifies, the VRF proof verifies, and the
  reveal opens a prior commit.
- The election result is represented as `VrfElectionResult` and committed as
  `SHA256("INDRA-ELECTION-v1" || height || round || elected_validator_id ||
  elected_vrf_output || fallback_used)`.
- `BlockHeaderV1` now carries `election_result_hash`.
- Precommit `VoteV1` signatures carry the same `election_result_hash`; prevotes
  do not.
- `QuorumCertificateV1` stores the attested `election_result_hash` so QC
  signature verification can reconstruct the exact precommit signing bytes.
- `block_hash()` includes the header `election_result_hash`, so the QC over the
  block hash commits to the elected proposer result.
- Sync/import verification remains O(1): it verifies VRF key ownership and
  checks that the header `election_result_hash` certifies the claimed proposer
  identity/output (or the fallback sentinel), without requiring historical
  commit/reveal gossip.

Migration notes:

- This is a consensus rule and network message change.
- Fresh testnet wipe is required before deploying this binary.
- No key regeneration is required.
- Genesis validator entries do not need to change.
- Block, vote, QC, and P2P encodings changed; all validators must run the new
  binary together.

The remainder of this document preserves the original diagnosis/design context
for audit history.

## Part A — Current Public Deterministic Election Verification

### A.1 Current-code answers

#### 1. Does `elect_proposer` ignore `verified_vrf_output` while public election is active?

Yes.

Code evidence:

- `ProposerCandidate` still has `verified_vrf_output: Option<VrfOutput>` for compatibility and tests (`indra-consensus/src/proposer.rs:10-20`).
- `public_proposer_output(...)` is the active public scoring function. It hashes the domain string `INDRA-PROPOSER-PUBLIC-v1`, `epoch_seed`, `height`, `round`, `validator_id`, and `vrf_pubkey` (`indra-consensus/src/proposer.rs:107-130`).
- `elect_proposer` chooses `public_proposer_output(...)` whenever `public_proposer_election_active(height)` is true (`indra-consensus/src/proposer.rs:148-161`).
- The mixed-output fallback that reads `candidate.verified_vrf_output` only exists in the older activation branch (`indra-consensus/src/proposer.rs:162-166`).
- `PUBLIC_PROPOSER_ELECTION_HEIGHT` is `0`, and `public_proposer_election_active(height)` checks `height >= PUBLIC_PROPOSER_ELECTION_HEIGHT` (`indra-core/src/types/primitives.rs:320-324`, `indra-core/src/types/primitives.rs:351-355`).

Result: for all current testnet heights, `verified_vrf_output` cannot affect proposer selection.

#### 2. Does `is_proposer` avoid injecting the local node's actual VRF output?

Yes.

`NodeEngine::is_proposer`:

- Requires a local VRF keypair and validator ID (`indra-node/src/engine.rs:422-427`).
- Finds the local validator in the candidate set (`indra-node/src/engine.rs:428-434`).
- Verifies the local VRF public key matches the registered validator VRF key (`indra-node/src/engine.rs:435-441`).
- Calls `elect_proposer(election, election.height)` directly and compares the returned winner to the local validator ID (`indra-node/src/engine.rs:442-452`).

There is no call to `compute_proposer_vrf` and no mutation of the candidate list in `is_proposer`.

#### 3. Does `verify_proposer_vrf` verify key ownership separately from winner selection?

Yes.

`verify_proposer_vrf` builds candidates with `verified_vrf_output: None` (`indra-node/src/sync.rs:274-285`). It then:

- Derives the election seed from the block's declared parent hash, so verification is bound to the header parent rather than mutable local tip state (`indra-node/src/sync.rs:300-305`).
- Recomputes the VRF input from seed, height, and proposer round (`indra-node/src/sync.rs:306-310`).
- Verifies the header's VRF proof/output against each active validator VRF key and requires exactly one matching validator (`indra-node/src/sync.rs:311-329`).
- Runs public election over the all-`None` candidate list and requires the matching validator to be the elected validator (`indra-node/src/sync.rs:331-350`).

Result: VRF proof is now key-ownership evidence; proposer selection is public deterministic election.

#### 4. Does `produce_block` still compute and embed a VRF proof without using it for election?

Yes.

`produce_block` computes the local proposer's VRF slot and proof for the header (`indra-consensus/src/producer.rs:74-86`), but separately calls `elect_proposer(election, election.height)` and requires the elected ID to match the local slot's proposer ID (`indra-consensus/src/producer.rs:88-91`).

The proof/output are then encoded into `proposer_vrf_output` and `proposer_vrf_proof` in the block header (`indra-consensus/src/producer.rs:119-147`).

Result: the VRF proof remains in the block header for verification, but does not affect selection while public election is active.

#### 5. Are there any remaining runtime paths that set `verified_vrf_output = Some(...)` for an active election?

No active runtime path was found.

Evidence:

- Live proposal-loop candidate construction sets `verified_vrf_output: None` (`indra-node/src/bin/node.rs:1820-1835`, `indra-node/src/bin/node.rs:1904-1921`).
- Incoming proposal verification sets `verified_vrf_output: None` (`indra-node/src/sync.rs:274-285`).
- Driver helper/test candidate construction uses `None` (`indra-node/src/driver.rs:1738-1763`, `indra-node/src/driver.rs:1783-1809`).
- `rg` finds `verified_vrf_output: Some(...)` only in tests, notably the regression test that proves verified output is ignored (`indra-consensus/src/proposer.rs:342-362`).

The field remains for compatibility and inactive hard-fork fallback logic, but not for current active proposer election.

### A.2 Determinism proof

Given the same chain state at a height/round, every correct validator computes the same proposer.

Inputs to `public_proposer_output` are:

- `epoch_seed`
- `height`
- `round`
- `validator_id`
- `vrf_pubkey`

The current live code derives the variable named `epoch_seed` from the parent/tip hash:

- Proposal loop: `sha256(state.tip_hash)` for the next height (`indra-node/src/bin/node.rs:1815-1817`, `indra-node/src/bin/node.rs:1899-1901`).
- Proposal verification: `sha256(block.header.prev_hash)` so the verifier uses the same parent seed the proposer used (`indra-node/src/sync.rs:300-305`).

Therefore, for validators on the same parent block, the seed is identical. `height` and `round` are consensus slot coordinates. `validator_id`, `vrf_pubkey`, and `stake` come from the active validator set. The score computation uses deterministic integer arithmetic: the first 8 output bytes are interpreted as `u64`, multiplied as `u128`, divided by stake, and clamped to `u64::MAX` (`indra-consensus/src/proposer.rs:84-94`). The winner comparison is a total order by score, then output bytes, then validator ID (`indra-consensus/src/proposer.rs:173-179`).

So two correct validators with the same parent, same active set, same height, and same round cannot disagree about the winner. If they disagree, at least one of those inputs differs; that is then a sync/state-consistency problem, not a proposer-election non-uniqueness problem.

### A.3 Grinding and predictability surface

The current Option D fix is deterministic and globally computable from public data. That is the right near-term liveness fix, but it is not the final mainnet design because it makes the proposer sequence predictable once the parent hash and active validator set are known.

Important detail: the code calls the seed an `epoch_seed`, but current construction uses the parent/tip hash for the next block. This means the next-height schedule is known immediately after the parent commits, and all rounds at that height are predictable from the same parent hash.

#### 4-validator testnet

Risk is low in the current 4-validator testnet because validators are known, registered keys are already fixed, and the immediate goal is eliminating multi-winner and zero-winner rounds.

Attack surface:

- A validator can know in advance which rounds it will win after the parent commits.
- A validator cannot cheaply change its registered VRF key every round if registration/key uniqueness/minimum-bond rules are enforced.
- With only 4 known validators, this is mostly an operational predictability issue, not a practical key-grinding attack.

Acceptability: acceptable for testnet.

#### 100 validators

Risk becomes medium if validator registration is permissionless and key rotation is cheap.

Attack surface:

- A validator or attacker can precompute scores for many candidate VRF public keys before registering.
- If registration accepts many identities at low cost, the attacker can choose keys/identities with favorable future slots.
- Stake weighting limits naive stake splitting, but multiple independently chosen keys still increase optionality if the attacker can register enough funded candidates.

Mitigation required before mainnet-scale permissionless operation:

- Minimum bond and active-set caps.
- Registration/activation delays so keys cannot be chosen after seeing the immediate seed they target.
- Preferably commit-reveal VRF so actual per-round outputs are not public until after a commit phase.

#### 1000 validators

Risk is high for a mainnet-size permissionless active set if Option D remains the permanent election rule.

Attack surface:

- Key grinding becomes a serious long-horizon optimization problem.
- The proposer schedule is publicly predictable, enabling targeted denial-of-service against upcoming proposers.
- Active-set manipulation and key-rotation policy become consensus-critical economic defenses.

Acceptability: not recommended as final mainnet proposer election.

### A.4 Requested regression tests

All requested tests passed locally:

```text
cargo test -p indra-consensus --lib elect_proposer --quiet
result: ok. 1 passed; 0 failed; 0 ignored; 47 filtered out

cargo test -p indra-node --lib only_one_validator_is_proposer --quiet
result: ok. 1 passed; 0 failed; 0 ignored; 132 filtered out

cargo test -p indra-node --lib two_validators_with_valid_vrf --quiet
result: ok. 1 passed; 0 failed; 0 ignored; 132 filtered out
```

## Part B — Commit-Reveal VRF Design

### B.1 Governance commit-reveal precedent

Governance already has a commit-reveal pattern that is useful as a design reference:

- `GovernancePayload::Commit` and `GovernancePayload::Reveal` dispatch through `apply_governance_op` (`indra-state/src/governance_apply.rs:43-69`).
- Proposal creation schedules deliberation, commit, reveal, tally, and execution-delay epochs (`indra-state/src/governance_apply.rs:165-173`).
- Proposal records persist `commits` and `reveals` maps (`indra-state/src/governance.rs:540-580`).
- Commit phase requires proposal phase `Commit`, eligible signer in snapshot1, no duplicate commit, and non-zero commit hash (`indra-state/src/governance_apply.rs:227-266`).
- Reveal phase requires proposal phase `Reveal`, prior commit from signer, no duplicate reveal, and matching commit hash (`indra-state/src/governance_apply.rs:268-313`).
- Epoch transition advances phases and tallies after the reveal window (`indra-state/src/epoch.rs:250-363`).

Differences for consensus VRF:

- Governance commit-reveal is epoch-scale and persistent state. Proposer election is round-scale and should be ephemeral or bounded.
- Governance reveal hash currently commits to vote and nonce only (`indra-state/src/governance_apply.rs:297-303`). Consensus VRF should use a stronger domain-separated preimage including chain ID, height, round, validator ID, VRF key, VRF output, and proof hash.
- Governance can tolerate long windows. Consensus cannot; commit/reveal windows must be short and integrated into round timeouts.

### B.2 Proposed message and evidence types

Add two consensus gossip messages:

```rust
pub struct VrfCommit {
    pub chain_id_hash: Bytes32,
    pub height: u64,
    pub round: u32,
    pub validator_id: Bytes32,
    pub vrf_pubkey: [u8; 32],
    pub commit_hash: Bytes32,
    pub signature: HybridSignature,
}

pub struct VrfReveal {
    pub chain_id_hash: Bytes32,
    pub height: u64,
    pub round: u32,
    pub validator_id: Bytes32,
    pub vrf_pubkey: [u8; 32],
    pub vrf_output: Bytes32,
    pub vrf_proof: VariableBytes<MAX_VRF_PROOF_BYTES>,
    pub commit_hash: Bytes32,
    pub signature: HybridSignature,
}
```

Recommended commitment preimage:

```text
SHA256(
  "INDRA-VRF-COMMIT-v1" ||
  chain_id_hash ||
  height ||
  round ||
  validator_id ||
  vrf_pubkey ||
  vrf_input ||
  vrf_output ||
  SHA256(vrf_proof_bytes)
)
```

The reveal is valid only if:

1. The validator is active for that height.
2. The `vrf_pubkey` matches the validator's registered key.
3. The reveal signature verifies under the validator's hybrid key.
4. The VRF proof verifies against `(vrf_pubkey, vrf_input, vrf_output)`.
5. A prior signed commit from the same validator for `(chain_id, height, round)` exists.
6. The recomputed commitment equals the prior commit hash.

#### Durable election evidence requirement

Commit-reveal creates a new sync/import problem: a live validator can verify commits and reveals from its in-memory round state, but a node syncing a finalized block later cannot reconstruct the reveal set unless that evidence is stored or certified.

Therefore Task 2 should not only add gossip messages. It should also add a durable election certificate, either in the block or in a QC extension:

```rust
pub struct VrfElectionCertificate {
    pub height: u64,
    pub round: u32,
    pub epoch_seed: Bytes32,
    pub commits: Vec<VrfCommit>,
    pub reveals: Vec<VrfReveal>,
    pub fallback_used: bool,
}
```

Block/proposal validation under commit-reveal should verify the certificate or, for live proposals, verify against locally observed round state and then persist enough evidence for later sync verification.

Open design choice for Task 2: certificate size. With 4 validators this is trivial. With a 1500-validator mainnet set and hybrid signatures, including all commits/reveals may be too large. A mainnet-grade version likely needs a compact certificate, aggregation, bitsets, or a rule that finalized QC voters attest proposer-election validity while sync relies on QC. For testnet implementation, a full explicit certificate is simplest and most auditable.

### B.3 Round phase and pipelining design

The minimal non-pipelined round flow is:

1. Enter `(height H, round R)`.
2. Validators compute their private VRF output/proof for `(H, R)`.
3. Validators gossip `VrfCommit(H, R)`.
4. Commit window closes when either enough commits arrive or `T_VRF_COMMIT_MS` expires.
5. Validators with accepted commits gossip `VrfReveal(H, R)`.
6. Reveal window closes when either enough reveals arrive or `T_VRF_REVEAL_MS` expires.
7. Election is computed from valid reveals.
8. The elected revealed validator proposes.
9. Normal prevote/precommit/finalization continues.

Recommended initial constants:

```rust
pub const T_VRF_COMMIT_MS: u64 = 500;
pub const T_VRF_REVEAL_MS: u64 = 500;
pub const MIN_VRF_REVEAL_STAKE_BPS: u32 = 6_667;
```

For mainnet liveness, pipelining should be added:

- Start `VrfCommit(H, R+1)` during prevote/precommit of `(H, R)`.
- Start `VrfReveal(H, R+1)` once enough commits or the commit timeout is reached.
- At the beginning of round `R+1`, the proposer is usually already known.
- For round 0 of a new height, start commit immediately after the parent commits. This adds the only unavoidable cold-start latency.

Election over reveals:

```text
valid_reveals = all reveals with a matching prior commit and valid VRF proof
winner = minimum stake-weighted election_score(vrf_output, stake, total_active_stake)
tiebreak = vrf_output bytes, then validator_id
```

The denominator should remain total active stake, not revealed stake. That preserves stake weighting and makes withholding reduce participation rather than increasing the relative weight of revealers.

### B.4 Withholding and fallback policy

Recommended rule:

- Commit without reveal: excluded from that round's election, equivalent to worst possible score.
- Reveal without prior commit: invalid.
- Duplicate commit/reveal for the same validator and slot: reject and peer-penalize. Future mainnet slashing can consider signed equivocation evidence for double-commit or double-reveal if needed.
- If at least one valid reveal exists by reveal timeout: elect from valid reveals.
- If no valid reveal exists: advance round, or use a clearly marked emergency fallback to current public deterministic election.

Preferred testnet policy:

```text
If zero valid reveals after T_VRF_REVEAL_MS, advance to the next round.
If this repeats for MAX_VRF_EMPTY_REVEAL_ROUNDS, use public deterministic fallback for one round and log loudly.
```

Rationale:

- A validator cannot improve its own chance by withholding after seeing others. If its reveal wins, it should reveal; if it loses, withholding does not make it win.
- A Byzantine validator can still grief by withholding to reduce reveal count or deny its own winning slot. That is a liveness issue, not a safety issue.
- Requiring 2/3 reveal stake for every round is safer against tiny reveal sets but can let one-third Byzantine stake force repeated timeouts. The testnet should measure this before hardening mainnet thresholds.

### B.5 ConsensusDriver state lifecycle

Add bounded per-slot state:

```rust
pub struct VrfRoundState {
    pub height: u64,
    pub round: u32,
    pub phase: VrfRoundPhase,
    pub commit_started_at: Instant,
    pub reveal_started_at: Option<Instant>,
    pub commits: BTreeMap<Bytes32, VrfCommit>,
    pub reveals: BTreeMap<Bytes32, VrfReveal>,
    pub pending_reveals: BTreeMap<Bytes32, VrfReveal>,
    pub elected: Option<Bytes32>,
}

pub enum VrfRoundPhase {
    Commit,
    Reveal,
    Complete,
    Fallback,
}
```

Lifecycle:

- Create for current round at round entry.
- Optionally create for next round during pipelining.
- Accept current-round and next-round commits/reveals only.
- Reject or drop old rounds and far-future rounds.
- Buffer reveal-before-commit only for current/next round, with a strict bounded map.
- On matching commit arrival, validate buffered reveal and move it into `reveals`.
- Clear all states for a height after finalization.
- Keep at most current and next round per height to prevent memory growth.
- On restart, empty VRF round state is acceptable; the node waits for the next round or syncs finalized blocks. Do not persist ephemeral commit/reveal state unless a block/election certificate requires it.

### B.6 Network gossip and validation

Current network messages include block, vote, transaction, peer list, sync request/response, status, proposal request, QC request, and QC response (`indra-network/src/message.rs:36-64`, `indra-network/src/message.rs:87-148`).

Add:

```rust
MessageType::VrfCommit = 0x0D
MessageType::VrfReveal = 0x0E

Message::VrfCommit(VrfCommit)
Message::VrfReveal(VrfReveal)
```

Processing rules:

- Fast-reject if signer is not active at the target height.
- Fast-reject if height/round is old or too far in the future.
- Verify hybrid signature before insertion into round state.
- Verify VRF proof on reveal before insertion into reveal set.
- Deduplicate by `(height, round, validator_id)`.
- Rate-limit like votes, with a small burst per validator per round.
- Gossip accepted commits/reveals to connected validators.
- Do not gossip invalid, duplicate, old, or far-future messages.

### B.7 Hard-fork activation

Add activation constants:

```rust
pub const VRF_COMMIT_REVEAL_ELECTION_HEIGHT: u64 = 0; // testnet fresh reset

pub fn vrf_commit_reveal_election_active(height: u64) -> bool {
    height >= VRF_COMMIT_REVEAL_ELECTION_HEIGHT
}
```

Behavior:

- Below activation: current public deterministic election remains active.
- At/after activation: proposal intake and block production require commit-reveal election result/certificate.
- Testnet can activate from genesis after a fresh reset.
- Mainnet must use a future announced hard-fork height.

Breaking-change status:

- Requires new network message types.
- Likely requires a block/QC wire-format extension if durable election certificates are embedded.
- Does not require key regeneration.
- Does not change cryptographic derivation of existing validator keys.

### B.8 Risk assessment

#### Safety

Commit-reveal does not weaken consensus safety if votes/QCs continue to certify full `block_hash()`. Even if two proposals are seen, only one full block hash can reach quorum under standard BFT quorum intersection.

The main safety requirement is deterministic proposal validity: all validators must evaluate the same election rule. That requires either shared live round state or a durable certificate for sync/import.

#### Liveness

New liveness risks:

- Commit messages delayed or dropped.
- Reveal messages delayed or dropped.
- Byzantine validators commit then withhold reveal.
- Too-strict reveal quorum causing timeout under partial network delay.
- Round latency increases by commit and reveal windows if not pipelined.

Mitigation:

- Pipeline next-round commit/reveal.
- Elect from available valid reveals after timeout.
- Advance round on zero reveals.
- Add bounded emergency fallback only after repeated empty-reveal rounds.

#### Latency

Non-pipelined implementation adds approximately `T_VRF_COMMIT_MS + T_VRF_REVEAL_MS` before every proposal. With the suggested 500 ms windows, that is roughly +1 second per round.

Pipelining reduces steady-state overhead because round `R+1` election material is collected while round `R` is still running. Round 0 of a new height still pays a cold-start cost unless the next height's seed is known early enough from the committed parent.

#### Withholding

A last revealer cannot change its already committed output, but can decide whether to reveal. This can deny its own winning slot or reduce the reveal set, causing liveness churn. It cannot safely create two valid winners if the election rule is deterministic over the accepted reveal set and validators vote only after computing the same accepted result.

#### Sync/import verification

This is the highest-design-risk area. The current `verify_proposer_vrf` can recompute public election from block header and active set. Commit-reveal cannot be recomputed later without reveal evidence. Task 2 must choose one of:

1. Store a full election certificate in each proposal/block.
2. Extend QC to attest proposer-election validity.
3. Use commit-reveal only for live proposal selection and rely on finalized QC during sync.

Option 1 is simplest for testnet and auditability. Option 2 is better long-term but larger protocol work. Option 3 is smallest but weakens local block-validity checks during sync.

## Recommended Task 2 Implementation Checklist

1. Add core consensus types:
   - `VrfCommit`
   - `VrfReveal`
   - `VrfElectionCertificate`
   - signing bytes and domain constants
   - encode/decode tests

2. Add network support:
   - `MessageType::VrfCommit`
   - `MessageType::VrfReveal`
   - message encoding/decoding tests
   - rate-limit buckets

3. Add hard-fork gate:
   - `VRF_COMMIT_REVEAL_ELECTION_HEIGHT`
   - `vrf_commit_reveal_election_active(height)`
   - fallback to public deterministic election below activation

4. Add proposer election logic:
   - `compute_vrf_commit_hash`
   - `verify_vrf_commit`
   - `verify_vrf_reveal`
   - `elect_proposer_from_reveals`
   - deterministic tiebreak rules

5. Add `ConsensusDriver` round state:
   - `VrfRoundState`
   - current/next round bounded maps
   - commit/reveal timers
   - reveal-before-commit buffering
   - cleanup on finalization and round advance

6. Add block/proposal evidence:
   - embed or attach `VrfElectionCertificate`
   - verify certificate at proposal intake
   - verify certificate during sync/import
   - decide certificate-size strategy for 4-validator testnet vs larger active sets

7. Update block production:
   - produce local commit at round start
   - produce local reveal after commit window
   - propose only if local validator is elected by reveal set
   - include VRF proof/output as before
   - include election certificate if selected

8. Update proposal verification:
   - verify proposer VRF proof still matches registered key
   - verify commit-reveal election result/certificate
   - reject non-elected proposer

9. Add tests:
   - valid commit then reveal verifies
   - reveal without commit rejected
   - reveal with wrong proof rejected
   - duplicate commit/reveal rejected
   - all validators compute the same winner from the same reveal set
   - non-revealer cannot win
   - zero-reveal round advances/fallbacks as specified
   - sync verifier rejects block with missing/invalid election certificate
   - public deterministic election remains valid below activation height

10. Migration notes:
    - testnet: fresh reset recommended
    - mainnet: future hard-fork height required
    - no key regeneration required
    - likely block/network wire-format changes if certificates are embedded

## Final Recommendation

Keep the current public deterministic election for testnet stability. It correctly fixes the original CS-05 multi-winner/zero-winner liveness regression, and the targeted tests pass.

For mainnet-grade proposer unpredictability, implement commit-reveal as a separate hard-forked protocol upgrade. The follow-up implementation should not be limited to adding commit/reveal gossip: it must also define durable election evidence for proposal intake and sync/import validation. Without that, live consensus can verify the election, but replaying or syncing nodes cannot independently verify proposer eligibility from stored blocks.
