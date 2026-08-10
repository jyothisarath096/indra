> **Historical archive:** This records completed audit work and intermediate designs. It is not current guidance; canonical specifications and current code take precedence.

# INDRA Security Audit — Phase 5: Governance Security

## Executive Summary

Phase 5 found two high-priority governance vulnerabilities and three medium/low hardening gaps. GV-01, GV-02, GV-04, GV-08, and GV-09 are now fixed. Governance proposal deposits must be owned by the proposer before the UTXO can be spent, closing the direct funds-at-risk path. Queued governance actions are revalidated immediately before both manual and automatic execution, preserving monotonic safety rules such as "governance YES-stake thresholds can only increase." Client vote encoding now matches state semantics (`0 = no`, `1 = yes`, abstain by not revealing), governance mempool admission validates ops against scratch state before acceptance, and `min_delegation_spark` has a hard upper bound.

Regression tests were added for all fixed Phase 5 findings. Remaining lower-priority governance cleanup is historical proposal pruning/archival.

## Summary Table

| ID | Component | Finding | Severity | Status |
|----|-----------|---------|----------|--------|
| GV-01 | Authorization | Proposal deposit UTXO ownership is now enforced before spending | CRITICAL | FIXED |
| GV-02 | Authorization | CLI/FFI vote encoding now matches state reveal semantics | MEDIUM | FIXED |
| GV-03 | Authorization | Double voting is prevented by one commit/reveal per validator per proposal | SAFE | VERIFIED |
| GV-04 | Lifecycle | Governance mempool admission validates ops before acceptance; historical proposal pruning remains cleanup | MEDIUM | FIXED |
| GV-05 | Threshold denominator | YES-threshold denominator is snapshot total governance stake, not live mutable stake | SAFE | VERIFIED |
| GV-06 | YES threshold | Approval requires yes stake to exceed the configured total-stake threshold; minority pass not possible under defaults | SAFE | VERIFIED |
| GV-07 | YES threshold | Thresholds are stake-weighted, not validator-count-weighted | SAFE | VERIFIED |
| GV-08 | Parameters | `min_delegation_spark` now has a maximum and stale governance constants are deprecated | LOW | FIXED |
| GV-09 | Parameters | Queued governance-of-governance actions are now revalidated at execution time | HIGH | FIXED |
| GV-10 | Parameters | Phase 4 security constants are mostly hard-coded and not governable | SAFE | VERIFIED |
| GV-11 | Execution | Timelocks exist for all passed proposals before execution | SAFE | VERIFIED |
| GV-12 | Execution | Block-level governance application is atomic via scratch-state validation/commit | SAFE | VERIFIED |
| GV-13 | Execution | Governance ops are chain-ID domain separated, nonce-protected, and execute-once | SAFE | VERIFIED |
| GV-14 | Economic | No direct treasury-withdrawal governance action exists; deposit theft is covered by GV-01 | SAFE | VERIFIED |
| GV-15 | Economic | Less than one-third stake cannot pass current standard or critical proposals alone | SAFE | VERIFIED |
| GV-16 | Economic | Governance cannot directly undo ST-01 minimum validator bond, ST-13 unbonding/evidence windows, or consensus quorum | SAFE | VERIFIED |

## Detailed Findings

### GV-01 — Proposal Deposit UTXO Ownership Is Enforced

Severity: CRITICAL

Status: FIXED

Code evidence:

- `apply_governance_op` verifies the governance operation signature and nonce before dispatching the proposal payload: `indra-state/src/governance_apply.rs:31`.
- `apply_propose` requires the signer to be an `Active` or `Registered` validator and enforces global/per-proposer proposal caps: `indra-state/src/governance_apply.rs:90`.
- The deposit UTXO is looked up, then `deposit.output.owner_pubkey` is required to equal `proposer_pubkey` before value checking and spending.
- The deposit is then spent with `state.utxos.spend(deposit_utxo_id)`.
- Refunds are minted to `proposal.proposer_pubkey`, with an explicit comment documenting that the proposer is the enforced deposit owner.
- Cancellation can burn the deposit during deliberation and only requires the proposer identity: `apply_cancel` at `indra-state/src/governance_apply.rs:374`.

Previous attack scenario:

1. The attacker is a registered or active validator.
2. The attacker observes a victim UTXO whose public `value_spark` is at least `proposal_deposit_spark`.
3. The attacker submits a validly signed governance proposal using the victim's `deposit_utxo_id`.
4. Before the fix, the state spent the victim UTXO immediately, without proving victim consent.
5. If the attacker cancelled or the proposal failed with low support, the victim's funds were burned.
6. If the proposal passed or reached the deposit-return support threshold, the refund was created for the attacker's `proposer_pubkey`.

Fix implemented:

`apply_propose` now rejects any proposal whose deposit UTXO `owner_pubkey` is not exactly the proposer key used in the governance payload. This uses the existing `HybridPubKey` type on both `OutputV1.owner_pubkey` and `GovernancePayload::Propose.proposer_pubkey`, so the comparison is type-safe and does not require a wire-format change.

Proof-of-concept sketch:

```rust
#[test]
fn governance_proposal_can_spend_third_party_deposit_utxo() {
    // Setup: victim owns a UTXO with value >= proposal_deposit_spark.
    // Setup: attacker is a registered validator with valid governance signing keys.
    // Action: attacker submits GovernancePayload::Propose using victim_deposit_utxo_id
    //         and attacker's proposer_pubkey.
    // Expected vulnerable behavior today:
    //   apply_governance_op(&mut state, &attacker_op, epoch, chain_id).unwrap();
    //   assert!(state.utxos.get(&victim_deposit_utxo_id).is_none());
    //   assert_eq!(proposal.proposer_pubkey, attacker_pubkey);
    // Fix expectation:
    //   proposal must fail unless the deposit owner signs/authorizes the spend.
}
```

Regression tests:

- `governance_proposal_rejects_deposit_utxo_not_owned_by_proposer`
- `governance_proposal_accepts_deposit_utxo_owned_by_proposer`
- `governance_deposit_refund_goes_to_proposer`

### GV-02 — Vote Authorization and Client Vote Encoding

Severity: MEDIUM

Status: FIXED

Code evidence:

- Governance operations are hybrid signed using `governance_signing_domain`, which includes the action type, signer ID, nonce, payload, and `chain_id`: `indra-core/src/types/governance.rs:512`.
- Commit/reveal signer keys are loaded from the validator set with `validator_pubkey`: `indra-state/src/governance_apply.rs:439`.
- Voting authorization is snapshot-gated: commits require `snapshot1` and reject signers absent from that snapshot.
- Double commits are rejected by `proposal.commits.contains_key(&op.signer_id)`.
- Reveal votes accept only `0` or `1`, where `1` is yes and `0` is no.
- CLI parsing now maps `"no"`/`"0"` to `0`, `"yes"`/`"1"` to `1`, and rejects explicit `"abstain"` with guidance that abstention is represented by not submitting a reveal op.
- FFI vote handling now accepts only the state wire values `0` and `1`; `2` is rejected as invalid.

Analysis:

The on-chain authorization model is strong: active/registered validator voting is hybrid-signed, nonce-protected, and tied to the chain ID. The client tooling now matches the state machine. INDRA keeps the existing non-breaking reveal model: `0 = no`, `1 = yes`, and abstention means not revealing.

Regression tests:

- `cli_no_vote_encodes_to_state_no_value`
- `cli_yes_vote_encodes_to_state_yes_value`
- `state_rejects_invalid_reveal_value`
- `abstain_behavior_is_explicitly_documented`
- FFI `governance_no_vote_uses_state_no_value`
- FFI `governance_invalid_vote_rejected`

### GV-03 — Double Voting Prevention

Severity: SAFE

Status: VERIFIED

Code evidence:

- `apply_commit` rejects a second commit from the same validator for the same proposal.
- `apply_reveal` requires an existing commit and rejects duplicate reveals.
- Nonces are also consumed per signer via `apply_governance_nonce` before dispatch: `indra-state/src/governance_apply.rs:31`.

Analysis:

A validator cannot add two different commit hashes or reveal twice for the same proposal. Vote weight is keyed by validator ID in proposal maps and by snapshot weights. Double-voting is therefore prevented at both the proposal level and the operation replay level.

### GV-04 — Proposal Lifecycle, Expiry, and Mempool Admission

Severity: MEDIUM

Status: FIXED

Code evidence:

- Active proposal caps are present: `MAX_ACTIVE_GOVERNANCE_PROPOSALS = 3` and `MAX_ACTIVE_GOVERNANCE_PROPOSALS_PER_PROPOSER = 1` at `indra-state/src/governance.rs:21`.
- Proposal timing constants are fixed in epochs: deliberation 30, commit 20/30, reveal 10 at `indra-state/src/governance.rs:27`.
- Epoch transitions move proposals from deliberation to commit, reveal, tally, execution delay, and auto-execution: `indra-state/src/epoch.rs:247`.
- Governance mempool admission in `NodeEngine::add_governance_op` now validates each op against a scratch clone of current state before admission.
- RPC still decodes governance ops and sends them to the engine, but engine admission now rejects bad signatures, invalid nonces, ineligible signers, missing proposals, and invalid proposal/deposit state.
- Proposer selection now applies governance ops sequentially to scratch state and evicts invalid pending ops instead of blindly taking the first `MAX_GOV_OPS_PER_BLOCK`.

Analysis:

The on-chain lifecycle has strong active caps and long timing windows, so live proposal spam is bounded. Invalid governance ops are now rejected before entering the engine mempool. Pending ops that become stale after admission are pruned/evicted before proposal construction.

There is also no apparent historical pruning of inactive proposal records. This is less urgent because active caps, deposit cost, and proposer cooldown bound near-term abuse, but historical storage growth should be bounded before mainnet.

Regression tests:

- `governance_mempool_rejects_invalid_signature`
- `governance_mempool_rejects_op_for_nonexistent_proposal`
- `governance_mempool_accepts_valid_op`

### GV-05 — YES-Threshold Denominator

Severity: SAFE

Status: VERIFIED

Code evidence:

- Snapshot 1 is taken when a proposal enters commit phase: `indra-state/src/epoch.rs:247`.
- The snapshot includes `Active` and `Registered` validators with positive `validator.stake_spark + delegated` weight: `take_governance_snapshot` at `indra-state/src/epoch.rs:386`.
- Tally uses snapshot total stake and snapshot-derived weights, not current live stake: `tally_votes` at `indra-state/src/epoch.rs:440`.

Analysis:

Governance voting weight is based on a snapshot, avoiding mid-vote stake mutation changing the YES-threshold denominator. Delegated stake is intentionally included for governance, with a reveal-phase redelegation overlay available to delegators. This is a governance-policy choice rather than a consensus-safety issue.

### GV-06 — Approval Threshold and Minority-Pass Risk

Severity: SAFE

Status: VERIFIED

Code evidence:

- Default standard YES-stake threshold is 5000 bps and default critical YES-stake threshold is 6700 bps: `GovernableParams::default_mainnet` at `indra-state/src/governance.rs:62`.
- A proposal passes only when `yes_stake > bps_of(total_stake, quorum_bps)`: `GovernanceSnapshot::quorum_met_at_height` at `indra-state/src/governance.rs:330`.
- No votes and non-reveals are not counted as yes; they effectively block passage unless yes stake exceeds the threshold.

Analysis:

There is no separate "participating vote" denominator that would let a small yes minority pass while others abstain. Yes stake must exceed the configured fraction of total snapshot stake. Under defaults, less than one-third stake cannot pass standard or critical proposals alone.

### GV-07 — Count-Based vs Stake-Weighted Thresholds

Severity: SAFE

Status: VERIFIED

Code evidence:

- Snapshot weights are `validator.stake_spark + delegated`: `indra-state/src/epoch.rs:386`.
- Tally accumulates yes/no/abstain by stake weight: `indra-state/src/epoch.rs:440`.

Analysis:

Governance does not use validator count for passage. Registering many tiny validators does not multiply voting power beyond their actual stake/delegation weight.

### GV-08 — Governable Parameters and Bounds

Severity: LOW

Status: FIXED

Governable actions:

- `SetSlashLivenessThresholdEpochs`
- `SetMinDelegationSpark`
- `SetProposalDepositSpark`
- `SetSlashLivenessBps`
- `SetSlashDoublePrecommitBps`
- `SetSlashSurroundVoteBps`
- `SetMaxCommissionBps`
- `SetGovernanceDelayEpochs`
- `SetGovernanceQuorumBps`
- `SetGovernanceCriticalQuorumBps`

Code evidence:

- The action enum is in `indra-core/src/types/governance.rs:87`.
- Tiers are defined in `GovernableAction::tier` at `indra-core/src/types/governance.rs:142`.
- Bounds are checked in `GovernableParams::validate_action` at `indra-state/src/governance.rs:80`.

Bounds summary:

| Parameter | Bound behavior |
|---|---|
| `slash_liveness_threshold_epochs` | 1 to 10 |
| `min_delegation_spark` | `DUST_LIMIT_SPARK` to `MAX_DELEGATION_SPARK` |
| `proposal_deposit_spark` | 100 to 10,000 INDRA |
| `slash_liveness_bps` | 1 to 1000 |
| `slash_double_precommit_bps` | 100 to 5000 |
| `slash_surround_vote_bps` | must be >= current double-precommit slash bps and <= 5000 |
| `max_commission_bps` | can only decrease; floor 500 |
| `governance_delay_epochs` | can only increase; 10 to 1000 |
| `governance_quorum_bps` | can only increase; 4000 to 9000 |
| `governance_critical_quorum_bps` | can only increase; 5000 to 9500 |

Analysis:

Most security-sensitive parameters have hard floors/ceilings and monotonic constraints. `SetMinDelegationSpark` is now bounded above by `MAX_DELEGATION_SPARK`, currently equal to `MINIMUM_VALIDATOR_BOND_SPARK`, so governance cannot set the delegation floor above the cost to register a validator. Stale constants `QUORUM_THRESHOLD_BPS` and `PASS_THRESHOLD_BPS` are now explicitly deprecated in primitives because current governance uses `GovernableParams` thresholds.

Regression tests:

- `governance_cannot_set_min_delegation_above_maximum`
- `governance_can_set_min_delegation_within_bounds`

### GV-09 — Governance-of-Governance Queued Execution Is Revalidated

Severity: HIGH

Status: FIXED

Code evidence:

- Actions are validated at proposal time in `apply_propose`: `state.governance.params.validate_action(action)` at `indra-state/src/governance_apply.rs:90`.
- Passed proposals are queued with their action and executable epoch after tally: `indra-state/src/epoch.rs:247`.
- Manual execution now calls shared execution-time revalidation before applying the action.
- Auto-execution now calls the same shared revalidation helper before applying the action.
- If revalidation fails, the proposal is marked `Failed`, the queued execution is marked consumed, and the action is not applied.

Attack scenario:

1. Current standard governance YES-stake threshold is 5000 bps.
2. Proposal A raises the standard threshold to 6000 bps. It is valid at proposal time and passes.
3. Proposal B raises the standard threshold to 7000 bps. It is also valid and executes first.
4. Proposal A executes later and sets the threshold to 6000 bps.
5. Before the fix, the monotonic rule "`governance_quorum_bps` can only increase" was bypassed because A was not revalidated against the current 7000 bps value.
6. After the fix, proposal A fails execution-time revalidation and the threshold remains 7000 bps.

The same pattern can affect:

- `governance_critical_quorum_bps`
- `governance_delay_epochs`
- `max_commission_bps`
- `slash_surround_vote_bps` relative to `slash_double_precommit_bps`

Proof-of-concept sketch:

```rust
#[test]
fn stale_queued_governance_action_can_lower_monotonic_quorum() {
    // Setup params.governance_quorum_bps = 5000.
    // Queue proposal A: SetGovernanceQuorumBps { value: 6000 }.
    // Queue proposal B: SetGovernanceQuorumBps { value: 7000 }.
    // Execute B first: params.governance_quorum_bps == 7000.
    // Execute A later.
    // Vulnerable behavior today:
    //   params.governance_quorum_bps == 6000.
    // Fix expectation:
    //   A is rejected/expired at execution because it no longer validates
    //   against current params.
}
```

Fix implemented:

`revalidate_queued_governance_action_or_fail` now re-runs `state.governance.params.validate_action(&exec.action)` immediately before both manual and automatic execution. If the action no longer validates against current parameters, the proposal is marked `Failed`, any remaining refundable deposit is returned through the existing deposit-return path, and the action is not applied.

Regression tests:

- `queued_governance_action_revalidated_before_execution`
- `valid_queued_governance_action_still_executes`
- `auto_execute_revalidates_stale_proposals`
- `failed_execution_time_revalidation_marks_proposal_failed`

### GV-10 — Phase 4 Security Constants Exposure

Severity: SAFE

Status: VERIFIED

Analysis:

The following Phase 4 hardening constants are not governable through the current action set:

- `MINIMUM_VALIDATOR_BOND_SPARK`
- `MINIMUM_ACTIVE_SELF_STAKE_SPARK`
- `UNBONDING_PERIOD_EPOCHS`
- `SLASH_EVIDENCE_WINDOW_EPOCHS`
- `MAX_VALIDATORS`
- `CONSENSUS_QUORUM_BPS`

Governance can adjust `min_delegation_spark`, proposal deposit, slashing percentages, commission ceiling, and governance thresholds/delay within bounded ranges. It cannot directly re-enable zero-bond validator registration, shorten the slash evidence window, lower consensus quorum, or raise the validator cap.

### GV-11 — Timelock Between Approval and Execution

Severity: SAFE

Status: VERIFIED

Code evidence:

- Proposal phases include deliberation, commit, reveal, tally, execution delay, and executed/failed/cancelled states.
- Proposal timing is assigned at creation: `commit_start_epoch`, `reveal_start_epoch`, `tally_epoch`, and `executable_after_epoch` in `apply_propose`.
- `apply_execute` rejects execution before `executable_epoch`: `indra-state/src/governance_apply.rs:345`.
- Auto-execution also waits until `current_epoch >= executable_epoch`: `indra-state/src/epoch.rs:365`.

Analysis:

Governance cannot propose, vote, and execute in the same block or short span. The default delay is `GOVERNANCE_DELAY_EPOCHS = 100`, and governance can only increase that delay under current validation rules.

### GV-12 — Execution Atomicity

Severity: SAFE

Status: VERIFIED

Code evidence:

- `apply_block` clones a scratch state and commits it back only after `apply_block_inner` succeeds: `indra-state/src/apply.rs:320`.
- Governance ops are shadow-applied before real mutation: `indra-state/src/apply.rs:409`.
- Real governance op application happens later in the same block after validation: `indra-state/src/apply.rs:440`.
- Epoch transitions, including governance phase transitions and auto-execution, run inside block application: `indra-state/src/apply.rs:473`.

Analysis:

Block-level governance execution is atomic at the state-transition level. If a governance operation or epoch transition returns an error during block application, the scratch state is not committed. GV-09 is a validation-timing bug, not an atomicity failure.

### GV-13 — Replay Protection

Severity: SAFE

Status: VERIFIED

Code evidence:

- `GovernanceOpV2` includes `signer_id`, `nonce`, payload, and hybrid signature: `indra-core/src/types/governance.rs:435`.
- `governance_signing_domain` includes `chain_id`: `indra-core/src/types/governance.rs:512`.
- `compute_proposal_id` includes `chain_id`: `indra-core/src/types/governance.rs:497`.
- `apply_governance_nonce` is called before dispatch: `indra-state/src/governance_apply.rs:31`.
- Executions carry an `executed` flag and `apply_execute` rejects repeated execution: `indra-state/src/governance_apply.rs:345`.

Analysis:

Governance operations are protected against same-chain replay by per-signer nonces and against cross-chain replay by chain-ID domain separation. Proposal IDs also include chain ID. Executed proposals cannot be executed again through the queued execution path.

### GV-14 — Treasury Access Via Governance

Severity: SAFE

Status: VERIFIED

Analysis:

The current `GovernableAction` enum does not include treasury withdrawal, arbitrary transfer, mint, or burn actions. Governance can affect parameters only. There is therefore no direct treasury-drain governance path. The deposit-ownership bug in GV-01 is an unauthorized UTXO spend/refund path, but it is not a general treasury withdrawal mechanism.

### GV-15 — Governance Capture With Less Than One-Third Stake

Severity: SAFE

Status: VERIFIED

Analysis:

Under defaults, standard proposals require yes stake greater than 50% of total snapshot stake and critical proposals require yes stake greater than 67%. A less-than-one-third stake attacker cannot pass either category alone, cannot lower governance thresholds because threshold changes are critical and monotonic upward, and cannot modify voter eligibility. The main caveat is GV-09: stale already-queued proposals can violate monotonic parameter intent after another proposal changes the same parameter.

### GV-16 — Interaction With Phase 4 Staking Security Fixes

Severity: SAFE

Status: VERIFIED

Analysis:

Governance cannot directly undo the high-severity Phase 4 fixes:

- ST-01 minimum validator bond is a hard-coded primitive/state rule, not a governable parameter.
- ST-02 key uniqueness is a registration invariant, not governable.
- ST-13 slash evidence window and unbonding period are hard-coded constants, not governable.
- ST-05 minimum active self-stake is hard-coded through `MINIMUM_ACTIVE_SELF_STAKE_SPARK`.

Governance can tune `min_delegation_spark`, slashing basis points, commission ceilings, governance delays, and governance YES-stake thresholds within the explicit bounds above. Those are economically sensitive but bounded.

## Proof-of-Concept / Regression Tests

The following high-severity proof-of-concept cases are now covered by regression tests in `indra-state/src/governance_apply.rs`.

### PoC 1 — Third-Party Governance Deposit Spend

Target finding: GV-01.

```rust
#[test]
fn governance_proposal_rejects_deposit_not_owned_by_proposer() {
    // Build state with victim UTXO >= proposal_deposit_spark.
    // Register attacker as an active/registered validator.
    // Construct a signed GovernancePayload::Propose from attacker
    // using victim_deposit_utxo_id and attacker proposer_pubkey.
    // Previous vulnerable behavior: apply_governance_op succeeds and
    // victim UTXO disappears.
    // Fixed behavior: apply_governance_op returns InvalidGovernanceOp
    // and victim UTXO remains present.
}
```

### PoC 2 — Stale Queued Proposal Violates Monotonic Governance Parameter

Target finding: GV-09.

```rust
#[test]
fn queued_governance_action_is_revalidated_before_execution() {
    // Queue two passed governance YES-stake threshold proposals:
    // A: SetGovernanceQuorumBps { value: 6000 }
    // B: SetGovernanceQuorumBps { value: 7000 }
    // Execute B first.
    // Previous vulnerable behavior: executing A later lowers the threshold to 6000.
    // Fixed behavior: A fails execution-time validation and the threshold remains 7000.
}
```

### PoC 3 — Client Vote Encoding Regression

Target finding: GV-02.

```rust
#[test]
fn governance_cli_no_vote_encodes_to_state_no_vote() {
    // CLI "no" must produce the state wire value for no.
    // Fixed behavior: "no" encodes to 0, "yes" to 1, and explicit abstain
    // is rejected client-side because abstention means not revealing.
}
```

## Findings NOT Present

- Governance operations are hybrid signed, not classical-only.
- Governance signing is chain-ID domain separated.
- Governance operation replay is nonce-protected.
- Proposal IDs include chain ID.
- Proposal passage is stake-weighted, not validator-count-weighted.
- Less than one-third stake cannot pass current standard or critical proposals alone.
- Critical parameter changes have higher thresholds than standard changes.
- Governance cannot directly change consensus quorum, maximum validator count, minimum validator bond, unbonding period, slash evidence window, or total supply.
- No direct treasury withdrawal action exists.
- Block-level governance application uses scratch-state atomicity.

## Remaining Cleanup

1. **GV-04 cleanup — Add historical proposal pruning/archival policy.** Active proposal spam is bounded, but inactive proposal history still needs an archival/pruning design before mainnet-scale operation.
