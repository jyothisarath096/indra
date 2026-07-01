# INDRA Security Audit — Phase 4: Staking and Economic Security

## Executive Summary

Phase 4 found three high-priority staking/economic issues and several medium/low hardening gaps. The three HIGH findings have now been fixed locally: validator registration requires an atomic minimum self-bond, validator key material is globally uniqueness-checked at registration, and unbonding self-stake remains slashable for valid evidence within the evidence window. The audit also confirmed several safe properties: staking operations are hybrid-signed with chain-id domain separation, delegation/unstake operations enforce ownership and unbonding delays, commission is capped by governance limits, duplicate slash evidence is rejected, and total-supply accounting is mostly explicit for rewards, fees, and slashing.

Fix status note: ST-01 intentionally changes the `RegisterValidator` staking-op wire format and requires a fresh testnet wipe after deployment. It does not require key regeneration. ST-02 and ST-13 do not change cryptographic derivation, key material, or block/QC wire formats.

## Summary Table

| ID | Component | Finding | Severity | Status |
|----|-----------|---------|----------|--------|
| ST-01 | Registration | Validator registration is permissionless and does not require bond before consuming registry capacity | HIGH | FIXED |
| ST-02 | Registration | Duplicate VRF keys are not rejected at registration | HIGH | FIXED |
| ST-03 | Bonding | Staking trusts `OutputV1.value_spark` as bond amount without per-output commitment opening | MEDIUM | OPEN |
| ST-04 | Unbonding | Unbonding delay exists and is state-enforced | SAFE | VERIFIED |
| ST-05 | Unbonding | Self-unstake can leave an active validator below practical minimum stake until epoch reselection | MEDIUM | OPEN |
| ST-06 | Rewards | Reward weights use validator self-stake, while active-set selection includes delegated stake | MEDIUM | OPEN |
| ST-07 | Rewards | Commission is capped, but changes take effect immediately for the next epoch distribution | LOW | OPEN |
| ST-08 | Rewards | Reward arithmetic is mostly bounded; rounding remainders are deterministic but not always explicitly accounted | LOW | OPEN |
| ST-09 | Rewards | Epoch transition is not transactionally atomic if a late transition step errors | MEDIUM | OPEN |
| ST-10 | Slashing | Slash amount and fund accounting are deterministic for active self-stake | SAFE | VERIFIED |
| ST-11 | Slashing | Double-slash protection prevents repeated penalties | SAFE | VERIFIED |
| ST-12 | Slashing | Slash underflow is avoided with saturating arithmetic | SAFE | VERIFIED |
| ST-13 | Slashing | Self-unstaking before evidence can avoid or reduce slashing | HIGH | FIXED |
| ST-14 | Economic | Delegated stake affects active-set selection but not consensus voting power | MEDIUM | OPEN |
| ST-15 | Economic | Proposer timing can affect fees/censorship, but not mint extra block reward | LOW | OPEN |
| ST-16 | Economic | Total-supply invariants are mostly preserved; liveness penalty and epoch failure paths need clearer policy/tests | LOW | OPEN |

Severity scale: CRITICAL / HIGH / MEDIUM / LOW / INFO / SAFE.

## Detailed Findings

### ST-01 — Validator registration is permissionless and consumes bounded registry capacity

Severity: HIGH  
Status: FIXED

Description: `apply_register_validator` accepts a signed `RegisterValidator` operation, checks commission bounds, derives `validator_id` from the supplied hybrid public key, rejects only an existing `validator_id`, and inserts a `ValidatorEntry` with `stake_spark: 0` and `status: Registered`. It does not require a self-bond, a deposit, governance approval, or a minimum stake before occupying a validator registry slot. `ValidatorSet::upsert` enforces `MAX_VALIDATORS` only by rejecting new entries once the map is full.

Code locations:

- `indra-state/src/delegation.rs:185` — `apply_register_validator`
- `indra-state/src/delegation.rs:203` — duplicate check only by `validator_id`
- `indra-state/src/delegation.rs:214` — new validator starts with `stake_spark: 0`
- `indra-state/src/validator.rs:454` — `ValidatorSet::upsert` rejects additions only after `MAX_VALIDATORS`
- `indra-core/src/types/primitives.rs:24` — `MAX_VALIDATORS = 1_500`

Attack scenario:

1. An attacker generates many hybrid validator keys and VRF keys.
2. The attacker submits signed `RegisterValidator` staking ops over many blocks.
3. Each registration costs no bond and inserts a zero-stake `Registered` validator.
4. Once `MAX_VALIDATORS` entries exist, future honest registrations fail with "validator set at maximum capacity."
5. The active set is not immediately corrupted because zero-stake validators rank poorly, but the registry is polluted and new entrants can be denied.

Proof-of-concept reasoning:

The exploit does not need private keys for existing validators or funds. It only needs valid signatures from newly generated keys. `apply_register_validator` has no UTXO or stake input, and `upsert` counts zero-stake registered entries toward the global cap.

Recommended fix:

Require registration to be paired with a minimum self-bond or registration deposit before consuming long-lived registry capacity. Also consider pruning never-bonded registrations after a timeout and/or moving candidate registrations into a separate bounded pending set until bonded.

Fix implemented:

`RegisterValidator` now carries a `bond_utxo_id`. State validation requires that UTXO to belong to the registering validator, have `value_spark >= MINIMUM_VALIDATOR_BOND_SPARK`, and be consumed atomically into a self-bond while the validator entry is inserted with nonzero `stake_spark`. This makes registry spam cost at least `MAX_VALIDATORS * MINIMUM_VALIDATOR_BOND_SPARK` in locked stake. This is a staking-op wire-format change and requires a fresh testnet wipe; it does not require key regeneration.

### ST-02 — Duplicate VRF keys are not rejected at registration

Severity: HIGH  
Status: FIXED

Description: Registration derives identity from the hybrid public key and rejects only duplicate `validator_id`. It does not scan existing validators for duplicate `vrf_pk`. After the CS-05 public deterministic election change, the VRF proof in a block header is still used as key-ownership proof. `verify_proposer_vrf` rejects a proposal if the proof matches zero or more than one active validator. Therefore, if two active validators share the same VRF key, a valid proof for that key can match both and cause proposer verification failure.

Code locations:

- `indra-state/src/delegation.rs:203` — duplicate check only by `validator_id`
- `indra-state/src/delegation.rs:217` — stores `vrf_pk: Some(vrf_pk)` without uniqueness check
- `indra-node/src/sync.rs:302` — `verify_proposer_vrf` collects all candidates whose VRF proof verifies
- `indra-node/src/sync.rs:306` — rejects unless `matching_candidates.len() == 1`

Attack scenario:

1. Attacker observes a target validator's registered VRF public key.
2. Attacker registers a new validator with a distinct hybrid key but the same `vrf_pk`.
3. If the attacker later gets that validator into the active set, the target's valid proposer proof matches both active validator entries.
4. The proposal is rejected as ambiguous, causing liveness failures for slots won by the duplicated key.

Proof-of-concept reasoning:

The current registration path allows duplicate `vrf_pk` because uniqueness is only checked for `validator_id`. The verifier explicitly treats multiple matching VRF keys as invalid. This turns duplicate VRF registration into an active-set DoS once the duplicate entry becomes active.

Recommended fix:

At registration, enforce uniqueness across `validator_id`, `hybrid_classical_pk`, `hybrid_pq_pk`, and `vrf_pk`. At minimum, reject duplicate VRF keys globally, including against inactive/registered validators unless there is an explicit key-rotation mechanism.

Fix implemented:

Registration now scans the bounded validator set and rejects duplicate `hybrid_classical_pk`, `hybrid_pq_pk`, or `vrf_pk` with `StateError::DuplicateValidatorKey`. The existing duplicate `validator_id` check remains in place.

### ST-03 — Staking trusts public `value_spark` as bond amount

Severity: MEDIUM  
Status: OPEN

Description: Phase 2 documented that `OutputV1.value_spark` is public metadata and is not individually proven to match the Pedersen commitment. Staking uses this field directly as the delegated or self-staked amount. The transaction-level aggregate balance equation prevents simple total-value inflation, but staking does not verify an individual opening for the bond output.

Code locations:

- `indra-core/src/types/transaction.rs:67` — `OutputV1.value_spark` comment warns it is not individually proven to match commitment
- `indra-state/src/delegation.rs:270` — delegated bond amount is `utxo_entry.output.value_spark`
- `indra-state/src/delegation.rs:383` — self-stake amount is `utxo_entry.output.value_spark`
- `indra-state/src/delegation.rs:692` and nearby tests — existing test constructs mismatched public and committed values

Attack scenario:

1. Attacker constructs a transaction with outputs whose public `value_spark` metadata and individual commitments do not correspond, while keeping the aggregate commitment equation valid.
2. Attacker uses one output as a staking bond.
3. Staking credits the bond based on public `value_spark`, not the commitment opening.
4. The protocol's economic layer now treats stake backing as public metadata rather than individually committed value.

Impact:

This is not a direct money-creation bug if transaction aggregate balance is enforced. It is still a staking-accounting design gap because stake weight and released bond outputs rely on an amount that is not individually bound to the output commitment.

Recommended fix:

Either make staking outputs explicitly public-value outputs and document that commitments are not authoritative for bonded stake, or require a per-output opening/ownership proof for any UTXO being bonded so `value_spark` and commitment are individually bound.

### ST-04 — Unbonding delay exists and is state-enforced

Severity: SAFE  
Status: VERIFIED

Description: Both delegated stake and validator self-stake enter an unbonding state for `UNBONDING_PERIOD_EPOCHS` before the UTXO is released. Release happens during epoch transition via `release_unbonded_bonds`, not merely through mempool policy.

Code locations:

- `indra-core/src/types/primitives.rs:27` — `UNBONDING_PERIOD_EPOCHS = 1008`
- `indra-state/src/delegation.rs:336` — delegation unbonding end epoch
- `indra-state/src/delegation.rs:446` — self-stake unbonding end epoch
- `indra-state/src/epoch.rs:720` — release only when `unbonding_end_epoch <= current_epoch`

Attack scenario checked:

Direct construction of an undelegate/self-unstake operation cannot bypass the delay because the release condition is enforced by state transition logic at epoch boundaries.

Recommended fix:

None for the delay itself. See ST-13 for slash interaction during unbonding.

### ST-05 — Partial self-unstake can leave an active validator below practical minimum stake

Severity: MEDIUM  
Status: OPEN

Description: `apply_self_unstake` immediately subtracts the bond amount from `validator.stake_spark` and marks the bond as unbonding, but it does not change validator status to `Unbonding` or `Registered`, and it does not enforce a post-unstake minimum self-stake. Active-set reselection occurs at epoch transition; until then, an active validator can remain active with reduced or zero self-stake.

Code locations:

- `indra-state/src/delegation.rs:413` — `apply_self_unstake`
- `indra-state/src/delegation.rs:449` — marks bond unbonding
- `indra-state/src/delegation.rs:452` — subtracts self-stake with `saturating_sub`
- `indra-state/src/validator.rs:490` — active set is reselected at epoch logic, not immediately in self-unstake

Attack scenario:

1. Validator self-stakes enough to enter the active set.
2. Validator self-unstakes most or all self-bond mid-epoch.
3. Validator remains `Active` until active-set reselection.
4. Consensus weight and reward calculations may see the updated lower stake, but active membership is temporarily inconsistent with any intended minimum stake rule.

Recommended fix:

Define and enforce a minimum active self-stake invariant. If self-unstake drops below it, immediately remove the validator from the active set or defer the unstake until epoch transition with the validator still slashable and stake weight stable through the epoch.

### ST-06 — Reward weights use self-stake while active-set selection includes delegated stake

Severity: MEDIUM  
Status: OPEN

Description: Active-set selection ranks validators by self-stake plus delegated stake, but reward distribution and consensus voter weights use only `validator.stake_spark`. This creates a mismatch: delegations can help a validator become active, but the validator's consensus weight and base reward share are calculated from self-stake only.

Code locations:

- `indra-state/src/validator.rs:490` — active-set ranking uses `stake_spark + delegations.total_delegated`
- `indra-state/src/validator.rs:412` — `total_active_stake` sums self-stake only
- `indra-state/src/epoch.rs:578` — block rewards use `total_active_stake`
- `indra-state/src/epoch.rs:637` — fee rewards use `total_active_stake`
- `indra-node/src/engine.rs:526` — registered voter stake is `validator.stake_spark`
- `indra-node/src/engine.rs:543` — QC validator stake is `validator.stake_spark`

Attack/economic scenario:

1. A validator attracts or self-directs large delegations and enters the active set.
2. Consensus quorum and rewards use only its self-stake, not delegated stake.
3. The active set composition is influenced by capital that does not provide corresponding consensus voting power.

Recommended fix:

Choose one staking model and apply it consistently. If delegated stake secures consensus, include it in consensus weights and reward weights. If delegated stake is only economic/reward metadata, do not use it for active-set selection.

### ST-07 — Commission is capped, but changes apply immediately for the next epoch distribution

Severity: LOW  
Status: OPEN

Description: Registration and commission update operations enforce commission within governance bounds. Defaults currently cap maximum commission at 20%, and governance can only decrease the maximum. However, `apply_set_commission` updates `validator.commission_bps` immediately; delegators do not appear to receive a delay window before the new commission affects the next epoch reward distribution.

Code locations:

- `indra-state/src/delegation.rs:191` — registration commission bounds
- `indra-state/src/delegation.rs:541` — `apply_set_commission`
- `indra-state/src/delegation.rs:566` — immediate commission update
- `indra-state/src/governance.rs:72` — default max commission from primitives
- `indra-core/src/types/primitives.rs:410` — `MAX_COMMISSION_BPS = 2000`

Attack/economic scenario:

1. Validator advertises low commission to attract delegators.
2. Validator raises commission up to the governance maximum just before an epoch distribution.
3. Delegators receive lower rewards without a notice/exit delay.

Recommended fix:

Apply commission changes with an activation delay of at least one unbonding/reward period, or store pending commission with an effective epoch.

### ST-08 — Reward arithmetic and precision are deterministic but not fully explicit

Severity: LOW  
Status: OPEN

Description: Reward calculations use deterministic proportional arithmetic and post-overflow-fix basis-point helpers. Some older code paths still use saturating operations when the hard-fork gate is inactive; all testnet gates are active from genesis. Delegator reward distribution can leave deterministic remainders. Fee reward remainders are returned to `fee_reward_pool`, while block reward remainders are ignored after being computed.

Code locations:

- `indra-state/src/epoch.rs:617` — block reward commission via `bps_of` when overflow fix active
- `indra-state/src/epoch.rs:671` — fee reward commission via `bps_of`
- `indra-state/src/epoch.rs:631` — block reward remainder ignored
- `indra-state/src/epoch.rs:682` — fee reward remainder tracked

Impact:

No direct overflow exploit was identified in the active configuration. The remaining issue is accounting clarity: small block-reward remainders are deterministically unallocated rather than explicitly burned, retained, or swept to treasury.

Recommended fix:

Document the monetary policy for reward dust and route all remainders explicitly.

### ST-09 — Epoch transition is not transactionally atomic on late failure

Severity: MEDIUM  
Status: OPEN

Description: `apply_block` applies transactions, staking ops, governance ops, slashes, fee updates, and height/tip updates before calling epoch transition at an epoch boundary. If a late epoch-transition step returns an error, the caller receives an error after prior state mutations have already occurred. There is shadow validation for staking/governance earlier in `apply_block`, but epoch transition itself is not wrapped in rollback semantics.

Code locations:

- `indra-state/src/apply.rs:422` — epoch transition called from `apply_block`
- `indra-state/src/epoch.rs:59` — `apply_epoch_transition`
- `indra-state/src/epoch.rs:720` — `release_unbonded_bonds` can return an error on UTXO collision/range-proof generation failure

Attack/failure scenario:

1. A block at an epoch boundary is applied.
2. Earlier block mutations succeed.
3. A late epoch-transition step returns an error.
4. Unless the caller applies the block to a cloned state and commits only on success, in-memory state can be left partially mutated.

Recommended fix:

Make `apply_block` atomic by applying to a scratch clone and replacing state only on success, or split epoch transition into a deterministic precheck phase and a mutation phase with no fallible operations.

### ST-10 — Slash amount and fund accounting are deterministic for active self-stake

Severity: SAFE  
Status: VERIFIED

Description: Precommit equivocation slashing verifies both vote signatures, rejects non-slashable prevote conflicts, computes slash amount as basis points of current self-stake, reduces validator self-stake, reduces active self-bond amounts, burns the non-reporter portion, credits treasury with the reporter reward, and marks the validator `Slashed`.

Code locations:

- `indra-state/src/apply.rs:108` — already slashed/exited validators rejected
- `indra-state/src/apply.rs:116` — vote signatures verified with validator keys and chain ID
- `indra-state/src/apply.rs:139` — same-hash votes are not equivocation
- `indra-state/src/apply.rs:155` — only precommit equivocation is slashable
- `indra-state/src/apply.rs:193` — slash amount calculation
- `indra-state/src/apply.rs:199` — validator stake and status updated
- `indra-state/src/apply.rs:208` — active self-bonds reduced
- `indra-state/src/apply.rs:224` — total supply and treasury updated

Recommended fix:

None for active self-stake accounting. See ST-13 for unbonding self-stake escape.

### ST-11 — Double-slash protection prevents repeated penalties

Severity: SAFE  
Status: VERIFIED

Description: Slash evidence is deduplicated by `compute_slash_evidence_hash`, and validators already in `Slashed` or `Exited` status are rejected. Even if equivalent evidence is re-encoded in a different order, the validator status guard prevents a second slash after the first successful application.

Code locations:

- `indra-state/src/apply.rs:85` — evidence hash membership check
- `indra-state/src/apply.rs:108` — rejects already slashed/exited validator
- `indra-state/src/apply.rs:239` — evidence hash computed from encoded evidence

Recommended fix:

None. A future improvement could canonicalize slash evidence hash by sorting the two votes, but current status-based protection prevents economic double-slash.

### ST-12 — Slash underflow is avoided

Severity: SAFE  
Status: VERIFIED

Description: Slash amount and stake reductions use saturating arithmetic. A slash cannot underflow validator stake, bond amount, total supply, or treasury accounting.

Code locations:

- `indra-state/src/apply.rs:197` — burned amount uses `saturating_sub`
- `indra-state/src/apply.rs:200` — validator stake uses `saturating_sub`
- `indra-state/src/apply.rs:219` — bond amount uses `saturating_sub`
- `indra-state/src/apply.rs:224` — total supply uses `saturating_sub`

Recommended fix:

None for underflow prevention. Continue constraining slash basis-point governance parameters to sane ranges.

### ST-13 — Self-unstaking before evidence can avoid or reduce slashing

Severity: HIGH  
Status: FIXED

Description: `apply_self_unstake` immediately subtracts the bond amount from `validator.stake_spark` and marks the bond as unbonding. Later, `apply_slash_at_height` computes slash amount from current `validator.stake_spark` and only reduces self-bonds whose `unbonding_end_epoch` is `None`. Therefore, a validator can self-unstake after equivocation but before evidence is applied, reducing the slash base and excluding the unbonding self-bond from bond reduction.

Code locations:

- `indra-state/src/delegation.rs:449` — self-bond marked unbonding
- `indra-state/src/delegation.rs:452` — validator stake immediately reduced
- `indra-state/src/apply.rs:188` — slash amount uses current `validator.stake_spark`
- `indra-state/src/apply.rs:208` — slash reduces only self-bonds with `unbonding_end_epoch.is_none()`
- `indra-state/src/epoch.rs:720` — unbonded bonds released after delay
- `indra-state/src/epoch.rs:743` — full original output returned if self-bond was not reduced

Attack scenario:

1. Validator equivocates with two conflicting precommit votes.
2. Before slash evidence is included, validator submits `SelfUnstake` for its self-bond.
3. State immediately lowers `validator.stake_spark` and marks the bond as unbonding.
4. Slash evidence is later applied.
5. Slash amount is computed from the reduced current stake, possibly zero.
6. The unbonding self-bond is skipped by the bond-reduction filter.
7. After the unbonding period, the validator can recover the original bonded output.

Proof-of-concept reasoning:

The exploit follows directly from the ordering of state transitions: self-unstake removes the stake from both the slash amount base and the active self-bond filter before evidence application. The unbonding delay does not preserve slashability for the old stake amount.

Recommended fix:

Keep unbonding self-stake slashable until `unbonding_end_epoch` plus any evidence window. Compute slashes against active plus unbonding self-bonds for infractions whose vote height occurred before the unbonding became withdrawable. Do not reduce `validator.stake_spark` immediately if it is the slash base; instead track active, unbonding, and slashable balances separately.

Fix implemented:

`SLASH_EVIDENCE_WINDOW_EPOCHS` now bounds valid equivocation evidence. While evidence is within that window, `apply_slash_at_height` computes the slash base from active self-bonds plus self-bonds that entered unbonding after the infraction epoch and are still locked. Bond reduction applies to both active and slashable-unbonding self-bonds. Active `validator.stake_spark` is reduced only by the active-bond portion so active stake remains consistent with active bonds. This avoids a persistent state-schema change while preserving slashability because the evidence window is shorter than `UNBONDING_PERIOD_EPOCHS`.

### ST-14 — Delegated stake affects active-set selection but not consensus voting power

Severity: MEDIUM  
Status: OPEN

Description: This is the consensus/economic consequence of ST-06. A validator can be selected into the active set based on total self-plus-delegated stake, but once active, its consensus voting power is only self-stake. This can reduce effective voting power below what active-set selection implies and can produce unintuitive quorum/reward results.

Code locations:

- `indra-state/src/validator.rs:490` — active-set selection includes delegated stake
- `indra-node/src/engine.rs:526` — registered voters use self-stake
- `indra-node/src/engine.rs:543` — QC validators use self-stake
- `indra-node/src/sync.rs:429` — QC verification uses `state.validators.total_active_stake`, self-stake only

Attack/economic scenario:

1. Attacker directs delegated stake to validators with minimal self-stake.
2. Those validators enter the active set.
3. Consensus total stake and quorum are calculated from small self-stake only.
4. The apparent economic backing of active-set membership is not reflected in actual consensus security.

Recommended fix:

Unify stake semantics. The active-set ranking, proposer election weight, QC voting power, rewards, and slashing base should all use the same explicitly-defined stake quantity.

### ST-15 — Reward manipulation via proposal timing is limited

Severity: LOW  
Status: OPEN

Description: Block rewards are distributed by epoch and active self-stake, not by proposer slot, so a proposer cannot mint extra block reward by proposing more or fewer transactions. A proposer can still censor, delay, or include/exclude transactions, which affects fee pool timing and normal MEV/censorship risk.

Code locations:

- `indra-state/src/epoch.rs:572` — block rewards distributed at epoch transition
- `indra-state/src/epoch.rs:637` — fee rewards distributed from fee pool
- `indra-state/src/apply.rs:398` — block fee pool updated during block application

Recommended fix:

Treat this as a policy/MEV issue rather than a direct accounting bug. If needed, add inclusion rules or fee-market anti-censorship mechanisms later.

### ST-16 — Total supply invariants are mostly preserved, but policy/test coverage should improve

Severity: LOW  
Status: OPEN

Description: Bonding/unbonding moves UTXOs into and out of `staked_bonds` without changing total supply. Block rewards appear preminted and do not increase total supply at epoch transition. Fee burn and slash burns reduce total supply; reporter rewards move to treasury. The code also applies liveness penalties at epoch transition, even though the current stated model says slashing is precommit-equivocation only.

Code locations:

- `indra-state/src/chain.rs` — genesis total supply constants and initial state
- `indra-state/src/delegation.rs:288` and `indra-state/src/delegation.rs:401` — bonding spends UTXO into bond table
- `indra-state/src/epoch.rs:720` — unbonding releases UTXO back to set
- `indra-state/src/apply.rs:224` — equivocation slash burn and treasury credit
- `indra-state/src/epoch.rs:790` — liveness penalties burn stake
- `indra-state/src/epoch.rs:114` — block reward distribution occurs at epoch transition

Impact:

No direct inflation path was identified in the staking layer. The open risk is specification drift: liveness penalties exist in code, total-supply effects are spread across multiple paths, and some invariant checks are debug assertions or tests rather than a central runtime accounting rule.

Recommended fix:

Write a single monetary-policy invariant test suite covering bond, unbond, slash, reward, fee burn, liveness penalty, and claim paths. Decide whether liveness penalties are intended; if not, gate or remove them in a future fix task.

## Proof-of-Concept Tests

The original Phase 4 audit was audit-only, so no tests were added then. The HIGH-finding fix added regression tests covering:

1. ST-01: registration without bond rejected, below-minimum bond rejected, valid bond succeeds and creates self-stake.
2. ST-02: duplicate VRF, classical, and PQ keys rejected; distinct key registrations still succeed.
3. ST-13: unbonding self-stake remains slashable within the evidence window; stale evidence is rejected; slash covers active plus slashable-unbonding bonds.

## Findings NOT Present

- Staking operations are hybrid-signed and include chain-id domain separation through `StakingOp::signing_bytes`.
- Delegation and self-stake verify UTXO ownership before bonding.
- Delegation and self-stake reject a UTXO already present in `staked_bonds`.
- Undelegation/self-unstake enforce a state-level unbonding delay before releasing UTXOs.
- Commission cannot exceed the governance maximum in the state transition path.
- Slash evidence requires valid hybrid signatures from the slashed validator and only precommit equivocation is slashable.
- Double-slash protection is enforced both by evidence-hash deduplication and by the validator `Slashed` status.
- Slash arithmetic avoids underflow.
- Block rewards do not increase `total_supply` during epoch transition; the model appears preminted.

## Recommended Fix Order

1. ST-06/ST-14 — Unify delegated stake semantics across active-set selection, consensus voting power, proposer weight, rewards, and slashing.
2. ST-09 — Make epoch-boundary block application atomic.
3. ST-03 — Resolve whether staking bonds are public-value-only or require commitment opening checks.
4. ST-05 — Enforce minimum active self-stake and deterministic active-status changes on self-unstake.
5. ST-07/ST-08/ST-15/ST-16 — Clarify commission delay, reward dust, MEV policy, liveness-penalty policy, and total-supply invariant tests.
