> **Historical archive:** This records completed audit work and intermediate designs. It is not current guidance; canonical specifications and current code take precedence.

# INDRA Security Audit — Phase 4: Staking and Economic Security

## Executive Summary

Phase 4 found three high-priority staking/economic issues and several medium/low hardening gaps. The three HIGH findings have now been fixed locally: validator registration requires an atomic minimum self-bond, validator key material is globally uniqueness-checked at registration, and unbonding self-stake remains slashable for valid evidence within the evidence window. The main MEDIUM findings have also been addressed locally: active-set selection now uses the same self-stake model as consensus/reward weight, self-unstake below the active minimum demotes the validator immediately, block application is atomic across epoch-transition failures, and staking bond operations now require a per-output commitment opening proof that binds the public bond amount to the stored Pedersen commitment. The audit also confirmed several safe properties: staking operations are hybrid-signed with chain-id domain separation, delegation/unstake operations enforce ownership and unbonding delays, commission is capped by governance limits, duplicate slash evidence is rejected, and total-supply accounting is mostly explicit for rewards, fees, and slashing.

Fix status note: ST-01 intentionally changes the `RegisterValidator` staking-op wire format and requires a fresh testnet wipe after deployment. ST-03 intentionally changes the staking-op wire format for `RegisterValidator`, `SelfStake`, and `Delegate` by adding an optional `StakingBondProof`; because activation is height 0 on testnet, deployment requires a fresh testnet wipe or coordinated hard-fork activation. ST-07 appends pending commission fields to `ValidatorEntry`, so it changes persisted validator-entry state layout and should also be deployed with a fresh state wipe. None of these changes require key regeneration or genesis validator-key changes. ST-02, ST-05, ST-06, ST-08, ST-09, ST-13, ST-14, ST-15, and ST-16 do not change cryptographic derivation, key material, block/QC wire formats, or genesis keys.

## Summary Table

| ID | Component | Finding | Severity | Status |
|----|-----------|---------|----------|--------|
| ST-01 | Registration | Validator registration is permissionless and does not require bond before consuming registry capacity | HIGH | FIXED |
| ST-02 | Registration | Duplicate VRF keys are not rejected at registration | HIGH | FIXED |
| ST-03 | Bonding | Staking bond ops require per-output commitment opening proof | MEDIUM | FIXED |
| ST-04 | Unbonding | Unbonding delay exists and is state-enforced | SAFE | VERIFIED |
| ST-05 | Unbonding | Self-unstake can leave an active validator below practical minimum stake until epoch reselection | MEDIUM | FIXED |
| ST-06 | Rewards | Reward weights use validator self-stake, while active-set selection includes delegated stake | MEDIUM | FIXED |
| ST-07 | Rewards | Commission changes are staged with an activation delay | LOW | FIXED |
| ST-08 | Rewards | Reward dust routing is explicit and covered by conservation tests | LOW | FIXED |
| ST-09 | Rewards | Epoch transition is not transactionally atomic if a late transition step errors | MEDIUM | FIXED |
| ST-10 | Slashing | Slash amount and fund accounting are deterministic for active self-stake | SAFE | VERIFIED |
| ST-11 | Slashing | Double-slash protection prevents repeated penalties | SAFE | VERIFIED |
| ST-12 | Slashing | Slash underflow is avoided with saturating arithmetic | SAFE | VERIFIED |
| ST-13 | Slashing | Self-unstaking before evidence can avoid or reduce slashing | HIGH | FIXED |
| ST-14 | Economic | Delegated stake affects active-set selection but not consensus voting power | MEDIUM | FIXED |
| ST-15 | Economic | Proposer MEV/censorship surface is documented and empty-block warnings added | LOW | FIXED |
| ST-16 | Economic | Total-supply invariants and liveness-penalty policy are explicitly tested/documented | LOW | FIXED |

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

### ST-03 — Staking bond UTXOs now prove public value matches commitment

Severity: MEDIUM  
Status: FIXED

Description: Phase 2 documented that `OutputV1.value_spark` is public metadata and was not individually proven to match the Pedersen commitment. Staking used this field directly as the delegated or self-staked amount. The transaction-level aggregate balance equation prevented simple total-value inflation, but staking did not verify an individual opening for the bond output.

Code locations:

- `indra-core/src/types/staking.rs` — `StakingBondProof` and optional proof fields on `RegisterValidator`, `SelfStake`, and `Delegate`
- `indra-core/src/types/primitives.rs` — `STAKING_COMMITMENT_PROOF_HEIGHT = 0`
- `indra-state/src/delegation.rs` — staking bond proof validation before UTXO spend
- `indra-cli/src/bin/stake.rs` and `indra-cli/src/tx_builder.rs` — CLI staking builders load the wallet blinding factor and construct the proof
- `indra-ffi/src/staking.rs` — FFI staking builders accept bond value and blinding factor inputs

Attack scenario:

1. Attacker constructs a transaction with outputs whose public `value_spark` metadata and individual commitments do not correspond, while keeping the aggregate commitment equation valid.
2. Attacker uses one output as a staking bond.
3. Staking credits the bond based on public `value_spark`, not the commitment opening.
4. The protocol's economic layer now treats stake backing as public metadata rather than individually committed value.

Impact:

This is not a direct money-creation bug if transaction aggregate balance is enforced. It is still a staking-accounting design gap because stake weight and released bond outputs rely on an amount that is not individually bound to the output commitment.

Fix implemented:

`RegisterValidator`, `SelfStake`, and `Delegate` now carry an optional `StakingBondProof { committed_value_spark, blinding_factor }`. At and above `STAKING_COMMITMENT_PROOF_HEIGHT` (height 0 on testnet), the proof is mandatory. If a proof is present below activation, it is still validated. State validation verifies that `Commit(committed_value_spark, blinding_factor)` opens the exact stored output commitment and that `committed_value_spark == output.value_spark` before the bond UTXO is spent. Missing proofs fail with `BondProofRequired`; invalid openings fail with `StakingBondCommitmentMismatch`; public/committed value mismatches fail with `StakingBondValueMismatch`.

The CLI staking path now loads the wallet entry for the bond UTXO and fails hard if the blinding factor is missing or zero. FFI staking builders now require the bond value and blinding factor so mobile/wallet callers can construct the same proof. This is a staking-op wire-format change and requires a fresh testnet wipe or coordinated hard-fork activation. It does not require key regeneration, cryptographic-derivation changes, or genesis validator-key changes.

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
Status: FIXED

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

Fix implemented:

`MINIMUM_ACTIVE_SELF_STAKE_SPARK` now defines the active self-stake floor. `apply_self_unstake` still allows registered validators to manage their own bonds, but if an active validator's self-stake falls below the floor, it is immediately demoted to `Registered`. Consensus voter/QC construction reads the active validator set from state, so the demotion is reflected after the block commits and the node refreshes registered voters.

### ST-06 — Reward weights use self-stake while active-set selection includes delegated stake

Severity: MEDIUM  
Status: FIXED

Description: Before the fix, active-set selection ranked validators by self-stake plus delegated stake, while reward distribution and consensus voter weights used only `validator.stake_spark`. This created a mismatch: delegations could help a validator become active without providing corresponding consensus weight.

Code locations:

- `indra-state/src/validator.rs:490` — active-set ranking now uses `stake_spark` only
- `indra-state/src/validator.rs:412` — `total_active_stake` sums self-stake only
- `indra-state/src/epoch.rs:578` — block rewards use `total_active_stake`
- `indra-state/src/epoch.rs:637` — fee rewards use `total_active_stake`
- `indra-node/src/engine.rs:526` — registered voter stake is `validator.stake_spark`
- `indra-node/src/engine.rs:543` — QC validator stake is `validator.stake_spark`

Attack/economic scenario:

1. Before the fix, a validator could attract or self-direct large delegations and enter the active set.
2. Consensus quorum and rewards would still use only its self-stake, not delegated stake.
3. After the fix, delegated stake cannot promote that validator into the active set, so active-set composition and consensus weight use the same stake quantity.

Recommended fix:

Choose one staking model and apply it consistently. If delegated stake secures consensus, include it in consensus weights and reward weights. If delegated stake is only economic/reward metadata, do not use it for active-set selection.

Fix implemented:

INDRA testnet now uses the explicit self-stake model. Active-set selection ranks by `validator.stake_spark` only, matching `total_active_stake`, QC/registered-voter weights, proposer/election stake, and reward weights. Delegated stake still affects how a validator's reward pool is split between validator commission and delegators, but it no longer increases validator selection or consensus weight.

### ST-07 — Commission is capped, but changes apply immediately for the next epoch distribution

Severity: LOW  
Status: FIXED

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

Fix implemented:

`ValidatorEntry` now stores `pending_commission_bps` and `pending_commission_effective_epoch`. `apply_set_commission` stages the requested rate and leaves `commission_bps` unchanged until `COMMISSION_CHANGE_DELAY_EPOCHS` has elapsed. `apply_epoch_transition` applies pending commission changes before reward distribution when the effective epoch is reached, then clears the pending fields. Regression tests cover immediate non-application, delayed activation, and delegator rewards using the pre-change commission during the delay window.

Serialization note: the pending commission fields are appended to the current encoded `ValidatorEntry` layout. This is a persisted state-schema change and should be deployed with a fresh state wipe. It does not require key regeneration or genesis validator-key changes.

### ST-08 — Reward arithmetic and precision are deterministic but not fully explicit

Severity: LOW  
Status: FIXED

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

Fix implemented:

Block-reward rounding/saturation/delegator-split dust is explicitly routed to `state.treasury_balance`. This keeps the preminted reward budget auditable without increasing `total_supply`. Fee reward dust remains carried forward in `state.fee_reward_pool`, preserving the existing policy for fees. Regression tests cover block-reward dust conservation and fee-reward dust carry-forward.

### ST-09 — Epoch transition is not transactionally atomic on late failure

Severity: MEDIUM  
Status: FIXED

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

Fix implemented:

`apply_block` now applies the full block, including epoch-transition work, to a scratch clone and commits the scratch state back only after all steps succeed. A regression test forces a late unbonded-bond release collision at an epoch boundary and verifies the original state is unchanged.

### ST-10 — Slash amount and fund accounting are deterministic for active self-stake

Severity: SAFE  
Status: VERIFIED

Description: Precommit equivocation slashing verifies both vote signatures, rejects non-slashable prevote conflicts, computes slash amount as basis points of slashable self-stake, reduces validator self-stake, reduces slashable self-bond amounts, pays a 50% reporter reward directly to the block proposer as a spendable UTXO when the proposer can be resolved and the reward is above dust, burns the remainder, and marks the validator `Slashed`. If no reporter/proposer is available or the reward is below dust, the full slash amount is burned.

Code locations:

- `indra-state/src/apply.rs:108` — already slashed/exited validators rejected
- `indra-state/src/apply.rs:116` — vote signatures verified with validator keys and chain ID
- `indra-state/src/apply.rs:139` — same-hash votes are not equivocation
- `indra-state/src/apply.rs:155` — only precommit equivocation is slashable
- `indra-state/src/apply.rs` — slash amount calculation and slashable self-bond reduction
- `indra-state/src/apply.rs` — deterministic slash reporter reward UTXO creation
- `indra-state/src/apply.rs` — total supply reduced only by the burned slash amount

Recommended fix:

None. Slash accounting now burns the non-reward portion and routes qualifying reporter rewards directly to the reporting block proposer; treasury is not used for slash reporter rewards.

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
Status: FIXED

Description: This was the consensus/economic consequence of ST-06. Before the fix, a validator could be selected into the active set based on total self-plus-delegated stake, while its consensus voting power remained self-stake only. The active-set path now uses self-stake only, matching consensus weight.

Code locations:

- `indra-state/src/validator.rs:490` — active-set selection uses self-stake only
- `indra-node/src/engine.rs:526` — registered voters use self-stake
- `indra-node/src/engine.rs:543` — QC validators use self-stake
- `indra-node/src/sync.rs:429` — QC verification uses `state.validators.total_active_stake`, self-stake only

Attack/economic scenario:

1. Before the fix, an attacker could direct delegated stake to validators with minimal self-stake.
2. Those validators could enter the active set.
3. Consensus total stake and quorum would still be calculated from small self-stake only.
4. After the fix, delegated stake no longer promotes a validator into the active set, so this mismatch is removed.

Recommended fix:

Unify stake semantics. The active-set ranking, proposer election weight, QC voting power, rewards, and slashing base should all use the same explicitly-defined stake quantity.

Fix implemented:

This is fixed together with ST-06 by choosing Model A: self-stake-only consensus/economic weight. Delegations remain reward-splitting metadata and no longer influence active-set selection.

### ST-15 — Reward manipulation via proposal timing is limited

Severity: LOW  
Status: FIXED

Description: Block rewards are distributed by epoch and active self-stake, not by proposer slot, so a proposer cannot mint extra block reward by proposing more or fewer transactions. A proposer can still censor, delay, or include/exclude transactions, which affects fee pool timing and normal MEV/censorship risk.

Code locations:

- `indra-state/src/epoch.rs:572` — block rewards distributed at epoch transition
- `indra-state/src/epoch.rs:637` — fee rewards distributed from fee pool
- `indra-state/src/apply.rs:398` — block fee pool updated during block application

Recommended fix:

Treat this as a policy/MEV issue rather than a direct accounting bug. If needed, add inclusion rules or fee-market anti-censorship mechanisms later.

Fix implemented:

`producer.rs` now documents the current transaction-selection policy: mempool selection is fee-rate ordered, proposers can censor or delay transactions, block rewards are epoch/stake based rather than per-proposal, and future mainnet MEV mitigations may require ordering commitments or PBS-style design. The producer also logs a warning if it emits an empty block while fee-eligible transactions are present, making possible censorship or selection bugs visible operationally. A regression test confirms transaction count does not change the base proposer reward share.

### ST-16 — Total supply invariants are mostly preserved, but policy/test coverage should improve

Severity: LOW  
Status: FIXED

Description: Bonding/unbonding moves UTXOs into and out of `staked_bonds` without changing total supply. Block rewards appear preminted and do not increase total supply at epoch transition. Fee burn and slash burns reduce total supply; slash reporter rewards are paid directly to the reporting block proposer as spendable UTXOs when above dust, while the remaining slash amount is burned. The code also applies liveness penalties at epoch transition, even though the current stated model says slashing is precommit-equivocation only.

Code locations:

- `indra-state/src/chain.rs` — genesis total supply constants and initial state
- `indra-state/src/delegation.rs:288` and `indra-state/src/delegation.rs:401` — bonding spends UTXO into bond table
- `indra-state/src/epoch.rs:720` — unbonding releases UTXO back to set
- `indra-state/src/apply.rs` — equivocation slash burn plus direct reporter reward UTXO
- `indra-state/src/epoch.rs:790` — liveness penalties burn stake
- `indra-state/src/epoch.rs:114` — block reward distribution occurs at epoch transition

Impact:

No direct inflation path was identified in the staking layer. The open risk is specification drift: liveness penalties exist in code, total-supply effects are spread across multiple paths, and some invariant checks are debug assertions or tests rather than a central runtime accounting rule.

Recommended fix:

Write a single monetary-policy invariant test suite covering bond, unbond, slash, reward, fee burn, liveness penalty, and claim paths. Decide whether liveness penalties are intended; if not, gate or remove them in a future fix task.

Fix implemented:

Liveness penalties are documented as intentional protocol penalties separate from the CS-08 equivocation-slashing model. They trigger when a validator remains inactive beyond the configured epoch threshold and burn the configured penalty amount from stake/supply. `indra-state/tests/monetary_invariants.rs` now covers bond/unbond, slash burn accounting, preminted epoch rewards, fee burn, liveness penalty burn, and a full block-plus-epoch cycle. `epoch.rs` also has a policy regression test that pins the current liveness penalty constants so future changes must update the test and documentation.

## Proof-of-Concept Tests

The original Phase 4 audit was audit-only, so no tests were added then. The HIGH-finding fix added regression tests covering:

1. ST-01: registration without bond rejected, below-minimum bond rejected, valid bond succeeds and creates self-stake.
2. ST-02: duplicate VRF, classical, and PQ keys rejected; distinct key registrations still succeed.
3. ST-13: unbonding self-stake remains slashable within the evidence window; stale evidence is rejected; slash covers active plus slashable-unbonding bonds.
4. ST-03: staking bond proof tests prove correct openings are accepted, missing proofs are rejected at activation, wrong blindings are rejected, public/committed value mismatches are rejected, and failed proof validation does not spend the UTXO or advance the staking nonce.
5. ST-05: active validator self-unstake below the active minimum demotes to `Registered`, while above-minimum and already-registered cases remain valid.
6. ST-06/ST-14: active-set selection and reward distribution tests prove delegated stake does not increase consensus/reward weight.
7. ST-09: epoch-boundary block application is tested for both successful commit and rollback on late epoch-transition failure.
8. ST-07: commission changes are staged, activate only after the delay, and rewards during the delay use the old rate.
9. ST-08: block-reward dust is routed to treasury and fee-reward dust remains in the fee reward pool.
10. ST-15: proposer base rewards are independent of transaction count.
11. ST-16: consolidated monetary invariant tests cover bond/unbond, slash, rewards, fee burn, liveness penalty burn, and block-plus-epoch cycles.

## Findings NOT Present

- Staking operations are hybrid-signed and include chain-id domain separation through `StakingOp::signing_bytes`.
- Delegation and self-stake verify UTXO ownership before bonding.
- Delegation and self-stake reject a UTXO already present in `staked_bonds`.
- Undelegation/self-unstake enforce a state-level unbonding delay before releasing UTXOs.
- Commission cannot exceed the governance maximum in the state transition path.
- Commission changes do not apply immediately; they are staged until the configured activation epoch.
- Slash evidence requires valid hybrid signatures from the slashed validator and only precommit equivocation is slashable.
- Liveness penalties are a separate intentional inactivity penalty, not equivocation slash evidence.
- Double-slash protection is enforced both by evidence-hash deduplication and by the validator `Slashed` status.
- Slash arithmetic avoids underflow.
- Block rewards do not increase `total_supply` during epoch transition; the model is preminted and block-reward dust is routed to treasury.

## Recommended Fix Order

1. Mainnet MEV policy — The ST-15 documentation/logging fix makes the current surface explicit, but inclusion rules, ordering commitments, or PBS remain future design work if the fee market becomes material.
