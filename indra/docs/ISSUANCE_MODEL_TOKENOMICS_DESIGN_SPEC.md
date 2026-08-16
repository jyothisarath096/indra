# INDRA Issuance-Model Tokenomics Design Specification

**Status:** design specification for adversarial review; no implementation is authorized by this document.

**Addresses:** Topic 11 findings T11-01 (missing reward reserve/global reconciliation), T11-02 (liveness burn without principal reduction), T11-03 (saturating fee accounting), T11-04 (schedule releases only 625,043,515.7952 INDRA), T11-05 (fragmented burn accounting), T11-06 (saturating monetary aggregates), and T11-08 (dead tokenomics state).

**Compatibility:** deliberately breaking. This replaces the pre-minted-reserve model, changes genesis and snapshot state, changes state roots and genesis identity, recalibrates every reward amount, and deletes fields and constants. There is no legacy decoder, migration, dual accounting path, or fallback. Testnet state is disposable; this change joins the batched wipe-and-redeploy queue.

## 1. Executive decision

INDRA adopts an **issuance model**:

1. Genesis issues only the value it actually creates.
2. Scheduled block rewards are minted when a finalized block earns them.
3. The permanent lifetime cap is exactly:

   ```text
   LIFETIME_SUPPLY_CAP_SPARK = 1_000_000_000 * 100_000_000
                             = 100_000_000_000_000_000 Spark
   ```

4. No transition, including genesis, can make `total_supply` exceed that cap.
5. `total_supply` always equals the checked sum of every spendable, bonded, unbonding, pending, or escrowed claim in consensus state.
6. There is no treasury, reward reserve, burn buffer, or other protocol fund.
7. Every mint and burn updates one canonical monetary ledger and the corresponding real value-bearing state atomically.

The post-genesis reward budget is not a second one-billion-INDRA allocation. It is fixed once at genesis:

```text
genesis_issued_spark = checked_sum(all genesis value claims)
reward_budget_spark  = LIFETIME_SUPPLY_CAP_SPARK - genesis_issued_spark
```

The fixed era durations and halving shape are applied to `reward_budget_spark` through the exact cumulative-target construction in Section 5. This resolves two otherwise-fatal arithmetic contradictions:

- genesis allocations consume part of the lifetime cap; and
- an arbitrary remaining Spark budget cannot generally be represented by one constant integer starting reward multiplied across fixed era lengths.

No governance action can change the cap, genesis issuance, reward budget, era boundaries, cumulative-target formula, or monetary ledger. A future change requires an explicit protocol replacement and redeploy/hard fork.

## 2. Problems in the current model

### 2.1 T11-01 — a claimed reserve that does not exist

The current state sets `total_supply` to one billion INDRA at genesis, creates validator stake positions and liquid validator UTXOs, and later credits block rewards, but has no state-committed reward-reserve balance to debit. Its hard-cap check observes only the unchanged scalar. It therefore cannot prove that real claims equal supply or remain within the cap.

The replacement treats `total_supply` as a derived-and-checked accounting fact, not a proxy for an unrepresented reserve.

### 2.2 T11-02 — liveness burns nominal supply but not principal

The current liveness path reduces `ValidatorEntry.stake_spark` and `total_supply` but does not reduce the authoritative active stake position or eligible unbonding tranches. The owner can therefore retain a claim to value that the ledger says was burned.

The replacement routes every slash through one exact principal-allocation transition.

### 2.3 T11-03/T11-05/T11-06 — fragmented and saturating accounting

Fee burns, governance burns, explicit slash burns, reporter-reward dust, and liveness penalties evolved through different counters and arithmetic. Some paths use checked arithmetic; others silently saturate. Epoch reports cannot independently reconstruct the lifetime supply equation from one source of truth.

The replacement permits no saturating arithmetic at a value, issuance, burn, allocation, or monetary-reporting boundary.

### 2.4 T11-04 — the documented schedule and implemented total disagree

The existing integer per-block constants distribute exactly 625,043,515.7952 INDRA before right shifts reach zero, not one billion INDRA. The replacement preserves the intended fixed-duration halving *shape*, but normalizes it to the actual post-genesis budget and allocates every Spark exactly.

## 3. Genesis under issuance

### 3.1 Value created at genesis

Genesis may create only these monetary claims:

- each genesis validator's configured active self-stake principal; and
- each genesis validator's fixed liquid bootstrap UTXO.

There is no implicit reserve or unowned balance. Genesis governance escrow, pending rewards, unbonding tranches, and fee pool must all be empty.

For validators in canonical ascending `validator_id` order:

```text
genesis_active_principal = checked_sum_u128(validator.stake_spark)
genesis_liquid_utxos     = checked_sum_u128(genesis output.value_spark)
genesis_issued_u128      = genesis_active_principal + genesis_liquid_utxos
```

Every addition is checked in `u128`. The final result must fit `u64` and must satisfy:

```text
genesis_issued_spark <= LIFETIME_SUPPLY_CAP_SPARK
```

Failure rejects genesis construction before a manifest, state root, or genesis hash is accepted. There is no clamping, partial validator insertion, or “remaining reserve went negative” interpretation.

After all genesis structures are built, the generic reconciliation algorithm in Section 4 independently recomputes their value. Genesis is valid only if:

```text
reconciled_value_spark == genesis_issued_spark == total_supply
```

### 3.2 Immutable genesis monetary parameters

Canonical genesis state stores:

```rust
MonetaryLedgerV1 {
    lifetime_cap_spark: u64,              // exactly 100_000_000_000_000_000
    genesis_issued_spark: u64,
    reward_budget_spark: u64,             // cap - genesis_issued
    cumulative_reward_minted_spark: u64,  // zero at genesis
    cumulative_fee_burned_spark: u64,
    cumulative_slash_burned_spark: u64,
    cumulative_governance_burned_spark: u64,
    epoch_reward_minted_spark: u64,
    epoch_fee_burned_spark: u64,
    epoch_slash_burned_spark: u64,
    epoch_governance_burned_spark: u64,
}
```

All burn counters are zero at genesis. Reporter-reward dust and liveness burns are slash burns; they do not receive parallel counter categories. The fixed fields avoid an attacker-expandable event log. Per-block monetary effects remain available in bounded block/application receipts, but the ledger is the canonical cumulative source of truth.

The following identities must hold after decoding genesis:

```text
reward_budget_spark = lifetime_cap_spark - genesis_issued_spark
total_supply        = genesis_issued_spark
cumulative_reward_minted_spark = 0
cumulative_burned_spark = 0
```

`lifetime_cap_spark`, `genesis_issued_spark`, and `reward_budget_spark` never change after genesis.

## 4. Global monetary reconciliation

### 4.1 Exact invariant

At every committed height:

```text
UTXO values
+ active stake principal
+ unbonding tranche principal
+ pending staking rewards
+ governance deposit escrow
+ fee reward pool
= total_supply
```

There is deliberately no term for:

- validator cache fields such as `ValidatorEntry.stake_spark` (derived mirrors, not additional claims);
- treasury;
- reward reserve;
- burn buffer;
- already burned value; or
- cumulative mint/burn audit counters.

The audit identity is independently:

```text
cumulative_burned_spark =
    cumulative_fee_burned_spark
  + cumulative_slash_burned_spark
  + cumulative_governance_burned_spark

total_supply =
    genesis_issued_spark
  + cumulative_reward_minted_spark
  - cumulative_burned_spark

cumulative_reward_minted_spark <= reward_budget_spark
total_supply <= lifetime_cap_spark
```

Every operation is checked with `u128` intermediate sums followed by a checked `u64` conversion. No `saturating_*`, wrapping operation, float, platform-width integer, or unchecked cast is permitted.

### 4.2 Structural enforcement without a full scan per block

Scanning up to the protocol cap of live UTXOs and staking records after every block would create an avoidable consensus-cost hazard. Instead, each authoritative value-bearing collection maintains a state-root-committed checked aggregate:

```rust
MonetaryAggregatesV1 {
    utxo_value_spark: u64,
    active_principal_spark: u64,
    unbonding_principal_spark: u64,
    pending_rewards_spark: u64,
    governance_escrow_spark: u64,
    fee_reward_pool_spark: u64,
}
```

Consensus mutation APIs are the only way to insert, remove, or change monetary records. Each API computes the old and new contribution and atomically updates the relevant aggregate using checked arithmetic. Direct mutable access to monetary maps or scalar balances is forbidden outside these APIs.

At the end of every block application, before commit:

1. checked-sum the six aggregate fields;
2. require equality with `total_supply`;
3. recompute the mint/burn audit identity above;
4. require the cap and reward-budget bounds;
5. commit the aggregates, ledger, and state root atomically.

At snapshot decode/import, aggregates are **not trusted**. The decoder exact-decodes all monetary collections, recomputes every aggregate from the records using checked arithmetic, rejects any mismatch with the encoded aggregates, then checks both global identities. Trailing bytes are rejected. Startup replay performs the same block-boundary check after every replayed state transition.

This follows the production Cosmos SDK bank-module principle that total supply is updated on mint/burn and is checked against the sum of real balances, while adapting the invariant to INDRA's UTXO, staking, tranche, and escrow stores rather than Cosmos accounts [Cosmos SDK bank module](https://docs.cosmos.network/sdk/v0.50/build/modules/bank/README).

### 4.3 Atomic transition rule

Every value transition produces a checked `MonetaryDeltaV1` internally:

```rust
MonetaryDeltaV1 {
    claims_created_spark: u64,
    claims_destroyed_spark: u64,
    minted_spark: u64,
    burned_spark: u64,
    burn_source: Option<BurnSourceV1>,
}
```

It is an internal verified capability, not a caller-supplied wire type. Commit requires:

```text
claims_created - claims_destroyed = minted - burned
```

expressed without signed underflow by comparing checked sums:

```text
claims_created + burned == claims_destroyed + minted
```

The state transaction rolls back all collection, aggregate, ledger, and supply mutations on any error.

## 5. Exact cumulative-target emission schedule

### 5.1 Fixed shape

The protocol retains these immutable era durations:

```text
D = 21_024_000 blocks
Era 1 duration = D
Era 2 duration = D
Era 3+ duration = 2D = 42_048_000 blocks per era
```

The intended per-block rate halves at each era boundary. Because Era 3+ lasts twice as long, the normalized ideal lifetime **era-total** weights are:

```text
Era 1:  1
Era 2:  1/2
Era 3:  1/2
Era 4:  1/4
Era 5:  1/8
...
```

Their exact infinite sum is:

```text
1 + 1/2 + (1/2 + 1/4 + 1/8 + ...)
= 1 + 1/2 + 1
= 5/2
```

Therefore the normalized lifetime fractions are:

```text
Era 1:  2/5
Era 2:  1/5
Era 3:  1/5
Era 4:  1/10
Era 5:  1/20
...
```

The conceptual starting per-block rate is the exact rational:

```text
starting_rate = (2 * reward_budget_spark) / (5 * D) Spark per block
```

It is not rounded into a single integer constant. Doing that would make exact convergence impossible for most genesis allocations.

### 5.2 Canonical cumulative era target

Let `B = reward_budget_spark`. Define the exact cumulative fraction after era `n`:

```text
F(0) = 0
F(1) = 2/5
F(2) = 3/5

For n >= 3:
F(n) = 1 - 1 / (5 * 2^(n-3))
```

Define canonical rounding to nearest Spark, ties upward:

```text
round_half_up(N / Q) = floor((2N + Q) / (2Q))
```

`N`, `Q`, `2N + Q`, and `2Q` are evaluated with a fixed-width checked integer type wide enough for the proof bounds; `u256` is sufficient for the one-billion-INDRA cap and the maximum nonzero era. No arbitrary-precision allocation driven by wire input is needed.

The cumulative minted target after era `n` is:

```text
T(n) = round_half_up(B * F(n))
```

and the exact budget for era `n` is:

```text
A(n) = T(n) - T(n-1)
```

Both subtraction and monotonicity are checked. An implementation must reject—not clamp—if `T(n) < T(n-1)` or `T(n) > B`.

### 5.3 Exact per-block target

For block offset `j` within era `n`, where `1 <= j <= duration(n)`, define:

```text
C(n,j) = T(n-1) + floor(j * A(n) / duration(n))
```

For the first block of the era, the minted reward is the difference from the preceding cumulative target. Generally, for global rewarded height `h`:

```text
block_reward(h) = cumulative_target(h) - cumulative_target(h-1)
```

Within one era, rewards are either:

```text
floor(A(n)/duration(n))
or
ceil(A(n)/duration(n))
```

and thus differ by at most one Spark. At `j = duration(n)`, `C(n,j) = T(n)` exactly, so every era distributes exactly `A(n)` with no residue.

### 5.4 Exact-convergence proof

For `n >= 3`, the ideal unissued tail after era `n` is:

```text
B * (1 - F(n)) = B / (5 * 2^(n-3))
```

Under round-half-up, `T(n) = B` whenever this tail is at most one-half Spark:

```text
B / (5 * 2^(n-3)) <= 1/2

equivalently:

2B <= 5 * 2^(n-3)
```

Because `B` is finite and `B <= 100_000_000_000_000_000`, a finite smallest era `N` satisfying this inequality always exists. For the maximum possible budget, `N <= 59`. At that era:

```text
T(N) = B
```

Thereafter `T(n) = B`, `A(n) = 0`, and every block reward is zero.

The lifetime sum telescopes:

```text
sum(n=1..N, A(n))
= sum(n=1..N, T(n)-T(n-1))
= T(N)-T(0)
= B
```

Within each era, the per-block differences also telescope:

```text
sum(j=1..duration(n), C(n,j)-C(n,j-1)) = A(n)
```

Therefore lifetime reward minting is exactly `reward_budget_spark`; genesis issuance plus rewards is exactly the lifetime cap before burns; there is no final-block special case, sweep, treasury, or unreachable remainder.

### 5.5 Runtime enforcement and persisted progress

The monetary ledger persists `cumulative_reward_minted_spark`. For a block at height `h`, consensus independently computes the schedule target `C(h)` and requires:

```text
expected_mint = C(h) - cumulative_reward_minted_spark
cumulative_reward_minted_spark == C(h-1) before application
```

The block transition checked-adds `expected_mint` to both real reward claims and `total_supply`, and to the cumulative/epoch mint counters. It rejects if:

- the previous cumulative value does not equal `C(h-1)`;
- subtraction or addition fails;
- cumulative mint would exceed `reward_budget_spark`;
- total supply would exceed the lifetime cap; or
- reward allocation cannot identify a valid recipient set.

Empty or failed consensus rounds do not mint and do not advance the height-indexed cumulative target. If no valid reward snapshot exists, the block fails closed rather than minting into a protocol pool.

## 6. Exact reward allocation with no treasury

### 6.1 Canonical largest-remainder allocation

For pool `P`, recipients with nonzero weights `w_i`, and `W = checked_sum(w_i)`, compute for each recipient:

```text
product_i       = u128(P) * u128(w_i)
base_i          = floor(product_i / W)
remainder_i     = product_i mod W
leftover        = P - checked_sum(base_i)
```

Sort recipients by:

1. descending `remainder_i`; then
2. ascending canonical recipient identity bytes; then
3. ascending canonical position ID where one identity has multiple destinations.

Add one Spark to the first `leftover` recipients. Require `leftover < recipient_count`; otherwise fail with an invariant error. The resulting allocations are deterministic, differ from exact proportional quotas by less than one Spark, and sum exactly to `P`.

This is Hamilton's largest-remainder apportionment shape: allocate integer floors, then award remaining indivisible units in descending fractional-remainder order [U.S. Census Bureau, methods of apportionment](https://www.census.gov/about/history/historical-censuses-and-surveys/census-programs-surveys/decennial-census/methods.html). INDRA adds canonical cryptographic identity tie-breaking, which political apportionment does not need.

### 6.2 Allocation hierarchy

Allocation uses the immutable consensus/economic reward snapshot governing the rewarded height:

1. Allocate the complete block reward across eligible validators by frozen consensus weight using largest remainder.
2. For a validator with no active delegations, credit its complete allocation to its validator-custody reward position.
3. For a validator with delegations:
   - calculate commission with checked `u128` basis-point arithmetic and canonical floor;
   - set `delegator_pool = validator_pool - commission` using checked subtraction;
   - credit commission to validator custody;
   - allocate the entire delegator pool across delegator identities by active principal using largest remainder;
   - allocate each identity's amount across its eligible destination positions using largest remainder where more than one destination exists.
4. Checked-sum all final credits and require exact equality with the minted pool before commit.

Commission flooring does not create residue because the delegator pool is defined as the exact complement. Every subsequent proportional split uses largest remainder. Zero-weight recipients are excluded; duplicate recipient identities/positions are rejected before allocation.

The same allocator is used for fee-pool distribution. Fee rewards move existing value from `fee_reward_pool` to pending rewards and therefore do not mint or change `total_supply`.

### 6.3 Why not retain a remainder bucket

A treasury/remainder bucket would weaken the invariant by creating an additional balance with exceptional ownership and future political pressure for a spend path. Largest remainder deterministically assigns every indivisible Spark to the intended recipient class and proves exact conservation locally. No monetary residue remains to warehouse.

## 7. Unified mint and burn transitions

### 7.1 The only mint authority

Only the height-derived reward transition may construct a verified mint delta. There is no public transaction, staking operation, governance action, FFI call, RPC method, admin method, or recovery method that accepts a caller-supplied mint amount.

The mint amount is recomputed from immutable genesis monetary parameters and height. Governance continues to have no monetary actions; this redesign does not add any.

### 7.2 Burn sources

The closed `BurnSourceV1` enum is internal consensus state:

```rust
enum BurnSourceV1 {
    TransactionFee = 1,
    ValidatorSlash = 2,
    GovernanceDeposit = 3,
}
```

`ValidatorSlash` includes:

- double-precommit principal burn;
- liveness-penalty principal burn; and
- reporter-reward amounts below the payout dust threshold, because those remain part of the actual slash burn.

For a qualifying reporter reward, the reward is a transfer from slashed principal to a new reporter UTXO, not a mint and not a burn. Therefore:

```text
slash_principal_reduction = reporter_reward_created + slash_burn
```

Governance cancellation/sub-support burns reduce escrow and supply by the same amount. Fee processing moves the validator share to `fee_reward_pool` and destroys only the burn share. Each path updates the corresponding cumulative and epoch counter in `MonetaryLedgerV1`.

### 7.3 Epoch and audit reporting

`EpochRecordVNext` carries:

```rust
reward_minted_spark: u64,
fee_burned_spark: u64,
slash_burned_spark: u64,
governance_burned_spark: u64,
total_burned_spark: u64,
opening_total_supply_spark: u64,
closing_total_supply_spark: u64,
```

It may separately report gross slashed principal and reporter rewards, but neither may be labeled “burned.” Epoch closure requires:

```text
total_burned = fee_burned + slash_burned + governance_burned
closing_supply = opening_supply + reward_minted - total_burned
```

and requires the epoch deltas to equal the differences between the canonical cumulative ledger counters. After the record is committed, epoch counters reset to zero using ordinary assignment; cumulative counters never reset or decrease.

## 8. Unified liveness and evidence slashing

### 8.1 One principal-reduction engine

Liveness and double-precommit penalties call the same internal checked slash allocator. Inputs are:

```rust
VerifiedSlashDirectiveV1 {
    validator_id: Bytes32,
    offense: SlashOffenseV1,
    slash_bps: u32,
    infraction_height_or_epoch: u64,
    reporter: Option<HybridPubKey>,
}
```

The capability can only be produced by independently verified equivocation evidence or the deterministic finalized liveness transition. It is not a wire type and cannot be fabricated by a caller.

The engine:

1. enumerates all slash-eligible self-custody active positions and unbonding tranches under the already-frozen infraction rules;
2. checked-sums their principal;
3. computes one aggregate slash amount using checked `u128` basis-point arithmetic;
4. distributes that amount across records using the existing canonical largest-remainder allocation;
5. reduces every real principal record by its exact allocation;
6. rebuilds/validates the validator cache from authoritative positions;
7. creates any qualifying reporter UTXO;
8. checked-burns the exact remainder through `BurnSourceV1::ValidatorSlash`; and
9. requires real principal reduction to equal reporter transfer plus burn.

No path may slash only `ValidatorEntry.stake_spark`, only `total_supply`, or an audit counter. Eligible unbonding principal remains slashable according to the existing evidence-window rules; delegated principal remains outside the approved self-custody-only slash burden.

### 8.2 Liveness infraction height

Persistent liveness failure has no signed vote height, so its infraction height
is derived canonically from the validator's last certified active epoch rather
than from the later detection boundary:

```text
first_missed_epoch = checked_add(last_active_epoch, 1)
infraction_height  = checked_add(
    checked_mul(first_missed_epoch, EPOCH_DURATION_BLOCKS),
    1,
)
```

Epoch zero covers produced heights `1..=EPOCH_DURATION_BLOCKS`; therefore the
formula identifies the first block of the first missed epoch. Arithmetic
failure rejects and rolls back the epoch transition.

The liveness directive targets:

- every active self-custody position belonging to the validator; and
- every still-locked self-custody unbonding tranche whose
  `start_height >= infraction_height`.

This is the structural analog of equivocation's
`tranche.start_height >= conflicting_vote.height` rule. It prevents a
validator from beginning unbonding after becoming inactive and escaping the
penalty while excluding tranches whose unbonding began before the liveness
offense. The detection epoch is not substituted for the infraction height.

### 8.3 Atomicity

Principal reductions, reporter output creation, aggregate updates, validator-cache updates, supply subtraction, and ledger increments occur in one state transaction. Any collision, missing record, arithmetic error, or reconciliation failure rolls back the entire slash.

## 9. Removed state and constants

The redesign deletes, without compatibility aliases:

- `ChainState.treasury_balance`;
- `ChainState.burn_buffer`;
- their state-root fields, snapshot fields, RPC fields, metrics, rollback fields, and tests;
- `MAX_RANGE_PROOF_BYTES`, the Topic 3 Bulletproof leftover;
- the existing fixed `ERA_1_BLOCK_REWARD_SPARK`, `ERA_2_BLOCK_REWARD_SPARK`, `ERA_3_BLOCK_REWARD_SPARK`, `ERA_4_BLOCK_REWARD_SPARK`, and `ERA_5_BLOCK_REWARD_SPARK` constants;
- the misleading `VALIDATOR_REWARDS_POOL_SPARK` name.

The one-billion-INDRA constant becomes:

```rust
pub const LIFETIME_SUPPLY_CAP_SPARK: u64 =
    1_000_000_000 * SPARK_PER_INDRA;
```

It is the single load-bearing cap used by genesis validation, schedule bounds, mint authorization, block reconciliation, and snapshot decoding. There is no separate `GENESIS_SUPPLY_SPARK`, `HARD_CAP_SPARK`, or reward-pool constant expressing the same number under conflicting semantics.

The fixed duration constants remain but are renamed only if necessary to express their issuance-model meaning. The schedule is derived from `reward_budget_spark`; no fixed integer starting-reward constant remains.

## 10. Wire, state, API, and identity changes

### 10.1 Consensus state

`ChainStateVNext`:

- removes `treasury_balance` and `burn_buffer`;
- replaces fragmented mint/burn epoch fields with `MonetaryLedgerV1`;
- adds `MonetaryAggregatesV1`;
- retains `total_supply`, now structurally reconciled;
- retains `fee_reward_pool` as a real value-bearing balance mirrored by its aggregate;
- stores immutable genesis issuance and reward budget inside the ledger.

Every monetary collection mutation API changes to maintain aggregates and return checked errors.

### 10.2 Genesis format and identity

The genesis manifest does not accept `total_supply`, cap, reward budget, starting reward, or cumulative counters from an operator. Consensus derives them from the fixed protocol cap and checked allocations.

Genesis canonical state bytes, state root, manifest commitment, and genesis hash change. A canonical genesis audit report must list:

- each validator stake allocation;
- each liquid genesis UTXO allocation;
- checked genesis issuance;
- derived reward budget; and
- the lifetime cap.

### 10.3 Blocks and epoch records

Transactions need no new mint field. Reward minting remains an implicit deterministic block/epoch transition derived from height, but block application effects and `EpochRecordVNext` expose exact minted/burned amounts for audit.

Epoch-record encoding changes as specified in Section 7.3. Snapshot encoding changes for the new ledger and aggregates and for deleted fields.

### 10.4 RPC, metrics, FFI, and tooling

Remove treasury/burn-buffer fields everywhere. Add read-only monetary fields:

```text
lifetime_cap_spark
genesis_issued_spark
reward_budget_spark
cumulative_reward_minted_spark
cumulative_*_burned_spark
reconciled_claims_spark
```

RPC values are projections of committed state, not alternate accounting. If any `#[repr(C)]` FFI structure changes, source and XCFramework headers require the existing compile-and-run C layout probe for size, alignment, and field offsets.

### 10.5 Breaking-change record

This changes at least:

- chain-state and snapshot encoding;
- state-root metadata and roots;
- genesis state root and genesis hash;
- epoch-record encoding;
- reward amounts at every rewarded height;
- monetary RPC/metrics schema;
- persisted rollback/undo state;
- replay results and all post-genesis block state roots; and
- any FFI state projection containing removed or added monetary fields.

No old snapshot, block-derived state root, or genesis identity remains valid. No migration or dual decoder is permitted.

## 11. Alternatives considered

### 11.1 Pre-minted reserve

An explicit state-committed reserve could make the old policy coherent: genesis would issue one billion and reward distribution would transfer from the reserve. It was rejected because the approved model is issuance, it adds a large exceptional balance, and it complicates the meaning of circulating versus total supply. Checked minting against an immutable remaining budget is simpler and matches actual value creation.

### 11.2 Minimal emergency treasury

Rejected. A treasury creates a privileged protocol fund, requires an authority/spend policy, enlarges governance attack surface, and invites future “temporary” uses. Emergency protocol upgrades should change code through the explicit upgrade/redeploy process, not rely on a pre-funded consensus account. Exact allocation removes the only mechanical reason for a remainder bucket.

### 11.3 Burn reward rounding residue

Rejected. Burning allocation dust makes aggregate issuance depend on recipient count/weights and causes actual lifetime issuance to fall below the approved schedule. It also turns harmless integer apportionment into monetary-policy variation.

### 11.4 Carry residue forward

Rejected. A carry is another protocol balance under a different name and delays rewards based on historical rounding. Largest remainder resolves each pool locally, exactly, and deterministically.

### 11.5 Fixed integer starting reward plus terminal sweep

Rejected. With fixed era lengths, reachable totals are constrained by the duration modulus, so most post-genesis budgets cannot be hit. A terminal sweep creates an exceptional final reward and is unnecessary. The cumulative-target construction reaches every possible integer budget without a special case.

### 11.6 Change era durations instead of reward arithmetic

Rejected. Making duration depend on genesis allocations changes the time profile and makes monetary timing chain-instance-specific. Fixed durations are already protocol commitments. Exact cumulative targets preserve those boundaries and the halving shape while varying adjacent block rewards by at most one Spark.

### 11.7 Allocate by sequential division

Rejected. Sequential “last recipient gets remainder” allocation is order-sensitive and systematically advantages one recipient. Largest remainder minimizes quota error under this integer allocation shape and uses explicit canonical tie-breaking.

## 12. Precedent

Bitcoin is the closest schedule precedent: consensus derives a subsidy from height, includes subsidy and fees in the block's generation reward, and full validation prevents rewards violating the supply rules [Bitcoin developer guide](https://developer.bitcoin.org/devguide/block_chain.html), [Bitcoin Core validation](https://bitcoin.org/en/bitcoin-core/features/validation). INDRA retains deterministic height-based issuance and finite smallest-unit termination, but deliberately differs by normalizing an exact rational schedule to a genesis-dependent remaining budget rather than using one fixed right-shifted integer subsidy.

Cosmos SDK supplies the closer accounting-invariant precedent: its bank module tracks total supply, updates it on mint/burn, and defines supply as the sum of real balances [Cosmos SDK bank module](https://docs.cosmos.network/sdk/v0.50/build/modules/bank/README). INDRA applies that principle to UTXOs, active/unbonding stake, pending rewards, governance escrow, and fee pool, without introducing Cosmos-style module accounts or governance authority over issuance.

Hamilton/Vinton largest remainder is a real deployed integer-apportionment precedent: floor exact quotas and distribute the indivisible remainder by descending fractional remainder [U.S. Census Bureau](https://www.census.gov/about/history/historical-censuses-and-surveys/census-programs-surveys/decennial-census/methods.html). INDRA's canonical bytewise tie-break and checked cryptographic-state implementation are protocol-specific additions.

## 13. Required verification and acceptance tests

Implementation is not complete without permanent tests for all of the following:

1. Genesis checked-sums all self-stakes and liquid UTXOs exactly.
2. Genesis rejects allocations one Spark above the lifetime cap.
3. Genesis accepts allocations exactly equal to the cap and derives a zero reward budget.
4. Genesis with zero remaining reward budget mints zero forever.
5. Snapshot decode rejects each independently corrupted monetary aggregate.
6. Snapshot decode rejects a ledger/claims mismatch and trailing bytes.
7. Every applied block ends with claims exactly equal to `total_supply`.
8. Every applied block satisfies the genesis-plus-mints-minus-burns identity.
9. No governance action can mutate cap, genesis issuance, reward budget, schedule, or mint counters.
10. Cumulative targets are monotonic and never exceed the budget for every `B` in exhaustive small-budget testing.
11. Exhaustive small-budget testing proves lifetime targets end at exactly `B` for every tested `B`, including 0 and 1 Spark.
12. Maximum-budget testing proves termination by Era 59 or earlier.
13. Era allocations telescope exactly to the lifetime budget.
14. Per-block rewards telescope exactly to each era allocation.
15. Adjacent rewards within an era differ by at most one Spark.
16. Boundary tests cover every era transition and the first permanently-zero reward.
17. An independent big-integer/rational oracle matches the fixed-width implementation over exhaustive boundaries and randomized budgets/heights.
18. Runtime rejects any cumulative-minted value inconsistent with the height target.
19. Runtime rejects any mint that would exceed the reward budget or lifetime cap.
20. Largest-remainder allocation sums exactly to the input pool.
21. Largest-remainder tie-breaking is invariant under input iteration order.
22. Fragmenting one recipient into positions cannot change its aggregate entitlement except where the explicitly defined final position-level apportionment permits a bounded one-Spark tie outcome; canonical tests quantify that bound.
23. Validator, delegator, commission, auto-delegation, and fee-pool distributions have zero residue.
24. No treasury or burn-buffer state is created under any reward distribution.
25. Double-precommit slashing reduces real principal exactly.
26. Liveness slashing reduces the same classes of real principal exactly.
27. Eligible unbonding principal remains slashable; delegated principal remains excluded under the approved burden model.
28. Reporter payout plus slash burn equals real principal reduction, including exactly at the dust boundary.
29. Fee, governance, explicit-slash, liveness, and reporter-dust burns each update the correct canonical counters.
30. Epoch opening supply plus mint minus burns equals closing supply.
31. A deliberately induced overflow/underflow in every monetary mutation fails closed and rolls back.
32. Startup replay and sync reproduce identical monetary ledger, aggregates, and state root.
33. Workspace-wide zero-reference checks confirm removal of treasury, burn buffer, fixed reward-pool semantics, fixed per-era reward constants, and `MAX_RANGE_PROOF_BYTES` from live code.

## 14. Residual risks and proof gates

### 14.1 Arithmetic implementation review

The convergence proof above is short, but implementation still needs independent review of:

- era/height indexing and off-by-one behavior;
- fixed-width bounds for `2N + Q`, powers of two, and per-block products;
- the exact round-half-up implementation;
- transition from the last nonzero target to permanent zero rewards; and
- state rollback if mint allocation fails after provisional credits.

Unlike Topic 7's transcendental Q768 interval approximation, this construction uses only integer multiplication, division, comparison, and powers of two. A machine-checked proof is not presently required, but an independently implemented big-integer oracle and exhaustive small-domain/property tests are mandatory. Any mismatch is a mainnet blocker.

### 14.2 Economic calibration is not solved by arithmetic correctness

Exact convergence proves how much is issued, not that the issuance time profile provides adequate validator security. The normalized schedule assigns 40% of the post-genesis budget to Era 1, 20% to Era 2, 20% to Era 3, then halves era totals. This differs materially from current documentation and requires economic simulation of validator revenue, fee transition, stake concentration, and long-tail security before mainnet.

### 14.3 Genesis allocations remain operationally sensitive

The protocol can prove that genesis allocations are within the cap and publicly enumerate them; it cannot decide whether those allocations are socially legitimate. The final manifest and audit report must be publicly reviewed before genesis.

### 14.4 Largest remainder has deterministic discontinuities

Changing stake by one Spark can change which recipient wins a one-Spark remainder. This is inherent to indivisible-unit apportionment, bounded to the remainder units, and not a supply risk. Canonical tie-breaking prevents nondeterminism but does not remove strategic stake fragmentation concerns; the required fragmentation tests must quantify and bound them.

### 14.5 No emergency fund

The deliberate absence of a treasury means protocol emergencies cannot be financed automatically from consensus state. Funding must occur through voluntary external transactions or an explicitly reviewed protocol change. This is an accepted consequence, not an omitted feature.

## 15. Review gates

Before implementation authorization, adversarial review must explicitly approve:

- [ ] Genesis issuance and derived reward-budget semantics.
- [ ] The two global reconciliation identities and aggregate-cache design.
- [ ] The normalized halving fractions and round-half-up cumulative target.
- [ ] The finite-tail and telescoping proofs.
- [ ] Largest-remainder allocation hierarchy and tie-breaking.
- [ ] Unified mint/burn ledger fields and source classification.
- [ ] Unified liveness/evidence principal-reduction engine.
- [ ] Complete removal list.
- [ ] Wire/state/API breaking-change record.
- [ ] All 33 acceptance tests and residual-risk gates.
