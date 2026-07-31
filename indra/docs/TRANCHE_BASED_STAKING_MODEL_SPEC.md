# Tranche-Based Staking Model

## Status and security boundary

**First-pass specification only. No implementation or activation is authorized
by this document.**

This document scopes a replacement for INDRA's one-record-per-bond staking
representation. It is deliberately a protocol design, not a mechanical
consolidation patch.

The current representation preserves every bonded UTXO as a separate
`StakeBondEntry`. That gives each bond independent custody, commitment, and
unbonding timing, but allows an unbounded number of records to accumulate
behind one validator. `DelegatorEntry`, by contrast, aggregates principal and
rewards by `(validator_id, delegator_id)` while carrying only one lifecycle
flag. The mismatch has already caused mixed-lifecycle accounting bugs.

The target representation is:

```text
staking position
├── one active aggregate
├── immutable height-precise unbonding tranche H1
├── immutable height-precise unbonding tranche H2
└── immutable legacy epoch-only tranche, when migrated
```

This specification does **not** claim that the construction is production
safe. It changes canonical custody accounting, staking-operation validity,
reward weights, governance eligibility, slashing targets, state roots,
checkpoint encoding, and refund creation. It requires staged implementation
and independent review before any activation height is selected.

Normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used in
their usual protocol-specification sense.

## 1. Existing behavior and motivation

### 1.1 Current authoritative structures

`StakeBondEntry` currently stores:

```text
utxo_id
validator_id
delegator_id
amount_spark
bonded_epoch
unbonding_end_epoch
unbonding_precision
custody_owner
original_output
```

(`indra-state/src/validator.rs:1770-1789`).

`StakeBondUnbondingPrecision` distinguishes:

- `LegacyEpochOnly`; and
- `HeightPrecise { unbonding_start_height: Option<u64> }`

(`indra-state/src/validator.rs:1758-1768`). The precision family is fixed when
the bond is created. `begin_unbonding` records the exact height only for a
height-precise bond and validates its corresponding end epoch
(`indra-state/src/validator.rs:1968-2029`).

`StakeBondCustodyOwner` distinguishes ordinary delegator identity from
validator cold identity (`indra-state/src/validator.rs:1792-1826`).
`StakeBondOutput` retains some or all of the original output metadata according
to legacy, compact, and fully-compact bond markers. Existing release code uses
that retained metadata, the custody descriptor, and height-gated blinding
rules to recreate a spendable output (`indra-state/src/epoch.rs:1038-1257`).

`DelegatorEntry` separately stores:

```text
delegator_id
staked_spark
pending_rewards
rewards_last_epoch
unbonding_end_epoch
```

(`indra-state/src/validator.rs:2887-2931`). One lifecycle field cannot
faithfully describe several bonds in different states.

### 1.2 Current partial repair is not the target model

The gated per-bond accounting repair derives active delegated principal from
the authoritative bond records and reconciles `DelegatorEntry` after
delegation lifecycle mutations (`indra-state/src/delegation.rs:1558-1621`).
That repair is necessary for the current representation, but it:

- does not bound bond-record growth;
- still requires scans over individual bonds;
- does not consolidate repeated active deposits;
- leaves two canonical representations that must remain consistent; and
- cannot make independently timed unbonding records disappear.

The tranche model MUST subsume that repair after activation. It MUST NOT
reintroduce `DelegatorEntry.unbonding_end_epoch` as authority.

### 1.3 Security and availability objectives

The model MUST provide all of the following:

1. repeated active deposits into the same logical custody position do not
   create new canonical active records;
2. every exit preserves the exact timing precision applicable to the principal
   being exited;
3. active principal, reward weight, governance weight, slashable self
   principal, and releasable principal cannot disagree;
4. no consolidation duplicates, destroys, unlocks early, or redirects value;
5. canonical record growth is explicitly bounded;
6. an operator retains a deterministic path to fully exit even when partial
   exit capacity is exhausted;
7. pre-activation replay remains byte-identical; and
8. tombstone eviction cannot bypass tranche maturity or slash retention.

## 2. Terminology and canonical keys

### 2.1 Position

A **position** is the complete canonical staking relationship for one:

```text
(validator_id, principal_owner_id, custody_descriptor)
```

It owns one active aggregate and zero or more immutable unbonding tranches.

`principal_owner_id` is:

- the validator ID for self-stake; or
- the delegator ID for delegated stake.

It is named separately rather than inferred from equality so decoding and
invariant validation remain explicit.

### 2.2 Custody descriptor

The first implementation SHOULD define a versioned `PositionCustodyV1` rather
than directly embedding the current enum:

```text
PositionCustodyV1
    DelegatorIdentity {
        delegator_id: Bytes32
    }
    ValidatorColdIdentity {
        validator_id: Bytes32
    }
    LegacyEmbeddedHybridKey {
        owner_pubkey: HybridPubKey
    }
```

The legacy embedded-key case exists solely to migrate a pre-identity or
otherwise non-registry-resolvable bond without redirecting its refund.

**DESIGN JUDGMENT J1 — REQUIRES MIGRATION REVIEW:** If an activation preflight
can prove that every extant bond is resolvable through the identity/cold-key
registries, the legacy embedded-key variant can be omitted. The implementation
MUST produce that proof from actual activation state; it MUST NOT assume it
from the intended post-gate rules.

### 2.3 Active aggregate

The active aggregate is:

```text
ActiveStakeAggregateV1
    principal_spark: u64
    contribution_commitment: CommitmentV1
    first_contribution_height: u64
    last_contribution_height: u64
```

`principal_spark` is authoritative for active staking economics.

`contribution_commitment` is the canonical homomorphic sum of commitments
consumed into the active aggregate. It is an audit/binding field; it MUST NOT
be reused directly as a partial-refund commitment. Addition must use the
existing validated curve commitment operation and fail on invalid points.

The two heights provide deterministic audit metadata. They do not determine
unbonding precision.

An empty position MUST have no active aggregate, not an aggregate with zero
principal.

**DESIGN JUDGMENT J2 — REQUIRES CRYPTOGRAPHIC/ACCOUNTING REVIEW:** Retaining an
aggregate contribution commitment is the conservative first-pass choice
because it preserves a cryptographic binding to consumed outputs. If reviewers
establish that canonical public principal plus state-transition balance checks
are sufficient, this field may be removed. It MUST NOT be retained and then
described as a spendable commitment: the aggregate generally has no known
single blinding factor.

### 2.4 Unbonding tranche

```text
UnbondingTrancheV1
    tranche_id: Bytes32
    position_id: Bytes32
    principal_spark: u64
    source_commitment: CommitmentV1
    timing: UnbondingTimingV1
    custody: PositionCustodyV1
    creation_op_id: Bytes32
    creation_ordinal: u32
```

with:

```text
UnbondingTimingV1
    HeightPrecise {
        start_height: u64
        end_epoch: u64
    }
    LegacyEpochOnly {
        start_epoch: u64
        end_epoch: u64
    }
```

Once created, a tranche is immutable except for proportional principal
reduction by a valid slash against slashable self-stake. Maturity removes the
whole remaining tranche atomically with creation of its refund output.

`source_commitment` is derived as specified in Section 5. It binds the tranche
to the active aggregate transition but is not the eventual refund commitment.

## 3. Deterministic identity

### 3.1 Position identifier

Define exact ASCII domain:

```text
D_POSITION = "INDRA-STAKE-POSITION-v1"
```

Then:

```text
position_id = SHA256(
    D_POSITION ||
    u8(1) ||
    validator_id ||
    principal_owner_id ||
    PositionCustodyV1.encode(custody)
)
```

There is exactly one canonical position per tuple. Decoding MUST recompute and
validate the identifier. Callers MUST NOT supply an independently mutable ID.

### 3.2 Tranche identifier

Define:

```text
D_TRANCHE = "INDRA-UNBONDING-TRANCHE-v1"
```

Then:

```text
tranche_id = SHA256(
    D_TRANCHE ||
    u8(1) ||
    position_id ||
    creation_op_id ||
    u32_le(creation_ordinal) ||
    UnbondingTimingV1.encode(timing) ||
    u64_le(principal_spark)
)
```

`creation_op_id` MUST be the canonical ID/hash of the staking operation that
created the tranche, including chain ID, nonce, and signed body. It MUST NOT be
the importing block hash because block reproposal metadata must not change
state-transition identity.

`creation_ordinal` is zero for the ordinary one-tranche operation. It permits a
future explicitly versioned operation to create multiple tranches without
changing the ID construction.

Every node MUST recompute both IDs. Duplicate IDs, tuple collisions, and
caller-supplied mismatches are consensus errors.

**DESIGN JUDGMENT J3 — REQUIRES OPERATION-ID INVENTORY:** The implementation
must confirm that the existing staking-operation ID is available before state
mutation and is stable across all accepted encodings. If it is not, a new
canonical `staking_op_id_v2` must be specified and domain-separated. An outer
block position alone is insufficient because operation reordering during
proposal construction must not create ambiguous user intent.

## 4. Canonical state model

### 4.1 Collections

Post-activation `ChainState` contains:

```text
stake_positions: map<position_id, StakePositionV1>
unbonding_tranches: map<tranche_id, UnbondingTrancheV1>
```

where:

```text
StakePositionV1
    position_id: Bytes32
    validator_id: Bytes32
    principal_owner_id: Bytes32
    custody: PositionCustodyV1
    active: Option<ActiveStakeAggregateV1>
    pending_rewards_spark: u64
    rewards_last_epoch: u64
```

Tranches are a separate map rather than an unbounded vector inside a position:

- deterministic global ordering and pruning are simpler;
- a tranche can be committed and rolled back independently;
- tombstones can reference tranche IDs without copying records; and
- global/per-validator bounds can be checked without decoding nested vectors.

An auxiliary non-canonical index from `position_id` to tranche IDs MAY be
maintained for performance. It MUST be rebuildable from canonical maps and
MUST NOT affect encoding or state roots.

### 4.2 Authoritative fields

After activation:

- `StakePositionV1.active.principal_spark` is authoritative for active
  delegated/self principal;
- `pending_rewards_spark` is authoritative for the owner's position rewards;
- `UnbondingTrancheV1.principal_spark` is authoritative for locked exiting
  principal;
- no aggregate lifecycle flag exists;
- validator `stake_spark` MAY remain as a cached aggregate only if every
  mutation updates it atomically and full rebuild validation recomputes it from
  self positions; and
- legacy `DelegatorEntry` MUST NOT be read for post-gate reward, governance,
  RPC lifecycle, or exit eligibility decisions.

### 4.3 Position lifecycle

A position exists while any of these is nonzero/nonempty:

- active principal;
- pending rewards;
- a referenced unbonding tranche; or
- a tombstone reference requiring custody retention.

When all are absent, the position is deleted deterministically.

## 5. Deposits, commitments, custody, and refunds

### 5.1 Delegate and SelfStake deposit

Post-gate `Delegate` and `SelfStake` continue to consume a real UTXO and prove
the opening of its public-value commitment under existing rules.

They then:

1. derive the position tuple and `position_id`;
2. validate or create the position;
3. add the input's public value to active principal using checked arithmetic;
4. add its commitment to `contribution_commitment`;
5. update contribution heights;
6. spend the input UTXO; and
7. update all roots atomically.

The cap preflight, identity/custody checks, proof validation, arithmetic, and
commitment addition MUST complete before the input is spent.

Repeated deposits to the same tuple do not create a new position or tranche.

### 5.2 Why original outputs cannot simply be retained

An aggregate may contain many original UTXOs, but a partial exit can select an
amount not equal to any original UTXO. Keeping one arbitrary
`original_output` would be incorrect. Keeping a list of every original output
would recreate the record-growth problem under a different field name.

Therefore post-gate refund outputs are protocol-generated from the exited
amount, tranche identity, custody, and a new domain-separated deterministic
blinding derivation. They are not restorations of one original output.

### 5.3 Tranche source commitment

At partial/full exit, define:

```text
D_TRANCHE_SOURCE_BLINDING =
    "INDRA-STAKE-TRANCHE-SOURCE-BLINDING-v1"
```

Derive a scalar using the repository's reviewed hash-to-scalar/KDF convention
over:

```text
chain_id
position_id
tranche_id
principal_spark
start_height or legacy start_epoch
creation_op_id
```

and create:

```text
source_commitment = PedersenCommit(principal_spark, derived_scalar)
```

The derivation MUST be specified byte-for-byte during the cryptographic
sub-arc and tested against an independent oracle. This document reserves the
inputs and semantic purpose but does not invent a new hash-to-scalar algorithm.

### 5.4 Refund output

At maturity, define a separate domain:

```text
D_TRANCHE_REFUND_BLINDING =
    "INDRA-STAKE-TRANCHE-REFUND-BLINDING-v1"
```

The refund commitment MUST use a separately derived scalar over at least:

```text
chain_id
tranche_id
principal_spark
release_height
release_epoch
custody encoding
```

The source and refund domains MUST differ.

The output owner is resolved from the tranche's immutable custody descriptor:

- `DelegatorIdentity`: current registered delegator key;
- `ValidatorColdIdentity`: current active cold key, or the retained tombstone
  cold key after eviction; or
- `LegacyEmbeddedHybridKey`: the embedded key.

Missing or ambiguous custody fails closed; it never burns, redirects, or
silently delays by choosing another owner.

The output is inserted using the existing deterministic staking output
position convention. Mature tranches MUST be ordered by:

```text
(end_epoch, tranche_id)
```

before output indices are assigned.

The existing payment-blinding/provenance mechanism must be extended so the
recipient can recover the refund opening. Merely creating a new Pedersen
commitment without a recoverable blinding factor is forbidden.

**DESIGN JUDGMENT J4 — REQUIRES CRYPTOGRAPHIC REVIEW:** The exact KDF and
recipient-delivery encoding are intentionally not finalized here. Existing
normal-bond release derivations should be reused where their input contract is
sufficient; otherwise this requires a narrowly scoped, reviewed extension.

### 5.5 Supply and commitment conservation

Every deposit, tranche creation, slash, and refund transition MUST preserve:

```text
spendable UTXO principal
+ active position principal
+ unbonding tranche principal
+ other protocol-held principal
```

subject only to explicit reward issuance, fees, and slashing burns.

The active contribution commitment cannot generally be algebraically split
using an unknown aggregate blinding. Consequently, tranche creation MUST NOT
pretend to subtract `source_commitment` from it. On every active-principal
change, the implementation either:

1. recomputes a protocol-owned active accounting commitment from public
   principal and deterministic position state; or
2. treats `contribution_commitment` as append-only audit history and commits
   current public principal separately.

**DESIGN JUDGMENT J5 — BLOCKING CRYPTOGRAPHIC DECISION:** One of these models
must be selected before implementation. The first gives a clean current-state
commitment but changes on withdrawals; the second preserves deposit history
but is not a commitment to remaining principal. Neither may be described as
providing confidential active stake: stake values are already public.

## 6. Partial unstake and undelegation semantics

### 6.1 New operation shape

The post-gate exit operation must identify the position and amount:

```text
ExitStakePositionV1
    position_id: Bytes32
    amount_spark: u64
    authorization...
```

Self-stake and delegated stake MAY retain separate operation tags because
their authorization roles differ. Both use the same state transition.

Legacy operations that reference a `bond_utxo_id` remain valid only for
legacy bonds under the migration rules in Section 8. They MUST NOT select a
post-gate position by guessing which contribution a historical UTXO entered.

### 6.2 Amount rules

For active principal `A` and requested exit `X`:

```text
0 < X <= A
X >= DUST_LIMIT_SPARK
A - X == 0 or A - X >= applicable_minimum
```

The applicable minimum is:

- validator active-self-stake policy for self positions; or
- current minimum delegation policy for delegated positions.

Dropping validator self-stake below the active minimum retains the existing
policy/status behavior, but consensus authority remains governed by the
currently active versioned snapshot until its specified transition.

### 6.3 Tranche creation and immutability

For post-gate positions:

```text
start_height = operation inclusion height
end_epoch = epoch_for_height(start_height) + UNBONDING_PERIOD_EPOCHS
```

The transition decrements active principal and creates a height-precise
tranche atomically.

Two exits at the same height MAY merge only if all of these match:

- position;
- exact timing variant and values;
- custody;
- protocol format version; and
- slash treatment.

If merged, the resulting ID and commitment must be defined from the ordered
set of creation operation IDs, which adds complexity. The conservative Version
1 rule is therefore **no tranche merging**, even at the same height.

**DESIGN JUDGMENT J6 — CAPACITY REVIEW:** Same-height merging could reduce
records but complicates identity and rollback. It is excluded from Version 1
unless benchmarks establish it is necessary.

### 6.4 Full exit availability

A hard tranche cap must not permanently trap active principal. Version 1
reserves one tranche slot per position for a final exit:

- partial exit is accepted only while tranche count is below
  `MAX_TRANCHES_PER_POSITION - 1`;
- the reserved slot may be used only when `X == A`; and
- once active principal is zero, no further exit can be requested.

If the final slot is already consumed due to malformed/migrated state, decode
or transition validation fails closed. It MUST NOT release early or discard an
older tranche.

This guarantees a bounded full-exit path while permitting partial exits under
normal capacity.

## 7. Rewards, governance, RPC, and `DelegatorEntry`

### 7.1 Rewards

Block and fee reward distribution use active position principal only.
Unbonding tranches receive no new rewards.

For each validator:

```text
delegator_active_total =
    sum(active.principal_spark for delegated positions)
```

Commission is applied under the separately gated commission timing rules.
Each delegated position receives its deterministic integer share, and rounding
dust follows the existing explicit dust policy.

Iteration MUST be ascending by `position_id` so rounding and root effects are
deterministic.

### 7.2 Governance

Governance delegation/redelegation eligibility and weight use active position
principal. An unbonding tranche never contributes weight. Redelegation moves
governance attribution only; it does not move principal between validators
unless a separately specified staking operation does so.

### 7.3 Replacement of `DelegatorEntry`

Post-gate `StakePositionV1` replaces `DelegatorEntry` as canonical principal,
reward, and lifecycle state.

There are two acceptable migration strategies:

1. remove migrated `DelegatorEntry` records at activation and use positions
   exclusively; or
2. retain them as a derived compatibility cache excluded from canonical
   encoding and roots.

Maintaining two independently canonical principal/reward balances is
prohibited.

**DESIGN JUDGMENT J7 — BLOCKING STATE-MIGRATION DECISION:** Version 1 SHOULD
remove canonical `DelegatorEntry` records for migrated relationships. A
non-canonical RPC cache is safer than another committed mirror. Exact RPC
compatibility requirements must be inventoried before finalizing this choice.

### 7.4 RPC and operator visibility

RPC must expose:

- position ID and tuple;
- active principal;
- pending rewards;
- each tranche ID, timing precision, start, maturity, amount, and custody role;
- whether final-exit capacity remains;
- whether the record is live or tombstone-retained; and
- legacy bonds not yet migrated.

RPC labels MUST distinguish active, partially unbonding, fully unbonding,
matured-pending-release, slashed, and tombstoned. It MUST NOT reconstruct one
aggregate “unbonding” flag.

## 8. Height precision and legacy migration

### 8.1 Gate dependencies

The tranche model depends on:

- the height-precise unbonding field/protocol transition;
- the delegator per-bond accounting repair;
- the live bond-count cap; and
- the identity/cold-custody gates needed to resolve owners.

Introduce an inert:

```text
TRANCHE_BASED_STAKING_HEIGHT: u64 = u64::MAX
```

and allocate the next unassigned block protocol version at implementation
time. This document deliberately does not hard-code version 8 because other
reviewed arcs may claim the next version before implementation.

A real gate MUST be later than every dependency gate. Old binaries must reject
the new block version cleanly at header decode.

### 8.2 Migration categories

At activation, every current `StakeBondEntry` belongs to one category.

#### Active, height-precise or legacy bond

Active bonds have no unbonding start to preserve. They MAY be aggregated into
the position matching their validator, owner, and custody tuple:

- sum public principal with checked arithmetic;
- combine or account for commitments according to J5;
- derive first/last contribution heights conservatively from available data;
- retain pending rewards exactly once from the matching delegator aggregate;
- remove migrated bond records only in the same atomic transition; and
- rebuild all commitments.

`bonded_epoch` is insufficient to recover exact original deposit height. The
migration must represent unknown exact deposit height explicitly or use
`bonded_epoch * EPOCH_DURATION_BLOCKS` solely as labeled legacy metadata. It
must not fabricate precision.

#### Height-precise unbonding bond

Create one immutable height-precise tranche preserving its exact
`unbonding_start_height`, `unbonding_end_epoch`, amount, and custody.

#### Legacy epoch-only unbonding bond

Create one immutable `LegacyEpochOnly` tranche. Its start epoch is:

```text
unbonding_end_epoch - UNBONDING_PERIOD_EPOCHS
```

using checked subtraction. It remains governed by epoch-level slash comparison
forever. Migration MUST NOT invent a start height.

### 8.3 Migration commitment/refund handling

For a migrated unbonding bond, the conservative first implementation SHOULD
retain a versioned legacy refund descriptor inside the tranche:

```text
TrancheRefundModeV1
    LegacyBondOutput {
        original_output: StakeBondOutput
    }
    SyntheticV1
```

That preserves byte-for-byte existing refund behavior for principal already
unbonding at activation. Newly created tranches always use `SyntheticV1`.

Active migrated bonds cannot retain one output each without defeating
aggregation. Any future exit from their aggregate uses synthetic refund mode.

**DESIGN JUDGMENT J8 — REQUIRES MIGRATION/PRIVACY REVIEW:** Retaining legacy
refund descriptors only for already-unbonding tranches is a bounded,
eventually-pruned compatibility cost and avoids changing their expected
outputs mid-flight. A simpler all-synthetic migration changes commitment and
blinding behavior for pending withdrawals and requires stronger justification.

### 8.4 Migration execution strategy

The migration may be too large for one ordinary boundary block. The final spec
must choose one:

1. **Atomic gate migration:** deterministically transform all records while
   validating the activation block.
2. **Enrollment then enforcement:** build shadow positions over a bounded
   preparation window, commit both representations, then switch authority at a
   second gate.
3. **Lazy per-position migration:** migrate on first touch while both models
   coexist.

This first pass recommends option 2. Atomic work scales with every live bond
and could exceed block-validation budgets. Lazy migration leaves two
authoritative models and makes rewards, slashing, and tombstones substantially
harder to reason about.

**DESIGN JUDGMENT J9 — BLOCKING ACTIVATION DESIGN:** The preparation-window
protocol, state-root treatment, and abort behavior require their own measured
migration specification. No implementation should begin by assuming the whole
map can be converted in one block.

## 9. Interaction with slashing and eviction tombstones

### 9.1 Slash base

Only validator self-stake remains monetarily slashable under current policy.
For an infraction at height `H`, the slash base includes:

- active self-position principal governed by the applicable historical
  authority rules;
- a height-precise self tranche when `start_height >= H`; and
- a legacy epoch-only self tranche when
  `start_epoch >= epoch_for_height(H)`.

This is the tranche-equivalent of the existing dual precision predicate. It
must be a fallible helper; malformed timing is an invariant error, never silent
exclusion.

Slashing proportionally reduces the selected active self principal/tranches
using deterministic ordering and checked arithmetic. It does not alter
delegated positions.

### 9.2 Tombstone ownership

The slash-membership/tombstone specification currently retains evicted bond
references and leaves each `StakeBondEntry` in canonical storage until release
(`docs/SLASH_EVIDENCE_MEMBERSHIP_PROOF_SPEC.md`, Section 7).

Under the tranche model, a tombstone instead retains:

```text
retained_self_position_ids
retained_self_tranche_ids
retained_delegated_position/tranche custody references as needed for release
```

The canonical position and tranche records remain in their own maps. A
tombstone references them and retains the cold custody material needed after
the live validator entry is removed.

### 9.3 Eviction transition

At eviction:

1. active positions cease reward/governance eligibility;
2. every active principal aggregate is converted into an ordinary
   height-precise tranche beginning at `eviction_height`;
3. existing tranches retain their exact timing;
4. the tombstone receives all resulting position/tranche references;
5. live validator/delegation indices are removed;
6. principal is not refunded; and
7. the whole transition is atomic.

This naturally eliminates the tombstone design's dependence on thousands of
individual active bond references, but the tombstone caps must be rewritten in
terms of positions plus tranches.

### 9.4 Shared review dependency

The tombstone specification must be amended before either arc is implemented:

- its 104,096 bond-reference cap cannot be mechanically interpreted as a
  tranche cap;
- release and slash algorithms must accept position/tranche references;
- commitment domains and rollback inventories must include the new maps; and
- mixed legacy-bond and tranche tombstones during migration must be specified.

The tranche model and membership-proof/tombstone arc MAY use distinct gates,
but activation ordering must be explicit. If tombstones activate first, they
must support later migration. If tranches activate first, the tombstone design
must be tranche-native before its own activation.

**DESIGN JUDGMENT J10 — CROSS-SPEC DECISION:** Implementing tombstones first
against individual bonds creates migration work but closes an existing
security bug earlier. Waiting for tranches reduces duplicate work but delays
that security fix. This is a project-priority decision, not something this
document silently resolves.

## 10. Hard bounds and capacity behavior

### 10.1 Required bound dimensions

The implementation MUST define and enforce all of:

```text
MAX_STAKE_POSITIONS_PER_VALIDATOR
MAX_STAKE_POSITIONS_TOTAL
MAX_TRANCHES_PER_POSITION
MAX_TRANCHES_PER_VALIDATOR
MAX_TRANCHES_TOTAL
```

Decode caps and write caps must match or the decoder must be strictly more
permissive only for explicitly migrated historical states.

The existing limits provide upper inputs:

- `MAX_VALIDATORS = 1,500`;
- `MAX_DELEGATORS_PER_VALIDATOR = 100,000`; and
- `MAX_LIVE_BONDS_PER_VALIDATOR = 104,096`

(`indra-core/src/types/primitives.rs:24-32`,
`indra-state/src/validator.rs:32-38`).

### 10.2 First-pass recommended bounds

This document recommends, but does not yet approve:

```text
MAX_STAKE_POSITIONS_PER_VALIDATOR = 100,001
    // 100,000 delegator identities + one validator self position

MAX_TRANCHES_PER_VALIDATOR = 104,096
    // preserve the already-approved live-record safety envelope

MAX_TRANCHES_PER_POSITION = 64
    // 63 ordinary partial-exit slots + one reserved final-exit slot

MAX_STAKE_POSITIONS_TOTAL =
    MAX_VALIDATORS * MAX_STAKE_POSITIONS_PER_VALIDATOR

MAX_TRANCHES_TOTAL =
    MAX_VALIDATORS * MAX_TRANCHES_PER_VALIDATOR
```

The mathematical total ceilings are decode-safety ceilings, not acceptable
operational state targets. State-size review must set a much smaller practical
write/retention envelope if measurements show these totals are infeasible.

**DESIGN JUDGMENT J11 — BLOCKING ECONOMIC/AVAILABILITY DECISION:** The value 64
has no current workload evidence behind it. It is a review placeholder chosen
to make semantics concrete. The final value requires:

- observed/testnet delegation exit frequency;
- worst-case encoded-size measurements;
- adversarial dust-level partial-exit modeling;
- wallet batching expectations; and
- proof that a full exit remains available.

### 10.3 Capacity failure

When a partial exit would exceed a per-position or per-validator tranche cap:

- reject before mutation with a dedicated error;
- leave active principal untouched;
- preserve the reserved final-exit path; and
- never merge different timing, discard a tranche, extend maturity, or release
  another tranche early.

Deposits into an existing position remain allowed because they do not create a
new position/tranche, subject to arithmetic and economic limits.

Creating a position for a new delegator is rejected at the position cap.

Maturity, release, slash, and full exit are never blocked merely because the
current count equals a write cap.

### 10.4 Dust and fragmentation

Every partial exit must satisfy the dust/minimum rules in Section 6.2.
Wallets SHOULD consolidate user intent by exiting one larger amount rather
than creating many small tranches.

The protocol cannot safely coalesce tranches with different exact start
heights. Fragmentation is bounded, not eliminated.

## 11. Encoding and state commitments

### 11.1 Versioned encodings

Each new structure has an explicit local format version:

```text
StakePositionV1              marker 1
ActiveStakeAggregateV1       marker 1
UnbondingTrancheV1           marker 1
UnbondingTimingV1            tagged enum
PositionCustodyV1            tagged enum
TrancheRefundModeV1          tagged enum
```

Unknown versions/tags fail closed. Counts are checked before allocation.
Maps encode in ascending key order, and each encoded key must equal the
recomputed object identifier.

Legacy `StakeBondEntry` markers remain forever decodable for replay and mixed
migration checkpoints.

### 11.2 Commitment placement

Reserve distinct `StateCommitmentV2` domains for:

- stake positions; and
- unbonding tranches.

Do not share validator, delegator, stake-bond, tombstone, or consensus-snapshot
domains.

Conceptually:

```text
position_leaf_key =
    derive_key(DOMAIN_STAKE_POSITION, position_id)

position_leaf_value =
    SHA256("INDRA-STAKE-POSITION-LEAF-v1" ||
           StakePositionV1.encode(position))

tranche_leaf_key =
    derive_key(DOMAIN_UNBONDING_TRANCHE, tranche_id)

tranche_leaf_value =
    SHA256("INDRA-UNBONDING-TRANCHE-LEAF-v1" ||
           UnbondingTrancheV1.encode(tranche))
```

The implementation must inventory then-current domain assignments. This
document does not guess numeric domain bytes.

Both the legacy/full root projection and `StateCommitmentV2` must bind the new
collections. Incremental updates and full rebuilds must agree after every
deposit, exit, slash, reward, maturity, eviction, and migration step.

### 11.3 Atomic rollback inventory

One atomic staking transition may touch:

- UTXOs and spent/nullifier state;
- validator entry/cached self stake;
- positions;
- tranches;
- legacy bonds during migration;
- legacy delegator records during migration;
- pending rewards;
- tombstones;
- delegation-return/provenance events;
- total supply and burns;
- non-canonical indices; and
- both commitment systems.

Failure injection after every mutation is required. Rollback must restore
byte-identical canonical state and rebuilt roots.

## 12. Activation, replay, and checkpoint behavior

### 12.1 Pre-gate behavior

Below the enforcement gate:

- staking operation bytes and validity remain unchanged;
- `StakeBondEntry` and `DelegatorEntry` remain authoritative;
- position/tranche collections are absent from canonical encoding and roots;
- decoding supplies empty collections; and
- no background rewrite may change historical state.

### 12.2 Preparation/enforcement gates

If J9 selects the recommended two-stage migration, use:

```text
TRANCHE_STAKING_PREPARATION_HEIGHT
TRANCHE_STAKING_ENFORCEMENT_HEIGHT
```

Preparation:

- builds and commits shadow positions/tranches deterministically;
- continues executing legacy semantics;
- validates equality between legacy and shadow economic totals; and
- permits abort before enforcement without changing legacy authority.

Enforcement:

- requires complete shadow coverage;
- switches all consumers atomically;
- rejects legacy creation operations except explicitly supported legacy exits;
- removes or de-canonicalizes migrated mirrors; and
- activates the new operation wire format.

Both heights need protocol versions unless reviewers prove the preparation
state is invisible to block validity, which is unlikely because it changes
state roots.

### 12.3 Replay and restore

Required replay classes:

1. genesis through both gates;
2. checkpoint immediately before, during, and after preparation;
3. mixed legacy height-precise and epoch-only bonds;
4. active and already-unbonding migration;
5. reward and slash activity during preparation;
6. eviction/tombstone activity during preparation;
7. two independent full replays producing byte-identical state and roots; and
8. old binaries cleanly rejecting the first unsupported protocol version.

Checkpoint restore must validate every position/tranche invariant and
cross-check economic totals against validator/delegation summaries.

## 13. Fail-closed invariants

Post-gate state is invalid if any of these holds:

1. a position ID does not match its tuple;
2. a tranche ID does not match its immutable fields;
3. a tranche references a missing position unless a precisely specified
   tombstone-owned detached state exists;
4. active or tranche principal is zero;
5. checked sums overflow;
6. a height-precise end epoch does not match its start height;
7. a legacy tranche claims height precision;
8. one logical tuple has multiple positions;
9. position/tranche bounds are exceeded;
10. a position has no active principal, reward, tranche, or tombstone reason to
    exist;
11. custody is missing, ambiguous, or inconsistent with identity state;
12. active self-principal disagrees with any retained validator cache;
13. active delegated totals disagree with reward/governance calculations;
14. a tranche is rewarded as active;
15. a mature tranche is deleted without exactly one refund/burn/slash outcome;
16. principal exists in both a migrated legacy bond and a position/tranche;
17. a refund blinding cannot be recovered by the intended owner; or
18. any caller falls back from position authority to a stale
    `DelegatorEntry`.

No “best effort” reconstruction or live-state fallback is permitted.

## 14. Required test program

### 14.1 Data model and encoding

- round trips for every structure/tag;
- deterministic IDs and independent hash oracles;
- sensitivity to every field;
- duplicate/collision rejection;
- malformed timing/custody rejection;
- exact encoded-size curves at all caps;
- insertion-order independence; and
- mixed legacy/new checkpoint restore.

### 14.2 Deposits and exits

- repeated deposits merge into exactly one active aggregate;
- self and delegated custody remain distinct;
- partial exits create immutable exact-height tranches;
- exits before/at/after an infraction height select the correct slash base;
- final-exit reservation works at the tranche cap;
- partial exit at capacity rejects atomically;
- deposits into an existing position remain possible at record capacity;
- dust/minimum remainder rules; and
- concurrent same-block operations have deterministic nonce/order behavior.

### 14.3 Rewards and governance

- active aggregate receives exactly the same economic share as equivalent
  pre-gate active bonds;
- unbonding tranches receive zero new reward;
- commission and rounding dust remain deterministic;
- mixed active/unbonding RPC output is exact;
- governance weight uses only active principal; and
- no `DelegatorEntry` lifecycle field influences post-gate results.

### 14.4 Refunds and commitments

- KDF oracle and domain separation;
- recipient recovers every refund blinding;
- no source/refund commitment reuse;
- custody rotation and tombstone cold-key cases;
- exactly-once output creation;
- maturity ordering;
- supply conservation;
- incremental/full root agreement; and
- rollback after every mutation.

### 14.5 Migration and compatibility

- byte-identical pre-gate behavior;
- active legacy aggregation;
- precise tranche preservation;
- epoch-only tranche preservation;
- pending reward migration exactly once;
- failed/aborted preparation;
- cross-version header rejection;
- full replay/live/sync/checkpoint equivalence; and
- realistic maximum-state timing benchmarks.

### 14.6 Tombstone composition

- eviction converts active aggregates to timed tranches;
- existing tranches retain maturity;
- delayed evidence finds slashable self principal;
- delegated principal is not slashed;
- no early refund;
- tombstone and tranche caps interact deterministically; and
- mixed legacy-bond/tranche tombstones during rollout.

## 15. Implementation plan and honest sizing

### 15.1 Recommended staged sub-arcs

This SHOULD NOT be implemented as one engineering stage.

Recommended sequence:

1. **Model and encoding primitives**
   - IDs, structs, validation, local encoding, size measurements.
2. **Commitment and refund cryptography**
   - accounting model J5, KDFs, recoverable output provenance.
3. **Isolated position/tranche state machine**
   - deposits, partial/full exits, caps, maturity, rollback.
4. **Rewards/governance/RPC retrofit**
   - remove canonical `DelegatorEntry` authority.
5. **Slashing and tombstone integration**
   - dual precision and eviction retention.
6. **Migration machinery**
   - preparation/enforcement gates, shadow validation, checkpoints.
7. **Full consumer audit**
   - every `staked_bonds`, `delegations`, `stake_spark`, reward, slash,
     governance, RPC, sync, projection, and archive call site.
8. **Capstone**
   - adversarial replay, migration load, independent implementation oracle,
     and activation readiness.

Each sub-arc needs its own acceptance tests before the next consumer is wired.

### 15.2 Scale comparison

This is **larger in implementation surface than the consensus-snapshot arc**
and **comparable to or larger than the hot/cold arc**.

The consensus-snapshot arc was more narrowly concentrated on consensus
authority lookup, despite its criticality. The tranche model crosses:

- canonical state schema;
- staking operation wire formats;
- commitments and recipient recovery;
- all stake lifecycle transitions;
- rewards and commission distribution;
- governance;
- slashing;
- tombstones/eviction;
- RPC/wallet behavior;
- migration of potentially every existing bond; and
- state-size/DoS policy.

It is less subtle than BFT quorum safety in one dimension, but has a broader
economic and migration blast radius. A realistic implementation is multiple
sub-arcs over several review cycles, not one session or one pull request.

## 16. Blocking decisions and review checklist

### 16.1 Decisions that block implementation

The following must be resolved before coding canonical structures:

1. **J5 accounting commitment semantics:** current principal commitment versus
   append-only contribution audit.
2. **J7 canonical `DelegatorEntry` retirement:** removal versus non-canonical
   compatibility cache.
3. **J9 migration architecture:** atomic, preparation/enforcement, or lazy.
4. **J11 actual tranche bounds:** especially per-position capacity and storage
   cost.
5. **Refund KDF/provenance:** exact reviewed construction and wallet recovery.
6. **Operation identity:** confirmation or replacement of the existing stable
   staking-operation ID.
7. **Cross-spec activation order:** tranche model versus tombstone/membership
   proof deployment.

These are genuine protocol design questions, not implementation details.

### 16.2 Decisions that can be resolved during staged design

These do not prevent an isolated prototype but must be fixed before
enforcement:

- J1 legacy embedded custody necessity, after activation-state inventory;
- J2 whether aggregate contribution commitments add useful assurance;
- J4 exact reuse of existing release-blinding primitives;
- J6 same-height tranche merging;
- J8 preserving already-pending legacy refund output behavior;
- numeric commitment-domain assignments; and
- RPC pagination/indexing.

### 16.3 External dependencies

Proceeding immediately is also blocked by:

- no measured activation-state migration size/time;
- no measured distribution of bonds per position and partial exits;
- tombstone spec still being bond-reference based;
- no independent audit of synthetic refund commitment recovery; and
- no reviewed wallet/CLI operation format for amount-based position exits.

An in-memory non-canonical prototype can begin once J5 is selected. Canonical
implementation should not.

## 17. Required external review gates

No real activation height may be selected until all gates pass.

### Gate 1 — cryptographic/accounting review

Independent reviewers must validate:

- commitment conservation and the J5 model;
- deterministic ID domains;
- refund/source KDF separation;
- recipient blinding recovery;
- no value creation, duplication, redirection, or loss; and
- slash/refund arithmetic and rounding.

### Gate 2 — state-machine and migration audit

Review:

- all canonical encodings and bounds;
- every staking/reward/governance/slash/tombstone consumer;
- migration completeness and duplicate-principal exclusion;
- atomic rollback;
- replay and checkpoint restore; and
- old-binary rejection.

### Gate 3 — independent differential implementation/testing

Build an independent oracle for:

- position/tranche ID derivation;
- migration classification;
- principal/reward totals;
- maturity/refund ordering;
- roots; and
- complete replay transcripts.

Fuzz malformed encodings, timing boundaries, cap pressure, operation ordering,
and failure injection.

### Gate 4 — staged testnet migration and soak

Before testnet enforcement:

1. inventory real bond/position/tranche counts;
2. publish measured migration/state-size cost;
3. run preparation without enforcement and compare shadow/legacy totals;
4. exercise deposits, partial/full exits, rewards, slashes, evictions, restart,
   sync, and checkpoint restore;
5. soak for multiple unbonding/reward epochs;
6. obtain validator agreement on roots and migration completion; and
7. choose enforcement height only after review sign-off.

Mainnet requires a separate review and activation decision.

## 18. Honest limitations and non-goals

Version 1 deliberately does not:

1. make active stake or tranche amounts confidential;
2. make delegated principal slashable;
3. provide unlimited partial exits;
4. merge tranches with different timing;
5. retroactively recover funds already mishandled by historical bugs;
6. reconstruct exact deposit heights absent from legacy state;
7. solve archive/indexer requirements for historical slash proofs;
8. remove the need for bounded tombstones;
9. promise byte-identical refund outputs for active bonds migrated into an
   aggregate; or
10. authorize any activation height.

The design bounds fragmentation rather than pretending exact-height tranches
can always be consolidated. It fixes the `DelegatorEntry` mixed-lifecycle
representation by removing that field from post-gate authority, not by adding
another approximate aggregate flag.

## 19. First-pass judgment-call register

The following items require explicit review/approval:

| ID | Judgment | Current first-pass position |
|---|---|---|
| J1 | Legacy embedded custody | Include only if activation preflight finds unresolved owners |
| J2 | Aggregate contribution commitment | Retain conservatively, subject to usefulness review |
| J3 | Synthetic ID operation input | Use canonical staking operation ID if stability is proven |
| J4 | Refund/source KDF | Reuse reviewed primitives where exact contracts fit |
| J5 | Active commitment semantics | Blocking; no silent choice |
| J6 | Same-height tranche merge | Exclude from Version 1 |
| J7 | `DelegatorEntry` future | Remove as canonical authority; optional derived RPC cache |
| J8 | Already-unbonding migration refunds | Preserve legacy output descriptor |
| J9 | Migration | Prefer preparation + enforcement gates |
| J10 | Tombstone deployment order | Project/security priority decision |
| J11 | Tranche caps | 64 per position is a placeholder requiring evidence |

This register is part of the specification. An implementation must record the
approved resolution of every blocking item rather than resolving it implicitly
in code.
