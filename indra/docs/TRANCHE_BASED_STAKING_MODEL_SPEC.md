# Tranche-Based Staking Model

## Status

This is the canonical genesis-native staking specification. There is no
pre-activation state, legacy bond model, migration interval, or compatibility
decoder.

## Canonical state

The staking state consists of:

- `StakePositionV1`, one active aggregate for a unique
  `(validator_id, principal_owner_id, custody)` tuple;
- `ActiveStakeAggregateV1`, the active amount and reward-accounting state;
- `UnbondingTrancheV1`, one immutable exit fragment with explicit timing,
  source commitment, refund provenance, and custody; and
- bounded eviction tombstones retaining exactly the position/tranche
  references needed for refunds, rewards, and slash processing.

`derive_position_id` commits to validator, logical owner, and custody.
`derive_tranche_id` additionally commits to the exit operation and immutable
tranche context. Decoders recompute and validate both identifiers.

## Ownership and custody

Two invariants are independent:

1. The logical principal is the validator ID for validator self positions and
   the delegator ID for delegated positions.
2. The funding UTXO is controlled by the corresponding custody identity:
   `ValidatorColdIdentity` uses the validator's full current cold hybrid key;
   `DelegatorIdentity` uses the registered delegator key.

This separation permits distinct hot consensus identity and cold asset custody
without changing position identity or downstream reward/accounting semantics.

## Deposits

`RegisterValidator`, `SelfStake`, and `Delegate` consume a real UTXO, verify
its value/blinding proof and custody, and atomically add its value to the
derived position. Multiple deposits into the same tuple consolidate into the
same active aggregate. Failed validation rolls back every state and commitment
mutation.

## Partial and full exits

An exit amount must be positive and cannot exceed active principal. Consensus
subtracts it from the active aggregate and creates one immutable tranche. A
full exit removes the active position only after reserving all required
capacity and recording the tranche. A partial exit preserves the remaining
active aggregate.

Maturity is height/epoch precise according to `UnbondingTimingV1`. Matured
tranches produce fresh canonical UTXOs whose commitment, range proof, owner,
and provenance agree. Tranches are removed only after successful refund
insertion.

## Rewards, governance, slashing, and eviction

- Rewards and governance snapshots read active position aggregates.
- Reward claims preserve the logical principal and custody classification.
- Slash processing operates on active principal and any protocol-defined
  slashable tranche state.
- Validator eviction converts affected positions through the same bounded
  tranche/refund model and records bounded tombstone references.

All mutations update `StateCommitmentV2` and emit `CanonicalStateEffects` so
pool invalidation and RPC indexes observe the same committed change.

## Capacity invariants

The authoritative constants are defined in `indra-core` and enforced before
mutation:

- `MAX_STAKE_POSITIONS_TOTAL`;
- `MAX_STAKE_POSITIONS_PER_VALIDATOR`;
- `MAX_TRANCHES_TOTAL`;
- `MAX_TRANCHES_PER_VALIDATOR`; and
- `MAX_TRANCHES_PER_POSITION`.

Exit admission reserves the final-exit slot and global/per-validator tranche
capacity before applying any mutation. Capacity failure is loud and atomic;
collections are never silently truncated.

## Required invariants

1. Position and tranche IDs always recompute from their canonical fields.
2. Logical ownership and source custody are both validated.
3. Principal, rewards, and supply are conserved across deposit, exit,
   maturity, slash, and eviction.
4. Every state/commitment mutation is atomic and rollback-safe.
5. Every collection remains within its explicit consensus and decode bounds.
6. Incremental commitments and RPC indexes equal a full reconstruction after
   arbitrary mutation sequences.
