# Versioned Consensus-Weight Snapshots

## Status and security boundary

**Specification only. No implementation is authorized by this document.**

This is a consensus-critical repair specification for the confirmed finality and
liveness vulnerability in which a quorum certificate for height `H` is formed
under the state before block `H`, but is later verified under the state after
block `H`. The same signed QC can consequently be interpreted under two
different validator-weight distributions.

This change affects the basis on which blocks become final. It must not be
described as production-ready merely because an implementation passes ordinary
unit or integration tests. Activation requires the external review gates in
Section 10.

Normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used in their
usual protocol-specification sense.

## 1. Snapshot structure

### 1.1 Canonical structures

Consensus state MUST contain a bounded, versioned collection of
`ConsensusSnapshot` records. Each record MUST contain:

```text
ConsensusSnapshot
    format_version: u8
    activation_height: u64
    source_boundary_height: u64
    entries: ordered list<ConsensusSnapshotEntry>
    total_weight_spark: u64
    snapshot_root: Bytes32

ConsensusSnapshotEntry
    validator_id: Bytes32
    consensus_weight_spark: u64
    classical_vote_pk: [u8; 32]
    pq_vote_pk: [u8; PQ_PK_BYTES]
    vrf_pk: [u8; 32]
```

`entries` MUST be sorted by ascending raw `validator_id` bytes. The zero-based
index in this canonical list is the validator's QC signer-bitfield position.
Position MUST NOT be separately mutable. If an implementation stores it for
convenience, decoding and invariant checks MUST require it to equal the
canonical list index.

`total_weight_spark` MUST equal the checked or saturating sum, according to the
arithmetic rules active at `activation_height`, of every entry's
`consensus_weight_spark`. Snapshot creation MUST reject:

- an empty snapshot when consensus requires a non-empty Active set;
- duplicate or non-strictly-ordered validator IDs;
- zero consensus weight;
- missing or malformed Ed25519, ML-DSA-87, or VRF public keys;
- more than `MAX_ACTIVE_VALIDATORS` entries;
- a stored total that differs from recomputation;
- a stored root that differs from canonical recomputation.

The current QC adapter already needs validator ID, sorted position, both vote
verification keys, and stake (`indra-consensus/src/qc.rs:26-39`). The current
vote adapter needs validator ID, both vote keys, and stake
(`indra-consensus/src/vote.rs:35-47`). Proposer election needs validator ID,
VRF key, and stake (`indra-consensus/src/proposer.rs:15-27`). These requirements
account for every entry field above.

### 1.2 Snapshot root

`snapshot_root` MUST be a domain-separated hash over the canonical encoding of:

```text
domain = "INDRA-CONSENSUS-SNAPSHOT-v1"
format_version
activation_height
source_boundary_height
entry_count
each entry in canonical order
total_weight_spark
```

The root is defense in depth, an audit identifier, and a compact invariant
check. The canonical snapshot records themselves MUST be included in
`ChainState` encoding and the consensus state commitment. A root stored without
the underlying entries is insufficient for ordinary consensus execution.

Current `ChainState` persists `ValidatorSet` because proposer and QC validation
depend on it (`indra-state/src/chain.rs:56-106`,
`indra-state/src/chain.rs:154-180`). Post-activation, the versioned consensus
snapshot becomes the authoritative source for consensus membership, weights,
positions, and consensus keys; `ValidatorSet` remains authoritative for
economic and registry policy.

### 1.3 Snapshot invariants

For any governed height `h`, exactly one retained snapshot MUST satisfy:

```text
snapshot.activation_height <= h
and no later snapshot has activation_height <= h
```

That snapshot is written `S(h)`.

Within one snapshot:

- membership is immutable;
- weights are immutable;
- positions are immutable;
- vote keys and VRF keys are immutable;
- total weight is immutable.

No mutation to `ValidatorEntry`, including stake, status, or key metadata, may
mutate an already-created snapshot.

## 2. Snapshot versioning and identification

### 2.1 Height-derived identification

QC wire format does not need a new snapshot identifier if snapshot activation
is deterministic and the correct snapshot is committed in chain state.

The authoritative lookup rule MUST be:

```text
snapshot_for_consensus_height(h) = retained snapshot with the greatest
activation_height not greater than h
```

A QC is always verified with:

```text
snapshot_for_consensus_height(qc.height)
```

not with the snapshot for the block carrying the QC, the verifier's tip, or the
verifier's current epoch.

Height is sufficient as the protocol reference because:

1. a QC already signs and encodes its certified height;
2. epoch boundaries are deterministic (`EPOCH_DURATION_BLOCKS = 300`,
   `indra-core/src/types/primitives.rs:21`);
3. snapshot activation heights are canonical state-transition results; and
4. snapshot contents and activation heights are committed in chain state.

An explicit `snapshot_root` in every QC would be redundant for selection and
would require a QC wire-format migration. It MAY be considered later for
standalone archival proofs, but it is not required for this repair and MUST NOT
replace height-based lookup.

### 2.2 Fail-closed lookup

For every post-gate governed height, lookup MUST return exactly one snapshot.
Missing, overlapping, duplicate-activation, malformed, or non-canonical
snapshots are consensus errors. No caller may substitute `state.validators`,
the newest snapshot, or a reconstructed best guess.

## 3. Activation timing

### 3.1 General rule

The validator set and weights that vote on a block are derived from the
committed parent state. Therefore:

- a boundary block is proposed, prevoted, precommitted, and certified using the
  snapshot already active before that block;
- applying the boundary block performs economic mutations, enforcement,
  active-set reselection, penalties, and other epoch work;
- after the complete boundary-block transition, a new immutable snapshot is
  created from the final selected consensus membership and weights; and
- that new snapshot activates at `boundary_height + 1`.

Snapshot creation MUST occur after every epoch-boundary mutation capable of
changing status, eligibility, stake, or consensus keys. Today, staking
operations are applied before the epoch transition, and the transition performs
active-set selection (`indra-state/src/apply.rs:727-735`,
`indra-state/src/apply.rs:780-799`,
`indra-state/src/epoch.rs:93-118`). The snapshot must represent the final
post-boundary result, not an intermediate result immediately after
`select_active_set`.

### 3.2 Concrete 300/301 example

Let `S0` be authoritative through height 300.

1. Height 299 is the committed parent state.
2. Proposer election, VRF quorum, prevotes, precommits, and QC construction for
   block 300 all use `S(300) = S0`.
3. Block 300 finalizes under `S0`.
4. Applying block 300 runs its normal operations and the epoch-boundary
   transition.
5. The transition selects the next Active set and creates `S1` with:
   `source_boundary_height = 300` and `activation_height = 301`.
6. QC 300 remains governed by `S0` forever.
7. Proposer election and all voting for block 301 use `S1`.
8. Block 301 carries QC 300. Verification performs
   `snapshot_for_consensus_height(300)` and therefore uses `S0`, even though
   `S1` is current for block 301.
9. QC 301, when carried by block 302, is verified under `S1`.

This old-for-boundary/new-for-next-height rule is mandatory. Updating a single
current snapshot while applying block 300 and then using it to verify QC 300
would reproduce the original vulnerability.

### 3.3 Genesis

For a chain with snapshots active from genesis, genesis construction MUST create
the first snapshot with `activation_height = 1` from the genesis Active set.
Block 1 has no parent QC under the current rule, but all block-1 proposer and
vote computations use this snapshot.

## 4. Retention requirements

### 4.1 Consensus-state retention

Canonical `ChainState` MUST retain exactly:

- the snapshot authoritative for the next consensus height; and
- its immediately preceding snapshot, when one exists.

Two snapshots are sufficient for normal operation because a block at height
`H+1` carries only the QC for `H`. At an epoch boundary, the current snapshot
governs `H+1` while the immediately previous snapshot governs boundary QC `H`.
Away from a boundary, both heights resolve to the current snapshot.

After a later boundary has finalized far enough that no next block can
legitimately reference the older snapshot, it may be pruned from canonical
state. Pruning MUST itself be deterministic.

### 4.2 Snapshot restore

A persisted node snapshot at state height `K` MUST include both canonical
consensus snapshots. This is necessary because the first imported block
`K+1` carries QC `K`; if `K` was a boundary height, QC `K` uses the preceding
snapshot, not the snapshot active for `K+1`.

The complete-state snapshot format serializes the canonical `ChainState` and
checks its single current schema. Governed consensus snapshots are mandatory
fields and receive full invariant validation on restore. A snapshot lacking
them is noncanonical and startup fails; no conversion path exists.

### 4.3 Sync, replay, and archival verification

Sequential sync does not require all historical snapshots in current state:
each imported boundary deterministically creates the next snapshot before it is
needed, and current plus previous is enough for the next parent QC.

Full replay from genesis similarly regenerates every snapshot.

Arbitrary verification of a historical block without replaying its parent state
is an archival feature, not a live-consensus requirement. Archive nodes or
indexers SHOULD retain every historical snapshot keyed by activation height and
root. Pruned nodes MAY require replay from their retained checkpoint to verify
older QCs.

QC-response handling only accepts a QC for the node's current height and thus
also needs no more than the canonical pair
(`indra-node/src/driver.rs:3105-3119`).

## 5. Registry status versus consensus authority

### 5.1 Required separation

After activation, these concepts are distinct:

```text
Registry/policy status
    Mutable ValidatorEntry state used for economic operations, enrollment,
    eligibility, penalties, and next-snapshot selection.

Consensus authority
    Immutable membership, keys, position, and weight in S(h), used only for
    consensus at height h.
```

`ValidatorStatus::Active` MUST no longer be queried directly to decide
post-gate consensus authority for a governed height. Current
`active_validators()` is a live filter over registry status
(`indra-state/src/validator.rs:1058-1061`); it remains useful for policy and
snapshot construction but is not a consensus-membership oracle after a
snapshot has activated.

### 5.2 SelfStake

Mid-epoch `SelfStake` continues to increase economic `stake_spark`
(`indra-state/src/delegation.rs:1592-1601`). It does not change membership or
weight in the active snapshot.

At the next boundary it participates in strict self-stake ranking. If selected,
the resulting economic self-stake becomes the validator's weight in the new
snapshot activating at the following height.

Snapshot freezing does not change selection policy. The current selector
filters eligible registry statuses/minimum stake/cold enrollment and ranks by
self-stake descending with validator-ID tie-breaking
(`indra-state/src/validator.rs:1090-1123`). Age, incumbency, commission, and
delegated stake remain excluded.

### 5.3 SelfUnstake and minimum-stake demotion

Mid-epoch `SelfUnstake` continues to:

- reduce economic `stake_spark`;
- begin the existing unbonding period; and
- immediately change registry status to `Registered` if economic stake falls
  below `MINIMUM_ACTIVE_SELF_STAKE_SPARK`
  (`indra-state/src/delegation.rs:1649-1673`).

It MUST NOT alter the already-active consensus snapshot. The validator retains
its frozen consensus authority through that snapshot's final governed height.
Its status change immediately affects policy, discretionary Active-only
operations, visibility, and next-snapshot eligibility.

This delayed consensus removal remains economically backed because the
withdrawn bond is locked through the unbonding period; the current constant is
300 epochs (`indra-core/src/types/primitives.rs:40`).

Software MUST NOT stop recognizing the validator's snapshot-valid votes merely
because its live registry status became `Registered`. Whether the validator's
own process continues voting is operational, but its weight remains in the
snapshot denominator. Voluntarily going offline already permits a validator to
withhold its own weight; snapshot freezing does not create a new safety power.

### 5.4 Liveness penalties

Epoch liveness penalties may reduce economic stake and immediately set registry
status to `Registered` below the minimum
(`indra-state/src/epoch.rs:1099-1131`). Because these execute during the
boundary transition, the final post-transition status and stake MUST determine
membership in the newly created snapshot. They do not rewrite the old snapshot
that certified the boundary block.

### 5.5 Slashing and equivocation

Slashing currently reduces economic stake and sets registry status to
`Slashed` immediately (`indra-state/src/apply.rs:299-308`). It MUST NOT rewrite
the active consensus snapshot.

A slashed validator therefore remains recognizable under its old consensus
keys and frozen weight until the next snapshot activates, but is ineligible for
that next snapshot. This is the unavoidable consequence of choosing
epoch-frozen membership rather than a general mid-epoch reconfiguration
protocol.

Immediate consensus-level removal would require a separate, explicitly
versioned reconfiguration mechanism:

- a deterministic activation height for the removal;
- old and new snapshots retained simultaneously;
- every QC resolved against the snapshot active at its own height;
- proposer, vote, VRF, sync, and bitfield logic switched atomically; and
- a reviewed safety argument covering the transition.

No such mechanism is specified here. Implementations MUST NOT introduce an
unreviewed slashing exception to snapshot immutability.

### 5.6 Cold-key enforcement

Cold-key enforcement currently changes unenrolled Active validators to
`Registered` (`indra-state/src/epoch.rs:204-232`). It executes in the epoch
transition before active-set selection, so it naturally excludes unenrolled
validators from the new snapshot without changing the old snapshot that
governed the boundary block.

The enforcement activation height MUST be aligned so all nodes apply the same
boundary semantics. If a future cold-key rule attempts true mid-epoch
consensus removal, it requires the separate reconfiguration protocol described
above.

### 5.7 Registry eviction and key changes

No operation may delete or mutate keys needed by either retained snapshot.
Registry-cap eviction, cold-key rotation, or future validator removal MUST
preserve snapshot-contained consensus keys independently of the live registry.
This is another reason entries contain keys rather than only validator IDs.

## 6. Consumer-by-consumer retrofit

Every post-gate consensus caller MUST accept an explicit consensus height or an
already-resolved immutable snapshot. APIs that hide the height and read
`state.validators` are prohibited.

### 6.1 Vote collection and `registered_voters()`

Current behavior builds voters from live `active_validators()` and copies live
`stake_spark` (`indra-node/src/engine.rs:783-797`). The driver refreshes that
list after each committed block (`indra-node/src/driver.rs:467-476`,
`indra-node/src/driver.rs:2832-2834`).

Required behavior:

- Replace the post-gate adapter with
  `registered_voters_for_height(height, snapshot)`.
- Construct every `RegisteredVoter` from `S(height)` entries.
- Continue freezing that vector inside each height/round/step collector; the
  collector already stores voters and total weight immutably
  (`indra-consensus/src/vote.rs:60-93`).
- Refreshing after a block may clear stale collectors, but MUST NOT change
  weights for another round at the same height.
- Local vote authorization MUST test membership in `S(height)`, not current
  registry status.

### 6.2 QC construction and signer positions

Current `qc_validators()` uses live Active membership, live keys, live stake,
and ascending-ID positions (`indra-node/src/engine.rs:800-816`).

Required behavior:

- `qc_validators_for_height(height)` MUST be a pure adapter over `S(height)`.
- `position` MUST equal the entry index in `S(height)`.
- Finalizing block `H` MUST construct QC `H` with `S(H)`.
- The registered-voter list and QC-validator list used for one height MUST have
  identical IDs, weights, keys, order, and total.
- A mismatch is a fatal local invariant failure, not a reason to fall back to
  live state.

### 6.3 QC verification

`verify_qc` correctly sums the weights supplied by its caller, but has no
independent snapshot identity (`indra-consensus/src/qc.rs:265-287`).

Required behavior:

- Keep the low-level verifier explicit: callers supply validators and total
  from one resolved snapshot.
- Add or require a wrapper whose sole accepted source is `S(qc.height)`.
- `verify_block_qc` MUST resolve by `qc.height`, after checking parent height
  and hash, rather than iterating current `state.validators`. The current live
  lookup is the root vulnerability
  (`indra-node/src/sync.rs:626-701`).
- QC-response, startup-QC restoration, sync import, proposal intake, and
  finalization validation MUST all use the same wrapper.
- `build_qc` remaining a formatting operation is acceptable only if every
  acceptance path independently verifies the resulting QC under `S(qc.height)`.

### 6.4 Proposer candidate construction and election

Current live driver candidates copy `validator.stake_spark` from
`active_validators()` (`indra-node/src/driver.rs:957-978`). Election totals and
scores use those copied weights (`indra-consensus/src/proposer.rs:135-174`,
`indra-consensus/src/proposer.rs:212-237`).

Required behavior:

- Build candidates only from `S(proposal_height)`.
- Use the VRF key and frozen weight stored in that snapshot.
- Proposer verification on proposal intake and sync MUST reconstruct the same
  candidate list from `S(block.header.height)`.
- A registry-status or stake change inside the proposed block cannot influence
  its own proposer authority or the next election until a new snapshot
  activates.

### 6.5 VRF commit/reveal quorum

Current live logic sums commit and reveal IDs by looking up current validator
stakes and compares them with current total Active stake
(`indra-node/src/driver.rs:986-1006`,
`indra-node/src/driver.rs:1347-1379`).

Required behavior:

- Resolve `S(vrf_round.height)` once for the round state.
- Count a commit/reveal only if its validator ID is in that snapshot.
- Use the entry's frozen weight.
- Use the snapshot's stored total.
- Missing-reveal lists MUST enumerate snapshot members with VRF keys, not live
  Active registry entries.
- Election computation and reveal quorum MUST use the identical snapshot
  object.

### 6.6 Election-result-hash precommit quorum

The additional precommit filter currently builds an ID-to-weight map and total
from `registered_voters` (`indra-node/src/driver.rs:2488-2519`).

Required behavior:

- It MUST use the same `S(block.header.height)` already bound to that block's
  vote collector.
- It MUST reject any internal mismatch between collector snapshot version and
  block height.

### 6.7 Sync-time proposer and reveal-set verification

Current sync reveal verification:

- requires live `ValidatorStatus::Active`;
- reads live VRF keys and `stake_spark`;
- builds live proposer candidates; and
- compares against live total Active stake
  (`indra-node/src/sync.rs:481-609`).

Required behavior:

- Resolve `S(block.header.height)`.
- Verify evidence membership and VRF keys against snapshot entries.
- Sum revealed frozen weights from the snapshot.
- Use the snapshot total and snapshot proposer candidates.
- Do not reject valid historical evidence because a validator was subsequently
  demoted, slashed, rotated, or removed from the live registry.

The non-reveal-set proposer verifier MUST likewise use
`S(block.header.height)`.

### 6.8 Validator roots, state roots, replay, and projections

Snapshot creation, activation, and pruning are consensus-state mutations.
Block production projection, live application, sync application, snapshot
replay, rollback, and state-root computation MUST produce byte-identical
results.

The post-gate validator/staking commitment MUST include both retained snapshots
or an equivalently binding canonical subtree. The existing block producer fills
projected state and validator-set roots after applying the candidate block
(`indra-consensus/src/producer.rs:224-254`); snapshot mutations must therefore
be present in that projection.

State transaction rollback/failpoint coverage must include snapshot creation,
rotation, and pruning.

### 6.9 Metrics and RPC

Consensus-facing metrics SHOULD expose:

- current snapshot activation height;
- current and previous snapshot roots;
- current snapshot member count and total weight; and
- next scheduled boundary.

RPC fields labelled “active validators” or “total active stake” must distinguish
live registry policy from frozen consensus authority. This is an observability
requirement, not a new source of consensus truth.

## 7. Downgrade and regression prohibitions

After activation:

1. A QC MUST NEVER be verified against a snapshot other than `S(qc.height)`.
2. No missing-snapshot path may fall back to current `ValidatorSet`, current
   `stake_spark`, newest snapshot, epoch arithmetic alone, or a zero/default
   snapshot.
3. No consumer may mix membership from one snapshot with weights, positions,
   keys, or totals from another.
4. Snapshot activation MUST be a deterministic state transition identical on
   live execution, projection, sync, replay, and restore.
5. Boundary QC `B` MUST remain governed by the snapshot active at height `B`;
   the snapshot created by applying `B` MUST start at `B+1`.
6. Bitfield positions MUST never be recomputed from current registry membership
   when processing a historical QC.
7. Registry demotion, stake mutation, slashing, key rotation, or eviction MUST
   never rewrite a retained snapshot.
8. Snapshot decode or lookup failure MUST fail closed before voting, proposing,
   QC acceptance, or block import.
9. Pre-gate and post-gate validation rules MUST never be selected by local
   configuration, wall-clock time, RPC input, or chain tip guess; only the
   certified/proposed height controls the hard-fork gate.

## 8. Migration and activation

### 8.1 Hard-fork gate

Introduce one global consensus constant:

```text
CONSENSUS_SNAPSHOT_HEIGHT: u64 = u64::MAX
```

It MUST initially remain unscheduled. A concrete value may be set only after
Section 10 review and a coordinated deployment buffer. The standard global
hard-fork warning applies: the value is network history, not automatically
different by chain ID. This follows the existing intentionally-unscheduled
cold-enforcement pattern
(`indra-core/src/types/primitives.rs:617-636`).

The activation height SHOULD be the first height after an epoch boundary:

```text
(CONSENSUS_SNAPSHOT_HEIGHT - 1) % EPOCH_DURATION_BLOCKS == 0
```

Alignment is normative for the initial migration. It avoids a partial first
snapshot and makes the initial snapshot identical to the Active set selected by
the immediately preceding boundary transition.

### 8.2 Initial snapshot

Let gate `G` be boundary `B + 1`.

- Blocks below `G` retain legacy behavior.
- Boundary block `B` is voted and certified under legacy live-state rules.
- State after applying `B` contains the newly selected registry Active set.
- Before proposer/vote processing for `G`, upgraded nodes deterministically
  materialize bootstrap snapshot `S0` from state at `B`, with
  `activation_height = G` and `source_boundary_height = B`.
- Block `G` persists and commits `S0` as part of its state transition without
  allowing operations inside `G` to alter `S0`.
- Block `G` verifies embedded QC `B` under the legacy pre-gate rule because
  `qc.height = B < G`.
- QC `G` and every governed consensus operation at height `G` use `S0`.

Snapshot selection for QC verification MUST be gated by `qc.height`, not the
carrying block's height. This is essential at activation.

### 8.3 Pre-gate byte identity

Pre-gate consensus behavior and canonical consensus bytes can remain
byte-identical:

- no canonical snapshot record exists before `G`;
- legacy consumers continue reading live state for governed heights below `G`;
- canonical snapshot fields are omitted from pre-gate `ChainState` encoding and
  pre-gate roots; and
- schema decoding supplies an empty pre-activation snapshot collection.

At `G`, state encoding/root rules intentionally change and commit `S0`.
Snapshot-file schema may be bumped in the pre-deployed binary, but blocks and
state roots below `G` MUST match the old binary exactly. Golden-vector and
cross-binary replay tests are mandatory.

Because the pre-gate behavior contains a live critical vulnerability, leaving
the gate at `u64::MAX` is only a safe development default, not an acceptable
long-term operational state. The deployment buffer must be real but should not
be unnecessarily long after review and validator readiness.

### 8.4 Protocol compatibility

Activation SHOULD also increment the block protocol version or otherwise
produce an explicit, deterministic old-node rejection at `G`. A mixed network
must not silently compute different state roots or validator authority.

Rollback below `G` after producing governed blocks is not supported. Operational
rollback requires restoring a pre-`G` checkpoint and coordinated chain policy.

## 9. Complexity and risk sizing

This work is **larger and riskier than the hot/cold key-separation arc in
consensus impact**, even if its raw data model appears smaller.

Hot/cold separation touched more operator workflows, signatures, migration
operations, and custody UX. Versioned snapshots touch fewer user-facing
features, but cross-cut:

- block proposal and validation;
- both vote phases and collector lifecycle;
- QC formation, wire interpretation, and every verification path;
- proposer election and VRF quorum;
- active-set transitions and every demotion mechanism;
- state encoding, roots, projections, rollback, replay, sync, and snapshots;
- activation-boundary compatibility; and
- historical-finality interpretation.

The protocol cap is 200 Active validators
(`indra-core/src/types/primitives.rs:332`). With ML-DSA-87 public keys of 2,592
bytes (`indra-crypto/src/constants.rs:16`), two retained full snapshots are
roughly on the order of one megabyte before encoding overhead at the maximum
set size. This is manageable but not negligible for state cloning, roots,
snapshot I/O, and block projection. Implementations should use immutable/shared
snapshot storage internally without making a derived cache authoritative.

The main risk is semantic, not storage cost: one missed live-state lookup can
reintroduce context-dependent finality. This should be sized as a multi-stage
consensus migration, not a local staking fix.

## 10. External review and activation gates

Real activation requires at least four gates, no weaker than the hot/cold
process:

### Gate 1 — independent protocol review

At least one external reviewer with Tendermint/BFT reconfiguration expertise
must review:

- the height-indexed safety argument;
- boundary activation semantics;
- retained-snapshot sufficiency;
- quorum intersection within each governed height;
- slashing/demotion deferral; and
- activation migration.

The review must explicitly attempt to reproduce the confirmed false-positive-QC
and false-negative-QC attacks.

### Gate 2 — implementation and state-machine audit

An independent code audit must enumerate every consensus-weight consumer and
show that each resolves the same snapshot. It must cover:

- all live, sync, replay, restore, and QC-response paths;
- state encoding and root commitments;
- bitfield positions;
- rollback/failpoints;
- pre-gate byte identity; and
- boundary blocks.

Search-based assurance alone is insufficient; reviewers must trace data flow
from certified height to snapshot lookup.

### Gate 3 — adversarial differential testing

Before scheduling:

- old and new binaries must replay identically below the gate;
- multiple nodes must produce identical snapshot roots;
- stake increase/decrease in ordinary and boundary blocks must not alter the
  interpretation of the block's own QC;
- genuine pre-snapshot QCs must remain valid after post-block stake mutation;
- deliberately sub-quorum signature sets must remain invalid even if signers
  gain stake in the certified block;
- demotion, slashing, cold enforcement, and key rotation transcripts must
  replay byte-identically; and
- snapshot restore at a boundary must validate the first child QC correctly.

Property tests should compare live execution, clone projection, sync import,
full replay, and restored-snapshot continuation across randomized stake and
status transitions.

### Gate 4 — staged testnet activation and soak

Only after Gates 1-3:

- choose an epoch-aligned future height with a real deployment buffer;
- require every validator to report the same precomputed bootstrap snapshot
  root from the boundary state;
- halt activation if any validator disagrees;
- activate on testnet;
- monitor at least several full epoch transitions, validator stake changes,
  slashes/demotions, restarts, and catch-up syncs; and
- conduct an explicit go/no-go review before any mainnet use.

Mainnet activation requires a separately reviewed height and must not inherit a
testnet constant accidentally.

## Decisions required before implementation

The following are genuine decisions and must not be guessed during coding:

1. **Slashed-validator authority:** this specification chooses the coherent
   epoch-frozen rule: registry slashing is immediate, consensus removal waits
   for the next snapshot. If immediate consensus expulsion is required, the
   scope changes to a general height-versioned reconfiguration protocol and
   needs a separate safety specification.
2. **Historical archival API:** live consensus needs two snapshots, but the
   project must decide whether archive nodes are required to persist every
   snapshot for standalone historical QC queries or whether replay-on-demand is
   acceptable.
3. **Snapshot commitment placement:** the canonical entries must be committed
   in state. The implementation must decide whether to add a dedicated
   state-commitment subtree or extend the existing validator/staking subtree;
   either choice needs measured root/projection costs and identical security
   semantics.
4. **Activation protocol version:** this specification recommends an explicit
   block protocol-version transition. The exact version number and old-node
   failure behavior must be fixed before implementation.
