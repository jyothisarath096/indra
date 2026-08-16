# Slash-Evidence Membership Proofs and Eviction Tombstones

## Status and security boundary

**Specification only. No implementation or activation is authorized by this
document.**

This specification repairs a consensus-validation gap in explicit
equivocation slashing. Today, `SlashEvidenceV1` proves that two hybrid-signed
votes conflict, but slash validation verifies those signatures against the
validator's current registry keys and never proves that the accused validator
belonged to the frozen consensus snapshot governing the alleged vote height
(`indra-state/src/apply.rs:120-215`). A validator who was not a member of
`S(evidence.vote_1.height)` must not be slashable merely because the same
identity or keys appear in current registry state.

The repair adds:

1. a versioned Merkle membership root derived from every authoritative
   `ConsensusSnapshot`;
2. a bounded canonical history of those roots for the existing 500-epoch
   evidence window; and
3. a proof-carrying slash-evidence format whose signatures are verified using
   the historical snapshot entry proven by the evidence; and
4. a separate, bounded evicted-validator tombstone collection that preserves
   slashable bond custody and release metadata after full-registry eviction
   without consuming a live `ValidatorSet` slot.

This changes slash-evidence validity, block encoding, canonical state, state
roots, replay, and checkpoint restore. Passing ordinary tests does not make an
implementation production-ready. Real activation is prohibited until all
review gates in Section 11 have passed.

Normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used in their
usual protocol-specification sense.

## 1. Existing behavior and fixed inputs

### 1.1 Existing evidence and snapshot structures

`SlashEvidenceV1` contains:

```text
SlashEvidenceV1
    validator_id: Bytes32
    vote_1: VoteV1
    vote_2: VoteV1
```

(`indra-core/src/types/slashing.rs:9-18`).

`ConsensusSnapshotEntry` contains:

```text
ConsensusSnapshotEntry
    validator_id: Bytes32
    consensus_weight_spark: u64
    classical_vote_pk: [u8; 32]
    pq_vote_pk: [u8; 2592]
    vrf_pk: [u8; 32]
```

Its exact canonical encoded size is 2,696 bytes
(`indra-core/src/types/consensus_snapshot.rs:20-82`,
`indra-crypto/src/constants.rs:16`). Snapshot entries are strictly sorted by
ascending validator ID, and the list index is already the canonical consensus
position.

The current `ConsensusSnapshot.snapshot_root` is:

```text
SHA256(
    "INDRA-CONSENSUS-SNAPSHOT-v1" ||
    format_version ||
    activation_height ||
    source_boundary_height ||
    encode_list(entries) ||
    total_weight_spark
)
```

(`indra-core/src/types/consensus_snapshot.rs:238-261`). It is a flat hash over
the complete entry list. It cannot authenticate an individual entry without
revealing the complete snapshot and therefore MUST NOT be treated as a
membership root.

### 1.2 Evidence window

This specification treats these existing constants as fixed inputs:

```text
EPOCH_DURATION_BLOCKS = 300
SLASH_EVIDENCE_WINDOW_EPOCHS = 500
UNBONDING_PERIOD_EPOCHS = 1008
MAX_ACTIVE_VALIDATORS = 200
```

The evidence window is inclusive under the existing check:

```text
current_epoch <= infraction_epoch + SLASH_EVIDENCE_WINDOW_EPOCHS
```

(`indra-state/src/apply.rs:194-202`). The code and a consistency test require
the evidence window not to exceed the unbonding period so slashable funds
remain locked (`indra-core/src/types/primitives.rs:35-46`,
`indra-core/src/types/primitives.rs:1335`). This specification does not shorten
or otherwise revisit the 500-epoch policy.

### 1.3 Security objective

For every proof-governed slash evidence `E`, validation MUST establish:

```text
E.validator_id was a member of S(E.vote_1.height)
```

and MUST verify both vote signatures using the vote keys in that proven
historical entry.

Current registry membership, current status, and current keys MUST NOT
substitute for that proof. Current economic state remains relevant only to
applying the resulting stake penalty after historical eligibility and
signatures have been established.

## 2. Versioned membership-root construction

### 2.1 Design choice and rationale

**DESIGN JUDGMENT — REQUIRES INDEPENDENT REVIEW:** Version 1 uses a fixed,
ordered binary Merkle tree over the already-canonical snapshot entry list. It
does not directly serialize `PersistentAuthTree::CompressedProof`.

INDRA's `PersistentAuthTree` provides deterministic domain-separated roots and
proofs (`indra-state/src/persistent.rs:843-951`), but its compressed proof is
data-dependent, is currently a state-crate internal type, and has no canonical
wire encoding suitable for `indra-core` slash evidence
(`indra-state/src/smt.rs:47-108`). A fixed binary tree:

- preserves the snapshot's established ordering;
- has an exact maximum depth of eight at 200 members;
- has a simple fixed proof algorithm;
- keeps proof size predictable; and
- minimizes new cross-crate consensus surface.

The implementation MAY reuse existing SHA-256 and Merkle helper code where its
byte-for-byte behavior matches this section. It MUST NOT silently substitute
the compressed authenticated tree or SSZ root because those have different
hash domains and proof semantics.

### 2.2 Hash function and canonical integer encoding

`H(x)` is INDRA's existing SHA-256 function.

All integer fields below use the existing canonical little-endian fixed-width
encoding:

- `u8`: one byte;
- `u32`: four bytes; and
- `u64`: eight bytes.

Domains are the exact ASCII byte strings shown, with no terminating NUL and no
length prefix:

```text
D_LEAF  = "INDRA-SLASH-MEMBER-LEAF-v1"
D_EMPTY = "INDRA-SLASH-MEMBER-EMPTY-v1"
D_NODE  = "INDRA-SLASH-MEMBER-NODE-v1"
D_ROOT  = "INDRA-SLASH-MEMBERSHIP-ROOT-v1"
```

`SLASH_MEMBERSHIP_ROOT_FORMAT_VERSION_V1 = 1`.

These domains MUST be checked against every existing protocol hash domain
during implementation review. No domain may be reused for another object.

### 2.3 Inputs and entry validation

Let `S` be a fully validated `ConsensusSnapshot`:

```text
A = S.activation_height
B = S.source_boundary_height
N = S.entries.len()
```

Root construction MUST first run all existing snapshot validation, including:

- `A = B + 1`;
- `1 <= N <= MAX_ACTIVE_VALIDATORS`;
- strict ascending validator IDs;
- nonzero weights;
- valid Ed25519, ML-DSA-87, and VRF keys;
- correct total weight; and
- correct existing flat `snapshot_root`.

Membership-root construction MUST never accept an unvalidated or
partially-constructed snapshot.

### 2.4 Leaves and padding

For each real entry at zero-based canonical position `i`:

```text
leaf[i] = H(
    D_LEAF ||
    u8(1) ||
    u64_le(A) ||
    u32_le(i) ||
    ConsensusSnapshotEntry.encode(S.entries[i])
)
```

Let:

```text
P = the smallest power of two such that P >= N
```

For `N = 1`, `P = 1`. Since `N <= 200`, `P <= 256`.

For each padding position `i` in `[N, P)`:

```text
leaf[i] = H(
    D_EMPTY ||
    u8(1) ||
    u64_le(A) ||
    u32_le(i)
)
```

Padding hashes are position-bound and cannot be confused with real-entry
leaves.

### 2.5 Internal nodes

Define level zero as the first level above the leaves. For every adjacent pair:

```text
node[level][j] = H(
    D_NODE ||
    u8(1) ||
    u8(level) ||
    left_child_hash ||
    right_child_hash
)
```

Continue until one 32-byte `tree_root` remains. At `N = 1`, `tree_root` is the
single real leaf and no internal-node hash is applied.

The final membership root is:

```text
membership_root = H(
    D_ROOT ||
    u8(1) ||
    u64_le(A) ||
    u64_le(B) ||
    u32_le(N) ||
    tree_root
)
```

Binding version, activation height, source boundary, and member count prevents
the same tree from being reinterpreted under a different snapshot interval or
padding shape.

### 2.6 Root-version selection

The root-history record remains minimal and does not store a separate version
byte. The authoritative root format is derived only from protocol height:

```text
slash_membership_root_version_for_height(activation_height)
```

Version 1 applies at and after the activation gate in Section 9. A future root
algorithm requires its own height-gated protocol version. Local configuration,
RPC input, or a proof-supplied version MUST NOT select the root algorithm.

## 3. Canonical rolling root history

### 3.1 Record format

Canonical chain state gains a separate collection:

```text
SlashMembershipRootRecord
    activation_height: u64
    membership_root: Bytes32

ChainState
    slash_membership_roots: ordered list<SlashMembershipRootRecord>
```

Each record is exactly 40 encoded bytes. The list uses the existing four-byte
count prefix. Records MUST be strictly sorted by `activation_height`, with no
duplicates.

The root authoritative for an evidence height `h` is:

```text
slash_membership_root_for_height(h) =
    record with greatest activation_height <= h
```

Lookup MUST fail closed for every proof-governed height if no record exists,
records are malformed, or more than one record could be authoritative. It MUST
NOT fall back to the current registry, the two retained full snapshots, the
newest root, or an archive service.

### 3.2 Creation timing

For every post-activation `ConsensusSnapshot` created after a fully settled
epoch boundary:

1. validate the complete snapshot;
2. compute its Version 1 membership root;
3. append the corresponding root record in the same atomic state transition;
4. commit both the full two-snapshot state and rolling root history; and
5. activate both at the snapshot's `activation_height`.

The boundary block itself remains governed by the preceding snapshot. A root
created from boundary `B` has activation height `B + 1` and proves membership
only for heights governed by that new snapshot. This matches the snapshot
activation rule in
`docs/VERSIONED_CONSENSUS_WEIGHT_SNAPSHOTS_SPEC.md`, Section 3.

No registry mutation may rewrite an existing root record.

### 3.3 Retention and pruning

For a record `R[i]`, define its last governed height as:

```text
last_governed_height(R[i]) =
    R[i + 1].activation_height - 1       if a successor exists
    undefined                            for the newest open interval
```

The newest record is never eligible for pruning. For every older record, let:

```text
I_last = epoch_for_height(last_governed_height(R[i]))
```

The record MUST remain available while:

```text
current_epoch <= I_last + SLASH_EVIDENCE_WINDOW_EPOCHS
```

Because the window is inclusive and the newly activated open-interval root
coexists with the oldest still-provable closed interval for one epoch,
canonical state MUST permit up to:

```text
SLASH_EVIDENCE_WINDOW_EPOCHS + 2 = 502 records
```

under the ordinary one-snapshot-per-epoch schedule.

Slash evidence in a boundary block is applied before the epoch transition
(`indra-state/src/apply.rs:763-799`). Pruning MUST therefore occur only after
all slash evidence in that block has been validated and applied. At the end of
the boundary transition, an older record MAY be removed exactly when:

```text
current_epoch > I_last + 500
```

This last-governed-height rule is required because a snapshot activated at
height 301 governs through boundary height 600: `epoch_for_height(600) == 2`
even though `epoch_for_height(301) == 1`. Pruning from the activation epoch
would remove the root one epoch too early for evidence about height 600.
Implementations MUST not use collection length alone as the semantic pruning
rule, although a 502-record cap MUST also be enforced as an invariant.

Replay, block projection, rollback, and checkpoint restore MUST perform
identical creation and pruning.

### 3.4 Exact canonical cost

At the 502-record inclusive maximum:

```text
4-byte list prefix + 502 * 40-byte records = 20,084 bytes
```

This is independent of active-validator count.

`StateCommitmentV2` authenticated-tree node overhead and in-memory collection
overhead are additional and implementation-dependent; 20,084 bytes is the
exact canonical encoding cost.

### 3.5 State-commitment placement

**DESIGN JUDGMENT — REQUIRES STATE-MACHINE REVIEW:** Root records use a
dedicated `StateCommitmentV2` leaf domain, separate from both validators and
full consensus snapshots:

```text
DOMAIN_REWARD_ECONOMIC_SNAPSHOT = 0x0B
DOMAIN_SLASH_MEMBERSHIP_ROOT = 0x0C

leaf_key = derive_key(
    DOMAIN_SLASH_MEMBERSHIP_ROOT,
    u64_le(record.activation_height)
)

leaf_value_hash = H(
    SlashMembershipRootRecord.encode(record)
)
```

The current domain inventory assigns consensus snapshots to `0x0A` and reward
economic snapshots to `0x0B`; slash-membership roots therefore use `0x0C`
(`indra-state/src/state_commitment.rs`). The collision-inventory test MUST
cover both adjacent assignments and reject any reuse.

The collection MUST also be included in:

- canonical `ChainState` encoding and length calculation;
- schema decode and invariant validation;
- state-root reconstruction;
- incremental state-commitment updates;
- projected block application;
- transaction rollback;
- snapshot/checkpoint save and restore; and
- replay determinism tests.

An optional archive sidecar is not consensus authority and cannot replace this
canonical history.

## 4. Proof and slash-evidence wire formats

### 4.1 Membership proof

Version 1 proof format is:

```text
SlashMembershipProofV1
    root_format_version: u8       // MUST equal 1
    activation_height: u64
    member_count: u32
    entry: ConsensusSnapshotEntry // exactly 2,696 bytes
    position: u32
    sibling_hashes: list<Bytes32> // u32 count + 32 bytes each
```

Canonical encoded length is:

```text
1 + 8 + 4 + 2696 + 4 + 4 + 32 * depth
= 2717 + 32 * depth
```

where:

```text
depth = log2(next_power_of_two(member_count))
```

`member_count` is carried in the proof because the deliberately minimal
40-byte root record does not retain it. The final root binds `member_count`, so
the prover cannot alter it without invalidating the proof.

Therefore:

| Active members | Depth | Exact proof size |
|---:|---:|---:|
| 1 | 0 | 2,717 bytes |
| 4 | 2 | 2,781 bytes |
| 20 | 5 | 2,877 bytes |
| 50 | 6 | 2,909 bytes |
| 100 | 7 | 2,941 bytes |
| 200 | 8 | 2,973 bytes |

This refines the investigation's earlier 2.7–3.0 KB estimate upward by 4–13
bytes because the final proof explicitly carries root version, activation
height, member count, position, and the sibling-list length.

Validation MUST require:

- `root_format_version == 1`;
- `1 <= member_count <= MAX_ACTIVE_VALIDATORS`;
- `position < member_count`;
- `activation_height` equals the selected root record's activation height;
- sibling count equals the exact depth implied by `member_count`;
- the entry passes existing `ConsensusSnapshotEntry` validation; and
- no trailing bytes remain after canonical decode.

The sibling list is ordered from leaf level upward. At level `l`, bit `l` of
`position` determines orientation:

- bit zero: accumulator is the left child, sibling is right;
- bit one: sibling is left, accumulator is right.

The verifier recomputes the leaf, internal path, and final root exactly as in
Section 2. `source_boundary_height` is reconstructed as
`activation_height - 1`; the existing snapshot invariant requires exactly
that relationship. Underflow is rejected.

### 4.2 Post-activation evidence envelope

Current blocks encode an untagged list of `SlashEvidenceV1`
(`indra-core/src/types/block.rs:180-232`). Adding even an `Option` flag directly
to `SlashEvidenceV1` would change every legacy block's bytes. It is prohibited.

Post-activation block bodies instead use:

```text
SlashEvidenceEnvelopeV2
    evidence_format: u8
    payload:
        0 => Legacy(SlashEvidenceV1)
        1 => MembershipProven(SlashEvidenceV2)

SlashEvidenceV2
    validator_id: Bytes32
    vote_1: VoteV1
    vote_2: VoteV1
    membership_proof: SlashMembershipProofV1
```

The envelope tag is encoded first, followed immediately by the selected
payload with no additional payload-length prefix. Unknown tags MUST be
rejected.

Pre-protocol-version blocks continue encoding the existing untagged
`list<SlashEvidenceV1>` byte-for-byte. Post-version blocks encode
`list<SlashEvidenceEnvelopeV2>`. Block decoding already selects optional body
shape from the decoded header protocol version for reveal-set evidence
(`indra-core/src/types/block.rs:200-232`); this migration MUST reuse that
explicit versioned-body pattern rather than EOF guessing.

### 4.3 Evidence-size bounds

Existing equivocation evidence is approximately:

- 9,586 bytes when neither vote carries an election-result hash; or
- 9,650 bytes when both votes carry one.

With the one-byte envelope and Version 1 proof:

| Active members | No election hashes | Both election hashes |
|---:|---:|---:|
| 4 | 12,368 bytes | 12,432 bytes |
| 200 | 12,560 bytes | 12,624 bytes |

At the existing `MAX_SLASHES_PER_BLOCK = 3`
(`indra-core/src/types/primitives.rs:174-175`), membership proofs add at most
8,919 bytes plus three envelope tags to a maximally populated
slash-evidence list.
The implementation MUST introduce explicit proof and aggregate block-body size
bounds before any hashing or signature verification.

### 4.4 Canonical proof generation

Proof construction takes a validated full `ConsensusSnapshot`, canonical
entry position, and Version 1 tree. It MUST return the unique sibling path for
that position.

Immediate equivocation detectors can construct a proof while the governing
full snapshot remains in the ordinary two-snapshot state. Delayed submitters
need an archive/indexer sidecar that retained either:

- the full historical snapshot; or
- the Version 1 tree leaves/internal nodes sufficient to reproduce the proof.

Proof-generation storage and RPC are operational infrastructure. They are not
trusted by validation: a malicious archive can only produce a proof that fails
against the canonical root.

No historical proof-generation API exists today. It is a required
implementation deliverable, not something this specification assumes is
already available.

## 5. Validation and state-transition rules

### 5.1 Rule selection

Evidence rules are selected by the alleged vote height, not submission height:

```text
if evidence.vote_1.height < SLASH_MEMBERSHIP_PROOF_HEIGHT:
    legacy eligibility rules
else:
    membership-proof rules
```

This prevents delayed submission from changing the rule under which a
historical vote was created.

The containing block's protocol version controls wire decoding. After the
block-body version transition:

- pre-gate infractions MUST use envelope format `0`;
- proof-governed infractions MUST use envelope format `1`;
- a legacy envelope for a proof-governed height MUST be rejected; and
- a proof envelope for a pre-gate height MUST be rejected.

### 5.2 Proof-governed validation

For `SlashEvidenceV2`, validation MUST proceed fail closed:

1. enforce evidence count, proof length, and canonical structure bounds;
2. require both votes' validator IDs to equal `evidence.validator_id`;
3. require equal vote heights and rounds;
4. compute `infraction_epoch = epoch_for_height(vote_1.height)`;
5. enforce the existing 500-epoch evidence window;
6. require conflicting nonzero block hashes and the currently slashable vote
   step;
7. resolve the one canonical root record for `vote_1.height`;
8. require proof entry validator ID to equal the evidence and both votes;
9. verify the membership proof against that root;
10. verify both hybrid vote signatures using exactly:

```text
proof.entry.classical_vote_pk
proof.entry.pq_vote_pk
```

11. perform duplicate-evidence and current economic-penalty checks; and
12. apply existing stake reduction, reporter reward, supply accounting, and
    `Slashed` status behavior unchanged.

Steps may be reordered only where the result is consensus-equivalent and cheap
structural rejection remains ahead of expensive ML-DSA verification.

Post-gate signature verification MUST NOT obtain vote keys from the current
`ValidatorEntry`. Current keys may differ because of registry lifecycle or
future key migration; the proof binds the keys that held authority at the
infraction height.

### 5.3 What the proof establishes

A valid proof establishes only:

- membership in the frozen snapshot;
- the historical consensus keys, VRF key, and frozen weight recorded there;
- the authoritative snapshot interval; and
- integrity against the canonical retained root.

It does not itself prove equivocation. Both vote signatures and all existing
same-height, same-round, conflicting-hash, step, chain-ID, duplicate, and
evidence-window checks remain mandatory.

Consensus weight and VRF key are included because the leaf is the complete
canonical snapshot entry. Slash amount MUST NOT be derived from the historical
weight field; economic penalty accounting remains governed by existing bonded
stake rules.

### 5.4 Current-registry checks

Historical eligibility and signature verification MUST no longer require the
validator to be currently Active, Registered, or keyed identically.

For a validator still present in `ValidatorSet`, current economic records remain
the penalty target. For a validator removed by a post-activation full-registry
eviction, Section 7's tombstone and retained `StakePositionV1`/
`UnbondingTrancheV1` records are the
penalty target. Absence from both locations MUST fail closed. A membership proof
proves historical authority; it does not create stake that canonical state no
longer retains.

## 6. Coexistence with full consensus snapshots

The snapshot and membership-root structures have distinct purposes and
retention:

```text
consensus_snapshots
    full entries and weights
    authoritative for live/sync consensus
    retain current + immediately previous (2)

slash_membership_roots
    compact membership commitments only
    authoritative for historical slash eligibility
    retain up to 502
```

They MUST be separate `ChainState` collections and separate state-commitment
domains. Increasing full-snapshot retention is explicitly not part of this
design.

Section 7 adds a third, separate collection:

```text
evicted_validator_tombstones
    identity, custody, eviction timing, and position/tranche references
    authoritative only for post-eviction economic targeting and release
    retained until both evidence expiry and final bond maturity
```

Tombstones do not replace either snapshot collection and cannot answer
historical membership on their own.

At root creation, both records originate from the same validated full snapshot.
Tests MUST prove that:

- every retained full snapshot's recomputed membership root equals the
  corresponding root-history record;
- pruning a full snapshot does not alter its retained membership root;
- pruning an expired membership root does not alter either current full
  snapshot; and
- replay and restore reproduce both collections independently.

A membership root cannot supply vote weights, bitfield positions, totals, or
full candidate sets to live consensus. No consensus consumer may use the root
history as a fallback when full snapshot lookup fails.

## 7. Evicted-validator tombstones and retained tranche custody

### 7.1 Existing eviction defect and design objective

Eviction is tranche-native. The planner converts each active position to a
height-precise `UnbondingTrancheV1`, retains the positions and tranches under
their canonical IDs, and commits an `EvictedValidatorTombstoneV2` before the
live `ValidatorEntry` is removed. No principal is released at eviction.

The live `ValidatorSet` is canonically capped at `MAX_VALIDATORS = 1,500`, and
the cap includes all retained lifecycle entries
(`indra-core/src/types/primitives.rs:29`,
`indra-state/src/validator.rs:755-758`,
`indra-state/src/validator.rs:1047-1056`). Keeping an evicted validator as
`ValidatorStatus::Exited` would therefore fail to free the slot. Excluding such
entries from the cap would instead make the registry unbounded. Tombstones MUST
be a separate canonical collection and MUST NOT count toward the 1,500 live
registry entries.

The post-activation eviction transition has four objectives:

1. remove the victim from the live registry so the new validator can register;
2. retain all principal under its canonical position and tranche IDs;
3. preserve enough identity, historical-key, custody, and timing data to apply
   valid delayed slash evidence and later release each bond; and
4. keep the new collection explicitly bounded under adversarial replacement
   churn.

### 7.2 Canonical structures

Canonical chain state gains:

```text
EvictedValidatorTombstoneV1
    format_version: u8 = 1
    validator_id: Bytes32
    eviction_height: u64
    eviction_epoch: u64
    last_classical_vote_pk: [u8; 32]
    last_pq_vote_pk: [u8; 2592]
    last_vrf_pk: [u8; 32]
    cold_custody:
        None
        or {
            classical_pk: [u8; 32]
            pq_pk: [u8; 2592]
            key_version: u64
        }
    retained_position_ids: ordered list<Bytes32>
    retained_tranche_ids: ordered list<Bytes32>

ChainState
    evicted_validator_tombstones:
        ordered map<validator_id, EvictedValidatorTombstoneV1>
```

`eviction_epoch` MUST equal `epoch_for_height(eviction_height)`. Tombstones are
keyed by `validator_id`, encoded in ascending validator-ID order, and MUST be
unique. Position and tranche references are strictly sorted with no duplicates.

The vote and VRF keys are the last complete, validated hot consensus-key set
held by the removed `ValidatorEntry`. They preserve an auditable identity/key
record but are not authoritative for a proof-governed infraction: Section 5.2
still verifies the evidence signatures against the keys inside the membership
proof for the infraction height. This distinction is necessary if a future
key-rotation protocol permits the eviction-time key set to differ from the set
that governed an older height.

`cold_custody` is required when any retained position has
`PositionCustodyV1::ValidatorColdIdentity`. Deleting the live entry without
preserving the active cold public key would make the corresponding matured
tranche unreleasable. A tombstone MUST reject:

- a missing or malformed hot consensus key;
- a retained cold-owned position without a complete active cold custody key;
- a cold key version inconsistent with the evicted entry;
- empty retained position/tranche lists at tombstone creation (empty lists are valid
  later only after every originally retained tranche has canonically matured or
  been slashed away, and the tombstone then remains until Section 7.6 permits
  pruning);
- a referenced position whose `validator_id` does not equal the tombstone ID;
- a tranche reference whose parent position is not retained;
- duplicate position or tranche IDs within or across tombstones; or
- any count above the bounds in Section 7.6.

The tombstone deliberately does not duplicate principal, unbonding precision,
or custody-owner fields. Canonical `stake_positions` and
`unbonding_tranches` remain the sole sources of truth. The tombstone is a
bounded ownership index and historical validator record. Every reference MUST
resolve to exactly one canonical record belonging to the evicted validator.

### 7.3 Atomic eviction transition

At a post-activation full-registry replacement, validation MUST complete before
any state mutation:

1. select the victim under the existing replacement ranking and custody rules;
2. validate the victim's complete hot keys and any required cold custody keys;
3. collect all associated positions and tranches in ascending canonical-ID order;
4. convert active principal to height-precise eviction tranches;
5. prove that adding one tombstone and all references remains within the hard
   bounds;
6. settle pending validator/delegator rewards under the existing policy; and
7. validate every resulting position/tranche/tombstone cross-reference.

The atomic mutation then:

1. removes the victim's live delegation and validator records;
2. for every associated bond that is not already unbonding, begins unbonding at
   `eviction_height` and sets:

   ```text
   unbonding_end_epoch =
       epoch_for_height(eviction_height) + UNBONDING_PERIOD_EPOCHS
   ```

   using the bond's existing legacy-epoch or height-precise encoding rules;
3. leaves every already-unbonding bond's existing start precision and
   `unbonding_end_epoch` unchanged;
4. inserts one tombstone referencing the resulting bonds;
5. removes the live validator entry, freeing exactly one `ValidatorSet` slot;
   and
6. registers the replacement validator.

No bond principal is converted to a spendable UTXO during eviction.
`DelegationReturnReason::ValidatorEvicted`, whose current comment promises an
immediate return (`indra-state/src/validator.rs:55-64`), MUST NOT be emitted by
the post-gate path. A matured release continues to use
`DelegationReturnReason::UnbondingMatured`.

**DESIGN JUDGMENT — REQUIRES ECONOMIC AND STATE-MACHINE REVIEW:** An active
bond has no pre-existing maturity schedule. This specification treats eviction
as the event that starts its ordinary 1,008-epoch unbonding period. An
already-unbonding bond keeps its earlier schedule. Immediately releasing active
bonds recreates the defect; restarting the clock for already-unbonding bonds
would extend a lock that was already promised. External review MUST confirm
this asymmetric rule.

The whole replacement MUST be transactional. Failure to create or commit the
tombstone, update every bond, or insert the replacement validator MUST restore
the exact pre-eviction registry, bonds, delegations, rewards, UTXOs,
commitments, and event log.

### 7.4 Historical authority and the already-exited distinction

For proof-governed evidence at infraction height `H` against a validator absent
from the live registry, slash validation MUST require all of:

1. a unique tombstone for `validator_id`;
2. `H <= tombstone.eviction_height`;
3. the authoritative membership root record for `H`;
4. a valid membership proof for the same validator ID in `S(H)`;
5. both vote signatures valid under the keys in that proven entry;
6. the ordinary equivocation, chain-ID, duplicate, and 500-epoch window rules;
   and
7. at least one canonical self-custody position or tranche that remains
   slashable under the height-aware principal predicate.

The non-strict height comparison is intentional. An eviction applied while
processing block `E` changes post-`E` economic state, while `S(E)` may still
authorize the validator for consensus at height `E`. Membership in `S(H)` is
the decisive historical-authority proof; the tombstone's eviction height
prevents a tombstone from being used for an alleged later infraction.

A validator that fully exited before `H` cannot satisfy the membership proof
for `S(H)`. This is the cryptographic distinction current
`ValidatorStatus::Exited` rejection cannot make. The live-registry `Exited`
rule remains unchanged for legacy evidence and for entries not removed through
the gated tombstone transition.

The tombstone's eviction-time hot keys MUST NOT override proof keys or permit a
legacy evidence item to masquerade as proof-governed evidence. For infractions
before the membership-proof gate, Section 8.3's legacy rules remain in force;
an eviction tombstone alone does not prove pre-gate authority.

On a valid tombstone-targeted slash:

- slash amount and reporter/burn accounting use the existing policy;
- only retained self-bonds selected by the existing slashability predicate are
  reduced;
- delegated principal is not made slashable by this design;
- the global applied-evidence hash is inserted as today;
- the tombstone remains until its ordinary pruning conditions are met; and
- later maturity releases the reduced principal.

There is no live `ValidatorEntry` to mark `Slashed`. Absence from the live
registry already permanently excludes the evicted identity from active-set and
reward eligibility while the tombstone exists. Re-registration under the same
validator ID MUST be rejected until the tombstone is pruned, preventing a new
live identity from aliasing a retained penalty target.

### 7.5 Position/tranche custody, maturity, and release

Retained principal remains in canonical `StakePositionV1` and
`UnbondingTrancheV1` records. Active principal is converted to an immutable,
height-precise tranche during eviction. This avoids a second principal-bearing
store and makes double release structurally detectable.

The maturity scan visits immutable tranches whose release height has arrived,
creates a transparent `OutputV1` under the resolved full hybrid custody key,
attaches `TrancheRefundEventV1` recovery context, removes the tranche, and
updates or removes its parent position. The tombstone-aware path MUST also:

1. resolve validator cold custody from the tombstone when the live validator
   lookup is absent;
2. create the same transparent release output used for non-evicted tranches;
3. remove the canonical tranche and update its parent position;
4. remove the matching tombstone references in the same atomic transition; and
5. emit the ordinary matured-return event where that event is otherwise
   required.

A referenced tranche MUST never be released before its height-precise maturity.
Slashing MUST never reset or accelerate that maturity. Deleting a tombstone
while it still contains a position or tranche reference is forbidden. Removing
a retained record without updating its reference, or removing a reference
without the corresponding canonical transition, is an invariant error.

Because `SLASH_EVIDENCE_WINDOW_EPOCHS = 500` is less than
`UNBONDING_PERIOD_EPOCHS = 1008`, a tranche whose unbonding begins at eviction
remains locked throughout every admissible evidence epoch. An already-unbonding
 self-custody tranche is slashable only when its recorded start is not earlier than the
infraction under the existing legacy/height-precise predicate. This preserves
the security relationship without extending unrelated delegator locks.

### 7.6 Hard bounds, retention, and full behavior

Introduce fixed consensus constants:

```text
MAX_EVICTED_VALIDATOR_TOMBSTONES = MAX_VALIDATORS = 1,500

MAX_RETAINED_BOND_REFERENCES_PER_TOMBSTONE = 104,096

MAX_TOTAL_RETAINED_BOND_REFERENCES = 104,096
```

The tombstone count and both reference limits are semantic write and decode
caps. The aggregate reference limit is binding: per-tombstone capacity cannot
be multiplied by the tombstone count. These explicit 104,096-reference limits
supersede the earlier inherited 150,000,000-entry defensive bond-map decode
ceiling, which was never a safe tombstone write bound. Eviction preflight MUST
reject a candidate that cannot be represented under either reference limit,
then try the next candidate. It MUST reject registration with a dedicated
capacity error if no candidate fits. Truncation is forbidden.

For tombstone `T`, define:

```text
evidence_retention_end_epoch(T) =
    epoch_for_height(T.eviction_height)
    + SLASH_EVIDENCE_WINDOW_EPOCHS

bonds_empty(T) = T.retained_bonds.is_empty()
```

Pruning is allowed only after all evidence in the current block has been
processed and only when:

```text
current_epoch > evidence_retention_end_epoch(T)
and bonds_empty(T)
```

In the ordinary case, newly unbonding bonds keep the tombstone alive for 1,008
epochs, longer than the 502-record membership-root horizon. That is safe:
membership roots are needed only while new evidence can be admitted; the
tombstone remains afterward solely to release locked principal. Tombstones
therefore do not piggyback on the 502-root collection and do not share its
retention length.

Prunable tombstones are removed in deterministic ascending order of:

```text
(eviction_height, validator_id)
```

before testing capacity for a new eviction. A non-prunable tombstone MUST NEVER
be removed merely because the count cap is reached.

If an eviction-requiring registration would exceed either hard bound after all
eligible pruning, the registration MUST fail with a dedicated deterministic
capacity error. It MUST NOT:

- refund bonds early;
- delete the oldest protected tombstone;
- reuse a tombstone key;
- omit some position or tranche references;
- fall back to current eviction behavior; or
- register the newcomer without atomically removing a live victim.

**DESIGN JUDGMENT — REQUIRES AVAILABILITY/DoS REVIEW:** A bounded state cannot
also permit unlimited adversarial eviction churn. This specification chooses
economic safety and deterministic backpressure: at tombstone capacity, a new
registration that requires eviction is rejected until a tombstone becomes
prunable. Tombstones never consume live-registry slots, so every successful
post-gate eviction still frees a 1,500-entry slot; however, the separate safety
cap can temporarily stop further replacements. Any design promising unlimited
replacement would require a different bounded accumulator or externalized
custody construction and is not specified here.

### 7.7 Encoding, commitments, replay, and rollback

**DESIGN JUDGMENT — REQUIRES DOMAIN-INVENTORY REVIEW:** Tombstones use a
dedicated `StateCommitmentV2` domain distinct from validator, bond, consensus
snapshot, and slash-membership-root domains:

```text
DOMAIN_EVICTED_VALIDATOR_TOMBSTONE = next_unassigned_domain

leaf_key = derive_key(
    DOMAIN_EVICTED_VALIDATOR_TOMBSTONE,
    tombstone.validator_id
)

leaf_value_hash = H(
    "INDRA-EVICTED-VALIDATOR-TOMBSTONE-v1" ||
    EvictedValidatorTombstoneV1.encode(tombstone)
)
```

The existing inventory assigns `0x0B` to reward-economic snapshots and `0x0C`
to slash-membership roots (`indra-state/src/state_commitment.rs`). Section 7
does not reserve a future tombstone domain; Part B MUST inventory the
then-current tree and assign its own collision-free value.

Canonical encoding MUST include:

- an explicit collection marker/version;
- a bounded tombstone count;
- ascending validator IDs;
- each tombstone's exact fields;
- bounded aggregate position- and tranche-reference counts; and
- ascending position and tranche IDs within each record.

Decode and checkpoint restore MUST validate all key material, ordering, count,
epoch/height, record existence, ownership, custody, and maturity
invariants before accepting state. Unknown tombstone versions fail closed.

Both state-root systems MUST bind the collection. `StateCommitmentV2` uses the
dedicated leaves above. The legacy/full state-root projection MUST include the
same canonical tombstone encoding under its own unambiguous collection
placement. Existing position and tranche leaves continue to bind principal and
record-local maturity independently.

The collection and every coupled mutation MUST be included in:

- canonical `ChainState` encoding and encoded length;
- schema decode and pre-gate defaulting;
- incremental and full state-root reconstruction;
- projected block application;
- failed-block and failed-operation rollback;
- checkpoint save/restore;
- full replay and archive replay; and
- differential live-versus-sync tests.

Rollback snapshots must cover the live validator/delegation removal,
stake positions, unbonding tranches, tombstone map, UTXOs, pending rewards,
applied slash hashes, supply accounting, and both commitment systems as one
atomic unit.

### 7.8 Activation and migration

Tombstone retention and membership-proof enforcement MUST share
`SLASH_MEMBERSHIP_PROOF_HEIGHT = G` and
`BLOCK_PROTOCOL_VERSION_SLASH_MEMBERSHIP`.

This is an atomic security dependency, not merely deployment convenience:

- membership proofs without tombstone retention still allow an evicted
  offender's economic target to disappear; and
- tombstones without membership proofs cannot safely distinguish authority at
  the infraction height from an identity that had already exited.

Below `G`, eviction bytes and behavior remain byte-identical: no tombstone
collection is encoded, and historical replay retains the existing immediate
refund/removal behavior. At and after `G`, every full-registry eviction uses
the tombstone path. Snapshot/checkpoint decoding supplies an empty tombstone
map for pre-gate state.

There is no bulk migration:

- validators present at `G` remain ordinary live entries;
- existing bonds remain in their current formats;
- a tombstone is created only if a post-`G` eviction occurs; and
- validators evicted before `G` cannot be reconstructed or retroactively
  slashed through this mechanism.

Proof-governed evidence for `H >= G` may target a post-`G` tombstone. Legacy
evidence for `H < G` follows Section 8.3 and MUST NOT acquire historical
eligibility merely from the new tombstone. External review must test the
entire transitional legacy tail.

A separate tombstone gate would create an interval in which one half of the
security invariant is active without the other. This specification rejects
that split. If implementation sequencing requires separate enrollment and
enforcement heights, the document MUST be revised and independently reviewed
before either height is chosen.

### 7.9 Required review additions

Section 11's four gates apply to this section. In addition, reviewers MUST
cover:

1. **Custody and accounting:** no early release, double release, lost release,
   principal duplication, supply drift, reporter overpayment, or slash of
   delegated principal.
2. **Lifecycle authority:** live, unbonding, evicted, re-registration, already
   exited, already slashed, and key-rotation cases around the exact infraction
   and eviction heights.
3. **Bounds and denial of service:** maximum tombstones, aggregate bond
   references, repeated replacement churn, capacity rejection, decode limits,
   and deterministic pruning.
4. **Atomicity:** injected failure after every eviction, slash, release, and
   replacement mutation, with byte-identical rollback.
5. **Replay and migration:** pre-gate byte identity, mixed legacy/proof
   evidence, live/sync/checkpoint equivalence, and cross-binary rejection.
6. **Operational soak:** delayed evidence against an evicted validator,
   maturity before and after tombstone evidence expiry, restart during retained
   custody, and cap-pressure behavior.

No real activation may proceed if review cannot establish that the
500-versus-1,008 security relationship still holds through eviction.

### 7.10 Honest limitations and unresolved decisions

This design deliberately does not:

1. recover validators or bonds already evicted before `G`;
2. make delegated principal slashable;
3. provide the archive/indexer service needed to construct historical
   membership proofs;
4. support unlimited eviction churn;
5. define a future consensus-key rotation history beyond using proof keys as
   authority;
6. change pending-reward policy at eviction;
7. change ordinary `Exited` lifecycle semantics; or
8. turn tombstones into a general historical validator query API.

The following judgments require explicit approval before implementation:

1. active bonds begin a fresh ordinary unbonding period at eviction, while
   already-unbonding bonds retain their existing end epoch;
2. eviction-time cold custody keys are retained because current self-bond
   release resolution otherwise depends on the deleted live entry;
3. tombstones are capped at 1,500 and aggregate references at the existing
   staked-bond decode ceiling;
4. safe capacity exhaustion rejects further eviction-requiring registrations;
5. same-height `H == eviction_height` evidence is allowed when membership in
   `S(H)` is proven;
6. re-registration under a tombstoned validator ID is forbidden;
7. tombstones and membership proofs share one gate/protocol version; and
8. the commitment uses a newly inventoried domain rather than sharing the
   validator or bond leaf.

These are protocol decisions, not descriptions of current behavior.

## 8. Bootstrap and pre-activation evidence

### 8.1 Gate alignment and dependency

Introduce:

```text
SLASH_MEMBERSHIP_PROOF_HEIGHT: u64 = u64::MAX
```

It remains inert until review and scheduling. A real value `G` MUST satisfy:

```text
CONSENSUS_SNAPSHOT_HEIGHT <= G
(G - 1) % EPOCH_DURATION_BLOCKS == 0
```

The snapshot mechanism must already be active and proven stable. `G` is the
first height governed by a newly selected snapshot `S(G)`.

### 8.2 Bootstrap root

At parent boundary `B = G - 1`, state already contains and commits the full
bootstrap snapshot `S(G)`. Pre-gate canonical root-history fields remain
absent, preserving historical bytes.

**DESIGN JUDGMENT — REQUIRES ACTIVATION REVIEW:** While validating/projecting
block `G`, upgraded nodes deterministically:

1. resolve the already-committed full `S(G)` from parent state;
2. validate it;
3. derive the Version 1 membership root;
4. use that derived root to validate any height-`G` proof in block `G`; and
5. insert the first canonical root record into block `G`'s post-state before
   computing its state root.

This is the only allowed derived-root bootstrap. After block `G`, lookup MUST
use canonical root history and MUST NOT reconstruct missing historical roots
from full snapshots as a fallback.

An alternative two-height root-enrollment/enforcement migration would remove
this special bootstrap but add a second gate. External reviewers may require
that alternative; implementation MUST NOT guess if review rejects the
single-gate bootstrap.

### 8.3 Pre-activation infractions

There is no deterministic way for ordinary pruned nodes to backfill 500 prior
membership roots from parent state at `G`. Archive replay could reconstruct
them, but consensus cannot depend on optional archive availability.

Therefore:

- infractions at heights `< G` remain governed by legacy `SlashEvidenceV1`
  eligibility rules for the remainder of their existing evidence windows;
- infractions at heights `>= G` require Version 1 membership proofs;
- no proof claim is made for pre-`G` membership; and
- no pre-`G` root backfill occurs.

This creates a transitional legacy tail of at most 500 epochs. It preserves
historical evidence validity and avoids silently granting offenders amnesty at
activation. After that tail expires, every admissible infraction is
proof-governed.

This is a deliberate design judgment. A policy that rejects all newly
submitted pre-`G` evidence at activation would effectively reset the evidence
window and requires a separate explicit decision; it is not selected here.

## 9. Protocol migration and compatibility

### 9.1 Block protocol version

Activation MUST add a new block protocol version:

```text
BLOCK_PROTOCOL_VERSION_SLASH_MEMBERSHIP
```

`block_protocol_version_for_height` MUST transition at `G`, coexisting
monotonically with reveal-set and consensus-snapshot transitions. An old node
encountering block `G` MUST reject it deterministically and cleanly under the
existing protocol-version mismatch path. It MUST not crash or decode the V2
evidence list as V1.

The containing block height and declared protocol version MUST agree. A local
flag cannot enable or disable proof enforcement.

### 9.2 Pre-gate byte identity

Below `G`:

- block protocol version is unchanged;
- block bodies retain untagged `SlashEvidenceV1`;
- `ChainState` omits `slash_membership_roots`;
- `ChainState` omits `evicted_validator_tombstones`;
- full-registry eviction retains its legacy immediate-refund behavior;
- state roots omit membership-root leaves;
- state roots omit tombstone leaves;
- replay produces byte-identical historical blocks and state; and
- snapshot-file decoding supplies empty pre-activation root and tombstone
  collections.

At and after `G`, block and state bytes intentionally change.

### 9.3 Projection, sync, and mempool behavior

Live proposal validation, block projection, sync import, full replay, and
checkpoint continuation MUST use the same height-derived evidence rule and
root lookup.

Pending evidence pools MUST:

- retain the infraction height and evidence format;
- attach or obtain a proof before proposing a governed item;
- purge malformed, expired, wrong-format, and now-committed evidence; and
- never downgrade a proof-governed item to legacy format when proof generation
  is unavailable.

Proof unavailability means the item cannot be proposed; it does not authorize a
validation bypass.

### 9.4 Checkpoint and sync requirements

A post-gate checkpoint MUST contain the exact canonical rolling root history
and tombstone collection. Restore MUST validate root ordering, root versions by
activation height, maximum retention, pruning eligibility, consistency with
any retained full snapshots, tombstone bounds, key/custody validity, and every
tombstone-to-bond cross-reference.

Sequential sync regenerates roots at each boundary. A checkpoint lacking a
required nonexpired root MUST be rejected rather than repaired from a peer or
current registry.

## 10. Downgrade and regression prohibitions

After activation:

1. A proof-governed slash MUST NEVER be accepted without a valid membership
   proof.
2. Historical membership MUST NEVER be inferred from current registry status,
   current keys, current stake, or current Active membership.
3. Both vote signatures MUST be verified against the keys in the proven entry,
   not current registry keys.
4. Root lookup MUST NEVER fall back to the newest record, a full snapshot, an
   archive response, or a locally reconstructed best guess.
5. Proof and root algorithms MUST be selected by protocol height only.
6. A malformed, missing, expired, pruned-too-early, duplicate, or ambiguous
   root history MUST fail closed.
7. A root record MUST NEVER be rewritten after activation.
8. Root pruning MUST NEVER occur while evidence for the governed epoch remains
   admissible.
9. Membership proof success MUST NOT bypass existing equivocation, signature,
   chain-ID, evidence-window, duplicate, or monetary checks.
10. The historical snapshot weight in the proof MUST NOT replace current
    slashable-bond accounting.
11. The two-snapshot consensus lookup MUST NOT consume compact root records.
12. A post-gate eviction MUST NEVER refund or delete a bond before its own
    `unbonding_end_epoch`.
13. A tombstone MUST NEVER be pruned while it retains a bond or while evidence
    about a pre-eviction governed height remains admissible.
14. Tombstone-cap pressure MUST NEVER select an unsafe fallback, partial
    tombstone, or early release.
15. Proof-governed evidence against an evicted validator MUST NEVER use the
    tombstone's eviction-time keys instead of the proven historical keys.
16. A tombstone and its referenced bonds MUST NEVER disagree about validator
    identity, bond ID, custody, or maturity.
17. Pre-gate blocks and states MUST remain byte-identical under replay.

## 11. Required external review and activation gates

Real activation requires all four gates. These are minimum requirements, not
optional recommendations.

### Gate 1 — independent cryptographic and protocol review

At least one independent reviewer experienced with authenticated data
structures and consensus protocol migrations must review:

- all hash domains and canonical encodings;
- leaf position, padding, level, count, and activation binding;
- proof orientation and exact-depth checks;
- resistance to leaf/padding, tree-size, and cross-snapshot substitution;
- root-history selection and pruning;
- tombstone identity binding and exact-height eviction ordering;
- legacy-tail semantics; and
- the single-gate bootstrap and atomic tombstone activation.

Review must include independent test vectors for 1, 4, 20, 50, 100, and 200
members.

### Gate 2 — implementation and state-machine audit

An independent audit must cover:

- block V1/V2 evidence decoding;
- old-node protocol-version rejection;
- `ChainState` encoding and schema migration;
- `StateCommitmentV2` domain inventory and incremental updates;
- transaction rollback and failed-block atomicity;
- boundary root creation and pruning order;
- tombstone/position/tranche encoding, bounds, custody resolution, maturity, and pruning;
- eviction, slash, release, and replacement atomicity;
- live, projected, sync, replay, and restored-checkpoint equivalence;
- use of proven historical keys;
- evidence-pool and archive/indexer proof generation; and
- every current-registry dependency in slash application.

### Gate 3 — adversarial and differential testing

Tests must include:

- valid proof for every active-set phase;
- wrong position, count, activation, sibling order, sibling orientation, root,
  entry field, and padding;
- a current registry key differing from the historical proven key;
- validator currently demoted, slashed, exited, evicted, or absent;
- eviction before, at, and after the alleged infraction height;
- active positions and already-unbonding tranches at eviction;
- tombstone position/tranche-reference cap exhaustion;
- injected rollback failure at every eviction/slash/release mutation;
- evidence at the first and last valid window epoch;
- pruning immediately after expiry;
- boundary and activation-height evidence;
- legacy evidence during and after the transition tail;
- maximum evidence per block and malformed-size denial-of-service cases;
- cross-binary pre-gate replay vectors; and
- two independent full replays producing byte-identical roots and state.

### Gate 4 — staged testnet activation and soak

Only after Gates 1-3:

- choose an epoch-aligned future testnet height with a real deployment buffer;
- require all validators to run the protocol-version-aware binary;
- independently precompute `S(G)` and its membership root;
- halt activation if any validator disagrees;
- exercise immediate and delayed evidence across multiple root rotations;
- restart and sync both archive and pruned nodes;
- verify root-history pruning after synthetic accelerated-window tests;
- exercise retained-bond maturity and delayed slashing through eviction;
- exercise deterministic registration rejection under tombstone-cap pressure;
- soak for a deliberately chosen period; and
- conduct an explicit go/no-go review.

Mainnet requires a separately reviewed activation height and cannot inherit a
testnet constant accidentally.

## 12. Complexity, costs, and implementation staging

### 12.1 Cost summary

- Canonical root history: exactly 20,084 bytes at 502 records.
- Membership proof: 2,717–2,973 bytes.
- Typical proof-carrying evidence: approximately 12.3–12.6 KB.
- Maximum additional proof bytes for three slash items: 8,919 bytes.
- Tombstone base encoding includes the retained position and tranche ID lists;
  cold custody adds one complete hybrid key and version.
- Tombstones with no remaining position or tranche references become prunable
  (7.64 MiB), including the four-byte outer count.

These replace the roughly 257 MiB maximum-set canonical cost of retaining 500
full 200-validator snapshots.

For an exact like-for-like 502-record inclusive history, a full snapshot's
canonical size is `61 + 2,696 * member_count` bytes, plus one four-byte outer
list prefix. The comparison is:

| Members | One full snapshot | 502 full snapshots | Compact 502-root history |
|---:|---:|---:|---:|
| 4 | 10,845 bytes | 5,444,194 bytes (5.19 MiB) | 20,084 bytes |
| 200 | 539,261 bytes | 270,709,026 bytes (258.17 MiB) | 20,084 bytes |

This refines “hundreds of MB” to 257.65 MiB at the active-set ceiling and
shows that even the current four-validator set would otherwise consume
5.18 MiB canonically.

The tombstone collection's principal remains in the already-counted position
and tranche maps; tombstone IDs are index/key overhead, not duplicated stake.
The implementation's explicit per-tombstone and aggregate reference caps bound
this collection, and capacity exhaustion fails closed as specified in Section
7.6.

### 12.2 Relative implementation size

This is smaller in consumer breadth than the versioned consensus-snapshot arc:
it does not change voting, QCs, proposer election, or VRF quorum.

It is nevertheless a medium-to-large consensus migration because it changes:

- a cryptographic commitment format;
- block-body encoding;
- slash validity;
- canonical state and state roots;
- snapshot/checkpoint schema;
- epoch-boundary retention;
- validator replacement, retained custody, bond maturity, and release;
- replay and sync; and
- proof-generation operations.

With the tombstone portion included, this is a large consensus migration. It is
still narrower than the versioned consensus-snapshot arc in live-consensus
consumer breadth, but is comparable to the hot/cold arc in custody and
state-machine surface and adds authenticated-data-structure risk on top.

### 12.3 Suggested implementation stages

This document does not authorize implementation. If later authorized, a safe
stage breakdown is:

1. isolated root/proof primitives and independent vectors;
2. canonical root-history state and retention;
3. isolated tombstone/bond-reference encoding, bounds, and invariants;
4. atomic eviction, retained custody, maturity, and rollback behind the inert
   shared gate;
5. V2 evidence/block encoding behind that gate;
6. slash validation using proven historical keys and live-or-tombstone
   economic targets;
7. proof generation and archive/indexer RPC;
8. replay, restore, sync, checkpoint, and rollback integration;
9. adversarial capstone and external review remediation; and
10. separate activation-height decision.

## 13. Honest limitations and decisions still required

### 13.1 Resolved by this specification

This specification resolves:

- the membership-root algorithm;
- exact leaf and proof encoding;
- root-history shape and inclusive retention bound;
- separate coexistence with two full snapshots;
- height-derived lookup;
- pre/post-gate wire handling;
- no-backfill legacy-tail behavior;
- bootstrap timing;
- post-activation full-registry eviction retention and historical economic
  targeting; and
- minimum review gates.

### 13.2 Explicit limitations

It does not solve:

1. **Other historical economic-record loss.** Tombstones solve
   post-activation full-registry eviction only. A valid proof still cannot
   recreate records lost through a different, unmodeled lifecycle path or
   before activation.
2. **Proof availability.** Delayed submitters need archive/indexer support that
   does not exist today. Verification is trustless; proof construction is not
   yet operationally supplied.
3. **Historical non-equivocation semantics.** The proof establishes membership,
   not that the two votes satisfy every future consensus-locking rule. Version
   1 retains today's explicit double-precommit semantics.
4. **Reporter identity and incentives.** No reporter-reward policy changes are
   made.
5. **Evidence-window policy.** The value 500 is fixed input here, not newly
   justified or made governable.
6. **Immediate versus epoch-frozen consensus removal.** This remains governed
   by the versioned consensus-snapshot design, not membership roots.
7. **Arbitrary historical QC APIs.** Root history is slash-specific and does
   not create a general historical consensus-query service.
8. **Root algorithm agility without a fork.** A future tree version requires a
   new height-gated protocol transition.
9. **Tombstone capacity.** Sustained adversarial replacement can exhaust the
   separate tombstone cap and temporarily reject new eviction-requiring
   registrations.
10. **Bond-reference capacity.** The explicit aggregate 104,096-reference cap
    bounds canonical growth but can make every live validator temporarily
    non-evictable if existing tombstones consume all capacity; registration
    then fails closed until references mature and capacity becomes available.

### 13.3 Decisions requiring confirmation before implementation

The following are deliberate design judgments rather than behavior inherited
from current code and MUST be explicitly approved after external review:

1. fixed ordered binary Merkle tree rather than serialized
   `PersistentAuthTree` proofs;
2. dedicated `StateCommitmentV2` domain `0x0C`, with `0x0B` assigned to
   reward-economic snapshots and both covered by collision inventory;
3. minimal 40-byte root records with member count carried in proofs;
4. single-gate bootstrap derived from committed `S(G)`;
5. legacy handling for pre-activation infractions until their windows expire;
6. public/archive proof-generation API and retention obligations; and
7. the tombstone structure, forced-unbonding rule, cold custody retention,
   exact-height authority rule, re-registration prohibition, and shared gate;
8. tombstone count and aggregate bond-reference caps, including whether a
   smaller explicit write cap replaces the inherited decode ceiling;
9. deterministic rejection when protected tombstone capacity is exhausted;
   and
10. a newly inventoried tombstone commitment domain.

No implementation should begin by silently choosing different answers to these
items. Any change requires an updated specification and review.
