# L3-CS-01 Production Reachability Analysis

## Result

**Classification: LOW — primitive ambiguity unreachable by the production governing-snapshot invariant.**

The preserved reproducer remains valid: because the vote transcript omits a
snapshot root, the same genuine hybrid QC can verify under two distinct,
individually valid snapshots when their signer positions/keys and quorum result
happen to agree. The reproducer's roots are:

- A: `3d9a5d8ca32afaac1217b06e8cb0ddd6e5cb0a96d1b015fc2f9a6e5381e4b7e2`
- B: `d9ebd21d0a25af79e9ec1039eed0ac34b662c9fb7da8ebb9b86c723e59d06f66`

Both verify the same QC. This is not cryptographic equivalence: the snapshots
have different weights and roots. Production, however, never accepts a peer-
selected snapshot. Every audited live, import, application, and restoration
path resolves the unique retained snapshot for the certified consensus height
from canonical `ChainState`.

No critical stop condition was reached. In particular, no trace was found in
which the same finalized parent produces two governing roots, local slash
evidence changes authority before finalization, historical verification uses a
different-height/current snapshot, or conflicting finality is reachable.

## 1. Governing-snapshot function

For a canonical parent state `P`, production implements:

```text
G(P, H) = the retained snapshot s in P.consensus_snapshots
          with maximal s.activation_height <= H
```

`ChainState::snapshot_for_consensus_height` first validates the retained
collection and then performs precisely that greatest-activation lookup
(`indra-state/src/chain.rs:613-627`). Collection validation requires each
snapshot to validate, `activation_height = source_boundary_height + 1`, and
strictly increasing activation heights (`indra-state/src/chain.rs:1409-1448`).
Duplicate activation heights are rejected during installation
(`indra-state/src/chain.rs:1070-1085`). There is no fallback to the live
validator registry, current snapshot, or caller-supplied network snapshot.

The resulting production rule by object is:

| Object/path | Governing authority |
|---|---|
| Proposal/prevote/precommit at H | `G(canonical state, H)`; imported proposals resolve it before proposal verification (`indra-node/src/sync.rs:801-818`), and the live engine builds voters/QC authority from the same height snapshot (`indra-node/src/engine.rs:1492-1527`). |
| PoLC at H | The driver's registered voter set is refreshed from the height-H governing snapshot; persisted PoLC restoration first resolves H and then rebuilds/verifies the prevote collector (`indra-node/src/driver.rs:813-856`). |
| QC for H | `G(state, qc.height)` in live and bounded network verification (`indra-node/src/engine.rs:1520-1539`). |
| Sync/import | `G(canonical provisional parent state, qc.height)`, explicitly ignoring the importing height (`indra-node/src/sync.rs:1045-1061`). |
| Block application | The embedded QC must certify exactly H-1 and the parent hash, then verifies under `G(pre-state, H-1)` (`indra-state/src/apply.rs:4884-4922`). |
| Restart tip QC | Exact decode, exact canonical tip height/hash, then `G(restored state, qc.height)` (`indra-node/src/driver.rs:412-434`). |
| Persisted lock | Resolve `G(restored state, lock.height)`, independently reverify the proposal and reconstruct the PoLC before installing any lock fields (`indra-node/src/driver.rs:813-865`). |

Thus, for a node processing height H from finalized parent P, the governing
snapshot is a deterministic function of `(P, H)`, not message arrival order or
local pools.

## 2. Creation, activation, persistence, and retention

- Genesis builds the active validator set into a snapshot with source boundary
  0 and activation height 1 (`indra-state/src/chain.rs:630-702`, `704-707`).
- Ordinary validator/stake/key/status mutations are incorporated by the regular
  epoch-boundary rotation only after the complete boundary block is applied.
  The builder reads active validators, canonical-sorts entries by validator ID,
  chooses the key whose activation epoch is effective, and constructs the
  snapshot (`indra-state/src/chain.rs:630-702`). The boundary guard requires the
  fully applied canonical boundary state (`indra-state/src/chain.rs:890-916`).
- A slash finalized in block H creates an intermediate snapshot for H+1 by
  removing only explicitly finalized slashed/tombstoned authorities from the
  snapshot governing H. It cannot activate unrelated live-registry changes
  (`indra-state/src/chain.rs:930-995`).
- At an epoch boundary, regular rotation occurs last, after slashing, liveness,
  rewards, releases, and other scheduled mutations, and therefore produces one
  consolidated H+1 snapshot (`indra-state/src/apply.rs:4788-4824`). At a
  non-boundary height, the slash-specific rotation occurs after the block tip is
  advanced and activates at H+1 (`indra-state/src/apply.rs:4727-4772`).
- Installation validates and sorts snapshots, rejects duplicate activation,
  and deterministically retains the newest two plus the economic epoch anchor
  (`indra-state/src/chain.rs:1070-1107`). Snapshots are part of canonical
  `ChainState`, snapshot persistence, and the state commitment; decode validates
  rather than trusting arbitrary lookup state.

### Activation table

| Trigger included/finalized at H | State mutation | Snapshot creation | First governed height |
|---|---|---|---|
| Genesis | Genesis construction | source 0 | 1 |
| Registration/stake/exit/key activation | During canonical block/epoch processing | End of applicable epoch boundary H | H+1 |
| Double-sign slash, non-boundary | During canonical application of evidence in H | After finalized state marks the authority slashed | H+1 |
| Slash/liveness at epoch boundary | During canonical boundary transition | One final regular snapshot, created last | H+1 |

## 3. Same-parent determinism and slash evidence

The block path validates transactions, staking operations, governance
operations, and slash evidence against shadow clones before any real mutation
(`indra-state/src/apply.rs:4506-4614`). Finalized slash effects are then applied
in canonical block order; only a validator present in the snapshot governing H
is placed in the deterministic `BTreeSet` of revoked authorities
(`indra-state/src/apply.rs:4672-4723`). Snapshot rotation happens within the
same atomic state transaction.

In contrast, `NodeEngine::add_slash_evidence` resolves the infraction snapshot,
builds the proof, applies it only to a scratch clone, and appends it to the
node-local bounded `pending_slashes` pool (`indra-node/src/engine.rs:885-952`).
It does not mutate `ChainState` or `consensus_snapshots`. Therefore two nodes
with the same finalized parent but different evidence pools retain identical
governing roots. Evidence affects authority only when included in and applied
by the same finalized block.

Transaction ordering cannot create divergent authority from the same finalized
parent because the ordered block is itself the agreed input. Restart/sync timing
cannot choose an authority snapshot: decoded canonical state is validated and
all consumers repeat the height lookup.

## 4. Historical and cross-height QC verification

Votes bind chain ID, height, round, step, full block hash, and validator ID
(`indra-core/src/types/vote_signing.rs:8-29`). They do not bind snapshot root.
QC verification maps the signer bitfield to positions, weights, and vote keys
in the snapshot supplied by the caller (`indra-core/src/types/qc.rs:134-225`).

Production callers constrain that parameter:

- live/network verification resolves by `qc.height`;
- sync resolves by `qc.height`, not import height;
- block application requires an exact H-1 parent QC and resolves H-1;
- persisted tip QC requires the canonical tip height/hash;
- lock restoration resolves the lock's next-height authority and reverifies all
  proposal/PoLC material before mutation.

A QC made under a snapshot active at H-1 is valid at H only if that same
snapshot remains the result of `G(P,H)`. A snapshot activating at H+1 or a later
epoch is not selected for H. If an old height is no longer covered by retained
history, lookup fails closed with `NoSnapshotForHeight`; it does not reinterpret
the QC under the current snapshot. Sequential sync verifies each embedded
parent QC while replaying the canonical parent state, where the adjacent
authority snapshots are retained.

## 5. Safety and liveness reachability answers

- **Can both primitive proposals/QCs pass when an arbitrary valid snapshot is
  supplied?** Yes; the preserved audit reproducer proves this.
- **Can both be admitted from the same finalized production parent under two
  governing snapshots?** No production trace found. `G(P,H)` selects one root.
- **Can local slash evidence change authority prefinalization?** No; it is
  scratch-validated and pooled only.
- **Can a QC be falsely accepted/rejected because a later/current snapshot is
  used?** No audited path does so. Missing historical authority fails closed.
- **Can the ambiguity poison locks, rounds, sync, or restart?** Not without first
  violating canonical parent-state equality. Each path resolves the same
  height-specific snapshot before mutation.
- **Can conflicting finality be constructed with <1/3 Byzantine weight?** Not
  from L3-CS-01. The prerequisite—two production-reachable governing snapshots
  for the same `(finalized parent, height)`—was not found, so the differing-set
  QC construction is unreachable.

## 6. Should votes sign `snapshot_root`?

**Yes, as defense in depth and protocol-context completeness.** Authority is not
only `(chain,height,round,step,block,validator)`; it also includes membership,
weight, vote keys, suite/version, and activation context. An explicit snapshot
root in the vote transcript would make the primitive incapable of the preserved
cross-snapshot replay and would convert any future snapshot-selection bug into a
signature failure.

This recommendation does not raise the production classification above LOW:
today's same-parent deterministic lookup prevents exploitation. It does mean
`NOT A FINDING` is inappropriate—the two contexts are demonstrably not
cryptographically equivalent by construction.

## 7. Focused validation

All passed:

```text
cargo test -p indra-state snapshot_lookup_uses_exact_greatest_activation_not_greater_than_height
cargo test -p indra-state slash_snapshot_is_deterministic_and_epoch_rotation_supersedes_it
cargo test -p indra-state full_consensus_snapshot_replay_matches_independent_reference
cargo test -p indra-node pending_slash_deduplicates_by_hash
cargo test -p indra-node qc_formation_and_verification_replay_across_snapshot_boundary
```

These respectively exercise exact greatest-activation lookup, deterministic
slash/boundary interaction, independent full snapshot replay, local pending
evidence handling, and historical QC verification across a snapshot boundary.

No production file was modified for this investigation.
