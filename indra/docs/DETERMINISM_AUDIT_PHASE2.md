# INDRA Determinism Audit — Phase 2

## Executive Summary
Phase 2 found one CRITICAL restart/replay determinism bug and one HIGH block-production canonicalization bug; both are now **FIXED**. The height 9872 restart divergence was most likely caused by the live commit path mutating `ValidatorEntry.last_active_epoch` from the committed block QC after `apply_block`, while startup replay only called `apply_block`. That QC-derived mutation now lives inside `indra-state::apply_block`, so live commit, sync import, block-production projection, and replay all execute the same state transition. Mempool equal-fee selection and capacity eviction now use deterministic `tx_id` tiebreakers. The originally suspected equal-stake active-set tiebreaker is safe: equal stake is broken deterministically by validator ID. The SMT uses `HashMap` internally, but its current root computation is order-insensitive.

## SMT Analysis
### Finding: SAFE
`indra-state/src/smt.rs` stores `leaves: HashMap<[u8; 32], [u8; 32]>` at line 37 and `nodes: HashMap<NodeLoc, [u8; 32]>` at line 38. Recompute builds `levels: Vec<HashMap<NodeLoc, [u8; 32]>>` at lines 124-125 and `grouped: HashMap<NodeLoc, (Option<[u8; 32]>, Option<[u8; 32]>)>` at lines 144-145.

The implementation does iterate these maps:

- `self.leaves` is iterated at line 128 to place leaf hashes into the leaf level.
- `child_level` is cloned and consumed at line 146 while grouping children by deterministic parent `NodeLoc`.
- `grouped` is consumed at line 162 to insert parent hashes into the level map.
- `levels` and each contained map are consumed at lines 171-173 to rebuild `self.nodes`.

Despite the randomized map iteration order, the computed root is deterministic because every write is keyed by a deterministic tree location, and parent hashes are pure functions of `(left_child, right_child)` selected by `bit_at`, not by iteration position. The final root is fetched by the fixed location `NodeLoc { depth: 0, prefix: [0; 32] }` at lines 177-184. Iteration order can affect insertion order into `HashMap`, but not the key/value set or the final root. The file also has a regression test, `deterministic_independent_of_insertion_order`, at lines 317-335.

Residual risk: this is safe only because recompute never folds hashes in map iteration order. Any future optimization that folds `HashMap` entries directly into a root would be dangerous.

## State Root Computation
### Finding: FIXED CRITICAL
`indra-state/src/state_root.rs` commits to:

- UTXO SMT root (`state.utxos.root()`) at line 22.
- Nullifier SMT root (`state.nullifiers.root()`) at line 23.
- Validator/delegation root (`compute_validator_set_root(state)`) at line 24.
- Metadata hash containing chain ID, height, total supply, base fee, treasury balance, burn buffer, fee reward pool, and governance state at lines 26-37.

The top-level combination order is fixed: UTXO root, nullifier root, validator root, metadata hash at lines 39-44.

The validator/delegation commitment collects leaves from validators, delegators, staking nonces, staked bonds, and applied slash hashes. It sorts all leaves by key before hashing at line 146, so mixed sources are canonicalized before Merkle reduction.

The critical issue is not iteration order inside `state_root.rs`; it is that `compute_validator_set_root` includes `validator.last_active_epoch` at line 62. `last_active_epoch` is mutated in live commit by `NodeEngine::update_last_active_epoch_from_block_qc` (`indra-node/src/engine.rs` lines 610-628), after `import_block` has applied the block. Startup replay (`rebuild_state_from_height`, `indra-node/src/engine.rs` lines 666-696) calls only `apply_block(state, &block, 0)` at line 692 and never applies the QC-derived `last_active_epoch` update. Therefore a snapshot-plus-replay node can reconstruct a different validator root than a continuously running node.

**Fix status:** FIXED. `indra-state/src/apply.rs::apply_block` now decodes the block header QC at the end of the canonical state transition and updates `last_active_epoch` for every QC signer. `indra-node/src/engine.rs::commit_block` no longer performs a separate live-only liveness mutation.

This reaches state-root computation directly:

`NodeEngine::init` → `rebuild_state_from_height` → `apply_block` only → missing `update_last_active_epoch_from_block_qc` → `last_active_epoch` differs → `compute_validator_set_root` includes different bytes → `compute_state_root` differs.

## UTXO Set
### Finding: SAFE
`indra-state/src/utxo.rs` stores `entries: HashMap<Bytes32, UtxoEntry>` at line 123. The set uses an SMT cache for state-root membership:

- Insert computes a deterministic UTXO ID from output bytes, height, transaction index, and output index at lines 204-218.
- Insert writes the entry and inserts a deterministic leaf value into the SMT at lines 239-255.
- Spend removes by key and deletes the SMT leaf at lines 266-271.
- `root()` returns the SMT root at lines 285-288.

Snapshot encoding does iterate `HashMap` values at lines 137 and 143, but explicitly sorts by `utxo_id` at lines 138 and 144 before encoding. Decode inserts entries in serialized order at lines 151-162; the SMT root remains deterministic because the SMT recompute is order-insensitive.

`all_entries()` at lines 274-278 exposes raw `HashMap` value iteration and is dangerous if used later for consensus logic, but no audited state-root path uses it to produce state.

## Mempool and Block Production
### Finding: FIXED HIGH
`indra-consensus/src/mempool.rs` stores `entries: HashMap<Bytes32, MempoolEntry>` at line 83. The dangerous path is `select_for_block`:

- It collects age-eligible entries from `self.entries.values()` at lines 231-235.
- It sorts only by `fee_rate` descending at line 236.
- It collects remaining entries from `self.entries.values()` at lines 238-242.
- It sorts only by `fee_rate` descending at line 243.
- It concatenates and truncates at lines 245-247.

Because the sort key does not break ties by `tx_id`, equal-fee transactions preserve the input order of `HashMap::values()`. If more equal-fee transactions exist than the block limit, different validators can select different subsets.

`indra-consensus/src/producer.rs` partially canonicalizes after selection: it sorts the selected transactions by `tx.tx_hash()` at line 100 and computes `mempool_set_root` from sorted transaction IDs at lines 155-164. That makes the order of the chosen transactions deterministic, but not the chosen subset. Therefore this is a block-production determinism risk, not a replay risk for already committed blocks.

Other mempool sites:

- Capacity eviction at `mempool.rs` lines 156-167 uses `min_by_key(|(_, e)| e.fee_rate)` with no `tx_id` tiebreaker. If the pool is full and multiple entries have the same lowest fee rate, different nodes can evict different transactions.
- `age_eligible()` at lines 251-255 and `iter()` at lines 263-266 expose raw `HashMap` order. They are safe only if callers do not feed that order into consensus output.

**Fix status:** FIXED. `select_for_block` now sorts age-eligible and remaining entries by `(fee_rate desc, tx_id asc)`. Capacity eviction now chooses by `(fee_rate asc, tx_id desc)`, matching the documented deterministic eviction rule: lowest fee loses, and equal-fee ties evict the highest transaction ID.

## QC Builder (remaining issues)
### Finding: SAFE
Phase 1/Gap fixes changed `QcBuilder.votes` to `BTreeMap<Bytes32, VoteV1>` at `indra-consensus/src/qc.rs` line 57. `QcBuilder::build` passes `self.votes.values()` into QC construction at line 131, so QC signature ordering is now canonical by validator ID.

Remaining `HashMap` and `HashSet` sites in `qc.rs` are lookup-only:

- `by_id: HashMap<Bytes32, &QcValidator>` at lines 154-155 is built from validator metadata and used only for `get()` lookups while iterating the already-canonical vote list at lines 160-180.
- `by_position: HashMap<usize, &QcValidator>` at lines 202-205 is used only for deterministic lookup while iterating the fixed signer bitfield bytes/bits at lines 208-222.
- `seen: HashSet<Bytes32>` at line 250 is duplicate detection only.
- `pq_by_validator: HashMap` at line 251 is populated from QC signatures, then queried by deterministic signer order at lines 266-272. It is not iterated to produce bytes or state.

QC quorum arithmetic is height-gated in `QcBuilder::current_stake_bps` lines 98-102, `QcBuilder::build` lines 115-119, and `verify_qc` lines 237-241.

`indra-consensus/src/vote.rs` also uses deterministic storage: `VoteCollector.received` is `BTreeMap` at line 68, and `stake_by_hash` is a `BTreeMap` at line 188. `accepted_votes()` returns `received.values()` at lines 216-219, so votes handed to QC construction are sorted by validator ID.

## Equal-Stake Tiebreaker
### Finding: SAFE
The active-set selector is in `indra-state/src/validator.rs`:

```rust
candidates.sort_by(|(id_a, stake_a), (id_b, stake_b)| {
    stake_b.cmp(stake_a).then_with(|| id_a.0.cmp(&id_b.0))
});
```

This is at lines 510-512. The primary key is stake descending. Equal stake is broken by `validator_id` bytes ascending. That tiebreaker is deterministic across processes and restarts. The source collection is `self.validators.values()` from a `BTreeMap` at lines 492-508, but even if that source were unordered, the explicit secondary key would canonicalize equal stake.

Therefore the suspected equal-stake root cause for height 9872 is not present in the current code.

## Snapshot Completeness
### Finding: FIXED CRITICAL
The snapshot format is a complete `ChainState` encoding in `indra-storage/src/state_store.rs`: `serialise_chain_state` writes version bytes and `state.encode()` at lines 199-204, while load decodes `ChainState` at lines 252-270.

`ChainState::encode` includes the consensus-critical fields in `indra-state/src/chain.rs` lines 94-129:

| Field | Snapshot? | State root? | Replay relevance |
|------|-----------|-------------|------------------|
| `chain_id` | yes | yes, metadata | signing/root domain |
| `height` | yes | yes, metadata | next block height |
| `tip_hash` | yes | excluded from state root by design | next `prev_hash` validation |
| `base_fee` | yes | yes, metadata | transaction fee validation |
| `total_supply` | yes | yes, metadata and value hash | supply invariant |
| `treasury_balance` | yes | yes, metadata | reward/slash accounting |
| `burn_buffer` | yes | yes, metadata | governance accounting |
| `fee_reward_pool` | yes | yes, metadata | epoch fee distribution |
| `utxos` | yes | yes, UTXO SMT | spend validation |
| `nullifiers` | yes | yes, nullifier SMT | double-spend guard |
| `validators` | yes | yes, validator root | proposer/QC/rewards/liveness |
| `delegations` | yes | yes, validator root | active power/rewards |
| `staked_bonds` | yes | yes, validator root | delegation/unbonding |
| `staking_nonces` | yes | yes, validator root | staking replay protection |
| `applied_slash_hashes` | yes | yes, validator root | slash replay protection |
| `governance` | yes | yes, metadata | governance transitions |
| `epoch_fees_burned` | no | no | epoch summary only |
| `epoch_slashed_spark` | no | no | epoch summary only |
| `epoch_slash_event_count` | no | no | epoch summary only |

The snapshot is mostly complete, but the replay pipeline is incomplete for post-apply consensus mutations. Live block commit calls `import_block` at `indra-node/src/engine.rs` lines 583-591, appends epoch records at lines 592-594, then mutates validator `last_active_epoch` in `update_last_active_epoch_from_block_qc` at lines 595 and 610-628. That field is snapshotted and state-rooted. On restart, `NodeEngine::init` loads a snapshot at lines 113-140 and calls `rebuild_state_from_height`; the rebuild loop applies blocks at lines 690-692 but does not call the QC-derived last-active update.

This means:

- A snapshot taken after live commits includes QC-derived `last_active_epoch` up to the snapshot height.
- Blocks replayed after the snapshot do not reproduce live QC-derived `last_active_epoch` mutations.
- The first replayed block with a non-empty QC can make replayed validator state differ from the originally committed live state.
- Since `last_active_epoch` is encoded in `compute_validator_set_root`, this can cause a state-root mismatch on a later block.

**Fix status:** FIXED. Replay still uses `rebuild_state_from_height` → `apply_block`, but `apply_block` now contains the QC signer liveness update. Snapshot restore tests now verify `last_active_epoch` and the full state root are identical across apply/replay/encode/decode paths.

Additional snapshot notes:

- `pending_rewards` is included in `ValidatorEntry::encode` and in validator root (`validator.rs` lines 137 and `state_root.rs` line 60).
- `last_active_epoch` is included (`validator.rs` line 136 and `state_root.rs` line 62).
- `auto_delegate_to` is included (`validator.rs` lines 142-145 and `state_root.rs` lines 67-70).
- `governance.queued_executions` is included (`governance.rs` lines 679-680 and encoded at line 726).
- Epoch record history is stored separately in `EpochStore`, not in `ChainState`. It is not used by the audited state-root path.

## Timestamp Non-Determinism
### Finding: SAFE
`apply_block(state, block, timestamp_secs)` receives a timestamp at `indra-state/src/apply.rs` lines 265-269. It passes this timestamp to `apply_epoch_transition_at_height` only when the block is an epoch boundary at lines 395-403.

`apply_epoch_transition_at_height` receives `timestamp_secs` at `indra-state/src/epoch.rs` lines 69-74 and stores it only in the returned `EpochRecord` at line 157. The timestamp is not written into `ChainState`, and `EpochRecord` is not included in `compute_state_root`.

Live import passes wall-clock time through `NodeEngine::commit_block` at `indra-node/src/engine.rs` lines 583-591, then appends the returned `EpochRecord` to `EpochStore` at lines 592-594. Replay passes `0` at `engine.rs` line 692. This can make epoch-history files differ between live operation and replay, but based on the audited code it does not affect `ChainState` or state root.

Operational caveat: if future consensus or state-root logic reads `EpochStore` or `EpochRecord.timestamp_secs`, this becomes dangerous immediately. Block headers also have `header.timestamp`, but `apply_block` does not currently use it for state mutation.

## Complete HashMap Inventory
| File | Line | Type | Classification | Reasoning |
|------|------|------|----------------|-----------|
| `indra-state/src/smt.rs` | 37 | `HashMap<[u8;32],[u8;32]>` leaves | SAFE | Iterated during recompute, but entries are placed by deterministic key; root fetched by fixed root key. |
| `indra-state/src/smt.rs` | 38 | `HashMap<NodeLoc,[u8;32]>` nodes | SAFE | Lookup/proof cache and rebuilt from deterministic levels; root is key lookup, not fold order. |
| `indra-state/src/smt.rs` | 124 | `Vec<HashMap<NodeLoc,[u8;32]>>` levels | SAFE | Intermediate maps keyed by deterministic node locations; iteration order does not alter parent hash values. |
| `indra-state/src/smt.rs` | 144 | `HashMap<NodeLoc,(Option<[u8;32]>,Option<[u8;32]>)>` grouped | SAFE | Parent entries are keyed by `NodeLoc`; left/right chosen by key bit, not encounter order. |
| `indra-state/src/utxo.rs` | 123 | `HashMap<Bytes32,UtxoEntry>` | SAFE | Snapshot encoding sorts by `utxo_id`; SMT root is order-insensitive; raw `all_entries()` should not be used in consensus. |
| `indra-state/src/nullifier.rs` | 32 | `HashSet<Bytes32>` | SAFE | Snapshot encoding sorts; SMT root is order-insensitive; membership only in apply path. |
| `indra-state/src/chain.rs` | 76 | `HashSet<Bytes32>` applied slash hashes | SAFE | Encoded by collecting and sorting at lines 278-284; state-root leaves sorted in `state_root.rs`. |
| `indra-state/src/epoch.rs` | 84 | `HashSet<Bytes32>` active_before | SAFE | Used for set difference only; resulting vectors are sorted before inclusion in `EpochRecord`. |
| `indra-state/src/epoch.rs` | 139 | `HashSet<Bytes32>` active_after_set | SAFE | Used for set difference only; `validators_joined` and `validators_left` are sorted at lines 144 and 149. |
| `indra-state/src/apply.rs` | 287 | `HashSet<Bytes32>` seen slash hashes | SAFE | Duplicate detection only; not iterated to produce state. |
| `indra-state/src/apply.rs` | 297 | `HashSet<Vec<u8>>` seen tx hashes | SAFE | Duplicate detection only; not iterated to produce state. |
| `indra-state/src/apply.rs` | 308 | `HashSet<Bytes32>` block nullifiers | SAFE | Duplicate detection during transaction validation; not iterated to produce state. |
| `indra-consensus/src/mempool.rs` | 83 | `HashMap<Bytes32,MempoolEntry>` | FIXED HIGH | `select_for_block` and capacity eviction previously sorted only by fee rate; equal-fee ties now use deterministic `tx_id` tiebreakers. |
| `indra-consensus/src/mempool.rs` | 209 | `HashSet<Bytes32>` block_nullifiers in `evict_invalid` | SAFE | Per-entry validation scratch set; not iterated for output. |
| `indra-consensus/src/qc.rs` | 154 | `HashMap<Bytes32,&QcValidator>` | SAFE | Lookup by validator ID while iterating canonical votes; not iterated for QC output. |
| `indra-consensus/src/qc.rs` | 202 | `HashMap<usize,&QcValidator>` | SAFE | Lookup by fixed bitfield positions; output order follows bitfield order. |
| `indra-consensus/src/qc.rs` | 250 | `HashSet<Bytes32>` seen signatures | SAFE | Duplicate detection only. |
| `indra-consensus/src/qc.rs` | 251 | `HashMap<Bytes32,&PQVoteSig>` | SAFE | Lookup by validator ID while iterating deterministic signer list; not iterated for output. |
| `indra-consensus/src/vote.rs` | 68 | `BTreeMap<Bytes32,(VoteV1,u64)>` | SAFE | Deterministic replacement for vote collection; accepted votes sorted by validator ID. |
| `indra-consensus/src/vote.rs` | 188 | `BTreeMap<Bytes32,u64>` | SAFE | Deterministic block-hash stake aggregation. |
| `indra-storage/src/state_store.rs` | 150 | `Vec<(u64,PathBuf)>` with directory iteration | SAFE | Directory entries are sorted by height before latest snapshot selection. |
| `indra-state/src/apply.rs` | end of `apply_block` | iterates `qc.pq_signatures` | FIXED CRITICAL | QC signer liveness is now inside canonical `apply_block`, so live, sync, projection, and replay paths execute the same mutation. |

## Ranked Findings (by severity)
1. **FIXED CRITICAL — Live/replay mismatch for `last_active_epoch` from QC signatures.** The QC-derived mutation now occurs inside `apply_block`.
2. **FIXED HIGH — Mempool equal-fee selection and eviction lacked deterministic tiebreakers.** Selection and eviction now use explicit `tx_id` tie rules.
3. **LOW — SMT uses `HashMap` internally.** Current implementation is order-insensitive and tested, but future maintenance could accidentally introduce order-dependent folding.
4. **LOW — `timestamp_secs` differs live vs replay but currently only affects `EpochRecord`.** Safe for state root today, dangerous if epoch records become consensus inputs.

## Recommended Fix Order
1. **Completed:** QC-derived `last_active_epoch` updates were moved into canonical `apply_block`.
2. **Completed:** Replay/snapshot regression coverage verifies identical `last_active_epoch` and full state roots.
3. **Completed:** Mempool selection and eviction now use explicit `tx_id` tiebreakers.
4. Keep QC construction on `BTreeMap` and retain the QC encoding-order regression test with votes inserted in different orders.
5. Add an SMT order-independence property test with a larger randomized insertion/deletion corpus to protect against future internal refactors.
6. Keep `timestamp_secs` out of consensus state unless block timestamp semantics are explicitly designed and replay uses committed block timestamps rather than wall-clock time.
