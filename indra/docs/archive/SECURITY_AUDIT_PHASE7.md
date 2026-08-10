> **Historical archive:** This records completed audit work and intermediate designs. It is not current guidance; canonical specifications and current code take precedence.

# INDRA Security Audit — Phase 7: Storage and State Integrity

## Summary Table

| ID | Component | Finding | Severity | Status |
|----|-----------|---------|----------|--------|
| ST7-01 | Persistence | State file enumeration and format | INFO | DOCUMENTED |
| ST7-02 | Persistence | Startup restoration consistency gaps | HIGH | FIXED |
| ST7-03 | Persistence | Snapshots are now sidecar-verified; legacy fallback warns | HIGH | FIXED |
| ST7-04 | Block store | Block log entries now carry CRC32 and retained heights are contiguous-checked | MEDIUM | FIXED |
| ST7-05 | Block store | Snapshot/block-log tip consistency enforced at startup | HIGH | FIXED |
| ST7-06 | Block store | Sync import verifies QC, parent, proposer and state roots before mutation | SAFE | VERIFIED |
| ST7-07 | Pruning | Pruning policy and scope are explicit | SAFE | VERIFIED |
| ST7-08 | Pruning | Pruned BlockResponse messages now advertise retained availability range | MEDIUM | FIXED |
| ST7-09 | Pruning | Slash evidence does not depend on retained block bodies | SAFE | VERIFIED |
| ST7-10 | Atomicity | Prune rewrite and critical replacements are fsync/rename hardened | HIGH | FIXED |
| ST7-11 | Atomicity | Durable chain manifest added for component consistency checks | HIGH | FIXED |
| ST7-12 | Atomicity | Corrupt vote_safety.dat and write failures now fail closed | HIGH | FIXED |
| ST7-13 | Replay | Deterministic state mutation is mostly centralized in apply_block | SAFE | VERIFIED |
| ST7-14 | Replay | Startup replay verifies state-root / validator-root / value-hash | HIGH | FIXED |
| ST7-15 | Replay | Epoch boundary state transition is deterministic; records are auxiliary | SAFE | VERIFIED |
| ST7-16 | Replay | Previously live-only state updates are now inside apply_block; auxiliary files remain recoverable | SAFE | VERIFIED |

## Fix Status Update — Phase 7 Findings

Implemented after this audit:

- ST7-12: `vote_safety.dat` now distinguishes `NoRecord`, valid records, and corrupt records. Corrupt records fail closed, and vote-safety persistence failure prevents vote broadcast.
- ST7-14: startup replay now reuses the same header commitment verification as sync import before applying stored blocks.
- ST7-02/ST7-03/ST7-05: snapshots now write sidecar metadata containing tip hash, state root, validator-set root, chain ID, and snapshot checksum; startup verifies retained block hash against snapshot tip when available.
- ST7-10/ST7-11: block pruning now rewrites through a synced temp file and atomic rename; consensus-critical replacements use synced temp+rename; a durable chain manifest records committed height, block hash, roots, snapshot height, block log tip, last QC height, epoch log tip, and chain ID. Missing sidecars/manifests are accepted as legacy with warnings for backward compatibility.
- ST7-04: `blocks.log` now uses v2 entries containing `u64 height || u32 len || block bytes || u32 crc32`. The CRC covers the height, length, and block bytes. Legacy headerless/v1 logs are read and atomically upgraded to v2 on open; retained heights are checked for gaps during index rebuild.
- ST7-08: `BlockResponse` now includes optional trailing `lowest_available` / `highest_available` metadata. Old decoders ignore the trailing fields, making this rolling-upgrade compatible; new peers can distinguish pruned history from a temporary empty response.

Breaking-change status: no consensus rule, state schema, or key material changes. New snapshot sidecar and chain manifest files are backward compatible; old storage without them starts with warnings and writes the new files after subsequent commits/snapshots. ST7-04 is an on-disk `blocks.log` format upgrade, but it is backward compatible because legacy logs auto-upgrade on open. ST7-08 is a network message extension, but rolling restart is safe because the new availability fields are optional trailing bytes ignored by old decoders.

## Detailed Findings

### ST7-01 — State file enumeration and format

Severity: INFO  
Status: DOCUMENTED

The storage crate currently uses flat files, not a transactional database. The persisted files found in `indra-storage/src/` and the node startup paths are:

| File | Owner | Format | Write pattern | Integrity handling |
|---|---|---|---|---|
| `blocks.log` | `BlockStore` | `INBK` header, then repeated `u64 height || u32 len || BlockV1 bytes` | append + `flush`; pruning rewrites in place | detects incomplete final entry; no checksum/hash per entry |
| `state_<height>.snap` | `StateStore` | `u64 height || u32 len || versioned ChainState bytes` | temp file + rename + cleanup | decode/schema/height checks only |
| `last_qc.bin` | `qc_store` | raw QC bytes | temp file + rename | decoded and height-checked by driver on restore |
| `vote_safety.dat` | `VoteSafetyStore` | 17-byte `(height, round, step, crc32)` | temp file + rename | CRC mismatch returns `None` |
| `epochs.log` | `EpochStore` | `INEP` header, then repeated `u64 epoch || u32 len || EpochRecord bytes` | append + `flush` | detects incomplete final entry; no checksum per entry |
| mempool WAL | `MempoolWal` | repeated `tag || len || payload || crc32` | append + `flush`; compaction truncates | CRC guards each entry |
| migration log | `MigrationLog` | fixed 26-byte records | append + `flush` | length multiple check only |
| `peers.json` | node discovery | JSON peer list | outside `indra-storage` | capped/validated by network fixes, not consensus-critical |

Code evidence:

- `indra-storage/src/block_store.rs:132-160` appends block entries.
- `indra-storage/src/state_store.rs:51-68` writes snapshots via temp+rename.
- `indra-storage/src/qc_store.rs:15-20` writes `last_qc.bin` via temp+rename.
- `indra-storage/src/vote_safety.rs:38-48` writes the 17-byte vote safety file.
- `indra-storage/src/epoch_store.rs:59-78` appends epoch records.
- `indra-storage/src/wal.rs:151-160` appends mempool WAL entries.

Recommended fix: none for enumeration; use this table as the baseline for the follow-up storage hardening task.

### ST7-02 — Startup restoration consistency gaps

Severity: HIGH  
Status: FIXED

Startup restoration loads the latest snapshot, computes `replay_start = snapshot.height + 1`, and replays blocks from that height through `block_store.next_height()` (`indra-node/src/engine.rs:117-144`, `indra-node/src/engine.rs:707-735`). It checks one important pruned-log gap: if the retained block log starts after the replay start, startup fails with `SnapshotReplayGap` (`indra-node/src/engine.rs:129-136`).

However, startup does not verify that the snapshot is anchored to a locally retained block at `snapshot.height`, nor that `snapshot.tip_hash` equals that block's `block_hash()`. A snapshot at height `N` can be accepted even if `blocks.log` only contains blocks through `N-1`; the replay range is empty and the node starts at height `N` with no local block `N` to serve or prove. This is the exact multi-file consistency failure described in the audit prompt.

Attack/failure scenario:

1. Snapshot `state_300.snap` exists and decodes successfully.
2. `blocks.log` is truncated or restored from an older backup and only contains blocks through 299.
3. Startup loads the snapshot, sets `replay_start = 301`, sees no replay gap because the block log is not ahead of the snapshot, and starts at height 300.
4. The node cannot serve block 300 to peers, and no local check proves that the snapshot state corresponds to the canonical block 300.

Recommended fix:

- On startup, if a snapshot at height `H > 0` is loaded and the block log is non-empty, require that block `H` is present unless the node is explicitly in a checkpoint-only/pruned mode with a signed checkpoint.
- Verify `snapshot.tip_hash == block_store.get(H).header.block_hash()`.
- If block `H` is pruned, require a signed checkpoint record containing height, block hash, state root, validator-set root, and chain_id.

### ST7-03 — Snapshots are not cryptographically/checkpoint verified

Severity: HIGH  
Status: FIXED

`StateStore::load_latest` picks the highest `state_*.snap`, reads its length, decodes the payload, and calls `validate_snapshot_state` (`indra-storage/src/state_store.rs:77-107`, `indra-storage/src/state_store.rs:302-312`). The validation only checks that `state.height == file_height`. It does not verify:

- `compute_state_root(snapshot)` against a trusted block header or checkpoint,
- `compute_validator_set_root(snapshot)` against a trusted block header,
- `snapshot.tip_hash` against the block at the same height,
- a cryptographic checksum/MAC/signature over the snapshot file.

This means a locally corrupted but decodable latest snapshot at the current tip can be silently trusted. Later replay may catch inconsistencies only if there are newer blocks whose `prev_hash` no longer matches the corrupted snapshot's `tip_hash`; if the snapshot is the latest state, no such check runs.

Recommended fix:

- Store a checkpoint sidecar for every snapshot: `height`, `block_hash`, `state_root`, `validator_set_root`, `chain_id`, and a checksum.
- On load, recompute the snapshot roots and require them to match the sidecar and the corresponding block header/checkpoint.
- If the latest snapshot fails verification, fall back to the previous verified snapshot plus replay instead of trusting or deleting state.

### ST7-04 — Block log lacks per-entry integrity checks and strict replay indexing

Severity: MEDIUM  
Status: FIXED

`BlockStore` now writes v2 entries as `u64 height || u32 len || BlockV1 bytes || u32 crc32`. The CRC covers the height, length, and payload, so full-length local corruption is detected before the block is trusted. The read path and index rebuild both verify CRCs for v2 entries.

Index rebuild also decodes each retained block, verifies that the stored entry height matches the decoded block header height, and rejects any gap inside the retained range with `StorageError::BlockLogGap`.

Compatibility:

- New logs are written as v2.
- Existing headerless/v1 logs are read and atomically rewritten to v2 on open.
- Startup/open logs the verified retained height range and whether checksums are available/valid.

### ST7-05 — Snapshot/block-log tip consistency is not enforced at startup

Severity: HIGH  
Status: FIXED

This is the concrete multi-file version of ST7-02. The import path writes several files in sequence:

1. `import_block` verifies and applies the block to in-memory state, appends the block, then snapshots at interval (`indra-node/src/sync.rs:228-255`).
2. `NodeEngine::commit_block` appends the epoch record after import returns (`indra-node/src/engine.rs:642-653`).
3. The driver persists `last_qc.bin` after `commit_block` succeeds (`indra-node/src/driver.rs:1248-1258`).

There is no manifest or commit marker tying `blocks.log`, `state_*.snap`, `epochs.log`, and `last_qc.bin` together. The stale-QC fix makes `last_qc.bin` recoverable, but block/state consistency is still inferred rather than explicitly checked.

Recommended fix:

- Introduce a durable commit manifest such as `chain_manifest.json`/binary containing the last fully committed height, block hash, state root, snapshot height, block log `next_height`, last QC height, and epoch log latest epoch.
- Write it last, using temp+rename+fsync, only after all component files are durable.
- Startup should validate component files against the manifest and either roll forward/replay or fail closed with an actionable error.

### ST7-06 — Sync import verifies QC, parent, proposer and state roots before mutation

Severity: SAFE  
Status: VERIFIED

The network sync/import path is substantially stronger than startup replay. `import_block` verifies the proposer VRF, embedded QC, and projected state roots before mutating the real state (`indra-node/src/sync.rs:220-228`). `verify_block_qc` checks the QC height and, after the CS-01/CS-12 fix, that `qc.block_hash == block.header.prev_hash` (`indra-node/src/sync.rs:355-430`). `verify_block_state_root` applies the block to a clone first and compares state root, validator-set root, and value hash (`indra-node/src/sync.rs:433-486`).

The `BlockResponse` path calls `d.engine.commit_block(&block)` for each next-height block (`indra-node/src/bin/node.rs:1510-1517`), so sync import uses the same validation pipeline.

Recommended fix: none for sync import itself. Reuse this validation path for startup replay.

### ST7-07 — Pruning policy and scope are explicit

Severity: SAFE  
Status: VERIFIED

Pruning applies to block bodies in `blocks.log`, not consensus state. `DEFAULT_PRUNE_KEEP_BLOCKS = 50_000` and `MIN_PRUNE_KEEP_BLOCKS = 1_000` are defined in `indra-core/src/types/primitives.rs:360-363`. Configuration normalizes `0` to archive mode and floors nonzero values at the minimum. `NodeEngine::init` asserts `prune_keep_blocks > 2 * snapshot_interval`, which protects normal snapshot-based restarts (`indra-node/src/engine.rs:90-97`).

Recommended fix: keep the policy, but address ST7-08/ST7-10 before relying on pruned mode for unattended validators.

### ST7-08 — Pruned nodes cannot serve far-behind peers; responses are silent partials

Severity: MEDIUM  
Status: FIXED

When a peer requests blocks below a pruned node's retained floor, the serving code now returns a `BlockResponse` with optional `lowest_available` and `highest_available` metadata. It starts serving from the retained floor when the requested range overlaps retained history, and returns an empty response with availability metadata when the requested range is fully below the floor.

This fixes the liveness ambiguity:

- A far-behind validator can distinguish pruned history from a temporarily empty/misbehaving peer.
- Requesters can skip this peer for historical ranges below `lowest_available` and try an archive/sufficiently retained peer.
- Normal in-range requests still return blocks without metadata.

Compatibility:

- The new fields are optional trailing bytes after the existing `BlockResponse` block vector.
- Existing decoders ignore trailing bytes, so rolling restarts are safe.
- All nodes should still be updated before relying on the metadata operationally.

### ST7-09 — Slash evidence does not depend on retained block bodies

Severity: SAFE  
Status: VERIFIED

Slash evidence verification uses the two signed votes and the validator's registered hybrid keys (`indra-state/src/apply.rs:80-133`). The evidence window is based on vote height and current application height (`indra-state/src/apply.rs:150-158`). It does not need the historical block body at the infraction height.

The important retained state is the validator registry and applied slash hashes, both committed in `ChainState` and included in state roots (`indra-state/src/state_root.rs:43-83`, `indra-state/src/state_root.rs:117-125`). Block pruning does not by itself prevent slash evidence within `SLASH_EVIDENCE_WINDOW_EPOCHS`.

Recommended fix: none for block pruning. Continue keeping validator records and `applied_slash_hashes` in consensus state.

### ST7-10 — Append logs and prune rewrite are not fsync/rename atomic

Severity: HIGH  
Status: FIXED

The crate-level invariant says “All writes are atomic at the OS level (write then rename)” (`indra-storage/src/lib.rs:27-31`), but that does not hold for the append logs:

- `BlockStore::append` writes directly to the log and calls `flush()`, not `sync_all()` (`indra-storage/src/block_store.rs:147-151`).
- `EpochStore::append` does the same (`indra-storage/src/epoch_store.rs:71-74`).
- `MempoolWal::write_entry` does the same (`indra-storage/src/wal.rs:155-159`).
- `MigrationLog::append` does the same (`indra-storage/src/migration.rs:48-58`).

More importantly, block pruning rewrites `blocks.log` in place: it reads the kept suffix, truncates the file to the header, writes the kept bytes, and flushes (`indra-storage/src/block_store.rs:249-258`). A crash during this window can destroy both old and new block-log contents.

Recommended fix:

- Replace in-place prune with write-new-file + fsync + atomic rename + directory fsync.
- Add `sync_all()`/directory fsync to consensus-critical file commits (`blocks.log`, snapshots, `last_qc.bin`, `vote_safety.dat`) or explicitly document weaker durability.
- Update the storage crate invariant comments to distinguish append recovery from atomic replacement.

### ST7-11 — Multi-file commit is not transactionally coordinated

Severity: HIGH  
Status: FIXED

Consensus commit spans `blocks.log`, snapshot files, `epochs.log`, `last_qc.bin`, and `vote_safety.dat`, but there is no multi-file transaction. The current order is good enough for many ordinary crashes, but not all:

- A block can be appended without its epoch record.
- A snapshot can exist without a manifest proving which block log tip it belongs to.
- A recovered QC can be stale/missing and is repaired by protocol recovery, but the same manifest concept is missing for state/block/epoch consistency.

Failure scenario:

1. Block at an epoch boundary is imported and state mutates.
2. `blocks.log` append succeeds and a snapshot may be written.
3. Crash occurs before `epoch_store.append`.
4. Consensus state is correct, but epoch history/RPC accounting is incomplete.

Recommended fix:

- Add a commit manifest as described in ST7-05.
- Treat epoch records as derived from blocks/state and rebuild missing epoch records during startup, or include them in the same durable commit manifest.
- Add crash-recovery tests that interrupt after each write step and assert startup either recovers or fails closed.

### ST7-12 — Corrupt/missing vote_safety.dat fails open

Severity: HIGH  
Status: FIXED

`VoteSafetyStore::load` returns `None` if the file is missing, has the wrong length, or fails CRC validation (`indra-storage/src/vote_safety.rs:51-75`). `ConsensusDriver::apply_vote_safety` only skips rounds when `load()` returns a record; otherwise it proceeds normally (`indra-node/src/driver.rs:449-460`).

This is dangerous for validator safety. If a validator signs a vote, crashes, and loses/corrupts `vote_safety.dat`, restart can proceed as if no vote was ever cast and may sign a conflicting vote at the same height/round/step. The driver also logs persistence errors but still signs and records the vote locally (`indra-node/src/driver.rs:791-805`), so a write failure does not fail closed.

Recommended fix:

- Make vote safety persistence a hard precondition: if `record()` fails, do not sign/broadcast the vote.
- On corrupt `vote_safety.dat`, refuse to vote until operator recovery or block height advancement proves the old record irrelevant.
- Consider a small append-only vote-safety log rather than single-record replacement, so the highest durable vote can be recovered after partial writes.

### ST7-13 — Deterministic state mutation is mostly centralized in apply_block

Severity: SAFE  
Status: VERIFIED

The main state transition runs through `apply_block`, which clones state, applies the whole block to scratch, and only commits the scratch on success (`indra-state/src/apply.rs:314-328`). Transactions, staking ops, governance ops, slash evidence, base fee, height/tip hash, epoch transitions, and QC signer liveness all mutate through this path (`indra-state/src/apply.rs:328-489`).

This is a strong property: live import, sync import, block-production projection, and block replay all call the same state transition function.

Recommended fix: none for mutation centralization.

### ST7-14 — Startup replay skips state-root / validator-root / value-hash verification

Severity: HIGH  
Status: FIXED

`rebuild_state_from_height` replays blocks with `indra_state::apply_block(state, &block, 0)` (`indra-node/src/engine.rs:731-733`). It does not call `verify_block_state_root`, and that helper is private to `sync.rs`.

As a result, startup replay checks basic block-header continuity inside `apply_block` (`indra-state/src/apply.rs:520-543`) but does not verify that the recomputed post-state matches:

- `block.header.state_root`,
- `block.header.validator_set_root`,
- `block.header.value_hash`.

By contrast, sync import verifies all three before mutation (`indra-node/src/sync.rs:433-486`). A locally corrupted but decodable block in `blocks.log` can therefore replay to a state that differs from the state committed in the block header, and startup will not catch it unless another later check happens to fail.

Recommended fix:

- Expose a replay-safe verification function that performs the same projected root checks as sync import.
- Use it in `rebuild_state_from_height` before applying each block.
- Add a regression test: corrupt a stored block transaction while preserving height/prev_hash; startup replay must reject due to state-root mismatch.

### ST7-15 — Epoch boundary state transition is deterministic; records are auxiliary

Severity: SAFE  
Status: VERIFIED

Epoch transitions explicitly keep wall-clock timestamps out of consensus state. `timestamp_secs` is stored only in `EpochRecord`, while ChainState mutations are derived from height/epoch and deterministic state (`indra-state/src/epoch.rs:69-85`). The transition includes governance phase changes, active-set selection, reward distribution, unbonding release, liveness penalties, and record creation (`indra-state/src/epoch.rs:86-170`).

`EpochRecord` persistence can be incomplete after a crash (ST7-11), but that affects historical reporting, not the consensus state root, because the record itself is not part of `ChainState`.

Recommended fix: rebuild or repair missing epoch records from replay, but no consensus safety fix is required for deterministic state mutation.

### ST7-16 — Live-only state fields are now inside apply_block; auxiliary files remain recoverable

Severity: SAFE  
Status: VERIFIED

The prior determinism class (“live path mutates state, replay path does not”) appears fixed for the major consensus-visible field reviewed here. `update_last_active_epoch_from_block_qc` is inside `apply_block`, with comments explicitly stating this keeps live import, sync import, replay, and production projection identical (`indra-state/src/apply.rs:489-517`).

`last_qc.bin` remains an auxiliary proposal-enablement file, not part of the state root. The stale-QC fix validates restored QC height and clears/recovers stale QCs during sync import; this is appropriate because QC bytes are recoverable from peers and should not define canonical state.

Recommended fix: none for known live-only consensus fields. Keep future state additions inside `apply_block` and state-root computation.

## Proof-of-Concept Tests

No executable PoC tests were added in this audit pass because the task is audit-only and requested zero code changes. The following tests should be added in the follow-up fix tasks for the HIGH findings:

1. `startup_rejects_snapshot_height_newer_than_block_log_tip` — create `state_300.snap` with `blocks.log` through 299; startup must fail closed.
2. `startup_rejects_snapshot_tip_hash_mismatch` — snapshot height matches a retained block height but `snapshot.tip_hash` differs from the retained block hash.
3. `startup_replay_verifies_state_root` — corrupt a stored block payload so `apply_block` succeeds but recomputed state root differs; startup must reject.
4. `vote_safety_corruption_disables_voting` — corrupt `vote_safety.dat`; driver must refuse to sign until safe recovery.
5. `block_prune_crash_recovery_preserves_kept_suffix` — simulate crash during prune rewrite; startup must either recover from a temp file or fail without destroying the retained range.
6. `request_blocks_reports_pruned_range` — request below `lowest_height`; response must explicitly identify the pruned lower bound.

## Findings NOT Present

- Sync `BlockResponse` import verifies proposer VRF, embedded QC height, embedded QC parent hash, QC signatures/quorum, state root, validator-set root, and value hash before applying a block.
- Block application uses scratch-clone atomicity; failed transaction/staking/governance/slash/epoch validation leaves the caller's state unchanged.
- Epoch transition does not use wall-clock time for consensus state.
- Slash evidence verification does not require pruned block bodies.
- `last_qc.bin` is height-validated/restored defensively and is recoverable through QC request/response.

## Recommended Fix Order

1. ST7-12 — Make vote safety fail closed on persistence/read corruption. This is the only finding with direct double-vote safety risk.
2. ST7-14 — Reuse sync root verification during startup replay.
3. ST7-02/ST7-03/ST7-05 — Add snapshot checkpoint/manifest validation tying snapshots to block hashes and state roots.
4. ST7-10/ST7-11 — Add durable atomic file/manifest writes and safe prune rewrite.
5. ST7-04 — FIXED: block log v2 CRC entries and strict contiguous-index verification.
6. ST7-08 — FIXED: explicit retained-range metadata in pruned `BlockResponse`s.
