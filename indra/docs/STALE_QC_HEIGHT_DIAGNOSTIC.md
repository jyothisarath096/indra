# INDRA Stale Embedded QC Height Diagnostic

Status: **FIXED locally, pending review/deploy approval.** The fix makes `last_qc_bytes` height-aware, clears stale cached QC bytes after sync imports, requests a fresh QC for the new tip, rejects malformed embedded-QC proposals at intake before voting, and validates persisted `last_qc.bin` height on driver startup.

## Executive Summary

Root cause found with high confidence: `ConsensusDriver.last_qc_bytes` is updated when a block is finalized through the live precommit-quorum path, but it is not updated or invalidated when the node imports blocks through the sync `BlockResponse` path. A node that sync-imports height `H-1` can therefore have `engine.state.height == H-1` while `last_qc_bytes` still contains the QC for height `H-2`. If that node later wins proposer election for height `H`, `NodeEngine::propose` / `repropose` embeds that stale byte blob unchanged. Validators then vote for the malformed proposal because proposal staging does not verify embedded QC linkage; all validators only discover the stale QC during finalization/import, producing the synchronized log: `embedded QC height H-2 does not match expected H-1`.

## Reproducing Pattern

The reported failures all match the same exact one-height lag:

- Height 208 embeds QC height 206, expected 207.
- Height 261 embeds QC height 259, expected 260.
- Height 301 embeds QC height 299, expected 300.

That pattern is precisely what happens when `last_qc_bytes` remains the QC for the previously committed tip before a one-block sync import. It is not random corruption, not epoch-boundary related, and not consistent with a multi-height replay bug.

Recovery behavior is also consistent with this diagnosis:

- If a stale-QC node wins a proposer slot, the network can form precommits for an invalid proposal and then fail finalization in lockstep.
- If a different validator with fresh `last_qc_bytes` wins a later round, the chain can self-recover.
- If the stale node wins repeatedly, or if multiple validators have become stale via sync import, recovery time can stretch dramatically.

I could not quantify the exact recovery duration for heights 208/261/301 or correlate with restarts from this workspace alone. There are no validator journal exports or log files in the repository, and `indra-data/blocks.log` is empty. The height-301 multi-validator timeline requires the four node journals around the incident.

## Step 1 — last_qc_bytes Read Sites

### `ConsensusDriver::last_qc_bytes`

Location: `indra-node/src/driver.rs:296-298`

```rust
pub fn last_qc_bytes(&self) -> Vec<u8> {
    self.last_qc_bytes.clone()
}
```

This accessor returns raw bytes only. It has no height metadata and cannot tell whether the bytes certify the current committed tip.

### Consensus proposal loop

Location: `indra-node/src/bin/node.rs:1504-1522`

Both normal proposal and reproposal read the same accessor:

- Reproposal passes `d.last_qc_bytes()` to `d.engine.repropose(...)`.
- Fresh proposal passes `d.last_qc_bytes()` to `d.engine.propose(...)`.

The read occurs while holding the `ConsensusDriver` mutex, so this is not a data race between simultaneous Rust threads mutating the same field. The risk is logical staleness: the field can already be stale relative to `engine.state.height`.

### `NodeEngine::propose`

Location: `indra-node/src/engine.rs:400-435`

`propose` accepts `prev_qc_bytes: Vec<u8>`, checks only that it is non-empty above height 1, and passes it into `BlockTemplate.prev_qc_bytes`. It does not decode the QC or verify `qc.height == proposal_height - 1`.

### `NodeEngine::repropose`

Location: `indra-node/src/engine.rs:447-515`

`repropose` behaves the same way: it accepts raw `last_qc` bytes, checks only non-emptiness above height 1, wraps them into the block header, and does not verify QC height linkage before returning the block.

### `handle_qc_request`

Location: `indra-node/src/driver.rs:1327-1334`

When a peer asks for a QC at the local committed height, this handler serves `self.last_qc_bytes.clone()`. If the local field is stale but non-empty, the node can serve a stale QC response as if it certified the current tip. For `height == local_height - 1`, the handler serves the QC embedded in the current block header, which certifies the previous height; that path is internally consistent.

## Step 2 — last_qc_bytes Write Sites

### Driver initialization from disk

Location: `indra-node/src/driver.rs:247-257`

On startup, the driver loads persisted QC bytes and only checks that they decode. It logs the current state height, but it does not check that the decoded `qc.height` equals `driver.engine.state.height`.

This is a restart risk: if `last_qc.bin` survives with bytes for an older height while the block store/state is ahead, startup can restore stale-but-decodable bytes. That said, the repeated `H-2` pattern during live operation is more directly explained by sync import, below.

### Live consensus finalization

Location: `indra-node/src/driver.rs:1166-1204`

This path is correct. `finalize_block_on_quorum` builds a QC for the block being finalized, commits the block, then stores:

```rust
self.last_qc_bytes = qc.encode_to_vec();
indra_storage::save_last_qc(&self.engine.config.state_dir(), &self.last_qc_bytes)
```

When height advances through this path, `last_qc_bytes` certifies the new tip height.

### QC recovery response

Location: `indra-node/src/driver.rs:1372-1418`

This path is correct when it is actually used. It only accepts a QC response if:

- response `height == self.engine.state.height`;
- `self.last_qc_bytes` is empty;
- decoded `qc.height == height`;
- `verify_qc` succeeds.

The flaw is that stale non-empty bytes suppress this path. `request_qc_if_needed` only requests recovery when `last_qc_bytes.is_empty()`, not when it is non-empty but certifies the wrong height.

### Sync `BlockResponse` import

Location: `indra-node/src/bin/node.rs:1157-1228`

This is the critical gap. The sync loop imports blocks with:

```rust
d.engine.commit_block(&block)
```

and then updates sync/round state:

```rust
d.refresh_registered_voters();
d.sync_mut().on_block_imported(block.header.height);
d.reset_round();
```

It does not build, recover, clear, validate, or update `d.last_qc_bytes`.

If the node was at height `H-2` with `last_qc_bytes = QC(H-2)`, receives/imports block `H-1` via `BlockResponse`, and then proposes height `H`, the proposal will embed `QC(H-2)`. That exactly matches the observed `embedded QC height H-2 does not match expected H-1`.

### Persistent store

Location: `indra-storage/src/qc_store.rs:15-31`

The storage layer atomically saves/loads raw bytes only. It stores no sidecar height, so callers must decode and compare the QC height against the current state height. Driver initialization currently decodes but does not perform the height comparison.

## Step 3 — Concurrency Analysis

The leading “read before update” race hypothesis is not the best explanation.

Evidence against a raw thread race:

- Proposal creation obtains the `ConsensusDriver` mutex and reads `d.last_qc_bytes()` while holding it.
- Live finalization also updates `self.last_qc_bytes` while holding the same driver lock.
- `NodeEngine::propose` / `repropose` are called synchronously inside that locked section.

So a proposal cannot interleave halfway through `finalize_block_on_quorum` and read the field before the assignment on the same driver instance.

The actual race-like behavior is higher-level and event-order dependent:

1. A node is one block behind and enters sync download.
2. It imports the missing block through the sync path, advancing `engine.state.height`.
3. That path leaves `last_qc_bytes` at the old tip's QC.
4. The node returns to caught-up consensus and may propose the next height before any QC recovery occurs.

This is deterministic once that event order occurs; it only appears intermittent because not every node sync-imports right before becoming proposer.

## Step 4 — Round-Timeout Retry Path Analysis

There is no evidence of a cached QC captured once at the beginning of a height and reused across all round attempts. The consensus loop re-enters the proposal block each round and calls `d.last_qc_bytes()` fresh for both proposal modes.

However, because the field itself remains stale until explicitly replaced, “fresh read” still returns stale bytes. Round timeouts therefore do not cause the stale QC directly; they expose it repeatedly when a stale node keeps winning proposer slots.

There is a second availability amplifier: `process_block_internal` validates proposer VRF and applies the block to a projected state, but it does not call `verify_block_qc` before staging/voting for the proposal. Because `apply_block` does not verify embedded QC linkage, validators can prevote/precommit a block whose embedded QC is stale. The malformed proposal is only rejected later in `engine.commit_block` → `import_block` → `verify_block_qc`, which explains why all validators log the same finalization failure for the same block hash.

## Step 5 — Timeline for Height 301 Occurrence

Precise multi-validator timeline could not be reconstructed from this workspace:

- No validator journal exports are present.
- `indra-data/blocks.log` exists but is 0 bytes.
- There are no local log files containing the height 208/261/301 incidents.

The expected timeline for height 301, based on code evidence, is:

1. A validator has committed height 299 and holds `last_qc_bytes = QC(299)`.
2. It receives/imports block 300 through `Message::BlockResponse`.
3. `d.engine.commit_block(&block_300)` advances state to height 300.
4. The sync path calls `d.sync_mut().on_block_imported(300)` and `d.reset_round()`, but does not update or clear `last_qc_bytes`.
5. The validator is caught up at height 300 with stale `last_qc_bytes = QC(299)`.
6. It wins proposer election for height 301 and calls `d.engine.propose(..., d.last_qc_bytes(), ...)`.
7. The height-301 proposal embeds QC height 299.
8. Other validators stage/vote for the proposal because proposal intake does not verify embedded QC linkage.
9. On precommit quorum, every validator attempts finalization and `verify_block_qc` rejects the block with `embedded QC height 299 does not match expected 300`.

To confirm the live timeline absolutely, collect for all four validators:

- process start/restart lines around heights 207/260/300;
- `[sync] imported block at height=207/260/300` lines;
- `[commit] finalizing ... height=207/260/300` lines;
- `[proposer] producing block at height=208/261/301` lines;
- the validator identity of each proposer for the failing block.

The key confirmation would be: the proposer of the malformed height-301 block imported height 300 via sync or restored stale `last_qc.bin`, rather than finalizing height 300 through `finalize_block_on_quorum`.

## Root Cause

`last_qc_bytes` was a bare byte cache whose height was not tracked or validated; the sync block-import path advanced `engine.state.height` without updating or invalidating that cache, so a validator could propose height `H` using the QC for `H-2`. This has been fixed locally by decoding and checking the cached QC height against `engine.state.height`.

## Fix Direction

Implemented locally:

- Added `ConsensusDriver::last_qc_is_stale()` and stale-cache clearing helpers.
- `request_qc_if_needed()` now triggers for stale non-empty cached QCs as well as empty QCs.
- The sync `BlockResponse` import path clears stale cached QC bytes after importing a block and requests QC recovery once caught up.
- `handle_qc_response()` can replace stale non-empty QC bytes with a verified fresh QC for the current tip.
- `handle_qc_request()` refuses to serve stale cached QC bytes for the local height.
- Driver startup now discards persisted QCs whose decoded height does not match the restored state height.
- `process_block_internal()` now runs embedded QC linkage verification before staging/voting for proposals above height 1.

Remaining deployment note: this should not go to live validators until reviewed and explicitly approved.
