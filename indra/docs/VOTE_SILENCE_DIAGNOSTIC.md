# INDRA Consensus Vote Silence Diagnostic

## Executive Summary

The QC bytes lifecycle is straightforward and raw-byte preserving: after a block commits, `ConsensusDriver` stores `qc.encode_to_vec()` in `last_qc_bytes`; the next proposer embeds those exact bytes into `BlockHeaderV1.quorum_certificate`; import then decodes and verifies that raw header field for blocks above height 1. The height-3-specific “first hybrid QC” hypothesis is not supported for a clean post-fix run: height 2 already imports a hybrid QC for height 1. The confirmed diagnostic finding is that successful vote production/broadcast has no log line, while several proposal drop paths return `DriverAction::None` silently before any vote is produced. Therefore “no vote logs” does not prove no votes exist; if the chain is stuck with proposals and no commits, the most likely hidden failure point is silent proposal rejection/staging before `maybe_prevote_current_round_proposal`, especially `process_block_internal`’s unlogged `apply_block` projection failure. The next fix should add strict proposal validation and explicit logging before votes are suppressed.

## 1. last_qc_bytes storage

`last_qc_bytes` is stored after commit in `indra-node/src/driver.rs`.

Trace:

- `finalize_block_on_quorum` builds a QC from accepted precommit votes.
- It commits the block with `self.engine.commit_block(&block)`.
- On success, it stores exactly `qc.encode_to_vec()`:

```rust
self.last_qc_bytes = qc.encode_to_vec();
indra_storage::save_last_qc(&self.engine.config.state_dir(), &self.last_qc_bytes)
```

Code location:

- `indra-node/src/driver.rs:920-950` builds and stores the QC.
- `indra-node/src/driver.rs:951-955` persists the same raw bytes to `last_qc.bin`.

Answer to Q1: `last_qc_bytes` is the raw encoded bytes of the newly built `QuorumCertificateV1`, not bytes copied from the prior block header.

With the current codec, a post-fix QC starts with the QC format byte:

- `QC_FORMAT_HYBRID = 2` when `hybrid_qc_active(qc.height)` is true.
- `QC_FORMAT_LEGACY = 1` otherwise.

## 2. Block proposal QC embedding

The proposal path passes `last_qc_bytes` through as raw bytes.

Trace:

1. The node loop calls `d.engine.propose(..., d.last_qc_bytes(), ...)`.
   - `indra-node/src/bin/node.rs:1430-1434`
2. `NodeEngine::propose` stores those bytes in `BlockTemplate.prev_qc_bytes`.
   - `indra-node/src/engine.rs:400-442`
3. `produce_block` wraps the bytes in `VariableBytes<MAX_QC_SIZE_BYTES>`.
   - `indra-consensus/src/producer.rs:122-126`
4. The resulting `BlockHeaderV1` stores them in `quorum_certificate`.
   - `indra-consensus/src/producer.rs:130-145`

There is no decode/re-encode step when proposing a fresh block. The QC bytes are copied as raw bytes into the header.

Re-proposal follows the same raw-byte pattern:

- `NodeEngine::repropose` receives `last_qc`.
- It wraps it with `VariableBytes::<MAX_QC_SIZE_BYTES>::from_slice(&last_qc)`.
- It assigns the result directly to `header.quorum_certificate`.

Code location:

- `indra-node/src/engine.rs:454-528`

Answer to Q2: the exact `last_qc_bytes` vector is embedded into the new block header as a raw byte blob.

## 3. Block header QC format

`BlockHeaderV1` stores the QC as raw bytes:

```rust
pub quorum_certificate: VariableBytes<MAX_QC_SIZE_BYTES>,
```

Code location:

- `indra-core/src/types/block.rs:66-68`

It is not stored as a decoded `QuorumCertificateV1`.

Block header encoding serializes the raw `VariableBytes`:

- `BlockHeaderV1::encode` calls `self.quorum_certificate.encode(buf)`.
- `BlockHeaderV1::decode` restores it with `VariableBytes::decode(r)?`.

Code location:

- `indra-core/src/types/block.rs:95-116`
- `indra-core/src/types/block.rs:137-153`

Answer to Q3: the block header stores raw QC bytes. Other validators decode those bytes during strict import verification.

## 4. Import and QC validation path

`import_block` validates the embedded previous QC only for blocks above height 1:

```rust
if height > 1 {
    verify_block_qc(block, state)?;
}
```

Code location:

- `indra-node/src/sync.rs:206-224`

`verify_block_qc`:

1. Allows an empty QC only for block height 1.
2. Decodes `block.header.quorum_certificate.as_slice()` as `QuorumCertificateV1`.
3. Builds the current active validator list.
4. Calls `verify_qc_strict`.

Code location:

- `indra-node/src/sync.rs:356-409`

Important: `verify_block_qc` does not currently check:

- `qc.height == block.header.height - 1`
- `qc.block_hash == previous block's value_hash`

It verifies the QC signatures and stake against the active validator set available in the current pre-block state.

## 5. Silent rejection paths

### Proposal handling in `driver.rs`

`process_block` has several silent returns:

| Location | Silent condition | Effect |
|---|---|---|
| `indra-node/src/driver.rs:553-555` | Node not caught up | Block ignored |
| `indra-node/src/driver.rs:558-560` | Block height below next height | Block ignored |
| `indra-node/src/driver.rs:562-563` | Block height more than two ahead | Block ignored |
| `indra-node/src/driver.rs:565-577` | Future height or wrong parent hash | Block buffered, no vote |

`process_block_internal` has the most important silent path:

```rust
let mut projected_state = self.engine.state.clone();
if indra_state::apply_block(&mut projected_state, &block, 0).is_err() {
    return vec![DriverAction::None];
}
```

Code location:

- `indra-node/src/driver.rs:602-604`

This suppresses voting without logging the reason. If height-3 proposals are malformed in a way that `apply_block` sees, every validator will silently decline to stage/vote for them.

Other silent proposal paths:

| Location | Silent condition | Effect |
|---|---|---|
| `indra-node/src/driver.rs:609-614` | Same height/round already has different block | Block ignored |
| `indra-node/src/driver.rs:616-617` | Pending block already known | Block ignored |

VRF rejection is logged:

- `indra-node/src/driver.rs:588-599`

So a complete absence of VRF rejection logs makes the VRF check less likely than a later silent path.

### Vote handling in `driver.rs`

Successful vote production and broadcast are not logged. `record_vote_and_actions` pushes `DriverAction::BroadcastVote`, but prints nothing on success.

Code location:

- `indra-node/src/driver.rs:781-858`

Silent vote paths:

| Location | Silent condition | Effect |
|---|---|---|
| `indra-node/src/driver.rs:700-701` | Vote for already committed height | Vote ignored |
| `indra-node/src/driver.rs:709-721` | Duplicate identical vote already seen | Vote ignored |
| `indra-node/src/driver.rs:725-727` | Node not caught up | Passive record only; no success log |
| `indra-node/src/driver.rs:730-748` | Vote references unknown proposal | Vote buffered/requested; no success log |

Vote rejection errors are logged:

- `indra-node/src/driver.rs:755-779`
- `indra-node/src/driver.rs:859-868`

### Driver action handling in `node.rs`

`process_driver_actions` broadcasts `BroadcastVote` and `BroadcastBlock` actions without logging them:

```rust
if let Some(out_msg) = action_to_message(&action) {
    broadcast_driver_message(gossip, &action, &out_msg);
}
```

Code location:

- `indra-node/src/bin/node.rs:1721-1723`

Therefore “no vote messages in logs” is expected for successful votes unless another subsystem logs network traffic externally.

### Network encoding/decoding

The network layer also has quiet drop behavior:

- `indra-network/src/peer_manager.rs:105-112`: outbound message encode failure is converted to `Ok(())`, dropping the message.
- `indra-network/src/peer_manager.rs:280-292`: inbound frame read or decode failure breaks the peer read loop without logging the message-specific reason.

This is outside the five requested files but relevant to “no messages appear”.

## 6. Height 1 vs height 3 difference

### Height 1

Height 1 may omit a previous QC:

- `verify_block_qc` returns `Ok(())` for empty QC when `block.header.height == 1`.
- Code location: `indra-node/src/sync.rs:356-360`

So height 1 does not prove the previous-QC path is healthy.

### Height 2

Height 2 embeds and verifies the QC for height 1.

If the run is a clean post-codec-fix wipe, the height-1 QC was produced by the current binary and is already a hybrid QC with a format byte.

Therefore height 2 does exercise:

- raw QC embedding in `BlockHeaderV1`
- `QuorumCertificateV1::decode`
- `verify_qc_strict`
- hybrid classical + PQ QC verification

### Height 3

Height 3 embeds and verifies the QC for height 2.

In a clean post-fix run, there is no codec-format distinction between the height-1 QC and the height-2 QC. Both are produced by:

```rust
qc.encode_to_vec()
```

and both are embedded as raw bytes.

The structural difference is not “legacy vs hybrid codec”; it is only the contents of the QC and state at the time it is checked:

- possibly a different signer set/signature count,
- possibly a changed active validator set after height 2,
- possibly a different state root/validator root projection,
- possibly a proposal dropped before voting by the silent `apply_block` projection path.

## 7. Root cause

The confirmed root cause of the “vote silence” symptom is missing instrumentation: successful vote production/broadcast is never logged, and several proposal rejection/staging paths silently return `DriverAction::None`. The code does not support the specific claim that height 3 is the first hybrid-QC codec case in a clean post-fix run; height 2 already verifies a hybrid QC.

For the “no commit after height 2” symptom, the strongest code-supported failure point is silent proposal suppression before voting, especially:

```rust
if indra_state::apply_block(&mut projected_state, &block, 0).is_err() {
    return vec![DriverAction::None];
}
```

at `indra-node/src/driver.rs:602-604`.

That path exactly matches:

- proposals are produced,
- peers exist,
- no vote rejection logs,
- no QC logs,
- rounds keep advancing,
- no commit happens.

## 8. Fix

Add explicit diagnostic logging and strict proposal pre-validation before voting: log the exact error from the projected `apply_block` failure in `process_block_internal`, and validate/log the embedded previous QC for `block.header.height > 1` before staging or voting on a proposal.

Separately, add success-level logs or counters for local vote production and `BroadcastVote` actions so future “vote silence” incidents distinguish “no votes produced” from “votes produced but not logged”.

## 9. Answers to Q1-Q6

| Question | Answer |
|---|---|
| Q1 — How is `last_qc_bytes` stored after height 2 commits? | It is `qc.encode_to_vec()` from the QC built in `finalize_block_on_quorum`, then persisted verbatim to `last_qc.bin`. |
| Q2 — How is `last_qc_bytes` embedded in a new block proposal? | The node loop passes `d.last_qc_bytes()` into `NodeEngine::propose`; producer wraps it in `VariableBytes<MAX_QC_SIZE_BYTES>` and assigns it to `BlockHeaderV1.quorum_certificate`. |
| Q3 — Does the block header store QC as raw bytes or decoded struct? | Raw bytes: `VariableBytes<MAX_QC_SIZE_BYTES>`. |
| Q4 — Why do heights 1 and 2 commit but height 3 does not? | Height 1 has no previous-QC requirement. Height 2 already verifies the height-1 QC. In a clean post-fix run, height 3 is not the first hybrid-QC codec case; failure must be due to QC contents/current state/proposal suppression, not merely the presence of `classical_signatures`. |
| Q5 — Is there a silent rejection path in import/block handling? | Yes. `process_block_internal` silently drops proposals when projected `apply_block` fails, and several other driver paths silently ignore/buffer blocks or votes. Strict sync import and commit-finalize failures are logged. |
| Q6 — What changed between height 2 committing and height 3 failing? | The embedded previous QC changes from “QC for height 1” to “QC for height 2”; in a clean run the codec format should be the same. The meaningful differences are signer set/signature count, validator-state changes after height 2, and whether the height-3 proposal passes the silent pre-vote projection path. |

## 10. Recommended next diagnostic step

Before changing consensus behavior, add temporary logs around these exact lines:

1. `driver.rs:602-604` — print the `apply_block` projection error.
2. `driver.rs:535-538` — print local vote signed and step/hash.
3. `node.rs:1721-1723` — print `BroadcastVote` action count/height/round/step.
4. `peer_manager.rs:109-112` — print outbound encode failures.
5. `sync.rs:371-409` — when strict QC validation fails, include decoded QC height/signature counts if decode succeeded.

Those logs should identify the exact runtime failure in one stalled round without altering consensus state.
