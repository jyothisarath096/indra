# INDRA Hybrid QC Diagnostic

## Executive Summary

The hybrid QC signature logic itself is internally consistent: votes carry both Ed25519 and ML-DSA signatures over the wire, `QcBuilder` preserves both signature components, and `verify_qc` verifies both against the same canonical vote signing bytes used by `produce_vote`. The confirmed deployment-breaking issue is QC wire-format incompatibility: `QuorumCertificateV1::decode` now always expects a trailing `classical_signatures` list, while any QC persisted or embedded before the C-03 change contains only `pq_signatures`. Because `HYBRID_QC_HEIGHT = 0`, a new binary rejects old QC bytes at every height, so a post-upgrade block with a pre-upgrade previous QC can be proposed and voted on but fails finalization/import.

## 1. Vote wire format

**Answer: YES — `VoteV1` carries `classical_sig` over the network.**

Trace:

- `indra-core/src/types/vote.rs`
  - `VoteV1` has `signature: HybridSignature`.
  - `VoteV1::encode` serializes `self.signature`.
  - `VoteV1::decode` restores `signature: HybridSignature::decode(r)?`.
- `indra-core/src/types/crypto.rs`
  - `HybridSignature` encodes `classical_sig` first, then `pq_sig`.
- `indra-network/src/message.rs`
  - `Message::Vote(v)` encodes payload with `v.encode_to_vec()`.
  - `MessageType::Vote` decodes payload with `VoteV1::decode`.
- `indra-node/src/net_driver.rs`
  - `Message::Vote(vote)` becomes `DriverEvent::InboundVote { vote }`.
  - `DriverAction::BroadcastVote(vote)` becomes `Message::Vote(vote.clone())`.

Conclusion: network transport does not strip the classical signature. A receiving node gets the full `VoteV1.signature.classical_sig` and `VoteV1.signature.pq_sig`.

## 2. QcBuilder extraction

**Answer: YES — `build()` correctly populates `classical_signatures`.**

Trace:

- `indra-consensus/src/qc.rs`
  - `QcBuilder.votes` is `BTreeMap<Bytes32, VoteV1>`, so the full vote object is retained.
  - `QcBuilder::add_precommit` inserts the whole `VoteV1`.
  - `QcBuilder::build` passes `self.votes.values()` into `build_qc_from_votes`.
  - `build_qc_from_votes` pushes:
    - `PQVoteSig { pq_sig: vote.signature.pq_sig }`
    - `ClassicalVoteSig { classical_sig: vote.signature.classical_sig }`

Conclusion: there is no evidence that classical signatures are lost between vote receipt and QC construction.

## 3. Signing bytes match

**Answer: YES — vote signing bytes match between production, vote verification, and QC verification.**

Canonical function:

```rust
indra_core::types::vote_signing::vote_signing_bytes(
    height,
    round,
    step,
    block_hash,
    validator_id,
)
```

Canonical bytes are:

```text
VOTE_SIGN domain || height || round || step || block_hash || validator_id
```

Trace:

- `indra-consensus/src/vote.rs::produce_vote`
  - signs `vote_signing_bytes(height, round, step, &block_hash, &validator_id)`.
- `indra-consensus/src/vote.rs::VoteCollector::add_vote`
  - verifies received votes with the same `vote_signing_bytes(vote.height, vote.round, vote.step, &vote.block_hash, &vote.validator_id)`.
- `indra-consensus/src/qc.rs::verify_qc`
  - verifies QC signatures with `VoteStep::Precommit` and the same `qc.height`, `qc.round`, `qc.block_hash`, and signer `validator_id`.

Important negative finding: C-02 chain ID was not implemented in this code path. There is no `chain_id` parameter in `vote_signing_bytes`, `produce_vote`, `VoteCollector::add_vote`, or `verify_qc`. Therefore the suspected chain-id mismatch is not the cause of this stall.

## 4. Quorum check

**Answer: YES — 3/4 validators reaches quorum.**

With four equal-stake validators:

```text
total_stake = 400_000_000_000
3 votes = 300_000_000_000
CONSENSUS_QUORUM_BPS = 6667
quorum_stake = bps_of(total_stake, 6667) = 266_680_000_000
300_000_000_000 >= 266_680_000_000
```

Trace:

- `VoteCollector::current_decision` counts stake per `block_hash` and returns `VoteDecision::QuorumReached` when stake crosses threshold.
- `QcBuilder::build` recomputes `voted_stake` and compares it to the same threshold before constructing the QC.

Conclusion: quorum math should trigger with 3 of 4 equal validators.

## 5. Error handling

**Answer: QC build/import errors are logged, not swallowed.**

Trace:

- Vote rejection logs:
  - `driver.rs::record_vote_and_actions` logs `[vote] rejected vote ...`.
  - `driver.rs::record_vote_passive` logs `[vote] rejected vote ...`.
- Proposal VRF rejection logs:
  - `driver.rs::process_block_internal` logs `[vote] rejecting proposal ... because it does not verify as the elected proposer block`.
- QC build failure logs:
  - `driver.rs::finalize_block_on_quorum` logs `[commit] failed to build QC ...`.
- Block finalization/import failure logs:
  - `driver.rs::finalize_block_on_quorum` logs `[commit] failed to finalize ...`.
- QC response recovery failure logs:
  - `driver.rs::handle_qc_response` logs invalid QC encoding or verification failures.

Conclusion: if a precommit quorum is reached and finalization fails because the embedded previous QC is old-format, the expected log is a `[commit] failed to finalize ... invalid QC encoding ...` style message.

## 6. Root cause

**Root cause:** the C-03 fix changed `QuorumCertificateV1` wire format by appending `classical_signatures`, but `QuorumCertificateV1::decode` has no legacy/pre-fork decode path while `HYBRID_QC_HEIGHT = 0`, so new binaries reject old persisted or embedded PQ-only QC bytes.

## 7. Why this matches the observed stall

The block import path validates the previous QC embedded in every block above height 1:

```rust
if height > 1 {
    verify_block_qc(block, state)?;
}
```

`verify_block_qc` does:

```rust
let qc = QuorumCertificateV1::decode(&mut reader)?;
verify_qc_strict(&qc, &validators, total_stake)?;
```

A block produced after upgrade can still carry `last_qc_bytes` loaded from disk or recovered from peers. If those bytes were produced before C-03, they contain:

```text
height || round || block_hash || signer_bitfield || pq_signatures
```

but new decode expects:

```text
height || round || block_hash || signer_bitfield || pq_signatures || classical_signatures
```

That decode fails before `verify_qc` is reached. The driver then cannot finalize/import the block, leaves height unchanged, and the timeout loop advances to the next round.

## 8. Fix

**Fix:** either perform a full testnet state/QC wipe for `HYBRID_QC_HEIGHT = 0`, or add a hard-fork-aware QC decode/verify path that accepts PQ-only legacy QC bytes before `HYBRID_QC_HEIGHT` and requires hybrid QCs at/after that height.

For mainnet, the safer framework is:

1. Set `HYBRID_QC_HEIGHT` to a future activation height.
2. Decode old QC format for blocks below that height.
3. Decode and require `classical_signatures` for blocks at or above that height.
4. Clear/rebuild any persisted `last_qc_bytes` whose format does not match the active height.

## Minimal Reproduction Test

This is a minimal test to add near QC/block import tests. It demonstrates the deployment bug: old PQ-only QC bytes are not decodable by the new QC codec.

```rust
#[test]
fn legacy_pq_only_qc_bytes_fail_new_hybrid_qc_decode() {
    use indra_core::{
        codec::{ByteReader, Decode, Encode},
        types::{
            crypto::PQVoteSig,
            primitives::{Bytes32, VariableBytes},
            qc::{QuorumCertificateV1, SIGNER_BITFIELD_BYTES},
        },
    };

    let mut legacy = Vec::new();
    3u64.encode(&mut legacy); // height
    0u32.encode(&mut legacy); // round
    Bytes32::from([0xAB; 32]).encode(&mut legacy); // block_hash
    legacy.extend_from_slice(&{
        let mut bitfield = [0u8; SIGNER_BITFIELD_BYTES];
        bitfield[0] = 0b0000_0111; // three signers
        bitfield
    });

    let pq_signatures = vec![
        PQVoteSig {
            validator_id: Bytes32::from([0x01; 32]),
            pq_sig: VariableBytes::from_slice(&[0x11; 32]).unwrap(),
        },
        PQVoteSig {
            validator_id: Bytes32::from([0x02; 32]),
            pq_sig: VariableBytes::from_slice(&[0x22; 32]).unwrap(),
        },
        PQVoteSig {
            validator_id: Bytes32::from([0x03; 32]),
            pq_sig: VariableBytes::from_slice(&[0x33; 32]).unwrap(),
        },
    ];
    pq_signatures.encode(&mut legacy);

    let mut reader = ByteReader::new(&legacy);
    assert!(
        QuorumCertificateV1::decode(&mut reader).is_err(),
        "new hybrid QC decoder rejects pre-C03 PQ-only QC bytes; this reproduces the post-upgrade stall"
    );
}
```

After a compatibility fix, invert the assertion for heights below `HYBRID_QC_HEIGHT` and assert that the legacy QC is decoded into a legacy/PQ-only representation or accepted by the pre-fork verification path.

## Answers to Q1–Q6

| Question | Answer | Evidence |
|----------|--------|----------|
| Q1 — Vote carries classical signature over network? | YES | `Message::Vote` encodes full `VoteV1`; `VoteV1` encodes `HybridSignature`; `HybridSignature` includes `classical_sig`. |
| Q2 — QcBuilder extracts classical signatures? | YES | `build_qc_from_votes` copies `vote.signature.classical_sig` into `classical_signatures`. |
| Q3 — QC signing bytes match vote signing bytes? | YES | `produce_vote`, `VoteCollector`, and `verify_qc` all use the same canonical `vote_signing_bytes`; no chain ID is present. |
| Q4 — 3/4 quorum triggers? | YES | 75% stake exceeds 66.67% quorum; code uses deterministic threshold math. |
| Q5 — QC errors swallowed? | NO | Driver logs vote rejection, QC build failure, and commit/import failure paths. |
| Q6 — chain-id mismatch root cause? | NO | C-02 chain ID was not implemented in this vote/QC path. |

