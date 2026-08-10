# INDRA Consensus Determinism Audit

## Executive Summary

The June 26, 2026 divergence was caused by applying changed consensus arithmetic while replaying blocks that had been committed under the previous arithmetic. This audit adds a height-gated overflow-fix framework, makes consensus-state maps ordered (`BTreeMap`), and verifies canonical map encoding. Snapshot schema versioning exists, but it is not a state-transition/protocol version and cannot identify the arithmetic rules that created a block. A `protocol_version` in `BlockHeaderV1` remains required before mainnet.

## Incident Report

Between blocks 25884 and 25885 the bonkai validator restarted from its height-25800 snapshot using a binary containing the u128 proportional-arithmetic fix. Blocks 25801–25884 had been committed by the previous binary, whose `saturating_mul` arithmetic can differ from `muldiv`. Replay therefore produced a different reward state; when block 25885 was applied its expected state root no longer matched, permanently isolating the validator.

The immediate cause was the missing activation height. The broader impact is that any consensus-state change applied by a newer binary can invalidate deterministic replay of historical blocks. On mainnet this is a permanent fork risk unless all nodes wipe state or otherwise coordinate an unsafe recovery.

## Findings

### CRITICAL: Arithmetic Fix Without Activation Height (FIXED)

- **Locations:** `epoch.rs` reward, fee, saturation, and virtual auto-delegation reward math; `apply.rs` slash and bond-slash math; `governance.rs` quorum; `qc.rs` and `vote.rs` consensus quorum.
- **Risk:** A restart used new arithmetic for blocks committed under old arithmetic.
- **Fix:** `indra_core::types::primitives::hard_forks::OVERFLOW_FIX_HEIGHT` and `overflow_fix_active(height)` select legacy saturating arithmetic before activation and u128 arithmetic at/after activation. Testnet is explicitly configured as active from genesis (`0`).
- **Deployment height:** The repository contains no signed deployment manifest or protocol-version marker recording the historical testnet upgrade height. It must be recovered from validator release/deployment records before interpreting pre-existing testnet history. This is an operational documentation gap; the testnet constant intentionally applies the corrected rules from genesis after the required coordinated wipe.

### HIGH: HashMap Non-Determinism in State Transitions (FIXED)

- **Locations:** `GovernanceState.proposals`, `gov_nonces`, `last_proposal_epoch`; proposal commits, reveals, and redelegation set; governance snapshot weights; `ChainState.staked_bonds` and `staking_nonces`; `ValidatorSet.validators`; `DelegationMap.delegators`.
- **Risk:** randomized `HashMap` order could affect mutation order or a serialized state root.
- **Fix:** all consensus-state maps above now use `BTreeMap<Bytes32, _>`, ordered lexicographically by the 32-byte key. Epoch processing also retains explicit sorted vectors where it deliberately snapshots validator IDs.
- **Audit result:** the governance proposal loop, validator traversal, bond processing, and delegation-wide mutation now have deterministic key order. `HashSet`s remain only where their iteration is not used for state mutation/encoding; `ChainState` encodes slash hashes through a sorted vector.

### MEDIUM: HashMap Non-Determinism in Codec (FIXED/VERIFIED)

- **Locations:** governance `encode_u64_map`, proposal/commit/reveal/set encoders; chain `encode_bond_map` and `encode_nonce_map`; validator and delegation encoders.
- **Risk:** logically equal state could serialize differently, producing different roots.
- **Fix:** BTreeMap-backed encoders now iterate map order directly. Validator/delegator encoders are canonical: validator and delegation keys are lexicographically ordered, and lists retain their explicit canonical handling. Historical explicit sorting was removed from maps now guaranteed ordered.
- **Snapshot serialization:** `state_store.rs` serializes `ChainState` through its canonical codec and writes a snapshot format/schema marker. It does not serialize unordered map entries independently.

### LOW: No Height-Gated Block Protocol Activation Schedule

- **Current state:** `BlockHeaderV1` contains `protocol_version`; its canonical encoding contributes to `block_hash()`, block decoding checks it in `block.rs`, and authoritative application checks it again in `apply.rs`. The original finding that the header lacked a hash-bound, validated protocol version is no longer accurate.
- **Remaining gap:** Validation is a flat equality check against the single current `BLOCK_FORMAT_VERSION`. There is no `expected_block_version(height)` or equivalent height-gated activation schedule that permits old and new block protocol versions to coexist across a deterministic transition boundary.
- **Disposition:** Keep this open as future protocol-upgrade architecture. It is needed when a second block protocol version must coexist during a transition, not as part of the current cleanup phase.

## Snapshot and Replay Assessment

`engine.rs::rebuild_state_from_height` reads persisted blocks and calls the current `indra_state::apply_block` implementation. Before this change it had no transition-version dispatch, and the snapshot schema cannot detect a logic-only arithmetic change. `apply_block` now supplies `block.header.height` to height-sensitive epoch and slash paths, so replay selects the same arithmetic on either side of the configured fork height.

## Mainnet Readiness

Before mainnet, set every hard-fork constant to an announced, future block height; never change a deployed constant retroactively. Record the release hash, activation height, and expected protocol version in release artifacts. Add the header `protocol_version`, test old/new replay across every fork boundary, and require multi-node state-root comparison after replay and epoch transitions.

For this testnet correction: wipe all four validators, build the same release for all nodes, deploy simultaneously rather than rolling, confirm progress past the old tip within 60 seconds, restart one validator, and compare roots after ten epochs. The existing chain cannot be safely reinterpreted with the genesis-active setting without that coordinated reset.
