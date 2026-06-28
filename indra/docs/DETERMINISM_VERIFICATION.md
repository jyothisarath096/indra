# Determinism Audit — Independent Verification Report

## Diagnosis Verification

### Confirmed: Arithmetic Overflow Caused State Divergence

The new regression test `replay_with_different_arithmetic_diverges_without_height_gating` constructs the four-validator reward boundary used by the incident and commits the old result into a state snapshot model.

- Old formula: `356_760_000_000u64.saturating_mul(100_000_000_000) / 400_000_000_000` returns **46,116,860** Spark, because the multiplication saturates at `u64::MAX`.
- New formula: `muldiv(356_760_000_000, 100_000_000_000, 400_000_000_000)` returns **89,190,000,000** Spark.
- The test verifies that applying those respective rewards to identical epoch-boundary states produces different `compute_state_root` values. It then models a pre-activation replay and verifies that height-selected legacy arithmetic reproduces the committed root.

This confirms the stated mechanism: replaying blocks 25801–25884 with unconditional u128 arithmetic could accumulate different `pending_rewards`, producing the observed mismatch at block 25885.

### Confirmed: HashMap Non-Determinism Was Present

The converted state collections are now `BTreeMap`: governance proposals/nonces/snapshots/commit-reveal data, staking bonds/nonces, validator entries, and delegation lists. Their state-transition traversals now receive sorted key order. The added `btreemap_iteration_is_deterministic_unlike_hashmap` test verifies lexicographic key traversal and byte-stable map encoding.

Consensus vote storage is also canonical now: both `QcBuilder.votes` and `VoteCollector.received` use `BTreeMap`, so QCs assembled directly by the builder and through the node driver preserve validator-ID order.

## Height Parameter Flow

| Function | Receives height | Gates arithmetic | Status |
|---|---:|---:|---|
| `apply_epoch_transition` | Indirectly derives `epoch * EPOCH_DURATION_BLOCKS`; block path calls `_at_height` | N/A | PASS on block/replay path |
| `apply_epoch_transition_at_height` | Yes | Passes to all listed epoch functions | PASS |
| `distribute_block_rewards` | Yes | Raw reward, saturation, commission, and delegator shares are gated | PASS |
| `distribute_fee_rewards` | Yes | Fee share, commission, and delegator shares are gated | PASS |
| `saturation_adjusted_reward` | Yes | Calls gated `proportional_reward` | PASS |
| `apply_block` slash path | Yes, `block.header.height` | `apply_slash_at_height` gates both slash amounts | PASS |
| `apply_governance_phase_transitions` | Yes | Tally calls height-gated quorum and support calculations | PASS |
| `verify_qc` / `QcBuilder` | Yes, `qc.height` / builder height | Verification and construction quorum gates with `overflow_fix_active` | PASS |
| `VoteCollector` quorum | Yes, stored collector height | Threshold and reported stake percentage gate with `overflow_fix_active`; storage is ordered | PASS |

### Gaps Found — FIXED

1. `DelegationMap::distribute_rewards` now receives `height` and gates each delegator share; both epoch callers pass their authoritative height.
2. Block-reward and fee-reward validator commission calculations now select legacy or u128 BPS arithmetic by height.
3. `apply_liveness_penalties` now receives height from `apply_epoch_transition_at_height` and gates its BPS penalty.
4. `GovernanceSnapshot::support_bps_at_height` is called from tally with the transition height.
5. `QcBuilder` uses ordered vote storage and gates both its displayed stake percentage and construction quorum decision. `VoteCollector` now uses ordered storage too, making node-driver QC construction canonical.

## Codec Determinism

- Governance encoders (`encode_u64_map`, `encode_set_map`, `encode_commit_map`, `encode_reveal_map`, and `encode_proposal_map`) take `BTreeMap` and iterate it directly. Decoders reconstruct `BTreeMap`s. Encoding is lexicographic by `Bytes32` key.
- Chain encoders (`encode_bond_map`, `encode_nonce_map`) take `BTreeMap` and iterate directly; decoders also construct `BTreeMap`s. `encode_hash_set` remains explicitly sorted, which is required and correct for its `HashSet` input.
- `ValidatorSet` and `DelegationMap` use `BTreeMap`. Their encoders still explicitly sort a collected vector. This is redundant but harmless; it also makes the intended canonical key order clear.

No converted state-map codec was found iterating an unordered map without sorting.

## Snapshot/Replay Consistency

The replay path is:

1. `NodeEngine::init` loads a snapshot and calls `rebuild_state_from_height(&mut state, ..., snapshot.height + 1)`.
2. `rebuild_state_from_height(state, block_store, start_height)` loads each persisted block and calls `indra_state::apply_block(state, &block, 0)`.
3. `apply_block(state, block, timestamp_secs)` takes the authoritative `block.header.height`; it passes that height to `apply_slash_at_height` and, at an epoch boundary, calls `apply_epoch_transition_at_height(state, epoch, timestamp_secs, block.header.height)`.
4. `apply_epoch_transition_at_height(state, current_epoch, timestamp_secs, height)` passes `height` to `distribute_block_rewards`, `distribute_fee_rewards`, `saturation_adjusted_reward` through `proportional_reward`, auto-delegation reward removal, and governance transition/tally.
5. `proportional_reward(amount, numerator, denominator, height)` calls `overflow_fix_active(height)` and selects legacy saturation or `muldiv`.

Therefore the full reward, fee, commission, delegation, liveness, governance, and QC replay paths have the correct block height available end-to-end.

## Phase 2 Restart Determinism Fixes

### Confirmed and Fixed: QC Signer Liveness Was Outside `apply_block`

Phase 2 confirmed a second replay divergence mechanism: `ValidatorEntry.last_active_epoch` was updated in `NodeEngine::commit_block` after `apply_block` returned, by decoding the committed block QC and marking every QC signer active in the current epoch. Startup replay uses `rebuild_state_from_height` and only calls `apply_block`, so replay did not reproduce that mutation. Because `last_active_epoch` is encoded into the validator-set root, this was a state-root bug.

Fix:

- `indra-state/src/apply.rs::apply_block` now performs the QC signer `last_active_epoch` update at the end of the canonical state transition.
- `indra-node/src/engine.rs::commit_block` no longer performs a separate live-only mutation.
- Live commit, sync import, replay, and block-production projection now all reach the same mutation through `apply_block`.

Regression tests:

- `last_active_epoch_updated_identically_live_and_replay`
- `apply_block_updates_last_active_epoch_for_qc_signers`

### Confirmed and Fixed: Equal-Fee Mempool Ties Were Not Canonical

Phase 2 also confirmed that `Mempool::select_for_block` sorted by fee rate only. Equal-fee transactions inherited randomized `HashMap` iteration order before truncation, allowing different proposers to choose different equal-fee subsets. Capacity eviction had the same issue when multiple lowest-fee entries existed.

Fix:

- Age-eligible and remaining block-selection entries now sort by `(fee_rate desc, tx_id asc)`.
- Capacity eviction now uses a deterministic total order: lowest fee first, and for equal fees the highest `tx_id` is evicted.

Regression tests:

- `mempool_select_for_block_is_deterministic_with_equal_fees`
- `mempool_eviction_is_deterministic_with_equal_fees`

## Fix Verification

### Test Results

`cargo test -p indra-state --test state_machine` passes all 20 tests, including:

- `replay_with_different_arithmetic_diverges_without_height_gating`
- `height_gated_arithmetic_is_deterministic_across_restarts`
- `btreemap_iteration_is_deterministic_unlike_hashmap`
- `delegator_reward_distribution_is_height_gated`
- `commission_bps_is_height_gated`
- `liveness_penalty_is_height_gated`
- `qc_vote_order_is_deterministic`
- `last_active_epoch_updated_identically_live_and_replay`
- `apply_block_updates_last_active_epoch_for_qc_signers`
- `mempool_select_for_block_is_deterministic_with_equal_fees`
- `mempool_eviction_is_deterministic_with_equal_fees`

The requested `cargo test --workspace --exclude indra-ffi --exclude indra-network` was also run. All determinism tests passed, but the command cannot complete in this sandbox because the unrelated `indra-node::metrics::tests::test_metrics_server_starts_and_responds` test is denied permission to bind its random local port (`Operation not permitted`). This is an environment restriction, not a test failure introduced by the audit changes.

### Remaining Risks

Snapshots store a schema version but not an explicit consensus transition/protocol version. A mainnet header `protocol_version`, committed to block hashes and validated by height, is still required.

## Conclusion

The diagnosis is proven and all identified arithmetic and QC-ordering gaps are now height-gated or canonicalized. Before mainnet, add and enforce a block-header protocol version, set announced nonzero production activation heights, and run multi-node replay/root comparisons across every fork boundary.
