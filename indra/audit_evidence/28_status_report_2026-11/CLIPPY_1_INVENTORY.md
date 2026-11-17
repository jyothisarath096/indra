# CLIPPY-1 inventory

UNFINISHED OR UNPROVEN: zero findings was not reached. The current residual inventory is recorded below; no full debug workspace suite or release workspace suite was run after these edits. The automatic Clippy fix also reordered the inline test module in indra-state/src/apply.rs, creating a large diff that requires review before final acceptance.

Commands were run from /Users/bonkai/Desktop/indra/project_indra/indra.

## Initial inventory

Initial command: cargo clippy --workspace --all-targets --no-deps --message-format=short
Raw output: /tmp/clippy1_inventory2.log.

Initial warning groups: large_enum_variant; too_many_arguments; type_complexity; missing unsafe documentation in indra-ffi; empty_line_after_doc_comments; manual_saturating_arithmetic; manual_is_multiple_of; manual_div_ceil; len_zero; collapsible_if; needless_borrow; single_match; redundant_closure; io_other_error; print_literal; assertions_on_constants; and clone/from-ref suggestions. Test-target findings included indra-core/tests/serialisation.rs, indra-network/src/observer.rs, indra-state/tests/state_machine.rs, indra-state/tests/monetary_invariants.rs, indra-consensus/tests/consensus.rs, indra-cli/tests/cli.rs, indra-node/src/driver_tests.rs, and indra-rpc/tests/rpc.rs.

## Residual inventory after mechanical suggestions

Follow-up command: cargo clippy --workspace --all-targets --no-deps --message-format=short
Raw output: /tmp/clippy1_after_boxed.log.

- large_enum_variant: indra-network/src/message.rs:137; indra-network/src/net_types.rs:26; indra-node/src/driver.rs:78,126; indra-ffi/src/handles.rs:192; and the local Event enum in indra-state/src/chain.rs:2500.
- too_many_arguments: indra-state/src/apply.rs:577, delegation.rs:707, governance_apply.rs:150, validator.rs:540; indra-consensus/src/vote.rs:283; indra-node/src/metrics.rs:267, sync.rs:283, engine.rs:2413, node.rs:1005,1093,1249,4220,4792,5308; and indra-state/tests/state_machine.rs:209.
- type_complexity: indra-state/src/chain.rs:1782, persistent.rs:474,771, smt.rs:460; indra-node/src/bin/node.rs:1263; and indra-ffi/src/handles.rs:608.
- large_err_variant: indra-network/src/peer_manager.rs:1381.
- new_without_default: indra-network/src/rate_limit.rs:162,218,315.
- Remaining clone/from-ref suggestions: indra-consensus/src/qc.rs:577,646,687,712,748,777; indra-cli/src/canonical_scan.rs:513,573,610,710; and three indra-cli/tests/cli.rs PathBuf references.
- FFI safety documentation remains for exported unsafe functions in indra-ffi/src/governance.rs, staking.rs, and lib.rs; the added sections are not yet reviewed against every actual pointer contract.
- Local source changes include boxed network/storage enum payloads. They compile, but wire/semantic compatibility still requires focused review.

## Loose ends

Vote membership — verified from code: indra-node/src/driver.rs:328-333, ConsensusDriver::set_voters, clears vote_collectors and round_advance_evidence before assigning registered_voters. refresh_registered_voters calls set_voters at lines 335-346. Height transition cleanup clears collectors at lines 2180 onward, and on_sync_caught_up clears them at lines 737 onward. Collector creation clones registered_voters at driver.rs:1804-1812 and :1861-1869. Therefore an old collector is not retained across the only voter-set replacement path. No stale-vote action or metric was added.

Storage overflow — verified from code: indra-storage/src/segmented_block_store.rs:280-303 now stores the checked (start,end) pair when the single loop addition succeeds and reuses that checked end. There is no second unreachable checked-add branch.

## Verification status

- cargo check --workspace --all-targets: passed after mechanical edits; log /tmp/clippy1_check_boxed6.log.
- Full Clippy with -D warnings: NOT RUN to completion because the residual inventory is still non-zero.
- Focused tests for every touched crate: NOT RUN after the boxed enum changes.
- cargo test --workspace --release: NOT RUN after the last edit.
- Golden/replay tests: NOT RUN after the last edit.
- cargo audit and cargo deny check: NOT RUN after the last edit.

## Final disk check

Filesystem      Size    Used   Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5   228Gi   193Gi   8.7Gi    96%    2.0M   91M    2%   /System/Volumes/Data

