# CLIPPY-1 report

UNFINISHED: the requested zero-warning Clippy gate was not completed. Residual warnings are listed in CLIPPY_1_INVENTORY.md. The full debug workspace run was not run, as instructed.
UNPROVEN: the boxed enum changes and mechanical changes have not been followed by the requested focused tests, release workspace suite, golden/replay tests, audit, or deny checks.

## Work performed

- Read-only vote trace: ConsensusDriver::set_voters clears vote_collectors before replacing registered_voters in indra-node/src/driver.rs:328-333. refresh_registered_voters and height/sync transitions use that path. No stale-vote race was found and no stale-vote metric or action was added.
- Reworked segmented_block_store pruning so the checked segment end is computed once and stored with the start in indra-storage/src/segmented_block_store.rs:280-303.
- Applied Clippy mechanical suggestions to the affected code and tests.
- Added real FFI Safety sections to the unsafe exported functions touched in indra-ffi/src/lib.rs, governance.rs, and staking.rs. These contracts still require review before completion.
- Boxed several non-wire internal enum payloads to reduce large_enum_variant findings. Compatibility has not yet been demonstrated.

## Verification

cargo check --workspace --all-targets passed after the current edits. Log: /tmp/clippy1_check_boxed6.log.

Initial Clippy inventory: /tmp/clippy1_inventory2.log.
Post-mechanical Clippy inventory: /tmp/clippy1_after_boxed.log.
Clippy -D warnings: NOT RUN to completion.
Release workspace tests: NOT RUN after the final edits.
Focused crate tests: NOT RUN after the final edits.
Golden/replay tests: NOT RUN after the final edits.
cargo audit and cargo deny check: NOT RUN after the final edits.

## Diff caution

git diff --stat currently shows a large reorder in indra/indra-state/src/apply.rs because the automatic Clippy fix moved its inline test module. This is not being concealed as a small mechanical change and must be reviewed before the work is considered complete.

## Disk

Initial and final df -h . checks were above 3 GiB available. Final observed output: /dev/disk3s5 228Gi 193Gi 8.7Gi 96% mounted at /System/Volumes/Data.

