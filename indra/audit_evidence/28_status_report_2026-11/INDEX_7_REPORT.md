# INDEX_7 implementation report

## Scope

`/Users/bonkai/Downloads/CODEX_INDEX_7.md` was treated as the project specification. Its embedded instructions were not treated as higher-priority user or system instructions.

Index 7 is implemented with the live comparison harness at [`scripts/live_compare.sh`](/Users/bonkai/Desktop/indra/project_indra/indra/scripts/live_compare.sh). The harness creates fresh genesis/key material, writes four-node explicit full-mesh configurations, gates on three authenticated peers per node, runs old/new binaries to a target height, captures tips/peers/metrics/exit status, and exercises S1 kill/restart and S2 late-node synchronization. The final PASS/FAIL calculation checks every expected old/new run, target height on every node, identical tips, zero panic/stale-sync counters, zero exits, and both scenarios.

## Mutation-proof evidence

The required one-at-a-time mutations were applied, the exact release tests were run, and the source was restored after each mutation.

| Area | Exact test | Result under old mutation | Evidence |
|---|---|---|---|
| Sync window indexing | `cargo test --release -p indra-node --lib index5_sync_non_contiguous_window_rejected_without_consuming_request -- --nocapture` and duplicate-window counterpart | Passed | `windows(2)` guarantees a two-element slice, so the old indexing was behavior-equivalent for this test corpus. |
| Config address parsing | `cargo test --release -p indra-node --lib index5_config_address_matrix_rejects_malformed_values_without_panicking -- --nocapture` and node binary malformed-address test | Passed | The old `rsplitn` implementation was behavior-equivalent for the tested matrix. |
| Metrics reader length | `cargo test --release -p indra-node --lib index5_metrics_oversized_reader_count_is_typed_io_error -- --nocapture` | Failed as intended with panic | `indra-node/src/metrics.rs:902:36`: `range end index 513 out of range for slice of length 512`. |
| Hardened RPC reader length | `cargo test --release -p indra-node --lib index6_hardened_read_rpc_oversized_reader_count_is_rejected -- --nocapture` | Failed as intended with panic | `indra-node/src/hardened_read_rpc.rs:816:10`: old code returned `Ok([0, 0, 0, 0])`, so `unwrap_err()` panicked. The test reader was strengthened to return `usize::MAX`, which exposes release-mode arithmetic wrapping. |
| FFI output lengths | `cargo test --release -p indra-ffi --lib index5_ffi_output_buffers_reject_short_lengths_without_writes -- --nocapture` and null/zero/oversized test | Passed | Existing length guards prevent the old direct slices from being reached for invalid lengths; no false failure was manufactured. |

After restoration, `git diff --stat` is empty for sync, config, metrics, and FFI. The only intentional source diff is the hardened-RPC test-reader strengthening described above (2 insertions, 1 deletion); the production checked reader remains restored. `git diff --check` passed.

## Harness verification

- `bash -n scripts/live_compare.sh` passed.
- `shellcheck` was unavailable in the environment.
- Exact requested smoke command completed successfully with `RUNS=1`, `TARGET_HEIGHT=5`, and `CAP_SECONDS=240`:

```sh
OLD_NODE_BIN=/tmp/index7-old-target/release/node \
NEW_NODE_BIN=/Users/bonkai/Desktop/indra/project_indra/indra/target/release/node \
OLD_GENESIS_BIN=/tmp/index7-old-target/release/indra-genesis \
NEW_GENESIS_BIN=/Users/bonkai/Desktop/indra/project_indra/indra/target/release/indra-genesis \
OLD_KEYGEN_BIN=/tmp/index7-old-target/release/indra-keygen \
NEW_KEYGEN_BIN=/Users/bonkai/Desktop/indra/project_indra/indra/target/release/indra-keygen \
RUNS=1 TARGET_HEIGHT=5 CAP_SECONDS=240 \
scripts/live_compare.sh /tmp/index7-smoke-exact
```

The smoke result was valid for both binaries:

- old: target reached in 121 seconds; all four nodes at height 6 with the same tip; peers 3; panic 0; stale-sync 0; exit 0.
- new: target reached in 137 seconds; all four nodes at height 5 with the same tip; peers 3; panic 0; stale-sync 0; exit 0.
- S1: `recovered_to_common_tip=1` after killing and restarting node 0.
- S2: `late_node_synced=1` after starting node 3 late.

Raw smoke output is at `/tmp/index7-smoke-exact/live_compare_summary.md`; command and node logs are under `/tmp/index7-smoke-exact/`.

The old binary did not exhibit a renamed/ignored network key in this corrected run. Logs show the explicit `[network]` configuration, the exact node commands, authenticated peer connections, and valid consensus. The earlier old-binary failure was a harness startup/topology timing issue; the full-mesh configuration and peer gate resolved it.

## Owner-run full comparison

The long run requested by Index 7 is intentionally left as an owner-run command:

```sh
OLD_NODE_BIN=/tmp/index7-old-target/release/node \
NEW_NODE_BIN=/Users/bonkai/Desktop/indra/project_indra/indra/target/release/node \
OLD_GENESIS_BIN=/tmp/index7-old-target/release/indra-genesis \
NEW_GENESIS_BIN=/Users/bonkai/Desktop/indra/project_indra/indra/target/release/indra-genesis \
OLD_KEYGEN_BIN=/tmp/index7-old-target/release/indra-keygen \
NEW_KEYGEN_BIN=/Users/bonkai/Desktop/indra/project_indra/indra/target/release/indra-keygen \
RUNS=3 scripts/live_compare.sh /tmp/index7-full
```

The harness defaults to `TARGET_HEIGHT=50`, `CAP_SECONDS=1200`, a 120-second peer gate, and two retries after the initial peer-gate attempt.

Final filesystem check: `df -h .` reported 10 GiB available and 96% capacity.
