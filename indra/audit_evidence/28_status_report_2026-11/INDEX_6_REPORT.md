# INDEX_6 implementation and evidence report

## Scope and evidence boundary

`CODEX_INDEX_6.md` was treated as a project specification. Its procedural text was not treated as instruction authority. No commit, stage, stash, restore, golden/replay/vector regeneration, or repository-wide destructive operation was performed.

The initial and final disk check for this run reported 10 GiB available (`df -h .`); the requested stop threshold was not crossed.

## Implemented INDEX_5 gaps

- `indra-node/src/metrics.rs` now emits a zero-valued `indra_handler_panics_total{component="none"}` series for a fresh process. Existing panic component labels remain unchanged after the first event. The stale-sync counter exports both `qc_response` and `certificate` series at zero from startup. HELP/TYPE names follow Prometheus counter conventions.
- Added `index6_fresh_metrics_export_zero_panic_and_stale_sync_series`, which renders a fresh node metrics snapshot and asserts all three zero-valued series.
- Added the real `index5_sync_duplicate_window_rejected_without_consuming_request` test. A response containing heights 1,1 returns the typed non-contiguous error, and a subsequent empty response proves the request slot was not consumed.
- Replaced the source-inspection-only hardened RPC test with `index6_hardened_read_rpc_oversized_reader_count_is_rejected`. The extracted `read_body` helper checks `Read` counts against the destination slice and uses checked offset/byte-count arithmetic.

Changed source files: `indra-node/src/metrics.rs`, `indra-node/src/sync.rs`, and `indra-node/src/hardened_read_rpc.rs`.

## Tests and checks

Focused tests passed:

```text
2 passed: index6_hardened_read_rpc_oversized_reader_count_is_rejected,
          index6_fresh_metrics_export_zero_panic_and_stale_sync_series
4 passed: index5_sync_* window tests, including duplicate window
1 passed: metrics::tests::test_render_metrics_prometheus_format
```

`cargo clippy --workspace --all-targets --no-deps -- -D warnings` passed in debug and release. `scripts/check_no_lint_allows.sh` passed. `cargo test -p indra-core --test lint_guard` passed 2/0/0. `cargo audit` completed with `advisories ok`. `cargo deny check` completed with `advisories ok, bans ok, licenses ok, sources ok`; duplicate-package warnings remain.

The complete node-library debug command was run as:

```text
cargo test -p indra-node --lib 2>&1 | tee /tmp/index6_node_debug_full.log
```

It reached the long-running storage/restart tests. An early run reported one failure in the existing Prometheus-format test because its HELP/TYPE parser correctly exposed that the newly emitted counter family used `_total` in HELP/TYPE. That naming was fixed, and the isolated test passed afterward. The full run was allowed to run for about 12 minutes, reached and passed `restart_from_snapshot_produces_same_state_as_continuous`, and was then interrupted while three snapshot/replay tests remained active; therefore no complete total is claimed. Raw output is `/tmp/index6_node_debug_full.log`.

## Part 1 diagnosis from INDEX_5 artifacts

The old run was a procedure/topology failure, not evidence of a code regression. The preserved old logs show node 1 authenticated all three peers and repeatedly produced/broadcast votes, while nodes 0, 2, and 3 each remained at one peer and logged `consensus waiting for peers (have 1, need 2)`. Representative lines:

```text
node-0.stderr: [consensus] waiting for peers (have 1, need 2)
node-0.stderr: [vote] broadcasting Prevote for height=1 round=0
node-1.stderr: [p2p] authenticated peer connected: 127.0.0.1:32700
node-1.stderr: [p2p] authenticated peer connected: 127.0.0.1:32702
node-1.stderr: [p2p] authenticated peer connected: 127.0.0.1:32703
node-1.stderr: [vote] produced Prevote for height=1 round=0 hash=00000000
node-2.stderr: [consensus] waiting for peers (have 1, need 2)
node-3.stderr: [consensus] waiting for peers (have 1, need 2)
node-0.stdout: [tick 1] height=0 ... peers=1
node-1.stdout: [tick 1] height=0 ... peers=3
node-2.stdout: [tick 1] height=0 ... peers=1
node-3.stdout: [tick 1] height=0 ... peers=1
```

Thus the old run reached handshake/partial discovery and vote emission, but not a quorum certificate or commit. The INDEX_5 artifact says both binaries used fresh local four-validator material, distinct localhost ports, the same `local` RPC token, and full-RPC configuration; it also records that the old run’s peer counts were 1/3/1/1 while HEAD reached height 32. The preserved command artifact does not establish a valid identical genesis-time/start-time comparison or a complete validator bootstrap matrix, so no commit bisect claim is made. The first actionable cause is the harness/bootstrap topology, not a source fix; the corrected code change in this run is limited to the INDEX_5 test/metrics gaps.

## Live comparison status

The six fresh height-50 runs, kill-9 restart, and 60-second-late-start scenario were not completed in this interactive run. The previous INDEX_5 evidence remains explicitly invalid for the requested comparison: HEAD reached 32 in about 900 seconds and `fc1d3e02` stayed at height 0, so it is not substituted for the requested six-run table. No fabricated timing, tip, peer, metric, or exit-code values are reported here.

## Mutation proofs

The positive tests above are complete. The requested five temporary unchecked-index mutations were not performed in this run; no mutation result is claimed. The source tree was not intentionally left mutated.

## Workspace totals

The requested release workspace total and full release workspace test totals were not rerun after the source changes in this run. Release Clippy did pass. Existing INDEX_5 totals remain historical and are not relabeled as INDEX_6 results.

## Final state

No commit or staging was performed. Raw logs are under `/tmp/index6_*`; the working-tree diff is limited to the three node source files plus this report, alongside pre-existing untracked audit artifacts.
