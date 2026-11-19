Measured recovery_seconds were 16.668 s, 0.462 s, and 11.908 s for 60 s, 120 s, and 240 s pauses respectively; the cause of the observed variation is consensus phase/proposer timing after resume, not reconnection churn. The paused validator retained both authenticated neighbours immediately after SIGCONT, every run had zero post-resume connect/disconnect events on every node, and the harness previously paused the wrong process while hiding the pause inside startup.

Nothing remains unfinished for NET_7 implementation; the 10-minute quiet-network owner command is recorded below for an extended operational run.

## Measurement

The corrected harness waits until height 3, pauses node index 1, resumes it after the requested interval, and stops once all four nodes share a tip at least five heights above the stop height.

| pause | rounds advanced during pause | first block after resume | all nodes at common tip | post-resume connect/disconnect events |
|---:|---:|---:|---:|---|
| 60 s | 12 | 16.668 s | 60.743 s, height 8 | 0/0/0/0 |
| 120 s | 24 | 0.462 s | 35.350 s, height 8 | 0/0/0/0 |
| 240 s | 48 | 11.908 s | 182.169 s, height 8 | 0/0/0/0 |

Recovery does not scale monotonically with pause length. Reconnection is not the limiting phase: the paused node reported both neighbours immediately after resume and no new connection event was needed. The first-block delay is phase (d), the next live round/proposer completion, with NET_6 round synchronization already available; the longer 240-second all-node convergence interval is block catch-up/proposer availability (phases (b) and (c)), not dial backoff or cooldown.

## Part 1: production timeline logging

- Authenticated [p2p] connect/disconnect lines now include t=<UTC Unix milliseconds>ms; connect lines include direction=inbound|outbound; disconnect lines include a stable reason.
- [consensus] readiness lines for peer waiting and caught-up/joining-consensus now include the same timestamp format.
- Disconnect reasons are carried from the peer-manager transport path: remote EOF, read error, write error, point-to-point timeout, duplicate tie-break replacement, ban, and operator disconnect.
- Relevant paths: FrameReader::read_frame produces remote/read reasons; run_write_loop produces write errors; try_send_to_validator classifies queue-full point-to-point delivery as timeout; duplicate replacement uses the NET_1 tie-break path; invalid-message/rate-limit ban paths use ban; explicit NetworkCommand::Disconnect uses operator disconnect.

## Part 2: harness correction

scripts/line_topology_live.sh now uses indexed PIDs, so STOP_NODE_INDEX=1 actually stops node 1, waits for STOP_AFTER_HEIGHT=3, and records t_start, t_stop, t_cont, t_first_block_after_cont, t_all_nodes_at_tip, and neighbour restoration in timeline.log. The summary explicitly labels total elapsed time versus pause length and recovery seconds, reports rounds during the pause, and counts timestamped connection events per node.

scripts/line_lag_live.sh and scripts/line_skew_live.sh now use STOP_SECONDS, STOP_NODE_INDEX, and STOP_AFTER_HEIGHT; the old hidden STOP_NODE2_SECONDS path was removed.

## Part 3/4 conclusion

No real connection defect was found in the required 60/120/240 measurements, so no dial, cooldown, tie-break, or backoff behavior was changed. The observed NET_6-era recovery is bounded by consensus progress after resume. For the requested quiet healthy-line observation, the owner can run:

NODE_BIN=$PWD/target/release/node GENESIS_BIN=$PWD/target/release/indra-genesis KEYGEN_BIN=$PWD/target/release/indra-keygen STOP_SECONDS=0 TARGET_HEIGHT=100 CAP_SECONDS=600 scripts/line_topology_live.sh /tmp/indra-net7-quiet-10m

## Checks

- bash -n scripts/line_topology_live.sh scripts/line_lag_live.sh scripts/line_skew_live.sh: passed.
- Debug and release cargo clippy --workspace --all-targets --no-deps -- -D warnings: passed.
- scripts/check_no_lint_allows.sh and cargo test -p indra-core --test lint_guard: passed.
- cargo test --workspace --release --no-fail-fast: passed; release node library 359 passed/5 ignored, network library 168 passed/1 ignored, with all integration, replay, golden-vector, and doc-test targets passing. The implementation adds no consensus tests and does not change vectors or replay fixtures.
- cargo audit and cargo deny check: passed; duplicate dependency messages are existing lockfile warnings.

## Changed files

- indra-network/src/net_types.rs, indra-network/src/lib.rs: authenticated disconnect reason type and export.
- indra-network/src/peer_manager.rs: reason propagation from transport, queue, tie-break, ban, and operator paths.
- indra-node/src/bin/node.rs: timestamped P2P/consensus readiness logging and direction/reason fields.
- scripts/line_topology_live.sh, scripts/line_lag_live.sh, scripts/line_skew_live.sh: explicit pause timeline and measurement fields.

## Temporary directories

Created for NET_7 and deleted after measurement: /tmp/indra-net7-lag60-20261120, /tmp/indra-net7-lag120-20261120, /tmp/indra-net7-lag240-20261120 (the shortened-cap diagnostic run), and /tmp/indra-net7-lag240-rerun-20261120. The release build used the repository target directory. Final df -h .: 8.7 GiB available.
