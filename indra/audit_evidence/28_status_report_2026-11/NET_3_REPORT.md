Result: NET_3 is implemented with real peer-manager relay-path coverage for line, star, and ring topologies, bounded deduplication, slot safety, and a strict live line runner. The live owner run reached height 10 on all four validators with identical tips, zero panics, zero stale-sync responses, zero exit failures, and the configured line remained partial at the endpoints.

Unfinished: none for the NET_3 specification; the full height-10 live run and all requested automated checks completed.

# Codex NET_3 implementation report

## Implementation

The implementation stays in the authenticated networking path and leaves consensus rules and wire formats unchanged.

- `indra-network/src/peer_manager.rs` now carries an optional consensus-slot context supplied by the node. When present, `relay_if_eligible` rejects votes and proposals whose height or round does not match the current slot before selecting relay targets. This closes the wrong-height/wrong-round relay gap without changing driver quorum or QC rules.
- `indra-network/src/net_types.rs` adds `NetworkCommand::UpdateRelayConsensusContext`.
- `indra-node/src/bin/node.rs` publishes the next consensus height and current round to the peer manager whenever that slot changes.
- The consensus startup readiness gate is now `MIN_CONSENSUS_PEERS = 1`. A single authenticated direct peer is sufficient to enter consensus because authenticated consensus messages can traverse the peer graph; quorum formation remains enforced by the consensus driver and QC verification. This was required by the strict line topology: endpoints have one direct neighbor by design.
- `scripts/line_topology_live.sh` creates fresh four-validator keys/genesis, writes explicit line bootstrap edges `0-1-2-3`, records topology, height, tip, peers, exit codes, panic counts, and stale-sync metrics, terminates all nodes, and returns PASS only when every requested condition holds.

## Real relay-path topology tests

`indra-network/src/peer_manager.rs:2882-3045` uses the actual `PeerManagerActor::handle_command`, `relay_if_eligible`, relay target selection, relay seen cache, signature verification, and both production outbound queues. The test harness recursively drains messages from each node to the configured graph neighbors; it does not reimplement relay selection.

`relay_reaches_all_nodes_through_line_star_and_ring` covers:

- line `0-1-2-3`;
- star `0-{1,2,3}`;
- ring `0-1-2-3-0`;
- a proposal plus four distinct signed consensus messages from a single origin, requiring multi-hop delivery;
- all validators reached and bounded delivery counts for every topology.

`relay_bounds_duplicate_and_conflicting_messages` verifies duplicate ring traffic remains finite and deduplicated. Existing peer-manager safety tests cover invalid signatures, inactive validator IDs, duplicate votes, and conflicting same-slot blocks; `pre_relay_slot_context_rejects_wrong_height_and_round` now verifies that validly signed but out-of-slot votes produce no relay output.

Mutation proof: inserting an unconditional return at the top of `relay_if_eligible` made `relay_reaches_all_nodes_through_line_star_and_ring` fail on the line topology (`reached 2`, expected 4). The mutation was removed; the production relay-path test passed afterward.

## Live transport evidence

Smoke command completed successfully at `TARGET_HEIGHT=3`:

```sh
TARGET_HEIGHT=3 CAP_SECONDS=120 BASE_P2P_PORT=32800 BASE_RPC_PORT=19800 \
  NODE_BIN="$PWD/target/debug/node" \
  GENESIS_BIN="$PWD/target/debug/indra-genesis" \
  KEYGEN_BIN="$PWD/target/debug/indra-keygen" \
  scripts/line_topology_live.sh /tmp/net3-line-smoke-fixed.OUmTYC
```

Smoke result: all four nodes reached height 3 with the same tip, `panics=0`, `stale_sync=0`, and exit 0. Endpoint peer counts remained 1, while the middle nodes had 2, confirming the test did not silently require a full mesh.

Full owner run completed successfully at height 10 in 335 seconds:

```sh
TARGET_HEIGHT=10 CAP_SECONDS=600 BASE_P2P_PORT=32900 BASE_RPC_PORT=19900 \
  NODE_BIN="$PWD/target/debug/node" \
  GENESIS_BIN="$PWD/target/debug/indra-genesis" \
  KEYGEN_BIN="$PWD/target/debug/indra-keygen" \
  scripts/line_topology_live.sh /tmp/net3-line-full.n4lt0l
```

Recorded result:

| Node | Height | Tip | Peers | Exit |
|---:|---:|---|---:|---:|
| 0 | 10 | `8824b2f6948aaad90b59fcdbee9a0b21673dc67bb2999e3dda54f772463dc7d1` | 1 | 0 |
| 1 | 10 | `8824b2f6948aaad90b59fcdbee9a0b21673dc67bb2999e3dda54f772463dc7d1` | 2 | 0 |
| 2 | 10 | `8824b2f6948aaad90b59fcdbee9a0b21673dc67bb2999e3dda54f772463dc7d1` | 2 | 0 |
| 3 | 10 | `8824b2f6948aaad90b59fcdbee9a0b21673dc67bb2999e3dda54f772463dc7d1` | 1 | 0 |

The topology RPC showed no endpoint full-mesh formation. The script summary reported `reached=1 same_tip=1 panics=0 stale_sync=0 exits_zero=1`.

The initial strict-line smoke before the readiness-gate fix stayed at height 0 because `node.rs` required two direct peers; its logs showed endpoints waiting with one peer. Lowering only the transport-readiness threshold to one exposed the existing authenticated relay path and produced the passing height-3 and height-10 runs. A two-component partition still has no quorum; this change does not alter quorum or finalization rules.

## Verification

- `cargo test -p indra-network --lib` — 164 passed, 1 ignored.
- New relay topology, duplicate-bound, and wrong-slot tests — passed in debug mode.
- `cargo clippy --workspace --all-targets --no-deps -- -D warnings` — passed.
- `cargo clippy --release --workspace --all-targets --no-deps -- -D warnings` — passed.
- `scripts/check_no_lint_allows.sh` — passed.
- `cargo test -p indra-core --test lint_guard` — 2 passed.
- `cargo audit` — advisories passed; existing duplicate-dependency warnings remain informational.
- `cargo deny check` — bans, licenses, and sources passed; existing duplicate-dependency warnings remain informational.
- `cargo test --workspace --release --no-fail-fast` — 49 targets, 1,682 passed, 0 failed, 10 ignored. This is four more passing tests than the NET_2 baseline of 1,678.
- `git diff --check` and `bash -n scripts/line_topology_live.sh` — passed.

## Diff accounting

Tracked source diff by crate:

| Crate | Files | Net change |
|---|---:|---:|
| `indra-network` | 2 | +238 / -4 |
| `indra-node` | 1 | +23 / -2 |

Additional untracked implementation script: `scripts/line_topology_live.sh` (190 lines). No consensus implementation file or protocol wire schema was changed. Final `df -h .`: 11 GiB available, 95% used.
