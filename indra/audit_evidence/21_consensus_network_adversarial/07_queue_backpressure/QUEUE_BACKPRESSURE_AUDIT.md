# Queue / Backpressure / Resource-Exhaustion Audit

## Final disposition

**PASS WITH NON-CRITICAL FINDINGS**. No unbounded attacker-controlled queue,
task-spawn path, or frame buffer was reproduced. No production code changed.

## Queue inventory and production path

Authenticated socket read tasks decode one bounded frame at a time and send a
`NetworkEvent` through bounded Tokio channels. The node bridge uses a 1024-entry
async event channel; peer-manager command/control channels use configured finite
capacity. Senders await capacity, so sustained producers are backpressured rather
than accumulated in unbounded queues. Unknown/malformed frames are dropped
before event enqueue.

Each authenticated peer has a 256-entry small writer queue and a 4-entry large
writer queue. `try_send` drops relay traffic or disconnects for point-to-point
traffic when full. There is no per-send task accumulation. Writer shutdown drops
queued messages and read tasks are aborted on peer removal.

Inbound handshakes are gated by a semaphore of 50. FrameReader rejects lengths
over `MAX_MSG_BYTES = 14,680,064` before allocation and reads one frame per task.

## Deterministic stress results

The bounded-channel model exercised 1,000,000 attempted events, 100,000 sends
to a stalled writer, and 100,000 relay attempts. Producers either blocked at
capacity or were dropped by `try_send`; queue cardinality never exceeded its
declared capacity and returned to zero after consumer/disconnect. Maximum frame
allocation remained one `MAX_MSG_BYTES` plaintext per active reader.

## Memory accounting and non-critical concern

All queues are finite, but the theoretical product of 256 small slots by the
global maximum message size is large (~3.76 GiB per peer), and the 4 large slots
add ~56 MiB. In practice message-class routing keeps large block payloads on the
4-slot queue, while small messages are materially smaller; nevertheless the
code does not express a byte aggregate bound for each writer queue. This is a
finite resource-hardening concern, not an unbounded queue finding. A future
focused task should add byte-budget measurements or byte-capped queues.

Relay fanout is synchronous within the actor and uses per-peer bounded queues;
it does not spawn one task per destination. Duplicate/relay caches are bounded.
Sync has one outstanding request and one provisional candidate; BlockResponse is
limited to 50 blocks and follow-up requests replace/consume the single slot.

## Lock/backpressure and shutdown

No attacker-controlled `.send().await` was found while holding the consensus
driver mutex or cooldown/discovery mutex. Peer-manager actor awaits its own
bounded channels without exposing internal state locks. Disconnect aborts read
and write tasks, removes the managed peer, and closes queue ownership.

## Validation

`cargo test -p indra-network --lib` and `cargo test -p indra-node --lib` passed;
`cargo fmt --all -- --check` and `git diff --check` passed. Existing tests cover
frame maximum rejection, bounded writer behavior, relay duplicate suppression,
sync single-request binding, and handshake semaphore behavior.

## Open assumptions

Configured command-buffer capacities are finite in production configuration;
maximum peer count and transport socket buffers are externally bounded; and the
theoretical queue-byte product is not simultaneously realized because message
class routing separates large responses. This audit did not perform cryptographic
verification-cost analysis or generic scheduler/backpressure analysis.
