# Peer-manager vote rate-limit review

## Classification

**TEST TIMING DEFECT.** No production rate-limit, concurrency, or identity-bypass defect was found.

The failed assertion treated an 80-token burst capacity as a timeless maximum of 80 deliveries. Production implements a token bucket with an 80-message capacity and a 20-message/second refill (`indra-network/src/rate_limit.rs:245-248`). Therefore an 81st message is correctly admitted once one complete token has accrued.

## Exact mechanism and the 80/81 result

- Identity key: `PeerManagerActor::handle_control` indexes `limiters_by_validator` by the authenticated connection's `validator_id`, not by message encoding or socket address (`indra-network/src/peer_manager.rs:895-921`). The read task obtains that ID from the completed handshake and copies it into every inbound control event (`indra-network/src/peer_manager.rs:1046-1071`).
- Bucket: authenticated vote traffic uses `TokenBucket::new(20, 80)` (`indra-network/src/rate_limit.rs:245-248`). Count tokens use scale 1,000, so the bucket begins with 80,000 sub-tokens and a vote costs 1,000 (`indra-network/src/rate_limit.rs:10-31,57-66`).
- Clock/refill: `Instant` supplies monotonic elapsed time. Refilling uses integer elapsed milliseconds and adds `elapsed_ms * 20` sub-tokens, capped at 80,000 (`indra-network/src/rate_limit.rs:45-55`). Thus one full vote token requires exactly `1000 / 20 = 50 ms` of credited elapsed time.
- Boundary: admission is `tokens >= cost`, then subtraction (`indra-network/src/rate_limit.rs:58-66`). A token available at the exact 50 ms boundary is intentionally usable.
- Reproduction: before correction, 20 isolated repetitions produced one 81-delivery failure and nineteen 80-delivery passes; passing runs took roughly 42-51 ms end-to-end. Full-workspace execution repeatedly produced 81. This is consistent with scheduler/runtime delays crossing the 50 ms refill boundary; end-to-end time is not itself the credited time because `last_refill` advances after millisecond-bearing checks.

The production promise is therefore **capacity 80 plus time-based refill at 20 votes/second**, not a hard lifetime maximum of 80.

## Synchronization and identity properties

- The limiter map and buckets are owned by one `PeerManagerActor`. Its run loop receives one command/control event and awaits its handler before selecting the next (`indra-network/src/peer_manager.rs:807-823`). `check` receives `&mut self` and token decrement is synchronous (`indra-network/src/rate_limit.rs:271-286`). Concurrent read tasks can enqueue concurrently, but they cannot concurrently mutate or overspend a bucket.
- Near-duplicate encodings do not create identities: all 81 distinct vote bodies in the regression use the same authenticated validator key and one limiter entry (`indra-network/src/peer_manager.rs:1942-1980`).
- Different validator identities get independent entries and budgets, verified by the two-validator regression (`indra-network/src/peer_manager.rs:1983-2020`).
- Disconnect/reconnect does not remove `limiters_by_validator`; `drop_peer` removes connection/address state only (`indra-network/src/peer_manager.rs:1132-1162`). The regression exhausts a budget, disconnects, and confirms the next vote remains rejected (`indra-network/src/peer_manager.rs:2022-2072`).

## Deterministic correction

Production behavior was not changed. A `#[cfg(test)]` constructor replaces only the test instance's vote bucket with capacity 80 and refill 0 (`indra-network/src/rate_limit.rs:233-243`). The identity-sharing boundary test now injects this frozen bucket before sending 81 messages (`indra-network/src/peer_manager.rs:1942-1980`). It still requires exactly 80 deliveries; the assertion was not relaxed.

Refill semantics are tested separately and deterministically by positioning the internal monotonic timestamp at 49 ms and 50 ms: the former rejects and the latter admits one token (`indra-network/src/rate_limit.rs:409-420`).

## Adversarial results

| Case | Result |
|---|---|
| 81 near-duplicate votes, one validator, frozen time | Exactly 80 delivered; one shared identity budget. |
| Two validators, 80 votes each | Exactly 160 delivered; independent budgets. |
| Disconnect after exhausting 80, then send again | 81st rejected; identity budget survives disconnect. |
| Alternate vote bodies/encoded hashes | Same authenticated validator ID and same bucket. |
| Concurrent arrival | Actor serialization prevents simultaneous mutable bucket access. |
| Refill at 49/50 ms | Reject at 49 ms; admit at 50 ms, matching 20/second. |

No stop condition was met: no concurrent or alternate-encoding path exceeded the mathematically permitted token-bucket allowance.

## Validation

- Focused corrected test: 25/25 consecutive passes.
- `cargo test -p indra-network`: 131 passed, 0 failed, 1 ignored; integration 4 passed.
- One transient unrelated `transport::tests::send_and_receive_message` failure occurred in the first crate run; it passed immediately in isolation and in the complete rerun. No changes were made for it.
- `cargo test --workspace`: passed (including `indra-network`: 131 unit passed, 1 ignored; 4 integration passed; and `indra-node`: 271 library passed, 5 ignored, 79 binary passed, 15 integration passed).
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.
