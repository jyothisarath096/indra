# Integrated audit harness (in progress)

Deterministic virtual transport with seeded reorder, partition/heal, GST bound,
disconnect/reconnect, trace capture, and safety-oracle self-tests. Build with
`cargo test --manifest-path integrated_harness/Cargo.toml`.

This is audit infrastructure only. Production consensus integration remains an
explicit blocker; no campaign PASS may be claimed from these transport tests.
