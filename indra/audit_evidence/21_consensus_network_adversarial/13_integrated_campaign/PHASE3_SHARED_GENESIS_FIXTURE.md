# Phase 3 Step 15 fixture refactor status

Status: BLOCKED — no production or test fixture changes were made.

Current dependency flow:

`local_driver(seed,suffix)` → deterministic hot/PQ/VRF/cold keys → validator
identity and VRF-possession proof → one `[[validators]]` record →
`seal_test_genesis_fixture` → `NodeConfig::local_test` with that validator seed
→ `NodeEngine::init` → `VoteSafetyStore::open` → `ConsensusDriver::new`.

The fixture binds the selected validator into the genesis manifest before
sealing. A correct shared two-validator fixture therefore requires generating
both complete validator records before sealing, then initializing two separate
configs against the same sealed manifest while assigning each node its own hot,
PQ, VRF, and cold key material. The current helper does not expose this split.

The required authority/snapshot-root and durable-path assertions cannot be
performed safely by mutating authority state after initialization. The work is
deferred to an atomic test-only refactor of the helper dependency cluster.
