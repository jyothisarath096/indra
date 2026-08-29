# Phase 3 Step 14 status

Status: BLOCKED — distinct two-validator fixture not implemented.

The canonical `local_driver` test fixture in `indra-node/src/driver.rs` creates
and seals a one-validator genesis and derives the engine configuration,
authority snapshot, and deterministic proposer election from that manifest.
Its validator seed is also bound into the node configuration. Simply opening a
second driver with another seed would produce a different one-validator
authority, not two nodes sharing one authority set.

Implementing this step correctly requires an atomic test-only fixture refactor:
construct both validator key records, emit one sealed genesis manifest, and
initialize each `NodeEngine` against that same manifest while selecting its own
validator seed. No production consensus code was changed and no authority state
was mutated after initialization.

The existing same-identity bridge remains in
`PHASE3_TWO_NODE_PRODUCTION_BRIDGE.md`; it is not evidence of distinct
validator authentication and must not be treated as such.
