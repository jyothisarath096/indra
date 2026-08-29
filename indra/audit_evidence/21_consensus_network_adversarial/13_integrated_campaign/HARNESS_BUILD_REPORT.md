# Harness Build Report

Created `integrated_harness/Cargo.toml`, `src/lib.rs`, `README.md`, and
`PRODUCTION_FIDELITY.md`. No production files were modified.

Implemented: seeded deterministic envelopes, virtual ticks, partition/heal,
GST delivery enforcement, disconnect/reconnect, reorder, serializable trace,
and independent finalized-hash/vote/height safety checks. Self-tests cover
partition/heal, deterministic replay, GST bounds, and oracle conflict detection.

Not yet implemented: production-driver node adapters, actual proposal/vote/QC
construction and verification, lock/PoLC transitions, durable restart
reconstruction, and multi-node liveness campaigns. Therefore status is
**HARNESS INCOMPLETE** and Phase 3 remains open.

Command: `cargo test --manifest-path audit_evidence/21_consensus_network_adversarial/13_integrated_campaign/integrated_harness/Cargo.toml`.

Step 2 API inventory: `integrated_harness/PRODUCTION_ADAPTER_MAP.md`. Adapter
integration remains blocked on crate-private signing paths and canonical
`NodeEngine`/genesis/snapshot construction; no production visibility or
consensus changes were introduced.

Step 3 fixture inventory: `integrated_harness/PRODUCTION_NODE_FIXTURE_MAP.md`.
Step 4 added the non-default `audit-harness` feature and a thin
`indra_node::audit_harness::ProductionNodeAdapter`. The adapter wraps a real
`ConsensusDriver`, delegates timeout/event processing, and exposes only the
semantic local-vote operation through a feature-gated `pub(crate)` bridge. The
complete production diff is `integrated_harness/HARNESS_TEST_ONLY_PRODUCTION.diff`.
Canonical fixture construction and multi-node finalization remain unimplemented;
Step 5 therefore remains incomplete and no production-backed signing proof is
claimed.

Step 6 re-confirmed that the canonical `local_driver` builder is nested in a
`#[cfg(test)]` module. Promoting it requires a reviewed crate-level refactor;
copying it into the audit module would violate the single-initialization-path
requirement. No fixture promotion or production semantic change was made.

Step 7 captured the exact refactor scope in `LOCAL_DRIVER_REFACTOR_NOTES.md`.
The builder remains pending because its private helper/import dependency cluster
must move atomically; no duplicate implementation was introduced.

Step 8 did not land a partial extraction. The complete cluster must be moved as
one crate-private unit before the audit feature can consume it; otherwise the
fixture would diverge from the canonical test setup. Phase 3 harness status
remains incomplete.

Step 10 pivot architecture is recorded in `IN_CRATE_HARNESS_ARCHITECTURE.md`.
The external scheduler remains consensus-agnostic; production fixture access
must be implemented inside `indra-node` tests using the existing private
`local_driver`. No full campaign or multi-node adapter was added yet.
