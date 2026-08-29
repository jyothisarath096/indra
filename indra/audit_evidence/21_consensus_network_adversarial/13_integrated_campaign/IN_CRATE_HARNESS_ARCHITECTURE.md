# In-crate harness architecture (Step 10)

The existing external `integrated_harness` is an independent scheduler crate; it
has no dependency on `indra-node`, so there is no Cargo cycle. The production
fixture cannot be moved outward. The intended integration boundary is therefore
an in-crate `#[cfg(test)]` module in `indra-node` that directly reuses the
private `local_driver` fixture, while the external scheduler remains opaque to
consensus semantics.

Current implementation status: architecture selected and documented; the
production-backed multi-node adapter is not yet implemented. Existing driver
tests already exercise real `ConsensusDriver`, `VoteSafetyStore`, signing,
restart, lock, QC, and commit paths and are the appropriate seed for the
in-crate harness. No dependency cycle or production semantic change was
introduced.
