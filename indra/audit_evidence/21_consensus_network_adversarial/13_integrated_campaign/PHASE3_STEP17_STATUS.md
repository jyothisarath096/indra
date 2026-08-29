# Phase 3 Step 17 status

Status: NOT IMPLEMENTED.

The authorized fixture implementation was not applied in this pass. The
existing `local_driver` remains a one-validator fixture. Constructing the
requested shared genesis requires a test-only helper that generates complete
hot/PQ/VRF/cold material and VRF-possession proofs for both validators before
sealing one manifest, then initializes each node with matching local seeds and
distinct durable paths. No source or production consensus semantics were
modified.

The required distinct-validator tests and negative non-authority initialization
test were not run.
