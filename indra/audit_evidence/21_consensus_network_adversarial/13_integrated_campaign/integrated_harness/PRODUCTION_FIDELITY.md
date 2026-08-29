# Production Fidelity

| Operation | Fidelity |
|---|---|
| transport scheduling/partitions/GST | TEST-ONLY ADAPTER |
| proposal creation/validation | NOT YET INTEGRATED |
| prevote/precommit signing/verification | NOT YET INTEGRATED (private driver path) |
| QC formation/verification | NOT YET INTEGRATED |
| lock/PoLC/commit/finality | NOT YET INTEGRATED |
| VoteSafetyStore | NOT YET INTEGRATED |
| restart reconstruction | NOT YET INTEGRATED |

The harness does not simulate consensus decisions. A production adapter must
live in the owning `indra-node` test context (or an explicit non-default audit
feature) to instantiate real drivers and invoke actual methods. Until that
adapter exists and passes fixture tests, this harness must not be used as Phase
3 campaign evidence.
