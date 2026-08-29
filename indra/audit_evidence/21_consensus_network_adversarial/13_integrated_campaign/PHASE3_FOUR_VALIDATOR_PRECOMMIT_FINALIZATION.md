# Phase 3 Step 19D — precommit quorum and finalization

The focused production-backed test `audit_harness_four_validator_strict_precommit_quorum_finalizes` uses the shared four-validator fixture, production proposal and vote paths, and `DriverEvent::InboundVote`. A/B/C independently reached Precommit via prevote quorum and emitted signed precommits. A observed its own precommit plus B (2/4) without QC or height advancement; C (3/4) triggered production QC construction, verification, durable staging, commit, and height advancement to 1. D was not delivered or required. The exact QC decodes to height 1, round 0, and the proposal hash. Replaying C's precommit after commit was a no-op.

Validation: focused test PASS; `cargo test --workspace --no-run --quiet` PASS; `git diff --check` PASS. No production consensus code was changed.

Step 19D.1 adds the complete 2/4 checkpoint (tip, QC bytes, collector membership,
and formation counter), decodes and re-verifies the production QC against the
height-1 snapshot, checks post-commit round/phase/lock/valid/pending cleanup,
loads persisted QC and confirms pending-QC removal, verifies VoteSafetyStore
cleanup, and proves stale precommit replay leaves all saved state and QC metrics
unchanged.

Step 19D.2 resolves the QC signer bitfield through the governing snapshot's
canonical entry ordering. The resulting signer IDs explicitly include A, B, C
and exclude D; their summed production snapshot weight satisfies the existing
strict-two-thirds quorum helper. Focused test, workspace no-run, and diff-check
all pass.
