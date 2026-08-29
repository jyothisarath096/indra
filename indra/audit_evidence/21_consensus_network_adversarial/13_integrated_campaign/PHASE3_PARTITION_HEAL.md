# Phase 3 Step 20A — deterministic 2+2 partition/heal

The production-backed test `audit_harness_four_validator_partition_heal_converges`
stages one proposal, applies an explicit A/B versus C/D delivery rule, and
delivers votes only within each side. Both sides remain at height 0 with no QC.
After real timeout advancement and healing, a production proposal and signed
votes are exchanged through inbound processing; all four independently finalize
the same height-1 hash. No production code was changed.

Validation: focused partition test PASS; two-height, finalization, workspace
no-run, and diff-check PASS.

Evidence hardening records dynamic initial proposer eligibility, production
empty-round advancement, two complete partitioned rounds with explicit 2+2
delivery, no-QC/no-commit checkpoints, and post-heal recovery using only a
genuinely eligible proposer (no fallback index). The existing production
proposal/vote/QC/finalization path remains unchanged.
Second-round proposer eligibility is explicitly checked; eligible proposals are
side-restricted, otherwise the production empty timeout path runs. Final phase
reset and canonical-root stale replay equality are asserted.
The literal assertion pass additionally records partition-round coordinates and
nil-precommit framing, preserves no-quorum state through two partitioned rounds,
verifies all recovered QCs against the governing snapshot, compares canonical
state roots across all four nodes, and replays saved pre-heal prevote/nil-
precommit traffic against a complete unchanged state snapshot on A.
