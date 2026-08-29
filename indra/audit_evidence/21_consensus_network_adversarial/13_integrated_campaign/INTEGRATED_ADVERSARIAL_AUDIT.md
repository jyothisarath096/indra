# Integrated Multi-Node Adversarial Campaign

## Disposition

**INCOMPLETE — INTEGRATED HARNESS/COVERAGE REQUIRED**. The requested
production-faithful multi-node scheduler is not present in the repository. No
multi-node campaign result is claimed or fabricated, and no production code was
modified.

## Production logic exercised by existing evidence

Consensus driver rules enforce strict quorum, persisted vote safety, legal
rounds, PoLC lock transitions, and fail-closed final-round behavior. Sync uses
one outstanding request, exact source binding, and bounded block responses.
Restart reconstruction discards volatile network state while restoring durable
chain, authority, lock, and anti-double-sign state. Discovery retains configured
honest roots and active validator registration is deduplicated.

Existing tests cover proposer silence/timeouts, stale and future traffic,
selective/late votes and QCs, lock/reproposal behavior, crash/restart vote
safety, sync recovery boundaries, and topology reservations. These are isolated
or deterministic component campaigns, not a substitute for a live multi-node
adversarial scheduler.

## Campaign coverage gaps

Partition/heal, topology-plus-consensus, valid-traffic pressure during active
consensus, GST recovery, near-threshold 32% Byzantine scheduling, restart
storms, and the 10,000-height long-run campaign were not executed. The required
numeric campaign matrix therefore remains explicitly zero/unexecuted. Component
tests are insufficient evidence for the requested integrated claims.

## Safety conclusion

No CRITICAL/HIGH issue was reproduced in existing component tests, but this is
not a conclusion about integrated behavior. No L3-NET-11 reproducer is created.
Run the campaign with a production-driver multi-node harness before any PASS
disposition or mainnet sign-off.

## Validation

Component commands previously passed: `cargo test -p indra-consensus`, `cargo
test -p indra-network --lib`, and `cargo test -p indra-node --lib`; `cargo fmt
--all -- --check` and `git diff --check` passed. No integrated harness command
was executed because no such harness exists in the tree.

Required final numbers for this evidence-completion pass: total integrated
campaign executions 0; deterministic seeds 0; finalized heights 0; maximum
round 0; crashes/restarts 0; partitions/heals 0; sync failovers 0; worst
finalization/recovery/catch-up delays not measured.
