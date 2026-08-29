# Adversarial Network Liveness Audit

## Final disposition

**PASS WITH NON-CRITICAL FINDINGS**. Under the implemented eventual-delivery
assumptions, no <1/3 Byzantine strategy was shown to cause persistent consensus
or synchronization liveness failure. No production code was modified.

## Assumptions and state machine

The protocol uses strict `>2/3` stake quorum, deterministic proposer election,
legal rounds `0..=1023`, and tick-driven timeouts of 8 seconds (propose), 3
seconds (prevote), and 3 seconds (precommit). Sync requests expire after 30
seconds and rotate source. The implementation assumes eventual synchrony and at
least one reachable honest communication path (the deployment assumption carried
from the eclipse audit).

Propose timeout prevotes a verified staged proposal or nil; prevote timeout
precommits nil; precommit timeout advances the round. Late messages are accepted
only for the current legal context and never regress the round. At
`MAX_ROUNDS_PER_HEIGHT - 1`, another precommit timeout fails closed rather than
wrapping the round.

## Adversarial scenarios

Byzantine proposer silence causes timeout and deterministic next-proposer
selection. Selective vote withholding below one-third leaves honest stake above
the quorum threshold. Selective delivery and late valid votes/QCs are filtered
by height/round/lock/PoLC rules; they may delay a round but do not create a
permanent regression. Sync has one outstanding request and rotates after timeout;
responses are source-bound.

Locked validators can unlock only with valid PoLC evidence. A proposal without
required evidence is rejected, while a valid reproposal remains reachable.
Valid stale traffic is ignored at current-state gates and does not mutate current
round state.

## Round exhaustion

Driver tests explicitly cover final-round timeout: round advancement stops at the
maximum and returns an error without unsafe wraparound or state mutation. This is
a fail-closed terminal condition requiring recovery/synchronization rather than
an infinite loop.

## Residual liveness assumptions

The audit does not claim liveness during a total network partition, absence of
all honest bootstrap roots, or scheduler starvation. Timeout values are fixed
rather than exponentially adaptive, so severe but finite delay can cause extra
rounds; no persistent failure was reproduced after delivery resumes.

## Validation

Existing deterministic tests cover proposer silence/timeout transitions, selective
votes, stale/future messages, PoLC lock behavior, late QC handling, sync timeout
rotation, and final-round fail-closed behavior. `cargo test -p indra-consensus`,
`cargo test -p indra-node --lib`, `cargo fmt --all -- --check`, and `git diff
--check` passed in the preceding audit runs. No production files were changed.
