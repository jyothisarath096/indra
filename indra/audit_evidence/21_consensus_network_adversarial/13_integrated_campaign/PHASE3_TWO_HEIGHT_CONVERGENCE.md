# Phase 3 Step 19F — two-height convergence

Status: CLOSED. Height 1 production finalization succeeds for all four
validators. Height 2 begins with no eligible round-0 proposer; all four nodes
advance through real nil prevote, nil precommit, and precommit-timeout round
transitions until round 5, where a production-eligible proposer creates a
proposal carrying the persisted height-1 QC. All four independently finalize
height 2 with identical canonical tip/state. No production code was changed.

Evidence hardening records state/tip preservation across every empty height-2
round, validates all height-2 vote coordinates, verifies each height-2 QC
against its governing snapshot, checks cleanup and VoteSafetyStore state on all
four validators, and replays height-1 proposal/prevote/precommit traffic on A
with a complete state snapshot remaining unchanged. Focused Step 19F/19E/19D/19C
tests, workspace no-run, and diff-check pass.
Final assertion completion adds production-computed canonical state and
validator-set root equality across all four nodes, explicit locked-value-hash,
PoLC, and valid-proposal cleanup checks, and includes both roots in A's stale
height-1 replay snapshot comparison.
Final evidence pass additionally validates the embedded height-1 QC in the
height-2 proposal against the production snapshot, captures H1 identity before
H2, verifies every H2 QC, and includes canonical cleanup and stale replay
state-root/validator-root checks where represented by production state roots.
