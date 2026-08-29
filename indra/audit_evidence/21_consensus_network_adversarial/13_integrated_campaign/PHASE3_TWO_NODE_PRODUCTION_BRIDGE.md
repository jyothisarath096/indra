# Phase 3 two-node production bridge

Status: EXECUTED (test-only bridge).

Test: `audit_harness_two_production_nodes_exchange_real_vote` in
`indra-node/src/driver.rs`.

The test constructs two real `ConsensusDriver` instances through the canonical
`local_driver` fixture, each backed by a real `NodeEngine` and
`VoteSafetyStore`. Driver A calls `sign_and_record_local_vote`, yielding the
real `DriverAction::BroadcastVote(VoteV1)`. The signed `VoteV1` is placed in a
deterministic FIFO scheduler queue and then delivered to Driver B via
`DriverEvent::InboundVote`; B processes it through `ConsensusDriver::process`
and its production vote admission path.

The transport is represented by a test-only queue; no direct consensus method
is called across nodes. No cryptography or validation is bypassed.

Limitation: both fixture instances use the same deterministic local validator
seed because the existing canonical `local_driver` fixture creates a one-
validator genesis. Thus this proves two production nodes exchanging a real
vote, but not yet a distinct multi-validator authority set. That broader
fixture work is explicitly deferred to the next step.
