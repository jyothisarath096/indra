# Distinct-validator authenticated exchange

Implemented `audit_harness_two_distinct_validators_exchange_votes` using the
reusable `shared_two_validator_fixture()`. A and B sign through
`sign_and_record_local_vote`; exact `VoteV1` values are delivered through
`DriverEvent::InboundVote` and `ConsensusDriver::process`. Production collector
state proves A is accepted by B and B by A. A correctly signed vote from
non-authority C is rejected and absent from the collector.

Validation: focused exchange test PASS; workspace no-run PASS; `git diff --check`
PASS. No QC, finalization, restart, partition, or GST behavior was run.

Both A→B and B→A deliveries are now mediated by a deterministic
`VecDeque<VoteV1>` enqueue/dequeue path. The C delivery captures production
actions and asserts `DisconnectInvalidConsensusPeer` with C's validator ID and
the authoritative `Vote validation failed` reason, while C remains absent from
the collector.
