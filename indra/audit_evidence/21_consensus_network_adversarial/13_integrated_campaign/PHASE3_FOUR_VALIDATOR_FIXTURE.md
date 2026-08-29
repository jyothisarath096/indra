# Four-validator shared-genesis fixture

Implemented test-only fixture test `audit_fixture_shared_genesis_four_distinct_validators`.
It creates four deterministic validators with equal stake (1,000,000 each),
renders all records before a single `seal_test_genesis_fixture` call, writes the
same sealed bytes to four independent directories, and initializes four real
`NodeEngine`/`VoteSafetyStore`/`ConsensusDriver` instances.

Assertions cover pairwise-distinct identities, common genesis fingerprint,
authority membership, common height/tip and snapshot root, byte-identical
genesis files, and pairwise-distinct durable/safety paths. No consensus traffic,
QC, or finalization was run.

The construction is now owned by `FourValidatorFixture` and
`shared_four_validator_fixture()`. The focused test consumes the returned live
drivers/materials/sealed bytes/directories/safety paths, asserts equal snapshot
weights and initial height/tip, then performs test-only cleanup.
