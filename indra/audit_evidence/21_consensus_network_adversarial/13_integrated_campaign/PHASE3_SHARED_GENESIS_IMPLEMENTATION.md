# Shared-genesis distinct-validator fixture implementation

Implemented test-only helpers `TestValidatorMaterial`,
`test_validator_material`, and `render_test_validator_record` in
`indra-node/src/driver.rs`.

The focused fixture test generates distinct deterministic hot/PQ/VRF/cold
material for validators A and B, appends B's production validator record to A's
manifest, seals one manifest with `seal_test_genesis_fixture`, writes identical
bytes to separate directories, and initializes both nodes with production
`NodeEngine::init`, `VoteSafetyStore::open`, and `ConsensusDriver` setup.

Assertions prove distinct identities, shared authority membership, identical
genesis fingerprint, and distinct durable directories. A separate negative test
proves a validator absent from the genesis is rejected by production
initialization.

This step does not implement network exchange, QC, finalization, restart,
partition, GST, or chaos campaigns.

Current source hash: `indra-node/src/driver.rs`
`9ee2a1de3bb2b99d6916d71f25c3ed7f6b1d5ea9e86e38f6e0e048218ae1f4a6`.
The exported diff is the complete unified `git diff` for that file; because the
working tree contains earlier unrelated changes, it necessarily includes those
adjacent hunks as well as the Step 17 test-only additions.
