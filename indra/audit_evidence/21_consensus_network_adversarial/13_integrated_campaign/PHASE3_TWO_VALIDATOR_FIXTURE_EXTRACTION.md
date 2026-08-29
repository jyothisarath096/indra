# Step 18A status

Status: EXTRACTED.

The Step 17 setup is embedded in a test that consumes and drops both drivers
inside the same function. Extracting it requires moving the complete manifest
construction and reinitialization sequence into a helper returning two
`ConsensusDriver` values, two `TestValidatorMaterial` values, the sealed bytes,
and both paths. The current test does not retain the intermediate validator
materials or safety-store paths as values, so a mechanical wrapper cannot
preserve semantics. No source changes were made in this pass.

No network traffic, vote processing, QC, or finalization was added.

Implemented `TwoValidatorFixture` and `shared_two_validator_fixture()`, returning
both production drivers, validator materials, sealed genesis bytes, durable
directories, and vote-safety paths. The Step 17 test now consumes this helper
and asserts identical genesis bytes plus distinct vote-safety paths.
