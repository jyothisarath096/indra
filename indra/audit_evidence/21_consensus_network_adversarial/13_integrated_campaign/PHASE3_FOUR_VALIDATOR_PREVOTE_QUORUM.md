# Four-validator strict prevote quorum

Using `shared_four_validator_fixture()`, one production proposal was staged on
all four drivers. Three validators produced prevotes through
`on_propose_timeout`; A observed its own vote plus B, then C. At two of four
votes the production decision remained below quorum. At three of four, the
production collector reached `VoteDecision::QuorumReached`, transitioned A to
Precommit, locked the proposal, and emitted one production precommit. No
precommits were distributed and no finalization occurred; height remained 0.

Focused test and regressions passed; workspace no-run and diff check passed.

Evidence hardening now records explicit A/B/C/D signer identities and vote
coordinates, the 1/4 and 2/4 non-quorum states, exact local precommit fields,
lock state, and retained PoLC membership (A/B/C present, D absent).

Final completion additionally asserts the 1/4 and 2/4 no-lock/no-valid-value
states, exact quorum block hash, exactly one generated precommit, complete
precommit fields, PoLC vote fields and snapshot binding, full replay state and
metrics equality, and cleanup of all four directories.

Step 19C.3 assertion-only closure validation: focused strict-prevote test PASS;
`cargo test --workspace --no-run --quiet` PASS; `git diff --check` PASS. The
post-B assertions explicitly remain in Prevote at height 0 with no QC. The
post-C assertions require Precommit, valid/locked round and value `(0, hash)`,
height 0, and no QC. The emitted precommit tuple includes step `Precommit`.
Each retained PoLC vote is checked for height 1, round 0, Prevote step, the
proposal hash, and the governing height-1 snapshot root; the signer set length
is exactly three (A/B/C, excluding D).
