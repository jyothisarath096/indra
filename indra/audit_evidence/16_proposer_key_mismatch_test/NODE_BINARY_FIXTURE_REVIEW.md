# Node binary proposer-authority fixture review

## Final classification

**TEST FIXTURE DEFECT.** Production behavior is correct and no security finding
was discovered.

## Reproduction

The exact failing test is:

```text
tests::top_level_proposer_authority_uses_snapshot_and_matches_driver
```

Its failing assertion was:

```text
snapshot-authorized local validator must remain able to propose
```

at `indra-node/src/bin/node.rs:5768` before the test-only correction.

The task's requested `--bin indra-node` command does not name an existing Cargo
binary target. Cargo reported that the available target is `node`, so the exact
reproducer used was:

```text
cargo test -p indra-node --bin node \
  tests::top_level_proposer_authority_uses_snapshot_and_matches_driver \
  -- --nocapture
```

It deterministically failed with one failed test and 78 filtered tests.

## Invariant versus fixture machinery

The real invariant is that all top-level consumers derive proposer authority
from the same governing consensus snapshot, even after the live validator
registry diverges. The test:

1. builds and stores a snapshot containing the local validator;
2. demotes that validator in the live registry;
3. adds a different active validator only to the live registry;
4. compares elections from the decision, construction, and driver paths;
5. proves the snapshot member remains the sole candidate and the live-only
   validator is excluded; and
6. confirms the snapshot-authorized local validator can propose.

Those assertions are visible at `indra-node/src/bin/node.rs:5737-5778`. The
specific round is not part of the authority invariant. It is only required to
make the deterministic local validator eligible so the final assertion reaches
the positive proposer path.

The fixture constructs the registered classical, PQ, and VRF keys from the same
32-byte `0xD1` seed and commits them in genesis
(`indra-node/src/bin/node.rs:5626-5675`). No foreign-key or snapshot mismatch is
present in this test.

## Why round 7 fails under mainnet `f=3/8`

The governing snapshot contains one validator with all snapshot stake, so
`w/W = 1` and:

```text
p = 1 - (1 - f)^(w/W) = f = 3/8.
```

For full stake, the ideal 512-bit eligibility threshold is `3/8 * 2^512`, whose
big-endian boundary begins `0x60...`. An audit experiment using the exact
production election and VRF path produced this round-7 output:

```text
a98113e3d4b15105ae3bffd95c2d3131f3e8a8b361c7d0cdf0cbdb9e778d734d
3fd5d41720d74be070788fbf736e35ed9be7a5c45b28da5b515cb9fe2781e9b4
```

Because `0xa9... > 0x60...`, round 7 is ineligible. Fixing mainnet `F` also
changes the committed snapshot root, which is bound into the VRF alpha, so this
is not merely the old output tested against a smaller threshold: the exact
deterministic transcript changed with the governing snapshot.

An audit-only exhaustive search over the complete legal round domain `0..1024`
found the first eligible round at **3**. Its output was:

```text
51ae4e5706cff7b1af5c1a6d7d7fcf7377061ca7ab63d2a3fc880fc9ca15a2b6
c3d2a687d01dd08882d2922091c30c62d9681f16b76c665752bf9f2fdefba3ce
```

This is below `0x60...` and production `NodeEngine::is_proposer` returns true.
The temporary search instrumentation was removed after recording the result.

## Test-only correction

The test now defines `ELIGIBLE_ROUND = 3` and supplies it to all three election
construction paths (`indra-node/src/bin/node.rs:5756-5768`). It remains fixed,
deterministic, and within the normative `0..1024` round domain; there is no
open-ended or probabilistic search in the permanent test.

All original security assertions remain intact:

* byte-for-relevant-field equivalence of decision/construction/driver elections;
* exactly one snapshot candidate;
* that candidate is the original local snapshot validator;
* the later live-only validator is absent; and
* the local snapshot validator is genuinely eligible and accepted as proposer.

No production code or consensus behavior changed.

## Production-path conclusion

`proposer_election_for_slot` delegates directly to the driver's snapshot-based
election constructor (`indra-node/src/bin/node.rs:355-361`). The driver obtains
the governing snapshot and constructs `ProposerElection` from it
(`indra-node/src/driver.rs:747-773`). `NodeEngine::is_proposer` then evaluates
the local validator identity/key against those frozen candidates
(`indra-node/src/engine.rs:1186-1193`). The passing round-3 fixture demonstrates
that these paths agree while ignoring the intentionally divergent live registry.

There is no production inconsistency: round 7 is simply a legitimate
non-eligible round, while round 3 exercises the intended positive authority
case.

## Validation

Results:

* The literal requested command with `--bin indra-node`: **not runnable** because
  that binary target does not exist; Cargo identifies the target as `node`.
* Corrected focused command using `--bin node`: **PASS** (`1 passed`, `0 failed`,
  `78 filtered out`).
* `cargo test -p indra-node`: **PASS** — library `268 passed`, `5 ignored`;
  node binary `79 passed`; integration tests `15 passed`; no failures.
* `cargo test --workspace --no-run`: **PASS**.
* `git diff --check`: **PASS**.
