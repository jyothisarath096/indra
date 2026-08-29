# Proposer key-mismatch regression review

## Final classification

**TEST FIXTURE DEFECT.** No production defect or security finding was found.

The failing test asked `first_eligible_test_election` to search using the node's
foreign local key after the governing snapshot had deliberately been changed to
a different registered key. The helper filters candidates by VRF public key
before evaluating eligibility, so every iteration returned `None`; the panic was
deterministic and did not mean that the VRF sequence lacked an eligible round.

## Exact reproduction

The original command was:

```text
cargo test -p indra-node engine::tests::is_proposer_rejects_registered_vrf_key_mismatch -- --nocapture
```

It failed at the helper's terminal `expect` with:

```text
test proposer must become eligible within bounded round search
```

The pre-fix helper searched `0..4_096`. After the finite-round protocol change,
only `0..1_024` is legal. More importantly, the helper first required a candidate
whose committed public key equalled the supplied key; therefore this mismatch
fixture performed zero eligibility evaluations. The test helper now limits its
other uses to the legal domain (`indra-node/src/engine.rs:2483-2500`), while this
security regression uses a fixed known-eligible round and no search
(`indra-node/src/engine.rs:4390-4433`).

The deterministic fixture was:

| Item | Value |
|---|---|
| validator identity | `29068bb6ce5feb4fbd71ed7e6609e7d227238e1444035a3ed68e8426280316e3` |
| local/foreign VRF seed | 32 bytes of `0x42` |
| local/foreign VRF public key | `2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12` |
| registered VRF seed | 32 bytes of `0x99` |
| registered VRF public key | `332ebe8d27cb7323b3a401c1c13b5dd64bccc0e10ecda1c2b5d11a03779a85e5` |
| snapshot root | `83fcd418cc8f9a1690bb94c402e550824e9333df2a5b7995061878138c4259c2` |
| election seed | `f0e5d3e88680f8b659c208ca593fba6b43c1c508bc93eb824cd2eef81e86971c27deb819bcf50c2097d2434d3fe82a7d2421c3ea1bd461d13cbc5ab8c2b37f66` |
| validator stake `w` | `1,000,000` Spark |
| total stake `W` | `1,000,000` Spark |
| `F` | `6,917,529,027,641,081,856 = 3*2^61` |

The fixture installs one active validator with `1,000,000` Spark and aligns the
local identity/signing keys before deliberately replacing only the state VRF key
(`indra-node/src/engine.rs:1903-1978`, `indra-node/src/engine.rs:4390-4404`).

## Eligibility analysis

Because `w/W = 1` and `f = 3/8`, the ideal per-round probability is exactly:

```text
p = 1 - (1 - 3/8)^1 = 3/8 = 0.375
```

For an independent ideal VRF sequence, the probability of no eligible round in
`N` trials is `(5/8)^N`. It is about `9.575e-210` for all 1,024 legal rounds.
That statistic did not explain the observed failure: the mismatched key was
absent from the candidates, so the helper rejected it before sortition on every
iteration (`indra-node/src/engine.rs:2488-2498`).

An audit-only search using the actually registered `0x99` key found the first
eligible legal round at **13**. The permanent test pins round 13 rather than
depending on a bounded search (`indra-node/src/engine.rs:4405-4433`). This is
classification A from the task: an eligible legal round exists, but the old
fixture/helper composition was invalid for the asserted property.

## Security invariant and production-path review

The security assertion is that a node cannot derive proposer authority for a
validator identity using a VRF key different from the key committed for that
identity in the governing snapshot. Eligibility discovery is only fixture
machinery.

The production path preserves the invariant:

1. `ProposerElection::from_snapshot` copies each identity, VRF key, and frozen
   stake directly from the validated snapshot (`indra-consensus/src/proposer.rs:58-94`).
2. `compute_proposer_vrf` requires one candidate matching **both** validator ID
   and the local keypair's public key before it creates/evaluates a proof
   (`indra-consensus/src/proposer.rs:113-150`).
3. `NodeEngine::is_proposer` supplies only its configured validator identity and
   local VRF keypair to that function (`indra-node/src/engine.rs:1186-1193`).
4. Block production repeats the same check and propagates failure before block
   construction (`indra-node/src/engine.rs:1327-1339`).
5. Incoming proposal verification looks up the proposer in the governing
   snapshot and verifies the proof against that entry's committed VRF key; it
   does not accept a key supplied by the proposal (`indra-core/src/types/proposal.rs:109-153`).

The repaired regression constructs a proof that is cryptographically valid for
the foreign `0x42` key and the exact round-13 alpha, proves that it verifies under
that foreign key, proves it fails under the registered `0x99` key, proves the
registered key is genuinely eligible, and then verifies that both
`compute_proposer_vrf` and `NodeEngine` reject the foreign local key
(`indra-node/src/engine.rs:4408-4445`). Thus the assertion no longer relies on
corrupted proof bytes or random eligibility discovery.

## Change scope

Only test code and this audit artifact changed for this review. Production
consensus behavior did not change. The shared test helper's range was narrowed
from the obsolete `0..4_096` bound to the normative legal `0..1_024` domain.

## Validation

Results:

* Focused regression: **PASS** (`1 passed`, `0 failed`).
* `indra-node` library tests: **PASS** (`268 passed`, `0 failed`, `5 ignored`).
* Full `cargo test -p indra-node`: the library and integration surfaces passed,
  but the separate binary test
  `tests::top_level_proposer_authority_uses_snapshot_and_matches_driver` failed
  at `indra-node/src/bin/node.rs:5768`; its fixed-round fixture asserts
  eligibility under `f=3/8`. It is unrelated to the reviewed key-mismatch test
  and was not changed in this task.
* `cargo test --workspace --no-run`: **PASS**.
* `git diff --check`: **PASS**.
