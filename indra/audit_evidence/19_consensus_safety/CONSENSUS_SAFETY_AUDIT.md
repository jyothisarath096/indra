# Layer 3 Phase 1 continuation — consensus safety

Source revision: `b6404ccacc508d92a022f50ad1af3da4d4e31a02` (working tree includes the reviewed L3-CS-01 remediation).

Scope: vote uniqueness, crash consistency, hybrid authorization, locks, PoLCs,
QC finality, height isolation, restart, verification order and concurrency. The
closed L3-CS-01 snapshot binding was exercised only as a regression dependency.

## Result

No mandatory safety stop condition was reproduced. One bounded admission-order
finding remains: future-height proposals are retained before proposer/QC/state
validation. They cannot vote, lock, finalize, or gossip before re-admission, but
this fails the stronger requested rule that a canonically state-invalid proposal
must not enter *any* pending-proposal container.

| ID | Severity | Description | Status |
|---|---|---|---|
| L3-CS-02 | LOW | Future/wrong-parent decoded proposals previously entered `future_proposals` before full validation. | FIXED — future/wrong-parent proposals are dropped and the container/activation surface was deleted; see `L3_CS_02_REMEDIATION.md`. |

## Classifications

| Area | Classification | Evidence |
|---|---|---|
| quorum arithmetic | PASS | One strict `u128` predicate, `signed*3 > total*2` (`indra-core/src/types/primitives.rs:375-393`), used by collectors, QCs and round advance. Snapshot weight summation is checked (`indra-core/src/types/consensus_snapshot.rs:300-307`). Exact model covered 4 equal, 7 unequal, 200 equal and `u64::MAX` total. |
| vote uniqueness | PASS | Local duplicate check precedes persistence (`indra-node/src/driver.rs:1317-1319`); the durable record precedes signing (`:1331-1349`); restart skips the entire last-voted round (`:896-918`). Thus a crash cannot return to the same signing slot. |
| crash consistency | PASS | Atomic file+directory sync occurs before signing; detailed matrix is in `crash_consistency.md`. |
| hybrid vote authorization | PASS | One byte vector, including snapshot root, is passed once to `HybridKeypair::sign`; both components sign it (`indra-core/src/types/vote_signing.rs:11-31`; `indra-crypto/src/hybrid.rs:248-254`). Verification requires both on that same vector (`indra-crypto/src/hybrid.rs:349-360`). Cross-vote half recombination therefore fails cryptographically. |
| lock safety | PASS | Rule 2 nil-prevotes a conflicting unlocked proposal; Rule 3 requires a genuine earlier-round PoLC and `locked_round <= polc_round` (`indra-node/src/driver.rs:1231-1284`). Same-round conflicting PoLCs require >1/3 double-signing stake and are unreachable under the assumption. |
| PoLC safety | PASS | Restored PoLC votes are exact-decoded, root-bound votes; restart reconstructs the canonical snapshot collector and demands strict quorum for the locked full hash (`indra-storage/src/vote_safety.rs:214-256`; `indra-node/src/driver.rs:813-866`). Chain/height/round/step/value/validator/snapshot are signature or collector dimensions. |
| conflicting-QC resistance | PASS | Two strict quorums intersect in strictly more than one third. With <1/3 Byzantine weight an honest signer lies in the intersection; durable vote uniqueness and locks prevent its conflicting authorization. Production tests and the independent exact model agree. |
| height isolation | PASS | Vote admission requires `vote.height == next_height` before any observation/collector mutation (`indra-node/src/driver.rs:1558-1572`). Commit clears height state and retains only greater heights (`:2099-2129`). Stale proposals return before staging (`:1397-1401`). |
| restart safety | PASS | Genuine locks are independently reverified before assignment; invalid lock height, proposal, PoLC, quorum or snapshot fails closed (`indra-node/src/driver.rs:813-928`). Final-round records deterministically disable voting rather than roll over (`:896-910`). |
| verification-order safety | PASS | Current-height proposals pass proposer/QC verification and detached state projection before pending/vote/lock/gossip mutation. Future and wrong-parent proposals are now dropped before any consensus-container mutation. |
| concurrency safety | PASS | All driver transitions execute under one `Arc<Mutex<ConsensusDriver>>`; inbound messages and timeout callbacks acquire the same mutex (`indra-node/src/bin/node.rs:3113-3126,3436-3493`). Persistence and synchronous hybrid signing occur within that serialized transition. |

## Lock/PoLC rule derived from code

For a proposal at current round `R` and current lock `(V,r)`:

| Proposal | Result |
|---|---|
| same full block `V`, no PoLC | prevote block |
| conflicting block, no PoLC | prevote nil |
| conflicting stable value, PoLC `< r` | prevote nil |
| conflicting stable value, PoLC `= r` | code permits only if a strict PoLC exists; a conflicting one is impossible without >1/3 equivocation |
| conflicting stable value, PoLC `> r` and `< R` | prevote block after the genuine PoLC is present |
| claimed PoLC without strict collected prevotes | prevote nil |

The PoLC field alone is not trusted: `has_quorum_for_value_hash` consults the
verified collector (`indra-node/src/driver.rs:1263-1275`). A lock is created
only after a non-nil prevote quorum (`:1832-1879`) and is persisted with those
votes before the local precommit is signed.

## Verification-order detail

`verify_proposal`, embedded-QC verification, and `project_block_for_roots`
precede insertion into `pending_blocks` and broadcast for the current height
(`indra-node/src/driver.rs:1423-1505`). Projection failure covers invalid
transaction, monetary and staking transitions; root comparisons cover state,
validator-set and stable-value identities (`:1470-1484`). The preserved VRF-007
test confirms no pending, collector or lock change on a cryptographically
authorized but canonically wrong value hash (`indra-node/src/driver.rs:5681-5778`).

L3-CS-02 is narrower: future/wrong-parent proposals are stored before reaching
those checks. They yield only `DriverAction::None`, are not gossiped, and are
reprocessed through normal admission when activated. This is bounded staging,
not a finalized-safety exploit, but it is not the requested strict ordering.

## Exact model and focused results

Run `python3 audit_evidence/19_consensus_safety/finality_model/model.py`. It uses
exact integers, enumerates signer subsets for 4-equal and 7-unequal sets, applies
the intersection theorem to 200 validators, checks a legal distribution totaling
`u64::MAX`, and exhaustively explores depth-seven abstract lock/PoLC/commit traces.
Observed minimum intersections were 2/4, 21/53, 68/200 and
9,223,372,036,854,775,807/18,446,744,073,709,551,615; no conflicting finalized
state was reachable in 17 abstract states.

Focused execution passed 17 QC tests plus crash/restart lock restoration,
lock-before-precommit durability, VRF-007 admission ordering, and high-round
pre-mutation rejection. No production files were modified in this continuation.

## Validation

- `cargo test -p indra-core`: PASS — 144 unit + 21 serialization.
- `cargo test -p indra-storage`: PASS — 45 passed, 1 ignored benchmark.
- `cargo test -p indra-consensus`: PASS — 59 unit + 5 integration.
- `cargo test -p indra-node`: PASS — 271 library (5 ignored), 79 binary,
  15 integration; the three replay tests completed in 886.77 seconds.
- `cargo test --workspace`: BLOCKED by an unrelated timing-sensitive network
  test. `peer_manager::tests::near_duplicate_votes_share_one_validator_identity_budget`
  delivered 81 rather than its fixed expectation of 80 at
  `indra-network/src/peer_manager.rs:1977` in two workspace attempts. The exact
  isolated test passed (80 delivered, 81st dropped). No production change was
  made; this pre-existing rate-limiter test requires separate review.
- `cargo fmt --all -- --check`: PASS.
- `git diff --check`: PASS.
