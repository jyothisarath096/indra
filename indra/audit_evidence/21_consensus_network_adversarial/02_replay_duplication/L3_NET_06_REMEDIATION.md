# L3-NET-06 Remediation Evidence

Status: remediation submitted for independent review. This report does not mark L3-NET-06 closed.

## Original root cause and exact production path

A canonical vote enters through encrypted frame/nonce validation and exact
message decoding. The connection read task owns a 512-entry exact vote filter,
so same-connection repeats can be dropped there. That filter resets with the
connection. The actor's 16,384-entry, 10-minute node-wide relay cache suppresses
repeat relay verification/gossip, but the message is still delivered to the
node. Reconnect, replacement connections, alternate relays, expiry, and eviction
therefore reach `ConsensusDriver::process_vote`.

The peer-manager actor charges the authenticated validator's message-count and
byte budgets before relay processing and node delivery. That policy remains
unchanged and survives connection replacement by validator identity.

Before remediation the driver performed:

1. legal round and exact next-height/current+8 checks;
2. governing snapshot lookup;
3. `verify_vote_authority`, including snapshot-root equality, membership/key
   lookup, Ed25519 verification, and ML-DSA-87 verification;
4. slash-detector observation;
5. `seen_round_votes` lookup keyed by validator/height/round/step and storing
   only the accepted block hash;
6. collector/evidence/buffer admission.

An exact cross-path replay repeated steps 2-4, then the driver recognized the
same block hash and returned without a second collector mutation.

## Exact accepted-vote identity

The authoritative map now represents:

```text
(validator_id, height, round, step)
    -> (block_hash, snapshot_root)
```

Chain identity is implicit in the driver and is also cryptographically bound by
the vote transcript. The tuple contains every variable semantic vote dimension:
validator, height, round, step, nil/non-nil block value, and L3-CS-01 snapshot
root. It does not use raw transport bytes or signature bytes. Canonical votes
with equivalent valid signature material therefore retain one consensus identity.

Using only the slot tuple would hide equivocation. Using block hash without
snapshot root would incorrectly collapse a wrong-snapshot object. Both are
explicitly avoided.

## Trusted-validity boundary and source changes

`seen_round_votes` already existed and remains the sole driver replay state. It
is populated only after governing snapshot lookup and successful
`verify_vote_authority`. Invalid or unverified input cannot create an entry.

The driver now constructs the semantic identity after cheap height/round guards
and checks it against this authoritative map before snapshot lookup. Only an
exact match returns immediately. A different block hash or snapshot root proceeds
through the unchanged authoritative path. After successful verification the
existing late check remains, slash observation still precedes it, and the full
identity is stored.

The map value changed from one `Bytes32` to two `Bytes32` values. No new map,
cache, persistence, or network state was added.

Test-only `VoteAdmissionMetrics` counts snapshot lookups, hybrid-authority calls,
successful Ed25519/ML-DSA verification pairs, successful collector insertions,
and QC formation attempts. Successful `verify_vote_authority` necessarily means
the sequential Ed25519 and ML-DSA-87 calls both completed successfully.

## Measured first delivery and replay behavior

| Scenario | Snapshot lookup | Hybrid authority | Ed25519 success | ML-DSA success | Collector insertion | QC formation |
|---|---:|---:|---:|---:|---:|---:|
| First valid remote prevote | 1 | 1 | 1 | 1 | 1 | 0 |
| Exact replay from another peer/replacement path | +0 | +0 | +0 | +0 | +0 | +0 |

The second application emits no driver action, request, gossip, QC, timer/phase
change, or persistent mutation. This removes the snapshot and both hybrid
component verification costs reproduced by L3-NET-06.

The original `L3-NET-06_REPRODUCER.md` is preserved unchanged as before-state
evidence. The updated Phase 2B source-order harness asserts that the trusted
semantic identity check now precedes snapshot and hybrid admission.

## Invalid-first / valid-second

`cryptographically_invalid_vote_cannot_poison_replay_state` begins with an
exact-size vote whose genuine Ed25519 component remains intact but whose
ML-DSA-87 signature bytes are corrupted. It reaches authoritative verification,
is disconnected/rejected, produces no replay entry and no collector insertion.
The genuine vote with the identical semantic tuple then performs full snapshot
and hybrid validation and is accepted once.

The pre-existing `forged_vote_cannot_poison_real_validators_round_slot` also
passes: a different key signing under a real validator ID cannot reserve that
validator's slot, and the later genuine vote is accepted.

## Wrong snapshot result

After one valid vote is accepted, the regression sends a genuinely signed vote
with the same validator, height, round, step, and block hash but another
`snapshot_root`. Because snapshot root is part of `AcceptedVoteIdentity`, it is
not treated as replay. The governing snapshot is looked up, the authoritative
root comparison executes, and the peer is rejected before successful signature
or collector admission. L3-CS-01 semantics remain intact.

## Equivocation result

`conflicting_vote_orderings_bypass_exact_replay_fast_path` tests A-then-B and
B-then-A for one validator/height/round/step/root with distinct block hashes.
In both orders:

- both votes perform snapshot and full hybrid verification;
- the second reaches `SlashDetector::observe_vote`;
- `DriverAction::SlashDetected` is emitted;
- the second is not counted as collector stake and cannot form another QC.

The pre-existing double-precommit regression also passes. The remediation does
not improve or weaken the existing policy that the first slot value remains the
collector value while authenticated conflict evidence is emitted.

## Dimension, stale/finalized, reconnect, and restart results

Votes by the same validator at another round or another step create distinct map
keys and each follow normal snapshot/hybrid/collector admission. A previous-
height/finalized vote fails the unchanged exact-next-height check before replay
lookup, snapshot, or crypto and cannot mutate state.

Driver state is node/consensus scoped rather than connection scoped. Replays from
another authenticated socket take the same fast path while the accepted entry
exists. Reconnect does not multiply accepted-vote state.

Replay state is deliberately not persisted. The restart regression accepts a
vote, reconstructs `ConsensusDriver`, proves `seen_round_votes` is empty, and
proves the replay undergoes full snapshot and hybrid validation once. No new
persistence was introduced merely for optimization.

## Collector, QC, lifecycle, and memory bounds

Collector insertion, strict >2/3 arithmetic, one-vote-per-validator behavior,
mixed-snapshot rejection, QC construction, vote safety, and finality code are
unchanged. The fast path occurs only for an identity already authenticated and
accepted into driver state. Exact replay cannot count stake or build a QC twice.

`seen_round_votes` remains capped at `MAX_STALLED_HEIGHT_ENTRIES = 256`. Each
value grows from 32 to 64 bytes, so value payload at the cap grows from 8,192 to
16,384 bytes, excluding unchanged map overhead. Keys remain fixed size. The map
is pruned around exact next height and the current ±8 round window, cleared on
height finalization and sync catch-up/reset, and reset on process restart.
Validator count per collector remains bounded by the protocol validator cap;
collector count and other stalled collections retain their existing 256-entry
bounds. Legal rounds remain 0..1023.

## Rate-limit and wire interaction

The authenticated validator limiter still runs in `PeerManagerActor::handle_control`
before node delivery and before this driver fast path. Exact cross-path replays
continue to consume the existing validator-level vote count and byte budgets.
No rate-limit exemption or identity change was introduced.

Vote encoding, canonical framing, signed transcript, snapshot-root binding,
signature representation, message discriminator, and network keys are unchanged.
Consensus semantics are unchanged; only computational handling of an already
authenticated exact semantic vote is optimized.

## Validation results

- Exact replay/alternate-peer measured regression: PASS.
- Exact-size cryptographically-invalid-first/valid-second regression: PASS.
- Wrong-snapshot non-collapse regression: PASS.
- Both equivocation arrival orders and existing double-precommit regression: PASS.
- Different-round, different-step, stale/finalized, and restart regressions: PASS.
- Existing bounded-state and forged-validator poisoning regressions: PASS.
- Updated Phase 2B replay harness: PASS.
- `cargo test -p indra-network`: PASS (140 unit, 1 ignored; 4 integration tests).
- `cargo test -p indra-core`: PASS (148 unit; 21 integration tests).
- `cargo test -p indra-consensus`: PASS (59 unit; 5 integration tests).
- `cargo test -p indra-node`: PASS (285 library tests; 79 node-binary and 15 integration tests).
- `cargo test --workspace`: PASS; only declared ignored tests ignored.
- `cargo test --workspace --no-run`: PASS.
- `cargo fmt --all -- --check`: PASS.
- `git diff --check`: PASS.
- Focused diff reverse-application check: PASS.

The repository had extensive pre-existing tracked and untracked changes. They
were preserved and are not attributed to L3-NET-06. The focused diff contains
only this remediation's production, test, and Phase 2B harness changes.

## Review disposition

Focused remediation complete and returned for independent review. L3-NET-06 remains OPEN pending that review.
