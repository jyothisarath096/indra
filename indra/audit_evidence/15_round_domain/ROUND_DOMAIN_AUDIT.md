# INDRA VRF-006 — round-domain reachability audit

## Remediation status

```text
VRF-006 — LOW — FIXED
normative domain: 0 <= round < 1024
highest legal round: 1023
```

All canonical decoders, cryptographic production/verification boundaries,
live transitions, and vote/lock persistence now use the authoritative core
round validator. The PoLC sentinel was replaced by canonical `Option<u32>`,
block format advanced from 3 to 4, and persisted schema/safety formats were
advanced without legacy decoders. The remainder of this document preserves the
pre-remediation reachability analysis.

## Classification

```text
REACHABLE LIVENESS FAILURE
```

Severity: **LOW**. The terminal state is real and fail-open with respect to
liveness, but honest timeout-only reachability takes approximately 1,906 years.
Rapid network-assisted reachability requires strict >2/3 stake to sign a long
sequence of higher-round votes, a coalition that can already halt consensus.
No single peer or <1/3 Byzantine coalition can force it. Local safety-file
tampering can reach it immediately but is outside the remote threat model.

The premise that `MAX_ROUNDS_PER_HEIGHT=1024` prevents saturation is false.
The constant's own contract says it is only used to derive a slot index and is
not a retry cap (`indra-core/src/types/primitives.rs:54-58`). Its only
production consumer uses saturating `height*1024+round`
(`indra-consensus/src/proposer.rs:113-118`), and that result has no downstream
consumer.

## Round representation inventory

| Object/state | Type and source | Decode/validation | Mutation/persistence | Result |
|---|---|---|---|---|
| `BlockHeaderVNext.proposer_round` | `u32`, proposer/peer | raw canonical `u32_le`; no domain cap (`block.rs:176-181,288-308`) | producer/reproposal assigns election round | all five boundary values decode |
| `ProposalEntropyV1.origin_round` | `u32`, first proposer | raw `u32_le`; VRF alpha cryptographically binds it, but no cap (`block.rs:89-97`; `proposal.rs:164-191`) | immutable across reproposals | all `u32` values representable |
| `BlockHeaderVNext.polc_round` | `u32`, proposer | raw `u32_le`; checked relative to current/locked round in driver | copied from `valid_round` | `u32::MAX` is reserved as `NO_POLC_ROUND`, so a real PoLC at max is not representable |
| `VoteV1.round` | `u32`, signer/peer | raw `u32_le`; signature binds round; collector requires exact equality (`vote.rs:35-78`; consensus `vote.rs:132-136`) | driver collects by `(height,round,step)` | no global cap |
| `QuorumCertificateV1.round` | `u32`, QC builder/peer | raw `u32_le`; every hybrid signature is reverified over it (`qc.rs:51-69,130-190`) | stored in block/last-QC cache | no global cap |
| driver `current_round` | `u32`, local state machine | not wire-decoded directly | `start_round`, timeout, or certified jump (`driver.rs:730-733,1618-1659,2271-2277`) | full domain |
| `locked_round` / `valid_round` | `Option<u32>`, verified prevote PoLC | restored PoLC signatures/quorum are reverified, but round is uncapped (`driver.rs:807-855`) | set on prevote quorum; lock persisted | full domain; max lock is possible |
| vote-safety `round` | `u32`, latest locally cast vote | canonical `u32_le`, CRC, exact framing, no cap (`vote_safety.rs:41-51,185-230`) | atomic pre-vote write; restart uses saturating `+1` | max restores max |
| persisted lock round | `u32`, verified lock | structural decode then proposal+PoLC revalidation | restored into locked and valid rounds | no cap |
| peer status round | `u32`, peer assertion | network frame decodes it; driver treats it as informational | never advances round | harmless at boundary |
| timeout phase round | driver `u32` | internal | precommit timeout uses saturating `+1` | max repeats forever |

All integer encodings are fixed-width little-endian and exact decoding rejects
trailing bytes. Canonical framing therefore prevents aliases, but does not
restrict the mathematical round domain.

## Increment inventory

Production round advancement occurs at three sites:

1. Local Rule-10 timeout calls
   `start_round(current_round.saturating_add(1))`
   (`indra-node/src/driver.rs:2271-2277`).
2. A strict->2/3 hybrid-signed vote union calls `start_round(target_round)`;
   the target must be greater than current and at most current+8
   (`driver.rs:1618-1659`).
3. Restart reconstruction uses `record.round.saturating_add(1)` and calls
   `start_round` (`driver.rs:886-894`).

There are no checked or wrapping round increments. Both increments that add
one saturate at `u32::MAX`.

## Meaning and enforcement of 1024

`MAX_ROUNDS_PER_HEIGHT` is neither wire validation nor a local resource cap.
It is not consulted by proposal verification, vote admission, QC verification,
PoLC verification, timeout progression, sync/replay, or persistence. Therefore:

```text
1023 -> 1024: allowed
1024 -> 1025: allowed
```

The actual per-message defense is `MAX_ACCEPTED_ROUND_JUMP=8`, explicitly
secondary to quorum evidence (`driver.rs:43-47`). Vote admission and certified
advance use `current_round.saturating_add(8)` (`driver.rs:1519-1526,
1618-1628`). Repeated valid certificates are not globally capped.

## Boundary behavior by path

| Path | 1023 / 1024 / 1025 / MAX-1 / MAX |
|---|---|
| Proposal decode | **ACCEPTED BUT NOT REACHABLE** from a low current round; decode itself accepts all. A cryptographically valid future proposal is staged but does not advance the driver. It becomes reachable when certified/current round matches. |
| Vote decode | accepts all; live admission is **REJECTED BEFORE STATE MUTATION** when more than current+8, otherwise accepted after signature verification. |
| QC decode/verification | accepts all round values when the strict-quorum hybrid signatures are valid. QC round is signed but uncapped. |
| PoLC verification | accepts signed prevote rounds throughout the domain; proposal `polc_round=MAX` instead denotes “none.” |
| Persisted vote safety | structurally accepts all; max causes restart to start at max. |
| Persisted lock restoration | accepts any round backed by a fully verified proposal and strict-quorum PoLC; no cap check exists. |
| Sync/replay/block application | verified proposals/QCs at these rounds are accepted; application consumes `VerifiedProposal` and does not impose a separate cap. |
| Live driver | values more than +8 cannot advance it; a strict-quorum certificate within +8 can. At max, timeout progress saturates. |

“Accepted but not reachable” above means not immediately reachable from a
fresh round-zero driver by that object alone. It does not mean the round is
outside the protocol domain.

## Network-assisted jumps

- Unsigned status claims cannot advance the driver.
- A valid higher-round proposal is verified, stored, and relayed, but cannot
  advance the round by itself (`driver.rs:1450-1502`).
- A single prevote/precommit cannot advance the round.
- A union of signed prevotes/precommits from strict >2/3 stake at one target
  round is the sole network round-change certificate. Its jump is at most 8.
- QCs certify blocks and can finalize/advance height; they are not an
  unauthenticated round-fast-forward mechanism.

At `current_round=MAX-8`, a valid strict-quorum vote union at `MAX` can move the
node directly to the terminal round. This satisfies the audit's remote,
consensus-valid critical-stop condition, although reaching `MAX-8` under the
honest-fault threshold remains operationally implausible.

## Persistence and restart

The in-memory driver round is reconstructed rather than separately persisted.
The latest vote round and optional lock/PoLC are durable. Restart uses the
latest vote round plus one, saturating. Consequently a canonical record for a
genuine vote at `MAX` restores `current_round=MAX`; it does not fail closed.

Lock restoration verifies proposal authorization, VRF eligibility, every PoLC
vote, block identity, and strict quorum. It does **not** enforce a round cap.
Thus genuine consensus evidence at a high round survives restart exactly, but
also preserves the saturation state.

## Secondary observations

1. `NO_POLC_ROUND=u32::MAX` overlaps the real round domain. A max-round QC can
   finalize a block, but a later proposal cannot encode “PoLC from max” because
   that byte representation means no PoLC. This does not create an earlier
   failure than saturation, since no round exists after max for such a
   reproposal.
2. `proposer_slot_index` is described as unique but aliases once round reaches
   1024. It is currently unused outside its definition/tests and is not a
   cryptographic input, so this is informational rather than an exploit.

## Final disposition

```text
VRF-006 — LOW — CONFIRMED
smallest terminal round: u32::MAX
attacker threshold for rapid network forcing: strict >2/3 stake
honest timeout-only time at 14 seconds/round: approximately 1,905.7 years
```

No remediation was attempted.

## Pre-remediation validation results

- `cargo test -p indra-core`: PASS (140 unit + 21 serialization tests).
- `cargo test -p indra-consensus`: PASS (54 unit + 5 integration tests).
- `cargo test -p indra-node`: **baseline failure unrelated to this audit
  artifact** (263 passed, 5 ignored, 1 failed). The failing deterministic test
  is `engine::tests::is_proposer_rejects_registered_vrf_key_mismatch`; its
  bounded eligibility search panics at `indra-node/src/engine.rs:2477`. An
  isolated rerun reproduces the same failure. This audit changed no production
  source and did not remediate it.
- `cargo test --workspace --no-run`: PASS.
- `git diff --check`: PASS.
- boundary harness: PASS, including full hybrid QCs at all five boundary
  rounds.

## Post-remediation validation results

- negative boundary harness: PASS (`0`/`1023` accepted;
  `1024`/`1025`/`u32::MAX` rejected).
- `cargo test -p indra-core`: PASS (143 unit + 21 serialization tests).
- `cargo test -p indra-consensus`: PASS (57 unit + 5 integration tests).
- `cargo test -p indra-node`: the remediation tests pass; the full crate result
  is 266 passed, 5 ignored, and the one explicitly out-of-scope pre-existing
  `is_proposer_rejects_registered_vrf_key_mismatch` failure.
- `cargo test --workspace --no-run`: PASS.
- `git diff --check`: PASS.
