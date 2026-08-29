# VRF-006 round-domain reproducer

## Remediation regression result

VRF-006 is fixed. The normative domain is `0..1024`: rounds 0 and 1023 are
accepted, while 1024, 1025, and `u32::MAX` fail before consensus mutation.
The former positive reproducer is retained in repository history; this harness
is its permanent negative regression.

At round 1023, precommit timeout now returns the explicit deterministic
`RoundLimitExceeded` error without changing round, phase, pending proposals,
vote collectors, or lock/valid state. It never constructs round 1024.

## Historical result

`u32::MAX` is part of the admitted production round domain. At that round the
precommit-timeout transition is:

```text
start_round(u32::MAX.saturating_add(1)) == start_round(u32::MAX)
```

The phase changes from `Precommit` to `Propose`, but the round cannot advance.
If no block commits at that round, later timeout cycles return to the same
round forever. Classification: **REACHABLE LIVENESS FAILURE**.

## Deterministic boundary harness

Run from the repository root:

```bash
cargo run --manifest-path audit_evidence/15_round_domain/harness/Cargo.toml --quiet
```

Current observed output:

```text
round-domain regression: PASS (0/1023 accepted; 1024/1025/MAX rejected)
```

The harness uses the real canonical codecs for `BlockHeaderVNext`, `VoteV1`,
`QuorumCertificateV1`, and `VoteSafetyStore`. For legal rounds it also creates
full Ed25519+ML-DSA-87 precommits, builds one-member strict-quorum QCs, and
passes them through production `verify_qc`. It exercises:

```text
0
1023 (accepted)
1024
1025
4294967295 (rejected)
```

The unused `proposer_slot_index` abstraction and its aliasing contract were
removed.

## Smallest terminal state

The smallest terminal state is:

```text
height = any uncommitted non-genesis height
current_round = 4294967295
current_phase = Precommit
sync.is_caught_up() = true
```

One `on_precommit_timeout()` call yields:

```text
current_round = 4294967295
current_phase = Propose
```

After propose and prevote timeouts return the driver to `Precommit`, the next
precommit timeout repeats the same transition. No state invariant converts the
overflow into an error, height change, or shutdown.

## Reachability

Ordinary empty-round progression reaches the state after `2^32-1` successful
increments. With the current 8s/3s/3s phase timeouts, that is at least
`60,129,542,130` seconds, approximately `1,905.7` years, absent faster valid
round certificates.

A strict->2/3 hybrid-signed vote union may advance at most eight rounds per
certificate. Repeated certificates can therefore reach `u32::MAX`, but doing
so quickly requires quorum cooperation; Byzantine stake within the protocol's
`<1/3` assumption cannot manufacture the certificates. A proposal, status, QC,
or lone peer cannot independently force the jump.

A structurally valid local vote-safety record at `round=u32::MAX` restores via
`record.round.saturating_add(1)` to the same maximum immediately. A genuine
persisted lock at that round additionally requires an independently verified
proposal and strict->2/3 prevote PoLC. Merely rewriting the local CRC-protected
file is a local-compromise/corruption scenario, not a remote consensus-valid
path.
