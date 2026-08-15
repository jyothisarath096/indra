# INDRA Governance Threshold Design

This note records the intended meaning of INDRA's governance
`governance_quorum_bps` and `governance_critical_quorum_bps` parameters.
The field names are kept for API stability, but their semantics are
deliberately more conservative than a conventional participation-quorum
system.

## What the threshold measures

For a proposal to pass, YES stake must exceed the configured threshold as
a fraction of total possible governance stake at proposal snapshot time:

```text
yes_stake > quorum_bps / 10_000 * snapshot_total_stake
```

The comparison is exclusive: exactly reaching the threshold is not
enough. A 50% standard threshold requires strictly more than 50% YES
stake.

The applicable standard or critical threshold is copied into the
proposal record at creation. A later governance parameter change cannot
retroactively change the rule used to tally an already-open proposal.

`snapshot_total_stake` comes from the proposal's governance snapshot,
not from current live stake at tally time. Snapshot 2 may move weight
between revealed validators through governance redelegation, but its
total denominator remains Snapshot 1 total stake.

## What the threshold is not

This is not a participation quorum plus majority vote.

INDRA does not first ask whether enough stake participated and then ask
whether YES beat NO among participants. Instead, passage depends only on
whether YES stake alone exceeds the configured fraction of total snapshot
stake.

Consequences:

- NO votes and abstentions do not directly block a proposal; they simply
  are not YES stake.
- A proposal with large NO stake still passes if YES stake alone clears
  the threshold.
- A proposal where YES beats NO still fails if YES stake is below the
  total-stake threshold.
- Non-participation cannot reduce the amount of YES stake needed for a
  proposal to pass.

## Rationale

This design intentionally closes a common governance failure mode:
low-participation capture. In a participation-quorum-plus-majority model,
a small, organized, motivated minority can pass changes during periods of
ordinary apathy if enough of the rest of the network simply does not
vote. Low turnout is not a rare edge case in governance systems; it is a
normal operating condition.

INDRA chooses the more conservative rule: meaningful changes require
affirmative YES support from a configured fraction of total possible
snapshot stake, regardless of turnout. Apathy cannot help a minority
succeed.

This matches the same project value behind INDRA's monetary immutability:
protocol capture should be structurally hard, even when that makes
routine change slower.

## Tradeoff

The tradeoff is real. This rule makes governance harder to use for
genuinely beneficial or uncontroversial changes if validators are
inattentive rather than opposed. Abstention cannot help a proposal pass;
it only withholds YES stake.

That friction is intentional. INDRA prefers conservative, capture-
resistant governance over easy mutability.
