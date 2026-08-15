# INDRA Monetary Immutability

This note records the current constitutional boundary between runtime
governance and monetary policy.

## Monetary policy is not governable

Runtime governance must not be able to change:

- the genesis supply;
- the hard cap;
- the validator reward pool;
- reward-era durations;
- per-era block reward constants;
- the block-height schedule that maps a block to its reward amount.

These values live in `indra-core/src/types/primitives.rs` as protocol
constants. The reward schedule is applied by
`indra-state/src/epoch.rs::block_reward_at_height`.

Changing any of these values requires an explicit protocol upgrade or
hard fork. It must not be introduced as a `GovernableAction`.

## What governance can change today

Current on-chain governance is limited to operational, security, and
participation parameters:

- liveness slashing threshold;
- minimum delegation floor;
- proposal deposit;
- slashing basis points for liveness and double-precommit evidence;
- maximum validator commission;
- governance execution delay;
- standard and critical governance YES-stake thresholds.

Some of these are economic in the broad operational sense: they affect
participation costs, slashing penalties, or validator/delegator reward
splits. They do not alter aggregate issuance, the hard cap, era timing,
or the block reward schedule.

## Enforcement

The regression test
`governance_actions_are_constitutionally_non_monetary` exhaustively
classifies every current `GovernableAction` as non-monetary and snapshots
the monetary constants plus representative reward-schedule heights before
and after applying each governance action.

The exhaustive match in that test is intentional. If a new governance
action is added later, the test must be updated deliberately, forcing an
explicit review of whether the new action crosses the monetary-policy
boundary.
