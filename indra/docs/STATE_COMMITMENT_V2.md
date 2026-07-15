# StateCommitmentV2 status and scope

`StateCommitmentV2` replaces the legacy validator/delegation/staking
commitment rule after `STATE_COMMITMENT_V2_HEIGHT`.

The old rule rebuilt a sorted leaf vector for every validator, delegator,
staking nonce, staked bond, applied slash hash, and delegation-return event,
then Merkleized that full vector whenever a block root was computed. That made
validator-set root computation O(total validator/delegation/staking state) per
block.

The V2 rule uses an incrementally updated sparse Merkle commitment with keys:

```text
SHA256("INDRA-state-v2-key:" || domain || raw_key_bytes)
```

The committed domains are intentionally narrow:

- `0x01` validators
- `0x02` delegators
- `0x03` staking nonces
- `0x04` staked bonds
- `0x05` applied slash hashes
- `0x06` delegation-return events

The canonical state maps remain the source of truth. The V2 commitment is a
derived cache and its internal sparse-Merkle nodes are not encoded as
consensus-critical snapshot state. On startup/snapshot decode, a node may
rebuild the V2 cache deterministically from canonical state.

## Explicit non-goals

This work does not solve three separate scale costs:

1. Full `ChainState` cloning during block-production projection and sync
   verification remains O(total state).
2. `DelegationMap` still stores per-validator delegators in a `Vec`, so lookup
   of one delegator under a heavily delegated validator is still linear.
3. Epoch reward distribution still touches every delegator whose rewards are
   updated. That is inherent to the current eager reward-accounting model.

Those are real follow-up scalability items. Completing StateCommitmentV2 means
the validator/delegation/staking root itself is no longer fully rebuilt on
ordinary per-block updates; it does not mean every multi-million-delegator
cost has disappeared.

## Activation note

`STATE_COMMITMENT_V2_HEIGHT` is a hard-fork activation height. It is currently
unscheduled in source. Before mainnet genesis, it must be deliberately reviewed
with every other hardcoded activation height listed in
`docs/MAINNET_VALIDATOR_REQUIREMENTS.md`.
