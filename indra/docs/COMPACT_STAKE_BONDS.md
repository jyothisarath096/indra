# Compact Stake-Bond Releases

`COMPACT_STAKE_BOND_HEIGHT` is the hard-fork height for compact stake-bond
records. It is currently set to `u64::MAX`, so compact bond creation is inert
until a coordinated activation height is deliberately selected.

Before activation, newly created `StakeBondEntry` records store the bonded
output's full `OutputV1`, including its Bulletproof range proof. At or after
activation, newly created bond records omit the stored range proof. Existing
legacy bonds are not migrated or rewritten; they keep their stored proof until
they are released and naturally leave staking state.

## Compact Release Output

When a compact bond is released, the chain does not recreate the original output
byte-for-byte. Instead it creates a fresh valid UTXO for the released value:

- owner public key: copied from the bonded output metadata
- lock height: copied from the bonded output metadata
- value: the released `amount_spark`
- commitment: freshly computed from `amount_spark` and the deterministic compact
  release blinding
- range proof: freshly generated for that same value and blinding

Because the output commitment and range proof are fresh, the released compact
bond UTXO has a different UTXO ID than the original staked output. This is
expected: INDRA UTXO IDs are `sha256(encode(output) || height_le || tx_idx_le ||
out_idx_le)`, so changing the output bytes changes the UTXO ID.

## Deterministic Release Blinding

Wallets can reconstruct the blinding for a released compact bond using only
public chain data.

The blinding is:

```text
sha256(
    COMPACT_STAKE_BOND_RELEASE_BLINDING_DOMAIN
    || validator_id
    || delegator_id
    || bond_utxo_id
    || release_height_le
    || released_amount_spark_le
)
```

Where:

- `COMPACT_STAKE_BOND_RELEASE_BLINDING_DOMAIN` is the exact byte string
  `INDRA-compact-stake-bond-release-v1`.
- `validator_id` is the 32-byte validator ID stored in the bond record.
- `delegator_id` is the 32-byte delegator ID stored in the bond record.
- `bond_utxo_id` is the 32-byte original bonded UTXO ID stored in the bond record.
- `release_height_le` is the release block height as an 8-byte little-endian
  unsigned integer.
- `released_amount_spark_le` is the released `amount_spark` as an 8-byte
  little-endian unsigned integer.

For epoch-boundary unbonding releases, `release_height` is
`current_epoch * EPOCH_DURATION_BLOCKS`, matching consensus release logic. For
forced validator-eviction refunds, `release_height` is the block height at which
the eviction refund is inserted.

## Wallet Behavior

To spend a released compact bond, a wallet or indexer should:

1. Find the released UTXO owned by the wallet's public key.
2. Locate the corresponding bond return event or staking history entry to obtain
   `validator_id`, `delegator_id`, `bond_utxo_id`, `release_height`, and
   `released_amount_spark`.
3. Recompute the deterministic compact release blinding exactly as specified
   above.
4. Store the released UTXO ID, value, location, and reconstructed blinding in the
   wallet.

The regenerated commitment and range proof are consensus-created and verifiable
like any other output. Wallets do not need the original bonded output's range
proof to spend a compact release.
