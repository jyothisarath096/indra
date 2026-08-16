# Canonical Stake-Position Releases

INDRA launches with one genesis-native staking model. Canonical state stores
`StakePositionV1` aggregates and immutable `UnbondingTrancheV1` exits. There is
one current representation and no compatibility decoder.

## Release output

Exiting stake creates an immutable tranche. At maturity, consensus resolves its
full hybrid custody key and creates a transparent `OutputV1 { value_spark,
owner_pubkey, lock_height }`. Its UTXO ID is derived from that canonical output
and the synthetic staking coordinate. `TrancheRefundEventV1` is attached to the
unspent UTXO for the same lifetime and binds its position, tranche, principal,
custody, release height, and maturity epoch. It is recovery metadata, not an
independent monetary or authorization mechanism.

## Custody

- Delegated positions resolve custody through the registered delegator
  identity.
- Validator self positions resolve custody through the validator's full
  current cold hybrid identity.
- Consensus never substitutes an empty/default owner key.

## Wallet behavior

Wallets scan canonical outputs by exact full-hybrid-key equality. Joined
tranche provenance is returned by RPC only after a random, expiring, single-use
challenge is signed by the canonical `PaymentAddressV1` owner. The wallet then
validates and persists the resulting UTXO location and value.
