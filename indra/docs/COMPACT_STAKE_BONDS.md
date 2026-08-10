# Canonical Stake-Position Releases

INDRA launches with one genesis-native staking model. Canonical state stores
`StakePositionV1` aggregates and immutable `UnbondingTrancheV1` exits; it does
not retain or decode an older bond representation and has no activation or
migration height.

## Release output

Exiting stake creates an immutable tranche. At maturity, consensus creates a
fresh UTXO for the tranche value using the tranche's recorded owner, lock
height, and deterministic refund blinding. The output commitment and range
proof are regenerated together, so the release is independently verifiable
and its UTXO ID is derived from the new canonical output and block location.

The refund blinding is derived by the canonical
`derive_tranche_refund_blinding_v1` domain-separated construction from the
tranche identity and release context. Wallets recover it from the tranche
provenance embedded in the resulting UTXO rather than from a historical bond
record.

## Custody

- Delegated positions resolve custody through the registered delegator
  identity.
- Validator self positions resolve custody through the validator's full
  current cold hybrid identity.
- Consensus never substitutes an empty/default owner key.

## Wallet behavior

Wallets scan canonical outputs, validate their embedded tranche provenance,
derive the refund blinding, and persist the resulting UTXO location and value.
No old-output recreation or compatibility decoder is required.
