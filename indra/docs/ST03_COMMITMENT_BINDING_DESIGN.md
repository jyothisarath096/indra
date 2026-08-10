# ST-03 Per-Output Commitment Binding

## Status

Resolved in the canonical genesis-native transaction and staking formats.
There is no activation height, proofless staking-operation tag, or legacy raw
FFI builder.

## Invariant

Every staking deposit carries `StakeDepositProof` containing the public bonded
value and the commitment blinding. Authoritative validation checks that:

1. the referenced UTXO exists and is unspent;
2. the operation has the required logical owner and custody authority;
3. the supplied value/blinding opens that exact UTXO commitment; and
4. the public `value_spark` equals the value committed by that opening.

Only after all four checks succeed may consensus spend the UTXO and credit the
derived stake position. Failure is atomic and cannot consume the source UTXO.

## Canonical operation builders

The Rust CLI builders for `RegisterValidator`, `SelfStake`, and `Delegate`
require the committed value and blinding. CLI commands obtain them from the
wallet's canonical UTXO record.

The C ABI exposes only opaque-handle staking builders:

- `indra_build_register_validator_with_handle`;
- `indra_build_self_stake_with_handle`; and
- `indra_build_delegate_with_handle`.

Each receives `bond_value_spark` and a 32-byte deposit blinding, validates
pointers and output bounds, resolves signing material through the opaque
handle, and emits the single canonical staking encoding. Raw private-key
builders do not exist.

## Privacy boundary

Revealing a staking deposit opening links the public staking action to its
source output. This is intentional because bonded value is consensus-visible.
The opening proves commitment consistency but never substitutes for ownership
or custody authorization.

Wallets must retain UTXO blindings, must not log them, and must zero temporary
FFI/Rust buffers where practical.

## Required tests

- matching value/blinding succeeds for registration, self stake, and delegate;
- wrong value or blinding fails without spending the UTXO;
- incorrect logical owner or custody key fails independently;
- duplicate UTXO consumption fails within and across transactions; and
- opaque-handle builders round-trip through canonical decode and signature
  verification.
