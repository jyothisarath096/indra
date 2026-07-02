# ST-03 Per-Output Commitment Binding — Design Document

## Root Cause Analysis

ST-03 is a staking-specific consequence of the public-value / private-commitment split documented in Phase 2 T-08.

`OutputV1` currently contains both a public accounting value and a confidential commitment:

- `value_spark: u64`
- `commitment: CommitmentV1`
- `owner_pubkey: HybridPubKey`
- `range_proof: VariableBytes<MAX_RANGE_PROOF_BYTES>`
- `lock_height: u64`

Code evidence: `indra-core/src/types/transaction.rs:57-75`.

The current transaction validator checks two separate things:

1. Public arithmetic: the sum of input `value_spark` values equals output `value_spark` values plus fee (`indra-state/src/apply.rs:637-713`).
2. Commitment arithmetic: input commitments equal output commitments plus fee commitment (`indra-state/src/apply.rs:715-733`).

It also verifies every range proof against the exact `output.commitment` that will be stored (`indra-state/src/apply.rs:722-726`), and verifies the fee commitment opening (`indra-state/src/apply.rs:676-683`).

What it does not verify is: for each individual output, `output.value_spark` equals the value hidden inside `output.commitment`.

The staking layer then consumes `value_spark` directly as economic stake:

- `RegisterValidator`: reads `utxo_entry.output.value_spark` as the atomic registration self-bond (`indra-state/src/delegation.rs:257-263`).
- `Delegate`: reads `utxo_entry.output.value_spark` as delegated stake (`indra-state/src/delegation.rs:359-365`).
- `SelfStake`: reads `utxo_entry.output.value_spark` as validator self-stake (`indra-state/src/delegation.rs:477-483`).

Each path stores the original output in `StakeBondEntry.original_output` before spending the UTXO into `staked_bonds`. On release, `release_unbonded_bonds` removes the bond and calls `released_bond_output`; when the bond is not reduced, the original output can be returned directly (`indra-state/src/epoch.rs:778-814`).

That produces the ST-03 risk: a staking operation may credit stake using public metadata that is not individually bound to the commitment that later comes back out of the staking pool.

## Why Explicit Opening (Approach A) is Correct

Approach A is to require the staker to reveal the exact Pedersen opening `(value, blinding)` for any UTXO used as stake, and to verify:

```text
Commit(value, blinding) == output.commitment
value == output.value_spark
```

This is the right model for staking because INDRA staking is already public:

- Validator and active-set stake must be public for consensus quorum and proposer/reward calculations.
- Delegated stake is public accounting in `delegations`.
- RPC exposes validator set and stake summaries as part of normal chain state.
- Phase 4 ST-06 intentionally chose self-stake-based public active-set semantics.

Revealing the blinding factor for a staking bond removes that specific UTXO's commitment privacy, but staking is an explicit public economic act. The tradeoff is acceptable for validator self-stake and delegation because the amount already affects public consensus and reward accounting.

This should not be generalized to normal transfers. Normal transfer outputs should continue to rely on range proofs and aggregate balance checks unless the protocol intentionally makes their values public.

## Current Commitment Scheme

### Output and commitment fields

`OutputV1.commitment` is a `CommitmentV1`, which is a 32-byte compressed Ristretto255 point (`indra-core/src/types/crypto.rs:111-129`).

`OutputV1.owner_pubkey` is `HybridPubKey`, consisting of a 32-byte Ed25519 public key and a variable-length ML-DSA-87 public key (`indra-core/src/types/crypto.rs:66-104`). This is relevant because staking already verifies the UTXO owner's identity by deriving an ID from this hybrid public key and comparing it to the validator/delegator signer.

### Pedersen generators

The crypto commitment implementation uses:

- `G = RISTRETTO_BASEPOINT_POINT`
- `H = RistrettoPoint::hash_from_bytes::<Sha512>(b"INDRA-PEDERSEN-H-v1")`

Code evidence: `indra-crypto/src/pedersen.rs:17-20` and `indra-crypto/src/pedersen.rs:66-70`.

The Bulletproof implementation uses the same `G` and `H` for the external value commitment (`indra-bulletproofs/src/generators.rs:11-18`). Its vector generators are separately domain-separated with `INDRA-BP-G-v1` and `INDRA-BP-H-v1`.

### Range proof status

Each `OutputV1` carries a Bulletproof range proof. `validate_transaction` verifies the proof using `verify_range(&output.commitment.compressed_point.0, output.range_proof.as_slice())`.

The proof establishes that the committed value is in the 64-bit range. It does not bind the committed value to `OutputV1.value_spark`.

### `verify_balance`

`indra_crypto::verify_balance` sums compressed Pedersen commitments homomorphically:

```text
sum(input commitments) == sum(output commitments) + fee commitment
```

It does not receive `value_spark` and therefore cannot prove individual public-value equality. It only proves aggregate commitment conservation.

## Staking Bond Proof Design

Add a wire type in `indra-core/src/types/staking.rs`:

```rust
/// Proof that a staking UTXO's Pedersen commitment opens to exactly
/// `OutputV1.value_spark`.
///
/// This is intentionally an explicit opening, not a zero-knowledge proof:
/// stake amounts are public economic state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakingBondProof {
    /// The committed value. Must equal the bonded UTXO's public value_spark.
    pub committed_value_spark: u64,
    /// Pedersen blinding factor for the bonded UTXO commitment.
    pub blinding_factor: Bytes32,
}
```

Use `[u8; 32]` / `Bytes32` on the wire rather than `curve25519_dalek::Scalar`. The existing commitment API accepts raw 32-byte blindings and maps them with `Scalar::from_bytes_mod_order`. Keeping the proof field as `Bytes32` avoids leaking a crypto-library type into the core wire schema.

Suggested validator:

```rust
pub fn validate_staking_bond_proof(
    output: &OutputV1,
    proof: &StakingBondProof,
) -> StateResult<()> {
    let opening = PedersenOpening {
        value: proof.committed_value_spark,
        blinding: proof.blinding_factor.0,
    };

    verify_opening(
        &PedersenCommitment(output.commitment.compressed_point.0),
        &opening,
    )
    .map_err(|_| StateError::CommitmentMismatch)?;

    if proof.committed_value_spark != output.value_spark {
        return Err(StateError::CommitmentValueMismatch {
            claimed: output.value_spark,
            proven: proof.committed_value_spark,
        });
    }

    Ok(())
}
```

Task 2 should add concrete `StateError` variants or reuse existing variants with clear messages. Prefer distinct errors:

- `StakingBondCommitmentMismatch`
- `StakingBondValueMismatch { public_value, committed_value }`

### Required staking checks

At every bond site, validation order should be:

1. Verify UTXO exists.
2. Verify UTXO owner matches the validator/delegator signer.
3. If `staking_commitment_proof_required(current_height)`, verify the proof against `utxo_entry.output`.
4. Use the proven/public amount for minimum-bond checks.
5. Spend the UTXO and insert the `StakeBondEntry`.

This placement ensures a failed proof never consumes the UTXO.

### Security analysis

Revealing `r` discloses the opening of the specific bonded UTXO. It may make that staking UTXO linkable to the transaction output that created it. For staking, this is acceptable because the act of bonding is public and the amount is consensus-relevant.

The proof is replay-safe in the economic sense because it is valid only for a specific commitment, and the staking layer already checks UTXO existence plus `state.staked_bonds.contains_key(&bond_utxo_id)`. The Phase 2 duplicate-UTXO-spend fix also prevents the same input UTXO from being consumed twice in one block. A replayed proof cannot bond a non-existent or already-bonded UTXO.

The proof does not replace ownership checks. A valid opening proves knowledge of the commitment opening; it does not prove the caller owns the UTXO's spend key. The existing `owner_pubkey` checks must remain mandatory.

## Blinding Factor Storage

The CLI wallet already stores blinding factors for spendable UTXOs:

- `WalletEntry.blinding: [u8; 32]`
- pending change outputs also store their blinding
- `wallet.json` serializes the blinding field

The FFI wallet input type also already carries a 32-byte blinding per UTXO (`IndraUtxoEntry.blinding` in `indra-ffi/src/lib.rs`).

So the core wallet model is compatible with Approach A. The missing piece is the staking builder interface:

- `build_register_validator_op`
- `build_self_stake_op`
- `build_delegate_op`
- `indra_build_register_validator`
- `indra_build_self_stake`
- future/optional `indra_build_delegate` if exposed over FFI

These currently accept only `bond_utxo_id` and signer keys. Task 2 should require the caller to provide either:

1. `(bond_value_spark, bond_blinding_factor)`, or
2. a full wallet entry from which those are read.

Recommendation: pass `StakingBondProof` into the builder functions, and have CLI commands load the wallet entry for `--utxo` instead of merely warning when it is absent.

## Wire Format Changes

`StakingOpBody` currently encodes the three bond-producing operations as:

### `RegisterValidator`

Current fields:

```text
tag(4)
commission_bps: u32
bond_utxo_id: Bytes32
validator_pubkey: HybridPubKey
vrf_pk: [u8; 32]
```

New fields:

```text
tag(4)
commission_bps: u32
bond_utxo_id: Bytes32
validator_pubkey: HybridPubKey
vrf_pk: [u8; 32]
bond_proof: StakingBondProof
```

### `SelfStake`

Current fields:

```text
tag(6)
bond_utxo_id: Bytes32
validator_pubkey: HybridPubKey
```

New fields:

```text
tag(6)
bond_utxo_id: Bytes32
validator_pubkey: HybridPubKey
bond_proof: StakingBondProof
```

### `Delegate`

Current fields:

```text
tag(1)
validator_id: Bytes32
bond_utxo_id: Bytes32
delegator_pubkey: HybridPubKey
```

New fields:

```text
tag(1)
validator_id: Bytes32
bond_utxo_id: Bytes32
delegator_pubkey: HybridPubKey
bond_proof: StakingBondProof
```

`StakingBondProof` encoding:

```text
committed_value_spark: u64
blinding_factor: Bytes32
```

Encoded length: 40 bytes.

Because `StakingOp::signing_bytes` includes the encoded body, this proof is automatically signed by the staking op signer once it is added to the body. That is desirable: a relayer cannot swap the proof after signing.

This is not backward-compatible for staking operation bytes. Testnet should use a fresh wipe after deployment. Mainnet would need a coordinated hard-fork activation height and client rollout.

## Hard-Fork Activation

Add:

```rust
pub const STAKING_COMMITMENT_PROOF_HEIGHT: u64 = 0;

pub fn staking_commitment_proof_required(height: u64) -> bool {
    height >= STAKING_COMMITMENT_PROOF_HEIGHT
}
```

For testnet, `0` is correct after a fresh reset.

For mainnet, the activation height should be future-dated. Below activation, legacy staking ops without proofs should decode and apply under old rules. At or above activation, bond-producing staking ops must contain and verify `bond_proof`.

Implementation detail: because decode format changes are hard to gate after decoding, the cleanest mainnet-compatible approach is versioned staking op body tags:

- Keep legacy tags `1`, `4`, `6` decodable before activation.
- Add new proof-bearing tags, for example:
  - `TAG_DELEGATE_WITH_PROOF`
  - `TAG_REGISTER_VALIDATOR_WITH_PROOF`
  - `TAG_SELF_STAKE_WITH_PROOF`
- At/above activation, reject legacy bond-producing tags.

For testnet-only fresh-wipe deployment, changing the existing tags in place is simpler, but the versioned-tag approach is safer and clearer for mainnet.

## FFI/Wallet Impact

The wallet must know and retain each UTXO's blinding factor. Current CLI and FFI wallet models already do this.

Required Task 2 changes:

1. Add `StakingBondProof` construction helper in CLI:

   ```rust
   pub fn staking_bond_proof_from_wallet_entry(entry: &WalletEntry) -> StakingBondProof {
       StakingBondProof {
           committed_value_spark: entry.value_spark,
           blinding_factor: Bytes32::from(entry.blinding),
       }
   }
   ```

2. Change staking builders to require `bond_proof`.

3. Change `indra-stake register`, `indra-stake self-stake`, and `indra-stake delegate` so missing wallet entries are fatal when proof activation is active. The current `warn_if_wallet_utxo_unavailable` behavior is insufficient because the proof cannot be produced without the blinding.

4. Add FFI support:

   ```c
   int indra_create_staking_bond_proof(
       uint64_t value_spark,
       const uint8_t *blinding_factor_32,
       uint8_t *out_proof_bytes,
       size_t out_len
   );
   ```

   Or, simpler for current FFI staking builders, add `bond_value_spark` and `bond_blinding_factor` parameters directly to `indra_build_register_validator` and `indra_build_self_stake`.

5. Keep all blinding-factor inputs treated as secret material in CLI/FFI logs. Even though staking reveals the blinding on-chain, wallets should not accidentally print it before the user intentionally submits a staking op.

## State Layer Integration Points

Add validation at these exact sites in `indra-state/src/delegation.rs`:

### `apply_register_validator`

After:

- `utxo_entry` is loaded
- `utxo_owner_id == validator_id` is checked

Before:

- reading `amount_spark` for minimum-bond enforcement
- `state.utxos.spend(&bond_utxo_id)`
- `ValidatorEntry` insertion

### `apply_self_stake`

After:

- validator exists and is active/registered
- UTXO is not already in `staked_bonds`
- UTXO exists
- UTXO owner matches the validator

Before:

- reading `amount_spark`
- spending the UTXO
- increasing `validator.stake_spark`

### `apply_delegate`

After:

- target validator exists and is active/registered
- UTXO is not already in `staked_bonds`
- UTXO exists
- UTXO owner matches the delegator

Before:

- reading `amount_spark`
- spending the UTXO
- `state.delegations.add_delegation`

Do not add this requirement to `SelfUnstake`, `Undelegate`, `ClaimRewards`, `SetCommission`, or `SetAutoDelegate`: those operations do not introduce a UTXO as new stake.

## Alternative: Extending Range Proofs

It is theoretically possible to use a zero-knowledge proof that proves the commitment opens to a public value without revealing the blinding factor. For example, the prover could provide a Schnorr-style proof of knowledge of `r` for:

```text
C - value_spark·G = r·H
```

That preserves blinding secrecy while proving equality to a public value.

However, current INDRA primitives expose:

- Pedersen commit / verify-opening
- Bulletproof range proofs for `v ∈ [0, 2^64)`
- Aggregate commitment balance verification

They do not currently expose a dedicated equality/opening proof. Adding one would be more protocol and crypto surface area than explicit opening, and it does not buy much for staking because stake amounts are already public.

Recommendation: implement explicit opening for the next testnet/mainnet-grade fix. Consider a zero-knowledge equality proof only if INDRA later wants private delegation amounts, which would require much broader economic-design changes.

## Interactions with Phase 4 Fixes

### ST-13 — slash evasion window

No regression expected.

ST-13 makes active and slashable-unbonding self-bonds remain slashable. ST-03 proof validation happens at bond entry time and ensures the amount recorded in `StakeBondEntry.amount_spark` is individually backed by the original commitment. Slashing can continue to compute reductions from `amount_spark`.

For reduced self-stake release, `released_bond_output` already creates a new output with `value_spark = bond.amount_spark`, a fresh deterministic blinding, and a fresh range proof. That path does not need the original staking proof.

### ST-06 — unified stake semantics

No regression expected.

ST-06 chose self-stake as the active-set and rewards-weighting basis. ST-03 proof validation does not change which stake counts for active-set selection. It only ensures that when self-stake or delegated stake is recorded, the public amount is bound to the UTXO commitment that entered staking.

Delegations remain excluded from active-set weighting under the current model; the proof merely prevents delegation accounting from relying on unbound metadata.

## Implementation Checklist (for Task 2)

Core types:

- Add `StakingBondProof` to `indra-core/src/types/staking.rs`.
- Implement `Encode`, `Decode`, and `encoded_len`.
- Add tests for proof encoding round-trip and signature-domain inclusion.
- Add `STAKING_COMMITMENT_PROOF_HEIGHT` and `staking_commitment_proof_required(height)` in `indra-core/src/types/primitives.rs`.
- Prefer versioned proof-bearing staking op tags for mainnet compatibility.

State:

- Add `validate_staking_bond_proof(output, proof)` in `indra-state/src/delegation.rs` or a small helper module.
- Add clear state errors for commitment mismatch and value mismatch.
- Validate proofs in `apply_register_validator`, `apply_self_stake`, and `apply_delegate`.
- Ensure proof validation happens before spending the UTXO.
- Reject legacy proofless bond ops at/above activation height.

CLI:

- Update `build_register_validator_op`, `build_self_stake_op`, and `build_delegate_op` to require `StakingBondProof`.
- Update `indra-stake register`, `self-stake`, and `delegate` to load the wallet entry and fail if it is absent after activation.
- Remove/replace `warn_if_wallet_utxo_unavailable` for proof-required bond ops.
- Add tests for proof construction from wallet entries.

FFI:

- Add an FFI helper or direct parameters for `bond_value_spark` and 32-byte `bond_blinding_factor`.
- Update FFI staking builders to encode proof-bearing staking ops.
- Keep pointer validation and bounded input handling consistent with API-10 fixes.

Tests:

- `staking_bond_proof_accepts_matching_value_and_blinding`
- `staking_bond_proof_rejects_wrong_blinding`
- `staking_bond_proof_rejects_public_value_mismatch`
- `register_validator_rejects_mismatched_bond_commitment`
- `self_stake_rejects_mismatched_bond_commitment`
- `delegate_rejects_mismatched_bond_commitment`
- `register_validator_valid_bond_proof_succeeds`
- `self_stake_valid_bond_proof_succeeds`
- `delegate_valid_bond_proof_succeeds`
- `proof_validation_failure_does_not_spend_utxo`
- activation tests: proofless legacy bond op accepted before activation and rejected at/after activation, if versioned legacy support is implemented.

Deployment:

- Testnet: fresh wipe acceptable; no key regeneration required.
- Mainnet: coordinated hard-fork height required.
- This changes staking-op wire format but not cryptographic key derivation.
