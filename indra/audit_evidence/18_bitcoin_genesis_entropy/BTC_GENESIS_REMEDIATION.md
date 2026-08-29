# BTC-GEN-01 / BTC-GEN-02 remediation

Status: **FIXED — pre-mainnet breaking ceremony replacement**.

## Enforced ordering

1. `commit-validator` creates a public commitment and private opening.
2. `precommit` requires two agreeing Bitcoin Core clients and a target at least
   144 blocks beyond their current tip. It fixes chain ID, Bitcoin descriptor,
   protocol versions, mainnet `F`, and the ordered commitment set.
3. Before the target exists, every validator reveals and `freeze-authority`
   verifies exact opening of the complete set while two nodes report
   `tip < target`.
4. The complete frozen authority artifact/hash is externally witnessed.
5. Only then does the target header become fixed at the committed height.
6. After at least 100 observed confirmations, `finalize` derives the manifest
   solely from the precommit and frozen authority, accepting no reveal input.

The one-shot `build` command hard-fails. There is no post-target validator input,
alternate height, single-node, depth override, legacy decoder, migration, or
testnet fallback.

## Canonical binary grammars

```text
GenesisValidatorCommitmentV1 =
  "INDRA-GENESIS-VALIDATOR-COMMIT-v1" ||
  u16_be(len(chain_id)) || chain_id ||
  validator_id[32] || self_stake_u64_le ||
  hot_ed25519_pk[32] || hot_ml_dsa_87_pk[2592] ||
  cold_ed25519_pk[32] || cold_ml_dsa_87_pk[2592] ||
  cold_key_version_u64_le || cold_nonce_u64_le ||
  vrf_pk[32] || vrf_suite_u8(1) || activation_epoch_u64_le(0) ||
  hiding_nonce[32]

validator_commitment = SHA-256(GenesisValidatorCommitmentV1)

GenesisPrecommitV1 =
  "INDRA-GENESIS-PRECOMMIT-v1" || ceremony_version_u8(1) ||
  u16_be(len(chain_id)) || chain_id ||
  BitcoinPowEntropySourceV1[48] || block_format_version_u16_le ||
  snapshot_format_version_u8 || mainnet_F_u64_le ||
  commitment_count_u16_be ||
  strictly_ascending_unique_validator_commitment[32] * count

precommit_hash = SHA-256(GenesisPrecommitV1)
```

JSON/TOML files are human wrappers and are never the cryptographic transcript.
Unknown wrapper fields are rejected; commitment hex is fixed-size lowercase.
The correction does not change either commitment grammar. The frozen-authority
artifact carries the sorted complete openings and hashes the original precommit
plus the observed pre-target Bitcoin tip, fixed VRF suite/activation epoch, and
exact commitment set under `INDRA-GENESIS-AUTHORITY-FROZEN-v1`:

```text
GenesisAuthorityFrozenV1 =
  "INDRA-GENESIS-AUTHORITY-FROZEN-v1" || version_u8(1) ||
  precommit_hash[32] || bitcoin_tip_at_freeze_u64_le ||
  vrf_suite_u8(1) || activation_epoch_u64_le(0) ||
  commitment_count_u16_be ||
  strictly_ascending_unique_validator_commitment[32] * count
```

## Genesis identity binding

The manifest retains `genesis_precommit_hash`. The genesis entropy-record hash
binds the descriptor, exact target header, and precommit hash. The genesis
fingerprint binds that record, the final election seed, and final snapshot root.

## Regression evidence

- BTC-GEN-01: descriptor/source mutations change or invalidate the precommit; a
  tampered artifact fails canonical hash verification before finalization.
- BTC-GEN-02: a permanent test generates 4,096 alternate legitimate VRF keys
  and proves none opens the baseline commitment. Individual authority-field and
  membership mutations change the commitment/precommit.
- Selective abort: `freeze-authority` succeeds only before target, a late freeze
  is rejected, the artifact exposes the complete final validator material, and
  `finalize --validator-reveal ...` is rejected unconditionally.
- The CLI test confirms the public precommit contains no raw VRF key bytes.
- Declared depths 99 and 101 are rejected; exactly 100 is accepted.

The 144-block lead provides time for both publications and complete opening; it
does not itself prove chronology. Both the precommit and frozen authority must
be published through two independent witness channels before target. Incomplete
or unwitnessed ceremonies are invalid and must not be used as selectively
published randomness trials. The election seed is not general-purpose
application randomness.
