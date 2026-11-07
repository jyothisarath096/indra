# Deterministic founder-genesis final report

Scope: final committed state at `a18ec213`, covering `048b6390` (founder genesis), `3f391126` (exact-error tests), `b704b960` (cold-owned genesis UTXOs), and `a18ec213` (cold-key CLI transfers). This report is based on files opened with `git show a18ec213:<path>`; no source file was changed for this report.

## 1. What changed and why

**Read from `a18ec213`:** Founder genesis is deterministic: `indra/indra-node/src/genesis.rs:108-143` derives the initial election seed with SHA-512, using the domain tag at `:121` and validator material sorted by validator ID at `:119-137`. The manifest schema is in `:28-106`; validation requires four validators at `:174-177`; finalization loads and seals the manifest at `:390-436`. The committed construction has no Bitcoin/drand entropy or commit-reveal ceremony input.

The genesis rules are one fixed ruleset: the initial seed is independent of manifest entry order, while the timestamp is a manifest input to the fingerprint and block header (`indra/indra-node/src/genesis.rs:291-307`, `:310-341`). The fixed liquid genesis amount is `GENESIS_VALIDATOR_UTXO_SPARK` at `:23`; the 64-byte name limit is `:25-26`.

Between `048b6390` and `b704b960`, genesis UTXO ownership changed from the validator hot hybrid public key to the cold hybrid public key. The final implementation constructs `owner_pubkey` from `cold_classical` and `cold_pq` at `indra/indra-node/src/genesis.rs:420-424`, so the ordinary spend path requires the registered cold owner; the ownership and spend tests are at `:634-668` and `:671-733`.

## 2. Manifest rules and proving tests

The error strings below are the strings returned by `validate_genesis_manifest` in the committed implementation. Test citations are freshly taken from `git grep -n` at `a18ec213`.

| Rule | Exact error string | Proving test in `a18ec213` |
|---|---|---|
| At least four validators | `genesis requires at least 4 validators for BFT safety` | `canonical_genesis_rejects_too_few_mismatched_and_duplicate_identities`, `indra/indra-node/src/genesis.rs:791`; `empty_genesis_manifest_is_rejected`, `:876` |
| Non-empty, bounded chain ID | `genesis chain_id is outside the canonical length range` | `canonical_genesis_rejects_missing_cold_fields_and_bad_chain_ids`, `indra/indra-node/src/genesis.rs:772` |
| Strict canonical active-slot coefficient | `active_slot_coefficient_numerator must be canonical ASCII decimal` | `active_slot_coefficient_uses_strict_canonical_decimal_string`, `indra/indra-node/src/genesis.rs:754` |
| Mainnet F | `invalid proposer sortition: mainnet active_slot_coefficient_numerator must equal {MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR}` | `four_validators_are_required_and_bad_f_is_rejected`, `indra/indra-node/src/genesis.rs:996` |
| Required fields / no unknown fields | `invalid genesis TOML: ...` | `canonical_genesis_rejects_missing_cold_fields_and_bad_chain_ids`, `indra/indra-node/src/genesis.rs:772` |
| Validator ID equals hot identity | `genesis validator v0 has an incorrect validator_id` | `canonical_genesis_rejects_too_few_mismatched_and_duplicate_identities`, `indra/indra-node/src/genesis.rs:791` |
| Validator, VRF, hot and cold key uniqueness | `duplicate genesis validator or key in v0` / `duplicate genesis validator or key in v1` | `canonical_genesis_rejects_too_few_mismatched_and_duplicate_identities`, `indra/indra-node/src/genesis.rs:791`; `genesis_rejects_cross_role_key_reuse_and_oversized_fields`, `:804` |
| VRF proof of possession | `genesis validator v0 has an invalid VRF PoP` | `genesis_rejects_vrf_squatting_cold_history_and_noncanonical_hex`, `indra/indra-node/src/genesis.rs:912` |
| Hot classical key validity | `genesis validator v0 has an invalid hot classical key` | `invalid_hot_classical_key_is_rejected`, `indra/indra-node/src/genesis.rs:957` |
| Hot PQ key validity | `genesis validator v0 has an invalid hot PQ key` | `invalid_hot_pq_key_is_rejected`, `indra/indra-node/src/genesis.rs:967` |
| Cold classical and PQ key validity | `genesis validator v0 has an invalid cold classical key` / `genesis validator v0 has an invalid cold PQ key` | `genesis_rejects_invalid_cold_classical_and_pq_keys_with_exact_errors`, `indra/indra-node/src/genesis.rs:858` (added in `3f391126`) |
| Lowercase canonical hex | `genesis test must be canonical lowercase hexadecimal` | `reject_noncanonical_hex`, `indra/indra-node/src/genesis.rs:929`; uppercase coverage also appears in `genesis_rejects_vrf_squatting_cold_history_and_noncanonical_hex`, `:912` |
| Fixed key lengths | `genesis hybrid_pq_pk must be exactly 2592 bytes` | `genesis_rejects_cross_role_key_reuse_and_oversized_fields`, `indra/indra-node/src/genesis.rs:804` |
| Cold version and nonce | `genesis validator v0 has invalid cold-key version or nonce` | `genesis_rejects_vrf_squatting_cold_history_and_noncanonical_hex`, `indra/indra-node/src/genesis.rs:912` |
| Stake is not below dust | `genesis validator v0 stake is below dust` | `genesis_rejects_stake_below_dust_with_exact_error`, `indra/indra-node/src/genesis.rs:848` (added in `3f391126`); CLI coverage is `below_dust_stake_rejected`, `indra/indra-cli/src/bin/genesis.rs:276` |
| Checked stake sum | `genesis validator stake total overflows u64` | `genesis_rejects_stake_sum_overflow`, `indra/indra-node/src/genesis.rs:1022` |
| Checked genesis total supply | `genesis total supply overflows u64` | `genesis_rejects_total_supply_overflow`, `indra/indra-node/src/genesis.rs:1030` |
| Lifetime supply cap | `genesis total supply exceeds lifetime supply cap {LIFETIME_SUPPLY_CAP_SPARK}` | `genesis_rejects_total_supply_cap_plus_one`, `indra/indra-node/src/genesis.rs:1006`; exact-cap acceptance is `genesis_accepts_total_supply_exactly_at_lifetime_cap`, `:1040` |
| Non-empty validator name | `genesis validator name must not be empty` | `genesis_validator_name_rules_are_canonical`, `indra/indra-node/src/genesis.rs:1048` |
| Name length at most 64 bytes | `genesis validator name exceeds 64 bytes` | `genesis_validator_name_rules_are_canonical`, `indra/indra-node/src/genesis.rs:1048` |
| Name character allow-list | `genesis validator name contains unsupported characters` | `genesis_validator_name_rules_are_canonical`, `indra/indra-node/src/genesis.rs:1048` |

Finalized-state properties are separately covered by `finalized_genesis_preserves_manifest_cold_authority_fields`, `indra/indra-node/src/genesis.rs:885`, and `finalized_genesis_sets_height_and_seed_from_manifest`, `:902`. The latter asserts election-seed height 1 and equality with `derive_genesis_election_seed`.

## 3. CLI and cold-owned spend path

The genesis CLI uses an atomic `create_new` helper at `indra/indra-cli/src/bin/genesis.rs:29-40`; `build` writes, syncs, and removes only the newly created file if inspection fails at `:129-165`. `validate` finalizes the manifest and prints chain ID, validator count, fingerprint, and block hash at `:168-175`. `inspect` prints all roots and per-validator integer basis-point shares at `:182-207`.

`indra-send --cold-keys` loads the encrypted cold file at `indra/indra-cli/src/bin/send.rs:57-64`, reconstructs the cold keypair and derives its owner key at `:80-101`, optionally seeds genesis outputs at `:103-112`, and passes the cold owner into `build_cold_transaction` at `:113-121`. The builder selects only entries with the requested owner at `indra/indra-cli/src/tx_builder.rs:268-299`; the proving test is `cold_cli_transfer_is_accepted_hot_signature_rejected_and_change_returns_to_cold_owner`, `indra/indra-cli/src/tx_builder.rs:710`.

Wallet entries carry a mandatory `owner_pubkey` at `indra/indra-cli/src/wallet.rs:75-82`; `add_utxo` requires it at `:109-118`, and missing JSON ownership is rejected as `missing required field: owner_pubkey` at `:367-377`. `seed_wallet_from_genesis` copies matching genesis outputs as unspent and is explicitly unable to learn later chain spends without a scan (`indra/indra-cli/src/wallet.rs:28-58`); its idempotence/ownership test is at `:809`.

`indra-wallet-scan --cold-owner` accepts only an encoded public `HybridPubKey` and never decrypts cold secrets (`indra/indra-cli/src/bin/wallet_scan.rs:1-8`, `:24-29`, `:112-146`). Its parser tests are `cold_owner_argument_accepts_encoded_public_key`, `:171`, `cold_owner_argument_rejects_bad_hex`, `:177`, and `cold_owner_argument_rejects_bad_encoding`, `:182`.

The hot password-file path remains permissive (`reject_permissive: false`) at `indra/indra-cli/src/keygen.rs:21-32`; the cold path is strict (`true`) at `:35-47`. The exact permission test is `cold_password_file_rejects_permissive_permissions`, `indra/indra-cli/src/keygen.rs:178`, and the wrong-passphrase test is `cold_cli_loader_reports_exact_wrong_passphrase_error`, `:154`.

## 4. Golden vector

`golden_vector_values`, `indra/indra-node/src/genesis.rs:1067-1078`, pins the final values:

```text
election seed:  f449538f3ffe86ac8fe27a2bea99714c8823140efdceda5144ac3f0143d58db0b3649bb84ddef0f63e2ebd3de8ecb1f09b46fc2d0b18fcf1feb3242ba477c039
fingerprint:   dc14cfe8a7d4b789554e442ad1bcd3cd4c26e782b6c5506b5e3e96b34e3f42dc
genesis block: 13cf73518f8185c762b72e125043259e8c52465a9acc933be69049ade9ab5223
```

The election seed stayed unchanged between the founder-genesis snapshot and `b704b960`; changing only the UTXO owner changed the state commitments, fingerprint, and block hash. The timestamp sensitivity test is `genesis_timestamp_changes_fingerprint_and_block_hash_but_not_seed`, `indra/indra-node/src/genesis.rs:977`.

## 5. Verification

| Label | Result |
|---|---|
| owner-reported, not Codex-verified | `~/Desktop/review/ws_a18ec213_debug.log`: 22m17s; node library 318 passed / 0 failed / 5 ignored; CLI library 58; FFI 26; all reported OK. |
| owner-reported, not Codex-verified | `~/Desktop/review/ws_a18ec213_release.log`: policy OK; Cargo.lock SHA-256 `24eea7cb276c93345c19667483d452b64e2bab9abb72beb9678d6a58dae43f46`; node library 318 passed / 0 failed / 5 ignored; all reported OK. |
| owner-reported, not Codex-verified | After `cargo build --release -p indra-node --bin node` (up to date at `a18ec213`), `strings target/release/node | grep -c INDRA-GENESIS-ELECTION-SEED-v2` printed `1`; `strings target/release/node | grep -c -E 'local-test-validator|test-validator-|canonical-local-genesis'` printed `0`. |
| run by Codex, log path | No command was run in this report-only regeneration task; no Codex verification of `a18ec213` is claimed. |

## 6. Known limits and open items

- Dominant-stake fixtures are count-rule tests, not BFT tests; the relevant test is `genesis_cli_inspect_warns_for_dominant_test_support_manifest`, `indra/indra-cli/tests/cli.rs:362`.
- `ValidatorSet::total_active_stake` uses `saturating_add` at `indra-state/src/validator.rs:685-690`; its safety relies on the genesis supply bound, not on checked accumulation.
- `select_active_set` has no post-genesis four-validator floor and no minimum-stake rule at `indra-state/src/validator.rs:778-800`; that design remains open.
- The liquid per-validator genesis UTXO is a decided fixed 10,000 INDRA, independent of manifest stake (`indra/indra-node/src/genesis.rs:23`, `:408-424`), for 40,000 INDRA total across four genesis validators. It is consensus-critical; changing the constant at `genesis.rs:23` later would be a hard fork.
- The `genesis_utxo_total` overflow error is `genesis validator UTXO total overflows u64` at `indra/indra-node/src/genesis.rs:188-190`; the count is `validators.len() as u64`, overflow is above about 18.4 million entries, and there is no committed test. It is practically unreachable.
- There is no end-to-end test of the `indra-send` binary against a live node in the cited committed tests; the transfer coverage is in-process (`indra/indra-cli/src/tx_builder.rs:710`).
- Offline signing is not implemented: cold keys must be decrypted on the signing machine (`indra/indra-cli/src/bin/send.rs:57-85`); the scan path accepts only a public cold owner (`indra/indra-cli/src/bin/wallet_scan.rs:112-146`).
- Hot-key password files are still accepted with permissive permissions (`indra/indra-cli/src/keygen.rs:21-27`).
- `seed_wallet_from_genesis` cannot know on-chain spent state; it adds matching entries as unspent and directs the operator to scan (`indra/indra-cli/src/wallet.rs:28-31`).
- FFI C signatures are unchanged. `indra-ffi/src/wallet.rs:19-24` defines `build_wallet_context`; it derives the sender `HybridPubKey` from `sender_classical_seed` and `sender_pq_pk` at `:25-36`, and tags every UTXO with that key at `:40-49`. Only the CLI wallet JSON format now requires `owner_pubkey` (`indra/indra-cli/src/wallet.rs:367-377`).
- `max_active_validators` returns `VALIDATOR_SET_PHASE1_MAX = 20` while total stake is below `VALIDATOR_SET_PHASE1_STAKE = 1_000_000 * SPARK_PER_INDRA` (`indra-core/src/types/primitives.rs:259-260`, `:268-294`). The phase-2 and phase-3 thresholds are `10_000_000 * SPARK_PER_INDRA` and `50_000_000 * SPARK_PER_INDRA` at `:262-266`. With 44,000 INDRA of genesis supply, the 1M/10M/50M thresholds are unreachable unless emission exists; whether emission exists is not established in this report.
- The committed evidence does not constitute an independent third-party audit or real multi-machine, real-socket latency, load, or long-duration operational validation.

## Appendix: exact cited-test grep at `a18ec213`

The following is the exact `git grep -n` output for every cited test name in sections 2–4 and 6:

```text
a18ec213:indra/indra-cli/src/bin/genesis.rs:251:    fn genesis_with_4_validators() {
a18ec213:indra/indra-cli/src/bin/genesis.rs:258:    fn genesis_rejects_3_validators() {
a18ec213:indra/indra-cli/src/bin/genesis.rs:264:    fn stake_shares_are_integer_basis_points() {
a18ec213:indra/indra-cli/src/bin/genesis.rs:276:    fn below_dust_stake_rejected() {
a18ec213:indra/indra-cli/src/bin/genesis.rs:284:    fn duplicate_validator_id_rejected() {
a18ec213:indra/indra-cli/src/bin/genesis.rs:292:    fn toml_output_has_all_fields() {
a18ec213:indra/indra-cli/src/bin/genesis.rs:301:    fn toml_renderer_escapes_operator_text() {
a18ec213:indra/indra-cli/src/bin/wallet_scan.rs:171:    fn cold_owner_argument_accepts_encoded_public_key() {
a18ec213:indra/indra-cli/src/bin/wallet_scan.rs:177:    fn cold_owner_argument_rejects_bad_hex() {
a18ec213:indra/indra-cli/src/bin/wallet_scan.rs:182:    fn cold_owner_argument_rejects_bad_encoding() {
a18ec213:indra/indra-cli/src/keygen.rs:154:    fn cold_cli_loader_reports_exact_wrong_passphrase_error() {
a18ec213:indra/indra-cli/src/keygen.rs:178:    fn cold_password_file_rejects_permissive_permissions() {
a18ec213:indra/indra-cli/src/keygen.rs:198:    fn cold_cli_argument_selects_cold_password_source() {
a18ec213:indra/indra-cli/src/tx_builder.rs:710:    fn cold_cli_transfer_is_accepted_hot_signature_rejected_and_change_returns_to_cold_owner() {
a18ec213:indra/indra-cli/src/wallet.rs:809:    fn seed_wallet_from_genesis_matches_owned_entries_and_is_idempotent() {
a18ec213:indra/indra-cli/tests/cli.rs:116:fn genesis_cli_round_trips_and_inspects_all_canonical_roots() {
a18ec213:indra/indra-cli/tests/cli.rs:151:fn genesis_cli_build_timestamp_warning_is_nonfatal_and_current_time_is_quiet() {
a18ec213:indra/indra-cli/tests/cli.rs:300:fn genesis_cli_build_refuses_to_overwrite_existing_output() {
a18ec213:indra/indra-cli/tests/cli.rs:316:fn genesis_cli_validator_entry_refuses_to_overwrite_existing_output() {
a18ec213:indra/indra-cli/tests/cli.rs:347:fn genesis_cli_validate_rejects_malformed_manifest() {
a18ec213:indra/indra-cli/tests/cli.rs:362:fn genesis_cli_inspect_warns_for_dominant_test_support_manifest() {
a18ec213:indra/indra-cli/tests/cli.rs:387:fn cold_share_ceremony_verifies_and_recovers_only_encrypted_keys() {
a18ec213:indra/indra-node/src/genesis.rs:582:    fn seed_is_order_independent_and_changes_for_each_material_field() {
a18ec213:indra/indra-node/src/genesis.rs:611:    fn genesis_block_is_deterministic() {
a18ec213:indra/indra-node/src/genesis.rs:619:    fn genesis_block_has_zero_prev_hash() {
a18ec213:indra/indra-node/src/genesis.rs:624:    fn genesis_block_height_is_zero() {
a18ec213:indra/indra-node/src/genesis.rs:629:    fn genesis_state_height_is_zero() {
a18ec213:indra/indra-node/src/genesis.rs:634:    fn genesis_utxo_uses_authoritative_public_value() {
a18ec213:indra/indra-node/src/genesis.rs:671:    fn genesis_utxo_spend_requires_the_cold_hybrid_key() {
a18ec213:indra/indra-node/src/genesis.rs:734:    fn genesis_liquid_issuance_is_independent_of_manifest_validator_order() {
a18ec213:indra/indra-node/src/genesis.rs:754:    fn active_slot_coefficient_uses_strict_canonical_decimal_string() {
a18ec213:indra/indra-node/src/genesis.rs:772:    fn canonical_genesis_rejects_missing_cold_fields_and_bad_chain_ids() {
a18ec213:indra/indra-node/src/genesis.rs:791:    fn canonical_genesis_rejects_too_few_mismatched_and_duplicate_identities() {
a18ec213:indra/indra-node/src/genesis.rs:804:    fn genesis_rejects_cross_role_key_reuse_and_oversized_fields() {
a18ec213:indra/indra-node/src/genesis.rs:848:    fn genesis_rejects_stake_below_dust_with_exact_error() {
a18ec213:indra/indra-node/src/genesis.rs:858:    fn genesis_rejects_invalid_cold_classical_and_pq_keys_with_exact_errors() {
a18ec213:indra/indra-node/src/genesis.rs:876:    fn empty_genesis_manifest_is_rejected() {
a18ec213:indra/indra-node/src/genesis.rs:885:    fn finalized_genesis_preserves_manifest_cold_authority_fields() {
a18ec213:indra/indra-node/src/genesis.rs:902:    fn finalized_genesis_sets_height_and_seed_from_manifest() {
a18ec213:indra/indra-node/src/genesis.rs:912:    fn genesis_rejects_vrf_squatting_cold_history_and_noncanonical_hex() {
a18ec213:indra/indra-node/src/genesis.rs:929:    fn reject_noncanonical_hex() {
a18ec213:indra/indra-node/src/genesis.rs:935:    fn fingerprint_changes_with_every_genesis_identity_domain() {
a18ec213:indra/indra-node/src/genesis.rs:957:    fn invalid_hot_classical_key_is_rejected() {
a18ec213:indra/indra-node/src/genesis.rs:967:    fn invalid_hot_pq_key_is_rejected() {
a18ec213:indra/indra-node/src/genesis.rs:977:    fn genesis_timestamp_changes_fingerprint_and_block_hash_but_not_seed() {
a18ec213:indra/indra-node/src/genesis.rs:996:    fn four_validators_are_required_and_bad_f_is_rejected() {
a18ec213:indra/indra-node/src/genesis.rs:1006:    fn genesis_rejects_total_supply_cap_plus_one() {
a18ec213:indra/indra-node/src/genesis.rs:1014:    fn genesis_rejects_stake_sum_above_lifetime_cap() {
a18ec213:indra/indra-node/src/genesis.rs:1022:    fn genesis_rejects_stake_sum_overflow() {
a18ec213:indra/indra-node/src/genesis.rs:1030:    fn genesis_rejects_total_supply_overflow() {
a18ec213:indra/indra-node/src/genesis.rs:1040:    fn genesis_accepts_total_supply_exactly_at_lifetime_cap() {
a18ec213:indra/indra-node/src/genesis.rs:1048:    fn genesis_validator_name_rules_are_canonical() {
a18ec213:indra/indra-node/src/genesis.rs:1067:    fn golden_vector_values() {
a18ec213:indra/indra-node/tests/node.rs:450:fn genesis_rejects_3_validators() {
a18ec213:indra/indra-node/tests/node.rs:457:fn genesis_with_4_validators() {
a18ec213:indra/indra-node/tests/node.rs:464:fn genesis_is_deterministic() {
```
