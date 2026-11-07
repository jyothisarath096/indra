# Deterministic founder-genesis final report

Scope: committed snapshot `048b639007cb73429e0ae7c3863b1954ff776eaa` plus test commit `3f391126`. This report was written from files opened at those commits with `git show`; no source or manifest file was changed.

## 1. Design and rationale

**Read from committed snapshot:** `indra/indra-node/src/genesis.rs:109-143` defines deterministic founder genesis: the election seed is SHA-512 over the domain string at `:121` and sorted validator material, with no ceremony input. `:23` defines `GENESIS_VALIDATOR_UTXO_SPARK`; `:25-26` defines `MAX_GENESIS_VALIDATOR_NAME_BYTES`. The manifest contains the chain settings and validator public material at `:28-106`.

**Read from committed snapshot:** Genesis validation requires at least four validators at `indra/indra-node/src/genesis.rs:174-177`; the builder inserts one fixed validator UTXO per entry at `:420-424`; and finalization derives the initial state from the manifest at `:390-436`. The resulting design has one fixed ruleset: no Bitcoin/drand entropy or commit-reveal ceremony appears in the committed genesis construction path.

## 2. Manifest rules and proving tests

The table uses exact error strings from the committed implementation and test assertions. “No dedicated test” is reported where the committed tree has validation code but no test proving that particular malformed field.

| Rule | Exact error string | Proving test in committed tree |
|---|---|---|
| At least four validators; an empty manifest is therefore rejected | `genesis requires at least 4 validators for BFT safety` | `canonical_genesis_rejects_too_few_mismatched_and_duplicate_identities`, `indra/indra-node/src/genesis.rs:703-707`; `empty_genesis_manifest_is_rejected`, `:788-794` |
| Chain ID must be non-empty and within the canonical byte limit | `genesis chain_id is outside the canonical length range` | `canonical_genesis_rejects_missing_cold_fields_and_bad_chain_ids`, `indra/indra-node/src/genesis.rs:684-696` |
| Active-slot coefficient must be canonical ASCII decimal | `active_slot_coefficient_numerator must be canonical ASCII decimal` | `active_slot_coefficient_uses_strict_canonical_decimal_string`, `indra/indra-node/src/genesis.rs:666-680` |
| Active-slot coefficient must equal mainnet F | `invalid proposer sortition: mainnet active_slot_coefficient_numerator must equal {MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR}` | `four_validators_are_required_and_bad_f_is_rejected`, `indra/indra-node/src/genesis.rs:908-915` |
| Required TOML fields and no unknown fields | `invalid genesis TOML: ...`; the committed assertion requires `unknown field \`missing_cold\`` | `canonical_genesis_rejects_missing_cold_fields_and_bad_chain_ids`, `indra/indra-node/src/genesis.rs:697-700` |
| Validator ID must equal the hot hybrid identity | `genesis validator v0 has an incorrect validator_id` | `canonical_genesis_rejects_too_few_mismatched_and_duplicate_identities`, `indra/indra-node/src/genesis.rs:707-709` |
| Validator IDs, VRF keys, and hot/cold classical and PQ components are unique | `duplicate genesis validator or key in v0` or `duplicate genesis validator or key in v1` | `canonical_genesis_rejects_too_few_mismatched_and_duplicate_identities`, `indra/indra-node/src/genesis.rs:710-712`; `genesis_rejects_cross_role_key_reuse_and_oversized_fields`, `:716-756` |
| VRF proof of possession must verify for the chain, validator ID, and VRF key | `genesis validator v0 has an invalid VRF PoP` | `genesis_rejects_vrf_squatting_cold_history_and_noncanonical_hex`, `indra/indra-node/src/genesis.rs:824-838` |
| Hot classical key must be structurally valid | `genesis validator v0 has an invalid hot classical key` | `invalid_hot_classical_key_is_rejected`, `indra/indra-node/src/genesis.rs:869-877` |
| Hot PQ key must be structurally valid | `genesis validator v0 has an invalid hot PQ key` | `invalid_hot_pq_key_is_rejected`, `indra/indra-node/src/genesis.rs:879-887` |
| Cold classical and PQ keys must be structurally valid | `genesis validator v0 has an invalid cold classical key` / `genesis validator v0 has an invalid cold PQ key` | `genesis_rejects_invalid_cold_classical_and_pq_keys_with_exact_errors`, `indra/indra-node/src/genesis.rs:770-785` (added in `3f391126`); validation is at `:238-242`. |
| Hex fields must be lowercase canonical hexadecimal | `genesis test must be canonical lowercase hexadecimal` | `reject_noncanonical_hex`, `indra/indra-node/src/genesis.rs:841-844`; uppercase manifest coverage is at `genesis_rejects_vrf_squatting_cold_history_and_noncanonical_hex`, `:824-838` |
| Fixed-width hex fields must have their required lengths | `genesis hybrid_pq_pk must be exactly 2592 bytes` | `genesis_rejects_cross_role_key_reuse_and_oversized_fields`, `indra/indra-node/src/genesis.rs:750-756`; the generic validator is at `:271-278` |
| Cold key version must be 1 and cold nonce must be 0 | `genesis validator v0 has invalid cold-key version or nonce` | `genesis_rejects_vrf_squatting_cold_history_and_noncanonical_hex`, `indra/indra-node/src/genesis.rs:824-838` |
| Stake must meet the dust limit | `genesis validator v0 stake is below dust` | `genesis_rejects_stake_below_dust_with_exact_error`, `indra/indra-node/src/genesis.rs:760-767` (added in `3f391126`); the CLI builder test is `below_dust_stake_rejected`, `indra/indra-cli/src/bin/genesis.rs:276-281`. |
| Checked validator-stake sum must fit in u64 | `genesis validator stake total overflows u64` | `genesis_rejects_stake_sum_overflow`, `indra/indra-node/src/genesis.rs:934-938` |
| Checked genesis total supply must fit in u64 | `genesis total supply overflows u64` | `genesis_rejects_total_supply_overflow`, `indra/indra-node/src/genesis.rs:942-949` |
| Genesis total supply must not exceed the lifetime cap | `genesis total supply exceeds lifetime supply cap {LIFETIME_SUPPLY_CAP_SPARK}` | `genesis_rejects_total_supply_cap_plus_one`, `indra/indra-node/src/genesis.rs:918-922`; exact-cap acceptance is `genesis_accepts_total_supply_exactly_at_lifetime_cap`, `:952-956` |
| Validator names are non-empty | `genesis validator name must not be empty` | `genesis_validator_name_rules_are_canonical`, `indra/indra-node/src/genesis.rs:960-963` |
| Validator names are at most 64 UTF-8 bytes | `genesis validator name exceeds 64 bytes` | `genesis_validator_name_rules_are_canonical`, `indra/indra-node/src/genesis.rs:964-969`; the constant is `indra/indra-node/src/genesis.rs:25-26` |
| Validator names contain only ASCII alphanumeric characters, space, period, underscore, or hyphen | `genesis validator name contains unsupported characters` | `genesis_validator_name_rules_are_canonical`, `indra/indra-node/src/genesis.rs:970-975` |

The committed tests also prove the finalized state preserves cold fields and sets election seed height 1: `finalized_genesis_preserves_manifest_cold_authority_fields`, `indra/indra-node/src/genesis.rs:797-810`, and `finalized_genesis_sets_height_and_seed_from_manifest`, `:814-820`.

## 3. CLI behavior

**Read from committed snapshot:** `indra-cli/src/bin/genesis.rs:29-35` uses `OpenOptions::create_new(true)`, so generated files do not overwrite existing files. `create-vrf-proof` and `validator-entry` use that helper at `:82` and `:123`; `build` uses it at `:153-157`, calls `sync_all`, and emits the timestamp warning at `:149-152`.

**Read from committed snapshot:** `validate` finalizes the manifest and prints chain ID, validator count, fingerprint, and genesis block hash at `indra-cli/src/bin/genesis.rs:168-175`. `inspect` prints the state/snapshot roots, fingerprint, block hash, file SHA-256, and per-validator stake shares at `:182-205`; the share calculation is integer basis-point arithmetic in `indra-cli/src/genesis_cmd.rs:33-40`.

**Read from committed snapshot:** `genesis_cli_round_trips_and_inspects_all_canonical_roots`, `indra-cli/tests/cli.rs:116-148`, checks validation output, all inspect roots, four `share_bps=2500` records, and no validator warning. `genesis_cli_build_timestamp_warning_is_nonfatal_and_current_time_is_quiet`, `:151-171`, checks old/current timestamp warning behavior. The binary tests `genesis_rejects_3_validators`, `indra-cli/src/bin/genesis.rs:258-262`, `below_dust_stake_rejected`, `:276-281`, and `duplicate_validator_id_rejected`, `:284-289`, assert the CLI validation errors.

## 4. Golden vector

**Read from committed snapshot:** `golden_vector_values`, `indra/indra-node/src/genesis.rs:979-991`, pins:

```text
election seed:  f449538f3ffe86ac8fe27a2bea99714c8823140efdceda5144ac3f0143d58db0b3649bb84ddef0f63e2ebd3de8ecb1f09b46fc2d0b18fcf1feb3242ba477c039
fingerprint:   3a5f1a3178613c686b686269a5aaf356459a5598f2a0bd3df5c8774402b1677c
genesis block: 185dc492b2c637f7928da5e7f775c3bff2d43575a4e8a2a17ce62c3cced2f3cd
```

The timestamp sensitivity test at `indra/indra-node/src/genesis.rs:889-905` asserts that changing only the timestamp changes fingerprint and block hash while leaving the election seed unchanged.

## 5. Verification status

The following verification lines are explicitly attributed.

| Verification line | Evidence |
|---|---|
| owner-reported, not Codex-verified | Debug `cargo test --workspace`: all targets ok; node library `315 passed / 0 failed / 5 ignored`. Codex has no log path for this owner run. |
| owner-reported, not Codex-verified | Release binary string check: `strings target/release/node | grep -c INDRA-GENESIS-ELECTION-SEED-v2` printed `1`; `strings target/release/node | grep -c -E 'local-test-validator|test-validator-|canonical-local-genesis'` printed `0`. |
| owner-reported, not Codex-verified | Release policy check: OK. Cargo.lock SHA-256: `24eea7cb276c93345c19667483d452b64e2bab9abb72beb9678d6a58dae43f46`. `cargo test --release --workspace`: all targets ok; node library `315 passed / 0 failed / 5 ignored`; log `~/Desktop/review/ws_final_release.log`. |
| run by Codex, log path | `cargo test -p indra-node --lib 'genesis::' -- --test-threads=1`: `30 passed / 0 failed / 0 ignored`; log `~/Desktop/review/genesis_part10_node_genesis_sequential.log`. |

The owner-reported runs above were on `048b6390`. `3f391126` is a test-only commit (+28 lines in `genesis.rs`, 2 tests); the full workspace was not re-run after it. The 30-test `genesis::` run is the only run covering `3f391126`.

## 6. Warning inventory and baseline comparison

**Read from committed snapshot and earlier recorded command output:** The known warning inventory is:

| Warning | Committed location | Baseline comparison |
|---|---|---|
| `value assigned to genesis is never read` | `indra/indra-node/src/engine.rs:4223` | The same assignment existed at line 4169 in `baseline-pre-gate-removal`; this warning predates founder-genesis changes. |
| `fields sealed_genesis, vote_safety_path_a, and vote_safety_path_b are never read` | `indra/indra-node/src/driver_tests.rs:741,744-745` | The same fields existed at lines 786, 789-790 in `baseline-pre-gate-removal`; this warning predates founder-genesis changes. |

## 7. Known limits and open items

- **Read from committed tests:** Fixtures containing a dominant-stake validator are count-rule tests, not BFT tests. The dominant-stake warning behavior is exercised by `genesis_cli_inspect_warns_for_dominant_test_support_manifest`, `indra-cli/tests/cli.rs:362-384`; it does not establish balanced-validator BFT safety.
- **Read from committed implementation:** `ValidatorSet::total_active_stake` uses `saturating_add` at `indra-state/src/validator.rs:685-690`. The genesis validator supply bound is the relied-upon guard against a valid genesis entering an overlarge stake total; the saturation behavior itself is not a proof of monetary correctness.
- **Read from committed implementation:** `select_active_set` has no post-genesis four-validator floor at `indra-state/src/validator.rs:778-800`; it ranks eligible active/registered validators by self stake and applies its capacity. The post-genesis minimum-stake/floor design remains open.
- **Read from committed implementation:** Each genesis validator receives a fixed `GENESIS_VALIDATOR_UTXO_SPARK` output at `indra/indra-node/src/genesis.rs:23,420-424`; the value is `1_000_000_000_000` Spark, i.e. 10,000 INDRA, and is independent of the manifest `stake` stored at `:408-412`. Whether this liquid per-validator genesis UTXO should remain separate from manifest stake is an open design decision.
- **Read from committed implementation and tests:** The `genesis_utxo_total` multiplication has the exact error `genesis validator UTXO total overflows u64` at `indra/indra-node/src/genesis.rs:188-190`, but no committed test reaches it. The count is `validators.len() as u64` (a `usize` cast); overflow can occur above about 18.4 million validator entries. It is practically unreachable; no test covers it.
- **Read from committed snapshot:** The committed tests establish deterministic construction, seed order independence, key/PoP validation, state-root/fingerprint sensitivity, and the golden vector, but they do not replace an independent third-party audit or real multi-machine/network, latency, or long-duration operational validation.

### Citation audit: `git grep -n` at `3f391126`

The following is the exact `git grep -n "fn <name>" 3f391126 -- ...` output for every cited test name in sections 2, 3, 4, and 7:

```text
3f391126:indra/indra-node/src/genesis.rs:703:    fn canonical_genesis_rejects_too_few_mismatched_and_duplicate_identities() {
3f391126:indra/indra-node/src/genesis.rs:788:    fn empty_genesis_manifest_is_rejected() {
3f391126:indra/indra-node/src/genesis.rs:684:    fn canonical_genesis_rejects_missing_cold_fields_and_bad_chain_ids() {
3f391126:indra/indra-node/src/genesis.rs:666:    fn active_slot_coefficient_uses_strict_canonical_decimal_string() {
3f391126:indra/indra-node/src/genesis.rs:908:    fn four_validators_are_required_and_bad_f_is_rejected() {
3f391126:indra/indra-node/src/genesis.rs:716:    fn genesis_rejects_cross_role_key_reuse_and_oversized_fields() {
3f391126:indra/indra-node/src/genesis.rs:824:    fn genesis_rejects_vrf_squatting_cold_history_and_noncanonical_hex() {
3f391126:indra/indra-node/src/genesis.rs:869:    fn invalid_hot_classical_key_is_rejected() {
3f391126:indra/indra-node/src/genesis.rs:879:    fn invalid_hot_pq_key_is_rejected() {
3f391126:indra/indra-node/src/genesis.rs:770:    fn genesis_rejects_invalid_cold_classical_and_pq_keys_with_exact_errors() {
3f391126:indra/indra-node/src/genesis.rs:841:    fn reject_noncanonical_hex() {
3f391126:indra/indra-node/src/genesis.rs:760:    fn genesis_rejects_stake_below_dust_with_exact_error() {
3f391126:indra/indra-node/src/genesis.rs:934:    fn genesis_rejects_stake_sum_overflow() {
3f391126:indra/indra-node/src/genesis.rs:942:    fn genesis_rejects_total_supply_overflow() {
3f391126:indra/indra-node/src/genesis.rs:918:    fn genesis_rejects_total_supply_cap_plus_one() {
3f391126:indra/indra-node/src/genesis.rs:952:    fn genesis_accepts_total_supply_exactly_at_lifetime_cap() {
3f391126:indra/indra-node/src/genesis.rs:960:    fn genesis_validator_name_rules_are_canonical() {
3f391126:indra/indra-node/src/genesis.rs:797:    fn finalized_genesis_preserves_manifest_cold_authority_fields() {
3f391126:indra/indra-node/src/genesis.rs:814:    fn finalized_genesis_sets_height_and_seed_from_manifest() {
3f391126:indra/indra-cli/tests/cli.rs:116:fn genesis_cli_round_trips_and_inspects_all_canonical_roots() {
3f391126:indra/indra-cli/tests/cli.rs:151:fn genesis_cli_build_timestamp_warning_is_nonfatal_and_current_time_is_quiet() {
3f391126:indra/indra-cli/src/bin/genesis.rs:258:    fn genesis_rejects_3_validators() {
3f391126:indra/indra-cli/src/bin/genesis.rs:276:    fn below_dust_stake_rejected() {
3f391126:indra/indra-cli/src/bin/genesis.rs:284:    fn duplicate_validator_id_rejected() {
3f391126:indra/indra-node/src/genesis.rs:979:    fn golden_vector_values() {
3f391126:indra/indra-node/src/genesis.rs:889:    fn genesis_timestamp_changes_fingerprint_and_block_hash_but_not_seed() {
3f391126:indra/indra-cli/tests/cli.rs:362:fn genesis_cli_inspect_warns_for_dominant_test_support_manifest() {
```

