# Issuance-model tokenomics acceptance matrix

This is the permanent traceability record for Section 13 of
`ISSUANCE_MODEL_TOKENOMICS_DESIGN_SPEC.md`. Test names are canonical Rust test
names; a row may cite more than one test where the invariant crosses crates.

| # | Permanent evidence |
|---:|---|
| 1 | `chain::tests::genesis_issuance_is_checked_exactly_against_lifetime_cap` |
| 2 | `chain::tests::genesis_issuance_is_checked_exactly_against_lifetime_cap` (cap + 1 case) |
| 3 | `chain::tests::genesis_issuance_is_checked_exactly_against_lifetime_cap` (exact-cap case) |
| 4 | `monetary::tests::zero_budget_mints_zero_forever_and_over_cap_is_rejected` |
| 5 | `chain::tests::snapshot_decode_rederives_all_monetary_aggregates_and_ledger_identity` |
| 6 | `chain::tests::snapshot_decode_rederives_all_monetary_aggregates_and_ledger_identity` |
| 7 | `monetary_invariants::total_supply_invariant_across_full_epoch_cycle`; `apply::tests::apply_empty_block_advances_height` |
| 8 | `monetary_invariants::total_supply_invariant_across_full_epoch_cycle`; `chain::tests::snapshot_decode_rederives_all_monetary_aggregates_and_ledger_identity` |
| 9 | `governance::tests::governance_actions_are_constitutionally_non_monetary` |
| 10 | `monetary::tests::exhaustive_small_budgets_are_exact` |
| 11 | `monetary::tests::exhaustive_small_budgets_are_exact` |
| 12 | `monetary::tests::maximum_budget_first_finishes_in_era_59` |
| 13 | `monetary::tests::eras_and_blocks_telescope_exactly` |
| 14 | `monetary::tests::eras_and_blocks_telescope_exactly` |
| 15 | `monetary::tests::adjacent_rewards_differ_by_at_most_one_and_boundaries_are_exact` |
| 16 | `monetary::tests::adjacent_rewards_differ_by_at_most_one_and_boundaries_are_exact` |
| 17 | `monetary::tests::fixed_width_schedule_matches_independent_big_integer_oracle` |
| 18 | `epoch::tests::runtime_issuance_rejects_inconsistent_cumulative_target_without_mutation` |
| 19 | `epoch::tests::runtime_issuance_rejects_lifetime_cap_overrun_without_mutation` |
| 20 | `epoch::tests::largest_remainder_is_exact_and_input_order_independent` |
| 21 | `epoch::tests::largest_remainder_is_exact_and_input_order_independent` |
| 22 | `epoch::tests::position_fragmentation_changes_aggregate_by_at_most_one_spark`; `apply::tests::largest_remainder_fragmentation_cannot_reduce_effective_slash_rate` |
| 23 | `epoch::tests::reward_distribution_no_overflow_large_stake`; `epoch::tests::auto_delegation_does_not_violate_supply_invariant`; `epoch::tests::proposer_cannot_earn_extra_reward_by_including_more_transactions` |
| 24 | Compile-time field removal plus the zero-reference command recorded below |
| 25 | `apply::tests::reporter_reward_pays_exact_five_percent_and_conserves_full_slash_flow` |
| 26 | `apply::tests::unified_liveness_directive_slashes_active_and_post_infraction_self_tranche_only` |
| 27 | `apply::tests::unified_liveness_directive_slashes_active_and_post_infraction_self_tranche_only` |
| 28 | `apply::tests::reporter_reward_pays_exact_five_percent_and_conserves_full_slash_flow`; `apply::tests::reporter_reward_dust_boundary_is_exact_and_sub_dust_share_is_burned` |
| 29 | `apply::tests::fee_burns_supply`; `governance_apply::tests::governance_burn_overflow_is_atomic`; `epoch::tests::liveness_penalty_burns_supply`; reporter tests in row 28 |
| 30 | `types::epoch_record::tests::epoch_record_encode_decode_round_trip`; `epoch::tests::epoch_transition_is_deterministic` |
| 31 | `epoch::tests::position_reward_overflow_fails_closed`; `epoch::tests::runtime_issuance_rejects_lifetime_cap_overrun_without_mutation`; `governance_apply::tests::governance_burn_overflow_is_atomic`; `apply::tests::project_block_for_roots_failpoint_rollback_covers_each_mutation` |
| 32 | `engine::tests::restart_from_snapshot_produces_same_state_as_continuous`; `sync::tests::imported_projection_commit_matches_reference_two_step_sequence`; `state_machine::epoch_transition_produces_identical_state_on_replay` |
| 33 | `rg -n 'treasury_balance|burn_buffer|MAX_RANGE_PROOF_BYTES|VALIDATOR_REWARDS_POOL_SPARK|ERA_[1-5]_BLOCK_REWARD_SPARK|HARD_CAP_SPARK|GENESIS_SUPPLY_(SPARK|INDRA)' --glob '*.rs'` must return no live-code matches |

The runtime cap test intentionally constructs an inconsistent near-cap state and
asserts byte-for-byte no mutation on rejection. It caught and permanently
guards the ordering requirement that cap/budget validation happen before reward
allocation credits any recipient.
