#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$repo"

# Fixed test names and no randomized inputs make this harness deterministic.
cargo test -p indra-network consensus_duplicate_filter_detects_exact_vote_duplicates
cargo test -p indra-network qc_response_dedup_is_node_wide_and_forwards_once
cargo test -p indra-network relay_does_not_forward_duplicate_vote
cargo test -p indra-network disconnect_does_not_reset_validator_vote_budget
cargo test -p indra-consensus duplicate_vote_rejected
cargo test -p indra-node peer_status_repeated_messages_cannot_force_round_advance
cargo test -p indra-node future_and_wrong_parent_proposals_are_dropped_before_consensus_mutation
cargo test -p indra-node response_binding_rejects_unsolicited_wrong_peer_and_out_of_range
cargo test -p indra-node accepted_proposal_replay_skips_authoritative_admission_across_peer_paths
cargo test -p indra-node invalid_proposal_cannot_poison_accepted_replay_state
cargo test -p indra-node accepted_height_two_proposal_replay_skips_embedded_qc_verification
cargo test -p indra-node accepted_vote_replay_skips_snapshot_and_hybrid_work_across_peer_paths
cargo test -p indra-node cryptographically_invalid_vote_cannot_poison_replay_state
cargo test -p indra-node wrong_snapshot_vote_is_not_collapsed_into_exact_replay
cargo test -p indra-node conflicting_vote_orderings_bypass_exact_replay_fast_path

# Guard both remediated trusted replay boundaries.
python3 audit_evidence/21_consensus_network_adversarial/02_replay_duplication/harness/source_order.py
