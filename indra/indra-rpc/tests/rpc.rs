//! Integration tests for the RPC layer.

use std::collections::BTreeMap;

use indra_core::types::{
    crypto::HybridPubKey,
    governance::{GovernableAction, ProposalTier},
    primitives::{Bytes32, VariableBytes},
    transaction::OutputV1,
};
use indra_core::CommitmentV1;
use indra_rpc::types::parse_request;
use indra_rpc::{
    handlers::{
        check_rpc_method_allowed, check_rpc_method_allowed_with_admin, dispatch,
        dispatch_with_admin, dispatch_with_mode, DispatchResult, NodeState, PeerTopologyEntry,
        RpcMethodAccess, RpcMode, RPC_METHODS,
    },
    server::{call_rpc, call_rpc_with_mode},
};
use indra_state::governance::{
    GovernanceSnapshot, ProposalPhase, ProposalRecord, VoteCommit, VoteReveal,
};
use indra_state::ChainState;

fn engine(_suffix: &str) -> ChainState {
    ChainState::new_genesis()
}

fn dummy_output(byte: u8) -> OutputV1 {
    OutputV1 {
        value_spark: 1_000 + byte as u64,
        commitment: CommitmentV1 {
            compressed_point: Bytes32::from([byte; 32]),
        },
        owner_pubkey: HybridPubKey {
            classical_pk: Bytes32::from([byte; 32]),
            pq_pk: VariableBytes::from_slice(&[byte; 32]).unwrap(),
        },
        range_proof: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
        lock_height: 0,
    }
}

#[test]
fn rpc_get_height() {
    let e = engine("rpc_h");
    let resp = call_rpc("indra_getHeight", &[], &e);
    assert!(resp.contains("\"height\":0"));
}

#[test]
fn rpc_get_tip() {
    let e = engine("rpc_tip");
    let resp = call_rpc("indra_getTip", &[], &e);
    assert!(resp.contains("\"tip_hash\""));
    assert!(resp.contains("\"height\""));
}

#[test]
fn rpc_get_utxo_proof_reports_canonical_compressed_shape() {
    let mut state = engine("rpc_utxo_proof_compressed");
    let id = state.utxos.insert(dummy_output(0xB1), 1, 0, 0).unwrap();
    let response = call_rpc(
        "indra_getUtxoProof",
        &[format!(r#""{}""#, hex::encode(id.0))],
        &state,
    );
    assert!(response.contains(r#""proof_version":"compressed-auth-tree-v2""#));
    assert!(response.contains(r#""terminal":"#));
    assert!(response.contains(r#""steps":["#));
}

#[test]
fn rpc_get_chain_info_fields() {
    let e = engine("rpc_ci");
    let resp = call_rpc("indra_getChainInfo", &[], &e);
    for field in &[
        "height",
        "base_fee",
        "total_supply",
        "epoch",
        "active_validators",
        "mempool_size",
    ] {
        assert!(resp.contains(field), "missing field: {field}");
    }
}

#[test]
fn rpc_mempool_size_zero_at_genesis() {
    let e = engine("rpc_mp");
    let resp = call_rpc("indra_getMempoolSize", &[], &e);
    assert!(resp.contains("\"size\":0"));
}

#[test]
fn rpc_get_block_beyond_tip() {
    let e = engine("rpc_gb");
    let resp = call_rpc("indra_getBlock", &["999".to_string()], &e);
    assert!(resp.contains("\"error\""));
    assert!(resp.contains("-32000"));
}

#[test]
fn rpc_invalid_method() {
    let e = engine("rpc_inv");
    let resp = call_rpc("indra_doesNotExist", &[], &e);
    assert!(resp.contains("-32601"));

    let full_resp = call_rpc_with_mode("indra_doesNotExist", &[], &e, RpcMode::Full);
    assert!(full_resp.contains("-32601"));
}

#[test]
fn rpc_full_request_parse_and_dispatch() {
    let e = engine("rpc_full");
    let json = r#"{"jsonrpc":"2.0","method":"indra_getHeight","params":[],"id":42}"#;
    let req = parse_request(json).unwrap();
    assert_eq!(req.method, "indra_getHeight");
    let resp = call_rpc(&req.method, &req.params, &e);
    assert!(resp.contains("\"height\""));
}

#[test]
fn get_staking_nonce_returns_zero_for_unknown() {
    let e = engine("rpc_nonce");
    let signer = "11".repeat(32);
    let resp = call_rpc("indra_getStakingNonce", &[format!(r#""{}""#, signer)], &e);
    assert!(resp.contains("\"nonce\":0"));
    assert!(resp.contains("\"next_nonce\":1"));
}

#[test]
fn old_public_utxo_scan_methods_are_removed_from_public_rpc() {
    assert!(!RPC_METHODS
        .iter()
        .any(|(name, _)| *name == "indra_getUtxos"));
    assert!(!RPC_METHODS
        .iter()
        .any(|(name, _)| *name == "indra_getBalance"));

    let e = engine("rpc_old_utxo_methods_removed");
    let resp = call_rpc_with_mode(
        "indra_getUtxos",
        &[format!(r#""{}""#, "11".repeat(32))],
        &e,
        RpcMode::ReadOnly,
    );
    assert!(resp.contains("\"error\""));
    assert!(resp.contains("-32601"));

    let full_resp = call_rpc_with_mode(
        "indra_getUtxos",
        &[format!(r#""{}""#, "11".repeat(32))],
        &e,
        RpcMode::Full,
    );
    assert!(full_resp.contains("\"error\""));
    assert!(full_resp.contains("-32601"));
}

#[test]
fn get_epoch_info_has_all_fields() {
    let e = engine("rpc_epoch");
    let resp = call_rpc("indra_getEpochInfo", &[], &e);
    for field in &[
        "epoch",
        "epoch_start_height",
        "epoch_end_height",
        "blocks_remaining",
        "block_reward_spark",
    ] {
        assert!(resp.contains(field), "missing field: {field}");
    }
}

#[test]
fn test_get_epoch_record_not_found_for_future_epoch() {
    let e = engine("rpc_epoch_record_missing");
    let resp = call_rpc("indra_getEpochRecord", &["999".to_string()], &e);
    assert!(resp.contains("\"error\""));
    assert!(resp.contains("-32000"));
}

#[test]
fn test_get_epoch_history_empty_when_no_epochs() {
    let e = engine("rpc_epoch_history_empty");
    let resp = call_rpc("indra_getEpochHistory", &[], &e);
    assert!(resp.contains("\"epochs\":[]"));
    assert!(resp.contains("\"count\":0"));
    assert!(resp.contains("\"oldest_epoch\":null"));
    assert!(resp.contains("\"latest_epoch\":null"));
}

#[test]
fn test_get_latest_epoch_null_when_no_epochs() {
    let e = engine("rpc_latest_epoch_empty");
    let resp = call_rpc("indra_getLatestEpoch", &[], &e);
    assert!(resp.contains("\"result\":null"));
}

#[test]
fn get_validator_stake_positions_returns_empty_for_unknown_validator() {
    let e = engine("rpc_positions");
    let validator = "22".repeat(32);
    let resp = call_rpc(
        "indra_getValidatorStakePositions",
        &[format!(r#""{}""#, validator)],
        &e,
    );
    assert!(resp.contains("\"positions\":[]"));
    assert!(resp.contains("\"total_count\":0"));
}

#[test]
fn get_proposal_votes_reports_committed_and_revealed_flags() {
    let mut e = engine("rpc_proposal_votes_flags");
    let proposal_id = Bytes32::from([0xE1; 32]);
    let validator_id = Bytes32::from([0xA1; 32]);
    let mut weights = BTreeMap::new();
    weights.insert(validator_id, 100);
    let snapshot = GovernanceSnapshot {
        weights,
        total_stake: 100,
    };
    let mut commits = BTreeMap::new();
    commits.insert(
        validator_id,
        VoteCommit {
            validator_id,
            commit_hash: Bytes32::from([0xC1; 32]),
            committed_epoch: 1,
        },
    );
    let mut reveals = BTreeMap::new();
    reveals.insert(
        validator_id,
        VoteReveal {
            validator_id,
            vote: true,
            revealed_epoch: 2,
        },
    );
    e.governance.proposals.insert(
        proposal_id,
        ProposalRecord {
            proposal_id,
            proposer_id: validator_id,
            proposer_pubkey: HybridPubKey {
                classical_pk: Bytes32::from([0xB1; 32]),
                pq_pk: VariableBytes::from_slice(&[0xB2; 32]).unwrap(),
            },
            tier: ProposalTier::Standard,
            action: GovernableAction::SetMinDelegationSpark { value: 1 },
            title: "test".to_string(),
            description: "test".to_string(),
            deposit_spark: 0,
            deposit_burned: false,
            proposed_epoch: 0,
            commit_start_epoch: 1,
            reveal_start_epoch: 2,
            tally_epoch: 3,
            exec_delay_epochs: 0,
            executable_after_epoch: 0,
            phase: ProposalPhase::Reveal,
            snapshot1: Some(snapshot),
            commits,
            reveals,
            redelegations: Vec::new(),
            redelegated_delegators: BTreeMap::new(),
            snapshot2: None,
            yes_stake: 0,
            no_stake: 0,
            abstain_stake: 0,
            passed: None,
        },
    );

    let resp = call_rpc(
        "indra_getProposalVotes",
        &[format!(r#""{}""#, hex::encode(proposal_id.0))],
        &e,
    );
    assert!(resp.contains("\"committed\":true"));
    assert!(resp.contains("\"revealed\":true"));
}

#[test]
fn rpc_governance_queries_reflect_retained_state_after_pruning() {
    let mut e = engine("rpc_proposal_pruned");
    let retained_id = Bytes32::from([0xE2; 32]);
    let pruned_id = Bytes32::from([0xE3; 32]);
    for proposal_id in [retained_id, pruned_id] {
        e.governance.proposals.insert(
            proposal_id,
            ProposalRecord {
                proposal_id,
                proposer_id: Bytes32::from([0xA2; 32]),
                proposer_pubkey: HybridPubKey {
                    classical_pk: Bytes32::from([0xB3; 32]),
                    pq_pk: VariableBytes::from_slice(&[0xB4; 32]).unwrap(),
                },
                tier: ProposalTier::Standard,
                action: GovernableAction::SetMinDelegationSpark { value: 1 },
                title: "retained-state".to_string(),
                description: "ordinary RPC exposes active plus retained recent proposals"
                    .to_string(),
                deposit_spark: 0,
                deposit_burned: false,
                proposed_epoch: 0,
                commit_start_epoch: 1,
                reveal_start_epoch: 2,
                tally_epoch: 3,
                exec_delay_epochs: 0,
                executable_after_epoch: 0,
                phase: ProposalPhase::Failed,
                snapshot1: None,
                commits: BTreeMap::new(),
                reveals: BTreeMap::new(),
                redelegations: Vec::new(),
                redelegated_delegators: BTreeMap::new(),
                snapshot2: None,
                yes_stake: 0,
                no_stake: 0,
                abstain_stake: 0,
                passed: Some(false),
            },
        );
    }
    e.governance.proposals.remove(&pruned_id);

    let retained = call_rpc(
        "indra_getProposal",
        &[format!(r#""{}""#, hex::encode(retained_id.0))],
        &e,
    );
    assert!(retained.contains("\"proposal_id\""));
    assert!(retained.contains(&hex::encode(retained_id.0)));

    let pruned = call_rpc(
        "indra_getProposal",
        &[format!(r#""{}""#, hex::encode(pruned_id.0))],
        &e,
    );
    assert!(pruned.contains("\"error\""));
    assert!(pruned.contains("proposal not found"));

    let pruned_votes = call_rpc(
        "indra_getProposalVotes",
        &[format!(r#""{}""#, hex::encode(pruned_id.0))],
        &e,
    );
    assert!(pruned_votes.contains("\"error\""));
    assert!(pruned_votes.contains("proposal not found"));
}

#[test]
fn test_get_owner_stake_positions_unknown_returns_empty() {
    let e = engine("rpc_positions_unknown");
    let delegator = "33".repeat(32);
    let resp = call_rpc(
        "indra_getOwnerStakePositions",
        &[format!(r#""{}""#, delegator)],
        &e,
    );

    assert!(resp.contains("\"positions\":[]"));
    assert!(resp.contains("\"total_count\":0"));
}

#[test]
fn test_get_delegator_rewards_unknown_returns_zero() {
    let e = engine("rpc_rewards_unknown");
    let delegator = "44".repeat(32);
    let resp = call_rpc(
        "indra_getDelegatorRewards",
        &[format!(r#""{}""#, delegator)],
        &e,
    );

    assert!(resp.contains("\"total_pending_rewards\":0"));
    assert!(resp.contains("\"claimable_from\":[]"));
}

#[test]
fn test_get_unbonding_tranches_unknown_returns_empty() {
    let e = engine("rpc_validator_delegators_unknown");
    let validator = "55".repeat(32);
    let resp = call_rpc(
        "indra_getUnbondingTranches",
        &["null".into(), "null".into(), format!(r#""{}""#, validator)],
        &e,
    );

    assert!(resp.contains("\"tranches\":[]"));
    assert!(resp.contains("\"total_count\":0"));
}

#[test]
fn test_all_methods_reachable_via_dispatch() {
    let e = engine("rpc_all_methods");
    let state = NodeState::read_only(&e);
    let hex32 = format!(r#""{}""#, "11".repeat(32));
    let methods: Vec<(&str, Vec<String>)> = vec![
        ("indra_getHeight", vec![]),
        ("indra_getTip", vec![]),
        ("indra_getChainInfo", vec![]),
        ("indra_getMempoolSize", vec![]),
        ("indra_getBlock", vec!["0".to_string()]),
        ("indra_getLegacyScanChallenge", vec![hex32.clone()]),
        ("indra_getUtxoProof", vec![hex32.clone()]),
        ("indra_getPeers", vec![]),
        ("indra_getStakingNonce", vec![hex32.clone()]),
        ("indra_getStakePositions", vec![]),
        ("indra_getStakePosition", vec![hex32.clone()]),
        ("indra_getUnbondingTranches", vec![]),
        ("indra_getUnbondingTranche", vec![hex32.clone()]),
        ("indra_getValidatorStakePositions", vec![hex32.clone()]),
        ("indra_getOwnerStakePositions", vec![hex32.clone()]),
        ("indra_getDelegatorRewards", vec![hex32.clone()]),
        ("indra_getDelegatorIdentityDebug", vec![hex32.clone()]),
        ("indra_getEpochInfo", vec![]),
        ("indra_getEpochRecord", vec!["0".to_string()]),
        ("indra_getEpochHistory", vec![]),
        ("indra_getLatestEpoch", vec![]),
        ("indra_getProposals", vec![]),
        ("indra_getProposal", vec![hex32.clone()]),
        ("indra_getProposalVotes", vec![hex32.clone()]),
        ("indra_getGovernanceParams", vec![]),
        ("indra_getGovernanceNonce", vec![hex32.clone()]),
        ("indra_getValidatorRewards", vec![hex32.clone()]),
        ("indra_getValidator", vec![hex32.clone()]),
        ("indra_getValidatorSelfStake", vec![hex32.clone()]),
        ("indra_getValidatorAutoDelegate", vec![hex32.clone()]),
        ("indra_getValidatorSet", vec![]),
        ("indra_getRpcPolicy", vec![]),
        ("indra_submitStakingOp", vec![r#""00""#.to_string()]),
        ("indra_submitGovernanceOp", vec![r#""00""#.to_string()]),
        ("indra_sendTransaction", vec![r#""00""#.to_string()]),
    ];

    for (method, params) in methods {
        assert!(
            RPC_METHODS.iter().any(|(name, _)| *name == method),
            "{method} must be explicitly classified for public read-only gating"
        );
        match dispatch(method, &params, &state) {
            DispatchResult::Ready(Err(indra_rpc::RpcError::MethodNotFound(_))) => {
                panic!("{method} was not reachable through dispatch")
            }
            _ => {}
        }
    }
}

#[test]
fn admin_method_reachable_only_with_valid_admin_policy() {
    let e = engine("rpc_admin_reachable");
    let state = NodeState::with_network_policy(
        &e,
        vec!["203.0.113.10:30303".to_string()],
        vec![PeerTopologyEntry {
            validator_id: Some("aa".repeat(32)),
            address: "203.0.113.10:30303".to_string(),
        }],
        1,
        2,
        3,
        RpcMode::Full,
        true,
    );

    match dispatch_with_admin(
        "indra_getPeerTopology",
        &[],
        &state,
        RpcMode::Full,
        true,
        true,
    ) {
        DispatchResult::Ready(Ok(result)) => {
            assert!(result.contains("validator_peers"));
            assert!(result.contains("203.0.113.10:30303"));
            assert!(result.contains(&"aa".repeat(32)));
        }
        _ => panic!("admin topology should be reachable with valid token"),
    }
}

#[test]
fn rpc_policy_reports_mode_and_token_presence_without_token_value() {
    let e = engine("rpc_policy");
    let state =
        NodeState::with_network_policy(&e, Vec::new(), Vec::new(), 0, 0, 0, RpcMode::Full, true);

    match dispatch_with_mode("indra_getRpcPolicy", &[], &state, RpcMode::Full) {
        DispatchResult::Ready(Ok(result)) => {
            assert!(result.contains(r#""listener_mode":"full""#));
            assert!(result.contains(r#""admin_token_configured":true"#));
            assert!(result.contains(r#""admin_token_value_exposed":false"#));
            assert!(!result.contains("secret"));
        }
        _ => panic!("rpc policy should be reachable as a read-only method"),
    }
}

#[test]
fn readonly_listener_rejects_unclassified_method() {
    let method = "indra_futureWriteMethodForgotClassification";
    assert!(
        !RPC_METHODS.iter().any(|(name, _)| *name == method),
        "test method must remain unclassified to prove read-only mode fails closed"
    );

    let err = check_rpc_method_allowed(method, RpcMode::ReadOnly).unwrap_err();
    assert!(matches!(err, indra_rpc::RpcError::MethodNotFound(_)));
}

#[test]
fn readonly_listener_allows_classified_read_methods_at_policy_gate() {
    for (method, access) in RPC_METHODS {
        if *access == RpcMethodAccess::ReadOnly {
            assert!(
                check_rpc_method_allowed(method, RpcMode::ReadOnly).is_ok(),
                "classified read-only method {method} should pass the read-only policy gate"
            );
        }
    }
}

#[test]
fn readonly_listener_rejects_classified_write_methods_at_policy_gate() {
    for (method, access) in RPC_METHODS {
        if *access == RpcMethodAccess::Write {
            let err = check_rpc_method_allowed(method, RpcMode::ReadOnly).unwrap_err();
            assert!(
                matches!(err, indra_rpc::RpcError::Forbidden(_)),
                "classified write method {method} should be forbidden on read-only listener"
            );
        }
    }
}

#[test]
fn admin_endpoint_rejected_when_no_token_is_provided() {
    let err =
        check_rpc_method_allowed_with_admin("indra_getPeerTopology", RpcMode::Full, true, false)
            .unwrap_err();
    assert!(matches!(err, indra_rpc::RpcError::Forbidden(_)));
    assert!(err.message().contains("X-Admin-Token"));
}

#[test]
fn admin_endpoint_rejected_when_token_is_wrong() {
    let err =
        check_rpc_method_allowed_with_admin("indra_getPeerTopology", RpcMode::Full, true, false)
            .unwrap_err();
    assert!(matches!(err, indra_rpc::RpcError::Forbidden(_)));
    assert!(err.message().contains("valid X-Admin-Token"));
}

#[test]
fn admin_endpoint_accepted_with_correct_token_on_full_listener() {
    assert!(check_rpc_method_allowed_with_admin(
        "indra_getPeerTopology",
        RpcMode::Full,
        true,
        true
    )
    .is_ok());
}

#[test]
fn admin_endpoint_rejected_on_readonly_listener_even_with_valid_token() {
    let err =
        check_rpc_method_allowed_with_admin("indra_getPeerTopology", RpcMode::ReadOnly, true, true)
            .unwrap_err();
    assert!(matches!(err, indra_rpc::RpcError::Forbidden(_)));
    assert!(err.message().contains("read-only listener"));
}

#[test]
fn empty_or_unset_admin_token_disables_admin_endpoints_fail_closed() {
    let err =
        check_rpc_method_allowed_with_admin("indra_getPeerTopology", RpcMode::Full, false, true)
            .unwrap_err();
    assert!(matches!(err, indra_rpc::RpcError::Forbidden(_)));
    assert!(err.message().contains("not configured"));
}

#[test]
fn full_listener_policy_gate_allows_classified_and_unclassified_methods() {
    for (method, access) in RPC_METHODS {
        if *access == RpcMethodAccess::Admin {
            continue;
        }
        assert!(
            check_rpc_method_allowed(method, RpcMode::Full).is_ok(),
            "full listener should allow classified method {method}"
        );
    }
    assert!(matches!(
        check_rpc_method_allowed("indra_unclassifiedFutureMethod", RpcMode::Full),
        Err(indra_rpc::RpcError::MethodNotFound(_))
    ));
}

#[test]
fn read_only_listener_allows_every_classified_read_method() {
    let e = engine("rpc_read_only_methods");
    let state = NodeState::read_only(&e);
    let hex32 = format!(r#""{}""#, "11".repeat(32));

    let params_for = |method: &str| -> Vec<String> {
        match method {
            "indra_getBlock" => vec!["0".to_string()],
            "indra_getLegacyScanChallenge"
            | "indra_getUtxoProof"
            | "indra_getStakingNonce"
            | "indra_getDelegatorRewards"
            | "indra_getStakePosition"
            | "indra_getUnbondingTranche"
            | "indra_getValidatorStakePositions"
            | "indra_getOwnerStakePositions"
            | "indra_getProposal"
            | "indra_getProposalVotes"
            | "indra_getGovernanceNonce"
            | "indra_getValidatorRewards"
            | "indra_getValidator"
            | "indra_getValidatorSelfStake"
            | "indra_getValidatorAutoDelegate" => vec![hex32.clone()],
            "indra_getEpochRecord" => vec!["0".to_string()],
            _ => Vec::new(),
        }
    };

    for (method, access) in RPC_METHODS {
        if *access != RpcMethodAccess::ReadOnly {
            continue;
        }
        match dispatch_with_mode(method, &params_for(method), &state, RpcMode::ReadOnly) {
            DispatchResult::Ready(Err(indra_rpc::RpcError::Forbidden(error))) => {
                panic!("read-only method {method} was blocked: {error}")
            }
            DispatchResult::SubmitStakingOp(_)
            | DispatchResult::SubmitGovernanceOp(_)
            | DispatchResult::SubmitTransaction(_) => {
                panic!("read-only method {method} produced a submission action")
            }
            _ => {}
        }
    }
}

#[test]
fn read_only_listener_rejects_every_write_method_before_decoding() {
    let e = engine("rpc_read_only_rejects_writes");
    let invalid_payload = vec![r#""not valid hex""#.to_string()];

    for (method, access) in RPC_METHODS {
        if *access != RpcMethodAccess::Write {
            continue;
        }
        let resp = call_rpc_with_mode(method, &invalid_payload, &e, RpcMode::ReadOnly);
        assert!(resp.contains("\"error\""), "{method} should be rejected");
        assert!(
            resp.contains("not available on read-only listener"),
            "{method} was not rejected at the read-only dispatch gate: {resp}"
        );
        assert!(
            !resp.contains("decode failed") && !resp.contains("invalid hex"),
            "{method} reached write decoding instead of being blocked first: {resp}"
        );
    }
}

#[test]
fn full_listener_write_methods_are_not_read_only_blocked() {
    let e = engine("rpc_full_writes");
    let syntactically_valid_payload = vec![r#""00""#.to_string()];

    for method in [
        "indra_submitStakingOp",
        "indra_submitGovernanceOp",
        "indra_sendTransaction",
    ] {
        let state = NodeState::read_only(&e);
        match dispatch_with_mode(method, &syntactically_valid_payload, &state, RpcMode::Full) {
            DispatchResult::Ready(Err(indra_rpc::RpcError::Forbidden(error))) => {
                panic!("full listener incorrectly blocked {method}: {error}")
            }
            DispatchResult::SubmitStakingOp(_)
            | DispatchResult::SubmitGovernanceOp(_)
            | DispatchResult::SubmitTransaction(_) => {}
            DispatchResult::Ready(other) => {
                panic!("full listener did not dispatch {method} to submission path: {other:?}")
            }
        }
    }
}
