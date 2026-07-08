//! Integration tests for the RPC layer.

use indra_rpc::types::parse_request;
use indra_rpc::{
    handlers::{
        check_rpc_method_allowed, dispatch, dispatch_with_mode, DispatchResult, NodeState,
        RpcMethodAccess, RpcMode, RPC_METHODS,
    },
    server::{call_rpc, call_rpc_with_mode},
};
use indra_state::ChainState;

fn engine(_suffix: &str) -> ChainState {
    ChainState::new_genesis()
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
    assert!(resp.contains("-32003"));
    assert!(resp.contains("read-only listener"));

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
fn get_delegations_returns_empty_for_unknown_validator() {
    let e = engine("rpc_delegations");
    let validator = "22".repeat(32);
    let resp = call_rpc("indra_getDelegations", &[format!(r#""{}""#, validator)], &e);
    assert!(resp.contains("\"delegators\":[]"));
}

#[test]
fn test_get_delegator_positions_unknown_returns_empty() {
    let e = engine("rpc_positions_unknown");
    let delegator = "33".repeat(32);
    let resp = call_rpc(
        "indra_getDelegatorPositions",
        &[format!(r#""{}""#, delegator)],
        &e,
    );

    assert!(resp.contains("\"positions\":[]"));
    assert!(resp.contains("\"total_staked_spark\":0"));
    assert!(resp.contains("\"total_pending_rewards\":0"));
    assert!(resp.contains("\"active_positions\":0"));
    assert!(resp.contains("\"unbonding_positions\":0"));
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
fn test_get_validator_delegators_unknown_returns_empty() {
    let e = engine("rpc_validator_delegators_unknown");
    let validator = "55".repeat(32);
    let resp = call_rpc(
        "indra_getValidatorDelegators",
        &[format!(r#""{}""#, validator)],
        &e,
    );

    assert!(resp.contains("\"validator_name\":\"unknown\""));
    assert!(resp.contains("\"total_delegated_spark\":0"));
    assert!(resp.contains("\"total_pending_rewards\":0"));
    assert!(resp.contains("\"delegator_count\":0"));
    assert!(resp.contains("\"delegators\":[]"));
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
        ("indra_getBalance", vec![hex32.clone()]),
        ("indra_getUtxos", vec![hex32.clone()]),
        ("indra_getUtxoProof", vec![hex32.clone()]),
        ("indra_getPeers", vec![]),
        ("indra_getStakingNonce", vec![hex32.clone()]),
        ("indra_getDelegations", vec![hex32.clone()]),
        ("indra_getDelegatorPositions", vec![hex32.clone()]),
        ("indra_getDelegatorRewards", vec![hex32.clone()]),
        ("indra_getValidatorDelegators", vec![hex32.clone()]),
        ("indra_getStakeBonds", vec![hex32.clone()]),
        ("indra_getEpochInfo", vec![]),
        ("indra_getEpochRecord", vec!["0".to_string()]),
        ("indra_getEpochHistory", vec![]),
        ("indra_getLatestEpoch", vec![]),
        ("indra_getSchemaInfo", vec![]),
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
fn readonly_listener_rejects_unclassified_method() {
    let method = "indra_futureWriteMethodForgotClassification";
    assert!(
        !RPC_METHODS.iter().any(|(name, _)| *name == method),
        "test method must remain unclassified to prove read-only mode fails closed"
    );

    let err = check_rpc_method_allowed(method, RpcMode::ReadOnly).unwrap_err();
    assert!(matches!(err, indra_rpc::RpcError::Forbidden(_)));
    assert!(err.message().contains("read-only listener"));
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
fn full_listener_policy_gate_allows_classified_and_unclassified_methods() {
    for (method, _) in RPC_METHODS {
        assert!(
            check_rpc_method_allowed(method, RpcMode::Full).is_ok(),
            "full listener should allow classified method {method}"
        );
    }
    assert!(check_rpc_method_allowed("indra_unclassifiedFutureMethod", RpcMode::Full).is_ok());
}

#[test]
fn read_only_listener_allows_every_classified_read_method() {
    let e = engine("rpc_read_only_methods");
    let state = NodeState::read_only(&e);
    let hex32 = format!(r#""{}""#, "11".repeat(32));

    let params_for = |method: &str| -> Vec<String> {
        match method {
            "indra_getBlock" => vec!["0".to_string()],
            "indra_getBalance"
            | "indra_getUtxos"
            | "indra_getUtxoProof"
            | "indra_getStakingNonce"
            | "indra_getDelegations"
            | "indra_getDelegatorPositions"
            | "indra_getDelegatorRewards"
            | "indra_getValidatorDelegators"
            | "indra_getStakeBonds"
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

#[test]
fn test_get_schema_info_has_required_fields() {
    let e = engine("rpc_schema_info");
    let resp = call_rpc("indra_getSchemaInfo", &[], &e);
    assert!(resp.contains("\"schema_version\":4"));
    assert!(resp.contains("\"schema_version_genesis\":1"));
    assert!(resp.contains("\"node_version\""));
    assert!(resp.contains("\"migration_history\""));
}
