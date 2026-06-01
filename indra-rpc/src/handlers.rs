//! RPC method handlers.
//!
//! Each handler receives the parsed request params and a reference to
//! the node state, and returns a JSON string result or an RpcError.

use indra_node::NodeEngine;

use crate::{
    error::{RpcError, RpcResult},
    types::unquote,
};

/// Shared node state passed to all handlers.
pub struct NodeState<'a> {
    /// The node engine.
    pub engine: &'a NodeEngine,
}

/// Dispatch a method call to the appropriate handler.
pub fn dispatch(
    method: &str,
    params: &[String],
    state: &NodeState<'_>,
) -> RpcResult<String> {
    match method {
        "indra_getHeight"       => get_height(state),
        "indra_getTip"          => get_tip(state),
        "indra_getChainInfo"    => get_chain_info(state),
        "indra_getMempoolSize"  => get_mempool_size(state),
        "indra_getBlock"        => get_block(params, state),
        "indra_getValidator"    => get_validator(params, state),
        "indra_getValidatorSet" => get_validator_set(state),
        "indra_sendTransaction" => send_transaction(params, state),
        _                       => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

/// `indra_getHeight` — returns the current chain height.
///
/// Result: `{"height": <u64>}`
fn get_height(state: &NodeState<'_>) -> RpcResult<String> {
    Ok(format!(r#"{{"height":{}}}"#, state.engine.state.height))
}

/// `indra_getTip` — returns the current tip hash and height.
///
/// Result: `{"height": <u64>, "tip_hash": "<hex>"}`
fn get_tip(state: &NodeState<'_>) -> RpcResult<String> {
    let tip = hex::encode(state.engine.state.tip_hash.0);
    Ok(format!(
        r#"{{"height":{},"tip_hash":"{}"}}"#,
        state.engine.state.height,
        tip
    ))
}

/// `indra_getChainInfo` — returns a full chain summary.
///
/// Result: `{"height", "tip_hash", "base_fee", "total_supply",
///           "treasury_balance", "burn_buffer", "fee_reward_pool",
///           "active_validators", "mempool_size", "epoch",
///           "pruned_mode", "lowest_block", "blocks_retained",
///           "block_reward_spark", "era"}`
fn get_chain_info(state: &NodeState<'_>) -> RpcResult<String> {
    let s = &state.engine.state;
    let tip = hex::encode(s.tip_hash.0);
    let active_validators = s.validators.active_count();
    let total_staked_spark = s
        .validators
        .total_selectable_self_stake()
        .saturating_add(s.delegations.total_staked());
    let max_active_validators =
        indra_core::types::primitives::max_active_validators(total_staked_spark);
    let effective_min_stake_spark = s
        .validators
        .effective_min_active_stake(&s.delegations)
        .unwrap_or(0);
    let validator_set_phase =
        indra_core::types::primitives::validator_set_phase(total_staked_spark);
    let mempool_size = state.engine.mempool.len();
    let epoch = s.current_epoch();
    let block_reward_spark = indra_state::epoch::block_reward_at_height(s.height);
    let era = era_for_height(s.height);
    let pruned_mode = !state.engine.block_store.is_archive();
    let lowest_block = state.engine.block_store.lowest_height();
    let blocks_retained = state.engine.block_store.len();

    Ok(format!(
        r#"{{"height":{height},"tip_hash":"{tip}","base_fee":{base_fee},"total_supply":{total_supply},"treasury_balance":{treasury},"burn_buffer":{burn},"fee_reward_pool":{fee_reward_pool},"active_validators":{validators},"max_active_validators":{max_active_validators},"total_staked_spark":{total_staked_spark},"effective_min_stake_spark":{effective_min_stake_spark},"validator_set_phase":{validator_set_phase},"mempool_size":{mempool},"epoch":{epoch},"pruned_mode":{pruned_mode},"lowest_block":{lowest_block},"blocks_retained":{blocks_retained},"block_reward_spark":{block_reward_spark},"era":{era}}}"#,
        height        = s.height,
        tip           = tip,
        base_fee      = s.base_fee,
        total_supply  = s.total_supply,
        treasury      = s.treasury_balance,
        burn          = s.burn_buffer,
        fee_reward_pool = s.fee_reward_pool,
        validators    = active_validators,
        max_active_validators = max_active_validators,
        total_staked_spark = total_staked_spark,
        effective_min_stake_spark = effective_min_stake_spark,
        validator_set_phase = validator_set_phase,
        mempool       = mempool_size,
        epoch         = epoch,
        pruned_mode   = if pruned_mode { "true" } else { "false" },
        lowest_block  = lowest_block,
        blocks_retained = blocks_retained,
        block_reward_spark = block_reward_spark,
        era           = era,
    ))
}

fn era_for_height(height: u64) -> u64 {
    use indra_core::types::primitives::{ERA_1_2_DURATION_BLOCKS, ERA_3_PLUS_DURATION_BLOCKS};

    if height < ERA_1_2_DURATION_BLOCKS {
        1
    } else if height < ERA_1_2_DURATION_BLOCKS * 2 {
        2
    } else {
        3 + ((height - (ERA_1_2_DURATION_BLOCKS * 2)) / ERA_3_PLUS_DURATION_BLOCKS)
    }
}

/// `indra_getMempoolSize` — returns the number of pending transactions.
///
/// Result: `{"size": <usize>}`
fn get_mempool_size(state: &NodeState<'_>) -> RpcResult<String> {
    Ok(format!(r#"{{"size":{}}}"#, state.engine.mempool.len()))
}

/// `indra_getBlock` — returns a block by height.
///
/// Params: `[<height: number>]`
/// Result: `{"height", "prev_hash", "state_root", "base_fee",
///           "tx_count", "timestamp"}`
fn get_block(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let height_str = params.first()
        .ok_or_else(|| RpcError::InvalidParams("missing height parameter".to_string()))?;

    let height: u64 = unquote(height_str)
        .parse()
        .map_err(|_| RpcError::InvalidParams(format!("invalid height: {height_str}")))?;

    // For now, return current block info if height matches current height
    // Full block retrieval from block_store requires &mut (Phase 8 refactor)
    let s = &state.engine.state;
    if height < state.engine.block_store.lowest_height() {
        return Err(RpcError::NotFound(format!(
            "Block {height} has been pruned. Lowest available: {}. Use an archive node for historical queries.",
            state.engine.block_store.lowest_height()
        )));
    }

    if height > s.height {
        return Err(RpcError::NotFound(format!("block {height} not yet produced")));
    }

    // Return summary info available from chain state
    let tip = hex::encode(s.tip_hash.0);
    Ok(format!(
        r#"{{"height":{height},"tip_hash":"{tip}","base_fee":{base_fee},"note":"full block retrieval added in Phase 8"}}"#,
        height   = height,
        tip      = tip,
        base_fee = s.base_fee,
    ))
}

/// `indra_getValidator` — returns validator info by ID (hex string).
///
/// Params: `["<validator_id_hex>"]`
/// Result: `{"validator_id", "stake", "status", "epoch_joined"}`
fn get_validator(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let id_str = params.first()
        .ok_or_else(|| RpcError::InvalidParams("missing validator_id parameter".to_string()))?;

    let id_hex = unquote(id_str);
    let id_bytes = hex::decode(id_hex)
        .map_err(|_| RpcError::InvalidParams(format!("invalid hex: {id_hex}")))?;

    if id_bytes.len() != 32 {
        return Err(RpcError::InvalidParams("validator_id must be 32 bytes (64 hex chars)".to_string()));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&id_bytes);
    let id = indra_core::types::primitives::Bytes32::from(arr);

    let validator = state.engine.state.validators
        .get(&id)
        .ok_or_else(|| RpcError::NotFound(format!("validator {id_hex} not found")))?;

    let status = match validator.status {
        indra_state::ValidatorStatus::Registered => "registered",
        indra_state::ValidatorStatus::Active => "active",
        indra_state::ValidatorStatus::Unbonding { .. } => "unbonding",
        indra_state::ValidatorStatus::Slashed => "slashed",
        indra_state::ValidatorStatus::Exited => "exited",
    };

    Ok(format!(
        r#"{{"validator_id":"{id}","name":"{name}","stake":{stake},"status":"{status}","epoch_joined":{epoch}}}"#,
        id     = id_hex,
        name   = validator.name,
        stake  = validator.stake_spark,
        status = status,
        epoch  = validator.registered_epoch,
    ))
}

/// `indra_getValidatorSet` — returns all active validators.
///
/// Result: `{"validators": [{"validator_id", "stake"}, ...]}`
// v2 — includes name field
fn get_validator_set(state: &NodeState<'_>) -> RpcResult<String> {
    let mut entries = Vec::new();
    for v in state.engine.state.validators.active_validators() {
        let id_hex = hex::encode(v.validator_id.0);
        entries.push(format!(
            r#"{{"validator_id":"{}","name":"{}","stake":{}}}"#,
            id_hex, v.name, v.stake_spark
        ));
    }
    Ok(format!(r#"{{"validators":[{}]}}"#, entries.join(",")))
}

/// `indra_sendTransaction` — submit a hex-encoded signed transaction.
///
/// Params: `["<tx_hex>"]`
/// Result: `{"tx_id": "<hex>", "status": "accepted"}`
fn send_transaction(params: &[String], _state: &NodeState<'_>) -> RpcResult<String> {
    let tx_hex = params.first()
        .ok_or_else(|| RpcError::InvalidParams("missing transaction parameter".to_string()))?;

    let tx_bytes = hex::decode(unquote(tx_hex))
        .map_err(|_| RpcError::InvalidParams("invalid hex encoding".to_string()))?;

    use indra_core::codec::{Decode, ByteReader};
    use indra_core::types::transaction::TransactionV1;

    let mut reader = ByteReader::new(&tx_bytes);
    let tx = TransactionV1::decode(&mut reader)
        .map_err(|e| RpcError::InvalidParams(format!("transaction decode failed: {e}")))?;

    // Compute tx_id
    use indra_consensus::mempool::Mempool;
    let tx_id = Mempool::tx_id(&tx);
    let tx_id_hex = hex::encode(tx_id.0);

    // Note: actual submission requires &mut engine — the server handles this
    // by returning the tx_id for the caller to track
    // Full mutable submission is wired in the RpcServer::handle_request path

    Ok(format!(
        r#"{{"tx_id":"{}","status":"decoded_ok","note":"submit via RpcServer for full validation"}}"#,
        tx_id_hex
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_node::{NodeConfig, NodeEngine};
    use std::path::PathBuf;

    fn temp_dir(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_rpc_handler_test_{}_{}", suffix, std::process::id()));
        p
    }

    fn make_state(suffix: &str) -> NodeEngine {
        let dir = temp_dir(suffix);
        let config = NodeConfig::local_test(dir);
        NodeEngine::init(config).unwrap()
    }

    #[test]
    fn get_height_returns_zero_at_genesis() {
        let engine = make_state("h");
        let state = NodeState { engine: &engine };
        let result = get_height(&state).unwrap();
        assert!(result.contains("\"height\":0"));
        let _ = std::fs::remove_dir_all(temp_dir("h"));
    }

    #[test]
    fn get_chain_info_has_all_fields() {
        let engine = make_state("ci");
        let state = NodeState { engine: &engine };
        let result = get_chain_info(&state).unwrap();
        assert!(result.contains("\"height\""));
        assert!(result.contains("\"base_fee\""));
        assert!(result.contains("\"total_supply\""));
        assert!(result.contains("\"epoch\""));
        assert!(result.contains("\"pruned_mode\""));
        assert!(result.contains("\"lowest_block\""));
        let _ = std::fs::remove_dir_all(temp_dir("ci"));
    }

    #[test]
    fn get_mempool_size_returns_zero() {
        let engine = make_state("mp");
        let state = NodeState { engine: &engine };
        let result = get_mempool_size(&state).unwrap();
        assert!(result.contains("\"size\":0"));
        let _ = std::fs::remove_dir_all(temp_dir("mp"));
    }

    #[test]
    fn method_not_found_errors() {
        let engine = make_state("mf");
        let state = NodeState { engine: &engine };
        let result = dispatch("indra_nonExistent", &[], &state);
        assert!(matches!(result, Err(RpcError::MethodNotFound(_))));
        let _ = std::fs::remove_dir_all(temp_dir("mf"));
    }

    #[test]
    fn get_block_beyond_tip_errors() {
        let engine = make_state("gb");
        let state = NodeState { engine: &engine };
        let result = get_block(&["999".to_string()], &state);
        assert!(matches!(result, Err(RpcError::NotFound(_))));
        let _ = std::fs::remove_dir_all(temp_dir("gb"));
    }

    #[test]
    fn get_validator_invalid_hex_errors() {
        let engine = make_state("gv");
        let state = NodeState { engine: &engine };
        let result = get_validator(&["not_hex".to_string()], &state);
        assert!(matches!(result, Err(RpcError::InvalidParams(_))));
        let _ = std::fs::remove_dir_all(temp_dir("gv"));
    }
}
