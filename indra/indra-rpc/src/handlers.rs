//! RPC method handlers.
//!
//! Each handler receives the parsed request params and a reference to
//! the node state, and returns a JSON string result or an RpcError.

use indra_core::{
    types::primitives::{SCHEMA_VERSION, SCHEMA_VERSION_GENESIS},
    types::{
        epoch_record::EpochRecord, governance::GovernanceOpV2, staking::StakingOp,
        transaction::TransactionV1,
    },
    Bytes32,
};
use indra_state::ChainState;

use crate::{
    error::{RpcError, RpcResult},
    types::unquote,
};

/// Shared node state passed to all handlers.
pub struct NodeState<'a> {
    /// Read-only engine view.
    pub engine: &'a dyn RpcEngineView,
    /// The chain state.
    pub chain: &'a ChainState,
    /// Current transaction mempool size.
    pub mempool_size: usize,
    /// Whether this node is running in pruned mode.
    pub pruned_mode: bool,
    /// Lowest locally retained block height.
    pub lowest_block: u64,
    /// Number of locally retained blocks.
    pub blocks_retained: usize,
    /// Optional network context for validator-node-only peer methods.
    pub network: Option<NetworkContext<'a>>,
}

/// Network-layer context needed by peer-aware RPC methods.
pub struct NetworkContext<'a> {
    /// Dialable connected validator peer addresses.
    pub validator_peer_addrs: Vec<String>,
    /// Number of currently authenticated validator peer connections.
    pub connected_validator_peer_count: usize,
    /// Number of discovered peers not necessarily connected.
    pub discovered_peer_count: usize,
    /// Number of currently connected observer peers.
    pub observer_peer_count: usize,
    /// Marker tying this context to the borrowed node state lifetime.
    pub _lifetime: std::marker::PhantomData<&'a ()>,
}

/// Read-only schema migration audit record for RPC output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationRecordView {
    /// Unix timestamp in seconds when the migration ran.
    pub timestamp_secs: u64,
    /// Schema version migrated from.
    pub from_version: u8,
    /// Schema version migrated to.
    pub to_version: u8,
    /// State height at migration time.
    pub state_height: u64,
    /// Number of validators migrated.
    pub validators_migrated: u32,
    /// Number of UTXOs migrated.
    pub utxos_migrated: u32,
}

impl<'a> NodeState<'a> {
    /// Construct a state object with network context.
    pub fn with_network(
        engine: &'a impl RpcEngineView,
        validator_peer_addrs: Vec<String>,
        connected_validator_peer_count: usize,
        discovered_peer_count: usize,
        observer_peer_count: usize,
    ) -> Self {
        Self {
            engine,
            chain: engine.chain_state(),
            mempool_size: engine.mempool_size(),
            pruned_mode: engine.pruned_mode(),
            lowest_block: engine.lowest_block(),
            blocks_retained: engine.blocks_retained(),
            network: Some(NetworkContext {
                validator_peer_addrs,
                connected_validator_peer_count,
                discovered_peer_count,
                observer_peer_count,
                _lifetime: std::marker::PhantomData,
            }),
        }
    }

    /// Construct a read-only state object without network context.
    pub fn read_only(engine: &'a impl RpcEngineView) -> Self {
        Self {
            engine,
            chain: engine.chain_state(),
            mempool_size: engine.mempool_size(),
            pruned_mode: engine.pruned_mode(),
            lowest_block: engine.lowest_block(),
            blocks_retained: engine.blocks_retained(),
            network: None,
        }
    }

    /// Construct directly from chain state and metadata.
    pub fn from_parts(
        chain: &'a ChainState,
        mempool_size: usize,
        pruned_mode: bool,
        lowest_block: u64,
        blocks_retained: usize,
    ) -> Self {
        Self {
            engine: chain,
            chain,
            mempool_size,
            pruned_mode,
            lowest_block,
            blocks_retained,
            network: None,
        }
    }
}

/// Read-only engine view required by RPC handlers.
pub trait RpcEngineView {
    /// Return the current chain state.
    fn chain_state(&self) -> &ChainState;
    /// Return the transaction mempool size.
    fn mempool_size(&self) -> usize;
    /// Return whether the block store is pruned.
    fn pruned_mode(&self) -> bool;
    /// Return the lowest locally retained block height.
    fn lowest_block(&self) -> u64;
    /// Return the number of locally retained blocks.
    fn blocks_retained(&self) -> usize;
    /// Return a stored epoch record, if available.
    fn get_epoch_record(&self, _epoch: u64) -> Result<Option<EpochRecord>, String> {
        Ok(None)
    }
    /// Return the latest stored epoch number, if any.
    fn latest_epoch(&self) -> Result<Option<u64>, String> {
        Ok(None)
    }
    /// Return epoch records ending at `to_epoch`, most recent first.
    fn get_epoch_range(&self, _to_epoch: u64, _limit: usize) -> Result<Vec<EpochRecord>, String> {
        Ok(Vec::new())
    }
    /// Return schema migration audit history.
    fn migration_history(&self) -> Result<Vec<MigrationRecordView>, String> {
        Ok(Vec::new())
    }
}

/// Mutable engine hooks required by RPC submission paths.
pub trait RpcEngineMut: RpcEngineView {
    /// Submit a staking operation to the local staking mempool.
    fn rpc_add_staking_op(&mut self, op: StakingOp) -> Result<(), String>;
    /// Submit a governance operation to the local governance mempool.
    fn rpc_add_governance_op(&mut self, op: GovernanceOpV2) -> Result<(), String>;
    /// Submit a transaction to the local mempool and return its transaction id.
    fn rpc_submit_transaction(&mut self, tx: TransactionV1) -> Result<Bytes32, String>;
}

impl RpcEngineView for ChainState {
    fn chain_state(&self) -> &ChainState {
        self
    }

    fn mempool_size(&self) -> usize {
        0
    }

    fn pruned_mode(&self) -> bool {
        false
    }

    fn lowest_block(&self) -> u64 {
        0
    }

    fn blocks_retained(&self) -> usize {
        0
    }
}

impl RpcEngineMut for ChainState {
    fn rpc_add_staking_op(&mut self, _op: StakingOp) -> Result<(), String> {
        Err("mutation not available in ChainState-only RPC context".to_string())
    }

    fn rpc_add_governance_op(&mut self, _op: GovernanceOpV2) -> Result<(), String> {
        Err("mutation not available in ChainState-only RPC context".to_string())
    }

    fn rpc_submit_transaction(&mut self, _tx: TransactionV1) -> Result<Bytes32, String> {
        Err("mutation not available in ChainState-only RPC context".to_string())
    }
}

/// Result of dispatching an RPC method.
pub enum DispatchResult {
    /// A complete result string, or a handler error.
    Ready(RpcResult<String>),
    /// Caller must submit this decoded staking operation with mutable engine access.
    SubmitStakingOp(Vec<u8>),
    /// Caller must submit this decoded governance operation with mutable engine access.
    SubmitGovernanceOp(Vec<u8>),
    /// Caller must submit this decoded transaction with mutable engine access.
    SubmitTransaction(Vec<u8>),
}

/// RPC listener capability mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcMode {
    /// Full local listener: read methods and submission methods are available.
    Full,
    /// Public listener: only explicit read-only methods are available.
    ReadOnly,
}

/// Access class for an RPC method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcMethodAccess {
    /// The method only reads local node/chain state and is safe for public exposure.
    ReadOnly,
    /// The method submits data to a local mempool or otherwise requests mutation.
    Write,
}

/// All RPC methods currently dispatched by this crate, with their access class.
///
/// This is an explicit allowlist for read-only public listeners. New methods must
/// be classified here before they can be dispatched.
pub const RPC_METHODS: &[(&str, RpcMethodAccess)] = &[
    ("indra_getHeight", RpcMethodAccess::ReadOnly),
    ("indra_getTip", RpcMethodAccess::ReadOnly),
    ("indra_getChainInfo", RpcMethodAccess::ReadOnly),
    ("indra_getMempoolSize", RpcMethodAccess::ReadOnly),
    ("indra_getBlock", RpcMethodAccess::ReadOnly),
    ("indra_getBalance", RpcMethodAccess::ReadOnly),
    ("indra_getUtxos", RpcMethodAccess::ReadOnly),
    ("indra_getUtxoProof", RpcMethodAccess::ReadOnly),
    ("indra_getPeers", RpcMethodAccess::ReadOnly),
    ("indra_getStakingNonce", RpcMethodAccess::ReadOnly),
    ("indra_getDelegations", RpcMethodAccess::ReadOnly),
    ("indra_getDelegatorPositions", RpcMethodAccess::ReadOnly),
    ("indra_getDelegatorRewards", RpcMethodAccess::ReadOnly),
    ("indra_getValidatorDelegators", RpcMethodAccess::ReadOnly),
    ("indra_getStakeBonds", RpcMethodAccess::ReadOnly),
    ("indra_getEpochInfo", RpcMethodAccess::ReadOnly),
    ("indra_getEpochRecord", RpcMethodAccess::ReadOnly),
    ("indra_getEpochHistory", RpcMethodAccess::ReadOnly),
    ("indra_getLatestEpoch", RpcMethodAccess::ReadOnly),
    ("indra_getSchemaInfo", RpcMethodAccess::ReadOnly),
    ("indra_getProposals", RpcMethodAccess::ReadOnly),
    ("indra_getProposal", RpcMethodAccess::ReadOnly),
    ("indra_getProposalVotes", RpcMethodAccess::ReadOnly),
    ("indra_getGovernanceParams", RpcMethodAccess::ReadOnly),
    ("indra_getGovernanceNonce", RpcMethodAccess::ReadOnly),
    ("indra_getValidatorRewards", RpcMethodAccess::ReadOnly),
    ("indra_getValidator", RpcMethodAccess::ReadOnly),
    ("indra_getValidatorSelfStake", RpcMethodAccess::ReadOnly),
    ("indra_getValidatorAutoDelegate", RpcMethodAccess::ReadOnly),
    ("indra_getValidatorSet", RpcMethodAccess::ReadOnly),
    ("indra_submitStakingOp", RpcMethodAccess::Write),
    ("indra_submitGovernanceOp", RpcMethodAccess::Write),
    ("indra_sendTransaction", RpcMethodAccess::Write),
];

/// Return the configured access class for a known RPC method.
pub fn rpc_method_access(method: &str) -> Option<RpcMethodAccess> {
    RPC_METHODS
        .iter()
        .find_map(|(candidate, access)| (*candidate == method).then_some(*access))
}

/// Return true if a method is explicitly allowlisted for read-only listeners.
pub fn rpc_method_is_read_only(method: &str) -> bool {
    rpc_method_access(method) == Some(RpcMethodAccess::ReadOnly)
}

/// Check whether a method is allowed on a listener with the given mode.
pub fn check_rpc_method_allowed(method: &str, mode: RpcMode) -> RpcResult<()> {
    if mode == RpcMode::ReadOnly && rpc_method_access(method) != Some(RpcMethodAccess::ReadOnly) {
        return Err(RpcError::Forbidden(format!(
            "RPC method {method} is not available on read-only listener"
        )));
    }
    Ok(())
}

/// Dispatch a method call to the appropriate handler.
pub fn dispatch(method: &str, params: &[String], state: &NodeState<'_>) -> DispatchResult {
    dispatch_with_mode(method, params, state, RpcMode::Full)
}

/// Dispatch a method call with listener-mode enforcement.
pub fn dispatch_with_mode(
    method: &str,
    params: &[String],
    state: &NodeState<'_>,
    mode: RpcMode,
) -> DispatchResult {
    use DispatchResult::Ready;
    if let Err(error) = check_rpc_method_allowed(method, mode) {
        return Ready(Err(error));
    }
    match method {
        "indra_getHeight" => Ready(get_height(state)),
        "indra_getTip" => Ready(get_tip(state)),
        "indra_getChainInfo" => Ready(get_chain_info(state)),
        "indra_getMempoolSize" => Ready(get_mempool_size(state)),
        "indra_getBlock" => Ready(get_block(params, state)),
        "indra_getBalance" => Ready(get_balance(params, state)),
        "indra_getUtxos" => Ready(get_utxos(params, state)),
        "indra_getUtxoProof" => Ready(get_utxo_proof(params, state)),
        "indra_getPeers" => Ready(get_peers(state)),
        "indra_getStakingNonce" => Ready(get_staking_nonce(params, state)),
        "indra_getDelegations" => Ready(get_delegations(params, state)),
        "indra_getDelegatorPositions" => Ready(get_delegator_positions(params, state)),
        "indra_getDelegatorRewards" => Ready(get_delegator_rewards(params, state)),
        "indra_getValidatorDelegators" => Ready(get_validator_delegators(params, state)),
        "indra_getStakeBonds" => Ready(get_stake_bonds(params, state)),
        "indra_getEpochInfo" => Ready(get_epoch_info(state)),
        "indra_getEpochRecord" => Ready(get_epoch_record(params, state)),
        "indra_getEpochHistory" => Ready(get_epoch_history(params, state)),
        "indra_getLatestEpoch" => Ready(get_latest_epoch(state)),
        "indra_getSchemaInfo" => Ready(get_schema_info(state)),
        "indra_getProposals" => Ready(get_proposals(params, state)),
        "indra_getProposal" => Ready(get_proposal(params, state)),
        "indra_getProposalVotes" => Ready(get_proposal_votes(params, state)),
        "indra_getGovernanceParams" => Ready(get_governance_params(state)),
        "indra_getGovernanceNonce" => Ready(get_governance_nonce(params, state)),
        "indra_getValidatorRewards" => Ready(get_validator_rewards(params, state)),
        "indra_submitStakingOp" => submit_staking_op(params),
        "indra_submitGovernanceOp" => submit_governance_op(params),
        "indra_getValidator" => Ready(get_validator(params, state)),
        "indra_getValidatorSelfStake" => Ready(get_validator_self_stake(params, state)),
        "indra_getValidatorAutoDelegate" => Ready(get_validator_auto_delegate(params, state)),
        "indra_getValidatorSet" => Ready(get_validator_set(state)),
        "indra_sendTransaction" => send_transaction(params),
        _ => Ready(Err(RpcError::MethodNotFound(method.to_string()))),
    }
}

fn parse_hex32_param(params: &[String], name: &str) -> RpcResult<indra_core::Bytes32> {
    let raw = params
        .first()
        .ok_or_else(|| RpcError::InvalidParams(format!("missing {name} parameter")))?;
    let hex_value = unquote(raw);
    let bytes = hex::decode(hex_value)
        .map_err(|_| RpcError::InvalidParams(format!("invalid hex: {hex_value}")))?;
    if bytes.len() != 32 {
        return Err(RpcError::InvalidParams(format!(
            "{name} must be 32 bytes (64 hex chars)"
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(indra_core::Bytes32::from(arr))
}

fn first_param(params: &[String], name: &str) -> RpcResult<String> {
    params
        .first()
        .map(|param| unquote(param).to_string())
        .ok_or_else(|| RpcError::InvalidParams(format!("missing {name} parameter")))
}

fn parse_hex32_value(hex_value: &str, name: &str) -> RpcResult<indra_core::Bytes32> {
    let bytes = hex::decode(hex_value)
        .map_err(|_| RpcError::InvalidParams(format!("invalid {name} hex")))?;
    if bytes.len() != 32 {
        return Err(RpcError::InvalidParams(format!("invalid {name} hex")));
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&bytes);
    Ok(indra_core::Bytes32::from(raw))
}

/// `indra_getHeight` — returns the current chain height.
///
/// Result: `{"height": <u64>}`
fn get_height(state: &NodeState<'_>) -> RpcResult<String> {
    Ok(format!(r#"{{"height":{}}}"#, state.chain.height))
}

/// `indra_getTip` — returns the current tip hash and height.
///
/// Result: `{"height": <u64>, "tip_hash": "<hex>"}`
fn get_tip(state: &NodeState<'_>) -> RpcResult<String> {
    let tip = hex::encode(state.chain.tip_hash.0);
    Ok(format!(
        r#"{{"height":{},"tip_hash":"{}"}}"#,
        state.chain.height, tip
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
    let s = &state.chain;
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
    let mempool_size = state.mempool_size;
    let epoch = s.current_epoch();
    let block_reward_spark = indra_state::epoch::block_reward_at_height(s.height);
    let era = era_for_height(s.height);
    let pruned_mode = state.pruned_mode;
    let lowest_block = state.lowest_block;
    let blocks_retained = state.blocks_retained;
    let peers = state
        .network
        .as_ref()
        .map(|network| network.connected_validator_peer_count)
        .unwrap_or(0);

    Ok(format!(
        r#"{{"height":{height},"tip_hash":"{tip}","base_fee":{base_fee},"total_supply":{total_supply},"treasury_balance":{treasury},"burn_buffer":{burn},"fee_reward_pool":{fee_reward_pool},"active_validators":{validators},"max_active_validators":{max_active_validators},"total_staked_spark":{total_staked_spark},"effective_min_stake_spark":{effective_min_stake_spark},"validator_set_phase":{validator_set_phase},"mempool_size":{mempool},"epoch":{epoch},"pruned_mode":{pruned_mode},"lowest_block":{lowest_block},"blocks_retained":{blocks_retained},"block_reward_spark":{block_reward_spark},"era":{era},"peers":{peers},"chain_id":"{chain_id}"}}"#,
        height = s.height,
        tip = tip,
        base_fee = s.base_fee,
        total_supply = s.total_supply,
        treasury = s.treasury_balance,
        burn = s.burn_buffer,
        fee_reward_pool = s.fee_reward_pool,
        validators = active_validators,
        max_active_validators = max_active_validators,
        total_staked_spark = total_staked_spark,
        effective_min_stake_spark = effective_min_stake_spark,
        validator_set_phase = validator_set_phase,
        mempool = mempool_size,
        epoch = epoch,
        pruned_mode = if pruned_mode { "true" } else { "false" },
        lowest_block = lowest_block,
        blocks_retained = blocks_retained,
        block_reward_spark = block_reward_spark,
        era = era,
        peers = peers,
        chain_id = s.chain_id,
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
    Ok(format!(r#"{{"size":{}}}"#, state.mempool_size))
}

/// `indra_getBlock` — returns a block by height.
///
/// Params: `[<height: number>]`
/// Result: `{"height", "prev_hash", "state_root", "base_fee",
///           "tx_count", "timestamp"}`
fn get_block(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let height_str = params
        .first()
        .ok_or_else(|| RpcError::InvalidParams("missing height parameter".to_string()))?;

    let height: u64 = unquote(height_str)
        .parse()
        .map_err(|_| RpcError::InvalidParams(format!("invalid height: {height_str}")))?;

    // For now, return current block info if height matches current height
    // Full block retrieval from block_store requires &mut (Phase 8 refactor)
    let s = &state.chain;
    if height < state.lowest_block {
        return Err(RpcError::NotFound(format!(
            "Block {height} has been pruned. Lowest available: {}. Use an archive node for historical queries.",
            state.lowest_block
        )));
    }

    if height > s.height {
        return Err(RpcError::NotFound(format!(
            "block {height} not yet produced"
        )));
    }

    // Return summary info available from chain state
    let tip = hex::encode(s.tip_hash.0);
    Ok(format!(
        r#"{{"height":{height},"tip_hash":"{tip}","base_fee":{base_fee},"note":"full block retrieval added in Phase 8"}}"#,
        height = height,
        tip = tip,
        base_fee = s.base_fee,
    ))
}

/// `indra_getBalance` — returns total UTXO balance for an address.
fn get_balance(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let address_hex = first_param(params, "address")?;
    let address = parse_address_hex(&address_hex)?;
    let mut balance = 0u64;
    for entry in state.chain.utxos.all_entries() {
        let owner_address = indra_crypto::sha256(&entry.output.owner_pubkey.classical_pk.0);
        if owner_address == address {
            balance = balance.saturating_add(entry.output.value_spark);
        }
    }
    Ok(format!(
        r#"{{"address":"{}","balance":{},"privacy_note":"{}"}}"#,
        address_hex, balance, UTXO_PRIVACY_NOTE
    ))
}

/// `indra_getUtxos` — returns UTXOs for an address.
fn get_utxos(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let address_hex = first_param(params, "address")?;
    let address = parse_address_hex(&address_hex)?;
    let utxos: Vec<String> = state
        .chain
        .utxos
        .all_entries()
        .filter(|entry| {
            indra_crypto::sha256(&entry.output.owner_pubkey.classical_pk.0) == address
        })
        .map(|entry| {
            format!(
                r#"{{"utxo_id":"{}","amount":{},"created_height":{},"tx_index":{},"out_index":{},"lock_height":{}}}"#,
                hex::encode(entry.utxo_id.0),
                entry.output.value_spark,
                entry.created_height,
                entry.tx_index,
                entry.output_index,
                entry.output.lock_height,
            )
        })
        .collect();
    Ok(format!(
        r#"{{"address":"{}","utxos":[{}],"privacy_note":"{}"}}"#,
        address_hex,
        utxos.join(","),
        UTXO_PRIVACY_NOTE
    ))
}

const UTXO_PRIVACY_NOTE: &str =
    "queries are public; UTXO amounts reflect public value_spark metadata, not committed values";

fn parse_address_hex(address_hex: &str) -> RpcResult<[u8; 32]> {
    if address_hex.len() != 64 {
        return Err(RpcError::InvalidParams(
            "invalid address: expected 32-byte hex".into(),
        ));
    }
    let bytes = hex::decode(address_hex)
        .map_err(|_| RpcError::InvalidParams("invalid address: expected 32-byte hex".into()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// `indra_getPeers` — returns public aggregate peer counts.
fn get_peers(state: &NodeState<'_>) -> RpcResult<String> {
    match &state.network {
        None => Ok(
            r#"{"peer_count":0,"target_peers":0,"discovered_count":0,"observer_peer_count":0}"#
                .to_string(),
        ),
        Some(network) => Ok(format!(
            r#"{{"peer_count":{},"target_peers":{},"discovered_count":{},"observer_peer_count":{}}}"#,
            network.connected_validator_peer_count,
            indra_core::types::primitives::TARGET_OUTBOUND_PEERS,
            network.discovered_peer_count,
            network.observer_peer_count,
        )),
    }
}

/// `indra_getStakingNonce` — returns current staking nonce for a signer.
fn get_staking_nonce(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let signer_id = parse_hex32_param(params, "signer_id")?;
    let nonce = state
        .chain
        .staking_nonces
        .get(&signer_id)
        .copied()
        .unwrap_or(0);
    Ok(format!(
        r#"{{"signer_id":"{}","nonce":{},"current_nonce":{},"next_nonce":{}}}"#,
        hex::encode(signer_id.0),
        nonce,
        nonce,
        nonce.saturating_add(1)
    ))
}

/// `indra_getGovernanceNonce` — returns current governance nonce for a signer.
fn get_governance_nonce(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let signer_id = parse_hex32_param(params, "signer_id")?;
    let nonce = state
        .chain
        .governance
        .gov_nonces
        .get(&signer_id)
        .copied()
        .unwrap_or(0);
    Ok(format!(
        r#"{{"signer_id":"{}","nonce":{},"current_nonce":{},"next_nonce":{}}}"#,
        hex::encode(signer_id.0),
        nonce,
        nonce,
        nonce.saturating_add(1)
    ))
}

fn submit_staking_op(params: &[String]) -> DispatchResult {
    let op_hex = match first_param(params, "staking op hex") {
        Ok(hex) => hex,
        Err(err) => return DispatchResult::Ready(Err(err)),
    };
    if op_hex.is_empty() {
        return DispatchResult::Ready(Err(RpcError::InvalidParams(
            "missing staking op hex param".to_string(),
        )));
    }
    match hex::decode(&op_hex) {
        Ok(bytes) => DispatchResult::SubmitStakingOp(bytes),
        Err(_) => DispatchResult::Ready(Err(RpcError::InvalidParams(
            "invalid hex encoding".to_string(),
        ))),
    }
}

fn submit_governance_op(params: &[String]) -> DispatchResult {
    let op_hex = match first_param(params, "governance op hex") {
        Ok(hex) => hex,
        Err(err) => return DispatchResult::Ready(Err(err)),
    };
    if op_hex.is_empty() {
        return DispatchResult::Ready(Err(RpcError::InvalidParams(
            "missing governance op hex param".to_string(),
        )));
    }
    match hex::decode(&op_hex) {
        Ok(bytes) => DispatchResult::SubmitGovernanceOp(bytes),
        Err(_) => DispatchResult::Ready(Err(RpcError::InvalidParams(
            "invalid hex encoding".to_string(),
        ))),
    }
}

/// `indra_getValidator` — returns validator info by ID (hex string).
///
/// Params: `["<validator_id_hex>"]`
/// Result: `{"validator_id", "stake", "status", "epoch_joined"}`
fn get_validator(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let id_str = params
        .first()
        .ok_or_else(|| RpcError::InvalidParams("missing validator_id parameter".to_string()))?;

    let id_hex = unquote(id_str);
    let id_bytes = hex::decode(id_hex)
        .map_err(|_| RpcError::InvalidParams(format!("invalid hex: {id_hex}")))?;

    if id_bytes.len() != 32 {
        return Err(RpcError::InvalidParams(
            "validator_id must be 32 bytes (64 hex chars)".to_string(),
        ));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&id_bytes);
    let id = indra_core::types::primitives::Bytes32::from(arr);

    let Some(validator) = state.chain.validators.get(&id) else {
        return Ok("null".to_string());
    };

    let status = match validator.status {
        indra_state::ValidatorStatus::Registered => "registered",
        indra_state::ValidatorStatus::Active => "active",
        indra_state::ValidatorStatus::Unbonding { .. } => "unbonding",
        indra_state::ValidatorStatus::Slashed => "slashed",
        indra_state::ValidatorStatus::Exited => "exited",
    };

    Ok(format!(
        r#"{{"validator_id":"{id}","name":"{name}","stake":{stake},"status":"{status}","epoch_joined":{epoch},"hybrid_classical_pk":"{classical_pk}","hybrid_pq_pk":"{pq_pk}"}}"#,
        id = id_hex,
        name = validator.name,
        stake = validator.stake_spark,
        status = status,
        epoch = validator.registered_epoch,
        classical_pk = validator
            .hybrid_classical_pk
            .map(hex::encode)
            .unwrap_or_default(),
        pq_pk = validator
            .hybrid_pq_pk
            .as_ref()
            .map(hex::encode)
            .unwrap_or_default(),
    ))
}

/// `indra_getValidatorSelfStake` — returns active self-stake bonds for a validator.
///
/// Params: `["<validator_id_hex>"]`
/// Result: `{"validator_id", "total_spark", "bonds"}`
fn get_validator_self_stake(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let id_str = params
        .first()
        .ok_or_else(|| RpcError::InvalidParams("missing validator_id parameter".to_string()))?;
    let id_hex = unquote(id_str);
    let id_bytes = hex::decode(id_hex)
        .map_err(|_| RpcError::InvalidParams(format!("invalid hex: {id_hex}")))?;
    if id_bytes.len() != 32 {
        return Err(RpcError::InvalidParams(
            "validator_id must be 32 bytes (64 hex chars)".to_string(),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&id_bytes);
    let validator_id = indra_core::types::primitives::Bytes32::from(arr);

    let mut total_spark = 0u64;
    let bonds: Vec<String> = state
        .chain
        .staked_bonds
        .values()
        .filter(|bond| {
            bond.validator_id == validator_id
                && bond.delegator_id == validator_id
                && bond.unbonding_end_epoch.is_none()
        })
        .map(|bond| {
            total_spark = total_spark.saturating_add(bond.amount_spark);
            format!(
                r#"{{"bond_utxo_id":"{}","amount_spark":{},"bonded_epoch":{}}}"#,
                hex::encode(bond.utxo_id.0),
                bond.amount_spark,
                bond.bonded_epoch,
            )
        })
        .collect();
    Ok(format!(
        r#"{{"validator_id":"{}","total_spark":{},"bonds":[{}]}}"#,
        id_hex,
        total_spark,
        bonds.join(",")
    ))
}

/// `indra_getValidatorAutoDelegate` — returns auto-delegation target for a validator.
///
/// Params: `["<validator_id_hex>"]`
/// Result: `{"validator_id", "auto_delegate_to", "target_name"}`
fn get_validator_auto_delegate(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let validator_id = parse_hex32_param(params, "validator_id")?;
    let validator = state.chain.validators.get(&validator_id).ok_or_else(|| {
        RpcError::NotFound(format!(
            "validator {} not found",
            hex::encode(validator_id.0)
        ))
    })?;

    let (target_hex, target_name) = match validator.auto_delegate_to {
        Some(target_id) => {
            let name = state
                .chain
                .validators
                .get(&target_id)
                .map(|target| format!(r#""{}""#, target.name))
                .unwrap_or_else(|| "null".to_string());
            (format!(r#""{}""#, hex::encode(target_id.0)), name)
        }
        None => ("null".to_string(), "null".to_string()),
    };

    Ok(format!(
        r#"{{"validator_id":"{}","auto_delegate_to":{},"target_name":{}}}"#,
        hex::encode(validator_id.0),
        target_hex,
        target_name,
    ))
}

/// `indra_getDelegations` — returns delegator entries for a validator.
fn get_delegations(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let validator_id = parse_hex32_param(params, "validator_id")?;
    let entries: Vec<String> = state
        .chain
        .delegations
        .get_delegators(&validator_id)
        .iter()
        .map(|entry| {
            format!(
                r#"{{"delegator_id":"{}","staked_spark":{},"pending_rewards":{},"unbonding":{},"unbonding_end_epoch":{}}}"#,
                hex::encode(entry.delegator_id.0),
                entry.staked_spark,
                entry.pending_rewards,
                if entry.unbonding_end_epoch.is_some() { "true" } else { "false" },
                entry.unbonding_end_epoch.unwrap_or(0),
            )
        })
        .collect();
    let bonds: Vec<String> = state
            .chain
        .staked_bonds
        .values()
        .filter(|bond| bond.validator_id == validator_id && bond.unbonding_end_epoch.is_none())
        .map(|bond| {
            format!(
                r#"{{"bond_utxo_id":"{}","delegator_id":"{}","amount_spark":{},"bonded_epoch":{}}}"#,
                hex::encode(bond.utxo_id.0),
                hex::encode(bond.delegator_id.0),
                bond.amount_spark,
                bond.bonded_epoch,
            )
        })
        .collect();
    Ok(format!(
        r#"{{"validator_id":"{}","delegations":[{}],"delegators":[{}],"bonds":[{}]}}"#,
        hex::encode(validator_id.0),
        entries.join(","),
        entries.join(","),
        bonds.join(",")
    ))
}

/// `indra_getDelegatorPositions` — returns all delegation positions for a delegator.
fn get_delegator_positions(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let delegator_hex = first_param(params, "delegator_id")?;
    let delegator_id = parse_hex32_value(&delegator_hex, "delegator_id")?;

    let mut positions = Vec::new();
    let mut total_staked = 0u64;
    let mut total_rewards = 0u64;
    let mut active_positions = 0u64;
    let mut unbonding_positions = 0u64;

    for (validator_id, entries) in state.chain.delegations.all_delegators() {
        for entry in entries {
            if entry.delegator_id != delegator_id {
                continue;
            }

            let (validator_name, commission_bps) = state
                .chain
                .validators
                .get(validator_id)
                .map(|validator| (validator.name.clone(), validator.commission_bps))
                .unwrap_or_else(|| ("unknown".to_string(), 1_000));
            let unbonding = entry.unbonding_end_epoch.is_some();
            let unbonding_end = entry
                .unbonding_end_epoch
                .map(|epoch| epoch.to_string())
                .unwrap_or_else(|| "null".to_string());

            total_staked = total_staked.saturating_add(entry.staked_spark);
            total_rewards = total_rewards.saturating_add(entry.pending_rewards);
            if unbonding {
                unbonding_positions = unbonding_positions.saturating_add(1);
            } else {
                active_positions = active_positions.saturating_add(1);
            }

            positions.push(format!(
                r#"{{"validator_id":"{}","validator_name":"{}","staked_spark":{},"pending_rewards":{},"rewards_last_epoch":{},"unbonding":{},"unbonding_end_epoch":{},"commission_bps":{}}}"#,
                hex::encode(validator_id.0),
                validator_name,
                entry.staked_spark,
                entry.pending_rewards,
                entry.rewards_last_epoch,
                if unbonding { "true" } else { "false" },
                unbonding_end,
                commission_bps,
            ));
        }
    }

    Ok(format!(
        r#"{{"delegator_id":"{}","positions":[{}],"total_staked_spark":{},"total_pending_rewards":{},"active_positions":{},"unbonding_positions":{}}}"#,
        delegator_hex,
        positions.join(","),
        total_staked,
        total_rewards,
        active_positions,
        unbonding_positions,
    ))
}

/// `indra_getDelegatorRewards` — returns pending rewards for a delegator.
fn get_delegator_rewards(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let delegator_hex = first_param(params, "delegator_id")?;
    let delegator_id = parse_hex32_value(&delegator_hex, "delegator_id")?;

    let mut claimable = Vec::new();
    let mut total_rewards = 0u64;

    for (validator_id, entries) in state.chain.delegations.all_delegators() {
        for entry in entries {
            if entry.delegator_id != delegator_id || entry.pending_rewards == 0 {
                continue;
            }

            let validator_name = state
                .chain
                .validators
                .get(validator_id)
                .map(|validator| validator.name.clone())
                .unwrap_or_else(|| "unknown".to_string());
            total_rewards = total_rewards.saturating_add(entry.pending_rewards);
            claimable.push(format!(
                r#"{{"validator_id":"{}","validator_name":"{}","pending_rewards":{}}}"#,
                hex::encode(validator_id.0),
                validator_name,
                entry.pending_rewards,
            ));
        }
    }

    Ok(format!(
        r#"{{"delegator_id":"{}","total_pending_rewards":{},"claimable_from":[{}]}}"#,
        delegator_hex,
        total_rewards,
        claimable.join(","),
    ))
}

/// `indra_getValidatorDelegators` — returns delegator positions for one validator.
fn get_validator_delegators(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let validator_hex = first_param(params, "validator_id")?;
    let validator_id = parse_hex32_value(&validator_hex, "validator_id")?;
    let (validator_name, _) = state
        .chain
        .validators
        .get(&validator_id)
        .map(|validator| (validator.name.clone(), validator.commission_bps))
        .unwrap_or_else(|| ("unknown".to_string(), 1_000));

    let mut total_delegated = 0u64;
    let mut total_rewards = 0u64;
    let mut delegators = Vec::new();

    for entry in state
        .chain
        .delegations
        .get_delegators(&validator_id)
        .iter()
        .take(1_000)
    {
        let unbonding = entry.unbonding_end_epoch.is_some();
        let unbonding_end = entry
            .unbonding_end_epoch
            .map(|epoch| epoch.to_string())
            .unwrap_or_else(|| "null".to_string());
        total_delegated = total_delegated.saturating_add(entry.staked_spark);
        total_rewards = total_rewards.saturating_add(entry.pending_rewards);
        delegators.push(format!(
            r#"{{"delegator_id":"{}","staked_spark":{},"pending_rewards":{},"unbonding":{},"unbonding_end_epoch":{},"rewards_last_epoch":{}}}"#,
            hex::encode(entry.delegator_id.0),
            entry.staked_spark,
            entry.pending_rewards,
            if unbonding { "true" } else { "false" },
            unbonding_end,
            entry.rewards_last_epoch,
        ));
    }

    Ok(format!(
        r#"{{"validator_id":"{}","validator_name":"{}","total_delegated_spark":{},"total_pending_rewards":{},"delegator_count":{},"delegators":[{}]}}"#,
        validator_hex,
        validator_name,
        total_delegated,
        total_rewards,
        state.chain.delegations.get_delegators(&validator_id).len(),
        delegators.join(","),
    ))
}

/// `indra_getStakeBonds` — returns active stake bonds for a delegator.
fn get_stake_bonds(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let delegator_hex = first_param(params, "delegator_id")?;
    let delegator_id = parse_hex32_value(&delegator_hex, "delegator_id")?;
    let bonds: Vec<String> = state
            .chain
        .staked_bonds
        .values()
        .filter(|bond| bond.delegator_id == delegator_id && bond.unbonding_end_epoch.is_none())
        .map(|bond| {
            format!(
                r#"{{"bond_utxo_id":"{}","validator_id":"{}","amount_spark":{},"bonded_epoch":{},"unbonding":false}}"#,
                hex::encode(bond.utxo_id.0),
                hex::encode(bond.validator_id.0),
                bond.amount_spark,
                bond.bonded_epoch,
            )
        })
        .collect();
    Ok(format!(
        r#"{{"delegator_id":"{}","bonds":[{}]}}"#,
        delegator_hex,
        bonds.join(",")
    ))
}

/// `indra_getEpochInfo` — returns current epoch details.
fn get_epoch_info(state: &NodeState<'_>) -> RpcResult<String> {
    use indra_core::types::primitives::EPOCH_DURATION_BLOCKS;
    let height = state.chain.height;
    let epoch = state.chain.current_epoch();
    let epoch_start_height = epoch.saturating_mul(EPOCH_DURATION_BLOCKS);
    let epoch_end_height = epoch_start_height
        .saturating_add(EPOCH_DURATION_BLOCKS)
        .saturating_sub(1);
    let blocks_remaining = epoch_end_height.saturating_sub(height);
    let block_reward_spark = indra_state::epoch::block_reward_at_height(height);
    let total_staked = state
        .chain
        .validators
        .total_selectable_self_stake()
        .saturating_add(state.chain.delegations.total_staked());
    let phase = indra_core::types::primitives::validator_set_phase(total_staked);
    let max_validators = indra_core::types::primitives::max_active_validators(total_staked);
    Ok(format!(
        r#"{{"epoch":{},"current_epoch":{},"epoch_start_height":{},"epoch_end_height":{},"blocks_remaining":{},"blocks_until_next_epoch":{},"next_epoch_height":{},"epoch_duration_blocks":{},"block_reward_spark":{},"validator_set_phase":{},"max_active_validators":{}}}"#,
        epoch,
        epoch,
        epoch_start_height,
        epoch_end_height,
        blocks_remaining,
        blocks_remaining,
        epoch_end_height.saturating_add(1),
        EPOCH_DURATION_BLOCKS,
        block_reward_spark,
        phase,
        max_validators,
    ))
}

fn parse_u64_param(params: &[String], index: usize, name: &str) -> RpcResult<u64> {
    let raw = params
        .get(index)
        .ok_or_else(|| RpcError::InvalidParams(format!("missing {name} parameter")))?;
    unquote(raw)
        .parse()
        .map_err(|_| RpcError::InvalidParams(format!("invalid {name}: {raw}")))
}

fn bytes32_vec_json(values: &[Bytes32]) -> String {
    let items: Vec<String> = values
        .iter()
        .map(|value| format!(r#""{}""#, hex::encode(value.0)))
        .collect();
    format!("[{}]", items.join(","))
}

fn epoch_record_json(record: &EpochRecord) -> String {
    format!(
        r#"{{"epoch":{},"start_height":{},"end_height":{},"timestamp_secs":{},"active_validators":{},"total_staked_spark":{},"block_rewards_distributed":{},"fee_rewards_distributed":{},"fees_burned":{},"total_slashed_spark":{},"slash_event_count":{},"liveness_penalty_count":{},"avg_base_fee":{},"validators_joined":{},"validators_left":{},"era":{},"block_reward_spark":{},"total_supply":{},"treasury_balance":{}}}"#,
        record.epoch,
        record.start_height,
        record.end_height,
        record.timestamp_secs,
        record.active_validators,
        record.total_staked_spark,
        record.block_rewards_distributed,
        record.fee_rewards_distributed,
        record.fees_burned,
        record.total_slashed_spark,
        record.slash_event_count,
        record.liveness_penalty_count,
        record.avg_base_fee,
        bytes32_vec_json(&record.validators_joined),
        bytes32_vec_json(&record.validators_left),
        record.era,
        record.block_reward_spark,
        record.total_supply,
        record.treasury_balance,
    )
}

fn epoch_summary_json(record: &EpochRecord) -> String {
    format!(
        r#"{{"epoch":{},"start_height":{},"end_height":{},"timestamp_secs":{},"active_validators":{},"total_staked_spark":{},"block_rewards_distributed":{},"fee_rewards_distributed":{},"fees_burned":{},"total_slashed_spark":{},"slash_event_count":{},"validators_joined":{},"validators_left":{}}}"#,
        record.epoch,
        record.start_height,
        record.end_height,
        record.timestamp_secs,
        record.active_validators,
        record.total_staked_spark,
        record.block_rewards_distributed,
        record.fee_rewards_distributed,
        record.fees_burned,
        record.total_slashed_spark,
        record.slash_event_count,
        bytes32_vec_json(&record.validators_joined),
        bytes32_vec_json(&record.validators_left),
    )
}

/// `indra_getEpochRecord` — returns the full record for a completed epoch.
fn get_epoch_record(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let epoch = parse_u64_param(params, 0, "epoch")?;
    match state
        .engine
        .get_epoch_record(epoch)
        .map_err(RpcError::Internal)?
    {
        Some(record) => Ok(epoch_record_json(&record)),
        None => Err(RpcError::NotFound(format!("epoch {epoch} not recorded"))),
    }
}

/// `indra_getEpochHistory` — returns compact epoch summaries, most recent first.
fn get_epoch_history(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let latest = state.engine.latest_epoch().map_err(RpcError::Internal)?;
    let Some(latest_epoch) = latest else {
        return Ok(
            r#"{"epochs":[],"count":0,"oldest_epoch":null,"latest_epoch":null}"#.to_string(),
        );
    };

    let (to_epoch, limit) = match params.len() {
        0 => (latest_epoch, 20usize),
        1 => {
            let limit = parse_u64_param(params, 0, "limit")?;
            (latest_epoch, limit as usize)
        }
        _ => {
            let to_epoch = parse_u64_param(params, 0, "to_epoch")?;
            let limit = parse_u64_param(params, 1, "limit")?;
            (to_epoch, limit as usize)
        }
    };
    let limit = limit.clamp(1, 100);
    let records = state
        .engine
        .get_epoch_range(to_epoch, limit)
        .map_err(RpcError::Internal)?;
    let latest_in_result = records.first().map(|record| record.epoch);
    let oldest_in_result = records.last().map(|record| record.epoch);
    let summaries: Vec<String> = records.iter().map(epoch_summary_json).collect();
    let oldest_json = oldest_in_result
        .map(|epoch| epoch.to_string())
        .unwrap_or_else(|| "null".to_string());
    let latest_json = latest_in_result
        .map(|epoch| epoch.to_string())
        .unwrap_or_else(|| "null".to_string());

    Ok(format!(
        r#"{{"epochs":[{}],"count":{},"oldest_epoch":{},"latest_epoch":{}}}"#,
        summaries.join(","),
        summaries.len(),
        oldest_json,
        latest_json,
    ))
}

/// `indra_getLatestEpoch` — returns the most recently completed epoch record.
fn get_latest_epoch(state: &NodeState<'_>) -> RpcResult<String> {
    let Some(epoch) = state.engine.latest_epoch().map_err(RpcError::Internal)? else {
        return Ok("null".to_string());
    };
    match state
        .engine
        .get_epoch_record(epoch)
        .map_err(RpcError::Internal)?
    {
        Some(record) => Ok(epoch_record_json(&record)),
        None => Ok("null".to_string()),
    }
}

/// `indra_getSchemaInfo` — returns node schema and migration audit details.
fn get_schema_info(state: &NodeState<'_>) -> RpcResult<String> {
    let history = state
        .engine
        .migration_history()
        .map_err(RpcError::Internal)?;
    let history_json = history
        .iter()
        .map(|record| {
            format!(
                "{{\"timestamp_secs\":{},\"from_version\":{},\"to_version\":{},\"state_height\":{},\"validators_migrated\":{},\"utxos_migrated\":{}}}",
                record.timestamp_secs,
                record.from_version,
                record.to_version,
                record.state_height,
                record.validators_migrated,
                record.utxos_migrated
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "{{\"schema_version\":{},\"schema_version_genesis\":{},\"node_version\":\"{}\",\"migration_history\":[{}]}}",
        SCHEMA_VERSION,
        SCHEMA_VERSION_GENESIS,
        env!("CARGO_PKG_VERSION"),
        history_json
    ))
}

fn get_governance_params(state: &NodeState<'_>) -> RpcResult<String> {
    let params = &state.chain.governance.params;
    Ok(format!(
        "{{\"slash_liveness_threshold_epochs\":{},\"min_delegation_spark\":{},\"proposal_deposit_spark\":{},\"slash_liveness_bps\":{},\"slash_double_precommit_bps\":{},\"slash_surround_vote_bps\":{},\"max_commission_bps\":{},\"governance_delay_epochs\":{},\"governance_quorum_bps\":{},\"governance_critical_quorum_bps\":{}}}",
        params.slash_liveness_threshold_epochs,
        params.min_delegation_spark,
        params.proposal_deposit_spark,
        params.slash_liveness_bps,
        params.slash_double_precommit_bps,
        params.slash_surround_vote_bps,
        params.max_commission_bps,
        params.governance_delay_epochs,
        params.governance_quorum_bps,
        params.governance_critical_quorum_bps
    ))
}

fn get_proposals(_params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let mut proposals: Vec<_> = state.chain.governance.proposals.values().collect();
    proposals.sort_by_key(|proposal| proposal.proposed_epoch);
    let summaries = proposals
        .iter()
        .map(|proposal| proposal_summary_json(proposal))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "{{\"proposals\":[{}],\"active_count\":{},\"total_count\":{}}}",
        summaries,
        state.chain.governance.active_proposal_count(),
        proposals.len()
    ))
}

fn get_proposal(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let proposal_id = parse_hex32_value(&first_param(params, "proposal_id")?, "proposal_id")?;
    let proposal = state
        .chain
        .governance
        .proposals
        .get(&proposal_id)
        .ok_or_else(|| RpcError::NotFound("proposal not found".into()))?;
    Ok(proposal_detail_json(proposal))
}

fn get_proposal_votes(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let proposal_id = parse_hex32_value(&first_param(params, "proposal_id")?, "proposal_id")?;
    let proposal = state
        .chain
        .governance
        .proposals
        .get(&proposal_id)
        .ok_or_else(|| RpcError::NotFound("proposal not found".into()))?;
    let mut validator_ids: Vec<_> = proposal
        .snapshot2
        .as_ref()
        .or(proposal.snapshot1.as_ref())
        .map(|snapshot| snapshot.weights.keys().copied().collect())
        .unwrap_or_else(Vec::new);
    validator_ids.sort_by_key(|id: &indra_core::Bytes32| id.0);
    let votes = validator_ids
        .iter()
        .map(|validator_id| {
            let weight = proposal
                .snapshot2
                .as_ref()
                .and_then(|snapshot| snapshot.weights.get(validator_id))
                .copied()
                .unwrap_or(0);
            let vote = match proposal.reveals.get(validator_id) {
                Some(reveal) if reveal.vote => "YES",
                Some(_) => "NO",
                None => "ABSTAIN",
            };
            let name = state
                .chain
                .validators
                .get(validator_id)
                .map(|validator| validator.name.as_str())
                .unwrap_or("unknown");
            format!(
                "{{\"validator_id\":\"{}\",\"name\":\"{}\",\"vote\":\"{}\",\"snapshot2_weight\":{},\"revealed\":{}}}",
                hex::encode(validator_id.0),
                json_escape(name),
                vote,
                weight,
                proposal.reveals.contains_key(validator_id)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "{{\"proposal_id\":\"{}\",\"votes\":[{}]}}",
        hex::encode(proposal_id.0),
        votes
    ))
}

fn proposal_summary_json(proposal: &indra_state::governance::ProposalRecord) -> String {
    format!(
        "{{\"proposal_id\":\"{}\",\"title\":\"{}\",\"tier\":\"{}\",\"phase\":\"{}\",\"action_type\":\"{}\",\"proposer_id\":\"{}\",\"proposed_epoch\":{},\"commit_start_epoch\":{},\"reveal_start_epoch\":{},\"tally_epoch\":{},\"executable_after_epoch\":{},\"yes_stake\":{},\"no_stake\":{},\"abstain_stake\":{},\"passed\":{},\"deposit_burned\":{}}}",
        hex::encode(proposal.proposal_id.0),
        json_escape(&proposal.title),
        proposal_tier_str(proposal.tier),
        proposal_phase_str(proposal.phase),
        governable_action_str(&proposal.action),
        hex::encode(proposal.proposer_id.0),
        proposal.proposed_epoch,
        proposal.commit_start_epoch,
        proposal.reveal_start_epoch,
        proposal.tally_epoch,
        proposal.executable_after_epoch,
        proposal.yes_stake,
        proposal.no_stake,
        proposal.abstain_stake,
        proposal.passed.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
        proposal.deposit_burned
    )
}

fn proposal_detail_json(proposal: &indra_state::governance::ProposalRecord) -> String {
    let mut base = proposal_summary_json(proposal);
    if base.ends_with('}') {
        base.pop();
    }
    format!(
        "{},\"description\":\"{}\",\"commit_count\":{},\"reveal_count\":{},\"redelegation_count\":{}}}",
        base,
        json_escape(&proposal.description),
        proposal.commits.len(),
        proposal.reveals.len(),
        proposal.redelegations.len()
    )
}

fn proposal_phase_str(phase: indra_state::governance::ProposalPhase) -> &'static str {
    match phase {
        indra_state::governance::ProposalPhase::Deliberation => "Deliberation",
        indra_state::governance::ProposalPhase::Commit => "Commit",
        indra_state::governance::ProposalPhase::Reveal => "Reveal",
        indra_state::governance::ProposalPhase::Tally => "Tally",
        indra_state::governance::ProposalPhase::ExecDelay => "ExecDelay",
        indra_state::governance::ProposalPhase::Executed => "Executed",
        indra_state::governance::ProposalPhase::Failed => "Failed",
        indra_state::governance::ProposalPhase::Expired => "Expired",
        indra_state::governance::ProposalPhase::Cancelled => "Cancelled",
    }
}

fn proposal_tier_str(tier: indra_core::types::governance::ProposalTier) -> &'static str {
    match tier {
        indra_core::types::governance::ProposalTier::Standard => "Standard",
        indra_core::types::governance::ProposalTier::Critical => "Critical",
    }
}

fn governable_action_str(action: &indra_core::types::governance::GovernableAction) -> &'static str {
    match action {
        indra_core::types::governance::GovernableAction::SetSlashLivenessThresholdEpochs {
            ..
        } => "SetSlashLivenessThresholdEpochs",
        indra_core::types::governance::GovernableAction::SetMinDelegationSpark { .. } => {
            "SetMinDelegationSpark"
        }
        indra_core::types::governance::GovernableAction::SetProposalDepositSpark { .. } => {
            "SetProposalDepositSpark"
        }
        indra_core::types::governance::GovernableAction::SetSlashLivenessBps { .. } => {
            "SetSlashLivenessBps"
        }
        indra_core::types::governance::GovernableAction::SetSlashDoublePrecommitBps { .. } => {
            "SetSlashDoublePrecommitBps"
        }
        indra_core::types::governance::GovernableAction::SetSlashSurroundVoteBps { .. } => {
            "SetSlashSurroundVoteBps"
        }
        indra_core::types::governance::GovernableAction::SetMaxCommissionBps { .. } => {
            "SetMaxCommissionBps"
        }
        indra_core::types::governance::GovernableAction::SetGovernanceDelayEpochs { .. } => {
            "SetGovernanceDelayEpochs"
        }
        indra_core::types::governance::GovernableAction::SetGovernanceQuorumBps { .. } => {
            "SetGovernanceQuorumBps"
        }
        indra_core::types::governance::GovernableAction::SetGovernanceCriticalQuorumBps {
            ..
        } => "SetGovernanceCriticalQuorumBps",
    }
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// `indra_getValidatorRewards` — returns pending validator and delegator rewards.
fn get_validator_rewards(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let validator_hex = first_param(params, "validator_id")?;
    let validator_id = parse_hex32_value(&validator_hex, "validator_id")?;
    let validator_rewards = state
        .chain
        .validators
        .get(&validator_id)
        .map(|v| v.pending_rewards)
        .unwrap_or(0);
    let delegator_rewards: Vec<String> = state
        .chain
        .delegations
        .get_delegators(&validator_id)
        .iter()
        .map(|entry| {
            format!(
                r#"{{"delegator_id":"{}","pending_rewards":{}}}"#,
                hex::encode(entry.delegator_id.0),
                entry.pending_rewards,
            )
        })
        .collect();
    Ok(format!(
        r#"{{"validator_id":"{}","validator_pending_rewards":{},"delegator_rewards":[{}]}}"#,
        validator_hex,
        validator_rewards,
        delegator_rewards.join(",")
    ))
}

/// `indra_getValidatorSet` — returns all active validators.
///
/// Result: `{"validators": [{"validator_id", "stake"}, ...]}`
// v2 — includes name field
fn get_validator_set(state: &NodeState<'_>) -> RpcResult<String> {
    let mut entries = Vec::new();
    for v in state.chain.validators.active_validators() {
        let id_hex = hex::encode(v.validator_id.0);
        let network_addr = v
            .network_addr
            .as_ref()
            .map(|addr| format!(r#""{}""#, json_escape(addr)))
            .unwrap_or_else(|| "null".to_string());
        entries.push(format!(
            r#"{{"validator_id":"{}","name":"{}","stake":{},"status":"active","commission_bps":{},"pending_rewards":{},"epoch_joined":{},"hybrid_classical_pk":"{}","hybrid_pq_pk":"{}","network_addr":{}}}"#,
            id_hex,
            json_escape(&v.name),
            v.stake_spark,
            v.commission_bps,
            v.pending_rewards,
            v.registered_epoch,
            v.hybrid_classical_pk.map(hex::encode).unwrap_or_default(),
            v.hybrid_pq_pk.as_ref().map(hex::encode).unwrap_or_default(),
            network_addr,
        ));
    }
    Ok(format!(r#"{{"validators":[{}]}}"#, entries.join(",")))
}

/// `indra_getUtxoProof` — returns sparse Merkle proof data for a UTXO.
fn get_utxo_proof(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let utxo_hex = first_param(params, "utxo_id")?;
    if utxo_hex.len() != 64 {
        return Ok("null".to_string());
    }
    let utxo_id = match parse_hex32_value(&utxo_hex, "utxo_id") {
        Ok(id) => id,
        Err(_) => return Ok("null".to_string()),
    };
    let proof = state.chain.utxos.prove(&utxo_id);
    let siblings = proof
        .siblings
        .iter()
        .map(|sibling| format!(r#""{}""#, hex::encode(sibling)))
        .collect::<Vec<_>>()
        .join(",");
    let value_hash = proof.value.map(hex::encode).unwrap_or_default();
    let state_root = indra_state::compute_state_root(&state.chain);
    Ok(format!(
        r#"{{"utxo_id":"{}","present":{},"value_hash":"{}","siblings":[{}],"state_root":"{}"}}"#,
        hex::encode(utxo_id.0),
        if proof.value.is_some() {
            "true"
        } else {
            "false"
        },
        value_hash,
        siblings,
        hex::encode(state_root.0),
    ))
}

/// `indra_sendTransaction` — submit a hex-encoded signed transaction.
///
/// Params: `["<tx_hex>"]`
/// Result: `{"tx_id": "<hex>", "status": "accepted"}`
fn send_transaction(params: &[String]) -> DispatchResult {
    let tx_hex = params
        .first()
        .map(|param| unquote(param).to_string())
        .unwrap_or_default();
    if tx_hex.is_empty() {
        return DispatchResult::Ready(Err(RpcError::InvalidParams(
            "missing tx_hex param".to_string(),
        )));
    }
    match hex::decode(&tx_hex) {
        Ok(bytes) => DispatchResult::SubmitTransaction(bytes),
        Err(_) => DispatchResult::Ready(Err(RpcError::InvalidParams(
            "invalid hex encoding".to_string(),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_state::ChainState;

    fn make_state(_suffix: &str) -> ChainState {
        ChainState::new_genesis()
    }

    #[test]
    fn get_height_returns_zero_at_genesis() {
        let engine = make_state("h");
        let state = NodeState::read_only(&engine);
        let result = get_height(&state).unwrap();
        assert!(result.contains("\"height\":0"));
    }

    #[test]
    fn get_chain_info_has_all_fields() {
        let engine = make_state("ci");
        let state = NodeState::read_only(&engine);
        let result = get_chain_info(&state).unwrap();
        assert!(result.contains("\"height\""));
        assert!(result.contains("\"base_fee\""));
        assert!(result.contains("\"total_supply\""));
        assert!(result.contains("\"epoch\""));
        assert!(result.contains("\"pruned_mode\""));
        assert!(result.contains("\"lowest_block\""));
    }

    #[test]
    fn get_mempool_size_returns_zero() {
        let engine = make_state("mp");
        let state = NodeState::read_only(&engine);
        let result = get_mempool_size(&state).unwrap();
        assert!(result.contains("\"size\":0"));
    }

    #[test]
    fn method_not_found_errors() {
        let engine = make_state("mf");
        let state = NodeState::read_only(&engine);
        let result = dispatch("indra_nonExistent", &[], &state);
        assert!(matches!(
            result,
            DispatchResult::Ready(Err(RpcError::MethodNotFound(_)))
        ));
    }

    #[test]
    fn get_block_beyond_tip_errors() {
        let engine = make_state("gb");
        let state = NodeState::read_only(&engine);
        let result = get_block(&["999".to_string()], &state);
        assert!(matches!(result, Err(RpcError::NotFound(_))));
    }

    #[test]
    fn get_validator_invalid_hex_errors() {
        let engine = make_state("gv");
        let state = NodeState::read_only(&engine);
        let result = get_validator(&["not_hex".to_string()], &state);
        assert!(matches!(result, Err(RpcError::InvalidParams(_))));
    }

    #[test]
    fn rpc_exposes_network_addr_field() {
        let mut engine = make_state("vna");
        for (byte, addr) in [(0x31, Some("203.0.113.31:30303")), (0x32, None)] {
            engine
                .validators
                .upsert(indra_state::ValidatorEntry {
                    validator_id: indra_core::Bytes32::from([byte; 32]),
                    name: format!("validator-{byte}"),
                    hybrid_classical_pk: None,
                    hybrid_pq_pk: None,
                    vrf_pk: None,
                    stake_spark: 1_000_000,
                    status: indra_state::ValidatorStatus::Active,
                    registered_epoch: 0,
                    last_active_epoch: 0,
                    pending_rewards: 0,
                    rewards_last_epoch: 0,
                    self_report_count: 0,
                    commission_bps: indra_core::types::primitives::DEFAULT_COMMISSION_BPS,
                    pending_commission_bps: None,
                    pending_commission_effective_epoch: None,
                    min_delegation_spark: indra_core::types::primitives::DUST_LIMIT_SPARK,
                    auto_delegate_to: None,
                    network_addr: addr.map(str::to_string),
                    network_addr_last_updated_epoch: addr.map(|_| 1),
                })
                .unwrap();
        }
        let state = NodeState::read_only(&engine);
        let result = get_validator_set(&state).unwrap();

        assert!(result.contains(r#""network_addr":"203.0.113.31:30303""#));
        assert!(result.contains(r#""network_addr":null"#));
    }

    #[test]
    fn get_validator_auto_delegate_returns_target_and_name() {
        let mut engine = make_state("gad");
        let validator_id = indra_core::Bytes32::from([0x11; 32]);
        let target_id = indra_core::Bytes32::from([0x22; 32]);
        engine
            .validators
            .upsert(indra_state::ValidatorEntry {
                validator_id,
                name: "source".to_string(),
                hybrid_classical_pk: None,
                hybrid_pq_pk: None,
                vrf_pk: None,
                stake_spark: 1_000_000,
                status: indra_state::ValidatorStatus::Registered,
                registered_epoch: 0,
                last_active_epoch: 0,
                pending_rewards: 0,
                rewards_last_epoch: 0,
                self_report_count: 0,
                commission_bps: indra_core::types::primitives::DEFAULT_COMMISSION_BPS,
                pending_commission_bps: None,
                pending_commission_effective_epoch: None,
                min_delegation_spark: indra_core::types::primitives::DUST_LIMIT_SPARK,
                auto_delegate_to: Some(target_id),
                network_addr: None,
                network_addr_last_updated_epoch: None,
            })
            .unwrap();
        engine
            .validators
            .upsert(indra_state::ValidatorEntry {
                validator_id: target_id,
                name: "target".to_string(),
                hybrid_classical_pk: None,
                hybrid_pq_pk: None,
                vrf_pk: None,
                stake_spark: 2_000_000,
                status: indra_state::ValidatorStatus::Active,
                registered_epoch: 0,
                last_active_epoch: 0,
                pending_rewards: 0,
                rewards_last_epoch: 0,
                self_report_count: 0,
                commission_bps: indra_core::types::primitives::DEFAULT_COMMISSION_BPS,
                pending_commission_bps: None,
                pending_commission_effective_epoch: None,
                min_delegation_spark: indra_core::types::primitives::DUST_LIMIT_SPARK,
                auto_delegate_to: None,
                network_addr: None,
                network_addr_last_updated_epoch: None,
            })
            .unwrap();
        let state = NodeState::read_only(&engine);
        let result = get_validator_auto_delegate(&[hex::encode(validator_id.0)], &state).unwrap();

        assert!(result.contains(&format!(
            r#""auto_delegate_to":"{}""#,
            hex::encode(target_id.0)
        )));
        assert!(result.contains(r#""target_name":"target""#));
    }

    #[test]
    fn get_peers_public_returns_only_count() {
        let engine = make_state("peers");
        let state = NodeState::with_network(
            &engine,
            vec![
                "203.0.113.10:30303".to_string(),
                "198.51.100.22:30303".to_string(),
            ],
            2,
            7,
            3,
        );

        let result = get_peers(&state).unwrap();

        assert!(result.contains(r#""peer_count":2"#));
        assert!(result.contains(r#""target_peers":"#));
        assert!(result.contains(r#""discovered_count":7"#));
        assert!(!result.contains("203.0.113.10"));
        assert!(!result.contains("198.51.100.22"));
        assert!(!result.contains("validator_peers"));
        assert!(!result.contains("connected\""));
    }

    #[test]
    fn peers_count_uses_authenticated_connection_count_not_dialable_addresses() {
        let engine = make_state("inbound-peers");
        let state = NodeState::with_network(&engine, Vec::new(), 3, 7, 0);

        let chain_info = get_chain_info(&state).unwrap();
        let peers = get_peers(&state).unwrap();

        assert!(chain_info.contains(r#""peers":3"#));
        assert!(peers.contains(r#""peer_count":3"#));
        assert!(peers.contains(r#""discovered_count":7"#));
    }
}
