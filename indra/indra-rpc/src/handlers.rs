//! RPC method handlers.
//!
//! Each handler receives the parsed request params and a reference to
//! the node state, and returns a JSON string result or an RpcError.

use indra_core::{
    codec::Encode,
    types::crypto::{HybridPubKey, HybridSignature},
    types::primitives::{
        delegator_bond_accounting_active, Bytes32 as CoreBytes32,
        COMPACT_STAKE_BOND_RELEASE_BLINDING_DOMAIN, NORMAL_STAKE_BOND_RELEASE_BLINDING_DOMAIN,
        SCHEMA_VERSION, SCHEMA_VERSION_GENESIS, STAKING_REWARD_BLINDING_DOMAIN, STAKING_TX_IDX,
    },
    types::{
        block::{BlockV1, NO_POLC_ROUND},
        epoch_record::EpochRecord,
        governance::{compute_proposal_id, GovernanceOpV2, GovernancePayload},
        staking::{StakingOp, StakingOpBody},
        transaction::TransactionV1,
    },
    Bytes32,
};
use indra_state::{
    epoch::epoch_for_height, validator::DelegationReturnReason, AuthTreeProof, ChainState,
    ProofTerminal,
};

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
    /// RPC listener mode serving this request.
    pub rpc_mode: RpcMode,
    /// Whether this listener has a configured non-empty admin token.
    pub admin_token_configured: bool,
}

/// Network-layer context needed by peer-aware RPC methods.
pub struct NetworkContext<'a> {
    /// Dialable connected validator peer addresses.
    pub validator_peer_addrs: Vec<String>,
    /// Full connected validator peer topology for admin-only diagnostics.
    pub validator_peer_topology: Vec<PeerTopologyEntry>,
    /// Number of currently authenticated validator peer connections.
    pub connected_validator_peer_count: usize,
    /// Number of discovered peers not necessarily connected.
    pub discovered_peer_count: usize,
    /// Number of currently connected observer peers.
    pub observer_peer_count: usize,
    /// Marker tying this context to the borrowed node state lifetime.
    pub _lifetime: std::marker::PhantomData<&'a ()>,
}

/// Admin-visible connected validator peer entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTopologyEntry {
    /// Authenticated validator ID, when known to the live node.
    pub validator_id: Option<String>,
    /// Connected peer socket address.
    pub address: String,
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
        Self::with_network_policy(
            engine,
            validator_peer_addrs,
            Vec::new(),
            connected_validator_peer_count,
            discovered_peer_count,
            observer_peer_count,
            RpcMode::Full,
            false,
        )
    }

    /// Construct a state object with network context and explicit RPC policy.
    #[allow(clippy::too_many_arguments)]
    pub fn with_network_policy(
        engine: &'a impl RpcEngineView,
        validator_peer_addrs: Vec<String>,
        validator_peer_topology: Vec<PeerTopologyEntry>,
        connected_validator_peer_count: usize,
        discovered_peer_count: usize,
        observer_peer_count: usize,
        rpc_mode: RpcMode,
        admin_token_configured: bool,
    ) -> Self {
        let topology = if validator_peer_topology.is_empty() {
            validator_peer_addrs
                .iter()
                .map(|address| PeerTopologyEntry {
                    validator_id: None,
                    address: address.clone(),
                })
                .collect()
        } else {
            validator_peer_topology
        };
        Self {
            engine,
            chain: engine.chain_state(),
            mempool_size: engine.mempool_size(),
            pruned_mode: engine.pruned_mode(),
            lowest_block: engine.lowest_block(),
            blocks_retained: engine.blocks_retained(),
            network: Some(NetworkContext {
                validator_peer_addrs,
                validator_peer_topology: topology,
                connected_validator_peer_count,
                discovered_peer_count,
                observer_peer_count,
                _lifetime: std::marker::PhantomData,
            }),
            rpc_mode,
            admin_token_configured,
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
            rpc_mode: RpcMode::ReadOnly,
            admin_token_configured: false,
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
            rpc_mode: RpcMode::Full,
            admin_token_configured: false,
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
    /// Return a retained block by height, if this RPC context has block-store access.
    fn get_block_by_height(&self, _height: u64) -> Result<Option<BlockV1>, String> {
        Ok(None)
    }
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
    /// The method exposes privileged local-node diagnostics and requires an
    /// explicit admin token on the full local listener.
    Admin,
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
    ("indra_getCanonicalBlocks", RpcMethodAccess::ReadOnly),
    ("indra_getTransaction", RpcMethodAccess::ReadOnly),
    ("indra_getLegacyScanChallenge", RpcMethodAccess::ReadOnly),
    (
        "indra_getLegacyBalanceAuthorized",
        RpcMethodAccess::ReadOnly,
    ),
    ("indra_getLegacyUtxosAuthorized", RpcMethodAccess::ReadOnly),
    (
        "indra_explainUtxoProvenanceAuthorized",
        RpcMethodAccess::ReadOnly,
    ),
    ("indra_getUtxoProof", RpcMethodAccess::ReadOnly),
    ("indra_getPeers", RpcMethodAccess::ReadOnly),
    ("indra_getStakingNonce", RpcMethodAccess::ReadOnly),
    ("indra_getDelegations", RpcMethodAccess::ReadOnly),
    ("indra_getDelegatorPositions", RpcMethodAccess::ReadOnly),
    ("indra_getDelegationReturnEvents", RpcMethodAccess::ReadOnly),
    ("indra_getDelegatorRewards", RpcMethodAccess::ReadOnly),
    ("indra_getValidatorDelegators", RpcMethodAccess::ReadOnly),
    ("indra_getStakeBonds", RpcMethodAccess::ReadOnly),
    ("indra_getDelegatorIdentityDebug", RpcMethodAccess::Admin),
    ("indra_getStakeBondDebug", RpcMethodAccess::Admin),
    ("indra_getConsensusSnapshots", RpcMethodAccess::Admin),
    ("indra_getEpochInfo", RpcMethodAccess::ReadOnly),
    ("indra_getEpochRecord", RpcMethodAccess::ReadOnly),
    ("indra_getEpochHistory", RpcMethodAccess::ReadOnly),
    ("indra_getLatestEpoch", RpcMethodAccess::ReadOnly),
    ("indra_getSchemaInfo", RpcMethodAccess::Admin),
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
    ("indra_getPeerTopology", RpcMethodAccess::Admin),
    ("indra_getRpcPolicy", RpcMethodAccess::ReadOnly),
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
    check_rpc_method_allowed_with_admin(method, mode, false, false)
}

/// Check whether a method is allowed on a listener with token-aware admin policy.
pub fn check_rpc_method_allowed_with_admin(
    method: &str,
    mode: RpcMode,
    admin_token_configured: bool,
    admin_token_valid: bool,
) -> RpcResult<()> {
    match rpc_method_access(method) {
        Some(RpcMethodAccess::Admin) => {
            if mode != RpcMode::Full {
                return Err(RpcError::Forbidden(format!(
                    "RPC admin method {method} is not available on read-only listener"
                )));
            }
            if !admin_token_configured {
                return Err(RpcError::Forbidden(
                    "RPC admin methods are disabled because rpc.admin_token is not configured"
                        .to_string(),
                ));
            }
            if !admin_token_valid {
                return Err(RpcError::Forbidden(
                    "RPC admin method requires a valid X-Admin-Token header".to_string(),
                ));
            }
        }
        Some(RpcMethodAccess::Write) if mode == RpcMode::ReadOnly => {
            return Err(RpcError::Forbidden(format!(
                "RPC method {method} is not available on read-only listener"
            )));
        }
        Some(RpcMethodAccess::ReadOnly | RpcMethodAccess::Write) => {}
        None if mode == RpcMode::ReadOnly => {
            return Err(RpcError::Forbidden(format!(
                "RPC method {method} is not available on read-only listener"
            )));
        }
        None => {}
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
    dispatch_with_admin(method, params, state, mode, false, false)
}

/// Dispatch a method call with listener-mode and admin-token enforcement.
pub fn dispatch_with_admin(
    method: &str,
    params: &[String],
    state: &NodeState<'_>,
    mode: RpcMode,
    admin_token_configured: bool,
    admin_token_valid: bool,
) -> DispatchResult {
    use DispatchResult::Ready;
    if let Err(error) =
        check_rpc_method_allowed_with_admin(method, mode, admin_token_configured, admin_token_valid)
    {
        return Ready(Err(error));
    }
    match method {
        "indra_getHeight" => Ready(get_height(state)),
        "indra_getTip" => Ready(get_tip(state)),
        "indra_getChainInfo" => Ready(get_chain_info(state)),
        "indra_getMempoolSize" => Ready(get_mempool_size(state)),
        "indra_getBlock" => Ready(get_block(params, state)),
        "indra_getCanonicalBlocks" => Ready(get_canonical_blocks(params, state)),
        "indra_getTransaction" => Ready(get_transaction(params, state)),
        "indra_getLegacyScanChallenge" => Ready(get_legacy_scan_challenge(params, state)),
        "indra_getLegacyBalanceAuthorized" => Ready(get_legacy_balance_authorized(params, state)),
        "indra_getLegacyUtxosAuthorized" => Ready(get_legacy_utxos_authorized(params, state)),
        "indra_explainUtxoProvenanceAuthorized" => {
            Ready(explain_utxo_provenance_authorized(params, state))
        }
        "indra_getUtxoProof" => Ready(get_utxo_proof(params, state)),
        "indra_getPeers" => Ready(get_peers(state)),
        "indra_getStakingNonce" => Ready(get_staking_nonce(params, state)),
        "indra_getDelegations" => Ready(get_delegations(params, state)),
        "indra_getDelegatorPositions" => Ready(get_delegator_positions(params, state)),
        "indra_getDelegationReturnEvents" => Ready(get_delegation_return_events(params, state)),
        "indra_getDelegatorRewards" => Ready(get_delegator_rewards(params, state)),
        "indra_getValidatorDelegators" => Ready(get_validator_delegators(params, state)),
        "indra_getStakeBonds" => Ready(get_stake_bonds(params, state)),
        "indra_getDelegatorIdentityDebug" => Ready(get_delegator_identity_debug(params, state)),
        "indra_getStakeBondDebug" => Ready(get_stake_bond_debug(params, state)),
        "indra_getConsensusSnapshots" => Ready(get_consensus_snapshots(state)),
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
        "indra_getPeerTopology" => Ready(get_peer_topology(state)),
        "indra_getRpcPolicy" => Ready(get_rpc_policy(state)),
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
    let total_staked_spark = s.validators.total_selectable_self_stake().saturating_add(
        if delegator_bond_accounting_active(s.height) {
            s.total_active_delegated_bond_stake()
        } else {
            s.delegations.total_staked()
        },
    );
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
/// Result: header-level block metadata for a retained block. This method does
/// not return full transaction or operation payloads; those remain a separate
/// full-block/RPC-size policy decision.
fn get_block(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let height_str = params
        .first()
        .ok_or_else(|| RpcError::InvalidParams("missing height parameter".to_string()))?;

    let height: u64 = unquote(height_str)
        .parse()
        .map_err(|_| RpcError::InvalidParams(format!("invalid height: {height_str}")))?;

    let s = &state.chain;
    if height < state.lowest_block {
        return Err(RpcError::NotFound(format!(
            "block {height} is below the local retention window; lowest available block is {}. Use an archive node for historical queries.",
            state.lowest_block
        )));
    }

    if height > s.height {
        return Err(RpcError::NotFound(format!(
            "block {height} exceeds current tip {}",
            s.height
        )));
    }

    match state.engine.get_block_by_height(height) {
        Ok(Some(block)) => Ok(block_rpc_json(&block)),
        Ok(None) => Err(RpcError::NotFound(format!(
            "block {height} is not available in this node's retained block log"
        ))),
        Err(error) => Err(RpcError::Internal(format!(
            "failed to read block {height}: {error}"
        ))),
    }
}

const MAX_CANONICAL_BLOCK_PAGE: u64 = 100;

/// `indra_getCanonicalBlocks(from_height, limit, expected_parent_hash)`.
///
/// Returns canonical full block encodings. The caller-provided parent anchor
/// makes a reorg explicit instead of silently continuing on another branch.
fn get_canonical_blocks(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    if params.len() != 3 {
        return Err(RpcError::InvalidParams(
            "expected [from_height, limit, expected_parent_hash]".to_string(),
        ));
    }
    let from_height = unquote(&params[0])
        .parse::<u64>()
        .map_err(|_| RpcError::InvalidParams("invalid from_height".to_string()))?;
    let limit = unquote(&params[1])
        .parse::<u64>()
        .map_err(|_| RpcError::InvalidParams("invalid limit".to_string()))?;
    if limit == 0 || limit > MAX_CANONICAL_BLOCK_PAGE {
        return Err(RpcError::InvalidParams(format!(
            "limit must be between 1 and {MAX_CANONICAL_BLOCK_PAGE}"
        )));
    }
    if from_height < state.lowest_block {
        return Err(RpcError::NotFound(format!(
            "block {from_height} is below the local retention window; lowest available block is {}",
            state.lowest_block
        )));
    }
    let expected_parent = parse_hex32_param(&[params[2].clone()], "expected_parent_hash")?;
    let first = state
        .engine
        .get_block_by_height(from_height)
        .map_err(|error| RpcError::Internal(format!("failed to read block: {error}")))?
        .ok_or_else(|| RpcError::NotFound(format!("block {from_height} is not retained")))?;
    if first.header.prev_hash != expected_parent {
        return Err(RpcError::InvalidParams(format!(
            "canonical parent mismatch at height {from_height}: expected {}, canonical {}",
            hex::encode(expected_parent.0),
            hex::encode(first.header.prev_hash.0)
        )));
    }

    let last_height = state
        .chain
        .height
        .min(from_height.saturating_add(limit).saturating_sub(1));
    let mut entries = Vec::new();
    for height in from_height..=last_height {
        let block = state
            .engine
            .get_block_by_height(height)
            .map_err(|error| RpcError::Internal(format!("failed to read block: {error}")))?
            .ok_or_else(|| RpcError::NotFound(format!("block {height} is not retained")))?;
        entries.push(format!(
            r#"{{"height":{},"block_hash":"{}","block_hex":"{}"}}"#,
            height,
            hex::encode(block.header.block_hash().0),
            hex::encode(block.encode_to_vec())
        ));
    }
    let next_height = last_height
        .checked_add(1)
        .filter(|height| *height <= state.chain.height);
    Ok(format!(
        r#"{{"from_height":{},"blocks":[{}],"next_height":{},"tip_height":{},"tip_hash":"{}"}}"#,
        from_height,
        entries.join(","),
        next_height.map_or_else(|| "null".to_string(), |height| height.to_string()),
        state.chain.height,
        hex::encode(state.chain.tip_hash.0),
    ))
}

/// `indra_getTransaction` — returns a canonical transaction by block position.
///
/// Params: `[<height: number>, <tx_index: number>]`
/// Result: retained transaction bytes as hex, plus its block position.
fn get_transaction(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    if params.len() != 2 {
        return Err(RpcError::InvalidParams(
            "expected [height, tx_index]".to_string(),
        ));
    }
    let height_str = &params[0];
    let tx_index_str = &params[1];
    let height: u64 = unquote(height_str)
        .parse()
        .map_err(|_| RpcError::InvalidParams(format!("invalid height: {height_str}")))?;
    let tx_index: usize = unquote(tx_index_str)
        .parse()
        .map_err(|_| RpcError::InvalidParams(format!("invalid tx_index: {tx_index_str}")))?;

    if height < state.lowest_block {
        return Err(RpcError::NotFound(format!(
            "block {height} is below the local retention window; lowest available block is {}. Use an archive node for historical queries.",
            state.lowest_block
        )));
    }
    if height > state.chain.height {
        return Err(RpcError::NotFound(format!(
            "block {height} exceeds current tip {}",
            state.chain.height
        )));
    }

    match state.engine.get_block_by_height(height) {
        Ok(Some(block)) => {
            let tx = block.transactions.get(tx_index).ok_or_else(|| {
                RpcError::NotFound(format!(
                    "transaction {tx_index} not found in block {height}"
                ))
            })?;
            Ok(format!(
                r#"{{"height":{},"tx_index":{},"tx_hex":"{}"}}"#,
                height,
                tx_index,
                hex::encode(tx.encode_to_vec())
            ))
        }
        Ok(None) => Err(RpcError::NotFound(format!(
            "block {height} is not available in this node's retained block log"
        ))),
        Err(error) => Err(RpcError::Internal(format!(
            "failed to read block {height}: {error}"
        ))),
    }
}

fn optional_hex_json(value: Option<Bytes32>) -> String {
    value
        .map(|bytes| format!(r#""{}""#, hex::encode(bytes.0)))
        .unwrap_or_else(|| "null".to_string())
}

fn polc_round_json(polc_round: u32) -> String {
    if polc_round == NO_POLC_ROUND {
        "null".to_string()
    } else {
        polc_round.to_string()
    }
}

fn block_rpc_json(block: &BlockV1) -> String {
    let header = &block.header;
    format!(
        concat!(
            r#"{{"height":{},"block_hash":"{}","protocol_version":{},"prev_hash":"{}","#,
            r#""timestamp":{},"state_root":"{}","validator_set_root":"{}","#,
            r#""mempool_set_root":"{}","value_hash":"{}","base_fee":{},"proposer_round":{},"polc_round":{},"#,
            r#""proposer_vrf_output":"{}","proposer_vrf_proof_len":{},"quorum_certificate_len":{},"election_result_hash":{},"#,
            r#""tx_count":{},"slash_evidence_count":{},"governance_op_count":{},"staking_op_count":{},"vrf_reveal_count":{}}}"#
        ),
        header.height,
        hex::encode(header.block_hash().0),
        header.protocol_version.0,
        hex::encode(header.prev_hash.0),
        header.timestamp,
        hex::encode(header.state_root.0),
        hex::encode(header.validator_set_root.0),
        hex::encode(header.mempool_set_root.0),
        hex::encode(header.value_hash.0),
        header.base_fee,
        header.proposer_round,
        polc_round_json(header.polc_round),
        hex::encode(header.proposer_vrf_output.0),
        header.proposer_vrf_proof.len(),
        header.quorum_certificate.len(),
        optional_hex_json(header.election_result_hash),
        block.transactions.len(),
        block.slashing_evidence.len(),
        block.governance_ops.len(),
        block.staking_ops.len(),
        block.vrf_reveals.len(),
    )
}

/// Domain separator for the temporary legacy UTXO-scan ownership proof.
///
/// This is not an OutputV2 view key. It proves possession of the legacy
/// address spend key before an address-indexed RPC scan is served.
pub const LEGACY_SCAN_AUTH_DOMAIN: &[u8] = b"INDRA-legacy-utxo-scan-auth-v1:";

fn legacy_scan_challenge_bytes(address: [u8; 32], state: &NodeState<'_>) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(LEGACY_SCAN_AUTH_DOMAIN.len() + b"challenge:".len() + 32);
    preimage.extend_from_slice(LEGACY_SCAN_AUTH_DOMAIN);
    preimage.extend_from_slice(b"challenge:");
    preimage.extend_from_slice(state.chain.chain_id.as_bytes());
    preimage.extend_from_slice(&address);
    indra_crypto::sha256(&preimage)
}

fn legacy_scan_signing_message(address: [u8; 32], challenge: [u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(LEGACY_SCAN_AUTH_DOMAIN.len() + 32 + 32);
    preimage.extend_from_slice(LEGACY_SCAN_AUTH_DOMAIN);
    preimage.extend_from_slice(b"proof:");
    preimage.extend_from_slice(&address);
    preimage.extend_from_slice(&challenge);
    indra_crypto::sha256(&preimage)
}

/// Build the message hash that a legacy scan proof must sign.
pub fn legacy_scan_auth_message(address: [u8; 32], challenge: [u8; 32]) -> [u8; 32] {
    legacy_scan_signing_message(address, challenge)
}

fn parse_hex_field<const N: usize>(json: &str, field: &str) -> RpcResult<[u8; N]> {
    let raw = extract_json_string_field(json, field)
        .ok_or_else(|| RpcError::InvalidParams(format!("missing auth field {field}")))?;
    let bytes = hex::decode(raw)
        .map_err(|_| RpcError::InvalidParams(format!("invalid hex in auth field {field}")))?;
    if bytes.len() != N {
        return Err(RpcError::InvalidParams(format!(
            "auth field {field} must be {N} bytes"
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex_vec_field(json: &str, field: &str) -> RpcResult<Vec<u8>> {
    let raw = extract_json_string_field(json, field)
        .ok_or_else(|| RpcError::InvalidParams(format!("missing auth field {field}")))?;
    hex::decode(raw)
        .map_err(|_| RpcError::InvalidParams(format!("invalid hex in auth field {field}")))
}

fn parse_u8_field(json: &str, field: &str) -> RpcResult<u8> {
    let key = format!("\"{}\":", field);
    let pos = json
        .find(&key)
        .ok_or_else(|| RpcError::InvalidParams(format!("missing auth field {field}")))?;
    let after = json[pos + key.len()..].trim_start();
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits
        .parse::<u8>()
        .map_err(|_| RpcError::InvalidParams(format!("invalid auth field {field}")))
}

fn extract_json_string_field<'a>(json: &'a str, field: &str) -> Option<&'a str> {
    let key = format!("\"{}\":", field);
    let pos = json.find(&key)?;
    let after = json[pos + key.len()..].trim_start();
    let after = after.strip_prefix('"')?;
    let end = after.find('"')?;
    Some(&after[..end])
}

fn verify_legacy_scan_auth(
    address: [u8; 32],
    auth_json: &str,
    state: &NodeState<'_>,
) -> RpcResult<()> {
    let version = parse_u8_field(auth_json, "version")?;
    if version != 1 {
        return Err(RpcError::Forbidden(format!(
            "unsupported legacy scan auth version {version}"
        )));
    }

    let challenge = parse_hex_field::<32>(auth_json, "challenge")?;
    let expected_challenge = legacy_scan_challenge_bytes(address, state);
    if challenge != expected_challenge {
        return Err(RpcError::Forbidden(
            "legacy scan authorization challenge was not issued for this address and chain".into(),
        ));
    }

    let classical_pk = parse_hex_field::<32>(auth_json, "hybrid_classical_pk")?;
    if indra_crypto::sha256(&classical_pk) != address {
        return Err(RpcError::Forbidden(
            "legacy scan authorization public key does not match requested address".into(),
        ));
    }

    let pq_pk = parse_hex_vec_field(auth_json, "hybrid_pq_pk")?;
    let classical_sig = parse_hex_vec_field(auth_json, "classical_sig")?;
    let pq_sig = parse_hex_vec_field(auth_json, "pq_sig")?;

    let pk = HybridPubKey {
        classical_pk: Bytes32::from(classical_pk),
        pq_pk: indra_core::types::primitives::VariableBytes::from_slice(&pq_pk)
            .map_err(|_| RpcError::InvalidParams("hybrid_pq_pk too large".into()))?,
    };
    let sig = HybridSignature {
        classical_sig: indra_core::types::primitives::VariableBytes::from_slice(&classical_sig)
            .map_err(|_| RpcError::InvalidParams("classical_sig too large".into()))?,
        pq_sig: indra_core::types::primitives::VariableBytes::from_slice(&pq_sig)
            .map_err(|_| RpcError::InvalidParams("pq_sig too large".into()))?,
    };
    let crypto_pk = pk
        .to_crypto_pubkey()
        .map_err(|reason| RpcError::InvalidParams(format!("invalid auth public key: {reason}")))?;
    let crypto_sig = sig
        .to_crypto_sig()
        .map_err(|reason| RpcError::InvalidParams(format!("invalid auth signature: {reason}")))?;
    let msg = legacy_scan_signing_message(address, challenge);
    indra_crypto::verify_hybrid(&msg, &crypto_sig, &crypto_pk)
        .map_err(|_| RpcError::Forbidden("legacy scan authorization signature invalid".into()))
}

fn authorized_address(params: &[String], state: &NodeState<'_>) -> RpcResult<(String, [u8; 32])> {
    if params.len() < 2 {
        return Err(RpcError::InvalidParams(
            "expected address and scan_auth_proof parameters".into(),
        ));
    }
    let address_hex = unquote(&params[0]).to_string();
    let auth = unquote(&params[1]);
    let address = parse_address_hex(&address_hex)?;
    verify_legacy_scan_auth(address, auth, state)?;
    Ok((address_hex, address))
}

/// `indra_getLegacyScanChallenge` — returns a node-provided challenge for a
/// temporary legacy UTXO-scan ownership proof.
fn get_legacy_scan_challenge(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let address_hex = first_param(params, "address")?;
    let address = parse_address_hex(&address_hex)?;
    let challenge = legacy_scan_challenge_bytes(address, state);
    Ok(format!(
        r#"{{"address":"{}","challenge":"{}","auth_format_version":1,"note":"sign INDRA legacy UTXO-scan authorization; this is not an OutputV2 view key"}}"#,
        address_hex,
        hex::encode(challenge)
    ))
}

/// `indra_getLegacyBalanceAuthorized` — returns total legacy UTXO balance after
/// the address owner proves possession of the legacy spend key.
fn get_legacy_balance_authorized(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let (address_hex, address) = authorized_address(params, state)?;
    let mut balance = 0u64;
    for entry in state.chain.utxos.all_entries() {
        let owner_address = indra_crypto::sha256(&entry.output.owner_pubkey.classical_pk.0);
        if owner_address == address {
            balance = balance.saturating_add(entry.output.value_spark);
        }
    }
    Ok(format!(
        r#"{{"address":"{}","balance":{},"privacy_note":"{}"}}"#,
        address_hex, balance, LEGACY_SCAN_PRIVACY_NOTE
    ))
}

/// `indra_getLegacyUtxosAuthorized` — returns legacy UTXOs after the address
/// owner proves possession of the legacy spend key.
fn get_legacy_utxos_authorized(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let (address_hex, address) = authorized_address(params, state)?;
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
        LEGACY_SCAN_PRIVACY_NOTE
    ))
}

/// `indra_explainUtxoProvenanceAuthorized` — classify an owned UTXO's
/// protocol-generated provenance when retained state/block data can prove it.
fn explain_utxo_provenance_authorized(
    params: &[String],
    state: &NodeState<'_>,
) -> RpcResult<String> {
    if params.len() < 3 {
        return Err(RpcError::InvalidParams(
            "expected address, scan_auth_proof, and utxo_id parameters".into(),
        ));
    }
    let (address_hex, address) = authorized_address(&params[..2], state)?;
    let utxo_id = parse_hex32_value(unquote(&params[2]), "utxo_id")?;
    let entry =
        state.chain.utxos.get(&utxo_id).ok_or_else(|| {
            RpcError::NotFound(format!("UTXO {} not found", hex::encode(utxo_id.0)))
        })?;
    let owner_address = indra_crypto::sha256(&entry.output.owner_pubkey.classical_pk.0);
    if owner_address != address {
        return Err(RpcError::Forbidden(
            "scan authorization does not cover requested UTXO owner".into(),
        ));
    }

    let explanation = classify_utxo_provenance(entry, state);
    Ok(format!(
        r#"{{"address":"{}","utxo_id":"{}","amount":{},"created_height":{},"tx_index":{},"out_index":{},"lock_height":{},"commitment":"{}","output_hex":"{}","category":"{}","recoverable":{},"context":{},"reason":{},"privacy_note":"{}"}}"#,
        address_hex,
        hex::encode(entry.utxo_id.0),
        entry.output.value_spark,
        entry.created_height,
        entry.tx_index,
        entry.output_index,
        entry.output.lock_height,
        hex::encode(entry.output.commitment.compressed_point.0),
        hex::encode(entry.output.encode_to_vec()),
        explanation.category,
        explanation.recoverable,
        explanation.context.unwrap_or_else(|| "null".to_string()),
        json_string_or_null(explanation.reason.as_deref()),
        LEGACY_SCAN_PRIVACY_NOTE,
    ))
}

struct UtxoProvenanceExplanation {
    category: &'static str,
    recoverable: bool,
    context: Option<String>,
    reason: Option<String>,
}

fn recoverable(category: &'static str, context: String) -> UtxoProvenanceExplanation {
    UtxoProvenanceExplanation {
        category,
        recoverable: true,
        context: Some(context),
        reason: None,
    }
}

fn unrecoverable(category: &'static str, reason: impl Into<String>) -> UtxoProvenanceExplanation {
    UtxoProvenanceExplanation {
        category,
        recoverable: false,
        context: None,
        reason: Some(reason.into()),
    }
}

fn classify_utxo_provenance(
    entry: &indra_state::utxo::UtxoEntry,
    state: &NodeState<'_>,
) -> UtxoProvenanceExplanation {
    if entry.created_height == 0 {
        return unrecoverable(
            "genesis",
            "genesis UTXOs are handled by the existing wallet-scan genesis recovery path",
        );
    }

    match entry.tx_index {
        STAKING_TX_IDX => classify_staking_provenance(entry, state),
        tx if tx == u32::MAX - 3 => classify_governance_change(entry, state),
        tx if tx == u32::MAX - 2 => classify_governance_refund(entry, state),
        _ => unrecoverable(
            "ordinary_transaction_output",
            "not a remaining protocol-generated wallet-scan recovery category",
        ),
    }
}

fn classify_staking_provenance(
    entry: &indra_state::utxo::UtxoEntry,
    state: &NodeState<'_>,
) -> UtxoProvenanceExplanation {
    if let Some(explanation) = classify_delegation_return_event(entry, state) {
        return explanation;
    }

    let block = match retained_block(entry.created_height, state) {
        Ok(Some(block)) => block,
        Ok(None) => {
            return unrecoverable(
                "staking_protocol_output_unavailable",
                retained_block_unavailable_reason(entry.created_height, state),
            )
        }
        Err(reason) => return unrecoverable("staking_protocol_output_unavailable", reason),
    };

    for evidence in &block.slashing_evidence {
        let evidence_hash = Bytes32::from(indra_crypto::sha256(&evidence.encode_to_vec()));
        let blinding = derive_slash_reward_blinding(&evidence_hash, entry.created_height);
        if commitment_matches(entry, &blinding) {
            return recoverable(
                "slash_reporter_reward",
                format!(
                    r#"{{"evidence_hash":"{}","block_height":{}}}"#,
                    hex::encode(evidence_hash.0),
                    entry.created_height
                ),
            );
        }
    }

    for op in &block.staking_ops {
        if let StakingOpBody::ClaimRewards {
            validator_id,
            delegator_pubkey,
            ..
        } = &op.body
        {
            let delegator_id = staking_pubkey_to_id(delegator_pubkey);
            let blinding =
                derive_staking_reward_blinding(validator_id, &delegator_id, entry.created_height);
            if commitment_matches(entry, &blinding) {
                return recoverable(
                    "staking_reward_claim",
                    format!(
                        r#"{{"validator_id":"{}","delegator_id":"{}","claim_height":{}}}"#,
                        hex::encode(validator_id.0),
                        hex::encode(delegator_id.0),
                        entry.created_height
                    ),
                );
            }
        }
    }

    unrecoverable(
        "staking_protocol_output_unclassified",
        "retained staking provenance did not open this UTXO commitment",
    )
}

fn classify_delegation_return_event(
    entry: &indra_state::utxo::UtxoEntry,
    state: &NodeState<'_>,
) -> Option<UtxoProvenanceExplanation> {
    for event in state.chain.delegation_return_events.iter().filter(|event| {
        event.returned_height == entry.created_height && event.refund_utxo_id == entry.utxo_id
    }) {
        match event.reason {
            DelegationReturnReason::ValidatorEvicted => {
                let compact = derive_compact_bond_release_blinding(
                    &event.validator_id,
                    &event.delegator_id,
                    &event.bond_utxo_id,
                    event.returned_height,
                    event.amount_spark,
                );
                if commitment_matches(entry, &compact) {
                    return Some(recoverable(
                        "validator_eviction_bond_refund",
                        delegation_event_context(event, "compact_bond_release"),
                    ));
                }

                return Some(unrecoverable(
                    "legacy_bond_release",
                    "legacy bond release reused the original output; the blinding is not derivable from retained state and requires local wallet history or an archive/indexer",
                ));
            }
            DelegationReturnReason::UnbondingMatured => {
                let normal = derive_normal_bond_release_blinding(
                    &event.validator_id,
                    &event.delegator_id,
                    &event.bond_utxo_id,
                    event.returned_height,
                    event.amount_spark,
                );
                if commitment_matches(entry, &normal) {
                    return Some(recoverable(
                        "normal_bond_release",
                        delegation_event_context(event, "normal_bond_release"),
                    ));
                }

                return Some(unrecoverable(
                    "normal_bond_release",
                    "matured bond release provenance did not open this UTXO commitment",
                ));
            }
        }
    }

    for event in state
        .chain
        .delegation_return_events
        .iter()
        .filter(|event| event.returned_height == entry.created_height)
    {
        let reward = derive_staking_reward_blinding(
            &event.validator_id,
            &event.delegator_id,
            event.returned_height,
        );
        if commitment_matches(entry, &reward) {
            return Some(recoverable(
                "validator_eviction_pending_reward",
                delegation_event_context(event, "pending_reward_payout"),
            ));
        }
    }

    None
}

fn classify_governance_change(
    entry: &indra_state::utxo::UtxoEntry,
    state: &NodeState<'_>,
) -> UtxoProvenanceExplanation {
    let block = match retained_block(entry.created_height, state) {
        Ok(Some(block)) => block,
        Ok(None) => {
            return unrecoverable(
                "governance_deposit_change_unavailable",
                retained_block_unavailable_reason(entry.created_height, state),
            )
        }
        Err(reason) => return unrecoverable("governance_deposit_change_unavailable", reason),
    };
    let proposed_epoch = epoch_for_height(entry.created_height);
    for op in &block.governance_ops {
        if let GovernancePayload::Propose { action, .. } = &op.payload {
            let proposal_id =
                compute_proposal_id(op.signer_id, action, proposed_epoch, &state.chain.chain_id);
            let blinding = derive_governance_change_blinding(&proposal_id);
            if commitment_matches(entry, &blinding) {
                return recoverable(
                    "governance_deposit_change",
                    format!(
                        r#"{{"proposal_id":"{}","proposer_id":"{}","proposed_epoch":{}}}"#,
                        hex::encode(proposal_id.0),
                        hex::encode(op.signer_id.0),
                        proposed_epoch
                    ),
                );
            }
        }
    }
    unrecoverable(
        "governance_deposit_change_unclassified",
        "retained proposal block data did not open this governance change commitment",
    )
}

fn classify_governance_refund(
    entry: &indra_state::utxo::UtxoEntry,
    state: &NodeState<'_>,
) -> UtxoProvenanceExplanation {
    for proposal in state.chain.governance.proposals.values() {
        if proposal.proposer_pubkey != entry.output.owner_pubkey {
            continue;
        }
        let blinding = derive_governance_refund_blinding(&proposal.proposal_id);
        if commitment_matches(entry, &blinding) {
            return recoverable(
                "governance_deposit_refund",
                format!(
                    r#"{{"proposal_id":"{}","proposer_id":"{}","proposed_epoch":{}}}"#,
                    hex::encode(proposal.proposal_id.0),
                    hex::encode(proposal.proposer_id.0),
                    proposal.proposed_epoch
                ),
            );
        }
    }
    unrecoverable(
        "governance_deposit_refund_unavailable",
        "matching proposal record is not retained; historical refunds require an archive/indexer",
    )
}

fn retained_block(height: u64, state: &NodeState<'_>) -> Result<Option<BlockV1>, String> {
    state.engine.get_block_by_height(height)
}

fn retained_block_unavailable_reason(height: u64, state: &NodeState<'_>) -> String {
    if state.pruned_mode && height < state.lowest_block {
        format!(
            "block {} is below this node's retained block window (lowest_block={}, blocks_retained={}); use an archive/indexer",
            height, state.lowest_block, state.blocks_retained
        )
    } else {
        format!(
            "block {} is not available from this RPC context; use a node with retained block bodies or an archive/indexer",
            height
        )
    }
}

fn commitment_matches(entry: &indra_state::utxo::UtxoEntry, blinding: &[u8; 32]) -> bool {
    indra_crypto::commit(entry.output.value_spark, blinding).0
        == entry.output.commitment.compressed_point.0
}

fn derive_staking_reward_blinding(
    validator_id: &CoreBytes32,
    delegator_id: &CoreBytes32,
    height: u64,
) -> [u8; 32] {
    let mut data = Vec::with_capacity(STAKING_REWARD_BLINDING_DOMAIN.len() + 32 + 32 + 8);
    data.extend_from_slice(STAKING_REWARD_BLINDING_DOMAIN);
    data.extend_from_slice(&validator_id.0);
    data.extend_from_slice(&delegator_id.0);
    data.extend_from_slice(&height.to_le_bytes());
    indra_crypto::sha256(&data)
}

fn staking_pubkey_to_id(pubkey: &HybridPubKey) -> CoreBytes32 {
    CoreBytes32::from(indra_crypto::sha256(&pubkey.classical_pk.0))
}

fn derive_slash_reward_blinding(evidence_hash: &CoreBytes32, height: u64) -> [u8; 32] {
    let mut data = b"INDRA-SLASH-REWARD-BLINDING-v1".to_vec();
    data.extend_from_slice(&evidence_hash.0);
    data.extend_from_slice(&height.to_le_bytes());
    indra_crypto::sha256(&data)
}

fn derive_compact_bond_release_blinding(
    validator_id: &CoreBytes32,
    delegator_id: &CoreBytes32,
    bond_utxo_id: &CoreBytes32,
    release_height: u64,
    amount_spark: u64,
) -> [u8; 32] {
    let mut data =
        Vec::with_capacity(COMPACT_STAKE_BOND_RELEASE_BLINDING_DOMAIN.len() + 32 + 32 + 32 + 8 + 8);
    data.extend_from_slice(COMPACT_STAKE_BOND_RELEASE_BLINDING_DOMAIN);
    data.extend_from_slice(&validator_id.0);
    data.extend_from_slice(&delegator_id.0);
    data.extend_from_slice(&bond_utxo_id.0);
    data.extend_from_slice(&release_height.to_le_bytes());
    data.extend_from_slice(&amount_spark.to_le_bytes());
    indra_crypto::sha256(&data)
}

fn derive_normal_bond_release_blinding(
    validator_id: &CoreBytes32,
    delegator_id: &CoreBytes32,
    bond_utxo_id: &CoreBytes32,
    release_height: u64,
    amount_spark: u64,
) -> [u8; 32] {
    let mut data =
        Vec::with_capacity(NORMAL_STAKE_BOND_RELEASE_BLINDING_DOMAIN.len() + 32 + 32 + 32 + 8 + 8);
    data.extend_from_slice(NORMAL_STAKE_BOND_RELEASE_BLINDING_DOMAIN);
    data.extend_from_slice(&validator_id.0);
    data.extend_from_slice(&delegator_id.0);
    data.extend_from_slice(&bond_utxo_id.0);
    data.extend_from_slice(&release_height.to_le_bytes());
    data.extend_from_slice(&amount_spark.to_le_bytes());
    indra_crypto::sha256(&data)
}

#[cfg(test)]
fn derive_slashed_self_stake_blinding(
    validator_id: &CoreBytes32,
    bond_utxo_id: &CoreBytes32,
    release_height: u64,
) -> [u8; 32] {
    use indra_core::types::primitives::SLASH_BOND_RELEASE_BLINDING_DOMAIN;

    let mut data = Vec::with_capacity(SLASH_BOND_RELEASE_BLINDING_DOMAIN.len() + 32 + 32 + 8);
    data.extend_from_slice(SLASH_BOND_RELEASE_BLINDING_DOMAIN);
    data.extend_from_slice(&validator_id.0);
    data.extend_from_slice(&bond_utxo_id.0);
    data.extend_from_slice(&release_height.to_le_bytes());
    indra_crypto::sha256(&data)
}

fn derive_governance_refund_blinding(proposal_id: &CoreBytes32) -> [u8; 32] {
    indra_crypto::sha256(
        &[
            b"governance-refund-blinding".as_slice(),
            proposal_id.0.as_slice(),
        ]
        .concat(),
    )
}

fn derive_governance_change_blinding(proposal_id: &CoreBytes32) -> [u8; 32] {
    indra_crypto::sha256(
        &[
            b"governance-deposit-change-blinding".as_slice(),
            proposal_id.0.as_slice(),
        ]
        .concat(),
    )
}

fn delegation_event_context(
    event: &indra_state::DelegationReturnEvent,
    derivation: &'static str,
) -> String {
    format!(
        r#"{{"validator_id":"{}","delegator_id":"{}","bond_utxo_id":"{}","returned_height":{},"returned_epoch":{},"amount_spark":{},"derivation":"{}"}}"#,
        hex::encode(event.validator_id.0),
        hex::encode(event.delegator_id.0),
        hex::encode(event.bond_utxo_id.0),
        event.returned_height,
        event.returned_epoch,
        event.amount_spark,
        derivation,
    )
}

fn json_string_or_null(value: Option<&str>) -> String {
    match value {
        Some(value) => format!("\"{}\"", json_escape(value)),
        None => "null".to_string(),
    }
}

const LEGACY_SCAN_PRIVACY_NOTE: &str =
    "authorized legacy RPC scan only; raw OutputV1 chain data still exposes owner and value metadata to full-node observers";

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

/// `indra_getPeerTopology` — admin-only full connected validator peer details.
fn get_peer_topology(state: &NodeState<'_>) -> RpcResult<String> {
    let Some(network) = &state.network else {
        return Ok(
            r#"{"validator_peers":[],"peer_count":0,"discovered_count":0,"observer_peer_count":0}"#
                .to_string(),
        );
    };
    let peers = network
        .validator_peer_topology
        .iter()
        .map(|peer| match &peer.validator_id {
            Some(validator_id) => format!(
                r#"{{"validator_id":"{}","address":"{}"}}"#,
                json_escape(validator_id),
                json_escape(&peer.address)
            ),
            None => format!(
                r#"{{"validator_id":null,"address":"{}"}}"#,
                json_escape(&peer.address)
            ),
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        r#"{{"validator_peers":[{}],"peer_count":{},"discovered_count":{},"observer_peer_count":{}}}"#,
        peers,
        network.connected_validator_peer_count,
        network.discovered_peer_count,
        network.observer_peer_count,
    ))
}

/// `indra_getRpcPolicy` — reports listener policy without revealing tokens.
fn get_rpc_policy(state: &NodeState<'_>) -> RpcResult<String> {
    let mode = match state.rpc_mode {
        RpcMode::Full => "full",
        RpcMode::ReadOnly => "read_only",
    };
    Ok(format!(
        r#"{{"listener_mode":"{}","admin_token_configured":{},"admin_token_value_exposed":false}}"#,
        mode, state.admin_token_configured
    ))
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
        r#"{{"validator_id":"{id}","name":"{name}","stake":{stake},"status":"{status}","epoch_joined":{epoch},"hybrid_classical_pk":"{classical_pk}","hybrid_pq_pk":"{pq_pk}","cold_hybrid_classical_pk":{cold_classical_pk},"cold_hybrid_pq_pk":{cold_pq_pk},"cold_key_version":{cold_version},"cold_key_status":"{cold_status}","cold_nonce":{cold_nonce}}}"#,
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
        cold_classical_pk = validator
            .cold_hybrid_classical_pk
            .map(|pk| format!(r#""{}""#, hex::encode(pk)))
            .unwrap_or_else(|| "null".to_string()),
        cold_pq_pk = validator
            .cold_hybrid_pq_pk
            .map(|pk| format!(r#""{}""#, hex::encode(pk)))
            .unwrap_or_else(|| "null".to_string()),
        cold_version = validator.cold_key_version,
        cold_status = match validator.cold_key_status {
            indra_state::ColdKeyStatus::Unenrolled => "unenrolled",
            indra_state::ColdKeyStatus::Active => "active",
        },
        cold_nonce = validator.cold_nonce,
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
            let (staked_spark, active_bonds, unbonding_bonds) =
                rpc_delegator_bond_status(state.chain, &validator_id, &entry.delegator_id);
            let precise = delegator_bond_accounting_active(state.chain.height);
            let unbonding = if precise {
                active_bonds == 0 && unbonding_bonds > 0
            } else {
                entry.unbonding_end_epoch.is_some()
            };
            if precise {
                format!(
                    r#"{{"delegator_id":"{}","staked_spark":{},"pending_rewards":{},"unbonding":{},"unbonding_end_epoch":{},"active_bond_count":{},"unbonding_bond_count":{}}}"#,
                    hex::encode(entry.delegator_id.0),
                    staked_spark,
                    entry.pending_rewards,
                    if unbonding { "true" } else { "false" },
                    entry.unbonding_end_epoch.unwrap_or(0),
                    active_bonds,
                    unbonding_bonds,
                )
            } else {
                format!(
                    r#"{{"delegator_id":"{}","staked_spark":{},"pending_rewards":{},"unbonding":{},"unbonding_end_epoch":{}}}"#,
                    hex::encode(entry.delegator_id.0),
                    entry.staked_spark,
                    entry.pending_rewards,
                    if entry.unbonding_end_epoch.is_some() { "true" } else { "false" },
                    entry.unbonding_end_epoch.unwrap_or(0),
                )
            }
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
            let (active_stake, active_bonds, unbonding_bonds) =
                rpc_delegator_bond_status(state.chain, validator_id, &entry.delegator_id);
            let precise = delegator_bond_accounting_active(state.chain.height);
            let unbonding = if precise {
                active_bonds == 0 && unbonding_bonds > 0
            } else {
                entry.unbonding_end_epoch.is_some()
            };
            let unbonding_end = entry
                .unbonding_end_epoch
                .map(|epoch| epoch.to_string())
                .unwrap_or_else(|| "null".to_string());

            total_staked = total_staked.saturating_add(if precise {
                active_stake
            } else {
                entry.staked_spark
            });
            total_rewards = total_rewards.saturating_add(entry.pending_rewards);
            if unbonding {
                unbonding_positions = unbonding_positions.saturating_add(1);
            } else {
                active_positions = active_positions.saturating_add(1);
            }

            positions.push(if precise {
                format!(
                    r#"{{"validator_id":"{}","validator_name":"{}","staked_spark":{},"pending_rewards":{},"rewards_last_epoch":{},"unbonding":{},"unbonding_end_epoch":{},"commission_bps":{},"active_bond_count":{},"unbonding_bond_count":{}}}"#,
                    hex::encode(validator_id.0),
                    validator_name,
                    active_stake,
                    entry.pending_rewards,
                    entry.rewards_last_epoch,
                    if unbonding { "true" } else { "false" },
                    unbonding_end,
                    commission_bps,
                    active_bonds,
                    unbonding_bonds,
                )
            } else {
                format!(
                    r#"{{"validator_id":"{}","validator_name":"{}","staked_spark":{},"pending_rewards":{},"rewards_last_epoch":{},"unbonding":{},"unbonding_end_epoch":{},"commission_bps":{}}}"#,
                    hex::encode(validator_id.0),
                    validator_name,
                    entry.staked_spark,
                    entry.pending_rewards,
                    entry.rewards_last_epoch,
                    if unbonding { "true" } else { "false" },
                    unbonding_end,
                    commission_bps,
                )
            });
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

fn rpc_delegator_bond_status(
    state: &ChainState,
    validator_id: &Bytes32,
    delegator_id: &Bytes32,
) -> (u64, u64, u64) {
    state
        .staked_bonds
        .values()
        .filter(|bond| {
            bond.validator_id == *validator_id
                && bond.delegator_id == *delegator_id
                && bond.validator_id != bond.delegator_id
        })
        .fold((0u64, 0u64, 0u64), |(stake, active, unbonding), bond| {
            if bond.unbonding_end_epoch.is_none() {
                (
                    stake.saturating_add(bond.amount_spark),
                    active.saturating_add(1),
                    unbonding,
                )
            } else {
                (stake, active, unbonding.saturating_add(1))
            }
        })
}

/// `indra_getDelegationReturnEvents` — returns automatic principal-return events for a delegator.
///
/// Params: `["<delegator_id_hex>", "<since_epoch optional>", "<limit optional>"]`
fn get_delegation_return_events(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let delegator_hex = first_param(params, "delegator_id")?;
    let delegator_id = parse_hex32_value(&delegator_hex, "delegator_id")?;
    let since_epoch = if params.len() > 1 {
        Some(parse_u64_param(params, 1, "since_epoch")?)
    } else {
        None
    };
    let limit = if params.len() > 2 {
        parse_u64_param(params, 2, "limit")?.min(1_000) as usize
    } else {
        100usize
    };

    let mut events = Vec::new();
    for event in state
        .chain
        .delegation_return_events
        .iter()
        .filter(|event| event.delegator_id == delegator_id)
        .filter(|event| {
            since_epoch
                .map(|epoch| event.returned_epoch >= epoch)
                .unwrap_or(true)
        })
        .rev()
        .take(limit)
    {
        let reason = match event.reason {
            indra_state::validator::DelegationReturnReason::ValidatorEvicted => "ValidatorEvicted",
            indra_state::validator::DelegationReturnReason::UnbondingMatured => "UnbondingMatured",
        };
        events.push(format!(
            r#"{{"delegator_id":"{}","validator_id":"{}","bond_utxo_id":"{}","amount_spark":{},"reason":"{}","returned_epoch":{},"returned_height":{},"refund_utxo_id":"{}"}}"#,
            hex::encode(event.delegator_id.0),
            hex::encode(event.validator_id.0),
            hex::encode(event.bond_utxo_id.0),
            event.amount_spark,
            reason,
            event.returned_epoch,
            event.returned_height,
            hex::encode(event.refund_utxo_id.0),
        ));
    }
    events.reverse();

    Ok(format!(
        r#"{{"delegator_id":"{}","events":[{}],"count":{}}}"#,
        delegator_hex,
        events.join(","),
        events.len(),
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
        let (active_stake, active_bonds, unbonding_bonds) =
            rpc_delegator_bond_status(state.chain, &validator_id, &entry.delegator_id);
        let precise = delegator_bond_accounting_active(state.chain.height);
        let unbonding = if precise {
            active_bonds == 0 && unbonding_bonds > 0
        } else {
            entry.unbonding_end_epoch.is_some()
        };
        let unbonding_end = entry
            .unbonding_end_epoch
            .map(|epoch| epoch.to_string())
            .unwrap_or_else(|| "null".to_string());
        total_delegated = total_delegated.saturating_add(if precise {
            active_stake
        } else {
            entry.staked_spark
        });
        total_rewards = total_rewards.saturating_add(entry.pending_rewards);
        delegators.push(if precise {
            format!(
                r#"{{"delegator_id":"{}","staked_spark":{},"pending_rewards":{},"unbonding":{},"unbonding_end_epoch":{},"rewards_last_epoch":{},"active_bond_count":{},"unbonding_bond_count":{}}}"#,
                hex::encode(entry.delegator_id.0),
                active_stake,
                entry.pending_rewards,
                if unbonding { "true" } else { "false" },
                unbonding_end,
                entry.rewards_last_epoch,
                active_bonds,
                unbonding_bonds,
            )
        } else {
            format!(
                r#"{{"delegator_id":"{}","staked_spark":{},"pending_rewards":{},"unbonding":{},"unbonding_end_epoch":{},"rewards_last_epoch":{}}}"#,
                hex::encode(entry.delegator_id.0),
                entry.staked_spark,
                entry.pending_rewards,
                if unbonding { "true" } else { "false" },
                unbonding_end,
                entry.rewards_last_epoch,
            )
        });
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

/// `indra_getDelegatorIdentityDebug` — admin-only direct lookup for one delegator identity.
fn get_delegator_identity_debug(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let delegator_id = parse_hex32_param(params, "delegator_id")?;
    let Some(pubkey) = state.chain.delegator_identities.get(&delegator_id) else {
        return Ok(format!(
            r#"{{"delegator_id":"{}","exists":false,"pubkey":null}}"#,
            hex::encode(delegator_id.0)
        ));
    };
    Ok(format!(
        r#"{{"delegator_id":"{}","exists":true,"pubkey":{{"classical_pk":"{}","pq_pk":"{}"}}}}"#,
        hex::encode(delegator_id.0),
        hex::encode(pubkey.classical_pk.0),
        hex::encode(pubkey.pq_pk.as_slice()),
    ))
}

/// `indra_getStakeBondDebug` — admin-only compact-format check for one stake bond.
fn get_stake_bond_debug(params: &[String], state: &NodeState<'_>) -> RpcResult<String> {
    let bond_utxo_id = parse_hex32_param(params, "bond_utxo_id")?;
    let bond = state.chain.staked_bonds.get(&bond_utxo_id).ok_or_else(|| {
        RpcError::NotFound(format!(
            "stake bond {} not found",
            hex::encode(bond_utxo_id.0)
        ))
    })?;
    Ok(format!(
        r#"{{"bond_utxo_id":"{}","compact":{},"has_range_proof":{},"has_owner_pubkey":{},"bonded_epoch":{},"validator_id":"{}","delegator_id":"{}"}}"#,
        hex::encode(bond.utxo_id.0),
        if bond.original_output.range_proof.is_none() {
            "true"
        } else {
            "false"
        },
        if bond.original_output.range_proof.is_some() {
            "true"
        } else {
            "false"
        },
        if bond.original_output.owner_pubkey.is_some() {
            "true"
        } else {
            "false"
        },
        bond.bonded_epoch,
        hex::encode(bond.validator_id.0),
        hex::encode(bond.delegator_id.0),
    ))
}

/// `indra_getConsensusSnapshots` — admin-only retained consensus authority summary.
fn get_consensus_snapshots(state: &NodeState<'_>) -> RpcResult<String> {
    fn snapshot_json(
        snapshot: Option<&indra_core::types::consensus_snapshot::ConsensusSnapshot>,
    ) -> String {
        snapshot.map_or_else(
            || "null".to_string(),
            |snapshot| {
                format!(
                    r#"{{"activation_height":{},"source_boundary_height":{},"snapshot_root":"{}","member_count":{},"total_weight_spark":{}}}"#,
                    snapshot.activation_height,
                    snapshot.source_boundary_height,
                    hex::encode(snapshot.snapshot_root.0),
                    snapshot.entries().len(),
                    snapshot.total_weight_spark,
                )
            },
        )
    }

    let current = state.chain.consensus_snapshots.last();
    let previous = state
        .chain
        .consensus_snapshots
        .len()
        .checked_sub(2)
        .and_then(|index| state.chain.consensus_snapshots.get(index));
    let epoch_length = indra_core::types::primitives::EPOCH_DURATION_BLOCKS;
    let next_boundary_height = state
        .chain
        .height
        .checked_div(epoch_length)
        .unwrap_or_default()
        .saturating_add(1)
        .saturating_mul(epoch_length);

    Ok(format!(
        r#"{{"state_height":{},"next_consensus_height":{},"next_scheduled_boundary_height":{},"current":{},"previous":{}}}"#,
        state.chain.height,
        state.chain.height.saturating_add(1),
        next_boundary_height,
        snapshot_json(current),
        snapshot_json(previous),
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
        .saturating_add(if delegator_bond_accounting_active(state.chain.height) {
            state.chain.total_active_delegated_bond_stake()
        } else {
            state.chain.delegations.total_staked()
        });
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
    // Returns active proposals plus the consensus-retained recent terminal
    // history. Older terminal proposals are pruned from ChainState; deep history is an archive
    // node/indexer concern, matching block-pruning precedent.
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
    // A missing proposal may either never have existed or may be an old
    // terminal proposal pruned by the consensus retention rule. Current RPC
    // intentionally exposes the retained state view only; archive/indexer
    // tooling is responsible for deep historical lookup.
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
    // Same retained-state semantics as `indra_getProposal`: votes for pruned
    // historical proposals are no longer available from ordinary node state.
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
            let committed = proposal.commits.contains_key(validator_id);
            let name = state
                .chain
                .validators
                .get(validator_id)
                .map(|validator| validator.name.as_str())
                .unwrap_or("unknown");
            format!(
                "{{\"validator_id\":\"{}\",\"name\":\"{}\",\"vote\":\"{}\",\"snapshot2_weight\":{},\"committed\":{},\"revealed\":{}}}",
                hex::encode(validator_id.0),
                json_escape(name),
                vote,
                weight,
                committed,
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
        indra_state::governance::ProposalPhase::ExecDelay => "ExecDelay",
        indra_state::governance::ProposalPhase::Executed => "Executed",
        indra_state::governance::ProposalPhase::Failed => "Failed",
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
            r#"{{"validator_id":"{}","name":"{}","stake":{},"status":"active","commission_bps":{},"pending_rewards":{},"epoch_joined":{},"hybrid_classical_pk":"{}","hybrid_pq_pk":"{}","network_addr":{},"cold_hybrid_classical_pk":{},"cold_hybrid_pq_pk":{},"cold_key_version":{},"cold_key_status":"{}","cold_nonce":{}}}"#,
            id_hex,
            json_escape(&v.name),
            v.stake_spark,
            v.commission_bps,
            v.pending_rewards,
            v.registered_epoch,
            v.hybrid_classical_pk.map(hex::encode).unwrap_or_default(),
            v.hybrid_pq_pk.as_ref().map(hex::encode).unwrap_or_default(),
            network_addr,
            v.cold_hybrid_classical_pk
                .map(|pk| format!(r#""{}""#, hex::encode(pk)))
                .unwrap_or_else(|| "null".to_string()),
            v.cold_hybrid_pq_pk
                .map(|pk| format!(r#""{}""#, hex::encode(pk)))
                .unwrap_or_else(|| "null".to_string()),
            v.cold_key_version,
            match v.cold_key_status {
                indra_state::ColdKeyStatus::Unenrolled => "unenrolled",
                indra_state::ColdKeyStatus::Active => "active",
            },
            v.cold_nonce,
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
    let proof = state
        .chain
        .utxos
        .prove_at_height(&utxo_id, state.chain.height);
    let state_root = indra_state::compute_state_root(&state.chain);
    match proof {
        AuthTreeProof::V2Compressed(proof) => {
            let value_hash = proof.value.map(hex::encode).unwrap_or_default();
            Ok(format!(
                r#"{{"proof_version":"compressed-auth-tree-v2","utxo_id":"{}","present":{},"value_hash":"{}","terminal":{},"steps":[{}],"state_root":"{}"}}"#,
                hex::encode(utxo_id.0),
                if proof.value.is_some() {
                    "true"
                } else {
                    "false"
                },
                value_hash,
                compressed_terminal_json(&proof.terminal),
                proof
                    .steps
                    .iter()
                    .map(compressed_step_json)
                    .collect::<Vec<_>>()
                    .join(","),
                hex::encode(state_root.0),
            ))
        }
    }
}

fn compressed_terminal_json(terminal: &ProofTerminal) -> String {
    match terminal {
        ProofTerminal::Included => r#"{"kind":"included"}"#.to_string(),
        ProofTerminal::MissingChild => r#"{"kind":"missing_child"}"#.to_string(),
        ProofTerminal::DivergentLeaf {
            existing_key,
            existing_value_hash,
        } => format!(
            r#"{{"kind":"divergent_leaf","existing_key":"{}","existing_value_hash":"{}"}}"#,
            hex::encode(existing_key),
            hex::encode(existing_value_hash)
        ),
        ProofTerminal::PrefixMismatch {
            branch_prefix,
            children,
        } => format!(
            r#"{{"kind":"prefix_mismatch","branch_prefix":"{}","children":[{}]}}"#,
            encode_nibble_path(branch_prefix),
            children
                .iter()
                .map(compressed_child_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

fn compressed_step_json(step: &indra_state::CompressedProofStep) -> String {
    format!(
        r#"{{"branch_prefix":"{}","target_nibble":{},"child_bitmap":{},"siblings":[{}]}}"#,
        encode_nibble_path(&step.branch_prefix),
        step.target_nibble,
        step.child_bitmap,
        step.siblings
            .iter()
            .map(compressed_child_json)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn compressed_child_json(child: &indra_state::CompressedProofChild) -> String {
    let kind = match child.kind {
        indra_state::smt::CompressedChildKind::Leaf => "leaf",
        indra_state::smt::CompressedChildKind::Branch => "branch",
    };
    format!(
        r#"{{"nibble":{},"kind":"{}","hash":"{}"}}"#,
        child.nibble,
        kind,
        hex::encode(child.hash)
    )
}

fn encode_nibble_path(path: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(path.len());
    for nibble in path {
        out.push(HEX[usize::from(*nibble & 0x0F)] as char);
    }
    out
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
    use indra_core::{
        types::{
            block::{BlockHeaderV1, BlockV1},
            consensus_snapshot::{ConsensusSnapshot, ConsensusSnapshotEntry},
            crypto::{HybridPubKey, HybridSignature},
            governance::{
                GovernableAction, GovernanceActionType, GovernanceOpV2, GovernancePayload,
                ProposalTier,
            },
            primitives::{MAX_RANGE_PROOF_BYTES, MAX_VRF_PROOF_BYTES},
            slashing::SlashEvidenceV1,
            staking::{StakingOp, StakingOpBody},
            transaction::OutputV1,
            vote::{VoteStep, VoteV1},
        },
        Bytes32, CommitmentV1, ProtocolVersion, VariableBytes,
    };
    use indra_crypto::{
        sha256, ClassicalKeypair, HybridKeypair, PaymentKeypairV1, PqKeypair, VrfKeypair,
    };
    use indra_state::{
        apply_staking_op,
        governance::{ProposalPhase, ProposalRecord},
        validator::{DelegationReturnEvent, DelegationReturnReason},
        validator::{StakeBondEntry, StakeBondOutput},
        ChainState,
    };
    use std::collections::BTreeMap;

    fn make_state(_suffix: &str) -> ChainState {
        ChainState::new_genesis()
    }

    struct BlockBackedEngine {
        chain: ChainState,
        lowest_block: u64,
        blocks: BTreeMap<u64, BlockV1>,
    }

    impl RpcEngineView for BlockBackedEngine {
        fn chain_state(&self) -> &ChainState {
            &self.chain
        }

        fn mempool_size(&self) -> usize {
            0
        }

        fn pruned_mode(&self) -> bool {
            true
        }

        fn lowest_block(&self) -> u64 {
            self.lowest_block
        }

        fn blocks_retained(&self) -> usize {
            self.blocks.len()
        }

        fn get_block_by_height(&self, height: u64) -> Result<Option<BlockV1>, String> {
            Ok(self.blocks.get(&height).cloned())
        }
    }

    fn dummy_block(height: u64, byte: u8) -> BlockV1 {
        BlockV1 {
            header: BlockHeaderV1 {
                protocol_version: ProtocolVersion::CURRENT,
                height,
                prev_hash: Bytes32::from([byte.wrapping_sub(1); 32]),
                timestamp: 1_700_000_000 + height,
                state_root: Bytes32::from([byte; 32]),
                validator_set_root: Bytes32::from([byte.wrapping_add(1); 32]),
                mempool_set_root: Bytes32::from([byte.wrapping_add(2); 32]),
                value_hash: Bytes32::from([byte.wrapping_add(3); 32]),
                base_fee: 100 + height,
                proposer_round: byte as u32,
                polc_round: NO_POLC_ROUND,
                proposer_vrf_output: Bytes32::from([byte.wrapping_add(4); 32]),
                proposer_vrf_proof: VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[byte; 64])
                    .unwrap(),
                quorum_certificate: VariableBytes::from_slice(&[]).unwrap(),
                election_result_hash: Some(Bytes32::from([byte.wrapping_add(5); 32])),
            },
            transactions: Vec::new(),
            slashing_evidence: Vec::new(),
            slashing_evidence_v2: Vec::new(),
            governance_ops: Vec::new(),
            staking_ops: Vec::new(),
            vrf_reveals: Vec::new(),
        }
    }

    fn block_with_transaction() -> BlockBackedEngine {
        let mut engine = block_backed_engine();
        let tx = TransactionV1 {
            version: ProtocolVersion::CURRENT,
            signature_module_id: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            payment_notes: Vec::new(),
            fee_amount: 50_000,
            fee_blinding: Bytes32::from([0x44; 32]),
            fee_commitment: CommitmentV1 {
                compressed_point: Bytes32::from([0x45; 32]),
            },
            signature: HybridSignature {
                classical_sig: VariableBytes::from_slice(&[0x46; 64]).unwrap(),
                pq_sig: VariableBytes::from_slice(&[0x47; 32]).unwrap(),
            },
        };
        engine.blocks.get_mut(&1).unwrap().transactions.push(tx);
        engine
    }

    fn test_pubkey(byte: u8) -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::from([byte; 32]),
            pq_pk: VariableBytes::from_slice(&[byte; 32]).unwrap_or_default(),
        }
    }

    fn test_output(byte: u8) -> OutputV1 {
        OutputV1 {
            value_spark: 1_000_000,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from([byte; 32]),
            },
            owner_pubkey: test_pubkey(byte),
            range_proof: VariableBytes::<MAX_RANGE_PROOF_BYTES>::from_slice(&[byte; 32])
                .unwrap_or_default(),
            lock_height: 0,
        }
    }

    fn dummy_signature(byte: u8) -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[byte; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[byte; 32]).unwrap(),
        }
    }

    fn scan_keypair() -> HybridKeypair {
        let classical = ClassicalKeypair::from_seed(&[0xA5; 32]);
        let pq = PqKeypair::from_seed(&[0x5A; 32]).unwrap();
        HybridKeypair::new(classical, pq)
    }

    fn authorized_params(engine: &BlockBackedEngine, utxo_id: Bytes32) -> Vec<String> {
        let state = NodeState::read_only(engine);
        let keypair = scan_keypair();
        let public = keypair.public_key();
        let address = indra_crypto::sha256(&public.classical.0);
        let challenge = legacy_scan_challenge_bytes(address, &state);
        let msg = legacy_scan_auth_message(address, challenge);
        let sig = keypair.sign(&msg).unwrap();
        let proof = format!(
            r#"{{"version":1,"challenge":"{}","hybrid_classical_pk":"{}","hybrid_pq_pk":"{}","classical_sig":"{}","pq_sig":"{}","reserved_output_v2":null}}"#,
            hex::encode(challenge),
            hex::encode(public.classical.0),
            hex::encode(public.pq.0),
            hex::encode(sig.classical.0),
            hex::encode(sig.pq.0)
        );
        vec![
            format!(r#""{}""#, hex::encode(address)),
            proof,
            format!(r#""{}""#, hex::encode(utxo_id.0)),
        ]
    }

    fn scan_owner_pubkey() -> HybridPubKey {
        let public = scan_keypair().public_key();
        HybridPubKey {
            classical_pk: Bytes32::from(public.classical.0),
            pq_pk: VariableBytes::from_slice(&public.pq.0).unwrap(),
        }
    }

    fn owned_output(amount: u64, blinding: [u8; 32]) -> OutputV1 {
        OutputV1 {
            value_spark: amount,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from(indra_crypto::commit(amount, &blinding).0),
            },
            owner_pubkey: scan_owner_pubkey(),
            range_proof: VariableBytes::<MAX_RANGE_PROOF_BYTES>::from_slice(&[0xAA; 32]).unwrap(),
            lock_height: 0,
        }
    }

    fn explain(engine: &BlockBackedEngine, utxo_id: Bytes32) -> String {
        let params = authorized_params(engine, utxo_id);
        let state = NodeState::read_only(engine);
        explain_utxo_provenance_authorized(&params, &state).unwrap()
    }

    fn test_bond(byte: u8, compact: bool) -> StakeBondEntry {
        let utxo_id = Bytes32::from([byte; 32]);
        let validator_id = Bytes32::from([byte.wrapping_add(1); 32]);
        let delegator_id = Bytes32::from([byte.wrapping_add(2); 32]);
        let mut original_output: StakeBondOutput = test_output(byte).into();
        if compact {
            original_output.range_proof = None;
        }
        StakeBondEntry {
            utxo_id,
            validator_id,
            delegator_id,
            amount_spark: 1_000_000,
            bonded_epoch: 7,
            unbonding_end_epoch: None,
            unbonding_precision: indra_state::StakeBondUnbondingPrecision::LegacyEpochOnly,
            custody_owner: indra_state::StakeBondCustodyOwner::DelegatorIdentity(delegator_id),
            original_output,
        }
    }

    #[test]
    fn rpc_bond_status_reports_mixed_position_from_individual_bonds() {
        let mut chain = ChainState::new_genesis();
        chain.height = u64::MAX;
        let mut active = test_bond(0x91, false);
        active.amount_spark = 60;
        let mut exiting = test_bond(0x92, false);
        exiting.validator_id = active.validator_id;
        exiting.delegator_id = active.delegator_id;
        exiting.amount_spark = 40;
        exiting.unbonding_end_epoch = Some(1008);
        chain.staked_bonds.insert(active.utxo_id, active.clone());
        chain.staked_bonds.insert(exiting.utxo_id, exiting);

        assert_eq!(
            rpc_delegator_bond_status(&chain, &active.validator_id, &active.delegator_id,),
            (60, 1, 1)
        );
    }

    fn block_backed_engine() -> BlockBackedEngine {
        let mut chain = ChainState::new_genesis();
        chain.height = 2;
        let block1 = dummy_block(1, 0x11);
        let block2 = dummy_block(2, 0x22);
        chain.tip_hash = block2.header.block_hash();
        BlockBackedEngine {
            chain,
            lowest_block: 1,
            blocks: [(1, block1), (2, block2)].into_iter().collect(),
        }
    }

    #[test]
    fn explain_utxo_provenance_authorized_classifies_reward_claim() {
        let mut engine = block_backed_engine();
        let height = 2;
        let validator_id = Bytes32::from([0x31; 32]);
        let delegator_pubkey = scan_owner_pubkey();
        let delegator_id = staking_pubkey_to_id(&delegator_pubkey);
        let blinding = derive_staking_reward_blinding(&validator_id, &delegator_id, height);
        let utxo_id = engine
            .chain
            .utxos
            .insert(owned_output(7_000, blinding), height, STAKING_TX_IDX, 0)
            .unwrap();
        engine
            .blocks
            .get_mut(&height)
            .unwrap()
            .staking_ops
            .push(StakingOp {
                body: StakingOpBody::ClaimRewards {
                    validator_id,
                    delegator_pubkey,
                    cold_authorization: None,
                },
                nonce: 1,
                signature: dummy_signature(0x31),
            });

        let result = explain(&engine, utxo_id);
        assert!(
            result.contains(r#""category":"staking_reward_claim""#),
            "{result}"
        );
        assert!(result.contains(r#""recoverable":true"#), "{result}");
        assert!(result.contains(r#""claim_height":2"#), "{result}");
    }

    #[test]
    fn explain_utxo_provenance_authorized_rejects_bad_reward_derivation() {
        let mut engine = block_backed_engine();
        let height = 2;
        let validator_id = Bytes32::from([0x32; 32]);
        let delegator_pubkey = scan_owner_pubkey();
        let utxo_id = engine
            .chain
            .utxos
            .insert(owned_output(7_000, [0xFF; 32]), height, STAKING_TX_IDX, 0)
            .unwrap();
        engine
            .blocks
            .get_mut(&height)
            .unwrap()
            .staking_ops
            .push(StakingOp {
                body: StakingOpBody::ClaimRewards {
                    validator_id,
                    delegator_pubkey,
                    cold_authorization: None,
                },
                nonce: 1,
                signature: dummy_signature(0x32),
            });

        let result = explain(&engine, utxo_id);
        assert!(
            result.contains(r#""category":"staking_protocol_output_unclassified""#),
            "{result}"
        );
        assert!(result.contains(r#""recoverable":false"#), "{result}");
    }

    #[test]
    fn explain_utxo_provenance_authorized_classifies_validator_eviction_outputs() {
        let mut engine = block_backed_engine();
        let height = 2;
        let validator_id = Bytes32::from([0x41; 32]);
        let delegator_id = Bytes32::from([0x42; 32]);
        let bond_utxo_id = Bytes32::from([0x43; 32]);
        let refund_blinding = derive_compact_bond_release_blinding(
            &validator_id,
            &delegator_id,
            &bond_utxo_id,
            height,
            9_000,
        );
        let refund_utxo_id = engine
            .chain
            .utxos
            .insert(
                owned_output(9_000, refund_blinding),
                height,
                STAKING_TX_IDX,
                1,
            )
            .unwrap();
        engine
            .chain
            .delegation_return_events
            .push(DelegationReturnEvent {
                delegator_id,
                validator_id,
                bond_utxo_id,
                amount_spark: 9_000,
                reason: DelegationReturnReason::ValidatorEvicted,
                returned_epoch: 0,
                returned_height: height,
                refund_utxo_id,
            });

        let reward_blinding = derive_staking_reward_blinding(&validator_id, &delegator_id, height);
        let reward_utxo_id = engine
            .chain
            .utxos
            .insert(
                owned_output(1_000, reward_blinding),
                height,
                STAKING_TX_IDX,
                2,
            )
            .unwrap();

        let refund = explain(&engine, refund_utxo_id);
        assert!(
            refund.contains(r#""category":"validator_eviction_bond_refund""#),
            "{refund}"
        );
        assert!(refund.contains(r#""recoverable":true"#), "{refund}");

        let reward = explain(&engine, reward_utxo_id);
        assert!(
            reward.contains(r#""category":"validator_eviction_pending_reward""#),
            "{reward}"
        );
        assert!(reward.contains(r#""recoverable":true"#), "{reward}");
    }

    #[test]
    fn explain_utxo_provenance_authorized_classifies_normal_matured_release() {
        let mut engine = block_backed_engine();
        let height = 2;
        let validator_id = Bytes32::from([0x49; 32]);
        let delegator_id = Bytes32::from([0x4A; 32]);
        let bond_utxo_id = Bytes32::from([0x4B; 32]);
        let amount = 9_000;
        let blinding = derive_normal_bond_release_blinding(
            &validator_id,
            &delegator_id,
            &bond_utxo_id,
            height,
            amount,
        );
        let refund_utxo_id = engine
            .chain
            .utxos
            .insert(owned_output(amount, blinding), height, STAKING_TX_IDX, 1)
            .unwrap();
        engine
            .chain
            .delegation_return_events
            .push(DelegationReturnEvent {
                delegator_id,
                validator_id,
                bond_utxo_id,
                amount_spark: amount,
                reason: DelegationReturnReason::UnbondingMatured,
                returned_epoch: 0,
                returned_height: height,
                refund_utxo_id,
            });

        let result = explain(&engine, refund_utxo_id);

        assert!(
            result.contains(r#""category":"normal_bond_release""#),
            "{result}"
        );
        assert!(result.contains(r#""recoverable":true"#), "{result}");
        assert!(
            result.contains(r#""derivation":"normal_bond_release""#),
            "{result}"
        );
        assert!(
            result.contains(&format!(
                r#""bond_utxo_id":"{}""#,
                hex::encode(bond_utxo_id.0)
            )),
            "{result}"
        );
    }

    #[test]
    fn explain_utxo_provenance_authorized_mixed_normal_release_adversarial_block() {
        let mut engine = block_backed_engine();
        let height = 2;
        let validator_id = Bytes32::from([0x54; 32]);
        let delegator_id = Bytes32::from([0x55; 32]);
        let bond_utxo_id = Bytes32::from([0x56; 32]);
        let amount = 9_000;
        let blinding = derive_normal_bond_release_blinding(
            &validator_id,
            &delegator_id,
            &bond_utxo_id,
            height,
            amount,
        );
        let refund_utxo_id = engine
            .chain
            .utxos
            .insert(owned_output(amount, blinding), height, STAKING_TX_IDX, 1)
            .unwrap();
        engine
            .chain
            .delegation_return_events
            .push(DelegationReturnEvent {
                delegator_id,
                validator_id,
                bond_utxo_id,
                amount_spark: amount,
                reason: DelegationReturnReason::UnbondingMatured,
                returned_epoch: 0,
                returned_height: height,
                refund_utxo_id,
            });

        let wrong_bond_utxo_id = Bytes32::from([0x57; 32]);
        let malformed_blinding = derive_normal_bond_release_blinding(
            &validator_id,
            &delegator_id,
            &bond_utxo_id,
            height,
            amount,
        );
        let malformed_utxo_id = engine
            .chain
            .utxos
            .insert(
                owned_output(amount, malformed_blinding),
                height,
                STAKING_TX_IDX,
                2,
            )
            .unwrap();
        engine
            .chain
            .delegation_return_events
            .push(DelegationReturnEvent {
                delegator_id,
                validator_id,
                bond_utxo_id: wrong_bond_utxo_id,
                amount_spark: amount,
                reason: DelegationReturnReason::UnbondingMatured,
                returned_epoch: 0,
                returned_height: height,
                refund_utxo_id: malformed_utxo_id,
            });

        let unrelated_utxo_id = engine
            .chain
            .utxos
            .insert(owned_output(7_000, [0x58; 32]), height, STAKING_TX_IDX, 3)
            .unwrap();

        let recovered = explain(&engine, refund_utxo_id);
        assert!(
            recovered.contains(r#""category":"normal_bond_release""#),
            "{recovered}"
        );
        assert!(recovered.contains(r#""recoverable":true"#), "{recovered}");
        assert!(
            recovered.contains(&format!(r#""utxo_id":"{}""#, hex::encode(refund_utxo_id.0))),
            "{recovered}"
        );

        let rejected = explain(&engine, malformed_utxo_id);
        assert!(
            rejected.contains(r#""category":"normal_bond_release""#),
            "{rejected}"
        );
        assert!(rejected.contains(r#""recoverable":false"#), "{rejected}");
        assert!(
            rejected.contains("matured bond release provenance did not open"),
            "{rejected}"
        );

        let unclassified = explain(&engine, unrelated_utxo_id);
        assert!(
            unclassified.contains(r#""category":"staking_protocol_output_unclassified""#),
            "{unclassified}"
        );
        assert!(
            unclassified.contains(r#""recoverable":false"#),
            "{unclassified}"
        );
    }

    #[test]
    fn explain_utxo_provenance_authorized_does_not_misclassify_pre_gate_matured_release() {
        let mut engine = block_backed_engine();
        let height = 2;
        let validator_id = Bytes32::from([0x4C; 32]);
        let delegator_id = Bytes32::from([0x4D; 32]);
        let bond_utxo_id = Bytes32::from([0x4E; 32]);
        let amount = 9_000;
        let blinding = derive_normal_bond_release_blinding(
            &validator_id,
            &delegator_id,
            &bond_utxo_id,
            height,
            amount,
        );
        let refund_utxo_id = engine
            .chain
            .utxos
            .insert(owned_output(amount, blinding), height, STAKING_TX_IDX, 1)
            .unwrap();

        let result = explain(&engine, refund_utxo_id);

        assert!(
            result.contains(r#""category":"staking_protocol_output_unclassified""#),
            "{result}"
        );
        assert!(result.contains(r#""recoverable":false"#), "{result}");
        assert!(
            !result.contains(r#""category":"normal_bond_release""#),
            "{result}"
        );
    }

    #[test]
    fn explain_utxo_provenance_authorized_reports_slashed_self_stake_release_unrecoverable() {
        let mut engine = block_backed_engine();
        let height = 2;
        let validator_id = Bytes32::from([0x51; 32]);
        let bond_utxo_id = Bytes32::from([0x52; 32]);
        let blinding = derive_slashed_self_stake_blinding(&validator_id, &bond_utxo_id, height);
        let utxo_id = engine
            .chain
            .utxos
            .insert(owned_output(3_000, blinding), height, STAKING_TX_IDX, 1)
            .unwrap();

        let result = explain(&engine, utxo_id);
        assert!(
            result.contains(r#""category":"staking_protocol_output_unclassified""#),
            "{result}"
        );
        assert!(result.contains(r#""recoverable":false"#), "{result}");
    }

    #[test]
    fn explain_utxo_provenance_authorized_classifies_slash_reporter_reward() {
        let mut engine = block_backed_engine();
        let height = 2;
        let evidence = SlashEvidenceV1 {
            validator_id: Bytes32::from([0x61; 32]),
            vote_1: VoteV1 {
                height: 9,
                round: 0,
                step: VoteStep::Precommit,
                block_hash: Bytes32::from([0x62; 32]),
                validator_id: Bytes32::from([0x61; 32]),
                election_result_hash: None,
                signature: dummy_signature(0x63),
            },
            vote_2: VoteV1 {
                height: 9,
                round: 0,
                step: VoteStep::Precommit,
                block_hash: Bytes32::from([0x64; 32]),
                validator_id: Bytes32::from([0x61; 32]),
                election_result_hash: None,
                signature: dummy_signature(0x65),
            },
        };
        let evidence_hash = Bytes32::from(indra_crypto::sha256(&evidence.encode_to_vec()));
        let blinding = derive_slash_reward_blinding(&evidence_hash, height);
        let utxo_id = engine
            .chain
            .utxos
            .insert(owned_output(2_000, blinding), height, STAKING_TX_IDX, 0)
            .unwrap();
        engine
            .blocks
            .get_mut(&height)
            .unwrap()
            .slashing_evidence
            .push(evidence);

        let result = explain(&engine, utxo_id);
        assert!(
            result.contains(r#""category":"slash_reporter_reward""#),
            "{result}"
        );
        assert!(result.contains(r#""recoverable":true"#), "{result}");
        assert!(result.contains(r#""evidence_hash":"#), "{result}");
    }

    #[test]
    fn explain_utxo_provenance_authorized_classifies_governance_change_and_refund() {
        let mut engine = block_backed_engine();
        let height = 2;
        let owner = scan_owner_pubkey();
        let proposer_id = Bytes32::from(indra_crypto::sha256(&owner.classical_pk.0));
        let action = GovernableAction::SetMinDelegationSpark { value: 44 };
        let proposed_epoch = epoch_for_height(height);
        let proposal_id =
            compute_proposal_id(proposer_id, &action, proposed_epoch, &engine.chain.chain_id);
        let change_blinding = derive_governance_change_blinding(&proposal_id);
        let change_utxo_id = engine
            .chain
            .utxos
            .insert(owned_output(500, change_blinding), height, u32::MAX - 3, 0)
            .unwrap();
        engine
            .blocks
            .get_mut(&height)
            .unwrap()
            .governance_ops
            .push(GovernanceOpV2 {
                action_type: GovernanceActionType::ProposeChange,
                signer_id: proposer_id,
                nonce: 1,
                payload: GovernancePayload::Propose {
                    action: action.clone(),
                    deposit_utxo_id: Bytes32::from([0x71; 32]),
                    proposer_pubkey: owner.clone(),
                    title: VariableBytes::from_slice(b"title").unwrap(),
                    description: VariableBytes::from_slice(b"description").unwrap(),
                    cold_authorization: None,
                },
                signature: dummy_signature(0x72),
            });

        engine.chain.governance.proposals.insert(
            proposal_id,
            ProposalRecord {
                proposal_id,
                proposer_id,
                proposer_pubkey: owner,
                tier: ProposalTier::Standard,
                action,
                title: "title".into(),
                description: "description".into(),
                deposit_spark: 0,
                deposit_burned: false,
                proposed_epoch,
                commit_start_epoch: proposed_epoch,
                reveal_start_epoch: proposed_epoch + 1,
                tally_epoch: proposed_epoch + 2,
                exec_delay_epochs: 0,
                executable_after_epoch: proposed_epoch + 2,
                phase: ProposalPhase::Executed,
                snapshot1: None,
                commits: BTreeMap::new(),
                reveals: BTreeMap::new(),
                redelegations: Vec::new(),
                redelegated_delegators: BTreeMap::new(),
                snapshot2: None,
                yes_stake: 0,
                no_stake: 0,
                abstain_stake: 0,
                passed: Some(true),
            },
        );
        let refund_blinding = derive_governance_refund_blinding(&proposal_id);
        let refund_utxo_id = engine
            .chain
            .utxos
            .insert(
                owned_output(10_000, refund_blinding),
                height,
                u32::MAX - 2,
                0,
            )
            .unwrap();

        let change = explain(&engine, change_utxo_id);
        assert!(
            change.contains(r#""category":"governance_deposit_change""#),
            "{change}"
        );
        assert!(change.contains(r#""recoverable":true"#), "{change}");

        let refund = explain(&engine, refund_utxo_id);
        assert!(
            refund.contains(r#""category":"governance_deposit_refund""#),
            "{refund}"
        );
        assert!(refund.contains(r#""recoverable":true"#), "{refund}");
    }

    #[test]
    fn explain_utxo_provenance_authorized_reports_legacy_bond_release_unrecoverable() {
        let mut engine = block_backed_engine();
        let height = 2;
        let validator_id = Bytes32::from([0x81; 32]);
        let delegator_id = Bytes32::from([0x82; 32]);
        let bond_utxo_id = Bytes32::from([0x83; 32]);
        let utxo_id = engine
            .chain
            .utxos
            .insert(owned_output(9_000, [0x84; 32]), height, STAKING_TX_IDX, 1)
            .unwrap();
        engine
            .chain
            .delegation_return_events
            .push(DelegationReturnEvent {
                delegator_id,
                validator_id,
                bond_utxo_id,
                amount_spark: 9_000,
                reason: DelegationReturnReason::ValidatorEvicted,
                returned_epoch: 0,
                returned_height: height,
                refund_utxo_id: utxo_id,
            });

        let result = explain(&engine, utxo_id);
        assert!(
            result.contains(r#""category":"legacy_bond_release""#),
            "{result}"
        );
        assert!(result.contains(r#""recoverable":false"#), "{result}");
        assert!(
            result.contains("local wallet history or an archive/indexer"),
            "{result}"
        );
    }

    #[test]
    fn explain_utxo_provenance_authorized_does_not_misclassify_ordinary_utxo() {
        let mut engine = block_backed_engine();
        let utxo_id = engine
            .chain
            .utxos
            .insert(owned_output(1_234, [0x91; 32]), 2, 0, 0)
            .unwrap();

        let result = explain(&engine, utxo_id);
        assert!(
            result.contains(r#""category":"ordinary_transaction_output""#),
            "{result}"
        );
        assert!(result.contains(r#""recoverable":false"#), "{result}");
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
    fn get_block_returns_requested_historical_height_not_tip() {
        let engine = block_backed_engine();
        let state = NodeState::read_only(&engine);
        let result = get_block(&["1".to_string()], &state).unwrap();
        let expected_hash = hex::encode(engine.blocks[&1].header.block_hash().0);
        let tip_hash = hex::encode(engine.blocks[&2].header.block_hash().0);
        assert!(result.contains(r#""height":1"#), "{result}");
        assert!(result.contains(&format!(r#""block_hash":"{expected_hash}""#)));
        assert!(result.contains(r#""timestamp":1700000001"#));
        assert!(result.contains(&format!(r#""state_root":"{}""#, "11".repeat(32))));
        assert!(
            !result.contains(&tip_hash),
            "returned current tip instead of requested block: {result}"
        );
        assert!(!result.contains("full block retrieval added in Phase 8"));
    }

    #[test]
    fn get_block_same_height_is_stable() {
        let engine = block_backed_engine();
        let state = NodeState::read_only(&engine);
        let first = get_block(&["1".to_string()], &state).unwrap();
        let second = get_block(&["1".to_string()], &state).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn canonical_block_range_returns_full_blocks_and_rejects_wrong_anchor() {
        assert!(rpc_method_is_read_only("indra_getCanonicalBlocks"));
        let engine = block_backed_engine();
        let state = NodeState::read_only(&engine);
        let result = get_canonical_blocks(
            &[
                "1".to_string(),
                "2".to_string(),
                format!("\"{}\"", "10".repeat(32)),
            ],
            &state,
        )
        .unwrap();
        assert!(result.contains(&hex::encode(engine.blocks[&1].encode_to_vec())));
        assert!(result.contains(&hex::encode(engine.blocks[&2].encode_to_vec())));
        assert!(result.contains(r#""tip_height":2"#));
        assert!(result.contains(r#""next_height":null"#));

        let error = get_canonical_blocks(
            &[
                "1".to_string(),
                "2".to_string(),
                format!("\"{}\"", "ff".repeat(32)),
            ],
            &state,
        )
        .unwrap_err();
        assert!(
            matches!(error, RpcError::InvalidParams(message) if message.contains("canonical parent mismatch"))
        );
    }

    #[test]
    fn get_block_below_retention_window_has_specific_error() {
        let engine = block_backed_engine();
        let state = NodeState::read_only(&engine);
        let result = get_block(&["0".to_string()], &state);
        match result {
            Err(RpcError::NotFound(message)) => {
                assert!(message.contains("below the local retention window"));
                assert!(message.contains("lowest available block is 1"));
            }
            other => panic!("expected retention-window NotFound, got {other:?}"),
        }
    }

    #[test]
    fn get_block_above_tip_has_distinct_error() {
        let engine = block_backed_engine();
        let state = NodeState::read_only(&engine);
        let result = get_block(&["3".to_string()], &state);
        match result {
            Err(RpcError::NotFound(message)) => {
                assert!(message.contains("exceeds current tip 2"));
                assert!(!message.contains("retention window"));
            }
            other => panic!("expected above-tip NotFound, got {other:?}"),
        }
    }

    #[test]
    fn get_transaction_returns_canonical_transaction_hex() {
        assert!(rpc_method_is_read_only("indra_getTransaction"));
        assert_eq!(
            crate::server::rpc_method_cost("indra_getTransaction"),
            crate::server::RpcMethodCost::Cheap
        );
        let engine = block_with_transaction();
        let state = NodeState::read_only(&engine);
        let result = get_transaction(&["1".to_string(), "0".to_string()], &state).unwrap();
        let expected = hex::encode(engine.blocks[&1].transactions[0].encode_to_vec());
        assert!(result.contains(r#""height":1"#), "{result}");
        assert!(result.contains(r#""tx_index":0"#), "{result}");
        assert!(result.contains(&format!(r#""tx_hex":"{expected}""#)));
    }

    #[test]
    fn get_block_current_tip_height_matches_chain_info_height() {
        let engine = block_backed_engine();
        let state = NodeState::read_only(&engine);
        let block = get_block(&["2".to_string()], &state).unwrap();
        let chain_info = get_chain_info(&state).unwrap();
        assert!(block.contains(r#""height":2"#));
        assert!(chain_info.contains(r#""height":2"#));
        let expected_hash = hex::encode(engine.blocks[&2].header.block_hash().0);
        assert!(block.contains(&format!(r#""block_hash":"{expected_hash}""#)));
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
                    cold_hybrid_classical_pk: (byte == 0x31).then_some([0x51; 32]),
                    cold_hybrid_pq_pk: (byte == 0x31).then_some([0x52; indra_crypto::PQ_PK_BYTES]),
                    cold_key_version: u64::from(byte == 0x31),
                    cold_key_status: if byte == 0x31 {
                        indra_state::ColdKeyStatus::Active
                    } else {
                        indra_state::ColdKeyStatus::Unenrolled
                    },
                    cold_nonce: if byte == 0x31 { 9 } else { 0 },
                })
                .unwrap();
        }
        let state = NodeState::read_only(&engine);
        let result = get_validator_set(&state).unwrap();

        assert!(result.contains(r#""network_addr":"203.0.113.31:30303""#));
        assert!(result.contains(r#""network_addr":null"#));
        assert!(result.contains(&format!(
            r#""cold_hybrid_classical_pk":"{}""#,
            hex::encode([0x51; 32])
        )));
        assert!(result.contains(r#""cold_key_version":1"#));
        assert!(result.contains(r#""cold_key_status":"active""#));
        assert!(result.contains(r#""cold_nonce":9"#));
        assert!(result.contains(r#""cold_hybrid_classical_pk":null"#));
        assert!(result.contains(r#""cold_key_status":"unenrolled""#));
    }

    #[test]
    fn rpc_exposes_delegation_return_events_for_delegator() {
        let mut engine = make_state("dre");
        let delegator_id = indra_core::Bytes32::from([0x41; 32]);
        let validator_id = indra_core::Bytes32::from([0x42; 32]);
        engine.push_delegation_return_event(indra_state::DelegationReturnEvent {
            delegator_id,
            validator_id,
            bond_utxo_id: indra_core::Bytes32::from([0x43; 32]),
            amount_spark: 123,
            reason: indra_state::DelegationReturnReason::ValidatorEvicted,
            returned_epoch: 7,
            returned_height: 2_100,
            refund_utxo_id: indra_core::Bytes32::from([0x44; 32]),
        });
        engine.push_delegation_return_event(indra_state::DelegationReturnEvent {
            delegator_id: indra_core::Bytes32::from([0x45; 32]),
            validator_id,
            bond_utxo_id: indra_core::Bytes32::from([0x46; 32]),
            amount_spark: 456,
            reason: indra_state::DelegationReturnReason::ValidatorEvicted,
            returned_epoch: 8,
            returned_height: 2_400,
            refund_utxo_id: indra_core::Bytes32::from([0x47; 32]),
        });
        let state = NodeState::read_only(&engine);
        let result = get_delegation_return_events(
            &[hex::encode(delegator_id.0), "0".into(), "10".into()],
            &state,
        )
        .unwrap();

        assert!(result.contains(r#""reason":"ValidatorEvicted""#));
        assert!(result.contains(r#""amount_spark":123"#));
        assert!(result.contains(r#""count":1"#));
        assert!(!result.contains(r#""amount_spark":456"#));
    }

    #[test]
    fn stake_bond_debug_reports_legacy_and_compact_without_sensitive_material() {
        let mut engine = make_state("sbd");
        let legacy = test_bond(0x51, false);
        let compact = test_bond(0x61, true);
        let mut fully_compact = test_bond(0x71, true);
        fully_compact.original_output.owner_pubkey = None;
        let legacy_id = legacy.utxo_id;
        let compact_id = compact.utxo_id;
        let fully_compact_id = fully_compact.utxo_id;
        engine.staked_bonds.insert(legacy_id, legacy);
        engine.staked_bonds.insert(compact_id, compact);
        engine.staked_bonds.insert(fully_compact_id, fully_compact);
        let state = NodeState::read_only(&engine);

        let legacy_result = get_stake_bond_debug(&[hex::encode(legacy_id.0)], &state).unwrap();
        assert!(
            legacy_result.contains(&format!(r#""bond_utxo_id":"{}""#, hex::encode(legacy_id.0)))
        );
        assert!(legacy_result.contains(r#""compact":false"#));
        assert!(legacy_result.contains(r#""has_range_proof":true"#));
        assert!(legacy_result.contains(r#""has_owner_pubkey":true"#));
        assert!(legacy_result.contains(r#""bonded_epoch":7"#));
        assert!(legacy_result.contains(&format!(r#""validator_id":"{}""#, hex::encode([0x52; 32]))));
        assert!(legacy_result.contains(&format!(r#""delegator_id":"{}""#, hex::encode([0x53; 32]))));
        assert!(!legacy_result.contains("commitment"));
        assert!(!legacy_result.contains("classical_pk"));
        assert!(!legacy_result.contains("pq_pk"));

        let compact_result = get_stake_bond_debug(&[hex::encode(compact_id.0)], &state).unwrap();
        assert!(compact_result.contains(r#""compact":true"#));
        assert!(compact_result.contains(r#""has_range_proof":false"#));
        assert!(compact_result.contains(r#""has_owner_pubkey":true"#));
        assert!(!compact_result.contains("commitment"));
        assert!(!compact_result.contains("classical_pk"));
        assert!(!compact_result.contains("pq_pk"));

        let fully_compact_result =
            get_stake_bond_debug(&[hex::encode(fully_compact_id.0)], &state).unwrap();
        assert!(fully_compact_result.contains(r#""compact":true"#));
        assert!(fully_compact_result.contains(r#""has_range_proof":false"#));
        assert!(fully_compact_result.contains(r#""has_owner_pubkey":false"#));
        assert!(!fully_compact_result.contains("commitment"));
        assert!(!fully_compact_result.contains("classical_pk"));
        assert!(!fully_compact_result.contains("pq_pk"));
    }

    #[test]
    fn delegator_identity_debug_reports_absent_or_registered_pubkey() {
        let mut engine = make_state("did");
        let delegator_id = Bytes32::from([0x91; 32]);
        let pubkey = HybridPubKey {
            classical_pk: Bytes32::from([0x92; 32]),
            pq_pk: VariableBytes::from_slice(&[0x93; 32]).unwrap(),
        };
        let state = NodeState::read_only(&engine);
        assert_eq!(
            get_delegator_identity_debug(&[hex::encode(delegator_id.0)], &state).unwrap(),
            format!(
                r#"{{"delegator_id":"{}","exists":false,"pubkey":null}}"#,
                hex::encode(delegator_id.0)
            )
        );

        engine
            .delegator_identities
            .insert(delegator_id, pubkey.clone());
        let state = NodeState::read_only(&engine);
        let result = get_delegator_identity_debug(&[hex::encode(delegator_id.0)], &state).unwrap();
        assert!(result.contains(&format!(
            r#""delegator_id":"{}""#,
            hex::encode(delegator_id.0)
        )));
        assert!(result.contains(r#""exists":true"#));
        assert!(result.contains(&format!(
            r#""classical_pk":"{}""#,
            hex::encode(pubkey.classical_pk.0)
        )));
        assert!(result.contains(&format!(
            r#""pq_pk":"{}""#,
            hex::encode(pubkey.pq_pk.as_slice())
        )));
        assert!(!result.contains("range_proof"));
        assert!(!result.contains("commitment"));
    }

    #[test]
    fn delegator_identity_debug_is_admin_gated() {
        let engine = make_state("did-admin");
        let state = NodeState::read_only(&engine);
        let params = [hex::encode([0x94; 32])];

        let read_only = dispatch_with_admin(
            "indra_getDelegatorIdentityDebug",
            &params,
            &state,
            RpcMode::ReadOnly,
            true,
            true,
        );
        assert!(matches!(
            read_only,
            DispatchResult::Ready(Err(RpcError::Forbidden(_)))
        ));

        let no_token = dispatch_with_admin(
            "indra_getDelegatorIdentityDebug",
            &params,
            &state,
            RpcMode::Full,
            false,
            false,
        );
        assert!(matches!(
            no_token,
            DispatchResult::Ready(Err(RpcError::Forbidden(_)))
        ));

        let admin = dispatch_with_admin(
            "indra_getDelegatorIdentityDebug",
            &params,
            &state,
            RpcMode::Full,
            true,
            true,
        );
        assert!(matches!(
            admin,
            DispatchResult::Ready(Ok(result)) if result.contains(r#""exists":false"#)
        ));
    }

    #[test]
    fn stake_bond_debug_is_admin_gated() {
        let mut engine = make_state("sbd-admin");
        let legacy = test_bond(0x71, false);
        let legacy_id = legacy.utxo_id;
        engine.staked_bonds.insert(legacy_id, legacy);
        let state = NodeState::read_only(&engine);
        let params = [hex::encode(legacy_id.0)];

        let read_only = dispatch_with_admin(
            "indra_getStakeBondDebug",
            &params,
            &state,
            RpcMode::ReadOnly,
            true,
            true,
        );
        assert!(matches!(
            read_only,
            DispatchResult::Ready(Err(RpcError::Forbidden(_)))
        ));

        let no_token = dispatch_with_admin(
            "indra_getStakeBondDebug",
            &params,
            &state,
            RpcMode::Full,
            false,
            false,
        );
        assert!(matches!(
            no_token,
            DispatchResult::Ready(Err(RpcError::Forbidden(_)))
        ));

        let admin = dispatch_with_admin(
            "indra_getStakeBondDebug",
            &params,
            &state,
            RpcMode::Full,
            true,
            true,
        );
        assert!(matches!(
            admin,
            DispatchResult::Ready(Ok(result)) if result.contains(r#""compact":false"#)
        ));
    }

    #[test]
    fn consensus_snapshot_observability_is_admin_gated_and_reports_retained_authority() {
        let mut engine = make_state("consensus-snapshot-admin");
        let classical = ClassicalKeypair::from_seed(&[0xA1; 32]);
        let pq = PqKeypair::from_seed(&[0xA2; 32]).unwrap();
        let public = HybridKeypair::new(classical, pq).public_key();
        let vrf = VrfKeypair::from_seed(&[0xA3; 32]);
        let entry = |weight| {
            ConsensusSnapshotEntry::new(
                Bytes32::from([0xA0; 32]),
                weight,
                public.classical.0,
                public.pq.0,
                vrf.public_key(),
            )
            .unwrap()
        };
        let previous = ConsensusSnapshot::new(601, 600, vec![entry(2_000_000_000)]).unwrap();
        let current = ConsensusSnapshot::new(901, 900, vec![entry(3_000_000_000)]).unwrap();
        let previous_root = hex::encode(previous.snapshot_root.0);
        let current_root = hex::encode(current.snapshot_root.0);
        engine.height = 950;
        engine.consensus_snapshots = vec![previous, current];
        let state = NodeState::read_only(&engine);

        assert!(matches!(
            dispatch_with_admin(
                "indra_getConsensusSnapshots",
                &[],
                &state,
                RpcMode::ReadOnly,
                true,
                true,
            ),
            DispatchResult::Ready(Err(RpcError::Forbidden(_)))
        ));
        assert!(matches!(
            dispatch_with_admin(
                "indra_getConsensusSnapshots",
                &[],
                &state,
                RpcMode::Full,
                false,
                false,
            ),
            DispatchResult::Ready(Err(RpcError::Forbidden(_)))
        ));

        let result = dispatch_with_admin(
            "indra_getConsensusSnapshots",
            &[],
            &state,
            RpcMode::Full,
            true,
            true,
        );
        let DispatchResult::Ready(Ok(json)) = result else {
            panic!("admin snapshot query must succeed");
        };
        assert!(json.contains(r#""activation_height":901"#));
        assert!(json.contains(r#""activation_height":601"#));
        assert!(json.contains(&current_root));
        assert!(json.contains(&previous_root));
        assert!(json.contains(r#""member_count":1"#));
        assert!(json.contains(r#""total_weight_spark":3000000000"#));
        assert!(json.contains(r#""next_scheduled_boundary_height":1200"#));
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
                cold_hybrid_classical_pk: None,
                cold_hybrid_pq_pk: None,
                cold_key_version: 0,
                cold_key_status: indra_state::ColdKeyStatus::Unenrolled,
                cold_nonce: 0,
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
                cold_hybrid_classical_pk: None,
                cold_hybrid_pq_pk: None,
                cold_key_version: 0,
                cold_key_status: indra_state::ColdKeyStatus::Unenrolled,
                cold_nonce: 0,
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
