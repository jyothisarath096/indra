//! INDRA v2 node binary.
//!
//! Networking runs on a Tokio runtime with authenticated encrypted transport.
//! Consensus and state transition logic remain synchronous on dedicated threads.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex, RwLock,
};
use std::time::{Duration, Instant};

use fs2::available_space;
use indra_core::codec::Encode;
use indra_core::types::primitives::{
    DEFAULT_PRUNE_KEEP_BLOCKS, DISK_CRITICAL_THRESHOLD_BYTES, DISK_WARN_THRESHOLD_BYTES,
    DNS_SEED_HOSTS, MAX_INBOUND_PEERS, MAX_OBSERVER_CONNECTIONS, MAX_PEER_LIST_SIZE,
    MIN_PRUNE_KEEP_BLOCKS, OBSERVER_PORT, PEER_LIST_INTERVAL_SECS, PEER_TABLE_SAVE_INTERVAL_SECS,
    TARGET_OUTBOUND_PEERS,
};
use indra_crypto::sha256;
use indra_crypto::{PqKeypair, PqPublicKey};
use indra_network::{
    message::{Message, PeerListEntry},
    observer::NODE_TYPE_FULL,
    perform_handshake_initiator, perform_handshake_responder, perform_observer_handshake_responder,
    read_frame_plain_limited, spawn_peer_manager, write_frame_plain, HandshakeConfig,
    NetworkCommand, NetworkEvent, ObserverFrameLimiter, PeerManagerConfig, PeerManagerHandle,
    RelayValidatorKey, TokenBucket,
};
use indra_node::{
    config::{default_governance_mempool_capacity, DEFAULT_STAKING_MEMPOOL_CAPACITY},
    discovery::{
        default_dns_seed_hosts_config, load_peers, peer_list_payload,
        resolve_dns_seeds_with_policies_and_replay_store, resolve_peer_addr, sanitize_loaded_peers,
        save_peers, signed_dns_replay_state_path, DnsSeedValidationMode,
        SignedDnsSeedValidationMode,
    },
    driver::{ConsensusDriver, DriverAction, DriverEvent, RoundPhase},
    genesis::load_genesis_seed_peers,
    metrics::{record_block_commit, DEFAULT_METRICS_ADDR},
    net_driver::{action_to_message, message_to_event},
    sync::SYNC_BATCH_SIZE,
    KeysData, MetricsState, NodeConfig, NodeConfigFile, NodeEngine,
};
use tokio::runtime::Builder as TokioRuntimeBuilder;
use tokio::sync::mpsc as tokio_mpsc;

const PROPOSE_TIMEOUT: Duration = Duration::from_secs(8);
const PREVOTE_TIMEOUT: Duration = Duration::from_secs(3);
const PRECOMMIT_TIMEOUT: Duration = Duration::from_secs(3);
const MIN_BLOCK_INTERVAL_SECS: u64 = 6;
const DIAL_RETRY: Duration = Duration::from_secs(5);
const STATUS_INTERVAL: Duration = Duration::from_secs(6);
const PROPOSAL_FAILURE_BACKOFF: Duration = Duration::from_secs(1);
const MAX_DISCOVERED_PEERS: usize = 256;
const OP_RELAY_SEEN_CAPACITY: usize = 16_384;
const OBSERVER_REQUEST_BLOCKS_RATE: u64 = 2;
const OBSERVER_REQUEST_BLOCKS_BURST: u64 = 4;
const MAX_INBOUND_PER_IP: u8 = 3;
const MAX_DIAL_FAILURES_BEFORE_EVICTION: u32 = 20;
const MAX_RPC_CONNECTIONS: u64 = indra_rpc::server::MAX_RPC_CONNECTIONS;

#[derive(Debug, Clone)]
struct RpcListenerPolicy {
    per_ip_rate_per_sec: u64,
    per_ip_burst: u64,
    global_rate_per_sec: Option<u64>,
    global_burst: Option<u64>,
    max_body_bytes: usize,
    request_timeout: Duration,
}

impl RpcListenerPolicy {
    fn full() -> Self {
        Self {
            per_ip_rate_per_sec: indra_rpc::server::RPC_RATE_LIMIT_PER_SEC,
            per_ip_burst: indra_rpc::server::RPC_RATE_BURST,
            global_rate_per_sec: None,
            global_burst: None,
            max_body_bytes: indra_rpc::server::MAX_RPC_BODY_BYTES,
            request_timeout: indra_rpc::server::RPC_REQUEST_TIMEOUT,
        }
    }

    fn public_from_config(cfg: &NodeConfigFile) -> Self {
        Self {
            per_ip_rate_per_sec: cfg
                .rpc_public_per_ip_rate_per_sec
                .unwrap_or(indra_rpc::server::RPC_PUBLIC_RATE_LIMIT_PER_SEC),
            per_ip_burst: cfg
                .rpc_public_per_ip_burst
                .unwrap_or(indra_rpc::server::RPC_PUBLIC_RATE_BURST),
            global_rate_per_sec: Some(
                cfg.rpc_public_global_rate_per_sec
                    .unwrap_or(indra_rpc::server::RPC_PUBLIC_GLOBAL_RATE_LIMIT_PER_SEC),
            ),
            global_burst: Some(
                cfg.rpc_public_global_burst
                    .unwrap_or(indra_rpc::server::RPC_PUBLIC_GLOBAL_RATE_BURST),
            ),
            max_body_bytes: cfg
                .rpc_public_max_body_bytes
                .unwrap_or(indra_rpc::server::RPC_PUBLIC_MAX_BODY_BYTES),
            request_timeout: Duration::from_millis(
                cfg.rpc_public_timeout_ms
                    .unwrap_or(indra_rpc::server::RPC_PUBLIC_REQUEST_TIMEOUT.as_millis() as u64),
            ),
        }
    }
}

#[derive(Debug, Default)]
struct RpcRejectionCounters {
    per_ip_rate_limited: AtomicU64,
    global_rate_limited: AtomicU64,
    expensive_method_limited: AtomicU64,
    auth_failures: AtomicU64,
    oversized_bodies: AtomicU64,
    timeouts_or_incomplete_reads: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProposalMode {
    None,
    Fresh,
    Reproposal,
}

fn proposer_election_for_slot(
    driver: &ConsensusDriver,
    height: u64,
    round: u32,
) -> indra_node::NodeResult<indra_consensus::proposer::ProposerElection> {
    driver.proposer_election_for_height(height, round)
}

#[derive(Clone)]
struct NetworkBridge {
    handle: PeerManagerHandle,
    peer_addrs: Arc<Mutex<HashMap<indra_core::Bytes32, SocketAddr>>>,
    addr_validators: Arc<Mutex<HashMap<SocketAddr, indra_core::Bytes32>>>,
}

impl NetworkBridge {
    fn new(
        handle: PeerManagerHandle,
        peer_addrs: Arc<Mutex<HashMap<indra_core::Bytes32, SocketAddr>>>,
        addr_validators: Arc<Mutex<HashMap<SocketAddr, indra_core::Bytes32>>>,
    ) -> Self {
        Self {
            handle,
            peer_addrs,
            addr_validators,
        }
    }

    fn broadcast(&self, msg: &Message) {
        let _ = self
            .handle
            .send_blocking(NetworkCommand::Broadcast(msg.clone()));
    }

    fn broadcast_except(&self, except: indra_core::Bytes32, msg: &Message) {
        let _ = self.handle.send_blocking(NetworkCommand::BroadcastExcept {
            except,
            msg: msg.clone(),
        });
    }

    fn send_to_validator(&self, validator_id: indra_core::Bytes32, msg: &Message) {
        let _ = self.handle.send_blocking(NetworkCommand::SendTo {
            validator_id,
            msg: msg.clone(),
        });
    }

    fn update_relay_validator_keys(&self, config: &HandshakeConfig) {
        let _ = self
            .handle
            .send_blocking(NetworkCommand::UpdateRelayValidatorKeys {
                chain_id: config.chain_id.clone(),
                validators: config.relay_validator_keys.clone(),
            });
    }

    fn disconnect_invalid_consensus_peer(&self, addr: &SocketAddr, reason: String) {
        if let Some(validator_id) = self.validator_for_addr(addr) {
            let _ = self
                .handle
                .send_blocking(NetworkCommand::DisconnectInvalidConsensusPeer {
                    validator_id,
                    reason,
                });
        }
    }

    fn connection_count(&self) -> usize {
        self.handle.connected_peer_count()
    }

    fn connected_addrs(&self) -> Vec<SocketAddr> {
        self.peer_addrs.lock().unwrap().values().copied().collect()
    }

    fn peer_topology(&self) -> Vec<indra_rpc::handlers::PeerTopologyEntry> {
        let mut peers: Vec<_> = self
            .peer_addrs
            .lock()
            .unwrap()
            .iter()
            .map(
                |(validator_id, addr)| indra_rpc::handlers::PeerTopologyEntry {
                    validator_id: Some(hex::encode(validator_id.0)),
                    address: addr.to_string(),
                },
            )
            .collect();
        peers.sort_by(|a, b| {
            a.validator_id
                .cmp(&b.validator_id)
                .then(a.address.cmp(&b.address))
        });
        peers
    }

    fn validator_for_addr(&self, addr: &SocketAddr) -> Option<indra_core::Bytes32> {
        self.addr_validators.lock().unwrap().get(addr).copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum OpRelayKey {
    Staking(indra_core::Bytes32),
    Governance(indra_core::Bytes32),
}

struct OpRelaySeenCache {
    seen: VecDeque<OpRelayKey>,
    capacity: usize,
}

impl OpRelaySeenCache {
    fn new(capacity: usize) -> Self {
        Self {
            seen: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn observe(&mut self, key: OpRelayKey) -> bool {
        if self.seen.contains(&key) {
            return false;
        }
        if self.capacity > 0 {
            if self.seen.len() >= self.capacity {
                self.seen.pop_front();
            }
            self.seen.push_back(key);
        }
        true
    }
}

fn op_relay_key(msg: &Message) -> Option<OpRelayKey> {
    match msg {
        Message::StakingOp(op) => Some(OpRelayKey::Staking(indra_core::Bytes32::from(sha256(
            &op.encode_to_vec(),
        )))),
        Message::GovernanceOp(op) => Some(OpRelayKey::Governance(indra_core::Bytes32::from(
            sha256(&op.encode_to_vec()),
        ))),
        _ => None,
    }
}

fn broadcast_locally_accepted_op(
    gossip: &NetworkBridge,
    op_relay_seen: &Mutex<OpRelaySeenCache>,
    msg: Message,
) {
    if let Some(key) = op_relay_key(&msg) {
        if let Ok(mut seen) = op_relay_seen.lock() {
            let _ = seen.observe(key);
        }
    }
    gossip.broadcast(&msg);
}

fn rebroadcast_inbound_accepted_op(
    gossip: &NetworkBridge,
    op_relay_seen: &Mutex<OpRelaySeenCache>,
    origin: indra_core::Bytes32,
    msg: Message,
) {
    if let Some(key) = op_relay_key(&msg) {
        if let Ok(mut seen) = op_relay_seen.lock() {
            if !seen.observe(key) {
                return;
            }
        } else {
            return;
        }
    }
    gossip.broadcast_except(origin, &msg);
}

fn has_connected_ip(
    connected_addrs: &Arc<Mutex<HashMap<IpAddr, usize>>>,
    addr: &SocketAddr,
) -> bool {
    connected_addrs.lock().unwrap().contains_key(&addr.ip())
}

fn has_connected_ip_from_socket_addrs(connected_addrs: &[SocketAddr], addr: &SocketAddr) -> bool {
    connected_addrs
        .iter()
        .any(|connected| connected.ip() == addr.ip())
}

fn choose_discovery_eviction_candidate(
    discovered_peers: &HashSet<String>,
    authenticated_peer_addrs: &HashSet<String>,
    bootstrap_peers: &HashSet<String>,
    genesis_peer_addrs: &HashSet<String>,
) -> Option<String> {
    let mut unauthenticated_discovered: Vec<String> = discovered_peers
        .iter()
        .filter(|peer| {
            !authenticated_peer_addrs.contains(*peer)
                && !bootstrap_peers.contains(*peer)
                && !genesis_peer_addrs.contains(*peer)
        })
        .cloned()
        .collect();
    unauthenticated_discovered.sort();
    if let Some(peer) = unauthenticated_discovered.into_iter().next() {
        return Some(peer);
    }

    let mut genesis_candidates: Vec<String> = discovered_peers
        .iter()
        .filter(|peer| {
            !authenticated_peer_addrs.contains(*peer) && !bootstrap_peers.contains(*peer)
        })
        .cloned()
        .collect();
    genesis_candidates.sort();
    genesis_candidates.into_iter().next()
}

fn insert_discovered_peer_bounded(
    discovered_peers: &mut HashSet<String>,
    authenticated_peer_addrs: &HashSet<String>,
    bootstrap_peers: &HashSet<String>,
    genesis_peer_addrs: &HashSet<String>,
    peer: String,
) -> bool {
    if discovered_peers.contains(&peer) {
        return false;
    }

    if discovered_peers.len() < MAX_DISCOVERED_PEERS {
        return discovered_peers.insert(peer);
    }

    let Some(evict) = choose_discovery_eviction_candidate(
        discovered_peers,
        authenticated_peer_addrs,
        bootstrap_peers,
        genesis_peer_addrs,
    ) else {
        return false;
    };

    discovered_peers.remove(&evict);
    discovered_peers.insert(peer)
}

fn insert_discovered_peer_if_not_self(
    discovered_peers: &mut HashSet<String>,
    authenticated_peer_addrs: &HashSet<String>,
    bootstrap_peers: &HashSet<String>,
    genesis_peer_addrs: &HashSet<String>,
    local_p2p_addr: &str,
    peer: String,
) -> bool {
    let Some(addr) = resolve_peer_addr(&peer) else {
        return false;
    };
    if is_configured_self_addr(&addr, local_p2p_addr) {
        return false;
    }
    insert_discovered_peer_bounded(
        discovered_peers,
        authenticated_peer_addrs,
        bootstrap_peers,
        genesis_peer_addrs,
        peer,
    )
}

fn bounded_discovered_peer_addrs(discovered_peers: &HashSet<String>) -> Vec<SocketAddr> {
    let mut peers: Vec<SocketAddr> = discovered_peers
        .iter()
        .filter_map(|peer| resolve_peer_addr(peer))
        .collect();
    peers.sort();
    peers.dedup();
    peers.truncate(MAX_DISCOVERED_PEERS);
    peers
}

fn reserve_inbound_connection(
    inbound_count: &AtomicU64,
    inbound_by_ip: &Mutex<HashMap<IpAddr, u8>>,
    ip: IpAddr,
) -> bool {
    let mut total = inbound_count.load(Ordering::Relaxed);
    loop {
        if total >= MAX_INBOUND_PEERS as u64 {
            return false;
        }
        match inbound_count.compare_exchange_weak(
            total,
            total + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(next_total) => total = next_total,
        }
    }

    let mut by_ip = inbound_by_ip.lock().unwrap();
    let count = by_ip.entry(ip).or_insert(0);
    if *count >= MAX_INBOUND_PER_IP {
        inbound_count.fetch_sub(1, Ordering::Relaxed);
        return false;
    }
    *count += 1;
    true
}

fn release_inbound_connection(
    inbound_count: &AtomicU64,
    inbound_by_ip: &Mutex<HashMap<IpAddr, u8>>,
    ip: IpAddr,
) {
    inbound_count.fetch_sub(1, Ordering::Relaxed);
    let mut by_ip = inbound_by_ip.lock().unwrap();
    if let Some(count) = by_ip.get_mut(&ip) {
        if *count <= 1 {
            by_ip.remove(&ip);
        } else {
            *count -= 1;
        }
    }
}

fn should_skip_dial_for_connected_validator(
    peer_addr: &str,
    authenticated_addr_validators: &HashMap<String, indra_core::Bytes32>,
    connected_validator_ids: &HashSet<indra_core::Bytes32>,
) -> bool {
    authenticated_addr_validators
        .get(peer_addr)
        .is_some_and(|validator_id| connected_validator_ids.contains(validator_id))
}

fn record_dial_failure(
    peer_addr: &str,
    discovered_peers: &mut HashSet<String>,
    retry_after: &mut HashMap<String, Instant>,
    retry_delay: &mut HashMap<String, Duration>,
    failure_counts: &mut HashMap<String, u32>,
    bootstrap_peer_addrs: &HashSet<String>,
) -> bool {
    let count = failure_counts.entry(peer_addr.to_string()).or_insert(0);
    *count = count.saturating_add(1);
    if *count < MAX_DIAL_FAILURES_BEFORE_EVICTION || bootstrap_peer_addrs.contains(peer_addr) {
        return false;
    }

    discovered_peers.remove(peer_addr);
    retry_after.remove(peer_addr);
    retry_delay.remove(peer_addr);
    failure_counts.remove(peer_addr);
    true
}

fn clear_dial_failure(peer_addr: &str, failure_counts: &mut HashMap<String, u32>) {
    failure_counts.remove(peer_addr);
}

fn is_configured_self_addr(addr: &SocketAddr, local_p2p_addr: &str) -> bool {
    resolve_peer_addr(local_p2p_addr).is_some_and(|local| *addr == local)
}

fn configured_self_addr_set(local_p2p_addr: &str) -> HashSet<SocketAddr> {
    resolve_peer_addr(local_p2p_addr).into_iter().collect()
}

fn discovery_accepts_peer_addr(
    addr: &SocketAddr,
    validator_id: Option<indra_core::Bytes32>,
    local_validator_id: indra_core::Bytes32,
    local_p2p_addr: &str,
    connected_addrs: &[SocketAddr],
) -> bool {
    if validator_id == Some(local_validator_id) {
        return false;
    }
    !is_configured_self_addr(addr, local_p2p_addr)
        && is_address_acceptable_for_discovery(addr)
        && !has_connected_ip_from_socket_addrs(connected_addrs, addr)
}

fn peer_list_payload_with_identities(
    candidates: impl IntoIterator<Item = SocketAddr>,
    own_addr: Option<SocketAddr>,
    banned: &HashSet<SocketAddr>,
    addr_validators: &HashMap<SocketAddr, indra_core::Bytes32>,
) -> Vec<PeerListEntry> {
    let mut entries = peer_list_payload(candidates, own_addr, banned);
    for entry in &mut entries {
        if let Some(addr) = resolve_peer_addr(&entry.addr) {
            entry.validator_id = addr_validators.get(&addr).copied();
        }
    }
    entries
}

fn is_address_acceptable_for_discovery(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => {
            !ip.is_loopback()
                && !ip.is_private()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_unicast_link_local()
                && !ip.is_unique_local()
        }
    }
}

fn proposal_matches_request(
    block: &indra_core::types::block::BlockV1,
    height: u64,
    round: u32,
    hash: &indra_core::Bytes32,
) -> bool {
    block.header.height == height
        && block.header.proposer_round == round
        && block.header.block_hash() == *hash
}

fn record_peer_connected_event(
    local_validator_id: indra_core::Bytes32,
    validator_id: indra_core::Bytes32,
    addr: SocketAddr,
    is_outbound: bool,
    connected_addrs: &Arc<Mutex<HashMap<IpAddr, usize>>>,
    peer_addrs: &Arc<Mutex<HashMap<indra_core::Bytes32, SocketAddr>>>,
    addr_validators: &Arc<Mutex<HashMap<SocketAddr, indra_core::Bytes32>>>,
    discovered_peers: &Arc<Mutex<HashSet<String>>>,
    authenticated_peer_addrs: &Arc<Mutex<HashSet<String>>>,
    authenticated_addr_validators: &Arc<Mutex<HashMap<String, indra_core::Bytes32>>>,
    connected_validator_ids: &Arc<Mutex<HashSet<indra_core::Bytes32>>>,
    bootstrap_peer_addrs: &HashSet<String>,
    genesis_peer_addrs: &HashSet<String>,
    retry_after: &Arc<Mutex<HashMap<String, Instant>>>,
    retry_delay: &Arc<Mutex<HashMap<String, Duration>>>,
    failure_counts: &Arc<Mutex<HashMap<String, u32>>>,
) -> bool {
    if validator_id == local_validator_id {
        eprintln!(
            "[p2p] WARNING: rejected self-connection from {} (own validator_id), not adding to peer table",
            addr
        );
        discovered_peers.lock().unwrap().remove(&addr.to_string());
        authenticated_peer_addrs
            .lock()
            .unwrap()
            .remove(&addr.to_string());
        authenticated_addr_validators
            .lock()
            .unwrap()
            .remove(&addr.to_string());
        retry_after.lock().unwrap().remove(&addr.ip().to_string());
        retry_after.lock().unwrap().remove(&addr.to_string());
        retry_delay.lock().unwrap().remove(&addr.ip().to_string());
        retry_delay.lock().unwrap().remove(&addr.to_string());
        failure_counts.lock().unwrap().remove(&addr.to_string());
        return false;
    }

    *connected_addrs
        .lock()
        .unwrap()
        .entry(addr.ip())
        .or_insert(0) += 1;
    addr_validators.lock().unwrap().insert(addr, validator_id);
    connected_validator_ids.lock().unwrap().insert(validator_id);

    // Only outbound connection addresses are dial targets. Inbound accepted
    // socket source addresses frequently contain ephemeral ports; they remain
    // live endpoints for routing/accounting via `addr_validators`, but must
    // never pollute discovery, PeerList gossip, or persisted peers.
    if is_outbound {
        peer_addrs.lock().unwrap().insert(validator_id, addr);
        authenticated_peer_addrs
            .lock()
            .unwrap()
            .insert(addr.to_string());
        authenticated_addr_validators
            .lock()
            .unwrap()
            .insert(addr.to_string(), validator_id);
        let authenticated = authenticated_peer_addrs.lock().unwrap().clone();
        insert_discovered_peer_bounded(
            &mut discovered_peers.lock().unwrap(),
            &authenticated,
            bootstrap_peer_addrs,
            genesis_peer_addrs,
            addr.to_string(),
        );
    }

    retry_after.lock().unwrap().remove(&addr.ip().to_string());
    retry_after.lock().unwrap().remove(&addr.to_string());
    retry_delay.lock().unwrap().remove(&addr.ip().to_string());
    retry_delay.lock().unwrap().remove(&addr.to_string());
    if is_outbound {
        clear_dial_failure(&addr.to_string(), &mut failure_counts.lock().unwrap());
    }
    true
}

fn peer_addresses_to_persist(
    discovered_peers: &HashSet<String>,
    peer_addrs: &HashMap<indra_core::Bytes32, SocketAddr>,
    local_p2p_addr: &str,
) -> Vec<SocketAddr> {
    let mut peers_to_save: Vec<SocketAddr> = bounded_discovered_peer_addrs(discovered_peers)
        .into_iter()
        .filter(|addr| !is_configured_self_addr(addr, local_p2p_addr))
        .collect();
    peers_to_save.extend(peer_addrs.values().copied());
    peers_to_save.retain(|addr| !is_configured_self_addr(addr, local_p2p_addr));
    peers_to_save.sort();
    peers_to_save.dedup();
    peers_to_save.truncate(MAX_DISCOVERED_PEERS);
    peers_to_save
}

fn insert_on_chain_validator_network_addrs(
    discovered_peers: &mut HashSet<String>,
    authenticated_peer_addrs: &HashSet<String>,
    bootstrap_peers: &HashSet<String>,
    genesis_peer_addrs: &HashSet<String>,
    local_p2p_addr: &str,
    local_validator_id: indra_core::Bytes32,
    connected_addrs: &[SocketAddr],
    addrs: impl IntoIterator<Item = String>,
) -> usize {
    let mut accepted = 0usize;
    for raw in addrs {
        let Some(addr) = resolve_peer_addr(&raw) else {
            continue;
        };
        if !discovery_accepts_peer_addr(
            &addr,
            None,
            local_validator_id,
            local_p2p_addr,
            connected_addrs,
        ) {
            continue;
        }
        if insert_discovered_peer_if_not_self(
            discovered_peers,
            authenticated_peer_addrs,
            bootstrap_peers,
            genesis_peer_addrs,
            local_p2p_addr,
            raw,
        ) {
            accepted = accepted.saturating_add(1);
        }
    }
    accepted
}

fn on_chain_validator_network_addrs_for_height(
    engine: &NodeEngine,
    consensus_height: u64,
) -> indra_node::NodeResult<Vec<String>> {
    Ok(engine
        .network_authority_for_height(consensus_height)?
        .into_iter()
        .filter_map(|member| member.network_addr)
        .collect())
}

fn choose_proposal_mode(
    should_propose: bool,
    valid_reproposal_available: bool,
    proposed_at_slot: Option<(u64, u32)>,
    next_height: u64,
    round: u32,
    already_have_proposal: bool,
) -> ProposalMode {
    if !should_propose {
        ProposalMode::None
    } else if valid_reproposal_available && proposed_at_slot != Some((next_height, round)) {
        ProposalMode::Reproposal
    } else if !already_have_proposal {
        ProposalMode::Fresh
    } else {
        ProposalMode::None
    }
}

fn proposal_failure_backoff_active(
    failed_at_slot: Option<((u64, u32), Instant)>,
    height: u64,
    round: u32,
) -> bool {
    failed_at_slot.is_some_and(|((h, r), at)| {
        h == height && r == round && at.elapsed() < PROPOSAL_FAILURE_BACKOFF
    })
}

fn build_handshake_config(engine: &NodeEngine) -> indra_node::NodeResult<Option<HandshakeConfig>> {
    let Some(my_validator_id) = engine.validator_id() else {
        return Ok(None);
    };
    let pq_keypair = match (
        engine.config.pq_pk.as_deref(),
        engine.config.pq_sk.as_deref(),
    ) {
        (Some(pk), Some(sk)) => match PqKeypair::from_bytes(pk, sk) {
            Ok(keypair) => keypair,
            Err(_) => return Ok(None),
        },
        _ => return Ok(None),
    };

    let consensus_height = engine.state.height.saturating_add(1);
    let authority = engine.network_authority_for_height(consensus_height)?;

    let known_validators = authority
        .iter()
        .filter_map(|member| {
            let pq_pk: [u8; indra_crypto::PQ_PK_BYTES] =
                member.hybrid_pq_pk.as_deref()?.try_into().ok()?;
            Some((member.validator_id, PqPublicKey(pq_pk)))
        })
        .collect::<Vec<_>>();
    let relay_validator_keys = authority
        .iter()
        .filter_map(|member| {
            Some(RelayValidatorKey {
                validator_id: member.validator_id,
                hybrid_classical_pk: member.hybrid_classical_pk?,
                hybrid_pq_pk: member.hybrid_pq_pk.clone()?,
                vrf_pk: member.vrf_pk,
            })
        })
        .collect::<Vec<_>>();

    Ok(Some(HandshakeConfig {
        my_validator_id,
        my_signing_key: pq_keypair,
        chain_id: engine.state.chain_id.clone(),
        known_validators,
        relay_validator_keys,
        timeout: Duration::from_secs(10),
    }))
}

fn refresh_handshake_and_relay_config(
    engine: &NodeEngine,
    config: &Arc<RwLock<HandshakeConfig>>,
    gossip: &Arc<NetworkBridge>,
) {
    match build_handshake_config(engine) {
        Ok(Some(new_config)) => {
            *config.write().unwrap() = new_config;
            gossip.update_relay_validator_keys(&config.read().unwrap());
        }
        Ok(None) => {}
        Err(error) => {
            // Snapshot lookup is authoritative post-gate. Clear remote
            // authorization rather than retaining stale or live-state keys.
            let mut current = config.write().unwrap();
            current.known_validators.clear();
            current.relay_validator_keys.clear();
            drop(current);
            gossip.update_relay_validator_keys(&config.read().unwrap());
            eprintln!(
                "[p2p] failed to resolve snapshot networking authority; remote authentication and consensus relay disabled: {error}"
            );
        }
    }
}

fn start_network_runtime(
    p2p_addr: String,
    bootstrap_peers: Vec<String>,
    initial_discovered_peers: Vec<String>,
    peers_file_path: String,
    dns_seed_host: String,
    dns_seed_validation: DnsSeedValidationMode,
    dns_seed_signed_validation: SignedDnsSeedValidationMode,
    dns_seed_signed_public_key: Option<Vec<u8>>,
    signed_dns_replay_state_path: PathBuf,
    handshake_config: Arc<RwLock<HandshakeConfig>>,
) -> (
    Arc<NetworkBridge>,
    Arc<Mutex<HashSet<String>>>,
    Arc<Mutex<HashSet<String>>>,
    std::sync::mpsc::Receiver<NetworkEvent>,
) {
    let connected_addrs = Arc::new(Mutex::new(HashMap::<std::net::IpAddr, usize>::new()));
    let peer_addrs = Arc::new(Mutex::new(HashMap::new()));
    let addr_validators = Arc::new(Mutex::new(HashMap::new()));
    let discovered_peers = Arc::new(Mutex::new(HashSet::<String>::new()));
    let authenticated_peer_addrs = Arc::new(Mutex::new(HashSet::<String>::new()));
    let authenticated_addr_validators =
        Arc::new(Mutex::new(HashMap::<String, indra_core::Bytes32>::new()));
    let connected_validator_ids = Arc::new(Mutex::new(HashSet::<indra_core::Bytes32>::new()));
    let bootstrap_peer_addrs =
        Arc::new(bootstrap_peers.iter().cloned().collect::<HashSet<String>>());
    let genesis_peer_addrs = Arc::new(
        initial_discovered_peers
            .iter()
            .cloned()
            .collect::<HashSet<String>>(),
    );
    let (event_tx, event_rx) = std::sync::mpsc::channel::<NetworkEvent>();
    let (handle_tx, handle_rx) = std::sync::mpsc::channel::<PeerManagerHandle>();
    let retry_after = Arc::new(Mutex::new(HashMap::<String, Instant>::new()));
    let retry_delay = Arc::new(Mutex::new(HashMap::<String, Duration>::new()));
    let failure_counts = Arc::new(Mutex::new(HashMap::<String, u32>::new()));
    let handshake_sem = Arc::new(tokio::sync::Semaphore::new(50));
    let inbound_count = Arc::new(AtomicU64::new(0));
    let inbound_by_ip = Arc::new(Mutex::new(HashMap::<IpAddr, u8>::new()));

    std::thread::spawn({
        let connected_addrs = Arc::clone(&connected_addrs);
        let peer_addrs = Arc::clone(&peer_addrs);
        let addr_validators = Arc::clone(&addr_validators);
        let retry_after = Arc::clone(&retry_after);
        let retry_delay = Arc::clone(&retry_delay);
        let handshake_sem = Arc::clone(&handshake_sem);
        let discovered_peers = Arc::clone(&discovered_peers);
        let authenticated_peer_addrs = Arc::clone(&authenticated_peer_addrs);
        let authenticated_addr_validators = Arc::clone(&authenticated_addr_validators);
        let connected_validator_ids = Arc::clone(&connected_validator_ids);
        let bootstrap_peer_addrs = Arc::clone(&bootstrap_peer_addrs);
        let genesis_peer_addrs = Arc::clone(&genesis_peer_addrs);
        let failure_counts = Arc::clone(&failure_counts);
        move || {
            let runtime = TokioRuntimeBuilder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");

            runtime.block_on(async move {
                let (async_event_tx, mut async_event_rx) = tokio_mpsc::channel::<NetworkEvent>(1024);
                let initial_handshake_config = handshake_config.read().unwrap().clone();
                let peer_manager = spawn_peer_manager(PeerManagerConfig {
                    local_validator_id: initial_handshake_config.my_validator_id,
                    chain_id: initial_handshake_config.chain_id,
                    relay_validator_keys: initial_handshake_config.relay_validator_keys,
                    event_tx: async_event_tx,
                    command_buffer: 1024,
                });
                let _ = handle_tx.send(peer_manager.clone());

                let network_bridge = PeerManagerHandle::clone(&peer_manager);

                tokio::spawn({
                    let connected_addrs = Arc::clone(&connected_addrs);
                    let peer_addrs = Arc::clone(&peer_addrs);
                    let addr_validators = Arc::clone(&addr_validators);
                    let retry_after = Arc::clone(&retry_after);
                    let retry_delay = Arc::clone(&retry_delay);
                    let discovered_peers = Arc::clone(&discovered_peers);
                    let authenticated_peer_addrs = Arc::clone(&authenticated_peer_addrs);
                    let authenticated_addr_validators = Arc::clone(&authenticated_addr_validators);
                    let connected_validator_ids = Arc::clone(&connected_validator_ids);
                    let bootstrap_peer_addrs = Arc::clone(&bootstrap_peer_addrs);
                    let genesis_peer_addrs = Arc::clone(&genesis_peer_addrs);
                    let failure_counts = Arc::clone(&failure_counts);
                    let handshake_config = Arc::clone(&handshake_config);
                    async move {
                        while let Some(event) = async_event_rx.recv().await {
                            match &event {
                                NetworkEvent::PeerConnected {
                                    validator_id,
                                    addr,
                                    is_outbound,
                                } => {
                                    let local_id =
                                        handshake_config.read().unwrap().my_validator_id;
                                    if !record_peer_connected_event(
                                        local_id,
                                        *validator_id,
                                        *addr,
                                        *is_outbound,
                                        &connected_addrs,
                                        &peer_addrs,
                                        &addr_validators,
                                        &discovered_peers,
                                        &authenticated_peer_addrs,
                                        &authenticated_addr_validators,
                                        &connected_validator_ids,
                                        &bootstrap_peer_addrs,
                                        &genesis_peer_addrs,
                                        &retry_after,
                                        &retry_delay,
                                        &failure_counts,
                                    ) {
                                        continue;
                                    }
                                }
                                NetworkEvent::PeerDisconnected { validator_id, addr } => {
                                    {
                                        let mut ca = connected_addrs.lock().unwrap();
                                        let count = ca.entry(addr.ip()).or_insert(0);
                                        if *count <= 1 {
                                            ca.remove(&addr.ip());
                                            retry_after.lock().unwrap().insert(addr.ip().to_string(), Instant::now() + Duration::from_secs(2));
                                            retry_delay.lock().unwrap().insert(addr.ip().to_string(), Duration::from_secs(2));
                                        } else {
                                            *count -= 1;
                                        }
                                    }
                                    peer_addrs.lock().unwrap().remove(validator_id);
                                    addr_validators.lock().unwrap().remove(addr);
                                    connected_validator_ids.lock().unwrap().remove(validator_id);
                                }
                                NetworkEvent::Message { .. } | NetworkEvent::SlashDetected(_) => {}
                            }
                            let _ = event_tx.send(event);
                        }
                    }
                });

                tokio::spawn({
                    let handshake_config = Arc::clone(&handshake_config);
                    let peer_manager = PeerManagerHandle::clone(&network_bridge);
                    let handshake_sem = Arc::clone(&handshake_sem);
                    let inbound_count = Arc::clone(&inbound_count);
                    let inbound_by_ip = Arc::clone(&inbound_by_ip);
                    let listener_addr = p2p_addr.clone();
                    async move {
                        let listener = match tokio::net::TcpListener::bind(&listener_addr).await {
                            Ok(listener) => listener,
                            Err(e) => {
                                eprintln!("[listener] bind failed: {}", e);
                                return;
                            }
                        };
                        eprintln!("[p2p] listening on {}", listener_addr);

                        loop {
                            let Ok((stream, addr)) = listener.accept().await else {
                                continue;
                            };
                            if !reserve_inbound_connection(&inbound_count, &inbound_by_ip, addr.ip())
                            {
                                eprintln!(
                                    "[p2p] dropping inbound connection from {}: at capacity",
                                    addr
                                );
                                drop(stream);
                                continue;
                            }
                            let permit = match handshake_sem.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    eprintln!("[p2p] handshake limit reached, rejecting connection from {}", addr);
                                    release_inbound_connection(
                                        &inbound_count,
                                        &inbound_by_ip,
                                        addr.ip(),
                                    );
                                    drop(stream);
                                    continue;
                                }
                            };
                            let peer_manager = PeerManagerHandle::clone(&peer_manager);
                            let handshake_config = Arc::clone(&handshake_config);
                            let inbound_count = Arc::clone(&inbound_count);
                            let inbound_by_ip = Arc::clone(&inbound_by_ip);
                            tokio::spawn(async move {
                                let _permit = permit;
                                let config = handshake_config.read().unwrap().clone();
                                match perform_handshake_responder(stream, &config).await {
                                    Ok(handshake) => {
                                        let _ = peer_manager.register_peer(addr, handshake).await;
                                    }
                                    Err(e) => {
                                        eprintln!("[p2p] inbound handshake failed from {}: {}", addr, e);
                                    }
                                }
                                release_inbound_connection(
                                    &inbound_count,
                                    &inbound_by_ip,
                                    addr.ip(),
                                );
                            });
                        }
                    }
                });

                tokio::spawn({
                    let handshake_config = Arc::clone(&handshake_config);
                    let peer_manager = PeerManagerHandle::clone(&network_bridge);
                    let connected_addrs = Arc::clone(&connected_addrs);
                    let retry_after = Arc::clone(&retry_after);
                    let retry_delay = Arc::clone(&retry_delay);
                    let handshake_sem = Arc::clone(&handshake_sem);
                    let discovered_peers = Arc::clone(&discovered_peers);
                    let authenticated_peer_addrs = Arc::clone(&authenticated_peer_addrs);
                    let authenticated_addr_validators = Arc::clone(&authenticated_addr_validators);
                    let connected_validator_ids = Arc::clone(&connected_validator_ids);
                    let bootstrap_peer_addrs = Arc::clone(&bootstrap_peer_addrs);
                    let genesis_peer_addrs = Arc::clone(&genesis_peer_addrs);
                    let peer_addrs = Arc::clone(&peer_addrs);
                    let failure_counts = Arc::clone(&failure_counts);
                    let peers_file_path = peers_file_path.clone();
                    let dns_seed_host = dns_seed_host.clone();
                    let dns_seed_signed_public_key = dns_seed_signed_public_key.clone();
                    let p2p_addr_for_port = p2p_addr.clone();
                    let signed_dns_replay_state = signed_dns_replay_state_path.clone();
                    async move {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        let p2p_port = p2p_addr_for_port
                            .rsplit(':')
                            .next()
                            .and_then(|port| port.parse::<u16>().ok())
                            .unwrap_or(30303);
                        let raw_persisted = load_peers(&peers_file_path);
                        let persisted =
                            sanitize_loaded_peers(raw_persisted.iter().copied(), Some(p2p_port));
                        if persisted.len() != raw_persisted.len() {
                            eprintln!(
                                "[discovery] sanitized persisted peers: {} -> {} entries",
                                raw_persisted.len(),
                                persisted.len()
                            );
                            save_peers(&peers_file_path, &persisted);
                        }
                        {
                            let mut dp = discovered_peers.lock().unwrap();
                            let authenticated = authenticated_peer_addrs.lock().unwrap().clone();
                            for addr in &persisted {
                                insert_discovered_peer_if_not_self(
                                    &mut dp,
                                    &authenticated,
                                    &bootstrap_peer_addrs,
                                    &genesis_peer_addrs,
                                    &p2p_addr_for_port,
                                    addr.to_string(),
                                );
                            }
                            for addr in &initial_discovered_peers {
                                insert_discovered_peer_if_not_self(
                                    &mut dp,
                                    &authenticated,
                                    &bootstrap_peer_addrs,
                                    &genesis_peer_addrs,
                                    &p2p_addr_for_port,
                                    addr.clone(),
                                );
                            }
                        }
                        eprintln!("[discovery] loaded {} persisted peers", persisted.len());
                        eprintln!(
                            "[discovery] invoking DNS seed resolver with dnssec={} signed={} signed_key_bytes={}",
                            dns_seed_validation,
                            dns_seed_signed_validation,
                            dns_seed_signed_public_key
                                .as_ref()
                                .map(|bytes| bytes.len())
                                .unwrap_or(0)
                        );
                        let signed_public_key =
                            dns_seed_signed_public_key.as_ref().and_then(|bytes| {
                                let array: [u8; indra_crypto::PQ_PK_BYTES] =
                                    bytes.as_slice().try_into().ok()?;
                                Some(PqPublicKey(array))
                            });
                        let dns_peers = resolve_dns_seeds_with_policies_and_replay_store(
                            &dns_seed_host,
                            p2p_port,
                            dns_seed_validation,
                            dns_seed_signed_validation,
                            signed_public_key.as_ref(),
                            Some(&signed_dns_replay_state),
                        )
                        .await;
                        {
                            let mut dp = discovered_peers.lock().unwrap();
                            let authenticated = authenticated_peer_addrs.lock().unwrap().clone();
                            for addr in &dns_peers {
                                insert_discovered_peer_if_not_self(
                                    &mut dp,
                                    &authenticated,
                                    &bootstrap_peer_addrs,
                                    &genesis_peer_addrs,
                                    &p2p_addr_for_port,
                                    addr.to_string(),
                                );
                            }
                        }
                        eprintln!("[discovery] {} DNS seed peers discovered", dns_peers.len());

                        const MIN_BACKOFF: Duration = Duration::from_secs(2);
                        const MAX_BACKOFF: Duration = Duration::from_secs(60);
                        let mut last_peer_save = Instant::now();
                        loop {
                            let mut all_peers = bootstrap_peers.clone();
                            {
                                let dp = discovered_peers.lock().unwrap();
                                for peer in dp.iter() {
                                    if !all_peers.contains(peer) {
                                        all_peers.push(peer.clone());
                                    }
                                }
                            }

                            for peer_addr_str in &all_peers {
                                if connected_addrs.lock().unwrap().len() >= TARGET_OUTBOUND_PEERS {
                                    break;
                                }
                                let Some(addr) = resolve_peer_addr(peer_addr_str) else {
                                    eprintln!("[dialer] invalid addr: {}", peer_addr_str);
                                    continue;
                                };
                                if is_configured_self_addr(&addr, &p2p_addr_for_port) {
                                    discovered_peers.lock().unwrap().remove(peer_addr_str);
                                    retry_after.lock().unwrap().remove(peer_addr_str);
                                    retry_delay.lock().unwrap().remove(peer_addr_str);
                                    continue;
                                }
                                if has_connected_ip(&connected_addrs, &addr) {
                                    retry_after.lock().unwrap().remove(peer_addr_str);
                                    retry_delay.lock().unwrap().remove(peer_addr_str);
                                    continue;
                                }
                                if should_skip_dial_for_connected_validator(
                                    peer_addr_str,
                                    &authenticated_addr_validators.lock().unwrap(),
                                    &connected_validator_ids.lock().unwrap(),
                                ) {
                                    retry_after.lock().unwrap().remove(peer_addr_str);
                                    retry_delay.lock().unwrap().remove(peer_addr_str);
                                    continue;
                                }
                                if let Some(next_attempt) = retry_after.lock().unwrap().get(peer_addr_str).copied() {
                                    if Instant::now() < next_attempt {
                                        continue;
                                    }
                                }
                                match tokio::net::TcpStream::connect(addr).await {
                                    Ok(stream) => {
                                        let permit = match handshake_sem.clone().try_acquire_owned() {
                                            Ok(permit) => permit,
                                            Err(_) => {
                                                eprintln!("[p2p] handshake limit reached, deferring outbound connection to {}", addr);
                                                retry_after.lock().unwrap().insert(peer_addr_str.clone(), Instant::now() + MIN_BACKOFF);
                                                continue;
                                            }
                                        };
                                        retry_after.lock().unwrap().remove(peer_addr_str);
                                        retry_delay.lock().unwrap().remove(peer_addr_str);
                                        let peer_manager = PeerManagerHandle::clone(&peer_manager);
                                        let handshake_config = Arc::clone(&handshake_config);
                                        let retry_after = Arc::clone(&retry_after);
                                        let retry_delay = Arc::clone(&retry_delay);
                                        let discovered_peers = Arc::clone(&discovered_peers);
                                        let failure_counts = Arc::clone(&failure_counts);
                                        let bootstrap_peer_addrs = Arc::clone(&bootstrap_peer_addrs);
                                        let peer_key = peer_addr_str.clone();
                                        tokio::spawn(async move {
                                            let _permit = permit;
                                            let config = handshake_config.read().unwrap().clone();
                                            match perform_handshake_initiator(stream, &config).await {
                                                Ok(handshake) => {
                                                    let _ = peer_manager.register_peer(addr, handshake).await;
                                                }
                                                Err(e) => {
                                                    eprintln!("[dialer] handshake failed with {}: {}", addr, e);
                                                    let mut delays = retry_delay.lock().unwrap();
                                                    let current = delays.get(&peer_key).copied().unwrap_or(MIN_BACKOFF);
                                                    let next = (current * 2).min(MAX_BACKOFF);
                                                    delays.insert(peer_key.clone(), next);
                                                    drop(delays);
                                                    retry_after
                                                        .lock()
                                                        .unwrap()
                                                        .insert(peer_key.clone(), Instant::now() + current);
                                                    if record_dial_failure(
                                                        &peer_key,
                                                        &mut discovered_peers.lock().unwrap(),
                                                        &mut retry_after.lock().unwrap(),
                                                        &mut retry_delay.lock().unwrap(),
                                                        &mut failure_counts.lock().unwrap(),
                                                        &bootstrap_peer_addrs,
                                                    ) {
                                                        eprintln!(
                                                            "[p2p] evicting permanently unreachable peer {} after {} failures",
                                                            peer_key,
                                                            MAX_DIAL_FAILURES_BEFORE_EVICTION
                                                        );
                                                    }
                                                }
                                            }
                                        });
                                    }
                                    Err(e) => {
                                        eprintln!("[dialer] failed to connect to {}: {}", addr, e);
                                        let mut delays = retry_delay.lock().unwrap();
                                        let current = delays.get(peer_addr_str).copied().unwrap_or(MIN_BACKOFF);
                                        let next = (current * 2).min(MAX_BACKOFF);
                                        delays.insert(peer_addr_str.clone(), next);
                                        drop(delays);
                                        retry_after
                                            .lock()
                                            .unwrap()
                                            .insert(peer_addr_str.clone(), Instant::now() + current);
                                        if record_dial_failure(
                                            peer_addr_str,
                                            &mut discovered_peers.lock().unwrap(),
                                            &mut retry_after.lock().unwrap(),
                                            &mut retry_delay.lock().unwrap(),
                                            &mut failure_counts.lock().unwrap(),
                                            &bootstrap_peer_addrs,
                                        ) {
                                            eprintln!(
                                                "[p2p] evicting permanently unreachable peer {} after {} failures",
                                                peer_addr_str,
                                                MAX_DIAL_FAILURES_BEFORE_EVICTION
                                            );
                                        }
                                    }
                                }
                            }
                            if last_peer_save.elapsed().as_secs() >= PEER_TABLE_SAVE_INTERVAL_SECS {
                                let peers_to_save = peer_addresses_to_persist(
                                    &discovered_peers.lock().unwrap(),
                                    &peer_addrs.lock().unwrap(),
                                    &p2p_addr_for_port,
                                );
                                save_peers(&peers_file_path, &peers_to_save);
                                last_peer_save = Instant::now();
                            }
                            tokio::time::sleep(DIAL_RETRY).await;
                        }
                    }
                });

                tokio::spawn({
                    let discovered_peers = Arc::clone(&discovered_peers);
                    let peer_addrs = Arc::clone(&peer_addrs);
                    let peers_file_path = peers_file_path.clone();
                    let local_p2p_addr = p2p_addr.clone();
                    async move {
                        if tokio::signal::ctrl_c().await.is_ok() {
                            let peers_to_save = peer_addresses_to_persist(
                                &discovered_peers.lock().unwrap(),
                                &peer_addrs.lock().unwrap(),
                                &local_p2p_addr,
                            );
                            save_peers(&peers_file_path, &peers_to_save);
                            eprintln!(
                                "[discovery] saved {} peers before shutdown",
                                peers_to_save.len()
                            );
                            std::process::exit(0);
                        }
                    }
                });

                std::future::pending::<()>().await;
            });
        }
    });

    let peer_manager = handle_rx.recv().expect("peer manager handle");
    let bridge = Arc::new(NetworkBridge::new(
        peer_manager,
        peer_addrs,
        addr_validators,
    ));

    (bridge, discovered_peers, authenticated_peer_addrs, event_rx)
}

fn start_observer_runtime(
    observer_addr: String,
    driver: Arc<Mutex<ConsensusDriver>>,
    observer_count: Arc<AtomicUsize>,
) {
    std::thread::spawn(move || {
        let runtime = TokioRuntimeBuilder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        runtime.block_on(async move {
            let listener = match tokio::net::TcpListener::bind(&observer_addr).await {
                Ok(listener) => listener,
                Err(e) => {
                    eprintln!("[observer] bind failed on {}: {}", observer_addr, e);
                    return;
                }
            };
            eprintln!("[observer] listening on {}", observer_addr);

            let (block_tx, _) =
                tokio::sync::broadcast::channel::<indra_core::types::block::BlockV1>(64);
            tokio::spawn(observer_block_poller(Arc::clone(&driver), block_tx.clone()));

            loop {
                let (stream, addr) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        eprintln!("[observer] accept error: {}", e);
                        continue;
                    }
                };
                let driver = Arc::clone(&driver);
                let observer_count = Arc::clone(&observer_count);
                let mut block_rx = block_tx.subscribe();
                tokio::spawn(async move {
                    if let Err(e) = handle_observer_connection(
                        stream,
                        addr,
                        driver,
                        observer_count,
                        &mut block_rx,
                    )
                    .await
                    {
                        eprintln!("[observer] connection {} closed: {}", addr, e);
                    }
                });
            }
        });
    });
}

async fn observer_block_poller(
    driver: Arc<Mutex<ConsensusDriver>>,
    block_tx: tokio::sync::broadcast::Sender<indra_core::types::block::BlockV1>,
) {
    let mut last_height = driver.lock().unwrap().height();
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let (current_height, blocks) = {
            let mut d = driver.lock().unwrap();
            let current_height = d.height();
            let mut blocks = Vec::new();
            if current_height > last_height {
                for height in last_height.saturating_add(1)..=current_height {
                    if let Ok(block) = d.engine.block_store.get(height) {
                        blocks.push(block);
                    }
                }
            }
            (current_height, blocks)
        };
        for block in blocks {
            let _ = block_tx.send(block);
        }
        last_height = current_height;
    }
}

async fn handle_observer_connection(
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    driver: Arc<Mutex<ConsensusDriver>>,
    observer_count: Arc<AtomicUsize>,
    block_rx: &mut tokio::sync::broadcast::Receiver<indra_core::types::block::BlockV1>,
) -> indra_network::NetworkResult<()> {
    let result = perform_observer_handshake_responder(stream, NODE_TYPE_FULL).await?;
    let mut stream = result.stream;
    let status = current_status_message(&driver);
    write_message_plain(&mut stream, &status).await?;

    if observer_count.load(Ordering::Relaxed) >= MAX_OBSERVER_CONNECTIONS {
        eprintln!(
            "[observer] at capacity ({}), sending status and closing {}",
            MAX_OBSERVER_CONNECTIONS, addr
        );
        return Ok(());
    }

    let total = observer_count.fetch_add(1, Ordering::Relaxed) + 1;
    eprintln!("[observer] new connection from {} (total: {})", addr, total);
    let (mut reader, mut writer) = stream.into_split();
    let (write_tx, mut write_rx) = tokio::sync::mpsc::channel::<Message>(64);
    let mut frame_limiter = ObserverFrameLimiter::new();
    let mut request_blocks_limiter =
        TokenBucket::new(OBSERVER_REQUEST_BLOCKS_RATE, OBSERVER_REQUEST_BLOCKS_BURST);

    let writer_task = tokio::spawn(async move {
        while let Some(msg) = write_rx.recv().await {
            if write_message_plain(&mut writer, &msg).await.is_err() {
                break;
            }
        }
    });

    loop {
        tokio::select! {
            frame = read_frame_plain_limited(&mut reader, &mut frame_limiter) => {
                let frame = frame?;
                let msg = Message::decode_wire(&frame)?;
                match msg {
                    Message::RequestBlocks { from_height, to_height } => {
                        if !observer_request_blocks_allowed(&mut request_blocks_limiter) {
                            eprintln!(
                                "[observer] rate-limited RequestBlocks from {}",
                                addr
                            );
                            let _ = write_tx
                                .send(Message::BlockResponse {
                                    blocks: Vec::new(),
                                    lowest_available: None,
                                    highest_available: None,
                                })
                                .await;
                            continue;
                        }
                        let (blocks, lowest_available, highest_available) =
                            observer_blocks_for_range(&driver, from_height, to_height);
                        let _ = write_tx
                            .send(Message::BlockResponse {
                                blocks,
                                lowest_available,
                                highest_available,
                            })
                            .await;
                    }
                    Message::Status { height, .. } => {
                        eprintln!("[observer] {} status height={}", addr, height);
                    }
                    Message::Ping(nonce) => {
                        let _ = write_tx.send(Message::Pong(nonce)).await;
                    }
                    Message::Pong(_) | Message::PeerList(_) => {}
                    Message::Vote(_)
                    | Message::VrfCommit(_)
                    | Message::VrfReveal(_)
                    | Message::RequestProposal { .. }
                    | Message::RequestQC { .. }
                    | Message::QCResponse { .. }
                    | Message::RequestVrfReveals { .. }
                    | Message::VrfRevealsResponse { .. } => {
                        eprintln!("[observer] consensus message from {}, closing", addr);
                        break;
                    }
                    Message::Block(_)
                    | Message::BlockResponse { .. }
                    | Message::Tx(_)
                    | Message::StakingOp(_)
                    | Message::GovernanceOp(_) => {}
                }
            }
            block = block_rx.recv() => {
                match block {
                    Ok(block) => {
                        let _ = write_tx.send(Message::Block(block)).await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    drop(write_tx);
    let _ = writer_task.await;
    let remaining = observer_count
        .fetch_sub(1, Ordering::Relaxed)
        .saturating_sub(1);
    eprintln!(
        "[observer] peer disconnected {} (total: {})",
        addr, remaining
    );
    Ok(())
}

fn observer_request_blocks_allowed(limiter: &mut TokenBucket) -> bool {
    limiter.try_consume(1)
}

fn current_status_message(driver: &Arc<Mutex<ConsensusDriver>>) -> Message {
    let d = driver.lock().unwrap();
    Message::Status {
        height: d.height(),
        tip_hash: d.engine.state.tip_hash,
        round: d.current_round(),
    }
}

fn observer_blocks_for_range(
    driver: &Arc<Mutex<ConsensusDriver>>,
    from_height: u64,
    to_height: u64,
) -> (
    Vec<indra_core::types::block::BlockV1>,
    Option<u64>,
    Option<u64>,
) {
    let mut d = driver.lock().unwrap();
    blocks_for_range_with_availability(&mut d.engine.block_store, from_height, to_height)
}

fn blocks_for_range_with_availability(
    block_store: &mut indra_storage::BlockStore,
    from_height: u64,
    to_height: u64,
) -> (
    Vec<indra_core::types::block::BlockV1>,
    Option<u64>,
    Option<u64>,
) {
    if block_store.is_empty() || from_height > to_height {
        return (Vec::new(), None, None);
    }

    let lowest = block_store.lowest_height();
    let highest = block_store.next_height().saturating_sub(1);
    let range_was_unavailable = from_height < lowest || to_height > highest;
    let start = from_height.max(lowest);
    let end = to_height
        .min(highest)
        .min(start.saturating_add(SYNC_BATCH_SIZE).saturating_sub(1));

    let mut blocks = Vec::new();
    if start <= end {
        for height in start..=end {
            match block_store.get(height) {
                Ok(block) => blocks.push(block),
                Err(_) => break,
            }
        }
    }

    if range_was_unavailable {
        (blocks, Some(lowest), Some(highest))
    } else {
        (blocks, None, None)
    }
}

async fn write_message_plain<W>(writer: &mut W, msg: &Message) -> indra_network::NetworkResult<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let wire = msg.encode_wire()?;
    write_frame_plain(writer, &wire[4..]).await
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let get_arg = |flag: &str| -> Option<String> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    if args.iter().any(|arg| arg == "--init") {
        run_init();
        return;
    }
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return;
    }
    let config_path = get_arg("--config");
    let mut cfg_file = if let Some(ref path) = config_path {
        NodeConfigFile::load(Path::new(path)).unwrap_or_else(|e| {
            eprintln!("ERROR: {}", e);
            std::process::exit(1);
        })
    } else {
        NodeConfigFile::default()
    };

    if let Some(v) = get_arg("--data-dir") {
        cfg_file.data_dir = Some(v);
    }
    if let Some(v) = get_arg("--genesis") {
        cfg_file.genesis = Some(v);
    }
    if let Some(v) = get_arg("--keys") {
        cfg_file.keys_path = Some(v);
    }
    if let Some(v) = get_arg("--keys-password-file") {
        cfg_file.keys_password_file = Some(v);
    }
    if let Some(v) = get_arg("--p2p-addr") {
        cfg_file.p2p_addr = Some(v);
    }
    if let Some(v) = get_arg("--observer-addr") {
        cfg_file.observer_addr = Some(v);
    }
    if let Some(v) = get_arg("--metrics-addr") {
        cfg_file.metrics_addr = Some(v);
        cfg_file.metrics_enabled = Some(true);
    }
    if let Some(v) = get_arg("--rpc-addr") {
        cfg_file.rpc_addr = Some(v);
    }
    if let Some(v) = get_arg("--rpc-public-addr") {
        cfg_file.rpc_public_addr = Some(v);
        cfg_file.rpc_public_enabled = Some(true);
    }
    if args.iter().any(|a| a == "--no-observer-port") {
        cfg_file.observer_addr = Some(String::new());
    }
    if args.iter().any(|a| a == "--no-metrics") {
        cfg_file.metrics_enabled = Some(false);
    }
    if args.iter().any(|a| a == "--archive") {
        cfg_file.prune_keep_blocks = Some(0);
    }
    if let Some(v) = get_arg("--prune-keep").and_then(|s| s.parse::<u64>().ok()) {
        cfg_file.prune_keep_blocks = Some(v);
    }
    if let Some(v) = get_arg("--bootstrap-peers") {
        cfg_file.bootstrap_peers = v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(v) = get_arg("--seeds") {
        cfg_file.dns_seed_host = Some(v);
    }
    if let Some(v) = get_arg("--peers-file") {
        cfg_file.peers_file = Some(v);
    }
    if config_path.is_some() {
        if let Err(errors) = cfg_file.validate() {
            eprintln!("ERROR: config.toml validation failed:");
            for err in &errors {
                eprintln!("  - {}", err);
            }
            std::process::exit(1);
        }
    } else {
        cfg_file.mode.get_or_insert_with(|| "validator".to_string());
        cfg_file
            .data_dir
            .get_or_insert_with(|| "./indra-data".to_string());
        cfg_file
            .genesis
            .get_or_insert_with(|| "genesis.toml".to_string());
        cfg_file
            .keys_path
            .get_or_insert_with(|| "keys.json".to_string());
    }

    let keys_path = cfg_file
        .keys_path
        .clone()
        .unwrap_or_else(|| "keys.json".to_string());
    let data_dir = cfg_file
        .data_dir
        .clone()
        .unwrap_or_else(|| "./indra-data".to_string());
    let p2p_addr = cfg_file
        .p2p_addr
        .clone()
        .unwrap_or_else(|| "0.0.0.0:30303".to_string());
    let observer_addr = match cfg_file.observer_addr.as_deref() {
        Some("") => None,
        Some(addr) => Some(addr.to_string()),
        None => Some(format!("0.0.0.0:{}", OBSERVER_PORT)),
    };
    let metrics_addr = if cfg_file.metrics_enabled == Some(false) {
        None
    } else {
        match cfg_file.metrics_addr.as_deref() {
            Some("") => None,
            Some(addr) => Some(addr.to_string()),
            None => Some(DEFAULT_METRICS_ADDR.to_string()),
        }
    };
    let dns_seed_host = cfg_file
        .dns_seed_host
        .clone()
        .unwrap_or_else(default_dns_seed_hosts_config);
    let dns_seed_validation = cfg_file
        .dns_seed_validation
        .as_deref()
        .map(str::parse::<DnsSeedValidationMode>)
        .transpose()
        .unwrap_or_else(|e| {
            eprintln!("ERROR: {}", e);
            std::process::exit(1);
        })
        .unwrap_or_default();
    let dns_seed_signed_validation = cfg_file
        .dns_seed_signed_validation
        .as_deref()
        .map(str::parse::<SignedDnsSeedValidationMode>)
        .transpose()
        .unwrap_or_else(|e| {
            eprintln!("ERROR: {}", e);
            std::process::exit(1);
        })
        .unwrap_or_default();
    let dns_seed_signed_public_key = cfg_file
        .dns_seed_signed_public_key
        .as_deref()
        .map(|value| hex::decode(value.trim()))
        .transpose()
        .unwrap_or_else(|_| {
            eprintln!("ERROR: network.dns_seed_signed_public_key must be valid hex");
            std::process::exit(1);
        });
    if dns_seed_signed_validation != SignedDnsSeedValidationMode::Off {
        match dns_seed_signed_public_key.as_ref().map(Vec::len) {
            Some(indra_crypto::PQ_PK_BYTES) => {}
            Some(len) => {
                eprintln!(
                    "ERROR: network.dns_seed_signed_public_key must be {} bytes when signed DNS discovery is enabled (got {len})",
                    indra_crypto::PQ_PK_BYTES
                );
                std::process::exit(1);
            }
            None => {
                eprintln!(
                    "ERROR: network.dns_seed_signed_public_key is required when network.dns_seed_signed_validation={}",
                    dns_seed_signed_validation
                );
                std::process::exit(1);
            }
        }
    }
    let prune_keep_cfg = cfg_file
        .prune_keep_blocks
        .unwrap_or(DEFAULT_PRUNE_KEEP_BLOCKS);
    let archive = prune_keep_cfg == 0;
    let prune_keep = if archive {
        0
    } else {
        prune_keep_cfg.max(MIN_PRUNE_KEEP_BLOCKS)
    };

    eprintln!("╔══════════════════════════════════════════╗");
    eprintln!("║      INDRA v2 — Phase 8 Node Starting     ║");
    eprintln!("╚══════════════════════════════════════════╝");
    eprintln!("Keys:      {}", keys_path);
    eprintln!("Data:      {}", data_dir);
    eprintln!("P2P:       {}", p2p_addr);
    eprintln!(
        "DNS seed:  dnssec={} signed={} signed_key_bytes={}",
        dns_seed_validation,
        dns_seed_signed_validation,
        dns_seed_signed_public_key
            .as_ref()
            .map(|bytes| bytes.len())
            .unwrap_or(0)
    );
    eprintln!(
        "Observer:  {}",
        observer_addr.as_deref().unwrap_or("(disabled)")
    );
    eprintln!(
        "Metrics:   {}",
        metrics_addr.as_deref().unwrap_or("(disabled)")
    );
    eprintln!("Mode:      {}", if archive { "archive" } else { "pruned" });
    if !archive {
        eprintln!("Retain:    {} blocks", prune_keep);
    }

    check_disk_space(Path::new(&data_dir));

    // Load keys
    let keys_data = load_keys_data(&keys_path, cfg_file.keys_password_file.as_deref());

    let bootstrap_peers: Vec<String> = if cfg_file.bootstrap_peers.is_empty() {
        eprintln!("Bootstrap: (none; DNS/persisted/genesis discovery enabled)");
        vec![]
    } else {
        eprintln!("Bootstrap: {}", cfg_file.bootstrap_peers.join(","));
        cfg_file.bootstrap_peers.clone()
    };
    let genesis_path = cfg_file
        .genesis
        .clone()
        .unwrap_or_else(|| "genesis.toml".to_string());
    let peers_file = cfg_file.peers_file.clone().unwrap_or_else(|| {
        Path::new(&data_dir)
            .join("peers.json")
            .to_string_lossy()
            .to_string()
    });
    let genesis_seed_peers = load_genesis_seed_peers(&genesis_path);
    if !genesis_seed_peers.is_empty() {
        eprintln!(
            "[discovery] loaded {} peer hints from genesis",
            genesis_seed_peers.len()
        );
    }

    let config = NodeConfig {
        data_dir: std::path::PathBuf::from(&data_dir),
        genesis_path: Some(genesis_path),
        validator_seed: Some(keys_data.hybrid_seed),
        vrf_seed: Some(keys_data.vrf_seed),
        pq_sk: if keys_data.pq_sk.is_empty() {
            None
        } else {
            Some(keys_data.pq_sk)
        },
        pq_pk: if keys_data.pq_pk.is_empty() {
            None
        } else {
            Some(keys_data.pq_pk)
        },
        p2p_addr: p2p_addr.clone(),
        bootstrap_peers: bootstrap_peers.clone(),
        dns_seed_host: dns_seed_host.clone(),
        dns_seed_validation,
        dns_seed_signed_validation,
        dns_seed_signed_public_key: dns_seed_signed_public_key.clone(),
        peers_file: peers_file.clone(),
        snapshot_interval: cfg_file.snapshot_interval.unwrap_or(300),
        mempool_capacity: cfg_file.mempool_capacity.unwrap_or(5_000),
        staking_mempool_capacity: cfg_file
            .staking_mempool_capacity
            .unwrap_or(DEFAULT_STAKING_MEMPOOL_CAPACITY),
        governance_mempool_capacity: cfg_file
            .governance_mempool_capacity
            .unwrap_or_else(default_governance_mempool_capacity),
        prune_keep_blocks: if archive { None } else { Some(prune_keep) },
        observer_addr: observer_addr.clone(),
        metrics_addr: metrics_addr.clone(),
    };

    // Init node engine + consensus driver
    let engine = NodeEngine::init(config).unwrap_or_else(|e| panic!("Node init failed: {}", e));

    eprintln!(
        "Validator set: {} active validators",
        engine.state.validators.active_count()
    );

    let validator_id = engine
        .validator_id()
        .map(|id| hex::encode(id.0))
        .unwrap_or_else(|| "full-node".to_string());

    eprintln!("\nChain:     {}", engine.state.chain_id);
    eprintln!("Validator: {}...", &validator_id[..16]);
    eprintln!("Height:    {}", engine.height());
    eprintln!("\nStarting P2P and consensus...\n");

    let vote_safety = indra_storage::VoteSafetyStore::open(engine.config.vote_safety_path());
    let mut driver_state = ConsensusDriver::new(engine, vote_safety);
    driver_state.refresh_registered_voters();
    let startup_qc_request = driver_state.request_qc_if_needed();
    let handshake_config = build_handshake_config(&driver_state.engine)
        .unwrap_or_else(|error| panic!("failed to resolve P2P validator authority: {error}"))
        .map(|config| Arc::new(RwLock::new(config)))
        .unwrap_or_else(|| panic!("authenticated transport requires validator networking keys"));
    let driver = driver_state;

    // Shared state between threads
    let driver = Arc::new(Mutex::new(driver));
    let (height_tx, height_rx) = std::sync::mpsc::channel::<()>();
    let observer_count = Arc::new(AtomicUsize::new(0));
    let connected_validator_peers = Arc::new(AtomicUsize::new(0));
    let metrics_state = Arc::new(MetricsState::new());
    let last_block_timestamp = Arc::new(AtomicU64::new(0));
    let op_relay_seen = Arc::new(Mutex::new(OpRelaySeenCache::new(OP_RELAY_SEEN_CAPACITY)));
    let (gossip, discovered_peers, authenticated_peer_addrs, network_events) =
        start_network_runtime(
            p2p_addr.clone(),
            bootstrap_peers.clone(),
            genesis_seed_peers.clone(),
            peers_file.clone(),
            dns_seed_host.clone(),
            dns_seed_validation,
            dns_seed_signed_validation,
            dns_seed_signed_public_key.clone(),
            signed_dns_replay_state_path(Path::new(&data_dir)),
            Arc::clone(&handshake_config),
        );
    if let Some(addr) = observer_addr {
        start_observer_runtime(addr, Arc::clone(&driver), Arc::clone(&observer_count));
    }
    if let Some(addr) = metrics_addr {
        indra_node::start_metrics_server(
            addr,
            Arc::clone(&driver),
            Arc::clone(&observer_count),
            Arc::clone(&metrics_state),
            Arc::clone(&last_block_timestamp),
            Arc::clone(&connected_validator_peers),
            data_dir.clone(),
            env!("CARGO_PKG_VERSION").to_string(),
        );
    }

    // ── Thread 3: Authenticated network event loop ──────────────────────────
    {
        let gossip = Arc::clone(&gossip);
        let driver = Arc::clone(&driver);
        let height_tx = height_tx.clone();
        let handshake_config = Arc::clone(&handshake_config);
        let discovered_peers = Arc::clone(&discovered_peers);
        let authenticated_peer_addrs = Arc::clone(&authenticated_peer_addrs);
        let bootstrap_peer_addrs = bootstrap_peers.iter().cloned().collect::<HashSet<String>>();
        let genesis_peer_addrs = genesis_seed_peers
            .iter()
            .cloned()
            .collect::<HashSet<String>>();
        let local_p2p_addr = p2p_addr.clone();
        let connected_validator_peers = Arc::clone(&connected_validator_peers);
        let metrics_state = Arc::clone(&metrics_state);
        let last_block_timestamp = Arc::clone(&last_block_timestamp);
        let op_relay_seen = Arc::clone(&op_relay_seen);

        std::thread::spawn(move || {
            while let Ok(event) = network_events.recv() {
                connected_validator_peers.store(gossip.connection_count(), Ordering::Relaxed);
                match event {
                    NetworkEvent::PeerConnected {
                        validator_id, addr, ..
                    } => {
                        connected_validator_peers
                            .store(gossip.connection_count(), Ordering::Relaxed);
                        eprintln!("[p2p] authenticated peer connected: {}", addr);
                        let self_addrs = configured_self_addr_set(&local_p2p_addr);
                        let known_addrs = peer_list_payload_with_identities(
                            gossip.connected_addrs(),
                            Some(addr),
                            &self_addrs,
                            &gossip.addr_validators.lock().unwrap(),
                        );
                        if !known_addrs.is_empty() {
                            gossip.send_to_validator(validator_id, &Message::PeerList(known_addrs));
                        }
                        announce_status_and_recovery(
                            &driver,
                            &gossip,
                            &height_tx,
                            &handshake_config,
                            validator_id,
                            &metrics_state,
                            &last_block_timestamp,
                        );
                    }
                    NetworkEvent::PeerDisconnected { addr, .. } => {
                        connected_validator_peers
                            .store(gossip.connection_count(), Ordering::Relaxed);
                        eprintln!("[p2p] peer disconnected: {}", addr);
                    }
                    NetworkEvent::SlashDetected(evidence) => {
                        metrics_state
                            .slash_events_total
                            .fetch_add(1, Ordering::Relaxed);
                        let mut d = driver.lock().unwrap();
                        d.engine.add_slash_evidence(evidence);
                    }
                    NetworkEvent::Message {
                        from: addr,
                        validator_id,
                        msg,
                    } => {
                        match &msg {
                            Message::StakingOp(op) => {
                                let accepted = driver
                                    .lock()
                                    .map_err(|_| "consensus driver lock poisoned".to_string())
                                    .and_then(|mut guard| {
                                        guard
                                            .engine
                                            .add_staking_op(op.clone())
                                            .map_err(|e| e.to_string())
                                    })
                                    .is_ok();
                                if accepted {
                                    rebroadcast_inbound_accepted_op(
                                        &gossip,
                                        &op_relay_seen,
                                        validator_id,
                                        msg.clone(),
                                    );
                                }
                                continue;
                            }
                            Message::GovernanceOp(op) => {
                                let accepted = driver
                                    .lock()
                                    .map_err(|_| "consensus driver lock poisoned".to_string())
                                    .and_then(|mut guard| {
                                        guard
                                            .engine
                                            .add_governance_op(op.clone())
                                            .map_err(|e| e.to_string())
                                    })
                                    .is_ok();
                                if accepted {
                                    rebroadcast_inbound_accepted_op(
                                        &gossip,
                                        &op_relay_seen,
                                        validator_id,
                                        msg.clone(),
                                    );
                                }
                                continue;
                            }
                            Message::PeerList(addrs) => {
                                let mut new_peers = discovered_peers.lock().unwrap();
                                let authenticated =
                                    authenticated_peer_addrs.lock().unwrap().clone();
                                let local_validator_id =
                                    handshake_config.read().unwrap().my_validator_id;
                                let mut accepted = 0usize;
                                for entry in addrs.iter().take(MAX_PEER_LIST_SIZE) {
                                    let Some(addr) = resolve_peer_addr(&entry.addr) else {
                                        continue;
                                    };
                                    if discovery_accepts_peer_addr(
                                        &addr,
                                        entry.validator_id,
                                        local_validator_id,
                                        &local_p2p_addr,
                                        &gossip.connected_addrs(),
                                    ) {
                                        if insert_discovered_peer_if_not_self(
                                            &mut new_peers,
                                            &authenticated,
                                            &bootstrap_peer_addrs,
                                            &genesis_peer_addrs,
                                            &local_p2p_addr,
                                            addr.to_string(),
                                        ) {
                                            accepted = accepted.saturating_add(1);
                                        }
                                    }
                                }
                                eprintln!(
                                    "[discovery] received {} peer addresses from {} (accepted {})",
                                    addrs.len(),
                                    addr,
                                    accepted
                                );
                                continue;
                            }
                            Message::RequestBlocks {
                                from_height,
                                to_height,
                            } => {
                                let (blocks_to_send, lowest_available, highest_available) = {
                                    let mut d = driver.lock().unwrap();
                                    blocks_for_range_with_availability(
                                        &mut d.engine.block_store,
                                        *from_height,
                                        *to_height,
                                    )
                                };
                                // If the requested range is partially or fully pruned,
                                // include the retained range so the requester can try
                                // an archive peer instead of retrying this peer blindly.
                                gossip.send_to_validator(
                                    validator_id,
                                    &Message::BlockResponse {
                                        blocks: blocks_to_send,
                                        lowest_available,
                                        highest_available,
                                    },
                                );
                                continue;
                            }
                            Message::RequestProposal {
                                height,
                                round,
                                hash,
                            } => {
                                let proposal = {
                                    let mut d = driver.lock().unwrap();
                                    d.pending_block(hash)
                                        .or_else(|| d.engine.block_store.get(*height).ok())
                                        .filter(|block| {
                                            proposal_matches_request(block, *height, *round, hash)
                                        })
                                };
                                if let Some(block) = proposal {
                                    gossip.send_to_validator(validator_id, &Message::Block(block));
                                }
                                continue;
                            }
                            Message::BlockResponse {
                                blocks,
                                lowest_available,
                                highest_available,
                            } => {
                                if blocks.is_empty() {
                                    if let (Some(lowest), Some(highest)) =
                                        (lowest_available, highest_available)
                                    {
                                        eprintln!(
                                            "[sync] peer {} cannot serve requested historical range; available heights {}..={}",
                                            addr, lowest, highest
                                        );
                                    }
                                }
                                let response_blocks = blocks.clone();
                                let request_more;
                                let mut caught_up_height = None;
                                let mut imported_any = false;
                                let mut qc_recovery_actions = Vec::new();
                                {
                                    let mut d = driver.lock().unwrap();
                                    for block in response_blocks {
                                        if block.header.height != d.height() + 1 {
                                            continue;
                                        }

                                        match d.engine.commit_block(&block) {
                                            Ok(()) => {
                                                imported_any = true;
                                                record_block_commit(
                                                    &metrics_state,
                                                    &last_block_timestamp,
                                                );
                                                refresh_handshake_and_relay_config(
                                                    &d.engine,
                                                    &handshake_config,
                                                    &gossip,
                                                );
                                                if let Err(err) =
                                                    d.promote_block_header_qc(&block, "sync")
                                                {
                                                    eprintln!(
                                                        "[sync] WARNING: imported height={} from {} but failed to promote embedded QC: {}",
                                                        block.header.height, addr, err,
                                                    );
                                                }
                                                d.refresh_registered_voters();
                                                d.sync_mut().on_block_imported(block.header.height);
                                                d.reset_round();
                                                if should_log_sync_height(block.header.height) {
                                                    eprintln!(
                                                        "[sync] imported block at height={} from {}",
                                                        block.header.height,
                                                        addr
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!(
                                                    "[sync] failed to import block {} from {}: {}",
                                                    block.header.height, addr, e
                                                );
                                                break;
                                            }
                                        }
                                    }
                                    if !imported_any {
                                        let current_height = d.height();
                                        d.sync_mut().on_empty_response(current_height);
                                    }
                                    let new_height = d.height();
                                    request_more =
                                        d.sync_mut().next_request_after_response(new_height);
                                    if d.sync().is_caught_up() {
                                        d.on_sync_caught_up();
                                        qc_recovery_actions = d.request_qc_if_needed();
                                        caught_up_height = Some(new_height);
                                    }
                                }

                                if let Some((peer, from_height, to_height)) = request_more {
                                    let req = Message::RequestBlocks {
                                        from_height,
                                        to_height,
                                    };
                                    if let Some(peer_validator_id) =
                                        gossip.validator_for_addr(&peer)
                                    {
                                        gossip.send_to_validator(peer_validator_id, &req);
                                    }
                                }
                                if imported_any {
                                    let _ = height_tx.send(());
                                    broadcast_status(&driver, &gossip);
                                }
                                if !qc_recovery_actions.is_empty() {
                                    process_driver_actions(
                                        &driver,
                                        &gossip,
                                        &height_tx,
                                        &handshake_config,
                                        caught_up_height.unwrap_or_default(),
                                        qc_recovery_actions,
                                        &metrics_state,
                                        &last_block_timestamp,
                                    );
                                }
                                if let Some(height) = caught_up_height {
                                    eprintln!(
                                        "[sync] caught up to height={}, joining consensus",
                                        height
                                    );
                                }
                                continue;
                            }
                            Message::Ping(_) => {
                                let (height, tip_hash, round) = {
                                    let d = driver.lock().unwrap();
                                    (d.height(), d.engine.state.tip_hash, d.current_round())
                                };
                                gossip.send_to_validator(
                                    validator_id,
                                    &Message::Status {
                                        height,
                                        tip_hash,
                                        round,
                                    },
                                );
                                continue;
                            }
                            _ => {}
                        }

                        if let Some(event) = message_to_event(msg, addr) {
                            let previous_height = driver.lock().unwrap().height();
                            let actions = driver.lock().unwrap().process(event);
                            process_driver_actions(
                                &driver,
                                &gossip,
                                &height_tx,
                                &handshake_config,
                                previous_height,
                                actions,
                                &metrics_state,
                                &last_block_timestamp,
                            );
                            let new_height = driver.lock().unwrap().height();
                            if new_height > previous_height {
                                refresh_handshake_and_relay_config(
                                    &driver.lock().unwrap().engine,
                                    &handshake_config,
                                    &gossip,
                                );
                                let _ = height_tx.send(());
                                broadcast_status(&driver, &gossip);
                            }
                        }
                    }
                }
            }
        });
    }

    // ── Thread 4: Consensus loop ────────────────────────────────────────────
    {
        let driver = Arc::clone(&driver);
        let gossip = Arc::clone(&gossip);
        let height_tx = height_tx.clone();
        let handshake_config = Arc::clone(&handshake_config);
        let height_rx = height_rx;
        let metrics_state = Arc::clone(&metrics_state);
        let last_block_timestamp = Arc::clone(&last_block_timestamp);

        std::thread::spawn(move || {
            // Wait for peer connections to establish
            std::thread::sleep(Duration::from_secs(3));

            let mut proposed_at_slot: Option<(u64, u32)> = None;
            let mut failed_proposal_at_slot: Option<((u64, u32), Instant)> = None;
            let mut last_commit_time: Option<std::time::SystemTime> = None;
            let mut last_observed_height = 0u64;
            let mut phase_started_at = Instant::now();
            let mut last_observed = None::<(u64, u32, RoundPhase)>;
            let mut last_status_at = Instant::now() - STATUS_INTERVAL;
            let mut last_peer_wait_log = None::<usize>;

            loop {
                let (height, round, phase, sync_target, sync_caught_up, connected, tip_hash) = {
                    let d = driver.lock().unwrap();
                    (
                        d.height(),
                        d.current_round(),
                        d.current_phase(),
                        d.sync().target_height(),
                        d.sync().is_caught_up(),
                        gossip.connection_count(),
                        d.engine.state.tip_hash,
                    )
                };
                let last_qc_bytes_empty = driver.lock().unwrap().last_qc_bytes().is_empty();
                if height > last_observed_height {
                    last_commit_time = Some(std::time::SystemTime::now());
                    last_observed_height = height;
                }

                if last_qc_bytes_empty && round % 10 == 0 {
                    let actions = driver.lock().unwrap().request_qc_if_needed();
                    if !actions.is_empty() {
                        process_driver_actions(
                            &driver,
                            &gossip,
                            &height_tx,
                            &handshake_config,
                            height,
                            actions,
                            &metrics_state,
                            &last_block_timestamp,
                        );
                    }
                }

                let observed = (height, round, phase);
                if last_observed != Some(observed) {
                    phase_started_at = Instant::now();
                    if last_observed.map(|(h, r, _)| (h, r)) != Some((height, round)) {
                        proposed_at_slot = None;
                    }
                    last_observed = Some(observed);
                }

                if connected < 2 {
                    if last_peer_wait_log != Some(connected) {
                        eprintln!("[consensus] waiting for peers (have {}, need 2)", connected);
                        last_peer_wait_log = Some(connected);
                    }
                    phase_started_at = Instant::now();
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
                last_peer_wait_log = None;

                if last_status_at.elapsed() >= STATUS_INTERVAL {
                    let status = Message::Status {
                        height,
                        tip_hash,
                        round,
                    };
                    gossip.broadcast(&status);
                    last_status_at = Instant::now();
                }

                if !sync_caught_up {
                    match height_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(()) => {
                            phase_started_at = Instant::now();
                            proposed_at_slot = None;
                        }
                        Err(_) => {}
                    }
                    continue;
                }

                if sync_target.is_none() {
                    match phase {
                        RoundPhase::Propose => {
                            let (should_propose, next_height, proposal_round, vrf_actions) = {
                                let mut d = driver.lock().unwrap();
                                let height = d.engine.state.height + 1;
                                let round = d.current_round();
                                match proposer_election_for_slot(&d, height, round) {
                                    Err(error) => {
                                        eprintln!(
                                            "[consensus] proposal eligibility unavailable at height={} round={}: {}",
                                            height, round, error,
                                        );
                                        (false, height, round, Vec::new())
                                    }
                                    Ok(election) if election.candidates.is_empty() => (
                                        d.can_propose()
                                            && d.engine.config.bootstrap_peers.is_empty(),
                                        height,
                                        round,
                                        Vec::new(),
                                    ),
                                    Ok(election) => {
                                        let vrf_actions =
                                            d.ensure_vrf_election_for_round(&election);
                                        let election_result = d.vrf_election_result(height, round);
                                        let should = d.can_propose()
                                            && election_result.is_some_and(|result| {
                                                Some(result.elected_validator_id)
                                                    == d.engine.validator_id()
                                            });
                                        (should, height, round, vrf_actions)
                                    }
                                }
                            };
                            if !vrf_actions.is_empty() {
                                let previous_height = driver.lock().unwrap().height();
                                process_driver_actions(
                                    &driver,
                                    &gossip,
                                    &height_tx,
                                    &handshake_config,
                                    previous_height,
                                    vrf_actions,
                                    &metrics_state,
                                    &last_block_timestamp,
                                );
                            }

                            let already_have_proposal = proposed_at_slot
                                == Some((next_height, proposal_round))
                                || driver
                                    .lock()
                                    .unwrap()
                                    .has_accepted_proposal_for_height(next_height);
                            let valid_reproposal = if should_propose {
                                driver.lock().unwrap().take_valid_block_for_reproposal()
                            } else {
                                None
                            };
                            let proposal_mode = choose_proposal_mode(
                                should_propose,
                                valid_reproposal.is_some(),
                                proposed_at_slot,
                                next_height,
                                proposal_round,
                                already_have_proposal,
                            );

                            if matches!(
                                proposal_mode,
                                ProposalMode::Fresh | ProposalMode::Reproposal
                            ) {
                                if proposal_failure_backoff_active(
                                    failed_proposal_at_slot,
                                    next_height,
                                    proposal_round,
                                ) {
                                    match height_rx.recv_timeout(Duration::from_millis(100)) {
                                        Ok(()) => {
                                            phase_started_at = Instant::now();
                                            proposed_at_slot = None;
                                            failed_proposal_at_slot = None;
                                        }
                                        Err(_) => {}
                                    }
                                    continue;
                                }

                                let time_since_last_commit = last_commit_time
                                    .and_then(|t| t.elapsed().ok())
                                    .unwrap_or(Duration::from_secs(MIN_BLOCK_INTERVAL_SECS));

                                if time_since_last_commit
                                    < Duration::from_secs(MIN_BLOCK_INTERVAL_SECS)
                                    && time_since_last_commit
                                        < Duration::from_secs(MIN_BLOCK_INTERVAL_SECS * 2)
                                {
                                    match height_rx.recv_timeout(Duration::from_millis(100)) {
                                        Ok(()) => {
                                            phase_started_at = Instant::now();
                                            proposed_at_slot = None;
                                        }
                                        Err(_) => {}
                                    }
                                    continue;
                                }

                                let proposal = {
                                    let mut d = driver.lock().unwrap();
                                    let height = d.engine.state.height + 1;
                                    let round = d.current_round();
                                    if height != next_height || round != proposal_round {
                                        eprintln!(
                                            "[consensus] proposal skipped: slot changed while preparing proposal (captured height={} round={}, current height={} round={})",
                                            next_height, proposal_round, height, round,
                                        );
                                        None
                                    } else {
                                        let election = match proposer_election_for_slot(
                                            &d, height, round,
                                        ) {
                                            Ok(election) => election,
                                            Err(error) => {
                                                eprintln!(
                                                        "[consensus] proposal construction authority unavailable at height={} round={}: {}",
                                                        height, round, error,
                                                    );
                                                continue;
                                            }
                                        };
                                        let election_result = d.vrf_election_result(height, round);
                                        if !election_result.is_some_and(|result| {
                                            Some(result.elected_validator_id)
                                                == d.engine.validator_id()
                                        }) {
                                            eprintln!(
                                                "[consensus] proposal skipped at height={} round={}: no current quorum-backed local election result for this validator",
                                                height, round,
                                            );
                                            None
                                        } else {
                                            let vrf_reveals = d.vrf_reveal_evidence(height, round);
                                            let timestamp = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap_or_default()
                                                .as_secs();
                                            let polc_round = d.proposal_polc_round(height);
                                            let last_qc_bytes = d.last_qc_bytes();
                                            let proposal_result = if matches!(
                                                proposal_mode,
                                                ProposalMode::Reproposal
                                            ) {
                                                let (valid_block, valid_round) = valid_reproposal
                                                    .expect(
                                                        "reproposal mode requires a valid block",
                                                    );
                                                d.engine.repropose(
                                                    &valid_block,
                                                    round,
                                                    Some(valid_round),
                                                    &election,
                                                    valid_block.header.timestamp,
                                                    last_qc_bytes,
                                                    election_result,
                                                    vrf_reveals.clone(),
                                                )
                                            } else {
                                                d.engine.propose(
                                                    &election,
                                                    timestamp,
                                                    last_qc_bytes,
                                                    polc_round,
                                                    election_result,
                                                    vrf_reveals.clone(),
                                                )
                                            };
                                            match proposal_result {
                                                Ok(block) => {
                                                    let actions =
                                                        d.process(DriverEvent::InboundBlock {
                                                            from: None,
                                                            block: block.clone(),
                                                        });
                                                    Some((block, actions))
                                                }
                                                Err(indra_node::error::NodeError::MissingQc {
                                                    height,
                                                }) => {
                                                    eprintln!(
                                                        "[consensus] proposal skipped at height {}: no QC for previous block",
                                                        height
                                                    );
                                                    None
                                                }
                                                Err(e) => {
                                                    eprintln!("[consensus] proposal failed: {}", e);
                                                    failed_proposal_at_slot =
                                                        Some(((height, round), Instant::now()));
                                                    None
                                                }
                                            }
                                        }
                                    }
                                };

                                if let Some((block, actions)) = proposal {
                                    proposed_at_slot =
                                        Some((block.header.height, block.header.proposer_round));
                                    process_driver_actions(
                                        &driver,
                                        &gossip,
                                        &height_tx,
                                        &handshake_config,
                                        height,
                                        actions,
                                        &metrics_state,
                                        &last_block_timestamp,
                                    );
                                }
                            }

                            if phase_started_at.elapsed() >= PROPOSE_TIMEOUT {
                                let actions = driver.lock().unwrap().on_propose_timeout();
                                process_driver_actions(
                                    &driver,
                                    &gossip,
                                    &height_tx,
                                    &handshake_config,
                                    height,
                                    actions,
                                    &metrics_state,
                                    &last_block_timestamp,
                                );
                                phase_started_at = Instant::now();
                            }
                        }
                        RoundPhase::Prevote => {
                            if phase_started_at.elapsed() >= PREVOTE_TIMEOUT {
                                let actions = driver.lock().unwrap().on_prevote_timeout();
                                process_driver_actions(
                                    &driver,
                                    &gossip,
                                    &height_tx,
                                    &handshake_config,
                                    height,
                                    actions,
                                    &metrics_state,
                                    &last_block_timestamp,
                                );
                                phase_started_at = Instant::now();
                            }
                        }
                        RoundPhase::Precommit => {
                            let actions = driver.lock().unwrap().retry_precommit_if_waiting();
                            if !actions.is_empty() {
                                process_driver_actions(
                                    &driver,
                                    &gossip,
                                    &height_tx,
                                    &handshake_config,
                                    height,
                                    actions,
                                    &metrics_state,
                                    &last_block_timestamp,
                                );
                            }
                            if phase_started_at.elapsed() >= PRECOMMIT_TIMEOUT {
                                let (old_round, height_before) = {
                                    let d = driver.lock().unwrap();
                                    (d.current_round(), d.height())
                                };
                                {
                                    let mut d = driver.lock().unwrap();
                                    d.on_precommit_timeout();
                                    if d.current_round() != old_round && d.current_round() > 0 {
                                        eprintln!(
                                            "[timing] t={}ms ROUND ADVANCED to {} at height={}",
                                            now_ms(),
                                            d.current_round(),
                                            height_before,
                                        );
                                    }
                                }
                                phase_started_at = Instant::now();
                            }
                        }
                    }
                }

                match height_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(()) => {
                        phase_started_at = Instant::now();
                        proposed_at_slot = None;
                    }
                    Err(_) => {}
                }
            }
        });
    }

    if !startup_qc_request.is_empty() {
        let current_height = driver.lock().unwrap().height();
        process_driver_actions(
            &driver,
            &gossip,
            &height_tx,
            &handshake_config,
            current_height,
            startup_qc_request,
            &metrics_state,
            &last_block_timestamp,
        );
    }

    // ── Thread 5: RPC server ────────────────────────────────────────────────
    // Inline HTTP/JSON-RPC handler — avoids circular dependency with indra-rpc.
    // Reads chain state directly from the driver under a brief lock.
    if rpc_should_start(cfg_file.rpc_enabled) {
        let rpc_addr = get_arg("--rpc-addr")
            .or_else(|| cfg_file.rpc_addr.clone())
            .unwrap_or_else(|| "127.0.0.1:8545".to_string());
        if let Some(warning) = rpc_non_loopback_warning(&rpc_addr) {
            eprintln!("{}", warning);
        }
        spawn_rpc_listener(
            "rpc",
            rpc_addr,
            indra_rpc::handlers::RpcMode::Full,
            RpcListenerPolicy::full(),
            Arc::clone(&driver),
            Arc::clone(&gossip),
            Arc::clone(&discovered_peers),
            Arc::clone(&op_relay_seen),
            Arc::clone(&observer_count),
            cfg_file.rpc_cors_origins.clone(),
            cfg_file
                .rpc_admin_token
                .clone()
                .filter(|token| !token.trim().is_empty()),
        );
    } else {
        eprintln!("[rpc] RPC server disabled by config");
    }

    if rpc_public_should_start(cfg_file.rpc_public_enabled) {
        let rpc_public_addr = cfg_file
            .rpc_public_addr
            .clone()
            .filter(|addr| !addr.trim().is_empty())
            .unwrap_or_else(|| "127.0.0.1:8547".to_string());
        if let Some(warning) = rpc_public_non_loopback_warning(&rpc_public_addr) {
            eprintln!("[rpc-public] {}", warning);
        }
        spawn_rpc_listener(
            "rpc-public",
            rpc_public_addr,
            indra_rpc::handlers::RpcMode::ReadOnly,
            RpcListenerPolicy::public_from_config(&cfg_file),
            Arc::clone(&driver),
            Arc::clone(&gossip),
            Arc::clone(&discovered_peers),
            Arc::clone(&op_relay_seen),
            Arc::clone(&observer_count),
            cfg_file.rpc_public_cors_origins.clone(),
            None,
        );
    }

    // ── Main thread: status printer ─────────────────────────────────────────
    let mut last_height = 0u64;
    let mut tick = 0u64;
    let bootstrap_peer_addrs_main: HashSet<String> = bootstrap_peers.iter().cloned().collect();
    let genesis_peer_addrs_main: HashSet<String> = genesis_seed_peers.iter().cloned().collect();

    loop {
        std::thread::sleep(STATUS_INTERVAL);
        tick += 1;

        let (height, base_fee, mempool, peers) = {
            let d = driver.lock().unwrap();
            (
                d.height(),
                d.engine.state.base_fee,
                d.engine.mempool.len(),
                gossip.connection_count(),
            )
        };

        let new_blocks = height.saturating_sub(last_height);
        let progress = if new_blocks > 0 {
            format!(" [+{} blocks]", new_blocks)
        } else {
            String::new()
        };

        println!(
            "[tick {}] height={}{} base_fee={} mempool={} txs peers={}",
            tick, height, progress, base_fee, mempool, peers
        );

        if tick.is_multiple_of(10) {
            check_disk_space(Path::new(&data_dir));
        }

        {
            let on_chain_addrs = {
                let d = driver.lock().unwrap();
                let consensus_height = d.height().saturating_add(1);
                match on_chain_validator_network_addrs_for_height(&d.engine, consensus_height) {
                    Ok(addrs) => addrs,
                    Err(error) => {
                        eprintln!(
                            "[discovery] failed to resolve snapshot authority for height {}: {}; skipping on-chain validator discovery for this cycle",
                            consensus_height, error
                        );
                        Vec::new()
                    }
                }
            };
            if !on_chain_addrs.is_empty() {
                let local_validator_id = handshake_config.read().unwrap().my_validator_id;
                let connected = gossip.connected_addrs();
                let authenticated = authenticated_peer_addrs.lock().unwrap().clone();
                let accepted = insert_on_chain_validator_network_addrs(
                    &mut discovered_peers.lock().unwrap(),
                    &authenticated,
                    &bootstrap_peer_addrs_main,
                    &genesis_peer_addrs_main,
                    &p2p_addr,
                    local_validator_id,
                    &connected,
                    on_chain_addrs,
                );
                if accepted > 0 {
                    eprintln!(
                        "[discovery] accepted {} on-chain active validator peer address(es)",
                        accepted
                    );
                }
            }
        }

        let peer_list_ticks = (PEER_LIST_INTERVAL_SECS / STATUS_INTERVAL.as_secs()).max(1);
        if tick.is_multiple_of(peer_list_ticks) {
            let self_addrs = configured_self_addr_set(&p2p_addr);
            let known_addrs = peer_list_payload_with_identities(
                gossip.connected_addrs(),
                None,
                &self_addrs,
                &gossip.addr_validators.lock().unwrap(),
            );
            if !known_addrs.is_empty() {
                gossip.broadcast(&Message::PeerList(known_addrs));
            }
        }

        last_height = height;
    }
}

fn broadcast_driver_message(gossip: &Arc<NetworkBridge>, _action: &DriverAction, msg: &Message) {
    gossip.broadcast(msg);
}

fn process_driver_actions(
    driver: &Arc<Mutex<ConsensusDriver>>,
    gossip: &Arc<NetworkBridge>,
    height_tx: &std::sync::mpsc::Sender<()>,
    handshake_config: &Arc<RwLock<HandshakeConfig>>,
    previous_height: u64,
    actions: Vec<DriverAction>,
    metrics_state: &Arc<MetricsState>,
    last_block_timestamp: &Arc<AtomicU64>,
) {
    let mut recorded_commit = false;
    for action in actions {
        if let DriverAction::ActivateBufferedProposal(block) = action {
            let actions2 = driver
                .lock()
                .unwrap()
                .process(DriverEvent::InboundBlock { from: None, block });
            process_driver_actions(
                driver,
                gossip,
                height_tx,
                handshake_config,
                previous_height,
                actions2,
                metrics_state,
                last_block_timestamp,
            );
            let new_height = driver.lock().unwrap().height();
            if new_height > previous_height {
                refresh_handshake_and_relay_config(
                    &driver.lock().unwrap().engine,
                    handshake_config,
                    gossip,
                );
                if !recorded_commit {
                    record_block_commit(metrics_state, last_block_timestamp);
                    recorded_commit = true;
                }
                let _ = height_tx.send(());
                broadcast_status(driver, gossip);
            }
            continue;
        }

        if let DriverAction::RequestQC { height } = &action {
            let peers: Vec<SocketAddr> = gossip.connected_addrs();
            eprintln!(
                "[driver] requesting QC for height {} from {} peers",
                height,
                peers.len()
            );
            let msg = Message::RequestQC { height: *height };
            for peer in &peers {
                if let Some(peer_validator_id) = gossip.validator_for_addr(peer) {
                    gossip.send_to_validator(peer_validator_id, &msg);
                }
            }
            continue;
        }

        if let DriverAction::RequestVrfReveals {
            height,
            round,
            missing_validator_ids,
        } = &action
        {
            let peers: Vec<SocketAddr> = gossip.connected_addrs();
            eprintln!(
                "[vrf] requesting {} reveal(s) for height={} round={} from {} peers",
                missing_validator_ids.len(),
                height,
                round,
                peers.len()
            );
            let msg = Message::RequestVrfReveals {
                height: *height,
                round: *round,
                validator_ids: missing_validator_ids.clone(),
            };
            for peer in &peers {
                if let Some(peer_validator_id) = gossip.validator_for_addr(peer) {
                    gossip.send_to_validator(peer_validator_id, &msg);
                }
            }
            continue;
        }

        if let DriverAction::SlashDetected(slash_evidence) = &action {
            metrics_state
                .slash_events_total
                .fetch_add(1, Ordering::Relaxed);
            let wire_evidence = indra_core::types::slashing::SlashEvidenceV1 {
                validator_id: slash_evidence.validator_id,
                vote_1: slash_evidence.vote_a.clone(),
                vote_2: slash_evidence.vote_b.clone(),
            };
            let mut d = driver.lock().unwrap();
            d.engine.add_slash_evidence(wire_evidence);
            eprintln!(
                "[slash] equivocation detected from validator {} — evidence queued",
                hex::encode(&slash_evidence.validator_id.0[..4])
            );
            continue;
        }

        if let DriverAction::DisconnectInvalidConsensusPeer {
            from,
            validator_id,
            reason,
        } = &action
        {
            eprintln!(
                "[p2p] invalid consensus message from {} claiming validator {}: {}",
                from,
                hex::encode(&validator_id.0[..4]),
                reason
            );
            gossip.disconnect_invalid_consensus_peer(from, reason.clone());
            continue;
        }

        if let Some(out_msg) = action_to_message(&action) {
            if let DriverAction::BroadcastVote(vote) = &action {
                eprintln!(
                    "[vote] broadcasting {:?} for height={} round={}",
                    vote.step, vote.height, vote.round,
                );
            }
            broadcast_driver_message(gossip, &action, &out_msg);
        }

        if let DriverAction::RequestBlocks {
            from,
            from_height,
            to_height,
        } = &action
        {
            if should_log_sync_height(*from_height)
                || to_height.saturating_sub(*from_height) < SYNC_BATCH_SIZE
            {
                eprintln!(
                    "[sync] requesting blocks {}..{} from {}",
                    from_height, to_height, from
                );
            }
            let req = Message::RequestBlocks {
                from_height: *from_height,
                to_height: *to_height,
            };
            if let Some(peer_validator_id) = gossip.validator_for_addr(from) {
                gossip.send_to_validator(peer_validator_id, &req);
            }
        }

        if let DriverAction::RequestProposal {
            from,
            height,
            round,
            hash,
        } = &action
        {
            let req = Message::RequestProposal {
                height: *height,
                round: *round,
                hash: *hash,
            };
            if let Some(peer_validator_id) = gossip.validator_for_addr(from) {
                gossip.send_to_validator(peer_validator_id, &req);
            }
        }

        if let DriverAction::SendQCResponse {
            to,
            height,
            qc_bytes,
        } = &action
        {
            let msg = Message::QCResponse {
                height: *height,
                qc_bytes: qc_bytes.clone(),
            };
            if let Some(peer_validator_id) = gossip.validator_for_addr(to) {
                gossip.send_to_validator(peer_validator_id, &msg);
            }
        }

        if let DriverAction::SendVrfRevealsResponse {
            to,
            height,
            round,
            reveals,
        } = &action
        {
            let msg = Message::VrfRevealsResponse {
                height: *height,
                round: *round,
                reveals: reveals.clone(),
            };
            if let Some(peer_validator_id) = gossip.validator_for_addr(to) {
                gossip.send_to_validator(peer_validator_id, &msg);
            }
        }

        let new_height = driver.lock().unwrap().height();
        if new_height > previous_height && !recorded_commit {
            record_block_commit(metrics_state, last_block_timestamp);
            recorded_commit = true;
        }
    }
}

fn announce_status_and_recovery(
    driver: &Arc<Mutex<ConsensusDriver>>,
    gossip: &Arc<NetworkBridge>,
    height_tx: &std::sync::mpsc::Sender<()>,
    handshake_config: &Arc<RwLock<HandshakeConfig>>,
    validator_id: indra_core::Bytes32,
    metrics_state: &Arc<MetricsState>,
    last_block_timestamp: &Arc<AtomicU64>,
) {
    let (height, tip_hash) = {
        let d = driver.lock().unwrap();
        (d.height(), d.engine.state.tip_hash)
    };
    let [status, ping] = startup_peer_messages(height, tip_hash);
    gossip.send_to_validator(validator_id, &status);
    gossip.send_to_validator(validator_id, &ping);
    broadcast_status(driver, gossip);

    let actions = driver.lock().unwrap().request_qc_if_needed();
    process_driver_actions(
        driver,
        gossip,
        height_tx,
        handshake_config,
        height,
        actions,
        metrics_state,
        last_block_timestamp,
    );
}

fn startup_peer_messages(height: u64, tip_hash: indra_core::Bytes32) -> [Message; 2] {
    [
        Message::Status {
            height,
            tip_hash,
            round: 0,
        },
        Message::Ping(now_ms() as u64),
    ]
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn should_log_sync_height(height: u64) -> bool {
    height <= 5 || height.is_multiple_of(100)
}

fn broadcast_status(driver: &Arc<Mutex<ConsensusDriver>>, gossip: &Arc<NetworkBridge>) {
    let (height, tip_hash, round) = {
        let d = driver.lock().unwrap();
        (d.height(), d.engine.state.tip_hash, d.current_round())
    };
    let status = Message::Status {
        height,
        tip_hash,
        round,
    };
    gossip.broadcast(&status);
}

fn check_disk_space(data_dir: &Path) -> u64 {
    let available = available_space(data_dir).unwrap_or(0);
    if available > 0 && available < DISK_CRITICAL_THRESHOLD_BYTES {
        eprintln!(
            "[disk] CRITICAL: only {} MB remaining",
            available / 1024 / 1024
        );
    } else if available > 0 && available < DISK_WARN_THRESHOLD_BYTES {
        eprintln!(
            "[disk] WARNING: only {} GB remaining",
            available / 1024 / 1024 / 1024
        );
    }
    available
}

fn print_help() {
    println!("Usage: indra-node [--config <path>] [flags]");
    println!();
    println!("  --config <path>         Load configuration from config.toml");
    println!("  --init                  Generate a config.toml interactively");
    println!("  --help                  Show this help");
    println!();
    println!("All flags below override the corresponding config.toml field:");
    println!("  --keys <path>");
    println!("  --data-dir <path>");
    println!("  --genesis <path>");
    println!("  --p2p-addr <host:port>");
    println!("  --observer-addr <host:port>");
    println!("  --no-observer-port");
    println!("  --rpc-addr <host:port>");
    println!("  --rpc-public-addr <host:port>  Enable read-only public RPC listener");
    println!("  --metrics-addr <addr>");
    println!("  --no-metrics");
    println!("  --bootstrap-peers <addr,addr,...>");
    println!("  --seeds <hostname>");
    println!("  --prune-keep <blocks>");
    println!("  --archive");
    println!("  --peers-file <path>");
}

fn run_init() {
    let name = prompt_default("Validator name (e.g. your name or city)", "validator");
    let data_dir = prompt_default("Data directory", "/root/.indra/data");
    let default_keys = Path::new(&data_dir)
        .join("keys.json")
        .to_string_lossy()
        .to_string();
    let keys_file = prompt_default("Keys file", &default_keys);
    let default_genesis = Path::new(&data_dir)
        .join("genesis.toml")
        .to_string_lossy()
        .to_string();
    let genesis_file = prompt_default("Genesis file", &default_genesis);
    let bootstrap_peers = prompt_default(
        "Bootstrap peers (comma-separated, leave blank for bootstrap node)",
        "",
    );
    let metrics_addr = prompt_default("Metrics address", "0.0.0.0:9615");
    let rpc_addr = prompt_default("RPC address", "127.0.0.1:8545");
    let prune_keep = prompt_default("Prune keep blocks [50000, 0=archive]", "50000");
    let config_path = Path::new(&data_dir).join("config.toml");
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        eprintln!("ERROR: cannot create data directory {}: {}", data_dir, e);
        std::process::exit(1);
    }
    let bootstrap_toml = bootstrap_peers_toml(&bootstrap_peers);
    let config = format!(
        r#"# INDRA Node Configuration
# Generated by: indra-node --init
# Version: {}

[node]
mode     = "validator"
chain_id = "indra-testnet-1"
data_dir = "{}"
genesis  = "{}"

[keys]
path = "{}"
# Required when path points to an encrypted keystore. File must be mode 0600.
# password_file = "{}/keys.pass"

[network]
p2p_addr        = "0.0.0.0:30303"
observer_addr   = "0.0.0.0:{}"
bootstrap_peers = {}
dns_seed_host   = "{}"
# off = ordinary DNS, warn = log DNSSEC problems but use answers, require = secure answers only.
dns_seed_validation = "warn"
# Signed DNS discovery is INDRA's EIP-1459-style overlay. It requires an
# independently configured ML-DSA-87 public key; DNS only transports the list.
dns_seed_signed_validation = "off"
# dns_seed_signed_public_key = "<ML-DSA-87 public key hex>"
peers_file      = "{}/peers.json"

[rpc]
addr    = "{}"
enabled = true
# Empty admin token disables privileged RPC topology details.
admin_token = ""
# Empty allowlist means browsers receive no cross-origin access by default.
cors_origins = []

[rpc_public]
# Optional read-only listener for public reverse proxies. Writes are rejected
# at the RPC dispatch layer before any submission path is reachable.
addr    = "127.0.0.1:8547"
enabled = false
cors_origins = []

[metrics]
addr    = "{}"
enabled = true

[storage]
prune_keep_blocks = {}
snapshot_interval = 300
mempool_capacity  = 5000
"#,
        env!("CARGO_PKG_VERSION"),
        toml_escape(&data_dir),
        toml_escape(&genesis_file),
        toml_escape(&keys_file),
        toml_escape(&data_dir),
        OBSERVER_PORT,
        bootstrap_toml,
        DNS_SEED_HOSTS.join(","),
        toml_escape(&data_dir),
        toml_escape(&rpc_addr),
        toml_escape(&metrics_addr),
        prune_keep
    );
    if let Err(e) = std::fs::write(&config_path, config) {
        eprintln!("ERROR: cannot write {}: {}", config_path.display(), e);
        std::process::exit(1);
    }
    println!("══════════════════════════════════════════");
    println!("  config.toml written to: {}", config_path.display());
    println!("  Validator name: {}", name);
    println!("══════════════════════════════════════════");
    println!();
    println!("  Systemd service file (copy to /etc/systemd/system/indra-node.service):");
    println!("  ─────────────────────────────────────────────────────────────────────");
    println!("  [Unit]");
    println!("  Description=INDRA Validator Node");
    println!("  After=network-online.target");
    println!("  Wants=network-online.target");
    println!();
    println!("  [Service]");
    println!("  Type=simple");
    println!("  User=root");
    println!(
        "  ExecStart=/root/.indra/bin/indra-node --config {}",
        config_path.display()
    );
    println!("  Restart=always");
    println!("  RestartSec=5");
    println!("  LimitNOFILE=65536");
    println!("  StandardOutput=journal");
    println!("  StandardError=journal");
    println!("  SyslogIdentifier=indra-node");
    println!();
    println!("  [Install]");
    println!("  WantedBy=multi-user.target");
    println!("  ─────────────────────────────────────────────────────────────────────");
    println!();
    println!("  Next steps:");
    println!("  1. sudo tee /etc/systemd/system/indra-node.service");
    println!("  2. sudo systemctl daemon-reload");
    println!("  3. sudo systemctl enable indra-node");
    println!("  4. sudo systemctl start indra-node");
    println!("══════════════════════════════════════════");
}

fn prompt_default(prompt: &str, default: &str) -> String {
    if default.is_empty() {
        print!("{}: ", prompt);
    } else {
        print!("{} [{}]: ", prompt, default);
    }
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return default.to_string();
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

fn bootstrap_peers_toml(raw: &str) -> String {
    let peers: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!("\"{}\"", toml_escape(s)))
        .collect();
    if peers.is_empty() {
        "[]".to_string()
    } else {
        format!("[{}]", peers.join(", "))
    }
}

fn toml_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn load_keys_data(keys_path: &str, password_file: Option<&str>) -> KeysData {
    let password_source = match password_file {
        Some(path) => indra_keystore::PasswordSource::File {
            path: Path::new(path),
            reject_permissive: true,
        },
        None => indra_keystore::PasswordSource::None,
    };
    let keys = indra_keystore::load_keys(keys_path, password_source).unwrap_or_else(|e| {
        panic!(
            "Cannot load {}: {}. Encrypted validator keys require [keys].password_file or --keys-password-file for unattended startup.",
            keys_path, e
        )
    });
    KeysData {
        hybrid_seed: keys.hybrid_seed,
        vrf_seed: keys.vrf_seed,
        pq_sk: keys.pq_sk,
        pq_pk: keys.public.hybrid_pq_pk,
    }
}

fn reserve_rpc_connection(count: &AtomicU64) -> bool {
    let mut current = count.load(Ordering::Relaxed);
    loop {
        if current >= MAX_RPC_CONNECTIONS {
            return false;
        }
        match count.compare_exchange_weak(
            current,
            current.saturating_add(1),
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

fn release_rpc_connection(count: &AtomicU64) {
    let _ = count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_sub(1))
    });
}

fn rpc_non_loopback_warning(addr: &str) -> Option<String> {
    let parsed = addr.parse::<SocketAddr>().ok()?;
    if parsed.ip().is_loopback() {
        None
    } else {
        Some(format!(
            "WARNING: full RPC listener binding to non-loopback address {}. This listener can accept signed submissions and admin methods; do not expose it directly to the public internet. Bind to 127.0.0.1 or a private interface and protect it with firewall rules.",
            parsed
        ))
    }
}

fn rpc_public_non_loopback_warning(addr: &str) -> Option<String> {
    let parsed = addr.parse::<SocketAddr>().ok()?;
    if parsed.ip().is_loopback() {
        None
    } else {
        Some(format!(
            "WARNING: rpc_public listener binding to non-loopback address {}. This read-only listener is designed for public consumers only with public-endpoint hardening; mainnet operators should still place it behind a reverse proxy/CDN/WAF with TLS, additional rate limits, logging, and monitoring.",
            parsed
        ))
    }
}

fn rpc_should_start(enabled: Option<bool>) -> bool {
    enabled.unwrap_or(true)
}

fn rpc_public_should_start(enabled: Option<bool>) -> bool {
    enabled.unwrap_or(false)
}

fn spawn_rpc_listener(
    label: &'static str,
    rpc_addr: String,
    mode: indra_rpc::handlers::RpcMode,
    policy: RpcListenerPolicy,
    driver: Arc<Mutex<indra_node::driver::ConsensusDriver>>,
    gossip: Arc<NetworkBridge>,
    discovered_peers: Arc<Mutex<HashSet<String>>>,
    op_relay_seen: Arc<Mutex<OpRelaySeenCache>>,
    observer_count: Arc<AtomicUsize>,
    cors_origins: Vec<String>,
    admin_token: Option<String>,
) {
    let rpc_cors_origins = Arc::new(cors_origins);
    let admin_token = Arc::new(admin_token);
    let policy = Arc::new(policy);
    let rpc_conn_count = Arc::new(AtomicU64::new(0));
    let rpc_rate_limiter = Arc::new(indra_rpc::server::RpcRateLimiter::new());
    let rpc_global_rate_limiter = policy
        .global_rate_per_sec
        .zip(policy.global_burst)
        .map(|(rate, burst)| Arc::new(indra_rpc::server::RpcGlobalRateLimiter::new(rate, burst)));
    let expensive_limiter = Arc::new(indra_rpc::server::RpcWindowRateLimiter::new());
    let expensive_global_limiter = Arc::new(indra_rpc::server::RpcGlobalWindowRateLimiter::new());
    let rejection_counters = Arc::new(RpcRejectionCounters::default());
    eprintln!("[{}] listening on {} ({:?})", label, rpc_addr, mode);

    std::thread::spawn(move || {
        let listener = match std::net::TcpListener::bind(&rpc_addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[{}] bind failed: {}", label, e);
                return;
            }
        };
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if !reserve_rpc_connection(&rpc_conn_count) {
                        eprintln!(
                            "[{}] connection limit reached ({}), dropping new connection",
                            label, MAX_RPC_CONNECTIONS
                        );
                        drop(stream);
                        continue;
                    }
                    let peer_ip = stream.peer_addr().ok().map(|addr| addr.ip());
                    let driver_rpc = Arc::clone(&driver);
                    let gossip_rpc = Arc::clone(&gossip);
                    let discovered_peers_rpc = Arc::clone(&discovered_peers);
                    let op_relay_seen_rpc = Arc::clone(&op_relay_seen);
                    let observer_count_rpc = Arc::clone(&observer_count);
                    let rpc_conn_count = Arc::clone(&rpc_conn_count);
                    let rpc_rate_limiter = Arc::clone(&rpc_rate_limiter);
                    let rpc_global_rate_limiter = rpc_global_rate_limiter.clone();
                    let expensive_limiter = Arc::clone(&expensive_limiter);
                    let expensive_global_limiter = Arc::clone(&expensive_global_limiter);
                    let rejection_counters = Arc::clone(&rejection_counters);
                    let rpc_cors_origins = Arc::clone(&rpc_cors_origins);
                    let admin_token = Arc::clone(&admin_token);
                    let policy = Arc::clone(&policy);
                    std::thread::spawn(move || {
                        handle_rpc(
                            stream,
                            &driver_rpc,
                            &gossip_rpc,
                            &discovered_peers_rpc,
                            &op_relay_seen_rpc,
                            &observer_count_rpc,
                            peer_ip,
                            &rpc_rate_limiter,
                            rpc_global_rate_limiter.as_deref(),
                            &expensive_limiter,
                            &expensive_global_limiter,
                            &rejection_counters,
                            &rpc_cors_origins,
                            mode,
                            &policy,
                            admin_token.as_ref().as_deref(),
                        );
                        release_rpc_connection(&rpc_conn_count);
                    });
                }
                Err(e) => eprintln!("[{}] accept error: {}", label, e),
            }
        }
    });
}

struct RpcSnapshot {
    chain: indra_state::ChainState,
    mempool_size: usize,
    pruned_mode: bool,
    lowest_block: u64,
    blocks_retained: usize,
    requested_block: Option<(u64, indra_core::types::block::BlockV1)>,
    latest_epoch: Option<u64>,
    epoch_records: HashMap<u64, indra_core::EpochRecord>,
}

impl indra_rpc::handlers::RpcEngineView for RpcSnapshot {
    fn chain_state(&self) -> &indra_state::ChainState {
        &self.chain
    }

    fn mempool_size(&self) -> usize {
        self.mempool_size
    }

    fn pruned_mode(&self) -> bool {
        self.pruned_mode
    }

    fn lowest_block(&self) -> u64 {
        self.lowest_block
    }

    fn blocks_retained(&self) -> usize {
        self.blocks_retained
    }

    fn get_block_by_height(
        &self,
        height: u64,
    ) -> Result<Option<indra_core::types::block::BlockV1>, String> {
        Ok(self
            .requested_block
            .as_ref()
            .filter(|(block_height, _)| *block_height == height)
            .map(|(_, block)| block.clone()))
    }

    fn get_epoch_record(&self, epoch: u64) -> Result<Option<indra_core::EpochRecord>, String> {
        Ok(self.epoch_records.get(&epoch).cloned())
    }

    fn latest_epoch(&self) -> Result<Option<u64>, String> {
        Ok(self.latest_epoch)
    }

    fn get_epoch_range(
        &self,
        to_epoch: u64,
        limit: usize,
    ) -> Result<Vec<indra_core::EpochRecord>, String> {
        let mut epochs: Vec<u64> = self
            .epoch_records
            .keys()
            .copied()
            .filter(|epoch| *epoch <= to_epoch)
            .collect();
        epochs.sort_by(|a, b| b.cmp(a));
        Ok(epochs
            .into_iter()
            .take(limit)
            .filter_map(|epoch| self.epoch_records.get(&epoch).cloned())
            .collect())
    }
}

fn snapshot_rpc_state(
    driver: &Arc<Mutex<indra_node::driver::ConsensusDriver>>,
    req: &indra_rpc::types::RpcRequest,
) -> Result<RpcSnapshot, String> {
    let guard = driver
        .lock()
        .map_err(|_| "consensus driver lock poisoned".to_string())?;
    let engine = &guard.engine;
    let requested_block_height = requested_block_height_for_rpc(req, &engine.state);
    let requested_block = match requested_block_height {
        Some(height) => match engine.block_store.get_read_only(height) {
            Ok(block) => Some((height, block)),
            Err(indra_storage::StorageError::BlockNotFound { .. })
            | Err(indra_storage::StorageError::BlockPruned { .. }) => None,
            Err(error) => return Err(error.to_string()),
        },
        None => None,
    };
    let latest_epoch = engine.epoch_store.latest_epoch();
    let epoch_records = match latest_epoch {
        Some(latest) => {
            let limit = usize::try_from(latest.saturating_add(1))
                .unwrap_or(usize::MAX)
                .min(10_000);
            engine
                .epoch_store
                .get_range(latest, limit)
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|record| (record.epoch, record))
                .collect()
        }
        None => HashMap::new(),
    };
    Ok(RpcSnapshot {
        chain: engine.state.clone(),
        mempool_size: engine.mempool.len(),
        pruned_mode: !engine.block_store.is_archive(),
        lowest_block: engine.block_store.lowest_height(),
        blocks_retained: engine.block_store.len(),
        requested_block,
        latest_epoch,
        epoch_records,
    })
}

fn requested_block_height_for_rpc(
    req: &indra_rpc::types::RpcRequest,
    chain: &indra_state::ChainState,
) -> Option<u64> {
    match req.method.as_str() {
        "indra_getBlock" | "indra_getTransaction" => req
            .params
            .first()
            .and_then(|param| indra_rpc::types::unquote(param).parse::<u64>().ok()),
        "indra_explainUtxoProvenanceAuthorized" => provenance_requested_block_height(req, chain),
        _ => None,
    }
}

fn provenance_requested_block_height(
    req: &indra_rpc::types::RpcRequest,
    chain: &indra_state::ChainState,
) -> Option<u64> {
    let utxo_hex = req
        .params
        .get(2)
        .map(|param| indra_rpc::types::unquote(param))?;
    let bytes = hex::decode(utxo_hex).ok()?;
    let raw: [u8; 32] = bytes.try_into().ok()?;
    chain
        .utxos
        .get(&indra_core::Bytes32::from(raw))
        .map(|entry| entry.created_height)
}

#[allow(clippy::too_many_arguments)]
fn dispatch_public_light_method(
    method: &str,
    driver: &Arc<Mutex<indra_node::driver::ConsensusDriver>>,
    connected_validator_peer_count: usize,
    discovered_count: usize,
    observer_count_val: usize,
    rpc_mode: indra_rpc::handlers::RpcMode,
    admin_token_configured: bool,
    rejection_counters: &RpcRejectionCounters,
) -> Option<indra_rpc::RpcResult<String>> {
    if rpc_mode != indra_rpc::handlers::RpcMode::ReadOnly {
        return None;
    }
    if !public_light_method_avoids_full_snapshot(method) {
        return None;
    }
    match method {
        "indra_getHeight" => Some(
            driver
                .lock()
                .map_err(|_| indra_rpc::RpcError::Internal("consensus driver lock poisoned".into()))
                .map(|guard| format!(r#"{{"height":{}}}"#, guard.engine.state.height)),
        ),
        "indra_getTip" => Some(
            driver
                .lock()
                .map_err(|_| indra_rpc::RpcError::Internal("consensus driver lock poisoned".into()))
                .map(|guard| {
                    format!(
                        r#"{{"height":{},"tip_hash":"{}"}}"#,
                        guard.engine.state.height,
                        hex::encode(guard.engine.state.tip_hash.0)
                    )
                }),
        ),
        "indra_getMempoolSize" => Some(
            driver
                .lock()
                .map_err(|_| indra_rpc::RpcError::Internal("consensus driver lock poisoned".into()))
                .map(|guard| format!(r#"{{"size":{}}}"#, guard.engine.mempool.len())),
        ),
        "indra_getPeers" => Some(Ok(format!(
            r#"{{"peer_count":{},"target_peers":{},"discovered_count":{},"observer_peer_count":{}}}"#,
            connected_validator_peer_count,
            indra_core::types::primitives::TARGET_OUTBOUND_PEERS,
            discovered_count,
            observer_count_val,
        ))),
        "indra_getRpcPolicy" => Some(Ok(public_rpc_policy_json(
            admin_token_configured,
            rejection_counters,
        ))),
        _ => None,
    }
}

fn public_rpc_policy_json(
    admin_token_configured: bool,
    rejection_counters: &RpcRejectionCounters,
) -> String {
    format!(
        r#"{{"listener_mode":"read_only","admin_token_configured":{},"admin_token_value_exposed":false,"public_rejections":{{"per_ip_rate_limited":{},"global_rate_limited":{},"expensive_method_limited":{},"auth_failures":{},"oversized_bodies":{},"timeouts_or_incomplete_reads":{}}}}}"#,
        admin_token_configured,
        rejection_counters
            .per_ip_rate_limited
            .load(Ordering::Relaxed),
        rejection_counters
            .global_rate_limited
            .load(Ordering::Relaxed),
        rejection_counters
            .expensive_method_limited
            .load(Ordering::Relaxed),
        rejection_counters.auth_failures.load(Ordering::Relaxed),
        rejection_counters.oversized_bodies.load(Ordering::Relaxed),
        rejection_counters
            .timeouts_or_incomplete_reads
            .load(Ordering::Relaxed),
    )
}

fn public_light_method_avoids_full_snapshot(method: &str) -> bool {
    matches!(
        method,
        "indra_getHeight"
            | "indra_getTip"
            | "indra_getMempoolSize"
            | "indra_getPeers"
            | "indra_getRpcPolicy"
    )
}

fn public_expensive_method_allowed(
    method: &str,
    peer_ip: Option<IpAddr>,
    expensive_limiter: &indra_rpc::server::RpcWindowRateLimiter,
    expensive_global_limiter: &indra_rpc::server::RpcGlobalWindowRateLimiter,
) -> bool {
    if indra_rpc::server::rpc_method_cost(method) != indra_rpc::server::RpcMethodCost::Expensive {
        return true;
    }
    let per_ip_allowed = peer_ip
        .map(|ip| expensive_limiter.allow(ip, indra_rpc::server::RPC_PUBLIC_EXPENSIVE_RATE_PER_MIN))
        .unwrap_or(true);
    let global_allowed =
        expensive_global_limiter.allow(indra_rpc::server::RPC_PUBLIC_EXPENSIVE_GLOBAL_RATE_PER_MIN);
    per_ip_allowed && global_allowed
}

/// Inline JSON-RPC handler for the node binary.
///
/// Reads one HTTP request, dispatches to the appropriate chain query,
/// and writes the JSON response. Locks the driver only for the duration
/// of the state read — not while writing the HTTP response.
fn handle_rpc(
    stream: std::net::TcpStream,
    driver: &Arc<Mutex<indra_node::driver::ConsensusDriver>>,
    gossip: &Arc<NetworkBridge>,
    discovered_peers: &Arc<Mutex<HashSet<String>>>,
    op_relay_seen: &Arc<Mutex<OpRelaySeenCache>>,
    observer_count: &Arc<AtomicUsize>,
    peer_ip: Option<IpAddr>,
    rate_limiter: &indra_rpc::server::RpcRateLimiter,
    global_rate_limiter: Option<&indra_rpc::server::RpcGlobalRateLimiter>,
    expensive_limiter: &indra_rpc::server::RpcWindowRateLimiter,
    expensive_global_limiter: &indra_rpc::server::RpcGlobalWindowRateLimiter,
    rejection_counters: &RpcRejectionCounters,
    cors_origins: &[String],
    rpc_mode: indra_rpc::handlers::RpcMode,
    policy: &RpcListenerPolicy,
    configured_admin_token: Option<&str>,
) {
    use indra_rpc::handlers::{
        check_rpc_method_allowed_with_admin, dispatch_with_admin, DispatchResult, NodeState,
    };
    use indra_rpc::types::RpcResponse;
    use std::io::{BufRead, BufReader, Read};

    let _ = stream.set_read_timeout(Some(policy.request_timeout));
    let _ = stream.set_write_timeout(Some(policy.request_timeout));

    if let Some(ip) = peer_ip {
        if !rate_limiter.allow_with_limits(ip, policy.per_ip_rate_per_sec, policy.per_ip_burst) {
            rejection_counters
                .per_ip_rate_limited
                .fetch_add(1, Ordering::Relaxed);
            eprintln!("[rpc] per-IP rate limit rejected request from {ip}");
            let response = indra_rpc::server::rpc_rate_limited_response();
            let _ = stream
                .try_clone()
                .map(|mut writer| writer.write_all(response.as_bytes()));
            return;
        }
    }
    if let Some(global_limiter) = global_rate_limiter {
        if !global_limiter.allow() {
            rejection_counters
                .global_rate_limited
                .fetch_add(1, Ordering::Relaxed);
            eprintln!("[rpc] global rate limit rejected request");
            let response = indra_rpc::server::rpc_rate_limited_response();
            let _ = stream
                .try_clone()
                .map(|mut writer| writer.write_all(response.as_bytes()));
            return;
        }
    }

    let mut reader = match stream.try_clone() {
        Ok(stream) => BufReader::new(stream),
        Err(_) => return,
    };

    let mut content_length = 0usize;
    let mut method = String::new();
    let mut origin: Option<String> = None;
    let mut presented_admin_token: Option<String> = None;
    let mut line = String::new();
    let mut first_line = true;

    loop {
        line.clear();
        if reader.read_line(&mut line).is_err() {
            rejection_counters
                .timeouts_or_incomplete_reads
                .fetch_add(1, Ordering::Relaxed);
            eprintln!("[rpc] incomplete or timed-out header read");
            return;
        }
        let trimmed = line.trim();
        if first_line {
            method = trimmed
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();
            first_line = false;
        }
        if trimmed.is_empty() {
            break;
        }
        if trimmed.to_lowercase().starts_with("content-length:") {
            content_length = trimmed["content-length:".len()..]
                .trim()
                .parse()
                .unwrap_or(0);
        }
        if trimmed.to_lowercase().starts_with("origin:") {
            origin = Some(trimmed["origin:".len()..].trim().to_string());
        }
        if trimmed.to_lowercase().starts_with("x-admin-token:") {
            presented_admin_token = Some(trimmed["x-admin-token:".len()..].trim().to_string());
        }
    }

    let cors = indra_rpc::server::cors_headers(origin.as_deref(), cors_origins);

    if method == "OPTIONS" {
        let resp = format!(
            "HTTP/1.1 204 No Content\r\n{}Connection: close\r\n\r\n",
            cors
        );
        let _ = stream
            .try_clone()
            .map(|mut writer| writer.write_all(resp.as_bytes()));
        return;
    }

    if method != "POST" {
        let response = indra_rpc::server::http_json_error(
            "405 Method Not Allowed",
            -32600,
            "Method Not Allowed",
            &cors,
        );
        let _ = stream
            .try_clone()
            .map(|mut writer| writer.write_all(response.as_bytes()));
        return;
    }

    if content_length == 0 {
        let body = r#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"empty body"},"id":null}"#;
        send_http(&stream, &cors, body);
        return;
    }

    if content_length > policy.max_body_bytes {
        rejection_counters
            .oversized_bodies
            .fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "[rpc] oversized request body rejected: {} bytes > {} bytes",
            content_length, policy.max_body_bytes
        );
        let response = indra_rpc::server::http_json_error(
            "413 Payload Too Large",
            -32600,
            "request body too large",
            &cors,
        );
        let _ = stream
            .try_clone()
            .map(|mut writer| writer.write_all(response.as_bytes()));
        return;
    }

    let mut body_bytes = vec![0u8; content_length];
    if reader.read_exact(&mut body_bytes).is_err() {
        rejection_counters
            .timeouts_or_incomplete_reads
            .fetch_add(1, Ordering::Relaxed);
        eprintln!("[rpc] incomplete or timed-out body read");
        return;
    }
    let body_str = String::from_utf8_lossy(&body_bytes);
    let req = match indra_rpc::server::parse_http_json_rpc_body(&body_str) {
        Ok(request) => request,
        Err(response) => {
            let body = response.to_json();
            send_http(&stream, &cors, &body);
            return;
        }
    };

    let (admin_token_configured, admin_token_valid) =
        rpc_admin_token_status(configured_admin_token, presented_admin_token.as_deref());

    if let Err(error) = check_rpc_method_allowed_with_admin(
        &req.method,
        rpc_mode,
        admin_token_configured,
        admin_token_valid,
    ) {
        if matches!(&error, indra_rpc::RpcError::Forbidden(_)) {
            rejection_counters
                .auth_failures
                .fetch_add(1, Ordering::Relaxed);
            eprintln!("[rpc] authorization/policy rejection for {}", req.method);
        }
        let body =
            RpcResponse::err(req.id.clone(), error.code(), error.message().to_string()).to_json();
        send_http(&stream, &cors, &body);
        return;
    }

    if rpc_mode == indra_rpc::handlers::RpcMode::ReadOnly
        && indra_rpc::server::rpc_method_cost(&req.method)
            == indra_rpc::server::RpcMethodCost::Expensive
    {
        if !public_expensive_method_allowed(
            &req.method,
            peer_ip,
            expensive_limiter,
            expensive_global_limiter,
        ) {
            rejection_counters
                .expensive_method_limited
                .fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "[rpc-public] expensive-method rate limit rejected {}",
                req.method
            );
            let response = indra_rpc::server::rpc_rate_limited_response();
            let _ = stream
                .try_clone()
                .map(|mut writer| writer.write_all(response.as_bytes()));
            return;
        }
    }

    let validator_peer_addrs: Vec<String> = gossip
        .connected_addrs()
        .iter()
        .map(|addr| addr.to_string())
        .collect();
    let validator_peer_topology = gossip.peer_topology();
    let connected_validator_peer_count = gossip.connection_count();
    let discovered_count = discovered_peers.lock().unwrap().len();
    let observer_count_val = observer_count.load(Ordering::Relaxed);

    if let Some(result) = dispatch_public_light_method(
        &req.method,
        driver,
        connected_validator_peer_count,
        discovered_count,
        observer_count_val,
        rpc_mode,
        admin_token_configured,
        rejection_counters,
    ) {
        match result {
            Ok(result) => {
                let body = RpcResponse::ok(req.id.clone(), result).to_json();
                send_http(&stream, &cors, &body);
            }
            Err(error) => {
                let body =
                    RpcResponse::err(req.id.clone(), error.code(), error.message().to_string())
                        .to_json();
                send_http(&stream, &cors, &body);
            }
        }
        return;
    }

    let response_body = {
        let snapshot = match snapshot_rpc_state(driver, &req) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let body = RpcResponse::err(req.id.clone(), -32000, error).to_json();
                send_http(&stream, &cors, &body);
                return;
            }
        };
        let state = NodeState::with_network_policy(
            &snapshot,
            validator_peer_addrs,
            validator_peer_topology,
            connected_validator_peer_count,
            discovered_count,
            observer_count_val,
            rpc_mode,
            admin_token_configured,
        );
        match dispatch_with_admin(
            &req.method,
            &req.params,
            &state,
            rpc_mode,
            admin_token_configured,
            admin_token_valid,
        ) {
            DispatchResult::Ready(Ok(result)) => RpcResponse::ok(req.id.clone(), result).to_json(),
            DispatchResult::Ready(Err(error)) => {
                RpcResponse::err(req.id.clone(), error.code(), error.message().to_string())
                    .to_json()
            }
            DispatchResult::SubmitStakingOp(op_bytes) => {
                use indra_core::codec::Decode;
                use indra_core::types::staking::StakingOp;
                match StakingOp::decode_exact(&op_bytes) {
                    Ok(op) => match driver
                        .lock()
                        .map_err(|_| "consensus driver lock poisoned".to_string())
                        .and_then(|mut guard| {
                            guard
                                .engine
                                .add_staking_op(op.clone())
                                .map_err(|e| e.to_string())
                        }) {
                        Ok(()) => {
                            broadcast_locally_accepted_op(
                                gossip,
                                op_relay_seen,
                                Message::StakingOp(op),
                            );
                            RpcResponse::ok(
                                req.id.clone(),
                                r#"{"status":"accepted","detail":"accepted into local mempool and relayed; not yet confirmed on-chain"}"#.to_string(),
                            )
                            .to_json()
                        }
                        Err(error) => {
                            RpcResponse::err(req.id.clone(), -32000, format!("rejected: {error}"))
                                .to_json()
                        }
                    },
                    Err(error) => RpcResponse::err(
                        req.id.clone(),
                        -32602,
                        format!("staking op decode failed: {error}"),
                    )
                    .to_json(),
                }
            }
            DispatchResult::SubmitGovernanceOp(op_bytes) => {
                use indra_core::codec::Decode;
                use indra_core::types::governance::GovernanceOpV2;
                match GovernanceOpV2::decode_exact(&op_bytes) {
                    Ok(op) => match driver
                        .lock()
                        .map_err(|_| "consensus driver lock poisoned".to_string())
                        .and_then(|mut guard| {
                            guard
                                .engine
                                .add_governance_op(op.clone())
                                .map_err(|e| e.to_string())
                        }) {
                        Ok(()) => {
                            broadcast_locally_accepted_op(
                                gossip,
                                op_relay_seen,
                                Message::GovernanceOp(op),
                            );
                            RpcResponse::ok(
                                req.id.clone(),
                                r#"{"status":"accepted","detail":"accepted into local mempool and relayed; not yet confirmed on-chain"}"#.to_string(),
                            )
                            .to_json()
                        }
                        Err(error) => {
                            RpcResponse::err(req.id.clone(), -32000, format!("rejected: {error}"))
                                .to_json()
                        }
                    },
                    Err(error) => RpcResponse::err(
                        req.id.clone(),
                        -32602,
                        format!("governance op decode failed: {error}"),
                    )
                    .to_json(),
                }
            }
            DispatchResult::SubmitTransaction(tx_bytes) => {
                use indra_core::codec::{ByteReader, Decode};
                use indra_core::types::transaction::TransactionV1;
                let mut reader = ByteReader::new(&tx_bytes);
                match TransactionV1::decode(&mut reader) {
                    Ok(tx) => {
                        let submit_result = driver
                            .lock()
                            .map_err(|_| "consensus driver lock poisoned".to_string())
                            .and_then(|mut guard| {
                                let engine = &mut guard.engine;
                                engine
                                    .mempool
                                    .submit_validated(tx.clone(), &engine.state)
                                    .map_err(|e| e.to_string())
                            });
                        match submit_result {
                            Ok(tx_id) => {
                                gossip.broadcast(&Message::Tx(tx));
                                RpcResponse::ok(
                                    req.id.clone(),
                                    format!(
                                        r#"{{"tx_id":"{}","status":"accepted"}}"#,
                                        hex::encode(tx_id.0)
                                    ),
                                )
                                .to_json()
                            }
                            Err(error) => RpcResponse::err(
                                req.id.clone(),
                                -32000,
                                format!("mempool rejected: {error}"),
                            )
                            .to_json(),
                        }
                    }
                    Err(error) => RpcResponse::err(
                        req.id.clone(),
                        -32602,
                        format!("tx decode failed: {error}"),
                    )
                    .to_json(),
                }
            }
        }
    };

    send_http(&stream, &cors, &response_body);
}

fn rpc_admin_token_status(
    configured_admin_token: Option<&str>,
    presented_admin_token: Option<&str>,
) -> (bool, bool) {
    let configured = configured_admin_token.is_some();
    let valid = configured_admin_token
        .zip(presented_admin_token)
        .is_some_and(|(expected, presented)| expected == presented);
    (configured, valid)
}

fn send_http(stream: &std::net::TcpStream, cors: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        cors,
        body.len(),
        body
    );
    let _ = stream
        .try_clone()
        .map(|mut writer| writer.write_all(response.as_bytes()));
}
#[cfg(test)]
mod tests {
    use super::*;

    fn proposer_test_driver(seed: [u8; 32], suffix: &str) -> (ConsensusDriver, PathBuf) {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "indra_node_proposer_authority_{}_{}",
            suffix,
            std::process::id()
        ));
        let mut config = NodeConfig::local_test(dir.clone());
        let classical = indra_crypto::hybrid::ClassicalKeypair::from_seed(&seed);
        let pq = indra_crypto::hybrid::PqKeypair::from_seed(&seed).unwrap();
        let vrf = indra_crypto::VrfKeypair::from_seed(&seed);
        let mut cold_seed = seed;
        cold_seed[0] ^= 0xFF;
        let cold_classical = indra_crypto::hybrid::ClassicalKeypair::from_seed(&cold_seed);
        let cold_pq = indra_crypto::hybrid::PqKeypair::from_seed(&cold_seed).unwrap();
        let genesis_path = dir.join("genesis.toml");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &genesis_path,
            format!(
                "[[validators]]\nname = \"local\"\nvalidator_id = \"{}\"\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\ncold_hybrid_classical_pk = \"{}\"\ncold_hybrid_pq_pk = \"{}\"\ncold_key_version = 1\ncold_nonce = 0\nstake = 1000000\n",
                hex::encode(indra_crypto::sha256(&classical.public_key().0)),
                hex::encode(classical.public_key().0),
                hex::encode(pq.public_key().0),
                hex::encode(vrf.public_key()),
                hex::encode(cold_classical.public_key().0),
                hex::encode(cold_pq.public_key().0),
            ),
        )
        .unwrap();
        config.genesis_path = Some(genesis_path.to_string_lossy().to_string());
        config.validator_seed = Some(seed);
        config.vrf_seed = Some(seed);
        config.pq_pk = Some(pq.public_key().0.to_vec());
        config.pq_sk = Some(pq.secret_key_bytes());
        let engine = NodeEngine::init(config).unwrap();
        let vote_safety = indra_storage::VoteSafetyStore::open(engine.config.vote_safety_path());
        (ConsensusDriver::new(engine, vote_safety), dir)
    }

    fn add_active_proposer_candidate(
        driver: &mut ConsensusDriver,
        seed: [u8; 32],
    ) -> indra_core::Bytes32 {
        let classical = indra_crypto::hybrid::ClassicalKeypair::from_seed(&seed);
        let pq = indra_crypto::hybrid::PqKeypair::from_seed(&seed).unwrap();
        let public = indra_crypto::HybridKeypair::new(classical, pq).public_key();
        let validator_id = indra_core::Bytes32::from(indra_crypto::sha256(&public.classical.0));
        driver
            .engine
            .state
            .validators
            .upsert(indra_state::ValidatorEntry {
                validator_id,
                name: "live-only".to_string(),
                hybrid_classical_pk: Some(public.classical.0),
                hybrid_pq_pk: Some(public.pq.0.to_vec()),
                vrf_pk: Some(indra_crypto::VrfKeypair::from_seed(&seed).public_key()),
                stake_spark: 9_000_000,
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
                cold_nonce: 0,
            })
            .unwrap();
        validator_id
    }

    fn assert_same_election(
        left: &indra_consensus::proposer::ProposerElection,
        right: &indra_consensus::proposer::ProposerElection,
    ) {
        assert_eq!(left.epoch_seed, right.epoch_seed);
        assert_eq!(left.height, right.height);
        assert_eq!(left.round, right.round);
        assert_eq!(left.candidates.len(), right.candidates.len());
        for (left, right) in left.candidates.iter().zip(&right.candidates) {
            assert_eq!(left.validator_id, right.validator_id);
            assert_eq!(left.vrf_pubkey, right.vrf_pubkey);
            assert_eq!(left.verified_vrf_output, right.verified_vrf_output);
            assert_eq!(left.stake, right.stake);
        }
    }

    #[test]
    fn top_level_proposer_authority_uses_snapshot_and_matches_driver() {
        let (mut driver, dir) = proposer_test_driver([0xD1; 32], "snapshot");
        let local_id = driver.engine.validator_id().unwrap();
        let snapshot = driver
            .engine
            .state
            .build_consensus_snapshot(u64::MAX, u64::MAX - 1)
            .unwrap();
        driver.engine.state.consensus_snapshots.push(snapshot);
        driver.engine.state.height = u64::MAX - 1;
        driver
            .engine
            .state
            .validators
            .get_mut(&local_id)
            .unwrap()
            .status = indra_state::ValidatorStatus::Registered;
        let live_only_id = add_active_proposer_candidate(&mut driver, [0xD2; 32]);

        let decision_election = proposer_election_for_slot(&driver, u64::MAX, 7).unwrap();
        let construction_election = proposer_election_for_slot(&driver, u64::MAX, 7).unwrap();
        let driver_election = driver.proposer_election_for_height(u64::MAX, 7).unwrap();

        assert_same_election(&decision_election, &construction_election);
        assert_same_election(&decision_election, &driver_election);
        assert_eq!(decision_election.candidates.len(), 1);
        assert_eq!(decision_election.candidates[0].validator_id, local_id);
        assert!(!decision_election
            .candidates
            .iter()
            .any(|candidate| candidate.validator_id == live_only_id));
        assert!(
            driver.engine.is_proposer(&decision_election),
            "snapshot-authorized local validator must remain able to propose"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn top_level_proposer_authority_ignores_live_only_candidates() {
        let (mut driver, dir) = proposer_test_driver([0xD3; 32], "legacy");
        let live_id = add_active_proposer_candidate(&mut driver, [0xD4; 32]);
        let election = proposer_election_for_slot(&driver, 1, 3).unwrap();

        assert!(!election
            .candidates
            .iter()
            .any(|candidate| candidate.validator_id == live_id));
        assert_same_election(
            &election,
            &driver.proposer_election_for_height(1, 3).unwrap(),
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn snapshot_network_authority_drives_handshake_relay_and_discovery() {
        let (mut driver, dir) = proposer_test_driver([0xE1; 32], "network_snapshot");
        let snapshot_member = driver.engine.validator_id().unwrap();
        driver
            .engine
            .state
            .validators
            .get_mut(&snapshot_member)
            .unwrap()
            .network_addr = Some("203.0.113.61:30303".to_string());
        let snapshot = driver
            .engine
            .state
            .build_consensus_snapshot(u64::MAX, u64::MAX - 1)
            .unwrap();
        driver.engine.state.consensus_snapshots.push(snapshot);
        driver.engine.state.height = u64::MAX - 1;

        // Steady state: live and snapshot membership agree.
        let steady = build_handshake_config(&driver.engine).unwrap().unwrap();
        assert!(steady
            .known_validators
            .iter()
            .any(|(id, _)| *id == snapshot_member));
        assert!(steady
            .relay_validator_keys
            .iter()
            .any(|member| member.validator_id == snapshot_member));

        // Diverge live policy state after S(height) was frozen.
        driver
            .engine
            .state
            .validators
            .get_mut(&snapshot_member)
            .unwrap()
            .status = indra_state::ValidatorStatus::Registered;
        let live_only = add_active_proposer_candidate(&mut driver, [0xE2; 32]);
        driver
            .engine
            .state
            .validators
            .get_mut(&live_only)
            .unwrap()
            .network_addr = Some("203.0.113.62:30303".to_string());

        let config = build_handshake_config(&driver.engine).unwrap().unwrap();
        assert!(config
            .known_validators
            .iter()
            .any(|(id, _)| *id == snapshot_member));
        assert!(!config
            .known_validators
            .iter()
            .any(|(id, _)| *id == live_only));
        assert!(config
            .relay_validator_keys
            .iter()
            .any(|member| member.validator_id == snapshot_member));
        assert!(!config
            .relay_validator_keys
            .iter()
            .any(|member| member.validator_id == live_only));

        let addrs = on_chain_validator_network_addrs_for_height(&driver.engine, u64::MAX).unwrap();
        assert_eq!(addrs, vec!["203.0.113.61:30303".to_string()]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn removed_snapshot_member_remains_authorized_but_has_no_discovery_address() {
        let (mut driver, dir) = proposer_test_driver([0xE3; 32], "network_removed");
        let snapshot_member = driver.engine.validator_id().unwrap();
        driver
            .engine
            .state
            .validators
            .get_mut(&snapshot_member)
            .unwrap()
            .network_addr = Some("203.0.113.63:30303".to_string());
        let snapshot = driver
            .engine
            .state
            .build_consensus_snapshot(u64::MAX, u64::MAX - 1)
            .unwrap();
        driver.engine.state.consensus_snapshots.push(snapshot);
        driver.engine.state.height = u64::MAX - 1;
        driver.engine.state.validators.remove(&snapshot_member);

        let config = build_handshake_config(&driver.engine).unwrap().unwrap();
        assert!(config
            .known_validators
            .iter()
            .any(|(id, _)| *id == snapshot_member));
        assert!(config
            .relay_validator_keys
            .iter()
            .any(|member| member.validator_id == snapshot_member));
        assert!(
            on_chain_validator_network_addrs_for_height(&driver.engine, u64::MAX)
                .unwrap()
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn network_authority_is_snapshot_membership_with_live_addresses() {
        let (mut driver, dir) = proposer_test_driver([0xE4; 32], "network_legacy");
        let local = driver.engine.validator_id().unwrap();
        driver
            .engine
            .state
            .validators
            .get_mut(&local)
            .unwrap()
            .network_addr = Some("203.0.113.64:30303".to_string());
        let live = add_active_proposer_candidate(&mut driver, [0xE5; 32]);
        driver
            .engine
            .state
            .validators
            .get_mut(&live)
            .unwrap()
            .network_addr = Some("203.0.113.65:30303".to_string());

        let config = build_handshake_config(&driver.engine).unwrap().unwrap();
        assert!(config.known_validators.iter().any(|(id, _)| *id == local));
        assert!(!config.known_validators.iter().any(|(id, _)| *id == live));
        let mut addrs = on_chain_validator_network_addrs_for_height(&driver.engine, 1).unwrap();
        addrs.sort();
        assert_eq!(addrs, vec!["203.0.113.64:30303".to_string()]);

        driver
            .engine
            .state
            .validators
            .get_mut(&local)
            .unwrap()
            .status = indra_state::ValidatorStatus::Registered;
        let config = build_handshake_config(&driver.engine).unwrap().unwrap();
        assert!(config.known_validators.iter().any(|(id, _)| *id == local));
        assert!(
            on_chain_validator_network_addrs_for_height(&driver.engine, 1)
                .unwrap()
                .contains(&"203.0.113.64:30303".to_string())
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    fn dummy_hybrid_sig() -> indra_core::types::crypto::HybridSignature {
        indra_core::types::crypto::HybridSignature {
            classical_sig: indra_core::types::primitives::VariableBytes::from_slice(&[0x11; 64])
                .unwrap(),
            pq_sig: indra_core::types::primitives::VariableBytes::from_slice(&[0x22; 64]).unwrap(),
        }
    }

    fn dummy_staking_op(nonce: u64) -> indra_core::types::staking::StakingOp {
        indra_core::types::staking::StakingOp {
            body: indra_core::types::staking::StakingOpBody::ClaimRewards {
                validator_id: indra_core::Bytes32::from([0x31; 32]),
                delegator_pubkey: indra_core::types::crypto::HybridPubKey {
                    classical_pk: indra_core::Bytes32::from([0x32; 32]),
                    pq_pk: indra_core::types::primitives::VariableBytes::from_slice(&[0x33; 32])
                        .unwrap(),
                },
                cold_authorization: None,
            },
            nonce,
            signature: dummy_hybrid_sig(),
        }
    }

    fn dummy_governance_op(nonce: u64) -> indra_core::types::governance::GovernanceOpV2 {
        indra_core::types::governance::GovernanceOpV2 {
            action_type: indra_core::types::governance::GovernanceActionType::CancelProposal,
            signer_id: indra_core::Bytes32::from([0x41; 32]),
            nonce,
            payload: indra_core::types::governance::GovernancePayload::Cancel {
                proposal_id: indra_core::Bytes32::from([0x42; 32]),
                cold_authorization: None,
            },
            signature: dummy_hybrid_sig(),
        }
    }

    #[test]
    fn status_broadcast_on_first_peer_connection() {
        let tip_hash = indra_core::Bytes32::from([0x55u8; 32]);
        let [first, second] = startup_peer_messages(42, tip_hash);

        assert!(
            matches!(first, Message::Status { height: 42, tip_hash: got, .. } if got == tip_hash)
        );
        assert!(matches!(second, Message::Ping(_)));
    }

    #[test]
    fn op_relay_seen_cache_deduplicates_staking_and_governance_ops() {
        let staking = Message::StakingOp(dummy_staking_op(7));
        let governance = Message::GovernanceOp(dummy_governance_op(9));
        let staking_key = op_relay_key(&staking).unwrap();
        let governance_key = op_relay_key(&governance).unwrap();
        let mut cache = OpRelaySeenCache::new(16);

        assert!(cache.observe(staking_key));
        assert!(!cache.observe(staking_key));
        assert!(cache.observe(governance_key));
        assert!(!cache.observe(governance_key));
    }

    #[test]
    fn op_relay_seen_cache_eviction_allows_old_key_again_after_capacity() {
        let first = op_relay_key(&Message::StakingOp(dummy_staking_op(1))).unwrap();
        let second = op_relay_key(&Message::StakingOp(dummy_staking_op(2))).unwrap();
        let third = op_relay_key(&Message::StakingOp(dummy_staking_op(3))).unwrap();
        let mut cache = OpRelaySeenCache::new(2);

        assert!(cache.observe(first));
        assert!(cache.observe(second));
        assert!(cache.observe(third));
        assert!(cache.observe(first));
    }

    #[test]
    fn stale_staged_proposal_does_not_block_valid_reproposal() {
        let mode = choose_proposal_mode(true, true, None, 10, 3, true);

        assert_eq!(mode, ProposalMode::Reproposal);
    }

    #[test]
    fn proposal_failure_backoff_suppresses_same_slot_retry() {
        let failed = Some(((42, 7), Instant::now()));

        assert!(proposal_failure_backoff_active(failed, 42, 7));
        assert!(!proposal_failure_backoff_active(failed, 42, 8));
        assert!(!proposal_failure_backoff_active(failed, 43, 7));
    }

    #[test]
    fn proposal_failure_backoff_allows_retry_after_window() {
        let failed = Some((
            (42, 7),
            Instant::now() - PROPOSAL_FAILURE_BACKOFF - Duration::from_millis(1),
        ));

        assert!(!proposal_failure_backoff_active(failed, 42, 7));
    }

    #[test]
    fn node_startup_loads_encrypted_keys_from_password_file() {
        let dir =
            std::env::temp_dir().join(format!("indra-node-keystore-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let keys_path = dir.join("keys.json");
        let password_path = dir.join("keys.pass");
        let keys =
            indra_keystore::generate_from_master_seed("validator".to_string(), [1; 32]).unwrap();
        let encrypted = indra_keystore::encrypt_plaintext_keys(&keys, b"pw").unwrap();
        indra_keystore::write_keys_secure(keys_path.to_str().unwrap(), &encrypted).unwrap();
        indra_keystore::write_keys_secure(password_path.to_str().unwrap(), "pw\n").unwrap();

        let loaded = load_keys_data(
            keys_path.to_str().unwrap(),
            Some(password_path.to_str().unwrap()),
        );
        assert_eq!(loaded.hybrid_seed, keys.hybrid_seed);
        assert_eq!(loaded.vrf_seed, keys.vrf_seed);
        assert_eq!(loaded.pq_sk, keys.pq_sk);
        assert_eq!(loaded.pq_pk, keys.public.hybrid_pq_pk);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_startup_rejects_encrypted_keys_without_password_source() {
        let dir = std::env::temp_dir().join(format!(
            "indra-node-keystore-no-password-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let keys_path = dir.join("keys.json");
        let keys =
            indra_keystore::generate_from_master_seed("validator".to_string(), [1; 32]).unwrap();
        let encrypted = indra_keystore::encrypt_plaintext_keys(&keys, b"pw").unwrap();
        indra_keystore::write_keys_secure(keys_path.to_str().unwrap(), &encrypted).unwrap();

        let result = std::panic::catch_unwind(|| load_keys_data(keys_path.to_str().unwrap(), None));
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn node_startup_rejects_permissive_password_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "indra-node-keystore-permissions-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let keys_path = dir.join("keys.json");
        let password_path = dir.join("keys.pass");
        let keys =
            indra_keystore::generate_from_master_seed("validator".to_string(), [1; 32]).unwrap();
        let encrypted = indra_keystore::encrypt_plaintext_keys(&keys, b"pw").unwrap();
        indra_keystore::write_keys_secure(keys_path.to_str().unwrap(), &encrypted).unwrap();
        std::fs::write(&password_path, "pw\n").unwrap();
        std::fs::set_permissions(&password_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let result = std::panic::catch_unwind(|| {
            load_keys_data(
                keys_path.to_str().unwrap(),
                Some(password_path.to_str().unwrap()),
            )
        });
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_connected_event_for_own_validator_id_is_rejected() {
        let local = indra_core::Bytes32::from([0x42; 32]);
        let addr: SocketAddr = "127.0.0.1:32782".parse().unwrap();
        let connected_addrs = Arc::new(Mutex::new(HashMap::<IpAddr, usize>::new()));
        let peer_addrs = Arc::new(Mutex::new(HashMap::<indra_core::Bytes32, SocketAddr>::new()));
        let addr_validators =
            Arc::new(Mutex::new(HashMap::<SocketAddr, indra_core::Bytes32>::new()));
        let discovered_peers = Arc::new(Mutex::new(HashSet::from([addr.to_string()])));
        let authenticated_peer_addrs = Arc::new(Mutex::new(HashSet::new()));
        let authenticated_addr_validators =
            Arc::new(Mutex::new(HashMap::<String, indra_core::Bytes32>::new()));
        let connected_validator_ids = Arc::new(Mutex::new(HashSet::<indra_core::Bytes32>::new()));
        let bootstrap_peer_addrs = HashSet::new();
        let genesis_peer_addrs = HashSet::new();
        let retry_after = Arc::new(Mutex::new(HashMap::<String, Instant>::new()));
        let retry_delay = Arc::new(Mutex::new(HashMap::<String, Duration>::new()));
        let failure_counts = Arc::new(Mutex::new(HashMap::<String, u32>::new()));

        let accepted = record_peer_connected_event(
            local,
            local,
            addr,
            true,
            &connected_addrs,
            &peer_addrs,
            &addr_validators,
            &discovered_peers,
            &authenticated_peer_addrs,
            &authenticated_addr_validators,
            &connected_validator_ids,
            &bootstrap_peer_addrs,
            &genesis_peer_addrs,
            &retry_after,
            &retry_delay,
            &failure_counts,
        );

        assert!(!accepted);
        assert!(connected_addrs.lock().unwrap().is_empty());
        assert!(peer_addrs.lock().unwrap().is_empty());
        assert!(addr_validators.lock().unwrap().is_empty());
        assert!(discovered_peers.lock().unwrap().is_empty());
        assert!(authenticated_peer_addrs.lock().unwrap().is_empty());
        assert!(authenticated_addr_validators.lock().unwrap().is_empty());
        assert!(connected_validator_ids.lock().unwrap().is_empty());
        assert!(failure_counts.lock().unwrap().is_empty());
    }

    struct PeerConnectionTestState {
        connected_addrs: Arc<Mutex<HashMap<IpAddr, usize>>>,
        peer_addrs: Arc<Mutex<HashMap<indra_core::Bytes32, SocketAddr>>>,
        addr_validators: Arc<Mutex<HashMap<SocketAddr, indra_core::Bytes32>>>,
        discovered_peers: Arc<Mutex<HashSet<String>>>,
        authenticated_peer_addrs: Arc<Mutex<HashSet<String>>>,
        authenticated_addr_validators: Arc<Mutex<HashMap<String, indra_core::Bytes32>>>,
        connected_validator_ids: Arc<Mutex<HashSet<indra_core::Bytes32>>>,
        bootstrap_peer_addrs: HashSet<String>,
        genesis_peer_addrs: HashSet<String>,
        retry_after: Arc<Mutex<HashMap<String, Instant>>>,
        retry_delay: Arc<Mutex<HashMap<String, Duration>>>,
        failure_counts: Arc<Mutex<HashMap<String, u32>>>,
    }

    impl PeerConnectionTestState {
        fn new() -> Self {
            Self {
                connected_addrs: Arc::new(Mutex::new(HashMap::new())),
                peer_addrs: Arc::new(Mutex::new(HashMap::new())),
                addr_validators: Arc::new(Mutex::new(HashMap::new())),
                discovered_peers: Arc::new(Mutex::new(HashSet::new())),
                authenticated_peer_addrs: Arc::new(Mutex::new(HashSet::new())),
                authenticated_addr_validators: Arc::new(Mutex::new(HashMap::new())),
                connected_validator_ids: Arc::new(Mutex::new(HashSet::new())),
                bootstrap_peer_addrs: HashSet::new(),
                genesis_peer_addrs: HashSet::new(),
                retry_after: Arc::new(Mutex::new(HashMap::new())),
                retry_delay: Arc::new(Mutex::new(HashMap::new())),
                failure_counts: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn record(
            &self,
            local: indra_core::Bytes32,
            validator: indra_core::Bytes32,
            addr: SocketAddr,
            is_outbound: bool,
        ) -> bool {
            record_peer_connected_event(
                local,
                validator,
                addr,
                is_outbound,
                &self.connected_addrs,
                &self.peer_addrs,
                &self.addr_validators,
                &self.discovered_peers,
                &self.authenticated_peer_addrs,
                &self.authenticated_addr_validators,
                &self.connected_validator_ids,
                &self.bootstrap_peer_addrs,
                &self.genesis_peer_addrs,
                &self.retry_after,
                &self.retry_delay,
                &self.failure_counts,
            )
        }

        fn gossip_payload(&self) -> Vec<PeerListEntry> {
            let addrs: Vec<_> = self.peer_addrs.lock().unwrap().values().copied().collect();
            peer_list_payload_with_identities(
                addrs,
                None,
                &HashSet::new(),
                &self.addr_validators.lock().unwrap(),
            )
        }

        fn persisted(&self, local_p2p_addr: &str) -> Vec<SocketAddr> {
            peer_addresses_to_persist(
                &self.discovered_peers.lock().unwrap(),
                &self.peer_addrs.lock().unwrap(),
                local_p2p_addr,
            )
        }
    }

    #[test]
    fn inbound_connection_source_address_not_added_to_discovery() {
        let local = indra_core::Bytes32::from([0x01; 32]);
        let validator = indra_core::Bytes32::from([0x02; 32]);
        let inbound_source: SocketAddr = "203.0.113.80:52154".parse().unwrap();
        let state = PeerConnectionTestState::new();

        assert!(state.record(local, validator, inbound_source, false));

        assert!(!state
            .discovered_peers
            .lock()
            .unwrap()
            .contains(&inbound_source.to_string()));
        assert!(!state.peer_addrs.lock().unwrap().contains_key(&validator));
        assert!(!state
            .authenticated_peer_addrs
            .lock()
            .unwrap()
            .contains(&inbound_source.to_string()));
        assert!(!state
            .authenticated_addr_validators
            .lock()
            .unwrap()
            .contains_key(&inbound_source.to_string()));
    }

    #[test]
    fn inbound_connection_source_address_not_in_outgoing_peerlist() {
        let local = indra_core::Bytes32::from([0x01; 32]);
        let validator = indra_core::Bytes32::from([0x02; 32]);
        let inbound_source: SocketAddr = "203.0.113.80:52154".parse().unwrap();
        let state = PeerConnectionTestState::new();

        assert!(state.record(local, validator, inbound_source, false));

        let payload = state.gossip_payload();
        assert!(payload
            .iter()
            .all(|entry| entry.addr != inbound_source.to_string()));
    }

    #[test]
    fn inbound_connection_source_address_not_persisted() {
        let local = indra_core::Bytes32::from([0x01; 32]);
        let validator = indra_core::Bytes32::from([0x02; 32]);
        let inbound_source: SocketAddr = "203.0.113.80:52154".parse().unwrap();
        let state = PeerConnectionTestState::new();

        assert!(state.record(local, validator, inbound_source, false));

        assert!(!state.persisted("0.0.0.0:30303").contains(&inbound_source));
    }

    #[test]
    fn outbound_connection_target_still_added_to_discovery() {
        let local = indra_core::Bytes32::from([0x01; 32]);
        let validator = indra_core::Bytes32::from([0x02; 32]);
        let dial_target: SocketAddr = "203.0.113.80:30303".parse().unwrap();
        let state = PeerConnectionTestState::new();

        assert!(state.record(local, validator, dial_target, true));

        assert!(state
            .discovered_peers
            .lock()
            .unwrap()
            .contains(&dial_target.to_string()));
        assert_eq!(
            state.peer_addrs.lock().unwrap().get(&validator).copied(),
            Some(dial_target)
        );
        assert!(state.gossip_payload().iter().any(|entry| {
            entry.addr == dial_target.to_string() && entry.validator_id == Some(validator)
        }));
        assert!(state.persisted("0.0.0.0:30303").contains(&dial_target));
    }

    #[test]
    fn inbound_connection_still_tracked_as_live_endpoint() {
        let local = indra_core::Bytes32::from([0x01; 32]);
        let validator = indra_core::Bytes32::from([0x02; 32]);
        let inbound_source: SocketAddr = "203.0.113.80:52154".parse().unwrap();
        let state = PeerConnectionTestState::new();

        assert!(state.record(local, validator, inbound_source, false));

        assert_eq!(
            state
                .addr_validators
                .lock()
                .unwrap()
                .get(&inbound_source)
                .copied(),
            Some(validator)
        );
        assert!(state
            .connected_validator_ids
            .lock()
            .unwrap()
            .contains(&validator));
        assert_eq!(
            state
                .connected_addrs
                .lock()
                .unwrap()
                .get(&inbound_source.ip())
                .copied(),
            Some(1)
        );
    }

    #[test]
    fn discovered_peers_table_has_bounded_size() {
        let mut discovered_peers = HashSet::new();
        let authenticated = HashSet::new();
        let bootstrap = HashSet::new();
        let genesis = HashSet::new();

        for port in 30_000..(30_000 + MAX_DISCOVERED_PEERS as u16 + 100) {
            insert_discovered_peer_bounded(
                &mut discovered_peers,
                &authenticated,
                &bootstrap,
                &genesis,
                SocketAddr::from(([127, 0, 0, 1], port)).to_string(),
            );
        }

        assert_eq!(discovered_peers.len(), MAX_DISCOVERED_PEERS);
        assert_eq!(
            bounded_discovered_peer_addrs(&discovered_peers).len(),
            MAX_DISCOVERED_PEERS
        );
    }

    #[test]
    fn discovery_eviction_prefers_unauthenticated_entries() {
        let authenticated_peer = "203.0.113.1:30303".to_string();
        let mut discovered_peers = HashSet::from([authenticated_peer.clone()]);
        let authenticated = HashSet::from([authenticated_peer.clone()]);
        let bootstrap = HashSet::new();
        let genesis = HashSet::new();

        for idx in 2..=MAX_DISCOVERED_PEERS {
            discovered_peers.insert(format!("203.0.{}.{}:30303", idx / 250, (idx % 250) + 1));
        }
        assert_eq!(discovered_peers.len(), MAX_DISCOVERED_PEERS);

        let new_peer = "198.51.100.250:30303".to_string();
        assert!(insert_discovered_peer_bounded(
            &mut discovered_peers,
            &authenticated,
            &bootstrap,
            &genesis,
            new_peer.clone(),
        ));

        assert!(discovered_peers.contains(&authenticated_peer));
        assert!(discovered_peers.contains(&new_peer));
        assert_eq!(discovered_peers.len(), MAX_DISCOVERED_PEERS);
    }

    #[test]
    fn bootstrap_peers_are_never_evicted() {
        let bootstrap_peer = "203.0.113.10:30303".to_string();
        let mut discovered_peers = HashSet::from([bootstrap_peer.clone()]);
        let authenticated = HashSet::new();
        let bootstrap = HashSet::from([bootstrap_peer.clone()]);
        let genesis = HashSet::new();

        for idx in 11..=(MAX_DISCOVERED_PEERS + 9) {
            discovered_peers.insert(format!("203.0.{}.{}:30303", idx / 250, (idx % 250) + 1));
        }
        assert_eq!(discovered_peers.len(), MAX_DISCOVERED_PEERS);

        assert!(insert_discovered_peer_bounded(
            &mut discovered_peers,
            &authenticated,
            &bootstrap,
            &genesis,
            "198.51.100.99:30303".to_string(),
        ));

        assert!(discovered_peers.contains(&bootstrap_peer));
        assert_eq!(discovered_peers.len(), MAX_DISCOVERED_PEERS);
    }

    #[test]
    fn inbound_connection_limit_is_enforced() {
        let inbound_count = AtomicU64::new(0);
        let inbound_by_ip = Mutex::new(HashMap::<IpAddr, u8>::new());
        let mut reserved_ips = Vec::new();

        for idx in 0..MAX_INBOUND_PEERS {
            let ip = IpAddr::from([198, 51, (idx / 250) as u8, (idx % 250 + 1) as u8]);
            assert!(reserve_inbound_connection(
                &inbound_count,
                &inbound_by_ip,
                ip
            ));
            reserved_ips.push(ip);
        }

        assert!(!reserve_inbound_connection(
            &inbound_count,
            &inbound_by_ip,
            IpAddr::from([203, 0, 113, 250])
        ));

        for ip in reserved_ips {
            release_inbound_connection(&inbound_count, &inbound_by_ip, ip);
        }
        assert_eq!(inbound_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn inbound_per_ip_limit_is_enforced() {
        let inbound_count = AtomicU64::new(0);
        let inbound_by_ip = Mutex::new(HashMap::<IpAddr, u8>::new());
        let ip = IpAddr::from([203, 0, 113, 77]);

        for _ in 0..MAX_INBOUND_PER_IP {
            assert!(reserve_inbound_connection(
                &inbound_count,
                &inbound_by_ip,
                ip
            ));
        }
        assert!(!reserve_inbound_connection(
            &inbound_count,
            &inbound_by_ip,
            ip
        ));

        for _ in 0..MAX_INBOUND_PER_IP {
            release_inbound_connection(&inbound_count, &inbound_by_ip, ip);
        }
        assert_eq!(inbound_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rpc_connection_limit_is_enforced() {
        let rpc_count = AtomicU64::new(0);

        for _ in 0..MAX_RPC_CONNECTIONS {
            assert!(reserve_rpc_connection(&rpc_count));
        }

        assert!(!reserve_rpc_connection(&rpc_count));

        for _ in 0..MAX_RPC_CONNECTIONS {
            release_rpc_connection(&rpc_count);
        }
        assert_eq!(rpc_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rpc_server_does_not_start_when_disabled_in_config() {
        assert!(!rpc_should_start(Some(false)));
        assert!(rpc_should_start(Some(true)));
        assert!(rpc_should_start(None));
    }

    #[test]
    fn rpc_public_server_is_opt_in() {
        assert!(!rpc_public_should_start(None));
        assert!(!rpc_public_should_start(Some(false)));
        assert!(rpc_public_should_start(Some(true)));
    }

    #[test]
    fn rpc_warns_on_non_loopback_binding() {
        let warning = rpc_non_loopback_warning("0.0.0.0:8545").unwrap();
        assert!(warning.contains("full RPC listener"));
        assert!(warning.contains("do not expose"));
        assert!(rpc_non_loopback_warning("127.0.0.1:8545").is_none());

        let public_warning = rpc_public_non_loopback_warning("0.0.0.0:8547").unwrap();
        assert!(public_warning.contains("rpc_public listener"));
        assert!(public_warning.contains("reverse proxy"));
        assert!(public_warning.contains("CDN"));
        assert!(rpc_public_non_loopback_warning("127.0.0.1:8547").is_none());
    }

    #[test]
    fn rpc_public_policy_uses_stricter_limits_than_full_rpc() {
        let cfg = NodeConfigFile::default();
        let public = RpcListenerPolicy::public_from_config(&cfg);
        let full = RpcListenerPolicy::full();
        assert_eq!(
            public.per_ip_rate_per_sec,
            indra_rpc::server::RPC_PUBLIC_RATE_LIMIT_PER_SEC
        );
        assert_eq!(
            public.per_ip_burst,
            indra_rpc::server::RPC_PUBLIC_RATE_BURST
        );
        assert_eq!(
            public.global_rate_per_sec,
            Some(indra_rpc::server::RPC_PUBLIC_GLOBAL_RATE_LIMIT_PER_SEC)
        );
        assert!(public.max_body_bytes < full.max_body_bytes);
        assert!(public.request_timeout < full.request_timeout);
    }

    #[test]
    fn rpc_public_policy_honors_configured_limits() {
        let cfg = NodeConfigFile {
            rpc_public_per_ip_rate_per_sec: Some(7),
            rpc_public_per_ip_burst: Some(17),
            rpc_public_global_rate_per_sec: Some(70),
            rpc_public_global_burst: Some(170),
            rpc_public_max_body_bytes: Some(8192),
            rpc_public_timeout_ms: Some(2500),
            ..NodeConfigFile::default()
        };
        let public = RpcListenerPolicy::public_from_config(&cfg);
        assert_eq!(public.per_ip_rate_per_sec, 7);
        assert_eq!(public.per_ip_burst, 17);
        assert_eq!(public.global_rate_per_sec, Some(70));
        assert_eq!(public.global_burst, Some(170));
        assert_eq!(public.max_body_bytes, 8192);
        assert_eq!(public.request_timeout, Duration::from_millis(2500));
    }

    #[test]
    fn public_light_methods_avoid_full_snapshot_path() {
        assert!(public_light_method_avoids_full_snapshot("indra_getHeight"));
        assert!(public_light_method_avoids_full_snapshot("indra_getTip"));
        assert!(public_light_method_avoids_full_snapshot(
            "indra_getMempoolSize"
        ));
        assert!(!public_light_method_avoids_full_snapshot(
            "indra_getChainInfo"
        ));
        assert!(!public_light_method_avoids_full_snapshot(
            "indra_getStakePositions"
        ));
    }

    #[test]
    fn public_rpc_policy_exposes_rejection_counters_without_token_values() {
        let counters = RpcRejectionCounters::default();
        counters.global_rate_limited.store(7, Ordering::Relaxed);
        let result = public_rpc_policy_json(false, &counters);
        assert!(result.contains(r#""listener_mode":"read_only""#));
        assert!(result.contains(r#""global_rate_limited":7"#));
        assert!(!result.contains("secret"));
    }

    #[test]
    fn expensive_public_method_gate_rejects_before_snapshot_work() {
        let ip = IpAddr::from([198, 51, 100, 7]);
        let per_ip = indra_rpc::server::RpcWindowRateLimiter::new();
        let global = indra_rpc::server::RpcGlobalWindowRateLimiter::new();
        for _ in 0..indra_rpc::server::RPC_PUBLIC_EXPENSIVE_RATE_PER_MIN {
            assert!(public_expensive_method_allowed(
                "indra_getStakePositions",
                Some(ip),
                &per_ip,
                &global
            ));
        }
        assert!(
            !public_expensive_method_allowed("indra_getStakePositions", Some(ip), &per_ip, &global),
            "the public expensive-method gate should reject before dispatch/snapshot"
        );
        assert!(public_expensive_method_allowed(
            "indra_getHeight",
            Some(ip),
            &per_ip,
            &global
        ));
    }

    #[test]
    fn rpc_admin_token_status_matches_header_policy() {
        assert_eq!(rpc_admin_token_status(None, None), (false, false));
        assert_eq!(rpc_admin_token_status(None, Some("secret")), (false, false));
        assert_eq!(rpc_admin_token_status(Some("secret"), None), (true, false));
        assert_eq!(
            rpc_admin_token_status(Some("secret"), Some("wrong")),
            (true, false)
        );
        assert_eq!(
            rpc_admin_token_status(Some("secret"), Some("secret")),
            (true, true)
        );
    }

    #[test]
    fn rpc_read_state_is_consistent_snapshot() {
        let mut chain = indra_state::ChainState::new_genesis();
        chain.height = 42;
        let snapshot = RpcSnapshot {
            chain,
            mempool_size: 3,
            pruned_mode: false,
            lowest_block: 0,
            blocks_retained: 43,
            requested_block: None,
            latest_epoch: None,
            epoch_records: HashMap::new(),
        };
        let state = indra_rpc::handlers::NodeState::with_network(&snapshot, Vec::new(), 0, 0, 0);

        match indra_rpc::handlers::dispatch("indra_getHeight", &[], &state) {
            indra_rpc::handlers::DispatchResult::Ready(Ok(result)) => {
                assert_eq!(result, r#"{"height":42}"#);
            }
            _ => panic!("height query should be served from snapshot"),
        }
    }

    fn snapshot_test_output(byte: u8) -> indra_core::types::transaction::OutputV1 {
        indra_core::types::transaction::OutputV1 {
            value_spark: 1_000_000,
            commitment: indra_core::types::crypto::CommitmentV1 {
                compressed_point: indra_core::Bytes32::from([byte; 32]),
            },
            owner_pubkey: indra_core::types::crypto::HybridPubKey {
                classical_pk: indra_core::Bytes32::from([byte.wrapping_add(1); 32]),
                pq_pk: indra_core::types::primitives::VariableBytes::from_slice(&[byte; 32])
                    .unwrap_or_default(),
            },
            range_proof: indra_core::types::primitives::VariableBytes::<
                { indra_core::types::primitives::MAX_RANGE_PROOF_BYTES },
            >::from_slice(&[byte; 32])
            .unwrap_or_default(),
            lock_height: 0,
        }
    }

    #[test]
    fn provenance_rpc_prefetches_utxo_creation_block() {
        let mut chain = indra_state::ChainState::new_genesis();
        let created_height = 174_599;
        let utxo_id = chain
            .utxos
            .insert(snapshot_test_output(0xA5), created_height, u32::MAX, 0)
            .unwrap();
        let req = indra_rpc::types::RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "indra_explainUtxoProvenanceAuthorized".to_string(),
            params: vec![
                r#""owner-address""#.to_string(),
                r#""scan-proof""#.to_string(),
                format!(r#""{}""#, hex::encode(utxo_id.0)),
            ],
            id: indra_rpc::types::JsonId::Number(1),
        };

        assert_eq!(
            requested_block_height_for_rpc(&req, &chain),
            Some(created_height)
        );

        let mut unknown = [0xCCu8; 32];
        unknown[0] ^= utxo_id.0[0];
        let unknown_req = indra_rpc::types::RpcRequest {
            params: vec![
                r#""owner-address""#.to_string(),
                r#""scan-proof""#.to_string(),
                format!(r#""{}""#, hex::encode(unknown)),
            ],
            ..req
        };
        assert_eq!(requested_block_height_for_rpc(&unknown_req, &chain), None);
    }

    #[test]
    fn get_transaction_rpc_prefetches_requested_block_height() {
        let chain = indra_state::ChainState::new_genesis();
        let req = indra_rpc::types::RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "indra_getTransaction".to_string(),
            params: vec!["176677".to_string(), "0".to_string()],
            id: indra_rpc::types::JsonId::Number(1),
        };

        assert_eq!(requested_block_height_for_rpc(&req, &chain), Some(176_677));
    }

    fn snapshot_test_transaction(byte: u8) -> indra_core::types::transaction::TransactionV1 {
        indra_core::types::transaction::TransactionV1 {
            version: indra_core::ProtocolVersion(
                indra_core::types::primitives::TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES,
            ),
            signature_module_id: 1,
            inputs: vec![indra_core::types::transaction::InputV1 {
                utxo_id: indra_core::Bytes32::from([byte; 32]),
                nullifier: indra_core::Bytes32::from([byte.wrapping_add(1); 32]),
            }],
            outputs: vec![snapshot_test_output(byte.wrapping_add(2))],
            payment_notes: vec![indra_crypto::PaymentBlindingNoteV1 {
                version: 1,
                owner_id: indra_crypto::sha256(&[byte.wrapping_add(1); 32]),
                payment_pubkey_hash: [0; 32],
                sender_x25519_ephemeral_pk: [0; 32],
                ml_kem_1024_ciphertext: [0; indra_crypto::constants::ML_KEM_1024_CT_BYTES],
                note_nonce: [0; 32],
            }],
            fee_amount: 500,
            fee_blinding: indra_core::Bytes32::from([byte.wrapping_add(3); 32]),
            fee_commitment: indra_core::types::crypto::CommitmentV1 {
                compressed_point: indra_core::Bytes32::from([byte.wrapping_add(4); 32]),
            },
            signature: indra_core::types::crypto::HybridSignature {
                classical_sig: indra_core::types::primitives::VariableBytes::from_slice(
                    &[byte.wrapping_add(5); 64],
                )
                .unwrap(),
                pq_sig: indra_core::types::primitives::VariableBytes::from_slice(
                    &[byte.wrapping_add(6); 64],
                )
                .unwrap(),
            },
        }
    }

    #[test]
    fn rpc_snapshot_serves_get_transaction_from_requested_block() {
        let height = 176_677;
        let mut chain = indra_state::ChainState::new_genesis();
        chain.height = height + 2;
        let tx = snapshot_test_transaction(0xA7);
        let expected_tx_hex = hex::encode(tx.encode_to_vec());
        let mut block = block_response_test_block(height);
        block.transactions.push(tx);
        let snapshot = RpcSnapshot {
            chain,
            mempool_size: 0,
            pruned_mode: true,
            lowest_block: 126_677,
            blocks_retained: 50_000,
            requested_block: Some((height, block)),
            latest_epoch: None,
            epoch_records: HashMap::new(),
        };
        let state = indra_rpc::handlers::NodeState::read_only(&snapshot);

        match indra_rpc::handlers::dispatch(
            "indra_getTransaction",
            &[height.to_string(), "0".to_string()],
            &state,
        ) {
            indra_rpc::handlers::DispatchResult::Ready(Ok(result)) => {
                assert!(result.contains(r#""height":176677"#));
                assert!(result.contains(r#""tx_index":0"#));
                assert!(result.contains(&format!(r#""tx_hex":"{expected_tx_hex}""#)));
            }
            _ => panic!("getTransaction should be served from requested block snapshot"),
        }
    }

    #[test]
    fn rpc_snapshot_serves_requested_block_without_tip_stub() {
        let mut chain = indra_state::ChainState::new_genesis();
        chain.height = 2;
        let block = indra_core::types::block::BlockV1 {
            header: indra_core::types::block::BlockHeaderV1 {
                protocol_version: indra_core::ProtocolVersion::CURRENT,
                height: 1,
                prev_hash: indra_core::Bytes32::from([0x10; 32]),
                timestamp: 1_700_000_001,
                state_root: indra_core::Bytes32::from([0x11; 32]),
                validator_set_root: indra_core::Bytes32::from([0x12; 32]),
                mempool_set_root: indra_core::Bytes32::from([0x13; 32]),
                value_hash: indra_core::Bytes32::from([0x14; 32]),
                base_fee: 101,
                proposer_round: 0,
                polc_round: indra_core::types::block::NO_POLC_ROUND,
                proposer_vrf_output: indra_core::Bytes32::from([0x15; 32]),
                proposer_vrf_proof: indra_core::VariableBytes::<
                    { indra_core::types::primitives::MAX_VRF_PROOF_BYTES },
                >::from_slice(&[0x16; 64])
                .unwrap(),
                quorum_certificate: indra_core::VariableBytes::from_slice(&[]).unwrap(),
                election_result_hash: None,
            },
            transactions: Vec::new(),
            slashing_evidence: Vec::new(),
            governance_ops: Vec::new(),
            staking_ops: Vec::new(),
            vrf_reveals: Vec::new(),
        };
        let expected_hash = hex::encode(block.header.block_hash().0);
        let snapshot = RpcSnapshot {
            chain,
            mempool_size: 0,
            pruned_mode: true,
            lowest_block: 1,
            blocks_retained: 2,
            requested_block: Some((1, block)),
            latest_epoch: None,
            epoch_records: HashMap::new(),
        };
        let state = indra_rpc::handlers::NodeState::read_only(&snapshot);

        match indra_rpc::handlers::dispatch("indra_getBlock", &["1".to_string()], &state) {
            indra_rpc::handlers::DispatchResult::Ready(Ok(result)) => {
                assert!(result.contains(r#""height":1"#));
                assert!(result.contains(&format!(r#""block_hash":"{expected_hash}""#)));
                assert!(result.contains(r#""timestamp":1700000001"#));
                assert!(!result.contains("full block retrieval added in Phase 8"));
            }
            _ => panic!("getBlock should be served from requested block snapshot"),
        }
    }

    #[test]
    fn dial_loop_skips_already_connected_validator_identity() {
        let validator_id = indra_core::Bytes32::from([0x42; 32]);
        let peer_addr = "203.0.113.42:30303".to_string();
        let authenticated_addr_validators = HashMap::from([(peer_addr.clone(), validator_id)]);
        let connected_validator_ids = HashSet::from([validator_id]);

        assert!(should_skip_dial_for_connected_validator(
            &peer_addr,
            &authenticated_addr_validators,
            &connected_validator_ids,
        ));

        let unknown_addr = "203.0.113.43:30303".to_string();
        assert!(!should_skip_dial_for_connected_validator(
            &unknown_addr,
            &authenticated_addr_validators,
            &connected_validator_ids,
        ));
    }

    #[test]
    fn peerlist_self_entry_is_not_added_to_dial_queue() {
        let local_p2p_addr = "198.51.100.10:30303";
        let self_addr: SocketAddr = local_p2p_addr.parse().unwrap();
        let mut discovered_peers = HashSet::new();
        let authenticated = HashSet::new();
        let bootstrap = HashSet::new();
        let genesis = HashSet::new();

        assert!(
            !discovery_accepts_peer_addr(
                &self_addr,
                None,
                indra_core::Bytes32::ZERO,
                local_p2p_addr,
                &[]
            ),
            "received peer-list entries matching this node's configured P2P address must be rejected before dial queue insertion"
        );
        assert!(!insert_discovered_peer_if_not_self(
            &mut discovered_peers,
            &authenticated,
            &bootstrap,
            &genesis,
            local_p2p_addr,
            self_addr.to_string(),
        ));
        assert!(discovered_peers.is_empty());
    }

    #[test]
    fn outgoing_peerlist_never_advertises_own_address() {
        let local_p2p_addr = "198.51.100.10:30303";
        let own_addr: SocketAddr = local_p2p_addr.parse().unwrap();
        let other_addr: SocketAddr = "198.51.100.11:30303".parse().unwrap();
        let self_addrs = configured_self_addr_set(local_p2p_addr);

        let payload = peer_list_payload([own_addr, other_addr], None, &self_addrs);

        assert_eq!(
            payload,
            vec![PeerListEntry::address_only(other_addr.to_string())]
        );
        assert!(!payload
            .iter()
            .any(|entry| entry.addr == own_addr.to_string()));
    }

    #[test]
    fn peerlist_non_self_entry_is_added_to_dial_queue() {
        let local_p2p_addr = "198.51.100.10:30303";
        let peer_addr: SocketAddr = "198.51.100.11:30303".parse().unwrap();
        let mut discovered_peers = HashSet::new();
        let authenticated = HashSet::new();
        let bootstrap = HashSet::new();
        let genesis = HashSet::new();

        assert!(discovery_accepts_peer_addr(
            &peer_addr,
            None,
            indra_core::Bytes32::ZERO,
            local_p2p_addr,
            &[]
        ));
        assert!(insert_discovered_peer_if_not_self(
            &mut discovered_peers,
            &authenticated,
            &bootstrap,
            &genesis,
            local_p2p_addr,
            peer_addr.to_string(),
        ));
        assert!(discovered_peers.contains(&peer_addr.to_string()));
    }

    #[test]
    fn on_chain_validator_addresses_feed_discovery_through_existing_filters() {
        let local_p2p_addr = "198.51.100.10:30303";
        let mut discovered_peers = HashSet::new();
        let accepted = insert_on_chain_validator_network_addrs(
            &mut discovered_peers,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            local_p2p_addr,
            indra_core::Bytes32::from([0x01; 32]),
            &[],
            [
                "203.0.113.60:30303".to_string(),
                local_p2p_addr.to_string(),
                "not-an-address".to_string(),
            ],
        );

        assert_eq!(accepted, 1);
        assert!(discovered_peers.contains("203.0.113.60:30303"));
        assert!(!discovered_peers.contains(local_p2p_addr));
    }

    #[test]
    fn peerlist_self_validator_id_is_filtered_even_when_address_differs() {
        let local_validator_id = indra_core::Bytes32::from([0x42; 32]);
        let local_p2p_addr = "198.51.100.10:30303";
        let nat_observed_addr: SocketAddr = "203.0.113.44:30303".parse().unwrap();

        assert!(
            !is_configured_self_addr(&nat_observed_addr, local_p2p_addr),
            "test must model NAT/dynamic-IP drift where address fallback cannot help"
        );
        assert!(
            !discovery_accepts_peer_addr(
                &nat_observed_addr,
                Some(local_validator_id),
                local_validator_id,
                local_p2p_addr,
                &[],
            ),
            "identity-tagged self entries must be filtered before they enter the dial queue"
        );
    }

    #[test]
    fn peerlist_entries_include_validator_ids_for_authenticated_peers() {
        let peer_addr: SocketAddr = "203.0.113.45:30303".parse().unwrap();
        let validator_id = indra_core::Bytes32::from([0x45; 32]);
        let addr_validators = HashMap::from([(peer_addr, validator_id)]);

        let payload =
            peer_list_payload_with_identities([peer_addr], None, &HashSet::new(), &addr_validators);

        assert_eq!(
            payload,
            vec![PeerListEntry::with_validator(
                peer_addr.to_string(),
                validator_id
            )]
        );
    }

    #[test]
    fn peerlist_non_self_identity_entry_is_added_to_dial_queue() {
        let local_validator_id = indra_core::Bytes32::from([0x50; 32]);
        let remote_validator_id = indra_core::Bytes32::from([0x51; 32]);
        let local_p2p_addr = "198.51.100.10:30303";
        let peer_addr: SocketAddr = "203.0.113.51:30303".parse().unwrap();

        assert!(discovery_accepts_peer_addr(
            &peer_addr,
            Some(remote_validator_id),
            local_validator_id,
            local_p2p_addr,
            &[]
        ));
    }

    #[test]
    fn permanently_unreachable_peer_is_evicted_after_max_failures() {
        let peer = "203.0.113.55:30303".to_string();
        let mut discovered_peers = HashSet::from([peer.clone()]);
        let mut retry_after = HashMap::from([(peer.clone(), Instant::now())]);
        let mut retry_delay = HashMap::from([(peer.clone(), Duration::from_secs(60))]);
        let mut failure_counts = HashMap::new();
        let bootstrap = HashSet::new();

        for _ in 0..(MAX_DIAL_FAILURES_BEFORE_EVICTION - 1) {
            assert!(!record_dial_failure(
                &peer,
                &mut discovered_peers,
                &mut retry_after,
                &mut retry_delay,
                &mut failure_counts,
                &bootstrap,
            ));
            assert!(discovered_peers.contains(&peer));
        }

        assert!(record_dial_failure(
            &peer,
            &mut discovered_peers,
            &mut retry_after,
            &mut retry_delay,
            &mut failure_counts,
            &bootstrap,
        ));
        assert!(!discovered_peers.contains(&peer));
        assert!(!retry_after.contains_key(&peer));
        assert!(!retry_delay.contains_key(&peer));
        assert!(!failure_counts.contains_key(&peer));
    }

    #[test]
    fn successful_connection_resets_failure_count() {
        let local = indra_core::Bytes32::from([0x01; 32]);
        let validator = indra_core::Bytes32::from([0x02; 32]);
        let addr: SocketAddr = "203.0.113.80:30303".parse().unwrap();
        let connected_addrs = Arc::new(Mutex::new(HashMap::<IpAddr, usize>::new()));
        let peer_addrs = Arc::new(Mutex::new(HashMap::<indra_core::Bytes32, SocketAddr>::new()));
        let addr_validators =
            Arc::new(Mutex::new(HashMap::<SocketAddr, indra_core::Bytes32>::new()));
        let discovered_peers = Arc::new(Mutex::new(HashSet::from([addr.to_string()])));
        let authenticated_peer_addrs = Arc::new(Mutex::new(HashSet::new()));
        let authenticated_addr_validators =
            Arc::new(Mutex::new(HashMap::<String, indra_core::Bytes32>::new()));
        let connected_validator_ids = Arc::new(Mutex::new(HashSet::<indra_core::Bytes32>::new()));
        let bootstrap_peer_addrs = HashSet::new();
        let genesis_peer_addrs = HashSet::new();
        let retry_after = Arc::new(Mutex::new(HashMap::<String, Instant>::new()));
        let retry_delay = Arc::new(Mutex::new(HashMap::<String, Duration>::new()));
        let failure_counts = Arc::new(Mutex::new(HashMap::from([(addr.to_string(), 7)])));

        assert!(record_peer_connected_event(
            local,
            validator,
            addr,
            true,
            &connected_addrs,
            &peer_addrs,
            &addr_validators,
            &discovered_peers,
            &authenticated_peer_addrs,
            &authenticated_addr_validators,
            &connected_validator_ids,
            &bootstrap_peer_addrs,
            &genesis_peer_addrs,
            &retry_after,
            &retry_delay,
            &failure_counts,
        ));

        assert!(!failure_counts
            .lock()
            .unwrap()
            .contains_key(&addr.to_string()));
        assert!(discovered_peers.lock().unwrap().contains(&addr.to_string()));
        assert!(connected_validator_ids.lock().unwrap().contains(&validator));
    }

    #[test]
    fn bootstrap_peers_are_not_evicted_by_failure_count() {
        let peer = "198.51.100.1:30303".to_string();
        let mut discovered_peers = HashSet::from([peer.clone()]);
        let mut retry_after = HashMap::from([(peer.clone(), Instant::now())]);
        let mut retry_delay = HashMap::from([(peer.clone(), Duration::from_secs(60))]);
        let mut failure_counts = HashMap::new();
        let bootstrap = HashSet::from([peer.clone()]);

        for _ in 0..MAX_DIAL_FAILURES_BEFORE_EVICTION {
            assert!(!record_dial_failure(
                &peer,
                &mut discovered_peers,
                &mut retry_after,
                &mut retry_delay,
                &mut failure_counts,
                &bootstrap,
            ));
        }

        assert!(discovered_peers.contains(&peer));
        assert!(retry_after.contains_key(&peer));
        assert!(retry_delay.contains_key(&peer));
        assert_eq!(
            failure_counts.get(&peer).copied(),
            Some(MAX_DIAL_FAILURES_BEFORE_EVICTION)
        );
    }

    #[test]
    fn peerlist_rejects_loopback_addresses() {
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();
        assert!(!is_address_acceptable_for_discovery(&addr));

        let addr: SocketAddr = "[::1]:30303".parse().unwrap();
        assert!(!is_address_acceptable_for_discovery(&addr));
    }

    #[test]
    fn peerlist_rejects_private_addresses() {
        for raw in ["10.1.2.3:30303", "172.16.1.2:30303", "192.168.1.2:30303"] {
            let addr: SocketAddr = raw.parse().unwrap();
            assert!(!is_address_acceptable_for_discovery(&addr));
        }
    }

    #[test]
    fn peerlist_accepts_legitimate_public_addresses() {
        let addr: SocketAddr = "93.184.216.34:30303".parse().unwrap();
        assert!(is_address_acceptable_for_discovery(&addr));
    }

    fn request_proposal_test_block() -> indra_core::types::block::BlockV1 {
        use indra_core::types::block::{BlockHeaderV1, BlockV1, NO_POLC_ROUND};
        use indra_core::types::primitives::{Bytes32, ProtocolVersion, VariableBytes};

        BlockV1 {
            header: BlockHeaderV1 {
                protocol_version: ProtocolVersion::CURRENT,
                height: 7,
                prev_hash: Bytes32::from([0x01; 32]),
                timestamp: 1_700_000_007,
                state_root: Bytes32::from([0x02; 32]),
                validator_set_root: Bytes32::from([0x03; 32]),
                mempool_set_root: Bytes32::from([0x04; 32]),
                value_hash: Bytes32::from([0xAA; 32]),
                base_fee: 1,
                proposer_round: 3,
                polc_round: NO_POLC_ROUND,
                proposer_vrf_output: Bytes32::from([0x05; 32]),
                proposer_vrf_proof: VariableBytes::from_slice(&[]).unwrap(),
                quorum_certificate: VariableBytes::from_slice(&[]).unwrap(),
                election_result_hash: None,
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            vrf_reveals: vec![],
        }
    }

    fn block_response_test_block(height: u64) -> indra_core::types::block::BlockV1 {
        use indra_core::types::block::{BlockHeaderV1, BlockV1, NO_POLC_ROUND};
        use indra_core::types::primitives::{Bytes32, ProtocolVersion, VariableBytes};

        BlockV1 {
            header: BlockHeaderV1 {
                protocol_version: ProtocolVersion::CURRENT,
                height,
                prev_hash: Bytes32::from([0x01; 32]),
                timestamp: 1_700_000_000 + height,
                state_root: Bytes32::from([0x02; 32]),
                validator_set_root: Bytes32::from([0x03; 32]),
                mempool_set_root: Bytes32::from([0x04; 32]),
                value_hash: Bytes32::from([0x05; 32]),
                base_fee: 1,
                proposer_round: 0,
                polc_round: NO_POLC_ROUND,
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof: VariableBytes::from_slice(&[]).unwrap(),
                quorum_certificate: VariableBytes::from_slice(&[]).unwrap(),
                election_result_hash: None,
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
            vrf_reveals: vec![],
        }
    }

    #[test]
    fn request_proposal_serves_by_full_block_hash() {
        let block = request_proposal_test_block();
        let full_hash = block.header.block_hash();

        assert!(proposal_matches_request(&block, 7, 3, &full_hash));
    }

    #[test]
    fn request_proposal_does_not_serve_by_value_hash_alone() {
        let block = request_proposal_test_block();
        let value_hash = block.header.value_hash;
        assert_ne!(block.header.block_hash(), value_hash);

        assert!(!proposal_matches_request(&block, 7, 3, &value_hash));
    }

    #[test]
    fn request_blocks_below_prune_window_returns_lowest_available() {
        let path = std::env::temp_dir().join(format!(
            "indra_node_pruned_blocks_{}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut store = indra_storage::BlockStore::open(
            &path,
            indra_storage::PruneConfig {
                keep_blocks: Some(11),
            },
        )
        .unwrap();
        for height in 0..=20u64 {
            store.append(&block_response_test_block(height)).unwrap();
        }
        assert_eq!(store.lowest_height(), 10);

        let (blocks, lowest_available, highest_available) =
            blocks_for_range_with_availability(&mut store, 5, 6);
        assert!(blocks.is_empty());
        assert_eq!(lowest_available, Some(10));
        assert_eq!(highest_available, Some(20));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn request_blocks_within_range_returns_blocks_normally() {
        let path = std::env::temp_dir().join(format!(
            "indra_node_in_range_blocks_{}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut store =
            indra_storage::BlockStore::open(&path, indra_storage::PruneConfig::archive()).unwrap();
        for height in 0..=20u64 {
            store.append(&block_response_test_block(height)).unwrap();
        }

        let (blocks, lowest_available, highest_available) =
            blocks_for_range_with_availability(&mut store, 5, 7);
        assert_eq!(
            blocks
                .iter()
                .map(|block| block.header.height)
                .collect::<Vec<_>>(),
            vec![5, 6, 7]
        );
        assert_eq!(lowest_available, None);
        assert_eq!(highest_available, None);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn observer_request_blocks_is_rate_limited() {
        let mut limiter =
            TokenBucket::new(OBSERVER_REQUEST_BLOCKS_RATE, OBSERVER_REQUEST_BLOCKS_BURST);

        for _ in 0..OBSERVER_REQUEST_BLOCKS_BURST {
            assert!(observer_request_blocks_allowed(&mut limiter));
        }
        assert!(
            !observer_request_blocks_allowed(&mut limiter),
            "observer RequestBlocks bursts beyond the configured budget must be throttled"
        );
    }

    #[tokio::test]
    async fn handshake_semaphore_limits_concurrency() {
        let sem = Arc::new(tokio::sync::Semaphore::new(50));
        let mut permits = Vec::new();
        for _ in 0..50 {
            permits.push(sem.clone().try_acquire_owned().expect("permit"));
        }
        assert!(sem.clone().try_acquire_owned().is_err());
        drop(permits);
        assert!(sem.clone().try_acquire_owned().is_ok());
    }
}
