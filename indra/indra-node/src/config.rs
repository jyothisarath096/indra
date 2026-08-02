//! Node configuration.
//!
//! In Phase 5 configuration is loaded from environment variables with
//! sensible defaults. Phase 7 adds a TOML config file.

use std::path::PathBuf;

use indra_core::types::primitives::MAX_ACTIVE_VALIDATORS;
use indra_state::governance::MAX_ACTIVE_GOVERNANCE_PROPOSALS;
use indra_storage::PruneConfig;

use crate::discovery::{DnsSeedValidationMode, SignedDnsSeedValidationMode};

/// All configuration for a running INDRA node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Directory for persistent data (blocks, state snapshots, WAL).
    pub data_dir: PathBuf,

    /// Optional path to `genesis.toml` for seeding the initial validator set.
    ///
    /// This is applied exactly once when building the base genesis state
    /// before any block replay. Snapshot-based restarts do not reload genesis
    /// into an already-populated state.
    pub genesis_path: Option<String>,

    /// The node's validator identity (32-byte Ed25519 seed).
    /// If None, this node is a full node (validates but does not propose).
    pub validator_seed: Option<[u8; 32]>,

    /// The node's VRF seed (32 bytes).
    /// Required if validator_seed is set.
    pub vrf_seed: Option<[u8; 32]>,

    /// The node's ML-DSA-87 seed bytes (from keys.json).
    /// Required if validator_seed is set.
    pub pq_sk: Option<Vec<u8>>,

    /// The node's ML-DSA-87 public key bytes (from keys.json).
    pub pq_pk: Option<Vec<u8>>,

    /// Listen address for P2P (Phase 6).
    pub p2p_addr: String,

    /// Bootstrap peer addresses (Phase 6).
    pub bootstrap_peers: Vec<String>,

    /// DNS seed hostname for peer discovery.
    pub dns_seed_host: String,

    /// DNSSEC validation policy for DNS seed hostname responses.
    pub dns_seed_validation: DnsSeedValidationMode,

    /// Signed DNS node-list validation policy.
    pub dns_seed_signed_validation: SignedDnsSeedValidationMode,

    /// ML-DSA-87 public key for signed DNS node-list verification.
    ///
    /// This key is the trust anchor for signed discovery and must be known
    /// independently of DNS. DNS is only transport for the signed list.
    pub dns_seed_signed_public_key: Option<Vec<u8>>,

    /// Path to peer table persistence file.
    pub peers_file: String,

    /// How many blocks between state snapshots.
    pub snapshot_interval: u64,

    /// Maximum mempool size (number of transactions).
    pub mempool_capacity: usize,

    /// Maximum staking operations held in the local staking-op mempool.
    pub staking_mempool_capacity: usize,

    /// Maximum governance operations held in the local governance-op mempool.
    pub governance_mempool_capacity: usize,

    /// Number of recent blocks to keep in pruned mode.
    ///
    /// `None` means archive mode.
    pub prune_keep_blocks: Option<u64>,

    /// Listen address for the observer/full-node port.
    ///
    /// `None` disables the observer port entirely.
    pub observer_addr: Option<String>,

    /// Listen address for the Prometheus metrics endpoint.
    ///
    /// `None` disables metrics entirely.
    pub metrics_addr: Option<String>,
}

/// Default staking-op mempool capacity.
pub const DEFAULT_STAKING_MEMPOOL_CAPACITY: usize = 5_000;

/// Default governance-op mempool capacity.
///
/// The expected governance burst is bounded by active validators and active
/// proposals: commits, reveals, and redelegations for each active validator,
/// plus headroom for propose/execute/cancel operations.
pub fn default_governance_mempool_capacity() -> usize {
    MAX_ACTIVE_VALIDATORS
        .saturating_mul(MAX_ACTIVE_GOVERNANCE_PROPOSALS)
        .saturating_mul(4)
        .max(256)
}

impl NodeConfig {
    /// Create a default configuration for local testing.
    pub fn local_test(data_dir: PathBuf) -> Self {
        let peers_file = data_dir.join("peers.json").to_string_lossy().to_string();
        Self {
            data_dir,
            genesis_path: None,
            validator_seed: Some([0x42u8; 32]),
            vrf_seed: Some([0x42u8; 32]),
            pq_sk: None,
            pq_pk: None,
            p2p_addr: "127.0.0.1:30303".to_string(),
            bootstrap_peers: vec![],
            dns_seed_host: indra_core::types::primitives::DNS_SEED_HOSTS.join(","),
            dns_seed_validation: DnsSeedValidationMode::DEFAULT,
            dns_seed_signed_validation: SignedDnsSeedValidationMode::DEFAULT,
            dns_seed_signed_public_key: None,
            peers_file,
            snapshot_interval: 300,
            mempool_capacity: 5_000,
            staking_mempool_capacity: DEFAULT_STAKING_MEMPOOL_CAPACITY,
            governance_mempool_capacity: default_governance_mempool_capacity(),
            prune_keep_blocks: None,
            observer_addr: None,
            metrics_addr: None,
        }
    }

    /// Create a validator-less full node config for testing.
    pub fn full_node(data_dir: PathBuf) -> Self {
        let peers_file = data_dir.join("peers.json").to_string_lossy().to_string();
        Self {
            data_dir,
            genesis_path: None,
            validator_seed: None,
            vrf_seed: None,
            pq_sk: None,
            pq_pk: None,
            p2p_addr: "127.0.0.1:30303".to_string(),
            bootstrap_peers: vec![],
            dns_seed_host: indra_core::types::primitives::DNS_SEED_HOSTS.join(","),
            dns_seed_validation: DnsSeedValidationMode::DEFAULT,
            dns_seed_signed_validation: SignedDnsSeedValidationMode::DEFAULT,
            dns_seed_signed_public_key: None,
            peers_file,
            snapshot_interval: 300,
            mempool_capacity: 5_000,
            staking_mempool_capacity: DEFAULT_STAKING_MEMPOOL_CAPACITY,
            governance_mempool_capacity: default_governance_mempool_capacity(),
            prune_keep_blocks: None,
            observer_addr: Some(format!(
                "0.0.0.0:{}",
                indra_core::types::primitives::OBSERVER_PORT
            )),
            metrics_addr: Some(crate::metrics::DEFAULT_METRICS_ADDR.to_string()),
        }
    }

    /// Create an observer node config.
    pub fn observer_node(data_dir: PathBuf, p2p_addr: String) -> Self {
        let peers_file = data_dir.join("peers.json").to_string_lossy().to_string();
        Self {
            data_dir,
            genesis_path: None,
            validator_seed: None,
            vrf_seed: None,
            pq_sk: None,
            pq_pk: None,
            p2p_addr,
            bootstrap_peers: vec![],
            dns_seed_host: indra_core::types::primitives::DNS_SEED_HOSTS.join(","),
            dns_seed_validation: DnsSeedValidationMode::DEFAULT,
            dns_seed_signed_validation: SignedDnsSeedValidationMode::DEFAULT,
            dns_seed_signed_public_key: None,
            peers_file,
            snapshot_interval: 300,
            mempool_capacity: 5_000,
            staking_mempool_capacity: DEFAULT_STAKING_MEMPOOL_CAPACITY,
            governance_mempool_capacity: default_governance_mempool_capacity(),
            prune_keep_blocks: None,
            observer_addr: Some(format!(
                "0.0.0.0:{}",
                indra_core::types::primitives::OBSERVER_PORT
            )),
            metrics_addr: Some(crate::metrics::DEFAULT_OBSERVER_METRICS_ADDR.to_string()),
        }
    }

    /// True if this node is configured as a validator.
    pub fn is_validator(&self) -> bool {
        self.validator_seed.is_some()
    }

    /// Path to the block log file.
    pub fn block_log_path(&self) -> PathBuf {
        self.data_dir.join("blocks.log")
    }

    /// Path to the epoch history log.
    pub fn epoch_log_path(&self) -> PathBuf {
        self.data_dir.join("epochs.log")
    }

    /// Path to the vote safety persistence file.
    pub fn vote_safety_path(&self) -> PathBuf {
        self.data_dir.join("vote_safety.dat")
    }

    /// Path to the schema migration audit log.
    pub fn migration_log_path(&self) -> PathBuf {
        self.data_dir.join("migration.log")
    }

    /// Path to the state snapshot directory.
    pub fn state_dir(&self) -> PathBuf {
        self.data_dir.join("state")
    }

    /// Path to the mempool WAL file.
    pub fn wal_path(&self) -> PathBuf {
        self.data_dir.join("mempool.wal")
    }

    /// Pruning configuration derived from this node config.
    pub fn prune_config(&self) -> PruneConfig {
        match self.prune_keep_blocks {
            Some(keep) => PruneConfig::keep(keep),
            None => PruneConfig::archive(),
        }
    }
}
