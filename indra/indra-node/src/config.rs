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

    /// Minimum genesis validator count. Production configurations must use 4;
    /// `local_test` uses 1 solely for focused single-validator unit fixtures.
    pub(crate) genesis_validator_minimum: usize,

    /// The node's validator identity (32-byte Ed25519 seed).
    /// If None, this node is a full node (validates but does not propose).
    pub validator_seed: Option<[u8; 32]>,

    /// The node's VRF seed (32 bytes).
    /// Required if validator_seed is set.
    pub vrf_seed: Option<[u8; 32]>,

    /// The node's ML-DSA-87 seed bytes (from keys.json).
    /// Required if validator_seed is set.
    pub pq_seed: Option<Vec<u8>>,

    /// The node's ML-DSA-87 public key bytes (from keys.json).
    pub pq_pk: Option<Vec<u8>>,

    /// Listen address for P2P (Phase 6).
    pub p2p_addr: String,

    /// Bootstrap peer addresses (Phase 6).
    pub bootstrap_peers: Vec<String>,

    /// DNS seed hostname for peer discovery.
    pub dns_seed_host: String,

    /// Whether DNS-based peer discovery is enabled.
    pub dns_discovery_enabled: bool,

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

/// Hard upper bound for the operator-configurable transaction mempool.
pub const MAX_MEMPOOL_CAPACITY: usize = 5_000;

/// Hard upper bound for the operator-configurable staking-operation pool.
pub const MAX_STAKING_MEMPOOL_CAPACITY: usize = 5_000;

/// Default governance-op mempool capacity.
///
/// The expected governance burst is bounded by active validators and active
/// proposals: commits, reveals, and redelegations for each active validator,
/// plus headroom for propose/execute/cancel operations.
pub fn default_governance_mempool_capacity() -> usize {
    max_governance_mempool_capacity()
}

/// Hard upper bound for the operator-configurable governance-operation pool.
///
/// This follows the same active-validator × active-proposal × four-operation
/// headroom formula as the default, rather than duplicating a numeric value.
pub fn max_governance_mempool_capacity() -> usize {
    MAX_ACTIVE_VALIDATORS
        .saturating_mul(MAX_ACTIVE_GOVERNANCE_PROPOSALS)
        .saturating_mul(4)
        .max(256)
}

/// Validate every operator-configurable pending-pool capacity.
pub fn validate_pool_capacities(
    mempool_capacity: usize,
    staking_mempool_capacity: usize,
    governance_mempool_capacity: usize,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    if !(1..=MAX_MEMPOOL_CAPACITY).contains(&mempool_capacity) {
        errors.push(format!(
            "storage.mempool_capacity must be between 1 and {MAX_MEMPOOL_CAPACITY}"
        ));
    }
    if !(1..=MAX_STAKING_MEMPOOL_CAPACITY).contains(&staking_mempool_capacity) {
        errors.push(format!(
            "storage.staking_mempool_capacity must be between 1 and {MAX_STAKING_MEMPOOL_CAPACITY}"
        ));
    }
    let governance_max = max_governance_mempool_capacity();
    if !(1..=governance_max).contains(&governance_mempool_capacity) {
        errors.push(format!(
            "storage.governance_mempool_capacity must be between 1 and {governance_max}"
        ));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

impl NodeConfig {
    /// Create a default configuration for local testing.
    pub fn local_test(data_dir: PathBuf) -> Self {
        let genesis_path = data_dir.join("genesis.toml");
        std::fs::create_dir_all(&data_dir).expect("create local-test data directory");
        if !genesis_path.exists() {
            let hot = indra_crypto::HybridKeypair::new(
                indra_crypto::ClassicalKeypair::from_seed(&[0x42; 32]),
                indra_crypto::PqKeypair::from_seed(&[0x43; 32]).unwrap(),
            );
            let cold =
                indra_crypto::ColdHybridKeypair::from_independent_seeds([0x44; 32], [0x45; 32])
                    .unwrap();
            let hot_public = hot.public_key();
            let cold_public = cold.public_key();
            let cold_public = cold_public.as_complete_hybrid();
            let vrf_public = indra_crypto::VrfKeypair::from_seed(&[0x42; 32]).public_key();
            let validator_id = indra_core::types::crypto::HybridPubKey {
                classical_pk: indra_core::Bytes32::from(hot_public.classical.0),
                pq_pk: indra_core::VariableBytes::from_slice(&hot_public.pq.0)
                    .expect("fixed-size ML-DSA-87 public key fits protocol maximum"),
            }
            .identity_id()
            .0;
            let contents = format!(
                "[genesis]\nchain_id = \"indra-testnet-1\"\nactive_slot_coefficient_numerator = \"9223372036854775808\"\nbitcoin_pow_entropy_header = \"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"\n\n[genesis.bitcoin_pow_entropy_source]\nscheme = 1\nnetwork_genesis_hash = \"0000000000000000000000000000000000000000000000000000000000000000\"\nannounced_height = 1\nheader_codec = 1\nextraction_algorithm = 1\nminimum_confirmations = 100\nreorg_policy = 1\n\n[[validators]]\nname = \"local-test-validator\"\nvalidator_id = \"{}\"\nstake = 1000000000000\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\ncold_hybrid_classical_pk = \"{}\"\ncold_hybrid_pq_pk = \"{}\"\ncold_key_version = 1\ncold_nonce = 0\n",
                hex::encode(validator_id), hex::encode(hot_public.classical.0),
                hex::encode(hot_public.pq.0), hex::encode(vrf_public),
                hex::encode(cold_public.classical.0), hex::encode(cold_public.pq.0),
            );
            std::fs::write(&genesis_path, contents).expect("write local-test genesis");
        }
        let peers_file = data_dir.join("peers.json").to_string_lossy().to_string();
        Self {
            data_dir,
            genesis_path: Some(genesis_path.to_string_lossy().to_string()),
            genesis_validator_minimum: 1,
            validator_seed: Some([0x42u8; 32]),
            vrf_seed: Some([0x42u8; 32]),
            pq_seed: Some(vec![0x43; indra_crypto::PQ_SK_BYTES]),
            pq_pk: Some(
                indra_crypto::PqKeypair::from_seed(&[0x43; 32])
                    .expect("fixed local-test ML-DSA seed is valid")
                    .public_key()
                    .0
                    .to_vec(),
            ),
            p2p_addr: "127.0.0.1:30303".to_string(),
            bootstrap_peers: vec![],
            dns_seed_host: indra_core::types::primitives::DNS_SEED_HOSTS.join(","),
            dns_discovery_enabled: true,
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
            genesis_validator_minimum: 4,
            validator_seed: None,
            vrf_seed: None,
            pq_seed: None,
            pq_pk: None,
            p2p_addr: "127.0.0.1:30303".to_string(),
            bootstrap_peers: vec![],
            dns_seed_host: indra_core::types::primitives::DNS_SEED_HOSTS.join(","),
            dns_discovery_enabled: true,
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
            genesis_validator_minimum: 4,
            validator_seed: None,
            vrf_seed: None,
            pq_seed: None,
            pq_pk: None,
            p2p_addr,
            bootstrap_peers: vec![],
            dns_seed_host: indra_core::types::primitives::DNS_SEED_HOSTS.join(","),
            dns_discovery_enabled: true,
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

    /// Path to the state snapshot directory.
    pub fn state_dir(&self) -> PathBuf {
        self.data_dir.join("state")
    }

    /// Pruning configuration derived from this node config.
    pub fn prune_config(&self) -> PruneConfig {
        match self.prune_keep_blocks {
            Some(keep) => PruneConfig::keep(keep),
            None => PruneConfig::archive(),
        }
    }
}
