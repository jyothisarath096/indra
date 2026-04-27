//! Node configuration.
//!
//! In Phase 5 configuration is loaded from environment variables with
//! sensible defaults. Phase 7 adds a TOML config file.

use std::path::PathBuf;

/// All configuration for a running INDRA node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Directory for persistent data (blocks, state snapshots, WAL).
    pub data_dir: PathBuf,

    /// The node's validator identity (32-byte Ed25519 seed).
    /// If None, this node is a full node (validates but does not propose).
    pub validator_seed: Option<[u8; 32]>,

    /// The node's BLS signing seed (32 bytes).
    /// Required if validator_seed is set.
    pub bls_seed: Option<[u8; 32]>,

    /// The node's VRF seed (32 bytes).
    /// Required if validator_seed is set.
    pub vrf_seed: Option<[u8; 32]>,

    /// The node's Dilithium2 secret key bytes (from keys.json).
    /// Required if validator_seed is set.
    pub pq_sk: Option<Vec<u8>>,

    /// The node's Dilithium2 public key bytes (from keys.json).
    pub pq_pk: Option<Vec<u8>>,

    /// Listen address for P2P (Phase 6).
    pub p2p_addr: String,

    /// Bootstrap peer addresses (Phase 6).
    pub bootstrap_peers: Vec<String>,

    /// How many blocks between state snapshots.
    pub snapshot_interval: u64,

    /// Maximum mempool size (number of transactions).
    pub mempool_capacity: usize,
}

impl NodeConfig {
    /// Create a default configuration for local testing.
    pub fn local_test(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            validator_seed:   Some([0x42u8; 32]),
            bls_seed:         Some([0x42u8; 32]),
            vrf_seed:         Some([0x42u8; 32]),
            pq_sk:            None,
            pq_pk:            None,
            p2p_addr:         "127.0.0.1:30303".to_string(),
            bootstrap_peers:  vec![],
            snapshot_interval: 300,
            mempool_capacity:  5_000,
        }
    }

    /// Create a validator-less full node config for testing.
    pub fn full_node(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            validator_seed:   None,
            bls_seed:         None,
            vrf_seed:         None,
            pq_sk:            None,
            pq_pk:            None,
            p2p_addr:         "127.0.0.1:30303".to_string(),
            bootstrap_peers:  vec![],
            snapshot_interval: 300,
            mempool_capacity:  5_000,
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

    /// Path to the state snapshot directory.
    pub fn state_dir(&self) -> PathBuf {
        self.data_dir.join("state")
    }

    /// Path to the mempool WAL file.
    pub fn wal_path(&self) -> PathBuf {
        self.data_dir.join("mempool.wal")
    }
}
