//! # indra-node
//!
//! The INDRA v2 node: ties together all protocol components into a
//! runnable unit.
//!
//! ## Architecture
//!
//! ```text
//!  ┌──────────────────────────────────────────────────┐
//!  │               ConsensusDriver                     │
//!  │                                                    │
//!  │  ┌──────────────┐  ┌──────────┐  ┌────────────┐  │
//!  │  │  NodeEngine  │  │  Slash   │  │   Network  │  │
//!  │  │ (consensus)  │  │Detector  │  │  (gossip)  │  │
//!  │  └──────────────┘  └──────────┘  └────────────┘  │
//!  │         │                                          │
//!  │  ┌──────────────┐  ┌──────────┐                   │
//!  │  │   Storage    │  │  State   │                   │
//!  │  │  (blocks +   │  │ Machine  │                   │
//!  │  │  snapshots)  │  └──────────┘                   │
//!  │  └──────────────┘                                  │
//!  └──────────────────────────────────────────────────┘
//! ```

#![forbid(unsafe_code)]
#![deny(unused_must_use)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable, clippy::todo, clippy::unimplemented)]
#![cfg_attr(
    any(test, feature = "test-support"),
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod config;
pub mod config_file;
mod consensus_authority;
pub mod discovery;
pub mod driver;
pub mod engine;
pub mod error;
pub mod genesis;
pub mod hardened_read_rpc;
pub mod metrics;
pub mod locks;
pub mod net_driver;
mod pending_dependencies;
pub mod qc_verification;
pub mod recovery;
pub mod rpc_snapshot;
pub mod slash;
pub mod sync;
pub mod supervisor;
#[cfg(feature = "audit-harness")]
pub mod audit_harness;

pub use config::NodeConfig;
pub use config_file::{KeysData, NodeConfigFile};
pub use driver::{ConsensusDriver, DriverAction, DriverEvent};
pub use engine::NodeEngine;
pub use error::{NodeError, NodeResult};
pub use genesis::{
    build_finalized_genesis_state, build_genesis_block,
    parse_genesis_manifest, parse_genesis_manifest_str,
    validate_genesis_manifest, GenesisManifest, GenesisSeed, GenesisSettings, GenesisValidator,
};
pub use metrics::{
    start_metrics_server, start_observer_metrics_server, MetricsServerConfig, MetricsState,
    RpcLimiterTelemetry,
};
pub use net_driver::{action_to_message, message_to_event};
pub use slash::{SlashDetector, SlashEvidence, SlashOffence};

impl indra_rpc::handlers::RpcEngineView for NodeEngine {
    fn chain_state(&self) -> &indra_state::ChainState {
        &self.state
    }

    fn mempool_size(&self) -> usize {
        self.mempool.len()
    }

    fn pruned_mode(&self) -> bool {
        !self.block_store.is_archive()
    }

    fn lowest_block(&self) -> u64 {
        self.block_store.lowest_height()
    }

    fn blocks_retained(&self) -> usize {
        self.block_store.len()
    }

    fn get_block_by_height(
        &self,
        height: u64,
    ) -> Result<Option<indra_core::types::block::BlockVNext>, String> {
        match self.block_store.get_read_only(height) {
            Ok(proposal) => Ok(Some(proposal.block)),
            Err(indra_storage::StorageError::BlockNotFound { .. })
            | Err(indra_storage::StorageError::BlockPruned { .. }) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn get_epoch_record(&self, epoch: u64) -> Result<Option<indra_core::EpochRecord>, String> {
        match self.epoch_store.get(epoch) {
            Ok(record) => Ok(Some(record)),
            Err(indra_storage::StorageError::EpochNotFound { .. }) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn latest_epoch(&self) -> Result<Option<u64>, String> {
        Ok(self.epoch_store.latest_epoch())
    }

    fn get_epoch_range(
        &self,
        to_epoch: u64,
        limit: usize,
    ) -> Result<Vec<indra_core::EpochRecord>, String> {
        self.epoch_store
            .get_range(to_epoch, limit)
            .map_err(|error| error.to_string())
    }
}

impl indra_rpc::handlers::RpcEngineMut for NodeEngine {
    fn rpc_add_staking_op(
        &mut self,
        op: indra_core::types::staking::StakingOp,
    ) -> Result<(), String> {
        self.add_staking_op(op).map_err(|error| error.to_string())
    }

    fn rpc_add_governance_op(
        &mut self,
        op: indra_core::types::governance::GovernanceOpV2,
    ) -> Result<(), String> {
        self.add_governance_op(op)
            .map_err(|error| error.to_string())
    }

    fn rpc_submit_transaction(
        &mut self,
        tx: indra_core::types::transaction::TransactionV1,
    ) -> Result<indra_core::Bytes32, String> {
        self.add_transaction(tx).map_err(|error| error.to_string())
    }
}
