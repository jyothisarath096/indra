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
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod config;
pub mod config_file;
pub mod discovery;
pub mod driver;
pub mod engine;
pub mod error;
pub mod genesis;
pub mod metrics;
pub mod net_driver;
pub mod slash;
pub mod state_root;
pub mod sync;

pub use config::NodeConfig;
pub use config_file::{KeysData, NodeConfigFile};
pub use driver::{ConsensusDriver, DriverAction, DriverEvent};
pub use engine::NodeEngine;
pub use error::{NodeError, NodeResult};
pub use genesis::{build_genesis_block, build_genesis_state, load_genesis_validators};
pub use metrics::{start_metrics_server, start_observer_metrics_server, MetricsState};
pub use net_driver::{action_to_message, message_to_event};
pub use slash::{SlashDetector, SlashEvidence, SlashOffence};
pub use sync::import_block;

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

    fn migration_history(&self) -> Result<Vec<indra_rpc::handlers::MigrationRecordView>, String> {
        self.migration_log
            .load_all()
            .map(|records| {
                records
                    .into_iter()
                    .map(|record| indra_rpc::handlers::MigrationRecordView {
                        timestamp_secs: record.timestamp_secs,
                        from_version: record.from_version,
                        to_version: record.to_version,
                        state_height: record.state_height,
                        validators_migrated: record.validators_migrated,
                        utxos_migrated: record.utxos_migrated,
                    })
                    .collect()
            })
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
        let state = self.state.clone();
        self.mempool
            .submit_validated(tx, &state)
            .map_err(|error| error.to_string())
    }
}
