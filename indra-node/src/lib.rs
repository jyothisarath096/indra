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
pub mod error;
pub mod genesis;
pub mod engine;
pub mod state_root;
pub mod sync;
pub mod slash;
pub mod driver;
pub mod net_driver;
pub mod reactor;

pub use config::NodeConfig;
pub use error::{NodeError, NodeResult};
pub use engine::NodeEngine;
pub use genesis::{build_genesis_block, build_genesis_state, load_genesis_validators};
pub use sync::import_block;
pub use slash::{SlashDetector, SlashEvidence, SlashOffence};
pub use driver::{ConsensusDriver, DriverEvent, DriverAction};
pub use net_driver::{message_to_event, action_to_message};
pub use reactor::{ChainSnapshot, ConsensusAction, ConsensusEvent, ConsensusReactor};
