//! Feature-gated adapter exposing semantic consensus operations to audit tests.
use crate::{ConsensusDriver, DriverAction, NodeResult};
use indra_core::types::primitives::Bytes32;
use indra_core::types::vote::{VoteStep, VoteV1};

/// Thin wrapper around a real production driver. No consensus state is copied.
pub struct ProductionNodeAdapter { driver: ConsensusDriver }

impl ProductionNodeAdapter {
    /// Wrap an already canonically constructed production driver.
    pub fn from_driver(driver: ConsensusDriver) -> Self { Self { driver } }
    /// Borrow the underlying driver for production-backed processing.
    pub fn driver(&self) -> &ConsensusDriver { &self.driver }
    /// Current committed height.
    pub fn height(&self) -> u64 { self.driver.height() }
    /// Current consensus round.
    pub fn round(&self) -> u32 { self.driver.current_round() }
    /// Drive the production propose timeout.
    pub fn propose_timeout(&mut self) -> Vec<DriverAction> { self.driver.on_propose_timeout() }
    /// Drive the production prevote timeout.
    pub fn prevote_timeout(&mut self) -> Vec<DriverAction> { self.driver.on_prevote_timeout() }
    /// Drive the production precommit timeout.
    pub fn precommit_timeout(&mut self) -> NodeResult<()> { self.driver.on_precommit_timeout() }
    /// Create a local vote through the real safety/signing path.
    pub fn create_local_vote(&mut self, height: u64, round: u32, step: VoteStep, hash: Bytes32) -> Vec<DriverAction> {
        self.driver.audit_create_local_vote(height, round, step, hash)
    }
    /// Process a production driver event.
    pub fn process(&mut self, event: crate::DriverEvent) -> Vec<DriverAction> { self.driver.process(event) }
}

/// Keep the vote type referenced by the adapter API documentation.
#[allow(dead_code)]
fn _vote_type_marker(_: VoteV1) {}
