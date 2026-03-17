//! Consensus driver — ties NodeEngine to the network layer.
//!
//! The driver is the top-level coordinator that:
//!   1. Accepts inbound messages (blocks, votes, txs) from the gossip engine
//!   2. Routes them to the appropriate subsystem (mempool, vote collector, sync)
//!   3. Triggers block proposal when this node is the elected proposer
//!   4. Forwards slash evidence to the slash detector
//!   5. Broadcasts committed blocks and QCs to peers
//!
//! ## Phase 6 execution model
//!
//! The driver runs a synchronous event loop suitable for single-threaded
//! testing. Phase 7 wraps this in Tokio for async I/O.
//!
//! ## Message routing
//!
//! ```text
//! Inbound message
//!     │
//!     ├── Block  → validate → apply_block → broadcast to peers
//!     ├── Vote   → slash_detector → vote_collector → if quorum: build QC
//!     ├── Tx     → mempool.submit
//!     └── Status → peer_table.update_height → if behind: send GetBlocks
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;

use indra_core::types::{
    block::BlockV1,
    primitives::Bytes32,
    vote::{VoteStep, VoteV1},
};
use indra_consensus::{
    vote::{RegisteredVoter, VoteCollector, VoteDecision},
};

use crate::{
    engine::NodeEngine,
    error::{NodeError, NodeResult},
    slash::{SlashDetector, SlashEvidence},
};

/// An inbound event for the driver to process.
#[derive(Debug)]
pub enum DriverEvent {
    /// A block arrived from a peer or was proposed locally.
    InboundBlock {
        /// Who sent it (None if proposed locally).
        from: Option<SocketAddr>,
        /// The block.
        block: BlockV1,
    },
    /// A vote arrived from a peer.
    InboundVote {
        /// Who sent it.
        from: SocketAddr,
        /// The vote.
        vote: VoteV1,
    },
    /// A new transaction arrived.
    InboundTx {
        /// Who sent it.
        from: SocketAddr,
        /// Encoded transaction bytes.
        tx_bytes: Vec<u8>,
    },
    /// A peer announced its chain status.
    PeerStatus {
        /// The peer.
        from: SocketAddr,
        /// Their height.
        height: u64,
        /// Their tip hash.
        tip_hash: Bytes32,
    },
}

/// An action the driver wants to perform in response to an event.
#[derive(Debug)]
pub enum DriverAction {
    /// Broadcast this block to all peers.
    BroadcastBlock(BlockV1),
    /// Broadcast this vote to all peers.
    BroadcastVote(VoteV1),
    /// Request blocks from a specific peer.
    RequestBlocks {
        /// The peer to ask.
        from: SocketAddr,
        /// First height needed.
        from_height: u64,
        /// Last height needed.
        to_height: u64,
    },
    /// Slash evidence was detected.
    SlashDetected(SlashEvidence),
    /// No action needed.
    None,
}

/// The consensus driver.
pub struct ConsensusDriver {
    /// The underlying node engine.
    pub engine: NodeEngine,
    /// Slash evidence detector.
    slash_detector: SlashDetector,
    /// Vote collectors keyed by (height, round).
    vote_collectors: HashMap<(u64, u32), VoteCollector>,
    /// Registered voters for the current epoch.
    registered_voters: Vec<RegisteredVoter>,
}

impl ConsensusDriver {
    /// Create a new driver from a node engine.
    pub fn new(engine: NodeEngine) -> Self {
        Self {
            engine,
            slash_detector: SlashDetector::new(),
            vote_collectors: HashMap::new(),
            registered_voters: Vec::new(),
        }
    }

    /// Register voters for the current epoch (called on epoch transition).
    pub fn set_voters(&mut self, voters: Vec<RegisteredVoter>) {
        self.vote_collectors.clear();
        self.registered_voters = voters;
    }

    /// Process one inbound event. Returns a list of actions to take.
    pub fn process(&mut self, event: DriverEvent) -> Vec<DriverAction> {
        match event {
            DriverEvent::InboundBlock { from, block } => {
                self.process_block(from, block)
            }
            DriverEvent::InboundVote { from, vote } => {
                self.process_vote(from, vote)
            }
            DriverEvent::InboundTx { from, tx_bytes } => {
                self.process_tx(from, tx_bytes)
            }
            DriverEvent::PeerStatus { from, height, tip_hash } => {
                self.process_status(from, height, tip_hash)
            }
        }
    }

    fn process_block(&mut self, from: Option<SocketAddr>, block: BlockV1) -> Vec<DriverAction> {
        let height = block.header.height;

        // Try to import (validate + apply + store)
        match self.engine.commit_block(&block) {
            Ok(_) => {
                // Prune slash detector state older than this height
                self.slash_detector.prune_below(height.saturating_sub(100));
                vec![DriverAction::BroadcastBlock(block)]
            }
            Err(NodeError::BlockInvalid { height, reason }) => {
                // Don't broadcast invalid blocks
                vec![DriverAction::None]
            }
            Err(_) => vec![DriverAction::None],
        }
    }

    fn process_vote(&mut self, from: SocketAddr, vote: VoteV1) -> Vec<DriverAction> {
        let mut actions = Vec::new();

        // Check for slash conditions
        if let Some(evidence) = self.slash_detector.observe_vote(vote.clone()) {
            actions.push(DriverAction::SlashDetected(evidence));
        }

        // Route to appropriate vote collector
        let key = (vote.height, vote.round);
        let collector = self.vote_collectors
            .entry(key)
            .or_insert_with(|| VoteCollector::new(
                vote.height,
                vote.round,
                vote.step,
                self.registered_voters.clone(),
            ));

        match collector.add_vote(vote.clone()) {
            Ok(VoteDecision::QuorumReached { block_hash, stake_bps }) => {
                // Quorum reached — in Phase 7 this triggers QC construction
                // For now just broadcast the vote
                actions.push(DriverAction::BroadcastVote(vote));
            }
            Ok(VoteDecision::Waiting) => {
                actions.push(DriverAction::BroadcastVote(vote));
            }
            Err(_) => {
                // Invalid vote — no action
            }
        }

        actions
    }

    fn process_tx(&mut self, _from: SocketAddr, tx_bytes: Vec<u8>) -> Vec<DriverAction> {
        use indra_core::codec::{Decode, ByteReader};
        use indra_core::types::transaction::TransactionV1;

        let mut reader = ByteReader::new(&tx_bytes);
        let tx = match TransactionV1::decode(&mut reader) {
            Ok(tx) => tx,
            Err(_) => return vec![DriverAction::None],
        };

        let base_fee = self.engine.state.base_fee;
        let height   = self.engine.state.height;
        let _ = self.engine.mempool.submit(tx, base_fee, height);
        vec![DriverAction::None]
    }

    fn process_status(
        &mut self,
        from: SocketAddr,
        height: u64,
        _tip_hash: Bytes32,
    ) -> Vec<DriverAction> {
        let our_height = self.engine.height();
        if height > our_height + 1 {
            // We're behind — request missing blocks
            vec![DriverAction::RequestBlocks {
                from,
                from_height: our_height + 1,
                to_height: height,
            }]
        } else {
            vec![DriverAction::None]
        }
    }

    /// Current chain height.
    pub fn height(&self) -> u64 {
        self.engine.height()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        Bytes32, ProtocolVersion, VariableBytes,
        types::block::{BlockHeaderV1, BlockV1},
        types::primitives::{INITIAL_BASE_FEE_SPARK_PER_KB, MAX_VRF_PROOF_BYTES},
    };
    use crate::NodeConfig;
    use std::path::PathBuf;

    fn temp_dir(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("indra_driver_test_{}_{}", suffix, std::process::id()));
        p
    }

    fn make_block(height: u64, prev_hash: Bytes32, base_fee: u64) -> BlockV1 {
        BlockV1 {
            header: BlockHeaderV1 {
                protocol_version:    ProtocolVersion::CURRENT,
                height,
                prev_hash,
                timestamp:           1_700_000_000 + height,
                state_root:          Bytes32::ZERO,
                validator_set_root:  Bytes32::ZERO,
                mempool_set_root:    Bytes32::ZERO,
                base_fee,
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof:  VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
                quorum_certificate:  indra_core::VariableBytes::from_slice(&[]).unwrap(),
            },
            transactions:      vec![],
            slashing_evidence: vec![],
            governance_ops:    vec![],
        }
    }

    #[test]
    fn driver_commits_valid_block() {
        let dir = temp_dir("a");
        let config = NodeConfig::local_test(dir.clone());
        let engine = NodeEngine::init(config).unwrap();
        let mut driver = ConsensusDriver::new(engine);

        let block = make_block(1, driver.engine.state.tip_hash, driver.engine.state.base_fee);
        let actions = driver.process(DriverEvent::InboundBlock { from: None, block });

        assert!(actions.iter().any(|a| matches!(a, DriverAction::BroadcastBlock(_))));
        assert_eq!(driver.height(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn driver_requests_blocks_when_behind() {
        let dir = temp_dir("b");
        let config = NodeConfig::local_test(dir.clone());
        let engine = NodeEngine::init(config).unwrap();
        let mut driver = ConsensusDriver::new(engine);

        let peer: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let actions = driver.process(DriverEvent::PeerStatus {
            from: peer,
            height: 50, // peer is at 50, we're at 0
            tip_hash: Bytes32::ZERO,
        });

        assert!(actions.iter().any(|a| matches!(a, DriverAction::RequestBlocks { .. })));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn driver_detects_double_precommit() {
        let dir = temp_dir("c");
        let config = NodeConfig::local_test(dir.clone());
        let engine = NodeEngine::init(config).unwrap();
        let mut driver = ConsensusDriver::new(engine);

        use indra_core::types::{
            crypto::HybridSignature,
            primitives::{MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES},
        };

        let peer: SocketAddr = "127.0.0.1:9998".parse().unwrap();
        let v_id = Bytes32::from([0x01u8; 32]);

        let vote_a = VoteV1 {
            height: 1, round: 0, step: VoteStep::Precommit,
            block_hash: Bytes32::from([0xAAu8; 32]),
            validator_id: v_id,
            signature: HybridSignature {
                classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(&[0u8; 64]).unwrap(),
                pq_sig:        VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&[0u8; 32]).unwrap(),
            },
        };
        let vote_b = VoteV1 {
            height: 1, round: 0, step: VoteStep::Precommit,
            block_hash: Bytes32::from([0xBBu8; 32]),
            validator_id: v_id,
            signature: HybridSignature {
                classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(&[0u8; 64]).unwrap(),
                pq_sig:        VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&[0u8; 32]).unwrap(),
            },
        };

        driver.process(DriverEvent::InboundVote { from: peer, vote: vote_a });
        let actions = driver.process(DriverEvent::InboundVote { from: peer, vote: vote_b });

        assert!(actions.iter().any(|a| matches!(a, DriverAction::SlashDetected(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
