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

use indra_core::codec::Encode;
use indra_core::types::{
    block::BlockV1,
    primitives::Bytes32,
    vote::{VoteStep, VoteV1},
};
use indra_consensus::{
    build_qc,
    vote::{RegisteredVoter, VoteCollector, VoteDecision},
};

use crate::{
    engine::NodeEngine,
    error::NodeError,
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
    /// Pending blocks by block hash until precommit quorum forms.
    pending_blocks: HashMap<Bytes32, BlockV1>,
    /// Serialised QC for the most recently finalised height.
    last_qc_bytes: Vec<u8>,
    /// Registered voters for the current epoch.
    registered_voters: Vec<RegisteredVoter>,
    /// Current consensus round for the next block height.
    current_round: u32,
}

impl ConsensusDriver {
    /// Create a new driver from a node engine.
    pub fn new(engine: NodeEngine) -> Self {
        let mut driver = Self {
            engine,
            slash_detector: SlashDetector::new(),
            vote_collectors: HashMap::new(),
            pending_blocks: HashMap::new(),
            last_qc_bytes: Vec::new(),
            registered_voters: Vec::new(),
            current_round: 0,
        };
        driver.refresh_registered_voters();
        driver
    }

    /// Register voters for the current epoch (called on epoch transition).
    pub fn set_voters(&mut self, voters: Vec<RegisteredVoter>) {
        self.vote_collectors.clear();
        self.registered_voters = voters;
    }

    /// Refresh the registered voter list from the engine's active validator set.
    pub fn refresh_registered_voters(&mut self) {
        self.set_voters(self.engine.registered_voters());
    }

    /// Return the previously finalised QC bytes for the next proposal header.
    pub fn last_qc_bytes(&self) -> Vec<u8> {
        self.last_qc_bytes.clone()
    }

    /// Current consensus round for the next block height.
    pub fn current_round(&self) -> u32 {
        self.current_round
    }

    /// Advance to the next consensus round if the current height remains unfinalized.
    pub fn advance_round(&mut self) {
        self.current_round = self.current_round.saturating_add(1);
    }

    /// Reset the consensus round after height advancement/finalization.
    pub fn reset_round(&mut self) {
        self.current_round = 0;
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

    fn process_block(&mut self, _from: Option<SocketAddr>, block: BlockV1) -> Vec<DriverAction> {
        if block.header.height != self.engine.state.height + 1
            || block.header.prev_hash != self.engine.state.tip_hash
        {
            return vec![DriverAction::None];
        }

        let mut projected_state = self.engine.state.clone();
        if indra_state::apply_block(&mut projected_state, &block).is_err() {
            return vec![DriverAction::None];
        }

        let block_hash = block.header.block_hash();
        eprintln!(
            "[vote] received proposal {} from {} at height={} round={}, staging block",
            hex::encode(&block_hash.0[..4]),
            _from.map(|addr| addr.to_string()).unwrap_or_else(|| "local".to_string()),
            block.header.height,
            block.header.proposer_round,
        );
        self.pending_blocks.insert(block_hash, block.clone());

        if let Some(action) = self.maybe_finalize_existing_quorum(
            block.header.height,
            block.header.proposer_round,
            block_hash,
        ) {
            return vec![action];
        }

        let mut actions = vec![DriverAction::BroadcastBlock(block.clone())];
        if let Ok(local_vote) = self.engine.sign_vote(
            block.header.height,
            block.header.proposer_round,
            VoteStep::Precommit,
            block_hash,
        ) {
            eprintln!(
                "[vote] sending local precommit for {} at height={} round={}",
                hex::encode(&block_hash.0[..4]),
                block.header.height,
                block.header.proposer_round,
            );
            actions.extend(self.record_vote_and_actions(SocketAddr::from(([127, 0, 0, 1], 0)), local_vote));
        } else {
            eprintln!(
                "[vote] failed to sign local precommit for {} at height={} round={}",
                hex::encode(&block_hash.0[..4]),
                block.header.height,
                block.header.proposer_round,
            );
        }

        actions
    }

    fn process_vote(&mut self, from: SocketAddr, vote: VoteV1) -> Vec<DriverAction> {
        let mut actions = Vec::new();

        eprintln!(
            "[vote] received vote from {} for {} at height={} round={}",
            from,
            hex::encode(&vote.block_hash.0[..4]),
            vote.height,
            vote.round,
        );

        // Check for slash conditions
        if let Some(evidence) = self.slash_detector.observe_vote(vote.clone()) {
            actions.push(DriverAction::SlashDetected(evidence));
        }

        // Route to appropriate vote collector
        actions.extend(self.record_vote_and_actions(from, vote));
        actions
    }

    fn record_vote_and_actions(&mut self, from: SocketAddr, vote: VoteV1) -> Vec<DriverAction> {
        let mut actions = Vec::new();
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
            Ok(VoteDecision::QuorumReached { block_hash, stake_bps: _ }) => {
                eprintln!(
                    "[vote] collected {}/{} votes for {} at height={} round={} — quorum",
                    collector.vote_count(),
                    self.registered_voters.len(),
                    hex::encode(&block_hash.0[..4]),
                    vote.height,
                    vote.round,
                );
                actions.push(DriverAction::BroadcastVote(vote.clone()));
                actions.extend(self.finalize_block_on_quorum(vote.height, vote.round, block_hash));
            }
            Ok(VoteDecision::Waiting) => {
                eprintln!(
                    "[vote] collected {}/{} votes for {} at height={} round={} — waiting",
                    collector.vote_count(),
                    self.registered_voters.len(),
                    hex::encode(&vote.block_hash.0[..4]),
                    vote.height,
                    vote.round,
                );
                actions.push(DriverAction::BroadcastVote(vote));
            }
            Err(err) => {
                eprintln!(
                    "[vote] rejected vote from {} for {} at height={} round={}: {}",
                    from,
                    hex::encode(&vote.block_hash.0[..4]),
                    vote.height,
                    vote.round,
                    err,
                );
            }
        }

        actions
    }

    fn maybe_finalize_existing_quorum(
        &mut self,
        height: u64,
        round: u32,
        block_hash: Bytes32,
    ) -> Option<DriverAction> {
        let key = (height, round);
        let Some(collector) = self.vote_collectors.get(&key) else {
            return None;
        };

        match collector.current_decision() {
            VoteDecision::QuorumReached { block_hash: quorum_hash, .. } if quorum_hash == block_hash => {
                self.finalize_block_on_quorum(height, round, block_hash)
                    .into_iter()
                    .find(|action| !matches!(action, DriverAction::None))
            }
            _ => None,
        }
    }

    fn finalize_block_on_quorum(&mut self, height: u64, round: u32, block_hash: Bytes32) -> Vec<DriverAction> {
        let Some(block) = self.pending_blocks.remove(&block_hash) else {
            eprintln!(
                "[commit] quorum reached for {} at height={} round={}, but block is not staged yet",
                hex::encode(&block_hash.0[..4]),
                height,
                round,
            );
            return vec![DriverAction::None];
        };
        let key = (height, round);
        let Some(collector) = self.vote_collectors.get(&key) else {
            eprintln!(
                "[commit] quorum reached for {} at height={} round={}, but collector is missing",
                hex::encode(&block_hash.0[..4]),
                height,
                round,
            );
            return vec![DriverAction::None];
        };

        let qc_validators = self.engine.qc_validators();
        if qc_validators.len() != self.registered_voters.len() {
            eprintln!(
                "[commit] cannot finalize {} at height={} round={} because QC validator set is incomplete",
                hex::encode(&block_hash.0[..4]),
                height,
                round,
            );
            return vec![DriverAction::None];
        }
        let quorum_votes: Vec<&VoteV1> = collector
            .accepted_votes()
            .into_iter()
            .filter(|vote| vote.block_hash == block_hash && vote.step == VoteStep::Precommit)
            .collect();
        let qc = match build_qc(height, round, block_hash, &qc_validators, quorum_votes) {
            Ok(qc) => qc,
            Err(err) => {
                eprintln!(
                    "[commit] failed to build QC for {} at height={} round={}: {}",
                    hex::encode(&block_hash.0[..4]),
                    height,
                    round,
                    err,
                );
                return vec![DriverAction::None];
            }
        };

        match self.engine.commit_block(&block) {
            Ok(_) => {
                eprintln!(
                    "[commit] quorum reached for {} at height={} round={}, finalizing",
                    hex::encode(&block_hash.0[..4]),
                    height,
                    round,
                );
                self.last_qc_bytes = qc.encode_to_vec();
                self.vote_collectors.remove(&key);
                self.slash_detector.prune_below(height.saturating_sub(100));
                self.refresh_registered_voters();
                self.reset_round();
                vec![DriverAction::BroadcastBlock(block)]
            }
            Err(NodeError::BlockInvalid { height, reason }) => {
                eprintln!(
                    "[commit] failed to finalize {} at height={}: {}",
                    hex::encode(&block_hash.0[..4]),
                    height,
                    reason,
                );
                vec![DriverAction::None]
            }
            Err(err) => {
                eprintln!(
                    "[commit] failed to finalize {} at height={} round={}: {}",
                    hex::encode(&block_hash.0[..4]),
                    height,
                    round,
                    err,
                );
                vec![DriverAction::None]
            }
        }
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
        types::primitives::{DEFAULT_COMMISSION_BPS, DUST_LIMIT_SPARK, MAX_VRF_PROOF_BYTES},
        types::vote::VoteStep,
    };
    use indra_crypto::{
        VrfKeypair,
        hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    };
    use indra_state::{ValidatorEntry, ValidatorStatus};
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
                proposer_round:      0,
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof:  VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
                quorum_certificate:  indra_core::VariableBytes::from_slice(&[]).unwrap(),
            },
            transactions:      vec![],
            slashing_evidence: vec![],
            governance_ops:    vec![],
        }
    }

    fn install_single_active_validator(driver: &mut ConsensusDriver, seed: [u8; 32]) {
        let classical = ClassicalKeypair::from_seed(&seed);
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let hybrid = HybridKeypair::new(classical, pq);
        let public = hybrid.public_key();
        let vrf_pk = VrfKeypair::from_seed(&seed).public_key();
        let validator_id = Bytes32::from(indra_crypto::sha256(&public.classical.0));

        driver.engine.state.validators.upsert(ValidatorEntry {
            validator_id,
            name: "test-validator".to_string(),
            hybrid_classical_pk: Some(public.classical.0),
            hybrid_pq_pk: Some(public.pq.0.clone()),
            vrf_pk: Some(vrf_pk),
            stake_spark: 1_000_000,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            pending_rewards: 0,
            rewards_last_epoch: 0,
            self_report_count: 0,
            commission_bps: DEFAULT_COMMISSION_BPS,
            min_delegation_spark: DUST_LIMIT_SPARK,
        }).unwrap();
        driver.refresh_registered_voters();
    }

    fn install_active_validator(driver: &mut ConsensusDriver, seed: [u8; 32], name: &str) -> HybridKeypair {
        let classical = ClassicalKeypair::from_seed(&seed);
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let hybrid = HybridKeypair::new(classical, pq);
        let public = hybrid.public_key();
        let vrf_pk = VrfKeypair::from_seed(&seed).public_key();
        let validator_id = Bytes32::from(indra_crypto::sha256(&public.classical.0));

        driver.engine.state.validators.upsert(ValidatorEntry {
            validator_id,
            name: name.to_string(),
            hybrid_classical_pk: Some(public.classical.0),
            hybrid_pq_pk: Some(public.pq.0.clone()),
            vrf_pk: Some(vrf_pk),
            stake_spark: 1_000_000,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            pending_rewards: 0,
            rewards_last_epoch: 0,
            self_report_count: 0,
            commission_bps: DEFAULT_COMMISSION_BPS,
            min_delegation_spark: DUST_LIMIT_SPARK,
        }).unwrap();
        hybrid
    }

    #[test]
    fn driver_commits_valid_block() {
        let dir = temp_dir("a");
        let mut config = NodeConfig::local_test(dir.clone());
        let pq = PqKeypair::from_seed(&[0x42u8; 32]).unwrap();
        config.pq_pk = Some(pq.public_key().0.clone());
        config.pq_sk = Some(pq.secret_key_bytes());
        let engine = NodeEngine::init(config).unwrap();
        let mut driver = ConsensusDriver::new(engine);
        install_single_active_validator(&mut driver, [0x42u8; 32]);

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

    #[test]
    fn driver_finalizes_when_votes_arrive_before_block() {
        let dir = temp_dir("d");
        let mut config = NodeConfig::local_test(dir.clone());
        let local_seed = [0x42u8; 32];
        let pq = PqKeypair::from_seed(&local_seed).unwrap();
        config.validator_seed = Some(local_seed);
        config.vrf_seed = Some(local_seed);
        config.pq_pk = Some(pq.public_key().0.clone());
        config.pq_sk = Some(pq.secret_key_bytes());
        let engine = NodeEngine::init(config).unwrap();
        let mut driver = ConsensusDriver::new(engine);

        let remote_a = install_active_validator(&mut driver, [0x43u8; 32], "remote-a");
        let remote_b = install_active_validator(&mut driver, [0x44u8; 32], "remote-b");
        let _local = install_active_validator(&mut driver, local_seed, "local");
        driver.refresh_registered_voters();

        let block = make_block(1, driver.engine.state.tip_hash, driver.engine.state.base_fee);
        let block_hash = block.header.block_hash();

        let remote_a_id = Bytes32::from(indra_crypto::sha256(&remote_a.public_key().classical.0));
        let remote_b_id = Bytes32::from(indra_crypto::sha256(&remote_b.public_key().classical.0));
        let vote_a = indra_consensus::vote::produce_vote(
            1, 0, VoteStep::Precommit, block_hash, remote_a_id, &remote_a
        ).unwrap();
        let vote_b = indra_consensus::vote::produce_vote(
            1, 0, VoteStep::Precommit, block_hash, remote_b_id, &remote_b
        ).unwrap();

        let peer_a: SocketAddr = "127.0.0.1:9101".parse().unwrap();
        let peer_b: SocketAddr = "127.0.0.1:9102".parse().unwrap();
        let _ = driver.process(DriverEvent::InboundVote { from: peer_a, vote: vote_a });
        let _ = driver.process(DriverEvent::InboundVote { from: peer_b, vote: vote_b });

        let actions = driver.process(DriverEvent::InboundBlock { from: Some(peer_a), block });

        assert!(actions.iter().any(|a| matches!(a, DriverAction::BroadcastBlock(_))));
        assert_eq!(driver.height(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
