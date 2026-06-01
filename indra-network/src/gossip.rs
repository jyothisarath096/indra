//! Gossip engine — broadcast messages to all connected peers.
//!
//! ## Algorithm
//!
//! When a node receives a message from peer A:
//!   1. Validate the message (structural only — full validation is in indra-node)
//!   2. If not seen before: forward to all other connected peers
//!   3. If seen before: discard (deduplication by message hash)
//!
//! The seen-message cache holds the last SEEN_CACHE_SIZE message hashes.
//! This prevents infinite gossip loops without requiring persistent storage.
//!
//! ## Fanout
//!
//! Each message is forwarded to at most MAX_GOSSIP_FANOUT peers chosen
//! by highest score. This limits bandwidth while maintaining propagation.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;

use indra_core::types::primitives::Bytes32;
use indra_crypto::sha256;

use crate::{
    error::{NetworkError, NetworkResult},
    message::Message,
    peer::{PeerTable, ScoreEvent},
    transport::Connection,
};

/// Maximum gossip fanout per message.
pub const MAX_GOSSIP_FANOUT: usize = 8;
/// How many message hashes to keep in the dedup cache.
pub const SEEN_CACHE_SIZE: usize = 10_000;

/// An event produced by the gossip engine for the node to process.
#[derive(Debug)]
pub enum GossipEvent {
    /// A new block was received from a peer.
    NewBlock {
        /// The sender.
        from: SocketAddr,
        /// The encoded block bytes (to be decoded and validated by node).
        block_bytes: Vec<u8>,
    },
    /// A new vote was received.
    NewVote {
        /// The sender.
        from: SocketAddr,
        /// The encoded vote bytes.
        vote_bytes: Vec<u8>,
    },
    /// A new transaction was received.
    NewTx {
        /// The sender.
        from: SocketAddr,
        /// The encoded tx bytes.
        tx_bytes: Vec<u8>,
    },
    /// A peer announced its chain status.
    PeerStatus {
        /// The peer.
        from: SocketAddr,
        /// Their current height.
        height: u64,
        /// Their tip hash.
        tip_hash: Bytes32,
    },
    /// A peer sent us its peer list.
    PeerList {
        /// The sender.
        from: SocketAddr,
        /// The addresses they know.
        addrs: Vec<String>,
    },
    /// A peer requested blocks.
    GetBlocksRequest {
        /// The requesting peer.
        from: SocketAddr,
        /// First height requested.
        from_height: u64,
        /// Last height requested.
        to_height: u64,
    },
}

/// The gossip engine.
pub struct GossipEngine {
    peers:        PeerTable,
    connections:  HashMap<SocketAddr, Connection>,
    seen_msgs:    VecDeque<[u8; 32]>,
    seen_set:     HashSet<[u8; 32]>,
}

impl GossipEngine {
    /// Create a new gossip engine with an empty peer table.
    pub fn new() -> Self {
        Self {
            peers:       PeerTable::new(),
            connections: HashMap::new(),
            seen_msgs:   VecDeque::with_capacity(SEEN_CACHE_SIZE),
            seen_set:    HashSet::new(),
        }
    }

    /// Add a connection for a peer.
    pub fn add_connection(&mut self, addr: SocketAddr, conn: Connection) -> NetworkResult<()> {
        self.peers.add(addr)?;
        self.peers.mark_connected(&addr);
        self.connections.insert(addr, conn);
        Ok(())
    }

    /// Remove a peer connection.
    pub fn remove_connection(&mut self, addr: &SocketAddr) {
        self.connections.remove(addr);
        self.peers.mark_disconnected(addr);
    }

    /// Broadcast a message to all connected peers (up to MAX_GOSSIP_FANOUT).
    ///
    /// Marks the message as seen so it won't be re-broadcast if received back.
    pub fn broadcast(&mut self, msg: &Message) -> NetworkResult<()> {
        let wire = msg.encode_wire()?;
        let hash = sha256(&wire);
        self.mark_seen(hash);

        // Choose top-scored peers
        let targets: Vec<SocketAddr> = {
            let mut connected = self.peers.connected();
            connected.sort_by(|a, b| b.score.cmp(&a.score));
            connected.iter()
                .take(MAX_GOSSIP_FANOUT)
                .map(|p| p.addr)
                .collect()
        };

        for addr in &targets {
            if let Some(conn) = self.connections.get_mut(addr) {
                if conn.send(msg).is_err() {
                    // Connection failed — mark disconnected, score penalty applied elsewhere
                    self.peers.mark_disconnected(addr);
                }
            }
        }
        Ok(())
    }

    /// Send a message to one specific peer.
    pub fn send_to(&mut self, addr: &SocketAddr, msg: &Message) -> NetworkResult<()> {
        let conn = self.connections.get_mut(addr)
            .ok_or(NetworkError::NoPeers)?;
        conn.send(msg)
    }

    /// Receive one message from a specific peer connection.
    pub fn recv_from(&mut self, addr: &SocketAddr) -> NetworkResult<Option<Message>> {
        if let Some(conn) = self.connections.get_mut(addr) {
            conn.recv()
        } else {
            Ok(None)
        }
    }

    /// Return the socket addresses of all connected peers.
    pub fn connected_addrs(&self) -> Vec<SocketAddr> {
        self.connections.keys().cloned().collect()
    }

    /// Check if a message hash has been seen recently.
    pub fn is_seen(&self, hash: &[u8; 32]) -> bool {
        self.seen_set.contains(hash)
    }

    /// Mark a message hash as seen.
    pub fn mark_seen(&mut self, hash: [u8; 32]) {
        if self.seen_set.contains(&hash) {
            return;
        }
        if self.seen_msgs.len() >= SEEN_CACHE_SIZE {
            if let Some(old) = self.seen_msgs.pop_front() {
                self.seen_set.remove(&old);
            }
        }
        self.seen_msgs.push_back(hash);
        self.seen_set.insert(hash);
    }

    /// Apply a score event to a peer.
    pub fn score_event(&mut self, addr: &SocketAddr, event: ScoreEvent) {
        self.peers.score_event(addr, event);
        // If peer is now banned, drop the connection
        if let Some(peer) = self.peers.get(addr) {
            if peer.is_banned() {
                self.connections.remove(addr);
            }
        }
    }

    /// Return a reference to the peer table.
    pub fn peers(&self) -> &PeerTable {
        &self.peers
    }

    /// Return a mutable reference to the peer table.
    pub fn peers_mut(&mut self) -> &mut PeerTable {
        &mut self.peers
    }

    /// Number of active connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

impl Default for GossipEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seen_cache_deduplicates() {
        let mut engine = GossipEngine::new();
        let hash = [0x42u8; 32];
        assert!(!engine.is_seen(&hash));
        engine.mark_seen(hash);
        assert!(engine.is_seen(&hash));
    }

    #[test]
    fn seen_cache_evicts_old_entries() {
        let mut engine = GossipEngine::new();
        // Fill the cache
        for i in 0..SEEN_CACHE_SIZE {
            let mut hash = [0u8; 32];
            hash[0] = (i & 0xFF) as u8;
            hash[1] = ((i >> 8) & 0xFF) as u8;
            engine.mark_seen(hash);
        }
        // First entry should be evicted
        let first = [0u8; 32];
        // Add one more to trigger eviction of first
        engine.mark_seen([0xFF; 32]);
        assert!(!engine.is_seen(&first));
    }

    #[test]
    fn peer_banned_drops_on_equivocation() {
        let mut engine = GossipEngine::new();
        use std::net::{IpAddr, Ipv4Addr};
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9000);
        engine.peers.add(addr).unwrap();
        // Drive score to zero with equivocating block events
        for _ in 0..4 {
            engine.score_event(&addr, ScoreEvent::EquivocatingBlock);
        }
        assert!(engine.peers.get(&addr).unwrap().is_banned());
    }
}
