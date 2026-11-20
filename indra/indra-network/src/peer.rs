//! Peer table — tracking, scoring, and banning peers.
//!
//! ## Peer lifecycle
//!
//! ```text
//!  Unknown → Connecting → Connected → Disconnected
//!                                  ↘ Banned (score = 0)
//! ```
//!
//! ## Scoring
//!
//! Peers start at score 100. Actions that change score:
//!
//! | Event                        | Score delta |
//! |------------------------------|-------------|
//! | Valid block received         | +5          |
//! | Valid vote received          | +1          |
//! | Valid tx received            | +1          |
//! | Invalid message              | -10         |
//! | Timeout / no response        | -5          |
//! | Sent duplicate vote          | -20         |
//! | Sent equivocating block      | -50         |
//!
//! Score is clamped to [0, 200]. Score 0 = banned.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use indra_core::types::primitives::Bytes32;

use crate::error::{NetworkError, NetworkResult};

/// Maximum number of peers in the table.
pub const MAX_PEERS: usize = 80; // MAX_OUTBOUND + MAX_INBOUND from spec
/// Starting score for a new peer.
pub const INITIAL_SCORE: i32 = 100;
/// Score floor — at or below this, the peer is banned.
pub const BAN_SCORE: i32 = 0;
/// Score ceiling.
pub const MAX_SCORE: i32 = 200;
/// How long a banned peer stays banned.
pub const BAN_DURATION: Duration = Duration::from_secs(3600); // 1 hour
/// Current status of a peer connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerStatus {
    /// We know this peer's address but haven't connected yet.
    Known,
    /// TCP connection is being established.
    Connecting,
    /// Fully connected and handshaked.
    Connected,
    /// Disconnected (may reconnect).
    Disconnected,
    /// Banned — do not connect until ban_until expires.
    Banned,
}

/// Information about a single peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Authenticated validator identity, once the handshake completes.
    pub validator_id: Option<Bytes32>,
    /// The peer's address.
    pub addr: SocketAddr,
    /// Current connection status.
    pub status: PeerStatus,
    /// Reputation score [0, 200].
    pub score: i32,
    /// The peer's reported chain height (from Status messages).
    pub reported_height: u64,
    /// When the ban expires (only meaningful if status == Banned).
    pub ban_until: Option<Instant>,
    /// When we last received any message from this peer.
    pub last_seen: Option<Instant>,
    /// Total messages received.
    pub messages_received: u64,
    /// Total invalid messages received.
    pub invalid_messages: u64,
    /// Total messages dropped by the rate limiter for this peer.
    pub rate_limit_drops: u64,
}

impl PeerInfo {
    /// Create a new peer entry.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            validator_id: None,
            addr,
            status: PeerStatus::Known,
            score: INITIAL_SCORE,
            reported_height: 0,
            ban_until: None,
            last_seen: None,
            messages_received: 0,
            invalid_messages: 0,
            rate_limit_drops: 0,
        }
    }

    /// True if this peer is currently banned.
    pub fn is_banned(&self) -> bool {
        if self.status != PeerStatus::Banned {
            return false;
        }
        match self.ban_until {
            None => true,
            Some(until) => Instant::now() < until,
        }
    }

    /// Apply a score delta and update status if banned.
    pub fn adjust_score(&mut self, delta: i32) {
        self.score = (self.score + delta).clamp(BAN_SCORE, MAX_SCORE);
        if self.score <= BAN_SCORE {
            self.status = PeerStatus::Banned;
            self.ban_until = Some(Instant::now() + BAN_DURATION);
        }
    }

    /// Apply a score delta with a custom ban duration.
    pub fn adjust_score_with_duration(&mut self, delta: i32, ban_duration: Duration) {
        self.score = (self.score + delta).clamp(BAN_SCORE, MAX_SCORE);
        if self.score <= BAN_SCORE {
            self.status = PeerStatus::Banned;
            self.ban_until = Some(Instant::now() + ban_duration);
        }
    }

    /// Count a bounded rate-limit drop for peer status and diagnostics.
    pub fn record_rate_limit_drop(&mut self) {
        self.rate_limit_drops = self.rate_limit_drops.saturating_add(1);
    }
}

/// Score adjustment reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreEvent {
    /// Received a valid block.
    ValidBlock,
    /// Received a valid vote.
    ValidVote,
    /// Received a valid transaction.
    ValidTx,
    /// Received an invalid or malformed message.
    InvalidMessage,
    /// Peer timed out.
    Timeout,
    /// Peer sent a duplicate vote (equivocation).
    DuplicateVote,
    /// Peer sent two different blocks at the same height (equivocation).
    EquivocatingBlock,
}

impl ScoreEvent {
    /// The score delta for this event.
    pub fn delta(self) -> i32 {
        match self {
            Self::ValidBlock => 5,
            Self::ValidVote => 1,
            Self::ValidTx => 1,
            Self::InvalidMessage => -10,
            Self::Timeout => -5,
            Self::DuplicateVote => -20,
            Self::EquivocatingBlock => -50,
        }
    }
}

/// The peer table — tracks all known peers.
pub struct PeerTable {
    peers: HashMap<SocketAddr, PeerInfo>,
}

impl PeerTable {
    /// Create an empty peer table.
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Add a peer address. Returns the peer info (or existing entry).
    pub fn add(&mut self, addr: SocketAddr) -> NetworkResult<()> {
        if self.peers.len() >= MAX_PEERS && !self.peers.contains_key(&addr) {
            return Err(NetworkError::PeerTableFull {
                capacity: MAX_PEERS,
            });
        }
        self.peers
            .entry(addr)
            .or_insert_with(|| PeerInfo::new(addr));
        Ok(())
    }

    /// Look up a peer by address.
    pub fn get(&self, addr: &SocketAddr) -> Option<&PeerInfo> {
        self.peers.get(addr)
    }

    /// Mutably look up a peer.
    pub fn get_mut(&mut self, addr: &SocketAddr) -> Option<&mut PeerInfo> {
        self.peers.get_mut(addr)
    }

    /// Apply a score event to a peer.
    pub fn score_event(&mut self, addr: &SocketAddr, event: ScoreEvent) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.adjust_score(event.delta());
        }
    }

    /// Apply a custom score delta with a caller-provided ban duration.
    pub fn adjust_score_with_duration(
        &mut self,
        addr: &SocketAddr,
        delta: i32,
        ban_duration: Duration,
    ) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.adjust_score_with_duration(delta, ban_duration);
        }
    }

    /// Mark a peer as connected.
    pub fn mark_connected(&mut self, addr: &SocketAddr) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.status = PeerStatus::Connected;
            peer.last_seen = Some(Instant::now());
        }
    }

    /// Bind an authenticated validator identity to a connected peer.
    pub fn set_validator_id(&mut self, addr: &SocketAddr, validator_id: Bytes32) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.validator_id = Some(validator_id);
            peer.last_seen = Some(Instant::now());
        }
    }

    /// Mark a peer as disconnected.
    pub fn mark_disconnected(&mut self, addr: &SocketAddr) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.status = PeerStatus::Disconnected;
        }
    }

    /// Update a peer's reported chain height.
    pub fn update_height(&mut self, addr: &SocketAddr, height: u64) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.reported_height = height;
            peer.last_seen = Some(Instant::now());
        }
    }

    /// Return all connected peers.
    pub fn connected(&self) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| p.status == PeerStatus::Connected)
            .collect()
    }

    /// Return the peer with the highest reported height.
    pub fn best_peer(&self) -> Option<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| p.status == PeerStatus::Connected)
            .max_by_key(|p| p.reported_height)
    }

    /// Total number of peers in the table.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// True if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Remove peers that have been banned longer than BAN_DURATION.
    pub fn cleanup_expired_bans(&mut self) -> usize {
        let before = self.peers.len();
        self.peers.retain(|_, peer| {
            if peer.status == PeerStatus::Banned {
                peer.is_banned()
            } else {
                true
            }
        });
        before - self.peers.len()
    }

    /// Evict the least-recently-seen disconnected, non-banned peer.
    pub fn evict_oldest_disconnected(&mut self) -> Option<SocketAddr> {
        let candidate = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.status == PeerStatus::Disconnected && !peer.is_banned())
            .min_by(|(addr_a, peer_a), (addr_b, peer_b)| {
                peer_a
                    .last_seen
                    .cmp(&peer_b.last_seen)
                    .then_with(|| addr_a.cmp(addr_b))
            })
            .map(|(addr, _)| *addr)?;
        self.peers.remove(&candidate);
        Some(candidate)
    }
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn add_and_retrieve_peer() {
        let mut table = PeerTable::new();
        let a = addr(1000);
        table.add(a).unwrap();
        assert!(table.get(&a).is_some());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn score_decreases_on_bad_event() {
        let mut table = PeerTable::new();
        let a = addr(1001);
        table.add(a).unwrap();
        table.score_event(&a, ScoreEvent::InvalidMessage);
        assert_eq!(table.get(&a).unwrap().score, INITIAL_SCORE - 10);
    }

    #[test]
    fn peer_banned_at_zero_score() {
        let mut table = PeerTable::new();
        let a = addr(1002);
        table.add(a).unwrap();
        // Drive score to zero
        for _ in 0..10 {
            table.score_event(&a, ScoreEvent::InvalidMessage);
        }
        assert_eq!(table.get(&a).unwrap().status, PeerStatus::Banned);
    }

    #[test]
    fn score_clamped_at_max() {
        let mut table = PeerTable::new();
        let a = addr(1003);
        table.add(a).unwrap();
        for _ in 0..100 {
            table.score_event(&a, ScoreEvent::ValidBlock);
        }
        assert_eq!(table.get(&a).unwrap().score, MAX_SCORE);
    }

    #[test]
    fn connected_filters_correctly() {
        let mut table = PeerTable::new();
        let a = addr(1004);
        let b = addr(1005);
        table.add(a).unwrap();
        table.add(b).unwrap();
        table.mark_connected(&a);
        assert_eq!(table.connected().len(), 1);
    }

    #[test]
    fn best_peer_is_highest_height() {
        let mut table = PeerTable::new();
        let a = addr(1006);
        let b = addr(1007);
        table.add(a).unwrap();
        table.add(b).unwrap();
        table.mark_connected(&a);
        table.mark_connected(&b);
        table.update_height(&a, 100);
        table.update_height(&b, 200);
        assert_eq!(table.best_peer().unwrap().addr, b);
    }

    #[test]
    fn cleanup_retains_active_bans_and_removes_expired_bans() {
        let mut table = PeerTable::new();
        let active = addr(1010);
        let expired = addr(1011);
        table.add(active).unwrap();
        table.add(expired).unwrap();
        for target in [active, expired] {
            let peer = table.get_mut(&target).unwrap();
            peer.status = PeerStatus::Banned;
        }
        table.get_mut(&active).unwrap().ban_until = Some(Instant::now() + Duration::from_secs(60));
        table.get_mut(&expired).unwrap().ban_until = Some(Instant::now() - Duration::from_secs(1));
        assert_eq!(table.cleanup_expired_bans(), 1);
        assert!(table.get(&active).is_some());
        assert!(table.get(&expired).is_none());
    }
}
