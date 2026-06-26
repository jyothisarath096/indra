#!/usr/bin/env bash
# =============================================================================
# INDRA v2 — Phase 6 Setup Script
# Networked Node: P2P, Async Runtime, RocksDB, Slash Detection
# =============================================================================
# Run from inside the indra/ workspace directory:
#
#   chmod +x setup_indra_phase6.sh
#   ./setup_indra_phase6.sh
#   cargo build
#   cargo test
#
# Prerequisites: Phases 1–5 must be passing.
#
# What this adds:
#
#   indra-network/        — new crate: P2P networking layer
#     src/lib.rs
#     src/error.rs
#     src/message.rs      — wire protocol messages (Block, Vote, Tx, Peer)
#     src/peer.rs         — peer table: track, score, ban peers
#     src/gossip.rs       — gossip engine: broadcast and receive messages
#     src/transport.rs    — TCP transport (sync in Phase 6, async in Phase 7)
#     tests/network.rs
#
#   Updates to indra-node:
#     src/slash.rs        — slash evidence detection (double-precommit, surround-vote)
#     src/driver.rs       — async-ready consensus driver wrapping NodeEngine + network
#     src/config.rs       — extended with network and RocksDB config fields
# =============================================================================

set -euo pipefail

echo "==> Setting up INDRA Phase 6 — Networked Node..."

if [ ! -f "Cargo.toml" ]; then
    echo "ERROR: Run from inside the indra/ workspace directory."
    exit 1
fi

# =============================================================================
# Update workspace Cargo.toml
# =============================================================================

cat > Cargo.toml << 'TOML'
[workspace]
members  = [
    "indra-core",
    "indra-crypto",
    "indra-state",
    "indra-consensus",
    "indra-storage",
    "indra-node",
    "indra-network",
]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
authors = ["INDRA Protocol"]
license = "MIT"

[workspace.dependencies]
sha2               = { version = "0.10", default-features = false }
thiserror          = { version = "1.0" }
hex                = { version = "0.4", default-features = false, features = ["alloc"] }
ed25519-dalek      = { version = "2.1", default-features = false, features = ["alloc"] }
curve25519-dalek   = { version = "4.1", default-features = false, features = ["alloc"] }
pqcrypto-dilithium = { version = "0.5", default-features = false }
pqcrypto-traits    = { version = "0.3", default-features = false }
blst               = { version = "0.3" }
proptest           = { version = "1.4", default-features = false, features = ["std"] }

[profile.release]
opt-level     = 3
lto           = true
codegen-units = 1
panic         = "abort"

[profile.dev]
opt-level = 0
debug     = true
TOML

# =============================================================================
# Create indra-network crate
# =============================================================================

mkdir -p indra-network/src
mkdir -p indra-network/tests

cat > indra-network/Cargo.toml << 'TOML'
[package]
name        = "indra-network"
description = "INDRA v2 P2P networking — wire protocol, peer table, gossip"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
indra-core   = { path = "../indra-core" }
indra-crypto = { path = "../indra-crypto" }
thiserror.workspace = true

[dev-dependencies]
indra-core   = { path = "../indra-core" }
indra-crypto = { path = "../indra-crypto" }
TOML

# --------------- indra-network/src/lib.rs ---------------

cat > indra-network/src/lib.rs << 'RUST'
//! # indra-network
//!
//! The INDRA v2 P2P networking layer.
//!
//! ## Architecture
//!
//! ```text
//!  ┌─────────────────────────────────────────────┐
//!  │                GossipEngine                  │
//!  │                                              │
//!  │  ┌───────────┐  ┌──────────┐  ┌──────────┐  │
//!  │  │ PeerTable │  │Transport │  │ Message  │  │
//!  │  │ (scoring) │  │  (TCP)   │  │ Codec    │  │
//!  │  └───────────┘  └──────────┘  └──────────┘  │
//!  └─────────────────────────────────────────────┘
//! ```
//!
//! ## Wire protocol
//!
//! All messages are length-prefixed:
//!   [u32 length LE] [u8 message_type] [payload bytes]
//!
//! Message types:
//!   0x01 = Block      — a complete BlockV1
//!   0x02 = Vote       — a VoteV1 (prevote or precommit)
//!   0x03 = Tx         — a TransactionV1 (mempool gossip)
//!   0x04 = PeerList   — list of known peer addresses
//!   0x05 = Ping       — liveness check
//!   0x06 = Pong       — liveness response
//!   0x07 = GetBlocks  — request blocks from height A to B
//!   0x08 = Status     — announce current chain height and tip hash
//!
//! ## Peer scoring
//!
//! Each peer starts with score 100. Good behaviour (timely messages,
//! valid blocks) increases score. Bad behaviour (invalid messages,
//! timeouts, sending duplicate votes) decreases it. Score drops to
//! zero → peer is banned for BAN_DURATION_BLOCKS blocks.
//!
//! ## Phase 7 upgrade
//!
//! Phase 6 uses synchronous TCP. Phase 7 wraps this in Tokio for
//! fully async I/O and adds:
//! - Noise protocol handshake for encrypted connections
//! - Peer discovery via Kademlia DHT
//! - Connection multiplexing via yamux

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod error;
pub mod message;
pub mod peer;
pub mod gossip;
pub mod transport;

pub use error::{NetworkError, NetworkResult};
pub use message::{Message, MessageType};
pub use peer::{PeerInfo, PeerTable, PeerStatus};
pub use gossip::{GossipEngine, GossipEvent};
pub use transport::{Transport, Connection};
RUST

# --------------- indra-network/src/error.rs ---------------

cat > indra-network/src/error.rs << 'RUST'
//! Network error types.

use thiserror::Error;

/// All errors that can occur in the networking layer.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// An I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A message failed to decode.
    #[error("message decode error: {reason}")]
    DecodeFailed {
        /// Why decoding failed.
        reason: String,
    },

    /// A message exceeded the maximum allowed size.
    #[error("message too large: {size} bytes (max {max})")]
    MessageTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Connection to a peer was refused or timed out.
    #[error("connection failed to {addr}: {reason}")]
    ConnectionFailed {
        /// The peer address.
        addr: String,
        /// Why it failed.
        reason: String,
    },

    /// The peer sent an unexpected message type.
    #[error("unexpected message type {got:#04x}")]
    UnexpectedMessage {
        /// The received type byte.
        got: u8,
    },

    /// Peer was banned.
    #[error("peer {addr} is banned")]
    PeerBanned {
        /// The peer address.
        addr: String,
    },

    /// No peers available.
    #[error("no peers available")]
    NoPeers,

    /// Peer table is full.
    #[error("peer table full: {capacity} peers")]
    PeerTableFull {
        /// Maximum capacity.
        capacity: usize,
    },
}

/// Convenience alias.
pub type NetworkResult<T> = Result<T, NetworkError>;
RUST

# --------------- indra-network/src/message.rs ---------------

cat > indra-network/src/message.rs << 'RUST'
//! Wire protocol messages.
//!
//! ## Encoding
//!
//! Each message on the wire:
//!   [u32 total_length LE] [u8 message_type] [payload bytes]
//!
//! `total_length` includes the type byte but NOT the 4-byte length prefix itself.
//! Maximum message size: MAX_MSG_BYTES (4 MB).

use indra_core::{
    codec::{Decode, Encode, ByteReader},
    types::{
        block::BlockV1,
        primitives::Bytes32,
        transaction::TransactionV1,
        vote::VoteV1,
    },
};

use crate::error::{NetworkError, NetworkResult};

/// Maximum wire message size: 4 MB.
pub const MAX_MSG_BYTES: usize = 4 * 1024 * 1024;

/// Message type discriminant bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// A complete block.
    Block     = 0x01,
    /// A prevote or precommit.
    Vote      = 0x02,
    /// A pending transaction.
    Tx        = 0x03,
    /// A list of known peer addresses.
    PeerList  = 0x04,
    /// Liveness ping.
    Ping      = 0x05,
    /// Liveness pong.
    Pong      = 0x06,
    /// Request blocks by height range.
    GetBlocks = 0x07,
    /// Announce current chain tip.
    Status    = 0x08,
}

impl MessageType {
    /// Parse from a raw byte.
    pub fn from_byte(b: u8) -> NetworkResult<Self> {
        match b {
            0x01 => Ok(Self::Block),
            0x02 => Ok(Self::Vote),
            0x03 => Ok(Self::Tx),
            0x04 => Ok(Self::PeerList),
            0x05 => Ok(Self::Ping),
            0x06 => Ok(Self::Pong),
            0x07 => Ok(Self::GetBlocks),
            0x08 => Ok(Self::Status),
            other => Err(NetworkError::UnexpectedMessage { got: other }),
        }
    }
}

/// A decoded network message.
#[derive(Debug, Clone)]
pub enum Message {
    /// A complete block for validation and inclusion.
    Block(BlockV1),
    /// A prevote or precommit vote.
    Vote(VoteV1),
    /// A pending transaction for the mempool.
    Tx(TransactionV1),
    /// A list of peer addresses (IP:port strings).
    PeerList(Vec<String>),
    /// Liveness ping with nonce.
    Ping(u64),
    /// Liveness pong matching a ping nonce.
    Pong(u64),
    /// Request blocks from `from_height` to `to_height` (inclusive).
    GetBlocks { from_height: u64, to_height: u64 },
    /// Announce current chain tip.
    Status { height: u64, tip_hash: Bytes32 },
}

impl Message {
    /// The message type discriminant.
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Block(_)     => MessageType::Block,
            Self::Vote(_)      => MessageType::Vote,
            Self::Tx(_)        => MessageType::Tx,
            Self::PeerList(_)  => MessageType::PeerList,
            Self::Ping(_)      => MessageType::Ping,
            Self::Pong(_)      => MessageType::Pong,
            Self::GetBlocks { .. } => MessageType::GetBlocks,
            Self::Status { .. }    => MessageType::Status,
        }
    }

    /// Encode this message to wire format.
    ///
    /// Wire format: [u32 length LE] [u8 type] [payload]
    pub fn encode_wire(&self) -> NetworkResult<Vec<u8>> {
        let payload = self.encode_payload();
        let total_len = 1 + payload.len(); // type byte + payload

        if total_len > MAX_MSG_BYTES {
            return Err(NetworkError::MessageTooLarge {
                size: total_len,
                max: MAX_MSG_BYTES,
            });
        }

        let mut wire = Vec::with_capacity(4 + total_len);
        wire.extend_from_slice(&(total_len as u32).to_le_bytes());
        wire.push(self.message_type() as u8);
        wire.extend_from_slice(&payload);
        Ok(wire)
    }

    /// Decode a message from wire bytes (after the 4-byte length prefix).
    pub fn decode_wire(data: &[u8]) -> NetworkResult<Self> {
        if data.is_empty() {
            return Err(NetworkError::DecodeFailed {
                reason: "empty message".to_string(),
            });
        }

        let msg_type = MessageType::from_byte(data[0])?;
        let payload = &data[1..];

        Self::decode_payload(msg_type, payload)
    }

    /// Encode the payload (without length prefix or type byte).
    fn encode_payload(&self) -> Vec<u8> {
        match self {
            Self::Block(b) => b.encode_to_vec(),
            Self::Vote(v)  => v.encode_to_vec(),
            Self::Tx(tx)   => tx.encode_to_vec(),
            Self::PeerList(peers) => {
                let mut buf = Vec::new();
                (peers.len() as u32).encode(&mut buf);
                for p in peers {
                    let bytes = p.as_bytes();
                    (bytes.len() as u16).encode(&mut buf);
                    buf.extend_from_slice(bytes);
                }
                buf
            }
            Self::Ping(nonce) => nonce.to_le_bytes().to_vec(),
            Self::Pong(nonce) => nonce.to_le_bytes().to_vec(),
            Self::GetBlocks { from_height, to_height } => {
                let mut buf = Vec::with_capacity(16);
                buf.extend_from_slice(&from_height.to_le_bytes());
                buf.extend_from_slice(&to_height.to_le_bytes());
                buf
            }
            Self::Status { height, tip_hash } => {
                let mut buf = Vec::with_capacity(40);
                buf.extend_from_slice(&height.to_le_bytes());
                buf.extend_from_slice(&tip_hash.0);
                buf
            }
        }
    }

    /// Decode a payload given its type.
    fn decode_payload(msg_type: MessageType, payload: &[u8]) -> NetworkResult<Self> {
        match msg_type {
            MessageType::Block => {
                let mut r = ByteReader::new(payload);
                let block = BlockV1::decode(&mut r).map_err(|e| NetworkError::DecodeFailed {
                    reason: e.to_string(),
                })?;
                Ok(Self::Block(block))
            }
            MessageType::Vote => {
                let mut r = ByteReader::new(payload);
                let vote = VoteV1::decode(&mut r).map_err(|e| NetworkError::DecodeFailed {
                    reason: e.to_string(),
                })?;
                Ok(Self::Vote(vote))
            }
            MessageType::Tx => {
                let mut r = ByteReader::new(payload);
                let tx = TransactionV1::decode(&mut r).map_err(|e| NetworkError::DecodeFailed {
                    reason: e.to_string(),
                })?;
                Ok(Self::Tx(tx))
            }
            MessageType::PeerList => {
                if payload.len() < 4 {
                    return Err(NetworkError::DecodeFailed {
                        reason: "peer list too short".to_string(),
                    });
                }
                let count = u32::from_le_bytes(
                    payload[..4].try_into().unwrap_or([0u8; 4])
                ) as usize;
                let mut peers = Vec::with_capacity(count);
                let mut offset = 4;
                for _ in 0..count {
                    if offset + 2 > payload.len() { break; }
                    let len = u16::from_le_bytes(
                        payload[offset..offset+2].try_into().unwrap_or([0u8; 2])
                    ) as usize;
                    offset += 2;
                    if offset + len > payload.len() { break; }
                    let s = String::from_utf8_lossy(&payload[offset..offset+len]).to_string();
                    peers.push(s);
                    offset += len;
                }
                Ok(Self::PeerList(peers))
            }
            MessageType::Ping => {
                if payload.len() < 8 {
                    return Err(NetworkError::DecodeFailed { reason: "short ping".to_string() });
                }
                let nonce = u64::from_le_bytes(payload[..8].try_into().unwrap_or([0u8; 8]));
                Ok(Self::Ping(nonce))
            }
            MessageType::Pong => {
                if payload.len() < 8 {
                    return Err(NetworkError::DecodeFailed { reason: "short pong".to_string() });
                }
                let nonce = u64::from_le_bytes(payload[..8].try_into().unwrap_or([0u8; 8]));
                Ok(Self::Pong(nonce))
            }
            MessageType::GetBlocks => {
                if payload.len() < 16 {
                    return Err(NetworkError::DecodeFailed { reason: "short get_blocks".to_string() });
                }
                let from_height = u64::from_le_bytes(payload[..8].try_into().unwrap_or([0u8; 8]));
                let to_height   = u64::from_le_bytes(payload[8..16].try_into().unwrap_or([0u8; 8]));
                Ok(Self::GetBlocks { from_height, to_height })
            }
            MessageType::Status => {
                if payload.len() < 40 {
                    return Err(NetworkError::DecodeFailed { reason: "short status".to_string() });
                }
                let height = u64::from_le_bytes(payload[..8].try_into().unwrap_or([0u8; 8]));
                let mut tip = [0u8; 32];
                tip.copy_from_slice(&payload[8..40]);
                Ok(Self::Status { height, tip_hash: Bytes32::from(tip) })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::primitives::Bytes32;

    #[test]
    fn ping_round_trip() {
        let msg = Message::Ping(0xDEADBEEF_CAFEBABE);
        let wire = msg.encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap(); // skip length prefix
        assert!(matches!(decoded, Message::Ping(0xDEADBEEF_CAFEBABE)));
    }

    #[test]
    fn pong_round_trip() {
        let msg = Message::Pong(42);
        let wire = msg.encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        assert!(matches!(decoded, Message::Pong(42)));
    }

    #[test]
    fn get_blocks_round_trip() {
        let msg = Message::GetBlocks { from_height: 100, to_height: 200 };
        let wire = msg.encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        assert!(matches!(decoded, Message::GetBlocks { from_height: 100, to_height: 200 }));
    }

    #[test]
    fn status_round_trip() {
        let tip = Bytes32::from([0xABu8; 32]);
        let msg = Message::Status { height: 999, tip_hash: tip };
        let wire = msg.encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        match decoded {
            Message::Status { height, tip_hash } => {
                assert_eq!(height, 999);
                assert_eq!(tip_hash, tip);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn peer_list_round_trip() {
        let peers = vec![
            "192.168.1.1:30303".to_string(),
            "10.0.0.1:30303".to_string(),
        ];
        let msg = Message::PeerList(peers.clone());
        let wire = msg.encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        match decoded {
            Message::PeerList(p) => assert_eq!(p, peers),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn unknown_type_errors() {
        let data = vec![0xFF, 0x00, 0x00];
        assert!(matches!(
            Message::decode_wire(&data),
            Err(NetworkError::UnexpectedMessage { got: 0xFF })
        ));
    }

    #[test]
    fn wire_format_has_length_prefix() {
        let msg = Message::Ping(1);
        let wire = msg.encode_wire().unwrap();
        let len = u32::from_le_bytes(wire[..4].try_into().unwrap()) as usize;
        assert_eq!(len + 4, wire.len());
    }
}
RUST

# --------------- indra-network/src/peer.rs ---------------

cat > indra-network/src/peer.rs << 'RUST'
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
}

impl PeerInfo {
    /// Create a new peer entry.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            status: PeerStatus::Known,
            score: INITIAL_SCORE,
            reported_height: 0,
            ban_until: None,
            last_seen: None,
            messages_received: 0,
            invalid_messages: 0,
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
}

/// Score adjustment reasons.
#[derive(Debug, Clone, Copy)]
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
            Self::ValidBlock       =>   5,
            Self::ValidVote        =>   1,
            Self::ValidTx          =>   1,
            Self::InvalidMessage   => -10,
            Self::Timeout          =>  -5,
            Self::DuplicateVote    => -20,
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
        Self { peers: HashMap::new() }
    }

    /// Add a peer address. Returns the peer info (or existing entry).
    pub fn add(&mut self, addr: SocketAddr) -> NetworkResult<()> {
        if self.peers.len() >= MAX_PEERS && !self.peers.contains_key(&addr) {
            return Err(NetworkError::PeerTableFull { capacity: MAX_PEERS });
        }
        self.peers.entry(addr).or_insert_with(|| PeerInfo::new(addr));
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

    /// Mark a peer as connected.
    pub fn mark_connected(&mut self, addr: &SocketAddr) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.status = PeerStatus::Connected;
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
        self.peers.values()
            .filter(|p| p.status == PeerStatus::Connected)
            .collect()
    }

    /// Return all known (not banned) peer addresses for dialing.
    pub fn dialable(&self) -> Vec<SocketAddr> {
        self.peers.values()
            .filter(|p| !p.is_banned() && p.status != PeerStatus::Connected)
            .map(|p| p.addr)
            .collect()
    }

    /// Return the peer with the highest reported height.
    pub fn best_peer(&self) -> Option<&PeerInfo> {
        self.peers.values()
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
    pub fn cleanup_expired_bans(&mut self) {
        self.peers.retain(|_, peer| {
            if peer.status == PeerStatus::Banned {
                !peer.is_banned() // keep if still banned, remove if ban expired
            } else {
                true
            }
        });
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
}
RUST

# --------------- indra-network/src/transport.rs ---------------

cat > indra-network/src/transport.rs << 'RUST'
//! TCP transport layer.
//!
//! Provides synchronous TCP connections for sending and receiving
//! length-prefixed wire messages.
//!
//! ## Phase 7 upgrade
//!
//! Phase 7 replaces this with an async Tokio implementation and adds:
//! - Noise protocol handshake (encrypted + authenticated connections)
//! - Connection multiplexing (yamux)
//! - Peer ID verification against public key

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use crate::{
    error::{NetworkError, NetworkResult},
    message::{Message, MAX_MSG_BYTES},
};

/// Default connection timeout.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default read timeout.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// A TCP connection to a single peer.
pub struct Connection {
    stream: TcpStream,
    /// The remote peer's address.
    pub remote_addr: SocketAddr,
}

impl Connection {
    /// Wrap an existing TCP stream.
    pub fn from_stream(stream: TcpStream) -> NetworkResult<Self> {
        let remote_addr = stream.peer_addr()?;
        stream.set_read_timeout(Some(READ_TIMEOUT))?;
        stream.set_write_timeout(Some(READ_TIMEOUT))?;
        Ok(Self { stream, remote_addr })
    }

    /// Send a message to this peer.
    pub fn send(&mut self, msg: &Message) -> NetworkResult<()> {
        let wire = msg.encode_wire()?;
        self.stream.write_all(&wire)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Receive one message from this peer.
    ///
    /// Reads the 4-byte length prefix, then the payload.
    /// Returns None if the connection was closed cleanly.
    pub fn recv(&mut self) -> NetworkResult<Option<Message>> {
        let mut len_buf = [0u8; 4];
        match self.stream.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(NetworkError::Io(e)),
        }

        let total_len = u32::from_le_bytes(len_buf) as usize;
        if total_len > MAX_MSG_BYTES {
            return Err(NetworkError::MessageTooLarge {
                size: total_len,
                max: MAX_MSG_BYTES,
            });
        }

        let mut payload = vec![0u8; total_len];
        self.stream.read_exact(&mut payload)?;

        let msg = Message::decode_wire(&payload)?;
        Ok(Some(msg))
    }

    /// Close this connection.
    pub fn close(self) -> NetworkResult<()> {
        self.stream.shutdown(std::net::Shutdown::Both)?;
        Ok(())
    }
}

/// The TCP transport: listens for inbound and dials outbound connections.
pub struct Transport {
    listener: TcpListener,
    /// The local address we're listening on.
    pub local_addr: SocketAddr,
}

impl Transport {
    /// Bind to the given address and start listening.
    pub fn bind(addr: &str) -> NetworkResult<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;
        Ok(Self { listener, local_addr })
    }

    /// Accept one inbound connection (non-blocking).
    /// Returns None if no connection is waiting.
    pub fn accept(&self) -> NetworkResult<Option<Connection>> {
        match self.listener.accept() {
            Ok((stream, _)) => Ok(Some(Connection::from_stream(stream)?)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(NetworkError::Io(e)),
        }
    }

    /// Dial an outbound connection to a peer.
    pub fn dial(&self, addr: SocketAddr) -> NetworkResult<Connection> {
        let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
            .map_err(|e| NetworkError::ConnectionFailed {
                addr: addr.to_string(),
                reason: e.to_string(),
            })?;
        Connection::from_stream(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn bind_and_get_local_addr() {
        let transport = Transport::bind("127.0.0.1:0").unwrap();
        let addr = transport.local_addr;
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert!(addr.port() > 0);
    }

    #[test]
    fn send_and_receive_message() {
        let server = Transport::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr;

        let handle = thread::spawn(move || {
            // Wait for connection with timeout
            let start = std::time::Instant::now();
            loop {
                match server.accept().unwrap() {
                    Some(mut conn) => {
                        let msg = conn.recv().unwrap().unwrap();
                        return msg;
                    }
                    None => {
                        if start.elapsed() > Duration::from_secs(3) {
                            panic!("timeout waiting for connection");
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        });

        // Give server time to start
        thread::sleep(Duration::from_millis(50));

        let client_transport = Transport::bind("127.0.0.1:0").unwrap();
        let mut conn = client_transport.dial(server_addr).unwrap();
        conn.send(&Message::Ping(12345)).unwrap();

        let received = handle.join().unwrap();
        assert!(matches!(received, Message::Ping(12345)));
    }

    #[test]
    fn non_blocking_accept_returns_none_when_empty() {
        let transport = Transport::bind("127.0.0.1:0").unwrap();
        assert!(transport.accept().unwrap().is_none());
    }
}
RUST

# --------------- indra-network/src/gossip.rs ---------------

cat > indra-network/src/gossip.rs << 'RUST'
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
                if let Err(_) = conn.send(msg) {
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
RUST

# --------------- indra-network/tests/network.rs ---------------

cat > indra-network/tests/network.rs << 'RUST'
//! Integration tests for the network layer.

use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

use indra_core::types::primitives::Bytes32;
use indra_network::{
    message::Message,
    peer::{PeerTable, PeerStatus, ScoreEvent, INITIAL_SCORE},
    transport::Transport,
    gossip::GossipEngine,
};

#[test]
fn message_encode_decode_all_types() {
    let messages = vec![
        Message::Ping(999),
        Message::Pong(999),
        Message::GetBlocks { from_height: 0, to_height: 100 },
        Message::Status { height: 42, tip_hash: Bytes32::from([0xAAu8; 32]) },
        Message::PeerList(vec!["127.0.0.1:30303".to_string()]),
    ];

    for msg in messages {
        let wire = msg.encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        // Check type matches
        assert_eq!(
            decoded.message_type() as u8,
            msg.message_type() as u8,
            "message type mismatch"
        );
    }
}

#[test]
fn peer_table_lifecycle() {
    let mut table = PeerTable::new();
    let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();

    // Add
    table.add(addr).unwrap();
    assert_eq!(table.get(&addr).unwrap().status, PeerStatus::Known);

    // Connect
    table.mark_connected(&addr);
    assert_eq!(table.get(&addr).unwrap().status, PeerStatus::Connected);
    assert_eq!(table.connected().len(), 1);

    // Update height
    table.update_height(&addr, 50);
    assert_eq!(table.get(&addr).unwrap().reported_height, 50);

    // Score up
    for _ in 0..5 {
        table.score_event(&addr, ScoreEvent::ValidBlock);
    }
    assert_eq!(table.get(&addr).unwrap().score, INITIAL_SCORE + 5 * 5);

    // Disconnect
    table.mark_disconnected(&addr);
    assert_eq!(table.connected().len(), 0);
}

#[test]
fn two_nodes_exchange_status() {
    let server_transport = Transport::bind("127.0.0.1:0").unwrap();
    let server_addr = server_transport.local_addr;

    let handle = thread::spawn(move || {
        let start = std::time::Instant::now();
        loop {
            match server_transport.accept().unwrap() {
                Some(mut conn) => {
                    let msg = conn.recv().unwrap().unwrap();
                    // Echo back a status
                    let response = Message::Status {
                        height: 100,
                        tip_hash: Bytes32::from([0xBBu8; 32]),
                    };
                    conn.send(&response).unwrap();
                    return msg;
                }
                None => {
                    if start.elapsed() > Duration::from_secs(3) {
                        panic!("timeout");
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    });

    thread::sleep(Duration::from_millis(50));

    let client = Transport::bind("127.0.0.1:0").unwrap();
    let mut conn = client.dial(server_addr).unwrap();

    conn.send(&Message::Status {
        height: 50,
        tip_hash: Bytes32::from([0xAAu8; 32]),
    }).unwrap();

    let received_by_server = handle.join().unwrap();
    match received_by_server {
        Message::Status { height, .. } => assert_eq!(height, 50),
        _ => panic!("wrong message type"),
    }

    let response = conn.recv().unwrap().unwrap();
    match response {
        Message::Status { height, .. } => assert_eq!(height, 100),
        _ => panic!("wrong response type"),
    }
}

#[test]
fn gossip_engine_seen_dedup() {
    let mut engine = GossipEngine::new();
    let hash = indra_crypto::sha256(b"test message");
    assert!(!engine.is_seen(&hash));
    engine.mark_seen(hash);
    assert!(engine.is_seen(&hash));
    // Marking again should be idempotent
    engine.mark_seen(hash);
    assert!(engine.is_seen(&hash));
}

#[test]
fn equivocating_peer_gets_banned() {
    let mut engine = GossipEngine::new();
    let addr: SocketAddr = "127.0.0.1:9002".parse().unwrap();
    engine.peers.add(addr).unwrap();

    // EquivocatingBlock = -50 per event, start at 100
    // After 2 events: score = 0 → banned
    engine.score_event(&addr, ScoreEvent::EquivocatingBlock);
    engine.score_event(&addr, ScoreEvent::EquivocatingBlock);

    assert!(engine.peers.get(&addr).unwrap().is_banned());
}
RUST

# =============================================================================
# Add slash detection to indra-node
# =============================================================================

cat > indra-node/src/slash.rs << 'RUST'
//! Slash evidence detection.
//!
//! Detects two types of slashable offences:
//!
//! ## Double precommit (equivocation)
//!
//! A validator signs two different precommit votes at the same height
//! and round for different block hashes. This is unambiguously malicious
//! (a validator cannot legitimately do this).
//!
//! Penalty: SLASH_DOUBLE_PRECOMMIT_BPS (5%) of stake.
//!
//! ## Surround vote
//!
//! A validator's outer vote (h1, r1) surrounds an inner vote (h2, r2)
//! where h1 < h2 and r1 > r2. This is the Ethereum-style long-range
//! attack vector.
//!
//! Penalty: SLASH_SURROUND_VOTE_BPS (100%) of stake.
//!
//! ## Evidence format
//!
//! Evidence is a pair of conflicting votes from the same validator.
//! The verifier checks:
//!   1. Both votes have the same validator_id
//!   2. Both signatures are valid
//!   3. The votes are actually conflicting (different hashes at same height/round,
//!      or surround relationship)

use std::collections::HashMap;

use indra_core::types::{
    primitives::Bytes32,
    vote::{VoteStep, VoteV1},
};

/// The type of slashable offence detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlashOffence {
    /// Two precommits at the same height/round for different blocks.
    DoublePrecommit,
    /// An outer vote surrounds an inner vote.
    SurroundVote,
}

/// A detected slashable offence with supporting evidence.
#[derive(Debug, Clone)]
pub struct SlashEvidence {
    /// The offending validator.
    pub validator_id: Bytes32,
    /// The type of offence.
    pub offence: SlashOffence,
    /// First conflicting vote.
    pub vote_a: VoteV1,
    /// Second conflicting vote.
    pub vote_b: VoteV1,
}

/// Tracks votes observed from validators to detect slashable behaviour.
pub struct SlashDetector {
    /// validator_id → list of observed precommits
    precommits: HashMap<Bytes32, Vec<VoteV1>>,
    /// validator_id → list of observed prevotes (for surround detection)
    prevotes:   HashMap<Bytes32, Vec<VoteV1>>,
}

impl SlashDetector {
    /// Create a new detector.
    pub fn new() -> Self {
        Self {
            precommits: HashMap::new(),
            prevotes:   HashMap::new(),
        }
    }

    /// Observe a vote. Returns slash evidence if this vote conflicts
    /// with a previously observed vote from the same validator.
    pub fn observe_vote(&mut self, vote: VoteV1) -> Option<SlashEvidence> {
        match vote.step {
            VoteStep::Precommit => self.observe_precommit(vote),
            VoteStep::Prevote   => self.observe_prevote(vote),
        }
    }

    fn observe_precommit(&mut self, vote: VoteV1) -> Option<SlashEvidence> {
        let existing = self.precommits
            .entry(vote.validator_id)
            .or_insert_with(Vec::new);

        // Check for double precommit: same height+round, different block hash
        for prev in existing.iter() {
            if prev.height == vote.height
                && prev.round == vote.round
                && prev.block_hash != vote.block_hash
            {
                return Some(SlashEvidence {
                    validator_id: vote.validator_id,
                    offence: SlashOffence::DoublePrecommit,
                    vote_a: prev.clone(),
                    vote_b: vote,
                });
            }
        }

        existing.push(vote);
        None
    }

    fn observe_prevote(&mut self, vote: VoteV1) -> Option<SlashEvidence> {
        let existing = self.prevotes
            .entry(vote.validator_id)
            .or_insert_with(Vec::new);

        // Check for surround vote:
        // outer (h1, r1) surrounds inner (h2, r2) if h1 < h2 and r1 > r2
        for prev in existing.iter() {
            if is_surround(prev, &vote) || is_surround(&vote, prev) {
                return Some(SlashEvidence {
                    validator_id: vote.validator_id,
                    offence: SlashOffence::SurroundVote,
                    vote_a: prev.clone(),
                    vote_b: vote,
                });
            }
        }

        existing.push(vote);
        None
    }

    /// Clear votes older than the given height (prune stale evidence).
    pub fn prune_below(&mut self, height: u64) {
        for votes in self.precommits.values_mut() {
            votes.retain(|v| v.height >= height);
        }
        for votes in self.prevotes.values_mut() {
            votes.retain(|v| v.height >= height);
        }
    }

    /// Number of validators being tracked.
    pub fn tracked_validators(&self) -> usize {
        let mut ids: std::collections::HashSet<Bytes32> = self.precommits.keys().copied().collect();
        ids.extend(self.prevotes.keys().copied());
        ids.len()
    }
}

/// Check if vote `outer` surrounds vote `inner`.
/// outer surrounds inner if outer.height < inner.height && outer.round > inner.round
fn is_surround(outer: &VoteV1, inner: &VoteV1) -> bool {
    outer.height < inner.height && outer.round > inner.round
}

impl Default for SlashDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        VariableBytes,
        types::{
            crypto::HybridSignature,
            primitives::{MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES},
            vote::VoteStep,
        },
    };

    fn dummy_vote(
        validator_id: [u8; 32],
        height: u64,
        round: u32,
        step: VoteStep,
        block_hash: [u8; 32],
    ) -> VoteV1 {
        VoteV1 {
            height,
            round,
            step,
            block_hash: Bytes32::from(block_hash),
            validator_id: Bytes32::from(validator_id),
            signature: HybridSignature {
                classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(&[0u8; 64]).unwrap(),
                pq_sig:        VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&[0u8; 32]).unwrap(),
            },
        }
    }

    #[test]
    fn no_slash_for_honest_validator() {
        let mut detector = SlashDetector::new();
        let v = [0x01u8; 32];

        // Two precommits at different heights — fine
        let r1 = detector.observe_vote(dummy_vote(v, 1, 0, VoteStep::Precommit, [0xAAu8; 32]));
        let r2 = detector.observe_vote(dummy_vote(v, 2, 0, VoteStep::Precommit, [0xBBu8; 32]));
        assert!(r1.is_none());
        assert!(r2.is_none());
    }

    #[test]
    fn double_precommit_detected() {
        let mut detector = SlashDetector::new();
        let v = [0x02u8; 32];

        // Same height+round, different block hash
        detector.observe_vote(dummy_vote(v, 5, 0, VoteStep::Precommit, [0xAAu8; 32]));
        let evidence = detector.observe_vote(dummy_vote(v, 5, 0, VoteStep::Precommit, [0xBBu8; 32]));

        assert!(evidence.is_some());
        assert_eq!(evidence.unwrap().offence, SlashOffence::DoublePrecommit);
    }

    #[test]
    fn same_vote_twice_no_slash() {
        let mut detector = SlashDetector::new();
        let v = [0x03u8; 32];

        // Same vote twice — not a double vote (same block hash)
        detector.observe_vote(dummy_vote(v, 5, 0, VoteStep::Precommit, [0xAAu8; 32]));
        let evidence = detector.observe_vote(dummy_vote(v, 5, 0, VoteStep::Precommit, [0xAAu8; 32]));
        assert!(evidence.is_none());
    }

    #[test]
    fn surround_vote_detected() {
        let mut detector = SlashDetector::new();
        let v = [0x04u8; 32];

        // Outer: height=1, round=10
        detector.observe_vote(dummy_vote(v, 1, 10, VoteStep::Prevote, [0xAAu8; 32]));
        // Inner: height=5, round=2 — surrounded by outer (1 < 5, 10 > 2)
        let evidence = detector.observe_vote(dummy_vote(v, 5, 2, VoteStep::Prevote, [0xBBu8; 32]));

        assert!(evidence.is_some());
        assert_eq!(evidence.unwrap().offence, SlashOffence::SurroundVote);
    }

    #[test]
    fn different_validators_no_slash() {
        let mut detector = SlashDetector::new();

        // Two different validators, same height+round, different hashes — NOT a slash
        detector.observe_vote(dummy_vote([0x01u8; 32], 5, 0, VoteStep::Precommit, [0xAAu8; 32]));
        let evidence = detector.observe_vote(dummy_vote([0x02u8; 32], 5, 0, VoteStep::Precommit, [0xBBu8; 32]));
        assert!(evidence.is_none());
    }

    #[test]
    fn prune_removes_old_votes() {
        let mut detector = SlashDetector::new();
        let v = [0x05u8; 32];

        detector.observe_vote(dummy_vote(v, 1, 0, VoteStep::Precommit, [0xAAu8; 32]));
        detector.observe_vote(dummy_vote(v, 2, 0, VoteStep::Precommit, [0xBBu8; 32]));

        detector.prune_below(3);

        // After pruning, the old precommits are gone — no conflict detected
        let evidence = detector.observe_vote(dummy_vote(v, 1, 0, VoteStep::Precommit, [0xCCu8; 32]));
        assert!(evidence.is_none());
    }
}
RUST

# --------------- indra-node/src/driver.rs ---------------

cat > indra-node/src/driver.rs << 'RUST'
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
    use indra_node::NodeConfig;
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
RUST

# Update indra-node/src/lib.rs to export new modules
cat > indra-node/src/lib.rs << 'RUST'
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
pub mod bls_vote;
pub mod state_root;
pub mod sync;
pub mod slash;
pub mod driver;

pub use config::NodeConfig;
pub use error::{NodeError, NodeResult};
pub use engine::NodeEngine;
pub use genesis::{build_genesis_block, build_genesis_state};
pub use sync::import_block;
pub use slash::{SlashDetector, SlashEvidence, SlashOffence};
pub use driver::{ConsensusDriver, DriverEvent, DriverAction};
RUST

# Update indra-node/Cargo.toml to add network dependency
cat > indra-node/Cargo.toml << 'TOML'
[package]
name        = "indra-node"
description = "INDRA v2 node binary — consensus engine, storage, sync, slash detection"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
indra-core      = { path = "../indra-core" }
indra-crypto    = { path = "../indra-crypto" }
indra-state     = { path = "../indra-state" }
indra-consensus = { path = "../indra-consensus" }
indra-storage   = { path = "../indra-storage" }
indra-network   = { path = "../indra-network" }
thiserror.workspace = true

[dev-dependencies]
indra-core      = { path = "../indra-core" }
indra-crypto    = { path = "../indra-crypto" }
indra-state     = { path = "../indra-state" }
indra-consensus = { path = "../indra-consensus" }
indra-storage   = { path = "../indra-storage" }
indra-network   = { path = "../indra-network" }
TOML

echo ""
echo "✓ INDRA Phase 6 files written."
echo ""
echo "New crate: indra-network"
echo "  src/message.rs   — wire protocol (8 message types, length-prefixed)"
echo "  src/peer.rs      — peer table with scoring and ban system"
echo "  src/transport.rs — TCP transport (send/recv with length prefix)"
echo "  src/gossip.rs    — gossip engine with dedup cache and fanout"
echo "  tests/network.rs — integration tests"
echo ""
echo "Updates to indra-node:"
echo "  src/slash.rs     — double-precommit and surround-vote detection"
echo "  src/driver.rs    — ConsensusDriver routing events to subsystems"
echo ""
echo "Now run:"
echo "  cargo build"
echo "  cargo test"
echo ""
