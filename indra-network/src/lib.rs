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
