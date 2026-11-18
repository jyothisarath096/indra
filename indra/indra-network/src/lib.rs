//! # indra-network
//!
//! The INDRA v2 P2P networking layer.
//!
//! ## Architecture
//!
//! ```text
//!  ┌─────────────────────────────────────────────┐
//!  │      Authenticated async peer manager       │
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
//!   0x01 = Block      — a complete BlockVNext
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
//! Validator networking uses the authenticated encrypted Tokio transport.

#![forbid(unsafe_code)]
#![deny(unused_must_use)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable, clippy::todo, clippy::unimplemented)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing
    )
)]
#![cfg_attr(not(test), deny(clippy::indexing_slicing))]

mod dandelion;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod message;
pub mod net_types;
pub mod observer;
pub mod peer;
pub mod peer_manager;
pub mod policy;
pub mod rate_limit;
pub mod transport;

pub use error::{NetworkError, NetworkResult};
pub use frame::{FrameReader, FrameWriter};
pub use handshake::{
    perform_handshake_initiator, perform_handshake_responder, HandshakeConfig, HandshakeResult,
};
pub use message::{Message, MessageType, PeerListEntry};
pub use net_types::{NetworkCommand, NetworkEvent, RelayValidatorKey};
pub use observer::{
    perform_observer_handshake_initiator, perform_observer_handshake_responder, read_frame_plain,
    read_frame_plain_limited, write_frame_plain, ObserverFrameLimiter, ObserverHandshakeResult,
};
pub use peer::{PeerInfo, PeerStatus, PeerTable};
pub use peer_manager::{spawn_peer_manager, PeerManagerConfig, PeerManagerHandle};
pub use policy::{BanStore, BoundedCooldownTracker, BoundedTtlSet, CooldownTracker, NetworkGroup};
pub use rate_limit::{
    GlobalRateLimiter, MessageClass, PeerRateLimiter, StrikeCounter, TokenBucket,
};
pub use transport::{Connection, Transport};
