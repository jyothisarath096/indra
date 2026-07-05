//! Async network bridge types shared between `indra-network` and `indra-node`.

use std::net::SocketAddr;

use indra_core::types::{primitives::Bytes32, slashing::SlashEvidenceV1};

use crate::message::Message;

/// Read-only validator public keys used by the peer manager for relay
/// eligibility checks.
#[derive(Debug, Clone)]
pub struct RelayValidatorKey {
    /// Validator identity.
    pub validator_id: Bytes32,
    /// Ed25519 hybrid public key component.
    pub hybrid_classical_pk: [u8; 32],
    /// ML-DSA-87 hybrid public key component.
    pub hybrid_pq_pk: Vec<u8>,
    /// Registered proposer-election VRF public key, when available.
    pub vrf_pk: Option<[u8; 32]>,
}

/// Events emitted by the async network layer.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A decrypted protocol message arrived from a peer.
    Message {
        /// Remote socket address for routing existing sync logic.
        from: SocketAddr,
        /// Authenticated validator identity of the peer.
        validator_id: Bytes32,
        /// Decoded application message.
        msg: Message,
    },
    /// A peer completed the authenticated transport handshake.
    PeerConnected {
        /// Authenticated validator identity.
        validator_id: Bytes32,
        /// Remote socket address.
        addr: SocketAddr,
        /// True when this node initiated the connection by dialing `addr`.
        ///
        /// For inbound connections, `addr` is the accepted socket's source
        /// endpoint and may contain an ephemeral port. Callers must not treat
        /// that endpoint as a future dial candidate.
        is_outbound: bool,
    },
    /// A connected peer dropped or was disconnected.
    PeerDisconnected {
        /// Authenticated validator identity.
        validator_id: Bytes32,
        /// Last known remote socket address.
        addr: SocketAddr,
    },
    /// Slash evidence detected by the transport before rate limiting.
    SlashDetected(SlashEvidenceV1),
}

/// Commands sent from the node to the async network layer.
#[derive(Debug, Clone)]
pub enum NetworkCommand {
    /// Broadcast a message to all connected peers.
    Broadcast(Message),
    /// Send a message to one authenticated validator.
    SendTo {
        /// Destination peer validator identity.
        validator_id: Bytes32,
        /// Message to send.
        msg: Message,
    },
    /// Disconnect a peer.
    Disconnect {
        /// Remote validator identity to drop.
        validator_id: Bytes32,
    },
    /// Disconnect a peer that sent an invalid consensus message.
    ///
    /// This applies an invalid-message score penalty, but unlike the rate
    /// limiter path it does not impose an immediate 10-minute ban for one
    /// bad consensus payload.
    DisconnectInvalidConsensusPeer {
        /// Remote validator identity to drop.
        validator_id: Bytes32,
        /// Human-readable reason for logs.
        reason: String,
    },
    /// Replace the read-only validator key snapshot used for relay checks.
    UpdateRelayValidatorKeys {
        /// Current chain id for vote domain separation.
        chain_id: String,
        /// Active validator public keys.
        validators: Vec<RelayValidatorKey>,
    },
}
