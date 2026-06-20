//! Async network bridge types shared between `indra-network` and `indra-node`.

use std::net::SocketAddr;

use indra_core::types::primitives::Bytes32;

use crate::message::Message;

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
    },
    /// A connected peer dropped or was disconnected.
    PeerDisconnected {
        /// Authenticated validator identity.
        validator_id: Bytes32,
        /// Last known remote socket address.
        addr: SocketAddr,
    },
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
}
