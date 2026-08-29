//! Network-to-consensus bridge.
//!
//! Converts inbound network messages into DriverEvents,
//! processes them through the ConsensusDriver, and converts
//! DriverActions back into network messages for broadcast.

use std::net::SocketAddr;

use indra_network::message::Message;

use crate::driver::{DriverAction, DriverEvent};

/// Convert a network Message into a DriverEvent.
pub fn message_to_event(
    msg: Message,
    from: SocketAddr,
    validator_id: indra_core::Bytes32,
) -> Option<DriverEvent> {
    match msg {
        Message::Block(proposal) => Some(DriverEvent::InboundBlock {
            from: Some(from),
            proposal,
        }),
        Message::Vote(vote) => Some(DriverEvent::InboundVote { from, vote }),
        // Transactions use the node's single authoritative path, which wraps
        // mempool validation with deduplication and identity scoring.
        Message::Tx(_) | Message::TxStem(_) => None,
        Message::Status {
            height,
            tip_hash,
            round,
        } => Some(DriverEvent::PeerStatus {
            from,
            validator_id,
            height,
            tip_hash,
            round,
        }),
        Message::RequestQC { height } => Some(DriverEvent::QcRequest { from, height }),
        Message::QCResponse { height, qc_bytes } => Some(DriverEvent::QcResponse {
            from,
            height,
            qc_bytes,
        }),
        _ => None, // Ping, Pong, PeerList, RequestBlocks, BlockResponse, RequestProposal handled elsewhere
    }
}

/// Convert a DriverAction into a network Message (if broadcastable).
pub fn action_to_message(action: &DriverAction) -> Option<Message> {
    match action {
        DriverAction::BroadcastBlock(block) => Some(Message::Block(block.clone())),
        DriverAction::BroadcastVote(vote) => Some(Message::Vote(vote.clone())),
        DriverAction::RequestQC { .. } => None,
        _ => None,
    }
}
