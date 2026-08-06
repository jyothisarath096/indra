//! Network-to-consensus bridge.
//!
//! Converts inbound network messages into DriverEvents,
//! processes them through the ConsensusDriver, and converts
//! DriverActions back into network messages for broadcast.

use std::net::SocketAddr;

use indra_network::message::Message;

use crate::driver::{DriverAction, DriverEvent};

/// Convert a network Message into a DriverEvent.
pub fn message_to_event(msg: Message, from: SocketAddr) -> Option<DriverEvent> {
    match msg {
        Message::Block(block) => Some(DriverEvent::InboundBlock {
            from: Some(from),
            block,
        }),
        Message::Vote(vote) => Some(DriverEvent::InboundVote { from, vote }),
        // Transactions use the node's single authoritative path, which wraps
        // mempool validation with deduplication and identity scoring.
        Message::Tx(_) => None,
        Message::Status {
            height,
            tip_hash,
            round,
        } => Some(DriverEvent::PeerStatus {
            from,
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
        Message::VrfCommit(commit) => Some(DriverEvent::InboundVrfCommit { from, commit }),
        Message::VrfReveal(reveal) => Some(DriverEvent::InboundVrfReveal { from, reveal }),
        Message::RequestVrfReveals {
            height,
            round,
            validator_ids,
        } => Some(DriverEvent::VrfRevealsRequest {
            from,
            height,
            round,
            missing_validator_ids: validator_ids,
        }),
        Message::VrfRevealsResponse {
            height,
            round,
            reveals,
        } => Some(DriverEvent::VrfRevealsResponse {
            from,
            height,
            round,
            reveals,
        }),
        _ => None, // Ping, Pong, PeerList, RequestBlocks, BlockResponse, RequestProposal handled elsewhere
    }
}

/// Convert a DriverAction into a network Message (if broadcastable).
pub fn action_to_message(action: &DriverAction) -> Option<Message> {
    match action {
        DriverAction::BroadcastBlock(block) => Some(Message::Block(block.clone())),
        DriverAction::BroadcastVote(vote) => Some(Message::Vote(vote.clone())),
        DriverAction::BroadcastVrfCommit(commit) => Some(Message::VrfCommit(commit.clone())),
        DriverAction::BroadcastVrfReveal(reveal) => Some(Message::VrfReveal(reveal.clone())),
        DriverAction::RequestQC { .. } => None,
        DriverAction::RequestVrfReveals { .. } => None,
        DriverAction::SendVrfRevealsResponse { .. } => None,
        _ => None,
    }
}
