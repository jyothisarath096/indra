//! Async network bridge types shared between `indra-network` and `indra-node`.

use std::net::SocketAddr;

use indra_core::types::transaction::TransactionV1;
use indra_core::types::{primitives::Bytes32, slashing::SlashEvidenceV1};

use crate::{message::Message, peer::ScoreEvent};

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
        msg: Box<Message>,
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
        /// True when this node initiated the disconnected connection.
        is_outbound: bool,
        /// Why the authenticated transport ended.
        reason: PeerDisconnectReason,
    },
    /// Slash evidence detected by the transport before rate limiting.
    SlashDetected(Box<SlashEvidenceV1>),
}

/// Stable high-level reason for an authenticated transport disconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerDisconnectReason {
    /// The remote side closed the stream or the read loop observed EOF.
    RemoteClosed,
    /// The encrypted frame reader failed.
    ReadError,
    /// The encrypted frame writer failed.
    WriteError,
    /// A bounded outbound queue could not accept a point-to-point message.
    Timeout,
    /// Duplicate authenticated connections were reconciled by the tie-break.
    DuplicateConnection,
    /// The peer was disconnected after a ban or invalid-message decision.
    Ban,
    /// The local operator explicitly requested a disconnect.
    Operator,
}

impl std::fmt::Display for PeerDisconnectReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::RemoteClosed => "remote closed",
            Self::ReadError => "read error",
            Self::WriteError => "write error",
            Self::Timeout => "timeout",
            Self::DuplicateConnection => "duplicate connection dropped by tie-break",
            Self::Ban => "ban",
            Self::Operator => "operator disconnect",
        };
        formatter.write_str(text)
    }
}

/// Commands sent from the node to the async network layer.
#[derive(Debug, Clone)]
pub enum NetworkCommand {
    /// Broadcast a message to all connected peers.
    Broadcast(Message),
    /// Broadcast a message to all connected peers except one authenticated
    /// validator.
    BroadcastExcept {
        /// Validator identity to skip.
        except: Bytes32,
        /// Message to send.
        msg: Message,
    },
    /// Send a message to one authenticated validator.
    SendTo {
        /// Destination peer validator identity.
        validator_id: Bytes32,
        /// Message to send.
        msg: Message,
    },
    /// Start a locally admitted transaction in the Dandelion stem phase.
    StartTxStem(TransactionV1),
    /// Continue or fluff an admitted inbound stem transaction.
    AcceptedTxStem {
        /// Authenticated validator that sent the stem message.
        from: Bytes32,
        /// Transaction that passed the node's normal admission path.
        tx: TransactionV1,
    },
    /// Record observed diffusion and cancel any local embargo for this transaction.
    ObserveTxFluff {
        /// Consensus transaction ID (SHA-256 of canonical transaction bytes).
        tx_id: Bytes32,
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
    /// Apply a validation outcome to an authenticated peer's reputation.
    ScorePeer {
        /// Remote validator identity whose message was authoritatively judged.
        validator_id: Bytes32,
        /// Positive or negative authoritative outcome.
        event: ScoreEvent,
    },
    /// Replace the read-only validator key snapshot used for relay checks.
    UpdateRelayValidatorKeys {
        /// Current chain id for vote domain separation.
        chain_id: String,
        /// Active validator public keys.
        validators: Vec<RelayValidatorKey>,
    },
    /// Update the consensus slot that transport relay may forward.
    UpdateRelayConsensusContext {
        /// Next block height currently being voted on.
        height: u64,
        /// Current consensus round for that height.
        round: u32,
    },
}
