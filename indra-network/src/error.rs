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
