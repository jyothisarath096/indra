//! Network error types.

use indra_core::types::primitives::Bytes32;
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

    /// The peer sent a message type from a newer protocol version.
    ///
    /// Unknown future messages are skipped rather than treated as invalid so a
    /// rolling upgrade can briefly mix old and new validators without causing
    /// disconnects or bans.
    #[error("unknown message type {got:#04x}")]
    UnknownMessageType {
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

    /// The peer did not complete the authenticated handshake in time.
    #[error("handshake timed out")]
    HandshakeTimeout,

    /// A peer sent the wrong protocol magic.
    #[error("invalid transport magic")]
    InvalidMagic,

    /// A peer announced an unsupported protocol version.
    #[error("unsupported transport version {got}")]
    UnsupportedVersion {
        /// Version announced by the peer.
        got: u16,
    },

    /// The peer belongs to a different chain.
    #[error("chain id mismatch: expected {expected:?}, got {got:?}")]
    ChainIdMismatch {
        /// Locally configured chain identifier.
        expected: String,
        /// Chain identifier announced by the peer.
        got: String,
    },

    /// The peer claimed a validator identity we do not trust.
    #[error("unknown validator {validator_id}")]
    UnknownValidator {
        /// The unknown validator identity.
        validator_id: Bytes32,
    },

    /// The peer's ML-DSA transport authentication signature was invalid.
    #[error("invalid transport authentication signature")]
    InvalidSignature,

    /// The peer sent malformed or invalid ML-KEM key material.
    #[error("invalid ML-KEM key material")]
    InvalidKem,

    /// An encrypted frame failed integrity verification or used a bad nonce.
    #[error("invalid encrypted frame: {reason}")]
    InvalidFrame {
        /// Why the frame was rejected.
        reason: String,
    },

    /// A peer replayed or reordered a frame nonce.
    #[error("unexpected frame nonce: expected {expected}, got {got}")]
    UnexpectedNonce {
        /// Next nonce expected by the receiver.
        expected: u64,
        /// Nonce observed on the wire.
        got: u64,
    },

    /// The transport exhausted its per-direction nonce space.
    #[error("transport nonce space exhausted")]
    NonceExhausted,

    /// A local cryptographic operation failed while preparing or verifying transport state.
    #[error("transport crypto error: {reason}")]
    Crypto {
        /// Human-readable failure detail.
        reason: String,
    },
}

/// Convenience alias.
pub type NetworkResult<T> = Result<T, NetworkError>;
