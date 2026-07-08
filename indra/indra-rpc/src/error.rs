//! RPC error types.

use thiserror::Error;

/// JSON-RPC 2.0 standard error codes.
/// JSON-RPC parse error code.
pub const ERR_PARSE_ERROR: i32 = -32700;
/// JSON-RPC invalid request code.
pub const ERR_INVALID_REQUEST: i32 = -32600;
/// JSON-RPC method not found code.
pub const ERR_METHOD_NOT_FOUND: i32 = -32601;
/// JSON-RPC invalid params code.
pub const ERR_INVALID_PARAMS: i32 = -32602;
/// JSON-RPC internal error code.
pub const ERR_INTERNAL_ERROR: i32 = -32603;
/// Application-specific error range starts at -32000.
pub const ERR_NOT_FOUND: i32 = -32000;
/// Transaction rejected.
pub const ERR_TX_REJECTED: i32 = -32001;
/// Node is not synced.
pub const ERR_NOT_SYNCED: i32 = -32002;
/// Request is not permitted on this RPC listener.
pub const ERR_FORBIDDEN: i32 = -32003;

/// An RPC-level error.
#[derive(Debug, Error, Clone)]
pub enum RpcError {
    /// Request JSON was malformed.
    #[error("parse error: {0}")]
    ParseError(String),

    /// The requested method does not exist.
    #[error("method not found: {0}")]
    MethodNotFound(String),

    /// Parameters were missing or invalid.
    #[error("invalid params: {0}")]
    InvalidParams(String),

    /// An internal node error occurred.
    #[error("internal error: {0}")]
    Internal(String),

    /// The requested resource was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// A submitted transaction was rejected.
    #[error("transaction rejected: {0}")]
    TxRejected(String),

    /// The requested method is not allowed in this RPC listener mode.
    #[error("forbidden: {0}")]
    Forbidden(String),
}

impl RpcError {
    /// The JSON-RPC error code for this error.
    pub fn code(&self) -> i32 {
        match self {
            Self::ParseError(_) => ERR_PARSE_ERROR,
            Self::MethodNotFound(_) => ERR_METHOD_NOT_FOUND,
            Self::InvalidParams(_) => ERR_INVALID_PARAMS,
            Self::Internal(_) => ERR_INTERNAL_ERROR,
            Self::NotFound(_) => ERR_NOT_FOUND,
            Self::TxRejected(_) => ERR_TX_REJECTED,
            Self::Forbidden(_) => ERR_FORBIDDEN,
        }
    }

    /// The user-facing JSON-RPC error message.
    pub fn message(&self) -> &str {
        match self {
            Self::ParseError(message)
            | Self::MethodNotFound(message)
            | Self::InvalidParams(message)
            | Self::Internal(message)
            | Self::NotFound(message)
            | Self::TxRejected(message)
            | Self::Forbidden(message) => message,
        }
    }
}

/// Convenience alias.
pub type RpcResult<T> = Result<T, RpcError>;
