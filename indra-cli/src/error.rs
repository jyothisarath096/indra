//! CLI error types.

use thiserror::Error;

/// All errors that can occur in CLI commands.
#[derive(Debug, Error)]
pub enum CliError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid hex input.
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    /// Missing required argument.
    #[error("missing argument: {0}")]
    MissingArgument(String),

    /// RPC call failed.
    #[error("RPC error: {0}")]
    Rpc(String),

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Genesis config is invalid.
    #[error("genesis error: {0}")]
    Genesis(String),
}

/// Convenience alias.
pub type CliResult<T> = Result<T, CliError>;
