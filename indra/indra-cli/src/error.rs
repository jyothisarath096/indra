//! CLI error types.

use thiserror::Error;

/// All errors that can occur in CLI commands.
#[derive(Debug, Error)]
pub enum CliError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(String),

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

    /// Wallet has insufficient balance.
    #[error("insufficient balance: have {have} Spark, need {need} Spark")]
    InsufficientBalance {
        /// Available balance in Spark.
        have: u64,
        /// Required amount in Spark.
        need: u64,
    },

    /// Failed to parse a value.
    #[error("parse error: {0}")]
    Parse(String),

    /// Transaction build failed.
    #[error("transaction error: {0}")]
    Transaction(String),
}

/// Convenience alias.
pub type CliResult<T> = Result<T, CliError>;
