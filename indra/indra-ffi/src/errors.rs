/// Error codes returned by INDRA FFI functions.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndraError {
    /// Operation succeeded.
    Ok = 0,
    /// A required pointer argument was null.
    NullPointer = -1,
    /// Output buffer too small.
    BufferTooSmall = -2,
    /// Invalid hex encoding in input.
    InvalidHex = -3,
    /// Key generation failed.
    KeygenFailed = -4,
    /// Transaction building failed.
    TxBuildFailed = -5,
    /// Signing failed.
    SignFailed = -6,
    /// Range proof generation or verification failed.
    RangeProofFailed = -7,
    /// Insufficient wallet balance.
    InsufficientBalance = -8,
    /// Invalid parameter value.
    InvalidParam = -9,
    /// JSON parse error for governance action JSON.
    InvalidJson = -10,
    /// Unknown governable action type.
    UnknownAction = -11,
    /// Invalid governance vote value.
    InvalidVote = -12,
    /// Unknown, destroyed, or otherwise invalid opaque key handle.
    InvalidHandle = -13,
    /// Internal error.
    Internal = -99,
}

impl IndraError {
    /// Convert to the ABI integer code.
    pub const fn code(self) -> i32 {
        self as i32
    }
}

impl From<indra_cli::CliError> for IndraError {
    fn from(value: indra_cli::CliError) -> Self {
        match value {
            indra_cli::CliError::InvalidHex(_) => Self::InvalidHex,
            indra_cli::CliError::InsufficientBalance { .. } => Self::InsufficientBalance,
            indra_cli::CliError::Crypto(_) => Self::SignFailed,
            indra_cli::CliError::Transaction(message) => {
                if message.contains("range proof") {
                    Self::RangeProofFailed
                } else {
                    Self::TxBuildFailed
                }
            }
            indra_cli::CliError::Parse(_) | indra_cli::CliError::MissingArgument(_) => {
                Self::InvalidParam
            }
            _ => Self::Internal,
        }
    }
}

/// Static C strings for each error code.
pub const fn error_string(error_code: i32) -> &'static [u8] {
    match error_code {
        0 => b"ok\0",
        -1 => b"null pointer\0",
        -2 => b"buffer too small\0",
        -3 => b"invalid hex\0",
        -4 => b"key generation failed\0",
        -5 => b"transaction build failed\0",
        -6 => b"signing failed\0",
        -7 => b"range proof failed\0",
        -8 => b"insufficient balance\0",
        -9 => b"invalid parameter\0",
        -10 => b"invalid json\0",
        -11 => b"unknown governance action\0",
        -12 => b"invalid vote\0",
        -13 => b"invalid key handle\0",
        _ => b"internal error\0",
    }
}
