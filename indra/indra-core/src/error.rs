//! Unified error type for the INDRA serialisation and validation layer.

use thiserror::Error;

/// All errors that can occur in indra-core.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum IndraError {
    /// Read requested more bytes than were available.
    #[error("unexpected end of input: need {needed} bytes, have {available}")]
    UnexpectedEof {
        /// How many bytes were needed.
        needed: usize,
        /// How many bytes were available.
        available: usize,
    },

    /// Trailing bytes remained after a complete decode.
    #[error("trailing bytes after decode: {count} bytes remain")]
    TrailingBytes {
        /// Number of unexpected trailing bytes.
        count: usize,
    },

    /// A length-prefixed field exceeded its protocol maximum.
    #[error("field '{field}' length {actual} exceeds maximum {max}")]
    LengthExceeded {
        /// Name of the field.
        field: &'static str,
        /// Maximum allowed length.
        max: usize,
        /// Actual length encountered.
        actual: usize,
    },

    /// A bool byte was not 0x00 or 0x01.
    #[error("invalid bool byte: 0x{byte:02x} (expected 0x00 or 0x01)")]
    InvalidBool {
        /// The invalid byte value.
        byte: u8,
    },

    /// Unsupported protocol version.
    #[error("unsupported protocol version {version} (expected 1)")]
    UnsupportedVersion {
        /// The version number found.
        version: u16,
    },

    /// Unsupported quorum certificate wire format version.
    #[error("unsupported QC format version {format}")]
    InvalidQcFormat {
        /// The QC format byte found.
        format: u8,
    },

    /// A versioned consensus snapshot failed canonical validation.
    #[error("invalid consensus snapshot: {0}")]
    InvalidConsensusSnapshot(String),

    /// A versioned reward-economic snapshot failed canonical validation.
    #[error("invalid reward economic snapshot: {0}")]
    InvalidRewardEconomicSnapshot(String),

    /// A canonical staking position or unbonding tranche failed validation.
    #[error("invalid staking position or tranche: {0}")]
    InvalidStakePosition(String),

    /// A slash-membership root, proof, or evidence envelope failed validation.
    #[error("invalid slash membership proof: {0}")]
    InvalidSlashMembershipProof(String),

    /// Unsupported persisted-struct schema version.
    #[error(
        "unsupported schema version {version} for {struct_name} (max supported {max_supported})"
    )]
    UnsupportedSchemaVersion {
        /// Name of the persisted struct.
        struct_name: &'static str,
        /// The version number found.
        version: u8,
        /// Highest version supported by this node.
        max_supported: u8,
    },

    /// Persisted data was written by a newer node schema.
    #[error("schema version {version} is newer than node schema version {max_supported}")]
    SchemaVersionTooNew {
        /// The version number found.
        version: u8,
        /// Highest version supported by this node.
        max_supported: u8,
    },

    /// Unsupported signature module ID.
    #[error("unsupported signature module ID {id}")]
    UnsupportedSignatureModule {
        /// The module ID found.
        id: u16,
    },

    /// Transaction has no inputs.
    #[error("transaction has zero inputs")]
    ZeroInputs,

    /// Transaction has no outputs.
    #[error("transaction has zero outputs")]
    ZeroOutputs,

    /// A UTXO value is below the dust limit.
    #[error("UTXO value {value} Spark is below dust limit {limit} Spark")]
    BelowDustLimit {
        /// The actual value.
        value: u64,
        /// The dust limit.
        limit: u64,
    },

    /// Fee is below the minimum required.
    #[error("fee {actual} Spark/KB is below minimum {minimum} Spark/KB")]
    FeeTooLow {
        /// The fee paid.
        actual: u64,
        /// The minimum required.
        minimum: u64,
    },

    /// Duplicate nullifier within a single transaction.
    #[error("duplicate nullifier in transaction")]
    DuplicateNullifier,

    /// Transaction failed structural validation.
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    /// Duplicate transaction in block.
    #[error("duplicate transaction in block")]
    DuplicateTransaction,

    /// Block exceeds the maximum size.
    #[error("block {actual} bytes exceeds maximum {max} bytes")]
    BlockTooLarge {
        /// Actual size in bytes.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// A list field contained duplicate entries.
    #[error("field '{field}' contains duplicate entries")]
    DuplicateEntries {
        /// Name of the field.
        field: &'static str,
    },

    /// Signature verification failed.
    #[error("signature verification failed for {scheme}")]
    SignatureInvalid {
        /// Which scheme failed.
        scheme: &'static str,
    },

    /// VRF proof failed.
    #[error("VRF proof verification failed")]
    VrfProofInvalid,

    /// QC below the required quorum threshold.
    #[error("QC below 2/3 threshold: {weight_bps} bps")]
    InsufficientQuorum {
        /// Stake-weighted vote in basis points.
        weight_bps: u32,
    },

    /// A referenced UTXO does not exist.
    #[error("UTXO not found")]
    UtxoNotFound,

    /// A nullifier has already been spent.
    #[error("nullifier already spent (double-spend)")]
    DoubleSpend,

    /// A UTXO is time-locked.
    #[error("UTXO locked until height {lock_height}, current height is {current_height}")]
    UtxoLocked {
        /// The height at which the UTXO unlocks.
        lock_height: u64,
        /// The current chain height.
        current_height: u64,
    },

    /// A staking operation was structurally invalid.
    #[error("invalid staking op: {0}")]
    InvalidStakingOp(String),

    /// A hot/cold authorization envelope was malformed or internally inconsistent.
    #[error("invalid authorization envelope: {0}")]
    InvalidAuthorizationEnvelope(String),

    /// Commission rate outside the protocol-allowed range.
    #[error("commission {actual} bps out of range [{min}, {max}]")]
    CommissionOutOfRange {
        /// The actual commission value supplied.
        actual: u32,
        /// The minimum allowed commission.
        min: u32,
        /// The maximum allowed commission.
        max: u32,
    },

    /// An internal invariant was violated. The node must halt.
    #[error("INVARIANT VIOLATION: {message} — node must halt")]
    InvariantViolation {
        /// Description of the violated invariant.
        message: &'static str,
    },
}

/// Convenience alias used throughout the crate.
pub type IndraResult<T> = Result<T, IndraError>;
