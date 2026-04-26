//! Error types for the state machine.

use thiserror::Error;

/// All errors that can occur during state transitions.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum StateError {
    // ── Block-level errors ─────────────────────────────────────────────────

    /// Block height is not exactly prev_height + 1.
    #[error("invalid block height: expected {expected}, got {actual}")]
    InvalidHeight {
        /// Expected height.
        expected: u64,
        /// Actual height in the block.
        actual: u64,
    },

    /// Block's prev_hash does not match the current tip hash.
    #[error("block prev_hash does not match current tip")]
    PrevHashMismatch,

    /// Block's protocol version is not supported.
    #[error("unsupported protocol version {version}")]
    UnsupportedVersion {
        /// The version found.
        version: u16,
    },

    /// Block exceeds the maximum permitted size.
    #[error("block {actual} bytes exceeds maximum {max} bytes")]
    BlockTooLarge {
        /// Actual encoded size.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Block contains more transactions than allowed.
    #[error("block contains {actual} transactions, maximum is {max}")]
    TooManyTransactions {
        /// Actual count.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Block's base_fee field does not match the computed value.
    #[error("block base_fee {block_fee} does not match computed {computed_fee}")]
    BaseFeeIncorrect {
        /// What the block claims.
        block_fee: u64,
        /// What we computed.
        computed_fee: u64,
    },

    // ── Transaction-level errors ───────────────────────────────────────────

    /// A transaction references a UTXO that does not exist.
    #[error("transaction references unknown UTXO")]
    UnknownUtxo,

    /// A transaction attempts to spend an already-spent nullifier.
    #[error("double-spend detected: nullifier already in nullifier set")]
    DoubleSpend,

    /// A transaction's fee is below the required base fee.
    #[error("transaction fee {actual} Spark/KB below required {required} Spark/KB")]
    FeeTooLow {
        /// Fee the transaction paid.
        actual: u64,
        /// Minimum required.
        required: u64,
    },

    /// A transaction has zero inputs.
    #[error("transaction has zero inputs")]
    ZeroInputs,

    /// A transaction has zero outputs.
    #[error("transaction has zero outputs")]
    ZeroOutputs,

    /// A transaction contains duplicate nullifiers.
    #[error("transaction contains duplicate nullifiers")]
    DuplicateNullifier,

    /// A block contains the same transaction twice.
    #[error("block contains duplicate transaction")]
    DuplicateTransaction,

    /// An output value is below the dust limit.
    #[error("output value below dust limit of {limit} Spark")]
    BelowDustLimit {
        /// The dust limit.
        limit: u64,
    },

    /// An output is locked and cannot be spent at the current height.
    #[error("output locked until height {lock_height}, current height {current_height}")]
    OutputLocked {
        /// When it unlocks.
        lock_height: u64,
        /// Current height.
        current_height: u64,
    },

    /// A transaction output carries an invalid Bulletproof range proof.
    #[error("output {index} has an invalid range proof")]
    RangeProofInvalid {
        /// Output index within the transaction.
        index: usize,
    },

    // ── State integrity errors ─────────────────────────────────────────────

    /// A staking operation was invalid.
    #[error("invalid staking op: {0}")]
    InvalidStakingOp(String),

    /// Validator not found in the validator set.
    #[error("validator not found")]
    ValidatorNotFound,

    /// Validator is not in Active status.
    #[error("validator is not active")]
    ValidatorNotActive,

    /// Delegator not found for this validator.
    #[error("delegator not found")]
    DelegatorNotFound,

    /// An invariant was violated. The node must halt.
    #[error("INVARIANT VIOLATION: {message}")]
    InvariantViolation {
        /// Description of the violated invariant.
        message: &'static str,
    },
}

/// Convenience alias.
pub type StateResult<T> = Result<T, StateError>;
