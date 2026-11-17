//! Error types for the state machine.

use thiserror::Error;

/// Definitive failures from height-derived consensus-snapshot resolution.
///
/// Callers either receive the one canonical snapshot for the requested
/// governed height or an error; this type carries no fallback value.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ConsensusSnapshotLookupError {
    /// Retained snapshot state was malformed or non-canonical.
    #[error("invalid retained consensus snapshots: {reason}")]
    InvalidRetainedState {
        /// Precise invariant failure.
        reason: String,
    },

    /// No retained activation covers a governed consensus height.
    #[error("no retained consensus snapshot governs height {height}")]
    NoSnapshotForHeight {
        /// Governed consensus height that could not be resolved.
        height: u64,
    },
}

/// All errors that can occur during state transitions.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum StateError {
    /// An internal canonical-state invariant was violated.
    #[error("internal state invariant violated at {site}")]
    InternalInvariant {
        /// Stable source location for the invariant.
        site: &'static str,
    },
    // ── Block-level errors ─────────────────────────────────────────────────
    /// A canonical staking position or tranche capacity invariant would fail.
    #[error("staking position capacity exceeded: {reason}")]
    StakePositionCapacityExceeded {
        /// Exact capacity invariant that rejected the transition.
        reason: String,
    },
    /// Block height is not exactly prev_height + 1.
    #[error("invalid block height: expected {expected}, got {actual}")]
    InvalidHeight {
        /// Expected height.
        expected: u64,
        /// Actual height in the block.
        actual: u64,
    },

    /// Block's prev_hash does not match the current tip hash.
    #[error("block prev_hash does not match current tip at height {height}: expected {expected}, got {got}")]
    PrevHashMismatchDetailed {
        /// Block height being applied.
        height: u64,
        /// The local state's current tip hash.
        expected: indra_core::Bytes32,
        /// The prev_hash carried by the block.
        got: indra_core::Bytes32,
    },

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

    /// A canonical collection has reached its live consensus capacity.
    #[error("live {collection} capacity reached: {current} entries (maximum {max})")]
    LiveStateCapacityExceeded {
        /// Canonical collection name.
        collection: &'static str,
        /// Current collection size.
        current: usize,
        /// Consensus maximum.
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

    /// A block or transaction attempts to spend the same UTXO more than once.
    #[error("duplicate UTXO spend in block: {utxo_id}")]
    DuplicateUtxoSpend {
        /// UTXO ID that appeared more than once in transaction inputs.
        utxo_id: indra_core::Bytes32,
    },

    /// Transaction signature verification failed.
    #[error("transaction signature invalid: {reason}")]
    SignatureInvalid {
        /// Specific reason the signature could not be verified.
        reason: String,
    },

    /// A newly created output carries a malformed or non-canonical hybrid owner key.
    #[error("transaction output owner key invalid: {reason}")]
    InvalidOutputOwnerKey {
        /// Canonical key-validation failure.
        reason: String,
    },

    /// Transaction version is not supported by this state machine.
    #[error("transaction version {version} not supported")]
    UnsupportedTxVersion {
        /// Unsupported version value.
        version: u16,
    },

    /// Transaction declared an unsupported signature module.
    #[error("unsupported signature module {module_id}")]
    UnsupportedSignatureModule {
        /// The unsupported signature module ID.
        module_id: u16,
    },

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

    /// Transaction value arithmetic overflowed.
    #[error("transaction value arithmetic overflow")]
    ValueOverflow,

    // ── State integrity errors ─────────────────────────────────────────────
    /// A staking operation was invalid.
    #[error("invalid staking op: {0}")]
    InvalidStakingOp(String),

    /// No full-registry victim can be represented within tombstone bounds.
    #[error("validator registry replacement cannot retain any victim within tombstone capacity")]
    TombstoneCapacityExceeded,

    /// A deposit would exceed one validator's canonical position cap.
    #[error("validator {validator_id} already has the maximum {max} stake positions")]
    ValidatorPositionCountAtMaximum {
        /// Validator whose bond population is full.
        validator_id: indra_core::Bytes32,
        /// Consensus cap in force.
        max: usize,
    },

    /// Canonical consensus-snapshot construction or retention failed.
    #[error("invalid consensus snapshot state: {0}")]
    InvalidConsensusSnapshot(String),

    /// Reward-economic snapshot state or pairing is malformed.
    #[error("invalid reward economic snapshot: {0}")]
    InvalidRewardEconomicSnapshot(String),

    /// Validator is already registered.
    #[error("validator already registered")]
    ValidatorAlreadyRegistered,

    /// Validator key material is already registered to another validator.
    #[error("duplicate validator key: {reason}")]
    DuplicateValidatorKey {
        /// Specific duplicated key field.
        reason: String,
    },

    /// Staking op signature verification failed.
    #[error("staking op signature invalid: {reason}")]
    StakingOpSignatureInvalid {
        /// Specific reason the signature could not be verified.
        reason: String,
    },

    /// Staking op nonce is invalid.
    #[error("staking op nonce invalid: expected {expected}, got {got}")]
    StakingNonceInvalid {
        /// Expected next nonce.
        expected: u64,
        /// Nonce carried by the operation.
        got: u64,
    },

    /// A block contains more staking operations than allowed.
    #[error("block contains {actual} staking ops, maximum is {max}")]
    TooManyStakingOps {
        /// Actual count.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Slash evidence already applied — duplicate submission.
    #[error("slash evidence already applied")]
    SlashAlreadyApplied,

    /// Slash evidence is cryptographically invalid or logically inconsistent.
    #[error("invalid slash evidence: {reason}")]
    InvalidSlashEvidence {
        /// Specific reason the evidence is invalid.
        reason: String,
    },

    /// Block contains duplicate slash evidence entries.
    #[error("block contains duplicate slash evidence")]
    DuplicateSlashEvidence,

    /// A block contains more governance operations than allowed.
    #[error("block contains {actual} governance ops, maximum is {max}")]
    TooManyGovernanceOps {
        /// Actual count.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Governance operation is invalid.
    #[error("invalid governance op: {reason}")]
    InvalidGovernanceOp {
        /// Specific reason.
        reason: String,
    },

    /// Governance operation signature is invalid.
    #[error("governance op signature invalid: {reason}")]
    GovernanceSignatureInvalid {
        /// Specific reason.
        reason: String,
    },

    /// Governance nonce is invalid.
    #[error("governance nonce invalid: expected {expected}, got {got}")]
    GovernanceNonceInvalid {
        /// Expected next nonce.
        expected: u64,
        /// Nonce carried by operation.
        got: u64,
    },

    /// Governance proposal was not found.
    #[error("governance proposal not found")]
    GovernanceProposalNotFound,

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
