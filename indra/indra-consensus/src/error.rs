//! Error types for the consensus engine.

use thiserror::Error;

/// All errors that can occur in the consensus engine.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ConsensusError {
    // ── Mempool errors ────────────────────────────────────────────────────
    /// Transaction is already in the mempool.
    #[error("transaction already in mempool")]
    DuplicateTransaction,

    /// Transaction failed structural validation.
    #[error("transaction failed validation: {reason}")]
    InvalidTransaction {
        /// Why it failed.
        reason: &'static str,
    },

    /// Mempool is at capacity.
    #[error("mempool full: {capacity} transactions")]
    MempoolFull {
        /// Maximum capacity.
        capacity: usize,
    },

    /// The mempool cannot accommodate another transaction within its byte cap.
    #[error("mempool encoded-byte limit reached: {limit} bytes")]
    MempoolByteLimit {
        /// Maximum aggregate canonical transaction bytes.
        limit: usize,
    },

    /// Transaction fee is below the current base fee.
    #[error("transaction fee too low")]
    FeeTooLow,

    // ── Proposer election errors ──────────────────────────────────────────
    /// The validator set is empty — cannot elect a proposer.
    #[error("cannot elect proposer: validator set is empty")]
    EmptyValidatorSet,

    /// The given validator is not in the active set.
    #[error("validator not found in active set")]
    ValidatorNotFound,

    // ── Block production errors ───────────────────────────────────────────
    /// The proposer keypair does not match the elected proposer.
    #[error("proposer identity mismatch: {reason}")]
    WrongProposer {
        /// Which proposer-identity check failed.
        reason: &'static str,
    },

    /// No transactions available to fill the block.
    #[error("no transactions available")]
    EmptyMempool,

    // ── Vote / QC errors ──────────────────────────────────────────────────
    /// A vote was received for the wrong height or round.
    #[error("vote height/round mismatch: expected {expected_height}/{expected_round}")]
    VoteHeightMismatch {
        /// Expected height.
        expected_height: u64,
        /// Expected round.
        expected_round: u32,
    },

    /// A vote was received from an unknown validator.
    #[error("vote from unknown validator")]
    UnknownVoter,

    /// A duplicate vote was received from the same validator.
    #[error("duplicate vote from validator")]
    DuplicateVote,

    /// QC construction attempted before quorum was reached.
    #[error("quorum not yet reached: have {have_bps} bps, need {need_bps} bps")]
    QuorumNotReached {
        /// Current stake in basis points.
        have_bps: u64,
        /// Required threshold.
        need_bps: u64,
    },

    /// Signer stake does not meet the QC threshold.
    #[error("insufficient QC signer stake: have {have}, need {need}")]
    InsufficientStake {
        /// Stake represented by included signatures.
        have: u64,
        /// Required quorum stake.
        need: u64,
    },

    /// QC signature list length does not match the signer bitfield.
    #[error("QC signature count mismatch: expected {expected}, got {got}")]
    SignatureCountMismatch {
        /// Number of signatures implied by the signer bitfield.
        expected: usize,
        /// Number of PQ signatures carried in the QC.
        got: usize,
    },

    /// Duplicate PQ signatures were included for the same validator.
    #[error("duplicate QC signature for validator")]
    DuplicateSignature,

    /// A signer indicated by the bitfield is missing its PQ signature.
    #[error("missing QC signature for validator {validator_id}")]
    MissingSignature {
        /// The validator whose signature is missing.
        validator_id: indra_core::types::primitives::Bytes32,
    },

    /// A validator's PQ signature did not verify.
    #[error("invalid QC PQ signature for validator {validator_id}")]
    InvalidPQSignature {
        /// The validator whose signature failed verification.
        validator_id: indra_core::types::primitives::Bytes32,
    },

    /// A QC failed signature verification.
    #[error("QC signature verification failed")]
    QcVerificationFailed,

    /// Crypto operation failed.
    #[error("crypto error: {detail}")]
    CryptoError {
        /// Detail from the underlying crypto layer.
        detail: String,
    },
}

/// Convenience alias.
pub type ConsensusResult<T> = Result<T, ConsensusError>;

impl ConsensusError {
    /// Construct a proposer-identity error with a stable diagnostic reason.
    pub fn wrong_proposer(reason: &'static str) -> Self {
        Self::WrongProposer { reason }
    }
}

impl From<indra_crypto::CryptoError> for ConsensusError {
    fn from(e: indra_crypto::CryptoError) -> Self {
        Self::CryptoError {
            detail: e.to_string(),
        }
    }
}
