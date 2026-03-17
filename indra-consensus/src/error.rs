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
    #[error("proposer identity mismatch")]
    WrongProposer,

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

impl From<indra_crypto::CryptoError> for ConsensusError {
    fn from(e: indra_crypto::CryptoError) -> Self {
        Self::CryptoError { detail: e.to_string() }
    }
}
