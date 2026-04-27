//! # indra-consensus
//!
//! The INDRA v2 consensus engine.
//!
//! ## What this crate does
//!
//! Implements the components that allow a validator node to participate
//! in block production and BFT consensus:
//!
//! - **Mempool**: a validated pool of pending transactions with age tracking.
//!   The age-inclusion guarantee requires that any transaction present in
//!   the mempool for AGE_INCLUSION_BLOCKS consecutive blocks must be included
//!   (prevents censorship without coordination).
//!
//! - **Proposer election**: VRF-based slot assignment. Each validator uses
//!   their secret key and the epoch seed to produce a VRF output. The
//!   validator with the smallest output (weighted by stake) wins the slot.
//!
//! - **Block production**: given a proposer keypair and mempool, assembles
//!   a structurally valid `BlockV1` ready for broadcast and voting.
//!
//! - **Vote handling**: produces signed prevotes and precommits for a given
//!   block hash. Tracks received votes and detects when quorum is reached.
//!
//! - **Quorum Certificate**: collects votes until 2/3 stake threshold is
//!   met, then aggregates the BLS classical signatures and bundles the
//!   individual Dilithium2 signatures into a `QuorumCertificateV1`.
//!
//! ## What this crate does NOT do
//!
//! - P2P networking (Phase 5)
//! - Disk persistence (Phase 5)
//! - Slash evidence detection (Phase 6)
//!
//! ## Invariants
//!
//! - No unsafe code.
//! - No floating-point arithmetic.
//! - All operations are deterministic given the same inputs.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::indexing_slicing)]

pub mod error;
pub mod mempool;
pub mod proposer;
pub mod producer;
pub mod vote;
pub mod qc;

pub use error::{ConsensusError, ConsensusResult};
pub use mempool::{Mempool, MempoolEntry, MempoolConfig};
pub use proposer::{elect_proposer, ProposerElection, SlotResult};
pub use producer::{produce_block, BlockTemplate};
pub use vote::{VoteCollector, VoteDecision, produce_vote};
pub use qc::{build_qc, qc_signing_bytes, verify_qc, verify_qc_strict, QcBuilder};
