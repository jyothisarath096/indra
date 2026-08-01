//! # indra-core — Serialisation Layer
//!
//! Canonical serialisation, all protocol data structures, and SSZ Merkleisation
//! for the INDRA v2 protocol.
//!
//! ## Five Invariants (must hold for every type in this crate)
//!
//! 1. **Deterministic** — same value → same bytes on all platforms.
//! 2. **Canonical**     — exactly one valid encoding per value.
//! 3. **Round-trip**    — `decode(encode(x)) == x` for all valid `x`.
//! 4. **Bounded**       — all types enforce explicit size limits at the type level.
//! 5. **No panics**     — all errors return `Result`. No `unwrap`, no `expect`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::indexing_slicing)]

pub mod codec;
pub mod error;
pub mod ssz;
pub mod types;

pub use error::{IndraError, IndraResult};
pub use types::{
    block::{BlockHeaderV1, BlockV1},
    checkpoint::CheckpointV1,
    crypto::{CommitmentV1, HybridPubKey, HybridSignature, PQVoteSig},
    epoch_record::EpochRecord,
    governance::GovernanceOpV2,
    primitives::{Bytes32, ProtocolVersion, VariableBytes},
    qc::QuorumCertificateV1,
    slashing::{SlashEvidenceEnvelopeV2, SlashEvidenceV1, SlashEvidenceV2},
    transaction::{InputV1, OutputV1, TransactionV1, TxId},
    vote::VoteV1,
    vrf_election::{VrfCommit, VrfElectionResult, VrfReveal},
};
