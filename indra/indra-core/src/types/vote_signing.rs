//! Canonical vote signing bytes shared by consensus and state verification.

use crate::{
    codec::Encode,
    types::{primitives::Bytes32, vote::VoteStep},
};

/// Produce the canonical bytes a vote signature covers.
pub fn vote_signing_bytes(
    height: u64,
    round: u32,
    step: VoteStep,
    block_hash: &Bytes32,
    validator_id: &Bytes32,
) -> Vec<u8> {
    let mut buf = indra_crypto::hash::domains::VOTE_SIGN.to_vec();
    height.encode(&mut buf);
    round.encode(&mut buf);
    step.encode(&mut buf);
    block_hash.encode(&mut buf);
    validator_id.encode(&mut buf);
    buf
}
