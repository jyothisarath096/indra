//! Canonical vote signing bytes shared by consensus and state verification.

use crate::{
    codec::Encode,
    types::{
        primitives::{vote_chain_id_active, Bytes32},
        vote::VoteStep,
    },
};

/// Produce the canonical bytes a vote signature covers.
///
/// `block_hash` is the full `BlockHeaderV1::block_hash()`, not `value_hash`.
pub fn vote_signing_bytes(
    height: u64,
    round: u32,
    step: VoteStep,
    block_hash: &Bytes32,
    validator_id: &Bytes32,
    chain_id: &str,
) -> Vec<u8> {
    let chain_bytes = chain_id.as_bytes();
    let mut buf = indra_crypto::hash::domains::VOTE_SIGN.to_vec();
    if vote_chain_id_active(height) {
        let chain_len = u16::try_from(chain_bytes.len()).expect("chain_id length must fit in u16");
        chain_len.encode(&mut buf);
        buf.extend_from_slice(chain_bytes);
    }
    height.encode(&mut buf);
    round.encode(&mut buf);
    step.encode(&mut buf);
    block_hash.encode(&mut buf);
    validator_id.encode(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vote_signing_bytes_includes_chain_id() {
        let bytes_testnet = vote_signing_bytes(
            1,
            0,
            VoteStep::Precommit,
            &Bytes32::ZERO,
            &Bytes32::ZERO,
            "indra-testnet-1",
        );
        let bytes_mainnet = vote_signing_bytes(
            1,
            0,
            VoteStep::Precommit,
            &Bytes32::ZERO,
            &Bytes32::ZERO,
            "indra-mainnet-1",
        );
        assert_ne!(
            bytes_testnet, bytes_mainnet,
            "Vote signing bytes must differ between chains"
        );
    }
}
