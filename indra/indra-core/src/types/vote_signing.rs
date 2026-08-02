//! Canonical vote signing bytes shared by consensus and state verification.

use crate::{
    codec::Encode,
    types::{primitives::Bytes32, vote::VoteStep},
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
    election_result_hash: Option<&Bytes32>,
    chain_id: &str,
) -> Vec<u8> {
    let chain_bytes = chain_id.as_bytes();
    let mut buf = indra_crypto::hash::domains::VOTE_SIGN.to_vec();
    let chain_len = u16::try_from(chain_bytes.len()).expect("chain_id length must fit in u16");
    chain_len.encode(&mut buf);
    buf.extend_from_slice(chain_bytes);
    height.encode(&mut buf);
    round.encode(&mut buf);
    step.encode(&mut buf);
    block_hash.encode(&mut buf);
    validator_id.encode(&mut buf);
    if let Some(hash) = election_result_hash {
        1u8.encode(&mut buf);
        hash.encode(&mut buf);
    } else {
        0u8.encode(&mut buf);
    }
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
            None,
            "indra-testnet-1",
        );
        let bytes_mainnet = vote_signing_bytes(
            1,
            0,
            VoteStep::Precommit,
            &Bytes32::ZERO,
            &Bytes32::ZERO,
            None,
            "indra-mainnet-1",
        );
        assert_ne!(
            bytes_testnet, bytes_mainnet,
            "Vote signing bytes must differ between chains"
        );
    }

    #[test]
    fn vote_signing_bytes_include_election_result_presence_flag() {
        let without = vote_signing_bytes(
            1,
            0,
            VoteStep::Precommit,
            &Bytes32::ZERO,
            &Bytes32::ZERO,
            None,
            "indra-testnet-1",
        );
        let with = vote_signing_bytes(
            1,
            0,
            VoteStep::Precommit,
            &Bytes32::ZERO,
            &Bytes32::ZERO,
            Some(&Bytes32::ZERO),
            "indra-testnet-1",
        );
        assert_ne!(without, with);
    }
}
