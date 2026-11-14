//! Canonical vote signing bytes shared by consensus and state verification.

use crate::{
    codec::Encode,
    error::{IndraError, IndraResult},
    types::{primitives::Bytes32, vote::VoteStep},
};

/// Produce the canonical bytes a vote signature covers.
///
/// `block_hash` is the full `BlockHeaderVNext::block_hash()`, not `value_hash`.
pub fn vote_signing_bytes(
    height: u64,
    round: u32,
    step: VoteStep,
    block_hash: &Bytes32,
    validator_id: &Bytes32,
    snapshot_root: &Bytes32,
    chain_id: &str,
) -> IndraResult<Vec<u8>> {
    let chain_bytes = chain_id.as_bytes();
    let mut buf = indra_crypto::hash::domains::VOTE_SIGN.to_vec();
    let chain_len = u16::try_from(chain_bytes.len()).map_err(|_| IndraError::LengthExceeded {
        field: "chain_id",
        max: usize::from(u16::MAX),
        actual: chain_bytes.len(),
    })?;
    chain_len.encode(&mut buf);
    buf.extend_from_slice(chain_bytes);
    height.encode(&mut buf);
    round.encode(&mut buf);
    step.encode(&mut buf);
    block_hash.encode(&mut buf);
    validator_id.encode(&mut buf);
    snapshot_root.encode(&mut buf);
    Ok(buf)
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
            &Bytes32::from([0x5A; 32]),
            &Bytes32::from([0x5A; 32]),
            &Bytes32::from([0x5A; 32]),
            "indra-testnet-1",
        )
        .unwrap();
        let bytes_mainnet = vote_signing_bytes(
            1,
            0,
            VoteStep::Precommit,
            &Bytes32::from([0x5A; 32]),
            &Bytes32::ZERO,
            &Bytes32::from([0x5A; 32]),
            "indra-mainnet-1",
        )
        .unwrap();
        assert_ne!(
            bytes_testnet, bytes_mainnet,
            "Vote signing bytes must differ between chains"
        );
    }

    #[test]
    fn vote_signing_bytes_bind_block_hash() {
        let first = vote_signing_bytes(
            1,
            0,
            VoteStep::Precommit,
            &Bytes32::ZERO,
            &Bytes32::ZERO,
            &Bytes32::from([0x5A; 32]),
            "indra-testnet-1",
        )
        .unwrap();
        let second = vote_signing_bytes(
            1,
            0,
            VoteStep::Precommit,
            &Bytes32([1; 32]),
            &Bytes32::ZERO,
            &Bytes32::from([0x5A; 32]),
            "indra-testnet-1",
        )
        .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn vote_signing_bytes_bind_snapshot_root() {
        let first = vote_signing_bytes(
            1,
            0,
            VoteStep::Precommit,
            &Bytes32::ZERO,
            &Bytes32::ZERO,
            &Bytes32::from([1; 32]),
            "indra-testnet-1",
        )
        .unwrap();
        let second = vote_signing_bytes(
            1,
            0,
            VoteStep::Precommit,
            &Bytes32::ZERO,
            &Bytes32::ZERO,
            &Bytes32::from([2; 32]),
            "indra-testnet-1",
        )
        .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn vote_signing_bytes_accepts_u16_max_chain_id_and_rejects_larger() {
        let at_limit = vote_signing_bytes(
            1,
            0,
            VoteStep::Precommit,
            &Bytes32::ZERO,
            &Bytes32::ZERO,
            &Bytes32::ZERO,
            &"x".repeat(usize::from(u16::MAX)),
        );
        assert!(at_limit.is_ok());
        let too_long = vote_signing_bytes(
            1,
            0,
            VoteStep::Precommit,
            &Bytes32::ZERO,
            &Bytes32::ZERO,
            &Bytes32::ZERO,
            &"x".repeat(usize::from(u16::MAX) + 1),
        );
        assert_eq!(
            too_long.unwrap_err().to_string(),
            "field 'chain_id' length 65536 exceeds maximum 65535"
        );
    }
}
