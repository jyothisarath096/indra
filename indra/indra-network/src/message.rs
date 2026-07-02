//! Wire protocol messages.
//!
//! ## Encoding
//!
//! Each message on the wire:
//!   [u32 total_length LE] [u8 message_type] [payload bytes]
//!
//! `total_length` includes the type byte but NOT the 4-byte length prefix itself.
//! Maximum message size: MAX_MSG_BYTES.

use indra_core::{
    codec::{ByteReader, Decode, Encode},
    types::{
        block::BlockV1,
        primitives::Bytes32,
        transaction::TransactionV1,
        vote::VoteV1,
        vrf_election::{VrfCommit, VrfReveal},
    },
};

use crate::error::{NetworkError, NetworkResult};

/// Maximum wire message size: 14 MB.
///
/// This must accommodate the current block/QC limits plus transport framing
/// overhead during sync responses and proposal propagation.
pub const MAX_MSG_BYTES: usize = 14_680_064;

/// Maximum number of peer addresses accepted in a single `PeerList`.
///
/// This prevents an attacker-controlled internal count prefix from causing
/// unbounded allocation before the payload has been validated.
pub const MAX_PEER_LIST_ENTRIES: usize = 256;

/// Maximum number of blocks accepted in a single `BlockResponse`.
///
/// This matches the node sync batch size and prevents unbounded allocation
/// from a malicious `BlockResponse` count prefix.
pub const MAX_BLOCK_RESPONSE_ENTRIES: usize = 50;

/// Message type discriminant bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// A complete block.
    Block = 0x01,
    /// A prevote or precommit.
    Vote = 0x02,
    /// A pending transaction.
    Tx = 0x03,
    /// A list of known peer addresses.
    PeerList = 0x04,
    /// Liveness ping.
    Ping = 0x05,
    /// Liveness pong.
    Pong = 0x06,
    /// Request blocks by height range.
    RequestBlocks = 0x07,
    /// Respond with a batch of blocks.
    BlockResponse = 0x08,
    /// Announce current chain tip.
    Status = 0x09,
    /// Request a specific proposal block by slot and hash.
    RequestProposal = 0x0A,
    /// Request the QC for a committed height.
    RequestQC = 0x0B,
    /// Respond with encoded QC bytes for a committed height.
    QCResponse = 0x0C,
    /// Commit to a validator's per-round VRF output.
    VrfCommit = 0x0D,
    /// Reveal a committed per-round VRF output.
    VrfReveal = 0x0E,
}

impl MessageType {
    /// Parse from a raw byte.
    pub fn from_byte(b: u8) -> NetworkResult<Self> {
        match b {
            0x01 => Ok(Self::Block),
            0x02 => Ok(Self::Vote),
            0x03 => Ok(Self::Tx),
            0x04 => Ok(Self::PeerList),
            0x05 => Ok(Self::Ping),
            0x06 => Ok(Self::Pong),
            0x07 => Ok(Self::RequestBlocks),
            0x08 => Ok(Self::BlockResponse),
            0x09 => Ok(Self::Status),
            0x0A => Ok(Self::RequestProposal),
            0x0B => Ok(Self::RequestQC),
            0x0C => Ok(Self::QCResponse),
            0x0D => Ok(Self::VrfCommit),
            0x0E => Ok(Self::VrfReveal),
            other => Err(NetworkError::UnexpectedMessage { got: other }),
        }
    }
}

/// A decoded network message.
#[derive(Debug, Clone)]
pub enum Message {
    /// A complete block for validation and inclusion.
    Block(BlockV1),
    /// A prevote or precommit vote.
    Vote(VoteV1),
    /// A pending transaction for the mempool.
    Tx(TransactionV1),
    /// A list of peer addresses (IP:port strings).
    PeerList(Vec<String>),
    /// Liveness ping with nonce.
    Ping(u64),
    /// Liveness pong matching a ping nonce.
    Pong(u64),
    /// Request blocks from `from_height` to `to_height` (inclusive).
    RequestBlocks {
        /// First height requested.
        from_height: u64,
        /// Last height requested (inclusive).
        to_height: u64,
    },
    /// Response containing blocks in ascending height order.
    BlockResponse {
        /// Blocks returned to the requester.
        blocks: Vec<BlockV1>,
        /// Lowest height this peer can currently serve, when known.
        lowest_available: Option<u64>,
        /// Highest height this peer can currently serve, when known.
        highest_available: Option<u64>,
    },
    /// Announce current chain tip.
    Status {
        /// The sender's current chain height.
        height: u64,
        /// The sender's current tip hash.
        tip_hash: Bytes32,
        /// The sender's current consensus round for the next height.
        round: u32,
    },
    /// Request a specific proposal block by slot and hash.
    RequestProposal {
        /// Proposal height.
        height: u64,
        /// Proposal round.
        round: u32,
        /// Proposal block hash.
        hash: Bytes32,
    },
    /// Request the QC that certifies the current committed tip height.
    RequestQC {
        /// The committed height whose QC is requested.
        height: u64,
    },
    /// Return encoded QC bytes for a committed height.
    QCResponse {
        /// The committed height whose QC is being returned.
        height: u64,
        /// Raw encoded QC bytes.
        qc_bytes: Vec<u8>,
    },
    /// Commit to a validator's per-round VRF output.
    VrfCommit(VrfCommit),
    /// Reveal a committed per-round VRF output.
    VrfReveal(VrfReveal),
}

impl Message {
    /// The message type discriminant.
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Block(_) => MessageType::Block,
            Self::Vote(_) => MessageType::Vote,
            Self::Tx(_) => MessageType::Tx,
            Self::PeerList(_) => MessageType::PeerList,
            Self::Ping(_) => MessageType::Ping,
            Self::Pong(_) => MessageType::Pong,
            Self::RequestBlocks { .. } => MessageType::RequestBlocks,
            Self::BlockResponse { .. } => MessageType::BlockResponse,
            Self::Status { .. } => MessageType::Status,
            Self::RequestProposal { .. } => MessageType::RequestProposal,
            Self::RequestQC { .. } => MessageType::RequestQC,
            Self::QCResponse { .. } => MessageType::QCResponse,
            Self::VrfCommit(_) => MessageType::VrfCommit,
            Self::VrfReveal(_) => MessageType::VrfReveal,
        }
    }

    /// Encode this message to wire format.
    ///
    /// Wire format: [u32 length LE] [u8 type] [payload]
    pub fn encode_wire(&self) -> NetworkResult<Vec<u8>> {
        let payload = self.encode_payload();
        let total_len = 1 + payload.len(); // type byte + payload

        if total_len > MAX_MSG_BYTES {
            return Err(NetworkError::MessageTooLarge {
                size: total_len,
                max: MAX_MSG_BYTES,
            });
        }

        let mut wire = Vec::with_capacity(4 + total_len);
        wire.extend_from_slice(&(total_len as u32).to_le_bytes());
        wire.push(self.message_type() as u8);
        wire.extend_from_slice(&payload);
        Ok(wire)
    }

    /// Decode a message from wire bytes (after the 4-byte length prefix).
    pub fn decode_wire(data: &[u8]) -> NetworkResult<Self> {
        let Some((&msg_type_byte, payload)) = data.split_first() else {
            return Err(NetworkError::DecodeFailed {
                reason: "empty message".to_string(),
            });
        };

        let msg_type = MessageType::from_byte(msg_type_byte)?;

        Self::decode_payload(msg_type, payload)
    }

    /// Encode the payload (without length prefix or type byte).
    fn encode_payload(&self) -> Vec<u8> {
        match self {
            Self::Block(b) => b.encode_to_vec(),
            Self::Vote(v) => v.encode_to_vec(),
            Self::Tx(tx) => tx.encode_to_vec(),
            Self::PeerList(peers) => {
                let mut buf = Vec::new();
                (peers.len() as u32).encode(&mut buf);
                for p in peers {
                    let bytes = p.as_bytes();
                    (bytes.len() as u16).encode(&mut buf);
                    buf.extend_from_slice(bytes);
                }
                buf
            }
            Self::Ping(nonce) => nonce.to_le_bytes().to_vec(),
            Self::Pong(nonce) => nonce.to_le_bytes().to_vec(),
            Self::RequestBlocks {
                from_height,
                to_height,
            } => {
                let mut buf = Vec::with_capacity(16);
                buf.extend_from_slice(&from_height.to_le_bytes());
                buf.extend_from_slice(&to_height.to_le_bytes());
                buf
            }
            Self::BlockResponse {
                blocks,
                lowest_available,
                highest_available,
            } => {
                let mut buf = Vec::new();
                (blocks.len() as u32).encode(&mut buf);
                for block in blocks {
                    let block_bytes = block.encode_to_vec();
                    (block_bytes.len() as u32).encode(&mut buf);
                    buf.extend_from_slice(&block_bytes);
                }
                // Optional trailing availability metadata. Older decoders ignore
                // these bytes after reading the block vector, so this is safe for
                // rolling upgrades while giving new requesters explicit pruned
                // range information.
                if lowest_available.is_some() || highest_available.is_some() {
                    let mut flags = 0u8;
                    if lowest_available.is_some() {
                        flags |= 0x01;
                    }
                    if highest_available.is_some() {
                        flags |= 0x02;
                    }
                    flags.encode(&mut buf);
                    if let Some(height) = lowest_available {
                        height.encode(&mut buf);
                    }
                    if let Some(height) = highest_available {
                        height.encode(&mut buf);
                    }
                }
                buf
            }
            Self::Status {
                height,
                tip_hash,
                round,
            } => {
                let mut buf = Vec::with_capacity(44);
                buf.extend_from_slice(&height.to_le_bytes());
                buf.extend_from_slice(&tip_hash.0);
                buf.extend_from_slice(&round.to_le_bytes());
                buf
            }
            Self::RequestProposal {
                height,
                round,
                hash,
            } => {
                let mut buf = Vec::with_capacity(44);
                buf.extend_from_slice(&height.to_le_bytes());
                buf.extend_from_slice(&round.to_le_bytes());
                buf.extend_from_slice(&hash.0);
                buf
            }
            Self::RequestQC { height } => height.to_le_bytes().to_vec(),
            Self::QCResponse { height, qc_bytes } => {
                let mut buf = Vec::with_capacity(12 + qc_bytes.len());
                buf.extend_from_slice(&height.to_le_bytes());
                buf.extend_from_slice(&(qc_bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(qc_bytes);
                buf
            }
            Self::VrfCommit(commit) => commit.encode_to_vec(),
            Self::VrfReveal(reveal) => reveal.encode_to_vec(),
        }
    }

    /// Decode a payload given its type.
    fn decode_payload(msg_type: MessageType, payload: &[u8]) -> NetworkResult<Self> {
        match msg_type {
            MessageType::Block => {
                let mut r = ByteReader::new(payload);
                let block = BlockV1::decode(&mut r).map_err(|e| NetworkError::DecodeFailed {
                    reason: e.to_string(),
                })?;
                Ok(Self::Block(block))
            }
            MessageType::Vote => {
                let mut r = ByteReader::new(payload);
                let vote = VoteV1::decode(&mut r).map_err(|e| NetworkError::DecodeFailed {
                    reason: e.to_string(),
                })?;
                Ok(Self::Vote(vote))
            }
            MessageType::Tx => {
                let mut r = ByteReader::new(payload);
                let tx = TransactionV1::decode(&mut r).map_err(|e| NetworkError::DecodeFailed {
                    reason: e.to_string(),
                })?;
                Ok(Self::Tx(tx))
            }
            MessageType::PeerList => {
                let count_bytes: [u8; 4] = payload
                    .get(..4)
                    .ok_or(NetworkError::DecodeFailed {
                        reason: "peer list too short".to_string(),
                    })?
                    .try_into()
                    .map_err(|_| NetworkError::DecodeFailed {
                        reason: "invalid peer list length prefix".to_string(),
                    })?;
                let count = u32::from_le_bytes(count_bytes) as usize;
                if count > MAX_PEER_LIST_ENTRIES {
                    return Err(NetworkError::DecodeFailed {
                        reason: format!(
                            "PeerList count {} exceeds maximum {}",
                            count, MAX_PEER_LIST_ENTRIES
                        ),
                    });
                }
                let mut peers = Vec::with_capacity(count);
                let mut offset = 4;
                for _ in 0..count {
                    let Some(len_bytes) = payload.get(offset..offset + 2) else {
                        return Err(NetworkError::DecodeFailed {
                            reason: "peer list entry length truncated".to_string(),
                        });
                    };
                    let len = u16::from_le_bytes(len_bytes.try_into().map_err(|_| {
                        NetworkError::DecodeFailed {
                            reason: "invalid peer list entry length".to_string(),
                        }
                    })?) as usize;
                    offset += 2;
                    let Some(peer_bytes) = payload.get(offset..offset + len) else {
                        return Err(NetworkError::DecodeFailed {
                            reason: "peer list entry truncated".to_string(),
                        });
                    };
                    let s = String::from_utf8_lossy(peer_bytes).to_string();
                    peers.push(s);
                    offset += len;
                }
                Ok(Self::PeerList(peers))
            }
            MessageType::Ping => {
                let nonce_bytes: [u8; 8] = payload
                    .get(..8)
                    .ok_or(NetworkError::DecodeFailed {
                        reason: "short ping".to_string(),
                    })?
                    .try_into()
                    .map_err(|_| NetworkError::DecodeFailed {
                        reason: "invalid ping payload".to_string(),
                    })?;
                let nonce = u64::from_le_bytes(nonce_bytes);
                Ok(Self::Ping(nonce))
            }
            MessageType::Pong => {
                let nonce_bytes: [u8; 8] = payload
                    .get(..8)
                    .ok_or(NetworkError::DecodeFailed {
                        reason: "short pong".to_string(),
                    })?
                    .try_into()
                    .map_err(|_| NetworkError::DecodeFailed {
                        reason: "invalid pong payload".to_string(),
                    })?;
                let nonce = u64::from_le_bytes(nonce_bytes);
                Ok(Self::Pong(nonce))
            }
            MessageType::RequestBlocks => {
                let from_height_bytes: [u8; 8] = payload
                    .get(..8)
                    .ok_or(NetworkError::DecodeFailed {
                        reason: "short get_blocks".to_string(),
                    })?
                    .try_into()
                    .map_err(|_| NetworkError::DecodeFailed {
                        reason: "invalid get_blocks from_height".to_string(),
                    })?;
                let to_height_bytes: [u8; 8] = payload
                    .get(8..16)
                    .ok_or(NetworkError::DecodeFailed {
                        reason: "short get_blocks".to_string(),
                    })?
                    .try_into()
                    .map_err(|_| NetworkError::DecodeFailed {
                        reason: "invalid get_blocks to_height".to_string(),
                    })?;
                let from_height = u64::from_le_bytes(from_height_bytes);
                let to_height = u64::from_le_bytes(to_height_bytes);
                Ok(Self::RequestBlocks {
                    from_height,
                    to_height,
                })
            }
            MessageType::BlockResponse => {
                let mut reader = ByteReader::new(payload);
                let count = u32::decode(&mut reader).map_err(|e| NetworkError::DecodeFailed {
                    reason: e.to_string(),
                })? as usize;
                if count > MAX_BLOCK_RESPONSE_ENTRIES {
                    return Err(NetworkError::DecodeFailed {
                        reason: format!(
                            "BlockResponse count {} exceeds maximum {}",
                            count, MAX_BLOCK_RESPONSE_ENTRIES
                        ),
                    });
                }
                let mut blocks = Vec::with_capacity(count);
                for _ in 0..count {
                    let len = u32::decode(&mut reader).map_err(|e| NetworkError::DecodeFailed {
                        reason: e.to_string(),
                    })? as usize;
                    let bytes = reader
                        .read_bytes(len)
                        .map_err(|e| NetworkError::DecodeFailed {
                            reason: e.to_string(),
                        })?;
                    let mut block_reader = ByteReader::new(bytes);
                    let block = BlockV1::decode(&mut block_reader).map_err(|e| {
                        NetworkError::DecodeFailed {
                            reason: e.to_string(),
                        }
                    })?;
                    blocks.push(block);
                }
                let mut lowest_available = None;
                let mut highest_available = None;
                if reader.remaining() > 0 {
                    let flags =
                        u8::decode(&mut reader).map_err(|e| NetworkError::DecodeFailed {
                            reason: e.to_string(),
                        })?;
                    if flags & 0x01 != 0 {
                        lowest_available = Some(u64::decode(&mut reader).map_err(|e| {
                            NetworkError::DecodeFailed {
                                reason: e.to_string(),
                            }
                        })?);
                    }
                    if flags & 0x02 != 0 {
                        highest_available = Some(u64::decode(&mut reader).map_err(|e| {
                            NetworkError::DecodeFailed {
                                reason: e.to_string(),
                            }
                        })?);
                    }
                    if flags & !0x03 != 0 || reader.remaining() != 0 {
                        return Err(NetworkError::DecodeFailed {
                            reason: "invalid BlockResponse availability metadata".to_string(),
                        });
                    }
                }
                Ok(Self::BlockResponse {
                    blocks,
                    lowest_available,
                    highest_available,
                })
            }
            MessageType::Status => {
                let height_bytes: [u8; 8] = payload
                    .get(..8)
                    .ok_or(NetworkError::DecodeFailed {
                        reason: "short status".to_string(),
                    })?
                    .try_into()
                    .map_err(|_| NetworkError::DecodeFailed {
                        reason: "invalid status height".to_string(),
                    })?;
                let tip: [u8; 32] = payload
                    .get(8..40)
                    .ok_or(NetworkError::DecodeFailed {
                        reason: "short status".to_string(),
                    })?
                    .try_into()
                    .map_err(|_| NetworkError::DecodeFailed {
                        reason: "invalid status tip hash".to_string(),
                    })?;
                let height = u64::from_le_bytes(height_bytes);
                let round = if payload.len() >= 44 {
                    let round_bytes: [u8; 4] =
                        payload[40..44]
                            .try_into()
                            .map_err(|_| NetworkError::DecodeFailed {
                                reason: "invalid status round".to_string(),
                            })?;
                    u32::from_le_bytes(round_bytes)
                } else {
                    0
                };
                Ok(Self::Status {
                    height,
                    tip_hash: Bytes32::from(tip),
                    round,
                })
            }
            MessageType::RequestProposal => {
                let height_bytes: [u8; 8] = payload
                    .get(..8)
                    .ok_or(NetworkError::DecodeFailed {
                        reason: "short request_proposal".to_string(),
                    })?
                    .try_into()
                    .map_err(|_| NetworkError::DecodeFailed {
                        reason: "invalid request_proposal height".to_string(),
                    })?;
                let round_bytes: [u8; 4] = payload
                    .get(8..12)
                    .ok_or(NetworkError::DecodeFailed {
                        reason: "short request_proposal".to_string(),
                    })?
                    .try_into()
                    .map_err(|_| NetworkError::DecodeFailed {
                        reason: "invalid request_proposal round".to_string(),
                    })?;
                let hash: [u8; 32] = payload
                    .get(12..44)
                    .ok_or(NetworkError::DecodeFailed {
                        reason: "short request_proposal".to_string(),
                    })?
                    .try_into()
                    .map_err(|_| NetworkError::DecodeFailed {
                        reason: "invalid request_proposal hash".to_string(),
                    })?;
                Ok(Self::RequestProposal {
                    height: u64::from_le_bytes(height_bytes),
                    round: u32::from_le_bytes(round_bytes),
                    hash: Bytes32::from(hash),
                })
            }
            MessageType::RequestQC => {
                let height_bytes: [u8; 8] = payload
                    .get(..8)
                    .ok_or(NetworkError::DecodeFailed {
                        reason: "short request_qc".to_string(),
                    })?
                    .try_into()
                    .map_err(|_| NetworkError::DecodeFailed {
                        reason: "invalid request_qc height".to_string(),
                    })?;
                Ok(Self::RequestQC {
                    height: u64::from_le_bytes(height_bytes),
                })
            }
            MessageType::QCResponse => {
                let height_bytes: [u8; 8] = payload
                    .get(..8)
                    .ok_or(NetworkError::DecodeFailed {
                        reason: "short qc_response".to_string(),
                    })?
                    .try_into()
                    .map_err(|_| NetworkError::DecodeFailed {
                        reason: "invalid qc_response height".to_string(),
                    })?;
                let len_bytes: [u8; 4] = payload
                    .get(8..12)
                    .ok_or(NetworkError::DecodeFailed {
                        reason: "short qc_response".to_string(),
                    })?
                    .try_into()
                    .map_err(|_| NetworkError::DecodeFailed {
                        reason: "invalid qc_response length".to_string(),
                    })?;
                let len = u32::from_le_bytes(len_bytes) as usize;
                let qc_bytes = payload
                    .get(12..12 + len)
                    .ok_or(NetworkError::DecodeFailed {
                        reason: "truncated qc_response bytes".to_string(),
                    })?
                    .to_vec();
                Ok(Self::QCResponse {
                    height: u64::from_le_bytes(height_bytes),
                    qc_bytes,
                })
            }
            MessageType::VrfCommit => {
                let mut r = ByteReader::new(payload);
                let commit = VrfCommit::decode(&mut r).map_err(|e| NetworkError::DecodeFailed {
                    reason: e.to_string(),
                })?;
                Ok(Self::VrfCommit(commit))
            }
            MessageType::VrfReveal => {
                let mut r = ByteReader::new(payload);
                let reveal = VrfReveal::decode(&mut r).map_err(|e| NetworkError::DecodeFailed {
                    reason: e.to_string(),
                })?;
                Ok(Self::VrfReveal(reveal))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::{
        block::{BlockHeaderV1, BlockV1, NO_POLC_ROUND},
        primitives::{Bytes32, ProtocolVersion, VariableBytes},
    };

    fn test_block(height: u64) -> BlockV1 {
        BlockV1 {
            header: BlockHeaderV1 {
                protocol_version: ProtocolVersion::CURRENT,
                height,
                prev_hash: Bytes32::ZERO,
                timestamp: 1_700_000_000 + height,
                state_root: Bytes32::from([0x11u8; 32]),
                validator_set_root: Bytes32::from([0x22u8; 32]),
                mempool_set_root: Bytes32::from([0x33u8; 32]),
                value_hash: Bytes32::from([0x44u8; 32]),
                base_fee: 1,
                proposer_round: 0,
                polc_round: NO_POLC_ROUND,
                election_result_hash: Some(Bytes32::ZERO),
                proposer_vrf_output: Bytes32::ZERO,
                proposer_vrf_proof: VariableBytes::from_slice(&[]).unwrap(),
                quorum_certificate: VariableBytes::from_slice(&[]).unwrap(),
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        }
    }

    #[test]
    fn ping_round_trip() {
        let msg = Message::Ping(0xDEADBEEF_CAFEBABE);
        let wire = msg.encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap(); // skip length prefix
        assert!(matches!(decoded, Message::Ping(0xDEADBEEF_CAFEBABE)));
    }

    #[test]
    fn pong_round_trip() {
        let msg = Message::Pong(42);
        let wire = msg.encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        assert!(matches!(decoded, Message::Pong(42)));
    }

    #[test]
    fn request_blocks_round_trip() {
        let msg = Message::RequestBlocks {
            from_height: 100,
            to_height: 200,
        };
        let wire = msg.encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        assert!(matches!(
            decoded,
            Message::RequestBlocks {
                from_height: 100,
                to_height: 200
            }
        ));
    }

    #[test]
    fn request_proposal_round_trip() {
        let hash = Bytes32::from([0x55u8; 32]);
        let msg = Message::RequestProposal {
            height: 7,
            round: 3,
            hash,
        };
        let wire = msg.encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        assert!(matches!(
            decoded,
            Message::RequestProposal { height: 7, round: 3, hash: decoded_hash } if decoded_hash == hash
        ));
    }

    #[test]
    fn qc_request_response_round_trip() {
        let request = Message::RequestQC { height: 42 };
        let request_wire = request.encode_wire().unwrap();
        let decoded_request = Message::decode_wire(&request_wire[4..]).unwrap();
        assert!(matches!(decoded_request, Message::RequestQC { height: 42 }));

        let response = Message::QCResponse {
            height: 42,
            qc_bytes: vec![1, 2, 3],
        };
        let response_wire = response.encode_wire().unwrap();
        let decoded_response = Message::decode_wire(&response_wire[4..]).unwrap();
        assert!(matches!(
            decoded_response,
            Message::QCResponse { height: 42, qc_bytes } if qc_bytes == vec![1, 2, 3]
        ));
    }

    #[test]
    fn status_round_trip() {
        let tip = Bytes32::from([0xABu8; 32]);
        let msg = Message::Status {
            height: 999,
            tip_hash: tip,
            round: 8,
        };
        let wire = msg.encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        match decoded {
            Message::Status {
                height,
                tip_hash,
                round,
            } => {
                assert_eq!(height, 999);
                assert_eq!(tip_hash, tip);
                assert_eq!(round, 8);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn peer_list_round_trip() {
        let peers = vec![
            "192.168.1.1:30303".to_string(),
            "10.0.0.1:30303".to_string(),
        ];
        let msg = Message::PeerList(peers.clone());
        let wire = msg.encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        match decoded {
            Message::PeerList(p) => assert_eq!(p, peers),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn peerlist_count_prefix_does_not_allocate_unbounded_vector() {
        let mut data = vec![MessageType::PeerList as u8];
        data.extend_from_slice(&u32::MAX.to_le_bytes());

        let err = Message::decode_wire(&data).unwrap_err();
        assert!(matches!(err, NetworkError::DecodeFailed { .. }));
    }

    #[test]
    fn peerlist_count_at_maximum_is_accepted() {
        let peers: Vec<String> = (0..MAX_PEER_LIST_ENTRIES)
            .map(|idx| format!("203.0.113.{}:30303", idx % 255))
            .collect();
        let wire = Message::PeerList(peers.clone()).encode_wire().unwrap();

        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        assert!(matches!(decoded, Message::PeerList(got) if got == peers));
    }

    #[test]
    fn peerlist_count_above_maximum_is_rejected() {
        let mut data = vec![MessageType::PeerList as u8];
        data.extend_from_slice(&((MAX_PEER_LIST_ENTRIES as u32) + 1).to_le_bytes());

        let err = Message::decode_wire(&data).unwrap_err();
        assert!(matches!(err, NetworkError::DecodeFailed { .. }));
    }

    #[test]
    fn block_response_count_prefix_does_not_allocate_unbounded_vector() {
        let mut data = vec![MessageType::BlockResponse as u8];
        u32::MAX.encode(&mut data);

        let err = Message::decode_wire(&data).unwrap_err();
        assert!(matches!(err, NetworkError::DecodeFailed { .. }));
    }

    #[test]
    fn block_response_count_at_maximum_is_accepted() {
        let blocks: Vec<BlockV1> = (0..MAX_BLOCK_RESPONSE_ENTRIES)
            .map(|idx| test_block(idx as u64 + 1))
            .collect();
        let wire = Message::BlockResponse {
            blocks: blocks.clone(),
            lowest_available: None,
            highest_available: None,
        }
        .encode_wire()
        .unwrap();

        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        assert!(matches!(
            decoded,
            Message::BlockResponse {
                blocks: got,
                lowest_available: None,
                highest_available: None,
            } if got == blocks
        ));
    }

    #[test]
    fn block_response_availability_metadata_round_trip() {
        let blocks = vec![test_block(1000)];
        let wire = Message::BlockResponse {
            blocks: blocks.clone(),
            lowest_available: Some(1000),
            highest_available: Some(2000),
        }
        .encode_wire()
        .unwrap();

        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        assert!(matches!(
            decoded,
            Message::BlockResponse {
                blocks: got,
                lowest_available: Some(1000),
                highest_available: Some(2000),
            } if got == blocks
        ));
    }

    #[test]
    fn block_response_count_above_maximum_is_rejected() {
        let mut data = vec![MessageType::BlockResponse as u8];
        ((MAX_BLOCK_RESPONSE_ENTRIES as u32) + 1).encode(&mut data);

        let err = Message::decode_wire(&data).unwrap_err();
        assert!(matches!(err, NetworkError::DecodeFailed { .. }));
    }

    #[test]
    fn unknown_type_errors() {
        let data = vec![0xFF, 0x00, 0x00];
        assert!(matches!(
            Message::decode_wire(&data),
            Err(NetworkError::UnexpectedMessage { got: 0xFF })
        ));
    }

    #[test]
    fn wire_format_has_length_prefix() {
        let msg = Message::Ping(1);
        let wire = msg.encode_wire().unwrap();
        let len = u32::from_le_bytes(wire[..4].try_into().unwrap()) as usize;
        assert_eq!(len + 4, wire.len());
    }
}
