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
        block::BlockProposalVNext,
        crypto::HybridSignature,
        governance::GovernanceOpV2,
        primitives::{validate_consensus_round, Bytes32},
        staking::{StakingOp, StakingOpBody},
        transaction::TransactionV1,
        vote::VoteV1,
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
    /// A pending staking operation.
    StakingOp = 0x11,
    /// A pending governance operation.
    GovernanceOp = 0x12,
    /// A pending transaction in the Dandelion stem phase.
    TxStem = 0x13,
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
            0x11 => Ok(Self::StakingOp),
            0x12 => Ok(Self::GovernanceOp),
            0x13 => Ok(Self::TxStem),
            other => Err(NetworkError::UnknownMessageType { got: other }),
        }
    }
}

/// One peer-discovery entry.
///
/// The address is always present. `validator_id` is present only when the
/// sender has authenticated that address; discovery-only candidates remain
/// explicitly unauthenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerListEntry {
    /// Peer socket address as `host:port`.
    pub addr: String,
    /// Authenticated validator identity for this address, when known.
    pub validator_id: Option<Bytes32>,
}

impl PeerListEntry {
    /// Construct an address-only entry.
    pub fn address_only(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            validator_id: None,
        }
    }

    /// Construct an entry with an authenticated validator identity.
    pub fn with_validator(addr: impl Into<String>, validator_id: Bytes32) -> Self {
        Self {
            addr: addr.into(),
            validator_id: Some(validator_id),
        }
    }
}

/// A decoded network message.
#[derive(Debug, Clone)]
pub enum Message {
    /// A complete block for validation and inclusion.
    Block(Box<BlockProposalVNext>),
    /// A prevote or precommit vote.
    Vote(VoteV1),
    /// A pending transaction for the mempool.
    Tx(TransactionV1),
    /// A pending transaction on one Dandelion stem hop.
    ///
    /// The payload is byte-identical to [`Message::Tx`]. Only the outer message
    /// discriminant differs; the signed transaction and its consensus ID do not.
    TxStem(TransactionV1),
    /// A pending staking operation for the staking mempool.
    StakingOp(StakingOp),
    /// A pending governance operation for the governance mempool.
    GovernanceOp(GovernanceOpV2),
    /// A list of peer addresses, optionally annotated with authenticated
    /// validator identities.
    PeerList(Vec<PeerListEntry>),
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
        blocks: Vec<BlockProposalVNext>,
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
}

fn require_exact_hybrid_signature(signature: &HybridSignature) -> NetworkResult<()> {
    let classical_len = signature.classical_sig.len();
    if classical_len != indra_crypto::CLASSICAL_SIG_BYTES {
        return Err(NetworkError::DecodeFailed {
            reason: format!(
                "hybrid classical signature must be exactly {} bytes, got {classical_len}",
                indra_crypto::CLASSICAL_SIG_BYTES
            ),
        });
    }
    let pq_len = signature.pq_sig.len();
    if pq_len != indra_crypto::PQ_SIG_BYTES {
        return Err(NetworkError::DecodeFailed {
            reason: format!(
                "hybrid PQ signature must be exactly {} bytes, got {pq_len}",
                indra_crypto::PQ_SIG_BYTES
            ),
        });
    }
    Ok(())
}

fn require_exact_staking_signatures(operation: &StakingOp) -> NetworkResult<()> {
    require_exact_hybrid_signature(&operation.signature)?;
    match &operation.body {
        StakingOpBody::RegisterValidator { cold_signature, .. } => {
            require_exact_hybrid_signature(cold_signature)
        }
        StakingOpBody::RotateValidatorColdKey {
            new_cold_signature: Some(signature),
            ..
        } => require_exact_hybrid_signature(signature),
        _ => Ok(()),
    }
}

fn require_exact_proposal_signatures(proposal: &BlockProposalVNext) -> NetworkResult<()> {
    require_exact_hybrid_signature(&proposal.proposer_authorization)?;
    for transaction in &proposal.block.transactions {
        require_exact_hybrid_signature(&transaction.signature)?;
    }
    for operation in &proposal.block.staking_ops {
        require_exact_staking_signatures(operation)?;
    }
    for operation in &proposal.block.governance_ops {
        require_exact_hybrid_signature(&operation.signature)?;
    }
    Ok(())
}

impl Message {
    /// The message type discriminant.
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Block(_) => MessageType::Block,
            Self::Vote(_) => MessageType::Vote,
            Self::Tx(_) => MessageType::Tx,
            Self::TxStem(_) => MessageType::TxStem,
            Self::StakingOp(_) => MessageType::StakingOp,
            Self::GovernanceOp(_) => MessageType::GovernanceOp,
            Self::PeerList(_) => MessageType::PeerList,
            Self::Ping(_) => MessageType::Ping,
            Self::Pong(_) => MessageType::Pong,
            Self::RequestBlocks { .. } => MessageType::RequestBlocks,
            Self::BlockResponse { .. } => MessageType::BlockResponse,
            Self::Status { .. } => MessageType::Status,
            Self::RequestProposal { .. } => MessageType::RequestProposal,
            Self::RequestQC { .. } => MessageType::RequestQC,
            Self::QCResponse { .. } => MessageType::QCResponse,
        }
    }

    /// Encode this message to wire format.
    ///
    /// Wire format: [u32 length LE] [u8 type] [payload]
    pub fn encode_wire(&self) -> NetworkResult<Vec<u8>> {
        if let Self::Status { round, .. } | Self::RequestProposal { round, .. } = self {
            validate_consensus_round(*round).map_err(|error| NetworkError::DecodeFailed {
                reason: error.to_string(),
            })?;
        }
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

    /// Decode one complete inner wire object, including its 4-byte length prefix.
    ///
    /// The declared length covers the message-type byte plus payload, but not
    /// the length prefix itself. The authenticated transport frame must contain
    /// exactly that one declared object.
    pub fn decode_framed_wire(data: &[u8]) -> NetworkResult<Self> {
        let length_bytes: [u8; 4] = data
            .get(..4)
            .ok_or(NetworkError::DecodeFailed {
                reason: "message length prefix truncated".to_string(),
            })?
            .try_into()
            .map_err(|_| NetworkError::DecodeFailed {
                reason: "invalid message length prefix".to_string(),
            })?;
        let declared_len = u32::from_le_bytes(length_bytes) as usize;
        if declared_len > MAX_MSG_BYTES {
            return Err(NetworkError::MessageTooLarge {
                size: declared_len,
                max: MAX_MSG_BYTES,
            });
        }
        let actual_len = data.len() - 4;
        if declared_len != actual_len {
            return Err(NetworkError::DecodeFailed {
                reason: format!(
                    "message length mismatch: declared {declared_len} bytes, frame contains {actual_len}"
                ),
            });
        }
        Self::decode_wire(&data[4..])
    }

    /// Encode the payload (without length prefix or type byte).
    fn encode_payload(&self) -> Vec<u8> {
        match self {
            Self::Block(b) => b.encode_to_vec(),
            Self::Vote(v) => v.encode_to_vec(),
            Self::Tx(tx) | Self::TxStem(tx) => tx.encode_to_vec(),
            Self::StakingOp(op) => op.encode_to_vec(),
            Self::GovernanceOp(op) => op.encode_to_vec(),
            Self::PeerList(peers) => {
                let mut buf = Vec::new();
                (peers.len() as u32).encode(&mut buf);
                for p in peers {
                    let bytes = p.addr.as_bytes();
                    (bytes.len() as u16).encode(&mut buf);
                    buf.extend_from_slice(bytes);
                    p.validator_id.is_some().encode(&mut buf);
                    if let Some(validator_id) = p.validator_id {
                        validator_id.encode(&mut buf);
                    }
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
        }
    }

    /// Decode a payload given its type.
    fn decode_payload(msg_type: MessageType, payload: &[u8]) -> NetworkResult<Self> {
        match msg_type {
            MessageType::Block => {
                let block = BlockProposalVNext::decode_exact(payload).map_err(|e| {
                    NetworkError::DecodeFailed {
                        reason: e.to_string(),
                    }
                })?;
                require_exact_proposal_signatures(&block)?;
                Ok(Self::Block(Box::new(block)))
            }
            MessageType::Vote => {
                let vote =
                    VoteV1::decode_exact(payload).map_err(|e| NetworkError::DecodeFailed {
                        reason: e.to_string(),
                    })?;
                require_exact_hybrid_signature(&vote.signature)?;
                Ok(Self::Vote(vote))
            }
            MessageType::Tx => {
                let tx = TransactionV1::decode_exact(payload).map_err(|e| {
                    NetworkError::DecodeFailed {
                        reason: e.to_string(),
                    }
                })?;
                require_exact_hybrid_signature(&tx.signature)?;
                Ok(Self::Tx(tx))
            }
            MessageType::TxStem => {
                let tx = TransactionV1::decode_exact(payload).map_err(|e| {
                    NetworkError::DecodeFailed {
                        reason: e.to_string(),
                    }
                })?;
                require_exact_hybrid_signature(&tx.signature)?;
                Ok(Self::TxStem(tx))
            }
            MessageType::StakingOp => {
                let op =
                    StakingOp::decode_exact(payload).map_err(|e| NetworkError::DecodeFailed {
                        reason: e.to_string(),
                    })?;
                require_exact_staking_signatures(&op)?;
                Ok(Self::StakingOp(op))
            }
            MessageType::GovernanceOp => {
                let op = GovernanceOpV2::decode_exact(payload).map_err(|e| {
                    NetworkError::DecodeFailed {
                        reason: e.to_string(),
                    }
                })?;
                require_exact_hybrid_signature(&op.signature)?;
                Ok(Self::GovernanceOp(op))
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
                    let s = std::str::from_utf8(peer_bytes)
                        .map_err(|_| NetworkError::DecodeFailed {
                            reason: "peer list address is not valid UTF-8".to_string(),
                        })?
                        .to_owned();
                    offset += len;
                    let Some(identity_flag) = payload.get(offset) else {
                        return Err(NetworkError::DecodeFailed {
                            reason: "peer list identity marker truncated".to_string(),
                        });
                    };
                    offset += 1;
                    let validator_id = match identity_flag {
                        0 => None,
                        1 => {
                            let Some(id_bytes) = payload.get(offset..offset + 32) else {
                                return Err(NetworkError::DecodeFailed {
                                    reason: "peer list validator identity truncated".to_string(),
                                });
                            };
                            let mut id = [0u8; 32];
                            id.copy_from_slice(id_bytes);
                            offset += 32;
                            Some(Bytes32::from(id))
                        }
                        byte => {
                            return Err(NetworkError::DecodeFailed {
                                reason: format!("invalid peer list identity marker {byte}"),
                            });
                        }
                    };
                    peers.push(PeerListEntry {
                        addr: s,
                        validator_id,
                    });
                }
                if offset != payload.len() {
                    return Err(NetworkError::DecodeFailed {
                        reason: "peer list contains trailing bytes".to_string(),
                    });
                }
                Ok(Self::PeerList(peers))
            }
            MessageType::Ping => {
                if payload.len() != 8 {
                    return Err(NetworkError::DecodeFailed {
                        reason: "ping payload must be exactly 8 bytes".to_string(),
                    });
                }
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
                if payload.len() != 8 {
                    return Err(NetworkError::DecodeFailed {
                        reason: "pong payload must be exactly 8 bytes".to_string(),
                    });
                }
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
                if payload.len() != 16 {
                    return Err(NetworkError::DecodeFailed {
                        reason: "request_blocks payload must be exactly 16 bytes".to_string(),
                    });
                }
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
                    let block = BlockProposalVNext::decode_exact(bytes).map_err(|e| {
                        NetworkError::DecodeFailed {
                            reason: e.to_string(),
                        }
                    })?;
                    require_exact_proposal_signatures(&block)?;
                    blocks.push(block);
                }
                let flags = u8::decode(&mut reader).map_err(|e| NetworkError::DecodeFailed {
                    reason: e.to_string(),
                })?;
                let lowest_available = if flags & 0x01 != 0 {
                    Some(
                        u64::decode(&mut reader).map_err(|e| NetworkError::DecodeFailed {
                            reason: e.to_string(),
                        })?,
                    )
                } else {
                    None
                };
                let highest_available = if flags & 0x02 != 0 {
                    Some(
                        u64::decode(&mut reader).map_err(|e| NetworkError::DecodeFailed {
                            reason: e.to_string(),
                        })?,
                    )
                } else {
                    None
                };
                if flags & !0x03 != 0 || reader.remaining() != 0 {
                    return Err(NetworkError::DecodeFailed {
                        reason: "invalid BlockResponse availability metadata".to_string(),
                    });
                }
                Ok(Self::BlockResponse {
                    blocks,
                    lowest_available,
                    highest_available,
                })
            }
            MessageType::Status => {
                if payload.len() != 44 {
                    return Err(NetworkError::DecodeFailed {
                        reason: "status payload must be exactly 44 bytes".to_string(),
                    });
                }
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
                let round_bytes: [u8; 4] =
                    payload[40..44]
                        .try_into()
                        .map_err(|_| NetworkError::DecodeFailed {
                            reason: "invalid status round".to_string(),
                        })?;
                let round =
                    validate_consensus_round(u32::from_le_bytes(round_bytes)).map_err(|error| {
                        NetworkError::DecodeFailed {
                            reason: error.to_string(),
                        }
                    })?;
                Ok(Self::Status {
                    height,
                    tip_hash: Bytes32::from(tip),
                    round,
                })
            }
            MessageType::RequestProposal => {
                if payload.len() != 44 {
                    return Err(NetworkError::DecodeFailed {
                        reason: "request_proposal payload must be exactly 44 bytes".to_string(),
                    });
                }
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
                let round =
                    validate_consensus_round(u32::from_le_bytes(round_bytes)).map_err(|error| {
                        NetworkError::DecodeFailed {
                            reason: error.to_string(),
                        }
                    })?;
                Ok(Self::RequestProposal {
                    height: u64::from_le_bytes(height_bytes),
                    round,
                    hash: Bytes32::from(hash),
                })
            }
            MessageType::RequestQC => {
                if payload.len() != 8 {
                    return Err(NetworkError::DecodeFailed {
                        reason: "request_qc payload must be exactly 8 bytes".to_string(),
                    });
                }
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
                let expected_len = 12usize.checked_add(len).ok_or(NetworkError::DecodeFailed {
                    reason: "qc_response length overflow".to_string(),
                })?;
                if payload.len() != expected_len {
                    return Err(NetworkError::DecodeFailed {
                        reason: format!(
                            "qc_response payload length mismatch: declared {len} QC bytes, payload contains {}",
                            payload.len().saturating_sub(12)
                        ),
                    });
                }
                let qc_bytes = payload
                    .get(12..expected_len)
                    .ok_or(NetworkError::DecodeFailed {
                        reason: "truncated qc_response bytes".to_string(),
                    })?
                    .to_vec();
                Ok(Self::QCResponse {
                    height: u64::from_le_bytes(height_bytes),
                    qc_bytes,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::{
        block::{BlockHeaderVNext, BlockVNext, SortitionClaimV1, VrfSuiteV1},
        governance::{GovernanceActionType, GovernanceOpV2, GovernancePayload},
        primitives::{
            Bytes32, Bytes64, ProtocolVersion, VariableBytes, MAX_CLASSICAL_SIG_BYTES,
            MAX_PQ_SIG_BYTES, MAX_STANDARD_VRF_OUTPUT_BYTES, MAX_STANDARD_VRF_PROOF_BYTES,
            TRANSACTION_PROTOCOL_VERSION,
        },
        staking::{StakingOp, StakingOpBody},
        transaction::{InputV1, OutputV1, TransactionV1},
        vote::{VoteStep, VoteV1},
    };

    fn test_block(height: u64) -> BlockVNext {
        BlockVNext {
            header: BlockHeaderVNext {
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
                polc_round: None,
                proposer_id: Bytes32::from([0x45; 32]),
                vrf_suite: VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
                election_seed: Bytes64([0x46; 64]),
                proposer_vrf_output: VariableBytes::<MAX_STANDARD_VRF_OUTPUT_BYTES>::from_slice(
                    &[0x47; 64],
                )
                .unwrap(),
                proposer_vrf_proof: VariableBytes::<MAX_STANDARD_VRF_PROOF_BYTES>::from_slice(
                    &[0x48; 80],
                )
                .unwrap(),
                value_entropy: indra_core::types::block::ProposalEntropyV1 {
                    origin_proposer_id: Bytes32::from([0x45; 32]),
                    origin_round: 0,
                    vrf_output: VariableBytes::from_slice(&[0x47; 64]).unwrap(),
                    vrf_proof: VariableBytes::from_slice(&[0x48; 80]).unwrap(),
                },
                sortition_claim: SortitionClaimV1::PraosThreshold,
                proposer_priority: Bytes64([0x49; 64]),
                quorum_certificate: VariableBytes::from_slice(&[]).unwrap(),
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        }
    }

    fn test_proposal(height: u64) -> indra_core::types::block::BlockProposalVNext {
        indra_core::types::block::BlockProposalVNext {
            block: test_block(height),
            proposer_authorization: dummy_sig(),
        }
    }

    fn dummy_sig() -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(&[0xAA; 64])
                .unwrap(),
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&[0xBB; 4627]).unwrap(),
        }
    }

    fn test_staking_op() -> StakingOp {
        StakingOp {
            body: StakingOpBody::ClaimRewards {
                validator_id: Bytes32::from([0x31; 32]),
                delegator_pubkey: indra_core::types::crypto::HybridPubKey {
                    classical_pk: Bytes32::from([0x32; 32]),
                    pq_pk: VariableBytes::from_slice(&[0x33; 32]).unwrap(),
                },
                cold_authorization: None,
            },
            nonce: 7,
            signature: dummy_sig(),
        }
    }

    fn test_governance_op() -> GovernanceOpV2 {
        GovernanceOpV2 {
            action_type: GovernanceActionType::CommitVote,
            signer_id: Bytes32::from([0x41; 32]),
            nonce: 9,
            payload: GovernancePayload::Commit {
                proposal_id: Bytes32::from([0x42; 32]),
                commit_hash: Bytes32::from([0x43; 32]),
                cold_authorization: None,
            },
            signature: dummy_sig(),
        }
    }

    fn test_transaction() -> TransactionV1 {
        TransactionV1 {
            version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
            signature_module_id: 1,
            inputs: vec![InputV1 {
                utxo_id: Bytes32::from([0x51; 32]),
            }],
            outputs: vec![OutputV1 {
                value_spark: 100_000,
                owner_pubkey: indra_core::types::crypto::HybridPubKey {
                    classical_pk: Bytes32::from([0x52; 32]),
                    pq_pk: VariableBytes::from_slice(&[0x53; 2592]).unwrap(),
                },
                lock_height: 0,
            }],
            fee_amount: 10_000,
            signature: dummy_sig(),
        }
    }

    fn signature_bearing_messages(signature: HybridSignature) -> Vec<Message> {
        let mut proposal = test_proposal(11);
        proposal.proposer_authorization = signature.clone();

        let mut tx = test_transaction();
        tx.signature = signature.clone();
        let mut staking = test_staking_op();
        staking.signature = signature.clone();
        let mut governance = test_governance_op();
        governance.signature = signature.clone();

        vec![
            Message::Block(Box::new(proposal.clone())),
            Message::BlockResponse {
                blocks: vec![proposal],
                lowest_available: None,
                highest_available: None,
            },
            Message::Vote(VoteV1 {
                height: 11,
                round: 0,
                step: VoteStep::Precommit,
                block_hash: Bytes32::from([0x61; 32]),
                validator_id: Bytes32::from([0x62; 32]),
                snapshot_root: Bytes32::from([0x63; 32]),
                signature: signature.clone(),
            }),
            Message::Tx(tx.clone()),
            Message::TxStem(tx),
            Message::StakingOp(staking),
            Message::GovernanceOp(governance),
        ]
    }

    #[test]
    fn tx_stem_changes_only_the_outer_discriminant() {
        let tx = test_transaction();
        let fluff = Message::Tx(tx.clone()).encode_wire().unwrap();
        let stem = Message::TxStem(tx.clone()).encode_wire().unwrap();
        assert_eq!(fluff[0..4], stem[0..4]);
        assert_ne!(fluff[4], stem[4]);
        assert_eq!(fluff[5..], stem[5..]);
        assert!(matches!(
            Message::decode_framed_wire(&stem).unwrap(),
            Message::TxStem(decoded) if decoded == tx
        ));
    }

    #[test]
    fn all_hybrid_signature_message_decoders_require_exact_component_lengths() {
        for message in signature_bearing_messages(dummy_sig()) {
            assert!(Message::decode_framed_wire(&message.encode_wire().unwrap()).is_ok());
        }

        for malformed in [
            HybridSignature {
                classical_sig: VariableBytes::from_slice(&[0xAA; 63]).unwrap(),
                pq_sig: VariableBytes::from_slice(&[0xBB; indra_crypto::PQ_SIG_BYTES]).unwrap(),
            },
            HybridSignature {
                classical_sig: VariableBytes::from_slice(&[]).unwrap(),
                pq_sig: VariableBytes::from_slice(&[0xBB; indra_crypto::PQ_SIG_BYTES]).unwrap(),
            },
            HybridSignature {
                classical_sig: VariableBytes::from_slice(
                    &[0xAA; indra_crypto::CLASSICAL_SIG_BYTES],
                )
                .unwrap(),
                pq_sig: VariableBytes::from_slice(&[0xBB; indra_crypto::PQ_SIG_BYTES - 1]).unwrap(),
            },
            HybridSignature {
                classical_sig: VariableBytes::from_slice(
                    &[0xAA; indra_crypto::CLASSICAL_SIG_BYTES],
                )
                .unwrap(),
                pq_sig: VariableBytes::from_slice(&[]).unwrap(),
            },
        ] {
            for message in signature_bearing_messages(malformed.clone()) {
                let wire = message.encode_wire().unwrap();
                assert_eq!(
                    u32::from_le_bytes(wire[..4].try_into().unwrap()) as usize,
                    wire.len() - 4
                );
                assert!(Message::decode_framed_wire(&wire).is_err());
            }
        }

        let vote = signature_bearing_messages(dummy_sig())
            .into_iter()
            .find(|message| matches!(message, Message::Vote(_)))
            .unwrap();
        let mut truncated = vote.encode_wire().unwrap();
        truncated.pop();
        let declared_len = (truncated.len() - 4) as u32;
        truncated[..4].copy_from_slice(&declared_len.to_le_bytes());
        assert!(Message::decode_framed_wire(&truncated).is_err());
    }

    #[test]
    fn ping_round_trip() {
        let msg = Message::Ping(0xDEADBEEF_CAFEBABE);
        let wire = msg.encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap(); // skip length prefix
        assert!(matches!(decoded, Message::Ping(0xDEADBEEF_CAFEBABE)));
    }

    #[test]
    fn staking_op_round_trip() {
        let op = test_staking_op();
        let wire = Message::StakingOp(op.clone()).encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        assert!(matches!(decoded, Message::StakingOp(got) if got == op));
    }

    #[test]
    fn staking_op_wire_rejects_trailing_bytes() {
        let mut payload = test_staking_op().encode_to_vec();
        payload.extend_from_slice(&[0xAA, 0x55]);
        let mut wire = vec![MessageType::StakingOp as u8];
        wire.extend_from_slice(&payload);
        assert!(matches!(
            Message::decode_wire(&wire),
            Err(NetworkError::DecodeFailed { .. })
        ));
    }

    #[test]
    fn governance_op_round_trip() {
        let op = test_governance_op();
        let wire = Message::GovernanceOp(op.clone()).encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        assert!(matches!(decoded, Message::GovernanceOp(got) if got == op));
    }

    #[test]
    fn governance_op_wire_rejects_trailing_bytes() {
        let op = test_governance_op();
        let mut payload = op.encode_to_vec();
        payload.extend_from_slice(&[0xAA, 0x55]);
        let mut wire = vec![MessageType::GovernanceOp as u8];
        wire.extend_from_slice(&payload);
        assert!(matches!(
            Message::decode_wire(&wire),
            Err(NetworkError::DecodeFailed { .. })
        ));
    }

    #[test]
    fn transaction_wire_rejects_trailing_bytes() {
        let mut payload = test_transaction().encode_to_vec();
        payload.extend_from_slice(&[0xAA, 0x55]);
        let mut wire = vec![MessageType::Tx as u8];
        wire.extend_from_slice(&payload);
        assert!(matches!(
            Message::decode_wire(&wire),
            Err(NetworkError::DecodeFailed { .. })
        ));
    }

    #[test]
    fn unknown_message_type_is_skippable_for_rolling_upgrade() {
        let err = Message::decode_wire(&[0xFE]).unwrap_err();
        assert!(matches!(
            err,
            NetworkError::UnknownMessageType { got: 0xFE }
        ));
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
    fn block_wire_decoding_rejects_trailing_bytes() {
        let mut encoded = Message::Block(Box::new(test_proposal(1))).encode_wire().unwrap()[4..].to_vec();
        encoded.push(0xA5);
        assert!(Message::decode_wire(&encoded).is_err());
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
    fn status_and_proposal_request_reject_out_of_domain_rounds() {
        for round in [
            indra_core::types::primitives::MAX_ROUNDS_PER_HEIGHT,
            indra_core::types::primitives::MAX_ROUNDS_PER_HEIGHT + 1,
            u32::MAX,
        ] {
            let mut status = Message::Status {
                height: 1,
                tip_hash: Bytes32::ZERO,
                round: 0,
            }
            .encode_wire()
            .unwrap();
            status[4 + 1 + 40..4 + 1 + 44].copy_from_slice(&round.to_le_bytes());
            assert!(Message::decode_wire(&status[4..]).is_err());

            let mut request = Message::RequestProposal {
                height: 1,
                round: 0,
                hash: Bytes32::ZERO,
            }
            .encode_wire()
            .unwrap();
            request[4 + 1 + 8..4 + 1 + 12].copy_from_slice(&round.to_le_bytes());
            assert!(Message::decode_wire(&request[4..]).is_err());
        }

        let status = Message::Status {
            height: 1,
            tip_hash: Bytes32::ZERO,
            round: 0,
        }
        .encode_wire()
        .unwrap();
        assert!(Message::decode_wire(&status[4..status.len() - 4]).is_err());
    }

    #[test]
    fn peer_list_round_trip() {
        let peers = vec![
            PeerListEntry::address_only("192.168.1.1:30303"),
            PeerListEntry::address_only("10.0.0.1:30303"),
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
        let peers: Vec<PeerListEntry> = (0..MAX_PEER_LIST_ENTRIES)
            .map(|idx| PeerListEntry::address_only(format!("203.0.113.{}:30303", idx % 255)))
            .collect();
        let wire = Message::PeerList(peers.clone()).encode_wire().unwrap();

        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        assert!(matches!(decoded, Message::PeerList(got) if got == peers));
    }

    #[test]
    fn peer_list_canonical_identity_marker_round_trip() {
        let validator_id = Bytes32::from([0x42; 32]);
        let peers = vec![
            PeerListEntry::with_validator("203.0.113.1:30303", validator_id),
            PeerListEntry::address_only("203.0.113.2:30303"),
        ];
        let wire = Message::PeerList(peers.clone()).encode_wire().unwrap();

        let decoded = Message::decode_wire(&wire[4..]).unwrap();

        assert!(matches!(decoded, Message::PeerList(got) if got == peers));
    }

    fn framed_peer_list_with_raw_address(address: &[u8]) -> Vec<u8> {
        let mut payload = vec![MessageType::PeerList as u8];
        1u32.encode(&mut payload);
        (address.len() as u16).encode(&mut payload);
        payload.extend_from_slice(address);
        0u8.encode(&mut payload);

        let mut framed = Vec::with_capacity(4 + payload.len());
        (payload.len() as u32).encode(&mut framed);
        framed.extend_from_slice(&payload);
        framed
    }

    #[test]
    fn peer_list_address_utf8_is_strict_and_canonical() {
        for address in [
            b"validator.example:27656".as_slice(),
            "例え.テスト:27656".as_bytes(),
        ] {
            let framed = framed_peer_list_with_raw_address(address);
            let decoded = Message::decode_framed_wire(&framed).unwrap();
            assert_eq!(decoded.encode_wire().unwrap(), framed);
        }

        for malformed in [
            &[0xFF][..],
            &[0xFE][..],
            &[0xE2, 0x82][..],
            &[0xC0, 0xAF][..],
            &[0xF5, 0x80, 0x80, 0x80][..],
        ] {
            let framed = framed_peer_list_with_raw_address(malformed);
            assert!(matches!(
                Message::decode_framed_wire(&framed),
                Err(NetworkError::DecodeFailed { .. })
            ));
        }
    }

    #[test]
    fn address_only_peer_list_without_identity_markers_is_rejected() {
        let peers = ["203.0.113.10:30303", "203.0.113.11:30303"];
        let mut data = vec![MessageType::PeerList as u8];
        (peers.len() as u32).encode(&mut data);
        for peer in peers {
            let bytes = peer.as_bytes();
            (bytes.len() as u16).encode(&mut data);
            data.extend_from_slice(bytes);
        }

        assert!(matches!(
            Message::decode_wire(&data),
            Err(NetworkError::DecodeFailed { .. })
        ));
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
        let blocks: Vec<indra_core::types::block::BlockProposalVNext> = (0
            ..MAX_BLOCK_RESPONSE_ENTRIES)
            .map(|idx| test_proposal(idx as u64 + 1))
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
        let blocks = vec![test_proposal(1000)];
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
    fn block_response_rejects_missing_mandatory_availability_flags() {
        let mut old_format_truncated = vec![MessageType::BlockResponse as u8];
        0u32.encode(&mut old_format_truncated);
        assert!(Message::decode_wire(&old_format_truncated).is_err());
    }

    #[test]
    fn block_response_count_above_maximum_is_rejected() {
        let mut data = vec![MessageType::BlockResponse as u8];
        ((MAX_BLOCK_RESPONSE_ENTRIES as u32) + 1).encode(&mut data);

        let err = Message::decode_wire(&data).unwrap_err();
        assert!(matches!(err, NetworkError::DecodeFailed { .. }));
    }

    #[test]
    fn unknown_type_is_reported_as_skippable() {
        let data = vec![0xFF, 0x00, 0x00];
        assert!(matches!(
            Message::decode_wire(&data),
            Err(NetworkError::UnknownMessageType { got: 0xFF })
        ));
    }

    #[test]
    fn wire_format_has_length_prefix() {
        let msg = Message::Ping(1);
        let wire = msg.encode_wire().unwrap();
        let len = u32::from_le_bytes(wire[..4].try_into().unwrap()) as usize;
        assert_eq!(len + 4, wire.len());
    }

    #[test]
    fn framed_decoder_enforces_declared_inner_length() {
        let canonical = Message::Ping(1).encode_wire().unwrap();
        assert!(matches!(
            Message::decode_framed_wire(&canonical),
            Ok(Message::Ping(1))
        ));

        let declared = u32::from_le_bytes(canonical[..4].try_into().unwrap());
        for mutated in [declared - 1, declared + 1, 0, u32::MAX] {
            let mut wire = canonical.clone();
            wire[..4].copy_from_slice(&mutated.to_le_bytes());
            assert!(Message::decode_framed_wire(&wire).is_err());
        }

        let mut missing_byte = canonical.clone();
        missing_byte.pop();
        assert!(Message::decode_framed_wire(&missing_byte).is_err());

        assert!(Message::decode_framed_wire(&canonical[..3]).is_err());
    }

    #[test]
    fn framed_decoder_rejects_noncanonical_fixed_payload_at_transport_maximum() {
        let declared_len = MAX_MSG_BYTES - 4;
        let mut wire = vec![0u8; MAX_MSG_BYTES];
        wire[..4].copy_from_slice(&(declared_len as u32).to_le_bytes());
        wire[4] = MessageType::Ping as u8;

        assert!(matches!(
            Message::decode_framed_wire(&wire),
            Err(NetworkError::DecodeFailed { .. })
        ));
    }

    fn assert_canonical_and_rejects_trailing(msg: Message) {
        let canonical = msg.encode_wire().unwrap();
        let decoded = Message::decode_framed_wire(&canonical).unwrap();
        assert_eq!(decoded.encode_wire().unwrap(), canonical);

        for suffix in [
            vec![0xAA],
            vec![0xAA, 0x55, 0x00],
            Message::Pong(9).encode_wire().unwrap(),
        ] {
            let mut malformed = canonical.clone();
            malformed.extend_from_slice(&suffix);
            let declared_len = (malformed.len() - 4) as u32;
            malformed[..4].copy_from_slice(&declared_len.to_le_bytes());
            assert!(Message::decode_framed_wire(&malformed).is_err());
        }
    }

    #[test]
    fn ping_payload_is_exact_and_canonical() {
        assert_canonical_and_rejects_trailing(Message::Ping(u64::MAX));
    }

    #[test]
    fn pong_payload_is_exact_and_canonical() {
        assert_canonical_and_rejects_trailing(Message::Pong(0));
    }

    #[test]
    fn request_blocks_payload_is_exact_and_canonical() {
        assert_canonical_and_rejects_trailing(Message::RequestBlocks {
            from_height: 0,
            to_height: u64::MAX,
        });
    }

    #[test]
    fn request_qc_payload_is_exact_and_canonical() {
        assert_canonical_and_rejects_trailing(Message::RequestQC { height: u64::MAX });
    }

    #[test]
    fn qc_response_payload_is_exact_and_canonical() {
        assert_canonical_and_rejects_trailing(Message::QCResponse {
            height: 0,
            qc_bytes: vec![],
        });
        assert_canonical_and_rejects_trailing(Message::QCResponse {
            height: u64::MAX,
            qc_bytes: vec![0x11, 0x22, 0x33],
        });

        let maximum = Message::QCResponse {
            height: 1,
            qc_bytes: vec![0; MAX_MSG_BYTES - 17],
        }
        .encode_wire()
        .unwrap();
        assert_eq!(maximum.len(), MAX_MSG_BYTES);
        assert!(Message::decode_framed_wire(&maximum).is_ok());
    }
}
