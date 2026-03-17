//! Wire protocol messages.
//!
//! ## Encoding
//!
//! Each message on the wire:
//!   [u32 total_length LE] [u8 message_type] [payload bytes]
//!
//! `total_length` includes the type byte but NOT the 4-byte length prefix itself.
//! Maximum message size: MAX_MSG_BYTES (4 MB).

use indra_core::{
    codec::{Decode, Encode, ByteReader},
    types::{
        block::BlockV1,
        primitives::Bytes32,
        transaction::TransactionV1,
        vote::VoteV1,
    },
};

use crate::error::{NetworkError, NetworkResult};

/// Maximum wire message size: 4 MB.
pub const MAX_MSG_BYTES: usize = 4 * 1024 * 1024;

/// Message type discriminant bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// A complete block.
    Block     = 0x01,
    /// A prevote or precommit.
    Vote      = 0x02,
    /// A pending transaction.
    Tx        = 0x03,
    /// A list of known peer addresses.
    PeerList  = 0x04,
    /// Liveness ping.
    Ping      = 0x05,
    /// Liveness pong.
    Pong      = 0x06,
    /// Request blocks by height range.
    GetBlocks = 0x07,
    /// Announce current chain tip.
    Status    = 0x08,
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
            0x07 => Ok(Self::GetBlocks),
            0x08 => Ok(Self::Status),
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
    GetBlocks {
        /// First height requested.
        from_height: u64,
        /// Last height requested (inclusive).
        to_height: u64,
    },
    /// Announce current chain tip.
    Status {
        /// The sender's current chain height.
        height: u64,
        /// The sender's current tip hash.
        tip_hash: Bytes32,
    },
}

impl Message {
    /// The message type discriminant.
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Block(_)     => MessageType::Block,
            Self::Vote(_)      => MessageType::Vote,
            Self::Tx(_)        => MessageType::Tx,
            Self::PeerList(_)  => MessageType::PeerList,
            Self::Ping(_)      => MessageType::Ping,
            Self::Pong(_)      => MessageType::Pong,
            Self::GetBlocks { .. } => MessageType::GetBlocks,
            Self::Status { .. }    => MessageType::Status,
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
        if data.is_empty() {
            return Err(NetworkError::DecodeFailed {
                reason: "empty message".to_string(),
            });
        }

        let msg_type = MessageType::from_byte(data[0])?;
        let payload = &data[1..];

        Self::decode_payload(msg_type, payload)
    }

    /// Encode the payload (without length prefix or type byte).
    fn encode_payload(&self) -> Vec<u8> {
        match self {
            Self::Block(b) => b.encode_to_vec(),
            Self::Vote(v)  => v.encode_to_vec(),
            Self::Tx(tx)   => tx.encode_to_vec(),
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
            Self::GetBlocks { from_height, to_height } => {
                let mut buf = Vec::with_capacity(16);
                buf.extend_from_slice(&from_height.to_le_bytes());
                buf.extend_from_slice(&to_height.to_le_bytes());
                buf
            }
            Self::Status { height, tip_hash } => {
                let mut buf = Vec::with_capacity(40);
                buf.extend_from_slice(&height.to_le_bytes());
                buf.extend_from_slice(&tip_hash.0);
                buf
            }
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
                if payload.len() < 4 {
                    return Err(NetworkError::DecodeFailed {
                        reason: "peer list too short".to_string(),
                    });
                }
                let count = u32::from_le_bytes(
                    payload[..4].try_into().unwrap_or([0u8; 4])
                ) as usize;
                let mut peers = Vec::with_capacity(count);
                let mut offset = 4;
                for _ in 0..count {
                    if offset + 2 > payload.len() { break; }
                    let len = u16::from_le_bytes(
                        payload[offset..offset+2].try_into().unwrap_or([0u8; 2])
                    ) as usize;
                    offset += 2;
                    if offset + len > payload.len() { break; }
                    let s = String::from_utf8_lossy(&payload[offset..offset+len]).to_string();
                    peers.push(s);
                    offset += len;
                }
                Ok(Self::PeerList(peers))
            }
            MessageType::Ping => {
                if payload.len() < 8 {
                    return Err(NetworkError::DecodeFailed { reason: "short ping".to_string() });
                }
                let nonce = u64::from_le_bytes(payload[..8].try_into().unwrap_or([0u8; 8]));
                Ok(Self::Ping(nonce))
            }
            MessageType::Pong => {
                if payload.len() < 8 {
                    return Err(NetworkError::DecodeFailed { reason: "short pong".to_string() });
                }
                let nonce = u64::from_le_bytes(payload[..8].try_into().unwrap_or([0u8; 8]));
                Ok(Self::Pong(nonce))
            }
            MessageType::GetBlocks => {
                if payload.len() < 16 {
                    return Err(NetworkError::DecodeFailed { reason: "short get_blocks".to_string() });
                }
                let from_height = u64::from_le_bytes(payload[..8].try_into().unwrap_or([0u8; 8]));
                let to_height   = u64::from_le_bytes(payload[8..16].try_into().unwrap_or([0u8; 8]));
                Ok(Self::GetBlocks { from_height, to_height })
            }
            MessageType::Status => {
                if payload.len() < 40 {
                    return Err(NetworkError::DecodeFailed { reason: "short status".to_string() });
                }
                let height = u64::from_le_bytes(payload[..8].try_into().unwrap_or([0u8; 8]));
                let mut tip = [0u8; 32];
                tip.copy_from_slice(&payload[8..40]);
                Ok(Self::Status { height, tip_hash: Bytes32::from(tip) })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::primitives::Bytes32;

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
    fn get_blocks_round_trip() {
        let msg = Message::GetBlocks { from_height: 100, to_height: 200 };
        let wire = msg.encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        assert!(matches!(decoded, Message::GetBlocks { from_height: 100, to_height: 200 }));
    }

    #[test]
    fn status_round_trip() {
        let tip = Bytes32::from([0xABu8; 32]);
        let msg = Message::Status { height: 999, tip_hash: tip };
        let wire = msg.encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        match decoded {
            Message::Status { height, tip_hash } => {
                assert_eq!(height, 999);
                assert_eq!(tip_hash, tip);
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
