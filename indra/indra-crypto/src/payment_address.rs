//! Canonical machine-oriented payment addresses carrying one complete hybrid key.

use crate::{
    hash::sha256,
    hybrid::{
        validate_classical_public_key, validate_pq_public_key, ClassicalPublicKey, HybridPublicKey,
        PqPublicKey,
    },
    CryptoError, CryptoResult, PQ_PK_BYTES,
};

/// Canonical binary address version.
pub const PAYMENT_ADDRESS_VERSION: u8 = 1;
/// Exact, case-sensitive textual prefix.
pub const PAYMENT_ADDRESS_TEXT_PREFIX: &str = "indra:";
/// Protocol maximum for a canonical chain identifier.
pub const MAX_PAYMENT_CHAIN_ID_BYTES: usize = 64;

const CHECKSUM_DOMAIN: &[u8] = b"INDRA-PAYMENT-ADDRESS-CHECKSUM-v1";
const CHECKSUM_BYTES: usize = 8;
const PQ_LENGTH_BYTES: usize = 4;
const FIXED_BYTES: usize = 1 + 2 + 32 + PQ_LENGTH_BYTES + PQ_PK_BYTES + CHECKSUM_BYTES;
const MAX_BINARY_BYTES: usize = FIXED_BYTES + MAX_PAYMENT_CHAIN_ID_BYTES;
const MAX_TEXT_PAYLOAD_BYTES: usize = (MAX_BINARY_BYTES * 4).div_ceil(3);
/// Maximum complete textual payment-address length, including the `indra:` prefix.
pub const MAX_PAYMENT_ADDRESS_TEXT_BYTES: usize =
    PAYMENT_ADDRESS_TEXT_PREFIX.len() + MAX_TEXT_PAYLOAD_BYTES;

/// A chain-bound raw hybrid-public-key payment address.
///
/// This intentionally large descriptor is meant for machine transport. Its
/// checksum detects accidental corruption only; it is not authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentAddressV1 {
    chain_id: Vec<u8>,
    owner_pubkey: HybridPublicKey,
}

impl PaymentAddressV1 {
    /// Construct and validate a canonical address.
    pub fn new(chain_id: &[u8], owner_pubkey: HybridPublicKey) -> CryptoResult<Self> {
        validate_chain_id(chain_id)?;
        validate_classical_public_key(&owner_pubkey.classical)?;
        validate_pq_public_key(&owner_pubkey.pq)?;
        Ok(Self {
            chain_id: chain_id.to_vec(),
            owner_pubkey,
        })
    }

    /// Decode canonical binary bytes and require the expected local chain ID.
    pub fn decode(bytes: &[u8], expected_chain_id: &[u8]) -> CryptoResult<Self> {
        validate_chain_id(expected_chain_id)?;
        if bytes.len() < FIXED_BYTES || bytes.len() > MAX_BINARY_BYTES {
            return malformed(bytes.len());
        }
        if bytes[0] != PAYMENT_ADDRESS_VERSION {
            return Err(CryptoError::UnsupportedVersion {
                scheme: "PaymentAddressV1",
                version: bytes[0],
            });
        }
        let chain_len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        if chain_len == 0 || chain_len > MAX_PAYMENT_CHAIN_ID_BYTES {
            return Err(CryptoError::InvalidPaymentAddress {
                reason: "chain ID length is outside protocol bounds",
            });
        }
        let expected_len = FIXED_BYTES + chain_len;
        if bytes.len() != expected_len {
            return malformed(bytes.len());
        }
        let chain_end = 3 + chain_len;
        let chain_id = &bytes[3..chain_end];
        if chain_id != expected_chain_id {
            return Err(CryptoError::InvalidPaymentAddress {
                reason: "chain ID mismatch",
            });
        }

        let key_start = chain_end;
        let pq_len_start = key_start + 32;
        let pq_start = pq_len_start + PQ_LENGTH_BYTES;
        let pq_len = u32::from_le_bytes(bytes[pq_len_start..pq_start].try_into().map_err(|_| {
            CryptoError::InvalidPaymentAddress {
                reason: "malformed PQ key length",
            }
        })?) as usize;
        if pq_len != PQ_PK_BYTES {
            return Err(CryptoError::InvalidPaymentAddress {
                reason: "PQ public key length must be exactly 2592 bytes",
            });
        }
        let pq_end = pq_start + pq_len;
        let checksum_start = bytes.len() - CHECKSUM_BYTES;
        if pq_end != checksum_start {
            return malformed(bytes.len());
        }
        if checksum(&bytes[..checksum_start]) != bytes[checksum_start..] {
            return Err(CryptoError::InvalidPaymentAddress {
                reason: "checksum mismatch",
            });
        }

        let classical: [u8; 32] = bytes[key_start..pq_len_start].try_into().map_err(|_| {
            CryptoError::InvalidPaymentAddress {
                reason: "malformed classical public key",
            }
        })?;
        let pq: [u8; PQ_PK_BYTES] =
            bytes[pq_start..pq_end]
                .try_into()
                .map_err(|_| CryptoError::InvalidPaymentAddress {
                    reason: "malformed PQ public key",
                })?;
        let owner_pubkey = HybridPublicKey {
            classical: ClassicalPublicKey(classical),
            pq: PqPublicKey(pq),
        };
        validate_classical_public_key(&owner_pubkey.classical)?;
        validate_pq_public_key(&owner_pubkey.pq)?;
        Ok(Self {
            chain_id: chain_id.to_vec(),
            owner_pubkey,
        })
    }

    /// Decode exact lowercase-prefix, unpadded RFC 4648 Base64URL text.
    pub fn from_text(text: &str, expected_chain_id: &[u8]) -> CryptoResult<Self> {
        let payload = text.strip_prefix(PAYMENT_ADDRESS_TEXT_PREFIX).ok_or(
            CryptoError::InvalidPaymentAddress {
                reason: "text prefix mismatch",
            },
        )?;
        if payload.len() > MAX_TEXT_PAYLOAD_BYTES {
            return Err(CryptoError::InvalidPaymentAddress {
                reason: "encoded address exceeds protocol maximum",
            });
        }
        let bytes = decode_base64url(payload)?;
        if encode_base64url(&bytes) != payload {
            return Err(CryptoError::InvalidPaymentAddress {
                reason: "non-canonical Base64URL",
            });
        }
        Self::decode(&bytes, expected_chain_id)
    }

    /// Encode the canonical binary representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FIXED_BYTES + self.chain_id.len());
        out.push(PAYMENT_ADDRESS_VERSION);
        out.extend_from_slice(&(self.chain_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.owner_pubkey.classical.0);
        out.extend_from_slice(&(PQ_PK_BYTES as u32).to_le_bytes());
        out.extend_from_slice(&self.owner_pubkey.pq.0);
        out.extend_from_slice(&checksum(&out));
        out
    }

    /// Encode as `indra:` plus canonical unpadded RFC 4648 Base64URL.
    #[must_use]
    pub fn to_text(&self) -> String {
        format!(
            "{PAYMENT_ADDRESS_TEXT_PREFIX}{}",
            encode_base64url(&self.encode())
        )
    }

    /// Exact bound chain identifier.
    #[must_use]
    pub fn chain_id(&self) -> &[u8] {
        &self.chain_id
    }

    /// Complete authenticated-at-spend ownership public key.
    #[must_use]
    pub fn owner_pubkey(&self) -> &HybridPublicKey {
        &self.owner_pubkey
    }
}

fn validate_chain_id(chain_id: &[u8]) -> CryptoResult<()> {
    if chain_id.is_empty() || chain_id.len() > MAX_PAYMENT_CHAIN_ID_BYTES {
        return Err(CryptoError::InvalidPaymentAddress {
            reason: "chain ID length is outside protocol bounds",
        });
    }
    Ok(())
}

fn malformed(actual: usize) -> CryptoResult<PaymentAddressV1> {
    Err(CryptoError::MalformedEncoding {
        scheme: "PaymentAddressV1",
        actual,
    })
}

fn checksum(payload: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let mut material = Vec::with_capacity(CHECKSUM_DOMAIN.len() + payload.len());
    material.extend_from_slice(CHECKSUM_DOMAIN);
    material.extend_from_slice(payload);
    let digest = sha256(&material);
    digest[..CHECKSUM_BYTES]
        .try_into()
        .unwrap_or([0; CHECKSUM_BYTES])
}

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode_base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.push(BASE64URL[(a >> 2) as usize] as char);
        out.push(BASE64URL[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(BASE64URL[(((b & 15) << 2) | (c >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(BASE64URL[(c & 63) as usize] as char);
        }
    }
    out
}

fn decode_base64url(text: &str) -> CryptoResult<Vec<u8>> {
    if text.is_empty() || text.contains('=') || text.len() % 4 == 1 {
        return Err(CryptoError::InvalidPaymentAddress {
            reason: "invalid unpadded Base64URL",
        });
    }
    let mut values = Vec::with_capacity(text.len());
    for byte in text.bytes() {
        let value = BASE64URL
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or(CryptoError::InvalidPaymentAddress {
                reason: "invalid unpadded Base64URL",
            })?;
        values.push(value as u8);
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for chunk in values.chunks(4) {
        out.push((chunk[0] << 2) | (chunk[1] >> 4));
        if chunk.len() > 2 {
            out.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        if chunk.len() > 3 {
            out.push((chunk[2] << 6) | chunk[3]);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClassicalKeypair, HybridKeypair, PqKeypair};

    fn address() -> PaymentAddressV1 {
        let keys = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[7; 32]),
            PqKeypair::from_seed(&[8; 32]).unwrap(),
        );
        PaymentAddressV1::new(b"indra-mainnet", keys.public_key()).unwrap()
    }

    #[test]
    fn canonical_binary_and_text_round_trip() {
        let address = address();
        assert_eq!(
            PaymentAddressV1::decode(&address.encode(), b"indra-mainnet").unwrap(),
            address
        );
        assert_eq!(
            PaymentAddressV1::from_text(&address.to_text(), b"indra-mainnet").unwrap(),
            address
        );
    }

    #[test]
    fn rejects_noncanonical_and_wrong_chain_encodings() {
        let address = address();
        assert!(
            PaymentAddressV1::from_text(&format!("{}=", address.to_text()), b"indra-mainnet")
                .is_err()
        );
        assert!(
            PaymentAddressV1::from_text(&format!(" {}", address.to_text()), b"indra-mainnet")
                .is_err()
        );
        assert!(PaymentAddressV1::decode(&address.encode(), b"other-chain").is_err());
        let mut trailing = address.encode();
        trailing.push(0);
        assert!(PaymentAddressV1::decode(&trailing, b"indra-mainnet").is_err());
    }

    #[test]
    fn rejects_bad_lengths_checksum_and_oversized_text_before_decode() {
        let address = address();
        let mut bad_pq_len = address.encode();
        let pq_len_offset = 3 + address.chain_id().len() + 32;
        bad_pq_len[pq_len_offset..pq_len_offset + 4].copy_from_slice(&2591u32.to_le_bytes());
        assert!(PaymentAddressV1::decode(&bad_pq_len, b"indra-mainnet").is_err());
        let mut bad_checksum = address.encode();
        let last = bad_checksum.len() - 1;
        bad_checksum[last] ^= 1;
        assert!(PaymentAddressV1::decode(&bad_checksum, b"indra-mainnet").is_err());
        let oversized = format!("indra:{}", "A".repeat(MAX_TEXT_PAYLOAD_BYTES + 1));
        assert!(PaymentAddressV1::from_text(&oversized, b"indra-mainnet").is_err());
    }
}
