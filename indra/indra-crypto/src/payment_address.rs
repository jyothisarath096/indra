//! Self-contained, chain-bound payment addresses.

use crate::{
    hash::{domain_hash, sha256},
    hybrid::{
        validate_classical_public_key, validate_pq_public_key, verify_hybrid, ClassicalPublicKey,
        ClassicalSignature, HybridKeypair, HybridPublicKey, HybridSignature, PqPublicKey,
        PqSignature,
    },
    CryptoError, CryptoResult, PaymentPubKeyV1, CLASSICAL_SIG_BYTES, PAYMENT_PUBKEY_V1_ENCODED_LEN,
    PQ_PK_BYTES, PQ_SIG_BYTES,
};

/// Literal binary address domain.
pub const PAYMENT_ADDRESS_DOMAIN: &[u8] = b"INDRA-PAYMENT-ADDRESS";
/// Canonical address format version.
pub const PAYMENT_ADDRESS_VERSION: u8 = 1;
/// Canonical textual prefix.
pub const PAYMENT_ADDRESS_TEXT_PREFIX: &str = "indra:";
const CHECKSUM_DOMAIN: &[u8] = b"INDRA-PAYMENT-ADDRESS-CHECKSUM-v1";
const CHECKSUM_BYTES: usize = 8;
const FIXED_BODY_BYTES: usize =
    PAYMENT_ADDRESS_DOMAIN.len() + 1 + 2 + 32 + PQ_PK_BYTES + PAYMENT_PUBKEY_V1_ENCODED_LEN;
const SIGNATURE_BYTES: usize = CLASSICAL_SIG_BYTES + PQ_SIG_BYTES;

/// A complete payment destination authenticated by its ownership key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentAddress {
    chain_id: Vec<u8>,
    owner_pubkey: HybridPublicKey,
    payment_pubkey: PaymentPubKeyV1,
    owner_signature: HybridSignature,
}

impl PaymentAddress {
    /// Construct and owner-sign a canonical descriptor.
    pub fn new(
        chain_id: &[u8],
        owner_keypair: &HybridKeypair,
        payment_pubkey: PaymentPubKeyV1,
    ) -> CryptoResult<Self> {
        let chain_len =
            u16::try_from(chain_id.len()).map_err(|_| CryptoError::InvalidPaymentAddress {
                reason: "chain ID exceeds u16 length",
            })?;
        if chain_len == 0 {
            return Err(CryptoError::InvalidPaymentAddress {
                reason: "chain ID is empty",
            });
        }
        PaymentPubKeyV1::decode(&payment_pubkey.encode())?;
        let owner_pubkey = owner_keypair.public_key();
        validate_classical_public_key(&owner_pubkey.classical)?;
        validate_pq_public_key(&owner_pubkey.pq)?;
        let payload = binding_payload(chain_id, &owner_pubkey, &payment_pubkey);
        let owner_signature = owner_keypair.sign(&payload)?;
        Ok(Self {
            chain_id: chain_id.to_vec(),
            owner_pubkey,
            payment_pubkey,
            owner_signature,
        })
    }

    /// Decode and fully validate a canonical binary descriptor.
    pub fn decode(bytes: &[u8], expected_chain_id: &[u8]) -> CryptoResult<Self> {
        if bytes.len() < FIXED_BODY_BYTES + SIGNATURE_BYTES + CHECKSUM_BYTES {
            return Err(CryptoError::MalformedEncoding {
                scheme: "PaymentAddress",
                actual: bytes.len(),
            });
        }
        let payload_end = bytes.len() - CHECKSUM_BYTES;
        if checksum(&bytes[..payload_end]) != bytes[payload_end..] {
            return Err(CryptoError::InvalidPaymentAddress {
                reason: "checksum mismatch",
            });
        }
        let mut cursor = 0;
        if &bytes[..PAYMENT_ADDRESS_DOMAIN.len()] != PAYMENT_ADDRESS_DOMAIN {
            return Err(CryptoError::InvalidPaymentAddress {
                reason: "domain mismatch",
            });
        }
        cursor += PAYMENT_ADDRESS_DOMAIN.len();
        let version = bytes[cursor];
        cursor += 1;
        if version != PAYMENT_ADDRESS_VERSION {
            return Err(CryptoError::UnsupportedVersion {
                scheme: "PaymentAddress",
                version,
            });
        }
        let chain_len = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
        cursor += 2;
        let expected_len = FIXED_BODY_BYTES + chain_len + SIGNATURE_BYTES + CHECKSUM_BYTES;
        if bytes.len() != expected_len || chain_len == 0 {
            return Err(CryptoError::MalformedEncoding {
                scheme: "PaymentAddress",
                actual: bytes.len(),
            });
        }
        let chain_id = bytes[cursor..cursor + chain_len].to_vec();
        cursor += chain_len;
        if chain_id != expected_chain_id {
            return Err(CryptoError::InvalidPaymentAddress {
                reason: "chain ID mismatch",
            });
        }
        let mut classical = [0u8; 32];
        classical.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        let mut pq = [0u8; PQ_PK_BYTES];
        pq.copy_from_slice(&bytes[cursor..cursor + PQ_PK_BYTES]);
        cursor += PQ_PK_BYTES;
        let owner_pubkey = HybridPublicKey {
            classical: ClassicalPublicKey(classical),
            pq: PqPublicKey(pq),
        };
        validate_classical_public_key(&owner_pubkey.classical)?;
        validate_pq_public_key(&owner_pubkey.pq)?;
        let payment_pubkey =
            PaymentPubKeyV1::decode(&bytes[cursor..cursor + PAYMENT_PUBKEY_V1_ENCODED_LEN])?;
        cursor += PAYMENT_PUBKEY_V1_ENCODED_LEN;
        let mut classical_sig = [0u8; CLASSICAL_SIG_BYTES];
        classical_sig.copy_from_slice(&bytes[cursor..cursor + CLASSICAL_SIG_BYTES]);
        cursor += CLASSICAL_SIG_BYTES;
        let mut pq_sig = [0u8; PQ_SIG_BYTES];
        pq_sig.copy_from_slice(&bytes[cursor..cursor + PQ_SIG_BYTES]);
        let owner_signature = HybridSignature {
            classical: ClassicalSignature(classical_sig),
            pq: PqSignature(pq_sig),
        };
        let payload = binding_payload(&chain_id, &owner_pubkey, &payment_pubkey);
        verify_hybrid(&payload, &owner_signature, &owner_pubkey).map_err(|_| {
            CryptoError::InvalidPaymentAddress {
                reason: "owner-binding signature failed",
            }
        })?;
        Ok(Self {
            chain_id,
            owner_pubkey,
            payment_pubkey,
            owner_signature,
        })
    }

    /// Decode the canonical textual representation and validate its chain.
    pub fn from_text(text: &str, expected_chain_id: &[u8]) -> CryptoResult<Self> {
        let encoded = text.strip_prefix(PAYMENT_ADDRESS_TEXT_PREFIX).ok_or(
            CryptoError::InvalidPaymentAddress {
                reason: "text prefix mismatch",
            },
        )?;
        let bytes = decode_base64url(encoded)?;
        if encode_base64url(&bytes) != encoded {
            return Err(CryptoError::InvalidPaymentAddress {
                reason: "non-canonical Base64URL",
            });
        }
        Self::decode(&bytes, expected_chain_id)
    }

    /// Encode the canonical binary descriptor.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = binding_payload(&self.chain_id, &self.owner_pubkey, &self.payment_pubkey);
        out.extend_from_slice(&self.owner_signature.classical.0);
        out.extend_from_slice(&self.owner_signature.pq.0);
        let check = checksum(&out);
        out.extend_from_slice(&check);
        out
    }

    /// Encode as `indra:` followed by canonical unpadded Base64URL.
    #[must_use]
    pub fn to_text(&self) -> String {
        format!(
            "{PAYMENT_ADDRESS_TEXT_PREFIX}{}",
            encode_base64url(&self.encode())
        )
    }

    /// Chain identifier bound into this address.
    #[must_use]
    pub fn chain_id(&self) -> &[u8] {
        &self.chain_id
    }

    /// Authenticated ownership public key.
    #[must_use]
    pub fn owner_pubkey(&self) -> &HybridPublicKey {
        &self.owner_pubkey
    }

    /// Authenticated payment public key.
    #[must_use]
    pub fn payment_pubkey(&self) -> &PaymentPubKeyV1 {
        &self.payment_pubkey
    }

    /// Owner ID derived solely from the ownership key.
    #[must_use]
    pub fn owner_id(&self) -> [u8; 32] {
        sha256(&self.owner_pubkey.classical.0)
    }
}

fn binding_payload(
    chain_id: &[u8],
    owner_pubkey: &HybridPublicKey,
    payment_pubkey: &PaymentPubKeyV1,
) -> Vec<u8> {
    let chain_len = chain_id.len() as u16;
    let mut out = Vec::with_capacity(FIXED_BODY_BYTES + chain_id.len());
    out.extend_from_slice(PAYMENT_ADDRESS_DOMAIN);
    out.push(PAYMENT_ADDRESS_VERSION);
    out.extend_from_slice(&chain_len.to_be_bytes());
    out.extend_from_slice(chain_id);
    out.extend_from_slice(&owner_pubkey.classical.0);
    out.extend_from_slice(&owner_pubkey.pq.0);
    out.extend_from_slice(&payment_pubkey.encode());
    out
}

fn checksum(payload: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let digest = domain_hash(CHECKSUM_DOMAIN, payload);
    let mut out = [0u8; CHECKSUM_BYTES];
    out.copy_from_slice(&digest[..CHECKSUM_BYTES]);
    out
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
    if text.contains('=') || text.len() % 4 == 1 {
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
    use crate::{ClassicalKeypair, PaymentKeypairV1, PqKeypair};

    fn owner(seed: u8) -> HybridKeypair {
        HybridKeypair::new(
            ClassicalKeypair::from_seed(&[seed; 32]),
            PqKeypair::from_seed(&[seed; 32]).unwrap(),
        )
    }

    #[test]
    fn binary_and_text_round_trip() {
        let address = PaymentAddress::new(
            b"indra-mainnet",
            &owner(7),
            PaymentKeypairV1::generate().public_key(),
        )
        .unwrap();
        assert_eq!(
            PaymentAddress::decode(&address.encode(), b"indra-mainnet").unwrap(),
            address
        );
        assert_eq!(
            PaymentAddress::from_text(&address.to_text(), b"indra-mainnet").unwrap(),
            address
        );
    }

    #[test]
    fn rejects_checksum_chain_and_substituted_payment_key() {
        let address = PaymentAddress::new(
            b"indra-mainnet",
            &owner(8),
            PaymentKeypairV1::generate().public_key(),
        )
        .unwrap();
        let mut corrupt = address.encode();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(PaymentAddress::decode(&corrupt, b"indra-mainnet").is_err());
        assert!(PaymentAddress::decode(&address.encode(), b"other-chain").is_err());

        let mut substituted = address.clone();
        substituted.payment_pubkey = PaymentKeypairV1::generate().public_key();
        assert!(PaymentAddress::decode(&substituted.encode(), b"indra-mainnet").is_err());
    }
}
