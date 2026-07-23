//! Payment blinding key primitives and isolated Stage 1 derivation helpers.
//!
//! Payment delivery uses X25519 key exchange plus ML-KEM-1024 encapsulation.
//! These keys are intentionally separate from `HybridPublicKey`, which carries
//! signature material.

use ml_kem::{Decapsulate, Encapsulate, EncapsulationKey1024, Kem, KeyExport, MlKem1024};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::{
    constants::{
        ML_KEM_1024_CT_BYTES, ML_KEM_1024_EK_BYTES, ML_KEM_SEED_BYTES, X25519_PK_BYTES,
        X25519_SK_BYTES,
    },
    error::{CryptoError, CryptoResult},
    hash::sha256,
};

/// Payment key schema version.
pub const PAYMENT_VERSION_V1: u8 = 1;

/// BLAKE3 derive-key context for payment blinding factors.
pub const PAYMENT_BLINDING_CONTEXT_V1: &str = "INDRA-payment-blinding-v1";

/// Encoded `PaymentKeypairV1` length.
pub const PAYMENT_KEYPAIR_V1_ENCODED_LEN: usize = 1 + X25519_SK_BYTES + ML_KEM_SEED_BYTES;

/// Encoded `PaymentPubKeyV1` length.
pub const PAYMENT_PUBKEY_V1_ENCODED_LEN: usize = 1 + X25519_PK_BYTES + ML_KEM_1024_EK_BYTES;

/// Encoded `PaymentBlindingNoteV1` length.
pub const PAYMENT_NOTE_V1_ENCODED_LEN: usize =
    1 + 32 + 32 + X25519_PK_BYTES + ML_KEM_1024_CT_BYTES + 32;

/// Payment public key, version 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentPubKeyV1 {
    /// Must be 1.
    pub version: u8,
    /// Static X25519 public key.
    pub x25519_pk: [u8; X25519_PK_BYTES],
    /// ML-KEM-1024 encapsulation key.
    pub ml_kem_1024_ek: [u8; ML_KEM_1024_EK_BYTES],
}

impl PaymentPubKeyV1 {
    /// Encode as `version || x25519_pk || ml_kem_1024_ek`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PAYMENT_PUBKEY_V1_ENCODED_LEN);
        out.push(self.version);
        out.extend_from_slice(&self.x25519_pk);
        out.extend_from_slice(&self.ml_kem_1024_ek);
        out
    }

    /// Decode the canonical fixed-length representation.
    pub fn decode(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != PAYMENT_PUBKEY_V1_ENCODED_LEN {
            return Err(CryptoError::MalformedEncoding {
                scheme: "PaymentPubKeyV1",
                actual: bytes.len(),
            });
        }
        let version = bytes[0];
        if version != PAYMENT_VERSION_V1 {
            return Err(CryptoError::UnsupportedVersion {
                scheme: "PaymentPubKeyV1",
                version,
            });
        }

        let mut x25519_pk = [0u8; X25519_PK_BYTES];
        x25519_pk.copy_from_slice(&bytes[1..(1 + X25519_PK_BYTES)]);
        let mut ml_kem_1024_ek = [0u8; ML_KEM_1024_EK_BYTES];
        ml_kem_1024_ek.copy_from_slice(&bytes[(1 + X25519_PK_BYTES)..]);

        EncapsulationKey1024::new((&ml_kem_1024_ek).into()).map_err(|_| {
            CryptoError::InvalidMlKem {
                material: "encapsulation key",
            }
        })?;

        Ok(Self {
            version,
            x25519_pk,
            ml_kem_1024_ek,
        })
    }

    /// SHA-256 hash of the canonical public-key encoding.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        sha256(&self.encode())
    }
}

/// Payment private keypair, version 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentKeypairV1 {
    /// Must be 1.
    pub version: u8,
    /// Static X25519 secret key bytes.
    pub x25519_sk: [u8; X25519_SK_BYTES],
    /// Canonical ML-KEM-1024 decapsulation-key seed.
    pub ml_kem_1024_seed: [u8; ML_KEM_SEED_BYTES],
}

impl PaymentKeypairV1 {
    /// Generate a fresh payment keypair.
    #[must_use]
    pub fn generate() -> Self {
        let x_secret = StaticSecret::random();
        let (kem_dk, _) = MlKem1024::generate_keypair();
        Self {
            version: PAYMENT_VERSION_V1,
            x25519_sk: x_secret.to_bytes(),
            ml_kem_1024_seed: kem_dk.to_bytes().into(),
        }
    }

    /// Return the corresponding payment public key.
    #[must_use]
    pub fn public_key(&self) -> PaymentPubKeyV1 {
        let x_secret = StaticSecret::from(self.x25519_sk);
        let x_public = PublicKey::from(&x_secret).to_bytes();
        let kem_dk = ml_kem::DecapsulationKey1024::from_seed(self.ml_kem_1024_seed.into());
        PaymentPubKeyV1 {
            version: PAYMENT_VERSION_V1,
            x25519_pk: x_public,
            ml_kem_1024_ek: kem_dk.encapsulation_key().to_bytes().into(),
        }
    }

    /// Encode as `version || x25519_sk || ml_kem_1024_seed`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PAYMENT_KEYPAIR_V1_ENCODED_LEN);
        out.push(self.version);
        out.extend_from_slice(&self.x25519_sk);
        out.extend_from_slice(&self.ml_kem_1024_seed);
        out
    }

    /// Decode the canonical fixed-length private representation.
    pub fn decode(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != PAYMENT_KEYPAIR_V1_ENCODED_LEN {
            return Err(CryptoError::MalformedEncoding {
                scheme: "PaymentKeypairV1",
                actual: bytes.len(),
            });
        }
        let version = bytes[0];
        if version != PAYMENT_VERSION_V1 {
            return Err(CryptoError::UnsupportedVersion {
                scheme: "PaymentKeypairV1",
                version,
            });
        }
        let mut x25519_sk = [0u8; X25519_SK_BYTES];
        x25519_sk.copy_from_slice(&bytes[1..(1 + X25519_SK_BYTES)]);
        let mut ml_kem_1024_seed = [0u8; ML_KEM_SEED_BYTES];
        ml_kem_1024_seed.copy_from_slice(&bytes[(1 + X25519_SK_BYTES)..]);
        Ok(Self {
            version,
            x25519_sk,
            ml_kem_1024_seed,
        })
    }
}

/// Public note carried to the payment recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentBlindingNoteV1 {
    /// Must be 1.
    pub version: u8,
    /// Output owner identifier.
    pub owner_id: [u8; 32],
    /// Hash of the recipient `PaymentPubKeyV1`.
    pub payment_pubkey_hash: [u8; 32],
    /// Sender ephemeral X25519 public key.
    pub sender_x25519_ephemeral_pk: [u8; X25519_PK_BYTES],
    /// ML-KEM-1024 ciphertext.
    pub ml_kem_1024_ciphertext: [u8; ML_KEM_1024_CT_BYTES],
    /// Per-note nonce.
    pub note_nonce: [u8; 32],
}

impl PaymentBlindingNoteV1 {
    /// Encode as the fixed sequence defined by `PaymentBlindingNoteV1`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PAYMENT_NOTE_V1_ENCODED_LEN);
        out.push(self.version);
        out.extend_from_slice(&self.owner_id);
        out.extend_from_slice(&self.payment_pubkey_hash);
        out.extend_from_slice(&self.sender_x25519_ephemeral_pk);
        out.extend_from_slice(&self.ml_kem_1024_ciphertext);
        out.extend_from_slice(&self.note_nonce);
        out
    }

    /// Decode the canonical fixed-length representation.
    pub fn decode(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != PAYMENT_NOTE_V1_ENCODED_LEN {
            return Err(CryptoError::MalformedEncoding {
                scheme: "PaymentBlindingNoteV1",
                actual: bytes.len(),
            });
        }
        let version = bytes[0];
        if version != PAYMENT_VERSION_V1 {
            return Err(CryptoError::UnsupportedVersion {
                scheme: "PaymentBlindingNoteV1",
                version,
            });
        }

        let mut cursor = 1;
        let mut owner_id = [0u8; 32];
        owner_id.copy_from_slice(&bytes[cursor..(cursor + 32)]);
        cursor += 32;
        let mut payment_pubkey_hash = [0u8; 32];
        payment_pubkey_hash.copy_from_slice(&bytes[cursor..(cursor + 32)]);
        cursor += 32;
        let mut sender_x25519_ephemeral_pk = [0u8; X25519_PK_BYTES];
        sender_x25519_ephemeral_pk.copy_from_slice(&bytes[cursor..(cursor + X25519_PK_BYTES)]);
        cursor += X25519_PK_BYTES;
        let mut ml_kem_1024_ciphertext = [0u8; ML_KEM_1024_CT_BYTES];
        ml_kem_1024_ciphertext.copy_from_slice(&bytes[cursor..(cursor + ML_KEM_1024_CT_BYTES)]);
        cursor += ML_KEM_1024_CT_BYTES;
        let mut note_nonce = [0u8; 32];
        note_nonce.copy_from_slice(&bytes[cursor..(cursor + 32)]);

        Ok(Self {
            version,
            owner_id,
            payment_pubkey_hash,
            sender_x25519_ephemeral_pk,
            ml_kem_1024_ciphertext,
            note_nonce,
        })
    }
}

/// Inputs to the payment blinding KDF.
pub struct PaymentBlindingInputsV1<'a> {
    /// X25519 shared secret.
    pub x_secret: [u8; 32],
    /// ML-KEM shared secret.
    pub kem_secret: [u8; 32],
    /// Chain identifier bytes.
    pub chain_id: &'a [u8],
    /// Output owner identifier.
    pub owner_id: [u8; 32],
    /// Hash of the recipient payment public key.
    pub payment_pubkey_hash: [u8; 32],
    /// Output index encoded as u32 little-endian.
    pub output_index: u32,
    /// Output value in Spark encoded as u64 little-endian.
    pub value_spark: u64,
    /// Output lock height encoded as u64 little-endian.
    pub lock_height: u64,
    /// Sender ephemeral X25519 public key.
    pub sender_x25519_ephemeral_pk: [u8; X25519_PK_BYTES],
    /// ML-KEM-1024 ciphertext.
    pub ml_kem_1024_ciphertext: [u8; ML_KEM_1024_CT_BYTES],
    /// Per-note nonce.
    pub note_nonce: [u8; 32],
}

/// Derive the Stage 1 payment blinding factor using the exact confirmed KDF.
pub fn derive_payment_blinding_v1(inputs: &PaymentBlindingInputsV1<'_>) -> CryptoResult<[u8; 32]> {
    let chain_id_len =
        u16::try_from(inputs.chain_id.len()).map_err(|_| CryptoError::LengthExceeded {
            field: "chain_id",
            max: u16::MAX as usize,
            actual: inputs.chain_id.len(),
        })?;

    let mut ikm = Vec::with_capacity(
        32 + 32 + 2 + inputs.chain_id.len() + 32 + 32 + 4 + 8 + 8 + 32 + ML_KEM_1024_CT_BYTES + 32,
    );
    ikm.extend_from_slice(&inputs.x_secret);
    ikm.extend_from_slice(&inputs.kem_secret);
    ikm.extend_from_slice(&chain_id_len.to_le_bytes());
    ikm.extend_from_slice(inputs.chain_id);
    ikm.extend_from_slice(&inputs.owner_id);
    ikm.extend_from_slice(&inputs.payment_pubkey_hash);
    ikm.extend_from_slice(&inputs.output_index.to_le_bytes());
    ikm.extend_from_slice(&inputs.value_spark.to_le_bytes());
    ikm.extend_from_slice(&inputs.lock_height.to_le_bytes());
    ikm.extend_from_slice(&inputs.sender_x25519_ephemeral_pk);
    ikm.extend_from_slice(&inputs.ml_kem_1024_ciphertext);
    ikm.extend_from_slice(&inputs.note_nonce);

    Ok(blake3::derive_key(PAYMENT_BLINDING_CONTEXT_V1, &ikm))
}

/// Derive an X25519 shared secret from local private and peer public bytes.
#[must_use]
pub fn payment_x25519_shared_secret(
    local_x25519_sk: [u8; X25519_SK_BYTES],
    peer_x25519_pk: [u8; X25519_PK_BYTES],
) -> [u8; 32] {
    let local = StaticSecret::from(local_x25519_sk);
    let peer = PublicKey::from(peer_x25519_pk);
    local.diffie_hellman(&peer).to_bytes()
}

/// Sender-side payment blinding derivation output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderPaymentBlindingV1 {
    /// Public note for the recipient.
    pub note: PaymentBlindingNoteV1,
    /// Derived X25519 secret.
    pub x_secret: [u8; 32],
    /// Derived ML-KEM secret.
    pub kem_secret: [u8; 32],
    /// Final payment blinding factor.
    pub blinding: [u8; 32],
}

/// Recipient-side payment blinding derivation output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientPaymentBlindingV1 {
    /// Derived X25519 secret.
    pub x_secret: [u8; 32],
    /// Derived ML-KEM secret.
    pub kem_secret: [u8; 32],
    /// Final payment blinding factor.
    pub blinding: [u8; 32],
}

/// Sender-side helper: generate ephemeral KEX material and derive the blinding.
pub fn sender_derive_payment_blinding_v1(
    recipient_pubkey: &PaymentPubKeyV1,
    chain_id: &[u8],
    owner_id: [u8; 32],
    output_index: u32,
    value_spark: u64,
    lock_height: u64,
) -> CryptoResult<SenderPaymentBlindingV1> {
    let sender_x = EphemeralSecret::random();
    let sender_x25519_ephemeral_pk = PublicKey::from(&sender_x).to_bytes();
    let recipient_x = PublicKey::from(recipient_pubkey.x25519_pk);
    let x_secret = sender_x.diffie_hellman(&recipient_x).to_bytes();

    let recipient_ek = EncapsulationKey1024::new((&recipient_pubkey.ml_kem_1024_ek).into())
        .map_err(|_| CryptoError::InvalidMlKem {
            material: "encapsulation key",
        })?;
    let (kem_ct, kem_secret) = recipient_ek.encapsulate();
    let kem_ct_bytes: &[u8] = kem_ct.as_ref();
    let mut ml_kem_1024_ciphertext = [0u8; ML_KEM_1024_CT_BYTES];
    ml_kem_1024_ciphertext.copy_from_slice(kem_ct_bytes);
    let kem_secret: [u8; 32] = kem_secret.into();

    let mut note_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut note_nonce);

    let note = PaymentBlindingNoteV1 {
        version: PAYMENT_VERSION_V1,
        owner_id,
        payment_pubkey_hash: recipient_pubkey.hash(),
        sender_x25519_ephemeral_pk,
        ml_kem_1024_ciphertext,
        note_nonce,
    };

    let blinding = derive_payment_blinding_v1(&PaymentBlindingInputsV1 {
        x_secret,
        kem_secret,
        chain_id,
        owner_id: note.owner_id,
        payment_pubkey_hash: note.payment_pubkey_hash,
        output_index,
        value_spark,
        lock_height,
        sender_x25519_ephemeral_pk: note.sender_x25519_ephemeral_pk,
        ml_kem_1024_ciphertext: note.ml_kem_1024_ciphertext,
        note_nonce: note.note_nonce,
    })?;

    Ok(SenderPaymentBlindingV1 {
        note,
        x_secret,
        kem_secret,
        blinding,
    })
}

/// Recipient-side helper: use only the recipient keypair, public note, and
/// public output context to rederive the same blinding.
pub fn recipient_derive_payment_blinding_v1(
    recipient_keypair: &PaymentKeypairV1,
    note: &PaymentBlindingNoteV1,
    chain_id: &[u8],
    output_index: u32,
    value_spark: u64,
    lock_height: u64,
) -> CryptoResult<RecipientPaymentBlindingV1> {
    if note.payment_pubkey_hash != recipient_keypair.public_key().hash() {
        return Err(CryptoError::PaymentKeyHashMismatch);
    }

    let x_secret =
        payment_x25519_shared_secret(recipient_keypair.x25519_sk, note.sender_x25519_ephemeral_pk);
    let kem_dk = ml_kem::DecapsulationKey1024::from_seed(recipient_keypair.ml_kem_1024_seed.into());
    let kem_secret = kem_dk
        .decapsulate_slice(&note.ml_kem_1024_ciphertext)
        .map_err(|_| CryptoError::InvalidMlKem {
            material: "ciphertext",
        })?;
    let kem_secret: [u8; 32] = kem_secret.into();

    let blinding = derive_payment_blinding_v1(&PaymentBlindingInputsV1 {
        x_secret,
        kem_secret,
        chain_id,
        owner_id: note.owner_id,
        payment_pubkey_hash: note.payment_pubkey_hash,
        output_index,
        value_spark,
        lock_height,
        sender_x25519_ephemeral_pk: note.sender_x25519_ephemeral_pk,
        ml_kem_1024_ciphertext: note.ml_kem_1024_ciphertext,
        note_nonce: note.note_nonce,
    })?;

    Ok(RecipientPaymentBlindingV1 {
        x_secret,
        kem_secret,
        blinding,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_blinding_oracle(inputs: &PaymentBlindingInputsV1<'_>) -> [u8; 32] {
        let chain_id_len = u16::try_from(inputs.chain_id.len()).unwrap();
        let mut ikm = Vec::new();
        ikm.extend_from_slice(&inputs.x_secret);
        ikm.extend_from_slice(&inputs.kem_secret);
        ikm.extend_from_slice(&chain_id_len.to_le_bytes());
        ikm.extend_from_slice(inputs.chain_id);
        ikm.extend_from_slice(&inputs.owner_id);
        ikm.extend_from_slice(&inputs.payment_pubkey_hash);
        ikm.extend_from_slice(&inputs.output_index.to_le_bytes());
        ikm.extend_from_slice(&inputs.value_spark.to_le_bytes());
        ikm.extend_from_slice(&inputs.lock_height.to_le_bytes());
        ikm.extend_from_slice(&inputs.sender_x25519_ephemeral_pk);
        ikm.extend_from_slice(&inputs.ml_kem_1024_ciphertext);
        ikm.extend_from_slice(&inputs.note_nonce);
        blake3::derive_key(PAYMENT_BLINDING_CONTEXT_V1, &ikm)
    }

    fn known_inputs() -> PaymentBlindingInputsV1<'static> {
        PaymentBlindingInputsV1 {
            x_secret: [0x10; 32],
            kem_secret: [0x20; 32],
            chain_id: b"indra-stage1-testnet",
            owner_id: [0x30; 32],
            payment_pubkey_hash: [0x40; 32],
            output_index: 7,
            value_spark: 1_234_567_890,
            lock_height: 98_765,
            sender_x25519_ephemeral_pk: [0x50; 32],
            ml_kem_1024_ciphertext: [0x60; ML_KEM_1024_CT_BYTES],
            note_nonce: [0x70; 32],
        }
    }

    #[test]
    fn payment_keypair_and_pubkey_generation_encode_decode_round_trip() {
        let keypair = PaymentKeypairV1::generate();
        let keypair_decoded = PaymentKeypairV1::decode(&keypair.encode()).unwrap();
        assert_eq!(keypair.version, keypair_decoded.version);
        assert_eq!(keypair.x25519_sk, keypair_decoded.x25519_sk);
        assert_eq!(keypair.ml_kem_1024_seed, keypair_decoded.ml_kem_1024_seed);

        let pubkey = keypair.public_key();
        let pubkey_decoded = PaymentPubKeyV1::decode(&pubkey.encode()).unwrap();
        assert_eq!(pubkey, pubkey_decoded);
        assert_eq!(keypair.encode().len(), PAYMENT_KEYPAIR_V1_ENCODED_LEN);
        assert_eq!(pubkey.encode().len(), PAYMENT_PUBKEY_V1_ENCODED_LEN);
    }

    #[test]
    fn x25519_ephemeral_static_round_trip_matches() {
        let recipient = PaymentKeypairV1::generate();
        let recipient_pubkey = recipient.public_key();

        let sender_x = EphemeralSecret::random();
        let sender_pk = PublicKey::from(&sender_x).to_bytes();
        let sender_secret = sender_x
            .diffie_hellman(&PublicKey::from(recipient_pubkey.x25519_pk))
            .to_bytes();
        let recipient_secret = payment_x25519_shared_secret(recipient.x25519_sk, sender_pk);

        assert_eq!(sender_secret, recipient_secret);
    }

    #[test]
    fn ml_kem_1024_encapsulation_round_trip_matches() {
        let recipient = PaymentKeypairV1::generate();
        let recipient_pubkey = recipient.public_key();
        let recipient_ek =
            EncapsulationKey1024::new((&recipient_pubkey.ml_kem_1024_ek).into()).unwrap();
        let (ciphertext, sender_secret) = recipient_ek.encapsulate();

        let recipient_dk =
            ml_kem::DecapsulationKey1024::from_seed(recipient.ml_kem_1024_seed.into());
        let recipient_secret = recipient_dk.decapsulate_slice(ciphertext.as_ref()).unwrap();

        let sender_secret: [u8; 32] = sender_secret.into();
        let recipient_secret: [u8; 32] = recipient_secret.into();
        assert_eq!(sender_secret, recipient_secret);
    }

    #[test]
    fn full_kdf_oracle_matches_direct_blake3_derive_key() {
        let inputs = known_inputs();
        let expected = direct_blinding_oracle(&inputs);
        let actual = derive_payment_blinding_v1(&inputs).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn end_to_end_sender_recipient_round_trip_matches_randomized() {
        for output_index in 0u32..16 {
            let recipient = PaymentKeypairV1::generate();
            let owner_id = blake3::hash(&output_index.to_le_bytes()).into();
            let sender = sender_derive_payment_blinding_v1(
                &recipient.public_key(),
                b"indra-stage1-randomized",
                owner_id,
                output_index,
                50_000 + u64::from(output_index),
                100 + u64::from(output_index),
            )
            .unwrap();
            let recipient_side = recipient_derive_payment_blinding_v1(
                &recipient,
                &sender.note,
                b"indra-stage1-randomized",
                output_index,
                50_000 + u64::from(output_index),
                100 + u64::from(output_index),
            )
            .unwrap();

            assert_eq!(sender.x_secret, recipient_side.x_secret);
            assert_eq!(sender.kem_secret, recipient_side.kem_secret);
            assert_eq!(sender.blinding, recipient_side.blinding);
        }
    }

    #[test]
    fn sender_helper_ephemeral_key_and_nonce_are_unique() {
        let recipient = PaymentKeypairV1::generate();
        let recipient_pubkey = recipient.public_key();
        let mut seen_ephemeral = std::collections::BTreeSet::new();
        let mut seen_nonces = std::collections::BTreeSet::new();

        for i in 0..32 {
            let sender = sender_derive_payment_blinding_v1(
                &recipient_pubkey,
                b"indra-stage1-uniqueness",
                [0xA5; 32],
                i,
                1_000,
                0,
            )
            .unwrap();
            assert!(seen_ephemeral.insert(sender.note.sender_x25519_ephemeral_pk));
            assert!(seen_nonces.insert(sender.note.note_nonce));
        }
    }

    #[test]
    fn payment_blinding_note_encode_decode_round_trip() {
        let note = PaymentBlindingNoteV1 {
            version: PAYMENT_VERSION_V1,
            owner_id: [0x01; 32],
            payment_pubkey_hash: [0x02; 32],
            sender_x25519_ephemeral_pk: [0x03; 32],
            ml_kem_1024_ciphertext: [0x04; ML_KEM_1024_CT_BYTES],
            note_nonce: [0x05; 32],
        };
        let encoded = note.encode();
        assert_eq!(encoded.len(), PAYMENT_NOTE_V1_ENCODED_LEN);
        assert_eq!(PaymentBlindingNoteV1::decode(&encoded).unwrap(), note);
    }

    #[test]
    fn payment_blinding_kdf_is_sensitive_to_every_input() {
        let baseline_inputs = known_inputs();
        let baseline = derive_payment_blinding_v1(&baseline_inputs).unwrap();

        macro_rules! assert_changed {
            ($mutator:expr) => {{
                let mut inputs = known_inputs();
                $mutator(&mut inputs);
                assert_ne!(derive_payment_blinding_v1(&inputs).unwrap(), baseline);
            }};
        }

        assert_changed!(|i: &mut PaymentBlindingInputsV1<'_>| i.x_secret[0] ^= 1);
        assert_changed!(|i: &mut PaymentBlindingInputsV1<'_>| i.kem_secret[0] ^= 1);
        assert_changed!(|i: &mut PaymentBlindingInputsV1<'_>| i.chain_id = b"other-chain");
        assert_changed!(|i: &mut PaymentBlindingInputsV1<'_>| i.owner_id[0] ^= 1);
        assert_changed!(|i: &mut PaymentBlindingInputsV1<'_>| i.payment_pubkey_hash[0] ^= 1);
        assert_changed!(|i: &mut PaymentBlindingInputsV1<'_>| i.output_index ^= 1);
        assert_changed!(|i: &mut PaymentBlindingInputsV1<'_>| i.value_spark ^= 1);
        assert_changed!(|i: &mut PaymentBlindingInputsV1<'_>| i.lock_height ^= 1);
        assert_changed!(|i: &mut PaymentBlindingInputsV1<'_>| {
            i.sender_x25519_ephemeral_pk[0] ^= 1;
        });
        assert_changed!(|i: &mut PaymentBlindingInputsV1<'_>| {
            i.ml_kem_1024_ciphertext[0] ^= 1;
        });
        assert_changed!(|i: &mut PaymentBlindingInputsV1<'_>| i.note_nonce[0] ^= 1);
    }
}
