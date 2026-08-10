//! Transaction types: InputV1, OutputV1, TransactionV1.
//!
//! Confidential UTXO model:
//! - Output values hidden in Pedersen commitments.
//! - Bulletproofs range proofs: values in [DUST_LIMIT, 2^64).
//! - Nullifiers prevent double-spend without revealing which UTXO was spent.
//! - fee_amount is the ONLY public field (needed for validator fee checking).

use std::collections::BTreeSet;

use crate::{
    codec::{decode_list, encode_list, list_encoded_len, ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    types::{
        crypto::{CommitmentV1, HybridPubKey, HybridSignature},
        primitives::{
            Bytes32, ProtocolVersion, VariableBytes, DUST_LIMIT_SPARK, MAX_CHAIN_ID_BYTES,
            MAX_INPUTS, MAX_OUTPUTS, MAX_RANGE_PROOF_BYTES,
            TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES,
        },
    },
};
use indra_crypto::{sha256, PaymentBlindingNoteV1};

/// Transaction ID = SHA-256 of the canonical transaction encoding.
pub type TxId = Bytes32;

/// A transaction input: a spent UTXO reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputV1 {
    /// ID of the UTXO being spent.
    pub utxo_id: Bytes32,
    /// Spend nullifier: SHA-256(secret_key || utxo_id).
    pub nullifier: Bytes32,
}

impl Encode for InputV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.utxo_id.encode(buf);
        self.nullifier.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        64
    }
}

impl Decode for InputV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            utxo_id: Bytes32::decode(r)?,
            nullifier: Bytes32::decode(r)?,
        })
    }
}

/// A transaction output: a new UTXO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputV1 {
    /// Public value in Spark for this output.
    ///
    /// WARNING: this field is NOT individually proven to match the Pedersen
    /// commitment. The aggregate commitment balance equation (`verify_balance`)
    /// prevents inflation across the full transaction, but individual output
    /// public values are unverified metadata. Code that consumes this field for
    /// economic decisions (for example, stake-deposit amounts) must not trust it
    /// as a commitment opening without additional verification, or must only use
    /// it where the aggregate balance guarantee is sufficient.
    pub value_spark: u64,
    /// Pedersen commitment to the output value.
    pub commitment: CommitmentV1,
    /// Owner's hybrid public key (required to spend this output).
    pub owner_pubkey: HybridPubKey,
    /// Bulletproof range proof: value ∈ [DUST_LIMIT, 2^64).
    pub range_proof: VariableBytes<MAX_RANGE_PROOF_BYTES>,
    /// Block height at which this output unlocks (0 = immediately spendable).
    pub lock_height: u64,
}

impl Encode for OutputV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.value_spark.encode(buf);
        self.commitment.encode(buf);
        self.owner_pubkey.encode(buf);
        self.range_proof.encode(buf);
        self.lock_height.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        8 + self.commitment.encoded_len()
            + self.owner_pubkey.encoded_len()
            + self.range_proof.encoded_len()
            + 8
    }
}

impl Decode for OutputV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            value_spark: u64::decode(r)?,
            commitment: CommitmentV1::decode(r)?,
            owner_pubkey: HybridPubKey::decode(r)?,
            range_proof: VariableBytes::decode(r)?,
            lock_height: u64::decode(r)?,
        })
    }
}

impl Encode for PaymentBlindingNoteV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&PaymentBlindingNoteV1::encode(self));
    }

    fn encoded_len(&self) -> usize {
        indra_crypto::PAYMENT_NOTE_V1_ENCODED_LEN
    }
}

impl Decode for PaymentBlindingNoteV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let bytes = r.read_bytes(indra_crypto::PAYMENT_NOTE_V1_ENCODED_LEN)?;
        PaymentBlindingNoteV1::decode(bytes).map_err(|_| {
            IndraError::InvalidTransaction(
                "payment_notes contains malformed payment blinding note".into(),
            )
        })
    }
}

/// A complete INDRA v1 transaction.
///
/// Fee privacy model (Spec Section C4):
///   fee_amount   — PUBLIC. Validators verify ≥ base_fee × weight.
///   fee_blinding — Pedersen blinding factor for the fee commitment.
///   fee_commitment = Commit(fee_amount, fee_blinding)
///   Transfer amounts in inputs/outputs remain fully private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionV1 {
    /// Must equal PROTOCOL_VERSION.
    pub version: ProtocolVersion,
    /// Identifies the signature module (must be a registered module ID).
    pub signature_module_id: u16,
    /// Inputs consumed (1–16).
    pub inputs: Vec<InputV1>,
    /// Outputs created (1–16).
    pub outputs: Vec<OutputV1>,
    /// Mandatory payment-blinding delivery note corresponding to each output.
    pub payment_notes: Vec<PaymentBlindingNoteV1>,
    /// PUBLIC: fee in Spark. Validators verify this covers the base fee.
    pub fee_amount: u64,
    /// Pedersen blinding factor for the fee commitment.
    pub fee_blinding: Bytes32,
    /// Pedersen commitment: Commit(fee_amount, fee_blinding).
    pub fee_commitment: CommitmentV1,
    /// Hybrid signature over the transaction hash (all fields excluding signature).
    pub signature: HybridSignature,
}

impl TransactionV1 {
    /// Validate structural rules (does NOT verify crypto).
    pub fn validate_structure(&self) -> IndraResult<()> {
        self.validate_structure_at_height(u64::MAX)
    }

    /// Validate structural rules under the transaction format active at `height`.
    pub fn validate_structure_at_height(&self, height: u64) -> IndraResult<()> {
        self.validate_structure_at_height_with_dust(height, DUST_LIMIT_SPARK)
    }

    /// Validate structural rules using the dust floor frozen from block pre-state.
    pub fn validate_structure_at_height_with_dust(
        &self,
        height: u64,
        dust_limit_spark: u64,
    ) -> IndraResult<()> {
        if self.inputs.is_empty() {
            return Err(IndraError::ZeroInputs);
        }
        if self.outputs.is_empty() {
            return Err(IndraError::ZeroOutputs);
        }
        if self.inputs.len() > MAX_INPUTS {
            return Err(IndraError::LengthExceeded {
                field: "inputs",
                max: MAX_INPUTS,
                actual: self.inputs.len(),
            });
        }
        if self.outputs.len() > MAX_OUTPUTS {
            return Err(IndraError::LengthExceeded {
                field: "outputs",
                max: MAX_OUTPUTS,
                actual: self.outputs.len(),
            });
        }
        for output in &self.outputs {
            if output.value_spark < dust_limit_spark {
                return Err(IndraError::BelowDustLimit {
                    value: output.value_spark,
                    limit: dust_limit_spark,
                });
            }
        }
        let _ = height;
        if self.version.0 != TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES {
            return Err(IndraError::UnsupportedVersion {
                version: self.version.0,
            });
        }
        if self.payment_notes.len() != self.outputs.len() {
            return Err(IndraError::InvalidTransaction(
                "payment_notes length must equal outputs length".into(),
            ));
        }
        for (output, note) in self.outputs.iter().zip(&self.payment_notes) {
            if note.owner_id != sha256(&output.owner_pubkey.classical_pk.0) {
                return Err(IndraError::InvalidTransaction(
                    "payment note owner_id does not match output owner".into(),
                ));
            }
        }
        // No duplicate nullifiers within this transaction
        let mut seen: BTreeSet<Bytes32> = BTreeSet::new();
        for input in &self.inputs {
            if !seen.insert(input.nullifier) {
                return Err(IndraError::DuplicateNullifier);
            }
        }
        Ok(())
    }

    /// Transaction weight in KB (rounded up). Used for fee calculation.
    pub fn weight_kb(&self) -> u64 {
        let bytes = self.encoded_len() as u64;
        bytes.div_ceil(1024)
    }

    /// Validate the fee is sufficient given the current base fee.
    pub fn validate_fee(&self, base_fee_spark_per_kb: u64) -> IndraResult<()> {
        let required = base_fee_spark_per_kb.saturating_mul(self.weight_kb());
        if self.fee_amount < required {
            return Err(IndraError::FeeTooLow {
                actual: self.fee_amount,
                minimum: required,
            });
        }
        Ok(())
    }

    /// Canonical bytes covered by the transaction signature.
    pub fn signing_bytes(&self, chain_id: &str) -> Vec<u8> {
        use indra_crypto::hash::domains::TX_SIGN;

        let mut buf = Vec::new();
        buf.extend_from_slice(TX_SIGN);
        VariableBytes::<MAX_CHAIN_ID_BYTES>::from_slice(chain_id.as_bytes())
            .unwrap_or_default()
            .encode(&mut buf);
        self.version.encode(&mut buf);
        self.signature_module_id.encode(&mut buf);
        encode_list(&self.inputs, &mut buf);
        encode_list(&self.outputs, &mut buf);
        encode_list(&self.payment_notes, &mut buf);
        self.fee_amount.encode(&mut buf);
        self.fee_blinding.encode(&mut buf);
        self.fee_commitment.encode(&mut buf);
        buf
    }

    /// Canonical transaction hash including signatures.
    pub fn tx_hash(&self) -> TxId {
        TxId::from(sha256(&self.encode_to_vec()))
    }
}

impl Encode for TransactionV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.version.encode(buf);
        self.signature_module_id.encode(buf);
        encode_list(&self.inputs, buf);
        encode_list(&self.outputs, buf);
        encode_list(&self.payment_notes, buf);
        self.fee_amount.encode(buf);
        self.fee_blinding.encode(buf);
        self.fee_commitment.encode(buf);
        self.signature.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        2 + 2
            + list_encoded_len(&self.inputs)
            + list_encoded_len(&self.outputs)
            + list_encoded_len(&self.payment_notes)
            + 8
            + 32
            + self.fee_commitment.encoded_len()
            + self.signature.encoded_len()
    }
}

impl Decode for TransactionV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let version = ProtocolVersion::decode(r)?;
        let signature_module_id = u16::decode(r)?;
        let inputs = decode_list(r, MAX_INPUTS, "inputs")?;
        let outputs = decode_list(r, MAX_OUTPUTS, "outputs")?;
        if version.0 != TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES {
            return Err(IndraError::UnsupportedVersion { version: version.0 });
        }
        let payment_notes = decode_list(r, MAX_OUTPUTS, "payment_notes")?;
        Ok(Self {
            version,
            signature_module_id,
            inputs,
            outputs,
            payment_notes,
            fee_amount: u64::decode(r)?,
            fee_blinding: Bytes32::decode(r)?,
            fee_commitment: CommitmentV1::decode(r)?,
            signature: HybridSignature::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Decode;
    use crate::codec::Encode;

    fn dummy_pubkey() -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::ZERO,
            pq_pk: VariableBytes::from_slice(&[0u8; 2592]).unwrap(),
        }
    }

    fn dummy_sig() -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
        }
    }

    fn minimal_tx() -> TransactionV1 {
        TransactionV1 {
            version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES),
            signature_module_id: 1,
            inputs: vec![InputV1 {
                utxo_id: Bytes32::from([0x01u8; 32]),
                nullifier: Bytes32::from([0x02u8; 32]),
            }],
            outputs: vec![OutputV1 {
                value_spark: 100_000,
                commitment: CommitmentV1 {
                    compressed_point: Bytes32::from([0x03u8; 32]),
                },
                owner_pubkey: dummy_pubkey(),
                range_proof: VariableBytes::from_slice(&[0u8; 674]).unwrap(),
                lock_height: 0,
            }],
            payment_notes: vec![note_for_owner(sha256(&[0u8; 32]), 0x10)],
            fee_amount: 500,
            fee_blinding: Bytes32::ZERO,
            fee_commitment: CommitmentV1 {
                compressed_point: Bytes32::ZERO,
            },
            signature: dummy_sig(),
        }
    }

    fn note_for_owner(owner_id: [u8; 32], seed: u8) -> PaymentBlindingNoteV1 {
        PaymentBlindingNoteV1 {
            version: indra_crypto::PAYMENT_VERSION_V1,
            owner_id,
            payment_pubkey_hash: [seed.wrapping_add(1); 32],
            sender_x25519_ephemeral_pk: [seed.wrapping_add(2); 32],
            ml_kem_1024_ciphertext: [seed.wrapping_add(3); 1568],
            note_nonce: [seed.wrapping_add(4); 32],
        }
    }

    #[test]
    fn tx_round_trip() {
        let tx = minimal_tx();
        assert_eq!(
            tx,
            TransactionV1::decode_exact(&tx.encode_to_vec()).unwrap()
        );
    }

    #[test]
    fn zero_inputs_rejected() {
        let mut tx = minimal_tx();
        tx.inputs.clear();
        assert_eq!(tx.validate_structure(), Err(IndraError::ZeroInputs));
    }

    #[test]
    fn zero_outputs_rejected() {
        let mut tx = minimal_tx();
        tx.outputs.clear();
        assert_eq!(tx.validate_structure(), Err(IndraError::ZeroOutputs));
    }

    #[test]
    fn duplicate_nullifier_rejected() {
        let mut tx = minimal_tx();
        tx.inputs.push(tx.inputs[0].clone());
        assert_eq!(tx.validate_structure(), Err(IndraError::DuplicateNullifier));
    }

    #[test]
    fn fee_too_low_rejected() {
        let tx = minimal_tx();
        let base_fee = tx.fee_amount.saturating_add(1);
        assert!(tx.validate_fee(base_fee).is_err());
    }

    #[test]
    fn fee_sufficient_passes() {
        let mut tx = minimal_tx();
        tx.fee_amount = tx.weight_kb().saturating_mul(100);
        assert!(tx.validate_fee(100).is_ok());
    }

    #[test]
    fn weight_is_nonzero() {
        assert!(minimal_tx().weight_kb() >= 1);
    }

    #[test]
    fn structural_validation_uses_caller_frozen_dust_floor() {
        let tx = minimal_tx();
        assert!(tx
            .validate_structure_at_height_with_dust(u64::MAX, 100_000)
            .is_ok());
        assert!(matches!(
            tx.validate_structure_at_height_with_dust(u64::MAX, 200_000),
            Err(IndraError::BelowDustLimit {
                value: 100_000,
                limit: 200_000
            })
        ));
    }

    #[test]
    fn tx_hash_is_deterministic() {
        let tx = minimal_tx();
        assert_eq!(tx.tx_hash(), tx.tx_hash());
    }

    #[test]
    fn canonical_transaction_encoding_includes_mandatory_notes() {
        let tx = minimal_tx();
        let mut expected = Vec::new();
        tx.version.encode(&mut expected);
        tx.signature_module_id.encode(&mut expected);
        encode_list(&tx.inputs, &mut expected);
        encode_list(&tx.outputs, &mut expected);
        encode_list(&tx.payment_notes, &mut expected);
        tx.fee_amount.encode(&mut expected);
        tx.fee_blinding.encode(&mut expected);
        tx.fee_commitment.encode(&mut expected);
        tx.signature.encode(&mut expected);

        assert_eq!(tx.encode_to_vec(), expected);

        let mut expected_signing = Vec::new();
        expected_signing.extend_from_slice(indra_crypto::hash::domains::TX_SIGN);
        VariableBytes::<MAX_CHAIN_ID_BYTES>::from_slice(b"indra-testnet-1")
            .unwrap()
            .encode(&mut expected_signing);
        tx.version.encode(&mut expected_signing);
        tx.signature_module_id.encode(&mut expected_signing);
        encode_list(&tx.inputs, &mut expected_signing);
        encode_list(&tx.outputs, &mut expected_signing);
        encode_list(&tx.payment_notes, &mut expected_signing);
        tx.fee_amount.encode(&mut expected_signing);
        tx.fee_blinding.encode(&mut expected_signing);
        tx.fee_commitment.encode(&mut expected_signing);
        assert_eq!(tx.signing_bytes("indra-testnet-1"), expected_signing);
    }

    #[test]
    fn mandatory_payment_notes_round_trip() {
        let mut tx = minimal_tx();
        tx.outputs.push(tx.outputs[0].clone());
        tx.payment_notes
            .push(note_for_owner(sha256(&[0u8; 32]), 0x11));

        let decoded = TransactionV1::decode_exact(&tx.encode_to_vec()).unwrap();
        assert_eq!(decoded, tx);
        assert!(decoded.validate_structure_at_height(u64::MAX).is_ok());
    }

    #[test]
    fn transaction_v2_rejects_payment_note_length_mismatch() {
        let mut tx = minimal_tx();
        tx.payment_notes.clear();

        assert_eq!(
            tx.validate_structure_at_height(u64::MAX),
            Err(IndraError::InvalidTransaction(
                "payment_notes length must equal outputs length".into()
            ))
        );
    }

    #[test]
    fn payment_notes_are_not_height_gated() {
        let mut tx = minimal_tx();
        tx.payment_notes[0].note_nonce = [0x30; 32];
        assert!(tx.validate_structure_at_height(0).is_ok());
        assert!(tx.validate_structure_at_height(u64::MAX).is_ok());
    }

    #[test]
    fn payment_note_owner_mismatch_is_rejected() {
        let mut tx = minimal_tx();
        tx.payment_notes[0].owner_id = [0x40; 32];
        assert!(matches!(
            tx.validate_structure(),
            Err(IndraError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn payment_notes_are_bound_to_signing_bytes_and_transaction_id() {
        let mut left = minimal_tx();
        left.payment_notes[0].note_nonce = [0x50; 32];

        let mut right = left.clone();
        right.payment_notes[0].note_nonce = [0x51; 32];

        assert_ne!(
            left.signing_bytes("indra-testnet-1"),
            right.signing_bytes("indra-testnet-1")
        );
        assert_ne!(left.tx_hash(), right.tx_hash());
    }

    #[test]
    fn transaction_signing_bytes_include_domain() {
        let tx = minimal_tx();
        let signing_bytes = tx.signing_bytes("indra-testnet-1");
        assert!(signing_bytes.starts_with(indra_crypto::hash::domains::TX_SIGN));
    }
}
