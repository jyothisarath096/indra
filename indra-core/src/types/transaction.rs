//! Transaction types: InputV1, OutputV1, TransactionV1.
//!
//! Confidential UTXO model:
//! - Output values hidden in Pedersen commitments.
//! - Bulletproofs range proofs: values in [DUST_LIMIT, 2^64).
//! - Nullifiers prevent double-spend without revealing which UTXO was spent.
//! - fee_amount is the ONLY public field (needed for validator fee checking).

use std::collections::BTreeSet;

use crate::{
    codec::{Encode, Decode, ByteReader, encode_list, decode_list, list_encoded_len},
    error::{IndraError, IndraResult},
    types::{
        primitives::{
            Bytes32, ProtocolVersion, VariableBytes,
            DUST_LIMIT_SPARK, MAX_CHAIN_ID_BYTES, MAX_INPUTS, MAX_OUTPUTS,
            MAX_RANGE_PROOF_BYTES,
        },
        crypto::{CommitmentV1, HybridPubKey, HybridSignature},
    },
};
use indra_crypto::sha256;

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
    fn encoded_len(&self) -> usize { 64 }
}

impl Decode for InputV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self { utxo_id: Bytes32::decode(r)?, nullifier: Bytes32::decode(r)? })
    }
}

/// A transaction output: a new UTXO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputV1 {
    /// Public amount in Spark.
    ///
    /// This preserves simple balance accounting for the current node/RPC
    /// implementation while commitments/range proofs still bind the value.
    pub value_spark: u64,
    /// Pedersen commitment to the output value.
    pub commitment:  CommitmentV1,
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
        8
            + self.commitment.encoded_len()
            + self.owner_pubkey.encoded_len()
            + self.range_proof.encoded_len()
            + 8
    }
}

impl Decode for OutputV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            value_spark: u64::decode(r)?,
            commitment:  CommitmentV1::decode(r)?,
            owner_pubkey: HybridPubKey::decode(r)?,
            range_proof: VariableBytes::decode(r)?,
            lock_height: u64::decode(r)?,
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
        if self.inputs.is_empty()  { return Err(IndraError::ZeroInputs);  }
        if self.outputs.is_empty() { return Err(IndraError::ZeroOutputs); }
        if self.inputs.len() > MAX_INPUTS {
            return Err(IndraError::LengthExceeded {
                field: "inputs", max: MAX_INPUTS, actual: self.inputs.len(),
            });
        }
        if self.outputs.len() > MAX_OUTPUTS {
            return Err(IndraError::LengthExceeded {
                field: "outputs", max: MAX_OUTPUTS, actual: self.outputs.len(),
            });
        }
        for output in &self.outputs {
            if output.value_spark < DUST_LIMIT_SPARK {
                return Err(IndraError::BelowDustLimit {
                    value: output.value_spark,
                    limit: DUST_LIMIT_SPARK,
                });
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
                actual: self.fee_amount, minimum: required,
            });
        }
        Ok(())
    }

    /// Canonical bytes covered by the transaction signature.
    pub fn signing_bytes(&self, chain_id: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        VariableBytes::<MAX_CHAIN_ID_BYTES>::from_slice(chain_id.as_bytes())
            .unwrap_or_default()
            .encode(&mut buf);
        self.version.encode(&mut buf);
        self.signature_module_id.encode(&mut buf);
        encode_list(&self.inputs, &mut buf);
        encode_list(&self.outputs, &mut buf);
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
        self.fee_amount.encode(buf);
        self.fee_blinding.encode(buf);
        self.fee_commitment.encode(buf);
        self.signature.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        2 + 2
            + list_encoded_len(&self.inputs)
            + list_encoded_len(&self.outputs)
            + 8 + 32
            + self.fee_commitment.encoded_len()
            + self.signature.encoded_len()
    }
}

impl Decode for TransactionV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            version:              ProtocolVersion::decode(r)?,
            signature_module_id:  u16::decode(r)?,
            inputs:               decode_list(r, MAX_INPUTS, "inputs")?,
            outputs:              decode_list(r, MAX_OUTPUTS, "outputs")?,
            fee_amount:           u64::decode(r)?,
            fee_blinding:         Bytes32::decode(r)?,
            fee_commitment:       CommitmentV1::decode(r)?,
            signature:            HybridSignature::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Decode;

    fn dummy_pubkey() -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::ZERO,
            pq_pk: VariableBytes::from_slice(&[0u8; 1312]).unwrap(),
        }
    }

    fn dummy_sig() -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig:        VariableBytes::from_slice(&[0u8; 2420]).unwrap(),
        }
    }

    fn minimal_tx() -> TransactionV1 {
        TransactionV1 {
            version:             ProtocolVersion::CURRENT,
            signature_module_id: 1,
            inputs:  vec![InputV1 {
                utxo_id:   Bytes32::from([0x01u8; 32]),
                nullifier: Bytes32::from([0x02u8; 32]),
            }],
            outputs: vec![OutputV1 {
                value_spark: 100_000,
                commitment:   CommitmentV1 { compressed_point: Bytes32::from([0x03u8; 32]) },
                owner_pubkey: dummy_pubkey(),
                range_proof:  VariableBytes::from_slice(&[0u8; 674]).unwrap(),
                lock_height:  0,
            }],
            fee_amount:     500,
            fee_blinding:   Bytes32::ZERO,
            fee_commitment: CommitmentV1 { compressed_point: Bytes32::ZERO },
            signature:      dummy_sig(),
        }
    }

    #[test]
    fn tx_round_trip() {
        let tx = minimal_tx();
        assert_eq!(tx, TransactionV1::decode_exact(&tx.encode_to_vec()).unwrap());
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
        // fee_amount=500, weight=1KB, so base_fee=1000 should fail
        assert!(tx.validate_fee(1_000).is_err());
    }

    #[test]
    fn fee_sufficient_passes() {
        let tx = minimal_tx();
        // fee_amount=500, weight=1KB, base_fee=100 → 100 Spark/KB → required=100
        assert!(tx.validate_fee(100).is_ok());
    }

    #[test]
    fn weight_is_nonzero() {
        assert!(minimal_tx().weight_kb() >= 1);
    }

    #[test]
    fn tx_hash_is_deterministic() {
        let tx = minimal_tx();
        assert_eq!(tx.tx_hash(), tx.tx_hash());
    }
}
