//! Transaction types: InputV1, OutputV1, TransactionV1.
//!
//! Transparent-value UTXO model. Values and ownership keys are public;
//! checked integer conservation, dust validation, signatures, and atomic UTXO consumption
//! provide the monetary and ownership invariants.

use crate::{
    codec::{decode_list, encode_list, list_encoded_len, ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    types::{
        crypto::{HybridPubKey, HybridSignature},
        primitives::{
            Bytes32, ProtocolVersion, VariableBytes, DUST_LIMIT_SPARK, MAX_CHAIN_ID_BYTES,
            MAX_INPUTS, MAX_OUTPUTS, TRANSACTION_PROTOCOL_VERSION,
        },
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
}

impl Encode for InputV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.utxo_id.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        32
    }
}

impl Decode for InputV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            utxo_id: Bytes32::decode(r)?,
        })
    }
}

/// A transaction output: a new UTXO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputV1 {
    /// Public, authoritative value in Spark for this output.
    pub value_spark: u64,
    /// Owner's hybrid public key (required to spend this output).
    pub owner_pubkey: HybridPubKey,
    /// Block height at which this output unlocks (0 = immediately spendable).
    pub lock_height: u64,
}

impl Encode for OutputV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.value_spark.encode(buf);
        self.owner_pubkey.encode(buf);
        self.lock_height.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        8 + self.owner_pubkey.encoded_len() + 8
    }
}

impl Decode for OutputV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            value_spark: u64::decode(r)?,
            owner_pubkey: HybridPubKey::decode(r)?,
            lock_height: u64::decode(r)?,
        })
    }
}

/// A complete canonical INDRA transaction.
///
/// Values, ownership keys, and fees are public. Validators enforce checked
/// input/output/fee conservation and the configured fee floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionV1 {
    /// Must equal [`TRANSACTION_PROTOCOL_VERSION`].
    pub version: ProtocolVersion,
    /// Identifies the signature module (must be a registered module ID).
    pub signature_module_id: u16,
    /// Inputs consumed (1–16).
    pub inputs: Vec<InputV1>,
    /// Outputs created (1–16).
    pub outputs: Vec<OutputV1>,
    /// PUBLIC: fee in Spark. Validators verify this covers the base fee.
    pub fee_amount: u64,
    /// Hybrid signature over the transaction hash (all fields excluding signature).
    pub signature: HybridSignature,
}

impl TransactionV1 {
    /// Validate structural rules (does NOT verify crypto).
    pub fn validate_structure(&self) -> IndraResult<()> {
        self.validate_structure_with_dust(DUST_LIMIT_SPARK)
    }

    /// Validate structural rules using the dust floor frozen from block pre-state.
    pub fn validate_structure_with_dust(&self, dust_limit_spark: u64) -> IndraResult<()> {
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
        if self.version.0 != TRANSACTION_PROTOCOL_VERSION {
            return Err(IndraError::UnsupportedVersion {
                version: self.version.0,
            });
        }
        Ok(())
    }

    /// Transaction weight in KB (rounded up). Used for fee calculation.
    pub fn weight_kb(&self) -> u64 {
        let bytes = self.encoded_len() as u64;
        bytes.div_ceil(1024)
    }

    /// Canonical bytes covered by the transaction signature.
    pub fn signing_bytes(&self, chain_id: &str) -> IndraResult<Vec<u8>> {
        use indra_crypto::hash::domains::TX_SIGN;

        let mut buf = Vec::new();
        buf.extend_from_slice(TX_SIGN);
        VariableBytes::<MAX_CHAIN_ID_BYTES>::from_slice(chain_id.as_bytes())?.encode(&mut buf);
        self.version.encode(&mut buf);
        self.signature_module_id.encode(&mut buf);
        encode_list(&self.inputs, &mut buf);
        encode_list(&self.outputs, &mut buf);
        self.fee_amount.encode(&mut buf);
        Ok(buf)
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
        self.signature.encode(buf);
    }
    fn encoded_len(&self) -> usize {
        2 + 2
            + list_encoded_len(&self.inputs)
            + list_encoded_len(&self.outputs)
            + 8
            + self.signature.encoded_len()
    }
}

impl Decode for TransactionV1 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let version = ProtocolVersion::decode(r)?;
        let signature_module_id = u16::decode(r)?;
        let inputs = decode_list(r, MAX_INPUTS, "inputs")?;
        let outputs = decode_list(r, MAX_OUTPUTS, "outputs")?;
        if version.0 != TRANSACTION_PROTOCOL_VERSION {
            return Err(IndraError::UnsupportedVersion { version: version.0 });
        }
        Ok(Self {
            version,
            signature_module_id,
            inputs,
            outputs,
            fee_amount: u64::decode(r)?,
            signature: HybridSignature::decode(r)?,
        })
    }
}

#[cfg(test)]
mod transparent_transaction_tests {
    use super::*;
    use crate::codec::{Decode, Encode};
    use crate::types::primitives::{Bytes32, VariableBytes, TRANSACTION_PROTOCOL_VERSION};

    fn signature() -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0; 4627]).unwrap(),
        }
    }

    #[test]
    fn transparent_output_and_transaction_round_trip() {
        let output = OutputV1 {
            value_spark: u64::MAX,
            owner_pubkey: HybridPubKey {
                classical_pk: Bytes32::from([3; 32]),
                pq_pk: VariableBytes::from_slice(&[4; 2592]).unwrap(),
            },
            lock_height: 9,
        };
        let tx = TransactionV1 {
            version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
            signature_module_id: 1,
            inputs: vec![InputV1 {
                utxo_id: Bytes32::from([1; 32]),
            }],
            outputs: vec![output],
            fee_amount: 7,
            signature: signature(),
        };
        assert_eq!(
            TransactionV1::decode_exact(&tx.encode_to_vec()).unwrap(),
            tx
        );
    }

    fn minimal_tx() -> TransactionV1 {
        TransactionV1 {
            version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
            signature_module_id: 1,
            inputs: vec![InputV1 {
                utxo_id: Bytes32::from([0x01; 32]),
            }],
            outputs: vec![OutputV1 {
                value_spark: 100_000,
                owner_pubkey: HybridPubKey {
                    classical_pk: Bytes32::ZERO,
                    pq_pk: VariableBytes::from_slice(&[0; 2592]).unwrap(),
                },
                lock_height: 0,
            }],
            fee_amount: 500,
            signature: signature(),
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
    fn weight_is_nonzero() {
        assert!(minimal_tx().weight_kb() >= 1);
    }

    #[test]
    fn structural_validation_uses_caller_frozen_dust_floor() {
        let tx = minimal_tx();
        assert!(tx.validate_structure_with_dust(100_000).is_ok());
        assert!(matches!(
            tx.validate_structure_with_dust(200_000),
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
    fn transaction_signing_bytes_include_domain() {
        let tx = minimal_tx();
        let signing_bytes = tx.signing_bytes("indra-testnet-1").unwrap();
        assert!(signing_bytes.starts_with(indra_crypto::hash::domains::TX_SIGN));
    }

    #[test]
    fn transaction_signing_rejects_overlong_chain_id() {
        let tx = minimal_tx();
        let chain_id = "x".repeat(MAX_CHAIN_ID_BYTES + 1);
        assert!(tx.signing_bytes(&chain_id).is_err());
    }
}
