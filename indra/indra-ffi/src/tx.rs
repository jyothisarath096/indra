use indra_cli::{build_transaction, TxParams};
use indra_core::{codec::Decode, types::transaction::TransactionV1};

use crate::{errors::IndraError, wallet::WalletContext};

/// Owned transaction result before transferring heap ownership over FFI.
pub struct BuiltTxOwned {
    pub tx_id: [u8; 32],
    pub tx_bytes: Box<[u8]>,
    pub change_spark: u64,
    pub spent_indices: Box<[usize]>,
}

/// Build and sign an INDRA transaction for a canonical payment address.
pub fn build_with_address(
    recipient_address: &str,
    amount_spark: u64,
    fee_spark: u64,
    sender_classical_seed: [u8; 32],
    sender_pq_sk: &[u8],
    chain_id: &str,
    wallet_context: WalletContext,
) -> Result<BuiltTxOwned, IndraError> {
    let params = TxParams {
        chain_id,
        recipient_address,
        amount_spark,
        fee_spark,
        wallet: &wallet_context.wallet,
        ed25519_seed: sender_classical_seed,
        ml_dsa_seed_bytes: sender_pq_sk.to_vec(),
        sender_pubkey: wallet_context.sender_pubkey,
    };

    let built = build_transaction(&params).map_err(IndraError::from)?;
    let tx_bytes = hex::decode(&built.tx_hex).map_err(|_| IndraError::Internal)?;
    let _ = decode_transaction(&tx_bytes)?;
    let tx_id = tx_id_from_bytes(&tx_bytes);

    let mut spent_indices = Vec::with_capacity(built.spent_utxo_ids.len());
    for utxo_id in &built.spent_utxo_ids {
        let Some(index) = wallet_context.spent_indices_by_utxo.get(utxo_id) else {
            return Err(IndraError::Internal);
        };
        spent_indices.push(*index);
    }

    Ok(BuiltTxOwned {
        tx_id,
        tx_bytes: tx_bytes.into_boxed_slice(),
        change_spark: built.change_spark,
        spent_indices: spent_indices.into_boxed_slice(),
    })
}

/// Encode transaction bytes as a hex string.
pub fn tx_to_hex(tx_bytes: &[u8]) -> String {
    hex::encode(tx_bytes)
}

/// Decode transaction bytes from the built output, validating they form a transaction.
pub fn decode_transaction(tx_bytes: &[u8]) -> Result<TransactionV1, IndraError> {
    TransactionV1::decode_exact(tx_bytes).map_err(|_| IndraError::TxBuildFailed)
}

/// Convert a byte array to a transaction id.
pub fn tx_id_from_bytes(tx_bytes: &[u8]) -> [u8; 32] {
    indra_crypto::sha256(tx_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        codec::Encode,
        types::{
            crypto::{HybridPubKey, HybridSignature},
            primitives::{Bytes32, ProtocolVersion, VariableBytes, TRANSACTION_PROTOCOL_VERSION},
            transaction::{InputV1, OutputV1},
        },
    };

    #[test]
    fn builder_result_validation_rejects_trailing_bytes() {
        let tx = TransactionV1 {
            version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
            signature_module_id: 1,
            inputs: vec![InputV1 {
                utxo_id: Bytes32::from([1; 32]),
            }],
            outputs: vec![OutputV1 {
                value_spark: 100_000,
                owner_pubkey: HybridPubKey {
                    classical_pk: Bytes32::from([2; 32]),
                    pq_pk: VariableBytes::from_slice(&[3; 2592]).unwrap(),
                },
                lock_height: 0,
            }],
            fee_amount: 10_000,
            signature: HybridSignature {
                classical_sig: VariableBytes::from_slice(&[4; 64]).unwrap(),
                pq_sig: VariableBytes::from_slice(&[5; 4627]).unwrap(),
            },
        };
        let mut encoded = tx.encode_to_vec();
        encoded.push(0xAA);
        assert_eq!(decode_transaction(&encoded), Err(IndraError::TxBuildFailed));
    }
}
