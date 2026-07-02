use indra_cli::{build_transaction, TxParams};
use indra_core::{codec::Decode, types::transaction::TransactionV1};

use crate::{errors::IndraError, wallet::WalletContext};

/// Owned transaction result before transferring heap ownership over FFI.
pub struct BuiltTxOwned {
    pub tx_id: [u8; 32],
    pub tx_bytes: Box<[u8]>,
    pub change_spark: u64,
    pub change_blinding: [u8; 32],
    pub spent_indices: Box<[usize]>,
}

/// Build and sign an INDRA transaction from safe Rust inputs.
pub fn build(
    recipient_classical_pk: [u8; 32],
    amount_spark: u64,
    fee_spark: u64,
    sender_classical_seed: [u8; 32],
    sender_pq_sk: &[u8],
    wallet_context: WalletContext,
) -> Result<BuiltTxOwned, IndraError> {
    let recipient_pubkey_hex = hex::encode(recipient_classical_pk);
    let mut params = TxParams {
        chain_id: indra_core::types::primitives::DEFAULT_CHAIN_ID,
        recipient_pubkey_hex: &recipient_pubkey_hex,
        amount_spark,
        fee_spark,
        wallet: &wallet_context.wallet,
        hybrid_seed: sender_classical_seed,
        pq_sk_bytes: sender_pq_sk.to_vec(),
        sender_pubkey: wallet_context.sender_pubkey,
    };

    let built = match build_transaction(&params) {
        Ok(built) => built,
        Err(error) => {
            params.hybrid_seed.fill(0);
            params.pq_sk_bytes.fill(0);
            return Err(IndraError::from(error));
        }
    };
    params.hybrid_seed.fill(0);
    params.pq_sk_bytes.fill(0);
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
        change_blinding: built.change_blinding.unwrap_or([0u8; 32]),
        spent_indices: spent_indices.into_boxed_slice(),
    })
}

/// Encode transaction bytes as a hex string.
pub fn tx_to_hex(tx_bytes: &[u8]) -> String {
    hex::encode(tx_bytes)
}

/// Decode transaction bytes from the built output, validating they form a transaction.
pub fn decode_transaction(tx_bytes: &[u8]) -> Result<TransactionV1, IndraError> {
    let mut reader = indra_core::codec::ByteReader::new(tx_bytes);
    TransactionV1::decode(&mut reader).map_err(|_| IndraError::TxBuildFailed)
}

/// Convert a byte array to a transaction id.
pub fn tx_id_from_bytes(tx_bytes: &[u8]) -> [u8; 32] {
    indra_crypto::sha256(tx_bytes)
}
