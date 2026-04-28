use std::collections::HashMap;

use indra_cli::Wallet;
use indra_core::types::{
    crypto::HybridPubKey,
    primitives::{Bytes32, VariableBytes, MAX_PQ_PK_BYTES},
};
use indra_crypto::hybrid::ClassicalKeypair;

use crate::{errors::IndraError, IndraUtxoEntry};

/// Wallet reconstruction result for FFI transaction building.
pub struct WalletContext {
    pub wallet: Wallet,
    pub sender_pubkey: HybridPubKey,
    pub spent_indices_by_utxo: HashMap<Bytes32, usize>,
}

/// Rebuild a CLI wallet and sender pubkey from FFI parameters.
pub fn build_wallet_context(
    sender_classical_seed: [u8; 32],
    sender_pq_pk: &[u8],
    utxos: &[IndraUtxoEntry],
) -> Result<WalletContext, IndraError> {
    let mut wallet = Wallet::new();
    let mut spent_indices_by_utxo = HashMap::with_capacity(utxos.len());

    for (index, utxo) in utxos.iter().enumerate() {
        let utxo_id = Bytes32::from(utxo.utxo_id);
        wallet.add_utxo(
            utxo_id,
            utxo.value_spark,
            utxo.blinding,
            utxo.created_height,
            utxo.tx_index,
            utxo.out_index,
        );
        if utxo.spent != 0 {
            wallet.mark_spent(&utxo_id);
        }
        spent_indices_by_utxo.insert(utxo_id, index);
    }

    let classical = ClassicalKeypair::from_seed(&sender_classical_seed);
    let pq_pk = VariableBytes::<MAX_PQ_PK_BYTES>::from_slice(sender_pq_pk)
        .map_err(|_| IndraError::InvalidParam)?;
    let sender_pubkey = HybridPubKey {
        classical_pk: Bytes32::from(classical.public_key().0),
        pq_pk,
    };

    Ok(WalletContext {
        wallet,
        sender_pubkey,
        spent_indices_by_utxo,
    })
}
