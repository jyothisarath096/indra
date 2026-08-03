//! Canonical block-range wallet discovery for ordinary payment outputs.

use indra_core::{
    codec::{Decode, Encode},
    types::{block::BlockV1, crypto::HybridPubKey, primitives::Bytes32},
};
use indra_crypto::{
    commit, derive_tranche_refund_blinding_v1, recipient_derive_payment_blinding_v1, sha256,
    PaymentKeypairV1, TrancheRefundBlindingInputsV1,
};
use indra_state::{utxo::UtxoEntry, UtxoSet};

use crate::{fetch_chain_id, json_string, rpc_call_raw_params, Wallet};

/// Scan canonical blocks from the wallet's saved scan tip and add ordinary
/// payment outputs recoverable by one of `payment_keys`.
pub fn scan_canonical_blocks(
    node_url: &str,
    wallet: &mut Wallet,
    payment_keys: &[PaymentKeypairV1],
    owner_pubkeys: &[HybridPubKey],
) -> Result<usize, String> {
    let chain_id = fetch_chain_id(node_url).map_err(|error| error.to_string())?;
    let mut discovered = 0usize;
    loop {
        let (from_height, expected_parent) = wallet
            .scan_tip()
            .map_or((1, Bytes32::ZERO), |(height, hash)| (height + 1, hash));
        let response = rpc_call_raw_params(
            node_url,
            "indra_getCanonicalBlocks",
            &[
                from_height.to_string(),
                "25".to_string(),
                json_string(&hex::encode(expected_parent.0)),
            ],
        )
        .map_err(|error| error.to_string())?;

        if response.contains("canonical parent mismatch") {
            let Some((height, _)) = wallet.scan_tip() else {
                return Err("canonical chain rejected the genesis scan anchor".to_string());
            };
            wallet.rollback_scan_from(height);
            continue;
        }
        if response.contains("exceeds current tip") || response.contains("not retained") {
            break;
        }
        let blocks = canonical_blocks_from_rpc(&response)?;
        let refunds = tranche_refunds_from_rpc(&response)?;
        if blocks.is_empty() {
            break;
        }
        for entry in refunds {
            discovered += scan_tranche_refund(wallet, &entry, owner_pubkeys, chain_id.as_bytes())?;
        }
        for block in blocks {
            if block.header.prev_hash != expected_scan_parent(wallet) {
                wallet.rollback_scan_from(block.header.height.saturating_sub(1));
                return Err(format!(
                    "non-contiguous canonical block page at height {}",
                    block.header.height
                ));
            }
            discovered += scan_canonical_block(wallet, &block, payment_keys, chain_id.as_bytes())?;
            wallet.record_scanned_block(block.header.height, block.header.block_hash());
        }
        if response.contains("\"next_height\":null") {
            break;
        }
    }
    Ok(discovered)
}

fn scan_tranche_refund(
    wallet: &mut Wallet,
    entry: &UtxoEntry,
    owner_pubkeys: &[HybridPubKey],
    chain_id: &[u8],
) -> Result<usize, String> {
    let Some(event) = &entry.tranche_refund else {
        return Ok(0);
    };
    if !owner_pubkeys
        .iter()
        .any(|owner| owner == &entry.output.owner_pubkey)
    {
        return Ok(0);
    }
    let custody = event.custody.encode_to_vec();
    let blinding = derive_tranche_refund_blinding_v1(&TrancheRefundBlindingInputsV1 {
        chain_id,
        position_id: event.position_id.0,
        tranche_id: event.tranche_id.0,
        principal_owner_id: event.principal_owner_id.0,
        custody_encoding: &custody,
        principal_spark: event.principal_spark,
        release_height: event.release_height,
        end_epoch: event.end_epoch,
    })
    .map_err(|error| format!("tranche refund derivation failed: {error}"))?;
    if commit(entry.output.value_spark, &blinding).0 != entry.output.commitment.compressed_point.0 {
        return Err("tranche refund provenance does not open output commitment".to_string());
    }
    if wallet.contains(&entry.utxo_id) {
        return Ok(0);
    }
    wallet.add_utxo(
        entry.utxo_id,
        entry.output.value_spark,
        blinding,
        entry.created_height,
        entry.tx_index,
        entry.output_index,
    );
    Ok(1)
}

/// Apply one canonical block to ordinary-payment wallet discovery.
pub fn scan_canonical_block(
    wallet: &mut Wallet,
    block: &BlockV1,
    payment_keys: &[PaymentKeypairV1],
    chain_id: &[u8],
) -> Result<usize, String> {
    let mut discovered = 0usize;
    for (transaction_index, transaction) in block.transactions.iter().enumerate() {
        let transaction_index = u32::try_from(transaction_index)
            .map_err(|_| "transaction index exceeds u32".to_string())?;
        for input in &transaction.inputs {
            wallet.mark_spent_at_height(&input.utxo_id, block.header.height);
        }
        for (output_index, (output, note)) in transaction
            .outputs
            .iter()
            .zip(&transaction.payment_notes)
            .enumerate()
        {
            let owner_id = sha256(&output.owner_pubkey.classical_pk.0);
            if note.owner_id != owner_id {
                return Err("payment note owner ID does not match canonical output".to_string());
            }
            let Some(keypair) = payment_keys
                .iter()
                .find(|keypair| keypair.public_key().hash() == note.payment_pubkey_hash)
            else {
                continue;
            };
            let output_index =
                u32::try_from(output_index).map_err(|_| "output index exceeds u32".to_string())?;
            let recovered = recipient_derive_payment_blinding_v1(
                keypair,
                note,
                chain_id,
                output_index,
                output.value_spark,
                output.lock_height,
            )
            .map_err(|error| format!("payment note derivation failed: {error}"))?;
            if commit(output.value_spark, &recovered.blinding).0
                != output.commitment.compressed_point.0
            {
                return Err("payment note does not open output commitment".to_string());
            }
            let utxo_id = UtxoSet::compute_utxo_id(
                output,
                block.header.height,
                transaction_index,
                output_index,
            );
            if !wallet.contains(&utxo_id) {
                wallet.add_utxo(
                    utxo_id,
                    output.value_spark,
                    recovered.blinding,
                    block.header.height,
                    transaction_index,
                    output_index,
                );
                discovered += 1;
            }
        }
    }
    Ok(discovered)
}

fn expected_scan_parent(wallet: &Wallet) -> Bytes32 {
    wallet.scan_tip().map_or(Bytes32::ZERO, |(_, hash)| hash)
}

fn canonical_blocks_from_rpc(json: &str) -> Result<Vec<BlockV1>, String> {
    let mut blocks = Vec::new();
    let mut remaining = json;
    let marker = "\"block_hex\":\"";
    while let Some(start) = remaining.find(marker) {
        let encoded = &remaining[start + marker.len()..];
        let end = encoded
            .find('"')
            .ok_or_else(|| "unterminated block_hex in RPC response".to_string())?;
        let bytes = hex::decode(&encoded[..end]).map_err(|_| "invalid block_hex".to_string())?;
        blocks.push(
            BlockV1::decode_exact(&bytes)
                .map_err(|error| format!("invalid canonical block encoding: {error}"))?,
        );
        remaining = &encoded[end + 1..];
    }
    Ok(blocks)
}

fn tranche_refunds_from_rpc(json: &str) -> Result<Vec<UtxoEntry>, String> {
    let mut entries = Vec::new();
    let mut remaining = json;
    let marker = "\"utxo_hex\":\"";
    while let Some(start) = remaining.find(marker) {
        let encoded = &remaining[start + marker.len()..];
        let end = encoded
            .find('"')
            .ok_or_else(|| "unterminated utxo_hex in RPC response".to_string())?;
        let bytes = hex::decode(&encoded[..end]).map_err(|_| "invalid utxo_hex".to_string())?;
        let entry = UtxoEntry::decode_exact(&bytes)
            .map_err(|error| format!("invalid canonical protocol UTXO encoding: {error}"))?;
        if entry.tranche_refund.is_none() {
            return Err("canonical protocol output lacks tranche refund provenance".to_string());
        }
        entries.push(entry);
        remaining = &encoded[end + 1..];
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        types::{
            crypto::CommitmentV1,
            stake_position::{PositionCustodyV1, TrancheRefundEventV1},
            transaction::OutputV1,
        },
        VariableBytes,
    };
    use indra_crypto::{derive_tranche_refund_blinding_v1, TrancheRefundBlindingInputsV1};

    #[test]
    fn canonical_scan_recovers_tranche_refund_from_embedded_provenance() {
        let chain_id = b"scan-test";
        let owner_id = Bytes32::from([4; 32]);
        let custody = PositionCustodyV1::DelegatorIdentity {
            delegator_id: owner_id,
        };
        let custody_encoding = custody.encode_to_vec();
        let position_id = Bytes32::from([1; 32]);
        let tranche_id = Bytes32::from([2; 32]);
        let principal_spark = 50;
        let release_height = 300;
        let end_epoch = 1;
        let blinding = derive_tranche_refund_blinding_v1(&TrancheRefundBlindingInputsV1 {
            chain_id,
            position_id: position_id.0,
            tranche_id: tranche_id.0,
            principal_owner_id: owner_id.0,
            custody_encoding: &custody_encoding,
            principal_spark,
            release_height,
            end_epoch,
        })
        .unwrap();
        let owner_pubkey = HybridPubKey {
            classical_pk: Bytes32::from([7; 32]),
            pq_pk: VariableBytes::from_slice(&[8; 32]).unwrap(),
        };
        let output = OutputV1 {
            value_spark: principal_spark,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from(commit(principal_spark, &blinding).0),
            },
            owner_pubkey: owner_pubkey.clone(),
            range_proof: VariableBytes::from_slice(&[9]).unwrap(),
            lock_height: 0,
        };
        let refund_utxo_id = UtxoSet::compute_utxo_id(&output, release_height, 0, 0);
        let entry = UtxoEntry {
            utxo_id: refund_utxo_id,
            output,
            created_height: release_height,
            tx_index: 0,
            output_index: 0,
            tranche_refund: Some(TrancheRefundEventV1 {
                refund_utxo_id,
                position_id,
                tranche_id,
                principal_owner_id: owner_id,
                custody,
                principal_spark,
                release_height,
                end_epoch,
            }),
        };
        let mut wallet = Wallet::new();
        assert_eq!(
            scan_tranche_refund(&mut wallet, &entry, &[owner_pubkey], chain_id).unwrap(),
            1
        );
        assert_eq!(wallet.balance(), principal_spark);
        assert_eq!(
            scan_tranche_refund(&mut wallet, &entry, &[], chain_id).unwrap(),
            0
        );
    }
}
