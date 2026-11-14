//! Canonical block-range wallet discovery for ordinary payment outputs.

use indra_core::{
    codec::Decode,
    types::{block::BlockVNext, crypto::HybridPubKey, primitives::Bytes32},
};
use indra_state::{utxo::UtxoEntry, UtxoSet};
#[cfg(not(test))]
use std::time::{Duration, Instant};

use crate::{build_scan_authorization, json_string, rpc_call_raw_params, KeysFile, Wallet};

/// Maximum number of canonical blocks requested per RPC page.
pub const CANONICAL_SCAN_PAGE_SIZE: u64 = 25;

fn format_scan_progress(current_height: u64, tip_height: u64) -> String {
    format!("Scanning canonical blocks: height {current_height}/{tip_height}")
}

/// Scan canonical blocks from the wallet's saved scan tip and add ordinary
/// payment outputs owned by one of `owner_pubkeys`.
pub fn scan_canonical_blocks(
    node_url: &str,
    wallet: &mut Wallet,
    keys: &KeysFile,
    owner_pubkeys: &[HybridPubKey],
    expected_genesis_hash: Bytes32,
) -> Result<usize, String> {
    let mut discovered = 0usize;
    #[cfg(not(test))]
    let mut last_progress = Instant::now() - Duration::from_secs(1);
    if wallet.scan_tip().is_none() {
        anchor_fresh_wallet_at_genesis(node_url, wallet, keys, expected_genesis_hash)?;
    }
    loop {
        let (from_height, expected_parent) = wallet
            .scan_tip()
            .ok_or_else(|| "canonical scan wallet has no genesis anchor".to_string())
            .map(|(height, hash)| (height + 1, hash))?;
        let authorization =
            build_scan_authorization(node_url, keys).map_err(|error| error.to_string())?;
        let response = rpc_call_raw_params(
            node_url,
            "indra_getCanonicalBlocks",
            &[
                from_height.to_string(),
                CANONICAL_SCAN_PAGE_SIZE.to_string(),
                json_string(&hex::encode(expected_parent.0)),
                json_string(&authorization.payment_address),
                authorization.proof,
            ],
        )
        .map_err(|error| error.to_string())?;

        if response.contains("canonical parent mismatch") {
            let (height, _) = wallet
                .scan_tip()
                .ok_or_else(|| "canonical scan wallet has no genesis anchor".to_string())?;
            if height == 0 {
                return Err(
                    "genesis anchor does not match canonical parent at height 1".to_string()
                );
            }
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
        #[cfg(not(test))]
        if last_progress.elapsed() >= Duration::from_secs(1) {
            let current_height = blocks.last().map_or(from_height.saturating_sub(1), |block| block.header.height);
            let tip_height = json_u64_field(&response, "tip_height").unwrap_or(current_height);
            eprintln!("{}", format_scan_progress(current_height, tip_height));
            last_progress = Instant::now();
        }
        for entry in refunds {
            discovered += scan_tranche_refund(wallet, &entry, owner_pubkeys)?;
        }
        for block in blocks {
            if block.header.prev_hash != expected_scan_parent(wallet) {
                let genesis_anchor_mismatch = block.header.height == 1
                    && wallet.scan_tip().is_some_and(|(height, _)| height == 0);
                wallet.rollback_scan_from(block.header.height.saturating_sub(1));
                if genesis_anchor_mismatch {
                    return Err(
                        "genesis anchor does not match canonical parent at height 1".to_string()
                    );
                }
                return Err(format!(
                    "non-contiguous canonical block page at height {}",
                    block.header.height
                ));
            }
            discovered += scan_canonical_block(wallet, &block, owner_pubkeys)?;
            wallet.record_scanned_block(block.header.height, block.header.block_hash());
        }
        if response.contains("\"next_height\":null") {
            break;
        }
    }
    Ok(discovered)
}

#[cfg(not(test))]
fn json_u64_field(json: &str, field: &str) -> Option<u64> {
    let marker = format!("\"{field}\":");
    let value = json.split_once(&marker)?.1.trim_start();
    let end = value.find(|character: char| !character.is_ascii_digit()).unwrap_or(value.len());
    value[..end].parse().ok()
}

fn anchor_fresh_wallet_at_genesis(
    node_url: &str,
    wallet: &mut Wallet,
    keys: &KeysFile,
    expected_genesis_hash: Bytes32,
) -> Result<(), String> {
    let authorization =
        build_scan_authorization(node_url, keys).map_err(|error| error.to_string())?;
    let response = rpc_call_raw_params(
        node_url,
        "indra_getCanonicalBlocks",
        &[
            "0".to_string(),
            "1".to_string(),
            json_string(&hex::encode(Bytes32::ZERO.0)),
            json_string(&authorization.payment_address),
            authorization.proof,
        ],
    )
    .map_err(|error| {
        let message = error.to_string();
        if message.contains("block 0") || message.contains("genesis") {
            "canonical genesis block is missing from node response".to_string()
        } else {
            message
        }
    })?;
    if response.contains("\"error\"") {
        return Err("canonical genesis block is missing from node response".to_string());
    }
    let mut blocks = canonical_blocks_from_rpc(&response)?;
    let genesis = blocks
        .drain(..)
        .find(|block| block.header.height == 0)
        .ok_or_else(|| "canonical genesis block is missing from node response".to_string())?;
    if genesis.header.prev_hash != Bytes32::ZERO {
        return Err("canonical genesis block has a non-zero parent".to_string());
    }
    if genesis.header.block_hash() != expected_genesis_hash {
        return Err("node genesis hash does not match the expected genesis hash".to_string());
    }
    wallet.record_scanned_block(0, genesis.header.block_hash());
    Ok(())
}

fn scan_tranche_refund(
    wallet: &mut Wallet,
    entry: &UtxoEntry,
    owner_pubkeys: &[HybridPubKey],
) -> Result<usize, String> {
    let Some(_event) = &entry.tranche_refund else {
        return Ok(0);
    };
    if !owner_pubkeys
        .iter()
        .any(|owner| owner == &entry.output.owner_pubkey)
    {
        return Ok(0);
    }
    if wallet.contains(&entry.utxo_id) {
        return Ok(0);
    }
    wallet.add_utxo(
        entry.utxo_id,
        entry.output.value_spark,
        entry.created_height,
        entry.tx_index,
        entry.output_index,
        entry.output.owner_pubkey.clone(),
    );
    Ok(1)
}

/// Apply one canonical block to ordinary-payment wallet discovery.
pub fn scan_canonical_block(
    wallet: &mut Wallet,
    block: &BlockVNext,
    owner_pubkeys: &[HybridPubKey],
) -> Result<usize, String> {
    let mut discovered = 0usize;
    for (transaction_index, transaction) in block.transactions.iter().enumerate() {
        let transaction_index = u32::try_from(transaction_index)
            .map_err(|_| "transaction index exceeds u32".to_string())?;
        for input in &transaction.inputs {
            wallet.mark_spent_at_height(&input.utxo_id, block.header.height);
        }
        for (output_index, output) in transaction.outputs.iter().enumerate() {
            if !owner_pubkeys.contains(&output.owner_pubkey) {
                continue;
            }
            let output_index =
                u32::try_from(output_index).map_err(|_| "output index exceeds u32".to_string())?;
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
                    block.header.height,
                    transaction_index,
                    output_index,
                    output.owner_pubkey.clone(),
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

fn canonical_blocks_from_rpc(json: &str) -> Result<Vec<BlockVNext>, String> {
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
            BlockVNext::decode_exact(&bytes)
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
        codec::Encode,
        types::{
            block::{
                BlockHeaderVNext, BlockVNext, ProposalEntropyV1, SortitionClaimV1, VrfSuiteV1,
            },
            crypto::HybridSignature,
            primitives::{Bytes64, ProtocolVersion, TRANSACTION_PROTOCOL_VERSION},
            stake_position::{PositionCustodyV1, TrancheRefundEventV1},
            transaction::{OutputV1, TransactionV1},
        },
        VariableBytes,
    };
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread,
    };

    #[test]
    fn scan_progress_format_is_exact() {
        assert_eq!(
            format_scan_progress(125, 300),
            "Scanning canonical blocks: height 125/300"
        );
    }

    fn scan_block(height: u64, prev_hash: Bytes32, output: Option<OutputV1>) -> BlockVNext {
        let is_genesis = height == 0;
        let proposer_vrf_output = if is_genesis {
            VariableBytes::default()
        } else {
            VariableBytes::from_slice(&[0x77; 64]).unwrap()
        };
        let proposer_vrf_proof = if is_genesis {
            VariableBytes::default()
        } else {
            VariableBytes::from_slice(&[0x88; 80]).unwrap()
        };
        let value_entropy = if is_genesis {
            ProposalEntropyV1::genesis()
        } else {
            ProposalEntropyV1 {
                origin_proposer_id: Bytes32::from([0x44; 32]),
                origin_round: 0,
                vrf_output: VariableBytes::from_slice(&[0x77; 64]).unwrap(),
                vrf_proof: VariableBytes::from_slice(&[0x88; 80]).unwrap(),
            }
        };
        let transactions = output.map_or_else(Vec::new, |output| {
            vec![TransactionV1 {
                version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
                signature_module_id: 1,
                inputs: Vec::new(),
                outputs: vec![output],
                fee_amount: 0,
                signature: HybridSignature {
                    classical_sig: VariableBytes::default(),
                    pq_sig: VariableBytes::default(),
                },
            }]
        });
        BlockVNext {
            header: BlockHeaderVNext {
                protocol_version: ProtocolVersion::CURRENT,
                height,
                prev_hash,
                timestamp: 1_700_000_000 + height,
                state_root: Bytes32::from([height as u8; 32]),
                validator_set_root: Bytes32::from([0x11; 32]),
                mempool_set_root: Bytes32::from([0x22; 32]),
                value_hash: Bytes32::from([0x33; 32]),
                base_fee: 1,
                proposer_round: 0,
                polc_round: None,
                proposer_id: if is_genesis {
                    Bytes32::ZERO
                } else {
                    Bytes32::from([0x44; 32])
                },
                vrf_suite: VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
                election_seed: Bytes64([0x55; 64]),
                proposer_vrf_output,
                proposer_vrf_proof,
                value_entropy,
                sortition_claim: SortitionClaimV1::PraosThreshold,
                proposer_priority: Bytes64([0x66; 64]),
                quorum_certificate: VariableBytes::default(),
            },
            transactions,
            slashing_evidence: Vec::new(),
            governance_ops: Vec::new(),
            staking_ops: Vec::new(),
        }
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut one = [0u8; 1];
        while !bytes.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut one).unwrap();
            bytes.push(one[0]);
        }
        let headers = String::from_utf8(bytes.clone()).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            })
            .unwrap();
        let mut body = vec![0u8; content_length];
        stream.read_exact(&mut body).unwrap();
        String::from_utf8(body).unwrap()
    }

    fn response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(), body
        )
    }

    fn canonical_response(
        blocks: &[BlockVNext],
        next_height: Option<u64>,
        tip_height: u64,
    ) -> String {
        let encoded = blocks
            .iter()
            .map(|block| {
                format!(
                    r#"{{"height":{},"block_hash":"{}","block_hex":"{}","protocol_outputs":[]}}"#,
                    block.header.height,
                    hex::encode(block.header.block_hash().0),
                    hex::encode(block.encode_to_vec())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"from_height":{},"blocks":[{}],"next_height":{},"tip_height":{},"tip_hash":"{}"}}"#,
            blocks.first().map_or(0, |block| block.header.height),
            encoded,
            next_height.map_or_else(|| "null".to_string(), |height| height.to_string()),
            tip_height,
            blocks.last().map_or_else(
                || hex::encode(Bytes32::ZERO.0),
                |block| hex::encode(block.header.block_hash().0)
            )
        )
    }

    fn mock_scan_server(
        genesis: BlockVNext,
        later_blocks: Vec<BlockVNext>,
        requests: usize,
        missing_genesis: bool,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            for _ in 0..requests {
                let (mut stream, _) = listener.accept().unwrap();
                let body = read_http_request(&mut stream);
                let result = if body.contains("indra_getChainInfo") {
                    r#"{"jsonrpc":"2.0","result":{"chain_id":"scan-test"},"id":1}"#.to_string()
                } else if body.contains("indra_getScanChallenge") {
                    format!(
                        r#"{{"jsonrpc":"2.0","result":{{"challenge":"{}"}},"id":1}}"#,
                        "00".repeat(32)
                    )
                } else if body.contains("indra_getCanonicalBlocks")
                    && body.contains("\"params\":[0,")
                {
                    if missing_genesis {
                        r#"{"jsonrpc":"2.0","error":{"message":"block 0 is not retained"},"id":1}"#
                            .to_string()
                    } else {
                        canonical_response(
                            &[genesis.clone()],
                            Some(1),
                            later_blocks.last().map_or(0, |block| block.header.height),
                        )
                    }
                } else if body.contains("indra_getCanonicalBlocks") {
                    canonical_response(
                        &later_blocks,
                        None,
                        later_blocks.last().map_or(0, |block| block.header.height),
                    )
                } else {
                    panic!("unexpected mock RPC request: {body}");
                };
                stream.write_all(response(&result).as_bytes()).unwrap();
            }
        });
        (address, handle)
    }

    #[test]
    fn canonical_scan_recovers_tranche_refund_from_embedded_provenance() {
        let owner_id = Bytes32::from([4; 32]);
        let custody = PositionCustodyV1::DelegatorIdentity {
            delegator_id: owner_id,
        };
        let position_id = Bytes32::from([1; 32]);
        let tranche_id = Bytes32::from([2; 32]);
        let principal_spark = 50;
        let release_height = 300;
        let end_epoch = 1;
        let owner_pubkey = HybridPubKey {
            classical_pk: Bytes32::from([7; 32]),
            pq_pk: VariableBytes::from_slice(&[8; 32]).unwrap(),
        };
        let output = OutputV1 {
            value_spark: principal_spark,
            owner_pubkey: owner_pubkey.clone(),
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
            scan_tranche_refund(&mut wallet, &entry, &[owner_pubkey.clone()]).unwrap(),
            1
        );
        assert_eq!(wallet.balance_owned_by(&owner_pubkey), principal_spark);
        assert_eq!(scan_tranche_refund(&mut wallet, &entry, &[]).unwrap(), 0);
    }

    #[test]
    fn fresh_wallet_scan_anchors_at_genesis_block_hash() {
        let keys = crate::generate_from_master_seed("scan-fresh".to_string(), [0x31; 32]).unwrap();
        let owner = HybridPubKey {
            classical_pk: Bytes32::from(keys.public.hybrid_classical_pk),
            pq_pk: VariableBytes::from_slice(&keys.public.hybrid_pq_pk).unwrap(),
        };
        let genesis = scan_block(0, Bytes32::ZERO, None);
        let block_one = scan_block(1, genesis.header.block_hash(), None);
        let expected_amount = 777_000_000;
        let block_two = scan_block(
            2,
            block_one.header.block_hash(),
            Some(OutputV1 {
                value_spark: expected_amount,
                owner_pubkey: owner.clone(),
                lock_height: 0,
            }),
        );
        let (node, server) = mock_scan_server(
            genesis.clone(),
            vec![block_one, block_two.clone()],
            6,
            false,
        );
        let mut wallet = Wallet::new();
        let discovered =
            scan_canonical_blocks(
                &node,
                &mut wallet,
                &keys,
                &[owner.clone()],
                genesis.header.block_hash(),
            )
            .unwrap();
        server.join().unwrap();
        assert_eq!(wallet.scan_tip(), Some((2, block_two.header.block_hash())));
        assert_eq!(wallet.balance_owned_by(&owner), expected_amount);
        assert_eq!(discovered, 1);
        assert_eq!(wallet.scan_tip().unwrap().0, 2);
        assert_ne!(genesis.header.block_hash(), Bytes32::ZERO);
    }

    #[test]
    fn scan_resumes_from_existing_tip_without_refetching_genesis() {
        let keys = crate::generate_from_master_seed("scan-resume".to_string(), [0x32; 32]).unwrap();
        let genesis = scan_block(0, Bytes32::ZERO, None);
        let block_one = scan_block(1, genesis.header.block_hash(), None);
        let (node, server) = mock_scan_server(genesis.clone(), vec![block_one.clone()], 3, false);
        let mut wallet = Wallet::new();
        wallet.record_scanned_block(0, genesis.header.block_hash());
        assert_eq!(
            scan_canonical_blocks(&node, &mut wallet, &keys, &[], genesis.header.block_hash())
                .unwrap(),
            0
        );
        server.join().unwrap();
        assert_eq!(wallet.scan_tip(), Some((1, block_one.header.block_hash())));
    }

    #[test]
    fn scan_fails_with_exact_error_when_genesis_block_missing() {
        let keys =
            crate::generate_from_master_seed("scan-missing".to_string(), [0x33; 32]).unwrap();
        let genesis = scan_block(0, Bytes32::ZERO, None);
        let (node, server) = mock_scan_server(genesis.clone(), Vec::new(), 3, true);
        let error = scan_canonical_blocks(
            &node,
            &mut Wallet::new(),
            &keys,
            &[],
            genesis.header.block_hash(),
        )
        .unwrap_err();
        server.join().unwrap();
        assert_eq!(
            error,
            "canonical genesis block is missing from node response"
        );
    }

    #[test]
    fn scan_fails_with_exact_error_when_height_one_parent_disagrees_with_genesis() {
        let keys = crate::generate_from_master_seed("scan-parent-mismatch".to_string(), [0x34; 32])
            .unwrap();
        let genesis = scan_block(0, Bytes32::ZERO, None);
        let block_one = scan_block(1, Bytes32::from([0xEE; 32]), None);
        let (node, server) = mock_scan_server(genesis.clone(), vec![block_one], 6, false);
        let error = scan_canonical_blocks(
            &node,
            &mut Wallet::new(),
            &keys,
            &[],
            genesis.header.block_hash(),
        )
        .unwrap_err();
        server.join().unwrap();
        assert_eq!(
            error,
            "genesis anchor does not match canonical parent at height 1"
        );
    }

    #[test]
    fn scan_rejects_genesis_hash_mismatch_with_exact_error() {
        let keys = crate::generate_from_master_seed("scan-mismatch".to_string(), [0x35; 32]).unwrap();
        let genesis = scan_block(0, Bytes32::ZERO, None);
        let (node, server) = mock_scan_server(genesis.clone(), Vec::new(), 3, false);
        let error = scan_canonical_blocks(
            &node,
            &mut Wallet::new(),
            &keys,
            &[],
            Bytes32::from([0xAB; 32]),
        )
        .unwrap_err();
        server.join().unwrap();
        assert_eq!(error, "node genesis hash does not match the expected genesis hash");
    }
}
