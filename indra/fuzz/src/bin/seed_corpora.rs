use indra_core::{
    codec::Encode,
    types::{
        crypto::{HybridPubKey, HybridSignature},
        governance::{
            ColdGovernanceAuthorization, GovernableAction, GovernanceActionType, GovernanceOpV2,
            GovernancePayload,
        },
        primitives::{Bytes32, ProtocolVersion, VariableBytes, TRANSACTION_PROTOCOL_VERSION},
        transaction::{InputV1, OutputV1, TransactionV1},
    },
};
use indra_network::{Message, MessageType};
use std::{fs, io, path::Path};

fn write(path: impl AsRef<Path>, bytes: &[u8]) -> io::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)
}

fn signature() -> HybridSignature {
    HybridSignature {
        classical_sig: VariableBytes::from_slice(&[0; 64]).expect("bounded fixture"),
        pq_sig: VariableBytes::from_slice(&[0; 4627]).expect("bounded fixture"),
    }
}

fn pubkey() -> HybridPubKey {
    HybridPubKey {
        classical_pk: Bytes32::from([3; 32]),
        pq_pk: VariableBytes::from_slice(&[4; 2592]).expect("bounded fixture"),
    }
}

fn transaction() -> TransactionV1 {
    TransactionV1 {
        version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
        signature_module_id: 1,
        inputs: vec![InputV1 {
            utxo_id: Bytes32::from([1; 32]),
        }],
        outputs: vec![OutputV1 {
            value_spark: 100_000,
            owner_pubkey: pubkey(),
            lock_height: 0,
        }],
        fee_amount: 500,
        signature: signature(),
    }
}

fn governance_payloads() -> Vec<GovernancePayload> {
    let cold = Some(ColdGovernanceAuthorization {
        cold_key_version: 1,
        cold_nonce: 1,
    });
    vec![
        GovernancePayload::Propose {
            action: GovernableAction::SetSlashLivenessBps { value: 20 },
            deposit_utxo_id: Bytes32::from([5; 32]),
            proposer_pubkey: pubkey(),
            title: VariableBytes::from_slice(b"fuzz proposal").expect("bounded fixture"),
            description: VariableBytes::from_slice(b"canonical proposal seed")
                .expect("bounded fixture"),
            cold_authorization: cold,
        },
        GovernancePayload::Commit {
            proposal_id: Bytes32::from([6; 32]),
            commit_hash: Bytes32::from([7; 32]),
            cold_authorization: cold,
        },
        GovernancePayload::Reveal {
            proposal_id: Bytes32::from([6; 32]),
            vote: 1,
            nonce: Bytes32::from([8; 32]),
            cold_authorization: cold,
        },
        GovernancePayload::Cancel {
            proposal_id: Bytes32::from([6; 32]),
            cold_authorization: cold,
        },
    ]
}

fn main() -> io::Result<()> {
    for corpus in [
        "fuzz/corpus/transaction_deserialization",
        "fuzz/corpus/public_json_rpc",
        "fuzz/corpus/governance_parsing",
        "fuzz/corpus/p2p_gossip_parsing",
    ] {
        match fs::remove_dir_all(corpus) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let tx = transaction();
    write(
        "fuzz/corpus/transaction_deserialization/canonical_tx",
        &tx.encode_to_vec(),
    )?;
    let mut tx_trailing = tx.encode_to_vec();
    tx_trailing.push(0xff);
    write(
        "fuzz/corpus/transaction_deserialization/trailing_byte",
        &tx_trailing,
    )?;
    let encoded_tx = tx.encode_to_vec();
    for (index, boundary) in [0, 1, 4, 8, encoded_tx.len() / 2, encoded_tx.len() - 1]
        .into_iter()
        .enumerate()
    {
        write(
            format!("fuzz/corpus/transaction_deserialization/truncated_{index}"),
            &encoded_tx[..boundary],
        )?;
    }
    for (index, offset) in [0, 2, 4, 40, encoded_tx.len() / 3, encoded_tx.len() - 1]
        .into_iter()
        .enumerate()
    {
        let mut mutated = encoded_tx.clone();
        mutated[offset] ^= 0xff;
        write(
            format!("fuzz/corpus/transaction_deserialization/bit_mutation_{index}"),
            &mutated,
        )?;
    }

    for (index, (method, _)) in indra_rpc::handlers::RPC_METHODS
        .iter()
        .filter(|(_, access)| *access == indra_rpc::handlers::RpcMethodAccess::ReadOnly)
        .enumerate()
    {
        let mut seed = vec![u8::try_from(index).expect("RPC method count fits u8")];
        seed.extend_from_slice(br#"[0,"0",null,true]"#);
        write(format!("fuzz/corpus/public_json_rpc/{method}"), &seed)?;
    }

    for (index, payload) in governance_payloads().into_iter().enumerate() {
        let mut payload_seed = vec![0];
        payload_seed.extend_from_slice(&payload.encode_to_vec());
        write(
            format!("fuzz/corpus/governance_parsing/payload_{index}"),
            &payload_seed,
        )?;

        let action_type = payload.action_type();
        let op = GovernanceOpV2 {
            action_type,
            signer_id: Bytes32::from([9; 32]),
            nonce: 0,
            payload,
            signature: signature(),
        };
        let mut op_seed = vec![1];
        op_seed.extend_from_slice(&op.encode_to_vec());
        write(
            format!("fuzz/corpus/governance_parsing/operation_{index}"),
            &op_seed,
        )?;
    }

    for (name, message) in [
        ("transaction", Message::Tx(tx)),
        (
            "governance",
            Message::GovernanceOp(GovernanceOpV2 {
                action_type: GovernanceActionType::CommitVote,
                signer_id: Bytes32::from([9; 32]),
                nonce: 0,
                payload: governance_payloads().remove(1),
                signature: signature(),
            }),
        ),
        ("ping", Message::Ping(42)),
    ] {
        let wire = message.encode_wire().expect("bounded fixture");
        write(format!("fuzz/corpus/p2p_gossip_parsing/{name}"), &wire[4..])?;
    }
    for (name, message_type) in [
        ("block_type", MessageType::Block),
        ("vote_type", MessageType::Vote),
        ("tx_type", MessageType::Tx),
        ("staking_type", MessageType::StakingOp),
        ("governance_type", MessageType::GovernanceOp),
        ("peer_list_type", MessageType::PeerList),
        ("ping_type", MessageType::Ping),
        ("pong_type", MessageType::Pong),
        ("request_blocks_type", MessageType::RequestBlocks),
        ("block_response_type", MessageType::BlockResponse),
        ("status_type", MessageType::Status),
        ("request_proposal_type", MessageType::RequestProposal),
        ("request_qc_type", MessageType::RequestQC),
        ("qc_response_type", MessageType::QCResponse),
    ] {
        write(
            format!("fuzz/corpus/p2p_gossip_parsing/{name}"),
            &[message_type as u8],
        )?;
    }
    Ok(())
}
