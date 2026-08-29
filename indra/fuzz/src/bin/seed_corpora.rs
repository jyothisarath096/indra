use curve25519_dalek_v5::{constants::EIGHT_TORSION, edwards::EdwardsPoint, traits::Identity};
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
use indra_crypto::{vrf_prove, VrfKeypair};
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

fn vrf_vectors() -> Vec<([u8; 32], Vec<u8>)> {
    vec![
        (
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap(),
            vec![],
        ),
        (
            hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
                .unwrap()
                .try_into()
                .unwrap(),
            vec![0x72],
        ),
        (
            hex::decode("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
                .unwrap()
                .try_into()
                .unwrap(),
            vec![0xaf, 0x82],
        ),
    ]
}

fn verification_seed(pk: &[u8; 32], alpha: &[u8], beta: &[u8; 64], proof: &[u8]) -> Vec<u8> {
    let mut seed = Vec::with_capacity(98 + alpha.len() + proof.len());
    seed.extend_from_slice(pk);
    seed.extend_from_slice(beta);
    seed.extend_from_slice(&(alpha.len() as u16).to_le_bytes());
    seed.extend_from_slice(alpha);
    seed.extend_from_slice(proof);
    seed
}

fn main() -> io::Result<()> {
    for corpus in [
        "fuzz/corpus/transaction_deserialization",
        "fuzz/corpus/public_json_rpc",
        "fuzz/corpus/governance_parsing",
        "fuzz/corpus/p2p_gossip_parsing",
        "fuzz/corpus/vrf_verify_arbitrary",
        "fuzz/corpus/vrf_valid_proof_mutation",
        "fuzz/corpus/vrf_public_key_validation",
        "fuzz/corpus/vrf_prove_verify_roundtrip",
        "fuzz/corpus/vrf_proof_framing",
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

    for (index, (seed, alpha)) in vrf_vectors().into_iter().enumerate() {
        let keypair = VrfKeypair::from_seed(&seed);
        let (output, proof) = vrf_prove(&keypair, &alpha);
        write(
            format!("fuzz/corpus/vrf_verify_arbitrary/rfc_{index}"),
            &verification_seed(&keypair.public_key, &alpha, &output.0, &proof.0),
        )?;
        write(
            format!("fuzz/corpus/vrf_public_key_validation/rfc_{index}"),
            &keypair.public_key,
        )?;
        write(
            format!("fuzz/corpus/vrf_proof_framing/rfc_{index}"),
            &proof.0,
        )?;
        let mut roundtrip = seed.to_vec();
        roundtrip.extend_from_slice(&alpha);
        write(
            format!("fuzz/corpus/vrf_prove_verify_roundtrip/rfc_{index}"),
            &roundtrip,
        )?;
        for selector in 0..6u8 {
            let mut mutation = seed.to_vec();
            mutation.push(selector);
            mutation.extend_from_slice(&alpha);
            write(
                format!("fuzz/corpus/vrf_valid_proof_mutation/rfc_{index}_{selector}"),
                &mutation,
            )?;
        }

        let mut noncanonical_scalar = proof.0.clone();
        noncanonical_scalar[48..80].copy_from_slice(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ]);
        for (name, malformed) in [
            ("truncated", proof.0[..79].to_vec()),
            ("overlong", [proof.0.clone(), vec![0]].concat()),
            ("noncanonical_scalar", noncanonical_scalar),
        ] {
            write(
                format!("fuzz/corpus/vrf_verify_arbitrary/rfc_{index}_{name}"),
                &verification_seed(&keypair.public_key, &alpha, &output.0, &malformed),
            )?;
            write(
                format!("fuzz/corpus/vrf_proof_framing/rfc_{index}_{name}"),
                &malformed,
            )?;
        }
    }

    let identity = EdwardsPoint::identity().compress().to_bytes();
    write("fuzz/corpus/vrf_public_key_validation/identity", &identity)?;
    for (index, point) in EIGHT_TORSION.iter().enumerate() {
        write(
            format!("fuzz/corpus/vrf_public_key_validation/torsion_{index}"),
            point.compress().as_bytes(),
        )?;
    }
    let mut noncanonical_identity = [0xff; 32];
    noncanonical_identity[0] = 0xee;
    noncanonical_identity[31] = 0x7f;
    write(
        "fuzz/corpus/vrf_public_key_validation/noncanonical_identity",
        &noncanonical_identity,
    )?;
    Ok(())
}
