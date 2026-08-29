use indra_core::types::{
    crypto::HybridSignature,
    primitives::{Bytes32, VariableBytes, MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES},
    vote::{VoteStep, VoteV1},
};
use indra_network::message::Message;

fn production_decode(plaintext: &[u8]) -> Result<Message, String> {
    let payload = if plaintext.len() >= 4 {
        &plaintext[4..]
    } else {
        plaintext
    };
    Message::decode_wire(payload).map_err(|error| error.to_string())
}

fn vote(round: u32, classical_len: usize, pq_len: usize) -> Message {
    Message::Vote(VoteV1 {
        height: 1,
        round,
        step: VoteStep::Prevote,
        block_hash: Bytes32::from([0x11; 32]),
        validator_id: Bytes32::from([0x22; 32]),
        snapshot_root: Bytes32::from([0x33; 32]),
        signature: HybridSignature {
            classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(
                &vec![0x44; classical_len],
            )
            .unwrap(),
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&vec![0x55; pq_len]).unwrap(),
        },
    })
}

fn frame_with_prefix(prefix: u32, body_after_prefix: &[u8]) -> Vec<u8> {
    let mut plaintext = prefix.to_le_bytes().to_vec();
    plaintext.extend_from_slice(body_after_prefix);
    plaintext
}

fn accepted(label: &str, bytes: &[u8]) -> bool {
    let result = production_decode(bytes).is_ok();
    println!("{label},{}", if result { "ACCEPT" } else { "REJECT" });
    result
}

fn main() {
    println!("case,result");

    let canonical_ping = Message::Ping(7).encode_wire().unwrap();
    assert!(accepted("ping_exact", &canonical_ping));
    let mut ping_trailing = canonical_ping.clone();
    ping_trailing.extend_from_slice(&[0xaa, 0xbb]);
    assert!(!accepted("ping_trailing", &ping_trailing));

    let mut request_blocks = Message::RequestBlocks {
        from_height: 1,
        to_height: 2,
    }
    .encode_wire()
    .unwrap();
    request_blocks.push(0xcc);
    assert!(!accepted("request_blocks_trailing", &request_blocks));

    let mut request_qc = Message::RequestQC { height: 1 }.encode_wire().unwrap();
    request_qc.push(0xdd);
    assert!(!accepted("request_qc_trailing", &request_qc));

    let mut qc_response = Message::QCResponse {
        height: 1,
        qc_bytes: vec![1, 2, 3],
    }
    .encode_wire()
    .unwrap();
    qc_response.extend_from_slice(&[0xee, 0xff]);
    assert!(!accepted("qc_response_trailing", &qc_response));

    let canonical_body = &canonical_ping[4..];
    assert!(accepted(
        "inner_length_zero",
        &frame_with_prefix(0, canonical_body)
    ));
    assert!(accepted(
        "inner_length_u32_max",
        &frame_with_prefix(u32::MAX, canonical_body)
    ));

    let peer_a = frame_with_prefix(8, &[0x04, 1, 0, 0, 0, 1, 0, 0xff, 0]);
    let peer_b = frame_with_prefix(8, &[0x04, 1, 0, 0, 0, 1, 0, 0xfe, 0]);
    assert!(!accepted("peer_list_invalid_utf8_ff", &peer_a));
    assert!(!accepted("peer_list_invalid_utf8_fe", &peer_b));

    for round in [0, 1023, 1024, u32::MAX] {
        let encoded = vote(round, 64, 4627).encode_wire();
        let ok = encoded
            .as_deref()
            .is_ok_and(|bytes| production_decode(bytes).is_ok());
        println!("vote_round_{round},{}", if ok { "ACCEPT" } else { "REJECT" });
        assert_eq!(ok, round < 1024);
    }

    for (label, classical_len, pq_len, expected) in [
        ("signature_empty", 0, 0, false),
        ("signature_ed25519_63", 63, 4627, false),
        ("signature_ed25519_64", 64, 4627, true),
        ("signature_mldsa_4626", 64, 4626, false),
        ("signature_mldsa_4627", 64, 4627, true),
    ] {
        let bytes = vote(0, classical_len, pq_len).encode_wire().unwrap();
        assert_eq!(accepted(label, &bytes), expected);
    }

    let mut unknown = canonical_ping;
    unknown[4] = 0xff;
    assert!(!accepted("unknown_discriminator", &unknown));
}
