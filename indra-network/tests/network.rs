//! Integration tests for the network layer.

use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

use indra_core::types::primitives::Bytes32;
use indra_network::{
    message::Message,
    peer::{PeerTable, PeerStatus, ScoreEvent, INITIAL_SCORE},
    transport::Transport,
    gossip::GossipEngine,
};

#[test]
fn message_encode_decode_all_types() {
    let messages = vec![
        Message::Ping(999),
        Message::Pong(999),
        Message::GetBlocks { from_height: 0, to_height: 100 },
        Message::Status { height: 42, tip_hash: Bytes32::from([0xAAu8; 32]) },
        Message::PeerList(vec!["127.0.0.1:30303".to_string()]),
    ];

    for msg in messages {
        let wire = msg.encode_wire().unwrap();
        let decoded = Message::decode_wire(&wire[4..]).unwrap();
        // Check type matches
        assert_eq!(
            decoded.message_type() as u8,
            msg.message_type() as u8,
            "message type mismatch"
        );
    }
}

#[test]
fn peer_table_lifecycle() {
    let mut table = PeerTable::new();
    let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();

    // Add
    table.add(addr).unwrap();
    assert_eq!(table.get(&addr).unwrap().status, PeerStatus::Known);

    // Connect
    table.mark_connected(&addr);
    assert_eq!(table.get(&addr).unwrap().status, PeerStatus::Connected);
    assert_eq!(table.connected().len(), 1);

    // Update height
    table.update_height(&addr, 50);
    assert_eq!(table.get(&addr).unwrap().reported_height, 50);

    // Score up
    for _ in 0..5 {
        table.score_event(&addr, ScoreEvent::ValidBlock);
    }
    assert_eq!(table.get(&addr).unwrap().score, INITIAL_SCORE + 5 * 5);

    // Disconnect
    table.mark_disconnected(&addr);
    assert_eq!(table.connected().len(), 0);
}

#[test]
fn two_nodes_exchange_status() {
    let server_transport = Transport::bind("127.0.0.1:0").unwrap();
    let server_addr = server_transport.local_addr;

    let handle = thread::spawn(move || {
        let start = std::time::Instant::now();
        loop {
            match server_transport.accept().unwrap() {
                Some(mut conn) => {
                    let msg = conn.recv().unwrap().unwrap();
                    // Echo back a status
                    let response = Message::Status {
                        height: 100,
                        tip_hash: Bytes32::from([0xBBu8; 32]),
                    };
                    conn.send(&response).unwrap();
                    return msg;
                }
                None => {
                    if start.elapsed() > Duration::from_secs(3) {
                        panic!("timeout");
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    });

    thread::sleep(Duration::from_millis(500));

    let client = Transport::bind("127.0.0.1:0").unwrap();
    let mut conn = client.dial(server_addr).unwrap();

    conn.send(&Message::Status {
        height: 50,
        tip_hash: Bytes32::from([0xAAu8; 32]),
    }).unwrap();

    let received_by_server = handle.join().unwrap();
    match received_by_server {
        Message::Status { height, .. } => assert_eq!(height, 50),
        _ => panic!("wrong message type"),
    }

    let response = conn.recv().unwrap().unwrap();
    match response {
        Message::Status { height, .. } => assert_eq!(height, 100),
        _ => panic!("wrong response type"),
    }
}

#[test]
fn gossip_engine_seen_dedup() {
    let mut engine = GossipEngine::new();
    let hash = indra_crypto::sha256(b"test message");
    assert!(!engine.is_seen(&hash));
    engine.mark_seen(hash);
    assert!(engine.is_seen(&hash));
    // Marking again should be idempotent
    engine.mark_seen(hash);
    assert!(engine.is_seen(&hash));
}

#[test]
fn equivocating_peer_gets_banned() {
    let mut engine = GossipEngine::new();
    let addr: SocketAddr = "127.0.0.1:9002".parse().unwrap();
    engine.peers_mut().add(addr).unwrap();

    // EquivocatingBlock = -50 per event, start at 100
    // After 2 events: score = 0 → banned
    engine.score_event(&addr, ScoreEvent::EquivocatingBlock);
    engine.score_event(&addr, ScoreEvent::EquivocatingBlock);

    assert!(engine.peers().get(&addr).unwrap().is_banned());
}
