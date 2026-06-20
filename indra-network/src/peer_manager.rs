//! Async peer-manager actor for the authenticated Tokio transport.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::{
    sync::mpsc,
    task::JoinHandle,
};

use indra_core::types::primitives::Bytes32;

use crate::{
    frame::{FrameReader, FrameWriter},
    handshake::HandshakeResult,
    message::Message,
    net_types::{NetworkCommand, NetworkEvent},
    peer::{PeerTable, ScoreEvent},
};

#[derive(Clone)]
struct OutboundMessage {
    msg: Message,
    point_to_point: bool,
}

enum PeerManagerMessage {
    Connected {
        addr: SocketAddr,
        handshake: HandshakeResult,
    },
    Disconnected {
        validator_id: Bytes32,
        addr: SocketAddr,
    },
}

struct ManagedPeer {
    addr: SocketAddr,
    write_tx: mpsc::Sender<OutboundMessage>,
    read_task: JoinHandle<()>,
    write_task: JoinHandle<()>,
}

struct PeerManagerActor {
    local_validator_id: Bytes32,
    event_tx: mpsc::Sender<NetworkEvent>,
    command_rx: mpsc::Receiver<NetworkCommand>,
    control_rx: mpsc::Receiver<PeerManagerMessage>,
    control_tx: mpsc::Sender<PeerManagerMessage>,
    peer_table: PeerTable,
    peers_by_validator: HashMap<Bytes32, ManagedPeer>,
    validator_by_addr: HashMap<SocketAddr, Bytes32>,
    connected_peers: Arc<AtomicUsize>,
    per_peer_write_buffer: usize,
}

fn short_validator_id(id: &Bytes32) -> String {
    id.0[..4].iter().map(|byte| format!("{:02x}", byte)).collect()
}

impl PeerManagerActor {
    async fn run(mut self) {
        loop {
            tokio::select! {
                maybe_command = self.command_rx.recv() => {
                    let Some(command) = maybe_command else {
                        break;
                    };
                    self.handle_command(command).await;
                }
                maybe_control = self.control_rx.recv() => {
                    let Some(control) = maybe_control else {
                        break;
                    };
                    self.handle_control(control).await;
                }
            }
        }
    }

    async fn handle_command(&mut self, command: NetworkCommand) {
        match command {
            NetworkCommand::Broadcast(msg) => {
                let validators: Vec<Bytes32> = self.peers_by_validator.keys().copied().collect();
                for validator_id in validators {
                    self.try_send_to_validator(validator_id, OutboundMessage {
                        msg: msg.clone(),
                        point_to_point: false,
                    }).await;
                }
            }
            NetworkCommand::SendTo { validator_id, msg } => {
                self.try_send_to_validator(validator_id, OutboundMessage {
                    msg,
                    point_to_point: true,
                }).await;
            }
            NetworkCommand::Disconnect { validator_id } => {
                if let Some(peer) = self.peers_by_validator.get(&validator_id) {
                    self.drop_peer(validator_id, peer.addr).await;
                }
            }
        }
    }

    async fn handle_control(&mut self, control: PeerManagerMessage) {
        match control {
            PeerManagerMessage::Connected { addr, handshake } => {
                self.register_peer(addr, handshake).await;
            }
            PeerManagerMessage::Disconnected { validator_id, addr } => {
                self.drop_peer(validator_id, addr).await;
            }
        }
    }

    async fn register_peer(&mut self, addr: SocketAddr, handshake: HandshakeResult) {
        let peer_validator_id = handshake.peer_validator_id;

        if let Some(existing) = self.peers_by_validator.get(&peer_validator_id) {
            // Tie-breaking: keep connection where initiator_id < responder_id.
            // This is deterministic — both sides compute the same outcome.
            let (initiator_id, responder_id) = if handshake.is_initiator {
                (self.local_validator_id, peer_validator_id)
            } else {
                (peer_validator_id, self.local_validator_id)
            };
            let keep_new = initiator_id < responder_id;
            if keep_new {
                // Drop old connection, register new one below
                let existing_addr = existing.addr;
                eprintln!(
                    "[p2p] tie-break: replacing connection to {} with new {} (validator {})",
                    existing_addr,
                    addr,
                    short_validator_id(&peer_validator_id),
                );
                self.drop_peer(peer_validator_id, existing_addr).await;
            } else {
                // Keep old connection, drop new one
                eprintln!(
                    "[p2p] tie-break: keeping existing connection to {} (validator {}), dropping new {}",
                    existing.addr,
                    short_validator_id(&peer_validator_id),
                    addr,
                );
                return;
            }
        }

        let stream = handshake.stream;
        let send_key = handshake.send_key;
        let recv_key = handshake.recv_key;
        let (reader_half, writer_half) = stream.into_split();
        let (write_tx, write_rx) = mpsc::channel(self.per_peer_write_buffer);
        let control_tx = self.control_tx.clone();
        let event_tx = self.event_tx.clone();

        let read_task = tokio::spawn(async move {
            let mut reader = FrameReader::new(reader_half, recv_key);
            loop {
                let plaintext = match reader.read_frame().await {
                    Ok(bytes) => bytes,
                    Err(_) => break,
                };
                // encode_wire() includes a 4-byte length prefix; strip it before decode
                let payload = if plaintext.len() >= 4 { &plaintext[4..] } else { &plaintext[..] };
                let msg = match Message::decode_wire(payload) {
                    Ok(msg) => msg,
                    Err(_) => break,
                };
                if event_tx
                    .send(NetworkEvent::Message {
                        from: addr,
                        validator_id: peer_validator_id,
                        msg,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = control_tx
                .send(PeerManagerMessage::Disconnected {
                    validator_id: peer_validator_id,
                    addr,
                })
                .await;
        });

        let control_tx = self.control_tx.clone();
        let write_task = tokio::spawn(async move {
            let mut writer = FrameWriter::new(writer_half, send_key);
            run_write_loop(&mut writer, write_rx).await;
            let _ = control_tx
                .send(PeerManagerMessage::Disconnected {
                    validator_id: peer_validator_id,
                    addr,
                })
                .await;
        });

        let _ = self.peer_table.add(addr);
        self.peer_table.set_validator_id(&addr, peer_validator_id);
        self.peer_table.mark_connected(&addr);
        self.validator_by_addr.insert(addr, peer_validator_id);
        self.peers_by_validator.insert(
            peer_validator_id,
            ManagedPeer {
                addr,
                write_tx,
                read_task,
                write_task,
            },
        );
        self.connected_peers.store(self.peers_by_validator.len(), Ordering::Relaxed);
        let _ = self
            .event_tx
            .send(NetworkEvent::PeerConnected {
                validator_id: peer_validator_id,
                addr,
            })
            .await;
    }

    async fn try_send_to_validator(&mut self, validator_id: Bytes32, outbound: OutboundMessage) {
        let Some(peer) = self.peers_by_validator.get(&validator_id) else {
            return;
        };
        match peer.write_tx.try_send(outbound) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(message)) => {
                if message.point_to_point {
                    self.drop_peer(validator_id, peer.addr).await;
                } else {
                    self.peer_table.score_event(&peer.addr, ScoreEvent::Timeout);
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.drop_peer(validator_id, peer.addr).await;
            }
        }
    }

    async fn drop_peer(&mut self, validator_id: Bytes32, addr: SocketAddr) {
        // Only remove if the stored peer matches the given addr.
        // This prevents a stale Disconnected message from a replaced connection
        // from removing the new connection that took its validator_id slot.
        if let Some(peer) = self.peers_by_validator.get(&validator_id) {
            if peer.addr == addr {
                let peer = self.peers_by_validator.remove(&validator_id).unwrap();
                peer.read_task.abort();
                peer.write_task.abort();
            } else {
                eprintln!(
                    "[p2p] ignoring stale disconnect for {} (validator {}, current addr is {})",
                    addr,
                    short_validator_id(&validator_id),
                    peer.addr,
                );
                return;
            }
        }
        self.validator_by_addr.remove(&addr);
        self.peer_table.mark_disconnected(&addr);
        self.connected_peers.store(self.peers_by_validator.len(), Ordering::Relaxed);
        let _ = self
            .event_tx
            .send(NetworkEvent::PeerDisconnected { validator_id, addr })
            .await;
    }
}

async fn run_write_loop(
    writer: &mut FrameWriter<tokio::net::tcp::OwnedWriteHalf>,
    mut write_rx: mpsc::Receiver<OutboundMessage>,
) {
    while let Some(outbound) = write_rx.recv().await {
        let Ok(wire) = outbound.msg.encode_wire() else {
            continue;
        };
        if writer.write_frame(&wire).await.is_err() {
            break;
        }
    }
}

/// Static configuration for the peer-manager actor.
#[derive(Clone)]
pub struct PeerManagerConfig {
    /// Local validator identity for deterministic duplicate-connection resolution.
    pub local_validator_id: Bytes32,
    /// Outbound event sink consumed by `indra-node`.
    pub event_tx: mpsc::Sender<NetworkEvent>,
    /// Maximum buffered commands from the node into the actor.
    pub command_buffer: usize,
    /// Maximum buffered outbound messages per peer.
    pub per_peer_write_buffer: usize,
}

/// Handle returned to callers that need to enqueue network commands or attach peers.
#[derive(Clone)]
pub struct PeerManagerHandle {
    command_tx: mpsc::Sender<NetworkCommand>,
    control_tx: mpsc::Sender<PeerManagerMessage>,
    connected_peers: Arc<AtomicUsize>,
}

impl PeerManagerHandle {
    /// Queue a node-originated network command.
    pub async fn send(
        &self,
        command: NetworkCommand,
    ) -> Result<(), mpsc::error::SendError<NetworkCommand>> {
        self.command_tx.send(command).await
    }

    /// Queue a node-originated network command from synchronous code.
    pub fn send_blocking(&self, command: NetworkCommand) -> Result<(), mpsc::error::SendError<NetworkCommand>> {
        self.command_tx.blocking_send(command)
    }

    /// Register a fully handshaked peer with the actor.
    pub async fn register_peer(
        &self,
        addr: SocketAddr,
        handshake: HandshakeResult,
    ) -> Result<(), ()> {
        self.control_tx
            .send(PeerManagerMessage::Connected { addr, handshake })
            .await
            .map_err(|_| ())
    }

    /// Number of currently connected authenticated peers.
    pub fn connected_peer_count(&self) -> usize {
        self.connected_peers.load(Ordering::Relaxed)
    }
}

/// Spawn the peer-manager actor and return its handle.
pub fn spawn_peer_manager(config: PeerManagerConfig) -> PeerManagerHandle {
    let (command_tx, command_rx) = mpsc::channel(config.command_buffer);
    let (control_tx, control_rx) = mpsc::channel(config.command_buffer);
    let connected_peers = Arc::new(AtomicUsize::new(0));
    let actor = PeerManagerActor {
        local_validator_id: config.local_validator_id,
        event_tx: config.event_tx,
        command_rx,
        control_rx,
        control_tx: control_tx.clone(),
        peer_table: PeerTable::new(),
        peers_by_validator: HashMap::new(),
        validator_by_addr: HashMap::new(),
        connected_peers: Arc::clone(&connected_peers),
        per_peer_write_buffer: config.per_peer_write_buffer,
    };
    tokio::spawn(actor.run());
    PeerManagerHandle {
        command_tx,
        control_tx,
        connected_peers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;
    use tokio::net::{TcpListener, TcpStream};

    async fn stream_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = TcpStream::connect(addr).await.expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        (client, server)
    }

    fn test_actor(event_tx: mpsc::Sender<NetworkEvent>, local_validator_id: Bytes32) -> PeerManagerActor {
        let (_command_tx, command_rx) = mpsc::channel(16);
        let (control_tx, control_rx) = mpsc::channel(16);
        PeerManagerActor {
            local_validator_id,
            event_tx,
            command_rx,
            control_rx,
            control_tx,
            peer_table: PeerTable::new(),
            peers_by_validator: HashMap::new(),
            validator_by_addr: HashMap::new(),
            connected_peers: Arc::new(AtomicUsize::new(0)),
            per_peer_write_buffer: 4,
        }
    }

    async fn handshake_result(
        peer_validator_id: Bytes32,
        _addr: SocketAddr,
        is_initiator: bool,
    ) -> (HandshakeResult, TcpStream) {
        let (owned, keepalive) = stream_pair().await;
        (
            HandshakeResult {
                peer_validator_id,
                send_key: [0x11; 32],
                recv_key: [0x22; 32],
                stream: owned,
                is_initiator,
            },
            keepalive,
        )
    }

    #[tokio::test]
    async fn test_duplicate_connection_tie_breaking() {
        let local = Bytes32::from([0x01; 32]);
        let peer = Bytes32::from([0x02; 32]);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, local);

        let addr_old: SocketAddr = "127.0.0.1:30001".parse().unwrap();
        let addr_new: SocketAddr = "127.0.0.1:30002".parse().unwrap();
        let ((old_hs, _old_keepalive), (new_hs, _new_keepalive)) = tokio::join!(
            handshake_result(peer, addr_old, false),
            handshake_result(peer, addr_new, true),
        );

        actor.register_peer(addr_old, old_hs).await;
        actor.register_peer(addr_new, new_hs).await;

        assert_eq!(actor.peers_by_validator.len(), 1);
        assert_eq!(actor.connected_peers.load(Ordering::Relaxed), 1);
        assert_eq!(actor.peers_by_validator.get(&peer).unwrap().addr, addr_new);
        assert!(!actor.validator_by_addr.contains_key(&addr_old));
        assert_eq!(actor.validator_by_addr.get(&addr_new), Some(&peer));

        let mut connected = 0;
        let mut disconnected = 0;
        while let Ok(event) = event_rx.try_recv() {
            match event {
                NetworkEvent::PeerConnected { .. } => connected += 1,
                NetworkEvent::PeerDisconnected { .. } => disconnected += 1,
                NetworkEvent::Message { .. } => {}
            }
        }
        assert_eq!(connected, 2);
        assert_eq!(disconnected, 1);
    }

    #[tokio::test]
    async fn test_stale_disconnect_preserves_replacement() {
        let local = Bytes32::from([0x01; 32]);
        let peer = Bytes32::from([0x02; 32]);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, local);

        let addr_old: SocketAddr = "127.0.0.1:31001".parse().unwrap();
        let addr_new: SocketAddr = "127.0.0.1:31002".parse().unwrap();
        let ((old_hs, _old_keepalive), (new_hs, _new_keepalive)) = tokio::join!(
            handshake_result(peer, addr_old, false),
            handshake_result(peer, addr_new, true),
        );

        actor.register_peer(addr_old, old_hs).await;
        actor.register_peer(addr_new, new_hs).await;
        let before = actor.connected_peers.load(Ordering::Relaxed);
        actor.drop_peer(peer, addr_old).await;

        assert_eq!(actor.connected_peers.load(Ordering::Relaxed), before);
        assert_eq!(actor.peers_by_validator.get(&peer).unwrap().addr, addr_new);
        assert!(!actor.validator_by_addr.contains_key(&addr_old));
        assert_eq!(actor.validator_by_addr.get(&addr_new), Some(&peer));

        let mut disconnected = 0;
        while let Ok(event) = event_rx.try_recv() {
            if matches!(event, NetworkEvent::PeerDisconnected { .. }) {
                disconnected += 1;
            }
        }
        assert_eq!(disconnected, 1);
    }

    #[tokio::test]
    async fn test_send_to_unknown_validator() {
        let local = Bytes32::from([0x01; 32]);
        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut actor = test_actor(event_tx, local);
        actor
            .handle_command(NetworkCommand::SendTo {
                validator_id: Bytes32::from([0xFF; 32]),
                msg: Message::Ping(1),
            })
            .await;
        assert_eq!(actor.connected_peers.load(Ordering::Relaxed), 0);
        assert!(actor.peers_by_validator.is_empty());
    }
}
