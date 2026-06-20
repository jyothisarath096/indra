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
            NetworkCommand::SendTo { addr, msg } => {
                if let Some(validator_id) = self.validator_by_addr.get(&addr).copied() {
                    self.try_send_to_validator(validator_id, OutboundMessage {
                        msg,
                        point_to_point: true,
                    }).await;
                }
            }
            NetworkCommand::Disconnect { addr } => {
                if let Some(validator_id) = self.validator_by_addr.get(&addr).copied() {
                    self.drop_peer(validator_id, addr).await;
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
            if self.local_validator_id < peer_validator_id {
                let existing_addr = existing.addr;
                self.drop_peer(peer_validator_id, existing_addr).await;
            } else {
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
                let msg = match Message::decode_wire(&plaintext) {
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
        if let Some(peer) = self.peers_by_validator.remove(&validator_id) {
            peer.read_task.abort();
            peer.write_task.abort();
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
