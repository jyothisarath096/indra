//! TCP transport layer.
//!
//! Provides synchronous TCP connections for sending and receiving
//! length-prefixed wire messages.
//!
//! ## Phase 7 upgrade
//!
//! Phase 7 replaces this with an async Tokio implementation and adds:
//! - Noise protocol handshake (encrypted + authenticated connections)
//! - Connection multiplexing (yamux)
//! - Peer ID verification against public key

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use crate::{
    error::{NetworkError, NetworkResult},
    message::{Message, MAX_MSG_BYTES},
};

/// Default connection timeout.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default read timeout.
pub const READ_TIMEOUT: Duration = Duration::from_millis(1);
/// Default write timeout.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Result of polling a connection for one inbound message.
pub enum RecvStatus {
    /// A full message was received.
    Message(Box<Message>),
    /// No message is available yet; the connection is still alive.
    NoData,
    /// The peer closed the connection cleanly.
    Disconnected,
}

/// A TCP connection to a single peer.
pub struct Connection {
    stream: TcpStream,
    /// The remote peer's address.
    pub remote_addr: SocketAddr,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl Connection {
    /// Wrap an existing TCP stream.
    pub fn from_stream(stream: TcpStream) -> NetworkResult<Self> {
        let remote_addr = stream.peer_addr()?;
        stream.set_read_timeout(Some(READ_TIMEOUT))?;
        stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
        Ok(Self {
            stream,
            remote_addr,
            read_buf: Vec::new(),
            read_pos: 0,
        })
    }

    /// Write raw framed bytes to this peer.
    pub fn write_raw(&mut self, bytes: &[u8]) -> NetworkResult<()> {
        self.stream.write_all(bytes)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Send a message to this peer.
    pub fn send(&mut self, msg: &Message) -> NetworkResult<()> {
        let wire = msg.encode_wire()?;
        self.write_raw(&wire)
    }

    /// Receive one message from this peer.
    ///
    /// Buffers length-prefixed wire data until a full message is available.
    pub fn recv(&mut self) -> NetworkResult<RecvStatus> {
        let mut saw_disconnect = false;
        let mut scratch = [0u8; 8192];
        loop {
            match self.stream.read(&mut scratch) {
                Ok(0) => {
                    saw_disconnect = true;
                    break;
                }
                Ok(n) => {
                    self.read_buf.extend_from_slice(scratch.get(..n).ok_or_else(|| {
                        NetworkError::DecodeFailed {
                            reason: "invalid transport read length".to_string(),
                        }
                    })?);
                    if n < scratch.len() {
                        break;
                    }
                }
                Err(e) => match e.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => break,
                    std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe => {
                        saw_disconnect = true;
                        break;
                    }
                    _ => return Err(NetworkError::Io(e)),
                },
            }
        }

        self.compact_read_buf();
        if self.read_buf.len() - self.read_pos < 4 {
            return if saw_disconnect && self.read_buf.len() == self.read_pos {
                Ok(RecvStatus::Disconnected)
            } else {
                Ok(RecvStatus::NoData)
            };
        }

        let len_start = self.read_pos;
        let length_prefix = self
            .read_buf
            .get(len_start..len_start + 4)
            .ok_or_else(|| NetworkError::DecodeFailed {
                reason: "truncated length prefix".to_string(),
            })?;
        let total_len = u32::from_le_bytes(
            length_prefix
                .try_into()
                .map_err(|_| NetworkError::DecodeFailed {
                    reason: "invalid length prefix".to_string(),
                })?,
        ) as usize;
        if total_len > MAX_MSG_BYTES {
            return Err(NetworkError::MessageTooLarge {
                size: total_len,
                max: MAX_MSG_BYTES,
            });
        }

        let frame_len = 4 + total_len;
        if self.read_buf.len() - self.read_pos < frame_len {
            return if saw_disconnect && self.read_buf.len() == self.read_pos {
                Ok(RecvStatus::Disconnected)
            } else {
                Ok(RecvStatus::NoData)
            };
        }

        let payload_start = self.read_pos + 4;
        let payload_end = self.read_pos + frame_len;
        let payload = self
            .read_buf
            .get(payload_start..payload_end)
            .ok_or_else(|| NetworkError::DecodeFailed {
                reason: "invalid transport frame bounds".to_string(),
            })?
            .to_vec();
        self.read_pos = payload_end;
        self.compact_read_buf();

        let msg = match Message::decode_wire(&payload) {
            Ok(msg) => msg,
            Err(NetworkError::UnknownMessageType { .. }) => return Ok(RecvStatus::NoData),
            Err(error) => return Err(error),
        };
        Ok(RecvStatus::Message(Box::new(msg)))
    }

    /// Close this connection.
    pub fn close(self) -> NetworkResult<()> {
        self.stream.shutdown(std::net::Shutdown::Both)?;
        Ok(())
    }

    fn compact_read_buf(&mut self) {
        if self.read_pos == 0 {
            return;
        }
        if self.read_pos >= self.read_buf.len() {
            self.read_buf.clear();
            self.read_pos = 0;
            return;
        }

        self.read_buf.drain(..self.read_pos);
        self.read_pos = 0;
    }
}

/// The TCP transport: listens for inbound and dials outbound connections.
pub struct Transport {
    listener: TcpListener,
    /// The local address we're listening on.
    pub local_addr: SocketAddr,
}

impl Transport {
    /// Bind to the given address and start listening.
    pub fn bind(addr: &str) -> NetworkResult<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            local_addr,
        })
    }

    /// Accept one inbound connection (non-blocking).
    /// Returns None if no connection is waiting.
    pub fn accept(&self) -> NetworkResult<Option<Connection>> {
        match self.listener.accept() {
            Ok((stream, _)) => Ok(Some(Connection::from_stream(stream)?)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(NetworkError::Io(e)),
        }
    }

    /// Dial an outbound connection to a peer.
    pub fn dial(&self, addr: SocketAddr) -> NetworkResult<Connection> {
        let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(|e| {
            NetworkError::ConnectionFailed {
                addr: addr.to_string(),
                reason: e.to_string(),
            }
        })?;
        Connection::from_stream(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::Bytes32;
    use std::{net::TcpStream, thread};

    #[test]
    fn bind_and_get_local_addr() {
        let transport = Transport::bind("127.0.0.1:0").unwrap();
        let addr = transport.local_addr;
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert!(addr.port() > 0);
    }

    #[test]
    fn send_and_receive_message() {
        let server = Transport::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr;

        let handle = thread::spawn(move || {
            // Wait for connection with timeout
            let start = std::time::Instant::now();
            loop {
                match server.accept().unwrap() {
                    Some(mut conn) => {
                        let msg = match conn.recv().unwrap() {
                            RecvStatus::Message(msg) => msg,
                            RecvStatus::NoData => continue,
                            RecvStatus::Disconnected => panic!("connection closed unexpectedly"),
                        };
                        return msg;
                    }
                    None => {
                        if start.elapsed() > Duration::from_secs(3) {
                            panic!("timeout waiting for connection");
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        });

        // Give server time to start
        thread::sleep(Duration::from_millis(50));

        let client_transport = Transport::bind("127.0.0.1:0").unwrap();
        let mut conn = client_transport.dial(server_addr).unwrap();
        conn.send(&Message::Ping(12345)).unwrap();

        let received = handle.join().unwrap();
        assert!(matches!(*received, Message::Ping(12345)));
    }

    #[test]
    fn non_blocking_accept_returns_none_when_empty() {
        let transport = Transport::bind("127.0.0.1:0").unwrap();
        assert!(transport.accept().unwrap().is_none());
    }

    #[test]
    fn recv_assembles_message_from_multiple_chunks() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (stream, _) = server.accept().unwrap();
            let mut conn = Connection::from_stream(stream).unwrap();

            assert!(matches!(conn.recv().unwrap(), RecvStatus::NoData));

            let start = std::time::Instant::now();
                loop {
                    match conn.recv().unwrap() {
                    RecvStatus::Message(msg) => return msg,
                    RecvStatus::NoData => {
                        if start.elapsed() > Duration::from_secs(2) {
                            panic!("timeout waiting for assembled message");
                        }
                        thread::sleep(Duration::from_millis(1));
                    }
                    RecvStatus::Disconnected => panic!("connection closed unexpectedly"),
                }
            }
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let wire = Message::Status {
            height: 42,
            tip_hash: Bytes32::ZERO,
            round: 0,
        }
        .encode_wire()
        .unwrap();

        client.write_all(&wire[..6]).unwrap();
        client.flush().unwrap();
        thread::sleep(Duration::from_millis(10));
        client.write_all(&wire[6..]).unwrap();
        client.flush().unwrap();

        let received = handle.join().unwrap();
        match *received {
            Message::Status { height, .. } => assert_eq!(height, 42),
            other => panic!("unexpected message: {:?}", other.message_type()),
        }
    }

    #[test]
    fn recv_decodes_back_to_back_messages() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (stream, _) = server.accept().unwrap();
            let mut conn = Connection::from_stream(stream).unwrap();

            let first = loop {
                match conn.recv().unwrap() {
                    RecvStatus::Message(msg) => break msg,
                    RecvStatus::NoData => thread::sleep(Duration::from_millis(1)),
                    RecvStatus::Disconnected => panic!("connection closed unexpectedly"),
                }
            };

            let second = loop {
                match conn.recv().unwrap() {
                    RecvStatus::Message(msg) => break msg,
                    RecvStatus::NoData => thread::sleep(Duration::from_millis(1)),
                    RecvStatus::Disconnected => panic!("connection closed unexpectedly"),
                }
            };

            (first, second)
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let first = Message::Ping(1).encode_wire().unwrap();
        let second = Message::Pong(2).encode_wire().unwrap();
        client.write_all(&first).unwrap();
        client.write_all(&second).unwrap();
        client.flush().unwrap();

        let (first_msg, second_msg) = handle.join().unwrap();
        assert!(matches!(*first_msg, Message::Ping(1)));
        assert!(matches!(*second_msg, Message::Pong(2)));
    }

    #[test]
    fn recv_skips_unknown_message_type_without_disconnect() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (stream, _) = server.accept().unwrap();
            let mut conn = Connection::from_stream(stream).unwrap();

            let first = match conn.recv().unwrap() {
                RecvStatus::NoData => RecvStatus::NoData,
                RecvStatus::Message(_) => panic!("unknown message should be skipped"),
                RecvStatus::Disconnected => panic!("connection closed unexpectedly"),
            };
            assert!(matches!(first, RecvStatus::NoData));

            loop {
                match conn.recv().unwrap() {
                    RecvStatus::Message(msg) => break msg,
                    RecvStatus::NoData => thread::sleep(Duration::from_millis(1)),
                    RecvStatus::Disconnected => panic!("connection closed unexpectedly"),
                }
            }
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(&1u32.to_le_bytes()).unwrap();
        client.write_all(&[0xFE]).unwrap();
        client
            .write_all(&Message::Ping(99).encode_wire().unwrap())
            .unwrap();
        client.flush().unwrap();

        let msg = handle.join().unwrap();
        assert!(matches!(*msg, Message::Ping(99)));
    }

    #[test]
    fn recv_rejects_oversized_length_prefix() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (stream, _) = server.accept().unwrap();
            let mut conn = Connection::from_stream(stream).unwrap();

            let err = loop {
                match conn.recv() {
                    Ok(RecvStatus::NoData) => thread::sleep(Duration::from_millis(1)),
                    Ok(RecvStatus::Message(_)) => panic!("unexpected message"),
                    Ok(RecvStatus::Disconnected) => panic!("unexpected disconnect"),
                    Err(err) => break err,
                }
            };

            match err {
                NetworkError::MessageTooLarge { size, max } => {
                    assert_eq!(size, MAX_MSG_BYTES + 1);
                    assert_eq!(max, MAX_MSG_BYTES);
                }
                other => panic!("unexpected error: {other:?}"),
            }
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .write_all(&((MAX_MSG_BYTES as u32) + 1).to_le_bytes())
            .unwrap();
        client.flush().unwrap();

        handle.join().unwrap();
    }
}
