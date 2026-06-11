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
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Result of polling a connection for one inbound message.
pub enum RecvStatus {
    /// A full message was received.
    Message(Message),
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
}

impl Connection {
    /// Wrap an existing TCP stream.
    pub fn from_stream(stream: TcpStream) -> NetworkResult<Self> {
        let remote_addr = stream.peer_addr()?;
        stream.set_read_timeout(Some(READ_TIMEOUT))?;
        stream.set_write_timeout(Some(READ_TIMEOUT))?;
        Ok(Self { stream, remote_addr })
    }

    /// Clone the underlying stream for a dedicated writer thread.
    pub fn clone_stream(&self) -> NetworkResult<TcpStream> {
        Ok(self.stream.try_clone()?)
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
    /// Reads the 4-byte length prefix, then the payload.
    pub fn recv(&mut self) -> NetworkResult<RecvStatus> {
        let mut len_buf = [0u8; 4];
        match self.stream.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(RecvStatus::Disconnected),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(RecvStatus::NoData),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return Ok(RecvStatus::NoData),
            Err(e) => return Err(NetworkError::Io(e)),
        }

        let total_len = u32::from_le_bytes(len_buf) as usize;
        if total_len > MAX_MSG_BYTES {
            return Err(NetworkError::MessageTooLarge {
                size: total_len,
                max: MAX_MSG_BYTES,
            });
        }

        let mut payload = vec![0u8; total_len];
        self.stream.read_exact(&mut payload)?;

        let msg = Message::decode_wire(&payload)?;
        Ok(RecvStatus::Message(msg))
    }

    /// Close this connection.
    pub fn close(self) -> NetworkResult<()> {
        self.stream.shutdown(std::net::Shutdown::Both)?;
        Ok(())
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
        Ok(Self { listener, local_addr })
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
        let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
            .map_err(|e| NetworkError::ConnectionFailed {
                addr: addr.to_string(),
                reason: e.to_string(),
            })?;
        Connection::from_stream(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

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
        assert!(matches!(received, Message::Ping(12345)));
    }

    #[test]
    fn non_blocking_accept_returns_none_when_empty() {
        let transport = Transport::bind("127.0.0.1:0").unwrap();
        assert!(transport.accept().unwrap().is_none());
    }
}
