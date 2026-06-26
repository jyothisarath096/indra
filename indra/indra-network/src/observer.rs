//! Plain observer/full-node transport.
//!
//! This is intentionally separate from the authenticated validator transport.

use std::time::Duration;

use indra_core::types::primitives::OBSERVER_HANDSHAKE_TIMEOUT_SECS;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use crate::{
    error::{NetworkError, NetworkResult},
    message::MAX_MSG_BYTES,
};

/// Observer protocol magic bytes.
pub const OBSERVER_MAGIC: &[u8; 4] = b"INOB";
/// Observer protocol version.
pub const OBSERVER_VERSION: u16 = 1;
/// Read-only observer node type.
pub const NODE_TYPE_OBSERVER: u8 = 0x01;
/// Full node type.
pub const NODE_TYPE_FULL: u8 = 0x02;
/// Observer handshake timeout.
pub const OBSERVER_HANDSHAKE_TIMEOUT: Duration =
    Duration::from_secs(OBSERVER_HANDSHAKE_TIMEOUT_SECS);

/// Result of a successful observer handshake.
#[derive(Debug)]
pub struct ObserverHandshakeResult {
    /// Peer node type.
    pub peer_node_type: u8,
    /// Handshaken stream.
    pub stream: TcpStream,
    /// True if this side initiated the connection.
    pub is_initiator: bool,
}

/// Perform the observer handshake as initiator.
pub async fn perform_observer_handshake_initiator(
    stream: TcpStream,
    node_type: u8,
) -> NetworkResult<ObserverHandshakeResult> {
    perform_observer_handshake(stream, node_type, true).await
}

/// Perform the observer handshake as responder.
pub async fn perform_observer_handshake_responder(
    stream: TcpStream,
    node_type: u8,
) -> NetworkResult<ObserverHandshakeResult> {
    perform_observer_handshake(stream, node_type, false).await
}

async fn perform_observer_handshake(
    mut stream: TcpStream,
    node_type: u8,
    is_initiator: bool,
) -> NetworkResult<ObserverHandshakeResult> {
    timeout(OBSERVER_HANDSHAKE_TIMEOUT, async {
        write_observer_hello(&mut stream, node_type).await?;
        let peer_node_type = read_observer_hello(&mut stream).await?;
        Ok(ObserverHandshakeResult {
            peer_node_type,
            stream,
            is_initiator,
        })
    })
    .await
    .map_err(|_| NetworkError::HandshakeTimeout)?
}

async fn write_observer_hello(stream: &mut TcpStream, node_type: u8) -> NetworkResult<()> {
    let mut hello = [0u8; 7];
    hello[..4].copy_from_slice(OBSERVER_MAGIC);
    hello[4..6].copy_from_slice(&OBSERVER_VERSION.to_le_bytes());
    hello[6] = node_type;
    stream.write_all(&hello).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_observer_hello(stream: &mut TcpStream) -> NetworkResult<u8> {
    let mut hello = [0u8; 7];
    stream.read_exact(&mut hello).await?;
    if &hello[..4] != OBSERVER_MAGIC {
        return Err(NetworkError::InvalidMagic);
    }
    let version = u16::from_le_bytes([hello[4], hello[5]]);
    if version != OBSERVER_VERSION {
        return Err(NetworkError::UnsupportedVersion { got: version });
    }
    Ok(hello[6])
}

/// Read a plain unencrypted framed message from a TCP stream.
pub async fn read_frame_plain<R>(stream: &mut R) -> NetworkResult<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_MSG_BYTES {
        return Err(NetworkError::MessageTooLarge {
            size: len,
            max: MAX_MSG_BYTES,
        });
    }
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    Ok(data)
}

/// Write a plain unencrypted framed message to a TCP stream.
pub async fn write_frame_plain<W>(stream: &mut W, data: &[u8]) -> NetworkResult<()>
where
    W: AsyncWrite + Unpin,
{
    if data.len() > MAX_MSG_BYTES {
        return Err(NetworkError::MessageTooLarge {
            size: data.len(),
            max: MAX_MSG_BYTES,
        });
    }
    stream.write_all(&(data.len() as u32).to_le_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
    };

    use super::*;
    use crate::{message::Message, NetworkError};

    async fn listener_pair() -> (TcpListener, std::net::SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    #[tokio::test]
    async fn observer_handshake_success() {
        let (listener, addr) = listener_pair().await;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            perform_observer_handshake_responder(stream, NODE_TYPE_FULL)
                .await
                .unwrap()
        });
        let client_stream = TcpStream::connect(addr).await.unwrap();
        let client = perform_observer_handshake_initiator(client_stream, NODE_TYPE_OBSERVER)
            .await
            .unwrap();
        let server = server.await.unwrap();
        assert_eq!(client.peer_node_type, NODE_TYPE_FULL);
        assert_eq!(server.peer_node_type, NODE_TYPE_OBSERVER);
        assert!(client.is_initiator);
        assert!(!server.is_initiator);
    }

    #[tokio::test]
    async fn observer_handshake_wrong_magic_rejected() {
        let (listener, addr) = listener_pair().await;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            perform_observer_handshake_responder(stream, NODE_TYPE_FULL).await
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"NOPE\x01\x00\x01").await.unwrap();
        let err = server.await.unwrap().unwrap_err();
        assert!(matches!(err, NetworkError::InvalidMagic));
    }

    #[tokio::test]
    async fn observer_handshake_wrong_version_rejected() {
        let (listener, addr) = listener_pair().await;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            perform_observer_handshake_responder(stream, NODE_TYPE_FULL).await
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"INOB\x02\x00\x01").await.unwrap();
        let err = server.await.unwrap().unwrap_err();
        assert!(matches!(err, NetworkError::UnsupportedVersion { got: 2 }));
    }

    #[tokio::test]
    async fn observer_handshake_timeout_on_idle() {
        let (listener, addr) = listener_pair().await;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            perform_observer_handshake_responder(stream, NODE_TYPE_FULL).await
        });
        let _client = TcpStream::connect(addr).await.unwrap();
        let err = server.await.unwrap().unwrap_err();
        assert!(matches!(err, NetworkError::HandshakeTimeout));
    }

    #[tokio::test]
    async fn plain_frame_round_trip() {
        let (listener, addr) = listener_pair().await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_frame_plain(&mut stream).await.unwrap()
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        let data = Message::Ping(42).encode_wire().unwrap();
        write_frame_plain(&mut client, &data).await.unwrap();
        assert_eq!(server.await.unwrap(), data);
    }

    #[tokio::test]
    async fn plain_frame_rejects_oversized_message() {
        let (listener, addr) = listener_pair().await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_frame_plain(&mut stream).await
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&((MAX_MSG_BYTES as u32) + 1).to_le_bytes())
            .await
            .unwrap();
        let err = server.await.unwrap().unwrap_err();
        assert!(matches!(err, NetworkError::MessageTooLarge { .. }));
    }
}
