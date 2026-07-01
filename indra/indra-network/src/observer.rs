//! Plain observer/full-node transport.
//!
//! This is intentionally separate from the authenticated validator transport.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use indra_core::types::primitives::OBSERVER_HANDSHAKE_TIMEOUT_SECS;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use crate::{
    error::{NetworkError, NetworkResult},
    rate_limit::TokenBucket,
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

/// Maximum frame size for observer/full-node connections.
///
/// Observer traffic is intentionally read-only and does not need the full
/// validator transport frame budget. Keeping this lower prevents public
/// observer clients from pinning large buffers per connection.
pub const MAX_OBSERVER_FRAME_BYTES: usize = 2_097_152;

/// Maximum bytes per second accepted from one observer connection.
pub const OBSERVER_BYTE_BUDGET_PER_SEC: u64 = 1_048_576;

/// Burst bytes accepted from one observer connection.
pub const OBSERVER_BYTE_BURST: u64 = 4_194_304;

/// Global cap on bytes actively allocated by observer frame reads.
pub const MAX_OBSERVER_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

static OBSERVER_BYTES_ACTIVE: AtomicU64 = AtomicU64::new(0);

/// Per-connection observer frame budget.
#[derive(Debug, Clone)]
pub struct ObserverFrameLimiter {
    byte_bucket: TokenBucket,
}

impl ObserverFrameLimiter {
    /// Construct a new observer limiter.
    pub fn new() -> Self {
        Self {
            byte_bucket: TokenBucket::new_bytes(OBSERVER_BYTE_BUDGET_PER_SEC, OBSERVER_BYTE_BURST),
        }
    }

    fn check_frame(&mut self, len: usize) -> NetworkResult<()> {
        if !self.byte_bucket.try_consume_bytes(len as u64) {
            return Err(NetworkError::InvalidFrame {
                reason: "observer byte budget exhausted".to_string(),
            });
        }
        Ok(())
    }
}

impl Default for ObserverFrameLimiter {
    fn default() -> Self {
        Self::new()
    }
}

struct ObserverAllocationGuard {
    bytes: u64,
}

impl ObserverAllocationGuard {
    fn reserve(bytes: u64) -> NetworkResult<Self> {
        let mut current = OBSERVER_BYTES_ACTIVE.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                return Err(NetworkError::MessageTooLarge {
                    size: usize::MAX,
                    max: MAX_OBSERVER_TOTAL_BYTES as usize,
                });
            };
            if next > MAX_OBSERVER_TOTAL_BYTES {
                return Err(NetworkError::MessageTooLarge {
                    size: next as usize,
                    max: MAX_OBSERVER_TOTAL_BYTES as usize,
                });
            }
            match OBSERVER_BYTES_ACTIVE.compare_exchange(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(Self { bytes }),
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for ObserverAllocationGuard {
    fn drop(&mut self) {
        OBSERVER_BYTES_ACTIVE.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

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
    let mut limiter = ObserverFrameLimiter::new();
    read_frame_plain_limited(stream, &mut limiter).await
}

/// Read a plain observer frame using a persistent per-connection limiter.
pub async fn read_frame_plain_limited<R>(
    stream: &mut R,
    limiter: &mut ObserverFrameLimiter,
) -> NetworkResult<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_OBSERVER_FRAME_BYTES {
        return Err(NetworkError::MessageTooLarge {
            size: len,
            max: MAX_OBSERVER_FRAME_BYTES,
        });
    }
    limiter.check_frame(len)?;
    let _allocation_guard = ObserverAllocationGuard::reserve(len as u64)?;
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    Ok(data)
}

/// Write a plain unencrypted framed message to a TCP stream.
pub async fn write_frame_plain<W>(stream: &mut W, data: &[u8]) -> NetworkResult<()>
where
    W: AsyncWrite + Unpin,
{
    if data.len() > MAX_OBSERVER_FRAME_BYTES {
        return Err(NetworkError::MessageTooLarge {
            size: data.len(),
            max: MAX_OBSERVER_FRAME_BYTES,
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
    use crate::{message::Message, message::MAX_MSG_BYTES, NetworkError};

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
            .write_all(&((MAX_OBSERVER_FRAME_BYTES as u32) + 1).to_le_bytes())
            .await
            .unwrap();
        let err = server.await.unwrap().unwrap_err();
        assert!(matches!(err, NetworkError::MessageTooLarge { .. }));
    }

    #[test]
    fn observer_frame_size_is_bounded_below_14mb() {
        assert!(MAX_OBSERVER_FRAME_BYTES < MAX_MSG_BYTES);
    }

    #[tokio::test]
    async fn observer_large_frame_claim_is_rejected() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let server_task = tokio::spawn(async move {
            let mut limiter = ObserverFrameLimiter::new();
            read_frame_plain_limited(&mut server, &mut limiter).await
        });
        client
            .write_all(&((MAX_OBSERVER_FRAME_BYTES as u32) + 1).to_le_bytes())
            .await
            .unwrap();
        let err = server_task.await.unwrap().unwrap_err();
        assert!(matches!(err, NetworkError::MessageTooLarge { .. }));
    }

    #[tokio::test]
    async fn observer_byte_budget_is_enforced_per_connection() {
        let capacity = MAX_OBSERVER_FRAME_BYTES * 3 + 64;
        let (mut client, mut server) = tokio::io::duplex(capacity);
        let server_task = tokio::spawn(async move {
            let mut limiter = ObserverFrameLimiter::new();
            read_frame_plain_limited(&mut server, &mut limiter)
                .await
                .unwrap();
            read_frame_plain_limited(&mut server, &mut limiter)
                .await
                .unwrap();
            read_frame_plain_limited(&mut server, &mut limiter).await
        });
        let frame = vec![0xA5u8; MAX_OBSERVER_FRAME_BYTES];
        write_frame_plain(&mut client, &frame).await.unwrap();
        write_frame_plain(&mut client, &frame).await.unwrap();
        write_frame_plain(&mut client, &frame).await.unwrap();
        let err = server_task.await.unwrap().unwrap_err();
        assert!(matches!(err, NetworkError::InvalidFrame { .. }));
    }
}
