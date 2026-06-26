//! AEAD framing for the async INDRA transport.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, Key, KeyInit, Nonce,
};

use crate::{
    error::{NetworkError, NetworkResult},
    message::MAX_MSG_BYTES,
};

const FRAME_HEADER_LEN: usize = 4 + 12;
const TAG_LEN: usize = 16;

fn build_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn cipher_from_key(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(Key::from_slice(key))
}

pub(crate) fn encrypt_with_aad(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> NetworkResult<Vec<u8>> {
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher_from_key(key)
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| NetworkError::InvalidFrame {
            reason: "encryption failed".to_string(),
        })
}

pub(crate) fn decrypt_with_aad(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> NetworkResult<Vec<u8>> {
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher_from_key(key)
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| NetworkError::InvalidFrame {
            reason: "authentication failed".to_string(),
        })
}

/// Encrypts and writes transport frames to an async stream.
pub struct FrameWriter<W> {
    key: [u8; 32],
    nonce_counter: u64,
    stream: W,
}

impl<W> FrameWriter<W>
where
    W: AsyncWrite + Unpin,
{
    /// Create a new frame writer. Nonce `0` is reserved for the handshake auth frame.
    pub fn new(stream: W, key: [u8; 32]) -> Self {
        Self {
            key,
            nonce_counter: 1,
            stream,
        }
    }

    /// Write one authenticated encrypted frame.
    pub async fn write_frame(&mut self, plaintext: &[u8]) -> NetworkResult<()> {
        if plaintext.len() > MAX_MSG_BYTES {
            return Err(NetworkError::MessageTooLarge {
                size: plaintext.len(),
                max: MAX_MSG_BYTES,
            });
        }
        if self.nonce_counter == u64::MAX {
            return Err(NetworkError::NonceExhausted);
        }

        let len_bytes = (plaintext.len() as u32).to_le_bytes();
        let nonce_bytes = build_nonce(self.nonce_counter);
        let mut aad = Vec::with_capacity(FRAME_HEADER_LEN);
        aad.extend_from_slice(&len_bytes);
        aad.extend_from_slice(&nonce_bytes);
        let ciphertext = encrypt_with_aad(&self.key, &nonce_bytes, plaintext, &aad)?;

        self.stream.write_all(&len_bytes).await?;
        self.stream.write_all(&nonce_bytes).await?;
        self.stream.write_all(&ciphertext).await?;
        self.stream.flush().await?;
        self.nonce_counter = self
            .nonce_counter
            .checked_add(1)
            .ok_or(NetworkError::NonceExhausted)?;
        Ok(())
    }
}

/// Reads and decrypts transport frames from an async stream.
pub struct FrameReader<R> {
    key: [u8; 32],
    nonce_counter: u64,
    stream: R,
}

impl<R> FrameReader<R>
where
    R: AsyncRead + Unpin,
{
    /// Create a new frame reader. Nonce `0` is reserved for the handshake auth frame.
    pub fn new(stream: R, key: [u8; 32]) -> Self {
        Self {
            key,
            nonce_counter: 1,
            stream,
        }
    }

    /// Read and decrypt one frame.
    pub async fn read_frame(&mut self) -> NetworkResult<Vec<u8>> {
        let mut len_bytes = [0u8; 4];
        self.stream.read_exact(&mut len_bytes).await?;
        let plaintext_len = u32::from_le_bytes(len_bytes) as usize;
        if plaintext_len > MAX_MSG_BYTES {
            return Err(NetworkError::MessageTooLarge {
                size: plaintext_len,
                max: MAX_MSG_BYTES,
            });
        }

        let mut nonce_bytes = [0u8; 12];
        self.stream.read_exact(&mut nonce_bytes).await?;
        let got_nonce = u64::from_le_bytes(nonce_bytes[4..].try_into().map_err(|_| {
            NetworkError::InvalidFrame {
                reason: "invalid nonce bytes".to_string(),
            }
        })?);
        if got_nonce != self.nonce_counter {
            return Err(NetworkError::UnexpectedNonce {
                expected: self.nonce_counter,
                got: got_nonce,
            });
        }

        let ciphertext_len =
            plaintext_len
                .checked_add(TAG_LEN)
                .ok_or(NetworkError::MessageTooLarge {
                    size: usize::MAX,
                    max: MAX_MSG_BYTES,
                })?;
        let mut ciphertext = vec![0u8; ciphertext_len];
        self.stream.read_exact(&mut ciphertext).await?;

        let mut aad = Vec::with_capacity(FRAME_HEADER_LEN);
        aad.extend_from_slice(&len_bytes);
        aad.extend_from_slice(&nonce_bytes);
        let plaintext = decrypt_with_aad(&self.key, &nonce_bytes, &ciphertext, &aad)?;
        self.nonce_counter = self
            .nonce_counter
            .checked_add(1)
            .ok_or(NetworkError::NonceExhausted)?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    use super::{decrypt_with_aad, encrypt_with_aad, FrameReader, FrameWriter};
    use crate::{error::NetworkError, message::MAX_MSG_BYTES};

    #[tokio::test]
    async fn frame_encrypt_decrypt_round_trip() {
        let (a, b) = duplex(4096);
        let key = [0x11u8; 32];
        let mut writer = FrameWriter::new(a, key);
        let mut reader = FrameReader::new(b, key);

        writer.write_frame(b"hello indra").await.unwrap();
        let plaintext = reader.read_frame().await.unwrap();
        assert_eq!(plaintext, b"hello indra");
    }

    #[tokio::test]
    async fn frame_aad_prevents_length_tampering() {
        let key = [0x22u8; 32];
        let nonce = [0u8; 12];
        let mut aad = Vec::new();
        aad.extend_from_slice(&(5u32).to_le_bytes());
        aad.extend_from_slice(&nonce);
        let ciphertext = encrypt_with_aad(&key, &nonce, b"abcde", &aad).unwrap();

        let mut tampered_aad = Vec::new();
        tampered_aad.extend_from_slice(&(6u32).to_le_bytes());
        tampered_aad.extend_from_slice(&nonce);
        let err = decrypt_with_aad(&key, &nonce, &ciphertext, &tampered_aad).unwrap_err();
        assert!(matches!(err, NetworkError::InvalidFrame { .. }));
    }

    #[tokio::test]
    async fn frame_rejects_replay() {
        let (mut tx, rx) = duplex(4096);
        let key = [0x33u8; 32];
        let mut writer = FrameWriter::new(&mut tx, key);
        writer.write_frame(b"one").await.unwrap();
        writer.write_frame(b"two").await.unwrap();
        tx.shutdown().await.unwrap();

        let mut raw = Vec::new();
        let mut reader_stream = rx;
        reader_stream.read_to_end(&mut raw).await.unwrap();

        let (mut replay_tx, replay_rx) = duplex(4096);
        replay_tx
            .write_all(&raw[..(4 + 12 + 3 + 16)])
            .await
            .unwrap();
        replay_tx
            .write_all(&raw[..(4 + 12 + 3 + 16)])
            .await
            .unwrap();
        replay_tx.shutdown().await.unwrap();

        let mut reader = FrameReader::new(replay_rx, key);
        let first = reader.read_frame().await.unwrap();
        assert_eq!(first, b"one");
        let err = reader.read_frame().await.unwrap_err();
        assert!(matches!(err, NetworkError::UnexpectedNonce { .. }));
    }

    #[tokio::test]
    async fn frame_rejects_oversized() {
        let (mut tx, rx) = duplex(32);
        let huge = (MAX_MSG_BYTES as u32).saturating_add(1).to_le_bytes();
        tx.write_all(&huge).await.unwrap();
        tx.write_all(&[0u8; 12]).await.unwrap();
        tx.shutdown().await.unwrap();

        let mut reader = FrameReader::new(rx, [0x44u8; 32]);
        let err = reader.read_frame().await.unwrap_err();
        assert!(matches!(err, NetworkError::MessageTooLarge { .. }));
    }
}
