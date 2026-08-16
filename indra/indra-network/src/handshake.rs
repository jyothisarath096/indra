//! Hybrid PQ authenticated transport handshake for INDRA.

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use blake3::Hash as Blake3Hash;
use indra_core::types::primitives::{Bytes32, MAX_CHAIN_ID_BYTES};
use indra_crypto::{verify_pq, PqKeypair, PqPublicKey, PqSignature, PQ_SIG_BYTES};
use ml_kem::{Decapsulate, Encapsulate, EncapsulationKey1024, Kem, KeyExport, MlKem1024};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    error::{NetworkError, NetworkResult},
    frame::{decrypt_with_aad, encrypt_with_aad},
    net_types::RelayValidatorKey,
};

const MAGIC: &[u8; 4] = b"INDR";
const VERSION: u16 = 2;
const X25519_PK_LEN: usize = 32;
const ML_KEM_1024_EK_LEN: usize = 1_568;
const ML_KEM_1024_CT_LEN: usize = 1_568;
const VALIDATOR_ID_LEN: usize = 32;
const CHAIN_PREFACE_HEADER_LEN: usize = 4 + 2 + 2;
const STEP1_LEN: usize = 4 + 2 + X25519_PK_LEN + ML_KEM_1024_EK_LEN + VALIDATOR_ID_LEN;
const STEP2_LEN: usize = 4 + 2 + X25519_PK_LEN + ML_KEM_1024_CT_LEN + VALIDATOR_ID_LEN;
const AUTH_CONTEXT: &[u8] = b"INDRA-auth-v1";
const AUTH_AAD: &[u8] = b"auth";

/// Static configuration shared by inbound and outbound handshakes.
#[derive(Clone)]
pub struct HandshakeConfig {
    /// Local validator identity announced on the wire.
    pub my_validator_id: Bytes32,
    /// Local ML-DSA-87 signing key for transport authentication.
    pub my_signing_key: PqKeypair,
    /// Current chain id used by relay signature verification.
    pub chain_id: String,
    /// Canonical fingerprint of the complete finalized genesis configuration.
    pub genesis_fingerprint: Bytes32,
    /// Accepted validator identities and their ML-DSA-87 verifying keys.
    pub known_validators: Vec<(Bytes32, PqPublicKey)>,
    /// Active validator public-key snapshot used by the peer manager for
    /// pre-relay cryptographic checks.
    pub relay_validator_keys: Vec<RelayValidatorKey>,
    /// Maximum time allowed for the full handshake.
    pub timeout: Duration,
}

/// Successful authenticated handshake output.
pub struct HandshakeResult {
    /// Remote validator identity authenticated during Step 4/5.
    pub peer_validator_id: Bytes32,
    /// Key for outbound application frames.
    pub send_key: [u8; 32],
    /// Key for inbound application frames.
    pub recv_key: [u8; 32],
    /// Established transport stream.
    pub stream: TcpStream,
    /// True if this node was the handshake initiator (dialed out).
    pub is_initiator: bool,
}

fn lookup_validator_pk(
    config: &HandshakeConfig,
    validator_id: Bytes32,
) -> NetworkResult<PqPublicKey> {
    config
        .known_validators
        .iter()
        .find(|(id, _)| *id == validator_id)
        .map(|(_, pk)| pk.clone())
        .ok_or(NetworkError::UnknownValidator { validator_id })
}

fn build_chain_preface(chain_id: &str, genesis_fingerprint: Bytes32) -> NetworkResult<Vec<u8>> {
    let chain_id = chain_id.as_bytes();
    if chain_id.is_empty() || chain_id.len() > MAX_CHAIN_ID_BYTES {
        return Err(NetworkError::DecodeFailed {
            reason: format!("local chain id length must be 1..={MAX_CHAIN_ID_BYTES} bytes"),
        });
    }
    let mut out = Vec::with_capacity(CHAIN_PREFACE_HEADER_LEN + chain_id.len() + 32);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(chain_id.len() as u16).to_le_bytes());
    out.extend_from_slice(chain_id);
    out.extend_from_slice(&genesis_fingerprint.0);
    Ok(out)
}

async fn write_chain_preface(
    stream: &mut TcpStream,
    chain_id: &str,
    genesis_fingerprint: Bytes32,
) -> NetworkResult<()> {
    stream
        .write_all(&build_chain_preface(chain_id, genesis_fingerprint)?)
        .await?;
    stream.flush().await?;
    Ok(())
}

async fn read_and_verify_chain_preface(
    stream: &mut TcpStream,
    expected_chain_id: &str,
    expected_genesis_fingerprint: Bytes32,
) -> NetworkResult<()> {
    let mut header = [0u8; CHAIN_PREFACE_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    parse_common_prefix(&header)?;
    let chain_len = u16::from_le_bytes([header[6], header[7]]) as usize;
    if chain_len == 0 || chain_len > MAX_CHAIN_ID_BYTES {
        return Err(NetworkError::DecodeFailed {
            reason: format!("peer chain id length must be 1..={MAX_CHAIN_ID_BYTES} bytes"),
        });
    }
    let mut chain_bytes = vec![0u8; chain_len];
    stream.read_exact(&mut chain_bytes).await?;
    let peer_chain_id = String::from_utf8(chain_bytes).map_err(|_| NetworkError::DecodeFailed {
        reason: "peer chain id is not valid UTF-8".to_string(),
    })?;
    if peer_chain_id != expected_chain_id {
        return Err(NetworkError::ChainIdMismatch {
            expected: expected_chain_id.to_string(),
            got: peer_chain_id,
        });
    }
    let mut peer_fingerprint = [0u8; 32];
    stream.read_exact(&mut peer_fingerprint).await?;
    if peer_fingerprint != expected_genesis_fingerprint.0 {
        return Err(NetworkError::DecodeFailed {
            reason: "peer genesis fingerprint does not match local canonical genesis".into(),
        });
    }
    Ok(())
}

fn build_step1(
    x25519_pk: [u8; 32],
    kem_ek: &[u8],
    validator_id: Bytes32,
) -> NetworkResult<Vec<u8>> {
    if kem_ek.len() != ML_KEM_1024_EK_LEN {
        return Err(NetworkError::InvalidKem);
    }
    let mut out = Vec::with_capacity(STEP1_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&x25519_pk);
    out.extend_from_slice(kem_ek);
    out.extend_from_slice(&validator_id.0);
    Ok(out)
}

fn build_step2(
    x25519_pk: [u8; 32],
    kem_ct: &[u8],
    validator_id: Bytes32,
) -> NetworkResult<Vec<u8>> {
    if kem_ct.len() != ML_KEM_1024_CT_LEN {
        return Err(NetworkError::InvalidKem);
    }
    let mut out = Vec::with_capacity(STEP2_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&x25519_pk);
    out.extend_from_slice(kem_ct);
    out.extend_from_slice(&validator_id.0);
    Ok(out)
}

fn parse_common_prefix(buf: &[u8]) -> NetworkResult<()> {
    if buf.len() < 6 {
        return Err(NetworkError::DecodeFailed {
            reason: "handshake message too short".to_string(),
        });
    }
    if &buf[..4] != MAGIC {
        return Err(NetworkError::InvalidMagic);
    }
    let version =
        u16::from_le_bytes(
            buf[4..6]
                .try_into()
                .map_err(|_| NetworkError::DecodeFailed {
                    reason: "invalid handshake version bytes".to_string(),
                })?,
        );
    if version != VERSION {
        return Err(NetworkError::UnsupportedVersion { got: version });
    }
    Ok(())
}

fn parse_step1(buf: &[u8]) -> NetworkResult<([u8; 32], [u8; ML_KEM_1024_EK_LEN], Bytes32)> {
    if buf.len() != STEP1_LEN {
        return Err(NetworkError::DecodeFailed {
            reason: "invalid step1 length".to_string(),
        });
    }
    parse_common_prefix(buf)?;
    let mut x25519_pk = [0u8; 32];
    x25519_pk.copy_from_slice(&buf[6..38]);
    let mut kem_ek = [0u8; ML_KEM_1024_EK_LEN];
    kem_ek.copy_from_slice(&buf[38..(38 + ML_KEM_1024_EK_LEN)]);
    let mut validator_id = [0u8; 32];
    validator_id.copy_from_slice(&buf[(38 + ML_KEM_1024_EK_LEN)..]);
    Ok((x25519_pk, kem_ek, Bytes32::from(validator_id)))
}

fn parse_step2(buf: &[u8]) -> NetworkResult<([u8; 32], [u8; ML_KEM_1024_CT_LEN], Bytes32)> {
    if buf.len() != STEP2_LEN {
        return Err(NetworkError::DecodeFailed {
            reason: "invalid step2 length".to_string(),
        });
    }
    parse_common_prefix(buf)?;
    let mut x25519_pk = [0u8; 32];
    x25519_pk.copy_from_slice(&buf[6..38]);
    let mut kem_ct = [0u8; ML_KEM_1024_CT_LEN];
    kem_ct.copy_from_slice(&buf[38..(38 + ML_KEM_1024_CT_LEN)]);
    let mut validator_id = [0u8; 32];
    validator_id.copy_from_slice(&buf[(38 + ML_KEM_1024_CT_LEN)..]);
    Ok((x25519_pk, kem_ct, Bytes32::from(validator_id)))
}

fn transcript_hash(step1: &[u8], step2: &[u8]) -> Blake3Hash {
    let mut input = Vec::with_capacity(step1.len() + step2.len());
    input.extend_from_slice(step1);
    input.extend_from_slice(step2);
    blake3::hash(&input)
}

fn derive_directional_keys(
    x25519_secret: &[u8; 32],
    kem_secret: &[u8; 32],
    transcript: &Blake3Hash,
    initiator: bool,
) -> ([u8; 32], [u8; 32]) {
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(x25519_secret);
    ikm.extend_from_slice(kem_secret);
    ikm.extend_from_slice(transcript.as_bytes());
    let i2r = blake3::derive_key("INDRA-transport-v1:i2r", &ikm);
    let r2i = blake3::derive_key("INDRA-transport-v1:r2i", &ikm);
    if initiator {
        (i2r, r2i)
    } else {
        (r2i, i2r)
    }
}

fn auth_plaintext(transcript: &Blake3Hash, validator_id: Bytes32) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(AUTH_CONTEXT.len() + 32 + 32);
    plaintext.extend_from_slice(AUTH_CONTEXT);
    plaintext.extend_from_slice(transcript.as_bytes());
    plaintext.extend_from_slice(&validator_id.0);
    plaintext
}

async fn write_auth_frame(
    stream: &mut TcpStream,
    key: &[u8; 32],
    signature: &PqSignature,
) -> NetworkResult<()> {
    let nonce = [0u8; 12];
    let ciphertext = encrypt_with_aad(key, &nonce, &signature.0, AUTH_AAD)?;
    let len_bytes = (signature.0.len() as u32).to_le_bytes();
    stream.write_all(&len_bytes).await?;
    stream.write_all(&nonce).await?;
    stream.write_all(&ciphertext).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_auth_frame(stream: &mut TcpStream, key: &[u8; 32]) -> NetworkResult<PqSignature> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len != PQ_SIG_BYTES {
        return Err(NetworkError::InvalidFrame {
            reason: "unexpected auth signature length".to_string(),
        });
    }

    let mut nonce = [0u8; 12];
    stream.read_exact(&mut nonce).await?;
    if nonce != [0u8; 12] {
        return Err(NetworkError::UnexpectedNonce {
            expected: 0,
            got: u64::from_le_bytes(nonce[4..].try_into().map_err(|_| {
                NetworkError::InvalidFrame {
                    reason: "invalid auth nonce bytes".to_string(),
                }
            })?),
        });
    }

    let mut ciphertext = vec![0u8; len + 16];
    stream.read_exact(&mut ciphertext).await?;
    let plaintext = decrypt_with_aad(key, &nonce, &ciphertext, AUTH_AAD)?;
    let sig_bytes: [u8; PQ_SIG_BYTES] =
        plaintext
            .try_into()
            .map_err(|_| NetworkError::InvalidFrame {
                reason: "invalid auth signature payload".to_string(),
            })?;
    Ok(PqSignature(sig_bytes))
}

async fn perform_handshake_inner(
    mut stream: TcpStream,
    config: &HandshakeConfig,
    initiator: bool,
) -> NetworkResult<HandshakeResult> {
    if initiator {
        // Establish chain identity before generating or exchanging any key
        // material and before looking up either validator identity.
        write_chain_preface(&mut stream, &config.chain_id, config.genesis_fingerprint).await?;
        read_and_verify_chain_preface(&mut stream, &config.chain_id, config.genesis_fingerprint)
            .await?;

        let x_secret = EphemeralSecret::random();
        let x_public = PublicKey::from(&x_secret).to_bytes();
        let (kem_dk, kem_ek) = MlKem1024::generate_keypair();
        let kem_ek_bytes = kem_ek.to_bytes();
        let step1 = build_step1(x_public, kem_ek_bytes.as_ref(), config.my_validator_id)?;
        stream.write_all(&step1).await?;
        stream.flush().await?;

        let mut step2 = vec![0u8; STEP2_LEN];
        stream.read_exact(&mut step2).await?;
        let (peer_x_pk_bytes, kem_ct_bytes, peer_validator_id) = parse_step2(&step2)?;
        let _ = lookup_validator_pk(config, peer_validator_id)?;

        let peer_x_pk = PublicKey::from(peer_x_pk_bytes);
        let x_secret_bytes = x_secret.diffie_hellman(&peer_x_pk).to_bytes();
        let transcript = transcript_hash(&step1, &step2);
        let kem_ct: ml_kem::ml_kem_1024::Ciphertext = kem_ct_bytes.into();
        let kem_secret = kem_dk.decapsulate(&kem_ct);
        let kem_secret_bytes: [u8; 32] = kem_secret.into();
        let (send_key, recv_key) =
            derive_directional_keys(&x_secret_bytes, &kem_secret_bytes, &transcript, true);

        let auth_sig = config
            .my_signing_key
            .sign(&auth_plaintext(&transcript, config.my_validator_id))
            .map_err(|err| NetworkError::Crypto {
                reason: err.to_string(),
            })?;
        write_auth_frame(&mut stream, &send_key, &auth_sig).await?;

        let peer_sig = read_auth_frame(&mut stream, &recv_key).await?;
        let peer_pk = lookup_validator_pk(config, peer_validator_id)?;
        verify_pq(
            &auth_plaintext(&transcript, peer_validator_id),
            &peer_sig,
            &peer_pk,
        )
        .map_err(|_| NetworkError::InvalidSignature)?;

        Ok(HandshakeResult {
            peer_validator_id,
            send_key,
            recv_key,
            stream,
            is_initiator: true,
        })
    } else {
        // Fail closed on cross-chain connections before key exchange or
        // validator authorization. Only acknowledge a matching chain.
        read_and_verify_chain_preface(&mut stream, &config.chain_id, config.genesis_fingerprint)
            .await?;
        write_chain_preface(&mut stream, &config.chain_id, config.genesis_fingerprint).await?;

        let mut step1 = vec![0u8; STEP1_LEN];
        stream.read_exact(&mut step1).await?;
        let (peer_x_pk_bytes, peer_kem_ek_bytes, peer_validator_id) = parse_step1(&step1)?;
        let _ = lookup_validator_pk(config, peer_validator_id)?;

        let x_secret = EphemeralSecret::random();
        let x_public = PublicKey::from(&x_secret).to_bytes();
        let peer_kem_ek = EncapsulationKey1024::new((&peer_kem_ek_bytes).into())
            .map_err(|_| NetworkError::InvalidKem)?;
        let (kem_ct, kem_secret) = peer_kem_ek.encapsulate();
        let step2 = build_step2(x_public, kem_ct.as_ref(), config.my_validator_id)?;
        stream.write_all(&step2).await?;
        stream.flush().await?;

        let peer_x_pk = PublicKey::from(peer_x_pk_bytes);
        let x_secret_bytes = x_secret.diffie_hellman(&peer_x_pk).to_bytes();
        let transcript = transcript_hash(&step1, &step2);
        let kem_secret_bytes: [u8; 32] = kem_secret.into();
        let (send_key, recv_key) =
            derive_directional_keys(&x_secret_bytes, &kem_secret_bytes, &transcript, false);

        let auth_sig = config
            .my_signing_key
            .sign(&auth_plaintext(&transcript, config.my_validator_id))
            .map_err(|err| NetworkError::Crypto {
                reason: err.to_string(),
            })?;
        write_auth_frame(&mut stream, &send_key, &auth_sig).await?;

        let peer_sig = read_auth_frame(&mut stream, &recv_key).await?;
        let peer_pk = lookup_validator_pk(config, peer_validator_id)?;
        verify_pq(
            &auth_plaintext(&transcript, peer_validator_id),
            &peer_sig,
            &peer_pk,
        )
        .map_err(|_| NetworkError::InvalidSignature)?;

        Ok(HandshakeResult {
            peer_validator_id,
            send_key,
            recv_key,
            stream,
            is_initiator: false,
        })
    }
}

/// Run the initiator side of the INDRA authenticated transport handshake.
pub async fn perform_handshake_initiator(
    stream: TcpStream,
    config: &HandshakeConfig,
) -> NetworkResult<HandshakeResult> {
    timeout(
        config.timeout,
        perform_handshake_inner(stream, config, true),
    )
    .await
    .map_err(|_| NetworkError::HandshakeTimeout)?
}

/// Run the responder side of the INDRA authenticated transport handshake.
pub async fn perform_handshake_responder(
    stream: TcpStream,
    config: &HandshakeConfig,
) -> NetworkResult<HandshakeResult> {
    timeout(
        config.timeout,
        perform_handshake_inner(stream, config, false),
    )
    .await
    .map_err(|_| NetworkError::HandshakeTimeout)?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_validator(seed: u8, id_seed: u8) -> (Bytes32, PqKeypair, PqPublicKey) {
        let signing = PqKeypair::from_seed(&[seed; 32]).expect("pq keypair");
        let public = signing.public_key();
        (Bytes32::from([id_seed; 32]), signing, public)
    }

    fn make_config(
        validator_id: Bytes32,
        signing_key: PqKeypair,
        known_validators: Vec<(Bytes32, PqPublicKey)>,
        timeout: Duration,
    ) -> HandshakeConfig {
        HandshakeConfig {
            my_validator_id: validator_id,
            my_signing_key: signing_key,
            chain_id: "indra-testnet-1".to_string(),
            genesis_fingerprint: Bytes32::from([0x51; 32]),
            known_validators,
            relay_validator_keys: Vec::new(),
            timeout,
        }
    }

    #[tokio::test]
    async fn handshake_success_initiator_responder() {
        let (initiator_id, initiator_sk, initiator_pk) = make_validator(0x11, 0xA1);
        let (responder_id, responder_sk, responder_pk) = make_validator(0x22, 0xB2);
        let initiator_cfg = make_config(
            initiator_id,
            initiator_sk,
            vec![
                (initiator_id, initiator_pk.clone()),
                (responder_id, responder_pk.clone()),
            ],
            Duration::from_secs(2),
        );
        let responder_cfg = make_config(
            responder_id,
            responder_sk,
            vec![(initiator_id, initiator_pk), (responder_id, responder_pk)],
            Duration::from_secs(2),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let responder = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            perform_handshake_responder(stream, &responder_cfg)
                .await
                .expect("responder handshake")
        });

        let initiator_stream = TcpStream::connect(addr).await.expect("connect");
        let initiator = perform_handshake_initiator(initiator_stream, &initiator_cfg)
            .await
            .expect("initiator handshake");
        let responder = responder.await.expect("join");

        assert_eq!(initiator.peer_validator_id, responder_id);
        assert_eq!(responder.peer_validator_id, initiator_id);
        assert_eq!(initiator.send_key, responder.recv_key);
        assert_eq!(initiator.recv_key, responder.send_key);
    }

    #[tokio::test]
    async fn handshake_rejects_chain_mismatch_before_validator_or_key_exchange() {
        let (initiator_id, initiator_sk, _) = make_validator(0x21, 0xA2);
        let (responder_id, responder_sk, _) = make_validator(0x22, 0xB2);
        let mut initiator_cfg = make_config(
            initiator_id,
            initiator_sk,
            Vec::new(),
            Duration::from_secs(2),
        );
        initiator_cfg.chain_id = "indra-other-chain".to_string();
        let responder_cfg = make_config(
            responder_id,
            responder_sk,
            Vec::new(),
            Duration::from_secs(2),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let responder = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            perform_handshake_responder(stream, &responder_cfg).await
        });
        let initiator = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.expect("connect");
            perform_handshake_initiator(stream, &initiator_cfg).await
        });

        let responder_result = responder.await.expect("join");
        let _ = initiator.await.expect("join");
        assert!(matches!(
            responder_result,
            Err(NetworkError::ChainIdMismatch { expected, got })
                if expected == "indra-testnet-1" && got == "indra-other-chain"
        ));
    }

    #[tokio::test]
    async fn handshake_rejects_genesis_fingerprint_mismatch_before_key_exchange() {
        let (initiator_id, initiator_sk, _) = make_validator(0x23, 0xA3);
        let (responder_id, responder_sk, _) = make_validator(0x24, 0xB4);
        let mut initiator_cfg = make_config(
            initiator_id,
            initiator_sk,
            Vec::new(),
            Duration::from_secs(2),
        );
        initiator_cfg.genesis_fingerprint = Bytes32::from([0x99; 32]);
        let responder_cfg = make_config(
            responder_id,
            responder_sk,
            Vec::new(),
            Duration::from_secs(2),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            perform_handshake_responder(stream, &responder_cfg).await
        });
        let initiator = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            perform_handshake_initiator(stream, &initiator_cfg).await
        });
        let responder_result = responder.await.unwrap();
        let _ = initiator.await.unwrap();
        assert!(matches!(
            responder_result,
            Err(NetworkError::DecodeFailed { reason }) if reason.contains("genesis fingerprint")
        ));
    }

    #[tokio::test]
    async fn handshake_rejects_unknown_validator() {
        let (initiator_id, initiator_sk, initiator_pk) = make_validator(0x31, 0xC1);
        let (responder_id, responder_sk, responder_pk) = make_validator(0x32, 0xD2);
        let initiator_cfg = make_config(
            initiator_id,
            initiator_sk,
            vec![
                (initiator_id, initiator_pk.clone()),
                (responder_id, responder_pk.clone()),
            ],
            Duration::from_secs(2),
        );
        let responder_cfg = make_config(
            responder_id,
            responder_sk,
            vec![(responder_id, responder_pk)],
            Duration::from_secs(2),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let responder = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            perform_handshake_responder(stream, &responder_cfg).await
        });

        let initiator = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.expect("connect");
            let _ = perform_handshake_initiator(stream, &initiator_cfg).await;
        });

        let responder_result = responder.await.expect("join");
        initiator.await.expect("join");
        assert!(matches!(
            responder_result,
            Err(NetworkError::UnknownValidator { validator_id }) if validator_id == initiator_id
        ));
    }

    #[tokio::test]
    async fn handshake_rejects_wrong_magic() {
        let (responder_id, responder_sk, responder_pk) = make_validator(0x41, 0xE1);
        let responder_cfg = make_config(
            responder_id,
            responder_sk,
            vec![(responder_id, responder_pk)],
            Duration::from_secs(2),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let responder = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            perform_handshake_responder(stream, &responder_cfg).await
        });

        let mut client = TcpStream::connect(addr).await.expect("connect");
        let mut bogus = vec![0u8; CHAIN_PREFACE_HEADER_LEN];
        bogus[..4].copy_from_slice(b"NOPE");
        client.write_all(&bogus).await.expect("write");

        let result = responder.await.expect("join");
        assert!(matches!(result, Err(NetworkError::InvalidMagic)));
    }

    #[tokio::test]
    async fn handshake_timeout() {
        let (responder_id, responder_sk, responder_pk) = make_validator(0x51, 0xF1);
        let responder_cfg = make_config(
            responder_id,
            responder_sk,
            vec![(responder_id, responder_pk)],
            Duration::from_millis(100),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let responder = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            perform_handshake_responder(stream, &responder_cfg).await
        });

        let _idle = TcpStream::connect(addr).await.expect("connect");
        let result = responder.await.expect("join");
        assert!(matches!(result, Err(NetworkError::HandshakeTimeout)));
    }

    #[tokio::test]
    async fn handshake_rejects_invalid_signature() {
        let (initiator_id, initiator_sk, initiator_pk) = make_validator(0x61, 0xA1);
        let (responder_id, responder_sk, responder_pk) = make_validator(0x62, 0xB2);
        let (_, wrong_sk, _) = make_validator(0x63, 0xC3);

        let initiator_cfg = make_config(
            initiator_id,
            initiator_sk,
            vec![
                (initiator_id, initiator_pk.clone()),
                (responder_id, responder_pk.clone()),
            ],
            Duration::from_secs(2),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            read_and_verify_chain_preface(
                &mut stream,
                "indra-testnet-1",
                Bytes32::from([0x51; 32]),
            )
            .await
            .expect("read chain preface");
            write_chain_preface(&mut stream, "indra-testnet-1", Bytes32::from([0x51; 32]))
                .await
                .expect("write chain preface");
            let mut step1 = vec![0u8; STEP1_LEN];
            stream.read_exact(&mut step1).await.expect("read step1");
            let (peer_x_pk_bytes, peer_kem_ek_bytes, peer_validator_id) =
                parse_step1(&step1).expect("parse step1");
            assert_eq!(peer_validator_id, initiator_id);

            let x_secret = EphemeralSecret::random();
            let x_public = PublicKey::from(&x_secret).to_bytes();
            let peer_kem_ek =
                EncapsulationKey1024::new((&peer_kem_ek_bytes).into()).expect("kem ek");
            let (kem_ct, kem_secret) = peer_kem_ek.encapsulate();
            let step2 = build_step2(x_public, kem_ct.as_ref(), responder_id).expect("build step2");
            stream.write_all(&step2).await.expect("write step2");
            stream.flush().await.expect("flush");

            let peer_x_pk = PublicKey::from(peer_x_pk_bytes);
            let x_secret_bytes = x_secret.diffie_hellman(&peer_x_pk).to_bytes();
            let transcript = transcript_hash(&step1, &step2);
            let kem_secret_bytes: [u8; 32] = kem_secret.into();
            let (send_key, recv_key) =
                derive_directional_keys(&x_secret_bytes, &kem_secret_bytes, &transcript, false);

            let bad_sig = wrong_sk
                .sign(&auth_plaintext(&transcript, responder_id))
                .expect("sign");
            write_auth_frame(&mut stream, &send_key, &bad_sig)
                .await
                .expect("write auth");
            let _ = read_auth_frame(&mut stream, &recv_key).await;
            let _ = responder_sk;
        });

        let initiator_stream = TcpStream::connect(addr).await.expect("connect");
        let result = perform_handshake_initiator(initiator_stream, &initiator_cfg).await;
        responder.await.expect("join");
        assert!(matches!(result, Err(NetworkError::InvalidSignature)));
    }
}
