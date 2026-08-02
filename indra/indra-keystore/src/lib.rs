//! INDRA encrypted validator keystore support.
//!
//! The keystore format keeps public validator metadata in cleartext and
//! encrypts only the secret signing material. It is local operator storage:
//! it does not affect consensus state, transaction formats, or state roots.

use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, Key, KeyInit, Nonce,
};
use indra_crypto::{
    derive_all_seeds, generate_mnemonic,
    hybrid::{ClassicalKeypair, ColdHybridKeypair, HybridKeypair, PqKeypair},
    mnemonic_to_seed, sha256, PaymentAddress, PaymentKeypairV1, PaymentPubKeyV1, VrfKeypair,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// Required filesystem mode for key/password files on Unix: owner read/write only.
pub const KEY_FILE_MODE: u32 = 0o600;
/// INDRA encrypted keystore top-level format marker.
pub const KEYSTORE_FORMAT: &str = "indra-keystore";
/// Current encrypted keystore format version.
pub const KEYSTORE_VERSION: u8 = 1;
/// Dedicated cold-keystore top-level format marker.
pub const COLD_KEYSTORE_FORMAT: &str = "indra-cold-keystore";
/// Current cold-keystore format version.
pub const COLD_KEYSTORE_VERSION: u8 = 1;
/// Argon2id memory cost in KiB.
pub const ARGON2_MEMORY_KIB: u32 = 65_536;
/// Argon2id iteration count.
pub const ARGON2_ITERATIONS: u32 = 3;
/// Argon2id parallelism.
pub const ARGON2_PARALLELISM: u32 = 1;

const ARGON2_SALT_BYTES: usize = 32;
const CHACHA_NONCE_BYTES: usize = 12;

/// Keystore errors.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(String),
    /// Parse/format error.
    #[error("keystore parse error: {0}")]
    Parse(String),
    /// Invalid hex.
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    /// Cryptographic failure.
    #[error("keystore crypto error: {0}")]
    Crypto(String),
    /// A password is required but no source was provided.
    #[error("encrypted keys require a password source; provide --keys-password-file or use an interactive prompt")]
    PasswordRequired,
    /// Password-file permissions are unsafe.
    #[error("password file {path} has permissive permissions ({mode:o}); expected 600")]
    PasswordFilePermissions {
        /// File path.
        path: String,
        /// Observed mode.
        mode: u32,
    },
    /// Unsupported encrypted keystore version.
    #[error("unsupported keystore version {0}")]
    UnsupportedVersion(u64),
}

/// Result alias.
pub type KeystoreResult<T> = Result<T, KeystoreError>;

/// All public keys for a validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorKeys {
    /// 32-byte validator identity (SHA-256 of hybrid classical public key).
    pub validator_id: [u8; 32],
    /// Ed25519 public key (32 bytes).
    pub hybrid_classical_pk: [u8; 32],
    /// ML-DSA-87 public key bytes.
    pub hybrid_pq_pk: Vec<u8>,
    /// VRF public key (32 bytes).
    pub vrf_pk: [u8; 32],
    /// Optional payment key-exchange public key for payment-blinding delivery.
    pub payment_pubkey: Option<PaymentPubKeyV1>,
}

/// A complete keys file including private seeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysFile {
    /// Validator display name chosen at key generation.
    pub name: String,
    /// All public keys.
    pub public: ValidatorKeys,
    /// Hybrid keypair seed (keep secret).
    pub hybrid_seed: [u8; 32],
    /// VRF keypair seed (keep secret).
    pub vrf_seed: [u8; 32],
    /// ML-DSA-87 secret key bytes (keep secret).
    pub pq_sk: Vec<u8>,
    /// Optional payment key-exchange private keypair (keep secret).
    pub payment_keypair: Option<PaymentKeypairV1>,
    /// Ordered retained historical payment keys, oldest first.
    pub payment_key_history: Vec<PaymentKeypairV1>,
}

/// Dedicated validator cold-key material. It contains no hot identity fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColdKeysFile {
    /// Ed25519 seed.
    pub classical_seed: [u8; 32],
    /// ML-DSA-87 seed.
    pub pq_seed: [u8; 32],
    /// Ed25519 public key.
    pub classical_pk: [u8; 32],
    /// ML-DSA-87 public key.
    pub pq_pk: Vec<u8>,
}

impl ColdKeysFile {
    /// Generate through the role-specific independent-entropy primitive.
    pub fn generate() -> KeystoreResult<Self> {
        let (keypair, classical_seed, pq_seed) = ColdHybridKeypair::generate_exportable()
            .map_err(|e| KeystoreError::Crypto(e.to_string()))?;
        let public = keypair.public_key();
        let public = public.as_complete_hybrid();
        Ok(Self {
            classical_seed,
            pq_seed,
            classical_pk: public.classical.0,
            pq_pk: public.pq.0.to_vec(),
        })
    }

    /// Reconstruct and verify the complete cold hybrid keypair.
    pub fn reconstruct(&self) -> KeystoreResult<ColdHybridKeypair> {
        let keypair = ColdHybridKeypair::from_independent_seeds(self.classical_seed, self.pq_seed)
            .map_err(|e| KeystoreError::Crypto(e.to_string()))?;
        let public = keypair.public_key();
        let public = public.as_complete_hybrid();
        if public.classical.0 != self.classical_pk || public.pq.0.as_slice() != self.pq_pk {
            return Err(KeystoreError::Crypto(
                "cold keystore public metadata does not match private seeds".into(),
            ));
        }
        Ok(keypair)
    }
}

impl KeysFile {
    /// Build this identity's canonical, self-contained payment address.
    pub fn payment_address(&self, chain_id: &[u8]) -> KeystoreResult<PaymentAddress> {
        let classical = ClassicalKeypair::from_seed(&self.hybrid_seed);
        let pq = PqKeypair::from_bytes(&self.public.hybrid_pq_pk, &self.pq_sk)
            .map_err(|error| KeystoreError::Crypto(error.to_string()))?;
        let hybrid = HybridKeypair::new(classical, pq);
        let payment = self.payment_keypair.as_ref().ok_or_else(|| {
            KeystoreError::Crypto("canonical keystore is missing its payment key".to_string())
        })?;
        PaymentAddress::new(chain_id, &hybrid, payment.public_key())
            .map_err(|error| KeystoreError::Crypto(error.to_string()))
    }

    /// Return the current payment key followed by retained historical keys.
    pub fn payment_keypairs(&self) -> impl Iterator<Item = &PaymentKeypairV1> {
        self.payment_keypair
            .iter()
            .chain(self.payment_key_history.iter())
    }

    /// Render the legacy plaintext JSON format.
    pub fn to_json(&self) -> String {
        plaintext_json(self)
    }

    /// Parse either the legacy plaintext format or an encrypted format if a
    /// password source is supplied.
    pub fn from_json_with_password(json: &str, source: PasswordSource<'_>) -> KeystoreResult<Self> {
        match detect_format(json)? {
            KeyFileFormat::Plaintext => plaintext_from_json(json),
            KeyFileFormat::Encrypted => {
                let password = source.resolve(false)?;
                decrypt_encrypted_keys(json, password.as_bytes())
            }
        }
    }

    /// Parse the legacy plaintext format.
    pub fn from_json(json: &str) -> KeystoreResult<Self> {
        plaintext_from_json(json)
    }

    /// Load either plaintext or encrypted keys.
    pub fn load_with_password(path: &str, source: PasswordSource<'_>) -> KeystoreResult<Self> {
        warn_if_key_file_permissive(path);
        let json = std::fs::read_to_string(path)
            .map_err(|e| KeystoreError::Io(format!("{}: {}", path, e)))?;
        if matches!(detect_format(&json)?, KeyFileFormat::Plaintext) {
            eprintln!(
                "WARNING: plaintext keys.json loaded. This is supported for compatibility, \
                 but mainnet validators should run: indra-keygen encrypt --keys {}",
                path
            );
        }
        Self::from_json_with_password(&json, source)
    }

    /// Load only legacy plaintext keys.
    pub fn load(path: &str) -> KeystoreResult<Self> {
        Self::load_with_password(path, PasswordSource::None)
    }
}

/// Password source for encrypted keystores.
#[derive(Debug, Clone)]
pub enum PasswordSource<'a> {
    /// Prompt interactively.
    Prompt,
    /// Read password from a file.
    File {
        /// Path to password file.
        path: &'a Path,
        /// Reject permissive permissions instead of warning.
        reject_permissive: bool,
    },
    /// Read password from stdin.
    Stdin,
    /// Read password from an environment variable. Discouraged except test/dev.
    Env(&'a str),
    /// No password source.
    None,
}

impl<'a> PasswordSource<'a> {
    /// Resolve the source into a zeroizing password string.
    pub fn resolve(&self, confirm: bool) -> KeystoreResult<Zeroizing<String>> {
        match self {
            Self::Prompt => read_password_prompt(confirm),
            Self::File {
                path,
                reject_permissive,
            } => read_password_file(path, *reject_permissive),
            Self::Stdin => {
                let mut input = String::new();
                std::io::stdin()
                    .read_to_string(&mut input)
                    .map_err(|e| KeystoreError::Io(e.to_string()))?;
                Ok(Zeroizing::new(
                    input.trim_end_matches(['\r', '\n']).to_string(),
                ))
            }
            Self::Env(name) => {
                eprintln!(
                    "WARNING: reading keystore password from environment variable {name}. \
                     Prefer a restricted-permission password file for validators."
                );
                std::env::var(name)
                    .map(Zeroizing::new)
                    .map_err(|_| KeystoreError::PasswordRequired)
            }
            Self::None => Err(KeystoreError::PasswordRequired),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyFileFormat {
    Plaintext,
    Encrypted,
}

fn detect_format(json: &str) -> KeystoreResult<KeyFileFormat> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| KeystoreError::Parse(e.to_string()))?;
    if value.get("format").and_then(|v| v.as_str()) == Some(KEYSTORE_FORMAT) {
        let version = value.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
        if version != KEYSTORE_VERSION as u64 {
            return Err(KeystoreError::UnsupportedVersion(version));
        }
        return Ok(KeyFileFormat::Encrypted);
    }
    if value.get("private").is_some() {
        return Ok(KeyFileFormat::Plaintext);
    }
    Err(KeystoreError::Parse(
        "unrecognized key file format".to_string(),
    ))
}

fn build_keys_file(
    name: String,
    hybrid_seed: [u8; 32],
    vrf_seed: [u8; 32],
    payment_x25519_seed: [u8; 32],
    payment_ml_kem_seed: [u8; 64],
) -> KeystoreResult<KeysFile> {
    let classical = ClassicalKeypair::from_seed(&hybrid_seed);
    let pq =
        PqKeypair::from_seed(&hybrid_seed).map_err(|e| KeystoreError::Crypto(e.to_string()))?;
    let pq_sk_bytes = pq.secret_key_bytes();
    let hybrid = HybridKeypair::new(classical, pq);
    let pk = hybrid.public_key();
    let vrf = VrfKeypair::from_seed(&vrf_seed);
    let payment_keypair = PaymentKeypairV1 {
        version: indra_crypto::PAYMENT_VERSION_V1,
        x25519_sk: payment_x25519_seed,
        ml_kem_1024_seed: payment_ml_kem_seed,
    };
    let payment_pubkey = payment_keypair.public_key();
    Ok(KeysFile {
        name,
        public: ValidatorKeys {
            validator_id: sha256(&pk.classical.0),
            hybrid_classical_pk: pk.classical.0,
            hybrid_pq_pk: pk.pq.0.to_vec(),
            vrf_pk: vrf.public_key(),
            payment_pubkey: Some(payment_pubkey),
        },
        hybrid_seed,
        vrf_seed,
        pq_sk: pq_sk_bytes,
        payment_keypair: Some(payment_keypair),
        payment_key_history: Vec::new(),
    })
}

/// Generate a complete canonical keystore from one 32-byte master seed.
pub fn generate_from_master_seed(name: String, master_seed: [u8; 32]) -> KeystoreResult<KeysFile> {
    let derived = derive_all_seeds(&master_seed);
    build_keys_file(
        name,
        derived.hybrid_seed,
        derived.vrf_seed,
        derived.payment_x25519_seed,
        derived.payment_ml_kem_seed,
    )
}

/// Generate a complete validator keypair set from a new mnemonic.
pub fn generate_from_new_mnemonic(name: String) -> KeystoreResult<(String, KeysFile)> {
    let phrase = generate_mnemonic();
    let master_seed =
        mnemonic_to_seed(&phrase).map_err(|e| KeystoreError::Crypto(e.to_string()))?;
    Ok((phrase, generate_from_master_seed(name, master_seed)?))
}

/// Recover a validator keypair set from an existing mnemonic.
pub fn recover_from_mnemonic(phrase: &str, name: String) -> KeystoreResult<KeysFile> {
    let master_seed = mnemonic_to_seed(phrase).map_err(|e| KeystoreError::Crypto(e.to_string()))?;
    generate_from_master_seed(name, master_seed)
}

/// Generate keypairs with random-looking seeds derived from a passphrase.
///
/// This remains testnet-only convenience. It is not a production KDF path.
pub fn generate_from_passphrase(passphrase: &str, name: String) -> KeystoreResult<KeysFile> {
    eprintln!(
        "WARNING: passphrase-derived key generation uses SHA-256, NOT a password KDF \
         (bcrypt/argon2/scrypt). This is NOT suitable for mainnet or production use. \
         Use secure mnemonic generation for production keys."
    );
    let master_seed =
        indra_crypto::hash::domain_hash(b"INDRA-TEST-ONLY-MASTER-SEED-v1", passphrase.as_bytes());
    generate_from_master_seed(name, master_seed)
}

/// Encrypt keys to the v1 encrypted keystore format.
pub fn encrypt_plaintext_keys(keys: &KeysFile, password: &[u8]) -> KeystoreResult<String> {
    let mut salt = [0u8; ARGON2_SALT_BYTES];
    let mut nonce = [0u8; CHACHA_NONCE_BYTES];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);
    encrypt_plaintext_keys_with_params(keys, password, salt, nonce)
}

fn encrypt_plaintext_keys_with_params(
    keys: &KeysFile,
    password: &[u8],
    salt: [u8; ARGON2_SALT_BYTES],
    nonce: [u8; CHACHA_NONCE_BYTES],
) -> KeystoreResult<String> {
    let mut container = EncryptedContainer::from_public(keys, salt, nonce, String::new());
    let aad = container.associated_data()?;
    let plaintext = serde_json::to_vec(&PrivatePayload::from(keys))
        .map_err(|e| KeystoreError::Parse(e.to_string()))?;
    let ciphertext = encrypt_payload(password, &salt, &nonce, &aad, &plaintext)?;
    container.crypto.cipher.ciphertext = hex::encode(ciphertext);
    serde_json::to_string_pretty(&container).map_err(|e| KeystoreError::Parse(e.to_string()))
}

/// Decrypt an encrypted keystore JSON string.
pub fn decrypt_encrypted_keys(json: &str, password: &[u8]) -> KeystoreResult<KeysFile> {
    let container: EncryptedContainer =
        serde_json::from_str(json).map_err(|e| KeystoreError::Parse(e.to_string()))?;
    if container.format != KEYSTORE_FORMAT {
        return Err(KeystoreError::Parse("not an INDRA keystore".to_string()));
    }
    if container.version != KEYSTORE_VERSION {
        return Err(KeystoreError::UnsupportedVersion(container.version as u64));
    }
    container.validate_crypto_params()?;
    let public = container.public.to_validator_keys()?;
    validate_public_container_identity(&container.validator_id, &public)?;
    let aad = container.associated_data()?;
    let salt = decode_hex_fixed::<ARGON2_SALT_BYTES>(&container.crypto.kdf.params.salt, "salt")?;
    let nonce =
        decode_hex_fixed::<CHACHA_NONCE_BYTES>(&container.crypto.cipher.params.nonce, "nonce")?;
    let ciphertext = decode_hex(&container.crypto.cipher.ciphertext, "ciphertext")?;
    let plaintext = decrypt_payload(password, &salt, &nonce, &aad, &ciphertext)?;
    let private: PrivatePayload =
        serde_json::from_slice(&plaintext).map_err(|e| KeystoreError::Parse(e.to_string()))?;
    let keys = private.to_keys_file(container.name, public)?;
    verify_public_metadata(&keys)?;
    Ok(keys)
}

/// Return public metadata from either plaintext or encrypted keys without a
/// password.
pub fn inspect_public_metadata(json: &str) -> KeystoreResult<(String, ValidatorKeys)> {
    match detect_format(json)? {
        KeyFileFormat::Plaintext => {
            let keys = plaintext_from_json(json)?;
            Ok((keys.name, keys.public))
        }
        KeyFileFormat::Encrypted => {
            let container: EncryptedContainer =
                serde_json::from_str(json).map_err(|e| KeystoreError::Parse(e.to_string()))?;
            if container.format != KEYSTORE_FORMAT {
                return Err(KeystoreError::Parse("not an INDRA keystore".to_string()));
            }
            if container.version != KEYSTORE_VERSION {
                return Err(KeystoreError::UnsupportedVersion(container.version as u64));
            }
            container.validate_crypto_params()?;
            let public = container.public.to_validator_keys()?;
            validate_public_container_identity(&container.validator_id, &public)?;
            Ok((container.name, public))
        }
    }
}

/// Load keys from disk with a password source.
pub fn load_keys(path: &str, source: PasswordSource<'_>) -> KeystoreResult<KeysFile> {
    KeysFile::load_with_password(path, source)
}

/// Securely write a key file with owner-only permissions.
pub fn write_keys_secure(path: &str, contents: &str) -> KeystoreResult<()> {
    write_secret_file_secure(path, contents.as_bytes())
}

/// Encrypt a dedicated cold-key file with the standard keystore KDF/cipher.
pub fn encrypt_cold_keys(keys: &ColdKeysFile, password: &[u8]) -> KeystoreResult<String> {
    let mut salt = [0u8; ARGON2_SALT_BYTES];
    let mut nonce = [0u8; CHACHA_NONCE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let public = ColdPublicJson {
        classical_pk: hex::encode(keys.classical_pk),
        pq_pk: hex::encode(&keys.pq_pk),
    };
    let mut container = ColdEncryptedContainer::new(public, salt, nonce);
    let aad = container.associated_data()?;
    let private = ColdPrivateJson {
        classical_seed: hex::encode(keys.classical_seed),
        pq_seed: hex::encode(keys.pq_seed),
    };
    let plaintext =
        serde_json::to_vec(&private).map_err(|e| KeystoreError::Parse(e.to_string()))?;
    container.crypto.cipher.ciphertext =
        hex::encode(encrypt_payload(password, &salt, &nonce, &aad, &plaintext)?);
    serde_json::to_string_pretty(&container).map_err(|e| KeystoreError::Parse(e.to_string()))
}

/// Decrypt and verify a dedicated cold-key file.
pub fn decrypt_cold_keys(json: &str, password: &[u8]) -> KeystoreResult<ColdKeysFile> {
    let container: ColdEncryptedContainer =
        serde_json::from_str(json).map_err(|e| KeystoreError::Parse(e.to_string()))?;
    container.validate()?;
    let aad = container.associated_data()?;
    let salt = decode_hex_fixed::<ARGON2_SALT_BYTES>(&container.crypto.kdf.params.salt, "salt")?;
    let nonce =
        decode_hex_fixed::<CHACHA_NONCE_BYTES>(&container.crypto.cipher.params.nonce, "nonce")?;
    let ciphertext = decode_hex(&container.crypto.cipher.ciphertext, "ciphertext")?;
    let plaintext = decrypt_payload(password, &salt, &nonce, &aad, &ciphertext)?;
    let private: ColdPrivateJson =
        serde_json::from_slice(&plaintext).map_err(|e| KeystoreError::Parse(e.to_string()))?;
    let keys = ColdKeysFile {
        classical_seed: decode_hex_fixed::<32>(&private.classical_seed, "classical_seed")?,
        pq_seed: decode_hex_fixed::<32>(&private.pq_seed, "pq_seed")?,
        classical_pk: decode_hex_fixed::<32>(&container.public.classical_pk, "classical_pk")?,
        pq_pk: decode_hex(&container.public.pq_pk, "pq_pk")?,
    };
    keys.reconstruct()?;
    Ok(keys)
}

/// Load a dedicated encrypted cold-key file.
pub fn load_cold_keys(path: &str, source: PasswordSource<'_>) -> KeystoreResult<ColdKeysFile> {
    warn_if_key_file_permissive(path);
    let json =
        std::fs::read_to_string(path).map_err(|e| KeystoreError::Io(format!("{}: {}", path, e)))?;
    if serde_json::from_str::<serde_json::Value>(&json)
        .ok()
        .and_then(|value| value.get("private").cloned())
        .is_some()
    {
        let container: ColdPlaintextContainer =
            serde_json::from_str(&json).map_err(|e| KeystoreError::Parse(e.to_string()))?;
        if container.format != COLD_KEYSTORE_FORMAT || container.version != COLD_KEYSTORE_VERSION {
            return Err(KeystoreError::Parse("invalid cold keystore format".into()));
        }
        let keys = ColdKeysFile {
            classical_seed: decode_hex_fixed::<32>(
                &container.private.classical_seed,
                "classical_seed",
            )?,
            pq_seed: decode_hex_fixed::<32>(&container.private.pq_seed, "pq_seed")?,
            classical_pk: decode_hex_fixed::<32>(&container.public.classical_pk, "classical_pk")?,
            pq_pk: decode_hex(&container.public.pq_pk, "pq_pk")?,
        };
        keys.reconstruct()?;
        return Ok(keys);
    }
    let password = source.resolve(false)?;
    decrypt_cold_keys(&json, password.as_bytes())
}

/// Generate and securely write a new dedicated cold-key file.
pub fn generate_cold_keys_file(
    path: &Path,
    password: Option<&[u8]>,
    force: bool,
) -> KeystoreResult<ColdKeysFile> {
    if path.exists() && !force {
        return Err(KeystoreError::Io(format!(
            "{} already exists; pass --force to overwrite",
            path.display()
        )));
    }
    let keys = ColdKeysFile::generate()?;
    let contents = match password {
        Some(password) => encrypt_cold_keys(&keys, password)?,
        None => serde_json::to_string_pretty(&ColdPlaintextContainer::from(&keys))
            .map_err(|e| KeystoreError::Parse(e.to_string()))?,
    };
    write_keys_secure(path_to_str(path)?, &contents)?;
    Ok(keys)
}

/// Write encrypted contents to a temporary file, verify decryption, back up the
/// original plaintext, and atomically replace it.
pub fn encrypt_plaintext_keys_replace(
    path: &Path,
    keys: &KeysFile,
    password: &[u8],
) -> KeystoreResult<PathBuf> {
    let encrypted = encrypt_plaintext_keys(keys, password)?;
    let verified = decrypt_encrypted_keys(&encrypted, password)?;
    if &verified != keys {
        return Err(KeystoreError::Crypto(
            "encrypted keystore round-trip verification failed".to_string(),
        ));
    }
    let tmp = path.with_extension("json.encrypted.tmp");
    write_keys_secure(path_to_str(&tmp)?, &encrypted)?;
    let backup = timestamped_backup_path(path);
    std::fs::rename(path, &backup).map_err(|e| KeystoreError::Io(e.to_string()))?;
    set_secret_file_permissions(&backup)?;
    std::fs::rename(&tmp, path).map_err(|e| KeystoreError::Io(e.to_string()))?;
    set_secret_file_permissions(path)?;
    Ok(backup)
}

fn path_to_str(path: &Path) -> KeystoreResult<&str> {
    path.to_str()
        .ok_or_else(|| KeystoreError::Io(format!("non-UTF-8 path: {}", path.display())))
}

fn timestamped_backup_path(path: &Path) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    path.with_extension(format!("plaintext-backup-{ts}.json"))
}

#[derive(Debug, Serialize, Deserialize)]
struct PlaintextContainer {
    #[serde(default)]
    name: String,
    validator_id: String,
    public: PublicJson,
    private: PrivateJson,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PublicJson {
    hybrid_classical_pk: String,
    hybrid_pq_pk: String,
    vrf_pk: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payment_pubkey: Option<String>,
}

impl PublicJson {
    fn from(keys: &KeysFile) -> Self {
        Self {
            hybrid_classical_pk: hex::encode(keys.public.hybrid_classical_pk),
            hybrid_pq_pk: hex::encode(&keys.public.hybrid_pq_pk),
            vrf_pk: hex::encode(keys.public.vrf_pk),
            payment_pubkey: keys
                .public
                .payment_pubkey
                .as_ref()
                .map(|payment_pubkey| hex::encode(payment_pubkey.encode())),
        }
    }

    fn to_validator_keys(&self) -> KeystoreResult<ValidatorKeys> {
        let hybrid_classical_pk =
            decode_hex_fixed::<32>(&self.hybrid_classical_pk, "public.hybrid_classical_pk")?;
        let payment_pubkey = self
            .payment_pubkey
            .as_deref()
            .map(|value| {
                PaymentPubKeyV1::decode(&decode_hex(value, "public.payment_pubkey")?)
                    .map_err(|e| KeystoreError::Crypto(e.to_string()))
            })
            .transpose()?;
        Ok(ValidatorKeys {
            validator_id: sha256(&hybrid_classical_pk),
            hybrid_classical_pk,
            hybrid_pq_pk: decode_hex(&self.hybrid_pq_pk, "public.hybrid_pq_pk")?,
            vrf_pk: decode_hex_fixed::<32>(&self.vrf_pk, "public.vrf_pk")?,
            payment_pubkey,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PrivateJson {
    hybrid_seed: String,
    vrf_seed: String,
    pq_sk: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payment_keypair: Option<String>,
    #[serde(default)]
    payment_key_history: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    warning: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PrivatePayload {
    private: PrivateJson,
}

impl PrivatePayload {
    fn from(keys: &KeysFile) -> Self {
        Self {
            private: PrivateJson {
                hybrid_seed: hex::encode(keys.hybrid_seed),
                vrf_seed: hex::encode(keys.vrf_seed),
                pq_sk: hex::encode(&keys.pq_sk),
                payment_keypair: keys
                    .payment_keypair
                    .as_ref()
                    .map(|payment_keypair| hex::encode(payment_keypair.encode())),
                payment_key_history: keys
                    .payment_key_history
                    .iter()
                    .map(|keypair| hex::encode(keypair.encode()))
                    .collect(),
                warning: None,
            },
        }
    }

    fn to_keys_file(self, name: String, public: ValidatorKeys) -> KeystoreResult<KeysFile> {
        Ok(KeysFile {
            name,
            public,
            hybrid_seed: decode_hex_fixed::<32>(&self.private.hybrid_seed, "hybrid_seed")?,
            vrf_seed: decode_hex_fixed::<32>(&self.private.vrf_seed, "vrf_seed")?,
            pq_sk: decode_hex(&self.private.pq_sk, "pq_sk")?,
            payment_keypair: self
                .private
                .payment_keypair
                .as_deref()
                .map(|value| {
                    PaymentKeypairV1::decode(&decode_hex(value, "payment_keypair")?)
                        .map_err(|e| KeystoreError::Crypto(e.to_string()))
                })
                .transpose()?,
            payment_key_history: self
                .private
                .payment_key_history
                .iter()
                .map(|value| {
                    PaymentKeypairV1::decode(&decode_hex(value, "payment_key_history")?)
                        .map_err(|e| KeystoreError::Crypto(e.to_string()))
                })
                .collect::<KeystoreResult<Vec<_>>>()?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedContainer {
    format: String,
    version: u8,
    name: String,
    validator_id: String,
    public: PublicJson,
    crypto: CryptoJson,
}

impl EncryptedContainer {
    fn from_public(
        keys: &KeysFile,
        salt: [u8; ARGON2_SALT_BYTES],
        nonce: [u8; CHACHA_NONCE_BYTES],
        ciphertext: String,
    ) -> Self {
        Self {
            format: KEYSTORE_FORMAT.to_string(),
            version: KEYSTORE_VERSION,
            name: keys.name.clone(),
            validator_id: hex::encode(keys.public.validator_id),
            public: PublicJson::from(keys),
            crypto: CryptoJson {
                kdf: KdfJson {
                    function: "argon2id".to_string(),
                    params: KdfParamsJson {
                        version: 19,
                        memory_kib: ARGON2_MEMORY_KIB,
                        iterations: ARGON2_ITERATIONS,
                        parallelism: ARGON2_PARALLELISM,
                        salt: hex::encode(salt),
                    },
                },
                cipher: CipherJson {
                    function: "chacha20-poly1305".to_string(),
                    params: CipherParamsJson {
                        nonce: hex::encode(nonce),
                    },
                    ciphertext,
                },
            },
        }
    }

    fn associated_data(&self) -> KeystoreResult<Vec<u8>> {
        // AAD is authenticated byte-for-byte for existing encrypted keystores.
        // Optional fields included here must omit `None` or be version-gated.
        #[derive(Serialize)]
        struct Aad<'a> {
            format: &'a str,
            version: u8,
            name: &'a str,
            validator_id: &'a str,
            public: &'a PublicJson,
            kdf: &'a KdfJson,
            cipher_function: &'a str,
            cipher_params: &'a CipherParamsJson,
        }
        serde_json::to_vec(&Aad {
            format: &self.format,
            version: self.version,
            name: &self.name,
            validator_id: &self.validator_id,
            public: &self.public,
            kdf: &self.crypto.kdf,
            cipher_function: &self.crypto.cipher.function,
            cipher_params: &self.crypto.cipher.params,
        })
        .map_err(|e| KeystoreError::Parse(e.to_string()))
    }

    fn validate_crypto_params(&self) -> KeystoreResult<()> {
        if self.crypto.kdf.function != "argon2id" {
            return Err(KeystoreError::Parse(format!(
                "unsupported keystore KDF '{}'",
                self.crypto.kdf.function
            )));
        }
        if self.crypto.kdf.params.version != 19
            || self.crypto.kdf.params.memory_kib != ARGON2_MEMORY_KIB
            || self.crypto.kdf.params.iterations != ARGON2_ITERATIONS
            || self.crypto.kdf.params.parallelism != ARGON2_PARALLELISM
        {
            return Err(KeystoreError::Parse(
                "unsupported Argon2id parameter set".to_string(),
            ));
        }
        if self.crypto.cipher.function != "chacha20-poly1305" {
            return Err(KeystoreError::Parse(format!(
                "unsupported keystore cipher '{}'",
                self.crypto.cipher.function
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CryptoJson {
    kdf: KdfJson,
    cipher: CipherJson,
}

#[derive(Debug, Serialize, Deserialize)]
struct ColdPublicJson {
    classical_pk: String,
    pq_pk: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ColdPrivateJson {
    classical_seed: String,
    pq_seed: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ColdPlaintextContainer {
    format: String,
    version: u8,
    public: ColdPublicJson,
    private: ColdPrivateJson,
}

impl From<&ColdKeysFile> for ColdPlaintextContainer {
    fn from(keys: &ColdKeysFile) -> Self {
        Self {
            format: COLD_KEYSTORE_FORMAT.to_string(),
            version: COLD_KEYSTORE_VERSION,
            public: ColdPublicJson {
                classical_pk: hex::encode(keys.classical_pk),
                pq_pk: hex::encode(&keys.pq_pk),
            },
            private: ColdPrivateJson {
                classical_seed: hex::encode(keys.classical_seed),
                pq_seed: hex::encode(keys.pq_seed),
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ColdEncryptedContainer {
    format: String,
    version: u8,
    public: ColdPublicJson,
    crypto: CryptoJson,
}

impl ColdEncryptedContainer {
    fn new(
        public: ColdPublicJson,
        salt: [u8; ARGON2_SALT_BYTES],
        nonce: [u8; CHACHA_NONCE_BYTES],
    ) -> Self {
        Self {
            format: COLD_KEYSTORE_FORMAT.to_string(),
            version: COLD_KEYSTORE_VERSION,
            public,
            crypto: CryptoJson {
                kdf: KdfJson {
                    function: "argon2id".into(),
                    params: KdfParamsJson {
                        version: 19,
                        memory_kib: ARGON2_MEMORY_KIB,
                        iterations: ARGON2_ITERATIONS,
                        parallelism: ARGON2_PARALLELISM,
                        salt: hex::encode(salt),
                    },
                },
                cipher: CipherJson {
                    function: "chacha20-poly1305".into(),
                    params: CipherParamsJson {
                        nonce: hex::encode(nonce),
                    },
                    ciphertext: String::new(),
                },
            },
        }
    }

    fn associated_data(&self) -> KeystoreResult<Vec<u8>> {
        #[derive(Serialize)]
        struct Aad<'a> {
            format: &'a str,
            version: u8,
            public: &'a ColdPublicJson,
            kdf: &'a KdfJson,
            cipher_function: &'a str,
            cipher_params: &'a CipherParamsJson,
        }
        serde_json::to_vec(&Aad {
            format: &self.format,
            version: self.version,
            public: &self.public,
            kdf: &self.crypto.kdf,
            cipher_function: &self.crypto.cipher.function,
            cipher_params: &self.crypto.cipher.params,
        })
        .map_err(|e| KeystoreError::Parse(e.to_string()))
    }

    fn validate(&self) -> KeystoreResult<()> {
        if self.format != COLD_KEYSTORE_FORMAT {
            return Err(KeystoreError::Parse("not an INDRA cold keystore".into()));
        }
        if self.version != COLD_KEYSTORE_VERSION {
            return Err(KeystoreError::UnsupportedVersion(self.version as u64));
        }
        if self.crypto.kdf.function != "argon2id"
            || self.crypto.kdf.params.version != 19
            || self.crypto.kdf.params.memory_kib != ARGON2_MEMORY_KIB
            || self.crypto.kdf.params.iterations != ARGON2_ITERATIONS
            || self.crypto.kdf.params.parallelism != ARGON2_PARALLELISM
            || self.crypto.cipher.function != "chacha20-poly1305"
        {
            return Err(KeystoreError::Parse(
                "unsupported cold-keystore crypto parameters".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct KdfJson {
    function: String,
    params: KdfParamsJson,
}

#[derive(Debug, Serialize, Deserialize)]
struct KdfParamsJson {
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CipherJson {
    function: String,
    params: CipherParamsJson,
    ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CipherParamsJson {
    nonce: String,
}

fn plaintext_json(keys: &KeysFile) -> String {
    let payment_pubkey_json = keys
        .public
        .payment_pubkey
        .as_ref()
        .map(|payment_pubkey| format!(r#""{}""#, hex::encode(payment_pubkey.encode())))
        .unwrap_or_else(|| "null".to_string());
    let payment_keypair_json = keys
        .payment_keypair
        .as_ref()
        .map(|payment_keypair| format!(r#""{}""#, hex::encode(payment_keypair.encode())))
        .unwrap_or_else(|| "null".to_string());
    let payment_key_history_json = keys
        .payment_key_history
        .iter()
        .map(|keypair| format!(r#""{}""#, hex::encode(keypair.encode())))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"{{
  "name": "{name}",
  "validator_id": "{validator_id}",
  "mnemonic_hint": "Back up your 24-word BIP-39 recovery phrase separately. It is never stored in this file.",
  "public": {{
    "hybrid_classical_pk": "{classical}",
    "hybrid_pq_pk": "{pq}",
    "vrf_pk": "{vrf}",
    "payment_pubkey": {payment_pubkey}
  }},
  "private": {{
    "hybrid_seed": "{h_seed}",
    "vrf_seed": "{v_seed}",
    "pq_sk": "{pq_sk}",
    "payment_keypair": {payment_keypair},
    "payment_key_history": [{payment_key_history}],
    "WARNING": "Keep private seeds secret. Never share this section."
  }}
}}"#,
        name = json_escape(&keys.name),
        validator_id = hex::encode(keys.public.validator_id),
        classical = hex::encode(keys.public.hybrid_classical_pk),
        pq = hex::encode(&keys.public.hybrid_pq_pk),
        vrf = hex::encode(keys.public.vrf_pk),
        h_seed = hex::encode(keys.hybrid_seed),
        v_seed = hex::encode(keys.vrf_seed),
        pq_sk = hex::encode(&keys.pq_sk),
        payment_pubkey = payment_pubkey_json,
        payment_keypair = payment_keypair_json,
        payment_key_history = payment_key_history_json,
    )
}

fn plaintext_from_json(json: &str) -> KeystoreResult<KeysFile> {
    let parsed: PlaintextContainer =
        serde_json::from_str(json).map_err(|e| KeystoreError::Parse(e.to_string()))?;
    let public = parsed.public.to_validator_keys()?;
    validate_public_container_identity(&parsed.validator_id, &public)?;
    let keys = KeysFile {
        name: parsed.name,
        public,
        hybrid_seed: decode_hex_fixed::<32>(&parsed.private.hybrid_seed, "hybrid_seed")?,
        vrf_seed: decode_hex_fixed::<32>(&parsed.private.vrf_seed, "vrf_seed")?,
        pq_sk: decode_hex(&parsed.private.pq_sk, "pq_sk")?,
        payment_keypair: parsed
            .private
            .payment_keypair
            .as_deref()
            .map(|value| {
                PaymentKeypairV1::decode(&decode_hex(value, "payment_keypair")?)
                    .map_err(|e| KeystoreError::Crypto(e.to_string()))
            })
            .transpose()?,
        payment_key_history: parsed
            .private
            .payment_key_history
            .iter()
            .map(|value| {
                PaymentKeypairV1::decode(&decode_hex(value, "payment_key_history")?)
                    .map_err(|e| KeystoreError::Crypto(e.to_string()))
            })
            .collect::<KeystoreResult<Vec<_>>>()?,
    };
    verify_public_metadata(&keys)?;
    Ok(keys)
}

fn validate_public_container_identity(
    validator_id_hex: &str,
    public: &ValidatorKeys,
) -> KeystoreResult<()> {
    let validator_id = decode_hex_fixed::<32>(validator_id_hex, "validator_id")?;
    if public.validator_id != validator_id {
        return Err(KeystoreError::Parse(
            "validator_id does not match public key".to_string(),
        ));
    }
    Ok(())
}

fn verify_public_metadata(keys: &KeysFile) -> KeystoreResult<()> {
    let payment_keypair = keys.payment_keypair.clone().ok_or_else(|| {
        KeystoreError::Crypto("canonical keystore is missing payment key material".to_string())
    })?;
    let derived = build_keys_file(
        keys.name.clone(),
        keys.hybrid_seed,
        keys.vrf_seed,
        payment_keypair.x25519_sk,
        payment_keypair.ml_kem_1024_seed,
    )?;
    if derived.public.validator_id != keys.public.validator_id
        || derived.public.hybrid_classical_pk != keys.public.hybrid_classical_pk
        || derived.public.hybrid_pq_pk != keys.public.hybrid_pq_pk
        || derived.public.vrf_pk != keys.public.vrf_pk
    {
        return Err(KeystoreError::Crypto(
            "private key material does not match public metadata".to_string(),
        ));
    }
    if derived.pq_sk != keys.pq_sk {
        return Err(KeystoreError::Crypto(
            "ML-DSA private key does not match public metadata".to_string(),
        ));
    }
    match (&keys.payment_keypair, &keys.public.payment_pubkey) {
        (Some(payment_keypair), Some(payment_pubkey))
            if payment_keypair.public_key() == *payment_pubkey => {}
        (Some(_), Some(_)) => {
            return Err(KeystoreError::Crypto(
                "payment private key does not match public metadata".to_string(),
            ));
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(KeystoreError::Crypto(
                "payment key material is incomplete".to_string(),
            ));
        }
        (None, None) => {}
    }
    Ok(())
}

fn derive_key(password: &[u8], salt: &[u8]) -> KeystoreResult<[u8; 32]> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|e| KeystoreError::Crypto(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| KeystoreError::Crypto(e.to_string()))?;
    Ok(key)
}

fn encrypt_payload(
    password: &[u8],
    salt: &[u8],
    nonce: &[u8; CHACHA_NONCE_BYTES],
    aad: &[u8],
    plaintext: &[u8],
) -> KeystoreResult<Vec<u8>> {
    let mut key = derive_key(password, salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let result = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| KeystoreError::Crypto("encryption failed".to_string()));
    key.zeroize();
    result
}

fn decrypt_payload(
    password: &[u8],
    salt: &[u8],
    nonce: &[u8; CHACHA_NONCE_BYTES],
    aad: &[u8],
    ciphertext: &[u8],
) -> KeystoreResult<Vec<u8>> {
    let mut key = derive_key(password, salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let result = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| KeystoreError::Crypto("authentication failed".to_string()));
    key.zeroize();
    result
}

fn decode_hex(value: &str, field: &str) -> KeystoreResult<Vec<u8>> {
    hex::decode(value).map_err(|e| KeystoreError::InvalidHex(format!("{field}: {e}")))
}

fn decode_hex_fixed<const N: usize>(value: &str, field: &str) -> KeystoreResult<[u8; N]> {
    let bytes = decode_hex(value, field)?;
    if bytes.len() != N {
        return Err(KeystoreError::Parse(format!(
            "field '{field}' must be {N} bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Securely write secret-bearing files.
#[cfg(unix)]
fn write_secret_file_secure(path: &str, contents: &[u8]) -> KeystoreResult<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(KEY_FILE_MODE)
        .open(path)
        .map_err(|e| KeystoreError::Io(format!("{}: {}", path, e)))?;
    file.write_all(contents)
        .map_err(|e| KeystoreError::Io(format!("{}: {}", path, e)))?;
    file.sync_all()
        .map_err(|e| KeystoreError::Io(format!("{}: {}", path, e)))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(KEY_FILE_MODE))
        .map_err(|e| KeystoreError::Io(format!("{}: {}", path, e)))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file_secure(path: &str, contents: &[u8]) -> KeystoreResult<()> {
    std::fs::write(path, contents).map_err(|e| KeystoreError::Io(format!("{}: {}", path, e)))
}

fn set_secret_file_permissions(path: &Path) -> KeystoreResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(KEY_FILE_MODE))
            .map_err(|e| KeystoreError::Io(format!("{}: {}", path.display(), e)))?;
    }
    Ok(())
}

/// Print a warning if an existing key file is readable by group/other users.
pub fn warn_if_key_file_permissive(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(meta) = std::fs::metadata(path) else {
            return;
        };
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            eprintln!(
                "WARNING: {} has permissive permissions ({:o}). Run: chmod 600 {}",
                path, mode, path
            );
        }
    }
}

/// Validate password-file permissions according to caller policy.
pub fn check_password_file_permissions(path: &Path, reject: bool) -> KeystoreResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| KeystoreError::Io(format!("{}: {}", path.display(), e)))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            if reject {
                return Err(KeystoreError::PasswordFilePermissions {
                    path: path.display().to_string(),
                    mode,
                });
            }
            eprintln!(
                "WARNING: password file {} has permissive permissions ({:o}). Run: chmod 600 {}",
                path.display(),
                mode,
                path.display()
            );
        }
    }
    Ok(())
}

fn read_password_file(path: &Path, reject_permissive: bool) -> KeystoreResult<Zeroizing<String>> {
    check_password_file_permissions(path, reject_permissive)?;
    let mut password = std::fs::read_to_string(path)
        .map_err(|e| KeystoreError::Io(format!("{}: {}", path.display(), e)))?;
    while password.ends_with('\n') || password.ends_with('\r') {
        password.pop();
    }
    Ok(Zeroizing::new(password))
}

fn read_password_prompt(confirm: bool) -> KeystoreResult<Zeroizing<String>> {
    let first = read_secret_from_stdin("Enter keystore password: ")?;
    if confirm {
        let second = read_secret_from_stdin("Confirm keystore password: ")?;
        if *first != *second {
            return Err(KeystoreError::Crypto("passwords do not match".to_string()));
        }
    }
    Ok(first)
}

fn read_secret_from_stdin(prompt: &str) -> KeystoreResult<Zeroizing<String>> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let echo_guard = EchoGuard::disable();
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| KeystoreError::Io(e.to_string()))?;
    drop(echo_guard);
    eprintln!();
    Ok(Zeroizing::new(
        input.trim_end_matches(['\r', '\n']).to_string(),
    ))
}

#[cfg(unix)]
struct EchoGuard {
    original: libc::termios,
    active: bool,
}

#[cfg(unix)]
impl EchoGuard {
    fn disable() -> Self {
        let fd = 0;
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `original` points to writable memory for libc to fill.
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return Self {
                // SAFETY: zeroed termios is never used when active=false.
                original: unsafe { std::mem::zeroed() },
                active: false,
            };
        }
        // SAFETY: tcgetattr succeeded, so `original` is initialized.
        let original = unsafe { original.assume_init() };
        let mut no_echo = original;
        no_echo.c_lflag &= !libc::ECHO;
        // SAFETY: `no_echo` is a valid termios copied from current settings.
        let active = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &no_echo) } == 0;
        Self { original, active }
    }
}

#[cfg(unix)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: original came from a successful tcgetattr call.
            let _ = unsafe { libc::tcsetattr(0, libc::TCSANOW, &self.original) };
        }
    }
}

#[cfg(not(unix))]
struct EchoGuard;

#[cfg(not(unix))]
impl EchoGuard {
    fn disable() -> Self {
        Self
    }
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Return true if a secret-bearing CLI flag was supplied with an argv value.
pub fn has_secret_value_in_argv(args: &[String], flag: &str) -> bool {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|idx| args.get(idx.saturating_add(1)))
        .is_some_and(|next| !next.starts_with("--"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> KeysFile {
        generate_from_master_seed("validator".to_string(), [1; 32]).unwrap()
    }

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("{name}-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn encrypted_keystore_round_trip_recovers_identical_keys() {
        let keys = fixture();
        let json =
            encrypt_plaintext_keys_with_params(&keys, b"correct horse", [7; 32], [8; 12]).unwrap();
        let recovered = decrypt_encrypted_keys(&json, b"correct horse").unwrap();
        assert_eq!(recovered, keys);
    }

    #[test]
    fn mnemonic_generation_and_recovery_produce_identical_complete_keystores() {
        let (phrase, generated) = generate_from_new_mnemonic("validator".to_string()).unwrap();
        let recovered = recover_from_mnemonic(&phrase, "validator".to_string()).unwrap();
        assert_eq!(generated, recovered);
        assert!(generated.payment_keypair.is_some());
        assert!(generated.public.payment_pubkey.is_some());
    }

    #[test]
    fn cold_key_file_is_encrypted_independent_secure_and_does_not_touch_hot_keys() {
        let dir = test_dir("cold-key-generate");
        let hot_path = dir.join("keys.json");
        let cold_path = dir.join("validator-cold-keys.json");
        let hot_bytes = b"existing-hot-identity-must-remain-byte-identical";
        write_secret_file_secure(hot_path.to_str().unwrap(), hot_bytes).unwrap();
        let generated = generate_cold_keys_file(&cold_path, Some(b"cold-password"), false).unwrap();
        assert_eq!(std::fs::read(&hot_path).unwrap(), hot_bytes);
        let json = std::fs::read_to_string(&cold_path).unwrap();
        assert!(json.contains(COLD_KEYSTORE_FORMAT));
        assert!(!json.contains(&hex::encode(generated.classical_seed)));
        let recovered = decrypt_cold_keys(&json, b"cold-password").unwrap();
        assert_eq!(recovered, generated);
        assert_ne!(generated.classical_seed, generated.pq_seed);
        let hot = derive_all_seeds(&[0x42; 32]);
        for cold_seed in [generated.classical_seed, generated.pq_seed] {
            assert_ne!(cold_seed, hot.hybrid_seed);
            assert_ne!(cold_seed, hot.vrf_seed);
            assert_ne!(cold_seed, hot.payment_x25519_seed);
            assert_ne!(cold_seed, hot.payment_ml_kem_seed[..32]);
            assert_ne!(cold_seed, hot.payment_ml_kem_seed[32..]);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&cold_path).unwrap().permissions().mode() & 0o777,
                KEY_FILE_MODE
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cold_key_file_refuses_overwrite_without_force() {
        let dir = test_dir("cold-key-overwrite");
        let path = dir.join("validator-cold-keys.json");
        let first = generate_cold_keys_file(&path, Some(b"pw"), false).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(generate_cold_keys_file(&path, Some(b"pw"), false).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let replacement = generate_cold_keys_file(&path, Some(b"pw"), true).unwrap();
        assert_ne!(replacement.classical_pk, first.classical_pk);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn key_generation_includes_payment_keypair() {
        let keys = fixture();
        let payment_keypair = keys.payment_keypair.as_ref().unwrap();
        let payment_pubkey = keys.public.payment_pubkey.as_ref().unwrap();
        assert_eq!(payment_keypair.public_key(), *payment_pubkey);
        assert_eq!(
            PaymentKeypairV1::decode(&payment_keypair.encode()).unwrap(),
            *payment_keypair
        );
        assert_eq!(
            PaymentPubKeyV1::decode(&payment_pubkey.encode()).unwrap(),
            *payment_pubkey
        );
    }

    #[test]
    fn payment_keypair_plaintext_json_round_trip() {
        let keys = fixture();
        let json = keys.to_json();
        assert!(!json.contains("bls_seed"));
        assert!(!json.contains("bls_pk"));
        assert!(json.contains("\"payment_pubkey\""));
        assert!(json.contains("\"payment_keypair\""));
        assert_eq!(KeysFile::from_json(&json).unwrap(), keys);
    }

    #[test]
    fn payment_keypair_encrypted_storage_round_trip() {
        let mut keys = fixture();
        keys.payment_key_history.push(PaymentKeypairV1::generate());
        let json = encrypt_plaintext_keys_with_params(&keys, b"pw", [7; 32], [8; 12]).unwrap();
        assert!(json.contains("\"payment_pubkey\""));
        assert!(!json.contains("\"payment_keypair\""));
        assert!(!json.contains("payment_key_history"));
        assert!(!json.contains("bls_seed"));
        assert!(!json.contains("bls_pk"));
        let recovered = decrypt_encrypted_keys(&json, b"pw").unwrap();
        assert_eq!(recovered.payment_keypair, keys.payment_keypair);
        assert_eq!(recovered.payment_key_history, keys.payment_key_history);
        assert_eq!(recovered.public.payment_pubkey, keys.public.payment_pubkey);
    }

    #[test]
    fn wrong_password_fails_authentication_cleanly() {
        let keys = fixture();
        let json = encrypt_plaintext_keys_with_params(&keys, b"right", [7; 32], [8; 12]).unwrap();
        assert!(decrypt_encrypted_keys(&json, b"wrong").is_err());
    }

    #[test]
    fn public_metadata_inspectable_without_password() {
        let keys = fixture();
        let json = encrypt_plaintext_keys_with_params(&keys, b"pw", [7; 32], [8; 12]).unwrap();
        let (name, public) = inspect_public_metadata(&json).unwrap();
        assert_eq!(name, keys.name);
        assert_eq!(public, keys.public);
    }

    #[test]
    fn decrypted_private_material_rederives_cleartext_public_metadata() {
        let keys = fixture();
        let mut json = encrypt_plaintext_keys_with_params(&keys, b"pw", [7; 32], [8; 12]).unwrap();
        let wrong_vrf = hex::encode([9u8; 32]);
        json = json.replacen(&hex::encode(keys.public.vrf_pk), &wrong_vrf, 1);
        assert!(matches!(
            decrypt_encrypted_keys(&json, b"pw"),
            Err(KeystoreError::Crypto(_))
        ));
    }

    #[test]
    fn tampering_with_public_metadata_causes_decrypt_failure() {
        let keys = fixture();
        let json = encrypt_plaintext_keys_with_params(&keys, b"pw", [7; 32], [8; 12]).unwrap();
        let tampered = json.replacen("validator", "evil", 1);
        assert!(decrypt_encrypted_keys(&tampered, b"pw").is_err());
    }

    #[test]
    fn encrypted_public_validator_id_mismatch_is_rejected_without_password() {
        let keys = fixture();
        let json = encrypt_plaintext_keys_with_params(&keys, b"pw", [7; 32], [8; 12]).unwrap();
        let bad = json.replacen(
            &format!(
                "\"validator_id\": \"{}\"",
                hex::encode(keys.public.validator_id)
            ),
            &format!("\"validator_id\": \"{}\"", hex::encode([0x55u8; 32])),
            1,
        );
        assert!(inspect_public_metadata(&bad).is_err());
        assert!(decrypt_encrypted_keys(&bad, b"pw").is_err());
    }

    #[test]
    fn encrypted_keystore_rejects_unsupported_crypto_params() {
        let keys = fixture();
        let json = encrypt_plaintext_keys_with_params(&keys, b"pw", [7; 32], [8; 12]).unwrap();
        let bad = json.replacen("\"memory_kib\": 65536", "\"memory_kib\": 1024", 1);
        assert!(matches!(
            decrypt_encrypted_keys(&bad, b"pw"),
            Err(KeystoreError::Parse(_))
        ));
    }

    #[test]
    fn legacy_plaintext_keys_json_still_loads() {
        let keys = fixture();
        let parsed = KeysFile::from_json(&keys.to_json()).unwrap();
        assert_eq!(parsed, keys);
    }

    #[test]
    fn unsupported_encrypted_version_fails_closed() {
        let keys = fixture();
        let json = encrypt_plaintext_keys_with_params(&keys, b"pw", [7; 32], [8; 12]).unwrap();
        let bad = json.replacen("\"version\": 1", "\"version\": 99", 1);
        assert!(matches!(
            decrypt_encrypted_keys(&bad, b"pw"),
            Err(KeystoreError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn migration_replace_verifies_before_replacing_original() {
        let dir =
            std::env::temp_dir().join(format!("indra-keystore-test-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys.json");
        let keys = fixture();
        write_keys_secure(path.to_str().unwrap(), &keys.to_json()).unwrap();
        let backup = encrypt_plaintext_keys_replace(&path, &keys, b"pw").unwrap();
        assert!(backup.exists());
        let encrypted = std::fs::read_to_string(&path).unwrap();
        assert_eq!(decrypt_encrypted_keys(&encrypted, b"pw").unwrap(), keys);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn encrypted_key_file_loads_from_password_file_source() {
        let dir = std::env::temp_dir().join(format!(
            "indra-keystore-password-source-test-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let keys_path = dir.join("keys.json");
        let password_path = dir.join("keys.pass");
        let keys = fixture();
        let encrypted = encrypt_plaintext_keys_with_params(&keys, b"pw", [7; 32], [8; 12]).unwrap();
        write_keys_secure(keys_path.to_str().unwrap(), &encrypted).unwrap();
        write_keys_secure(password_path.to_str().unwrap(), "pw\n").unwrap();
        let loaded = load_keys(
            keys_path.to_str().unwrap(),
            PasswordSource::File {
                path: &password_path,
                reject_permissive: true,
            },
        )
        .unwrap();
        assert_eq!(loaded, keys);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn password_file_permission_policy_rejects_for_validator_warns_for_cli() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "indra-keystore-permission-test-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let password_path = dir.join("keys.pass");
        std::fs::write(&password_path, "pw\n").unwrap();
        std::fs::set_permissions(&password_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(matches!(
            check_password_file_permissions(&password_path, true),
            Err(KeystoreError::PasswordFilePermissions { .. })
        ));
        assert!(check_password_file_permissions(&password_path, false).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
