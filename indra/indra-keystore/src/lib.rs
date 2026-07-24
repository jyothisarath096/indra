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
    bls::BlsKeypair,
    derive_all_seeds, generate_mnemonic,
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    mnemonic_to_seed, sha256, PaymentKeypairV1, PaymentPubKeyV1, VrfKeypair,
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
    /// BLS12-381 public key (48 bytes).
    pub bls_pk: [u8; 48],
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
    /// Legacy BLS keypair seed (keep secret).
    pub bls_seed: [u8; 32],
    /// VRF keypair seed (keep secret).
    pub vrf_seed: [u8; 32],
    /// ML-DSA-87 secret key bytes (keep secret).
    pub pq_sk: Vec<u8>,
    /// Optional payment key-exchange private keypair (keep secret).
    pub payment_keypair: Option<PaymentKeypairV1>,
}

/// Byte-for-byte identity material snapshot used by payment-key retrofit checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityMaterialSnapshot {
    /// Private hybrid seed.
    pub hybrid_seed: [u8; 32],
    /// Private BLS seed.
    pub bls_seed: [u8; 32],
    /// Private VRF seed.
    pub vrf_seed: [u8; 32],
    /// Private ML-DSA-87 key bytes.
    pub pq_sk: Vec<u8>,
    /// Public validator id.
    pub validator_id: [u8; 32],
    /// Public classical signing key.
    pub hybrid_classical_pk: [u8; 32],
    /// Public PQ signing key bytes.
    pub hybrid_pq_pk: Vec<u8>,
    /// Public BLS key.
    pub bls_pk: [u8; 48],
    /// Public VRF key.
    pub vrf_pk: [u8; 32],
}

impl IdentityMaterialSnapshot {
    /// Capture all non-payment identity material.
    pub fn from_keys(keys: &KeysFile) -> Self {
        Self {
            hybrid_seed: keys.hybrid_seed,
            bls_seed: keys.bls_seed,
            vrf_seed: keys.vrf_seed,
            pq_sk: keys.pq_sk.clone(),
            validator_id: keys.public.validator_id,
            hybrid_classical_pk: keys.public.hybrid_classical_pk,
            hybrid_pq_pk: keys.public.hybrid_pq_pk.clone(),
            bls_pk: keys.public.bls_pk,
            vrf_pk: keys.public.vrf_pk,
        }
    }

    /// Rows for explicit operator-facing before/after reporting.
    pub fn comparison_rows(
        before: &Self,
        after: &Self,
    ) -> Vec<(&'static str, String, String, bool)> {
        vec![
            (
                "hybrid_seed",
                hex::encode(before.hybrid_seed),
                hex::encode(after.hybrid_seed),
                before.hybrid_seed == after.hybrid_seed,
            ),
            (
                "bls_seed",
                hex::encode(before.bls_seed),
                hex::encode(after.bls_seed),
                before.bls_seed == after.bls_seed,
            ),
            (
                "vrf_seed",
                hex::encode(before.vrf_seed),
                hex::encode(after.vrf_seed),
                before.vrf_seed == after.vrf_seed,
            ),
            (
                "pq_sk",
                hex::encode(&before.pq_sk),
                hex::encode(&after.pq_sk),
                before.pq_sk == after.pq_sk,
            ),
            (
                "validator_id",
                hex::encode(before.validator_id),
                hex::encode(after.validator_id),
                before.validator_id == after.validator_id,
            ),
            (
                "hybrid_classical_pk",
                hex::encode(before.hybrid_classical_pk),
                hex::encode(after.hybrid_classical_pk),
                before.hybrid_classical_pk == after.hybrid_classical_pk,
            ),
            (
                "hybrid_pq_pk",
                hex::encode(&before.hybrid_pq_pk),
                hex::encode(&after.hybrid_pq_pk),
                before.hybrid_pq_pk == after.hybrid_pq_pk,
            ),
            (
                "bls_pk",
                hex::encode(before.bls_pk),
                hex::encode(after.bls_pk),
                before.bls_pk == after.bls_pk,
            ),
            (
                "vrf_pk",
                hex::encode(before.vrf_pk),
                hex::encode(after.vrf_pk),
                before.vrf_pk == after.vrf_pk,
            ),
        ]
    }
}

/// Result of a payment-key retrofit operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddPaymentKeyReport {
    /// Identity material before adding payment fields.
    pub before: IdentityMaterialSnapshot,
    /// Identity material after adding payment fields.
    pub after: IdentityMaterialSnapshot,
    /// Newly installed payment public key, hex-encoded.
    pub payment_pubkey_hex: String,
    /// File written by the operation.
    pub output_path: PathBuf,
    /// Backup created before replacement, if `--replace` was used.
    pub backup_path: Option<PathBuf>,
}

impl KeysFile {
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

/// Generate a complete set of validator keypairs from three seeds.
pub fn generate_keypairs(
    name: String,
    hybrid_seed: [u8; 32],
    bls_seed: [u8; 32],
    vrf_seed: [u8; 32],
) -> KeystoreResult<KeysFile> {
    use indra_crypto::hash::domain_hash;
    let mut payment_material = Vec::with_capacity(96);
    payment_material.extend_from_slice(&hybrid_seed);
    payment_material.extend_from_slice(&bls_seed);
    payment_material.extend_from_slice(&vrf_seed);
    let payment_x25519_seed =
        domain_hash(b"INDRA-KEYGEN-PAYMENT-X25519-COMPAT-v1", &payment_material);
    let mut payment_ml_kem_seed = [0u8; 64];
    payment_ml_kem_seed[..32].copy_from_slice(&domain_hash(
        b"INDRA-KEYGEN-PAYMENT-ML-KEM-COMPAT-v1:0",
        &payment_material,
    ));
    payment_ml_kem_seed[32..].copy_from_slice(&domain_hash(
        b"INDRA-KEYGEN-PAYMENT-ML-KEM-COMPAT-v1:1",
        &payment_material,
    ));
    generate_keypairs_with_payment(
        name,
        hybrid_seed,
        bls_seed,
        vrf_seed,
        payment_x25519_seed,
        payment_ml_kem_seed,
    )
}

fn generate_keypairs_with_payment(
    name: String,
    hybrid_seed: [u8; 32],
    bls_seed: [u8; 32],
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
    let bls = BlsKeypair::from_seed(&bls_seed).map_err(|e| KeystoreError::Crypto(e.to_string()))?;
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
            bls_pk: bls.public_key().0,
            vrf_pk: vrf.public_key(),
            payment_pubkey: Some(payment_pubkey),
        },
        hybrid_seed,
        bls_seed,
        vrf_seed,
        pq_sk: pq_sk_bytes,
        payment_keypair: Some(payment_keypair),
    })
}

/// Generate a complete validator keypair set from a new mnemonic.
pub fn generate_from_new_mnemonic(name: String) -> KeystoreResult<(String, KeysFile)> {
    let phrase = generate_mnemonic();
    let master_seed =
        mnemonic_to_seed(&phrase).map_err(|e| KeystoreError::Crypto(e.to_string()))?;
    let derived = derive_all_seeds(&master_seed);
    Ok((
        phrase,
        generate_keypairs_with_payment(
            name,
            derived.hybrid_seed,
            derived.bls_seed,
            derived.vrf_seed,
            derived.payment_x25519_seed,
            derived.payment_ml_kem_seed,
        )?,
    ))
}

/// Recover a validator keypair set from an existing mnemonic.
pub fn recover_from_mnemonic(phrase: &str, name: String) -> KeystoreResult<KeysFile> {
    let master_seed = mnemonic_to_seed(phrase).map_err(|e| KeystoreError::Crypto(e.to_string()))?;
    let derived = derive_all_seeds(&master_seed);
    generate_keypairs_with_payment(
        name,
        derived.hybrid_seed,
        derived.bls_seed,
        derived.vrf_seed,
        derived.payment_x25519_seed,
        derived.payment_ml_kem_seed,
    )
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
    use indra_crypto::hash::domain_hash;
    let hybrid_seed = domain_hash(b"INDRA-KEYGEN-HYBRID-v1", passphrase.as_bytes());
    let bls_seed = domain_hash(b"INDRA-KEYGEN-BLS-v1", passphrase.as_bytes());
    let vrf_seed = domain_hash(b"INDRA-KEYGEN-VRF-v1", passphrase.as_bytes());
    let payment_x25519_seed = domain_hash(b"INDRA-KEYGEN-PAYMENT-X25519-v1", passphrase.as_bytes());
    let mut payment_ml_kem_seed = [0u8; 64];
    payment_ml_kem_seed[..32].copy_from_slice(&domain_hash(
        b"INDRA-KEYGEN-PAYMENT-ML-KEM-v1:0",
        passphrase.as_bytes(),
    ));
    payment_ml_kem_seed[32..].copy_from_slice(&domain_hash(
        b"INDRA-KEYGEN-PAYMENT-ML-KEM-v1:1",
        passphrase.as_bytes(),
    ));
    generate_keypairs_with_payment(
        name,
        hybrid_seed,
        bls_seed,
        vrf_seed,
        payment_x25519_seed,
        payment_ml_kem_seed,
    )
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

/// Add deterministic payment key material to an existing key set without
/// changing any validator identity material.
pub fn add_payment_key_material(keys: &KeysFile, force: bool) -> KeystoreResult<KeysFile> {
    if keys.payment_keypair.is_some() && !force {
        return Err(KeystoreError::Parse(
            "payment_keypair already exists; pass --force to replace payment key material"
                .to_string(),
        ));
    }
    let before = IdentityMaterialSnapshot::from_keys(keys);
    let payment_source = generate_keypairs(
        keys.name.clone(),
        keys.hybrid_seed,
        keys.bls_seed,
        keys.vrf_seed,
    )?;
    let payment_keypair = payment_source.payment_keypair.ok_or_else(|| {
        KeystoreError::Crypto(
            "compatibility payment-key derivation did not produce a keypair".into(),
        )
    })?;
    let mut updated = keys.clone();
    updated.payment_keypair = Some(payment_keypair.clone());
    updated.public.payment_pubkey = Some(payment_keypair.public_key());
    let after = IdentityMaterialSnapshot::from_keys(&updated);
    if before != after {
        return Err(KeystoreError::Crypto(
            "payment-key retrofit changed validator identity material".to_string(),
        ));
    }
    verify_public_metadata(&updated)?;
    Ok(updated)
}

/// Add payment key material, encrypt, verify decryption, and write the result.
///
/// By default this writes a sibling file named `keys.with-payment.json`. Passing
/// `replace=true` creates a timestamped backup and atomically replaces `path`.
pub fn add_payment_key_to_file(
    path: &Path,
    password: &[u8],
    out: Option<&Path>,
    replace: bool,
    force: bool,
) -> KeystoreResult<AddPaymentKeyReport> {
    add_payment_key_to_file_with_encryptor(
        path,
        password,
        out,
        replace,
        force,
        encrypt_plaintext_keys,
    )
}

fn add_payment_key_to_file_with_encryptor(
    path: &Path,
    password: &[u8],
    out: Option<&Path>,
    replace: bool,
    force: bool,
    encryptor: fn(&KeysFile, &[u8]) -> KeystoreResult<String>,
) -> KeystoreResult<AddPaymentKeyReport> {
    if replace && out.is_some() {
        return Err(KeystoreError::Parse(
            "choose either --replace or --out, not both".to_string(),
        ));
    }
    let json = std::fs::read_to_string(path)
        .map_err(|e| KeystoreError::Io(format!("{}: {}", path.display(), e)))?;
    let original = match detect_format(&json)? {
        KeyFileFormat::Plaintext => plaintext_from_json(&json)?,
        KeyFileFormat::Encrypted => decrypt_encrypted_keys(&json, password)?,
    };
    let before = IdentityMaterialSnapshot::from_keys(&original);
    let updated = add_payment_key_material(&original, force)?;
    let after = IdentityMaterialSnapshot::from_keys(&updated);
    let encrypted = encryptor(&updated, password)?;
    let verified = decrypt_encrypted_keys(&encrypted, password)?;
    if verified != updated {
        return Err(KeystoreError::Crypto(
            "payment-key retrofit encryption round-trip verification failed".to_string(),
        ));
    }

    let output_path = if replace {
        path.to_path_buf()
    } else {
        out.map(Path::to_path_buf)
            .unwrap_or_else(|| default_payment_key_output_path(path))
    };
    let backup_path = if replace {
        let tmp = path.with_extension("json.payment-key.tmp");
        write_keys_secure(path_to_str(&tmp)?, &encrypted)?;
        let backup = timestamped_backup_path(path);
        std::fs::rename(path, &backup).map_err(|e| KeystoreError::Io(e.to_string()))?;
        set_secret_file_permissions(&backup)?;
        std::fs::rename(&tmp, path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        set_secret_file_permissions(path)?;
        Some(backup)
    } else {
        write_keys_secure(path_to_str(&output_path)?, &encrypted)?;
        None
    };

    Ok(AddPaymentKeyReport {
        before,
        after,
        payment_pubkey_hex: hex::encode(
            updated
                .public
                .payment_pubkey
                .as_ref()
                .expect("retrofit installs payment_pubkey")
                .encode(),
        ),
        output_path,
        backup_path,
    })
}

fn default_payment_key_output_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let stem = path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("keys");
    parent.join(format!("{stem}.with-payment.json"))
}

fn timestamped_backup_path(path: &Path) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    path.with_extension(format!("plaintext-backup-{ts}.json"))
}

fn path_to_str(path: &Path) -> KeystoreResult<&str> {
    path.to_str()
        .ok_or_else(|| KeystoreError::Io(format!("non-UTF-8 path: {}", path.display())))
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
    bls_pk: String,
    vrf_pk: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payment_pubkey: Option<String>,
}

impl PublicJson {
    fn from(keys: &KeysFile) -> Self {
        Self {
            hybrid_classical_pk: hex::encode(keys.public.hybrid_classical_pk),
            hybrid_pq_pk: hex::encode(&keys.public.hybrid_pq_pk),
            bls_pk: hex::encode(keys.public.bls_pk),
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
            bls_pk: decode_hex_fixed::<48>(&self.bls_pk, "public.bls_pk")?,
            vrf_pk: decode_hex_fixed::<32>(&self.vrf_pk, "public.vrf_pk")?,
            payment_pubkey,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PrivateJson {
    hybrid_seed: String,
    bls_seed: String,
    vrf_seed: String,
    pq_sk: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payment_keypair: Option<String>,
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
                bls_seed: hex::encode(keys.bls_seed),
                vrf_seed: hex::encode(keys.vrf_seed),
                pq_sk: hex::encode(&keys.pq_sk),
                payment_keypair: keys
                    .payment_keypair
                    .as_ref()
                    .map(|payment_keypair| hex::encode(payment_keypair.encode())),
                warning: None,
            },
        }
    }

    fn to_keys_file(self, name: String, public: ValidatorKeys) -> KeystoreResult<KeysFile> {
        Ok(KeysFile {
            name,
            public,
            hybrid_seed: decode_hex_fixed::<32>(&self.private.hybrid_seed, "hybrid_seed")?,
            bls_seed: decode_hex_fixed::<32>(&self.private.bls_seed, "bls_seed")?,
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
    format!(
        r#"{{
  "name": "{name}",
  "validator_id": "{validator_id}",
  "mnemonic_hint": "Back up your 24-word BIP-39 recovery phrase separately. It is never stored in this file.",
  "public": {{
    "hybrid_classical_pk": "{classical}",
    "hybrid_pq_pk": "{pq}",
    "bls_pk": "{bls}",
    "vrf_pk": "{vrf}",
    "payment_pubkey": {payment_pubkey}
  }},
  "private": {{
    "hybrid_seed": "{h_seed}",
    "bls_seed": "{b_seed}",
    "vrf_seed": "{v_seed}",
    "pq_sk": "{pq_sk}",
    "payment_keypair": {payment_keypair},
    "WARNING": "Keep private seeds secret. Never share this section."
  }}
}}"#,
        name = json_escape(&keys.name),
        validator_id = hex::encode(keys.public.validator_id),
        classical = hex::encode(keys.public.hybrid_classical_pk),
        pq = hex::encode(&keys.public.hybrid_pq_pk),
        bls = hex::encode(keys.public.bls_pk),
        vrf = hex::encode(keys.public.vrf_pk),
        h_seed = hex::encode(keys.hybrid_seed),
        b_seed = hex::encode(keys.bls_seed),
        v_seed = hex::encode(keys.vrf_seed),
        pq_sk = hex::encode(&keys.pq_sk),
        payment_pubkey = payment_pubkey_json,
        payment_keypair = payment_keypair_json,
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
        bls_seed: decode_hex_fixed::<32>(&parsed.private.bls_seed, "bls_seed")?,
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
    let derived = generate_keypairs(
        keys.name.clone(),
        keys.hybrid_seed,
        keys.bls_seed,
        keys.vrf_seed,
    )?;
    if derived.public.validator_id != keys.public.validator_id
        || derived.public.hybrid_classical_pk != keys.public.hybrid_classical_pk
        || derived.public.hybrid_pq_pk != keys.public.hybrid_pq_pk
        || derived.public.bls_pk != keys.public.bls_pk
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
        generate_keypairs("validator".to_string(), [1; 32], [2; 32], [3; 32]).unwrap()
    }

    fn fixture_without_payment() -> KeysFile {
        let mut keys = fixture();
        keys.payment_keypair = None;
        keys.public.payment_pubkey = None;
        keys
    }

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("{name}-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn corrupt_encryptor(keys: &KeysFile, password: &[u8]) -> KeystoreResult<String> {
        let encrypted = encrypt_plaintext_keys(keys, password)?;
        Ok(encrypted.replacen(r#""ciphertext": ""#, r#""ciphertext": "00"#, 1))
    }

    #[test]
    fn encrypted_keystore_round_trip_recovers_identical_keys() {
        let keys = fixture();
        let json =
            encrypt_plaintext_keys_with_params(&keys, b"correct horse", [7; 32], [8; 12]).unwrap();
        let recovered = decrypt_encrypted_keys(&json, b"correct horse").unwrap();
        assert_eq!(recovered, keys);
    }

    fn legacy_stage5_encrypted_keys_json(keys: &KeysFile, password: &[u8]) -> String {
        #[derive(Serialize)]
        struct LegacyPublicJson {
            hybrid_classical_pk: String,
            hybrid_pq_pk: String,
            bls_pk: String,
            vrf_pk: String,
        }
        #[derive(Serialize)]
        struct LegacyAad<'a> {
            format: &'a str,
            version: u8,
            name: &'a str,
            validator_id: &'a str,
            public: &'a LegacyPublicJson,
            kdf: &'a KdfJson,
            cipher_function: &'a str,
            cipher_params: &'a CipherParamsJson,
        }
        #[derive(Serialize)]
        struct LegacyPrivateJson {
            hybrid_seed: String,
            bls_seed: String,
            vrf_seed: String,
            pq_sk: String,
            warning: Option<String>,
        }
        #[derive(Serialize)]
        struct LegacyPrivatePayload {
            private: LegacyPrivateJson,
        }
        #[derive(Serialize)]
        struct LegacyEncryptedContainer {
            format: String,
            version: u8,
            name: String,
            validator_id: String,
            public: LegacyPublicJson,
            crypto: CryptoJson,
        }

        let salt = [7u8; ARGON2_SALT_BYTES];
        let nonce = [8u8; CHACHA_NONCE_BYTES];
        let public = LegacyPublicJson {
            hybrid_classical_pk: hex::encode(keys.public.hybrid_classical_pk),
            hybrid_pq_pk: hex::encode(&keys.public.hybrid_pq_pk),
            bls_pk: hex::encode(keys.public.bls_pk),
            vrf_pk: hex::encode(keys.public.vrf_pk),
        };
        let kdf = KdfJson {
            function: "argon2id".to_string(),
            params: KdfParamsJson {
                version: 19,
                memory_kib: ARGON2_MEMORY_KIB,
                iterations: ARGON2_ITERATIONS,
                parallelism: ARGON2_PARALLELISM,
                salt: hex::encode(salt),
            },
        };
        let cipher_params = CipherParamsJson {
            nonce: hex::encode(nonce),
        };
        let validator_id = hex::encode(keys.public.validator_id);
        let aad = serde_json::to_vec(&LegacyAad {
            format: KEYSTORE_FORMAT,
            version: KEYSTORE_VERSION,
            name: &keys.name,
            validator_id: &validator_id,
            public: &public,
            kdf: &kdf,
            cipher_function: "chacha20-poly1305",
            cipher_params: &cipher_params,
        })
        .unwrap();
        let plaintext = serde_json::to_vec(&LegacyPrivatePayload {
            private: LegacyPrivateJson {
                hybrid_seed: hex::encode(keys.hybrid_seed),
                bls_seed: hex::encode(keys.bls_seed),
                vrf_seed: hex::encode(keys.vrf_seed),
                pq_sk: hex::encode(&keys.pq_sk),
                warning: None,
            },
        })
        .unwrap();
        let ciphertext = encrypt_payload(password, &salt, &nonce, &aad, &plaintext).unwrap();
        serde_json::to_string_pretty(&LegacyEncryptedContainer {
            format: KEYSTORE_FORMAT.to_string(),
            version: KEYSTORE_VERSION,
            name: keys.name.clone(),
            validator_id,
            public,
            crypto: CryptoJson {
                kdf,
                cipher: CipherJson {
                    function: "chacha20-poly1305".to_string(),
                    params: cipher_params,
                    ciphertext: hex::encode(ciphertext),
                },
            },
        })
        .unwrap()
    }

    #[test]
    fn stage5_encrypted_keystore_without_payment_fields_still_decrypts() {
        let keys = fixture();
        let json = legacy_stage5_encrypted_keys_json(&keys, b"pw");
        assert!(!json.contains("payment_pubkey"));
        assert!(!json.contains("payment_keypair"));

        let loaded = decrypt_encrypted_keys(&json, b"pw").unwrap();
        assert_eq!(loaded.public.payment_pubkey, None);
        assert_eq!(loaded.payment_keypair, None);
        assert_eq!(
            loaded.public.hybrid_classical_pk,
            keys.public.hybrid_classical_pk
        );
        assert_eq!(loaded.pq_sk, keys.pq_sk);
    }

    #[test]
    fn encrypted_keystore_aad_omits_absent_optional_public_fields() {
        let mut keys = fixture();
        keys.public.payment_pubkey = None;
        keys.payment_keypair = None;
        let container =
            EncryptedContainer::from_public(&keys, [7; ARGON2_SALT_BYTES], [8; 12], "00".into());
        let aad = String::from_utf8(container.associated_data().unwrap()).unwrap();

        assert!(!aad.contains("payment_pubkey"));
        assert!(!aad.contains("null"));
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
        assert!(json.contains("\"payment_pubkey\""));
        assert!(json.contains("\"payment_keypair\""));
        assert_eq!(KeysFile::from_json(&json).unwrap(), keys);
    }

    #[test]
    fn payment_keypair_encrypted_storage_round_trip() {
        let keys = fixture();
        let json = encrypt_plaintext_keys_with_params(&keys, b"pw", [7; 32], [8; 12]).unwrap();
        assert!(json.contains("\"payment_pubkey\""));
        assert!(!json.contains("\"payment_keypair\""));
        let recovered = decrypt_encrypted_keys(&json, b"pw").unwrap();
        assert_eq!(recovered.payment_keypair, keys.payment_keypair);
        assert_eq!(recovered.public.payment_pubkey, keys.public.payment_pubkey);
    }

    #[test]
    fn add_payment_key_writes_new_file_with_identity_material_unchanged() {
        let dir = test_dir("indra-add-payment-key-new");
        let path = dir.join("keys.json");
        let out = dir.join("keys.retrofit.json");
        let keys = fixture_without_payment();
        let original = encrypt_plaintext_keys_with_params(&keys, b"pw", [7; 32], [8; 12]).unwrap();
        write_keys_secure(path.to_str().unwrap(), &original).unwrap();

        let report = add_payment_key_to_file(&path, b"pw", Some(&out), false, false).unwrap();
        let updated_json = std::fs::read_to_string(&out).unwrap();
        let updated = decrypt_encrypted_keys(&updated_json, b"pw").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert_eq!(report.output_path, out);
        assert_eq!(report.backup_path, None);
        assert!(updated.payment_keypair.is_some());
        assert!(updated.public.payment_pubkey.is_some());
        assert_eq!(
            IdentityMaterialSnapshot::from_keys(&keys),
            IdentityMaterialSnapshot::from_keys(&updated)
        );
        assert!(
            IdentityMaterialSnapshot::comparison_rows(&report.before, &report.after)
                .into_iter()
                .all(|(_, _, _, unchanged)| unchanged)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_payment_key_refuses_existing_payment_key_unless_forced() {
        let dir = test_dir("indra-add-payment-key-force");
        let path = dir.join("keys.json");
        let out = dir.join("forced.json");
        let keys = fixture();
        let original = encrypt_plaintext_keys_with_params(&keys, b"pw", [7; 32], [8; 12]).unwrap();
        write_keys_secure(path.to_str().unwrap(), &original).unwrap();

        assert!(add_payment_key_to_file(&path, b"pw", Some(&out), false, false).is_err());
        let report = add_payment_key_to_file(&path, b"pw", Some(&out), false, true).unwrap();
        let forced =
            decrypt_encrypted_keys(&std::fs::read_to_string(&out).unwrap(), b"pw").unwrap();

        assert_eq!(report.output_path, out);
        assert!(forced.payment_keypair.is_some());
        assert_eq!(
            IdentityMaterialSnapshot::from_keys(&keys),
            IdentityMaterialSnapshot::from_keys(&forced)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_payment_key_round_trip_failure_does_not_write_output() {
        let dir = test_dir("indra-add-payment-key-corrupt");
        let path = dir.join("keys.json");
        let out = dir.join("keys.with-payment.json");
        let keys = fixture_without_payment();
        let original = encrypt_plaintext_keys_with_params(&keys, b"pw", [7; 32], [8; 12]).unwrap();
        write_keys_secure(path.to_str().unwrap(), &original).unwrap();

        let err = add_payment_key_to_file_with_encryptor(
            &path,
            b"pw",
            Some(&out),
            false,
            false,
            corrupt_encryptor,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            KeystoreError::InvalidHex(_) | KeystoreError::Crypto(_)
        ));
        assert!(!out.exists());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_payment_key_replace_creates_backup_before_replacing() {
        let dir = test_dir("indra-add-payment-key-replace");
        let path = dir.join("keys.json");
        let keys = fixture_without_payment();
        let original = encrypt_plaintext_keys_with_params(&keys, b"pw", [7; 32], [8; 12]).unwrap();
        write_keys_secure(path.to_str().unwrap(), &original).unwrap();

        let report = add_payment_key_to_file(&path, b"pw", None, true, false).unwrap();
        let backup = report.backup_path.expect("replace creates backup");
        let replaced =
            decrypt_encrypted_keys(&std::fs::read_to_string(&path).unwrap(), b"pw").unwrap();
        let backup_keys =
            decrypt_encrypted_keys(&std::fs::read_to_string(&backup).unwrap(), b"pw").unwrap();

        assert!(backup.exists());
        assert_eq!(backup_keys.payment_keypair, None);
        assert_eq!(backup_keys.public.payment_pubkey, None);
        assert!(replaced.payment_keypair.is_some());
        assert!(replaced.public.payment_pubkey.is_some());
        assert_eq!(
            IdentityMaterialSnapshot::from_keys(&keys),
            IdentityMaterialSnapshot::from_keys(&replaced)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_payment_key_default_output_never_touches_original() {
        let dir = test_dir("indra-add-payment-key-default");
        let path = dir.join("keys.json");
        let default_out = dir.join("keys.with-payment.json");
        let keys = fixture_without_payment();
        let original = encrypt_plaintext_keys_with_params(&keys, b"pw", [7; 32], [8; 12]).unwrap();
        write_keys_secure(path.to_str().unwrap(), &original).unwrap();

        let report = add_payment_key_to_file(&path, b"pw", None, false, false).unwrap();

        assert_eq!(report.output_path, default_out);
        assert!(default_out.exists());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pre_payment_key_plaintext_json_still_loads_with_absent_payment_fields() {
        let keys = fixture();
        let json = keys.to_json();
        let payment_pubkey_line = format!(
            ",\n    \"payment_pubkey\": \"{}\"",
            hex::encode(keys.public.payment_pubkey.as_ref().unwrap().encode())
        );
        let payment_keypair_line = format!(
            ",\n    \"payment_keypair\": \"{}\"",
            hex::encode(keys.payment_keypair.as_ref().unwrap().encode())
        );
        let legacy_json = json
            .replace(&payment_pubkey_line, "")
            .replace(&payment_keypair_line, "");
        let loaded = KeysFile::from_json(&legacy_json).unwrap();
        assert_eq!(loaded.public.payment_pubkey, None);
        assert_eq!(loaded.payment_keypair, None);
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
