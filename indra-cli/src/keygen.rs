//! Validator keypair generation.
//!
//! Generates all three keypairs a validator needs:
//!   1. Hybrid (Ed25519 + Dilithium2) — for transaction and vote signatures
//!   2. Legacy BLS12-381 metadata — retained for backward compatibility only
//!   3. VRF — for proposer election
//!
//! ## Security
//!
//! Wallet recovery uses a 24-word BIP-39 mnemonic that encodes a 32-byte
//! master seed. INDRA derives all signing seeds deterministically from that
//! master seed using domain-separated SHA-256.
//! Never share anything from the `private` section of the keys file.
//!
//! ## Output format (keys.json)
//!
//! ```json
//! {
//!   "validator_id": "<hex>",
//!   "public": {
//!     "hybrid_classical_pk": "<hex>",
//!     "hybrid_pq_pk": "<hex>",
//!     "bls_pk": "<hex>",
//!     "vrf_pk": "<hex>"
//!   },
//!   "private": {
//!     "hybrid_seed": "<hex>",
//!     "bls_seed": "<hex>",
//!     "vrf_seed": "<hex>"
//!   }
//! }
//! ```

use indra_crypto::{
    bls::BlsKeypair,
    derive_all_seeds,
    generate_mnemonic,
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    mnemonic_to_seed,
    sha256,
    VrfKeypair,
};

use crate::error::{CliError, CliResult};

/// All public keys for a validator.
#[derive(Debug, Clone)]
pub struct ValidatorKeys {
    /// 32-byte validator identity (SHA-256 of hybrid classical public key).
    pub validator_id: [u8; 32],
    /// Ed25519 public key (32 bytes).
    pub hybrid_classical_pk: [u8; 32],
    /// Dilithium2 public key bytes.
    pub hybrid_pq_pk: Vec<u8>,
    /// BLS12-381 public key (48 bytes).
    pub bls_pk: [u8; 48],
    /// VRF public key (32 bytes).
    pub vrf_pk: [u8; 32],
}

/// A complete keys file including private seeds.
#[derive(Debug, Clone)]
pub struct KeysFile {
    /// Validator display name chosen at key generation.
    pub name: String,
    /// All public keys.
    pub public: ValidatorKeys,
    /// Hybrid keypair seed (keep secret).
    pub hybrid_seed: [u8; 32],
    /// BLS keypair seed (keep secret).
    pub bls_seed: [u8; 32],
    /// VRF keypair seed (keep secret).
    pub vrf_seed: [u8; 32],
    /// Dilithium2 secret key bytes (keep secret).
    pub pq_sk: Vec<u8>,
}

impl KeysFile {
    /// Serialise to a JSON string.
    pub fn to_json(&self) -> String {
        let v = &self.public;
        format!(
            r#"{{
  "name": "{name}",
  "validator_id": "{validator_id}",
  "mnemonic_hint": "Back up your 24-word BIP-39 recovery phrase separately. It is never stored in this file.",
  "public": {{
    "hybrid_classical_pk": "{classical}",
    "hybrid_pq_pk": "{pq}",
    "bls_pk": "{bls}",
    "vrf_pk": "{vrf}"
  }},
  "private": {{
    "hybrid_seed": "{h_seed}",
    "bls_seed": "{b_seed}",
    "vrf_seed": "{v_seed}",
    "pq_sk": "{pq_sk}",
    "WARNING": "Keep private seeds secret. Never share this section."
  }}
}}"#,
            name         = self.name,
            validator_id = hex::encode(v.validator_id),
            classical    = hex::encode(v.hybrid_classical_pk),
            pq           = hex::encode(&v.hybrid_pq_pk),
            bls          = hex::encode(v.bls_pk),
            vrf          = hex::encode(v.vrf_pk),
            h_seed       = hex::encode(self.hybrid_seed),
            b_seed       = hex::encode(self.bls_seed),
            v_seed       = hex::encode(self.vrf_seed),
            pq_sk        = hex::encode(&self.pq_sk),
        )
    }

    /// Parse a `keys.json` string produced by `indra-keygen`.
    pub fn from_json(json: &str) -> CliResult<Self> {
        let public = extract_object(json, "public")?;
        let private = extract_object(json, "private")?;

        let name = extract_string(json, "name").unwrap_or_default();
        let validator_id = extract_hex32(json, "validator_id")?;
        let hybrid_classical_pk = extract_hex32(public, "hybrid_classical_pk")?;
        let hybrid_pq_pk = extract_hex(public, "hybrid_pq_pk")?;
        let bls_pk = extract_hex_fixed::<48>(public, "bls_pk")?;
        let vrf_pk = extract_hex32(public, "vrf_pk")?;
        let hybrid_seed = extract_hex32(private, "hybrid_seed")?;
        let bls_seed = extract_hex32(private, "bls_seed")?;
        let vrf_seed = extract_hex32(private, "vrf_seed")?;
        let pq_sk = extract_hex(private, "pq_sk")?;

        Ok(Self {
            name,
            public: ValidatorKeys {
                validator_id,
                hybrid_classical_pk,
                hybrid_pq_pk,
                bls_pk,
                vrf_pk,
            },
            hybrid_seed,
            bls_seed,
            vrf_seed,
            pq_sk,
        })
    }

    /// Load and parse a `keys.json` file from disk.
    pub fn load(path: &str) -> CliResult<Self> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| CliError::Io(format!("{}: {}", path, e)))?;
        Self::from_json(&json)
    }
}

fn extract_object<'a>(json: &'a str, field: &str) -> CliResult<&'a str> {
    let key = format!("\"{}\":", field);
    let pos = json.find(&key)
        .ok_or_else(|| CliError::Parse(format!("missing object '{}'", field)))?;
    let after = json[pos + key.len()..].trim_start();
    if !after.starts_with('{') {
        return Err(CliError::Parse(format!("field '{}' is not an object", field)));
    }

    let mut depth = 0usize;
    for (idx, ch) in after.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Ok(&after[..=idx]);
                }
            }
            _ => {}
        }
    }

    Err(CliError::Parse(format!("unterminated object '{}'", field)))
}

fn extract_string(json: &str, field: &str) -> Option<String> {
    let key = format!("\"{}\":", field);
    let pos = json.find(&key)?;
    let after = json[pos + key.len()..].trim_start();
    let after = after.strip_prefix('"')?;
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

fn extract_hex(json: &str, field: &str) -> CliResult<Vec<u8>> {
    let value = extract_string(json, field)
        .ok_or_else(|| CliError::Parse(format!("missing field '{}'", field)))?;
    hex::decode(&value)
        .map_err(|e| CliError::InvalidHex(format!("{}: {}", field, e)))
}

fn extract_hex32(json: &str, field: &str) -> CliResult<[u8; 32]> {
    extract_hex_fixed::<32>(json, field)
}

fn extract_hex_fixed<const N: usize>(json: &str, field: &str) -> CliResult<[u8; N]> {
    let bytes = extract_hex(json, field)?;
    if bytes.len() != N {
        return Err(CliError::Parse(format!(
            "field '{}' must be {} bytes, got {}",
            field,
            N,
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Generate a complete set of validator keypairs from three seeds.
pub fn generate_keypairs(
    name: String,
    hybrid_seed: [u8; 32],
    bls_seed: [u8; 32],
    vrf_seed: [u8; 32],
) -> CliResult<KeysFile> {
    let classical = ClassicalKeypair::from_seed(&hybrid_seed);
    let pq = PqKeypair::from_seed(&hybrid_seed)
        .map_err(|e| CliError::Crypto(e.to_string()))?;
    let pq_sk_bytes = pq.secret_key_bytes();
    let hybrid = HybridKeypair::new(classical, pq);
    let pk = hybrid.public_key();

    let bls = BlsKeypair::from_seed(&bls_seed)
        .map_err(|e| CliError::Crypto(e.to_string()))?;

    let vrf = VrfKeypair::from_seed(&vrf_seed);

    let validator_id = sha256(&pk.classical.0);
    let bls_pk_bytes = bls.public_key().0;
    let vrf_pk_bytes = vrf.public_key();

    let pq_sk = pq_sk_bytes;

    Ok(KeysFile {
        name,
        public: ValidatorKeys {
            validator_id,
            hybrid_classical_pk: pk.classical.0,
            hybrid_pq_pk:        pk.pq.0,
            bls_pk:              bls_pk_bytes,
            vrf_pk:              vrf_pk_bytes,
        },
        hybrid_seed,
        bls_seed,
        vrf_seed,
        pq_sk,
    })
}

/// Generate keypairs with random-looking seeds derived from a passphrase.
///
/// This is NOT cryptographically secure — use proper random seeds in production.
/// This is for testnet convenience only.
pub fn generate_from_passphrase(passphrase: &str, name: String) -> CliResult<KeysFile> {
    use indra_crypto::hash::domain_hash;
    let hybrid_seed = domain_hash(b"INDRA-KEYGEN-HYBRID-v1", passphrase.as_bytes());
    let bls_seed    = domain_hash(b"INDRA-KEYGEN-BLS-v1",    passphrase.as_bytes());
    let vrf_seed    = domain_hash(b"INDRA-KEYGEN-VRF-v1",    passphrase.as_bytes());
    generate_keypairs(name, hybrid_seed, bls_seed, vrf_seed)
}

/// Generate a complete validator keypair set from a new mnemonic.
pub fn generate_from_new_mnemonic(name: String) -> CliResult<(String, KeysFile)> {
    let phrase = generate_mnemonic();
    let master_seed = mnemonic_to_seed(&phrase)
        .map_err(|e| CliError::Crypto(e.to_string()))?;
    let derived = derive_all_seeds(&master_seed);
    let keys = generate_keypairs(name, derived.hybrid_seed, derived.bls_seed, derived.vrf_seed)?;
    Ok((phrase, keys))
}

/// Recover a validator keypair set from an existing mnemonic.
pub fn recover_from_mnemonic(phrase: &str, name: String) -> CliResult<KeysFile> {
    let master_seed = mnemonic_to_seed(phrase)
        .map_err(|e| CliError::Crypto(e.to_string()))?;
    let derived = derive_all_seeds(&master_seed);
    generate_keypairs(name, derived.hybrid_seed, derived.bls_seed, derived.vrf_seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_produces_all_fields() {
        let keys = generate_keypairs(
            "validator".to_string(),
            [0x01u8; 32],
            [0x02u8; 32],
            [0x03u8; 32],
        )
        .unwrap();
        assert_eq!(keys.name, "validator");
        assert_eq!(keys.public.hybrid_classical_pk.len(), 32);
        assert_eq!(keys.public.bls_pk.len(), 48);
        assert_eq!(keys.public.vrf_pk.len(), 32);
        assert!(!keys.public.hybrid_pq_pk.is_empty());
    }

    #[test]
    fn keygen_is_deterministic() {
        let k1 = generate_keypairs(
            "validator".to_string(),
            [0x01u8; 32],
            [0x02u8; 32],
            [0x03u8; 32],
        )
        .unwrap();
        let k2 = generate_keypairs(
            "validator".to_string(),
            [0x01u8; 32],
            [0x02u8; 32],
            [0x03u8; 32],
        )
        .unwrap();
        assert_eq!(k1.public.validator_id, k2.public.validator_id);
        assert_eq!(k1.name, k2.name);
        assert_eq!(k1.public.hybrid_classical_pk, k2.public.hybrid_classical_pk);
        assert_eq!(k1.public.hybrid_pq_pk, k2.public.hybrid_pq_pk);
        assert_eq!(k1.public.bls_pk, k2.public.bls_pk);
        assert_eq!(k1.public.vrf_pk, k2.public.vrf_pk);
        assert_eq!(k1.pq_sk, k2.pq_sk);
    }

    #[test]
    fn different_seeds_give_different_keys() {
        let k1 = generate_keypairs(
            "alice".to_string(),
            [0x01u8; 32],
            [0x02u8; 32],
            [0x03u8; 32],
        )
        .unwrap();
        let k2 = generate_keypairs(
            "bob".to_string(),
            [0xFFu8; 32],
            [0xFEu8; 32],
            [0xFDu8; 32],
        )
        .unwrap();
        assert_ne!(k1.public.validator_id, k2.public.validator_id);
    }

    #[test]
    fn passphrase_keygen_is_deterministic() {
        let k1 = generate_from_passphrase("testnet-validator-1", "validator".to_string()).unwrap();
        let k2 = generate_from_passphrase("testnet-validator-1", "validator".to_string()).unwrap();
        assert_eq!(k1.public.validator_id, k2.public.validator_id);
        assert_eq!(k1.name, "validator");
    }

    #[test]
    fn different_passphrases_give_different_keys() {
        let k1 = generate_from_passphrase("alice", "alice".to_string()).unwrap();
        let k2 = generate_from_passphrase("bob", "bob".to_string()).unwrap();
        assert_ne!(k1.public.validator_id, k2.public.validator_id);
    }

    #[test]
    fn keys_json_contains_required_fields() {
        let keys = generate_keypairs(
            "validator".to_string(),
            [0x01u8; 32],
            [0x02u8; 32],
            [0x03u8; 32],
        )
        .unwrap();
        let json = keys.to_json();
        assert!(json.contains("\"name\": \"validator\""));
        assert!(json.contains("validator_id"));
        assert!(json.contains("mnemonic_hint"));
        assert!(json.contains("hybrid_classical_pk"));
        assert!(json.contains("bls_pk"));
        assert!(json.contains("vrf_pk"));
        assert!(json.contains("WARNING"));
    }

    #[test]
    fn keys_json_round_trips_with_nested_public_private_sections() {
        let keys = generate_keypairs(
            "validator".to_string(),
            [0x01u8; 32],
            [0x02u8; 32],
            [0x03u8; 32],
        )
        .unwrap();
        let json = keys.to_json();
        let parsed = KeysFile::from_json(&json).unwrap();
        assert_eq!(parsed.name, keys.name);
        assert_eq!(parsed.public.validator_id, keys.public.validator_id);
        assert_eq!(parsed.public.hybrid_classical_pk, keys.public.hybrid_classical_pk);
        assert_eq!(parsed.public.hybrid_pq_pk, keys.public.hybrid_pq_pk);
        assert_eq!(parsed.hybrid_seed, keys.hybrid_seed);
        assert_eq!(parsed.bls_seed, keys.bls_seed);
        assert_eq!(parsed.vrf_seed, keys.vrf_seed);
        assert_eq!(parsed.pq_sk, keys.pq_sk);
    }

    #[test]
    fn validator_id_is_sha256_of_classical_pk() {
        let keys = generate_keypairs(
            "validator".to_string(),
            [0x42u8; 32],
            [0x42u8; 32],
            [0x42u8; 32],
        )
        .unwrap();
        let expected = indra_crypto::sha256(&keys.public.hybrid_classical_pk);
        assert_eq!(keys.public.validator_id, expected);
    }

    #[test]
    fn mnemonic_recovery_is_deterministic() {
        let (phrase, keys1) = generate_from_new_mnemonic("validator".to_string()).unwrap();
        let keys2 = recover_from_mnemonic(&phrase, "validator".to_string()).unwrap();
        assert_eq!(keys1.name, keys2.name);
        assert_eq!(keys1.public.validator_id, keys2.public.validator_id);
        assert_eq!(keys1.public.hybrid_classical_pk, keys2.public.hybrid_classical_pk);
        assert_eq!(keys1.public.hybrid_pq_pk, keys2.public.hybrid_pq_pk);
        assert_eq!(keys1.pq_sk, keys2.pq_sk);
    }
}
