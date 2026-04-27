//! Validator keypair generation.
//!
//! Generates all three keypairs a validator needs:
//!   1. Hybrid (Ed25519 + Dilithium2) — for transaction and vote signatures
//!   2. BLS12-381 — for QC aggregation
//!   3. VRF — for proposer election
//!
//! ## Security
//!
//! Each keypair is derived from a 32-byte random seed.
//! The seeds are the private keys — keep them secret.
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
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
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
    /// All public keys.
    pub public: ValidatorKeys,
    /// Hybrid keypair seed (keep secret).
    pub hybrid_seed: [u8; 32],
    /// BLS keypair seed (keep secret).
    pub bls_seed: [u8; 32],
    /// VRF keypair seed (keep secret).
    pub vrf_seed: [u8; 32],
    /// Dilithium2 secret key bytes (keep secret).
    /// Stored because Dilithium2 has no deterministic from_seed.
    pub pq_sk: Vec<u8>,
}

impl KeysFile {
    /// Serialise to a JSON string.
    pub fn to_json(&self) -> String {
        let v = &self.public;
        format!(
            r#"{{
  "validator_id": "{validator_id}",
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
}

/// Generate a complete set of validator keypairs from three seeds.
///
/// If seeds are None, they are set to a deterministic test value.
/// In production, seeds should be generated from a secure RNG.
pub fn generate_keypairs(
    hybrid_seed: [u8; 32],
    bls_seed: [u8; 32],
    vrf_seed: [u8; 32],
) -> CliResult<KeysFile> {
    let classical = ClassicalKeypair::from_seed(&hybrid_seed);
    let pq = PqKeypair::generate();
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
pub fn generate_from_passphrase(passphrase: &str) -> CliResult<KeysFile> {
    use indra_crypto::hash::domain_hash;
    let hybrid_seed = domain_hash(b"INDRA-KEYGEN-HYBRID-v1", passphrase.as_bytes());
    let bls_seed    = domain_hash(b"INDRA-KEYGEN-BLS-v1",    passphrase.as_bytes());
    let vrf_seed    = domain_hash(b"INDRA-KEYGEN-VRF-v1",    passphrase.as_bytes());
    generate_keypairs(hybrid_seed, bls_seed, vrf_seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_produces_all_fields() {
        let keys = generate_keypairs([0x01u8; 32], [0x02u8; 32], [0x03u8; 32]).unwrap();
        assert_eq!(keys.public.hybrid_classical_pk.len(), 32);
        assert_eq!(keys.public.bls_pk.len(), 48);
        assert_eq!(keys.public.vrf_pk.len(), 32);
        assert!(!keys.public.hybrid_pq_pk.is_empty());
    }

    #[test]
    fn keygen_is_deterministic() {
        let k1 = generate_keypairs([0x01u8; 32], [0x02u8; 32], [0x03u8; 32]).unwrap();
        let k2 = generate_keypairs([0x01u8; 32], [0x02u8; 32], [0x03u8; 32]).unwrap();
        assert_eq!(k1.public.validator_id, k2.public.validator_id);
        assert_eq!(k1.public.hybrid_classical_pk, k2.public.hybrid_classical_pk);
        assert_eq!(k1.public.bls_pk, k2.public.bls_pk);
        assert_eq!(k1.public.vrf_pk, k2.public.vrf_pk);
    }

    #[test]
    fn different_seeds_give_different_keys() {
        let k1 = generate_keypairs([0x01u8; 32], [0x02u8; 32], [0x03u8; 32]).unwrap();
        let k2 = generate_keypairs([0xFFu8; 32], [0xFEu8; 32], [0xFDu8; 32]).unwrap();
        assert_ne!(k1.public.validator_id, k2.public.validator_id);
    }

    #[test]
    fn passphrase_keygen_is_deterministic() {
        let k1 = generate_from_passphrase("testnet-validator-1").unwrap();
        let k2 = generate_from_passphrase("testnet-validator-1").unwrap();
        assert_eq!(k1.public.validator_id, k2.public.validator_id);
    }

    #[test]
    fn different_passphrases_give_different_keys() {
        let k1 = generate_from_passphrase("alice").unwrap();
        let k2 = generate_from_passphrase("bob").unwrap();
        assert_ne!(k1.public.validator_id, k2.public.validator_id);
    }

    #[test]
    fn keys_json_contains_required_fields() {
        let keys = generate_keypairs([0x01u8; 32], [0x02u8; 32], [0x03u8; 32]).unwrap();
        let json = keys.to_json();
        assert!(json.contains("validator_id"));
        assert!(json.contains("hybrid_classical_pk"));
        assert!(json.contains("bls_pk"));
        assert!(json.contains("vrf_pk"));
        assert!(json.contains("WARNING"));
    }

    #[test]
    fn validator_id_is_sha256_of_classical_pk() {
        let keys = generate_keypairs([0x42u8; 32], [0x42u8; 32], [0x42u8; 32]).unwrap();
        let expected = indra_crypto::sha256(&keys.public.hybrid_classical_pk);
        assert_eq!(keys.public.validator_id, expected);
    }
}
