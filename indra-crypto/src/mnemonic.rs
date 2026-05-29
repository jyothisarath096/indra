//! BIP-39 mnemonic seed phrase support for INDRA wallets.

extern crate alloc;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use bip39::{Language, Mnemonic, rand::RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{error::CryptoError, sha256};

/// Number of words in INDRA mnemonic (256 bits of entropy = 24 words).
pub const MNEMONIC_WORD_COUNT: usize = 24;

/// All seeds derived from a master seed.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedSeeds {
    /// Master seed (32 bytes). This is what the mnemonic encodes.
    pub master_seed: [u8; 32],
    /// Ed25519 + Dilithium2 hybrid keypair seed.
    pub hybrid_seed: [u8; 32],
    /// VRF keypair seed.
    pub vrf_seed: [u8; 32],
    /// BLS keypair seed (for compatibility).
    pub bls_seed: [u8; 32],
}

/// Generate a new random 24-word BIP-39 mnemonic phrase.
pub fn generate_mnemonic() -> String {
    let mut entropy = [0u8; 32];
    bip39::rand::thread_rng().fill_bytes(&mut entropy);
    match Mnemonic::from_entropy_in(Language::English, &entropy) {
        Ok(mnemonic) => mnemonic.to_string(),
        Err(_) => String::new(),
    }
}

/// Convert a BIP-39 mnemonic phrase to a 32-byte master seed.
pub fn mnemonic_to_seed(phrase: &str) -> Result<[u8; 32], CryptoError> {
    let phrase = phrase.trim().to_lowercase();
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, &phrase)
        .map_err(|_| CryptoError::InvalidMnemonic)?;
    let bip39_seed = mnemonic.to_seed_normalized("");
    let mut master_seed = [0u8; 32];
    master_seed.copy_from_slice(&bip39_seed[..32]);
    Ok(master_seed)
}

/// Derive all INDRA keypair seeds from a 32-byte master seed.
pub fn derive_all_seeds(master_seed: &[u8; 32]) -> DerivedSeeds {
    let hybrid_seed = derive_seed(master_seed, b"indra-hybrid-v1");
    let vrf_seed = derive_seed(master_seed, b"indra-vrf-v1");
    let bls_seed = derive_seed(master_seed, b"indra-bls-v1");
    DerivedSeeds {
        master_seed: *master_seed,
        hybrid_seed,
        vrf_seed,
        bls_seed,
    }
}

fn derive_seed(master_seed: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(master_seed.len() + domain.len());
    input.extend_from_slice(master_seed);
    input.extend_from_slice(domain);
    sha256(&input)
}

/// Validate a mnemonic phrase without deriving keys.
pub fn validate_mnemonic(phrase: &str) -> bool {
    let phrase = phrase.trim().to_lowercase();
    Mnemonic::parse_in_normalized(Language::English, &phrase).is_ok()
}

/// Split a mnemonic into individual words.
pub fn mnemonic_words(phrase: &str) -> Vec<String> {
    phrase.split_whitespace().map(ToString::to_string).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_24_words() {
        let phrase = generate_mnemonic();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), MNEMONIC_WORD_COUNT);
    }

    #[test]
    fn mnemonic_round_trips_to_seed() {
        let phrase = generate_mnemonic();
        let seed1 = mnemonic_to_seed(&phrase).unwrap();
        let seed2 = mnemonic_to_seed(&phrase).unwrap();
        assert_eq!(seed1, seed2);
    }

    #[test]
    fn same_phrase_gives_same_seeds() {
        let phrase = generate_mnemonic();
        let seed = mnemonic_to_seed(&phrase).unwrap();
        let derived1 = derive_all_seeds(&seed);
        let derived2 = derive_all_seeds(&seed);
        assert_eq!(derived1.hybrid_seed, derived2.hybrid_seed);
        assert_eq!(derived1.vrf_seed, derived2.vrf_seed);
        assert_eq!(derived1.bls_seed, derived2.bls_seed);
    }

    #[test]
    fn different_phrases_give_different_seeds() {
        let phrase1 = generate_mnemonic();
        let phrase2 = generate_mnemonic();
        let seed1 = mnemonic_to_seed(&phrase1).unwrap();
        let seed2 = mnemonic_to_seed(&phrase2).unwrap();
        assert_ne!(seed1, seed2);
    }

    #[test]
    fn invalid_mnemonic_returns_error() {
        assert!(mnemonic_to_seed("not valid words").is_err());
        assert!(mnemonic_to_seed("").is_err());
        assert!(mnemonic_to_seed("word word word").is_err());
    }

    #[test]
    fn validate_mnemonic_works() {
        let phrase = generate_mnemonic();
        assert!(validate_mnemonic(&phrase));
        assert!(!validate_mnemonic("invalid phrase"));
    }

    #[test]
    fn case_insensitive() {
        let phrase = generate_mnemonic();
        let upper = phrase.to_uppercase();
        let seed1 = mnemonic_to_seed(&phrase).unwrap();
        let seed2 = mnemonic_to_seed(&upper).unwrap();
        assert_eq!(seed1, seed2);
    }

    #[test]
    fn hybrid_and_vrf_seeds_are_different() {
        let phrase = generate_mnemonic();
        let seed = mnemonic_to_seed(&phrase).unwrap();
        let derived = derive_all_seeds(&seed);
        assert_ne!(derived.hybrid_seed, derived.vrf_seed);
        assert_ne!(derived.hybrid_seed, derived.bls_seed);
        assert_ne!(derived.vrf_seed, derived.bls_seed);
    }

    #[test]
    fn known_vector() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let seed = mnemonic_to_seed(phrase).unwrap();
        let derived = derive_all_seeds(&seed);
        assert_eq!(&derived.hybrid_seed[0..4], &[143u8, 153u8, 67u8, 141u8]);
    }
}
