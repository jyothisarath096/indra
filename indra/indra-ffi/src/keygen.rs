use indra_cli::{generate_from_master_seed, recover_from_mnemonic, KeysFile};
use indra_crypto::{generate_mnemonic, validate_mnemonic};
use zeroize::Zeroizing;

use crate::errors::IndraError;

/// Generate an INDRA keypair bundle from one wallet seed.
pub fn generate_keys(seed: [u8; 32]) -> Result<KeysFile, IndraError> {
    let seed = Zeroizing::new(seed);
    generate_from_master_seed(String::new(), *seed).map_err(|_| IndraError::KeygenFailed)
}

/// Generate a new BIP-39 mnemonic phrase.
pub fn new_mnemonic() -> String {
    generate_mnemonic()
}

/// Generate an INDRA keypair bundle from a BIP-39 mnemonic phrase.
pub fn generate_keys_from_mnemonic(phrase: &str) -> Result<KeysFile, IndraError> {
    recover_from_mnemonic(phrase, String::new()).map_err(|_| IndraError::InvalidParam)
}

/// Validate a mnemonic phrase.
pub fn is_valid_mnemonic(phrase: &str) -> bool {
    validate_mnemonic(phrase)
}
