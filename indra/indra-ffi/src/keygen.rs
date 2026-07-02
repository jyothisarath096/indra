use indra_cli::{generate_keypairs, recover_from_mnemonic};
use indra_crypto::{derive_all_seeds, generate_mnemonic, validate_mnemonic};

use crate::{errors::IndraError, IndraKeyPair};

const PQ_PK_BYTES: usize = 2592;
const PQ_SK_BYTES: usize = 32;

/// Generate an INDRA keypair bundle from one wallet seed.
pub fn generate(mut seed: [u8; 32]) -> Result<IndraKeyPair, IndraError> {
    let derived = derive_all_seeds(&seed);
    seed.fill(0);
    let keys = generate_keypairs(
        String::new(),
        derived.hybrid_seed,
        derived.bls_seed,
        derived.vrf_seed,
    )
    .map_err(|_| IndraError::KeygenFailed)?;
    keys_to_ffi(&keys)
}

/// Generate a new BIP-39 mnemonic phrase.
pub fn new_mnemonic() -> String {
    generate_mnemonic()
}

/// Generate an INDRA keypair bundle from a BIP-39 mnemonic phrase.
pub fn generate_from_mnemonic(phrase: &str) -> Result<IndraKeyPair, IndraError> {
    let keys =
        recover_from_mnemonic(phrase, String::new()).map_err(|_| IndraError::InvalidParam)?;
    keys_to_ffi(&keys)
}

/// Validate a mnemonic phrase.
pub fn is_valid_mnemonic(phrase: &str) -> bool {
    validate_mnemonic(phrase)
}

fn keys_to_ffi(keys: &indra_cli::KeysFile) -> Result<IndraKeyPair, IndraError> {
    if keys.public.hybrid_pq_pk.len() != PQ_PK_BYTES || keys.pq_sk.len() != PQ_SK_BYTES {
        return Err(IndraError::KeygenFailed);
    }

    let mut out = IndraKeyPair::zeroed();
    out.validator_id.copy_from_slice(&keys.public.validator_id);
    out.classical_pk
        .copy_from_slice(&keys.public.hybrid_classical_pk);
    out.pq_pk.copy_from_slice(&keys.public.hybrid_pq_pk);
    out.classical_seed.copy_from_slice(&keys.hybrid_seed);
    out.pq_sk.copy_from_slice(&keys.pq_sk);
    out.bls_seed.copy_from_slice(&keys.bls_seed);
    out.vrf_seed.copy_from_slice(&keys.vrf_seed);
    Ok(out)
}
