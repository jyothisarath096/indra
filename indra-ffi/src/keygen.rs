use indra_cli::generate_keypairs;
use indra_crypto::sha256;

use crate::{errors::IndraError, IndraKeyPair};

const PQ_PK_BYTES: usize = 1312;
const PQ_SK_BYTES: usize = 2560;

/// Generate an INDRA keypair bundle from one wallet seed.
pub fn generate(seed: [u8; 32]) -> Result<IndraKeyPair, IndraError> {
    let bls_seed = sha256(&[seed.as_slice(), b"bls"].concat());
    let vrf_seed = sha256(&[seed.as_slice(), b"vrf"].concat());
    let keys = generate_keypairs(seed, bls_seed, vrf_seed).map_err(|_| IndraError::KeygenFailed)?;

    if keys.public.hybrid_pq_pk.len() != PQ_PK_BYTES || keys.pq_sk.len() != PQ_SK_BYTES {
        return Err(IndraError::KeygenFailed);
    }

    let mut out = IndraKeyPair::zeroed();
    out.validator_id.copy_from_slice(&keys.public.validator_id);
    out.classical_pk.copy_from_slice(&keys.public.hybrid_classical_pk);
    out.pq_pk.copy_from_slice(&keys.public.hybrid_pq_pk);
    out.classical_seed.copy_from_slice(&keys.hybrid_seed);
    out.pq_sk.copy_from_slice(&keys.pq_sk);
    Ok(out)
}
