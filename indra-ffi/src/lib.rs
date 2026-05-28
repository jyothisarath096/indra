//! INDRA FFI — thin C bridge for iOS wallet.
//!
//! # Safety contract
//!
//! - All pointer arguments must be valid and non-null unless documented otherwise.
//! - All output buffers must have sufficient capacity.
//! - Functions never panic across the FFI boundary. Panics are caught and
//!   translated to `INDRA_ERR_INTERNAL`.
//! - Memory allocated by Rust (`tx_bytes`, `spent_indices`) must be freed by
//!   the caller using `indra_free_bytes()` / `indra_free_usize()`.
//! - This library is not synchronised at the FFI layer. Swift callers should
//!   serialise access if they share mutable wallet state.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use std::{ffi::c_char, panic::catch_unwind};

use indra_bulletproofs::RANGE_PROOF_BYTES;
use indra_crypto::sha256;

pub mod errors;
pub mod keygen;
pub mod tx;
pub mod wallet;

use errors::{error_string, IndraError};

const CLASSICAL_PK_BYTES: usize = 32;
const CLASSICAL_SK_BYTES: usize = 32;
const PQ_PK_BYTES: usize = 1312;
const PQ_SK_BYTES: usize = 2560;
const BYTES32_LEN: usize = 32;

/// FFI keypair bundle returned to Swift.
#[repr(C)]
pub struct IndraKeyPair {
    pub validator_id: [u8; BYTES32_LEN],
    pub classical_pk: [u8; CLASSICAL_PK_BYTES],
    pub pq_pk: [u8; PQ_PK_BYTES],
    pub classical_seed: [u8; CLASSICAL_SK_BYTES],
    pub pq_sk: [u8; PQ_SK_BYTES],
}

impl IndraKeyPair {
    /// Zero-initialised value for tests and error paths.
    pub const fn zeroed() -> Self {
        Self {
            validator_id: [0u8; BYTES32_LEN],
            classical_pk: [0u8; CLASSICAL_PK_BYTES],
            pq_pk: [0u8; PQ_PK_BYTES],
            classical_seed: [0u8; CLASSICAL_SK_BYTES],
            pq_sk: [0u8; PQ_SK_BYTES],
        }
    }
}

/// FFI wallet UTXO entry.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IndraUtxoEntry {
    pub utxo_id: [u8; BYTES32_LEN],
    pub value_spark: u64,
    pub blinding: [u8; BYTES32_LEN],
    pub created_height: u64,
    pub tx_index: u32,
    pub out_index: u32,
    pub spent: u8,
}

/// FFI transaction builder input parameters.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IndraTxParams {
    pub recipient_classical_pk: *const u8,
    pub amount_spark: u64,
    pub fee_spark: u64,
    pub utxos: *const IndraUtxoEntry,
    pub utxo_count: usize,
    pub sender_classical_seed: *const u8,
    pub sender_pq_sk: *const u8,
    pub sender_pq_pk: *const u8,
}

/// FFI transaction builder output.
#[repr(C)]
pub struct IndraTxResult {
    pub tx_id: [u8; BYTES32_LEN],
    pub tx_bytes: *mut u8,
    pub tx_bytes_len: usize,
    pub change_spark: u64,
    pub change_blinding: [u8; BYTES32_LEN],
    pub spent_indices: *mut usize,
    pub spent_count: usize,
}

impl IndraTxResult {
    /// Zero-initialised value for tests and error paths.
    pub const fn zeroed() -> Self {
        Self {
            tx_id: [0u8; BYTES32_LEN],
            tx_bytes: std::ptr::null_mut(),
            tx_bytes_len: 0,
            change_spark: 0,
            change_blinding: [0u8; BYTES32_LEN],
            spent_indices: std::ptr::null_mut(),
            spent_count: 0,
        }
    }
}

/// Generate a new INDRA keypair from one 32-byte wallet seed.
#[no_mangle]
pub unsafe extern "C" fn indra_keygen(seed: *const u8, out: *mut IndraKeyPair) -> i32 {
    if seed.is_null() || out.is_null() {
        return IndraError::NullPointer.code();
    }

    *out = IndraKeyPair::zeroed();

    match catch_unwind(|| {
        let mut seed_bytes = [0u8; CLASSICAL_SK_BYTES];
        seed_bytes.copy_from_slice(std::slice::from_raw_parts(seed, CLASSICAL_SK_BYTES));
        keygen::generate(seed_bytes)
    }) {
        Ok(Ok(keypair)) => {
            *out = keypair;
            IndraError::Ok.code()
        }
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Derive the validator id from a classical public key.
#[no_mangle]
pub unsafe extern "C" fn indra_validator_id(classical_pk: *const u8, out_id: *mut u8) -> i32 {
    if classical_pk.is_null() || out_id.is_null() {
        return IndraError::NullPointer.code();
    }

    match catch_unwind(|| {
        let classical_pk_bytes = std::slice::from_raw_parts(classical_pk, CLASSICAL_PK_BYTES);
        let validator_id = sha256(classical_pk_bytes);
        std::slice::from_raw_parts_mut(out_id, BYTES32_LEN).copy_from_slice(&validator_id);
    }) {
        Ok(()) => IndraError::Ok.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Build and sign a transaction for the iOS wallet.
#[no_mangle]
pub unsafe extern "C" fn indra_build_tx(params: *const IndraTxParams, out: *mut IndraTxResult) -> i32 {
    if params.is_null() || out.is_null() {
        return IndraError::NullPointer.code();
    }

    *out = IndraTxResult::zeroed();

    match catch_unwind(|| {
        let params_ref = &*params;
        if params_ref.recipient_classical_pk.is_null()
            || params_ref.sender_classical_seed.is_null()
            || params_ref.sender_pq_sk.is_null()
            || params_ref.sender_pq_pk.is_null()
            || (params_ref.utxo_count > 0 && params_ref.utxos.is_null())
        {
            return Err(IndraError::NullPointer);
        }

        let mut recipient_classical_pk = [0u8; CLASSICAL_PK_BYTES];
        recipient_classical_pk.copy_from_slice(
            std::slice::from_raw_parts(params_ref.recipient_classical_pk, CLASSICAL_PK_BYTES),
        );

        let mut sender_classical_seed = [0u8; CLASSICAL_SK_BYTES];
        sender_classical_seed.copy_from_slice(
            std::slice::from_raw_parts(params_ref.sender_classical_seed, CLASSICAL_SK_BYTES),
        );

        let sender_pq_sk = std::slice::from_raw_parts(params_ref.sender_pq_sk, PQ_SK_BYTES);
        let sender_pq_pk = std::slice::from_raw_parts(params_ref.sender_pq_pk, PQ_PK_BYTES);
        let utxos = if params_ref.utxo_count == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(params_ref.utxos, params_ref.utxo_count)
        };

        let wallet_context = wallet::build_wallet_context(sender_classical_seed, sender_pq_pk, utxos)?;
        let built = tx::build(
            recipient_classical_pk,
            params_ref.amount_spark,
            params_ref.fee_spark,
            sender_classical_seed,
            sender_pq_sk,
            wallet_context,
        )?;

        let tx_id = built.tx_id;
        let change_spark = built.change_spark;
        let change_blinding = built.change_blinding;

        let tx_bytes_len = built.tx_bytes.len();
        let tx_bytes_ptr = Box::into_raw(built.tx_bytes) as *mut u8;
        let spent_count = built.spent_indices.len();
        let spent_ptr = Box::into_raw(built.spent_indices) as *mut usize;

        *out = IndraTxResult {
            tx_id,
            tx_bytes: tx_bytes_ptr,
            tx_bytes_len,
            change_spark,
            change_blinding,
            spent_indices: spent_ptr,
            spent_count,
        };

        Ok::<(), IndraError>(())
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Hex-encode raw transaction bytes into a caller-provided buffer.
#[no_mangle]
pub unsafe extern "C" fn indra_tx_to_hex(
    tx_bytes: *const u8,
    tx_bytes_len: usize,
    out_hex: *mut c_char,
    out_hex_len: usize,
) -> i32 {
    if tx_bytes.is_null() || out_hex.is_null() {
        return IndraError::NullPointer.code();
    }

    match catch_unwind(|| {
        let bytes = std::slice::from_raw_parts(tx_bytes, tx_bytes_len);
        let encoded = tx::tx_to_hex(bytes);
        let needed = encoded.len().saturating_add(1);
        if out_hex_len < needed {
            return Err(IndraError::BufferTooSmall);
        }

        let out_bytes = std::slice::from_raw_parts_mut(out_hex.cast::<u8>(), out_hex_len);
        out_bytes[..encoded.len()].copy_from_slice(encoded.as_bytes());
        out_bytes[encoded.len()] = 0;
        Ok(())
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Derive the deterministic genesis blinding factor from a classical public key.
#[no_mangle]
pub unsafe extern "C" fn indra_genesis_utxo_blinding(
    classical_pk: *const u8,
    out_blinding: *mut u8,
) -> i32 {
    if classical_pk.is_null() || out_blinding.is_null() {
        return IndraError::NullPointer.code();
    }

    match catch_unwind(|| {
        let classical_pk_bytes = std::slice::from_raw_parts(classical_pk, CLASSICAL_PK_BYTES);
        let blinding = sha256(&[classical_pk_bytes, b"genesis-utxo-blinding"].concat());
        std::slice::from_raw_parts_mut(out_blinding, BYTES32_LEN).copy_from_slice(&blinding);
    }) {
        Ok(()) => IndraError::Ok.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Verify a Bulletproof range proof against a Pedersen commitment.
#[no_mangle]
pub unsafe extern "C" fn indra_verify_range_proof(
    commitment_bytes: *const u8,
    proof_bytes: *const u8,
    proof_len: usize,
) -> i32 {
    if commitment_bytes.is_null() || proof_bytes.is_null() {
        return IndraError::NullPointer.code();
    }
    if proof_len != RANGE_PROOF_BYTES {
        return IndraError::RangeProofFailed.code();
    }

    match catch_unwind(|| {
        let mut commitment = [0u8; BYTES32_LEN];
        commitment.copy_from_slice(std::slice::from_raw_parts(commitment_bytes, BYTES32_LEN));
        let proof = std::slice::from_raw_parts(proof_bytes, proof_len);
        indra_crypto::verify_range(&commitment, proof).map_err(|_| IndraError::RangeProofFailed)
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Free a byte buffer allocated by Rust.
#[no_mangle]
pub unsafe extern "C" fn indra_free_bytes(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let slice_ptr = std::ptr::slice_from_raw_parts_mut(ptr, len);
    drop(Box::from_raw(slice_ptr));
}

/// Free a `usize` array allocated by Rust.
#[no_mangle]
pub unsafe extern "C" fn indra_free_usize(ptr: *mut usize, len: usize) {
    if ptr.is_null() {
        return;
    }
    let slice_ptr = std::ptr::slice_from_raw_parts_mut(ptr, len);
    drop(Box::from_raw(slice_ptr));
}

/// Return a static human-readable string for an FFI error code.
#[no_mangle]
pub extern "C" fn indra_error_string(error_code: i32) -> *const c_char {
    error_string(error_code).as_ptr().cast::<c_char>()
}

#[cfg(test)]
mod tests {
    use super::*;

    const INDRA_OK: i32 = IndraError::Ok as i32;
    const INDRA_ERR_NULL_POINTER: i32 = IndraError::NullPointer as i32;

    #[test]
    fn keygen_produces_valid_output() {
        let seed = [0x42u8; 32];
        let mut out = IndraKeyPair::zeroed();
        let result = unsafe { indra_keygen(seed.as_ptr(), &mut out) };
        assert_eq!(result, INDRA_OK);
        assert_ne!(out.validator_id, [0u8; 32]);
        assert_ne!(out.classical_pk, [0u8; 32]);
        assert_ne!(out.pq_pk, [0u8; 1312]);
    }

    #[test]
    fn keygen_is_deterministic() {
        let seed = [0x01u8; 32];
        let mut out1 = IndraKeyPair::zeroed();
        let mut out2 = IndraKeyPair::zeroed();
        unsafe {
            indra_keygen(seed.as_ptr(), &mut out1);
            indra_keygen(seed.as_ptr(), &mut out2);
        }
        assert_eq!(out1.validator_id, out2.validator_id);
        assert_eq!(out1.classical_pk, out2.classical_pk);
    }

    #[test]
    fn keygen_null_seed_returns_error() {
        let mut out = IndraKeyPair::zeroed();
        let result = unsafe { indra_keygen(std::ptr::null(), &mut out) };
        assert_eq!(result, INDRA_ERR_NULL_POINTER);
    }

    #[test]
    fn keygen_null_out_returns_error() {
        let seed = [0x42u8; 32];
        let result = unsafe { indra_keygen(seed.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(result, INDRA_ERR_NULL_POINTER);
    }

    #[test]
    fn build_tx_self_send_succeeds() {
        let seed = [0x42u8; 32];
        let mut keys = IndraKeyPair::zeroed();
        unsafe {
            indra_keygen(seed.as_ptr(), &mut keys);
        }

        let utxo = IndraUtxoEntry {
            utxo_id: [0xAAu8; 32],
            value_spark: 10_000_000,
            blinding: [0x01u8; 32],
            created_height: 0,
            tx_index: 0,
            out_index: 0,
            spent: 0,
        };

        let params = IndraTxParams {
            recipient_classical_pk: keys.classical_pk.as_ptr(),
            amount_spark: 1_000_000,
            fee_spark: 50_000,
            utxos: &utxo,
            utxo_count: 1,
            sender_classical_seed: keys.classical_seed.as_ptr(),
            sender_pq_sk: keys.pq_sk.as_ptr(),
            sender_pq_pk: keys.pq_pk.as_ptr(),
        };

        let mut result = IndraTxResult::zeroed();
        let code = unsafe { indra_build_tx(&params, &mut result) };
        assert_eq!(code, INDRA_OK);
        assert!(!result.tx_bytes.is_null());
        assert!(result.tx_bytes_len > 0);
        assert_ne!(result.tx_id, [0u8; 32]);

        unsafe {
            indra_free_bytes(result.tx_bytes, result.tx_bytes_len);
            indra_free_usize(result.spent_indices, result.spent_count);
        }
    }

    #[test]
    fn free_null_is_safe() {
        unsafe {
            indra_free_bytes(std::ptr::null_mut(), 0);
            indra_free_usize(std::ptr::null_mut(), 0);
        }
    }

    #[test]
    fn tx_to_hex_encodes_correctly() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut hex_buf = [0u8; 16];
        let result = unsafe {
            indra_tx_to_hex(
                bytes.as_ptr(),
                bytes.len(),
                hex_buf.as_mut_ptr().cast::<c_char>(),
                hex_buf.len(),
            )
        };
        assert_eq!(result, INDRA_OK);
        assert_eq!(&hex_buf[..8], b"deadbeef");
    }
}
