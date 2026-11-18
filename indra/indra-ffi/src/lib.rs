//! INDRA FFI — thin C bridge for iOS wallet.
//!
//! # Safety contract
//!
//! - All pointer arguments must be valid and non-null unless documented otherwise.
//! - All output buffers must have sufficient capacity.
//! - Functions never panic across the FFI boundary. Panics are caught and
//!   translated to `INDRA_ERR_INTERNAL`.
//! - Transaction results remain Rust-owned behind opaque result handles.
//! - Opaque key handles are process-local. The consuming app must persist
//!   recovery material in platform secure storage, recreate handles on unlock,
//!   and destroy handles on wallet lock/logout.

#![deny(clippy::unwrap_used)]
#![deny(unused_must_use)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable, clippy::todo, clippy::unimplemented)]
#![deny(clippy::indexing_slicing)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

use std::{ffi::c_char, panic::catch_unwind};

use indra_core::types::{
    crypto::HybridPubKey,
    primitives::{Bytes32, VariableBytes},
};

pub mod errors;
pub mod governance;
pub mod handles;
pub mod keygen;
pub mod staking;
pub mod tx;
pub mod wallet;

use errors::{error_string, IndraError};
pub use handles::{
    IndraKeyHandle, IndraResultHandle, IndraSessionHandle, INDRA_KEY_HANDLE_INVALID,
    INDRA_RESULT_HANDLE_INVALID, INDRA_SESSION_HANDLE_INVALID,
};
use zeroize::Zeroizing;

pub const CLASSICAL_PK_BYTES: usize = 32;
pub const CLASSICAL_SK_BYTES: usize = 32;
pub const PQ_PK_BYTES: usize = 2592;
pub const PQ_SK_BYTES: usize = 32;
pub const BYTES32_LEN: usize = 32;
/// Maximum byte length of a hex-encoded staking or governance operation
/// including the null terminator. 32 KB is generous for current ops.
pub const INDRA_OP_HEX_MAX_BYTES: usize = 32768;
/// Length of a validator ID.
pub const INDRA_VALIDATOR_ID_BYTES: usize = 32;
/// Length of a VRF public key.
pub const INDRA_VRF_PK_BYTES: usize = 32;
/// Maximum number of UTXOs allowed in a single transaction.
pub const MAX_UTXO_COUNT: usize = 100;
/// Maximum byte length of a serialized transaction.
pub const MAX_TX_BYTES: usize = 1_048_576;
/// Maximum byte length of a hex-encoded transaction including null terminator.
pub const MAX_TX_HEX_BYTES: usize = MAX_TX_BYTES * 2 + 1;
/// Maximum byte length for a generated mnemonic output buffer.
pub const MAX_MNEMONIC_BYTES: usize = 512;
/// Maximum byte length accepted for an FFI UTF-8 input.
pub const MAX_FFI_STRING_BYTES: usize = 4096;

pub(crate) unsafe fn bounded_utf8(
    ptr: *const c_char,
    len: usize,
    max_len: usize,
) -> Result<String, IndraError> {
    if ptr.is_null() {
        return Err(IndraError::NullPointer);
    }
    if len > max_len {
        return Err(IndraError::InvalidParam);
    }
    let slice = std::slice::from_raw_parts(ptr.cast::<u8>(), len);
    std::str::from_utf8(slice)
        .map(str::to_owned)
        .map_err(|_| IndraError::InvalidParam)
}

/// Public metadata for an opaque key handle. Contains no private key material.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IndraPublicKeyInfo {
    pub validator_id: [u8; BYTES32_LEN],
    pub classical_pk: [u8; CLASSICAL_PK_BYTES],
    pub pq_pk: [u8; PQ_PK_BYTES],
    pub vrf_pk: [u8; INDRA_VRF_PK_BYTES],
}

/// Public metadata for an independently-derived validator cold key.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IndraColdPublicKeyInfo {
    pub classical_pk: [u8; CLASSICAL_PK_BYTES],
    pub pq_pk: [u8; PQ_PK_BYTES],
}

impl IndraColdPublicKeyInfo {
    pub const fn zeroed() -> Self {
        Self {
            classical_pk: [0; CLASSICAL_PK_BYTES],
            pq_pk: [0; PQ_PK_BYTES],
        }
    }
}

impl IndraPublicKeyInfo {
    /// Zero-initialised value for tests and error paths.
    pub const fn zeroed() -> Self {
        Self {
            validator_id: [0u8; BYTES32_LEN],
            classical_pk: [0u8; CLASSICAL_PK_BYTES],
            pq_pk: [0u8; PQ_PK_BYTES],
            vrf_pk: [0u8; INDRA_VRF_PK_BYTES],
        }
    }
}

/// FFI wallet UTXO entry.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IndraUtxoEntry {
    pub utxo_id: [u8; BYTES32_LEN],
    pub value_spark: u64,
    pub created_height: u64,
    pub tx_index: u32,
    pub out_index: u32,
    pub spent: u8,
}

/// FFI transaction builder input using one canonical textual payment address.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IndraTxParams {
    /// UTF-8 bytes of the complete \`indra:\` payment descriptor (not NUL-terminated).
    pub recipient_address: *const u8,
    /// Byte length of \`recipient_address\`.
    pub recipient_address_len: usize,
    pub amount_spark: u64,
    pub fee_spark: u64,
    pub utxos: *const IndraUtxoEntry,
    pub utxo_count: usize,
    pub sender_handle: IndraKeyHandle,
    /// Chain id used for descriptor validation and transaction signing.
    pub chain_id: *const c_char,
    /// Exact readable byte length of `chain_id`; no NUL terminator is consumed.
    pub chain_id_len: usize,
}

/// Copyable metadata for an opaque transaction-result handle.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IndraTxResultMetadata {
    pub tx_id: [u8; BYTES32_LEN],
    pub tx_bytes_len: usize,
    pub change_spark: u64,
    pub spent_count: usize,
}

impl IndraTxResultMetadata {
    /// Zero-initialised value for tests and error paths.
    pub const fn zeroed() -> Self {
        Self {
            tx_id: [0u8; BYTES32_LEN],
            tx_bytes_len: 0,
            change_spark: 0,
            spent_count: 0,
        }
    }
}

#[no_mangle]
/// # Safety
///
/// `out_session` must be null or point to writable storage for one session handle.
pub unsafe extern "C" fn indra_create_session(out_session: *mut IndraSessionHandle) -> i32 {
    if out_session.is_null() {
        return IndraError::NullPointer.code();
    }
    *out_session = INDRA_SESSION_HANDLE_INVALID;
    match catch_unwind(handles::create_session) {
        Ok(Ok(session)) => {
            *out_session = session;
            IndraError::Ok.code()
        }
        Ok(Err(error)) => error.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

#[no_mangle]
pub extern "C" fn indra_destroy_session(session: IndraSessionHandle) -> i32 {
    match catch_unwind(|| handles::destroy_session(session)) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(error)) => error.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Generate a new INDRA key handle from one 32-byte wallet seed.
///
/// Handles are process-local. The consuming app should recreate handles from
/// platform secure storage on unlock and destroy them on lock/logout.
///
/// # Safety
///
/// `seed` must point to at least 32 readable bytes. `out_handle` and
/// `out_public` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn indra_keygen_handle(
    session: IndraSessionHandle,
    seed: *const u8,
    out_handle: *mut IndraKeyHandle,
    out_public: *mut IndraPublicKeyInfo,
) -> i32 {
    if seed.is_null() || out_handle.is_null() || out_public.is_null() {
        return IndraError::NullPointer.code();
    }

    *out_handle = INDRA_KEY_HANDLE_INVALID;
    *out_public = IndraPublicKeyInfo::zeroed();

    match catch_unwind(|| {
        let mut seed_bytes = Zeroizing::new([0u8; CLASSICAL_SK_BYTES]);
        seed_bytes.copy_from_slice(std::slice::from_raw_parts(seed, CLASSICAL_SK_BYTES));
        keygen::generate_keys(*seed_bytes).and_then(|keys| handles::store_hot_keys(session, &keys))
    }) {
        Ok(Ok((handle, public))) => {
            *out_handle = handle;
            *out_public = public;
            IndraError::Ok.code()
        }
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Import an independently-derived validator cold key into a session.
///
/// Both seed inputs remain caller-owned and must each reference exactly 32
/// readable bytes. Rust zeroizes its copies on every return path.
#[no_mangle]
/// # Safety
///
/// `classical_seed` and `pq_seed` must each point to 32 readable bytes; the
/// output handle and public-key pointer must be writable and valid.
pub unsafe extern "C" fn indra_cold_key_handle_from_seeds(
    session: IndraSessionHandle,
    classical_seed: *const u8,
    pq_seed: *const u8,
    out_handle: *mut IndraKeyHandle,
    out_public: *mut IndraColdPublicKeyInfo,
) -> i32 {
    if classical_seed.is_null() || pq_seed.is_null() || out_handle.is_null() || out_public.is_null()
    {
        return IndraError::NullPointer.code();
    }
    *out_handle = INDRA_KEY_HANDLE_INVALID;
    *out_public = IndraColdPublicKeyInfo::zeroed();
    match catch_unwind(|| {
        let mut classical = Zeroizing::new([0; CLASSICAL_SK_BYTES]);
        let mut pq = Zeroizing::new([0; PQ_SK_BYTES]);
        classical.copy_from_slice(std::slice::from_raw_parts(
            classical_seed,
            CLASSICAL_SK_BYTES,
        ));
        pq.copy_from_slice(std::slice::from_raw_parts(pq_seed, PQ_SK_BYTES));
        handles::store_cold_seeds(session, *classical, *pq)
    }) {
        Ok(Ok((handle, public))) => {
            *out_handle = handle;
            *out_public = public;
            IndraError::Ok.code()
        }
        Ok(Err(error)) => error.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Generate a new random 24-word BIP-39 mnemonic phrase.
///
/// # Safety
///
/// `out_phrase` must point to a writable buffer of length `out_len`.
#[no_mangle]
pub unsafe extern "C" fn indra_generate_mnemonic(out_phrase: *mut c_char, out_len: usize) -> i32 {
    if out_phrase.is_null() {
        return IndraError::NullPointer.code();
    }

    match catch_unwind(|| {
        let phrase = keygen::new_mnemonic();
        let bytes = phrase.as_bytes();
        if out_len > MAX_MNEMONIC_BYTES {
            return Err(IndraError::InvalidParam);
        }
        if bytes.len().saturating_add(1) > out_len {
            return Err(IndraError::BufferTooSmall);
        }
        let out_slice = std::slice::from_raw_parts_mut(out_phrase.cast::<u8>(), out_len);
        let Some(destination) = out_slice.get_mut(..bytes.len()) else {
            return Err(IndraError::BufferTooSmall);
        };
        destination.copy_from_slice(bytes);
        let Some(terminator) = out_slice.get_mut(bytes.len()) else {
            return Err(IndraError::BufferTooSmall);
        };
        *terminator = 0;
        Ok(())
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Recover an INDRA key handle from a BIP-39 mnemonic phrase.
///
/// # Safety
///
/// `phrase` must point to exactly `phrase_len` readable UTF-8 bytes. The caller
/// retains ownership and must securely erase its mnemonic buffer after return.
/// `out_handle` and `out_public` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn indra_keygen_from_mnemonic_handle(
    session: IndraSessionHandle,
    phrase: *const c_char,
    phrase_len: usize,
    out_handle: *mut IndraKeyHandle,
    out_public: *mut IndraPublicKeyInfo,
) -> i32 {
    if phrase.is_null() || out_handle.is_null() || out_public.is_null() {
        return IndraError::NullPointer.code();
    }

    *out_handle = INDRA_KEY_HANDLE_INVALID;
    *out_public = IndraPublicKeyInfo::zeroed();

    match catch_unwind(|| {
        let phrase_str = Zeroizing::new(bounded_utf8(phrase, phrase_len, MAX_MNEMONIC_BYTES)?);
        keygen::generate_keys_from_mnemonic(&phrase_str)
            .and_then(|keys| handles::store_hot_keys(session, &keys))
    }) {
        Ok(Ok((handle, public))) => {
            *out_handle = handle;
            *out_public = public;
            IndraError::Ok.code()
        }
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Copy public metadata for an opaque key handle.
///
/// # Safety
///
/// `out_public` must point to writable `IndraPublicKeyInfo` storage.
#[no_mangle]
pub unsafe extern "C" fn indra_key_handle_public(
    session: IndraSessionHandle,
    handle: IndraKeyHandle,
    out_public: *mut IndraPublicKeyInfo,
) -> i32 {
    if out_public.is_null() {
        return IndraError::NullPointer.code();
    }
    *out_public = IndraPublicKeyInfo::zeroed();
    match catch_unwind(|| handles::public_info(session, handle)) {
        Ok(Ok(public)) => {
            *out_public = public;
            IndraError::Ok.code()
        }
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

#[no_mangle]
/// # Safety
///
/// `out_public` must point to writable storage for one cold public-key record.
pub unsafe extern "C" fn indra_cold_key_handle_public(
    session: IndraSessionHandle,
    handle: IndraKeyHandle,
    out_public: *mut IndraColdPublicKeyInfo,
) -> i32 {
    if out_public.is_null() {
        return IndraError::NullPointer.code();
    }
    *out_public = IndraColdPublicKeyInfo::zeroed();
    match catch_unwind(|| handles::cold_public_info(session, handle)) {
        Ok(Ok(public)) => {
            *out_public = public;
            IndraError::Ok.code()
        }
        Ok(Err(error)) => error.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Destroy one opaque key handle and zeroize its in-process key material.
#[no_mangle]
pub extern "C" fn indra_destroy_key_handle(
    session: IndraSessionHandle,
    handle: IndraKeyHandle,
) -> i32 {
    match catch_unwind(|| handles::destroy_key(session, handle)) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Validate a BIP-39 mnemonic phrase.
///
/// # Safety
///
/// `phrase` must point to exactly `phrase_len` readable UTF-8 bytes. The caller
/// retains ownership and must securely erase its mnemonic buffer after return.
#[no_mangle]
pub unsafe extern "C" fn indra_validate_mnemonic(phrase: *const c_char, phrase_len: usize) -> i32 {
    if phrase.is_null() {
        return IndraError::NullPointer.code();
    }

    match catch_unwind(|| {
        let phrase_str = Zeroizing::new(bounded_utf8(phrase, phrase_len, MAX_MNEMONIC_BYTES)?);
        if keygen::is_valid_mnemonic(&phrase_str) {
            Ok(())
        } else {
            Err(IndraError::InvalidParam)
        }
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Derive the validator ID from a complete Ed25519 + ML-DSA-87 public key.
///
/// # Safety
///
/// `classical_pk` and `pq_pk` must point to 32 and 2592 readable bytes,
/// respectively, and `out_id` must point to a writable 32-byte output buffer.
#[no_mangle]
pub unsafe extern "C" fn indra_validator_id(
    classical_pk: *const u8,
    pq_pk: *const u8,
    out_id: *mut u8,
) -> i32 {
    if classical_pk.is_null() || pq_pk.is_null() || out_id.is_null() {
        return IndraError::NullPointer.code();
    }

    match catch_unwind(|| -> Result<(), IndraError> {
        let classical_pk_bytes = std::slice::from_raw_parts(classical_pk, CLASSICAL_PK_BYTES);
        let pq_pk_bytes = std::slice::from_raw_parts(pq_pk, PQ_PK_BYTES);
        let identity_key = HybridPubKey {
            classical_pk: Bytes32::from(
                <[u8; CLASSICAL_PK_BYTES]>::try_from(classical_pk_bytes)
                    .map_err(|_| IndraError::InvalidParam)?,
            ),
            pq_pk: VariableBytes::from_slice(pq_pk_bytes).map_err(|_| IndraError::InvalidParam)?,
        };
        let crypto_key = identity_key
            .to_crypto_pubkey()
            .map_err(|_| IndraError::InvalidParam)?;
        indra_crypto::validate_classical_public_key(&crypto_key.classical)
            .map_err(|_| IndraError::InvalidParam)?;
        indra_crypto::validate_pq_public_key(&crypto_key.pq)
            .map_err(|_| IndraError::InvalidParam)?;
        std::slice::from_raw_parts_mut(out_id, BYTES32_LEN)
            .copy_from_slice(&identity_key.identity_id().0);
        Ok(())
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Build and sign a transaction using a canonical payment descriptor.
///
/// # Safety
///
/// \`params\` and \`out\` must be valid pointers. The address pointer must
/// reference \`recipient_address_len\` readable UTF-8 bytes, \`chain_id\` must
/// reference exactly `chain_id_len` UTF-8 bytes, and UTXO pointers must match their count.
#[no_mangle]
pub unsafe extern "C" fn indra_build_tx_with_handle(
    session: IndraSessionHandle,
    params: *const IndraTxParams,
    out_result: *mut IndraResultHandle,
    out_metadata: *mut IndraTxResultMetadata,
) -> i32 {
    if params.is_null() || out_result.is_null() || out_metadata.is_null() {
        return IndraError::NullPointer.code();
    }
    *out_result = INDRA_RESULT_HANDLE_INVALID;
    *out_metadata = IndraTxResultMetadata::zeroed();

    match catch_unwind(|| {
        let params_ref = &*params;
        if params_ref.utxo_count > MAX_UTXO_COUNT
            || params_ref.recipient_address_len == 0
            || params_ref.recipient_address_len
                > indra_crypto::payment_address::MAX_PAYMENT_ADDRESS_TEXT_BYTES
        {
            return Err(IndraError::InvalidParam);
        }
        if params_ref.recipient_address.is_null()
            || params_ref.chain_id.is_null()
            || (params_ref.utxo_count > 0 && params_ref.utxos.is_null())
        {
            return Err(IndraError::NullPointer);
        }
        let recipient_address = std::str::from_utf8(std::slice::from_raw_parts(
            params_ref.recipient_address,
            params_ref.recipient_address_len,
        ))
        .map_err(|_| IndraError::InvalidParam)?;
        let chain_id = bounded_utf8(
            params_ref.chain_id,
            params_ref.chain_id_len,
            MAX_FFI_STRING_BYTES,
        )?;
        indra_crypto::PaymentAddressV1::from_text(recipient_address, chain_id.as_bytes())
            .map_err(|_| IndraError::InvalidParam)?;
        let utxos = if params_ref.utxo_count == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(params_ref.utxos, params_ref.utxo_count)
        };
        let lease = handles::acquire_hot_signing_lease(session, params_ref.sender_handle)?;
        lease.checkpoint()?;
        let sender_classical_seed = Zeroizing::new(lease.material().classical_seed());
        let sender_ml_dsa_seed = Zeroizing::new(lease.material().ml_dsa_seed());
        let wallet_context = wallet::build_wallet_context(
            *sender_classical_seed,
            &lease.material().hot_public()?.pq_pk,
            utxos,
        )?;
        let built = tx::build_with_address(
            recipient_address,
            params_ref.amount_spark,
            params_ref.fee_spark,
            *sender_classical_seed,
            sender_ml_dsa_seed.as_ref(),
            &chain_id,
            wallet_context,
        )?;
        let metadata = IndraTxResultMetadata {
            tx_id: built.tx_id,
            tx_bytes_len: built.tx_bytes.len(),
            change_spark: built.change_spark,
            spent_count: built.spent_indices.len(),
        };
        lease.publish(|| {
            let result_handle = handles::store_result(session, built)?;
            *out_result = result_handle;
            *out_metadata = metadata;
            Ok(())
        })?;
        Ok::<(), IndraError>(())
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Hex-encode raw transaction bytes into a caller-provided buffer.
///
/// # Safety
///
/// `tx_bytes` must reference `tx_bytes_len` readable bytes and `out_hex` must
/// point to a writable buffer of length `out_hex_len`.
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
        if tx_bytes_len == 0 || tx_bytes_len > MAX_TX_BYTES || out_hex_len > MAX_TX_HEX_BYTES {
            return Err(IndraError::InvalidParam);
        }
        let bytes = std::slice::from_raw_parts(tx_bytes, tx_bytes_len);
        let encoded = tx::tx_to_hex(bytes);
        let needed = encoded.len().saturating_add(1);
        if out_hex_len < needed {
            return Err(IndraError::BufferTooSmall);
        }

        let out_bytes = std::slice::from_raw_parts_mut(out_hex.cast::<u8>(), out_hex_len);
        let Some(destination) = out_bytes.get_mut(..encoded.len()) else {
            return Err(IndraError::BufferTooSmall);
        };
        destination.copy_from_slice(encoded.as_bytes());
        let Some(terminator) = out_bytes.get_mut(encoded.len()) else {
            return Err(IndraError::BufferTooSmall);
        };
        *terminator = 0;
        Ok(())
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

#[no_mangle]
/// # Safety
///
/// `out` must point to writable storage for `out_len` bytes; the result handle
/// must belong to `session` and remain alive for this call.
pub unsafe extern "C" fn indra_result_copy_tx_bytes(
    session: IndraSessionHandle,
    result: IndraResultHandle,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if out.is_null() {
        return IndraError::NullPointer.code();
    }
    match catch_unwind(|| {
        handles::with_result(session, result, |owned| {
            if out_len < owned.tx_bytes.len() {
                return Err(IndraError::BufferTooSmall);
            }
            let Some(destination) = std::slice::from_raw_parts_mut(out, out_len)
                .get_mut(..owned.tx_bytes.len())
            else {
                return Err(IndraError::BufferTooSmall);
            };
            destination.copy_from_slice(&owned.tx_bytes);
            Ok(())
        })?
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(error)) => error.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

#[no_mangle]
/// # Safety
///
/// `out` must point to writable storage for `out_len` indices; the result handle
/// must belong to `session` and remain alive for this call.
pub unsafe extern "C" fn indra_result_copy_spent_indices(
    session: IndraSessionHandle,
    result: IndraResultHandle,
    out: *mut usize,
    out_len: usize,
) -> i32 {
    if out.is_null() {
        return IndraError::NullPointer.code();
    }
    match catch_unwind(|| {
        handles::with_result(session, result, |owned| {
            if out_len < owned.spent_indices.len() {
                return Err(IndraError::BufferTooSmall);
            }
            let Some(destination) = std::slice::from_raw_parts_mut(out, out_len)
                .get_mut(..owned.spent_indices.len())
            else {
                return Err(IndraError::BufferTooSmall);
            };
            destination.copy_from_slice(&owned.spent_indices);
            Ok(())
        })?
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(error)) => error.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

#[no_mangle]
pub extern "C" fn indra_destroy_result(
    session: IndraSessionHandle,
    result: IndraResultHandle,
) -> i32 {
    match catch_unwind(|| handles::destroy_result(session, result)) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(error)) => error.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Return a static human-readable string for an FFI error code.
#[no_mangle]
pub extern "C" fn indra_error_string(error_code: i32) -> *const c_char {
    error_string(error_code).as_ptr().cast::<c_char>()
}
#[cfg(test)]
mod handle_tests {
    use super::*;
    use indra_core::{
        codec::Decode,
        types::{
            crypto::HybridPubKey,
            governance::{governance_vote_commit_hash, GovernanceOpV2, GovernancePayload},
            primitives::{
                Bytes32, VariableBytes, TEST_CHAIN_ID, MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
            },
            staking::{StakingOp, StakingOpBody},
            transaction::{OutputV1, TransactionV1},
        },
    };
    use indra_crypto::{mnemonic_to_seed, ClassicalKeypair, HybridKeypair, PqKeypair};
    use std::{
        ffi::{CStr, CString},
        fs,
        path::Path,
        process::Command,
        sync::{Mutex, OnceLock},
        thread,
    };

    const OK: i32 = IndraError::Ok as i32;
    const INVALID_HANDLE: i32 = IndraError::InvalidHandle as i32;

    fn create_session() -> IndraSessionHandle {
        let mut session = INDRA_SESSION_HANDLE_INVALID;
        assert_eq!(unsafe { indra_create_session(&mut session) }, OK);
        assert_ne!(session, INDRA_SESSION_HANDLE_INVALID);
        session
    }

    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn account_fixture_claims(state: &mut indra_state::ChainState) {
        state.monetary_aggregates = state.recompute_monetary_aggregates().unwrap();
        let issued = state.monetary_aggregates.total_claims_spark().unwrap();
        state.total_supply = issued;
        state.monetary_ledger.genesis_issued_spark = issued;
        state.monetary_ledger.reward_budget_spark =
            indra_core::types::primitives::LIFETIME_SUPPLY_CAP_SPARK - issued;
        state.monetary_ledger.validate(issued).unwrap();
    }

    fn handle_from_seed(
        session: IndraSessionHandle,
        seed: [u8; 32],
    ) -> (IndraKeyHandle, IndraPublicKeyInfo) {
        let mut handle = INDRA_KEY_HANDLE_INVALID;
        let mut public = IndraPublicKeyInfo::zeroed();
        let code = unsafe { indra_keygen_handle(session, seed.as_ptr(), &mut handle, &mut public) };
        assert_eq!(code, OK);
        assert_ne!(handle, INDRA_KEY_HANDLE_INVALID);
        (handle, public)
    }

    fn cold_handle_from_seeds(
        session: IndraSessionHandle,
        classical_seed: [u8; 32],
        pq_seed: [u8; 32],
    ) -> (IndraKeyHandle, IndraColdPublicKeyInfo) {
        let mut handle = INDRA_KEY_HANDLE_INVALID;
        let mut public = IndraColdPublicKeyInfo::zeroed();
        assert_eq!(
            unsafe {
                indra_cold_key_handle_from_seeds(
                    session,
                    classical_seed.as_ptr(),
                    pq_seed.as_ptr(),
                    &mut handle,
                    &mut public,
                )
            },
            OK
        );
        (handle, public)
    }

    fn direct_keypair_from_master_seed(seed: [u8; 32]) -> HybridKeypair {
        let keys = keygen::generate_keys(seed).unwrap();
        HybridKeypair::new(
            ClassicalKeypair::from_seed(&keys.ed25519_seed),
            PqKeypair::from_bytes(&keys.public.hybrid_pq_pk, &keys.ml_dsa_seed).unwrap(),
        )
    }

    fn assert_wire_signature_matches_direct(
        signature: &indra_core::types::crypto::HybridSignature,
        direct: &indra_crypto::HybridSignature,
    ) {
        assert_eq!(signature.classical_sig.as_slice(), direct.classical.0);
        assert_eq!(signature.pq_sig.as_slice(), direct.pq.0);
    }

    fn out() -> Vec<c_char> {
        vec![0; INDRA_OP_HEX_MAX_BYTES]
    }

    unsafe fn decode_staking(out: &[c_char]) -> StakingOp {
        let hex = CStr::from_ptr(out.as_ptr()).to_str().unwrap();
        StakingOp::decode_exact(&hex::decode(hex).unwrap()).unwrap()
    }

    unsafe fn decode_governance(out: &[c_char]) -> GovernanceOpV2 {
        let hex = CStr::from_ptr(out.as_ptr()).to_str().unwrap();
        GovernanceOpV2::decode_exact(&hex::decode(hex).unwrap()).unwrap()
    }

    fn hot_wire_public(public: &IndraPublicKeyInfo) -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::from(public.classical_pk),
            pq_pk: VariableBytes::from_slice(&public.pq_pk).unwrap(),
        }
    }

    fn cold_wire_public(public: &IndraColdPublicKeyInfo) -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::from(public.classical_pk),
            pq_pk: VariableBytes::from_slice(&public.pq_pk).unwrap(),
        }
    }

    unsafe fn decode_tx_result(
        session: IndraSessionHandle,
        result: IndraResultHandle,
        metadata: &IndraTxResultMetadata,
    ) -> TransactionV1 {
        let mut bytes = vec![0u8; metadata.tx_bytes_len];
        assert_eq!(
            indra_result_copy_tx_bytes(session, result, bytes.as_mut_ptr(), bytes.len()),
            OK
        );
        TransactionV1::decode_exact(&bytes).unwrap()
    }

    #[test]
    fn keygen_handle_returns_public_metadata_without_private_fields() {
        let _guard = test_lock();
        let session = create_session();
        let (_handle, public) = handle_from_seed(session, [0x42; 32]);
        assert_ne!(public.validator_id, [0u8; 32]);
        assert_ne!(public.classical_pk, [0u8; 32]);
        assert_ne!(public.pq_pk, [0u8; PQ_PK_BYTES]);
        assert_ne!(public.vrf_pk, [0u8; 32]);
        assert_eq!(
            std::mem::size_of::<IndraPublicKeyInfo>(),
            INDRA_VALIDATOR_ID_BYTES + CLASSICAL_PK_BYTES + PQ_PK_BYTES + INDRA_VRF_PK_BYTES
        );
    }

    #[test]
    fn session_and_key_capabilities_are_nonzero_high_entropy_tokens() {
        use std::collections::HashSet;
        let _guard = test_lock();
        let mut sessions = HashSet::new();
        let mut keys = HashSet::new();
        for seed_byte in 1..=32u8 {
            let session = create_session();
            let (key, _) = handle_from_seed(session, [seed_byte; 32]);
            assert!(sessions.insert(session.bytes));
            assert!(keys.insert(key.bytes));
            assert_ne!(session.bytes, [0u8; 16]);
            assert_ne!(key.bytes, [0u8; 16]);
        }
    }

    #[test]
    fn key_handle_public_matches_canonical_keystore_public_fields() {
        let _guard = test_lock();
        let seed = [0x24; 32];
        let session = create_session();
        let (handle, public) = handle_from_seed(session, seed);
        let direct = keygen::generate_keys(seed).unwrap();
        assert_eq!(public.validator_id, direct.public.validator_id);
        assert_eq!(public.classical_pk, direct.public.hybrid_classical_pk);
        assert_eq!(
            public.pq_pk.as_slice(),
            direct.public.hybrid_pq_pk.as_slice()
        );
        assert_eq!(public.vrf_pk, direct.public.vrf_pk);

        let mut fetched = IndraPublicKeyInfo::zeroed();
        let code = unsafe { indra_key_handle_public(session, handle, &mut fetched) };
        assert_eq!(code, OK);
        assert_eq!(fetched.validator_id, public.validator_id);
        assert_eq!(fetched.classical_pk, public.classical_pk);
        assert_eq!(fetched.pq_pk, public.pq_pk);
        assert_eq!(fetched.vrf_pk, public.vrf_pk);
    }

    #[test]
    fn hot_and_cold_handle_roles_fail_closed_when_substituted() {
        let _guard = test_lock();
        let session = create_session();
        let (hot, _) = handle_from_seed(session, [0x25; 32]);
        let (cold, _) = cold_handle_from_seeds(session, [0x26; 32], [0x27; 32]);
        assert!(matches!(
            handles::acquire_cold_signing_lease(session, hot),
            Err(IndraError::WrongKeyRole)
        ));
        assert!(matches!(
            handles::acquire_hot_signing_lease(session, cold),
            Err(IndraError::WrongKeyRole)
        ));
        let mut hot_public = IndraPublicKeyInfo::zeroed();
        let mut cold_public = IndraColdPublicKeyInfo::zeroed();
        assert_eq!(
            unsafe { indra_key_handle_public(session, cold, &mut hot_public) },
            IndraError::WrongKeyRole.code()
        );
        assert_eq!(
            unsafe { indra_cold_key_handle_public(session, hot, &mut cold_public) },
            IndraError::WrongKeyRole.code()
        );
    }

    #[test]
    fn ffi_master_seed_matches_keystore_master_seed_api() {
        let _guard = test_lock();
        let seed = [0x27; 32];
        let seed_keys = keygen::generate_keys(seed).unwrap();
        let canonical = indra_cli::generate_from_master_seed(String::new(), seed).unwrap();
        assert_eq!(seed_keys, canonical);

        let phrase = keygen::new_mnemonic();
        let mnemonic_keys = keygen::generate_keys_from_mnemonic(&phrase).unwrap();
        let master_seed = mnemonic_to_seed(&phrase).unwrap();
        let canonical_mnemonic =
            indra_cli::generate_from_master_seed(String::new(), master_seed).unwrap();
        assert_eq!(mnemonic_keys, canonical_mnemonic);

        let phrase_c = CString::new(phrase).unwrap();
        let session = create_session();
        let mut mnemonic_handle = INDRA_KEY_HANDLE_INVALID;
        let mut public = IndraPublicKeyInfo::zeroed();
        assert_eq!(
            unsafe {
                indra_keygen_from_mnemonic_handle(
                    session,
                    phrase_c.as_ptr(),
                    phrase_c.as_bytes().len(),
                    &mut mnemonic_handle,
                    &mut public,
                )
            },
            OK
        );
        assert_eq!(public.validator_id, mnemonic_keys.public.validator_id);
        assert_eq!(
            public.classical_pk,
            mnemonic_keys.public.hybrid_classical_pk
        );
        assert_eq!(
            public.pq_pk.as_slice(),
            mnemonic_keys.public.hybrid_pq_pk.as_slice()
        );
        assert_eq!(indra_destroy_key_handle(session, mnemonic_handle), OK);
    }

    #[test]
    fn ffi_validator_id_binds_complete_hybrid_public_key() {
        let _guard = test_lock();
        let first = direct_keypair_from_master_seed([0x28; 32]).public_key();
        let alternate_pq = PqKeypair::from_seed(&[0x29; 32]).unwrap().public_key();
        let mut first_id = [0u8; BYTES32_LEN];
        let mut mixed_id = [0u8; BYTES32_LEN];

        assert_eq!(
            unsafe {
                indra_validator_id(
                    first.classical.0.as_ptr(),
                    first.pq.0.as_ptr(),
                    first_id.as_mut_ptr(),
                )
            },
            OK
        );
        assert_eq!(
            unsafe {
                indra_validator_id(
                    first.classical.0.as_ptr(),
                    alternate_pq.0.as_ptr(),
                    mixed_id.as_mut_ptr(),
                )
            },
            OK
        );

        assert_eq!(
            first_id,
            indra_core::types::crypto::hybrid_identity_id(&first.classical.0, &first.pq.0).0
        );
        assert_ne!(first_id, mixed_id);
    }

    #[test]
    fn destroy_key_handle_zeroizes_and_invalidates_entry() {
        let _guard = test_lock();
        let session = create_session();
        let (handle, _public) = handle_from_seed(session, [0x11; 32]);
        assert_eq!(indra_destroy_key_handle(session, handle), OK);
        let mut fetched = IndraPublicKeyInfo::zeroed();
        let code = unsafe { indra_key_handle_public(session, handle, &mut fetched) };
        assert_eq!(code, INVALID_HANDLE);
    }

    fn funded_utxo() -> IndraUtxoEntry {
        IndraUtxoEntry {
            utxo_id: [0xAB; 32],
            value_spark: 10_000_000,
            created_height: 0,
            tx_index: 0,
            out_index: 0,
            spent: 0,
        }
    }

    #[test]
    fn transaction_handle_signature_matches_direct_and_recipient_owner() {
        let _guard = test_lock();
        let session = create_session();
        let (sender_handle, _sender_public) = handle_from_seed(session, [0x76; 32]);
        let (recipient_handle, _) = handle_from_seed(session, [0x77; 32]);
        let recipient_lease =
            handles::acquire_hot_signing_lease(session, recipient_handle).unwrap();
        let recipient_keypair = recipient_lease.material().keypair().unwrap();
        let recipient_address = indra_crypto::PaymentAddressV1::new(
            TEST_CHAIN_ID.as_bytes(),
            recipient_keypair.public_key(),
        )
        .unwrap()
        .to_text();
        let chain = CString::new(TEST_CHAIN_ID).unwrap();
        let utxo = funded_utxo();
        let amount = 1_000_000;
        let params = IndraTxParams {
            recipient_address: recipient_address.as_ptr(),
            recipient_address_len: recipient_address.len(),
            amount_spark: amount,
            fee_spark: 50_000,
            utxos: &utxo,
            utxo_count: 1,
            sender_handle,
            chain_id: chain.as_ptr(),
            chain_id_len: chain.as_bytes().len(),
        };
        let mut result = INDRA_RESULT_HANDLE_INVALID;
        let mut metadata = IndraTxResultMetadata::zeroed();
        assert_eq!(
            unsafe { indra_build_tx_with_handle(session, &params, &mut result, &mut metadata) },
            OK
        );
        let tx = unsafe { decode_tx_result(session, result, &metadata) };
        let direct = direct_keypair_from_master_seed([0x76; 32])
            .sign(&tx.signing_bytes(TEST_CHAIN_ID).unwrap())
            .unwrap();
        assert_wire_signature_matches_direct(&tx.signature, &direct);
        assert_eq!(tx.outputs[0].value_spark, amount);
        assert_eq!(
            tx.outputs[0].owner_pubkey.classical_pk.0,
            recipient_keypair.public_key().classical.0
        );
        assert_eq!(indra_destroy_result(session, result), OK);
        drop(recipient_lease);
        assert_eq!(indra_destroy_key_handle(session, sender_handle), OK);
        assert_eq!(indra_destroy_key_handle(session, recipient_handle), OK);
    }

    #[test]
    fn transaction_builder_rejects_oversized_address_before_dereferencing_slice() {
        let _guard = test_lock();
        let session = create_session();
        let chain = CString::new(TEST_CHAIN_ID).unwrap();
        let params = IndraTxParams {
            recipient_address: std::ptr::dangling(),
            recipient_address_len: indra_crypto::payment_address::MAX_PAYMENT_ADDRESS_TEXT_BYTES
                + 1,
            amount_spark: 1_000_000,
            fee_spark: 50_000,
            utxos: std::ptr::null(),
            utxo_count: 0,
            sender_handle: INDRA_KEY_HANDLE_INVALID,
            chain_id: chain.as_ptr(),
            chain_id_len: chain.as_bytes().len(),
        };
        let mut result = INDRA_RESULT_HANDLE_INVALID;
        let mut metadata = IndraTxResultMetadata::zeroed();

        assert_eq!(
            unsafe { indra_build_tx_with_handle(session, &params, &mut result, &mut metadata) },
            IndraError::InvalidParam.code()
        );
    }

    #[test]
    fn staking_handle_signature_is_byte_identical_to_direct_signing() {
        let _guard = test_lock();
        let session = create_session();
        let (handle, public) = handle_from_seed(session, [0x44; 32]);
        let chain = CString::new("indra-testnet-1").unwrap();
        let mut out = out();
        let code = unsafe {
            crate::staking::indra_build_delegator_claim_rewards_with_handle(
                session,
                public.validator_id.as_ptr(),
                handle,
                7,
                chain.as_ptr(),
                chain.as_bytes().len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(code, OK);
        let op = unsafe { decode_staking(&out) };
        assert_eq!(op.nonce, 7);
        let direct = direct_keypair_from_master_seed([0x44; 32])
            .sign(&op.signing_bytes("indra-testnet-1"))
            .unwrap();
        assert_wire_signature_matches_direct(&op.signature, &direct);
        match &op.body {
            StakingOpBody::ClaimRewards {
                validator_id,
                delegator_pubkey,
                ..
            } => {
                assert_eq!(validator_id.0, public.validator_id);
                assert_eq!(delegator_pubkey.classical_pk.0, public.classical_pk);
            }
            other => panic!("unexpected staking op: {other:?}"),
        }
    }

    #[test]
    fn ffi_registration_and_active_validator_staking_builders_apply_to_consensus_state() {
        let _guard = test_lock();
        let session = create_session();
        let (hot, hot_public) = handle_from_seed(session, [0x81; 32]);
        let (cold, cold_public) = cold_handle_from_seeds(session, [0x82; 32], [0x83; 32]);
        let chain = CString::new(TEST_CHAIN_ID).unwrap();
        let mut state = indra_state::ChainState::new_genesis(TEST_CHAIN_ID);
        let deposit_id = state
            .utxos
            .insert(
                OutputV1 {
                    value_spark: MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
                    owner_pubkey: cold_wire_public(&cold_public),
                    lock_height: 0,
                },
                0,
                0,
                0,
            )
            .unwrap();
        let mut output = out();
        assert_eq!(
            unsafe {
                crate::staking::indra_build_register_validator_with_handle(
                    session,
                    1_000,
                    deposit_id.0.as_ptr(),
                    hot,
                    cold,
                    1,
                    chain.as_ptr(),
                    chain.as_bytes().len(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            },
            OK
        );
        let registration = unsafe { decode_staking(&output) };
        indra_state::delegation::apply_staking_op(&mut state, &registration, TEST_CHAIN_ID, 1)
            .unwrap();
        let validator_id = Bytes32::from(hot_public.validator_id);
        state.validators.get_mut(&validator_id).unwrap().status =
            indra_state::validator::ValidatorStatus::Active;

        let self_stake_id = state
            .utxos
            .insert(
                OutputV1 {
                    value_spark: MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
                    owner_pubkey: cold_wire_public(&cold_public),
                    lock_height: 0,
                },
                1,
                0,
                0,
            )
            .unwrap();
        output.fill(0);
        assert_eq!(
            unsafe {
                crate::staking::indra_build_self_stake_with_handle(
                    session,
                    self_stake_id.0.as_ptr(),
                    hot,
                    cold,
                    1,
                    1,
                    chain.as_ptr(),
                    chain.as_bytes().len(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            },
            OK
        );
        indra_state::delegation::apply_staking_op(
            &mut state,
            &unsafe { decode_staking(&output) },
            TEST_CHAIN_ID,
            2,
        )
        .unwrap();

        output.fill(0);
        assert_eq!(
            unsafe {
                crate::staking::indra_build_set_commission_with_handle(
                    session,
                    1_100,
                    hot,
                    cold,
                    1,
                    2,
                    chain.as_ptr(),
                    chain.as_bytes().len(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            },
            OK
        );
        indra_state::delegation::apply_staking_op(
            &mut state,
            &unsafe { decode_staking(&output) },
            TEST_CHAIN_ID,
            3,
        )
        .unwrap();

        output.fill(0);
        let clear_target = [0; 32];
        assert_eq!(
            unsafe {
                crate::staking::indra_build_set_auto_delegate_with_handle(
                    session,
                    clear_target.as_ptr(),
                    hot,
                    cold,
                    1,
                    3,
                    chain.as_ptr(),
                    chain.as_bytes().len(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            },
            OK
        );
        indra_state::delegation::apply_staking_op(
            &mut state,
            &unsafe { decode_staking(&output) },
            TEST_CHAIN_ID,
            4,
        )
        .unwrap();

        output.fill(0);
        assert_eq!(
            unsafe {
                crate::staking::indra_build_validator_claim_rewards_with_handle(
                    session,
                    hot,
                    cold,
                    1,
                    4,
                    chain.as_ptr(),
                    chain.as_bytes().len(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            },
            OK
        );
        indra_state::delegation::apply_staking_op(
            &mut state,
            &unsafe { decode_staking(&output) },
            TEST_CHAIN_ID,
            5,
        )
        .unwrap();

        let (delegator, delegator_public) = handle_from_seed(session, [0x84; 32]);
        let delegator_pubkey = hot_wire_public(&delegator_public);
        let delegation_id = state
            .utxos
            .insert(
                OutputV1 {
                    value_spark: 1_000_000,
                    owner_pubkey: delegator_pubkey.clone(),
                    lock_height: 0,
                },
                5,
                0,
                0,
            )
            .unwrap();
        output.fill(0);
        assert_eq!(
            unsafe {
                crate::staking::indra_build_delegate_with_handle(
                    session,
                    validator_id.0.as_ptr(),
                    delegation_id.0.as_ptr(),
                    delegator,
                    1,
                    chain.as_ptr(),
                    chain.as_bytes().len(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            },
            OK
        );
        indra_state::delegation::apply_staking_op(
            &mut state,
            &unsafe { decode_staking(&output) },
            TEST_CHAIN_ID,
            6,
        )
        .unwrap();
        let delegator_id = delegator_pubkey.identity_id();
        let position_id = indra_core::types::stake_position::derive_position_id(
            validator_id,
            delegator_id,
            indra_core::types::stake_position::PositionCustodyV1::DelegatorIdentity {
                delegator_id,
            },
        );
        let mut position = state.stake_positions.get(&position_id).unwrap().clone();
        position.pending_rewards_spark = 100_000;
        state.stake_positions.insert(position_id, position);
        output.fill(0);
        assert_eq!(
            unsafe {
                crate::staking::indra_build_delegator_claim_rewards_with_handle(
                    session,
                    validator_id.0.as_ptr(),
                    delegator,
                    2,
                    chain.as_ptr(),
                    chain.as_bytes().len(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            },
            OK
        );
        indra_state::delegation::apply_staking_op(
            &mut state,
            &unsafe { decode_staking(&output) },
            TEST_CHAIN_ID,
            7,
        )
        .unwrap();

        assert_eq!(state.validators.get(&validator_id).unwrap().cold_nonce, 4);
        assert_eq!(hot_wire_public(&hot_public).identity_id(), validator_id);
    }

    #[test]
    fn governance_handle_signature_is_byte_identical_to_direct_signing() {
        let _guard = test_lock();
        let session = create_session();
        let (hot_handle, public) = handle_from_seed(session, [0x55; 32]);
        let (cold_handle, _) = cold_handle_from_seeds(session, [0x56; 32], [0x57; 32]);
        let chain = CString::new("indra-testnet-1").unwrap();
        let proposal_id = [0x99; 32];
        let mut out = out();
        let code = unsafe {
            crate::governance::indra_build_governance_cancel_with_handle(
                session,
                proposal_id.as_ptr(),
                hot_handle,
                cold_handle,
                1,
                9,
                chain.as_ptr(),
                chain.as_bytes().len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(code, OK);
        let op = unsafe { decode_governance(&out) };
        let message = op
            .cold_authorization_signing_bytes("indra-testnet-1")
            .unwrap()
            .unwrap();
        let direct =
            indra_crypto::ColdHybridKeypair::from_independent_seeds([0x56; 32], [0x57; 32])
                .unwrap()
                .sign(&message)
                .unwrap();
        assert_wire_signature_matches_direct(&op.signature, &direct);
        assert_eq!(op.signer_id.0, public.validator_id);
        assert_eq!(op.nonce, 0);
        assert!(matches!(op.payload, GovernancePayload::Cancel { .. }));
    }

    #[test]
    fn ffi_cold_governance_builders_apply_to_consensus_state() {
        use indra_core::types::governance::{compute_proposal_id, GovernableAction};
        use indra_state::governance::{GovernanceSnapshot, ProposalPhase};

        let _guard = test_lock();
        let session = create_session();
        let (hot, hot_public) = handle_from_seed(session, [0x91; 32]);
        let (cold, cold_public) = cold_handle_from_seeds(session, [0x92; 32], [0x93; 32]);
        let chain = CString::new(TEST_CHAIN_ID).unwrap();
        let mut state = indra_state::ChainState::new_genesis(TEST_CHAIN_ID);
        let registration_deposit = state
            .utxos
            .insert(
                OutputV1 {
                    value_spark: MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
                    owner_pubkey: cold_wire_public(&cold_public),
                    lock_height: 0,
                },
                0,
                0,
                0,
            )
            .unwrap();
        account_fixture_claims(&mut state);
        let mut output = out();
        assert_eq!(
            unsafe {
                crate::staking::indra_build_register_validator_with_handle(
                    session,
                    1_000,
                    registration_deposit.0.as_ptr(),
                    hot,
                    cold,
                    1,
                    chain.as_ptr(),
                    chain.as_bytes().len(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            },
            OK
        );
        indra_state::delegation::apply_staking_op(
            &mut state,
            &unsafe { decode_staking(&output) },
            TEST_CHAIN_ID,
            1,
        )
        .unwrap();
        let validator_id = Bytes32::from(hot_public.validator_id);
        state.validators.get_mut(&validator_id).unwrap().status =
            indra_state::validator::ValidatorStatus::Active;

        let proposal_deposit = state.governance.params.proposal_deposit_spark;
        let deposit_id = state
            .utxos
            .insert(
                OutputV1 {
                    value_spark: proposal_deposit,
                    owner_pubkey: cold_wire_public(&cold_public),
                    lock_height: 0,
                },
                1,
                1,
                0,
            )
            .unwrap();
        account_fixture_claims(&mut state);
        let title = CString::new("FFI proposal").unwrap();
        let description = CString::new("consensus application proof").unwrap();
        let action = GovernableAction::SetMinDelegationSpark { value: 200_000 };
        let action_json =
            CString::new(r#"{"type":"SetMinDelegationSpark","value":200000}"#).unwrap();
        output.fill(0);
        assert_eq!(
            unsafe {
                crate::governance::indra_build_governance_propose_with_handle(
                    session,
                    title.as_ptr(),
                    title.as_bytes().len(),
                    description.as_ptr(),
                    description.as_bytes().len(),
                    action_json.as_ptr(),
                    action_json.as_bytes().len(),
                    deposit_id.0.as_ptr(),
                    hot,
                    cold,
                    1,
                    1,
                    chain.as_ptr(),
                    chain.as_bytes().len(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            },
            OK
        );
        let propose = unsafe { decode_governance(&output) };
        indra_state::governance_apply::apply_governance_op(
            &mut state,
            &propose,
            0,
            2,
            TEST_CHAIN_ID,
        )
        .unwrap();
        let proposal_id = compute_proposal_id(validator_id, &action, 0, TEST_CHAIN_ID);

        let mut cancel_state = state.clone();
        output.fill(0);
        assert_eq!(
            unsafe {
                crate::governance::indra_build_governance_cancel_with_handle(
                    session,
                    proposal_id.0.as_ptr(),
                    hot,
                    cold,
                    1,
                    2,
                    chain.as_ptr(),
                    chain.as_bytes().len(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            },
            OK
        );
        indra_state::governance_apply::apply_governance_op(
            &mut cancel_state,
            &unsafe { decode_governance(&output) },
            0,
            3,
            TEST_CHAIN_ID,
        )
        .unwrap();

        let proposal = state.governance.proposals.get_mut(&proposal_id).unwrap();
        proposal.phase = ProposalPhase::Commit;
        proposal.snapshot1 = Some(GovernanceSnapshot {
            weights: [(validator_id, MINIMUM_VALIDATOR_SELF_STAKE_SPARK)].into(),
            total_stake: MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
        });
        let mut reveal_nonce = [0; 32];
        let mut commitment = [0; 32];
        output.fill(0);
        assert_eq!(
            unsafe {
                crate::governance::indra_build_governance_commit_with_handle(
                    session,
                    proposal_id.0.as_ptr(),
                    1,
                    reveal_nonce.as_mut_ptr(),
                    commitment.as_mut_ptr(),
                    hot,
                    cold,
                    1,
                    2,
                    chain.as_ptr(),
                    chain.as_bytes().len(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            },
            OK
        );
        assert_ne!(reveal_nonce, [0; 32]);
        assert_eq!(
            commitment,
            governance_vote_commit_hash(proposal_id, validator_id, 1, Bytes32::from(reveal_nonce))
                .0
        );
        let mut second_nonce = [0; 32];
        let mut second_commitment = [0; 32];
        let mut second_output = vec![0i8; INDRA_OP_HEX_MAX_BYTES];
        assert_eq!(
            unsafe {
                crate::governance::indra_build_governance_commit_with_handle(
                    session,
                    proposal_id.0.as_ptr(),
                    1,
                    second_nonce.as_mut_ptr(),
                    second_commitment.as_mut_ptr(),
                    hot,
                    cold,
                    1,
                    2,
                    chain.as_ptr(),
                    chain.as_bytes().len(),
                    second_output.as_mut_ptr(),
                    second_output.len(),
                )
            },
            OK
        );
        assert_ne!(second_nonce, reveal_nonce);
        assert_ne!(second_commitment, commitment);
        indra_state::governance_apply::apply_governance_op(
            &mut state,
            &unsafe { decode_governance(&output) },
            1,
            3,
            TEST_CHAIN_ID,
        )
        .unwrap();
        state
            .governance
            .proposals
            .get_mut(&proposal_id)
            .unwrap()
            .phase = ProposalPhase::Reveal;
        output.fill(0);
        assert_eq!(
            unsafe {
                crate::governance::indra_build_governance_reveal_with_handle(
                    session,
                    proposal_id.0.as_ptr(),
                    1,
                    reveal_nonce.as_ptr(),
                    hot,
                    cold,
                    1,
                    3,
                    chain.as_ptr(),
                    chain.as_bytes().len(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            },
            OK
        );
        indra_state::governance_apply::apply_governance_op(
            &mut state,
            &unsafe { decode_governance(&output) },
            2,
            4,
            TEST_CHAIN_ID,
        )
        .unwrap();
        assert_eq!(state.validators.get(&validator_id).unwrap().cold_nonce, 3);
    }

    #[test]
    fn invalid_handle_rejected_for_all_handle_builders() {
        let _guard = test_lock();
        let session = create_session();
        let chain = CString::new("indra-testnet-1").unwrap();
        let mut out_hex = out();
        let mut result = INDRA_RESULT_HANDLE_INVALID;
        let mut metadata = IndraTxResultMetadata::zeroed();
        let address_keypair = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0x21; 32]),
            PqKeypair::from_seed(&[0x21; 32]).unwrap(),
        );
        let address =
            indra_crypto::PaymentAddressV1::new(b"indra-testnet-1", address_keypair.public_key())
                .unwrap()
                .to_text();
        let tx_params = IndraTxParams {
            recipient_address: address.as_ptr(),
            recipient_address_len: address.len(),
            amount_spark: 1,
            fee_spark: 1,
            utxos: std::ptr::null(),
            utxo_count: 0,
            sender_handle: INDRA_KEY_HANDLE_INVALID,
            chain_id: chain.as_ptr(),
            chain_id_len: chain.as_bytes().len(),
        };
        assert_eq!(
            unsafe { indra_build_tx_with_handle(session, &tx_params, &mut result, &mut metadata) },
            INVALID_HANDLE
        );
        let id = [0x02; 32];
        assert_eq!(
            unsafe {
                crate::staking::indra_build_delegator_claim_rewards_with_handle(
                    session,
                    id.as_ptr(),
                    INDRA_KEY_HANDLE_INVALID,
                    1,
                    chain.as_ptr(),
                    chain.as_bytes().len(),
                    out_hex.as_mut_ptr(),
                    out_hex.len(),
                )
            },
            INVALID_HANDLE
        );
        macro_rules! assert_invalid {
            ($call:expr) => {{
                out_hex.fill(0x5A as c_char);
                assert_eq!(unsafe { $call }, INVALID_HANDLE);
                assert_eq!(out_hex[0], 0, "failed call left stale output");
            }};
        }
        assert_invalid!(crate::staking::indra_build_register_validator_with_handle(
            session,
            100,
            id.as_ptr(),
            INDRA_KEY_HANDLE_INVALID,
            INDRA_KEY_HANDLE_INVALID,
            1,
            chain.as_ptr(),
            chain.as_bytes().len(),
            out_hex.as_mut_ptr(),
            out_hex.len()
        ));
        assert_invalid!(crate::staking::indra_build_self_stake_with_handle(
            session,
            id.as_ptr(),
            INDRA_KEY_HANDLE_INVALID,
            INDRA_KEY_HANDLE_INVALID,
            1,
            1,
            chain.as_ptr(),
            chain.as_bytes().len(),
            out_hex.as_mut_ptr(),
            out_hex.len()
        ));
        assert_invalid!(crate::staking::indra_build_delegate_with_handle(
            session,
            id.as_ptr(),
            id.as_ptr(),
            INDRA_KEY_HANDLE_INVALID,
            1,
            chain.as_ptr(),
            chain.as_bytes().len(),
            out_hex.as_mut_ptr(),
            out_hex.len()
        ));
        assert_invalid!(crate::staking::indra_build_set_commission_with_handle(
            session,
            100,
            INDRA_KEY_HANDLE_INVALID,
            INDRA_KEY_HANDLE_INVALID,
            1,
            1,
            chain.as_ptr(),
            chain.as_bytes().len(),
            out_hex.as_mut_ptr(),
            out_hex.len()
        ));
        assert_invalid!(crate::staking::indra_build_set_auto_delegate_with_handle(
            session,
            id.as_ptr(),
            INDRA_KEY_HANDLE_INVALID,
            INDRA_KEY_HANDLE_INVALID,
            1,
            1,
            chain.as_ptr(),
            chain.as_bytes().len(),
            out_hex.as_mut_ptr(),
            out_hex.len()
        ));

        let title = CString::new("title").unwrap();
        let description = CString::new("description").unwrap();
        let action = CString::new(r#"{"type":"SetMinDelegationSpark","value":1}"#).unwrap();
        let mut nonce = [0u8; 32];
        let mut commitment = [0u8; 32];
        assert_invalid!(
            crate::governance::indra_build_governance_propose_with_handle(
                session,
                title.as_ptr(),
                title.as_bytes().len(),
                description.as_ptr(),
                description.as_bytes().len(),
                action.as_ptr(),
                action.as_bytes().len(),
                id.as_ptr(),
                INDRA_KEY_HANDLE_INVALID,
                INDRA_KEY_HANDLE_INVALID,
                1,
                1,
                chain.as_ptr(),
                chain.as_bytes().len(),
                out_hex.as_mut_ptr(),
                out_hex.len()
            )
        );
        assert_invalid!(
            crate::governance::indra_build_governance_commit_with_handle(
                session,
                id.as_ptr(),
                1,
                nonce.as_mut_ptr(),
                commitment.as_mut_ptr(),
                INDRA_KEY_HANDLE_INVALID,
                INDRA_KEY_HANDLE_INVALID,
                1,
                1,
                chain.as_ptr(),
                chain.as_bytes().len(),
                out_hex.as_mut_ptr(),
                out_hex.len()
            )
        );
        assert_invalid!(
            crate::governance::indra_build_governance_reveal_with_handle(
                session,
                id.as_ptr(),
                1,
                nonce.as_ptr(),
                INDRA_KEY_HANDLE_INVALID,
                INDRA_KEY_HANDLE_INVALID,
                1,
                1,
                chain.as_ptr(),
                chain.as_bytes().len(),
                out_hex.as_mut_ptr(),
                out_hex.len()
            )
        );
        assert_invalid!(
            crate::governance::indra_build_governance_redelegate_with_handle(
                session,
                id.as_ptr(),
                id.as_ptr(),
                id.as_ptr(),
                1,
                INDRA_KEY_HANDLE_INVALID,
                1,
                chain.as_ptr(),
                chain.as_bytes().len(),
                out_hex.as_mut_ptr(),
                out_hex.len()
            )
        );
        assert_invalid!(
            crate::governance::indra_build_governance_execute_with_handle(
                session,
                id.as_ptr(),
                INDRA_KEY_HANDLE_INVALID,
                1,
                chain.as_ptr(),
                chain.as_bytes().len(),
                out_hex.as_mut_ptr(),
                out_hex.len()
            )
        );
        assert_eq!(
            unsafe {
                crate::governance::indra_build_governance_cancel_with_handle(
                    session,
                    id.as_ptr(),
                    INDRA_KEY_HANDLE_INVALID,
                    INDRA_KEY_HANDLE_INVALID,
                    1,
                    1,
                    chain.as_ptr(),
                    chain.as_bytes().len(),
                    out_hex.as_mut_ptr(),
                    out_hex.len(),
                )
            },
            INVALID_HANDLE
        );
    }

    #[test]
    fn destroy_session_invalidates_all_existing_handles() {
        let _guard = test_lock();
        let session = create_session();
        let (h1, _p1) = handle_from_seed(session, [0x61; 32]);
        let (h2, _p2) = handle_from_seed(session, [0x62; 32]);
        assert_eq!(indra_destroy_session(session), OK);
        let mut fetched = IndraPublicKeyInfo::zeroed();
        assert_eq!(
            unsafe { indra_key_handle_public(session, h1, &mut fetched) },
            IndraError::InvalidSession.code()
        );
        assert_eq!(
            unsafe { indra_key_handle_public(session, h2, &mut fetched) },
            IndraError::InvalidSession.code()
        );
    }

    #[test]
    fn concurrent_handle_builds_do_not_cross_use_or_panic() {
        let _guard = test_lock();
        let mut workers = Vec::new();
        for i in 0..8u8 {
            workers.push(thread::spawn(move || {
                let session = create_session();
                let (handle, public) = handle_from_seed(session, [i + 1; 32]);
                let chain = CString::new("indra-testnet-1").unwrap();
                let mut out = out();
                let code = unsafe {
                    crate::staking::indra_build_delegator_claim_rewards_with_handle(
                        session,
                        public.validator_id.as_ptr(),
                        handle,
                        u64::from(i) + 1,
                        chain.as_ptr(),
                        chain.as_bytes().len(),
                        out.as_mut_ptr(),
                        out.len(),
                    )
                };
                assert_eq!(code, OK);
                let op = unsafe { decode_staking(&out) };
                match op.body {
                    StakingOpBody::ClaimRewards { validator_id, .. } => {
                        assert_eq!(validator_id.0, public.validator_id);
                    }
                    other => panic!("unexpected staking op: {other:?}"),
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
    }

    #[test]
    fn same_handle_concurrent_signing_is_isolated_and_valid() {
        let _guard = test_lock();
        let session = create_session();
        let (handle, public) = handle_from_seed(session, [0x71; 32]);
        let mut workers = Vec::new();
        for nonce in 1..=4u64 {
            workers.push(thread::spawn(move || {
                let chain = CString::new("indra-testnet-1").unwrap();
                let mut output = out();
                let code = unsafe {
                    crate::staking::indra_build_delegator_claim_rewards_with_handle(
                        session,
                        public.validator_id.as_ptr(),
                        handle,
                        nonce,
                        chain.as_ptr(),
                        chain.as_bytes().len(),
                        output.as_mut_ptr(),
                        output.len(),
                    )
                };
                assert_eq!(code, OK);
                let op = unsafe { decode_staking(&output) };
                assert_eq!(op.nonce, nonce);
                assert_eq!(op.signer_id().0, public.validator_id);
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
    }

    #[test]
    fn destroy_actively_revokes_in_flight_signing_before_publication() {
        use std::sync::{mpsc, Arc, Barrier};
        let _guard = test_lock();
        let session = create_session();
        let (handle, public) = handle_from_seed(session, [0x72; 32]);
        let reached = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let revoked = Arc::new(Barrier::new(2));
        handles::install_checkpoint_hook(Arc::clone(&reached), Arc::clone(&release));
        handles::install_revocation_hook(Arc::clone(&revoked));

        let signer = thread::spawn(move || {
            let chain = CString::new("indra-testnet-1").unwrap();
            let mut output = vec![0x5A as c_char; INDRA_OP_HEX_MAX_BYTES];
            let code = unsafe {
                crate::staking::indra_build_delegator_claim_rewards_with_handle(
                    session,
                    public.validator_id.as_ptr(),
                    handle,
                    1,
                    chain.as_ptr(),
                    chain.as_bytes().len(),
                    output.as_mut_ptr(),
                    output.len(),
                )
            };
            (code, output)
        });
        reached.wait();
        let (destroyed_tx, destroyed_rx) = mpsc::channel();
        let destroyer = thread::spawn(move || {
            let code = indra_destroy_key_handle(session, handle);
            destroyed_tx.send(code).unwrap();
        });
        revoked.wait();
        assert!(
            destroyed_rx.try_recv().is_err(),
            "destroy returned before lease drained"
        );
        release.wait();
        let (code, output) = signer.join().unwrap();
        assert_eq!(code, IndraError::HandleRevoked.code());
        assert_eq!(output[0], 0);
        assert!(output[1..].iter().all(|byte| *byte == 0x5A as c_char));
        assert_eq!(destroyed_rx.recv().unwrap(), OK);
        destroyer.join().unwrap();
    }

    #[test]
    fn session_teardown_revokes_and_waits_for_all_active_leases() {
        use std::sync::mpsc;
        let _guard = test_lock();
        let session = create_session();
        let (first_handle, _) = handle_from_seed(session, [0x7A; 32]);
        let (second_handle, _) = handle_from_seed(session, [0x7B; 32]);
        let first_lease = handles::acquire_hot_signing_lease(session, first_handle).unwrap();
        let second_lease = handles::acquire_hot_signing_lease(session, second_handle).unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let teardown = thread::spawn(move || {
            done_tx.send(indra_destroy_session(session)).unwrap();
        });

        for _ in 0..10_000 {
            if first_lease.checkpoint() == Err(IndraError::HandleRevoked)
                && second_lease.checkpoint() == Err(IndraError::HandleRevoked)
            {
                break;
            }
            thread::yield_now();
        }
        assert_eq!(first_lease.checkpoint(), Err(IndraError::HandleRevoked));
        assert_eq!(second_lease.checkpoint(), Err(IndraError::HandleRevoked));
        assert!(done_rx.try_recv().is_err());
        drop(first_lease);
        assert!(done_rx.try_recv().is_err());
        drop(second_lease);
        assert_eq!(done_rx.recv().unwrap(), OK);
        teardown.join().unwrap();
    }

    #[test]
    fn cross_session_key_and_result_capabilities_are_rejected() {
        let _guard = test_lock();
        let first = create_session();
        let second = create_session();
        let (handle, _) = handle_from_seed(first, [0x73; 32]);
        let mut public = IndraPublicKeyInfo::zeroed();
        assert_eq!(
            unsafe { indra_key_handle_public(second, handle, &mut public) },
            INVALID_HANDLE
        );

        let result = tx::BuiltTxOwned {
            tx_id: [7u8; 32],
            tx_bytes: vec![1u8, 2, 3].into_boxed_slice(),
            change_spark: 9,
            spent_indices: vec![4usize].into_boxed_slice(),
        };
        let result_handle = handles::store_result(first, result).unwrap();
        let mut bytes = [0u8; 3];
        assert_eq!(
            unsafe {
                indra_result_copy_tx_bytes(second, result_handle, bytes.as_mut_ptr(), bytes.len())
            },
            IndraError::InvalidResult.code()
        );
    }

    #[test]
    fn opaque_result_accessors_and_double_destroy_fail_closed() {
        let _guard = test_lock();
        let session = create_session();
        let owned = tx::BuiltTxOwned {
            tx_id: [8u8; 32],
            tx_bytes: vec![9u8, 10, 11].into_boxed_slice(),
            change_spark: 12,
            spent_indices: vec![2usize, 5].into_boxed_slice(),
        };
        let result = handles::store_result(session, owned).unwrap();
        let mut bytes = [0u8; 3];
        let mut indices = [0usize; 2];
        assert_eq!(
            unsafe { indra_result_copy_tx_bytes(session, result, bytes.as_mut_ptr(), bytes.len()) },
            OK
        );
        assert_eq!(bytes, [9, 10, 11]);
        assert_eq!(
            unsafe {
                indra_result_copy_spent_indices(
                    session,
                    result,
                    indices.as_mut_ptr(),
                    indices.len(),
                )
            },
            OK
        );
        assert_eq!(indices, [2, 5]);
        assert_eq!(indra_destroy_result(session, result), OK);
        assert_eq!(
            indra_destroy_result(session, result),
            IndraError::InvalidResult.code()
        );
    }

    #[test]
    fn exact_length_utf8_input_never_scans_past_short_allocation() {
        let allocation = Box::new([b'x', 0]);
        let parsed = unsafe {
            bounded_utf8(
                allocation.as_ptr().cast::<c_char>(),
                1,
                MAX_FFI_STRING_BYTES,
            )
        }
        .unwrap();
        assert_eq!(parsed, "x");
        assert_eq!(
            unsafe {
                bounded_utf8(
                    allocation.as_ptr().cast::<c_char>(),
                    MAX_FFI_STRING_BYTES + 1,
                    MAX_FFI_STRING_BYTES,
                )
            },
            Err(IndraError::InvalidParam)
        );
    }

    #[test]
    fn secret_containers_have_drop_guaranteed_zeroization() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<indra_cli::KeysFile>();
        assert_zeroize_on_drop::<indra_cli::ValidatorKeys>();
        assert_zeroize_on_drop::<indra_crypto::PqKeypair>();

        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        struct PanicProbe(Arc<AtomicBool>);
        impl zeroize::Zeroize for PanicProbe {
            fn zeroize(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let observed = Arc::new(AtomicBool::new(false));
        let result = std::panic::catch_unwind({
            let observed = Arc::clone(&observed);
            move || {
                let _secret = zeroize::Zeroizing::new(PanicProbe(observed));
                panic!("exercise unwind cleanup");
            }
        });
        assert!(result.is_err());
        assert!(observed.load(Ordering::SeqCst));
    }

    #[test]
    fn header_abi_sync_check_covers_source_and_xcframework_headers() {
        let _guard = test_lock();
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let source = manifest.join("include/indra.h");
        let xc_root = manifest.parent().unwrap().join("IndraFFI.xcframework");
        let source_header = fs::read_to_string(&source).unwrap();
        for header in [
            xc_root.join("ios-arm64/Headers/indra.h"),
            xc_root.join("ios-arm64_x86_64-simulator/Headers/indra.h"),
        ] {
            let bundled = fs::read_to_string(&header).unwrap();
            assert_eq!(
                bundled,
                source_header,
                "stale FFI header: {}",
                header.display()
            );
        }
    }

    #[test]
    fn c_header_struct_layouts_match_rust_repr_c_exactly() {
        let _guard = test_lock();
        let _: unsafe extern "C" fn(*const u8, *const u8, *mut u8) -> i32 = indra_validator_id;
        let _: unsafe extern "C" fn(*mut IndraSessionHandle) -> i32 = indra_create_session;
        let _: extern "C" fn(IndraSessionHandle) -> i32 = indra_destroy_session;
        let _: unsafe extern "C" fn(
            IndraSessionHandle,
            *const IndraTxParams,
            *mut IndraResultHandle,
            *mut IndraTxResultMetadata,
        ) -> i32 = indra_build_tx_with_handle;
        let _: unsafe extern "C" fn(IndraSessionHandle, IndraResultHandle, *mut u8, usize) -> i32 =
            indra_result_copy_tx_bytes;
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let temp = std::env::temp_dir().join(format!("indra-ffi-layout-{}", std::process::id()));
        fs::create_dir_all(&temp).unwrap();
        let source = temp.join("layout.c");
        let binary = temp.join("layout-probe");
        fs::write(
            &source,
            r#"#include <stddef.h>
#include <stdio.h>
#include "indra.h"
typedef int32_t (*IndraValidatorIdFn)(const uint8_t*, const uint8_t*, uint8_t*);
#define CHECK(fn, ty) _Static_assert(__builtin_types_compatible_p(__typeof__(&(fn)), ty), "signature mismatch: " #fn)
_Static_assert(
  __builtin_types_compatible_p(__typeof__(&indra_validator_id), IndraValidatorIdFn),
  "indra_validator_id declaration must bind both hybrid public-key components");
CHECK(indra_create_session, int32_t (*)(IndraSessionHandle*));
CHECK(indra_destroy_session, int32_t (*)(IndraSessionHandle));
CHECK(indra_keygen_handle, int32_t (*)(IndraSessionHandle, const uint8_t*, IndraKeyHandle*, IndraPublicKeyInfo*));
CHECK(indra_cold_key_handle_from_seeds, int32_t (*)(IndraSessionHandle, const uint8_t*, const uint8_t*, IndraKeyHandle*, IndraColdPublicKeyInfo*));
CHECK(indra_keygen_from_mnemonic_handle, int32_t (*)(IndraSessionHandle, const char*, size_t, IndraKeyHandle*, IndraPublicKeyInfo*));
CHECK(indra_key_handle_public, int32_t (*)(IndraSessionHandle, IndraKeyHandle, IndraPublicKeyInfo*));
CHECK(indra_cold_key_handle_public, int32_t (*)(IndraSessionHandle, IndraKeyHandle, IndraColdPublicKeyInfo*));
CHECK(indra_destroy_key_handle, int32_t (*)(IndraSessionHandle, IndraKeyHandle));
CHECK(indra_build_tx_with_handle, int32_t (*)(IndraSessionHandle, const IndraTxParams*, IndraResultHandle*, IndraTxResultMetadata*));
CHECK(indra_build_register_validator_with_handle, int32_t (*)(IndraSessionHandle, uint32_t, const uint8_t*, IndraKeyHandle, IndraKeyHandle, uint64_t, const char*, size_t, char*, size_t));
CHECK(indra_build_self_stake_with_handle, int32_t (*)(IndraSessionHandle, const uint8_t*, IndraKeyHandle, IndraKeyHandle, uint64_t, uint64_t, const char*, size_t, char*, size_t));
CHECK(indra_build_delegator_claim_rewards_with_handle, int32_t (*)(IndraSessionHandle, const uint8_t*, IndraKeyHandle, uint64_t, const char*, size_t, char*, size_t));
CHECK(indra_build_validator_claim_rewards_with_handle, int32_t (*)(IndraSessionHandle, IndraKeyHandle, IndraKeyHandle, uint64_t, uint64_t, const char*, size_t, char*, size_t));
CHECK(indra_build_set_commission_with_handle, int32_t (*)(IndraSessionHandle, uint32_t, IndraKeyHandle, IndraKeyHandle, uint64_t, uint64_t, const char*, size_t, char*, size_t));
CHECK(indra_build_set_auto_delegate_with_handle, int32_t (*)(IndraSessionHandle, const uint8_t*, IndraKeyHandle, IndraKeyHandle, uint64_t, uint64_t, const char*, size_t, char*, size_t));
CHECK(indra_build_governance_propose_with_handle, int32_t (*)(IndraSessionHandle, const char*, size_t, const char*, size_t, const char*, size_t, const uint8_t*, IndraKeyHandle, IndraKeyHandle, uint64_t, uint64_t, const char*, size_t, char*, size_t));
CHECK(indra_build_governance_commit_with_handle, int32_t (*)(IndraSessionHandle, const uint8_t*, uint8_t, uint8_t*, uint8_t*, IndraKeyHandle, IndraKeyHandle, uint64_t, uint64_t, const char*, size_t, char*, size_t));
CHECK(indra_build_governance_reveal_with_handle, int32_t (*)(IndraSessionHandle, const uint8_t*, uint8_t, const uint8_t*, IndraKeyHandle, IndraKeyHandle, uint64_t, uint64_t, const char*, size_t, char*, size_t));
CHECK(indra_build_governance_redelegate_with_handle, int32_t (*)(IndraSessionHandle, const uint8_t*, const uint8_t*, const uint8_t*, uint64_t, IndraKeyHandle, uint64_t, const char*, size_t, char*, size_t));
CHECK(indra_build_governance_execute_with_handle, int32_t (*)(IndraSessionHandle, const uint8_t*, IndraKeyHandle, uint64_t, const char*, size_t, char*, size_t));
CHECK(indra_build_governance_cancel_with_handle, int32_t (*)(IndraSessionHandle, const uint8_t*, IndraKeyHandle, IndraKeyHandle, uint64_t, uint64_t, const char*, size_t, char*, size_t));
CHECK(indra_result_copy_tx_bytes, int32_t (*)(IndraSessionHandle, IndraResultHandle, uint8_t*, size_t));
CHECK(indra_result_copy_spent_indices, int32_t (*)(IndraSessionHandle, IndraResultHandle, size_t*, size_t));
CHECK(indra_destroy_result, int32_t (*)(IndraSessionHandle, IndraResultHandle));
int main(void) {
  printf("%zu %zu %zu %zu %zu %zu ",
    sizeof(IndraSessionHandle), _Alignof(IndraSessionHandle),
    sizeof(IndraKeyHandle), _Alignof(IndraKeyHandle),
    sizeof(IndraResultHandle), _Alignof(IndraResultHandle));
  printf("%zu %zu %zu %zu %zu %zu ",
    sizeof(IndraPublicKeyInfo), _Alignof(IndraPublicKeyInfo),
    offsetof(IndraPublicKeyInfo, validator_id), offsetof(IndraPublicKeyInfo, classical_pk),
    offsetof(IndraPublicKeyInfo, pq_pk), offsetof(IndraPublicKeyInfo, vrf_pk));
  printf("%zu %zu %zu %zu ", sizeof(IndraColdPublicKeyInfo), _Alignof(IndraColdPublicKeyInfo),
    offsetof(IndraColdPublicKeyInfo, classical_pk), offsetof(IndraColdPublicKeyInfo, pq_pk));
  printf("%zu %zu %zu %zu %zu %zu %zu %zu %zu ",
    sizeof(IndraUtxoEntry), _Alignof(IndraUtxoEntry),
    offsetof(IndraUtxoEntry, utxo_id), offsetof(IndraUtxoEntry, value_spark),
    offsetof(IndraUtxoEntry, created_height), offsetof(IndraUtxoEntry, tx_index),
    offsetof(IndraUtxoEntry, out_index), offsetof(IndraUtxoEntry, spent),
    sizeof(((IndraUtxoEntry*)0)->spent));
  printf("%zu %zu %zu %zu %zu %zu %zu %zu %zu %zu ",
    sizeof(IndraTxParams), _Alignof(IndraTxParams),
    offsetof(IndraTxParams, recipient_address), offsetof(IndraTxParams, recipient_address_len),
    offsetof(IndraTxParams, amount_spark), offsetof(IndraTxParams, fee_spark),
    offsetof(IndraTxParams, utxos), offsetof(IndraTxParams, utxo_count),
    offsetof(IndraTxParams, sender_handle), offsetof(IndraTxParams, chain_id_len));
  printf("%zu %zu %zu %zu %zu %zu\n",
    sizeof(IndraTxResultMetadata), _Alignof(IndraTxResultMetadata),
    offsetof(IndraTxResultMetadata, tx_id), offsetof(IndraTxResultMetadata, tx_bytes_len),
    offsetof(IndraTxResultMetadata, change_spark), offsetof(IndraTxResultMetadata, spent_count));
  return 0;
}"#,
        )
        .unwrap();
        let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
        let compiled = Command::new(compiler)
            .arg("-std=c11")
            .arg("-I")
            .arg(manifest.join("include"))
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "C layout probe failed: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let output = Command::new(&binary).output().unwrap();
        assert!(output.status.success());
        let c: Vec<usize> = String::from_utf8(output.stdout)
            .unwrap()
            .split_whitespace()
            .map(|value| value.parse().unwrap())
            .collect();
        let rust = vec![
            std::mem::size_of::<IndraSessionHandle>(),
            std::mem::align_of::<IndraSessionHandle>(),
            std::mem::size_of::<IndraKeyHandle>(),
            std::mem::align_of::<IndraKeyHandle>(),
            std::mem::size_of::<IndraResultHandle>(),
            std::mem::align_of::<IndraResultHandle>(),
            std::mem::size_of::<IndraPublicKeyInfo>(),
            std::mem::align_of::<IndraPublicKeyInfo>(),
            std::mem::offset_of!(IndraPublicKeyInfo, validator_id),
            std::mem::offset_of!(IndraPublicKeyInfo, classical_pk),
            std::mem::offset_of!(IndraPublicKeyInfo, pq_pk),
            std::mem::offset_of!(IndraPublicKeyInfo, vrf_pk),
            std::mem::size_of::<IndraColdPublicKeyInfo>(),
            std::mem::align_of::<IndraColdPublicKeyInfo>(),
            std::mem::offset_of!(IndraColdPublicKeyInfo, classical_pk),
            std::mem::offset_of!(IndraColdPublicKeyInfo, pq_pk),
            std::mem::size_of::<IndraUtxoEntry>(),
            std::mem::align_of::<IndraUtxoEntry>(),
            std::mem::offset_of!(IndraUtxoEntry, utxo_id),
            std::mem::offset_of!(IndraUtxoEntry, value_spark),
            std::mem::offset_of!(IndraUtxoEntry, created_height),
            std::mem::offset_of!(IndraUtxoEntry, tx_index),
            std::mem::offset_of!(IndraUtxoEntry, out_index),
            std::mem::offset_of!(IndraUtxoEntry, spent),
            std::mem::size_of::<u8>(),
            std::mem::size_of::<IndraTxParams>(),
            std::mem::align_of::<IndraTxParams>(),
            std::mem::offset_of!(IndraTxParams, recipient_address),
            std::mem::offset_of!(IndraTxParams, recipient_address_len),
            std::mem::offset_of!(IndraTxParams, amount_spark),
            std::mem::offset_of!(IndraTxParams, fee_spark),
            std::mem::offset_of!(IndraTxParams, utxos),
            std::mem::offset_of!(IndraTxParams, utxo_count),
            std::mem::offset_of!(IndraTxParams, sender_handle),
            std::mem::offset_of!(IndraTxParams, chain_id_len),
            std::mem::size_of::<IndraTxResultMetadata>(),
            std::mem::align_of::<IndraTxResultMetadata>(),
            std::mem::offset_of!(IndraTxResultMetadata, tx_id),
            std::mem::offset_of!(IndraTxResultMetadata, tx_bytes_len),
            std::mem::offset_of!(IndraTxResultMetadata, change_spark),
            std::mem::offset_of!(IndraTxResultMetadata, spent_count),
        ];
        eprintln!("C layout:    {c:?}");
        eprintln!("Rust layout: {rust:?}");
        assert_eq!(c, rust, "C header and Rust repr(C) layouts diverged");
        let _ = fs::remove_dir_all(temp);
    }
}
