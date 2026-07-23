//! C FFI helpers for payment blinding keys and notes.

use std::{ffi::c_char, panic::catch_unwind};

use indra_crypto::{
    recipient_derive_payment_blinding_v1, sender_derive_payment_blinding_v1, PaymentBlindingNoteV1,
    PaymentKeypairV1, PaymentPubKeyV1,
};

use crate::{
    bounded_cstr, errors::IndraError, handles, IndraKeyHandle, BYTES32_LEN,
    PAYMENT_KEYPAIR_V1_BYTES, PAYMENT_NOTE_V1_BYTES, PAYMENT_PUBKEY_V1_BYTES,
};

unsafe fn read_bytes32(ptr: *const u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(std::slice::from_raw_parts(ptr, BYTES32_LEN));
    out
}

unsafe fn read_payment_pubkey(ptr: *const u8) -> Result<PaymentPubKeyV1, IndraError> {
    let bytes = std::slice::from_raw_parts(ptr, PAYMENT_PUBKEY_V1_BYTES);
    PaymentPubKeyV1::decode(bytes).map_err(|_| IndraError::InvalidParam)
}

unsafe fn read_payment_keypair(ptr: *const u8) -> Result<PaymentKeypairV1, IndraError> {
    let bytes = std::slice::from_raw_parts(ptr, PAYMENT_KEYPAIR_V1_BYTES);
    PaymentKeypairV1::decode(bytes).map_err(|_| IndraError::InvalidParam)
}

unsafe fn read_payment_note(ptr: *const u8) -> Result<PaymentBlindingNoteV1, IndraError> {
    let bytes = std::slice::from_raw_parts(ptr, PAYMENT_NOTE_V1_BYTES);
    PaymentBlindingNoteV1::decode(bytes).map_err(|_| IndraError::InvalidParam)
}

unsafe fn write_fixed(out: *mut u8, bytes: &[u8]) {
    std::slice::from_raw_parts_mut(out, bytes.len()).copy_from_slice(bytes);
}

/// Generate a fresh payment keypair and public key.
///
/// # Safety
///
/// `out_keypair` and `out_pubkey` must point to writable buffers of
/// `INDRA_PAYMENT_KEYPAIR_V1_BYTES` and `INDRA_PAYMENT_PUBKEY_V1_BYTES`.
#[no_mangle]
pub unsafe extern "C" fn indra_payment_keygen(out_keypair: *mut u8, out_pubkey: *mut u8) -> i32 {
    if out_keypair.is_null() || out_pubkey.is_null() {
        return IndraError::NullPointer.code();
    }

    match catch_unwind(|| {
        let keypair = PaymentKeypairV1::generate();
        let pubkey = keypair.public_key();
        write_fixed(out_keypair, &keypair.encode());
        write_fixed(out_pubkey, &pubkey.encode());
    }) {
        Ok(()) => IndraError::Ok.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Copy the payment public key associated with an opaque key handle.
///
/// # Safety
///
/// `out_pubkey` must point to a writable `INDRA_PAYMENT_PUBKEY_V1_BYTES` buffer.
#[no_mangle]
pub unsafe extern "C" fn indra_key_handle_payment_pubkey(
    handle: IndraKeyHandle,
    out_pubkey: *mut u8,
) -> i32 {
    if out_pubkey.is_null() {
        return IndraError::NullPointer.code();
    }

    match catch_unwind(|| {
        let pubkey = handles::payment_pubkey(handle)?;
        write_fixed(out_pubkey, &pubkey.encode());
        Ok::<(), IndraError>(())
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Copy the payment private keypair associated with an opaque key handle.
///
/// # Safety
///
/// `out_keypair` must point to a writable `INDRA_PAYMENT_KEYPAIR_V1_BYTES`
/// buffer. The caller is responsible for protecting and zeroizing it.
#[no_mangle]
pub unsafe extern "C" fn indra_key_handle_payment_keypair(
    handle: IndraKeyHandle,
    out_keypair: *mut u8,
) -> i32 {
    if out_keypair.is_null() {
        return IndraError::NullPointer.code();
    }

    match catch_unwind(|| {
        let keypair = handles::payment_keypair(handle)?;
        write_fixed(out_keypair, &keypair.encode());
        Ok::<(), IndraError>(())
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Sender-side payment note construction.
///
/// # Safety
///
/// `recipient_payment_pubkey`, `owner_id`, `chain_id`, `out_note`, and
/// `out_blinding` must be valid for the documented fixed lengths.
#[no_mangle]
pub unsafe extern "C" fn indra_derive_payment_note(
    recipient_payment_pubkey: *const u8,
    owner_id: *const u8,
    chain_id: *const c_char,
    output_index: u32,
    value_spark: u64,
    lock_height: u64,
    out_note: *mut u8,
    out_blinding: *mut u8,
) -> i32 {
    if recipient_payment_pubkey.is_null()
        || owner_id.is_null()
        || chain_id.is_null()
        || out_note.is_null()
        || out_blinding.is_null()
    {
        return IndraError::NullPointer.code();
    }

    match catch_unwind(|| {
        let pubkey = read_payment_pubkey(recipient_payment_pubkey)?;
        let owner = read_bytes32(owner_id);
        let chain = bounded_cstr(chain_id)?;
        let derived = sender_derive_payment_blinding_v1(
            &pubkey,
            chain.as_bytes(),
            owner,
            output_index,
            value_spark,
            lock_height,
        )
        .map_err(|_| IndraError::InvalidParam)?;
        write_fixed(out_note, &derived.note.encode());
        write_fixed(out_blinding, &derived.blinding);
        Ok::<(), IndraError>(())
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Recipient-side payment blinding recovery from an encoded keypair and note.
///
/// # Safety
///
/// `payment_keypair`, `note`, `chain_id`, and `out_blinding` must be valid for
/// the documented fixed lengths.
#[no_mangle]
pub unsafe extern "C" fn indra_recover_payment_blinding(
    payment_keypair: *const u8,
    note: *const u8,
    chain_id: *const c_char,
    output_index: u32,
    value_spark: u64,
    lock_height: u64,
    out_blinding: *mut u8,
) -> i32 {
    if payment_keypair.is_null() || note.is_null() || chain_id.is_null() || out_blinding.is_null() {
        return IndraError::NullPointer.code();
    }

    match catch_unwind(|| {
        let keypair = read_payment_keypair(payment_keypair)?;
        let note = read_payment_note(note)?;
        let chain = bounded_cstr(chain_id)?;
        let derived = recipient_derive_payment_blinding_v1(
            &keypair,
            &note,
            chain.as_bytes(),
            output_index,
            value_spark,
            lock_height,
        )
        .map_err(|_| IndraError::InvalidParam)?;
        write_fixed(out_blinding, &derived.blinding);
        Ok::<(), IndraError>(())
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Recipient-side payment blinding recovery using an opaque key handle.
///
/// # Safety
///
/// `note`, `chain_id`, and `out_blinding` must be valid for the documented
/// fixed lengths.
#[no_mangle]
pub unsafe extern "C" fn indra_recover_payment_blinding_with_handle(
    handle: IndraKeyHandle,
    note: *const u8,
    chain_id: *const c_char,
    output_index: u32,
    value_spark: u64,
    lock_height: u64,
    out_blinding: *mut u8,
) -> i32 {
    if note.is_null() || chain_id.is_null() || out_blinding.is_null() {
        return IndraError::NullPointer.code();
    }

    match catch_unwind(|| {
        let keypair = handles::payment_keypair(handle)?;
        let note = read_payment_note(note)?;
        let chain = bounded_cstr(chain_id)?;
        let derived = recipient_derive_payment_blinding_v1(
            &keypair,
            &note,
            chain.as_bytes(),
            output_index,
            value_spark,
            lock_height,
        )
        .map_err(|_| IndraError::InvalidParam)?;
        write_fixed(out_blinding, &derived.blinding);
        Ok::<(), IndraError>(())
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}
