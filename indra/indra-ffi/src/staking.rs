//! C FFI builders for INDRA staking operations.

use std::{
    ffi::c_char,
    panic::{catch_unwind, UnwindSafe},
};

use indra_cli::tx_builder::{
    build_claim_rewards_op, build_delegate_op, build_register_validator_op, build_self_stake_op,
    build_set_auto_delegate_op, build_set_commission_op,
};
use indra_core::types::primitives::Bytes32;
use indra_crypto::hybrid::HybridKeypair;

use crate::{
    bounded_utf8, errors::IndraError, handles, IndraKeyHandle, IndraSessionHandle,
    INDRA_OP_HEX_MAX_BYTES, MAX_FFI_STRING_BYTES,
};

pub(crate) unsafe fn read_bytes32(ptr: *const u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(std::slice::from_raw_parts(ptr, 32));
    out
}

pub(crate) unsafe fn read_chain_id(
    chain_id: *const c_char,
    chain_id_len: usize,
) -> Result<String, IndraError> {
    bounded_utf8(chain_id, chain_id_len, MAX_FFI_STRING_BYTES)
}

pub(crate) unsafe fn write_hex_to_buf(
    hex: &str,
    out: *mut c_char,
    out_len: usize,
) -> Result<(), IndraError> {
    let needed = hex.len().saturating_add(1);
    if out_len > INDRA_OP_HEX_MAX_BYTES {
        return Err(IndraError::InvalidParam);
    }
    if out_len < needed {
        return Err(IndraError::BufferTooSmall);
    }
    let out_bytes = std::slice::from_raw_parts_mut(out.cast::<u8>(), out_len);
    out_bytes[..hex.len()].copy_from_slice(hex.as_bytes());
    out_bytes[hex.len()] = 0;
    Ok(())
}

unsafe fn build_with_handle<F>(args: StakingHandleArgs, build: F) -> i32
where
    F: FnOnce(&HybridKeypair, &[u8; 32], u64, &str) -> Result<String, IndraError> + UnwindSafe,
{
    if args.chain_id.is_null() || args.out_hex.is_null() {
        return IndraError::NullPointer.code();
    }
    if args.out_len != 0 {
        *args.out_hex = 0;
    }

    match catch_unwind(|| {
        let lease = handles::acquire_signing_lease(args.session, args.handle)?;
        lease.checkpoint()?;
        let keypair = lease.material().keypair()?;
        let chain = read_chain_id(args.chain_id, args.chain_id_len)?;
        let hex = build(
            &keypair,
            &lease.material().public.validator_id,
            args.nonce,
            &chain,
        )?;
        lease.publish(|| write_hex_to_buf(&hex, args.out_hex, args.out_len))
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

#[derive(Clone, Copy)]
struct StakingHandleArgs {
    session: IndraSessionHandle,
    handle: IndraKeyHandle,
    nonce: u64,
    chain_id: *const c_char,
    chain_id_len: usize,
    out_hex: *mut c_char,
    out_len: usize,
}

/// Build and sign a RegisterValidator staking operation using an opaque handle.
/// The VRF public key is derived from the handle's stored public metadata.
#[no_mangle]
pub unsafe extern "C" fn indra_build_register_validator_with_handle(
    session: IndraSessionHandle,
    commission_bps: u32,
    deposit_utxo_id: *const u8,
    handle: IndraKeyHandle,
    nonce: u64,
    chain_id: *const c_char,
    chain_id_len: usize,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if deposit_utxo_id.is_null() {
        return IndraError::NullPointer.code();
    }
    if commission_bps > 10_000 {
        return IndraError::InvalidParam.code();
    }
    build_with_handle(
        StakingHandleArgs {
            session,
            handle,
            nonce,
            chain_id,
            chain_id_len,
            out_hex,
            out_len,
        },
        |keypair, _validator_id, nonce, chain| {
            let bond = Bytes32::from(read_bytes32(deposit_utxo_id));
            let vrf = handles::public_info(session, handle)?.vrf_pk;
            build_register_validator_op(commission_bps, bond, keypair, vrf, nonce, chain)
                .map(|built| built.op_hex)
                .map_err(IndraError::from)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn indra_build_self_stake_with_handle(
    session: IndraSessionHandle,
    deposit_utxo_id: *const u8,
    handle: IndraKeyHandle,
    nonce: u64,
    chain_id: *const c_char,
    chain_id_len: usize,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if deposit_utxo_id.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_handle(
        StakingHandleArgs {
            session,
            handle,
            nonce,
            chain_id,
            chain_id_len,
            out_hex,
            out_len,
        },
        |keypair, _validator_id, nonce, chain| {
            build_self_stake_op(
                Bytes32::from(read_bytes32(deposit_utxo_id)),
                keypair,
                nonce,
                chain,
            )
            .map(|built| built.op_hex)
            .map_err(IndraError::from)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn indra_build_delegate_with_handle(
    session: IndraSessionHandle,
    validator_id: *const u8,
    deposit_utxo_id: *const u8,
    handle: IndraKeyHandle,
    nonce: u64,
    chain_id: *const c_char,
    chain_id_len: usize,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if validator_id.is_null() || deposit_utxo_id.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_handle(
        StakingHandleArgs {
            session,
            handle,
            nonce,
            chain_id,
            chain_id_len,
            out_hex,
            out_len,
        },
        |keypair, _signer_id, nonce, chain| {
            build_delegate_op(
                Bytes32::from(read_bytes32(validator_id)),
                Bytes32::from(read_bytes32(deposit_utxo_id)),
                keypair,
                nonce,
                chain,
            )
            .map(|built| built.op_hex)
            .map_err(IndraError::from)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn indra_build_claim_rewards_with_handle(
    session: IndraSessionHandle,
    handle: IndraKeyHandle,
    nonce: u64,
    chain_id: *const c_char,
    chain_id_len: usize,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    build_with_handle(
        StakingHandleArgs {
            session,
            handle,
            nonce,
            chain_id,
            chain_id_len,
            out_hex,
            out_len,
        },
        |keypair, validator_id, nonce, chain| {
            build_claim_rewards_op(Bytes32::from(*validator_id), keypair, nonce, chain)
                .map(|built| built.op_hex)
                .map_err(IndraError::from)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn indra_build_set_commission_with_handle(
    session: IndraSessionHandle,
    new_commission_bps: u32,
    handle: IndraKeyHandle,
    nonce: u64,
    chain_id: *const c_char,
    chain_id_len: usize,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if new_commission_bps > 10_000 {
        return IndraError::InvalidParam.code();
    }
    build_with_handle(
        StakingHandleArgs {
            session,
            handle,
            nonce,
            chain_id,
            chain_id_len,
            out_hex,
            out_len,
        },
        |keypair, validator_id, nonce, chain| {
            build_set_commission_op(
                Bytes32::from(*validator_id),
                new_commission_bps,
                keypair,
                nonce,
                chain,
            )
            .map(|built| built.op_hex)
            .map_err(IndraError::from)
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn indra_build_set_auto_delegate_with_handle(
    session: IndraSessionHandle,
    target_validator_id: *const u8,
    handle: IndraKeyHandle,
    nonce: u64,
    chain_id: *const c_char,
    chain_id_len: usize,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if target_validator_id.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_handle(
        StakingHandleArgs {
            session,
            handle,
            nonce,
            chain_id,
            chain_id_len,
            out_hex,
            out_len,
        },
        |keypair, validator_id, nonce, chain| {
            build_set_auto_delegate_op(
                Bytes32::from(*validator_id),
                Bytes32::from(read_bytes32(target_validator_id)),
                keypair,
                nonce,
                chain,
            )
            .map(|built| built.op_hex)
            .map_err(IndraError::from)
        },
    )
}
