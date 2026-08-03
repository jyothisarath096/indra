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
use indra_core::types::staking::StakingBondProof;
use indra_crypto::hybrid::HybridKeypair;
#[cfg(feature = "legacy_raw_keys")]
use indra_crypto::hybrid::{ClassicalKeypair, PqKeypair};

use crate::{bounded_cstr, errors::IndraError, handles, IndraKeyHandle, INDRA_OP_HEX_MAX_BYTES};
#[cfg(feature = "legacy_raw_keys")]
use crate::{CLASSICAL_SK_BYTES, PQ_PK_BYTES, PQ_SK_BYTES};

#[cfg(feature = "legacy_raw_keys")]
fn reconstruct_keypair(
    classical_seed: &[u8; CLASSICAL_SK_BYTES],
    pq_pk: &[u8; PQ_PK_BYTES],
    pq_sk: &[u8; PQ_SK_BYTES],
) -> Result<HybridKeypair, IndraError> {
    let classical = ClassicalKeypair::from_seed(classical_seed);
    let pq = PqKeypair::from_bytes(pq_pk, pq_sk).map_err(|_| IndraError::KeygenFailed)?;
    Ok(HybridKeypair::new(classical, pq))
}

pub(crate) unsafe fn read_bytes32(ptr: *const u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(std::slice::from_raw_parts(ptr, 32));
    out
}

pub(crate) unsafe fn read_staking_bond_proof(
    bond_value_spark: u64,
    bond_blinding_factor: *const u8,
) -> StakingBondProof {
    let mut blinding = read_bytes32(bond_blinding_factor);
    let proof = StakingBondProof {
        committed_value_spark: bond_value_spark,
        blinding_factor: Bytes32::from(blinding),
    };
    blinding.fill(0);
    proof
}

#[cfg(feature = "legacy_raw_keys")]
pub(crate) unsafe fn read_keypair(
    classical_seed: *const u8,
    pq_pk: *const u8,
    pq_sk: *const u8,
) -> Result<HybridKeypair, IndraError> {
    let mut seed = [0u8; CLASSICAL_SK_BYTES];
    seed.copy_from_slice(std::slice::from_raw_parts(
        classical_seed,
        CLASSICAL_SK_BYTES,
    ));
    let mut pk = [0u8; PQ_PK_BYTES];
    pk.copy_from_slice(std::slice::from_raw_parts(pq_pk, PQ_PK_BYTES));
    let mut sk = [0u8; PQ_SK_BYTES];
    sk.copy_from_slice(std::slice::from_raw_parts(pq_sk, PQ_SK_BYTES));
    let result = reconstruct_keypair(&seed, &pk, &sk);
    seed.fill(0);
    sk.fill(0);
    result
}

pub(crate) unsafe fn read_chain_id(chain_id: *const c_char) -> Result<String, IndraError> {
    bounded_cstr(chain_id)
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

#[cfg(feature = "legacy_raw_keys")]
fn key_ptrs_are_null(
    classical_seed: *const u8,
    pq_pk: *const u8,
    pq_sk: *const u8,
    chain_id: *const c_char,
    out_hex: *mut c_char,
) -> bool {
    classical_seed.is_null()
        || pq_pk.is_null()
        || pq_sk.is_null()
        || chain_id.is_null()
        || out_hex.is_null()
}

#[cfg(feature = "legacy_raw_keys")]
unsafe fn build_with_keypair<F>(args: StakingCommonArgs, build: F) -> i32
where
    F: FnOnce(&HybridKeypair, u64, &str) -> Result<String, IndraError> + UnwindSafe,
{
    if key_ptrs_are_null(
        args.classical_seed,
        args.pq_pk,
        args.pq_sk,
        args.chain_id,
        args.out_hex,
    ) {
        return IndraError::NullPointer.code();
    }

    match catch_unwind(|| {
        let keypair = read_keypair(args.classical_seed, args.pq_pk, args.pq_sk)?;
        let chain = read_chain_id(args.chain_id)?;
        let hex = build(&keypair, args.nonce, &chain)?;
        write_hex_to_buf(&hex, args.out_hex, args.out_len)
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

unsafe fn build_with_handle<F>(args: StakingHandleArgs, build: F) -> i32
where
    F: FnOnce(&HybridKeypair, &[u8; 32], u64, &str) -> Result<String, IndraError> + UnwindSafe,
{
    if args.chain_id.is_null() || args.out_hex.is_null() {
        return IndraError::NullPointer.code();
    }

    match catch_unwind(|| {
        let signing = handles::signing_material(args.handle)?;
        let keypair = signing.keypair()?;
        let chain = read_chain_id(args.chain_id)?;
        let hex = build(&keypair, &signing.public.validator_id, args.nonce, &chain)?;
        write_hex_to_buf(&hex, args.out_hex, args.out_len)
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

#[derive(Clone, Copy)]
#[cfg(feature = "legacy_raw_keys")]
struct StakingCommonArgs {
    classical_seed: *const u8,
    pq_pk: *const u8,
    pq_sk: *const u8,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
}

#[derive(Clone, Copy)]
struct StakingHandleArgs {
    handle: IndraKeyHandle,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
}

/// Build and sign a RegisterValidator staking operation.
///
/// # Safety
///
/// All pointer arguments must be valid and non-null. `classical_seed`,
/// `pq_pk`, `pq_sk`, and `vrf_pk` must reference 32, 2592, 32, and 32
/// readable bytes respectively. `chain_id` must be a valid null-terminated
/// UTF-8 string. `out_hex` must point to a writable buffer of length `out_len`.
#[cfg(feature = "legacy_raw_keys")]
#[no_mangle]
pub unsafe extern "C" fn indra_build_register_validator(
    commission_bps: u32,
    bond_utxo_id: *const u8,
    bond_value_spark: u64,
    bond_blinding_factor: *const u8,
    classical_seed: *const u8,
    pq_pk: *const u8,
    pq_sk: *const u8,
    vrf_pk: *const u8,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if bond_utxo_id.is_null() || bond_blinding_factor.is_null() || vrf_pk.is_null() {
        return IndraError::NullPointer.code();
    }
    if commission_bps > 10_000 {
        return IndraError::InvalidParam.code();
    }
    build_with_keypair(
        StakingCommonArgs {
            classical_seed,
            pq_pk,
            pq_sk,
            nonce,
            chain_id,
            out_hex,
            out_len,
        },
        |keypair, nonce, chain| {
            let bond = Bytes32::from(read_bytes32(bond_utxo_id));
            let vrf = read_bytes32(vrf_pk);
            let proof = read_staking_bond_proof(bond_value_spark, bond_blinding_factor);
            build_register_validator_op(commission_bps, bond, proof, keypair, vrf, nonce, chain)
                .map(|built| built.op_hex)
                .map_err(IndraError::from)
        },
    )
}

/// Build and sign a RegisterValidator staking operation using an opaque handle.
/// The VRF public key is derived from the handle's stored public metadata.
#[no_mangle]
pub unsafe extern "C" fn indra_build_register_validator_with_handle(
    commission_bps: u32,
    bond_utxo_id: *const u8,
    bond_value_spark: u64,
    bond_blinding_factor: *const u8,
    handle: IndraKeyHandle,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if bond_utxo_id.is_null() || bond_blinding_factor.is_null() {
        return IndraError::NullPointer.code();
    }
    if commission_bps > 10_000 {
        return IndraError::InvalidParam.code();
    }
    build_with_handle(
        StakingHandleArgs {
            handle,
            nonce,
            chain_id,
            out_hex,
            out_len,
        },
        |keypair, _validator_id, nonce, chain| {
            let bond = Bytes32::from(read_bytes32(bond_utxo_id));
            let proof = read_staking_bond_proof(bond_value_spark, bond_blinding_factor);
            let vrf = handles::public_info(handle)?.vrf_pk;
            build_register_validator_op(commission_bps, bond, proof, keypair, vrf, nonce, chain)
                .map(|built| built.op_hex)
                .map_err(IndraError::from)
        },
    )
}

/// Build and sign a SelfStake staking operation.
///
/// # Safety
///
/// All pointer arguments must be valid and non-null. `bond_utxo_id` must
/// reference 32 readable bytes. Key and output pointers follow
/// `indra_build_register_validator`.
#[cfg(feature = "legacy_raw_keys")]
#[no_mangle]
pub unsafe extern "C" fn indra_build_self_stake(
    bond_utxo_id: *const u8,
    bond_value_spark: u64,
    bond_blinding_factor: *const u8,
    classical_seed: *const u8,
    pq_pk: *const u8,
    pq_sk: *const u8,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if bond_utxo_id.is_null() || bond_blinding_factor.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_keypair(
        StakingCommonArgs {
            classical_seed,
            pq_pk,
            pq_sk,
            nonce,
            chain_id,
            out_hex,
            out_len,
        },
        |keypair, nonce, chain| {
            build_self_stake_op(
                Bytes32::from(read_bytes32(bond_utxo_id)),
                read_staking_bond_proof(bond_value_spark, bond_blinding_factor),
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
pub unsafe extern "C" fn indra_build_self_stake_with_handle(
    bond_utxo_id: *const u8,
    bond_value_spark: u64,
    bond_blinding_factor: *const u8,
    handle: IndraKeyHandle,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if bond_utxo_id.is_null() || bond_blinding_factor.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_handle(
        StakingHandleArgs {
            handle,
            nonce,
            chain_id,
            out_hex,
            out_len,
        },
        |keypair, _validator_id, nonce, chain| {
            build_self_stake_op(
                Bytes32::from(read_bytes32(bond_utxo_id)),
                read_staking_bond_proof(bond_value_spark, bond_blinding_factor),
                keypair,
                nonce,
                chain,
            )
            .map(|built| built.op_hex)
            .map_err(IndraError::from)
        },
    )
}

/// Build and sign a Delegate staking operation.
///
/// # Safety
///
/// All pointer arguments must be valid and non-null. `validator_id` and
/// `bond_utxo_id` must each reference 32 readable bytes. Key and output
/// pointers follow `indra_build_register_validator`.
#[cfg(feature = "legacy_raw_keys")]
#[no_mangle]
pub unsafe extern "C" fn indra_build_delegate(
    validator_id: *const u8,
    bond_utxo_id: *const u8,
    bond_value_spark: u64,
    bond_blinding_factor: *const u8,
    classical_seed: *const u8,
    pq_pk: *const u8,
    pq_sk: *const u8,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if validator_id.is_null() || bond_utxo_id.is_null() || bond_blinding_factor.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_keypair(
        StakingCommonArgs {
            classical_seed,
            pq_pk,
            pq_sk,
            nonce,
            chain_id,
            out_hex,
            out_len,
        },
        |keypair, nonce, chain| {
            build_delegate_op(
                Bytes32::from(read_bytes32(validator_id)),
                Bytes32::from(read_bytes32(bond_utxo_id)),
                read_staking_bond_proof(bond_value_spark, bond_blinding_factor),
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
    validator_id: *const u8,
    bond_utxo_id: *const u8,
    bond_value_spark: u64,
    bond_blinding_factor: *const u8,
    handle: IndraKeyHandle,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if validator_id.is_null() || bond_utxo_id.is_null() || bond_blinding_factor.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_handle(
        StakingHandleArgs {
            handle,
            nonce,
            chain_id,
            out_hex,
            out_len,
        },
        |keypair, _signer_id, nonce, chain| {
            build_delegate_op(
                Bytes32::from(read_bytes32(validator_id)),
                Bytes32::from(read_bytes32(bond_utxo_id)),
                read_staking_bond_proof(bond_value_spark, bond_blinding_factor),
                keypair,
                nonce,
                chain,
            )
            .map(|built| built.op_hex)
            .map_err(IndraError::from)
        },
    )
}

/// Build and sign a ClaimRewards staking operation.
///
/// # Safety
///
/// All pointer arguments must be valid and non-null. `validator_id` must
/// reference 32 readable bytes. Key and output pointers follow
/// `indra_build_register_validator`.
#[cfg(feature = "legacy_raw_keys")]
#[no_mangle]
pub unsafe extern "C" fn indra_build_claim_rewards(
    validator_id: *const u8,
    classical_seed: *const u8,
    pq_pk: *const u8,
    pq_sk: *const u8,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if validator_id.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_keypair(
        StakingCommonArgs {
            classical_seed,
            pq_pk,
            pq_sk,
            nonce,
            chain_id,
            out_hex,
            out_len,
        },
        |keypair, nonce, chain| {
            build_claim_rewards_op(
                Bytes32::from(read_bytes32(validator_id)),
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
    handle: IndraKeyHandle,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    build_with_handle(
        StakingHandleArgs {
            handle,
            nonce,
            chain_id,
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

/// Build and sign a SetCommission staking operation.
///
/// # Safety
///
/// All pointer arguments must be valid and non-null. `validator_id` must
/// reference 32 readable bytes. Key and output pointers follow
/// `indra_build_register_validator`.
#[cfg(feature = "legacy_raw_keys")]
#[no_mangle]
pub unsafe extern "C" fn indra_build_set_commission(
    validator_id: *const u8,
    new_commission_bps: u32,
    classical_seed: *const u8,
    pq_pk: *const u8,
    pq_sk: *const u8,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if validator_id.is_null() {
        return IndraError::NullPointer.code();
    }
    if new_commission_bps > 10_000 {
        return IndraError::InvalidParam.code();
    }
    build_with_keypair(
        StakingCommonArgs {
            classical_seed,
            pq_pk,
            pq_sk,
            nonce,
            chain_id,
            out_hex,
            out_len,
        },
        |keypair, nonce, chain| {
            build_set_commission_op(
                Bytes32::from(read_bytes32(validator_id)),
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
pub unsafe extern "C" fn indra_build_set_commission_with_handle(
    new_commission_bps: u32,
    handle: IndraKeyHandle,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if new_commission_bps > 10_000 {
        return IndraError::InvalidParam.code();
    }
    build_with_handle(
        StakingHandleArgs {
            handle,
            nonce,
            chain_id,
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

/// Build and sign a SetAutoDelegate staking operation.
///
/// # Safety
///
/// All pointer arguments must be valid and non-null. `validator_id` and
/// `target_validator_id` must each reference 32 readable bytes. Key and output
/// pointers follow `indra_build_register_validator`.
#[cfg(feature = "legacy_raw_keys")]
#[no_mangle]
pub unsafe extern "C" fn indra_build_set_auto_delegate(
    validator_id: *const u8,
    target_validator_id: *const u8,
    classical_seed: *const u8,
    pq_pk: *const u8,
    pq_sk: *const u8,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if validator_id.is_null() || target_validator_id.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_keypair(
        StakingCommonArgs {
            classical_seed,
            pq_pk,
            pq_sk,
            nonce,
            chain_id,
            out_hex,
            out_len,
        },
        |keypair, nonce, chain| {
            build_set_auto_delegate_op(
                Bytes32::from(read_bytes32(validator_id)),
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

#[no_mangle]
pub unsafe extern "C" fn indra_build_set_auto_delegate_with_handle(
    target_validator_id: *const u8,
    handle: IndraKeyHandle,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if target_validator_id.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_handle(
        StakingHandleArgs {
            handle,
            nonce,
            chain_id,
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

#[cfg(all(test, feature = "legacy_raw_keys"))]
mod tests {
    use super::*;
    use crate::{indra_keygen, IndraKeyPair};
    use indra_core::{
        codec::Decode,
        types::staking::{StakingOp, StakingOpBody},
    };
    use std::ffi::{CStr, CString};

    const OK: i32 = IndraError::Ok as i32;

    fn keys() -> IndraKeyPair {
        let mut keys = IndraKeyPair::zeroed();
        unsafe {
            assert_eq!(indra_keygen([0x42u8; 32].as_ptr(), &mut keys), OK);
        }
        keys
    }

    fn out() -> Vec<c_char> {
        vec![0; INDRA_OP_HEX_MAX_BYTES]
    }

    unsafe fn decode(out: &[c_char]) -> StakingOp {
        let hex = CStr::from_ptr(out.as_ptr()).to_str().unwrap();
        StakingOp::decode_exact(&hex::decode(hex).unwrap()).unwrap()
    }

    #[test]
    fn claim_rewards_produces_valid_hex() {
        let keys = keys();
        let chain = CString::new("indra-testnet-1").unwrap();
        let validator_id = [0x01u8; 32];
        let mut out = out();
        let result = unsafe {
            indra_build_claim_rewards(
                validator_id.as_ptr(),
                keys.classical_seed.as_ptr(),
                keys.pq_pk.as_ptr(),
                keys.pq_sk.as_ptr(),
                1,
                chain.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(result, OK);
        let op = unsafe { decode(&out) };
        assert_eq!(op.nonce, 1);
        assert!(matches!(op.body, StakingOpBody::ClaimRewards { .. }));
        assert!(op
            .signature
            .classical_sig
            .as_slice()
            .iter()
            .any(|b| *b != 0));
        assert!(op.signature.pq_sig.as_slice().iter().any(|b| *b != 0));
    }

    #[test]
    fn staking_null_pointer_rejected() {
        let keys = keys();
        let chain = CString::new("indra-testnet-1").unwrap();
        let mut out = out();
        let result = unsafe {
            indra_build_claim_rewards(
                std::ptr::null(),
                keys.classical_seed.as_ptr(),
                keys.pq_pk.as_ptr(),
                keys.pq_sk.as_ptr(),
                1,
                chain.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(result, IndraError::NullPointer.code());
    }

    #[test]
    fn staking_buffer_too_small_rejected() {
        let keys = keys();
        let chain = CString::new("indra-testnet-1").unwrap();
        let validator_id = [0x01u8; 32];
        let mut out = [0i8; 16];
        let result = unsafe {
            indra_build_claim_rewards(
                validator_id.as_ptr(),
                keys.classical_seed.as_ptr(),
                keys.pq_pk.as_ptr(),
                keys.pq_sk.as_ptr(),
                1,
                chain.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(result, IndraError::BufferTooSmall.code());
    }

    #[test]
    fn commission_out_of_range_rejected() {
        let keys = keys();
        let chain = CString::new("indra-testnet-1").unwrap();
        let bond_utxo_id = [0x08u8; 32];
        let bond_blinding_factor = [0x0au8; 32];
        let vrf_pk = [0x09u8; 32];
        let mut out = out();
        let result = unsafe {
            indra_build_register_validator(
                10_001,
                bond_utxo_id.as_ptr(),
                1_000_000,
                bond_blinding_factor.as_ptr(),
                keys.classical_seed.as_ptr(),
                keys.pq_pk.as_ptr(),
                keys.pq_sk.as_ptr(),
                vrf_pk.as_ptr(),
                1,
                chain.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(result, IndraError::InvalidParam.code());
    }
}
