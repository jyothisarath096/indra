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
//! - Opaque key handles are process-local. The consuming app must persist
//!   recovery material in platform secure storage, recreate handles on unlock,
//!   and destroy handles on wallet lock/logout.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use std::{ffi::c_char, panic::catch_unwind};

use indra_bulletproofs::RANGE_PROOF_BYTES;
use indra_crypto::{
    derive_genesis_utxo_blinding_from_classical_pk, sha256, PAYMENT_KEYPAIR_V1_ENCODED_LEN,
    PAYMENT_NOTE_V1_ENCODED_LEN, PAYMENT_PUBKEY_V1_ENCODED_LEN,
};

pub mod errors;
pub mod governance;
pub mod handles;
pub mod keygen;
pub mod payment;
pub mod staking;
pub mod tx;
pub mod wallet;

use errors::{error_string, IndraError};
pub use handles::{IndraKeyHandle, INDRA_KEY_HANDLE_INVALID};

pub const CLASSICAL_PK_BYTES: usize = 32;
pub const CLASSICAL_SK_BYTES: usize = 32;
pub const PQ_PK_BYTES: usize = 2592;
pub const PQ_SK_BYTES: usize = 32;
pub const BYTES32_LEN: usize = 32;
/// Encoded `PaymentKeypairV1` byte length.
pub const PAYMENT_KEYPAIR_V1_BYTES: usize = PAYMENT_KEYPAIR_V1_ENCODED_LEN;
/// Encoded `PaymentPubKeyV1` byte length.
pub const PAYMENT_PUBKEY_V1_BYTES: usize = PAYMENT_PUBKEY_V1_ENCODED_LEN;
/// Encoded `PaymentBlindingNoteV1` byte length.
pub const PAYMENT_NOTE_V1_BYTES: usize = PAYMENT_NOTE_V1_ENCODED_LEN;

/// Maximum byte length of a hex-encoded staking or governance operation
/// including the null terminator. 32 KB is generous for current ops.
pub const INDRA_OP_HEX_MAX_BYTES: usize = 32768;
/// Length of a validator ID.
pub const INDRA_VALIDATOR_ID_BYTES: usize = 32;
/// Length of a UTXO ID.
pub const INDRA_UTXO_ID_BYTES: usize = 32;
/// Length of a VRF public key.
pub const INDRA_VRF_PK_BYTES: usize = 32;
/// Length of a proposal ID.
pub const INDRA_PROPOSAL_ID_BYTES: usize = 32;
/// Maximum number of UTXOs allowed in a single transaction.
pub const MAX_UTXO_COUNT: usize = 100;
/// Maximum byte length of a serialized transaction.
pub const MAX_TX_BYTES: usize = 1_048_576;
/// Maximum byte length of a hex-encoded transaction including null terminator.
pub const MAX_TX_HEX_BYTES: usize = MAX_TX_BYTES * 2 + 1;
/// Maximum byte length for a generated mnemonic output buffer.
pub const MAX_MNEMONIC_BYTES: usize = 512;
/// Maximum number of bytes scanned while reading a C string over FFI.
pub const MAX_CSTR_LEN: usize = 4096;

pub(crate) unsafe fn bounded_cstr(ptr: *const c_char) -> Result<String, IndraError> {
    if ptr.is_null() {
        return Err(IndraError::NullPointer);
    }
    let slice = std::slice::from_raw_parts(ptr.cast::<u8>(), MAX_CSTR_LEN);
    let nul_pos = slice
        .iter()
        .position(|&b| b == 0)
        .ok_or(IndraError::InvalidParam)?;
    std::str::from_utf8(&slice[..nul_pos])
        .map(str::to_owned)
        .map_err(|_| IndraError::InvalidParam)
}

#[cfg(test)]
mod handle_tests {
    use super::*;
    use indra_core::{
        codec::Decode,
        types::{
            governance::{GovernanceOpV2, GovernancePayload},
            primitives::{Bytes32, DEFAULT_CHAIN_ID, TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES},
            staking::{StakingOp, StakingOpBody},
            transaction::TransactionV1,
        },
    };
    use indra_crypto::{
        verify_opening, PaymentKeypairV1, PaymentPubKeyV1, PedersenCommitment, PedersenOpening,
    };
    use indra_state::{apply_staking_op, ChainState};
    use std::{
        ffi::{CStr, CString},
        fs,
        path::Path,
        sync::{Mutex, OnceLock},
        thread,
    };

    const OK: i32 = IndraError::Ok as i32;
    const INVALID_HANDLE: i32 = IndraError::InvalidHandle as i32;

    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn handle_from_seed(seed: [u8; 32]) -> (IndraKeyHandle, IndraPublicKeyInfo) {
        let mut handle = INDRA_KEY_HANDLE_INVALID;
        let mut public = IndraPublicKeyInfo::zeroed();
        let code = unsafe { indra_keygen_handle(seed.as_ptr(), &mut handle, &mut public) };
        assert_eq!(code, OK);
        assert_ne!(handle, INDRA_KEY_HANDLE_INVALID);
        (handle, public)
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

    unsafe fn decode_tx_result(result: &IndraTxResult) -> TransactionV1 {
        let bytes = std::slice::from_raw_parts(result.tx_bytes, result.tx_bytes_len);
        TransactionV1::decode_exact(bytes).unwrap()
    }

    #[test]
    fn keygen_handle_returns_public_metadata_without_private_fields() {
        let _guard = test_lock();
        let (_handle, public) = handle_from_seed([0x42; 32]);
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
    fn key_handle_public_matches_legacy_keygen_public_fields() {
        let _guard = test_lock();
        let seed = [0x24; 32];
        let (handle, public) = handle_from_seed(seed);
        let direct = keygen::generate_keys(seed).unwrap();
        assert_eq!(public.validator_id, direct.public.validator_id);
        assert_eq!(public.classical_pk, direct.public.hybrid_classical_pk);
        assert_eq!(
            public.pq_pk.as_slice(),
            direct.public.hybrid_pq_pk.as_slice()
        );
        assert_eq!(public.vrf_pk, direct.public.vrf_pk);

        let mut fetched = IndraPublicKeyInfo::zeroed();
        let code = unsafe { indra_key_handle_public(handle, &mut fetched) };
        assert_eq!(code, OK);
        assert_eq!(fetched.validator_id, public.validator_id);
        assert_eq!(fetched.classical_pk, public.classical_pk);
        assert_eq!(fetched.pq_pk, public.pq_pk);
        assert_eq!(fetched.vrf_pk, public.vrf_pk);
    }

    #[test]
    fn payment_keygen_ffi_round_trips_keypair_and_pubkey() {
        let _guard = test_lock();
        let mut keypair_bytes = [0u8; PAYMENT_KEYPAIR_V1_BYTES];
        let mut pubkey_bytes = [0u8; PAYMENT_PUBKEY_V1_BYTES];

        let code = unsafe {
            crate::payment::indra_payment_keygen(
                keypair_bytes.as_mut_ptr(),
                pubkey_bytes.as_mut_ptr(),
            )
        };

        assert_eq!(code, OK);
        let keypair = PaymentKeypairV1::decode(&keypair_bytes).unwrap();
        let pubkey = PaymentPubKeyV1::decode(&pubkey_bytes).unwrap();
        assert_eq!(keypair.public_key(), pubkey);
    }

    #[test]
    fn derive_payment_note_ffi_round_trips_through_raw_recovery() {
        let _guard = test_lock();
        let mut keypair_bytes = [0u8; PAYMENT_KEYPAIR_V1_BYTES];
        let mut pubkey_bytes = [0u8; PAYMENT_PUBKEY_V1_BYTES];
        assert_eq!(
            unsafe {
                crate::payment::indra_payment_keygen(
                    keypair_bytes.as_mut_ptr(),
                    pubkey_bytes.as_mut_ptr(),
                )
            },
            OK
        );
        let owner_id = [0x5Au8; BYTES32_LEN];
        let chain = CString::new(DEFAULT_CHAIN_ID).unwrap();
        let mut note = [0u8; PAYMENT_NOTE_V1_BYTES];
        let mut sender_blinding = [0u8; BYTES32_LEN];

        assert_eq!(
            unsafe {
                crate::payment::indra_derive_payment_note(
                    pubkey_bytes.as_ptr(),
                    owner_id.as_ptr(),
                    chain.as_ptr(),
                    3,
                    7_000_000,
                    9,
                    note.as_mut_ptr(),
                    sender_blinding.as_mut_ptr(),
                )
            },
            OK
        );

        let mut recovered = [0u8; BYTES32_LEN];
        assert_eq!(
            unsafe {
                crate::payment::indra_recover_payment_blinding(
                    keypair_bytes.as_ptr(),
                    note.as_ptr(),
                    chain.as_ptr(),
                    3,
                    7_000_000,
                    9,
                    recovered.as_mut_ptr(),
                )
            },
            OK
        );
        assert_eq!(sender_blinding, recovered);
    }

    #[test]
    fn key_handle_exposes_payment_key_material_as_encoded_v1() {
        let _guard = test_lock();
        let (handle, _public) = handle_from_seed([0x26; 32]);
        let mut keypair_bytes = [0u8; PAYMENT_KEYPAIR_V1_BYTES];
        let mut pubkey_bytes = [0u8; PAYMENT_PUBKEY_V1_BYTES];

        assert_eq!(
            unsafe {
                crate::payment::indra_key_handle_payment_keypair(handle, keypair_bytes.as_mut_ptr())
            },
            OK
        );
        assert_eq!(
            unsafe {
                crate::payment::indra_key_handle_payment_pubkey(handle, pubkey_bytes.as_mut_ptr())
            },
            OK
        );

        let keypair = PaymentKeypairV1::decode(&keypair_bytes).unwrap();
        let pubkey = PaymentPubKeyV1::decode(&pubkey_bytes).unwrap();
        assert_eq!(keypair.public_key(), pubkey);
    }

    #[test]
    fn genesis_utxo_blinding_ffi_matches_canonical_derivation() {
        let classical_pk = [0x42u8; 32];
        let mut out = [0u8; BYTES32_LEN];
        let code = unsafe { indra_genesis_utxo_blinding(classical_pk.as_ptr(), out.as_mut_ptr()) };
        let expected = derive_genesis_utxo_blinding_from_classical_pk(&classical_pk);
        let old_ffi_formula = sha256(&[classical_pk.as_slice(), b"genesis-utxo-blinding"].concat());

        assert_eq!(code, OK);
        assert_eq!(out, expected);
        assert_ne!(out, old_ffi_formula);
    }

    #[test]
    fn destroy_key_handle_zeroizes_and_invalidates_entry() {
        let _guard = test_lock();
        let (handle, _public) = handle_from_seed([0x11; 32]);
        assert_eq!(indra_destroy_key_handle(handle), OK);
        let mut fetched = IndraPublicKeyInfo::zeroed();
        let code = unsafe { indra_key_handle_public(handle, &mut fetched) };
        assert_eq!(code, INVALID_HANDLE);
    }

    #[test]
    fn build_tx_with_handle_matches_legacy_builder_output_shape() {
        let _guard = test_lock();
        let (handle, public) = handle_from_seed([0x33; 32]);
        let utxo = IndraUtxoEntry {
            utxo_id: [0xAA; 32],
            value_spark: 10_000_000,
            blinding: [0x01; 32],
            created_height: 0,
            tx_index: 0,
            out_index: 0,
            spent: 0,
        };
        let params = IndraTxParamsV2 {
            recipient_classical_pk: public.classical_pk.as_ptr(),
            amount_spark: 1_000_000,
            fee_spark: 50_000,
            utxos: &utxo,
            utxo_count: 1,
            sender_handle: handle,
        };
        let mut result = IndraTxResult::zeroed();
        let code = unsafe { indra_build_tx_with_handle(&params, &mut result) };
        assert_eq!(code, OK);
        assert!(!result.tx_bytes.is_null());
        assert!(result.tx_bytes_len > 0);
        assert_ne!(result.tx_id, [0u8; 32]);
        unsafe {
            indra_free_bytes(result.tx_bytes, result.tx_bytes_len);
            indra_free_usize(result.spent_indices, result.spent_count);
        }
    }

    #[test]
    fn register_payment_key_builder_with_handle_validates_in_state_layer() {
        let _guard = test_lock();
        let (handle, public) = handle_from_seed([0x72; 32]);
        let mut payment_pubkey = [0u8; PAYMENT_PUBKEY_V1_BYTES];
        assert_eq!(
            unsafe {
                crate::payment::indra_key_handle_payment_pubkey(handle, payment_pubkey.as_mut_ptr())
            },
            OK
        );
        let decoded_payment = PaymentPubKeyV1::decode(&payment_pubkey).unwrap();
        let chain = CString::new(DEFAULT_CHAIN_ID).unwrap();
        let mut out = out();

        let code = unsafe {
            crate::staking::indra_build_register_payment_key_with_handle(
                handle,
                payment_pubkey.as_ptr(),
                1,
                chain.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
            )
        };

        assert_eq!(code, OK);
        let op = unsafe { decode_staking(&out) };
        assert_eq!(op.nonce, 1);
        assert!(matches!(op.body, StakingOpBody::RegisterPaymentKey { .. }));

        let mut state = ChainState::new_genesis();
        apply_staking_op(&mut state, &op, DEFAULT_CHAIN_ID, u64::MAX).unwrap();
        let owner_id = Bytes32::from(sha256(&public.classical_pk));
        assert_eq!(
            state.payment_identities.get(&owner_id),
            Some(&decoded_payment)
        );
    }

    fn funded_utxo() -> IndraUtxoEntry {
        IndraUtxoEntry {
            utxo_id: [0xAB; 32],
            value_spark: 10_000_000,
            blinding: [0x03; 32],
            created_height: 0,
            tx_index: 0,
            out_index: 0,
            spent: 0,
        }
    }

    #[test]
    fn build_tx_with_payment_pubkey_ffi_produces_v2_note_and_change_none_slot() {
        let _guard = test_lock();
        let (sender_handle, _sender_public) = handle_from_seed([0x73; 32]);
        let (recipient_handle, recipient_public) = handle_from_seed([0x74; 32]);
        let mut recipient_payment_pubkey = [0u8; PAYMENT_PUBKEY_V1_BYTES];
        assert_eq!(
            unsafe {
                crate::payment::indra_key_handle_payment_pubkey(
                    recipient_handle,
                    recipient_payment_pubkey.as_mut_ptr(),
                )
            },
            OK
        );
        let chain = CString::new(DEFAULT_CHAIN_ID).unwrap();
        let utxo = funded_utxo();
        let params = IndraTxParamsV3 {
            recipient_classical_pk: recipient_public.classical_pk.as_ptr(),
            amount_spark: 1_000_000,
            fee_spark: 50_000,
            utxos: &utxo,
            utxo_count: 1,
            sender_handle,
            recipient_payment_pubkey: recipient_payment_pubkey.as_ptr(),
            chain_id: chain.as_ptr(),
        };
        let mut result = IndraTxResult::zeroed();

        let code = unsafe { indra_build_tx_with_payment_with_handle(&params, &mut result) };

        assert_eq!(code, OK);
        let tx = unsafe { decode_tx_result(&result) };
        assert_eq!(tx.version.0, TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES);
        assert_eq!(tx.payment_notes.len(), tx.outputs.len());
        assert!(tx.payment_notes[0].is_some());
        assert!(tx.payment_notes[1].is_none());
        unsafe {
            indra_free_bytes(result.tx_bytes, result.tx_bytes_len);
            indra_free_usize(result.spent_indices, result.spent_count);
        }
    }

    #[test]
    fn build_tx_without_payment_pubkey_ffi_preserves_fallback_behavior() {
        let _guard = test_lock();
        let (sender_handle, sender_public) = handle_from_seed([0x75; 32]);
        let chain = CString::new(DEFAULT_CHAIN_ID).unwrap();
        let utxo = funded_utxo();
        let params = IndraTxParamsV3 {
            recipient_classical_pk: sender_public.classical_pk.as_ptr(),
            amount_spark: 1_000_000,
            fee_spark: 50_000,
            utxos: &utxo,
            utxo_count: 1,
            sender_handle,
            recipient_payment_pubkey: std::ptr::null(),
            chain_id: chain.as_ptr(),
        };
        let mut result = IndraTxResult::zeroed();

        let code = unsafe { indra_build_tx_with_payment_with_handle(&params, &mut result) };

        assert_eq!(code, OK);
        let tx = unsafe { decode_tx_result(&result) };
        assert!(tx.payment_notes.is_empty());
        unsafe {
            indra_free_bytes(result.tx_bytes, result.tx_bytes_len);
            indra_free_usize(result.spent_indices, result.spent_count);
        }
    }

    #[test]
    fn blinding_recovery_ffi_opens_real_transaction_commitment() {
        let _guard = test_lock();
        let (sender_handle, _sender_public) = handle_from_seed([0x76; 32]);
        let (recipient_handle, recipient_public) = handle_from_seed([0x77; 32]);
        let mut recipient_payment_pubkey = [0u8; PAYMENT_PUBKEY_V1_BYTES];
        assert_eq!(
            unsafe {
                crate::payment::indra_key_handle_payment_pubkey(
                    recipient_handle,
                    recipient_payment_pubkey.as_mut_ptr(),
                )
            },
            OK
        );
        let chain = CString::new(DEFAULT_CHAIN_ID).unwrap();
        let utxo = funded_utxo();
        let amount = 1_000_000;
        let params = IndraTxParamsV3 {
            recipient_classical_pk: recipient_public.classical_pk.as_ptr(),
            amount_spark: amount,
            fee_spark: 50_000,
            utxos: &utxo,
            utxo_count: 1,
            sender_handle,
            recipient_payment_pubkey: recipient_payment_pubkey.as_ptr(),
            chain_id: chain.as_ptr(),
        };
        let mut result = IndraTxResult::zeroed();
        assert_eq!(
            unsafe { indra_build_tx_with_payment_with_handle(&params, &mut result) },
            OK
        );
        let tx = unsafe { decode_tx_result(&result) };
        let note = tx.payment_notes[0].as_ref().unwrap().encode();
        let mut recovered = [0u8; BYTES32_LEN];

        assert_eq!(
            unsafe {
                crate::payment::indra_recover_payment_blinding_with_handle(
                    recipient_handle,
                    note.as_ptr(),
                    chain.as_ptr(),
                    0,
                    amount,
                    0,
                    recovered.as_mut_ptr(),
                )
            },
            OK
        );
        assert!(verify_opening(
            &PedersenCommitment(tx.outputs[0].commitment.compressed_point.0),
            &PedersenOpening {
                value: amount,
                blinding: recovered
            }
        )
        .is_ok());

        let mut payment_keypair = [0u8; PAYMENT_KEYPAIR_V1_BYTES];
        assert_eq!(
            unsafe {
                crate::payment::indra_key_handle_payment_keypair(
                    recipient_handle,
                    payment_keypair.as_mut_ptr(),
                )
            },
            OK
        );
        let mut recovered_raw = [0u8; BYTES32_LEN];
        assert_eq!(
            unsafe {
                crate::payment::indra_recover_payment_blinding(
                    payment_keypair.as_ptr(),
                    note.as_ptr(),
                    chain.as_ptr(),
                    0,
                    amount,
                    0,
                    recovered_raw.as_mut_ptr(),
                )
            },
            OK
        );
        assert_eq!(recovered_raw, recovered);
        unsafe {
            indra_free_bytes(result.tx_bytes, result.tx_bytes_len);
            indra_free_usize(result.spent_indices, result.spent_count);
        }
    }

    #[test]
    fn staking_builders_with_handle_sign_with_canonical_validator_identity() {
        let _guard = test_lock();
        let (handle, public) = handle_from_seed([0x44; 32]);
        let chain = CString::new("indra-testnet-1").unwrap();
        let mut out = out();
        let code = unsafe {
            crate::staking::indra_build_claim_rewards_with_handle(
                handle,
                7,
                chain.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(code, OK);
        let op = unsafe { decode_staking(&out) };
        assert_eq!(op.nonce, 7);
        match op.body {
            StakingOpBody::ClaimRewards {
                validator_id,
                delegator_pubkey,
            } => {
                assert_eq!(validator_id.0, public.validator_id);
                assert_eq!(delegator_pubkey.classical_pk.0, public.classical_pk);
            }
            other => panic!("unexpected staking op: {other:?}"),
        }
    }

    #[test]
    fn governance_builders_with_handle_sign_with_canonical_identity() {
        let _guard = test_lock();
        let (handle, public) = handle_from_seed([0x55; 32]);
        let chain = CString::new("indra-testnet-1").unwrap();
        let proposal_id = [0x99; 32];
        let mut out = out();
        let code = unsafe {
            crate::governance::indra_build_governance_cancel_with_handle(
                proposal_id.as_ptr(),
                handle,
                9,
                chain.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(code, OK);
        let op = unsafe { decode_governance(&out) };
        assert_eq!(op.signer_id.0, public.validator_id);
        assert_eq!(op.nonce, 9);
        assert!(matches!(op.payload, GovernancePayload::Cancel { .. }));
    }

    #[test]
    fn invalid_handle_rejected_for_all_handle_builders() {
        let _guard = test_lock();
        let chain = CString::new("indra-testnet-1").unwrap();
        let mut out_hex = out();
        let mut result = IndraTxResult::zeroed();
        let recipient = [0x01; 32];
        let tx_params = IndraTxParamsV2 {
            recipient_classical_pk: recipient.as_ptr(),
            amount_spark: 1,
            fee_spark: 1,
            utxos: std::ptr::null(),
            utxo_count: 0,
            sender_handle: INDRA_KEY_HANDLE_INVALID,
        };
        assert_eq!(
            unsafe { indra_build_tx_with_handle(&tx_params, &mut result) },
            INVALID_HANDLE
        );
        assert_eq!(
            unsafe {
                crate::staking::indra_build_claim_rewards_with_handle(
                    INDRA_KEY_HANDLE_INVALID,
                    1,
                    chain.as_ptr(),
                    out_hex.as_mut_ptr(),
                    out_hex.len(),
                )
            },
            INVALID_HANDLE
        );
        let proposal_id = [0x02; 32];
        assert_eq!(
            unsafe {
                crate::governance::indra_build_governance_cancel_with_handle(
                    proposal_id.as_ptr(),
                    INDRA_KEY_HANDLE_INVALID,
                    1,
                    chain.as_ptr(),
                    out_hex.as_mut_ptr(),
                    out_hex.len(),
                )
            },
            INVALID_HANDLE
        );
    }

    #[test]
    fn destroy_all_key_handles_invalidates_existing_handles() {
        let _guard = test_lock();
        let (h1, _p1) = handle_from_seed([0x61; 32]);
        let (h2, _p2) = handle_from_seed([0x62; 32]);
        assert_eq!(indra_destroy_all_key_handles(), OK);
        let mut fetched = IndraPublicKeyInfo::zeroed();
        assert_eq!(
            unsafe { indra_key_handle_public(h1, &mut fetched) },
            INVALID_HANDLE
        );
        assert_eq!(
            unsafe { indra_key_handle_public(h2, &mut fetched) },
            INVALID_HANDLE
        );
    }

    #[test]
    fn concurrent_handle_builds_do_not_cross_use_or_panic() {
        let _guard = test_lock();
        let mut workers = Vec::new();
        for i in 0..8u8 {
            workers.push(thread::spawn(move || {
                let (handle, public) = handle_from_seed([i + 1; 32]);
                let chain = CString::new("indra-testnet-1").unwrap();
                let mut out = out();
                let code = unsafe {
                    crate::staking::indra_build_claim_rewards_with_handle(
                        handle,
                        u64::from(i) + 1,
                        chain.as_ptr(),
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
}

/// FFI keypair bundle returned to Swift.
#[cfg(feature = "legacy_raw_keys")]
#[repr(C)]
pub struct IndraKeyPair {
    pub validator_id: [u8; BYTES32_LEN],
    pub classical_pk: [u8; CLASSICAL_PK_BYTES],
    pub pq_pk: [u8; PQ_PK_BYTES],
    pub classical_seed: [u8; CLASSICAL_SK_BYTES],
    pub pq_sk: [u8; PQ_SK_BYTES],
    pub bls_seed: [u8; BYTES32_LEN],
    pub vrf_seed: [u8; BYTES32_LEN],
}

#[cfg(feature = "legacy_raw_keys")]
impl IndraKeyPair {
    /// Zero-initialised value for tests and error paths.
    pub const fn zeroed() -> Self {
        Self {
            validator_id: [0u8; BYTES32_LEN],
            classical_pk: [0u8; CLASSICAL_PK_BYTES],
            pq_pk: [0u8; PQ_PK_BYTES],
            classical_seed: [0u8; CLASSICAL_SK_BYTES],
            pq_sk: [0u8; PQ_SK_BYTES],
            bls_seed: [0u8; BYTES32_LEN],
            vrf_seed: [0u8; BYTES32_LEN],
        }
    }
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
    pub blinding: [u8; BYTES32_LEN],
    pub created_height: u64,
    pub tx_index: u32,
    pub out_index: u32,
    pub spent: u8,
}

/// FFI transaction builder input parameters.
#[cfg(feature = "legacy_raw_keys")]
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

/// FFI transaction builder input parameters for opaque key handles.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IndraTxParamsV2 {
    pub recipient_classical_pk: *const u8,
    pub amount_spark: u64,
    pub fee_spark: u64,
    pub utxos: *const IndraUtxoEntry,
    pub utxo_count: usize,
    pub sender_handle: IndraKeyHandle,
}

/// FFI transaction builder input parameters with optional payment blinding.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IndraTxParamsV3 {
    pub recipient_classical_pk: *const u8,
    pub amount_spark: u64,
    pub fee_spark: u64,
    pub utxos: *const IndraUtxoEntry,
    pub utxo_count: usize,
    pub sender_handle: IndraKeyHandle,
    /// Null means preserve legacy random-blinding behavior. Non-null must
    /// reference `INDRA_PAYMENT_PUBKEY_V1_BYTES` readable bytes.
    pub recipient_payment_pubkey: *const u8,
    /// Chain id used in payment-note KDF and transaction signing.
    pub chain_id: *const c_char,
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

/// Explicitly zeroize an FFI keypair bundle in caller-owned memory.
///
/// # Safety
///
/// `keypair` must be null or point to valid writable `IndraKeyPair` storage.
#[cfg(feature = "legacy_raw_keys")]
#[no_mangle]
pub unsafe extern "C" fn indra_zeroize_keypair(keypair: *mut IndraKeyPair) {
    if keypair.is_null() {
        return;
    }
    std::ptr::write_volatile(keypair, IndraKeyPair::zeroed());
}

/// Explicitly zeroize sensitive transaction result fields in caller-owned memory.
///
/// # Safety
///
/// `result` must be null or point to valid writable `IndraTxResult` storage.
#[no_mangle]
pub unsafe extern "C" fn indra_zeroize_tx_result(result: *mut IndraTxResult) {
    if result.is_null() {
        return;
    }
    (*result).change_blinding = [0u8; BYTES32_LEN];
    (*result).tx_id = [0u8; BYTES32_LEN];
}

/// Generate a new INDRA keypair from one 32-byte wallet seed.
///
/// # Safety
///
/// `seed` must point to at least 32 readable bytes and `out` must point to a
/// valid writable `IndraKeyPair`.
#[cfg(feature = "legacy_raw_keys")]
#[no_mangle]
pub unsafe extern "C" fn indra_keygen(seed: *const u8, out: *mut IndraKeyPair) -> i32 {
    if seed.is_null() || out.is_null() {
        return IndraError::NullPointer.code();
    }

    *out = IndraKeyPair::zeroed();

    match catch_unwind(|| {
        let mut seed_bytes = [0u8; CLASSICAL_SK_BYTES];
        seed_bytes.copy_from_slice(std::slice::from_raw_parts(seed, CLASSICAL_SK_BYTES));
        let result = keygen::generate(seed_bytes);
        seed_bytes.fill(0);
        result
    }) {
        Ok(Ok(keypair)) => {
            *out = keypair;
            IndraError::Ok.code()
        }
        Ok(Err(err)) => err.code(),
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
        let mut seed_bytes = [0u8; CLASSICAL_SK_BYTES];
        seed_bytes.copy_from_slice(std::slice::from_raw_parts(seed, CLASSICAL_SK_BYTES));
        let result = keygen::generate_keys(seed_bytes);
        seed_bytes.fill(0);
        result.and_then(|keys| handles::store_keys(&keys))
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
        out_slice[..bytes.len()].copy_from_slice(bytes);
        out_slice[bytes.len()] = 0;
        Ok(())
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Recover an INDRA keypair from a BIP-39 mnemonic phrase.
///
/// # Safety
///
/// `phrase` must point to a valid null-terminated UTF-8 C string and `out`
/// must point to writable `IndraKeyPair` storage.
#[cfg(feature = "legacy_raw_keys")]
#[no_mangle]
pub unsafe extern "C" fn indra_keygen_from_mnemonic(
    phrase: *const c_char,
    out: *mut IndraKeyPair,
) -> i32 {
    if phrase.is_null() || out.is_null() {
        return IndraError::NullPointer.code();
    }

    *out = IndraKeyPair::zeroed();

    match catch_unwind(|| {
        let phrase_str = bounded_cstr(phrase)?;
        keygen::generate_from_mnemonic(&phrase_str)
    }) {
        Ok(Ok(keypair)) => {
            *out = keypair;
            IndraError::Ok.code()
        }
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Recover an INDRA key handle from a BIP-39 mnemonic phrase.
///
/// # Safety
///
/// `phrase` must point to a valid null-terminated UTF-8 C string.
/// `out_handle` and `out_public` must point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn indra_keygen_from_mnemonic_handle(
    phrase: *const c_char,
    out_handle: *mut IndraKeyHandle,
    out_public: *mut IndraPublicKeyInfo,
) -> i32 {
    if phrase.is_null() || out_handle.is_null() || out_public.is_null() {
        return IndraError::NullPointer.code();
    }

    *out_handle = INDRA_KEY_HANDLE_INVALID;
    *out_public = IndraPublicKeyInfo::zeroed();

    match catch_unwind(|| {
        let phrase_str = bounded_cstr(phrase)?;
        keygen::generate_keys_from_mnemonic(&phrase_str).and_then(|keys| handles::store_keys(&keys))
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
    handle: IndraKeyHandle,
    out_public: *mut IndraPublicKeyInfo,
) -> i32 {
    if out_public.is_null() {
        return IndraError::NullPointer.code();
    }
    *out_public = IndraPublicKeyInfo::zeroed();
    match catch_unwind(|| handles::public_info(handle)) {
        Ok(Ok(public)) => {
            *out_public = public;
            IndraError::Ok.code()
        }
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Destroy one opaque key handle and zeroize its in-process key material.
#[no_mangle]
pub extern "C" fn indra_destroy_key_handle(handle: IndraKeyHandle) -> i32 {
    match catch_unwind(|| handles::destroy(handle)) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Destroy all opaque key handles and zeroize their in-process key material.
#[no_mangle]
pub extern "C" fn indra_destroy_all_key_handles() -> i32 {
    match catch_unwind(handles::destroy_all) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Validate a BIP-39 mnemonic phrase.
///
/// # Safety
///
/// `phrase` must point to a valid null-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn indra_validate_mnemonic(phrase: *const c_char) -> i32 {
    if phrase.is_null() {
        return IndraError::NullPointer.code();
    }

    match catch_unwind(|| {
        let phrase_str = bounded_cstr(phrase)?;
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

/// Derive the validator id from a classical public key.
///
/// # Safety
///
/// `classical_pk` must point to at least 32 readable bytes and `out_id` must
/// point to a writable 32-byte output buffer.
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
///
/// # Safety
///
/// `params` and `out` must be valid non-null pointers. Any pointer fields inside
/// `params` must reference readable memory for the documented lengths, and
/// `out` must point to writable storage for `IndraTxResult`.
#[cfg(feature = "legacy_raw_keys")]
#[no_mangle]
pub unsafe extern "C" fn indra_build_tx(
    params: *const IndraTxParams,
    out: *mut IndraTxResult,
) -> i32 {
    if params.is_null() || out.is_null() {
        return IndraError::NullPointer.code();
    }

    *out = IndraTxResult::zeroed();

    match catch_unwind(|| {
        let params_ref = &*params;
        if params_ref.utxo_count > MAX_UTXO_COUNT {
            return Err(IndraError::InvalidParam);
        }
        if params_ref.recipient_classical_pk.is_null()
            || params_ref.sender_classical_seed.is_null()
            || params_ref.sender_pq_sk.is_null()
            || params_ref.sender_pq_pk.is_null()
            || (params_ref.utxo_count > 0 && params_ref.utxos.is_null())
        {
            return Err(IndraError::NullPointer);
        }

        let mut recipient_classical_pk = [0u8; CLASSICAL_PK_BYTES];
        recipient_classical_pk.copy_from_slice(std::slice::from_raw_parts(
            params_ref.recipient_classical_pk,
            CLASSICAL_PK_BYTES,
        ));

        let mut sender_classical_seed = [0u8; CLASSICAL_SK_BYTES];
        sender_classical_seed.copy_from_slice(std::slice::from_raw_parts(
            params_ref.sender_classical_seed,
            CLASSICAL_SK_BYTES,
        ));

        let sender_pq_sk = std::slice::from_raw_parts(params_ref.sender_pq_sk, PQ_SK_BYTES);
        let sender_pq_pk = std::slice::from_raw_parts(params_ref.sender_pq_pk, PQ_PK_BYTES);
        let utxos = if params_ref.utxo_count == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(params_ref.utxos, params_ref.utxo_count)
        };

        let wallet_context =
            wallet::build_wallet_context(sender_classical_seed, sender_pq_pk, utxos)?;
        let built = match tx::build(
            recipient_classical_pk,
            params_ref.amount_spark,
            params_ref.fee_spark,
            sender_classical_seed,
            sender_pq_sk,
            wallet_context,
        ) {
            Ok(built) => built,
            Err(error) => {
                sender_classical_seed.fill(0);
                return Err(error);
            }
        };
        sender_classical_seed.fill(0);

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

/// Build and sign a transaction for the wallet using an opaque key handle.
///
/// # Safety
///
/// `params` and `out` must be valid non-null pointers. Any pointer fields inside
/// `params` must reference readable memory for the documented lengths, and
/// `out` must point to writable storage for `IndraTxResult`.
#[no_mangle]
pub unsafe extern "C" fn indra_build_tx_with_handle(
    params: *const IndraTxParamsV2,
    out: *mut IndraTxResult,
) -> i32 {
    if params.is_null() || out.is_null() {
        return IndraError::NullPointer.code();
    }

    *out = IndraTxResult::zeroed();

    match catch_unwind(|| {
        let params_ref = &*params;
        if params_ref.utxo_count > MAX_UTXO_COUNT {
            return Err(IndraError::InvalidParam);
        }
        if params_ref.recipient_classical_pk.is_null()
            || (params_ref.utxo_count > 0 && params_ref.utxos.is_null())
        {
            return Err(IndraError::NullPointer);
        }

        let mut recipient_classical_pk = [0u8; CLASSICAL_PK_BYTES];
        recipient_classical_pk.copy_from_slice(std::slice::from_raw_parts(
            params_ref.recipient_classical_pk,
            CLASSICAL_PK_BYTES,
        ));

        let utxos = if params_ref.utxo_count == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(params_ref.utxos, params_ref.utxo_count)
        };

        let signing = handles::signing_material(params_ref.sender_handle)?;
        let mut sender_classical_seed = signing.classical_seed();
        let mut sender_pq_sk = signing.pq_sk();
        let wallet_context =
            wallet::build_wallet_context(sender_classical_seed, &signing.public.pq_pk, utxos)?;
        let built = match tx::build(
            recipient_classical_pk,
            params_ref.amount_spark,
            params_ref.fee_spark,
            sender_classical_seed,
            &sender_pq_sk,
            wallet_context,
        ) {
            Ok(built) => built,
            Err(error) => {
                sender_classical_seed.fill(0);
                sender_pq_sk.fill(0);
                return Err(error);
            }
        };
        sender_classical_seed.fill(0);
        sender_pq_sk.fill(0);

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

/// Build and sign a transaction using an opaque key handle and optional
/// recipient payment key.
///
/// # Safety
///
/// `params` and `out` must be valid non-null pointers. If
/// `recipient_payment_pubkey` is non-null, it must reference
/// `INDRA_PAYMENT_PUBKEY_V1_BYTES` readable bytes. `chain_id` must be a valid
/// null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn indra_build_tx_with_payment_with_handle(
    params: *const IndraTxParamsV3,
    out: *mut IndraTxResult,
) -> i32 {
    if params.is_null() || out.is_null() {
        return IndraError::NullPointer.code();
    }

    *out = IndraTxResult::zeroed();

    match catch_unwind(|| {
        let params_ref = &*params;
        if params_ref.utxo_count > MAX_UTXO_COUNT {
            return Err(IndraError::InvalidParam);
        }
        if params_ref.recipient_classical_pk.is_null()
            || params_ref.chain_id.is_null()
            || (params_ref.utxo_count > 0 && params_ref.utxos.is_null())
        {
            return Err(IndraError::NullPointer);
        }

        let mut recipient_classical_pk = [0u8; CLASSICAL_PK_BYTES];
        recipient_classical_pk.copy_from_slice(std::slice::from_raw_parts(
            params_ref.recipient_classical_pk,
            CLASSICAL_PK_BYTES,
        ));

        let recipient_payment_pubkey = if params_ref.recipient_payment_pubkey.is_null() {
            None
        } else {
            Some(
                indra_crypto::PaymentPubKeyV1::decode(std::slice::from_raw_parts(
                    params_ref.recipient_payment_pubkey,
                    PAYMENT_PUBKEY_V1_BYTES,
                ))
                .map_err(|_| IndraError::InvalidParam)?,
            )
        };
        let chain_id = bounded_cstr(params_ref.chain_id)?;

        let utxos = if params_ref.utxo_count == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(params_ref.utxos, params_ref.utxo_count)
        };

        let signing = handles::signing_material(params_ref.sender_handle)?;
        let mut sender_classical_seed = signing.classical_seed();
        let mut sender_pq_sk = signing.pq_sk();
        let wallet_context =
            wallet::build_wallet_context(sender_classical_seed, &signing.public.pq_pk, utxos)?;
        let built = match tx::build_with_payment(
            recipient_classical_pk,
            params_ref.amount_spark,
            params_ref.fee_spark,
            sender_classical_seed,
            &sender_pq_sk,
            &chain_id,
            recipient_payment_pubkey,
            wallet_context,
        ) {
            Ok(built) => built,
            Err(error) => {
                sender_classical_seed.fill(0);
                sender_pq_sk.fill(0);
                return Err(error);
            }
        };
        sender_classical_seed.fill(0);
        sender_pq_sk.fill(0);

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
///
/// # Safety
///
/// `classical_pk` must point to at least 32 readable bytes and
/// `out_blinding` must point to a writable 32-byte output buffer.
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
        let mut classical_pk_array = [0u8; CLASSICAL_PK_BYTES];
        classical_pk_array.copy_from_slice(classical_pk_bytes);
        let blinding = derive_genesis_utxo_blinding_from_classical_pk(&classical_pk_array);
        std::slice::from_raw_parts_mut(out_blinding, BYTES32_LEN).copy_from_slice(&blinding);
    }) {
        Ok(()) => IndraError::Ok.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Verify a Bulletproof range proof against a Pedersen commitment.
///
/// # Safety
///
/// `commitment_bytes` must point to 32 readable bytes and `proof_bytes` must
/// point to `proof_len` readable bytes.
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
///
/// # Safety
///
/// `ptr` must either be null or a pointer returned by `indra_build_tx()` for a
/// byte buffer, paired with the original allocation length.
#[no_mangle]
pub unsafe extern "C" fn indra_free_bytes(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    if len > MAX_TX_BYTES {
        return;
    }
    let slice_ptr = std::ptr::slice_from_raw_parts_mut(ptr, len);
    drop(Box::from_raw(slice_ptr));
}

/// Free a `usize` array allocated by Rust.
///
/// # Safety
///
/// `ptr` must either be null or a pointer returned by `indra_build_tx()` for a
/// `usize` array, paired with the original allocation length.
#[no_mangle]
pub unsafe extern "C" fn indra_free_usize(ptr: *mut usize, len: usize) {
    if ptr.is_null() {
        return;
    }
    if len > MAX_UTXO_COUNT {
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

#[cfg(all(test, feature = "legacy_raw_keys"))]
mod tests {
    use super::*;

    const MNEMONIC_MAX_BYTES: usize = 300;
    const INDRA_OK: i32 = IndraError::Ok as i32;
    const INDRA_ERR_NULL_POINTER: i32 = IndraError::NullPointer as i32;
    const INDRA_ERR_INVALID_PARAM: i32 = IndraError::InvalidParam as i32;

    #[test]
    fn keygen_produces_valid_output() {
        let seed = [0x42u8; 32];
        let mut out = IndraKeyPair::zeroed();
        let result = unsafe { indra_keygen(seed.as_ptr(), &mut out) };
        assert_eq!(result, INDRA_OK);
        assert_ne!(out.validator_id, [0u8; 32]);
        assert_ne!(out.classical_pk, [0u8; 32]);
        assert_ne!(out.pq_pk, [0u8; 2592]);
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
        assert_eq!(out1.pq_pk, out2.pq_pk);
        assert_eq!(out1.pq_sk, out2.pq_sk);
    }

    #[test]
    fn genesis_utxo_blinding_ffi_matches_canonical_derivation() {
        let classical_pk = [0x42u8; 32];
        let mut out = [0u8; BYTES32_LEN];
        let result =
            unsafe { indra_genesis_utxo_blinding(classical_pk.as_ptr(), out.as_mut_ptr()) };
        let expected = derive_genesis_utxo_blinding_from_classical_pk(&classical_pk);
        let old_ffi_formula = sha256(&[classical_pk.as_slice(), b"genesis-utxo-blinding"].concat());

        assert_eq!(result, INDRA_OK);
        assert_eq!(out, expected);
        assert_ne!(out, old_ffi_formula);
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
    fn ffi_bounded_cstr_rejects_string_without_nul_in_limit() {
        let buffer = vec![b'a'; MAX_CSTR_LEN + 1];
        let result = unsafe { bounded_cstr(buffer.as_ptr().cast::<c_char>()) };
        assert_eq!(result, Err(IndraError::InvalidParam));
    }

    #[test]
    fn ffi_bounded_cstr_accepts_valid_short_string() {
        let input = std::ffi::CString::new("indra-testnet-1").unwrap();
        let result = unsafe { bounded_cstr(input.as_ptr()) }.unwrap();
        assert_eq!(result, "indra-testnet-1");
    }

    #[test]
    fn ffi_intermediate_key_buffers_are_zeroized() {
        let mut secret = [0xA5u8; 32];
        secret.fill(0);
        assert_eq!(secret, [0u8; 32]);
    }

    #[test]
    fn generate_mnemonic_produces_phrase() {
        let mut phrase = [0u8; MNEMONIC_MAX_BYTES];
        let code =
            unsafe { indra_generate_mnemonic(phrase.as_mut_ptr().cast::<c_char>(), phrase.len()) };
        assert_eq!(code, INDRA_OK);
        let nul = phrase.iter().position(|b| *b == 0).unwrap();
        let rendered = std::str::from_utf8(&phrase[..nul]).unwrap();
        assert_eq!(rendered.split_whitespace().count(), 24);
    }

    #[test]
    fn keygen_from_mnemonic_is_deterministic() {
        let phrase = std::ffi::CString::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        ).unwrap();
        let mut out1 = IndraKeyPair::zeroed();
        let mut out2 = IndraKeyPair::zeroed();
        unsafe {
            assert_eq!(
                indra_keygen_from_mnemonic(phrase.as_ptr(), &mut out1),
                INDRA_OK
            );
            assert_eq!(
                indra_keygen_from_mnemonic(phrase.as_ptr(), &mut out2),
                INDRA_OK
            );
        }
        assert_eq!(out1.validator_id, out2.validator_id);
        assert_eq!(out1.classical_pk, out2.classical_pk);
        assert_eq!(out1.pq_pk, out2.pq_pk);
        assert_eq!(out1.pq_sk, out2.pq_sk);
    }

    #[test]
    fn keygen_from_mnemonic_includes_all_seeds() {
        let phrase = std::ffi::CString::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon art",
        )
        .unwrap();
        let mut out = IndraKeyPair::zeroed();

        let result = unsafe { indra_keygen_from_mnemonic(phrase.as_ptr(), &mut out) };

        assert_eq!(result, INDRA_OK);
        assert_ne!(out.classical_seed, [0u8; 32], "hybrid_seed is zero");
        assert_ne!(out.bls_seed, [0u8; 32], "bls_seed is zero");
        assert_ne!(out.vrf_seed, [0u8; 32], "vrf_seed is zero");
        assert_ne!(
            out.classical_seed, out.bls_seed,
            "hybrid and bls seeds are identical"
        );
        assert_ne!(
            out.classical_seed, out.vrf_seed,
            "hybrid and vrf seeds are identical"
        );
        assert_ne!(
            out.bls_seed, out.vrf_seed,
            "bls and vrf seeds are identical"
        );

        let mut out2 = IndraKeyPair::zeroed();
        unsafe {
            assert_eq!(
                indra_keygen_from_mnemonic(phrase.as_ptr(), &mut out2),
                INDRA_OK
            );
        }
        assert_eq!(out.bls_seed, out2.bls_seed);
        assert_eq!(out.vrf_seed, out2.vrf_seed);
    }

    #[test]
    fn keypair_zeroize_clears_private_fields() {
        let seed = [0x42u8; 32];
        let mut keypair = IndraKeyPair::zeroed();

        unsafe {
            assert_eq!(indra_keygen(seed.as_ptr(), &mut keypair), INDRA_OK);
        }
        assert_ne!(keypair.classical_seed, [0u8; 32]);
        assert_ne!(keypair.pq_sk, [0u8; 32]);
        assert_ne!(keypair.bls_seed, [0u8; 32]);
        assert_ne!(keypair.vrf_seed, [0u8; 32]);

        unsafe {
            indra_zeroize_keypair(&mut keypair);
        }
        assert_eq!(keypair.classical_seed, [0u8; 32]);
        assert_eq!(keypair.pq_sk, [0u8; 32]);
        assert_eq!(keypair.bls_seed, [0u8; 32]);
        assert_eq!(keypair.vrf_seed, [0u8; 32]);
    }

    #[test]
    fn validate_mnemonic_rejects_invalid_phrase() {
        let phrase = std::ffi::CString::new("invalid phrase").unwrap();
        let code = unsafe { indra_validate_mnemonic(phrase.as_ptr()) };
        assert_eq!(code, INDRA_ERR_INVALID_PARAM);
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
    fn tx_result_zeroize_clears_sensitive_fields() {
        let mut result = IndraTxResult {
            tx_id: [0xAAu8; 32],
            tx_bytes: std::ptr::null_mut(),
            tx_bytes_len: 0,
            change_spark: 123,
            change_blinding: [0xBBu8; 32],
            spent_indices: std::ptr::null_mut(),
            spent_count: 0,
        };

        unsafe {
            indra_zeroize_tx_result(&mut result);
        }
        assert_eq!(result.tx_id, [0u8; 32]);
        assert_eq!(result.change_blinding, [0u8; 32]);
        assert_eq!(result.change_spark, 123);
    }

    #[test]
    fn indra_build_tx_rejects_excessive_utxo_count() {
        let seed = [0x42u8; 32];
        let mut keys = IndraKeyPair::zeroed();
        unsafe {
            indra_keygen(seed.as_ptr(), &mut keys);
        }

        let params = IndraTxParams {
            recipient_classical_pk: keys.classical_pk.as_ptr(),
            amount_spark: 1_000_000,
            fee_spark: 50_000,
            utxos: std::ptr::null(),
            utxo_count: MAX_UTXO_COUNT + 1,
            sender_classical_seed: keys.classical_seed.as_ptr(),
            sender_pq_sk: keys.pq_sk.as_ptr(),
            sender_pq_pk: keys.pq_pk.as_ptr(),
        };

        let mut result = IndraTxResult::zeroed();
        let code = unsafe { indra_build_tx(&params, &mut result) };
        assert_eq!(code, INDRA_ERR_INVALID_PARAM);
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

    #[test]
    fn indra_tx_to_hex_rejects_excessive_length() {
        let bytes = [0u8; 4];
        let mut hex = [0i8; 16];
        let code = unsafe {
            indra_tx_to_hex(
                bytes.as_ptr(),
                MAX_TX_BYTES + 1,
                hex.as_mut_ptr(),
                hex.len(),
            )
        };
        assert_eq!(code, INDRA_ERR_INVALID_PARAM);
    }
}
