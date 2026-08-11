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
            primitives::DEFAULT_CHAIN_ID,
            staking::{StakingOp, StakingOpBody},
            transaction::TransactionV1,
        },
    };
    use indra_crypto::{
        mnemonic_to_seed, verify_opening, ClassicalKeypair, HybridKeypair, PaymentKeypairV1,
        PaymentPubKeyV1, PedersenCommitment, PedersenOpening, PqKeypair,
    };
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
    fn key_handle_public_matches_canonical_keystore_public_fields() {
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
    fn ffi_master_seed_matches_keystore_master_seed_api() {
        let _guard = test_lock();

        let seed = [0x27; 32];
        let seed_keys = keygen::generate_keys(seed).unwrap();
        let canonical = indra_cli::generate_from_master_seed(String::new(), seed).unwrap();
        assert_eq!(seed_keys, canonical);
        assert_eq!(
            seed_keys.public.payment_pubkey,
            seed_keys
                .payment_keypair
                .as_ref()
                .map(PaymentKeypairV1::public_key)
        );

        let (seed_handle, _) = handle_from_seed(seed);
        let mut seed_keypair_bytes = [0u8; PAYMENT_KEYPAIR_V1_BYTES];
        assert_eq!(
            unsafe {
                crate::payment::indra_key_handle_payment_keypair(
                    seed_handle,
                    seed_keypair_bytes.as_mut_ptr(),
                )
            },
            OK
        );
        assert_eq!(
            PaymentKeypairV1::decode(&seed_keypair_bytes).unwrap(),
            seed_keys.payment_keypair.clone().unwrap()
        );

        let phrase = keygen::new_mnemonic();
        let mnemonic_keys = keygen::generate_keys_from_mnemonic(&phrase).unwrap();
        let master_seed = mnemonic_to_seed(&phrase).unwrap();
        let canonical_mnemonic =
            indra_cli::generate_from_master_seed(String::new(), master_seed).unwrap();
        assert_eq!(mnemonic_keys, canonical_mnemonic);
        assert_eq!(
            mnemonic_keys.public.payment_pubkey,
            mnemonic_keys
                .payment_keypair
                .as_ref()
                .map(PaymentKeypairV1::public_key)
        );

        let phrase_c = CString::new(phrase).unwrap();
        let mut mnemonic_handle = INDRA_KEY_HANDLE_INVALID;
        let mut public = IndraPublicKeyInfo::zeroed();
        assert_eq!(
            unsafe {
                indra_keygen_from_mnemonic_handle(
                    phrase_c.as_ptr(),
                    &mut mnemonic_handle,
                    &mut public,
                )
            },
            OK
        );
        let mut mnemonic_keypair_bytes = [0u8; PAYMENT_KEYPAIR_V1_BYTES];
        assert_eq!(
            unsafe {
                crate::payment::indra_key_handle_payment_keypair(
                    mnemonic_handle,
                    mnemonic_keypair_bytes.as_mut_ptr(),
                )
            },
            OK
        );
        assert_eq!(
            PaymentKeypairV1::decode(&mnemonic_keypair_bytes).unwrap(),
            mnemonic_keys.payment_keypair.clone().unwrap()
        );

        seed_keypair_bytes.fill(0);
        mnemonic_keypair_bytes.fill(0);
        assert_eq!(indra_destroy_key_handle(seed_handle), OK);
        assert_eq!(indra_destroy_key_handle(mnemonic_handle), OK);
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
    fn transaction_handle_signature_matches_direct_and_blinding_recovery_opens_commitment() {
        let _guard = test_lock();
        let (sender_handle, _sender_public) = handle_from_seed([0x76; 32]);
        let (recipient_handle, _) = handle_from_seed([0x77; 32]);
        let recipient_signing = handles::signing_material(recipient_handle).unwrap();
        let recipient_keypair = recipient_signing.keypair().unwrap();
        let recipient_payment = handles::payment_keypair(recipient_handle).unwrap();
        let recipient_address = indra_crypto::PaymentAddress::new(
            DEFAULT_CHAIN_ID.as_bytes(),
            &recipient_keypair,
            recipient_payment.public_key(),
        )
        .unwrap()
        .to_text();
        let chain = CString::new(DEFAULT_CHAIN_ID).unwrap();
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
        };
        let mut result = IndraTxResult::zeroed();
        assert_eq!(
            unsafe { indra_build_tx_with_handle(&params, &mut result) },
            OK
        );
        let tx = unsafe { decode_tx_result(&result) };
        let direct = direct_keypair_from_master_seed([0x76; 32])
            .sign(&tx.signing_bytes(DEFAULT_CHAIN_ID))
            .unwrap();
        assert_wire_signature_matches_direct(&tx.signature, &direct);
        let note = tx.payment_notes[0].encode();
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
    fn staking_handle_signature_is_byte_identical_to_direct_signing() {
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
    fn governance_handle_signature_is_byte_identical_to_direct_signing() {
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
        let domain = indra_core::types::governance::governance_signing_domain(
            op.action_type,
            op.signer_id,
            op.nonce,
            &op.payload,
            "indra-testnet-1",
        );
        let direct = direct_keypair_from_master_seed([0x55; 32])
            .sign(&indra_crypto::sha256(&domain))
            .unwrap();
        assert_wire_signature_matches_direct(&op.signature, &direct);
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
        let address_keypair = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0x21; 32]),
            PqKeypair::from_seed(&[0x21; 32]).unwrap(),
        );
        let address = indra_crypto::PaymentAddress::new(
            b"indra-testnet-1",
            &address_keypair,
            PaymentKeypairV1::generate().public_key(),
        )
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
    /// Chain id used for descriptor validation, note KDF, and transaction signing.
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

/// Build and sign a transaction using a canonical payment descriptor.
///
/// # Safety
///
/// \`params\` and \`out\` must be valid pointers. The address pointer must
/// reference \`recipient_address_len\` readable UTF-8 bytes, \`chain_id\` must
/// be a valid NUL-terminated UTF-8 string, and UTXO pointers must match their count.
#[no_mangle]
pub unsafe extern "C" fn indra_build_tx_with_handle(
    params: *const IndraTxParams,
    out: *mut IndraTxResult,
) -> i32 {
    if params.is_null() || out.is_null() {
        return IndraError::NullPointer.code();
    }
    *out = IndraTxResult::zeroed();

    match catch_unwind(|| {
        let params_ref = &*params;
        if params_ref.utxo_count > MAX_UTXO_COUNT || params_ref.recipient_address_len == 0 {
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
        let chain_id = bounded_cstr(params_ref.chain_id)?;
        indra_crypto::PaymentAddress::from_text(recipient_address, chain_id.as_bytes())
            .map_err(|_| IndraError::InvalidParam)?;
        let utxos = if params_ref.utxo_count == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(params_ref.utxos, params_ref.utxo_count)
        };
        let signing = handles::signing_material(params_ref.sender_handle)?;
        let sender_payment_pubkey = handles::payment_pubkey(params_ref.sender_handle)?;
        let mut sender_classical_seed = signing.classical_seed();
        let mut sender_ml_dsa_seed = signing.ml_dsa_seed();
        let wallet_context =
            wallet::build_wallet_context(sender_classical_seed, &signing.public.pq_pk, utxos)?;
        let built = match tx::build_with_address(
            recipient_address,
            params_ref.amount_spark,
            params_ref.fee_spark,
            sender_classical_seed,
            &sender_ml_dsa_seed,
            &chain_id,
            sender_payment_pubkey,
            wallet_context,
        ) {
            Ok(built) => built,
            Err(error) => {
                sender_classical_seed.fill(0);
                sender_ml_dsa_seed.fill(0);
                return Err(error);
            }
        };
        sender_classical_seed.fill(0);
        sender_ml_dsa_seed.fill(0);

        let tx_bytes_len = built.tx_bytes.len();
        let tx_bytes_ptr = Box::into_raw(built.tx_bytes) as *mut u8;
        let spent_count = built.spent_indices.len();
        let spent_ptr = Box::into_raw(built.spent_indices) as *mut usize;
        *out = IndraTxResult {
            tx_id: built.tx_id,
            tx_bytes: tx_bytes_ptr,
            tx_bytes_len,
            change_spark: built.change_spark,
            change_blinding: built.change_blinding,
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
/// `ptr` must either be null or a pointer returned by `indra_build_tx_with_handle()` for a
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
/// `ptr` must either be null or a pointer returned by `indra_build_tx_with_handle()` for a
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
