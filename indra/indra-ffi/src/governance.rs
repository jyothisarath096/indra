//! C FFI builders for INDRA governance operations.

use std::{
    ffi::{c_char, CStr},
    panic::{catch_unwind, UnwindSafe},
};

use indra_core::{
    codec::Encode,
    types::{
        crypto::{HybridPubKey, HybridSignature},
        governance::{
            governance_signing_domain, GovernableAction, GovernanceOpV2, GovernancePayload,
        },
        primitives::{Bytes32, VariableBytes},
    },
};
use indra_crypto::{hybrid::HybridKeypair, sha256};
use serde_json::Value;

use crate::{
    errors::IndraError,
    staking::{read_bytes32, read_chain_id, read_keypair, write_hex_to_buf},
};

fn hybrid_pubkey_from_keypair(keypair: &HybridKeypair) -> Result<HybridPubKey, IndraError> {
    let public = keypair.public_key();
    Ok(HybridPubKey {
        classical_pk: Bytes32::from(public.classical.0),
        pq_pk: VariableBytes::from_slice(&public.pq.0).map_err(|_| IndraError::TxBuildFailed)?,
    })
}

fn signer_id_from_keypair(keypair: &HybridKeypair) -> Bytes32 {
    Bytes32::from(sha256(&keypair.public_key().classical.0))
}

fn build_governance_op(
    signer_id: Bytes32,
    nonce: u64,
    payload: GovernancePayload,
    keypair: &HybridKeypair,
    chain_id: &str,
) -> Result<String, IndraError> {
    let action_type = payload.action_type();
    let domain = governance_signing_domain(action_type, signer_id, nonce, &payload, chain_id);
    let msg_hash = sha256(&domain);
    let sig = keypair
        .sign(&msg_hash)
        .map_err(|_| IndraError::SignFailed)?;
    let op = GovernanceOpV2 {
        action_type,
        signer_id,
        nonce,
        payload,
        signature: HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0)
                .map_err(|_| IndraError::TxBuildFailed)?,
            pq_sig: VariableBytes::from_slice(&sig.pq.0).map_err(|_| IndraError::TxBuildFailed)?,
        },
    };
    Ok(hex::encode(op.encode_to_vec()))
}

fn parse_action_json(action_json: *const c_char) -> Result<GovernableAction, IndraError> {
    let raw = unsafe { CStr::from_ptr(action_json) }
        .to_str()
        .map_err(|_| IndraError::InvalidJson)?;
    let value: Value = serde_json::from_str(raw).map_err(|_| IndraError::InvalidJson)?;
    let action_type = value
        .get("type")
        .and_then(Value::as_str)
        .ok_or(IndraError::InvalidJson)?;
    let numeric = value.get("value").ok_or(IndraError::InvalidJson)?;

    fn as_u64(value: &Value) -> Result<u64, IndraError> {
        value.as_u64().ok_or(IndraError::InvalidJson)
    }

    fn as_u32(value: &Value) -> Result<u32, IndraError> {
        let raw = as_u64(value)?;
        u32::try_from(raw).map_err(|_| IndraError::InvalidParam)
    }

    match action_type {
        "SetSlashLivenessThresholdEpochs" => {
            Ok(GovernableAction::SetSlashLivenessThresholdEpochs {
                value: as_u64(numeric)?,
            })
        }
        "SetMinDelegationSpark" => Ok(GovernableAction::SetMinDelegationSpark {
            value: as_u64(numeric)?,
        }),
        "SetProposalDepositSpark" => Ok(GovernableAction::SetProposalDepositSpark {
            value: as_u64(numeric)?,
        }),
        "SetSlashLivenessBps" => Ok(GovernableAction::SetSlashLivenessBps {
            value: as_u32(numeric)?,
        }),
        "SetSlashDoublePrecommitBps" => Ok(GovernableAction::SetSlashDoublePrecommitBps {
            value: as_u32(numeric)?,
        }),
        "SetSlashSurroundVoteBps" => Ok(GovernableAction::SetSlashSurroundVoteBps {
            value: as_u32(numeric)?,
        }),
        "SetMaxCommissionBps" => Ok(GovernableAction::SetMaxCommissionBps {
            value: as_u32(numeric)?,
        }),
        "SetGovernanceDelayEpochs" => Ok(GovernableAction::SetGovernanceDelayEpochs {
            value: as_u64(numeric)?,
        }),
        "SetGovernanceQuorumBps" => Ok(GovernableAction::SetGovernanceQuorumBps {
            value: as_u32(numeric)?,
        }),
        "SetGovernanceCriticalQuorumBps" => Ok(GovernableAction::SetGovernanceCriticalQuorumBps {
            value: as_u32(numeric)?,
        }),
        _ => Err(IndraError::UnknownAction),
    }
}

fn wire_vote(vote: u8) -> Result<u8, IndraError> {
    match vote {
        0 => Ok(1),
        1 => Ok(0),
        2 => Ok(2),
        _ => Err(IndraError::InvalidVote),
    }
}

fn compute_vote_commit_hash(wire_vote: u8, reveal_nonce: Bytes32) -> Bytes32 {
    let mut bytes = Vec::with_capacity(33);
    wire_vote.encode(&mut bytes);
    reveal_nonce.encode(&mut bytes);
    Bytes32::from(sha256(&bytes))
}

fn shared_null(
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

unsafe fn build_with_payload<F>(args: GovernanceCommonArgs, make_payload: F) -> i32
where
    F: FnOnce(&HybridKeypair) -> Result<GovernancePayload, IndraError> + UnwindSafe,
{
    if shared_null(
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
        let payload = make_payload(&keypair)?;
        let signer_id = signer_id_from_keypair(&keypair);
        let hex = build_governance_op(signer_id, args.nonce, payload, &keypair, &chain)?;
        write_hex_to_buf(&hex, args.out_hex, args.out_len)
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

#[derive(Clone, Copy)]
struct GovernanceCommonArgs {
    classical_seed: *const u8,
    pq_pk: *const u8,
    pq_sk: *const u8,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
}

/// Build and sign a governance Propose operation.
///
/// # Safety
///
/// All pointer arguments must be valid and non-null. `title`, `description`,
/// `action_json`, and `chain_id` must be valid null-terminated UTF-8 strings.
/// `deposit_utxo_id` must reference 32 readable bytes. Key and output pointers
/// must reference the documented readable/writable lengths.
#[no_mangle]
pub unsafe extern "C" fn indra_build_governance_propose(
    title: *const c_char,
    description: *const c_char,
    action_json: *const c_char,
    deposit_utxo_id: *const u8,
    classical_seed: *const u8,
    pq_pk: *const u8,
    pq_sk: *const u8,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if title.is_null()
        || description.is_null()
        || action_json.is_null()
        || deposit_utxo_id.is_null()
    {
        return IndraError::NullPointer.code();
    }
    build_with_payload(
        GovernanceCommonArgs {
            classical_seed,
            pq_pk,
            pq_sk,
            nonce,
            chain_id,
            out_hex,
            out_len,
        },
        |keypair| {
            let title_str = CStr::from_ptr(title)
                .to_str()
                .map_err(|_| IndraError::InvalidParam)?;
            let description_str = CStr::from_ptr(description)
                .to_str()
                .map_err(|_| IndraError::InvalidParam)?;
            Ok(GovernancePayload::Propose {
                action: parse_action_json(action_json)?,
                deposit_utxo_id: Bytes32::from(read_bytes32(deposit_utxo_id)),
                proposer_pubkey: hybrid_pubkey_from_keypair(keypair)?,
                title: VariableBytes::from_slice(title_str.as_bytes())
                    .map_err(|_| IndraError::InvalidParam)?,
                description: VariableBytes::from_slice(description_str.as_bytes())
                    .map_err(|_| IndraError::InvalidParam)?,
            })
        },
    )
}

/// Compute a vote commitment: SHA-256(wire_vote_byte || reveal_nonce).
///
/// # Safety
///
/// `reveal_nonce` must reference 32 readable bytes and `out_commitment` must
/// reference 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn indra_compute_vote_commitment(
    vote: u8,
    reveal_nonce: *const u8,
    out_commitment: *mut u8,
) -> i32 {
    if reveal_nonce.is_null() || out_commitment.is_null() {
        return IndraError::NullPointer.code();
    }
    match catch_unwind(|| {
        let vote = wire_vote(vote)?;
        let commitment = compute_vote_commit_hash(vote, Bytes32::from(read_bytes32(reveal_nonce)));
        std::slice::from_raw_parts_mut(out_commitment, 32).copy_from_slice(&commitment.0);
        Ok::<(), IndraError>(())
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

/// Build and sign a governance CommitVote operation.
///
/// # Safety
///
/// Pointer arguments must be valid and non-null. `proposal_id`,
/// `reveal_nonce`, and `out_commitment` must reference 32 bytes. Key and
/// output pointers follow `indra_build_governance_propose`.
#[no_mangle]
pub unsafe extern "C" fn indra_build_governance_commit(
    proposal_id: *const u8,
    vote: u8,
    reveal_nonce: *const u8,
    out_commitment: *mut u8,
    classical_seed: *const u8,
    pq_pk: *const u8,
    pq_sk: *const u8,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if proposal_id.is_null() || reveal_nonce.is_null() || out_commitment.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_payload(
        GovernanceCommonArgs {
            classical_seed,
            pq_pk,
            pq_sk,
            nonce,
            chain_id,
            out_hex,
            out_len,
        },
        |_| {
            let vote = wire_vote(vote)?;
            let commitment =
                compute_vote_commit_hash(vote, Bytes32::from(read_bytes32(reveal_nonce)));
            std::slice::from_raw_parts_mut(out_commitment, 32).copy_from_slice(&commitment.0);
            Ok(GovernancePayload::Commit {
                proposal_id: Bytes32::from(read_bytes32(proposal_id)),
                commit_hash: commitment,
            })
        },
    )
}

/// Build and sign a governance RevealVote operation.
///
/// # Safety
///
/// Pointer arguments must be valid and non-null. `proposal_id` and
/// `reveal_nonce` must each reference 32 readable bytes. Key and output
/// pointers follow `indra_build_governance_propose`.
#[no_mangle]
pub unsafe extern "C" fn indra_build_governance_reveal(
    proposal_id: *const u8,
    vote: u8,
    reveal_nonce: *const u8,
    classical_seed: *const u8,
    pq_pk: *const u8,
    pq_sk: *const u8,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if proposal_id.is_null() || reveal_nonce.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_payload(
        GovernanceCommonArgs {
            classical_seed,
            pq_pk,
            pq_sk,
            nonce,
            chain_id,
            out_hex,
            out_len,
        },
        |_| {
            Ok(GovernancePayload::Reveal {
                proposal_id: Bytes32::from(read_bytes32(proposal_id)),
                vote: wire_vote(vote)?,
                nonce: Bytes32::from(read_bytes32(reveal_nonce)),
            })
        },
    )
}

/// Build and sign a GovernanceRedelegate operation.
///
/// # Safety
///
/// Pointer arguments must be valid and non-null. The ID pointers must each
/// reference 32 readable bytes. Key and output pointers follow
/// `indra_build_governance_propose`.
#[no_mangle]
pub unsafe extern "C" fn indra_build_governance_redelegate(
    proposal_id: *const u8,
    from_validator_id: *const u8,
    to_validator_id: *const u8,
    amount_spark: u64,
    classical_seed: *const u8,
    pq_pk: *const u8,
    pq_sk: *const u8,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if proposal_id.is_null() || from_validator_id.is_null() || to_validator_id.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_payload(
        GovernanceCommonArgs {
            classical_seed,
            pq_pk,
            pq_sk,
            nonce,
            chain_id,
            out_hex,
            out_len,
        },
        |_| {
            Ok(GovernancePayload::Redelegate {
                proposal_id: Bytes32::from(read_bytes32(proposal_id)),
                from_validator: Bytes32::from(read_bytes32(from_validator_id)),
                to_validator: Bytes32::from(read_bytes32(to_validator_id)),
                amount_spark,
            })
        },
    )
}

/// Build and sign a governance Execute operation.
///
/// # Safety
///
/// Pointer arguments must be valid and non-null. `proposal_id` must reference
/// 32 readable bytes. Key and output pointers follow
/// `indra_build_governance_propose`.
#[no_mangle]
pub unsafe extern "C" fn indra_build_governance_execute(
    proposal_id: *const u8,
    classical_seed: *const u8,
    pq_pk: *const u8,
    pq_sk: *const u8,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if proposal_id.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_payload(
        GovernanceCommonArgs {
            classical_seed,
            pq_pk,
            pq_sk,
            nonce,
            chain_id,
            out_hex,
            out_len,
        },
        |_| {
            Ok(GovernancePayload::Execute {
                proposal_id: Bytes32::from(read_bytes32(proposal_id)),
            })
        },
    )
}

/// Build and sign a governance Cancel operation.
///
/// # Safety
///
/// Pointer arguments must be valid and non-null. `proposal_id` must reference
/// 32 readable bytes. Key and output pointers follow
/// `indra_build_governance_propose`.
#[no_mangle]
pub unsafe extern "C" fn indra_build_governance_cancel(
    proposal_id: *const u8,
    classical_seed: *const u8,
    pq_pk: *const u8,
    pq_sk: *const u8,
    nonce: u64,
    chain_id: *const c_char,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if proposal_id.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_payload(
        GovernanceCommonArgs {
            classical_seed,
            pq_pk,
            pq_sk,
            nonce,
            chain_id,
            out_hex,
            out_len,
        },
        |_| {
            Ok(GovernancePayload::Cancel {
                proposal_id: Bytes32::from(read_bytes32(proposal_id)),
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{indra_keygen, IndraKeyPair, INDRA_OP_HEX_MAX_BYTES};
    use indra_core::{
        codec::Decode,
        types::governance::{GovernanceOpV2, GovernancePayload},
    };
    use std::ffi::{CStr, CString};

    const OK: i32 = IndraError::Ok as i32;

    fn keys() -> IndraKeyPair {
        let mut keys = IndraKeyPair::zeroed();
        unsafe {
            assert_eq!(indra_keygen([0x43u8; 32].as_ptr(), &mut keys), OK);
        }
        keys
    }

    fn out() -> Vec<c_char> {
        vec![0; INDRA_OP_HEX_MAX_BYTES]
    }

    unsafe fn decode(out: &[c_char]) -> GovernanceOpV2 {
        let hex = CStr::from_ptr(out.as_ptr()).to_str().unwrap();
        GovernanceOpV2::decode_exact(&hex::decode(hex).unwrap()).unwrap()
    }

    #[test]
    fn governance_commit_reveal_commitment_matches() {
        let vote = 0u8;
        let reveal_nonce = [0xABu8; 32];
        let mut out_commitment = [0u8; 32];
        let result = unsafe {
            indra_compute_vote_commitment(vote, reveal_nonce.as_ptr(), out_commitment.as_mut_ptr())
        };
        assert_eq!(result, OK);
        let expected = compute_vote_commit_hash(1, Bytes32::from(reveal_nonce));
        assert_eq!(out_commitment, expected.0);
    }

    #[test]
    fn governance_propose_with_valid_action_json() {
        let keys = keys();
        let title = CString::new("Reduce liveness penalty").unwrap();
        let description = CString::new("Reduce slash_liveness_bps from 10 to 8").unwrap();
        let action_json = CString::new(r#"{"type":"SetSlashLivenessBps","value":8}"#).unwrap();
        let chain_id = CString::new("indra-testnet-1").unwrap();
        let deposit_utxo_id = [0x01u8; 32];
        let mut out = out();
        let result = unsafe {
            indra_build_governance_propose(
                title.as_ptr(),
                description.as_ptr(),
                action_json.as_ptr(),
                deposit_utxo_id.as_ptr(),
                keys.classical_seed.as_ptr(),
                keys.pq_pk.as_ptr(),
                keys.pq_sk.as_ptr(),
                1,
                chain_id.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(result, OK);
        let op = unsafe { decode(&out) };
        assert_eq!(op.nonce, 1);
        assert!(matches!(op.payload, GovernancePayload::Propose { .. }));
    }

    #[test]
    fn governance_unknown_action_type_rejected() {
        let keys = keys();
        let title = CString::new("Unknown").unwrap();
        let description = CString::new("Unknown").unwrap();
        let action_json = CString::new(r#"{"type":"UnknownAction","value":0}"#).unwrap();
        let chain_id = CString::new("indra-testnet-1").unwrap();
        let deposit_utxo_id = [0x01u8; 32];
        let mut out = out();
        let result = unsafe {
            indra_build_governance_propose(
                title.as_ptr(),
                description.as_ptr(),
                action_json.as_ptr(),
                deposit_utxo_id.as_ptr(),
                keys.classical_seed.as_ptr(),
                keys.pq_pk.as_ptr(),
                keys.pq_sk.as_ptr(),
                1,
                chain_id.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(result, IndraError::UnknownAction.code());
    }

    #[test]
    fn governance_invalid_vote_rejected() {
        let reveal_nonce = [0xABu8; 32];
        let mut out_commitment = [0u8; 32];
        let result = unsafe {
            indra_compute_vote_commitment(3, reveal_nonce.as_ptr(), out_commitment.as_mut_ptr())
        };
        assert_eq!(result, IndraError::InvalidVote.code());
    }
}
