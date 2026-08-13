//! C FFI builders for INDRA governance operations.

use std::{
    ffi::c_char,
    panic::{catch_unwind, UnwindSafe},
};

use crate::{
    bounded_utf8,
    errors::IndraError,
    handles,
    staking::{read_bytes32, read_chain_id, write_hex_to_buf},
    IndraKeyHandle, IndraSessionHandle,
};
use indra_core::{
    codec::Encode,
    types::{
        crypto::{HybridPubKey, HybridSignature},
        governance::{
            governance_signing_domain, governance_vote_commit_hash, GovernableAction,
            GovernanceOpV2, GovernancePayload,
        },
        primitives::{Bytes32, VariableBytes},
    },
};
use indra_crypto::{hybrid::HybridKeypair, sha256};
use serde_json::Value;

fn hybrid_pubkey_from_keypair(keypair: &HybridKeypair) -> Result<HybridPubKey, IndraError> {
    let public = keypair.public_key();
    Ok(HybridPubKey {
        classical_pk: Bytes32::from(public.classical.0),
        pq_pk: VariableBytes::from_slice(&public.pq.0).map_err(|_| IndraError::TxBuildFailed)?,
    })
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

fn wire_signature(
    signature: &indra_crypto::HybridSignature,
) -> Result<HybridSignature, IndraError> {
    Ok(HybridSignature {
        classical_sig: VariableBytes::from_slice(&signature.classical.0)
            .map_err(|_| IndraError::TxBuildFailed)?,
        pq_sig: VariableBytes::from_slice(&signature.pq.0)
            .map_err(|_| IndraError::TxBuildFailed)?,
    })
}

fn dummy_signature() -> Result<HybridSignature, IndraError> {
    Ok(HybridSignature {
        classical_sig: VariableBytes::from_slice(&[0; indra_crypto::CLASSICAL_SIG_BYTES])
            .map_err(|_| IndraError::TxBuildFailed)?,
        pq_sig: VariableBytes::from_slice(&[0; indra_crypto::PQ_SIG_BYTES])
            .map_err(|_| IndraError::TxBuildFailed)?,
    })
}

unsafe fn build_with_cold_payload_handle<F>(args: ColdGovernanceHandleArgs, make_payload: F) -> i32
where
    F: FnOnce(
            &HybridKeypair,
            &indra_crypto::ColdHybridKeypair,
        ) -> Result<GovernancePayload, IndraError>
        + UnwindSafe,
{
    if args.chain_id.is_null() || args.out_hex.is_null() {
        return IndraError::NullPointer.code();
    }
    if args.out_len != 0 {
        *args.out_hex = 0;
    }
    match catch_unwind(|| {
        let hot_lease = handles::acquire_hot_signing_lease(args.session, args.hot_handle)?;
        let cold_lease = handles::acquire_cold_signing_lease(args.session, args.cold_handle)?;
        hot_lease.checkpoint()?;
        cold_lease.checkpoint()?;
        let hot_keypair = hot_lease.material().keypair()?;
        let cold_keypair = cold_lease.material().cold_keypair()?;
        let signer_id = Bytes32::from(hot_lease.material().hot_public()?.validator_id);
        let chain = read_chain_id(args.chain_id, args.chain_id_len)?;
        let payload = make_payload(&hot_keypair, &cold_keypair)?;
        let mut op = GovernanceOpV2 {
            action_type: payload.action_type(),
            signer_id,
            nonce: 0,
            payload,
            signature: dummy_signature()?,
        };
        op.validate_structure()
            .map_err(|_| IndraError::TxBuildFailed)?;
        let message = op
            .cold_authorization_signing_bytes(&chain)
            .map_err(|_| IndraError::TxBuildFailed)?
            .ok_or(IndraError::TxBuildFailed)?;
        op.signature = wire_signature(
            &cold_keypair
                .sign(&message)
                .map_err(|_| IndraError::SignFailed)?,
        )?;
        let hex = hex::encode(op.encode_to_vec());
        hot_lease
            .publish(|| cold_lease.publish(|| write_hex_to_buf(&hex, args.out_hex, args.out_len)))
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(error)) => error.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

#[derive(Clone, Copy)]
struct ColdGovernanceHandleArgs {
    session: IndraSessionHandle,
    hot_handle: IndraKeyHandle,
    cold_handle: IndraKeyHandle,
    chain_id: *const c_char,
    chain_id_len: usize,
    out_hex: *mut c_char,
    out_len: usize,
}

fn parse_action_json(
    action_json: *const c_char,
    action_json_len: usize,
) -> Result<GovernableAction, IndraError> {
    let raw = unsafe { bounded_utf8(action_json, action_json_len, crate::MAX_FFI_STRING_BYTES) }
        .map_err(|_| IndraError::InvalidJson)?;
    let value: Value = serde_json::from_str(&raw).map_err(|_| IndraError::InvalidJson)?;
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
        // Governance reveal wire values are defined by the state machine:
        // 0 = NO, 1 = YES. Abstain is represented by not revealing.
        0 => Ok(0),
        1 => Ok(1),
        _ => Err(IndraError::InvalidVote),
    }
}

unsafe fn build_with_payload_handle<F>(args: GovernanceHandleArgs, make_payload: F) -> i32
where
    F: FnOnce(&HybridKeypair) -> Result<GovernancePayload, IndraError> + UnwindSafe,
{
    if args.chain_id.is_null() || args.out_hex.is_null() {
        return IndraError::NullPointer.code();
    }
    if args.out_len != 0 {
        *args.out_hex = 0;
    }

    match catch_unwind(|| {
        let lease = handles::acquire_hot_signing_lease(args.session, args.handle)?;
        lease.checkpoint()?;
        let keypair = lease.material().keypair()?;
        let chain = read_chain_id(args.chain_id, args.chain_id_len)?;
        let payload = make_payload(&keypair)?;
        let signer_id = Bytes32::from(lease.material().hot_public()?.validator_id);
        let hex = build_governance_op(signer_id, args.nonce, payload, &keypair, &chain)?;
        lease.publish(|| write_hex_to_buf(&hex, args.out_hex, args.out_len))
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

#[derive(Clone, Copy)]
struct GovernanceHandleArgs {
    session: IndraSessionHandle,
    handle: IndraKeyHandle,
    nonce: u64,
    chain_id: *const c_char,
    chain_id_len: usize,
    out_hex: *mut c_char,
    out_len: usize,
}

#[no_mangle]
pub unsafe extern "C" fn indra_build_governance_propose_with_handle(
    session: IndraSessionHandle,
    title: *const c_char,
    title_len: usize,
    description: *const c_char,
    description_len: usize,
    action_json: *const c_char,
    action_json_len: usize,
    deposit_utxo_id: *const u8,
    hot_handle: IndraKeyHandle,
    cold_handle: IndraKeyHandle,
    cold_key_version: u64,
    cold_nonce: u64,
    chain_id: *const c_char,
    chain_id_len: usize,
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
    build_with_cold_payload_handle(
        ColdGovernanceHandleArgs {
            session,
            hot_handle,
            cold_handle,
            chain_id,
            chain_id_len,
            out_hex,
            out_len,
        },
        |_hot_keypair, cold_keypair| {
            let title_str = bounded_utf8(title, title_len, crate::MAX_FFI_STRING_BYTES)?;
            let description_str =
                bounded_utf8(description, description_len, crate::MAX_FFI_STRING_BYTES)?;
            Ok(GovernancePayload::Propose {
                action: parse_action_json(action_json, action_json_len)?,
                deposit_utxo_id: Bytes32::from(read_bytes32(deposit_utxo_id)),
                proposer_pubkey: {
                    let public = cold_keypair.public_key();
                    let public = public.as_complete_hybrid();
                    HybridPubKey {
                        classical_pk: Bytes32::from(public.classical.0),
                        pq_pk: VariableBytes::from_slice(&public.pq.0)
                            .map_err(|_| IndraError::TxBuildFailed)?,
                    }
                },
                title: VariableBytes::from_slice(title_str.as_bytes())
                    .map_err(|_| IndraError::InvalidParam)?,
                description: VariableBytes::from_slice(description_str.as_bytes())
                    .map_err(|_| IndraError::InvalidParam)?,
                cold_authorization: Some(
                    indra_core::types::governance::ColdGovernanceAuthorization {
                        cold_key_version,
                        cold_nonce,
                    },
                ),
            })
        },
    )
}

/// Compute the canonical domain-separated governance vote commitment over the
/// proposal, complete validator identity, vote, and reveal nonce.
///
/// # Safety
///
/// Each input pointer must reference 32 readable bytes except `vote`;
/// `out_commitment` must reference 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn indra_compute_vote_commitment(
    proposal_id: *const u8,
    validator_id: *const u8,
    vote: u8,
    reveal_nonce: *const u8,
    out_commitment: *mut u8,
) -> i32 {
    if proposal_id.is_null()
        || validator_id.is_null()
        || reveal_nonce.is_null()
        || out_commitment.is_null()
    {
        return IndraError::NullPointer.code();
    }
    match catch_unwind(|| {
        let vote = wire_vote(vote)?;
        let commitment = governance_vote_commit_hash(
            Bytes32::from(read_bytes32(proposal_id)),
            Bytes32::from(read_bytes32(validator_id)),
            vote,
            Bytes32::from(read_bytes32(reveal_nonce)),
        );
        std::slice::from_raw_parts_mut(out_commitment, 32).copy_from_slice(&commitment.0);
        Ok::<(), IndraError>(())
    }) {
        Ok(Ok(())) => IndraError::Ok.code(),
        Ok(Err(err)) => err.code(),
        Err(_) => IndraError::Internal.code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn indra_build_governance_commit_with_handle(
    session: IndraSessionHandle,
    proposal_id: *const u8,
    vote: u8,
    reveal_nonce: *const u8,
    out_commitment: *mut u8,
    hot_handle: IndraKeyHandle,
    cold_handle: IndraKeyHandle,
    cold_key_version: u64,
    cold_nonce: u64,
    chain_id: *const c_char,
    chain_id_len: usize,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if proposal_id.is_null() || reveal_nonce.is_null() || out_commitment.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_cold_payload_handle(
        ColdGovernanceHandleArgs {
            session,
            hot_handle,
            cold_handle,
            chain_id,
            chain_id_len,
            out_hex,
            out_len,
        },
        |hot_keypair, _cold_keypair| {
            let vote = wire_vote(vote)?;
            let signer_id = hybrid_pubkey_from_keypair(hot_keypair)?.identity_id();
            let commitment = governance_vote_commit_hash(
                Bytes32::from(read_bytes32(proposal_id)),
                signer_id,
                vote,
                Bytes32::from(read_bytes32(reveal_nonce)),
            );
            std::slice::from_raw_parts_mut(out_commitment, 32).copy_from_slice(&commitment.0);
            Ok(GovernancePayload::Commit {
                proposal_id: Bytes32::from(read_bytes32(proposal_id)),
                commit_hash: commitment,
                cold_authorization: Some(
                    indra_core::types::governance::ColdGovernanceAuthorization {
                        cold_key_version,
                        cold_nonce,
                    },
                ),
            })
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn indra_build_governance_reveal_with_handle(
    session: IndraSessionHandle,
    proposal_id: *const u8,
    vote: u8,
    reveal_nonce: *const u8,
    hot_handle: IndraKeyHandle,
    cold_handle: IndraKeyHandle,
    cold_key_version: u64,
    cold_nonce: u64,
    chain_id: *const c_char,
    chain_id_len: usize,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if proposal_id.is_null() || reveal_nonce.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_cold_payload_handle(
        ColdGovernanceHandleArgs {
            session,
            hot_handle,
            cold_handle,
            chain_id,
            chain_id_len,
            out_hex,
            out_len,
        },
        |_hot_keypair, _cold_keypair| {
            Ok(GovernancePayload::Reveal {
                proposal_id: Bytes32::from(read_bytes32(proposal_id)),
                vote: wire_vote(vote)?,
                nonce: Bytes32::from(read_bytes32(reveal_nonce)),
                cold_authorization: Some(
                    indra_core::types::governance::ColdGovernanceAuthorization {
                        cold_key_version,
                        cold_nonce,
                    },
                ),
            })
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn indra_build_governance_redelegate_with_handle(
    session: IndraSessionHandle,
    proposal_id: *const u8,
    from_validator_id: *const u8,
    to_validator_id: *const u8,
    amount_spark: u64,
    handle: IndraKeyHandle,
    nonce: u64,
    chain_id: *const c_char,
    chain_id_len: usize,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if proposal_id.is_null() || from_validator_id.is_null() || to_validator_id.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_payload_handle(
        GovernanceHandleArgs {
            session,
            handle,
            nonce,
            chain_id,
            chain_id_len,
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

#[no_mangle]
pub unsafe extern "C" fn indra_build_governance_execute_with_handle(
    session: IndraSessionHandle,
    proposal_id: *const u8,
    handle: IndraKeyHandle,
    nonce: u64,
    chain_id: *const c_char,
    chain_id_len: usize,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if proposal_id.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_payload_handle(
        GovernanceHandleArgs {
            session,
            handle,
            nonce,
            chain_id,
            chain_id_len,
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

#[no_mangle]
pub unsafe extern "C" fn indra_build_governance_cancel_with_handle(
    session: IndraSessionHandle,
    proposal_id: *const u8,
    hot_handle: IndraKeyHandle,
    cold_handle: IndraKeyHandle,
    cold_key_version: u64,
    cold_nonce: u64,
    chain_id: *const c_char,
    chain_id_len: usize,
    out_hex: *mut c_char,
    out_len: usize,
) -> i32 {
    if proposal_id.is_null() {
        return IndraError::NullPointer.code();
    }
    build_with_cold_payload_handle(
        ColdGovernanceHandleArgs {
            session,
            hot_handle,
            cold_handle,
            chain_id,
            chain_id_len,
            out_hex,
            out_len,
        },
        |_hot_keypair, _cold_keypair| {
            Ok(GovernancePayload::Cancel {
                proposal_id: Bytes32::from(read_bytes32(proposal_id)),
                cold_authorization: Some(
                    indra_core::types::governance::ColdGovernanceAuthorization {
                        cold_key_version,
                        cold_nonce,
                    },
                ),
            })
        },
    )
}
