//! Transaction builder — constructs, signs and serialises TransactionV1.
//!
//! ## Flow
//!
//! 1. Caller provides: recipient pubkey, amount, fee, wallet, signing keypair
//! 2. Builder selects UTXOs (coin selection)
//! 3. Builds outputs: recipient output + change output (if needed)
//! 4. Generates Pedersen commitments + Bulletproof range proofs for each output
//! 5. Signs the transaction with the hybrid keypair
//! 6. Returns serialised hex ready for indra_sendTransaction RPC

use curve25519_dalek::scalar::Scalar;
use indra_core::{
    codec::Encode,
    types::{
        crypto::{ColdHybridPubKey, CommitmentV1, HybridPubKey, HybridSignature},
        primitives::{
            Bytes32, ProtocolVersion, VariableBytes, MAX_RANGE_PROOF_BYTES,
            TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES,
        },
        stake_position::PositionCustodyV1,
        staking::{ColdStakingAuthorization, StakeDepositProof, StakingOp, StakingOpBody},
        transaction::{InputV1, OutputV1, TransactionV1},
    },
};
use indra_crypto::{
    hybrid::{ClassicalKeypair, ColdHybridKeypair, HybridKeypair, PqKeypair},
    pedersen::commit,
    sender_derive_payment_blinding_v1, sha256, PaymentAddress, PaymentPubKeyV1,
};

use crate::{
    error::{CliError, CliResult},
    wallet::{PendingChange, Wallet},
};

/// Minimum fee in Spark.
/// Transactions with Bulletproof range proofs are ~4-5 KB.
/// At 8 decimal places this is 0.0005 INDRA = 50,000 Spark.
pub const MIN_FEE_SPARK: u64 = 50_000;

/// Dust limit — outputs below this are rejected.
pub const DUST_LIMIT_SPARK: u64 = 100_000;

/// Parameters for building a transaction.
pub struct TxParams<'a> {
    /// Chain identifier used in transaction signing.
    pub chain_id: &'a str,
    /// Recipient's complete canonical payment address.
    pub recipient_address: &'a str,
    /// Amount to send in Spark.
    pub amount_spark: u64,
    /// Fee in Spark (must be >= MIN_FEE_SPARK).
    pub fee_spark: u64,
    /// Sender's wallet (for coin selection).
    pub wallet: &'a Wallet,
    /// Sender's hybrid seed (for Ed25519 signing).
    pub hybrid_seed: [u8; 32],
    /// Sender's ML-DSA-87 seed bytes (from keys.json).
    pub pq_sk_bytes: Vec<u8>,
    /// Sender's own pubkey (for change output).
    pub sender_pubkey: HybridPubKey,
    /// Sender's canonical payment key for self-directed change.
    pub sender_payment_pubkey: PaymentPubKeyV1,
}

/// The result of building a transaction.
pub struct BuiltTransaction {
    /// The serialised transaction (hex-encoded).
    pub tx_hex: String,
    /// The transaction ID (SHA-256 of serialised bytes).
    pub tx_id: String,
    /// Change amount returned to sender in Spark (0 if exact).
    pub change_spark: u64,
    /// The blinding factor for the recipient output.
    pub recipient_blinding: [u8; 32],
    /// The blinding factor for the change output (if any).
    pub change_blinding: Option<[u8; 32]>,
    /// The UTXO IDs that were spent.
    pub spent_utxo_ids: Vec<Bytes32>,
    /// Pending change output to persist until the transaction is mined.
    pub pending_change: Option<PendingChange>,
}

/// The result of building a staking operation.
pub struct BuiltStakingOp {
    /// The serialised staking operation (hex-encoded).
    pub op_hex: String,
    /// SHA-256 of the serialised operation.
    pub op_id: String,
}

/// Key material and replay namespace for a canonical position exit.
pub enum StakePositionExitSigner<'a> {
    /// Ordinary delegator authorization through the staking nonce namespace.
    Delegator {
        /// Delegator identity keypair.
        keypair: &'a HybridKeypair,
        /// Next ordinary staking nonce.
        nonce: u64,
    },
    /// Validator self-position authorization through the cold-role namespace.
    ValidatorCold {
        /// Independent validator cold-role keypair.
        keypair: &'a ColdHybridKeypair,
        /// Currently registered cold-key version.
        cold_key_version: u64,
        /// Next nonce in that cold-key version's namespace.
        cold_nonce: u64,
    },
}

/// Build and sign a transaction.
pub fn build_transaction(params: &TxParams<'_>) -> CliResult<BuiltTransaction> {
    // 1. Validate amount and fee
    if params.amount_spark < DUST_LIMIT_SPARK {
        return Err(CliError::Transaction(format!(
            "amount {} Spark is below dust limit {}",
            params.amount_spark, DUST_LIMIT_SPARK
        )));
    }
    if params.fee_spark < MIN_FEE_SPARK {
        return Err(CliError::Transaction(format!(
            "fee {} Spark is below minimum {}",
            params.fee_spark, MIN_FEE_SPARK
        )));
    }

    // 2. Decode and authenticate the complete recipient descriptor.
    let recipient_address =
        PaymentAddress::from_text(params.recipient_address, params.chain_id.as_bytes()).map_err(
            |e| CliError::Transaction(format!("invalid recipient payment address: {e}")),
        )?;
    let recipient_pubkey = crypto_pubkey_to_wire(recipient_address.owner_pubkey())?;

    // 3. Coin selection
    let selected = params
        .wallet
        .select_utxos(params.amount_spark, params.fee_spark)?;
    let total_in: u64 = selected.iter().map(|e| e.value_spark).sum();
    let change_spark = total_in
        .saturating_sub(params.amount_spark)
        .saturating_sub(params.fee_spark);

    // 4. Build inputs
    let inputs: Vec<InputV1> = selected
        .iter()
        .map(|e| {
            // nullifier = SHA-256(hybrid_seed || utxo_id)
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&params.hybrid_seed);
            data.extend_from_slice(&e.utxo_id.0);
            let nullifier = Bytes32::from(sha256(&data));
            InputV1 {
                utxo_id: e.utxo_id,
                nullifier,
            }
        })
        .collect();

    let mut rng = rand::rngs::OsRng;
    // 5. Every ordinary output uses the same mandatory note-construction path.
    let recipient_payment = sender_derive_payment_blinding_v1(
        recipient_address.payment_pubkey(),
        params.chain_id.as_bytes(),
        recipient_address.owner_id(),
        0,
        params.amount_spark,
        0,
    )
    .map_err(|e| CliError::Crypto(e.to_string()))?;
    let recipient_blinding = recipient_payment.blinding;

    let change_payment = if change_spark > DUST_LIMIT_SPARK {
        Some(
            sender_derive_payment_blinding_v1(
                &params.sender_payment_pubkey,
                params.chain_id.as_bytes(),
                sha256(&params.sender_pubkey.classical_pk.0),
                1,
                change_spark,
                0,
            )
            .map_err(|e| CliError::Crypto(e.to_string()))?,
        )
    } else {
        None
    };
    let change_blinding = change_payment.as_ref().map(|payment| payment.blinding);

    let input_blinding_sum = selected.iter().fold(Scalar::ZERO, |acc, entry| {
        acc + Scalar::from_bytes_mod_order(entry.blinding)
    });
    let recipient_blinding_scalar = Scalar::from_bytes_mod_order(recipient_blinding);
    let change_blinding_scalar = change_blinding
        .map(Scalar::from_bytes_mod_order)
        .unwrap_or(Scalar::ZERO);
    let fee_blinding =
        (input_blinding_sum - recipient_blinding_scalar - change_blinding_scalar).to_bytes();

    // 6. Build outputs with Pedersen commitments + range proofs
    let mut outputs = Vec::new();

    // Recipient output
    let recipient_commitment = commit(params.amount_spark, &recipient_blinding);
    let recipient_proof =
        indra_crypto::prove_range(params.amount_spark, &recipient_blinding, &mut rng)
            .map_err(|e| CliError::Transaction(format!("range proof failed: {e}")))?;

    outputs.push(OutputV1 {
        value_spark: params.amount_spark,
        commitment: CommitmentV1 {
            compressed_point: Bytes32::from(recipient_commitment.0),
        },
        owner_pubkey: recipient_pubkey,
        range_proof: VariableBytes::<MAX_RANGE_PROOF_BYTES>::from_slice(&recipient_proof)
            .map_err(|_| CliError::Transaction("range proof too large".into()))?,
        lock_height: 0,
    });

    // Change output (if above dust)
    let mut pending_change = None;
    if let Some(cb) = change_blinding {
        let change_commitment = commit(change_spark, &cb);
        let change_proof = indra_crypto::prove_range(change_spark, &cb, &mut rng)
            .map_err(|e| CliError::Transaction(format!("change range proof failed: {e}")))?;

        let change_output = OutputV1 {
            value_spark: change_spark,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from(change_commitment.0),
            },
            owner_pubkey: params.sender_pubkey.clone(),
            range_proof: VariableBytes::<MAX_RANGE_PROOF_BYTES>::from_slice(&change_proof)
                .map_err(|_| CliError::Transaction("change range proof too large".into()))?,
            lock_height: 0,
        };
        pending_change = Some(PendingChange {
            output: change_output.clone(),
            blinding: cb,
        });
        outputs.push(change_output);
    }

    // 7. Build fee commitment
    let fee_commitment = commit(params.fee_spark, &fee_blinding);

    // 8. Build unsigned transaction
    let mut tx = TransactionV1 {
        version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION_PAYMENT_NOTES),
        signature_module_id: 1,
        inputs,
        outputs,
        payment_notes: std::iter::once(recipient_payment.note)
            .chain(change_payment.map(|payment| payment.note))
            .collect(),
        fee_amount: params.fee_spark,
        fee_blinding: Bytes32::from(fee_blinding),
        fee_commitment: CommitmentV1 {
            compressed_point: Bytes32::from(fee_commitment.0),
        },
        signature: dummy_signature()?,
    };

    // 9. Sign: compute tx hash (all fields except signature), then sign
    let tx_bytes_unsigned = tx.signing_bytes(params.chain_id);

    let classical = ClassicalKeypair::from_seed(&params.hybrid_seed);
    let pq = PqKeypair::from_bytes(
        // pq_pk is embedded in sender_pubkey
        params.sender_pubkey.pq_pk.as_slice(),
        &params.pq_sk_bytes,
    )
    .map_err(|e| CliError::Crypto(e.to_string()))?;
    let keypair = HybridKeypair::new(classical, pq);
    let sig = keypair
        .sign(&tx_bytes_unsigned)
        .map_err(|e| CliError::Crypto(e.to_string()))?;

    let classical_sig_bytes = sig.classical.0.to_vec();
    let pq_sig_bytes = sig.pq.0.to_vec();

    tx.signature = HybridSignature {
        classical_sig: VariableBytes::from_slice(&classical_sig_bytes)
            .map_err(|_| CliError::Transaction("classical sig too large".into()))?,
        pq_sig: VariableBytes::from_slice(&pq_sig_bytes)
            .map_err(|_| CliError::Transaction("pq sig too large".into()))?,
    };

    // 10. Serialise
    let tx_bytes = tx.encode_to_vec();
    let tx_id = hex::encode(sha256(&tx_bytes));
    let tx_hex = hex::encode(&tx_bytes);
    let spent_ids: Vec<Bytes32> = selected.iter().map(|e| e.utxo_id).collect();

    Ok(BuiltTransaction {
        tx_hex,
        tx_id,
        change_spark,
        recipient_blinding,
        change_blinding,
        spent_utxo_ids: spent_ids,
        pending_change,
    })
}

/// Build and sign a validator self-stake operation.
pub fn build_self_stake_op(
    deposit_utxo_id: Bytes32,
    deposit_proof: StakeDepositProof,
    validator_keypair: &HybridKeypair,
    nonce: u64,
    chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    build_signed_staking_op(
        StakingOpBody::SelfStake {
            deposit_utxo_id,
            validator_pubkey: hybrid_pubkey_from_keypair(validator_keypair)?,
            deposit_proof: Some(deposit_proof),
            cold_authorization: None,
        },
        validator_keypair,
        nonce,
        chain_id,
    )
}

/// Build and sign a validator registration staking operation.
pub fn build_register_validator_op_with_cold(
    commission_bps: u32,
    deposit_utxo_id: Bytes32,
    deposit_proof: StakeDepositProof,
    keypair: &HybridKeypair,
    cold_keypair: &ColdHybridKeypair,
    vrf_pk: [u8; 32],
    nonce: u64,
    chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    let cold_public = cold_keypair.public_key();
    let cold_public = cold_public.as_complete_hybrid();
    let cold_pubkey = ColdHybridPubKey {
        classical_pk: Bytes32::from(cold_public.classical.0),
        pq_pk: VariableBytes::from_slice(&cold_public.pq.0)
            .map_err(|_| CliError::Transaction("cold PQ public key too large".into()))?,
    };
    let mut op = StakingOp {
        body: StakingOpBody::RegisterValidator {
            commission_bps,
            deposit_utxo_id,
            validator_pubkey: hybrid_pubkey_from_keypair(keypair)?,
            vrf_pk,
            deposit_proof: Some(deposit_proof),
            cold_pubkey: Some(cold_pubkey),
            cold_signature: Some(dummy_signature()?),
        },
        nonce,
        signature: dummy_signature()?,
    };
    let message = op
        .register_validator_dual_signing_bytes(chain_id)
        .map_err(|e| CliError::Transaction(e.to_string()))?
        .ok_or_else(|| {
            CliError::Transaction("registration dual-signing message unavailable".into())
        })?;
    let hot_sig = keypair
        .sign(&message)
        .map_err(|e| CliError::Crypto(e.to_string()))?;
    let cold_sig = cold_keypair
        .sign(&message)
        .map_err(|e| CliError::Crypto(e.to_string()))?;
    op.signature = HybridSignature {
        classical_sig: VariableBytes::from_slice(&hot_sig.classical.0).unwrap(),
        pq_sig: VariableBytes::from_slice(&hot_sig.pq.0).unwrap(),
    };
    if let StakingOpBody::RegisterValidator { cold_signature, .. } = &mut op.body {
        *cold_signature = Some(HybridSignature {
            classical_sig: VariableBytes::from_slice(&cold_sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&cold_sig.pq.0).unwrap(),
        });
    }
    let op_bytes = op.encode_to_vec();
    Ok(BuiltStakingOp {
        op_hex: hex::encode(&op_bytes),
        op_id: hex::encode(sha256(&op_bytes)),
    })
}

/// Registration without an independently persisted cold key is unsupported.
pub fn build_register_validator_op(
    _commission_bps: u32,
    _deposit_utxo_id: Bytes32,
    _deposit_proof: StakeDepositProof,
    _keypair: &HybridKeypair,
    _vrf_pk: [u8; 32],
    _nonce: u64,
    _chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    Err(CliError::Transaction(
        "validator registration requires an independent cold keypair".into(),
    ))
}

/// Build and sign a delegate staking operation.
pub fn build_delegate_op(
    validator_id: Bytes32,
    deposit_utxo_id: Bytes32,
    deposit_proof: StakeDepositProof,
    delegator_keypair: &HybridKeypair,
    nonce: u64,
    chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    build_signed_staking_op(
        StakingOpBody::Delegate {
            validator_id,
            deposit_utxo_id,
            delegator_pubkey: hybrid_pubkey_from_keypair(delegator_keypair)?,
            deposit_proof: Some(deposit_proof),
        },
        delegator_keypair,
        nonce,
        chain_id,
    )
}

/// Build and sign a canonical active-position exit.
pub fn build_exit_stake_position_op(
    position_id: Bytes32,
    amount_spark: u64,
    custody: PositionCustodyV1,
    signer: StakePositionExitSigner<'_>,
    chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    match (custody, signer) {
        (
            custody @ PositionCustodyV1::DelegatorIdentity { .. },
            StakePositionExitSigner::Delegator { keypair, nonce },
        ) => build_signed_staking_op(
            StakingOpBody::ExitStakePosition {
                position_id,
                amount_spark,
                custody,
                cold_authorization: None,
            },
            keypair,
            nonce,
            chain_id,
        ),
        (
            custody @ PositionCustodyV1::ValidatorColdIdentity { .. },
            StakePositionExitSigner::ValidatorCold {
                keypair,
                cold_key_version,
                cold_nonce,
            },
        ) => {
            let mut op = StakingOp {
                body: StakingOpBody::ExitStakePosition {
                    position_id,
                    amount_spark,
                    custody,
                    cold_authorization: Some(ColdStakingAuthorization {
                        cold_key_version,
                        cold_nonce,
                    }),
                },
                nonce: 0,
                signature: dummy_signature()?,
            };
            op.validate_structure()
                .map_err(|e| CliError::Transaction(e.to_string()))?;
            let message = op
                .cold_authorization_signing_bytes(chain_id)
                .map_err(|e| CliError::Transaction(e.to_string()))?
                .ok_or_else(|| {
                    CliError::Transaction("missing cold authorization message".into())
                })?;
            let signature = keypair
                .sign(&message)
                .map_err(|e| CliError::Crypto(e.to_string()))?;
            op.signature = wire_hybrid_signature(&signature)?;
            encode_built_staking_op(op)
        }
        _ => Err(CliError::Transaction(
            "position custody and exit signer role do not match".into(),
        )),
    }
}

/// Build and sign a claim-rewards staking operation.
pub fn build_claim_rewards_op(
    validator_id: Bytes32,
    delegator_keypair: &HybridKeypair,
    nonce: u64,
    chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    build_signed_staking_op(
        StakingOpBody::ClaimRewards {
            validator_id,
            delegator_pubkey: hybrid_pubkey_from_keypair(delegator_keypair)?,
            cold_authorization: None,
        },
        delegator_keypair,
        nonce,
        chain_id,
    )
}

/// Build and sign a set-commission staking operation.
pub fn build_set_commission_op(
    validator_id: Bytes32,
    new_commission_bps: u32,
    keypair: &HybridKeypair,
    nonce: u64,
    chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    build_signed_staking_op(
        StakingOpBody::SetCommission {
            validator_id,
            new_commission_bps,
            cold_authorization: None,
        },
        keypair,
        nonce,
        chain_id,
    )
}

/// Build and sign a SetAutoDelegate staking op.
/// Pass target_validator_id = Bytes32::ZERO to clear.
pub fn build_set_auto_delegate_op(
    validator_id: Bytes32,
    target_validator_id: Bytes32,
    keypair: &HybridKeypair,
    nonce: u64,
    chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    build_signed_staking_op(
        StakingOpBody::SetAutoDelegate {
            validator_id,
            target_validator_id,
            cold_authorization: None,
        },
        keypair,
        nonce,
        chain_id,
    )
}

/// Build and sign a validator network-address update staking op.
pub fn build_update_network_address_op(
    validator_id: Bytes32,
    network_addr: Option<String>,
    keypair: &HybridKeypair,
    nonce: u64,
    chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    let body = StakingOpBody::UpdateNetworkAddress {
        validator_id,
        network_addr,
    };
    StakingOp {
        body: body.clone(),
        nonce,
        signature: dummy_signature()?,
    }
    .validate_structure()
    .map_err(|e| CliError::Transaction(e.to_string()))?;
    build_signed_staking_op(body, keypair, nonce, chain_id)
}

fn build_signed_staking_op(
    body: StakingOpBody,
    keypair: &HybridKeypair,
    nonce: u64,
    chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    let mut op = StakingOp {
        body,
        nonce,
        signature: dummy_signature()?,
    };
    let sig = keypair
        .sign(&op.signing_bytes(chain_id))
        .map_err(|e| CliError::Crypto(e.to_string()))?;
    op.signature = wire_hybrid_signature(&sig)?;
    encode_built_staking_op(op)
}

fn wire_hybrid_signature(
    sig: &indra_crypto::hybrid::HybridSignature,
) -> CliResult<HybridSignature> {
    Ok(HybridSignature {
        classical_sig: VariableBytes::from_slice(&sig.classical.0)
            .map_err(|_| CliError::Transaction("classical sig too large".into()))?,
        pq_sig: VariableBytes::from_slice(&sig.pq.0)
            .map_err(|_| CliError::Transaction("pq sig too large".into()))?,
    })
}

fn encode_built_staking_op(op: StakingOp) -> CliResult<BuiltStakingOp> {
    let op_bytes = op.encode_to_vec();
    Ok(BuiltStakingOp {
        op_hex: hex::encode(&op_bytes),
        op_id: hex::encode(sha256(&op_bytes)),
    })
}

fn hybrid_pubkey_from_keypair(keypair: &HybridKeypair) -> CliResult<HybridPubKey> {
    let public = keypair.public_key();
    Ok(HybridPubKey {
        classical_pk: Bytes32::from(public.classical.0),
        pq_pk: VariableBytes::from_slice(&public.pq.0)
            .map_err(|_| CliError::Transaction("pq pubkey too large".into()))?,
    })
}

fn crypto_pubkey_to_wire(pubkey: &indra_crypto::HybridPublicKey) -> CliResult<HybridPubKey> {
    Ok(HybridPubKey {
        classical_pk: Bytes32::from(pubkey.classical.0),
        pq_pk: VariableBytes::from_slice(&pubkey.pq.0)
            .map_err(|_| CliError::Transaction("PQ public key is too large".into()))?,
    })
}

/// Build a dummy signature (all zeros) for pre-signing placeholder.
fn dummy_signature() -> CliResult<HybridSignature> {
    Ok(HybridSignature {
        classical_sig: VariableBytes::from_slice(&[0u8; 64]).map_err(|_| {
            CliError::Transaction("dummy classical signature exceeded max length".into())
        })?,
        pq_sig: VariableBytes::from_slice(&[0u8; 4627])
            .map_err(|_| CliError::Transaction("dummy PQ signature exceeded max length".into()))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Wallet;
    use indra_core::codec::Decode;
    use indra_core::types::primitives::{Bytes32, DEFAULT_CHAIN_ID};
    use indra_core::types::transaction::TransactionV1;
    use indra_crypto::{
        hybrid::{
            verify_hybrid, ClassicalSignature, HybridSignature as CryptoHybridSignature,
            PqSignature,
        },
        payment_x25519_shared_secret, recipient_derive_payment_blinding_v1, PaymentBlindingNoteV1,
        PaymentKeypairV1, PAYMENT_BLINDING_CONTEXT_V1,
    };

    fn make_wallet_with_funds() -> (Wallet, [u8; 32], Vec<u8>, HybridPubKey) {
        let seed = [0x42u8; 32];
        let mut w = Wallet::new();

        let blinding = [0x01u8; 32];
        let utxo_id = Bytes32::from([0xAAu8; 32]);
        w.add_utxo(utxo_id, 10_000_000, blinding, 1, 0, 0);

        let pq = PqKeypair::generate();
        let pq_sk = pq.secret_key_bytes();
        let pq_pk = pq.public_key().0;
        let classical = ClassicalKeypair::from_seed(&seed);
        let spk = HybridPubKey {
            classical_pk: Bytes32::from(classical.public_key().0),
            pq_pk: VariableBytes::from_slice(&pq_pk).unwrap(),
        };
        (w, seed, pq_sk, spk)
    }

    fn test_keypair(seed: u8) -> HybridKeypair {
        HybridKeypair::new(
            ClassicalKeypair::from_seed(&[seed; 32]),
            PqKeypair::from_seed(&[seed; 32]).unwrap(),
        )
    }

    fn test_cold_keypair(seed: u8) -> ColdHybridKeypair {
        ColdHybridKeypair::from_independent_seeds([seed; 32], [seed.wrapping_add(1); 32]).unwrap()
    }

    fn decode_built(built: &BuiltStakingOp) -> StakingOp {
        let bytes = hex::decode(&built.op_hex).unwrap();
        StakingOp::decode_exact(&bytes).unwrap()
    }

    fn decode_built_tx(built: &BuiltTransaction) -> TransactionV1 {
        let bytes = hex::decode(&built.tx_hex).unwrap();
        TransactionV1::decode_exact(&bytes).unwrap()
    }

    fn pubkey_hex(pubkey: &HybridPubKey) -> String {
        format!(
            "{}:{}",
            hex::encode(pubkey.classical_pk.0),
            hex::encode(pubkey.pq_pk.as_slice())
        )
    }

    fn direct_blinding_oracle(
        note: &PaymentBlindingNoteV1,
        x_secret: [u8; 32],
        kem_secret: [u8; 32],
        chain_id: &[u8],
        output_index: u32,
        value_spark: u64,
        lock_height: u64,
    ) -> [u8; 32] {
        let chain_id_len = u16::try_from(chain_id.len()).unwrap();
        let mut ikm = Vec::new();
        ikm.extend_from_slice(&x_secret);
        ikm.extend_from_slice(&kem_secret);
        ikm.extend_from_slice(&chain_id_len.to_le_bytes());
        ikm.extend_from_slice(chain_id);
        ikm.extend_from_slice(&note.owner_id);
        ikm.extend_from_slice(&note.payment_pubkey_hash);
        ikm.extend_from_slice(&output_index.to_le_bytes());
        ikm.extend_from_slice(&value_spark.to_le_bytes());
        ikm.extend_from_slice(&lock_height.to_le_bytes());
        ikm.extend_from_slice(&note.sender_x25519_ephemeral_pk);
        ikm.extend_from_slice(&note.ml_kem_1024_ciphertext);
        ikm.extend_from_slice(&note.note_nonce);
        blake3::derive_key(PAYMENT_BLINDING_CONTEXT_V1, &ikm)
    }

    fn deposit_proof(byte: u8, value: u64) -> StakeDepositProof {
        StakeDepositProof {
            committed_value_spark: value,
            blinding_factor: Bytes32::from([byte; 32]),
        }
    }

    fn payment_address(keypair: &HybridKeypair, payment: &PaymentKeypairV1) -> String {
        PaymentAddress::new(DEFAULT_CHAIN_ID.as_bytes(), keypair, payment.public_key())
            .unwrap()
            .to_text()
    }

    #[test]
    fn build_transaction_requires_valid_descriptor_and_mandatory_notes() {
        let (wallet, seed, pq_sk, sender_pubkey) = make_wallet_with_funds();
        let recipient_keypair = test_keypair(0x61);
        let recipient_payment = PaymentKeypairV1::generate();
        let recipient_address = payment_address(&recipient_keypair, &recipient_payment);
        let sender_payment = PaymentKeypairV1::generate();
        let params = TxParams {
            chain_id: DEFAULT_CHAIN_ID,
            recipient_address: &recipient_address,
            amount_spark: 1_000_000,
            fee_spark: MIN_FEE_SPARK,
            wallet: &wallet,
            hybrid_seed: seed,
            pq_sk_bytes: pq_sk,
            sender_pubkey,
            sender_payment_pubkey: sender_payment.public_key(),
        };

        let built = build_transaction(&params).unwrap();
        let tx = decode_built_tx(&built);
        assert_eq!(tx.payment_notes.len(), tx.outputs.len());
        assert!(tx.validate_structure().is_ok());
        let recipient_note = &tx.payment_notes[0];
        let recipient_side = recipient_derive_payment_blinding_v1(
            &recipient_payment,
            recipient_note,
            DEFAULT_CHAIN_ID.as_bytes(),
            0,
            1_000_000,
            0,
        )
        .unwrap();
        assert_eq!(
            tx.outputs[0].commitment.compressed_point.0,
            commit(1_000_000, &recipient_side.blinding).0
        );
    }

    #[test]
    fn self_directed_change_uses_sender_payment_key() {
        let (wallet, seed, pq_sk, sender_pubkey) = make_wallet_with_funds();
        let recipient_keypair = test_keypair(0x62);
        let recipient_address = payment_address(&recipient_keypair, &PaymentKeypairV1::generate());
        let sender_payment = PaymentKeypairV1::generate();
        let built = build_transaction(&TxParams {
            chain_id: DEFAULT_CHAIN_ID,
            recipient_address: &recipient_address,
            amount_spark: 1_000_000,
            fee_spark: MIN_FEE_SPARK,
            wallet: &wallet,
            hybrid_seed: seed,
            pq_sk_bytes: pq_sk,
            sender_pubkey,
            sender_payment_pubkey: sender_payment.public_key(),
        })
        .unwrap();
        let tx = decode_built_tx(&built);
        assert_eq!(tx.outputs.len(), 2);
        let recovered = recipient_derive_payment_blinding_v1(
            &sender_payment,
            &tx.payment_notes[1],
            DEFAULT_CHAIN_ID.as_bytes(),
            1,
            built.change_spark,
            0,
        )
        .unwrap();
        assert_eq!(
            tx.outputs[1].commitment.compressed_point.0,
            commit(built.change_spark, &recovered.blinding).0
        );
    }

    #[test]
    fn malformed_or_wrong_chain_descriptor_is_rejected() {
        let (wallet, seed, pq_sk, sender_pubkey) = make_wallet_with_funds();
        let sender_payment = PaymentKeypairV1::generate();
        for recipient_address in [
            "not-an-address".to_string(),
            payment_address(&test_keypair(0x63), &PaymentKeypairV1::generate())
                .replace("indra:", "bad:"),
        ] {
            assert!(build_transaction(&TxParams {
                chain_id: DEFAULT_CHAIN_ID,
                recipient_address: &recipient_address,
                amount_spark: 1_000_000,
                fee_spark: MIN_FEE_SPARK,
                wallet: &wallet,
                hybrid_seed: seed,
                pq_sk_bytes: pq_sk.clone(),
                sender_pubkey: sender_pubkey.clone(),
                sender_payment_pubkey: sender_payment.public_key(),
            })
            .is_err());
        }
    }

    #[test]
    fn insufficient_balance_and_dust_are_rejected() {
        let (wallet, seed, pq_sk, sender_pubkey) = make_wallet_with_funds();
        let recipient_address = payment_address(&test_keypair(0x64), &PaymentKeypairV1::generate());
        let sender_payment = PaymentKeypairV1::generate().public_key();
        for amount_spark in [1, 100_000_000] {
            assert!(build_transaction(&TxParams {
                chain_id: DEFAULT_CHAIN_ID,
                recipient_address: &recipient_address,
                amount_spark,
                fee_spark: MIN_FEE_SPARK,
                wallet: &wallet,
                hybrid_seed: seed,
                pq_sk_bytes: pq_sk.clone(),
                sender_pubkey: sender_pubkey.clone(),
                sender_payment_pubkey: sender_payment.clone(),
            })
            .is_err());
        }
    }

    #[test]
    fn build_self_stake_op_serialises_signed_operation() {
        let (_, seed, _, spk) = make_wallet_with_funds();
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let keypair = HybridKeypair::new(ClassicalKeypair::from_seed(&seed), pq);
        let deposit_utxo_id = Bytes32::from([0xA5; 32]);

        let proof = deposit_proof(0xA5, 1_000_000);
        let built = build_self_stake_op(
            deposit_utxo_id,
            proof.clone(),
            &keypair,
            7,
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        let bytes = hex::decode(&built.op_hex).unwrap();
        let op = StakingOp::decode_exact(&bytes).unwrap();

        assert_eq!(built.op_id.len(), 64);
        assert_eq!(op.nonce, 7);
        assert!(matches!(
            op.body,
            StakingOpBody::SelfStake {
                deposit_utxo_id: id,
                validator_pubkey,
                deposit_proof,
                ..
            } if id == deposit_utxo_id
                && validator_pubkey.classical_pk == spk.classical_pk
                && deposit_proof == Some(proof)
        ));
    }

    #[test]
    fn build_validator_cold_position_exit_serialises_signed_operation() {
        let cold = test_cold_keypair(0x73);
        let validator_id = Bytes32::from([0xA6; 32]);
        let position_id = Bytes32::from([0xA7; 32]);
        let built = build_exit_stake_position_op(
            position_id,
            700_000,
            PositionCustodyV1::ValidatorColdIdentity { validator_id },
            StakePositionExitSigner::ValidatorCold {
                keypair: &cold,
                cold_key_version: 2,
                cold_nonce: 8,
            },
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        let bytes = hex::decode(&built.op_hex).unwrap();
        let op = StakingOp::decode_exact(&bytes).unwrap();

        assert_eq!(built.op_id.len(), 64);
        assert_eq!(op.nonce, 0);
        assert!(matches!(
            op.body,
            StakingOpBody::ExitStakePosition {
                position_id: id,
                amount_spark: 700_000,
                custody: PositionCustodyV1::ValidatorColdIdentity { validator_id: v },
                cold_authorization: Some(ColdStakingAuthorization { cold_key_version: 2, cold_nonce: 8 }),
            } if id == position_id && v == validator_id
        ));
    }

    #[test]
    fn build_register_validator_op_serialises_and_decodes() {
        let keypair = test_keypair(0x71);
        let deposit_utxo_id = Bytes32::from([0xAB; 32]);
        let built = build_register_validator_op_with_cold(
            1_000,
            deposit_utxo_id,
            deposit_proof(0xAB, 2_000_000),
            &keypair,
            &test_cold_keypair(0x91),
            [0xAA; 32],
            9,
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        let op = decode_built(&built);
        assert_eq!(op.nonce, 9);
        assert!(matches!(
            op.body,
            StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                deposit_utxo_id: id,
                vrf_pk,
                ..
            } if id == deposit_utxo_id && vrf_pk == [0xAA; 32]
        ));
    }

    #[test]
    fn build_delegate_op_serialises_and_decodes() {
        let keypair = test_keypair(0x72);
        let validator_id = Bytes32::from([0x01; 32]);
        let deposit_utxo_id = Bytes32::from([0x02; 32]);
        let built = build_delegate_op(
            validator_id,
            deposit_utxo_id,
            deposit_proof(0x02, 500_000),
            &keypair,
            10,
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        let op = decode_built(&built);
        assert!(matches!(
            op.body,
            StakingOpBody::Delegate {
                validator_id: v,
                deposit_utxo_id: b,
                ..
            } if v == validator_id && b == deposit_utxo_id
        ));
    }

    #[test]
    fn build_delegator_position_exit_serialises_and_decodes() {
        let keypair = test_keypair(0x73);
        let delegator_id = Bytes32::from([0x03; 32]);
        let position_id = Bytes32::from([0x04; 32]);
        let built = build_exit_stake_position_op(
            position_id,
            400_000,
            PositionCustodyV1::DelegatorIdentity { delegator_id },
            StakePositionExitSigner::Delegator {
                keypair: &keypair,
                nonce: 11,
            },
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        let op = decode_built(&built);
        assert!(matches!(
            op.body,
            StakingOpBody::ExitStakePosition {
                position_id: id,
                amount_spark: 400_000,
                custody: PositionCustodyV1::DelegatorIdentity { delegator_id: d },
                ..
            } if id == position_id && d == delegator_id
        ));
    }

    #[test]
    fn build_claim_rewards_op_serialises_and_decodes() {
        let keypair = test_keypair(0x74);
        let validator_id = Bytes32::from([0x05; 32]);
        let built = build_claim_rewards_op(validator_id, &keypair, 12, DEFAULT_CHAIN_ID).unwrap();
        let op = decode_built(&built);
        assert!(matches!(
            op.body,
            StakingOpBody::ClaimRewards {
                validator_id: v,
                ..
            } if v == validator_id
        ));
    }

    #[test]
    fn build_set_commission_op_serialises_and_decodes() {
        let keypair = test_keypair(0x75);
        let validator_id = Bytes32::from([0x06; 32]);
        let built =
            build_set_commission_op(validator_id, 1_500, &keypair, 13, DEFAULT_CHAIN_ID).unwrap();
        let op = decode_built(&built);
        assert!(matches!(
            op.body,
            StakingOpBody::SetCommission {
                validator_id: v,
                new_commission_bps: 1_500,
                ..
            } if v == validator_id
        ));
    }

    #[test]
    fn build_set_auto_delegate_op_serialises_and_decodes() {
        let keypair = test_keypair(0x78);
        let validator_id = Bytes32::from([0x16; 32]);
        let target_validator_id = Bytes32::from([0x17; 32]);
        let built = build_set_auto_delegate_op(
            validator_id,
            target_validator_id,
            &keypair,
            14,
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        let op = decode_built(&built);
        assert_eq!(op.nonce, 14);
        assert!(matches!(
            op.body,
            StakingOpBody::SetAutoDelegate {
                validator_id: v,
                target_validator_id: t,
                ..
            } if v == validator_id && t == target_validator_id
        ));
    }

    #[test]
    fn build_clear_auto_delegate_op_uses_zero_target() {
        let keypair = test_keypair(0x79);
        let validator_id = Bytes32::from([0x18; 32]);
        let built =
            build_set_auto_delegate_op(validator_id, Bytes32::ZERO, &keypair, 15, DEFAULT_CHAIN_ID)
                .unwrap();
        let op = decode_built(&built);
        assert!(matches!(
            op.body,
            StakingOpBody::SetAutoDelegate {
                validator_id: v,
                target_validator_id: Bytes32::ZERO,
                ..
            } if v == validator_id
        ));
    }

    #[test]
    fn build_update_network_address_op_serialises_and_decodes() {
        let keypair = test_keypair(0x7A);
        let validator_id = Bytes32::from([0x1B; 32]);
        let built = build_update_network_address_op(
            validator_id,
            Some("203.0.113.20:30303".to_string()),
            &keypair,
            16,
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        let op = decode_built(&built);
        assert_eq!(op.nonce, 16);
        assert!(matches!(
            op.body,
            StakingOpBody::UpdateNetworkAddress {
                validator_id: v,
                network_addr: Some(addr),
            } if v == validator_id && addr == "203.0.113.20:30303"
        ));
    }

    #[test]
    fn build_clear_network_address_op_uses_none() {
        let keypair = test_keypair(0x7B);
        let validator_id = Bytes32::from([0x1C; 32]);
        let built =
            build_update_network_address_op(validator_id, None, &keypair, 17, DEFAULT_CHAIN_ID)
                .unwrap();
        let op = decode_built(&built);
        assert!(matches!(
            op.body,
            StakingOpBody::UpdateNetworkAddress {
                validator_id: v,
                network_addr: None,
            } if v == validator_id
        ));
    }

    #[test]
    fn build_update_network_address_rejects_invalid_syntax() {
        let keypair = test_keypair(0x7C);
        let validator_id = Bytes32::from([0x1D; 32]);
        assert!(build_update_network_address_op(
            validator_id,
            Some("validator.example.com:30303".to_string()),
            &keypair,
            18,
            DEFAULT_CHAIN_ID,
        )
        .is_err());
    }

    #[test]
    fn all_ops_have_correct_nonce() {
        let keypair = test_keypair(0x76);
        let validator_id = Bytes32::from([0x07; 32]);
        let deposit_utxo_id = Bytes32::from([0x08; 32]);
        let ops = vec![
            build_register_validator_op_with_cold(
                1_000,
                deposit_utxo_id,
                deposit_proof(0x11, 1_000),
                &keypair,
                &test_cold_keypair(0x92),
                [0x11; 32],
                42,
                DEFAULT_CHAIN_ID,
            )
            .unwrap(),
            build_self_stake_op(
                deposit_utxo_id,
                deposit_proof(0x12, 1_000),
                &keypair,
                42,
                DEFAULT_CHAIN_ID,
            )
            .unwrap(),
            build_delegate_op(
                validator_id,
                deposit_utxo_id,
                deposit_proof(0x13, 1_000),
                &keypair,
                42,
                DEFAULT_CHAIN_ID,
            )
            .unwrap(),
            build_exit_stake_position_op(
                Bytes32::from([0x31; 32]),
                1_000,
                PositionCustodyV1::DelegatorIdentity {
                    delegator_id: validator_id,
                },
                StakePositionExitSigner::Delegator {
                    keypair: &keypair,
                    nonce: 42,
                },
                DEFAULT_CHAIN_ID,
            )
            .unwrap(),
            build_claim_rewards_op(validator_id, &keypair, 42, DEFAULT_CHAIN_ID).unwrap(),
            build_set_commission_op(validator_id, 1_100, &keypair, 42, DEFAULT_CHAIN_ID).unwrap(),
            build_set_auto_delegate_op(
                validator_id,
                Bytes32::from([0x19; 32]),
                &keypair,
                42,
                DEFAULT_CHAIN_ID,
            )
            .unwrap(),
            build_update_network_address_op(
                validator_id,
                Some("203.0.113.20:30303".to_string()),
                &keypair,
                42,
                DEFAULT_CHAIN_ID,
            )
            .unwrap(),
        ];
        for built in ops {
            assert_eq!(decode_built(&built).nonce, 42);
        }
    }

    #[test]
    fn all_ops_have_non_zero_signatures() {
        let keypair = test_keypair(0x77);
        let validator_id = Bytes32::from([0x09; 32]);
        let deposit_utxo_id = Bytes32::from([0x0A; 32]);
        let ops = vec![
            build_register_validator_op_with_cold(
                1_000,
                deposit_utxo_id,
                deposit_proof(0x21, 1_000),
                &keypair,
                &test_cold_keypair(0x93),
                [0x12; 32],
                1,
                DEFAULT_CHAIN_ID,
            )
            .unwrap(),
            build_self_stake_op(
                deposit_utxo_id,
                deposit_proof(0x22, 1_000),
                &keypair,
                2,
                DEFAULT_CHAIN_ID,
            )
            .unwrap(),
            build_delegate_op(
                validator_id,
                deposit_utxo_id,
                deposit_proof(0x23, 1_000),
                &keypair,
                4,
                DEFAULT_CHAIN_ID,
            )
            .unwrap(),
            build_exit_stake_position_op(
                Bytes32::from([0x32; 32]),
                1_000,
                PositionCustodyV1::DelegatorIdentity {
                    delegator_id: validator_id,
                },
                StakePositionExitSigner::Delegator {
                    keypair: &keypair,
                    nonce: 5,
                },
                DEFAULT_CHAIN_ID,
            )
            .unwrap(),
            build_claim_rewards_op(validator_id, &keypair, 6, DEFAULT_CHAIN_ID).unwrap(),
            build_set_commission_op(validator_id, 1_200, &keypair, 7, DEFAULT_CHAIN_ID).unwrap(),
            build_set_auto_delegate_op(
                validator_id,
                Bytes32::from([0x1A; 32]),
                &keypair,
                8,
                DEFAULT_CHAIN_ID,
            )
            .unwrap(),
            build_update_network_address_op(
                validator_id,
                Some("203.0.113.21:30303".to_string()),
                &keypair,
                9,
                DEFAULT_CHAIN_ID,
            )
            .unwrap(),
        ];
        for built in ops {
            let op = decode_built(&built);
            assert!(op
                .signature
                .classical_sig
                .as_slice()
                .iter()
                .any(|b| *b != 0));
            assert!(op.signature.pq_sig.as_slice().iter().any(|b| *b != 0));
        }
    }
}
