//! Transaction builder — constructs, signs and serialises TransactionV1.
//!
//! ## Flow
//!
//! 1. Caller provides: recipient pubkey, amount, fee, wallet, signing keypair
//! 2. Builder selects UTXOs (coin selection)
//! 3. Builds outputs: recipient output + change output (if needed)
//! 4. Signs the transparent-value transaction with the hybrid keypair
//! 5. Returns serialised hex ready for indra_sendTransaction RPC

use indra_core::{
    codec::{Decode, Encode},
    types::{
        crypto::{ColdHybridPubKey, HybridPubKey, HybridSignature},
        primitives::{
            Bytes32, Bytes64, ProtocolVersion, VariableBytes, TRANSACTION_PROTOCOL_VERSION,
        },
        stake_position::PositionCustodyV1,
        staking::{ColdStakingAuthorization, StakingOp, StakingOpBody},
        transaction::{InputV1, OutputV1, TransactionV1},
    },
};
use indra_crypto::{
    hybrid::{ClassicalKeypair, ColdHybridKeypair, HybridKeypair, PqKeypair},
    sha256, PaymentAddressV1, VrfKeypair,
};
use zeroize::Zeroize;

use crate::{
    error::{CliError, CliResult},
    wallet::{PendingChange, Wallet},
};

/// Safety multiplier applied to the current consensus-required fee.
/// The base-fee controller can rise by at most 12.5% per full block; 2x
/// covers five consecutive full blocks before the sixth full block exceeds 2x.
pub const FEE_SAFETY_MARGIN: u64 = 2;

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
    /// Fee in Spark.
    pub fee_spark: u64,
    /// Sender's wallet (for coin selection).
    pub wallet: &'a Wallet,
    /// Sender's hybrid seed (for Ed25519 signing).
    pub ed25519_seed: [u8; 32],
    /// Sender's ML-DSA-87 seed bytes (from keys.json).
    pub ml_dsa_seed_bytes: Vec<u8>,
    /// Sender's own pubkey (for change output).
    pub sender_pubkey: HybridPubKey,
}

/// Parameters for an ordinary transfer signed by a validator cold key.
pub struct ColdTxParams<'a> {
    /// Chain identifier used in transaction signing.
    pub chain_id: &'a str,
    /// Recipient's complete canonical payment address.
    pub recipient_address: &'a str,
    /// Amount to send in Spark.
    pub amount_spark: u64,
    /// Transaction fee in Spark.
    pub fee_spark: u64,
    /// Wallet containing owner-tagged scanned UTXOs.
    pub wallet: &'a Wallet,
    /// Cold key used both for ownership selection and signing.
    pub keypair: &'a ColdHybridKeypair,
    /// Cold public key used for change.
    pub owner_pubkey: HybridPubKey,
}

impl Drop for TxParams<'_> {
    fn drop(&mut self) {
        self.ed25519_seed.zeroize();
        self.ml_dsa_seed_bytes.zeroize();
    }
}

/// The result of building a transaction.
pub struct BuiltTransaction {
    /// The serialised transaction (hex-encoded).
    pub tx_hex: String,
    /// The transaction ID (SHA-256 of serialised bytes).
    pub tx_id: String,
    /// Change amount returned to sender in Spark (0 if exact).
    pub change_spark: u64,
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

type AssembledTransfer = (Vec<InputV1>, Vec<OutputV1>, u64, Option<PendingChange>);

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

fn assemble_transfer(
    owner_pubkey: &HybridPubKey,
    recipient_pubkey: HybridPubKey,
    amount_spark: u64,
    fee_spark: u64,
    selected: &[&crate::wallet::WalletEntry],
) -> CliResult<AssembledTransfer> {
    let total_in = selected.iter().try_fold(0u64, |sum, entry| {
        sum.checked_add(entry.value_spark)
            .ok_or_else(|| CliError::Transaction("input value overflow".into()))
    })?;
    let change_spark = total_in
        .checked_sub(amount_spark)
        .and_then(|value| value.checked_sub(fee_spark))
        .ok_or_else(|| CliError::Transaction("inputs do not cover outputs and fee".into()))?;
    let inputs = selected
        .iter()
        .map(|entry| InputV1 {
            utxo_id: entry.utxo_id,
        })
        .collect();
    let mut outputs = vec![OutputV1 {
        value_spark: amount_spark,
        owner_pubkey: recipient_pubkey,
        lock_height: 0,
    }];
    let mut pending_change = None;
    let mut effective_fee_spark = fee_spark;
    if change_spark > DUST_LIMIT_SPARK {
        let change_output = OutputV1 {
            value_spark: change_spark,
            owner_pubkey: owner_pubkey.clone(),
            lock_height: 0,
        };
        pending_change = Some(PendingChange {
            output: change_output.clone(),
        });
        outputs.push(change_output);
    } else if change_spark > 0 {
        effective_fee_spark = effective_fee_spark
            .checked_add(change_spark)
            .ok_or_else(|| {
                CliError::Transaction("fee overflow while folding dust change".into())
            })?;
    }
    Ok((inputs, outputs, effective_fee_spark, pending_change))
}

fn sign_transfer<Sign>(
    chain_id: &str,
    mut tx: TransactionV1,
    selected: &[&crate::wallet::WalletEntry],
    pending_change: Option<PendingChange>,
    sign: Sign,
) -> CliResult<BuiltTransaction>
where
    Sign: FnOnce(&[u8]) -> Result<indra_crypto::hybrid::HybridSignature, String>,
{
    let signing_bytes = tx
        .signing_bytes(chain_id)
        .map_err(|error| CliError::Transaction(error.to_string()))?;
    let sig = sign(&signing_bytes).map_err(CliError::Crypto)?;
    tx.signature = HybridSignature {
        classical_sig: VariableBytes::from_slice(&sig.classical.0)
            .map_err(|_| CliError::Transaction("classical sig too large".into()))?,
        pq_sig: VariableBytes::from_slice(&sig.pq.0)
            .map_err(|_| CliError::Transaction("pq sig too large".into()))?,
    };
    let tx_bytes = tx.encode_to_vec();
    let tx_id = hex::encode(sha256(&tx_bytes));
    Ok(BuiltTransaction {
        tx_hex: hex::encode(tx_bytes),
        tx_id,
        change_spark: pending_change
            .as_ref()
            .map(|change| change.output.value_spark)
            .unwrap_or(0),
        spent_utxo_ids: selected.iter().map(|entry| entry.utxo_id).collect(),
        pending_change,
    })
}

/// Compute the consensus-required fee for an encoded transaction.
pub fn required_fee_for_transaction(tx: &TransactionV1, base_fee_spark_per_kb: u64) -> CliResult<u64> {
    base_fee_spark_per_kb
        .checked_mul(tx.weight_kb())
        .ok_or_else(|| CliError::Transaction("fee calculation overflow".into()))
}

/// Compute the default fee offered by the CLI for the current base fee.
pub fn default_fee_for_base_fee(base_fee_spark_per_kb: u64) -> CliResult<u64> {
    base_fee_spark_per_kb
        .checked_mul(FEE_SAFETY_MARGIN)
        .ok_or_else(|| CliError::Transaction("fee calculation overflow".into()))
}

fn required_fee_from_built(built: &BuiltTransaction, base_fee: u64) -> CliResult<u64> {
    let bytes = hex::decode(&built.tx_hex)
        .map_err(|_| CliError::Transaction("built transaction is not canonical hex".into()))?;
    let tx = TransactionV1::decode_exact(&bytes)
        .map_err(|error| CliError::Transaction(format!("built transaction decode failed: {error}")))?;
    required_fee_for_transaction(&tx, base_fee)
}

/// Build a transfer using the current chain fee. If `requested_fee` is None,
/// offer the checked safety-margin default; otherwise enforce the requested fee.
pub fn build_transaction_with_fee_policy(
    params: &TxParams<'_>,
    base_fee_spark_per_kb: u64,
    requested_fee: Option<u64>,
) -> CliResult<(BuiltTransaction, u64)> {
    let mut fee = match requested_fee {
        Some(fee) => fee,
        None => default_fee_for_base_fee(base_fee_spark_per_kb)?,
    };
    for _ in 0..8 {
        let attempt = TxParams {
            chain_id: params.chain_id,
            recipient_address: params.recipient_address,
            amount_spark: params.amount_spark,
            fee_spark: fee,
            wallet: params.wallet,
            ed25519_seed: params.ed25519_seed,
            ml_dsa_seed_bytes: params.ml_dsa_seed_bytes.clone(),
            sender_pubkey: params.sender_pubkey.clone(),
        };
        let built = build_transaction(&attempt)?;
        let required = required_fee_from_built(&built, base_fee_spark_per_kb)?;
        if fee < required {
            if requested_fee.is_some() {
                return Err(CliError::Transaction(format!(
                    "fee {fee} spark is below the minimum {required} spark for this transaction at base fee {base_fee_spark_per_kb} spark/KiB"
                )));
            }
            fee = required
                .checked_mul(FEE_SAFETY_MARGIN)
                .ok_or_else(|| CliError::Transaction("fee calculation overflow".into()))?;
            continue;
        }
        return Ok((built, required));
    }
    Err(CliError::Transaction("fee calculation did not converge".into()))
}

/// Build a cold transfer using the current chain fee.
pub fn build_cold_transaction_with_fee_policy(
    params: &ColdTxParams<'_>,
    base_fee_spark_per_kb: u64,
    requested_fee: Option<u64>,
) -> CliResult<(BuiltTransaction, u64)> {
    let mut fee = match requested_fee {
        Some(fee) => fee,
        None => default_fee_for_base_fee(base_fee_spark_per_kb)?,
    };
    for _ in 0..8 {
        let attempt = ColdTxParams {
            chain_id: params.chain_id,
            recipient_address: params.recipient_address,
            amount_spark: params.amount_spark,
            fee_spark: fee,
            wallet: params.wallet,
            keypair: params.keypair,
            owner_pubkey: params.owner_pubkey.clone(),
        };
        let built = build_cold_transaction(&attempt)?;
        let required = required_fee_from_built(&built, base_fee_spark_per_kb)?;
        if fee < required {
            if requested_fee.is_some() {
                return Err(CliError::Transaction(format!(
                    "fee {fee} spark is below the minimum {required} spark for this transaction at base fee {base_fee_spark_per_kb} spark/KiB"
                )));
            }
            fee = required
                .checked_mul(FEE_SAFETY_MARGIN)
                .ok_or_else(|| CliError::Transaction("fee calculation overflow".into()))?;
            continue;
        }
        return Ok((built, required));
    }
    Err(CliError::Transaction("fee calculation did not converge".into()))
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

    // 2. Decode and authenticate the complete recipient descriptor.
    let recipient_address =
        PaymentAddressV1::from_text(params.recipient_address, params.chain_id.as_bytes()).map_err(
            |e| CliError::Transaction(format!("invalid recipient payment address: {e}")),
        )?;
    let recipient_pubkey = crypto_pubkey_to_wire(recipient_address.owner_pubkey())?;

    // 3. Coin selection
    let selected =
        params
            .wallet
            .select_utxos(&params.sender_pubkey, params.amount_spark, params.fee_spark)?;
    let (inputs, outputs, effective_fee_spark, pending_change) = assemble_transfer(
        &params.sender_pubkey,
        recipient_pubkey,
        params.amount_spark,
        params.fee_spark,
        &selected,
    )?;

    // 6. Build unsigned transaction.
    let tx = TransactionV1 {
        version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
        signature_module_id: 1,
        inputs,
        outputs,
        fee_amount: effective_fee_spark,
        signature: dummy_signature()?,
    };

    let classical = ClassicalKeypair::from_seed(&params.ed25519_seed);
    let pq = PqKeypair::from_bytes(
        // pq_pk is embedded in sender_pubkey
        params.sender_pubkey.pq_pk.as_slice(),
        &params.ml_dsa_seed_bytes,
    )
    .map_err(|e| CliError::Crypto(e.to_string()))?;
    let keypair = HybridKeypair::new(classical, pq);
    sign_transfer(
        params.chain_id,
        tx,
        &selected,
        pending_change,
        move |bytes| keypair.sign(bytes).map_err(|e| e.to_string()),
    )
}

/// Build and sign an ordinary transfer with a cold hybrid key.
pub fn build_cold_transaction(params: &ColdTxParams<'_>) -> CliResult<BuiltTransaction> {
    if params.amount_spark < DUST_LIMIT_SPARK {
        return Err(CliError::Transaction(format!(
            "amount {} Spark is below dust limit {}",
            params.amount_spark, DUST_LIMIT_SPARK
        )));
    }
    let recipient_address =
        PaymentAddressV1::from_text(params.recipient_address, params.chain_id.as_bytes()).map_err(
            |e| CliError::Transaction(format!("invalid recipient payment address: {e}")),
        )?;
    let recipient_pubkey = crypto_pubkey_to_wire(recipient_address.owner_pubkey())?;
    let selected =
        params
            .wallet
            .select_utxos(&params.owner_pubkey, params.amount_spark, params.fee_spark)?;
    let (inputs, outputs, effective_fee_spark, pending_change) = assemble_transfer(
        &params.owner_pubkey,
        recipient_pubkey,
        params.amount_spark,
        params.fee_spark,
        &selected,
    )?;
    let tx = TransactionV1 {
        version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
        signature_module_id: 1,
        inputs,
        outputs,
        fee_amount: effective_fee_spark,
        signature: dummy_signature()?,
    };
    sign_transfer(params.chain_id, tx, &selected, pending_change, |bytes| {
        params.keypair.sign(bytes).map_err(|e| e.to_string())
    })
}

/// Payload fields for an active-validator cold-authorized staking operation.
pub enum ColdAuthorizedStakingAction {
    /// Bond another validator-cold-owned UTXO.
    SelfStake {
        /// UTXO atomically consumed into self-stake.
        deposit_utxo_id: Bytes32,
        /// Complete registered hot validator identity.
        validator_pubkey: HybridPubKey,
    },
    /// Claim the validator's own position rewards.
    ClaimRewards {
        /// Registered validator identity.
        validator_id: Bytes32,
        /// Complete registered hot validator identity.
        validator_pubkey: HybridPubKey,
    },
    /// Stage a validator commission change.
    SetCommission {
        /// Registered validator identity.
        validator_id: Bytes32,
        /// New commission in basis points.
        new_commission_bps: u32,
    },
    /// Set or clear a validator auto-delegation target.
    SetAutoDelegate {
        /// Registered validator identity.
        validator_id: Bytes32,
        /// Target validator, or zero to clear.
        target_validator_id: Bytes32,
    },
}

/// Build an active-validator staking operation authorized by its cold key.
pub fn build_cold_authorized_staking_op(
    action: ColdAuthorizedStakingAction,
    cold_keypair: &ColdHybridKeypair,
    cold_key_version: u64,
    cold_nonce: u64,
    chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    let authorization = ColdStakingAuthorization {
        cold_key_version,
        cold_nonce,
    };
    let body = match action {
        ColdAuthorizedStakingAction::SelfStake {
            deposit_utxo_id,
            validator_pubkey,
        } => StakingOpBody::SelfStake {
            deposit_utxo_id,
            validator_pubkey,
            cold_authorization: authorization,
        },
        ColdAuthorizedStakingAction::ClaimRewards {
            validator_id,
            validator_pubkey,
        } => StakingOpBody::ClaimRewards {
            validator_id,
            delegator_pubkey: validator_pubkey,
            cold_authorization: Some(authorization),
        },
        ColdAuthorizedStakingAction::SetCommission {
            validator_id,
            new_commission_bps,
        } => StakingOpBody::SetCommission {
            validator_id,
            new_commission_bps,
            cold_authorization: authorization,
        },
        ColdAuthorizedStakingAction::SetAutoDelegate {
            validator_id,
            target_validator_id,
        } => StakingOpBody::SetAutoDelegate {
            validator_id,
            target_validator_id,
            cold_authorization: authorization,
        },
    };
    let mut op = StakingOp {
        body,
        nonce: 0,
        signature: dummy_signature()?,
    };
    op.validate_structure()
        .map_err(|error| CliError::Transaction(error.to_string()))?;
    let message = op
        .cold_authorization_signing_bytes(chain_id)
        .map_err(|error| CliError::Transaction(error.to_string()))?
        .ok_or_else(|| CliError::Transaction("missing cold authorization message".into()))?;
    let signature = cold_keypair
        .sign(&message)
        .map_err(|error| CliError::Crypto(error.to_string()))?;
    op.signature = wire_hybrid_signature(&signature)?;
    encode_built_staking_op(op)
}

/// Build and sign a validator registration staking operation.
pub fn build_register_validator_op_with_cold(
    commission_bps: u32,
    deposit_utxo_id: Bytes32,
    keypair: &HybridKeypair,
    cold_keypair: &ColdHybridKeypair,
    vrf_keypair: &VrfKeypair,
    nonce: u64,
    chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    let validator_pubkey = hybrid_pubkey_from_keypair(keypair)?;
    let vrf_pk = vrf_keypair.public_key();
    let challenge = StakingOp::vrf_possession_challenge(
        chain_id,
        &validator_pubkey.identity_id(),
        &Bytes32::from(vrf_pk),
        0,
    )
    .map_err(|error| CliError::Transaction(error.to_string()))?;
    let (vrf_output, vrf_proof) = indra_crypto::vrf_prove(vrf_keypair, &challenge);
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
            validator_pubkey,
            vrf_pk,
            vrf_possession_output: Bytes64(vrf_output.0),
            vrf_possession_proof: VariableBytes::from_slice(&vrf_proof.0)
                .map_err(|_| CliError::Transaction("VRF possession proof too large".into()))?,
            cold_pubkey,
            cold_signature: dummy_signature()?,
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
        classical_sig: VariableBytes::from_slice(&hot_sig.classical.0)
            .map_err(|_| CliError::Transaction("hot classical signature too large".into()))?,
        pq_sig: VariableBytes::from_slice(&hot_sig.pq.0)
            .map_err(|_| CliError::Transaction("hot PQ signature too large".into()))?,
    };
    if let StakingOpBody::RegisterValidator { cold_signature, .. } = &mut op.body {
        *cold_signature = HybridSignature {
            classical_sig: VariableBytes::from_slice(&cold_sig.classical.0)
                .map_err(|_| CliError::Transaction("cold classical signature too large".into()))?,
            pq_sig: VariableBytes::from_slice(&cold_sig.pq.0)
                .map_err(|_| CliError::Transaction("cold PQ signature too large".into()))?,
        };
    }
    let op_bytes = op.encode_to_vec();
    Ok(BuiltStakingOp {
        op_hex: hex::encode(&op_bytes),
        op_id: hex::encode(sha256(&op_bytes)),
    })
}

/// Build and sign a delegate staking operation.
pub fn build_delegate_op(
    validator_id: Bytes32,
    deposit_utxo_id: Bytes32,
    delegator_keypair: &HybridKeypair,
    nonce: u64,
    chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    build_signed_staking_op(
        StakingOpBody::Delegate {
            validator_id,
            deposit_utxo_id,
            delegator_pubkey: hybrid_pubkey_from_keypair(delegator_keypair)?,
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

    const TEST_FEE_SPARK: u64 = 50_000;
    use crate::wallet::Wallet;
    use indra_core::codec::Decode;
    use indra_core::types::primitives::Bytes32;
    use indra_core::types::primitives::TEST_CHAIN_ID;
    use indra_core::types::transaction::TransactionV1;

    fn make_wallet_with_funds() -> (Wallet, [u8; 32], Vec<u8>, HybridPubKey) {
        let seed = [0x42u8; 32];
        let mut w = Wallet::new();

        let utxo_id = Bytes32::from([0xAAu8; 32]);
        let pq = PqKeypair::generate();
        let pq_seed = pq.secret_key_bytes();
        let pq_pk = pq.public_key().0;
        let classical = ClassicalKeypair::from_seed(&seed);
        let spk = HybridPubKey {
            classical_pk: Bytes32::from(classical.public_key().0),
            pq_pk: VariableBytes::from_slice(&pq_pk).unwrap(),
        };
        w.add_utxo(utxo_id, 10_000_000, 1, 0, 0, spk.clone());
        (w, seed, pq_seed, spk)
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

    #[test]
    fn fee_weight_rounds_at_1023_1024_and_1025_bytes() {
        let mut found = [None, None, None];
        for pq_len in 0..2048 {
            let tx = TransactionV1 {
                version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
                signature_module_id: 1,
                inputs: vec![InputV1 { utxo_id: Bytes32::ZERO }],
                outputs: vec![OutputV1 {
                    value_spark: 1,
                    owner_pubkey: HybridPubKey {
                        classical_pk: Bytes32::ZERO,
                        pq_pk: VariableBytes::from_slice(&vec![0; pq_len]).unwrap(),
                    },
                    lock_height: 0,
                }],
                fee_amount: 1,
                signature: HybridSignature {
                    classical_sig: VariableBytes::default(),
                    pq_sig: VariableBytes::default(),
                },
            };
            let len = tx.encoded_len();
            if (1023..=1025).contains(&len) {
                found[len - 1023] = Some(tx);
            }
        }
        assert_eq!(found[0].as_ref().map(TransactionV1::encoded_len), Some(1023));
        assert_eq!(found[1].as_ref().map(TransactionV1::encoded_len), Some(1024));
        assert_eq!(found[2].as_ref().map(TransactionV1::encoded_len), Some(1025));
        assert_eq!(found[0].as_ref().map(TransactionV1::weight_kb), Some(1));
        assert_eq!(found[1].as_ref().map(TransactionV1::weight_kb), Some(1));
        assert_eq!(found[2].as_ref().map(TransactionV1::weight_kb), Some(2));
    }

    #[test]
    fn fee_policy_default_is_required_fee_times_two_and_overflow_is_typed() {
        assert_eq!(default_fee_for_base_fee(123).unwrap(), 246);
        let tx = TransactionV1 {
            version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
            signature_module_id: 1,
            inputs: vec![InputV1 { utxo_id: Bytes32::ZERO }],
            outputs: vec![OutputV1 {
                value_spark: 1,
                owner_pubkey: HybridPubKey {
                    classical_pk: Bytes32::ZERO,
                    pq_pk: VariableBytes::default(),
                },
                lock_height: 0,
            }],
            fee_amount: 1,
            signature: HybridSignature {
                classical_sig: VariableBytes::default(),
                pq_sig: VariableBytes::default(),
            },
        };
        assert_eq!(required_fee_for_transaction(&tx, 123).unwrap(), 123);
        let mut oversized = tx.clone();
        oversized.outputs[0].owner_pubkey.pq_pk =
            VariableBytes::from_slice(&vec![0; 2048]).unwrap();
        let overflow = required_fee_for_transaction(&oversized, u64::MAX).unwrap_err();
        assert_eq!(overflow.to_string(), "transaction error: fee calculation overflow");
    }

    #[test]
    fn fee_policy_rejects_below_required_with_exact_message() {
        let (wallet, seed, pq_seed, sender) = make_wallet_with_funds();
        let recipient = test_keypair(0x77);
        let address = PaymentAddressV1::new(TEST_CHAIN_ID.as_bytes(), recipient.public_key())
            .unwrap()
            .to_text();
        let baseline = build_transaction(&TxParams {
            chain_id: TEST_CHAIN_ID,
            recipient_address: &address,
            amount_spark: 1_000_000,
            fee_spark: 1,
            wallet: &wallet,
            ed25519_seed: seed,
            ml_dsa_seed_bytes: pq_seed.clone(),
            sender_pubkey: sender.clone(),
        })
        .unwrap();
        let required = required_fee_from_built(&baseline, 1).unwrap();
        let error = match build_transaction_with_fee_policy(
            &TxParams {
                chain_id: TEST_CHAIN_ID,
                recipient_address: &address,
                amount_spark: 1_000_000,
                fee_spark: required.saturating_sub(1),
                wallet: &wallet,
                ed25519_seed: seed,
                ml_dsa_seed_bytes: pq_seed,
                sender_pubkey: sender,
            },
            1,
            Some(required.saturating_sub(1)),
        ) {
            Ok(_) => panic!("below-required fee unexpectedly accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            format!(
                "transaction error: fee {} spark is below the minimum {} spark for this transaction at base fee 1 spark/KiB",
                required.saturating_sub(1),
                required
            )
        );
    }

    #[test]
    fn cold_cli_transfer_is_accepted_hot_signature_rejected_and_change_returns_to_cold_owner() {
        let entries = [
            ([1; 32], [1; 32], [1; 32]),
            ([2; 32], [2; 32], [2; 32]),
            ([3; 32], [3; 32], [3; 32]),
            ([4; 32], [4; 32], [4; 32]),
        ];
        let manifest = indra_node::genesis::test_genesis_toml(TEST_CHAIN_ID, &entries);
        let path = std::env::temp_dir().join(format!(
            "indra-cli-cold-transfer-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, manifest).unwrap();
        let state = indra_node::build_finalized_genesis_state(path.to_str()).unwrap();
        let mut cold_classical_seed = [1u8; 32];
        cold_classical_seed[0] ^= 0xA5;
        let mut cold_pq_seed = [1u8; 32];
        cold_pq_seed[0] ^= 0x5A;
        let cold =
            ColdHybridKeypair::from_independent_seeds(cold_classical_seed, cold_pq_seed).unwrap();
        let cold_public = cold.public_key();
        let complete = cold_public.as_complete_hybrid();
        let cold_owner = HybridPubKey {
            classical_pk: Bytes32::from(complete.classical.0),
            pq_pk: VariableBytes::from_slice(&complete.pq.0).unwrap(),
        };
        let entry = state
            .utxos
            .all_entries()
            .find(|entry| entry.output.owner_pubkey == cold_owner)
            .unwrap();
        let genesis_utxo_id = entry.utxo_id;
        let genesis_value = entry.output.value_spark;
        let mut wallet = Wallet::new();
        wallet.add_utxo(
            genesis_utxo_id,
            genesis_value,
            entry.created_height,
            entry.tx_index,
            entry.output_index,
            cold_owner.clone(),
        );
        let recipient = test_keypair(0x77);
        let recipient_owner = hybrid_pubkey_from_keypair(&recipient).unwrap();
        let recipient_address =
            PaymentAddressV1::new(TEST_CHAIN_ID.as_bytes(), recipient.public_key())
                .unwrap()
                .to_text();
        let built = build_cold_transaction(&ColdTxParams {
            chain_id: TEST_CHAIN_ID,
            recipient_address: &recipient_address,
            amount_spark: 1_000_000,
            fee_spark: TEST_FEE_SPARK,
            wallet: &wallet,
            keypair: &cold,
            owner_pubkey: cold_owner.clone(),
        })
        .unwrap();
        let tx = decode_built_tx(&built);
        assert_eq!(tx.outputs[0].value_spark, 1_000_000);
        assert_eq!(tx.outputs[0].owner_pubkey, recipient_owner);
        assert_eq!(tx.outputs[1].owner_pubkey, cold_owner);
        let mut accepted = state.clone();
        assert_eq!(
            indra_state::try_apply_transaction_candidate_with_dust(
                &mut accepted,
                &tx,
                1,
                0,
                indra_core::types::primitives::DUST_LIMIT_SPARK,
            ),
            Ok(())
        );
        assert!(!accepted.utxos.contains(&genesis_utxo_id));
        assert!(accepted.utxos.all_entries().any(|entry| {
            entry.output.owner_pubkey == cold_owner
                && entry.output.value_spark == genesis_value - 1_000_000 - TEST_FEE_SPARK
        }));
        assert!(accepted.utxos.all_entries().any(|entry| {
            entry.output.owner_pubkey == recipient_owner && entry.output.value_spark == 1_000_000
        }));
        let mut hot_tx = tx.clone();
        let hot = test_keypair(1);
        let signature = hot
            .sign(&hot_tx.signing_bytes(TEST_CHAIN_ID).unwrap())
            .unwrap();
        hot_tx.signature = wire_hybrid_signature(&signature).unwrap();
        let mut rejected = state;
        let error = indra_state::try_apply_transaction_candidate_with_dust(
            &mut rejected,
            &hot_tx,
            1,
            0,
            indra_core::types::primitives::DUST_LIMIT_SPARK,
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "transaction signature invalid: Ed25519 signature verification failed"
        );
        assert!(rejected.utxos.contains(&genesis_utxo_id));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn hot_and_cold_builders_select_only_their_owner_utxos() {
        let hot = test_keypair(0x31);
        let hot_owner = hybrid_pubkey_from_keypair(&hot).unwrap();
        let cold = test_cold_keypair(0x41);
        let cold_owner = crate::cold_hybrid_pubkey(&cold).unwrap();
        let recipient = test_keypair(0x51);
        let recipient_address =
            PaymentAddressV1::new(TEST_CHAIN_ID.as_bytes(), recipient.public_key())
                .unwrap()
                .to_text();
        let hot_id = Bytes32::from([0xA1; 32]);
        let cold_id = Bytes32::from([0xB2; 32]);
        let mut wallet = Wallet::new();
        wallet.add_utxo(hot_id, 200_000, 1, 0, 0, hot_owner.clone());
        wallet.add_utxo(cold_id, 2_000_000, 1, 0, 1, cold_owner.clone());
        let hot_built = build_transaction(&TxParams {
            chain_id: TEST_CHAIN_ID,
            recipient_address: &recipient_address,
            amount_spark: 100_000,
            fee_spark: TEST_FEE_SPARK,
            wallet: &wallet,
            ed25519_seed: [0x31; 32],
            ml_dsa_seed_bytes: PqKeypair::from_seed(&[0x31; 32])
                .unwrap()
                .secret_key_bytes()
                .to_vec(),
            sender_pubkey: hot_owner,
        })
        .unwrap();
        assert_eq!(hot_built.spent_utxo_ids, vec![hot_id]);
        let cold_built = build_cold_transaction(&ColdTxParams {
            chain_id: TEST_CHAIN_ID,
            recipient_address: &recipient_address,
            amount_spark: 100_000,
            fee_spark: TEST_FEE_SPARK,
            wallet: &wallet,
            keypair: &cold,
            owner_pubkey: cold_owner,
        })
        .unwrap();
        assert_eq!(cold_built.spent_utxo_ids, vec![cold_id]);
    }

    fn build_self_stake_op(
        deposit_utxo_id: Bytes32,
        validator_keypair: &HybridKeypair,
        cold_nonce: u64,
        chain_id: &str,
    ) -> CliResult<BuiltStakingOp> {
        build_cold_authorized_staking_op(
            ColdAuthorizedStakingAction::SelfStake {
                deposit_utxo_id,
                validator_pubkey: hybrid_pubkey_from_keypair(validator_keypair)?,
            },
            &test_cold_keypair(0xE1),
            1,
            cold_nonce,
            chain_id,
        )
    }

    fn build_set_commission_op(
        validator_id: Bytes32,
        new_commission_bps: u32,
        _validator_keypair: &HybridKeypair,
        cold_nonce: u64,
        chain_id: &str,
    ) -> CliResult<BuiltStakingOp> {
        build_cold_authorized_staking_op(
            ColdAuthorizedStakingAction::SetCommission {
                validator_id,
                new_commission_bps,
            },
            &test_cold_keypair(0xE2),
            1,
            cold_nonce,
            chain_id,
        )
    }

    fn build_set_auto_delegate_op(
        validator_id: Bytes32,
        target_validator_id: Bytes32,
        _validator_keypair: &HybridKeypair,
        cold_nonce: u64,
        chain_id: &str,
    ) -> CliResult<BuiltStakingOp> {
        build_cold_authorized_staking_op(
            ColdAuthorizedStakingAction::SetAutoDelegate {
                validator_id,
                target_validator_id,
            },
            &test_cold_keypair(0xE3),
            1,
            cold_nonce,
            chain_id,
        )
    }

    fn decode_built(built: &BuiltStakingOp) -> StakingOp {
        let bytes = hex::decode(&built.op_hex).unwrap();
        StakingOp::decode_exact(&bytes).unwrap()
    }

    fn decode_built_tx(built: &BuiltTransaction) -> TransactionV1 {
        let bytes = hex::decode(&built.tx_hex).unwrap();
        TransactionV1::decode_exact(&bytes).unwrap()
    }

    fn payment_address(keypair: &HybridKeypair) -> String {
        PaymentAddressV1::new(TEST_CHAIN_ID.as_bytes(), keypair.public_key())
            .unwrap()
            .to_text()
    }

    #[test]
    fn build_transaction_requires_valid_address_and_sets_recipient_owner() {
        let (wallet, seed, pq_seed, sender_pubkey) = make_wallet_with_funds();
        let recipient_keypair = test_keypair(0x61);
        let recipient_address = payment_address(&recipient_keypair);
        let built = build_transaction(&TxParams {
            chain_id: TEST_CHAIN_ID,
            recipient_address: &recipient_address,
            amount_spark: 1_000_000,
            fee_spark: TEST_FEE_SPARK,
            wallet: &wallet,
            ed25519_seed: seed,
            ml_dsa_seed_bytes: pq_seed,
            sender_pubkey,
        })
        .unwrap();
        let tx = decode_built_tx(&built);
        assert!(tx.validate_structure().is_ok());
        assert_eq!(tx.outputs[0].value_spark, 1_000_000);
        assert_eq!(
            tx.outputs[0].owner_pubkey,
            hybrid_pubkey_from_keypair(&recipient_keypair).unwrap()
        );
    }

    #[test]
    fn change_output_uses_sender_hybrid_pubkey() {
        let (wallet, seed, pq_seed, sender_pubkey) = make_wallet_with_funds();
        let recipient_address = payment_address(&test_keypair(0x62));
        let built = build_transaction(&TxParams {
            chain_id: TEST_CHAIN_ID,
            recipient_address: &recipient_address,
            amount_spark: 1_000_000,
            fee_spark: TEST_FEE_SPARK,
            wallet: &wallet,
            ed25519_seed: seed,
            ml_dsa_seed_bytes: pq_seed,
            sender_pubkey: sender_pubkey.clone(),
        })
        .unwrap();
        let tx = decode_built_tx(&built);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.outputs[1].value_spark, built.change_spark);
        assert_eq!(tx.outputs[1].owner_pubkey, sender_pubkey);
    }

    #[test]
    fn sub_dust_change_is_folded_into_fee_and_conservation_remains_exact() {
        for remainder in [1, DUST_LIMIT_SPARK] {
            let (wallet, seed, pq_seed, sender_pubkey) = make_wallet_with_funds();
            let recipient_address = payment_address(&test_keypair(0x6A));
            let amount = 10_000_000 - TEST_FEE_SPARK - remainder;
            let built = build_transaction(&TxParams {
                chain_id: TEST_CHAIN_ID,
                recipient_address: &recipient_address,
                amount_spark: amount,
                fee_spark: TEST_FEE_SPARK,
                wallet: &wallet,
                ed25519_seed: seed,
                ml_dsa_seed_bytes: pq_seed,
                sender_pubkey,
            })
            .unwrap();
            let tx = decode_built_tx(&built);
            assert_eq!(built.change_spark, 0);
            assert!(built.pending_change.is_none());
            assert_eq!(tx.outputs.len(), 1);
            assert_eq!(tx.fee_amount, TEST_FEE_SPARK + remainder);
            assert_eq!(tx.outputs[0].value_spark + tx.fee_amount, 10_000_000);
        }
    }

    #[test]
    fn malformed_or_wrong_chain_descriptor_is_rejected() {
        let (wallet, seed, pq_seed, sender_pubkey) = make_wallet_with_funds();
        for recipient_address in [
            "not-an-address".to_string(),
            payment_address(&test_keypair(0x63)).replace("indra:", "bad:"),
        ] {
            assert!(build_transaction(&TxParams {
                chain_id: TEST_CHAIN_ID,
                recipient_address: &recipient_address,
                amount_spark: 1_000_000,
                fee_spark: TEST_FEE_SPARK,
                wallet: &wallet,
                ed25519_seed: seed,
                ml_dsa_seed_bytes: pq_seed.clone(),
                sender_pubkey: sender_pubkey.clone(),
            })
            .is_err());
        }
    }

    #[test]
    fn insufficient_balance_and_dust_are_rejected() {
        let (wallet, seed, pq_seed, sender_pubkey) = make_wallet_with_funds();
        let recipient_address = payment_address(&test_keypair(0x64));
        for amount_spark in [1, 100_000_000] {
            assert!(build_transaction(&TxParams {
                chain_id: TEST_CHAIN_ID,
                recipient_address: &recipient_address,
                amount_spark,
                fee_spark: TEST_FEE_SPARK,
                wallet: &wallet,
                ed25519_seed: seed,
                ml_dsa_seed_bytes: pq_seed.clone(),
                sender_pubkey: sender_pubkey.clone(),
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
        let built = build_self_stake_op(deposit_utxo_id, &keypair, 7, TEST_CHAIN_ID).unwrap();
        let bytes = hex::decode(&built.op_hex).unwrap();
        let op = StakingOp::decode_exact(&bytes).unwrap();

        assert_eq!(built.op_id.len(), 64);
        assert_eq!(op.nonce, 0);
        assert!(matches!(
            op.body,
            StakingOpBody::SelfStake {
                deposit_utxo_id: id,
                validator_pubkey,
                ..
            } if id == deposit_utxo_id
                && validator_pubkey.classical_pk == spk.classical_pk
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
            TEST_CHAIN_ID,
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
            &keypair,
            &test_cold_keypair(0x91),
            &VrfKeypair::from_seed(&[0xAA; 32]),
            9,
            TEST_CHAIN_ID,
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
            } if id == deposit_utxo_id
                && vrf_pk == VrfKeypair::from_seed(&[0xAA; 32]).public_key()
        ));
    }

    #[test]
    fn build_delegate_op_serialises_and_decodes() {
        let keypair = test_keypair(0x72);
        let validator_id = Bytes32::from([0x01; 32]);
        let deposit_utxo_id = Bytes32::from([0x02; 32]);
        let built =
            build_delegate_op(validator_id, deposit_utxo_id, &keypair, 10, TEST_CHAIN_ID).unwrap();
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
            TEST_CHAIN_ID,
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
        let built = build_claim_rewards_op(validator_id, &keypair, 12, TEST_CHAIN_ID).unwrap();
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
            build_set_commission_op(validator_id, 1_500, &keypair, 13, TEST_CHAIN_ID).unwrap();
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
            TEST_CHAIN_ID,
        )
        .unwrap();
        let op = decode_built(&built);
        assert_eq!(op.nonce, 0);
        assert_eq!(op.cold_authorization().unwrap().cold_nonce, 14);
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
            build_set_auto_delegate_op(validator_id, Bytes32::ZERO, &keypair, 15, TEST_CHAIN_ID)
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
            TEST_CHAIN_ID,
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
            build_update_network_address_op(validator_id, None, &keypair, 17, TEST_CHAIN_ID)
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
            TEST_CHAIN_ID,
        )
        .is_err());
    }

    #[test]
    fn all_ops_have_correct_replay_nonce_namespace() {
        let keypair = test_keypair(0x76);
        let validator_id = Bytes32::from([0x07; 32]);
        let deposit_utxo_id = Bytes32::from([0x08; 32]);
        let ops = vec![
            build_register_validator_op_with_cold(
                1_000,
                deposit_utxo_id,
                &keypair,
                &test_cold_keypair(0x92),
                &VrfKeypair::from_seed(&[0x11; 32]),
                42,
                TEST_CHAIN_ID,
            )
            .unwrap(),
            build_self_stake_op(deposit_utxo_id, &keypair, 42, TEST_CHAIN_ID).unwrap(),
            build_delegate_op(validator_id, deposit_utxo_id, &keypair, 42, TEST_CHAIN_ID).unwrap(),
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
                TEST_CHAIN_ID,
            )
            .unwrap(),
            build_claim_rewards_op(validator_id, &keypair, 42, TEST_CHAIN_ID).unwrap(),
            build_set_commission_op(validator_id, 1_100, &keypair, 42, TEST_CHAIN_ID).unwrap(),
            build_set_auto_delegate_op(
                validator_id,
                Bytes32::from([0x19; 32]),
                &keypair,
                42,
                TEST_CHAIN_ID,
            )
            .unwrap(),
            build_update_network_address_op(
                validator_id,
                Some("203.0.113.20:30303".to_string()),
                &keypair,
                42,
                TEST_CHAIN_ID,
            )
            .unwrap(),
        ];
        for (index, built) in ops.into_iter().enumerate() {
            let op = decode_built(&built);
            if matches!(index, 1 | 5 | 6) {
                assert_eq!(op.nonce, 0);
                assert_eq!(op.cold_authorization().unwrap().cold_nonce, 42);
            } else {
                assert_eq!(op.nonce, 42);
            }
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
                &keypair,
                &test_cold_keypair(0x93),
                &VrfKeypair::from_seed(&[0x12; 32]),
                1,
                TEST_CHAIN_ID,
            )
            .unwrap(),
            build_self_stake_op(deposit_utxo_id, &keypair, 2, TEST_CHAIN_ID).unwrap(),
            build_delegate_op(validator_id, deposit_utxo_id, &keypair, 4, TEST_CHAIN_ID).unwrap(),
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
                TEST_CHAIN_ID,
            )
            .unwrap(),
            build_claim_rewards_op(validator_id, &keypair, 6, TEST_CHAIN_ID).unwrap(),
            build_set_commission_op(validator_id, 1_200, &keypair, 7, TEST_CHAIN_ID).unwrap(),
            build_set_auto_delegate_op(
                validator_id,
                Bytes32::from([0x1A; 32]),
                &keypair,
                8,
                TEST_CHAIN_ID,
            )
            .unwrap(),
            build_update_network_address_op(
                validator_id,
                Some("203.0.113.21:30303".to_string()),
                &keypair,
                9,
                TEST_CHAIN_ID,
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
