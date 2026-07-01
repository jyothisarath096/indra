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
        crypto::{CommitmentV1, HybridPubKey, HybridSignature},
        primitives::{Bytes32, ProtocolVersion, VariableBytes, MAX_RANGE_PROOF_BYTES},
        staking::{StakingOp, StakingOpBody},
        transaction::{InputV1, OutputV1, TransactionV1},
    },
};
use indra_crypto::{
    hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
    pedersen::commit,
    sha256,
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
    /// Recipient's hybrid public key (hex-encoded).
    pub recipient_pubkey_hex: &'a str,
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

    // 2. Parse recipient pubkey
    let recipient_pubkey = parse_pubkey_hex(params.recipient_pubkey_hex)?;

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
    // 5. Generate random blinding factors using OsRng.
    // Each transaction gets unique blindings — reusing blindings across
    // transactions breaks Pedersen commitment hiding (audit finding #8).
    use rand::RngCore;
    let mut blinding_buf = [0u8; 32];
    rng.fill_bytes(&mut blinding_buf);
    let recipient_blinding = blinding_buf;

    let change_blinding = if change_spark > DUST_LIMIT_SPARK {
        let mut cb = [0u8; 32];
        rng.fill_bytes(&mut cb);
        Some(cb)
    } else {
        None
    };

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
        version: ProtocolVersion::CURRENT,
        signature_module_id: 1,
        inputs,
        outputs,
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
    bond_utxo_id: Bytes32,
    validator_keypair: &HybridKeypair,
    nonce: u64,
    chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    build_signed_staking_op(
        StakingOpBody::SelfStake {
            bond_utxo_id,
            validator_pubkey: hybrid_pubkey_from_keypair(validator_keypair)?,
        },
        validator_keypair,
        nonce,
        chain_id,
    )
}

/// Build and sign a validator registration staking operation.
pub fn build_register_validator_op(
    commission_bps: u32,
    bond_utxo_id: Bytes32,
    keypair: &HybridKeypair,
    vrf_pk: [u8; 32],
    nonce: u64,
    chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    build_signed_staking_op(
        StakingOpBody::RegisterValidator {
            commission_bps,
            bond_utxo_id,
            validator_pubkey: hybrid_pubkey_from_keypair(keypair)?,
            vrf_pk,
        },
        keypair,
        nonce,
        chain_id,
    )
}

/// Build and sign a delegate staking operation.
pub fn build_delegate_op(
    validator_id: Bytes32,
    bond_utxo_id: Bytes32,
    delegator_keypair: &HybridKeypair,
    nonce: u64,
    chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    build_signed_staking_op(
        StakingOpBody::Delegate {
            validator_id,
            bond_utxo_id,
            delegator_pubkey: hybrid_pubkey_from_keypair(delegator_keypair)?,
        },
        delegator_keypair,
        nonce,
        chain_id,
    )
}

/// Build and sign an undelegate staking operation.
pub fn build_undelegate_op(
    validator_id: Bytes32,
    bond_utxo_id: Bytes32,
    delegator_keypair: &HybridKeypair,
    nonce: u64,
    chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    build_signed_staking_op(
        StakingOpBody::Undelegate {
            validator_id,
            bond_utxo_id,
            delegator_pubkey: hybrid_pubkey_from_keypair(delegator_keypair)?,
        },
        delegator_keypair,
        nonce,
        chain_id,
    )
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
        },
        keypair,
        nonce,
        chain_id,
    )
}

/// Build and sign a validator self-unstake operation.
pub fn build_self_unstake_op(
    bond_utxo_id: Bytes32,
    validator_keypair: &HybridKeypair,
    nonce: u64,
    chain_id: &str,
) -> CliResult<BuiltStakingOp> {
    build_signed_staking_op(
        StakingOpBody::SelfUnstake {
            bond_utxo_id,
            validator_pubkey: hybrid_pubkey_from_keypair(validator_keypair)?,
        },
        validator_keypair,
        nonce,
        chain_id,
    )
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
    op.signature = HybridSignature {
        classical_sig: VariableBytes::from_slice(&sig.classical.0)
            .map_err(|_| CliError::Transaction("classical sig too large".into()))?,
        pq_sig: VariableBytes::from_slice(&sig.pq.0)
            .map_err(|_| CliError::Transaction("pq sig too large".into()))?,
    };
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

/// Parse a hex-encoded hybrid public key.
fn parse_pubkey_hex(hex_str: &str) -> CliResult<HybridPubKey> {
    // Format: classical_pk_hex:pq_pk_hex (split by colon)
    // OR: just classical_pk_hex (32 bytes, pq_pk zeroed for now)
    let parts: Vec<&str> = hex_str.splitn(2, ':').collect();

    let classical_bytes = hex::decode(parts[0])
        .map_err(|_| CliError::InvalidHex("bad classical pubkey hex".into()))?;

    if classical_bytes.len() != 32 {
        return Err(CliError::Transaction(format!(
            "classical pubkey must be 32 bytes, got {}",
            classical_bytes.len()
        )));
    }

    let mut classical_arr = [0u8; 32];
    classical_arr.copy_from_slice(&classical_bytes);

    let pq_bytes = if parts.len() == 2 {
        hex::decode(parts[1]).map_err(|_| CliError::InvalidHex("bad pq pubkey hex".into()))?
    } else {
        vec![0u8; 2592] // zeroed pq key — not recommended for mainnet
    };

    Ok(HybridPubKey {
        classical_pk: Bytes32::from(classical_arr),
        pq_pk: VariableBytes::from_slice(&pq_bytes)
            .map_err(|_| CliError::Transaction("pq pubkey too large".into()))?,
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

    fn decode_built(built: &BuiltStakingOp) -> StakingOp {
        let bytes = hex::decode(&built.op_hex).unwrap();
        StakingOp::decode_exact(&bytes).unwrap()
    }

    #[test]
    fn build_basic_transaction() {
        let (wallet, seed, pq_sk, spk) = make_wallet_with_funds();
        let recipient_hex = hex::encode(spk.classical_pk.0);

        let params = TxParams {
            chain_id: DEFAULT_CHAIN_ID,
            recipient_pubkey_hex: &recipient_hex,
            amount_spark: 1_000_000,
            fee_spark: MIN_FEE_SPARK,
            wallet: &wallet,
            hybrid_seed: seed,
            pq_sk_bytes: pq_sk,
            sender_pubkey: spk,
        };

        let result = build_transaction(&params).unwrap();
        assert!(!result.tx_hex.is_empty());
        assert_eq!(result.tx_id.len(), 64);
        assert_eq!(result.change_spark, 8_950_000);
        assert_eq!(result.spent_utxo_ids.len(), 1);
    }

    #[test]
    fn insufficient_balance_errors() {
        let (wallet, seed, pq_sk, spk) = make_wallet_with_funds();
        let recipient_hex = hex::encode(spk.classical_pk.0);

        let params = TxParams {
            chain_id: DEFAULT_CHAIN_ID,
            recipient_pubkey_hex: &recipient_hex,
            amount_spark: 100_000_000,
            fee_spark: MIN_FEE_SPARK,
            wallet: &wallet,
            hybrid_seed: seed,
            pq_sk_bytes: pq_sk,
            sender_pubkey: spk,
        };

        assert!(build_transaction(&params).is_err());
    }

    #[test]
    fn dust_amount_rejected() {
        let (wallet, seed, pq_sk, spk) = make_wallet_with_funds();
        let recipient_hex = hex::encode(spk.classical_pk.0);

        let params = TxParams {
            chain_id: DEFAULT_CHAIN_ID,
            recipient_pubkey_hex: &recipient_hex,
            amount_spark: 1,
            fee_spark: MIN_FEE_SPARK,
            wallet: &wallet,
            hybrid_seed: seed,
            pq_sk_bytes: pq_sk,
            sender_pubkey: spk,
        };

        assert!(build_transaction(&params).is_err());
    }

    #[test]
    fn build_self_stake_op_serialises_signed_operation() {
        let (_, seed, _, spk) = make_wallet_with_funds();
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let keypair = HybridKeypair::new(ClassicalKeypair::from_seed(&seed), pq);
        let bond_utxo_id = Bytes32::from([0xA5; 32]);

        let built = build_self_stake_op(bond_utxo_id, &keypair, 7, DEFAULT_CHAIN_ID).unwrap();
        let bytes = hex::decode(&built.op_hex).unwrap();
        let op = StakingOp::decode_exact(&bytes).unwrap();

        assert_eq!(built.op_id.len(), 64);
        assert_eq!(op.nonce, 7);
        assert!(matches!(
            op.body,
            StakingOpBody::SelfStake {
                bond_utxo_id: id,
                validator_pubkey
            } if id == bond_utxo_id && validator_pubkey.classical_pk == spk.classical_pk
        ));
    }

    #[test]
    fn build_self_unstake_op_serialises_signed_operation() {
        let (_, seed, _, _) = make_wallet_with_funds();
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let keypair = HybridKeypair::new(ClassicalKeypair::from_seed(&seed), pq);
        let bond_utxo_id = Bytes32::from([0xA6; 32]);

        let built = build_self_unstake_op(bond_utxo_id, &keypair, 8, DEFAULT_CHAIN_ID).unwrap();
        let bytes = hex::decode(&built.op_hex).unwrap();
        let op = StakingOp::decode_exact(&bytes).unwrap();

        assert_eq!(built.op_id.len(), 64);
        assert_eq!(op.nonce, 8);
        assert!(matches!(
            op.body,
            StakingOpBody::SelfUnstake {
                bond_utxo_id: id,
                ..
            } if id == bond_utxo_id
        ));
    }

    #[test]
    fn build_register_validator_op_serialises_and_decodes() {
        let keypair = test_keypair(0x71);
        let bond_utxo_id = Bytes32::from([0xAB; 32]);
        let built = build_register_validator_op(
            1_000,
            bond_utxo_id,
            &keypair,
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
                bond_utxo_id: id,
                vrf_pk,
                ..
            } if id == bond_utxo_id && vrf_pk == [0xAA; 32]
        ));
    }

    #[test]
    fn build_delegate_op_serialises_and_decodes() {
        let keypair = test_keypair(0x72);
        let validator_id = Bytes32::from([0x01; 32]);
        let bond_utxo_id = Bytes32::from([0x02; 32]);
        let built =
            build_delegate_op(validator_id, bond_utxo_id, &keypair, 10, DEFAULT_CHAIN_ID).unwrap();
        let op = decode_built(&built);
        assert!(matches!(
            op.body,
            StakingOpBody::Delegate {
                validator_id: v,
                bond_utxo_id: b,
                ..
            } if v == validator_id && b == bond_utxo_id
        ));
    }

    #[test]
    fn build_undelegate_op_serialises_and_decodes() {
        let keypair = test_keypair(0x73);
        let validator_id = Bytes32::from([0x03; 32]);
        let bond_utxo_id = Bytes32::from([0x04; 32]);
        let built = build_undelegate_op(validator_id, bond_utxo_id, &keypair, 11, DEFAULT_CHAIN_ID)
            .unwrap();
        let op = decode_built(&built);
        assert!(matches!(
            op.body,
            StakingOpBody::Undelegate {
                validator_id: v,
                bond_utxo_id: b,
                ..
            } if v == validator_id && b == bond_utxo_id
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
            } if v == validator_id
        ));
    }

    #[test]
    fn all_ops_have_correct_nonce() {
        let keypair = test_keypair(0x76);
        let validator_id = Bytes32::from([0x07; 32]);
        let bond_utxo_id = Bytes32::from([0x08; 32]);
        let ops = vec![
            build_register_validator_op(
                1_000,
                bond_utxo_id,
                &keypair,
                [0x11; 32],
                42,
                DEFAULT_CHAIN_ID,
            )
            .unwrap(),
            build_self_stake_op(bond_utxo_id, &keypair, 42, DEFAULT_CHAIN_ID).unwrap(),
            build_self_unstake_op(bond_utxo_id, &keypair, 42, DEFAULT_CHAIN_ID).unwrap(),
            build_delegate_op(validator_id, bond_utxo_id, &keypair, 42, DEFAULT_CHAIN_ID).unwrap(),
            build_undelegate_op(validator_id, bond_utxo_id, &keypair, 42, DEFAULT_CHAIN_ID)
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
        ];
        for built in ops {
            assert_eq!(decode_built(&built).nonce, 42);
        }
    }

    #[test]
    fn all_ops_have_non_zero_signatures() {
        let keypair = test_keypair(0x77);
        let validator_id = Bytes32::from([0x09; 32]);
        let bond_utxo_id = Bytes32::from([0x0A; 32]);
        let ops = vec![
            build_register_validator_op(
                1_000,
                bond_utxo_id,
                &keypair,
                [0x12; 32],
                1,
                DEFAULT_CHAIN_ID,
            )
            .unwrap(),
            build_self_stake_op(bond_utxo_id, &keypair, 2, DEFAULT_CHAIN_ID).unwrap(),
            build_self_unstake_op(bond_utxo_id, &keypair, 3, DEFAULT_CHAIN_ID).unwrap(),
            build_delegate_op(validator_id, bond_utxo_id, &keypair, 4, DEFAULT_CHAIN_ID).unwrap(),
            build_undelegate_op(validator_id, bond_utxo_id, &keypair, 5, DEFAULT_CHAIN_ID).unwrap(),
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
