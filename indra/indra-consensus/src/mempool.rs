//! Mempool — the validated pool of pending transactions.
//!
//! ## Design
//!
//! Transactions enter the mempool after passing structural validation and
//! a fee check against the current base fee. They stay until either:
//!   a) included in a block (evicted on block application), or
//!   b) they age out (fee too low after base fee rises), or
//!   c) the mempool is full and a higher-fee tx displaces them.
//!
//! ## Age-inclusion guarantee
//!
//! Any transaction that has been in the mempool for AGE_INCLUSION_BLOCKS
//! consecutive blocks without being included is "age-eligible". The block
//! producer MUST include all age-eligible transactions (up to block limits).
//! This prevents censorship: a validator cannot indefinitely exclude a tx.
//!
//! ## Storage model (Phase 4)
//!
//! In-memory HashMap keyed by tx_id = SHA-256(encode(tx)).
//! Phase 5 adds WAL-backed persistence.

use std::collections::{HashMap, HashSet};

use indra_core::{
    codec::Encode,
    types::{primitives::Bytes32, transaction::TransactionV1},
};
use indra_crypto::sha256;

use crate::error::{ConsensusError, ConsensusResult};

/// Number of blocks a transaction can wait before becoming age-eligible.
/// After this many blocks without inclusion, the proposer MUST include it.
pub const AGE_INCLUSION_BLOCKS: u64 = 50;

/// Maximum number of transactions the mempool holds at once.
pub const DEFAULT_MEMPOOL_CAPACITY: usize = 5_000;

/// Configuration for the mempool.
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of transactions.
    pub capacity: usize,
    /// Minimum fee ratio: transaction fee must be at least this multiple
    /// of the current base fee (in basis points, 10000 = 1x).
    pub min_fee_ratio_bps: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_MEMPOOL_CAPACITY,
            min_fee_ratio_bps: 10_000, // exactly 1x base fee
        }
    }
}

/// A single entry in the mempool.
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    /// The transaction itself.
    pub tx: TransactionV1,
    /// SHA-256 of the encoded transaction (used as the map key).
    pub tx_id: Bytes32,
    /// Block height at which this transaction entered the mempool.
    pub arrived_height: u64,
    /// Fee per KB of transaction weight (Spark/KB).
    pub fee_rate: u64,
}

impl MempoolEntry {
    /// True if this transaction has been waiting long enough to be
    /// age-eligible (the proposer must include it).
    pub fn is_age_eligible(&self, current_height: u64) -> bool {
        current_height.saturating_sub(self.arrived_height) >= AGE_INCLUSION_BLOCKS
    }
}

/// The mempool.
#[derive(Debug, Clone)]
pub struct Mempool {
    entries: HashMap<Bytes32, MempoolEntry>,
    config: MempoolConfig,
}

impl Mempool {
    /// Create a new empty mempool with the given configuration.
    pub fn new(config: MempoolConfig) -> Self {
        Self {
            entries: HashMap::new(),
            config,
        }
    }

    /// Create with default configuration.
    pub fn default_config() -> Self {
        Self::new(MempoolConfig::default())
    }

    /// Number of transactions currently in the mempool.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute the transaction ID: SHA-256(encode(tx)).
    pub fn tx_id(tx: &TransactionV1) -> Bytes32 {
        Bytes32::from(sha256(&tx.encode_to_vec()))
    }

    /// Submit a transaction to the mempool.
    ///
    /// Validates:
    /// - Not already present
    /// - Has at least one input and one output
    /// - Fee meets the minimum ratio against `current_base_fee`
    ///
    /// Does NOT validate: signatures, UTXO existence, nullifier set.
    /// Those checks happen in apply_block when the tx is included.
    pub fn submit(
        &mut self,
        tx: TransactionV1,
        current_base_fee: u64,
        current_height: u64,
    ) -> ConsensusResult<Bytes32> {
        tx.validate_structure()
            .map_err(|_| ConsensusError::InvalidTransaction {
                reason: "transaction structure invalid",
            })?;

        let tx_id = Self::tx_id(&tx);

        // Duplicate check
        if self.entries.contains_key(&tx_id) {
            return Err(ConsensusError::DuplicateTransaction);
        }

        // Fee check
        let weight_kb = (tx.encode_to_vec().len() as u64).div_ceil(1024);
        let fee_rate = if weight_kb > 0 {
            tx.fee_amount / weight_kb
        } else {
            tx.fee_amount
        };
        let min_fee = current_base_fee.saturating_mul(self.config.min_fee_ratio_bps) / 10_000;
        if fee_rate < min_fee {
            return Err(ConsensusError::FeeTooLow);
        }

        // Capacity check — evict lowest-fee tx if full
        if self.entries.len() >= self.config.capacity {
            // Find the tx with the lowest fee rate. Break equal-fee ties by
            // highest tx_id so every node evicts the same transaction.
            let min_id = self
                .entries
                .iter()
                .min_by(|(_, a), (_, b)| {
                    a.fee_rate
                        .cmp(&b.fee_rate)
                        .then_with(|| b.tx_id.cmp(&a.tx_id))
                })
                .map(|(id, _)| *id);

            if let Some(min_id) = min_id {
                let min_rate = self.entries.get(&min_id).map(|e| e.fee_rate).unwrap_or(0);
                if fee_rate > min_rate {
                    self.entries.remove(&min_id);
                } else {
                    return Err(ConsensusError::MempoolFull {
                        capacity: self.config.capacity,
                    });
                }
            }
        }

        self.entries.insert(
            tx_id,
            MempoolEntry {
                tx,
                tx_id,
                arrived_height: current_height,
                fee_rate,
            },
        );

        Ok(tx_id)
    }

    /// Submit a transaction after full state-machine validation.
    ///
    /// This is the admission path for RPC and P2P gossip. Final block
    /// application still revalidates every transaction authoritatively, but
    /// full admission validation keeps signature-invalid, unknown-UTXO, or
    /// already-spent transactions out of the mempool and prevents gossiping
    /// them to peers.
    pub fn submit_validated(
        &mut self,
        tx: TransactionV1,
        state: &indra_state::ChainState,
    ) -> ConsensusResult<Bytes32> {
        let mut block_nullifiers = HashSet::new();
        let mut block_input_utxos = HashSet::new();
        if let Err(error) = indra_state::apply::validate_transaction(
            state,
            &tx,
            &state.chain_id,
            &mut block_nullifiers,
            &mut block_input_utxos,
            state.height.saturating_add(1),
        ) {
            eprintln!(
                "[mempool] rejected invalid tx {:?}: {}",
                Self::tx_id(&tx),
                error
            );
            return Err(ConsensusError::InvalidTransaction {
                reason: "state validation failed",
            });
        }
        self.submit(tx, state.base_fee, state.height)
    }

    /// Remove a transaction by ID (called after block inclusion).
    pub fn evict(&mut self, tx_id: &Bytes32) -> Option<MempoolEntry> {
        self.entries.remove(tx_id)
    }

    /// Remove all transactions whose nullifiers appear in the given set.
    /// Called after a block is applied to evict spent transactions.
    pub fn evict_spent(&mut self, nullifiers: &indra_state::NullifierSet) {
        self.entries.retain(|_, entry| {
            !entry
                .tx
                .inputs
                .iter()
                .any(|i| nullifiers.contains(&i.nullifier))
        });
    }

    /// Remove transactions that are no longer valid against the current state.
    pub fn evict_invalid(&mut self, state: &indra_state::ChainState) {
        self.entries.retain(|tx_id, entry| {
            let mut block_nullifiers = HashSet::new();
            let mut block_input_utxos = HashSet::new();
            let keep = indra_state::apply::validate_transaction(
                state,
                &entry.tx,
                &state.chain_id,
                &mut block_nullifiers,
                &mut block_input_utxos,
                state.height.saturating_add(1),
            )
            .is_ok();
            if !keep {
                eprintln!("[mempool] evicting invalid tx {:?}", tx_id);
            }
            keep
        });
    }

    /// Return transactions for block production.
    ///
    /// Returns up to `max_count` transactions, prioritising:
    ///   1. Age-eligible transactions (MUST be included), sorted by fee_rate desc, tx_id asc
    ///   2. Remaining transactions sorted by fee_rate desc, tx_id asc
    pub fn select_for_block(&self, max_count: usize, current_height: u64) -> Vec<&MempoolEntry> {
        let mut age_eligible: Vec<&MempoolEntry> = self
            .entries
            .values()
            .filter(|e| e.is_age_eligible(current_height))
            .collect();
        age_eligible.sort_by(|a, b| {
            b.fee_rate
                .cmp(&a.fee_rate)
                .then_with(|| a.tx_id.cmp(&b.tx_id))
        });

        let mut remaining: Vec<&MempoolEntry> = self
            .entries
            .values()
            .filter(|e| !e.is_age_eligible(current_height))
            .collect();
        remaining.sort_by(|a, b| {
            b.fee_rate
                .cmp(&a.fee_rate)
                .then_with(|| a.tx_id.cmp(&b.tx_id))
        });

        age_eligible.extend(remaining);
        age_eligible.truncate(max_count);
        age_eligible
    }

    /// Return all age-eligible transactions regardless of count.
    pub fn age_eligible(&self, current_height: u64) -> Vec<&MempoolEntry> {
        self.entries
            .values()
            .filter(|e| e.is_age_eligible(current_height))
            .collect()
    }

    /// True if the mempool contains at least one transaction whose fee rate
    /// currently meets this mempool's admission threshold.
    pub fn has_fee_eligible_transactions(&self, current_base_fee: u64) -> bool {
        let min_fee = current_base_fee.saturating_mul(self.config.min_fee_ratio_bps) / 10_000;
        self.entries.values().any(|entry| entry.fee_rate >= min_fee)
    }

    /// Check whether a transaction is present.
    pub fn contains(&self, tx_id: &Bytes32) -> bool {
        self.entries.contains_key(tx_id)
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &MempoolEntry> {
        self.entries.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use indra_core::{
        types::{
            crypto::{CommitmentV1, HybridSignature},
            primitives::{DUST_LIMIT_SPARK, INITIAL_BASE_FEE_SPARK_PER_KB, MAX_RANGE_PROOF_BYTES},
            transaction::{InputV1, OutputV1, TransactionV1},
        },
        Bytes32, HybridPubKey, ProtocolVersion, VariableBytes,
    };
    use indra_crypto::{commit, prove_range, ClassicalKeypair, HybridKeypair, PqKeypair};
    use indra_state::ChainState;
    use rand::{rngs::StdRng, SeedableRng};

    fn dummy_tx(fee: u64, nullifier_byte: u8) -> TransactionV1 {
        TransactionV1 {
            version: ProtocolVersion::CURRENT,
            signature_module_id: 1,
            inputs: vec![InputV1 {
                utxo_id: Bytes32::from([nullifier_byte; 32]),
                nullifier: Bytes32::from([nullifier_byte; 32]),
            }],
            outputs: vec![OutputV1 {
                value_spark: DUST_LIMIT_SPARK,
                commitment: CommitmentV1 {
                    compressed_point: Bytes32::ZERO,
                },
                owner_pubkey: HybridPubKey {
                    classical_pk: Bytes32::ZERO,
                    pq_pk: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
                },
                range_proof: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
                lock_height: 0,
            }],
            payment_notes: Vec::new(),
            fee_amount: fee,
            fee_blinding: Bytes32::ZERO,
            fee_commitment: CommitmentV1 {
                compressed_point: Bytes32::ZERO,
            },
            signature: HybridSignature {
                classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                pq_sig: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            },
        }
    }

    fn keypair(seed: [u8; 32]) -> (HybridPubKey, HybridKeypair) {
        let classical = ClassicalKeypair::from_seed(&seed);
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let keypair = HybridKeypair::new(classical, pq);
        let public = keypair.public_key();
        (
            HybridPubKey {
                classical_pk: Bytes32::from(public.classical.0),
                pq_pk: VariableBytes::from_slice(&public.pq.0).unwrap(),
            },
            keypair,
        )
    }

    fn output(
        value: u64,
        blinding: [u8; 32],
        owner_pubkey: HybridPubKey,
        proof_seed: [u8; 32],
    ) -> OutputV1 {
        let commitment = commit(value, &blinding);
        let mut rng = StdRng::from_seed(proof_seed);
        let proof = prove_range(value, &blinding, &mut rng).unwrap();
        OutputV1 {
            value_spark: value,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from(commitment.0),
            },
            owner_pubkey,
            range_proof: VariableBytes::<MAX_RANGE_PROOF_BYTES>::from_slice(&proof).unwrap(),
            lock_height: 0,
        }
    }

    fn sign_tx(tx: &TransactionV1, keypair: &HybridKeypair, chain_id: &str) -> HybridSignature {
        let sig = keypair.sign(&tx.signing_bytes(chain_id)).unwrap();
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
        }
    }

    fn valid_state_and_tx() -> (ChainState, TransactionV1) {
        let mut state = ChainState::new_genesis();
        let (owner_pubkey, owner_keypair) = keypair([0x42; 32]);
        let input_value = 10_000_000_000u64;
        let input_blinding = [0x11; 32];
        let original_output = output(
            input_value,
            input_blinding,
            owner_pubkey.clone(),
            [0x51; 32],
        );
        let utxo_id = state.utxos.insert(original_output, 0, 0, 0).unwrap();
        let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 10;
        let output_value = input_value - fee;
        let output_blinding = [0x21; 32];
        let fee_blinding = (Scalar::from_bytes_mod_order(input_blinding)
            - Scalar::from_bytes_mod_order(output_blinding))
        .to_bytes();
        let fee_commitment = commit(fee, &fee_blinding);
        let mut tx = TransactionV1 {
            version: ProtocolVersion::CURRENT,
            signature_module_id: 1,
            inputs: vec![InputV1 {
                utxo_id,
                nullifier: Bytes32::from([0xA1; 32]),
            }],
            outputs: vec![output(
                output_value,
                output_blinding,
                owner_pubkey,
                [0x61; 32],
            )],
            payment_notes: Vec::new(),
            fee_amount: fee,
            fee_blinding: Bytes32::from(fee_blinding),
            fee_commitment: CommitmentV1 {
                compressed_point: Bytes32::from(fee_commitment.0),
            },
            signature: HybridSignature {
                classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
            },
        };
        tx.signature = sign_tx(&tx, &owner_keypair, &state.chain_id);
        (state, tx)
    }

    #[test]
    fn submit_and_retrieve() {
        let mut mp = Mempool::default_config();
        let tx = dummy_tx(10_000, 0x01);
        let id = mp.submit(tx.clone(), 100, 1).unwrap();
        assert!(mp.contains(&id));
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn duplicate_rejected() {
        let mut mp = Mempool::default_config();
        let tx = dummy_tx(10_000, 0x01);
        mp.submit(tx.clone(), 100, 1).unwrap();
        assert_eq!(
            mp.submit(tx, 100, 1),
            Err(ConsensusError::DuplicateTransaction)
        );
    }

    #[test]
    fn low_fee_rejected() {
        let mut mp = Mempool::default_config();
        let tx = dummy_tx(0, 0x01); // zero fee
        assert_eq!(mp.submit(tx, 1_000, 1), Err(ConsensusError::FeeTooLow));
    }

    #[test]
    fn evict_removes_tx() {
        let mut mp = Mempool::default_config();
        let tx = dummy_tx(10_000, 0x01);
        let id = mp.submit(tx, 100, 1).unwrap();
        mp.evict(&id);
        assert!(!mp.contains(&id));
    }

    #[test]
    fn age_eligible_after_threshold() {
        let mut mp = Mempool::default_config();
        let tx = dummy_tx(10_000, 0x01);
        mp.submit(tx, 100, 1).unwrap();

        // Not yet eligible
        assert!(mp.age_eligible(10).is_empty());
        // Eligible after AGE_INCLUSION_BLOCKS
        assert_eq!(mp.age_eligible(1 + AGE_INCLUSION_BLOCKS).len(), 1);
    }

    #[test]
    fn select_prioritises_age_eligible() {
        let mut mp = Mempool::default_config();
        // High fee tx submitted recently
        mp.submit(dummy_tx(100_000, 0x01), 100, 100).unwrap();
        // Low fee tx submitted long ago (age-eligible)
        mp.submit(dummy_tx(1_000, 0x02), 100, 1).unwrap();

        let selected = mp.select_for_block(2, 1 + AGE_INCLUSION_BLOCKS);
        // Age-eligible tx must come first despite lower fee
        assert_eq!(selected.first().map(|e| e.tx.fee_amount), Some(1_000));
    }

    #[test]
    fn high_fee_displaces_low_fee_when_full() {
        let config = MempoolConfig {
            capacity: 2,
            min_fee_ratio_bps: 10_000,
        };
        let mut mp = Mempool::new(config);
        mp.submit(dummy_tx(1_000, 0x01), 100, 1).unwrap();
        mp.submit(dummy_tx(2_000, 0x02), 100, 1).unwrap();
        // Third tx with higher fee should displace the lowest (0x01)
        mp.submit(dummy_tx(5_000, 0x03), 100, 1).unwrap();
        assert_eq!(mp.len(), 2);
        // The 1_000 fee tx should have been evicted
        let fees: Vec<u64> = mp.iter().map(|e| e.tx.fee_amount).collect();
        assert!(!fees.contains(&1_000));
    }

    #[test]
    fn mempool_select_for_block_is_deterministic_with_equal_fees() {
        let mut mp1 = Mempool::new(MempoolConfig {
            capacity: 100,
            min_fee_ratio_bps: 10_000,
        });
        let mut mp2 = Mempool::new(MempoolConfig {
            capacity: 100,
            min_fee_ratio_bps: 10_000,
        });
        let txs: Vec<TransactionV1> = (1..=10).map(|byte| dummy_tx(10_000, byte)).collect();

        for tx in &txs {
            mp1.submit(tx.clone(), 100, 1).unwrap();
        }
        for tx in txs.iter().rev() {
            mp2.submit(tx.clone(), 100, 1).unwrap();
        }

        let ids1: Vec<Bytes32> = mp1
            .select_for_block(5, 1)
            .iter()
            .map(|entry| entry.tx_id)
            .collect();
        let ids2: Vec<Bytes32> = mp2
            .select_for_block(5, 1)
            .iter()
            .map(|entry| entry.tx_id)
            .collect();
        let mut expected: Vec<Bytes32> = txs.iter().map(Mempool::tx_id).collect();
        expected.sort();
        expected.truncate(5);

        assert_eq!(ids1, ids2);
        assert_eq!(ids1, expected);
    }

    #[test]
    fn mempool_eviction_is_deterministic_with_equal_fees() {
        let config = MempoolConfig {
            capacity: 3,
            min_fee_ratio_bps: 10_000,
        };
        let mut mp1 = Mempool::new(config.clone());
        let mut mp2 = Mempool::new(config);
        let txs: Vec<TransactionV1> = (1..=3).map(|byte| dummy_tx(10_000, byte)).collect();
        let mut equal_fee_ids: Vec<Bytes32> = txs.iter().map(Mempool::tx_id).collect();
        equal_fee_ids.sort();
        let evicted_id = *equal_fee_ids.last().unwrap();

        for tx in &txs {
            mp1.submit(tx.clone(), 100, 1).unwrap();
        }
        for tx in txs.iter().rev() {
            mp2.submit(tx.clone(), 100, 1).unwrap();
        }

        mp1.submit(dummy_tx(20_000, 0xF0), 100, 1).unwrap();
        mp2.submit(dummy_tx(20_000, 0xF0), 100, 1).unwrap();

        assert!(!mp1.contains(&evicted_id));
        assert!(!mp2.contains(&evicted_id));

        let mut remaining1: Vec<Bytes32> = mp1.iter().map(|entry| entry.tx_id).collect();
        let mut remaining2: Vec<Bytes32> = mp2.iter().map(|entry| entry.tx_id).collect();
        remaining1.sort();
        remaining2.sort();
        assert_eq!(remaining1, remaining2);
    }

    #[test]
    fn evict_invalid_drops_transactions_that_fail_state_validation() {
        let mut mp = Mempool::default_config();
        let tx = dummy_tx(100_000, 0x01);
        let tx_id = mp.submit(tx, 100, 1).unwrap();
        assert!(mp.contains(&tx_id));

        let state = indra_state::ChainState::new_genesis();
        mp.evict_invalid(&state);

        assert!(!mp.contains(&tx_id));
    }

    #[test]
    fn mempool_rejects_transaction_with_invalid_signature() {
        let (state, mut tx) = valid_state_and_tx();
        tx.signature.classical_sig = VariableBytes::from_slice(&[0u8; 64]).unwrap();
        let mut mp = Mempool::default_config();

        assert!(matches!(
            mp.submit_validated(tx, &state),
            Err(ConsensusError::InvalidTransaction { .. })
        ));
        assert!(mp.is_empty());
    }

    #[test]
    fn mempool_rejects_transaction_spending_nonexistent_utxo() {
        let (state, mut tx) = valid_state_and_tx();
        tx.inputs[0].utxo_id = Bytes32::from([0xFF; 32]);
        let mut mp = Mempool::default_config();

        assert!(matches!(
            mp.submit_validated(tx, &state),
            Err(ConsensusError::InvalidTransaction { .. })
        ));
        assert!(mp.is_empty());
    }

    #[test]
    fn mempool_accepts_valid_transaction() {
        let (state, tx) = valid_state_and_tx();
        let mut mp = Mempool::default_config();
        let tx_id = mp.submit_validated(tx, &state).unwrap();

        assert!(mp.contains(&tx_id));
        assert_eq!(mp.len(), 1);
    }
}
