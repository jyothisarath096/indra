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
    types::{
        primitives::Bytes32,
        transaction::TransactionV1,
    },
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
    config:  MempoolConfig,
}

impl Mempool {
    /// Create a new empty mempool with the given configuration.
    pub fn new(config: MempoolConfig) -> Self {
        Self { entries: HashMap::new(), config }
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
        tx.validate_structure().map_err(|_| {
            ConsensusError::InvalidTransaction { reason: "transaction structure invalid" }
        })?;

        let tx_id = Self::tx_id(&tx);

        // Duplicate check
        if self.entries.contains_key(&tx_id) {
            return Err(ConsensusError::DuplicateTransaction);
        }

        // Fee check
        let weight_kb = (tx.encode_to_vec().len() as u64).div_ceil(1024);
        let fee_rate  = if weight_kb > 0 { tx.fee_amount / weight_kb } else { tx.fee_amount };
        let min_fee   = current_base_fee
            .saturating_mul(self.config.min_fee_ratio_bps)
            / 10_000;
        if fee_rate < min_fee {
            return Err(ConsensusError::FeeTooLow);
        }

        // Capacity check — evict lowest-fee tx if full
        if self.entries.len() >= self.config.capacity {
            // Find the tx with the lowest fee rate
            let min_id = self.entries
                .iter()
                .min_by_key(|(_, e)| e.fee_rate)
                .map(|(id, _)| *id);

            if let Some(min_id) = min_id {
                let min_rate = self.entries
                    .get(&min_id)
                    .map(|e| e.fee_rate)
                    .unwrap_or(0);
                if fee_rate > min_rate {
                    self.entries.remove(&min_id);
                } else {
                    return Err(ConsensusError::MempoolFull {
                        capacity: self.config.capacity,
                    });
                }
            }
        }

        self.entries.insert(tx_id, MempoolEntry {
            tx,
            tx_id,
            arrived_height: current_height,
            fee_rate,
        });

        Ok(tx_id)
    }

    /// Remove a transaction by ID (called after block inclusion).
    pub fn evict(&mut self, tx_id: &Bytes32) -> Option<MempoolEntry> {
        self.entries.remove(tx_id)
    }

    /// Remove all transactions whose nullifiers appear in the given set.
    /// Called after a block is applied to evict spent transactions.
    pub fn evict_spent(&mut self, nullifiers: &indra_state::NullifierSet) {
        self.entries.retain(|_, entry| {
            !entry.tx.inputs.iter().any(|i| nullifiers.contains(&i.nullifier))
        });
    }

    /// Remove transactions that are no longer valid against the current state.
    pub fn evict_invalid(&mut self, state: &indra_state::ChainState) {
        self.entries.retain(|tx_id, entry| {
            let mut block_nullifiers = HashSet::new();
            let keep = indra_state::apply::validate_transaction(
                state,
                &entry.tx,
                &state.chain_id,
                &mut block_nullifiers,
                state.height.saturating_add(1),
            ).is_ok();
            if !keep {
                eprintln!("[mempool] evicting invalid tx {:?}", tx_id);
            }
            keep
        });
    }

    /// Return transactions for block production.
    ///
    /// Returns up to `max_count` transactions, prioritising:
    ///   1. Age-eligible transactions (MUST be included), sorted by fee_rate desc
    ///   2. Remaining transactions sorted by fee_rate desc
    pub fn select_for_block(
        &self,
        max_count: usize,
        current_height: u64,
    ) -> Vec<&MempoolEntry> {
        let mut age_eligible: Vec<&MempoolEntry> = self.entries
            .values()
            .filter(|e| e.is_age_eligible(current_height))
            .collect();
        age_eligible.sort_by(|a, b| b.fee_rate.cmp(&a.fee_rate));

        let mut remaining: Vec<&MempoolEntry> = self.entries
            .values()
            .filter(|e| !e.is_age_eligible(current_height))
            .collect();
        remaining.sort_by(|a, b| b.fee_rate.cmp(&a.fee_rate));

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
    use indra_core::{
        Bytes32, CommitmentV1, HybridPubKey, ProtocolVersion, VariableBytes,
        types::{
            crypto::HybridSignature,
            primitives::DUST_LIMIT_SPARK,
            transaction::{InputV1, OutputV1, TransactionV1},
        },
    };

    fn dummy_tx(fee: u64, nullifier_byte: u8) -> TransactionV1 {
        TransactionV1 {
            version: ProtocolVersion::CURRENT,
            signature_module_id: 1,
            inputs: vec![InputV1 {
                utxo_id:   Bytes32::from([nullifier_byte; 32]),
                nullifier: Bytes32::from([nullifier_byte; 32]),
            }],
            outputs: vec![OutputV1 {
                value_spark: DUST_LIMIT_SPARK,
                commitment:   CommitmentV1 { compressed_point: Bytes32::ZERO },
                owner_pubkey: HybridPubKey {
                    classical_pk: Bytes32::ZERO,
                    pq_pk: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
                },
                range_proof:  VariableBytes::from_slice(&[0u8; 32]).unwrap(),
                lock_height:  0,
            }],
            fee_amount:     fee,
            fee_blinding:   Bytes32::ZERO,
            fee_commitment: CommitmentV1 { compressed_point: Bytes32::ZERO },
            signature: HybridSignature {
                classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                pq_sig:        VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            },
        }
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
        assert_eq!(mp.submit(tx, 100, 1), Err(ConsensusError::DuplicateTransaction));
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
        let config = MempoolConfig { capacity: 2, min_fee_ratio_bps: 10_000 };
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
    fn evict_invalid_drops_transactions_that_fail_state_validation() {
        let mut mp = Mempool::default_config();
        let tx = dummy_tx(100_000, 0x01);
        let tx_id = mp.submit(tx, 100, 1).unwrap();
        assert!(mp.contains(&tx_id));

        let state = indra_state::ChainState::new_genesis();
        mp.evict_invalid(&state);

        assert!(!mp.contains(&tx_id));
    }
}
