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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use indra_core::{
    codec::Encode,
    types::{
        primitives::{Bytes32, MAX_BLOCK_SIZE_BYTES},
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

/// Maximum aggregate canonical transaction payload retained in memory.
pub const MAX_MEMPOOL_ENCODED_BYTES: usize = 10 * MAX_BLOCK_SIZE_BYTES;

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
    /// Canonical encoded transaction size accounted against the byte cap.
    encoded_size: usize,
    verified: Option<indra_state::pending::VerifiedPendingTransaction>,
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
    total_encoded_bytes: usize,
    max_encoded_bytes: usize,
    by_utxo: BTreeMap<Bytes32, BTreeSet<Bytes32>>,
}

impl Mempool {
    /// Create a new empty mempool with the given configuration.
    pub fn new(config: MempoolConfig) -> Self {
        Self {
            entries: HashMap::new(),
            config,
            total_encoded_bytes: 0,
            max_encoded_bytes: MAX_MEMPOOL_ENCODED_BYTES,
            by_utxo: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    fn new_with_byte_limit(config: MempoolConfig, max_encoded_bytes: usize) -> Self {
        Self {
            entries: HashMap::new(),
            config,
            total_encoded_bytes: 0,
            max_encoded_bytes,
            by_utxo: BTreeMap::new(),
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

    /// Aggregate canonical encoded size of all retained transactions.
    pub fn total_encoded_bytes(&self) -> usize {
        self.total_encoded_bytes
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
    /// Does NOT validate signatures or UTXO existence.
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
        let encoded_size = tx.encoded_len();
        if encoded_size > self.max_encoded_bytes {
            return Err(ConsensusError::MempoolByteLimit {
                limit: self.max_encoded_bytes,
            });
        }
        let weight_kb = (encoded_size as u64).div_ceil(1024);
        let fee_rate = if weight_kb > 0 {
            tx.fee_amount / weight_kb
        } else {
            tx.fee_amount
        };
        let min_fee = current_base_fee.saturating_mul(self.config.min_fee_ratio_bps) / 10_000;
        if fee_rate < min_fee {
            return Err(ConsensusError::FeeTooLow);
        }

        // Admission conflict check. A higher-fee transaction atomically replaces
        // every lower-fee entry that claims one of the same UTXOs.
        // Equal/lower-fee conflicts are rejected so pool contents are independent
        // of hash-map iteration order.
        let input_utxos: HashSet<_> = tx.inputs.iter().map(|input| input.utxo_id).collect();
        let mut conflicts: Vec<(Bytes32, u64)> = self
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry
                    .tx
                    .inputs
                    .iter()
                    .any(|input| input_utxos.contains(&input.utxo_id))
            })
            .map(|(id, entry)| (*id, entry.fee_rate))
            .collect();
        conflicts.sort_by_key(|(id, _)| *id);
        if conflicts
            .iter()
            .any(|(_, existing_rate)| fee_rate <= *existing_rate)
        {
            return Err(ConsensusError::InvalidTransaction {
                reason: "transaction conflicts with equal-or-higher-fee mempool entry",
            });
        }
        let mut evict_ids: HashSet<Bytes32> = conflicts.iter().map(|(id, _)| *id).collect();
        let conflict_bytes = evict_ids
            .iter()
            .filter_map(|id| self.entries.get(id))
            .map(|entry| entry.encoded_size)
            .sum::<usize>();
        let mut prospective_count = self
            .entries
            .len()
            .saturating_sub(evict_ids.len())
            .saturating_add(1);
        let mut prospective_bytes = self
            .total_encoded_bytes
            .saturating_sub(conflict_bytes)
            .saturating_add(encoded_size);

        // Select every additional eviction before mutating the pool. Lowest
        // fee rate loses first; equal rates evict the highest tx_id, matching
        // the established deterministic count-cap ordering.
        let mut eviction_candidates: Vec<_> = self
            .entries
            .iter()
            .filter(|(id, _)| !evict_ids.contains(id))
            .map(|(id, entry)| (*id, entry.fee_rate, entry.encoded_size))
            .collect();
        eviction_candidates.sort_by(|(id_a, rate_a, _), (id_b, rate_b, _)| {
            rate_a.cmp(rate_b).then_with(|| id_b.cmp(id_a))
        });
        let mut candidates = eviction_candidates.into_iter();
        while prospective_count > self.config.capacity || prospective_bytes > self.max_encoded_bytes
        {
            let count_exceeded = prospective_count > self.config.capacity;
            let Some((candidate_id, candidate_rate, candidate_size)) = candidates.next() else {
                return Err(if count_exceeded {
                    ConsensusError::MempoolFull {
                        capacity: self.config.capacity,
                    }
                } else {
                    ConsensusError::MempoolByteLimit {
                        limit: self.max_encoded_bytes,
                    }
                });
            };
            if fee_rate <= candidate_rate {
                return Err(if count_exceeded {
                    ConsensusError::MempoolFull {
                        capacity: self.config.capacity,
                    }
                } else {
                    ConsensusError::MempoolByteLimit {
                        limit: self.max_encoded_bytes,
                    }
                });
            }
            evict_ids.insert(candidate_id);
            prospective_count = prospective_count.saturating_sub(1);
            prospective_bytes = prospective_bytes.saturating_sub(candidate_size);
        }

        for evict_id in evict_ids {
            self.remove_entry(&evict_id);
        }

        self.entries.insert(
            tx_id,
            MempoolEntry {
                tx,
                tx_id,
                arrived_height: current_height,
                fee_rate,
                encoded_size,
                verified: None,
            },
        );
        self.index_entry(tx_id);
        self.total_encoded_bytes = self
            .total_encoded_bytes
            .checked_add(encoded_size)
            .expect("mempool byte accounting overflow");
        self.debug_assert_byte_accounting();

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
        let tx_id = Self::tx_id(&tx);
        let verified = match indra_state::pending::verify_pending_transaction(
            state,
            &tx,
            tx_id,
            state.height.saturating_add(1),
        ) {
            Ok(verified) => verified,
            Err(error) => {
                eprintln!("[mempool] rejected invalid tx {tx_id:?}: {error}");
                return Err(ConsensusError::InvalidTransaction {
                    reason: "state validation failed",
                });
            }
        };
        let inserted_id = self.submit(tx, state.base_fee, state.height)?;
        let entry =
            self.entries
                .get_mut(&inserted_id)
                .ok_or(ConsensusError::InvalidTransaction {
                    reason: "inserted transaction missing from mempool",
                })?;
        entry.verified = Some(verified);
        Ok(inserted_id)
    }

    /// Remove a transaction by ID (called after block inclusion).
    pub fn evict(&mut self, tx_id: &Bytes32) -> Option<MempoolEntry> {
        let removed = self.remove_entry(tx_id);
        self.debug_assert_byte_accounting();
        removed
    }

    /// Eagerly invalidate only entries selected by committed state effects.
    pub fn apply_canonical_effects(
        &mut self,
        state: &indra_state::ChainState,
        effects: &indra_state::CanonicalStateEffects,
    ) {
        let mut affected = BTreeSet::new();
        for id in &effects.spent_utxos {
            affected.extend(self.by_utxo.get(id).into_iter().flatten().copied());
        }
        if effects.base_fee_changed {
            affected.extend(self.entries.keys().copied());
        }

        for tx_id in affected {
            let keep = self.entries.get(&tx_id).is_some_and(|entry| {
                entry.verified.as_ref().is_some_and(|verified| {
                    indra_state::pending::validate_verified_pending_transaction(
                        state,
                        &entry.tx,
                        verified,
                        state.height.saturating_add(1),
                    )
                    .is_ok()
                })
            });
            if !keep {
                eprintln!("[mempool] evicting invalid tx {tx_id:?}");
                self.remove_entry(&tx_id);
            }
        }
        self.debug_assert_indexes();
    }

    /// Remove every pending transaction and reset byte accounting.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.total_encoded_bytes = 0;
        self.by_utxo.clear();
        self.debug_assert_byte_accounting();
    }

    fn remove_entry(&mut self, tx_id: &Bytes32) -> Option<MempoolEntry> {
        let removed = self.entries.remove(tx_id);
        if let Some(entry) = &removed {
            Self::remove_index_memberships(
                &mut self.by_utxo,
                *tx_id,
                entry.tx.inputs.iter().map(|i| i.utxo_id),
            );
            self.total_encoded_bytes = self
                .total_encoded_bytes
                .checked_sub(entry.encoded_size)
                .expect("mempool byte accounting underflow");
        }
        removed
    }

    fn index_entry(&mut self, tx_id: Bytes32) {
        let Some(entry) = self.entries.get(&tx_id) else {
            return;
        };
        for input in &entry.tx.inputs {
            self.by_utxo.entry(input.utxo_id).or_default().insert(tx_id);
        }
        self.debug_assert_indexes();
    }

    fn remove_index_memberships(
        index: &mut BTreeMap<Bytes32, BTreeSet<Bytes32>>,
        entry_id: Bytes32,
        keys: impl Iterator<Item = Bytes32>,
    ) {
        for key in keys {
            if let Some(ids) = index.get_mut(&key) {
                ids.remove(&entry_id);
                if ids.is_empty() {
                    index.remove(&key);
                }
            }
        }
    }

    fn debug_assert_indexes(&self) {
        #[cfg(debug_assertions)]
        {
            let mut utxos = BTreeMap::<Bytes32, BTreeSet<Bytes32>>::new();
            for (id, entry) in &self.entries {
                for input in &entry.tx.inputs {
                    utxos.entry(input.utxo_id).or_default().insert(*id);
                }
            }
            debug_assert_eq!(self.by_utxo, utxos);
        }
    }

    fn debug_assert_byte_accounting(&self) {
        debug_assert_eq!(
            self.total_encoded_bytes,
            self.entries
                .values()
                .map(|entry| entry.encoded_size)
                .sum::<usize>()
        );
        debug_assert!(self.total_encoded_bytes <= self.max_encoded_bytes);
        debug_assert!(self.entries.len() <= self.config.capacity);
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

    /// Check whether a transaction is present.
    pub fn contains(&self, tx_id: &Bytes32) -> bool {
        self.entries.contains_key(tx_id)
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &MempoolEntry> {
        self.entries.values()
    }

    /// Inject an entry for cross-crate adversarial tests that reproduce pools
    /// created by older software before conflict-aware admission existed.
    #[cfg(feature = "test-utils")]
    pub fn insert_unchecked_for_test(&mut self, tx: TransactionV1, submitted_height: u64) {
        let tx_id = tx.tx_hash();
        let encoded_size = tx.encoded_len();
        let weight_kb = (encoded_size as u64).div_ceil(1024);
        let fee_rate = tx.fee_amount / weight_kb.max(1);
        self.remove_entry(&tx_id);
        self.entries.insert(
            tx_id,
            MempoolEntry {
                tx,
                tx_id,
                fee_rate,
                arrived_height: submitted_height,
                encoded_size,
                verified: None,
            },
        );
        self.index_entry(tx_id);
        self.total_encoded_bytes = self
            .total_encoded_bytes
            .checked_add(encoded_size)
            .expect("mempool byte accounting overflow");
        self.debug_assert_byte_accounting();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        types::{
            crypto::HybridSignature,
            primitives::{
                DUST_LIMIT_SPARK, INITIAL_BASE_FEE_SPARK_PER_KB, TRANSACTION_PROTOCOL_VERSION,
            },
            transaction::{InputV1, OutputV1, TransactionV1},
        },
        Bytes32, HybridPubKey, ProtocolVersion, VariableBytes,
    };
    use indra_crypto::{ClassicalKeypair, HybridKeypair, PqKeypair};
    use indra_state::ChainState;

    fn dummy_tx(fee: u64, input_byte: u8) -> TransactionV1 {
        let owner_pubkey = HybridPubKey {
            classical_pk: Bytes32::ZERO,
            pq_pk: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
        };
        TransactionV1 {
            version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
            signature_module_id: 1,
            inputs: vec![InputV1 {
                utxo_id: Bytes32::from([input_byte; 32]),
            }],
            outputs: vec![OutputV1 {
                value_spark: DUST_LIMIT_SPARK,
                owner_pubkey: owner_pubkey.clone(),
                lock_height: 0,
            }],
            fee_amount: fee,
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
        _fixture_tag: [u8; 32],
        owner_pubkey: HybridPubKey,
        _proof_seed: [u8; 32],
    ) -> OutputV1 {
        OutputV1 {
            value_spark: value,
            owner_pubkey,
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
        let input_fixture_tag = [0x11; 32];
        let original_output = output(
            input_value,
            input_fixture_tag,
            owner_pubkey.clone(),
            [0x51; 32],
        );
        let utxo_id = state.utxos.insert(original_output, 0, 0, 0).unwrap();
        let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 10;
        let output_value = input_value - fee;
        let output_fixture_tag = [0x21; 32];
        let mut tx = TransactionV1 {
            version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
            signature_module_id: 1,
            inputs: vec![InputV1 { utxo_id }],
            outputs: vec![output(
                output_value,
                output_fixture_tag,
                owner_pubkey.clone(),
                [0x61; 32],
            )],
            fee_amount: fee,
            signature: HybridSignature {
                classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
            },
        };
        tx.signature = sign_tx(&tx, &owner_keypair, &state.chain_id);
        (state, tx)
    }

    fn assert_byte_accounting(mempool: &Mempool) {
        let canonical_sum = mempool
            .entries
            .values()
            .map(|entry| entry.tx.encoded_len())
            .sum::<usize>();
        let recorded_sum = mempool
            .entries
            .values()
            .map(|entry| entry.encoded_size)
            .sum::<usize>();
        assert_eq!(mempool.total_encoded_bytes(), canonical_sum);
        assert_eq!(mempool.total_encoded_bytes(), recorded_sum);
        assert!(mempool.total_encoded_bytes() <= mempool.max_encoded_bytes);
    }

    #[test]
    fn submit_and_retrieve() {
        let mut mp = Mempool::default_config();
        let tx = dummy_tx(10_000, 0x01);
        let id = mp.submit(tx.clone(), 100, 1).unwrap();
        assert!(mp.contains(&id));
        assert_eq!(mp.len(), 1);
        assert_byte_accounting(&mp);
    }

    #[test]
    fn production_byte_cap_is_ten_maximum_blocks() {
        assert_eq!(MAX_MEMPOOL_ENCODED_BYTES, 125_829_120);
        assert_eq!(MAX_MEMPOOL_ENCODED_BYTES, 10 * MAX_BLOCK_SIZE_BYTES);
    }

    #[test]
    fn zero_capacity_mempool_reliably_rejects_insertion() {
        let mut mempool = Mempool::new(MempoolConfig {
            capacity: 0,
            min_fee_ratio_bps: 10_000,
        });
        assert!(matches!(
            mempool.submit(dummy_tx(10_000, 0x01), 100, 1),
            Err(ConsensusError::MempoolFull { capacity: 0 })
        ));
        assert!(mempool.is_empty());
        assert_eq!(mempool.total_encoded_bytes(), 0);
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
    fn higher_fee_conflict_replaces_lower_fee_entry() {
        let mut mempool = Mempool::default_config();
        let lower = dummy_tx(10_000, 0x31);
        let mut higher = lower.clone();
        higher.fee_amount = 20_000;
        let lower_id = mempool.submit(lower, 100, 1).unwrap();
        let higher_id = mempool.submit(higher, 100, 1).unwrap();

        assert!(!mempool.contains(&lower_id));
        assert!(mempool.contains(&higher_id));
        assert_eq!(mempool.len(), 1);
        assert_byte_accounting(&mempool);
    }

    #[test]
    fn equal_or_lower_fee_conflict_is_rejected() {
        let mut mempool = Mempool::default_config();
        let incumbent = dummy_tx(20_000, 0x32);
        let mut lower = incumbent.clone();
        lower.fee_amount = 10_000;
        let incumbent_id = mempool.submit(incumbent, 100, 1).unwrap();

        assert!(matches!(
            mempool.submit(lower, 100, 1),
            Err(ConsensusError::InvalidTransaction { reason })
                if reason.contains("equal-or-higher-fee")
        ));
        assert!(mempool.contains(&incumbent_id));
        assert_eq!(mempool.len(), 1);
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
        assert_byte_accounting(&mp);
    }

    #[test]
    fn byte_cap_evicts_by_fee_rate_while_count_cap_has_room() {
        let sample_size = dummy_tx(10_000, 0x01).encoded_len();
        let config = MempoolConfig {
            capacity: 10,
            min_fee_ratio_bps: 10_000,
        };
        let mut mempool = Mempool::new_with_byte_limit(config, sample_size * 2);
        let lowest_id = mempool.submit(dummy_tx(10_000, 0x01), 100, 1).unwrap();
        mempool.submit(dummy_tx(20_000, 0x02), 100, 1).unwrap();

        mempool.submit(dummy_tx(30_000, 0x03), 100, 1).unwrap();
        assert_eq!(mempool.len(), 2);
        assert!(!mempool.contains(&lowest_id));
        assert_byte_accounting(&mempool);

        let before_ids: HashSet<_> = mempool.entries.keys().copied().collect();
        let before_bytes = mempool.total_encoded_bytes();
        assert!(matches!(
            mempool.submit(dummy_tx(15_000, 0x04), 100, 1),
            Err(ConsensusError::MempoolByteLimit { .. })
        ));
        assert_eq!(
            mempool.entries.keys().copied().collect::<HashSet<_>>(),
            before_ids
        );
        assert_eq!(mempool.total_encoded_bytes(), before_bytes);
        assert_byte_accounting(&mempool);
    }

    #[test]
    fn transaction_larger_than_byte_cap_is_rejected_without_mutation() {
        let tx = dummy_tx(10_000, 0x05);
        let mut mempool = Mempool::new_with_byte_limit(
            MempoolConfig {
                capacity: 10,
                min_fee_ratio_bps: 10_000,
            },
            tx.encoded_len() - 1,
        );
        assert!(matches!(
            mempool.submit(tx, 100, 1),
            Err(ConsensusError::MempoolByteLimit { .. })
        ));
        assert!(mempool.is_empty());
        assert_byte_accounting(&mempool);
    }

    #[test]
    fn byte_accounting_tracks_commit_and_spent_evictions() {
        let mut mempool = Mempool::default_config();
        let committed = dummy_tx(10_000, 0x11);
        let spent = dummy_tx(20_000, 0x12);
        let retained = dummy_tx(30_000, 0x13);
        let committed_id = mempool.submit(committed, 100, 1).unwrap();
        mempool.submit(spent.clone(), 100, 1).unwrap();
        mempool.submit(retained, 100, 1).unwrap();
        assert_byte_accounting(&mempool);

        mempool.evict(&committed_id);
        assert_byte_accounting(&mempool);

        let mut effects = indra_state::CanonicalStateEffects::default();
        effects.spent_utxos.insert(spent.inputs[0].utxo_id);
        mempool.apply_canonical_effects(&ChainState::new_genesis(), &effects);
        assert_eq!(mempool.len(), 1);
        assert_byte_accounting(&mempool);
    }

    #[test]
    fn byte_accounting_tracks_targeted_invalidation_and_clear() {
        let mut mempool = Mempool::default_config();
        let first = dummy_tx(10_000, 0x21);
        let second = dummy_tx(20_000, 0x22);
        mempool.submit(first.clone(), 100, 1).unwrap();
        mempool.submit(second.clone(), 100, 1).unwrap();
        assert_byte_accounting(&mempool);

        let mut effects = indra_state::CanonicalStateEffects::default();
        effects.spent_utxos.insert(first.inputs[0].utxo_id);
        effects.spent_utxos.insert(second.inputs[0].utxo_id);
        mempool.apply_canonical_effects(&ChainState::new_genesis(), &effects);
        assert!(mempool.is_empty());
        assert_byte_accounting(&mempool);

        mempool.submit(dummy_tx(30_000, 0x23), 100, 1).unwrap();
        assert_byte_accounting(&mempool);
        mempool.clear();
        assert!(mempool.is_empty());
        assert_eq!(mempool.total_encoded_bytes(), 0);
        assert_byte_accounting(&mempool);
    }

    #[test]
    fn byte_accounting_remains_exact_across_combined_mutations() {
        let sample_size = dummy_tx(10_000, 0x31).encoded_len();
        let config = MempoolConfig {
            capacity: 3,
            min_fee_ratio_bps: 10_000,
        };
        let mut mempool = Mempool::new_with_byte_limit(config, sample_size * 2);
        let conflict_low = dummy_tx(10_000, 0x31);
        let mut conflict_high = conflict_low.clone();
        conflict_high.fee_amount = 40_000;
        mempool.submit(conflict_low, 100, 1).unwrap();
        mempool.submit(dummy_tx(20_000, 0x32), 100, 1).unwrap();
        assert_byte_accounting(&mempool);

        let replacement_id = mempool.submit(conflict_high, 100, 1).unwrap();
        assert_byte_accounting(&mempool);
        mempool.submit(dummy_tx(50_000, 0x33), 100, 1).unwrap();
        assert_eq!(mempool.len(), 2);
        assert_byte_accounting(&mempool);

        mempool.evict(&replacement_id);
        assert_byte_accounting(&mempool);
        mempool.submit(dummy_tx(60_000, 0x34), 100, 1).unwrap();
        assert_byte_accounting(&mempool);
        mempool.clear();
        assert_byte_accounting(&mempool);
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
    fn targeted_invalidation_drops_affected_unverified_test_entry() {
        let mut mp = Mempool::default_config();
        let tx = dummy_tx(100_000, 0x01);
        let tx_id = mp.submit(tx, 100, 1).unwrap();
        assert!(mp.contains(&tx_id));

        let state = indra_state::ChainState::new_genesis();
        let mut effects = indra_state::CanonicalStateEffects::default();
        effects
            .spent_utxos
            .insert(mp.entries.get(&tx_id).unwrap().tx.inputs[0].utxo_id);
        mp.apply_canonical_effects(&state, &effects);

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

    #[test]
    fn targeted_transaction_invalidation_matches_full_oracle_and_leaves_untouched_valid() {
        let (mut state, tx) = valid_state_and_tx();
        let tx_id = Mempool::tx_id(&tx);
        let mut targeted = Mempool::default_config();
        targeted.submit_validated(tx.clone(), &state).unwrap();

        let unrelated = indra_state::CanonicalStateEffects {
            validators_changed: BTreeSet::from([Bytes32::from([0xEE; 32])]),
            ..Default::default()
        };
        targeted.apply_canonical_effects(&state, &unrelated);
        assert!(targeted.contains(&tx_id));
        let mut inputs = HashSet::new();
        assert!(indra_state::apply::validate_transaction(
            &state,
            &tx,
            &state.chain_id,
            &mut inputs,
            state.height.saturating_add(1),
        )
        .is_ok());

        let input = &tx.inputs[0];
        state.utxos.spend_at_height(&input.utxo_id, 1).unwrap();
        let mut effects = indra_state::CanonicalStateEffects::default();
        effects.spent_utxos.insert(input.utxo_id);
        targeted.apply_canonical_effects(&state, &effects);

        let mut inputs = HashSet::new();
        assert!(indra_state::apply::validate_transaction(
            &state,
            &tx,
            &state.chain_id,
            &mut inputs,
            state.height.saturating_add(1),
        )
        .is_err());
        assert!(!targeted.contains(&tx_id));
    }
}
