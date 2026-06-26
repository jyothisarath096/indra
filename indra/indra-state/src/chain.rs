//! ChainState — the complete state of the INDRA chain at a point in time.
//!
//! This is everything a node needs to validate the next block.
//! It is the input and output of `apply_block`.

use indra_core::codec::{ByteReader, Decode, Encode};
use indra_core::error::IndraResult;

use std::collections::{BTreeMap, HashSet};

use indra_core::types::primitives::{
    Bytes32, VariableBytes, DEFAULT_CHAIN_ID, GENESIS_SUPPLY_SPARK, INITIAL_BASE_FEE_SPARK_PER_KB,
    MAX_CHAIN_ID_BYTES,
};

use crate::{
    governance::GovernanceState,
    nullifier::NullifierSet,
    utxo::UtxoSet,
    validator::{DelegationMap, StakeBondEntry, ValidatorSet},
};

/// The complete chain state at a given block height.
///
/// Two `ChainState` values are equivalent if and only if they represent
/// the same chain history. The `state_root` field (once implemented in
/// Phase 5) will be a cryptographic commitment to this entire structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainState {
    /// Chain identifier loaded from genesis and included in consensus-visible state.
    pub chain_id: String,

    /// Height of the most recently applied block (0 = genesis, before block 1).
    pub height: u64,

    /// Hash of the most recently applied block header.
    /// All-zero at genesis (no block has been applied yet).
    pub tip_hash: Bytes32,

    /// Current base fee in Spark/KB.
    /// Set to INITIAL_BASE_FEE at genesis, updated after each block.
    pub base_fee: u64,

    /// Total supply of Spark in existence (minted - burned).
    pub total_supply: u64,

    /// Treasury balance in Spark.
    pub treasury_balance: u64,

    /// Burn buffer balance in Spark (pending governance-directed burns).
    pub burn_buffer: u64,

    /// Accumulated validator fee rewards awaiting epoch distribution.
    pub fee_reward_pool: u64,

    /// All unspent transaction outputs.
    pub utxos: UtxoSet,

    /// All spent nullifiers (double-spend guard).
    pub nullifiers: NullifierSet,

    /// Current validator set.
    pub validators: ValidatorSet,

    /// Delegation map: validator_id → delegator entries.
    pub delegations: DelegationMap,

    /// Stake bonds: UTXOs locked as delegation stake.
    pub staked_bonds: BTreeMap<Bytes32, StakeBondEntry>,

    /// Monotonic nonces for staking op replay protection.
    pub staking_nonces: BTreeMap<Bytes32, u64>,

    /// Hashes of applied slash evidence — prevents double-slash.
    /// Key: SHA-256(encode(SlashEvidenceV1))
    pub applied_slash_hashes: HashSet<Bytes32>,

    /// On-chain governance state.
    pub governance: GovernanceState,

    /// Transient fee burns accumulated for the current epoch summary.
    /// Not encoded and not included in consensus state roots.
    pub epoch_fees_burned: u64,

    /// Transient slash total accumulated for the current epoch summary.
    /// Not encoded and not included in consensus state roots.
    pub epoch_slashed_spark: u64,

    /// Transient slash event count accumulated for the current epoch summary.
    /// Not encoded and not included in consensus state roots.
    pub epoch_slash_event_count: u32,
}

impl Encode for ChainState {
    fn encode(&self, buf: &mut Vec<u8>) {
        // Included: transaction signing and state-root computation depend on the configured chain.
        VariableBytes::<MAX_CHAIN_ID_BYTES>::from_slice(self.chain_id.as_bytes())
            .unwrap_or_default()
            .encode(buf);
        // Included: the applied height determines the next valid block height.
        self.height.encode(buf);
        // Included: the next block must chain to the exact committed tip hash.
        self.tip_hash.encode(buf);
        // Included: fee validation for the next block depends on the current base fee.
        self.base_fee.encode(buf);
        // Included: block value hashing and supply accounting depend on total supply.
        self.total_supply.encode(buf);
        // Included: treasury accounting is part of consensus state and affects rewards.
        self.treasury_balance.encode(buf);
        // Included: burn-buffer accounting is consensus-visible and must survive restart.
        self.burn_buffer.encode(buf);
        // Included: pending fee rewards affect future epoch distribution.
        self.fee_reward_pool.encode(buf);
        // Included: the full UTXO set is required to validate spends after restart.
        self.utxos.encode(buf);
        // Included: nullifiers are the double-spend guard and cannot be reconstructed from summaries.
        self.nullifiers.encode(buf);
        // Included: validator metadata is needed for proposer election and signature/QC verification.
        self.validators.encode(buf);
        // Included: delegations affect validator power and epoch transitions.
        self.delegations.encode(buf);
        // Included: stake bonds lock UTXOs and drive delegation/unbonding state.
        encode_bond_map(&self.staked_bonds, buf);
        encode_nonce_map(&self.staking_nonces, buf);
        encode_hash_set(&self.applied_slash_hashes, buf);
        self.governance.encode(buf);
        // Omitted: transient epoch summary counters and nested SMT caches are intentionally
        // reconstructed/reset by decoders from the serialized canonical entries.
    }

    fn encoded_len(&self) -> usize {
        VariableBytes::<MAX_CHAIN_ID_BYTES>::from_slice(self.chain_id.as_bytes())
            .unwrap_or_default()
            .encoded_len()
            + self.height.encoded_len()
            + self.tip_hash.encoded_len()
            + self.base_fee.encoded_len()
            + self.total_supply.encoded_len()
            + self.treasury_balance.encoded_len()
            + self.burn_buffer.encoded_len()
            + self.fee_reward_pool.encoded_len()
            + self.utxos.encoded_len()
            + self.nullifiers.encoded_len()
            + self.validators.encoded_len()
            + self.delegations.encoded_len()
            + bond_map_encoded_len(&self.staked_bonds)
            + nonce_map_encoded_len(&self.staking_nonces)
            + hash_set_encoded_len(&self.applied_slash_hashes)
            + self.governance.encoded_len()
    }
}

impl Decode for ChainState {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let chain_id_bytes = VariableBytes::<MAX_CHAIN_ID_BYTES>::decode(r)?;
        Ok(Self {
            chain_id: String::from_utf8(chain_id_bytes.as_slice().to_vec())
                .unwrap_or_else(|_| DEFAULT_CHAIN_ID.to_string()),
            height: u64::decode(r)?,
            tip_hash: Bytes32::decode(r)?,
            base_fee: u64::decode(r)?,
            total_supply: u64::decode(r)?,
            treasury_balance: u64::decode(r)?,
            burn_buffer: u64::decode(r)?,
            fee_reward_pool: u64::decode(r)?,
            utxos: UtxoSet::decode(r)?,
            nullifiers: NullifierSet::decode(r)?,
            validators: ValidatorSet::decode(r)?,
            delegations: DelegationMap::decode(r)?,
            staked_bonds: decode_bond_map(r)?,
            staking_nonces: decode_nonce_map(r)?,
            applied_slash_hashes: decode_hash_set(r, "snapshot.applied_slash_hashes")?,
            governance: GovernanceState::decode(r)?,
            epoch_fees_burned: 0,
            epoch_slashed_spark: 0,
            epoch_slash_event_count: 0,
        })
    }
}

impl ChainState {
    /// Create the genesis state (before any block has been applied).
    ///
    /// This is the canonical starting point for every INDRA node.
    pub fn new_genesis() -> Self {
        Self {
            chain_id: DEFAULT_CHAIN_ID.to_string(),
            height: 0,
            tip_hash: Bytes32::ZERO,
            base_fee: INITIAL_BASE_FEE_SPARK_PER_KB,
            total_supply: GENESIS_SUPPLY_SPARK,
            treasury_balance: 0,
            burn_buffer: 0,
            fee_reward_pool: 0,
            utxos: UtxoSet::new(),
            nullifiers: NullifierSet::new(),
            validators: ValidatorSet::new(),
            delegations: DelegationMap::new(),
            staked_bonds: BTreeMap::new(),
            staking_nonces: BTreeMap::new(),
            applied_slash_hashes: HashSet::new(),
            governance: GovernanceState::new(),
            epoch_fees_burned: 0,
            epoch_slashed_spark: 0,
            epoch_slash_event_count: 0,
        }
    }

    /// Decode a legacy unversioned snapshot payload at the supplied schema version.
    pub fn decode_legacy_snapshot(r: &mut ByteReader<'_>, schema_version: u8) -> IndraResult<Self> {
        let chain_id_bytes = VariableBytes::<MAX_CHAIN_ID_BYTES>::decode(r)?;
        Ok(Self {
            chain_id: String::from_utf8(chain_id_bytes.as_slice().to_vec())
                .unwrap_or_else(|_| DEFAULT_CHAIN_ID.to_string()),
            height: u64::decode(r)?,
            tip_hash: Bytes32::decode(r)?,
            base_fee: u64::decode(r)?,
            total_supply: u64::decode(r)?,
            treasury_balance: u64::decode(r)?,
            burn_buffer: u64::decode(r)?,
            fee_reward_pool: u64::decode(r)?,
            utxos: UtxoSet::decode_legacy(r)?,
            nullifiers: NullifierSet::decode(r)?,
            validators: ValidatorSet::decode_legacy(r, schema_version)?,
            delegations: DelegationMap::decode_legacy(r)?,
            staked_bonds: decode_bond_map_legacy(r)?,
            staking_nonces: decode_nonce_map(r)?,
            applied_slash_hashes: if r.remaining() > 0 {
                decode_hash_set(r, "snapshot.applied_slash_hashes")?
            } else {
                HashSet::new()
            },
            governance: GovernanceState::new(),
            epoch_fees_burned: 0,
            epoch_slashed_spark: 0,
            epoch_slash_event_count: 0,
        })
    }

    /// Decode a schema-v2 versioned snapshot payload that predates governance.
    pub fn decode_schema_v2_snapshot(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let chain_id_bytes = VariableBytes::<MAX_CHAIN_ID_BYTES>::decode(r)?;
        Ok(Self {
            chain_id: String::from_utf8(chain_id_bytes.as_slice().to_vec())
                .unwrap_or_else(|_| DEFAULT_CHAIN_ID.to_string()),
            height: u64::decode(r)?,
            tip_hash: Bytes32::decode(r)?,
            base_fee: u64::decode(r)?,
            total_supply: u64::decode(r)?,
            treasury_balance: u64::decode(r)?,
            burn_buffer: u64::decode(r)?,
            fee_reward_pool: u64::decode(r)?,
            utxos: UtxoSet::decode(r)?,
            nullifiers: NullifierSet::decode(r)?,
            validators: ValidatorSet::decode(r)?,
            delegations: DelegationMap::decode(r)?,
            staked_bonds: decode_bond_map(r)?,
            staking_nonces: decode_nonce_map(r)?,
            applied_slash_hashes: decode_hash_set(r, "snapshot.applied_slash_hashes")?,
            governance: GovernanceState::new(),
            epoch_fees_burned: 0,
            epoch_slashed_spark: 0,
            epoch_slash_event_count: 0,
        })
    }

    /// Current epoch number (0-indexed).
    pub fn current_epoch(&self) -> u64 {
        crate::epoch::epoch_for_height(self.height)
    }

    /// True if the chain has had at least one block applied.
    pub fn has_blocks(&self) -> bool {
        self.height > 0
    }
}

fn encode_hash_set(hashes: &HashSet<Bytes32>, buf: &mut Vec<u8>) {
    let mut entries: Vec<_> = hashes.iter().copied().collect();
    entries.sort_by_key(|hash| hash.0);
    (entries.len() as u32).encode(buf);
    for hash in entries {
        hash.encode(buf);
    }
}

fn hash_set_encoded_len(hashes: &HashSet<Bytes32>) -> usize {
    4 + hashes.len() * 32
}

fn decode_hash_set(r: &mut ByteReader<'_>, field: &'static str) -> IndraResult<HashSet<Bytes32>> {
    use indra_core::error::IndraError;
    use indra_core::types::primitives::MAX_SLASHES_PER_BLOCK;

    let count = u32::decode(r)? as usize;
    let max = MAX_SLASHES_PER_BLOCK.saturating_mul(10_000);
    if count > max {
        return Err(IndraError::LengthExceeded {
            field,
            max,
            actual: count,
        });
    }
    let mut hashes = HashSet::with_capacity(count);
    for _ in 0..count {
        let hash = Bytes32::decode(r)?;
        if !hashes.insert(hash) {
            return Err(IndraError::DuplicateEntries { field });
        }
    }
    Ok(hashes)
}

fn encode_bond_map(bonds: &BTreeMap<Bytes32, StakeBondEntry>, buf: &mut Vec<u8>) {
    (bonds.len() as u32).encode(buf);
    for (utxo_id, bond) in bonds {
        utxo_id.encode(buf);
        bond.encode(buf);
    }
}

fn bond_map_encoded_len(bonds: &BTreeMap<Bytes32, StakeBondEntry>) -> usize {
    4 + bonds
        .iter()
        .map(|(utxo_id, bond)| utxo_id.encoded_len() + bond.encoded_len())
        .sum::<usize>()
}

fn decode_bond_map(r: &mut ByteReader<'_>) -> IndraResult<BTreeMap<Bytes32, StakeBondEntry>> {
    use indra_core::error::IndraError;
    use indra_core::types::primitives::MAX_VALIDATORS;

    let count = u32::decode(r)? as usize;
    let max = MAX_VALIDATORS.saturating_mul(1_000);
    if count > max {
        return Err(IndraError::LengthExceeded {
            field: "snapshot.staked_bonds",
            max,
            actual: count,
        });
    }
    let mut bonds = BTreeMap::new();
    for _ in 0..count {
        let key = Bytes32::decode(r)?;
        let bond = StakeBondEntry::decode(r)?;
        if key != bond.utxo_id {
            return Err(IndraError::InvariantViolation {
                message: "stake bond map key must match bond utxo_id",
            });
        }
        if bonds.insert(key, bond).is_some() {
            return Err(IndraError::DuplicateEntries {
                field: "snapshot.staked_bonds",
            });
        }
    }
    Ok(bonds)
}

fn decode_bond_map_legacy(
    r: &mut ByteReader<'_>,
) -> IndraResult<BTreeMap<Bytes32, StakeBondEntry>> {
    use indra_core::error::IndraError;
    use indra_core::types::primitives::MAX_VALIDATORS;

    let count = u32::decode(r)? as usize;
    let max = MAX_VALIDATORS.saturating_mul(1_000);
    if count > max {
        return Err(IndraError::LengthExceeded {
            field: "snapshot.staked_bonds",
            max,
            actual: count,
        });
    }
    let mut bonds = BTreeMap::new();
    for _ in 0..count {
        let key = Bytes32::decode(r)?;
        let bond = StakeBondEntry::decode_legacy(r)?;
        if key != bond.utxo_id {
            return Err(IndraError::InvariantViolation {
                message: "stake bond map key must match bond utxo_id",
            });
        }
        if bonds.insert(key, bond).is_some() {
            return Err(IndraError::DuplicateEntries {
                field: "snapshot.staked_bonds",
            });
        }
    }
    Ok(bonds)
}

fn encode_nonce_map(nonces: &BTreeMap<Bytes32, u64>, buf: &mut Vec<u8>) {
    (nonces.len() as u32).encode(buf);
    for (signer_id, nonce) in nonces {
        signer_id.encode(buf);
        nonce.encode(buf);
    }
}

fn nonce_map_encoded_len(nonces: &BTreeMap<Bytes32, u64>) -> usize {
    4 + nonces.len() * (32 + 8)
}

fn decode_nonce_map(r: &mut ByteReader<'_>) -> IndraResult<BTreeMap<Bytes32, u64>> {
    use indra_core::error::IndraError;
    use indra_core::types::primitives::MAX_VALIDATORS;

    let count = u32::decode(r)? as usize;
    let max = MAX_VALIDATORS.saturating_mul(100);
    if count > max {
        return Err(IndraError::LengthExceeded {
            field: "snapshot.staking_nonces",
            max,
            actual: count,
        });
    }
    let mut nonces = BTreeMap::new();
    for _ in 0..count {
        let signer_id = Bytes32::decode(r)?;
        let nonce = u64::decode(r)?;
        if nonces.insert(signer_id, nonce).is_some() {
            return Err(IndraError::DuplicateEntries {
                field: "snapshot.staking_nonces",
            });
        }
    }
    Ok(nonces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::primitives::{GENESIS_SUPPLY_SPARK, INITIAL_BASE_FEE_SPARK_PER_KB};

    #[test]
    fn genesis_state_is_correct() {
        let state = ChainState::new_genesis();
        assert_eq!(state.height, 0);
        assert_eq!(state.chain_id, DEFAULT_CHAIN_ID);
        assert_eq!(state.tip_hash, Bytes32::ZERO);
        assert_eq!(state.base_fee, INITIAL_BASE_FEE_SPARK_PER_KB);
        assert_eq!(state.total_supply, GENESIS_SUPPLY_SPARK);
        assert_eq!(state.treasury_balance, 0);
        assert_eq!(state.fee_reward_pool, 0);
        assert!(state.utxos.is_empty());
        assert!(state.nullifiers.is_empty());
        assert!(state.validators.is_empty());
    }

    #[test]
    fn genesis_has_no_blocks() {
        assert!(!ChainState::new_genesis().has_blocks());
    }

    #[test]
    fn genesis_epoch_is_zero() {
        assert_eq!(ChainState::new_genesis().current_epoch(), 0);
    }
}
