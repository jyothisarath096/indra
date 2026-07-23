//! ChainState — the complete state of the INDRA chain at a point in time.
//!
//! This is everything a node needs to validate the next block.
//! It is the input and output of `apply_block`.

use indra_core::codec::{ByteReader, Decode, Encode};
use indra_core::error::{IndraError, IndraResult};
use indra_core::types::crypto::HybridPubKey;
use indra_crypto::PaymentPubKeyV1;

use indra_core::types::primitives::{
    state_commitment_v2_active, Bytes32, VariableBytes, DEFAULT_CHAIN_ID, GENESIS_SUPPLY_SPARK,
    INITIAL_BASE_FEE_SPARK_PER_KB, MAX_CHAIN_ID_BYTES, MAX_DELEGATION_RETURN_EVENTS,
};

use crate::{
    governance::GovernanceState,
    nullifier::NullifierSet,
    persistent::{PersistentOrdMap, PersistentOrdSet},
    state_commitment::StateCommitmentV2,
    utxo::UtxoSet,
    validator::{
        decode_delegation_return_events, delegation_return_events_encoded_len,
        encode_delegation_return_events, DelegationMap, DelegationReturnEvent, StakeBondEntry,
        ValidatorSet,
    },
};

/// Defensive snapshot decode ceiling for staked-bond entries.
///
/// This must not be lower than the validator/delegator state that the protocol
/// itself can accept: every retained delegator position may have at least one
/// corresponding bonded UTXO. The guard remains finite so corrupted snapshots
/// cannot request unbounded decode work.
pub const MAX_STAKED_BONDS_DECODE: usize = indra_core::types::primitives::MAX_VALIDATORS
    .saturating_mul(crate::validator::MAX_DELEGATORS_PER_VALIDATOR);

/// Defensive snapshot decode ceiling for staking nonce entries.
///
/// Staking nonces are keyed by staking signer identity: validator identities
/// for validator-owned ops and delegator identities for delegation-owned ops.
/// This guard must therefore cover the largest current validator/delegator
/// identity set the protocol can retain, not only validators.
pub const MAX_STAKING_NONCES_DECODE: usize = indra_core::types::primitives::MAX_VALIDATORS
    .saturating_add(
        indra_core::types::primitives::MAX_VALIDATORS
            .saturating_mul(crate::validator::MAX_DELEGATORS_PER_VALIDATOR),
    );

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

    /// Accumulated block reward dust from proportional distribution rounding.
    ///
    /// This balance has no spend path and is effectively locked. Reporter slash
    /// rewards are not routed here; they are paid directly to the reporting
    /// block proposer as spendable UTXOs. Future cleanup: burn reward dust
    /// directly and remove treasury accounting entirely.
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
    pub staked_bonds: PersistentOrdMap<Bytes32, StakeBondEntry>,

    /// Monotonic nonces for staking op replay protection.
    pub staking_nonces: PersistentOrdMap<Bytes32, u64>,

    /// Canonical full public key for each post-activation delegator identity.
    pub delegator_identities: PersistentOrdMap<Bytes32, HybridPubKey>,

    /// Canonical payment key-exchange public key for each payment owner identity.
    pub payment_identities: PersistentOrdMap<Bytes32, PaymentPubKeyV1>,

    /// Hashes of applied slash evidence — prevents double-slash.
    /// Key: SHA-256(encode(SlashEvidenceV1))
    pub applied_slash_hashes: PersistentOrdSet<Bytes32>,

    /// On-chain governance state.
    pub governance: GovernanceState,

    /// Bounded rolling log of automatic delegation principal returns.
    ///
    /// This is consensus-visible after the registered-validator-cap activation
    /// so delegators can discover forced returns caused by validator eviction.
    pub delegation_return_events: Vec<DelegationReturnEvent>,

    /// Derived, non-authoritative StateCommitmentV2 cache.
    ///
    /// This is intentionally not encoded in snapshots. Canonical maps above
    /// remain the only persisted consensus state; the cache is rebuilt from
    /// them on decode/startup or before the first post-activation mutation.
    /// This task does not solve three separate scale costs: full-state clone
    /// during projected block application, linear per-validator delegation Vec
    /// lookup, or the O(touched delegators) reward distribution pass.
    pub state_commitment_v2: Option<StateCommitmentV2>,

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
        encode_delegation_return_events(&self.delegation_return_events, buf);
        if !self.delegator_identities.is_empty() || !self.payment_identities.is_empty() {
            encode_delegator_identity_registry(&self.delegator_identities, buf);
        }
        if !self.payment_identities.is_empty() {
            encode_payment_identity_registry(&self.payment_identities, buf);
        }
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
            + delegation_return_events_encoded_len(&self.delegation_return_events)
            + if self.delegator_identities.is_empty() && self.payment_identities.is_empty() {
                0
            } else {
                delegator_identity_registry_encoded_len(&self.delegator_identities)
            }
            + if self.payment_identities.is_empty() {
                0
            } else {
                payment_identity_registry_encoded_len(&self.payment_identities)
            }
    }
}

impl Decode for ChainState {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let chain_id_bytes = VariableBytes::<MAX_CHAIN_ID_BYTES>::decode(r)?;
        let chain_id = String::from_utf8(chain_id_bytes.as_slice().to_vec())
            .unwrap_or_else(|_| DEFAULT_CHAIN_ID.to_string());
        let height = u64::decode(r)?;
        let tip_hash = Bytes32::decode(r)?;
        let base_fee = u64::decode(r)?;
        let total_supply = u64::decode(r)?;
        let treasury_balance = u64::decode(r)?;
        let burn_buffer = u64::decode(r)?;
        let fee_reward_pool = u64::decode(r)?;
        let utxos = UtxoSet::decode_at_height(r, height)?;
        let nullifiers = NullifierSet::decode_at_height(r, height)?;
        let validators = ValidatorSet::decode(r)?;
        let delegations = DelegationMap::decode(r)?;
        let staked_bonds = decode_bond_map(r)?;
        let staking_nonces = decode_nonce_map(r)?;
        let applied_slash_hashes = decode_hash_set(r, "snapshot.applied_slash_hashes")?;
        let governance = GovernanceState::decode(r)?;
        let delegation_return_events = if r.remaining() > 0 {
            decode_delegation_return_events(r)?
        } else {
            Vec::new()
        };
        let delegator_identities = if r.remaining() > 0 {
            decode_delegator_identity_registry(r)?
        } else {
            PersistentOrdMap::new()
        };
        let payment_identities = if r.remaining() > 0 {
            decode_payment_identity_registry(r)?
        } else {
            PersistentOrdMap::new()
        };
        Ok(Self {
            chain_id,
            height,
            tip_hash,
            base_fee,
            total_supply,
            treasury_balance,
            burn_buffer,
            fee_reward_pool,
            utxos,
            nullifiers,
            validators,
            delegations,
            staked_bonds,
            staking_nonces,
            delegator_identities,
            payment_identities,
            applied_slash_hashes,
            governance,
            delegation_return_events,
            state_commitment_v2: None,
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
            staked_bonds: PersistentOrdMap::new(),
            staking_nonces: PersistentOrdMap::new(),
            delegator_identities: PersistentOrdMap::new(),
            payment_identities: PersistentOrdMap::new(),
            applied_slash_hashes: PersistentOrdSet::new(),
            governance: GovernanceState::new(),
            delegation_return_events: Vec::new(),
            state_commitment_v2: None,
            epoch_fees_burned: 0,
            epoch_slashed_spark: 0,
            epoch_slash_event_count: 0,
        }
    }

    /// Decode a legacy unversioned snapshot payload at the supplied schema version.
    pub fn decode_legacy_snapshot(r: &mut ByteReader<'_>, schema_version: u8) -> IndraResult<Self> {
        let chain_id_bytes = VariableBytes::<MAX_CHAIN_ID_BYTES>::decode(r)?;
        let chain_id = String::from_utf8(chain_id_bytes.as_slice().to_vec())
            .unwrap_or_else(|_| DEFAULT_CHAIN_ID.to_string());
        let height = u64::decode(r)?;
        Ok(Self {
            chain_id,
            height,
            tip_hash: Bytes32::decode(r)?,
            base_fee: u64::decode(r)?,
            total_supply: u64::decode(r)?,
            treasury_balance: u64::decode(r)?,
            burn_buffer: u64::decode(r)?,
            fee_reward_pool: u64::decode(r)?,
            utxos: UtxoSet::decode_legacy_at_height(r, height)?,
            nullifiers: NullifierSet::decode_at_height(r, height)?,
            validators: ValidatorSet::decode_legacy(r, schema_version)?,
            delegations: DelegationMap::decode_legacy(r)?,
            staked_bonds: decode_bond_map_legacy(r)?,
            staking_nonces: decode_nonce_map(r)?,
            delegator_identities: PersistentOrdMap::new(),
            payment_identities: PersistentOrdMap::new(),
            applied_slash_hashes: if r.remaining() > 0 {
                decode_hash_set(r, "snapshot.applied_slash_hashes")?
            } else {
                PersistentOrdSet::new()
            },
            governance: GovernanceState::new(),
            delegation_return_events: Vec::new(),
            state_commitment_v2: None,
            epoch_fees_burned: 0,
            epoch_slashed_spark: 0,
            epoch_slash_event_count: 0,
        })
    }

    /// Decode a schema-v2 versioned snapshot payload that predates governance.
    pub fn decode_schema_v2_snapshot(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let chain_id_bytes = VariableBytes::<MAX_CHAIN_ID_BYTES>::decode(r)?;
        let chain_id = String::from_utf8(chain_id_bytes.as_slice().to_vec())
            .unwrap_or_else(|_| DEFAULT_CHAIN_ID.to_string());
        let height = u64::decode(r)?;
        Ok(Self {
            chain_id,
            height,
            tip_hash: Bytes32::decode(r)?,
            base_fee: u64::decode(r)?,
            total_supply: u64::decode(r)?,
            treasury_balance: u64::decode(r)?,
            burn_buffer: u64::decode(r)?,
            fee_reward_pool: u64::decode(r)?,
            utxos: UtxoSet::decode_at_height(r, height)?,
            nullifiers: NullifierSet::decode_at_height(r, height)?,
            validators: ValidatorSet::decode(r)?,
            delegations: DelegationMap::decode(r)?,
            staked_bonds: decode_bond_map(r)?,
            staking_nonces: decode_nonce_map(r)?,
            delegator_identities: PersistentOrdMap::new(),
            payment_identities: PersistentOrdMap::new(),
            applied_slash_hashes: decode_hash_set(r, "snapshot.applied_slash_hashes")?,
            governance: GovernanceState::new(),
            delegation_return_events: Vec::new(),
            state_commitment_v2: None,
            epoch_fees_burned: 0,
            epoch_slashed_spark: 0,
            epoch_slash_event_count: 0,
        })
    }

    /// Ensure the derived StateCommitmentV2 cache exists when the V2 root rule
    /// is active at `height`.
    pub fn ensure_state_commitment_v2(&mut self, height: u64) {
        if state_commitment_v2_active(height) && self.state_commitment_v2.is_none() {
            self.state_commitment_v2 = Some(StateCommitmentV2::from_state(self, height));
        }
    }

    /// Rebuild the derived StateCommitmentV2 cache from canonical state.
    pub fn rebuild_state_commitment_v2(&mut self, height: u64) {
        self.state_commitment_v2 = Some(StateCommitmentV2::from_state(self, height));
    }

    /// Return the StateCommitmentV2 root, rebuilding from canonical state if
    /// this decoded/restarted state does not yet have a warm cache.
    pub fn state_commitment_v2_root(&self, height: u64) -> Bytes32 {
        self.state_commitment_v2
            .as_ref()
            .map(StateCommitmentV2::root)
            .unwrap_or_else(|| StateCommitmentV2::from_state(self, height).root())
    }

    /// Current epoch number (0-indexed).
    pub fn current_epoch(&self) -> u64 {
        crate::epoch::epoch_for_height(self.height)
    }

    /// True if the chain has had at least one block applied.
    pub fn has_blocks(&self) -> bool {
        self.height > 0
    }

    /// Append a delegation-return event and prune the oldest entries if the
    /// fixed global retention bound is exceeded.
    pub fn push_delegation_return_event(&mut self, event: DelegationReturnEvent) {
        if let Some(commitment) = self.state_commitment_v2.as_mut() {
            commitment.put_delegation_return_event(&event);
        }
        self.delegation_return_events.push(event);
        let excess = self
            .delegation_return_events
            .len()
            .saturating_sub(MAX_DELEGATION_RETURN_EVENTS);
        if excess > 0 {
            let removed: Vec<_> = self.delegation_return_events.drain(0..excess).collect();
            if let Some(commitment) = self.state_commitment_v2.as_mut() {
                for event in &removed {
                    commitment.delete_delegation_return_event(event);
                }
            }
        }
    }
}

fn encode_hash_set(hashes: &PersistentOrdSet<Bytes32>, buf: &mut Vec<u8>) {
    (hashes.len() as u32).encode(buf);
    for hash in hashes {
        hash.encode(buf);
    }
}

fn hash_set_encoded_len(hashes: &PersistentOrdSet<Bytes32>) -> usize {
    4 + hashes.len() * 32
}

fn decode_hash_set(
    r: &mut ByteReader<'_>,
    field: &'static str,
) -> IndraResult<PersistentOrdSet<Bytes32>> {
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
    let mut hashes = PersistentOrdSet::new();
    for _ in 0..count {
        let hash = Bytes32::decode(r)?;
        if !hashes.insert(hash) {
            return Err(IndraError::DuplicateEntries { field });
        }
    }
    Ok(hashes)
}

fn encode_bond_map(bonds: &PersistentOrdMap<Bytes32, StakeBondEntry>, buf: &mut Vec<u8>) {
    (bonds.len() as u32).encode(buf);
    for (utxo_id, bond) in bonds {
        utxo_id.encode(buf);
        bond.encode(buf);
    }
}

fn bond_map_encoded_len(bonds: &PersistentOrdMap<Bytes32, StakeBondEntry>) -> usize {
    4 + bonds
        .iter()
        .map(|(utxo_id, bond)| utxo_id.encoded_len() + bond.encoded_len())
        .sum::<usize>()
}

fn decode_bond_map(
    r: &mut ByteReader<'_>,
) -> IndraResult<PersistentOrdMap<Bytes32, StakeBondEntry>> {
    let count = u32::decode(r)? as usize;
    validate_bond_map_count(count)?;
    let mut bonds = PersistentOrdMap::new();
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
) -> IndraResult<PersistentOrdMap<Bytes32, StakeBondEntry>> {
    let count = u32::decode(r)? as usize;
    validate_bond_map_count(count)?;
    let mut bonds = PersistentOrdMap::new();
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

fn validate_bond_map_count(count: usize) -> IndraResult<()> {
    use indra_core::error::IndraError;

    if count > MAX_STAKED_BONDS_DECODE {
        return Err(IndraError::LengthExceeded {
            field: "snapshot.staked_bonds",
            max: MAX_STAKED_BONDS_DECODE,
            actual: count,
        });
    }
    Ok(())
}

fn encode_nonce_map(nonces: &PersistentOrdMap<Bytes32, u64>, buf: &mut Vec<u8>) {
    (nonces.len() as u32).encode(buf);
    for (signer_id, nonce) in nonces {
        signer_id.encode(buf);
        nonce.encode(buf);
    }
}

fn nonce_map_encoded_len(nonces: &PersistentOrdMap<Bytes32, u64>) -> usize {
    4 + nonces.len() * (32 + 8)
}

fn decode_nonce_map(r: &mut ByteReader<'_>) -> IndraResult<PersistentOrdMap<Bytes32, u64>> {
    let count = u32::decode(r)? as usize;
    validate_nonce_map_count(count)?;
    let mut nonces = PersistentOrdMap::new();
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

fn validate_nonce_map_count(count: usize) -> IndraResult<()> {
    if count > MAX_STAKING_NONCES_DECODE {
        return Err(IndraError::LengthExceeded {
            field: "snapshot.staking_nonces",
            max: MAX_STAKING_NONCES_DECODE,
            actual: count,
        });
    }
    Ok(())
}

fn encode_delegator_identity_registry(
    identities: &PersistentOrdMap<Bytes32, HybridPubKey>,
    buf: &mut Vec<u8>,
) {
    (identities.len() as u32).encode(buf);
    for (delegator_id, pubkey) in identities {
        delegator_id.encode(buf);
        pubkey.encode(buf);
    }
}

fn delegator_identity_registry_encoded_len(
    identities: &PersistentOrdMap<Bytes32, HybridPubKey>,
) -> usize {
    4 + identities
        .iter()
        .map(|(delegator_id, pubkey)| delegator_id.encoded_len() + pubkey.encoded_len())
        .sum::<usize>()
}

fn decode_delegator_identity_registry(
    r: &mut ByteReader<'_>,
) -> IndraResult<PersistentOrdMap<Bytes32, HybridPubKey>> {
    let count = u32::decode(r)? as usize;
    validate_delegator_identity_count(count)?;
    let mut identities = PersistentOrdMap::new();
    for _ in 0..count {
        let delegator_id = Bytes32::decode(r)?;
        let pubkey = HybridPubKey::decode(r)?;
        if identities.insert(delegator_id, pubkey).is_some() {
            return Err(IndraError::DuplicateEntries {
                field: "snapshot.delegator_identities",
            });
        }
    }
    Ok(identities)
}

fn validate_delegator_identity_count(count: usize) -> IndraResult<()> {
    if count > MAX_STAKING_NONCES_DECODE {
        return Err(IndraError::LengthExceeded {
            field: "snapshot.delegator_identities",
            max: MAX_STAKING_NONCES_DECODE,
            actual: count,
        });
    }
    Ok(())
}

fn encode_payment_identity_registry(
    identities: &PersistentOrdMap<Bytes32, PaymentPubKeyV1>,
    buf: &mut Vec<u8>,
) {
    (identities.len() as u32).encode(buf);
    for (owner_id, pubkey) in identities {
        owner_id.encode(buf);
        buf.extend_from_slice(&pubkey.encode());
    }
}

fn payment_identity_registry_encoded_len(
    identities: &PersistentOrdMap<Bytes32, PaymentPubKeyV1>,
) -> usize {
    4 + identities
        .iter()
        .map(|(owner_id, pubkey)| owner_id.encoded_len() + pubkey.encode().len())
        .sum::<usize>()
}

fn decode_payment_identity_registry(
    r: &mut ByteReader<'_>,
) -> IndraResult<PersistentOrdMap<Bytes32, PaymentPubKeyV1>> {
    let count = u32::decode(r)? as usize;
    validate_payment_identity_count(count)?;
    let mut identities = PersistentOrdMap::new();
    for _ in 0..count {
        let owner_id = Bytes32::decode(r)?;
        let pubkey_bytes = r.read_bytes(indra_crypto::PAYMENT_PUBKEY_V1_ENCODED_LEN)?;
        let pubkey =
            PaymentPubKeyV1::decode(pubkey_bytes).map_err(|_| IndraError::InvariantViolation {
                message: "snapshot.payment_identities contains malformed payment public key",
            })?;
        if identities.insert(owner_id, pubkey).is_some() {
            return Err(IndraError::DuplicateEntries {
                field: "snapshot.payment_identities",
            });
        }
    }
    Ok(identities)
}

fn validate_payment_identity_count(count: usize) -> IndraResult<()> {
    if count > MAX_STAKING_NONCES_DECODE {
        return Err(IndraError::LengthExceeded {
            field: "snapshot.payment_identities",
            max: MAX_STAKING_NONCES_DECODE,
            actual: count,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashSet};

    use indra_core::{
        codec::Encode,
        error::IndraError,
        types::{
            crypto::HybridPubKey,
            primitives::{
                VariableBytes, GENESIS_SUPPLY_SPARK, INITIAL_BASE_FEE_SPARK_PER_KB, MAX_VALIDATORS,
            },
            transaction::OutputV1,
        },
        CommitmentV1,
    };
    use indra_crypto::{PaymentKeypairV1, PAYMENT_VERSION_V1};

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

    fn test_output(byte: u8) -> OutputV1 {
        OutputV1 {
            value_spark: 1_000_000,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from([byte; 32]),
            },
            owner_pubkey: HybridPubKey {
                classical_pk: Bytes32::from([byte; 32]),
                pq_pk: VariableBytes::from_slice(&[byte; 32]).unwrap(),
            },
            range_proof: VariableBytes::from_slice(&[byte; 32]).unwrap(),
            lock_height: 0,
        }
    }

    fn test_hybrid_pubkey(byte: u8) -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::from([byte; 32]),
            pq_pk: VariableBytes::from_slice(&vec![byte.wrapping_add(1); 2_592]).unwrap(),
        }
    }

    fn test_payment_pubkey(index: usize) -> PaymentPubKeyV1 {
        let mut x25519_sk = [0u8; 32];
        x25519_sk[0] = 0xA5;
        x25519_sk[8..16].copy_from_slice(&(index as u64).to_be_bytes());
        let mut ml_kem_1024_seed = [0u8; 64];
        ml_kem_1024_seed[0] = 0x5A;
        ml_kem_1024_seed[8..16].copy_from_slice(&(index as u64).to_be_bytes());
        PaymentKeypairV1 {
            version: PAYMENT_VERSION_V1,
            x25519_sk,
            ml_kem_1024_seed,
        }
        .public_key()
    }

    fn test_bond(byte: u8) -> StakeBondEntry {
        StakeBondEntry {
            utxo_id: Bytes32::from([byte; 32]),
            validator_id: Bytes32::from([0xA0 | byte; 32]),
            delegator_id: Bytes32::from([0xD0 | byte; 32]),
            amount_spark: 1_000_000,
            bonded_epoch: 7,
            unbonding_end_epoch: None,
            original_output: test_output(byte).into(),
        }
    }

    fn encode_bond_map_btree(bonds: &BTreeMap<Bytes32, StakeBondEntry>, buf: &mut Vec<u8>) {
        (bonds.len() as u32).encode(buf);
        for (utxo_id, bond) in bonds {
            utxo_id.encode(buf);
            bond.encode(buf);
        }
    }

    fn encode_nonce_map_btree(nonces: &BTreeMap<Bytes32, u64>, buf: &mut Vec<u8>) {
        (nonces.len() as u32).encode(buf);
        for (signer_id, nonce) in nonces {
            signer_id.encode(buf);
            nonce.encode(buf);
        }
    }

    fn encode_chain_state_without_delegator_identities(state: &ChainState) -> Vec<u8> {
        let mut buf = Vec::new();
        VariableBytes::<MAX_CHAIN_ID_BYTES>::from_slice(state.chain_id.as_bytes())
            .unwrap_or_default()
            .encode(&mut buf);
        state.height.encode(&mut buf);
        state.tip_hash.encode(&mut buf);
        state.base_fee.encode(&mut buf);
        state.total_supply.encode(&mut buf);
        state.treasury_balance.encode(&mut buf);
        state.burn_buffer.encode(&mut buf);
        state.fee_reward_pool.encode(&mut buf);
        state.utxos.encode(&mut buf);
        state.nullifiers.encode(&mut buf);
        state.validators.encode(&mut buf);
        state.delegations.encode(&mut buf);
        encode_bond_map(&state.staked_bonds, &mut buf);
        encode_nonce_map(&state.staking_nonces, &mut buf);
        encode_hash_set(&state.applied_slash_hashes, &mut buf);
        state.governance.encode(&mut buf);
        encode_delegation_return_events(&state.delegation_return_events, &mut buf);
        buf
    }

    fn encode_chain_state_without_identity_tails(state: &ChainState) -> Vec<u8> {
        encode_chain_state_without_delegator_identities(state)
    }

    fn encode_hash_set_hashset(hashes: &HashSet<Bytes32>, buf: &mut Vec<u8>) {
        let mut entries: Vec<_> = hashes.iter().copied().collect();
        entries.sort_by_key(|hash| hash.0);
        (entries.len() as u32).encode(buf);
        for hash in entries {
            hash.encode(buf);
        }
    }

    #[test]
    fn staked_bond_decode_cap_is_derived_from_validator_delegator_caps() {
        let old_placeholder_cap = MAX_VALIDATORS.saturating_mul(1_000);
        assert!(
            MAX_STAKED_BONDS_DECODE > old_placeholder_cap,
            "corrected cap must accept states above the old placeholder ceiling"
        );
        assert_eq!(
            MAX_STAKED_BONDS_DECODE,
            MAX_VALIDATORS.saturating_mul(crate::validator::MAX_DELEGATORS_PER_VALIDATOR)
        );
        assert!(validate_bond_map_count(old_placeholder_cap + 1).is_ok());
    }

    #[test]
    fn staked_bond_decode_no_longer_rejects_count_above_old_placeholder_cap() {
        let old_placeholder_cap = MAX_VALIDATORS.saturating_mul(1_000);
        let mut bytes = Vec::new();
        ((old_placeholder_cap + 1) as u32).encode(&mut bytes);

        let err = decode_bond_map(&mut ByteReader::new(&bytes)).unwrap_err();
        assert!(
            matches!(err, IndraError::UnexpectedEof { .. }),
            "count above old placeholder cap should pass the staked_bonds cap guard and fail only because this synthetic stream has no entries; got {err:?}"
        );
    }

    #[test]
    fn staked_bond_decode_rejects_count_above_corrected_cap_cleanly() {
        let mut bytes = Vec::new();
        ((MAX_STAKED_BONDS_DECODE + 1) as u32).encode(&mut bytes);

        let err = decode_bond_map(&mut ByteReader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            IndraError::LengthExceeded {
                field: "snapshot.staked_bonds",
                max: MAX_STAKED_BONDS_DECODE,
                actual
            } if actual == MAX_STAKED_BONDS_DECODE + 1
        ));
    }

    #[test]
    fn staked_bond_encode_decode_round_trip_uses_same_cap_path() {
        let mut bonds = PersistentOrdMap::new();
        let bond_a = test_bond(0x01);
        let bond_b = test_bond(0x02);
        bonds.insert(bond_a.utxo_id, bond_a);
        bonds.insert(bond_b.utxo_id, bond_b);

        let mut bytes = Vec::new();
        encode_bond_map(&bonds, &mut bytes);
        let decoded = decode_bond_map(&mut ByteReader::new(&bytes)).unwrap();
        assert_eq!(decoded, bonds);
    }

    #[test]
    fn mixed_legacy_range_compact_and_fully_compact_staked_bonds_encode_decode_and_root() {
        let mut state = ChainState::new_genesis();
        let legacy = StakeBondEntry::new_for_test_with_compact_activation(
            Bytes32::from([0x21; 32]),
            Bytes32::from([0xA1; 32]),
            Bytes32::from([0xD1; 32]),
            1_000_000,
            7,
            test_output(0x21),
            9,
            10,
        );
        let compact = StakeBondEntry::new_for_test_with_compact_activation(
            Bytes32::from([0x22; 32]),
            Bytes32::from([0xA2; 32]),
            Bytes32::from([0xD2; 32]),
            1_000_000,
            8,
            test_output(0x22),
            10,
            10,
        );
        let fully_compact = StakeBondEntry::new_for_test_with_compact_and_pubkey_activation(
            Bytes32::from([0x23; 32]),
            Bytes32::from([0xA3; 32]),
            Bytes32::from([0xD3; 32]),
            1_000_000,
            9,
            test_output(0x23),
            20,
            10,
            20,
        );
        assert!(legacy.original_output.range_proof.is_some());
        assert!(legacy.original_output.owner_pubkey.is_some());
        assert!(compact.original_output.range_proof.is_none());
        assert!(compact.original_output.owner_pubkey.is_some());
        assert!(fully_compact.original_output.range_proof.is_none());
        assert!(fully_compact.original_output.owner_pubkey.is_none());
        state.staked_bonds.insert(legacy.utxo_id, legacy);
        state.staked_bonds.insert(compact.utxo_id, compact);
        state
            .staked_bonds
            .insert(fully_compact.utxo_id, fully_compact);

        let encoded = state.encode_to_vec();
        let decoded = ChainState::decode(&mut ByteReader::new(&encoded)).unwrap();
        assert_eq!(decoded, state);
        assert_eq!(
            crate::state_root::compute_state_root(&decoded),
            crate::state_root::compute_state_root(&state)
        );
        assert_eq!(
            crate::state_commitment::StateCommitmentV2::from_state(&decoded, u64::MAX).root(),
            crate::state_commitment::StateCommitmentV2::from_state(&state, u64::MAX).root()
        );
    }

    #[test]
    fn staked_bond_persistent_encoding_matches_legacy_btree_encoding() {
        let mut legacy = BTreeMap::new();
        let mut persistent = PersistentOrdMap::new();
        for byte in [0x03, 0x01, 0x02] {
            let bond = test_bond(byte);
            legacy.insert(bond.utxo_id, bond.clone());
            persistent.insert(bond.utxo_id, bond);
        }

        let mut legacy_bytes = Vec::new();
        encode_bond_map_btree(&legacy, &mut legacy_bytes);
        let mut persistent_bytes = Vec::new();
        encode_bond_map(&persistent, &mut persistent_bytes);
        assert_eq!(persistent_bytes, legacy_bytes);

        let mut state = ChainState::new_genesis();
        state.staked_bonds = persistent;
        let encoded = state.encode_to_vec();
        let decoded = ChainState::decode(&mut ByteReader::new(&encoded)).unwrap();
        assert_eq!(decoded, state);
    }

    #[test]
    fn staked_bond_persistent_encoding_is_insertion_order_independent() {
        let mut forward = PersistentOrdMap::new();
        let mut reverse = PersistentOrdMap::new();
        for byte in [0x01, 0x02, 0x03, 0x04] {
            let bond = test_bond(byte);
            forward.insert(bond.utxo_id, bond);
        }
        for byte in [0x04, 0x03, 0x02, 0x01] {
            let bond = test_bond(byte);
            reverse.insert(bond.utxo_id, bond);
        }

        let mut forward_bytes = Vec::new();
        encode_bond_map(&forward, &mut forward_bytes);
        let mut reverse_bytes = Vec::new();
        encode_bond_map(&reverse, &mut reverse_bytes);
        assert_eq!(forward_bytes, reverse_bytes);
    }

    #[test]
    fn staking_nonce_decode_cap_is_derived_from_staking_signer_capacity() {
        let old_placeholder_cap = MAX_VALIDATORS.saturating_mul(100);
        assert!(
            MAX_STAKING_NONCES_DECODE > old_placeholder_cap,
            "corrected cap must accept signer nonce counts above the old validator-only placeholder"
        );
        assert_eq!(
            MAX_STAKING_NONCES_DECODE,
            MAX_VALIDATORS.saturating_add(
                MAX_VALIDATORS.saturating_mul(crate::validator::MAX_DELEGATORS_PER_VALIDATOR)
            )
        );
        assert!(validate_nonce_map_count(old_placeholder_cap + 1).is_ok());
    }

    #[test]
    fn staking_nonce_decode_no_longer_rejects_count_above_old_placeholder_cap() {
        let old_placeholder_cap = MAX_VALIDATORS.saturating_mul(100);
        let mut bytes = Vec::new();
        ((old_placeholder_cap + 1) as u32).encode(&mut bytes);

        let err = decode_nonce_map(&mut ByteReader::new(&bytes)).unwrap_err();
        assert!(
            matches!(err, IndraError::UnexpectedEof { .. }),
            "count above old placeholder cap should pass the staking_nonces cap guard and fail only because this synthetic stream has no entries; got {err:?}"
        );
    }

    #[test]
    fn staking_nonce_decode_rejects_count_above_corrected_cap_cleanly() {
        let mut bytes = Vec::new();
        ((MAX_STAKING_NONCES_DECODE + 1) as u32).encode(&mut bytes);

        let err = decode_nonce_map(&mut ByteReader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            IndraError::LengthExceeded {
                field: "snapshot.staking_nonces",
                max: MAX_STAKING_NONCES_DECODE,
                actual
            } if actual == MAX_STAKING_NONCES_DECODE + 1
        ));
    }

    #[test]
    fn staking_nonce_encode_decode_round_trip_uses_same_cap_path() {
        let mut nonces = PersistentOrdMap::new();
        nonces.insert(Bytes32::from([0xA1; 32]), 7);
        nonces.insert(Bytes32::from([0xD1; 32]), 11);

        let mut bytes = Vec::new();
        encode_nonce_map(&nonces, &mut bytes);
        let decoded = decode_nonce_map(&mut ByteReader::new(&bytes)).unwrap();
        assert_eq!(decoded, nonces);
    }

    #[test]
    fn staking_nonce_persistent_encoding_matches_legacy_btree_encoding() {
        let legacy = BTreeMap::from([
            (Bytes32::from([0xD1; 32]), 11),
            (Bytes32::from([0xA1; 32]), 7),
            (Bytes32::from([0xB1; 32]), 9),
        ]);
        let mut persistent = PersistentOrdMap::new();
        for (key, value) in [
            (Bytes32::from([0xD1; 32]), 11),
            (Bytes32::from([0xA1; 32]), 7),
            (Bytes32::from([0xB1; 32]), 9),
        ] {
            persistent.insert(key, value);
        }

        let mut legacy_bytes = Vec::new();
        encode_nonce_map_btree(&legacy, &mut legacy_bytes);
        let mut persistent_bytes = Vec::new();
        encode_nonce_map(&persistent, &mut persistent_bytes);
        assert_eq!(persistent_bytes, legacy_bytes);
    }

    #[test]
    fn staking_nonce_persistent_encoding_is_insertion_order_independent() {
        let mut forward = PersistentOrdMap::new();
        let mut reverse = PersistentOrdMap::new();
        for byte in [0x01, 0x02, 0x03, 0x04] {
            forward.insert(Bytes32::from([byte; 32]), byte as u64);
        }
        for byte in [0x04, 0x03, 0x02, 0x01] {
            reverse.insert(Bytes32::from([byte; 32]), byte as u64);
        }

        let mut forward_bytes = Vec::new();
        encode_nonce_map(&forward, &mut forward_bytes);
        let mut reverse_bytes = Vec::new();
        encode_nonce_map(&reverse, &mut reverse_bytes);
        assert_eq!(forward_bytes, reverse_bytes);
    }

    #[test]
    fn delegator_identity_registry_insert_lookup_contains() {
        let mut registry = PersistentOrdMap::new();
        let delegator_id = Bytes32::from([0xD1; 32]);
        let pubkey = test_hybrid_pubkey(0x11);

        assert!(registry.is_empty());
        assert!(!registry.contains_key(&delegator_id));
        assert_eq!(registry.insert(delegator_id, pubkey.clone()), None);
        assert_eq!(registry.len(), 1);
        assert!(registry.contains_key(&delegator_id));
        assert_eq!(registry.get(&delegator_id), Some(&pubkey));

        let replacement = test_hybrid_pubkey(0x22);
        assert_eq!(
            registry.insert(delegator_id, replacement.clone()),
            Some(pubkey)
        );
        assert_eq!(registry.get(&delegator_id), Some(&replacement));
    }

    #[test]
    fn delegator_identity_registry_round_trips_empty_small_and_realistic_scale() {
        for size in [0usize, 3, 2_000] {
            let mut registry = PersistentOrdMap::new();
            for index in 0..size {
                let mut id = [0u8; 32];
                id[0] = 0xD0;
                id[8..16].copy_from_slice(&(index as u64).to_be_bytes());
                registry.insert(Bytes32::from(id), test_hybrid_pubkey(index as u8));
            }

            let mut bytes = Vec::new();
            encode_delegator_identity_registry(&registry, &mut bytes);
            assert_eq!(
                bytes.len(),
                delegator_identity_registry_encoded_len(&registry)
            );
            let decoded = decode_delegator_identity_registry(&mut ByteReader::new(&bytes)).unwrap();
            assert_eq!(decoded, registry);
        }
    }

    #[test]
    fn delegator_identity_registry_encoding_is_insertion_order_independent() {
        let mut forward = PersistentOrdMap::new();
        let mut reverse = PersistentOrdMap::new();
        for byte in [0x01, 0x02, 0x03, 0x04] {
            forward.insert(Bytes32::from([byte; 32]), test_hybrid_pubkey(byte));
        }
        for byte in [0x04, 0x03, 0x02, 0x01] {
            reverse.insert(Bytes32::from([byte; 32]), test_hybrid_pubkey(byte));
        }

        let mut forward_bytes = Vec::new();
        encode_delegator_identity_registry(&forward, &mut forward_bytes);
        let mut reverse_bytes = Vec::new();
        encode_delegator_identity_registry(&reverse, &mut reverse_bytes);
        assert_eq!(forward_bytes, reverse_bytes);
        assert_eq!(
            forward
                .iter()
                .map(|(delegator_id, _)| delegator_id.0[0])
                .collect::<Vec<_>>(),
            vec![0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn delegator_identity_registry_decode_rejects_duplicate_ids() {
        let delegator_id = Bytes32::from([0xD1; 32]);
        let mut bytes = Vec::new();
        2u32.encode(&mut bytes);
        delegator_id.encode(&mut bytes);
        test_hybrid_pubkey(0x11).encode(&mut bytes);
        delegator_id.encode(&mut bytes);
        test_hybrid_pubkey(0x22).encode(&mut bytes);

        let err = decode_delegator_identity_registry(&mut ByteReader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            IndraError::DuplicateEntries {
                field: "snapshot.delegator_identities"
            }
        ));
    }

    #[test]
    fn payment_identity_registry_round_trips_empty_small_and_realistic_scale() {
        for size in [0usize, 3, 2_000] {
            let mut registry = PersistentOrdMap::new();
            for index in 0..size {
                let mut id = [0u8; 32];
                id[0] = 0xC0;
                id[8..16].copy_from_slice(&(index as u64).to_be_bytes());
                registry.insert(Bytes32::from(id), test_payment_pubkey(index));
            }

            let mut bytes = Vec::new();
            encode_payment_identity_registry(&registry, &mut bytes);
            assert_eq!(
                bytes.len(),
                payment_identity_registry_encoded_len(&registry)
            );
            let decoded = decode_payment_identity_registry(&mut ByteReader::new(&bytes)).unwrap();
            assert_eq!(decoded, registry);
        }
    }

    #[test]
    fn payment_identity_registry_encoding_is_insertion_order_independent() {
        let mut forward = PersistentOrdMap::new();
        let mut reverse = PersistentOrdMap::new();
        for index in [1usize, 2, 3, 4] {
            forward.insert(Bytes32::from([index as u8; 32]), test_payment_pubkey(index));
        }
        for index in [4usize, 3, 2, 1] {
            reverse.insert(Bytes32::from([index as u8; 32]), test_payment_pubkey(index));
        }

        let mut forward_bytes = Vec::new();
        encode_payment_identity_registry(&forward, &mut forward_bytes);
        let mut reverse_bytes = Vec::new();
        encode_payment_identity_registry(&reverse, &mut reverse_bytes);
        assert_eq!(forward_bytes, reverse_bytes);
        assert_eq!(
            forward
                .iter()
                .map(|(owner_id, _)| owner_id.0[0])
                .collect::<Vec<_>>(),
            vec![0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn payment_identity_registry_decode_rejects_duplicate_ids() {
        let owner_id = Bytes32::from([0xC1; 32]);
        let mut bytes = Vec::new();
        2u32.encode(&mut bytes);
        owner_id.encode(&mut bytes);
        bytes.extend_from_slice(&test_payment_pubkey(1).encode());
        owner_id.encode(&mut bytes);
        bytes.extend_from_slice(&test_payment_pubkey(2).encode());

        let err = decode_payment_identity_registry(&mut ByteReader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            IndraError::DuplicateEntries {
                field: "snapshot.payment_identities"
            }
        ));
    }

    #[test]
    fn empty_delegator_identity_registry_preserves_chain_state_encoding() {
        let mut state = ChainState::new_genesis();
        state.height = 42;
        state.staking_nonces.insert(Bytes32::from([0x44; 32]), 7);
        state.applied_slash_hashes.insert(Bytes32::from([0x55; 32]));

        let old_bytes = encode_chain_state_without_delegator_identities(&state);
        let new_bytes = state.encode_to_vec();
        assert!(state.delegator_identities.is_empty());
        assert_eq!(new_bytes, old_bytes);
        assert_eq!(new_bytes.len(), state.encoded_len());

        let decoded = ChainState::decode_exact(&old_bytes).unwrap();
        assert_eq!(decoded, state);
        assert!(decoded.delegator_identities.is_empty());
    }

    #[test]
    fn empty_payment_identity_registry_preserves_chain_state_encoding() {
        let mut state = ChainState::new_genesis();
        state.height = 42;
        state.staking_nonces.insert(Bytes32::from([0x44; 32]), 7);
        state.applied_slash_hashes.insert(Bytes32::from([0x55; 32]));

        let old_bytes = encode_chain_state_without_identity_tails(&state);
        let new_bytes = state.encode_to_vec();
        assert!(state.delegator_identities.is_empty());
        assert!(state.payment_identities.is_empty());
        assert_eq!(new_bytes, old_bytes);
        assert_eq!(new_bytes.len(), state.encoded_len());

        let decoded = ChainState::decode_exact(&old_bytes).unwrap();
        assert_eq!(decoded, state);
        assert!(decoded.delegator_identities.is_empty());
        assert!(decoded.payment_identities.is_empty());
    }

    #[test]
    fn chain_state_round_trips_optional_payment_identity_registry_tail() {
        let mut state = ChainState::new_genesis();
        state
            .payment_identities
            .insert(Bytes32::from([0xC2; 32]), test_payment_pubkey(2));
        state
            .payment_identities
            .insert(Bytes32::from([0xC1; 32]), test_payment_pubkey(1));

        let without_identity_tails = encode_chain_state_without_identity_tails(&state);
        let encoded = state.encode_to_vec();
        assert!(encoded.len() > without_identity_tails.len());
        assert!(encoded.starts_with(&without_identity_tails));
        assert_eq!(encoded.len(), state.encoded_len());

        let decoded = ChainState::decode_exact(&encoded).unwrap();
        assert_eq!(decoded, state);
        assert!(decoded.delegator_identities.is_empty());
        assert_eq!(decoded.payment_identities.len(), 2);
    }

    #[test]
    fn chain_state_round_trips_optional_delegator_identity_registry_tail() {
        let mut state = ChainState::new_genesis();
        state
            .delegator_identities
            .insert(Bytes32::from([0xD2; 32]), test_hybrid_pubkey(0x12));
        state
            .delegator_identities
            .insert(Bytes32::from([0xD1; 32]), test_hybrid_pubkey(0x11));

        let without_registry = encode_chain_state_without_delegator_identities(&state);
        let encoded = state.encode_to_vec();
        assert!(encoded.len() > without_registry.len());
        assert!(encoded.starts_with(&without_registry));
        assert_eq!(encoded.len(), state.encoded_len());

        let decoded = ChainState::decode_exact(&encoded).unwrap();
        assert_eq!(decoded, state);
    }

    #[test]
    fn applied_slash_hash_persistent_encoding_matches_legacy_hashset_encoding() {
        let mut legacy = HashSet::new();
        let mut persistent = PersistentOrdSet::new();
        for byte in [0x03, 0x01, 0x02, 0x04] {
            let hash = Bytes32::from([byte; 32]);
            legacy.insert(hash);
            persistent.insert(hash);
        }

        let mut legacy_bytes = Vec::new();
        encode_hash_set_hashset(&legacy, &mut legacy_bytes);
        let mut persistent_bytes = Vec::new();
        encode_hash_set(&persistent, &mut persistent_bytes);
        assert_eq!(persistent_bytes, legacy_bytes);

        let decoded = decode_hash_set(
            &mut ByteReader::new(&persistent_bytes),
            "snapshot.applied_slash_hashes",
        )
        .unwrap();
        assert_eq!(decoded, persistent);
    }

    #[test]
    fn applied_slash_hash_persistent_encoding_is_insertion_order_independent() {
        let mut forward = PersistentOrdSet::new();
        let mut reverse = PersistentOrdSet::new();
        for byte in [0x01, 0x02, 0x03, 0x04] {
            forward.insert(Bytes32::from([byte; 32]));
        }
        for byte in [0x04, 0x03, 0x02, 0x01] {
            reverse.insert(Bytes32::from([byte; 32]));
        }

        let mut forward_bytes = Vec::new();
        encode_hash_set(&forward, &mut forward_bytes);
        let mut reverse_bytes = Vec::new();
        encode_hash_set(&reverse, &mut reverse_bytes);
        assert_eq!(forward_bytes, reverse_bytes);
    }

    #[test]
    fn chain_state_migrated_clone_matches_deep_materialized_oracle() {
        let mut state = ChainState::new_genesis();
        state.height = indra_core::types::primitives::hard_forks::STATE_COMMITMENT_V2_HEIGHT;
        state.utxos.insert(test_output(0x11), 1, 0, 0).unwrap();
        state.nullifiers.insert(Bytes32::from([0x22; 32]));
        state
            .staked_bonds
            .insert(Bytes32::from([0x33; 32]), test_bond(0x33));
        state.staking_nonces.insert(Bytes32::from([0x44; 32]), 7);
        state.applied_slash_hashes.insert(Bytes32::from([0x55; 32]));
        state.push_delegation_return_event(DelegationReturnEvent {
            delegator_id: Bytes32::from([0x66; 32]),
            validator_id: Bytes32::from([0x77; 32]),
            bond_utxo_id: Bytes32::from([0x88; 32]),
            amount_spark: 123,
            reason: crate::validator::DelegationReturnReason::ValidatorEvicted,
            returned_epoch: 9,
            returned_height: state.height,
            refund_utxo_id: Bytes32::from([0x99; 32]),
        });
        state.rebuild_state_commitment_v2(state.height);

        let migrated_clone = state.clone();
        let deep_materialized = ChainState::decode_exact(&state.encode_to_vec()).unwrap();

        assert_eq!(
            migrated_clone.encode_to_vec(),
            deep_materialized.encode_to_vec()
        );
        assert_eq!(
            crate::state_root::compute_state_roots(&migrated_clone),
            crate::state_root::compute_state_roots(&deep_materialized)
        );
        assert_eq!(migrated_clone, state);
    }

    #[test]
    #[ignore = "release-mode fix #6 capstone whole-ChainState clone benchmark; run with --release --ignored --nocapture"]
    fn fix6_capstone_whole_chain_state_clone_benchmark() {
        use std::{hint::black_box, time::Instant};

        fn id_from_index(domain: u8, index: usize) -> Bytes32 {
            let mut bytes = [0u8; 32];
            bytes[0] = domain;
            bytes[8..16].copy_from_slice(&(index as u64).to_be_bytes());
            Bytes32::from(bytes)
        }

        fn heavy_output(index: usize) -> OutputV1 {
            let byte = (index as u8).wrapping_add(1);
            OutputV1 {
                value_spark: 1_000,
                commitment: CommitmentV1 {
                    compressed_point: id_from_index(0xC0, index),
                },
                owner_pubkey: HybridPubKey {
                    classical_pk: id_from_index(0xA0, index),
                    pq_pk: VariableBytes::from_slice(&vec![byte.wrapping_add(2); 2_592]).unwrap(),
                },
                range_proof: VariableBytes::from_slice(&vec![byte.wrapping_add(3); 674]).unwrap(),
                lock_height: 0,
            }
        }

        fn heavy_bond(
            index: usize,
            validator_id: Bytes32,
            delegator_id: Bytes32,
        ) -> StakeBondEntry {
            let utxo_id = id_from_index(0xB0, index);
            StakeBondEntry {
                utxo_id,
                validator_id,
                delegator_id,
                amount_spark: 1_000,
                bonded_epoch: 0,
                unbonding_end_epoch: None,
                original_output: heavy_output(index).into(),
            }
        }

        fn populate_state(size: usize, heavy_bond_count: usize) -> ChainState {
            let mut state = ChainState::new_genesis();
            state.height = indra_core::types::primitives::hard_forks::STATE_COMMITMENT_V2_HEIGHT;
            let validator_count = size.clamp(1, 10_000);
            for index in 0..size {
                let validator_id = id_from_index(0x70, index % validator_count);
                let delegator_id = id_from_index(0xD0, index);
                state
                    .delegations
                    .add_delegation(validator_id, delegator_id, 1_000, 0)
                    .unwrap();
                state.staking_nonces.insert(delegator_id, index as u64);
                if index < heavy_bond_count {
                    let bond = heavy_bond(index, validator_id, delegator_id);
                    state.staked_bonds.insert(bond.utxo_id, bond);
                }
            }
            for index in 0..size.min(30_000) {
                state
                    .applied_slash_hashes
                    .insert(id_from_index(0xE0, index));
            }
            for index in 0..size.min(MAX_DELEGATION_RETURN_EVENTS) {
                state.push_delegation_return_event(DelegationReturnEvent {
                    delegator_id: id_from_index(0xD0, index),
                    validator_id: id_from_index(0x70, index % validator_count),
                    bond_utxo_id: id_from_index(0xB0, index),
                    amount_spark: 1_000,
                    reason: crate::validator::DelegationReturnReason::ValidatorEvicted,
                    returned_epoch: index as u64 / 100,
                    returned_height: state.height,
                    refund_utxo_id: id_from_index(0xF0, index),
                });
            }
            state.rebuild_state_commitment_v2(state.height);
            state
        }

        let sizes = std::env::var("INDRA_FIX6_CAPSTONE_CLONE_BENCH_SIZES")
            .unwrap_or_else(|_| "100000,1000000".to_string())
            .split(',')
            .map(|part| part.trim().parse::<usize>().unwrap())
            .collect::<Vec<_>>();
        let heavy_bond_limit = std::env::var("INDRA_FIX6_CAPSTONE_HEAVY_BOND_LIMIT")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(1_000_000);

        eprintln!(
            "[fix6-capstone] original Step 0: normal import/commit ≈7 clone-equivalents and ≈11.6-11.9s at 1M delegators before the clone-cost arc"
        );

        for size in sizes {
            let heavy_bonds = size.min(heavy_bond_limit);
            let setup_start = Instant::now();
            let state = populate_state(size, heavy_bonds);
            let setup = setup_start.elapsed();

            let whole_clone_start = Instant::now();
            let whole_clone = state.clone();
            let whole_clone_elapsed = whole_clone_start.elapsed();
            black_box(&whole_clone);

            let slash_hash_clone_start = Instant::now();
            let slash_hash_clone = state.applied_slash_hashes.clone();
            let slash_hash_clone_elapsed = slash_hash_clone_start.elapsed();
            black_box(&slash_hash_clone);

            let event_clone_start = Instant::now();
            let event_clone = state.delegation_return_events.clone();
            let event_clone_elapsed = event_clone_start.elapsed();
            black_box(&event_clone);

            println!(
                "fix6_capstone_chainstate_clone delegators={size} heavy_bonds={heavy_bonds} setup={setup:?} whole_chainstate_clone={whole_clone_elapsed:?} applied_slash_hashes_clone={slash_hash_clone_elapsed:?} delegation_return_events_clone={event_clone_elapsed:?}"
            );
        }
    }

    #[test]
    #[ignore = "release-mode Stage 2a field-clone benchmark; run explicitly with --release --ignored --nocapture"]
    fn stage2a_persistent_bonds_and_nonces_clone_benchmark() {
        use std::{hint::black_box, time::Instant};

        fn id_from_index(index: usize) -> Bytes32 {
            let mut bytes = [0u8; 32];
            for (dst, src) in bytes
                .iter_mut()
                .zip((index as u64).to_le_bytes().into_iter())
            {
                *dst = src;
            }
            Bytes32::from(bytes)
        }

        fn heavy_output(index: usize) -> OutputV1 {
            let byte = (index as u8).wrapping_add(1);
            OutputV1 {
                value_spark: 1_000,
                commitment: CommitmentV1 {
                    compressed_point: Bytes32::from([byte; 32]),
                },
                owner_pubkey: HybridPubKey {
                    classical_pk: Bytes32::from([byte.wrapping_add(1); 32]),
                    pq_pk: VariableBytes::from_slice(&vec![byte.wrapping_add(2); 2_592]).unwrap(),
                },
                range_proof: VariableBytes::from_slice(&vec![byte.wrapping_add(3); 674]).unwrap(),
                lock_height: 0,
            }
        }

        fn heavy_bond(index: usize) -> StakeBondEntry {
            let utxo_id = id_from_index(index);
            StakeBondEntry {
                utxo_id,
                validator_id: Bytes32::from([0x55; 32]),
                delegator_id: id_from_index(index + 1_000_000),
                amount_spark: 1_000,
                bonded_epoch: 0,
                unbonding_end_epoch: None,
                original_output: heavy_output(index).into(),
            }
        }

        fn legacy_bonds(size: usize) -> BTreeMap<Bytes32, StakeBondEntry> {
            let mut map = BTreeMap::new();
            for index in 0..size {
                let bond = heavy_bond(index);
                map.insert(bond.utxo_id, bond);
            }
            map
        }

        fn persistent_bonds(size: usize) -> PersistentOrdMap<Bytes32, StakeBondEntry> {
            let mut map = PersistentOrdMap::new();
            for index in 0..size {
                let bond = heavy_bond(index);
                map.insert(bond.utxo_id, bond);
            }
            map
        }

        fn legacy_nonces(size: usize) -> BTreeMap<Bytes32, u64> {
            let mut map = BTreeMap::new();
            for index in 0..size {
                map.insert(id_from_index(index), index as u64);
            }
            map
        }

        fn persistent_nonces(size: usize) -> PersistentOrdMap<Bytes32, u64> {
            let mut map = PersistentOrdMap::new();
            for index in 0..size {
                map.insert(id_from_index(index), index as u64);
            }
            map
        }

        // This is intentionally ignored and release-only: debug timings for
        // million-entry heavy bond maps are dominated by instrumentation and are
        // not meaningful for validator deployment decisions.
        for size in [100_000usize, 1_000_000usize] {
            let legacy = legacy_bonds(size);
            let start = Instant::now();
            let legacy_clone = legacy.clone();
            black_box(&legacy_clone);
            let legacy_bond_clone = start.elapsed();
            drop(legacy_clone);
            drop(legacy);

            let persistent = persistent_bonds(size);
            let start = Instant::now();
            let persistent_clone = persistent.clone();
            black_box(&persistent_clone);
            let persistent_bond_clone = start.elapsed();
            drop(persistent_clone);
            drop(persistent);

            let legacy = legacy_nonces(size);
            let start = Instant::now();
            let legacy_clone = legacy.clone();
            black_box(&legacy_clone);
            let legacy_nonce_clone = start.elapsed();
            drop(legacy_clone);
            drop(legacy);

            let persistent = persistent_nonces(size);
            let start = Instant::now();
            let persistent_clone = persistent.clone();
            black_box(&persistent_clone);
            let persistent_nonce_clone = start.elapsed();
            drop(persistent_clone);
            drop(persistent);

            println!(
                "stage2a_persistent_bonds_and_nonces_clone size={size} legacy_bonds_clone={legacy_bond_clone:?} persistent_bonds_clone={persistent_bond_clone:?} legacy_nonces_clone={legacy_nonce_clone:?} persistent_nonces_clone={persistent_nonce_clone:?}"
            );

            assert!(
                persistent_bond_clone < legacy_bond_clone,
                "persistent staked_bonds clone should be cheaper than legacy BTreeMap clone at size {size}"
            );
            assert!(
                persistent_nonce_clone < legacy_nonce_clone,
                "persistent staking_nonces clone should be cheaper than legacy BTreeMap clone at size {size}"
            );
        }
    }
}
