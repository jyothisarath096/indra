//! Primitive types and all INDRA v2 protocol constants.
//!
//! Every protocol constant is defined here and referenced by name everywhere
//! else. No magic numbers appear elsewhere in the codebase.

use crate::{
    codec::{ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
};

// =============================================================================
// PROTOCOL CONSTANTS (Spec Section G1 — Parameter Registry)
// =============================================================================

// ── Consensus ─────────────────────────────────────────────────────────────────

/// Target block time in seconds.
pub const BLOCK_TIME_TARGET_SECS: u64 = 6;

/// Blocks per epoch.
pub const EPOCH_DURATION_BLOCKS: u64 = 300;

/// Maximum active validators.
pub const MAX_VALIDATORS: usize = 1_500;

/// Epochs a validator's stake is locked after initiating exit.
pub const UNBONDING_PERIOD_EPOCHS: u64 = 1008; // 21 days at 2 epochs/hour (48 epochs/day × 21 days = 1008)

/// Number of epochs after equivocation during which evidence is accepted
/// and self-bonds that entered unbonding after the infraction remain slashable.
/// This must be <= UNBONDING_PERIOD_EPOCHS so slashable funds are still locked.
pub const SLASH_EVIDENCE_WINDOW_EPOCHS: u64 = 500;

/// Epochs after exit during which a validator's signatures remain valid.
/// AUTH_WINDOW = UNBONDING_PERIOD + 100
pub const AUTH_WINDOW_EPOCHS: u64 = 1108; // unbonding(1008) + buffer(100)

/// Epochs beyond which a new node must have a checkpoint to sync.
pub const WS_WINDOW_EPOCHS: u64 = 500;

/// Epochs within which a validator must claim rewards before expiry.
pub const CLAIM_WINDOW_EPOCHS: u64 = 175_200; // ~100 years — rewards never expire in practice

/// Default propose phase timeout (ms).
pub const T_PROPOSE_MS: u64 = 2_000;

/// Default prevote phase timeout (ms).
pub const T_PREVOTE_MS: u64 = 1_500;

/// Default precommit phase timeout (ms).
pub const T_PRECOMMIT_MS: u64 = 1_500;

/// Hard floor on total round time — immutable, not governable.
pub const MIN_ROUND_TIME_MS: u64 = 3_000;

/// Hard ceiling on total round time — immutable, not governable.
pub const MAX_ROUND_TIME_MS: u64 = 15_000;

/// Maximum logical rounds tracked per height when deriving proposer slots.
///
/// This is used only to derive a unique deterministic slot index from
/// `(height, round)` and is not a runtime cap on retries.
pub const MAX_ROUNDS_PER_HEIGHT: u64 = 1_024;

/// Epochs delay before a governance-approved timeout change takes effect.
pub const TIMEOUT_CHANGE_DELAY_EPOCHS: u64 = 100;

// ── Slashing ──────────────────────────────────────────────────────────────────

/// Double precommit slash: 5% of stake.
/// Covers both accidental (bug) and intentional equivocation.
/// 5% hurts but doesn't destroy honest validators with software bugs.
pub const SLASH_DOUBLE_PRECOMMIT_BPS: u32 = 500;

/// Surround vote slash: 10% of stake.
/// Surround voting is a deliberate protocol attack — higher penalty.
pub const SLASH_SURROUND_VOTE_BPS: u32 = 1_000;

/// Self-report slash: 1% of stake.
/// Validator reports own equivocation within SLASH_GRACE_PERIOD_EPOCHS.
pub const SLASH_SELF_REPORT_BPS: u32 = 100;

/// Reporter reward: 5% of slashed amount to treasury.
/// Incentivizes evidence submission.
pub const SLASH_REPORTER_REWARD_BPS: u32 = 500;

/// Liveness slash: 0.1% per missed epoch after threshold.
pub const SLASH_LIVENESS_BPS: u32 = 10;

/// Consecutive missed epochs before liveness slash begins.
pub const SLASH_LIVENESS_THRESHOLD_EPOCHS: u64 = 3;

/// Grace period epochs for self-reported bug slash.
pub const SLASH_GRACE_PERIOD_EPOCHS: u64 = 5;

// ── Block and Transaction Limits ──────────────────────────────────────────────

/// Maximum block size in bytes.
pub const MAX_BLOCK_SIZE_BYTES: usize = 12_582_912; // 12 MB

/// Maximum transactions per block.
pub const MAX_TX_PER_BLOCK: usize = 200;

/// Maximum inputs per transaction.
pub const MAX_INPUTS: usize = 16;

/// Maximum outputs per transaction.
pub const MAX_OUTPUTS: usize = 16;

/// Maximum quorum certificate size in bytes.
pub const MAX_QC_SIZE_BYTES: usize = 10_485_760; // 10 MB

/// Maximum slash evidence per block (reduced — each requires 2 signature verifications).
pub const MAX_SLASHES_PER_BLOCK: usize = 3;

/// Maximum governance operations per block.
pub const MAX_GOV_OPS_PER_BLOCK: usize = 5;

/// Maximum staking operations per block.
pub const MAX_STAKING_OPS_PER_BLOCK: usize = 10;

/// Domain separation tag for staking operation signing bytes.
pub const STAKING_OP_DOMAIN: &str = "indra-stake-v1";

/// Special transaction index reserved for staking-created UTXOs.
pub const STAKING_TX_IDX: u32 = u32::MAX;

/// Domain for deterministic staking reward blinding factor derivation.
pub const STAKING_REWARD_BLINDING_DOMAIN: &[u8] = b"indra-staking-reward-v1";

/// Domain for deterministic slashed self-stake bond release blinding derivation.
pub const SLASH_BOND_RELEASE_BLINDING_DOMAIN: &[u8] = b"INDRA-slash-bond-release-v1";

// ── Cryptographic Size Bounds ─────────────────────────────────────────────────

/// Maximum Ed25519 signature size (bytes).
pub const MAX_CLASSICAL_SIG_BYTES: usize = 64;

/// Maximum ML-DSA-87 signature size (bytes).
pub const MAX_PQ_SIG_BYTES: usize = 4_627;

/// Maximum ML-DSA-87 public key size (bytes).
pub const MAX_PQ_PK_BYTES: usize = 2_592;

/// Maximum length of a chain ID string in bytes.
pub const MAX_CHAIN_ID_BYTES: usize = 64;

/// Maximum VRF proof size (bytes).
pub const MAX_VRF_PROOF_BYTES: usize = 1_024;

/// Maximum Bulletproof range proof per output (bytes).
pub const MAX_RANGE_PROOF_BYTES: usize = 674;

// ── Economics ─────────────────────────────────────────────────────────────────

/// Genesis supply in INDRA (human-readable unit).
pub const GENESIS_SUPPLY_INDRA: u64 = 1_000_000_000;

/// Default testnet chain ID — matches genesis.toml.example.
pub const DEFAULT_CHAIN_ID: &str = "indra-testnet-1";

/// Spark per INDRA — 8 decimal places (matches Bitcoin's satoshi model).
pub const SPARK_PER_INDRA: u64 = 100_000_000;

/// Genesis supply in Spark. All 1 billion INDRA are pre-minted at genesis.
pub const GENESIS_SUPPLY_SPARK: u64 = GENESIS_SUPPLY_INDRA * SPARK_PER_INDRA;

/// Hard cap in Spark. Total supply can only decrease via fee burn.
pub const HARD_CAP_SPARK: u64 = GENESIS_SUPPLY_SPARK;

/// Minimum UTXO value in Spark. Outputs below this are rejected.
pub const DUST_LIMIT_SPARK: u64 = 100_000;

/// Minimum validator self-bond required for registration.
pub const MINIMUM_VALIDATOR_BOND_SPARK: u64 = 1_000_000_000;

/// Maximum governance-set global delegation floor.
///
/// The delegation floor may be raised for spam resistance, but it must not be
/// raised above the minimum cost to register a validator. Otherwise governance
/// could effectively disable ordinary delegation while validator registration
/// remains cheaper than delegating.
pub const MAX_DELEGATION_SPARK: u64 = MINIMUM_VALIDATOR_BOND_SPARK;

/// Minimum active validator self-stake required to remain in the active set.
///
/// Falling below this floor after self-unstaking demotes the validator back to
/// `Registered` immediately; it can re-enter the active set after adding enough
/// self-stake and the next active-set selection.
pub const MINIMUM_ACTIVE_SELF_STAKE_SPARK: u64 = MINIMUM_VALIDATOR_BOND_SPARK;

/// Blocks per year assuming a 6 second target block time.
pub const BLOCKS_PER_YEAR: u64 = 5_256_000;

/// Blocks per era for Eras 1 and 2 (4 years each).
pub const ERA_1_2_DURATION_BLOCKS: u64 = BLOCKS_PER_YEAR * 4;

/// Blocks per era for Era 3+ (8 years each).
pub const ERA_3_PLUS_DURATION_BLOCKS: u64 = BLOCKS_PER_YEAR * 8;

/// Era 1 block reward in Spark.
pub const ERA_1_BLOCK_REWARD_SPARK: u64 = 1_189_200_000;

/// Era 2 block reward in Spark.
pub const ERA_2_BLOCK_REWARD_SPARK: u64 = ERA_1_BLOCK_REWARD_SPARK / 2;

/// Era 3 block reward in Spark.
pub const ERA_3_BLOCK_REWARD_SPARK: u64 = ERA_2_BLOCK_REWARD_SPARK / 2;

/// Era 4 block reward in Spark.
pub const ERA_4_BLOCK_REWARD_SPARK: u64 = ERA_3_BLOCK_REWARD_SPARK / 2;

/// Era 5 block reward in Spark.
pub const ERA_5_BLOCK_REWARD_SPARK: u64 = ERA_4_BLOCK_REWARD_SPARK / 2;

/// All 1,000,000,000 INDRA are earned through block rewards.
/// No pre-allocation to any person or entity.
pub const VALIDATOR_REWARDS_POOL_SPARK: u64 = 1_000_000_000 * SPARK_PER_INDRA;

/// Fraction of transaction fees burned (basis points).
pub const FEE_BURN_BPS: u32 = 5_000;

/// Fraction of transaction fees distributed to validators (basis points).
pub const FEE_VALIDATOR_BPS: u32 = 5_000;

/// Soft target for the number of active validators.
pub const TARGET_VALIDATOR_COUNT: u64 = 200;

/// Saturation is disabled until the active validator set reaches this size.
pub const SATURATION_MIN_VALIDATORS: u64 = 20;

/// Minimum active validator set size (bootstrap phase).
pub const MIN_ACTIVE_VALIDATORS: usize = 4;

/// Maximum active validator set size (mature network).
pub const MAX_ACTIVE_VALIDATORS: usize = 200;

/// Target active validator set size for QC size management.
pub const TARGET_VALIDATOR_SET_SIZE: u64 = 150;

/// Phase 1 total-stake threshold for validator set expansion.
pub const VALIDATOR_SET_PHASE1_STAKE: u64 = 1_000_000 * SPARK_PER_INDRA;

/// Phase 2 total-stake threshold for validator set expansion.
pub const VALIDATOR_SET_PHASE2_STAKE: u64 = 10_000_000 * SPARK_PER_INDRA;

/// Phase 3 total-stake threshold for validator set expansion.
pub const VALIDATOR_SET_PHASE3_STAKE: u64 = 50_000_000 * SPARK_PER_INDRA;

/// Maximum active validators during Phase 1.
pub const VALIDATOR_SET_PHASE1_MAX: usize = 20;

/// Maximum active validators during Phase 2.
pub const VALIDATOR_SET_PHASE2_MAX: usize = 50;

/// Maximum active validators during Phase 3.
pub const VALIDATOR_SET_PHASE3_MAX: usize = 100;

/// Maximum active validators during Phase 4.
pub const VALIDATOR_SET_PHASE4_MAX: usize = 200;

/// Maximum validators that may appear in a single QC.
pub const MAX_QC_SIGNERS: usize = MAX_ACTIVE_VALIDATORS;

/// Compute the maximum active validator set size from total staked supply.
pub fn max_active_validators(total_staked_spark: u64) -> usize {
    if total_staked_spark < VALIDATOR_SET_PHASE1_STAKE {
        VALIDATOR_SET_PHASE1_MAX
    } else if total_staked_spark < VALIDATOR_SET_PHASE2_STAKE {
        VALIDATOR_SET_PHASE2_MAX
    } else if total_staked_spark < VALIDATOR_SET_PHASE3_STAKE {
        VALIDATOR_SET_PHASE3_MAX
    } else {
        VALIDATOR_SET_PHASE4_MAX
    }
}

/// Compute the current validator-set growth phase from total staked supply.
pub fn validator_set_phase(total_staked_spark: u64) -> u8 {
    if total_staked_spark < VALIDATOR_SET_PHASE1_STAKE {
        1
    } else if total_staked_spark < VALIDATOR_SET_PHASE2_STAKE {
        2
    } else if total_staked_spark < VALIDATOR_SET_PHASE3_STAKE {
        3
    } else {
        4
    }
}

/// Multiply two u64 values and divide by a third using a u128 intermediate.
///
/// Returns 0 when `c` is 0. This is the canonical helper for proportional
/// Spark calculations such as `reward * stake / total_stake`.
pub fn muldiv(a: u64, b: u64, c: u64) -> u64 {
    if c == 0 {
        return 0;
    }
    ((a as u128) * (b as u128) / (c as u128)) as u64
}

/// Calculate a basis-point portion using a u128 intermediate.
pub fn bps_of(value: u64, bps: u32) -> u64 {
    ((value as u128) * (bps as u128) / 10_000u128) as u64
}

/// Consensus hard-fork activation heights.
///
/// Testnet activates existing arithmetic fixes from genesis. Mainnet values
/// must be set and announced before the corresponding release is deployed.
pub mod hard_forks {
    /// u128 intermediate arithmetic for proportional reward and slash math.
    pub const OVERFLOW_FIX_HEIGHT: u64 = 0;
    /// Proposer election uses verified VRF output instead of public key grinding hashes.
    pub const VRF_VERIFIED_OUTPUT_HEIGHT: u64 = 0;
    /// Quorum certificates require both Ed25519 and ML-DSA vote signatures.
    pub const HYBRID_QC_HEIGHT: u64 = 0;
    /// Vote signatures include the chain ID in their signing domain.
    pub const VOTE_CHAIN_ID_HEIGHT: u64 = 0;
    /// Proposer election uses a fully public deterministic score.
    ///
    /// Testnet activates this from genesis after a fresh reset. Mainnet may
    /// choose a future height if migrating an existing chain.
    pub const PUBLIC_PROPOSER_ELECTION_HEIGHT: u64 = 0;
}

/// Whether proportional arithmetic uses the overflow-safe implementation.
#[inline]
pub fn overflow_fix_active(height: u64) -> bool {
    height >= hard_forks::OVERFLOW_FIX_HEIGHT
}

/// Whether proposer election must use verified VRF output when available.
#[inline]
pub fn vrf_verified_output_active(height: u64) -> bool {
    height >= hard_forks::VRF_VERIFIED_OUTPUT_HEIGHT
}

/// Whether QCs must carry and verify both classical and PQ vote signatures.
#[inline]
pub fn hybrid_qc_active(height: u64) -> bool {
    height >= hard_forks::HYBRID_QC_HEIGHT
}

/// Whether vote signatures must include the chain ID in their signing bytes.
#[inline]
pub fn vote_chain_id_active(height: u64) -> bool {
    height >= hard_forks::VOTE_CHAIN_ID_HEIGHT
}

/// Whether proposer election must use the fully public deterministic score.
#[inline]
pub fn public_proposer_election_active(height: u64) -> bool {
    height >= hard_forks::PUBLIC_PROPOSER_ELECTION_HEIGHT
}

// ── Pruning ───────────────────────────────────────────────────────────────────

/// Default number of blocks to retain in pruned mode.
pub const DEFAULT_PRUNE_KEEP_BLOCKS: u64 = 50_000;

/// Minimum number of blocks to keep when pruning.
pub const MIN_PRUNE_KEEP_BLOCKS: u64 = 1_000;

/// Disk space warning threshold in bytes (5 GB).
pub const DISK_WARN_THRESHOLD_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// Disk space critical threshold in bytes (500 MB).
pub const DISK_CRITICAL_THRESHOLD_BYTES: u64 = 500 * 1024 * 1024;

/// Slash for intentional double-signing (equivocation), in basis points.
/// 1000 bps = 10% of stake burned.
///
/// ## Slashing philosophy (v7.1)
///
/// INDRA does NOT slash validators for being offline.
/// Offline validators simply earn no rewards — the economic
/// incentive to stay online is sufficient without punitive slashing.
///
/// This follows Bitcoin's model: miners who stop mining earn nothing,
/// but are not penalised for stopping. Validators who go offline earn
/// nothing, but their stake is not burned.
///
/// The ONLY slashable offence is intentional equivocation:
/// signing two different blocks at the same height (double-sign).
/// This is an unambiguous malicious act that threatens consensus safety.
/// All other failures (missed blocks, downtime, crashes) result only
/// in lost rewards for the affected epochs.
///
/// Rationale:
/// - A validator who can only run 4 hours/day should be welcome.
///   They earn proportionally. They are not punished.
/// - Infrastructure failures (crashes, ISP outages) should not
///   destroy a validator's stake. This would centralise validation
///   toward only large professional operators with redundant infra.
/// - Liveness is maintained by the economic incentive to earn rewards,
///   not by the threat of stake destruction.
pub const SLASH_DOUBLE_SIGN_BPS: u32 = 1_000;

/// Initial base fee in Spark per KB.
pub const INITIAL_BASE_FEE_SPARK_PER_KB: u64 = 100;

/// Minimum base fee in Spark per KB.
pub const MIN_BASE_FEE_SPARK_PER_KB: u64 = 10;

/// EIP-1559 adjustment numerator (κ = 0.125 = 125/1000).
pub const FEE_ADJUST_NUMERATOR: u64 = 125;

/// EIP-1559 adjustment denominator.
pub const FEE_ADJUST_DENOMINATOR: u64 = 1_000;

/// Target block utilisation numerator (50%).
pub const TARGET_UTILISATION_NUMERATOR: u64 = 50;

/// Target block utilisation denominator.
pub const TARGET_UTILISATION_DENOMINATOR: u64 = 100;

// ── Governance ────────────────────────────────────────────────────────────────

/// Deprecated legacy governance quorum constant.
///
/// Current governance uses `GovernableParams::governance_quorum_bps` and
/// `governance_critical_quorum_bps` instead.
#[deprecated(note = "superseded by GovernableParams governance quorum fields")]
pub const QUORUM_THRESHOLD_BPS: u32 = 3_300;
/// Consensus quorum threshold — strictly more than 2/3 of stake must agree
/// for a block to be finalised.
pub const CONSENSUS_QUORUM_BPS: u32 = 6_667;

/// Deprecated legacy governance pass threshold.
///
/// Current governance requires yes stake to exceed the per-proposal total-stake
/// quorum in `GovernableParams`.
#[deprecated(note = "superseded by GovernableParams governance quorum fields")]
pub const PASS_THRESHOLD_BPS: u32 = 6_600; // reduced from 8000 — 80% impossible at 500+ validators

/// Minimum validator commission rate in basis points (500 = 5%).
/// Validators cannot undercut this — prevents race-to-zero on delegator fees.
pub const MIN_COMMISSION_BPS: u32 = 500;

/// Maximum validator commission rate in basis points (2000 = 20%).
/// Set by governance — prevents validators extracting excessive rent.
pub const MAX_COMMISSION_BPS: u32 = 2_000;

/// Default commission rate for validators that do not set one explicitly.
pub const DEFAULT_COMMISSION_BPS: u32 = 1_000;

/// Epoch delay before a requested validator commission change takes effect.
///
/// This gives delegators a small observation/exit window before a validator's
/// new commission rate affects reward distribution.
pub const COMMISSION_CHANGE_DELAY_EPOCHS: u64 = 2;

/// Veto threshold — if this fraction of total stake votes No, the proposal fails
/// regardless of the yes percentage. Prevents minority capture via voter apathy.
/// A coordinated third of stake can block any proposal (lazy-majority attack defence).
pub const VETO_THRESHOLD_BPS: u32 = 3_300;
/// Minimum validator commission rate in basis points (500 = 5%).
/// Validators cannot undercut this — prevents race-to-zero on delegator fees.
/// Veto threshold — if this fraction of total stake votes No, the proposal fails
/// regardless of the yes percentage. Prevents minority capture via voter apathy.
/// At 33%: a coordinated 1/3 of stake can block any proposal (lazy-majority attack defence).
/// Required YES fraction of total stake for emergency proposals (9000 = 90.00%).
pub const EMERGENCY_PASS_BPS: u32 = 9_000;

/// Epochs before governance changes take effect.
pub const GOVERNANCE_DELAY_EPOCHS: u64 = 100;

// ── Networking ────────────────────────────────────────────────────────────────

/// Minimum outbound peer connections.
pub const MIN_OUTBOUND_PEERS: usize = 8;

/// Default DNS seed hostname for peer discovery.
pub const DNS_SEED_HOST: &str = "seeds.indraprotocol.com";

/// Maximum peers to share in a single PeerList message.
pub const MAX_PEER_LIST_SIZE: usize = 20;

/// Interval between peer list announcements to the same peer (seconds).
pub const PEER_LIST_INTERVAL_SECS: u64 = 60;

/// Target number of outbound connections to maintain.
pub const TARGET_OUTBOUND_PEERS: usize = 8;

/// Maximum outbound peer connections.
pub const MAX_OUTBOUND_PEERS: usize = 16;

/// Maximum inbound peer connections.
pub const MAX_INBOUND_PEERS: usize = 64;

/// Default observer/full-node P2P port.
pub const OBSERVER_PORT: u16 = 30304;

/// Maximum concurrent observer connections per validator.
pub const MAX_OBSERVER_CONNECTIONS: usize = 256;

/// Observer handshake timeout in seconds.
pub const OBSERVER_HANDSHAKE_TIMEOUT_SECS: u64 = 5;

/// Seconds between observer liveness pings.
pub const OBSERVER_PING_INTERVAL_SECS: u64 = 30;

/// Seconds to wait for observer pong before reconnecting.
pub const OBSERVER_PONG_TIMEOUT_SECS: u64 = 10;

/// Peer table persistence interval (seconds).
pub const PEER_TABLE_SAVE_INTERVAL_SECS: u64 = 1800;

/// Maximum messages per second from one peer before rate limiting.
pub const MAX_MSG_PER_SEC: u32 = 100;

/// Maximum bytes per second from one peer.
pub const MAX_BYTES_PER_SEC: u32 = 5_242_880; // 5 MB/s

/// Epochs a banned peer remains banned.
pub const BAN_DURATION_EPOCHS: u64 = 10;

/// Block pruning window in epochs.
pub const PRUNE_WINDOW_EPOCHS: u64 = 500;

// ── Protocol Version ──────────────────────────────────────────────────────────

/// The only protocol version this implementation supports.
pub const PROTOCOL_VERSION: u16 = 1;

/// Current schema version for all persisted structs.
///
/// Increment this whenever any persisted struct changes its encoding.
pub const SCHEMA_VERSION: u8 = 3;

/// The schema version when INDRA was first deployed.
pub const SCHEMA_VERSION_GENESIS: u8 = 1;

// =============================================================================
// PRIMITIVE TYPES
// =============================================================================

/// A fixed 32-byte value (block hash, state root, nullifier, UTXO ID, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Bytes32(pub [u8; 32]);
impl Bytes32 {
    /// The all-zero value.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Create from a byte array.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// View as a fixed-size array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// View as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Encode for Bytes32 {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
    fn encoded_len(&self) -> usize {
        32
    }
}

impl Decode for Bytes32 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self(r.read_bytes32()?))
    }
}

impl AsRef<[u8]> for Bytes32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Bytes32 {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl core::fmt::Display for Bytes32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A variable-length byte sequence with a protocol-enforced maximum size.
///
/// Encoded as: `u32_le(length) || data[0..length]`
///
/// The `MAX` const generic enforces the limit at the type level —
/// it is impossible to construct an oversized `VariableBytes<MAX>`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VariableBytes<const MAX: usize>(Vec<u8>);

impl<const MAX: usize> VariableBytes<MAX> {
    /// Construct from a Vec, enforcing the length limit.
    pub fn new(data: Vec<u8>) -> IndraResult<Self> {
        if data.len() > MAX {
            return Err(IndraError::LengthExceeded {
                field: "VariableBytes",
                max: MAX,
                actual: data.len(),
            });
        }
        Ok(Self(data))
    }

    /// Construct from a slice.
    pub fn from_slice(data: &[u8]) -> IndraResult<Self> {
        Self::new(data.to_vec())
    }

    /// Byte length.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// View as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Consume and return the inner Vec.
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl<const MAX: usize> Encode for VariableBytes<MAX> {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.0.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.0);
    }
    fn encoded_len(&self) -> usize {
        4 + self.0.len()
    }
}

impl<const MAX: usize> Decode for VariableBytes<MAX> {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let len = r.read_u32_le()? as usize;
        if len > MAX {
            return Err(IndraError::LengthExceeded {
                field: "VariableBytes",
                max: MAX,
                actual: len,
            });
        }
        let bytes = r.read_bytes(len)?;
        Ok(Self(bytes.to_vec()))
    }
}

/// Protocol version wrapper with validation on decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolVersion(pub u16);

impl ProtocolVersion {
    /// The version this implementation supports.
    pub const CURRENT: Self = Self(PROTOCOL_VERSION);

    /// True if this version is supported.
    pub fn is_supported(&self) -> bool {
        self.0 == PROTOCOL_VERSION
    }
}

impl Encode for ProtocolVersion {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0.to_le_bytes());
    }
    fn encoded_len(&self) -> usize {
        2
    }
}

impl Decode for ProtocolVersion {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let v = r.read_u16_le()?;
        if v != PROTOCOL_VERSION {
            return Err(IndraError::UnsupportedVersion { version: v });
        }
        Ok(Self(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Decode;

    #[test]
    fn bytes32_round_trip() {
        let b = Bytes32::from([0xABu8; 32]);
        let enc = b.encode_to_vec();
        assert_eq!(enc.len(), 32);
        assert_eq!(Bytes32::decode_exact(&enc).unwrap(), b);
    }

    #[test]
    fn bytes32_zero_is_all_zeros() {
        assert_eq!(Bytes32::ZERO.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn variable_bytes_round_trip() {
        let vb: VariableBytes<100> = VariableBytes::from_slice(b"hello INDRA").unwrap();
        let enc = vb.encode_to_vec();
        let dec: VariableBytes<100> = VariableBytes::decode_exact(&enc).unwrap();
        assert_eq!(vb, dec);
    }

    #[test]
    fn variable_bytes_too_large_rejected() {
        let data = vec![0u8; 101];
        assert!(VariableBytes::<100>::new(data).is_err());
    }

    #[test]
    fn protocol_version_current_round_trip() {
        let v = ProtocolVersion::CURRENT;
        let enc = v.encode_to_vec();
        assert_eq!(ProtocolVersion::decode_exact(&enc).unwrap(), v);
    }

    #[test]
    fn protocol_version_wrong_version_rejected() {
        let bad = 99u16.to_le_bytes();
        assert!(ProtocolVersion::decode_exact(&bad).is_err());
    }

    #[test]
    fn economics_constants_consistent() {
        assert_eq!(
            VALIDATOR_REWARDS_POOL_SPARK, GENESIS_SUPPLY_SPARK,
            "All INDRA must be in the validator rewards pool — no pre-mine"
        );
        assert_eq!(HARD_CAP_SPARK, GENESIS_SUPPLY_SPARK);
        assert_eq!(GENESIS_SUPPLY_SPARK, GENESIS_SUPPLY_INDRA * SPARK_PER_INDRA);
        assert_eq!(FEE_BURN_BPS + FEE_VALIDATOR_BPS, 10_000);
        let era_1_total = ERA_1_2_DURATION_BLOCKS * ERA_1_BLOCK_REWARD_SPARK;
        let era_1_indra = era_1_total / SPARK_PER_INDRA;
        assert!(
            (248_000_000..=252_000_000).contains(&era_1_indra),
            "Era 1 total INDRA out of range: {}",
            era_1_indra
        );
        assert_eq!(SPARK_PER_INDRA, 100_000_000);
        assert!(VALIDATOR_SET_PHASE1_STAKE < VALIDATOR_SET_PHASE2_STAKE);
        assert!(VALIDATOR_SET_PHASE2_STAKE < VALIDATOR_SET_PHASE3_STAKE);
        assert!(VALIDATOR_SET_PHASE1_MAX < VALIDATOR_SET_PHASE2_MAX);
        assert!(VALIDATOR_SET_PHASE2_MAX < VALIDATOR_SET_PHASE3_MAX);
        assert!(VALIDATOR_SET_PHASE3_MAX < VALIDATOR_SET_PHASE4_MAX);
        assert!(VALIDATOR_SET_PHASE4_MAX <= MAX_QC_SIGNERS);
        assert!(AUTH_WINDOW_EPOCHS >= UNBONDING_PERIOD_EPOCHS);
        assert!(SLASH_EVIDENCE_WINDOW_EPOCHS <= UNBONDING_PERIOD_EPOCHS);
    }

    #[test]
    fn validator_set_sizing_consistent() {
        assert_eq!(max_active_validators(0), VALIDATOR_SET_PHASE1_MAX);
        assert_eq!(
            max_active_validators(VALIDATOR_SET_PHASE1_STAKE - 1),
            VALIDATOR_SET_PHASE1_MAX
        );
        assert_eq!(
            max_active_validators(VALIDATOR_SET_PHASE1_STAKE),
            VALIDATOR_SET_PHASE2_MAX
        );
        assert_eq!(
            max_active_validators(VALIDATOR_SET_PHASE2_STAKE - 1),
            VALIDATOR_SET_PHASE2_MAX
        );
        assert_eq!(
            max_active_validators(VALIDATOR_SET_PHASE2_STAKE),
            VALIDATOR_SET_PHASE3_MAX
        );
        assert_eq!(
            max_active_validators(VALIDATOR_SET_PHASE3_STAKE - 1),
            VALIDATOR_SET_PHASE3_MAX
        );
        assert_eq!(
            max_active_validators(VALIDATOR_SET_PHASE3_STAKE),
            VALIDATOR_SET_PHASE4_MAX
        );
        assert_eq!(max_active_validators(u64::MAX), VALIDATOR_SET_PHASE4_MAX);
        assert!(MAX_QC_SIGNERS >= VALIDATOR_SET_PHASE4_MAX);
        assert!(MIN_ACTIVE_VALIDATORS <= VALIDATOR_SET_PHASE1_MAX);
    }

    #[test]
    fn overflow_fix_activates_at_correct_height() {
        assert!(overflow_fix_active(0));
        assert!(overflow_fix_active(1));
        assert!(overflow_fix_active(25_932));
        assert!(overflow_fix_active(u64::MAX));
    }
}
