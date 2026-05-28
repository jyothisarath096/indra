//! Primitive types and all INDRA v2 protocol constants.
//!
//! Every protocol constant is defined here and referenced by name everywhere
//! else. No magic numbers appear elsewhere in the codebase.

use crate::{
    codec::{Encode, Decode, ByteReader},
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
pub const UNBONDING_PERIOD_EPOCHS: u64 = 60; // reduced from 200 — 30 days vs 100 days, industry standard

/// Epochs after exit during which a validator's signatures remain valid.
/// AUTH_WINDOW = UNBONDING_PERIOD + 100
pub const AUTH_WINDOW_EPOCHS: u64 = 160; // reduced with unbonding — unbonding(60) + buffer(100)

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

/// Epochs delay before a governance-approved timeout change takes effect.
pub const TIMEOUT_CHANGE_DELAY_EPOCHS: u64 = 100;

// ── Slashing ──────────────────────────────────────────────────────────────────

/// Slash fraction for double precommit: 10% (1000 basis points out of 10000).
pub const SLASH_DOUBLE_PRECOMMIT_BPS: u32 = 1_000;

/// Slash fraction for surround vote: 100% (10000 / 10000).
pub const SLASH_SURROUND_VOTE_BPS: u32 = 10_000;

/// Grace period (epochs) for a self-reported software-bug slash.
pub const SLASH_GRACE_PERIOD_EPOCHS: u64 = 5;

// ── Block and Transaction Limits ──────────────────────────────────────────────

/// Maximum block size in bytes.
pub const MAX_BLOCK_SIZE_BYTES: usize = 1_048_576; // 1 MB

/// Maximum transactions per block.
pub const MAX_TX_PER_BLOCK: usize = 200;

/// Maximum inputs per transaction.
pub const MAX_INPUTS: usize = 16;

/// Maximum outputs per transaction.
pub const MAX_OUTPUTS: usize = 16;

/// Maximum quorum certificate size in bytes.
pub const MAX_QC_SIZE_BYTES: usize = 2_097_152; // 2 MB

/// Maximum slash evidence entries per block.
pub const MAX_SLASHES_PER_BLOCK: usize = 10;

/// Maximum governance operations per block.
pub const MAX_GOV_OPS_PER_BLOCK: usize = 5;

// ── Cryptographic Size Bounds ─────────────────────────────────────────────────

/// Maximum Ed25519 signature size (bytes).
pub const MAX_CLASSICAL_SIG_BYTES: usize = 64;

/// Maximum Dilithium2 signature size (bytes).
pub const MAX_PQ_SIG_BYTES: usize = 2_500;

/// Maximum Dilithium2 public key size (bytes).
pub const MAX_PQ_PK_BYTES: usize = 1_400;

/// Maximum VRF proof size (bytes).
pub const MAX_VRF_PROOF_BYTES: usize = 1_024;

/// Maximum Bulletproof range proof per output (bytes).
pub const MAX_RANGE_PROOF_BYTES: usize = 674;

/// Maximum governance operation payload (bytes).
pub const MAX_GOV_PAYLOAD_BYTES: usize = 4_096;

// ── Economics ─────────────────────────────────────────────────────────────────

/// Genesis supply in INDRA (human-readable unit).
pub const GENESIS_SUPPLY_INDRA: u64 = 1_000_000_000;

/// Spark per INDRA — 8 decimal places (matches Bitcoin's satoshi model).
pub const SPARK_PER_INDRA: u64 = 100_000_000;

/// Genesis supply in Spark. All 1 billion INDRA are pre-minted at genesis.
pub const GENESIS_SUPPLY_SPARK: u64 = GENESIS_SUPPLY_INDRA * SPARK_PER_INDRA;

/// Hard cap in Spark. Total supply can only decrease via fee burn.
pub const HARD_CAP_SPARK: u64 = GENESIS_SUPPLY_SPARK;

/// Minimum validator stake in INDRA.
pub const MIN_STAKE_INDRA: u64 = 100_000;

/// Minimum validator stake in Spark.
pub const MIN_STAKE_SPARK: u64 = MIN_STAKE_INDRA * SPARK_PER_INDRA;

/// Minimum UTXO value in Spark. Outputs below this are rejected.
pub const DUST_LIMIT_SPARK: u64 = 100_000;

/// Blocks per year assuming a 6 second target block time.
pub const BLOCKS_PER_YEAR: u64 = 5_256_000;

/// Blocks per era for Eras 1 and 2 (4 years each).
pub const ERA_1_2_DURATION_BLOCKS: u64 = BLOCKS_PER_YEAR * 4;

/// Blocks per era for Era 3+ (8 years each).
pub const ERA_3_PLUS_DURATION_BLOCKS: u64 = BLOCKS_PER_YEAR * 8;

/// Era 1 block reward in Spark.
pub const ERA_1_BLOCK_REWARD_SPARK: u64 = 1_129_700_000;

/// Era 2 block reward in Spark.
pub const ERA_2_BLOCK_REWARD_SPARK: u64 = ERA_1_BLOCK_REWARD_SPARK / 2;

/// Era 3 block reward in Spark.
pub const ERA_3_BLOCK_REWARD_SPARK: u64 = ERA_2_BLOCK_REWARD_SPARK / 2;

/// Era 4 block reward in Spark.
pub const ERA_4_BLOCK_REWARD_SPARK: u64 = ERA_3_BLOCK_REWARD_SPARK / 2;

/// Era 5 block reward in Spark.
pub const ERA_5_BLOCK_REWARD_SPARK: u64 = ERA_4_BLOCK_REWARD_SPARK / 2;

/// Total validator rewards pool in Spark (95% of genesis supply).
pub const VALIDATOR_REWARDS_POOL_SPARK: u64 = 950_000_000 * SPARK_PER_INDRA;

/// Operational bootstrap allocation in Spark (5% of genesis supply).
pub const OPERATIONAL_BOOTSTRAP_SPARK: u64 = 50_000_000 * SPARK_PER_INDRA;

/// Fraction of transaction fees burned (basis points).
pub const FEE_BURN_BPS: u32 = 5_000;

/// Fraction of transaction fees distributed to validators (basis points).
pub const FEE_VALIDATOR_BPS: u32 = 5_000;

/// Soft target for the number of active validators.
pub const TARGET_VALIDATOR_COUNT: u64 = 200;

/// Target active validator set size for QC size management.
pub const TARGET_VALIDATOR_SET_SIZE: u64 = 150;

/// Maximum validators that may appear in a single QC.
pub const MAX_QC_SIGNERS: usize = 200;

/// Slash for repeated missed blocks (>10% proposals missed), in basis points.
pub const SLASH_REPEATED_MISS_BPS: u32 = 1;

/// Slash for 24 consecutive hours offline, in basis points.
pub const SLASH_OFFLINE_24H_BPS: u32 = 50;

/// Slash for 7 consecutive days offline, in basis points.
pub const SLASH_OFFLINE_7D_BPS: u32 = 200;

/// Slash for intentional double-signing, in basis points.
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

/// Minimum stake participation for a vote to be valid (3300 = 33.00%).
pub const QUORUM_THRESHOLD_BPS: u32 = 3_300;
/// Consensus quorum threshold — strictly more than 2/3 of stake must agree
/// for a block to be finalised.
pub const CONSENSUS_QUORUM_BPS: u32 = 6_667;

/// Required YES fraction of participating stake to pass (8000 = 80.00%).
pub const PASS_THRESHOLD_BPS: u32 = 6_600; // reduced from 8000 — 80% impossible at 500+ validators

/// Minimum validator commission rate in basis points (500 = 5%).
/// Validators cannot undercut this — prevents race-to-zero on delegator fees.
pub const MIN_COMMISSION_BPS: u32 = 500;

/// Maximum validator commission rate in basis points (2000 = 20%).
/// Set by governance — prevents validators extracting excessive rent.
pub const MAX_COMMISSION_BPS: u32 = 2_000;

/// Default commission rate for validators that do not set one explicitly.
pub const DEFAULT_COMMISSION_BPS: u32 = 1_000;

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

/// Maximum outbound peer connections.
pub const MAX_OUTBOUND_PEERS: usize = 16;

/// Maximum inbound peer connections.
pub const MAX_INBOUND_PEERS: usize = 64;

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
    pub fn from_bytes(b: [u8; 32]) -> Self { Self(b) }

    /// View as a fixed-size array.
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }

    /// View as a slice.
    pub fn as_slice(&self) -> &[u8] { &self.0 }
}

impl Encode for Bytes32 {
    fn encode(&self, buf: &mut Vec<u8>) { buf.extend_from_slice(&self.0); }
    fn encoded_len(&self) -> usize { 32 }
}

impl Decode for Bytes32 {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self(r.read_bytes32()?))
    }
}

impl AsRef<[u8]> for Bytes32 {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl From<[u8; 32]> for Bytes32 {
    fn from(b: [u8; 32]) -> Self { Self(b) }
}

impl core::fmt::Display for Bytes32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x")?;
        for b in &self.0 { write!(f, "{b:02x}")?; }
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
    pub fn len(&self) -> usize { self.0.len() }

    /// True if empty.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// View as a slice.
    pub fn as_slice(&self) -> &[u8] { &self.0 }

    /// Consume and return the inner Vec.
    pub fn into_vec(self) -> Vec<u8> { self.0 }
}

impl<const MAX: usize> Encode for VariableBytes<MAX> {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.0.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.0);
    }
    fn encoded_len(&self) -> usize { 4 + self.0.len() }
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
    pub fn is_supported(&self) -> bool { self.0 == PROTOCOL_VERSION }
}

impl Encode for ProtocolVersion {
    fn encode(&self, buf: &mut Vec<u8>) { buf.extend_from_slice(&self.0.to_le_bytes()); }
    fn encoded_len(&self) -> usize { 2 }
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
        assert_eq!(HARD_CAP_SPARK, GENESIS_SUPPLY_SPARK);
        assert_eq!(GENESIS_SUPPLY_SPARK, GENESIS_SUPPLY_INDRA * SPARK_PER_INDRA);
        assert_eq!(
            VALIDATOR_REWARDS_POOL_SPARK + OPERATIONAL_BOOTSTRAP_SPARK,
            GENESIS_SUPPLY_SPARK
        );
        assert_eq!(FEE_BURN_BPS + FEE_VALIDATOR_BPS, 10_000);
        let era_1_total = ERA_1_2_DURATION_BLOCKS * ERA_1_BLOCK_REWARD_SPARK;
        let era_1_indra = era_1_total / SPARK_PER_INDRA;
        assert!(
            (237_000_000..=238_000_000).contains(&era_1_indra),
            "Era 1 total INDRA out of range: {}",
            era_1_indra
        );
        assert_eq!(SPARK_PER_INDRA, 100_000_000);
        assert_eq!(MIN_STAKE_INDRA, 100_000);
        assert_eq!(MIN_STAKE_SPARK, MIN_STAKE_INDRA * SPARK_PER_INDRA);
        assert!(AUTH_WINDOW_EPOCHS >= UNBONDING_PERIOD_EPOCHS);
    }
}
