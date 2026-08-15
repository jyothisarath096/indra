//! Epoch history records.

use crate::{
    codec::{decode_list, encode_list, list_encoded_len, ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    types::primitives::{Bytes32, MAX_VALIDATORS, SCHEMA_VERSION},
};

/// A complete summary of one epoch's activity, written at epoch transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochRecord {
    /// Epoch number (0-indexed).
    pub epoch: u64,
    /// First block height of this epoch.
    pub start_height: u64,
    /// Last block height of this epoch.
    pub end_height: u64,
    /// Unix timestamp of the epoch transition.
    pub timestamp_secs: u64,
    /// Number of active validators during this epoch.
    pub active_validators: u32,
    /// Total Spark staked at epoch start.
    pub total_staked_spark: u64,
    /// Total block rewards distributed this epoch in Spark.
    pub block_rewards_distributed: u64,
    /// Total fee rewards distributed this epoch in Spark.
    pub fee_rewards_distributed: u64,
    /// Total Spark burned via fee burn this epoch.
    pub fees_burned: u64,
    /// Total Spark burned from governance proposal deposits this epoch.
    pub governance_deposits_burned: u64,
    /// Total Spark slashed this epoch.
    pub total_slashed_spark: u64,
    /// Number of slash events this epoch.
    pub slash_event_count: u32,
    /// Number of liveness penalties applied this epoch.
    pub liveness_penalty_count: u32,
    /// Average base fee during this epoch in Spark/KB.
    pub avg_base_fee: u64,
    /// Validators that joined the active set this epoch.
    pub validators_joined: Vec<Bytes32>,
    /// Validators that left the active set this epoch.
    pub validators_left: Vec<Bytes32>,
    /// Era number at this epoch.
    pub era: u64,
    /// Block reward at `start_height` in Spark.
    ///
    /// An epoch that crosses a monetary-era boundary can contain more than one
    /// rate. In that case this field remains the starting rate while
    /// `block_rewards_distributed` records the exact mixed-rate total.
    pub block_reward_spark: u64,
    /// Total supply at end of epoch.
    pub total_supply: u64,
    /// Treasury balance at end of epoch.
    pub treasury_balance: u64,
}

impl Encode for EpochRecord {
    fn encode(&self, buf: &mut Vec<u8>) {
        SCHEMA_VERSION.encode(buf);
        self.epoch.encode(buf);
        self.start_height.encode(buf);
        self.end_height.encode(buf);
        self.timestamp_secs.encode(buf);
        self.active_validators.encode(buf);
        self.total_staked_spark.encode(buf);
        self.block_rewards_distributed.encode(buf);
        self.fee_rewards_distributed.encode(buf);
        self.fees_burned.encode(buf);
        self.governance_deposits_burned.encode(buf);
        self.total_slashed_spark.encode(buf);
        self.slash_event_count.encode(buf);
        self.liveness_penalty_count.encode(buf);
        self.avg_base_fee.encode(buf);
        encode_list(&self.validators_joined, buf);
        encode_list(&self.validators_left, buf);
        self.era.encode(buf);
        self.block_reward_spark.encode(buf);
        self.total_supply.encode(buf);
        self.treasury_balance.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        1 + 15 * 8
            + 3 * 4
            + list_encoded_len(&self.validators_joined)
            + list_encoded_len(&self.validators_left)
    }
}

impl Decode for EpochRecord {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let schema_version = u8::decode(r)?;
        if schema_version != SCHEMA_VERSION {
            return Err(IndraError::UnsupportedSchemaVersion {
                struct_name: "EpochRecord",
                version: schema_version,
                max_supported: SCHEMA_VERSION,
            });
        }
        decode_epoch_record(r)
    }
}

fn decode_epoch_record(r: &mut ByteReader<'_>) -> IndraResult<EpochRecord> {
    Ok(EpochRecord {
        epoch: u64::decode(r)?,
        start_height: u64::decode(r)?,
        end_height: u64::decode(r)?,
        timestamp_secs: u64::decode(r)?,
        active_validators: u32::decode(r)?,
        total_staked_spark: u64::decode(r)?,
        block_rewards_distributed: u64::decode(r)?,
        fee_rewards_distributed: u64::decode(r)?,
        fees_burned: u64::decode(r)?,
        governance_deposits_burned: u64::decode(r)?,
        total_slashed_spark: u64::decode(r)?,
        slash_event_count: u32::decode(r)?,
        liveness_penalty_count: u32::decode(r)?,
        avg_base_fee: u64::decode(r)?,
        validators_joined: decode_list(r, MAX_VALIDATORS, "epoch.validators_joined")?,
        validators_left: decode_list(r, MAX_VALIDATORS, "epoch.validators_left")?,
        era: u64::decode(r)?,
        block_reward_spark: u64::decode(r)?,
        total_supply: u64::decode(r)?,
        treasury_balance: u64::decode(r)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> EpochRecord {
        EpochRecord {
            epoch: 4,
            start_height: 1_200,
            end_height: 1_499,
            timestamp_secs: 1_750_000_000,
            active_validators: 4,
            total_staked_spark: 400_000_000_000,
            block_rewards_distributed: 356_760_000_000,
            fee_rewards_distributed: 123,
            fees_burned: 456,
            governance_deposits_burned: 123,
            total_slashed_spark: 789,
            slash_event_count: 2,
            liveness_penalty_count: 1,
            avg_base_fee: 10,
            validators_joined: vec![Bytes32::from([1u8; 32]), Bytes32::from([2u8; 32])],
            validators_left: vec![Bytes32::from([3u8; 32])],
            era: 1,
            block_reward_spark: 1_189_200_000,
            total_supply: 100_000_000_000_000_000,
            treasury_balance: 42,
        }
    }

    #[test]
    fn epoch_record_encode_decode_round_trip() {
        let record = sample_record();
        let bytes = record.encode_to_vec();
        let mut reader = ByteReader::new(&bytes);
        let decoded = EpochRecord::decode(&mut reader).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn epoch_record_empty_validator_changes_round_trip() {
        let mut record = sample_record();
        record.validators_joined.clear();
        record.validators_left.clear();
        let bytes = record.encode_to_vec();
        let mut reader = ByteReader::new(&bytes);
        let decoded = EpochRecord::decode(&mut reader).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn epoch_record_encoded_len_is_accurate() {
        let record = sample_record();
        assert_eq!(record.encoded_len(), record.encode_to_vec().len());
    }
}
