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
    /// Total rewards minted and distributed this epoch in Spark.
    pub reward_minted_spark: u64,
    /// Total fee rewards distributed this epoch in Spark.
    pub fee_rewards_distributed: u64,
    /// Total Spark burned via fee burn this epoch.
    pub fee_burned_spark: u64,
    /// Total Spark burned from validator principal this epoch.
    pub slash_burned_spark: u64,
    /// Total Spark burned from governance proposal deposits this epoch.
    pub governance_burned_spark: u64,
    /// Checked sum of every burn source this epoch.
    pub total_burned_spark: u64,
    /// Total supply at the beginning of the epoch.
    pub opening_total_supply_spark: u64,
    /// Total supply at the end of the epoch.
    pub closing_total_supply_spark: u64,
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
        self.reward_minted_spark.encode(buf);
        self.fee_rewards_distributed.encode(buf);
        self.fee_burned_spark.encode(buf);
        self.slash_burned_spark.encode(buf);
        self.governance_burned_spark.encode(buf);
        self.total_burned_spark.encode(buf);
        self.opening_total_supply_spark.encode(buf);
        self.closing_total_supply_spark.encode(buf);
        self.slash_event_count.encode(buf);
        self.liveness_penalty_count.encode(buf);
        self.avg_base_fee.encode(buf);
        encode_list(&self.validators_joined, buf);
        encode_list(&self.validators_left, buf);
        self.era.encode(buf);
        self.block_reward_spark.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        1 + 16 * 8
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
    let record = EpochRecord {
        epoch: u64::decode(r)?,
        start_height: u64::decode(r)?,
        end_height: u64::decode(r)?,
        timestamp_secs: u64::decode(r)?,
        active_validators: u32::decode(r)?,
        total_staked_spark: u64::decode(r)?,
        reward_minted_spark: u64::decode(r)?,
        fee_rewards_distributed: u64::decode(r)?,
        fee_burned_spark: u64::decode(r)?,
        slash_burned_spark: u64::decode(r)?,
        governance_burned_spark: u64::decode(r)?,
        total_burned_spark: u64::decode(r)?,
        opening_total_supply_spark: u64::decode(r)?,
        closing_total_supply_spark: u64::decode(r)?,
        slash_event_count: u32::decode(r)?,
        liveness_penalty_count: u32::decode(r)?,
        avg_base_fee: u64::decode(r)?,
        validators_joined: decode_list(r, MAX_VALIDATORS, "epoch.validators_joined")?,
        validators_left: decode_list(r, MAX_VALIDATORS, "epoch.validators_left")?,
        era: u64::decode(r)?,
        block_reward_spark: u64::decode(r)?,
    };
    let total_burned = record
        .fee_burned_spark
        .checked_add(record.slash_burned_spark)
        .and_then(|value| value.checked_add(record.governance_burned_spark))
        .ok_or(IndraError::InvariantViolation {
            message: "epoch burn accounting overflow",
        })?;
    let expected_close = record
        .opening_total_supply_spark
        .checked_add(record.reward_minted_spark)
        .and_then(|value| value.checked_sub(total_burned))
        .ok_or(IndraError::InvariantViolation {
            message: "epoch supply accounting overflow",
        })?;
    if total_burned != record.total_burned_spark
        || expected_close != record.closing_total_supply_spark
    {
        return Err(IndraError::InvariantViolation {
            message: "epoch monetary identity mismatch",
        });
    }
    Ok(record)
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
            reward_minted_spark: 356_760_000_000,
            fee_rewards_distributed: 123,
            fee_burned_spark: 456,
            slash_burned_spark: 789,
            governance_burned_spark: 123,
            total_burned_spark: 1_368,
            opening_total_supply_spark: 100_000_000_000_000_000,
            closing_total_supply_spark: 100_000_356_759_998_632,
            slash_event_count: 2,
            liveness_penalty_count: 1,
            avg_base_fee: 10,
            validators_joined: vec![Bytes32::from([1u8; 32]), Bytes32::from([2u8; 32])],
            validators_left: vec![Bytes32::from([3u8; 32])],
            era: 1,
            block_reward_spark: 1_189_200_000,
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
