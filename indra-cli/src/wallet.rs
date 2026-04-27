//! UTXO wallet — tracks outputs owned by this node's keypair.
//!
//! A UTXO is "owned" if its owner_pubkey matches our hybrid public key.
//! The wallet tracks unspent outputs, their values, and blinding factors
//! so we can spend them later.
//!
//! ## Storage
//!
//! Wallet state is stored in a JSON file alongside keys.json.
//! Format: wallet.json

use std::collections::HashMap;

use indra_core::{
    types::primitives::Bytes32,
};
use indra_crypto::sha256;

use crate::error::{CliError, CliResult};

/// A spendable UTXO entry in the wallet.
#[derive(Debug, Clone)]
pub struct WalletEntry {
    /// The UTXO ID (SHA-256 of encoded output + location).
    pub utxo_id: Bytes32,
    /// The actual value in Spark.
    pub value_spark: u64,
    /// The blinding factor used in the Pedersen commitment.
    pub blinding: [u8; 32],
    /// Block height when this UTXO was created.
    pub created_height: u64,
    /// Transaction index within the block.
    pub tx_index: u32,
    /// Output index within the transaction.
    pub out_index: u32,
    /// Whether this UTXO has been spent (pending confirmation).
    pub spent: bool,
}

impl WalletEntry {
    /// Compute the UTXO ID from its location.
    ///
    /// utxo_id = SHA-256(height_le || tx_index_le || out_index_le)
    pub fn compute_id(height: u64, tx_index: u32, out_index: u32) -> Bytes32 {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(&tx_index.to_le_bytes());
        data.extend_from_slice(&out_index.to_le_bytes());
        Bytes32::from(sha256(&data))
    }
}

/// The wallet: a collection of UTXO entries keyed by UTXO ID.
#[derive(Debug, Clone, Default)]
pub struct Wallet {
    entries: HashMap<Bytes32, WalletEntry>,
}

impl Wallet {
    /// Create an empty wallet.
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    /// Add a new UTXO to the wallet.
    pub fn add_utxo(
        &mut self,
        utxo_id: Bytes32,
        value_spark: u64,
        blinding: [u8; 32],
        created_height: u64,
        tx_index: u32,
        out_index: u32,
    ) {
        self.entries.insert(utxo_id, WalletEntry {
            utxo_id,
            value_spark,
            blinding,
            created_height,
            tx_index,
            out_index,
            spent: false,
        });
    }

    /// Mark a UTXO as spent.
    pub fn mark_spent(&mut self, utxo_id: &Bytes32) {
        if let Some(entry) = self.entries.get_mut(utxo_id) {
            entry.spent = true;
        }
    }

    /// Total spendable balance in Spark.
    pub fn balance(&self) -> u64 {
        self.entries.values()
            .filter(|e| !e.spent)
            .fold(0u64, |acc, e| acc.saturating_add(e.value_spark))
    }

    /// Select UTXOs to cover `target_spark` plus `fee_spark`.
    ///
    /// Uses a simple greedy algorithm: sort by value descending,
    /// pick until we have enough.
    ///
    /// Returns selected entries or an error if balance is insufficient.
    pub fn select_utxos(
        &self,
        target_spark: u64,
        fee_spark: u64,
    ) -> CliResult<Vec<&WalletEntry>> {
        let needed = target_spark.saturating_add(fee_spark);
        let mut available: Vec<&WalletEntry> = self.entries.values()
            .filter(|e| !e.spent)
            .collect();

        // Sort by value descending (largest first — minimise inputs)
        available.sort_by(|a, b| b.value_spark.cmp(&a.value_spark));

        let mut selected = Vec::new();
        let mut total: u64 = 0;

        for entry in available {
            selected.push(entry);
            total = total.saturating_add(entry.value_spark);
            if total >= needed {
                return Ok(selected);
            }
        }

        Err(CliError::InsufficientBalance {
            have: self.balance(),
            need: needed,
        })
    }

    /// Serialize wallet to JSON.
    pub fn to_json(&self) -> String {
        let entries: Vec<String> = self.entries.values().map(|e| {
            format!(
                r#"  {{"utxo_id":"{}","value_spark":{},"blinding":"{}","created_height":{},"tx_index":{},"out_index":{},"spent":{}}}"#,
                hex::encode(e.utxo_id.0),
                e.value_spark,
                hex::encode(e.blinding),
                e.created_height,
                e.tx_index,
                e.out_index,
                e.spent,
            )
        }).collect();
        format!("[\n{}\n]", entries.join(",\n"))
    }

    /// Load wallet from JSON string.
    pub fn from_json(json: &str) -> CliResult<Self> {
        let mut wallet = Self::new();
        // Simple parser — find each { object } block containing utxo_id
        let mut pos = 0;
        while pos < json.len() {
            // Find next opening brace
            let obj_start = match json[pos..].find('{') {
                Some(i) => pos + i,
                None => break,
            };
            // Find matching closing brace
            let obj_end = match json[obj_start..].find('}') {
                Some(i) => obj_start + i + 1,
                None => break,
            };
            let obj = &json[obj_start..obj_end];
            pos = obj_end;

            // Only process objects that contain utxo_id
            if !obj.contains("utxo_id") {
                continue;
            }

            let utxo_id = parse_str_field(obj, "utxo_id")?;
            let value   = parse_u64_field(obj, "value_spark")?;
            let blinding_hex = parse_str_field(obj, "blinding")?;
            let height  = parse_u64_field(obj, "created_height")?;
            let tx_idx  = parse_u64_field(obj, "tx_index")? as u32;
            let out_idx = parse_u64_field(obj, "out_index")? as u32;
            let spent   = obj.contains("\"spent\":true");

            let id_bytes = hex::decode(&utxo_id)
                .map_err(|_| CliError::Parse("bad utxo_id hex".into()))?;
            let blinding_bytes = hex::decode(&blinding_hex)
                .map_err(|_| CliError::Parse("bad blinding hex".into()))?;

            if id_bytes.len() != 32 || blinding_bytes.len() != 32 {
                return Err(CliError::Parse("wrong field length".into()));
            }

            let mut id_arr = [0u8; 32];
            let mut bl_arr = [0u8; 32];
            id_arr.copy_from_slice(&id_bytes);
            bl_arr.copy_from_slice(&blinding_bytes);

            let utxo = Bytes32::from(id_arr);
            wallet.entries.insert(utxo, WalletEntry {
                utxo_id: utxo,
                value_spark: value,
                blinding: bl_arr,
                created_height: height,
                tx_index: tx_idx,
                out_index: out_idx,
                spent,
            });
        }
        Ok(wallet)
    }

    /// Save wallet to a file.
    pub fn save(&self, path: &str) -> CliResult<()> {
        std::fs::write(path, self.to_json())
            .map_err(|e| CliError::Io(e.to_string()))
    }

    /// Load wallet from a file, or return empty wallet if file doesn't exist.
    pub fn load(path: &str) -> CliResult<Self> {
        match std::fs::read_to_string(path) {
            Ok(json) => Self::from_json(&json),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::new()),
            Err(e) => Err(CliError::Io(e.to_string())),
        }
    }
}

fn parse_str_field(json: &str, field: &str) -> CliResult<String> {
    let key = format!("\"{field}\":\"");
    let pos = json.find(&key)
        .ok_or_else(|| CliError::Parse(format!("missing field: {field}")))?;
    let after = &json[pos + key.len()..];
    let end = after.find('\"')
        .ok_or_else(|| CliError::Parse(format!("unterminated field: {field}")))?;
    Ok(after[..end].to_string())
}

fn parse_u64_field(json: &str, field: &str) -> CliResult<u64> {
    let key = format!("\"{field}\":");
    let pos = json.find(&key)
        .ok_or_else(|| CliError::Parse(format!("missing field: {field}")))?;
    let after = json[pos + key.len()..].trim_start();
    let num: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse::<u64>().map_err(|_| CliError::Parse(format!("bad number: {field}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(b: u8) -> Bytes32 { Bytes32::from([b; 32]) }

    #[test]
    fn empty_wallet_has_zero_balance() {
        assert_eq!(Wallet::new().balance(), 0);
    }

    #[test]
    fn add_and_balance() {
        let mut w = Wallet::new();
        w.add_utxo(make_id(1), 1_000_000, [0u8;32], 1, 0, 0);
        w.add_utxo(make_id(2), 2_000_000, [0u8;32], 1, 0, 1);
        assert_eq!(w.balance(), 3_000_000);
    }

    #[test]
    fn mark_spent_reduces_balance() {
        let mut w = Wallet::new();
        let id = make_id(1);
        w.add_utxo(id, 1_000_000, [0u8;32], 1, 0, 0);
        w.mark_spent(&id);
        assert_eq!(w.balance(), 0);
    }

    #[test]
    fn coin_selection_sufficient() {
        let mut w = Wallet::new();
        w.add_utxo(make_id(1), 5_000_000, [0u8;32], 1, 0, 0);
        w.add_utxo(make_id(2), 3_000_000, [0u8;32], 1, 0, 1);
        let selected = w.select_utxos(4_000_000, 100_000).unwrap();
        let total: u64 = selected.iter().map(|e| e.value_spark).sum();
        assert!(total >= 4_100_000);
    }

    #[test]
    fn coin_selection_insufficient_errors() {
        let mut w = Wallet::new();
        w.add_utxo(make_id(1), 100, [0u8;32], 1, 0, 0);
        assert!(w.select_utxos(1_000_000, 0).is_err());
    }

    #[test]
    fn wallet_json_round_trip() {
        let mut w = Wallet::new();
        w.add_utxo(make_id(0xAB), 999_000, [0x42u8;32], 5, 1, 2);
        let json = w.to_json();
        let w2 = Wallet::from_json(&json).unwrap();
        assert_eq!(w2.balance(), 999_000);
    }
}
