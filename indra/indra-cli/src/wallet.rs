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
    codec::{Decode, Encode},
    types::primitives::Bytes32,
    types::transaction::OutputV1,
};
use indra_crypto::sha256;
use indra_state::UtxoSet;

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

/// A locally tracked change output waiting to be confirmed on-chain.
#[derive(Debug, Clone)]
pub struct PendingChange {
    /// The change output exactly as constructed in the signed transaction.
    pub output: OutputV1,
    /// The blinding factor for the output commitment.
    pub blinding: [u8; 32],
}

/// The wallet: a collection of UTXO entries keyed by UTXO ID.
#[derive(Debug, Clone, Default)]
pub struct Wallet {
    entries: HashMap<Bytes32, WalletEntry>,
    pending_changes: Vec<PendingChange>,
}

impl Wallet {
    /// Create an empty wallet.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            pending_changes: Vec::new(),
        }
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
        self.entries.insert(
            utxo_id,
            WalletEntry {
                utxo_id,
                value_spark,
                blinding,
                created_height,
                tx_index,
                out_index,
                spent: false,
            },
        );
    }

    /// Mark a UTXO as spent.
    pub fn mark_spent(&mut self, utxo_id: &Bytes32) {
        if let Some(entry) = self.entries.get_mut(utxo_id) {
            entry.spent = true;
        }
    }

    /// Mark accepted transaction inputs spent and record any pending change.
    ///
    /// This is local wallet bookkeeping only. It must run after a node accepts a
    /// locally built transaction, never before submission.
    pub fn record_accepted_transaction(
        &mut self,
        spent_utxo_ids: &[Bytes32],
        pending_change: Option<PendingChange>,
    ) {
        for id in spent_utxo_ids {
            self.mark_spent(id);
        }
        if let Some(change) = pending_change {
            self.add_pending_change(change.output, change.blinding);
        }
    }

    /// True if the wallet already tracks this UTXO.
    pub fn contains(&self, utxo_id: &Bytes32) -> bool {
        self.entries.contains_key(utxo_id)
    }

    /// Look up a wallet entry by UTXO ID.
    pub fn get(&self, utxo_id: &Bytes32) -> Option<&WalletEntry> {
        self.entries.get(utxo_id)
    }

    /// Record a change output until it is mined and can be assigned a real UTXO ID.
    pub fn add_pending_change(&mut self, output: OutputV1, blinding: [u8; 32]) {
        self.pending_changes
            .push(PendingChange { output, blinding });
    }

    /// Number of pending change outputs awaiting confirmation.
    pub fn pending_change_count(&self) -> usize {
        self.pending_changes.len()
    }

    /// Reconcile a mined UTXO against pending change outputs and add it if matched.
    pub fn reconcile_pending_change(
        &mut self,
        utxo_id: Bytes32,
        created_height: u64,
        tx_index: u32,
        out_index: u32,
    ) -> bool {
        let Some(index) = self.pending_changes.iter().position(|pending| {
            UtxoSet::compute_utxo_id(&pending.output, created_height, tx_index, out_index)
                == utxo_id
        }) else {
            return false;
        };

        let pending = self.pending_changes.remove(index);
        self.add_utxo(
            utxo_id,
            pending.output.value_spark,
            pending.blinding,
            created_height,
            tx_index,
            out_index,
        );
        true
    }

    /// Total spendable balance in Spark.
    pub fn balance(&self) -> u64 {
        self.entries
            .values()
            .filter(|e| !e.spent)
            .fold(0u64, |acc, e| acc.saturating_add(e.value_spark))
    }

    /// Select UTXOs to cover `target_spark` plus `fee_spark`.
    ///
    /// Uses a simple greedy algorithm: sort by value descending,
    /// pick until we have enough.
    ///
    /// Returns selected entries or an error if balance is insufficient.
    pub fn select_utxos(&self, target_spark: u64, fee_spark: u64) -> CliResult<Vec<&WalletEntry>> {
        let needed = target_spark.saturating_add(fee_spark);
        let mut available: Vec<&WalletEntry> = self.entries.values().filter(|e| !e.spent).collect();

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
        let pending: Vec<String> = self
            .pending_changes
            .iter()
            .map(|pending| {
                format!(
                    r#"  {{"output_hex":"{}","blinding":"{}"}}"#,
                    hex::encode(pending.output.encode_to_vec()),
                    hex::encode(pending.blinding),
                )
            })
            .collect();

        format!(
            "{{\n  \"entries\": [\n{}\n  ],\n  \"pending_changes\": [\n{}\n  ]\n}}",
            entries.join(",\n"),
            pending.join(",\n"),
        )
    }

    /// Load wallet from JSON string.
    pub fn from_json(json: &str) -> CliResult<Self> {
        let mut wallet = Self::new();
        let entries_json = extract_array(json, "entries").unwrap_or(json);
        let mut pos = 0;
        while pos < entries_json.len() {
            // Find next opening brace
            let obj_start = match entries_json[pos..].find('{') {
                Some(i) => pos + i,
                None => break,
            };
            // Find matching closing brace
            let obj_end = match entries_json[obj_start..].find('}') {
                Some(i) => obj_start + i + 1,
                None => break,
            };
            let obj = &entries_json[obj_start..obj_end];
            pos = obj_end;

            // Only process objects that contain utxo_id
            if !obj.contains("utxo_id") {
                continue;
            }

            let utxo_id = parse_str_field(obj, "utxo_id")?;
            let value = parse_u64_field(obj, "value_spark")?;
            let blinding_hex = parse_str_field(obj, "blinding")?;
            let height = parse_u64_field(obj, "created_height")?;
            let tx_idx = parse_u64_field(obj, "tx_index")? as u32;
            let out_idx = parse_u64_field(obj, "out_index")? as u32;
            let spent = obj.contains("\"spent\":true");

            let id_bytes =
                hex::decode(&utxo_id).map_err(|_| CliError::Parse("bad utxo_id hex".into()))?;
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
            wallet.entries.insert(
                utxo,
                WalletEntry {
                    utxo_id: utxo,
                    value_spark: value,
                    blinding: bl_arr,
                    created_height: height,
                    tx_index: tx_idx,
                    out_index: out_idx,
                    spent,
                },
            );
        }

        if let Some(pending_json) = extract_array(json, "pending_changes") {
            let mut pos = 0;
            while pos < pending_json.len() {
                let obj_start = match pending_json[pos..].find('{') {
                    Some(i) => pos + i,
                    None => break,
                };
                let obj_end = match pending_json[obj_start..].find('}') {
                    Some(i) => obj_start + i + 1,
                    None => break,
                };
                let obj = &pending_json[obj_start..obj_end];
                pos = obj_end;

                let output_hex = parse_str_field(obj, "output_hex")?;
                let blinding_hex = parse_str_field(obj, "blinding")?;
                let output_bytes = hex::decode(&output_hex)
                    .map_err(|_| CliError::Parse("bad pending output hex".into()))?;
                let blinding_bytes = hex::decode(&blinding_hex)
                    .map_err(|_| CliError::Parse("bad pending blinding hex".into()))?;
                if blinding_bytes.len() != 32 {
                    return Err(CliError::Parse("wrong pending blinding length".into()));
                }
                let output = OutputV1::decode_exact(&output_bytes)
                    .map_err(|_| CliError::Parse("bad pending output encoding".into()))?;
                let mut blinding = [0u8; 32];
                blinding.copy_from_slice(&blinding_bytes);
                wallet
                    .pending_changes
                    .push(PendingChange { output, blinding });
            }
        }

        Ok(wallet)
    }

    /// Save wallet to a file.
    pub fn save(&self, path: &str) -> CliResult<()> {
        std::fs::write(path, self.to_json()).map_err(|e| CliError::Io(e.to_string()))
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

fn extract_array<'a>(json: &'a str, field: &str) -> Option<&'a str> {
    let key = format!("\"{field}\":");
    let pos = json.find(&key)?;
    let after = json[pos + key.len()..].trim_start();
    let after = after.strip_prefix('[')?;
    let mut depth = 1usize;
    for (idx, ch) in after.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&after[..idx]);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_str_field(json: &str, field: &str) -> CliResult<String> {
    let key = format!("\"{field}\":\"");
    let pos = json
        .find(&key)
        .ok_or_else(|| CliError::Parse(format!("missing field: {field}")))?;
    let after = &json[pos + key.len()..];
    let end = after
        .find('\"')
        .ok_or_else(|| CliError::Parse(format!("unterminated field: {field}")))?;
    Ok(after[..end].to_string())
}

fn parse_u64_field(json: &str, field: &str) -> CliResult<u64> {
    let key = format!("\"{field}\":");
    let pos = json
        .find(&key)
        .ok_or_else(|| CliError::Parse(format!("missing field: {field}")))?;
    let after = json[pos + key.len()..].trim_start();
    let num: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse::<u64>()
        .map_err(|_| CliError::Parse(format!("bad number: {field}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(b: u8) -> Bytes32 {
        Bytes32::from([b; 32])
    }

    #[test]
    fn empty_wallet_has_zero_balance() {
        assert_eq!(Wallet::new().balance(), 0);
    }

    #[test]
    fn add_and_balance() {
        let mut w = Wallet::new();
        w.add_utxo(make_id(1), 1_000_000, [0u8; 32], 1, 0, 0);
        w.add_utxo(make_id(2), 2_000_000, [0u8; 32], 1, 0, 1);
        assert_eq!(w.balance(), 3_000_000);
    }

    #[test]
    fn mark_spent_reduces_balance() {
        let mut w = Wallet::new();
        let id = make_id(1);
        w.add_utxo(id, 1_000_000, [0u8; 32], 1, 0, 0);
        w.mark_spent(&id);
        assert_eq!(w.balance(), 0);
    }

    #[test]
    fn coin_selection_sufficient() {
        let mut w = Wallet::new();
        w.add_utxo(make_id(1), 5_000_000, [0u8; 32], 1, 0, 0);
        w.add_utxo(make_id(2), 3_000_000, [0u8; 32], 1, 0, 1);
        let selected = w.select_utxos(4_000_000, 100_000).unwrap();
        let total: u64 = selected.iter().map(|e| e.value_spark).sum();
        assert!(total >= 4_100_000);
    }

    #[test]
    fn coin_selection_insufficient_errors() {
        let mut w = Wallet::new();
        w.add_utxo(make_id(1), 100, [0u8; 32], 1, 0, 0);
        assert!(w.select_utxos(1_000_000, 0).is_err());
    }

    #[test]
    fn wallet_json_round_trip() {
        let mut w = Wallet::new();
        w.add_utxo(make_id(0xAB), 999_000, [0x42u8; 32], 5, 1, 2);
        let json = w.to_json();
        let w2 = Wallet::from_json(&json).unwrap();
        assert_eq!(w2.balance(), 999_000);
    }

    #[test]
    fn pending_change_round_trip() {
        let mut wallet = Wallet::new();
        let output = sample_output(123_456);
        wallet.add_pending_change(output.clone(), [0x55; 32]);

        let restored = Wallet::from_json(&wallet.to_json()).unwrap();
        assert_eq!(restored.pending_change_count(), 1);

        let utxo_id = UtxoSet::compute_utxo_id(&output, 7, 1, 1);
        let mut reconciled = restored.clone();
        assert!(reconciled.reconcile_pending_change(utxo_id, 7, 1, 1));
        assert!(reconciled.contains(&utxo_id));
        assert_eq!(reconciled.pending_change_count(), 0);
    }

    #[test]
    fn accepted_transaction_bookkeeping_marks_spent_and_records_change() {
        let spent_id = make_id(0xA1);
        let other_id = make_id(0xA2);
        let mut wallet = Wallet::new();
        wallet.add_utxo(spent_id, 700_000, [0x11; 32], 4, 0, 0);
        wallet.add_utxo(other_id, 900_000, [0x22; 32], 4, 0, 1);
        let change = PendingChange {
            output: sample_output(550_000),
            blinding: [0x33; 32],
        };

        wallet.record_accepted_transaction(&[spent_id], Some(change));

        assert!(wallet.get(&spent_id).unwrap().spent);
        assert!(!wallet.get(&other_id).unwrap().spent);
        assert_eq!(wallet.pending_change_count(), 1);
        assert_eq!(wallet.balance(), 900_000);
        assert!(wallet.select_utxos(900_000, 1).is_err());
        assert!(wallet.select_utxos(800_000, 50_000).is_ok());
    }

    fn sample_output(value_spark: u64) -> OutputV1 {
        OutputV1 {
            value_spark,
            commitment: indra_core::types::crypto::CommitmentV1 {
                compressed_point: Bytes32::from([0x11; 32]),
            },
            owner_pubkey: indra_core::types::crypto::HybridPubKey {
                classical_pk: Bytes32::from([0x22; 32]),
                pq_pk: indra_core::types::primitives::VariableBytes::from_slice(&[0x33; 32])
                    .unwrap(),
            },
            range_proof: indra_core::types::primitives::VariableBytes::from_slice(&[0x44; 32])
                .unwrap(),
            lock_height: 0,
        }
    }
}
