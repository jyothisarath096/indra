//! UTXO wallet — tracks outputs owned by this node's keypair.
//!
//! A UTXO is "owned" if its owner_pubkey matches our hybrid public key.
//! The wallet tracks unspent outputs and their public values.
//!
//! ## Storage
//!
//! Wallet state is stored in a JSON file alongside keys.json.
//! Format: wallet.json

use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use indra_core::{
    codec::{Decode, Encode},
    types::primitives::Bytes32,
    types::transaction::OutputV1,
};
use indra_state::UtxoSet;

use crate::error::{CliError, CliResult};

const WALLET_FILE_MODE: u32 = 0o600;

/// A spendable UTXO entry in the wallet.
#[derive(Debug, Clone)]
pub struct WalletEntry {
    /// The UTXO ID (SHA-256 of encoded output + location).
    pub utxo_id: Bytes32,
    /// The actual value in Spark.
    pub value_spark: u64,
    /// Block height when this UTXO was created.
    pub created_height: u64,
    /// Transaction index within the block.
    pub tx_index: u32,
    /// Output index within the transaction.
    pub out_index: u32,
    /// Whether this UTXO has been spent (pending confirmation).
    pub spent: bool,
    /// Confirmed block height that spent this entry, if discovered by scanning.
    pub spent_height: Option<u64>,
}

/// A locally tracked change output waiting to be confirmed on-chain.
#[derive(Debug, Clone)]
pub struct PendingChange {
    /// The change output exactly as constructed in the signed transaction.
    pub output: OutputV1,
}

/// The wallet: a collection of UTXO entries keyed by UTXO ID.
#[derive(Debug, Clone, Default)]
pub struct Wallet {
    entries: HashMap<Bytes32, WalletEntry>,
    pending_changes: Vec<PendingChange>,
    scan_block_hashes: BTreeMap<u64, Bytes32>,
}

impl Wallet {
    /// Create an empty wallet.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            pending_changes: Vec::new(),
            scan_block_hashes: BTreeMap::new(),
        }
    }

    /// Add a new UTXO to the wallet.
    pub fn add_utxo(
        &mut self,
        utxo_id: Bytes32,
        value_spark: u64,
        created_height: u64,
        tx_index: u32,
        out_index: u32,
    ) {
        self.entries.insert(
            utxo_id,
            WalletEntry {
                utxo_id,
                value_spark,
                created_height,
                tx_index,
                out_index,
                spent: false,
                spent_height: None,
            },
        );
    }

    /// Mark a UTXO as spent.
    pub fn mark_spent(&mut self, utxo_id: &Bytes32) {
        if let Some(entry) = self.entries.get_mut(utxo_id) {
            entry.spent = true;
            entry.spent_height = None;
        }
    }

    /// Mark an entry spent by a confirmed canonical block.
    pub fn mark_spent_at_height(&mut self, utxo_id: &Bytes32, height: u64) {
        if let Some(entry) = self.entries.get_mut(utxo_id) {
            entry.spent = true;
            entry.spent_height = Some(height);
        }
    }

    /// Record public scan metadata for one canonical block.
    pub fn record_scanned_block(&mut self, height: u64, hash: Bytes32) {
        self.scan_block_hashes.insert(height, hash);
    }

    /// Return the latest recorded canonical scan anchor.
    pub fn scan_tip(&self) -> Option<(u64, Bytes32)> {
        self.scan_block_hashes
            .last_key_value()
            .map(|(height, hash)| (*height, *hash))
    }

    /// Roll back discoveries and confirmed spends at or above a reorg height.
    pub fn rollback_scan_from(&mut self, height: u64) {
        self.entries
            .retain(|_, entry| entry.created_height < height);
        for entry in self.entries.values_mut() {
            if entry
                .spent_height
                .is_some_and(|spent_height| spent_height >= height)
            {
                entry.spent = false;
                entry.spent_height = None;
            }
        }
        self.scan_block_hashes
            .retain(|block_height, _| *block_height < height);
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
            self.add_pending_change(change.output);
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
    pub fn add_pending_change(&mut self, output: OutputV1) {
        self.pending_changes.push(PendingChange { output });
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
                r#"  {{"utxo_id":"{}","value_spark":{},"created_height":{},"tx_index":{},"out_index":{},"spent":{},"spent_height":{}}}"#,
                hex::encode(e.utxo_id.0),
                e.value_spark,
                e.created_height,
                e.tx_index,
                e.out_index,
                e.spent,
                e.spent_height.map_or_else(|| "null".to_string(), |height| height.to_string()),
            )
        }).collect();
        let pending: Vec<String> = self
            .pending_changes
            .iter()
            .map(|pending| {
                format!(
                    r#"  {{"output_hex":"{}"}}"#,
                    hex::encode(pending.output.encode_to_vec())
                )
            })
            .collect();

        let scan_blocks = self
            .scan_block_hashes
            .iter()
            .map(|(height, hash)| {
                format!(
                    r#"  {{"height":{},"hash":"{}"}}"#,
                    height,
                    hex::encode(hash.0)
                )
            })
            .collect::<Vec<_>>();
        format!(
            "{{\n  \"entries\": [\n{}\n  ],\n  \"pending_changes\": [\n{}\n  ],\n  \"scan_blocks\": [\n{}\n  ]\n}}",
            entries.join(",\n"),
            pending.join(",\n"),
            scan_blocks.join(",\n"),
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
            let height = parse_u64_field(obj, "created_height")?;
            let tx_idx = parse_u64_field(obj, "tx_index")? as u32;
            let out_idx = parse_u64_field(obj, "out_index")? as u32;
            let spent = obj.contains("\"spent\":true");
            let spent_height = parse_optional_u64_field(obj, "spent_height")?;

            let id_bytes =
                hex::decode(&utxo_id).map_err(|_| CliError::Parse("bad utxo_id hex".into()))?;
            if id_bytes.len() != 32 {
                return Err(CliError::Parse("wrong field length".into()));
            }

            let mut id_arr = [0u8; 32];
            id_arr.copy_from_slice(&id_bytes);

            let utxo = Bytes32::from(id_arr);
            wallet.entries.insert(
                utxo,
                WalletEntry {
                    utxo_id: utxo,
                    value_spark: value,
                    created_height: height,
                    tx_index: tx_idx,
                    out_index: out_idx,
                    spent,
                    spent_height,
                },
            );
        }

        if let Some(scan_json) = extract_array(json, "scan_blocks") {
            let mut pos = 0;
            while let Some(offset) = scan_json[pos..].find('{') {
                let start = pos + offset;
                let end = scan_json[start..]
                    .find('}')
                    .ok_or_else(|| CliError::Parse("bad scan block metadata".into()))?
                    + start
                    + 1;
                let object = &scan_json[start..end];
                let height = parse_u64_field(object, "height")?;
                let bytes = hex::decode(parse_str_field(object, "hash")?)
                    .map_err(|_| CliError::Parse("bad scan block hash".into()))?;
                if bytes.len() != 32 {
                    return Err(CliError::Parse("bad scan block hash length".into()));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                wallet.scan_block_hashes.insert(height, Bytes32::from(hash));
                pos = end;
            }
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
                let output_bytes = hex::decode(&output_hex)
                    .map_err(|_| CliError::Parse("bad pending output hex".into()))?;
                let output = OutputV1::decode_exact(&output_bytes)
                    .map_err(|_| CliError::Parse("bad pending output encoding".into()))?;
                wallet.pending_changes.push(PendingChange { output });
            }
        }

        Ok(wallet)
    }

    /// Save wallet to a file.
    pub fn save(&self, path: &str) -> CliResult<()> {
        write_wallet_file_atomic(Path::new(path), &self.to_json(), || Ok(()))
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

fn write_wallet_file_atomic<F>(path: &Path, json: &str, before_rename: F) -> CliResult<()>
where
    F: FnOnce() -> CliResult<()>,
{
    Wallet::from_json(json)?;
    let tmp = wallet_temp_path(path);
    let write_result = (|| -> CliResult<()> {
        write_wallet_temp_secure(&tmp, json.as_bytes())?;
        let written = std::fs::read_to_string(&tmp)
            .map_err(|e| CliError::Io(format!("{}: {}", tmp.display(), e)))?;
        Wallet::from_json(&written)?;
        before_rename()?;
        std::fs::rename(&tmp, path)
            .map_err(|e| CliError::Io(format!("{} -> {}: {}", tmp.display(), path.display(), e)))?;
        set_wallet_file_permissions(path)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    write_result
}

fn wallet_temp_path(path: &Path) -> PathBuf {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("wallet.json");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    parent.join(format!(".{file_name}.tmp-{}-{nonce}", std::process::id()))
}

#[cfg(unix)]
fn write_wallet_temp_secure(path: &Path, contents: &[u8]) -> CliResult<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(WALLET_FILE_MODE)
        .open(path)
        .map_err(|e| CliError::Io(format!("{}: {}", path.display(), e)))?;
    file.write_all(contents)
        .map_err(|e| CliError::Io(format!("{}: {}", path.display(), e)))?;
    file.sync_all()
        .map_err(|e| CliError::Io(format!("{}: {}", path.display(), e)))?;
    set_wallet_file_permissions(path)
}

#[cfg(not(unix))]
fn write_wallet_temp_secure(path: &Path, contents: &[u8]) -> CliResult<()> {
    std::fs::write(path, contents).map_err(|e| CliError::Io(format!("{}: {}", path.display(), e)))
}

fn set_wallet_file_permissions(path: &Path) -> CliResult<()> {
    #[cfg(unix)]
    {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(WALLET_FILE_MODE))
            .map_err(|e| CliError::Io(format!("{}: {}", path.display(), e)))?;
    }
    Ok(())
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

fn parse_optional_u64_field(json: &str, field: &str) -> CliResult<Option<u64>> {
    let key = format!("\"{field}\":");
    let Some(pos) = json.find(&key) else {
        return Ok(None);
    };
    let after = json[pos + key.len()..].trim_start();
    if after.starts_with("null") {
        return Ok(None);
    }
    let number = after
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    number
        .parse::<u64>()
        .map(Some)
        .map_err(|_| CliError::Parse(format!("bad number: {field}")))
}

#[cfg(test)]
mod transparent_wallet_tests {
    use super::*;

    #[test]
    fn wallet_json_rejects_negative_value_spark() {
        let json = r#"{"entries":[{"utxo_id":"0000000000000000000000000000000000000000000000000000000000000000","value_spark":-1,"created_height":0,"tx_index":0,"out_index":0,"spent":false,"spent_height":null}],"pending_changes":[],"scan_blocks":[]}"#;
        assert!(Wallet::from_json(json).is_err());
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(b: u8) -> Bytes32 {
        Bytes32::from([b; 32])
    }

    fn temp_wallet_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "indra-wallet-{label}-{}-{}.json",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    #[test]
    fn empty_wallet_has_zero_balance() {
        assert_eq!(Wallet::new().balance(), 0);
    }

    #[test]
    fn add_and_balance() {
        let mut w = Wallet::new();
        w.add_utxo(make_id(1), 1_000_000, 1, 0, 0);
        w.add_utxo(make_id(2), 2_000_000, 1, 0, 1);
        assert_eq!(w.balance(), 3_000_000);
    }

    #[test]
    fn mark_spent_reduces_balance() {
        let mut w = Wallet::new();
        let id = make_id(1);
        w.add_utxo(id, 1_000_000, 1, 0, 0);
        w.mark_spent(&id);
        assert_eq!(w.balance(), 0);
    }

    #[test]
    fn coin_selection_sufficient() {
        let mut w = Wallet::new();
        w.add_utxo(make_id(1), 5_000_000, 1, 0, 0);
        w.add_utxo(make_id(2), 3_000_000, 1, 0, 1);
        let selected = w.select_utxos(4_000_000, 100_000).unwrap();
        let total: u64 = selected.iter().map(|e| e.value_spark).sum();
        assert!(total >= 4_100_000);
    }

    #[test]
    fn coin_selection_insufficient_errors() {
        let mut w = Wallet::new();
        w.add_utxo(make_id(1), 100, 1, 0, 0);
        assert!(w.select_utxos(1_000_000, 0).is_err());
    }

    #[test]
    fn wallet_json_round_trip() {
        let mut w = Wallet::new();
        w.add_utxo(make_id(0xAB), 999_000, 5, 1, 2);
        let json = w.to_json();
        let w2 = Wallet::from_json(&json).unwrap();
        assert_eq!(w2.balance(), 999_000);
    }

    #[cfg(unix)]
    #[test]
    fn wallet_save_writes_mode_0600() {
        let path = temp_wallet_path("mode");
        let path_str = path.to_string_lossy().to_string();
        let mut wallet = Wallet::new();
        wallet.add_utxo(make_id(0xC1), 999_000, 5, 1, 2);

        wallet.save(&path_str).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let restored = Wallet::load(&path_str).unwrap();
        assert_eq!(restored.balance(), 999_000);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn wallet_atomic_write_preserves_existing_file_on_pre_rename_failure() {
        let path = temp_wallet_path("atomic");
        let path_str = path.to_string_lossy().to_string();
        let mut original = Wallet::new();
        original.add_utxo(make_id(0xD1), 1_000_000, 5, 1, 2);
        original.save(&path_str).unwrap();
        let original_json = std::fs::read_to_string(&path).unwrap();
        let mut replacement = Wallet::new();
        replacement.add_utxo(make_id(0xD2), 2_000_000, 6, 1, 2);

        let err = write_wallet_file_atomic(&path, &replacement.to_json(), || {
            Err(CliError::Io("simulated interruption before rename".into()))
        })
        .unwrap_err();

        assert!(err.to_string().contains("simulated interruption"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original_json);
        let restored = Wallet::load(&path_str).unwrap();
        assert_eq!(restored.balance(), 1_000_000);
        assert!(restored.contains(&make_id(0xD1)));
        assert!(!restored.contains(&make_id(0xD2)));
        let tmp_prefix = format!(".{}.tmp-", path.file_name().unwrap().to_string_lossy());
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&tmp_prefix))
            .collect();
        assert!(leftovers.is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn pending_change_round_trip() {
        let mut wallet = Wallet::new();
        let output = sample_output(123_456);
        wallet.add_pending_change(output.clone());

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
        wallet.add_utxo(spent_id, 700_000, 4, 0, 0);
        wallet.add_utxo(other_id, 900_000, 4, 0, 1);
        let change = PendingChange {
            output: sample_output(550_000),
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
            owner_pubkey: indra_core::types::crypto::HybridPubKey {
                classical_pk: Bytes32::from([0x22; 32]),
                pq_pk: indra_core::types::primitives::VariableBytes::from_slice(&[0x33; 32])
                    .unwrap(),
            },
            lock_height: 0,
        }
    }
}
