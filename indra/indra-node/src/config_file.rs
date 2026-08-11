//! TOML configuration file parsing for the INDRA node.
//!
//! Parses `config.toml` into a `NodeConfigFile` intermediate struct, then
//! converts to `NodeConfig` for use by the node engine. Parsing is manual over
//! `toml::Value`; no serde derives are used.

use std::path::{Path, PathBuf};

use toml::Value;

use crate::config::{
    default_governance_mempool_capacity, validate_pool_capacities, NodeConfig,
    DEFAULT_STAKING_MEMPOOL_CAPACITY,
};
use crate::discovery::{DnsSeedValidationMode, SignedDnsSeedValidationMode};
use indra_core::types::primitives::{
    DEFAULT_PRUNE_KEEP_BLOCKS, DNS_SEED_HOSTS, MIN_PRUNE_KEEP_BLOCKS, OBSERVER_PORT,
};
use indra_crypto::PQ_PK_BYTES;

/// Parsed key material loaded from `keys.json`.
#[derive(Debug, Clone)]
pub struct KeysData {
    /// Ed25519 seed for the hybrid classical key.
    pub ed25519_seed: [u8; 32],
    /// VRF seed.
    pub vrf_seed: [u8; 32],
    /// ML-DSA private key bytes.
    pub ml_dsa_seed: [u8; 32],
    /// ML-DSA public key bytes.
    pub pq_pk: Vec<u8>,
}

/// Raw parsed config file values.
#[derive(Debug, Default, Clone)]
pub struct NodeConfigFile {
    /// `[node].mode`.
    pub mode: Option<String>,
    /// `[node].chain_id`.
    pub chain_id: Option<String>,
    /// `[node].data_dir`.
    pub data_dir: Option<String>,
    /// `[node].genesis`.
    pub genesis: Option<String>,
    /// `[keys].path`.
    pub keys_path: Option<String>,
    /// `[keys].password_file`.
    pub keys_password_file: Option<String>,
    /// `[network].p2p_addr`.
    pub p2p_addr: Option<String>,
    /// `[network].observer_addr`.
    pub observer_addr: Option<String>,
    /// `[network].bootstrap_peers`.
    pub bootstrap_peers: Vec<String>,
    /// `[network].dns_seed_host`.
    pub dns_seed_host: Option<String>,
    /// `[network].dns_discovery_enabled`.
    pub dns_discovery_enabled: Option<bool>,
    /// `[network].dns_seed_validation`.
    pub dns_seed_validation: Option<String>,
    /// `[network].dns_seed_signed_validation`.
    pub dns_seed_signed_validation: Option<String>,
    /// `[network].dns_seed_signed_public_key`.
    pub dns_seed_signed_public_key: Option<String>,
    /// `[network].peers_file`.
    pub peers_file: Option<String>,
    /// `[rpc].addr`.
    pub rpc_addr: Option<String>,
    /// `[rpc].enabled`.
    pub rpc_enabled: Option<bool>,
    /// `[rpc].admin_token`.
    pub rpc_admin_token: Option<String>,
    /// `[rpc].access_token`.
    pub rpc_access_token: Option<String>,
    /// `[rpc].trusted_tls_proxy`.
    pub rpc_trusted_tls_proxy: Option<bool>,
    /// `[rpc].per_ip_connection_cap`.
    pub rpc_per_ip_connection_cap: Option<u64>,
    /// `[rpc].cors_origins`.
    pub rpc_cors_origins: Vec<String>,
    /// `[rpc_public].addr`.
    pub rpc_public_addr: Option<String>,
    /// `[rpc_public].enabled`.
    pub rpc_public_enabled: Option<bool>,
    /// `[rpc_public].trusted_tls_proxy`.
    pub rpc_public_trusted_tls_proxy: Option<bool>,
    /// `[rpc_public].per_ip_connection_cap`.
    pub rpc_public_per_ip_connection_cap: Option<u64>,
    /// `[rpc_public].cors_origins`.
    pub rpc_public_cors_origins: Vec<String>,
    /// `[rpc_public].per_ip_rate_per_sec`.
    pub rpc_public_per_ip_rate_per_sec: Option<u64>,
    /// `[rpc_public].per_ip_burst`.
    pub rpc_public_per_ip_burst: Option<u64>,
    /// `[rpc_public].global_rate_per_sec`.
    pub rpc_public_global_rate_per_sec: Option<u64>,
    /// `[rpc_public].global_burst`.
    pub rpc_public_global_burst: Option<u64>,
    /// `[rpc_public].max_body_bytes`.
    pub rpc_public_max_body_bytes: Option<usize>,
    /// `[rpc_public].timeout_ms`.
    pub rpc_public_timeout_ms: Option<u64>,
    /// `[metrics].addr`.
    pub metrics_addr: Option<String>,
    /// `[metrics].enabled`.
    pub metrics_enabled: Option<bool>,
    /// `[storage].prune_keep_blocks`.
    pub prune_keep_blocks: Option<u64>,
    /// `[storage].snapshot_interval`.
    pub snapshot_interval: Option<u64>,
    /// `[storage].mempool_capacity`.
    pub mempool_capacity: Option<usize>,
    /// `[storage].staking_mempool_capacity`.
    pub staking_mempool_capacity: Option<usize>,
    /// `[storage].governance_mempool_capacity`.
    pub governance_mempool_capacity: Option<usize>,
}

impl NodeConfigFile {
    /// Load a TOML config file from disk.
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config file {}: {}", path.display(), e))?;
        let table = toml::from_str::<Value>(&content)
            .map_err(|e| format!("config.toml parse error: {}", e))?;
        validate_known_config_keys(&table)?;
        Ok(Self {
            mode: get_str(&table, "node", "mode"),
            chain_id: get_str(&table, "node", "chain_id"),
            data_dir: get_str(&table, "node", "data_dir"),
            genesis: get_str(&table, "node", "genesis"),
            keys_path: get_str(&table, "keys", "path"),
            keys_password_file: get_str(&table, "keys", "password_file"),
            p2p_addr: get_str(&table, "network", "p2p_addr"),
            observer_addr: get_str(&table, "network", "observer_addr"),
            bootstrap_peers: get_str_array(&table, "network", "bootstrap_peers"),
            dns_seed_host: get_str(&table, "network", "dns_seed_host"),
            dns_discovery_enabled: get_bool(&table, "network", "dns_discovery_enabled"),
            dns_seed_validation: get_str(&table, "network", "dns_seed_validation"),
            dns_seed_signed_validation: get_str(&table, "network", "dns_seed_signed_validation"),
            dns_seed_signed_public_key: get_str(&table, "network", "dns_seed_signed_public_key"),
            peers_file: get_str(&table, "network", "peers_file"),
            rpc_addr: get_str(&table, "rpc", "addr"),
            rpc_enabled: get_bool(&table, "rpc", "enabled"),
            rpc_admin_token: get_str(&table, "rpc", "admin_token"),
            rpc_access_token: get_str(&table, "rpc", "access_token"),
            rpc_trusted_tls_proxy: get_bool(&table, "rpc", "trusted_tls_proxy"),
            rpc_per_ip_connection_cap: get_u64(&table, "rpc", "per_ip_connection_cap"),
            rpc_cors_origins: get_str_array(&table, "rpc", "cors_origins"),
            rpc_public_addr: get_str(&table, "rpc_public", "addr"),
            rpc_public_enabled: get_bool(&table, "rpc_public", "enabled"),
            rpc_public_trusted_tls_proxy: get_bool(&table, "rpc_public", "trusted_tls_proxy"),
            rpc_public_per_ip_connection_cap: get_u64(
                &table,
                "rpc_public",
                "per_ip_connection_cap",
            ),
            rpc_public_cors_origins: get_str_array(&table, "rpc_public", "cors_origins"),
            rpc_public_per_ip_rate_per_sec: get_u64(&table, "rpc_public", "per_ip_rate_per_sec"),
            rpc_public_per_ip_burst: get_u64(&table, "rpc_public", "per_ip_burst"),
            rpc_public_global_rate_per_sec: get_u64(&table, "rpc_public", "global_rate_per_sec"),
            rpc_public_global_burst: get_u64(&table, "rpc_public", "global_burst"),
            rpc_public_max_body_bytes: get_usize(&table, "rpc_public", "max_body_bytes"),
            rpc_public_timeout_ms: get_u64(&table, "rpc_public", "timeout_ms"),
            metrics_addr: get_str(&table, "metrics", "addr"),
            metrics_enabled: get_bool(&table, "metrics", "enabled"),
            prune_keep_blocks: get_u64(&table, "storage", "prune_keep_blocks"),
            snapshot_interval: get_u64(&table, "storage", "snapshot_interval"),
            mempool_capacity: get_usize(&table, "storage", "mempool_capacity"),
            staking_mempool_capacity: get_usize(&table, "storage", "staking_mempool_capacity"),
            governance_mempool_capacity: get_usize(
                &table,
                "storage",
                "governance_mempool_capacity",
            ),
        })
    }

    /// Validate parsed config and return all detected errors.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        let mode = self.mode.as_deref().unwrap_or("validator");
        if !matches!(mode, "validator" | "observer") {
            errors.push("node.mode must be \"validator\" or \"observer\"".to_string());
        }
        if is_blank(self.data_dir.as_deref()) {
            errors.push("node.data_dir must be set and non-empty".to_string());
        }
        if is_blank(self.genesis.as_deref()) {
            errors.push("node.genesis must be set and non-empty".to_string());
        }
        if mode != "observer" && is_blank(self.keys_path.as_deref()) {
            errors.push("keys.path must be set and non-empty for validator mode".to_string());
        }
        if let Some(addr) = self.p2p_addr.as_deref() {
            if !is_valid_addr(addr) {
                errors
                    .push("network.p2p_addr must be valid host:port with port 1-65535".to_string());
            }
        }
        if let Some(addr) = self.observer_addr.as_deref() {
            if !addr.is_empty() && !is_valid_addr(addr) {
                errors.push(
                    "network.observer_addr must be valid host:port, empty, or omitted".to_string(),
                );
            }
        }
        if let Some(mode) = self.dns_seed_validation.as_deref() {
            if let Err(err) = mode.parse::<DnsSeedValidationMode>() {
                errors.push(err);
            }
        }
        if let Some(mode) = self.dns_seed_signed_validation.as_deref() {
            if let Err(err) = mode.parse::<SignedDnsSeedValidationMode>() {
                errors.push(err);
            }
        }
        if let Some(pk_hex) = self.dns_seed_signed_public_key.as_deref() {
            match hex::decode(pk_hex.trim()) {
                Ok(bytes) if bytes.len() == PQ_PK_BYTES => {}
                Ok(bytes) => errors.push(format!(
                    "network.dns_seed_signed_public_key must be {PQ_PK_BYTES} bytes of hex (got {} bytes)",
                    bytes.len()
                )),
                Err(_) => errors.push(
                    "network.dns_seed_signed_public_key must be valid hex".to_string(),
                ),
            }
        }
        let signed_mode = self
            .dns_seed_signed_validation
            .as_deref()
            .and_then(|mode| mode.parse::<SignedDnsSeedValidationMode>().ok())
            .unwrap_or_default();
        if signed_mode != SignedDnsSeedValidationMode::Off
            && self.dns_seed_signed_public_key.is_none()
        {
            errors.push(format!(
                "network.dns_seed_signed_public_key is required when network.dns_seed_signed_validation={signed_mode}"
            ));
        }
        if let Some(addr) = self.metrics_addr.as_deref() {
            if !addr.is_empty() && !is_valid_addr(addr) {
                errors.push("metrics.addr must be valid host:port, empty, or omitted".to_string());
            }
        }
        if let Some(addr) = self.rpc_addr.as_deref() {
            if !addr.is_empty() && !is_valid_addr(addr) {
                errors.push("rpc.addr must be valid host:port, empty, or omitted".to_string());
            }
            if !addr.is_empty()
                && self.rpc_enabled.unwrap_or(true)
                && !is_loopback_addr(addr)
                && self.rpc_trusted_tls_proxy != Some(true)
            {
                errors.push(
                    "rpc.addr must be loopback unless rpc.trusted_tls_proxy=true explicitly acknowledges a trusted TLS-terminating proxy"
                        .to_string(),
                );
            }
        }
        if mode != "observer"
            && self.rpc_enabled.unwrap_or(true)
            && is_blank(self.rpc_access_token.as_deref())
        {
            errors.push(
                "rpc.access_token must be set and non-empty when full RPC is enabled".to_string(),
            );
        }
        validate_connection_cap(
            "rpc.per_ip_connection_cap",
            self.rpc_per_ip_connection_cap,
            &mut errors,
        );
        for origin in &self.rpc_cors_origins {
            if origin.trim().is_empty() || origin == "*" {
                errors.push(
                    "rpc.cors_origins entries must be explicit non-wildcard origins".to_string(),
                );
            }
        }
        if let Some(addr) = self.rpc_public_addr.as_deref() {
            if !addr.is_empty() && !is_valid_addr(addr) {
                errors
                    .push("rpc_public.addr must be valid host:port, empty, or omitted".to_string());
            }
            if !addr.is_empty()
                && self.rpc_public_enabled == Some(true)
                && !is_loopback_addr(addr)
                && self.rpc_public_trusted_tls_proxy != Some(true)
            {
                errors.push(
                    "rpc_public.addr must be loopback unless rpc_public.trusted_tls_proxy=true explicitly acknowledges a trusted TLS-terminating proxy"
                        .to_string(),
                );
            }
        }
        validate_connection_cap(
            "rpc_public.per_ip_connection_cap",
            self.rpc_public_per_ip_connection_cap,
            &mut errors,
        );
        for origin in &self.rpc_public_cors_origins {
            if origin.trim().is_empty() || origin == "*" {
                errors.push(
                    "rpc_public.cors_origins entries must be explicit non-wildcard origins"
                        .to_string(),
                );
            }
        }
        for (name, value) in [
            (
                "rpc_public.per_ip_rate_per_sec",
                self.rpc_public_per_ip_rate_per_sec,
            ),
            ("rpc_public.per_ip_burst", self.rpc_public_per_ip_burst),
            (
                "rpc_public.global_rate_per_sec",
                self.rpc_public_global_rate_per_sec,
            ),
            ("rpc_public.global_burst", self.rpc_public_global_burst),
            ("rpc_public.timeout_ms", self.rpc_public_timeout_ms),
        ] {
            if value == Some(0) {
                errors.push(format!("{name} must be greater than 0"));
            }
        }
        if self.rpc_public_max_body_bytes == Some(0) {
            errors.push("rpc_public.max_body_bytes must be greater than 0".to_string());
        }
        if let Some(keep) = self.prune_keep_blocks {
            if keep > 0 && keep < MIN_PRUNE_KEEP_BLOCKS {
                errors.push(format!(
                    "storage.prune_keep_blocks must be 0 for archive or at least {}",
                    MIN_PRUNE_KEEP_BLOCKS
                ));
            }
        }
        if self.snapshot_interval == Some(0) {
            errors.push("storage.snapshot_interval must be greater than 0".to_string());
        }
        if let Err(capacity_errors) = validate_pool_capacities(
            self.mempool_capacity.unwrap_or(5_000),
            self.staking_mempool_capacity
                .unwrap_or(DEFAULT_STAKING_MEMPOOL_CAPACITY),
            self.governance_mempool_capacity
                .unwrap_or_else(default_governance_mempool_capacity),
        ) {
            errors.extend(capacity_errors);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Convert parsed config into runtime node configuration.
    pub fn to_node_config(&self, keys_data: Option<&KeysData>) -> Result<NodeConfig, String> {
        if let Err(errors) = self.validate() {
            return Err(errors.join("; "));
        }
        let mode = self.mode.as_deref().unwrap_or("validator");
        let data_dir = self
            .data_dir
            .as_ref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| "node.data_dir must be set".to_string())?;
        let genesis = self
            .genesis
            .as_ref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| "node.genesis must be set".to_string())?;
        let peers_file = self.peers_file.clone().unwrap_or_else(|| {
            Path::new(data_dir)
                .join("peers.json")
                .to_string_lossy()
                .to_string()
        });
        let prune_keep_blocks = match self.prune_keep_blocks.unwrap_or(DEFAULT_PRUNE_KEEP_BLOCKS) {
            0 => None,
            keep => Some(keep),
        };
        let observer_addr = match self.observer_addr.as_deref() {
            Some("") => None,
            Some(addr) => Some(addr.to_string()),
            None => Some(format!("0.0.0.0:{}", OBSERVER_PORT)),
        };
        let metrics_addr = if self.metrics_enabled == Some(false) {
            None
        } else {
            match self.metrics_addr.as_deref() {
                Some("") => None,
                Some(addr) => Some(addr.to_string()),
                None => Some(crate::metrics::DEFAULT_METRICS_ADDR.to_string()),
            }
        };
        let (validator_seed, vrf_seed, pq_seed, pq_pk) = if mode == "observer" {
            (None, None, None, None)
        } else {
            let keys =
                keys_data.ok_or_else(|| "validator mode requires keys.json data".to_string())?;
            (
                Some(keys.ed25519_seed),
                Some(keys.vrf_seed),
                Some(keys.ml_dsa_seed.to_vec()),
                if keys.pq_pk.is_empty() {
                    None
                } else {
                    Some(keys.pq_pk.clone())
                },
            )
        };
        Ok(NodeConfig {
            data_dir: PathBuf::from(data_dir),
            genesis_path: Some(genesis.clone()),
            genesis_validator_minimum: 4,
            validator_seed,
            vrf_seed,
            pq_seed,
            pq_pk,
            p2p_addr: self
                .p2p_addr
                .clone()
                .unwrap_or_else(|| "0.0.0.0:30303".to_string()),
            bootstrap_peers: self.bootstrap_peers.clone(),
            dns_seed_host: self
                .dns_seed_host
                .clone()
                .unwrap_or_else(|| DNS_SEED_HOSTS.join(",")),
            dns_discovery_enabled: self.dns_discovery_enabled.unwrap_or(true),
            dns_seed_validation: self
                .dns_seed_validation
                .as_deref()
                .map(str::parse::<DnsSeedValidationMode>)
                .transpose()?
                .unwrap_or_default(),
            dns_seed_signed_validation: self
                .dns_seed_signed_validation
                .as_deref()
                .map(str::parse::<SignedDnsSeedValidationMode>)
                .transpose()?
                .unwrap_or_default(),
            dns_seed_signed_public_key: self
                .dns_seed_signed_public_key
                .as_deref()
                .map(|hex| hex::decode(hex.trim()))
                .transpose()
                .map_err(|_| "network.dns_seed_signed_public_key must be valid hex".to_string())?,
            peers_file,
            snapshot_interval: self.snapshot_interval.unwrap_or(300),
            mempool_capacity: self.mempool_capacity.unwrap_or(5_000),
            staking_mempool_capacity: self
                .staking_mempool_capacity
                .unwrap_or(DEFAULT_STAKING_MEMPOOL_CAPACITY),
            governance_mempool_capacity: self
                .governance_mempool_capacity
                .unwrap_or_else(default_governance_mempool_capacity),
            prune_keep_blocks,
            observer_addr,
            metrics_addr,
        })
    }
}

fn get_str(table: &Value, section: &str, key: &str) -> Option<String> {
    table
        .get(section)?
        .get(key)?
        .as_str()
        .map(ToString::to_string)
}

fn validate_known_config_keys(table: &Value) -> Result<(), String> {
    let Some(root) = table.as_table() else {
        return Err("config.toml root must be a table".to_string());
    };
    let mut errors = Vec::new();
    for (section, value) in root {
        let Some(allowed_keys) = allowed_config_keys(section) else {
            errors.push(format!(
                "unrecognized config table [{section}]; expected one of [node], [keys], [network], [rpc], [rpc_public], [metrics], [storage]"
            ));
            continue;
        };
        let Some(section_table) = value.as_table() else {
            errors.push(format!("config section [{section}] must be a TOML table"));
            continue;
        };
        for key in section_table.keys() {
            if !allowed_keys.contains(&key.as_str()) {
                errors.push(format!(
                    "unrecognized config key {section}.{key}; if this was intended for a different section, move it there instead of leaving it silently ignored"
                ));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn allowed_config_keys(section: &str) -> Option<&'static [&'static str]> {
    match section {
        "node" => Some(&["mode", "chain_id", "data_dir", "genesis"]),
        "keys" => Some(&["path", "password_file"]),
        "network" => Some(&[
            "p2p_addr",
            "observer_addr",
            "bootstrap_peers",
            "dns_seed_host",
            "dns_discovery_enabled",
            "dns_seed_validation",
            "dns_seed_signed_validation",
            "dns_seed_signed_public_key",
            "peers_file",
        ]),
        "rpc" => Some(&[
            "addr",
            "enabled",
            "admin_token",
            "access_token",
            "trusted_tls_proxy",
            "per_ip_connection_cap",
            "cors_origins",
        ]),
        "rpc_public" => Some(&[
            "addr",
            "enabled",
            "trusted_tls_proxy",
            "per_ip_connection_cap",
            "cors_origins",
            "per_ip_rate_per_sec",
            "per_ip_burst",
            "global_rate_per_sec",
            "global_burst",
            "max_body_bytes",
            "timeout_ms",
        ]),
        "metrics" => Some(&["addr", "enabled"]),
        "storage" => Some(&[
            "prune_keep_blocks",
            "snapshot_interval",
            "mempool_capacity",
            "staking_mempool_capacity",
            "governance_mempool_capacity",
        ]),
        _ => None,
    }
}

fn get_bool(table: &Value, section: &str, key: &str) -> Option<bool> {
    table.get(section)?.get(key)?.as_bool()
}

fn get_u64(table: &Value, section: &str, key: &str) -> Option<u64> {
    table
        .get(section)?
        .get(key)?
        .as_integer()
        .and_then(|v| u64::try_from(v).ok())
}

fn get_usize(table: &Value, section: &str, key: &str) -> Option<usize> {
    table
        .get(section)?
        .get(key)?
        .as_integer()
        .and_then(|v| usize::try_from(v).ok())
}

fn get_str_array(table: &Value, section: &str, key: &str) -> Vec<String> {
    table
        .get(section)
        .and_then(|s| s.get(key))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn is_blank(value: Option<&str>) -> bool {
    value.map(str::trim).unwrap_or("").is_empty()
}

fn is_valid_addr(s: &str) -> bool {
    let parts: Vec<&str> = s.rsplitn(2, ':').collect();
    if parts.len() != 2 || parts[1].is_empty() {
        return false;
    }
    parts[0].parse::<u16>().map(|p| p > 0).unwrap_or(false)
}

fn is_loopback_addr(s: &str) -> bool {
    s.parse::<std::net::SocketAddr>()
        .is_ok_and(|addr| addr.ip().is_loopback())
}

fn validate_connection_cap(name: &str, value: Option<u64>, errors: &mut Vec<String>) {
    if let Some(value) = value {
        if !(1..=64).contains(&value) {
            errors.push(format!("{name} must be in the range 1..=64"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> KeysData {
        KeysData {
            ed25519_seed: [1u8; 32],
            vrf_seed: [3u8; 32],
            ml_dsa_seed: [4u8; 32],
            pq_pk: vec![7, 8, 9],
        }
    }

    fn temp_file(name: &str, content: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "{}-{}-{}.toml",
            name,
            std::process::id(),
            crate::metrics::MetricsState::new()
                .started_at
                .elapsed()
                .as_nanos()
        ));
        if let Err(e) = std::fs::write(&path, content) {
            panic!("failed to write temp config {}: {}", path.display(), e);
        }
        path
    }

    fn minimal() -> NodeConfigFile {
        NodeConfigFile {
            mode: Some("validator".to_string()),
            data_dir: Some("/tmp/indra".to_string()),
            genesis: Some("/tmp/indra/genesis.toml".to_string()),
            keys_path: Some("/tmp/indra/keys.json".to_string()),
            rpc_access_token: Some("test-access".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_parse_minimal_config() {
        let path = temp_file(
            "minimal-config",
            r#"
[node]
mode = "validator"
data_dir = "/tmp/indra"
genesis = "/tmp/indra/genesis.toml"

[keys]
path = "/tmp/indra/keys.json"
password_file = "/tmp/indra/keys.pass"
"#,
        );
        let cfg = NodeConfigFile::load(&path).unwrap_or_else(|e| panic!("{}", e));
        assert_eq!(cfg.mode.as_deref(), Some("validator"));
        assert_eq!(cfg.data_dir.as_deref(), Some("/tmp/indra"));
        assert_eq!(cfg.keys_path.as_deref(), Some("/tmp/indra/keys.json"));
        assert_eq!(
            cfg.keys_password_file.as_deref(),
            Some("/tmp/indra/keys.pass")
        );
    }

    #[test]
    fn test_parse_full_config() {
        let path = temp_file(
            "full-config",
            r#"
[node]
mode = "validator"
chain_id = "indra-testnet-1"
data_dir = "/root/.indra/data"
genesis = "/root/.indra/data/genesis.toml"

[keys]
path = "/root/.indra/data/keys.json"
password_file = "/root/.indra/secrets/keys.pass"

[network]
p2p_addr = "0.0.0.0:30303"
observer_addr = "0.0.0.0:30304"
bootstrap_peers = ["1.1.1.1:30303", "2.2.2.2:30303"]
dns_seed_host = "seeds.indraprotocol.com"
dns_discovery_enabled = false
dns_seed_validation = "require"
dns_seed_signed_validation = "warn"
peers_file = "/root/.indra/data/peers.json"

[rpc]
addr = "127.0.0.1:8545"
enabled = true
admin_token = "local-admin"
access_token = "local-access"
trusted_tls_proxy = false
per_ip_connection_cap = 4
cors_origins = ["http://localhost:3000"]

[rpc_public]
addr = "127.0.0.1:8547"
enabled = true
trusted_tls_proxy = false
per_ip_connection_cap = 4
cors_origins = ["https://explorer.indraprotocol.com"]
per_ip_rate_per_sec = 5
per_ip_burst = 20
global_rate_per_sec = 100
global_burst = 200
max_body_bytes = 65536
timeout_ms = 10000

[metrics]
addr = "0.0.0.0:9615"
enabled = true

[storage]
prune_keep_blocks = 50000
snapshot_interval = 300
mempool_capacity = 5000
staking_mempool_capacity = 5001
governance_mempool_capacity = 2400
"#,
        );
        let cfg = NodeConfigFile::load(&path).unwrap_or_else(|e| panic!("{}", e));
        assert_eq!(cfg.p2p_addr.as_deref(), Some("0.0.0.0:30303"));
        assert_eq!(cfg.bootstrap_peers.len(), 2);
        assert_eq!(cfg.dns_discovery_enabled, Some(false));
        assert_eq!(cfg.dns_seed_validation.as_deref(), Some("require"));
        assert_eq!(cfg.dns_seed_signed_validation.as_deref(), Some("warn"));
        assert_eq!(cfg.rpc_enabled, Some(true));
        assert_eq!(cfg.rpc_admin_token.as_deref(), Some("local-admin"));
        assert_eq!(cfg.rpc_access_token.as_deref(), Some("local-access"));
        assert_eq!(
            cfg.rpc_cors_origins,
            vec!["http://localhost:3000".to_string()]
        );
        assert_eq!(cfg.rpc_public_addr.as_deref(), Some("127.0.0.1:8547"));
        assert_eq!(cfg.rpc_public_enabled, Some(true));
        assert_eq!(
            cfg.rpc_public_cors_origins,
            vec!["https://explorer.indraprotocol.com".to_string()]
        );
        assert_eq!(cfg.rpc_public_per_ip_rate_per_sec, Some(5));
        assert_eq!(cfg.rpc_public_per_ip_burst, Some(20));
        assert_eq!(cfg.rpc_public_global_rate_per_sec, Some(100));
        assert_eq!(cfg.rpc_public_global_burst, Some(200));
        assert_eq!(cfg.rpc_public_max_body_bytes, Some(65536));
        assert_eq!(cfg.rpc_public_timeout_ms, Some(10000));
        assert_eq!(cfg.metrics_addr.as_deref(), Some("0.0.0.0:9615"));
        assert_eq!(cfg.mempool_capacity, Some(5000));
        assert_eq!(cfg.staking_mempool_capacity, Some(5001));
        assert_eq!(cfg.governance_mempool_capacity, Some(2400));
    }

    #[test]
    fn test_parse_bootstrap_peers_array() {
        let path = temp_file(
            "bootstrap-config",
            r#"
[network]
bootstrap_peers = ["a.example:30303", "b.example:30303"]
"#,
        );
        let cfg = NodeConfigFile::load(&path).unwrap_or_else(|e| panic!("{}", e));
        assert_eq!(
            cfg.bootstrap_peers,
            vec!["a.example:30303".to_string(), "b.example:30303".to_string()]
        );
    }

    #[test]
    fn dns_seed_validation_defaults_to_warn_when_unset() {
        let cfg = minimal();
        let node = cfg.to_node_config(None).unwrap_err();
        assert!(node.contains("validator mode requires keys.json data"));

        let mut observer = cfg;
        observer.mode = Some("observer".to_string());
        let node = observer.to_node_config(None).unwrap();
        assert_eq!(node.dns_seed_validation, DnsSeedValidationMode::Warn);
        assert_eq!(
            node.dns_seed_signed_validation,
            SignedDnsSeedValidationMode::Off
        );
    }

    #[test]
    fn test_validate_invalid_dns_seed_validation_mode() {
        let mut cfg = minimal();
        cfg.dns_seed_validation = Some("maybe".to_string());
        let err = cfg.validate().err().unwrap_or_else(|| vec![]);
        assert!(err.iter().any(|e| e.contains("dns_seed_validation")));
    }

    #[test]
    fn test_validate_invalid_signed_dns_seed_config() {
        let mut cfg = minimal();
        cfg.dns_seed_signed_validation = Some("maybe".to_string());
        cfg.dns_seed_signed_public_key = Some("abcd".to_string());
        let err = cfg.validate().err().unwrap_or_else(|| vec![]);
        assert!(err.iter().any(|e| e.contains("dns_seed_signed_validation")));
        assert!(err.iter().any(|e| e.contains("dns_seed_signed_public_key")));
    }

    #[test]
    fn test_validate_signed_dns_seed_requires_public_key() {
        let mut cfg = minimal();
        cfg.dns_seed_signed_validation = Some("warn".to_string());
        let err = cfg.validate().err().unwrap_or_else(|| vec![]);
        assert!(err
            .iter()
            .any(|e| e.contains("dns_seed_signed_public_key is required")));
    }

    #[test]
    fn signed_dns_seed_security_setting_misplaced_outside_network_is_rejected() {
        let path = temp_file(
            "misplaced-signed-dns-config",
            &format!(
                r#"
[node]
mode = "observer"
data_dir = "/tmp/indra"
genesis = "/tmp/indra/genesis.toml"

[rpc]
dns_seed_signed_validation = "warn"
dns_seed_signed_public_key = "{}"
"#,
                "00".repeat(PQ_PK_BYTES)
            ),
        );
        let err = NodeConfigFile::load(&path).err().unwrap_or_default();

        assert!(err.contains("unrecognized config key rpc.dns_seed_signed_validation"));
        assert!(err.contains("unrecognized config key rpc.dns_seed_signed_public_key"));
        assert!(err.contains("move it there"));
    }

    #[test]
    fn unknown_config_table_is_rejected() {
        let path = temp_file(
            "unknown-config-table",
            r#"
[node]
mode = "observer"
data_dir = "/tmp/indra"
genesis = "/tmp/indra/genesis.toml"

[experimental]
future_flag = true
"#,
        );
        let err = NodeConfigFile::load(&path).err().unwrap_or_default();
        assert!(err.contains("unrecognized config table [experimental]"));
    }

    #[test]
    fn unknown_config_key_in_known_table_is_rejected() {
        let path = temp_file(
            "unknown-config-key",
            r#"
[node]
mode = "observer"
data_dir = "/tmp/indra"
genesis = "/tmp/indra/genesis.toml"
extra_security_mode = "warn"
"#,
        );
        let err = NodeConfigFile::load(&path).err().unwrap_or_default();
        assert!(err.contains("unrecognized config key node.extra_security_mode"));
    }

    #[test]
    fn test_validate_missing_data_dir() {
        let err = NodeConfigFile::default()
            .validate()
            .err()
            .unwrap_or_else(|| vec![]);
        assert!(err.iter().any(|e| e.contains("data_dir")));
    }

    #[test]
    fn test_validate_invalid_p2p_addr() {
        let mut cfg = minimal();
        cfg.p2p_addr = Some("bad-address".to_string());
        let err = cfg.validate().err().unwrap_or_else(|| vec![]);
        assert!(err.iter().any(|e| e.contains("p2p_addr")));
    }

    #[test]
    fn test_validate_invalid_port_zero() {
        let mut cfg = minimal();
        cfg.p2p_addr = Some("127.0.0.1:0".to_string());
        let err = cfg.validate().err().unwrap_or_else(|| vec![]);
        assert!(err.iter().any(|e| e.contains("port")));
    }

    #[test]
    fn test_validate_invalid_rpc_public_addr() {
        let mut cfg = minimal();
        cfg.rpc_public_addr = Some("bad-public-rpc".to_string());
        let err = cfg.validate().err().unwrap_or_else(|| vec![]);
        assert!(err.iter().any(|e| e.contains("rpc_public.addr")));
    }

    #[test]
    fn rpc_security_configuration_fails_closed() {
        let mut cfg = minimal();
        cfg.rpc_access_token = None;
        cfg.rpc_enabled = Some(true);
        cfg.rpc_addr = Some("0.0.0.0:8545".to_string());
        cfg.rpc_public_enabled = Some(true);
        cfg.rpc_public_addr = Some("0.0.0.0:8547".to_string());
        cfg.rpc_per_ip_connection_cap = Some(0);
        cfg.rpc_public_per_ip_connection_cap = Some(65);
        let errors = cfg.validate().unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.contains("rpc.access_token")));
        assert!(errors
            .iter()
            .any(|error| error.contains("rpc.trusted_tls_proxy")));
        assert!(errors
            .iter()
            .any(|error| error.contains("rpc_public.trusted_tls_proxy")));
        assert!(errors
            .iter()
            .any(|error| error.contains("rpc.per_ip_connection_cap")));
        assert!(errors
            .iter()
            .any(|error| error.contains("rpc_public.per_ip_connection_cap")));

        cfg.rpc_access_token = Some("access".to_string());
        cfg.rpc_trusted_tls_proxy = Some(true);
        cfg.rpc_public_trusted_tls_proxy = Some(true);
        cfg.rpc_per_ip_connection_cap = Some(4);
        cfg.rpc_public_per_ip_connection_cap = Some(4);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_collects_all_errors() {
        let cfg = NodeConfigFile {
            p2p_addr: Some("nope".to_string()),
            metrics_addr: Some("also-nope".to_string()),
            ..Default::default()
        };
        let err = cfg.validate().err().unwrap_or_else(|| vec![]);
        assert!(err.iter().any(|e| e.contains("data_dir")));
        assert!(err.iter().any(|e| e.contains("p2p_addr")));
    }

    #[test]
    fn test_validate_observer_mode_no_keys() {
        let cfg = NodeConfigFile {
            mode: Some("observer".to_string()),
            data_dir: Some("/tmp/indra-observer".to_string()),
            genesis: Some("/tmp/indra-observer/genesis.toml".to_string()),
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_prune_keep_below_minimum() {
        let mut cfg = minimal();
        cfg.prune_keep_blocks = Some(MIN_PRUNE_KEEP_BLOCKS.saturating_sub(1));
        let err = cfg.validate().err().unwrap_or_else(|| vec![]);
        assert!(err.iter().any(|e| e.contains("prune_keep_blocks")));
    }

    #[test]
    fn test_validate_rejects_pool_capacities_outside_hard_ranges() {
        let governance_max = crate::config::max_governance_mempool_capacity();
        for (key, mutate) in [
            (
                "storage.mempool_capacity",
                (|cfg: &mut NodeConfigFile| cfg.mempool_capacity = Some(0))
                    as fn(&mut NodeConfigFile),
            ),
            (
                "storage.staking_mempool_capacity",
                (|cfg: &mut NodeConfigFile| cfg.staking_mempool_capacity = Some(0))
                    as fn(&mut NodeConfigFile),
            ),
            (
                "storage.governance_mempool_capacity",
                (|cfg: &mut NodeConfigFile| cfg.governance_mempool_capacity = Some(0))
                    as fn(&mut NodeConfigFile),
            ),
        ] {
            let mut cfg = minimal();
            mutate(&mut cfg);
            let errors = cfg.validate().unwrap_err();
            assert!(errors.iter().any(|error| error.contains(key)));
        }

        let mut cfg = minimal();
        cfg.mempool_capacity = Some(crate::config::MAX_MEMPOOL_CAPACITY + 1);
        cfg.staking_mempool_capacity = Some(crate::config::MAX_STAKING_MEMPOOL_CAPACITY + 1);
        cfg.governance_mempool_capacity = Some(governance_max + 1);
        let errors = cfg.validate().unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.contains("storage.mempool_capacity")));
        assert!(errors
            .iter()
            .any(|error| error.contains("storage.staking_mempool_capacity")));
        assert!(errors
            .iter()
            .any(|error| error.contains("storage.governance_mempool_capacity")));
    }

    #[test]
    fn test_validate_accepts_pool_capacity_range_endpoints() {
        for (transaction, staking, governance) in [
            (1, 1, 1),
            (
                crate::config::MAX_MEMPOOL_CAPACITY,
                crate::config::MAX_STAKING_MEMPOOL_CAPACITY,
                crate::config::max_governance_mempool_capacity(),
            ),
        ] {
            let mut cfg = minimal();
            cfg.mempool_capacity = Some(transaction);
            cfg.staking_mempool_capacity = Some(staking);
            cfg.governance_mempool_capacity = Some(governance);
            assert!(cfg.validate().is_ok());
        }
    }

    #[test]
    fn test_load_nonexistent_file() {
        let path = PathBuf::from("/tmp/indra-definitely-missing-config.toml");
        let err = NodeConfigFile::load(&path).err().unwrap_or_default();
        assert!(err.contains("cannot read config file"));
        assert!(err.contains("/tmp/indra-definitely-missing-config.toml"));
    }

    #[test]
    fn test_load_invalid_toml() {
        let path = temp_file("invalid-config", "not = [valid");
        let err = NodeConfigFile::load(&path).err().unwrap_or_default();
        assert!(err.contains("config.toml parse error"));
    }

    #[test]
    fn test_to_node_config_defaults() {
        let cfg = minimal();
        let node = cfg
            .to_node_config(Some(&keys()))
            .unwrap_or_else(|e| panic!("{}", e));
        assert_eq!(node.p2p_addr, "0.0.0.0:30303");
        assert_eq!(node.dns_seed_host, DNS_SEED_HOSTS.join(","));
        assert!(node.dns_discovery_enabled);
        assert_eq!(node.peers_file, "/tmp/indra/peers.json");
        assert_eq!(node.prune_keep_blocks, Some(DEFAULT_PRUNE_KEEP_BLOCKS));
        assert_eq!(
            node.metrics_addr.as_deref(),
            Some(crate::metrics::DEFAULT_METRICS_ADDR)
        );
    }

    #[test]
    fn test_cli_override_beats_config_file() {
        let mut cfg = minimal();
        cfg.p2p_addr = Some("0.0.0.0:30303".to_string());
        cfg.p2p_addr = Some("0.0.0.0:30304".to_string());
        let node = cfg
            .to_node_config(Some(&keys()))
            .unwrap_or_else(|e| panic!("{}", e));
        assert_eq!(node.p2p_addr, "0.0.0.0:30304");
    }

    #[test]
    fn test_archive_mode_when_prune_zero() {
        let mut cfg = minimal();
        cfg.prune_keep_blocks = Some(0);
        let node = cfg
            .to_node_config(Some(&keys()))
            .unwrap_or_else(|e| panic!("{}", e));
        assert_eq!(node.prune_keep_blocks, None);
    }
}
