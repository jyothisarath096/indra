//! Peer discovery — DNS seeding, peer exchange, and peer table persistence.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    future::Future,
    io,
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    str::FromStr,
};

use hickory_resolver::{
    config::{ResolveHosts, ResolverConfig, CLOUDFLARE},
    net::runtime::TokioRuntimeProvider,
    proto::{
        dnssec::Proof,
        rr::{RData, RecordType},
    },
    Resolver,
};
use indra_core::types::primitives::{DNS_SEED_HOSTS, MAX_PEER_LIST_SIZE};
use indra_crypto::{sha256, verify_pq, PqKeypair, PqPublicKey, PqSignature};
use indra_network::PeerListEntry;

/// DNS seeds currently publish IPv4 validator addresses only.
///
/// Querying AAAA unconditionally adds no discovery value for today's network and
/// can surface resolver/provider-specific DNSSEC negative-response errors for a
/// record type we do not consume. Add `RecordType::AAAA` here only when seed
/// records and validator operations explicitly support IPv6 bootstrap
/// addresses.
const DNS_SEED_RECORD_TYPES: &[RecordType] = &[RecordType::A];

/// Root record prefix for INDRA's signed DNS discovery list.
///
/// Ethereum EIP-1459 signs a compact secp256k1 root directly in one TXT
/// record. INDRA keeps the same "DNS is transport, a separately-known public
/// key is the trust anchor" model, but uses ML-DSA-87. The ML-DSA signature is
/// too large for one practical DNS TXT record, so the root commits to
/// hash-addressed signature chunks and node-list chunks instead of embedding
/// the signature inline.
pub const SIGNED_DNS_DISCOVERY_ROOT_PREFIX: &str = "indradisc-root:v1";

/// Domain separator for the ML-DSA-87 signature over a signed DNS seed root.
pub const SIGNED_DNS_DISCOVERY_SIGNING_DOMAIN: &[u8] = b"INDRA-signed-dns-discovery-root-v1:";

const SIGNED_DNS_DISCOVERY_CHUNK_HEX_LEN: usize = 240;

/// Parsed signed DNS discovery root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDnsSeedRoot {
    /// Monotonically increasing publisher sequence number.
    pub seq: u64,
    /// SHA-256 hash of the concatenated node-list payload.
    pub nodes_hash: [u8; 32],
    /// Number of node-list TXT chunks.
    pub nodes_chunks: usize,
    /// SHA-256 hash of the concatenated ML-DSA signature bytes.
    pub sig_hash: [u8; 32],
    /// Number of signature TXT chunks.
    pub sig_chunks: usize,
}

/// DNS TXT records needed to publish a signed discovery list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDnsSeedRecords {
    /// Root TXT record content for the seed hostname.
    pub root_txt: String,
    /// Hash-addressed node-list chunk records: `(relative_name, txt_content)`.
    pub node_chunks: Vec<(String, String)>,
    /// Hash-addressed signature chunk records: `(relative_name, txt_content)`.
    pub sig_chunks: Vec<(String, String)>,
}

/// DNSSEC policy for DNS seed hostname resolution.
///
/// DNS seeds are only one discovery layer, so even `Require` rejects only the
/// DNS seed answer itself; node startup continues via bootstrap peers,
/// persisted peers, genesis hints, PEX, and on-chain validator addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsSeedValidationMode {
    /// Use ordinary OS DNS resolution with no DNSSEC attempt.
    Off,
    /// Attempt DNSSEC-aware resolution and log on unsigned/invalid answers, but
    /// keep using returned addresses until the real zone is operationally signed.
    Warn,
    /// Accept only DNSSEC-secure answers. Unsigned, bogus, and unvalidated seed
    /// answers are ignored.
    Require,
}

impl DnsSeedValidationMode {
    /// Default DNS seed validation mode.
    ///
    /// This remains `warn` until the operational DNSSEC signing step for the
    /// real `indraprotocol.com` zone has been completed and externally verified.
    pub const DEFAULT: Self = Self::Warn;

    /// Return the config-file string for this mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Warn => "warn",
            Self::Require => "require",
        }
    }
}

impl Default for DnsSeedValidationMode {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for DnsSeedValidationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DnsSeedValidationMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "warn" => Ok(Self::Warn),
            "require" => Ok(Self::Require),
            other => Err(format!(
                "network.dns_seed_validation must be one of off, warn, require (got {other:?})"
            )),
        }
    }
}

/// Validation policy for INDRA's signed DNS node-list overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedDnsSeedValidationMode {
    /// Do not attempt signed-list discovery; use existing A-record discovery.
    Off,
    /// Prefer a valid signed list when configured, but fall back to A records.
    Warn,
    /// Require a valid signed list when DNS seed discovery is used.
    Require,
}

impl SignedDnsSeedValidationMode {
    /// Default signed DNS discovery mode.
    pub const DEFAULT: Self = Self::Off;

    /// Return the config-file string for this mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Warn => "warn",
            Self::Require => "require",
        }
    }
}

impl Default for SignedDnsSeedValidationMode {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for SignedDnsSeedValidationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SignedDnsSeedValidationMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "warn" => Ok(Self::Warn),
            "require" => Ok(Self::Require),
            other => Err(format!(
                "network.dns_seed_signed_validation must be one of off, warn, require (got {other:?})"
            )),
        }
    }
}

/// DNSSEC validation status for a seed response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsSeedValidationStatus {
    /// DNSSEC validation was not attempted.
    Unchecked,
    /// The returned address RRset was DNSSEC-signed and accepted by the
    /// DNSSEC-validating resolver.
    Secure,
    /// A response was returned without DNSSEC signatures.
    Unsigned,
    /// DNSSEC validation failed or the answer could not be authenticated.
    Bogus,
    /// The resolver could not determine whether the answer should have been
    /// signed, usually because required DNSSEC metadata was unavailable.
    Indeterminate,
}

#[derive(Debug, Clone)]
struct DnsSeedLookup {
    addrs: Vec<SocketAddr>,
    status: DnsSeedValidationStatus,
}

#[derive(Debug, Clone)]
struct SignedDnsSeedTxtLookup {
    root_txt: String,
    node_chunks: Vec<String>,
    sig_chunks: Vec<String>,
}

/// Node-local replay protection for signed DNS discovery.
///
/// DNS remains a best-effort discovery layer, but signed discovery must not
/// accept a lower sequence number after this node has already verified a newer
/// list for the same seed hostname. The file is node-local operational state,
/// not consensus state.
#[derive(Debug, Default)]
struct SignedDnsSeqStore {
    path: Option<PathBuf>,
    highest_by_host: HashMap<String, u64>,
}

impl SignedDnsSeqStore {
    fn load(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let mut highest_by_host = HashMap::new();
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                for (line_no, line) in content.lines().enumerate() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let mut parts = line.split_whitespace();
                    let Some(host) = parts.next() else {
                        continue;
                    };
                    let Some(seq) = parts.next() else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "signed DNS replay state {} line {} missing sequence",
                                path.display(),
                                line_no + 1
                            ),
                        ));
                    };
                    if parts.next().is_some() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "signed DNS replay state {} line {} has extra fields",
                                path.display(),
                                line_no + 1
                            ),
                        ));
                    }
                    let seq = seq.parse::<u64>().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "signed DNS replay state {} line {} has invalid sequence",
                                path.display(),
                                line_no + 1
                            ),
                        )
                    })?;
                    highest_by_host.insert(host.to_string(), seq);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        Ok(Self {
            path: Some(path),
            highest_by_host,
        })
    }

    fn highest_seq(&self, host: &str) -> Option<u64> {
        self.highest_by_host.get(host).copied()
    }

    fn record_verified(&mut self, host: &str, seq: u64) -> io::Result<()> {
        if self.highest_seq(host).is_some_and(|current| seq <= current) {
            return Ok(());
        }
        self.highest_by_host.insert(host.to_string(), seq);
        self.save()
    }

    fn save(&self) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut entries: Vec<_> = self.highest_by_host.iter().collect();
        entries.sort_by(|(host_a, _), (host_b, _)| host_a.cmp(host_b));
        let mut content = String::from("# INDRA signed DNS discovery highest verified sequences\n");
        for (host, seq) in entries {
            content.push_str(host);
            content.push(' ');
            content.push_str(&seq.to_string());
            content.push('\n');
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, content)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }
}

/// Default node-local path for signed DNS replay-protection state.
pub fn signed_dns_replay_state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("signed_dns_sequences")
}

/// Encode the default DNS seed list into the existing config string field.
pub fn default_dns_seed_hosts_config() -> String {
    DNS_SEED_HOSTS.join(",")
}

fn parse_dns_seed_hosts(hosts: &str) -> Vec<String> {
    hosts
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn resolve_dns_seed_hosts_with<F>(hosts: &[String], port: u16, mut resolver: F) -> Vec<SocketAddr>
where
    F: FnMut(&str) -> io::Result<Vec<SocketAddr>>,
{
    resolve_dns_seed_hosts_with_status(hosts, port, DnsSeedValidationMode::Off, |addr_str| {
        resolver(addr_str).map(|addrs| DnsSeedLookup {
            addrs,
            status: DnsSeedValidationStatus::Unchecked,
        })
    })
}

fn resolve_dns_seed_hosts_with_status<F>(
    hosts: &[String],
    port: u16,
    mode: DnsSeedValidationMode,
    mut resolver: F,
) -> Vec<SocketAddr>
where
    F: FnMut(&str) -> io::Result<DnsSeedLookup>,
{
    let mut addrs = HashSet::new();
    for host in hosts {
        let addr_str = format!("{host}:{port}");
        match resolver(&addr_str) {
            Ok(lookup) => {
                let status = lookup.status;
                if status != DnsSeedValidationStatus::Secure && mode == DnsSeedValidationMode::Warn
                {
                    eprintln!(
                        "[discovery] DNS seed {} returned {} DNSSEC status in warn mode — using addresses for now; enable zone signing before switching network.dns_seed_validation=require",
                        host,
                        dnssec_status_label(status)
                    );
                }
                if status != DnsSeedValidationStatus::Secure
                    && mode == DnsSeedValidationMode::Require
                {
                    eprintln!(
                        "[discovery] DNS seed {} rejected: DNSSEC status {} is not secure",
                        host,
                        dnssec_status_label(status)
                    );
                    continue;
                }
                if !lookup.addrs.is_empty() {
                    eprintln!(
                        "[discovery] DNS seed {} resolved to {} addresses (dnssec={})",
                        host,
                        lookup.addrs.len(),
                        dnssec_status_label(status)
                    );
                }
                addrs.extend(lookup.addrs);
            }
            Err(e) => {
                eprintln!(
                    "[discovery] DNS seed {} resolution failed: {} — using bootstrap peers only",
                    host, e
                );
            }
        }
    }

    let mut resolved: Vec<SocketAddr> = addrs.into_iter().collect();
    resolved.sort();
    resolved
}

async fn resolve_dns_seed_hosts_with_status_async<F, Fut>(
    hosts: &[String],
    port: u16,
    mode: DnsSeedValidationMode,
    mut resolver: F,
) -> Vec<SocketAddr>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = io::Result<DnsSeedLookup>>,
{
    let mut addrs = HashSet::new();
    for host in hosts {
        let addr_str = format!("{host}:{port}");
        match resolver(addr_str).await {
            Ok(lookup) => {
                let status = lookup.status;
                if status != DnsSeedValidationStatus::Secure && mode == DnsSeedValidationMode::Warn
                {
                    eprintln!(
                        "[discovery] DNS seed {} returned {} DNSSEC status in warn mode — using addresses for now; enable zone signing before switching network.dns_seed_validation=require",
                        host,
                        dnssec_status_label(status)
                    );
                }
                if status != DnsSeedValidationStatus::Secure
                    && mode == DnsSeedValidationMode::Require
                {
                    eprintln!(
                        "[discovery] DNS seed {} rejected: DNSSEC status {} is not secure",
                        host,
                        dnssec_status_label(status)
                    );
                    continue;
                }
                if !lookup.addrs.is_empty() {
                    eprintln!(
                        "[discovery] DNS seed {} resolved to {} addresses (dnssec={})",
                        host,
                        lookup.addrs.len(),
                        dnssec_status_label(status)
                    );
                }
                addrs.extend(lookup.addrs);
            }
            Err(e) => {
                eprintln!(
                    "[discovery] DNS seed {} resolution failed: {} — using bootstrap peers only",
                    host, e
                );
            }
        }
    }

    let mut resolved: Vec<SocketAddr> = addrs.into_iter().collect();
    resolved.sort();
    resolved
}

#[cfg(test)]
fn resolve_signed_dns_seed_hosts_with<F>(
    hosts: &[String],
    mode: SignedDnsSeedValidationMode,
    public_key: Option<&PqPublicKey>,
    mut resolver: F,
) -> Vec<SocketAddr>
where
    F: FnMut(&str) -> io::Result<SignedDnsSeedTxtLookup>,
{
    let mut addrs = HashSet::new();
    if mode == SignedDnsSeedValidationMode::Off {
        return Vec::new();
    }
    let Some(public_key) = public_key else {
        eprintln!(
            "[discovery] signed DNS discovery {}: no public key configured",
            if mode == SignedDnsSeedValidationMode::Require {
                "required but unavailable"
            } else {
                "unavailable"
            }
        );
        return Vec::new();
    };

    for host in hosts {
        match resolver(host) {
            Ok(lookup) => match verify_signed_dns_seed_records(
                &lookup.root_txt,
                &lookup.node_chunks,
                &lookup.sig_chunks,
                public_key,
            ) {
                Ok(host_addrs) => {
                    eprintln!(
                        "[discovery] signed DNS seed {} verified {} addresses",
                        host,
                        host_addrs.len()
                    );
                    addrs.extend(host_addrs);
                }
                Err(err) => {
                    eprintln!("[discovery] signed DNS seed {} rejected: {}", host, err);
                }
            },
            Err(err) => {
                eprintln!("[discovery] signed DNS seed {} unavailable: {}", host, err);
            }
        }
    }

    let mut resolved: Vec<SocketAddr> = addrs.into_iter().collect();
    resolved.sort();
    resolved
}

async fn resolve_signed_dns_seed_hosts_with_async<F, Fut>(
    hosts: &[String],
    mode: SignedDnsSeedValidationMode,
    public_key: Option<&PqPublicKey>,
    mut replay_store: Option<&mut SignedDnsSeqStore>,
    mut resolver: F,
) -> Vec<SocketAddr>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = io::Result<SignedDnsSeedTxtLookup>>,
{
    let mut addrs = HashSet::new();
    if mode == SignedDnsSeedValidationMode::Off {
        eprintln!("[discovery] signed DNS discovery disabled (mode=off)");
        return Vec::new();
    }
    let Some(public_key) = public_key else {
        eprintln!(
            "[discovery] signed DNS discovery {}: no public key configured",
            if mode == SignedDnsSeedValidationMode::Require {
                "required but unavailable"
            } else {
                "unavailable"
            }
        );
        return Vec::new();
    };

    for host in hosts {
        eprintln!(
            "[discovery] signed DNS seed {}: starting lookup (mode={})",
            host, mode
        );
        match resolver(host.clone()).await {
            Ok(lookup) => {
                eprintln!(
                    "[discovery] signed DNS seed {}: fetched root plus {} node chunk(s) and {} signature chunk(s)",
                    host,
                    lookup.node_chunks.len(),
                    lookup.sig_chunks.len()
                );
                let root = match parse_signed_dns_seed_root(&lookup.root_txt) {
                    Ok(root) => root,
                    Err(err) => {
                        eprintln!("[discovery] signed DNS seed {} rejected: {}", host, err);
                        continue;
                    }
                };
                if let Some(store) = replay_store.as_deref_mut() {
                    if let Some(highest) = store.highest_seq(host) {
                        if root.seq < highest {
                            eprintln!(
                                "[discovery] signed DNS seed {} rejected: replayed sequence {} below persisted highest {}",
                                host, root.seq, highest
                            );
                            continue;
                        }
                    }
                }
                match verify_signed_dns_seed_records(
                    &lookup.root_txt,
                    &lookup.node_chunks,
                    &lookup.sig_chunks,
                    public_key,
                ) {
                    Ok(host_addrs) => {
                        if let Some(store) = replay_store.as_deref_mut() {
                            if let Err(err) = store.record_verified(host, root.seq) {
                                eprintln!(
                                    "[discovery] signed DNS seed {} rejected: could not persist verified sequence {}: {}",
                                    host, root.seq, err
                                );
                                continue;
                            }
                        }
                        eprintln!(
                            "[discovery] signed DNS seed {} verified {} addresses at seq={}",
                            host,
                            host_addrs.len(),
                            root.seq
                        );
                        addrs.extend(host_addrs);
                    }
                    Err(err) => {
                        eprintln!("[discovery] signed DNS seed {} rejected: {}", host, err);
                    }
                }
            }
            Err(err) => {
                eprintln!("[discovery] signed DNS seed {} unavailable: {}", host, err);
            }
        }
    }

    let mut resolved: Vec<SocketAddr> = addrs.into_iter().collect();
    resolved.sort();
    resolved
}

fn dnssec_status_label(status: DnsSeedValidationStatus) -> &'static str {
    match status {
        DnsSeedValidationStatus::Unchecked => "unchecked",
        DnsSeedValidationStatus::Secure => "secure",
        DnsSeedValidationStatus::Unsigned => "unsigned",
        DnsSeedValidationStatus::Bogus => "bogus",
        DnsSeedValidationStatus::Indeterminate => "indeterminate",
    }
}

/// Resolve DNS seed hostname to a list of socket addresses.
///
/// Returns an empty vec on failure. Discovery is best-effort and must not
/// prevent node startup.
///
/// `hosts` may contain one hostname or a comma-separated host list. DNS seeds
/// supplement configured bootstrap peers but never replace them; a node with
/// configured bootstrap peers can function if DNS resolution returns nothing.
///
/// DNSSEC validation is controlled by `network.dns_seed_validation`. A poisoned
/// unchecked DNS response can cause dial churn, but cannot eclipse consensus
/// because the validator transport rejects unknown validator identities.
pub async fn resolve_dns_seeds(hosts: &str, port: u16) -> Vec<SocketAddr> {
    resolve_dns_seeds_with_validation(hosts, port, DnsSeedValidationMode::DEFAULT).await
}

/// Resolve DNS seed hostnames with the configured DNSSEC validation mode.
pub async fn resolve_dns_seeds_with_validation(
    hosts: &str,
    port: u16,
    mode: DnsSeedValidationMode,
) -> Vec<SocketAddr> {
    resolve_dns_seeds_with_policies(hosts, port, mode, SignedDnsSeedValidationMode::Off, None).await
}

/// Resolve DNS seed hostnames with DNSSEC and signed-list policy controls.
///
/// A valid signed list is preferred when configured. In `require` mode an
/// absent or invalid signed list rejects DNS seed discovery for that cycle, but
/// discovery remains best-effort overall: bootstrap peers, persisted peers,
/// PEX, genesis hints, and on-chain validator addresses continue to work.
pub async fn resolve_dns_seeds_with_policies(
    hosts: &str,
    port: u16,
    mode: DnsSeedValidationMode,
    signed_mode: SignedDnsSeedValidationMode,
    signed_public_key: Option<&PqPublicKey>,
) -> Vec<SocketAddr> {
    resolve_dns_seeds_with_policies_and_replay_store(
        hosts,
        port,
        mode,
        signed_mode,
        signed_public_key,
        None,
    )
    .await
}

/// Resolve DNS seed hostnames with policy controls and node-local signed-list
/// replay protection.
pub async fn resolve_dns_seeds_with_policies_and_replay_store(
    hosts: &str,
    port: u16,
    mode: DnsSeedValidationMode,
    signed_mode: SignedDnsSeedValidationMode,
    signed_public_key: Option<&PqPublicKey>,
    signed_replay_state_path: Option<&Path>,
) -> Vec<SocketAddr> {
    let hosts = parse_dns_seed_hosts(hosts);
    eprintln!(
        "[discovery] DNS seed policy: hosts={} dnssec={} signed={} signed_key_configured={}",
        hosts.join(","),
        mode,
        signed_mode,
        signed_public_key.is_some()
    );
    if signed_mode != SignedDnsSeedValidationMode::Off {
        let mut replay_store_unavailable = false;
        let mut replay_store = match signed_replay_state_path {
            Some(path) => match SignedDnsSeqStore::load(path) {
                Ok(store) => Some(store),
                Err(err) => {
                    eprintln!(
                        "[discovery] signed DNS replay state unavailable at {}: {}",
                        path.display(),
                        err
                    );
                    if signed_mode == SignedDnsSeedValidationMode::Require {
                        return Vec::new();
                    }
                    replay_store_unavailable = true;
                    None
                }
            },
            None => None,
        };
        let signed = if replay_store_unavailable {
            eprintln!(
                "[discovery] signed DNS discovery skipped because replay protection state is unavailable; falling back to DNS A records"
            );
            Vec::new()
        } else {
            resolve_signed_dns_seed_hosts_with_async(
                &hosts,
                signed_mode,
                signed_public_key,
                replay_store.as_mut(),
                |host| async move { resolve_signed_seed_with_hickory_dnssec_async(&host).await },
            )
            .await
        };
        if !signed.is_empty() || signed_mode == SignedDnsSeedValidationMode::Require {
            eprintln!(
                "[discovery] signed DNS discovery final outcome: {} peer(s), fallback=false",
                signed.len()
            );
            return signed;
        }
        eprintln!(
            "[discovery] signed DNS discovery did not produce peers; falling back to DNS A records"
        );
    } else {
        eprintln!("[discovery] signed DNS discovery not attempted because mode=off");
    }

    match mode {
        DnsSeedValidationMode::Off => resolve_dns_seed_hosts_with(&hosts, port, |addr_str| {
            addr_str
                .to_socket_addrs()
                .map(|iter| iter.collect::<Vec<SocketAddr>>())
        }),
        DnsSeedValidationMode::Warn | DnsSeedValidationMode::Require => {
            resolve_dns_seed_hosts_with_status_async(&hosts, port, mode, |addr_str| async move {
                let (host, port) = split_host_port(&addr_str)?;
                resolve_seed_with_hickory_dnssec_async(&host, port).await
            })
            .await
        }
    }
}

async fn resolve_seed_with_hickory_dnssec_async(
    host: &str,
    port: u16,
) -> io::Result<DnsSeedLookup> {
    if let Ok(ip) = host.parse() {
        return Ok(DnsSeedLookup {
            addrs: vec![SocketAddr::new(ip, port)],
            status: DnsSeedValidationStatus::Unchecked,
        });
    }
    // Seed DNSSEC validation must not depend on each validator host's
    // `/etc/resolv.conf`. Hickory's `builder_tokio()` intentionally uses the
    // operating-system resolver configuration, which may point at a local or
    // provider resolver that strips DNSSEC metadata. For seed trust decisions we
    // query the same DNSSEC-capable Cloudflare resolver used by the operational
    // verification runbooks, then let Hickory validate the returned records.
    let mut builder = Resolver::builder_with_config(
        dnssec_seed_resolver_config(),
        TokioRuntimeProvider::default(),
    );
    {
        let opts = builder.options_mut();
        opts.validate = true;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.try_tcp_on_error = true;
    }
    let resolver = builder.build().map_err(|e| {
        io::Error::other(
            format!("DNS resolver build failed: {e}"),
        )
    })?;

    let mut addrs = Vec::new();
    let mut saw_unsigned_answer = false;
    let mut saw_secure_answer = false;
    let mut saw_bogus_answer = false;
    let mut saw_indeterminate_answer = false;
    let mut saw_lookup_error = false;

    let query_host = dns_query_name(host);

    for &record_type in DNS_SEED_RECORD_TYPES {
        match resolver.lookup(query_host.as_str(), record_type).await {
            Ok(lookup) => {
                let ips: Vec<_> = lookup
                    .answers()
                    .iter()
                    .filter(|record| record.record_type() == record_type)
                    .filter_map(|record| record.data.ip_addr())
                    .collect();
                if ips.is_empty() {
                    continue;
                }
                match dnssec_status_for_lookup_answers(&lookup, record_type) {
                    DnsSeedValidationStatus::Secure => saw_secure_answer = true,
                    DnsSeedValidationStatus::Unsigned => saw_unsigned_answer = true,
                    DnsSeedValidationStatus::Bogus => saw_bogus_answer = true,
                    DnsSeedValidationStatus::Indeterminate => saw_indeterminate_answer = true,
                    DnsSeedValidationStatus::Unchecked => {}
                }
                addrs.extend(ips.into_iter().map(|ip| SocketAddr::new(ip, port)));
            }
            Err(e) => {
                saw_lookup_error = true;
                eprintln!(
                    "[discovery] DNSSEC lookup for {} {} failed: {}",
                    host, record_type, e
                );
            }
        }
    }

    let status = if saw_bogus_answer {
        DnsSeedValidationStatus::Bogus
    } else if saw_indeterminate_answer {
        DnsSeedValidationStatus::Indeterminate
    } else if !addrs.is_empty() && saw_secure_answer && !saw_unsigned_answer {
        DnsSeedValidationStatus::Secure
    } else if !addrs.is_empty() && saw_unsigned_answer {
        DnsSeedValidationStatus::Unsigned
    } else if saw_lookup_error {
        DnsSeedValidationStatus::Bogus
    } else {
        DnsSeedValidationStatus::Unsigned
    };

    addrs.sort();
    addrs.dedup();
    Ok(DnsSeedLookup { addrs, status })
}

fn dnssec_status_for_lookup_answers(
    lookup: &hickory_resolver::lookup::Lookup,
    record_type: RecordType,
) -> DnsSeedValidationStatus {
    dnssec_status_from_proofs(
        lookup
            .answers()
            .iter()
            .filter(move |record| record.record_type() == record_type)
            .map(|record| record.proof),
    )
}

fn dnssec_status_from_proofs<I>(proofs: I) -> DnsSeedValidationStatus
where
    I: IntoIterator<Item = Proof>,
{
    let mut saw_secure = false;
    let mut saw_insecure = false;
    let mut saw_bogus = false;
    let mut saw_indeterminate = false;

    for proof in proofs {
        match proof {
            Proof::Secure => saw_secure = true,
            Proof::Insecure => saw_insecure = true,
            Proof::Bogus => saw_bogus = true,
            Proof::Indeterminate => saw_indeterminate = true,
        }
    }

    if saw_bogus {
        DnsSeedValidationStatus::Bogus
    } else if saw_indeterminate {
        DnsSeedValidationStatus::Indeterminate
    } else if saw_insecure {
        DnsSeedValidationStatus::Unsigned
    } else if saw_secure {
        DnsSeedValidationStatus::Secure
    } else {
        DnsSeedValidationStatus::Unsigned
    }
}

fn dnssec_seed_resolver_config() -> ResolverConfig {
    ResolverConfig::udp_and_tcp(&CLOUDFLARE)
}

fn dns_query_name(host: &str) -> String {
    if host.ends_with('.') {
        host.to_string()
    } else {
        format!("{host}.")
    }
}

async fn resolve_txt_records_dnssec(
    resolver: &Resolver<TokioRuntimeProvider>,
    name: &str,
) -> io::Result<Vec<String>> {
    eprintln!("[discovery] signed DNS TXT lookup: querying {name}");
    let lookup = resolver
        .lookup(dns_query_name(name).as_str(), RecordType::TXT)
        .await
        .map_err(|e| {
            io::Error::other(
                format!("TXT lookup for {name} failed: {e}"),
            )
        })?;
    let status = dnssec_status_for_lookup_answers(&lookup, RecordType::TXT);
    if status != DnsSeedValidationStatus::Secure {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "TXT lookup for {name} was not DNSSEC-secure (status={})",
                dnssec_status_label(status)
            ),
        ));
    }

    let records = lookup
        .answers()
        .iter()
        .filter(|record| record.record_type() == RecordType::TXT)
        .filter_map(|record| match &record.data {
            RData::TXT(txt) => {
                let bytes = txt
                    .txt_data
                    .iter()
                    .flat_map(|part| part.iter().copied())
                    .collect::<Vec<_>>();
                Some(String::from_utf8_lossy(&bytes).into_owned())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    eprintln!(
        "[discovery] signed DNS TXT lookup: {} returned {} secure TXT record(s)",
        name,
        records.len()
    );
    Ok(records)
}

async fn resolve_signed_seed_with_hickory_dnssec_async(
    host: &str,
) -> io::Result<SignedDnsSeedTxtLookup> {
    let mut builder = Resolver::builder_with_config(
        dnssec_seed_resolver_config(),
        TokioRuntimeProvider::default(),
    );
    {
        let opts = builder.options_mut();
        opts.validate = true;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.try_tcp_on_error = true;
    }
    let resolver = builder.build().map_err(|e| {
        io::Error::other(
            format!("DNS resolver build failed: {e}"),
        )
    })?;

    let roots = resolve_txt_records_dnssec(&resolver, host).await?;
    let root_txt = roots
        .into_iter()
        .find(|record| record.starts_with(SIGNED_DNS_DISCOVERY_ROOT_PREFIX))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("signed DNS root TXT not found at {host}"),
            )
        })?;
    let root = parse_signed_dns_seed_root(&root_txt)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    eprintln!(
        "[discovery] signed DNS seed {}: root seq={} nodes_chunks={} sig_chunks={}",
        host, root.seq, root.nodes_chunks, root.sig_chunks
    );

    let mut node_chunks = Vec::with_capacity(root.nodes_chunks);
    for idx in 0..root.nodes_chunks {
        let relative = signed_dns_seed_chunk_name("nodes", root.nodes_hash, idx);
        let name = format!("{relative}.{}", host.trim_end_matches('.'));
        let records = resolve_txt_records_dnssec(&resolver, &name).await?;
        let chunk = records.into_iter().next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("signed DNS node chunk {idx} not found at {name}"),
            )
        })?;
        node_chunks.push(chunk);
    }
    eprintln!(
        "[discovery] signed DNS seed {}: fetched all {} node chunk(s)",
        host,
        node_chunks.len()
    );

    let mut sig_chunks = Vec::with_capacity(root.sig_chunks);
    for idx in 0..root.sig_chunks {
        let relative = signed_dns_seed_chunk_name("sig", root.sig_hash, idx);
        let name = format!("{relative}.{}", host.trim_end_matches('.'));
        let records = resolve_txt_records_dnssec(&resolver, &name).await?;
        let chunk = records.into_iter().next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("signed DNS signature chunk {idx} not found at {name}"),
            )
        })?;
        sig_chunks.push(chunk);
    }
    eprintln!(
        "[discovery] signed DNS seed {}: fetched all {} signature chunk(s)",
        host,
        sig_chunks.len()
    );

    Ok(SignedDnsSeedTxtLookup {
        root_txt,
        node_chunks,
        sig_chunks,
    })
}

fn hex32(bytes: [u8; 32]) -> String {
    hex::encode(bytes)
}

fn parse_hex32(value: &str, field: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|_| format!("{field} must be hex"))?;
    if bytes.len() != 32 {
        return Err(format!("{field} must be 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_usize_field(value: &str, field: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("{field} must be an integer"))
}

fn parse_u64_field(value: &str, field: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{field} must be an integer"))
}

/// Parse an `indradisc-root:v1` TXT record.
pub fn parse_signed_dns_seed_root(root_txt: &str) -> Result<SignedDnsSeedRoot, String> {
    let mut parts = root_txt.split_whitespace();
    let prefix = parts
        .next()
        .ok_or_else(|| "signed DNS root is empty".to_string())?;
    if prefix != SIGNED_DNS_DISCOVERY_ROOT_PREFIX {
        return Err(format!(
            "signed DNS root must start with {SIGNED_DNS_DISCOVERY_ROOT_PREFIX}"
        ));
    }

    let mut seq = None;
    let mut nodes_hash = None;
    let mut nodes_chunks = None;
    let mut sig_hash = None;
    let mut sig_chunks = None;

    for part in parts {
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| format!("invalid signed DNS root field {part:?}"))?;
        match key {
            "seq" => seq = Some(parse_u64_field(value, "seq")?),
            "nodes" => nodes_hash = Some(parse_hex32(value, "nodes")?),
            "nodes_chunks" => nodes_chunks = Some(parse_usize_field(value, "nodes_chunks")?),
            "sig" => sig_hash = Some(parse_hex32(value, "sig")?),
            "sig_chunks" => sig_chunks = Some(parse_usize_field(value, "sig_chunks")?),
            _ => return Err(format!("unknown signed DNS root field {key:?}")),
        }
    }

    let root = SignedDnsSeedRoot {
        seq: seq.ok_or_else(|| "signed DNS root missing seq".to_string())?,
        nodes_hash: nodes_hash.ok_or_else(|| "signed DNS root missing nodes".to_string())?,
        nodes_chunks: nodes_chunks
            .ok_or_else(|| "signed DNS root missing nodes_chunks".to_string())?,
        sig_hash: sig_hash.ok_or_else(|| "signed DNS root missing sig".to_string())?,
        sig_chunks: sig_chunks.ok_or_else(|| "signed DNS root missing sig_chunks".to_string())?,
    };
    if root.nodes_chunks == 0 {
        return Err("signed DNS root must have at least one node chunk".to_string());
    }
    if root.sig_chunks == 0 {
        return Err("signed DNS root must have at least one signature chunk".to_string());
    }
    Ok(root)
}

fn signed_dns_seed_root_without_signature_fields(root: &SignedDnsSeedRoot) -> String {
    format!(
        "{} seq={} nodes={} nodes_chunks={}",
        SIGNED_DNS_DISCOVERY_ROOT_PREFIX,
        root.seq,
        hex32(root.nodes_hash),
        root.nodes_chunks,
    )
}

fn signed_dns_seed_signing_message(root: &SignedDnsSeedRoot) -> Vec<u8> {
    let canonical = signed_dns_seed_root_without_signature_fields(root);
    let mut msg = Vec::with_capacity(SIGNED_DNS_DISCOVERY_SIGNING_DOMAIN.len() + canonical.len());
    msg.extend_from_slice(SIGNED_DNS_DISCOVERY_SIGNING_DOMAIN);
    msg.extend_from_slice(canonical.as_bytes());
    msg
}

fn chunk_hex(bytes: &[u8]) -> Vec<String> {
    let hex = hex::encode(bytes);
    hex.as_bytes()
        .chunks(SIGNED_DNS_DISCOVERY_CHUNK_HEX_LEN)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect()
}

fn reassemble_hex_chunks(
    chunks: &[String],
    expected_count: usize,
    field: &str,
) -> Result<Vec<u8>, String> {
    if chunks.len() != expected_count {
        return Err(format!(
            "{field} chunk count mismatch: got {}, expected {expected_count}",
            chunks.len()
        ));
    }
    let joined = chunks.join("");
    hex::decode(joined).map_err(|_| format!("{field} chunks are not valid hex"))
}

fn signed_dns_seed_chunk_name(kind: &str, hash: [u8; 32], index: usize) -> String {
    format!(
        "_indra-seed-{}-{}-{}",
        kind,
        index,
        &hex::encode(hash)[..16]
    )
}

/// Canonicalize peer addresses for signed DNS discovery.
pub fn signed_dns_seed_nodes_payload(addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<u8> {
    let mut addrs: Vec<SocketAddr> = addrs.into_iter().collect();
    addrs.sort();
    addrs.dedup();
    addrs
        .into_iter()
        .map(|addr| addr.to_string())
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

/// Build signed DNS discovery records using an ML-DSA-87 signing key.
pub fn build_signed_dns_seed_records(
    addrs: impl IntoIterator<Item = SocketAddr>,
    seq: u64,
    signing_key: &PqKeypair,
) -> Result<SignedDnsSeedRecords, String> {
    let nodes_payload = signed_dns_seed_nodes_payload(addrs);
    let node_chunks_content = chunk_hex(&nodes_payload);
    let mut root = SignedDnsSeedRoot {
        seq,
        nodes_hash: sha256(&nodes_payload),
        nodes_chunks: node_chunks_content.len(),
        sig_hash: [0u8; 32],
        sig_chunks: 1,
    };
    let signature = signing_key
        .sign(&signed_dns_seed_signing_message(&root))
        .map_err(|error| format!("ML-DSA DNS discovery signing failed: {error}"))?;
    let sig_chunks_content = chunk_hex(&signature.0);
    root.sig_hash = sha256(&signature.0);
    root.sig_chunks = sig_chunks_content.len();

    let root_txt = format!(
        "{} sig={} sig_chunks={}",
        signed_dns_seed_root_without_signature_fields(&root),
        hex32(root.sig_hash),
        root.sig_chunks
    );
    let node_chunks = node_chunks_content
        .into_iter()
        .enumerate()
        .map(|(idx, content)| {
            (
                signed_dns_seed_chunk_name("nodes", root.nodes_hash, idx),
                content,
            )
        })
        .collect();
    let sig_chunks = sig_chunks_content
        .into_iter()
        .enumerate()
        .map(|(idx, content)| {
            (
                signed_dns_seed_chunk_name("sig", root.sig_hash, idx),
                content,
            )
        })
        .collect();

    Ok(SignedDnsSeedRecords {
        root_txt,
        node_chunks,
        sig_chunks,
    })
}

/// Verify and decode signed DNS discovery records using a public key known
/// independently of DNS.
pub fn verify_signed_dns_seed_records(
    root_txt: &str,
    node_chunks: &[String],
    sig_chunks: &[String],
    public_key: &PqPublicKey,
) -> Result<Vec<SocketAddr>, String> {
    let root = parse_signed_dns_seed_root(root_txt)?;
    let nodes_payload = reassemble_hex_chunks(node_chunks, root.nodes_chunks, "node")?;
    if sha256(&nodes_payload) != root.nodes_hash {
        return Err("signed DNS node-list payload hash mismatch".to_string());
    }
    let sig_bytes = reassemble_hex_chunks(sig_chunks, root.sig_chunks, "signature")?;
    if sig_bytes.len() != indra_crypto::PQ_SIG_BYTES {
        return Err(format!(
            "signed DNS signature must be {} bytes",
            indra_crypto::PQ_SIG_BYTES
        ));
    }
    if sha256(&sig_bytes) != root.sig_hash {
        return Err("signed DNS signature hash mismatch".to_string());
    }
    let mut sig = [0u8; indra_crypto::PQ_SIG_BYTES];
    sig.copy_from_slice(&sig_bytes);
    verify_pq(
        &signed_dns_seed_signing_message(&root),
        &PqSignature(sig),
        public_key,
    )
    .map_err(|_| "signed DNS root ML-DSA signature verification failed".to_string())?;

    let text = String::from_utf8(nodes_payload)
        .map_err(|_| "signed DNS node-list payload is not UTF-8".to_string())?;
    let mut addrs = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let addr = line
            .parse::<SocketAddr>()
            .map_err(|_| format!("signed DNS node-list contains invalid address {line:?}"))?;
        addrs.push(addr);
    }
    addrs.sort();
    addrs.dedup();
    Ok(addrs)
}

fn split_host_port(addr_str: &str) -> io::Result<(String, u16)> {
    if let Ok(addr) = addr_str.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    let (host, port_str) = addr_str.rsplit_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("DNS seed address {addr_str:?} is missing a port"),
        )
    })?;
    let port = port_str.parse::<u16>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("DNS seed address {addr_str:?} has invalid port: {e}"),
        )
    })?;
    Ok((host.trim_matches(&['[', ']'][..]).to_string(), port))
}

/// Resolve a single peer address string to a socket address.
pub fn resolve_peer_addr(addr_str: &str) -> Option<SocketAddr> {
    if let Ok(addr) = addr_str.parse::<SocketAddr>() {
        return Some(addr);
    }
    addr_str.to_socket_addrs().ok()?.next()
}

/// Persist known peers to disk as a JSON array of `"ip:port"` strings.
pub fn save_peers(path: &str, peers: &[SocketAddr]) {
    let mut strings: Vec<String> = peers.iter().map(|addr| addr.to_string()).collect();
    strings.sort();
    strings.dedup();
    let json = serde_json::to_string_pretty(&strings).unwrap_or_default();
    if let Err(e) = std::fs::write(path, &json) {
        eprintln!("[discovery] failed to save peers to {}: {}", path, e);
    }
}

/// Load known peers from disk.
pub fn load_peers(path: &str) -> Vec<SocketAddr> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(_) => return vec![],
    };
    let strings: Vec<String> = serde_json::from_str(&content).unwrap_or_default();
    strings
        .iter()
        .filter_map(|addr| addr.parse::<SocketAddr>().ok())
        .collect()
}

/// Sanitize persisted peers loaded from disk before they enter discovery.
///
/// Persisted `peers.json` predates connection-direction tracking, so a bare
/// `ip:port` cannot prove whether it was a legitimate listening address or an
/// accepted inbound socket source with an ephemeral port. Multiple ports for
/// the same IP are therefore treated as an anomaly and collapsed to a single
/// deterministic candidate, preferring the configured P2P listening port when
/// present.
pub fn sanitize_loaded_peers(
    peers: impl IntoIterator<Item = SocketAddr>,
    preferred_port: Option<u16>,
) -> Vec<SocketAddr> {
    let mut by_ip = BTreeMap::new();
    for peer in peers {
        by_ip.entry(peer.ip()).or_insert_with(Vec::new).push(peer);
    }

    let mut sanitized = Vec::new();
    for (_ip, mut candidates) in by_ip {
        candidates.sort_by_key(|addr| {
            (
                preferred_port
                    .map(|port| addr.port() != port)
                    .unwrap_or(false),
                addr.port(),
                addr.to_string(),
            )
        });
        if let Some(peer) = candidates.into_iter().next() {
            sanitized.push(peer);
        }
    }
    sanitized.sort();
    sanitized.dedup();
    sanitized
}

/// Build a deterministic PeerList payload from candidate addresses.
pub fn peer_list_payload(
    candidates: impl IntoIterator<Item = SocketAddr>,
    own_addr: Option<SocketAddr>,
    banned: &HashSet<SocketAddr>,
) -> Vec<PeerListEntry> {
    let mut seen = HashSet::new();
    let mut peers = Vec::new();
    for addr in candidates {
        if Some(addr) == own_addr || banned.contains(&addr) || !seen.insert(addr) {
            continue;
        }
        peers.push(PeerListEntry::address_only(addr.to_string()));
        if peers.len() >= MAX_PEER_LIST_SIZE {
            break;
        }
    }
    peers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_resolve_returns_empty_on_failure() {
        let resolved =
            resolve_dns_seed_hosts_with(&["bad-seed.example".to_string()], 30303, |_| {
                Err(io::Error::new(io::ErrorKind::NotFound, "dns unavailable"))
            });
        assert!(resolved.is_empty());
    }

    #[test]
    fn multiple_dns_seeds_are_queried() {
        let hosts = vec!["seed-a.example".to_string(), "seed-b.example".to_string()];
        let resolved = resolve_dns_seed_hosts_with(&hosts, 30303, |addr_str| match addr_str {
            "seed-a.example:30303" => Ok(vec!["203.0.113.10:30303".parse().unwrap()]),
            "seed-b.example:30303" => Ok(vec![
                "203.0.113.11:30303".parse().unwrap(),
                "203.0.113.10:30303".parse().unwrap(),
            ]),
            _ => Err(io::Error::new(io::ErrorKind::NotFound, "unexpected seed")),
        });

        assert_eq!(
            resolved,
            vec![
                "203.0.113.10:30303".parse().unwrap(),
                "203.0.113.11:30303".parse().unwrap()
            ]
        );
    }

    #[test]
    fn secure_dns_answer_accepted_in_all_modes() {
        for mode in [
            DnsSeedValidationMode::Off,
            DnsSeedValidationMode::Warn,
            DnsSeedValidationMode::Require,
        ] {
            let resolved = resolve_dns_seed_hosts_with_status(
                &["seed.example".to_string()],
                30303,
                mode,
                |_| {
                    Ok(DnsSeedLookup {
                        addrs: vec!["203.0.113.10:30303".parse().unwrap()],
                        status: DnsSeedValidationStatus::Secure,
                    })
                },
            );
            assert_eq!(resolved, vec!["203.0.113.10:30303".parse().unwrap()]);
        }
    }

    #[test]
    fn bogus_dnssec_answer_rejected_in_require_mode() {
        let resolved = resolve_dns_seed_hosts_with_status(
            &["seed.example".to_string()],
            30303,
            DnsSeedValidationMode::Require,
            |_| {
                Ok(DnsSeedLookup {
                    addrs: vec!["203.0.113.10:30303".parse().unwrap()],
                    status: DnsSeedValidationStatus::Bogus,
                })
            },
        );
        assert!(resolved.is_empty());
    }

    #[test]
    fn unsigned_dns_answer_policy_matches_mode() {
        let off = resolve_dns_seed_hosts_with_status(
            &["seed.example".to_string()],
            30303,
            DnsSeedValidationMode::Off,
            |_| {
                Ok(DnsSeedLookup {
                    addrs: vec!["203.0.113.10:30303".parse().unwrap()],
                    status: DnsSeedValidationStatus::Unsigned,
                })
            },
        );
        assert_eq!(off, vec!["203.0.113.10:30303".parse().unwrap()]);

        let warn = resolve_dns_seed_hosts_with_status(
            &["seed.example".to_string()],
            30303,
            DnsSeedValidationMode::Warn,
            |_| {
                Ok(DnsSeedLookup {
                    addrs: vec!["203.0.113.10:30303".parse().unwrap()],
                    status: DnsSeedValidationStatus::Unsigned,
                })
            },
        );
        assert_eq!(warn, vec!["203.0.113.10:30303".parse().unwrap()]);

        let require = resolve_dns_seed_hosts_with_status(
            &["seed.example".to_string()],
            30303,
            DnsSeedValidationMode::Require,
            |_| {
                Ok(DnsSeedLookup {
                    addrs: vec!["203.0.113.10:30303".parse().unwrap()],
                    status: DnsSeedValidationStatus::Unsigned,
                })
            },
        );
        assert!(require.is_empty());
    }

    #[test]
    fn dns_failure_does_not_prevent_bootstrap_peer_connection() {
        let bootstrap_peers = vec!["198.51.100.10:30303".to_string()];
        let dns_peers =
            resolve_dns_seed_hosts_with(&["bad-seed.example".to_string()], 30303, |_| {
                Err(io::Error::new(io::ErrorKind::NotFound, "dns unavailable"))
            });
        let mut dial_candidates = bootstrap_peers.clone();
        dial_candidates.extend(dns_peers.into_iter().map(|addr| addr.to_string()));

        assert_eq!(dial_candidates, bootstrap_peers);
    }

    #[test]
    fn dns_failure_returns_empty_in_all_validation_modes() {
        for mode in [
            DnsSeedValidationMode::Off,
            DnsSeedValidationMode::Warn,
            DnsSeedValidationMode::Require,
        ] {
            let resolved = resolve_dns_seed_hosts_with_status(
                &["bad-seed.example".to_string()],
                30303,
                mode,
                |_| Err(io::Error::new(io::ErrorKind::NotFound, "dns unavailable")),
            );
            assert!(resolved.is_empty());
        }
    }

    #[tokio::test]
    async fn dnssec_seed_resolution_is_safe_inside_existing_tokio_runtime() {
        let resolved =
            resolve_dns_seeds_with_validation("127.0.0.1", 30303, DnsSeedValidationMode::Warn)
                .await;

        assert_eq!(resolved, vec!["127.0.0.1:30303".parse().unwrap()]);
    }

    #[test]
    fn dnssec_seed_resolution_is_ipv4_only_until_ipv6_seeds_are_supported() {
        assert_eq!(
            DNS_SEED_RECORD_TYPES,
            &[RecordType::A],
            "do not query AAAA for IPv4-only seed records; absent AAAA records in signed zones can produce DNSSEC negative-response errors that add no usable peers"
        );
    }

    #[test]
    fn dnssec_status_uses_hickory_proof_not_rrsig_presence() {
        assert_eq!(
            dnssec_status_from_proofs([Proof::Secure]),
            DnsSeedValidationStatus::Secure,
            "Hickory stores DNSSEC validation on each answer record's Proof; a secure answer must not be downgraded just because the lookup sections do not expose a raw RRSIG record"
        );
    }

    #[test]
    fn dnssec_status_maps_hickory_proof_values() {
        assert_eq!(
            dnssec_status_from_proofs([Proof::Insecure]),
            DnsSeedValidationStatus::Unsigned
        );
        assert_eq!(
            dnssec_status_from_proofs([Proof::Bogus]),
            DnsSeedValidationStatus::Bogus
        );
        assert_eq!(
            dnssec_status_from_proofs([Proof::Indeterminate]),
            DnsSeedValidationStatus::Indeterminate
        );
        assert_eq!(
            dnssec_status_from_proofs([Proof::Secure, Proof::Bogus]),
            DnsSeedValidationStatus::Bogus,
            "a mixed answer is only as trustworthy as its weakest proof"
        );
    }

    #[test]
    fn signed_dns_seed_list_verifies_with_correct_public_key() {
        let key = PqKeypair::from_seed(&[0x51; 32]).unwrap();
        let records = build_signed_dns_seed_records(
            [
                "203.0.113.10:30303".parse().unwrap(),
                "198.51.100.7:30303".parse().unwrap(),
                "203.0.113.10:30303".parse().unwrap(),
            ],
            7,
            &key,
        )
        .unwrap();
        let nodes: Vec<String> = records
            .node_chunks
            .iter()
            .map(|(_, value)| value.clone())
            .collect();
        let sig: Vec<String> = records
            .sig_chunks
            .iter()
            .map(|(_, value)| value.clone())
            .collect();

        let resolved =
            verify_signed_dns_seed_records(&records.root_txt, &nodes, &sig, &key.public_key())
                .unwrap();

        assert_eq!(
            resolved,
            vec![
                "198.51.100.7:30303".parse().unwrap(),
                "203.0.113.10:30303".parse().unwrap()
            ]
        );
    }

    #[test]
    fn signed_dns_seed_tampered_list_fails_verification() {
        let key = PqKeypair::from_seed(&[0x52; 32]).unwrap();
        let records =
            build_signed_dns_seed_records(["203.0.113.10:30303".parse().unwrap()], 1, &key)
                .unwrap();
        let mut nodes: Vec<String> = records
            .node_chunks
            .iter()
            .map(|(_, value)| value.clone())
            .collect();
        nodes[0].push_str("00");
        let sig: Vec<String> = records
            .sig_chunks
            .iter()
            .map(|(_, value)| value.clone())
            .collect();

        let err =
            verify_signed_dns_seed_records(&records.root_txt, &nodes, &sig, &key.public_key())
                .unwrap_err();
        assert!(err.contains("hash mismatch") || err.contains("invalid address"));
    }

    #[test]
    fn signed_dns_seed_wrong_key_fails_verification() {
        let key = PqKeypair::from_seed(&[0x53; 32]).unwrap();
        let wrong = PqKeypair::from_seed(&[0x54; 32]).unwrap();
        let records =
            build_signed_dns_seed_records(["203.0.113.10:30303".parse().unwrap()], 1, &key)
                .unwrap();
        let nodes: Vec<String> = records
            .node_chunks
            .iter()
            .map(|(_, value)| value.clone())
            .collect();
        let sig: Vec<String> = records
            .sig_chunks
            .iter()
            .map(|(_, value)| value.clone())
            .collect();

        let err =
            verify_signed_dns_seed_records(&records.root_txt, &nodes, &sig, &wrong.public_key())
                .unwrap_err();
        assert!(err.contains("signature verification failed"));
    }

    #[test]
    fn signed_dns_seed_chunk_reordering_substitution_partial_and_malformed_fail() {
        let key = PqKeypair::from_seed(&[0x5A; 32]).unwrap();
        let addrs: Vec<SocketAddr> = (1..=24)
            .map(|i| format!("203.0.113.{i}:30303").parse().unwrap())
            .collect();
        let records = build_signed_dns_seed_records(addrs, 8, &key).unwrap();
        let replacement =
            build_signed_dns_seed_records(["198.51.100.200:30303".parse().unwrap()], 8, &key)
                .unwrap();
        let nodes: Vec<String> = records
            .node_chunks
            .iter()
            .map(|(_, value)| value.clone())
            .collect();
        let sig: Vec<String> = records
            .sig_chunks
            .iter()
            .map(|(_, value)| value.clone())
            .collect();
        assert!(
            nodes.len() > 1,
            "test vector must exercise node chunk order"
        );
        assert!(sig.len() > 1, "ML-DSA signature must be chunked");

        let mut reordered_nodes = nodes.clone();
        reordered_nodes.swap(0, 1);
        let err = verify_signed_dns_seed_records(
            &records.root_txt,
            &reordered_nodes,
            &sig,
            &key.public_key(),
        )
        .unwrap_err();
        assert!(err.contains("hash mismatch") || err.contains("invalid address"));

        let mut reordered_sig = sig.clone();
        reordered_sig.swap(0, 1);
        let err = verify_signed_dns_seed_records(
            &records.root_txt,
            &nodes,
            &reordered_sig,
            &key.public_key(),
        )
        .unwrap_err();
        assert!(
            err.contains("signature hash mismatch")
                || err.contains("signature verification failed")
        );

        let mut substituted_nodes = nodes.clone();
        substituted_nodes[0] = replacement.node_chunks[0].1.clone();
        let err = verify_signed_dns_seed_records(
            &records.root_txt,
            &substituted_nodes,
            &sig,
            &key.public_key(),
        )
        .unwrap_err();
        assert!(err.contains("hash mismatch") || err.contains("invalid address"));

        let partial_sig = &sig[..sig.len() - 1];
        let err = verify_signed_dns_seed_records(
            &records.root_txt,
            &nodes,
            partial_sig,
            &key.public_key(),
        )
        .unwrap_err();
        assert!(err.contains("chunk count mismatch"));

        let mut malformed_nodes = nodes.clone();
        malformed_nodes[0].replace_range(0..2, "zz");
        let err = verify_signed_dns_seed_records(
            &records.root_txt,
            &malformed_nodes,
            &sig,
            &key.public_key(),
        )
        .unwrap_err();
        assert!(err.contains("not valid hex"));
    }

    #[tokio::test]
    async fn signed_dns_seed_rejects_lower_sequence_after_persisted_higher_sequence() {
        let key = PqKeypair::from_seed(&[0x5B; 32]).unwrap();
        let older = build_signed_dns_seed_records(["203.0.113.10:30303".parse().unwrap()], 1, &key)
            .unwrap();
        let newer = build_signed_dns_seed_records(["203.0.113.11:30303".parse().unwrap()], 2, &key)
            .unwrap();
        let equal_seq =
            build_signed_dns_seed_records(["203.0.113.12:30303".parse().unwrap()], 2, &key)
                .unwrap();
        let state_path = std::env::temp_dir().join(format!(
            "indra-signed-dns-seq-{}-{}.txt",
            std::process::id(),
            crate::metrics::MetricsState::new()
                .started_at
                .elapsed()
                .as_nanos()
        ));
        let host = "seeds.example".to_string();

        assert_eq!(parse_signed_dns_seed_root(&older.root_txt).unwrap().seq, 1);
        assert_eq!(parse_signed_dns_seed_root(&newer.root_txt).unwrap().seq, 2);
        assert_eq!(
            parse_signed_dns_seed_root(&equal_seq.root_txt).unwrap().seq,
            2
        );

        let mut first_start_store = SignedDnsSeqStore::load(&state_path).unwrap();
        let newer_resolved = resolve_signed_dns_seed_hosts_with_async(
            std::slice::from_ref(&host),
            SignedDnsSeedValidationMode::Warn,
            Some(&key.public_key()),
            Some(&mut first_start_store),
            |_| {
                let root_txt = newer.root_txt.clone();
                let node_chunks = newer
                    .node_chunks
                    .iter()
                    .map(|(_, value)| value.clone())
                    .collect();
                let sig_chunks = newer
                    .sig_chunks
                    .iter()
                    .map(|(_, value)| value.clone())
                    .collect();
                async move {
                    Ok(SignedDnsSeedTxtLookup {
                        root_txt,
                        node_chunks,
                        sig_chunks,
                    })
                }
            },
        )
        .await;
        assert_eq!(newer_resolved, vec!["203.0.113.11:30303".parse().unwrap()]);

        let persisted_after_restart = SignedDnsSeqStore::load(&state_path).unwrap();
        assert!(
            persisted_after_restart.highest_seq(&host) == Some(2),
            "verified sequence must survive restart via node-local persistence"
        );
        let mut restarted_store = persisted_after_restart;

        let older_resolved = resolve_signed_dns_seed_hosts_with_async(
            std::slice::from_ref(&host),
            SignedDnsSeedValidationMode::Warn,
            Some(&key.public_key()),
            Some(&mut restarted_store),
            |_| {
                let root_txt = older.root_txt.clone();
                let node_chunks = older
                    .node_chunks
                    .iter()
                    .map(|(_, value)| value.clone())
                    .collect();
                let sig_chunks = older
                    .sig_chunks
                    .iter()
                    .map(|(_, value)| value.clone())
                    .collect();
                async move {
                    Ok(SignedDnsSeedTxtLookup {
                        root_txt,
                        node_chunks,
                        sig_chunks,
                    })
                }
            },
        )
        .await;
        assert!(
            older_resolved.is_empty(),
            "lower-sequence replay must be rejected after a higher sequence was persisted"
        );

        let equal_resolved = resolve_signed_dns_seed_hosts_with_async(
            std::slice::from_ref(&host),
            SignedDnsSeedValidationMode::Warn,
            Some(&key.public_key()),
            Some(&mut restarted_store),
            |_| {
                let root_txt = equal_seq.root_txt.clone();
                let node_chunks = equal_seq
                    .node_chunks
                    .iter()
                    .map(|(_, value)| value.clone())
                    .collect();
                let sig_chunks = equal_seq
                    .sig_chunks
                    .iter()
                    .map(|(_, value)| value.clone())
                    .collect();
                async move {
                    Ok(SignedDnsSeedTxtLookup {
                        root_txt,
                        node_chunks,
                        sig_chunks,
                    })
                }
            },
        )
        .await;
        assert_eq!(
            equal_resolved,
            vec!["203.0.113.12:30303".parse().unwrap()],
            "equal sequence lookups are allowed for cache hits/repeated publication"
        );

        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn signed_dns_seed_root_signature_is_chunked_for_dns_txt_practicality() {
        let key = PqKeypair::from_seed(&[0x55; 32]).unwrap();
        let records =
            build_signed_dns_seed_records(["203.0.113.10:30303".parse().unwrap()], 1, &key)
                .unwrap();
        assert!(
            records.sig_chunks.len() > 1,
            "ML-DSA-87 signatures are intentionally chunked instead of embedded in one TXT root"
        );
        assert!(records
            .sig_chunks
            .iter()
            .all(|(_, value)| value.len() <= SIGNED_DNS_DISCOVERY_CHUNK_HEX_LEN));
    }

    #[test]
    fn signed_dns_seed_require_rejects_unsigned_or_invalid_list() {
        let key = PqKeypair::from_seed(&[0x56; 32]).unwrap();
        let records =
            build_signed_dns_seed_records(["203.0.113.10:30303".parse().unwrap()], 1, &key)
                .unwrap();
        let mut node_chunks: Vec<String> = records
            .node_chunks
            .iter()
            .map(|(_, value)| value.clone())
            .collect();
        node_chunks[0].push_str("00");
        let sig_chunks: Vec<String> = records
            .sig_chunks
            .iter()
            .map(|(_, value)| value.clone())
            .collect();

        let resolved = resolve_signed_dns_seed_hosts_with(
            &["seeds.example".to_string()],
            SignedDnsSeedValidationMode::Require,
            Some(&key.public_key()),
            |_| {
                Ok(SignedDnsSeedTxtLookup {
                    root_txt: records.root_txt.clone(),
                    node_chunks: node_chunks.clone(),
                    sig_chunks: sig_chunks.clone(),
                })
            },
        );
        assert!(resolved.is_empty());

        let no_key = resolve_signed_dns_seed_hosts_with(
            &["seeds.example".to_string()],
            SignedDnsSeedValidationMode::Require,
            None,
            |_| unreachable!("require mode without a public key must not query DNS"),
        );
        assert!(no_key.is_empty());
    }

    #[test]
    fn signed_dns_seed_warn_can_fall_back_to_plain_a_records() {
        let key = PqKeypair::from_seed(&[0x57; 32]).unwrap();
        let signed = resolve_signed_dns_seed_hosts_with(
            &["seeds.example".to_string()],
            SignedDnsSeedValidationMode::Warn,
            Some(&key.public_key()),
            |_| Err(io::Error::new(io::ErrorKind::NotFound, "no signed root")),
        );
        assert!(signed.is_empty());

        let plain = resolve_dns_seed_hosts_with_status(
            &["seeds.example".to_string()],
            30303,
            DnsSeedValidationMode::Warn,
            |_| {
                Ok(DnsSeedLookup {
                    addrs: vec!["203.0.113.10:30303".parse().unwrap()],
                    status: DnsSeedValidationStatus::Secure,
                })
            },
        );
        assert_eq!(plain, vec!["203.0.113.10:30303".parse().unwrap()]);
    }

    #[tokio::test]
    async fn signed_dns_seed_async_path_verifies_chunked_records() {
        let key = PqKeypair::from_seed(&[0x58; 32]).unwrap();
        let records = build_signed_dns_seed_records(
            [
                "203.0.113.10:30303".parse().unwrap(),
                "198.51.100.7:30303".parse().unwrap(),
            ],
            11,
            &key,
        )
        .unwrap();
        let node_chunks: Vec<String> = records
            .node_chunks
            .iter()
            .map(|(_, value)| value.clone())
            .collect();
        let sig_chunks: Vec<String> = records
            .sig_chunks
            .iter()
            .map(|(_, value)| value.clone())
            .collect();

        let resolved = resolve_signed_dns_seed_hosts_with_async(
            &["seeds.example".to_string()],
            SignedDnsSeedValidationMode::Warn,
            Some(&key.public_key()),
            None,
            |_| {
                let root_txt = records.root_txt.clone();
                let node_chunks = node_chunks.clone();
                let sig_chunks = sig_chunks.clone();
                async move {
                    Ok(SignedDnsSeedTxtLookup {
                        root_txt,
                        node_chunks,
                        sig_chunks,
                    })
                }
            },
        )
        .await;

        assert_eq!(
            resolved,
            vec![
                "198.51.100.7:30303".parse().unwrap(),
                "203.0.113.10:30303".parse().unwrap()
            ]
        );
    }

    #[test]
    fn dnssec_seed_resolver_uses_explicit_cloudflare_upstream() {
        let config = dnssec_seed_resolver_config();
        let upstreams: HashSet<_> = config
            .name_servers()
            .iter()
            .map(|server| server.ip)
            .collect();

        assert!(
            upstreams.contains(&"1.1.1.1".parse().unwrap()),
            "DNSSEC seed validation should not depend on the validator host's system resolver"
        );
        assert!(upstreams.contains(&"1.0.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn async_dnssec_policy_gate_rejects_unsigned_in_require_mode() {
        let resolved = resolve_dns_seed_hosts_with_status_async(
            &["seed.example".to_string()],
            30303,
            DnsSeedValidationMode::Require,
            |_| async {
                Ok(DnsSeedLookup {
                    addrs: vec!["203.0.113.10:30303".parse().unwrap()],
                    status: DnsSeedValidationStatus::Unsigned,
                })
            },
        )
        .await;

        assert!(resolved.is_empty());
    }

    #[test]
    fn save_and_load_peers_round_trip() {
        let path = std::env::temp_dir().join(format!(
            "indra_peers_{}_round_trip.json",
            std::process::id()
        ));
        let peers = vec![
            "127.0.0.1:30303".parse().unwrap(),
            "127.0.0.2:30303".parse().unwrap(),
        ];
        save_peers(path.to_str().unwrap(), &peers);
        let loaded = load_peers(path.to_str().unwrap());
        assert_eq!(loaded, peers);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_peers_missing_file_returns_empty() {
        let path =
            std::env::temp_dir().join(format!("indra_missing_peers_{}.json", std::process::id()));
        assert!(load_peers(path.to_str().unwrap()).is_empty());
    }

    #[test]
    fn sanitize_loaded_peers_collapses_multiple_ports_per_ip() {
        let peers = vec![
            "203.0.113.10:52154".parse().unwrap(),
            "203.0.113.10:30303".parse().unwrap(),
            "203.0.113.10:49844".parse().unwrap(),
            "198.51.100.22:45240".parse().unwrap(),
            "198.51.100.22:30303".parse().unwrap(),
        ];

        let sanitized = sanitize_loaded_peers(peers, Some(30303));

        assert_eq!(
            sanitized,
            vec![
                "198.51.100.22:30303".parse().unwrap(),
                "203.0.113.10:30303".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn sanitize_loaded_peers_leaves_single_port_per_ip_unchanged() {
        let peers = vec![
            "203.0.113.10:30303".parse().unwrap(),
            "198.51.100.22:30303".parse().unwrap(),
            "192.0.2.44:30303".parse().unwrap(),
        ];

        let mut expected = peers;
        expected.sort();
        let sanitized = sanitize_loaded_peers(expected.clone(), Some(30303));

        assert_eq!(sanitized, expected);
    }

    #[test]
    fn peer_list_deduplicates() {
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();
        let payload = peer_list_payload([addr, addr], None, &HashSet::new());
        assert_eq!(
            payload,
            vec![PeerListEntry::address_only("127.0.0.1:30303")]
        );
    }

    #[test]
    fn peer_list_respects_max_size() {
        let peers = (0..40).map(|i| SocketAddr::from(([127, 0, 0, 1], 30_000 + i)));
        let payload = peer_list_payload(peers, None, &HashSet::new());
        assert_eq!(payload.len(), MAX_PEER_LIST_SIZE);
    }

    #[test]
    fn peer_discovery_skips_banned_peers() {
        let banned_addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();
        let good_addr: SocketAddr = "127.0.0.2:30303".parse().unwrap();
        let banned = HashSet::from([banned_addr]);
        let payload = peer_list_payload([banned_addr, good_addr], None, &banned);
        assert_eq!(
            payload,
            vec![PeerListEntry::address_only("127.0.0.2:30303")]
        );
    }
}
