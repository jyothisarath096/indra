//! Peer discovery — DNS seeding, peer exchange, and peer table persistence.

use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    future::Future,
    io,
    net::{SocketAddr, ToSocketAddrs},
    str::FromStr,
};

use hickory_resolver::{config::ResolveHosts, proto::rr::RecordType, Resolver};
use indra_core::types::primitives::{DNS_SEED_HOSTS, MAX_PEER_LIST_SIZE};
use indra_network::PeerListEntry;

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
}

#[derive(Debug, Clone)]
struct DnsSeedLookup {
    addrs: Vec<SocketAddr>,
    status: DnsSeedValidationStatus,
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

fn dnssec_status_label(status: DnsSeedValidationStatus) -> &'static str {
    match status {
        DnsSeedValidationStatus::Unchecked => "unchecked",
        DnsSeedValidationStatus::Secure => "secure",
        DnsSeedValidationStatus::Unsigned => "unsigned",
        DnsSeedValidationStatus::Bogus => "bogus",
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
    let hosts = parse_dns_seed_hosts(hosts);
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

/// Resolve the default DNS seed hostnames.
pub async fn resolve_default_dns_seeds(port: u16) -> Vec<SocketAddr> {
    resolve_dns_seeds(&default_dns_seed_hosts_config(), port).await
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
    let mut builder = Resolver::builder_tokio().map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("DNS resolver configuration failed: {e}"),
        )
    })?;
    {
        let opts = builder.options_mut();
        opts.validate = true;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.try_tcp_on_error = true;
    }
    let resolver = builder.build().map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("DNS resolver build failed: {e}"),
        )
    })?;

    let mut addrs = Vec::new();
    let mut saw_unsigned_answer = false;
    let mut saw_secure_answer = false;
    let mut saw_lookup_error = false;

    let query_host = if host.ends_with('.') {
        host.to_string()
    } else {
        format!("{host}.")
    };

    for record_type in [RecordType::A, RecordType::AAAA] {
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
                if lookup_contains_rrsig(&lookup) {
                    saw_secure_answer = true;
                } else {
                    saw_unsigned_answer = true;
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

    let status = if !addrs.is_empty() && saw_secure_answer && !saw_unsigned_answer {
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

fn lookup_contains_rrsig(lookup: &hickory_resolver::lookup::Lookup) -> bool {
    lookup
        .answers()
        .iter()
        .chain(lookup.authorities().iter())
        .chain(lookup.additionals().iter())
        .any(|record| record.record_type() == RecordType::RRSIG)
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
