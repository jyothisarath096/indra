# DNSSEC validation for DNS seed discovery

INDRA DNS seeds are a discovery cache, not a consensus authority. A DNS seed
answer can suggest peer addresses, but the authenticated P2P handshake remains
the validator identity boundary. DNSSEC validation hardens this seed layer
against spoofed or poisoned DNS answers during node startup/restart.

This has two separate halves:

1. **Operational DNSSEC signing** for the real `indraprotocol.com` zone.
2. **Code-side DNSSEC validation** in the node's DNS seed resolver.

The code-side half is implemented in the node. The operational half must still
be completed by whoever manages the domain's DNS provider/registrar.

## Current node behavior

`network.dns_seed_validation` controls how DNS seed answers are handled:

```toml
[network]
dns_seed_host = "seeds.indraprotocol.com,seeds2.indraprotocol.com"
dns_seed_validation = "warn"
```

Modes:

- `off`: use ordinary DNS resolution for seed hostnames. This is intended only
  for local/dev environments.
- `warn`: attempt DNSSEC-aware resolution. Log clearly when an answer is
  unsigned, bogus, or not validated, but continue using returned addresses.
  This is the default until the real zone is signed and externally verified.
- `require`: accept only DNSSEC-secure seed answers. Unsigned, bogus, or
  unvalidated seed answers are ignored.

Even in `require` mode, DNS seed failure does **not** stop node startup.
Discovery continues through configured bootstrap peers, genesis seed hints,
persisted peer tables, PEX, and on-chain validator network addresses.

## Operator checklist: enable DNSSEC for the real domain

If `indraprotocol.com` is managed in Cloudflare:

1. In the Cloudflare dashboard, open the `indraprotocol.com` zone.
2. Go to DNS settings and enable DNSSEC.
3. Cloudflare signs the zone and generates DS record material.
4. Add the DS record at the domain registrar, unless the domain uses
   Cloudflare Registrar or another setup where Cloudflare submits DS records
   automatically.
5. Confirm `seeds.indraprotocol.com` and `seeds2.indraprotocol.com` are normal
   DNS-only A/AAAA records under the signed zone.
6. Wait for DS/NS TTL propagation before switching production nodes to
   `dns_seed_validation = "require"`.

If the domain is not managed through Cloudflare, perform the equivalent
provider-specific steps: sign the authoritative zone, publish DS at the
registrar/parent zone, and verify the chain from the DNS root to the seed
records.

## External verification

Before switching production nodes from `warn` to `require`, verify the DNSSEC
chain externally from more than one network:

```sh
dig +dnssec seeds.indraprotocol.com A
dig +dnssec seeds2.indraprotocol.com A
delv seeds.indraprotocol.com A
delv seeds2.indraprotocol.com A
```

DNSViz or an equivalent DNSSEC analyzer should show a valid chain from the root
through the TLD, registrar DS record, Cloudflare DNSKEY, and the seed records.

## Seed data source of truth

DNS seed records must remain a cache of chain-derived validator addresses, not
an independent hand-maintained authority.

The intended relationship is:

1. chain state stores each validator's identity, active status, and
   `network_addr`;
2. `indra_getValidatorSet` exposes active validators and their addresses;
3. DNS seed publishing caches that current active-address set;
4. PEX and persisted peer tables accelerate discovery after first contact.

The operational publisher and its Cloudflare safety model are documented in
[`DNS_SEED_PUBLISHING_AUTOMATION.md`](DNS_SEED_PUBLISHING_AUTOMATION.md).

When DNSSEC is enabled, it authenticates the DNS cache contents. It does not
replace the requirement that the cache be generated from current on-chain
validator state.
