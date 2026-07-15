# DNS seed publishing automation

Status: operational tooling, not consensus logic.

INDRA DNS seed records are a cache of chain state. They must be generated from
the active validator set exposed by `indra_getValidatorSet`, not maintained as
an independent source of truth.

The publishing tool is:

```sh
ops/dns_publish_seed_records.py
```

It queries `indra_getValidatorSet`, extracts active validators' non-null
`network_addr` values, derives IPv4 A records for the configured seed hostnames,
compares those desired records against Cloudflare's current DNS state, and
applies only the necessary create/update/delete operations.

## Safety model

The tool is dry-run by default. It writes Cloudflare records only when `--apply`
is provided.

It refuses to publish if:

- the RPC validator set is empty or below `--min-expected-validators`;
- no active validator has an IPv4 `network_addr`;
- any published `network_addr` is malformed or not usable as an A record;
- a token file is group/world accessible;
- applying would delete existing managed A records and `--allow-destructive`
  was not explicitly provided.

The tool manages only A records for the configured seed hostnames. It does not
touch AAAA, CNAME, NS, or unrelated records.

## Cloudflare credentials

Use a scoped Cloudflare API token, not a global API key. The token needs DNS
read/write permission for the `indraprotocol.com` zone only.

Preferred invocation uses a restricted-permission token file:

```sh
install -m 0600 /dev/null /etc/indra/cloudflare-dns-token
# paste token into /etc/indra/cloudflare-dns-token
```

Do not pass the token as a command-line argument; argv is visible in process
listings on many systems.

## Example dry run

```sh
ops/dns_publish_seed_records.py \
  --rpc-url http://127.0.0.1:8545 \
  --zone-id "$CLOUDFLARE_ZONE_ID" \
  --token-file /etc/indra/cloudflare-dns-token \
  --min-expected-validators 4
```

## Example apply

```sh
ops/dns_publish_seed_records.py \
  --rpc-url http://127.0.0.1:8545 \
  --zone-id "$CLOUDFLARE_ZONE_ID" \
  --token-file /etc/indra/cloudflare-dns-token \
  --min-expected-validators 4 \
  --apply \
  --allow-destructive
```

`--allow-destructive` is required because normal convergence may delete stale
A records that are no longer present in the active on-chain validator address
set.

## Scheduling

Run manually first. Once dry-run output is stable, this can be scheduled with a
systemd timer or cron on one operations host. The command is idempotent: if the
on-chain active-address set and Cloudflare DNS already match, it performs no
changes.

DNSSEC remains a separate operational requirement. DNSSEC authenticates the DNS
cache; this publisher keeps that cache synchronized with chain state.
