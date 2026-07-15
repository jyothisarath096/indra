# Public read-only RPC deployment guidance

`rpc_public` is INDRA's structurally read-only RPC listener. It exists so
explorers, wallets, monitoring tools, and other public consumers can read chain
data without being able to submit transactions, staking operations, governance
operations, or admin diagnostics through the same endpoint.

The listener is hardened in-process with a read-only method allowlist,
write/admin rejection, per-IP rate limiting, listener-wide global rate limiting,
public-specific body and timeout limits, and stricter throttles for expensive
read methods. Those protections are necessary, but they are not a substitute for
normal production internet-edge infrastructure.

## Recommended mainnet architecture

For mainnet, keep the node process bound to loopback or a private interface:

```toml
[rpc_public]
enabled = true
addr = "127.0.0.1:8547"
```

Expose the public hostname through operator-managed infrastructure:

```text
Internet
  -> CDN / WAF / reverse proxy / TLS terminator
  -> 127.0.0.1:8547 rpc_public
```

The proxy or gateway should provide:

- TLS termination;
- additional global and per-client rate limiting;
- request and response logging;
- abuse monitoring and alerting;
- request body limits matching the read-only JSON-RPC surface;
- optional upstream health checks and failover.

This mirrors the standard posture used by mature blockchain RPC deployments.
For example, Geth's security guidance warns that API endpoints are not designed
to withstand hostile internet traffic directly and recommends firewalls,
proxies, application filtering, rate limiting, TLS termination, logging, and
monitoring when APIs are exposed publicly:
<https://geth.ethereum.org/docs/fundamentals/security>.

## Direct binding

Binding `rpc_public` to `0.0.0.0` is intentionally possible for controlled
environments, but it is not the recommended final mainnet posture:

```toml
[rpc_public]
enabled = true
addr = "0.0.0.0:8547"
```

If an operator does this, they should treat the listener as live internet attack
surface and confirm host firewall rules, monitoring, and external rate limiting
before opening the port.

The full local RPC listener is different. It exposes signed submission methods
and admin-token-protected diagnostics, and should not be exposed publicly:

```toml
[rpc]
enabled = true
addr = "127.0.0.1:8545"
```

## Public listener defaults

The in-node defaults for `rpc_public` are intentionally stricter than the full
local RPC listener:

- per-IP: 5 requests/second, burst 20;
- global listener-wide: 100 requests/second, burst 200;
- request body: 64 KiB;
- request timeout: 10 seconds;
- expensive read methods: 30/minute per IP and 300/minute globally;
- legacy authorized UTXO scans: 10/minute per IP.

Operators can tune the main public caps under `[rpc_public]`:

```toml
[rpc_public]
per_ip_rate_per_sec = 5
per_ip_burst = 20
global_rate_per_sec = 100
global_burst = 200
max_body_bytes = 65536
timeout_ms = 10000
```

These in-node limits are deliberately a last line of defense. The public
internet-facing proxy should still enforce its own independent limits.
