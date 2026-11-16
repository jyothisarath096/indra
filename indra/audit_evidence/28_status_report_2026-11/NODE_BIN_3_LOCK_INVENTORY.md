# Node Bin 3 lock inventory

Unfinished or unproven: this inventory proves that the direct lock/read/write patterns in `start_network_runtime` were removed from the current source scan. It does not prove an end-to-end poisoned-lock injection through the live P2P runtime. The runtime lock failure path reports to the supervisor and terminates the process.

## Verified source scan

Command run from `/Users/bonkai/Desktop/indra/project_indra/indra`:

```text
sed -n '1206,1885p' indra-node/src/bin/node.rs | nl -ba | grep -E '\.lock\(|\.read\(|\.write\(|if let Ok\(|\.ok\(' || true
```

Output:

```text
   376	                            .and_then(|port| port.parse::<u16>().ok());
   427	                                        bytes.as_slice().try_into().ok()?;
```

The two remaining `.ok()` calls are parsing fallbacks, not lock operations. No `.lock()`, `.read()`, `.write()`, or `if let Ok(` lock pattern remains in the function.

## Lock sites converted

The converted sites use `indra_node::locks::lock` or `indra_node::locks::read` through the local `fatal_lock!` and `fatal_read!` wrappers in `indra-node/src/bin/node.rs:1226-1248`. The inventory covers initialization, handshake configuration reads, peer-event cooldowns and maps, inbound admission, discovery maps, dial eligibility and cooldowns, dial-failure bookkeeping, peer persistence, and shutdown persistence. Each wrapper reports `p2p-runtime` through `indra-node/src/locks.rs:7-16` and exits the process after the report; it never uses `into_inner`, `parking_lot`, or a silent `unwrap_or` lock fallback.

## Spawn inventory

Long-lived runtime tasks are supervised at `indra-node/src/bin/node.rs:1335`, `1442`, `1556`, and `1855` through `supervisor::spawn_critical`. Per-connection inbound and outbound tasks are isolated through `supervisor::spawn_connection` at `indra-node/src/bin/node.rs:1518` and `1789`.

The exact wrapper inventory command was:

```text
rg -n 'fatal_lock!|fatal_read!' indra-node/src/bin/node.rs | awk '$1+0>=1226 && $1+0<1880'
```

It reported these current call sites: `1322`, `1358`, `1386`, `1399`, `1410`, `1415`, `1427-1429`, `1470`, `1518`, `1525`, `1536`, `1593-1594`, `1647-1648`, `1658`, `1677`, `1681`, `1698-1699`, `1704`, `1711`, `1733-1734`, `1740`, `1747-1750`, `1755`, `1760`, `1771`, `1789`, `1796`, `1802-1804`, `1819`, `1825-1827`, `1841-1842`, and `1861-1862`. The command output is the line-by-line source inventory; the named lock labels identify the protected shared handle and operation.
