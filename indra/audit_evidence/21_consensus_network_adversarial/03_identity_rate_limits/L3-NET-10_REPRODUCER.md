# L3-NET-10 Reproducer

## Unbound provisional-QC response peer correlation

- Severity: MEDIUM
- Production reachable: yes
- Prerequisite: node is syncing with a staged provisional block; attacker has any authenticated validator connection.

Production path: `NetworkEvent::Message::QCResponse` enters the node sync loop in
`indra-node/src/bin/node.rs`. When `driver.sync().provisional()` exists, the code
checks only `pending.block.header.height == response.height`, then calls
`verify_network_direct_provisional_qc`. It does not require the response sender to
match the validator/socket recorded for the outstanding QC request. Distinct response
bytes avoid the peer-manager's bounded 2,048-entry wire-hash cache.

Expected: a QC response should be bound to the selected outstanding request peer,
or be rejected before expensive verification. Actual: any authenticated peer with a
matching height reaches bounded QC verification.

Safety: no unrequested commit was reproduced; the QC must still cryptographically
verify against the provisional block. Resource impact is bounded by validator QC
rate/byte buckets, frame and QC signer limits, and one provisional slot. Recommended
next action is independent review of peer correlation; no remediation was performed.
