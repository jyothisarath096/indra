# L3-NET-03 — lossy PeerList UTF-8 is non-canonical

Two payloads use discriminator `04`, count 1, address length 1, address byte respectively `ff` and `fe`, and identity marker 0. Both are enclosed with any four-byte inner prefix.

Production decoder: `Message::decode_wire` PeerList branch, specifically `String::from_utf8_lossy(peer_bytes).to_string()`.

Expected: invalid UTF-8 is rejected.

Actual: both inputs are accepted and decode to the same replacement-character address. Re-encoding both objects produces identical UTF-8 bytes and does not reproduce either input.

Reachability/consequence: yes, but only peer discovery. Address resolution subsequently rejects the replacement-character string. No consensus identity, authentication, or state mutation is affected.

Run the audit harness command documented in L3-NET-01.

