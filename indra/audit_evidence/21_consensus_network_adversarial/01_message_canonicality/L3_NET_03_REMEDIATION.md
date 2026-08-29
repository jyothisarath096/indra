# L3-NET-03 Remediation Evidence

Status: remediation submitted for independent review. This report does not mark L3-NET-03 closed.

## Root cause and production path

`PeerListEntry.addr` is a protocol string containing a peer network address (the production consumers treat it as `host:port`). `Message::PeerList` encodes a `u32` entry count, then for each entry a little-endian `u16` byte length, the raw bytes of `String::as_bytes()`, a one-byte identity marker, and an optional fixed 32-byte validator ID.

The authenticated inbound path is encrypted transport/frame extraction, `PeerManager` frame admission, `Message::decode_framed_wire`, `Message::decode_wire`, and the `PeerList` discriminator branch. L3-NET-01 first proves that the declared message length equals the supplied framed plaintext length. L3-NET-02 then enforces complete semantic payload consumption. In the `PeerList` branch, the address slice is selected using its `u16` length.

The branch previously converted that slice with `String::from_utf8_lossy(...).to_string()`. Malformed sequences were accepted and replaced with U+FFFD. For example, the distinct one-byte addresses `ff` and `fe` both decoded to the same logical replacement-character string and re-encoded as `ef bf bd`, so accepted bytes were neither injective nor round-trip canonical.

After decoding, `indra-node` hashes the canonical re-encoding for its bounded PeerList seen cache, then calls `resolve_peer_addr` before admitting an address to discovery. That resolver applies the existing socket/hostname interpretation. The wire type itself remains `String`, so valid arbitrary UTF-8 remains permitted; this remediation deliberately adds no ASCII-only, hostname, IP, or port-syntax rule.

## Implemented invariant and source change

Every encoded PeerList address must be valid UTF-8. Valid UTF-8 produces exactly the same `String` and wire encoding as before. Invalid UTF-8 produces `NetworkError::DecodeFailed` at the production PeerList decoder.

The only production source change is in `indra-network/src/message.rs`: `String::from_utf8_lossy` was replaced with strict `std::str::from_utf8`, error mapping, and `to_owned`. No discriminator, field order, length, identity marker, or valid wire encoding changed.

## Permanent regressions

`peer_list_address_utf8_is_strict_and_canonical` exercises `Message::decode_framed_wire` with exact declared and payload lengths. It proves:

- a canonical ASCII `host:port` string is accepted;
- a canonical multibyte UTF-8 hostname is accepted;
- canonical decode/re-encode is byte-identical;
- malformed single bytes `ff` and `fe` are both rejected (the prior collision pair);
- truncated multibyte `e2 82` is rejected;
- overlong `c0 af` is rejected;
- illegal out-of-range sequence `f5 80 80 80` is rejected.

The canonicality audit harness was changed only for L3-NET-03: its preserved `ff` and `fe` vectors now expect rejection. The original accepted behavior and exact vectors remain documented in `L3-NET-03_REPRODUCER.md`.

## Interaction and scope

The malformed harness frames retain correct inner length 8 and exact payload length, so they pass L3-NET-01 framing and L3-NET-02 exact-consumption checks and fail specifically at UTF-8 validation. Neither closed invariant was weakened or bypassed.

L3-NET-04 hybrid-signature framing was untouched. Authentication, validator identity, rate limiting, peer scoring, connection policy, gossip, address selection, consensus semantics, and address syntax were not changed.

## Downstream ambiguity analysis

Before remediation, distinct malformed address bytes could collapse to the same `String`, canonical re-encoding, PeerList hash, and equality value. Production then attempted address resolution; replacement-character addresses from the reproduced vectors are rejected and do not enter connection selection or persisted discovery. The optional validator ID is a separate fixed-width field, and authenticated transport identity is established outside PeerList, so no valid peer or validator impersonation was reproduced. No stop condition was met.

The strict decoder now rejects the ambiguity before PeerList hashing, deduplication, address resolution, reconnect selection, or gossip handling. This is not a full Sybil/eclipse, replay, or rate-limit audit.

## Validation results

- Focused production regression: PASS (1 passed).
- Canonicality audit harness: PASS; both L3-NET-03 malformed vectors report `REJECT`.
- `cargo test -p indra-network`: PASS (139 passed, 1 ignored; 4 integration tests passed).
- `cargo test -p indra-core`: PASS.
- `cargo test -p indra-consensus`: PASS.
- `cargo test -p indra-node`: PASS (271 passed, 5 ignored; 79 binary and 15 integration tests passed).
- `cargo test --workspace`: PASS.
- `cargo test --workspace --no-run`: PASS.
- `cargo fmt --all -- --check`: PASS.
- `git diff --check`: PASS.
- Focused patch reverse applicability check: PASS.

The repository had extensive pre-existing tracked and untracked changes. They were preserved and are not attributed to L3-NET-03.

## Review disposition

Focused remediation complete and returned for independent review. L3-NET-03 remains OPEN pending that review.
