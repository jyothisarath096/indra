# L3-NET-01 Focused Remediation

Date: 2026-08-20  
Finding: L3-NET-01 — inner message-length prefix is ignored  
Status: remediation implemented and validated; this report does not mark the finding closed.

## Original root cause

`Message::encode_wire` emits:

```text
[u32 total_length LE] [u8 message_type] [payload]
```

`total_length` counts the discriminator plus payload and excludes the four-byte length field. The authenticated validator transport writes the entire result as one AEAD plaintext frame.

On receive, `FrameReader::read_frame` authenticated and bounded that plaintext, after which the peer-manager read task discarded `plaintext[0..4]` and called `Message::decode_wire(&plaintext[4..])`. The declared inner length was never parsed or compared with the authenticated frame contents. An authenticated peer could therefore mutate only those four bytes to any value and reach the same application decoder and logical message.

Production reachability was:

```text
authenticated validator TCP connection
  -> FrameReader::read_frame (outer u32 cap, nonce, AEAD)
  -> peer_manager read task
  -> unconditional four-byte strip
  -> Message::decode_wire
  -> classification, rate limiting, relay/NetworkEvent, consensus consumer
```

The encoder documentation and implementation make the intended inner-length semantics authoritative and unambiguous.

## Authoritative framing invariant

For a complete inner wire object `data`:

```text
N = little_endian_u32(data[0..4])
N == data.len() - 4
N covers exactly: message discriminator + payload
```

The four-byte prefix is not included in `N`. A truncated prefix, a declaration below or above the available object, a zero declaration for a non-empty message, and a declaration above `MAX_MSG_BYTES` all fail closed. No fallback, normalization, alternate decoder, feature flag, or legacy mode exists.

## Source changes

Production files changed for this remediation:

- `indra-network/src/message.rs`
  - added `Message::decode_framed_wire`, which parses the four-byte prefix;
  - rejects declared lengths above `MAX_MSG_BYTES` before payload processing;
  - requires exact equality between declared and available inner-object bytes;
  - delegates to the existing payload decoder only after the framing invariant succeeds;
  - added two permanent regression tests.
- `indra-network/src/peer_manager.rs`
  - replaced the unconditional four-byte strip and direct payload decode with `Message::decode_framed_wire(&plaintext)`.

No other production file was changed for L3-NET-01.

## Regression tests

`framed_decoder_enforces_declared_inner_length` exercises the production decoder used by the peer manager and covers:

- canonical exact declaration: accepted;
- declaration one byte too small: rejected;
- declaration one byte too large: rejected;
- zero declaration for non-empty Ping: rejected;
- `u32::MAX` mutation of an otherwise valid message: rejected;
- declared length beyond available frame by removing one byte: rejected;
- truncated four-byte prefix: rejected.

`framed_decoder_accepts_outer_transport_maximum_when_declared_exactly` constructs a plaintext exactly `MAX_MSG_BYTES` bytes long, declares `MAX_MSG_BYTES - 4`, and proves the framed decoder accepts the exact declaration. It intentionally uses Ping trailing payload bytes because L3-NET-02 remains out of scope; this verifies L3-NET-01 without silently fixing the separate payload trailing-byte finding.

Focused test command:

```text
cargo test -p indra-network framed_decoder -- --nocapture
2 passed; 0 failed
```

## Malformed cases now rejected

- inner length 0 for a non-empty encoded message;
- inner length smaller than the discriminator-plus-payload bytes;
- inner length larger than the discriminator-plus-payload bytes;
- inner length larger than the available authenticated frame;
- inner declaration above `MAX_MSG_BYTES`;
- any mutation of only the inner length bytes that changes the canonical value;
- missing or truncated inner length prefix.

Rejection occurs before message classification, rate limiting, duplicate handling, signature validation, snapshot lookup, or consensus mutation. The decoder performs no attacker-sized allocation.

## Security properties preserved

- The outer `FrameReader` limit and pre-allocation check are unchanged.
- AEAD authentication, nonce validation, and handshake authentication are unchanged.
- `MAX_MSG_BYTES` remains enforced; the new decoder adds a redundant fail-closed inner check.
- Rate limiting still receives the authenticated plaintext byte count.
- Duplicate/relay keys and their canonical re-encoding are unchanged.
- Round, signature, QC, validator, and snapshot validation are unchanged.
- No malformed message can pass the new framing gate into consensus processing.

## Compatibility decision

Wire semantics are now strict: malformed frames previously accepted solely because the inner length was ignored are rejected and the peer connection closes through the existing malformed-message path. Canonically encoded messages are unchanged. No compatibility path was added because INDRA is pre-mainnet.

L3-NET-02, L3-NET-03, and L3-NET-04 were not remediated. In particular, payload decoders that currently accept trailing bytes still do so when the inner declared length accurately includes those bytes.

## Validation results

All required commands passed:

- `cargo test -p indra-network`: 133 passed, 1 ignored; 4 integration tests passed.
- `cargo test -p indra-core`: 144 unit and 21 integration tests passed.
- `cargo test -p indra-consensus`: 59 unit and 5 integration tests passed.
- `cargo test -p indra-node`: 271 library tests passed, 5 ignored; 79 node-binary and 15 integration tests passed.
- `cargo test --workspace`: passed across all workspace crates and doc tests.
- `cargo test --workspace --no-run`: passed; all workspace test executables built.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.

The repository was heavily dirty before remediation, including both production files changed here. Unrelated pre-existing changes were preserved and are excluded from the focused diff.

## Focused diff review notes

The focused patch is [L3_NET_01_REMEDIATION.diff](L3_NET_01_REMEDIATION.diff). Review scope is one new validation entry point, one production call-site replacement, and two regression tests. It does not change frame allocation, payload decoders, message classification, authentication, rate limiting, relay keys, or consensus code.

