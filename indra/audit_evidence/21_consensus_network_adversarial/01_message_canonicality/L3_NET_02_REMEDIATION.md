# L3-NET-02 Focused Remediation

Date: 2026-08-20  
Finding: L3-NET-02 — trailing bytes accepted by five message decoders  
Status: remediation implemented and validated; this report does not mark the finding closed.

## Original root cause and affected variants

All five affected branches were independent custom decoders in `Message::decode_payload`:

- Ping read `payload[0..8]` and never required `payload.len() == 8`.
- Pong read `payload[0..8]` and never required `payload.len() == 8`.
- RequestBlocks read `payload[0..8]` and `payload[8..16]` and never required `payload.len() == 16`.
- RequestQC read `payload[0..8]` and never required `payload.len() == 8`.
- QCResponse read its 12-byte header and copied `payload[12..12+declared_qc_len]` without requiring that slice to end at `payload.len()`.

Each decoder therefore consumed the required prefix and silently ignored the remainder. No shared helper caused the defect, and no nested parser returned an alternate interpretation.

Production reachability was the authenticated validator path:

```text
FrameReader -> Message::decode_framed_wire -> Message::decode_wire
  -> affected Message::decode_payload branch
  -> rate limiting / NetworkEvent / node consumer
```

## Canonicality invariant

Every payload decoder must consume exactly all bytes assigned to its message. Specifically:

- Ping: exactly 8 payload bytes.
- Pong: exactly 8 payload bytes.
- RequestBlocks: exactly 16 payload bytes.
- RequestQC: exactly 8 payload bytes.
- QCResponse: exactly `12 + declared_qc_bytes_length` payload bytes, using checked addition.

Canonical encodings are unchanged. A canonical payload followed by any byte sequence is now rejected rather than normalized or truncated.

## Source changes

Production file changed:

- `indra-network/src/message.rs`
  - added exact payload-length gates to the five affected branches;
  - added checked QCResponse expected-length calculation and exact equality;
  - added a shared test helper and five message-specific permanent tests;
  - changed the transport-maximum framing test to expect rejection for a maximum-sized noncanonical Ping payload;
  - added a maximum legal QCResponse canonical round-trip.

Audit harness changed:

- `audit_evidence/.../harness/src/main.rs`
  - changed only L3-NET-02 trailing-byte expectations from ACCEPT to REJECT.
  - original accepted behavior remains preserved in `L3-NET-02_REPRODUCER.md` and the original audit report.

No production file other than `message.rs` changed for this remediation.

## Regressions

Each of Ping, Pong, RequestBlocks, RequestQC, and QCResponse now has a permanent regression which proves:

- canonical encoding is accepted;
- decode followed by encode returns the identical canonical bytes;
- one trailing byte is rejected;
- multiple trailing bytes are rejected;
- trailing bytes resembling a complete Pong wire object are rejected;
- the malformed frame declares the correct enlarged inner length, proving semantic rejection after the L3-NET-01 gate.

Message boundaries additionally cover `0`/`u64::MAX` nonce or height values, empty and non-empty QC bytes, and a QCResponse whose complete framed encoding is exactly `MAX_MSG_BYTES`.

## Interaction with L3-NET-01

L3-NET-01 remains intact: `declared_length == framed_plaintext.len() - 4` is checked first. Every trailing-garbage regression updates the inner declaration to include the garbage. The frame therefore passes L3-NET-01 and is rejected only by the exact semantic payload check.

No inner framing code, fallback, or compatibility behavior was changed.

## Downstream ambiguity removed

Before remediation, distinct authenticated wire strings differing only by a suffix decoded to the same logical message. Current relay/dedup/QC-response keys canonicalized via re-encoding, while rate limiting charged the actual frame size; no security-significant bypass or signed-transcript divergence was found.

The remediation removes that representational ambiguity before message classification, hashing, duplicate/replay keys, rate-limit admission, signature processing, or consensus consumers. Field values and signature transcripts are unchanged.

## Scope confirmation

- L3-NET-03 PeerList UTF-8 behavior was untouched.
- L3-NET-04 hybrid signature framing was untouched.
- Authentication, rate limiting, duplicate handling, gossip, consensus semantics, discriminators, and field ordering were untouched.
- No additional Message variant became strict as an automatic side effect; only the five named branches changed.
- No stop condition was encountered.

## Validation results

All required validation passed:

- focused exact-payload tests: 5 passed;
- focused framed-decoder tests: 2 passed;
- updated message canonicality audit harness: passed, with all five L3-NET-02 variants rejected;
- `cargo test -p indra-network`: 138 passed, 1 ignored; 4 integration tests passed;
- `cargo test -p indra-core`: 144 unit and 21 integration tests passed;
- `cargo test -p indra-consensus`: 59 unit and 5 integration tests passed;
- `cargo test -p indra-node`: 271 library tests passed, 5 ignored; 79 node-binary and 15 integration tests passed;
- `cargo test --workspace`: passed across all crates and doc tests;
- `cargo test --workspace --no-run`: passed;
- `cargo fmt --all -- --check`: passed;
- `git diff --check`: passed.

The worktree was heavily dirty before this remediation. Unrelated pre-existing changes were preserved and excluded from the focused diff.

## Focused diff

See [L3_NET_02_REMEDIATION.diff](L3_NET_02_REMEDIATION.diff). It contains only the five exact-consumption changes, their regression tests, and the audit-harness expectation updates.

