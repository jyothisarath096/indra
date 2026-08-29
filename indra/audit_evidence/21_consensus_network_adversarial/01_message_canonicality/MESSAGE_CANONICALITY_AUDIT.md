# PROJECT INDRA Layer 3 Phase 2A — Message Canonicality Audit

Audit date: 2026-08-20  
Repository: `/Users/bonkai/Desktop/project_indra/indra`  
Scope: audit-only; current dirty worktree; no production remediation performed.

## 1. Production inbound call graph

The validator-node production path is:

```text
TCP socket
  -> authenticated hybrid-PQ handshake
     chain preface: magic/version/chain-id/genesis fingerprint
     fixed step1/step2: X25519 + ML-KEM-1024 + validator_id
     fixed 4627-byte ML-DSA-87 authentication frame and verification
  -> FrameReader::read_frame
     read u32 plaintext_len; reject > 14,680,064
     read/validate monotonic nonce
     allocate plaintext_len + 16 ciphertext bytes
     AEAD authenticate/decrypt
  -> peer_manager read task
     discard plaintext bytes [0..4] without validating the inner message length
  -> Message::decode_wire
     classify discriminator
     exact or custom payload decode
  -> canonical re-encoding for vote/block relay and duplicate keys
  -> per-connection duplicate/status filters
  -> PeerManagerActor::handle_control
     QC-response coalescing; per-peer/global rate checks
     vote/block pre-relay signature verification (failure prevents relay, not event delivery)
  -> NetworkEvent::Message
  -> indra-node main loop / net_driver::message_to_event
  -> ConsensusDriver::process
  -> cheap height/round/parent/context gates
  -> snapshot/validator lookup
  -> hybrid signature, proposer/VRF, QC verification
  -> state projection
  -> pending collector/proposal mutation or durable commit
```

`indra-network::transport::Connection` is a separate synchronous length-prefixed implementation with a correctly enforced u32 prefix and 14 MB cap. The validator peer manager uses authenticated `FrameReader`; observer networking uses separately bounded plain frames. No production dependency request/response message exists. Proposal recovery is `RequestProposal` followed by ordinary `Block`. QC recovery uses `RequestQC/QCResponse`.

## 2. Complete consensus-message inventory

The authoritative field-by-field inventory is [message_inventory.csv](message_inventory.csv). Consensus-relevant application messages are Block/Proposal, Vote, Status, RequestProposal, RequestBlocks/BlockResponse, RequestQC/QCResponse, and nested QC. Transaction, staking, governance, peer discovery, ping/pong, and authentication messages were included because they share the framing boundary or validator identity channel.

There is no standalone proposal-response discriminator, dependency request/response, validator-authentication application message, or direct QC gossip message. A proposal response is `Block`; validator identity is established in the transport handshake; QCs travel inside blocks or `QCResponse`.

## 3. Framing bounds

- `MAX_MSG_BYTES = 14,680,064` is checked before the async frame reader allocates `plaintext_len + 16` ciphertext bytes.
- AEAD additional data binds the outer length and nonce. The nonce must be the next counter value.
- The application encoder emits `[u32 inner length][u8 discriminator][payload]`. The async receiver discards the four-byte inner length without comparing it to the authenticated frame length (L3-NET-01).
- PeerList count is capped at 256 before `Vec::with_capacity`.
- BlockResponse count is capped at 50 before `Vec::with_capacity`.
- Core lists check type-specific maxima before capacity allocation. `VariableBytes<MAX>` checks its u32 length before copying.
- Nested block lengths in BlockResponse are slices borrowed from the already bounded plaintext; checked cursor arithmetic prevents overflow. Nested block decode is exact.
- `QCResponse.qc_bytes` has no local protocol-size check, but its allocation is strictly bounded by the already authenticated 14 MB frame. Its downstream QC decoder is exact and QC containers inside blocks are capped at 10,485,760 bytes.

No effectively unbounded attacker-controlled allocation was reproduced.

## 4. Canonicality results

Block, Vote, transaction, staking, governance, Status, RequestProposal, BlockResponse, and the nested core types use exact decode or explicit remainder checks. Their accepted payloads round-trip exactly.

Four non-critical exceptions were reproduced:

1. The four-byte inner application length can take any value while the same message is accepted (L3-NET-01).
2. Ping, Pong, RequestBlocks, RequestQC, and QCResponse accept trailing bytes (L3-NET-02).
3. Distinct invalid UTF-8 PeerList address bytes collapse through replacement decoding to one string (L3-NET-03).
4. Hybrid signature byte strings accept undersized values structurally and reject them at crypto conversion (L3-NET-04).

For L3-NET-01 and L3-NET-02, vote/block relay and duplicate identities hash `msg.encode_wire()`, not the received bytes, so all variants collapse to the canonical object key. Rate limiting charges `msg_size` from the original authenticated frame. QC-response coalescing also hashes canonical re-encoding. No bypass of authentication, vote identity, authorization, replay accounting, or consensus hashing was demonstrated.

## 5. Malformed-input results

The complete deterministic matrix is [decoding_matrix.csv](decoding_matrix.csv). Truncation of required fixed fields, variable data, and signature material rejects. Unknown message discriminators return a distinct error and are skipped by the peer read loop for rolling upgrade behavior. Unknown consensus enum/tag values reject. Bool and Option encodings accept only 0/1. Excess list counts reject before allocation.

Height 0, 1, and `u64::MAX` are syntactically valid integers. Height 0 is required for the genesis anchor. Live consumers enforce current/next-height, parent, request binding, and QC-height semantics, so the decoder correctly does not impose a universal height prohibition.

## 6. Round-boundary results

The authoritative legal domain is `0..1024`. Deterministic tests and existing crate tests establish:

- 0: accepted.
- 1023: accepted.
- 1024: rejected.
- `u32::MAX`: rejected.

The rule is applied by Vote, QC, block proposer round, block PoLC round, proposal-entropy origin round, Status, and RequestProposal decoding. Consensus entry points defensively repeat the validation before mutation. No illegal round reached consensus state.

## 7. Length/allocation analysis

All attacker-controlled allocation sites on the validator path have a proven outer cap. The largest single frame allocation is approximately 14,680,080 bytes of ciphertext plus the returned plaintext and decoder-owned copies. This is bounded, not unbounded; broader aggregate memory/DoS analysis is deferred as requested.

Potentially large inner fields use these widths and gates:

- frame/application/QCResponse/block item/VariableBytes: u32 little-endian;
- PeerList address: u16 little-endian;
- list counts: u32 little-endian;
- transport chain ID: u16 little-endian, checked at 1..64.

`read_bytes` uses checked addition and slice bounds. No `reserve(attacker_length)` or `vec![..; attacker_length]` occurs before either a protocol count bound or the transport cap. The handshake checks chain/auth lengths before allocation; step messages are fixed size.

An encoder-side PeerList caveat was noted: an internally constructed address longer than `u16::MAX` is cast to u16 while all bytes are appended. It is not attacker-reachable through the decoder (received addresses are already u16-bounded) and is not a finding in this inbound audit.

## 8. Signature-framing analysis

- Auth handshake ML-DSA-87 signature: exactly 4627 bytes before ciphertext allocation/decryption.
- Vote/proposal hybrid signature: u32-length Ed25519 bytes capped at 64 and ML-DSA-87 bytes capped at 4627. Truncated and oversized representations reject. Lengths below the exact algorithm sizes parse, then `to_crypto_sig` rejects before verification (L3-NET-04).
- QC signature lists: at most 200 PQ and 200 classical entries; each byte string is capped. QC verification requires signer counts to match the bitfield and exact 4627/64 conversions before cryptographic verification.
- Structurally valid, exact-length but cryptographically invalid signatures parse and fail verification, as intended.
- Truncated hybrid signatures and signature material reject through bounds-checked reads.

## 9. Validation-order analysis

Framing, count, enum, version, and round checks precede semantic/cryptographic work. Vote processing checks legal round, expected height, and maximum plausible round jump before snapshot lookup and signature verification. Proposal processing checks all round fields, sync state, next height, and parent hash before snapshot lookup, proposer authorization/VRF verification, embedded QC verification, and state projection. QCResponse checks local state/claimed height before exact QC decoding and QC verification.

One suspicious but low-impact ordering remains: malformed undersized vote signatures survive decoding, fail pre-relay verification, but are still delivered to the node, where snapshot lookup occurs before authoritative signature conversion/rejection. They do not enter a vote collector, slash detector, round evidence, or state mutation. This is L3-NET-04; broader cost analysis belongs to Phase 2G.

Block proposal authorization is verified before embedded QC and state projection. QC verification performs snapshot/bitfield/stake/count/duplicate checks before per-signer cryptography. No malformed message was observed reaching safety mutation before required structural validation.

## 10. Anomalies investigated

- Ignored inner length: reproduced; non-canonical; bounded by outer authenticated frame.
- Trailing data in five custom decoders: reproduced; canonical re-encoding collapses variants.
- Lossy PeerList UTF-8: reproduced; discovery resolution rejects resulting invalid address.
- Undersized signatures: reproduced; rejected before cryptographic acceptance/mutation.
- Unknown discriminator: rejected by decoder and skipped by peer loop; no alternate interpretation.
- Unknown tags/bools/options: rejected.
- Huge and nested lengths: rejected or strictly frame-bounded.
- Illegal rounds: rejected at decode and again at consensus admission.
- Extreme heights: syntactically accepted, contextually constrained; no universal decoder rule is valid.
- Raw QCResponse trailing data: discarded outside the declared QC; retained QC is exact-decoded before use.
- Outer vs inner transport parsers: no honest-node interpretation split was found; async production ignores only the redundant inner field, while synchronous Connection honors it on its separate stream path.

## 11. Findings and production reachability

### L3-NET-01 — Redundant inner message length is not validated

Preliminary severity: Low. Production reachable: yes, authenticated validators. Safety impact: none demonstrated. Liveness impact: none demonstrated. Resource impact: bounded extra bytes charged to sender. Potential subsystem: future raw-wire dedup/accounting and protocol tooling. Reproducer: [L3-NET-01_REPRODUCER.md](L3-NET-01_REPRODUCER.md). Recommended next audit action: decide whether the inner field is normative and add an interoperability/canonical-framing review during remediation planning.

### L3-NET-02 — Five message decoders accept trailing bytes

Preliminary severity: Low. Production reachable: yes. Safety impact: none demonstrated; nested QC remains exact. Liveness impact: none demonstrated. Resource impact: bounded and charged by actual frame size. Potential subsystem: QC-response coalescing, request accounting, future wire-hash replay keys. Reproducer: [L3-NET-02_REPRODUCER.md](L3-NET-02_REPRODUCER.md). Recommended next audit action: include exact-length enforcement in the remediation backlog and explicitly regression-test canonical re-encoding.

### L3-NET-03 — PeerList uses lossy UTF-8 decoding

Preliminary severity: Informational/Low. Production reachable: yes. Safety impact: none. Liveness impact: none; invalid result does not resolve as a peer address. Resource impact: bounded. Potential subsystem: peer-discovery dedup/telemetry. Reproducer: [L3-NET-03_REPRODUCER.md](L3-NET-03_REPRODUCER.md). Recommended next audit action: review discovery canonicalization when peer-exchange hardening is audited.

### L3-NET-04 — Undersized hybrid signatures admitted past decoding

Preliminary severity: Low. Production reachable: yes. Safety impact: none; rejected before collector/state mutation. Liveness impact: none demonstrated. Resource impact: a snapshot lookup and ordinary rejection path; bounded. Potential subsystem: relay admission and consensus vote validation. Reproducer: [L3-NET-04_REPRODUCER.md](L3-NET-04_REPRODUCER.md). Recommended next audit action: quantify malformed-signature traffic cost in Phase 2G and consider exact algorithm-size structural checks during remediation.

## 12. Open assumptions

- The audit targets the current working tree, which contained extensive pre-existing modifications in all reviewed crates. No attempt was made to attribute or revert them.
- Authenticated validators are still attacker-controlled for message bytes after a valid handshake; findings are not dismissed merely because the transport authenticates peers.
- Observer paths were checked for framing bounds, but observers do not feed validator consensus mutation.
- Full aggregate DoS, replay, rate-limit efficacy, database amplification, and cryptographic cost measurement remain out of scope.
- Maximum encoded block size is enforced semantically after decode in addition to the larger transport cap; this audit does not claim every 14 MB syntactically decodable block is semantically valid.

## 13. Validation and final disposition

Audit harness:

```text
cargo run --offline --manifest-path audit_evidence/21_consensus_network_adversarial/01_message_canonicality/harness/Cargo.toml
PASS (all assertions); reproduced L3-NET-01 through L3-NET-04
```

Required suites:

```text
cargo test -p indra-network
cargo test -p indra-core
cargo test -p indra-consensus
cargo test -p indra-node
```

Results:

- `indra-network`: 131 unit tests passed, 1 benchmark ignored; 4 integration tests passed; doc tests passed.
- `indra-core`: 144 unit tests and 21 serialization integration tests passed; doc tests passed.
- `indra-consensus`: 59 unit tests and 5 integration tests passed; doc tests passed.
- `indra-node`: 271 library tests passed with 5 benchmarks ignored; 79 node-binary tests and 15 integration tests passed; auxiliary binaries/doc tests passed.
- `git diff --check`: clean (exit 0).
- `git status --short`: remained heavily dirty with the pre-existing modified/untracked files observed before the audit, plus the requested untracked evidence directory. In particular, pre-existing modifications remained in `indra-network/src/message.rs`, `indra-network/src/peer_manager.rs`, `indra-core`, `indra-consensus`, and `indra-node`. No production file was edited by this audit.

The generated harness `target` directory was moved out of the evidence tree to `/tmp/indra-audit-build.DIOdsZ/target`; source and lockfile remain reproducible in evidence.

**PASS WITH NON-CRITICAL FINDINGS**
