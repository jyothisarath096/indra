# L3-NET-04 Remediation Evidence

Status: remediation submitted for independent review. This report does not mark L3-NET-04 closed.

## Original root cause

Hybrid signature components are encoded as `u32_le(length) || bytes`. `VariableBytes<MAX>` rejected lengths above its maximum and truncation, but accepted every length at or below the maximum. Consequently, zero- and undersized Ed25519 or ML-DSA-87 components survived `Message::decode_wire`. `HybridSignature::to_crypto_sig` later required fixed arrays and rejected them before cryptographic verification or consensus mutation.

For votes, the authenticated production path was transport/frame extraction, L3-NET-01 exact frame-length validation, `Message::decode_framed_wire`, `Message::decode_wire`, `VoteV1::decode_exact`, permissive `HybridSignature::decode`, relay conversion/rejection, event delivery, node height/round checks, snapshot lookup, and authoritative conversion/rejection. This admitted bounded malformed data farther than necessary.

QC components had the same maximum-versus-exact distinction in `PQVoteSig::decode` and `ClassicalVoteSig::decode`; exact array conversion occurred only in QC verification.

## Scope and affected paths

The network boundary carries `HybridSignature` through:

- `Block` proposal authorization and signatures nested in its transactions, staking operations, and governance operations;
- `BlockResponse` through the same nested proposal decoder;
- `Vote`;
- `Tx`;
- `StakingOp`, including validator-registration and cold-key-rotation signatures;
- `GovernanceOp`.

Embedded QCs and `QCResponse.qc_bytes` carry per-signer ML-DSA-87 `PQVoteSig` and Ed25519 `ClassicalVoteSig` components. `QCResponse` intentionally admits opaque bounded QC bytes at the message layer; every production consumer subsequently calls `QuorumCertificateV1::decode_exact`, where component lengths are now rejected structurally.

Peer authentication is not affected: `read_auth_frame` already requires an exact 4,627-byte ML-DSA-87 signature before allocation/decryption and was unchanged.

## Authoritative sizes and layout

The implementation uses the production constants exported by `indra-crypto/src/constants.rs`:

- `indra_crypto::CLASSICAL_SIG_BYTES`: 64 bytes (Ed25519);
- `indra_crypto::PQ_SIG_BYTES`: 4,627 bytes (ML-DSA-87).

A hybrid signature remains two independently `u32`-length-prefixed byte strings in Ed25519-then-ML-DSA order. No discriminator, field order, length width, signed transcript, or canonical valid encoding changed.

## Exact invariant and source changes

At network admission, every hybrid component must have exactly its authoritative algorithm size. `require_exact_hybrid_signature` and its proposal/staking traversal reject any decoded network object whose Ed25519 length is not 64 or whose ML-DSA-87 length is not 4,627. This check runs inside `Message::decode_payload`, before message classification, relay admission, validator/snapshot lookup, cryptographic verification, database access, or consensus-driver mutation.

Oversized `VariableBytes` lengths continue to reject before copying. Undersized hybrid components undergo only their existing bounded copy (at most 4,691 total signature bytes) and are then rejected at the network decoder boundary; no lookup or cryptographic work follows.

QC decoding uses the shared `decode_fixed_signature` helper. It reads the `u32` length, compares it with the authoritative constant, and only then reads/copies signature bytes. A new `IndraError::InvalidLength` reports exact-size violations. QC signature components therefore reject before allocation/copy, signer/snapshot processing, or cryptographic verification.

Investigation found that the shared core `HybridSignature` decoder is also used for the canonical genesis block's intentional empty proposer-authorization sentinel. Making that shared decoder universally strict changed canonical persisted genesis bytes and broke recovery. That over-broad approach was discarded. Final enforcement is at the network boundary, preserving genesis and all canonical production encodings while making every accepted network hybrid signature exact.

## Regressions

Permanent tests establish:

- canonical exact-size hybrid signatures decode for every application message carrier;
- Ed25519 zero and one-byte-short components reject for Block, BlockResponse, Vote, Tx, StakingOp, and GovernanceOp with otherwise exact outer framing;
- ML-DSA-87 zero and one-byte-short components reject for the same variants;
- `HybridSignature` exact-size garbage converts structurally but fails `verify_hybrid`, proving framing validity is distinct from cryptographic validity;
- QC Ed25519 and ML-DSA-87 components reject at zero, one byte short, and one byte long;
- a truncated exact-size hybrid component rejects;
- canonical exact-size vectors remain accepted and byte-identical through existing round-trip suites.

The canonicality harness retains the original vectors but now expects `signature_empty`, `signature_ed25519_63`, and `signature_mldsa_4626` to reject. Exact 64/4,627 vectors remain accepted.

## Closed-finding interaction

All malformed application-message regressions are created through `encode_wire`; their declared inner length equals the complete frame length. They therefore pass L3-NET-01 framing and fail specifically on signature size. Exact semantic consumption from L3-NET-02 remains unchanged. Strict PeerList UTF-8 from L3-NET-03 is unrelated and unchanged.

## Downstream consequence review

Before remediation, undersized vote/proposal signatures caused one bounded signature allocation/copy, relay conversion failure, event delivery, and—for the reproduced vote path—a snapshot lookup before authoritative rejection. No Ed25519 or ML-DSA verification occurred for malformed lengths, no rate-limit identity changed, no signature transcript ambiguity was found, and no collector, slash detector, authentication state, or consensus state mutation was reachable.

After remediation, malformed application-message signature lengths stop inside network decoding. Malformed QC component lengths stop in exact QC structural decoding before verification. Exact-size but cryptographically invalid bytes continue to reach the normal cryptographic verifier and are rejected there, as required. Preliminary severity remains LOW; no stop condition was met.

## Validation results

- Focused network carrier regression: PASS.
- Focused hybrid/QC structural and cryptographic-distinction regressions: PASS.
- Previously exposed genesis/recovery regression: PASS after boundary-scoped design.
- Canonicality audit harness: PASS; undersized vectors reject and exact-size vectors accept.
- `cargo test -p indra-network`: PASS (140 passed, 1 ignored; 4 integration tests passed).
- `cargo test -p indra-core`: PASS (148 passed; 21 integration tests passed).
- `cargo test -p indra-consensus`: PASS (59 unit and 5 integration tests passed).
- `cargo test -p indra-node`: PASS (271 passed, 5 ignored; 79 binary and 15 integration tests passed).
- `cargo test --workspace`: PASS.
- `cargo test --workspace --no-run`: PASS.
- `cargo fmt --all -- --check`: PASS.
- `git diff --check`: PASS.
- Focused diff reverse-application check: PASS.

The repository had extensive pre-existing tracked and untracked changes. They were preserved and are not attributed to L3-NET-04.

## Review disposition

Focused remediation complete and returned for independent review. L3-NET-04 remains OPEN pending that review.
