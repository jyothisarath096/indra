# L3-CS-01 remediation — governing snapshot binding

Date: 2026-08-20

Status: **L3-CS-01 — LOW — FIXED**

## Protocol result

Every vote now carries the exact 32-byte root of the consensus snapshot that
governs its height. The canonical vote transcript binds, in order:

`domain || chain_len:u16_le || chain || height:u64_le || round:u32_le || step:u8 || block_hash[32] || validator_id[32] || snapshot_root[32]`.

Both Ed25519 and ML-DSA-87 sign these identical bytes. `VoteV1` serializes the
root before its hybrid signature (`indra-core/src/types/vote.rs:45-90`), and the
shared transcript appends it canonically (`indra-core/src/types/vote_signing.rs:11-31`).

`VoteCollector` is constructed for one root and rejects a vote carrying another
before authority/signature processing (`indra-consensus/src/vote.rs:67-111,
149-155,221-241`). QC construction rejects a mixed-root union and stores the
single root (`indra-consensus/src/qc.rs:131-211`). QC verification signs and
verifies with the certificate root (`indra-consensus/src/qc.rs:337-344`) and the
snapshot adapter rejects a root different from the governing validated snapshot
(`indra-core/src/types/qc.rs:141-153`).

Production signing resolves the root from canonical historical state rather
than accepting a caller-supplied root (`indra-node/src/engine.rs:1558-1582`).
Driver QC construction uses the height-governing snapshot
(`indra-node/src/driver.rs:2009-2021`); sync/import fixtures and verification use
the corresponding certified snapshot (`indra-node/src/sync.rs:1388-1454`).

## Wire and storage changes

- `VoteV1`: breaking wire change; a mandatory `snapshot_root[32]` precedes the
  signature. There is no legacy vote decoder.
- `QuorumCertificateV1`: `QC_FORMAT_HYBRID = 3`; the mandatory root follows
  `block_hash` (`indra-core/src/types/qc.rs:26,266-307`). Format 2 is rejected.
- Durable vote-safety: `SAFETY_FORMAT_VERSION = 3`; embedded PoLC votes use the
  new exact vote encoding (`indra-storage/src/vote_safety.rs:24,172-205`). Old
  records are rejected; there is no migration decoder.
- No block-format discriminator was independently bumped: blocks already carry
  QC/PoLC bytes as bounded opaque fields, and those bytes now require QC format
  3/new `VoteV1` framing.

This is a pre-mainnet consensus/storage break. Existing votes, QCs, persisted
locks, and testnet state must be discarded in a clean redeployment.

## Fixture migration and zero-root sweep

Shared QC/vote builders in driver, engine, sync, state, consensus, and node
integration tests now derive `snapshot.snapshot_root` from the fixture's actual
governing snapshot. Low-level codec/collector tests use an explicit nonzero
synthetic snapshot context. Deliberate mixed-root tests remain unchanged in
purpose.

The final targeted grep found no `snapshot_root: Bytes32::ZERO`,
`snapshot_root = Bytes32::ZERO`, or `&Bytes32::ZERO` used as a consensus
snapshot argument. Remaining zero values are nil block hashes, empty IDs, or
status/tip sentinels unrelated to snapshot identity.

## Preserved regressions

- `qc_is_cryptographically_bound_to_one_snapshot_root`: a genuine QC signed
  under snapshot A verifies under A and fails under valid snapshot B, whose
  membership/key are identical but weight/root differ.
- `qc_builder_rejects_mixed_snapshot_votes_before_quorum`: genuine votes signed
  under roots A and B cannot be unioned into a QC.
- Node driver and sync capstone tests demonstrate live admission, replay, and
  historical verification use the governing root.

## Validation

- `cargo test -p indra-core`: PASS — 165 tests (144 unit + 21 integration).
- `cargo test -p indra-storage`: PASS — 45 passed, 1 ignored.
- `cargo test -p indra-consensus`: PASS — 64 tests (59 unit + 5 integration).
- `cargo test -p indra-node`: PASS — 365 passed, 5 ignored across library,
  binaries, and integration tests.
- `cargo test --workspace`: PASS — all workspace unit, integration, and doc
  tests; only explicitly ignored benchmark tests were skipped.
- `cargo fmt --all -- --check`: PASS.
- `git diff --check`: PASS.

