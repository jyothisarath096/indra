# Layer 2 Phase 5 — transcript canonicality audit

## L3-CS-01 snapshot-binding update

The canonical hybrid vote transcript now ends with the exact 32-byte governing
`snapshot_root`. Both signature components cover identical bytes. `VoteV1`
carries that root on wire, QC construction rejects mixed roots, and QC
verification compares the certificate root with the validated governing
snapshot before checking signer authority. The QC discriminator is format 3 and
the durable vote-safety record is format 3; neither retains an old decoder.

Date: 2026-08-18  
Result: **PASS (VRF-007 retained as a closed historical finding)**

No new legal-input collision, cross-context acceptance, decoder ambiguity, or
domain-separation failure was found. Production code was not changed during the
resumed audit. The executable cross-context evidence is isolated under
`cross_context_harness/`.

## Closed historical finding

### L2-TC-01 / VRF-007 — stable value did not bind `ProposalEntropyV1`

**Status: CLOSED.** The original evidence and end-to-end analysis remain in
`VRF007_EXPLOITABILITY.md`; the reviewed remediation diff remains in
`VRF007_REMEDIATION.diff`. Version 3 now computes:

```text
entropy_commitment =
  SHA-256("INDRA-PROPOSAL-ENTROPY-COMMIT-v1" ||
          canonical_encode(ProposalEntropyV1))
```

and places that fixed 32-byte commitment in the stable value-hash preimage
(`indra-core/src/types/block.rs:100-110,208-230`). Live admission projects and
compares state, validator and value commitments before inserting the proposal
or mutating vote/lock state (`indra-node/src/driver.rs:1431-1459`). Sync/replay
does the same without a zero-hash fallback (`indra-node/src/sync.rs:1084-1141`).

The preserved scenario now produces distinct stable hashes and
`original_polc_authorizes_substituted=false`. Permanent tests establish
component sensitivity, exact commitment round-trip, unchanged-entropy
reproposal stability, and pre-mutation rejection
(`block.rs:517-602`; `driver.rs:5329-5454`).

## Canonical codec foundation

Consensus integers have one fixed-width little-endian representation; `u8`,
`u16`, `u32`, and `u64` occupy 1/2/4/8 bytes
(`indra-core/src/codec/mod.rs:55-109`). Booleans accept only `00` and `01`
(`codec/mod.rs:111-125`). Lists use a `u32_le` count and bounded decode before
allocation (`codec/mod.rs:129-157`). `VariableBytes` uses a `u32_le` length and
enforces its type-level maximum (`types/primitives.rs:545-610`). `decode_exact`
rejects every trailing byte (`codec/mod.rs:35-50`).

The proofs below concern transcript preimages. Hash outputs additionally rely
on SHA-256/SHA-512 collision resistance; no finite digest can be mathematically
injective over an unbounded input space.

## Transcript classifications and injectivity proofs

### 1. Proposer sortition alpha — PASS

`INDRA-PROPOSER-SORTITION-v2 || u16_be(chain_len) || chain || seed[64] ||
height:u64_le || round:u32_le || snapshot_root[32] || proposer_id[32]`
(`indra-core/src/types/proposal.rs:34-56`). The sole variable field is explicitly
length-prefixed; every suffix is fixed width. Parsing left-to-right is unique.
The valid-proof harness rejects changes to chain, height, round, validator and
snapshot. The snapshot root transitively binds suite, VRF key and activation
epoch.

### 2. Election-seed evolution — PASS

`INDRA-ELECTION-SEED-v2 || u16_be(chain_len) || chain || prior[64] ||
height:u64_le || origin_round:u32_le || origin_proposer_id[32] ||
vrf_output[64] || snapshot_root[32]` (`proposal.rs:59-84`). The verified output
is exactly 64 bytes before this function is reached (`proposal.rs:179-191`), so
every boundary is fixed or length-delimited. `vrf_proof` is deliberately absent:
RFC 9381 proof-to-hash binds the output, while stable value identity binds the
proof bytes through the entropy commitment.

### 3. `ProposalEntropyV1` commitment — PASS

The preimage is its unique domain followed by `Bytes32 || u32_le ||
VariableBytes<64> || VariableBytes<80>` (`block.rs:87-143`). Both variable
values have `u32_le` lengths and exact maximums. Each field mutation changes the
preimage and tested digest; exact decode/re-encode preserves it
(`block.rs:557-602`). Stable value hash includes the resulting fixed 32 bytes
but excludes current-round proof fields (`block.rs:208-230,434-449`).

### 4. VRF secret-possession challenge — PASS

Initial `RegisterValidator`, genesis registration, and later `RegisterVrfKey`
use one proof protocol:
`INDRA-VRF-KEY-POSSESSION-v1 || u16_be(chain_len) || chain || validator_id[32]
|| vrf_pk[32] || activation_epoch:u64_le` (`staking.rs:230-251`). Initial
registration fixes activation to 0 (`indra-state/src/delegation.rs:719-728`;
genesis: `indra-node/src/genesis.rs:278-290`). Rotation uses its required
snapshot epoch (`delegation.rs:254-266,428-472`). The harness rejects wrong
chain, validator, epoch, key, and both PoP/election cross-domain replays.

### 5. Proposal hybrid authorization — PASS

`INDRA-PROPOSAL-AUTH-v1 || u16_be(chain_len) || chain || height:u64_le ||
round:u32_le || proposer_id[32] || block_len:u64_le || canonical_block`
(`block.rs:382-402`). Lengths eliminate concatenation ambiguity. Redundant
height/round/proposer fields equal fields inside the single encoded block, so
they create no aliases. Verification reconstructs bytes from the received
object and independently resolves the snapshot key (`proposal.rs:116-129`).
Tests reject changed content and another chain (`driver.rs:2867-2882`).

### 6. Consensus snapshot root — PASS

`INDRA-CONSENSUS-SNAPSHOT-v1 || format:u8 || activation_height:u64_le ||
source_boundary_height:u64_le || u32_le(entry_count) || entries ||
total_weight:u64_le || F:u64_le || log_lo[128] || log_hi[128]`
(`consensus_snapshot.rs:310-332`). Entries are fixed width, strictly ascending,
unique, and capped at 200 (`consensus_snapshot.rs:220-235`). Decode validates
format, keys, total, Q768 certificate and recomputed root before returning
(`consensus_snapshot.rs:99-112,206-250,272-286`). Snapshot format version 2 is
therefore transitively present in every proposer alpha.

### 7. Genesis entropy descriptor and record — PASS

The descriptor is fixed-width: `scheme:u8 || network_genesis_hash[32] ||
announced_height:u64_le || header_codec:u8 || extraction:u8 ||
minimum_confirmations:u32_le || reorg_policy:u8`. Only enum value 1 is accepted
and confirmations must be at least 100 (`indra-node/src/genesis.rs:75-115`).
The record is `INDRA-GENESIS-ENTROPY-RECORD-v1 || descriptor[48] ||
bitcoin_header[80]` (`genesis.rs:118-129`). Text hex accepts only exact-length
lowercase ASCII hex (`genesis.rs:372-389`), eliminating textual aliases.

### 8. Genesis source ID and election seed — PASS

Source ID is `INDRA-EXTERNAL-ENTROPY-SOURCE-ID-v1 || descriptor[48]`. The seed
preimage is `INDRA-GENESIS-ELECTION-SEED-v1 || chain || source_id[32] ||
double_sha256(header)[32]` (`genesis.rs:131-151`). Although chain lacks an
explicit prefix here, its boundary is uniquely recoverable as total length
minus 64 because both suffixes are fixed 32 bytes. Callers cannot shift bytes
between chain and either fixed-width suffix.

### 9. Genesis fingerprint — PASS

`INDRA-GENESIS-FINGERPRINT-v1 || u16_be(chain_len) || chain || state_root[32] ||
snapshot_root[32] || canonical_monetary_ledger || election_seed[64] ||
entropy_record_hash[32]` (`genesis.rs:395-411`). Chain is length-prefixed;
ledger and other fields have canonical fixed boundaries. This fingerprint is
the height-zero stable anchor and P2P genesis identity.

### 10. Validator/key-activation authorization — PASS

Outer staking bytes are `INDRA_STAKING_V2 || u16_le(chain_len) || chain ||
nonce:u64_le || tagged canonical body` (`staking.rs:253-267`). Legal chain ID
length is bounded below `u16::MAX` at genesis. `RegisterVrfKey` has a unique tag
and fixed suite/key/epoch/output plus a length-prefixed proof
(`staking.rs:726-740,902-909`). Initial registration additionally signs a dual
hot/cold authorization with independently `u32_le`-framed canonical envelopes
(`staking.rs:360-418`). Authorization envelopes frame domain, chain and payload
and bind operation tag, identity, role, key version and nonce
(`authorization.rs:78-121,193-195`). Unknown roles/domains/tags fail.

## Snapshot and version recontextualization

Snapshots with identical validator/key membership but different activation and
source heights have different roots; a proof made for one fails under the
other. Changing VRF key, suite, or activation epoch changes the canonical entry
and root (`consensus_snapshot.rs:27-42,80-96,310-332`). Only suite value 1 is
legal; alternate suite bytes fail enum decoding (`block.rs:25-56`). A future
suite must change the entry/root and therefore the alpha.

## Decoder/adversarial framing result

Network proposal and staking ingress use `decode_exact`
(`indra-network/src/message.rs:344-375`); block responses exact-decode every
length-framed proposal (`message.rs:520-543`). Segmented storage exact-decodes
after length and CRC verification (`indra-storage/src/segmented_block_store.rs:
420-444,505-519`). Persisted locks length-frame and exact-decode the proposal
and every PoLC vote, cap vote count, and reject unknown option markers
(`indra-storage/src/vote_safety.rs:183-219`). Startup replay then independently
verifies proposal and projected roots.

Permanent tests cover truncated/trailing headers/proposals, overlong bounded
bytes, unknown suite/claim/tag/version values, invalid Boolean/Option markers,
duplicate/unsorted snapshot members, tampered roots/certificates, and staking
trailing bytes. No relevant ingress used a prefix-only decoder.

## Residual assumptions

* Commitments rely on SHA-256/SHA-512 collision resistance.
* RFC 9381 uniqueness/canonical decoding supplies one output for `(key, alpha)`;
  separate negative and differential audit evidence covers this.
* Future suites must receive a new enum value and snapshot root rather than
  reassigning suite value 1.

These are explicit cryptographic/versioning assumptions, not open encoding
gaps.

## Validation record

The deterministic, release-mode cross-context harness passed all twelve checks:
six election recontextualizations, three PoP recontextualizations, both
cross-protocol proof replays, and the same-membership/different-snapshot-root
check. The exact command and output are retained in `cross_context_tests.md`.

Required package results:

* `cargo test -p indra-core`: **159 passed** (138 unit + 21 serialization).
* `cargo test -p indra-state`: **351 passed, 2 ignored** (315 unit, 4 audit,
  10 monetary, 22 state-machine); its zero-test rustdoc phase was then rerun
  successfully in the isolated target described below.
* `cargo test -p indra-consensus`: **59 passed** (54 unit + 5 integration).
* `cargo test -p indra-node`: **358 passed, 5 ignored** (264 library, 79
  binary, 15 integration).
* `cargo test --workspace --no-run`: **PASS**.
* `git diff --check`: **PASS**.

During the first sequential run, Cargo's final `indra-state` rustdoc invocation
found that dependency `.rlib` files had disappeared from the shared default
target directory; an immediate retry similarly lost `rand_core` while compiling
`rand_chacha`. No other Cargo/rustc process remained visible. To avoid treating
an artifact-directory race as a protocol failure, the remaining commands were
rerun with `CARGO_TARGET_DIR` set to a fresh `mktemp` directory and
`CARGO_BUILD_JOBS=1`. In that isolated target the state rustdoc, complete
consensus and node suites, workspace no-run build, and diff check all passed.
