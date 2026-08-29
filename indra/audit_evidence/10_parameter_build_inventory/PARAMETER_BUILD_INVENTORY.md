# Layer 2 Phase 4A: consensus parameter and build inventory

Audit revision: `b6404ccacc508d92a022f50ad1af3da4d4e31a02`  
Review date: 2026-08-18  
Scope: inventory only; no production source was changed.

## Executive result

| ID | Classification | Result |
|---|---|---|
| BM-01 | **OPEN** | The repository does not define a complete permitted consensus-build matrix. It has no `rust-toolchain*`, `.cargo/config*`, Dockerfile, Makefile, release workflow, MSRV, exact target triples, or CPU-feature policy. |
| BM-02 | **FINDING-CANDIDATE** | The release installer names three supported OS/architecture pairs, while the whitepaper additionally claims Windows support. No Windows release artifact or build/test path exists. |
| FP-01 | **PASS (source/current binary only)** | The production authority-to-sortition path contains no source-level floating-point operations. The inspected optimized `aarch64-apple-darwin` sortition assembly contains no scalar/vector FP arithmetic or integer-to-FP conversions. This is not a universal-build proof because BM-01 is open. |
| PAR-01 | **PASS** | `F`, stake weights, total weight, snapshot certificate, suite, proposal version, seed, and entropy identity are validated and committed; persisted invalid values fail closed on the normal decode paths. |
| PAR-02 | **FINDING-CANDIDATE** | Consensus rounds have wire type `u32` but no protocol maximum below `u32::MAX`; timeout/restart advancement uses `saturating_add(1)`. At `u32::MAX`, advancement remains at the same round. `MAX_ROUNDS_PER_HEIGHT=1024` is explicitly not a retry cap. This is a boundary-liveness ambiguity, not an observed exploit in this inventory. |
| VER-01 | **OPEN** | There is one accepted version/suite today, but no on-chain activation schedule or mixed-version compatibility rule for a future suite/snapshot/proposal/entropy/transcript change. Unknown values fail closed, so a future transition requires a coordinated redeploy unless a schedule is designed first. |

## A. Build matrix

### A.1 Repository evidence

- Workspace release settings are optimization level 3, LTO, one codegen unit,
  and `panic=abort` (`Cargo.toml:51-56`). README build instructions use
  `cargo build --release` (`README.md:70-76`).
- There is no pinned compiler: no `rust-toolchain` file and no
  `rust-version` workspace/package field. `Cargo.lock` pins dependencies, not
  the Rust compiler.
- The only workflow is a fuzz smoke job on `ubuntu-latest` with unpinned
  `nightly`; it does not build a release validator (`.github/workflows/fuzz-smoke.yml:11-27`).
- The installer explicitly accepts Linux x86-64, Linux AArch64, and macOS
  arm64 (`releases/install.sh:20-34`), and matching node binaries are checked
  in. The exact Linux triples (GNU versus musl) and build flags are not
  recorded; `file` reports the Linux binaries as static ELF executables.
- The whitepaper claims macOS 12+, Ubuntu 20.04+, and Windows 10+ 64-bit
  (`docs/WHITEPAPER.md:807-821`), but there is no Windows artifact or build CI.
- Workspace crates expose no production feature switches. The sole local
  feature is `indra-consensus/test-utils`; it is not enabled by default
  (`indra-consensus/Cargo.toml:9-10`). Dependency feature resolution remains
  relevant and is locked by `Cargo.lock`.

### A.2 Classification

| Dimension | Classification | Inventory conclusion |
|---|---|---|
| Rust compiler/toolchain | **UNKNOWN / UNDEFINED** | No channel, version, MSRV, or compiler commit is required. Current audit host used `rustc 1.96.0 (ac68faa20, LLVM 22.1.2)`, but that is an observation, not protocol policy. |
| Release profile | **SUPPORTED** | `cargo build --release` is the documented deployment build and the profile is explicit. The protocol does not technically reject binaries built with another profile. |
| Dev/test profile | **TESTED BUT NOT SUPPORTED** | Normal `cargo test` uses the declared unoptimized dev profile (`Cargo.toml:58-60`); no document authorizes it for validators. |
| Linux x86-64 | **SUPPORTED** | Installer and checked-in release binary. Exact target triple and CPU baseline are undefined. |
| Linux AArch64 | **SUPPORTED** | Installer and checked-in release binary. Exact target triple and CPU baseline are undefined. |
| macOS arm64 / `aarch64-apple-darwin` | **SUPPORTED** | Installer and checked-in binary; current release compilation was inspected on this target. Minimum macOS claim is documentation only. |
| Windows x86-64 | **UNKNOWN / UNDEFINED** | Whitepaper claim only; contradicted by the installer's explicit unsupported-platform branch and absence of artifact/CI. |
| Other OS/architectures | **UNKNOWN / UNDEFINED** | An installed Rust target is not repository support. |
| CPU/target features | **UNKNOWN / UNDEFINED** | No `RUSTFLAGS`, `target-cpu`, `target-feature`, or `.cargo/config` policy. Dependency runtime dispatch may vary by target. |
| Production Cargo features | **REQUIRED** | Effective default workspace feature set: no local production feature toggles. A non-default dependency feature build is not declared supported. |
| `indra-consensus/test-utils` | **TESTED BUT NOT SUPPORTED** | Test-only local feature, not a validator configuration. |

**BM-01 conclusion:** there is no complete consensus-build matrix. In
particular, the repository cannot currently support a universal claim that
all permitted compiler/target/feature combinations compile consensus math
identically, because “permitted” is not defined.

## B. Election parameter registry

All fixed-width integers use the core codec's little-endian encoding
(`indra-core/src/codec/mod.rs:69-108`) unless a row explicitly says otherwise.

| Parameter | Type/domain | Source and mutation | Serialization/commitment | Validation, activation, bypass assessment | Status |
|---|---|---|---|---|---|
| Active-slot numerator `F` | `u64`; `1..=2^63` (`indra-core/src/sortition.rs:10-11,75-83`) | Required canonical decimal **string** in genesis TOML (`indra-node/src/genesis.rs:45-70`); copied into chain state (`genesis.rs:581-585`). No governance action or post-genesis production mutation was found. | State: 8-byte LE (`indra-state/src/chain.rs:278-283`); state-root metadata (`state_root.rs:44-57`); snapshot: 8-byte LE and root-bound with its 128-byte BE Q768 endpoints (`consensus_snapshot.rs:254-268,310-332`). | Genesis calls `validate_f` while deriving the seed (`genesis.rs:131-151`); state decode validates it (`chain.rs:364-365`); snapshot construction/decode validates `F` and recomputes the certificate (`consensus_snapshot.rs:139-171,206-250,272-286`). Test-only genesis fallback is `#[cfg(test)]` (`chain.rs:823-828`). Immediate at genesis; immutable afterward. No production bypass found. | **PASS** |
| Validator election weight `w` | Snapshot type/domain is `u64`, `1..=u64::MAX`, additionally `w<=W`; reachable ordinary active validators must have at least `1_000_000_000` Spark (`primitives.rs:192-207`; `validator.rs:793-799`) | Frozen from active validator `stake_spark` at snapshot construction (`chain.rs:640-700`). Stake operations may alter live state, but ordinary changes enter a later epoch snapshot; slash revocation can only remove an entry in an H+1 intermediate snapshot (`chain.rs:931-996`). | 8-byte LE in canonical sorted snapshot entry (`consensus_snapshot.rs:83-112`); snapshot-root committed (`:310-332`); validator state is state-root committed. | Entry rejects zero and validates keys (`:68-80`); `evaluate` rejects zero/`w>W` (`sortition.rs:150-160`). Persisted snapshots run full validation. No direct caller-supplied weight reaches verified proposal election. | **PASS** |
| Total snapshot stake `W` | `u64`; `1..=u64::MAX` | Checked sum of all snapshot entries (`consensus_snapshot.rs:300-307`); recomputed by proposal production as defense in depth (`indra-consensus/src/proposer.rs:134-142`). | 8-byte LE snapshot field/root commitment (`consensus_snapshot.rs:254-268,310-332`). | Snapshot rejects empty, >200 entries, total overflow, and stored/recomputed mismatch (`:206-250`). No persisted-value trust bypass found. | **PASS** |
| Validator-count caps | Registry `MAX_VALIDATORS=1500`; active/snapshot cap phases 20/50/100/200, absolute 200 (`primitives.rs:20-26,233-273`) | Compile-time constants. Active set is deterministically ranked by self-stake then validator ID (`indra-state/src/validator.rs:778-815`). | Not serialized as parameters. Resulting canonical membership is snapshot-root/state-root committed. Snapshot list has `u32` LE length and decode cap 200 (`consensus_snapshot.rs:272-285`). | Registry insertion enforces 1500 (`validator.rs:726-760`); snapshot validation enforces 200 (`consensus_snapshot.rs:206-233`). Changes require a protocol binary/version change. | **PASS** |
| Epoch duration | `u64` constant `300` blocks (`primitives.rs:17-18`) | Compile-time, non-governable. Epoch boundaries rotate snapshots (`chain.rs:891-928`). | Not serialized separately; its effects appear in activation/source heights (`u64` LE) and snapshot roots. | Boundary creation requires nonzero exact multiple of 300 and fully applied state (`chain.rs:891-905`). A binary with a different constant would disagree without a version transition mechanism. | **PASS current version / OPEN transition** |
| Round representation and limits | Proposal/vote/lock round `u32`, `0..=u32::MAX`; `NO_POLC_ROUND=u32::MAX` only for PoLC field (`block.rs:84-85,165-170`) | Runtime state machine. Per-certificate jump is 8 (`driver.rs:43-47,1606-1616`). `MAX_ROUNDS_PER_HEIGHT=1024` is only a slot-index multiplier and explicitly not a retry cap (`primitives.rs:54-58`). | 4-byte LE in header/transcripts (`block.rs:221-264`; `proposal.rs:35-56`). Round is bound into VRF alpha and proposal authorization. | Decode accepts every `u32`. Timeout and restart use saturating increment (`driver.rs:887-894,2259-2265`). Thus `u32::MAX` cannot advance. No practical route to that many rounds was established, but the domain/terminal behavior is undefined. | **FINDING-CANDIDATE** |
| VRF suite | `VrfSuiteV1` encoded `u8`; sole legal value 1 = RFC 9381 ELL2 (`block.rs:35-57`) | Genesis/live snapshots hardcode suite 1 (`genesis.rs:419-439`; `chain.rs:679-688`); key registration carries and signs a suite discriminator (`staking.rs:213-227,726-740`). | One byte in snapshot entry and block header; both roots/header hash bind it. | Unknown values fail decode; proposal verification requires header and snapshot suite equality and specifically suite 1 (`proposal.rs:100-115`). Activation of a rotated key is next epoch. No alternate suite path found. | **PASS current version** |
| Sortition algorithm claim | `SortitionClaimV1` `u8`; sole value 1 | Producer always writes `PraosThreshold` (`producer.rs:113-145`). | One byte in block header, hence block hash/QC bound (`block.rs:59-80,221-264`). | Unknown value fails decode; verification/application accepts only current claim. No activation schedule exists. | **PASS current version / OPEN transition** |
| Snapshot version | `u8`, exactly 2 (`consensus_snapshot.rs:17-18,206-210`) | Constructor writes current constant; no mutation. | First snapshot byte and included in snapshot root (`:254-268,310-332`). | Decode calls `validate`; wrong version fails closed (`:272-286`). No dual decoder. | **PASS current version** |
| Proposal/block version | `ProtocolVersion(u16)`, block value exactly 2 (`primitives.rs:434-443,612-637`) | Producer emits `BLOCK_FORMAT_VERSION` (`producer.rs:111-126`). Proposal envelope has no second discriminator; it is interpreted through its block header. | 2-byte LE first header field (`block.rs:221-274`); complete header/block and hybrid envelope signature bind it (`block.rs:361-405`). | Header decode and state application reject other block versions (`block.rs:267-274`; `indra-state/src/apply.rs:4928`). No legacy block decoder. | **PASS current version** |
| VRF key activation delay | Operation `activation_epoch_id: u64`; must equal `epoch_for_height(current)+1` (`delegation.rs:425-440`) | Genesis keys activate at epoch 0. Rotation is a staking operation with VRF PoP; pending key is installed only into a snapshot whose boundary epoch has arrived (`delegation.rs:441-472`; `chain.rs:661-688`). | 8-byte LE in signed staking operation (`staking.rs:230-265,726-740,902-909`); pending/current key state and selected snapshot entry are committed. | Wrong epoch, malformed/reused key, invalid validator status, bad PoP/signature are rejected before state use. Activation is delayed to the next snapshot epoch, never mid-epoch. Slash snapshots copy governing entries and therefore do not prematurely activate pending keys (`chain.rs:931-985`). | **PASS** |
| Genesis entropy confirmation depth | Manifest `u32`; legal `>=100` (`genesis.rs:76-103`) | Genesis-only operator-selected floor. No governance/runtime mutation. | Canonical descriptor uses LE `u32`; descriptor+80-byte header are hashed into `genesis_entropy_record_hash` (`genesis.rs:93-128`), which is state-root/genesis-fingerprint committed (`state_root.rs:52-57`; `genesis.rs:395-411`). | Parser rejects `<100`. `indra-genesis verify-bitcoin-entropy` checks height/header/current tip using Bitcoin Core before assembly (`indra-cli/src/bin/genesis.rs:188-243`); consensus itself verifies the committed record format, not external chain truth. | **PASS with operational trust assumption** |
| Other entropy parameters | `scheme:u8=1`, network genesis hash 32 canonical bytes, announced height `u64`, header codec `u8=1`, extraction `u8=1`, source header exactly 80 bytes, reorg policy `u8=1` (`genesis.rs:73-115`) | Required genesis manifest; fixed forever. Seed format version is state `u8=1`, seed applicability height `u64` (`chain.rs:109-119,364-373`). | Descriptor fields use the stated one-byte widths and LE integers; header raw bytes; seed and record hash are state-root committed (`state_root.rs:44-60`). Seed transition transcript is `INDRA-ELECTION-SEED-v2` and binds chain ID, prior seed, height, immutable origin round/proposer/output, snapshot root (`proposal.rs:59-84`). | Unknown enum/version, malformed/noncanonical hex, shallow confirmations, and invalid persisted seed version fail closed (`genesis.rs:93-128,361-389`; `chain.rs:364-373`). No deadline fallback/window exists. | **PASS** |

## C. Extreme legal combinations

| Combination | Analysis | Classification |
|---|---|---|
| `F=2^63`, `W=u64::MAX`, `w=W` | `F` validation accepts the endpoint; snapshot total uses checked `u64`; Q768 uses `BigUint`; full stake produces the maximum legal `z`. The independent Phase 2/3 artifacts cover the mathematical endpoint and live width certificate. | **PASS** |
| `F=1`, `W=u64::MAX`, `w=1` | Smallest probability and stake fraction remain nonzero mathematical inputs; all scaling is integer/`BigUint`. The conservative threshold may be zero, meaning ineligibility, without arithmetic failure. | **PASS** |
| 200 validators with minimum reachable active stake | Each ordinary active entry has at least `1_000_000_000` Spark, so `W=200_000_000_000`; canonical ordering and checked sum hold. The lower-level snapshot type also safely admits synthetic positive weights down to 1. Production sortition tests exercise validator counts through 200 (`sortition.rs:223-230`). | **PASS** |
| 200 validators with individually large weights | Individually legal entries can be rejected together if their checked total exceeds `u64`; there is no saturating snapshot total. | **PASS fail-closed** |
| VRF rotation at epoch boundary plus slash-triggered snapshot | Normal rotation selects a pending key only when `activation<=snapshot_epoch`; slash snapshot filters the already-governing snapshot instead of rebuilding live state, so it cannot activate the key early. | **PASS** |
| Round near `u32::MAX` | Wire/transcript accepts it, jump checks saturate, and next-round timeout at max does not advance. | **FINDING-CANDIDATE PAR-02** |
| Suite/version boundary | Unknown suite, sortition claim, snapshot version, block version, and seed version fail closed. Mixed old/new binaries therefore reject rather than reinterpret, but no activation schedule permits a safe rolling transition. | **OPEN VER-01** |
| Maximum `F` plus maximum validator count and stake total | Q768 work is per proposal, independent of validator count once `(w,W)` is selected; candidate total recomputation is O(200) checked additions. No combined overflow path found. | **PASS** |

## D. Floating-point inventory

### D.1 Production call graph

```text
indra-node::vrf_authority_from_snapshot
  -> ProposerElection::from_snapshot
     -> ConsensusSnapshot::sortition_log_interval
indra-node::NodeEngine::{is_proposer,propose,repropose}
  -> indra-consensus::produce_block / compute_proposer_vrf
     -> indra-core::sortition::evaluate

remote proposal verification:
indra-core::types::proposal::verify_proposal
  -> ConsensusSnapshot::sortition_log_interval
  -> sortition::evaluate (current proposer and immutable entropy origin)
```

Sources: `indra-node/src/consensus_authority.rs:8-23`,
`indra-node/src/engine.rs:1186-1194,1249-1284,1287-1359`,
`indra-consensus/src/producer.rs:61-93`,
`indra-consensus/src/proposer.rs:58-92,120-146`, and
`indra-core/src/types/proposal.rs:87-213`.

### D.2 Source review

`sortition.rs` production code uses `u64`, `BigUint`, and `BigInt`; there are
no `f32`, `f64`, casts to floating point, `libm`, or floating intrinsics in
the transitive files above. The only `ln()`/`exp()` occurrence is the
`#[cfg(test)]` Rug/MPFR oracle (`sortition.rs:195-212`), not production.
Hash/VRF code consumes fixed byte strings and does not convert election
parameters to floating point.

**Source-level no-FP: PASS.**

### D.3 Current optimized binary review

Command:

```sh
cargo rustc -p indra-core --release --lib -- --emit=asm
```

Host/compiler: `aarch64-apple-darwin`, rustc 1.96.0, LLVM 22.1.2. The emitted
assembly was `target/release/deps/indra_core-35e22268ded5c210.s` (SHA-256
`48fa7ef6c048f7080aeb833abe63225853f870dc56173991d9459089494bedce`).
The exact sortition symbol region (`validate_f`, `certified_log`, `mul`,
`phi`, `ceil`, `evaluate`, and `priority`) contained none of `fadd`, `fsub`,
`fmul`, `fdiv`, `fcmp`, `fcsel`, `fsqrt`, `scvtf`, `ucvtf`, `frint`, `fmov`,
`.float`, or `.double`.

**Current-binary no-FP: PASS for this release build.** This does not prove
linked allocator/bignum code never uses FP for unrelated bookkeeping, but no
FP instruction occurs in the emitted sortition implementation itself.

**Universal-build no-FP: OPEN.** There is no defined build matrix, and no
release object inspection exists for the checked-in Linux targets or a pinned
compiler/CPU-feature set. Source structure strongly limits the risk, but the
requested universal statement needs a finite permitted matrix first.

## E. Version-transition inventory

| Discriminator/transcript | Current value and binding | Transition behavior | Status |
|---|---|---|---|
| VRF suite | `VrfSuiteV1=1`; snapshot entry + block header | Unknown rejected; no height/epoch activation map. | **PASS current / OPEN transition** |
| Sortition claim | `PraosThreshold=1`; block header | Unknown rejected; no second algorithm. | **PASS current / OPEN transition** |
| Snapshot format | `CONSENSUS_SNAPSHOT_FORMAT_VERSION=2`; snapshot root | Wrong version rejected. | **PASS current / OPEN transition** |
| Block/proposal format | `BLOCK_FORMAT_VERSION=2`; header hash and proposal signature | Wrong version rejected; envelope relies on block discriminator. | **PASS current / OPEN transition** |
| Entropy record descriptor | scheme/header codec/extraction/reorg all `1`; genesis record hash | Unknown rejected at genesis; no post-genesis change. | **PASS** |
| Election-seed state version | `1`; state root | Wrong persisted version rejected (`chain.rs:368-373`). | **PASS current / OPEN transition** |
| Proposer alpha transcript | `INDRA-PROPOSER-SORTITION-v2`; chain ID, full seed, height, `u32` round, snapshot root, validator ID (`proposal.rs:34-56`) | No discriminator separate from binary/block version. | **OPEN transition** |
| Seed evolution transcript | `INDRA-ELECTION-SEED-v2` (`proposal.rs:59-84`) | No scheduled transcript-version selection. | **OPEN transition** |
| Proposal authorization transcript | `INDRA-PROPOSAL-AUTH-v1`; full canonical block (`block.rs:369-388`) | No scheduled transcript-version selection. | **OPEN transition** |
| Snapshot-root domain | `INDRA-CONSENSUS-SNAPSHOT-v1` despite wire format 2 (`consensus_snapshot.rs:17-20`) | Constant is unambiguous today but has no activation registry. | **OPEN transition** |

No accepted discriminator has aliases, so two current binaries cannot decode
the same byte as two current algorithms. The unresolved risk is deployment:
old and future binaries would reject one another's objects or derive different
transcripts unless an activation boundary is explicitly introduced. The
archived determinism guidance reaches the same conclusion for a future format
(`docs/archive/DETERMINISM_AUDIT.md:50`).

## Final classification

- **PASS:** current parameter domains, canonical serialization, snapshot
  commitment, fail-closed persisted decoding, one-epoch VRF activation, current
  source-level no-FP, and current Apple-arm64 release sortition object.
- **OPEN:** permitted consensus build matrix and all future version-transition
  activation rules.
- **FINDING-CANDIDATE:** terminal `u32` round liveness behavior; Windows support
  documentation disagrees with available release/install infrastructure.

No production code was modified.
