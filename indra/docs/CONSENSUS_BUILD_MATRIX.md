# Consensus Build Matrix

Status: **normative for block format version 2 validator releases**.

The machine-readable authority for this document is
[`ci/consensus-build-matrix.toml`](../ci/consensus-build-matrix.toml). CI runs
`scripts/check_consensus_build_policy.py` to prevent the toolchain, release
profile, lockfile identity, target list, and this document from silently
diverging.

## 1. Permitted validator release targets

Only these target triples are consensus-qualified:

| Platform | Rust target triple | Link/runtime policy |
|---|---|---|
| macOS ARM64 | `aarch64-apple-darwin` | Platform-default linkage; deployment floor macOS 12.0. |
| Linux x86-64 | `x86_64-unknown-linux-musl` | Static musl release. |
| Linux AArch64 | `aarch64-unknown-linux-musl` | Static musl release. |

Every other platform or target triple is **not consensus-qualified**, even if
the workspace compiles or tests there. In particular, Windows is not in the
matrix. Wallet/client portability does not qualify an OS to run a validator.

### Existing-binary ABI determination and provenance limit

The checked-in Linux node binaries are static ELF files with no `PT_INTERP`,
no dynamic section, and no GLIBC symbol/version dependency. Their `.comment`
sections record the same Rust compiler and Homebrew clang/LLD provenance. In
combination with Rust's released static Linux targets and the repository's
`linux-x86_64`/`linux-arm64` release labels, this identifies the existing
release ABI as static musl rather than the dynamically linked GNU ABI. The
repository contains no historical build command, Cargo build metadata, or
embedded target-triple string, so a stripped ELF cannot prove the literal
triple argument originally passed to rustc or exclude an equivalent custom
target JSON. That provenance fact is irrecoverable from the artifact alone;
claiming otherwise would be guessing.

The normative built-in triples selected here are therefore the exact Rust
targets that reproduce the established architectures and static-musl ABI:
`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`. Future artifacts
must record the literal target so this ambiguity cannot recur. The evidence
and existing artifact digests are:

| Artifact | SHA-256 | Recorded provenance |
|---|---|---|
| `releases/linux-x86_64/indra-node` | `f0bf2a97203d05dc8cfdc8da33770843bd6b67a340d16cc8283ded26e5b6e163` | static ELF x86-64; rustc 1.93.1; clang/LLD 21.1.8 |
| `releases/linux-arm64/indra-node` | `827ab1bf8491727cbaac3d88c31824b79dc130aac1a2dce965e567ddf9653c7e` | static ELF AArch64; rustc 1.93.1; clang/LLD 21.1.8; GCC 9.4 support object |
| `releases/macos-arm64/indra-node` | `edca9319466a06debecde17ce1744d8b9822f76feecca4f36d22667b1947fc78` | Mach-O arm64; minimum OS 11.0 in the historical artifact |

The macOS policy floor is 12.0, matching the operator requirement; the older
Mach-O load-command minimum does not broaden the supported deployment matrix.

## 2. Pinned toolchain

Validator release builds MUST use:

```text
rustc 1.93.1 (01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf)
LLVM 21.1.8
cargo 1.93.1 (083ac5135f967fd9dc906ab057a2315861c7a80d, 2025-12-15)
```

`rust-toolchain.toml` enforces Rust 1.93.1. A compiler with the same semantic
version but a different commit, a patched downstream compiler, or another LLVM
code generator is not qualified until the Layer-2 determinism checks are rerun
and this matrix is deliberately revised.

## 3. Normative build command and profile

For the selected matrix target, the release command is:

```sh
cargo build --workspace --release --locked --target <target>
```

The workspace's `[profile.release]` is normative:

```toml
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
```

No profile override is permitted. Dev, test, bench, incremental, sanitizer,
coverage, PGO, and locally patched profiles are not validator release builds.
Builds MUST use the committed `Cargo.lock` via `--locked`. The machine matrix
records its reviewed SHA-256; a lockfile change requires dependency review and
an intentional digest update.

## 4. Features and build flags

- Use the workspace's default feature resolution exactly.
- No local workspace feature may be enabled. In particular,
  `indra-consensus/test-utils` is prohibited in releases.
- `--all-features`, `--no-default-features`, package-local feature additions,
  `[patch]`, and dependency substitution are prohibited unless a new matrix is
  reviewed.
- `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, and target-specific rustflags MUST be
  empty for consensus release compilation.
- Use the Rust target's default CPU and target features. `target-cpu=native`,
  explicit `+feature`/`-feature` changes, and host-feature inheritance are
  prohibited.
- Linker selection and sysroots must implement the target ABI above and must
  not change Rust/LLVM code-generation flags.

These restrictions make the CPU baseline portable inside each target rather
than silently specializing a validator binary to the release host.

## 5. Runtime CPU dispatch

Runtime CPU dispatch is permitted only inside a dependency or primitive when
all selected implementations are specified to return byte-identical results
for every input. Examples include SHA acceleration selected by `cpufeatures`.
Dispatch may affect timing, never consensus output, parsing, arithmetic,
rounding, or error classification.

Q768/sortition has no permitted floating-point or CPU-specific alternate
algorithm. A new dispatched consensus implementation requires explicit
cross-backend equivalence tests and matrix review before release.

## 6. Qualification and changes

A release is consensus-qualified only if all of the following hold:

1. source revision and `Cargo.lock` are reviewed;
2. `python3 scripts/check_consensus_build_policy.py` passes;
3. the pinned compiler and exact target are used;
4. the normative release command/profile/features/flags are used;
5. workspace tests and release build pass;
6. release artifacts record source revision, target, compiler, lockfile digest,
   and artifact SHA-256.

Adding a target, compiler, CPU policy, feature, or flag is a consensus build
policy change. It does not by itself change wire bytes, but it is forbidden
until determinism, no-floating-point object inspection, and consensus tests are
repeated for the new matrix member.

## 7. Compatibility impact

This policy does not modify Q768, VRF, proposal, snapshot, state, or consensus
behavior. It does not rewrite the existing checked-in binaries. It narrows
future qualified builds to the toolchain already embedded in the Linux release
artifacts and makes previously implicit target/flag requirements enforceable.

Developers currently using another Rust version can still do non-release work,
but repository-local Cargo commands select 1.93.1. Any dependency that no
longer builds with the audited compiler is a release blocker; using a newer
compiler silently is not an allowed workaround.
