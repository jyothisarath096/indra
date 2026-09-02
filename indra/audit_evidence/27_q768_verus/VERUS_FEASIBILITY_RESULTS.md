# Q768 fixed-limb shadow: Verus feasibility and first closure attempt

Date: 2026-09-01

Repository revision inspected: `dd39d5e4` plus the pre-existing untracked
workspace state. No production source was changed.

## Result in one paragraph

The existing differential-tested shadow cannot be fully verified by merely
adding contracts and loop invariants around its unchanged executable bodies.
Verus does provide an attribute-based migration path for ordinary Rust, and it
can model fixed arrays, fixed-count loops, mathematical integers, division, and
the invariants this algorithm needs. An exact-body probe nevertheless stopped
before any Q768 property reached SMT: Verus ignores the shadow's ordinary Rust
types/constants until they are made Verus-aware, and, decisively, Verus
`0.2026.08.30.b432e82` rejects the shadow's real
`u64::overflowing_add` operations as unsupported. Accepting the suggested
`assume_specification` would trust the semantics of the carry primitive and
would not close the requested arithmetic property. A meaningful full attempt
therefore requires a Verus-compatible fork/rewrite of at least the carry/borrow
primitives (and likely further local compatibility edits), followed by a fresh
production differential run. That decision was not made implicitly here. All
five full-path properties remain **open due to a structural frontend blocker**;
none was disproved, timed out, or verified. Topic 26 was restored byte-for-byte
after the probe.

## Step 0: exact artifact and structural answer

### Artifact under test

The target is the Topic 26 `no_std` crate at
`audit_evidence/26_q768_shadow_implementation/`, not a new arithmetic model.
Its current source SHA-256 is:

```text
a4c769a51fb2ff71c133b57225272f4109930e741d633660e37b6a69c22d612c  src/lib.rs
```

That is the same hash recorded by `DIFFERENTIAL_TEST_RESULTS.md` for the code
that agreed with production in 461,126 cases and 8,518,704 stage comparisons.

The relevant unchanged executable structure is:

- `Uint([u64; 16])` and `Wide([u64; 32])` at `src/lib.rs:30` and
  `src/lib.rs:327`;
- checked addition and subtraction/carry code at `src/lib.rs:73-113`;
- 16-by-16 schoolbook multiplication at `src/lib.rs:170-202`;
- scalar and fixed-limb division at `src/lib.rs:204-284` and
  `src/lib.rs:404-510`;
- the exact 256-round log recurrence at `src/lib.rs:604-643`;
- the exact 128/129-round phi recurrence at `src/lib.rs:645-673`;
- stake scaling, width checking, threshold conversion, and eligibility at
  `src/lib.rs:755-785`.

### Can it be annotated in place?

**At the syntax level, partially yes. At the level required to close the five
properties while preserving every executable body, no.**

Verus documents `#[verus_spec]` as its incremental, attribute-based route for
adding specifications to existing Rust, and permits a loop-level
`#[verus_spec(invariant ...)]`. This avoids putting every executable function
inside a `verus!` block and can leave normal executable statements unchanged.
See the official [attribute syntax documentation](https://verus-lang.github.io/verus/guide/exec_attr.html)
and [loop-invariant documentation](https://verus-lang.github.io/verus/guide/invariants.html).

The exact-body probe in `EXACT_BODY_ANNOTATION_PROBE.patch` added only:

- the matching released `vstd` dependency and Verus Cargo metadata;
- the configuration required for loop attributes;
- `#[verus_spec]` on the existing `Uint::is_zero` and
  `Uint::checked_add` bodies;
- index-bound invariants on their unchanged loops.

Normal `cargo check` and all six ordinary tests passed with this probe applied.
Verus then reported four frontend errors:

1. `Uint` was ignored because its ordinary struct declaration was outside a
   `verus!` block;
2. `VALUE_LIMBS` was likewise ignored;
3. `ArithmeticError` was ignored;
4. `u64::overflowing_add` was unsupported.

The first three are migration work: move declarations into Verus-aware syntax
or provide external type declarations. They do not by themselves require a
different arithmetic algorithm. The fourth is the decisive exact-body blocker.
The diagnostic suggested:

```text
pub assume_specification [core::num::<impl u64>::overflowing_add]
    (_0: u64, _1: u64) -> (u64, bool);
```

That would make the central carry semantics an assumption rather than a
verified fact. This task deliberately did not do that. The same shadow also
uses `overflowing_sub` for borrow at `src/lib.rs:107-108` and another
`overflowing_add` in `Wide::add_one` at `src/lib.rs:435`, so this is not one
dead or irrelevant call.

`EXACT_BODY_PROBE_OUTPUT.txt` preserves the root-crate diagnostic. No
`external_body`, project-defined `assume_specification`, `assume`, or admitted
lemma was accepted.

### Rewrite/evidence-chain decision

A useful Verus attempt therefore needs a Verus-compatible version of the
shadow, even if the rewrite is localized rather than wholesale. A plausible
first change would replace the unsupported `overflowing_add/sub` operations
with supported checked operations or explicitly modeled `u128` carry/borrow
logic. That changes executable source and must be reviewed as a real rewrite,
not described as a ghost-only annotation.

Consequently, the 461,126-case Topic 26 differential result does not
automatically transfer to that future version. The complete differential
corpus, including every named intermediate stage, must be rerun after the
Verus-compatible implementation stabilizes. This is a human decision point:
authorize a second verification-only implementation plus a renewed empirical
bridge, or retain the exact shadow and accept that current Verus cannot verify
its bodies without trusted primitive specifications.

This pass did neither silently.

## Can Verus express the required proof structure?

Yes, subject to the implementation-compatibility issue above.

### Fixed limbs and loop invariants

The released `vstd` defines an array view from `[T; N]` to `Seq<T>` and index
lemmas (`vstd/array.rs:11-59`). Thus `[u64; 16]`, `[u64; 32]`, and their
per-prefix loop invariants are expressible. Verus loop contracts support the
fixed 256-round log loop, parameterized 128/129-round phi loop, nested
schoolbook-multiplication loops, and 2048-step long-division loop. Fixed counts
are favorable here: inductive invariants summarize one iteration instead of
materializing all rounds as Kani/CBMC did.

### Arithmetic primitive specifications

Verus specification integers (`int`/`nat`) provide the unbounded mathematical
model needed for a limb-array value function. The released `vstd` has:

- specifications for primitive `checked_add`, `checked_sub`, and
  `checked_mul` (`vstd/std_specs/num.rs:138-175`);
- array and slice views plus a `copy_from_slice` specification
  (`vstd/std_specs/slice.rs:362-368`);
- integer quotient/remainder definitions and a substantial division lemma
  library (`vstd/arithmetic/div_mod.rs`, beginning at lines 20-46 and 81-180);
- bit-vector, nonlinear-arithmetic, and integer-ring proof modes suitable for
  shifts, truncating casts, and schoolbook-product algebra.

Therefore contracts for fixed-limb checked add/sub, multiplication, floor
division, and ceiling division can be stated precisely. They still need
project-specific inductive proofs. In particular, the 16-by-16 accumulator
invariant and the restoring long-division quotient/remainder invariant do not
come for free from these libraries.

### Q768 recurrence invariants

Verus can state the required recurrence relations and bounds. Topic 25 supplies
the mathematical targets:

- `phi_rounding_width 128 = 254`;
- `phi_rounding_width 129 = 256`;
- the 1026-unit stake-scaled endpoint uncertainty;
- `2^640 <= zlo` on every admissible input;
- final integer width `<= 1537`.

Those Rocq theorems are guidance, not imported Verus facts. To use them without
adding assumptions, the Verus proof must independently connect the fixed-limb
exec state to mathematical `nat` values and establish the corresponding
per-iteration integer bounds. Verus is capable of expressing that bridge; this
pass did not establish it.

## Why the first target was foundational arithmetic

The first attempt targeted no-panic/no-arithmetic-error support at
`Uint::checked_add`, rather than guessing that either phi or log would be
easiest. Every one of the five properties depends on a sound fixed-limb value
model and carry/borrow contracts. Testing the earliest real primitive exposed
the unsupported operation before weeks were spent writing downstream
invariants against an unverifiable body.

Re-proving only the isolated VRF byte comparator was not chosen as the first
target: Kani already exhaustively closed that isolated property, while the
remaining requested property is explicitly the *full-path* comparison after a
symbolically computed threshold. Repeating the isolated result in Verus would
not unblock that path.

## Exact status of the five requested properties

| Property | Status in this pass | Exact reason |
|---|---|---|
| Interval width `<= 1537` | **Open — structurally blocked** | No verified fixed-limb value/arithmetic layer exists for the exact body, so the Rocq budgets cannot yet be attached to the executable recurrence. |
| No panic, overflow, or arithmetic error on the full admissible domain | **Open — structurally blocked** | The first real carry primitive, `u64::overflowing_add`, is unsupported; trusting an assumed spec was rejected. |
| Ordering (`lo <= hi`) | **Open — structurally blocked** | Depends on verified outward add/mul/div and signed phi contracts, none of which can be composed before the primitive layer is migrated. |
| Stake-to-threshold monotonicity | **Open — structurally blocked** | Requires two full executions plus monotonic floor/ceil, phi, clamp, and conversion lemmas. The executable graph is not yet Verus-verifiable. |
| Full-path VRF-output comparison correctness | **Open — structurally blocked** | The isolated comparator is already Kani-verified, but the full property requires successful exact-body `evaluate`; that call graph is blocked at the arithmetic layer. |

These outcomes are distinct from a failed proof or timeout. No SMT obligation
for any end property was generated, so there is no counterexample and no basis
for weakening the domain.

## Toolchain and commands

Official release:

```text
Verus 0.2026.08.30.b432e82
commit b432e82fed7e05090fd53b5e5fc39020f725aabe
platform macos_aarch64
required Rust toolchain 1.97.1-aarch64-apple-darwin
vstd 0.0.0-2026-08-30-0159
release archive SHA-256 4eacbfeee673356136b56ad94b4c132e7bbadeb7fcbbcee3231b0a1c1327861d
```

Release source: [Verus 0.2026.08.30.b432e82](https://github.com/verus-lang/verus/releases/tag/release/0.2026.08.30.b432e82).

Probe commands, in a disposable copy or worktree:

```sh
patch -p1 < audit_evidence/27_q768_verus/EXACT_BODY_ANNOTATION_PROBE.patch
cd audit_evidence/26_q768_shadow_implementation
cargo generate-lockfile
cargo check
cargo test
PATH=/path/to/verus-arm64-macos:$PATH cargo verus focus -- --no-cheating
```

`cargo check`: pass.  
`cargo test`: 6 passed, 0 failed.  
Root-only Verus run: frontend failure shown in
`EXACT_BODY_PROBE_OUTPUT.txt`.

An initial `cargo verus verify -- --no-cheating` forwarded the option into
`vstd` and rejected `vstd`'s own admitted/axiomatized standard-library
specifications. The reported root result therefore uses `cargo verus focus`,
which checks the project crate with `--no-cheating` while treating the released
`vstd` artifact as part of Verus's declared trusted base. This distinction is
important: even a future successful Verus result would rely on Verus, Rust
lowering, Z3, and the relevant `vstd` specifications.

## Guarantee category

No new deductive guarantee was obtained in this pass. Had a property closed,
the correct characterization would be: SMT-backed deductive verification of
the annotated executable Rust subset and its specifications by the Verus
toolchain. That is neither Rocq kernel checking nor Kani/CBMC exhaustive bounded
model checking.

The current result is a tool-supported feasibility/blocker finding only.

## Recommendation and estimate

Do not add an assumed specification for `overflowing_add/sub` merely to make
verification proceed. It would place exactly the carry/borrow behavior under
review into the trusted base.

If a human authorizes the Verus-native path, keep it in a separate Topic 27
crate so Topic 26 remains the immutable differential-tested baseline. Suggested
sequence:

1. replace unsupported carry/borrow operations with a Verus-supported,
   explicitly specified implementation;
2. model `[u64; 16]` and `[u64; 32]` as mathematical natural numbers;
3. close add/sub, shift, multiplication, and directed division contracts;
4. rerun the full Topic 26 differential harness against production and compare
   all named stages;
5. only then build the 256/128/129 recurrence invariants and the five end
   properties.

This is not a same-day annotation exercise. A reasonable planning range for an
engineer already experienced with Verus is **6-10 engineer-weeks**: roughly
1-2 weeks for the compatible primitive layer and value model, 2-3 weeks for
schoolbook multiplication and directed long division, and 3-5 weeks for the
recurrence/budget/monotonicity composition. The estimate may move after the
primitive rewrite reveals whether additional exact-body Rust constructs are
unsupported. The fresh differential computation itself was about 14 minutes in
Topic 26; review and discrepancy analysis, if any, are the meaningful cost.

## Restoration and scope boundary

The probe changes were removed using explicit edits, and the dependency-free
lockfile was regenerated. Final hashes are:

```text
fffa7c96814f822b10def92ea1ba851b76953cf8d8bb645d69579134481e0d3d  Cargo.lock
6afbc11200cf2a33149e608cb739f9d0364294084391c3c855c8b93d43b6fcc0  Cargo.toml
a4c769a51fb2ff71c133b57225272f4109930e741d633660e37b6a69c22d612c  src/lib.rs
```

`git diff --exit-code` against all three Topic 26 files succeeded. No
production file, Topic 25 theorem, Topic 26 arithmetic function, or existing
differential artifact remains modified.

Even a future complete Verus proof would establish properties of the
Verus-compatible fixed-limb shadow. Its relationship to production's dynamic
`num_bigint` implementation would remain the empirical differential bridge
unless production adopts the verified implementation or a separate deductive
conformance proof is completed. The separate R1 bit-identical cross-platform
determinism question would also remain open.
