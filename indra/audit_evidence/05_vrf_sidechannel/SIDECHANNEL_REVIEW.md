# VRF proving-path static side-channel review

Date: 2026-08-18  
Scope: `indra-crypto/src/vrf.rs::{expand,VrfKeypair::from_seed,nonce,vrf_prove}`  
Result: **PASS**, with the residual assumptions listed below. No production code
was changed by this review.

## Environment and resolved dependencies

- Host/target: `aarch64-apple-darwin`; Rust `1.96.0` (`ac68faa20`).
- Dalek: crates.io `curve25519-dalek 5.0.0`, checksum
  `b5eed333089e2e1c1ac8c6c0398e5e2497b4c9926ca6d0365ed1e099afa5bc23`.
- Dalek features active for the v5 package: `alloc`, `digest`, `group`,
  `legacy_compatibility`, `rand_core`, `zeroize`. `precomputed-tables` is not
  active.
- SHA-512 expansion/nonce implementation: `sha2 0.10.9`. Its `asm` and
  `force-soft*` features are not active.
- Dalek's build selection makes SIMD available only for x86_64/64-bit targets.
  Therefore this arm64 target selects `curve25519_dalek_backend="serial"` and
  `curve25519_dalek_bits="64"`. On eligible x86_64 builds, dispatch chooses
  AVX2/AVX-512/serial from CPU features, not from secret data.

Reproduce the feature inventory with:

```sh
cargo tree -p indra-crypto -e features -i curve25519-dalek@5.0.0
```

## Taint trace and classification

| Operation | Taint and control/memory behavior | Result |
|---|---|---|
| `expand`: SHA-512(seed) | Secret input has fixed 32-byte length. SHA padding, block count, and round loops therefore do not depend on seed contents. Compression contains fixed-round arithmetic and fixed-index loads. | PASS |
| `expand`: split/clamp | Fixed slices and fixed byte indices; masking has no branch. Dalek `Scalar::from_bits` only masks the high bit. | PASS |
| `from_seed`: `x * B` | `mul_base` uses ordinary variable-base multiplication because precomputed tables are disabled. The selected serial implementation always performs 64 radix-16 digits and 63 four-doubling rounds. | PASS |
| `nonce`: SHA-512(prefix || H) | Prefix is secret; `H` is public. Input length is always exactly 64 bytes. SHA execution length is content-independent. | PASS |
| `nonce`: wide reduction to `k` | `from_bytes_mod_order_wide` uses fixed-limb Montgomery operations with no secret-selected loops or branches. | PASS |
| `vrf_prove`: `Gamma = x*H` | Ordinary scalar-point multiplication reaches the same constant-time variable-base implementation. Its table scan visits all eight entries and uses `subtle::ct_eq` plus conditional assignment, not a secret index. | PASS |
| `vrf_prove`: `U = k*B`, `V = k*H` | Same constant-time scalar multiplication paths as above. Loop counts and table traversal are fixed. | PASS |
| `vrf_prove`: `s = k + c*x` | `c` is public. Scalar multiply is a fixed 5x5 limb product and fixed Montgomery reduction; addition/subtraction uses fixed five-limb loops and conditional selection. | PASS |
| Proof assembly/output | Gamma, challenge, `s`, and beta are public by the audit model. Allocation size and copies are fixed by the 80/64-byte formats. | PASS |
| Zeroization | Secret expansion buffers, prefix, nonce buffers, `x`, and `k` are explicitly wiped. This is lifetime hygiene rather than a timing property. | PASS |

No seed-derived value controls an application-level branch, loop bound,
allocation size, or direct memory index in INDRA's proving path.

## Exact dependency source inspected

Paths below are relative to the unpacked crates.io
`curve25519-dalek-5.0.0` source:

- `build.rs:35-115`: 32/64-bit selection and serial/SIMD/AVX-512 selection.
- `src/edwards.rs:885-928`: scalar multiplication dispatch and `mul_base`;
  confirms no-precomputed builds delegate to ordinary multiplication.
- `src/backend.rs:45-75,253-275`: runtime backend selection and separation of
  constant-time `variable_base_mul` from `vartime_double_base_mul`.
- `src/backend/serial/scalar_mul/variable_base.rs:9-48`: fixed 64-digit
  constant-time variable-base algorithm.
- `src/backend/vector/scalar_mul/variable_base.rs:1-43`: SIMD counterpart;
  fixed 64 iterations and the same lookup abstraction.
- `src/window.rs:34-76`: full-table scan, constant-time equality,
  conditional assignment, and conditional negation.
- `src/scalar.rs:232-278`: wide reduction and `from_bits` construction.
- `src/scalar.rs:309-344`: scalar multiply/add API dispatch.
- `src/scalar.rs:1009-1050`: fixed radix-16 decomposition.
- `src/backend/serial/u64/scalar.rs:160-305`: fixed-limb add, subtract,
  multiplication, and Montgomery reduction used by `c*x` and `k+c*x`.

Paths inspected in crates.io `sha2-0.10.9`:

- `src/sha512.rs:1-45`: target/feature backend selection.
- `src/core_api.rs:95-142`: block update and length-based finalization.
- `src/sha512/soft.rs:203-215`: fixed per-block traversal into the SHA-512
  compression rounds. On this arm64 build, absence of `asm` selects this path.

INDRA call sites inspected:

- `indra-crypto/src/vrf.rs:34-48`: `expand`.
- `indra-crypto/src/vrf.rs:50-62`: `VrfKeypair::from_seed`.
- `indra-crypto/src/vrf.rs:88-100`: `nonce`.
- `indra-crypto/src/vrf.rs:128-148`: `vrf_prove`.
- `indra-crypto/src/vrf.rs:180`: the sole `vartime_*` call, confined to
  `vrf_verify`, where its scalars and points are parsed public proof/key data.

## Comparisons and backend notes

Dalek's radix lookup performs comparisons involving secret scalar digits, but
they are constant-time `ct_eq` operations followed by conditional assignment;
the table is scanned linearly. Debug builds also contain range
`debug_assert!` comparisons on secret digits (`window.rs:55-56`) and on a
scalar's high byte (`scalar.rs:1020`). For every valid `Scalar` these
conditions are invariants and therefore have the same successful outcome for
all inputs; they are removed in optimized release builds. They are not a
variable-outcome secret branch in this path, but are recorded here because the
source-level operands are secret-derived.

On x86_64, Dalek's variable-base SIMD implementation repeats the same fixed
radix-16 schedule and constant-time lookup abstraction. CPU-feature dispatch
is process/hardware-dependent and occurs independently of keys. Scalar
addition and multiplication remain in the serial fixed-limb implementation.

## Residual assumptions / OPEN items

These are limitations of static source review, not observed defects:

1. **Compiler preservation:** the review assumes Rust/LLVM does not transform
   `subtle` conditional operations or fixed-limb arithmetic into
   secret-dependent control flow. Assembly-level validation per release target
   is outside this artifact.
2. **Microarchitecture:** fixed instruction/control flow does not prove absence
   of data-dependent instruction latency, speculative effects, cache behavior
   below the source abstraction, power leakage, or EM leakage.
3. **Alternate targets:** arm64 serial and the x86 SIMD source/dispatch were
   reviewed. Other targets, explicit `curve25519_dalek_backend` overrides, and
   future compiler/dependency versions require re-review.
4. **SHA implementation contract:** message lengths are fixed for both secret
   hashes, so public length-dependent padding and backend dispatch are safe.
   This review assumes the selected SHA-512 compression instructions are
   content-independent at the relevant threat-model level.
5. **Public-after-derivation model:** this review follows the requested model
   that H, Gamma, U/V, challenge, and `s` are public. It does not attempt a
   higher-order leakage analysis correlating those public values with power or
   fault traces during their computation.

## Conclusion

No concrete secret-dependent variable-time behavior was found in
`VrfKeypair::from_seed` or `vrf_prove`. All secret scalar multiplications use
Dalek's constant-time variable-base path; scalar response arithmetic is
fixed-limb; secret SHA-512 inputs have fixed lengths; and `vartime_*` is used
only by verification over public data. Classification: **PASS**, subject to
the explicitly OPEN compiler, target, and microarchitectural assumptions.
