# First Kani attempt against production Q768 sortition

Date: 2026-08-30

## Outcome

The Kani toolchain works, and all five requested harnesses compile and are
discoverable. No real Q768 property completed bounded model checking. The
smallest real harness exhausted practical model-construction capacity inside
`num-bigint` before SAT solving; it produced neither a verification result nor a
counterexample. This is an inconclusive resource/representation result, not a
disproof.

Nothing in this report is a kernel-checked theorem-prover proof or third-party
certification. A successful Kani result, if obtained later, should be described
as exhaustive bit-precise verification over its declared finite state space via
bounded model checking.

## Step 0: feasibility facts

### Representation

The shipped implementation is not a fixed `[u64; 12]` Q768 representation.
`indra-core/src/sortition.rs:3` imports `num_bigint::{BigInt, BigUint}`, the
private arithmetic interval stores two `BigUint` values at lines 31-35, and the
public certificate stores two `BigUint` values at lines 57-64. Intermediates are
also dynamically sized `BigUint`/`BigInt` values.

The resolved dependency is `num-bigint 0.4.8`. Its source defines `BigUint` as
`data: BigDigits` (`num-bigint-0.4.8/src/biguint.rs:45-48`); `BigDigits` is the
crate's heap-backed digit collection. The Kani trace concretely entered
`alloc::vec::Vec<u64>` growth while modeling this representation.

The snapshot wire form is fixed-width `[u8; 128]` at
`indra-core/src/types/consensus_snapshot.rs:129-132`, but it is decoded into
dynamic `BigUint` before sortition (`consensus_snapshot.rs:191-203`). That fixed
wire form therefore does not make the arithmetic fixed-size.

### Loop termination

There is no convergence-based loop:

* `certified_log` uses `for n in 0..256u64`, exactly 256 iterations
  (`indra-core/src/sortition.rs:100-127`).
* `phi` uses `for k in 1..=terms` (`sortition.rs:129-163`). Production calls use
  the literal counts 128 and 129 (`sortition.rs:181-182`).

No separate numerical-convergence bound is needed. The difficulty is expansion
of fixed loops over dynamically allocated arbitrary-precision operations.

## Step 1: toolchain smoke test

Installed and used:

* `kani-verifier 0.67.0`
* `cargo-kani 0.67.0`
* CBMC 6.8.0, arm64 macOS
* Kani-pinned `nightly-2025-11-21-aarch64-apple-darwin`

An isolated symbolic `u8` wrapping-addition commutativity harness completed:
one harness verified successfully, zero failures, in 0.666098 seconds of
reported verification time. This establishes that the local Kani/CBMC pipeline
works; it says nothing about Q768.

## Step 2: real harnesses

The source is `src/lib.rs`. Every harness calls the shipped public
`indra_core::sortition::{certified_log, evaluate}` functions. It contains no
Q768 reimplementation or reduced-precision stand-in. `cargo kani list` finds all
five `#[kani::proof]` functions:

1. `q768_runtime_certificate_width_is_strictly_below_2_pow_24`
2. `q768_admissible_domain_has_no_panic_or_arithmetic_error`
3. `certified_log_interval_is_ordered`
4. `stake_to_sigma_conversion_is_monotone`
5. `vrf_big_endian_conversion_matches_eligibility_comparison`

The shared symbolic domain uses explicit assumptions:

* `0 < f <= MAX_F`;
* `total_stake > 0`;
* `validator_stake > 0`;
* `validator_stake <= total_stake`.

The width harness deliberately checks the requested strict inequality
`interval_width < 2^24`. Production rejects only `width > 2^24`
(`sortition.rs:186-190`), so equality is not ruled out merely by inspecting the
runtime guard. Kani did not reach this assertion.

The stake-conversion harness checks the observable consequence of the shipped
integer-to-ratio conversion: increasing positive stake at fixed total must not
decrease the returned threshold. The output-conversion harness checks the
shipped big-endian 512-bit output classification against the returned threshold
and checks that the threshold is at most 512 bits. Private intermediate `zl` and
`zh` values cannot be inspected from a verification-only external crate without
changing production visibility; no such change was made.

## Step 3: actual verification results

| Harness | Result | Meaning |
|---|---|---|
| `certified_log_interval_is_ordered` | **Inconclusive: stopped during GOTO model generation** | No SAT solve, success, or counterexample. Dynamic `Vec<u64>` allocation and `num-bigint` arithmetic loops dominated expansion; an internal subtraction loop had passed 200 unwind iterations when stopped. |
| strict runtime width | **Not run past compiled/discovered state** | It necessarily traverses the same blocked `certified_log` path and then adds both `phi` computations. Not verified and not disproved. |
| no panic/arithmetic error | **Not run past compiled/discovered state** | Same shared blocker. Kani also warned that the compiled dependency graph contains one `caller_location` and two foreign-function constructs; reachability was not resolved because model generation did not finish. |
| stake-to-sigma monotonicity | **Not run past compiled/discovered state** | Same blocker, plus two complete `evaluate` calls. Not verified and not disproved. |
| VRF-output conversion | **Inconclusive: CBMC timeout during GOTO model generation** | A second run used Kani's 20-second per-harness timeout. It timed out while expanding the same dynamic arithmetic, before SAT solving. Not verified and not disproved. |

No artificial restriction to a small `f`, stake, total, limb count, or reduced
iteration count was introduced. Such a run could be useful engineering evidence,
but it would not answer the requested full-domain properties and is therefore
not reported as verification.

## Production precondition trace

There is one non-test Rust call to `evaluate`, in
`indra-consensus/src/proposer.rs:137-142`.

The production chain is:

1. `ConsensusDriver::proposer_election_for_height` resolves a governing snapshot
   and passes it to `vrf_authority_from_snapshot`
   (`indra-node/src/driver.rs:774-788`).
2. That function calls `ProposerElection::from_snapshot`
   (`indra-node/src/consensus_authority.rs:8-23`).
3. `from_snapshot` obtains candidates only from snapshot entries and copies each
   validated `consensus_weight_spark` (`indra-consensus/src/proposer.rs:58-95`).
4. Snapshot entry validation rejects zero weight
   (`indra-core/src/types/consensus_snapshot.rs:68-72`). Snapshot validation
   rejects an empty set, validates every entry, recomputes the total using
   checked addition, and requires equality with the stored total
   (`consensus_snapshot.rs:206-250`, recomputation at 300-307).
5. `compute_proposer_vrf` selects a candidate that is actually in that vector,
   recomputes total stake with `checked_add`, and only then calls `evaluate`
   (`indra-consensus/src/proposer.rs:121-142`).

Therefore the real production path supplies `validator_stake > 0`,
`total_stake > 0`, and `validator_stake <= total_stake`, with overflow rejected.
The active-slot numerator is mainnet-validated and its stored certificate is
checked against `certified_log` during snapshot validation
(`consensus_snapshot.rs:214-218`). `evaluate` independently rejects zero stake,
zero total, and `w > total` at `sortition.rs:171-175`, preserving defense in depth.

`ProposerElection` has public fields, so external Rust code could manually build
an invalid value. That is not the production construction path found by the
repository trace, and `evaluate` still rejects its invalid stake domain.

## Trusted computing base and scope caveats

Even a future passing run would trust Kani, CBMC, their Rust translation and
models, the compiler/toolchain, and the modeled allocation/`num-bigint`
implementation. The current attempt establishes no width theorem, no panic
freedom theorem, no interval-order theorem, and no conversion theorem. It also
does not close the separate bit-identical cross-platform determinism question;
Topic 11 remains the relevant empirical evidence for that question.

## Recommendation

Do not restructure consensus arithmetic solely on the strength of this first
attempt. Ask for a human design decision between these paths:

1. **Fixed-size limb representation, then Kani.** Q768 endpoints are already
   bounded to 1024 bits and scratch products to 2048 bits in production. A
   carefully reviewed fixed-capacity limb type would give Kani statically bounded
   loops and storage, making exhaustive bit-precise verification materially more
   plausible. This is a consensus-critical rewrite and needs independent oracle,
   determinism, migration, and review planning before authorization.
2. **Gappa/Coq or another arithmetic proof route without a production rewrite.**
   Formalize the integer rounding recurrences and analytic tail separately, then
   connect the theorem to the Rust implementation through translation validation
   or a narrow equivalence check. Gappa is attractive for rounding/error bounds;
   it will not by itself verify Rust allocation/panic behavior.
3. **Verus with a specified fixed-width arithmetic layer.** This may express
   loop invariants more naturally than CBMC, but dynamic `num-bigint` internals
   still need specifications or replacement. Switching tools alone does not
   remove the representation problem.

The immediate next step should be a short design review comparing a verified
fixed-limb helper against a Gappa-backed mathematical certificate. A larger Kani
unwind or reduced symbolic domain is unlikely to resolve the present bottleneck
honestly.
