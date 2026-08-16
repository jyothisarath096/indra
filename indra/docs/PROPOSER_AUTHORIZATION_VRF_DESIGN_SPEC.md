# INDRA Proposer Authorization and VRF Election Design Specification

**Status:** design specification for adversarial review; no implementation is authorized by this document.

**Addresses:** Topic 7 findings T7-03 (VRF treated as proposer authorization), T7-04 (non-standard VRF presented as RFC 9381 suite `0x04`), T7-05 (64-bit seed/output truncation), and T7-06 (grindable parent-hash seed and commit/reveal withholding bias).

**Compatibility:** deliberately breaking. There is no decoder, verifier, or fallback for the current bespoke VRF, current block proposal format, current election scoring, or current commit/reveal election. Testnet state is disposable and this change joins the batched wipe-and-redeploy queue.

## 1. Executive decision

INDRA will separate three properties which the current design conflates:

1. **Eligibility:** a standards-compliant classical ECVRF proves that a registered validator's fixed VRF key produced one unique output for one chain, height, round, and finalized seed.
2. **Authorization:** a full Ed25519 + ML-DSA-87 hybrid signature proves that the same registered validator authorized the exact proposal bytes. Both signature components must verify.
3. **Randomness evolution:** the elected proposer's unique VRF output becomes input to the next seed only after a QC finalizes the proposal carrying it. Block-content hashes and raw QC signature lists are not entropy inputs.

The current all-validator commit/reveal election is removed. Each validator privately evaluates its own VRF, uses the complete output in stake-weighted sortition, and reveals a proof only if eligible. This follows Algorand's architectural separation: its protocol uses VRF output for sortition while consensus messages are separately signed with participation keys [Algorand consensus overview](https://dev.algorand.co/concepts/protocol/overview/). INDRA re-derives that shape using its own hybrid authorization and does not inherit Algorand's classical-only authorization.

This design does **not** claim that the VRF is post-quantum. It makes a classical VRF break an eligibility/predictability problem rather than an authorization forgery.

Specifically, it closes the authorization component of proposer accountability, ordering authority, and censorship resistance under a VRF break: forged eligibility cannot replace, reorder, or suppress transactions *as the victim proposer* because the attacker cannot authorize alternate victim content. It does not claim to prevent network-level censorship or targeted denial of service against the real proposer; those remain liveness risks stated in Section 9.

### 1.1 Parameter-addendum status

The following parameters are approved and normative in this revision:

- VRF-key activation occurs only when the next existing `ConsensusSnapshot` epoch is created after the registration transaction finalizes. It never occurs at a standalone height or in the middle of an epoch. Genesis keys are declared directly in genesis.
- Genesis election entropy is obtained from a publicly precommitted future external source and derived as specified in Section 7.4.
- VRF proof of possession is a full-hybrid signature over the exact bytes in Section 7.3.
- RFC ELL2 output and proof bounds are 64 and 80 bytes respectively; the INDRA suite enum is `1`; the block protocol version changes from the current repository value `1` to `2`.
- Proposal collection uses the existing propose-phase timeout (currently eight seconds). No second election timer is introduced.
- `election_seed[1] = election_seed[0]`; failed rounds do not evolve it.

The sortition construction in Section 5.2 is approved as the Ouroboros Praos/Minotaur single-validator threshold. Its arithmetic and calibration rules are normative below; the actual active-slot coefficient `f` is selected during the genesis ceremony by the prescribed simulation and is immutable in this implementation. Any future governance-controlled change is separately gated on Topic 9 design and audit.

## 2. Current problems and security objectives

### 2.1 T7-03 — eligibility is incorrectly accepted as authorization

The current header carries `proposer_vrf_output` and `proposer_vrf_proof`, but no proposer signature. A verifier recovers an elected validator from classical VRF material and accepts the proposal as that validator's act. A quantum adversary capable of solving the Curve25519 discrete-log problem could therefore impersonate the proposer without defeating ML-DSA-87.

The replacement must require two independent checks:

- the registered VRF key won the slot; and
- the registered complete hybrid consensus key authorized these exact proposal bytes.

Neither result may substitute for the other.

### 2.2 T7-04 — the implementation is not RFC 9381 suite `0x04`

The current implementation labels a Ristretto construction with suite byte `0x04`, uses a bespoke decompression/rejection loop as “hash to Ristretto,” and uses non-RFC transcript and nonce rules. RFC 9381 assigns `0x04` to **ECVRF-EDWARDS25519-SHA512-ELL2**, not Ristretto; the Edwards25519-TAI suite uses `0x03` [RFC 9381, Section 5.5](https://datatracker.ietf.org/doc/html/rfc9381#section-5.5). Passing internally generated tests cannot establish conformance to a different ciphersuite.

The replacement must use an identified standard suite, its exact transcript, canonical key/proof checks, proof-to-hash operation, and published test vectors.

### 2.3 T7-05 — effective election width is only 64 bits

The current VRF input includes only `epoch_seed[..8]`; election scoring interprets only `vrf_output[..8]` as a `u64`. The effective seed and ranking spaces are therefore capped at 64 bits even though both protocol values are 256 bits.

The replacement must bind all 256 seed bits and consume the complete standards-defined VRF output. No consensus decision may narrow either value to a machine integer.

### 2.4 T7-06 — proposer-controlled seed and last-Confirmation — cumulative-target issuance approved
Option 1, confirmed. Compute the exact halving schedule as a cumulative target function over the remaining post-genesis budget, minting cumulative_target(height) − cumulative_minted at each block via genuine exact integer/rational arithmetic — no floating-point anywhere in the computation, including internal intermediate steps, matching the same discipline already established for the Q768 sortition math. Every era total and the full lifetime total must be exact by construction; individual block rewards may differ by ±1 Spark, and that's fine — no terminal sweep, no special-cased final block.
Proceed with the design doc using this resolution. Same standing instruction: keep stopping and reporting on any further genuine ambiguity — this is now the second real arithmetic contradiction this exact-convergence work has surfaced, and catching both before they became silent approximations in a permanent monetary schedule is exactly the diligence this needs.revealer choice

The current seed is `SHA-256(parent block hash)`. The parent proposer controls fields that affect that hash and can evaluate candidate blocks before publishing one. INDRA's existing grinding test demonstrates this is reachable. Algorand's own guidance likewise warns that a validator can influence a block seed by declining a proposal and says a block seed must not be used directly as application randomness [Algorand randomness guidance](https://dev.algorand.co/concepts/protocol/randomness/).

The current all-validator commit/reveal phase also gives a committed participant an ex-post reveal/withhold choice after observing other reveals. Merely slashing non-reveal does not cryptographically remove that choice; a Byzantine participant may willingly pay.

The replacement must remove content grinding and the multi-party last-revealer decision, while stating the remaining whole-proposal withholding risk honestly.

## 3. Cryptographic primitives and margins

### 3.1 Authorization primitive

Proposer authorization uses INDRA's existing full hybrid consensus signature:

- Ed25519: classical security, approximately 128-bit classical; broken by a sufficiently capable quantum computer using Shor's algorithm.
- ML-DSA-87: NIST security category 5 and the PQ component of the authorization boundary. ML-DSA is standardized as FIPS 204; NIST lists FIPS 204 among its finalized PQ standards [NIST PQC project](https://csrc.nist.gov/projects/post-quantum-cryptography).
- Hybrid rule: **both** signatures must verify against both components of the registered `HybridPubKey`. No OR rule, downgrade, missing-component acceptance, or classical fallback exists.

Consequently, breaking only the classical VRF and Ed25519 does not authorize a proposal; the adversary must also forge ML-DSA-87.

### 3.2 Selected VRF suite

**Selected protocol suite:** `ECVRF-EDWARDS25519-SHA512-ELL2` from RFC 9381, with its RFC suite string and proof-to-hash output used exactly as specified.

Reasons:

- It is a standardized suite with fixed encodings, transcript rules, deterministic proof generation, canonical verification requirements, and test vectors [RFC 9381](https://datatracker.ietf.org/doc/html/rfc9381).
- Edwards25519 has mature Rust arithmetic through the same Curve25519 ecosystem already used by INDRA.
- ELL2 avoids the variable-time try-and-increment behavior of TAI and is the modern hash-to-curve choice in RFC 9381.
- The VRF key remains role-separated from the Ed25519 signing key. Sharing a curve does not permit seed/key reuse.

The wire suite identifier is an INDRA protocol enum, not a copied RFC byte:

```text
VrfSuiteV1::EcvrfEdwards25519Sha512Ell2 = 1
```

The RFC suite string is internal to the RFC algorithm. This avoids repeating the current mistake of treating a transcript byte as a free protocol label.

### 3.3 Implementation maturity gate

No currently reviewed Rust crate may be adopted solely because it claims RFC compatibility:

- `vrf-rfc9381` implements the relevant Edwards suites and reports passing RFC vectors, but its own documentation says it has **not been audited**, uses prerelease primitives, and should be used with caution [crate documentation](https://docs.rs/vrf-rfc9381/latest/vrf_rfc9381/). It is a conformance reference, not an acceptable mainnet dependency as-is.
- Mysten's `fastcrypto` Ristretto ECVRF received an external audit, but Ristretto is not an RFC 9381 ciphersuite; the audit itself describes a Ristretto implementation rather than RFC suite `0x04` [Common Prefix audit](https://www.commonprefix.com/static/clients/mysten/mysten_fastcrypto_ecvrf_ristretto255_audit.pdf). It is evidence that audited Rust VRF engineering exists, not evidence of RFC interoperability.

Implementation is gated on either:

1. an independently audited RFC 9381 Edwards25519-ELL2 Rust implementation with pinned source and reproducible RFC vectors; or
2. a narrowly scoped in-tree implementation built from reviewed curve/hash-to-curve primitives and independently audited before activation.

Until that gate is met, this specification is not implementation-ready. Substituting the current bespoke construction is forbidden.

### 3.4 Genuine post-quantum VRF status

No standardized, broadly deployed, independently audited PQ VRF is mainnet-ready as of this review. NIST has standardized PQ KEMs and signatures, but not a VRF [NIST PQC project](https://csrc.nist.gov/projects/post-quantum-cryptography). Research constructions exist—for example, the lattice-based few-time LB-VRF [Esgin et al.](https://eprint.iacr.org/2020/1222) and an isogeny-based DeuringVRF with a research implementation [DeuringVRF](https://eprint.iacr.org/2023/1251)—but neither is a standardized, production-deployed general VRF with the audit and lifecycle evidence required here. “Few-time” limitations are especially material for a long-lived validator key.

Therefore the ECVRF is a **named classical exception**:

- classical discrete-log security is roughly 128 bits;
- under Shor, its public-key security margin is effectively zero;
- SHA-512 transcript hashing retains approximately 256-bit quantum preimage resistance under generic Grover search, but that does not rescue the elliptic-curve proof relation.

This exception is acceptable only because hybrid proposal authorization is independently mandatory. A quantum attacker who forges or predicts eligibility still cannot create an accepted proposal for another validator without its ML-DSA-87 signature. The residual damage is advance knowledge, eligibility impersonation attempts, targeted DoS, and liveness/censorship pressure—not content authorization or finality forgery.

Migration trigger: reopen this choice when a PQ VRF has a stable specification, unrestricted long-lived-key security, independent cryptanalysis, production-quality constant-time implementation, and at least one serious deployment/audit record.

## 4. Proposal authorization construction

### 4.1 Avoiding a signature/hash cycle

A signature cannot be embedded in bytes whose hash it signs without circularity. Authorization is therefore an envelope around an unsigned block, not a field included in the signed block header.

```rust
BlockProposalVNext {
    block: BlockVNext,
    proposer_authorization: HybridSignature,
}
```

`BlockVNext` contains no proposer authorization signature. Its canonical bytes include its complete header and all transaction, slashing, governance, staking, and VRF-evidence lists.

The exact signed message is:

```text
proposal_signing_bytes =
    "INDRA-PROPOSAL-AUTH-v1" ||
    u16_be(chain_id_len) || chain_id ||
    u64_le(height) ||
    u32_le(round) ||
    proposer_id[32] ||
    u64_le(canonical_block_len) ||
    canonical_encode(BlockVNext)
```

The domain string is a signing input, not transmitted. `chain_id`, height, round, and proposer ID are repeated outside the block encoding deliberately: this makes cross-protocol/cross-chain intent explicit and permits simple independent test oracles. Verification requires the repeated values to equal the header values.

The signature covers canonical block bytes, not only `block_hash`. This avoids making proposer authorization depend solely on the collision resistance of the block-ID hash and prevents body/header mix-and-match. Block identity remains unchanged: `block_hash` is SHA-256 of the canonical header only, and votes, QCs, chain links, storage, replay, and manifests continue to use that header identity. The body remains indirectly bound by the roots embedded in the header, while `proposal_signing_bytes` additionally authenticates the complete canonical block (header plus body) directly under the proposer’s hybrid signature.

### 4.2 Required verification order

Before mempool/state projection or expensive body application, every live, sync, replay, and recovery proposal path must:

1. Exact-decode `BlockProposalVNext`; reject trailing bytes.
2. Resolve the immutable consensus snapshot governing `height`.
3. Resolve `proposer_id` in that snapshot; require exactly one complete registered hybrid key and VRF key.
4. Canonically reconstruct `proposal_signing_bytes`.
5. Verify Ed25519 **and** ML-DSA-87 signatures against the registered full hybrid key.
6. Recompute the election seed and VRF input.
7. Verify the RFC ECVRF proof against the registered VRF key and require its proof-to-hash output to equal the transmitted output.
8. Recompute stake-weighted sortition and require eligibility and priority claims to match.
9. Verify ordinary parent/QC, proposer-round, PoLC, state-root, and body rules.

Steps 5 and 7 are independent. A valid authorization does not make an ineligible proposer valid; a valid VRF proof does not authorize content.

### 4.3 Security consequence of a quantum VRF break

If the ECVRF is broken while ML-DSA-87 remains secure, an attacker may learn or forge who appears eligible. They still cannot:

- authorize a block under the victim's registered hybrid identity;
- alter the victim's authorized block content;
- obtain ordering authority attributed to the victim;
- censor by publishing a replacement victim proposal; or
- redirect proposer accountability or slashing attribution.

They can still target an elected validator, predict schedules, submit unauthorizable spam, or suppress a validator whose host they compromise. Thus the fix preserves authorization, accountability, and content-ordering integrity; it reduces but does not magically eliminate censorship/liveness risks caused by advance eligibility knowledge.

## 5. Full-width election input and stake-weighted sortition

### 5.1 Canonical VRF input

```text
vrf_alpha =
    "INDRA-PROPOSER-SORTITION-v2" ||
    u16_be(chain_id_len) || chain_id ||
    election_seed[64] ||
    u64_le(height) ||
    u32_le(round) ||
    snapshot_root[32] ||
    proposer_id[32]
```

The RFC suite processes this complete byte string. No seed prefix is extracted. `snapshot_root` freezes membership, keys, and stake weights for the slot. `proposer_id` prevents proof reuse across registered identities even if a VRF key-registration uniqueness invariant were ever violated.

`election_seed` is 64 bytes because its derivation uses SHA-512. Its generic quantum preimage margin is approximately 256 bits under Grover search. The classical ECVRF remains the weaker cryptographic component.

### 5.2 Selected sampling method: Praos/Minotaur threshold

For active validator stake `w_i`, total active stake `W`, stake fraction `alpha_i = w_i/W`, active-slot coefficient `f`, and the 512-bit RFC proof-to-hash output interpreted as an unsigned big-endian integer `x`:

```text
phi_f(alpha_i) = 1 - (1-f)^alpha_i
T_i            = 2^512 * phi_f(alpha_i)
eligible_i     iff x < T_i
```

This is the Praos threshold formalized and reused by Minotaur [Ouroboros Praos](https://www.iacr.org/archive/eurocrypt2018/10822378/10822378.pdf), [Minotaur](https://eprint.iacr.org/2022/104.pdf). It is split/merge invariant because the probability that no identity in a partition is elected is `(1-f)^(sum alpha_i)`. Across all active stake, the ideal probability of an empty round is exactly `1-f`.

#### 5.2.1 Protocol representation and admitted domain

`f` is encoded canonically as `F/2^64`, where `F` is the required genesis-config field `active_slot_coefficient_numerator`. In genesis TOML it is a quoted canonical ASCII decimal string: digits only, no sign, whitespace, or leading zeroes. This string form is required because TOML's signed integer domain cannot represent the admitted upper endpoint `2^63`. After parsing, consensus and snapshot encodings use `u64_le`. Genesis validation requires `1 <= F <= 2^63`; thus `0 < f <= 1/2`. This is an arithmetic/liveness safety domain, not the selection of an operational value. It bounds the series argument, keeps the expected number of eligible validators appropriate for one-proposer BFT, and permits one fixed proof of cost/error. The selected `F` is immutable in this implementation and is copied into and state-root committed by every `ConsensusSnapshot`.

There is deliberately no governance operation, feature flag, or runtime override for `F`. A governance-controlled parameter-change mechanism is a tracked future design item, to be considered only after Topic 9 audits the governance commit-reveal subsystem; it must define advance publication and snapshot-epoch activation before implementation. Its absence here is intentional, not an implied permission to mutate `F` out of band.

Stake is represented without quantization: every `w_i` is its exact snapshot `u64` Spark value. `W` is accumulated with checked `u128` arithmetic and must convert back to `u64` (consistent with the monetary supply cap) or snapshot construction fails. Zero stake is ineligible and bypasses the calculation.

#### 5.2.2 Normative outward-rounded integer arithmetic

All transcendental evaluation uses a signed fixed-point interval `[lo, hi]` at scale `S = 2^768`. Stored endpoints are arbitrary-precision integers with a protocol maximum of 1024 bits; multiplication scratch values are bounded to 2048 bits. Every operation rounds outward:

```text
mul_down(a,b) = floor(a*b/S)       mul_up(a,b) = ceil(a*b/S)
div_down(a,b) = floor(a*S/b)       div_up(a,b) = ceil(a*S/b)
```

Addition/subtraction use exact integers and interval rules. No hardware floating point, host math library, locale, or platform-dependent extended precision is permitted. Overflow or an endpoint exceeding 1024 bits is a consensus error.

Compute `L = -ln(1-f)` once when constructing the governing `ConsensusSnapshot`, persist its certified interval, and state-root commit both endpoints. This follows Cardano's useful computation shape—cache the logarithmic coefficient—but replaces host fixed precision with a protocol-defined interval.

Let `y = f/(2-f)`. Since `f <= 1/2`, `0 < y <= 1/3`. Evaluate exactly 256 positive terms using outward-rounded interval operations:

```text
L = 2 * atanh(y)
L_lo = 2 * sum(n=0..255, y^(2n+1)/(2n+1)) rounded down
L_hi = 2 * sum(n=0..255, y^(2n+1)/(2n+1)) rounded up + R_ln_up

R_ln_up = upward_round(
    2*y_hi^513 / (513*(1-y_hi^2))
)
```

For validator `i`, derive:

```text
z_lo = floor(L_lo*w_i/W)
z_hi = ceil (L_hi*w_i/W)
```

Because `0 <= z <= ln(2) < 1`, the alternating expansion of `1-exp(-z)` has monotonically decreasing terms. Evaluate the even 128-term partial sum at `z_lo`, rounding positive terms down and negative terms up:

```text
phi_lo = downward_interval_evaluation(
    z_lo - z_lo^2/2! + z_lo^3/3! - ... - z_lo^128/128!
)
```

For the error certificate, evaluate the 129-term odd partial sum at `z_hi`, rounding positive terms up and negative terms down, producing `phi_hi`. Clamp only after proof to `0 <= phi_lo <= phi_hi <= S`. The canonical eligibility threshold is deliberately conservative:

```text
threshold_i = floor(phi_lo / 2^(768-512))
eligible_i  iff x < threshold_i
```

Therefore an approximation can deny an infinitesimal boundary eligibility but can never grant eligibility above the mathematical Praos threshold.

#### 5.2.3 Error-bound proof

The logarithm identity is exact for `|y|<1`. Its omitted positive tail obeys:

```text
R_ln <= 2*y^513 / (513*(1-y^2))
```

At the admitted endpoint `y=1/3`, this is less than `2^-820.91`. For the exponential alternating series, the first omitted term bounds the remainder; at `z<=ln(2)` the 128-term lower sum differs from `1-exp(-z)` by less than `(ln 2)^129/129! < 2^-791.38`.

Outward rounding makes every true intermediate a member of its computed interval by induction over the operation sequence. With 768 fractional bits, each directed multiplication/division contributes less than one unit in the last place. The fixed operation graph and `y<=1/3`, `z<=ln 2` bounds give a conservative total interval-width ceiling of `2^24` Q768 units. Consensus requires `phi_hi-phi_lo <= 2^24`; failure rejects the snapshot parameter rather than using an uncertain threshold. Consequently:

The width lemma follows from the integer inequalities below, applied inductively to the fixed graph (`width([a,b]) = b-a`, in Q768 units):

```text
width(mul(I,J)) <= J_hi*width(I)/S + I_hi*width(J)/S + 2
width(div(I,J)) <= ceil(S*width(I)/J_lo)
                   + ceil(S*I_hi*width(J)/J_lo^2) + 2
width(sum(I_k)) <= sum(width(I_k))
```

All logarithm operands lie in `[0,1/3]`; all exponential operands lie in `[0,ln 2]`; division denominators are positive odd integers or `W>=w_i>0`. Iterating these inequalities for 256 logarithm terms yields `width(L) < 2^20` units. Multiplication by `w_i/W` cannot enlarge that width by more than one unit. Iterating the factorial recurrence through terms 128/129 and summing the alternating interval endpoints yields `width(phi) < 2^22` units. Adding both analytic remainder enclosures and clamp slack remains below `2^23`; the normative `2^24` ceiling retains a factor-of-two proof margin. These are integer inequalities over fixed loop bounds and are suitable for direct proof-assistant transcription.

```text
0 <= mathematical_phi - phi_lo < 2^(24-768) = 2^-744
0 <= mathematical_T - threshold_i < 1 + 2^-232
```

The real-valued function approximation loses less than `2^-744`. After mapping to the discrete 512-bit VRF space, ordinary threshold flooring adds less than `2^-512`; therefore the total probability conservatively withheld from the continuous ideal is less than `2^-512 + 2^-744`. Relative to the exact digital rule `floor(2^512*mathematical_phi)`, the implemented integer threshold is either identical or one integer lower, and differs only when the ideal threshold lies within `2^-232` above an integer boundary. For at most 200 validators, aggregate implementation/discretization split-or-merge deviation is below `200*(2^-512 + 2^-744) < 2^-504`. The analytic split/merge identity remains exact; this stated bound covers only canonical approximation and the finite VRF grid.

Testnet implementation proceeds with the hand-derived bounds above, exhaustive reduced-width and boundary tests, and high-precision rational/Arb oracle vectors. The runtime certificate `phi_hi-phi_lo <= 2^24` is mandatory consensus logic and must fail closed for every real computation that exceeds it. A machine-checked Lean/Coq/Isabelle proof or independently reviewed proof artifact for the `2^24` interval-width lemma is deferred only to the explicit hard pre-mainnet gate; it is not waived, and runtime enforcement remains mandatory regardless of proof-artifact status.

#### 5.2.4 Measured cost

A direct Python 3 reference prototype executing the exact operation schedule above—256 cached-log terms plus 128/129 interval exponential terms for each of 200 unevenly weighted validators—was measured on an Apple M4 arm64. Across 100 complete 200-validator runs, mean time was **55.45 ms per snapshot/round set**; the worst observed `phi` interval width was 137 Q768 units, far below the `2^24` ceiling. The logarithm interval is snapshot-cached; ordinary per-round work is at most 200 bounded 768-bit interval evaluations. This Python result is a conservative implementation benchmark, not a projected Rust figure. The Rust implementation must re-benchmark the same worst-domain vectors and remain below 10% of the existing eight-second propose timeout on the minimum supported validator hardware.

#### 5.2.5 Calibration methodology for `f`

No value of `F` is selected here. Candidate values within `0 < f <= 1/2` must be simulated across every validator count from 1 to 200, observed and adversarial stake distributions, network-latency/loss traces, and Byzantine withholding up to but not including one-third stake.

For Byzantine fraction `beta`, the ideal probability that no honest stake is eligible in one round is `(1-f)^(1-beta)`, and for `r` independent rounds it is `(1-f)^((1-beta)r)`. Calibration must choose and publish targets for:

- 50th/95th/99.9th percentile time to an honest proposal under the existing eight-second timeout;
- probability of no honest eligible proposer for enough consecutive rounds to breach the liveness SLO;
- expected and 99.9th-percentile number/bytes of simultaneous valid proposals;
- fork/prevote contention under realistic propagation delay;
- Byzantine withholding and targeted loss scenarios;
- all partitions and mergers of identical aggregate stake, requiring ideal probabilities to agree and implementation/discretization differences to remain below the `2^-504` aggregate bound.

Selection minimizes latency subject to the published bandwidth/contention ceiling and safety/liveness assumptions. It must not copy Cardano mainnet's coefficient: INDRA has different validator count, timeout, network, and economics. The simulation code, seeds, input distributions, raw results, and chosen `F` must be committed to the genesis record before validator keys and genesis state are finalized.

### 5.3 Full-width priority and proposal timing

Multiple eligible proposers are expected under any approved model. Select the lexicographically smallest priority:

```text
priority = SHA-512(
    "INDRA-PROPOSER-PRIORITY-v1" ||
    vrf_output ||
    canonical_sortition_claim ||
    proposer_id
)
```

Tie-break by full `proposer_id`. All 512 bits are compared lexicographically. `canonical_sortition_claim` is the single byte `0x01`, denoting the selected Praos-threshold rule.

Reuse the existing propose-phase timeout machinery; the repository currently sets `PROPOSE_TIMEOUT` to eight seconds. A validator tracks the lowest-priority valid proposal observed before its local timeout expires. It may replace that candidate if a better valid proposal arrives before its own prevote is cast. Once it prevotes, existing Tendermint lock and PoLC rules apply; election priority introduces no timer or unlock rule.

### 5.4 Alternative considered: one weighted global draw

A single common 256/512-bit random integer mapped by rejection sampling into cumulative stake intervals gives exactly one proportional winner and is simpler to audit. It was rejected because it requires every validator to know the same unpredictable draw before proposals. Producing that draw without a trusted party requires a threshold beacon, PVSS, or reveal protocol; the currently available commit/reveal path reintroduces last-revealer bias. Private VRF sortition has a production precedent and does not require all validators to reveal losing outputs.

### 5.5 Alternative considered: exponential-race score

Comparing `-ln(U)/stake` yields an elegant weighted exponential race, but consensus needs a specified platform-independent high-precision logarithm and boundary behavior. That complexity is not justified relative to the single-threshold candidate. Hardware floating-point logarithms are prohibited.

## 6. Grinding-resistant seed evolution

### 6.1 Selected construction

The seed for height `h+1` is derived from the prior seed and the unique VRF output carried by the block finalized at height `h`:

```text
election_seed[h+1] = SHA-512(
    "INDRA-ELECTION-SEED-v2" ||
    u16_be(chain_id_len) || chain_id ||
    election_seed[h] ||
    u64_le(h) ||
    u32_le(finalized_proposer_round[h]) ||
    finalized_block_id[h] ||
    finalized_proposer_id[h] ||
    finalized_proposer_vrf_output[h] ||
    governing_snapshot_root[h]
)
```

The seed becomes authoritative only when a fully verified QC certifies `finalized_block_id[h]`. The QC is the finalization gate, not the randomness payload. Nodes persist `election_seed[h+1]` with committed state and recompute it during replay.

Why this prevents current content grinding:

- RFC ECVRF uniqueness fixes one output for a registered key and `vrf_alpha`.
- `vrf_alpha` is fixed before the proposer chooses timestamp, transaction ordering, state roots, or other block content.
- changing block content changes `finalized_block_id` but cannot change the fixed VRF output or eligibility for height `h`.
- the next seed includes the finalized block ID for chain binding, but its unpredictable contribution is the unique VRF output, not proposer-selectable content.

### 6.2 Why raw parent QC bytes are not hashed as entropy

The suggested QC direction is valuable only if the QC contributes a unique value. INDRA QCs contain individual signatures rather than a unique threshold signature. An assembler may have several valid signer subsets, orderings must be normalized, and randomized signature encodings can add further choices. Hashing raw QC bytes would therefore give the assembler a combinatorial grinding surface.

Alternatives:

- **QC certified statement only:** deterministic but contains the already-known block ID and adds no entropy.
- **Raw/canonicalized QC signatures:** potentially unpredictable before votes arrive, but subset-selectable and therefore biasable.
- **Unique threshold signature beacon:** cryptographically attractive because one message has one threshold output, but production threshold/DKG operations would be a new major subsystem; standard BLS variants are classical and no reviewed threshold ML-DSA replacement is ready for this use.

The selected construction uses the QC only to prove that the unique proposer output was finalized. If INDRA later adopts a reviewed unique PQ threshold beacon, that beacon can be added under a new seed-domain version after a separate design review.

### 6.3 Commit/reveal removal and withholding

The current `VrfCommit`, `VrfReveal`, reveal-set commitment, reveal recovery, and zero/sub-quorum fallback election are deleted from the active protocol. There is no legacy message decoder or height gate.

This removes the specific last-revealer attack: no validator observes other validators' election outputs and then chooses whether its own output participates in the same winner calculation. Losing validators reveal nothing. An eligible validator reveals its proof only with its proposal.

Residual withholding remains: an eligible Byzantine proposer may decline to propose after learning its own result. That is a whole-proposal availability failure, not a choice between two randomness contributions. Consensus advances to the next round, whose VRF input includes the new round. Depending on the approved Section 5.2 parameter, another eligible proposal may already exist.

An empty or failed round does **not** advance the election seed. The recurrence in Section 6.1 runs only on block finalization and is indexed by height, not round. T7-02's existing timeout and quorum-evidence-gated round advance handles empty rounds; this design adds no bypass.

Operational accountability should be coordinated with Topic 8:

- an observed, validly hybrid-authorized proposal followed by equivocation is objectively slashable;
- repeated failure to propose can support bounded inactivity penalties only where eligibility was publicly revealed or statistically established over a long window;
- absence of a private VRF proof is not proof of malicious withholding, so immediate slashing for “non-reveal” is unsound.

This matches the honest limitation of private sortition: cryptography removes ex-post reveal-set manipulation, while timeouts and long-window availability policy address silent elected proposers.

### 6.4 Algorand warning comparison

Algorand explicitly warns that a block seed can be influenced when a validator declines a block whose resulting seed is unfavorable [Algorand randomness guidance](https://dev.algorand.co/concepts/protocol/randomness/). This design avoids the narrower and more severe INDRA bug—grinding many different valid block contents for different seeds—because block content does not determine the VRF output. It does not claim to eliminate the publish/withhold bit. Applications must not treat `election_seed` as unbiased gambling randomness; it is consensus sortition entropy with a bounded Byzantine withholding model.

## 7. Exact wire and state changes

### 7.1 Block header

Replace the current proposal-election fields with:

```rust
BlockHeaderVNext {
    // Existing non-election fields remain in canonical order.
    protocol_version: ProtocolVersion,
    height: u64,
    prev_hash: Bytes32,
    timestamp: u64,
    state_root: Bytes32,
    validator_set_root: Bytes32,
    mempool_set_root: Bytes32,
    value_hash: Bytes32,
    base_fee: u64,
    proposer_round: u32,
    polc_round: u32,
    quorum_certificate: VariableBytes<MAX_QC_SIZE_BYTES>,

    proposer_id: Bytes32,
    vrf_suite: VrfSuiteV1,
    election_seed: Bytes64,
    proposer_vrf_output: VariableBytes<MAX_STANDARD_VRF_OUTPUT_BYTES>,
    proposer_vrf_proof: VariableBytes<MAX_STANDARD_VRF_PROOF_BYTES>,
    sortition_claim: SortitionClaimV1, // PraosThreshold = 1
    proposer_priority: Bytes64,
}
```

Removed:

- `election_result_hash`;
- reveal-set commitment/evidence from the block body;
- fallback marker/output;
- any pre-activation or legacy current-VRF decoding.

`election_seed` is transmitted for auditability but must equal the locally derived committed seed; it is never trusted from the proposer.

`SortitionClaimV1::PraosThreshold = 1` is the only accepted value. There is no binomial or linear-threshold alternative decoder.

### 7.2 Proposal envelope

```rust
BlockProposalVNext {
    block: BlockVNext,
    proposer_authorization: HybridSignature,
}
```

The authorization is not part of `block_id`, votes, or QCs. The proposal verifier retains a verified-proposal capability so state transition cannot accidentally accept a decoded but unauthenticated block.

### 7.3 Consensus snapshot and registration

Each validator snapshot entry must bind:

- `validator_id` derived from the complete hybrid key;
- complete `HybridPubKey`;
- canonical RFC Edwards25519 VRF public key;
- stake weight;
- VRF suite enum and key activation epoch.

Registration validates the RFC public-key encoding, rejects identity/small-order/noncanonical keys per the suite, and enforces VRF-key uniqueness. A new staking-adjacent operation follows the existing registration-operation shape:

```rust
VrfKeyRegistrationV1 {
    validator_id: Bytes32,
    vrf_suite: VrfSuiteV1,
    vrf_pubkey: Bytes32,
    activation_epoch_id: u64,
    proof_of_possession: HybridSignature,
}
```

The exact proof-of-possession message is:

```text
vrf_pop_signing_bytes =
    "INDRA-VRF-POP-v1" ||
    u16_be(chain_id_len) || chain_id ||
    validator_id[32] ||
    vrf_pubkey_canonical_bytes ||
    u64_le(activation_epoch_id)
```

The domain string is a signing input and is not transmitted. Both Ed25519 and ML-DSA-87 components of the validator's snapshot-bound `HybridPubKey` must verify. The state-transition callee derives the only permitted activation epoch—the next `ConsensusSnapshot` epoch boundary after the registration transaction finalizes—and rejects a caller-supplied mismatch.

The key remains inactive for the rest of the current epoch and becomes visible atomically in the next snapshot. This reuses the existing snapshot construction/rotation machinery; there is no height countdown, wall-clock timer, or mid-epoch mutation. Genesis validators declare their initial VRF suite/key directly in genesis and neither submit this operation nor wait an epoch.

### 7.4 Persistent state

Persist and state-root commit:

- current `election_seed: [u8; 64]`;
- seed version;
- height from which it applies;
- VRF suite/key activation metadata in the consensus snapshot.

Genesis records a source descriptor and canonical external entropy value. Before validator VRF keys are finalized, operators publicly commit to a named external chain and a future block height (or an equivalently unpredictable public beacon event). The descriptor canonically binds source protocol/network, source genesis hash, future height, header codec/version, extraction algorithm, minimum confirmation depth, and the reorganization policy. The source block's height, ancestry, most-work-chain membership, and confirmation depth are established once during genesis assembly using independently operated Bitcoin full nodes. INDRA consensus does not attempt to prove those external-chain facts from the single stored header. The signed genesis record retains the real header permanently, making the ceremony claim publicly and indefinitely falsifiable against Bitcoin chain history. Every INDRA node canonically validates the recorded fields and deterministically derives:

For protocol version 2, the sole descriptor is encoded exactly as:

```rust
BitcoinPowEntropySourceV1 {
    scheme: u8,                     // 1
    network_genesis_hash: [u8; 32], // raw digest order, never display-reversed
    announced_height: u64,          // u64_le
    header_codec: u8,               // 1 = Bitcoin80ByteHeader
    extraction_algorithm: u8,       // 1 = DoubleSha256
    minimum_confirmations: u32,     // u32_le, must be >= 100
    reorg_policy: u8,               // 1 = SameHeightRestartConfirmations
}
```

No field is optional and no textual network alias participates in consensus. The network is identified by its raw 32-byte genesis digest. The fixed-width source identifier is:

```text
external_entropy_source_id = SHA-256(
    "INDRA-EXTERNAL-ENTROPY-SOURCE-ID-v1" ||
    canonical_encode(BitcoinPowEntropySourceV1)
)
```

The signed genesis record separately retains the exact consensus-serialized 80-byte source header. Unknown enum values, display-reversed hashes, a confirmation depth below 100, or any noncanonical/trailing encoding are rejected.

```text
election_seed[0] = SHA-512(
    "INDRA-GENESIS-ELECTION-SEED-v1" ||
    chain_id ||
    external_entropy_source_id ||
    external_entropy_value
)
```

Each variable field has one canonical genesis encoding specified by the source descriptor, so the concatenation is unambiguous. The concrete source and future height are operational genesis-time choices, not hardcoded constants. The public commitment must precede finalization of validator VRF keys; otherwise validators could grind keys after learning the seed. `election_seed[1] = election_seed[0]` exactly, with no additional derivation.

For a Bitcoin source, the extraction rule is normative:

1. During genesis assembly, obtain the consensus-serialized 80-byte block header at the announced height from independently operated fully validating Bitcoin nodes.
2. During genesis assembly, verify its proof of work, height, ancestry to the descriptor's Bitcoin genesis hash, most-work-chain membership, and required confirmation depth. These publicly checkable external-chain facts are an operational genesis gate, not an INDRA consensus-code proof.
3. Set `external_entropy_value = SHA-256(SHA-256(header_bytes))` as the raw 32 digest bytes produced by SHA-256, not RPC/display-reversed hexadecimal.
4. Set `external_entropy_source_id` to the canonical descriptor encoding, including the network/genesis hash and announced height; the header itself is retained in the signed genesis record.

Protocol version 2 supports this `BitcoinPowHeaderV1` source scheme. Using Ethereum, drand, or another structurally different beacon requires a separately specified source-scheme enum value and extraction/finality verifier before the ceremony precommitment; operators cannot improvise an unversioned parser. The particular supported network and future height remain ceremony choices.

The confirmation-depth floor is the source chain's protocol/economic stale-block horizon. For Bitcoin it is **at least 100 blocks**, matching Bitcoin's consensus coinbase-maturity interval, which exists to prevent spending rewards from blocks later made stale [Bitcoin developer guide](https://developer.bitcoin.org/devguide/block_chain.html). This is a protocol-grounded floor, not a claim of deterministic Bitcoin finality. Ceremony operators must perform and publish a cost analysis and may require a greater depth where the value of biasing INDRA sortition could exceed the cost of the corresponding source-chain reorganization.

There is no deadline fallback. If the announced height has not produced a block by the planned genesis time, genesis waits. The source, height, and extraction rule may not be changed after observing candidate entropy; changing them requires aborting the ceremony, publishing a new precommitment before its newly selected future event, and refinalizing validator VRF keys afterward.

Before the required depth, a source-chain reorganization discards the displaced candidate, selects the block at the **same announced height** on the new canonical chain, and restarts the confirmation count. A reorganization detected after the depth but before INDRA genesis launch aborts finalization and applies the same rule. Once INDRA genesis has launched, its signed genesis entropy is immutable; a later source-chain reorganization is recorded as a ceremony incident but cannot rewrite INDRA genesis.

Using a future proof-of-work block as a public beacon has formal precedent, including analysis specifically of Bitcoin as a public randomness source [Bentov, Gabizon, and Zuckerman](https://eprint.iacr.org/2015/1015.pdf). It removes INDRA operators' post-commit choice, but “non-gameable” is not absolute: the external chain's block producer can withhold/grind within that chain's economic constraints, and a reorganization can change a recent value. The genesis operations record must therefore fix the exact header field/value extraction, canonical-chain confirmation depth, and reorg contingency *before* the event. Operators may not choose among blocks, chains, or encodings after observing outcomes.

### 7.5 Network messages

Delete `VrfCommit`, `VrfReveal`, reveal-request, and reveal-response messages. Proposal gossip carries `BlockProposalVNext`. Proposal requests/responses return the same envelope, never a bare unsigned block.

Canonical storage after finalization MUST persist the complete `BlockProposalVNext` authorization envelope, including its hybrid signature. The storage key and block identity remain the unchanged SHA-256 hash of the canonical header. Engine commit, segmented storage, sync import, recovery, and persisted consensus-lock records retain the independently verified envelope. Pruning removes the envelope only together with its corresponding prunable block body; no retained unsigned body may be treated by replay as fully validated.

Startup replay exact-decodes and independently verifies every stored envelope against its governing snapshot before state projection. QC certification never substitutes for the proposer authorization signature. RPC surfaces may expose an unsigned block projection only when derived from a verified stored envelope; forensic and audit surfaces expose the authorization metadata required for accountability.

Persisting one ML-DSA-87 signature per block creates material storage growth. Implementation acceptance therefore includes a measured canonical per-block byte delta and projected growth at the configured block cadence, checked against the state/storage budget established by the pipeline audit. This cost must be reported from real encoded artifacts, not estimated from field names.

### 7.6 Protocol constants and version

```text
MAX_STANDARD_VRF_OUTPUT_BYTES = 64
MAX_STANDARD_VRF_PROOF_BYTES  = 80
VrfSuiteV1::EcvrfEdwards25519Sha512Ell2 = 1
BlockHeader protocol version: 1 -> 2
```

The old value is the repository's current `BLOCK_FORMAT_VERSION: u16 = 1`; the new value is exactly one greater. This is a wire break, not a compatibility discriminator: after clean redeploy only version 2 is decoded.

## 8. Invariants and required verification tests

Implementation is not complete until all of the following are permanent tests:

1. A valid VRF proof with a missing, Ed25519-only, ML-DSA-only, mixed-key, or wrong-proposer hybrid signature is rejected.
2. A valid hybrid signature with an invalid/ineligible/wrong-slot VRF proof is rejected.
3. Changing any header or body byte after signing invalidates authorization.
4. Cross-chain, cross-height, cross-round, cross-snapshot, and cross-validator replay fails.
5. RFC 9381 official vectors pass byte-for-byte; current bespoke proofs fail with no fallback.
6. Noncanonical Edwards keys, points, scalars, proofs, lengths, truncation, and trailing bytes fail cleanly.
7. Flipping every one of the 512 seed bits changes `vrf_alpha`; flipping every output bit can affect sortition/priority.
8. Praos sortition matches high-precision Arb/rational oracle intervals across exhaustive reduced-width distributions, all Q768 rounding boundaries, `f=2^-64`, `f=1/2`, maximum stake, and the 200-validator cap; every result satisfies the `2^24` interval-width ceiling.
9. No floating-point instruction or platform-dependent ordering affects election output.
10. Changing timestamp, transaction ordering, or other block content cannot change a validator's VRF output for a fixed slot.
11. Withholding one validator's non-winning proof cannot change another validator's eligibility or priority.
12. Restart, sync, and replay derive identical seeds and winners from finalized history.
13. Every proposal consumption site requires a verified hybrid-authorization capability.
14. A simulated quantum-VRF compromise—arbitrary accepted eligibility proof for a victim—still cannot produce an accepted victim proposal without ML-DSA-87 authorization.
15. A finalized registration never changes the current epoch snapshot, activates in exactly the next snapshot, and a mixed-key proof of possession is rejected.
16. Genesis validator VRF keys are active directly without a synthetic registration or delay.
17. Published genesis-source vectors reproduce `election_seed[0]`; changing source ID, source value, or chain ID changes it; `election_seed[1]` is byte-identical.
18. Empty rounds leave the seed unchanged, while finalization advances it exactly once.
19. Proposal selection switches to a better priority only before the local prevote and uses the existing propose timeout.
20. RFC output/proof lengths, suite enum, and protocol version are pinned to the Section 7.6 constants.

## 9. Residual risks and explicit trade-offs

| Risk | Status after design | Consequence |
|---|---|---|
| Classical ECVRF broken by Shor | Accepted, monitored exception | Eligibility becomes predictable/forgeable; hybrid authorization still prevents proposer impersonation and content forgery. |
| Eligible proposer withholds whole proposal | Not cryptographically eliminable with private sortition | Round timeout/liveness delay; bounded by multiple eligibility and Byzantine stake assumptions. |
| Targeted DoS after eligibility reveal | Residual | Proof is revealed with proposal, minimizing but not eliminating the attack window. |
| Multiple eligible proposers | Intentional | Deterministic full-width priority plus BFT voting resolves competition. |
| No eligible proposer | Probabilistic | Existing propose timeout advances the round without changing the seed; ideal probability is `1-f`, with `F` selected by the published calibration. |
| Sortition arithmetic/model | Resolved construction; operational coefficient pending simulation | Praos threshold uses certified downward-rounded Q768 intervals; the selected `F` must be justified by the Section 5.2.5 simulation record. |
| Genesis/key-registration grinding | Bounded operationally and in consensus | Precommitted future external entropy plus snapshot-delayed, proof-of-possession-bound VRF-key activation; external-source producer/reorg risk remains. |
| Election seed used as application randomness | Forbidden | Consensus entropy retains a proposer publish/withhold bit and is not a general randomness beacon. |

## 10. Alternatives not selected

### Keep Ristretto and merely change the suite byte

Rejected. A new private suite identifier would stop the false RFC claim but retain a bespoke cryptographic construction. Mysten's audited Ristretto code is a possible engineering reference, not wire compatibility with RFC 9381.

### Use the unaudited RFC Rust crate immediately

Rejected for mainnet. Passing vectors establishes conformance evidence, not side-channel resistance, misuse resistance, or implementation security; the crate itself disclaims an audit.

### Add ML-DSA output to create a “hybrid VRF”

Rejected. A signature over a VRF output authenticates it but does not make the VRF pseudorandomness or uniqueness post-quantum. Randomized ML-DSA signatures would themselves create a grinding surface if hashed as election output.

### Retain commit/reveal and slash missing reveals

Rejected. Penalties alter incentives but do not remove a Byzantine participant's ex-post choice. Missing private eligibility proofs also cannot be objectively distinguished from non-eligibility.

### Hash parent QC signature bytes

Rejected. INDRA has no unique threshold QC signature; signer-subset and encoding choices make raw certificates grindable. The QC remains the finalization gate for the selected unique proposer VRF output.

## 11. Activation and breaking-change record

This redesign changes:

- VRF keys and proofs;
- block header and proposal wire encodings;
- proposal signing bytes;
- block IDs and QC messages indirectly through the new block identity;
- election messages and timing;
- consensus snapshot content and roots;
- validator registration/key-rotation encoding;
- genesis format and roots;
- persistent state/snapshot schema;
- sync, replay, storage, RPC, FFI, CLI, fixtures, and network message schemas.

Activation is a clean redeploy. There is no old-proof verifier, old-header decoder, dual suite, height-gated fallback, or migration tool. It is another identity/format-breaking item in the existing batched redeploy queue.

## 12. Review and activation gates

- [ ] **Hard pre-mainnet blocker:** independent cryptographic review of the in-tree RFC 9381 Edwards25519-ELL2 implementation and the eligibility/authorization construction.
- [ ] **Hard pre-mainnet blocker:** an audited RFC 9381 Edwards25519-ELL2 crate or audited implementation path replaces or approves the testnet in-tree path.
- [ ] **Hard pre-mainnet blocker:** a machine-checked Lean/Coq/Isabelle proof or independently reviewed proof artifact establishes the Section 5.2.3 `2^24` interval-width lemma. The runtime certificate remains mandatory before and after this gate closes.
- [x] Section 5.2 fixes the Praos construction, Q768 arithmetic, error bound, benchmark procedure, and `f` calibration method; the operational `F` is a required immutable genesis parameter selected by that method.
- [x] Genesis external-entropy mechanism and snapshot-bound VRF-key activation are specified.
- [x] Topic 8 penalty design is not a dependency of proposer authorization/sortition implementation; any future penalty remains separately scoped.
- [x] All live/sync/replay proposal-consumption sites are enumerated and form the mandatory migration checklist.
- [x] Wire constants, suite enum, and protocol-version increment are fixed.
- [x] All 20 invariants in Section 8 are approved as the implementation acceptance bar.

Implementation is authorized for testnet. The three unchecked items above are non-negotiable mainnet-activation blockers; authorization sequences them after testnet rather than waiving them. No additional open Section 12 item blocks this implementation.
