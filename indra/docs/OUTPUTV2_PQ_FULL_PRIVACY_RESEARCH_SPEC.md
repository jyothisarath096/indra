# OutputV2 Post-Quantum Full-Privacy Research Specification

**Status:** research specification only; no implementation authorization  
**Scope:** recipient privacy plus sender/input privacy  
**Version:** investigation draft 1, 2026-07-28

> [!CAUTION]
> ## Non-negotiable research boundary
>
> This specification, and any future implementation built from it, is a
> **FAITHFUL RESEARCH IMPLEMENTATION of recently published, thinly reviewed
> academic cryptography**. It has not been independently reviewed, audited, or
> proven safe by anyone with the relevant cryptographic expertise.
>
> It MUST NEVER be described as "safe for real value", "production ready",
> "audited", "certified", or equivalent. Its purpose is to make the research
> boundary precise enough to hand to genuine post-quantum and anonymous-payment
> cryptographic experts for review.
>
> This document does not authorize implementation, activation, migration, or use
> by live validators. Any future document that cites this specification MUST
> repeat this boundary prominently rather than incorporating it only by
> reference.

## 1. Result and specification status

This review does **not** produce a complete implementable OutputV2 protocol.
It produces:

1. a faithful specification of the Module-LWE stealth-address proposal;
2. a faithful specification of the Lattice RingCT v1.0 sender-privacy proposal;
3. an exact mapping analysis against INDRA's current UTXO architecture; and
4. a proof that the two requested constructions cannot presently be composed
   faithfully with each other or with INDRA's current transparent-value UTXO
   system.

Three blockers prevent a normative end-to-end OutputV2:

- The Module-LWE stealth paper and Lattice RingCT use different public/secret
  key relations, dimensions, moduli, distributions, and signing algorithms.
  Neither paper defines a bridge.
- Lattice RingCT proves balance using its own lattice commitment
  `Com_A(m, sk) = A*sk + m mod q`. INDRA's current baseline instead exposes
  authoritative `u64` values and enforces checked public conservation, so an
  OutputV2 composition would need a new, fully specified confidential-value
  transition rather than compatibility with an existing proof system.
- INDRA reveals and deletes the exact input UTXO. A ring spend must leave ring
  members in the anonymity pool and reject reuse through a linkability tag.
  This is a different state-transition model, not a signature-module swap.

Accordingly, every INDRA schema below is either:

- **PAPER:** directly specified by a cited paper; or
- **INDRA ADDITION - UNREVIEWED:** a necessary local bridge absent from the
  papers.

No `INDRA ADDITION - UNREVIEWED` in this document is approved cryptography.

## 2. Sources and provenance rules

### 2.1 Primary sources

**SAP26**

Marija Mikić, Mihajlo Srbakoski, and Strahinja Praška, "Post-Quantum
Stealth Address Protocols", *Journal of Cyber Security Technology*, published
online 8 January 2026, DOI
[10.1080/23742917.2025.2611820](https://www.tandfonline.com/doi/abs/10.1080/23742917.2025.2611820).
The inspectable construction is the authors' arXiv v1 manuscript,
[arXiv:2501.13733](https://arxiv.org/abs/2501.13733), January 2025.

**LRCT18**

W. A. A. Torres et al., "Post-Quantum One-Time Linkable Ring Signature
and Application to Ring Confidential Transactions in Blockchain (Lattice
RingCT v1.0)", ACISP 2018, DOI
[10.1007/978-3-319-93638-3_32](https://doi.org/10.1007/978-3-319-93638-3_32);
full version:
[IACR ePrint 2018/379](https://eprint.iacr.org/2018/379.pdf).

**APQC18**

Huang Zhang, Fangguo Zhang, Haibo Tian, and Man Ho Au, "Anonymous
Post-Quantum Cryptocash", Financial Cryptography 2018, DOI
[10.1007/978-3-662-58387-6_25](https://doi.org/10.1007/978-3-662-58387-6_25);
full version:
[IACR ePrint 2017/716](https://eprint.iacr.org/2017/716.pdf).

**FIPS203**

NIST, [FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism
Standard](https://csrc.nist.gov/pubs/fips/203/final), especially Table 3 for
wire sizes.

### 2.2 Citation precision

References such as "SAP26 §5.3 step 4" refer to the numbered steps in the
paper's Section 5.3. References to LRCT algorithms and equations use the
paper's printed numbers. Page numbers are PDF page numbers printed by the
paper, not viewer offsets.

The 2026 journal page says the final article uses Kyber and Dilithium, but the
public arXiv record available for equation-level inspection is still v1. This
document does not silently impute changes from the journal abstract to the
arXiv formulas. An expert review MUST obtain and diff the final typeset article
before any implementation.

## 3. INDRA baseline relevant to OutputV2

INDRA currently has:

- `InputV1 { utxo_id }`; the exact spent output is public
  ([transaction.rs lines 28-44](../indra-core/src/types/transaction.rs));
- `OutputV1 { value_spark, owner_pubkey, lock_height }`, with a visible
  amount and hybrid Ed25519 + ML-DSA-87 owner
  ([transaction.rs lines 56-93](../indra-core/src/types/transaction.rs));
- one transaction-wide hybrid signature, and a rule that every input has the
  same owner key
  ([apply.rs lines 950-1023](../indra-state/src/apply.rs));
- public lookup, validation, then deletion of each exact `utxo_id`
  ([apply.rs lines 960-1008](../indra-state/src/apply.rs) and
  [1091-1108](../indra-state/src/apply.rs));
- checked-`u64` public conservation and dust validation as the sole monetary
  validity mechanism; and
- direct wallet ownership detection by full canonical hybrid-key equality.

`OutputV1.value_spark` is authoritative public consensus data. Full amount
privacy therefore requires replacing this transparent baseline, including the
staking logic that derives principal directly from referenced UTXOs.

# Part I - recipient privacy: Module-LWE SAP

## 4. Module-LWE key structure

### 4.1 Exact paper structure

**PAPER - SAP26 §5.3 step 1.**

The recipient invokes `Kyber.CCA.KeyGen` twice:

```text
(k, z_k, K) <- Kyber.CCA.KeyGen()
(v, z_v, V) <- Kyber.CCA.KeyGen()

K = (t_K, rho_K)
V = (t_V, rho_V)
```

The paper's notation assigns:

- `K` and secret `k` to spending-key derivation;
- `V` and secret `v` to viewing/recognition; and
- `z_k`, `z_v` to the Fujisaki-Okamoto decapsulation-key state.

The published stealth meta-address is:

```text
M = (K, V)
```

**PAPER - SAP26 §5.3 step 2.**

The paper registers `M` in ENS. It therefore assumes an external authenticated
registry but does not specify its authorization, update, revocation, collision,
or consensus rules.

### 4.2 Mapping to INDRA identity

`M` MUST NOT be an INDRA validator hot key, validator cold key, delegator
identity key, `HybridPubKey`, or existing `PaymentPubKeyV1`.

Reasons:

- The paper needs two Kyber public keys with different roles.
- INDRA identity keys authorize consensus, staking, and governance.
- `PaymentPubKeyV1` contains only one ML-KEM key and an X25519 key.
- Key reuse across KEM scanning, transaction spending, and validator identity
  is neither in SAP26 nor justified by FIPS 203.

> [!WARNING]
> **INDRA ADDITION - UNREVIEWED: dedicated meta-address type**
>
> A future research implementation would need a dedicated, versioned
> `StealthMetaAddress` containing exactly `K` and `V`, plus an authenticated
> registry record binding it to an INDRA identity. The binding, version,
> rotation, revocation, domain separation, and anti-substitution rules are not
> supplied by SAP26. They require their own protocol and security review.

For ordinary user payments, identity-to-meta-address binding may be an
application-level directory concern. For validator rewards, self-bonds,
delegation returns, governance deposits, or slashing refunds, it is a consensus
custody rule. This document does not authorize replacing a registered cold
owner with a stealth key.

## 5. Exact one-time address derivation

### 5.1 Sender algorithm

**PAPER - SAP26 §5.3 steps 3-7; Kyber subroutines are Algorithms 4 and 2.**

Given recipient meta-address `M = (K, V)`:

1. Retrieve `M`.
2. Encapsulate to the viewing key:

   ```text
   (R, S) = Kyber.CCA.Encaps(V)
   ```

   `R` is the KEM ciphertext called the "ephemeral public key" by SAP26; `S`
   is the shared secret. Encapsulation internally obtains randomness through
   `Kyber.CPA.Enc` (SAP26 §5.3 step 4; Algorithms 4 and 2).

3. Derive the stealth public key:

   ```text
   P = XOF(rho_K) * XOF(S) + Decompress_q(t_K, d_t)
   ```

   This is SAP26 §5.3 step 5.

4. Publish `R` and a view tag consisting of one or more bytes of `Hash(S)`.
   Send the asset to `P` (SAP26 §5.3 steps 6-7).

The paper does not number this as a standalone algorithm; the normative
locator is Section 5.3 steps 3-7 and Figure 2.

### 5.2 Recognition/scanning

**PAPER - SAP26 §5.3 steps 8-9.**

For every new registry item `(R_i, tag_i)` since the wallet's last scan:

```text
S_i = Kyber.CCA.Decaps(v, z_v, V, R_i)
candidate_tag = prefix(Hash(S_i), configured_tag_length)
```

If `candidate_tag != tag_i`, skip the item. If it matches, recompute:

```text
P_i = XOF(rho_K) * XOF(S_i) + Decompress_q(t_K, d_t)
```

Derive the chain address from `P_i` and compare it with the output destination.
The paper recommends a one-byte tag after its Section 6.1 benchmark: it reports
a 25.12% scan improvement at one million announcements over no tag and says a
full-hash tag adds little further benefit.

The tag is only a filter. A one-byte match has probability approximately
`1/256`; ownership is confirmed only by recomputing and comparing `P_i`.

### 5.3 Spending-key recovery

**PAPER - SAP26 §5.3 step 10.**

For a recognized output:

```text
p = k + XOF(S)
```

SAP26 then states:

```text
P = XOF(rho_K) * p + e_1
e_1 = Decompress_q(t_K, d_t) - XOF(rho_K) * k
```

This establishes the algebraic relation printed immediately after step 10.

### 5.4 Critical paper ambiguity

SAP26 does not give a complete serialized spending-key algorithm equivalent to
FIPS 204 `ML-DSA.Sign`, nor does it specify all auxiliary secret-key fields,
bounded distributions, rejection-sampling behavior, or an exact verification
key encoding for `P`. The arXiv v1 paper calls Kyber's secret `k` a spending
key, while Kyber is a KEM, not a signature scheme.

The 2026 journal abstract says the final design uses Dilithium, but a statement
in an abstract is not an implementable signing specification.

> [!CAUTION]
> **No conservative local extension exists here.**
>
> Selecting an ML-DSA serialization, treating `(p,e_1)` as an ML-DSA secret
> key, changing distributions to make signing work, or defining a new
> verification algorithm would be new cryptography. This document does not do
> so. The final journal article and its authors must clarify this point, and an
> independent lattice-signature expert must validate it.

## 6. On-chain announcement and evidence-based size

### 6.1 Paper-prescribed data

**PAPER - SAP26 §5.3 step 6.**

Every payment publishes:

```text
Announcement = (R, view_tag)
```

The output itself publishes the stealth destination derived from `P`.
`K` and `V` belong in the meta-address registry, not every transaction.

### 6.2 Exact sizes the sources support

SAP26 benchmarks Kyber512 and a one-byte view tag. Under the Kyber/ML-KEM
wire sizes:

| Item | Kyber/ML-KEM-512 bytes | Basis |
|---|---:|---|
| `K` encapsulation key | 800 | FIPS 203 Table 3 |
| `V` encapsulation key | 800 | FIPS 203 Table 3 |
| Meta-address `M=(K,V)` | 1,600 | exact sum, excluding registry framing |
| `R` ciphertext | 768 | FIPS 203 Table 3 |
| one-byte view tag | 1 | SAP26 §6.1 choice |
| per-payment announcement | **769** | exact sum, excluding list/framing |

If INDRA instead chose its existing ML-KEM-1024 parameter set, the equivalent
mechanical sizes would be:

| Item | ML-KEM-1024 bytes |
|---|---:|
| two encapsulation keys | 3,136 |
| ciphertext plus one-byte tag | 1,569 |

The ML-KEM-1024 figures are **not SAP26's benchmark configuration**. They are
only FIPS 203 wire-size arithmetic.

The following are not specified exactly by SAP26 and MUST NOT be guessed:

- canonical encoding and byte length of `P`;
- whether an entire ML-DSA verification key is stored or only a polynomial
  vector;
- framing, version, and output-to-announcement binding;
- address checksum/encoding;
- final-journal changes relative to arXiv v1.

Consequently, 769 bytes is an exact announcement payload for the paper's
Kyber512/one-byte-tag case, **not an exact OutputV2 overhead**.

## 7. UTXO mapping

### 7.1 Paper model to ordinary INDRA output

The minimal abstract mapping is:

| SAP26 concept | INDRA concept |
|---|---|
| asset sent to stealth address | new UTXO |
| `P` | one-time ownership verification key |
| `(R, tag)` registry item | output-bound announcement |
| recipient scans registry | wallet scans blocks/outputs |
| `p` | one-time spending secret |

> [!WARNING]
> **INDRA ADDITION - UNREVIEWED: output binding**
>
> Ethereum's separate announcement registry is not appropriate to copy
> implicitly into a UTXO protocol. The most conservative architectural
> placement would bind `(R, tag)` inside the same canonical output or
> transaction signing transcript as `P`, the commitment, lock height, and
> output index. SAP26 does not specify this binding or prove substitution
> resistance. Exact fields and hashes remain undefined pending review.

### 7.2 What cannot map unchanged

- `HybridPubKey` cannot encode paper key `P`; its format is fixed to Ed25519
  plus ML-DSA-87.
- `TransactionV1.signature` cannot spend different one-time keys across
  multiple inputs; validation requires one common owner.
- `InputV1.utxo_id` reveals the exact spent output.
- Deleting the referenced UTXO destroys its future use as a decoy.
- Public `value_spark` reveals the amount.
- Staking operations resolve custody through stable validator/delegator
  identities, while stealth `P` is intentionally unlinkable to them.

Therefore this is not an `OutputV1.owner_pubkey` field substitution.

### 7.3 Paper silences and required review questions

SAP26 does not specify:

- UTXO identifiers, maturity/lock heights, or reorg-safe scan cursors;
- duplicate or replayed announcements;
- malformed-key validation and chosen-key attacks;
- output/amount/commitment binding;
- multi-output transaction indexing;
- change-output handling;
- fee or denial-of-service policy;
- meta-address rotation;
- validator/delegator identity binding;
- backup/recovery of derived one-time keys;
- concurrency across wallets and devices;
- transaction-spend authorization; or
- security in composition with ring signatures.

Each is an `INDRA ADDITION - UNREVIEWED`; none is filled cryptographically by
this specification.

# Part II - sender/input privacy: Lattice RingCT

## 8. Choice between LRCT18 and APQC18

LRCT18 is the closer paper for sender privacy plus confidential values because
it defines:

- a concrete one-time linkable ring signature (L2RS), Algorithms 1-4;
- a coin commitment and homomorphic balance relation, Equation (1);
- `LRCT.Mint`, Algorithm 5;
- a single-input/single-output confidential spend, Algorithm 6; and
- concrete key and ring-signature sizes, Table 1.

APQC18 is the closer *whole receiver-plus-sender* design: its Sections 6-7
combine temporary destination keys with its own linkable ring signature.
However, APQC18 explicitly leaves confidential transactions as future work
(APQC18 §7). It therefore cannot justify composition with INDRA's existing
commitments.

This specification uses LRCT18 for Part II. APQC18 is used only to identify
decoy-selection and receiver-key alternatives. Mixing APQC18's destination
keys with SAP26 would itself be a new construction.

## 9. Exact L2RS construction

### 9.1 Setup and keys

**PAPER - LRCT18 §5.1, Remark 2; §5.2, Algorithm 1.**

Public parameters are polynomial vectors:

```text
A, H in R_q^(1 x (m-1))
```

Remark 2 requires generating `A` and `H` from a hash evaluated at two distinct
fixed constants rather than installing a trapdoor.

For each owner:

```text
S^T = (s_1, ..., s_(m-1))
s_i <- (-2^gamma, 2^gamma)^n
a = A*S mod q
```

`a` is the public key; `S` is the private key (Algorithm 1 lines 2-4).

### 9.2 Ring formation and membership proof

**PAPER - LRCT18 §5.3, Algorithm 2.**

Let:

```text
L = {a_1, ..., a_w}
```

contain the actual signer at hidden index `pi`. The signer knows `S_pi`.

The linkability component is:

```text
h = H*S_pi in R_q
H_2q = (2H, -2h + q) in R_2q^(1 x m)
S_2q,pi^T = (S_pi^T, 1)
```

and `H_2q * S_2q,pi = q` in `R_2q` (LRCT18 §5.3 step 1).

Each public key is lifted:

```text
Lift(A,a_i) = A_2q,i = (2A, -2a_i + q)
```

(LRCT18 Definition 7 and §5.3 step 2).

The signer samples Gaussian vector `u`, hashes the ring, tag, message, and two
commitments to create `c_(pi+1)`, and walks cyclically through all non-signer
ring members. For each it samples Gaussian `t_i` and computes:

```text
c_(i+1) =
  H_1(L, H_2q, mu,
      A_2q,i*t_i + q*c_i,
      H_2q*t_i + q*c_i)
```

It closes the ring at the true index with:

```text
t_pi = u + S_2q,pi*c_pi*(-1)^b
```

and rejection sampling (Algorithm 2 lines 10-12). The signature is:

```text
sigma_L(mu) = (c_1, t_1, ..., t_w, h)
```

(Algorithm 2 line 13).

**PAPER - LRCT18 §5.4, Algorithm 3.**

Verification recomputes every challenge around the ring, enforces the
`L2` and infinity-norm bounds, and accepts only if the challenge cycle closes.

### 9.3 Linkability and double-spend detection

**PAPER - LRCT18 §5.5, Algorithm 4.**

For fixed public parameter `H`, the same private key gives the same:

```text
h = H*S
```

The link algorithm compares signature tags and returns `Linked` when equal.
In LRCT, the transaction/serial number is `TN = h` (LRCT18 §7,
Algorithm 6 lines 10-12). Consensus rejects a previously seen `TN`.

The paper calls the construction **one-time** linkable. Reusing an address/key
after spending is outside its intended model.

## 10. LRCT confidential-transaction relation

### 10.1 Paper commitment

**PAPER - LRCT18 §7, Equation (1).**

The paper defines:

```text
Com_A(m, sk) = A*sk + m mod q
```

with:

```text
Com_A(m1,sk) +/- Com_A(m2,sk')
  = Com_A(m1 +/- m2, sk +/- sk') mod q
```

Amounts are bit-encoded coefficient vectors. `LRCT.Mint` creates:

```text
cn = A*ck + amount mod q
```

(Algorithm 5).

For a one-input/one-output spend, ring member `i` contributes:

```text
abar_in,i = a_in,i + cn_in,i - cn_out
```

For the real member `pi`, equal input/output amounts make this a commitment to
zero with witness:

```text
Sbar_in,pi = S_in,pi + ck_in,pi - ck_out
```

The L2RS membership proof is run over the list of `abar_in,i`
(LRCT18 §7 and Algorithm 6 lines 7-10).

### 10.2 Non-composition with INDRA commitments

INDRA uses:

```text
C = value*G + blinding*H
```

over Ristretto255, and verifies a separate Bulletproof. LRCT18 uses polynomial
lattice commitments whose opening witness is deliberately combined with the
lattice ownership secret before ring signing.

The identity:

```text
a_in + cn_in - cn_out = A*Sbar
```

has no analogue obtained by substituting a Ristretto point for `cn`. The
ring-signature witness and commitment witness would live in unrelated algebraic
structures.

> [!CAUTION]
> **No faithful composition with INDRA's former Pedersen/Bulletproof design existed.**
>
> A proof that simultaneously establishes ownership of one ring member and
> balance of INDRA curve commitments would be a new cross-algebra
> zero-knowledge construction. LRCT18 does not provide it. Keeping the existing
> balance check would also require revealing the real input commitments,
> defeating sender privacy.

There is an additional post-quantum boundary: INDRA's commitments and
Bulletproofs use Ristretto255 discrete-log relations. They must not be assumed
post-quantum merely because amount recovery is not currently implemented.
Whether future quantum discrete-log capability breaks hiding, binding, proof
soundness, or all three in INDRA's exact transcript requires separate expert
analysis.

## 11. Ring/decoy selection and UTXO state

### 11.1 What the paper actually says

**PAPER - LRCT18 §7, Algorithm 6 line 6 and preceding prose.**

The signer selects `w-1` input wallets and adds the real wallet to make a ring
of size `w`. The paper gives no probability distribution, age distribution,
sampling algorithm, uniqueness rule, eligibility filter, or adversarial-decoy
model.

APQC18 §7 similarly selects outputs and warns in its conclusion that users may
fail to find enough outputs with the same value, especially early in a system
(APQC18 §7, printed pp. 37-39). Confidential commitments remove the simple
"same public amount" filter but do not solve age and behavior fingerprinting.

### 11.2 INDRA requirements absent from the papers

> [!WARNING]
> **INDRA ADDITION - UNREVIEWED: decoy policy**
>
> A deployable protocol would need a consensus- or wallet-specified decoy
> selection distribution, eligibility rules, treatment of locked/staked
> outputs, reorg behavior, sampling without replacement, and defenses against
> adversarial output flooding. The papers provide none. This document does not
> select a distribution.

The UTXO set must retain all output records as possible ring members after
spend. Spentness is represented by the global set of linkability tags, not by
deleting the actual output.

That conflicts directly with INDRA's present behavior:

- `InputV1` discloses `utxo_id`;
- validation loads that exact UTXO;
- application deletes it; and
- state rejects another use of that exact ID.

The ring transaction would instead disclose `w` ring member identifiers and a
tag. Consensus would verify membership and tag freshness without learning
which member is spent. This requires a new accumulator/state model and changes
state growth permanently.

Locked, bonded, slashed, governance-controlled, and protocol-generated outputs
cannot safely serve as ordinary decoys without a policy proving equivalent
spend conditions. Otherwise ring composition itself reveals the real eligible
member.

## 12. Evidence-based L2RS size and cost

LRCT18 Table 1 says its parameters "might give 90-100 bits of security" against
the authors' 2018 BKZ estimate. It does not provide a modern NIST-category
parameter set. That is already below the security target normally expected for
a new long-lived ledger.

The table contains five parameter versions. For the smallest reported Version
I:

| Ring size `w` | L2RS signature |
|---:|---:|
| 1 | 7.2 KB |
| 5 | 28.4 KB |
| 8 | 44.3 KB |
| 16 | **86.6 KB** |
| 32 | 171.2 KB |
| 64 | 340.4 KB |
| 128 | 678.9 KB |

The first row is printed as `w = 1` with a footnote marker that can appear as
`w = 15` in extracted text. Rows 5-128 establish the linear progression.
Version I also reports a 1.92 KB public key and 1.95 KB private key.

For ring size 16, larger table versions report 94.8, 113.2, 191.1, and
390.5 KB signatures respectively.

These are paper-reported decimal KB figures, not exact canonical byte strings.
The paper does not specify a byte-level canonical codec, compression format,
transaction-reference encoding, or implementation benchmark. Therefore:

- 86.6 KB is a paper-reported signature size, not an exact INDRA transaction
  size;
- the ring-member list, output wallet, transaction framing, and range/balance
  proof data are additional; and
- no honest 128-bit-security size can be calculated from the paper because it
  provides no reviewed 128-bit parameter set.

# Part III - composition

## 13. Do the two pieces work together?

**No, not as published.**

### 13.1 Ownership-key incompatibility

SAP26 derives:

```text
p = k + XOF(S)
P = XOF(rho_K)*p + e_1
```

under Kyber/Dilithium-shaped Module-LWE parameters.

LRCT18 requires:

```text
S in R_q^(m-1)
a = A*S mod q
```

with coefficients sampled from a specific short interval, then consumes `S`
inside `L2RS.SigGen` and the balance witness
`S + ck_in - ck_out`.

No paper proves that `p` has LRCT's distribution or bounds, that `P` is an LRCT
key, or that SAP's `XOF(rho_K)` equals LRCT's global `A`. Direct substitution
would invalidate the correctness and security arguments.

### 13.2 Commitment incompatibility

Even if ownership keys were bridged, LRCT's anonymity-and-balance proof depends
on its lattice `cn`. INDRA's curve commitment cannot be substituted into
Algorithm 6.

### 13.3 Whole-transaction security

Neither SAP26 nor LRCT18 analyzes:

- announcements and ring members in the same transaction;
- view-tag false positives correlated with ring composition;
- KEM ciphertext malleability/replay bound to a ring transaction;
- decoy-selection leakage correlated with recipient scan timing;
- multiple inputs or multiple outputs;
- change classification;
- common wallet fingerprints;
- public fees and output counts;
- network-origin metadata; or
- selective disclosure across both mechanisms.

The privacy guarantee of two mechanisms cannot be multiplied informally. For
example, a unique ring-member age pattern can identify the sender even when
the recipient output is unlinkable; a unique announcement or change pattern
can identify the recipient despite a valid ring signature.

## 14. Concrete end-to-end example: where construction stops

Suppose Alice wants to consume one real output among a ring of 16 and create
one payment to Bob plus one change output.

### 14.1 Steps supplied by the papers

1. Bob publishes SAP meta-address `M_B=(K_B,V_B)`.
2. Alice encapsulates `(R_B,S_B)=Encaps(V_B)`.
3. Alice computes Bob's `P_B`, view tag, and announcement under SAP26 §5.3.
4. For the input, Alice chooses 15 decoys and her real wallet as LRCT ring
   `IW`, constructs `L'`, and runs LRCT18 Algorithm 6.
5. LRCT verification checks the L2RS and rejects a repeated `TN=h`.

### 14.2 Missing step that prevents a transaction

LRCT Algorithm 6 requires the output address and coin commitment to be in
LRCT's key/commitment system. SAP26 gives a different `P_B`; INDRA's current
transparent baseline supplies neither an LRCT ownership secret nor an LRCT
coin commitment.

There is no published operation in the selected sources that produces:

```text
LRCT-compatible output ownership secret for Bob
+ a specified transition from INDRA's transparent-value baseline
+ one ring proof hiding Alice's real input
+ a binding to SAP announcement (R_B, tag_B)
```

The example therefore stops before a valid transaction can be formed. Filling
this line would be original protocol design.

### 14.3 Extensions considered and rejected

The following seemingly minimal bridges are **not from the papers** and are
not adopted:

- Derive an LRCT secret directly from `S_B`: Alice would know the spending
  secret.
- Hash `p` into an LRCT secret: Bob could derive it, but its key relation and
  proof distribution would be new and SAP's published `P` would no longer be
  the spending key.
- Include both SAP and LRCT owner keys: binding them to the same owner without
  linkability or theft requires a new proof.
- Encrypt a fresh LRCT secret to Bob: sender-generated ownership lets the
  sender steal unless an additional jointly derived/key-private construction
  is reviewed.
- Keep INDRA's public input commitment balance check: it reveals the real
  input.
- Run LRCT only as an auxiliary signature: without its lattice commitment
  relation, it does not prove that a balanced real input was authorized.

APQC18 supplies a coherent temporary-key plus ring-signature family, but
substituting it would abandon the mandated SAP26 construction and still would
not compose with INDRA commitments. APQC18 also explicitly leaves confidential
transactions for future work.

## 15. Total transaction size and practicality

Because no valid combined transaction is defined, this specification does not
present a fictional exact total.

A defensible **lower-bound illustration**, not a transaction specification, is:

| Component | Supported size |
|---|---:|
| LRCT Version-I ring-16 signature | 86.6 KB, paper-reported |
| SAP Kyber512 announcement | 769 bytes exact payload |
| one former INDRA range proof | 674 bytes in archived repository test/codec usage |
| subtotal | over 88 KB before ring list, keys, outputs, framing, second output, or balance-proof replacement |

For the paper's Version III ring-16 row, the signature alone is 113.2 KB. None
of the table's parameter versions is presented as a modern 128-bit reviewed
configuration.

INDRA currently allows at most 16 inputs, but an LRCT ring size is not the
number of real inputs. A ring-16 proof for each of several real inputs may
multiply proof cost unless a separately reviewed multi-input construction is
chosen. LRCT18 specifies only SISO and contains no production multi-input size.

At INDRA's byte-weighted fee rule, an 88+ KB transaction would pay for at least
89 KB before uncounted data. More importantly, verification, block propagation,
state retention of spent decoys, and anonymity-pool growth have not been
benchmarked. It is not responsible to call this remotely practical based only
on the papers.

## 16. Normative disposition

### 16.1 What may responsibly be built

A **non-value-bearing, isolated research harness** may be responsible if all of
the following hold:

- it is not connected to live validators or wallets;
- it uses published parameter sets exactly;
- it reproduces paper test vectors or author reference code where available;
- it labels every result experimental and unsafe;
- it separately tests SAP26 and LRCT18 before any composition experiment;
- it is provided to qualified external cryptographers; and
- no compatibility extension is treated as inherited paper security.

### 16.2 What may not responsibly be built from this specification

- a live OutputV2;
- a migration path for real UTXOs or bonds;
- a claim of full post-quantum transaction privacy;
- a new key-conversion layer between SAP26 and LRCT18;
- a claim that existing Pedersen/Bulletproof value privacy composes with
  LRCT18; or
- a security-level claim based on LRCT18's 2018 "90-100 bit" estimates.

## 17. Expert-review questions required before design resumes

1. Obtain and diff the final 2026 journal version of SAP26 against arXiv v1.
2. Ask the authors to provide exact signing and verification algorithms,
   serialized key formats, bounds, and security games for the derived `p,P`.
3. Determine whether SAP26 recipient anonymity is formally reduced to
   ML-KEM/Kyber security or needs a separate key-privacy game.
4. Re-evaluate LRCT18 parameters under current lattice estimators and a quantum
   random-oracle model.
5. Determine whether a newer peer-reviewed PQ RingCT, such as MatRiCT, offers a
   materially better reviewed and sized basis than LRCT18.
6. Select one coherent commitment system; do not bridge curve and lattice
   commitments without a reviewed proof.
7. Specify multi-input/multi-output security, not just SISO.
8. Develop and analyze a decoy distribution against temporal analysis and
   adversarial flooding.
9. Define staking/bond custody separately from anonymous ordinary transfers.
10. Model transaction, wallet-scanning, mempool, network, and selective-view
    privacy together.

## 18. Final assessment

The act of writing the equation-level specification changes the earlier
assessment materially.

It remains responsible to build isolated, non-value-bearing research
implementations of each paper for expert evaluation. It is **not** presently
responsible to build "full OutputV2 stealth-address privacy" as a combined
research feature and imply that it faithfully implements the selected papers.
The required composition is absent, the value-commitment algebra is
incompatible, the stealth paper's spending algorithm is underspecified in the
inspectable version, and the ring-signature parameters are very large and
target only an old 90-100-bit estimate.

The honest result is therefore:

> There is published research for each broad privacy goal, but these specific
> papers do not yet define a sound complete INDRA transaction. The next step is
> cryptographic expert review and source clarification, not implementation of a
> combined OutputV2.
