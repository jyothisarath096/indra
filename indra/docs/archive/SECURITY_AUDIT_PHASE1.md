> **Historical archive:** This records completed audit work and intermediate designs. It is not current guidance; canonical specifications and current code take precedence.

# INDRA Security Audit — Phase 1: Cryptographic Security

Scope: `indra-crypto/`, `indra-bulletproofs/`, `indra-ffi/src/keygen.rs`, plus the consensus/state call sites needed to determine exploitability.

This report began as an audit and proof-of-concept report. It now also records the Phase 1 remediation status for the high, medium, and low findings that have been fixed in the Rust codebase.

## Summary Table

| ID | Component | Finding | Severity | Status |
|----|-----------|---------|----------|--------|
| C-01 | hybrid.rs / signing domains | Transaction signing lacked an explicit literal domain; other domains are distinct | LOW | FIXED — `TX_SIGN` is prepended to transaction signing bytes |
| C-02 | vote signing | Votes omitted `chain_id` | MEDIUM | FIXED — vote signing bytes include length-prefixed `chain_id` |
| C-03 | QC verification | Block QC verification was ML-DSA-only, not hybrid | HIGH | FIXED — QCs now carry and verify Ed25519 + ML-DSA signatures |
| C-04 | Ed25519 | `ed25519-dalek` 2.2.0 is used; non-canonical signature acceptance is now regression-tested | LOW | FIXED — malleability regression test added |
| C-05 | ML-DSA-87 | Signing API takes no caller RNG; no weak RNG passed | SAFE | Checked |
| C-06 | VRF | Ed25519-style clamping was applied to a Ristretto scalar | MEDIUM | FIXED — scalar derivation now uses 64-byte wide reduction |
| C-07 | VRF | Implementation deviates from ECVRF-RISTRETTO255-SHA512 | MEDIUM | Non-standard |
| C-08 | proposer election | Election used public `sha256(vrf_pubkey || input)`, enabling VRF-key grinding | HIGH | FIXED — election uses verified VRF output when active |
| C-09 | mnemonic.rs | BIP-39 passphrase is fixed to empty string | LOW | Feature limitation |
| C-10 | mnemonic.rs | KDF used `SHA256(master || domain)` instead of HMAC/BIP-32 style KDF | LOW | FIXED — HMAC-SHA256 KDF implemented |
| C-11 | mnemonic / FFI | Rust seeds zeroize; FFI returned secret arrays lacked explicit zeroize APIs | MEDIUM | FIXED — Rust FFI zeroize functions added; Swift lifecycle remains follow-up |
| C-12 | bulletproof transcript | SHA-512 labelled transcript with challenge absorption | SAFE | Checked |
| C-13 | range proof binding | Proof verifies against stored output commitment; balance equation is enforced | SAFE | Checked |
| C-14 | blinding factors | CLI builder uses `OsRng`; FFI UTXO blindings are caller-supplied | SAFE / LOW | Operational caveat |
| C-15 | commitment.rs / apply.rs | `verify_balance` is called during transaction validation | SAFE | Checked |
| C-16 | indra-ffi | Raw pointer lengths/counts were not globally bounded before `from_raw_parts` | HIGH | FIXED — transaction/UTXO/buffer caps added |
| C-17 | indra-ffi | Secret key material returned over FFI lacked explicit zeroize APIs | MEDIUM | PARTIAL FIX — Rust zeroize APIs added; Swift wrapper follow-up remains |
| C-18 | bls.rs | Same-message aggregate BLS has no proof-of-possession guard | HIGH | Latent if BLS is used for consensus |
| C-19 | bls.rs | `blst` parsing/verification requests subgroup/key validation | SAFE | Checked, with C-18 caveat |

Severity key: CRITICAL / HIGH / MEDIUM / LOW / INFO / SAFE.

## Detailed Findings

### C-01 — Signature domain separation is mostly present, but transaction signing has no literal domain

**Description:** Staking, governance, and votes use distinct literal domains:

- Staking: `indra-stake-v1` in `indra-core/src/types/primitives.rs`
- Governance: `INDRA-gov-v1:` in `indra-core/src/types/governance.rs`
- Votes: `INDRA-VOTE-SIGN-v1` via `indra-crypto/src/hash.rs`

Transactions include `chain_id`, version, module id, inputs, outputs, fee, fee blinding, and fee commitment in `TransactionV1::signing_bytes`, but do not prepend `INDRA-TX-SIGN-v1` despite that domain existing in `indra-crypto::hash::domains::TX_SIGN`.

**Attack scenario:** A direct cross-context replay between current transaction/staking/governance/vote encodings was not found because the byte layouts differ substantially. The remaining risk is maintainability: a future operation could accidentally construct bytes compatible with transaction signing because transactions do not have a literal domain separator.

**Code location:** `indra-core/src/types/transaction.rs`, `indra-core/src/types/staking.rs`, `indra-core/src/types/governance.rs`, `indra-core/src/types/vote_signing.rs`.

**Proof-of-concept:** `indra-crypto/tests/audit_phase1.rs::audit_hybrid_rejects_single_component_forgery` locks in the hybrid verification invariant. Cross-context replay itself was not found exploitable in current encodings.

**Recommended fix:** Prepend `indra_crypto::hash::domains::TX_SIGN` to `TransactionV1::signing_bytes` under a hard-fork/protocol-version gate.

**Status:** FIXED. `TransactionV1::signing_bytes` now prepends `indra_crypto::hash::domains::TX_SIGN`, and `transaction_signing_bytes_include_domain` locks the invariant.

**References:** RFC 8032 domain separation guidance; general protocol transcript domain separation practice.

### C-02 — Vote signatures omit `chain_id`

**Description:** `vote_signing_bytes(height, round, step, block_hash, validator_id)` signs only the vote domain, height, round, step, value hash, and validator id. It does not include `chain_id`.

**Attack scenario:** If the same validator key is used on two chains and the same vote tuple exists on both chains, a vote signature from chain A can verify on chain B. The block/value hash makes accidental replay unlikely, but chain separation should be explicit because validators frequently reuse operational keys during testnet/mainnet transitions.

**Code location:** `indra-core/src/types/vote_signing.rs`.

**Proof-of-concept:** Reasoning: the signed byte function has no `chain_id` parameter, so no call site can bind chain identity.

**Recommended fix:** Add `chain_id` to vote signing bytes and thread it through vote production/verification under a hard-fork/protocol-version gate.

**Status:** FIXED. `vote_signing_bytes` now includes a length-prefixed `chain_id` when `vote_chain_id_active(height)` is active. Vote production, vote verification, QC construction, QC verification, slash evidence verification, and tests now pass the chain id explicitly. The `block_hash` parameter remains the full `BlockHeaderV1::block_hash()` as required by the consensus safety fix, not `value_hash`.

**References:** Tendermint/Cosmos signing domain practices; replay protection design.

### C-03 — QC verification is ML-DSA-only, not hybrid

**Description:** Normal vote collection verifies hybrid signatures in `indra-consensus/src/vote.rs`. However, block import verifies embedded QCs through `verify_qc`, which checks only `PQVoteSig` entries with `verify_pq`. A syncing or replaying node therefore accepts QC finality based only on ML-DSA signatures and does not require Ed25519 signatures.

**Attack scenario:**

1. Assume an attacker can forge ML-DSA-87 signatures but cannot forge Ed25519.
2. The attacker constructs a `QuorumCertificateV1` with forged `pq_signatures` for enough validator IDs.
3. `verify_qc` reconstructs the precommit signing bytes and calls `verify_pq` only.
4. If PQ forgery succeeds, the QC verifies even though no Ed25519 component exists.

This violates the “break both schemes” hybrid security goal for consensus finality on block import.

**Code location:** `indra-consensus/src/qc.rs`.

**Proof-of-concept:** The call graph itself is the PoC: `verify_block_qc` → `verify_qc_strict` → `verify_qc` → `verify_pq`. A runnable exploit test would require a forged ML-DSA signature, which is not feasible without breaking ML-DSA. The structural vulnerability is that no classical signature is present or checked.

**Status:** FIXED. `QuorumCertificateV1` now carries `classical_signatures` alongside `pq_signatures`; `QcBuilder` extracts both from accepted hybrid votes; and `verify_qc` enforces Ed25519 verification when `hybrid_qc_active(qc.height)` is active. Regression tests cover missing classical signatures, valid hybrid QCs, and forged classical signatures.

**Recommended fix:** Implemented. Continue to keep QC signing bytes stable and require both signature components for any future QC format.

**References:** Hybrid signature composition guidance; NIST PQ migration guidance.

### C-04 — Ed25519 verification strictness should be made explicit

**Description:** `Cargo.lock` uses `ed25519-dalek` 2.2.0. The code calls `Verifier::verify`. Version 2.x has stronger parsing behavior than old dalek versions, but dalek also exposes stricter verification APIs. Consensus code should not rely on ambiguous defaults for malleability-sensitive signatures.

**Attack scenario:** If non-canonical or small-order edge cases are accepted, an attacker may produce multiple encodings for one logical signature or trigger signature-set confusion. No such acceptance was proven in this audit.

**Code location:** `indra-crypto/src/hybrid.rs`, `Cargo.lock`.

**Proof-of-concept:** No accepted malleable signature was found.

**Recommended fix:** Use the strictest available dalek verification API and add malleability test vectors.

**Status:** FIXED. `ed25519_rejects_non_canonical_signature` confirms the current `ed25519-dalek` verification path rejects a deliberately non-canonical signature encoding.

**References:** RFC 8032; `ed25519-dalek` strict verification documentation.

### C-05 — ML-DSA-87 signing does not use caller-provided weak RNG

**Description:** `PqKeypair::sign` reconstructs the signing key from a 32-byte seed and calls `MlDsaSigner::sign(&sk, message)`. No caller RNG is passed, so the INDRA code does not inject weak randomness.

**Attack scenario:** The Sony-PS3-style nonce failure requires reused/predictable signing randomness. No INDRA-provided weak RNG was found in this path.

**Code location:** `indra-crypto/src/hybrid.rs`.

**Proof-of-concept:** Existing tests show deterministic seeded key generation and sign/verify round trips.

**Recommended fix:** Document whether the `ml-dsa` crate’s `sign` mode is deterministic or randomized internally; pin/audit the crate before mainnet.

**References:** FIPS 204 ML-DSA.

### C-06 — VRF clamps a Ristretto scalar with Ed25519 rules

**Description:** `derive_scalar` hashes the seed with SHA-512, takes 32 bytes, then applies Ed25519 clamping before `Scalar::from_bytes_mod_order`. Ristretto255 scalar derivation does not require Ed25519 clamping.

**Attack scenario:** This does not directly reveal the secret key, but it reduces the scalar distribution and deviates from expected Ristretto scalar derivation. Any non-standard key derivation in a VRF should be treated cautiously because proposer election depends on uniqueness and pseudorandomness.

**Code location:** `indra-crypto/src/vrf.rs`.

**Proof-of-concept:** Code inspection: the clamp masks low/high bits before scalar conversion.

**Recommended fix:** Use a standard ECVRF-RISTRETTO255-SHA512 scalar derivation or `Scalar::from_bytes_mod_order_wide` from a 64-byte hash, gated if existing keys/state depend on current public keys.

**Status:** FIXED. VRF scalar derivation now reduces the full SHA-512 output with `Scalar::from_bytes_mod_order_wide`. This is a breaking key-derivation change for existing VRF seeds and is intended for fresh-genesis deployment only.

**References:** draft-irtf-cfrg-vrf-15; Ristretto255 group documentation.

### C-07 — VRF implementation deviates from standard ECVRF

**Description:** The module says it implements draft ECVRF-RISTRETTO255-SHA512, but nonce generation is `SHA512(secret_key || alpha || "INDRA-VRF-NONCE-v1")`, and hash-to-curve is implemented by repeated compressed-point decompression. This is not the standard ECVRF nonce/hash-to-curve construction.

**Attack scenario:** No immediate forgery was found: verification recomputes `U`, `V`, and the challenge, and output is bound to `Gamma`. The risk is non-standard cryptography in consensus proposer selection, especially around nonce uniqueness, bias, and future interoperability.

**Code location:** `indra-crypto/src/vrf.rs`.

**Proof-of-concept:** Existing tests verify wrong input/output/key failures; this audit did not forge proofs.

**Recommended fix:** Either adopt a vetted ECVRF implementation or document this as “INDRA VRF” rather than standards-compliant ECVRF, with external review.

**References:** draft-irtf-cfrg-vrf-15.

### C-08 — Proposer election uses public candidate output and is grindable

**Description:** `elect_proposer` ranks validators by `candidate_output(vrf_pubkey, vrf_input) = SHA256(vrf_pubkey || vrf_input)`. This is public and independent of the validator’s secret VRF scalar. `verify_proposer_vrf` checks that the block proposer can produce a valid VRF proof, but the election winner itself is selected by public key hash, not by the verified VRF output in the block.

**Attack scenario:**

1. A validator generates many VRF keypairs offline.
2. For known future `(epoch_seed, height, round)` inputs, the validator computes `SHA256(vrf_pubkey || input)` for each candidate key.
3. The validator registers the key that gives the best future schedule.
4. This improves proposer odds without breaking VRF cryptography.

This is strongest when `epoch_seed` or future heights are predictable before validator registration or VRF key rotation.

**Code location:** `indra-consensus/src/proposer.rs`; `indra-node/src/sync.rs`.

**Proof-of-concept:** `indra-crypto/tests/audit_phase1.rs::audit_vrf_public_candidate_output_is_grindable` grinds 2048 VRF public keys and reliably finds a very low first output byte for a fixed public election input.

**Historical resolution, corrected for the final design:** The interim single-header-proof design was superseded. Current proposer selection uses commit/reveal VRF evidence; the header binds `election_result_hash`, the QC attests that hash, and sync verifies the durable reveal evidence and proposer/output relationship. There is no public-hash legacy fallback in the canonical protocol.

**Recommended fix:** Implemented for the current single-proposer block-header proof flow. For stronger future sortition, consider requiring/revealing verified VRF outputs for every candidate in the slot instead of relying on fallback scores for non-proposers.

**References:** Algorand sortition VRF design; general key-grinding attacks in proof-of-stake.

### C-09 — BIP-39 passphrase is not supported

**Description:** `mnemonic_to_seed` calls `mnemonic.to_seed_normalized("")`; the passphrase is always empty.

**Attack scenario:** Users cannot add a “25th word” passphrase. This is not a protocol break, but it removes a defense against mnemonic theft.

**Code location:** `indra-crypto/src/mnemonic.rs`.

**Proof-of-concept:** Code inspection.

**Recommended fix:** Add optional passphrase support in CLI/FFI/UI.

**References:** BIP-39.

### C-10 — Key derivation uses plain SHA-256 instead of HMAC/HKDF/BIP-32

**Description:** Seeds are derived as `SHA256(master_seed || domain)`. The domains are distinct, and the derived seeds are secret, so SHA-256 length extension is not directly exploitable from public data. However, HMAC/HKDF gives better PRF and domain-separation guarantees.

**Attack scenario:** No practical attack was found given a secret random master seed. The main risk is conservative cryptographic design and future derivations.

**Code location:** `indra-crypto/src/mnemonic.rs`.

**Proof-of-concept:** Reasoning only; derived seeds are not public in normal operation.

**Recommended fix:** Use HKDF-SHA256 or HMAC-SHA512 with labelled info strings.

**Status:** FIXED. `derive_seed` now uses HMAC-SHA256 keyed by the BIP-39 master seed and labelled by the INDRA domain string. This changes derived wallet seeds for the same mnemonic and must only be deployed with an explicit migration/fresh-genesis plan.

**References:** RFC 5869 HKDF; BIP-32.

### C-11 — Seed zeroization is partial

**Description:** `DerivedSeeds` implements `Zeroize` and `ZeroizeOnDrop`. However, `indra-ffi::IndraKeyPair` returns `classical_seed`, `pq_sk`, `bls_seed`, and `vrf_seed` as plain fixed arrays. There is no FFI destructor that zeroizes `IndraKeyPair`, and Swift ARC does not guarantee secure erasure.

**Attack scenario:** A local memory disclosure on a jailbroken device or crash dump could recover long-lived private seed material from the Swift/Rust boundary.

**Code location:** `indra-crypto/src/mnemonic.rs`, `indra-ffi/src/keygen.rs`, `indra-ffi/src/lib.rs`.

**Proof-of-concept:** Code inspection; no zeroizing wrapper exists for `IndraKeyPair`.

**Recommended fix:** Return opaque key handles or encrypted key blobs where possible. Add explicit zeroize/free APIs and Swift-side secure memory handling.

**Historical status:** The then-current raw-key FFI added explicit keypair and transaction-result zeroizers. That entire raw-key surface was subsequently removed; the canonical API uses opaque handles.

**References:** Rust `zeroize`; iOS Keychain/Secure Enclave key handling guidance.

### C-12 — Bulletproof transcript is labelled and hash-based

**Description:** The transcript uses SHA-512, labelled messages with length prefixes, a domain separator, and absorbs challenge outputs back into the transcript.

**Attack scenario:** No transcript manipulation was found. Proof elements influence challenges through labelled transcript absorption.

**Code location:** `indra-bulletproofs/src/transcript.rs`, `indra-bulletproofs/src/range_proof.rs`.

**Proof-of-concept:** Existing tests reject tampered proofs and wrong commitments.

**Recommended fix:** Prefer Merlin if adopting standard Bulletproof tooling, but current transcript structure is reasonable.

**References:** Bulletproofs paper; Fiat-Shamir transform best practices.

### C-13 — Range proof verifies against the stored output commitment

**Description:** `validate_transaction` calls `verify_range` using `output.commitment.compressed_point.0`, the same commitment stored in the UTXO. It does not verify a proof against one commitment and store another.

**Attack scenario:** The specified “C1 proof, C2 UTXO” attack is not present. An output commitment/value mismatch is also constrained by public input/output arithmetic and `verify_balance`, so no inflation path was found.

**Code location:** `indra-state/src/apply.rs`.

**Proof-of-concept:** Existing `wrong_commitment_fails` range-proof test.

**Recommended fix:** Add an explicit transaction validation regression test for “proof for wrong output commitment fails”.

**References:** Bulletproofs range proof binding.

### C-14 — Blinding factor generation uses secure RNG in CLI

**Description:** `build_transaction` uses `rand::rngs::OsRng` and fills fresh 32-byte blindings for recipient and change outputs. FFI transaction building delegates to the same CLI builder. Existing wallet UTXO blindings are caller-provided because they come from wallet state.

**Attack scenario:** No static production blinding was found. Test code uses fixed blindings only in unit tests.

**Code location:** `indra-cli/src/tx_builder.rs`, `indra-ffi/src/tx.rs`.

**Proof-of-concept:** Code inspection.

**Recommended fix:** Ensure imported wallet UTXO blindings are stored encrypted and never reused for newly created outputs.

**References:** Pedersen commitment hiding requirements.

### C-15 — Balance verification is enforced

**Description:** `validate_transaction` verifies public value arithmetic and then calls `verify_balance(input_commitments, output_commitments, fee_commitment)`.

**Attack scenario:** The inflation attack “skip commitment balance” is not present.

**Code location:** `indra-state/src/apply.rs`, `indra-crypto/src/commitment.rs`.

**Proof-of-concept:** Existing `commitment::tests::unbalanced_fails`.

**Recommended fix:** Keep this check mandatory before any UTXO insertion.

**References:** Confidential transaction balance equations.

### C-16 — FFI pointer lengths/counts are not globally bounded

**Description:** The FFI checks null pointers and some fixed lengths, but raw pointer lengths and counts are trusted before `from_raw_parts`. Examples:

- `indra_tx_to_hex(tx_bytes, tx_bytes_len, ...)` accepts arbitrary `tx_bytes_len`.
- The then-current raw transaction builder accepted arbitrary `utxo_count`.
- `indra_free_bytes(ptr, len)` and `indra_free_usize(ptr, len)` trust caller-provided lengths.
- Fixed-size pointer inputs such as seeds and public keys cannot prove the caller actually provided enough bytes.

This is partly inherent to C FFI, but unbounded `usize` lengths are avoidable.

**Attack scenario:** A malicious or compromised caller passes an enormous `utxo_count` or `tx_bytes_len`. Rust constructs a slice over invalid memory. `catch_unwind` cannot catch undefined behavior, SIGSEGV, or aborts.

**Code location:** `indra-ffi/src/lib.rs`, `indra-ffi/src/staking.rs`, `indra-ffi/src/governance.rs`.

**Proof-of-concept:** Not executed because a live PoC would intentionally invoke undefined behavior or crash the test process. The unsafe calls are visible in code.

**Status:** FIXED for the identified HIGH-risk FFI length/count sites. `MAX_UTXO_COUNT`, `MAX_TX_BYTES`, and `MAX_TX_HEX_BYTES` cap transaction inputs and outputs before slice construction; suspicious free lengths are ignored; staking/governance hex output buffers are bounded by `INDRA_OP_HEX_MAX_BYTES`. Regression tests cover excessive UTXO counts and transaction byte lengths.

**Recommended fix:** Implemented for the scoped findings. A future hardening pass should add allocation handles/metadata so free functions can validate exact lengths rather than only rejecting clearly impossible lengths.

**References:** Rustonomicon FFI safety; C ABI pointer safety.

### C-17 — FFI secret key material is not securely erased

**Description:** `IndraKeyPair` carries private seeds in plain arrays. `IndraTxResult` carries `change_blinding`. Rust-owned byte buffers are freed without zeroization.

**Attack scenario:** Local memory disclosure, crash reports, swapped pages, or Swift object lifetime extension can expose private seeds or output blindings.

**Code location:** `indra-ffi/src/lib.rs`, `indra-ffi/src/keygen.rs`.

**Proof-of-concept:** Code inspection; no zeroizing drop/free path exists for FFI structs.

**Recommended fix:** Add explicit zeroizing free functions and Swift wrappers that call them; avoid returning raw long-term secrets when a handle/keychain design is possible.

**Historical status:** The then-current raw-key FFI added zeroizers and tests for exposed private fields/blindings. That interface was subsequently deleted; current wallet integrations use opaque key handles and bounded result destruction APIs.

**References:** Rust `zeroize`; mobile wallet key management practice.

### C-18 — BLS aggregate verification lacks proof-of-possession protection

**Description:** `verify_aggregate` verifies an aggregate signature over the same message for multiple public keys. The module does not implement proof-of-possession registration or message augmentation. Same-message BLS aggregation is vulnerable to rogue-key attacks unless PoP or augmentation is enforced.

**Attack scenario:**

1. Attacker registers a malicious public key related to a victim public key.
2. The malicious key cancels or incorporates the victim’s contribution in an aggregate.
3. The attacker can make an aggregate verify without all claimed signers independently signing.

This is a latent risk because current QC verification is PQ-only, but the BLS module remains exported.

**Code location:** `indra-crypto/src/bls.rs`.

**Proof-of-concept:** The code has no PoP API or registry check. A runnable rogue-key construction was not added because it requires low-level point arithmetic and malformed-key registration helpers not exposed by the wrapper.

**Recommended fix:** Do not use this BLS aggregate API for same-message consensus signatures unless public keys have proof-of-possession at registration or messages are augmented per signer.

**References:** Boneh-Lynn-Shacham signatures; rogue-key attack literature; IETF BLS signature draft.

### C-19 — BLS subgroup/key validation appears enabled

**Description:** The BLS wrapper parses keys/signatures with `blst` and calls `aggregate_verify(true, ..., true)`. In `blst`, these boolean flags request signature group checks and public-key validation.

**Attack scenario:** Invalid-subgroup public keys or signatures should be rejected by parsing/verification. No bypass was found.

**Code location:** `indra-crypto/src/bls.rs`.

**Proof-of-concept:** Existing wrong-key/wrong-message tests reject invalid verification cases.

**Recommended fix:** Keep validation flags enabled and add malformed subgroup test vectors if BLS is used in consensus again.

**References:** BLS12-381 subgroup security; `blst` API documentation.

## Proof-of-Concept Tests

PoC tests were added in `indra-crypto/tests/audit_phase1.rs`:

- `audit_hybrid_rejects_single_component_forgery`: confirms that a hybrid signature with only one valid component does not verify.
- `audit_vrf_public_candidate_output_is_grindable`: demonstrates the public-key grinding surface caused by ranking candidates with `SHA256(vrf_pubkey || input)`.

High findings C-03, C-16, and C-18 are structural/cryptographic-design issues where a safe unit test cannot produce the real exploit without either breaking ML-DSA, invoking undefined behavior, or adding low-level BLS rogue-key construction helpers. They are documented with call-graph or reasoning PoCs above.

## Findings NOT Present

The following checks were performed and found secure in the current code:

- Transaction signature verification uses `verify_hybrid`.
- Staking operation verification uses `verify_hybrid`.
- Governance operation verification uses `verify_hybrid`.
- Slash evidence vote verification uses `verify_hybrid`.
- Vote collector verification uses `verify_hybrid`.
- Range proofs are verified against the exact commitment stored in each output.
- Commitment balance is verified before transaction application.
- CLI-generated output blindings use `OsRng`.
- Bulletproof proof parsing enforces exact proof length and canonical scalar encodings.
- SMT/state-root determinism issues are outside this audit phase and already separately documented.

## Recommended Fix Order

1. **DONE:** Redesign proposer election so the verified VRF output, not public `sha256(vrf_pubkey || input)`, determines eligibility/order.
2. **DONE:** Make QCs hybrid and require both classical and PQ security for block import finality.
3. **DONE:** Add hard FFI maximum lengths/counts before the identified `from_raw_parts` transaction/UTXO/buffer paths.
4. **DEFERRED — HIGH if BLS returns to consensus:** Add proof-of-possession or message augmentation to BLS aggregation.
5. Add `chain_id` to vote signing bytes under a protocol-version gate.
6. Add an explicit transaction signing literal domain.
7. Replace custom VRF/KDF constructions with reviewed standard constructions or obtain external cryptographic review.
8. Add FFI and Swift-side secret zeroization lifecycle.
