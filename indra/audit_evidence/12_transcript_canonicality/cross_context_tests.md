# Cryptographically valid cross-context tests

## Audit harness

```bash
cargo run --release --locked --offline \
  --manifest-path audit_evidence/12_transcript_canonicality/cross_context_harness/Cargo.toml
```

The harness deterministically creates genuine RFC 9381 proofs; it never
corrupts proof bytes. Result:

```text
election_wrong_chain=rejected
election_wrong_height=rejected
election_wrong_round=rejected
election_wrong_validator=rejected
election_wrong_snapshot=rejected
election_wrong_key=rejected
pop_wrong_context_0=rejected
pop_wrong_context_1=rejected
pop_wrong_context_2=rejected
registration_pop_as_election=rejected
election_proof_as_registration_pop=rejected
same_membership_different_snapshot_root=true
```

PoP contexts 0/1/2 are wrong chain, validator identity, and activation epoch.

## Existing permanent evidence

| Case | Evidence | Result |
|---|---|---|
| Seed bits and chain/height/round/snapshot/validator mutation | `proposal.rs::vrf_alpha_binds_every_seed_bit_and_every_context` | PASS |
| RegisterValidator PoP wrong chain and identity | `delegation.rs::register_validator_vrf_proof_binds_chain_and_validator_identity_context` | PASS |
| RegisterVrfKey wrong secret/public key | `delegation.rs::vrf_rotation_is_snapshot_delayed_and_public_key_squatting_is_rejected` | PASS |
| Proposal authorization changed content/chain | `driver.rs::proposal_requires_both_hybrid_components_and_independent_vrf_validity` | PASS |
| Changed proposal height/round | Both fields occur explicitly and inside the signed canonical block | PASS |
| Wrong suite | Only suite 1 is legal; unknown enum bytes fail before verification; future suite changes snapshot root | PASS |
| Valid entropy assigned to another stable value | VRF-007 component-sensitivity and pre-vote admission regressions | PASS |
| Proposal authorization on another proposal | Complete canonical block is length-framed; content mutation rejects | PASS |

## Post-VRF-007 regression

```text
original_value_hash=44bd54815f187080a2b7adbb17a17e7a6ce9decb791122841b1e44ebedfc2a6d
substituted_value_hash=d89592308468b9ddfc000701cf9ac33c3ba5291422133ce3135af0b58d60cfa7
original_polc_authorizes_substituted=false
```

Both entropy records remain cryptographically valid in their own contexts but
are correctly different consensus values. Unchanged entropy plus a legitimate
new proposer round retains the original stable hash.
