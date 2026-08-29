# Differential run results

Run date: 2026-08-18

- Reference repository: `https://github.com/reyzin/ecvrf.git`
- Reference commit: `917883bc5fa4dfb069bc40ed7cf8ba5d988bedf1`
- INDRA commit: `b6404ccacc508d92a022f50ad1af3da4d4e31a02`
- Tested `indra-crypto/src/vrf.rs` SHA-256:
  `8bc91bc99570d8571d6f704b91b8cfb48c2f2ffd799c7f4314ba462f603e77e9`
- Deterministic corpus seed: `0x494e4452412d5652`
- Official RFC 9381 ELL2 vectors: 3 matched
- Positive differential cases: 1,000
- Malformed differential cases: 9,000
- Public-key/proof/output mismatches: 0
- Prove/verify/proof-to-hash mismatches: 0
- Accept/reject disagreements: 0

Command:

```sh
./audit_evidence/03_vrf_differential/run.sh
```

Terminal result:

```text
reference_repository=https://github.com/reyzin/ecvrf.git
reference_commit=917883bc5fa4dfb069bc40ed7cf8ba5d988bedf1
indra_commit=b6404ccacc508d92a022f50ad1af3da4d4e31a02
indra_vrf_source_sha256=8bc91bc99570d8571d6f704b91b8cfb48c2f2ffd799c7f4314ba462f603e77e9
official_rfc_vectors=3 matched=true
positive_cases=1000
malformed_cases=9000
prove_verify_output_mismatches=0
accept_reject_disagreements=0
```

The reference repository describes this implementation as insecure,
inefficient test-vector software. Agreement here is evidence of independent
protocol-mapping conformance only, not a security certification.
