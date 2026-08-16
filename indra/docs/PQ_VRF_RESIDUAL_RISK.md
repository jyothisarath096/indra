# PQ VRF Residual Risk — Classical Eligibility, Hybrid Authorization

INDRA proposer eligibility uses the in-tree RFC 9381
`ECVRF-EDWARDS25519-SHA512-ELL2` implementation. This is a classical
discrete-log construction and is not post-quantum secure. Mainnet activation
remains blocked on the independent implementation audit and audited-crate-path
gates recorded in `PROPOSER_AUTHORIZATION_VRF_DESIGN_SPEC.md`.

The VRF proves eligibility only. Every proposal independently requires the
registered validator's complete Ed25519 + ML-DSA-87 hybrid authorization over
the canonical proposal transcript. A future break of the classical VRF may
permit eligibility prediction or forgery, but does not authorize a block,
forge votes, move funds, or register/rotate a key without the independently
verified hybrid signature.

Genesis and post-genesis VRF registrations both require an RFC 9381
proof-of-possession over a chain-, validator-, key-, and activation-bound
transcript. Genesis keys activate at height 1; later registrations activate
only through the next consensus-snapshot epoch boundary.

VRF seed material is independently domain-derived from the Ed25519 and
ML-DSA-87 seeds. Compromise of the VRF secret therefore does not arise from,
or directly disclose, either hybrid signing seed.
