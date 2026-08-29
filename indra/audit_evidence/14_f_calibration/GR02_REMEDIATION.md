# L2-GR-02 remediation record

- `L2-GR-02 — MEDIUM — FIXED`: initial mainnet admits exactly `f=3/8`, encoded
  as `F=6917529027641081856`. Genesis, consensus snapshots, and persisted chain
  state reject every other value. The genesis builder no longer accepts an
  active-slot-coefficient option.
- `L2-GR-01 — MEDIUM — ACCEPTED RESIDUAL`: publish/withhold grinding remains a
  bounded residual under the Phase-7 assumptions at `f=3/8`. Election-seed
  output is consensus sortition entropy and must not be used as general
  application randomness.

Changing `F` requires a consensus protocol version change and renewed
grinding/liveness analysis. There is no compatibility decoder or migration
path for pre-mainnet state carrying another value.
