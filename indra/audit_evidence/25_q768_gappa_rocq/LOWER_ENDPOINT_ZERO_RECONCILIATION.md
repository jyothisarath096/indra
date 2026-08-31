# Q768 lower stake-scaled endpoint: zero-reachability reconciliation

Date: 2026-08-31  
Repository revision inspected: `2c10ded495e472eee5238bf3d676d7029db01e59`

## Resolution

This is **option 1**: both reports refer to the same integer quantity, and the
later report is wrong.

The correct conclusion is:

> For every input satisfying `Q768AbstractModel.v`'s `admissible` predicate,
> and for every real production call using its validated consensus snapshot,
> the lower stake-scaled log endpoint passed into the phi recurrence is at least
> `2^640`, hence is never zero.

The lower-bound analysis in `X_ZERO_REACHABILITY_AND_REPAIR.md` at commit
`80b3f6b3` is correct and needs no correction. The contrary sentences in
`ABSTRACT_TARGET_PROGRESS.md` at commit `2c10ded4`, specifically lines 132-133
and 149-152 in the current file, are inaccurate. This addendum records that
finding without silently rewriting either committed report.

No `.v` file or already-closed theorem was changed.

## The quantities are identical

In the abstract model, `certificate_model` computes exactly

```coq
let zlo := (l.(ilo) * w) / total in
...
phi_model zlo 128%nat true
```

at `Q768AbstractModel.v:83-88`. `phi_model` immediately creates the point
interval `zi = [z,z]` and passes it to `phi_recurrence`
(`Q768AbstractModel.v:77-81`). There is no rescaling, shift, division,
truncation, or representation conversion between `zlo` and the recurrence
input. `Z.to_N` at line 81 converts the **final signed phi accumulator**, after
all recurrence steps; it does not modify the input `zlo`. Likewise, the final
`N.min q768_scale` clamp is applied to `phi_model`'s output at lines 87-88, not
to its input.

Production has the same path. `evaluate` computes
`zl = log.lo * w / total` at `indra-core/src/sortition.rs:176-179` and passes
that exact `BigUint` to `phi(zl, 128, true)` at lines 180-182. `phi` copies the
argument directly into the point interval `zi` at lines 129-134. Its signed-sum
to-`BigUint` conversion occurs only after the loop at lines 158-162.

Therefore the `zl` analyzed by `80b3f6b3` and the allegedly zero-reachable
rounded lower endpoint in `2c10ded4` are not different quantities.

## Universal lower bound on the admitted domain

Let `S = 2^768`. The abstract and Rust computations give:

1. `F >= 1`, so `fq = F * 2^(768-64) >= 2^704`.
2. `den = 2*S - fq < 2^769`. Consequently

   ```text
   y.lo = floor(fq*S/den) >= 2^703.
   ```

   The inequality before flooring is strict (`fq*S/den > 2^703`), so flooring
   cannot reduce it below the integer `2^703`.
3. The first log term divides `y.lo` by one, all later lower terms are
   nonnegative, and the final lower sum is doubled. Hence

   ```text
   log.lo >= 2^704.
   ```

4. On the admitted domain, `w >= 1` and `total <= 2^64-1`. Thus

   ```text
   zlo = floor(log.lo*w/total)
       >= floor(2^704/(2^64-1))
       >= 2^640
       > 0.
   ```

The operations supporting steps 1-3 are the construction of `fq`, `den`, `y`,
the 256-term recurrence, and the doubled lower sum at
`Q768AbstractModel.v:42-54`; step 4 is the exact `zlo` expression at lines
83-88. The domain facts are explicit in `admissible` at lines 111-113.

As an independent arithmetic check, an exact-integer reproduction of the full
256-term recurrence at the broad boundary `F=1`, `w=1`,
`total=2^64-1` produced a 641-bit `zlo` satisfying `zlo >= 2^640`. This agrees
with the universal bound; it is not used in place of the reasoning above.

## Production versus artificially broadened domains

Zero is not reachable under the abstract end theorem's full domain:
`admissible` requires `1 <= f`, `1 <= w`, `w <= total`, and
`total <= 2^64-1` (`Q768AbstractModel.v:111-113`). It is also not reachable on
real production paths:

- `evaluate` rejects `w == 0`, `total == 0`, and `w > total` before computing
  `zl` (`indra-core/src/sortition.rs:165-175`);
- each consensus snapshot entry rejects zero weight
  (`indra-core/src/types/consensus_snapshot.rs:68-79`);
- snapshot construction derives the log certificate from the admitted mainnet
  `F` (`consensus_snapshot.rs:137-172`), while validation rejects a zero lower
  endpoint and requires exact equality with a recomputed certificate
  (`consensus_snapshot.rs:191-219`); and
- the production proposer and received-proposal paths obtain stakes and the log
  from those snapshots (`indra-consensus/src/proposer.rs:58-95,121-142` and
  `indra-core/src/types/proposal.rs:109-153,165-198`).

A zero recurrence input is possible only outside that scope—for example by
calling the pure `phi_model 0 ...` definition directly, by invoking
`certificate_model` with non-admissible `f=0` or `w=0`, or by directly calling
the public Rust `evaluate` API with a manually forged `CertifiedLogInterval`
whose lower endpoint is zero. Those are useful generic/API test cases, but they
are neither inputs to `full_q768_abstract_target` nor validated production
sortition inputs.

## Consequence for the next proof task

The final abstract theorem does **not** need a `zlo = 0` branch. On its stated
`admissible` domain, a future proof may and should establish `2^640 <= zlo`
(or merely `0 < zlo`) before applying the strict-domain phi theorem. The
separate checked equality `phi_at_zero_is_exact` remains mathematically valid
and useful for a future generalized theorem, but it is not required by the
current production-domain end theorem.
